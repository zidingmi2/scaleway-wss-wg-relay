use crate::atomic::AtomicU64;
use crate::ip_stack::{packet::PacketBuffer, wake::Wake};
use gotatun::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
    udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams},
};
use std::{
    io,
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
};
use tokio::sync::{mpsc, oneshot};

/// Requested kernel socket-buffer sizes for the WireGuard carrier. Best
/// effort: the OS clamps to `net.core.{r,w}mem_max` when they are smaller,
/// which is logged once by the shared helper. The default Linux receive
/// buffer (~208 KiB) holds only ~150 WireGuard-sized datagrams, and the
/// 100 mVCPU CFS quota can stall this task for ~100 ms at a time, so a full
/// queue drops authenticated traffic exactly while the CPU budget is
/// exhausted. 4 MiB covers several such stalls without hurting the 128 MiB
/// container budget.
const CARRIER_UDP_BUFFER_BYTES: usize = 4 * 1024 * 1024;
/// Maximum packets coalesced into one `sendmmsg` syscall. gotatun's buffered
/// sender drains its channel with the transport's reported limit, so this is
/// also the channel backpressure window (its capacity is 64).
const SEND_BATCH_MAX: usize = 64;
/// Number of 65535-byte scratch slots per receive batch. Eight slots keep one
/// syscall per eight datagrams while limiting the allocation to 512 KiB.
const RECV_BATCH_SLOTS: usize = 8;
/// Upper bound on packets appended per `recv_many_from` call, matching the
/// gotatun receive channel capacity so backpressure bounds memory.
const RECV_DRAIN_LIMIT: usize = 64;
/// Largest possible UDP datagram; slots of this size can never truncate a
/// valid one (the reusable 4096-byte packet pool would, which is why the
/// scratch is separate).
const MAX_DATAGRAM_SCRATCH: usize = 65535;

pub(super) struct IpSink {
    pub sender: mpsc::Sender<PacketBuffer>,
    pub wake: Wake,
    pub drops: Arc<AtomicU64>,
}
impl IpSend for IpSink {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let packet = packet.into_bytes();
        // The peer has its own interface MTU. Our local transmit MTU must not
        // discard valid larger incoming IPv4 packets/fragments from that peer.
        if packet.len() > 65_575 {
            self.drops.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        // Charge decrypted UDP before copying it into the cross-thread queue.
        // Fragmented IPv4 keeps protocol=UDP in every IP header, so this also
        // covers fragments whose transport header is not present yet.
        let udp = match packet.first().map(|byte| byte >> 4) {
            Some(4) => packet.get(9) == Some(&17),
            Some(6) => packet.get(6) == Some(&17),
            _ => false,
        };
        let permit = if udp {
            let Some(permit) = crate::udp_budget::global().acquire(packet.len()) else {
                self.drops.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            };
            Some(permit)
        } else {
            None
        };
        let mut owned = PacketBuffer::copy_from_slice(&packet);
        if let Some(permit) = permit {
            owned = owned.with_lease(Arc::new(vec![permit]));
        }
        self.sender
            .send(owned)
            .await
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        self.wake.notify();
        Ok(())
    }
}
pub(super) struct IpSource {
    pub receiver: crate::ip_stack::driver::OutputReceiver,
    pub mtu: u16,
}
impl IpRecv for IpSource {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let packet = self
            .receiver
            .recv()
            .await
            .ok_or(io::ErrorKind::BrokenPipe)?;
        let packet = pool
            .get()
            .overwrite_with(&*packet)
            .try_into_ip()
            .map_err(io::Error::other)?;
        Ok(std::iter::once(packet))
    }
    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(self.mtu)
    }
}

struct Socket {
    socket: Option<tokio::net::UdpSocket>,
    closed: Option<oneshot::Sender<()>>,
    ipv6: bool,
    // One bounded scratch allocation per carrier avoids truncating legitimate
    // peer packets at the 4096-byte reusable GotaTun pool size. Small packets
    // still reuse pooled storage; jumbo allocations are not retained by it.
    receive_buffer: tokio::sync::Mutex<Box<[u8]>>,
}
impl Drop for Socket {
    fn drop(&mut self) {
        // Releases the bind before notifying shutdown waiters.
        drop(self.socket.take());
        if let Some(closed) = self.closed.take() {
            let _ = closed.send(());
        }
    }
}
#[derive(Clone)]
pub(super) struct Udp(Arc<Socket>);
pub(super) struct Factory(Option<(UdpSender, UdpReceiver)>);

#[derive(Clone)]
pub(super) enum UdpSender {
    Direct(Udp),
    Detour(super::detour::Sender),
}

pub(super) enum UdpReceiver {
    Direct(Udp),
    Detour(super::detour::Receiver),
}

impl Factory {
    pub fn new(
        listen: Option<SocketAddr>,
        interface: Option<String>,
    ) -> io::Result<(Self, oneshot::Receiver<()>, SocketAddr)> {
        let socket = if let Some(listen) = listen {
            let socket = crate::socket_util::new_outbound_socket2_udp_socket(
                listen.is_ipv6(),
                interface,
                Some(listen),
            )?;
            tokio::net::UdpSocket::from_std(socket.into())?
        } else {
            crate::socket_util::new_hostname_udp_socket(interface)?
        };
        let local = socket.local_addr()?;
        crate::socket_util::set_udp_socket_buffers(
            socket2::SockRef::from(&socket),
            CARRIER_UDP_BUFFER_BYTES,
        );
        let (closed, released) = oneshot::channel();
        let udp = Udp(Arc::new(Socket {
            socket: Some(socket),
            closed: Some(closed),
            ipv6: local.is_ipv6(),
            receive_buffer: tokio::sync::Mutex::new(vec![0; 65535].into_boxed_slice()),
        }));
        Ok((
            Self(Some((
                UdpSender::Direct(udp.clone()),
                UdpReceiver::Direct(udp),
            ))),
            released,
            local,
        ))
    }

    pub fn detour(sender: super::detour::Sender, receiver: super::detour::Receiver) -> Self {
        Self(Some((
            UdpSender::Detour(sender),
            UdpReceiver::Detour(receiver),
        )))
    }
}
impl UdpTransportFactory for Factory {
    type Send = UdpSender;
    type Recv = UdpReceiver;
    async fn bind(
        &mut self,
        _: &UdpTransportFactoryParams,
    ) -> io::Result<(UdpSender, UdpReceiver)> {
        self.0.take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "WireGuard socket reconfiguration requires reload",
            )
        })
    }
}

impl UdpSend for UdpSender {
    type SendManyBuf = ();
    async fn send_to(&self, packet: Packet, target: SocketAddr) -> io::Result<()> {
        match self {
            Self::Direct(socket) => socket.send_to(packet, target).await,
            Self::Detour(sender) => sender.send_to(packet, target),
        }
    }
    fn max_number_of_packets_to_send(&self) -> usize {
        match self {
            // Direct carriers coalesce queued packets into one syscall.
            // Detour transports multiplex across per-target proxy queues and
            // stay on the single-packet path.
            Self::Direct(_) => SEND_BATCH_MAX,
            Self::Detour(_) => 1,
        }
    }
    async fn send_many_to(
        &self,
        send_buf: &mut Self::SendManyBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        match self {
            Self::Direct(socket) => socket.send_many_to(send_buf, packets).await,
            Self::Detour(sender) => {
                for (packet, target) in packets.drain(..) {
                    sender.send_to(packet, target)?;
                }
                Ok(())
            }
        }
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        match self {
            Self::Direct(socket) => socket.local_addr(),
            Self::Detour(_) => Ok(None),
        }
    }
}

impl UdpRecv for UdpReceiver {
    type RecvManyBuf = CarrierRecvBatch;
    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        match self {
            Self::Direct(socket) => socket.recv_from(pool).await,
            Self::Detour(receiver) => receiver.recv_from(pool).await,
        }
    }
    async fn recv_many_from(
        &mut self,
        batch: &mut CarrierRecvBatch,
        pool: &mut PacketBufPool,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        match self {
            Self::Direct(socket) => socket.recv_many_from(batch, pool, packets).await,
            Self::Detour(receiver) => {
                // Detour queues deliver one datagram per wakeup; the proxy
                // chain side already coalesces what it received.
                let (packet, source) = receiver.recv_from(pool).await?;
                packets.push((packet, source));
                Ok(())
            }
        }
    }
}
impl UdpSend for Udp {
    type SendManyBuf = ();
    async fn send_to(&self, packet: Packet, mut target: SocketAddr) -> io::Result<()> {
        if self.0.ipv6
            && let std::net::IpAddr::V4(ip) = target.ip()
        {
            target.set_ip(ip.to_ipv6_mapped().into());
        }
        let len = self
            .0
            .socket
            .as_ref()
            .unwrap()
            .send_to(&packet, target)
            .await?;
        if len != packet.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(())
    }
    fn max_number_of_packets_to_send(&self) -> usize {
        SEND_BATCH_MAX
    }
    async fn send_many_to(
        &self,
        _: &mut Self::SendManyBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        // A full channel drain becomes one `sendmmsg` syscall instead of one
        // readiness round trip per packet. Whatever the kernel does not accept
        // right now falls back to the readiness-managed per-packet path, so
        // the tail behaves exactly like `send_to` (it parks on a full socket
        // buffer instead of spinning). On success `packets` is empty. On
        // error the kernel may have already transmitted a prefix while the
        // vector still lists it; gotatun's buffered sender drops the
        // remainder on error, which the trait allows.
        let mut sent = 0;
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        #[cfg(target_os = "linux")]
        while packets.len() - sent > 1 {
            match sendmmsg_batch(self, &packets[sent..])? {
                0 => break,
                count => sent += count,
            }
        }
        // The batched prefix has already left the process; drop it so the
        // readiness-managed tail sends only what the kernel did not accept.
        // Without this, a fully accepted `sendmmsg` would leave the whole
        // batch in `packets`, and gotatun's buffered sender (which reuses its
        // batch buffer after an `Ok`) would send every packet twice.
        packets.drain(..sent);
        for (packet, target) in packets.drain(..) {
            self.send_to(packet, target).await?;
        }
        Ok(())
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.0.socket.as_ref().unwrap().local_addr().map(Some)
    }
}

/// Sends the leading packets of `packets` in a single `sendmmsg` syscall and
/// returns how many were accepted. `Ok(0)` means the socket buffer is full
/// (or the call was interrupted) right now; any other error is propagated
/// with nothing removed from the caller's vector. Purely synchronous, so the
/// surrounding future stays cancel-safe and `Send`.
#[cfg(target_os = "linux")]
fn sendmmsg_batch(udp: &Udp, packets: &[(Packet, SocketAddr)]) -> io::Result<usize> {
    let count = packets.len().min(SEND_BATCH_MAX);
    let socket = udp.0.socket.as_ref().unwrap();
    // Stack storage reused within the call; the packets stay in the caller's
    // vector (referenced by the iovecs) until the syscall has completed.
    let mut messages: [libc::mmsghdr; SEND_BATCH_MAX] = unsafe { std::mem::zeroed() };
    let mut iovecs: [libc::iovec; SEND_BATCH_MAX] = unsafe { std::mem::zeroed() };
    let mut targets: [libc::sockaddr_storage; SEND_BATCH_MAX] = unsafe { std::mem::zeroed() };
    for (index, (packet, target)) in packets.iter().take(count).enumerate() {
        let mut target = *target;
        if udp.0.ipv6
            && let std::net::IpAddr::V4(ip) = target.ip()
        {
            target.set_ip(ip.to_ipv6_mapped().into());
        }
        targets[index] = socket_addr_storage(&target);
        let bytes: &[u8] = packet.as_ref();
        iovecs[index] = libc::iovec {
            iov_base: bytes.as_ptr() as *mut libc::c_void,
            iov_len: bytes.len(),
        };
        let header = &mut messages[index].msg_hdr;
        header.msg_name = (&raw mut targets[index]).cast();
        header.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as _;
        header.msg_iov = (&raw mut iovecs[index]).cast();
        header.msg_iovlen = 1;
    }
    let result = unsafe {
        libc::sendmmsg(
            std::os::fd::AsRawFd::as_raw_fd(socket),
            messages.as_mut_ptr(),
            count as libc::c_uint,
            libc::MSG_DONTWAIT,
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        // Transient "not now" conditions hand the batch back to the
        // readiness-managed tail; anything else is a real error.
        return match error.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(0),
            _ => Err(error),
        };
    }
    Ok(result as usize)
}

/// Scratch storage for `recv_many_from`. One set per receive task, lazily
/// created on first use so a carrier that never carries traffic never pays
/// for it.
#[derive(Default)]
pub(super) struct CarrierRecvBatch {
    buffers: Vec<Box<[u8]>>,
}

impl CarrierRecvBatch {
    fn ensure_slots(&mut self) {
        while self.buffers.len() < RECV_BATCH_SLOTS {
            self.buffers
                .push(vec![0; MAX_DATAGRAM_SCRATCH].into_boxed_slice());
        }
    }
}
impl UdpRecv for Udp {
    type RecvManyBuf = CarrierRecvBatch;
    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let mut buffer = self.0.receive_buffer.lock().await;
        let (len, source) = self
            .0
            .socket
            .as_ref()
            .unwrap()
            .recv_from(buffer.as_mut())
            .await?;
        let packet = pool.get().overwrite_with(&buffer[..len]);
        Ok((packet, super::canonical_socket_addr(source)))
    }
    async fn recv_many_from(
        &mut self,
        batch: &mut CarrierRecvBatch,
        pool: &mut PacketBufPool,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        batch.ensure_slots();
        // The first packet goes through the readiness-managed path: it parks
        // when the queue is empty and its WouldBlock handling keeps tokio's
        // readiness state consistent, which is what lets the synchronous
        // drain below exit without spinning. Cancel-safe: once that first
        // packet is observed, the drain runs to completion with no await.
        let (packet, source) = self.recv_from(pool).await?;
        packets.push((packet, source));
        // The kernel may have queued a burst while this task was parked;
        // coalesce it into one syscall per batch instead of one readiness
        // round trip per packet. A partial batch means the queue is drained;
        // a full batch may hold more, bounded by RECV_DRAIN_LIMIT so `packets`
        // cannot grow without bound in a single call.
        while packets.len() < RECV_DRAIN_LIMIT {
            #[cfg(target_os = "linux")]
            let received = recvmmsg_batch(self, batch, pool, packets)?;
            #[cfg(not(target_os = "linux"))]
            let received = try_recv_batch(self, batch, pool, packets)?;
            if received < RECV_BATCH_SLOTS {
                return Ok(());
            }
        }
        Ok(())
    }
}

/// Drains queued datagrams with one `recvmmsg` syscall into the batch's
/// scratch slots, appending them to `packets`. Returns how many datagrams the
/// syscall reported: `Ok(0)` when the queue is empty or the call was
/// interrupted, `RECV_BATCH_SLOTS` when it filled completely. Purely
/// synchronous.
#[cfg(target_os = "linux")]
fn recvmmsg_batch(
    udp: &Udp,
    batch: &mut CarrierRecvBatch,
    pool: &mut PacketBufPool,
    packets: &mut Vec<(Packet, SocketAddr)>,
) -> io::Result<usize> {
    let socket = udp.0.socket.as_ref().unwrap();
    let mut messages: [libc::mmsghdr; RECV_BATCH_SLOTS] = unsafe { std::mem::zeroed() };
    let mut iovecs: [libc::iovec; RECV_BATCH_SLOTS] = unsafe { std::mem::zeroed() };
    let mut sources: [libc::sockaddr_storage; RECV_BATCH_SLOTS] = unsafe { std::mem::zeroed() };
    for index in 0..RECV_BATCH_SLOTS {
        let slot = &mut batch.buffers[index];
        iovecs[index] = libc::iovec {
            iov_base: slot.as_mut_ptr().cast(),
            iov_len: slot.len(),
        };
        let header = &mut messages[index].msg_hdr;
        header.msg_name = (&raw mut sources[index]).cast();
        header.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as _;
        header.msg_iov = (&raw mut iovecs[index]).cast();
        header.msg_iovlen = 1;
    }
    let result = unsafe {
        libc::recvmmsg(
            std::os::fd::AsRawFd::as_raw_fd(socket),
            messages.as_mut_ptr(),
            RECV_BATCH_SLOTS as libc::c_uint,
            libc::MSG_DONTWAIT,
            std::ptr::null_mut(),
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        return match error.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(0),
            _ => Err(error),
        };
    }
    let count = result as usize;
    for index in 0..count {
        let header = &messages[index];
        // The kernel cuts a datagram off at the slot boundary and reports it
        // here. With 65535-byte slots this cannot happen for a valid UDP
        // datagram; refuse rather than feed a truncated payload to the
        // WireGuard device (which would reject it anyway).
        if header.msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
            continue;
        }
        let Some(source) = parse_socket_addr_storage(&sources[index]) else {
            continue;
        };
        packets.push((
            pool.get()
                .overwrite_with(&batch.buffers[index][..header.msg_len as usize]),
            super::canonical_socket_addr(source),
        ));
    }
    Ok(count)
}

/// Portable fallback draining queued datagrams through tokio's nonblocking
/// `try_recv_from`, which also keeps tokio's readiness bookkeeping correct.
#[cfg(not(target_os = "linux"))]
fn try_recv_batch(
    udp: &Udp,
    batch: &mut CarrierRecvBatch,
    pool: &mut PacketBufPool,
    packets: &mut Vec<(Packet, SocketAddr)>,
) -> io::Result<usize> {
    let socket = udp.0.socket.as_ref().unwrap();
    let mut received = 0;
    for slot in &mut batch.buffers[..RECV_BATCH_SLOTS] {
        match socket.try_recv_from(slot) {
            Ok((length, source)) => {
                packets.push((
                    pool.get().overwrite_with(&slot[..length]),
                    super::canonical_socket_addr(source),
                ));
                received += 1;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        }
    }
    Ok(received)
}

/// Converts a filled `sockaddr_storage` from `recvmmsg` into a `SocketAddr`.
#[cfg(target_os = "linux")]
fn parse_socket_addr_storage(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let address = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            Some(SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                    address.sin_addr.s_addr,
                ))),
                u16::from_be(address.sin_port),
            ))
        }
        libc::AF_INET6 => {
            let address = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            Some(SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(address.sin6_addr.s6_addr)),
                u16::from_be(address.sin6_port),
            ))
        }
        _ => None,
    }
}

/// Converts a `SocketAddr` into the kernel's `sockaddr_storage` layout.
#[cfg(target_os = "linux")]
fn socket_addr_storage(address: &SocketAddr) -> libc::sockaddr_storage {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    unsafe {
        match address {
            SocketAddr::V4(address) => {
                let sin = &mut *(&raw mut storage).cast::<libc::sockaddr_in>();
                sin.sin_family = libc::AF_INET as _;
                sin.sin_port = address.port().to_be();
                sin.sin_addr.s_addr = u32::from_ne_bytes(address.ip().octets());
            }
            SocketAddr::V6(address) => {
                let sin6 = &mut *(&raw mut storage).cast::<libc::sockaddr_in6>();
                sin6.sin6_family = libc::AF_INET6 as _;
                sin6.sin6_port = address.port().to_be();
                sin6.sin6_addr.s6_addr = address.ip().octets();
                sin6.sin6_scope_id = address.scope_id();
            }
        }
    }
    storage
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn carrier_receive_does_not_truncate_at_packet_pool_capacity() {
        let (mut factory, _released, address) =
            Factory::new(Some("127.0.0.1:0".parse().unwrap()), None).unwrap();
        let (_, mut receiver) = factory.0.take().unwrap();
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let payload = vec![0x7b; 5000];
        sender.send_to(&payload, address).await.unwrap();
        let mut pool: PacketBufPool = PacketBufPool::new(1);
        let (packet, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            receiver.recv_from(&mut pool),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(packet.as_ref(), payload);
    }

    #[tokio::test]
    async fn decrypted_udp_larger_than_local_transmit_mtu_is_preserved() {
        let (sender, mut receiver) = mpsc::channel(1);
        let (wake, _wake_rx) = Wake::new().unwrap();
        let drops = Arc::default();
        let mut sink = IpSink {
            sender,
            wake,
            drops: Arc::clone(&drops),
        };
        let bytes = crate::tun::udp_handler::build_udp_packet(
            &vec![0xa5; 5000],
            "10.77.0.1:1".parse().unwrap(),
            "10.77.0.2:2".parse().unwrap(),
        )
        .unwrap();
        let pool: PacketBufPool = PacketBufPool::new(1);
        let packet = pool.get().overwrite_with(&*bytes).try_into_ip().unwrap();
        sink.send(packet).await.unwrap();
        let received = receiver.recv().await.unwrap();
        assert_eq!(&*received, &*bytes);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert!(
            received.lease().is_some(),
            "decrypted UDP queue retains its byte reservation"
        );
    }

    #[tokio::test]
    async fn decrypted_packets_wait_for_capacity_and_fail_only_when_closed() {
        let (sender, mut receiver) = mpsc::channel(1);
        let (wake, _wake_rx) = Wake::new().unwrap();
        let drops = Arc::default();
        let mut sink = IpSink {
            sender,
            wake,
            drops: Arc::clone(&drops),
        };
        let bytes = crate::tun::udp_handler::build_udp_packet(
            b"packet",
            "10.77.0.1:1".parse().unwrap(),
            "10.77.0.2:2".parse().unwrap(),
        )
        .unwrap();
        let pool: PacketBufPool = PacketBufPool::new(4);
        sink.sender
            .send(PacketBuffer::copy_from_slice(b"full"))
            .await
            .unwrap();
        let packet = pool.get().overwrite_with(&*bytes).try_into_ip().unwrap();
        {
            let send = sink.send(packet);
            tokio::pin!(send);
            assert!(futures::poll!(&mut send).is_pending());
            assert_eq!(&*receiver.recv().await.unwrap(), b"full");
            send.await.unwrap();
        }
        assert_eq!(&*receiver.recv().await.unwrap(), &*bytes);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        drop(receiver);
        let packet = pool.get().overwrite_with(&*bytes).try_into_ip().unwrap();
        assert_eq!(
            sink.send(packet).await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    /// Round-trips an ordered batch through `send_many_to` and
    /// `recv_many_from` on loopback, exercising the batched syscall paths
    /// (`sendmmsg`/`recvmmsg` on Linux, the portable drain elsewhere). The
    /// peer echoes every datagram back, since a transport send lands in the
    /// peer's queue, not the carrier's.
    #[tokio::test]
    async fn batched_send_and_receive_preserve_order_contents_and_addresses() {
        let (mut factory, _released, _address) =
            Factory::new(Some("127.0.0.1:0".parse().unwrap()), None).unwrap();
        let (transport, mut receiver) = factory.0.take().unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_address = peer.local_addr().unwrap();
        let total = RECV_BATCH_SLOTS + 2;
        let pool: PacketBufPool = PacketBufPool::new(total);
        let mut batch = Vec::new();
        for index in 0..total {
            let payload = vec![index as u8; 16 + index * 400];
            let mut packet = pool.get();
            packet.truncate(payload.len());
            packet.copy_from_slice(&payload);
            batch.push((packet, peer_address));
        }
        let mut send_buf = <UdpSender as UdpSend>::SendManyBuf::default();
        transport
            .send_many_to(&mut send_buf, &mut batch)
            .await
            .unwrap();
        assert!(batch.is_empty(), "a completed send_many_to must drain the batch");
        // The peer observes the batched send, then echoes each datagram back
        // to the carrier so the batched receive can observe it in order.
        echo_back(&peer, total).await;
        let mut receive_pool: PacketBufPool = PacketBufPool::new(total);
        let mut recv_buf = <UdpReceiver as UdpRecv>::RecvManyBuf::default();
        let mut received = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while received.len() < total {
                receiver
                    .recv_many_from(&mut recv_buf, &mut receive_pool, &mut received)
                    .await
                    .unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(received.len(), total);
        for (index, (packet, source)) in received.iter().enumerate() {
            assert_eq!(packet.len(), 16 + index * 400);
            assert!(packet.as_ref().iter().all(|byte| *byte == index as u8));
            assert_eq!(*source, peer_address);
        }
    }

    /// A datagram far larger than the 4096-byte packet pool must survive the
    /// batched receive path intact, exactly like the single-packet path. The
    /// portable size stays under the 9216-byte macOS default send buffer,
    /// which rejects bigger datagrams with EMSGSIZE; Linux additionally gets
    /// a full-size 60000-byte variant below.
    #[tokio::test]
    async fn batched_receive_preserves_oversized_datagrams() {
        let (mut factory, _released, address) =
            Factory::new(Some("127.0.0.1:0".parse().unwrap()), None).unwrap();
        let (transport, mut receiver) = factory.0.take().unwrap();
        drop(transport);
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_address = peer.local_addr().unwrap();
        let payload: Vec<u8> = (0..8000u32).map(|byte| byte as u8).collect();
        peer.send_to(&payload, address).await.unwrap();
        let mut receive_pool: PacketBufPool = PacketBufPool::new(1);
        let mut recv_buf = <UdpReceiver as UdpRecv>::RecvManyBuf::default();
        let mut received = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            receiver.recv_many_from(&mut recv_buf, &mut receive_pool, &mut received),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].0.as_ref(), payload);
        assert_eq!(received[0].1, peer_address);
    }

    /// Linux can queue and drain a full-size 60000-byte datagram through the
    /// batched scratch slots without truncation.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn batched_receive_preserves_full_size_datagrams() {
        let (mut factory, _released, address) =
            Factory::new(Some("127.0.0.1:0".parse().unwrap()), None).unwrap();
        let (transport, mut receiver) = factory.0.take().unwrap();
        drop(transport);
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let payload: Vec<u8> = (0..60_000u32).map(|byte| byte as u8).collect();
        peer.send_to(&payload, address).await.unwrap();
        let mut receive_pool: PacketBufPool = PacketBufPool::new(1);
        let mut recv_buf = <UdpReceiver as UdpRecv>::RecvManyBuf::default();
        let mut received = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            receiver.recv_many_from(&mut recv_buf, &mut receive_pool, &mut received),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].0.as_ref(), payload);
    }

    /// A single datagram must still flow through `recv_many_from` without a
    /// spurious second wake (the drain observes an empty queue immediately).
    #[tokio::test]
    async fn single_packet_round_trip_through_batched_paths() {
        let (mut factory, _released, _address) =
            Factory::new(Some("127.0.0.1:0".parse().unwrap()), None).unwrap();
        let (transport, mut receiver) = factory.0.take().unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_address = peer.local_addr().unwrap();
        let pool: PacketBufPool = PacketBufPool::new(1);
        let payload = b"single";
        let mut packet = pool.get();
        packet.truncate(payload.len());
        packet.copy_from_slice(&payload[..]);
        let mut batch = vec![(packet, peer_address)];
        let mut send_buf = <UdpSender as UdpSend>::SendManyBuf::default();
        transport
            .send_many_to(&mut send_buf, &mut batch)
            .await
            .unwrap();
        assert!(batch.is_empty());
        echo_back(&peer, 1).await;
        let mut receive_pool: PacketBufPool = PacketBufPool::new(1);
        let mut recv_buf = <UdpReceiver as UdpRecv>::RecvManyBuf::default();
        let mut received = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            receiver.recv_many_from(&mut recv_buf, &mut receive_pool, &mut received),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].0.as_ref(), payload);
        assert_eq!(received[0].1, peer_address);
    }

    /// Echoes `count` datagrams received by `peer` back to their source (the
    /// carrier), letting a transport-originated send reach the carrier's
    /// receiver. Reply goes to the observed source so the carrier address
    /// never has to be threaded through the caller.
    async fn echo_back(peer: &tokio::net::UdpSocket, count: usize) {
        let mut buffer = vec![0u8; MAX_DATAGRAM_SCRATCH];
        for _ in 0..count {
            let (length, source) = peer.recv_from(&mut buffer).await.unwrap();
            peer.send_to(&buffer[..length], source).await.unwrap();
        }
    }

    /// The direct carrier must advertise batching so gotatun's buffered
    /// sender drains its channel in whole batches.
    #[tokio::test]
    async fn direct_carrier_advertises_batched_sends() {
        let (mut factory, _released, _) =
            Factory::new(Some("127.0.0.1:0".parse().unwrap()), None).unwrap();
        let (transport, _) = factory.0.take().unwrap();
        assert_eq!(
            transport.max_number_of_packets_to_send(),
            SEND_BATCH_MAX,
            "direct carrier must advertise batching"
        );
        let carrier = match &transport {
            UdpSender::Direct(carrier) => carrier,
            UdpSender::Detour(_) => unreachable!(),
        };
        assert_eq!(
            gotatun::udp::UdpSend::max_number_of_packets_to_send(carrier),
            SEND_BATCH_MAX
        );
    }
}
