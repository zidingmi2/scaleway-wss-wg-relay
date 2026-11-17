use super::{packet::PacketBuffer, wake::Wake};
use crate::atomic::AtomicU64;
use crate::{async_stream::*, resources::Budget, udp_budget};
use parking_lot::Mutex;
use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::io::ReadBuf;

const FLOW_QUEUE_CAPACITY: usize = 8;

/// Idle lifetime of an outbound UDP flow (one local-address five-tuple). The
/// stack thread reaps flows after this long without a send or a receive, so
/// abandoned DNS or UDP sessions cannot accumulate for the process lifetime on
/// a 128 MB host. Pending datagrams keep the flow alive until they drain;
/// registered readers do not count as traffic and are woken on expiry. A
/// reaped flow surfaces as BrokenPipe on the next handle use, matching the
/// existing close semantics.
pub(crate) const UDP_FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

pub(crate) struct Datagram {
    pub packet: PacketBuffer,
}

pub(crate) struct UdpControl {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub incoming: VecDeque<Datagram>,
    pub outgoing: VecDeque<Datagram>,
    pub reader: Option<Waker>,
    pub writer: Option<Waker>,
    pub closed: bool,
    pub budget: Arc<Budget>,
    pub last_activity: std::time::Instant,
}

impl UdpControl {
    pub fn receive(&mut self, packet: PacketBuffer) -> bool {
        if self.closed || self.incoming.len() == FLOW_QUEUE_CAPACITY {
            return false;
        }
        let Some(permits) = udp_budget::reserve(&self.budget, packet.len()) else {
            return false;
        };
        self.last_activity = std::time::Instant::now();
        self.incoming.push_back(Datagram {
            packet: packet.into_payload(true).with_lease(Arc::new(permits)),
        });
        if let Some(waker) = self.reader.take() {
            waker.wake();
        }
        true
    }
    pub fn close(&mut self) {
        self.closed = true;
        self.incoming.clear();
        self.outgoing.clear();
        if let Some(waker) = self.reader.take() {
            waker.wake();
        }
        if let Some(waker) = self.writer.take() {
            waker.wake();
        }
    }
    /// Closes and reports reaping for flows idle past [`UDP_FLOW_IDLE_TIMEOUT`]
    /// with no pending work. Returns whether the flow should be removed.
    pub fn reap_if_expired(&mut self) -> bool {
        if self.closed {
            return true;
        }
        if self.idle_delay(std::time::Instant::now()) == Some(Duration::ZERO) {
            self.close();
            return true;
        }
        false
    }

    /// Pending datagrams must drain before the idle timer can close a flow.
    pub fn idle_delay(&self, now: std::time::Instant) -> Option<Duration> {
        self.idle_deadline()
            .map(|deadline| deadline.saturating_duration_since(now))
    }

    pub fn idle_deadline(&self) -> Option<std::time::Instant> {
        if self.closed || !self.incoming.is_empty() || !self.outgoing.is_empty() {
            return None;
        }
        Some(self.last_activity + UDP_FLOW_IDLE_TIMEOUT)
    }
}

pub(crate) struct UdpConnection {
    pub control: Arc<Mutex<UdpControl>>,
    pub wake: Wake,
    pub mtu: usize,
    pub drops: Arc<AtomicU64>,
}

impl Drop for UdpConnection {
    fn drop(&mut self) {
        self.control.lock().close();
        self.wake.notify();
    }
}

impl AsyncReadMessage for UdpConnection {
    fn read_message_eof_on_empty(&self) -> bool {
        false
    }
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut control = self.control.lock();
        if let Some(datagram) = control.incoming.pop_front() {
            let drained = control.incoming.is_empty();
            drop(control);
            if drained {
                // Queued input suppresses the idle timer. Recompute its
                // deadline when the final datagram leaves the queue, even if
                // no later packet or connection command arrives.
                self.wake.notify();
            }
            if buf.remaining() < datagram.packet.len() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP receive buffer too small",
                )));
            }
            buf.put_slice(&datagram.packet);
            return Poll::Ready(Ok(()));
        }
        if control.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        control.reader = Some(cx.waker().clone());
        Poll::Pending
    }
}
impl AsyncWriteMessage for UdpConnection {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<()>> {
        let mut control = self.control.lock();
        if control.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let ipv4 = control.local.is_ipv4();
        let overhead = if ipv4 { 28 } else { 48 };
        if data.len() > if ipv4 { 65507 } else { 65527 } {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP payload exceeds IP length limit",
            )));
        }
        if control.outgoing.len() == FLOW_QUEUE_CAPACITY {
            control.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let reservation =
            super::ipv4_fragments::output_reservation(data.len() + overhead, ipv4, self.mtu)?;
        let Some(permits) = udp_budget::reserve(&control.budget, reservation) else {
            self.drops.fetch_add(1, Ordering::Relaxed);
            return Poll::Ready(Ok(()));
        };
        control.last_activity = std::time::Instant::now();
        // This path deliberately uses exact, nonpooled storage: small datagrams
        // must not pin a jumbo packet allocation or hide capacity from budgets.
        let builder = match (control.local, control.remote) {
            (SocketAddr::V4(local), SocketAddr::V4(remote)) => {
                etherparse::PacketBuilder::ipv4(local.ip().octets(), remote.ip().octets(), 64)
                    .udp(local.port(), remote.port())
            }
            (SocketAddr::V6(local), SocketAddr::V6(remote)) => {
                etherparse::PacketBuilder::ipv6(local.ip().octets(), remote.ip().octets(), 64)
                    .udp(local.port(), remote.port())
            }
            _ => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP address family mismatch",
                )));
            }
        };
        let mut bytes = vec![0; builder.size(data.len())];
        builder
            .write(&mut &mut bytes[..], data)
            .map_err(io::Error::other)?;
        let packet = PacketBuffer::from_vec(bytes).with_lease(Arc::new(permits));
        control.outgoing.push_back(Datagram { packet });
        drop(control);
        self.wake.notify();
        Poll::Ready(Ok(()))
    }
}
impl AsyncFlushMessage for UdpConnection {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut control = self.control.lock();
        if control.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if control.outgoing.is_empty() {
            return Poll::Ready(Ok(()));
        }
        control.writer = Some(cx.waker().clone());
        Poll::Pending
    }
}
impl AsyncShutdownMessage for UdpConnection {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush_message(cx))?;
        self.control.lock().close();
        self.wake.notify();
        Poll::Ready(Ok(()))
    }
}
impl AsyncPing for UdpConnection {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncMessageStream for UdpConnection {}

#[cfg(test)]
mod tests {
    use super::*;

    fn control() -> UdpControl {
        UdpControl {
            local: "10.77.0.2:40000".parse().unwrap(),
            remote: "10.77.0.1:53".parse().unwrap(),
            incoming: Default::default(),
            outgoing: Default::default(),
            reader: None,
            writer: None,
            closed: false,
            budget: Arc::new(Budget::new(Some(4096))),
            last_activity: std::time::Instant::now(),
        }
    }

    #[test]
    fn idle_deadline_preserves_fresh_flows_and_pending_datagrams() {
        let mut control = control();
        let start = control.last_activity;
        assert_eq!(control.idle_delay(start), Some(UDP_FLOW_IDLE_TIMEOUT));
        assert_eq!(
            control.idle_delay(start + UDP_FLOW_IDLE_TIMEOUT - Duration::from_nanos(1)),
            Some(Duration::from_nanos(1))
        );
        assert_eq!(
            control.idle_delay(start + UDP_FLOW_IDLE_TIMEOUT),
            Some(Duration::ZERO)
        );
        assert!(!control.reap_if_expired());

        control.last_activity = start - UDP_FLOW_IDLE_TIMEOUT - Duration::from_secs(1);
        control.incoming.push_back(Datagram {
            packet: PacketBuffer::copy_from_slice(b"pending reply"),
        });
        assert_eq!(control.idle_delay(start), None);
        assert!(!control.reap_if_expired());
        control.outgoing.append(&mut control.incoming);
        assert_eq!(control.idle_delay(start), None);
        assert!(!control.reap_if_expired());
        control.outgoing.clear();
        assert!(control.reap_if_expired());
        assert!(control.closed);
    }

    #[test]
    fn draining_last_reply_reschedules_idle_expiry_even_with_a_short_buffer() {
        for short_buffer in [false, true] {
            let mut control = control();
            control.last_activity -= UDP_FLOW_IDLE_TIMEOUT + Duration::from_secs(1);
            control.incoming.push_back(Datagram {
                packet: PacketBuffer::copy_from_slice(b"reply"),
            });
            let (wake, wake_rx) = Wake::new().unwrap();
            let mut stream = UdpConnection {
                control: Arc::new(Mutex::new(control)),
                wake,
                mtu: 1280,
                drops: Arc::default(),
            };
            assert!(!wake_rx.wait(-1, Some(Duration::ZERO)).unwrap());
            let mut bytes = [0; 5];
            let mut buf = ReadBuf::new(if short_buffer { &mut [] } else { &mut bytes });
            let mut cx = Context::from_waker(Waker::noop());
            let Poll::Ready(result) = Pin::new(&mut stream).poll_read_message(&mut cx, &mut buf)
            else {
                panic!("the queued datagram must be ready");
            };
            if short_buffer {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
            } else {
                result.unwrap();
                assert_eq!(buf.filled(), b"reply");
            }
            assert!(wake_rx.wait(-1, Some(Duration::ZERO)).unwrap());
            assert!(stream.control.lock().reap_if_expired());
        }
    }
}
