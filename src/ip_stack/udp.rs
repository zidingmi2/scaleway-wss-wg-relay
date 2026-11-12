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
};
use tokio::io::ReadBuf;

const FLOW_QUEUE_CAPACITY: usize = 8;

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
}

impl UdpControl {
    pub fn receive(&mut self, packet: PacketBuffer) -> bool {
        if self.closed || self.incoming.len() == FLOW_QUEUE_CAPACITY {
            return false;
        }
        let Some(permits) = udp_budget::reserve(&self.budget, packet.len()) else {
            return false;
        };
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
