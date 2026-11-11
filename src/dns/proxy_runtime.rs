//! RuntimeProvider for DNS TCP and fixed-peer UDP through proxy/WireGuard chains.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

#[cfg(not(feature = "relay-minimal"))]
use hickory_resolver::net::runtime::QuicSocketBinder;
use hickory_resolver::net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::net::runtime::{DnsUdpSocket, RuntimeProvider, Spawn, TokioTime};
use tokio::io::ReadBuf;

use crate::address::{Address, NetLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::client_proxy_chain::ClientChainGroup;
use crate::resolver::Resolver;

#[cfg(test)]
const TEST_CONNECT_TIMEOUT: Duration = Duration::from_millis(100);

/// TCP and UDP use the selected chain; only explicitly direct chains create
/// native UDP sockets. QUIC, when compiled, still requires a direct-only chain.
#[derive(Clone)]
pub struct ProxyRuntimeProvider {
    chain_group: Arc<ClientChainGroup>,
    /// Resolver for proxy server hostnames (not the DNS queries themselves).
    /// Uses the explicit bootstrap route, or native DNS when none was configured.
    bootstrap_resolver: Arc<dyn Resolver>,
    /// QUIC socket binder that selects from the same direct-only chain.
    #[cfg(not(feature = "relay-minimal"))]
    quic_binder: ProxyQuicBinder,
    /// Timeout for establishing connections to DNS upstreams.
    connect_timeout: Duration,
}

impl ProxyRuntimeProvider {
    /// Create with the given chain group, bootstrap resolver, and connect timeout.
    pub fn with_bootstrap(
        chain_group: Arc<ClientChainGroup>,
        bootstrap_resolver: Arc<dyn Resolver>,
        connect_timeout: Duration,
    ) -> Self {
        #[cfg(not(feature = "relay-minimal"))]
        let quic_binder = ProxyQuicBinder {
            chain_group: chain_group.clone(),
            memory_bytes: crate::resources::limits().quic_dns_memory_bytes,
            socket_buffer: crate::resources::limits().quic_socket_buffer,
        };
        Self {
            chain_group,
            bootstrap_resolver,
            #[cfg(not(feature = "relay-minimal"))]
            quic_binder,
            connect_timeout,
        }
    }

    pub fn with_quic_memory(mut self, bytes: usize) -> Self {
        #[cfg(not(feature = "relay-minimal"))]
        {
            self.quic_binder.memory_bytes = bytes;
        }
        #[cfg(feature = "relay-minimal")]
        let _ = bytes;
        self
    }

    pub fn with_quic_socket_buffer(mut self, bytes: usize) -> Self {
        #[cfg(not(feature = "relay-minimal"))]
        {
            self.quic_binder.socket_buffer = bytes;
        }
        #[cfg(feature = "relay-minimal")]
        let _ = bytes;
        self
    }
}

/// Spawn handle for tokio runtime.
#[derive(Clone, Default)]
pub struct TokioSpawnHandle;

impl Spawn for TokioSpawnHandle {
    fn spawn_bg(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        tokio::spawn(future);
    }
}

/// Type alias for our wrapped TCP stream.
type ProxiedTcp = AsyncIoTokioAsStd<Box<dyn AsyncStream>>;

/// Hickory's socket contract over either a real UDP socket or a fixed-peer
/// datagram tunnel. A tunnel must never fall back to a native socket on failure.
pub enum ProxyUdpSocket {
    Native(tokio::net::UdpSocket),
    Tunnel {
        server: SocketAddr,
        local: SocketAddr,
        state: parking_lot::Mutex<TunnelUdpState>,
    },
}

pub struct TunnelUdpState {
    stream: Box<dyn AsyncMessageStream>,
    // Hickory serializes sends. Retain a datagram accepted by the transport
    // until its flush completes so a Pending poll cannot enqueue it twice.
    pending_send: Option<PendingDnsDatagram>,
}

struct PendingDnsDatagram {
    bytes: Box<[u8]>,
    _permit: crate::resources::BudgetPermit,
}

impl ProxyUdpSocket {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Native(socket) => socket.local_addr(),
            Self::Tunnel { local, .. } => Ok(*local),
        }
    }
}

impl DnsUdpSocket for ProxyUdpSocket {
    type Time = TokioTime;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        match self {
            Self::Native(socket) => DnsUdpSocket::poll_recv_from(socket, cx, buf),
            Self::Tunnel { server, state, .. } => {
                let mut state = state.lock();
                let mut read = ReadBuf::new(buf);
                ready!(Pin::new(&mut *state.stream).poll_read_message(cx, &mut read))?;
                if read.filled().is_empty() && state.stream.read_message_eof_on_empty() {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                Poll::Ready(Ok((read.filled().len(), *server)))
            }
        }
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        match self {
            Self::Native(socket) => DnsUdpSocket::poll_send_to(socket, cx, buf, target),
            Self::Tunnel { server, state, .. } => {
                if target != *server {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "DNS tunnel is pinned to its configured upstream",
                    )));
                }
                if buf.len() > 65_507 {
                    return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
                }
                let mut state = state.lock();
                if state.pending_send.is_some() {
                    ready!(Pin::new(&mut *state.stream).poll_flush_message(cx))?;
                    let completed = state.pending_send.take().unwrap();
                    if completed.bytes.as_ref() == buf {
                        return Poll::Ready(Ok(buf.len()));
                    }
                    // The previous sender was canceled after acceptance. Finish
                    // that flush, then accept the next distinct datagram.
                }
                // Reserve the possible retained copy before a send side effect.
                // The transport's own queued copy has a separate charge.
                let permit = crate::udp_budget::global()
                    .acquire(buf.len())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "DNS datagram memory budget exhausted",
                        )
                    })?;
                ready!(Pin::new(&mut *state.stream).poll_write_message(cx, buf))?;
                match Pin::new(&mut *state.stream).poll_flush_message(cx) {
                    Poll::Ready(result) => Poll::Ready(result.map(|()| buf.len())),
                    Poll::Pending => {
                        state.pending_send = Some(PendingDnsDatagram {
                            bytes: buf.into(),
                            _permit: permit,
                        });
                        Poll::Pending
                    }
                }
            }
        }
    }
}

impl RuntimeProvider for ProxyRuntimeProvider {
    type Handle = TokioSpawnHandle;
    type Timer = TokioTime;
    type Udp = ProxyUdpSocket;
    type Tcp = ProxiedTcp;

    fn create_handle(&self) -> Self::Handle {
        TokioSpawnHandle
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        _bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Tcp, io::Error>>>> {
        let chain_group = self.chain_group.clone();
        let resolver = self.bootstrap_resolver.clone();
        let timeout = timeout
            .map(|timeout| timeout.min(self.connect_timeout))
            .unwrap_or(self.connect_timeout);

        Box::pin(async move {
            let address = match server_addr.ip() {
                IpAddr::V4(addr) => Address::Ipv4(addr),
                IpAddr::V6(addr) => Address::Ipv6(addr),
            };
            let target = NetLocation::new(address, server_addr.port());

            let started = std::time::Instant::now();
            let connect_future = chain_group.connect_tcp(target.into(), &resolver);
            match tokio::time::timeout(timeout, connect_future).await {
                Ok(Ok(result)) => {
                    log::debug!(
                        "DNS upstream connect to {} succeeded in {:?}",
                        server_addr,
                        started.elapsed()
                    );
                    let stream: Box<dyn AsyncStream> =
                        Box::new(crate::prepend_stream::PrependStream::new(
                            result.client_stream,
                            result.early_data.map(Vec::into_boxed_slice),
                        ));
                    Ok(AsyncIoTokioAsStd(stream))
                }
                Ok(Err(e)) => {
                    log::warn!(
                        "DNS upstream connect to {} failed in {:?}: {}",
                        server_addr,
                        started.elapsed(),
                        e
                    );
                    Err(e)
                }
                Err(_) => {
                    log::warn!(
                        "DNS upstream connect to {} timed out in {:?}",
                        server_addr,
                        started.elapsed()
                    );
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "DNS server connection to {server_addr} timed out after {timeout:?}"
                        ),
                    ))
                }
            }
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Udp, io::Error>>>> {
        let chain_group = self.chain_group.clone();
        let resolver = self.bootstrap_resolver.clone();
        let timeout = self.connect_timeout;

        Box::pin(async move {
            if chain_group.is_direct_only() {
                let bind_interface = chain_group.select_bind_interface()?;
                let socket = crate::socket_util::new_outbound_socket2_udp_socket(
                    local_addr.is_ipv6(),
                    bind_interface,
                    Some(local_addr),
                )?;
                return tokio::net::UdpSocket::from_std(socket.into()).map(ProxyUdpSocket::Native);
            }
            let target = NetLocation::from_ip_addr(server_addr.ip(), server_addr.port());
            let stream = tokio::time::timeout(
                timeout,
                chain_group.connect_udp_with_info(&resolver, target.into(), Default::default()),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS tunnel setup timed out"))??;
            Ok(ProxyUdpSocket::Tunnel {
                server: server_addr,
                local: local_addr,
                state: parking_lot::Mutex::new(TunnelUdpState {
                    stream,
                    pending_send: None,
                }),
            })
        })
    }

    #[cfg(not(feature = "relay-minimal"))]
    fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
        self.chain_group
            .is_direct_only()
            .then_some(&self.quic_binder as &dyn QuicSocketBinder)
    }
}

/// QUIC socket binder that supports bind_interface.
#[derive(Clone)]
#[cfg(not(feature = "relay-minimal"))]
struct ProxyQuicBinder {
    chain_group: Arc<ClientChainGroup>,
    memory_bytes: usize,
    socket_buffer: usize,
}

#[cfg(not(feature = "relay-minimal"))]
impl QuicSocketBinder for ProxyQuicBinder {
    fn bind_quic(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Result<Arc<dyn quinn::AsyncUdpSocket>, io::Error> {
        let memory = crate::resources::try_quic_memory(self.memory_bytes)
            .ok_or_else(|| crate::resources::quic_memory_exhausted(self.memory_bytes))?;
        let socket = crate::socket_util::new_outbound_socket2_udp_socket(
            local_addr.is_ipv6(),
            self.chain_group.select_bind_interface()?,
            Some(local_addr),
        )?;
        crate::socket_util::set_udp_socket_buffers(
            socket2::SockRef::from(&socket),
            self.socket_buffer,
        );
        crate::quic_endpoint::socket_with_memory(socket.into(), memory)
    }
}

#[cfg(test)]
mod tests;
