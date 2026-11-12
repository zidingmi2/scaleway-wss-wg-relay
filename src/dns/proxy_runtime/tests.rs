use super::*;
use crate::async_stream::AsyncMessageStream;
use crate::client_proxy_chain::{ClientProxyChain, InitialHopEntry};
use crate::resolver::NativeResolver;
use crate::tcp::chain_builder::build_direct_chain_group;
use crate::tcp::socket_connector::SocketConnector;
use async_trait::async_trait;

#[tokio::test]
#[cfg(not(feature = "relay-minimal"))]
async fn downstream_dns_proxy_names_remain_remote_for_forwarding() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Debug)]
    struct RemoteOnly;
    impl Resolver for RemoteOnly {
        fn resolve_location(&self, location: &NetLocation) -> crate::resolver::ResolveFuture {
            assert_eq!(location.address().to_string(), "second.invalid");
            Box::pin(async { Err(io::Error::other("proxy name is only resolvable remotely")) })
        }
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first = listener.local_addr().unwrap();
    let fixture = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (mut stream, _) = listener.accept().await.unwrap();
            for downstream in [true, false] {
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                stream.write_all(&[5, 0]).await.unwrap();
                let mut header = [0; 4];
                stream.read_exact(&mut header).await.unwrap();
                assert_eq!(header, [5, 1, 0, if downstream { 3 } else { 1 }]);
                if downstream {
                    let length = stream.read_u8().await.unwrap();
                    let mut name = vec![0; length as usize];
                    stream.read_exact(&mut name).await.unwrap();
                    assert_eq!(name, b"second.invalid");
                    assert_eq!(stream.read_u16().await.unwrap(), 1080);
                } else {
                    let mut address = [0; 4];
                    stream.read_exact(&mut address).await.unwrap();
                    assert_eq!(address, [192, 0, 2, 53]);
                    assert_eq!(stream.read_u16().await.unwrap(), 80);
                }
                stream
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                    .await
                    .unwrap();
            }
            assert!(stream.read_u8().await.is_err());
        })
        .await
        .unwrap();
    });
    let resolver: Arc<dyn Resolver> = Arc::new(RemoteOnly);
    let chain = crate::config::test_support::from_json(serde_json::json!([
        {"address": first.to_string(), "protocol": {"type": "socks"}},
        {"address": "second.invalid:1080", "protocol": {"type": "socks"}}
    ]))
    .unwrap();
    let chains = Arc::new(
        crate::tcp::chain_builder::build_client_chain_group_with_limits(
            crate::option_util::NoneOrSome::One(chain),
            resolver.clone(),
            Default::default(),
        )
        .unwrap(),
    );
    let provider = ProxyRuntimeProvider::with_bootstrap(chains, resolver, Duration::from_secs(2));
    drop(
        provider
            .connect_tcp("192.0.2.53:80".parse().unwrap(), None, None)
            .await
            .unwrap(),
    );
    fixture.await.unwrap();
}

#[derive(Debug)]
struct PendingSocketConnector;

#[async_trait]
impl SocketConnector for PendingSocketConnector {
    async fn connect(
        &self,
        _resolver: &Arc<dyn Resolver>,
        _address: &crate::address::ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncStream>> {
        std::future::pending().await
    }

    async fn connect_udp_bidirectional(
        &self,
        _resolver: &Arc<dyn Resolver>,
        _target: crate::address::ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        unreachable!("TCP timeout tests do not open UDP streams")
    }

    fn bind_interface(&self) -> Option<&str> {
        None
    }
}

fn build_pending_chain_group() -> ClientChainGroup {
    ClientChainGroup::new(vec![ClientProxyChain::new(
        vec![InitialHopEntry::Direct(Arc::new(PendingSocketConnector))],
        vec![],
    )])
}

#[test]
fn test_provider_is_clone() {
    // RuntimeProvider requires Clone
    let resolver = Arc::new(NativeResolver::new());
    let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
    let provider =
        ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, TEST_CONNECT_TIMEOUT);
    let _cloned = provider.clone();
}

#[derive(Debug, Default)]
struct DatagramFixture {
    opened: parking_lot::Mutex<Vec<SocketAddr>>,
    sent: parking_lot::Mutex<Vec<Vec<u8>>>,
    incoming: parking_lot::Mutex<std::collections::VecDeque<Vec<u8>>>,
    flush_ready: std::sync::atomic::AtomicBool,
    fail: bool,
    hang: bool,
}

#[derive(Debug)]
struct FakeTunnelConnector(Arc<DatagramFixture>);

#[async_trait]
impl SocketConnector for FakeTunnelConnector {
    async fn connect(
        &self,
        _: &Arc<dyn Resolver>,
        _: &crate::address::ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncStream>> {
        panic!("UDP DNS must not open TCP or a native DNS fallback")
    }
    async fn connect_udp_bidirectional(
        &self,
        _: &Arc<dyn Resolver>,
        target: crate::address::ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        self.0
            .opened
            .lock()
            .push(target.location().to_socket_addr_nonblocking().unwrap());
        if self.0.hang {
            std::future::pending::<()>().await;
        }
        if self.0.fail {
            return Err(io::ErrorKind::ConnectionRefused.into());
        }
        Ok(Box::new(FakeDatagramStream(self.0.clone())))
    }
    fn bind_interface(&self) -> Option<&str> {
        None
    }
}

struct FakeDatagramStream(Arc<DatagramFixture>);

impl crate::async_stream::AsyncReadMessage for FakeDatagramStream {
    fn read_message_eof_on_empty(&self) -> bool {
        false
    }
    fn poll_read_message(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(bytes) = self.0.incoming.lock().pop_front() {
            if bytes.len() > buf.remaining() {
                return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
            }
            buf.put_slice(&bytes);
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}
impl crate::async_stream::AsyncWriteMessage for FakeDatagramStream {
    fn poll_write_message(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<()>> {
        self.0.sent.lock().push(bytes.to_vec());
        Poll::Ready(Ok(()))
    }
}
impl crate::async_stream::AsyncFlushMessage for FakeDatagramStream {
    fn poll_flush_message(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self
            .0
            .flush_ready
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}
impl crate::async_stream::AsyncShutdownMessage for FakeDatagramStream {
    fn poll_shutdown_message(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl crate::async_stream::AsyncPing for FakeDatagramStream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncMessageStream for FakeDatagramStream {}

fn fake_tunnel_provider(fixture: Arc<DatagramFixture>) -> ProxyRuntimeProvider {
    let chains = ClientChainGroup::new(vec![ClientProxyChain::new(
        vec![InitialHopEntry::Wireguard(Arc::new(FakeTunnelConnector(
            fixture,
        )))],
        vec![],
    )]);
    ProxyRuntimeProvider::with_bootstrap(
        Arc::new(chains),
        Arc::new(NativeResolver::new()),
        TEST_CONNECT_TIMEOUT,
    )
}

#[tokio::test]
async fn udp_dns_tunnel_preserves_datagrams_and_pins_upstream() {
    let fixture = Arc::new(DatagramFixture::default());
    let provider = fake_tunnel_provider(fixture.clone());
    let upstream: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let socket = provider
        .bind_udp("0.0.0.0:0".parse().unwrap(), upstream)
        .await
        .unwrap();
    assert_eq!(*fixture.opened.lock(), [upstream]);
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(
        socket
            .poll_send_to(&mut cx, b"query", upstream)
            .is_pending()
    );
    assert!(
        socket
            .poll_send_to(&mut cx, b"query", upstream)
            .is_pending()
    );
    assert_eq!(
        fixture.sent.lock().len(),
        1,
        "Pending flush must not duplicate a DNS query"
    );
    fixture
        .flush_ready
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(
        socket.poll_send_to(&mut cx, b"query", upstream),
        Poll::Ready(Ok(5))
    ));
    assert!(matches!(
        socket.poll_send_to(&mut cx, b"query", "192.0.2.54:53".parse().unwrap()),
        Poll::Ready(Err(_))
    ));
    fixture.incoming.lock().push_back(b"answer".to_vec());
    let mut bytes = [0; 32];
    assert!(
        matches!(socket.poll_recv_from(&mut cx, &mut bytes), Poll::Ready(Ok((6, peer))) if peer == upstream)
    );
    assert_eq!(&bytes[..6], b"answer");
}

#[tokio::test(start_paused = true)]
async fn udp_dns_tunnel_setup_failure_never_falls_back_to_native_socket() {
    for hang in [false, true] {
        let fixture = Arc::new(DatagramFixture {
            fail: !hang,
            hang,
            ..Default::default()
        });
        let provider = fake_tunnel_provider(fixture.clone());
        let result = provider
            .bind_udp(
                "0.0.0.0:0".parse().unwrap(),
                "192.0.2.53:53".parse().unwrap(),
            )
            .await;
        let error = match result {
            Ok(_) => panic!("failed tunnel must not become direct UDP"),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            if hang {
                io::ErrorKind::TimedOut
            } else {
                io::ErrorKind::ConnectionRefused
            }
        );
        assert_eq!(fixture.opened.lock().len(), 1);
    }
}

#[test]
fn test_spawn_handle_is_clone() {
    let handle = TokioSpawnHandle;
    let _cloned = handle.clone();
}

#[tokio::test]
async fn test_bind_udp_works_directly() {
    let resolver = Arc::new(NativeResolver::new());
    let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
    let provider =
        ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, TEST_CONNECT_TIMEOUT);

    let local_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();

    // UDP DNS works directly (not through proxy)
    let result = provider.bind_udp(local_addr, server_addr).await;
    assert!(
        result.is_ok(),
        "bind_udp should succeed: {:?}",
        result.err()
    );
}

#[cfg(all(target_os = "linux", not(feature = "relay-minimal")))]
#[tokio::test]
async fn new_dns_sockets_follow_direct_selector_changes() {
    let config = r#"
- client_group: dns-route
  type: selector
  default: usable
  client_chains:
    - chain:
        - name: unavailable
          bind_interface: shoes-missing
          protocol: {type: direct}
    - chain:
        - name: usable
          protocol: {type: direct}
- dns_group: upstream
  dns_servers:
    - url: udp://192.0.2.1
      client_chain: dns-route
"#;
    let mut validated =
        crate::config::create_server_configs(serde_yaml::from_str(config).unwrap()).unwrap();
    let mut owner = crate::control::selection::SelectionOwner::new(None).unwrap();
    owner
        .activate(validated.catalog.take().unwrap().selection)
        .unwrap();
    let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let chains = validated.dns_groups.remove(0).specs.remove(0).client_chains;
    let group = crate::tcp::chain_builder::try_build_client_chain_group(
        crate::option_util::NoneOrSome::Some(chains),
        resolver.clone(),
    )
    .unwrap();
    let provider =
        ProxyRuntimeProvider::with_bootstrap(Arc::new(group), resolver, TEST_CONNECT_TIMEOUT)
            .with_quic_memory(0);
    let local = "0.0.0.0:0".parse().unwrap();
    let server = "192.0.2.1:53".parse().unwrap();
    let udp = provider.bind_udp(local, server).await.unwrap();
    let quic = provider
        .quic_binder()
        .unwrap()
        .bind_quic(local, server)
        .unwrap();
    owner.select("dns-route", "unavailable").unwrap();
    assert!(provider.bind_udp(local, server).await.is_err());
    assert!(
        provider
            .quic_binder()
            .unwrap()
            .bind_quic(local, server)
            .is_err()
    );
    assert!(udp.local_addr().is_ok());
    assert!(quic.local_addr().is_ok());
    owner.select("dns-route", "usable").unwrap();
    assert!(provider.bind_udp(local, server).await.is_ok());
    assert!(
        provider
            .quic_binder()
            .unwrap()
            .bind_quic(local, server)
            .is_ok()
    );
}

#[tokio::test]
async fn test_connect_tcp_with_direct_chain_connects_to_target() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let resolver = Arc::new(NativeResolver::new());
    let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
    let provider =
        ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, TEST_CONNECT_TIMEOUT);

    let result = provider.connect_tcp(server_addr, None, None).await;
    assert!(result.is_ok());
    assert!(
        tokio::time::timeout(TEST_CONNECT_TIMEOUT, listener.accept())
            .await
            .is_ok()
    );
}

#[test]
fn test_create_handle() {
    let resolver = Arc::new(NativeResolver::new());
    let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
    let provider =
        ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, TEST_CONNECT_TIMEOUT);
    let _handle = provider.create_handle();
}

#[test]
#[cfg(not(feature = "relay-minimal"))]
fn test_quic_binder_available() {
    let resolver = Arc::new(NativeResolver::new());
    let chain_group = Arc::new(build_direct_chain_group(resolver.clone()));
    let provider =
        ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, TEST_CONNECT_TIMEOUT);
    assert!(provider.quic_binder().is_some());
}

#[cfg(not(feature = "relay-minimal"))]
fn run_quic_test_in_child(name: &str) -> bool {
    if std::env::var("SHOES_DNS_QUIC_TEST_CHILD").as_deref() == Ok(name) {
        crate::resources::configure(crate::config::GlobalLimits {
            quic_memory_bytes: Some(16 << 20),
            ..Default::default()
        })
        .unwrap();
        return false;
    }
    shoes_test_support::isolated::run_isolated(
        &format!("dns::proxy_runtime::tests::{name}"),
        "SHOES_DNS_QUIC_TEST_CHILD",
        name,
    );
    true
}

#[tokio::test]
#[cfg(not(feature = "relay-minimal"))]
async fn quic_binder_keeps_candidate_reservation_without_publishing_limits() {
    if run_quic_test_in_child("quic_binder_keeps_candidate_reservation_without_publishing_limits") {
        return;
    }
    let resolver = Arc::new(NativeResolver::new());
    let provider = ProxyRuntimeProvider::with_bootstrap(
        Arc::new(build_direct_chain_group(resolver.clone())),
        resolver,
        TEST_CONNECT_TIMEOUT,
    )
    .with_quic_memory(1 << 20)
    .with_quic_socket_buffer(65536);
    assert_eq!(crate::resources::limits().quic_dns_memory_bytes, 16 << 20);
    assert_eq!(crate::resources::limits().quic_socket_buffer, 8 << 20);
    assert_eq!(provider.quic_binder.socket_buffer, 65536);
    let binder = provider.quic_binder().unwrap();
    let bind = || {
        binder.bind_quic(
            "0.0.0.0:0".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        )
    };
    crate::resources::configure(crate::config::GlobalLimits {
        quic_memory_bytes: Some(512 << 10),
        ..Default::default()
    })
    .unwrap();
    let error = bind().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    assert!(
        error
            .to_string()
            .contains("requested 1048576 bytes, active 0 bytes, live cap 524288")
    );
    crate::resources::configure(crate::config::GlobalLimits {
        quic_memory_bytes: Some(2 << 20),
        ..Default::default()
    })
    .unwrap();
    let socket = bind().unwrap();
    assert_eq!(
        crate::resources::snapshot().quic_buffer_bytes.active,
        1 << 20
    );
    let second = bind().unwrap();
    crate::resources::configure(crate::config::GlobalLimits {
        quic_memory_bytes: Some(1 << 20),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        crate::resources::snapshot().quic_buffer_bytes.active,
        2 << 20
    );
    assert!(bind().is_err());
    drop(second);
    assert!(bind().is_err());
    drop(socket);
    assert_eq!(crate::resources::snapshot().quic_buffer_bytes.active, 0);
    assert!(bind().is_ok());
}

#[tokio::test]
#[cfg(not(feature = "relay-minimal"))]
async fn quic_binder_reserves_shared_memory_until_last_socket_drop() {
    if run_quic_test_in_child("quic_binder_reserves_shared_memory_until_last_socket_drop") {
        return;
    }
    let binder = ProxyQuicBinder {
        chain_group: Arc::new(build_direct_chain_group(Arc::new(NativeResolver::new()))),
        memory_bytes: crate::resources::limits().quic_dns_memory_bytes,
        socket_buffer: crate::resources::limits().quic_socket_buffer,
    };
    let local_addr = "0.0.0.0:0".parse().unwrap();
    let server_addr = "127.0.0.1:443".parse().unwrap();
    let memory_bytes =
        crate::resources::configure_quic_transport(&mut quinn::TransportConfig::default());
    assert!(crate::resources::try_quic_memory(memory_bytes).is_some());
    let socket = binder.bind_quic(local_addr, server_addr).unwrap();
    assert_eq!(
        crate::resources::snapshot().quic_buffer_bytes.active,
        16 << 20
    );
    assert!(crate::resources::try_quic_memory(memory_bytes).is_none());
    assert_eq!(
        binder
            .bind_quic(local_addr, server_addr)
            .unwrap_err()
            .kind(),
        io::ErrorKind::ConnectionRefused,
    );
    let clone = socket.clone();
    drop(socket);
    assert_eq!(
        crate::resources::snapshot().quic_buffer_bytes.active,
        16 << 20
    );
    drop(clone);
    assert_eq!(crate::resources::snapshot().quic_buffer_bytes.active, 0);

    let occupied = std::net::UdpSocket::bind(local_addr).unwrap();
    assert!(
        binder
            .bind_quic(occupied.local_addr().unwrap(), server_addr)
            .is_err()
    );
    assert_eq!(crate::resources::snapshot().quic_buffer_bytes.active, 0);
    assert!(binder.bind_quic(local_addr, server_addr).is_ok());
}

#[tokio::test]
#[cfg(not(feature = "relay-minimal"))]
async fn h3_lookup_uses_budgeted_socket_and_releases_it_on_teardown() {
    use bytes::Buf;
    use hickory_resolver::config::{
        ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig,
    };
    use hickory_resolver::net::h3::h3_server::H3Server;
    use hickory_resolver::proto::op::{Message, MessageType};
    use hickory_resolver::proto::rr::{RData, Record, rdata::A};

    if run_quic_test_in_child("h3_lookup_uses_budgeted_socket_and_releases_it_on_teardown") {
        return;
    }
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut server = H3Server::with_socket_and_tls_config(
        tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap(),
        Arc::new(tls),
    )
    .unwrap();
    let mut connection_config = ConnectionConfig::new(ProtocolConfig::H3 {
        server_name: "localhost".into(),
        path: "/dns-query".into(),
        disable_grease: true,
    });
    connection_config.port = server.local_addr().unwrap().port();
    let config = ResolverConfig::from_parts(
        None,
        vec![],
        vec![NameServerConfig::new(
            "127.0.0.1".parse().unwrap(),
            true,
            vec![connection_config],
        )],
    );
    let bootstrap = Arc::new(NativeResolver::new());
    let provider = ProxyRuntimeProvider::with_bootstrap(
        Arc::new(build_direct_chain_group(bootstrap.clone())),
        bootstrap,
        Duration::from_secs(5),
    );
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let resolver = hickory_resolver::Resolver::builder_with_config(config, provider)
        .with_tls_config(tls)
        .build()
        .unwrap();
    let answer = RData::A(A::new(192, 0, 2, 42));
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let serve = async {
        let (mut connection, _) = server.accept().await.unwrap().unwrap();
        let (request, mut stream) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.uri().path(), "/dns-query");
        let respond = async {
            let mut body = Vec::new();
            while let Some(mut data) = stream.recv_data().await.unwrap() {
                body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
            }
            let mut response = Message::from_vec(&body).unwrap();
            response.metadata.message_type = MessageType::Response;
            response.add_answer(Record::from_rdata(
                response.queries[0].name().clone(),
                60,
                answer.clone(),
            ));
            let body = response.to_vec().unwrap();
            stream
                .send_response(
                    http::Response::builder()
                        .header("content-type", "application/dns-message")
                        .header("content-length", body.len())
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            stream.send_data(body.into()).await.unwrap();
            stream.finish().await.unwrap();
            done_rx.await.unwrap();
        };
        tokio::select! {
            _ = respond => {},
            _ = connection.accept() => panic!("unexpected extra H3 request or closure"),
        }
    };
    let lookup = async {
        let result = resolver.ipv4_lookup("memory.test.").await.unwrap();
        assert_eq!(result.answers()[0].data, answer);
        assert_eq!(
            crate::resources::snapshot().quic_buffer_bytes.active,
            16 << 20
        );
        done_tx.send(()).unwrap();
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(serve, lookup)
    })
    .await
    .unwrap();
    drop((resolver, server));
    tokio::time::timeout(Duration::from_secs(5), async {
        while crate::resources::snapshot().quic_buffer_bytes.active != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn test_connect_tcp_respects_timeout() {
    let resolver = Arc::new(NativeResolver::new());
    let chain_group = Arc::new(build_pending_chain_group());
    let provider =
        ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, TEST_CONNECT_TIMEOUT);

    let server_addr: SocketAddr = "192.0.2.1:53".parse().unwrap();

    let start = std::time::Instant::now();
    let result = provider
        .connect_tcp(server_addr, None, Some(Duration::from_millis(100)))
        .await;
    let elapsed = start.elapsed();

    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("connection should fail"),
    };
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::TimedOut,
        "should be timeout error"
    );

    // Verify timeout was respected (should complete in ~100ms, not 5+ seconds)
    assert!(
        elapsed < Duration::from_secs(1),
        "timeout should fire quickly, but took {:?}",
        elapsed
    );
}

#[tokio::test]
async fn test_connect_tcp_caps_passed_timeout_by_configured_connect_timeout() {
    let resolver = Arc::new(NativeResolver::new());
    let chain_group = Arc::new(build_pending_chain_group());
    let provider =
        ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, Duration::from_millis(100));

    let server_addr: SocketAddr = "192.0.2.1:53".parse().unwrap();

    let start = std::time::Instant::now();
    let result = provider
        .connect_tcp(server_addr, None, Some(Duration::from_secs(5)))
        .await;
    let elapsed = start.elapsed();

    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("connection should fail"),
    };
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert!(
        elapsed < Duration::from_secs(1),
        "configured connect timeout should cap a longer request timeout, but took {:?}",
        elapsed
    );
}

#[tokio::test]
async fn test_connect_tcp_uses_configured_timeout_when_none() {
    let resolver = Arc::new(NativeResolver::new());
    let chain_group = Arc::new(build_pending_chain_group());
    let provider =
        ProxyRuntimeProvider::with_bootstrap(chain_group, resolver, TEST_CONNECT_TIMEOUT);

    let server_addr: SocketAddr = "192.0.2.1:53".parse().unwrap();

    let start = std::time::Instant::now();
    let result = provider.connect_tcp(server_addr, None, None).await;
    let elapsed = start.elapsed();

    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("connection should fail"),
    };
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::TimedOut,
        "should be timeout error"
    );

    assert!(
        elapsed < Duration::from_secs(1),
        "configured timeout should apply, but took {:?}",
        elapsed
    );
    assert!(
        elapsed >= Duration::from_millis(50),
        "configured timeout fired too early after {:?}",
        elapsed
    );
}
