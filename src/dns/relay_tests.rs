//! In-memory DNS acceptance tests: no real WG key, DNS socket, or external host.
use super::{
    hickory_resolver::{HickoryResolver, HickoryResolverOptions},
    parsed::IpStrategy,
};
use crate::{
    address::{NetLocation, ResolvedLocation},
    async_stream::*,
    client_proxy_chain::{ClientChainGroup, ClientProxyChain, InitialHopEntry},
    resolver::{ResolveFuture, Resolver},
    tcp::socket_connector::SocketConnector,
};
use async_trait::async_trait;
use hickory_resolver::{
    config::ConnectionConfig,
    proto::{
        op::{Message, ResponseCode},
        rr::{
            Name, RData, Record,
            rdata::{A, CNAME},
        },
    },
};
use parking_lot::Mutex;
use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::io::ReadBuf;

#[derive(Debug, Clone, Copy)]
enum Behavior {
    Answer,
    ServFail,
    NxDomain,
    Silent,
    Alias,
    Truncated,
}

#[derive(Debug)]
struct Fixture {
    modes: [Behavior; 2],
    calls: AtomicUsize,
    gated: AtomicBool,
    readers: Mutex<Vec<Waker>>,
    tcp_targets: Mutex<Vec<SocketAddr>>,
}

impl Fixture {
    fn release(&self) {
        self.gated.store(false, Ordering::Relaxed);
        for waker in self.readers.lock().drain(..) {
            waker.wake();
        }
    }
}

#[derive(Debug)]
struct NoBootstrap;
impl Resolver for NoBootstrap {
    fn resolve_location(&self, _: &NetLocation) -> ResolveFuture {
        panic!("literal WG DNS upstream must never invoke bootstrap/native DNS")
    }
}

#[derive(Debug)]
struct Connector(Arc<Fixture>);
#[async_trait]
impl SocketConnector for Connector {
    async fn connect(
        &self,
        _: &Arc<dyn Resolver>,
        target: &ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncStream>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let address = target.location().to_socket_addr_nonblocking().unwrap();
        let index = if address.ip() == "192.0.2.53".parse::<IpAddr>().unwrap() {
            0
        } else {
            assert_eq!(address.ip(), "192.0.2.54".parse::<IpAddr>().unwrap());
            1
        };
        assert!(
            matches!(self.0.modes[index], Behavior::Truncated),
            "only a truncated datagram may initiate TCP retry"
        );
        assert_eq!(address.port(), 53);
        self.0.tcp_targets.lock().push(address);
        let (client, mut server) = tokio::io::duplex(2048);
        tokio::spawn(async move {
            while let Ok(length) = server.read_u16().await {
                let mut bytes = vec![0; length as usize];
                if server.read_exact(&mut bytes).await.is_err() {
                    break;
                }
                let mut answer = Message::from_vec(&bytes).unwrap().into_response();
                answer.add_answer(Record::from_rdata(
                    answer.queries[0].name.clone(),
                    2,
                    RData::A(A::new(198, 51, 100, 7)),
                ));
                let bytes = answer.to_vec().unwrap();
                if server.write_u16(bytes.len() as u16).await.is_err()
                    || server.write_all(&bytes).await.is_err()
                {
                    break;
                }
            }
        });
        Ok(Box::new(client))
    }
    async fn connect_udp_bidirectional(
        &self,
        _: &Arc<dyn Resolver>,
        target: ResolvedLocation,
    ) -> io::Result<Box<dyn AsyncMessageStream>> {
        let ip = target.location().to_socket_addr_nonblocking().unwrap().ip();
        let index = if ip == "192.0.2.53".parse::<IpAddr>().unwrap() {
            0
        } else {
            assert_eq!(ip, "192.0.2.54".parse::<IpAddr>().unwrap());
            1
        };
        Ok(Box::new(Stream {
            fixture: self.0.clone(),
            mode: self.0.modes[index],
            replies: VecDeque::new(),
        }))
    }
    fn bind_interface(&self) -> Option<&str> {
        None
    }
}

struct Stream {
    fixture: Arc<Fixture>,
    mode: Behavior,
    replies: VecDeque<Vec<u8>>,
}
impl AsyncReadMessage for Stream {
    fn read_message_eof_on_empty(&self) -> bool {
        false
    }
    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.fixture.gated.load(Ordering::Relaxed) {
            self.fixture.readers.lock().push(cx.waker().clone());
            return Poll::Pending;
        }
        if let Some(bytes) = self.replies.pop_front() {
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
impl AsyncWriteMessage for Stream {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<()>> {
        self.fixture.calls.fetch_add(1, Ordering::Relaxed);
        let request = Message::from_vec(bytes).unwrap();
        let query_name = request.queries[0].name.clone();
        let mut answer = request.into_response();
        match self.mode {
            Behavior::Silent => return Poll::Ready(Ok(())),
            Behavior::ServFail => answer.metadata.response_code = ResponseCode::ServFail,
            Behavior::NxDomain => answer.metadata.response_code = ResponseCode::NXDomain,
            Behavior::Truncated => answer.metadata.truncation = true,
            Behavior::Alias if query_name == Name::from_ascii("alias.test.").unwrap() => {
                answer.add_answer(Record::from_rdata(
                    query_name,
                    2,
                    RData::CNAME(CNAME(Name::from_ascii("target.test.").unwrap())),
                ));
                answer.add_answer(Record::from_rdata(
                    Name::from_ascii("unrelated.test.").unwrap(),
                    2,
                    RData::A(A::new(203, 0, 113, 99)),
                ));
            }
            _ => {
                answer.add_answer(Record::from_rdata(
                    query_name,
                    2,
                    RData::A(A::new(198, 51, 100, 7)),
                ));
            }
        }
        self.replies.push_back(answer.to_vec().unwrap());
        Poll::Ready(Ok(()))
    }
}
impl AsyncFlushMessage for Stream {
    fn poll_flush_message(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl AsyncShutdownMessage for Stream {
    fn poll_shutdown_message(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl AsyncPing for Stream {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}
impl AsyncMessageStream for Stream {}

fn resolver(modes: [Behavior; 2], gated: bool) -> (Arc<HickoryResolver>, Arc<Fixture>) {
    let fixture = Arc::new(Fixture {
        modes,
        calls: AtomicUsize::new(0),
        gated: AtomicBool::new(gated),
        readers: Mutex::new(Vec::new()),
        tcp_targets: Mutex::new(Vec::new()),
    });
    let chain = ClientChainGroup::new(vec![ClientProxyChain::new(
        vec![InitialHopEntry::Wireguard(Arc::new(Connector(
            fixture.clone(),
        )))],
        vec![],
    )]);
    let resolver = HickoryResolver::build_pooled(
        ["192.0.2.53", "192.0.2.54"]
            .into_iter()
            .map(|ip| (ip.parse().unwrap(), ConnectionConfig::udp()))
            .collect(),
        Arc::new(chain),
        Arc::new(NoBootstrap),
        HickoryResolverOptions {
            ip_strategy: IpStrategy::Ipv4Only,
            request_timeout: Some(Duration::from_secs(10)),
            connect_timeout: Duration::from_secs(10),
            attempts: 1,
            ..Default::default()
        },
        "memory-only WG DNS fixture".into(),
    )
    .unwrap();
    (Arc::new(resolver), fixture)
}

fn target(name: &str, port: u16) -> NetLocation {
    NetLocation::new(crate::address::Address::Hostname(name.into()), port)
}

#[test]
fn relay_dns_configuration_accepts_tunneled_udp_but_rejects_bootstrap_cycles() {
    use base64::Engine;
    use serde_json::json;
    let key = |byte| base64::engine::general_purpose::STANDARD.encode([byte; 32]);
    let config = json!([
        {"global_settings": {"default_dns": {"servers": "wg-dns"}}},
        {"client_group": "wg", "client_chains": [{
            "address": "192.0.2.1:51820", "transport": "udp",
            "protocol": {"type": "wireguard", "private_key": key(42), "public_key": key(43), "addresses": ["10.77.0.2/32"], "mtu": 1280}
        }]},
        {"dns_group": "wg-dns", "dns_servers": [{"url": "udp://192.0.2.53:53", "client_chain": "wg", "ip_strategy": "ipv4_only", "timeout_secs": 10, "connect_timeout_secs": 10, "attempts": 1}]}
    ]);
    let validate =
        |value| crate::config::create_server_configs(serde_json::from_value(value).unwrap());
    validate(config.clone()).unwrap();
    let mut bad = config.clone();
    bad[2]["dns_servers"][0]["bootstrap_url"] = json!("system");
    assert!(validate(bad).is_err());
    let mut bad = config;
    bad[2]["dns_servers"][0]["url"] = json!("udp://dns.invalid:53");
    assert!(validate(bad).is_err());
}

#[tokio::test(start_paused = true)]
async fn relay_dns_races_past_servfail_or_silent_upstream() {
    for first in [Behavior::ServFail, Behavior::NxDomain, Behavior::Silent] {
        let (dns, fixture) = resolver([first, Behavior::Answer], false);
        let result = dns
            .resolve_location(&target("race.test.", 443))
            .await
            .unwrap();
        assert_eq!(result, ["198.51.100.7:443".parse::<SocketAddr>().unwrap()]);
        assert!(fixture.calls.load(Ordering::Relaxed) <= 2);
    }
}

#[tokio::test(start_paused = true)]
async fn relay_dns_coalesces_identical_queries_and_respects_ttl() {
    let (dns, fixture) = resolver([Behavior::Answer, Behavior::Answer], true);
    let first = tokio::spawn(dns.resolve_location(&target("cache.test.", 443)));
    let second = tokio::spawn(dns.resolve_location(&target("cache.test.", 80)));
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    let calls = fixture.calls.load(Ordering::Relaxed);
    assert_eq!(
        calls, 2,
        "one shared query is sent to each configured resolver"
    );
    fixture.release();
    assert_eq!(first.await.unwrap().unwrap()[0].port(), 443);
    assert_eq!(second.await.unwrap().unwrap()[0].port(), 80);
    dns.resolve_location(&target("cache.test.", 8080))
        .await
        .unwrap();
    assert_eq!(fixture.calls.load(Ordering::Relaxed), calls);
    tokio::time::advance(Duration::from_secs(3)).await;
    dns.resolve_location(&target("cache.test.", 443))
        .await
        .unwrap();
    assert!(fixture.calls.load(Ordering::Relaxed) > calls);
}

#[tokio::test(start_paused = true)]
async fn relay_dns_double_failure_is_closed_and_bounded() {
    for mode in [Behavior::ServFail, Behavior::Silent] {
        let (dns, _) = resolver([mode, mode], false);
        assert!(
            dns.resolve_location(&target("failure.test.", 443))
                .await
                .is_err()
        );
    }
}

#[tokio::test(start_paused = true)]
async fn relay_dns_follows_cname_without_accepting_unrelated_records() {
    let (dns, _) = resolver([Behavior::Alias, Behavior::Alias], false);
    let result = dns
        .resolve_location(&target("alias.test.", 443))
        .await
        .unwrap();
    assert_eq!(result, ["198.51.100.7:443".parse::<SocketAddr>().unwrap()]);
}

#[tokio::test(start_paused = true)]
async fn relay_dns_truncation_retries_same_upstream_over_the_wg_tcp_connector() {
    let (dns, fixture) = resolver([Behavior::Truncated, Behavior::Truncated], false);
    let result = dns
        .resolve_location(&target("large.test.", 443))
        .await
        .unwrap();
    assert_eq!(result, ["198.51.100.7:443".parse::<SocketAddr>().unwrap()]);
    assert!(!fixture.tcp_targets.lock().is_empty());
}
