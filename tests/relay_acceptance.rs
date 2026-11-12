//! Offline contract checks for the production relay binary.
//!
//! All OS sockets bind/connect to loopback. The apparent public IPs below exist only
//! inside an isolated, randomly keyed WireGuard pair. Run the harness in a container
//! with `--network none --memory 128m`; no real configuration or key is ever loaded.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use aws_lc_rs::rand::SecureRandom;
use base64::{Engine, engine::general_purpose::STANDARD};
use gotatun::x25519::{PublicKey, StaticSecret};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{
    TcpListener, TcpStream, UdpSocket,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};

const PATH: &str = "/relay/offline-acceptance";
const OWNER: &str = "offline-owner-only-not-a-production-secret";
const SECOND_OWNER: &str = "offline-wg-owner-only-not-a-production-secret";
const VIRTUAL_IP: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);

struct Process {
    child: Child,
    log: tempfile::NamedTempFile,
}

impl Process {
    fn start(config: Value) -> io::Result<Self> {
        let binary = std::env::var_os("SHOES_TEST_SHOES_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_shoes")));
        let log = tempfile::NamedTempFile::new()?;
        let child = Command::new(binary)
            .args(["--config-env", "RELAY_CONFIG"])
            .env("RELAY_CONFIG", config.to_string())
            .env("RUST_LOG", "warn")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.reopen()?))
            .stderr(Stdio::from(log.reopen()?))
            .spawn()?;
        Ok(Self { child, log })
    }

    fn ensure_running(&mut self) -> io::Result<()> {
        if let Some(status) = self.child.try_wait()? {
            let log = std::fs::read_to_string(self.log.path()).unwrap_or_default();
            return Err(io::Error::other(format!(
                "offline relay exited {status}: {log}"
            )));
        }
        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() || std::env::var_os("RELAY_ACCEPTANCE_VERBOSE").is_some() {
            eprintln!(
                "offline process log: {}",
                std::fs::read_to_string(self.log.path()).unwrap_or_default()
            );
        }
    }
}

struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn keypair() -> io::Result<(String, String)> {
    let mut key = [0; 32];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| io::Error::other("cannot generate isolated test key"))?;
    let public = PublicKey::from(&StaticSecret::from(key));
    Ok((STANDARD.encode(key), STANDARD.encode(public.as_bytes())))
}

async fn tcp_echo() -> io::Result<(u16, Arc<AtomicUsize>, Task)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let connections = Arc::new(AtomicUsize::new(0));
    let observed = connections.clone();
    let task = tokio::spawn(async move {
        let mut children = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((mut socket, _)) = accepted else { break; };
                    observed.fetch_add(1, Ordering::Relaxed);
                    children.spawn(async move {
                        let (mut reader, mut writer) = socket.split();
                        let _ = tokio::io::copy(&mut reader, &mut writer).await;
                        let _ = writer.shutdown().await;
                    });
                }
                _ = children.join_next(), if !children.is_empty() => {}
            }
        }
    });
    Ok((port, connections, Task(task)))
}

async fn udp_echo() -> io::Result<(u16, Task)> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let port = socket.local_addr()?.port();
    let task = tokio::spawn(async move {
        let mut bytes = vec![0; 65_535];
        loop {
            let Ok((len, source)) = socket.recv_from(&mut bytes).await else {
                break;
            };
            if socket.send_to(&bytes[..len], source).await.is_err() {
                break;
            }
        }
    });
    Ok((port, Task(task)))
}

async fn dns_stub() -> io::Result<(u16, Arc<AtomicUsize>, Task)> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let port = socket.local_addr()?.port();
    let count = Arc::new(AtomicUsize::new(0));
    let observed = count.clone();
    let task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let Ok((len, source)) = socket.recv_from(&mut bytes).await else {
                break;
            };
            if len < 17 || bytes[4..6] != [0, 1] {
                continue;
            }
            let mut end = 12;
            let mut labels = Vec::new();
            while end < len && bytes[end] != 0 {
                let size = bytes[end] as usize;
                if size > 63 || end + 1 + size >= len {
                    break;
                }
                labels.push(String::from_utf8_lossy(&bytes[end + 1..end + 1 + size]).into_owned());
                end += 1 + size;
            }
            if end + 5 > len || bytes[end] != 0 {
                continue;
            }
            end += 5; // zero label, QTYPE and QCLASS
            observed.fetch_add(1, Ordering::Relaxed);
            let mut reply = bytes[..2].to_vec();
            reply.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
            reply.extend_from_slice(&bytes[12..end]);
            reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
            let ip = if labels.join(".").starts_with("private.") {
                Ipv4Addr::LOCALHOST
            } else {
                VIRTUAL_IP
            };
            reply.extend_from_slice(&ip.octets());
            let _ = socket.send_to(&reply, source).await;
        }
    });
    Ok((port, count, Task(task)))
}

fn ws_protocol() -> Value {
    json!({"type":"websocket", "targets":[{
        "matching_path":PATH, "ping_type":"disabled",
        "protocol":{"type":"trojan", "password":[OWNER, SECOND_OWNER]}
    }]})
}

fn policy() -> Value {
    json!([
        {"masks":{"domain":["localhost", "metadata", "metadata.google.internal", "instance-data.ec2.internal"]}, "action":"block"},
        {"masks":{"domain_suffix":["localhost","local","internal","home.arpa"]}, "action":"block"},
        {"masks":{"ip_cidr":["0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8","169.254.0.0/16","172.16.0.0/12","192.0.0.0/24","192.0.2.0/24","192.168.0.0/16","198.18.0.0/15","198.51.100.0/24","203.0.113.0/24","224.0.0.0/4","240.0.0.0/4","::/0"]}, "action":"block"},
        {"masks":{"ip_cidr":["0.0.0.0/0"]}, "action":"allow", "client_chain":"wg"}
    ])
}

struct WsWriter(OwnedWriteHalf);
struct WsReader {
    socket: OwnedReadHalf,
    pending: Vec<u8>,
}

async fn websocket(port: u16, path: &str) -> io::Result<(WsWriter, WsReader)> {
    let mut socket = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: relay.invalid\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    socket.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") && response.len() < 8192 {
        response.push(socket.read_u8().await?);
    }
    let headers = String::from_utf8_lossy(&response).to_ascii_lowercase();
    if !headers.starts_with("http/1.1 101")
        || !headers.contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo=")
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("WebSocket upgrade rejected: {headers}"),
        ));
    }
    let (reader, writer) = socket.into_split();
    Ok((
        WsWriter(writer),
        WsReader {
            socket: reader,
            pending: Vec::new(),
        },
    ))
}

impl WsWriter {
    async fn frame(&mut self, opcode: u8, fin: bool, bytes: &[u8]) -> io::Result<()> {
        let mut header = vec![opcode | if fin { 0x80 } else { 0 }];
        match bytes.len() {
            0..126 => header.push(0x80 | bytes.len() as u8),
            126..65_536 => {
                header.push(0xfe);
                header.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            }
            _ => {
                header.push(0xff);
                header.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            }
        }
        let mask = [0x12, 0x34, 0x56, 0x78];
        header.extend_from_slice(&mask);
        self.0.write_all(&header).await?;
        let masked = bytes
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect::<Vec<_>>();
        self.0.write_all(&masked).await?;
        self.0.flush().await
    }
    async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.frame(2, true, bytes).await
    }
}

impl WsReader {
    async fn bytes(&mut self, count: usize) -> io::Result<Vec<u8>> {
        while self.pending.len() < count {
            let first = self.socket.read_u8().await?;
            let second = self.socket.read_u8().await?;
            if first & 0x70 != 0 || second & 0x80 != 0 {
                return Err(io::Error::other("invalid server WebSocket flags"));
            }
            let length = match second & 0x7f {
                126 => self.socket.read_u16().await? as usize,
                127 => usize::try_from(self.socket.read_u64().await?)
                    .map_err(|_| io::Error::other("oversized WS frame"))?,
                n => n as usize,
            };
            if length > 131_072 {
                return Err(io::Error::other("oversized WS frame"));
            }
            let mut frame = vec![0; length];
            self.socket.read_exact(&mut frame).await?;
            match first & 0x0f {
                0 | 2 => self.pending.extend_from_slice(&frame),
                8 => return Err(io::ErrorKind::ConnectionAborted.into()),
                10 => {}
                _ => return Err(io::Error::other("unexpected WS control frame")),
            }
        }
        Ok(self.pending.drain(..count).collect())
    }

    async fn datagram(&mut self) -> io::Result<(SocketAddr, Vec<u8>)> {
        if self.bytes(1).await? != [1] {
            return Err(io::Error::other("expected IPv4 UDP reply"));
        }
        let ip = self.bytes(4).await?;
        let port = self.bytes(2).await?;
        let length = self.bytes(2).await?;
        if self.bytes(2).await? != b"\r\n" {
            return Err(io::Error::other("bad UDP CRLF"));
        }
        let source = SocketAddr::new(
            Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).into(),
            u16::from_be_bytes([port[0], port[1]]),
        );
        let bytes = self
            .bytes(u16::from_be_bytes([length[0], length[1]]) as usize)
            .await?;
        Ok((source, bytes))
    }
}

fn address(host: &str, port: u16) -> Vec<u8> {
    let mut bytes = Vec::new();
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ip) => {
                bytes.push(1);
                bytes.extend(ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                bytes.push(4);
                bytes.extend(ip.octets());
            }
        }
    } else {
        bytes.extend([3, host.len() as u8]);
        bytes.extend_from_slice(host.as_bytes());
    }
    bytes.extend(port.to_be_bytes());
    bytes
}

fn request(password: &str, command: u8, host: &str, port: u16) -> Vec<u8> {
    let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA224, password.as_bytes());
    let mut bytes = hash
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        .into_bytes();
    bytes.extend_from_slice(b"\r\n");
    bytes.push(command);
    bytes.extend(address(host, port));
    bytes.extend_from_slice(b"\r\n");
    bytes
}

fn datagram(host: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = address(host, port);
    bytes.extend((payload.len() as u16).to_be_bytes());
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(payload);
    bytes
}

async fn udp_exchange(
    writer: &mut WsWriter,
    reader: &mut WsReader,
    port: u16,
    payload: &[u8],
) -> io::Result<()> {
    let receive = async {
        loop {
            let (source, response) = reader.datagram().await?;
            if response == payload {
                assert_eq!(source, SocketAddr::new(VIRTUAL_IP.into(), port));
                return Ok::<_, io::Error>(());
            }
            // A prior UDP retry may produce one extra, valid earlier reply.
        }
    };
    tokio::pin!(receive);
    for _ in 0..4 {
        writer.send(&datagram("9.9.9.9", port, payload)).await?;
        if let Ok(result) = tokio::time::timeout(Duration::from_secs(2), receive.as_mut()).await {
            return result;
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "isolated UDP exchange timed out",
    ))
}

#[tokio::test(flavor = "current_thread")]
async fn production_binary_websocket_trojan_wireguard_contract() -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(120), async {
        let (tcp_port, tcp_connections, _tcp) = tcp_echo().await?;
        let (udp_port, _udp) = udp_echo().await?;
        let (dns1, dns_count1, _dns1) = dns_stub().await?;
        let (dns2, dns_count2, _dns2) = dns_stub().await?;
        let peer_reservation = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let peer_port = peer_reservation.local_addr()?.port();
        let ws_reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
        let ws_port = ws_reservation.local_addr()?.port();
        let (peer_key, peer_public) = keypair()?;
        let (client_key, client_public) = keypair()?;
        let limits = json!({"tcp_buffer_size":32768, "tcp_buffer_max_size":1048576, "tcp_memory_bytes":33554432, "max_tcp_connections":80, "max_udp_queued_bytes":8388608});
        let peer = json!([{
            "address":format!("127.0.0.1:{peer_port}"),
            "protocol":{"type":"wireguard", "wireguard_name":"offline-peer", "private_key":peer_key,
                "addresses":["10.77.0.1/32"], "mtu":1420, "resource_limits":limits,
                "peers":[{"public_key":client_public,"allowed_ips":["10.77.0.2/32"]}]},
            // The peer maps every inner IPv4 target to loopback. This also makes a
            // client-side private-address policy regression observable by a local trap.
            "rules":[{"masks":"0.0.0.0/0","action":"allow","override_address":"127.0.0.1:0"}]
        }]);
        let proxy = json!([
            {"global_settings":{"max_connections":80,"default_dns":{"servers":"wg-dns"}}},
            {"dns_group":"wg-dns", "dns_servers":[
                {"url":format!("udp://9.9.9.9:{dns1}"),"client_chain":"wg","ip_strategy":"ipv4_only","timeout_secs":2},
                {"url":format!("udp://9.9.9.9:{dns2}"),"client_chain":"wg","ip_strategy":"ipv4_only","timeout_secs":2}
            ]},
            {"client_group":"wg", "client_chains":[{"address":format!("127.0.0.1:{peer_port}"),
                "protocol":{"type":"wireguard","private_key":client_key,"public_key":peer_public,
                    "addresses":["10.77.0.2/32"],"allowed_ips":["0.0.0.0/0"],"mtu":1280,"resource_limits":limits}}]},
            {"address":format!("127.0.0.1:{ws_port}"),"protocol":ws_protocol(),"dns":{"servers":"wg-dns"},"rules":policy()}
        ]);
        drop(peer_reservation);
        let mut peer = Process::start(peer)?;
        drop(ws_reservation);
        let mut proxy = Process::start(proxy)?;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                peer.ensure_running()?; proxy.ensure_running()?;
                if TcpStream::connect((Ipv4Addr::LOCALHOST, ws_port)).await.is_ok() { return Ok::<_,io::Error>(()); }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await??;

        for password in [OWNER, SECOND_OWNER] {
            let (mut writer, mut reader) = websocket(ws_port, PATH).await?;
            eprintln!("offline stage: WebSocket upgraded for TCP");
            let payload = (0..512 * 1024).map(|n| (n % 251) as u8).collect::<Vec<_>>();
            let host = if password == OWNER { "9.9.9.9" } else { "relay-acceptance.invalid" };
            let mut bytes = request(password, 1, host, tcp_port);
            bytes.extend_from_slice(&payload);
            // Fragment the first Trojan header across WebSocket continuation frames.
            let send = async {
                writer.frame(2, false, &bytes[..17]).await?;
                writer.frame(0, true, &bytes[17..]).await
            };
            let receive = reader.bytes(payload.len());
            let (_, response) = tokio::try_join!(send, receive)?;
            assert_eq!(response, payload);
            eprintln!("offline stage: TCP over WireGuard echoed");
            writer.0.shutdown().await?;
        }
        assert!(dns_count1.load(Ordering::Relaxed) + dns_count2.load(Ordering::Relaxed) > 0);

        let (mut writer, mut reader) = websocket(ws_port, PATH).await?;
        eprintln!("offline stage: WebSocket upgraded for UDP");
        let mut initial = request(OWNER, 3, "0.0.0.0", 0);
        initial.extend(datagram("9.9.9.9", udp_port, b"first-coalesced-datagram"));
        writer.send(&initial).await?;
        assert_eq!(reader.datagram().await?.1, b"first-coalesced-datagram");
        // macOS normally caps kernel UDP sends at net.inet.udp.maxdgram=9216.
        // The production Linux container must exercise the full IPv4 datagram;
        // codec/reassembly unit tests cover 65507 independently of host sockets.
        let sizes: &[usize] = if cfg!(target_os = "linux") {
            &[0, 1200, 4096, 65_507]
        } else {
            &[0, 1200, 4096, 8192]
        };
        for &size in sizes {
            eprintln!("offline stage: UDP payload {size}");
            let payload = (0..size).map(|n| ((n + size) % 251) as u8).collect::<Vec<_>>();
            udp_exchange(&mut writer, &mut reader, udp_port, &payload).await?;
        }
        writer.0.shutdown().await?;

        let before = tcp_connections.load(Ordering::Relaxed);
        for (password, host) in [
            ("wrong-offline-password", "9.9.9.9"),
            (OWNER, "127.0.0.1"),
            (OWNER, "169.254.169.254"),
            (OWNER, "private.relay-acceptance.invalid"),
            (OWNER, "::ffff:9.9.9.9"),
        ] {
            let (mut writer, mut reader) = websocket(ws_port, PATH).await?;
            let mut bytes = request(password, 1, host, tcp_port); bytes.extend_from_slice(b"must-not-forward");
            writer.send(&bytes).await?;
            let reply = tokio::time::timeout(Duration::from_secs(5), reader.bytes(1)).await;
            assert!(matches!(reply, Ok(Err(_))), "rejected request did not close");
        }
        assert_eq!(tcp_connections.load(Ordering::Relaxed), before);

        let trap = UdpSocket::bind("127.0.0.1:0").await?;
        let trap_port = trap.local_addr()?.port();
        let (mut writer, mut reader) = websocket(ws_port, PATH).await?;
        writer.send(&request(SECOND_OWNER, 3, "0.0.0.0", 0)).await?;
        for host in ["127.0.0.1", "169.254.169.254", "private.relay-acceptance.invalid"] {
            writer.send(&datagram(host, trap_port, b"must-not-reach-loopback")).await?;
        }
        udp_exchange(&mut writer, &mut reader, udp_port, b"valid-after-rejected-targets").await?;
        let mut trap_bytes = [0; 128];
        assert!(tokio::time::timeout(Duration::from_millis(500), trap.recv_from(&mut trap_bytes)).await.is_err());
        writer.0.shutdown().await?;

        for payload in [
            datagram("::ffff:9.9.9.9", udp_port, b"mapped-ipv6-is-not-allowed"),
            {
                let mut frame = datagram("9.9.9.9", udp_port, b"invalid-delimiter");
                frame[9] = b'x';
                frame
            },
            {
                let mut frame = datagram("9.9.9.9", udp_port, b"");
                frame[7..9].copy_from_slice(&u16::MAX.to_be_bytes());
                frame
            },
        ] {
            let (mut writer, mut reader) = websocket(ws_port, PATH).await?;
            let mut initial = request(OWNER, 3, "0.0.0.0", 0);
            initial.extend(payload);
            writer.send(&initial).await?;
            let reply = tokio::time::timeout(Duration::from_secs(5), reader.bytes(1)).await;
            assert!(matches!(reply, Ok(Err(_))), "malformed UDP association did not close");
        }
        assert!(websocket(ws_port, "/wrong-path").await.is_err());
        peer.ensure_running()?; proxy.ensure_running()?;
        Ok::<_,io::Error>(())
    }).await?
}
