use std::sync::Arc;

use async_trait::async_trait;
use aws_lc_rs::digest::SHA224;
#[cfg(not(feature = "relay-minimal"))]
use log::debug;
use subtle::ConstantTimeEq;
use tokio::io::AsyncWriteExt;

use crate::address::{Address, ResolvedLocation};
use crate::async_stream::AsyncStream;
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::ShadowsocksConfig;
#[cfg(not(feature = "relay-minimal"))]
use crate::h2mux::{MUX_DESTINATION_HOST, MUX_DESTINATION_PORT, handle_h2mux_session};
#[cfg(feature = "relay-minimal")]
const MUX_DESTINATION_HOST: &str = "sp.mux.sing-box.arpa";
#[cfg(feature = "relay-minimal")]
const MUX_DESTINATION_PORT: u16 = 444;
use crate::prepend_stream::PrependStream;
use crate::resolver::Resolver;
#[cfg(not(feature = "relay-minimal"))]
use crate::shadowsocks::{
    DefaultKey, ShadowsocksCipher, ShadowsocksKey, ShadowsocksStream, ShadowsocksStreamType,
};
use crate::socks_handler::{CMD_CONNECT, CMD_UDP_ASSOCIATE, read_location, write_location_to_vec};
use crate::stream_reader::StreamReader;
use crate::tcp::tcp_handler::{
    TcpClientHandler, TcpClientSetupResult, TcpServerHandler, TcpServerSetupResult,
};
use crate::trojan_udp_stream::TrojanUdpStream;
use crate::util::write_all;

#[cfg(test)]
mod client_handshake_tests {
    use super::*;
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    #[derive(Debug, Default)]
    struct RecordingStream(Arc<parking_lot::Mutex<Vec<Vec<u8>>>>);

    impl AsyncRead for RecordingStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for RecordingStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.lock().push(bytes.to_vec());
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl crate::async_stream::AsyncPing for RecordingStream {
        fn supports_ping(&self) -> bool {
            false
        }
        fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }
    impl AsyncStream for RecordingStream {}

    #[tokio::test]
    async fn client_submits_complete_handshake_in_one_write() {
        for address in ["example.com:443", "127.0.0.1:80", "[::1]:8080"] {
            let handler = TrojanTcpHandler::new_client("password", &None);
            let location = crate::address::NetLocation::from_str(address, None).unwrap();
            let stream = RecordingStream::default();
            let writes = stream.0.clone();
            handler
                .setup_client_tcp_stream(Box::new(stream), (&location).into())
                .await
                .unwrap();
            let expected = [
                create_password_hash("password").as_ref(),
                &CRLF_BYTES,
                &[CMD_CONNECT],
                &write_location_to_vec(&location).unwrap(),
                &CRLF_BYTES,
            ]
            .concat();
            assert_eq!(*writes.lock(), vec![expected]);
        }
    }
}

#[cfg(not(feature = "relay-minimal"))]
#[derive(Debug)]
struct ShadowsocksData {
    cipher: ShadowsocksCipher,
    key: Arc<Box<dyn ShadowsocksKey>>,
}

pub struct TrojanTcpHandler {
    password_hash: Box<[u8]>,
    additional_password_hashes: Vec<Box<[u8]>>,
    #[cfg(not(feature = "relay-minimal"))]
    shadowsocks_data: Option<ShadowsocksData>,
    /// Proxy selector for server handler use. None when used as client handler.
    proxy_selector: Option<Arc<ClientProxySelector>>,
    /// DNS resolver for h2mux sessions. None when used as client handler.
    #[cfg(not(feature = "relay-minimal"))]
    resolver: Option<Arc<dyn Resolver>>,
}

impl std::fmt::Debug for TrojanTcpHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut description = f.debug_struct("TrojanTcpHandler");
        description
            .field(
                "credential_count",
                &(1 + self.additional_password_hashes.len()),
            )
            .field("server", &self.proxy_selector.is_some());
        #[cfg(not(feature = "relay-minimal"))]
        description.field("shadowsocks", &self.shadowsocks_data.is_some());
        description.finish_non_exhaustive()
    }
}

impl TrojanTcpHandler {
    /// Create a new handler for server use (with proxy_selector for routing)
    pub fn new_server(
        password: &str,
        shadowsocks_config: &Option<ShadowsocksConfig>,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        Self::new_inner(
            password,
            shadowsocks_config,
            Some(proxy_selector),
            Some(resolver),
        )
    }

    /// Accept multiple server credentials without changing the single-password client interface.
    /// Configuration validation rejects an empty list before this constructor is used.
    pub fn new_server_with_passwords<'a>(
        passwords: impl IntoIterator<Item = &'a str>,
        shadowsocks_config: &Option<ShadowsocksConfig>,
        proxy_selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> Self {
        let mut passwords = passwords.into_iter();
        let first = passwords.next().expect("validated Trojan password list");
        let mut handler = Self::new_server(first, shadowsocks_config, proxy_selector, resolver);
        handler.additional_password_hashes = passwords.map(create_password_hash).collect();
        handler
    }

    /// Create a new handler for client use (no proxy_selector needed)
    pub fn new_client(password: &str, shadowsocks_config: &Option<ShadowsocksConfig>) -> Self {
        Self::new_inner(password, shadowsocks_config, None, None)
    }

    fn new_inner(
        password: &str,
        shadowsocks_config: &Option<ShadowsocksConfig>,
        proxy_selector: Option<Arc<ClientProxySelector>>,
        resolver: Option<Arc<dyn Resolver>>,
    ) -> Self {
        let password_hash = create_password_hash(password);
        #[cfg(not(feature = "relay-minimal"))]
        let shadowsocks_data = shadowsocks_config.as_ref().map(|config| match config {
            ShadowsocksConfig::Legacy {
                cipher,
                password: shadowsocks_password,
            } => {
                let key: Arc<Box<dyn ShadowsocksKey>> = Arc::new(Box::new(DefaultKey::new(
                    shadowsocks_password,
                    cipher.algorithm().key_len(),
                )));
                ShadowsocksData {
                    cipher: *cipher,
                    key,
                }
            }
            ShadowsocksConfig::Aead2022 { .. } => {
                panic!("Trojan does not support shadowsocks 2022 ciphers (checked during config validation)")
            }
        });
        #[cfg(feature = "relay-minimal")]
        let _ = (shadowsocks_config, resolver);

        Self {
            password_hash,
            additional_password_hashes: Vec::new(),
            #[cfg(not(feature = "relay-minimal"))]
            shadowsocks_data,
            proxy_selector,
            #[cfg(not(feature = "relay-minimal"))]
            resolver,
        }
    }
}

#[async_trait]
impl TcpServerHandler for TrojanTcpHandler {
    async fn setup_server_stream(
        &self,
        mut server_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<TcpServerSetupResult> {
        #[cfg(not(feature = "relay-minimal"))]
        if let Some(ShadowsocksData {
            ref cipher,
            ref key,
        }) = self.shadowsocks_data
        {
            server_stream = Box::new(ShadowsocksStream::new(
                server_stream,
                ShadowsocksStreamType::Aead,
                cipher.algorithm(),
                cipher.salt_len(),
                key.clone(),
                None,
            ));
        }

        let mut stream_reader = StreamReader::new_with_buffer_size(400);

        // read the entire line rather than exactly 56 bytes, so that we can masquerade as an HTTP server
        // and handle the request as if it were a HTTP request.
        // TODO: implement http response
        let received_hash = stream_reader.read_line_bytes(&mut server_stream).await?;
        if received_hash.len() != self.password_hash.len() {
            return Err(std::io::Error::other(format!(
                "Invalid password hash length, expected {}, got {}",
                self.password_hash.len(),
                received_hash.len()
            )));
        }

        // Check every precomputed credential, without exposing which identity matched in timing.
        let mut authenticated = self.password_hash.ct_eq(received_hash);
        for password_hash in &self.additional_password_hashes {
            authenticated |= password_hash.ct_eq(received_hash);
        }
        if authenticated.unwrap_u8() == 0 {
            return Err(std::io::Error::other("Invalid password hash"));
        }

        let command_type = stream_reader.read_u8(&mut server_stream).await?;

        if command_type != CMD_CONNECT && command_type != CMD_UDP_ASSOCIATE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid command code: {command_type}"),
            ));
        }

        let remote_location = read_location(&mut server_stream, &mut stream_reader).await?;
        #[cfg(feature = "relay-minimal")]
        if matches!(remote_location.address(), Address::Ipv6(_)) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "IPv6 is disabled for this relay",
            ));
        }

        let request_suffix = stream_reader.read_u16_be(&mut server_stream).await?;
        if request_suffix != 0x0d0a {
            return Err(std::io::Error::other(format!(
                "Invalid request suffix bytes {request_suffix}"
            )));
        }

        if command_type == CMD_UDP_ASSOCIATE {
            // The request address is advisory. Each UDP frame supplies its own destination,
            // which the shared UDP router resolves, checks, and pins before creating a flow.
            let stream = PrependStream::new(server_stream, stream_reader.unparsed_data_owned());
            return Ok(TcpServerSetupResult::MultiDirectionalUdp {
                need_initial_flush: false,
                stream: Box::new(TrojanUdpStream::new(stream)),
                proxy_selector: self
                    .proxy_selector
                    .clone()
                    .expect("proxy_selector required for server handler"),
            });
        }

        // Checks for h2mux magic destination
        if let Address::Hostname(host) = remote_location.address()
            && host == MUX_DESTINATION_HOST
            && remote_location.port() == MUX_DESTINATION_PORT
        {
            #[cfg(feature = "relay-minimal")]
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "multiplexed Trojan sessions are disabled for this relay",
            ));

            #[cfg(not(feature = "relay-minimal"))]
            {
                let proxy_selector = self
                    .proxy_selector
                    .clone()
                    .expect("proxy_selector required for server handler");
                let resolver = self.resolver.clone().expect("resolver required for h2mux");

                let initial_data = stream_reader.unparsed_data_owned();

                return Ok(TcpServerSetupResult::Session(Box::pin(async move {
                    if let Err(e) = handle_h2mux_session(
                        server_stream,
                        initial_data,
                        false,
                        proxy_selector,
                        resolver,
                    )
                    .await
                    {
                        debug!("Trojan h2mux session ended: {}", e);
                    }
                })));
            }
        }

        Ok(TcpServerSetupResult::TcpForward {
            remote_location,
            stream: server_stream,
            need_initial_flush: false,
            connection_success_response: None,
            connection_failure_response: None,
            initial_remote_data: stream_reader.unparsed_data_owned(),
            proxy_selector: self
                .proxy_selector
                .clone()
                .expect("proxy_selector required for server handler"),
        })
    }
}

const CRLF_BYTES: [u8; 2] = [0x0d, 0x0a];

#[async_trait]
impl TcpClientHandler for TrojanTcpHandler {
    async fn setup_client_tcp_stream(
        &self,
        mut client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        #[cfg(not(feature = "relay-minimal"))]
        if let Some(ShadowsocksData {
            ref cipher,
            ref key,
        }) = self.shadowsocks_data
        {
            client_stream = Box::new(ShadowsocksStream::new(
                client_stream,
                ShadowsocksStreamType::Aead,
                cipher.algorithm(),
                cipher.salt_len(),
                key.clone(),
                None,
            ));
        }

        let location_bytes = write_location_to_vec(remote_location.location())?;
        // Xray's Trojan inbound requires the credentials in its first read.
        let mut header = Vec::with_capacity(self.password_hash.len() + location_bytes.len() + 5);
        header.extend_from_slice(&self.password_hash);
        header.extend_from_slice(&CRLF_BYTES);
        header.push(CMD_CONNECT);
        header.extend_from_slice(&location_bytes);
        header.extend_from_slice(&CRLF_BYTES);
        write_all(&mut client_stream, &header).await?;
        client_stream.flush().await?;
        Ok(TcpClientSetupResult {
            client_stream,
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        // TODO: Return true once setup_client_udp_bidirectional is implemented
        false
    }

    // TODO: Implement Trojan UDP-over-TCP
    // Trojan UDP uses a message-framed protocol where each packet has:
    // ATYPE + Address + Port + Length(2 bytes) + CRLF + Payload
    // async fn setup_client_udp_bidirectional(...)
}

fn create_password_hash(password: &str) -> Box<[u8]> {
    let digest = aws_lc_rs::digest::digest(&SHA224, password.as_bytes());
    let hash_bytes = digest.as_ref();
    let mut hex_str = String::with_capacity(hash_bytes.len() * 2);
    for b in hash_bytes {
        hex_str.push_str(&format!("{b:02x}"));
    }
    let hex_bytes = hex_str.into_bytes().into_boxed_slice();
    if hex_bytes.len() != 56 {
        panic!(
            "Invalid password hash length, expected 56, got {}",
            hex_bytes.len()
        );
    }
    hex_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::NetLocation;
    use crate::resolver::NativeResolver;
    use std::io::ErrorKind;
    use tokio::io::AsyncReadExt;

    fn handler() -> TrojanTcpHandler {
        TrojanTcpHandler::new_server(
            "password",
            &None,
            Arc::new(ClientProxySelector::new(vec![])),
            Arc::new(NativeResolver::new()),
        )
    }

    fn request(location: &NetLocation) -> Vec<u8> {
        // SHA-224("password"), independently fixed to verify client wire encoding too.
        let mut request =
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\r\n\x01".to_vec();
        request.extend_from_slice(&write_location_to_vec(location).unwrap());
        request.extend_from_slice(b"\r\n");
        request
    }

    #[tokio::test]
    async fn ordinary_connect_preserves_coalesced_payload() {
        let location = NetLocation::from_str("example.com:443", None).unwrap();
        let mut request = request(&location);
        request.extend_from_slice(b"payload");
        let (mut client, server) = tokio::io::duplex(1024);
        client.write_all(&request).await.unwrap();
        client.shutdown().await.unwrap();
        let result = handler()
            .setup_server_stream(Box::new(server))
            .await
            .unwrap();
        let TcpServerSetupResult::TcpForward {
            remote_location,
            initial_remote_data,
            connection_success_response,
            need_initial_flush,
            ..
        } = result
        else {
            panic!("expected TCP forwarding");
        };
        assert_eq!(remote_location, location);
        assert_eq!(initial_remote_data.as_deref(), Some(&b"payload"[..]));
        assert!(connection_success_response.is_none());
        assert!(!need_initial_flush);
    }

    #[tokio::test]
    async fn client_emits_hash_connect_address_and_suffix() {
        let location = NetLocation::from_str("example.com:443", None).unwrap();
        let (client, mut server) = tokio::io::duplex(1024);
        let result = TrojanTcpHandler::new_client("password", &None)
            .setup_client_tcp_stream(Box::new(client), location.clone().into())
            .await
            .unwrap();
        assert!(result.early_data.is_none());
        drop(result);
        let expected = request(&location);
        let mut bytes = Vec::new();
        server.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, expected);
    }

    #[tokio::test]
    async fn both_server_credentials_authenticate_without_exposing_hashes() {
        let handler = TrojanTcpHandler::new_server_with_passwords(
            ["owner-secret", "wg-owner-secret"],
            &None,
            Arc::new(ClientProxySelector::new(vec![])),
            Arc::new(NativeResolver::new()),
        );
        let description = format!("{handler:?}");
        for password in ["owner-secret", "wg-owner-secret", "invalid-secret"] {
            let hash = create_password_hash(password);
            assert!(!description.contains(password));
            assert!(!description.contains(std::str::from_utf8(&hash).unwrap()));
            let mut bytes = hash.into_vec();
            bytes.extend_from_slice(b"\r\n\x01\x01\xc0\x00\x02\x01\x01\xbb\r\n");
            let (mut client, server) = tokio::io::duplex(1024);
            client.write_all(&bytes).await.unwrap();
            client.shutdown().await.unwrap();
            let result = handler.setup_server_stream(Box::new(server)).await;
            assert_eq!(result.is_ok(), password != "invalid-secret");
        }
    }

    #[tokio::test]
    async fn udp_association_preserves_coalesced_frames_and_routes_each_target() {
        let location = NetLocation::from_str("0.0.0.0:0", None).unwrap();
        let mut bytes = request(&location);
        bytes[58] = CMD_UDP_ASSOCIATE;
        bytes.extend_from_slice(b"\x01\xc0\x00\x02\x01\x00\x35\x00\x03\r\none");
        bytes.extend_from_slice(b"\x03\x0bexample.com\x01\xbb\x00\x03\r\ntwo");
        let (mut client, server) = tokio::io::duplex(1024);
        client.write_all(&bytes).await.unwrap();
        client.shutdown().await.unwrap();
        let TcpServerSetupResult::MultiDirectionalUdp {
            mut stream,
            need_initial_flush,
            ..
        } = handler()
            .setup_server_stream(Box::new(server))
            .await
            .unwrap()
        else {
            panic!("expected per-destination UDP routing");
        };
        assert!(!need_initial_flush);
        for (destination, payload) in [("192.0.2.1:53", b"one"), ("example.com:443", b"two")] {
            let mut bytes = [0; 3];
            let mut output = tokio::io::ReadBuf::new(&mut bytes);
            let target = std::future::poll_fn(|cx| {
                std::pin::Pin::new(&mut *stream).poll_read_targeted_message(cx, &mut output)
            })
            .await
            .unwrap();
            assert_eq!(target, NetLocation::from_str(destination, None).unwrap());
            assert_eq!(output.filled(), payload);
        }
    }

    #[tokio::test]
    async fn malformed_requests_never_produce_forwarding_work() {
        let valid = request(&NetLocation::from_str("example.com:443", None).unwrap());
        let mut cases = vec![(b"short\r\n".to_vec(), ErrorKind::Other)];
        let mut wrong_hash = valid.clone();
        wrong_hash[0] = b'0';
        cases.push((wrong_hash, ErrorKind::Other));
        for command in [0x00, 0xff] {
            let mut request = valid.clone();
            request[58] = command;
            cases.push((request, ErrorKind::InvalidInput));
        }
        let mut bad_address = valid.clone();
        bad_address[59] = 0xff;
        cases.push((bad_address, ErrorKind::InvalidInput));
        cases.push((valid[..62].to_vec(), ErrorKind::ConnectionAborted));
        let mut bad_suffix = valid;
        *bad_suffix.last_mut().unwrap() = b'x';
        cases.push((bad_suffix, ErrorKind::Other));
        for (request, kind) in cases {
            let (mut client, server) = tokio::io::duplex(1024);
            client.write_all(&request).await.unwrap();
            client.shutdown().await.unwrap();
            assert_eq!(
                handler()
                    .setup_server_stream(Box::new(server))
                    .await
                    .err()
                    .unwrap()
                    .kind(),
                kind
            );
        }
    }

    #[cfg(not(feature = "relay-minimal"))]
    #[tokio::test]
    async fn dropping_unpolled_mux_session_releases_transport() {
        let location = NetLocation::new(
            Address::Hostname(MUX_DESTINATION_HOST.into()),
            MUX_DESTINATION_PORT,
        );
        let (mut client, server) = tokio::io::duplex(1024);
        client.write_all(&request(&location)).await.unwrap();
        client.shutdown().await.unwrap();
        let TcpServerSetupResult::Session(session) = handler()
            .setup_server_stream(Box::new(server))
            .await
            .unwrap()
        else {
            panic!("expected multiplexed session");
        };
        drop(session);
        let mut byte = [0];
        let read = std::pin::pin!(client.read(&mut byte));
        assert!(matches!(
            futures::poll!(read),
            std::task::Poll::Ready(Ok(0))
        ));
    }
}
