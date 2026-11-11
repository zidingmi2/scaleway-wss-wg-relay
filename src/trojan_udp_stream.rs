//! Trojan UDP framing on an existing authenticated byte stream.
//!
//! Frames contain a SOCKS address, a big-endian payload length, CRLF, then one datagram.
//! The framing state survives partial IO and cancelled polling. No buffer is allocated at
//! the maximum datagram size until a datagram actually needs it.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::ready;
use tokio::io::ReadBuf;

use crate::address::NetLocation;
use crate::async_stream::{
    AsyncFlushMessage, AsyncPing, AsyncReadTargetedMessage, AsyncShutdownMessage, AsyncStream,
    AsyncTargetedMessageStream, AsyncWriteSourcedMessage,
};
use crate::resources::{Budget, BudgetPermit};
use crate::uot::socks_addr::{parse_socks_packet_address, write_socks_packet_address};

/// Largest IPv4 UDP payload (65535-byte IP packet minus 20-byte IP and 8-byte UDP headers).
pub(crate) const MAX_PAYLOAD: usize = 65_507;
const MAX_ADDRESS: usize = 1 + 1 + 255 + 2;
const MAX_HEADER: usize = MAX_ADDRESS + 2 + 2;
const MAX_IO_POLLS: usize = 64;

pub(crate) struct TrojanUdpStream<S> {
    stream: S,
    read_header: [u8; MAX_HEADER],
    header_filled: usize,
    header_needed: usize,
    read_target: Option<NetLocation>,
    read_payload: Vec<u8>,
    read_memory: Option<BudgetPermit>,
    payload_filled: usize,
    read_closed: bool,
    write_buffer: Vec<u8>,
    write_memory: Option<BudgetPermit>,
    write_sent: usize,
    budget: Arc<Budget>,
}

impl<S: AsyncStream> TrojanUdpStream<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self::with_budget(stream, crate::udp_budget::global())
    }

    fn with_budget(stream: S, budget: Arc<Budget>) -> Self {
        Self {
            stream,
            read_header: [0; MAX_HEADER],
            header_filled: 0,
            header_needed: 1,
            read_target: None,
            read_payload: Vec::new(),
            read_memory: None,
            payload_filled: 0,
            read_closed: false,
            write_buffer: Vec::new(),
            write_memory: None,
            write_sent: 0,
            budget,
        }
    }

    fn close_read(&mut self) -> io::Error {
        self.read_closed = true;
        if self.header_filled == 0 && self.read_target.is_none() {
            io::Error::new(io::ErrorKind::BrokenPipe, "Trojan UDP association closed")
        } else {
            io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete Trojan UDP frame")
        }
    }

    fn poll_drain_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut polls = 0;
        while self.write_sent < self.write_buffer.len() {
            if polls == MAX_IO_POLLS {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let n = ready!(
                Pin::new(&mut self.stream).poll_write(cx, &self.write_buffer[self.write_sent..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write_sent += n;
            polls += 1;
        }
        self.write_buffer.clear();
        self.write_sent = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncStream> AsyncReadTargetedMessage for TrojanUdpStream<S> {
    fn targeted_eof_on_empty(&self) -> bool {
        // An authenticated zero-length UDP frame is a datagram, not stream EOF.
        false
    }

    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<NetLocation>> {
        let this = self.get_mut();
        if this.read_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }

        let mut polls = 0;
        loop {
            if polls == MAX_IO_POLLS {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if this.read_target.is_none() {
                if this.header_filled < this.header_needed {
                    let mut input =
                        ReadBuf::new(&mut this.read_header[this.header_filled..this.header_needed]);
                    ready!(Pin::new(&mut this.stream).poll_read(cx, &mut input))?;
                    let n = input.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(this.close_read()));
                    }
                    this.header_filled += n;
                    polls += 1;
                    continue;
                }

                if this.header_needed == 1 {
                    this.header_needed = match this.read_header[0] {
                        1 => 7 + 4,
                        3 => 2,
                        4 => 19 + 4,
                        _ => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid Trojan UDP address type",
                            )));
                        }
                    };
                    continue;
                }
                if this.header_needed == 2 {
                    let length = this.read_header[1] as usize;
                    if length == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "empty Trojan UDP hostname",
                        )));
                    }
                    this.header_needed = 1 + 1 + length + 2 + 4;
                    continue;
                }

                let (target, address_len) =
                    parse_socks_packet_address(&this.read_header[..this.header_needed])?
                        .ok_or_else(|| io::Error::other("incomplete Trojan UDP address"))?;
                #[cfg(feature = "relay-minimal")]
                if matches!(target.address(), crate::address::Address::Ipv6(_)) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "IPv6 is disabled for this relay",
                    )));
                }
                let payload_len = u16::from_be_bytes([
                    this.read_header[address_len],
                    this.read_header[address_len + 1],
                ]) as usize;
                if this.read_header[address_len + 2..address_len + 4] != *b"\r\n" {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid Trojan UDP frame delimiter",
                    )));
                }
                if payload_len > MAX_PAYLOAD {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Trojan UDP payload exceeds IPv4 datagram limit",
                    )));
                }
                reserve_empty_buffer(
                    &mut this.read_payload,
                    &mut this.read_memory,
                    &this.budget,
                    payload_len,
                )?;
                this.read_payload.resize(payload_len, 0);
                this.payload_filled = 0;
                this.read_target = Some(target);
            }

            if this.payload_filled < this.read_payload.len() {
                let mut input = ReadBuf::new(&mut this.read_payload[this.payload_filled..]);
                ready!(Pin::new(&mut this.stream).poll_read(cx, &mut input))?;
                let n = input.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(this.close_read()));
                }
                this.payload_filled += n;
                polls += 1;
                continue;
            }

            if output.remaining() < this.read_payload.len() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Trojan UDP output buffer is too small",
                )));
            }
            output.put_slice(&this.read_payload);
            let target = this.read_target.take().expect("complete frame target");
            this.read_payload.clear();
            this.header_filled = 0;
            this.header_needed = 1;
            this.payload_filled = 0;
            return Poll::Ready(Ok(target));
        }
    }
}

impl<S: AsyncStream> AsyncWriteSourcedMessage for TrojanUdpStream<S> {
    fn supports_hostname_source(&self) -> bool {
        // Replies identify the actual remote socket; require the shared router to pin its IP.
        false
    }

    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        payload: &[u8],
        source: &NetLocation,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if payload.len() > MAX_PAYLOAD {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Trojan UDP payload exceeds IPv4 datagram limit",
            )));
        }
        ready!(this.poll_drain_write(cx))?;

        let mut header = [0; MAX_HEADER];
        let address_len = write_socks_packet_address(&mut header, source)?;
        header[address_len..address_len + 2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        header[address_len + 2..address_len + 4].copy_from_slice(b"\r\n");
        reserve_empty_buffer(
            &mut this.write_buffer,
            &mut this.write_memory,
            &this.budget,
            address_len + 4 + payload.len(),
        )?;
        this.write_buffer
            .extend_from_slice(&header[..address_len + 4]);
        this.write_buffer.extend_from_slice(payload);
        Poll::Ready(Ok(()))
    }
}

/// Resize only between frames. Reserving the replacement while the previous buffer is
/// still charged includes transient reallocation memory in the global byte budget.
fn reserve_empty_buffer(
    buffer: &mut Vec<u8>,
    memory: &mut Option<BudgetPermit>,
    budget: &Arc<Budget>,
    required: usize,
) -> io::Result<()> {
    if buffer.capacity() >= required {
        return Ok(());
    }
    debug_assert!(buffer.is_empty());
    let reservation = budget.acquire(required).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            "UDP framing memory budget exhausted",
        )
    })?;
    let mut replacement = Vec::new();
    replacement.try_reserve_exact(required).map_err(|_| {
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            "cannot allocate UDP frame buffer",
        )
    })?;
    *buffer = replacement;
    *memory = Some(reservation);
    Ok(())
}

impl<S: AsyncStream> AsyncFlushMessage for TrojanUdpStream<S> {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_write(cx))?;
        Pin::new(&mut this.stream).poll_flush(cx)
    }
}

impl<S: AsyncStream> AsyncShutdownMessage for TrojanUdpStream<S> {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush_message(cx))?;
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

impl<S: AsyncStream> AsyncPing for TrojanUdpStream<S> {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    fn poll_write_ping(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        ready!(self.as_mut().poll_flush_message(cx))?;
        Pin::new(&mut self.get_mut().stream).poll_write_ping(cx)
    }
}

impl<S: AsyncStream> AsyncTargetedMessageStream for TrojanUdpStream<S> {
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.stream.peer_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn ipv4_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![1, 192, 0, 2, 1, 0, 53];
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(b"\r\n");
        frame.extend_from_slice(payload);
        frame
    }

    async fn read<S: AsyncStream>(
        stream: &mut TrojanUdpStream<S>,
    ) -> io::Result<(NetLocation, Vec<u8>)> {
        let mut bytes = vec![0; MAX_PAYLOAD];
        let mut output = ReadBuf::new(&mut bytes);
        let target =
            poll_fn(|cx| Pin::new(&mut *stream).poll_read_targeted_message(cx, &mut output))
                .await?;
        Ok((target, output.filled().to_vec()))
    }

    #[tokio::test]
    async fn split_headers_payload_and_multiple_destinations() {
        let v4 = ipv4_frame(b"first");
        let mut domain = b"\x03\x0bexample.com\x01\xbb\x00\x06\r\nsecond".to_vec();
        if !cfg!(feature = "relay-minimal") {
            let mut v6 = vec![4];
            v6.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
            v6.extend_from_slice(b"\x01\xbb\x00\x05\r\nthird");
            domain.extend_from_slice(&v6);
        }
        for split in 0..=v4.len() {
            let (mut sender, receiver) = tokio::io::duplex(7);
            let mut stream = TrojanUdpStream::new(receiver);
            let send = async {
                sender.write_all(&v4[..split]).await.unwrap();
                tokio::task::yield_now().await;
                sender.write_all(&v4[split..]).await.unwrap();
                sender.write_all(&domain).await.unwrap();
                sender.shutdown().await.unwrap();
            };
            let receive = async {
                for (target, payload) in [
                    ("192.0.2.1:53", b"first".as_slice()),
                    ("example.com:443", b"second".as_slice()),
                    ("[::1]:443", b"third".as_slice()),
                ] {
                    if cfg!(feature = "relay-minimal") && target.starts_with('[') {
                        continue;
                    }
                    let actual = read(&mut stream).await.unwrap();
                    assert_eq!(actual.0, NetLocation::from_str(target, None).unwrap());
                    assert_eq!(actual.1, payload);
                }
                assert_eq!(
                    read(&mut stream).await.unwrap_err().kind(),
                    io::ErrorKind::BrokenPipe
                );
            };
            tokio::join!(send, receive);
        }
    }

    #[tokio::test]
    async fn empty_datagram_is_not_eof_and_maximum_datagram_is_preserved() {
        let (mut sender, receiver) = tokio::io::duplex(97);
        let mut stream = TrojanUdpStream::new(receiver);
        assert!(!stream.targeted_eof_on_empty());
        let payload = (0..MAX_PAYLOAD)
            .map(|n| (n % 251) as u8)
            .collect::<Vec<_>>();
        let send = async {
            sender.write_all(&ipv4_frame(&[])).await.unwrap();
            sender.write_all(&ipv4_frame(&payload)).await.unwrap();
            sender.shutdown().await.unwrap();
        };
        let receive = async {
            assert!(read(&mut stream).await.unwrap().1.is_empty());
            assert_eq!(read(&mut stream).await.unwrap().1, payload);
            assert_eq!(
                read(&mut stream).await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
        };
        tokio::join!(send, receive);
    }

    #[tokio::test]
    async fn malformed_and_truncated_frames_are_errors() {
        let mut bad_crlf = ipv4_frame(b"x");
        bad_crlf[9] = b'x';
        let mut oversize = ipv4_frame(&[]);
        oversize[7..9].copy_from_slice(&u16::MAX.to_be_bytes());
        for (frame, kind) in [
            (vec![0xff], io::ErrorKind::InvalidData),
            (vec![3, 0], io::ErrorKind::InvalidData),
            (bad_crlf, io::ErrorKind::InvalidData),
            (oversize, io::ErrorKind::InvalidData),
            (vec![1, 192], io::ErrorKind::UnexpectedEof),
            (
                ipv4_frame(b"abc")[..12].to_vec(),
                io::ErrorKind::UnexpectedEof,
            ),
        ] {
            let (mut sender, receiver) = tokio::io::duplex(64);
            sender.write_all(&frame).await.unwrap();
            sender.shutdown().await.unwrap();
            assert_eq!(
                read(&mut TrojanUdpStream::new(receiver))
                    .await
                    .unwrap_err()
                    .kind(),
                kind
            );
        }
    }

    #[tokio::test]
    async fn cancellation_retains_partial_frame_and_small_output_never_panics() {
        let frame = ipv4_frame(b"payload");
        let (mut sender, receiver) = tokio::io::duplex(64);
        let mut stream = TrojanUdpStream::new(receiver);
        sender.write_all(&frame[..13]).await.unwrap();
        {
            let partial = read(&mut stream);
            tokio::pin!(partial);
            assert!(matches!(futures::poll!(partial.as_mut()), Poll::Pending));
        }
        sender.write_all(&frame[13..]).await.unwrap();
        // Drop the future's borrow before repolling the same framing state.
        let mut small = [0; 1];
        let mut output = ReadBuf::new(&mut small);
        let error = poll_fn(|cx| Pin::new(&mut stream).poll_read_targeted_message(cx, &mut output))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(read(&mut stream).await.unwrap().1, b"payload");
    }

    #[tokio::test]
    async fn partial_writes_flush_exactly_once_and_shutdown_drains() {
        let (client, mut receiver) = tokio::io::duplex(3);
        let mut stream = TrojanUdpStream::new(client);
        let target = NetLocation::from_str("192.0.2.1:53", None).unwrap();
        let write = async {
            for payload in [b"first".as_slice(), b"".as_slice(), b"second".as_slice()] {
                poll_fn(|cx| {
                    Pin::new(&mut stream).poll_write_sourced_message(cx, payload, &target)
                })
                .await
                .unwrap();
            }
            poll_fn(|cx| Pin::new(&mut stream).poll_shutdown_message(cx))
                .await
                .unwrap();
        };
        let receive = async {
            let mut actual = Vec::new();
            receiver.read_to_end(&mut actual).await.unwrap();
            assert_eq!(
                actual,
                [ipv4_frame(b"first"), ipv4_frame(b""), ipv4_frame(b"second")].concat()
            );
        };
        tokio::join!(write, receive);
    }

    #[tokio::test]
    async fn zero_byte_writes_fail_instead_of_spinning() {
        struct ZeroWriter;
        impl tokio::io::AsyncRead for ZeroWriter {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }
        impl tokio::io::AsyncWrite for ZeroWriter {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(0))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        impl AsyncPing for ZeroWriter {
            fn supports_ping(&self) -> bool {
                false
            }
            fn poll_write_ping(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<io::Result<bool>> {
                Poll::Ready(Ok(false))
            }
        }
        impl AsyncStream for ZeroWriter {}
        let mut stream = TrojanUdpStream::new(ZeroWriter);
        let target = NetLocation::from_str("192.0.2.1:53", None).unwrap();
        poll_fn(|cx| Pin::new(&mut stream).poll_write_sourced_message(cx, b"data", &target))
            .await
            .unwrap();
        let error = poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    }

    #[test]
    fn lazy_buffer_growth_is_charged_and_released_with_the_association() {
        let budget = Arc::new(Budget::new(Some(128)));
        let (_sender, receiver) = tokio::io::duplex(64);
        let mut stream = TrojanUdpStream::with_budget(receiver, budget.clone());
        assert_eq!(budget.snapshot().active, 0);
        reserve_empty_buffer(
            &mut stream.read_payload,
            &mut stream.read_memory,
            &budget,
            32,
        )
        .unwrap();
        assert_eq!(budget.snapshot().active, 32);
        reserve_empty_buffer(
            &mut stream.read_payload,
            &mut stream.read_memory,
            &budget,
            64,
        )
        .unwrap();
        assert_eq!(budget.snapshot().active, 64);
        assert_eq!(budget.snapshot().peak, 96);
        let error = reserve_empty_buffer(
            &mut stream.write_buffer,
            &mut stream.write_memory,
            &budget,
            65,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert_eq!(budget.snapshot().active, 64);
        drop(stream);
        assert_eq!(budget.snapshot().active, 0);
    }

    #[cfg(feature = "relay-minimal")]
    #[tokio::test]
    async fn relay_rejects_ipv6_and_ipv4_mapped_ipv6_before_routing() {
        for address in ["2001:db8::1", "::ffff:192.0.2.1"] {
            let mut frame = vec![4];
            frame.extend_from_slice(&address.parse::<std::net::Ipv6Addr>().unwrap().octets());
            frame.extend_from_slice(b"\x00\x35\x00\x00\r\n");
            let (mut sender, receiver) = tokio::io::duplex(64);
            sender.write_all(&frame).await.unwrap();
            let error = read(&mut TrojanUdpStream::new(receiver)).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        }
    }
}
