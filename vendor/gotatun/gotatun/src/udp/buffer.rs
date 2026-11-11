// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

//! Generic buffered `UdpTransport` implementation.

use std::{net::SocketAddr, sync::Arc};

use futures::{FutureExt, select};
use tokio::{io, sync::mpsc};

use crate::packet::{Packet, PacketBufPool};
use crate::task::Task;
use crate::udp::{UdpRecv, UdpSend};

/// A [`UdpSend`] that wraps another [`UdpSend`] to provide buffering.
///
/// Packets sent on this [`UdpSend::send_to`] will be buffered on a channel, and asynchronously
/// processed on another task. This means [`UdpSend::send_to`] won't block unless the channel is
/// full.
#[derive(Clone)]
pub struct BufferedUdpSend {
    _send_task: Arc<Task>,

    /// Channel where IPv4 packets are sent to `_send_task`
    send_tx_v4: mpsc::Sender<(Packet, SocketAddr)>,

    /// Channel where IPv6 packets are sent to `_send_task`
    send_tx_v6: mpsc::Sender<(Packet, SocketAddr)>,
}

impl BufferedUdpSend {
    /// Wrap a [`UdpSend`] into a [`BufferedUdpSend`] with `capacity`.
    pub fn new(capacity: usize, udp_tx: impl UdpSend + 'static) -> Self {
        let (send_tx_v4, mut send_rx_v4) = mpsc::channel::<(Packet, SocketAddr)>(capacity);
        let (send_tx_v6, mut send_rx_v6) = mpsc::channel::<(Packet, SocketAddr)>(capacity);

        let send_task = Task::spawn("buffered UDP send", async move {
            let mut buf_v4 = vec![];
            let mut buf_v6 = vec![];
            let max_packet_count = udp_tx.max_number_of_packets_to_send();
            let mut send_many_buf = Default::default();

            loop {
                // use separate channels because we musn't call `send_many_to` with mixed IPv4/IPv6.
                let (count, buf) = select! {
                    // recv_many is cancel-safe
                    n = send_rx_v4.recv_many(&mut buf_v4, max_packet_count).fuse() => (n, &mut buf_v4),
                    n = send_rx_v6.recv_many(&mut buf_v6, max_packet_count).fuse() => (n, &mut buf_v6),
                };
                match count {
                    0 => break,
                    1 => {
                        let (packet, addr) =
                            buf.pop().expect("recv_many received 1 packet into buf");
                        let _ = udp_tx
                            .send_to(packet, addr)
                            .await
                            .inspect_err(|e| tracing::trace!("send_to_err: {e:#}"));
                    }
                    2.. => {
                        // send all packets at once
                        if let Err(e) = udp_tx.send_many_to(&mut send_many_buf, buf).await {
                            tracing::trace!("send_to_many_err: {e:#}");
                            if !buf.is_empty() {
                                tracing::trace!(
                                    "send_to_many dropping {} packets due to error.",
                                    buf.len()
                                );
                                buf.clear(); // give up, drop the packets we meant to send
                            }
                        }
                    }
                }
            }
        });

        Self {
            _send_task: Arc::new(send_task),
            send_tx_v4,
            send_tx_v6,
        }
    }
}

impl UdpSend for BufferedUdpSend {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        let tx = match destination {
            SocketAddr::V4(..) => &self.send_tx_v4,
            SocketAddr::V6(..) => &self.send_tx_v6,
        };
        tx.send((packet, destination))
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        Ok(())
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        debug_assert_eq!(
            self.send_tx_v4.max_capacity(),
            self.send_tx_v6.max_capacity(),
        );
        self.send_tx_v4.max_capacity()
    }
}

/// A [`UdpRecv`] that wraps another [`UdpRecv`] to provide buffering.
///
/// This will spawn a background task that continuously calls [`UdpRecv::recv_from`] until the
/// buffer is full. Any call to [`UdpRecv::recv_from`] on _this_ object will not block unless the
/// buffer is empty.
pub struct BufferedUdpReceive {
    _recv_task: Arc<Task>,
    recv_rx: mpsc::Receiver<io::Result<(Packet, SocketAddr)>>,
}

impl BufferedUdpReceive {
    /// Wrap a [`UdpRecv`] into a [`BufferedUdpReceive`] with `capacity`.
    pub fn new(
        capacity: usize,
        mut udp_rx: impl UdpRecv + 'static,
        mut recv_pool: PacketBufPool,
    ) -> Self {
        let (recv_tx, recv_rx) = mpsc::channel(capacity);

        let recv_task = Task::spawn("buffered UDP receive", async move {
            let mut recv_many_buf = Default::default();
            let mut packet_bufs = vec![];

            loop {
                // Read packets from the socket.
                if let Err(err) = udp_rx
                    .recv_many_from(&mut recv_many_buf, &mut recv_pool, &mut packet_bufs)
                    .await
                {
                    let _ = recv_tx.send(Err(err)).await;
                    return;
                }

                for (packet_buf, src) in packet_bufs.drain(..) {
                    match recv_tx.try_send(Ok((packet_buf, src))) {
                        Ok(()) => (),
                        Err(mpsc::error::TrySendError::Full(packet)) => {
                            if recv_tx.send(packet).await.is_err() {
                                // Buffer dropped
                                return;
                            }
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => return,
                    }
                }
            }
        });

        Self {
            _recv_task: Arc::new(recv_task),
            recv_rx,
        }
    }
}

impl UdpRecv for BufferedUdpReceive {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, _pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let Some(packet) = self.recv_rx.recv().await else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "UDP receive task stopped",
            ));
        };
        packet
    }
}

#[cfg(test)]
mod bounded_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::Semaphore;

    struct ActiveSend(Arc<AtomicUsize>);

    impl Drop for ActiveSend {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[derive(Clone)]
    struct BlockedSend {
        started: Arc<Semaphore>,
        release: Arc<Semaphore>,
        active: Arc<AtomicUsize>,
    }

    impl UdpSend for BlockedSend {
        type SendManyBuf = ();

        async fn send_to(&self, _packet: Packet, _target: SocketAddr) -> io::Result<()> {
            self.active.fetch_add(1, Ordering::SeqCst);
            let _active = ActiveSend(Arc::clone(&self.active));
            self.started.add_permits(1);
            self.release.acquire().await.unwrap().forget();
            Ok(())
        }
    }

    #[tokio::test]
    async fn small_send_capacity_applies_backpressure_and_drop_cancels_io() {
        let inner = BlockedSend {
            started: Arc::new(Semaphore::new(0)),
            release: Arc::new(Semaphore::new(0)),
            active: Arc::new(AtomicUsize::new(0)),
        };
        let sender = BufferedUdpSend::new(2, inner.clone());
        let pool: PacketBufPool = PacketBufPool::new_lazy(2);
        let target = "127.0.0.1:1234".parse().unwrap();
        sender.send_to(pool.get(), target).await.unwrap();
        inner.started.acquire().await.unwrap().forget();
        // The transport is stalled on the first packet. Only two additional
        // packets may queue; a fourth send must wait, not silently accumulate.
        sender.send_to(pool.get(), target).await.unwrap();
        sender.send_to(pool.get(), target).await.unwrap();
        {
            let waiting = sender.send_to(pool.get(), target);
            tokio::pin!(waiting);
            assert!(futures::poll!(waiting.as_mut()).is_pending());
            inner.release.add_permits(1);
            tokio::time::timeout(Duration::from_secs(1), waiting)
                .await
                .expect("released queue capacity must wake a waiting sender")
                .unwrap();
        }
        drop(sender);
        for _ in 0..32 {
            if inner.active.load(Ordering::SeqCst) == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(inner.active.load(Ordering::SeqCst), 0);
    }

    struct CountingRecv {
        calls: Arc<AtomicUsize>,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for CountingRecv {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl UdpRecv for CountingRecv {
        type RecvManyBuf = ();

        async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok((pool.get(), "127.0.0.1:1234".parse().unwrap()))
        }
    }

    #[tokio::test]
    async fn small_receive_capacity_stops_reading_and_drop_releases_transport() {
        let calls = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        let inner = CountingRecv {
            calls: Arc::clone(&calls),
            dropped: Arc::clone(&dropped),
        };
        let mut pool: PacketBufPool = PacketBufPool::new_lazy(2);
        let mut receiver = BufferedUdpReceive::new(2, inner, pool.clone());
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        // Two queued plus one pending send, with no further calls to the source.
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        receiver.recv_from(&mut pool).await.unwrap();
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        drop(receiver);
        for _ in 0..32 {
            if dropped.load(Ordering::SeqCst) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(dropped.load(Ordering::SeqCst));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod test {
    use super::*;
    use crate::udp::socket::{SockOpt, UdpSocket};

    #[tokio::test]
    /// Regression test for security advisory GHSA-6gxq-8xp9-742r.
    async fn empty_loopback_datagram_mustnt_stop_buffered_udp_receive() {
        let socket = UdpSocket::bind("127.0.0.1:0".parse().unwrap(), SockOpt::default()).unwrap();
        let addr = socket.local_addr().unwrap();
        let mut receiver = BufferedUdpReceive::new(16, socket, PacketBufPool::new(16));
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();

        sender.send_to(&[], addr).unwrap();
        sender.send_to(b"after-empty", addr).unwrap();

        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            receiver.recv_from(&mut PacketBufPool::new(1)),
        )
        .await
        .expect("the receive task must stop promptly")
        .expect("the panicked receive task must not close its channel");
    }
}
