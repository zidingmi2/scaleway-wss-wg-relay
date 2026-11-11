//! Shared IP packet helpers only; no device creation or host-network management.
#[path = "../tun/udp_handler.rs"]
pub(crate) mod udp_handler;
#[path = "../tun/udp_manager.rs"]
pub(crate) mod udp_manager;
use crate::{address::NetLocation, client_proxy_selector::ClientProxySelector, resolver::Resolver};
use log::{debug, warn};
use std::sync::Arc;
pub(crate) async fn handle_tcp_connection<T: crate::async_stream::AsyncStream>(
    mut connection: T,
    target: NetLocation,
    proxy_selector: Arc<ClientProxySelector>,
    resolver: Arc<dyn Resolver>,
    source: Option<std::net::SocketAddr>,
) -> std::io::Result<()> {
    let _permit = crate::resources::try_stream().ok_or_else(crate::resources::exhausted)?;
    let prepared =
        crate::tcp::ingress::PreparedTcp::new(&proxy_selector, target.clone(), Vec::new())?
            .with_source(source);
    let route = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        prepared.route(&mut connection, &proxy_selector, &resolver),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TUN routing timed out"))??;
    let connected = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        use tokio::io::AsyncWriteExt;
        let routed = route.connect(&resolver).await?;
        let Some(mut setup) = routed.setup else {
            return Ok(None);
        };
        let flow = setup.client_stream.flow().cloned();
        crate::control::tracked_stream::during_flow(flow.as_deref(), async {
            if let Some(data) = setup.early_data.take() {
                connection.write_all(&data).await?;
                connection.flush().await?;
            }
            if !routed.prefix.is_empty() {
                setup.client_stream.write_all(&routed.prefix).await?;
                setup.client_stream.flush().await?;
            }
            Ok(())
        })
        .await?;
        drop(routed.prefix);
        Ok::<_, std::io::Error>(Some((setup.client_stream, routed.wire_destination)))
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TUN TCP setup timed out"))
    .and_then(|result| result)
    .inspect_err(|error| warn!("Failed to connect to {}: {}", target, error))?;
    drop(proxy_selector);
    drop(resolver);

    let Some((mut remote, wire_destination)) = connected else {
        debug!("TCP connection blocked by rules");
        return Ok(());
    };
    let flow = remote.flow().cloned();
    let result = tokio::select! {
        result = tokio::io::copy_bidirectional(&mut connection, &mut remote) => result,
        _ = crate::control::tracked_stream::wait_cancel(flow.as_deref()) => Err(crate::control::tracked_stream::cancelled()),
    };
    match result {
        Ok((sent, received)) => debug!(
            "TCP connection to {} completed: {} bytes sent, {} bytes received",
            wire_destination, sent, received,
        ),
        Err(error) => debug!("TCP connection to {} error: {}", wire_destination, error),
    }
    Ok(())
}

use crate::ip_stack::{packet, wake};
