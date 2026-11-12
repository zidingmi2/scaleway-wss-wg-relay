use crate::tcp::proxy_connector::ProxyConnector;
use crate::{config::ResolvedClientConfig, resolver::Resolver};
use std::sync::Arc;
pub(crate) fn create_proxy_connector(
    config: ResolvedClientConfig,
    _: Arc<dyn Resolver>,
) -> std::io::Result<Option<Box<dyn ProxyConnector>>> {
    if config.protocol.is_direct() {
        return Ok(None);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "relay-minimal supports direct WG carrier and WireGuard egress only",
    ))
}
