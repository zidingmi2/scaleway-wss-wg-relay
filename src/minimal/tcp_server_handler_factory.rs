//! The relay build exposes only Trojan inside WebSocket.
use super::tcp_client_handler_factory::create_tcp_client_proxy_selector;
use crate::{
    client_proxy_selector::ClientProxySelector,
    config::{ResolvedRuleConfig, ResolvedServerProxyConfig},
    option_util::NoneOrSome,
    resolver::Resolver,
    tcp::tcp_handler::TcpServerHandler,
    trojan_handler::TrojanTcpHandler,
    websocket::{WebsocketServerTarget, WebsocketTcpServerHandler},
};
use std::{net::IpAddr, sync::Arc};
#[derive(Default)]
pub(crate) struct HandlerServices;
fn unsupported() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "protocol is excluded from relay-minimal",
    )
}
fn selector_for(
    rules: NoneOrSome<ResolvedRuleConfig>,
    parent: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<Arc<ClientProxySelector>> {
    if rules.is_empty() {
        return Ok(parent.clone());
    }
    Ok(Arc::new(
        create_tcp_client_proxy_selector(rules.into_vec(), resolver.clone())?
            .inherit_inbound_policy(parent)?,
    ))
}
pub fn create_tcp_server_handler(
    config: ResolvedServerProxyConfig,
    selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    bind: Option<IpAddr>,
) -> std::io::Result<Box<dyn TcpServerHandler>> {
    create_tcp_server_handler_shared(config, selector, resolver, bind, &mut HandlerServices)
}
pub(crate) fn create_tcp_server_handler_shared(
    config: ResolvedServerProxyConfig,
    selector: &Arc<ClientProxySelector>,
    resolver: &Arc<dyn Resolver>,
    _: Option<IpAddr>,
    _: &mut HandlerServices,
) -> std::io::Result<Box<dyn TcpServerHandler>> {
    match config {
        ResolvedServerProxyConfig::Trojan {
            password,
            shadowsocks,
        } => {
            if shadowsocks.is_some() {
                return Err(unsupported());
            }
            Ok(Box::new(TrojanTcpHandler::new_server_with_passwords(
                password.iter().map(String::as_str),
                &shadowsocks,
                selector.clone(),
                resolver.clone(),
            )))
        }
        ResolvedServerProxyConfig::Websocket { targets } => {
            let mut handlers = Vec::new();
            for target in targets.into_vec() {
                if target.max_early_data != 0 || target.early_data_header_name.is_some() {
                    return Err(unsupported());
                }
                let effective = selector_for(target.override_rules, selector, resolver)?;
                let handler = create_tcp_server_handler_shared(
                    target.protocol,
                    &effective,
                    resolver,
                    None,
                    &mut HandlerServices,
                )?;
                let headers = target.matching_headers.map(|h| {
                    h.into_iter()
                        .map(|(k, v)| (k.to_ascii_lowercase(), v))
                        .collect()
                });
                handlers.push(WebsocketServerTarget {
                    matching_path: target.matching_path,
                    matching_headers: headers,
                    early_data: crate::websocket::EarlyData::new(0, None),
                    ping_type: target.ping_type,
                    handler,
                });
            }
            Ok(Box::new(WebsocketTcpServerHandler::new(handlers)))
        }
        _ => Err(unsupported()),
    }
}
