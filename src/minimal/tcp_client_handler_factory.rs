use crate::client_proxy_selector::{ClientProxySelector, ConnectAction, ConnectRule};
use crate::config::{ResolvedRuleActionConfig, ResolvedRuleConfig};
use crate::resolver::Resolver;
use crate::tcp::chain_builder::try_build_client_chain_group;
use std::sync::Arc;
pub fn create_tcp_client_proxy_selector(
    rules: Vec<ResolvedRuleConfig>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<ClientProxySelector> {
    let rules = rules
        .into_iter()
        .map(|rule_config| {
            let ResolvedRuleConfig {
                criteria, action, ..
            } = rule_config;
            let connect_action = match action {
                ResolvedRuleActionConfig::Allow {
                    override_address,
                    client_chains,
                } => {
                    let chain_group =
                        try_build_client_chain_group(client_chains, resolver.clone())?
                            .with_description(criteria.description.clone());
                    ConnectAction::new_allow(override_address, chain_group)
                }
                ResolvedRuleActionConfig::Block => ConnectAction::new_block(),
            };
            Ok(ConnectRule::compiled(
                criteria.compiled.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "routing predicates must be compiled during config preparation",
                    )
                })?,
                criteria.no_resolve,
                connect_action,
            ))
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    ClientProxySelector::new(rules).with_fake_dns_context(resolver.fake_dns_context())
}

#[cfg(test)]
pub(crate) fn create_test_selector(
    mut rules: Vec<ResolvedRuleConfig>,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<ClientProxySelector> {
    for rule in &mut rules {
        rule.compile(&mut crate::rules::Compiler::default())?;
    }
    create_tcp_client_proxy_selector(rules, resolver)
}
