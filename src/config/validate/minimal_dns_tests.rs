use super::*;
use serde_json::{Value, json};

fn profile() -> Value {
    json!([
        {"client_group":"wg", "client_chain":{
            "address":"192.0.2.1:51820", "protocol":{
                "type":"wireguard",
                "private_key":"KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=",
                "public_key":"F9firNML9eGdhhroCYjRf66PZi9dgLAFP2zHPNqx0mQ=",
                "addresses":["10.77.0.2/32"]
            }
        }},
        {"dns_group":"application", "dns_servers":[{
            "url":"udp://192.0.2.53", "client_chain":"wg"
        }]},
        {"address":"127.0.0.1:8080", "protocol":{"type":"trojan", "password":"offline"},
         "dns":{"servers":"application"}, "rules":[{
             "masks":{"any_destination":true}, "action":"allow", "client_chain":"wg"
         }]}
    ])
}

fn validate(value: Value) -> std::io::Result<ValidatedConfigs> {
    create_server_configs(serde_json::from_value(value).unwrap())
}

fn assert_dns_rejected(value: Value) {
    let error = validate(value).err().expect("unsafe application DNS must be rejected");
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    assert!(error.to_string().contains("ingress DNS"), "{error}");
}

#[test]
fn wg_application_dns_rejects_implicit_system_empty_and_direct_routes() {
    validate(profile()).unwrap();
    for dns in [
        Value::Null,
        json!({}),
        json!({"servers":null}),
        json!({"servers":[]}),
        json!({"servers":"system"}),
        json!({"servers":{"url":"system"}}),
        json!({"servers":"udp://192.0.2.53"}),
        json!({"servers":{"url":"tcp://192.0.2.53", "client_chain":"direct"}}),
    ] {
        let mut raw = profile();
        raw[2]["dns"] = dns;
        assert_dns_rejected(raw);
    }
    let mut raw = profile();
    raw[2].as_object_mut().unwrap().remove("dns");
    raw.as_array_mut().unwrap().push(json!({
        "global_settings":{"default_dns":{"servers":"system"}}
    }));
    assert_dns_rejected(raw);
}

#[test]
fn wg_application_dns_checks_inheritance_inline_and_composed_groups() {
    let mut inherited = profile();
    inherited[2].as_object_mut().unwrap().remove("dns");
    inherited.as_array_mut().unwrap().push(json!({
        "global_settings":{"default_dns":{"servers":"application"}}
    }));
    validate(inherited).unwrap();

    let mut inline = profile();
    inline[2]["dns"] = json!({"servers":[{
        "url":"tcp://192.0.2.53", "client_chain":"wg"
    }]});
    validate(inline).unwrap();

    for leak in [json!("system"), json!("udp://192.0.2.54")] {
        let mut composed = profile();
        composed.as_array_mut().unwrap().push(json!({
            "dns_group":"composed", "dns_servers":["application", leak]
        }));
        composed[2]["dns"] = json!({"servers":"composed"});
        assert_dns_rejected(composed);
    }
    let mut hosts_with_default = profile();
    hosts_with_default[2]["dns"] = json!({"hosts":{"fixed.example":"192.0.2.10"}});
    assert_dns_rejected(hosts_with_default);
}

#[test]
fn wg_dns_and_ingress_require_every_selectable_branch_to_use_the_tunnel() {
    for branch in ["direct", "wg"] {
        for nested in [false, true] {
            let mut raw = profile();
            raw.as_array_mut().unwrap().push(json!({
                "client_group":"choices", "client_chains":[
                    {"chain":["wg"]}, {"chain":[branch]}
                ]
            }));
            let route = if nested {
                raw.as_array_mut().unwrap().push(json!({
                    "client_group":"outer", "client_chains":[
                        {"chain":["choices"]}, {"chain":["wg"]}
                    ]
                }));
                "outer"
            } else {
                "choices"
            };
            raw[1]["dns_servers"][0]["client_chain"] = json!(route);
            if branch == "direct" {
                assert_dns_rejected(raw.clone());
            } else {
                validate(raw.clone()).unwrap();
            }
            raw[1]["dns_servers"][0]["client_chain"] = json!("wg");
            raw[2]["rules"][0]["client_chain"] = json!(route);
            let result = validate(raw);
            if branch == "direct" {
                let error = result.err().unwrap();
                assert!(error.to_string().contains("direct-egress route"), "{error}");
            } else {
                result.unwrap();
            }
        }
    }
}

#[test]
fn only_effective_websocket_rules_determine_application_dns_use() {
    let mut raw = profile();
    raw[2].as_object_mut().unwrap().remove("dns");
    raw[2]["protocol"] = json!({"type":"websocket", "targets":[{
        "matching_path":"/offline", "protocol":{"type":"trojan", "password":"offline"},
        "override_rules":"block-all"
    }]});
    validate(raw.clone()).unwrap();

    raw[2]["protocol"]["targets"][0]["override_rules"] = raw[2]["rules"].clone();
    raw[2]["rules"] = json!("block-all");
    assert_dns_rejected(raw.clone());
    raw[2]["dns"] = json!({"servers":"application"});
    validate(raw).unwrap();
}

#[test]
fn maintenance_and_provably_ip_only_rules_do_not_require_unused_application_dns() {
    for rules in [
        json!("block-all"),
        json!([
            {"masks":{"any_destination":true}, "action":"block"},
            {"masks":{"any_destination":true}, "action":"allow", "client_chain":"wg"}
        ]),
        json!([{"masks":"192.0.2.0/24", "no_resolve":true,
                "action":"allow", "client_chain":"wg"}]),
        json!([{"masks":{"not":{"ip_cidr":["192.0.2.0/24"]}}, "no_resolve":true,
                "action":"allow", "client_chain":"wg"}]),
        json!([{"masks":{"domain":["fixed.example"]}, "override_address":"192.0.2.10:443",
                "action":"allow", "client_chain":"wg"}]),
    ] {
        let mut raw = profile();
        raw[2].as_object_mut().unwrap().remove("dns");
        raw[2]["rules"] = rules;
        validate(raw).unwrap();
    }
    // no_resolve suppresses IP matching lookups; it cannot suppress a
    // hostname which another OR branch permits the connector to resolve.
    let mut raw = profile();
    raw[2].as_object_mut().unwrap().remove("dns");
    raw[2]["rules"] = json!([{
        "masks":{"any":[{"ip_cidr":["192.0.2.0/24"]},{"domain":["allowed.example"]}]},
        "no_resolve":true, "action":"allow", "client_chain":"wg"
    }]);
    assert_dns_rejected(raw);

    // Even block rules may issue DNS before the final maintenance rejection.
    let mut raw = profile();
    raw[2].as_object_mut().unwrap().remove("dns");
    raw[2]["rules"] = json!([{"masks":"192.0.2.0/24", "action":"block"}]);
    assert_dns_rejected(raw);
}

#[test]
fn bootstrap_groups_and_direct_mode_keep_their_separate_contracts() {
    let mut raw = profile();
    raw.as_array_mut().unwrap().extend([
        json!({"dns_group":"bootstrap-only", "dns_servers":"system"}),
        json!({"dns_group":"unused-infrastructure", "dns_servers":[{
            "url":"tls://resolver.invalid:853", "bootstrap_url":"bootstrap-only"
        }]}),
    ]);
    validate(raw).unwrap();

    for dns in [Value::Null, json!({"servers":"system"}), json!({"servers":"udp://192.0.2.53"})] {
        let mut raw = profile();
        raw[0] = json!({"global_settings":{"relay_egress":"direct"}});
        raw[1]["dns_servers"][0]["client_chain"] = json!("direct");
        raw[2]["rules"][0]["client_chain"] = json!("direct");
        raw[2]["dns"] = dns;
        validate(raw).unwrap();
    }
}
