//! Deliberately narrow, offline converter for the audited sing-box relay configuration.
//!
//! This is not a general sing-box converter. The input policy is compared in full
//! with the supported policy before any native configuration is produced. Secrets
//! are never printed, including on malformed input or native-validation errors.

use std::collections::HashSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value, json};

const MAX_INPUT_BYTES: usize = 1024 * 1024;
const SOURCE_NAMES: [&str; 2] = ["owner", "wg-owner"];
const BLOCKED_DOMAINS: [&str; 4] = [
    "localhost",
    "metadata",
    "metadata.google.internal",
    "instance-data.ec2.internal",
];
const BLOCKED_SUFFIXES: [&str; 4] = ["localhost", "local", "internal", "home.arpa"];
const RESERVED_CIDRS: [&str; 24] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "100::/64",
    "2001:db8::/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

/// All errors have fixed text; do not include an input value or serde diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SafeError(&'static str);

impl fmt::Display for SafeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

type Result<T> = std::result::Result<T, SafeError>;

/// `serde_json::Value` alone accepts duplicate keys. Reject them at every level.
struct UniqueJson(Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON with unique object keys")
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                v: bool,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::Bool(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::Number(v.into())))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::Number(v.into())))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                Number::from_f64(v)
                    .map(|n| UniqueJson(Value::Number(n)))
                    .ok_or_else(|| E::custom("invalid JSON number"))
            }
            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::String(v.into())))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::String(v)))
            }
            fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueJson(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(UniqueJson(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate object key"));
                    }
                    let UniqueJson(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(UniqueJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(JsonVisitor)
    }
}

fn parse_json(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(SafeError("configuration exceeds the 1 MiB input limit"));
    }
    serde_json::from_slice::<UniqueJson>(bytes)
        .map(|v| v.0)
        .map_err(|_| SafeError("configuration must be valid JSON with unique keys"))
}

/// This type intentionally has no Debug or Serialize implementation.
struct Parameters {
    passwords: [String; 2],
    path: String,
    private_key: String,
    public_key: String,
    peer: Ipv4Addr,
    port: u16,
    interface: String,
    dns: [Ipv4Addr; 2],
}

fn text_at<'a>(value: &'a Value, pointer: &str) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or(SafeError(
            "required source field is absent or has the wrong type",
        ))
}

fn key_at(value: &Value, pointer: &str) -> Result<String> {
    let text = text_at(value, pointer)?;
    let valid = STANDARD
        .decode(text)
        .ok()
        .is_some_and(|bytes| bytes.len() == 32 && bytes.iter().any(|b| *b != 0));
    if !valid {
        return Err(SafeError("WireGuard key must encode a nonzero 32-byte key"));
    }
    Ok(text.into())
}

fn reserved_cidrs() -> &'static [&'static str] {
    &RESERVED_CIDRS
}

fn is_reserved_v4(ip: Ipv4Addr) -> bool {
    reserved_cidrs()
        .iter()
        .filter(|s| !s.contains(':'))
        .any(|cidr| {
            let (net, prefix) = cidr.split_once('/').unwrap();
            let prefix: u32 = prefix.parse().unwrap();
            let mask = u32::MAX << (32 - prefix);
            u32::from(ip) & mask == u32::from(net.parse::<Ipv4Addr>().unwrap()) & mask
        })
}

fn public_ip_at(value: &Value, pointer: &str) -> Result<Ipv4Addr> {
    let ip = text_at(value, pointer)?
        .parse::<Ipv4Addr>()
        .map_err(|_| SafeError("WireGuard peer and DNS servers must be literal IPv4 addresses"))?;
    if is_reserved_v4(ip) {
        return Err(SafeError(
            "WireGuard peer and DNS servers must be public IPv4 addresses",
        ));
    }
    Ok(ip)
}

impl Parameters {
    fn read(source: &Value) -> Result<Self> {
        let mut passwords = [String::new(), String::new()];
        for (i, password) in passwords.iter_mut().enumerate() {
            let value = text_at(source, &format!("/inbounds/0/users/{i}/password"))?;
            if !(16..=1024).contains(&value.len()) || value.chars().any(char::is_control) {
                return Err(SafeError(
                    "Trojan passwords must be 16–1024 bytes without control characters",
                ));
            }
            *password = value.into();
        }
        if passwords[0] == passwords[1] {
            return Err(SafeError(
                "the two Trojan identities must use distinct passwords",
            ));
        }
        let path = text_at(source, "/inbounds/0/transport/path")?;
        if !(2..=1024).contains(&path.len())
            || !path.starts_with('/')
            || path
                .chars()
                .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '?' | '#' | '\\'))
        {
            return Err(SafeError("unsupported WebSocket path"));
        }
        let interface = text_at(source, "/endpoints/0/address/0")?;
        let valid_interface = interface.split_once('/').is_some_and(|(ip, prefix)| {
            let Ok(ip) = ip.parse::<Ipv4Addr>() else {
                return false;
            };
            let Ok(prefix) = prefix.parse::<u8>() else {
                return false;
            };
            prefix <= 32
                && !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_broadcast()
        });
        if !valid_interface {
            return Err(SafeError(
                "WireGuard interface requires one unicast IPv4 CIDR",
            ));
        }
        let port = source
            .pointer("/endpoints/0/peers/0/port")
            .and_then(Value::as_u64)
            .filter(|v| (1..=65535).contains(v))
            .ok_or(SafeError("WireGuard peer port is invalid"))? as u16;
        let dns = [
            public_ip_at(source, "/dns/servers/0/server")?,
            public_ip_at(source, "/dns/servers/1/server")?,
        ];
        if dns[0] == dns[1] {
            return Err(SafeError("two distinct DNS servers are required"));
        }
        Ok(Self {
            passwords,
            path: path.into(),
            private_key: key_at(source, "/endpoints/0/private_key")?,
            public_key: key_at(source, "/endpoints/0/peers/0/public_key")?,
            peer: public_ip_at(source, "/endpoints/0/peers/0/address")?,
            port,
            interface: interface.into(),
            dns,
        })
    }
}

fn expected_source(p: &Parameters) -> Value {
    json!({
        "log":{"level":"warn","timestamp":false},
        "dns":{
            "servers":[
                {"type":"udp","tag":"wg-dns-1","server":p.dns[0].to_string(),"server_port":53,"detour":"wg-exit"},
                {"type":"udp","tag":"wg-dns-2","server":p.dns[1].to_string(),"server_port":53,"detour":"wg-exit"}
            ],
            "final":"wg-dns-1","strategy":"ipv4_only",
            "rules":[
                {"action":"evaluate","server":"wg-dns-1","tag":"primary","timeout":"10s"},
                {"match_response":"primary","response_rcode":"NOERROR","ip_accept_any":true,"action":"respond","race":true},
                {"action":"evaluate","server":"wg-dns-2","tag":"secondary","speculative":true,"timeout":"10s"},
                {"match_response":"secondary","response_rcode":"NOERROR","ip_accept_any":true,"action":"respond","race":true},
                {"match_response":"primary","action":"respond"},
                {"match_response":"secondary","action":"respond"},
                {"action":"predefined","rcode":"SERVFAIL"}
            ]
        },
        "inbounds":[{
            "type":"trojan","tag":"private-ws","listen":"0.0.0.0","listen_port":8080,
            "users":[{"name":SOURCE_NAMES[0],"password":p.passwords[0]},{"name":SOURCE_NAMES[1],"password":p.passwords[1]}],
            "transport":{"type":"ws","path":p.path}
        }],
        "outbounds":[{"type":"direct","tag":"wg-socket-only","connect_timeout":"10s"}],
        "route":{
            "default_domain_resolver":"wg-dns-1",
            "rules":[
                {"ip_cidr":["::/0"],"action":"reject"},
                {"domain":BLOCKED_DOMAINS,"action":"reject"},
                {"domain_suffix":BLOCKED_SUFFIXES,"action":"reject"},
                {"action":"resolve","strategy":"ipv4_only"},
                {"ip_is_private":true,"action":"reject"},
                {"ip_cidr":reserved_cidrs(),"action":"reject"},
                {"network":"udp","action":"route-options","udp_connect":true},
                {"auth_user":SOURCE_NAMES,"action":"route","outbound":"wg-exit"},
                {"action":"reject"}
            ],"final":"wg-exit"
        },
        "endpoints":[{
            "type":"wireguard","tag":"wg-exit","system":false,"mtu":1280,
            "address":[p.interface],"private_key":p.private_key,
            "peers":[{"address":p.peer.to_string(),"port":p.port,"public_key":p.public_key,
                "allowed_ips":["0.0.0.0/0"],"persistent_keepalive_interval":25}],
            "workers":1,"detour":"wg-socket-only"
        }]
    })
}

fn convert(source: &Value) -> Result<Value> {
    let p = Parameters::read(source)?;
    if *source != expected_source(&p) {
        return Err(SafeError(
            "source contains unknown fields or an unsupported policy; conversion refused",
        ));
    }
    let v4_cidrs: Vec<&str> = reserved_cidrs()
        .iter()
        .copied()
        .filter(|s| !s.contains(':'))
        .collect();
    let dns_specs: Vec<Value> = p
        .dns
        .iter()
        .map(|ip| {
            json!({
                "url":format!("udp://{ip}:53"),"client_chain":"wg-exit","ip_strategy":"ipv4_only",
                "timeout_secs":10,"connect_timeout_secs":10,"attempts":1
            })
        })
        .collect();
    Ok(json!([
        {"global_settings":{"max_connections":80,"max_streams":80,"max_udp_destinations":256,
            "default_dns":{"servers":"relay-dns"}}},
        {"dns_group":"relay-dns","dns_servers":dns_specs},
        {"client_group":"wg-exit","client_chains":[{
            "address":format!("{}:{}",p.peer,p.port),
            "protocol":{
                "type":"wireguard","private_key":p.private_key,"public_key":p.public_key,
                "addresses":[p.interface],"allowed_ips":["0.0.0.0/0"],
                "persistent_keepalive":25,"mtu":1280,
                "resource_limits":{
                    "tcp_buffer_size":32768,"tcp_buffer_max_size":1048576,
                    "tcp_memory_bytes":33554432,"max_tcp_connections":80,
                    "max_udp_sessions":128,"max_udp_destinations":256,
                    "max_udp_destinations_per_session":32,"max_udp_queued_bytes":8388608
                }
            }
        }]},
        {
            "name":"private-ws","address":"0.0.0.0:8080","sniff":false,
            "protocol":{"type":"websocket","targets":[{
                "matching_path":p.path,"max_early_data":0,"ping_type":"disabled",
                "protocol":{"type":"trojan","password":p.passwords}
            }]},
            "dns":{"servers":"relay-dns"},
            "rules":[
                {"masks":{"domain":BLOCKED_DOMAINS},"action":"block"},
                {"masks":{"domain_suffix":BLOCKED_SUFFIXES},"action":"block"},
                {"masks":{"ip_cidr":["::/0"]},"action":"block"},
                {"masks":{"ip_cidr":v4_cidrs},"action":"block"},
                {"masks":{"ip_cidr":["0.0.0.0/0"]},"action":"allow","client_chain":"wg-exit"},
                {"masks":{"any_destination":true},"action":"block"}
            ]
        }
    ]))
}

fn validate_native(config: &Value) -> Result<()> {
    if !cfg!(feature = "relay-minimal") {
        return Err(SafeError(
            "relay-config must be built with the relay-minimal feature",
        ));
    }
    let native: Vec<shoes::config::Config> = serde_json::from_value(config.clone())
        .map_err(|_| SafeError("converted configuration failed native schema validation"))?;
    shoes::config::create_server_configs(native)
        .map(|_| ())
        .map_err(|_| SafeError("converted configuration failed native policy validation"))
}

fn read_limited(reader: impl Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SafeError("could not read configuration input"))?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(SafeError("configuration exceeds the 1 MiB input limit"));
    }
    Ok(bytes)
}

fn read_path(path: &Path) -> Result<Vec<u8>> {
    let file = fs::File::open(path).map_err(|_| SafeError("could not open configuration input"))?;
    read_limited(file)
}

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn write_private_atomic(output: &Path, contents: &[u8]) -> Result<()> {
    #[cfg(not(unix))]
    {
        let _ = (output, contents);
        return Err(SafeError(
            "private output requires Unix file permission support",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let parent = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if output.file_name().is_none() {
            return Err(SafeError("output must name a private configuration file"));
        }
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SafeError("could not create private output"))?
            .as_nanos();
        let temp = parent.join(format!(
            ".relay-config-{}-{stamp}-{}.tmp",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|_| SafeError("could not create private output"))?;
        let written = (|| {
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| SafeError("could not protect private output"))?;
            file.write_all(contents)
                .map_err(|_| SafeError("could not write private output"))?;
            file.write_all(b"\n")
                .map_err(|_| SafeError("could not write private output"))?;
            file.sync_all()
                .map_err(|_| SafeError("could not sync private output"))?;
            drop(file);
            fs::rename(&temp, output).map_err(|_| SafeError("could not publish private output"))?;
            Ok(())
        })();
        if written.is_err() {
            let _ = fs::remove_file(&temp);
        }
        written
    }
}

struct Options {
    input: String,
    output: Option<PathBuf>,
    check: bool,
    compare: Option<PathBuf>,
}

fn parse_options(args: impl IntoIterator<Item = String>) -> Result<Option<Options>> {
    let mut options = Options {
        input: "-".into(),
        output: None,
        check: false,
        compare: None,
    };
    let mut args = args.into_iter();
    let mut seen = HashSet::new();
    while let Some(arg) = args.next() {
        if !seen.insert(arg.clone()) {
            return Err(SafeError("duplicate command-line option"));
        }
        match arg.as_str() {
            "--help" | "-h" => return Ok(None),
            "--input" => {
                options.input = args
                    .next()
                    .ok_or(SafeError("--input requires a path or -"))?
            }
            "--output" => {
                let value = args
                    .next()
                    .ok_or(SafeError("--output requires a private file path"))?;
                if value == "-" {
                    return Err(SafeError(
                        "secret configuration cannot be written to standard output",
                    ));
                }
                options.output = Some(value.into());
            }
            "--check" => options.check = true,
            "--compare" => {
                options.compare = Some(
                    args.next()
                        .ok_or(SafeError("--compare requires a native configuration path"))?
                        .into(),
                )
            }
            _ => return Err(SafeError("unsupported command-line option")),
        }
    }
    if options.check == options.output.is_some() || (options.compare.is_some() && !options.check) {
        return Err(SafeError(
            "select either --check [--compare FILE] or --output FILE",
        ));
    }
    Ok(Some(options))
}

fn run() -> Result<()> {
    let Some(options) = parse_options(std::env::args().skip(1))? else {
        println!(
            "relay-config --input SOURCE.json|- (--check [--compare NATIVE.json] | --output PRIVATE.json)\nOffline strict conversion; never prints credentials. No network or WireGuard sessions are started."
        );
        return Ok(());
    };
    let input = if options.input == "-" {
        read_limited(io::stdin().lock())?
    } else {
        read_path(Path::new(&options.input))?
    };
    let source = parse_json(&input)?;
    let native = convert(&source)?;
    validate_native(&native)?;
    if let Some(compare) = options.compare {
        let existing = parse_json(&read_path(&compare)?)?;
        if existing != native {
            return Err(SafeError(
                "native configuration does not match the validated conversion",
            ));
        }
    }
    if let Some(output) = options.output {
        if options.input != "-" {
            let input_path = fs::canonicalize(&options.input)
                .map_err(|_| SafeError("could not resolve input path"))?;
            if fs::canonicalize(&output).ok().as_ref() == Some(&input_path) {
                return Err(SafeError(
                    "output must not replace the source configuration",
                ));
            }
        }
        let contents = serde_json::to_vec_pretty(&native)
            .map_err(|_| SafeError("could not encode native configuration"))?;
        write_private_atomic(&output, &contents)?;
        println!("Validated private configuration written with mode 0600. Nothing was deployed.");
    } else {
        println!("Configuration validation passed. Nothing was written or deployed.");
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("relay-config: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parameters() -> Parameters {
        Parameters {
            passwords: [
                "test-owner-password-only".into(),
                "test-second-password-only".into(),
            ],
            path: "/relay/offline-fixture".into(),
            private_key: STANDARD.encode([42; 32]),
            public_key: STANDARD.encode([43; 32]),
            peer: "8.8.8.8".parse().unwrap(),
            port: 51820,
            interface: "10.77.0.2/32".into(),
            dns: ["1.1.1.1".parse().unwrap(), "9.9.9.9".parse().unwrap()],
        }
    }

    #[test]
    fn known_policy_preserves_credentials_route_and_budgets() {
        let p = parameters();
        let native = convert(&expected_source(&p)).unwrap();
        assert_eq!(
            native[3]["protocol"]["targets"][0]["protocol"]["password"],
            json!(p.passwords)
        );
        assert_eq!(native[3]["protocol"]["targets"][0]["matching_path"], p.path);
        assert_eq!(
            native[2]["client_chains"][0]["protocol"]["private_key"],
            p.private_key
        );
        assert_eq!(native[2]["client_chains"][0]["address"], "8.8.8.8:51820");
        assert_eq!(
            native[2]["client_chains"][0]["protocol"]["resource_limits"]["tcp_memory_bytes"],
            33554432
        );
        assert_eq!(native[3]["rules"][4]["client_chain"], "wg-exit");
        assert_eq!(native[3]["rules"][5]["action"], "block");
        for resolver in native[1]["dns_servers"].as_array().unwrap() {
            assert_eq!(resolver["client_chain"], "wg-exit");
            assert_eq!(resolver["ip_strategy"], "ipv4_only");
            assert_eq!(resolver["timeout_secs"], 10);
        }
    }

    #[test]
    #[cfg(feature = "relay-minimal")]
    fn generated_native_configuration_passes_offline_validation() {
        let native = convert(&expected_source(&parameters())).unwrap();
        validate_native(&native).unwrap();
    }

    #[test]
    fn unknown_or_changed_policy_fails_closed() {
        let source = expected_source(&parameters());
        let mut cases = Vec::new();
        let mut changed = source.clone();
        changed["experimental"] = json!({"unsafe":true});
        cases.push(changed);
        let mut changed = source.clone();
        changed["dns"]["servers"][0]["detour"] = json!("wg-socket-only");
        cases.push(changed);
        let mut changed = source.clone();
        changed["route"]["rules"][4]["ip_is_private"] = json!(false);
        cases.push(changed);
        let mut changed = source.clone();
        changed["route"]["rules"][7]["outbound"] = json!("wg-socket-only");
        cases.push(changed);
        let mut changed = source.clone();
        changed["route"]["rules"][8] = json!({"action":"route","outbound":"wg-exit"});
        cases.push(changed);
        let mut changed = source.clone();
        changed["inbounds"][0]["transport"]["max_early_data"] = json!(1024);
        cases.push(changed);
        let mut changed = source.clone();
        changed["endpoints"][0]["system"] = json!(true);
        cases.push(changed);
        let mut changed = source.clone();
        changed["endpoints"][0]["mtu"] = json!(1420);
        cases.push(changed);
        let mut changed = source.clone();
        changed["dns"]["rules"][0]["timeout"] = json!("3s");
        cases.push(changed);
        for changed in cases {
            assert!(convert(&changed).is_err());
        }
    }

    #[test]
    fn invalid_secret_errors_do_not_disclose_values() {
        let marker = "private-value-must-never-appear-in-errors";
        let mut source = expected_source(&parameters());
        source["endpoints"][0]["private_key"] = json!(marker);
        let error = convert(&source).err().unwrap();
        assert!(!error.to_string().contains(marker));
        source["endpoints"][0]["private_key"] = json!(STANDARD.encode([0; 32]));
        assert!(convert(&source).is_err());
        for raw in [
            format!("{{\"secret\":\"{marker}\",}}"),
            format!("{{\"secret\":\"{marker}\",\"secret\":\"duplicate\"}}"),
        ] {
            let error = parse_json(raw.as_bytes()).err().unwrap();
            assert!(!error.to_string().contains(marker));
        }
    }

    #[test]
    fn malformed_and_duplicate_json_is_rejected() {
        for input in [
            b"{\"a\":1,\"a\":2}".as_slice(),
            b"{\"a\":{\"b\":1,\"b\":2}}",
            b"[NaN]",
            b"{} trailing",
        ] {
            assert!(parse_json(input).is_err());
        }
        assert!(parse_json(&vec![b' '; MAX_INPUT_BYTES + 1]).is_err());
    }

    #[test]
    fn no_private_peer_or_bootstrap_dns_or_duplicate_identity() {
        let base = expected_source(&parameters());
        for path in ["/dns/servers/0/server", "/endpoints/0/peers/0/address"] {
            for ip in [
                "localhost",
                "127.0.0.1",
                "169.254.169.254",
                "::1",
                "100.64.0.1",
            ] {
                let mut source = base.clone();
                *source.pointer_mut(path).unwrap() = json!(ip);
                assert!(convert(&source).is_err());
            }
        }
        let mut source = base.clone();
        source["inbounds"][0]["users"][1]["password"] =
            source["inbounds"][0]["users"][0]["password"].clone();
        assert!(convert(&source).is_err());
        let mut source = base;
        source["inbounds"][0]["users"][1]["name"] = json!("owner");
        assert!(convert(&source).is_err());
    }

    #[test]
    fn command_line_never_allows_secret_stdout_or_implicit_write() {
        for args in [
            vec![],
            vec!["--output", "-"],
            vec!["--check", "--output", "x"],
            vec!["--compare", "x"],
            vec!["--check", "--check"],
        ] {
            assert!(parse_options(args.into_iter().map(String::from)).is_err());
        }
        let options = parse_options(["--input", "-", "--check"].into_iter().map(String::from))
            .unwrap()
            .unwrap();
        assert!(options.check && options.output.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn output_is_atomic_private_and_does_not_follow_existing_symlink() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let output = dir.path().join("converted");
        fs::write(&target, b"untouched").unwrap();
        symlink(&target, &output).unwrap();
        write_private_atomic(&output, b"fake-test-config").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"untouched");
        assert_eq!(fs::read(&output).unwrap(), b"fake-test-config\n");
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn failed_atomic_publish_removes_temporary_secret_file() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("already-a-directory");
        fs::create_dir(&output).unwrap();
        assert!(write_private_atomic(&output, b"fake-test-config").is_err());
        assert!(output.is_dir());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
