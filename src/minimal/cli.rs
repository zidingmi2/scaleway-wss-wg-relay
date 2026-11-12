//! Environment-first, single-runtime relay entry point. No reload/control services.
use crate::config::{Config, ResolvedConfig, ValidatedConfigs};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
const MAX_CONFIG: usize = 1024 * 1024;

pub fn main() {
    if let Err(error) = run() {
        // Configuration errors may contain secret values. Print only the error kind.
        eprintln!(
            "relay failed ({:?}); inspect configuration locally",
            error.kind()
        );
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut env_name = None;
    let mut paths = Vec::new();
    let mut check = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config-env" => env_name = Some(args.next().ok_or_else(invalid)?),
            "--check" | "--dry-run" | "-d" | "check" => check = true,
            "-t" | "--threads" => {
                if args.next().as_deref() != Some("1") {
                    return Err(invalid());
                }
            }
            "--no-reload" => {}
            "-V" | "--version" | "version" => {
                println!(
                    "shoes {} relay-minimal\ntarget: {}\ncompiler: {}",
                    env!("SHOES_VERSION"),
                    env!("SHOES_TARGET"),
                    env!("SHOES_COMPILER")
                );
                return Ok(());
            }
            "-h" | "--help" => {
                println!(
                    "shoes --config-env RELAY_CONFIG [-t 1] [--no-reload] [--check]\nshoes check CONFIG.json\nThis build supports Trojan/WebSocket with WireGuard or explicit direct egress.\nSet global_settings.relay_egress to direct to disable WireGuard definitions and require direct-only routes; the default is wireguard."
                );
                return Ok(());
            }
            other if other.starts_with('-') => return Err(invalid()),
            _ => paths.push(arg),
        }
    }
    if env_name.is_some() == !paths.is_empty() {
        return Err(invalid());
    }
    let mut configs = Vec::new();
    if let Some(name) = env_name {
        let mut content = std::env::var(&name).map_err(|_| invalid())?;
        // No runtime, worker, watcher or logger thread has been started yet.
        unsafe {
            std::env::remove_var(&name);
        }
        let parsed = parse(&content);
        use zeroize::Zeroize;
        content.zeroize();
        configs.extend(parsed?);
    } else {
        for path in paths {
            let metadata = std::fs::metadata(&path)?;
            if metadata.len() > MAX_CONFIG as u64 {
                return Err(invalid());
            }
            let mut content = std::fs::read_to_string(path)?;
            let parsed = parse(&content);
            use zeroize::Zeroize;
            content.zeroize();
            configs.extend(parsed?);
        }
    }
    crate::thread_util::set_num_threads(1);
    let validated = crate::config::create_server_configs(configs)?;
    if check {
        println!("relay configuration valid; no listeners or WireGuard device started");
        return Ok(());
    }
    let logs = Arc::new(RelayLogState::new());
    log::set_boxed_logger(Box::new(RelayLogger(logs.clone()))).map_err(io::Error::other)?;
    log::set_max_level(log::LevelFilter::Warn);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(serve(validated, logs))
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid relay configuration or arguments",
    )
}
fn parse(text: &str) -> io::Result<Vec<Config>> {
    if text.len() > MAX_CONFIG {
        return Err(invalid());
    }
    // Strict native decoding; never silently interpret a sing-box document.
    let entries: Vec<Config> = serde_json::from_str(text).map_err(|_| invalid())?;
    Ok(entries)
}
async fn serve(mut validated: ValidatedConfigs, logs: Arc<RelayLogState>) -> io::Result<()> {
    crate::resources::configure(validated.global_limits)?;
    let prepared = crate::wireguard::Prepared::new(&mut validated).await?;
    let mut dns = crate::dns::build_dns_registry_for_runtime(
        std::mem::take(&mut validated.dns_groups),
        validated.global_limits,
        None,
        &[],
        false,
    )
    .await?;
    let mut running = crate::wireguard::Running::default();
    prepared.start(&mut dns, &mut running).await?;
    let mut listeners = crate::tcp::tcp_server::TcpListeners::default();
    let mut tasks = Vec::new();
    for config in validated.configs {
        let dns_ref = match &config {
            ResolvedConfig::Server(s) => s.dns.as_ref(),
            ResolvedConfig::TunServer(_) => return Err(invalid()),
        };
        let resolver = dns.get_for_server(dns_ref);
        match crate::tcp::tcp_server::start_servers_with_listeners(config, resolver, &mut listeners)
            .await
        {
            Ok(mut new) => tasks.append(&mut new),
            Err(error) => {
                for task in tasks {
                    task.abort();
                }
                running.stop().await;
                return Err(error);
            }
        }
    }
    let _reporter = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let rss = memory_stats::memory_stats()
                .map(|s| s.physical_mem)
                .unwrap_or(0);
            eprintln!(
                "relay resources rss_bytes={rss} warnings={} errors={} {}",
                logs.warnings.load(Ordering::Relaxed),
                logs.errors.load(Ordering::Relaxed),
                crate::resources::snapshot()
            );
        }
    }));
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        let _ = task.await;
    }
    running.stop().await;
    Ok(())
}

/// The relay never formats log arguments, which can contain destinations or credentials.
/// Runtime events expose only severity and a compile-time module identifier, twice/second at most.
struct RelayLogState {
    start: std::time::Instant,
    warnings: AtomicU64,
    errors: AtomicU64,
    last_warning: AtomicU64,
    last_error: AtomicU64,
}
impl RelayLogState {
    fn new() -> Self {
        Self {
            start: std::time::Instant::now(),
            warnings: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            last_warning: AtomicU64::new(u64::MAX),
            last_error: AtomicU64::new(u64::MAX),
        }
    }
}
struct RelayLogger(Arc<RelayLogState>);
fn safe_event(record: &log::Record<'_>) -> String {
    let component: String = record
        .module_path()
        .unwrap_or("dependency")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_'))
        .take(96)
        .collect();
    format!("relay event level={} component={component}", record.level())
}
impl log::Log for RelayLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Warn
    }
    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        // Local acceptance fixtures use freshly generated keys and loopback only.
        // This branch is absent from the production release executable.
        #[cfg(debug_assertions)]
        if std::env::var_os("RELAY_ACCEPTANCE_VERBOSE").is_some() {
            eprintln!("offline {} {}", record.level(), record.args());
            return;
        }
        let (counter, last) = if record.level() == log::Level::Error {
            (&self.0.errors, &self.0.last_error)
        } else {
            (&self.0.warnings, &self.0.last_warning)
        };
        counter.fetch_add(1, Ordering::Relaxed);
        let now = self.0.start.elapsed().as_secs();
        let previous = last.load(Ordering::Relaxed);
        if previous != now
            && last
                .compare_exchange(previous, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            eprintln!("{}", safe_event(record));
        }
    }
    fn flush(&self) {}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn logging_never_formats_secret_arguments() {
        struct Secret;
        impl std::fmt::Display for Secret {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                panic!("log arguments must not be formatted")
            }
        }
        let args = format_args!("{}", Secret);
        let record = log::Record::builder()
            .args(args)
            .level(log::Level::Warn)
            .module_path(Some("shoes::relay"))
            .build();
        assert_eq!(
            safe_event(&record),
            "relay event level=WARN component=shoes::relay"
        );
    }
    #[test]
    fn sing_box_object_is_not_accepted_as_native_config() {
        assert!(parse(r#"{"inbounds":[],"outbounds":[]}"#).is_err());
        assert!(parse(&" ".repeat(MAX_CONFIG + 1)).is_err());
    }
}
