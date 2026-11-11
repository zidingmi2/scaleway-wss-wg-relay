//! Certificate configuration shapes, without ACME or certificate workers.
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NamedSource {
    pub certificate_source: String,
    #[serde(flatten)]
    pub source: SourceConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceConfig {
    Files { cert: PathBuf, key: PathBuf },
    Acme(AcmeConfig),
}

impl NamedSource {
    pub(crate) fn validate_file_paths(&self) -> io::Result<()> {
        let validate = |field: &str, path: &Path| {
            let value = path.to_string_lossy();
            if value.trim_start().starts_with("-----BEGIN") || value.contains(['\r', '\n']) {
                return Err(invalid(&format!(
                    "certificate source {}: {field} requires a file path, not inline material",
                    self.certificate_source
                )));
            }
            Ok(())
        };
        match &self.source {
            SourceConfig::Files { cert, key } => {
                validate("cert", cert)?;
                validate("key", key)?;
            }
            SourceConfig::Acme(config) => {
                if let Some(path) = &config.ca_cert {
                    validate("ca_cert", path)?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    pub domains: Vec<String>,
    pub directory_url: String,
    pub state_dir: PathBuf,
    /// Exact CA terms URL accepted by the operator, not blanket future acceptance.
    pub terms_of_service: Option<String>,
    #[serde(default)]
    pub contacts: Vec<String>,
    pub challenge: ChallengeConfig,
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChallengeConfig {
    Http01 { listen: Vec<std::net::SocketAddr> },
    TlsAlpn01,
}

#[derive(Debug)]
pub struct Source;
impl rustls::server::ResolvesServerCert for Source {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        None
    }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}
pub(crate) fn configure(configs: &mut [crate::config::Config]) -> io::Result<Vec<Arc<Source>>> {
    if configs
        .iter()
        .any(|c| matches!(c, crate::config::Config::CertificateSource(_)))
    {
        return Err(invalid(
            "certificate sources and ACME are excluded from relay-minimal",
        ));
    }
    Ok(Vec::new())
}
