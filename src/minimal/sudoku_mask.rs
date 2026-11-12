//! Legacy configuration shape only; Sudoku transport is not compiled.
use serde::{Deserialize, Serialize};
use std::{fmt, io};
use zeroize::Zeroize;
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Password(String);

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SudokuMaskConfig<P> {
    #[serde(default)]
    pub password: Password,
    #[serde(default)]
    pub ascii: String,
    #[serde(default, alias = "customTable")]
    pub custom_table: String,
    #[serde(default, alias = "customTables")]
    pub custom_tables: Vec<String>,
    #[serde(default, alias = "paddingMin")]
    pub padding_min: u32,
    #[serde(default, alias = "paddingMax")]
    pub padding_max: u32,
    pub protocol: Box<P>,
}

pub(crate) fn validate_resolved_client(
    protocol: &crate::config::ResolvedClientProxyConfig,
    _: &crate::config::Transport,
) -> io::Result<()> {
    if matches!(
        protocol,
        crate::config::ResolvedClientProxyConfig::SudokuMask(_)
    ) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Sudoku excluded from relay-minimal",
        ));
    }
    Ok(())
}

pub(crate) fn validate_server(
    _: &crate::config::ServerProxyConfig,
    _: &crate::config::Transport,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Sudoku excluded from relay-minimal",
    ))
}
