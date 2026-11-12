//! No host-network mutation is linked into the relay profile.
#[cfg(target_os = "linux")]
pub(crate) const MANAGED_STATE_DIRECTORY: &str = "/run/shoes";
pub(crate) fn validate_config(configs: &[crate::config::ResolvedConfig]) -> std::io::Result<()> {
    if configs
        .iter()
        .any(|c| matches!(c, crate::config::ResolvedConfig::TunServer(_)))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN is excluded from relay-minimal",
        ));
    }
    Ok(())
}
