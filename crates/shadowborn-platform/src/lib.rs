//! File-only provisioning boundary; live network activation is intentionally gated.
mod command;
mod storage;
use anyhow::{bail, Result};
pub use command::*;
use shadowborn_core::Config;
use std::path::Path;
pub use storage::*;
pub fn require_root() -> Result<()> {
    // SAFETY: geteuid takes no pointers and has no side effects.
    if unsafe { libc::geteuid() } != 0 {
        bail!("root is required for secret state and provisioning writes")
    }
    Ok(())
}
pub fn require_offline(config: &Config) -> Result<()> {
    config.validate()?;
    if Path::new("/sys/class/net")
        .join(&config.server.interface)
        .exists()
        || std::fs::symlink_metadata(
            Path::new("/etc/wireguard").join(format!("{}.conf", config.server.interface)),
        )
        .is_ok()
        || Path::new("/etc/systemd/system/shadowborn-firewall.service").exists()
    {
        bail!("provisioning-only operation refused: gateway appears deployed; live reconciliation is unsupported")
    }
    Ok(())
}
pub fn unsupported(feature: &str) -> Result<()> {
    bail!("UNSUPPORTED: {feature}; isolated rollback/boot/packet validation release gates are not met")
}
