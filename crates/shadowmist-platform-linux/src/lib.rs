pub mod adapter;
pub mod command;
pub mod discovery;
pub mod dns_diagnostics;
pub mod operations;
pub mod report;
pub mod storage;
pub use adapter::*;
pub use command::*;
pub use discovery::*;
pub use dns_diagnostics::*;
pub use operations::*;
pub use report::*;
pub use storage::*;

pub fn is_root() -> bool {
    // SAFETY: geteuid has no pointer arguments or preconditions.
    unsafe { libc::geteuid() == 0 }
}
pub fn require_root() -> anyhow::Result<()> {
    if !is_root() {
        anyhow::bail!("root authorization required for mutations; use sudo")
    }
    Ok(())
}
