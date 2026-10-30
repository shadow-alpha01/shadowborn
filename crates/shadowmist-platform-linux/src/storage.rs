use crate::require_root;
use anyhow::{bail, Context, Result};
use fs2::FileExt;
use shadowmist_core::*;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub const DEFAULT_STATE: &str = "/var/lib/shadowmist";
pub const DEFAULT_CONFIG: &str = "/etc/shadowmist/config.toml";
pub const DEFAULT_RUNTIME: &str = "/run/shadowmist";
pub fn published_status(max_age: u64) -> Option<Report> {
    let path = Path::new(DEFAULT_RUNTIME).join("status.json");
    let meta = fs::symlink_metadata(&path).ok()?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.uid() != 0
        || meta.mode() & 0o022 != 0
    {
        return None;
    }
    let r: Report = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    if r.schema_version != SCHEMA_VERSION
        || !r.redacted
        || timestamp().saturating_sub(r.timestamp) > max_age
    {
        return None;
    }
    if matches!(r.dns.state, Protection::Configured | Protection::Verified)
        && (crate::resolver_owner() != "systemd-resolved-stub"
            || !crate::resolved_dbus_available().ok()?)
    {
        return None;
    }
    Some(r)
}
pub struct StateLock {
    _file: File,
}
pub fn private_dir(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("state/runtime directory must be absolute")
    }
    if !path.exists() {
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    let meta = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no pointer arguments.
    let uid = unsafe { libc::geteuid() };
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != uid
        || meta.mode() & 0o022 != 0
    {
        bail!("state/runtime directory must be owned by current service user and not group/world writable")
    }
    // Reject symlink ancestors and directories writable by an untrusted user.
    for ancestor in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(ancestor)?;
        if m.file_type().is_symlink() {
            bail!("symlink ancestor rejected")
        };
        if uid == 0 && m.uid() != 0 {
            bail!("root state/config paths cannot have non-root-owned ancestors")
        };
    }
    Ok(())
}
pub fn lock_state(path: &Path) -> Result<StateLock> {
    lock_state_timeout(path, Duration::from_secs(20))
}
pub fn lock_state_timeout(path: &Path, wait: Duration) -> Result<StateLock> {
    private_dir(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path.join("lock"))?;
    let deadline = Instant::now() + wait;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(StateLock { _file: file }),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(e) => return Err(e).context("another transaction owns the state lock"),
        }
    }
}
pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("path has no parent")?;
    let name = path
        .file_name()
        .context("path has no filename")?
        .to_string_lossy();
    let tmp = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    let result = (|| -> Result<()> {
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}
pub struct DiskStore {
    pub directory: PathBuf,
}
impl DiskStore {
    pub fn new(path: &Path) -> Result<Self> {
        private_dir(path)?;
        let directory = path.join("transactions");
        private_dir(&directory)?;
        Ok(Self { directory })
    }
    pub fn journals(&self) -> Result<Vec<Journal>> {
        let mut journals = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json") {
                let meta = fs::symlink_metadata(&path)?;
                if !meta.is_file() || meta.file_type().is_symlink() || meta.mode() & 0o077 != 0 {
                    bail!("unsafe journal file permissions/type")
                };
                let j: Journal = serde_json::from_slice(&fs::read(&path)?)?;
                if j.schema_version != SCHEMA_VERSION || !valid_id(&j.id) {
                    bail!("unsupported or malformed journal; manual inspection required")
                };
                journals.push(j);
            }
        }
        journals.sort_by(|a, b| b.id.cmp(&a.id));
        Ok(journals)
    }
}
pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() < 80 && id.bytes().all(|c| c.is_ascii_digit() || c == b'-')
}
impl JournalStore for DiskStore {
    fn save(&mut self, j: &Journal) -> Result<()> {
        if !valid_id(&j.id) {
            bail!("invalid transaction ID")
        };
        atomic_write(
            &self.directory.join(format!("{}.json", j.id)),
            &serde_json::to_vec_pretty(j)?,
            0o600,
        )
    }
}
pub fn transaction_id() -> String {
    format!(
        "{:020}-{:010}-{:09}",
        timestamp(),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
    )
}
pub fn next_transaction_id(store: &DiskStore) -> Result<String> {
    let previous = store
        .journals()?
        .iter()
        .filter_map(|j| j.id.split('-').next().and_then(|s| s.parse::<u64>().ok()))
        .max()
        .unwrap_or(0);
    let sequence = timestamp().max(
        previous
            .checked_add(1)
            .context("transaction sequence exhausted")?,
    );
    let suffix = transaction_id();
    Ok(format!("{sequence:020}{}", &suffix[20..]))
}
pub fn load_config(path: &Path) -> Result<Config> {
    if path.exists() {
        Config::parse(&fs::read_to_string(path)?)
    } else if path == Path::new(DEFAULT_CONFIG) {
        Ok(Config::default())
    } else {
        bail!("configuration file does not exist")
    }
}
pub fn secure_config(path: &Path) -> Result<()> {
    require_root()?;
    let meta =
        fs::symlink_metadata(path).context("mutations require an installed configuration file")?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.uid() != 0
        || meta.mode() & 0o022 != 0
    {
        bail!("configuration must be a root-owned regular file, not group/world writable")
    }
    for a in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(a)?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 || m.file_type().is_symlink() {
            bail!("configuration ancestors must be root-owned and not writable by other users")
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_transactions_are_excluded() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let lock = lock_state(dir.path()).unwrap();
        assert!(lock_state_timeout(dir.path(), Duration::ZERO).is_err());
        drop(lock);
        assert!(lock_state_timeout(dir.path(), Duration::ZERO).is_ok());
    }
    #[test]
    fn atomic_journal_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let _lock = lock_state(dir.path()).unwrap();
        let mut s = DiskStore::new(dir.path()).unwrap();
        let j = Journal {
            schema_version: 1,
            id: "123-45".into(),
            state: TransactionState::Pending,
            changes: vec![],
            attempted: 0,
            error: None,
            dns_live: false,
        };
        s.save(&j).unwrap();
        assert_eq!(s.journals().unwrap()[0].id, j.id);
        assert_eq!(
            fs::metadata(s.directory.join("123-45.json"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
    }
    #[test]
    fn symlink_state_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        assert!(private_dir(&link).is_err());
    }
    #[test]
    fn traversal_ids_rejected() {
        assert!(!valid_id("../../etc/passwd"));
        assert!(!valid_id("--help"));
        assert!(valid_id("123-456"));
    }
}
