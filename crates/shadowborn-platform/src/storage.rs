use anyhow::{bail, Context, Result};
use fs2::FileExt;
use shadowborn_core::State;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

const MAX_STATE: u64 = 4 * 1024 * 1024;
fn uid() -> u32 {
    unsafe { libc::geteuid() }
}
pub fn secure_directory(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        bail!("absolute normalized private directory required")
    }
    for (index, ancestor) in path.ancestors().enumerate() {
        let m = fs::symlink_metadata(ancestor).context("private path is missing")?;
        let sticky_root = m.uid() == 0 && m.mode() & 0o1000 != 0;
        if !m.is_dir()
            || m.file_type().is_symlink()
            || (m.uid() != 0 && m.uid() != uid())
            || (m.mode() & 0o022 != 0 && !sticky_root)
            || (index == 0 && (m.uid() != uid() || m.mode() & 0o077 != 0))
        {
            bail!("unsafe private directory ownership, permissions or ancestor")
        }
    }
    Ok(())
}
pub fn create_private(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        bail!("absolute normalized private directory required before creation")
    }
    let parent = path.parent().context("missing directory parent")?;
    // Validate ancestors before creating anything; a private leaf under a sticky
    // root-owned /tmp is allowed, but an attacker-owned parent is never allowed.
    for a in parent.ancestors() {
        let m = fs::symlink_metadata(a)?;
        if !m.is_dir()
            || m.file_type().is_symlink()
            || (m.uid() != 0 && m.uid() != uid())
            || (m.mode() & 0o022 != 0 && !(m.uid() == 0 && m.mode() & 0o1000 != 0))
        {
            bail!("unsafe parent directory")
        }
    }
    fs::DirBuilder::new().mode(0o700).create(path)?;
    secure_directory(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn checked_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != uid()
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
        || m.len() > MAX_STATE
    {
        bail!("unsafe secret file ownership, permissions, links or size")
    }
    Ok(file)
}
pub fn read_secret(path: &Path) -> Result<Vec<u8>> {
    secure_directory(path.parent().context("missing parent")?)?;
    let mut bytes = Vec::new();
    checked_file(path)?
        .take(MAX_STATE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STATE {
        bail!("secret file too large")
    }
    Ok(bytes)
}
pub fn write_new_secret(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().context("missing parent")?;
    secure_directory(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist_noclobber(path)
        .map_err(|_| anyhow::anyhow!("output exists or could not be committed"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub struct Store {
    path: PathBuf,
    _lock: File,
}
impl Store {
    pub fn open(path: &Path, create: bool) -> Result<Self> {
        if create && fs::symlink_metadata(path).is_err() {
            create_private(path)?;
        }
        secure_directory(path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path.join("lock"))?;
        let m = lock.metadata()?;
        if !m.is_file() || m.uid() != uid() || m.mode() & 0o077 != 0 || m.nlink() != 1 {
            bail!("unsafe lock file")
        }
        lock.try_lock_exclusive()
            .context("another provisioning operation holds the lock")?;
        Ok(Self {
            path: path.to_path_buf(),
            _lock: lock,
        })
    }
    pub fn load(&self) -> Result<State> {
        Self::decode(&read_secret(&self.path.join("state.json"))?)
    }
    pub fn decode(data: &[u8]) -> Result<State> {
        let state: State = serde_json::from_slice(data)
            .map_err(|_| anyhow::anyhow!("invalid protected state schema"))?;
        state.validate()?;
        Ok(state)
    }
    pub fn save(&self, before: Option<&State>, after: &State) -> Result<()> {
        after.validate()?;
        let path = self.path.join("state.json");
        match before {
            Some(expected) if self.load()? != *expected => {
                bail!("state changed since planning; refusing overwrite")
            }
            None if fs::symlink_metadata(&path).is_ok() => bail!("gateway already initialized"),
            _ => {}
        }
        let data = serde_json::to_vec(after)?;
        if data.len() as u64 > MAX_STATE - 65536 {
            bail!("state exceeds supported size (space reserved for encrypted backup overhead)")
        }
        let mut tmp = tempfile::NamedTempFile::new_in(&self.path)?;
        tmp.write_all(&data)?;
        tmp.as_file().sync_all()?;
        if before.is_none() {
            tmp.persist_noclobber(&path)
                .map_err(|_| anyhow::anyhow!("state initialization conflict"))?;
        } else {
            tmp.persist(&path)
                .map_err(|_| anyhow::anyhow!("state commit failed"))?;
        }
        File::open(&self.path)?.sync_all()?;
        Ok(())
    }
}
pub fn export_bundle(path: &Path, state: &State) -> Result<()> {
    let files = shadowborn_core::bundle(state)?;
    // Stage the entire bundle inside a new private directory; remove only our
    // own incomplete directory on failure. Existing paths are never overwritten.
    create_private(path)?;
    let result = (|| {
        for (name, data) in files {
            write_new_secret(&path.join(name), data.as_bytes())?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(path);
    }
    result
}
