use anyhow::{bail, Context, Result};
use shadowborn_core::{validate_key, Secret};
use std::{
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

/// Fixed program allowlist, no shell, bounded output, timeout, suppressed stderr.
/// Secret input uses a pipe, never argv; inherited descriptors are not logged.
pub fn run(program: &str, args: &[&str], input: &[u8]) -> Result<Vec<u8>> {
    if !["wg", "age"].contains(&program) {
        bail!("unsupported subprocess")
    }
    let executable = ["/usr/bin", "/usr/sbin"]
        .iter()
        .map(|dir| Path::new(dir).join(program))
        .find(|p| p.is_file())
        .context("required tool missing (wg or age)")?;
    let mut child = Command::new(executable)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("could not start required tool")?;
    let mut stdin = child.stdin.take().context("subprocess stdin missing")?;
    let bytes = input.to_vec();
    let writer = thread::spawn(move || stdin.write_all(&bytes));
    let stdout = child.stdout.take().context("subprocess stdout missing")?;
    let reader = thread::spawn(move || {
        let mut output = Vec::new();
        let result = stdout.take(4 * 1024 * 1024 + 1).read_to_end(&mut output);
        (result, output)
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let written = writer
        .join()
        .map_err(|_| anyhow::anyhow!("subprocess input failed"))?;
    let (read, output) = reader
        .join()
        .map_err(|_| anyhow::anyhow!("subprocess output failed"))?;
    if status.is_none_or(|s| !s.success())
        || written.is_err()
        || read.is_err()
        || output.len() > 4 * 1024 * 1024
    {
        bail!("external tool failed or timed out; details suppressed to protect secrets")
    }
    Ok(output)
}
pub fn generate_key(psk: bool) -> Result<Secret> {
    let output = run("wg", &[if psk { "genpsk" } else { "genkey" }], &[])?;
    Secret::new(
        String::from_utf8(output)
            .context("invalid key output")?
            .trim()
            .into(),
    )
}
pub fn public_key(private: &Secret) -> Result<String> {
    let result = String::from_utf8(run(
        "wg",
        &["pubkey"],
        format!("{}\n", private.expose()).as_bytes(),
    )?)
    .context("invalid public key output")?;
    let key = result.trim().to_string();
    validate_key(&key)?;
    Ok(key)
}
pub fn encrypt(recipient: &str, plain: &[u8]) -> Result<Vec<u8>> {
    if !recipient.starts_with("age1")
        || recipient.len() > 100
        || !recipient
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        bail!("native age recipient required")
    }
    run("age", &["--encrypt", "--recipient", recipient], plain)
}
pub fn decrypt(identity: &Path, cipher: &[u8]) -> Result<Vec<u8>> {
    // Validate the identity path/permissions before passing it to age. No secret
    // identity contents or diagnostic stderr are ever echoed.
    let _ = crate::read_secret(identity)?;
    run(
        "age",
        &[
            "--decrypt",
            "--identity",
            identity.to_str().context("non-UTF8 identity path")?,
        ],
        cipher,
    )
}
