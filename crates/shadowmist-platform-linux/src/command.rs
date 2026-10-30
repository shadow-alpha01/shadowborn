use anyhow::{bail, Context, Result};
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MAX_OUTPUT: u64 = 1024 * 1024;
pub fn binary(name: &str) -> Option<PathBuf> {
    // Privileged execution never trusts PATH, shell aliases, or the working directory.
    if ![
        "nmcli",
        "resolvectl",
        "systemctl",
        "systemd-run",
        "busctl",
        "ip",
        "ss",
        "nft",
        "loginctl",
        "NetworkManager",
    ]
    .contains(&name)
    {
        return None;
    }
    ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
        .iter()
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
}
pub fn run(name: &str, args: &[&str], timeout: Duration) -> Result<String> {
    let path = binary(name).with_context(|| format!("required executable {name} unavailable"))?;
    let mut child = Command::new(path)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_PAGER", "cat")
        .env("COLUMNS", "4096")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("cannot start {name}"))?;
    let output = child.stdout.take().context("missing stdout pipe")?;
    let reader = thread::spawn(move || {
        let mut data = Vec::new();
        let result = output.take(MAX_OUTPUT + 1).read_to_end(&mut data);
        (result, data)
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            bail!("{name} timed out; operation outcome requires state verification")
        }
        thread::sleep(Duration::from_millis(20));
    };
    let (result, data) = reader
        .join()
        .map_err(|_| anyhow::anyhow!("command reader failed"))?;
    result?;
    if data.len() as u64 > MAX_OUTPUT {
        bail!("{name} output exceeded safety limit")
    }
    if !status.success() {
        bail!(
            "{name} failed (exit {}); sensitive command output suppressed",
            status.code().unwrap_or(-1)
        )
    }
    Ok(String::from_utf8(data)
        .context("command output was not UTF-8")?
        .trim()
        .to_string())
}
pub fn query(name: &str, args: &[&str]) -> Result<String> {
    run(name, args, Duration::from_secs(6))
}
pub fn property(
    service: &str,
    path: &str,
    interface: &str,
    key: &str,
) -> Result<serde_json::Value> {
    let out = query(
        "busctl",
        &[
            "--system",
            "--json=short",
            "get-property",
            service,
            path,
            interface,
            key,
        ],
    )?;
    let v: serde_json::Value = serde_json::from_str(&out)?;
    v.get("data").cloned().context("D-Bus property has no data")
}
pub fn split_escaped(line: &str) -> Vec<String> {
    let mut fields = vec![String::new()];
    let mut escape = false;
    for c in line.chars() {
        if escape {
            fields.last_mut().unwrap().push(c);
            escape = false;
        } else if c == '\\' {
            escape = true;
        } else if c == ':' {
            fields.push(String::new());
        } else {
            fields.last_mut().unwrap().push(c);
        }
    }
    if escape {
        fields.last_mut().unwrap().push('\\');
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nm_escaping() {
        assert_eq!(
            split_escaped("eth0:aa\\:bb:name\\\\x"),
            vec!["eth0", "aa:bb", "name\\x"]
        );
    }
    #[test]
    fn programs_are_allowlisted() {
        assert!(binary("sh").is_none());
        assert!(binary("../../bin/sh").is_none());
    }
}
