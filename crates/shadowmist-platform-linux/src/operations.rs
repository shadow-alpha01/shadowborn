use crate::*;
use anyhow::{bail, Context, Result};
use shadowmist_core::*;
use std::{fs, path::Path, time::Duration};

pub fn pending_exists(state: &Path) -> Result<bool> {
    if !state.exists() {
        return Ok(false);
    };
    let store = DiskStore::new(state)?;
    Ok(store.journals()?.iter().any(|j| {
        matches!(
            j.state,
            TransactionState::Pending | TransactionState::Conflict
        )
    }))
}
pub fn recover(state: &Path, config: &Config, only: Option<&str>) -> Result<usize> {
    require_root()?;
    let _lock = lock_state_timeout(state, Duration::from_secs(180))?;
    let mut store = DiskStore::new(state)?;
    let mut adapter = LinuxAdapter::new(config.clone());
    let mut count = 0;
    for mut j in store.journals()? {
        if j.state == TransactionState::Pending && only.is_none_or(|id| id == j.id) {
            restore_transaction(&mut adapter, &mut store, &mut j)?;
            count += 1;
        }
    }
    if count > 0 {
        degraded(state)?;
    }
    Ok(count)
}
pub fn restore(state: &Path, config: &Config, dry: bool) -> Result<Vec<Journal>> {
    if dry && !state.exists() {
        return Ok(vec![]);
    }
    if dry {
        // A dry run never creates directories, lock files, timers or metadata.
        let directory = state.join("transactions");
        if !directory.exists() {
            return Ok(vec![]);
        }
        return DiskStore { directory }.journals().map(|js| {
            js.into_iter()
                .filter(|j| j.state != TransactionState::RolledBack)
                .collect()
        });
    }
    require_root()?;
    let _lock = lock_state(state)?;
    let mut store = DiskStore::new(state)?;
    let mut adapter = LinuxAdapter::new(config.clone());
    let journals: Vec<_> = store
        .journals()?
        .into_iter()
        .filter(|j| j.state != TransactionState::RolledBack)
        .collect();
    // Stop at the first conflicting transaction; older baselines must not overwrite newer ownership.
    for mut j in journals.clone() {
        restore_transaction(&mut adapter, &mut store, &mut j)?;
    }
    atomic_write(
        &state.join("health.json"),
        b"{\"state\":\"restored\"}",
        0o600,
    )?;
    Ok(journals)
}
struct Watchdog {
    unit: String,
}
impl Watchdog {
    fn arm(config: &Path, state: &Path, id: &str) -> Result<Self> {
        let exe = std::env::current_exe()?;
        secure_config(&exe).context("watchdog executable and its ancestors must be root-owned and protected from replacement")?;
        if exe.file_name().and_then(|s| s.to_str()) != Some("shadowmist") {
            bail!("rollback watchdog requires the shadowmist CLI binary")
        }
        let unit = format!("shadowmist-rollback-{id}");
        let exe = exe.to_str().context("binary path is not UTF-8")?;
        let config = config.to_str().context("config path is not UTF-8")?;
        let state = state.to_str().context("state path is not UTF-8")?;
        run(
            "systemd-run",
            &[
                "--quiet",
                "--collect",
                "--unit",
                &unit,
                "--on-active=180s",
                "--timer-property=AccuracySec=1s",
                exe,
                "--config",
                config,
                "--state-dir",
                state,
                "recover",
                "--transaction",
                id,
            ],
            Duration::from_secs(8),
        )
        .context("independent rollback timer could not be armed; no changes applied")?;
        Ok(Self { unit })
    }
    fn disarm(&self) -> Result<()> {
        query("systemctl", &["stop", &format!("{}.timer", self.unit)])?;
        Ok(())
    }
}
fn degraded(state: &Path) -> Result<()> {
    atomic_write(&state.join("health.json"),b"{\"state\":\"DEGRADED\",\"reason\":\"Rollback occurred; previous/plaintext DNS may be active. Inspect journal and run apply explicitly to retry.\"}",0o600)
}
pub fn apply(config: &Config, config_path: &Path, state: &Path) -> Result<(Plan, Option<Journal>)> {
    apply_replacing_search_domains(config, config_path, state, &[])
}
pub fn apply_replacing_search_domains(
    config: &Config,
    config_path: &Path,
    state: &Path,
    approved_domains: &[String],
) -> Result<(Plan, Option<Journal>)> {
    require_root()?;
    secure_config(config_path)?;
    config.validate()?;
    if approved_domains
        .iter()
        .any(|domain| !valid_search_domain(domain))
    {
        bail!("invalid input: replace-search-domain requires a literal search domain, without routing prefixes or wildcards")
    }
    let _lock = lock_state(state)?;
    let mut store = DiskStore::new(state)?;
    if store.journals()?.iter().any(|j| {
        matches!(
            j.state,
            TransactionState::Pending | TransactionState::Conflict
        )
    }) {
        bail!("unfinished transaction/conflict; run recover or restore before apply")
    }
    let host = discover(config);
    let p = plan_replacing_search_domains(config, &host, approved_domains);
    if p.changes.is_empty() {
        return Ok((p, None));
    }
    let id = next_transaction_id(&store)?;
    let watchdog = if p.dns_live {
        if !host.routes.iter().any(|r| r.contains(" default ")) {
            bail!("no local default route; DNS application refused")
        }
        Some(Watchdog::arm(config_path, state, &id)?)
    } else {
        None
    };
    let mut adapter = LinuxAdapter::new(config.clone());
    adapter.require_dns_health = p.dns_live;
    adapter.dns_interface = host
        .connections
        .iter()
        .find(|c| c.active && c.physical)
        .map(|c| c.interface.clone());
    match apply_transaction(&mut adapter, &mut store, &p, id) {
        Ok(j) => {
            atomic_write(
                &state.join("health.json"),
                b"{\"state\":\"applied\"}",
                0o600,
            )?;
            if let Some(w) = watchdog {
                w.disarm()?;
            }
            Ok((p, Some(j)))
        }
        Err(e) => {
            let _ = degraded(state);
            if let Some(w) = watchdog {
                let _ = w.disarm();
            }
            Err(e)
        }
    }
}
pub fn monitor_health(config: &Config, state: &Path) -> Result<bool> {
    if !is_root()
        || config.general.profile == Profile::Observe
        || !config.dns.enabled
        || config.dns.health_domains.len() < 2
        || !state.join("transactions").is_dir()
    {
        return Ok(false);
    }
    if fs::read_to_string(state.join("health.json")).is_ok_and(|s| s.contains("DEGRADED")) {
        return Ok(false);
    }
    let _lock = lock_state(state)?;
    let mut store = DiskStore::new(state)?;
    let journals = store.journals()?;
    if journals.iter().any(|j| {
        matches!(
            j.state,
            TransactionState::Pending | TransactionState::Conflict
        )
    }) {
        bail!("pending recovery or restore conflict requires attention")
    }
    let Some(mut j) = journals
        .into_iter()
        .find(|j| j.state == TransactionState::Committed && j.dns_live)
    else {
        return Ok(false);
    };
    let interface = j.changes.iter().find_map(|c| match &c.target {
        Target::Resolved { interface, .. } => Some(interface.clone()),
        _ => None,
    }).or_else(||{let host=discover(config);host.connections.iter().find(|c|c.active&&j.changes.iter().any(|change|matches!(&change.target,Target::Nm{uuid,key} if uuid==&c.uuid&&key.contains("dns")))).map(|c|c.interface.clone())});
    let Some(interface) = interface else {
        return Ok(false);
    };
    if j.changes
        .iter()
        .find(|c| matches!(&c.target,Target::Resolved{key,..} if key=="dns"))
        .is_some_and(|c| {
            c.after
                .split_whitespace()
                .any(|s| !config.dns.servers().iter().any(|approved| approved == s))
        })
    {
        bail!("DNS configuration changed since approval; explicit apply required")
    }
    let mut adapter = LinuxAdapter::new(config.clone());
    // Never reconcile changed fields by overwriting another manager's decisions.
    for c in &j.changes {
        if adapter.read(&c.target)? != c.after {
            bail!("owned setting drift detected; no automatic overwrite")
        }
    }
    if verify_dns(config, &interface, true).is_err() {
        restore_transaction(&mut adapter, &mut store, &mut j)?;
        degraded(state)?;
        bail!("DEGRADED: DNS health failed; previous DNS restored")
    }
    Ok(true)
}

fn device_path(interface: &str) -> Result<String> {
    let value = property(
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager",
        "org.freedesktop.NetworkManager",
        "Devices",
    )?;
    for path in value.as_array().context("invalid Devices D-Bus property")? {
        if let Some(path) = path.as_str() {
            if property(
                "org.freedesktop.NetworkManager",
                path,
                "org.freedesktop.NetworkManager.Device",
                "Interface",
            )
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .as_deref()
                == Some(interface)
            {
                return Ok(path.into());
            }
        }
    }
    bail!("NetworkManager device path unavailable")
}
fn checkpoint(interface: &str) -> Result<String> {
    let device = device_path(interface)?;
    let out = query(
        "busctl",
        &[
            "--system",
            "call",
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
            "CheckpointCreate",
            "aouu",
            "1",
            &device,
            "90",
            "0",
        ],
    )?;
    let path = out
        .split('"')
        .nth(1)
        .filter(|s| s.starts_with("/org/freedesktop/NetworkManager/Checkpoint/"))
        .context("checkpoint creation returned an unexpected object path")?;
    Ok(path.into())
}
fn checkpoint_call(method: &str, path: &str) -> Result<()> {
    query(
        "busctl",
        &[
            "--system",
            "call",
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
            method,
            "o",
            path,
        ],
    )?;
    Ok(())
}
pub fn rotation_preflight(
    config: &Config,
    host: &Host,
    interface: &str,
    reconnect: bool,
    ack: bool,
    force_remote: bool,
) -> Result<Connection> {
    if config.general.profile == Profile::Observe {
        bail!("observe profile is read-only; explicitly select balanced before rotation")
    }
    if !valid_interface(interface) {
        bail!("invalid interface name")
    }
    if !reconnect || !ack {
        bail!("rotation drops SSH/VPN/calls/sessions briefly; require --reconnect --acknowledge-disconnect")
    }
    if host.capabilities.remote_session && !force_remote {
        bail!("remote administration detected; require --force-remote and --acknowledge-disconnect with console recovery available")
    }
    if !host.capabilities.systemd
        || host.capabilities.container
        || !host.capabilities.nm_active
        || !host.capabilities.checkpoint_supported
    {
        bail!("rotation unsupported: requires host systemd and NetworkManager checkpoints")
    }
    let c = host
        .connections
        .iter()
        .find(|c| c.interface == interface && c.active && c.physical)
        .context("active supported physical profile not found")?;
    if !config.general.enrolled_profiles.contains(&c.uuid)
        || c.enterprise
        || excluded(interface, &config.identity.exclude_interfaces)
    {
        bail!("profile must be enrolled, physical and non-enterprise")
    }
    let policy = if c.kind == "802-11-wireless" {
        config.identity.wifi_mac
    } else if c.kind == "802-3-ethernet" {
        config.identity.ethernet_mac
    } else {
        bail!("unsupported connection type")
    };
    if policy != MacPolicy::Random {
        bail!("immediate rotation requires explicit random MAC policy for this interface type")
    }
    Ok(c.clone())
}
pub fn rotate(
    config: &Config,
    config_path: &Path,
    state: &Path,
    interface: &str,
    reconnect: bool,
    ack: bool,
    force_remote: bool,
) -> Result<()> {
    require_root()?;
    secure_config(config_path)?;
    let host = discover(config);
    let c = rotation_preflight(config, &host, interface, reconnect, ack, force_remote)?;
    let _lock = lock_state(state)?;
    let mut store = DiskStore::new(state)?;
    if store.journals()?.iter().any(|j| {
        matches!(
            j.state,
            TransactionState::Pending | TransactionState::Conflict
        )
    }) {
        bail!("recover incomplete transactions before rotation")
    }
    let key = if c.kind == "802-11-wireless" {
        "802-11-wireless.cloned-mac-address"
    } else {
        "802-3-ethernet.cloned-mac-address"
    };
    let mask = if c.kind == "802-11-wireless" {
        "802-11-wireless.generate-mac-address-mask"
    } else {
        "802-3-ethernet.generate-mac-address-mask"
    };
    let before = host
        .interfaces
        .iter()
        .find(|i| i.name == interface)
        .and_then(|i| i.effective_mac.clone())
        .context("cannot read current effective MAC")?;
    // An explicit mask would weaken the locally-administered unicast invariant.
    if !read_nm(&c.uuid, mask)?.is_empty() {
        bail!("custom MAC generation mask requires manual compatibility review")
    }
    let p = Plan {
        changes: vec![Change {
            target: Target::Nm {
                uuid: c.uuid.clone(),
                key: key.into(),
            },
            before: read_nm(&c.uuid, key)?,
            after: "random".into(),
            reason: "explicit active identity rotation".into(),
        }],
        reconnect: true,
        ..Plan::default()
    };
    let cp = checkpoint(interface)?;
    let id = next_transaction_id(&store)?;
    let w = match Watchdog::arm(config_path, state, &id) {
        Ok(w) => w,
        Err(e) => {
            let _ = checkpoint_call("CheckpointDestroy", &cp);
            return Err(e);
        }
    };
    let mut adapter = RotationAdapter {
        inner: LinuxAdapter::new(config.clone()),
        connection: c,
        interface: interface.into(),
        before,
        checkpoint: cp.clone(),
        other_macs: host
            .interfaces
            .iter()
            .filter(|i| i.name != interface)
            .filter_map(|i| i.effective_mac.clone())
            .collect(),
        expect_ipv4_default: host
            .routes
            .iter()
            .any(|r| r.starts_with("-4 default ") && r.contains(&format!(" dev {interface}"))),
        expect_ipv6_default: host
            .routes
            .iter()
            .any(|r| r.starts_with("-6 default ") && r.contains(&format!(" dev {interface}"))),
    };
    let result = apply_transaction(&mut adapter, &mut store, &p, id).map(|_| ());
    if result.is_err() {
        let _ = checkpoint_call("CheckpointRollback", &cp);
        let _ = degraded(state);
    }
    let _ = w.disarm();
    result
}

struct RotationAdapter {
    inner: LinuxAdapter,
    connection: Connection,
    interface: String,
    before: String,
    checkpoint: String,
    other_macs: Vec<String>,
    expect_ipv4_default: bool,
    expect_ipv6_default: bool,
}
impl Adapter for RotationAdapter {
    fn read(&mut self, t: &Target) -> Result<String> {
        self.inner.read(t)
    }
    fn write(&mut self, t: &Target, v: &str) -> Result<()> {
        self.inner.write(t, v)
    }
    fn health(&mut self) -> Result<()> {
        run(
            "nmcli",
            &[
                "--wait",
                "45",
                "connection",
                "up",
                "uuid",
                &self.connection.uuid,
                "ifname",
                &self.interface,
            ],
            Duration::from_secs(50),
        )?;
        let effective = fs::read_to_string(
            Path::new("/sys/class/net")
                .join(&self.interface)
                .join("address"),
        )?
        .trim()
        .to_string();
        let first = effective
            .split(':')
            .next()
            .and_then(|s| u8::from_str_radix(s, 16).ok())
            .context("invalid effective MAC")?;
        if first & 3 != 2
            || effective.eq_ignore_ascii_case(&self.before)
            || self
                .other_macs
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&effective))
        {
            bail!("effective random MAC invariant/rotation verification failed")
        }
        let routes = query("ip", &["route", "show", "dev", &self.interface])?;
        let v6 = query("ip", &["-6", "route", "show", "dev", &self.interface])?;
        if routes.is_empty() && v6.is_empty() {
            bail!("no interface routes after reconnect")
        }
        if (self.expect_ipv4_default && !routes.lines().any(|r| r.starts_with("default ")))
            || (self.expect_ipv6_default && !v6.lines().any(|r| r.starts_with("default ")))
        {
            bail!("a previous IPv4/IPv6 default route disappeared after reconnect")
        }
        checkpoint_call("CheckpointDestroy", &self.checkpoint)?;
        Ok(())
    }
}
