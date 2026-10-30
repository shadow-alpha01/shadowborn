use crate::*;
use shadowmist_core::*;
use std::{collections::BTreeMap, fs, path::Path};

fn active(unit: &str) -> bool {
    query("systemctl", &["is-active", unit]).is_ok_and(|s| s == "active")
}
fn nm_property(key: &str) -> Option<serde_json::Value> {
    property(
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager",
        "org.freedesktop.NetworkManager",
        key,
    )
    .ok()
}
pub fn remote_session() -> bool {
    if std::env::var_os("SSH_CONNECTION").is_some()
        || std::env::var_os("SSH_CLIENT").is_some()
        || std::env::var_os("SSH_TTY").is_some()
    {
        return true;
    }
    // Any SSH/remote session is conservatively treated as a remote-management path.
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().bytes().all(|c| c.is_ascii_digit()) {
                if let Ok(comm) = fs::read_to_string(entry.path().join("comm")) {
                    if comm.trim().starts_with("sshd") {
                        return true;
                    }
                }
            }
        }
    }
    false
}
fn read_file(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}
fn filesystem_writable() -> bool {
    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();
    !mounts.lines().any(|line| {
        let p: Vec<_> = line.split_whitespace().collect();
        p.len() > 3 && ["/", "/etc", "/var"].contains(&p[1]) && p[3].split(',').any(|v| v == "ro")
    })
}
pub fn discover(config: &Config) -> Host {
    let mut h = Host::default();
    let cap = &mut h.capabilities;
    cap.systemd = read_file("/proc/1/comm").is_some_and(|s| s == "systemd");
    cap.root = is_root();
    cap.container = Path::new("/.dockerenv").exists()
        || Path::new("/run/.containerenv").exists()
        || std::env::var_os("WSL_DISTRO_NAME").is_some()
        || read_file("/proc/sys/kernel/osrelease")
            .is_some_and(|s| s.to_lowercase().contains("microsoft"));
    cap.writable = filesystem_writable();
    cap.remote_session = remote_session();
    cap.nm_version = query("nmcli", &["--version"]).ok();
    // --offline validates supported settings and serializes a synthetic keyfile;
    // it never creates a live profile or contacts a network.
    cap.nm_dot_supported = query(
        "nmcli",
        &[
            "--offline",
            "connection",
            "add",
            "type",
            "ethernet",
            "con-name",
            "shadowmist-capability",
            "connection.dns-over-tls",
            "yes",
            "ipv4.dns",
            "9.9.9.9#dns.quad9.net",
        ],
    )
    .is_ok();
    cap.nm_stable_ssid_supported = query(
        "nmcli",
        &[
            "--offline",
            "connection",
            "add",
            "type",
            "wifi",
            "con-name",
            "shadowmist-capability",
            "ssid",
            "shadowmist-capability",
            "802-11-wireless.cloned-mac-address",
            "stable-ssid",
        ],
    )
    .is_ok();
    cap.nm_active =
        query("nmcli", &["-t", "-f", "RUNNING", "general"]).is_ok_and(|s| s == "running");
    cap.resolved_active = active("systemd-resolved.service");
    cap.resolved_version = query("resolvectl", &["--version"])
        .ok()
        .and_then(|s| s.lines().next().map(str::to_string));
    cap.resolver_owner = match fs::canonicalize("/etc/resolv.conf").ok().as_deref() {
        Some(p) if p == Path::new("/run/systemd/resolve/stub-resolv.conf") => {
            "systemd-resolved-stub"
        }
        Some(p) if p == Path::new("/run/systemd/resolve/resolv.conf") => {
            "systemd-resolved-uplink-bypasses-stub"
        }
        _ => "other/unknown",
    }
    .into();
    cap.nm_dns_plugin = property(
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager/DnsManager",
        "org.freedesktop.NetworkManager.DnsManager",
        "Mode",
    )
    .ok()
    .and_then(|v| v.as_str().map(str::to_string))
    .unwrap_or_else(|| "unknown".into());
    cap.nft_available = binary("nft").is_some();
    cap.checkpoint_supported = query(
        "busctl",
        &[
            "--system",
            "introspect",
            "org.freedesktop.NetworkManager",
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
        ],
    )
    .is_ok_and(|v| v.contains("CheckpointCreate") && v.contains("CheckpointRollback"));
    h.connectivity = match nm_property("Connectivity").and_then(|v| v.as_u64()) {
        Some(1) => "none",
        Some(2) => "portal",
        Some(3) => "limited",
        Some(4) => "full",
        _ => "unknown",
    }
    .into();
    if matches!(h.connectivity.as_str(), "portal" | "limited") {
        cap.dns_blockers.push("NetworkManager indicates captive portal/limited connectivity; no compatibility exception applied".into());
    }
    if let Ok(out) = query(
        "nmcli",
        &["-t", "-f", "DEVICE,TYPE,STATE,CON-UUID", "device", "status"],
    ) {
        for line in out.lines() {
            let f = split_escaped(line);
            if f.len() != 4 || !valid_interface(&f[0]) {
                continue;
            }
            let name = &f[0];
            let sys = Path::new("/sys/class/net").join(name);
            let physical =
                sys.join("device").exists() && ["wifi", "ethernet"].contains(&f[1].as_str());
            let permanent = query(
                "nmcli",
                &[
                    "--escape",
                    "no",
                    "-g",
                    "GENERAL.PERM-HWADDR",
                    "device",
                    "show",
                    name,
                ],
            )
            .ok()
            .filter(|v| !v.is_empty() && v != "--");
            h.interfaces.push(Interface {
                name: name.clone(),
                kind: f[1].clone(),
                state: f[2].clone(),
                profile_uuid: valid_uuid(&f[3]).then(|| f[3].clone()),
                effective_mac: read_file(sys.join("address")),
                permanent_mac: permanent,
                physical,
                excluded: !physical || excluded(name, &config.identity.exclude_interfaces),
                scan_randomization:
                    "UNKNOWN: profile policy and hardware effectiveness are distinct".into(),
                ..Interface::default()
            });
        }
    } else {
        cap.errors
            .push("NetworkManager device discovery unavailable".into());
    }
    if h.interfaces.is_empty() {
        if let Ok(entries) = fs::read_dir("/sys/class/net") {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                h.interfaces.push(Interface {
                    name: name.clone(),
                    kind: "unknown".into(),
                    effective_mac: read_file(e.path().join("address")),
                    excluded: true,
                    ..Interface::default()
                });
            }
        }
    }
    if let Ok(out) = query("nmcli", &["-t", "-f", "UUID,TYPE", "connection", "show"]) {
        for line in out.lines() {
            let f = split_escaped(line);
            if f.len() != 2 || !valid_uuid(&f[0]) {
                continue;
            }
            let device = h
                .interfaces
                .iter()
                .find(|i| i.profile_uuid.as_deref() == Some(&f[0]))
                .cloned();
            let enrolled = config.general.enrolled_profiles.contains(&f[0]);
            if device.is_none() && !enrolled {
                continue;
            }
            let interface = device
                .as_ref()
                .map(|i| i.name.clone())
                .or_else(|| {
                    query(
                        "nmcli",
                        &[
                            "--escape",
                            "no",
                            "-g",
                            "connection.interface-name",
                            "connection",
                            "show",
                            "uuid",
                            &f[0],
                        ],
                    )
                    .ok()
                })
                .unwrap_or_default();
            let physical = device.as_ref().map(|i| i.physical).unwrap_or_else(|| {
                Path::new("/sys/class/net")
                    .join(&interface)
                    .join("device")
                    .exists()
            });
            let mut settings = BTreeMap::new();
            for key in NM_KEYS {
                if let Ok(value) = read_nm(&f[0], key) {
                    settings.insert(key.to_string(), value);
                }
            }
            let enterprise = settings.get("802-1x.eap").is_some_and(|v| !v.is_empty())
                || settings
                    .get("802-11-wireless-security.key-mgmt")
                    .is_some_and(|v| v.contains("eap") || v.contains("ieee8021x"));
            if let Some(i) = h.interfaces.iter_mut().find(|i| i.name == interface) {
                i.wifi_security = settings.get("802-11-wireless-security.key-mgmt").cloned();
                i.configured_mac_policy = settings
                    .get(if f[1] == "802-11-wireless" {
                        "802-11-wireless.cloned-mac-address"
                    } else {
                        "802-3-ethernet.cloned-mac-address"
                    })
                    .cloned();
                i.mac_differs_from_permanent = i
                    .effective_mac
                    .as_ref()
                    .zip(i.permanent_mac.as_ref())
                    .map(|(a, b)| !a.eq_ignore_ascii_case(b));
            }
            if device.is_some()
                && !["802-11-wireless", "802-3-ethernet", "loopback", "bridge"]
                    .contains(&f[1].as_str())
            {
                cap.dns_blockers
                    .push("active VPN, tunnel or unsupported connection; preserve its DNS".into());
            }
            h.connections.push(Connection {
                uuid: f[0].clone(),
                kind: f[1].clone(),
                interface,
                active: device.is_some(),
                physical,
                enterprise,
                settings,
            });
        }
    }
    if let Ok(out) = query("ip", &["-j", "address", "show"]) {
        if let Ok(v) = serde_json::from_str::<Vec<serde_json::Value>>(&out) {
            for addr in v {
                if let Some(i) = h
                    .interfaces
                    .iter_mut()
                    .find(|i| Some(i.name.as_str()) == addr["ifname"].as_str())
                {
                    if let Some(info) = addr["addr_info"].as_array() {
                        i.addresses = info
                            .iter()
                            .filter_map(|v| v["local"].as_str().map(str::to_string))
                            .collect();
                    }
                }
            }
        }
    }
    for family in ["-4", "-6"] {
        if let Ok(out) = query("ip", &[family, "route", "show", "table", "main"]) {
            h.routes
                .extend(out.lines().map(|v| format!("{family} {v}")));
        }
    }
    if config.network_audit.include_listening_ports {
        match query("ss", &["-H", "-lntu"]) {
            Ok(out) => h.listeners = out.lines().map(str::to_string).collect(),
            Err(_) => cap
                .errors
                .push("local socket inspection unavailable".into()),
        }
    }
    if let Ok(out) = query("ss", &["-H", "-ntu"]) {
        for line in out.lines() {
            if let Some(peer) = line.split_whitespace().last() {
                if peer.ends_with(":53") && !peer.starts_with("127.") && !peer.starts_with("[::1]")
                {
                    h.plaintext_dns_peers.push(peer.into());
                }
            }
        }
    }
    h.firewall = if is_root() {
        match query("nft", &["list", "tables"]) {
            Ok(s) if !s.is_empty() => "nftables tables present; rules not assessed",
            Ok(_) => "no nftables tables; other firewall backends not excluded",
            Err(_) => "UNKNOWN: firewall inspection unavailable",
        }
    } else {
        "UNKNOWN: root needed to inspect firewall rules"
    }
    .into();
    if cap.resolved_active {
        match query("resolvectl", &["dns"]) {
            Ok(out) => {
                for line in out.lines() {
                    let Some((label, value)) = line.split_once(": ") else {
                        continue;
                    };
                    if label.starts_with("Global")
                        && !value.trim().is_empty()
                        && value.trim() != "--"
                    {
                        cap.dns_blockers.push(
                            "global DNS servers configured; coexistence is audit-only".into(),
                        );
                    }
                }
            }
            Err(_) => cap
                .dns_blockers
                .push("cannot inspect global resolver selection".into()),
        }
        for i in &h.interfaces {
            if i.state.starts_with("connected") {
                match live_dns(&i.name) {
                    Ok(live) => {
                        if live
                            .get("domain")
                            .is_some_and(|v| v.split_whitespace().any(|s| s != "~."))
                        {
                            cap.dns_blockers.push("search/split DNS detected; preserve enterprise/LAN resolver policy".into());
                        }
                        if !i.physical && live.get("dns").is_some_and(|v| !v.is_empty()) {
                            cap.dns_blockers
                                .push("DNS on virtual/VPN link detected".into());
                        }
                        h.dns_links.insert(i.name.clone(), live);
                    }
                    Err(_) => cap
                        .dns_blockers
                        .push("cannot snapshot an active resolved link".into()),
                }
            }
        }
    }
    // WireGuard and unmanaged tunnels can exist outside NM profiles.
    if h.interfaces
        .iter()
        .any(|i| i.name.starts_with("wg") || i.name.starts_with("tun") || i.kind == "wireguard")
    {
        cap.dns_blockers
            .push("VPN/tunnel interface detected; automatic DNS takeover disabled".into());
    }
    h
}
