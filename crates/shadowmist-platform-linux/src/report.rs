use crate::*;
use shadowmist_core::*;
use std::{fs, path::Path};

pub fn report(config: &Config, host: &Host, state_dir: &Path, probe: bool) -> Report {
    let mut findings = Vec::new();
    let mut add = |code: &str, severity: Severity, evidence: String, mitigation: &str| {
        findings.push(Finding {
            code: code.into(),
            severity,
            evidence,
            mitigation: mitigation.into(),
        });
    };
    if !host.capabilities.nm_active {
        add(
            "NM_UNAVAILABLE",
            Severity::Unknown,
            "NetworkManager is unavailable/inactive".into(),
            "Use observe mode or a supported NetworkManager host",
        );
    }
    if !host.capabilities.resolved_active {
        add(
            "RESOLVED_UNAVAILABLE",
            Severity::Warn,
            "systemd-resolved unavailable/inactive; encrypted DNS is not enabled".into(),
            "Review docs/compatibility.md; setup is a separate administrator action",
        );
    }
    if host.capabilities.resolved_active && !host.capabilities.resolved_dbus_available {
        add("RESOLVED_DBUS_UNAVAILABLE", Severity::High,
            "systemd-resolved is active but org.freedesktop.resolve1 has no reachable D-Bus owner; NetworkManager cannot publish DNS settings".into(),
            "Inspect journalctl -u dbus -u systemd-resolved for registration/user errors; see docs/recovery.md before restarting DNS services");
    }
    if host.capabilities.resolved_upstream_configured == Some(false) {
        add("RESOLVED_NO_UPSTREAM", Severity::Warn,
            "Resolved reports no explicit global or per-link DNS servers; compiled fallback behavior is not verified".into(),
            "Compare resolvectl dns with nmcli -g IP4.DNS,IP6.DNS device show; repair NM/resolved communication and inspect fallback status");
    }
    if host.capabilities.resolver_owner == "systemd-resolved-stub-bypassed" {
        add("RESOLV_CONF_BYPASS", Severity::High,
            "resolv.conf points to the resolved stub file but lists other nameservers; applications can bypass encrypted system DNS".into(),
            "Keep the working fallback until resolver integration is repaired and verified; do not edit the generated stub as permanent configuration");
    } else if host.capabilities.resolver_owner == "systemd-resolved-stub-invalid" {
        add("RESOLV_CONF_INVALID", Severity::High,
            "The resolved stub file is unreadable, malformed, or contains no nameserver".into(),
            "Inspect resolver configuration from a console and preserve working access before changing it");
    } else if host.capabilities.resolver_owner != "systemd-resolved-stub" {
        add(
            "RESOLVER_OWNERSHIP",
            Severity::Warn,
            "resolv.conf is not the resolved stub".into(),
            "Keep current ownership; investigate before any DNS migration",
        );
    }
    if host.capabilities.container || !host.capabilities.systemd || !host.capabilities.writable {
        add(
            "AUDIT_ONLY",
            Severity::Unknown,
            "container/WSL, missing systemd, or read-only system".into(),
            "Host mutations are unsupported",
        );
    }
    for b in &host.capabilities.dns_blockers {
        add(
            "DNS_COMPATIBILITY",
            Severity::Warn,
            b.clone(),
            "Preserve current VPN, LAN and resolver policy",
        );
    }
    if config.general.enrolled_profiles.is_empty() {
        add(
            "NO_ENROLLMENT",
            Severity::Info,
            "No connection UUIDs enrolled; startup is read-only".into(),
            "Explicitly enroll owned profiles and review apply --dry-run",
        );
    }
    if config.dns.enabled && config.dns.health_domains.is_empty() {
        add(
            "DNS_PROBES_DISABLED",
            Severity::Info,
            "No external DNS health lookups approved; DNS apply is disabled".into(),
            "Set at least two independent dns.health_domains to opt in",
        );
    }
    if config.network_audit.check_wifi_security {
        for i in &host.interfaces {
            if i.kind == "wifi" && i.state.starts_with("connected") {
                match i.wifi_security.as_deref() {
                    Some("" | "none") => add(
                        "WIFI_OPEN_OR_WEP",
                        Severity::High,
                        "Active Wi-Fi profile has no modern key management; open/WEP indicated"
                            .into(),
                        "Prefer an authenticated WPA2/WPA3 network",
                    ),
                    Some("wpa-psk") => add(
                        "WIFI_WPA_PSK",
                        Severity::Info,
                        "WPA-PSK profile; negotiated WPA2/cipher is not proven by profile policy"
                            .into(),
                        "Review access point and negotiated link security",
                    ),
                    Some("sae") => add(
                        "WIFI_SAE",
                        Severity::Info,
                        "SAE configured; negotiated protocol is not independently inspected".into(),
                        "Keep driver and access point updated",
                    ),
                    _ => add(
                        "WIFI_SECURITY_UNKNOWN",
                        Severity::Unknown,
                        "Wi-Fi security cannot be established from accessible profile data".into(),
                        "Inspect the connection locally",
                    ),
                }
            }
        }
    }
    add(
        "SCAN_PRIVACY",
        Severity::Unknown,
        "Hardware scan MAC randomization has not been verified".into(),
        "Inspect NetworkManager scan policy and supported Wi-Fi hardware",
    );
    add(
        "DHCP_IDENTIFIERS",
        Severity::Info,
        "DHCP client ID and DHCPv6 DUID may remain stable across MAC changes".into(),
        "Review profile identifiers; MVP does not rewrite DHCP identity",
    );
    add(
        "FIREWALL",
        Severity::Unknown,
        host.firewall.clone(),
        "Review existing firewall independently; Shadow Mist installs no firewall rules",
    );
    if config.network_audit.include_listening_ports {
        let exposed = host
            .listeners
            .iter()
            .filter(|s| {
                let f: Vec<_> = s.split_whitespace().collect();
                f.get(4).is_some_and(|a| {
                    a.starts_with("0.0.0.0:") || a.starts_with("[::]:") || a.starts_with("*:")
                })
            })
            .count();
        add("LOCAL_LISTENERS",if exposed>0{Severity::Warn}else{Severity::Info},format!("{} local listening sockets observed, {exposed} wildcard bindings; no remote hosts probed",host.listeners.len()),"Review local services and discovery ports (53, 137, 5353, 5355); listeners do not prove reachability");
    }
    if !host.plaintext_dns_peers.is_empty() {
        add(
            "PLAINTEXT_DNS_INDICATOR",
            Severity::Warn,
            format!(
                "{} socket peer(s) on non-loopback port 53 observed; snapshot only",
                host.plaintext_dns_peers.len()
            ),
            "Inspect originating applications; absence is not evidence of no leaks",
        );
    }
    if !host.routes.iter().any(|r| r.contains(" default ")) {
        add(
            "NO_DEFAULT_ROUTE",
            Severity::Warn,
            "No main-table IPv4/IPv6 default route observed; policy routing not excluded".into(),
            "Inspect addresses, route tables and VPN policy",
        );
    }
    if host.connectivity == "portal" {
        add(
            "CAPTIVE_PORTAL_INDICATOR",
            Severity::Warn,
            "NetworkManager reports portal connectivity; no independent portal request issued"
                .into(),
            "Authenticate using an explicit compatibility workflow; no automatic downgrade",
        );
    }
    for e in &host.capabilities.errors {
        add(
            "INSPECTION_UNAVAILABLE",
            Severity::Unknown,
            e.clone(),
            "Review local permissions and required components",
        );
    }
    let active: Vec<_> = host
        .connections
        .iter()
        .filter(|c| c.active && c.physical)
        .collect();
    let mut dns=DnsReport{state:Protection::Unprotected,scope:"systemd-resolved system queries only; no packet capture or application-wide enforcement".into(),reason:"Authenticated DoT is not established".into(),enforced:false};
    if host.capabilities.resolved_active && !host.capabilities.resolved_dbus_available {
        dns.reason="Resolved is running but its D-Bus API is unavailable; NetworkManager cannot deliver DNS configuration".into();
    } else if host.capabilities.resolver_owner == "systemd-resolved-stub-bypassed" {
        dns.reason="Additional nameservers in resolv.conf bypass the resolved stub; system DNS encryption cannot be claimed".into();
    }
    if active.len() == 1
        && host.capabilities.resolved_active
        && host.capabilities.resolved_dbus_available
        && host.capabilities.resolver_owner == "systemd-resolved-stub"
        && host.capabilities.nm_dns_plugin == "systemd-resolved"
        && host.capabilities.dns_blockers.is_empty()
    {
        match verify_dns(config, &active[0].interface, probe) {
            Ok(true) => {
                dns.state = Protection::Verified;
                dns.reason="All effective per-link servers are approved, with pinned certificate hostname and DoT=yes; uncached approved lookups succeeded. Protocol guaranteed by resolved policy, not packet capture.".into();
            }
            Ok(false) => {
                dns.state = Protection::Configured;
                dns.reason="Effective resolved settings match authenticated DoT; no fresh upstream health lookup performed".into();
            }
            Err(_) => {
                dns.state = Protection::Uncertain;
                dns.reason =
                    "Effective encrypted DNS configuration/health could not be verified".into();
            }
        }
    }
    let mut state = if config.general.profile == Profile::Observe {
        Protection::Observe
    } else {
        dns.state.clone()
    };
    if fs::read_to_string(state_dir.join("health.json")).is_ok_and(|s| s.contains("DEGRADED")) {
        state = Protection::Degraded;
        dns.state = Protection::Degraded;
        dns.reason="Previous rollback reported DEGRADED; prior/plaintext DNS may be active. Explicit apply is required to retry.".into();
    }
    Report {
        schema_version: SCHEMA_VERSION,
        timestamp: timestamp(),
        profile: config.general.profile,
        state,
        dns,
        capabilities: host.capabilities.clone(),
        interfaces: host.interfaces.clone(),
        findings,
        limitations: PRIVACY_LIMITS.into(),
        redacted: false,
    }
}

pub fn route_change(previous: &Host, next: &Host) -> Option<Finding> {
    let gateways = |h: &Host| {
        h.routes
            .iter()
            .filter(|r| r.contains(" default "))
            .cloned()
            .collect::<Vec<_>>()
    };
    if !previous.routes.is_empty() && gateways(previous) != gateways(next) {
        Some(Finding{code:"DEFAULT_ROUTE_CHANGE".into(),severity:Severity::Warn,evidence:"Default route/gateway changed since previous observation; an indicator, not proof of an attack".into(),mitigation:"Review DHCP/RA, roaming and VPN changes locally".into()})
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn active_service_without_bus_or_upstream_has_specific_findings() {
        let h = Host {
            capabilities: Capabilities {
                resolved_active: true,
                resolved_dbus_available: false,
                resolved_upstream_configured: Some(false),
                resolver_owner: "systemd-resolved-stub".into(),
                ..Capabilities::default()
            },
            ..Host::default()
        };
        let r = report(
            &Config::default(),
            &h,
            Path::new("/nonexistent/shadowmist"),
            false,
        );
        assert!(r
            .findings
            .iter()
            .any(|f| f.code == "RESOLVED_DBUS_UNAVAILABLE" && f.severity == Severity::High));
        assert!(r.findings.iter().any(|f| f.code == "RESOLVED_NO_UPSTREAM"));
        assert_eq!(r.dns.state, Protection::Unprotected);
        assert!(r.dns.reason.contains("D-Bus"));
    }
    #[test]
    fn mixed_stub_cannot_report_encrypted_dns() {
        let h = Host {
            capabilities: Capabilities {
                resolved_active: true,
                resolved_dbus_available: true,
                resolver_owner: "systemd-resolved-stub-bypassed".into(),
                ..Capabilities::default()
            },
            ..Host::default()
        };
        let r = report(
            &Config::default(),
            &h,
            Path::new("/nonexistent/shadowmist"),
            false,
        );
        assert!(r.findings.iter().any(|f| f.code == "RESOLV_CONF_BYPASS"));
        assert_eq!(r.dns.state, Protection::Unprotected);
        assert!(r.dns.reason.contains("bypass"));
    }
    #[test]
    fn reports_redact_addresses() {
        let h = Host {
            interfaces: vec![Interface {
                effective_mac: Some("02:aa:bb:cc:dd:ee".into()),
                addresses: vec!["192.0.2.1".into()],
                ..Interface::default()
            }],
            ..Host::default()
        };
        let r = report(
            &Config::default(),
            &h,
            Path::new("/nonexistent/shadowmist"),
            false,
        )
        .redacted();
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("02:aa"));
        assert!(!json.contains("192.0.2.1"));
        assert_ne!(r.state, Protection::Verified);
    }
    #[test]
    fn route_changes_are_indicators() {
        let a = Host {
            routes: vec!["-4 default via 192.0.2.1".into()],
            ..Host::default()
        };
        let b = Host {
            routes: vec!["-4 default via 192.0.2.2".into()],
            ..Host::default()
        };
        assert!(route_change(&a, &b).unwrap().evidence.contains("not proof"));
    }
    #[test]
    fn rotation_is_explicit() {
        let c = Config::default();
        let h = Host::default();
        assert!(rotation_preflight(&c, &h, "wlan0", false, false, false).is_err());
        assert!(rotation_preflight(&c, &h, "wlan0", true, true, false).is_err());
    }
}
