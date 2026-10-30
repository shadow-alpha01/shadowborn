use crate::*;

pub const SEARCH_DNS_BLOCKER: &str =
    "search/split DNS detected; preserve enterprise/LAN resolver policy";

fn has_search_domains(host: &Host) -> bool {
    host.dns_links.values().any(|link| {
        link.get("domain")
            .is_some_and(|domains| domains.split_whitespace().any(|domain| domain != "~."))
    })
}

fn replacement_is_authorized(config: &Config, host: &Host, approved: &[String]) -> bool {
    if approved.is_empty() || approved.iter().any(|domain| !valid_search_domain(domain)) {
        return false;
    }
    let mut seen = false;
    for (interface, link) in &host.dns_links {
        for domain in link
            .get("domain")
            .into_iter()
            .flat_map(|domains| domains.split_whitespace())
            .filter(|domain| *domain != "~.")
        {
            seen = true;
            let enrolled_physical = host.connections.iter().any(|connection| {
                connection.interface == *interface
                    && connection.active
                    && connection.physical
                    && !connection.enterprise
                    && ["802-11-wireless", "802-3-ethernet"].contains(&connection.kind.as_str())
                    && config.general.enrolled_profiles.contains(&connection.uuid)
                    && !excluded(interface, &config.identity.exclude_interfaces)
            });
            // Route-only domains and other links remain unsupported, even with a matching suffix.
            if !enrolled_physical
                || domain.starts_with('~')
                || !approved
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(domain))
            {
                return false;
            }
        }
    }
    seen
}

fn nm_change(plan: &mut Plan, c: &Connection, key: &str, value: &str, reason: &str) {
    match c.settings.get(key) {
        Some(before) if before != value => plan.changes.push(Change {
            target: Target::Nm {
                uuid: c.uuid.clone(),
                key: key.into(),
            },
            before: before.clone(),
            after: value.into(),
            reason: reason.into(),
        }),
        None => plan
            .warnings
            .push(format!("unsupported property {key}; skipped")),
        _ => {}
    }
}
pub fn plan(config: &Config, host: &Host) -> Plan {
    plan_replacing_search_domains(config, host, &[])
}

pub fn plan_replacing_search_domains(
    config: &Config,
    host: &Host,
    approved_domains: &[String],
) -> Plan {
    let mut p = Plan::default();
    if config.general.profile == Profile::Observe {
        return p;
    }
    let cap = &host.capabilities;
    if !cap.nm_active || !cap.systemd || cap.container || !cap.writable {
        p.warnings.push("platform is audit-only: requires host systemd, active NetworkManager and writable configuration".into());
        return p;
    }
    let selected: Vec<_> = host
        .connections
        .iter()
        .filter(|c| config.general.enrolled_profiles.contains(&c.uuid))
        .collect();
    if selected.is_empty() {
        p.warnings
            .push("no enrolled profiles; add explicit UUIDs to general.enrolled_profiles".into());
    }
    for uuid in &config.general.enrolled_profiles {
        if !host.connections.iter().any(|c| &c.uuid == uuid) {
            p.warnings
                .push("an enrolled profile is unavailable; skipped".into());
        }
    }
    for c in &selected {
        if !c.physical
            || !["802-11-wireless", "802-3-ethernet"].contains(&c.kind.as_str())
            || excluded(&c.interface, &config.identity.exclude_interfaces)
            || c.enterprise
        {
            p.warnings.push(
                "excluded virtual, enterprise/802.1X, or unsupported profile; no mutation".into(),
            );
            continue;
        }
        let (key, policy) = if c.kind == "802-11-wireless" {
            (
                "802-11-wireless.cloned-mac-address",
                config.identity.wifi_mac,
            )
        } else {
            (
                "802-3-ethernet.cloned-mac-address",
                config.identity.ethernet_mac,
            )
        };
        if policy == MacPolicy::StableSsid && !cap.nm_stable_ssid_supported {
            p.warnings.push(
                "stable-ssid is unsupported by the installed NetworkManager; MAC policy skipped"
                    .into(),
            );
        } else if c.kind == "802-11-wireless" || policy != MacPolicy::Preserve {
            nm_change(
                &mut p,
                c,
                key,
                policy.as_str(),
                "MAC policy for next activation; no reconnect",
            );
        }
        if config.ipv6.privacy_addresses == "prefer-temporary"
            && matches!(
                c.settings.get("ipv6.method").map(String::as_str),
                Some("auto" | "dhcp")
            )
        {
            nm_change(
                &mut p,
                c,
                "ipv6.addr-gen-mode",
                "stable-privacy",
                "IPv6 stable identifier on next activation",
            );
            nm_change(
                &mut p,
                c,
                "ipv6.ip6-privacy",
                "2",
                "prefer temporary IPv6 addresses on next activation",
            );
        }
    }
    if config.identity.wifi_scan_randomization {
        p.warnings.push(
            "scan MAC randomization is audited only; driver effectiveness is not verified".into(),
        );
    }
    if !config.dns.enabled {
        return p;
    }
    let mut blockers = cap.dns_blockers.clone();
    if replacement_is_authorized(config, host, approved_domains) {
        // Remove only this known blocker after validating every affected link/domain.
        blockers.retain(|blocker| blocker != SEARCH_DNS_BLOCKER);
        p.warnings.push("Explicitly approved DNS search domains will be replaced; their local names may stop resolving. Prior values remain in the rollback journal.".into());
    } else if has_search_domains(host)
        && !blockers.iter().any(|blocker| blocker == SEARCH_DNS_BLOCKER)
    {
        blockers.push(SEARCH_DNS_BLOCKER.into());
    }
    if !cap.resolved_dbus_available {
        blockers.push("resolved D-Bus interface unavailable: active service/Varlink alone cannot receive NetworkManager DNS settings".into());
    }
    if !cap.nm_dot_supported {
        blockers.push(
            "NetworkManager offline validation did not confirm authenticated DoT/SNI support"
                .into(),
        );
    }
    if !cap.resolved_active
        || cap.resolver_owner != "systemd-resolved-stub"
        || cap.nm_dns_plugin != "systemd-resolved"
    {
        blockers.push(
            "requires active resolved, its stub resolv.conf and NetworkManager resolved DNS plugin"
                .into(),
        );
    }
    if config.dns.health_domains.len() < 2 {
        blockers.push(
            "DNS changes require opt-in: configure at least two independent dns.health_domains"
                .into(),
        );
    }
    let active: Vec<_> = host
        .connections
        .iter()
        .filter(|c| c.active && c.physical)
        .collect();
    if active.len() != 1 {
        blockers.push("DNS requires exactly one active ordinary physical connection".into());
    }
    let chosen = active.first().copied();
    if let Some(c) = chosen {
        if !selected.iter().any(|s| s.uuid == c.uuid)
            || c.enterprise
            || excluded(&c.interface, &config.identity.exclude_interfaces)
        {
            blockers.push("active profile is not enrolled/eligible".into());
        }
        for key in [
            "connection.dns-over-tls",
            "ipv4.dns",
            "ipv6.dns",
            "ipv4.ignore-auto-dns",
            "ipv6.ignore-auto-dns",
            "ipv4.dns-search",
            "ipv6.dns-search",
        ] {
            if !c.settings.contains_key(key) {
                blockers.push(format!("DNS property unavailable: {key}"));
            }
        }
        if !host.dns_links.contains_key(&c.interface) {
            blockers.push("resolved link properties unavailable".into());
        }
    }
    if !blockers.is_empty() {
        for b in blockers {
            p.warnings.push(format!("DNS skipped: {b}"));
        }
        return p;
    }
    let c = chosen.expect("checked active length");
    let servers: Vec<_> = config
        .dns
        .servers()
        .into_iter()
        .filter(|s| {
            let key = if s.split('#').next().unwrap_or("").contains(':') {
                "ipv6.method"
            } else {
                "ipv4.method"
            };
            !matches!(
                c.settings.get(key).map(String::as_str),
                Some("disabled" | "ignore")
            )
        })
        .collect();
    if servers.is_empty() {
        p.warnings
            .push("DNS skipped: no approved endpoint for enabled IP families".into());
        return p;
    }
    let v4 = servers
        .iter()
        .filter(|s| !s.split('#').next().unwrap_or("").contains(':'))
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    let v6 = servers
        .iter()
        .filter(|s| s.split('#').next().unwrap_or("").contains(':'))
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    for (key, value) in [
        ("connection.dns-over-tls", "yes"),
        ("ipv4.ignore-auto-dns", "yes"),
        ("ipv6.ignore-auto-dns", "yes"),
        ("ipv4.dns", v4.as_str()),
        ("ipv6.dns", v6.as_str()),
        ("ipv4.dns-search", "~."),
        ("ipv6.dns-search", "~."),
    ] {
        if key.starts_with("ipv4.")
            && matches!(
                c.settings.get("ipv4.method").map(String::as_str),
                Some("disabled" | "ignore")
            )
        {
            continue;
        }
        if key.starts_with("ipv6.")
            && matches!(
                c.settings.get("ipv6.method").map(String::as_str),
                Some("disabled" | "ignore")
            )
        {
            continue;
        }
        nm_change(
            &mut p,
            c,
            key,
            value,
            "persistent authenticated system DNS policy",
        );
    }
    let live = &host.dns_links[&c.interface];
    // Transport is tightened first; removing old servers precedes root-domain routing.
    for (key, value) in [
        ("dnsovertls", "yes".to_string()),
        ("dns", servers.join(" ")),
        ("domain", "~.".into()),
    ] {
        match live.get(key) {
            Some(before) if before != &value => p.changes.push(Change {
                target: Target::Resolved {
                    interface: c.interface.clone(),
                    key: key.into(),
                    uuid: c.uuid.clone(),
                },
                before: before.clone(),
                after: value,
                reason: "live per-link DNS; independent timed rollback required".into(),
            }),
            None => {
                p.warnings
                    .push("resolved link snapshot incomplete; refusing all DNS operations".into());
                p.changes
                    .retain(|x| !matches!(x.target, Target::Resolved { .. }) && !is_dns_change(x));
                return p;
            }
            _ => {}
        }
    }
    p.dns_live = p.changes.iter().any(is_dns_change);
    p
}
pub fn is_dns_change(c: &Change) -> bool {
    match &c.target {
        Target::Resolved { .. } => true,
        Target::Nm { key, .. } => key.contains("dns"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn home_fixture() -> (Config, Host) {
        let (config, mut host) = fixture();
        host.dns_links
            .get_mut("wlan0")
            .unwrap()
            .insert("domain".into(), "home".into());
        host.capabilities
            .dns_blockers
            .push(SEARCH_DNS_BLOCKER.into());
        (config, host)
    }
    #[test]
    fn search_domains_require_exact_explicit_consent() {
        let (config, host) = home_fixture();
        assert!(!plan(&config, &host).dns_live);
        assert!(!plan_replacing_search_domains(&config, &host, &["other".into()]).dns_live);
        for consent in ["home", "HOME"] {
            let p = plan_replacing_search_domains(&config, &host, &[consent.into()]);
            assert!(p.dns_live);
            assert!(!p.reconnect);
            let domain = p
                .changes
                .iter()
                .find(|c| matches!(&c.target,Target::Resolved{key,..} if key=="domain"))
                .unwrap();
            assert_eq!(domain.before, "home");
            assert_eq!(domain.after, "~.");
        }
    }
    #[test]
    fn every_search_domain_must_be_approved() {
        let (config, mut host) = home_fixture();
        host.dns_links
            .get_mut("wlan0")
            .unwrap()
            .insert("domain".into(), "home lab.example".into());
        assert!(!plan_replacing_search_domains(&config, &host, &["home".into()]).dns_live);
        assert!(
            plan_replacing_search_domains(&config, &host, &["home".into(), "lab.example".into()])
                .dns_live
        );
    }
    #[test]
    fn routing_domains_and_vpns_remain_blocked() {
        let (config, mut host) = home_fixture();
        host.dns_links
            .get_mut("wlan0")
            .unwrap()
            .insert("domain".into(), "~home".into());
        for consent in ["home", "~home"] {
            assert!(!plan_replacing_search_domains(&config, &host, &[consent.into()]).dns_live);
        }
        host.dns_links
            .get_mut("wlan0")
            .unwrap()
            .insert("domain".into(), "home".into());
        host.capabilities
            .dns_blockers
            .push("VPN/tunnel interface detected; automatic DNS takeover disabled".into());
        assert!(!plan_replacing_search_domains(&config, &host, &["home".into()]).dns_live);
    }
    #[test]
    fn consent_cannot_clear_domains_on_other_or_enterprise_links() {
        let (config, host) = home_fixture();
        for scenario in 0..4 {
            let mut host = host.clone();
            let mut config = config.clone();
            match scenario {
                0 => {
                    host.dns_links
                        .insert("docker0".into(), [("domain".into(), "home".into())].into());
                }
                1 => host.connections[0].enterprise = true,
                2 => config.general.enrolled_profiles.clear(),
                _ => host.connections[0].physical = false,
            }
            assert!(
                !plan_replacing_search_domains(&config, &host, &["home".into()]).dns_live,
                "scenario {scenario}"
            );
        }
    }
    #[test]
    fn planner_detects_search_domains_without_discovery_hint() {
        let (config, mut host) = home_fixture();
        host.capabilities.dns_blockers.clear();
        assert!(!plan(&config, &host).dns_live);
        assert!(plan_replacing_search_domains(&config, &host, &["home".into()]).dns_live);
    }
    #[test]
    fn unknown_search_blocker_is_not_cleared_without_snapshot_evidence() {
        let (config, mut host) = home_fixture();
        host.dns_links
            .get_mut("wlan0")
            .unwrap()
            .insert("domain".into(), "".into());
        assert!(!plan_replacing_search_domains(&config, &host, &["home".into()]).dns_live);
    }
    #[test]
    fn invalid_consent_never_enables_dns() {
        let (config, host) = home_fixture();
        for domain in ["*", "*.home", "~.", "home corp", "--all"] {
            assert!(!plan_replacing_search_domains(&config, &host, &[domain.into()]).dns_live);
        }
    }
    #[test]
    fn approved_search_domain_is_restored_with_the_transaction() {
        use anyhow::Result;
        use std::collections::BTreeMap;
        struct Simulated(BTreeMap<Target, String>);
        impl Adapter for Simulated {
            fn read(&mut self, target: &Target) -> Result<String> {
                Ok(self.0[target].clone())
            }
            fn write(&mut self, target: &Target, value: &str) -> Result<()> {
                self.0.insert(target.clone(), value.into());
                Ok(())
            }
            fn health(&mut self) -> Result<()> {
                Ok(())
            }
        }
        struct Memory(Vec<Journal>);
        impl JournalStore for Memory {
            fn save(&mut self, journal: &Journal) -> Result<()> {
                self.0.push(journal.clone());
                Ok(())
            }
        }
        let (config, host) = home_fixture();
        let p = plan_replacing_search_domains(&config, &host, &["home".into()]);
        let original: BTreeMap<_, _> = p
            .changes
            .iter()
            .map(|change| (change.target.clone(), change.before.clone()))
            .collect();
        let mut adapter = Simulated(original.clone());
        let mut store = Memory(vec![]);
        let mut journal = apply_transaction(&mut adapter, &mut store, &p, "1".into()).unwrap();
        assert!(journal.changes.iter().any(
            |change| matches!(&change.target,Target::Resolved{key,..} if key=="domain")
                && change.before == "home"
        ));
        restore_transaction(&mut adapter, &mut store, &mut journal).unwrap();
        assert_eq!(adapter.0, original);
        assert_eq!(journal.state, TransactionState::RolledBack);
    }
    #[test]
    fn active_resolved_without_dbus_cannot_receive_dns_policy() {
        let (c, mut h) = fixture();
        h.capabilities.resolved_dbus_available = false;
        let p = plan(&c, &h);
        assert!(!p.dns_live);
        assert!(!p.changes.iter().any(is_dns_change));
        assert!(p.warnings.iter().any(|w| w.contains("D-Bus")));
    }
    #[test]
    fn manual_stub_bypass_blocks_dns_application() {
        let (c, mut h) = fixture();
        h.capabilities.resolver_owner = "systemd-resolved-stub-bypassed".into();
        let p = plan(&c, &h);
        assert!(!p.dns_live);
        assert!(!p.changes.iter().any(is_dns_change));
    }
    #[test]
    fn wifi_preserve_replaces_previous_random_policy() {
        let (mut c, mut h) = fixture();
        c.identity.wifi_mac = MacPolicy::Preserve;
        h.connections[0]
            .settings
            .insert("802-11-wireless.cloned-mac-address".into(), "random".into());
        assert!(plan(&c, &h).changes.iter().any(
            |c| matches!(&c.target,Target::Nm{key,..} if key=="802-11-wireless.cloned-mac-address")
                && c.after == "preserve"
        ));
    }
    #[test]
    fn single_stack_plans_only_enabled_family() {
        for disabled in ["ipv4.method", "ipv6.method"] {
            let (c, mut h) = fixture();
            h.connections[0]
                .settings
                .insert(disabled.into(), "disabled".into());
            let p = plan(&c, &h);
            assert!(p.dns_live);
            let prefix = disabled.split('.').next().unwrap();
            assert!(!p
                .changes
                .iter()
                .any(|c| matches!(&c.target,Target::Nm{key,..} if key.starts_with(prefix))));
            let dns = p
                .changes
                .iter()
                .find(|c| matches!(&c.target,Target::Resolved{key,..} if key=="dns"))
                .unwrap();
            for server in dns.after.split_whitespace() {
                assert_eq!(
                    server.split('#').next().unwrap().contains(':'),
                    disabled == "ipv4.method"
                );
            }
        }
    }
    #[test]
    fn repeated_apply_is_empty() {
        let (c, mut h) = fixture();
        let p = plan(&c, &h);
        for change in p.changes {
            match change.target {
                Target::Nm { uuid, key } => {
                    h.connections
                        .iter_mut()
                        .find(|c| c.uuid == uuid)
                        .unwrap()
                        .settings
                        .insert(key, change.after);
                }
                Target::Resolved { interface, key, .. } => {
                    h.dns_links
                        .get_mut(&interface)
                        .unwrap()
                        .insert(key, change.after);
                }
            }
        }
        assert!(plan(&c, &h).changes.is_empty());
    }
    #[test]
    fn unsupported_offline_parser_and_portal_skip_dns() {
        let (c, mut h) = fixture();
        h.capabilities.nm_dot_supported = false;
        assert!(!plan(&c, &h).dns_live);
        h.capabilities.nm_dot_supported = true;
        h.capabilities
            .dns_blockers
            .push("captive portal indicated".into());
        assert!(!plan(&c, &h).dns_live);
    }
    #[test]
    fn stable_ssid_needs_capability() {
        let (mut c, mut h) = fixture();
        c.identity.wifi_mac = MacPolicy::StableSsid;
        assert!(!plan(&c, &h)
            .changes
            .iter()
            .any(|c| c.after == "stable-ssid"));
        h.capabilities.nm_stable_ssid_supported = true;
        assert!(plan(&c, &h)
            .changes
            .iter()
            .any(|c| c.after == "stable-ssid"));
    }
    pub fn fixture() -> (Config, Host) {
        let uuid = "01234567-89ab-cdef-0123-456789abcdef".to_string();
        let mut c = Config::default();
        c.general.enrolled_profiles.push(uuid.clone());
        c.dns.health_domains = vec!["example.com".into(), "example.net".into()];
        let conn = Connection {
            uuid,
            kind: "802-11-wireless".into(),
            interface: "wlan0".into(),
            active: true,
            physical: true,
            settings: [
                ("802-11-wireless.cloned-mac-address", "preserve"),
                ("ipv6.method", "auto"),
                ("ipv6.addr-gen-mode", "eui64"),
                ("ipv6.ip6-privacy", "0"),
                ("connection.dns-over-tls", "no"),
                ("ipv4.dns", ""),
                ("ipv6.dns", ""),
                ("ipv4.ignore-auto-dns", "no"),
                ("ipv6.ignore-auto-dns", "no"),
                ("ipv4.dns-search", ""),
                ("ipv6.dns-search", ""),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            ..Connection::default()
        };
        let host = Host {
            capabilities: Capabilities {
                systemd: true,
                nm_active: true,
                nm_dot_supported: true,
                writable: true,
                resolved_active: true,
                resolved_dbus_available: true,
                resolver_owner: "systemd-resolved-stub".into(),
                nm_dns_plugin: "systemd-resolved".into(),
                ..Capabilities::default()
            },
            connections: vec![conn],
            dns_links: [(
                "wlan0".into(),
                [
                    ("dns".into(), "192.0.2.1".into()),
                    ("domain".into(), "".into()),
                    ("dnsovertls".into(), "no".into()),
                ]
                .into(),
            )]
            .into(),
            ..Host::default()
        };
        (c, host)
    }
    #[test]
    fn enroll_and_next_activation_only() {
        let (c, h) = fixture();
        let p = plan(&c, &h);
        assert!(p.dns_live);
        assert!(!p.reconnect);
        assert!(p.changes.iter().any(|x| x.after == "random"));
        let mut c = c;
        c.general.enrolled_profiles.clear();
        assert!(plan(&c, &h).changes.is_empty());
    }
    #[test]
    fn capability_matrix() {
        let (c, h) = fixture();
        for case in 0..8 {
            let mut h = h.clone();
            match case {
                0 => h.capabilities.nm_active = false,
                1 => h.capabilities.container = true,
                2 => h.capabilities.writable = false,
                3 => h.capabilities.resolved_active = false,
                4 => h.capabilities.resolver_owner = "other".into(),
                5 => h.capabilities.dns_blockers.push("VPN/split DNS".into()),
                6 => h.connections[0].enterprise = true,
                _ => h.connections[0].physical = false,
            };
            let p = plan(&c, &h);
            if !(3..6).contains(&case) {
                assert!(p.changes.is_empty(), "case {case}");
            }
            assert!(!p.dns_live);
        }
    }
    #[test]
    fn ipv6_not_disabled_and_remote_no_reconnect() {
        let (c, mut h) = fixture();
        h.capabilities.remote_session = true;
        for method in ["auto", "dhcp", "disabled", "manual", "ignore"] {
            h.connections[0]
                .settings
                .insert("ipv6.method".into(), method.into());
            let p = plan(&c, &h);
            assert!(!p.reconnect);
            assert!(!p.changes.iter().any(|x| x.after == "disabled"));
            if method == "disabled" {
                assert!(!p
                    .changes
                    .iter()
                    .any(|x| matches!(&x.target,Target::Nm{key,..} if key=="ipv6.ip6-privacy")));
            }
        }
    }
    #[test]
    fn observe_has_no_mutations() {
        let (mut c, h) = fixture();
        c.general.profile = Profile::Observe;
        assert!(plan(&c, &h).changes.is_empty());
    }
    #[test]
    fn missing_dot_property_skips_dns() {
        let (c, mut h) = fixture();
        h.connections[0].settings.remove("connection.dns-over-tls");
        assert!(!plan(&c, &h).dns_live);
    }
    #[test]
    fn ethernet_preserved_by_default() {
        let (c, mut h) = fixture();
        h.connections[0].kind = "802-3-ethernet".into();
        let p = plan(&c, &h);
        assert!(!p.changes.iter().any(|x| x.after == "random"));
    }
}
