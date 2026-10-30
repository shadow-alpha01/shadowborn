use crate::*;
use anyhow::{bail, Context, Result};
use shadowmist_core::*;
use std::{collections::BTreeMap, time::Duration};

pub const NM_KEYS: &[&str] = &[
    "802-11-wireless.cloned-mac-address",
    "802-3-ethernet.cloned-mac-address",
    "802-11-wireless.generate-mac-address-mask",
    "802-3-ethernet.generate-mac-address-mask",
    "ipv6.addr-gen-mode",
    "ipv6.ip6-privacy",
    "ipv6.method",
    "ipv4.method",
    "connection.dns-over-tls",
    "ipv4.dns",
    "ipv6.dns",
    "ipv4.ignore-auto-dns",
    "ipv6.ignore-auto-dns",
    "ipv4.dns-search",
    "ipv6.dns-search",
    "ipv4.dhcp-client-id",
    "ipv6.dhcp-duid",
    "802-1x.eap",
    "802-11-wireless-security.key-mgmt",
];
pub fn canonical(key: &str, value: &str) -> String {
    let v = value.trim();
    if v == "--" {
        return String::new();
    }
    if key.ends_with("dns") && !key.contains("ignore-auto") {
        return v
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(",");
    }
    match key {
        "ipv6.addr-gen-mode" => match v.split_whitespace().next().unwrap_or("") {
            "0" => "eui64".into(),
            "1" => "stable-privacy".into(),
            "2" => "default-or-eui64".into(),
            "3" => "default".into(),
            _ => v.into(),
        },
        "ipv6.ip6-privacy" => v.split_whitespace().next().unwrap_or("").into(),
        "connection.dns-over-tls" => match v.split_whitespace().next().unwrap_or("") {
            "-1" => "default".into(),
            "0" => "no".into(),
            "1" => "opportunistic".into(),
            "2" => "yes".into(),
            _ => v.into(),
        },
        _ => v.into(),
    }
}
pub fn read_nm(uuid: &str, key: &str) -> Result<String> {
    if !valid_uuid(uuid) || !NM_KEYS.contains(&key) {
        bail!("invalid NetworkManager target")
    }
    Ok(canonical(
        key,
        &query(
            "nmcli",
            &[
                "--escape",
                "no",
                "--get-values",
                key,
                "connection",
                "show",
                "uuid",
                uuid,
            ],
        )?,
    ))
}
pub fn resolved_value(interface: &str, key: &str) -> Result<String> {
    if !valid_interface(interface) || !["dns", "domain", "dnsovertls"].contains(&key) {
        bail!("invalid resolved target")
    }
    let out = query("resolvectl", &[key, interface])?;
    let value = out
        .lines()
        .next()
        .and_then(|s| s.split_once(": ").map(|(_, v)| v))
        .unwrap_or("")
        .trim();
    // '--' is resolvectl's display marker for an empty list.
    Ok(if value == "--" {
        String::new()
    } else {
        value.to_string()
    })
}
pub fn live_dns(interface: &str) -> Result<BTreeMap<String, String>> {
    ["dns", "domain", "dnsovertls"]
        .iter()
        .map(|key| Ok((key.to_string(), resolved_value(interface, key)?)))
        .collect()
}
pub struct LinuxAdapter {
    pub config: Config,
    pub dns_interface: Option<String>,
    pub require_dns_health: bool,
}
impl LinuxAdapter {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            dns_interface: None,
            require_dns_health: false,
        }
    }
}
impl Adapter for LinuxAdapter {
    fn read(&mut self, target: &Target) -> Result<String> {
        match target {
            Target::Nm { uuid, key } => read_nm(uuid, key),
            Target::Resolved {
                interface,
                key,
                uuid,
            } => {
                ensure_link_profile(interface, uuid)?;
                resolved_value(interface, key)
            }
        }
    }
    fn write(&mut self, target: &Target, value: &str) -> Result<()> {
        require_root()?;
        if value.contains('\0') || value.contains('\n') {
            bail!("invalid setting value")
        }
        match target {
            Target::Nm { uuid, key } => {
                if !valid_uuid(uuid) || !NM_KEYS.contains(&key.as_str()) {
                    bail!("invalid NM target")
                }
                run(
                    "nmcli",
                    &[
                        "--wait",
                        "10",
                        "connection",
                        "modify",
                        "uuid",
                        uuid,
                        key,
                        value,
                    ],
                    Duration::from_secs(12),
                )?;
            }
            Target::Resolved {
                interface,
                key,
                uuid,
            } => {
                ensure_link_profile(interface, uuid)?;
                if !valid_interface(interface)
                    || !["dns", "domain", "dnsovertls"].contains(&key.as_str())
                {
                    bail!("invalid resolved target")
                }
                let mut args = vec![key.as_str(), interface.as_str()];
                let values: Vec<_> = value.split_whitespace().collect();
                if values.is_empty() {
                    args.push("");
                } else {
                    args.extend(values);
                }
                query("resolvectl", &args)?;
            }
        }
        Ok(())
    }
    fn health(&mut self) -> Result<()> {
        if !self.require_dns_health {
            return Ok(());
        }
        let interface = self
            .dns_interface
            .as_ref()
            .context("DNS interface missing")?;
        verify_dns(&self.config, interface, true)?;
        Ok(())
    }
}
pub fn verify_dns(config: &Config, interface: &str, probe: bool) -> Result<bool> {
    let live = live_dns(interface)?;
    validate_effective_dns(config, &live)?;
    if !probe {
        return Ok(false);
    }
    verify_approved_lookups(config)?;
    if live_dns(interface)? != live {
        bail!("resolved configuration changed during health verification")
    }
    Ok(true)
}
pub fn validate_effective_dns(config: &Config, live: &BTreeMap<String, String>) -> Result<()> {
    if live.get("dnsovertls").map(String::as_str) != Some("yes") {
        bail!("resolved does not require authenticated DoT")
    }
    if live.get("domain").map(String::as_str) != Some("~.") {
        bail!("resolved root-domain routing is not selected")
    }
    let effective: std::collections::BTreeSet<_> = live
        .get("dns")
        .context("missing DNS state")?
        .split_whitespace()
        .map(str::to_string)
        .collect();
    let expected: std::collections::BTreeSet<_> = config.dns.servers().into_iter().collect();
    if effective.is_empty() || !effective.is_subset(&expected) {
        bail!("effective DNS differs from the selected authenticated resolver")
    }
    Ok(())
}
fn verify_approved_lookups(config: &Config) -> Result<()> {
    if config.dns.health_domains.len() < 2 {
        bail!("no approved independent health domains")
    }
    let mut successes = 0;
    // --cache=no forces actual upstream resolution; DNSSEC 'authenticated' is not used as TLS evidence.
    for domain in &config.dns.health_domains {
        if run(
            "resolvectl",
            &[
                "--cache=no",
                "--protocol=dns",
                "--search=no",
                "--type=A",
                "query",
                domain,
            ],
            Duration::from_secs(config.dns.health_timeout_seconds),
        )
        .is_ok()
        {
            successes += 1;
        }
    }
    if successes == 0 {
        bail!("DNS resolution failed for all approved domains; provider/853/TLS/endpoint failure (portal not proven)")
    }
    Ok(())
}

fn ensure_link_profile(interface: &str, uuid: &str) -> Result<()> {
    if !valid_interface(interface) || !valid_uuid(uuid) {
        bail!("invalid link provenance")
    }
    let current = query(
        "nmcli",
        &[
            "--escape",
            "no",
            "-g",
            "GENERAL.CON-UUID",
            "device",
            "show",
            interface,
        ],
    )?;
    if current != uuid {
        bail!("link profile changed; resolved restore conflict preserves the new connection")
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_requires_tls_hostname_and_selection() {
        let config = Config::default();
        let valid: BTreeMap<String, String> = [
            ("dns".into(), "9.9.9.9#dns.quad9.net".into()),
            ("domain".into(), "~.".into()),
            ("dnsovertls".into(), "yes".into()),
        ]
        .into();
        validate_effective_dns(&config, &valid).unwrap();
        for (key, value) in [
            ("dnsovertls", "opportunistic"),
            ("dnsovertls", "no"),
            ("domain", "~corp.example"),
            ("dns", "9.9.9.9"),
            ("dns", "9.9.9.9#wrong.example"),
            ("dns", "9.9.9.9#dns.quad9.net 192.0.2.1"),
            ("dns", ""),
        ] {
            let mut live = valid.clone();
            live.insert(key.into(), value.into());
            assert!(
                validate_effective_dns(&config, &live).is_err(),
                "{key}={value}"
            );
        }
    }
    #[test]
    fn ipv6_resolver_must_also_be_approved() {
        let config = Config::default();
        let mut live: BTreeMap<String, String> = [
            ("dns".into(), "2620:fe::fe#dns.quad9.net".into()),
            ("domain".into(), "~.".into()),
            ("dnsovertls".into(), "yes".into()),
        ]
        .into();
        assert!(validate_effective_dns(&config, &live).is_ok());
        live.insert(
            "dns".into(),
            "2620:fe::fe#dns.quad9.net 2001:db8::53".into(),
        );
        assert!(validate_effective_dns(&config, &live).is_err());
    }
    #[test]
    fn canonical_nm_values() {
        assert_eq!(canonical("connection.dns-over-tls", "2 (yes)"), "yes");
        assert_eq!(
            canonical("ipv6.ip6-privacy", "2 (enabled, prefer temporary IP)"),
            "2"
        );
        assert_eq!(
            canonical(
                "ipv4.dns",
                "9.9.9.9#dns.quad9.net, 149.112.112.112#dns.quad9.net"
            ),
            "9.9.9.9#dns.quad9.net,149.112.112.112#dns.quad9.net"
        );
    }
    #[test]
    fn reject_targets_before_invocation() {
        assert!(read_nm("--help", "ipv4.dns").is_err());
        assert!(read_nm(
            "01234567-89ab-cdef-0123-456789abcdef",
            "802-11-wireless-security.psk"
        )
        .is_err());
        assert!(resolved_value("a;id", "dns").is_err());
    }
}
