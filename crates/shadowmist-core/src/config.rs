use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    Observe,
    #[default]
    Balanced,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum MacPolicy {
    #[default]
    Random,
    StableSsid,
    Preserve,
}
impl MacPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Random => "random",
            Self::StableSsid => "stable-ssid",
            Self::Preserve => "preserve",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub general: General,
    pub identity: Identity,
    pub dns: Dns,
    pub ipv6: Ipv6,
    pub network_audit: NetworkAudit,
    pub logging: Logging,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: 1,
            general: General::default(),
            identity: Identity::default(),
            dns: Dns::default(),
            ipv6: Ipv6::default(),
            network_audit: NetworkAudit::default(),
            logging: Logging::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct General {
    pub profile: Profile,
    pub check_on_connect: bool,
    pub network_scan: String,
    pub enrolled_profiles: Vec<String>,
    pub reconcile_seconds: u64,
}
impl Default for General {
    fn default() -> Self {
        Self {
            profile: Profile::Balanced,
            check_on_connect: true,
            network_scan: "passive".into(),
            enrolled_profiles: vec![],
            reconcile_seconds: 120,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Identity {
    pub wifi_mac: MacPolicy,
    pub wifi_scan_randomization: bool,
    pub ethernet_mac: MacPolicy,
    pub rotate_on_daemon_start: bool,
    pub rotate_active_connections: bool,
    pub exclude_interfaces: Vec<String>,
}
impl Default for Identity {
    fn default() -> Self {
        Self {
            wifi_mac: MacPolicy::Random,
            wifi_scan_randomization: true,
            ethernet_mac: MacPolicy::Preserve,
            rotate_on_daemon_start: false,
            rotate_active_connections: false,
            exclude_interfaces: ["lo", "docker*", "veth*", "br-*", "tun*", "wg*"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dns {
    pub enabled: bool,
    pub provider: String,
    pub transport: String,
    pub verify_effective_state: bool,
    pub balanced_restore_on_failure: bool,
    pub custom_servers: Vec<String>,
    pub health_domains: Vec<String>,
    pub health_timeout_seconds: u64,
}
impl Default for Dns {
    fn default() -> Self {
        Self {
            enabled: true,
            provider: "quad9".into(),
            transport: "dot".into(),
            verify_effective_state: true,
            balanced_restore_on_failure: true,
            custom_servers: vec![],
            health_domains: vec![],
            health_timeout_seconds: 8,
        }
    }
}
impl Dns {
    pub fn servers(&self) -> Vec<String> {
        match self.provider.as_str() {
            "quad9" => [
                "9.9.9.9#dns.quad9.net",
                "149.112.112.112#dns.quad9.net",
                "2620:fe::fe#dns.quad9.net",
                "2620:fe::9#dns.quad9.net",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            "cloudflare" => [
                "1.1.1.1#cloudflare-dns.com",
                "1.0.0.1#cloudflare-dns.com",
                "2606:4700:4700::1111#cloudflare-dns.com",
                "2606:4700:4700::1001#cloudflare-dns.com",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            _ => self.custom_servers.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ipv6 {
    pub enabled: bool,
    pub privacy_addresses: String,
}
impl Default for Ipv6 {
    fn default() -> Self {
        Self {
            enabled: true,
            privacy_addresses: "prefer-temporary".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkAudit {
    pub include_listening_ports: bool,
    pub check_gateway_changes: bool,
    pub check_wifi_security: bool,
}
impl Default for NetworkAudit {
    fn default() -> Self {
        Self {
            include_listening_ports: true,
            check_gateway_changes: true,
            check_wifi_security: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Logging {
    pub level: String,
    pub redact_sensitive_values: bool,
}
impl Default for Logging {
    fn default() -> Self {
        Self {
            level: "info".into(),
            redact_sensitive_values: true,
        }
    }
}

pub fn valid_domain(s: &str) -> bool {
    s.contains('.') && valid_search_domain(s)
}
pub fn valid_search_domain(s: &str) -> bool {
    s.len() <= 253
        && !s.ends_with('.')
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
impl Config {
    pub fn parse(s: &str) -> Result<Self> {
        let c: Self = toml::from_str(s)?;
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            bail!("unsupported config schema_version (expected 1); migrate explicitly")
        }
        if self.general.profile == Profile::Strict {
            bail!("strict mode is unsupported until phase 2 namespace/VM release gates pass")
        }
        if self.general.network_scan != "passive" {
            bail!("only passive local assessment is supported")
        }
        if !(15..=3600).contains(&self.general.reconcile_seconds) {
            bail!("reconcile_seconds must be 15..3600")
        }
        if self
            .general
            .enrolled_profiles
            .iter()
            .any(|s| !crate::valid_uuid(s))
        {
            bail!("enrolled_profiles must contain NetworkManager UUIDs")
        }
        if self.identity.rotate_on_daemon_start || self.identity.rotate_active_connections {
            bail!("automatic rotation is unsupported; use explicit identity rotate --reconnect")
        }
        if self.identity.ethernet_mac == MacPolicy::StableSsid {
            bail!("stable-ssid applies only to Wi-Fi")
        }
        if self.identity.exclude_interfaces.iter().any(|p| {
            p.is_empty()
                || p.trim_end_matches('*').contains('*')
                || p.contains('/')
                || p.contains('\n')
        }) {
            bail!("exclusion supports literal interfaces or trailing * only")
        }
        if self.dns.transport != "dot"
            || !["quad9", "cloudflare", "custom"].contains(&self.dns.provider.as_str())
        {
            bail!("supported DNS: authenticated dot with quad9, cloudflare or custom")
        }
        if !self.dns.verify_effective_state || !self.dns.balanced_restore_on_failure {
            bail!("MVP requires DNS verification and balanced rollback")
        }
        if self.dns.provider != "custom" && !self.dns.custom_servers.is_empty() {
            bail!("custom_servers requires provider=custom")
        }
        if self.dns.servers().is_empty() {
            bail!("DNS servers cannot be empty")
        }
        for server in self.dns.servers() {
            let Some((ip, name)) = server.split_once('#') else {
                bail!("each DNS server requires IP#certificate-hostname")
            };
            if ip.parse::<IpAddr>().is_err() || !valid_domain(name) {
                bail!("invalid authenticated DNS endpoint")
            }
        }
        if self.dns.health_domains.iter().any(|d| !valid_domain(d)) {
            bail!("health_domains must be DNS hostnames, not URLs/options")
        }
        if self.dns.health_domains.len() == 1 || self.dns.health_domains.len() > 4 {
            bail!("configure two to four independent health_domains or leave empty to disable DNS changes")
        }
        if !(2..=15).contains(&self.dns.health_timeout_seconds) {
            bail!("health_timeout_seconds must be 2..15")
        }
        if !self.ipv6.enabled
            || !["prefer-temporary", "preserve"].contains(&self.ipv6.privacy_addresses.as_str())
        {
            bail!("MVP preserves IPv6; privacy_addresses must be prefer-temporary or preserve")
        }
        if !["error", "warn", "info", "debug"].contains(&self.logging.level.as_str()) {
            bail!("invalid logging level")
        }
        if !self.logging.redact_sensitive_values {
            bail!("persistent sensitive logging is unsupported; use console --verbose")
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn search_domain_consent_accepts_literal_names_only() {
        assert!(valid_search_domain("home"));
        assert!(valid_search_domain("lab.example"));
        assert!(!valid_domain("home"));
        for domain in [
            "",
            "*",
            "*.home",
            "~home",
            "~.",
            "home.",
            "--all",
            "home corp",
            "home;id",
            "../home",
        ] {
            assert!(!valid_search_domain(domain), "{domain}");
        }
    }
    #[test]
    fn config_validation() {
        Config::parse("").unwrap();
        for bad in [
            "schema_version=2",
            "oops=true",
            "[dns]\nunknown=1",
            "[identity]\nrotate_on_daemon_start=true",
            "[general]\nprofile='strict'",
            "[dns]\ntransport='opportunistic'",
            "[dns]\nhealth_domains=['example.com']",
            "[ipv6]\nenabled=false",
            "[general]\nnetwork_scan='active'",
            "broken = [",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad}");
        }
        assert!(
            Config::parse("[dns]\nprovider='custom'\ncustom_servers=['1.1.1.1#bad;id']").is_err()
        );
        let c = Config::parse("[dns]\nhealth_domains=['example.com','example.net']").unwrap();
        assert_eq!(c.dns.servers().len(), 4);
        assert_eq!(
            Config::parse(&toml::to_string(&c).unwrap())
                .unwrap()
                .schema_version,
            1
        );
    }
}
