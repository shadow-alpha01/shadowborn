use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    pub systemd: bool,
    pub root: bool,
    pub container: bool,
    pub writable: bool,
    pub nm_active: bool,
    pub nm_version: Option<String>,
    pub nm_dot_supported: bool,
    pub nm_stable_ssid_supported: bool,
    pub resolved_active: bool,
    #[serde(default)]
    pub resolved_dbus_available: bool,
    #[serde(default)]
    pub resolved_upstream_configured: Option<bool>,
    pub resolved_version: Option<String>,
    pub resolver_owner: String,
    pub nm_dns_plugin: String,
    pub remote_session: bool,
    pub checkpoint_supported: bool,
    pub nft_available: bool,
    pub dns_blockers: Vec<String>,
    pub errors: Vec<String>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub kind: String,
    pub state: String,
    pub profile_uuid: Option<String>,
    pub effective_mac: Option<String>,
    pub permanent_mac: Option<String>,
    pub physical: bool,
    pub addresses: Vec<String>,
    pub wifi_security: Option<String>,
    pub scan_randomization: String,
    pub excluded: bool,
    pub configured_mac_policy: Option<String>,
    pub mac_differs_from_permanent: Option<bool>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Connection {
    pub uuid: String,
    pub kind: String,
    pub interface: String,
    pub active: bool,
    pub physical: bool,
    pub enterprise: bool,
    pub settings: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Host {
    pub capabilities: Capabilities,
    pub interfaces: Vec<Interface>,
    pub connections: Vec<Connection>,
    pub routes: Vec<String>,
    pub listeners: Vec<String>,
    pub plaintext_dns_peers: Vec<String>,
    pub dns_links: BTreeMap<String, BTreeMap<String, String>>,
    pub connectivity: String,
    pub firewall: String,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Info,
    Warn,
    High,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub code: String,
    pub severity: Severity,
    pub evidence: String,
    pub mitigation: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Protection {
    Observe,
    Unprotected,
    Configured,
    Verified,
    Uncertain,
    Degraded,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsReport {
    pub state: Protection,
    pub scope: String,
    pub reason: String,
    pub enforced: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub timestamp: u64,
    pub profile: crate::Profile,
    pub state: Protection,
    pub dns: DnsReport,
    pub capabilities: Capabilities,
    pub interfaces: Vec<Interface>,
    pub findings: Vec<Finding>,
    pub limitations: String,
    pub redacted: bool,
}
impl Report {
    pub fn redacted(mut self) -> Self {
        self.redacted = true;
        for i in &mut self.interfaces {
            i.effective_mac = None;
            i.permanent_mac = None;
            i.addresses.clear();
            i.profile_uuid = None;
        }
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "adapter", rename_all = "snake_case")]
pub enum Target {
    Nm {
        uuid: String,
        key: String,
    },
    Resolved {
        interface: String,
        key: String,
        uuid: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Change {
    pub target: Target,
    pub before: String,
    pub after: String,
    pub reason: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Plan {
    pub changes: Vec<Change>,
    pub warnings: Vec<String>,
    pub dns_live: bool,
    pub reconnect: bool,
}

pub fn timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
