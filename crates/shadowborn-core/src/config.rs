use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub server: Server,
    pub security: Security,
    pub dns: Dns,
    pub privacy: Privacy,
    pub operations: Operations,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub interface: String,
    pub listen_port: u16,
    pub endpoint: IpAddr,
    pub tunnel_ipv4: String,
    pub wan_interface: String,
    pub admin_ipv4: String,
    pub ssh_port: u16,
    #[serde(default)]
    pub profile: Profile,
    pub ipv6: Ipv6Mode,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    #[default]
    Baseline,
    Hardened,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Ipv6Mode {
    Blocked,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Security {
    pub peer_isolation: bool,
    pub restrict_peer_lan_access: bool,
    pub psk_per_peer: bool,
    pub public_management_api: bool,
    pub firewall_default_deny: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    pub mode: String,
    pub bind_to_vpn_only: bool,
    pub upstream: String,
    pub query_logging: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Privacy {
    pub no_activity_logs: bool,
    pub telemetry: bool,
    pub store_peer_activity: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Operations {
    pub auto_apply_on_install: bool,
    pub require_confirm: bool,
    pub transactional_rollback: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V4Prefix {
    pub address: Ipv4Addr,
    pub bits: u8,
}
impl V4Prefix {
    pub fn parse(value: &str) -> Result<Self> {
        let (address, bits) = value
            .split_once('/')
            .context("IPv4 prefix requires /length")?;
        let result = Self {
            address: address.parse().context("invalid IPv4 address")?,
            bits: bits.parse().context("invalid prefix length")?,
        };
        if result.bits > 32 {
            bail!("invalid IPv4 prefix length")
        }
        Ok(result)
    }
    pub fn network(self) -> u32 {
        u32::from(self.address) & self.mask()
    }
    pub fn mask(self) -> u32 {
        u32::MAX.checked_shl(u32::from(32 - self.bits)).unwrap_or(0)
    }
    pub fn broadcast(self) -> u32 {
        self.network() | !self.mask()
    }
    pub fn contains(self, address: Ipv4Addr) -> bool {
        u32::from(address) & self.mask() == self.network()
    }
    pub fn cidr(self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.network()), self.bits)
    }
}
pub fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
pub fn valid_interface(value: &str) -> bool {
    valid_name(value) && value.len() <= 15 && value != "lo" && value != "auto-detect"
}
impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        // Do not reflect unknown input values into error output.
        let config: Self = toml::from_str(text).map_err(|_| {
            anyhow::anyhow!("invalid server TOML schema (unknown fields are rejected)")
        })?;
        config.validate()?;
        Ok(config)
    }
    pub fn prefix(&self) -> Result<V4Prefix> {
        V4Prefix::parse(&self.server.tunnel_ipv4)
    }
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            bail!("unsupported schema version")
        }
        let s = &self.server;
        if !valid_interface(&s.interface)
            || !valid_interface(&s.wan_interface)
            || s.interface == s.wan_interface
        {
            bail!("explicit, distinct, valid tunnel and WAN interfaces required")
        }
        if s.listen_port == 0 || s.ssh_port == 0 {
            bail!("ports must be nonzero")
        }
        let IpAddr::V4(endpoint) = s.endpoint else {
            bail!("IPv6 endpoint bootstrap is not yet supported")
        };
        if endpoint.is_unspecified()
            || endpoint.is_loopback()
            || endpoint.is_multicast()
            || endpoint.is_link_local()
            || endpoint.is_broadcast()
            || endpoint.is_private()
        {
            bail!("pinned public IPv4 endpoint required")
        }
        let p = self.prefix()?;
        if !(16..=30).contains(&p.bits)
            || !p.address.is_private()
            || !Ipv4Addr::from(p.network()).is_private()
            || !Ipv4Addr::from(p.broadcast()).is_private()
            || u32::from(p.address) == p.network()
            || u32::from(p.address) == p.broadcast()
        {
            bail!("tunnel needs a usable RFC1918 host address with /16 through /30")
        }
        let admin = V4Prefix::parse(&s.admin_ipv4)?;
        if admin.bits < 8
            || u32::from(admin.address) != admin.network()
            || admin.address.is_unspecified()
            || admin.address.is_loopback()
            || admin.address.is_multicast()
            || p.contains(admin.address)
            || admin.contains(p.address)
        {
            bail!("explicit, canonical, nonoverlapping admin IPv4 CIDR required (/8 or narrower)")
        }
        let sec = &self.security;
        if !sec.peer_isolation
            || !sec.restrict_peer_lan_access
            || !sec.psk_per_peer
            || sec.public_management_api
            || !sec.firewall_default_deny
        {
            bail!("mandatory server security policy cannot be relaxed")
        }
        if self.dns.mode != "vpn-resolver"
            || !self.dns.bind_to_vpn_only
            || self.dns.upstream != "quad9-dot"
            || self.dns.query_logging
        {
            bail!("only VPN-scoped Quad9 DoT without query logging is supported")
        }
        if !self.privacy.no_activity_logs
            || self.privacy.telemetry
            || self.privacy.store_peer_activity
        {
            bail!("activity logging and telemetry are forbidden")
        }
        if self.operations.auto_apply_on_install
            || !self.operations.require_confirm
            || !self.operations.transactional_rollback
        {
            bail!("explicit approval and rollback policy required")
        }
        Ok(())
    }
}
