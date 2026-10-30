use crate::{valid_name, Config};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt, net::Ipv4Addr};

/// Intentionally has no Display implementation; Debug is always redacted.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Secret(String);
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}
impl Secret {
    pub fn new(value: String) -> Result<Self> {
        validate_key(&value)?;
        Ok(Self(value))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}
pub fn validate_key(value: &str) -> Result<()> {
    let b = value.as_bytes();
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if b.len() != 44
        || b[43] != b'='
        || !b[..43].iter().all(|c| ALPHABET.contains(c))
        || ALPHABET
            .iter()
            .position(|c| *c == b[42])
            .is_none_or(|n| n % 4 != 0)
        || b[..43].iter().all(|c| *c == b'A')
    {
        bail!("invalid nonzero canonical WireGuard key")
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PeerStatus {
    Active,
    Disabled,
    Revoked,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub name: String,
    pub public_key: String,
    pub address: Ipv4Addr,
    pub status: PeerStatus,
    pub psk: Option<Secret>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub schema_version: u32,
    pub config: Config,
    pub server_private_key: Secret,
    pub server_public_key: String,
    pub peers: Vec<Peer>,
}
impl State {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            bail!("unsupported state schema")
        }
        self.config.validate()?;
        validate_key(self.server_private_key.expose())?;
        validate_key(&self.server_public_key)?;
        let p = self.config.prefix()?;
        let mut names = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        for peer in &self.peers {
            if !valid_name(&peer.name)
                || !names.insert(&peer.name)
                || !keys.insert(&peer.public_key)
                || !addresses.insert(peer.address)
            {
                bail!("duplicate or invalid peer identity/address")
            }
            validate_key(&peer.public_key)?;
            if peer.public_key == self.server_public_key {
                bail!("server key cannot be enrolled as a client")
            }
            if !p.contains(peer.address)
                || peer.address == p.address
                || [p.network(), p.broadcast()].contains(&u32::from(peer.address))
            {
                bail!("invalid peer tunnel address")
            }
            match (&peer.psk, peer.status) {
                (Some(psk), PeerStatus::Active | PeerStatus::Disabled) => {
                    validate_key(psk.expose())?
                }
                (None, PeerStatus::Revoked) => {}
                _ => bail!("active/disabled peers require PSK; revoked peers retain no PSK"),
            }
        }
        Ok(())
    }
    pub fn add(&mut self, name: String, public_key: String, psk: Secret) -> Result<()> {
        self.validate()?;
        if !valid_name(&name)
            || self
                .peers
                .iter()
                .any(|p| p.name == name || p.public_key == public_key)
            || public_key == self.server_public_key
        {
            bail!("invalid or duplicate peer identity (revoked identities remain reserved)")
        }
        validate_key(&public_key)?;
        let prefix = self.config.prefix()?;
        let used: BTreeSet<_> = self
            .peers
            .iter()
            .map(|p| u32::from(p.address))
            .chain([u32::from(prefix.address)])
            .collect();
        let address = (prefix.network() + 1..prefix.broadcast())
            .find(|a| !used.contains(a))
            .context("tunnel address pool exhausted")?;
        self.peers.push(Peer {
            name,
            public_key,
            address: address.into(),
            status: PeerStatus::Active,
            psk: Some(psk),
        });
        self.validate()
    }
    pub fn peer(&self, name: &str) -> Result<&Peer> {
        self.peers
            .iter()
            .find(|p| p.name == name)
            .context("peer not found")
    }
    pub fn disable(&mut self, name: &str, revoke: bool) -> Result<()> {
        let p = self
            .peers
            .iter_mut()
            .find(|p| p.name == name)
            .context("peer not found")?;
        if revoke {
            p.status = PeerStatus::Revoked;
            p.psk = None;
        } else if p.status != PeerStatus::Revoked {
            p.status = PeerStatus::Disabled;
        }
        Ok(())
    }
    /// Preserve local revocation tombstones across restore. Never resurrect a key.
    pub fn restore_authorization(&self, mut backup: Self) -> Result<Self> {
        self.validate()?;
        backup.validate()?;
        if self.config != backup.config
            || self.server_public_key != backup.server_public_key
            || self.server_private_key != backup.server_private_key
        {
            bail!("backup belongs to a different gateway configuration/key")
        }
        for current in &self.peers {
            if current.status == PeerStatus::Active {
                continue;
            }
            if let Some(old) = backup
                .peers
                .iter_mut()
                .find(|p| p.public_key == current.public_key)
            {
                old.status = current.status;
                if current.status == PeerStatus::Revoked {
                    old.psk = None;
                }
            } else {
                backup.peers.push(current.clone());
            }
        }
        backup.validate()?;
        Ok(backup)
    }
}
