pub mod config;
pub mod model;
pub mod planner;
pub mod transaction;
pub use config::*;
pub use model::*;
pub use planner::*;
pub use transaction::*;

pub const SCHEMA_VERSION: u32 = 1;
pub const PRIVACY_LIMITS: &str = "MAC privacy is local-link only; public IP is unchanged. Encrypted system DNS is not a VPN. ISP metadata, resolver query visibility, application DoH, accounts and browser fingerprints remain outside this protection. IPv6 privacy does not hide routing information. Stopping the daemon does not restore persistent settings.";

pub fn valid_interface(value: &str) -> bool {
    !value.is_empty()
        && value.len() < 16
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        && !value.starts_with('-')
}

pub fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

pub fn local_mac(mut entropy: [u8; 6]) -> String {
    entropy[0] = (entropy[0] | 2) & 0xfe;
    entropy
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn excluded(name: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| match p.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == p,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mac_invariants() {
        let mut seen = std::collections::BTreeSet::new();
        for i in 0u32..10000 {
            let b = i.to_le_bytes();
            let m = local_mac([b[3], b[0], b[1], b[2], 0, 0]);
            let first = u8::from_str_radix(&m[..2], 16).unwrap();
            assert_eq!(first & 3, 2);
            assert_ne!(m, "00:00:00:00:00:00");
            assert_ne!(m, "ff:ff:ff:ff:ff:ff");
            assert!(seen.insert(m));
        }
    }
    #[test]
    fn arguments_are_data_not_commands() {
        for bad in ["--help", "eth0;id", "$(id)", "../../etc/passwd", "a\nb", ""] {
            assert!(!valid_interface(bad));
        }
        assert!(valid_interface("wlan0"));
        assert!(!valid_uuid("--help"));
        assert!(valid_uuid("01234567-89ab-cdef-0123-456789abcdef"));
    }
}
