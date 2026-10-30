use crate::query;
use anyhow::{Context, Result};
use std::{fs, net::IpAddr, path::Path};

/// Read the bus owner without activating or restarting the resolver service.
/// A running service and a working resolvectl/Varlink socket do not prove that
/// NetworkManager can reach resolved's D-Bus configuration API.
pub fn resolved_dbus_available() -> Result<bool> {
    let output = query(
        "busctl",
        &[
            "--system",
            "--timeout=2",
            "--json=short",
            "call",
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "NameHasOwner",
            "s",
            "org.freedesktop.resolve1",
        ],
    )?;
    parse_bus_owner(&output)
}

fn parse_bus_owner(output: &str) -> Result<bool> {
    let value: serde_json::Value = serde_json::from_str(output)?;
    value
        .get("data")
        .and_then(|v| v.as_bool().or_else(|| v.as_array()?.first()?.as_bool()))
        .context("D-Bus owner query returned an unexpected value")
}

pub fn resolver_owner() -> String {
    let target = fs::canonicalize("/etc/resolv.conf").ok();
    let contents = fs::read_to_string("/etc/resolv.conf").ok();
    classify_resolver(target.as_deref(), contents.as_deref()).into()
}

pub fn classify_resolver(target: Option<&Path>, contents: Option<&str>) -> &'static str {
    match target {
        Some(p) if p == Path::new("/run/systemd/resolve/resolv.conf") => {
            "systemd-resolved-uplink-bypasses-stub"
        }
        Some(p) if p == Path::new("/run/systemd/resolve/stub-resolv.conf") => {
            let Some(contents) = contents else {
                return "systemd-resolved-stub-invalid";
            };
            let mut count = 0;
            let mut bypass = false;
            for line in contents.lines() {
                let line = line.split(['#', ';']).next().unwrap_or("");
                let mut fields = line.split_whitespace();
                if fields.next() != Some("nameserver") {
                    continue;
                }
                let Some(address) = fields.next().and_then(|v| v.parse::<IpAddr>().ok()) else {
                    return "systemd-resolved-stub-invalid";
                };
                if fields.next().is_some() {
                    return "systemd-resolved-stub-invalid";
                }
                count += 1;
                bypass |= address != IpAddr::from([127, 0, 0, 53]);
            }
            if count == 0 {
                "systemd-resolved-stub-invalid"
            } else if bypass {
                "systemd-resolved-stub-bypassed"
            } else {
                "systemd-resolved-stub"
            }
        }
        _ => "other/unknown",
    }
}

/// Presence of explicit global/per-link servers, not a resolution health test.
/// Compiled-in fallback servers are outside `resolvectl dns` output.
pub fn configured_dns_present(output: &str) -> Option<bool> {
    let mut seen = false;
    let mut configured = false;
    for line in output.lines() {
        let Some((label, value)) = line.split_once(':') else {
            continue;
        };
        if label != "Global" && !label.starts_with("Link ") {
            continue;
        }
        seen = true;
        configured |= value.split_whitespace().any(|v| v != "--");
    }
    seen.then_some(configured)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn stub(contents: Option<&str>) -> &'static str {
        classify_resolver(
            Some(Path::new("/run/systemd/resolve/stub-resolv.conf")),
            contents,
        )
    }
    #[test]
    fn clean_stub_is_recognized() {
        assert_eq!(
            stub(Some(
                "# generated\nnameserver\t127.0.0.53 # local\noptions edns0 trust-ad\n"
            )),
            "systemd-resolved-stub"
        );
    }
    #[test]
    fn mixed_stub_is_a_bypass_regardless_of_order_or_family() {
        for contents in [
            "nameserver 1.1.1.1\nnameserver 127.0.0.53\n",
            "nameserver 127.0.0.53\nnameserver 9.9.9.9\n",
            "nameserver 127.0.0.53\nnameserver 2001:db8::53\n",
        ] {
            assert_eq!(stub(Some(contents)), "systemd-resolved-stub-bypassed");
        }
    }
    #[test]
    fn missing_or_malformed_stub_cannot_be_verified() {
        for contents in [
            None,
            Some("# empty"),
            Some("nameserver invalid"),
            Some("nameserver"),
            Some("nameserver 127.0.0.53 extra"),
        ] {
            assert_eq!(stub(contents), "systemd-resolved-stub-invalid");
        }
    }
    #[test]
    fn other_managers_and_uplink_are_distinct() {
        assert_eq!(
            classify_resolver(None, Some("nameserver 127.0.0.53")),
            "other/unknown"
        );
        assert_eq!(
            classify_resolver(
                Some(Path::new("/run/systemd/resolve/resolv.conf")),
                Some("nameserver 1.1.1.1")
            ),
            "systemd-resolved-uplink-bypasses-stub"
        );
    }
    #[test]
    fn absent_bus_owner_is_not_service_health() {
        assert!(!parse_bus_owner(r#"{"type":"b","data":[false]}"#).unwrap());
        assert!(parse_bus_owner(r#"{"type":"b","data":[true]}"#).unwrap());
        assert!(parse_bus_owner(r#"{"type":"b","data":true}"#).unwrap());
        assert!(parse_bus_owner(r#"{"type":"s","data":"true"}"#).is_err());
    }
    #[test]
    fn upstream_inventory_distinguishes_empty_unknown_and_configured() {
        assert_eq!(
            configured_dns_present("Global:\nLink 2 (wlan0):\nLink 3 (docker0): --"),
            Some(false)
        );
        assert_eq!(
            configured_dns_present("Global:\nLink 2 (wlan0): 192.0.2.53"),
            Some(true)
        );
        assert_eq!(
            configured_dns_present("Global: 2001:db8::53\nLink 2 (wlan0):"),
            Some(true)
        );
        assert_eq!(configured_dns_present("unrecognized output"), None);
    }
}
