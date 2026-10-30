# Threat model

## Assets and adversaries

Assets: connectivity, administrator-owned configuration, local identifiers,
system DNS query confidentiality, profile ownership and trustworthy status.
Relevant observers include Wi-Fi operators, nearby passive link observers,
access providers, DNS providers and local unprivileged users. Misconfiguration,
driver incompatibility and concurrent administrators are failure sources too.

## Controls

| Asset / threat | Control | Evidence / remaining scope |
| --- | --- | --- |
| Stable link-layer tracking | NM random/stable-SSID per enrolled Wi-Fi profile | Configured policy; effective MAC separately inspected |
| DNS queries on local transport | Resolved `DNSOverTLS=yes` and IP#certificate hostname | Effective settings plus explicit uncached lookups; no downgrade |
| DHCP/IPv6 resolver takeover | Ignore automatic DNS for enrolled supported families and root-domain routing | Exact owned settings; incompatible split/VPN setups excluded |
| Stable IPv6 interface identifiers | Stable privacy and temporary source preference | Next activation; public prefix remains observable |
| Connectivity loss | Narrow preflight, snapshots, independent timer, checkpoint and balanced rollback | Live failure/reboot behavior still VM release gates |
| Concurrent administration | Compare-before-write/restore, exclusive state lock | Conflicts preserved; D-Bus has no global cross-tool CAS |
| Local privilege boundary | Root-only mutation CLI, private state, status-only socket | No command execution API; binaries are not setuid |
| Log disclosure | Identifier redaction, bounded structured event logs | Verbose console is explicitly sensitive |

## Residual risks

This is not anonymity, a VPN, Tor, traffic obfuscation or browser isolation.
Public IPs, destination IPs, route prefixes, timing and volumes remain visible.
DNS provider visibility moves to the configured resolver; there is no promise
that any provider never logs. Application DoH/DoQ, hardcoded addresses, custom
resolvers, accounts and fingerprints bypass these controls. No port-53 firewall
exists in this MVP; even one could not universally control DoH on port 443.

MAC rotation does not rewrite DHCP IDs, DUIDs, hostname or accounts. Drivers can
ignore policy, virtual machines may expose no Wi-Fi, and 802.1X or registered
MAC networks may reject a new address. Split DNS, VPNs, local resolvers and
captive portals require explicit compatibility work. Local socket snapshots do
not prove packets are absent or that listening services are externally reachable.

The privileged CLI and OS daemons remain trusted. Malicious root, a compromised
kernel/network manager or a tampered Rust toolchain is out of scope. State files
may contain prior local identifiers and are 0600 inside a private directory.
There is no telemetry, identifier upload, homemade encryption or active peer scan.

## Operational limitations

No root live changes were executed on the developer host. Pending recovery is
durable but reboot recovery starts after NM is available; it cannot guarantee
restoration before NM's first connection activation. A restore can conflict with
another manager or fail when its profile/device no longer exists. Such cases
remain visibly pending/conflicted and require console review, never forced
replacement of unrelated settings. Production rollout is blocked on VM tests.
