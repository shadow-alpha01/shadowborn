# Compatibility and capability policy

| Environment / feature | Current behavior | Verification |
| --- | --- | --- |
| Kali 2026.3, x86_64, systemd, NM 1.58.1 | Real passive doctor/audit; build and local tests | Developer-host read-only testing |
| Same stack plus active resolved and NM resolved plugin | Conditional enrolled DoT, MAC/IPv6 application | Code/simulated tests; live VM NOT TESTED |
| Resolved absent/inactive or different resolv.conf owner | No DNS mutation; truthful unprotected/audit status | Real developer-host condition |
| Ethernet | Preserve MAC by default; random explicit opt-in | Pure planner; hardware NOT TESTED |
| Wi-Fi random/stable-SSID | Future-activation profile policy; stable-SSID parser probe | NM offline parser; hardware rotation NOT TESTED |
| IPv4-only / IPv6-only / dual stack | Plan DNS only for enabled families, preserve IPv6 configuration | Pure planner; live VM NOT TESTED |
| VPN, enterprise/802.1X, split-routing/global DNS | Exclude incompatible DNS/profile mutation | Simulated planners; live interoperability NOT TESTED |
| Ordinary search domains such as home | Preserve by default; exact per-apply consent can give up local names transactionally | Simulated consent/restore tests; live application NOT TESTED |
| Virtual bridges, containers, tunnels | No identity changes; DNS coexistence exclusion as needed | Real discovery; no network mutation |
| Read-only root / no systemd / container / WSL | Audit-only or rejected host installation | Capability logic; some paths simulated |
| Fedora / Arch | Planned tier 2; observe/build only until verified | NOT TESTED |
| aarch64 | Portable Rust target; CI cross-check | Local cross-build NOT TESTED |
| systemd-networkd / other init / macOS / Android | No mutation adapter | Unsupported |
| Strict firewall enforcement | Rejected by config and CLI | Planned phase 2 |

The installer does not install dependencies or migrate resolvers. On Kali/Debian,
`--check` prints package guidance. Review the actual distribution package versions
and resolved integration yourself in a disposable VM. Never replace a working
`resolv.conf` symlink blindly or globally restart NM just to meet eligibility.

DoT support and stable-SSID are checked using `nmcli --offline connection add`
with synthetic profiles serialized only to stdout; these never become live
NetworkManager profiles. Each property is also read before planning; missing
properties are skipped with reasons. This avoids distro-name behavior switches.

Enrolled profiles must correspond to currently discoverable physical devices.
Unbound inactive profiles are excluded rather than guessed. Multiple active
physical links exclude DNS takeover. LAN names/search domains are deliberately
left alone by default. Explicit `apply --replace-search-domain DOMAIN` consent
can give up exact ordinary search domains on eligible links while preserving
their prior values in the journal. Route-only domains and other compatibility
restrictions remain unsupported. See `docs/recovery.md` for the scoped workflow.

Wi-Fi scan randomization, LLMNR/mDNS/NetBIOS and DHCP/DUID changes are audit-only.
No hostname changes, sysctl presets, generic firewall replacement or automatic
active reconnection occurs. Broad scan-driver privacy is UNKNOWN, not verified.
