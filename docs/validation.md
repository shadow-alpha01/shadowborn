# Shadowborn validation — 2026-10-30

Baseline: clean tracked checkout e06bf37; four legacy crates, no server code.
Environment: Kali x86_64, Rust/Cargo 1.97.1; ordinary user. No developer-host
network, installed client, resolver, route, firewall or service changes.
The legacy regression suite remains part of workspace validation; its results
do not certify the new server. Obsolete draft reports have been removed.

All claims refer only to their stated scope; actual supported server OS versions remain NOT TESTED.

| Check | Result / scope |
| --- | --- |
| Formatting, Clippy, workspace tests, release build | PASS; 66 tests (54 legacy + 12 new) |
| Pure configuration/authorization/storage tests | PASS; permissions, conflicts, tombstones, policy and no-history schema |
| Staged server/legacy installation lifecycle | PASS; server documentation links, legacy-only package, retained prior manifest ownership and 10 legacy smoke checks |
| Root CLI in disposable chroot/user/network namespace | PASS; init/enroll, encrypted issue/backup, restore with revocation, deployed-host refusal |
| Generated Unbound / systemd syntax | PASS; Unbound 1.26.1, systemd verify; paths relocated for validation |
| Namespace test entry guard | PASS; absent/current outer-namespace marker rejected before any network command |
| Kernel WG + generated nft NAT in isolated namespaces | PASS: synthetic IPv4 ping/return, owned-table reload |
| Host/metadata/spoofed-source denial | PASS: tested synthetic namespace cases only |
| Explicit kernel peer removal | PASS: traffic stops; does not implement CLI live revoke |
| Real HTTPS, Internet egress IP, public DNS ACL | NOT TESTED |
| Actual authenticated DoT / certificate failure / no-log runtime | NOT TESTED / UNKNOWN |
| Strict client, boot, sleep, multiple NICs, alternate routes, IPv6 bypass | NOT IMPLEMENTED / NOT TESTED |
| VM restart/recovery, SSH lockout, live durable revoke | NOT IMPLEMENTED / NOT TESTED |
| Peer-to-peer and Docker/corporate VPN integration | NOT TESTED |
| aarch64 runtime, Debian/Ubuntu VM acceptance | NOT TESTED |
| Dependency CVE audit, signed release, complete SBOM | NOT TESTED |
| Performance | NOT TESTED |
| Pre-commit repository checks | PASS; relative documentation links, diff whitespace, default server-only Cargo members, no common private-key/token patterns in 78 text files |

Activity-history schema/configuration tests are not a substitute for real
service observations after ordinary traffic, failure, revoke, restart and reboot.
Kernel tests use invented addresses and ephemeral keys, with no customer data,
Internet traffic or persistent packet capture. Namespace exit removes test links.

Commands: scripts/validate.sh; cargo build --locked -p shadowborn-core --example
render_lab; python3 tests/namespaces/shadowborn.py; python3
tests/integration/provisioning.py; python3 tests/integration/generated.py.
Missing optional dependencies are explicitly SKIPPED. No script existence alone
counts as PASS. Tests/vm/README.md lists the outstanding acceptance matrix.

Phase 0 is implemented. Phase 1 provisioning and manual lab generation exist;
automatic activation, network rollback/recovery and live peer lifecycle remain
unfinished. Phase 2 strict activation is rejected. Phase 3 full VM validation and
Phase 4 production hardening/performance are not complete. This is a reviewable
intermediate implementation, not a release candidate.

Extra tools were downloaded from configured distro repositories and extracted
under a temporary directory, never system-installed: Unbound 1.26.1, age 1.3.2,
ShellCheck 0.11.0. ShellCheck passed for all shell scripts. No runtime DoT or
complete service sandbox claim follows from these syntax checks.
