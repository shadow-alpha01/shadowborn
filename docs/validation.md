# Validation record

Environment: Kali GNU/Linux 2026.3, x86_64, systemd PID 1, Rust/Cargo 1.97.1,
NetworkManager 1.58.1. Running as an ordinary user. Resolved inactive/unavailable;
NM DNS plugin `default`. No developer-host network mutation is permitted.

## Automated results

The standard toolchain lacks installed rustfmt/Clippy; matching Kali packages were downloaded
and extracted under `/tmp/shadowmist-rust-tools`, without system installation.
Their bin directory is used on PATH for validation.

- [x] `cargo fmt --all -- --check` — PASS
- [x] `cargo clippy --locked --workspace --all-targets -- -D warnings` — PASS, zero warnings
- [x] `cargo test --locked --workspace` — PASS, 34 unit tests (21 core, 13 Linux)
- [x] `cargo build --locked --release --workspace` — PASS, both binaries
- [x] `python3 tests/integration/smoke.py` — PASS, 11 integration checks
- [x] Shell syntax and systemd unit validation using built executable paths — PASS.

The simulated adapter tests exercise transaction failure, health failure,
conflict handling, crash recovery, stale plans and permission boundaries. They
do not establish actual TLS certificate validation, port-853 reachability,
hardware MAC behavior or boot-time ordering on a supported live stack.

## Required isolated VM release checklist — NOT TESTED

- [ ] Fresh Kali connectivity before install and after balanced apply.
- [ ] Root service start/enable/restart and sandbox permissions with NM/resolved.
- [ ] Actual Quad9 authenticated DoT; packet capture evidence if authorized.
- [ ] Offline resolver, blocked TCP 853 and invalid certificate rollback.
- [ ] DHCP DNS injection, IPv6-only DNS, dual stack and resolver priority.
- [ ] Captive portal exclusion and working local network resources.
- [ ] Supported Wi-Fi future-activation random MAC; stable-SSID; actual driver limits.
- [ ] Explicit active rotation success, checkpoint failure and remote-session guard.
- [ ] Ethernet 802.1X, registered MAC and reservations remain safe/excluded.
- [ ] VPN, Docker, corporate split DNS and existing firewall are preserved.
- [ ] SIGKILL/reboot during apply and during restore; boot recovery timing.
- [ ] Restore/uninstall diff preserves all unrelated settings.
- [ ] aarch64 build/run, Fedora and Arch integration.

Strict nftables namespace tests are **NOT IMPLEMENTED / phase 2**, and strict
mode is rejected. Scan driver validation and timed portal exceptions are planned.

The full phase 1 production/VM exit gate is **NOT MET** until this checklist is
executed. Development implementation and safe local verification are separate
from operational certification.

## Real read-only observations

`shadowmist doctor/audit/status --json` inspected the actual host. Status was
`UNPROTECTED`, with eight interfaces and nine findings: NM was active, resolved
was not active, resolver ownership was other/unknown. Reports were redacted.
No DNS health domains were enrolled and no upstream health probes were issued.
The smoke suite compared resolver contents and NM profile UUID/type inventory
before/after dry runs and offline parser probes, tested a real unprivileged
daemon/socket/SIGTERM lifecycle, and staged install/update/uninstall with
ownership-conflict injection. Host networking, services and firewall were not
modified. No failed automated checks remain in the final validation run.
