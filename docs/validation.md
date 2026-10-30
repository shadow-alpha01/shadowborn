# Validation record

Environment: Kali GNU/Linux 2026.3, x86_64, systemd PID 1, Rust/Cargo 1.97.1,
NetworkManager 1.58.1. Running as an ordinary user. The initial foundation run
had resolved inactive/unavailable and NM DNS plugin `default`. A later read-only
incident investigation found resolved 262 active, the NM resolved plugin selected,
and resolver D-Bus registration broken after package installation. No host network
mutation is performed by these checks.

## Automated results

The standard toolchain lacks installed rustfmt/Clippy; matching Kali packages were downloaded
and extracted under `/tmp/shadowmist-rust-tools`, without system installation.
Their bin directory is used on PATH for validation.

- [x] `cargo fmt --all -- --check` — PASS
- [x] `cargo clippy --locked --workspace --all-targets -- -D warnings` — PASS, zero warnings
- [x] `cargo test --locked --workspace` — PASS, 54 unit tests (32 core, 21 Linux, 1 daemon)
- [x] `cargo build --locked --release --workspace` — PASS, both binaries
- [x] `python3 tests/integration/smoke.py` — PASS, 12 integration checks
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

## DNS incident regression validation

The user restored connectivity by adding a public nameserver to the generated
resolved stub. Read-only inspection found a running resolved process with no
owner for `org.freedesktop.resolve1`, empty resolved upstream state despite NM
knowing DHCP DNS, and an installation-time D-Bus log reporting unknown user
`systemd-resolve`, followed by activation timeouts. The new doctor identifies
`RESOLVED_DBUS_UNAVAILABLE`, `RESOLVED_NO_UPSTREAM` and `RESOLV_CONF_BYPASS`
on this real host without upstream DNS probes or service activation.

Regression tests cover stub-content validation (including IPv6 and order),
missing bus ownership, planner refusal, precise findings, and sanitized daemon
assessment logs containing state/finding codes. Host repair commands are documented
in `recovery.md`; they were not executed. Installed binaries and system services
were left untouched; updated binaries are available under `target/release`.

## Explicit ordinary search-domain replacement

`apply --replace-search-domain home` is a one-time exact consent for dropping
the local suffix on an active enrolled eligible physical connection. New tests
cover default preservation, exact/case-insensitive consent, complete domain
coverage, routing/VPN/other/enterprise exclusions, missing snapshot evidence,
literal input validation, and restoring the prior `home` value with the entire
transaction. No new blanket policy is saved in configuration.

Read-only planning against the actual configured host was compared with and
without consent. The default plan skipped DNS; the consented plan proposed live
DNS changes including recorded `home` -> `~.` with no reconnect. The host's
resolver contents, link, per-link DNS/domain/transport and NM profile inventory
were preserved during verification. Live replacement was not executed: root
authorization still requires the user's sudo password. The prepared installed
CLI workflow must be run by the user; no VERIFIED live-DNS claim is made.
