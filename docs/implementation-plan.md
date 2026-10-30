# Implementation plan and traceability

The authoritative input is `SHADOW_MIST_CODEX_SPEC.md`. Work proceeds in order;
unchecked release gates remain release blockers, not claims of support.

| Task | Specification | Evidence / gate |
| --- | --- | --- |
| P0.1 Workspace, architecture, threat model | 0, 9, 13 | Cargo workspace, docs |
| P0.2 Strict versioned TOML and stable reports | 3, 11 | core tests, CLI JSON |
| P0.3 Safe capability discovery and passive audit | 2, 8 | real doctor/audit |
| P0.4 Pure planner and simulated adapters | 9, 14 | planner/transaction tests |
| P1.1 Ownership journal, locks, rollback conflicts | 6, 10 | failure-injection tests |
| P1.2 Enrolled MAC/IPv6 next-activation policy | 5, 7 | planner, adapter validation |
| P1.3 Authenticated resolved DoT, health, fallback | 6, 10 | unit tests; VM release gate |
| P1.4 Explicit guarded reconnect and checkpoint | 3, 5 | unit tests; VM release gate |
| P1.5 Daemon events, socket, durable state | 3, 8, 9 | runtime smoke and unit tests |
| P1.6 Installer/uninstaller, recovery, CI | 10, 12 | shell checks, staging tests |
| P1.7 Isolated Kali VM verification | 14, 15 | **NOT TESTED** until performed |
| P2 Strict nftables / DHCP identity / portal exception | 6, 15 | Planned; commands reject |
| P3 Other managers and rotation on startup | 15 | Planned; config rejects |

## Task checklist

- [x] Inspect real environment and initialize local Git, without remote.
- [x] Write architecture and implementation plan before implementation.
- [x] Implement and validate core configuration, reports, and pure planner.
- [x] Implement capability discovery, audit, Linux adapters and CLI.
- [x] Implement durable transactions, restore, watchdog and reconnect.
- [x] Implement daemon, read-only IPC and recovery units.
- [x] Implement installation, uninstallation and documentation.
- [x] Run format, Clippy, workspace tests, release build and real passive smoke.
- [ ] Complete all isolated VM checks in `docs/validation.md` (**NOT TESTED**).

## Decisions

No root networking mutation is authorized on this development host. Test real
read-only commands, a simulated adapter, staged installation and daemon runtime
in private temporary directories. A capability limitation is reported as such.
No strict-mode or firewall implementation before the phase 1 VM release gate.
