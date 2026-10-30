# Architecture

Shadow Mist is a Linux privacy service, not an anonymity system. The initial
implementation targets a deliberately narrow, capability-checked NetworkManager
and systemd-resolved setup. All host-network integration testing happens in an
isolated VM. Development, installation, and daemon startup never imply approval
to change networking.

## Boundaries

- `shadowmist-core`: versioned configuration, reports, pure policy planner,
  reversible changes, adapter contract, and transaction state machine.
- `shadowmist-platform-linux`: bounded subprocesses with argument arrays,
  NetworkManager profile adapter, resolved per-link adapter, passive discovery,
  root checks, private durable journals, locks, and recovery.
- `shadowmist-daemon`: asynchronous NetworkManager event stream, debounced
  passive assessments, periodic health checks, sanitized read-only Unix socket,
  cancellation and restart recovery. It never enrolls profiles or rotates links.
- `shadowmist-cli`: direct read-only discovery and explicit root-only mutations.
  The daemon socket accepts status queries only; mutations have no IPC endpoint.

## Conservative application

Only explicitly enrolled profile UUIDs are considered. MAC/IPv6 profile changes
take effect at the next activation. No automatic disconnect or NetworkManager
restart is allowed. The audited `nmcli` fallback uses NetworkManager's D-Bus API;
`nmcli monitor` supplies its event stream. No custom D-Bus protocol is necessary
for the MVP. A direct adapter can replace this without changing the planner.

DNS is eligible only when resolved owns the stub resolv.conf, the NM DNS plugin
is resolved, and one ordinary enrolled physical link is active without VPN,
split/search DNS, competing link/global resolvers, or captive-portal indication.
Unsupported/uncertain ownership blocks DNS changes but allows useful auditing.
Persistent NM per-profile settings and matching resolved live per-link settings
are separately snapshotted. No global DNS restart or resolv.conf replacement.
DoT requires `yes`, pinned certificate hostname, uncached successful lookups,
and exact effective configuration; status distinguishes configuration from
verification and never infers encryption from DNSSEC. Verification is scoped
to resolved, not all application traffic. Optional health lookups are explicit.

## Recovery

Acquire an exclusive private-state lock; reread every old value; durably journal
the entire plan before mutation; arm an independent systemd rollback timer for
live DNS/reconnect operations; write each intent before executing it; verify each
result and health; commit atomically, then disarm the timer. A crash leaves a
recoverable journal. The daemon and timer recover incomplete transactions.
Restore compares current values with owned values, refuses conflicts, and
restores in reverse order. Baseline values survive repeated apply. Reboot removes
transient timers; the boot recovery service restores pending operations as soon
as NetworkManager's D-Bus API is available, before the monitor. It cannot promise
recovery before NetworkManager's first activation. Reboot timing remains a VM
release gate and is documented as unverified.

Strict firewall enforcement is phase 2 and is explicitly rejected by the MVP.
No nftables changes are implemented or executed on the developer host.
