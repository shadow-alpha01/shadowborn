# Architecture

Shadowborn is a separate server provisioning control plane. The kernel carries
WireGuard packets; Rust never relays payloads or implements cryptography.
The existing Shadow Mist client is retained, with its architecture documented
in [legacy/architecture.md](legacy/architecture.md).

- `shadowborn-core`: strict versioned configuration, peer authorization model,
  deterministic address allocation, revocation-preserving restore, redacted
  secret type, pure plans and WireGuard/nft/Unbound/systemd renderers.
- `shadowborn-platform`: root/undeployed guards, protected files, no-follow
  opens, atomic replacement/fsync, exclusive locking, compare-before-write,
  bounded `wg` and `age` subprocesses with pipes and suppressed diagnostics.
- `shadowborn-cli`: explicit provisioning and inspection; no daemon, socket,
  public API, background probes or activity recorder.
- Existing `shadowmist-*` crates remain independent; server installation selects
  only the Shadowborn executable and documentation.

The single protected state.json is the canonical offline authorization state.
It stores no timestamps, counters, endpoints observed from peers or activity.
A change replaces one file atomically after validating and comparing the old
state. Revoked entries retain only identity/address tombstones; their PSK is
removed. Lock contention and stale state fail closed. This transaction manages
files, not kernel networking. Exported bundles are immutable review artifacts,
not another canonical database; retire stale bundles after authorization changes.

Server traffic policy: IPv4 peers may reach public Internet via the configured
WAN only, with scoped masquerade and established return traffic. WireGuard uses
individual source /32 AllowedIPs. The firewall denies peer access to server
management, other peers, private/CGNAT/link-local/multicast destinations and
cloud metadata. Tunnel-only DNS is the sole allowed host service. IPv6 forwarding
is dropped. There is no global firewall flush. Owned table replacement is an
atomic nft batch, but initial ownership/collision checks remain manual in a VM.

The generated WG systemd drop-in requires firewall startup first; stopping WG
does not remove firewall tables. Unbound runs as its package user, binds the
VPN IPv4 address and forwards to pinned Quad9 DoT endpoints. No custom server
monitor or persistent client daemon exists. DNS local DNSSEC validation and
routed IPv6 are not implemented in this preview.

Automated live apply, kernel/config synchronization, live revoke, timed network
rollback and reboot recovery are not implemented. Commands reject these paths
instead of presenting file staging as live protection. Phase 1 remains partial;
Phase 2 strict client and Phase 3 VM acceptance remain release gates.
