# Hardening and operational boundaries

Use a maintained minimal distro, provider console, SSH keys and a proven alternate
admin session. Review admin source CIDR/port, cloud UDP policy, WAN routing,
port-53 conflicts, private subnet collisions and third-party firewall managers.
The installer does not change sshd, provider agents, firewall, resolver or sysctl.
Do not remove global host security logs.

Generated services suppress stdout/stderr and core dumps. Unbound runs as the
package user with bind-service capability; the firewall oneshot retains NET_ADMIN
and has a read-only filesystem sandbox. WG remains the standard distro service
with a per-instance output-suppression/ordering drop-in. These properties need
real service validation, especially distribution AppArmor and boot ordering.

Secret state uses private paths, no-follow reads, link/owner/mode checks, bounded
reads, exclusive locks, fsynced atomic replacement and stale-state rejection.
Subprocesses are allowlisted wg/age executables with bounded I/O, a timeout,
secret stdin and suppressed stderr. No arbitrary shell interpolation is used.
Memory copies/swap and administrator-controlled command capture remain limitations.

No global flush, NAT66, blanket forwarding, automatic route detection approval,
automatic reconnect, production key rotation or privileged workstation testing.
No dependency CVE clearance or signed release/SBOM is claimed until performed.
