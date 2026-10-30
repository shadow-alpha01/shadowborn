# No retained activity logs

This is mandatory for Shadowborn-owned components, not an anonymity guarantee.
Configuration rejects enabling telemetry, peer activity storage or query logging.

Never collect or persist browsing URLs, DNS queries, destination-flow history,
packet payloads/captures, connection history, observed source IPs, location,
handshake timelines or per-peer traffic series. No analytics, metrics exporter,
crash reporting, remote collector or persistent troubleshooting mode exists.
The CLI performs no periodic recording. `status` currently reports UNKNOWN for
runtime properties rather than collecting or caching peer traffic information.

Necessary persistent configuration: server private/public key, peer public keys,
per-peer PSKs, assigned tunnel addresses, names, active/disabled/revoked state,
validated server policy. Revoked entries lose their PSK but keep a tombstone to
prevent reuse/restore. Private directories are 0700 and files 0600. Configuration
backups are age encrypted with an explicit recipient; retained copies contain
secrets and authorization inventory, never traffic. The operator controls backup
retention and must retire outdated exported profiles/bundles. Memory buffers are
not guaranteed to be securely erased; no SSD erasure promise is made.

Generated Unbound disables query/reply/SERVFAIL logs, syslog and periodic
statistics; no cache-dump or remote-control service is enabled. Its volatile
cache necessarily holds current DNS data in RAM. Service stdout/stderr are null
and core dumps disabled per service. Generated nft rules have no log/nflog or
counters. WG service output is suppressed by a per-instance drop-in. No global
journald, SSH, kernel or security auditing settings are changed.

The OS/systemd manager may record unit lifecycle and administrator actions.
The VPS/cloud provider, ISP, upstream Quad9 resolver and websites can retain
their own metadata. WireGuard and conntrack retain live operational state in
kernel memory. Shadowborn does not control these boundaries. Legacy Shadow Mist
has its own existing status/event semantics and is not covered by this new
server-owned-service claim.

Source-level configuration and state tests are automated. Actual Unbound,
service/journal behavior after traffic, outage, revocation and reboot is UNKNOWN
until the full disposable VM suite has run. Do not advertise verified no-log
runtime compliance based on configuration rendering alone.
