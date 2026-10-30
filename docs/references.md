# Upstream references

Consulted during implementation, 2026-10-30. Installed capabilities are probed
instead of assuming the latest online documentation matches a host.

- [NetworkManager profile settings](https://www.networkmanager.dev/docs/api/latest/nm-settings-nmcli.html): cloned MAC, IPv6 privacy, DNS/SNI and required DoT policy.
- [NetworkManager CLI](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nmcli.html): audited command fallback, offline keyfiles and monitor events.
- [NetworkManager 1.46](https://www.networkmanager.dev/blog/networkmanager-1-46/): stable-SSID option introduction; runtime parser probe remains authoritative.
- [resolvectl](https://www.freedesktop.org/software/systemd/man/latest/resolvectl.html): per-link settings and uncached resolution.
- [resolved.conf](https://www.freedesktop.org/software/systemd/man/latest/resolved.conf.html): authenticated TLS versus opportunistic downgrade, per-link selection.
- [resolved D-Bus API](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.resolve1.html): local service semantics.
- [Quad9 service endpoints](https://docs.quad9.net/services/): secure IPv4, IPv6 and certificate name.

No bespoke crypto or DNS transport is implemented. External DNS queries are
limited to explicitly configured health domains; these references are developer
documentation, not runtime telemetry endpoints.
