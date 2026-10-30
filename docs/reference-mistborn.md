# Design references

Mistborn is architectural inspiration for an owned VPN gateway plus DNS, not a
source dependency. No code, web stack, license or old defaults were imported.
Pi-hole and dnscrypt-proxy are deferred; any future integration must independently
pass the no-query-history/no-database/no-telemetry gate for its exact version.

Primary references used for fresh configuration design:

- [WireGuard quick start and key generation](https://www.wireguard.com/quickstart/)
- [wg-quick routing and DNS behavior](https://manpages.debian.org/bookworm/wireguard-tools/wg-quick.8.en.html)
- [nftables manual](https://www.netfilter.org/projects/nftables/manpage.html)
- [Netfilter hooks](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks)
- [Unbound configuration](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html)
- [systemd service execution/sandboxing](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)

Online documentation is design input, not proof of installed-version behavior.
Actual namespace and VM results are recorded separately in validation.md.
