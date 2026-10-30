# Namespace tests

Strict DNS nftables enforcement is phase 2 and is rejected by the MVP. There
are no nftables mutation tests or host-firewall changes to execute. Before
implementing strict mode, add an explicitly isolated network namespace harness
covering IPv4/IPv6, loopback stubs, owned-table-only removal, timed watchdog
rollback and preservation of unrelated rules. Namespace isolation alone cannot
prove Wi-Fi-driver, NetworkManager or systemd integration.
