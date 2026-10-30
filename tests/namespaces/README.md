# Isolated network validation

Build `cargo build --locked -p shadowborn-core --example render_lab`, then run
`python3 tests/namespaces/shadowborn.py` as an ordinary user. It uses disposable
user/network namespaces, synthetic addresses and ephemeral keys. It never runs
privileged commands in the developer host's network namespace.

Executed coverage: actual kernel WireGuard handshake, generated nft syntax and
owned-table replacement, scoped IPv4 NAT/return traffic, host/metadata/spoofed
source denial, and traffic loss after explicit kernel peer removal. This is not
a test of automatic CLI live revoke, real Internet, DNS/DoT, strict client,
boot/recovery or actual VM portability. Missing kernel capabilities/tools are
SKIPPED or explicit failures, never converted into VERIFIED protection.
