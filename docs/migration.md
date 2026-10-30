# Shadowborn migration plan

Baseline inspected on 2026-10-30: clean tracked checkout at `e06bf37`, four
`shadowmist-*` workspace crates, a local NetworkManager/resolved privacy client,
no WireGuard server implementation. `origin` already points to
`git@github.com:shadow-alpha01/shadowborn.git`. No remote change is necessary.
The supplied AGENTS.md is included in the new repository; its old ignore rule
was removed.

1. Preserve the four legacy crates, commands, systemd units, configuration and
   installer. Archive their documentation under explicitly named legacy pages.
2. Add independent `shadowborn-core`, `shadowborn-platform`, `shadowborn-cli`
   crates. No dependency on NetworkManager or legacy host discovery.
3. Implement validated server configuration, minimal peer authorization state,
   native WireGuard key generation, protected provisioning bundles, a separate
   installer, encrypted backups and conservative recovery.
4. Generate server firewall, DNS and service configuration for disposable VM
   evaluation. Keep automated live apply and strict client activation unsupported
   until rollback, boot and packet-level failure gates are demonstrated.
5. Publish separate server and standard client instructions and explicit gates.
   Never describe generated configuration or mocked tests as a validated VPN.

No existing workstation service, DNS configuration, firewall, routes, keys or
installed application is changed by this migration. No push, remote publication
or Git history rewrite is part of this task.

Licensing: the root LICENSE contains AGPLv3 while legacy Cargo metadata says
MIT. Preserve both historical evidence and older source; do not infer ownership
or a relicensing grant. See licensing.md before distributing a release.

## Pre-commit cleanup

The owner confirmed retaining the legacy client while removing unnecessary draft
material. Operational legacy guides now live only under docs/legacy. Superseded
roadmaps, historical incident/test reports, duplicate guides, a static file list,
unused fixtures and placeholder-only directories were removed. Default Cargo
members select Shadowborn; explicit --workspace checks retain legacy coverage.
The legacy installer builds only its two binaries and ships its own guide and
documentation, not the server manual. No installed host files are changed.
