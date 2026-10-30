# Shadow Mist legacy client

The retained `shadowmist` / `shadowmistd` application audits local Linux networking
and can apply explicitly enrolled NetworkManager MAC/IPv6 and systemd-resolved
DoT policies. It is independent of the Shadowborn WireGuard server and does not
provide a VPN, anonymity or a strict client kill switch.

This directory contains the maintained compatibility guide. Obsolete draft
roadmaps and historical test reports have been removed; current regression
results are in the repository's `docs/validation.md`.

## Build and inspect

Run source commands from the repository root:

```bash
cargo build --locked --release -p shadowmist-cli -p shadowmist-daemon
./target/release/shadowmist version
./target/release/shadowmist doctor
./target/release/shadowmist audit --json
./scripts/install.sh --check
./scripts/install.sh --dry-run
```

The legacy installer builds only the client and daemon. Server installation uses
`scripts/install-server.sh` separately. The provided legacy installer copies files
but never installs dependencies, enables units, enrolls profiles or applies DNS.
Native Debian packages are not provided.

## Configure and apply on an explicitly approved host

```bash
sudo ./scripts/install.sh --profile balanced
sudoedit /etc/shadowmist/config.toml
sudo shadowmist config validate
sudo shadowmist apply --dry-run --verbose
```

Configure `general.enrolled_profiles` with the exact intended NetworkManager
profile UUIDs. DNS changes additionally require two to four approved
`dns.health_domains`, an eligible active link and confirmed resolved ownership.
Review every proposed change. A skipped DNS plan means DNS will not be changed.
The monitor does not supply this consent or automatically enroll connections.

Only after deliberately approving that plan:

```bash
sudo shadowmist apply
sudo systemctl enable --now shadowmist-recover shadowmist
shadowmist status --json
shadowmist dns status --probe --json
```

MAC/IPv6 changes normally take effect on the next activation. Active identity
rotation requires explicit reconnect consent and may interrupt connectivity;
see `shadowmist identity rotate --help`. Exact search-domain replacement has its
own consent workflow in [recovery](recovery.md). Never change a working laptop's
resolver merely to satisfy eligibility requirements.

## Update and recover

```bash
sudo systemctl stop shadowmist
sudo ./scripts/install.sh --update
sudo systemctl start shadowmist

sudo shadowmist restore --dry-run
sudo shadowmist restore
sudo ./scripts/uninstall.sh --restore
# Installed uninstaller:
sudo /usr/local/libexec/shadowmist/uninstall.sh --restore
```

Stopping a service does not undo persistent settings. Restore uses ownership
journals and preserves administrator conflicts. Uninstall removes unchanged
manifest-owned files and retains configuration/recovery state. Neither operation
should be replaced with deletion of journals while changes are still active.
Read the [recovery procedure](recovery.md) before using these commands.

## Scope and technical references

- [Architecture and transaction recovery](architecture.md)
- [Compatibility and unverified hardware/VM behavior](compatibility.md)
- [CLI / JSON contract](status-schema.md)
- [License provenance](../licensing.md) and the existing [license text](../../LICENSE)
- [NetworkManager settings](https://www.networkmanager.dev/docs/api/latest/nm-settings-nmcli.html)
- [systemd-resolved configuration](https://www.freedesktop.org/software/systemd/man/latest/resolved.conf.html)

A configured or verified system DNS path does not guarantee all applications use
it. VPNs, enterprise DNS, captive portals and conflicting ownership remain
unsupported for automatic changes. Existing legacy event/status semantics are
separate from the new Shadowborn server's no-activity-history policy.
