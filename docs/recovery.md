# Recovery and uninstall

## Active resolved service, missing DNS, or a manual nameserver workaround

A running `systemd-resolved` process is insufficient for NetworkManager
integration. Recent `resolvectl` versions can read state over Varlink while the
resolver's D-Bus API is unavailable. In that condition NM may know the DHCP DNS
servers but fail to deliver them to resolved. The stub then has no configured
upstream. An extra `nameserver 1.1.1.1` in the generated stub can restore access
by bypassing resolved, without enabling authenticated system DNS.

Inspect local state without issuing external DNS probes or changing networking:

```bash
shadowmist doctor
resolvectl status
resolvectl dns
nmcli -g IP4.DNS,IP6.DNS device show
busctl --system --timeout=2 call \
  org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus \
  NameHasOwner s org.freedesktop.resolve1
journalctl -b -u dbus -u systemd-resolved --no-pager
getent passwd systemd-resolve
```

`b false` means that no process owns the resolver's bus name. An `activatable`
entry in `busctl list` is not an active owner. Installation-time logs such as
`Unknown username "systemd-resolve"` followed by resolve1 activation timeouts
indicate a bus registration/policy problem to investigate. Shadow Mist reports
`RESOLVED_DBUS_UNAVAILABLE`, `RESOLVED_NO_UPSTREAM`, and `RESOLV_CONF_BYPASS`
separately instead of treating a successful service start as readiness.

For a freshly installed resolver with that registration failure, an administrator
can reload D-Bus policy, restart resolved, and refresh only NM's DNS plugin.
**These are manual repair operations, not tests. They can briefly interrupt name
resolution and restarting resolved can regenerate its stub, removing a manual
nameserver entry. Keep a local console and save the working file first.**

```bash
SHADOWMIST_DNS_BACKUP="/root/shadowmist-resolv.conf.$(date -u +%Y%m%dT%H%M%SZ).bak"
sudo cp --dereference --preserve=mode,timestamps /etc/resolv.conf "$SHADOWMIST_DNS_BACKUP"

sudo systemctl reload dbus.service
sudo systemctl restart systemd-resolved.service
sudo nmcli general reload dns-full

resolvectl dns
busctl --system --timeout=2 call \
  org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus \
  NameHasOwner s org.freedesktop.resolve1
```

Verify that the bus owner is now `b true` and that the active link has the
expected upstream DNS servers. If the repair fails, restore the saved working
contents from the console, keeping the existing symlink:

```bash
sudo cp "$SHADOWMIST_DNS_BACKUP" /etc/resolv.conf
```

This restores the temporary plaintext workaround; it is not DoT protection.
Do not restart the whole NetworkManager service or replace resolver ownership
merely to refresh DNS. The upstream [nmcli reference](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nmcli.html)
documents `general reload dns-full` and its short DNS interruption.

Once basic resolver integration works, enroll profile UUIDs, approve health
domains, review `apply --dry-run`, and apply explicitly. Starting Shadow Mist
alone does not configure these consent-dependent settings. A mixed stub is
rejected for encrypted system-DNS verification even if resolved itself uses TLS.

## Explicitly give up an ordinary local DNS search domain

An ordinary search suffix such as `home` can block DNS application because
replacing its router DNS may stop local names from resolving. If you deliberately
give up that suffix, use an exact, one-time consent flag on `apply`:

```bash
sudo /usr/local/bin/shadowmist apply --replace-search-domain home --dry-run --verbose
sudo /usr/local/bin/shadowmist apply --replace-search-domain home
sudo systemctl enable --now shadowmist-recover shadowmist
/usr/local/bin/shadowmist dns status --probe --json
```

Use a current installed binary; `apply --help` lists the flag. The dry-run plan
must contain live DNS changes, with no unresolved `DNS skipped` condition.
Consent is exact and case-insensitive, without wildcards; repeat the flag for
each ordinary search domain that must be replaced. Every affected domain must
belong to an active, enrolled, eligible physical connection. Route-only domains
(such as `~corp.example`), VPN/tunnel links, enterprise profiles, other links,
global DNS conflicts and all other compatibility checks remain blocked.

The explicit application replaces the resolved domain list with `~.` and writes
the matching persistent NM policy, including ignore-auto-dns for enabled IP
families. Old DNS servers, transport, domains and profile values are snapshotted
in the same transaction before mutation. Failed health checks or explicit
`restore` can therefore return `home` and the prior resolver values together.
No extra reconnect or global network-manager restart is requested.

The flag does not save a blanket override in TOML or authorize the daemon to
discard later search/split-DNS changes. Future connection activations use the
committed profile settings; restore retains the original baseline. This is
explicit removal of local-name support, not split-DNS interoperability or strict
firewall enforcement. Live application remains subject to the VM release gates.

## Restore recorded Shadow Mist changes

Keep a local console available when testing DNS or explicit reconnect. The CLI
does not need a running monitor to restore recorded values.

```bash
sudo systemctl stop shadowmist
sudo shadowmist restore --dry-run
sudo shadowmist restore
shadowmist doctor
```

`stop`, `disable` and `restart` do not undo persistent NetworkManager settings.
Restore changes recorded profile keys and live resolved properties in reverse
order; an already active MAC/IPv6 address remains until next activation.
Configuration syntax errors do not prevent restore/recover: recorded journal
values are used independently of the current policy.

Transactions are under `/var/lib/shadowmist/transactions`, 0600, ordered by ID.
The journal records the complete proposed plan before the first write and each
attempt before execution. `pending` is recoverable, `committed` owns applied
values, `rolled_back` has no active ownership, `conflict` needs review. Restore
records pending intent before rollback so an interrupted restore is recoverable.
Repeated apply does not overwrite the original baseline; committed history is
restored newest-first. Keys already at their original value are skipped.

Live DNS application arms an independent 180-second systemd transient timer
before mutation. Explicit MAC rotation additionally uses a 90-second NM device
checkpoint. A killed process leaves its journal; the timer invokes:

```bash
sudo shadowmist recover
```

Do not delete transaction files while changes are active. A reboot loses transient
timers; the enabled `shadowmist-recover` boot unit and monitor startup recover
pending operations when NetworkManager's API becomes available. NM can begin
activation before recovery; this timing and crash behavior are **NOT TESTED**
and remain production release blockers. DNS verification failures restore the
whole affected transaction, including future-activation policy in that batch.

A detected external change is a conflict. Shadow Mist does not overwrite it.
Inspect recorded/current values locally (they may contain sensitive identifiers),
decide which settings you own, and resolve the conflict deliberately before
rerunning restore. Missing profiles/devices or inaccessible D-Bus stay errors;
there is no unconditional `--force` that destroys third-party changes.

Balanced rollback emits `DEGRADED`: previous/plaintext DNS may be active. A
durable marker prevents automatic retry loops. Explicit apply is needed to retry
and verify policy; inspect current status first. There is no strict-mode firewall
to remove in this MVP.

```bash
sudo ./scripts/uninstall.sh --restore
# Installed copy:
sudo /usr/local/libexec/shadowmist/uninstall.sh --restore
# Deliberately retain persistent policy instead:
sudo ./scripts/uninstall.sh --keep-settings
```

Without a restoration flag, uninstall offers restore first. It stops the monitor,
restores (unless explicitly declined), checks SHA-256 installation ownership and
removes unchanged owned files only. Config, journals and install backups remain
for review. A modified installed file blocks removal, preserving it. Dependency
packages, resolv.conf, unrelated services/firewalls and network profiles are never
deleted. Restore must succeed before `--restore` uninstall can continue.

Updates require a stopped monitor, `install.sh --update`, matching old hashes,
and keep copies under `install-backups`. Existing config is preserved. Interrupted
file installation is diagnosable using retained backups; installer file-copy
crash recovery is not yet packaged as an automatic rollback transaction.
