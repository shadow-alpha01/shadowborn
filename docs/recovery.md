# Recovery and uninstall

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
