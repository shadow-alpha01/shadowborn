# Administration and recovery

This preview provides protected file transactions, not a live network transaction
engine. `apply --confirm`, strict activation and automatic live gateway removal
fail with UNSUPPORTED. Do not deploy over SSH relying on a rollback timer that
does not exist. A disposable VM snapshot plus verified console is the manual
lab recovery boundary. Network timed rollback, crash/reboot recovery and live
revocation are explicit remaining Phase 1 gates.

## Offline authorization and backups

`peer disable/revoke/rotate-psk --name NAME --confirm` requires root, exclusive
locking and an undeployed gateway. Changes atomically replace state.json after
comparison with the planned old value. Revoked keys/names/addresses stay reserved;
PSKs are deleted from current state. Previously exported copies are not erased.

```bash
sudo shadowborn backup --recipient AGE_RECIPIENT --output /root/gateway.age
sudo shadowborn restore --input /root/gateway.age --identity /root/operator.agekey --dry-run
sudo shadowborn restore --input /root/gateway.age --identity /root/operator.agekey --confirm
```

Native age identities and encrypted inputs must be private 0600 files under
private 0700 directories. Restore requires the existing same gateway key/config
and unions current disabled/revoked restrictions into the backup; conflicts abort.
It cannot restore an empty new server because there is no local revocation ledger
to compare. Full disaster-rebuild reconciliation is a release gate, not an
implicit permission to reauthorize credentials from an old backup.

Keep encrypted off-host backups with explicit retention. Package update snapshots
contain program/docs only, no peer activity. If packaging leaves `pending/`,
inspect before.json and numbered copies, compare current files, and manually
restore only unchanged owned paths. The installer refuses a new operation until
that interruption is resolved; it does not force over an administrator's edits.

## Manual VM emergency actions

From the verified console, stop `wg-quick@wg-shadowborn` to prevent all peer egress
while fixing a compromised/revoked credential. Stop its DNS unit too. Remove the
peer from the persisted WG file and its address from the firewall peers set;
regenerate the offline state/bundle only after detaching the manual deployment.
A live `wg set INTERFACE peer PUBLIC_KEY remove` alone is insufficient: restart
would reauthorize the old config. Do not restore a snapshot containing an old
peer inventory without reconciling every revocation.

For manual uninstall: stop/disable the three dedicated units, remove only the
exact generated WG config, WG per-instance drop-in, owned DNS/firewall units and
owned sysctl drop-in. Restore the original forwarding value only after comparing
it with the value this deployment set and considering other forwarding users.
Remove only `inet shadowborn` and `ip shadowborn_nat` after checking ownership.
Do not flush rulesets, uninstall shared dependencies or delete system logs. Use
the VM snapshot/console when ownership is ambiguous. After detaching the manual
network deployment, file-only `scripts/uninstall-server.sh` removes the package.
Configuration, encrypted backups and revocation state are deliberately retained.
