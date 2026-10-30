# CLI and JSON contract (schema 1)

`status --json`, `doctor --json` and `audit --json` return `Report` with:

| Field | Meaning |
| --- | --- |
| schema_version | Integer 1; incompatible report changes increment it |
| timestamp | Unix seconds at observation time (including cached daemon status) |
| profile | observe / balanced; strict is rejected until phase 2 |
| state | OBSERVE / UNPROTECTED / CONFIGURED / VERIFIED / UNCERTAIN / DEGRADED |
| dns | State, reason, scope and application-wide enforcement flag (false) |
| capabilities | Actual component availability, ownership, compatibility blockers |
| interfaces | Sanitized local devices; verbose adds effective/permanent MAC and addresses |
| findings | Code, INFO/WARN/HIGH/UNKNOWN severity, evidence and mitigation |
| limitations | Privacy scope and stop-versus-restore disclosure |
| redacted | Sensitive identifiers were removed |

`interfaces --json` and `identity status --json` return the interface array;
`dns status --json` returns the scoped DNS object. `apply --dry-run --json` returns
the actual plan, with prior/desired values and profile UUIDs redacted by default;
`--verbose` exposes them locally for review. Restore JSON lists transaction IDs,
state, attempted operation count and DNS scope without prior identifiers.

Exit codes: 0 success/observe/verified; 2 partial/configured/uncertain/unprotected/
degraded; 3 invalid input; 4 unsupported; 5 operation/auth/recovery failure.
Consumers must accept unknown additive fields within schema 1 and inspect state,
not just process success. No state means Internet anonymity or no application DNS
leaks. `VERIFIED` is fresh uncached resolution under required authenticated TLS;
normal passive status is at most `CONFIGURED` when policy matches.

Configuration schema 1 rejects unknown fields, unknown profiles, malformed TOML,
future versions and unsupported automatic rotation. Migration is explicit: retain
a backup, update version/keys using documented release instructions, validate,
review the plan, then apply. There is no implicit destructive schema migration.
