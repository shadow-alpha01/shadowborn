use crate::*;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    Pending,
    Committed,
    RolledBack,
    Conflict,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Journal {
    pub schema_version: u32,
    pub id: String,
    pub state: TransactionState,
    pub changes: Vec<Change>,
    pub attempted: usize,
    pub error: Option<String>,
    pub dns_live: bool,
}
pub trait Adapter {
    fn read(&mut self, target: &Target) -> Result<String>;
    fn write(&mut self, target: &Target, value: &str) -> Result<()>;
    fn health(&mut self) -> Result<()>;
}
pub trait JournalStore {
    fn save(&mut self, journal: &Journal) -> Result<()>;
}

pub fn apply_transaction<A: Adapter, S: JournalStore>(
    adapter: &mut A,
    store: &mut S,
    p: &Plan,
    id: String,
) -> Result<Journal> {
    for c in &p.changes {
        if adapter.read(&c.target)? != c.before {
            bail!("preflight conflict: state changed after planning; no changes applied")
        }
    }
    let mut j = Journal {
        schema_version: SCHEMA_VERSION,
        id,
        state: TransactionState::Pending,
        changes: p.changes.clone(),
        attempted: 0,
        error: None,
        dns_live: p.dns_live,
    };
    store.save(&j)?;
    let result = (|| -> Result<()> {
        for (i, c) in j.changes.iter().enumerate() {
            if adapter.read(&c.target)? != c.before {
                bail!("concurrent configuration change; transaction cancelled")
            }
            j.attempted = i + 1;
            store.save(&j)?;
            adapter.write(&c.target, &c.after)?;
            if adapter.read(&c.target)? != c.after {
                bail!("post-write state verification failed")
            }
        }
        adapter.health().context("health check failed")?;
        j.state = TransactionState::Committed;
        store.save(&j)?;
        Ok(())
    })();
    if let Err(e) = result {
        j.error = Some("application or health verification failed; rollback requested".into());
        let rollback = restore_transaction(adapter, store, &mut j);
        return match rollback {
            Ok(()) => Err(e.context("DEGRADED: rolled back; previous/plaintext DNS may be active")),
            Err(r) => Err(e.context(format!(
                "DEGRADED: incomplete rollback; run restore from console: {r}"
            ))),
        };
    }
    Ok(j)
}
pub fn restore_transaction<A: Adapter, S: JournalStore>(
    adapter: &mut A,
    store: &mut S,
    j: &mut Journal,
) -> Result<()> {
    if j.schema_version != SCHEMA_VERSION || j.attempted > j.changes.len() {
        bail!("invalid transaction schema or operation count")
    }
    // A killed restore is recovered by the same pending-transaction path.
    j.state = TransactionState::Pending;
    store.save(j)?;
    let mut conflicts = 0;
    for c in j.changes[..j.attempted].iter().rev() {
        let result = (|| -> Result<()> {
            let current = adapter.read(&c.target)?;
            if current == c.before {
                return Ok(());
            }
            if current != c.after {
                bail!("restore conflict; administrator changes preserved")
            }
            adapter.write(&c.target, &c.before)?;
            if adapter.read(&c.target)? != c.before {
                bail!("restore verification failed")
            }
            Ok(())
        })();
        if result.is_err() {
            conflicts += 1;
        }
    }
    j.state = if conflicts == 0 {
        TransactionState::RolledBack
    } else {
        TransactionState::Conflict
    };
    store.save(j)?;
    if conflicts > 0 {
        bail!("{conflicts} restore conflicts/errors; unrelated current values were preserved")
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    #[test]
    fn partial_failure_rolls_back_completed_operations() {
        let (mut a, mut p) = fixture();
        let second = Target::Nm {
            uuid: "test".into(),
            key: "ipv6.dns".into(),
        };
        a.values.insert(second.clone(), "v6-old".into());
        p.changes.push(Change {
            target: second,
            before: "v6-old".into(),
            after: "v6-new".into(),
            reason: "second stage".into(),
        });
        a.fail_at = 2;
        let baseline = a.values.clone();
        let mut s = Memory::default();
        assert!(apply_transaction(&mut a, &mut s, &p, "1".into()).is_err());
        assert_eq!(a.values, baseline);
        assert_eq!(s.saved.last().unwrap().state, TransactionState::RolledBack);
    }
    #[test]
    fn failed_rollback_stays_conflicted_and_recoverable() {
        let (mut a, p) = fixture();
        a.unhealthy = true;
        a.fail_at = 2;
        let mut s = Memory::default();
        let error = apply_transaction(&mut a, &mut s, &p, "1".into()).unwrap_err();
        assert!(error.to_string().contains("incomplete rollback"));
        let mut j = s.saved.last().unwrap().clone();
        assert_eq!(j.state, TransactionState::Conflict);
        restore_transaction(&mut a, &mut s, &mut j).unwrap();
        assert_eq!(a.read(&p.changes[0].target).unwrap(), "old");
    }
    #[derive(Default)]
    struct Fake {
        values: BTreeMap<Target, String>,
        writes: usize,
        fail_at: usize,
        unhealthy: bool,
    }
    impl Adapter for Fake {
        fn read(&mut self, t: &Target) -> Result<String> {
            Ok(self.values.get(t).cloned().unwrap_or_default())
        }
        fn write(&mut self, t: &Target, v: &str) -> Result<()> {
            self.writes += 1;
            if self.writes == self.fail_at {
                bail!("injected failure")
            };
            self.values.insert(t.clone(), v.into());
            Ok(())
        }
        fn health(&mut self) -> Result<()> {
            if self.unhealthy {
                bail!("blocked 853 / offline / bad certificate / endpoint unavailable")
            };
            Ok(())
        }
    }
    #[derive(Default)]
    struct Memory {
        saved: Vec<Journal>,
    }
    impl JournalStore for Memory {
        fn save(&mut self, j: &Journal) -> Result<()> {
            self.saved.push(j.clone());
            Ok(())
        }
    }
    fn fixture() -> (Fake, Plan) {
        let target = Target::Nm {
            uuid: "test".into(),
            key: "ipv4.dns".into(),
        };
        (
            Fake {
                values: [(target.clone(), "old".into())].into(),
                ..Fake::default()
            },
            Plan {
                changes: vec![Change {
                    target,
                    before: "old".into(),
                    after: "new".into(),
                    reason: "test".into(),
                }],
                dns_live: true,
                ..Plan::default()
            },
        )
    }
    #[test]
    fn apply_restore_and_idempotence() {
        let (mut a, p) = fixture();
        let mut s = Memory::default();
        let mut j = apply_transaction(&mut a, &mut s, &p, "1".into()).unwrap();
        assert_eq!(s.saved[0].attempted, 0);
        assert_eq!(s.saved[1].attempted, 1);
        assert_eq!(j.state, TransactionState::Committed);
        restore_transaction(&mut a, &mut s, &mut j).unwrap();
        assert_eq!(a.read(&p.changes[0].target).unwrap(), "old");
        let writes = a.writes;
        restore_transaction(&mut a, &mut s, &mut j).unwrap();
        assert_eq!(a.writes, writes);
    }
    #[test]
    fn rollback_failure_and_negative_dns() {
        for fail in [true, false] {
            let (mut a, p) = fixture();
            a.unhealthy = fail;
            a.fail_at = if fail { 0 } else { 1 };
            let mut s = Memory::default();
            assert!(apply_transaction(&mut a, &mut s, &p, "1".into()).is_err());
            assert_eq!(a.read(&p.changes[0].target).unwrap(), "old");
            assert_eq!(s.saved.last().unwrap().state, TransactionState::RolledBack);
        }
    }
    #[test]
    fn third_party_conflict_is_preserved() {
        let (mut a, p) = fixture();
        let mut s = Memory::default();
        let mut j = apply_transaction(&mut a, &mut s, &p, "1".into()).unwrap();
        a.values.insert(p.changes[0].target.clone(), "admin".into());
        assert!(restore_transaction(&mut a, &mut s, &mut j).is_err());
        assert_eq!(a.read(&p.changes[0].target).unwrap(), "admin");
        assert_eq!(j.state, TransactionState::Conflict);
    }
    #[test]
    fn interrupted_pending_recovers() {
        let (mut a, p) = fixture();
        let mut s = Memory::default();
        a.values.insert(p.changes[0].target.clone(), "new".into());
        let mut j = Journal {
            schema_version: 1,
            id: "crash".into(),
            state: TransactionState::Pending,
            changes: p.changes,
            attempted: 1,
            error: None,
            dns_live: true,
        };
        restore_transaction(&mut a, &mut s, &mut j).unwrap();
        assert_eq!(j.state, TransactionState::RolledBack);
    }
    #[test]
    fn stale_plan_makes_zero_changes() {
        let (mut a, p) = fixture();
        a.values.insert(p.changes[0].target.clone(), "admin".into());
        let mut s = Memory::default();
        assert!(apply_transaction(&mut a, &mut s, &p, "1".into()).is_err());
        assert_eq!(a.writes, 0);
        assert!(s.saved.is_empty());
    }
}
