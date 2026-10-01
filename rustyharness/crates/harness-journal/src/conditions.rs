//! Standing conditions, journaled once per state change (design §2.6,
//! R3 H-14). Pure: no I/O.
//!
//! A standing condition (`Quarantined`, `SandboxUnavailable`, a budget
//! dimension above 80%) is observed every step. It produces a record only
//! when it BEGINS and when it ENDS; the exit record carries how many
//! observations fell inside the episode. Observing an unchanged state
//! writes nothing.

use std::collections::BTreeMap;

use crate::canon::{EventKind, Ident};
use crate::event::{Event, Trusted};

/// Which standing condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConditionKind {
    /// A capability is quarantined (pin drift, H4).
    Quarantined,
    /// No conformed sandbox (H2).
    SandboxUnavailable,
    /// A budget dimension has crossed 80% of its limit.
    BudgetAbove80,
}

impl ConditionKind {
    fn event_kind(self) -> EventKind {
        match self {
            ConditionKind::Quarantined => EventKind::Quarantined,
            ConditionKind::SandboxUnavailable => EventKind::SandboxUnavailable,
            ConditionKind::BudgetAbove80 => EventKind::BudgetCharged,
        }
    }
}

/// A condition instance: its kind plus what it is about (a capability id,
/// a reason code, a budget dimension).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Condition {
    /// Kind.
    pub kind: ConditionKind,
    /// Subject.
    pub key: Ident,
}

/// Tracks which conditions are active and how many observations each
/// active episode has seen.
#[derive(Debug, Clone, Default)]
pub struct StandingConditions {
    active: BTreeMap<Condition, u64>,
}

impl StandingConditions {
    /// Record one observation. Returns the event to journal, or `None` when
    /// the state did not change.
    pub fn observe(&mut self, c: &Condition, now_active: bool) -> Option<Event> {
        let was = self.active.get_mut(c);
        match (was, now_active) {
            (None, false) => None,
            (Some(n), true) => {
                *n = n.saturating_add(1);
                None
            }
            (None, true) => {
                self.active.insert(c.clone(), 1);
                Some(
                    Event::new(c.kind.event_kind())
                        .field("condition", Trusted::Text("enter"))
                        .field("key", Trusted::Id(c.key.clone())),
                )
            }
            (Some(n), false) => {
                let count = *n;
                self.active.remove(c);
                Some(
                    Event::new(c.kind.event_kind())
                        .field("condition", Trusted::Text("exit"))
                        .field("key", Trusted::Id(c.key.clone()))
                        .field("affected", Trusted::U64(count)),
                )
            }
        }
    }

    /// Whether `c` is currently active.
    pub fn is_active(&self, c: &Condition) -> bool {
        self.active.contains_key(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journaled_once_on_entry_and_once_on_exit_with_the_count() {
        let mut s = StandingConditions::default();
        let q = Condition {
            kind: ConditionKind::Quarantined,
            key: Ident::of("fixture.item.read").unwrap(),
        };
        assert!(s.observe(&q, false).is_none(), "inactive and unchanged");
        let enter = s.observe(&q, true).expect("entry is journaled");
        assert_eq!(enter.kind(), EventKind::Quarantined);
        for _ in 0..40 {
            assert!(
                s.observe(&q, true).is_none(),
                "a standing condition is not re-journaled"
            );
        }
        let exit = s.observe(&q, false).expect("exit is journaled");
        assert_eq!(
            exit.body().unwrap().get("affected"),
            Some(&serde_json::Value::from(41u64))
        );
        assert!(s.observe(&q, false).is_none());
        // A second episode is a new entry.
        assert!(s.observe(&q, true).is_some());
    }

    #[test]
    fn conditions_are_tracked_independently() {
        let mut s = StandingConditions::default();
        let a = Condition {
            kind: ConditionKind::SandboxUnavailable,
            key: Ident::of("userns-disabled").unwrap(),
        };
        let b = Condition {
            kind: ConditionKind::BudgetAbove80,
            key: Ident::of("tokens").unwrap(),
        };
        assert!(s.observe(&a, true).is_some());
        assert!(s.observe(&b, true).is_some());
        assert!(s.observe(&a, true).is_none());
        assert!(s.observe(&b, false).is_some());
        assert!(s.is_active(&a) && !s.is_active(&b));
    }
}
