//! Deterministic seams for testing the MCP provider (feature `testing`,
//! P-37h).
//!
//! This module is deliberately tiny and PURE: the purity gate
//! (`scripts/ci/purity.sh` §2) scans every file of this package, so no
//! thread, pipe or process may be named here — not even under
//! `#[cfg(test)]` or `#[cfg(feature = "testing")]`. The real in-memory
//! connector (a server thread joined by channels, the shape the fixture
//! package's hostile suites already use) lives in
//! `harness-mcp-fixture`, which is a test double: unpublished, never a
//! dependency of shipped code, and outside the scan. No normal dependency
//! edge may enable this feature; the gate plants one and expects the
//! refusal (`testing_feature_not_enabled_by_normal_edges`).

use std::time::Duration;

use crate::client::Clock;

/// A clock whose deadlines are plain counters (feature `testing`):
/// `after` returns the budget's own millisecond count, so a scripted
/// transport can compare deadlines deterministically without a wall
/// behind it. Budgets are positive, so longer waits name larger
/// deadlines.
#[derive(Debug, Clone, Copy, Default)]
pub struct SeqClock;

impl Clock for SeqClock {
    type Time = u64;
    fn after(&self, budget: Duration) -> u64 {
        u64::try_from(budget.as_millis()).unwrap_or(u64::MAX)
    }
}
