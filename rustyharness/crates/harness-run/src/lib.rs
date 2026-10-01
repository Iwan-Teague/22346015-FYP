//! The rustyharness run driver (design `docs/01-design-v0.1.md` §2.1-§2.6,
//! §2.8; H1 row of §9): session planning, the run loop, per-call
//! journaling. The embedding API for apps.
//!
//! [`run`] takes a task and runs it to a stop:
//!
//! 1. **Before anything is written** (a refusal here is
//!    `Indeterminate { CouldNotRun }`, nothing ran): plan the policy session
//!    (grants, trifecta, classes), build the tool definitions from the
//!    admitted capabilities, open the workspace (a real directory),
//!    canonicalise `state_root`, refuse a `state_root` inside the workspace
//!    or the reverse, run the filesystem-locality check (§2.8, INV-35; the
//!    caller supplies the probe, and `NoProbe` refuses every `state_root`),
//!    and measure the workspace facts.
//! 2. Create `runs/<run-id>` with `layout::create_run_dir` (the only way a
//!    run directory is made) and the first attempt with a durable journal
//!    header.
//! 3. **The loop** (§2.2 steps 1-10): charge the meter → build the context
//!    (§2.3) → call the model under the remaining wall budget → journal the
//!    request and reply → feed token usage to the meter → parse exactly one
//!    action → loop detection → policy decision (journaled with its rule) →
//!    write-ahead intent (`Journaled<Authorized<Call>>`) → run the tool →
//!    journal the result → stop checks.
//! 4. **Commit** (§7.1): `RunStopped` durable, then the outcome is released.
//!
//! **Every H1 outcome is `Indeterminate { NothingChecked }`** (INV-18): no
//! H1 task has checks, so nothing the agent does, submitting included, can
//! pass. A journal failure at any point after the header is
//! `Indeterminate { UnreadableEvidence }` (INV-33).
//!
//! Audit replay and resume are [`replay`]; the CLI verbs over both are
//! `harness-cli`.

#![forbid(unsafe_code)]
// The panic-set lints ratchet production code; unit tests may assert loosely.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

pub mod driver;
pub mod replay;
mod sample;

pub use driver::{run, ReadLog, Run, RunConfig, RunRefused, RunReport, StaleRead, TaskSpec};
pub use replay::{audit, resume, Audit, AuditRefused, AuditReport, Divergence, Resume};

#[cfg(test)]
mod tests;
