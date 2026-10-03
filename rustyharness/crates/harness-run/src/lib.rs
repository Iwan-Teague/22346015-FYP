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
//!    action → loop detection (keyed by the workspace tree digest too) →
//!    policy decision (journaled with its rule) → for an ask, the approver
//!    ([`approve`], §5.3) → write-ahead intent
//!    (`Journaled<Authorized<Call>>`) → run the tool (the provider that
//!    serves its capability: the read tools, or the edit tools, anchored on
//!    the run's reads) → journal the result (a verified edit's
//!    `EditApplied` first, with the tree digest after it) → stop checks.
//!    A task with pre-submit checks ([`presubmit`], H3a) runs them when the
//!    model submits, and turns a failing submission back for a bounded
//!    number of rounds.
//! 4. **Commit** (§7.1): `RunStopped` durable, then the outcome is released.
//!
//! **Every outcome so far is `Indeterminate { NothingChecked }`** (INV-18):
//! no task has checks yet (H3), so nothing the agent does, editing and
//! submitting included, can pass. A journal failure at any point after the
//! header is `Indeterminate { UnreadableEvidence }` (INV-33).
//!
//! **Edits (H2b)** change the task's workspace in place: there is no
//! sandbox around them and no content snapshot to restore, so a built-in
//! edit asks unless the caller's policy allows it (§5.2 as this build
//! applies it), and with no approver it is denied.
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

pub mod approve;
pub mod driver;
pub mod presubmit;
pub mod replay;
pub mod restore;
mod sample;
pub mod scratch;
pub mod session;

pub use approve::{ApprovalAnswer, Approver, ApproverKind};
pub use driver::{
    run, ReadLog, Run, RunConfig, RunRefused, RunReport, StaleRead, TaskSpec, WorkspaceModeRecord,
};
/// Re-exported: a `TaskSpec`'s `kind` field names it (P-39i), so an
/// embedder builds specs without a direct `harness-policy` dependency.
pub use harness_policy::SessionKind;
pub use harness_tools::{plain_name, ExecLimits, ExecProgram, ExecSpec, MAX_PROGRAMS};
pub use presubmit::{PresubmitRefused, PresubmitReport, PresubmitResult, PresubmitSpec};
pub use replay::{
    audit, audit_session, resume, resume_session, Audit, AuditRefused, AuditReport, Divergence,
    Resume, ResumeSession,
};
pub use restore::{external_differ, marks_from_records, plan, RestoreCommand, RestoreMark};
pub use session::{
    run_research, run_session, EventSink, InputEnd, ResearchRun, SessionConfig, SessionReport,
    SessionRun, TurnLimits, UiEvent, UserInput, UserInputEvent, UserMessage, UserMessageRefused,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod context_tests;

#[cfg(test)]
mod presubmit_tests;
