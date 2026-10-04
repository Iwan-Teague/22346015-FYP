//! Audit replay (design §2.9, INV-20) and resume (§2.10).
//!
//! Both re-drive the SAME loop as a live run over what a journal recorded:
//! the recorded model replies through `ReplayBackend` (which re-renders each
//! request and refuses one whose digest differs), the recorded tool results
//! in place of running the tools, and the recorded observation nonces (each
//! journaled once, with the request that first showed its observation, and
//! re-fed by the observation's step: design row H1i), so every request
//! renders byte for byte. Everything else is recomputed: the context (its
//! digest is journaled as `ContextBuilt`), which observations and replies
//! are withheld, the parse, loop detection, every policy decision, the
//! meter.
//!
//! **Audit** ([`audit`]) writes what it recomputes into a fresh journal,
//! `runs/<run-id>/replay-<k>/`, next to the attempts (never inside one),
//! then compares it with the recorded attempt record by record (kind, step
//! and body; the time fields and the header's own run-specific fields
//! excepted). The first difference is reported with its record and step,
//! and the audit's outcome is `Indeterminate { UnreadableEvidence }`. A
//! journal that does not verify, belongs to another run or attempt, or
//! does not match a caller-supplied chain head (the anchor) is the same.
//! The header inputs, the budget limits among them, are the CALLER's and
//! must equal the recorded ones: the replay recomputes every budget stop
//! from the limits, so limits read from the journal would let a re-chained
//! edit choose the stop it then "recomputes" (H1 phase-exit review F-1).
//! Two recorded facts are not recomputable and are handled explicitly:
//! - **wall time.** A `BudgetCharged` record for the `wall` dimension is
//!   left out of the comparison on both sides, and the replay's meter has
//!   no wall limit. What is left out must be exactly what the loop writes
//!   for the wall dimension: at most one record per attempt, the entry
//!   `{condition: enter, key: wall}` (wall time never decreases within an
//!   attempt, so the loop never writes a wall exit; H1g confirming review
//!   NF-1); anything else is a divergence, and how many were left out is
//!   reported
//!   (`AuditReport::wall_skipped`). A run stopped by the wall budget can
//!   only be checked up to its last record: every recorded record must
//!   match, but the stop itself is NOT recomputed
//!   (`AuditReport::stop_recomputed` is false). Since a journal cut at any
//!   step boundary and ended with a forged wall stop, re-chained, looks
//!   exactly the same (H1e-2b review F-1), such an audit is
//!   `Indeterminate { UnreadableEvidence }` unless the caller's anchor
//!   matched the journal's chain head; only the anchor proves that nothing
//!   was removed.
//! - **the workspace.** Audit mode re-feeds tool output; it never reads the
//!   workspace. The workspace facts come from the recorded header.
//!
//! **Sessions (P-17).** [`audit_session`] re-drives a session attempt the
//! same way, with the session loop instead of the batch one: the recorded
//! `UserTurn`s are re-fed in exactly what the clock cannot recompute (the
//! text, the facts the turn was measured with, its wall time) and each
//! `InputEnded` by its reason, while everything else is recomputed and
//! compared — the turn boundaries (`TurnEnded`), the per-turn allowances
//! and notices, whether the workspace changed between turns, the shown
//! decisions. Where the recorded inputs run out (an attempt a crash cut),
//! the replay stops `Cancelled` and only the recorded prefix is compared.
//! A session journal's records in a batch audit are a divergence ("not a
//! shape the loop writes"), and the batch audit refuses a session journal
//! at its header's `mode`.
//!
//! **Resume** ([`resume`]) continues an attempt that has no `RunStopped`
//! (a crash or a kill) in a NEW attempt directory: the old journal is only
//! read, never appended to, poisoned or not. Its header records the attempt
//! it continues and that journal's chain head. The new attempt first
//! replays every COMPLETED step of the old one (catch-up: recorded
//! replies, tool results, edits and approvals re-fed; each model request
//! the catch-up renders must have its recorded digest, but the other
//! records it recomputes are NOT compared with the old attempt's: to check
//! those, audit the old attempt, `replay --attempt <n>`; H1 phase-exit
//! review F-3). A step is completed when its call has a durable
//! `ToolFinished` (H2b, the H1e-2b row's H2 condition): it is re-fed and
//! never run again, so a completed edit is never repeated. Only a last step
//! the crash cut (a trailing intent without a result, or no call yet) runs
//! again live, so policy decides it again, never executing it blindly. A
//! request that differs makes the resumed run `Indeterminate
//! { UnreadableEvidence }`. The header inputs, the budget limits included,
//! must equal the recorded ones, and the approver's presence too, or the
//! resume is refused. The harness keeps no content snapshot to restore
//! (materialisation, H2), so the snapshot of §2.10 is a tree digest: the
//! workspace must hold the one the kept records end with (the last
//! `EditApplied`'s, or the header's), and a resume is refused otherwise
//! (an edit applied without its result, or a change made outside the run).
//! The resumed header carries the run-start facts, so block 4 renders as
//! it did. An attempt with no header (a start that failed) and a resumed
//! attempt that stopped at its header are passed over and named (H1
//! phase-exit review F-5).
//! The wall time the interrupted attempt spent (its journal's last
//! monotonic time, the writer's elapsed time) is charged to the resumed
//! attempt's meter from the start, so a kill and resume buys no fresh wall
//! budget up to the interrupted attempt's last durable record; the time
//! after it, up to one model call (300 s by default), is not charged, so
//! each kill and resume can regain that much (H1 phase-exit review F-13).
//! Steps and tokens are re-charged by the catch-up. That wall time
//! is taken from the interrupted attempt's journal (the header's
//! `resumed_from.wall_carried_ms` and the last record's `t_mono_ms`). An
//! interrupted attempt has no printed chain head, and resume takes no
//! anchor, so a consistent edit made to it before the resume is not
//! detected; after it, the resumed header's `resumed_from.chain_head` pins
//! what was resumed from, and an anchored audit of the resumed attempt
//! covers that (H1g confirming review NF-2).
// The replay is split by concern: what a journal recorded (feed), the
// header and record comparison (compare), the audit replay (audit) and
// the resume (resume). The public paths are unchanged: everything the
// crate re-exports is re-exported below, from the submodules.
pub(crate) mod audit;
pub(crate) mod compare;
pub(crate) mod feed;
pub(crate) mod fork;
pub(crate) mod resume;

pub use audit::{audit, audit_session, Audit, AuditRefused, AuditReport};
pub use compare::Divergence;
pub use fork::{fork_session, ForkSession};
pub use resume::{resume, resume_session, Resume, ResumeSession};
