//! The driver's half of the background processes (P-36j, P-36 §5.1, §5.2):
//! the loop's [`Loop::bg`] manager seam, and the journal records that keep
//! the audit's liveness recomputation exact (§11.2, INV-40).
//!
//! **Why the driver owns the records.** The tools own the children (only
//! [`BgTools`] holds them); the loop owns the journal. At every point a
//! process's life ends outside `harness.exec.stop` — it exits on its own,
//! its lifetime runs out, the turn, session or run ends — the driver polls
//! or stops through the seam and journals one `BgStopped` per id *before*
//! the terminal record that closes its scope (`TurnEnded`, `InputEnded`,
//! `RunStopped`), so the journal state always precedes the acts (§5.2).
//!
//! **Escalation.** A sweep that cannot confirm its kill domain is a
//! process possibly alive outside the harness's view (§5.1): the stop cause
//! becomes [`StopCause::SandboxLost`] unless it is already at least as
//! hard (a journal failure leaves nothing to journal into, and the
//! `Drop` of the children is then the backstop — the kill still happens,
//! only the record cannot).

use harness_core::StopCause;
use harness_journal::{BlobSink, Clock, Event, EventKind, JournalFile, JournalWriter, Trusted};
use harness_tools::{BgExit, ExecCleanup, ExecEnd};

use super::step::{journal, Loop};
use super::tools::{bg_cleanup_obj, bg_end_obj};

impl<'a> Loop<'a> {
    /// The poll (P-36 §5.2): every live id the sandbox already has an exit
    /// for gets its `BgStopped` record — the reason `exited`, or `lifetime`
    /// when the closer thread fired (`end` timed out) — so the journal
    /// state precedes the step's acts. Called at the start of every step
    /// (before the context is built) and before every `harness.exec.start`
    /// decision, so a start never runs while an unobserved exit sits in
    /// the journal's future.
    pub(crate) fn bg_poll<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
        step: u64,
    ) -> Result<(), StopCause> {
        let Some(bg) = self.bg.as_mut() else {
            return Ok(());
        };
        for x in bg.poll() {
            bg_stopped(w, step, &x, exit_reason(&x.end))?;
        }
        Ok(())
    }

    /// The turn-scope stop (P-36 §5.1): before the session loop writes
    /// `TurnEnded`, every live turn-scoped id is swept and journaled
    /// `reason: "turn_end"`. Session-scoped ids survive (they exist only
    /// under `bg.persist`, and stop when the session does).
    pub(crate) fn bg_turn_end<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
    ) -> Result<(), StopCause> {
        let Some(bg) = self.bg.as_mut() else {
            return Ok(());
        };
        for x in bg.stop_live(true) {
            bg_stopped(w, self.step, &x, "turn_end")?;
        }
        Ok(())
    }

    /// The run's or the session's end stop (P-36 §5.1): every remaining
    /// live id is polled (the ones already gone get their own reason),
    /// then swept — the exits journaled first, then the stops, then the
    /// tree is measured once more by the caller's commit path. The cause
    /// is returned, escalated to [`StopCause::SandboxLost`] when any sweep
    /// ended unconfirmed (§3.3: a process may have survived the kill
    /// domain) and the cause is not already at least as hard.
    ///
    /// `session` names the scope the records carry: a session's end says
    /// `session_end` (it is `InputEnded` that closes it), everything else
    /// a batch run's `RunStopped` names from the cause (`budget`, or
    /// `run_end`; a sandbox loss says `sandbox_lost`). A poisoned writer
    /// or a journal-failure cause journals nothing — the children are
    /// still stopped, and their `Drop` is the backstop kill (§5.1).
    pub(crate) fn bg_halt<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
        cause: StopCause,
        session: bool,
    ) -> StopCause {
        let Some(bg) = self.bg.as_mut() else {
            return cause;
        };
        let step = self.step;
        // Nothing can be journaled: stop everything, kill on `Drop`, and
        // let the cause stand (a journal failure is the harder stop).
        if w.is_poisoned() || matches!(cause, StopCause::JournalUnavailable { .. }) {
            bg.stop_live(false);
            return cause;
        }
        let reason = halt_reason(&cause, session);
        let mut unconfirmed = false;
        let mut result = Ok(());
        for x in bg.poll() {
            unconfirmed |= matches!(x.cleanup, ExecCleanup::Unconfirmed);
            if result.is_ok() {
                result = bg_stopped(w, step, &x, exit_reason(&x.end));
            }
        }
        for x in bg.stop_live(false) {
            unconfirmed |= matches!(x.cleanup, ExecCleanup::Unconfirmed);
            if result.is_ok() {
                result = bg_stopped(w, step, &x, reason);
            }
        }
        if let Err(e) = result {
            // The journal broke mid-stop: whatever is still live is swept
            // unjournaled, and the run ends as a journal failure.
            bg.stop_live(false);
            return e;
        }
        if unconfirmed && !matches!(cause, StopCause::SandboxLost) {
            return StopCause::SandboxLost;
        }
        cause
    }
}

/// The record's reason for an id the poll observed to end: a lifetime
/// closer's timed-out end is the lifetime firing (§5.1); anything else the
/// process exited on its own.
fn exit_reason(end: &ExecEnd) -> &'static str {
    match end {
        ExecEnd::TimedOut => "lifetime",
        _ => "exited",
    }
}

/// The record's reason for a halt sweep, from the stop cause and the scope
/// that is closing (§5.1): any budget stop is `budget`; a sandbox loss is
/// `sandbox_lost`; the session's end is `session_end`; every other batch
/// stop (submit accepted, context exhausted, loop stop, policy abort) is
/// `run_end`.
fn halt_reason(cause: &StopCause, session: bool) -> &'static str {
    match cause {
        StopCause::Budget(_) => "budget",
        StopCause::SandboxLost => "sandbox_lost",
        _ if session => "session_end",
        _ => "run_end",
    }
}

/// One `BgStopped` record (P-36 §10.2, INV-40): the id, why it stopped,
/// how it ended and whether its kill domain is confirmed swept, and the
/// whole-stream totals and digests the journal commits to without storing
/// the bytes. Exactly one per id, its last record (§10).
fn bg_stopped<F: JournalFile, B: BlobSink, K: Clock>(
    w: &mut JournalWriter<F, B, K>,
    step: u64,
    x: &BgExit,
    reason: &'static str,
) -> Result<(), StopCause> {
    let ev = Event::new(EventKind::BgStopped)
        .field("id", Trusted::U64(u64::from(x.id)))
        .field("reason", Trusted::Text(reason))
        .field("end", bg_end_obj(x.end))
        .field("cleanup", bg_cleanup_obj(x.cleanup))
        .field("out_total", Trusted::U64(x.out_total))
        .field("err_total", Trusted::U64(x.err_total))
        .field("out_sha", Trusted::Digest(x.out_sha))
        .field("err_sha", Trusted::Digest(x.err_sha));
    w.append(step, ev).map_err(journal)?;
    Ok(())
}
