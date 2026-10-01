//! Pre-submit checks (design rows H3a).
//!
//! A task may declare commands the harness runs, in the sandbox, when the
//! model calls `harness.task.submit`: `cargo build`, `cargo test`. If one
//! fails the submission is not accepted: the model is shown that check's
//! output as an observation (delimited by its own nonce like any other) with
//! a harness notice, and goes on, for at most `max_rounds` submissions that
//! a failing check turns back. After that a submission is accepted and the
//! run records that a check still failed (`StopCause::SubmittedChecksFailed`),
//! never a plain `Submitted`.
//!
//! **This is not the H3 verification** (design §2.5, §7.3). The commands run
//! in the agent's own workspace, under the same sandbox and the same policy
//! as the model's `harness.exec.run`, at the model's request to submit, and
//! their result decides only whether the harness turns the submission back.
//! The outcome of a run is still `Indeterminate { NothingChecked }` (INV-18):
//! no pristine grading worktree, protected paths or hidden checks are involved.
//!
//! What is journaled, in the submit step (records of the same step, in order):
//! `SubmitRequested`; then, for each check that ran, its `PolicyDecided`,
//! approval records if it asked, and an ordinary `harness.exec.run`
//! `ToolStarted` (write-ahead) and `ToolFinished` (with `exec` and the tree
//! measured after it), which replay and resume re-feed exactly like a
//! command the model ran; then one `PresubmitChecked`; then the submit's own
//! `ToolFinished` (`error`, code 22 when the submission was turned back).

use std::time::Instant;

use gate_outcome::Digest;
use harness_core::{sha256, LoopEvent, StopCause, Untrusted};
use harness_journal::{
    BlobSink, Clock, Event, EventKind, Ident, JournalFile, JournalWriter, Trusted,
};
use harness_model::context::{presubmit_notice, PresubmitRejected};
use harness_model::HarnessText;
use harness_policy::{Call, PolicyDecision, EXEC_ID};
use harness_tools::builtin::WorkspaceTree;
use harness_tools::{ExecCleanup, ExecEnd, ExecSpec, InvokeCtx, ToolError, ToolStatus};
use serde_json::{json, Value};

use crate::driver::step::{journal, Loop};
use crate::driver::stop::decided;
use crate::driver::tools::{exec_fields, status_name};
use crate::sample;

/// Most commands a task may declare.
pub const MAX_CHECKS: usize = 4;
/// Most arguments of one command.
pub const MAX_ARGS: usize = 32;
/// Longest argument of a command, in bytes.
pub const MAX_ARG_BYTES: usize = 1024;
/// Most submissions a failing check may turn back.
pub const MAX_ROUNDS: u32 = 5;
/// How many submissions a failing check turns back when the task does not
/// say.
pub const DEFAULT_ROUNDS: u32 = 2;

/// A task's pre-submit checks (design rows H3a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresubmitSpec {
    /// The commands, run in order in the workspace's sandbox; each an argv
    /// whose first item is a program name on the task's exec allowlist.
    pub commands: Vec<Vec<String>>,
    /// The most submissions a failing check turns back (1 to
    /// [`MAX_ROUNDS`]); the next submission is accepted whatever its checks
    /// say, and a failing check is recorded.
    pub max_rounds: u32,
}

/// Why a task's pre-submit checks are refused: nothing ran, nothing was
/// journaled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PresubmitRefused {
    /// The checks are commands in the sandbox, so the task must grant the
    /// command runner (and give its allowlist).
    #[error("presubmit needs the task to grant harness.exec.run and give an exec section")]
    NoExec,
    /// No commands, or more than [`MAX_CHECKS`].
    #[error("presubmit.commands must hold 1 to {MAX_CHECKS} commands")]
    Commands,
    /// A command is empty, too long, or holds a NUL.
    #[error(
        "presubmit command {0} must be 1 to {MAX_ARGS} arguments of at most {MAX_ARG_BYTES} bytes without NUL"
    )]
    Argv(usize),
    /// A command's program is not a name on the exec allowlist.
    #[error("presubmit command {0} does not start with a program name on the exec allowlist")]
    Program(usize),
    /// `max_rounds` out of range.
    #[error("presubmit.max_rounds must be from 1 to {MAX_ROUNDS}")]
    Rounds,
    /// The policy denies a command: it would never run (an unattended task
    /// needs the allow rule for `harness.exec.run`, as for the model's own
    /// commands).
    #[error("the policy denies presubmit command {0}; nothing would run")]
    Denied(usize),
}

impl PresubmitSpec {
    /// The structural rules, given the task's grants and its exec setup:
    /// commands and rounds are bounded, and every command names a program on
    /// the allowlist. Policy is checked by the session (see [`Self::call`]).
    pub fn check(
        &self,
        grants: &[String],
        exec: Option<&ExecSpec>,
    ) -> Result<(), PresubmitRefused> {
        let Some(exec) = exec.filter(|_| grants.iter().any(|g| g == EXEC_ID)) else {
            return Err(PresubmitRefused::NoExec);
        };
        if self.commands.is_empty() || self.commands.len() > MAX_CHECKS {
            return Err(PresubmitRefused::Commands);
        }
        if !(1..=MAX_ROUNDS).contains(&self.max_rounds) {
            return Err(PresubmitRefused::Rounds);
        }
        let names = exec.names();
        for (i, argv) in self.commands.iter().enumerate() {
            let n = i + 1;
            if argv.is_empty()
                || argv.len() > MAX_ARGS
                || argv
                    .iter()
                    .any(|a| a.len() > MAX_ARG_BYTES || a.contains('\0'))
            {
                return Err(PresubmitRefused::Argv(n));
            }
            if argv.first().is_none_or(|p| !names.contains(p)) {
                return Err(PresubmitRefused::Program(n));
            }
        }
        Ok(())
    }

    /// The call of check `index` (0-based): exactly what the model would
    /// send to run the same command, so policy decides it the same way.
    pub(crate) fn call(&self, index: usize) -> Option<Call> {
        Some(Call {
            capability: EXEC_ID.to_owned(),
            args: json!({ "argv": self.commands.get(index)? }),
        })
    }

    /// SHA-256 over everything the spec says, in one canonical encoding
    /// (the journal header's `presubmit` input: an audit or a resume must be
    /// given the same checks).
    pub fn digest(&self) -> Digest {
        let v = json!({
            "format": "rh-presubmit/1",
            "commands": self.commands,
            "max_rounds": self.max_rounds,
        });
        sha256(v.to_string().as_bytes())
    }

    /// The header's `presubmit` object (comparable with a recorded one).
    pub(crate) fn header_value(&self) -> Value {
        json!({
            "spec": self.digest().to_string(),
            "commands": self.commands.len() as u64,
            "max_rounds": u64::from(self.max_rounds),
        })
    }
}

// ---------------------------------------------------------------------------
// What a run does with them.
// ---------------------------------------------------------------------------

/// How the checks of one submission ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresubmitResult {
    /// Every command ran and exited with status 0.
    Passed,
    /// A command did not exit with status 0 (a non-zero status, a signal, a
    /// timeout, a program that could not start): the commands after it did
    /// not run.
    Failed,
    /// A command was not run: the policy denied it, an approver declined it
    /// or did not answer, or no provider could run it. Nothing the model can
    /// repair, so the submission is accepted, and this is recorded.
    NotRun,
}

impl PresubmitResult {
    /// The name the journal records.
    pub fn name(self) -> &'static str {
        match self {
            PresubmitResult::Passed => "passed",
            PresubmitResult::Failed => "failed",
            PresubmitResult::NotRun => "not_run",
        }
    }
}

/// What a run that has pre-submit checks did with them, for its report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresubmitReport {
    /// The task's bound on submissions a failing check turns back.
    pub max_rounds: u32,
    /// Submissions that ran the checks.
    pub submissions: u32,
    /// Submissions a failing check turned back.
    pub turned_back: u32,
    /// How the last submission's checks ended; `None`: the run stopped
    /// before it submitted.
    pub last: Option<PresubmitResult>,
}

/// The pre-submit state of a loop: the checks, and how many submissions ran
/// them and were turned back so far.
#[derive(Debug)]
pub(crate) struct PresubmitState {
    spec: PresubmitSpec,
    submissions: u32,
    turned_back: u32,
    last: Option<PresubmitResult>,
}

impl PresubmitState {
    /// The state of a run whose task has these checks (none: none).
    pub(crate) fn of(spec: &Option<PresubmitSpec>) -> Option<Self> {
        spec.as_ref().map(|s| Self {
            spec: s.clone(),
            submissions: 0,
            turned_back: 0,
            last: None,
        })
    }

    /// The report so far.
    pub(crate) fn report(&self) -> PresubmitReport {
        PresubmitReport {
            max_rounds: self.spec.max_rounds,
            submissions: self.submissions,
            turned_back: self.turned_back,
            last: self.last,
        }
    }
}

/// One command's end, as the round sees it.
enum CheckRun {
    Passed,
    Failed {
        body: Untrusted<String>,
        digest: Digest,
    },
    NotRun,
}

/// A submission a failing check turned back: what the model is shown.
pub(crate) struct TurnedBack {
    /// The harness's message (static words, numbers and the task's command).
    pub(crate) notice: HarnessText,
    /// The failing command's output: an observation, delimited by its own
    /// nonce like any other.
    pub(crate) body: Untrusted<String>,
    /// SHA-256 of that output.
    pub(crate) digest: Digest,
}

/// How a submission's checks ended, and, when a failing check turned it
/// back, what the model is told.
pub(crate) struct Round {
    pub(crate) result: PresubmitResult,
    pub(crate) turned_back: Option<TurnedBack>,
}

impl<'a> Loop<'a> {
    /// Run the task's checks for the submission of step `step` (see the
    /// module docs). The checks run in order, each as the `harness.exec.run`
    /// call the model would make for the same argv: decided by policy (an ask
    /// goes to the approver, and is recorded like any), journaled ahead of
    /// its run, re-fed from the journal by an audit and by a resume's
    /// catch-up (never run again), its tree measured after it. The first
    /// command that fails ends the round. `Err` is a stop: a journal
    /// failure, a sandbox that cannot confirm a command left nothing behind,
    /// or the wall budget.
    pub(crate) fn presubmit_round<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
        step: u64,
    ) -> Result<Round, StopCause> {
        let spec = self
            .presubmit
            .as_ref()
            .ok_or(StopCause::PolicyAbort)?
            .spec
            .clone();
        let (mut ran, mut result, mut at, mut failed) = (0u64, PresubmitResult::Passed, 0u64, None);
        for i in 0..spec.commands.len() {
            let call = spec.call(i).ok_or(StopCause::PolicyAbort)?;
            match self.run_check(w, step, call)? {
                CheckRun::Passed => ran += 1,
                CheckRun::Failed { body, digest } => {
                    (ran, result, at, failed) = (
                        ran + 1,
                        PresubmitResult::Failed,
                        i as u64 + 1,
                        Some((body, digest)),
                    );
                    break;
                }
                CheckRun::NotRun => {
                    (result, at) = (PresubmitResult::NotRun, i as u64 + 1);
                    break;
                }
            }
        }
        let state = self.presubmit.as_mut().ok_or(StopCause::PolicyAbort)?;
        state.submissions += 1;
        // A failing check turns the submission back until the bound is
        // spent; then it is accepted, and the failure is recorded.
        let back = result == PresubmitResult::Failed && state.turned_back < spec.max_rounds;
        state.turned_back += u32::from(back);
        state.last = Some(result);
        let (submissions, turned_back) = (state.submissions, state.turned_back);
        let mut ev = Event::new(EventKind::PresubmitChecked)
            .field("round", Trusted::U64(u64::from(submissions)))
            .field("checks", Trusted::U64(spec.commands.len() as u64))
            .field("ran", Trusted::U64(ran))
            .field("result", Trusted::Text(result.name()));
        if at > 0 {
            ev = ev.field("check", Trusted::U64(at));
        }
        ev = ev
            .field("turned_back", Trusted::U64(u64::from(turned_back)))
            .field("accepted", Trusted::Bool(!back));
        w.append(step, ev).map_err(journal)?;
        let turned_back = match (back, failed) {
            (false, _) => None,
            (true, Some((body, digest))) => {
                let argv = usize::try_from(at)
                    .ok()
                    .and_then(|n| n.checked_sub(1))
                    .and_then(|n| spec.commands.get(n))
                    .ok_or(StopCause::PolicyAbort)?;
                Some(TurnedBack {
                    notice: presubmit_notice(
                        self.profile.protocol(),
                        &PresubmitRejected {
                            check: at,
                            checks: spec.commands.len() as u64,
                            argv,
                            round: u64::from(turned_back),
                            max_rounds: u64::from(spec.max_rounds),
                        },
                    ),
                    body,
                    digest,
                })
            }
            (true, None) => return Err(StopCause::PolicyAbort),
        };
        Ok(Round {
            result,
            turned_back,
        })
    }

    /// One check: decide, ask if the policy asks, write the intent ahead,
    /// run it (or take the recorded result of the same call), journal its
    /// result with the tree measured after it, keep the loop's tree current,
    /// and charge the wall time.
    fn run_check<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
        step: u64,
        call: Call,
    ) -> Result<CheckRun, StopCause> {
        let capability = self.capability(EXEC_ID)?;
        let tool_id = Ident::from_capability(capability).ok_or(StopCause::PolicyAbort)?;
        let decision = self.session.decide(&call);
        w.append(step, decided(&decision)).map_err(journal)?;
        let authorized = match decision {
            // `decide` is pure, so `authorize` decides the same way.
            PolicyDecision::Allow { .. } => self
                .session
                .authorize(call)
                .map_err(|_| StopCause::PolicyAbort)?,
            PolicyDecision::Ask { tier, .. } => {
                match self.approve(w, step, capability, call, tier)? {
                    Ok(a) => a,
                    Err(_) => return Ok(CheckRun::NotRun),
                }
            }
            PolicyDecision::Deny { .. } => return Ok(CheckRun::NotRun),
        };
        let intent = Event::new(EventKind::ToolStarted).field("capability", Trusted::Id(tool_id));
        let journaled = w.append_intent(step, intent, authorized).map_err(journal)?;
        let intent_seq = journaled.intent_seq();
        let ctx = InvokeCtx {
            step,
            deadline: Instant::now() + self.config.exec_call_timeout.min(self.remaining_wall()),
            reads: &self.reads,
        };
        let (mut fed_environment, mut fed_tree) = (None, None);
        let result = if let Some(rec) = self.feed.pop_front() {
            // Replaying (audit, or a resume catching up): the recorded
            // result of this very call stands in for running it again.
            fed_environment = rec.environment;
            fed_tree = rec.exec.as_ref().map(|(_, t)| *t);
            drop(journaled);
            rec.into_result(EXEC_ID, None)
        } else {
            match self.providers.iter_mut().find(|p| p.serves(EXEC_ID)) {
                Some(p) => p.invoke(journaled, &ctx),
                None => {
                    drop(journaled);
                    Err(ToolError("no provider serves it".into()))
                }
            }
        };
        let mut exec_stop = None;
        let run = match result {
            Ok(res) => {
                let out = w.untrusted(&res.output).map_err(journal)?;
                let mut ev = Event::new(EventKind::ToolFinished)
                    .field("intent_seq", Trusted::U64(intent_seq))
                    .field("status", Trusted::Text(status_name(res.status)))
                    .field("truncated", Trusted::Bool(res.truncated))
                    .field("digest", Trusted::Digest(res.digest))
                    .field("output", Trusted::Untrusted(out));
                if let ToolStatus::Error { code } = res.status {
                    ev = ev.field("code", Trusted::U64(u64::from(code)));
                }
                // The command's record and the tree measured after it, live
                // or re-fed; an unconfirmed cleanup, or a tree that could not
                // be measured, stops the run (option (b), design row H2d).
                let mut changed = false;
                if let Some(x) = &res.exec {
                    let tree = match fed_tree {
                        Some(t) => t,
                        None => x.workspace.as_ref().map(WorkspaceTree::digest),
                    };
                    if let (None, Some(listing)) = (fed_tree, &x.workspace) {
                        self.workspace = Some(listing.clone());
                    }
                    ev = ev.field("exec", exec_fields(x));
                    if let Some(t) = tree {
                        ev = ev.field("workspace_tree", Trusted::Digest(t));
                        changed = t != self.tree;
                        self.tree = t;
                    }
                    exec_stop = match (x.cleanup, tree) {
                        (ExecCleanup::Unconfirmed, _) => Some(StopCause::SandboxLost),
                        (_, None) => Some(StopCause::PolicyAbort),
                        _ => None,
                    };
                }
                if matches!(res.status, ToolStatus::Timeout | ToolStatus::Crashed { .. }) {
                    let s = fed_environment.unwrap_or_else(|| self.env.sample());
                    ev = ev.field("environment", sample::to_trusted(&s));
                    if s.possibly_environmental() {
                        self.pressure.push(step);
                    }
                }
                w.append(step, ev).map_err(journal)?;
                if changed {
                    self.detector.observe(LoopEvent::WorkspaceChanged {
                        tree_digest: self.tree,
                    });
                }
                let passed = res.status == ToolStatus::Ok
                    && res
                        .exec
                        .as_ref()
                        .is_some_and(|x| x.end == ExecEnd::Exited(0));
                if passed {
                    CheckRun::Passed
                } else {
                    let body = String::from_utf8_lossy(res.output.inspect("context: observation"))
                        .into_owned();
                    let body = if body.is_empty() {
                        "(the call succeeded with no output)".to_owned()
                    } else {
                        body
                    };
                    CheckRun::Failed {
                        body: Untrusted::new(body, res.output.source().clone()),
                        digest: res.digest,
                    }
                }
            }
            Err(_) => {
                // A provider failure is the tool-level "could not run": the
                // check did not run (§7.1 samples the host, as for any tool).
                let s = fed_environment.unwrap_or_else(|| self.env.sample());
                if s.possibly_environmental() {
                    self.pressure.push(step);
                }
                w.append(
                    step,
                    Event::new(EventKind::ToolFinished)
                        .field("intent_seq", Trusted::U64(intent_seq))
                        .field("status", Trusted::Text("provider_error"))
                        .field("environment", sample::to_trusted(&s)),
                )
                .map_err(journal)?;
                CheckRun::NotRun
            }
        };
        if let Some(cause) = exec_stop {
            return Err(cause);
        }
        // The command's wall time is charged after its result is durable
        // (H1e-2a review F-1); a spent wall budget stops the run here, and
        // the next check's deadline is what the budget has left.
        self.meter.tick_wall()?;
        self.observe_budgets(w, step)?;
        Ok(run)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harness_tools::ExecProgram;

    fn exec() -> ExecSpec {
        ExecSpec {
            programs: vec![ExecProgram {
                name: "cargo".into(),
                path: "/usr/bin/cargo".into(),
            }],
            ..ExecSpec::default()
        }
    }

    fn grants() -> Vec<String> {
        vec![EXEC_ID.to_owned()]
    }

    fn spec(commands: &[&[&str]], max_rounds: u32) -> PresubmitSpec {
        PresubmitSpec {
            commands: commands
                .iter()
                .map(|c| c.iter().map(|s| (*s).to_owned()).collect())
                .collect(),
            max_rounds,
        }
    }

    #[test]
    fn a_well_formed_spec_passes() {
        let s = spec(
            &[&["cargo", "build"], &["cargo", "test", "--", "--nocapture"]],
            3,
        );
        assert_eq!(s.check(&grants(), Some(&exec())), Ok(()));
    }

    // The checks are commands in the sandbox: no exec grant, or no exec
    // section, and the section is refused.
    #[test]
    fn checks_need_the_exec_grant_and_its_section() {
        let s = spec(&[&["cargo", "build"]], 2);
        assert_eq!(s.check(&[], Some(&exec())), Err(PresubmitRefused::NoExec));
        assert_eq!(s.check(&grants(), None), Err(PresubmitRefused::NoExec));
        assert_eq!(
            s.check(&["harness.fs.read".to_owned()], Some(&exec())),
            Err(PresubmitRefused::NoExec)
        );
    }

    #[test]
    fn counts_and_rounds_are_bounded() {
        let ok = &["cargo", "build"][..];
        let many: Vec<&[&str]> = vec![ok; MAX_CHECKS + 1];
        assert_eq!(
            spec(&many, 2).check(&grants(), Some(&exec())),
            Err(PresubmitRefused::Commands)
        );
        assert_eq!(
            spec(&[], 2).check(&grants(), Some(&exec())),
            Err(PresubmitRefused::Commands)
        );
        let four: Vec<&[&str]> = vec![ok; MAX_CHECKS];
        assert_eq!(spec(&four, 5).check(&grants(), Some(&exec())), Ok(()));
        for rounds in [0, MAX_ROUNDS + 1, u32::MAX] {
            assert_eq!(
                spec(&[ok], rounds).check(&grants(), Some(&exec())),
                Err(PresubmitRefused::Rounds),
                "{rounds}"
            );
        }
    }

    #[test]
    fn every_command_is_an_argv_naming_an_allowlisted_program() {
        let s = |c: Vec<Vec<String>>| PresubmitSpec {
            commands: c,
            max_rounds: 2,
        };
        let check = |c| s(c).check(&grants(), Some(&exec()));
        let ok = vec!["cargo".to_owned(), "build".to_owned()];
        assert_eq!(
            check(vec![ok.clone(), vec![]]),
            Err(PresubmitRefused::Argv(2))
        );
        assert_eq!(
            check(vec![vec!["cargo".into(), "a\0b".into()]]),
            Err(PresubmitRefused::Argv(1))
        );
        assert_eq!(
            check(vec![vec!["cargo".into(), "x".repeat(MAX_ARG_BYTES + 1)]]),
            Err(PresubmitRefused::Argv(1))
        );
        assert_eq!(
            check(vec![
                std::iter::repeat_n("cargo".to_owned(), MAX_ARGS + 1).collect()
            ]),
            Err(PresubmitRefused::Argv(1))
        );
        // A name, exactly: not a path, not another case, not a shell line.
        for bad in ["/usr/bin/cargo", "Cargo", "sh", "cargo build", ""] {
            assert_eq!(
                check(vec![ok.clone(), vec![bad.to_owned(), "x".into()]]),
                Err(PresubmitRefused::Program(2)),
                "{bad:?}"
            );
        }
    }

    // The digest is the header's input: it moves with every field.
    #[test]
    fn the_digest_covers_every_field() {
        let base = spec(&[&["cargo", "build"], &["cargo", "test"]], 3);
        let same = spec(&[&["cargo", "build"], &["cargo", "test"]], 3);
        assert_eq!(base.digest(), same.digest());
        for other in [
            spec(&[&["cargo", "build"], &["cargo", "test"]], 4),
            spec(&[&["cargo", "test"], &["cargo", "build"]], 3),
            spec(&[&["cargo", "build"]], 3),
            spec(&[&["cargo", "build"], &["cargo", "test", "-q"]], 3),
            // Not a join of words: two words are not one.
            spec(&[&["cargo", "build"], &["cargo test"]], 3),
        ] {
            assert_ne!(base.digest(), other.digest());
        }
        assert_eq!(base.header_value()["commands"], 2);
        assert_eq!(base.header_value()["max_rounds"], 3);
    }

    // The call is what the model would send, so policy decides it as it does
    // the model's own command.
    #[test]
    fn a_checks_call_is_the_exec_call_the_model_would_make() {
        let s = spec(&[&["cargo", "build"], &["cargo", "test"]], 2);
        let c = s.call(1).unwrap();
        assert_eq!(c.capability, "harness.exec.run");
        assert_eq!(c.args, json!({"argv": ["cargo", "test"]}));
        assert!(s.call(2).is_none());
    }
}
