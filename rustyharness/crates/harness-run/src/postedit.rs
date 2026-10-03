//! Post-edit verified checks (design slice P-27).
//!
//! A task may declare checks the harness runs after every successful edit:
//! each check is a glob over the edited paths plus an argv in which `{path}`
//! names the first file the glob matched (`cargo check`, `ruff check {path}`).
//! They run in the same sandbox and under the same policy as the model's own
//! `harness.exec.run` — the same one-call machinery as the pre-submit checks
//! ([`crate::presubmit`]), reusing its records: each round of checks is one
//! `PresubmitChecked` record after the edited call's own records.
//!
//! If every matched check passes, the edit stands. If a check fails, the
//! edit is rolled back from its pre-image by default: the workspace is put
//! back byte for byte (verified against the tree measured before the edit),
//! a `Restored` record is written, and the model is shown the check's output
//! as an observation. A check may say `keep_on_failure` instead: the edit
//! stands and the model is shown the edit's own output with the check's
//! appended. A check that could not run (a policy denial, a declined ask, no
//! provider) is a failure and rolls the edit back: the task asked for a
//! verified edit, so unverifiable is not good enough.

use std::time::Instant;

use gate_outcome::Digest;
use harness_core::glob::Glob;
use harness_core::{sha256, StopCause, Untrusted};
use harness_journal::{BlobSink, Clock, Event, EventKind, JournalFile, JournalWriter, Trusted};
use harness_model::context::{restored_notice_text, Feedback};
use harness_model::HarnessText;
use harness_policy::{Call, EXEC_ID};
use harness_tools::builtin::workspace_tree;
use harness_tools::{recreate_file, restore_file, uncreate_file, EditRecord, ExecSpec};
use serde_json::{json, Value};

use crate::driver::step::{journal, Loop};
use crate::presubmit::{CheckRun, MAX_ARGS, MAX_ARG_BYTES, MAX_CHECKS};

/// Most checks a task may declare.
pub const MAX_POST_EDIT_CHECKS: usize = MAX_CHECKS;
/// Most arguments of one check.
pub const MAX_POST_EDIT_ARGS: usize = MAX_ARGS;
/// Longest argument of a check, in bytes.
pub const MAX_POST_EDIT_ARG_BYTES: usize = MAX_ARG_BYTES;

/// One post-edit check: a glob over the edited paths and the command to run
/// for the first path it matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostEditCheck {
    /// The glob, over workspace-relative paths of the files one edit touched.
    pub pattern: String,
    /// The argv, run with every `{path}` replaced by the first edited path
    /// the glob matches; its first item is a program name on the task's exec
    /// allowlist.
    pub argv: Vec<String>,
    /// A failing check leaves the edit in place (the model sees the check's
    /// output) instead of rolling the edit back.
    pub keep_on_failure: bool,
}

/// A task's post-edit checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostEditSpec {
    /// The checks, in order; each edit runs the checks whose glob matches it.
    pub checks: Vec<PostEditCheck>,
}

/// Why a task's post-edit checks are refused: nothing ran, nothing was
/// journaled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PostEditRefused {
    /// The checks are commands in the sandbox, so the task must grant the
    /// command runner (and give its allowlist).
    #[error("post_edit needs the task to grant harness.exec.run and give an exec section")]
    NoExec,
    /// No checks, or more than [`MAX_POST_EDIT_CHECKS`].
    #[error("post_edit must list 1 to {MAX_POST_EDIT_CHECKS} checks")]
    Checks,
    /// A check's glob is not a pattern the workspace can match.
    #[error("post_edit check {0} has a bad match pattern: {1}")]
    Match(usize, &'static str),
    /// A command is empty, too long, or holds a NUL.
    #[error(
        "post_edit check {0} must be 1 to {MAX_POST_EDIT_ARGS} arguments of at most {MAX_POST_EDIT_ARG_BYTES} bytes without NUL"
    )]
    Argv(usize),
    /// A check's program is not a name on the exec allowlist.
    #[error("post_edit check {0} does not start with a program name on the exec allowlist")]
    Program(usize),
    /// The policy denies a check: it would never run (an unattended task
    /// needs the allow rule for `harness.exec.run`, as for the model's own
    /// commands).
    #[error("the policy denies post_edit check {0}; nothing would run")]
    Denied(usize),
}

impl PostEditSpec {
    /// The checks, with each glob compiled once up front (a task file whose
    /// patterns cannot match is refused before anything runs).
    pub fn new(checks: Vec<PostEditCheck>) -> Result<Self, PostEditRefused> {
        if checks.is_empty() || checks.len() > MAX_POST_EDIT_CHECKS {
            return Err(PostEditRefused::Checks);
        }
        for (i, check) in checks.iter().enumerate() {
            let n = i + 1;
            Glob::new(&check.pattern).map_err(|e| PostEditRefused::Match(n, e.message()))?;
            if check.argv.is_empty()
                || check.argv.len() > MAX_POST_EDIT_ARGS
                || check
                    .argv
                    .iter()
                    .any(|a| a.len() > MAX_POST_EDIT_ARG_BYTES || a.contains('\0'))
            {
                return Err(PostEditRefused::Argv(n));
            }
        }
        Ok(PostEditSpec { checks })
    }

    /// The structural rules, given the task's grants and its exec setup:
    /// every check names a program on the allowlist. (The patterns were
    /// compiled by [`Self::new`].) Policy is checked by the session (see
    /// [`Self::call`]).
    pub fn check(&self, grants: &[String], exec: Option<&ExecSpec>) -> Result<(), PostEditRefused> {
        let Some(exec) = exec.filter(|_| grants.iter().any(|g| g == EXEC_ID)) else {
            return Err(PostEditRefused::NoExec);
        };
        let names = exec.names();
        for (i, check) in self.checks.iter().enumerate() {
            let n = i + 1;
            if check.argv.first().is_none_or(|p| !names.contains(p)) {
                return Err(PostEditRefused::Program(n));
            }
        }
        Ok(())
    }

    /// The call of check `index` (0-based) for the edited file `path`, with
    /// every `{path}` in the argv replaced: exactly what the model would
    /// send to run the same command, so policy decides it the same way.
    pub(crate) fn call(&self, index: usize, path: &str) -> Option<Call> {
        let argv: Vec<String> = self
            .checks
            .get(index)?
            .argv
            .iter()
            .map(|a| a.replace("{path}", path))
            .collect();
        Some(Call {
            capability: EXEC_ID.to_owned(),
            args: json!({ "argv": argv }),
        })
    }

    /// SHA-256 over everything the spec says, in one canonical encoding
    /// (the journal header's `post_edit` input: an audit or a resume must be
    /// given the same checks).
    pub fn digest(&self) -> Digest {
        let checks: Vec<Value> = self
            .checks
            .iter()
            .map(|c| {
                json!({
                    "match": c.pattern,
                    "argv": c.argv,
                    "keep_on_failure": c.keep_on_failure,
                })
            })
            .collect();
        let v = json!({ "format": "rh-postedit/1", "checks": checks });
        sha256(v.to_string().as_bytes())
    }

    /// The header's `post_edit` object (comparable with a recorded one).
    pub(crate) fn header_value(&self) -> Value {
        json!({
            "spec": self.digest().to_string(),
            "checks": self.checks.len() as u64,
        })
    }

    /// The first edited path check `index` matches, if any.
    fn matches<'p>(&self, index: usize, edited: &'p [String]) -> Option<&'p str> {
        let check = self.checks.get(index)?;
        let glob = Glob::new(&check.pattern).ok()?;
        edited.iter().find(|p| glob.matches(p)).map(|p| p.as_str())
    }
}

/// How the checks of one edit ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostEditResult {
    /// Every matched check ran and exited with status 0.
    Passed,
    /// A check did not exit with status 0: the edit was rolled back, or the
    /// task asked to keep it and the failure was recorded.
    Failed,
    /// A check was not run: the policy denied it, an approver declined it or
    /// did not answer, or no provider could run it. The edit was rolled back
    /// either way.
    NotRun,
}

impl PostEditResult {
    /// The name the journal records.
    pub fn name(self) -> &'static str {
        match self {
            PostEditResult::Passed => "passed",
            PostEditResult::Failed => "failed",
            PostEditResult::NotRun => "not_run",
        }
    }
}

/// What a run that has post-edit checks did with them, for its report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostEditReport {
    /// The task's number of checks.
    pub checks: usize,
    /// Edits that ran matched checks.
    pub submissions: u64,
    /// Edits whose checks did not all pass (rolled back or kept).
    pub failed: u64,
    /// Edits rolled back from their pre-image.
    pub rolled_back: u64,
    /// How the last edit's checks ended; `None`: no edit ran a check.
    pub last: Option<PostEditResult>,
}

/// The post-edit state of a loop: the checks, and what they have done so far.
#[derive(Debug)]
pub(crate) struct PostEditState {
    spec: PostEditSpec,
    submissions: u64,
    failed: u64,
    rolled_back: u64,
    last: Option<PostEditResult>,
}

impl PostEditState {
    /// The state of a run whose task has these checks (none: none).
    pub(crate) fn of(spec: &Option<PostEditSpec>) -> Option<Self> {
        spec.as_ref().map(|s| Self {
            spec: s.clone(),
            submissions: 0,
            failed: 0,
            rolled_back: 0,
            last: None,
        })
    }

    /// The report so far.
    pub(crate) fn report(&self) -> PostEditReport {
        PostEditReport {
            checks: self.spec.checks.len(),
            submissions: self.submissions,
            failed: self.failed,
            rolled_back: self.rolled_back,
            last: self.last,
        }
    }
}

impl<'a> Loop<'a> {
    /// Run the task's checks for the edit of step `step`. `edit_records` are
    /// the edit's per-file records (with their pre-images), `edited` the
    /// files it touched, `pre_edit_tree` the tree measured before the edit.
    /// Returns the step's feedback (the same, or with a failing check's
    /// output appended to it, or replaced by it) and, when the edit was
    /// rolled back, the notice the turn carries.
    ///
    /// Each check whose glob matches runs once, as the `harness.exec.run`
    /// call the model would make for the substituted argv: decided by policy
    /// (an ask goes to the approver, and is recorded like any), journaled
    /// ahead of its run, re-fed from the journal by an audit and by a
    /// resume's catch-up (never run again). One `PresubmitChecked` record
    /// sums the round up.
    pub(crate) fn post_edit_round<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
        step: u64,
        edit_records: &[EditRecord],
        edited: &[String],
        pre_edit_tree: Digest,
        feedback: Feedback,
    ) -> Result<(Feedback, Option<HarnessText>), StopCause> {
        let Some(spec) = self.post_edit.as_ref().map(|state| state.spec.clone()) else {
            return Ok((feedback, None));
        };
        if edited.is_empty() || edit_records.is_empty() {
            return Ok((feedback, None));
        }
        // One run per check, for the first edited path its glob matches.
        let matched: Vec<(usize, &str)> = (0..spec.checks.len())
            .filter_map(|i| spec.matches(i, edited).map(|p| (i, p)))
            .collect();
        if matched.is_empty() {
            return Ok((feedback, None));
        }
        let (mut ran, mut result, mut at, mut failure) = (0u64, PostEditResult::Passed, 0u64, None);
        for &(i, path) in &matched {
            let call = spec.call(i, path).ok_or(StopCause::PolicyAbort)?;
            match self.run_check(w, step, call)? {
                CheckRun::Passed => ran += 1,
                CheckRun::Failed { body, digest } => {
                    (ran, result, at, failure) = (
                        ran + 1,
                        PostEditResult::Failed,
                        i as u64 + 1,
                        Some((body, digest)),
                    );
                    break;
                }
                CheckRun::NotRun => {
                    (result, at) = (PostEditResult::NotRun, i as u64 + 1);
                    break;
                }
            }
        }
        // A failing check rolls the edit back unless the check says to keep
        // it; a check that could not run rolls it back either way.
        let keep = result == PostEditResult::Failed
            && failure.is_some()
            && at > 0
            && spec
                .checks
                .get((at - 1) as usize)
                .is_some_and(|c| c.keep_on_failure);
        let rolled = result != PostEditResult::Passed && !keep;
        if rolled {
            self.rollback(w, step, edit_records, edited, pre_edit_tree)?;
        }
        if let Some(state) = self.post_edit.as_mut() {
            state.submissions += 1;
            if rolled {
                state.rolled_back += 1;
            }
            if result != PostEditResult::Passed {
                state.failed += 1;
            }
            state.last = Some(result);
        }
        let submissions = self
            .post_edit
            .as_ref()
            .map(|state| state.submissions)
            .unwrap_or(0);
        let mut ev = Event::new(EventKind::PresubmitChecked)
            .field("round", Trusted::U64(submissions))
            .field("checks", Trusted::U64(matched.len() as u64))
            .field("ran", Trusted::U64(ran))
            .field("result", Trusted::Text(result.name()));
        if at > 0 {
            ev = ev.field("check", Trusted::U64(at));
        }
        ev = ev
            .field("turned_back", Trusted::U64(u64::from(rolled)))
            .field("accepted", Trusted::Bool(!rolled));
        w.append(step, ev).map_err(journal)?;
        let notice = rolled.then(|| restored_notice_text(edited.len(), step));
        let feedback = match (rolled, failure) {
            (false, None) => feedback,
            (true, None) => Feedback::Harness(HarnessText::from_static(
                "A post-edit check could not run, so the edit was rolled back.",
            )),
            (rolled, Some((body, digest))) => {
                let out = body.inspect("context: observation").clone();
                let out = if out.is_empty() {
                    "(the check succeeded with no output)".to_owned()
                } else {
                    out
                };
                let call = match &feedback {
                    Feedback::Observation { call, .. } => call.clone(),
                    _ => EXEC_ID.to_owned(),
                };
                let head = format!(
                    "a post-edit check failed (check {} of {}); its output:",
                    at,
                    matched.len(),
                );
                let body = if rolled {
                    Untrusted::new(format!("{head}\n{out}"), body.source().clone())
                } else {
                    // The edit stands: the model sees its own result first,
                    // then the check's output under the same delimiter.
                    let prev = match &feedback {
                        Feedback::Observation { body, .. } => {
                            body.inspect("context: observation").clone()
                        }
                        _ => String::new(),
                    };
                    Untrusted::new(format!("{prev}\n{head}\n{out}"), body.source().clone())
                };
                Feedback::Observation { call, body, digest }
            }
        };
        Ok((feedback, notice))
    }

    /// Put the files one edit touched back to their pre-images, verify the
    /// tree against the measurement taken before the edit, journal the
    /// `Restored` record, and move the loop's own state back. (A recompute
    /// has no workspace of its own: the records are what count there.)
    fn rollback<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
        step: u64,
        edit_records: &[EditRecord],
        edited: &[String],
        pre_edit_tree: Digest,
    ) -> Result<(), StopCause> {
        if let Some(root) = &self.workspace_root {
            for e in edit_records.iter().rev() {
                match (&e.before_image, e.after) {
                    (Some(img), Some(after)) => {
                        restore_file(root, e.path.as_str(), img, after).map_err(restore_abort)?
                    }
                    (None, Some(after)) => {
                        uncreate_file(root, e.path.as_str(), after).map_err(restore_abort)?
                    }
                    (Some(img), None) => {
                        recreate_file(root, e.path.as_str(), img).map_err(restore_abort)?
                    }
                    (None, None) => return Err(StopCause::PolicyAbort),
                }
            }
            let measured = workspace_tree(root, Instant::now() + self.config.facts_timeout)
                .map_err(|_| StopCause::PolicyAbort)?;
            if measured.facts().tree != pre_edit_tree {
                // Something changed under us; fail closed rather than
                // journal a rollback that did not happen.
                return Err(StopCause::PolicyAbort);
            }
        }
        self.journal_restored(w, step, pre_edit_tree, edited)?;
        self.restore.push_tree(step, pre_edit_tree);
        for p in edited {
            self.reads.forget(p);
        }
        self.tree = pre_edit_tree;
        Ok(())
    }
}

/// A rollback primitive that refused is a stop, not a recovery.
fn restore_abort(_: harness_tools::RestoreError) -> StopCause {
    StopCause::PolicyAbort
}
