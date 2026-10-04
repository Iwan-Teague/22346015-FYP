//! The loop itself ([`Loop`]): one step, the turn it renders, the budget
//! notices, observation nonces and their delimiting, and the helpers the
//! other loop modules (tools, approvals, stops) are `impl Loop` blocks of.

use std::time::{Duration, Instant};

use gate_outcome::Digest;
use harness_core::environment::EnvProbe;
use harness_core::{
    sha256, BudgetDim, ChildSpend, LoopDetector, LoopEvent, LoopKind, LoopSignal, Meter, Nonce,
    Source, StopCause, TokenUsage, Untrusted,
};
use harness_journal::{
    writer::stop_cause_name, BlobSink, Clock, Condition, ConditionKind, Event, EventKind, Ident,
    JournalError, JournalFile, JournalWriter, Trusted,
};
use harness_manifest::admission::Registry;
use harness_model::context::{
    self, budget_notice, budget_notice_session, budget_tokens, step_notice, valid_wall_notice,
    wall_threshold, BudgetNotice, ContextError, Delimiting, Fact, Feedback, Renderings,
    SessionModeView, Shown, ShownCall, Turn, UserEntry, SUBMIT_ACCEPTED_FAILING_TEXT,
    SUBMIT_ACCEPTED_TEXT,
};
use harness_model::profile::{Profile, Protocol};
use harness_model::protocol::{self, parse_reply, FormatError};
use harness_model::replay::{replied_event, requested_event};
use harness_model::wire::{contains_nonce, render_request};
use harness_model::{
    Completion, HarnessText, ModelBackend, ModelError, ModelRequest, TaskText, ToolSpec,
};
use harness_policy::{
    is_plan_tool_id, Call, Matcher, PolicyDecision, Session, SessionMode, DELEGATE_ID,
    PLAN_SUBMIT_ID, SUBMIT_ID, TODO_ID,
};
use harness_tools::builtin::code::{DELEGATE_NOT_STARTED, DELEGATE_NO_REPORT, DELEGATE_REFUSED};
use harness_tools::builtin::{WorkspaceFacts, WorkspaceTree};
use harness_tools::{
    EditRecord, ExecCleanup, Image, InvokeCtx, ReadLog, TodoList, ToolProvider, ToolStatus,
};
use serde_json::Value;

use super::approvals::Approvals;
use super::new_nonce;
use super::stop::{denied_text, End};
use super::tools::{exec_fields, is_edit, is_exec, is_read, status_name, RecordedResult};
use super::{ParentLink, RunConfig};
use crate::delegate::{
    check_admission, frame_report, run_child, ChildRefused, NOT_STARTED_TEXT, REFUSAL_CARVE,
};
use crate::presubmit::{PresubmitResult, PresubmitState, Round};
use crate::replay::feed::RecordedChild;
use crate::sample;

// ---------------------------------------------------------------------------
// The loop.
// ---------------------------------------------------------------------------

pub(crate) struct Loop<'a> {
    pub(crate) session: Session,
    pub(crate) registry: &'a Registry,
    pub(crate) tools: Vec<ToolSpec>,
    pub(crate) task: &'a TaskText,
    pub(crate) facts: Vec<Fact>,
    pub(crate) profile: &'a Profile,
    pub(crate) backend: &'a dyn ModelBackend,
    pub(crate) providers: Vec<Box<dyn ToolProvider + 'a>>,
    pub(crate) meter: Meter,
    pub(crate) detector: LoopDetector,
    pub(crate) turns: Vec<Turn>,
    pub(crate) config: &'a RunConfig,
    pub(crate) step: u64,
    /// Where observation nonces come from (recorded ones first when
    /// replaying), and every observation's delimiting so far (H1i).
    pub(crate) nonces: NonceSource,
    /// Recorded tool results that stand in for calls (audit replay and a
    /// resume's catch-up); when empty, the providers run.
    pub(crate) feed: std::collections::VecDeque<RecordedResult>,
    /// Files read this run and their digests (§2.3 "Stale reads").
    pub(crate) reads: ReadLog,
    /// The workspace tree digest, kept current through the run's own edits
    /// (the loop detector's repeat key includes it, §2.6).
    pub(crate) tree: Digest,
    /// The workspace listing the tree digest is computed over, for a live
    /// run: each verified edit updates it (H2b). `None` in an audit, which
    /// never reads the workspace: there the tree digest after an edit is
    /// re-fed from the journal.
    pub(crate) workspace: Option<WorkspaceTree>,
    /// Where the answers to asks come from, and the attempt's approval
    /// authority (§5.3, H2b).
    pub(crate) approvals: Approvals<'a>,
    /// Samples the host when a live tool call times out or crashes (§7.1).
    pub(crate) env: &'a dyn EnvProbe,
    /// Steps whose tool timed out or crashed under host pressure.
    pub(crate) pressure: Vec<u64>,
    /// Read-class calls already made, by (tool, args digest, tree digest),
    /// with the digest of their output: an exact repeat on an unchanged
    /// workspace that returns the same output gets a notice (the dev-suite
    /// judge's finding (b), H2b). The loop detector's rules are unchanged.
    pub(crate) reads_seen: std::collections::BTreeMap<(String, [u8; 32], [u8; 32]), [u8; 32]>,
    /// The model's checklist (H2e), when the session is granted
    /// `harness.task.todo`: applied call by call, in an audit and a resume's
    /// catch-up too, so every result is recomputed, never re-fed.
    pub(crate) todo: Option<TodoList>,
    /// The budget notices' state (H2e).
    pub(crate) notices: BudgetNotices,
    /// The task's pre-submit checks and what they did so far (H3a); `None`
    /// for a task without any: a submission is then accepted at once.
    pub(crate) presubmit: Option<PresubmitState>,
    /// The task's post-edit checks and what they did so far (P-27); `None`
    /// for a task without any: an edit then stands as it lands.
    pub(crate) post_edit: Option<crate::postedit::PostEditState>,
    /// The workspace root, for a post-edit check's rollback to the
    /// pre-images (P-27); `None` in an audit, which never touches the
    /// workspace.
    pub(crate) workspace_root: Option<std::path::PathBuf>,
    /// The workspace states the journal carries, for a session's `/undo`
    /// and `/rewind` (P-26); rebuilt the same way in an audit and a
    /// resume's catch-up.
    pub(crate) restore: crate::restore::RestoreLog,
    /// The interactive session's state (P-05); `None` in a batch run, an
    /// audit and a resume's catch-up, which take every batch path unchanged.
    pub(crate) user: Option<UserState<'a>>,
    /// A research session drives its turns with the research context (P-39i)
    /// instead of the coding one (fail closed: a batch loop never renders
    /// research text). Never `true` with `user: None` — a research session
    /// is always a driven session.
    pub(crate) research: bool,
    /// Trusted project instructions (P-30), `None` when the host loaded
    /// none: a batch run and a research session never load any. They reach
    /// the context as the fixed project-notes block and the nonce draw
    /// refuses a nonce the notes carry.
    pub(crate) instructions: Option<&'a crate::session::Instructions>,
    /// What a `harness.task.delegate` call needs to admit and build a
    /// child (P-38e): `None` in a child (the depth limit, §11 — the branch
    /// stops on it), in an audit and in a resume's catch-up until the
    /// reconstruction slice lands (P-38f).
    pub(crate) delegate: Option<crate::delegate::ChildCtx<'a>>,
    /// The plan awaiting `/build` (P-28): set by an accepted
    /// `harness.plan.submit`, taken by an approval. Not in `LoopInit`: it
    /// always starts empty, in a live run, an audit and a resume alike — a
    /// resume and an audit re-derive it by re-driving the recorded calls.
    pub(crate) plan_pending: Option<PendingPlan>,
    /// The rendered approved-plan block (P-28): what `build_session` shows
    /// as the user's own approved intent. Also always starts empty and is
    /// re-derived the same way.
    pub(crate) plan_approved: Option<String>,
    /// The ledger's commands-run list (P-33): each command's argv and its
    /// one-line end, in call order, captured where the result is journaled
    /// (a replay re-derives it from the re-parsed call and the re-fed
    /// exec record, which are identical). Always starts empty, like the
    /// plan state.
    pub(crate) ledger_commands: Vec<context::LedgerCommand>,
    /// The ledger's events (P-33): the mode changes and the restores, in
    /// order, pushed where their records are written. Also always starts
    /// empty and is re-derived by re-driving.
    pub(crate) ledger_events: Vec<context::LedgerEvent>,
    /// Where each build's repo map comes from (P-33): a live run computes
    /// it from the touched files; an audit and a resume's catch-up re-feed
    /// the recorded one (the workspace is not read in a replay).
    pub(crate) repo_feed: super::repomap::RepoMapFeed,
    /// The confined file helper's stop flag (P-36f): set after the
    /// helper's third loss of the attempt, and the loop then stops with
    /// [`harness_core::StopCause::SandboxLost`] — continuing would do the
    /// next file work outside the helper's kernel-enforced view (INV-42).
    /// `None` when the run used no helper (and in a replay, which never
    /// touches the workspace).
    pub(crate) file_ops_stop: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

/// A submitted plan awaiting the user's `/build` (P-28): the validated
/// parts, and the digest the `ModeChanged` record carries. The digest is
/// over the canonical JSON of exactly these parts, so a replay that
/// re-derives the plan from the same call names the same digest.
pub(crate) struct PendingPlan {
    pub(crate) summary: String,
    pub(crate) files: Vec<String>,
    pub(crate) steps: Vec<String>,
    pub(crate) digest: Digest,
}

impl PendingPlan {
    /// The plan as the context shows it once approved (P-28): the user's
    /// approved intent, rendered from the validated parts.
    pub(crate) fn block_text(&self) -> String {
        let mut s = String::from("Summary: ");
        s.push_str(self.summary.trim());
        s.push_str("\nFiles:\n");
        for f in &self.files {
            s.push_str("- ");
            s.push_str(f);
            s.push('\n');
        }
        s.push_str("Steps:\n");
        for (i, st) in self.steps.iter().enumerate() {
            s.push_str(&format!("{}. {st}\n", i + 1));
        }
        s
    }

    /// Validate a plan call's args (P-28): a non-empty summary within the
    /// schema cap, relative in-workspace file paths (no more than 64, each
    /// within the schema cap, duplicates collapsed), and non-empty steps
    /// (no more than 64, each within the schema cap). Anything else is a
    /// bad call: the observation says so and the turn goes on.
    fn parse(args: &Value) -> Result<Self, String> {
        let summary = args
            .get("summary")
            .and_then(Value::as_str)
            .ok_or("summary must be a string")?
            .to_owned();
        if summary.trim().is_empty() {
            return Err("summary must not be empty".to_owned());
        }
        if summary.len() > 2000 {
            return Err("summary is over 2000 bytes".to_owned());
        }
        let files_v = args
            .get("files")
            .and_then(Value::as_array)
            .ok_or("files must be an array of paths")?;
        if files_v.is_empty() {
            return Err("files must name at least one path".to_owned());
        }
        if files_v.len() > 64 {
            return Err("files has more than 64 entries".to_owned());
        }
        let mut files: Vec<String> = Vec::new();
        for f in files_v {
            let s = f.as_str().ok_or("files entries must be strings")?;
            if s.is_empty() || s.len() > 4096 {
                return Err("a file path is empty or over 4096 bytes".to_owned());
            }
            if s.starts_with('/') || s.split(['/', '\\']).any(|c| c == "..") {
                return Err("file paths must be relative and stay inside the workspace".to_owned());
            }
            if !files.iter().any(|x| x == s) {
                files.push(s.to_owned());
            }
        }
        let steps_v = args
            .get("steps")
            .and_then(Value::as_array)
            .ok_or("steps must be an array of strings")?;
        if steps_v.len() > 64 {
            return Err("steps has more than 64 entries".to_owned());
        }
        let mut steps: Vec<String> = Vec::new();
        for st in steps_v {
            let t = st.as_str().ok_or("steps entries must be strings")?;
            if t.trim().is_empty() {
                return Err("a step must not be empty".to_owned());
            }
            if t.len() > 500 {
                return Err("a step is over 500 bytes".to_owned());
            }
            steps.push(t.to_owned());
        }
        let canonical = serde_json::json!({
            "summary": summary,
            "files": files,
            "steps": steps,
        });
        let digest = sha256(canonical.to_string().as_bytes());
        Ok(Self {
            summary,
            files,
            steps,
            digest,
        })
    }
}

/// The interactive session's state on the loop (P-05): the current turn's
/// budget, the users shown so far, and where the UI drain sends records.
pub(crate) struct UserState<'a> {
    /// The session's turn limits (validated before anything was written).
    pub(crate) limits: crate::session::TurnLimits,
    /// 1-based number of the current user turn (the count of `UserTurn`
    /// records so far).
    pub(crate) turn: u64,
    /// This turn's step allowance: the lesser of the turn limit and the
    /// steps the session budget has left (P-05 §4).
    pub(crate) allowance: u64,
    /// Steps taken this turn so far (counted by the session loop).
    pub(crate) used: u64,
    /// The users shown to the model so far, in order (a refused input is
    /// never here).
    pub(crate) users: Vec<UserEntry>,
    /// SHA-256 of the last accepted submission's note, once one is accepted.
    pub(crate) deliverable: Option<Digest>,
    /// The workspace root, for the external-change measurement at each turn
    /// start (P-05 §5); `None` where there is no live workspace to measure.
    pub(crate) root: Option<std::path::PathBuf>,
    /// The attempt's blobs directory, for the UI drain's events.
    pub(crate) blobs: std::path::PathBuf,
    /// Where journaled records are shown; `None` means drain and drop.
    pub(crate) sink: Option<&'a dyn crate::session::EventSink>,
}

/// The loop's starting state, field for field, in one place. Every mode
/// that drives the loop (a live run, an audit, a resume, the tests) builds
/// one of these and hands it to [`Loop::new`], so a new loop field is
/// added here once, not at every construction site (P-05 §14).
pub(crate) struct LoopInit<'a> {
    pub(crate) session: Session,
    pub(crate) registry: &'a Registry,
    pub(crate) tools: Vec<ToolSpec>,
    pub(crate) task: &'a TaskText,
    pub(crate) facts: Vec<Fact>,
    pub(crate) profile: &'a Profile,
    pub(crate) backend: &'a dyn ModelBackend,
    pub(crate) providers: Vec<Box<dyn ToolProvider + 'a>>,
    pub(crate) meter: Meter,
    pub(crate) detector: LoopDetector,
    pub(crate) turns: Vec<Turn>,
    pub(crate) config: &'a RunConfig,
    pub(crate) step: u64,
    pub(crate) nonces: NonceSource,
    pub(crate) feed: std::collections::VecDeque<RecordedResult>,
    pub(crate) reads: ReadLog,
    pub(crate) tree: Digest,
    pub(crate) workspace: Option<WorkspaceTree>,
    pub(crate) approvals: Approvals<'a>,
    pub(crate) env: &'a dyn EnvProbe,
    pub(crate) pressure: Vec<u64>,
    pub(crate) reads_seen: std::collections::BTreeMap<(String, [u8; 32], [u8; 32]), [u8; 32]>,
    pub(crate) todo: Option<TodoList>,
    pub(crate) notices: BudgetNotices,
    pub(crate) presubmit: Option<PresubmitState>,
    pub(crate) post_edit: Option<crate::postedit::PostEditState>,
    pub(crate) workspace_root: Option<std::path::PathBuf>,
    pub(crate) restore: crate::restore::RestoreLog,
    pub(crate) user: Option<UserState<'a>>,
    pub(crate) research: bool,
    pub(crate) instructions: Option<&'a crate::session::Instructions>,
    pub(crate) repo_feed: super::repomap::RepoMapFeed,
    pub(crate) delegate: Option<crate::delegate::ChildCtx<'a>>,
    pub(crate) file_ops_stop: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl<'a> Loop<'a> {
    pub(crate) fn new(init: LoopInit<'a>) -> Self {
        let LoopInit {
            session,
            registry,
            tools,
            task,
            facts,
            profile,
            backend,
            providers,
            meter,
            detector,
            turns,
            config,
            step,
            nonces,
            feed,
            reads,
            tree,
            workspace,
            approvals,
            env,
            pressure,
            reads_seen,
            todo,
            notices,
            presubmit,
            post_edit,
            workspace_root,
            restore,
            user,
            research,
            instructions,
            repo_feed,
            delegate,
            file_ops_stop,
        } = init;
        Loop {
            session,
            registry,
            tools,
            task,
            facts,
            profile,
            backend,
            providers,
            meter,
            detector,
            turns,
            config,
            step,
            nonces,
            feed,
            reads,
            tree,
            workspace,
            approvals,
            env,
            pressure,
            reads_seen,
            todo,
            notices,
            presubmit,
            post_edit,
            workspace_root,
            restore,
            user,
            research,
            instructions,
            repo_feed,
            delegate,
            file_ops_stop,
            plan_pending: None,
            plan_approved: None,
            ledger_commands: Vec::new(),
            ledger_events: Vec::new(),
        }
    }
}

/// The command line a ledger entry names (P-33): the call's `argv` array
/// joined with spaces. `None` when the arguments are not that shape (fail
/// closed: never fabricate an entry — the exec schema always sends one,
/// so this is defence in depth).
fn exec_argv(args: &Value) -> Option<String> {
    let items = args.get("argv")?.as_array()?;
    let mut out = String::new();
    for (i, v) in items.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(v.as_str()?);
    }
    Some(out)
}

/// A command's one-line end, as the ledger names it (P-33): the same ends
/// the `exec` record's `end` field names, in words.
fn exec_end_text(x: &harness_tools::ExecRecord) -> String {
    match x.end {
        harness_tools::ExecEnd::Exited(c) => format!("exited {c}"),
        harness_tools::ExecEnd::Signaled(n) => format!("signaled {n}"),
        harness_tools::ExecEnd::TimedOut => String::from("timed out"),
        harness_tools::ExecEnd::ProcessLimit => String::from("process limit"),
        harness_tools::ExecEnd::ExecFailed => String::from("exec failed"),
        harness_tools::ExecEnd::Unknown => String::from("unknown"),
    }
}

/// Where the budget notices come from, and what was announced (H2e). The
/// step notices are recomputed from the step and the step limit (a header
/// input), in every mode. The wall notices depend on the clock, which a
/// replay cannot recompute (§2.9), so an audit and a resume's catch-up
/// re-feed the recorded ones, checked to be ones the loop writes; a live
/// step measures the meter.
#[derive(Debug, Clone, Default)]
pub(crate) struct BudgetNotices {
    /// The wall budget the notices measure against: the run's own, in an
    /// audit too (whose meter has no wall limit).
    pub(crate) wall_limit: Duration,
    /// Recorded wall notices by step: (percent, milliseconds used).
    pub(crate) recorded: std::collections::BTreeMap<u64, (u64, u64)>,
    /// The last step whose wall notice is re-fed rather than measured: an
    /// audit's every step, a resume's kept steps, none for a live run.
    pub(crate) recorded_through: u64,
    /// The highest wall threshold announced so far (0: none).
    pub(crate) wall_announced: u64,
}

impl BudgetNotices {
    /// A live run's: every wall notice measured, against `wall_limit`.
    pub(crate) fn live(wall_limit: Duration) -> Self {
        Self {
            wall_limit,
            ..Self::default()
        }
    }
}

/// Where observation nonces come from, and how every turn so far is shown
/// (design row H1i). A nonce is drawn when its observation is first
/// rendered: the one recorded for that observation when replaying (so a
/// replayed request renders byte for byte), else a fresh random one.
#[derive(Debug, Default)]
pub(crate) struct NonceSource {
    /// Recorded nonces, by the step of the observation each delimits
    /// (`ModelRequested.nonce_step`): audit replay and a resume's catch-up.
    pub(crate) recorded: std::collections::BTreeMap<u64, Nonce>,
    /// How every turn so far is shown, by its step: decided at its first
    /// render, fixed after.
    pub(crate) assigned: Renderings,
}

impl NonceSource {
    fn next(&mut self, step: u64) -> Option<Nonce> {
        self.recorded.remove(&step).or_else(new_nonce)
    }

    /// Every nonce drawn so far in this run.
    pub(crate) fn drawn(&self) -> impl Iterator<Item = &Nonce> {
        self.assigned.values().filter_map(|s| match &s.output {
            Some(Delimiting::Nonce(n)) => Some(n),
            _ => None,
        })
    }
}

/// One step's result.
pub(crate) enum Flow {
    Continue,
    Stop(StopCause, Option<Digest>),
    /// The user turn ended (P-05 §3); the session goes on to its next
    /// input. Never returned by a batch loop.
    EndTurn(TurnEnd),
}

/// Why a user turn ended, as the `TurnEnded` journal record names it
/// (P-05 §1.1, §3).
pub(crate) enum TurnEnd {
    Answered,
    Submitted,
    SubmittedChecksFailed,
    /// The plan sentinel was accepted (P-28): the turn is over so the user
    /// can read the plan and answer `/build` or `/plan`.
    PlanSubmitted,
    TurnSteps,
    FormatErrors,
    Loop(LoopKind),
    ModelUnavailable,
}

impl TurnEnd {
    /// The `reason` text the `TurnEnded` record carries.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            TurnEnd::Answered => "answered",
            TurnEnd::Submitted => "submitted",
            TurnEnd::SubmittedChecksFailed => "submitted_checks_failed",
            TurnEnd::PlanSubmitted => "plan_submitted",
            TurnEnd::TurnSteps => "turn_steps",
            TurnEnd::FormatErrors => "format_errors",
            TurnEnd::Loop(kind) => match kind {
                LoopKind::Repeat => "loop:repeat",
                LoopKind::EditChurn => "loop:edit_churn",
                LoopKind::NoProgress => "loop:no_progress",
                LoopKind::Denied => "loop:denied",
            },
            TurnEnd::ModelUnavailable => "model_unavailable",
        }
    }

    /// The notice the model sees with the next request, when the turn ended
    /// for a reason worth naming (`turn_end_text`); joined into the last
    /// step's turn, which that request shows first (P-05 §3).
    pub(crate) fn notice(&self) -> Option<HarnessText> {
        harness_model::context::turn_end_text(self.name())
    }
}

pub(crate) fn journal(e: JournalError) -> StopCause {
    e.stop_cause()
}

impl<'a> Loop<'a> {
    /// Run steps until one stops the loop.
    pub(crate) fn drive<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
    ) -> End {
        loop {
            let flow = self.step(w).unwrap_or_else(|cause| Flow::Stop(cause, None));
            // §2.2 step 10: a poisoned writer stops the run whatever the step
            // said.
            let flow = if w.is_poisoned() {
                match flow {
                    Flow::Stop(c @ StopCause::JournalUnavailable { .. }, d) => Flow::Stop(c, d),
                    _ => Flow::Stop(
                        StopCause::JournalUnavailable {
                            op: "append".into(),
                            error: "the journal writer is poisoned".into(),
                        },
                        None,
                    ),
                }
            } else {
                flow
            };
            if let Flow::Stop(cause, deliverable) = flow {
                return End {
                    cause,
                    step: self.step,
                    deliverable,
                };
            }
        }
    }

    pub(crate) fn remaining_wall(&self) -> Duration {
        self.config.limits.wall.saturating_sub(self.meter.elapsed())
    }

    /// Whether the session is in plan mode (P-28): read-only tools only,
    /// until the user approves the pending plan with `/build`.
    pub(crate) fn plan_mode(&self) -> bool {
        self.session.mode() == SessionMode::Plan
    }

    /// The tools the request declares (P-28): in plan mode, only the plan
    /// set survives (the read-class fs tools, the checklist and the plan
    /// sentinel) — the model sees no edit or exec tool to name. In build
    /// mode the full declared list minus the plan sentinel (a plan-mode
    /// tool: not declared, not granted — policy denies it, so a build
    /// session names the same tools it named before P-28 and the profile's
    /// active-tool bound is unchanged). The context build and the wire
    /// render take the same list, so a request names and shows the same
    /// ids.
    pub(crate) fn active_tools(&self) -> Vec<ToolSpec> {
        if self.plan_mode() {
            self.tools
                .iter()
                .filter(|t| is_plan_tool_id(&t.id))
                .cloned()
                .collect()
        } else {
            self.tools
                .iter()
                .filter(|t| t.id != PLAN_SUBMIT_ID)
                .cloned()
                .collect()
        }
    }

    /// The plan-mode view the session context renders (P-28): the mode
    /// line, and the approved-plan block once `/build` approved one. A
    /// pure function of the loop state, so audit replay recomputes it.
    fn mode_view(&self) -> SessionModeView {
        SessionModeView {
            plan_mode: self.plan_mode(),
            approved_plan: self.plan_approved.clone(),
        }
    }

    /// The trusted project instructions as the context's fixed
    /// project-notes block (P-30): `None` when none were loaded. The
    /// digest is the one the user approved; the text keeps its untrusted
    /// source (the workspace file it came from).
    fn session_notes(&self) -> Option<context::ProjectNotes> {
        self.instructions.map(|n| context::ProjectNotes {
            name: n.name.to_owned(),
            digest: n.digest.to_string(),
            text: Untrusted::new(
                n.text.inspect("context: project notes").clone(),
                Source::Workspace(n.name.to_owned()),
            ),
        })
    }

    /// The checklist as the ledger shows it (P-33): one line per item,
    /// `None` when the run keeps no checklist or an empty one. The texts
    /// are the model's own words but the ledger is the harness's rendering
    /// of state it applied itself (each item went through
    /// `TodoList::apply`), so it is ledger material, not model-written
    /// text the harness vouches for.
    fn ledger_todo(&self) -> Option<String> {
        let t = self.todo.as_ref()?;
        if t.items().is_empty() {
            return None;
        }
        let mut s = String::new();
        for i in t.items() {
            let status = match i.status {
                harness_tools::TodoStatus::Pending => "pending",
                harness_tools::TodoStatus::InProgress => "in progress",
                harness_tools::TodoStatus::Done => "done",
            };
            s.push_str(&format!("- [{status}] {}\n", i.text));
        }
        Some(s)
    }

    /// The conversation ledger as the session context shows it (P-33): a
    /// pure function of the loop state — the checklist, the files-touched
    /// table from the restore log's edit marks, the commands run and the
    /// mode/restore events — so audit replay recomputes it.
    fn ledger_view(&self) -> context::Ledger {
        let mut files = Vec::new();
        for f in super::repomap::touched_files(self.restore.marks()) {
            files.push(context::LedgerFile {
                path: f.path,
                edits: f.edits,
                last: f.last.map(|d| d.to_string()),
            });
        }
        context::Ledger {
            todo: self.ledger_todo(),
            files,
            commands: self.ledger_commands.clone(),
            events: self.ledger_events.clone(),
        }
    }

    /// The repo map this build shows (P-33): computed live from the
    /// touched files when the workspace is readable, re-fed from the
    /// journal in an audit and a resume's catch-up. `Some` exactly when
    /// the context carries a map, so the `ContextBuilt` record names it
    /// exactly then.
    fn repo_map_for_build(&mut self) -> Option<Untrusted<String>> {
        if self.research || self.user.is_none() {
            return None;
        }
        let root = self.user.as_ref().and_then(|u| u.root.clone());
        super::repomap::for_build(
            &mut self.repo_feed,
            root.as_deref(),
            self.step,
            self.restore.marks(),
        )
    }

    /// `/plan` (P-28): narrow the session to the plan set. A research
    /// session or a batch loop has no plan mode (fail closed: refuse
    /// silently, journal nothing). Idempotent: `/plan` twice journals one
    /// `ModeChanged`.
    pub(crate) fn plan_mode_enter<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
    ) -> Result<(), StopCause> {
        if self.research || self.user.is_none() || self.plan_mode() {
            return Ok(());
        }
        // The plan set must fit the profile's active-tool bound, or the
        // first plan-mode request would be refused mid-run (fail closed:
        // `/plan` does nothing rather than narrowing into a stop).
        let plan_tools = self.tools.iter().filter(|t| is_plan_tool_id(&t.id)).count();
        if u32::try_from(plan_tools).unwrap_or(u32::MAX) > self.profile.max_active_tools() {
            return Ok(());
        }
        self.session.enter_plan();
        self.ledger_events.push(context::LedgerEvent::Plan);
        w.append(
            self.step,
            Event::new(EventKind::ModeChanged).field("mode", Trusted::Text("plan")),
        )
        .map_err(journal)?;
        Ok(())
    }

    /// `/build` (P-28): approve the pending plan. With none pending,
    /// nothing is journaled and the loop asks for the next input. With
    /// one: the full active set is re-decided and the trifecta recomputed
    /// (fail closed: a refusal leaves the pending plan and the mode
    /// unchanged), every active edit capability takes one `plan.allow`
    /// rule per approved file (an edit on a named file skips its ask; the
    /// move tool's target must match too), and the `ModeChanged` record
    /// names the plan digest.
    pub(crate) fn build_approve<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
    ) -> Result<(), StopCause> {
        if self.research || self.user.is_none() {
            return Ok(());
        }
        let Some(pending) = self.plan_pending.take() else {
            return Ok(());
        };
        if self.session.build().is_err() {
            // The widened set is lethal (a quarantine since the plan could
            // not have made it worse, but fail closed all the same): the
            // approval does not stand, the plan stays pending.
            self.plan_pending = Some(pending);
            return Ok(());
        }
        // The plan rules: for each active edit capability, one path-glob
        // rule per approved file. A file whose glob cannot compile (it
        // cannot: `parse` bounds and shapes every path, but fail closed)
        // refuses the whole approval.
        let mut matchers: Vec<(_, Matcher)> = Vec::new();
        for cap in self.session.edit_caps() {
            for f in &pending.files {
                match Matcher::path_glob(f) {
                    Ok(m) => matchers.push((cap.clone(), m)),
                    Err(_) => {
                        self.plan_pending = Some(pending);
                        return Ok(());
                    }
                }
            }
        }
        for (cap, m) in matchers {
            self.session.grant_plan(&cap, m);
        }
        self.plan_approved = Some(pending.block_text());
        self.ledger_events.push(context::LedgerEvent::Build);
        w.append(
            self.step,
            Event::new(EventKind::ModeChanged)
                .field("mode", Trusted::Text("build"))
                .field("plan_digest", Trusted::Digest(pending.digest)),
        )
        .map_err(journal)?;
        Ok(())
    }

    /// One step, then (when the run goes on) the budget notices it earned,
    /// joined to its turn (H2e).
    pub(crate) fn step<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
    ) -> Result<Flow, StopCause> {
        let flow = self.step_inner(w)?;
        if let Flow::Continue = flow {
            self.budget_notices(w, self.step)?;
        }
        Ok(flow)
    }

    /// The budget notices after step `step` (H2e), journaled as
    /// `BudgetNotice` records and joined to the step's turn, which the next
    /// request shows first and every later one shows unchanged (the
    /// context stays append-mostly, H1i). Steps: at the first step at or
    /// past 50%, 80% and 90% of the step budget, and when one step is left
    /// (recomputed in every mode). Wall time: once for the highest of those
    /// thresholds the meter has passed since the last one announced (re-fed
    /// when replaying, and refused unless it is one the loop writes). With
    /// a checklist, the last notice counts its open items.
    fn budget_notices<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
        step: u64,
    ) -> Result<(), StopCause> {
        let mut due: Vec<BudgetNotice> = Vec::new();
        // In a session the step notices measure the TURN's budget against
        // this turn's allowance (P-05 §4); a batch run measures the run's
        // steps against the run limit, unchanged.
        let (used, limit) = match &self.user {
            Some(u) => (u.used, u.allowance),
            None => (step, u64::from(self.config.limits.steps)),
        };
        if let Some(n) = step_notice(used, limit) {
            let (key, used, limit) = match n {
                BudgetNotice::LastStep { used, limit } => ("last_step", used, limit),
                BudgetNotice::Steps { used, limit } => ("steps", used, limit),
                BudgetNotice::Wall { .. } => return Err(StopCause::PolicyAbort),
            };
            w.append(
                step,
                Event::new(EventKind::BudgetNotice)
                    .field("key", Trusted::Text(key))
                    .field("used", Trusted::U64(used))
                    .field("limit", Trusted::U64(limit)),
            )
            .map_err(journal)?;
            due.push(n);
        }
        let limit_ms = u64::try_from(self.notices.wall_limit.as_millis()).unwrap_or(u64::MAX);
        let announced = self.notices.wall_announced;
        let wall = if step <= self.notices.recorded_through {
            match self.notices.recorded.remove(&step) {
                None => None,
                // Only a notice the loop would write: a threshold above the
                // last one announced, reached by the recorded time.
                Some((percent, used_ms))
                    if valid_wall_notice(percent, used_ms, limit_ms, announced) =>
                {
                    Some((percent, used_ms))
                }
                Some(_) => return Err(StopCause::PolicyAbort),
            }
        } else {
            // The time charged at the step's last tick (every path ticks after
            // the model's reply; a tool call ticks again after its result):
            // reading the clock again here would move a budget stop.
            let used_ms = u64::try_from(self.meter.elapsed().as_millis()).unwrap_or(u64::MAX);
            wall_threshold(used_ms, limit_ms, announced).map(|p| (p, used_ms))
        };
        if let Some((percent, used_ms)) = wall {
            self.notices.wall_announced = percent;
            w.append(
                step,
                Event::new(EventKind::BudgetNotice)
                    .field("key", Trusted::Text("wall"))
                    .field("percent", Trusted::U64(percent))
                    .field("used_ms", Trusted::U64(used_ms))
                    .field("limit_ms", Trusted::U64(limit_ms)),
            )
            .map_err(journal)?;
            due.push(BudgetNotice::Wall {
                percent,
                used_ms,
                limit_ms,
            });
        }
        if due.is_empty() {
            return Ok(());
        }
        let protocol = self.profile.protocol();
        let open = self.todo.as_ref().map(TodoList::open);
        let last = due.len() - 1;
        let turn = match self.turns.last_mut() {
            Some(t) if t.step == step => t,
            _ => return Err(StopCause::PolicyAbort),
        };
        for (i, n) in due.into_iter().enumerate() {
            let open = if i == last { open } else { None };
            let text = if self.user.is_some() {
                budget_notice_session(protocol, n, open)
            } else {
                budget_notice(protocol, n, open)
            };
            turn.notice = Some(match turn.notice.take() {
                Some(prev) => prev.joined(&text),
                None => text,
            });
        }
        Ok(())
    }

    fn step_inner<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
    ) -> Result<Flow, StopCause> {
        self.step += 1;
        let step = self.step;

        // 1. Charge the meter.
        self.meter.tick_wall()?;
        self.meter.charge_step()?;
        self.observe_budgets(w, step)?;

        // 2. Build the context (§2.3), once the observation it shows for the
        // first time has its delimiting (H1i). A session build keeps every
        // user's turn in the window and reserves the users' share of the
        // budget for them (P-05 §2.3); a research session's build (P-39i)
        // takes the research rules and facts instead of the coding ones.
        let first = self.first_render()?;
        // P-28: in plan mode the request names and shows only the plan set
        // (the read tools, the checklist, the plan sentinel).
        let tools = self.active_tools();
        // P-33: the session context carries the ledger and, when this
        // build shows one, the repo map. The ledger is a pure function of
        // the loop state; the map is computed live or re-fed (see
        // `repo_map_for_build`), and its text is journaled with the
        // `ContextBuilt` record exactly when it is shown.
        let ledger = self.ledger_view();
        let repo_map = self.repo_map_for_build().map(context::RepoMap::new);
        let built = match (&self.user, self.research) {
            (Some(u), true) => context::build_research(
                self.profile,
                &tools,
                self.task,
                &self.facts,
                &self.turns,
                &u.users,
                &self.nonces.assigned,
            ),
            (Some(u), false) => context::build_session(
                self.profile,
                &tools,
                self.task,
                &self.facts,
                self.session_notes().as_ref(),
                Some(&ledger),
                repo_map.as_ref(),
                &self.turns,
                &u.users,
                &self.nonces.assigned,
                &self.mode_view(),
            ),
            // Fail closed: a batch loop never renders research text. A
            // research spec is refused by `run` and `resume` (and a batch
            // audit at the recorded header's mode key), so this arm is
            // unreachable; refuse rather than guess.
            (None, true) => return Err(StopCause::PolicyAbort),
            (None, false) => context::build(
                self.profile,
                &tools,
                self.task,
                &self.facts,
                &self.turns,
                &self.nonces.assigned,
            ),
        };
        let built = match built {
            Ok(b) => b,
            Err(ContextError::Exhausted { .. }) => return Err(StopCause::ContextExhausted),
            Err(ContextError::TooManyTools { .. } | ContextError::Undecided { .. }) => {
                return Err(StopCause::PolicyAbort)
            }
        };
        let users_dropped = built.users_dropped;
        let mut ev = Event::new(EventKind::ContextBuilt)
            .field("context", Trusted::Digest(built.digest))
            .field("recent_turns", Trusted::U64(built.recent as u64))
            // H1i: whether this build compacted (a prefix-cache break).
            .field("compacted", Trusted::Bool(built.compacted))
            .field("estimated_tokens", Trusted::U64(built.estimated_tokens))
            .field("budget_tokens", Trusted::U64(built.budget_tokens));
        if self.user.is_some() {
            // P-05 §1.1: only a session's ContextBuilt carries this.
            ev = ev.field("users_dropped", Trusted::U64(users_dropped));
        }
        // P-33: a coding session names the repo map it showed, as an
        // untrusted workspace payload. An audit and a resume's catch-up
        // re-feed the recorded text (the workspace is not read in a
        // replay) and write the identical payload back; the context digest
        // covers the text either way. Research sessions and batch runs
        // never carry one.
        if let Some(map) = &repo_map {
            let tok = w
                .untrusted(&Untrusted::new(
                    map.text.inspect("context: repo map").clone(),
                    Source::Workspace(super::repomap::REPO_MAP_NAME.to_owned()),
                ))
                .map_err(journal)?;
            ev = ev.field("repo_map", Trusted::Untrusted(tok));
        }
        w.append(step, ev).map_err(journal)?;

        // 3. Call the model under the remaining wall budget.
        let (req, rendered) = self.request(built.messages, &tools)?;
        let ev = requested_event(&rendered, first.as_ref().map(|(s, d)| (*s, d)))
            .ok_or(StopCause::PolicyAbort)?;
        w.append(step, ev).map_err(journal)?;
        let request_bytes = rendered.to_string().len() as u64;
        let deadline = Instant::now() + self.config.model_call_timeout.min(self.remaining_wall());
        let result = self.backend.complete(&req, deadline);
        // Journal first, then charge (H1e-2a review F-1): a wall-budget stop
        // must never leave a request without its reply in the journal.
        let ev = replied_event(w, &result).map_err(journal)?;
        w.append(step, ev).map_err(journal)?;
        self.meter.tick_wall()?;

        let mut completion = match result {
            Ok(c) => c,
            Err(e) => return self.model_error(e, step, request_bytes),
        };
        self.meter.record_tokens(
            completion.usage.map(|u| TokenUsage {
                input: u.input,
                output: u.output,
            }),
            completion.request_bytes.max(request_bytes),
            completion.reply_bytes,
        )?;
        self.observe_budgets(w, step)?;

        // 4. Parse exactly one action.
        let parsed = parse_reply(&completion, self.profile.protocol(), &self.tools);
        // P-53: a native profile that opted in to parallel tool calls keeps
        // the FIRST call of a multi-call reply; the surplus calls are
        // dropped (never capability-checked, never policy-decided, never
        // run) and a turn notice says so, and the reply is shown with the
        // one call that runs. A pure function of the completion and the
        // profile, so an audit replay re-runs exactly this. No
        // `FormatError` is recorded and the format-error meter is not
        // charged when the kept call parses; if it does not (an unknown
        // tool, bad JSON), the usual error path runs on the new error. The
        // default profile rejects the whole reply below, as before. The
        // text protocol is exactly-one-action by its own grammar: its
        // `SeveralActions` always keeps the format-error path.
        let mut dropped_calls = 0usize;
        let parsed = match parsed {
            Err(FormatError::SeveralActions)
                if self.profile.protocol() == Protocol::Native
                    && self.profile.parallel_tool_calls() =>
            {
                dropped_calls = completion.tool_calls.len().saturating_sub(1);
                completion.tool_calls.truncate(1);
                parse_reply(&completion, self.profile.protocol(), &self.tools)
            }
            other => other,
        };
        // P-05 §3: in a session, a plain-text answer (a `no_action` parse
        // error with no tool call and non-whitespace text) is the turn's
        // answer, not a format error: no `FormatError` record, no account
        // charge; the format-error streak is cleared. Both protocols.
        if let (Err(FormatError::NoAction), true) = (&parsed, self.user.is_some()) {
            if completion.tool_calls.is_empty()
                && !completion
                    .content
                    .inspect("context: reply")
                    .trim()
                    .is_empty()
            {
                self.meter.record_format_ok();
                self.turns.push(Turn {
                    step,
                    reply: shown_reply(&completion),
                    action: None,
                    feedback: Feedback::Answer,
                    notice: None,
                });
                return Ok(Flow::EndTurn(TurnEnd::Answered));
            }
        }
        if let Err(fe) = &parsed {
            w.append(
                step,
                Event::new(EventKind::FormatError).field("error", Trusted::Text(fe_name(*fe))),
            )
            .map_err(journal)?;
        }
        protocol::account(&mut self.meter, &parsed)?;
        let reply = shown_reply(&completion);
        let parsed = match parsed {
            Ok(p) => p,
            Err(fe) => {
                let stalled = self.feed_stall()?;
                if let Some(kind) = stalled {
                    return Ok(Flow::EndTurn(TurnEnd::Loop(kind)));
                }
                // No action: the native protocol withholds this reply and
                // shows only the repair text (H1h; see `context`).
                self.turns.push(Turn {
                    step,
                    reply,
                    action: None,
                    feedback: Feedback::Harness(fe.repair_message(self.profile.protocol())),
                    notice: None,
                });
                // P-05 §3: a turn's run of format errors ends the TURN, not
                // the session (the meter's own limit is off in a session).
                if let Some(u) = &self.user {
                    if self.meter.consecutive_format_errors() >= u.limits.format_errors {
                        return Ok(Flow::EndTurn(TurnEnd::FormatErrors));
                    }
                }
                return Ok(Flow::Continue);
            }
        };
        let tool = parsed.action.tool.clone();
        let capability = self.capability(&tool)?;
        let args = Value::Object(parsed.action.args);
        let args_text = args.to_string();
        // P-33: the ledger's commands-run argv, taken before `args` moves
        // into the policy call (re-derived identically in a replay).
        let ledger_argv = exec_argv(&args);
        // The action as the native protocol shows it back (H1h): the active
        // tool's id and the canonical JSON of the arguments policy decides
        // on, beside the reply's text; never the raw call the server sent.
        let shown = ShownCall {
            tool: tool.clone(),
            arguments: Untrusted::new(args_text.clone(), Source::Model),
            content: Untrusted::new(
                completion.content.inspect("context: reply").clone(),
                Source::Model,
            ),
        };
        let args_blob = w
            .untrusted(&Untrusted::new(args_text.clone(), Source::Model))
            .map_err(journal)?;
        let reasoning = w.untrusted(&parsed.reasoning).map_err(journal)?;
        let tool_id = Ident::from_capability(capability).ok_or(StopCause::PolicyAbort)?;
        w.append(
            step,
            Event::new(EventKind::ActionParsed)
                .field("tool", Trusted::Id(tool_id.clone()))
                .field("args", Trusted::Untrusted(args_blob))
                .field("reasoning", Trusted::Untrusted(reasoning)),
        )
        .map_err(journal)?;

        // Loop detection on the proposed action (§2.6).
        // P-53: when the opt-in dropped surplus calls, the turn notice says
        // so before any loop notice (joined, never replaced).
        let mut notice = (dropped_calls > 0).then(|| {
            HarnessText::from_facts(format!(
                "Notice: your reply made {} tool calls; the first one ran and the other {} were dropped. Make exactly one tool call per reply.",
                dropped_calls + 1,
                dropped_calls
            ))
        });
        match self.detector.observe(LoopEvent::Action {
            tool: tool.clone(),
            args_digest: sha256(args_text.as_bytes()),
            tree: self.tree,
        }) {
            LoopSignal::Quiet => {}
            LoopSignal::Notice(_) => {
                w.append(
                    step,
                    Event::new(EventKind::LoopDetected)
                        .field("kind", Trusted::Text("repeat"))
                        .field("stop", Trusted::Bool(false)),
                )
                .map_err(journal)?;
                let repeat = HarnessText::from_static(
                    "Notice: you have made the same call three times in the last six steps. \
                     Doing it again will stop the run. Try something different or submit.",
                );
                notice = Some(match notice {
                    Some(n) => n.joined(&repeat),
                    None => repeat,
                });
            }
            LoopSignal::Stop(kind) => return self.loop_stop(w, step, kind),
        }

        // 5-6. Validate and decide (§5.1); the decision is journaled with its rule.
        let call = Call {
            capability: tool.clone(),
            args,
        };
        let decision = self.session.decide(&call);
        w.append(step, super::stop::decided(&decision))
            .map_err(journal)?;
        let outcome = match decision {
            // `decide` is pure, so `authorize` decides the same way.
            PolicyDecision::Allow { .. } => self
                .session
                .authorize(call)
                .map_err(|_| StopCause::PolicyAbort)?,
            // §5.3: an ask runs only with an approval of exactly this call.
            PolicyDecision::Ask { tier, .. } => {
                match self.approve(w, step, capability, call, tier)? {
                    Ok(a) => a,
                    Err(text) => return self.refused(w, step, reply, shown, notice, text, tool),
                }
            }
            PolicyDecision::Deny { .. } => {
                let programs: Vec<&str> = self.session.exec_programs().collect();
                let text = denied_text(&decision, &self.tools, &tool, &programs);
                return self.refused(w, step, reply, shown, notice, text, tool);
            }
        };
        let authorized = outcome;

        // 7. Write-ahead intent: only a Journaled call can run.
        let intent = Event::new(EventKind::ToolStarted).field("capability", Trusted::Id(tool_id));
        let journaled = w.append_intent(step, intent, authorized).map_err(journal)?;

        // The submit sentinel: recorded, never executed by a provider.
        if tool == SUBMIT_ID {
            let note = journaled
                .call()
                .call()
                .args
                .get("note")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let digest = sha256(note.as_bytes());
            let blob = w
                .untrusted(&Untrusted::new(note, Source::Model))
                .map_err(journal)?;
            w.append(
                step,
                Event::new(EventKind::SubmitRequested)
                    .field("intent_seq", Trusted::U64(journaled.intent_seq()))
                    .field("note", Trusted::Untrusted(blob)),
            )
            .map_err(journal)?;
            let intent_seq = journaled.intent_seq();
            drop(journaled);
            // The task's pre-submit checks (H3a): run now, in the submit's
            // own step. Without any, the submission is accepted at once.
            let round = match self.presubmit {
                Some(_) => Some(self.presubmit_round(w, step)?),
                None => None,
            };
            if let Some(Round {
                turned_back: Some(back),
                ..
            }) = round
            {
                // A failing check turned the submission back: its result is
                // an error whose observation is that check's output, and the
                // turn carries the harness's notice. The run goes on.
                let out = w.untrusted(&back.body).map_err(journal)?;
                w.append(
                    step,
                    Event::new(EventKind::ToolFinished)
                        .field("intent_seq", Trusted::U64(intent_seq))
                        .field("status", Trusted::Text("error"))
                        .field("truncated", Trusted::Bool(false))
                        .field("digest", Trusted::Digest(back.digest))
                        .field("output", Trusted::Untrusted(out))
                        .field(
                            "code",
                            Trusted::U64(u64::from(
                                harness_tools::builtin::code::PRESUBMIT_REJECTED,
                            )),
                        ),
                )
                .map_err(journal)?;
                self.detector.observe(LoopEvent::Observation {
                    digest: back.digest,
                });
                let notice = Some(match notice {
                    Some(n) => n.joined(&back.notice),
                    None => back.notice,
                });
                self.turns.push(Turn {
                    step,
                    reply,
                    action: Some(shown),
                    feedback: Feedback::Observation {
                        call: tool,
                        body: back.body,
                        digest: back.digest,
                    },
                    notice,
                });
                self.meter.tick_wall()?;
                self.observe_budgets(w, step)?;
                return Ok(Flow::Continue);
            }
            w.append(
                step,
                Event::new(EventKind::ToolFinished)
                    .field("status", Trusted::Text("ok"))
                    .field("intent_seq", Trusted::U64(intent_seq)),
            )
            .map_err(journal)?;
            // Accepted with a check that still fails (the bound is spent):
            // its own stop cause, never a plain submit.
            let failed = matches!(
                round,
                Some(Round {
                    result: PresubmitResult::Failed,
                    ..
                })
            );
            // P-05 §3: in a session a submission ends the TURN, not the run;
            // the turn says so (the harness text the next request shows),
            // the note's digest becomes the session's deliverable, and the
            // submit sentinel stays granted for later turns.
            if let Some(u) = self.user.as_mut() {
                u.deliverable = Some(digest);
                self.turns.push(Turn {
                    step,
                    reply,
                    action: Some(shown),
                    feedback: Feedback::Harness(HarnessText::from_static(if failed {
                        SUBMIT_ACCEPTED_FAILING_TEXT
                    } else {
                        SUBMIT_ACCEPTED_TEXT
                    })),
                    notice,
                });
                return Ok(Flow::EndTurn(if failed {
                    TurnEnd::SubmittedChecksFailed
                } else {
                    TurnEnd::Submitted
                }));
            }
            let cause = if failed {
                StopCause::SubmittedChecksFailed
            } else {
                StopCause::Submitted
            };
            return Ok(Flow::Stop(cause, Some(digest)));
        }

        // The checklist (H2e): like the sentinel, recorded and never run by
        // a provider; its result is the list after the call, recomputed from
        // the call in every mode (an audit compares it with the recorded
        // one), shown as an observation like any tool's.
        if tool == TODO_ID {
            let intent_seq = journaled.intent_seq();
            let args = journaled.call().call().args.clone();
            drop(journaled);
            let list = self.todo.as_mut().ok_or(StopCause::PolicyAbort)?;
            let (status, text) = match list.apply(&args) {
                Ok(t) => (ToolStatus::Ok, t),
                Err(e) => (
                    ToolStatus::Error {
                        code: harness_tools::builtin::code::BAD_ARGS,
                    },
                    format!("error: {e}"),
                ),
            };
            let digest = sha256(text.as_bytes());
            let body = Untrusted::new(text, Source::Tool(TODO_ID.to_owned()));
            let out = w.untrusted(&body).map_err(journal)?;
            let mut ev = Event::new(EventKind::ToolFinished)
                .field("intent_seq", Trusted::U64(intent_seq))
                .field("status", Trusted::Text(status_name(status)))
                .field("truncated", Trusted::Bool(false))
                .field("digest", Trusted::Digest(digest))
                .field("output", Trusted::Untrusted(out));
            if let ToolStatus::Error { code } = status {
                ev = ev.field("code", Trusted::U64(u64::from(code)));
            }
            w.append(step, ev).map_err(journal)?;
            self.detector.observe(LoopEvent::Observation { digest });
            self.turns.push(Turn {
                step,
                reply,
                action: Some(shown),
                feedback: Feedback::Observation {
                    call: tool,
                    body,
                    digest,
                },
                notice,
            });
            self.meter.tick_wall()?;
            self.observe_budgets(w, step)?;
            return Ok(Flow::Continue);
        }

        // The delegate sentinel (P-38e, design §4-§7): admit the call,
        // carve this step's remaining budget for one helper, run the child
        // synchronously (§12: at most one request in flight, this thread),
        // and land its report as an ordinary untrusted observation. A
        // refusal is a plain tool error with static text (§6.3) and no
        // child record; a started child always leaves a `ChildRun` record
        // before the step's own `ToolFinished` (§6.1).
        if tool == DELEGATE_ID {
            let intent_seq = journaled.intent_seq();
            let intent_hash = journaled.intent_hash();
            let args = journaled.call().call().args.clone();
            drop(journaled);

            // §11: depth one. A child runs with no delegate context, and
            // so do an audit and a resume's catch-up until the
            // reconstruction slice lands (P-38f): reaching this branch
            // without one is a harness bug — stop.
            let ctx = match self.delegate.as_ref() {
                Some(c) => crate::delegate::ChildCtx {
                    state_root: c.state_root,
                    workspace: c.workspace,
                    parent_spec: c.parent_spec,
                    registry: c.registry,
                    policy: c.policy,
                    profile: c.profile,
                    backend: c.backend,
                    probe: c.probe,
                    env: c.env,
                    approver: c.approver,
                    parent_run: c.parent_run.clone(),
                    parent_attempt: c.parent_attempt,
                    live: c.live,
                    admitted: c.admitted,
                    facts: c.facts,
                    timeouts: c.timeouts,
                },
                None => return Err(StopCause::PolicyAbort),
            };

            let brief = args.get("task").and_then(Value::as_str);

            // §5.1: what is left of the parent's budgets now, this step's
            // own charge already taken. In a session the turn's allowance
            // bounds the carve too. The wall never gates admission (§4).
            let (carve_steps, carve_tokens) = {
                let steps_base = u64::from(
                    self.config
                        .limits
                        .steps
                        .saturating_sub(self.meter.steps_spent()),
                );
                let steps_left = match &self.user {
                    Some(u) => steps_base.min(u.allowance.saturating_sub(u.used)),
                    None => steps_base,
                };
                let (tokens_in, tokens_out) = self.meter.tokens_spent();
                let tokens_left = self
                    .config
                    .limits
                    .tokens
                    .saturating_sub(tokens_in.saturating_add(tokens_out));
                (u32::try_from(steps_left).unwrap_or(u32::MAX), tokens_left)
            };

            // P-38f: an audit replay (and a resume's catch-up) never runs a
            // child. The admission and the carve are recomputed — so a
            // refusal is re-derived, never re-fed — and a started child's
            // record is re-written from what the child's own run alone
            // knows (its identity, its chain head, its stop, its spend)
            // plus what the replay recomputes (the carve, the grants, the
            // digests, the parent link into the child's own journal).
            let replaying = !ctx.live || !self.feed.is_empty();
            if replaying {
                let rec = match self.feed.pop_front() {
                    Some(r) if r.capability == tool => r,
                    // An admitted delegation with nothing recorded for it:
                    // a committed journal would differ here (divergence);
                    // a crash-cut prefix has no such step re-fed at all
                    // (its catch-up simply never reaches this branch with
                    // an empty feed — this arm is a harness bug).
                    _ => return Err(StopCause::PolicyAbort),
                };
                let Some(child) = rec.child else {
                    return Err(StopCause::PolicyAbort);
                };
                // The wall never gates anything here (§4), so the replay's
                // refusal decision needs no wall time at all; a started
                // child's carve gets the hand-off time back from the
                // record.
                let refusal = match check_admission(&ctx, brief) {
                    Ok(()) => match harness_core::carve(
                        carve_steps,
                        carve_tokens,
                        self.config.limits.wall,
                        budget_tokens(self.profile),
                    ) {
                        Ok(_) => None,
                        Err(_) => Some(REFUSAL_CARVE.to_owned()),
                    },
                    Err(text) => Some(text),
                };
                let wall_left = |used_ms: u64| {
                    self.config
                        .limits
                        .wall
                        .saturating_sub(Duration::from_millis(used_ms))
                };
                return match (refusal, child) {
                    (Some(text), RecordedChild::Refused) => self.delegate_finish(
                        w,
                        step,
                        intent_seq,
                        reply,
                        shown,
                        notice,
                        tool,
                        "error",
                        Some(DELEGATE_REFUSED),
                        text,
                        false,
                        None,
                    ),
                    (None, RecordedChild::NotStarted { stopped: true }) => {
                        // The recorded run stopped right after: the child's
                        // journal could not be read back. The error text is
                        // static (§10: nothing of the child's work), and the
                        // stop it produced is reproduced.
                        self.delegate_journal_lost(w, step, intent_seq, NOT_STARTED_TEXT.to_owned())
                    }
                    (None, RecordedChild::NotStarted { stopped: false }) => self.delegate_finish(
                        w,
                        step,
                        intent_seq,
                        reply,
                        shown,
                        notice,
                        tool,
                        "provider_error",
                        Some(DELEGATE_NOT_STARTED),
                        NOT_STARTED_TEXT.to_owned(),
                        false,
                        None,
                    ),
                    (None, RecordedChild::Started(st)) => {
                        let Ok(carve) = harness_core::carve(
                            carve_steps,
                            carve_tokens,
                            wall_left(st.wall_used_ms),
                            budget_tokens(self.profile),
                        ) else {
                            // The recorded carve cannot be re-derived: the
                            // parent journal would differ here.
                            return Err(StopCause::PolicyAbort);
                        };
                        let Some(spec_grants) =
                            crate::delegate::child_spec(&ctx.parent_spec.grants, self.profile)
                        else {
                            return Err(StopCause::PolicyAbort);
                        };
                        let mut grants = Vec::with_capacity(spec_grants.len());
                        for g in &spec_grants {
                            let harness_manifest::admission::Resolved::One { capability, .. } =
                                ctx.registry.resolve(g)
                            else {
                                return Err(StopCause::PolicyAbort);
                            };
                            let Some(id) = Ident::from_capability(capability) else {
                                return Err(StopCause::PolicyAbort);
                            };
                            grants.push(Trusted::Id(id));
                        }
                        let Some(child_id) = Ident::from_trusted(&st.child) else {
                            return Err(StopCause::PolicyAbort);
                        };
                        let Some(stop) = harness_journal::stop_cause_named(&st.stop) else {
                            return Err(StopCause::PolicyAbort);
                        };
                        let Ok(text) = String::from_utf8(rec.output) else {
                            return Err(StopCause::PolicyAbort);
                        };
                        let (status, code) = match rec.status {
                            Some(ToolStatus::Ok) => ("ok", None),
                            Some(ToolStatus::Error {
                                code: DELEGATE_NO_REPORT,
                            }) => ("error", Some(DELEGATE_NO_REPORT)),
                            _ => return Err(StopCause::PolicyAbort),
                        };
                        let brief = brief.unwrap_or_default();
                        let mut child_ev = Event::new(EventKind::ChildRun)
                            .field("intent_seq", Trusted::U64(intent_seq))
                            .field("child", Trusted::Id(child_id))
                            .field("stop", Trusted::Text(stop))
                            .field("brief", Trusted::Digest(sha256(brief.as_bytes())))
                            .field(
                                "template",
                                Trusted::Digest(crate::delegate::child_template_digest()),
                            )
                            .field("grants", Trusted::List(grants))
                            .field(
                                "limits",
                                Trusted::Obj(vec![
                                    ("steps", Trusted::U64(u64::from(carve.steps))),
                                    ("tokens", Trusted::U64(carve.tokens)),
                                    (
                                        "wall_ms",
                                        Trusted::U64(
                                            u64::try_from(carve.wall.as_millis())
                                                .unwrap_or(u64::MAX),
                                        ),
                                    ),
                                ]),
                            )
                            .field("wall_used_ms", Trusted::U64(st.wall_used_ms))
                            .field(
                                "spent",
                                Trusted::Obj(vec![
                                    ("steps", Trusted::U64(u64::from(st.spend_steps))),
                                    ("tokens_in", Trusted::U64(st.tokens_in)),
                                    ("tokens_out", Trusted::U64(st.tokens_out)),
                                    ("estimated", Trusted::Bool(st.estimated)),
                                    ("wall_ms", Trusted::U64(st.spend_wall_ms)),
                                ]),
                            )
                            .field("chain_head", Trusted::Digest(st.chain_head));
                        if let Some(result) = st.result {
                            child_ev = child_ev.field("result", Trusted::Digest(result));
                        }
                        w.append(step, child_ev).map_err(journal)?;
                        if let Some(c) = self.delegate.as_mut() {
                            c.admitted += 1;
                        }
                        let spend = ChildSpend::recorded(
                            st.spend_steps,
                            st.tokens_in,
                            st.tokens_out,
                            st.estimated,
                            Duration::from_millis(st.spend_wall_ms),
                        );
                        self.delegate_finish(
                            w,
                            step,
                            intent_seq,
                            reply,
                            shown,
                            notice,
                            tool,
                            status,
                            code,
                            text,
                            rec.truncated,
                            Some(&spend),
                        )
                    }
                    _ => Err(StopCause::PolicyAbort),
                };
            }

            // §5.1: what is left of the parent's wall time now.
            let carve = harness_core::carve(
                carve_steps,
                carve_tokens,
                self.remaining_wall(),
                budget_tokens(self.profile),
            );

            // §4: admission, in order — the run's cap, the brief, the
            // child's plannable scope, then the carve.
            let refusal = match check_admission(&ctx, brief) {
                Ok(()) => match carve {
                    Ok(_) => None,
                    Err(_) => Some(REFUSAL_CARVE.to_owned()),
                },
                Err(text) => Some(text),
            };
            if let Some(text) = refusal {
                return self.delegate_finish(
                    w,
                    step,
                    intent_seq,
                    reply,
                    shown,
                    notice,
                    tool,
                    "error",
                    Some(DELEGATE_REFUSED),
                    text,
                    false,
                    None,
                );
            }
            let Ok(carve) = carve else {
                return Err(StopCause::PolicyAbort);
            };
            let brief = brief.unwrap_or_default();

            // §5.2: the child's wall time is its own — the parent's meter
            // is paused for the whole child, asks included, and the child
            // pauses its own during its asks. The run so far is what the
            // `ChildRun` record cites.
            let wall_used_ms = u64::try_from(self.meter.elapsed().as_millis()).unwrap_or(u64::MAX);
            let facts = WorkspaceFacts {
                tree: self.tree,
                files: ctx.facts.files,
                oversize: ctx.facts.oversize,
            };
            let link = ParentLink {
                run: ctx.parent_run.clone(),
                attempt: ctx.parent_attempt,
                step,
                intent_hash,
            };
            let pause = self.meter.pause_wall()?;
            let outcome = run_child(&ctx, brief, &carve, &link, &facts, self.workspace.clone());
            drop(pause);

            // §10 stop table: a child that started but whose journal
            // cannot be read back (or whose committed head is missing) is
            // a harness-visible failure — record the tool-level "could not
            // run" with nothing of the child's work in it, then stop. Any
            // other refusal means the child never started: a `provider_error`
            // observation, and the run goes on.
            let done = match outcome {
                Ok(done) => done,
                Err(e @ ChildRefused::ReadBack(_)) => {
                    return self.delegate_journal_lost(w, step, intent_seq, e.to_string());
                }
                Err(e @ ChildRefused::Note(_)) => {
                    return self.delegate_journal_lost(w, step, intent_seq, e.to_string());
                }
                Err(_) => {
                    return self.delegate_finish(
                        w,
                        step,
                        intent_seq,
                        reply,
                        shown,
                        notice,
                        tool,
                        "provider_error",
                        Some(DELEGATE_NOT_STARTED),
                        NOT_STARTED_TEXT.to_owned(),
                        false,
                        None,
                    );
                }
            };
            let Some(_) = done.chain_head else {
                return self.delegate_journal_lost(
                    w,
                    step,
                    intent_seq,
                    format!(
                        "the child run stopped ({}) but its journal has no committed head",
                        stop_cause_name(&done.stop)
                    ),
                );
            };

            // §6.2: the child's record, recomputable from the parent
            // journal alone (the brief and note are cited by digest; their
            // bytes travel as the tool's untrusted payloads).
            let Some(child_id) = Ident::from_trusted(&done.run) else {
                return Err(StopCause::PolicyAbort);
            };
            let spend = done.spend;
            let (text, truncated) = match &done.note {
                Some(note) => frame_report(&done.run, done.steps, carve.steps, note, self.profile),
                None => (
                    crate::delegate::no_report_text(
                        &done.run,
                        stop_cause_name(&done.stop),
                        done.steps,
                        carve.steps,
                    ),
                    false,
                ),
            };
            let submitted = done.note.is_some();
            let Some(spec_grants) =
                crate::delegate::child_spec(&ctx.parent_spec.grants, self.profile)
            else {
                return Err(StopCause::PolicyAbort);
            };
            let mut grants = Vec::with_capacity(spec_grants.len());
            for g in &spec_grants {
                // The id comes from the resolved capability, like the
                // header's `grants` field — a grant that does not resolve
                // cannot be vouched for.
                let harness_manifest::admission::Resolved::One { capability, .. } =
                    ctx.registry.resolve(g)
                else {
                    return Err(StopCause::PolicyAbort);
                };
                let Some(id) = Ident::from_capability(capability) else {
                    return Err(StopCause::PolicyAbort);
                };
                grants.push(Trusted::Id(id));
            }
            let mut child_ev = Event::new(EventKind::ChildRun)
                .field("intent_seq", Trusted::U64(intent_seq))
                .field("child", Trusted::Id(child_id))
                .field("stop", Trusted::Text(stop_cause_name(&done.stop)))
                .field("brief", Trusted::Digest(sha256(brief.as_bytes())))
                .field(
                    "template",
                    Trusted::Digest(crate::delegate::child_template_digest()),
                )
                .field("grants", Trusted::List(grants))
                .field(
                    "limits",
                    Trusted::Obj(vec![
                        ("steps", Trusted::U64(u64::from(carve.steps))),
                        ("tokens", Trusted::U64(carve.tokens)),
                        (
                            "wall_ms",
                            Trusted::U64(u64::try_from(carve.wall.as_millis()).unwrap_or(u64::MAX)),
                        ),
                    ]),
                )
                .field("wall_used_ms", Trusted::U64(wall_used_ms))
                .field(
                    "spent",
                    Trusted::Obj(vec![
                        ("steps", Trusted::U64(u64::from(spend.steps()))),
                        ("tokens_in", Trusted::U64(spend.tokens().0)),
                        ("tokens_out", Trusted::U64(spend.tokens().1)),
                        ("estimated", Trusted::Bool(spend.estimated())),
                        (
                            "wall_ms",
                            Trusted::U64(
                                u64::try_from(spend.wall().as_millis()).unwrap_or(u64::MAX),
                            ),
                        ),
                    ]),
                );
            if let Some(head) = done.chain_head {
                child_ev = child_ev.field("chain_head", Trusted::Digest(head));
            }
            if let Some(note) = &done.note {
                child_ev = child_ev.field("result", Trusted::Digest(sha256(note.as_bytes())));
            }
            w.append(step, child_ev).map_err(journal)?;

            // §6.3: the report (framed, §7) or the no-report error, as the
            // step's ToolFinished; the child's spend joins the parent's
            // meter only once that record is durable (§5.2, in
            // `delegate_finish`). The observation is untrusted like any
            // tool's: nonce delimiting, withholding and no parsing come
            // from the ordinary turn path (§7, INV-29).
            let status = if submitted { "ok" } else { "error" };
            let code = (!submitted).then_some(DELEGATE_NO_REPORT);
            if let Some(c) = self.delegate.as_mut() {
                c.admitted += 1;
            }
            return self.delegate_finish(
                w,
                step,
                intent_seq,
                reply,
                shown,
                notice,
                tool,
                status,
                code,
                text,
                truncated,
                Some(&spend),
            );
        }

        // The plan sentinel (P-28): like the checklist, recorded and never
        // run by a provider. A valid call is stored as the pending plan and
        // ends the turn, so the user can read it and answer `/build`; an
        // invalid one (or any call outside a session, which has no user to
        // approve a plan) is an error observation and the turn goes on.
        if tool == PLAN_SUBMIT_ID {
            let intent_seq = journaled.intent_seq();
            let args = journaled.call().call().args.clone();
            drop(journaled);
            let (status, text) = if self.user.is_none() {
                (
                    ToolStatus::Error {
                        code: harness_tools::builtin::code::BAD_ARGS,
                    },
                    "error: harness.plan.submit needs a session (a user to approve the plan)"
                        .to_owned(),
                )
            } else {
                match PendingPlan::parse(&args) {
                    Ok(p) => {
                        self.plan_pending = Some(p);
                        (
                            ToolStatus::Ok,
                            "Plan recorded. It is shown to the user for approval with /build."
                                .to_owned(),
                        )
                    }
                    Err(e) => (
                        ToolStatus::Error {
                            code: harness_tools::builtin::code::BAD_ARGS,
                        },
                        format!("error: {e}"),
                    ),
                }
            };
            let digest = sha256(text.as_bytes());
            let body = Untrusted::new(text, Source::Tool(PLAN_SUBMIT_ID.to_owned()));
            let out = w.untrusted(&body).map_err(journal)?;
            let mut ev = Event::new(EventKind::ToolFinished)
                .field("intent_seq", Trusted::U64(intent_seq))
                .field("status", Trusted::Text(status_name(status)))
                .field("truncated", Trusted::Bool(false))
                .field("digest", Trusted::Digest(digest))
                .field("output", Trusted::Untrusted(out));
            if let ToolStatus::Error { code } = status {
                ev = ev.field("code", Trusted::U64(u64::from(code)));
            }
            w.append(step, ev).map_err(journal)?;
            self.detector.observe(LoopEvent::Observation { digest });
            self.turns.push(Turn {
                step,
                reply,
                action: Some(shown),
                feedback: Feedback::Observation {
                    call: tool,
                    body,
                    digest,
                },
                notice,
            });
            self.meter.tick_wall()?;
            self.observe_budgets(w, step)?;
            if matches!(status, ToolStatus::Ok) {
                return Ok(Flow::EndTurn(TurnEnd::PlanSubmitted));
            }
            return Ok(Flow::Continue);
        }

        // P-05 §8: the sink has seen the intent (and every record before
        // it) before a provider runs.
        self.ui_drain(w);

        // 8. Execute.
        let intent_seq = journaled.intent_seq();
        // Per-tool timeouts (H2d): a command gets the exec timeout, every
        // other tool the tool timeout; both capped by the wall budget left.
        let timeout = if is_exec(&tool) {
            self.config.exec_call_timeout
        } else {
            self.config.tool_call_timeout
        };
        let ctx = InvokeCtx {
            step,
            deadline: Instant::now() + timeout.min(self.remaining_wall()),
            reads: &self.reads,
            egress: None,
        };
        let mut fed_environment = None;
        let mut fed_edit_trees: Vec<Digest> = Vec::new();
        let mut fed_exec_tree = None;
        let result = if let Some(rec) = self.feed.pop_front() {
            fed_environment = rec.environment;
            fed_edit_trees = rec.edits.iter().map(|e| e.tree).collect();
            fed_exec_tree = rec.exec.as_ref().map(|(_, t)| *t);
            // Replaying (audit, or a resume catching up): the recorded
            // result of this very call stands in for running it again, an
            // edit's and a command's included: a replay re-feeds what an
            // edit did and never applies it again (H2b), and never runs a
            // completed command again (H2d). The intent above is journaled
            // all the same, so the replayed journal has the recorded shape.
            let path = journaled
                .call()
                .call()
                .args
                .get("path")
                .and_then(Value::as_str)
                .map(str::to_owned);
            drop(journaled);
            rec.into_result(&tool, path.as_deref())
        } else {
            // The built-in providers share the `harness` namespace, so a
            // call goes to the first provider that serves its capability
            // (H2b), never to one that merely shares its namespace.
            match self.providers.iter_mut().find(|p| p.serves(&tool)) {
                Some(p) => p.invoke(journaled, &ctx),
                None => {
                    drop(journaled);
                    Err(harness_tools::ToolError("no provider serves it".into()))
                }
            }
        };
        // No budget check between the call and its result record (H1e-2a
        // review F-1): the wall time it took is charged at step 10, after
        // `ToolFinished` is durable, so every intent that ran has its result.

        // 9. Journal the result.
        let mut edited: Vec<String> = Vec::new();
        let mut unverified = false;
        let mut repeated = false;
        let mut exec_stop = None;
        let mut exec_changed = false;
        // The edit's own records and the tree before it (P-27): a failing
        // post-edit check rolls the edit back from here.
        let mut edit_records: Vec<EditRecord> = Vec::new();
        let mut pre_edit_tree = self.tree;
        let feedback = match result {
            Ok(mut res) => {
                let out = w.untrusted(&res.output).map_err(journal)?;
                edit_records = std::mem::take(&mut res.edits);
                pre_edit_tree = self.tree;
                // A verified edit (§4.9 step 5): one `EditApplied` per
                // touched file before the `ToolFinished`, so a durable
                // result implies a durable record of every change (P-25: a
                // patch touches several files, a move two). Each tree
                // digest comes from the live listing (or from the journal
                // when re-fed: a resume's catch-up measured its listing
                // after the edit), and each file's own path is in its
                // record, not the call's.
                if res.status == ToolStatus::Ok && !edit_records.is_empty() {
                    for (i, e) in edit_records.iter().enumerate() {
                        let tree = match (fed_edit_trees.get(i), self.workspace.as_mut()) {
                            (Some(&t), _) => t,
                            (None, Some(ws)) => match e.after {
                                Some(after) => ws.record_edit(&e.path, after),
                                // A delete takes the file out of the tree.
                                None => ws.record_delete(&e.path),
                            },
                            // An audit re-feeds every edit with its tree
                            // digest (`recorded` refuses one without it).
                            (None, None) => return Err(StopCause::PolicyAbort),
                        };
                        let path = w
                            .untrusted(&Untrusted::new(e.path.as_str().to_owned(), Source::Model))
                            .map_err(journal)?;
                        let mut ev = Event::new(EventKind::EditApplied)
                            .field("intent_seq", Trusted::U64(intent_seq))
                            .field("path", Trusted::Untrusted(path));
                        // A create has no `before` (the journal's convention).
                        if let Some(b) = e.before {
                            ev = ev.field("before", Trusted::Digest(b));
                        }
                        // The pre-image store (P-22): the file's bytes before
                        // and after are kept as content-addressed blobs, and
                        // the record cites them by their digests (`before_blob`
                        // only when there was a before; the after-blob is what
                        // a `/diff` shows; a delete cites neither after
                        // field). An image whose bytes do not hash to the
                        // digest the edit itself carries would make a record
                        // no replay can recompute, so it is refused before
                        // the record is written, with nothing journaled.
                        let mut store = |img: &Image| {
                            w.untrusted_stored(&Untrusted::new(
                                img.bytes.clone(),
                                Source::Workspace(e.path.as_str().to_owned()),
                            ))
                        };
                        let before_blob = match &e.before_image {
                            Some(img) => {
                                let d = store(img).map_err(journal)?;
                                if Some(d.sha256()) != e.before || d.sha256() != img.sha256 {
                                    return Err(journal(JournalError::InvalidEvent(
                                        "an edit image does not hash to the digest the edit carries",
                                    )));
                                }
                                Some(d.sha256())
                            }
                            // A create keeps no pre-image: the field's absence is
                            // the absent marker.
                            None => None,
                        };
                        let after_blob = match (&e.after_image, e.after) {
                            (Some(img), Some(after)) => {
                                let d = store(img).map_err(journal)?;
                                if Some(d.sha256()) != Some(after) || d.sha256() != img.sha256 {
                                    return Err(journal(JournalError::InvalidEvent(
                                        "an edit image does not hash to the digest the edit carries",
                                    )));
                                }
                                Some(d.sha256())
                            }
                            // A delete keeps no after-image: both fields
                            // absent is the absent marker.
                            (None, None) => None,
                            _ => {
                                return Err(journal(JournalError::InvalidEvent(
                                    "an edit image does not hash to the digest the edit carries",
                                )))
                            }
                        };
                        if let Some(b) = before_blob {
                            ev = ev.field("before_blob", Trusted::Digest(b));
                        }
                        if let Some(a) = after_blob {
                            ev = ev.field("after", Trusted::Digest(a));
                            ev = ev.field("after_blob", Trusted::Digest(a));
                        }
                        ev = ev.field("workspace_tree", Trusted::Digest(tree));
                        w.append(step, ev).map_err(journal)?;
                        // P-26: the record is a mark a `/rewind` can undo.
                        self.restore.push_edit(
                            step,
                            intent_seq,
                            e.path.as_str(),
                            e.before,
                            e.after,
                            tree,
                        );
                        // A written file is the model's latest read of it, so
                        // it may edit it again without re-reading; a deleted
                        // one is forgotten: a further edit needs a fresh read.
                        match e.after {
                            Some(after) => self.reads.record(e.path.as_str(), after),
                            None => self.reads.forget(e.path.as_str()),
                        }
                        self.tree = tree;
                        edited.push(e.path.as_str().to_owned());
                    }
                }
                let mut ev = Event::new(EventKind::ToolFinished)
                    .field("intent_seq", Trusted::U64(intent_seq))
                    .field("status", Trusted::Text(status_name(res.status)))
                    .field("truncated", Trusted::Bool(res.truncated))
                    .field("digest", Trusted::Digest(res.digest))
                    .field("output", Trusted::Untrusted(out));
                if let ToolStatus::Error { code } = res.status {
                    ev = ev.field("code", Trusted::U64(u64::from(code)));
                    // An edit written but not verified may have changed the
                    // workspace in a way the harness cannot state (H2b).
                    unverified = is_edit(&tool) && code == harness_tools::builtin::code::UNVERIFIED;
                }
                // A command that started (H2d): what it did, and the tree
                // digest after it, measured live or re-fed. Its kill domain
                // must be confirmed empty or the run stops here, before any
                // other file operation (option (b), the interim for the
                // file tools' race); a tree the harness could not measure
                // stops it too (a fact it cannot state).
                if let (Some(x), true) = (&res.exec, is_exec(&tool)) {
                    // P-33: the ledger's commands-run entry. The argv comes
                    // from the parsed call (re-derived identically in a
                    // replay), the one-line end from the exec record the
                    // result carries (live or re-fed).
                    if let Some(argv) = &ledger_argv {
                        self.ledger_commands.push(context::LedgerCommand {
                            argv: argv.clone(),
                            result: exec_end_text(x),
                        });
                    }
                    let tree = match fed_exec_tree {
                        Some(t) => t,
                        None => x.workspace.as_ref().map(WorkspaceTree::digest),
                    };
                    if let (None, Some(listing)) = (fed_exec_tree, &x.workspace) {
                        self.workspace = Some(listing.clone());
                    }
                    // No background process exists yet (the tools arrive
                    // with P-36i), so no loopback port is reachable and
                    // the record carries no `connect`; a live run passes
                    // the ports its live ids hold (P-36 §6.2).
                    ev = ev.field("exec", exec_fields(x, &[]));
                    if let Some(t) = tree {
                        ev = ev.field("workspace_tree", Trusted::Digest(t));
                        exec_changed = t != self.tree;
                        self.tree = t;
                        // P-26: a command's measured tree is a checkpoint.
                        self.restore.push_tree(step, t);
                    }
                    exec_stop = match (x.cleanup, tree) {
                        (ExecCleanup::Unconfirmed, _) => Some(StopCause::SandboxLost),
                        (_, None) => Some(StopCause::PolicyAbort),
                        _ => None,
                    };
                }
                // Only an ok result records a read (the reader refuses a read
                // digest on anything else; confirming review NF-3).
                if let (Some(r), ToolStatus::Ok) = (&res.read, res.status) {
                    ev = ev.field("read_sha256", Trusted::Digest(r.sha256));
                    self.reads.record(r.path.as_str(), r.sha256);
                }
                // §7.1: a timeout or a crash records the host's condition.
                // A re-fed result carries the sample recorded with it (a
                // past host cannot be re-measured).
                if matches!(res.status, ToolStatus::Timeout | ToolStatus::Crashed { .. }) {
                    let s = fed_environment.unwrap_or_else(|| self.env.sample());
                    ev = ev.field("environment", sample::to_trusted(&s));
                    if s.possibly_environmental() {
                        self.pressure.push(step);
                    }
                }
                w.append(step, ev).map_err(journal)?;
                self.detector
                    .observe(LoopEvent::Observation { digest: res.digest });
                // An exact repeat of a read on an unchanged workspace, with
                // the same output as before, is said so (a read never
                // changes the tree, so the tree now is the tree it was
                // proposed on). Only a notice: the detector's rules stand.
                if res.status == ToolStatus::Ok && is_read(&tool) {
                    let key = (
                        tool.clone(),
                        *sha256(args_text.as_bytes()).as_bytes(),
                        *self.tree.as_bytes(),
                    );
                    let out = *res.digest.as_bytes();
                    match self.reads_seen.get(&key) {
                        Some(first) => repeated = *first == out && notice.is_none(),
                        None => {
                            self.reads_seen.insert(key, out);
                        }
                    }
                }
                let body = String::from_utf8_lossy(res.output.inspect("context: observation"))
                    .into_owned();
                let body = if body.is_empty() {
                    "(the call succeeded with no output)".to_owned()
                } else {
                    body
                };
                Feedback::Observation {
                    call: tool,
                    body: Untrusted::new(body, res.output.source().clone()),
                    digest: res.digest,
                }
            }
            Err(_) => {
                // A provider failure is the tool-level "could not run"
                // (§7.1 samples on CouldNotRun; H1f-3 review F-2).
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
                Feedback::Harness(HarnessText::from_static(
                    "The tool could not run (a provider failure). Try another tool or submit.",
                ))
            }
        };
        // P-27: the task's post-edit checks run against the edit that just
        // landed; a failing check (or one that could not run) rolls it back
        // and this step's feedback becomes the check's diagnostics.
        let (feedback, restored) =
            self.post_edit_round(w, step, &edit_records, &edited, pre_edit_tree, feedback)?;
        if unverified {
            return Err(StopCause::PolicyAbort);
        }
        if let Some(cause) = exec_stop {
            return Err(cause);
        }
        // P-36f: the file helper's third loss stops the run. The failing
        // call's error result is already durable (the restart it caused is
        // visible in the journal as that error, no new record kind);
        // continuing would do the next file work outside the helper's
        // view (INV-42), so the run ends as a sandbox loss instead.
        if self
            .file_ops_stop
            .as_ref()
            .is_some_and(|f| f.load(std::sync::atomic::Ordering::SeqCst))
        {
            return Err(StopCause::SandboxLost);
        }
        // A command that changed the workspace is progress (§2.6).
        if exec_changed {
            self.detector.observe(LoopEvent::WorkspaceChanged {
                tree_digest: self.tree,
            });
        }
        // §2.6: edit churn, and a changed tree is progress.
        // §2.6: edit churn (per touched file), and a changed tree once.
        let n_edited = edited.len();
        for file in edited {
            if let LoopSignal::Stop(kind) = self.detector.observe(LoopEvent::EditApplied { file }) {
                return self.loop_stop(w, step, kind);
            }
        }
        if n_edited > 0 {
            self.detector.observe(LoopEvent::WorkspaceChanged {
                tree_digest: self.tree,
            });
        }
        let notice = if repeated {
            Some(HarnessText::from_static(
                "Notice: this call repeats an earlier one exactly, on an unchanged workspace, \
                 and its result is the same as before. Use what you already have, or try \
                 something different.",
            ))
        } else {
            notice
        };
        // P-27: a rollback says so in the same slot as the other notices.
        let notice = match restored {
            Some(n) => Some(match notice {
                Some(prev) => prev.joined(&n),
                None => n,
            }),
            None => notice,
        };
        self.turns.push(Turn {
            step,
            reply,
            action: Some(shown),
            feedback,
            notice,
        });

        // 10. Stop checks: the meter (budgets, the tool's wall time
        // included) and the journal (in drive).
        self.meter.tick_wall()?;
        self.observe_budgets(w, step)?;
        Ok(Flow::Continue)
    }

    /// The delegate step's `ToolFinished` and the turn closed around it
    /// (P-38e): the observation lands like any tool's, and when a child
    /// actually ran, its spend joins the parent's meter after the record
    /// is durable (§5.2), then the wall tick and the budget checks. Every
    /// delegate outcome but an unreadable child journal comes through here.
    #[allow(clippy::too_many_arguments)]
    fn delegate_finish<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
        step: u64,
        intent_seq: u64,
        reply: Untrusted<String>,
        shown: ShownCall,
        notice: Option<HarnessText>,
        tool: String,
        status: &'static str,
        code: Option<u16>,
        text: String,
        truncated: bool,
        spend: Option<&ChildSpend>,
    ) -> Result<Flow, StopCause> {
        let digest = sha256(text.as_bytes());
        let body = Untrusted::new(text, Source::Tool(DELEGATE_ID.to_owned()));
        let out = w
            .untrusted(&body)
            .map_err(|e: JournalError| e.stop_cause())?;
        let mut ev = Event::new(EventKind::ToolFinished)
            .field("intent_seq", Trusted::U64(intent_seq))
            .field("status", Trusted::Text(status))
            .field("truncated", Trusted::Bool(truncated))
            .field("digest", Trusted::Digest(digest))
            .field("output", Trusted::Untrusted(out));
        if let Some(code) = code {
            ev = ev.field("code", Trusted::U64(u64::from(code)));
        }
        w.append(step, ev)
            .map_err(|e: JournalError| e.stop_cause())?;
        self.detector.observe(LoopEvent::Observation { digest });
        self.turns.push(Turn {
            step,
            reply,
            action: Some(shown),
            feedback: Feedback::Observation {
                call: tool,
                body,
                digest,
            },
            notice,
        });
        if let Some(spend) = spend {
            self.meter.absorb_child(spend)?;
        }
        self.meter.tick_wall()?;
        self.observe_budgets(w, step)?;
        Ok(Flow::Continue)
    }

    /// §10: the child started but its journal cannot be read back (or its
    /// committed head is missing). The step's result is the tool-level
    /// "could not run" carrying nothing of the child's work, and the run
    /// stops: its own journal may share the child's failure.
    fn delegate_journal_lost<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
        step: u64,
        intent_seq: u64,
        error: String,
    ) -> Result<Flow, StopCause> {
        let body = Untrusted::new(
            NOT_STARTED_TEXT.to_owned(),
            Source::Tool(DELEGATE_ID.to_owned()),
        );
        let out = w
            .untrusted(&body)
            .map_err(|e: JournalError| e.stop_cause())?;
        w.append(
            step,
            Event::new(EventKind::ToolFinished)
                .field("intent_seq", Trusted::U64(intent_seq))
                .field("status", Trusted::Text("provider_error"))
                .field("truncated", Trusted::Bool(false))
                .field(
                    "digest",
                    Trusted::Digest(sha256(NOT_STARTED_TEXT.as_bytes())),
                )
                .field("output", Trusted::Untrusted(out))
                .field("code", Trusted::U64(u64::from(DELEGATE_NOT_STARTED))),
        )
        .map_err(|e: JournalError| e.stop_cause())?;
        Err(StopCause::JournalUnavailable {
            op: "child journal".to_owned(),
            error,
        })
    }

    /// Decide how the turn this step's request shows for the first time
    /// (the newest) is shown, and return the decision for the request's
    /// journal record (design row H1i). Its untrusted text is checked
    /// against every nonce drawn earlier in the run (all of them, not only
    /// those still in the context, so the decision does not depend on the
    /// window; every one has been shown to the model, which could quote it
    /// or have it echoed into tool output): its observation is withheld if
    /// the body contains one, its reply if the text the context would show
    /// of it does. Otherwise its observation gets a new nonce, drawn now,
    /// at its first render. The decision is fixed from here on.
    fn first_render(&mut self) -> Result<Option<(u64, Shown)>, StopCause> {
        let protocol = self.profile.protocol();
        let (step, reply_withheld, output_withheld) = match self.turns.last() {
            Some(t) if !self.nonces.assigned.contains_key(&t.step) => {
                let drawn: Vec<&Nonce> = self.nonces.drawn().collect();
                let has = |text: &str| drawn.iter().any(|n| contains_nonce(text, n));
                let reply = context::model_texts(protocol, t).into_iter().any(has);
                let output = match &t.feedback {
                    Feedback::Observation { body, .. } => {
                        Some(has(body.inspect("context: nonce check")))
                    }
                    Feedback::Harness(_) | Feedback::Answer => None,
                };
                (t.step, reply, output)
            }
            _ => return Ok(None),
        };
        let output = match output_withheld {
            None => None,
            Some(true) => Some(Delimiting::Withheld),
            Some(false) => Some(Delimiting::Nonce(self.draw(step)?)),
        };
        let shown = Shown {
            output,
            reply_withheld,
        };
        self.nonces.assigned.insert(step, shown.clone());
        Ok(Some((step, shown)))
    }

    /// Draw the nonce of the observation of `step`: one that no other
    /// observation carries and that no untrusted text of this run contains,
    /// observation bodies and shown replies alike (checked on every turn,
    /// not only those still shown, so the check does not depend on the
    /// window). A chance collision is drawn again, three times, before the
    /// run stops; a replay's recorded nonce that collides is a divergence
    /// (its redraw is fresh, and the request digest differs).
    fn draw(&mut self, step: u64) -> Result<Nonce, StopCause> {
        let protocol = self.profile.protocol();
        // A shown user's text is untrusted too (INV-37, P-05 §2.3): a nonce
        // inside it is never drawn again.
        let user_texts: Vec<&str> = match &self.user {
            Some(u) => u
                .users
                .iter()
                .map(|e| e.text.inspect("context: user").as_str())
                .collect(),
            None => Vec::new(),
        };
        // The project notes are untrusted text too (P-30): a nonce inside
        // them is never drawn. (A recorded nonce that already collides with
        // the notes — possible only in a resumed attempt — fails later at
        // the render, which refuses a delimiter collision.)
        let notes_text: Option<&str> = self
            .instructions
            .map(|n| n.text.inspect("context: project notes").as_str());
        for _ in 0..3 {
            let n = self.nonces.next(step).ok_or(StopCause::PolicyAbort)?;
            let taken = self.nonces.drawn().any(|m| *m == n);
            let inside = self.turns.iter().any(|t| {
                let body = match &t.feedback {
                    Feedback::Observation { body, .. } => {
                        contains_nonce(body.inspect("context: nonce check"), &n)
                    }
                    Feedback::Harness(_) | Feedback::Answer => false,
                };
                body || context::model_texts(protocol, t)
                    .into_iter()
                    .any(|s| contains_nonce(s, &n))
            }) || user_texts.iter().any(|s| contains_nonce(s, &n))
                || notes_text.is_some_and(|s| contains_nonce(s, &n));
            if !taken && !inside {
                return Ok(n);
            }
        }
        Err(StopCause::PolicyAbort)
    }

    /// Render the request. Every observation already carries its nonce
    /// (H1i), drawn so that no shown body contains any of them; a request
    /// the renderer refuses anyway (a nonce inside a body, a malformed tool
    /// sequence) is a harness bug, and the run stops.
    fn request(
        &self,
        messages: Vec<harness_model::Message>,
        tools: &[ToolSpec],
    ) -> Result<(ModelRequest, Value), StopCause> {
        let req = ModelRequest {
            messages,
            tools: tools.to_vec(),
        };
        let v = render_request(&req, self.profile).map_err(|_| StopCause::PolicyAbort)?;
        Ok((req, v))
    }

    /// §2.2 step 3: an empty, truncated or unusable completion is never a
    /// turn result; it counts as a format error. An unreachable backend
    /// stops the run.
    fn model_error(
        &mut self,
        e: ModelError,
        step: u64,
        request_bytes: u64,
    ) -> Result<Flow, StopCause> {
        // The prompt was sent (and possibly processed): charge the
        // conservative estimate for it.
        self.meter.record_tokens(None, request_bytes, 0)?;
        // Static text per protocol (H1h: the native protocol's names its
        // own form, like its repair messages).
        let native = self.profile.protocol() == Protocol::Native;
        let text = match (e, native) {
            (ModelError::Empty, false) => "The reply was empty. Reply with exactly one action.",
            (ModelError::Empty, true) => {
                "The reply was empty. Call exactly one tool through the function-calling interface."
            }
            (ModelError::Truncated(_), false) => {
                "The reply was cut off. Keep the reasoning short and reply with exactly one action."
            }
            (ModelError::Truncated(_), true) => {
                "The reply was cut off. Keep the reasoning short and call exactly one tool \
                 through the function-calling interface."
            }
            (ModelError::Unusable(_), false) => {
                "The reply could not be used. Reply with exactly one action."
            }
            (ModelError::Unusable(_), true) => {
                "The reply could not be used. Call exactly one tool through the function-calling interface."
            }
            (
                ModelError::Unavailable(_) | ModelError::RateLimited { .. },
                _,
            ) => {
                // P-05 §3: in a session an unavailable backend ends the
                // TURN (the user may be back when it is); a batch run stops.
                if self.user.is_some() {
                    return Ok(Flow::EndTurn(TurnEnd::ModelUnavailable));
                }
                return Err(StopCause::ModelUnavailable);
            }
            (ModelError::ReplayDiverged { .. }, _) => return Err(StopCause::ModelUnavailable),
        };
        self.meter.record_format_error()?;
        let stalled = self.feed_stall()?;
        if let Some(kind) = stalled {
            return Ok(Flow::EndTurn(TurnEnd::Loop(kind)));
        }
        self.turns.push(Turn {
            step,
            reply: Untrusted::new(String::new(), Source::Model),
            action: None,
            feedback: Feedback::Harness(HarnessText::from_static(text)),
            notice: None,
        });
        // P-05 §3: a turn's run of format errors ends the TURN, not the
        // session (the meter's own limit is off in a session).
        if let Some(u) = &self.user {
            if self.meter.consecutive_format_errors() >= u.limits.format_errors {
                return Ok(Flow::EndTurn(TurnEnd::FormatErrors));
            }
        }
        Ok(Flow::Continue)
    }

    /// The 80% standing condition per budget dimension (§2.6), journaled
    /// only when it begins or ends (`BudgetCharged`, key = dimension).
    pub(crate) fn observe_budgets<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
        step: u64,
    ) -> Result<(), StopCause> {
        for dim in BUDGET_DIMS {
            let Some(key) = Ident::of(budget_key(dim)) else {
                continue;
            };
            let c = Condition {
                kind: ConditionKind::BudgetAbove80,
                key,
            };
            w.observe_condition(step, &c, self.meter.above_80(dim))
                .map_err(journal)?;
        }
        Ok(())
    }

    /// A step with no action still counts toward no-progress (§2.6). In a
    /// session a detected loop ends the TURN, not the run (P-05 §3): the
    /// kind comes back for the turn's `TurnEnded` record.
    fn feed_stall(&mut self) -> Result<Option<LoopKind>, StopCause> {
        match self.detector.observe(LoopEvent::Step) {
            LoopSignal::Stop(kind) => {
                if self.user.is_some() {
                    Ok(Some(kind))
                } else {
                    Err(StopCause::Loop(kind))
                }
            }
            _ => Ok(None),
        }
    }

    /// The UI drain (P-05 §1.3, §8): hand every record written and fsynced
    /// since the last drain to the session's sink, in seq order. Display
    /// only — never an input to a decision — and a no-op without a sink
    /// (a batch run's tap stays off, so it buffers nothing).
    pub(crate) fn ui_drain<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
    ) {
        let Some(sink) = self.user.as_ref().and_then(|u| u.sink) else {
            return;
        };
        let blobs = match &self.user {
            Some(u) => u.blobs.clone(),
            None => return,
        };
        for t in w.drain_tap() {
            sink.emit(&crate::session::UiEvent {
                seq: t.seq,
                step: t.step,
                kind: t.kind,
                body: &t.body,
                blobs: &blobs,
            });
        }
    }
}

/// The model's reply as the TEXT protocol shows it back: the content, plus
/// each native tool call a text-protocol reply carried (a format error),
/// written out so the model sees what it sent. Untrusted, like the reply.
/// The native protocol never shows it: a native action is shown as a tool
/// call (`ShownCall`), and a native reply without one is withheld (H1h).
fn shown_reply(c: &Completion) -> Untrusted<String> {
    let mut s = c.content.inspect("context: reply").clone();
    for call in &c.tool_calls {
        let raw = call.inspect("context: reply tool call");
        s.push_str(&format!("\n[tool call] {} {}", raw.name, raw.arguments));
    }
    Untrusted::new(s, Source::Model)
}

/// The dimensions whose 80% crossing is journaled (§2.6). Repair rounds
/// are a verification budget (not spent in H1).
const BUDGET_DIMS: [BudgetDim; 5] = [
    BudgetDim::Steps,
    BudgetDim::Tokens,
    BudgetDim::Wall,
    BudgetDim::Cost,
    BudgetDim::FormatErrors,
];

pub(crate) fn budget_key(d: BudgetDim) -> &'static str {
    match d {
        BudgetDim::Steps => "steps",
        BudgetDim::Tokens => "tokens",
        BudgetDim::Wall => "wall",
        BudgetDim::Cost => "cost",
        BudgetDim::FormatErrors => "format_errors",
        BudgetDim::RepairRounds => "repair_rounds",
    }
}

fn fe_name(e: FormatError) -> &'static str {
    match e {
        FormatError::NoAction => "no_action",
        FormatError::SeveralActions => "several_actions",
        FormatError::Unbalanced => "unbalanced",
        FormatError::ToolCallsInTextMode => "tool_calls_in_text_mode",
        FormatError::BadJson(_) => "bad_json",
        FormatError::WrongShape => "wrong_shape",
        FormatError::UnknownTool => "unknown_tool",
        FormatError::TooLarge => "too_large",
    }
}
