//! The interactive session loop (P-05, this slice P-13): [`run_session`],
//! the twin of [`crate::driver::run`] that serves one user at a time — and,
//! since P-39i, [`run_research`], the same loop for a research session
//! (no workspace, the research context, §2.2-§2.4).
//!
//! A session is one run whose journal holds any number of **user turns**.
//! Between turns the loop asks its [`UserInput`] for the next message (the
//! wait is not charged to the wall budget, like an approval wait). Each
//! message opens a turn: the workspace is measured again (external edits
//! between turns are named to the model, INV-39), the message is journaled
//! (`UserTurn`), and model/tool steps run until the turn ends — a
//! plain-text answer, an accepted submission, the turn's step or
//! format-error budget, a detected loop, or an unavailable model —
//! journaled as `TurnEnded`. `submit` ends the turn, not the session. The
//! session ends when the input ends, the run budget is carved to nothing,
//! the journal fails, or the context window fills; the outcome is
//! `Indeterminate { NothingChecked }` unless the journal failed.
//!
//! The sink ([`EventSink`]) sees every journaled record after it is
//! written and fsynced, in seq order, through the journal tap (P-05 §1.3).
//! It is display only: nothing it returns can reach a decision, because it
//! returns nothing.

use std::path::Path;
use std::time::{Duration, Instant};

use gate_outcome::Digest;
use harness_core::environment::EnvProbe;
use harness_core::{BudgetDim, LoopDetector, Source, StopCause, Untrusted};
use harness_journal::writer::SystemClock;
use harness_journal::{
    layout, BlobSink, Clock, Event, EventKind, JournalFile, JournalWriter, Trusted,
};
use harness_manifest::admission::Registry;
use harness_model::context::{user_fits, UserEntry};
use harness_model::profile::Profile;
use harness_model::wire::contains_nonce;
use harness_model::ModelBackend;
use harness_policy::locality::{self, LocalityProbe};
use harness_policy::{SessionKind, UserPolicy};
use harness_sandbox::Confinement;
use harness_tools::builtin::workspace_tree;
use harness_tools::builtin::WorkspaceFacts;
use harness_tools::ReadLog;
use serde_json::{Map, Value};
use std::collections::VecDeque;

use crate::approve::Approver;
use crate::driver::step::{journal, Flow, TurnEnd, UserState};
use crate::driver::stop::End;
use crate::driver::{
    attempt_check, commit, create_run, exec_tools, header, loop_facts, new_meter,
    no_workspace_facts, prepare, Approvals, BudgetNotices, ExecHeader, HeaderInputs, Loop,
    LoopInit, NonceSource, PortsHeader, Prepared, RunConfig, RunRefused, RunReport, TaskSpec,
};
use crate::presubmit::PresubmitState;

// ---------------------------------------------------------------------------
// Inputs.
// ---------------------------------------------------------------------------

/// One message from the user (P-05 §8). Refused before anything is
/// journaled: an empty (after trimming) text, or one over [`UserMessage::MAX_BYTES`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserMessage(String);

/// Why a [`UserMessage`] was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UserMessageRefused {
    /// The text was empty after trimming.
    #[error("a user message must not be empty")]
    Empty,
    /// The text was over the byte cap.
    #[error("a user message is limited to {max} bytes (got {len})")]
    TooLong {
        /// The text's length in bytes.
        len: usize,
        /// The cap.
        max: usize,
    },
}

impl UserMessage {
    /// The cap on one message's length, in bytes.
    pub const MAX_BYTES: usize = 64 * 1024;

    /// A message from non-empty text of at most [`UserMessage::MAX_BYTES`]
    /// bytes. The text is used as given (no trimming).
    pub fn new(text: String) -> Result<Self, UserMessageRefused> {
        if text.trim().is_empty() {
            return Err(UserMessageRefused::Empty);
        }
        if text.len() > Self::MAX_BYTES {
            return Err(UserMessageRefused::TooLong {
                len: text.len(),
                max: Self::MAX_BYTES,
            });
        }
        Ok(Self(text))
    }

    /// The message's text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why the input ended (P-05 §1.1): the names the `InputEnded` record
/// carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEnd {
    /// The input source is done (stdin closed, UI closed).
    Eof,
    /// The user asked to quit.
    Exit,
    /// No message arrived within the deadline.
    Timeout,
}

impl InputEnd {
    fn name(self) -> &'static str {
        match self {
            InputEnd::Eof => "eof",
            InputEnd::Exit => "exit",
            InputEnd::Timeout => "timeout",
        }
    }
}

/// What [`UserInput::next`] reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserInputEvent {
    /// The user's next message.
    Message(UserMessage),
    /// The user asked to restore an earlier workspace state (`/undo`,
    /// `/rewind N`, P-26). Handled between turns; a refusal journals
    /// nothing.
    Restore(crate::restore::RestoreCommand),
    /// The input ended; the session does too (`RunStopped`,
    /// cause `session_ended`).
    End(InputEnd),
}

/// Where the session's messages come from (P-05 §8), a synchronous trait
/// like [`Approver`]. Called only BETWEEN turns, under a paused wall clock,
/// with the instant past which [`InputEnd::Timeout`] is the answer.
pub trait UserInput {
    /// The next message, or the input's end. Must return by `deadline`.
    fn next(&self, deadline: Instant) -> UserInputEvent;
}

/// One recorded input (P-17 §6): a `UserTurn`'s re-fed parts, or an
/// `InputEnded`. The parts the loop recomputes (the turn's number, whether
/// the workspace changed, the shown decision, the allowance) are carried
/// by nothing here: the replay recomputes and compares them.
pub(crate) enum RecordedInput {
    /// A recorded `UserTurn`: the message, the facts it was measured with
    /// (its tree, file and oversize counts), and the wall time the loop
    /// had used when it was journaled (the clock is never recomputable).
    Message {
        text: String,
        facts: WorkspaceFacts,
        wall_used_ms: u64,
    },
    /// A recorded `InputEnded`: its reason is re-fed; its turn number is
    /// recomputed.
    End(InputEnd),
    /// A recorded `Restored` (P-26): the checkpoint it went back to (the
    /// step and tree digest the record names). Everything else about the
    /// restore is recomputed from the marks and compared by the record's
    /// body.
    Restore {
        /// The step the `Restored` record names.
        to_step: u64,
        /// The tree digest the `Restored` record names.
        tree_digest: Digest,
    },
}

/// The name a recorded `InputEnded` carries, back to the enum: anything
/// else is not a record this loop writes.
pub(crate) fn parse_input_end(reason: &str) -> Option<InputEnd> {
    match reason {
        "eof" => Some(InputEnd::Eof),
        "exit" => Some(InputEnd::Exit),
        "timeout" => Some(InputEnd::Timeout),
        _ => None,
    }
}

/// Where a session loop's turns come from: live (P-05), a replay's
/// recorded inputs (an audit, P-17 §6), or a resume's catch-up — recorded
/// inputs first, then the live source (P-17 §7).
pub(crate) enum SessionInputs<'x> {
    Live(&'x dyn UserInput),
    Replay(VecDeque<RecordedInput>),
    Resume {
        recorded: VecDeque<RecordedInput>,
        live: &'x dyn UserInput,
    },
}

// ---------------------------------------------------------------------------
// The UI drain.
// ---------------------------------------------------------------------------

/// One journaled record, as the sink sees it (P-05 §1.3): a projection of
/// what was written and fsynced, in seq order. Display only.
#[derive(Debug, Clone)]
pub struct UiEvent<'a> {
    /// Sequence number.
    pub seq: u64,
    /// Loop step.
    pub step: u64,
    /// Kind.
    pub kind: EventKind,
    /// Body (untrusted payloads still escaped and marked).
    pub body: &'a Map<String, Value>,
    /// The attempt's blobs directory, for resolving untrusted payloads
    /// stored as blobs.
    pub blobs: &'a Path,
}

/// Where the session's records are shown (P-05 §8). Never an input to a
/// decision: `emit` returns nothing.
pub trait EventSink {
    /// One record, written and fsynced.
    fn emit(&self, ev: &UiEvent<'_>);
}

// ---------------------------------------------------------------------------
// Configuration.
// ---------------------------------------------------------------------------

/// A user turn's budgets (P-05 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TurnLimits {
    /// Longest one turn may run (model/tool steps).
    pub steps: u32,
    /// Consecutive unparseable replies a turn may absorb before it ends.
    pub format_errors: u32,
}

/// A session's configuration: the run's budgets, the per-turn budgets, and
/// how long to wait for input.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// The run's budgets and timeouts (`limits.steps` is the whole
    /// session's step budget; `limits.format_errors` is ignored — the
    /// meter never latches format errors in a session, the turn limit
    /// governs).
    pub run: RunConfig,
    /// Each turn's budgets.
    pub turn: TurnLimits,
    /// Longest the loop waits for the next message (not charged to the
    /// wall budget). Past it the input reports a timeout and the session
    /// ends.
    pub input_timeout: Duration,
}

impl SessionConfig {
    /// The P-05 §15 defaults: 500 steps for the whole session (4 h of
    /// working wall), 50 steps and 3 format errors per turn, 24 h of
    /// input idle.
    pub fn defaults(tokens: u64) -> Self {
        let mut run = RunConfig::defaults(tokens);
        run.limits.steps = 500;
        run.limits.wall = Duration::from_secs(4 * 60 * 60);
        Self {
            run,
            turn: TurnLimits {
                steps: 50,
                format_errors: 3,
            },
            input_timeout: Duration::from_secs(24 * 60 * 60),
        }
    }
}

/// The limits a session config may use, checked before anything is written
/// (P-05 §4): a refusal here is `RunRefused::TurnLimits`, nothing ran.
pub(crate) fn check_turn_limits(config: &SessionConfig) -> Result<(), RunRefused> {
    if config.run.limits.steps == 0 || config.run.limits.steps > 5000 {
        return Err(RunRefused::TurnLimits(
            "the run step limit must be between 1 and 5000",
        ));
    }
    if config.turn.steps == 0 || config.turn.steps > 500 {
        return Err(RunRefused::TurnLimits(
            "the turn step limit must be between 1 and 500",
        ));
    }
    if config.turn.steps > config.run.limits.steps {
        return Err(RunRefused::TurnLimits(
            "the turn step limit exceeds the run's step budget",
        ));
    }
    if config.turn.format_errors == 0 || config.turn.format_errors > 10 {
        return Err(RunRefused::TurnLimits(
            "the turn format-error limit must be between 1 and 10",
        ));
    }
    Ok(())
}

/// The meter limits a session runs under: the run's, with the format-error
/// dimension off (the meter never latches it; the turn limit governs,
/// P-05 §4). The header records these, so an audit or a resume recomputes
/// them from the same config.
pub(crate) fn session_limits(config: &SessionConfig) -> harness_core::MeterLimits {
    let mut limits = config.run.limits.clone();
    limits.format_errors = u32::MAX;
    limits
}

// ---------------------------------------------------------------------------
// run_session.
// ---------------------------------------------------------------------------

/// Everything [`run_session`] needs (P-05 §8): [`crate::driver::run`]'s
/// inputs, plus the session config, the input source and the sink.
pub struct SessionRun<'a> {
    /// The per-user state root (§2.8). Must exist.
    pub state_root: &'a Path,
    /// The workspace the read tools see.
    pub workspace: &'a Path,
    /// The task.
    pub spec: &'a TaskSpec,
    /// Admitted providers.
    pub registry: &'a Registry,
    /// User policy.
    pub policy: &'a UserPolicy,
    /// The model profile.
    pub profile: &'a Profile,
    /// The model backend.
    pub backend: &'a dyn ModelBackend,
    /// The filesystem-locality probe.
    pub probe: &'a dyn LocalityProbe,
    /// The environment probe (§7.1).
    pub env: &'a dyn EnvProbe,
    /// Budgets, timeouts and the turn limits.
    pub config: &'a SessionConfig,
    /// Who answers an `Ask` (§5.3); `None` turns every ask into a deny.
    pub approver: Option<&'a dyn Approver>,
    /// Where commands are confined (H2d); asked for only with an exec
    /// grant.
    pub confinement: Option<&'a dyn Confinement>,
    /// Where the session's messages come from.
    pub input: &'a dyn UserInput,
    /// Where journaled records are shown as they are written; `None`
    /// buffers nothing and shows nothing.
    pub sink: Option<&'a dyn EventSink>,
}

/// How a session that started ended: the run's report (cause
/// `session_ended` when the input ended) and how many user turns the
/// journal holds.
#[derive(Debug)]
pub struct SessionReport {
    /// The run's report.
    pub run: RunReport,
    /// User turns journaled (refused inputs included: each journaled a
    /// `UserTurn`).
    pub turns: u64,
}

/// Run an interactive session (see the module docs). `Err` means the
/// session did not start.
pub fn run_session(s: SessionRun<'_>) -> Result<SessionReport, RunRefused> {
    // A research session (P-39i) is not a coding session: it is driven by
    // `run_research`, whose loop carries no workspace.
    if let SessionKind::Research(_) = s.spec.kind {
        return Err(RunRefused::Research(
            "a research session runs under run_research, not run_session",
        ));
    }
    check_turn_limits(s.config)?;
    let limits = session_limits(s.config);

    // ---- Before anything is written (the batch run's order). ----
    let pre = prepare(
        s.spec,
        s.registry,
        s.policy,
        s.profile,
        Some(s.workspace),
        s.state_root,
        s.probe,
        &s.config.run,
        s.approver.is_some(),
        s.confinement,
        s.backend.identity().endpoint,
    )?;
    let facts = pre.facts;

    // ---- runs/<run-id>, the first attempt, the durable header. ----
    let (run_id, run_dir) = create_run(&pre.state_root)?;
    if let Some(str) = run_dir.to_str() {
        locality::check(s.probe, str)?;
    }
    let exec_header = pre
        .exec
        .as_ref()
        .map(|(p, w)| ExecHeader::live(p, w, &s.config.run));
    let exec_tools = exec_tools(&pre, &run_dir, s.confinement, &s.config.run)?;
    let ports_header = PortsHeader::of(s.spec, &s.config.run, pre.ports.as_ref());
    let header = header(&HeaderInputs {
        spec: s.spec,
        registry: s.registry,
        policy: s.policy,
        profile: s.profile,
        identity: &s.backend.identity(),
        facts,
        limits: &limits,
        resumed_from: None,
        environment: s.env.sample(),
        environment_recorded: false,
        approver_present: s.approver.is_some(),
        session: Some(s.config.turn),
        exec: exec_header,
        ports: ports_header,
        workspace_mode: s.config.run.workspace_mode.as_ref(),
    })?;
    let (mut w, attempt) = JournalWriter::create_next_attempt_checked(
        &run_dir,
        run_id.clone(),
        header,
        &attempt_check(s.probe),
    )?;

    // The UI drain (P-05 §1.3): on only with a sink, and only here (a
    // batch run's tap stays off, so it buffers nothing).
    if s.sink.is_some() {
        w.enable_tap();
    }
    let blobs = layout::attempt_dir(&run_dir, attempt).join(layout::BLOBS_DIR);

    // ---- The loop. ----
    let meter = new_meter(limits, Box::new(SystemClock::default()));
    let edit_tools = pre.edit_tools.clone();
    let mut lp = Loop::new(LoopInit {
        session: pre.session,
        registry: s.registry,
        tools: pre.tools,
        task: &s.spec.task,
        facts: loop_facts(&facts, s.spec),
        profile: s.profile,
        backend: s.backend,
        providers: Prepared::providers(pre.read_tools, pre.edit_tools, pre.patch_tools, exec_tools),
        meter,
        detector: LoopDetector::new(),
        turns: Vec::new(),
        config: &s.config.run,
        step: 0,
        nonces: NonceSource::default(),
        feed: std::collections::VecDeque::new(),
        reads: ReadLog::default(),
        tree: facts.tree,
        workspace: pre.tree,
        research: false,
        approvals: Approvals::new(
            &run_id,
            attempt,
            s.approver,
            std::collections::VecDeque::new(),
        )
        .may_grant(s.config.run.allow_session_grants)
        .with_edits(edit_tools),
        env: s.env,
        pressure: Vec::new(),
        reads_seen: Default::default(),
        todo: crate::driver::todo_for(&s.spec.grants),
        notices: BudgetNotices::live(s.config.run.limits.wall),
        presubmit: PresubmitState::of(&s.spec.presubmit),
        restore: Default::default(),
        user: Some(UserState {
            limits: s.config.turn,
            turn: 1,
            allowance: 0,
            used: 0,
            users: Vec::new(),
            deliverable: None,
            root: Some(s.workspace.to_path_buf()),
            blobs,
            sink: s.sink,
        }),
    });
    let end = lp.drive_session(&mut w, SessionInputs::Live(s.input), s.config.input_timeout);
    let turns = lp.user.as_ref().map_or(0, |u| u.turn.saturating_sub(1));
    let released = commit(w, &end, None);
    Ok(SessionReport {
        run: RunReport {
            run: run_id,
            attempt,
            run_dir,
            cause: end.cause,
            outcome: released.outcome,
            chain_head: released.chain_head,
            steps: end.step,
            journal_error: released.error,
            possibly_environmental: lp.pressure,
            presubmit: lp.presubmit.as_ref().map(PresubmitState::report),
        },
        turns,
    })
}

// ---------------------------------------------------------------------------
// run_research (P-39i).
// ---------------------------------------------------------------------------

/// Everything [`run_research`] needs (P-39i): a [`SessionRun`] without a
/// workspace — a research session has none (§2.4), and its turn starts
/// re-measure nothing (P-05 D4 is a coding session's check).
pub struct ResearchRun<'a> {
    /// The per-user state root (§2.8). Must exist.
    pub state_root: &'a Path,
    /// The task: kind [`SessionKind::Research`] (refused otherwise), grants
    /// the task tools only (the web capabilities are wired by P-39j).
    pub spec: &'a TaskSpec,
    /// Admitted providers (the research registry: §2.2).
    pub registry: &'a Registry,
    /// User policy.
    pub policy: &'a UserPolicy,
    /// The model profile.
    pub profile: &'a Profile,
    /// The model backend.
    pub backend: &'a dyn ModelBackend,
    /// The filesystem-locality probe.
    pub probe: &'a dyn LocalityProbe,
    /// The environment probe (§7.1).
    pub env: &'a dyn EnvProbe,
    /// Budgets, timeouts and the turn limits.
    pub config: &'a SessionConfig,
    /// Who answers an `Ask` (§5.3); `None` turns every ask into a deny.
    pub approver: Option<&'a dyn Approver>,
    /// Where the session's confinement is witnessed (INV-42): the web
    /// airlock's cases must be covered, or the session does not start.
    pub confinement: Option<&'a dyn Confinement>,
    /// Where the session's messages come from.
    pub input: &'a dyn UserInput,
    /// Where journaled records are shown as they are written; `None`
    /// buffers nothing and shows nothing.
    pub sink: Option<&'a dyn EventSink>,
}

/// Run a research session (P-39i, §2.2-§2.4): the session loop with no
/// workspace — the same turn budget, input handling and journal records as
/// [`run_session`], but no tree walk at a turn's start (the facts stay the
/// no-workspace facts), the research context (`rh-research/1`), and the
/// header's `session_kind`/`web` keys. `Err` means the session did not
/// start.
pub fn run_research(s: ResearchRun<'_>) -> Result<SessionReport, RunRefused> {
    if let SessionKind::Coding = s.spec.kind {
        return Err(RunRefused::Research(
            "run_research runs a research session; this task is a coding one",
        ));
    }
    check_turn_limits(s.config)?;
    let limits = session_limits(s.config);

    // ---- Before anything is written (the session's order; prepare's
    // research branch takes no workspace and demands the airlock's
    // witness, INV-42). ----
    let pre = prepare(
        s.spec,
        s.registry,
        s.policy,
        s.profile,
        None,
        s.state_root,
        s.probe,
        &s.config.run,
        s.approver.is_some(),
        s.confinement,
        s.backend.identity().endpoint,
    )?;
    let facts = pre.facts;

    // ---- runs/<run-id>, the first attempt, the durable header. ----
    let (run_id, run_dir) = create_run(&pre.state_root)?;
    if let Some(str) = run_dir.to_str() {
        locality::check(s.probe, str)?;
    }
    // No exec grant is possible (prepare refused the exec section), so no
    // exec header and no exec tools; no port grant either (P-36g: prepare
    // refused it), so no ports header.
    let header = header(&HeaderInputs {
        spec: s.spec,
        registry: s.registry,
        policy: s.policy,
        profile: s.profile,
        identity: &s.backend.identity(),
        facts,
        limits: &limits,
        resumed_from: None,
        environment: s.env.sample(),
        environment_recorded: false,
        approver_present: s.approver.is_some(),
        session: Some(s.config.turn),
        exec: None,
        ports: None,
        workspace_mode: s.config.run.workspace_mode.as_ref(),
    })?;
    let (mut w, attempt) = JournalWriter::create_next_attempt_checked(
        &run_dir,
        run_id.clone(),
        header,
        &attempt_check(s.probe),
    )?;

    // The UI drain (P-05 §1.3), as in a coding session.
    if s.sink.is_some() {
        w.enable_tap();
    }
    let blobs = layout::attempt_dir(&run_dir, attempt).join(layout::BLOBS_DIR);

    // ---- The loop: the session loop, workspace-less (P-39i). The facts
    // are the research facts; the tree is the digest of nothing and no
    // provider serves tools (the task tools are the loop's own). ----
    let meter = new_meter(limits, Box::new(SystemClock::default()));
    let mut lp = Loop::new(LoopInit {
        session: pre.session,
        registry: s.registry,
        tools: pre.tools,
        task: &s.spec.task,
        facts: loop_facts(&facts, s.spec),
        profile: s.profile,
        backend: s.backend,
        providers: Prepared::providers(None, None, None, None),
        meter,
        detector: LoopDetector::new(),
        turns: Vec::new(),
        config: &s.config.run,
        step: 0,
        nonces: NonceSource::default(),
        feed: std::collections::VecDeque::new(),
        reads: ReadLog::default(),
        tree: facts.tree,
        workspace: None,
        research: true,
        approvals: Approvals::new(
            &run_id,
            attempt,
            s.approver,
            std::collections::VecDeque::new(),
        ),
        env: s.env,
        pressure: Vec::new(),
        reads_seen: Default::default(),
        todo: crate::driver::todo_for(&s.spec.grants),
        notices: BudgetNotices::live(s.config.run.limits.wall),
        presubmit: PresubmitState::of(&s.spec.presubmit),
        restore: Default::default(),
        user: Some(UserState {
            limits: s.config.turn,
            turn: 1,
            allowance: 0,
            used: 0,
            users: Vec::new(),
            deliverable: None,
            // No workspace: a turn's start re-measures nothing (P-05 D4 is
            // skipped), so `external_change` is always false.
            root: None,
            blobs,
            sink: s.sink,
        }),
    });
    let end = lp.drive_session(&mut w, SessionInputs::Live(s.input), s.config.input_timeout);
    let turns = lp.user.as_ref().map_or(0, |u| u.turn.saturating_sub(1));
    let released = commit(w, &end, None);
    Ok(SessionReport {
        run: RunReport {
            run: run_id,
            attempt,
            run_dir,
            cause: end.cause,
            outcome: released.outcome,
            chain_head: released.chain_head,
            steps: end.step,
            journal_error: released.error,
            possibly_environmental: lp.pressure,
            presubmit: lp.presubmit.as_ref().map(PresubmitState::report),
        },
        turns,
    })
}

// ---------------------------------------------------------------------------
// The session loop.
// ---------------------------------------------------------------------------

/// What `begin_user_turn` decided about the message.
enum TurnStart {
    /// The message is shown; its turn's steps may run.
    Shown,
    /// The message is refused (a drawn nonce inside it, or it does not fit
    /// the users' share): the turn ends at once, no model call.
    Refused,
}

impl<'a> Loop<'a> {
    /// Run user turns until the session stops (P-05 §12): input, turn,
    /// input, turn… Each iteration is one of: a stop the meter or the
    /// carved step budget already decided, the input's end, or one user
    /// turn. The inputs are live (P-05), recorded (an audit's replay,
    /// P-17 §6), or a resume's (recorded catch-up first, then live, P-17
    /// §7); recorded inputs are consumed only BETWEEN turns, never inside
    /// one, so a resume's mid-turn catch-up runs the interrupted turn's
    /// steps live without asking for input.
    pub(crate) fn drive_session<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
        inputs: SessionInputs<'_>,
        input_timeout: Duration,
    ) -> End {
        let (mut recorded, live): (VecDeque<RecordedInput>, Option<&dyn UserInput>) = match inputs {
            SessionInputs::Live(input) => (VecDeque::new(), Some(input)),
            SessionInputs::Replay(recorded) => (recorded, None),
            SessionInputs::Resume { recorded, live } => (recorded, Some(live)),
        };
        // What the next input is: a live event, or one recorded input. A
        // replay whose recorded inputs are gone stops as cancelled (P-17
        // §6): nothing was journaled for a next turn, so there is no
        // `InputEnded` to write and no record after it to compare.
        enum Next {
            Live(UserInputEvent),
            Message {
                text: String,
                facts: WorkspaceFacts,
                wall_used_ms: u64,
            },
            Restore {
                to_step: u64,
                tree_digest: Digest,
            },
            End(InputEnd),
            Spent,
        }
        loop {
            self.ui_drain(w);
            // A latched budget (tokens, wall, cost) stops the session.
            if let Some(cause) = self.meter.stop_cause() {
                return self.session_end(cause);
            }
            // P-05 §4 (the carve): the session's step budget is carved
            // among its turns; with none left there is no input to ask for
            // and nothing to run it on.
            let remaining = u64::from(self.config.limits.steps)
                .saturating_sub(u64::from(self.meter.steps_spent()));
            if remaining == 0 {
                return self.session_end(StopCause::Budget(BudgetDim::Steps));
            }
            let deliverable = self.deliverable();

            // The wait for input is not charged to the wall budget
            // (P-05 §4, INV-41), like an approval wait (§2.4). The pause
            // guard lives exactly as long as the wait (it ends the pause on
            // drop), so the wait sits in its own block, and the End is
            // built from values read before the meter is borrowed. A
            // replay's recorded input needs no wait (the clock is not
            // real), but sits under the same paused meter.
            let next = {
                let at_step = self.step;
                let pause = match self.meter.pause_wall() {
                    Ok(pause) => pause,
                    Err(cause) => {
                        return End {
                            cause,
                            step: at_step,
                            deliverable,
                        }
                    }
                };
                let next = if recorded.is_empty() {
                    match live {
                        Some(input) => {
                            let deadline = Instant::now() + input_timeout;
                            Next::Live(input.next(deadline))
                        }
                        None => Next::Spent,
                    }
                } else {
                    match recorded.pop_front() {
                        Some(RecordedInput::Message {
                            text,
                            facts,
                            wall_used_ms,
                        }) => Next::Message {
                            text,
                            facts,
                            wall_used_ms,
                        },
                        Some(RecordedInput::Restore {
                            to_step,
                            tree_digest,
                        }) => Next::Restore {
                            to_step,
                            tree_digest,
                        },
                        Some(RecordedInput::End(reason)) => Next::End(reason),
                        None => Next::Spent,
                    }
                };
                drop(pause);
                next
            };

            let message = match next {
                Next::Spent => {
                    return End {
                        cause: StopCause::Cancelled,
                        step: self.step,
                        deliverable,
                    }
                }
                // P-05 §1.1: the input's end is journaled, then the run
                // stops with cause `session_ended`. A replay re-feeds the
                // recorded reason; the turn count is recomputed.
                Next::End(reason) | Next::Live(UserInputEvent::End(reason)) => {
                    let turn = self.turns_journaled();
                    let ev = Event::new(EventKind::InputEnded)
                        .field("reason", Trusted::Text(reason.name()))
                        .field("turn", Trusted::U64(turn));
                    if let Err(e) = w.append(self.step, ev) {
                        return self.session_end(journal(e));
                    }
                    self.ui_drain(w);
                    if w.is_poisoned() {
                        return self.poisoned();
                    }
                    return End {
                        cause: StopCause::SessionEnded,
                        step: self.step,
                        deliverable,
                    };
                }
                // P-26: a restore command runs between turns, consumes no
                // step and opens no turn. Applied (and journaled) or not,
                // the loop asks for the next input afterwards.
                Next::Live(UserInputEvent::Restore(cmd)) => {
                    if let Err(cause) = self.restore_to_step(w, cmd) {
                        return self.session_end(cause);
                    }
                    self.ui_drain(w);
                    if w.is_poisoned() {
                        return self.poisoned();
                    }
                    continue;
                }
                // P-26: a recorded `Restored` is recomputed from the marks,
                // never re-applied — the replay has no workspace.
                Next::Restore {
                    to_step,
                    tree_digest,
                } => {
                    if let Err(cause) = self.recompute_restore(w, to_step, tree_digest) {
                        return self.session_end(cause);
                    }
                    self.ui_drain(w);
                    if w.is_poisoned() {
                        return self.poisoned();
                    }
                    continue;
                }
                Next::Live(UserInputEvent::Message(m)) => {
                    match self.begin_user_turn(
                        w,
                        m.as_str(),
                        u32::try_from(remaining).unwrap_or(u32::MAX),
                    ) {
                        Err(cause) => return self.session_end(cause),
                        Ok(turn) => turn,
                    }
                }
                Next::Message {
                    text,
                    facts,
                    wall_used_ms,
                } => {
                    // P-17 §6: a replayed turn re-feeds the recorded
                    // measurement and the recorded wall time; everything
                    // else about the turn is recomputed, to be compared.
                    let remaining = u32::try_from(remaining).unwrap_or(u32::MAX);
                    match self.open_user_turn(w, &text, facts, wall_used_ms, remaining) {
                        Err(cause) => return self.session_end(cause),
                        Ok(turn) => turn,
                    }
                }
            };

            match message {
                TurnStart::Refused => {
                    // P-05 §2.3: a refused input journaled its `UserTurn`
                    // (shown: withheld | over_share) and ends its turn at
                    // once: no model call, no steps.
                    if let Err(e) = self.append_turn_ended(w, "input_refused", 0) {
                        return self.session_end(e);
                    }
                    self.ui_drain(w);
                    if w.is_poisoned() {
                        return self.poisoned();
                    }
                    continue;
                }
                TurnStart::Shown => {}
            }

            // The turn's steps (P-05 §3): until a step ends the turn, the
            // turn's allowance is spent, or something stops the session.
            let ended = loop {
                self.ui_drain(w);
                if let Some(u) = self.user.as_mut() {
                    u.used += 1;
                }
                match self.step(w) {
                    Ok(Flow::Continue) => {}
                    Ok(Flow::EndTurn(end)) => break end,
                    Ok(Flow::Stop(cause, d)) => {
                        // A session step never asks to stop the RUN (P-05
                        // §3); fail closed if one ever does.
                        return End {
                            cause,
                            step: self.step,
                            deliverable: d.or(deliverable),
                        };
                    }
                    Err(cause) => return self.session_end(cause),
                }
                if w.is_poisoned() {
                    return self.poisoned();
                }
                if let Some(u) = self.user.as_ref() {
                    if u.used >= u.allowance {
                        break TurnEnd::TurnSteps;
                    }
                }
            };

            // The turn-end notice (P-05 §3): joined into the last step's
            // turn, which the next request shows first; never into one
            // already rendered.
            if let Some(text) = ended.notice() {
                let step = self.step;
                if let Some(t) = self.turns.last_mut().filter(|t| t.step == step) {
                    t.notice = Some(match t.notice.take() {
                        Some(prev) => prev.joined(&text),
                        None => text,
                    });
                }
            }
            let used = match self.user.as_ref() {
                Some(u) => u.used,
                None => 0,
            };
            if let Err(e) = self.append_turn_ended(w, ended.name(), used) {
                return self.session_end(e);
            }
            self.ui_drain(w);
            if w.is_poisoned() {
                return self.poisoned();
            }
        }
    }

    /// Measure the workspace, then open the turn (P-05 §2.3, §5, §9). The
    /// measurement happens BEFORE anything is journaled for the message,
    /// so the record's facts are the turn's starting facts (INV-39). A
    /// research session (P-39i) has no workspace: the turn starts on the
    /// no-workspace facts and the re-measure (P-05 D4) is skipped, so
    /// `external_change` is always false.
    fn begin_user_turn<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
        text: &str,
        remaining: u32,
    ) -> Result<TurnStart, StopCause> {
        // 1. The workspace now (P-05 §5): a live run measures; a failure
        // stops the session with nothing journaled for this message.
        // (An audit re-feeds the recorded measurement, P-17.)
        let (measured, listing) = match self.user.as_ref().and_then(|u| u.root.clone()) {
            Some(root) => {
                let deadline = Instant::now() + self.config.facts_timeout;
                let listing =
                    workspace_tree(&root, deadline).map_err(|_| StopCause::PolicyAbort)?;
                (listing.facts(), Some(listing))
            }
            None if self.research => (no_workspace_facts(), None),
            None => return Err(StopCause::PolicyAbort),
        };
        let wall_used_ms = u64::try_from(self.meter.elapsed().as_millis()).unwrap_or(u64::MAX);
        let started = self.open_user_turn(w, text, measured, wall_used_ms, remaining)?;
        // The loop's state moves to the measured listing (P-05 §5); a
        // replayed turn has no listing of its own (the replay never
        // touches the workspace), and a research turn has none to move to.
        self.workspace = listing;
        Ok(started)
    }

    /// Open a turn from facts already in hand — measured live
    /// ([`Self::begin_user_turn`]) or re-fed from the journal (a replay,
    /// P-17 §6): decide whether the message is shown, journal the
    /// `UserTurn` record and set the turn up.
    fn open_user_turn<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
        text: &str,
        measured: WorkspaceFacts,
        wall_used_ms: u64,
        remaining: u32,
    ) -> Result<TurnStart, StopCause> {
        let (turn_no, limits, before) = match &self.user {
            Some(u) => (u.turn, u.limits, u.users.len()),
            None => return Err(StopCause::PolicyAbort),
        };
        let old_tree = self.tree;
        let external_change = measured.tree != old_tree;

        // 2. Is the message shown? A text holding any nonce drawn so far
        // in the session is withheld (the model could be told its own
        // delimiters); one that does not fit the users' share of the
        // context is over share (P-05 §2.3). A refused message is never
        // added to the users.
        let withheld = self.nonces.drawn().any(|n| contains_nonce(text, n));
        let candidate = UserEntry {
            before,
            turn: turn_no,
            text: Untrusted::new(text.to_owned(), Source::User),
            external: None,
        };
        let (shown, entry) = if withheld {
            ("withheld", None)
        } else if !user_fits(self.profile, &candidate) {
            ("over_share", None)
        } else {
            ("yes", Some(candidate))
        };

        // 3. Journal the turn: its input, its allowance and the facts it
        // starts from (P-05 §1.1). The clock fact is re-fed by an audit,
        // never recomputed.
        let allowance = u64::from(limits.steps).min(u64::from(remaining));
        let blob = w
            .untrusted(&Untrusted::new(text.to_owned(), Source::User))
            .map_err(journal)?;
        let ev = Event::new(EventKind::UserTurn)
            .field("external_change", Trusted::Bool(external_change))
            .field("shown", Trusted::Text(shown))
            .field("text", Trusted::Untrusted(blob))
            .field("turn", Trusted::U64(turn_no))
            .field("turn_steps", Trusted::U64(allowance))
            .field("wall_used_ms", Trusted::U64(wall_used_ms))
            .field("workspace_files", Trusted::U64(measured.files))
            .field("workspace_oversize", Trusted::U64(measured.oversize))
            .field("workspace_tree", Trusted::Digest(measured.tree));
        w.append(self.step, ev).map_err(journal)?;

        // 4. The loop's state moves to the recorded facts (P-05 §5).
        self.tree = measured.tree;
        // P-26: the measured tree is a checkpoint a `/rewind` can go back
        // to.
        self.restore.push_tree(self.step, measured.tree);
        let u = self.user.as_mut().ok_or(StopCause::PolicyAbort)?;
        u.turn += 1;
        u.allowance = allowance;
        u.used = 0;
        match entry {
            Some(mut e) => {
                // An external change is said with the message it was first
                // seen with (P-05 §5); the context renders it as a notice.
                if external_change {
                    e.external = Some((old_tree, measured.tree));
                }
                u.users.push(e);
                // §9: every accepted turn starts its own detector, its own
                // read-repeat memory and its own format-error streak, and
                // the pre-submit bound counts this turn's submissions only.
                self.detector = LoopDetector::new();
                self.reads_seen.clear();
                self.meter.record_format_ok();
                if let Some(p) = self.presubmit.as_mut() {
                    p.begin_turn();
                }
                Ok(TurnStart::Shown)
            }
            None => Ok(TurnStart::Refused),
        }
    }

    /// The `TurnEnded` record (P-05 §1.1): the turn's number, its reason
    /// and the steps it took.
    fn append_turn_ended<F: JournalFile, B: BlobSink, K: Clock>(
        &self,
        w: &mut JournalWriter<F, B, K>,
        reason: &'static str,
        steps: u64,
    ) -> Result<(), StopCause> {
        let ev = Event::new(EventKind::TurnEnded)
            .field("reason", Trusted::Text(reason))
            .field("steps", Trusted::U64(steps))
            .field("turn", Trusted::U64(self.turns_journaled()));
        w.append(self.step, ev).map_err(journal)?;
        Ok(())
    }

    /// How many `UserTurn` records the journal holds.
    fn turns_journaled(&self) -> u64 {
        self.user.as_ref().map_or(0, |u| u.turn.saturating_sub(1))
    }

    /// The digest of the last accepted submission's note, when there was
    /// one (P-05 §1.1): the session's deliverable.
    fn deliverable(&self) -> Option<Digest> {
        self.user.as_ref().and_then(|u| u.deliverable)
    }

    /// An `End` for a stop: the cause, and whatever the session delivered.
    fn session_end(&self, cause: StopCause) -> End {
        End {
            cause,
            step: self.step,
            deliverable: self.deliverable(),
        }
    }

    /// An `End` for a writer poisoned outside an append's error path.
    fn poisoned(&self) -> End {
        self.session_end(StopCause::JournalUnavailable {
            op: "append".into(),
            error: "the journal writer is poisoned".into(),
        })
    }
}
