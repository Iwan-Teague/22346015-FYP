//! The run driver and loop (see the crate docs for the order of events).
//!
//! **The one real `Meter`.** This file is the only place outside the meter's
//! own tests where a `Meter` is built (the purity gate enforces it), and
//! [`run`] builds it with the real monotonic clock
//! (`harness_journal::SystemClock`), so no caller can hand the loop a clock
//! that stands still.
//!
//! **Trusted fields.** Every journal field written here is a number, a
//! digest, a boolean, compile-time text, or an `Ident` from a resolved
//! `Capability` or a `RunId`/`Nonce`. The model's reply, its arguments, its
//! reasoning, the submit note and every tool output go only into
//! `UntrustedBlob`s. What is fed back to the model is static harness text or
//! an untrusted observation; no model- or tool-chosen text is ever rendered
//! as harness text.
//!
//! **Randomness.** Run ids and render nonces take their random bits from
//! std's `RandomState` (SipHash keyed from OS randomness) over a counter,
//! the time and the process id, XORed on Unix with bytes from
//! `/dev/urandom`. Without the device (Windows) that is not a CSPRNG; what
//! these values need is uniqueness, and that nothing can predict a new
//! observation's nonce before it is drawn, which it cannot without the key.
//! A CSPRNG crate would be a new dependency for no gain here.
//!
//! **Observation nonces (design row H1i).** How a turn is shown is decided
//! once, when the turn is first rendered (the step after it), and reused
//! every time it is shown again, so the history's bytes do not change
//! between requests and a server's prompt cache keeps them. Its
//! observation's nonce is drawn then and journaled in that step's
//! `ModelRequested` (`nonce`, `nonce_step`). The draw refuses a nonce that
//! another observation carries or any untrusted text of the run contains
//! (observation bodies, shown replies); a new body or shown reply that
//! contains a nonce drawn earlier in the run (the model has seen every one
//! of them) is withheld (`withheld_output_step`, `withheld_reply_step`),
//! shown as a harness notice, never as data or as the model's words.

pub(crate) mod approvals;
pub(crate) mod header;
pub(crate) mod plan;
pub(crate) mod step;
pub(crate) mod stop;
pub(crate) mod tools;

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::approve::Approver;
use crate::postedit::{PostEditRefused, PostEditReport, PostEditSpec, PostEditState};
use crate::presubmit::{PresubmitRefused, PresubmitReport, PresubmitSpec, PresubmitState};
use gate_outcome::{Digest, GateOutcome, IndeterminateKind};
use harness_core::environment::EnvProbe;
use harness_core::{LoopDetector, Meter, MeterLimits, MonoClock, Nonce, Pricing, RunId, StopCause};
use harness_journal::writer::SystemClock;
use harness_journal::{JournalError, JournalWriter, StartError};
use harness_manifest::admission::Registry;
use harness_model::profile::Profile;
use harness_model::{ModelBackend, TaskText};
use harness_policy::locality::{self, LocalityProbe, LocalityRefused};
use harness_policy::{SessionKind, SessionRefused, UserPolicy};
use harness_sandbox::{Confinement, Refused};
use harness_tools::builtin::RootRefused;
use harness_tools::{ExecSetupError, ExecSpec};

pub(crate) use approvals::Approvals;
pub use header::WorkspaceModeRecord;
pub(crate) use header::{
    builtin_manifest_sha256, header, limits_fields, protected_task_digest, terse_table_sha256,
    web_grant_digest, ChildHeader, ExecHeader, HeaderInputs, ParentLink, PortsHeader,
    SandboxRecord, HEADER_INPUT_KEYS,
};
pub(crate) use plan::{
    attempt_check, create_run, loop_facts, no_workspace_facts, plan, prepare, todo_for, Prepared,
};
pub(crate) use step::{BudgetNotices, Loop, LoopInit, NonceSource};
pub(crate) use stop::commit;
pub(crate) use tools::{exec_tools, is_edit, is_exec, parse_exec, RecordedEdit, RecordedResult};

// ---------------------------------------------------------------------------
// Inputs and outputs.
// ---------------------------------------------------------------------------

/// What the task spec says about this run (§2.1). H1 tasks have no checks.
#[derive(Debug, Clone)]
pub struct TaskSpec {
    /// The task text (trusted intent).
    pub task: TaskText,
    /// Capability grants. The submit sentinel is always granted in
    /// addition: it is the harness's own way to end a run (§2.5).
    pub grants: Vec<String>,
    /// The task declared the workspace public (§5.4).
    pub workspace_public: bool,
    /// Ports the task may bind on loopback (P-36g §6.1): at most
    /// [`PORTS_PER_TASK`], each [`harness_sandbox::PORT_MIN`] or above, no
    /// duplicates, never a reserved (model) port. Empty: no port grant.
    pub ports: Vec<u16>,
    /// Of those ports, the ones reachable from the LAN (P-36g §6.3): a
    /// subset of [`TaskSpec::ports`]. Each such port's `harness.exec.start`
    /// is a `protected_action` ask, every time.
    pub lan_ports: Vec<u16>,
    /// The command runner's setup (§4.8, H2d): the exec allowlist and what
    /// a command needs besides the workspace. Present exactly when the
    /// grants include `harness.exec.run`.
    pub exec: Option<ExecSpec>,
    /// Commands the harness runs when the model submits (H3a): a failing
    /// one turns the submission back, up to a bound. Needs the exec grant
    /// and section; `None`: a submit is accepted at once, exactly as before.
    pub presubmit: Option<PresubmitSpec>,
    /// Checks the harness runs after every successful edit (P-27): a
    /// failing one rolls the edit back from its pre-image (or keeps it,
    /// when the check says so). Needs the exec grant and section; `None`:
    /// an edit stands as it lands, exactly as before.
    pub post_edit: Option<PostEditSpec>,
    /// Task-declared protected-path globs (P-29), on top of the build's
    /// defaults: edits under them are refused, exec sees them read-only.
    pub protected: Vec<String>,
    /// The session's kind (P-39i): [`SessionKind::Coding`] (the default,
    /// unchanged) or [`SessionKind::Research`] — a workspace-less session
    /// driven by [`crate::run_research`].
    pub kind: SessionKind,
}

/// Budgets and timeouts (§2.4).
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// The meter's limits.
    pub limits: MeterLimits,
    /// Longest a single model call may take (also capped by the remaining
    /// wall budget).
    pub model_call_timeout: Duration,
    /// Longest a single tool call may take (§2.4: 30 s for non-exec tools;
    /// also capped by the remaining wall budget).
    pub tool_call_timeout: Duration,
    /// Longest one command of `harness.exec.run` may take (H2d: 120 s;
    /// also capped by the remaining wall budget). It is the command's wall
    /// clock in the sandbox.
    pub exec_call_timeout: Duration,
    /// Longest the pre-start workspace-facts walk may take.
    pub facts_timeout: Duration,
    /// Longest an approver may take to answer (§2.4: 15 min; past it the
    /// request is a deny, §5.3). Not charged to the wall budget.
    pub approval_timeout: Duration,
    /// Whether an approver may grant a session-scoped rule at the prompt
    /// (P-23): answering `a`/`d` allows or denies one call's minimal
    /// pattern (exec argv prefix, the edited file, the read directory) for
    /// the rest of the session. Default false (Q-4): an explicit opt-in,
    /// and a `protected_action` ask is never lowered either way.
    pub allow_session_grants: bool,
    /// The workspace-mode record (P-52): set when the CLI, as trust base,
    /// copied the workspace to a scratch directory before the run; `None`
    /// in-place (the default, unchanged). Recorded in the journal header,
    /// never compared by an audit (see [`WorkspaceModeRecord`]).
    pub workspace_mode: Option<WorkspaceModeRecord>,
    /// The model's own ports (P-36g §6.1): what a port grant may never
    /// include. The CLI derives the endpoint's port; a library caller
    /// passes its own. A port grant with a loopback endpoint and no
    /// reserved ports is refused ([`RunRefused::ModelPortUnknown`]).
    pub reserved_ports: Vec<u16>,
    /// Whether background processes survive the run (P-36 spec §3.5,
    /// `--bg-persist`). Parsed and recorded; the persist path lands with
    /// the background tooling itself (P-36i).
    pub bg_persist: bool,
}

impl RunConfig {
    /// The §2.4 defaults, with the profile-derived token limit given.
    pub fn defaults(tokens: u64) -> Self {
        Self {
            limits: MeterLimits {
                steps: 50,
                tokens,
                wall: Duration::from_secs(30 * 60),
                cost_micros: 0,
                format_errors: 3,
                repair_rounds: 1,
            },
            model_call_timeout: Duration::from_secs(300),
            tool_call_timeout: Duration::from_secs(30),
            exec_call_timeout: Duration::from_secs(120),
            facts_timeout: Duration::from_secs(120),
            approval_timeout: Duration::from_secs(15 * 60),
            allow_session_grants: false,
            workspace_mode: None,
            reserved_ports: Vec::new(),
            bg_persist: false,
        }
    }
}

/// The most ports one task may hold (P-36 spec §6.1): a bound the loader
/// checks before anything runs. The tools layer carries the same bound for
/// its own parsing (P-36i).
pub const PORTS_PER_TASK: usize = 8;

/// Everything [`run`] needs.
pub struct Run<'a> {
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
    /// The filesystem-locality probe (the binary passes
    /// `harness_sandbox::locality::SystemProbe`; `NoProbe` refuses every
    /// state root).
    pub probe: &'a dyn LocalityProbe,
    /// The environment probe (§7.1; the binary passes
    /// `harness_sandbox::environment::SystemEnv`).
    pub env: &'a dyn EnvProbe,
    /// Budgets and timeouts.
    pub config: &'a RunConfig,
    /// Who answers an `Ask` (§5.3): the CLI's terminal prompt, an
    /// embedding UI, or nobody. With `None`, policy turns every ask into a
    /// deny (§5.2); the choice is recorded in the journal header
    /// (`approver_present`), and a resume must make the same one.
    pub approver: Option<&'a dyn Approver>,
    /// Where commands are confined (H2d; the binary passes
    /// `harness_sandbox::SystemConfinement`). Asked for a witness only when
    /// the task grants `harness.exec.run`; `None`, or a refusal, refuses such
    /// a run before anything starts (INV-6: no unconfined fallback).
    pub confinement: Option<&'a dyn Confinement>,
}

/// A run that did not start: nothing ran, nothing was journaled
/// (`Indeterminate { CouldNotRun }`).
#[derive(Debug, thiserror::Error)]
pub enum RunRefused {
    /// Policy refused the session (§2.1 "plan session").
    #[error("session refused: {0}")]
    Session(#[from] SessionRefused),
    /// More tools than the profile allows (§2.3 block 2).
    #[error("{active} tools granted; the profile allows {max}")]
    TooManyTools {
        /// Granted tools, the sentinel included.
        active: usize,
        /// The profile's cap.
        max: u32,
    },
    /// The workspace root is not a usable real directory.
    #[error("workspace refused: {0}")]
    Workspace(#[from] RootRefused),
    /// The workspace facts could not be measured.
    #[error("workspace facts could not be measured: {0}")]
    Facts(io::Error),
    /// `state_root` could not be canonicalised or is not valid UTF-8.
    #[error("state_root unusable: {0}")]
    StateRoot(io::Error),
    /// `state_root` is inside the workspace, or the workspace inside it
    /// (§2.8).
    #[error("state_root and the workspace overlap")]
    Overlap,
    /// Filesystem-locality check (§2.8, INV-35).
    #[error("{0}")]
    Locality(#[from] LocalityRefused),
    /// `runs/<run-id>` could not be created.
    #[error("run directory not created: {0}")]
    RunDir(io::Error),
    /// The journal header is not durable (§2.5).
    #[error("{0}")]
    Start(#[from] StartError),
    /// A resume that cannot continue this run (§2.10). A session's stop
    /// names the recorded cause (P-17), so the message may be owned.
    #[error("cannot resume: {0}")]
    NotResumable(std::borrow::Cow<'static, str>),
    /// The task's exec grant and exec section disagree, or no confinement
    /// was given for an exec grant (H2d).
    #[error("exec refused: {0}")]
    ExecGrant(&'static str),
    /// The command runner's setup is refused (§4.8, H2d).
    #[error("{0}")]
    Exec(#[from] ExecSetupError),
    /// The task grants execution and this host has no conformed sandbox
    /// (INV-6, §6.1): refused, never run unconfined.
    #[error("{0}")]
    Confinement(Refused),
    /// The task's pre-submit checks are refused (H3a).
    #[error("presubmit refused: {0}")]
    Presubmit(#[from] PresubmitRefused),
    /// The task's post-edit checks are refused (P-27).
    #[error("post_edit refused: {0}")]
    PostEdit(#[from] PostEditRefused),
    /// A protected-path glob or ask rule this build must write is refused
    /// (P-29): a task glob the glob compiler rejects, or a floor rule the
    /// user policy already states. The run does not start half-protected.
    #[error("protected paths refused: {0}")]
    Protected(&'static str),
    /// The session's turn limits are out of range (P-05 §4); nothing ran.
    #[error("turn limits refused: {0}")]
    TurnLimits(&'static str),
    /// A port grant with a loopback endpoint and no reserved ports (P-36g
    /// §6.1): the harness cannot tell a granted port from the model
    /// server's own port, so it refuses rather than guess. The CLI always
    /// knows (it derives the port from the endpoint); a library caller
    /// passes `RunConfig::reserved_ports`.
    #[error("ports are granted but no reserved (model) ports are known: a loopback endpoint's port is never a granted port, and none was given")]
    ModelPortUnknown,
    /// A research session's spec is refused (P-39i, fail closed): web
    /// capabilities this build does not wire, an exec section, pre-submit
    /// commands, protected paths, a workspace, no confinement, a witness
    /// short of the web airlock, or the wrong registry. Nothing ran.
    #[error("research session refused: {0}")]
    Research(&'static str),
    /// A delegating task (`harness.task.delegate`, P-38) cannot be served
    /// by this run: no `harness.fs.*` grant to answer a child's question
    /// with, or a profile whose context budget is under the child floor
    /// ([`crate::delegate::CHILD_MIN_BUDGET_TOKENS`]). Nothing ran.
    #[error("delegate refused: {0}")]
    Delegate(&'static str),
    /// A hosted profile's run is refused (P-31, fail closed): no price
    /// table (§2.4: a hosted run without one refuses to start), or a grant
    /// at personal sensitivity or above (Q-2: no personal data to a hosted
    /// upstream). Nothing ran.
    #[error("hosted profile refused: {0}")]
    Hosted(&'static str),
}

impl RunRefused {
    /// Nothing ran: `Indeterminate { CouldNotRun }`, or `UnsupportedOs`
    /// when execution was refused because no backend exists for this OS
    /// (§6.1).
    pub fn outcome(&self) -> GateOutcome {
        let why = match self {
            RunRefused::Confinement(Refused(u))
                if u.kind() == harness_sandbox::UnavailableKind::UnsupportedOs =>
            {
                IndeterminateKind::UnsupportedOs
            }
            _ => IndeterminateKind::CouldNotRun,
        };
        GateOutcome::Indeterminate { why }
    }
}

/// How a run that started ended.
#[derive(Debug)]
pub struct RunReport {
    /// The run id.
    pub run: RunId,
    /// The attempt number.
    pub attempt: u32,
    /// `state_root/runs/<run-id>`.
    pub run_dir: PathBuf,
    /// Why the loop stopped.
    pub cause: StopCause,
    /// The released outcome (after `RunStopped` is durable, or downgraded).
    pub outcome: GateOutcome,
    /// The final chain head, if `RunStopped` is durable.
    pub chain_head: Option<Digest>,
    /// Loop steps taken.
    pub steps: u64,
    /// The journal failure, when there was one.
    pub journal_error: Option<JournalError>,
    /// Steps whose tool timed out, crashed or could not run (a provider
    /// failure) while the host was under pressure (§7.1: memory available
    /// under 5% or load above twice the CPUs), for the report's
    /// `possibly-environmental` Info finding.
    pub possibly_environmental: Vec<u64>,
    /// What the task's pre-submit checks did (H3a); `None` for a task
    /// without any.
    pub presubmit: Option<PresubmitReport>,
    /// What the task's post-edit checks did (P-27); `None` for a task
    /// without any.
    pub post_edit: Option<PostEditReport>,
}

// ---------------------------------------------------------------------------
// run()
// ---------------------------------------------------------------------------

/// Run a task (see the crate docs). `Err` means the run did not start.
pub fn run(r: Run<'_>) -> Result<RunReport, RunRefused> {
    // ---- Before anything is written. ----
    // A research session (P-39i) is not a batch run: it is driven by
    // `run_research`, whose loop carries the conversation.
    if let SessionKind::Research(_) = r.spec.kind {
        return Err(RunRefused::Research(
            "a research session is not a batch run; drive it with run_research",
        ));
    }
    let pre = prepare(
        r.spec,
        r.registry,
        r.policy,
        r.profile,
        Some(r.workspace),
        r.state_root,
        r.probe,
        r.config,
        r.approver.is_some(),
        r.confinement,
        r.backend.identity().endpoint,
    )?;
    let facts = pre.facts;

    // ---- runs/<run-id>, the first attempt, the durable header. ----
    let (run_id, run_dir) = create_run(&pre.state_root)?;
    if let Some(s) = run_dir.to_str() {
        locality::check(r.probe, s)?;
    }
    // The command runner, with the run's scratch directory (H2d).
    let exec_header = pre
        .exec
        .as_ref()
        .map(|(p, w)| ExecHeader::live(p, w, r.config));
    let exec_tools = exec_tools(&pre, &run_dir, r.confinement, r.config)?;
    let ports_header = PortsHeader::of(r.spec, r.config, pre.ports.as_ref());
    let header = header(&HeaderInputs {
        spec: r.spec,
        registry: r.registry,
        policy: r.policy,
        profile: r.profile,
        identity: &r.backend.identity(),
        facts,
        limits: &r.config.limits,
        resumed_from: None,
        environment: r.env.sample(),
        environment_recorded: false,
        approver_present: r.approver.is_some(),
        session: None,
        exec: exec_header,
        ports: ports_header,
        instructions: None,
        workspace_mode: r.config.workspace_mode.as_ref(),
        parent: None,
        child: None,
    })?;
    let (mut w, attempt) = JournalWriter::create_next_attempt_checked(
        &run_dir,
        run_id.clone(),
        header,
        &attempt_check(r.probe),
    )?;

    // ---- The loop. ----
    let meter = new_meter(
        r.config.limits.clone(),
        r.profile.pricing(),
        Box::new(SystemClock::default()),
    );
    let edit_tools = pre.edit_tools.clone();
    let mut lp = Loop::new(LoopInit {
        session: pre.session,
        registry: r.registry,
        tools: pre.tools,
        task: &r.spec.task,
        facts: loop_facts(&facts, r.spec),
        profile: r.profile,
        backend: r.backend,
        providers: Prepared::providers(pre.read_tools, pre.edit_tools, pre.patch_tools, exec_tools),
        meter,
        detector: LoopDetector::new(),
        turns: Vec::new(),
        config: r.config,
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
            r.approver,
            std::collections::VecDeque::new(),
        )
        .may_grant(r.config.allow_session_grants)
        .with_edits(edit_tools),
        env: r.env,
        pressure: Vec::new(),
        reads_seen: Default::default(),
        todo: todo_for(&r.spec.grants),
        notices: BudgetNotices::live(r.config.limits.wall),
        presubmit: PresubmitState::of(&r.spec.presubmit),
        post_edit: PostEditState::of(&r.spec.post_edit),
        workspace_root: Some(r.workspace.to_path_buf()),
        restore: Default::default(),
        instructions: None,
        user: None,
    });
    let end = lp.drive(&mut w);
    let released = commit(w, &end, None);
    Ok(RunReport {
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
        post_edit: lp.post_edit.as_ref().map(PostEditState::report),
    })
}

/// The files read this run, with the SHA-256 of each file's whole content
/// at its latest read (design §2.3 "Stale reads"). Defined by the edit
/// engine's crate and re-exported here (the run loop and the edit engine
/// must agree on one type); the edits themselves call [`ReadLog::check`],
/// which refuses an edit to a file that changed since it was read, or was
/// never read.
pub use harness_tools::{ReadLog, StaleRead};

/// The meter, built here and only here in production code, always with a
/// clock the caller does not control in [`run`] (the real one). The
/// profile's price table (P-31) rides along: it is what makes the `Cost`
/// dimension count, and it is `None` for a local model, which costs
/// nothing (§2.4).
pub(crate) fn new_meter(
    limits: MeterLimits,
    pricing: Option<Pricing>,
    clock: Box<dyn MonoClock>,
) -> Meter {
    Meter::new(limits, pricing, clock)
}

/// The meter of a resumed attempt: the wall time the interrupted attempt
/// already spent (its journal's last monotonic time) is charged from the
/// start (§2.10). The price table rides along exactly as in [`new_meter`].
pub(crate) fn new_meter_resumed(
    limits: MeterLimits,
    pricing: Option<Pricing>,
    clock: Box<dyn MonoClock>,
    already_elapsed: Duration,
) -> Meter {
    Meter::new_resumed(limits, pricing, clock, already_elapsed)
}

// ---------------------------------------------------------------------------
// Identity and randomness.
// ---------------------------------------------------------------------------

pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut filled = 0;
    let mut n: u64 = 0;
    while filled < N {
        n += 1;
        // Each RandomState has fresh keys (std increments the per-thread
        // random key on every `new`), so repeated calls differ.
        let mut h = RandomState::new().build_hasher();
        h.write_u64(n);
        h.write_u128(nanos);
        h.write_u32(std::process::id());
        for b in h.finish().to_le_bytes() {
            if let Some(slot) = out.get_mut(filled) {
                *slot = b;
                filled += 1;
            }
        }
    }
    // Where the OS offers a CSPRNG device, mix it in (H1e-2a review,
    // recommendation 8): XOR with independent bytes is never weaker than
    // either source. Without it (Windows, or the device unreadable) the
    // keyed-hash bytes above stand alone.
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut dev = [0u8; N];
        if std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut dev))
            .is_ok()
        {
            for (o, d) in out.iter_mut().zip(dev) {
                *o ^= d;
            }
        }
    }
    out
}

/// A new run id: 48-bit Unix milliseconds, then 80 random bits (§2.8).
pub(crate) fn new_run_id() -> RunId {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    RunId::new(ms, random_bytes::<10>())
}

/// A new render nonce: 128 random bits as 32 lowercase hex characters.
pub(crate) fn new_nonce() -> Option<Nonce> {
    let hex: String = random_bytes::<16>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Nonce::new(&hex)
}
