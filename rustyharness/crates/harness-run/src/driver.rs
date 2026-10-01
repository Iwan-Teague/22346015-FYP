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
//! these values need is uniqueness, and that the model cannot predict the
//! next turn's nonce, which it cannot without the key. A CSPRNG crate would
//! be a new dependency for no gain here.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use gate_outcome::{Digest, GateOutcome, IndeterminateKind};
use harness_core::environment::{EnvProbe, EnvSample};
use harness_core::{
    sha256, BudgetDim, LoopDetector, LoopEvent, LoopKind, LoopSignal, Meter, MeterLimits,
    MonoClock, Nonce, RunId, Source, StopCause, TokenUsage, Untrusted,
};
use harness_journal::writer::SystemClock;
use harness_journal::{
    layout, BlobSink, Clock, Event, EventKind, Header, Ident, JournalError, JournalFile,
    JournalWriter, StartError, Trusted,
};
use harness_journal::{Condition, ConditionKind};
use harness_manifest::admission::{Registry, Resolved};
use harness_manifest::{builtin, Capability, Confirmation};
use harness_model::context::{
    self, ContextError, Fact, FactValue, Feedback, ShownCall, Turn, CONTEXT_FORMAT,
};
use harness_model::profile::{Profile, Protocol};
use harness_model::protocol::{self, parse_reply, FormatError};
use harness_model::replay::{replied_event, requested_event};
use harness_model::wire::{render_request, RenderError};
use harness_model::{
    Completion, HarnessText, ModelBackend, ModelError, ModelRequest, TaskText, ToolSpec,
};
use harness_policy::approval::{
    ApprovalAuthority, ApprovalRequest, ApprovalScope, BoundCall, MintRequest, PrincipalId, StepId,
};
use harness_policy::locality::{self, LocalityProbe, LocalityRefused};
use harness_policy::{
    Authorized, Call, DenyReason, PolicyDecision, RuleId, RuleList, Session, SessionRefused,
    SessionSpec, UserPolicy, WorkspaceDecl, SUBMIT_ID,
};
use harness_tools::builtin::{workspace_tree, RootRefused, WorkspaceFacts, WorkspaceTree};
use harness_tools::{EditTools, InvokeCtx, ReadTools, ToolProvider, ToolStatus};
use serde_json::Value;

use crate::approve::{nonce_name, ApprovalAnswer, Approver, RecordedApproval};
use crate::sample;

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
    /// Longest the pre-start workspace-facts walk may take.
    pub facts_timeout: Duration,
    /// Longest an approver may take to answer (§2.4: 15 min; past it the
    /// request is a deny, §5.3). Not charged to the wall budget.
    pub approval_timeout: Duration,
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
            facts_timeout: Duration::from_secs(120),
            approval_timeout: Duration::from_secs(15 * 60),
        }
    }
}

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
    /// A resume that cannot continue this run (§2.10).
    #[error("cannot resume: {0}")]
    NotResumable(&'static str),
}

impl RunRefused {
    /// Nothing ran: `Indeterminate { CouldNotRun }`.
    pub fn outcome(&self) -> GateOutcome {
        GateOutcome::Indeterminate {
            why: IndeterminateKind::CouldNotRun,
        }
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
}

// ---------------------------------------------------------------------------
// run()
// ---------------------------------------------------------------------------

/// Run a task (see the crate docs). `Err` means the run did not start.
pub fn run(r: Run<'_>) -> Result<RunReport, RunRefused> {
    // ---- Before anything is written. ----
    let pre = prepare(
        r.spec,
        r.registry,
        r.policy,
        r.profile,
        r.workspace,
        r.state_root,
        r.probe,
        r.config,
        r.approver.is_some(),
    )?;
    let facts = pre.facts;

    // ---- runs/<run-id>, the first attempt, the durable header. ----
    let (run_id, run_dir) = create_run(&pre.state_root)?;
    if let Some(s) = run_dir.to_str() {
        locality::check(r.probe, s)?;
    }
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
    })?;
    let (mut w, attempt) = JournalWriter::create_next_attempt_checked(
        &run_dir,
        run_id.clone(),
        header,
        &attempt_check(r.probe),
    )?;

    // ---- The loop. ----
    let meter = new_meter(r.config.limits.clone(), Box::new(SystemClock::default()));
    let mut lp = Loop {
        session: pre.session,
        registry: r.registry,
        tools: pre.tools,
        task: &r.spec.task,
        facts: facts_block(&facts),
        profile: r.profile,
        backend: r.backend,
        providers: Prepared::providers(pre.read_tools, pre.edit_tools),
        meter,
        detector: LoopDetector::new(),
        turns: Vec::new(),
        config: r.config,
        step: 0,
        nonces: NonceSource::default(),
        feed: std::collections::VecDeque::new(),
        reads: ReadLog::default(),
        tree: facts.tree,
        workspace: Some(pre.tree),
        approvals: Approvals::new(
            &run_id,
            attempt,
            r.approver,
            std::collections::VecDeque::new(),
        ),
        env: r.env,
        pressure: Vec::new(),
        reads_seen: Default::default(),
    };
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
    })
}

/// What `prepare` established before anything was written.
pub(crate) struct Prepared {
    pub(crate) session: Session,
    pub(crate) tools: Vec<ToolSpec>,
    pub(crate) read_tools: ReadTools,
    pub(crate) edit_tools: EditTools,
    pub(crate) state_root: PathBuf,
    pub(crate) facts: WorkspaceFacts,
    /// The listing the facts were measured over, kept so the tree digest
    /// follows the run's own edits (H2b).
    pub(crate) tree: WorkspaceTree,
}

impl Prepared {
    /// The built-in providers: the read tools and the edit tools, which
    /// share the `harness` namespace and split it by verb (H2b).
    pub(crate) fn providers<'p>(
        read: ReadTools,
        edit: EditTools,
    ) -> Vec<Box<dyn ToolProvider + 'p>> {
        vec![Box::new(read), Box::new(edit)]
    }
}

/// The pre-start checks shared by `run` and `resume` (§2.1): plan the
/// session, open the workspace, canonicalise `state_root`, refuse an
/// overlap, check locality, measure the workspace facts.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare(
    spec: &TaskSpec,
    registry: &Registry,
    policy: &UserPolicy,
    profile: &Profile,
    workspace: &Path,
    state_root: &Path,
    probe: &dyn LocalityProbe,
    config: &RunConfig,
    approver_present: bool,
) -> Result<Prepared, RunRefused> {
    let (session, tools) = plan(spec, registry, policy, profile, approver_present)?;
    let read_tools = ReadTools::new(workspace)?;
    let edit_tools = EditTools::new(workspace)?;
    let ws = read_tools.root().to_path_buf();
    let state_root = std::fs::canonicalize(state_root).map_err(RunRefused::StateRoot)?;
    if state_root.starts_with(&ws) || ws.starts_with(&state_root) {
        return Err(RunRefused::Overlap);
    }
    let state_str = state_root.to_str().ok_or_else(|| {
        RunRefused::StateRoot(io::Error::new(
            io::ErrorKind::InvalidInput,
            "state_root is not valid UTF-8",
        ))
    })?;
    locality::check(probe, state_str)?;
    let tree =
        workspace_tree(&ws, Instant::now() + config.facts_timeout).map_err(RunRefused::Facts)?;
    Ok(Prepared {
        session,
        tools,
        read_tools,
        edit_tools,
        state_root,
        facts: tree.facts(),
        tree,
    })
}

/// The locality check run on each new attempt directory (§2.8).
pub(crate) fn attempt_check(
    probe: &dyn LocalityProbe,
) -> impl Fn(&Path) -> Result<(), String> + '_ {
    move |dir: &Path| {
        let s = dir
            .to_str()
            .ok_or_else(|| "the attempt directory is not valid UTF-8".to_owned())?;
        locality::check(probe, s)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// Context block 4 from the measured facts.
pub(crate) fn facts_block(f: &WorkspaceFacts) -> Vec<Fact> {
    vec![
        Fact {
            name: "workspace tree digest",
            value: FactValue::Digest(f.tree),
            method: "walk of the workspace in name order, symlinks not followed, sha256 of each file up to 64 MiB, size only above",
        },
        Fact {
            name: "workspace file count",
            value: FactValue::Count(f.files),
            method: "the same walk",
        },
        Fact {
            name: "workspace files over 64 MiB (size only)",
            value: FactValue::Count(f.oversize),
            method: "the same walk",
        },
    ]
}

/// The meter, built here and only here in production code, always with a
/// clock the caller does not control in [`run`] (the real one).
pub(crate) fn new_meter(limits: MeterLimits, clock: Box<dyn MonoClock>) -> Meter {
    // No hosted endpoints in this build, so no price table (§2.4: a hosted
    // run without one refuses to start, N-7, with the `hosted` feature).
    Meter::new(limits, None, clock)
}

/// The meter of a resumed attempt: the wall time the interrupted attempt
/// already spent (its journal's last monotonic time) is charged from the
/// start (§2.10).
pub(crate) fn new_meter_resumed(
    limits: MeterLimits,
    clock: Box<dyn MonoClock>,
    already_elapsed: Duration,
) -> Meter {
    Meter::new_resumed(limits, None, clock, already_elapsed)
}

/// Plan the session and the tool definitions (§2.1 "plan session").
/// `approver_present`: whether anyone answers an ask (§5.2: with nobody,
/// every ask is a deny).
pub(crate) fn plan(
    spec: &TaskSpec,
    registry: &Registry,
    policy: &UserPolicy,
    profile: &Profile,
    approver_present: bool,
) -> Result<(Session, Vec<ToolSpec>), RunRefused> {
    let mut grants = spec.grants.clone();
    if !grants.iter().any(|g| g == SUBMIT_ID) {
        grants.push(SUBMIT_ID.to_owned());
    }
    let session = Session::plan(
        &SessionSpec {
            grants: grants.clone(),
            workspace: Some(WorkspaceDecl {
                declared_public: spec.workspace_public,
            }),
            approver_present,
            personal_data_granted: false,
        },
        registry,
        policy,
    )?;
    let mut tools = Vec::with_capacity(grants.len());
    for g in &grants {
        // Planning resolved every grant to exactly one capability.
        if let Resolved::One { capability, .. } = registry.resolve(g) {
            tools.push(ToolSpec::from_capability(capability));
        }
    }
    let max = profile.max_active_tools();
    if u32::try_from(tools.len()).map_or(true, |n| n > max) {
        return Err(RunRefused::TooManyTools {
            active: tools.len(),
            max,
        });
    }
    Ok((session, tools))
}

fn create_run(state_root: &Path) -> Result<(RunId, PathBuf), RunRefused> {
    let mut last = io::Error::other("no attempt");
    for _ in 0..3 {
        let id = new_run_id();
        match layout::create_run_dir(state_root, &id) {
            Ok(dir) => return Ok((id, dir)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = e,
            Err(e) => return Err(RunRefused::RunDir(e)),
        }
    }
    Err(RunRefused::RunDir(last))
}

/// Everything the journal header is built from.
pub(crate) struct HeaderInputs<'a> {
    pub(crate) spec: &'a TaskSpec,
    pub(crate) registry: &'a Registry,
    pub(crate) policy: &'a UserPolicy,
    pub(crate) profile: &'a Profile,
    pub(crate) identity: &'a harness_model::ModelIdentity,
    pub(crate) facts: WorkspaceFacts,
    pub(crate) limits: &'a MeterLimits,
    /// A resumed attempt: the attempt it continues, that journal's chain
    /// head, the wall time carried into this attempt (every earlier
    /// attempt's, in milliseconds), and the later attempts passed over as
    /// holding no evidence (H1 phase-exit review F-5).
    pub(crate) resumed_from: Option<(u32, Digest, u64, Vec<u32>)>,
    /// The environment sample (§7.1): measured for a live attempt, the
    /// recorded one for an audit replay.
    pub(crate) environment: EnvSample,
    /// Whether `environment` was copied from a recording (an audit replay's
    /// header) rather than measured here (H1f-3 review F-9).
    pub(crate) environment_recorded: bool,
    /// Whether an approver answers asks in this run (§5.2, H2b).
    pub(crate) approver_present: bool,
}

/// The header keys an audit replay or a resume recomputes from its own
/// inputs and requires to be equal to the recorded ones. `limits` is one
/// (H1 phase-exit review F-1): the replay recomputes every budget stop
/// from the limits, so limits taken from the journal would let a
/// re-chained edit choose the stop the audit then "recomputes".
/// `builtin_manifest`, `shell_enabled` (H1f-3) and `context_format` (H1h)
/// belong to the harness build: a journal another build wrote is refused
/// by name, never replayed into a mismatch.
pub(crate) const HEADER_INPUT_KEYS: [&str; 11] = [
    "task",
    "grants",
    "workspace_public",
    "protocol",
    "profile",
    "policy",
    "checks",
    "builtin_manifest",
    "shell_enabled",
    "context_format",
    "limits",
];

/// The header's `limits` object, field by field: the one encoding the
/// header writes and an audit or a resume compares.
pub(crate) fn limits_fields(l: &MeterLimits) -> [(&'static str, u64); 6] {
    [
        ("steps", u64::from(l.steps)),
        ("tokens", l.tokens),
        (
            "wall_ms",
            u64::try_from(l.wall.as_millis()).unwrap_or(u64::MAX),
        ),
        ("cost_micros", l.cost_micros),
        ("format_errors", u64::from(l.format_errors)),
        ("repair_rounds", u64::from(l.repair_rounds)),
    ]
}

/// The SHA-256 of the compiled-in manifest (§7.1 header "manifest
/// SHA-256s": in H1 the built-in provider is the only one admission
/// accepts). rustc reads CRLF sources as LF, so it is the same digest on
/// every OS.
pub(crate) fn builtin_manifest_sha256() -> Digest {
    sha256(builtin::BUILTIN_MANIFEST_JSON.as_bytes())
}

pub(crate) fn header(h: &HeaderInputs<'_>) -> Result<Header, RunRefused> {
    let version = Ident::of(env!("CARGO_PKG_VERSION")).ok_or(StartError {
        op: "header",
        error: "the harness version is not an identifier".into(),
    })?;
    let spec = h.spec;
    let grants = spec
        .grants
        .iter()
        // The sentinel once, whether or not the spec granted it (review N-c).
        .chain(
            (!spec.grants.iter().any(|g| g == SUBMIT_ID))
                .then(|| SUBMIT_ID.to_owned())
                .as_ref(),
        )
        .filter_map(|g| match h.registry.resolve(g) {
            Resolved::One { capability, .. } => Ident::from_capability(capability),
            _ => None,
        })
        .map(Trusted::Id)
        .collect();
    let mut hd = Header::new(version)
        .field(
            "endpoint",
            Trusted::Text(match h.identity.endpoint {
                harness_model::EndpointClass::Loopback => "loopback",
                harness_model::EndpointClass::Replay => "replay",
                harness_model::EndpointClass::Scripted => "scripted",
            }),
        )
        .field(
            "protocol",
            Trusted::Text(match h.profile.protocol() {
                Protocol::Text => "text",
                Protocol::Native => "native",
            }),
        )
        .field(
            "task",
            Trusted::Digest(sha256(spec.task.as_str().as_bytes())),
        )
        .field("profile", Trusted::Digest(h.profile.content_sha256()))
        .field(
            "profile_validated",
            Trusted::Bool(h.identity.profile_validated),
        )
        .field("policy", Trusted::Digest(h.policy.digest()))
        // Whether asks can be answered (H2b): it decides every ask, so an
        // audit plans with the recorded value and a resume must match it.
        .field("approver_present", Trusted::Bool(h.approver_present))
        .field("grants", Trusted::List(grants))
        .field("workspace_public", Trusted::Bool(spec.workspace_public))
        .field("workspace_tree", Trusted::Digest(h.facts.tree))
        .field("workspace_files", Trusted::U64(h.facts.files))
        .field("workspace_oversize", Trusted::U64(h.facts.oversize))
        .field(
            "limits",
            Trusted::Obj(
                limits_fields(h.limits)
                    .into_iter()
                    .map(|(k, v)| (k, Trusted::U64(v)))
                    .collect(),
            ),
        )
        .field("checks", Trusted::U64(0))
        .field(
            "builtin_manifest",
            Trusted::Digest(builtin_manifest_sha256()),
        )
        // No execute-class capability exists in H1, so no shell can be on
        // any exec allowlist (§4.8) and there is no sandbox backend (§6).
        .field("shell_enabled", Trusted::Bool(false))
        // What this build's contexts and requests are (H1h): a replay
        // recomputes them, so it needs the same format.
        .field("context_format", Trusted::Text(CONTEXT_FORMAT))
        .field(
            "sandbox",
            Trusted::Obj(vec![("backend", Trusted::Text("none"))]),
        )
        .field("os", Trusted::Text(std::env::consts::OS))
        .field("arch", Trusted::Text(std::env::consts::ARCH))
        .field("environment", sample::to_trusted(&h.environment))
        .field(
            "environment_source",
            Trusted::Text(if h.environment_recorded {
                "recorded"
            } else {
                "measured"
            }),
        );
    if let Some((attempt, head, carried_ms, skipped)) = &h.resumed_from {
        let mut from = vec![
            ("attempt", Trusted::U64(u64::from(*attempt))),
            ("chain_head", Trusted::Digest(*head)),
            // H1e-2b confirming review NF-1: the wall time of EVERY
            // earlier attempt, so a chain of resumes is charged in full.
            ("wall_carried_ms", Trusted::U64(*carried_ms)),
        ];
        // Named, not silently passed over (H1 phase-exit review F-5).
        if !skipped.is_empty() {
            from.push((
                "skipped_attempts",
                Trusted::List(
                    skipped
                        .iter()
                        .map(|n| Trusted::U64(u64::from(*n)))
                        .collect(),
                ),
            ));
        }
        hd = hd.field("resumed_from", Trusted::Obj(from));
    }
    // §3.5: what the server claims, as untrusted payloads, labelled.
    let c = &h.identity.claimed;
    for (key, v) in [
        ("claimed_model_id", &c.model_id),
        ("claimed_server", &c.server),
        ("claimed_template_sha256", &c.template_sha256),
    ] {
        if let Some(v) = v {
            hd = hd.claimed(key, Untrusted::new(v.clone(), Source::Model));
        }
    }
    Ok(hd)
}

/// How the loop ended.
#[derive(Debug)]
pub(crate) struct End {
    pub(crate) cause: StopCause,
    pub(crate) step: u64,
    pub(crate) deliverable: Option<Digest>,
}

/// The commit point: every H1 outcome is `NothingChecked`; a journal
/// failure is `UnreadableEvidence` (the writer also downgrades by itself).
pub(crate) fn commit<F: JournalFile, B: BlobSink, K: Clock>(
    w: JournalWriter<F, B, K>,
    end: &End,
    outcome: Option<GateOutcome>,
) -> harness_journal::Released {
    let outcome = outcome.unwrap_or(match end.cause {
        StopCause::JournalUnavailable { .. } => GateOutcome::Indeterminate {
            why: IndeterminateKind::UnreadableEvidence,
        },
        _ => GateOutcome::Indeterminate {
            why: IndeterminateKind::NothingChecked,
        },
    });
    w.commit(end.step, &end.cause, outcome, end.deliverable)
}

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
    /// Where render nonces come from (recorded ones first when replaying).
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
}

/// Where the answers to asks come from (§5.3, H2b): recorded answers first
/// (an audit, a resume's catch-up), then the live approver, if any. The
/// attempt's approval authority mints and redeems every token with a key
/// drawn here from OS randomness, held only in this struct.
pub(crate) struct Approvals<'a> {
    /// The live approver; `None` when nobody answers.
    pub(crate) approver: Option<&'a dyn Approver>,
    /// Recorded answers, re-fed in order before the approver is asked.
    pub(crate) recorded: std::collections::VecDeque<RecordedApproval>,
    /// The attempt's minter and verifier of approval tokens.
    pub(crate) authority: ApprovalAuthority,
    /// The attempt the tokens bind.
    pub(crate) attempt: u32,
    /// The authority's time origin (expiry is measured from it).
    pub(crate) epoch: Instant,
}

impl<'a> Approvals<'a> {
    /// The approvals of attempt `attempt` of `run`: a fresh per-attempt key
    /// (the run-id randomness, §2.8), so no token outlives its attempt.
    pub(crate) fn new(
        run: &RunId,
        attempt: u32,
        approver: Option<&'a dyn Approver>,
        recorded: std::collections::VecDeque<RecordedApproval>,
    ) -> Self {
        Self {
            approver,
            recorded,
            authority: ApprovalAuthority::new(run.clone(), random_bytes::<32>()),
            attempt,
            epoch: Instant::now(),
        }
    }
}

/// Where render nonces come from: recorded ones in order (so a replayed
/// request renders byte for byte), then fresh random ones.
#[derive(Debug, Default)]
pub(crate) struct NonceSource {
    pub(crate) recorded: std::collections::VecDeque<Nonce>,
}

impl NonceSource {
    fn next(&mut self) -> Option<Nonce> {
        self.recorded.pop_front().or_else(new_nonce)
    }
}

/// A recorded `ToolFinished`, re-fed in place of the call it records.
#[derive(Debug, Clone)]
pub(crate) struct RecordedResult {
    /// The capability the recorded intent named.
    pub(crate) capability: String,
    /// `None` for a recorded provider failure.
    pub(crate) status: Option<ToolStatus>,
    pub(crate) output: Vec<u8>,
    pub(crate) truncated: bool,
    pub(crate) digest: Digest,
    pub(crate) read_sha256: Option<Digest>,
    /// The sample recorded with a `timeout`, `crashed` or `provider_error`
    /// result (§7.1).
    pub(crate) environment: Option<EnvSample>,
    /// The `EditApplied` recorded before an ok edit's result (H2b).
    pub(crate) edit: Option<RecordedEdit>,
}

/// What an `EditApplied` record says an edit did (the path is the call's).
#[derive(Debug, Clone, Copy)]
pub(crate) struct RecordedEdit {
    pub(crate) before: Option<Digest>,
    pub(crate) after: Digest,
    /// The workspace tree digest after the edit.
    pub(crate) tree: Digest,
}

/// Whether `tool` is a built-in workspace edit (H2b).
pub(crate) fn is_edit(tool: &str) -> bool {
    harness_policy::EDIT_IDS.contains(&tool)
}

/// Whether `tool` is a built-in read tool (`harness.fs.*`).
fn is_read(tool: &str) -> bool {
    matches!(
        tool,
        "harness.fs.read" | "harness.fs.search" | "harness.fs.list"
    )
}

/// The files read this run, with the SHA-256 of each file's whole content
/// at its latest read (design §2.3 "Stale reads"). Defined by the edit
/// engine's crate and re-exported here (the run loop and the edit engine
/// must agree on one type); the edits themselves call [`ReadLog::check`],
/// which refuses an edit to a file that changed since it was read, or was
/// never read.
pub use harness_tools::{ReadLog, StaleRead};

/// One step's result.
enum Flow {
    Continue,
    Stop(StopCause, Option<Digest>),
}

fn journal(e: JournalError) -> StopCause {
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

    fn remaining_wall(&self) -> Duration {
        self.config.limits.wall.saturating_sub(self.meter.elapsed())
    }

    fn step<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
    ) -> Result<Flow, StopCause> {
        self.step += 1;
        let step = self.step;

        // 1. Charge the meter.
        self.meter.tick_wall()?;
        self.meter.charge_step()?;
        self.observe_budgets(w, step)?;

        // 2. Build the context (§2.3).
        let built = match context::build(
            self.profile,
            &self.tools,
            self.task,
            &self.facts,
            &self.turns,
        ) {
            Ok(b) => b,
            Err(ContextError::Exhausted { .. }) => return Err(StopCause::ContextExhausted),
            Err(ContextError::TooManyTools { .. }) => return Err(StopCause::PolicyAbort),
        };
        w.append(
            step,
            Event::new(EventKind::ContextBuilt)
                .field("context", Trusted::Digest(built.digest))
                .field("recent_turns", Trusted::U64(built.recent as u64))
                .field("estimated_tokens", Trusted::U64(built.estimated_tokens))
                .field("budget_tokens", Trusted::U64(built.budget_tokens)),
        )
        .map_err(journal)?;

        // 3. Call the model under the remaining wall budget.
        let (req, rendered) = self.request(built.messages)?;
        let ev = requested_event(&rendered, &req.nonce).ok_or(StopCause::PolicyAbort)?;
        w.append(step, ev).map_err(journal)?;
        let request_bytes = rendered.to_string().len() as u64;
        let deadline = Instant::now() + self.config.model_call_timeout.min(self.remaining_wall());
        let result = self.backend.complete(&req, deadline);
        // Journal first, then charge (H1e-2a review F-1): a wall-budget stop
        // must never leave a request without its reply in the journal.
        let ev = replied_event(w, &result).map_err(journal)?;
        w.append(step, ev).map_err(journal)?;
        self.meter.tick_wall()?;

        let completion = match result {
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
                self.feed_stall()?;
                // No action: the native protocol withholds this reply and
                // shows only the repair text (H1h; see `context`).
                self.turns.push(Turn {
                    step,
                    reply,
                    action: None,
                    feedback: Feedback::Harness(fe.repair_message(self.profile.protocol())),
                    notice: None,
                });
                return Ok(Flow::Continue);
            }
        };
        let tool = parsed.action.tool.clone();
        let capability = self.capability(&tool)?;
        let args = Value::Object(parsed.action.args);
        let args_text = args.to_string();
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
        let mut notice = None;
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
                notice = Some(HarnessText::from_static(
                    "Notice: you have made the same call three times in the last six steps. \
                     Doing it again will stop the run. Try something different or submit.",
                ));
            }
            LoopSignal::Stop(kind) => return self.loop_stop(w, step, kind),
        }

        // 5-6. Validate and decide (§5.1); the decision is journaled with its rule.
        let call = Call {
            capability: tool.clone(),
            args,
        };
        let decision = self.session.decide(&call);
        w.append(step, decided(&decision)).map_err(journal)?;
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
                let text = denied_text(&decision, &self.tools, &tool);
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
            w.append(
                step,
                Event::new(EventKind::ToolFinished)
                    .field("status", Trusted::Text("ok"))
                    .field("intent_seq", Trusted::U64(journaled.intent_seq())),
            )
            .map_err(journal)?;
            return Ok(Flow::Stop(StopCause::Submitted, Some(digest)));
        }

        // 8. Execute.
        let intent_seq = journaled.intent_seq();
        let ctx = InvokeCtx {
            step,
            deadline: Instant::now() + self.config.tool_call_timeout.min(self.remaining_wall()),
            reads: &self.reads,
        };
        let mut fed_environment = None;
        let mut fed_tree = None;
        let result = if let Some(rec) = self.feed.pop_front() {
            fed_environment = rec.environment;
            fed_tree = rec.edit.as_ref().map(|e| e.tree);
            // Replaying (audit, or a resume catching up): the recorded
            // result of this very call stands in for running it again, an
            // edit's included: a replay re-feeds what an edit did and never
            // applies it again (H2b). The intent above is journaled all the
            // same, so the replayed journal has the recorded shape.
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
        let mut edited = None;
        let mut unverified = false;
        let mut repeated = false;
        let feedback = match result {
            Ok(res) => {
                let out = w.untrusted(&res.output).map_err(journal)?;
                // A verified edit (§4.9 step 5): `EditApplied` before its
                // `ToolFinished`, so a durable result implies a durable
                // record of the edit. The tree digest after it comes from
                // the live listing, or from the journal when re-fed (a
                // resume's catch-up measured its listing after the edit).
                if let (Some(e), ToolStatus::Ok) = (&res.edit, res.status) {
                    let tree = match (fed_tree, self.workspace.as_mut()) {
                        (Some(t), _) => t,
                        (None, Some(ws)) => ws.record_edit(&e.path, e.after),
                        // An audit re-feeds every edit with its tree digest
                        // (`recorded` refuses one without it).
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
                    ev = ev
                        .field("after", Trusted::Digest(e.after))
                        .field("workspace_tree", Trusted::Digest(tree));
                    w.append(step, ev).map_err(journal)?;
                    // The harness wrote these bytes: they are the file's
                    // latest read, so the model may edit it again without
                    // re-reading; any other change still makes it stale.
                    self.reads.record(e.path.as_str(), e.after);
                    self.tree = tree;
                    edited = Some(e.path.as_str().to_owned());
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
        if unverified {
            return Err(StopCause::PolicyAbort);
        }
        // §2.6: edit churn, and a changed tree is progress.
        if let Some(file) = edited {
            if let LoopSignal::Stop(kind) = self.detector.observe(LoopEvent::EditApplied { file }) {
                return self.loop_stop(w, step, kind);
            }
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

    /// Build the request with a fresh nonce. A body that happens to contain
    /// the nonce is refused by the renderer; a new nonce is tried (three
    /// times) before the run stops.
    fn request(
        &mut self,
        mut messages: Vec<harness_model::Message>,
    ) -> Result<(ModelRequest, Value), StopCause> {
        for _ in 0..3 {
            let nonce = self.nonces.next().ok_or(StopCause::PolicyAbort)?;
            let req = ModelRequest {
                messages,
                tools: self.tools.clone(),
                nonce,
            };
            match render_request(&req, self.profile) {
                Ok(v) => return Ok((req, v)),
                Err(RenderError::DelimiterCollision) => messages = req.messages,
                Err(_) => return Err(StopCause::PolicyAbort),
            }
        }
        Err(StopCause::PolicyAbort)
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
                ModelError::Unavailable(_)
                | ModelError::RateLimited { .. }
                | ModelError::ReplayDiverged { .. },
                _,
            ) => return Err(StopCause::ModelUnavailable),
        };
        self.meter.record_format_error()?;
        self.feed_stall()?;
        self.turns.push(Turn {
            step,
            reply: Untrusted::new(String::new(), Source::Model),
            action: None,
            feedback: Feedback::Harness(HarnessText::from_static(text)),
            notice: None,
        });
        Ok(Flow::Continue)
    }

    /// The 80% standing condition per budget dimension (§2.6), journaled
    /// only when it begins or ends (`BudgetCharged`, key = dimension).
    fn observe_budgets<F: JournalFile, B: BlobSink, K: Clock>(
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

    /// A step with no action still counts toward no-progress (§2.6).
    fn feed_stall(&mut self) -> Result<(), StopCause> {
        match self.detector.observe(LoopEvent::Step) {
            LoopSignal::Stop(kind) => Err(StopCause::Loop(kind)),
            _ => Ok(()),
        }
    }

    /// A call that did not run (a denial, a declined or unanswered
    /// approval): its turn shows the static `text`, and it counts toward
    /// denial hammering (§2.6).
    #[allow(clippy::too_many_arguments)]
    fn refused<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
        step: u64,
        reply: Untrusted<String>,
        shown: ShownCall,
        notice: Option<HarnessText>,
        text: HarnessText,
        tool: String,
    ) -> Result<Flow, StopCause> {
        self.turns.push(Turn {
            step,
            reply,
            action: Some(shown),
            feedback: Feedback::Harness(text),
            notice,
        });
        if let LoopSignal::Stop(kind) = self
            .detector
            .observe(LoopEvent::PolicyDenied { capability: tool })
        {
            return self.loop_stop(w, step, kind);
        }
        Ok(Flow::Continue)
    }

    /// §5.3: an `Ask` becomes a call only with a yes for exactly this call.
    /// Journals `ApprovalRequested`, takes the answer (recorded, when
    /// replaying; else the live approver's, with the wall clock paused and
    /// the approval timeout as its deadline; else none), and on a yes mints
    /// a single-use token bound to this attempt, step, capability, argument
    /// digest and tier, redeems it at once, and authorises the call with
    /// the proof (`ApprovalGranted` records the consumed nonce, never the
    /// MAC). A no is `ApprovalDenied`, no answer `ApprovalExpired`: the
    /// call does not run and the model is told so in static text. A token
    /// that fails to mint, redeem or authorise (a recorded nonce reused, a
    /// harness bug) stops the run: `PolicyAbort`, never a call.
    fn approve<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
        step: u64,
        capability: &Capability,
        call: Call,
        tier: Confirmation,
    ) -> Result<Result<Authorized<Call>, HarnessText>, StopCause> {
        let abort = StopCause::PolicyAbort;
        let cap_id = Ident::from_capability(capability).ok_or(abort.clone())?;
        let class = self
            .session
            .class(capability.id().as_str())
            .ok_or(abort.clone())?;
        let at = StepId::new(step);
        let attempt = self.approvals.attempt;
        let bound = BoundCall::for_call(attempt, at, &call, tier).ok_or(abort.clone())?;
        let about = |kind| {
            Event::new(kind)
                .field("capability", Trusted::Id(cap_id.clone()))
                .field("args", Trusted::Digest(bound.args_sha256))
                .field("tier", Trusted::Text(tier.as_str()))
        };
        w.append(step, about(EventKind::ApprovalRequested))
            .map_err(journal)?;
        let answer = match self.approvals.recorded.pop_front() {
            Some(recorded) => recorded,
            None => match self.approvals.approver {
                Some(a) => {
                    let req = ApprovalRequest::new(
                        capability.id().clone(),
                        capability.summary().to_owned(),
                        class,
                        call.args.clone(),
                        tier,
                        attempt,
                        at,
                    );
                    let deadline = Instant::now() + self.config.approval_timeout;
                    // §2.4: the wait for a human is not charged to the
                    // wall budget (the guard resumes the clock on drop).
                    let pause = self.meter.pause_wall()?;
                    let said = a.ask(&req, deadline);
                    drop(pause);
                    match said {
                        ApprovalAnswer::Yes => RecordedApproval::Granted {
                            kind: a.kind(),
                            nonce: random_bytes::<16>(),
                        },
                        ApprovalAnswer::No => RecordedApproval::Denied { kind: a.kind() },
                        ApprovalAnswer::NoAnswer => RecordedApproval::Expired,
                    }
                }
                // Policy asked with nobody here to answer (an audit whose
                // journal ends in the wait): no yes, so no call.
                None => RecordedApproval::Expired,
            },
        };
        match answer {
            RecordedApproval::Granted { kind, nonce } => {
                let a = &mut self.approvals;
                let now = a.epoch.elapsed();
                let token = a
                    .authority
                    .mint(
                        &MintRequest {
                            attempt,
                            step: at,
                            capability: bound.capability.clone(),
                            args_sha256: bound.args_sha256,
                            tier,
                            scope: ApprovalScope::Once,
                            approver: PrincipalId::new(kind.as_str()).map_err(|_| abort.clone())?,
                        },
                        nonce,
                        now,
                    )
                    .map_err(|_| abort.clone())?;
                let redeemed = a
                    .authority
                    .redeem(&token, &bound, now)
                    .map_err(|_| abort.clone())?;
                let authorized = self
                    .session
                    .authorize_approved(call, redeemed)
                    .map_err(|_| abort.clone())?;
                let name = nonce_name(nonce).ok_or(abort.clone())?;
                let nonce_id = Ident::from_trusted(&name).ok_or(abort)?;
                w.append(
                    step,
                    about(EventKind::ApprovalGranted)
                        .field("approver", Trusted::Text(kind.as_str()))
                        .field("nonce", Trusted::Id(nonce_id))
                        .field("scope", Trusted::Text("once")),
                )
                .map_err(journal)?;
                Ok(Ok(authorized))
            }
            RecordedApproval::Denied { kind } => {
                w.append(
                    step,
                    about(EventKind::ApprovalDenied)
                        .field("approver", Trusted::Text(kind.as_str())),
                )
                .map_err(journal)?;
                Ok(Err(HarnessText::from_static(
                    "The approver declined the call, so it did not run.",
                )))
            }
            RecordedApproval::Expired => {
                w.append(step, about(EventKind::ApprovalExpired))
                    .map_err(journal)?;
                Ok(Err(HarnessText::from_static(
                    "No approval arrived in time, so the call did not run.",
                )))
            }
        }
    }

    fn loop_stop<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
        step: u64,
        kind: LoopKind,
    ) -> Result<Flow, StopCause> {
        w.append(
            step,
            Event::new(EventKind::LoopDetected)
                .field("kind", Trusted::Text(loop_name(kind)))
                .field("stop", Trusted::Bool(true)),
        )
        .map_err(journal)?;
        Ok(Flow::Stop(StopCause::Loop(kind), None))
    }

    /// The admitted capability behind an active tool id.
    fn capability(&self, id: &str) -> Result<&'a Capability, StopCause> {
        let registry: &'a Registry = self.registry;
        match registry.resolve(id) {
            Resolved::One { capability, .. } => Ok(capability),
            // The parser only returns active tool ids, all resolved at
            // planning; anything else is a harness bug, refused.
            _ => Err(StopCause::PolicyAbort),
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

fn decided(d: &PolicyDecision) -> Event {
    let rule = match d.rule() {
        RuleId::Builtin(name) => Trusted::Text(name),
        RuleId::User { list, index } => Trusted::Obj(vec![
            (
                "list",
                Trusted::Text(match list {
                    RuleList::Deny => "deny",
                    RuleList::Ask => "ask",
                    RuleList::Allow => "allow",
                }),
            ),
            ("index", Trusted::U64(index as u64)),
        ]),
    };
    let mut ev = Event::new(EventKind::PolicyDecided)
        .field(
            "decision",
            Trusted::Text(match d {
                PolicyDecision::Allow { .. } => "allow",
                PolicyDecision::Ask { .. } => "ask",
                PolicyDecision::Deny { .. } => "deny",
            }),
        )
        .field("rule", rule);
    if let PolicyDecision::Deny { reason, .. } = d {
        ev = ev.field("reason", Trusted::Text(deny_name(reason)));
    }
    // An ask names its tier (it binds the approval token, §5.3).
    if let PolicyDecision::Ask { tier, .. } = d {
        ev = ev.field("tier", Trusted::Text(tier.as_str()));
    }
    ev
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

impl RecordedResult {
    /// The recorded result as a tool result for this call. A recorded
    /// result for another capability is a provider failure here, so the
    /// replayed journal differs from the recorded one at this step.
    fn into_result(
        self,
        tool: &str,
        path: Option<&str>,
    ) -> Result<harness_tools::ToolResult, harness_tools::ToolError> {
        let unfit =
            || harness_tools::ToolError("the recorded result does not fit this call".into());
        if self.capability != tool {
            return Err(unfit());
        }
        let status = self.status.ok_or_else(unfit)?;
        let read = match (self.read_sha256, path) {
            (Some(sha256), Some(p)) => Some(harness_tools::ReadRecord {
                path: harness_policy::workspace_path(p).map_err(|_| unfit())?,
                sha256,
            }),
            (None, _) => None,
            (Some(_), None) => return Err(unfit()),
        };
        let edit = match (self.edit, path) {
            (Some(e), Some(p)) if is_edit(tool) => Some(harness_tools::EditRecord {
                path: harness_policy::workspace_path(p).map_err(|_| unfit())?,
                before: e.before,
                after: e.after,
            }),
            (None, _) => None,
            _ => return Err(unfit()),
        };
        Ok(harness_tools::ToolResult {
            status,
            output: Untrusted::new(self.output, Source::Tool(self.capability)),
            truncated: self.truncated,
            digest: self.digest,
            read,
            edit,
        })
    }
}

fn deny_name(r: &DenyReason) -> &'static str {
    match r {
        DenyReason::NotGranted => "not_granted",
        DenyReason::Quarantined => "quarantined",
        DenyReason::ClassOutOfScope(_) => "class_out_of_scope",
        DenyReason::Restricted => "restricted",
        DenyReason::EgressUnavailable => "egress_unavailable",
        DenyReason::NoConformed => "no_conformed",
        DenyReason::PersonalNotGranted => "personal_not_granted",
        DenyReason::UserDenied => "user_denied",
        DenyReason::Args(_) => "args_schema",
        DenyReason::Path(_) => "path_outside_workspace",
        DenyReason::NoApprover => "no_approver",
        DenyReason::NoRuleMatched => "no_rule_matched",
    }
}

/// What the model is told about a denial: static text per reason (the
/// argument error's own detail may quote model text, so it is not shown).
fn denied_text(d: &PolicyDecision, tools: &[ToolSpec], tool: &str) -> HarnessText {
    // An argument outside its schema's bounds is named with its bounds, as
    // the tool's own schema gives them (the argument's name is the schema's
    // key, found by the error's path; the call's text is never shown).
    if let PolicyDecision::Deny {
        reason: DenyReason::Args(e),
        ..
    } = d
    {
        let bounded =
            e.at.strip_prefix('/')
                .filter(|p| !p.contains('/'))
                .and_then(|p| {
                    let spec = tools.iter().find(|t| t.id == tool)?;
                    HarnessText::argument_bounds(spec, p)
                });
        if let Some(text) = bounded {
            return text;
        }
    }
    HarnessText::from_static(match d {
        PolicyDecision::Deny {
            reason: DenyReason::Path(_),
            ..
        } => {
            "Policy denied the call: the path must be a normalised relative path inside the workspace (no '..', no leading or trailing '/', no empty components, no '\\\\' or ':')."
        }
        PolicyDecision::Deny {
            reason: DenyReason::Args(_),
            ..
        } => "Policy denied the call: the arguments do not match the tool's schema.",
        PolicyDecision::Deny {
            reason: DenyReason::NotGranted,
            ..
        } => "Policy denied the call: that tool is not granted in this session.",
        PolicyDecision::Deny {
            reason: DenyReason::NoApprover,
            ..
        } => {
            "Policy denied the call: it needs a person's approval, and no approver is present in this run. It did not run."
        }
        _ => "Policy denied the call.",
    })
}

fn fe_name(e: FormatError) -> &'static str {
    match e {
        FormatError::NoAction => "no_action",
        FormatError::SeveralActions => "several_actions",
        FormatError::Unbalanced => "unbalanced",
        FormatError::ToolCallsInTextMode => "tool_calls_in_text_mode",
        FormatError::BadJson => "bad_json",
        FormatError::WrongShape => "wrong_shape",
        FormatError::UnknownTool => "unknown_tool",
        FormatError::TooLarge => "too_large",
    }
}

fn loop_name(k: LoopKind) -> &'static str {
    match k {
        LoopKind::Repeat => "repeat",
        LoopKind::EditChurn => "edit_churn",
        LoopKind::NoProgress => "no_progress",
        LoopKind::Denied => "denied",
    }
}

fn status_name(s: ToolStatus) -> &'static str {
    match s {
        ToolStatus::Ok => "ok",
        ToolStatus::Error { .. } => "error",
        ToolStatus::Timeout => "timeout",
        ToolStatus::Crashed { .. } => "crashed",
        ToolStatus::Refused { .. } => "refused",
    }
}

// ---------------------------------------------------------------------------
// Identity and randomness.
// ---------------------------------------------------------------------------

fn random_bytes<const N: usize>() -> [u8; N] {
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
