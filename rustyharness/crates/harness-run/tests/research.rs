//! Research sessions without a workspace (P-39i, slice card §11): whole
//! runs through the public `run_research`, the refusals around them, and
//! the coding paths staying byte-for-byte what they were. The model is
//! the scripted backend; the state roots are real directories; the
//! research sessions run with no workspace at all — the tests' scratch
//! has none to give.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Instant;

use gate_outcome::{GateOutcome, IndeterminateKind};
use harness_core::environment::{EnvSample, Unmeasured};
use harness_core::StopCause;
use harness_journal::layout;
use harness_journal::{EventKind, JournalReader, Record};
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, SemVer, ValidationContext};
use harness_model::profile::Profile;
use harness_model::scripted::ScriptedBackend;
use harness_model::TaskText;
use harness_policy::{SessionKind, UserPolicy, WebConfirmation, WebGrant};
use harness_run::{
    audit_session, resume_session, run, run_research, run_session, InputEnd, ResumeSession,
    RunRefused, SessionConfig, SessionReport, SessionRun, TaskSpec, TurnLimits, UserInput,
    UserInputEvent, UserMessage,
};
use harness_sandbox::{Confinement, Conformed, Refused, SystemConfinement};
use harness_testkit::{act, say, Local};
use serde_json::Value;

/// A fixed environment sample (the real probe is harness-sandbox's; these
/// tests only need the header and records to carry one).
const FIXED_ENV: EnvSample = EnvSample::unmeasured(Unmeasured::NoSafeApi);

/// The token budget every scripted session is given.
const TOKENS: u64 = 1_000_000;

const NOTHING_CHECKED: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::NothingChecked,
};

const TASK: &str = "Research the thing and submit what you find.";

// ---------------------------------------------------------------------------
// The rig.
// ---------------------------------------------------------------------------

/// A state root and — for the coding contrast runs — a workspace with two
/// files. The research runs use the state root only.
fn scratch(name: &str) -> (PathBuf, PathBuf) {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("research-{name}"));
    let _ = fs::remove_dir_all(&base);
    let (state, ws) = (base.join("state"), base.join("ws"));
    fs::create_dir_all(&state).unwrap();
    fs::create_dir_all(&ws).unwrap();
    fs::write(ws.join("a.txt"), "alpha\n").unwrap();
    (state, ws)
}

/// A state root with no workspace beside it: what a research session gets.
fn scratch_alone(name: &str) -> PathBuf {
    scratch(name).0
}

/// The research registry (§2.2): the built-in research manifest, whose web
/// capabilities are admitted even though this build wires no driver for
/// them (P-39j does).
fn research_registry() -> Registry {
    let ctx = ValidationContext::new(
        SemVer {
            major: 0,
            minor: 0,
            patch: 1,
        },
        &[],
    )
    .unwrap();
    Registry::admit(vec![(
        builtin::research_manifest(&ctx).unwrap(),
        Tier::Builtin,
    )])
    .unwrap()
}

/// The coding registry: the built-in manifest, as every coding test uses.
fn coding_registry() -> Registry {
    let ctx = ValidationContext::new(
        SemVer {
            major: 0,
            minor: 0,
            patch: 1,
        },
        &[],
    )
    .unwrap();
    Registry::admit(vec![(builtin::manifest(&ctx).unwrap(), Tier::Builtin)]).unwrap()
}

/// A research spec: the task tools (`todo`, plus the always-added submit),
/// the confirmed allowlist and search flag, and no exec, pre-submit or
/// protected section (each of those is a refusal, tested below).
fn research_spec(
    grants: &[&str],
    allowlist: &[&str],
    search: bool,
    confirmed: Option<WebConfirmation>,
) -> TaskSpec {
    TaskSpec {
        task: TaskText::new(TASK.into()),
        grants: grants.iter().map(|g| (*g).to_owned()).collect(),
        workspace_public: false,
        exec: None,
        presubmit: None,
        protected: Vec::new(),
        kind: SessionKind::Research(WebGrant {
            allowlist: allowlist.iter().map(|a| (*a).to_owned()).collect(),
            search,
            confirmed,
        }),
    }
}

/// A coding spec (the contrast runs).
fn coding_spec(grants: &[&str]) -> TaskSpec {
    TaskSpec {
        task: TaskText::new("Say what a.txt says.".into()),
        grants: grants.iter().map(|g| (*g).to_owned()).collect(),
        workspace_public: false,
        exec: None,
        presubmit: None,
        protected: Vec::new(),
        kind: SessionKind::Coding,
    }
}

/// A scripted [`UserInput`]: the messages in order, then `eof`.
struct ScriptedInput {
    steps: RefCell<VecDeque<UserInputEvent>>,
}

impl ScriptedInput {
    fn of(msgs: &[&str]) -> Self {
        Self {
            steps: RefCell::new(
                msgs.iter()
                    .map(|m| {
                        UserInputEvent::Message(UserMessage::new((*m).to_owned()).expect("message"))
                    })
                    .collect(),
            ),
        }
    }
}

impl UserInput for ScriptedInput {
    fn next(&self, _deadline: Instant) -> UserInputEvent {
        self.steps
            .borrow_mut()
            .pop_front()
            .unwrap_or(UserInputEvent::End(InputEnd::Eof))
    }
}

/// The production witness, obtained once per test binary (the live probe
/// runs FT-5's fork burst and sweep; one of them proves the same for
/// every test here, as `tests/exec.rs` found).
struct Real;

impl Confinement for Real {
    fn require(&self) -> Result<Conformed, Refused> {
        static W: OnceLock<Result<Conformed, Refused>> = OnceLock::new();
        W.get_or_init(|| SystemConfinement.require()).clone()
    }

    fn spawn(
        &self,
        spec: &harness_sandbox::ConfinedSpec,
        ev: &Conformed,
    ) -> Result<harness_sandbox::ConfinedChild, harness_sandbox::SpawnError> {
        SystemConfinement.spawn(spec, ev)
    }
}

/// Run a research session with explicit everything (defaults otherwise).
#[allow(clippy::too_many_arguments)]
fn drive_research(
    state: &Path,
    spec: &TaskSpec,
    registry: &Registry,
    replies: Vec<harness_model::Completion>,
    input: &dyn UserInput,
    confinement: Option<&dyn Confinement>,
) -> Result<SessionReport, RunRefused> {
    let profile = Profile::conservative_default("m");
    let backend = ScriptedBackend::new(profile.clone(), replies.into_iter().map(Ok).collect());
    run_research(harness_run::ResearchRun {
        state_root: state,
        spec,
        registry,
        policy: &UserPolicy::default(),
        profile: &profile,
        backend: &backend,
        probe: &Local,
        env: &FIXED_ENV,
        config: &SessionConfig::defaults(TOKENS),
        approver: None,
        confinement,
        input,
        sink: None,
    })
}

/// Run a research session the default way: the research registry, the
/// task tools, a confirmed allowlist, the real confinement.
fn go_research(
    name: &str,
    replies: Vec<harness_model::Completion>,
    msgs: &[&str],
) -> SessionReport {
    let state = scratch_alone(name);
    let spec = research_spec(
        &["harness.task.todo"],
        &["example.com"],
        false,
        Some(WebConfirmation::Tty),
    );
    drive_research(
        &state,
        &spec,
        &research_registry(),
        replies,
        &ScriptedInput::of(msgs),
        Some(&Real),
    )
    .unwrap()
}

/// The session audit over a research journal, given what the run had.
fn audit_research(
    state: &Path,
    run_id: &harness_core::RunId,
    spec: &TaskSpec,
    chain_head: Option<gate_outcome::Digest>,
    attempt: Option<u32>,
) -> harness_run::AuditReport {
    let mut limits = SessionConfig::defaults(TOKENS).run.limits.clone();
    limits.format_errors = u32::MAX;
    audit_session(
        harness_run::Audit {
            state_root: state,
            run: run_id,
            attempt,
            anchor: chain_head,
            spec,
            registry: &research_registry(),
            policy: &UserPolicy::default(),
            profile: &Profile::conservative_default("m"),
            limits: &limits,
        },
        &SessionConfig::defaults(TOKENS).turn,
    )
    .unwrap()
}

fn records(state: &Path, run_id: &harness_core::RunId, attempt: u32) -> Vec<Record> {
    JournalReader::open(&layout::attempt_dir(
        &layout::run_dir(state, run_id),
        attempt,
    ))
    .unwrap()
    .records
}

fn kinds(recs: &[Record]) -> Vec<EventKind> {
    recs.iter().map(|r| r.kind).collect()
}

fn header_of(recs: &[Record]) -> &serde_json::Map<String, Value> {
    &recs.first().unwrap().body
}

fn journal_path(state: &Path, run_id: &harness_core::RunId, attempt: u32) -> PathBuf {
    layout::attempt_dir(&layout::run_dir(state, run_id), attempt).join(layout::JOURNAL_FILE)
}

/// Cut a journal just before its first record of kind `kind` at `step`
/// (a crash mid-session: whole lines survive, `RunStopped` is gone).
fn crash_in(path: &Path, step: u64, kind: &str) {
    let text = fs::read_to_string(path).unwrap();
    let mut out = String::new();
    for line in text.lines() {
        let v: Value = serde_json::from_str(line).unwrap();
        let s = v["step"].as_u64().unwrap();
        if s > step || (s == step && v["kind"] == kind) || v["kind"] == "RunStopped" {
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    fs::write(path, out).unwrap();
}

/// Context digests of a run's journal, in order.
fn context_digests(recs: &[Record]) -> Vec<String> {
    recs.iter()
        .filter(|r| r.kind == EventKind::ContextBuilt)
        .map(|r| r.body["context"].as_str().unwrap().to_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// The slice-card tests.
// ---------------------------------------------------------------------------

/// A research session grants no workspace: the batch `run` and the coding
/// `run_session` refuse a research spec (each loop is the other's), and a
/// research session's turn records measure nothing — the no-workspace
/// facts (zero files, the digest of an empty walk), never a tree.
#[test]
fn research_session_has_no_workspace_grant() {
    // `run` refuses: a research session is not a batch run.
    let state = scratch_alone("no-batch");
    let spec = research_spec(&[], &[], false, Some(WebConfirmation::Tty));
    let err = run(harness_run::Run {
        state_root: &state,
        workspace: &state,
        spec: &spec,
        registry: &research_registry(),
        policy: &UserPolicy::default(),
        profile: &Profile::conservative_default("m"),
        backend: &ScriptedBackend::new(Profile::conservative_default("m"), Vec::new()),
        probe: &Local,
        env: &FIXED_ENV,
        config: &harness_run::RunConfig::defaults(TOKENS),
        approver: None,
        confinement: Some(&Real),
    })
    .expect_err("a research session is not a batch run");
    assert!(matches!(err, RunRefused::Research(_)), "{err:?}");

    // `run_session` refuses: a research session is not a coding session.
    let err = run_session(SessionRun {
        state_root: &state,
        workspace: &state,
        spec: &spec,
        registry: &research_registry(),
        policy: &UserPolicy::default(),
        profile: &Profile::conservative_default("m"),
        backend: &ScriptedBackend::new(Profile::conservative_default("m"), Vec::new()),
        probe: &Local,
        env: &FIXED_ENV,
        config: &SessionConfig::defaults(TOKENS),
        approver: None,
        confinement: Some(&Real),
        input: &ScriptedInput::of(&["hi"]),
        sink: None,
    })
    .expect_err("a research session is not a coding session");
    assert!(matches!(err, RunRefused::Research(_)), "{err:?}");

    // `run_research` refuses a coding spec the same way.
    let err = drive_research(
        &state,
        &coding_spec(&["harness.fs.read"]),
        &coding_registry(),
        Vec::new(),
        &ScriptedInput::of(&["hi"]),
        Some(&Real),
    )
    .expect_err("run_research runs research sessions only");
    assert!(matches!(err, RunRefused::Research(_)), "{err:?}");

    // A research session's turn records carry the no-workspace facts.
    let r = go_research(
        "no-ws-facts",
        vec![act("harness.task.submit", r#"{"note":"found it"}"#)],
        &["go"],
    );
    let recs = records(&state_of(&r), &r.run.run, r.run.attempt);
    let turns: Vec<&serde_json::Map<String, Value>> = recs
        .iter()
        .filter(|x| x.kind == EventKind::UserTurn)
        .map(|x| &x.body)
        .collect();
    assert_eq!(turns.len(), 1);
    assert_eq!(turns[0]["workspace_files"], Value::from(0u64));
    assert_eq!(turns[0]["workspace_oversize"], Value::from(0u64));
    // The digest of an empty walk: sha256 of the empty input.
    let tree = turns[0]["workspace_tree"].as_str().unwrap();
    assert_eq!(tree.len(), 64);
}

/// The state root a report ran under (the report carries the run dir; its
/// parent's parent is the state root).
fn state_of(r: &SessionReport) -> PathBuf {
    r.run
        .run_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// A scripted research session runs two user turns to their submits, and
/// the session audit replays it clean: every record recomputed or re-fed,
/// the stop recomputed, the chain head anchored.
#[test]
fn research_session_runs_two_turns_and_audits_clean() {
    let r = go_research(
        "two-turns",
        vec![
            act(
                "harness.task.todo",
                r#"{"items":[{"text":"search the docs","status":"in_progress"}]}"#,
            ),
            act("harness.task.submit", r#"{"note":"first finding"}"#),
            act("harness.task.submit", r#"{"note":"second finding"}"#),
        ],
        &["research the docs", "and again"],
    );
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(r.run.outcome, NOTHING_CHECKED);
    assert_eq!(r.turns, 2);
    let recs = records(&state_of(&r), &r.run.run, r.run.attempt);
    assert_eq!(
        kinds(&recs)
            .iter()
            .filter(|k| **k == EventKind::UserTurn)
            .count(),
        2
    );
    assert_eq!(
        kinds(&recs)
            .iter()
            .filter(|k| **k == EventKind::TurnEnded)
            .count(),
        2
    );
    assert_eq!(
        kinds(&recs)
            .iter()
            .filter(|k| **k == EventKind::InputEnded)
            .count(),
        1
    );
    // The checklist applied: the todo call ran (and only it, beside the
    // two submits), and its result is journaled.
    let finished: Vec<(&Record, &serde_json::Map<String, Value>)> = recs
        .iter()
        .filter(|x| x.kind == EventKind::ToolFinished)
        .map(|x| (x, &x.body))
        .collect();
    assert_eq!(finished.len(), 3, "todo + two submits");
    assert_eq!(
        finished[0].0.body["output"]["source"]["id"],
        Value::from("harness.task.todo"),
        "the todo call ran in turn 1"
    );

    let spec = research_spec(
        &["harness.task.todo"],
        &["example.com"],
        false,
        Some(WebConfirmation::Tty),
    );
    let a = audit_research(&state_of(&r), &r.run.run, &spec, r.run.chain_head, None);
    assert_eq!(a.divergence, None, "{a:?}");
    assert!(a.stop_recomputed);
    assert!(a.anchored);
    assert_eq!(a.outcome, NOTHING_CHECKED);
}

/// The research header records the session kind and the web grant
/// (INV-42): `session_kind` is `research`, `web` is the digest of the
/// grant (a 64-hex sha256), and both keys are absent from a coding
/// journal's header (tested beside this one).
#[test]
fn research_header_records_kind_allowlist_and_confirmation() {
    let r = go_research(
        "header",
        vec![act("harness.task.submit", r#"{"note":"done"}"#)],
        &["go"],
    );
    let recs = records(&state_of(&r), &r.run.run, r.run.attempt);
    let head = header_of(&recs);
    assert_eq!(head["session_kind"], Value::from("research"));
    let web = head["web"].as_str().expect("the web grant digest");
    assert_eq!(web.len(), 64, "sha256 hex: {web}");
    // The same grant digests the same: a second run's header carries the
    // identical digest.
    let r2 = go_research(
        "header-again",
        vec![act("harness.task.submit", r#"{"note":"done"}"#)],
        &["go"],
    );
    let recs2 = records(&state_of(&r2), &r2.run.run, r2.run.attempt);
    let head2 = header_of(&recs2);
    assert_eq!(head2["web"], head["web"]);
    // A different grant digests differently.
    let state = scratch_alone("header-other");
    let other = research_spec(
        &["harness.task.todo"],
        &["example.org"],
        true,
        Some(WebConfirmation::Flag),
    );
    let r3 = drive_research(
        &state,
        &other,
        &research_registry(),
        vec![act("harness.task.submit", r#"{"note":"done"}"#)],
        &ScriptedInput::of(&["go"]),
        Some(&Real),
    )
    .unwrap();
    let recs3 = records(&state, &r3.run.run, r3.run.attempt);
    let head3 = header_of(&recs3);
    assert_ne!(head3["web"], head["web"]);
}

/// The coding paths are unchanged (the formats are their own lines, and a
/// coding header names no session kind and no web grant): a batch header
/// carries `rh-context/5` and a session header `rh-context/6`, and
/// neither carries `session_kind` or `web`.
#[test]
fn coding_header_digest_unchanged() {
    // A coding batch run.
    let (state, ws) = scratch("coding-batch");
    let reg = coding_registry();
    let profile = Profile::conservative_default("m");
    let backend = ScriptedBackend::new(profile.clone(), vec![Ok(say("it says alpha"))]);
    let r = run(harness_run::Run {
        state_root: &state,
        workspace: &ws,
        spec: &coding_spec(&["harness.fs.read"]),
        registry: &reg,
        policy: &UserPolicy::default(),
        profile: &profile,
        backend: &backend,
        probe: &Local,
        env: &FIXED_ENV,
        config: &harness_run::RunConfig::defaults(TOKENS),
        approver: None,
        confinement: None,
    })
    .unwrap();
    let recs = JournalReader::open(&layout::attempt_dir(&r.run_dir, r.attempt))
        .unwrap()
        .records;
    let head = header_of(&recs);
    assert_eq!(head.get("session_kind"), None, "no kind key for coding");
    assert_eq!(head.get("web"), None, "no web key for coding");
    assert_eq!(head["context_format"], Value::from("rh-context/5"));

    // A coding session.
    let (state, ws) = scratch("coding-session");
    let spec = coding_spec(&["harness.fs.read"]);
    let sr = run_session(SessionRun {
        state_root: &state,
        workspace: &ws,
        spec: &spec,
        registry: &reg,
        policy: &UserPolicy::default(),
        profile: &profile,
        backend: &ScriptedBackend::new(profile.clone(), vec![Ok(say("alpha")), Ok(say("done"))]),
        probe: &Local,
        env: &FIXED_ENV,
        config: &SessionConfig::defaults(TOKENS),
        approver: None,
        confinement: None,
        input: &ScriptedInput::of(&["what does it say", "thanks"]),
        sink: None,
    })
    .unwrap();
    let recs = records(&state, &sr.run.run, sr.run.attempt);
    let head = header_of(&recs);
    assert_eq!(head.get("session_kind"), None, "no kind key for coding");
    assert_eq!(head.get("web"), None, "no web key for coding");
    assert_eq!(head["context_format"], Value::from("rh-context/6"));
    assert_eq!(head["mode"], Value::from("session"));
}

/// The coding contexts are unchanged: the same scripted batch run and the
/// same scripted session produce the same ContextBuilt digests they did
/// before this slice (the research path renders nothing into them).
#[test]
fn batch_and_session_context_digests_unchanged() {
    // Two identical batch runs: identical context digests.
    let mut batch_vectors = Vec::new();
    for i in 0..2 {
        let (state, ws) = scratch(&format!("digest-batch-{i}"));
        let profile = Profile::conservative_default("m");
        let backend = ScriptedBackend::new(profile.clone(), vec![Ok(say("it says alpha"))]);
        let r = run(harness_run::Run {
            state_root: &state,
            workspace: &ws,
            spec: &coding_spec(&["harness.fs.read"]),
            registry: &coding_registry(),
            policy: &UserPolicy::default(),
            profile: &profile,
            backend: &backend,
            probe: &Local,
            env: &FIXED_ENV,
            config: &harness_run::RunConfig::defaults(TOKENS),
            approver: None,
            confinement: None,
        })
        .unwrap();
        let recs = JournalReader::open(&layout::attempt_dir(&r.run_dir, r.attempt))
            .unwrap()
            .records;
        batch_vectors.push(context_digests(&recs));
    }
    assert!(!batch_vectors[0].is_empty(), "a batch run builds contexts");
    assert_eq!(
        batch_vectors[0], batch_vectors[1],
        "the build is deterministic"
    );
    let batch_digests = batch_vectors.remove(0);

    // Two identical sessions: identical context digests, and different
    // from the batch's (the session shape has its own).
    let mut session_vectors = Vec::new();
    for i in 0..2 {
        let (state, ws) = scratch(&format!("digest-session-{i}"));
        let profile = Profile::conservative_default("m");
        let spec = coding_spec(&["harness.fs.read"]);
        let sr = run_session(SessionRun {
            state_root: &state,
            workspace: &ws,
            spec: &spec,
            registry: &coding_registry(),
            policy: &UserPolicy::default(),
            profile: &profile,
            backend: &ScriptedBackend::new(
                profile.clone(),
                vec![Ok(say("alpha")), Ok(say("done"))],
            ),
            probe: &Local,
            env: &FIXED_ENV,
            config: &SessionConfig::defaults(TOKENS),
            approver: None,
            confinement: None,
            input: &ScriptedInput::of(&["what does it say", "thanks"]),
            sink: None,
        })
        .unwrap();
        let recs = records(&state, &sr.run.run, sr.run.attempt);
        session_vectors.push(context_digests(&recs));
    }
    assert!(session_vectors[0].len() >= 2, "two turns, two builds");
    assert_eq!(
        session_vectors[0], session_vectors[1],
        "the build is deterministic"
    );
    // The session's first-turn build is its own shape (the users' share);
    // it is not the batch build's digest.
    assert_ne!(session_vectors[0][0], batch_digests[0]);
}

/// The research context is its own format line: `rh-research/1`, in the
/// compiled-in constant and in the research header alike — never a bump
/// of either `rh-context` line.
#[test]
fn research_context_format_is_rh_research_1() {
    assert_eq!(
        harness_model::context::RESEARCH_CONTEXT_FORMAT,
        "rh-research/1"
    );
    assert_eq!(harness_model::context::CONTEXT_FORMAT, "rh-context/5");
    assert_eq!(
        harness_model::context::SESSION_CONTEXT_FORMAT,
        "rh-context/6"
    );

    let r = go_research(
        "format",
        vec![act("harness.task.submit", r#"{"note":"done"}"#)],
        &["go"],
    );
    let recs = records(&state_of(&r), &r.run.run, r.run.attempt);
    let head = header_of(&recs);
    assert_eq!(
        head["context_format"],
        Value::from(harness_model::context::RESEARCH_CONTEXT_FORMAT)
    );
}

/// The research refusals, fail closed (P-39i): no confinement, an
/// unconfirmed grant, a web capability this build does not wire, an exec
/// section, a pre-submit section, protected paths, and the coding
/// registry are each refused before anything is written.
#[test]
fn research_refused_without_conformed() {
    let state = scratch_alone("refusals");
    let confirmed = research_spec(
        &["harness.task.todo"],
        &["example.com"],
        false,
        Some(WebConfirmation::Tty),
    );

    // No confinement: the web airlock has no witness to demand, so the
    // session does not start (INV-42).
    let err = drive_research(
        &state,
        &confirmed,
        &research_registry(),
        Vec::new(),
        &ScriptedInput::of(&["go"]),
        None,
    )
    .expect_err("no confinement, no research session");
    assert!(
        matches!(err, RunRefused::Research(msg) if msg.contains("confinement")),
        "{err:?}"
    );

    // A confinement whose witness is refused: the session does not start
    // (no unconfined fallback; INV-42).
    struct Sick;
    impl Confinement for Sick {
        fn require(&self) -> Result<Conformed, Refused> {
            Err(Refused(harness_sandbox::Unavailable {
                backend: None,
                reason: harness_sandbox::UnavailableReason::NoBackendForOs,
            }))
        }

        fn spawn(
            &self,
            _spec: &harness_sandbox::ConfinedSpec,
            _ev: &Conformed,
        ) -> Result<harness_sandbox::ConfinedChild, harness_sandbox::SpawnError> {
            Err(harness_sandbox::SpawnError::Io("no sandbox".into()))
        }
    }
    let err = drive_research(
        &state,
        &confirmed,
        &research_registry(),
        Vec::new(),
        &ScriptedInput::of(&["go"]),
        Some(&Sick),
    )
    .expect_err("no witness, no research session");
    assert!(matches!(err, RunRefused::Confinement(_)), "{err:?}");

    // A grant the driver does not wire (P-39j does): refused even though
    // the research registry admits it.
    let web = research_spec(
        &["harness.web.fetch"],
        &["example.com"],
        false,
        Some(WebConfirmation::Tty),
    );
    let err = drive_research(
        &state,
        &web,
        &research_registry(),
        Vec::new(),
        &ScriptedInput::of(&["go"]),
        Some(&Real),
    )
    .expect_err("web capabilities are not wired into this build's driver");
    assert!(
        matches!(err, RunRefused::Research(msg) if msg.contains("web capabilities")),
        "{err:?}"
    );

    // An unconfirmed grant: policy refuses (the web grant needs a
    // confirmation, tty or flag).
    let unconfirmed = research_spec(&["harness.task.todo"], &["example.com"], false, None);
    let err = drive_research(
        &state,
        &unconfirmed,
        &research_registry(),
        Vec::new(),
        &ScriptedInput::of(&["go"]),
        Some(&Real),
    )
    .expect_err("an unconfirmed web grant is refused");
    assert!(
        matches!(
            err,
            RunRefused::Session(harness_policy::SessionRefused::Web(_))
        ),
        "{err:?}"
    );

    // An exec section: a research session takes none.
    let mut execd = research_spec(
        &["harness.task.todo"],
        &["example.com"],
        false,
        Some(WebConfirmation::Tty),
    );
    execd.exec = Some(harness_run::ExecSpec::default());
    let err = drive_research(
        &state,
        &execd,
        &research_registry(),
        Vec::new(),
        &ScriptedInput::of(&["go"]),
        Some(&Real),
    )
    .expect_err("a research session takes no exec section");
    assert!(
        matches!(err, RunRefused::Research(msg) if msg.contains("exec")),
        "{err:?}"
    );

    // A pre-submit section: refused.
    let mut pre = research_spec(
        &["harness.task.todo"],
        &["example.com"],
        false,
        Some(WebConfirmation::Tty),
    );
    pre.presubmit = Some(harness_run::PresubmitSpec {
        commands: Vec::new(),
        max_rounds: 1,
    });
    let err = drive_research(
        &state,
        &pre,
        &research_registry(),
        Vec::new(),
        &ScriptedInput::of(&["go"]),
        Some(&Real),
    )
    .expect_err("a research session runs no pre-submit commands");
    assert!(
        matches!(err, RunRefused::Research(msg) if msg.contains("pre-submit")),
        "{err:?}"
    );

    // Protected paths: there is no workspace to protect.
    let mut prot = research_spec(
        &["harness.task.todo"],
        &["example.com"],
        false,
        Some(WebConfirmation::Tty),
    );
    prot.protected = vec!["secrets/**".into()];
    let err = drive_research(
        &state,
        &prot,
        &research_registry(),
        Vec::new(),
        &ScriptedInput::of(&["go"]),
        Some(&Real),
    )
    .expect_err("a research session has no protected paths");
    assert!(
        matches!(err, RunRefused::Research(msg) if msg.contains("protected")),
        "{err:?}"
    );

    // The coding registry: a research session needs the research registry
    // (§2.2: the kind agrees with what was admitted).
    let err = drive_research(
        &state,
        &confirmed,
        &coding_registry(),
        Vec::new(),
        &ScriptedInput::of(&["go"]),
        Some(&Real),
    )
    .expect_err("a research session needs the research registry");
    assert!(
        matches!(err, RunRefused::Research(msg) if msg.contains("registry")),
        "{err:?}"
    );
}

/// A research session resumes without a tree check (P-05 D4 is a coding
/// session's check and there is no workspace to measure): a crash after
/// the first turn's submit result resumes with `workspace: None`, and a
/// caller who passes one is refused.
#[test]
fn resume_of_research_session_skips_tree_check() {
    let state = scratch_alone("resume");
    let spec = research_spec(
        &["harness.task.todo"],
        &["example.com"],
        false,
        Some(WebConfirmation::Tty),
    );
    let first = drive_research(
        &state,
        &spec,
        &research_registry(),
        vec![act("harness.task.submit", r#"{"note":"first"}"#)],
        &ScriptedInput::of(&["research it"]),
        Some(&Real),
    )
    .unwrap();
    // Crash the journal just after the first turn's submit result: the
    // attempt holds a turn in flight (a `UserTurn`, its submit's
    // `ToolFinished`), no `TurnEnded`, no `RunStopped`.
    crash_in(&journal_path(&state, &first.run.run, 1), 1, "TurnEnded");

    // A workspace is refused: a research session takes none.
    let profile = Profile::conservative_default("m");
    let err = resume_session(ResumeSession {
        state_root: &state,
        run: &first.run.run,
        workspace: Some(&state),
        spec: &spec,
        registry: &research_registry(),
        policy: &UserPolicy::default(),
        profile: &profile,
        backend: &ScriptedBackend::new(profile.clone(), Vec::new()),
        probe: &Local,
        env: &FIXED_ENV,
        config: &SessionConfig::defaults(TOKENS),
        input: &ScriptedInput::of(&["more"]),
        approver: None,
        sink: None,
        confinement: Some(&Real),
    })
    .expect_err("a research session takes no workspace");
    assert!(
        matches!(err, RunRefused::Research(msg) if msg.contains("workspace")),
        "{err:?}"
    );

    // Without one, the resume continues the session: the recorded turn's
    // submit is re-fed (the catch-up), the next message opens turn 2, its
    // submit ends it, and the input's end ends the session.
    let resumed = resume_session(ResumeSession {
        state_root: &state,
        run: &first.run.run,
        workspace: None,
        spec: &spec,
        registry: &research_registry(),
        policy: &UserPolicy::default(),
        profile: &profile,
        backend: &ScriptedBackend::new(
            profile.clone(),
            vec![Ok(act("harness.task.submit", r#"{"note":"second"}"#))],
        ),
        probe: &Local,
        env: &FIXED_ENV,
        config: &SessionConfig::defaults(TOKENS),
        input: &ScriptedInput::of(&["and more"]),
        approver: None,
        sink: None,
        confinement: Some(&Real),
    })
    .unwrap();
    assert_eq!(resumed.run.attempt, 2, "the resume opened a new attempt");
    assert_eq!(resumed.run.cause, StopCause::SessionEnded);
    assert_eq!(resumed.turns, 2);
    assert_eq!(resumed.run.outcome, NOTHING_CHECKED);

    // The resumed journal audits clean.
    let a = audit_research(
        &state,
        &first.run.run,
        &spec,
        resumed.run.chain_head,
        Some(2),
    );
    assert_eq!(a.divergence, None, "{a:?}");
    assert!(a.stop_recomputed);
    assert!(a.anchored);
}

/// The turn limits a research session validates are the session's.
#[test]
fn research_session_turn_limits_checked() {
    let state = scratch_alone("limits");
    let spec = research_spec(&[], &[], false, Some(WebConfirmation::Tty));
    let mut cfg = SessionConfig::defaults(TOKENS);
    cfg.turn = TurnLimits {
        steps: 0,
        format_errors: 3,
    };
    let err = run_research(harness_run::ResearchRun {
        state_root: &state,
        spec: &spec,
        registry: &research_registry(),
        policy: &UserPolicy::default(),
        profile: &Profile::conservative_default("m"),
        backend: &ScriptedBackend::new(Profile::conservative_default("m"), Vec::new()),
        probe: &Local,
        env: &FIXED_ENV,
        config: &cfg,
        approver: None,
        confinement: Some(&Real),
        input: &ScriptedInput::of(&["go"]),
        sink: None,
    })
    .expect_err("a zero-step turn limit is out of range");
    assert!(matches!(err, RunRefused::TurnLimits(_)), "{err:?}");
}
