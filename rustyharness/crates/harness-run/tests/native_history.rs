//! The native protocol's tool history (design row H1h, devkit finding F1):
//! whole runs through the public `run`, `audit` and `resume` with a
//! native-protocol profile, a real state root and workspace, the real
//! journal and the real read tools.
//!
//! The model here is a mimic: it answers with its next planned call in the
//! form its context shows past calls in. Shown them as native tool calls,
//! it calls natively; shown them as text (`[tool call] name {args}`, the
//! form the native protocol used before H1h), it writes its call as text,
//! as glm-5.3-flash did in every multi-step run of the dev suite.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::{Cell, RefCell};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use gate_outcome::{GateOutcome, IndeterminateKind};
use harness_core::environment::{EnvSample, Unmeasured};
use harness_core::{MeterLimits, RunId, Source, StopCause, Untrusted};
use harness_journal::canon::{RecordFields, GENESIS};
use harness_journal::{layout, EventKind, JournalReader, Record};
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, SemVer, ValidationContext};
use harness_model::profile::{Profile, Protocol};
use harness_model::protocol::{parse_reply, FormatError};
use harness_model::scripted::{text_reply, tool_reply, ScriptedBackend};
use harness_model::wire::render_request;
use harness_model::{
    Completion, EndpointClass, HarnessText, Message, ModelBackend, ModelError, ModelIdentity,
    ModelRequest, RawToolCall, RenderNonce, ServerClaims, TaskText, ToolSpec,
};
use harness_policy::locality::{FsQuery, LocalityProbe};
use harness_policy::UserPolicy;
use harness_run::{
    audit, resume, run, Audit, AuditReport, Resume, Run, RunConfig, RunRefused, RunReport, TaskSpec,
};
use serde_json::Value;

const FIXED_ENV: EnvSample = EnvSample::unmeasured(Unmeasured::NoSafeApi);

struct Local;
impl LocalityProbe for Local {
    fn query(&self, _path: &str) -> FsQuery {
        FsQuery::MacOs {
            mnt_local: true,
            fs_type_name: "apfs".into(),
        }
    }
}

fn scratch(name: &str) -> (PathBuf, PathBuf) {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("native-{name}"));
    let _ = fs::remove_dir_all(&base);
    let (state, ws) = (base.join("state"), base.join("ws"));
    fs::create_dir_all(&state).unwrap();
    fs::create_dir_all(&ws).unwrap();
    fs::write(ws.join("a.txt"), "alpha\n").unwrap();
    fs::write(ws.join("b.txt"), "beta\n").unwrap();
    (state, ws)
}

fn registry() -> Registry {
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

/// A native-protocol profile shaped like the devkit's glm-5.3-flash one.
fn native() -> Profile {
    Profile::parse(
        br#"{"profile_version":1,"id":"native-test","model":"m","context_window":32768,
        "fill_ratio":0.6,"protocol":"native","tool_choice_required_ok":false,"grammar":"none",
        "max_active_tools":6,"edit_format":"replace","recent_turns":5,
        "sampling":{"temperature":0.2,"top_p":0.95,"seed":7,"max_tokens":1024}}"#,
    )
    .unwrap()
}

const TASK: &str = "What do a.txt and b.txt say? Submit both words.";

fn spec(task: &str) -> TaskSpec {
    TaskSpec {
        task: TaskText::new(task.into()),
        grants: vec!["harness.fs.read".into(), "harness.fs.list".into()],
        workspace_public: false,
        exec: None,
        presubmit: None,
        protected: Vec::new(),
    }
}

fn limits() -> MeterLimits {
    RunConfig::defaults(1_000_000).limits
}

fn go(state: &Path, ws: &Path, backend: &dyn ModelBackend) -> RunReport {
    run(Run {
        state_root: state,
        workspace: ws,
        spec: &spec(TASK),
        registry: &registry(),
        policy: &UserPolicy::default(),
        profile: &native(),
        backend,
        probe: &Local,
        env: &FIXED_ENV,
        config: &RunConfig::defaults(1_000_000),
        approver: None,
        confinement: None,
    })
    .unwrap()
}

fn audit_of(state: &Path, run: &RunId, attempt: Option<u32>) -> AuditReport {
    audit(Audit {
        state_root: state,
        run,
        attempt,
        anchor: None,
        spec: &spec(TASK),
        registry: &registry(),
        policy: &UserPolicy::default(),
        profile: &native(),
        limits: &limits(),
    })
    .unwrap()
}

fn records(r: &RunReport, attempt: u32) -> Vec<Record> {
    JournalReader::open(&layout::attempt_dir(&r.run_dir, attempt))
        .unwrap()
        .records
}

fn journal_path(r: &RunReport, attempt: u32) -> PathBuf {
    layout::attempt_dir(&r.run_dir, attempt).join(layout::JOURNAL_FILE)
}

fn format_errors(recs: &[Record]) -> Vec<String> {
    recs.iter()
        .filter(|r| r.kind == EventKind::FormatError)
        .map(|r| r.body["error"].as_str().unwrap().to_owned())
        .collect()
}

const NOTHING_CHECKED: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::NothingChecked,
};
const UNREADABLE: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::UnreadableEvidence,
};

// ---- the mimic --------------------------------------------------------------------

/// The plan every mimic follows: list, read both files, submit.
fn plan() -> Vec<(&'static str, &'static str)> {
    vec![
        ("harness_fs_list", r#"{"path":"."}"#),
        ("harness_fs_read", r#"{"path":"a.txt"}"#),
        ("harness_fs_read", r#"{"path":"b.txt"}"#),
        ("harness_task_submit", r#"{"note":"alpha beta"}"#),
    ]
}

/// A model that answers with its next planned call in the form its
/// context shows its past calls in (see the module docs). It records every
/// request as rendered for the wire. With `parallel_at: Some(n)`, its n-th
/// reply (1-based) makes two calls at once, as glm-5.3-flash does by
/// default; it then makes the first of them again alone.
struct Mimic {
    profile: Profile,
    plan: Vec<(&'static str, &'static str)>,
    next: Cell<usize>,
    parallel_at: Option<usize>,
    requests: RefCell<Vec<Value>>,
}

impl Mimic {
    fn new(parallel_at: Option<usize>) -> Self {
        Self {
            profile: native(),
            plan: plan(),
            next: Cell::new(0),
            parallel_at,
            requests: RefCell::new(Vec::new()),
        }
    }
}

/// Whether a rendered request shows a past call written out as text.
fn shows_calls_as_text(request: &Value) -> bool {
    request["messages"].as_array().unwrap().iter().any(|m| {
        m["role"] == "assistant"
            && m["content"]
                .as_str()
                .is_some_and(|c| c.contains("[tool call]"))
    })
}

fn call(name: &str, arguments: &str) -> Untrusted<RawToolCall> {
    Untrusted::new(
        RawToolCall {
            name: name.to_owned(),
            arguments: arguments.to_owned(),
        },
        Source::Model,
    )
}

impl ModelBackend for Mimic {
    fn identity(&self) -> ModelIdentity {
        ModelIdentity {
            endpoint: EndpointClass::Scripted,
            profile_id: self.profile.id().to_owned(),
            profile_sha256: self.profile.sha256().map(|d| d.to_string()),
            profile_validated: false,
            profile_stamp_sha256: None,
            api_key_handle: None,
            claimed: ServerClaims::default(),
        }
    }

    fn complete(&self, req: &ModelRequest, _deadline: Instant) -> Result<Completion, ModelError> {
        let v =
            render_request(req, &self.profile).map_err(|e| ModelError::Unusable(e.to_string()))?;
        let as_text = shows_calls_as_text(&v);
        let n = {
            let mut r = self.requests.borrow_mut();
            r.push(v);
            r.len()
        };
        let i = self.next.get();
        let Some(&(name, args)) = self.plan.get(i) else {
            return Err(ModelError::Unusable("the plan is done".into()));
        };
        if as_text {
            // The form its history shows: the call written as text, which
            // the native parser never reads (a format error, no_action).
            return Ok(text_reply(&format!("[tool call] {name} {args}")));
        }
        if self.parallel_at == Some(n) {
            let (next_name, next_args) = self.plan[i + 1];
            let mut c = tool_reply(name, args);
            c.tool_calls.push(call(next_name, next_args));
            return Ok(c);
        }
        self.next.set(i + 1);
        let mut c = tool_reply(name, args);
        c.content = Untrusted::new(format!("Step {}.", i + 1), Source::Model);
        Ok(c)
    }
}

/// Every assistant `tool_calls` entry of every request is answered by the
/// very next message, a `tool` message with its id; every `tool` message
/// answers the call just before it; one call per assistant message.
fn assert_valid_tool_sequence(request: &Value) {
    let m = request["messages"].as_array().unwrap();
    for (i, msg) in m.iter().enumerate() {
        if let Some(calls) = msg.get("tool_calls") {
            let calls = calls.as_array().unwrap();
            assert_eq!(calls.len(), 1, "one call per assistant message: {msg}");
            let next = m.get(i + 1).expect("a call is answered");
            assert_eq!(next["role"], "tool", "{next}");
            assert_eq!(next["tool_call_id"], calls[0]["id"]);
        }
        if msg["role"] == "tool" {
            let prev = &m[i - 1];
            assert_eq!(prev["tool_calls"][0]["id"], msg["tool_call_id"]);
        }
    }
}

// ---- the loop ----------------------------------------------------------------------

/// F1 end to end: a model that copies the form of its history. Shown its
/// past calls as native tool calls (H1h), it calls natively, finds both
/// words and submits in four steps with no format error. Before H1h the
/// native protocol showed them as text, and this model wrote every call
/// after the first as text until three format errors stopped the run
/// (the break-it record of design row H1h).
#[test]
fn f1_a_model_that_copies_its_history_calls_natively_and_submits() {
    let (state, ws) = scratch("mimic");
    let mimic = Mimic::new(None);
    let r = go(&state, &ws, &mimic);
    let recs = records(&r, 1);
    assert_eq!(format_errors(&recs), Vec::<String>::new());
    assert_eq!(r.cause, StopCause::Submitted);
    assert_eq!(r.steps, 4);
    assert_eq!(r.outcome, NOTHING_CHECKED);
    let note = recs
        .iter()
        .find(|x| x.kind == EventKind::SubmitRequested)
        .unwrap();
    assert_eq!(note.body["note"]["inline"], "alpha beta");

    let requests = mimic.requests.borrow();
    assert_eq!(requests.len(), 4);
    for q in requests.iter() {
        assert!(!shows_calls_as_text(q));
        assert_valid_tool_sequence(q);
    }
    // The last request shows the three calls and their results natively,
    // with harness-made ids, the canonical arguments and the reply text.
    let last = requests[3]["messages"].as_array().unwrap();
    let calls: Vec<&Value> = last
        .iter()
        .filter(|m| m.get("tool_calls").is_some())
        .collect();
    assert_eq!(calls.len(), 3);
    assert_eq!(
        calls[1],
        &serde_json::json!({"role": "assistant", "content": "Step 2.", "tool_calls": [{
            "id": "call00002", "type": "function",
            "function": {"name": "harness_fs_read", "arguments": "{\"path\":\"a.txt\"}"}}]})
    );
    let results: Vec<&str> = last
        .iter()
        .filter(|m| m["role"] == "tool")
        .map(|m| m["content"].as_str().unwrap())
        .collect();
    assert_eq!(results.len(), 3);
    assert!(results[1].contains("result of harness_fs_read:\n") && results[1].contains("alpha"));
    assert!(results[1].starts_with("<<untrusted "));
    assert!(results[2].contains("beta"));
    // And the run audits clean: every context recomputed and matched.
    let a = audit_of(&state, &r.run, None);
    assert_eq!(a.divergence, None, "{a:?}");
    assert_eq!(a.outcome, NOTHING_CHECKED);
    assert!(a.stop_recomputed);
    assert_eq!(a.matched, recs.len() - 1);
}

/// glm-5.3-flash's other native habit: two calls in one reply. The reply is
/// a `several_actions` format error; neither call runs, the next request
/// shows no assistant message for it (so no `tool_calls` without their
/// `tool` messages) and ends with the native repair text; the model then
/// calls alone, and the run submits and audits clean.
#[test]
fn a_rejected_parallel_reply_leaves_no_unanswered_call_and_is_repaired_natively() {
    let (state, ws) = scratch("parallel");
    let mimic = Mimic::new(Some(2));
    let r = go(&state, &ws, &mimic);
    let recs = records(&r, 1);
    assert_eq!(format_errors(&recs), vec!["several_actions".to_owned()]);
    assert_eq!(r.cause, StopCause::Submitted);
    assert_eq!(r.steps, 5);
    let started: Vec<&str> = recs
        .iter()
        .filter(|x| x.kind == EventKind::ToolStarted)
        .map(|x| x.body["capability"].as_str().unwrap())
        .collect();
    assert_eq!(
        started,
        [
            "harness.fs.list",
            "harness.fs.read",
            "harness.fs.read",
            "harness.task.submit"
        ],
        "neither parallel call ran"
    );

    let requests = mimic.requests.borrow();
    for q in requests.iter() {
        assert_valid_tool_sequence(q);
    }
    let after = requests[2]["messages"].as_array().unwrap();
    let last = after.last().unwrap();
    assert_eq!(last["role"], "user");
    let text = last["content"].as_str().unwrap();
    assert!(text.starts_with("[harness] Format error:"), "{text}");
    assert!(text.contains("more than one tool call"), "{text}");
    assert!(text.contains("exactly one tool call per reply"), "{text}");
    // Step 2's reply is not shown: the assistant messages are step 1's call
    // only.
    let calls: Vec<&Value> = after.iter().filter(|m| m["role"] == "assistant").collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["tool_calls"][0]["id"], "call00001");

    let a = audit_of(&state, &r.run, None);
    assert_eq!(a.divergence, None, "{a:?}");
    assert_eq!(a.outcome, NOTHING_CHECKED);
}

/// A scripted model that records every request as rendered for the wire.
struct Recorder {
    profile: Profile,
    inner: ScriptedBackend,
    requests: RefCell<Vec<Value>>,
}

impl Recorder {
    fn new(replies: Vec<Result<Completion, ModelError>>) -> Self {
        Self {
            profile: native(),
            inner: ScriptedBackend::new(native(), replies),
            requests: RefCell::new(Vec::new()),
        }
    }
}

impl ModelBackend for Recorder {
    fn identity(&self) -> ModelIdentity {
        self.inner.identity()
    }

    fn complete(&self, req: &ModelRequest, deadline: Instant) -> Result<Completion, ModelError> {
        let v =
            render_request(req, &self.profile).map_err(|e| ModelError::Unusable(e.to_string()))?;
        self.requests.borrow_mut().push(v);
        self.inner.complete(req, deadline)
    }
}

/// A native reply that writes its call as text (`no_action`) is withheld
/// too: its text is in the journal, in no later request, and the repair
/// text says to call through the function-calling interface.
#[test]
fn a_call_written_as_text_is_withheld_and_repaired_in_native_terms() {
    let (state, ws) = scratch("as-text");
    let backend = Recorder::new(vec![
        Ok(tool_reply("harness_fs_read", r#"{"path":"a.txt"}"#)),
        Ok(text_reply(
            r#"[tool call] harness_fs_read {"path":"b.txt"} WITHHELD"#,
        )),
        Ok(tool_reply("harness_fs_read", r#"{"path":"b.txt"}"#)),
        Ok(tool_reply(
            "harness_task_submit",
            r#"{"note":"alpha beta"}"#,
        )),
    ]);
    let r = go(&state, &ws, &backend);
    let recs = records(&r, 1);
    assert_eq!(format_errors(&recs), vec!["no_action".to_owned()]);
    assert_eq!(r.cause, StopCause::Submitted);
    // The withheld text is journaled (its reply record)...
    let replied = recs
        .iter()
        .filter(|x| x.kind == EventKind::ModelReplied)
        .nth(1)
        .unwrap();
    assert!(replied.body["content"]["inline"]
        .as_str()
        .unwrap()
        .contains("WITHHELD"));
    // ...and in no later request, which shows the native repair instead.
    let requests = backend.requests.borrow();
    assert_eq!(requests.len(), 4);
    for q in &requests[2..] {
        assert!(!q.to_string().contains("WITHHELD"));
        assert!(!shows_calls_as_text(q));
        assert_valid_tool_sequence(q);
    }
    let step3 = requests[2]["messages"].as_array().unwrap();
    let repair = step3.last().unwrap()["content"].as_str().unwrap();
    assert!(
        repair.starts_with("[harness] Format error: your last reply had no tool call"),
        "{repair}"
    );
    assert!(repair.contains("Call exactly one tool through the function-calling interface"));
    assert!(repair.contains("do not write the call as text"));
    let a = audit_of(&state, &r.run, None);
    assert_eq!(a.divergence, None, "{a:?}");
}

/// The mimic's control: shown a past call written as text, as the native
/// protocol rendered it before H1h (an assistant message
/// `[tool call] name {args}` and the result in the user role), it writes
/// its next call as text too, which the native parser does not read.
#[test]
fn control_shown_a_past_call_as_text_the_mimic_writes_as_text() {
    let m = Mimic::new(None);
    let tools: Vec<ToolSpec> = ["harness.fs.list", "harness.fs.read"]
        .iter()
        .map(|id| ToolSpec {
            id: (*id).to_owned(),
            description: HarnessText::from_static("a tool"),
            parameters: serde_json::json!({"type": "object"}),
        })
        .collect();
    let req = ModelRequest {
        messages: vec![
            Message::System(HarnessText::from_static("rules")),
            Message::Task(TaskText::new(TASK.into())),
            Message::Assistant(Untrusted::new(
                "\n[tool call] harness_fs_list {\"path\":\".\"}".into(),
                Source::Model,
            )),
            Message::Observation {
                call: "harness.fs.list".into(),
                body: Untrusted::new("f a.txt\nf b.txt\n".into(), Source::Model),
                nonce: RenderNonce::new("00112233445566778899aabbccddeeff").unwrap(),
            },
        ],
        tools: tools.clone(),
    };
    let c = m.complete(&req, Instant::now()).unwrap();
    assert!(c.tool_calls.is_empty());
    assert_eq!(
        parse_reply(&c, Protocol::Native, &tools).unwrap_err(),
        FormatError::NoAction
    );
    assert_eq!(m.next.get(), 0, "a reply written as text is not progress");
}

// ---- audit and resume ----------------------------------------------------------------

/// Resume of a native run: the catch-up re-renders every recorded native
/// request (tool calls, tool messages and ids included) to its recorded
/// digest, the step after the last completed one runs live, and the
/// resumed attempt audits clean.
#[test]
fn a_native_run_resumes_and_its_catch_up_matches_every_recorded_request() {
    let (state, ws) = scratch("resume");
    let r = go(&state, &ws, &Mimic::new(Some(2)));
    assert_eq!(r.steps, 5);
    // Crash in step 5 (the submit): steps 1-4 survive. Step 4's call has a
    // durable result, so it is complete (H2b: a completed step is re-fed,
    // never run again): resume replays steps 1-4 (a call and its result,
    // the parallel format error, two calls and their results) and runs
    // step 5 live.
    crash_after(&journal_path(&r, 1), 5);
    let profile = native();
    let backend = ScriptedBackend::new(
        profile.clone(),
        vec![Ok(tool_reply(
            "harness_task_submit",
            r#"{"note":"alpha beta"}"#,
        ))],
    );
    let res = resume(Resume {
        state_root: &state,
        run: &r.run,
        workspace: &ws,
        spec: &spec(TASK),
        registry: &registry(),
        policy: &UserPolicy::default(),
        profile: &profile,
        backend: &backend,
        probe: &Local,
        env: &FIXED_ENV,
        config: &RunConfig::defaults(1_000_000),
        approver: None,
        confinement: None,
    })
    .unwrap();
    assert_eq!(res.attempt, 2);
    assert_eq!(res.cause, StopCause::Submitted);
    assert_eq!(res.steps, 5, "steps 1-4 replayed, 5 live");
    let old = records(&r, 1);
    let new = records(&res, 2);
    let requested = |v: &[Record]| -> Vec<Value> {
        v.iter()
            .filter(|x| x.kind == EventKind::ModelRequested && x.step <= 4)
            .map(|x| x.body["request"].clone())
            .collect()
    };
    assert_eq!(
        requested(&new),
        requested(&old),
        "the catch-up rendered the recorded requests"
    );
    assert_eq!(res.outcome, NOTHING_CHECKED, "the catch-up did not diverge");
    // The live step's request carried the replayed history natively.
    assert_eq!(backend.seen().len(), 1);
    let a = audit_of(&state, &r.run, Some(2));
    assert_eq!(a.divergence, None, "{a:?}");
    assert_eq!(a.outcome, NOTHING_CHECKED);
}

/// The native context digest covers a past call's arguments and its reply
/// text: an edit to either, made consistently to the reply, the parsed
/// action and the intent's call digest and re-chained, matches its own
/// step (the reply is re-fed and the rest recomputed from it) and diverges
/// at the first context built from it: the next step's `ContextBuilt`,
/// before the request that renders it.
#[test]
fn an_edited_native_call_diverges_at_the_next_context_built() {
    for field in ["arguments", "content"] {
        let (state, ws) = scratch(&format!("edit-{field}"));
        let r = go(&state, &ws, &Mimic::new(None));
        let path = journal_path(&r, 1);
        let mut recs = lines(&path);
        let edit = |blob: &mut Value, from: &str, to: &str| {
            let s = blob["inline"].as_str().unwrap().replace(from, to);
            blob["inline"] = Value::from(s.clone());
            blob["sha256"] = Value::from(harness_core::sha256(s.as_bytes()).to_string());
            blob["len"] = Value::from(s.len());
        };
        for v in recs.iter_mut().filter(|v| v["step"] == 2) {
            match (v["kind"].as_str().unwrap(), field) {
                ("ModelReplied", "arguments") => edit(
                    &mut v["body"]["tool_calls"][0]["arguments"],
                    "a.txt",
                    "b.txt",
                ),
                ("ActionParsed", "arguments") => edit(&mut v["body"]["args"], "a.txt", "b.txt"),
                // The intent's call digest, recomputed as the loop does.
                ("ToolStarted", "arguments") => {
                    let call = serde_json::json!({
                        "args": {"path": "b.txt"}, "capability": "harness.fs.read"
                    });
                    v["body"]["call"] =
                        Value::from(harness_core::sha256(call.to_string().as_bytes()).to_string());
                }
                ("ModelReplied", "content") => edit(&mut v["body"]["content"], "Step", "Stop"),
                ("ActionParsed", "content") => edit(&mut v["body"]["reasoning"], "Step", "Stop"),
                _ => {}
            }
        }
        write_chained(&path, &recs);
        assert!(JournalReader::open(&layout::attempt_dir(&r.run_dir, 1)).is_ok());
        let a = audit_of(&state, &r.run, Some(1));
        assert_eq!(a.outcome, UNREADABLE, "{field}");
        let d = a.divergence.unwrap();
        assert_eq!(
            (d.step, recs[d.seq as usize]["kind"].clone()),
            (3, Value::from("ContextBuilt")),
            "{field}: {d:?}"
        );
    }
}

/// The compatibility breaks of H1h and H1i, named (like H1f-3's): a
/// journal whose header records no context format (every journal written
/// before H1h) or another one (rh-context/2: H1h, before H1i's
/// per-observation nonces and append-mostly context; rh-context/3: H1i,
/// before H2e's budget notices and read-window caps; rh-context/4: an
/// H2e commit before its repair messages named the fault) cannot be recomputed
/// by this build, so audit and resume refuse it at the header, saying why,
/// instead of diverging at its first context or request. Text-protocol
/// journals are refused the same way.
#[test]
fn a_journal_from_before_h1i_is_refused_by_name_by_audit_and_resume() {
    for (case, text_protocol) in [("native", false), ("text", true)] {
        for recorded in [
            None,
            Some("rh-context/1"),
            Some("rh-context/2"),
            Some("rh-context/3"),
            Some("rh-context/4"),
        ] {
            let tag = recorded.unwrap_or("none").replace('/', "-");
            let (state, ws) = scratch(&format!("old-{case}-{tag}"));
            let r = if text_protocol {
                let p = Profile::conservative_default("m");
                let b = ScriptedBackend::new(
                    p.clone(),
                    vec![Ok(text_reply(
                        r#"<action>{"tool":"harness.task.submit","args":{"note":"x"}}</action>"#,
                    ))],
                );
                run(Run {
                    state_root: &state,
                    workspace: &ws,
                    spec: &spec(TASK),
                    registry: &registry(),
                    policy: &UserPolicy::default(),
                    profile: &p,
                    backend: &b,
                    probe: &Local,
                    env: &FIXED_ENV,
                    config: &RunConfig::defaults(1_000_000),
                    approver: None,
                    confinement: None,
                })
                .unwrap()
            } else {
                go(&state, &ws, &Mimic::new(None))
            };
            assert_eq!(
                records(&r, 1)[0].body["context_format"],
                "rh-context/5",
                "this build records its format"
            );
            let path = journal_path(&r, 1);
            let mut recs = lines(&path);
            let h = recs[0]["body"].as_object_mut().unwrap();
            match recorded {
                None => {
                    h.remove("context_format");
                }
                Some(f) => {
                    h.insert("context_format".into(), Value::from(f));
                }
            }
            write_chained(&path, &recs);
            let profile = if text_protocol {
                Profile::conservative_default("m")
            } else {
                native()
            };
            let a = audit(Audit {
                state_root: &state,
                run: &r.run,
                attempt: None,
                anchor: None,
                spec: &spec(TASK),
                registry: &registry(),
                policy: &UserPolicy::default(),
                profile: &profile,
                limits: &limits(),
            })
            .unwrap();
            assert_eq!(a.outcome, UNREADABLE, "{case} {recorded:?}");
            let d = a.divergence.unwrap();
            assert_eq!(d.seq, 0, "at the header");
            assert!(d.why.contains("another harness build"), "{}", d.why);
            assert!(d.why.contains("context format"), "{}", d.why);
            assert!(a.replay_dir.is_none(), "nothing was replayed");

            // Resume refuses it the same way (the attempt cut before its
            // stop, so it is resumable but for the format).
            crash_after(&path, 2);
            let b = ScriptedBackend::new(profile.clone(), vec![]);
            let e = resume(Resume {
                state_root: &state,
                run: &r.run,
                workspace: &ws,
                spec: &spec(TASK),
                registry: &registry(),
                policy: &UserPolicy::default(),
                profile: &profile,
                backend: &b,
                probe: &Local,
                env: &FIXED_ENV,
                config: &RunConfig::defaults(1_000_000),
                approver: None,
                confinement: None,
            })
            .unwrap_err();
            assert!(
                matches!(e, RunRefused::NotResumable(ref w) if w.contains("context format")),
                "{case} {recorded:?}: {e:?}"
            );
            assert!(!layout::attempt_dir(&r.run_dir, 2).exists());
        }
    }
}

// ---- journal editing (a forger who re-chains) -------------------------------------------

fn lines(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// Write `records` as a journal, every hash recomputed (the records keep
/// their seqs: the edits here never add or remove one).
fn write_chained(path: &Path, records: &[Value]) {
    let mut prev = GENESIS;
    let mut out = Vec::new();
    for v in records {
        let f = RecordFields {
            seq: v["seq"].as_u64().unwrap(),
            prev,
            t_mono_ms: v["t_mono_ms"].as_u64().unwrap(),
            t_wall: v["t_wall"].as_str().unwrap().to_owned(),
            run: RunId::parse(v["run"].as_str().unwrap()).unwrap(),
            attempt: u32::try_from(v["attempt"].as_u64().unwrap()).unwrap(),
            step: v["step"].as_u64().unwrap(),
            kind: EventKind::parse(v["kind"].as_str().unwrap()).unwrap(),
            body: v["body"].as_object().unwrap().clone(),
        };
        let (bytes, hash) = f.encode();
        out.extend(bytes);
        out.push(b'\n');
        prev = hash;
    }
    fs::write(path, out).unwrap();
}

/// Cut a journal back to its records of steps < `keep_below` (a crash:
/// whole lines survive, `RunStopped` is gone).
fn crash_after(path: &Path, keep_below: u64) {
    let text = fs::read_to_string(path).unwrap();
    let mut out = String::new();
    for line in text.lines() {
        let v: Value = serde_json::from_str(line).unwrap();
        if v["step"].as_u64().unwrap() < keep_below && v["kind"] != "RunStopped" {
            out.push_str(line);
            out.push('\n');
        }
    }
    fs::write(path, out).unwrap();
}
