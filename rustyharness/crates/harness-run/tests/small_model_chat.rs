//! Small-model chat robustness (slice P-53): whole runs through the
//! public `run` and `audit` with a native-protocol profile, a real state
//! root and workspace, the real journal and the real read tools.
//!
//! The model here is the native_history mimic again: it answers with its
//! next planned call. Two small-model habits are under test: two calls in
//! one reply (refused unless the profile opts in, dropped-but-first-ran
//! when it does) and the terse tool docs (a shorter declaration table,
//! stamped into the journal header).

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
use harness_journal::{layout, EventKind, JournalReader, Record};
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, SemVer, ValidationContext};
use harness_model::profile::Profile;
use harness_model::scripted::tool_reply;
use harness_model::wire::render_request;
use harness_model::{
    Completion, EndpointClass, ModelBackend, ModelError, ModelIdentity, ModelRequest, RawToolCall,
    ServerClaims, TaskText,
};
use harness_policy::locality::{FsQuery, LocalityProbe};
use harness_policy::UserPolicy;
use harness_run::{
    audit, run, Audit, AuditReport, Run, RunConfig, RunRefused, RunReport, TaskSpec,
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
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("small-{name}"));
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
        br#"{"profile_version":1,"id":"small-test","model":"m","context_window":32768,
        "fill_ratio":0.6,"protocol":"native","tool_choice_required_ok":false,"grammar":"none",
        "max_active_tools":6,"edit_format":"replace","recent_turns":5,
        "sampling":{"temperature":0.2,"top_p":0.95,"seed":7,"max_tokens":1024}}"#,
    )
    .unwrap()
}

/// The same profile with terse tool docs (P-53).
fn terse() -> Profile {
    Profile::parse(
        br#"{"profile_version":1,"id":"small-test","model":"m","context_window":32768,
        "fill_ratio":0.6,"protocol":"native","tool_choice_required_ok":false,"grammar":"none",
        "max_active_tools":6,"edit_format":"replace","recent_turns":5,"tool_docs":"terse",
        "sampling":{"temperature":0.2,"top_p":0.95,"seed":7,"max_tokens":1024}}"#,
    )
    .unwrap()
}

/// The same profile with the parallel-calls opt-in (P-53).
fn parallel() -> Profile {
    Profile::parse(
        br#"{"profile_version":1,"id":"small-test","model":"m","context_window":32768,
        "fill_ratio":0.6,"protocol":"native","tool_choice_required_ok":false,"grammar":"none",
        "max_active_tools":6,"edit_format":"replace","recent_turns":5,"parallel_tool_calls":true,
        "sampling":{"temperature":0.2,"top_p":0.95,"seed":7,"max_tokens":1024}}"#,
    )
    .unwrap()
}

/// The same profile with a different tool cap.
fn with_max_active_tools(max: u32) -> Profile {
    Profile::parse(
        format!(
            r#"{{"profile_version":1,"id":"small-test","model":"m","context_window":32768,
        "fill_ratio":0.6,"protocol":"native","tool_choice_required_ok":false,"grammar":"none",
        "max_active_tools":{max},"edit_format":"replace","recent_turns":5,
        "sampling":{{"temperature":0.2,"top_p":0.95,"seed":7,"max_tokens":1024}}}}"#
        )
        .as_bytes(),
    )
    .unwrap()
}

const TASK: &str = "What do a.txt and b.txt say? Submit both words.";

fn spec(grants: &[&str]) -> TaskSpec {
    TaskSpec {
        task: TaskText::new(TASK.into()),
        grants: grants.iter().map(|g| (*g).to_owned()).collect(),
        workspace_public: false,
        ports: Vec::new(),
        lan_ports: Vec::new(),
        exec: None,
        presubmit: None,
        post_edit: None,
        protected: Vec::new(),
        kind: harness_run::SessionKind::Coding,
    }
}

fn limits() -> MeterLimits {
    RunConfig::defaults(1_000_000).limits
}

fn go(state: &Path, ws: &Path, profile: &Profile, backend: &dyn ModelBackend) -> RunReport {
    run(Run {
        state_root: state,
        workspace: ws,
        spec: &spec(READ_GRANTS),
        registry: &registry(),
        policy: &UserPolicy::default(),
        profile,
        backend,
        probe: &Local,
        env: &FIXED_ENV,
        config: &RunConfig::defaults(1_000_000),
        approver: None,
        confinement: None,
    })
    .unwrap()
}

fn audit_of(state: &Path, run: &RunId, profile: &Profile) -> AuditReport {
    audit(Audit {
        state_root: state,
        run,
        attempt: None,
        anchor: None,
        spec: &spec(READ_GRANTS),
        registry: &registry(),
        policy: &UserPolicy::default(),
        profile,
        limits: &limits(),
    })
    .unwrap()
}

fn records(r: &RunReport, attempt: u32) -> Vec<Record> {
    JournalReader::open(&layout::attempt_dir(&r.run_dir, attempt))
        .unwrap()
        .records
}

fn format_errors(recs: &[Record]) -> Vec<String> {
    recs.iter()
        .filter(|r| r.kind == EventKind::FormatError)
        .map(|r| r.body["error"].as_str().unwrap().to_owned())
        .collect()
}

fn started(recs: &[Record]) -> Vec<String> {
    recs.iter()
        .filter(|r| r.kind == EventKind::ToolStarted)
        .map(|r| r.body["capability"].as_str().unwrap().to_owned())
        .collect()
}

const NOTHING_CHECKED: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::NothingChecked,
};

/// The grants every run here carries: the five read-only fs tools. With
/// the always-granted submit sentinel that is six active tools, exactly
/// the dev profile's cap.
const READ_GRANTS: &[&str] = &[
    "harness.fs.read",
    "harness.fs.list",
    "harness.fs.glob",
    "harness.fs.outline",
    "harness.fs.search",
];

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

/// A model that answers with its next planned call, rendered for the wire
/// under the profile it was given (it records every request). With
/// `parallel_at: Some(n)`, its n-th reply (1-based) makes two calls at
/// once, as glm-5.3-flash does by default; it then makes the first of
/// them again alone.
struct Mimic {
    profile: Profile,
    plan: Vec<(&'static str, &'static str)>,
    next: Cell<usize>,
    parallel_at: Option<usize>,
    requests: RefCell<Vec<Value>>,
}

impl Mimic {
    fn new(parallel_at: Option<usize>) -> Self {
        Self::with(native(), plan(), parallel_at)
    }

    fn with(
        profile: Profile,
        plan: Vec<(&'static str, &'static str)>,
        parallel_at: Option<usize>,
    ) -> Self {
        Self {
            profile,
            plan,
            next: Cell::new(0),
            parallel_at,
            requests: RefCell::new(Vec::new()),
        }
    }
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
        let n = {
            let mut r = self.requests.borrow_mut();
            r.push(v);
            r.len()
        };
        let i = self.next.get();
        let Some(&(name, args)) = self.plan.get(i) else {
            return Err(ModelError::Unusable("the plan is done".into()));
        };
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
/// very next message, a `tool` message with its id; one call per
/// assistant message.
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

/// P-53, refusal side: without the profile opt-in, a second tool call in
/// one reply is the `several_actions` format error. Neither call runs, the
/// next request ends with the repair text, the model then calls alone,
/// and the run submits and audits clean. The header carries no
/// `tool_docs` field (full docs are the default).
#[test]
fn second_tool_call_in_a_turn_rejected_when_not_opted_in() {
    let (state, ws) = scratch("not-opted-in");
    let mimic = Mimic::new(Some(2));
    let r = go(&state, &ws, &native(), &mimic);
    let recs = records(&r, 1);
    assert_eq!(format_errors(&recs), vec!["several_actions".to_owned()]);
    assert_eq!(r.cause, StopCause::Submitted);
    assert_eq!(r.steps, 5);
    assert_eq!(
        started(&recs),
        [
            "harness.fs.list",
            "harness.fs.read",
            "harness.fs.read",
            "harness.task.submit"
        ],
        "neither parallel call ran"
    );
    assert_eq!(recs[0].body.get("tool_docs"), None, "full docs by default");

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

    let a = audit_of(&state, &r.run, &native());
    assert_eq!(a.divergence, None, "{a:?}");
    assert_eq!(a.outcome, NOTHING_CHECKED);
}

/// P-53, opt-in side: with `parallel_tool_calls`, the same reply runs its
/// first call; the dropped one is never shown, the next request ends with
/// the drop notice, and the run submits and audits clean.
#[test]
fn parallel_calls_allowed_when_profile_opts_in() {
    let (state, ws) = scratch("opted-in");
    let profile = parallel();
    let mimic = Mimic::with(profile.clone(), plan(), Some(2));
    let r = go(&state, &ws, &profile, &mimic);
    let recs = records(&r, 1);
    assert_eq!(format_errors(&recs), Vec::<String>::new());
    assert_eq!(r.cause, StopCause::Submitted);
    assert_eq!(r.steps, 5);
    // The first of the pair ran at once; the mimic then makes it again
    // alone (its plan did not advance), so read a.txt appears twice.
    assert_eq!(
        started(&recs),
        [
            "harness.fs.list",
            "harness.fs.read",
            "harness.fs.read",
            "harness.fs.read",
            "harness.task.submit"
        ],
    );

    let requests = mimic.requests.borrow();
    assert_eq!(requests.len(), 5);
    for q in requests.iter() {
        assert_eq!(q["parallel_tool_calls"], Value::Bool(true), "{q}");
        assert_valid_tool_sequence(q);
    }
    let after = requests[2]["messages"].as_array().unwrap();
    let last = after.last().unwrap();
    assert_eq!(last["role"], "user");
    let text = last["content"].as_str().unwrap();
    assert!(text.starts_with("[harness] Notice:"), "{text}");
    assert!(
        text.contains("your reply made 2 tool calls")
            && text.contains("the other 1 were dropped")
            && text.contains("exactly one tool call per reply"),
        "{text}"
    );
    // The dropped call is in no request: one call per assistant message.
    let calls: Vec<&Value> = after
        .iter()
        .filter(|m| m.get("tool_calls").is_some())
        .collect();
    assert_eq!(calls.len(), 2, "steps 1 and 2 only");

    let a = audit_of(&state, &r.run, &profile);
    assert_eq!(a.divergence, None, "{a:?}");
    assert_eq!(a.outcome, NOTHING_CHECKED);
}

/// P-53: more active tools than the profile allows is a refusal naming
/// both counts; exactly at the cap the tools are declared.
#[test]
fn max_active_tools_limits_declarations() {
    let (state, ws) = scratch("too-many");
    let profile = with_max_active_tools(5);
    let err = run(Run {
        state_root: &state,
        workspace: &ws,
        spec: &spec(READ_GRANTS),
        registry: &registry(),
        policy: &UserPolicy::default(),
        profile: &profile,
        backend: &Mimic::new(None),
        probe: &Local,
        env: &FIXED_ENV,
        config: &RunConfig::defaults(1_000_000),
        approver: None,
        confinement: None,
    })
    .expect_err("six tools exceed a cap of five");
    assert!(
        matches!(err, RunRefused::TooManyTools { active: 6, max: 5 }),
        "{err:?}"
    );

    // Exactly at the cap: the run goes ahead and submits.
    let (state, ws) = scratch("at-cap");
    let mimic = Mimic::with(
        native(),
        vec![("harness_task_submit", r#"{"note":"alpha beta"}"#)],
        None,
    );
    let r = go(&state, &ws, &native(), &mimic);
    assert_eq!(r.cause, StopCause::Submitted);
    let recs = records(&r, 1);
    assert_eq!(started(&recs), ["harness.task.submit"]);
    let a = audit_of(&state, &r.run, &native());
    assert_eq!(a.divergence, None, "{a:?}");
}

/// P-53: with terse tool docs the journal header carries the terse
/// table's digest, the declarations on the wire are the terse summaries,
/// and the run still audits clean.
#[test]
fn replay_audits_clean_with_terse_docs() {
    let (state, ws) = scratch("terse");
    let profile = terse();
    let mimic = Mimic::with(profile.clone(), plan(), None);
    let r = go(&state, &ws, &profile, &mimic);
    assert_eq!(r.cause, StopCause::Submitted);

    let recs = records(&r, 1);
    let docs = recs[0].body["tool_docs"].as_str().expect("a digest");
    assert_eq!(docs.len(), 64, "sha256 hex: {docs}");

    let requests = mimic.requests.borrow();
    let tools = requests[0]["tools"].as_array().unwrap();
    let read = tools
        .iter()
        .find(|t| t["function"]["name"] == "harness_fs_read")
        .unwrap();
    assert_eq!(
        read["function"]["description"],
        builtin::terse_summary("harness.fs.read").unwrap()
    );

    let a = audit_of(&state, &r.run, &profile);
    assert_eq!(a.divergence, None, "{a:?}");
    assert_eq!(a.outcome, NOTHING_CHECKED);
    assert!(a.stop_recomputed);
    assert_eq!(a.matched, recs.len() - 1);
}

/// P-33: with terse tool docs every request is smaller than the full-docs
/// run's (the declaration block shrinks; everything else is equal), which
/// is what `full_docs_digest_unchanged` pins from the other side.
#[test]
fn terse_docs_reduce_tool_block_bytes() {
    let (state, ws) = scratch("terse-bytes");
    let full = native();
    let full_mimic = Mimic::with(full.clone(), plan(), None);
    let fr = go(&state, &ws, &full, &full_mimic);
    assert_eq!(fr.cause, StopCause::Submitted);

    let (state2, ws2) = scratch("terse-bytes-terse");
    let tp = terse();
    let terse_mimic = Mimic::with(tp.clone(), plan(), None);
    let tr = go(&state2, &ws2, &tp, &terse_mimic);
    assert_eq!(tr.cause, StopCause::Submitted);

    let bytes = |m: &Mimic| {
        m.requests
            .borrow()
            .iter()
            .map(|v| v.to_string().len())
            .sum::<usize>()
    };
    assert!(
        bytes(&terse_mimic) < bytes(&full_mimic),
        "terse requests ({}) must be smaller than full ones ({})",
        bytes(&terse_mimic),
        bytes(&full_mimic)
    );
}

/// P-33: `tool_docs` defaults to `full`, so an explicit `"full"` profile
/// renders byte-for-byte the requests the default profile renders — no
/// digest moves for runs that never opted in to terse.
#[test]
fn full_docs_digest_unchanged() {
    let explicit = Profile::parse(
        br#"{"profile_version":1,"id":"small-test","model":"m","context_window":32768,
        "fill_ratio":0.6,"protocol":"native","tool_choice_required_ok":false,"grammar":"none",
        "max_active_tools":6,"edit_format":"replace","recent_turns":5,"tool_docs":"full",
        "sampling":{"temperature":0.2,"top_p":0.95,"seed":7,"max_tokens":1024}}"#,
    )
    .unwrap();
    assert_eq!(explicit.tool_docs(), harness_model::profile::ToolDocs::Full);

    let (state, ws) = scratch("full-default");
    let default = native();
    let default_mimic = Mimic::with(default.clone(), plan(), None);
    let dr = go(&state, &ws, &default, &default_mimic);
    assert_eq!(dr.cause, StopCause::Submitted);

    let (state2, ws2) = scratch("full-explicit");
    let explicit_mimic = Mimic::with(explicit.clone(), plan(), None);
    let er = go(&state2, &ws2, &explicit, &explicit_mimic);
    assert_eq!(er.cause, StopCause::Submitted);

    // The two runs' rendered requests, with each observation's nonce
    // replaced (a nonce is drawn fresh per run; every other byte must
    // match).
    fn norm(v: &Value) -> String {
        let s = v.to_string();
        let b = s.as_bytes();
        let mut out = String::with_capacity(s.len());
        let mut i = 0usize;
        while let Some(p) = s[i..].find("untrusted ") {
            let at = i + p;
            // A delimiter only when it opens as `<<untrusted` (its opening
            // form) or `<</untrusted` (its closing form); any other
            // occurrence of the word is text, kept verbatim.
            let tag = if at >= 2 && &b[at - 2..at] == b"<<" {
                "<<untrusted "
            } else if at >= 3 && &b[at - 3..at] == b"<</" {
                "<</untrusted "
            } else {
                i = at + 1;
                out.push_str(s.get(i - 1..i).unwrap_or(""));
                continue;
            };
            let j = at + "untrusted ".len();
            let hex = &s[j..(j + 32).min(s.len())];
            if hex.len() == 32 && hex.bytes().all(|c| c.is_ascii_hexdigit()) {
                out.push_str(
                    s.get(i..at - (tag.len() - "untrusted ".len()))
                        .unwrap_or(""),
                );
                out.push_str(tag);
                out.push('N');
                i = j + 32;
            } else {
                i = at + 1;
                out.push_str(s.get(i - 1..i).unwrap_or(""));
            }
        }
        out.push_str(s.get(i..).unwrap_or(""));
        out
    }
    let left: Vec<String> = default_mimic.requests.borrow().iter().map(norm).collect();
    let right: Vec<String> = explicit_mimic.requests.borrow().iter().map(norm).collect();
    assert_eq!(left.len(), right.len(), "the same number of requests");
    for (i, (a, b)) in left.iter().zip(&right).enumerate() {
        if a != b {
            let at = a
                .bytes()
                .zip(b.bytes())
                .position(|(x, y)| x != y)
                .unwrap_or(a.len().min(b.len()));
            let lo = at.saturating_sub(80);
            panic!(
                "request {i} differs at byte {at}:\nL ...{}\nR ...{}",
                a.get(lo..(at + 120).min(a.len())).unwrap_or(""),
                b.get(lo..(at + 120).min(b.len())).unwrap_or("")
            );
        }
    }
    // The header of neither run carries a `tool_docs` key (only a terse
    // run stamps one), so the journal headers compare equal too.
    let head = |r: &RunReport| records(r, 1)[0].body.clone();
    let h1 = head(&dr);
    let h2 = head(&er);
    assert_eq!(h1.get("tool_docs"), None);
    assert_eq!(h2.get("tool_docs"), None);
}
