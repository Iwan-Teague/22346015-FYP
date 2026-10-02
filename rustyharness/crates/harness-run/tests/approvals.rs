//! H2b: approvals through the real loop (design §5.2, §5.3; INV-5, INV-16
//! end to end). A scripted approver answers asks; the real journal, edit
//! tools and approval authority do the rest.
//!
//! - INV-5: an asked call runs only with a yes for exactly that call: no
//!   approver, a no, no answer and a yes for another step all leave it
//!   unrun; a yes runs it once.
//! - INV-16: tokens never leave the harness (no nonce or MAC in any model
//!   request); the consumed nonce is journaled; an audit re-mints with the
//!   recorded nonces, so a journal that reuses one is refused.

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
use std::time::{Duration, Instant};

use gate_outcome::{GateOutcome, IndeterminateKind};
use harness_core::environment::{EnvSample, Unmeasured};
use harness_core::{RunId, StopCause};
use harness_journal::canon::{RecordFields, GENESIS};
use harness_journal::{layout, EventKind, JournalReader, Record};
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, SemVer, ValidationContext};
use harness_model::profile::Profile;
use harness_model::scripted::{text_reply, ScriptedBackend};
use harness_model::wire::render_request;
use harness_model::{Completion, ModelBackend, ModelError, ModelIdentity, ModelRequest, TaskText};
use harness_policy::approval::ApprovalRequest;
use harness_policy::locality::{FsQuery, LocalityProbe};
use harness_policy::UserPolicy;
use harness_run::{
    audit, resume, run, ApprovalAnswer, Approver, ApproverKind, Audit, Resume, Run, RunConfig,
    RunRefused, RunReport, TaskSpec,
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

const LIB: &str = "pub const RETRY_BASE_MS: u64 = 250;\n";

fn scratch(name: &str) -> (PathBuf, PathBuf) {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("approvals-{name}"));
    let _ = fs::remove_dir_all(&base);
    let (state, ws) = (base.join("state"), base.join("ws"));
    fs::create_dir_all(&state).unwrap();
    fs::create_dir_all(&ws).unwrap();
    fs::write(ws.join("lib.rs"), LIB).unwrap();
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

fn action(tool: &str, args: &Value) -> Result<Completion, ModelError> {
    Ok(text_reply(&format!(
        "<action>{{\"tool\":\"{tool}\",\"args\":{args}}}</action>"
    )))
}
fn read() -> Result<Completion, ModelError> {
    action("harness.fs.read", &serde_json::json!({"path": "lib.rs"}))
}
/// An edit that still matches after it is applied (`= 250;` stays in the
/// file), so a second application would show as a second comment.
fn tag() -> Result<Completion, ModelError> {
    action(
        "harness.edit.replace",
        &serde_json::json!({"path": "lib.rs", "old": "= 250;", "new": "= 250; // tagged"}),
    )
}
fn submit() -> Result<Completion, ModelError> {
    action("harness.task.submit", &serde_json::json!({"note": "done"}))
}

const TASK: &str = "Tag the retry base.";

fn spec() -> TaskSpec {
    TaskSpec {
        task: TaskText::new(TASK.into()),
        grants: vec!["harness.fs.read".into(), "harness.edit.replace".into()],
        workspace_public: false,
        exec: None,
        presubmit: None,
        protected: Vec::new(),
    }
}

/// An approver that answers from a script and remembers what it was shown.
struct Scripted {
    answers: RefCell<VecDeque<ApprovalAnswer>>,
    shown: RefCell<Vec<String>>,
    deadlines: RefCell<Vec<Duration>>,
    /// How long each answer takes (a person reading the request).
    think: Duration,
}

impl Scripted {
    fn new(answers: &[ApprovalAnswer]) -> Self {
        Self {
            answers: RefCell::new(answers.iter().copied().collect()),
            shown: RefCell::new(Vec::new()),
            deadlines: RefCell::new(Vec::new()),
            think: Duration::ZERO,
        }
    }
    fn asked(&self) -> usize {
        self.shown.borrow().len()
    }
}

impl Approver for Scripted {
    fn kind(&self) -> ApproverKind {
        ApproverKind::Embedded
    }
    fn ask(&self, req: &ApprovalRequest, deadline: Instant) -> ApprovalAnswer {
        self.shown.borrow_mut().push(req.to_string());
        self.deadlines
            .borrow_mut()
            .push(deadline.saturating_duration_since(Instant::now()));
        std::thread::sleep(self.think);
        self.answers
            .borrow_mut()
            .pop_front()
            .unwrap_or(ApprovalAnswer::NoAnswer)
    }
}

/// A scripted model that keeps every rendered request body, to show what
/// reached the model.
struct Capture {
    inner: ScriptedBackend,
    profile: Profile,
    bodies: RefCell<Vec<String>>,
}

impl Capture {
    fn new(replies: Vec<Result<Completion, ModelError>>) -> Self {
        let profile = Profile::conservative_default("m");
        Self {
            inner: ScriptedBackend::new(profile.clone(), replies),
            profile,
            bodies: RefCell::new(Vec::new()),
        }
    }
}

impl ModelBackend for Capture {
    fn identity(&self) -> ModelIdentity {
        self.inner.identity()
    }
    fn complete(&self, req: &ModelRequest, deadline: Instant) -> Result<Completion, ModelError> {
        if let Ok(v) = render_request(req, &self.profile) {
            self.bodies.borrow_mut().push(v.to_string());
        }
        self.inner.complete(req, deadline)
    }
}

fn config() -> RunConfig {
    RunConfig::defaults(1_000_000)
}

fn go(
    state: &Path,
    ws: &Path,
    backend: &dyn ModelBackend,
    approver: Option<&dyn Approver>,
    cfg: &RunConfig,
) -> RunReport {
    run(Run {
        state_root: state,
        workspace: ws,
        spec: &spec(),
        registry: &registry(),
        policy: &UserPolicy::default(),
        profile: &Profile::conservative_default("m"),
        backend,
        probe: &Local,
        env: &FIXED_ENV,
        config: cfg,
        approver,
        confinement: None,
    })
    .unwrap()
}

fn records(r: &RunReport, attempt: u32) -> Vec<Record> {
    JournalReader::open(&layout::attempt_dir(&r.run_dir, attempt))
        .unwrap()
        .records
}

fn kinds(recs: &[Record], step: u64) -> Vec<EventKind> {
    recs.iter()
        .filter(|r| r.step == step)
        .map(|r| r.kind)
        .collect()
}

fn of(recs: &[Record], kind: EventKind) -> Vec<&Record> {
    recs.iter().filter(|r| r.kind == kind).collect()
}

fn audited(state: &Path, run: &RunId, attempt: Option<u32>) -> harness_run::AuditReport {
    audit(Audit {
        state_root: state,
        run,
        attempt,
        anchor: None,
        spec: &spec(),
        registry: &registry(),
        policy: &UserPolicy::default(),
        profile: &Profile::conservative_default("m"),
        limits: &config().limits,
    })
    .unwrap()
}

fn tagged(ws: &Path) -> usize {
    fs::read_to_string(ws.join("lib.rs"))
        .unwrap()
        .matches("// tagged")
        .count()
}

const NOTHING_CHECKED: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::NothingChecked,
};
const UNREADABLE: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::UnreadableEvidence,
};

// INV-5 / §5.3: a yes runs exactly the asked call, once. The step's records
// are the ask, the request, the grant (approver kind and consumed nonce,
// never a MAC), then the intent, the edit and its result. The approver was
// shown the summary, the class in words, the escaped arguments and the step.
#[test]
fn inv_5_a_yes_runs_the_asked_edit_once_and_the_grant_records_the_nonce() {
    let (state, ws) = scratch("yes");
    let yes = Scripted::new(&[ApprovalAnswer::Yes]);
    let backend = Capture::new(vec![read(), tag(), submit()]);
    let r = go(&state, &ws, &backend, Some(&yes), &config());
    assert_eq!(r.cause, StopCause::Submitted);
    assert_eq!(tagged(&ws), 1);
    let recs = records(&r, 1);
    assert_eq!(recs[0].body["approver_present"], Value::Bool(true));
    let step2 = kinds(&recs, 2);
    let at = step2
        .iter()
        .position(|k| *k == EventKind::PolicyDecided)
        .unwrap();
    assert_eq!(
        step2[at..],
        [
            EventKind::PolicyDecided,
            EventKind::ApprovalRequested,
            EventKind::ApprovalGranted,
            EventKind::ToolStarted,
            EventKind::EditApplied,
            EventKind::ToolFinished,
        ]
    );
    let decided = &of(&recs, EventKind::PolicyDecided)[1].body;
    assert_eq!(decided["decision"], "ask");
    assert_eq!(decided["rule"], "ask.edit.in-place");
    assert_eq!(decided["tier"], "user_confirm");
    let granted = &of(&recs, EventKind::ApprovalGranted)[0].body;
    assert_eq!(granted["approver"], "embedded");
    assert_eq!(granted["scope"], "once");
    let nonce = granted["nonce"].as_str().unwrap();
    assert_eq!(nonce.len(), 32);
    assert!(granted.get("mac").is_none());
    assert_eq!(
        granted["args"],
        of(&recs, EventKind::ApprovalRequested)[0].body["args"]
    );
    // What the approver saw.
    assert_eq!(yes.asked(), 1);
    let shown = &yes.shown.borrow()[0];
    assert!(shown.contains("harness.edit.replace"), "{shown}");
    assert!(shown.contains("step 2"), "{shown}");
    assert!(shown.contains("user_confirm"), "{shown}");
    assert!(shown.contains("// tagged"), "{shown}");
    // INV-16: the token never reached the model.
    for body in backend.bodies.borrow().iter() {
        assert!(!body.contains(nonce), "a nonce in a model request");
    }
    // The audit re-feeds the answer and re-mints with the recorded nonce.
    let a = audited(&state, &r.run, None);
    assert_eq!(a.divergence, None, "{a:?}");
    assert!(a.stop_recomputed);
    assert_eq!(a.outcome, NOTHING_CHECKED);
}

// INV-5: a no, and no answer, each leave the call unrun (ApprovalDenied,
// ApprovalExpired), and the model is told so in harness words.
#[test]
fn inv_5_a_no_or_no_answer_never_runs_the_call() {
    for (answer, kind, words) in [
        (
            ApprovalAnswer::No,
            EventKind::ApprovalDenied,
            "The approver declined the call",
        ),
        (
            ApprovalAnswer::NoAnswer,
            EventKind::ApprovalExpired,
            "No approval arrived in time",
        ),
    ] {
        let (state, ws) = scratch(&format!("{answer:?}"));
        let approver = Scripted::new(&[answer]);
        let backend = Capture::new(vec![read(), tag(), submit()]);
        let r = go(&state, &ws, &backend, Some(&approver), &config());
        assert_eq!(r.cause, StopCause::Submitted);
        assert_eq!(tagged(&ws), 0, "{answer:?}");
        let recs = records(&r, 1);
        assert_eq!(of(&recs, kind).len(), 1, "{answer:?}");
        assert!(of(&recs, EventKind::EditApplied).is_empty());
        let started: Vec<&str> = of(&recs, EventKind::ToolStarted)
            .iter()
            .map(|x| x.body["capability"].as_str().unwrap())
            .collect();
        assert_eq!(started, ["harness.fs.read", "harness.task.submit"]);
        // The next request carries the harness's words.
        let bodies = backend.bodies.borrow();
        assert!(bodies[2].contains(words), "{answer:?}");
        let a = audited(&state, &r.run, None);
        assert_eq!(a.divergence, None, "{a:?}");
    }
}

// INV-5: approvals are single-use and bound to their step (the owner kept
// strict step binding): the same call asked again at the next step is
// asked again, and a no there leaves it unrun although step 2's was yes.
#[test]
fn inv_5_a_yes_at_one_step_never_runs_the_same_call_at_another() {
    let (state, ws) = scratch("step-bound");
    let approver = Scripted::new(&[ApprovalAnswer::Yes, ApprovalAnswer::No]);
    let backend = Capture::new(vec![read(), tag(), tag(), submit()]);
    let r = go(&state, &ws, &backend, Some(&approver), &config());
    assert_eq!(r.cause, StopCause::Submitted);
    assert_eq!(approver.asked(), 2, "asked at step 2 and again at step 3");
    assert_eq!(tagged(&ws), 1, "only the approved step ran");
    let recs = records(&r, 1);
    assert_eq!(of(&recs, EventKind::ApprovalGranted).len(), 1);
    assert_eq!(of(&recs, EventKind::ApprovalDenied).len(), 1);
    assert_eq!(of(&recs, EventKind::ApprovalDenied)[0].step, 3);
}

// §5.2 end to end: with no approver present the ask is a deny, the
// approver is never reached, and the header says nobody could answer.
#[test]
fn inv_5_with_no_approver_the_ask_is_a_deny() {
    let (state, ws) = scratch("no-approver");
    let backend = Capture::new(vec![read(), tag(), submit()]);
    let r = go(&state, &ws, &backend, None, &config());
    assert_eq!(tagged(&ws), 0);
    let recs = records(&r, 1);
    assert_eq!(recs[0].body["approver_present"], Value::Bool(false));
    assert!(of(&recs, EventKind::ApprovalRequested).is_empty());
    assert_eq!(
        of(&recs, EventKind::PolicyDecided)[1].body["rule"],
        "deny.no-approver"
    );
}

// §2.4: the wait for a human is not charged to the wall budget, and the
// approver gets the approval timeout as its deadline.
#[test]
fn the_approval_wait_is_not_charged_to_the_wall_budget() {
    let (state, ws) = scratch("wall-pause");
    let mut slow = Scripted::new(&[ApprovalAnswer::Yes]);
    slow.think = Duration::from_millis(3000);
    let mut cfg = config();
    cfg.limits.wall = Duration::from_millis(2500);
    cfg.approval_timeout = Duration::from_secs(600);
    let backend = Capture::new(vec![read(), tag(), submit()]);
    let r = go(&state, &ws, &backend, Some(&slow), &cfg);
    assert_eq!(r.cause, StopCause::Submitted, "the wait was charged");
    assert_eq!(tagged(&ws), 1);
    let d = slow.deadlines.borrow()[0];
    assert!(
        d > Duration::from_secs(590) && d <= Duration::from_secs(600),
        "{d:?}"
    );
}

/// Re-chain a journal after `edit` changes some records' bodies.
fn rechain_all(path: &Path, edit: impl Fn(&mut Value)) {
    let text = fs::read_to_string(path).unwrap();
    let mut prev = GENESIS;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut v: Value = serde_json::from_str(line).unwrap();
        edit(&mut v);
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

// INV-16 in replay: consumed nonces are journaled so reuse is detectable.
// A journal whose second grant reuses the first grant's nonce, re-chained,
// cannot be re-minted by the audit's authority: the replay stops where the
// recorded run went on, and the audit is unreadable evidence. A grant
// naming an approver outside the closed set is refused as a shape the loop
// does not write.
#[test]
fn inv_16_a_reused_or_misnamed_grant_makes_the_audit_unreadable() {
    let (state, ws) = scratch("reuse");
    let approver = Scripted::new(&[ApprovalAnswer::Yes, ApprovalAnswer::Yes]);
    let backend = Capture::new(vec![
        read(),
        tag(),
        read(),
        action(
            "harness.edit.replace",
            &serde_json::json!({"path": "lib.rs", "old": "// tagged", "new": "// tagged twice"}),
        ),
        submit(),
    ]);
    let r = go(&state, &ws, &backend, Some(&approver), &config());
    assert_eq!(r.cause, StopCause::Submitted);
    let recs = records(&r, 1);
    let grants = of(&recs, EventKind::ApprovalGranted);
    assert_eq!(grants.len(), 2);
    let first = grants[0].body["nonce"].clone();
    assert_ne!(first, grants[1].body["nonce"], "fresh nonces");
    assert_eq!(audited(&state, &r.run, None).divergence, None);

    let path = layout::attempt_dir(&r.run_dir, 1).join(layout::JOURNAL_FILE);
    let pristine = fs::read(&path).unwrap();
    let second_seq = grants[1].seq;
    rechain_all(&path, |v| {
        if v["seq"].as_u64() == Some(second_seq) {
            v["body"]["nonce"] = first.clone();
        }
    });
    let a = audited(&state, &r.run, Some(1));
    assert_eq!(a.outcome, UNREADABLE, "{a:?}");
    assert!(a.divergence.is_some());

    fs::write(&path, &pristine).unwrap();
    rechain_all(&path, |v| {
        if v["seq"].as_u64() == Some(second_seq) {
            v["body"]["approver"] = Value::from("someone");
        }
    });
    let a = audited(&state, &r.run, Some(1));
    assert_eq!(a.outcome, UNREADABLE, "{a:?}");
    assert_eq!(
        a.divergence.unwrap().why,
        "a record is not the shape the loop writes"
    );
}

/// Cut a committed journal back to its records of steps < `keep_below`.
fn crash_after(r: &RunReport, keep_below: u64) {
    let path = layout::attempt_dir(&r.run_dir, 1).join(layout::JOURNAL_FILE);
    let text = fs::read_to_string(&path).unwrap();
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

fn resume_with(
    state: &Path,
    ws: &Path,
    run: &RunId,
    backend: &dyn ModelBackend,
    approver: Option<&dyn Approver>,
) -> Result<RunReport, RunRefused> {
    resume(Resume {
        state_root: state,
        run,
        workspace: ws,
        spec: &spec(),
        registry: &registry(),
        policy: &UserPolicy::default(),
        profile: &Profile::conservative_default("m"),
        backend,
        probe: &Local,
        env: &FIXED_ENV,
        config: &config(),
        approver,
        confinement: None,
    })
}

// Resume with approvals: the catch-up re-feeds the recorded grant (the
// approver is not asked again for a completed step, and the edit is not
// applied again); the next ask goes to the live approver. A resume without
// the approver the run was started with is refused, nothing written.
#[test]
fn a_resume_re_feeds_recorded_approvals_and_asks_live_only_after() {
    let (state, ws) = scratch("resume");
    let first = Scripted::new(&[ApprovalAnswer::Yes]);
    let backend = Capture::new(vec![read(), tag(), submit()]);
    let r = go(&state, &ws, &backend, Some(&first), &config());
    assert_eq!(tagged(&ws), 1);
    crash_after(&r, 3); // step 2, the approved edit, is complete

    let none = Capture::new(vec![]);
    let e = resume_with(&state, &ws, &r.run, &none, None).unwrap_err();
    assert!(
        matches!(e, RunRefused::NotResumable(w) if w.contains("approver")),
        "{e:?}"
    );
    assert!(!layout::attempt_dir(&r.run_dir, 2).exists());

    let second = Scripted::new(&[ApprovalAnswer::No]);
    let backend = Capture::new(vec![tag(), submit()]);
    let res = resume_with(&state, &ws, &r.run, &backend, Some(&second)).unwrap();
    assert_eq!(res.cause, StopCause::Submitted);
    assert_eq!(res.steps, 4, "steps 1-2 re-fed, 3 and 4 live");
    assert_eq!(second.asked(), 1, "asked only for the live step 3");
    assert_eq!(tagged(&ws), 1, "the approved edit was not applied again");
    let new = records(&res, 2);
    assert_eq!(of(&new, EventKind::ApprovalGranted).len(), 1, "re-fed");
    assert_eq!(of(&new, EventKind::ApprovalDenied)[0].step, 3);
    let a = audited(&state, &r.run, Some(2));
    assert_eq!(a.divergence, None, "{a:?}");
}
