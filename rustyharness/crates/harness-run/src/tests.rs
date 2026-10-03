//! The loop against a scripted model and a spy provider, with the
//! journal's fault-injecting file (no filesystem). End-to-end runs through
//! the public `run` are in `tests/run.rs`.

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use gate_outcome::{GateOutcome, IndeterminateKind};
use harness_core::environment::{EnvSample, Method, Reading, Unmeasured};
use harness_core::{sha256, BudgetDim, LoopKind, MonoClock, RunId, Source, StopCause, Untrusted};
use harness_journal::testing::{FaultFile, FaultPlan, MemBlobs};
use harness_journal::{verify, Clock, EventKind, Header, Ident, JournalWriter, Journaled};
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, ProviderName, SemVer, ValidationContext};
use harness_model::profile::Profile;
use harness_model::scripted::{text_reply, ScriptedBackend};
use harness_model::{Completion, ModelError, ServerUsage, TaskText, Unavailable};
use harness_policy::{Authorized, Call, UserPolicy};
use harness_tools::{InvokeCtx, ToolError, ToolProvider, ToolResult, ToolStatus};

use crate::driver::approvals::Approvals;
use crate::driver::plan::plan;
use crate::driver::step::{BudgetNotices, Loop, LoopInit, NonceSource};
use crate::driver::stop::{commit, End};
use crate::driver::tools::{bg_fields, exec_fields, parse_bg, parse_exec};
use crate::driver::{new_meter, new_nonce, new_run_id, ReadLog};

use crate::{RunConfig, TaskSpec};

struct Tick(Cell<u64>);
impl Clock for Tick {
    fn mono_ms(&self) -> u64 {
        self.0.set(self.0.get() + 1);
        self.0.get()
    }
    fn unix_ms(&self) -> u64 {
        0
    }
}

/// A monotonic clock that advances `step` on every read.
struct Advancing {
    now: Cell<Duration>,
    step: Duration,
}
impl MonoClock for Advancing {
    fn now(&self) -> Duration {
        let t = self.now.get() + self.step;
        self.now.set(t);
        t
    }
}

struct Spy {
    ns: ProviderName,
    invoked: Rc<Cell<u32>>,
    /// The status every call ends with; `None`: the provider fails.
    status: Option<ToolStatus>,
}
impl ToolProvider for Spy {
    fn namespace(&self) -> &ProviderName {
        &self.ns
    }
    fn invoke(
        &mut self,
        call: Journaled<Authorized<Call>>,
        _ctx: &InvokeCtx<'_>,
    ) -> Result<ToolResult, ToolError> {
        self.invoked.set(self.invoked.get() + 1);
        let Some(status) = self.status else {
            return Err(ToolError("the spy fails".into()));
        };
        let out = format!(
            "contents #{} of {}",
            self.invoked.get(),
            call.call().call().args
        );
        Ok(ToolResult {
            status,
            digest: sha256(out.as_bytes()),
            output: Untrusted::new(out.into_bytes(), Source::Tool("harness.fs.read".into())),
            truncated: false,
            read: None,
            edits: Vec::new(),
            exec: None,
        })
    }
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

fn action(tool: &str, args: &str) -> Result<Completion, ModelError> {
    Ok(text_reply(&format!(
        "thinking <action>{{\"tool\":\"{tool}\",\"args\":{args}}}</action>"
    )))
}

fn read(path: &str) -> Result<Completion, ModelError> {
    action("harness.fs.read", &format!("{{\"path\":\"{path}\"}}"))
}

fn submit() -> Result<Completion, ModelError> {
    action("harness.task.submit", "{\"note\":\"the answer is 42\"}")
}

struct Outcome {
    end: End,
    released: GateOutcome,
    invoked: u32,
    kinds: Vec<EventKind>,
    journal: Vec<u8>,
    tokens: (u64, u64),
    estimated: bool,
    blobs: MemBlobs,
    /// Steps whose tool timed out or crashed under host pressure.
    pressure: Vec<u64>,
}

fn drive_with(
    replies: Vec<Result<Completion, ModelError>>,
    plan_faults: FaultPlan,
    limits: impl FnOnce(&mut RunConfig),
    clock_step: Duration,
) -> Outcome {
    drive_full(
        replies,
        plan_faults,
        limits,
        clock_step,
        Some(ToolStatus::Ok),
        &EnvSample::unmeasured(Unmeasured::NoSafeApi),
    )
}

fn drive_full(
    replies: Vec<Result<Completion, ModelError>>,
    plan_faults: FaultPlan,
    limits: impl FnOnce(&mut RunConfig),
    clock_step: Duration,
    status: Option<ToolStatus>,
    env: &EnvSample,
) -> Outcome {
    let reg = registry();
    let profile = Profile::conservative_default("m");
    let spec = TaskSpec {
        task: TaskText::new("What is in a.txt?".into()),
        grants: vec!["harness.fs.read".into(), "harness.fs.list".into()],
        workspace_public: false,
        exec: None,
        presubmit: None,
        protected: Vec::new(),
    };
    let policy = UserPolicy::default();
    let (session, tools) = plan(&spec, &reg, &policy, &profile, false, false).unwrap();
    let backend = ScriptedBackend::new(profile.clone(), replies);
    let invoked = Rc::new(Cell::new(0));
    let mut cfg = RunConfig::defaults(1_000_000);
    limits(&mut cfg);
    let file = FaultFile::new(plan_faults);
    let buf = file.buf.clone();
    let blobs = MemBlobs::default();
    let mut w = JournalWriter::start(
        file,
        blobs.clone(),
        Tick(Cell::new(0)),
        RunId::new(9, [1; 10]),
        1,
        Header::new(Ident::of("0.0.1").unwrap()),
    )
    .unwrap();
    let mut lp = Loop::new(LoopInit {
        session,
        registry: &reg,
        tools,
        task: &spec.task,
        facts: Vec::new(),
        profile: &profile,
        backend: &backend,
        providers: vec![Box::new(Spy {
            ns: ProviderName::new("harness").unwrap(),
            invoked: invoked.clone(),
            status,
        })],
        meter: new_meter(
            cfg.limits.clone(),
            Box::new(Advancing {
                now: Cell::new(Duration::ZERO),
                step: clock_step,
            }),
        ),
        detector: harness_core::LoopDetector::new(),
        turns: Vec::new(),
        config: &cfg,
        step: 0,
        nonces: NonceSource::default(),
        feed: std::collections::VecDeque::new(),
        reads: ReadLog::default(),
        tree: harness_core::sha256(b"tree"),
        workspace: None,
        approvals: Approvals::new(&RunId::new(9, [1; 10]), 1, None, Default::default()),
        env,
        pressure: Vec::new(),
        reads_seen: Default::default(),
        todo: None,
        notices: BudgetNotices::live(cfg.limits.wall),
        presubmit: None,
        restore: Default::default(),
        user: None,
    });
    let end = lp.drive(&mut w);
    let pressure = lp.pressure.clone();
    let tokens = lp.meter.tokens_spent();
    let estimated = lp.meter.tokens_were_estimated();
    let released = commit(w, &end, None).outcome;
    let journal = buf.borrow().clone();
    let kinds = match verify(&journal, &blobs) {
        Ok(v) => v.records.iter().map(|r| r.kind).collect(),
        // A failed write leaves a journal that stops early; its kinds are
        // not needed by those tests.
        Err(_) => Vec::new(),
    };
    Outcome {
        end,
        released,
        invoked: invoked.get(),
        kinds,
        journal,
        tokens,
        estimated,
        blobs,
        pressure,
    }
}

fn drive(replies: Vec<Result<Completion, ModelError>>) -> Outcome {
    drive_with(replies, FaultPlan::default(), |_| {}, Duration::ZERO)
}

const NOTHING_CHECKED: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::NothingChecked,
};
const UNREADABLE: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::UnreadableEvidence,
};

fn count(o: &Outcome, k: EventKind) -> usize {
    o.kinds.iter().filter(|x| **x == k).count()
}

// ---- the loop, per step ----------------------------------------------------------

#[test]
fn a_read_then_submit_journals_every_step_and_is_nothing_checked() {
    let o = drive(vec![read("a.txt"), submit()]);
    assert_eq!(o.end.cause, StopCause::Submitted);
    assert_eq!(o.end.step, 2);
    assert_eq!(o.invoked, 1);
    assert_eq!(
        o.released, NOTHING_CHECKED,
        "INV-18: submit is never a pass"
    );
    assert_eq!(o.end.deliverable, Some(sha256(b"the answer is 42")));
    use EventKind as K;
    assert_eq!(
        o.kinds,
        [
            K::RunStarted,
            K::ContextBuilt,
            K::ModelRequested,
            K::ModelReplied,
            K::ActionParsed,
            K::PolicyDecided,
            K::ToolStarted,
            K::ToolFinished,
            K::ContextBuilt,
            K::ModelRequested,
            K::ModelReplied,
            K::ActionParsed,
            K::PolicyDecided,
            K::ToolStarted,
            K::SubmitRequested,
            K::ToolFinished,
            K::RunStopped,
        ]
    );
}

#[test]
fn trusted_fields_never_carry_model_text() {
    // The model's path, reasoning and note appear only inside untrusted
    // payloads ("untrusted": true objects), never as a trusted value.
    let o = drive(vec![read("MODEL-PATH.txt"), submit()]);
    let v = verify(&o.journal, &MemBlobs::default()).unwrap();
    fn walk(v: &serde_json::Value, inside_untrusted: bool, hits: &mut Vec<String>) {
        match v {
            serde_json::Value::String(s) if !inside_untrusted => {
                if s.contains("MODEL-PATH") || s.contains("thinking") || s.contains("the answer is")
                {
                    hits.push(s.clone());
                }
            }
            serde_json::Value::Object(m) => {
                let u = inside_untrusted || m.get("untrusted") == Some(&serde_json::json!(true));
                for x in m.values() {
                    walk(x, u, hits);
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, inside_untrusted, hits)),
            _ => {}
        }
    }
    let mut hits = Vec::new();
    for r in &v.records {
        walk(&serde_json::Value::Object(r.body.clone()), false, &mut hits);
    }
    assert!(hits.is_empty(), "{hits:?}");
    // And the model text did reach the journal, as untrusted payload.
    assert!(String::from_utf8_lossy(&o.journal).contains("MODEL-PATH"));
}

#[test]
fn token_usage_reaches_the_meter_measured_or_estimated() {
    let mut c = read("a.txt").unwrap();
    c.usage = Some(ServerUsage {
        input: 1000,
        output: 50,
    });
    let mut s = submit().unwrap();
    s.usage = Some(ServerUsage {
        input: 1200,
        output: 20,
    });
    let o = drive(vec![Ok(c), Ok(s)]);
    assert_eq!(o.tokens, (2200, 70));
    assert!(!o.estimated);
    // No usage from the server: the conservative estimate, marked as such.
    let o = drive(vec![read("a.txt"), submit()]);
    assert!(o.tokens.0 > 0 && o.tokens.1 > 0);
    assert!(o.estimated);
}

// ---- INV-3 (run half): an empty or truncated completion is never a turn result --

#[test]
fn inv_3_empty_and_truncated_replies_are_format_errors_not_results() {
    let o = drive(vec![
        Err(ModelError::Empty),
        Err(ModelError::Truncated("length")),
        submit(),
    ]);
    assert_eq!(o.end.cause, StopCause::Submitted);
    assert_eq!(
        count(&o, EventKind::ActionParsed),
        1,
        "only the submit parsed"
    );
    assert_eq!(count(&o, EventKind::ToolStarted), 1);
    assert_eq!(o.invoked, 0);

    // Three in a row stop the run, nothing executed.
    let o = drive(vec![
        Err(ModelError::Empty),
        Err(ModelError::Truncated("length")),
        Err(ModelError::Unusable("x".into())),
        submit(),
    ]);
    assert_eq!(o.end.cause, StopCause::FormatErrors);
    assert_eq!(count(&o, EventKind::ToolStarted), 0);
    assert_eq!(o.released, NOTHING_CHECKED);
}

#[test]
fn replies_without_exactly_one_action_are_format_errors() {
    let o = drive(vec![
        Ok(text_reply("no action here")),
        Ok(text_reply(
            "<action>{\"tool\":\"harness.fs.read\",\"args\":{}}</action><action>{}</action>",
        )),
        Ok(text_reply(
            "<action>{\"tool\":\"harness.exec.run\",\"args\":{}}</action>",
        )),
    ]);
    assert_eq!(o.end.cause, StopCause::FormatErrors);
    assert_eq!(count(&o, EventKind::FormatError), 3);
    assert_eq!(o.invoked, 0);
}

#[test]
fn an_unreachable_model_stops_the_run() {
    let o = drive(vec![Err(ModelError::Unavailable(
        Unavailable::ConnectTimeout,
    ))]);
    assert_eq!(o.end.cause, StopCause::ModelUnavailable);
    assert_eq!(o.released, NOTHING_CHECKED);
}

// ---- INV-14: every budget stop carries its typed cause ---------------------------

#[test]
fn inv_14_the_step_budget_stops_the_run() {
    let o = drive_with(
        vec![read("a"), read("b"), read("c"), read("d")],
        FaultPlan::default(),
        |c| c.limits.steps = 2,
        Duration::ZERO,
    );
    assert_eq!(o.end.cause, StopCause::Budget(BudgetDim::Steps));
    assert_eq!(o.invoked, 2);
    assert!(String::from_utf8_lossy(&o.journal).contains("\"dimension\":\"steps\""));
}

#[test]
fn inv_14_the_token_budget_stops_the_run() {
    let mut c = read("a.txt").unwrap();
    c.usage = Some(ServerUsage {
        input: 900,
        output: 200,
    });
    let o = drive_with(
        vec![Ok(c), read("b"), submit()],
        FaultPlan::default(),
        |c| c.limits.tokens = 1000,
        Duration::ZERO,
    );
    assert_eq!(o.end.cause, StopCause::Budget(BudgetDim::Tokens));
    assert_eq!(
        o.invoked, 0,
        "the exchange that crossed the limit runs nothing"
    );
}

#[test]
fn inv_14_the_wall_budget_stops_the_run_from_the_meters_own_clock() {
    // Every clock read advances 4 minutes; the budget is 30 minutes. The
    // loop cannot outlive it whatever the model does.
    let replies: Vec<_> = (0..50).map(|i| read(&format!("f{i}"))).collect();
    let o = drive_with(
        replies,
        FaultPlan::default(),
        |_| {},
        Duration::from_secs(4 * 60),
    );
    assert_eq!(o.end.cause, StopCause::Budget(BudgetDim::Wall));
    assert!(o.end.step < 10, "stopped after {} steps", o.end.step);
}

// ---- Loop detection (§2.6) -----------------------------------------------------

#[test]
fn a_repeated_action_gets_one_notice_then_stops_before_running_again() {
    let o = drive(vec![read("a"), read("a"), read("a"), read("a"), read("a")]);
    assert_eq!(o.end.cause, StopCause::Loop(LoopKind::Repeat));
    assert_eq!(o.invoked, 3, "the 4th identical call is not executed");
    assert_eq!(count(&o, EventKind::LoopDetected), 2);
    let j = String::from_utf8_lossy(&o.journal);
    assert!(j.contains("\"kind\":\"repeat\",\"stop\":false"));
    assert!(j.contains("\"kind\":\"repeat\",\"stop\":true"));
}

#[test]
fn denial_hammering_stops_the_run_and_nothing_runs() {
    let o = drive(vec![read("../x"), read("/etc/passwd"), read("a/../../x")]);
    assert_eq!(o.end.cause, StopCause::Loop(LoopKind::Denied));
    assert_eq!(o.invoked, 0);
    assert_eq!(count(&o, EventKind::ToolStarted), 0);
    assert_eq!(count(&o, EventKind::PolicyDecided), 3);
    assert!(String::from_utf8_lossy(&o.journal).contains("\"reason\":\"path_outside_workspace\""));
}

#[test]
fn an_ungranted_capability_is_denied_by_policy_not_run() {
    // fs.search is admitted but not granted in this session: the parser
    // refuses it as an unknown tool (not in the active set).
    let o = drive(vec![
        action("harness.fs.search", "{\"pattern\":\"x\"}"),
        submit(),
    ]);
    assert_eq!(count(&o, EventKind::FormatError), 1);
    assert_eq!(o.invoked, 0);
    assert_eq!(o.end.cause, StopCause::Submitted);
}

// ---- INV-33 (run level): write-ahead through the whole loop ---------------------

#[test]
fn inv_33_a_failed_intent_write_runs_nothing_and_is_unreadable_evidence() {
    // Writes: 1 header, then per read step ContextBuilt, ModelRequested,
    // ModelReplied, ActionParsed, PolicyDecided = 2..=6, the intent = 7.
    let o = drive_with(
        vec![read("a.txt"), submit()],
        FaultPlan {
            fail_write: Some(7),
            ..FaultPlan::default()
        },
        |_| {},
        Duration::ZERO,
    );
    assert_eq!(o.invoked, 0, "no Journaled value, no invocation");
    assert!(matches!(o.end.cause, StopCause::JournalUnavailable { .. }));
    assert_eq!(o.released, UNREADABLE);
    assert_eq!(
        o.kinds.last(),
        Some(&EventKind::PolicyDecided),
        "the failed write was the intent"
    );

    // Its fsync: syncs are 1 header, 2 the intent.
    let o = drive_with(
        vec![read("a.txt"), submit()],
        FaultPlan {
            fail_sync: Some(2),
            ..FaultPlan::default()
        },
        |_| {},
        Duration::ZERO,
    );
    assert_eq!(o.invoked, 0);
    assert_eq!(o.released, UNREADABLE);
    assert_eq!(
        o.kinds.last(),
        Some(&EventKind::ToolStarted),
        "the failed fsync was the intent's"
    );
}

#[test]
fn inv_33_a_failed_result_write_stops_after_the_one_call() {
    // Write 8 is step 1's ToolFinished: the tool ran, nothing after it.
    let o = drive_with(
        vec![read("a.txt"), read("b.txt"), submit()],
        FaultPlan {
            fail_write: Some(8),
            ..FaultPlan::default()
        },
        |_| {},
        Duration::ZERO,
    );
    assert_eq!(o.invoked, 1);
    assert!(matches!(o.end.cause, StopCause::JournalUnavailable { .. }));
    assert_eq!(o.released, UNREADABLE);
}

#[test]
fn inv_33_a_failed_run_stopped_write_is_unreadable_evidence() {
    // Submit-only run: header, ContextBuilt, ModelRequested, ModelReplied,
    // ActionParsed, PolicyDecided, ToolStarted, SubmitRequested,
    // ToolFinished = 9 writes; RunStopped is the 10th.
    let o = drive_with(
        vec![submit()],
        FaultPlan {
            fail_write: Some(10),
            ..FaultPlan::default()
        },
        |_| {},
        Duration::ZERO,
    );
    assert_eq!(o.end.cause, StopCause::Submitted);
    assert_eq!(o.released, UNREADABLE);
}

// ---- identities ------------------------------------------------------------------

#[test]
fn run_ids_and_nonces_are_well_formed_and_distinct() {
    let a = new_run_id();
    let b = new_run_id();
    assert_ne!(a, b);
    assert!(RunId::parse(a.as_str()).is_some());
    let n1 = new_nonce().unwrap();
    let n2 = new_nonce().unwrap();
    assert_ne!(n1.as_str(), n2.as_str());
    assert_eq!(n1.as_str().len(), 32);
}

// ---- F-1 (H1e-2a review): every stop leaves a paired, replayable journal ----

/// Every `ModelRequested` has its `ModelReplied`, every intent has its
/// result (by `intent_seq`), and the audit replay backend accepts the
/// journal.
fn assert_paired(o: &Outcome, what: &str) {
    let v = verify(&o.journal, &o.blobs).unwrap_or_else(|e| panic!("{what}: {e:?}"));
    let n = |k| v.records.iter().filter(|r| r.kind == k).count();
    assert_eq!(
        n(EventKind::ModelRequested),
        n(EventKind::ModelReplied),
        "{what}: a model request without its reply"
    );
    let intents: Vec<u64> = v
        .records
        .iter()
        .filter(|r| r.kind == EventKind::ToolStarted)
        .map(|r| r.seq)
        .collect();
    let results: Vec<u64> = v
        .records
        .iter()
        .filter(|r| r.kind == EventKind::ToolFinished)
        .filter_map(|r| r.body.get("intent_seq").and_then(serde_json::Value::as_u64))
        .collect();
    assert_eq!(intents, results, "{what}: an intent without its result");
    let replay = harness_model::replay::ReplayBackend::from_journal(
        &v,
        &o.blobs,
        Profile::conservative_default("m"),
    )
    .unwrap_or_else(|e| panic!("{what}: replay refused the journal: {e:?}"));
    assert_eq!(replay.len(), n(EventKind::ModelReplied), "{what}");
}

#[test]
fn every_stop_cause_leaves_every_call_paired_and_the_journal_replayable() {
    let reads = |n: usize| -> Vec<_> { (0..n).map(|i| read(&format!("f{i}"))).collect() };
    let mut cases: Vec<(String, Outcome, StopCause)> = Vec::new();
    // The wall budget, at every clock rate that trips it at a different
    // point of the step (after a model call, after a tool call, ...).
    for secs in [30, 60, 90, 120, 180, 240, 300, 450, 600, 900, 1800, 3600] {
        let o = drive_with(
            reads(50),
            FaultPlan::default(),
            |_| {},
            Duration::from_secs(secs),
        );
        cases.push((
            format!("wall budget, {secs} s per clock read"),
            o,
            StopCause::Budget(BudgetDim::Wall),
        ));
    }
    let o = drive_with(
        reads(5),
        FaultPlan::default(),
        |c| c.limits.steps = 2,
        Duration::ZERO,
    );
    cases.push(("step budget".into(), o, StopCause::Budget(BudgetDim::Steps)));
    let mut big = read("a").unwrap();
    big.usage = Some(ServerUsage {
        input: 900,
        output: 200,
    });
    let o = drive_with(
        vec![read("x"), Ok(big), read("b")],
        FaultPlan::default(),
        |c| c.limits.tokens = 1000,
        Duration::ZERO,
    );
    cases.push((
        "token budget".into(),
        o,
        StopCause::Budget(BudgetDim::Tokens),
    ));
    let o = drive(vec![
        Ok(text_reply("no action")),
        Ok(text_reply("still none")),
        Ok(text_reply("none again")),
    ]);
    cases.push(("three format errors".into(), o, StopCause::FormatErrors));
    let o = drive(vec![read("a"), read("a"), read("a"), read("a")]);
    cases.push((
        "repeat detector".into(),
        o,
        StopCause::Loop(LoopKind::Repeat),
    ));
    let o = drive(vec![read("../x"), read("../y"), read("../z")]);
    cases.push((
        "denial detector".into(),
        o,
        StopCause::Loop(LoopKind::Denied),
    ));
    let o = drive(vec![
        read("a"),
        Err(ModelError::Unavailable(Unavailable::ConnectTimeout)),
    ]);
    cases.push(("model unavailable".into(), o, StopCause::ModelUnavailable));
    let o = drive(vec![read("a"), submit()]);
    cases.push(("submit".into(), o, StopCause::Submitted));
    for (what, o, want) in &cases {
        assert_eq!(&o.end.cause, want, "{what}");
        assert_paired(o, what);
    }
}

// ---- H1e-2b: the 80% budget condition and the read log ----------------------------

#[test]
fn the_80_percent_budget_condition_is_journaled_once_on_entry() {
    let o = drive_with(
        (0..6).map(|i| read(&format!("f{i}"))).collect(),
        FaultPlan::default(),
        |c| c.limits.steps = 5,
        Duration::ZERO,
    );
    assert_eq!(o.end.cause, StopCause::Budget(BudgetDim::Steps));
    let v = verify(&o.journal, &o.blobs).unwrap();
    let steps: Vec<(u64, String)> = v
        .records
        .iter()
        .filter(|r| r.kind == EventKind::BudgetCharged)
        .filter(|r| r.body.get("key").and_then(serde_json::Value::as_str) == Some("steps"))
        .map(|r| (r.step, r.body["condition"].as_str().unwrap().to_owned()))
        .collect();
    assert_eq!(
        steps,
        vec![(4, "enter".to_owned())],
        "4 of 5 steps is 80%, journaled once"
    );
}

/// H1g confirming review NF-1: wall time never decreases within an
/// attempt and its limit is fixed, so the wall dimension's 80% condition
/// turns true at most once and never turns false again. A run that
/// crosses 80% of its wall budget and then goes on, over several more
/// steps, to submit writes exactly one wall record, an entry, and no exit
/// (not even at commit); that is all the audit's shape check admits.
#[test]
fn the_wall_condition_is_journaled_once_as_an_entry_and_never_exits() {
    let mut replies: Vec<_> = (0..20).map(|i| read(&format!("f{i}"))).collect();
    replies.push(submit());
    // Every clock read advances 1 s; 21 steps take a little over 60 s, so
    // a 66 s budget is crossed at 80% a few steps before the submit.
    let o = drive_with(
        replies,
        FaultPlan::default(),
        |c| c.limits.wall = Duration::from_secs(66),
        Duration::from_secs(1),
    );
    let v = verify(&o.journal, &o.blobs).unwrap();
    let walls: Vec<(u64, String)> = v
        .records
        .iter()
        .filter(|r| r.kind == EventKind::BudgetCharged)
        .filter(|r| r.body.get("key").and_then(serde_json::Value::as_str) == Some("wall"))
        .map(|r| (r.step, r.body["condition"].as_str().unwrap().to_owned()))
        .collect();
    assert_eq!(o.end.cause, StopCause::Submitted);
    assert_eq!(walls.len(), 1, "{walls:?}");
    assert_eq!(walls[0].1, "enter");
    assert!(
        walls[0].0 + 2 <= o.end.step,
        "crossed at least two steps before the last, so later steps observed it: {walls:?}"
    );
    assert!(matches!(
        crate::replay::compare::check_wall_conditions(&v.records),
        Ok(1)
    ));
}

#[test]
fn the_read_log_refuses_an_edit_to_a_file_never_read_or_changed_since() {
    let mut log = ReadLog::default();
    let d1 = sha256(b"v1");
    assert_eq!(log.check("a.rs", d1), Err(crate::StaleRead::NeverRead));
    log.record("a.rs", d1);
    assert_eq!(log.check("a.rs", d1), Ok(()));
    assert_eq!(
        log.check("a.rs", sha256(b"v2")),
        Err(crate::StaleRead::Changed)
    );
    log.record("a.rs", sha256(b"v2"));
    assert_eq!(log.check("a.rs", sha256(b"v2")), Ok(()));
}

// ---- the environment sample (§7.1) ----------------------------------------------

/// A host under memory pressure: 1% available.
fn pressed() -> EnvSample {
    let mut s = EnvSample::unmeasured(Unmeasured::NoSafeApi);
    s.mem_total_bytes = Reading::Measured {
        value: 1000,
        method: Method::ProcMeminfoTotal,
    };
    s.mem_available_bytes = Reading::Measured {
        value: 10,
        method: Method::ProcMeminfoAvailable,
    };
    s
}

#[test]
fn a_timeout_or_crash_records_the_host_and_flags_pressure() {
    let calm = EnvSample::unmeasured(Unmeasured::NoSafeApi);
    for (what, status, env, sampled, flagged) in [
        (
            "timeout under pressure",
            Some(ToolStatus::Timeout),
            pressed(),
            true,
            true,
        ),
        (
            "crash on a calm host",
            Some(ToolStatus::Crashed { signal: Some(9) }),
            calm,
            true,
            false,
        ),
        // A provider failure is the tool-level "could not run" (§7.1).
        (
            "provider failure under pressure",
            None,
            pressed(),
            true,
            true,
        ),
        (
            "ok under pressure",
            Some(ToolStatus::Ok),
            pressed(),
            false,
            false,
        ),
    ] {
        let o = drive_full(
            vec![read("a.txt"), submit()],
            FaultPlan::default(),
            |_| {},
            Duration::ZERO,
            status,
            &env,
        );
        assert_eq!(o.end.cause, StopCause::Submitted, "{what}");
        let v = verify(&o.journal, &o.blobs).unwrap();
        // The read's result (the sentinel's ToolFinished carries neither an
        // output nor a provider_error status).
        let done: Vec<_> = v
            .records
            .iter()
            .filter(|r| {
                r.kind == EventKind::ToolFinished
                    && (r.body.get("output").is_some()
                        || r.body.get("status").and_then(|s| s.as_str()) == Some("provider_error"))
            })
            .collect();
        assert_eq!(done.len(), 1, "{what}");
        let rec = done[0];
        match rec.body.get("environment") {
            Some(e) => {
                assert!(sampled, "{what}: sampled an ok result");
                assert_eq!(crate::sample::from_value(e), Some(env), "{what}");
            }
            None => assert!(!sampled, "{what}: no sample"),
        }
        let want: Vec<u64> = if flagged { vec![rec.step] } else { Vec::new() };
        assert_eq!(o.pressure, want, "{what}");
        // The sample never changes the outcome.
        assert_eq!(o.released, NOTHING_CHECKED, "{what}");
    }
}

// H2b: an edit that was written but not verified (code UNVERIFIED) may have
// changed the workspace in a way the harness cannot state: the result is
// journaled, then the run stops (PolicyAbort), fail closed, and the model
// is never asked again. Driven through a spy that reports that status for
// the edit (the real engine cannot produce it without another writer).
#[test]
fn h2b_an_unverified_edit_stops_the_run_after_its_result_is_durable() {
    let reg = registry();
    let profile = Profile::conservative_default("m");
    let spec = TaskSpec {
        task: TaskText::new("Edit a.txt.".into()),
        grants: vec!["harness.edit.replace".into()],
        workspace_public: false,
        exec: None,
        presubmit: None,
        protected: Vec::new(),
    };
    let policy = UserPolicy::new(&[], &[], &["harness.edit.replace"]).unwrap();
    let (session, tools) = plan(&spec, &reg, &policy, &profile, false, false).unwrap();
    let backend = ScriptedBackend::new(
        profile.clone(),
        vec![
            action(
                "harness.edit.replace",
                "{\"path\":\"a.txt\",\"old\":\"a\",\"new\":\"b\"}",
            ),
            submit(),
        ],
    );
    let invoked = Rc::new(Cell::new(0));
    let cfg = RunConfig::defaults(1_000_000);
    let file = FaultFile::new(FaultPlan::default());
    let buf = file.buf.clone();
    let blobs = MemBlobs::default();
    let mut w = JournalWriter::start(
        file,
        blobs.clone(),
        Tick(Cell::new(0)),
        RunId::new(9, [1; 10]),
        1,
        Header::new(Ident::of("0.0.1").unwrap()),
    )
    .unwrap();
    let env = EnvSample::unmeasured(Unmeasured::NoSafeApi);
    let mut lp = Loop::new(LoopInit {
        session,
        registry: &reg,
        tools,
        task: &spec.task,
        facts: Vec::new(),
        profile: &profile,
        backend: &backend,
        providers: vec![Box::new(Spy {
            ns: ProviderName::new("harness").unwrap(),
            invoked: invoked.clone(),
            status: Some(ToolStatus::Error {
                code: harness_tools::builtin::code::UNVERIFIED,
            }),
        })],
        meter: new_meter(
            cfg.limits.clone(),
            Box::new(Advancing {
                now: Cell::new(Duration::ZERO),
                step: Duration::ZERO,
            }),
        ),
        detector: harness_core::LoopDetector::new(),
        turns: Vec::new(),
        config: &cfg,
        step: 0,
        nonces: NonceSource::default(),
        feed: std::collections::VecDeque::new(),
        reads: ReadLog::default(),
        tree: harness_core::sha256(b"tree"),
        workspace: None,
        approvals: Approvals::new(&RunId::new(9, [1; 10]), 1, None, Default::default()),
        env: &env,
        pressure: Vec::new(),
        reads_seen: Default::default(),
        todo: None,
        notices: BudgetNotices::live(cfg.limits.wall),
        presubmit: None,
        restore: Default::default(),
        user: None,
    });
    let end = lp.drive(&mut w);
    assert_eq!(end.cause, StopCause::PolicyAbort);
    assert_eq!(end.step, 1, "the model is not asked again");
    assert_eq!(invoked.get(), 1);
    let released = commit(w, &end, None).outcome;
    assert_eq!(released, NOTHING_CHECKED);
    let journal = buf.borrow().clone();
    let v = verify(&journal, &blobs).unwrap();
    let last_finished = v
        .records
        .iter()
        .rev()
        .find(|r| r.kind == EventKind::ToolFinished)
        .unwrap();
    assert_eq!(
        last_finished.body.get("code").and_then(|c| c.as_u64()),
        Some(u64::from(harness_tools::builtin::code::UNVERIFIED))
    );
    assert!(!v.records.iter().any(|r| r.kind == EventKind::EditApplied));
}

// H2d: a command's journal record reads back exactly as the loop wrote it,
// through the real encoding; anything the loop never writes (an extra or
// missing key, a guard the end does not imply, a code on a timeout) reads
// back as nothing, so an audit calls it a divergence.
#[test]
fn h2d_a_command_record_reads_back_exactly_and_nothing_else_does() {
    use harness_journal::{Event, Trusted};
    use harness_tools::{ExecCleanup, ExecEnd, ExecRecord};
    let ends = [
        ExecEnd::Exited(0),
        ExecEnd::Exited(101),
        ExecEnd::Exited(-1),
        ExecEnd::Signaled(9),
        ExecEnd::Signaled(24),
        ExecEnd::Signaled(25),
        ExecEnd::TimedOut,
        ExecEnd::ProcessLimit,
        ExecEnd::ExecFailed,
        ExecEnd::Unknown,
    ];
    let cleanups = [
        ExecCleanup::Confirmed { kills: 0 },
        ExecCleanup::Confirmed { kills: 3 },
        ExecCleanup::Unconfirmed,
    ];
    let file = FaultFile::new(FaultPlan::default());
    let buf = file.buf.clone();
    let blobs = MemBlobs::default();
    let mut w = JournalWriter::start(
        file,
        blobs.clone(),
        Tick(Cell::new(0)),
        RunId::new(1, [0; 10]),
        1,
        Header::new(Ident::of("0.0.1").unwrap()),
    )
    .unwrap();
    let mut written = Vec::new();
    for end in ends {
        for cleanup in cleanups {
            let x = ExecRecord {
                end,
                cleanup,
                stdout_bytes: 12,
                stderr_bytes: 0,
                stdout_cut: false,
                stderr_cut: true,
                elapsed_ms: 345,
                workspace: None,
            };
            w.append(
                1,
                Event::new(EventKind::ToolFinished)
                    .field("status", Trusted::Text("ok"))
                    .field("exec", exec_fields(&x, &[])),
            )
            .unwrap();
            written.push(x);
        }
    }
    let v = verify(&buf.borrow().clone(), &blobs).unwrap();
    let read: Vec<ExecRecord> = v
        .records
        .iter()
        .filter(|r| r.kind == EventKind::ToolFinished)
        .map(|r| parse_exec(&r.body["exec"]).expect("reads back"))
        .collect();
    assert_eq!(read, written);
    // Shapes the loop never writes.
    let good = v
        .records
        .iter()
        .find(|r| r.kind == EventKind::ToolFinished)
        .unwrap()
        .body["exec"]
        .clone();
    let mut extra = good.clone();
    extra["extra"] = serde_json::json!(1);
    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("elapsed_ms");
    let mut guard = good.clone();
    guard["guard"] = serde_json::json!("wall");
    let timed_out = v
        .records
        .iter()
        .find(|r| r.body.get("exec").is_some_and(|e| e["end"] == "timed_out"))
        .unwrap();
    let mut coded = timed_out.body["exec"].clone();
    coded["code"] = serde_json::json!(0);
    let mut unguarded = timed_out.body["exec"].clone();
    unguarded.as_object_mut().unwrap().remove("guard");
    let mut kills_unconfirmed = good.clone();
    kills_unconfirmed["cleanup"] = serde_json::json!("unconfirmed");
    for (what, bad) in [
        ("an extra key", extra),
        ("a missing key", missing),
        ("a guard the end does not imply", guard),
        ("a code on a timeout", coded),
        ("a timeout without its guard", unguarded),
        ("kills on an unconfirmed cleanup", kills_unconfirmed),
    ] {
        assert!(parse_exec(&bad).is_none(), "{what}: {bad}");
    }
}

// P-36h: the loopback ports a command may reach (`connect`, P-36 §6.2) are
// in the exec record only when non-empty, so a journal from a build before
// background processes encodes byte for byte the same body.

#[test]
fn exec_record_connect_absent_when_empty_digest_unchanged() {
    use harness_journal::Trusted;
    use harness_tools::{ExecCleanup, ExecEnd, ExecRecord};
    // The body the loop wrote before background processes existed,
    // hand-written field for field (the pre-P-36h `exec_fields`).
    let old_body = |x: &ExecRecord| -> Trusted {
        let mut f = vec![(
            "end",
            Trusted::Text(match x.end {
                ExecEnd::Exited(_) => "exited",
                ExecEnd::Signaled(_) => "signaled",
                ExecEnd::TimedOut => "timed_out",
                ExecEnd::ProcessLimit => "process_limit",
                ExecEnd::ExecFailed => "exec_failed",
                ExecEnd::Unknown => "unknown",
            }),
        )];
        match x.end {
            ExecEnd::Exited(c) => f.push(("code", Trusted::I64(i64::from(c)))),
            ExecEnd::Signaled(n) => f.push(("signal", Trusted::I64(i64::from(n)))),
            _ => {}
        }
        if let Some(g) = x.end.guard() {
            f.push(("guard", Trusted::Text(g)));
        }
        match x.cleanup {
            ExecCleanup::Confirmed { kills } => {
                f.push(("cleanup", Trusted::Text("confirmed")));
                f.push(("kills", Trusted::U64(u64::from(kills))));
            }
            ExecCleanup::Unconfirmed => f.push(("cleanup", Trusted::Text("unconfirmed"))),
        }
        f.extend([
            ("stdout_bytes", Trusted::U64(x.stdout_bytes)),
            ("stderr_bytes", Trusted::U64(x.stderr_bytes)),
            ("stdout_cut", Trusted::Bool(x.stdout_cut)),
            ("stderr_cut", Trusted::Bool(x.stderr_cut)),
            ("elapsed_ms", Trusted::U64(x.elapsed_ms)),
        ]);
        Trusted::Obj(f)
    };
    let ends = [
        ExecEnd::Exited(0),
        ExecEnd::Signaled(9),
        ExecEnd::TimedOut,
        ExecEnd::ProcessLimit,
        ExecEnd::ExecFailed,
        ExecEnd::Unknown,
    ];
    let cleanups = [
        ExecCleanup::Confirmed { kills: 0 },
        ExecCleanup::Confirmed { kills: 2 },
        ExecCleanup::Unconfirmed,
    ];
    for end in ends {
        for cleanup in cleanups {
            let x = ExecRecord {
                end,
                cleanup,
                stdout_bytes: 12,
                stderr_bytes: 0,
                stdout_cut: false,
                stderr_cut: true,
                elapsed_ms: 345,
                workspace: None,
            };
            // No ports: the body is exactly the old one, byte for byte
            // (identical field list, order included), so the record hash
            // of an old journal is unchanged.
            assert_eq!(exec_fields(&x, &[]), old_body(&x));
        }
    }
    // Ports held by live ids: `connect` sits after the cleanup fields and
    // before the byte counts, and the record reads back whole.
    let x = ExecRecord {
        end: ExecEnd::Exited(0),
        cleanup: ExecCleanup::Confirmed { kills: 1 },
        stdout_bytes: 5,
        stderr_bytes: 6,
        stdout_cut: false,
        stderr_cut: false,
        elapsed_ms: 7,
        workspace: None,
    };
    let connected = Trusted::Obj(vec![
        ("end", Trusted::Text("exited")),
        ("code", Trusted::I64(0)),
        ("cleanup", Trusted::Text("confirmed")),
        ("kills", Trusted::U64(1)),
        (
            "connect",
            Trusted::List(vec![Trusted::U64(5173), Trusted::U64(8000)]),
        ),
        ("stdout_bytes", Trusted::U64(5)),
        ("stderr_bytes", Trusted::U64(6)),
        ("stdout_cut", Trusted::Bool(false)),
        ("stderr_cut", Trusted::Bool(false)),
        ("elapsed_ms", Trusted::U64(7)),
    ]);
    assert_eq!(exec_fields(&x, &[5173, 8000]), connected);
    // The connected record round-trips through the real encoding ...
    let file = FaultFile::new(FaultPlan::default());
    let buf = file.buf.clone();
    let blobs = MemBlobs::default();
    let mut w = JournalWriter::start(
        file,
        blobs.clone(),
        Tick(Cell::new(0)),
        RunId::new(1, [0; 10]),
        1,
        Header::new(Ident::of("0.0.1").unwrap()),
    )
    .unwrap();
    use harness_journal::Event;
    w.append(
        1,
        Event::new(EventKind::ToolFinished)
            .field("status", Trusted::Text("ok"))
            .field("exec", exec_fields(&x, &[5173, 8000])),
    )
    .unwrap();
    let v = verify(&buf.borrow().clone(), &blobs).unwrap();
    let json = v.records[1].body["exec"].clone();
    assert_eq!(parse_exec(&json), Some(x));
    // ... and `connect: []` is a shape the loop never writes: refused.
    let mut empty = json.clone();
    empty
        .as_object_mut()
        .unwrap()
        .insert("connect".into(), serde_json::json!([]));
    assert!(parse_exec(&empty).is_none());
}

// P-36h: a background tool's `bg` record (P-36 §10.2) reads back exactly as
// the tools write it, every op, through the real encoding; anything the
// tools never write reads back as nothing, so an audit calls it a
// divergence.

#[test]
fn tool_finished_bg_record_round_trip_every_op() {
    use crate::driver::tools::{
        BgListItem, BgRead, BgReadMode, BgReady, BgReadyKind, BgRecord, BgScope, BgStart,
        BgStartState, BgState, BgStop, BgWindow,
    };
    use harness_journal::{Event, Trusted};
    use harness_tools::{ExecCleanup, ExecEnd};
    let window = |since: u64, total: u64, dropped: u64, bytes: &[u8]| BgWindow {
        since,
        from: since + dropped,
        to: total,
        dropped,
        skipped: 0,
        total,
        sha: sha256(bytes),
    };
    let records = vec![
        BgRecord::Start(BgStart {
            id: 1,
            state: BgStartState::Running,
            ports: vec![5173, 8000],
            lan: vec![8000],
            scope: BgScope::Turn,
            lifetime_s: 1800,
            ready: Some(BgReady {
                kind: BgReadyKind::Port,
                met: true,
                waited_ms: 12,
            }),
        }),
        BgRecord::Start(BgStart {
            id: 2,
            state: BgStartState::ExecFailed,
            ports: Vec::new(),
            lan: Vec::new(),
            scope: BgScope::Session,
            lifetime_s: 60,
            ready: None,
        }),
        BgRecord::Read(BgRead {
            id: 1,
            mode: BgReadMode::Next,
            state: BgState::Running,
            out: window(0, 4096, 0, b"out bytes"),
            err: window(100, 2128, 1024, b"err bytes"),
            ended: None,
        }),
        BgRecord::Read(BgRead {
            id: 1,
            mode: BgReadMode::Tail,
            state: BgState::Exited,
            out: window(4096, 8192, 0, b"later out"),
            err: window(2128, 2128, 0, b""),
            ended: Some((ExecEnd::Exited(0), ExecCleanup::Confirmed { kills: 2 })),
        }),
        BgRecord::List(vec![
            BgListItem {
                id: 1,
                state: BgState::Exited,
                ports: vec![5173],
                pending_out: 0,
                pending_err: 0,
            },
            BgListItem {
                id: 2,
                state: BgState::Running,
                ports: Vec::new(),
                pending_out: 40,
                pending_err: 2,
            },
        ]),
        BgRecord::Stop(BgStop {
            id: 2,
            end: ExecEnd::Signaled(15),
            cleanup: ExecCleanup::Unconfirmed,
            out: window(0, 512, 0, b"stop out"),
            err: window(0, 0, 0, b""),
            out_total: 512,
            err_total: 0,
            out_sha: sha256(b"every out byte"),
            err_sha: sha256(b""),
        }),
    ];
    let file = FaultFile::new(FaultPlan::default());
    let buf = file.buf.clone();
    let blobs = MemBlobs::default();
    let mut w = JournalWriter::start(
        file,
        blobs.clone(),
        Tick(Cell::new(0)),
        RunId::new(1, [0; 10]),
        1,
        Header::new(Ident::of("0.0.1").unwrap()),
    )
    .unwrap();
    for r in &records {
        w.append(
            1,
            Event::new(EventKind::ToolFinished)
                .field("status", Trusted::Text("ok"))
                .field("bg", bg_fields(r)),
        )
        .unwrap();
    }
    let v = verify(&buf.borrow().clone(), &blobs).unwrap();
    let read: Vec<BgRecord> = v
        .records
        .iter()
        .filter(|r| r.kind == EventKind::ToolFinished)
        .map(|r| parse_bg(&r.body["bg"]).expect("reads back"))
        .collect();
    assert_eq!(read, records);
    // Shapes the tools never write.
    let good = v
        .records
        .iter()
        .find(|r| r.kind == EventKind::ToolFinished && r.body["bg"]["op"] == "stop")
        .unwrap()
        .body["bg"]
        .clone();
    let mut extra = good.clone();
    extra["extra"] = serde_json::json!(1);
    let mut missing = good.clone();
    missing.as_object_mut().unwrap().remove("out_sha");
    let mut bad_sha = good.clone();
    bad_sha["out_sha"] = serde_json::json!("nothex");
    let mut window_extra = good.clone();
    window_extra["out"]["extra"] = serde_json::json!(0);
    let mut unknown_op = good.clone();
    unknown_op["op"] = serde_json::json!("peek");
    let read_ended = v
        .records
        .iter()
        .find(|r| {
            r.kind == EventKind::ToolFinished
                && r.body["bg"]["op"] == "read"
                && r.body["bg"].get("end").is_some()
        })
        .unwrap()
        .body["bg"]
        .clone();
    let mut no_cleanup = read_ended.clone();
    no_cleanup.as_object_mut().unwrap().remove("cleanup");
    let mut cleanup_without_end = read_ended.clone();
    cleanup_without_end.as_object_mut().unwrap().remove("end");
    let mut bad_state = read_ended.clone();
    bad_state["state"] = serde_json::json!("zombie");
    for (what, bad) in [
        ("an extra key", extra),
        ("a missing key", missing),
        ("a digest that is not hex", bad_sha),
        ("a window with an extra key", window_extra),
        ("an op the tools do not have", unknown_op),
        ("an ended read without its cleanup", no_cleanup),
        ("a cleanup without an end", cleanup_without_end),
        ("a state the loop never writes", bad_state),
    ] {
        assert!(parse_bg(&bad).is_none(), "{what}: {bad}");
    }
}
