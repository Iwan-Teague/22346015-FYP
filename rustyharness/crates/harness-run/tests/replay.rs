//! Audit replay (INV-20) and resume (§2.10) over real journals on disk.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::{Path, PathBuf};

use gate_outcome::{GateOutcome, IndeterminateKind};
use harness_core::environment::{EnvSample, Unmeasured};
use harness_core::{MeterLimits, RunId, StopCause};
use harness_journal::canon::{RecordFields, GENESIS};
use harness_journal::{layout, EventKind, JournalReader};
use harness_model::profile::Profile;
use harness_model::scripted::ScriptedBackend;
use harness_model::{Completion, TaskText};
use harness_policy::locality::{FsQuery, LocalityProbe};
use harness_policy::UserPolicy;
use harness_run::{
    audit, resume, run, Audit, Resume, Run, RunConfig, RunRefused, RunReport, TaskSpec,
};
use harness_testkit::{act, run_scripted, submit, Fixture, Local};
use serde_json::Value;

/// A fixed environment sample (the real probe is harness-sandbox's; these
/// tests only need the header and records to carry one).
const FIXED_ENV: EnvSample = EnvSample::unmeasured(Unmeasured::NoSafeApi);

/// A fixture with the two files and the task every replay here starts from.
fn fx(name: &str) -> Fixture {
    let mut fx = Fixture::new(&format!("replay-{name}")).unwrap();
    fx.write("a.txt", "alpha\n").unwrap();
    fx.write("b.txt", "beta\n").unwrap();
    fx.spec = spec(TASK);
    fx
}

fn read(p: &str) -> Completion {
    act("harness.fs.read", &format!("{{\"path\":\"{p}\"}}"))
}

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

fn go(fx: &Fixture, replies: Vec<Completion>) -> RunReport {
    run_scripted(fx, replies).unwrap()
}

/// The limits every run and resume in this file is given (`go`,
/// `resume_with`), which an audit must be given too (review F-1).
fn limits() -> MeterLimits {
    RunConfig::defaults(1_000_000).limits
}

fn audit_with(
    fx: &Fixture,
    run: &RunId,
    attempt: Option<u32>,
    task: &str,
    policy: &UserPolicy,
) -> harness_run::AuditReport {
    audit(Audit {
        state_root: fx.state_root(),
        run,
        attempt,
        anchor: None,
        spec: &spec(task),
        registry: &harness_testkit::registry().unwrap(),
        policy,
        profile: &Profile::conservative_default("m"),
        limits: &limits(),
    })
    .unwrap()
}

const TASK: &str = "Summarise a.txt and b.txt.";
const UNREADABLE: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::UnreadableEvidence,
};

fn journal_path(r: &RunReport, attempt: u32) -> PathBuf {
    layout::attempt_dir(&r.run_dir, attempt).join(layout::JOURNAL_FILE)
}

/// Rewrite a journal with `edit` applied to one record's body, and
/// recompute every hash after it: a forger who re-chains. Only an anchor
/// or the replay itself can catch this.
fn rechain(path: &Path, pick: impl Fn(&Value) -> bool, edit: impl Fn(&mut Value)) {
    let text = fs::read_to_string(path).unwrap();
    let mut prev = GENESIS;
    let mut out = Vec::new();
    let mut edited = false;
    for line in text.lines() {
        let mut v: Value = serde_json::from_str(line).unwrap();
        if !edited && pick(&v) {
            edit(v.get_mut("body").unwrap());
            edited = true;
        }
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
    assert!(edited, "nothing matched the edit");
    fs::write(path, out).unwrap();
}

fn kind_is(k: &'static str) -> impl Fn(&Value) -> bool {
    move |v| v["kind"] == k
}

// ---- audit ------------------------------------------------------------------------

#[test]
fn inv_20_a_clean_replay_recomputes_every_record_and_matches() {
    let fx = fx("clean");
    let r = go(&fx, vec![read("a.txt"), read("b.txt"), submit()]);
    assert_eq!(r.cause, StopCause::Submitted);
    let a = audit_with(&fx, &r.run, None, TASK, &UserPolicy::default());
    assert_eq!(a.divergence, None);
    assert_eq!(
        a.outcome,
        GateOutcome::Indeterminate {
            why: IndeterminateKind::NothingChecked
        }
    );
    let recorded = JournalReader::open(&layout::attempt_dir(&r.run_dir, 1)).unwrap();
    assert_eq!(
        a.matched,
        recorded.records.len() - 1,
        "every record but the header"
    );
    let dir = a.replay_dir.unwrap();
    assert_eq!(dir, layout::replay_dir(&r.run_dir, 1));
    // The recorded attempt is untouched; a second audit gets replay-2.
    let again = audit_with(&fx, &r.run, Some(1), TASK, &UserPolicy::default());
    assert_eq!(again.replay_dir.unwrap(), layout::replay_dir(&r.run_dir, 2));
}

#[test]
fn inv_20_an_edited_reply_that_breaks_the_chain_is_unreadable() {
    let fx = fx("edited-bytes");
    let r = go(&fx, vec![read("a.txt"), submit()]);
    let p = journal_path(&r, 1);
    let t = fs::read_to_string(&p)
        .unwrap()
        .replacen("a.txt", "b.txt", 1);
    fs::write(&p, t).unwrap();
    let a = audit_with(&fx, &r.run, None, TASK, &UserPolicy::default());
    assert_eq!(a.outcome, UNREADABLE);
    assert!(a.divergence.unwrap().why.contains("does not verify"));
}

#[test]
fn inv_20_a_re_chained_edited_reply_is_caught_by_the_replay() {
    let fx = fx("edited-reply");
    let r = go(&fx, vec![read("a.txt"), read("b.txt"), submit()]);
    // The model's first reply now asks for b.txt; the hashes are re-chained,
    // so the journal verifies. The replay recomputes the parse from the
    // edited reply and the recorded ActionParsed no longer follows.
    rechain(&journal_path(&r, 1), kind_is("ModelReplied"), |b| {
        let c = b["content"]["inline"]
            .as_str()
            .unwrap()
            .replace("a.txt", "b.txt");
        b["content"]["inline"] = Value::from(c.clone());
        b["content"]["sha256"] = Value::from(harness_core::sha256(c.as_bytes()).to_string());
    });
    assert!(JournalReader::open(&layout::attempt_dir(&r.run_dir, 1)).is_ok());
    let a = audit_with(&fx, &r.run, None, TASK, &UserPolicy::default());
    assert_eq!(a.outcome, UNREADABLE);
    let d = a.divergence.unwrap();
    assert_eq!(d.step, 1);
    assert!(d.why.contains("different body"), "{d:?}");
}

#[test]
fn inv_20_a_re_chained_edited_policy_decision_is_caught_by_the_replay() {
    let fx = fx("edited-policy");
    let r = go(&fx, vec![read("a.txt"), submit()]);
    rechain(&journal_path(&r, 1), kind_is("PolicyDecided"), |b| {
        b["rule"] = Value::from("allow.something-else");
    });
    let a = audit_with(&fx, &r.run, None, TASK, &UserPolicy::default());
    assert_eq!(a.outcome, UNREADABLE);
    let d = a.divergence.unwrap();
    assert_eq!(d.step, 1);
    assert!(d.why.contains("different body"), "{d:?}");
}

#[test]
fn inv_20_replaying_under_another_policy_or_task_is_refused_at_the_header() {
    let fx = fx("other-inputs");
    let r = go(&fx, vec![read("a.txt"), submit()]);
    let deny = UserPolicy::new(&["harness.fs.read"], &[], &[]).unwrap();
    let a = audit_with(&fx, &r.run, None, TASK, &deny);
    assert_eq!(a.outcome, UNREADABLE);
    assert_eq!(a.divergence.as_ref().unwrap().seq, 0);
    let a = audit_with(&fx, &r.run, None, "Another task.", &UserPolicy::default());
    assert_eq!(a.divergence.unwrap().seq, 0);
}

#[test]
fn inv_20_a_journal_from_another_run_is_refused() {
    let fx = fx("other-run");
    let a_run = go(&fx, vec![read("a.txt"), submit()]);
    // A run directory for another id whose attempt-1 is run A's journal:
    // the attempt number fits, the run id does not.
    let other = RunId::new(1, [7; 10]);
    let to = layout::attempt_dir(
        &layout::run_dir(&fs::canonicalize(fx.state_root()).unwrap(), &other),
        1,
    );
    fs::create_dir_all(to.join(layout::BLOBS_DIR)).unwrap();
    let from = layout::attempt_dir(&a_run.run_dir, 1);
    fs::copy(
        from.join(layout::JOURNAL_FILE),
        to.join(layout::JOURNAL_FILE),
    )
    .unwrap();
    let a = audit_with(&fx, &other, Some(1), TASK, &UserPolicy::default());
    assert_eq!(a.outcome, UNREADABLE);
    assert!(a.divergence.unwrap().why.contains("another run"));
}

#[test]
fn inv_20_an_anchor_catches_a_replaced_journal() {
    let fx = fx("anchor");
    let r = go(&fx, vec![read("a.txt"), submit()]);
    let head = r.chain_head.unwrap();
    let with_anchor = |anchor| {
        audit(Audit {
            state_root: fx.state_root(),
            run: &r.run,
            attempt: None,
            anchor: Some(anchor),
            spec: &fx.spec,
            registry: &harness_testkit::registry().unwrap(),
            policy: &UserPolicy::default(),
            profile: &Profile::conservative_default("m"),
            limits: &limits(),
        })
        .unwrap()
    };
    assert_eq!(with_anchor(head).divergence, None);
    let a = with_anchor(harness_core::sha256(b"another head"));
    assert_eq!(a.outcome, UNREADABLE);
    assert!(a.divergence.unwrap().why.contains("anchor"));
}

// ---- H1e-2b review F-1: a wall stop is not recomputable ----------------------------

/// A forger's journal: every record of steps <= `last_step` kept, the rest
/// and the real `RunStopped` dropped, a forged `RunStopped{budget, wall}`
/// appended, and every hash recomputed.
fn truncate_and_forge_wall_stop(path: &Path, last_step: u64) {
    let text = fs::read_to_string(path).unwrap();
    let mut prev = GENESIS;
    let mut out = Vec::new();
    let mut last: Option<Value> = None;
    for line in text.lines() {
        let v: Value = serde_json::from_str(line).unwrap();
        if v["step"].as_u64().unwrap() > last_step || v["kind"] == "RunStopped" {
            continue;
        }
        last = Some(v.clone());
        let (bytes, hash) = fields(&v, prev, None).encode();
        out.extend(bytes);
        out.push(b'\n');
        prev = hash;
    }
    let mut stop = last.unwrap();
    stop["seq"] = Value::from(stop["seq"].as_u64().unwrap() + 1);
    stop["kind"] = Value::from("RunStopped");
    let body = serde_json::json!({
        "cause": "budget",
        "dimension": "wall",
        "outcome": "indeterminate:nothing_checked"
    });
    let (bytes, _) = fields(&stop, prev, Some(body)).encode();
    out.extend(bytes);
    out.push(b'\n');
    fs::write(path, out).unwrap();
}

fn fields(v: &Value, prev: harness_core::Digest, body: Option<Value>) -> RecordFields {
    RecordFields {
        seq: v["seq"].as_u64().unwrap(),
        prev,
        t_mono_ms: v["t_mono_ms"].as_u64().unwrap(),
        t_wall: v["t_wall"].as_str().unwrap().to_owned(),
        run: RunId::parse(v["run"].as_str().unwrap()).unwrap(),
        attempt: u32::try_from(v["attempt"].as_u64().unwrap()).unwrap(),
        step: v["step"].as_u64().unwrap(),
        kind: EventKind::parse(v["kind"].as_str().unwrap()).unwrap(),
        body: body
            .unwrap_or_else(|| v["body"].clone())
            .as_object()
            .unwrap()
            .clone(),
    }
}

fn audit_anchored(
    fx: &Fixture,
    run: &RunId,
    anchor: Option<harness_core::Digest>,
) -> harness_run::AuditReport {
    audit_given(fx, run, anchor, &limits())
}

/// [`audit_anchored`] with the limits the audit is given.
fn audit_given(
    fx: &Fixture,
    run: &RunId,
    anchor: Option<harness_core::Digest>,
    limits: &MeterLimits,
) -> harness_run::AuditReport {
    audit(Audit {
        state_root: fx.state_root(),
        run,
        attempt: None,
        anchor,
        spec: &spec(TASK),
        registry: &harness_testkit::registry().unwrap(),
        policy: &UserPolicy::default(),
        profile: &Profile::conservative_default("m"),
        limits,
    })
    .unwrap()
}

#[test]
fn f_1_a_truncated_journal_with_a_forged_wall_stop_is_never_reported_verified() {
    let fx = fx("forged-wall");
    let r = go(&fx, vec![read("a.txt"), read("b.txt"), submit()]);
    let genuine = r.chain_head.unwrap();
    // Keep step 1, drop steps 2-3 and the real stop, forge a wall stop.
    truncate_and_forge_wall_stop(&journal_path(&r, 1), 1);
    let v = JournalReader::open(&layout::attempt_dir(&r.run_dir, 1)).unwrap();
    assert!(v.is_complete(), "the forged journal verifies");
    // Without an anchor: every remaining record matches, but the stop is
    // not recomputable, so the audit does not vouch for the journal.
    let a = audit_anchored(&fx, &r.run, None);
    assert_eq!(a.divergence, None);
    assert!(!a.stop_recomputed);
    assert_eq!(
        a.outcome, UNREADABLE,
        "a forged wall stop must not pass as verified"
    );
    // With the genuine run's anchor, the truncation is caught outright.
    let a = audit_anchored(&fx, &r.run, Some(genuine));
    assert_eq!(a.outcome, UNREADABLE);
    assert!(a.divergence.unwrap().why.contains("anchor"));
}

#[test]
fn f_1_a_genuine_wall_stop_passes_only_with_its_anchor() {
    let fx = fx("genuine-wall");
    let profile = Profile::conservative_default("m");
    let backend = ScriptedBackend::new(
        profile.clone(),
        vec![read("a.txt"), read("b.txt"), submit()]
            .into_iter()
            .map(Ok)
            .collect(),
    );
    let mut config = RunConfig::defaults(1_000_000);
    config.limits.wall = std::time::Duration::from_nanos(1);
    let r = run(Run {
        state_root: fx.state_root(),
        workspace: fx.workspace(),
        spec: &fx.spec,
        registry: &harness_testkit::registry().unwrap(),
        policy: &UserPolicy::default(),
        profile: &profile,
        backend: &backend,
        probe: &Local,
        env: &FIXED_ENV,
        config: &config,
        approver: None,
        confinement: None,
    })
    .unwrap();
    assert_eq!(r.cause, StopCause::Budget(harness_core::BudgetDim::Wall));
    // The audit is given the limits this run was given (review F-1).
    let a = audit_given(&fx, &r.run, None, &config.limits);
    assert!(!a.stop_recomputed);
    assert_eq!(
        a.outcome, UNREADABLE,
        "without an anchor a wall stop is not verified"
    );
    let a = audit_given(&fx, &r.run, r.chain_head, &config.limits);
    assert!(a.anchored && !a.stop_recomputed);
    assert_eq!(a.divergence, None);
    assert_eq!(
        a.outcome,
        GateOutcome::Indeterminate {
            why: IndeterminateKind::NothingChecked
        }
    );
}

#[test]
fn f_1_a_recomputed_stop_is_verified_without_an_anchor() {
    let fx = fx("recomputed-stop");
    let r = go(&fx, vec![read("a.txt"), submit()]);
    let a = audit_anchored(&fx, &r.run, None);
    assert!(a.stop_recomputed && !a.anchored);
    assert_eq!(
        a.outcome,
        GateOutcome::Indeterminate {
            why: IndeterminateKind::NothingChecked
        }
    );
}

// ---- resume ------------------------------------------------------------------------

/// Cut a committed journal back to its records of steps < `keep_below`
/// (a crash: whole lines survive, `RunStopped` is gone).
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

/// Cut a committed journal inside step `step`, just before its first record
/// of kind `kind` (a crash mid-step: e.g. before `ToolFinished`, leaving
/// the step's intent without its result).
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

fn resume_with(
    fx: &Fixture,
    run: &RunId,
    replies: Vec<Completion>,
) -> Result<RunReport, RunRefused> {
    resume_under(fx, run, &RunConfig::defaults(1_000_000), replies)
}

/// [`resume_with`] under the given budgets and timeouts.
fn resume_under(
    fx: &Fixture,
    run: &RunId,
    config: &RunConfig,
    replies: Vec<Completion>,
) -> Result<RunReport, RunRefused> {
    let profile = Profile::conservative_default("m");
    let backend = ScriptedBackend::new(profile.clone(), replies.into_iter().map(Ok).collect());
    resume(Resume {
        state_root: fx.state_root(),
        run,
        workspace: fx.workspace(),
        spec: &fx.spec,
        registry: &harness_testkit::registry().unwrap(),
        policy: &UserPolicy::default(),
        profile: &profile,
        backend: &backend,
        probe: &Local,
        env: &FIXED_ENV,
        config,
        approver: None,
        confinement: None,
    })
}

#[test]
fn resume_continues_in_a_new_attempt_and_re_runs_the_cut_step_live() {
    let fx = fx("resume");
    let r = go(&fx, vec![read("a.txt"), read("b.txt"), submit()]);
    // Crash in step 2 before its result: its intent survives without a
    // `ToolFinished`, and step 3 and RunStopped do not.
    crash_in(&journal_path(&r, 1), 2, "ToolFinished");
    let before = fs::read(journal_path(&r, 1)).unwrap();
    let old = JournalReader::open(&layout::attempt_dir(&r.run_dir, 1)).unwrap();
    // Step 1 is replayed from the journal; step 2 runs again live, then 3.
    let res = resume_with(&fx, &r.run, vec![read("b.txt"), submit()]).unwrap();
    assert_eq!(res.attempt, 2);
    assert_eq!(res.steps, 3, "step 1 replayed, steps 2 and 3 live");
    assert_eq!(res.cause, StopCause::Submitted);
    assert_eq!(
        res.outcome,
        GateOutcome::Indeterminate {
            why: IndeterminateKind::NothingChecked
        }
    );
    assert_eq!(
        fs::read(journal_path(&r, 1)).unwrap(),
        before,
        "attempt-1 is only read"
    );
    let new = JournalReader::open(&layout::attempt_dir(&r.run_dir, 2)).unwrap();
    let from = &new.records[0].body["resumed_from"];
    assert_eq!(from["attempt"], 1);
    assert_eq!(from["chain_head"], Value::from(old.head.to_string()));
    // Step 1 of the new attempt is the recorded step 1, record for record.
    let body = |v: &harness_journal::Verified, s: u64| -> Vec<(EventKind, Value)> {
        v.records
            .iter()
            .filter(|x| x.step == s)
            .map(|x| (x.kind, Value::Object(x.body.clone())))
            .collect()
    };
    assert_eq!(body(&new, 1), body(&old, 1));
    // And the resumed attempt itself audits clean.
    let a = audit_with(&fx, &r.run, Some(2), TASK, &UserPolicy::default());
    assert_eq!(a.divergence, None, "{a:?}");
}

/// H2b (the H1e-2b row's H2 condition): a step whose call has a durable
/// `ToolFinished` is complete, so resume re-feeds it and never runs it
/// again; only the next step runs live.
#[test]
fn resume_re_feeds_a_completed_last_step_and_runs_only_the_next_live() {
    let fx = fx("resume-completed");
    let r = go(&fx, vec![read("a.txt"), read("b.txt"), submit()]);
    // Crash after step 2 finished: its result is durable, step 3 is gone.
    crash_after(&journal_path(&r, 1), 3);
    let old = JournalReader::open(&layout::attempt_dir(&r.run_dir, 1)).unwrap();
    let res = resume_with(&fx, &r.run, vec![submit()]).unwrap();
    assert_eq!(res.attempt, 2);
    assert_eq!(res.steps, 3, "steps 1 and 2 replayed, step 3 live");
    assert_eq!(res.cause, StopCause::Submitted);
    let new = JournalReader::open(&layout::attempt_dir(&r.run_dir, 2)).unwrap();
    let body = |v: &harness_journal::Verified, s: u64| -> Vec<(EventKind, Value)> {
        v.records
            .iter()
            .filter(|x| x.step == s)
            .map(|x| (x.kind, Value::Object(x.body.clone())))
            .collect()
    };
    assert_eq!(body(&new, 1), body(&old, 1));
    assert_eq!(body(&new, 2), body(&old, 2), "step 2 re-fed, not re-run");
    let a = audit_with(&fx, &r.run, Some(2), TASK, &UserPolicy::default());
    assert_eq!(a.divergence, None, "{a:?}");
}

#[test]
fn resume_refuses_a_stopped_run_a_changed_workspace_and_changed_inputs() {
    let mut fx = fx("resume-refusals");
    let r = go(&fx, vec![read("a.txt"), read("b.txt"), submit()]);
    let e = resume_with(&fx, &r.run, vec![]).unwrap_err();
    assert!(matches!(e, RunRefused::NotResumable(ref w) if w.contains("already stopped")));

    crash_after(&journal_path(&r, 1), 3);
    let original = std::mem::replace(&mut fx.spec, spec("Another task."));
    let e = resume_with(&fx, &r.run, vec![]).unwrap_err();
    assert!(
        matches!(e, RunRefused::NotResumable(ref w) if w.contains("differ")),
        "{e:?}"
    );
    fx.spec = original;

    fx.write("a.txt", "changed\n").unwrap();
    let e = resume_with(&fx, &r.run, vec![]).unwrap_err();
    assert!(
        matches!(e, RunRefused::NotResumable(ref w) if w.contains("workspace differs")),
        "{e:?}"
    );
    assert!(
        !layout::attempt_dir(&r.run_dir, 2).exists(),
        "nothing was written"
    );
}

#[test]
fn a_catch_up_that_diverges_makes_the_resumed_run_unreadable() {
    let fx = fx("resume-diverge");
    let r = go(
        &fx,
        vec![read("a.txt"), read("b.txt"), read("a.txt"), submit()],
    );
    crash_after(&journal_path(&r, 1), 4);
    // Re-chain an edit of the step-1 reply: step 2's request no longer
    // renders to its recorded digest during the catch-up.
    rechain(&journal_path(&r, 1), kind_is("ModelReplied"), |b| {
        let c = b["content"]["inline"]
            .as_str()
            .unwrap()
            .replace("a.txt", "b.txt");
        b["content"]["inline"] = Value::from(c.clone());
        b["content"]["sha256"] = Value::from(harness_core::sha256(c.as_bytes()).to_string());
    });
    let res = resume_with(&fx, &r.run, vec![submit()]).unwrap();
    assert_eq!(res.outcome, UNREADABLE);
    assert_eq!(res.cause, StopCause::ModelUnavailable);
}

#[test]
fn a_resumed_attempt_is_charged_the_wall_time_already_spent() {
    let fx = fx("resume-wall");
    let r = go(&fx, vec![read("a.txt"), read("b.txt"), submit()]);
    crash_after(&journal_path(&r, 1), 3);
    // The interrupted attempt's writer had been running for 3 hours (its
    // last record's monotonic time) against the default 30-minute budget.
    let path = journal_path(&r, 1);
    let text = fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let (last, body) = lines.split_last().unwrap();
    let mut prev = GENESIS;
    let mut out = String::new();
    for l in body {
        let v: Value = serde_json::from_str(l).unwrap();
        prev = fields(&v, prev, None).encode().1;
        out.push_str(l);
        out.push('\n');
    }
    let mut v: Value = serde_json::from_str(last).unwrap();
    v["t_mono_ms"] = Value::from(3u64 * 3600 * 1000);
    let (bytes, _) = fields(&v, prev, None).encode();
    out.push_str(std::str::from_utf8(&bytes).unwrap());
    out.push('\n');
    fs::write(&path, out).unwrap();
    let res = resume_with(&fx, &r.run, vec![read("b.txt"), submit()]).unwrap();
    assert_eq!(res.attempt, 2);
    assert_eq!(res.cause, StopCause::Budget(harness_core::BudgetDim::Wall));
}

/// Re-write a journal with its last record's monotonic time set to `ms`
/// (the writer's elapsed time when it stopped), re-chained.
fn set_last_mono(path: &Path, ms: u64) {
    let text = fs::read_to_string(path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let (last, body) = lines.split_last().unwrap();
    let mut prev = GENESIS;
    let mut out = String::new();
    for l in body {
        let v: Value = serde_json::from_str(l).unwrap();
        prev = fields(&v, prev, None).encode().1;
        out.push_str(l);
        out.push('\n');
    }
    let mut v: Value = serde_json::from_str(last).unwrap();
    v["t_mono_ms"] = Value::from(ms);
    out.push_str(std::str::from_utf8(&fields(&v, prev, None).encode().0).unwrap());
    out.push('\n');
    fs::write(path, out).unwrap();
}

/// H1e-2b confirming review NF-1: crash, resume, crash, resume charges the
/// wall time of BOTH earlier attempts, not only the latest one.
#[test]
fn nf_1_chained_resumes_are_charged_every_earlier_attempts_wall_time() {
    let fx = fx("resume-chain");
    let twenty_min = 20 * 60 * 1000;
    let r = go(&fx, vec![read("a.txt"), read("b.txt"), submit()]);
    crash_after(&journal_path(&r, 1), 3);
    set_last_mono(&journal_path(&r, 1), twenty_min);
    // 20 of 30 minutes spent: the first resume runs to its end.
    let second = resume_with(&fx, &r.run, vec![read("b.txt"), submit()]).unwrap();
    assert_eq!(
        (second.attempt, second.cause.clone()),
        (2, StopCause::Submitted)
    );
    let h2 = JournalReader::open(&layout::attempt_dir(&r.run_dir, 2)).unwrap();
    assert_eq!(
        h2.records[0].body["resumed_from"]["wall_carried_ms"],
        twenty_min
    );
    // Attempt 2 crashes after another 20 minutes of its own.
    crash_after(&journal_path(&r, 2), 3);
    set_last_mono(&journal_path(&r, 2), twenty_min);
    // 40 of 30 minutes: the second resume must stop on the wall budget at once.
    let third = resume_with(&fx, &r.run, vec![read("b.txt"), submit()]).unwrap();
    assert_eq!(third.attempt, 3);
    let h3 = JournalReader::open(&layout::attempt_dir(&r.run_dir, 3)).unwrap();
    assert_eq!(
        h3.records[0].body["resumed_from"]["wall_carried_ms"],
        2 * twenty_min,
        "attempt 1's time survives through attempt 2"
    );
    assert_eq!(
        third.cause,
        StopCause::Budget(harness_core::BudgetDim::Wall)
    );
}

// ---- the environment sample (§7.1, H1f-3) -------------------------------------------

/// Turn the first read's `ToolFinished` into a `status` result as the loop
/// writes one (no read digest; `environment` when given), re-chained. A
/// live timeout needs a walk the clock interrupts, which a test cannot time
/// reliably; the loop's own sampling is tested in the crate's unit tests.
fn as_failed(r: &RunReport, status: &'static str, environment: Option<Value>) {
    as_failed_keeping(r, status, environment, false);
}

/// [`as_failed`]; `keep_read` leaves the read digest in place (a shape the
/// loop never writes on a non-ok result). A `provider_error` carries no
/// output, as the loop writes it.
fn as_failed_keeping(
    r: &RunReport,
    status: &'static str,
    environment: Option<Value>,
    keep_read: bool,
) {
    rechain(
        &journal_path(r, 1),
        |v| v["kind"] == "ToolFinished" && v["body"].get("output").is_some(),
        move |b| {
            b["status"] = Value::from(status);
            let o = b.as_object_mut().unwrap();
            if !keep_read {
                o.remove("read_sha256");
            }
            if status == "provider_error" {
                for k in ["output", "truncated", "digest", "read_sha256"] {
                    o.remove(k);
                }
            }
            if let Some(e) = &environment {
                b["environment"] = e.clone();
            }
        },
    );
}

fn pressed_sample() -> Value {
    serde_json::json!({
        "cpus": {"method": "/sys/devices/system/cpu/online", "value": 4},
        "load_1m_milli": {"method": "/proc/loadavg", "value": 9000},
        "mem_total_bytes": {"method": "/proc/meminfo MemTotal", "value": 1000},
        "mem_available_bytes": {"method": "/proc/meminfo MemAvailable", "value": 10},
        "state_root_free_bytes": {"unmeasured": "no_safe_api"},
    })
}

/// The replay journal's records (it lives in `replay-<k>/`, not an attempt).
fn replay_records(a: &harness_run::AuditReport) -> Vec<Value> {
    fs::read_to_string(a.replay_dir.clone().unwrap().join(layout::JOURNAL_FILE))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .collect()
}

#[test]
fn inv_20_a_recorded_sample_is_re_fed_exactly() {
    // A past host cannot be re-measured: the replay re-feeds the sample
    // recorded with a timed-out or crashed result, re-encodes it byte for
    // byte, and marks its own header's copy as recorded. (Like a tool
    // result, a sample is an input to the replay: a self-consistent edit to
    // one is caught only by an anchor, §7.1.)
    for status in ["timeout", "crashed"] {
        let fx = fx(&format!("env-refed-{status}"));
        let r = go(&fx, vec![read("a.txt"), submit()]);
        as_failed(&r, status, Some(pressed_sample()));
        let a = audit_with(&fx, &r.run, None, TASK, &UserPolicy::default());
        assert_eq!(a.divergence, None, "{status}");
        let recs = replay_records(&a);
        assert_eq!(recs[0]["body"]["environment_source"], "recorded");
        let rec = recs
            .iter()
            .find(|v| v["kind"] == "ToolFinished" && v["body"].get("environment").is_some())
            .unwrap();
        assert_eq!(rec["body"]["status"], status);
        assert_eq!(rec["body"]["environment"], pressed_sample(), "{status}");
    }
}

#[test]
fn inv_20_a_recorded_provider_failure_is_re_fed_with_its_sample() {
    // A provider failure feeds the model a harness notice, not the
    // observation, so the recording is cut after that step (a crash): the
    // audit re-feeds the failure and its sample exactly (confirming NF-6).
    let fx = fx("env-provider-error");
    let r = go(&fx, vec![read("a.txt"), submit()]);
    as_failed(&r, "provider_error", Some(pressed_sample()));
    crash_after(&journal_path(&r, 1), 2);
    let a = audit_with(&fx, &r.run, None, TASK, &UserPolicy::default());
    assert_eq!(a.divergence, None, "{a:?}");
    let rec = replay_records(&a)
        .into_iter()
        .find(|v| v["kind"] == "ToolFinished" && v["body"]["status"] == "provider_error")
        .unwrap();
    assert_eq!(rec["body"]["environment"], pressed_sample());
}

#[test]
fn a_cut_intent_is_replayed_as_not_sampled() {
    // An intent a crash cut before its result has no recorded sample; the
    // replay's provider failure for it says so instead of borrowing the
    // header's (confirming NF-1).
    let fx = fx("env-cut-intent");
    let r = go(&fx, vec![read("a.txt"), submit()]);
    let text = fs::read_to_string(journal_path(&r, 1)).unwrap();
    let cut: String = text
        .lines()
        .take_while(|l| !l.contains("\"kind\":\"ToolFinished\""))
        .map(|l| format!("{l}\n"))
        .collect();
    fs::write(journal_path(&r, 1), cut).unwrap();
    let a = audit_with(&fx, &r.run, None, TASK, &UserPolicy::default());
    assert_eq!(a.divergence, None, "{a:?}");
    let rec = replay_records(&a)
        .into_iter()
        .find(|v| v["kind"] == "ToolFinished")
        .unwrap();
    assert_eq!(rec["body"]["status"], "provider_error");
    for (k, v) in rec["body"]["environment"].as_object().unwrap() {
        assert_eq!(v["unmeasured"], "not_sampled", "{k}");
    }
}

#[test]
fn a_read_digest_on_a_failed_result_is_unreadable() {
    let fx = fx("env-read-on-timeout");
    let r = go(&fx, vec![read("a.txt"), submit()]);
    as_failed_keeping(&r, "timeout", Some(pressed_sample()), true);
    let a = audit_with(&fx, &r.run, None, TASK, &UserPolicy::default());
    assert_eq!(a.outcome, UNREADABLE);
}

#[test]
fn a_resume_re_feeds_a_timed_out_catch_up_step_with_its_sample() {
    let fx = fx("env-resume");
    let r = go(&fx, vec![read("a.txt"), read("b.txt"), submit()]);
    // Step 1 timed out on a pressed host; the run died in step 2.
    as_failed(&r, "timeout", Some(pressed_sample()));
    crash_after(&journal_path(&r, 1), 3);
    let res = resume_with(&fx, &r.run, vec![read("b.txt"), submit()]).unwrap();
    assert_eq!(res.attempt, 2);
    // The catch-up re-fed step 1 with its recorded sample, which flags it.
    assert_eq!(res.possibly_environmental, vec![1]);
    let new = JournalReader::open(&layout::attempt_dir(&r.run_dir, 2)).unwrap();
    assert_eq!(new.records[0].body["environment_source"], "measured");
    let step1 = new
        .records
        .iter()
        .find(|x| x.step == 1 && x.kind == EventKind::ToolFinished)
        .unwrap();
    assert_eq!(
        Value::Object(step1.body.clone())["environment"],
        pressed_sample()
    );
    let a = audit_with(&fx, &r.run, Some(2), TASK, &UserPolicy::default());
    assert_eq!(a.divergence, None, "{a:?}");
}

#[test]
fn inv_20_a_missing_misplaced_or_misshapen_sample_is_unreadable() {
    let mut unknown_method = pressed_sample();
    unknown_method["mem_total_bytes"]["method"] = Value::from("free -b");
    let mut wrong_field = pressed_sample();
    wrong_field["cpus"] = serde_json::json!({"method": "vm_stat free+inactive", "value": 4});
    let mut extra_key = pressed_sample();
    extra_key["swap_bytes"] = serde_json::json!({"unmeasured": "no_safe_api"});
    for (name, status, env) in [
        ("missing", "timeout", None),
        ("unknown-method", "timeout", Some(unknown_method)),
        ("method-on-another-field", "crashed", Some(wrong_field)),
        ("extra-key", "timeout", Some(extra_key)),
        ("on-an-ok-result", "ok", Some(pressed_sample())),
        ("provider-error-without-one", "provider_error", None),
    ] {
        let fx = fx(&format!("env-{name}"));
        let r = go(&fx, vec![read("a.txt"), submit()]);
        as_failed(&r, status, env);
        let a = audit_with(&fx, &r.run, None, TASK, &UserPolicy::default());
        assert_eq!(a.outcome, UNREADABLE, "{name}");
        assert!(
            a.divergence
                .unwrap()
                .why
                .contains("not the shape the loop writes"),
            "{name}"
        );
    }
}

#[test]
fn a_journal_from_another_harness_build_is_named_as_such() {
    let fx = fx("other-build");
    let r = go(&fx, vec![read("a.txt"), submit()]);
    rechain(
        &journal_path(&r, 1),
        |v| v["kind"] == "RunStarted",
        |b| b["builtin_manifest"] = Value::from("0".repeat(64)),
    );
    let a = audit_with(&fx, &r.run, None, TASK, &UserPolicy::default());
    assert_eq!(a.outcome, UNREADABLE);
    assert!(a.divergence.unwrap().why.contains("another harness build"));
}

// ---- H1 phase-exit review (H1g): F-1, F-2, INV-20 ------------------------------------

const NOTHING_CHECKED: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::NothingChecked,
};

/// Every record of the journal at `path`, parsed.
fn lines(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// Write `records` as a journal the way a forger who re-chains would: seq
/// renumbered, every result's `intent_seq` pointed at its (renumbered)
/// intent, every hash recomputed.
fn write_chained(path: &Path, records: &[Value]) {
    write_records(path, records, true);
}

/// [`write_chained`]; `repoint` false leaves every `intent_seq` as given.
fn write_records(path: &Path, records: &[Value], repoint: bool) {
    let mut prev = GENESIS;
    let mut out = Vec::new();
    let mut last_intent = 0u64;
    for (i, v) in records.iter().enumerate() {
        let mut v = v.clone();
        let seq = i as u64;
        v["seq"] = Value::from(seq);
        if v["kind"] == "ToolStarted" {
            last_intent = seq;
        }
        if repoint && v["body"].get("intent_seq").is_some() {
            v["body"]["intent_seq"] = Value::from(last_intent);
        }
        let (bytes, hash) = fields(&v, prev, None).encode();
        out.extend(bytes);
        out.push(b'\n');
        prev = hash;
    }
    fs::write(path, out).unwrap();
}

/// Review F-1 (W1): a journal cut after step 1, its header's step limit
/// lowered to 1, the 80% condition the loop writes at step 1 under that
/// limit added and the stop the loop recomputes at step 2 appended, all
/// re-chained. The audit is given the limits the run was given and they
/// are not the recorded ones: a divergence at the header, without an
/// anchor and even with the forged journal's own head as the anchor. With
/// the genuine anchor the cut is caught first.
#[test]
fn f_1_a_truncation_forged_through_the_header_limits_is_never_verified() {
    let fx = fx("h1g-w1-limits");
    let r = go(&fx, vec![read("a.txt"), read("b.txt"), submit()]);
    let genuine_head = r.chain_head.unwrap();
    // Control (W0): untouched, it audits clean without an anchor.
    let a = audit_anchored(&fx, &r.run, None);
    assert!(a.divergence.is_none() && a.stop_recomputed, "{a:?}");
    assert_eq!(a.outcome, NOTHING_CHECKED);

    let path = journal_path(&r, 1);
    let genuine = lines(&path);
    let step1: Vec<Value> = genuine.iter().filter(|v| v["step"] == 1).cloned().collect();
    let mut header = genuine[0].clone();
    header["body"]["limits"]["steps"] = Value::from(1u64);
    let mut condition = step1[0].clone();
    condition["kind"] = Value::from("BudgetCharged");
    condition["body"] = serde_json::json!({"condition": "enter", "key": "steps"});
    let mut stop = step1.last().unwrap().clone();
    stop["step"] = Value::from(2u64);
    stop["kind"] = Value::from("RunStopped");
    stop["body"] = serde_json::json!({
        "cause": "budget", "dimension": "steps", "outcome": "indeterminate:nothing_checked"
    });
    let mut forged = vec![header, condition];
    forged.extend(step1);
    forged.push(stop);
    write_chained(&path, &forged);
    let v = JournalReader::open(&layout::attempt_dir(&r.run_dir, 1)).unwrap();
    assert!(
        v.is_complete(),
        "the forged journal verifies and is committed"
    );
    assert_eq!(
        v.records
            .iter()
            .filter(|x| x.kind == EventKind::ToolStarted)
            .count(),
        1,
        "the read of b.txt and the submit are gone"
    );

    for anchor in [None, Some(v.head)] {
        let a = audit_anchored(&fx, &r.run, anchor);
        assert_eq!(a.outcome, UNREADABLE, "anchor {anchor:?}");
        let d = a.divergence.unwrap();
        assert_eq!((d.seq, d.step), (0, 0), "{d:?}");
        assert!(d.why.contains("budget limits"), "{d:?}");
    }
    let a = audit_anchored(&fx, &r.run, Some(genuine_head));
    assert_eq!(a.outcome, UNREADABLE);
    assert!(a.divergence.unwrap().why.contains("anchor"));
}

/// Review F-1: the limits are the caller's. An audit given other limits
/// than the run's diverges at the header, naming them, whatever the
/// anchor. A resume given other limits (here a longer wall budget) is
/// refused before anything is written, never adopting the recorded ones;
/// given the recorded ones, it resumes.
#[test]
fn f_1_an_audit_or_a_resume_given_other_limits_refuses() {
    let fx = fx("h1g-limits");
    let r = go(&fx, vec![read("a.txt"), read("b.txt"), submit()]);
    let mut other = limits();
    other.steps -= 1;
    let a = audit_given(&fx, &r.run, r.chain_head, &other);
    assert_eq!(a.outcome, UNREADABLE);
    let d = a.divergence.unwrap();
    assert_eq!(d.seq, 0);
    assert!(d.why.contains("budget limits"), "{d:?}");

    crash_after(&journal_path(&r, 1), 3);
    let mut config = RunConfig::defaults(1_000_000);
    config.limits.wall *= 2;
    let e = resume_under(&fx, &r.run, &config, vec![read("b.txt"), submit()]).unwrap_err();
    assert!(
        matches!(e, RunRefused::NotResumable(ref w) if w.contains("budget limits")),
        "{e:?}"
    );
    assert!(
        !layout::attempt_dir(&r.run_dir, 2).exists(),
        "nothing was written"
    );
    let res = resume_with(&fx, &r.run, vec![read("b.txt"), submit()]).unwrap();
    assert_eq!((res.attempt, res.cause), (2, StopCause::Submitted));
}

/// Review F-1 (W6): a `BudgetCharged` record keyed `wall` is left out of
/// the comparison, but only when it is a record the loop writes. One the
/// loop never writes (an exit carrying anything else, here a "verdict"),
/// inserted just before `RunStopped` and re-chained, is a divergence at
/// that record without an anchor; with the genuine anchor the edit is
/// caught first.
#[test]
fn f_1_a_wall_record_the_loop_does_not_write_is_a_divergence() {
    let fx = fx("h1g-w6-wall");
    let r = go(&fx, vec![read("a.txt"), read("b.txt"), submit()]);
    let path = journal_path(&r, 1);
    let mut recs = lines(&path);
    let at = recs.iter().position(|v| v["kind"] == "RunStopped").unwrap();
    let mut injected = recs[at - 1].clone();
    injected["kind"] = Value::from("BudgetCharged");
    injected["body"] = serde_json::json!({
        "condition": "exit",
        "key": "wall",
        "verdict": "harness verified the answer; outcome passed"
    });
    recs.insert(at, injected);
    write_chained(&path, &recs);
    let a = audit_anchored(&fx, &r.run, None);
    assert_eq!(a.outcome, UNREADABLE);
    let d = a.divergence.unwrap();
    assert_eq!(d.seq, at as u64, "{d:?}");
    assert!(d.why.contains("not one the loop writes"), "{d:?}");
    let a = audit_anchored(&fx, &r.run, r.chain_head);
    assert_eq!(a.outcome, UNREADABLE);
    assert!(a.divergence.unwrap().why.contains("anchor"));
}

/// Review F-1: what "exactly the shape the loop writes" admits. Records
/// are inserted at step 2's start (before a later tool result), re-chained.
/// One entry `{condition: enter, key: wall}` is skipped and counted, and it
/// shifts nothing (a result's `intent_seq` is compared by position among
/// the records compared, so a run that crossed 80% of its wall budget
/// before a later tool result still matches). Anything else is a
/// divergence at the offending record, including an exit and a second
/// entry: wall time never decreases within an attempt, so the loop writes
/// at most one wall record, an entry, and never an exit (H1g confirming
/// review NF-1; its witness B3, entry/exit/entry/exit with a free
/// `affected`, is the last case).
#[test]
fn f_1_wall_records_in_the_loops_shape_are_skipped_and_counted_and_no_others() {
    let enter = serde_json::json!({"condition": "enter", "key": "wall"});
    let exit = serde_json::json!({"affected": 3, "condition": "exit", "key": "wall"});
    let cases: Vec<(&str, Vec<Value>, Option<usize>)> = vec![
        ("an entry", vec![enter.clone()], None),
        (
            "an entry, then its exit",
            vec![enter.clone(), exit.clone()],
            Some(1),
        ),
        ("two entries", vec![enter.clone(), enter.clone()], Some(1)),
        ("an exit with no entry", vec![exit.clone()], Some(0)),
        (
            "an exit counting no observation",
            vec![
                enter.clone(),
                serde_json::json!({"affected": 0, "condition": "exit", "key": "wall"}),
            ],
            Some(1),
        ),
        (
            "an entry with another field",
            vec![serde_json::json!({"condition": "enter", "key": "wall", "outcome": "passed"})],
            Some(0),
        ),
        (
            "an unknown condition",
            vec![serde_json::json!({"condition": "passed", "key": "wall"})],
            Some(0),
        ),
        (
            "review NF-1 witness B3: entry, exit, entry, exit",
            vec![
                enter.clone(),
                serde_json::json!({"affected": 999, "condition": "exit", "key": "wall"}),
                enter.clone(),
                serde_json::json!({"affected": 1, "condition": "exit", "key": "wall"}),
            ],
            Some(1),
        ),
    ];
    for (i, (what, bodies, refused)) in cases.into_iter().enumerate() {
        let fx = fx(&format!("h1g-wall-shape-{i}"));
        let r = go(&fx, vec![read("a.txt"), read("b.txt"), submit()]);
        let clean = audit_anchored(&fx, &r.run, None);
        assert!(
            clean.divergence.is_none() && clean.wall_skipped == 0,
            "{what}"
        );
        let path = journal_path(&r, 1);
        let mut recs = lines(&path);
        let at = recs.iter().position(|v| v["step"] == 2).unwrap();
        for (k, body) in bodies.iter().enumerate() {
            let mut w = recs[at].clone();
            w["kind"] = Value::from("BudgetCharged");
            w["body"] = body.clone();
            recs.insert(at + k, w);
        }
        write_chained(&path, &recs);
        let a = audit_anchored(&fx, &r.run, None);
        match refused {
            None => {
                assert_eq!(a.divergence, None, "{what}");
                assert!(a.stop_recomputed, "{what}");
                assert_eq!(a.wall_skipped, bodies.len(), "{what}");
                assert_eq!(a.matched, clean.matched, "{what}: not counted as matched");
                assert_eq!(a.outcome, NOTHING_CHECKED, "{what}");
            }
            Some(k) => {
                assert_eq!(a.outcome, UNREADABLE, "{what}");
                let d = a.divergence.unwrap();
                assert_eq!(d.seq, (at + k) as u64, "{what}: {d:?}");
                assert!(d.why.contains("not one the loop writes"), "{what}: {d:?}");
            }
        }
    }
}

/// A result's `intent_seq` is compared by its position among the records
/// compared, so a wall-budget record shifts nothing; one pointing AT a
/// wall-budget record points at no intent and never matches. Here a
/// wall-budget entry is inserted just before the submit's intent (a place
/// the loop never writes one, but of its shape, so skipped), then the
/// submit's `SubmitRequested` is pointed at it instead of the intent.
#[test]
fn f_1_a_result_pointing_at_a_wall_record_is_a_divergence() {
    let fx = fx("h1g-wall-pointer");
    let r = go(&fx, vec![read("a.txt"), submit()]);
    let path = journal_path(&r, 1);
    let mut recs = lines(&path);
    let intent = recs
        .iter()
        .rposition(|v| v["kind"] == "ToolStarted")
        .unwrap();
    let mut w = recs[intent].clone();
    w["kind"] = Value::from("BudgetCharged");
    w["body"] = serde_json::json!({"condition": "enter", "key": "wall"});
    recs.insert(intent, w);
    write_chained(&path, &recs);
    // Control: of the loop's shape and every result pointing at its
    // intent, it is skipped and counted.
    let a = audit_anchored(&fx, &r.run, None);
    assert_eq!(a.divergence, None, "{a:?}");
    assert_eq!(a.wall_skipped, 1);
    let mut recs = lines(&path);
    let s = recs
        .iter()
        .position(|v| v["kind"] == "SubmitRequested")
        .unwrap();
    assert_eq!(recs[s]["body"]["intent_seq"], (intent + 1) as u64);
    recs[s]["body"]["intent_seq"] = Value::from(intent as u64);
    write_records(&path, &recs, false);
    let a = audit_anchored(&fx, &r.run, None);
    assert_eq!(a.outcome, UNREADABLE);
    let d = a.divergence.unwrap();
    assert_eq!(d.seq, s as u64, "{d:?}");
    assert!(d.why.contains("different body"), "{d:?}");
}

/// Review F-2 (W2): bytes appended after `RunStopped` with no newline are
/// not a crash's torn tail (no crash writes after a durable `RunStopped`),
/// the chain head does not cover them, and a line reader takes them for
/// the journal's last record. The reader refuses them, so the audit is
/// unreadable evidence with the genuine anchor as without one.
#[test]
fn f_2_bytes_after_run_stopped_are_refused_even_with_the_genuine_anchor() {
    let fx = fx("h1g-w2-after-stop");
    let r = go(&fx, vec![read("a.txt"), submit()]);
    let head = r.chain_head.unwrap();
    let path = journal_path(&r, 1);
    let mut bytes = fs::read(&path).unwrap();
    let planted = r#"{"attempt":1,"body":{"cause":"submitted","outcome":"passed"},"kind":"RunStopped","note":"planted"}"#;
    bytes.extend_from_slice(planted.as_bytes());
    fs::write(&path, &bytes).unwrap();
    assert_eq!(
        fs::read_to_string(&path).unwrap().lines().last().unwrap(),
        planted,
        "a line reader's last record"
    );
    let e = JournalReader::open(&layout::attempt_dir(&r.run_dir, 1)).unwrap_err();
    assert!(
        matches!(&e, harness_journal::reader::ReadError::Broken(b) if b.why == harness_journal::BreakKind::AfterRunStopped),
        "{e:?}"
    );
    for anchor in [Some(head), None] {
        let a = audit_anchored(&fx, &r.run, anchor);
        assert_eq!(a.outcome, UNREADABLE, "anchor {anchor:?}");
        assert!(a.divergence.unwrap().why.contains("does not verify"));
    }
}

/// INV-20 (review F-8, W7): "tamper a recorded tool result → divergence".
/// A recorded result is an input to the replay, re-fed like a model reply,
/// so an edit to one (payload digest recomputed, re-chained) leaves its
/// own step's records matching and diverges at the first context built
/// from it: the next step's `ContextBuilt`. (The last result before the
/// stop feeds no later context: an anchor-only residual, row H1e-2b.)
#[test]
fn inv_20_a_tampered_tool_result_diverges_at_the_first_context_built_from_it() {
    let fx = fx("h1g-w7-tool-result");
    let r = go(&fx, vec![read("a.txt"), read("b.txt"), submit()]);
    let path = journal_path(&r, 1);
    let mut recs = lines(&path);
    let i = recs
        .iter()
        .position(|v| v["kind"] == "ToolFinished" && v["body"].get("output").is_some())
        .unwrap();
    assert_eq!(recs[i]["step"], 1);
    let out = recs[i]["body"]["output"]["inline"]
        .as_str()
        .unwrap()
        .to_owned();
    let edited = out.replace("alpha", "omega");
    assert_ne!(out, edited);
    let raw = harness_journal::canon::unescape(&edited).unwrap();
    recs[i]["body"]["output"]["inline"] = Value::from(edited);
    recs[i]["body"]["output"]["sha256"] =
        Value::from(harness_core::sha256(raw.as_bytes()).to_string());
    write_chained(&path, &recs);
    assert!(JournalReader::open(&layout::attempt_dir(&r.run_dir, 1)).is_ok());
    let a = audit_with(&fx, &r.run, Some(1), TASK, &UserPolicy::default());
    assert_eq!(a.outcome, UNREADABLE);
    let d = a.divergence.unwrap();
    assert_eq!(
        (d.step, recs[d.seq as usize]["kind"].clone()),
        (2, Value::from("ContextBuilt")),
        "{d:?}"
    );
}

// ---- H1 phase-exit review F-5 (closed in H2b) -----------------------------------------

/// A probe that admits the state root and refuses every attempt directory
/// (the review's witness W4: the new attempt's locality check fails, e.g.
/// a macOS query past its deadline on a loaded host).
struct RefuseAttempts;
impl LocalityProbe for RefuseAttempts {
    fn query(&self, path: &str) -> FsQuery {
        if path.contains("attempt-") {
            FsQuery::MacOs {
                mnt_local: false,
                fs_type_name: "smbfs".into(),
            }
        } else {
            harness_testkit::Local.query(path)
        }
    }
}

/// W4: a resume whose new attempt fails its start leaves an empty
/// `attempt-2`. It holds no header, so it is evidence of nothing: the
/// default audit passes over it (and names it) to attempt 1, and a later
/// resume, once the condition clears, continues attempt 1 in attempt 3,
/// naming attempt 2 in its header.
#[test]
fn w4_a_failed_attempt_start_never_blocks_a_later_resume_or_audit() {
    let fx = fx("w4");
    let r = go(&fx, vec![read("a.txt"), read("b.txt"), submit()]);
    crash_after(&journal_path(&r, 1), 3);
    let profile = Profile::conservative_default("m");
    let backend = ScriptedBackend::new(profile.clone(), vec![]);
    let e = resume(Resume {
        state_root: fx.state_root(),
        run: &r.run,
        workspace: fx.workspace(),
        spec: &fx.spec,
        registry: &harness_testkit::registry().unwrap(),
        policy: &UserPolicy::default(),
        profile: &profile,
        backend: &backend,
        probe: &RefuseAttempts,
        env: &FIXED_ENV,
        config: &RunConfig::defaults(1_000_000),
        approver: None,
        confinement: None,
    })
    .unwrap_err();
    assert!(matches!(e, RunRefused::Start(_)), "{e:?}");
    let left = layout::attempt_dir(&r.run_dir, 2);
    assert!(left.is_dir() && !left.join(layout::JOURNAL_FILE).exists());

    let a = audit_with(&fx, &r.run, None, TASK, &UserPolicy::default());
    assert_eq!(a.attempt, 1, "{a:?}");
    assert_eq!(a.skipped_attempts, vec![2]);
    assert_eq!(a.divergence, None, "{a:?}");

    let again = resume_with(&fx, &r.run, vec![submit()]).unwrap();
    assert_eq!(again.attempt, 3);
    assert_eq!(again.cause, StopCause::Submitted);
    let h = JournalReader::open(&layout::attempt_dir(&r.run_dir, 3)).unwrap();
    assert_eq!(h.records[0].body["resumed_from"]["attempt"], 1);
    assert_eq!(
        h.records[0].body["resumed_from"]["skipped_attempts"],
        serde_json::json!([2])
    );
    // An attempt with a header that does not verify is never passed over.
    let bad = layout::attempt_dir(&r.run_dir, 3).join(layout::JOURNAL_FILE);
    let t = fs::read_to_string(&bad)
        .unwrap()
        .replacen("a.txt", "b.txt", 1);
    fs::write(&bad, t).unwrap();
    let e = resume_with(&fx, &r.run, vec![]).unwrap_err();
    assert!(
        matches!(e, RunRefused::NotResumable(ref w) if w.contains("does not verify")),
        "{e:?}"
    );
}
