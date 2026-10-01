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
use harness_core::{RunId, StopCause};
use harness_journal::canon::{RecordFields, GENESIS};
use harness_journal::{layout, EventKind, JournalReader};
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, SemVer, ValidationContext};
use harness_model::profile::Profile;
use harness_model::scripted::{text_reply, ScriptedBackend};
use harness_model::{Completion, ModelError, TaskText};
use harness_policy::locality::{FsQuery, LocalityProbe};
use harness_policy::UserPolicy;
use harness_run::{
    audit, resume, run, Audit, Resume, Run, RunConfig, RunRefused, RunReport, TaskSpec,
};
use serde_json::Value;

/// A fixed environment sample (the real probe is harness-sandbox's; these
/// tests only need the header and records to carry one).
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
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("replay-{name}"));
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

fn action(tool: &str, args: &str) -> Result<Completion, ModelError> {
    Ok(text_reply(&format!(
        "<action>{{\"tool\":\"{tool}\",\"args\":{args}}}</action>"
    )))
}
fn read(p: &str) -> Result<Completion, ModelError> {
    action("harness.fs.read", &format!("{{\"path\":\"{p}\"}}"))
}
fn submit() -> Result<Completion, ModelError> {
    action("harness.task.submit", "{\"note\":\"done\"}")
}

fn spec(task: &str) -> TaskSpec {
    TaskSpec {
        task: TaskText::new(task.into()),
        grants: vec!["harness.fs.read".into(), "harness.fs.list".into()],
        workspace_public: false,
    }
}

fn go(state: &Path, ws: &Path, replies: Vec<Result<Completion, ModelError>>) -> RunReport {
    let profile = Profile::conservative_default("m");
    let backend = ScriptedBackend::new(profile.clone(), replies);
    run(Run {
        state_root: state,
        workspace: ws,
        spec: &spec("Summarise a.txt and b.txt."),
        registry: &registry(),
        policy: &UserPolicy::default(),
        profile: &profile,
        backend: &backend,
        probe: &Local,
        env: &FIXED_ENV,
        config: &RunConfig::defaults(1_000_000),
    })
    .unwrap()
}

fn audit_with(
    state: &Path,
    run: &RunId,
    attempt: Option<u32>,
    task: &str,
    policy: &UserPolicy,
) -> harness_run::AuditReport {
    audit(Audit {
        state_root: state,
        run,
        attempt,
        anchor: None,
        spec: &spec(task),
        registry: &registry(),
        policy,
        profile: &Profile::conservative_default("m"),
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
    let (state, ws) = scratch("clean");
    let r = go(&state, &ws, vec![read("a.txt"), read("b.txt"), submit()]);
    assert_eq!(r.cause, StopCause::Submitted);
    let a = audit_with(&state, &r.run, None, TASK, &UserPolicy::default());
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
    let again = audit_with(&state, &r.run, Some(1), TASK, &UserPolicy::default());
    assert_eq!(again.replay_dir.unwrap(), layout::replay_dir(&r.run_dir, 2));
}

#[test]
fn inv_20_an_edited_reply_that_breaks_the_chain_is_unreadable() {
    let (state, ws) = scratch("edited-bytes");
    let r = go(&state, &ws, vec![read("a.txt"), submit()]);
    let p = journal_path(&r, 1);
    let t = fs::read_to_string(&p)
        .unwrap()
        .replacen("a.txt", "b.txt", 1);
    fs::write(&p, t).unwrap();
    let a = audit_with(&state, &r.run, None, TASK, &UserPolicy::default());
    assert_eq!(a.outcome, UNREADABLE);
    assert!(a.divergence.unwrap().why.contains("does not verify"));
}

#[test]
fn inv_20_a_re_chained_edited_reply_is_caught_by_the_replay() {
    let (state, ws) = scratch("edited-reply");
    let r = go(&state, &ws, vec![read("a.txt"), read("b.txt"), submit()]);
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
    let a = audit_with(&state, &r.run, None, TASK, &UserPolicy::default());
    assert_eq!(a.outcome, UNREADABLE);
    let d = a.divergence.unwrap();
    assert_eq!(d.step, 1);
    assert!(d.why.contains("different body"), "{d:?}");
}

#[test]
fn inv_20_a_re_chained_edited_policy_decision_is_caught_by_the_replay() {
    let (state, ws) = scratch("edited-policy");
    let r = go(&state, &ws, vec![read("a.txt"), submit()]);
    rechain(&journal_path(&r, 1), kind_is("PolicyDecided"), |b| {
        b["rule"] = Value::from("allow.something-else");
    });
    let a = audit_with(&state, &r.run, None, TASK, &UserPolicy::default());
    assert_eq!(a.outcome, UNREADABLE);
    let d = a.divergence.unwrap();
    assert_eq!(d.step, 1);
    assert!(d.why.contains("different body"), "{d:?}");
}

#[test]
fn inv_20_replaying_under_another_policy_or_task_is_refused_at_the_header() {
    let (state, ws) = scratch("other-inputs");
    let r = go(&state, &ws, vec![read("a.txt"), submit()]);
    let deny = UserPolicy::new(&["harness.fs.read"], &[], &[]).unwrap();
    let a = audit_with(&state, &r.run, None, TASK, &deny);
    assert_eq!(a.outcome, UNREADABLE);
    assert_eq!(a.divergence.as_ref().unwrap().seq, 0);
    let a = audit_with(
        &state,
        &r.run,
        None,
        "Another task.",
        &UserPolicy::default(),
    );
    assert_eq!(a.divergence.unwrap().seq, 0);
}

#[test]
fn inv_20_a_journal_from_another_run_is_refused() {
    let (state, ws) = scratch("other-run");
    let a_run = go(&state, &ws, vec![read("a.txt"), submit()]);
    // A run directory for another id whose attempt-1 is run A's journal:
    // the attempt number fits, the run id does not.
    let other = RunId::new(1, [7; 10]);
    let to = layout::attempt_dir(
        &layout::run_dir(&fs::canonicalize(&state).unwrap(), &other),
        1,
    );
    fs::create_dir_all(to.join(layout::BLOBS_DIR)).unwrap();
    let from = layout::attempt_dir(&a_run.run_dir, 1);
    fs::copy(
        from.join(layout::JOURNAL_FILE),
        to.join(layout::JOURNAL_FILE),
    )
    .unwrap();
    let a = audit_with(&state, &other, Some(1), TASK, &UserPolicy::default());
    assert_eq!(a.outcome, UNREADABLE);
    assert!(a.divergence.unwrap().why.contains("another run"));
}

#[test]
fn inv_20_an_anchor_catches_a_replaced_journal() {
    let (state, ws) = scratch("anchor");
    let r = go(&state, &ws, vec![read("a.txt"), submit()]);
    let head = r.chain_head.unwrap();
    let with_anchor = |anchor| {
        audit(Audit {
            state_root: &state,
            run: &r.run,
            attempt: None,
            anchor: Some(anchor),
            spec: &spec(TASK),
            registry: &registry(),
            policy: &UserPolicy::default(),
            profile: &Profile::conservative_default("m"),
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
    state: &Path,
    run: &RunId,
    anchor: Option<harness_core::Digest>,
) -> harness_run::AuditReport {
    audit(Audit {
        state_root: state,
        run,
        attempt: None,
        anchor,
        spec: &spec(TASK),
        registry: &registry(),
        policy: &UserPolicy::default(),
        profile: &Profile::conservative_default("m"),
    })
    .unwrap()
}

#[test]
fn f_1_a_truncated_journal_with_a_forged_wall_stop_is_never_reported_verified() {
    let (state, ws) = scratch("forged-wall");
    let r = go(&state, &ws, vec![read("a.txt"), read("b.txt"), submit()]);
    let genuine = r.chain_head.unwrap();
    // Keep step 1, drop steps 2-3 and the real stop, forge a wall stop.
    truncate_and_forge_wall_stop(&journal_path(&r, 1), 1);
    let v = JournalReader::open(&layout::attempt_dir(&r.run_dir, 1)).unwrap();
    assert!(v.is_complete(), "the forged journal verifies");
    // Without an anchor: every remaining record matches, but the stop is
    // not recomputable, so the audit does not vouch for the journal.
    let a = audit_anchored(&state, &r.run, None);
    assert_eq!(a.divergence, None);
    assert!(!a.stop_recomputed);
    assert_eq!(
        a.outcome, UNREADABLE,
        "a forged wall stop must not pass as verified"
    );
    // With the genuine run's anchor, the truncation is caught outright.
    let a = audit_anchored(&state, &r.run, Some(genuine));
    assert_eq!(a.outcome, UNREADABLE);
    assert!(a.divergence.unwrap().why.contains("anchor"));
}

#[test]
fn f_1_a_genuine_wall_stop_passes_only_with_its_anchor() {
    let (state, ws) = scratch("genuine-wall");
    let profile = Profile::conservative_default("m");
    let backend = ScriptedBackend::new(
        profile.clone(),
        vec![read("a.txt"), read("b.txt"), submit()],
    );
    let mut config = RunConfig::defaults(1_000_000);
    config.limits.wall = std::time::Duration::from_nanos(1);
    let r = run(Run {
        state_root: &state,
        workspace: &ws,
        spec: &spec(TASK),
        registry: &registry(),
        policy: &UserPolicy::default(),
        profile: &profile,
        backend: &backend,
        probe: &Local,
        env: &FIXED_ENV,
        config: &config,
    })
    .unwrap();
    assert_eq!(r.cause, StopCause::Budget(harness_core::BudgetDim::Wall));
    let a = audit_anchored(&state, &r.run, None);
    assert!(!a.stop_recomputed);
    assert_eq!(
        a.outcome, UNREADABLE,
        "without an anchor a wall stop is not verified"
    );
    let a = audit_anchored(&state, &r.run, r.chain_head);
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
    let (state, ws) = scratch("recomputed-stop");
    let r = go(&state, &ws, vec![read("a.txt"), submit()]);
    let a = audit_anchored(&state, &r.run, None);
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

fn resume_with(
    state: &Path,
    ws: &Path,
    run: &RunId,
    task: &str,
    replies: Vec<Result<Completion, ModelError>>,
) -> Result<RunReport, RunRefused> {
    let profile = Profile::conservative_default("m");
    let backend = ScriptedBackend::new(profile.clone(), replies);
    resume(Resume {
        state_root: state,
        run,
        workspace: ws,
        spec: &spec(task),
        registry: &registry(),
        policy: &UserPolicy::default(),
        profile: &profile,
        backend: &backend,
        probe: &Local,
        env: &FIXED_ENV,
        config: &RunConfig::defaults(1_000_000),
    })
}

#[test]
fn resume_continues_in_a_new_attempt_and_re_runs_the_cut_step_live() {
    let (state, ws) = scratch("resume");
    let r = go(&state, &ws, vec![read("a.txt"), read("b.txt"), submit()]);
    // Crash in step 2: its records survive but step 3 and RunStopped do not.
    crash_after(&journal_path(&r, 1), 3);
    let before = fs::read(journal_path(&r, 1)).unwrap();
    let old = JournalReader::open(&layout::attempt_dir(&r.run_dir, 1)).unwrap();
    // Step 1 is replayed from the journal; step 2 runs again live, then 3.
    let res = resume_with(&state, &ws, &r.run, TASK, vec![read("b.txt"), submit()]).unwrap();
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
    let a = audit_with(&state, &r.run, Some(2), TASK, &UserPolicy::default());
    assert_eq!(a.divergence, None, "{a:?}");
}

#[test]
fn resume_refuses_a_stopped_run_a_changed_workspace_and_changed_inputs() {
    let (state, ws) = scratch("resume-refusals");
    let r = go(&state, &ws, vec![read("a.txt"), read("b.txt"), submit()]);
    let e = resume_with(&state, &ws, &r.run, TASK, vec![]).unwrap_err();
    assert!(matches!(e, RunRefused::NotResumable(w) if w.contains("already stopped")));

    crash_after(&journal_path(&r, 1), 3);
    let e = resume_with(&state, &ws, &r.run, "Another task.", vec![]).unwrap_err();
    assert!(
        matches!(e, RunRefused::NotResumable(w) if w.contains("differ")),
        "{e:?}"
    );

    fs::write(ws.join("a.txt"), "changed\n").unwrap();
    let e = resume_with(&state, &ws, &r.run, TASK, vec![]).unwrap_err();
    assert!(
        matches!(e, RunRefused::NotResumable(w) if w.contains("workspace changed")),
        "{e:?}"
    );
    assert!(
        !layout::attempt_dir(&r.run_dir, 2).exists(),
        "nothing was written"
    );
}

#[test]
fn a_catch_up_that_diverges_makes_the_resumed_run_unreadable() {
    let (state, ws) = scratch("resume-diverge");
    let r = go(
        &state,
        &ws,
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
    let res = resume_with(&state, &ws, &r.run, TASK, vec![submit()]).unwrap();
    assert_eq!(res.outcome, UNREADABLE);
    assert_eq!(res.cause, StopCause::ModelUnavailable);
}

#[test]
fn a_resumed_attempt_is_charged_the_wall_time_already_spent() {
    let (state, ws) = scratch("resume-wall");
    let r = go(&state, &ws, vec![read("a.txt"), read("b.txt"), submit()]);
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
    let res = resume_with(&state, &ws, &r.run, TASK, vec![read("b.txt"), submit()]).unwrap();
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
    let (state, ws) = scratch("resume-chain");
    let twenty_min = 20 * 60 * 1000;
    let r = go(&state, &ws, vec![read("a.txt"), read("b.txt"), submit()]);
    crash_after(&journal_path(&r, 1), 3);
    set_last_mono(&journal_path(&r, 1), twenty_min);
    // 20 of 30 minutes spent: the first resume runs to its end.
    let second = resume_with(&state, &ws, &r.run, TASK, vec![read("b.txt"), submit()]).unwrap();
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
    let third = resume_with(&state, &ws, &r.run, TASK, vec![read("b.txt"), submit()]).unwrap();
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
        let (state, ws) = scratch(&format!("env-refed-{status}"));
        let r = go(&state, &ws, vec![read("a.txt"), submit()]);
        as_failed(&r, status, Some(pressed_sample()));
        let a = audit_with(&state, &r.run, None, TASK, &UserPolicy::default());
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
    let (state, ws) = scratch("env-provider-error");
    let r = go(&state, &ws, vec![read("a.txt"), submit()]);
    as_failed(&r, "provider_error", Some(pressed_sample()));
    crash_after(&journal_path(&r, 1), 2);
    let a = audit_with(&state, &r.run, None, TASK, &UserPolicy::default());
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
    let (state, ws) = scratch("env-cut-intent");
    let r = go(&state, &ws, vec![read("a.txt"), submit()]);
    let text = fs::read_to_string(journal_path(&r, 1)).unwrap();
    let cut: String = text
        .lines()
        .take_while(|l| !l.contains("\"kind\":\"ToolFinished\""))
        .map(|l| format!("{l}\n"))
        .collect();
    fs::write(journal_path(&r, 1), cut).unwrap();
    let a = audit_with(&state, &r.run, None, TASK, &UserPolicy::default());
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
    let (state, ws) = scratch("env-read-on-timeout");
    let r = go(&state, &ws, vec![read("a.txt"), submit()]);
    as_failed_keeping(&r, "timeout", Some(pressed_sample()), true);
    let a = audit_with(&state, &r.run, None, TASK, &UserPolicy::default());
    assert_eq!(a.outcome, UNREADABLE);
}

#[test]
fn a_resume_re_feeds_a_timed_out_catch_up_step_with_its_sample() {
    let (state, ws) = scratch("env-resume");
    let r = go(&state, &ws, vec![read("a.txt"), read("b.txt"), submit()]);
    // Step 1 timed out on a pressed host; the run died in step 2.
    as_failed(&r, "timeout", Some(pressed_sample()));
    crash_after(&journal_path(&r, 1), 3);
    let res = resume_with(&state, &ws, &r.run, TASK, vec![read("b.txt"), submit()]).unwrap();
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
    let a = audit_with(&state, &r.run, Some(2), TASK, &UserPolicy::default());
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
        let (state, ws) = scratch(&format!("env-{name}"));
        let r = go(&state, &ws, vec![read("a.txt"), submit()]);
        as_failed(&r, status, env);
        let a = audit_with(&state, &r.run, None, TASK, &UserPolicy::default());
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
    let (state, ws) = scratch("other-build");
    let r = go(&state, &ws, vec![read("a.txt"), submit()]);
    rechain(
        &journal_path(&r, 1),
        |v| v["kind"] == "RunStarted",
        |b| b["builtin_manifest"] = Value::from("0".repeat(64)),
    );
    let a = audit_with(&state, &r.run, None, TASK, &UserPolicy::default());
    assert_eq!(a.outcome, UNREADABLE);
    assert!(a.divergence.unwrap().why.contains("another harness build"));
}
