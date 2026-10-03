//! Audit replay and resume of sessions (P-17, P-05 §6/§7) over real
//! journals on disk. The batch suites (`tests/replay.rs`) stay the record
//! of batch behaviour; everything here is the session's.

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
use std::time::Instant;

use gate_outcome::{GateOutcome, IndeterminateKind};
use harness_core::environment::{EnvSample, Unmeasured};
use harness_core::{RunId, StopCause};
use harness_journal::canon::{RecordFields, GENESIS};
use harness_journal::{layout, EventKind, JournalReader};
use harness_model::profile::Profile;
use harness_model::scripted::ScriptedBackend;
use harness_model::{Completion, ModelError, TaskText};
use harness_policy::UserPolicy;
use harness_run::{
    audit, audit_session, resume, resume_session, run_session, Approver, Audit, InputEnd, Resume,
    ResumeSession, RunRefused, SessionConfig, SessionReport, SessionRun, TaskSpec, TurnLimits,
    UserInput, UserInputEvent, UserMessage,
};
use harness_testkit::{act, registry, run_scripted, say, submit, Fixture, Local};
use serde_json::Value;

/// A fixed environment sample (the real probe is harness-sandbox's; these
/// tests only need the header and records to carry one).
const FIXED_ENV: EnvSample = EnvSample::unmeasured(Unmeasured::NoSafeApi);

/// The token budget every scripted session is given.
const TOKENS: u64 = 1_000_000;

const TASK: &str = "Summarise a.txt and b.txt.";

const NOTHING_CHECKED: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::NothingChecked,
};

const UNREADABLE: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::UnreadableEvidence,
};

// ---------------------------------------------------------------------------
// Fixtures, drivers and journals.
// ---------------------------------------------------------------------------

/// A fixture with the two files and the task every session here starts
/// from.
fn fx(name: &str) -> Fixture {
    let mut fx = Fixture::new(&format!("session-replay-{name}")).unwrap();
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
        ports: Vec::new(),
        lan_ports: Vec::new(),
        exec: None,
        presubmit: None,
        protected: Vec::new(),
        kind: harness_run::SessionKind::Coding,
    }
}

/// A scripted [`UserInput`]: messages in order, then `End` (as
/// `tests/session.rs`).
struct ScriptedInput {
    steps: RefCell<VecDeque<Box<dyn Fn() -> UserInputEvent>>>,
}

impl ScriptedInput {
    fn message(text: &str) -> Box<dyn Fn() -> UserInputEvent> {
        let text = text.to_owned();
        Box::new(move || UserInputEvent::Message(UserMessage::new(text.clone()).expect("message")))
    }

    fn of(msgs: &[&str]) -> Self {
        Self {
            steps: RefCell::new(msgs.iter().map(|m| Self::message(m)).collect()),
        }
    }

    fn ends(end: InputEnd) -> Self {
        Self {
            steps: RefCell::new(VecDeque::from([
                Box::new(move || UserInputEvent::End(end)) as Box<dyn Fn() -> UserInputEvent>
            ])),
        }
    }
}

impl UserInput for ScriptedInput {
    fn next(&self, _deadline: Instant) -> UserInputEvent {
        match self.steps.borrow_mut().pop_front() {
            Some(step) => step(),
            None => UserInputEvent::End(InputEnd::Eof),
        }
    }
}

/// Run a session with explicit everything (defaults otherwise).
#[allow(clippy::too_many_arguments)]
fn drive_session(
    fx: &Fixture,
    replies: Vec<Result<Completion, ModelError>>,
    input: &dyn UserInput,
    config: &SessionConfig,
    approver: Option<&dyn Approver>,
) -> Result<SessionReport, RunRefused> {
    let reg = registry().unwrap();
    let profile = Profile::conservative_default("m");
    let backend = ScriptedBackend::new(profile.clone(), replies);
    run_session(SessionRun {
        state_root: fx.state_root(),
        workspace: fx.workspace(),
        spec: &fx.spec,
        registry: &reg,
        policy: &UserPolicy::default(),
        profile: &profile,
        backend: &backend,
        probe: &Local,
        env: &FIXED_ENV,
        config,
        approver,
        confinement: None,
        input,
        sink: None,
    })
}

/// Run a session with the defaults: ok replies, messages, no approver.
fn go_session(fx: &Fixture, replies: Vec<Completion>, msgs: &[&str]) -> SessionReport {
    drive_session(
        fx,
        replies.into_iter().map(Ok).collect(),
        &ScriptedInput::of(msgs),
        &SessionConfig::defaults(TOKENS),
        None,
    )
    .unwrap()
}

/// The limits a session's header carries (`session_limits` is not public;
/// this is its exact shape: the run's limits with the meter's
/// `format_errors` replaced by "never").
fn session_limits(config: &SessionConfig) -> harness_core::MeterLimits {
    let mut limits = config.run.limits.clone();
    limits.format_errors = u32::MAX;
    limits
}

/// The turn limits every session here is given.
fn turn_limits() -> TurnLimits {
    SessionConfig::defaults(TOKENS).turn
}

fn audit_session_with(
    fx: &Fixture,
    run: &RunId,
    attempt: Option<u32>,
    task: &str,
) -> harness_run::AuditReport {
    let config = SessionConfig::defaults(TOKENS);
    audit_session(
        Audit {
            state_root: fx.state_root(),
            run,
            attempt,
            anchor: None,
            spec: &spec(task),
            registry: &registry().unwrap(),
            policy: &UserPolicy::default(),
            profile: &Profile::conservative_default("m"),
            limits: &session_limits(&config),
        },
        &turn_limits(),
    )
    .unwrap()
}

fn resume_session_with(
    fx: &Fixture,
    run: &RunId,
    replies: Vec<Completion>,
    input: &ScriptedInput,
    config: &SessionConfig,
) -> Result<SessionReport, RunRefused> {
    let profile = Profile::conservative_default("m");
    let backend = ScriptedBackend::new(profile.clone(), replies.into_iter().map(Ok).collect());
    resume_session(ResumeSession {
        state_root: fx.state_root(),
        run,
        workspace: Some(fx.workspace()),
        spec: &fx.spec,
        registry: &registry().unwrap(),
        policy: &UserPolicy::default(),
        profile: &profile,
        backend: &backend,
        probe: &Local,
        env: &FIXED_ENV,
        config,
        input,
        approver: None,
        sink: None,
        confinement: None,
    })
}

fn journal_path(run_dir: &Path, attempt: u32) -> PathBuf {
    layout::attempt_dir(run_dir, attempt).join(layout::JOURNAL_FILE)
}

fn records_of(run_dir: &Path, attempt: u32) -> harness_journal::Verified {
    JournalReader::open(&layout::attempt_dir(run_dir, attempt)).unwrap()
}

/// `(kind, body)` of every record at `step`, for re-fed-prefix equality.
fn bodies_at(v: &harness_journal::Verified, s: u64) -> Vec<(EventKind, Value)> {
    v.records
        .iter()
        .filter(|x| x.step == s)
        .map(|x| (x.kind, Value::Object(x.body.clone())))
        .collect()
}

/// Rewrite a journal, keeping each line only if `keep` says so, applying
/// `edit` to every kept record, and re-chaining every hash: a forger who
/// re-chains. Only an anchor or the replay itself can catch this.
fn rewrite_journal(
    path: &Path,
    keep: impl Fn(&Value) -> bool,
    edit: impl Fn(&mut Value),
) -> Vec<Value> {
    let text = fs::read_to_string(path).unwrap();
    let mut prev = GENESIS;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut v: Value = serde_json::from_str(line).unwrap();
        if !keep(&v) {
            continue;
        }
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
        let mut line = bytes;
        line.push(b'\n');
        out.push((v, line));
        prev = hash;
    }
    let bytes: Vec<u8> = out.iter().flat_map(|(_, l)| l.iter().copied()).collect();
    fs::write(path, bytes).unwrap();
    out.into_iter().map(|(v, _)| v).collect()
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

// ---- audit -------------------------------------------------------------------------

/// A two-turn session audits clean: every record is recomputed or re-fed
/// and matches, the stop is recomputed, and the outcome is the plain
/// nothing-checked of a journal that vouches for itself.
#[test]
fn audit_of_two_turn_session_is_clean() {
    let fx = fx("audit-clean");
    let r = go_session(&fx, vec![say("first"), say("second")], &["one", "two"]);
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    let a = audit_session_with(&fx, &r.run.run, None, TASK);
    assert_eq!(a.divergence, None, "{a:?}");
    assert!(a.stop_recomputed, "the session_ended stop is recomputed");
    assert!(!a.anchored);
    assert_eq!(a.outcome, NOTHING_CHECKED);
    let recorded = records_of(&r.run.run_dir, r.run.attempt);
    assert_eq!(a.matched, recorded.records.len() - 1);
    assert_eq!(a.replay_dir.unwrap(), layout::replay_dir(&r.run.run_dir, 1));
    // The recorded attempt is untouched; a second audit gets replay-2.
    let again = audit_session_with(&fx, &r.run.run, Some(1), TASK);
    assert_eq!(
        again.replay_dir.unwrap(),
        layout::replay_dir(&r.run.run_dir, 2)
    );
}

/// The recorded user text is evidence: re-chain an edited `UserTurn` text
/// and the replay's own re-fed turn diverges from it.
#[test]
fn audit_detects_edited_user_turn_text() {
    let fx = fx("audit-edited-text");
    let r = go_session(&fx, vec![say("first"), say("second")], &["one", "two"]);
    rewrite_journal(
        &journal_path(&r.run.run_dir, 1),
        |_| true,
        |v| {
            if v["kind"] == "UserTurn" && v["body"]["turn"] == 1 {
                let t = v["body"]["text"]["inline"]
                    .as_str()
                    .unwrap()
                    .replace("one", "OWN");
                v["body"]["text"]["inline"] = Value::from(t.clone());
                v["body"]["text"]["sha256"] =
                    Value::from(harness_core::sha256(t.as_bytes()).to_string());
            }
        },
    );
    let a = audit_session_with(&fx, &r.run.run, None, TASK);
    assert_eq!(a.outcome, UNREADABLE);
    let d = a.divergence.expect("the edited text is caught");
    // The re-fed turn 1 matches (its text is evidence, re-fed verbatim);
    // the first record recomputed from it does not: turn 1's context.
    assert_eq!(d.step, 1, "{d:?}");
    assert!(d.why.contains("different body"), "{d:?}");
}

/// A dropped turn (its records re-chained away) diverges: the replayed
/// turns are numbered 1, 2 but the journal says 1, 3.
#[test]
fn audit_detects_dropped_turn() {
    let fx = fx("audit-dropped-turn");
    let r = go_session(
        &fx,
        vec![say("first"), say("second"), say("third")],
        &["one", "two", "three"],
    );
    rewrite_journal(
        &journal_path(&r.run.run_dir, 1),
        |v| {
            !(v["kind"] == "UserTurn" && v["body"]["turn"] == 2)
                && !(v["kind"] == "TurnEnded" && v["body"]["turn"] == 2)
                && !(v["kind"] == "ContextBuilt" && v["step"] == 2)
                && !(v["kind"] == "ModelRequested" && v["step"] == 2)
                && !(v["kind"] == "ModelReplied" && v["step"] == 2)
        },
        |_| {},
    );
    let a = audit_session_with(&fx, &r.run.run, None, TASK);
    assert_eq!(a.outcome, UNREADABLE);
    assert!(a.divergence.is_some(), "{a:?}");
}

/// `external_change` is recomputed from the re-fed tree, not trusted: a
/// forged flag diverges at the turn's record.
#[test]
fn audit_detects_forged_external_change_flag() {
    let fx = fx("audit-forged-external");
    let r = go_session(&fx, vec![say("first"), say("second")], &["one", "two"]);
    rewrite_journal(
        &journal_path(&r.run.run_dir, 1),
        |_| true,
        |v| {
            if v["kind"] == "UserTurn" && v["body"]["turn"] == 1 {
                v["body"]["external_change"] = Value::from(true);
            }
        },
    );
    let a = audit_session_with(&fx, &r.run.run, None, TASK);
    assert_eq!(a.outcome, UNREADABLE);
    let d = a.divergence.expect("the forged flag is caught");
    assert_eq!(d.step, 0, "{d:?}");
}

/// A turn's wall time must not go backwards: a decreasing
/// `wall_used_ms` is a divergence before the loop even runs.
#[test]
fn audit_detects_decreasing_wall_used() {
    let fx = fx("audit-decreasing-wall");
    let r = go_session(&fx, vec![say("first"), say("second")], &["one", "two"]);
    rewrite_journal(
        &journal_path(&r.run.run_dir, 1),
        |_| true,
        |v| {
            if v["kind"] == "UserTurn" && v["body"]["turn"] == 1 {
                v["body"]["wall_used_ms"] = Value::from(100_000u64);
            }
            if v["kind"] == "UserTurn" && v["body"]["turn"] == 2 {
                v["body"]["wall_used_ms"] = Value::from(0u64);
            }
        },
    );
    let a = audit_session_with(&fx, &r.run.run, None, TASK);
    assert_eq!(a.outcome, UNREADABLE);
    let d = a.divergence.expect("the decreasing wall is caught");
    assert!(d.why.contains("wall"), "{d:?}");
}

/// A reserved kind is not a shape the loop writes: a session journal
/// carrying one diverges by name.
#[test]
fn reserved_kind_in_session_journal_diverges() {
    let fx = fx("audit-reserved-kind");
    let r = go_session(&fx, vec![say("first"), say("second")], &["one", "two"]);
    rewrite_journal(
        &journal_path(&r.run.run_dir, 1),
        |_| true,
        |v| {
            if v["kind"] == "TurnEnded" && v["body"]["turn"] == 1 {
                v["kind"] = Value::from("ModeChanged");
                v["body"] = serde_json::json!({});
            }
        },
    );
    let a = audit_session_with(&fx, &r.run.run, None, TASK);
    assert_eq!(a.outcome, UNREADABLE);
    let d = a.divergence.expect("the reserved kind is caught");
    assert_eq!(d.why, "a record is not the shape the loop writes", "{d:?}");
}

/// Batch behaviour is unchanged: a batch journal audits clean as before,
/// and a session audit of it is refused at the header's mode.
#[test]
fn batch_audit_unchanged() {
    let fx = fx("batch-unchanged");
    let r = run_scripted(&fx, vec![read("a.txt"), read("b.txt"), submit()]).unwrap();
    assert_eq!(r.cause, StopCause::Submitted);
    let a = audit(Audit {
        state_root: fx.state_root(),
        run: &r.run,
        attempt: None,
        anchor: None,
        spec: &spec(TASK),
        registry: &registry().unwrap(),
        policy: &UserPolicy::default(),
        profile: &Profile::conservative_default("m"),
        limits: &harness_run::RunConfig::defaults(TOKENS).limits,
    })
    .unwrap();
    assert_eq!(a.divergence, None);
    assert!(a.stop_recomputed);
    assert_eq!(a.outcome, NOTHING_CHECKED);
    let recorded = records_of(&r.run_dir, r.attempt);
    assert_eq!(a.matched, recorded.records.len() - 1);

    // The same batch journal through the session audit: refused at mode.
    let config = SessionConfig::defaults(TOKENS);
    let s = audit_session(
        Audit {
            state_root: fx.state_root(),
            run: &r.run,
            attempt: None,
            anchor: None,
            spec: &spec(TASK),
            registry: &registry().unwrap(),
            policy: &UserPolicy::default(),
            profile: &Profile::conservative_default("m"),
            limits: &session_limits(&config),
        },
        &turn_limits(),
    )
    .unwrap();
    assert_eq!(s.outcome, UNREADABLE);
    let d = s.divergence.expect("the batch journal is refused");
    assert_eq!(d.seq, 0);
    // The first refused key decides the wording: `context_format` (a
    // session's is /6) is checked before `mode` (see
    // `batch_audit_refuses_session_journal_by_mode`). Either refusal is
    // the fail-closed answer.
    assert!(
        d.why.contains("mode") || d.why.contains("context format"),
        "{d:?}"
    );
}

// ---- resume ------------------------------------------------------------------------

/// A session cut mid-turn resumes in a new attempt: the kept steps are
/// re-fed record for record and the interrupted turn's next step runs
/// live; the session then asks for its next input.
#[test]
fn resume_session_mid_turn_continues() {
    let fx = fx("resume-mid-turn");
    let r = go_session(&fx, vec![say("first"), say("second")], &["one", "two"]);
    // Turn 2 was shown but its first step (the build at step 2) never
    // happened: the kept records end at turn 2's `UserTurn`.
    crash_in(&journal_path(&r.run.run_dir, 1), 2, "ContextBuilt");
    let before = fs::read(journal_path(&r.run.run_dir, 1)).unwrap();
    let old = records_of(&r.run.run_dir, 1);
    let res = resume_session_with(
        &fx,
        &r.run.run,
        vec![read("b.txt"), say("done")],
        &ScriptedInput::ends(InputEnd::Eof),
        &SessionConfig::defaults(TOKENS),
    )
    .unwrap();
    assert_eq!(res.run.attempt, 2);
    assert_eq!(res.run.cause, StopCause::SessionEnded);
    assert_eq!(res.turns, 2, "turn 2 completed live; no turn 3 was asked");
    assert_eq!(
        fs::read(journal_path(&r.run.run_dir, 1)).unwrap(),
        before,
        "attempt-1 is only read"
    );
    let new = records_of(&r.run.run_dir, 2);
    let from = &new.records[0].body["resumed_from"];
    assert_eq!(from["attempt"], 1);
    assert_eq!(from["chain_head"], Value::from(old.head.to_string()));
    // Step 1 of the new attempt is the recorded step 1, record for record
    // (the catch-up re-fed it, turn 2's `UserTurn` included).
    assert_eq!(bodies_at(&new, 1), bodies_at(&old, 1));
    // And the resumed attempt itself audits clean.
    let a = audit_session_with(&fx, &r.run.run, Some(2), TASK);
    assert_eq!(a.divergence, None, "{a:?}");
}

/// A session cut at a turn boundary resumes by asking for the next
/// message: turns 1 and 2 are re-fed, turn 3 comes from the input.
#[test]
fn resume_session_at_boundary_waits_for_input() {
    let fx = fx("resume-boundary");
    let r = go_session(&fx, vec![say("first"), say("second")], &["one", "two"]);
    // Cut before the input's end: turn 2 is complete on the record.
    crash_in(&journal_path(&r.run.run_dir, 1), 2, "InputEnded");
    let old = records_of(&r.run.run_dir, 1);
    let res = resume_session_with(
        &fx,
        &r.run.run,
        vec![say("third")],
        &ScriptedInput::of(&["go on"]),
        &SessionConfig::defaults(TOKENS),
    )
    .unwrap();
    assert_eq!(res.run.attempt, 2);
    assert_eq!(res.run.cause, StopCause::SessionEnded);
    assert_eq!(res.turns, 3, "two re-fed, the third from the input");
    let new = records_of(&r.run.run_dir, 2);
    assert_eq!(bodies_at(&new, 1), bodies_at(&old, 1));
    let turns: Vec<Value> = new
        .records
        .iter()
        .filter(|x| x.kind == EventKind::UserTurn)
        .map(|x| Value::Object(x.body.clone()))
        .collect();
    assert_eq!(turns.len(), 3);
    assert_eq!(turns[2]["turn"], 3);
    assert_eq!(turns[2]["text"]["inline"], "go on");
    let a = audit_session_with(&fx, &r.run.run, Some(2), TASK);
    assert_eq!(a.divergence, None, "{a:?}");
}

/// At a turn boundary the workspace may have changed outside the run
/// (nothing of the session is mid-flight): the resume proceeds and the
/// next turn's `UserTurn` flags the external change.
#[test]
fn resume_session_at_boundary_accepts_external_change_and_flags_it() {
    let fx = fx("resume-boundary-external");
    let r = go_session(&fx, vec![say("first"), say("second")], &["one", "two"]);
    crash_in(&journal_path(&r.run.run_dir, 1), 2, "InputEnded");
    fx.write("c.txt", "arrived between attempts\n").unwrap();
    let res = resume_session_with(
        &fx,
        &r.run.run,
        vec![say("third")],
        &ScriptedInput::of(&["go on"]),
        &SessionConfig::defaults(TOKENS),
    )
    .unwrap();
    assert_eq!(res.run.attempt, 2);
    assert_eq!(res.turns, 3);
    let new = records_of(&r.run.run_dir, 2);
    let last_turn = new
        .records
        .iter()
        .rfind(|x| x.kind == EventKind::UserTurn)
        .unwrap();
    assert_eq!(last_turn.body["turn"], 3);
    assert_eq!(
        last_turn.body["external_change"], true,
        "the external change is journaled and flagged"
    );
}

/// Mid-turn, the workspace must still match what the session last
/// recorded: a change since the turn's `UserTurn` refuses the resume
/// (this build keeps no snapshot to restore) and writes nothing.
#[test]
fn resume_refuses_workspace_changed_since_last_record() {
    let fx = fx("resume-workspace-changed");
    let r = go_session(&fx, vec![say("first"), say("second")], &["one", "two"]);
    crash_in(&journal_path(&r.run.run_dir, 1), 2, "ContextBuilt");
    fx.write("a.txt", "changed mid-turn\n").unwrap();
    let e = resume_session_with(
        &fx,
        &r.run.run,
        vec![],
        &ScriptedInput::ends(InputEnd::Eof),
        &SessionConfig::defaults(TOKENS),
    )
    .unwrap_err();
    assert!(
        matches!(e, RunRefused::NotResumable(ref w) if w.contains("workspace differs")),
        "{e:?}"
    );
    assert!(
        !layout::attempt_dir(&r.run.run_dir, 2).exists(),
        "nothing was written"
    );
}

/// A session journal is not a batch attempt: the batch resume refuses it
/// at the header's mode.
#[test]
fn batch_resume_refuses_session_journal() {
    let fx = fx("batch-resume-session");
    let r = go_session(&fx, vec![say("first"), say("second")], &["one", "two"]);
    // Without the stop the mode check is the first refusal (a committed
    // session is "already stopped" to the batch resume).
    crash_in(&journal_path(&r.run.run_dir, 1), 2, "InputEnded");
    let profile = Profile::conservative_default("m");
    let backend = ScriptedBackend::new(profile.clone(), vec![]);
    let e = resume(Resume {
        state_root: fx.state_root(),
        run: &r.run.run,
        workspace: Some(fx.workspace()),
        spec: &fx.spec,
        registry: &registry().unwrap(),
        policy: &UserPolicy::default(),
        profile: &profile,
        backend: &backend,
        probe: &Local,
        env: &FIXED_ENV,
        config: &harness_run::RunConfig::defaults(TOKENS),
        approver: None,
        confinement: None,
    })
    .unwrap_err();
    assert!(
        matches!(e, RunRefused::NotResumable(ref w) if w.contains("mode") || w.contains("context format")),
        "{e:?}"
    );
}

/// A committed session attempt reopens where it ended: the `InputEnded`
/// and the `session_ended` stop are dropped and the next message is
/// asked.
#[test]
fn resume_session_reopens_session_ended() {
    let fx = fx("resume-reopen");
    let r = go_session(&fx, vec![say("first"), say("second")], &["one", "two"]);
    let res = resume_session_with(
        &fx,
        &r.run.run,
        vec![say("third")],
        &ScriptedInput::of(&["one more"]),
        &SessionConfig::defaults(TOKENS),
    )
    .unwrap();
    assert_eq!(res.run.attempt, 2);
    assert_eq!(res.run.cause, StopCause::SessionEnded);
    assert_eq!(res.turns, 3);
    let new = records_of(&r.run.run_dir, 2);
    let from = &new.records[0].body["resumed_from"];
    assert_eq!(from["attempt"], 1);
    let a = audit_session_with(&fx, &r.run.run, Some(2), TASK);
    assert_eq!(a.divergence, None, "{a:?}");
}

/// Any other committed stop ended the session for good: the resume
/// refuses with the recorded cause and writes nothing.
#[test]
fn resume_session_refuses_other_stops() {
    let fx = fx("resume-other-stop");
    let mut config = SessionConfig::defaults(TOKENS);
    config.run.limits.steps = 1;
    config.turn.steps = 1;
    let r = drive_session(
        &fx,
        vec![Ok(say("first"))],
        &ScriptedInput::of(&["one", "two"]),
        &config,
        None,
    )
    .unwrap();
    assert_eq!(
        r.run.cause,
        StopCause::Budget(harness_core::BudgetDim::Steps),
        "the step budget stopped the whole session"
    );
    let e = resume_session_with(
        &fx,
        &r.run.run,
        vec![],
        &ScriptedInput::of(&["go on"]),
        &SessionConfig::defaults(TOKENS),
    )
    .unwrap_err();
    assert!(
        matches!(e, RunRefused::NotResumable(ref w) if w.contains("the session stopped (")),
        "{e:?}"
    );
    assert!(
        !layout::attempt_dir(&r.run.run_dir, 2).exists(),
        "nothing was written"
    );
}

/// The resumed session is charged the working wall time its records
/// already spent, not an idle count from the input's end: a session cut
/// hours after its last step resumes already over its wall budget.
#[test]
fn resume_session_carries_working_wall_not_idle() {
    let fx = fx("resume-wall");
    let r = go_session(&fx, vec![say("first"), say("second")], &["one", "two"]);
    let path = journal_path(&r.run.run_dir, 1);
    crash_in(&path, 2, "InputEnded");
    // The recorded attempt had been running for 3 hours when its last
    // durable record (turn 2's `TurnEnded`) was written.
    let kept = rewrite_journal(
        &path,
        |_| true,
        |v| {
            if v["kind"] == "TurnEnded" && v["body"]["turn"] == 2 {
                v["t_mono_ms"] = Value::from(3 * 60 * 60 * 1000u64);
            }
        },
    );
    assert!(kept.iter().any(|v| v["kind"] == "TurnEnded"));
    let res = resume_session_with(
        &fx,
        &r.run.run,
        vec![],
        &ScriptedInput::ends(InputEnd::Eof),
        &SessionConfig::defaults(TOKENS),
    )
    .unwrap();
    let new = records_of(&r.run.run_dir, 2);
    let from = &new.records[0].body["resumed_from"];
    let carried = from["wall_carried_ms"].as_u64().unwrap();
    assert!(
        carried >= 2 * 60 * 60 * 1000,
        "the 3 hours of work are carried, not an idle count: {carried}"
    );
    assert_eq!(res.run.cause, StopCause::SessionEnded);
}
