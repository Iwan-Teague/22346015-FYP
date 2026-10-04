//! The scripted scenario suite (P-20): twelve end-to-end sessions through
//! the public `run_session` (one of them resumed through
//! `resume_session`), each a real-world shape — fix a failing test, add a
//! function, rename across files, refuse a bad path and recover, recover
//! from a stale read, trip the loop detector, spend a turn budget, repair
//! a turned-back submission, take a refusal and an alternative
//! approval, resume after a kill, compact a long context, and a two-turn
//! follow-up. A real state root and workspace on disk (a
//! `harness-testkit` fixture), the real journal, the real tools, a
//! scripted model and a scripted [`UserInput`]; every test asserts the
//! final files, the journal's records and a clean session audit.
//!
//! The two scenarios that run real commands (the fake test runner and the
//! pre-submit check) are macOS-gated: on this host the commands run in
//! the real sandbox, exactly as `tests/exec.rs` and `tests/presubmit.rs`
//! do.

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

use harness_core::environment::{EnvSample, Unmeasured};
use harness_core::StopCause;
use harness_journal::layout;
use harness_journal::{EventKind, JournalReader, Record};
use harness_model::profile::Profile;
use harness_model::scripted::ScriptedBackend;
use harness_model::{Completion, ModelError, TaskText};
use harness_policy::UserPolicy;
use harness_run::{
    resume_session, run_session, ApprovalAnswer, Approver, ApproverKind, InputEnd, ResumeSession,
    RunRefused, SessionConfig, SessionReport, SessionRun, TaskSpec, TurnLimits, UserInput,
    UserInputEvent, UserMessage,
};
use harness_testkit::{act, registry, say, submit, Fixture, Local};

/// A fixed environment sample (the real probe is harness-sandbox's; these
/// tests only need the header and records to carry one).
const FIXED_ENV: EnvSample = EnvSample::unmeasured(Unmeasured::NoSafeApi);

/// The token budget every scripted session is given.
const TOKENS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Scripted inputs and approver.
// ---------------------------------------------------------------------------

/// A scripted [`UserInput`]: each step is a closure producing the next
/// event, so a test can compute a message from what the run did so far
/// (as `tests/session.rs`).
struct ScriptedInput {
    steps: RefCell<VecDeque<Box<dyn Fn() -> UserInputEvent>>>,
}

impl ScriptedInput {
    /// One message step.
    fn message(text: &str) -> Box<dyn Fn() -> UserInputEvent> {
        let text = text.to_owned();
        Box::new(move || UserInputEvent::Message(UserMessage::new(text.clone()).expect("message")))
    }

    /// A message computed when the input is polled (after the previous
    /// turn ended).
    #[allow(dead_code)]
    fn then(computed: Box<dyn Fn() -> UserInputEvent>) -> Self {
        Self {
            steps: RefCell::new(VecDeque::from([computed])),
        }
    }

    /// Messages in order; the input ends with `eof` after the last.
    fn of(msgs: &[&str]) -> Self {
        Self {
            steps: RefCell::new(msgs.iter().map(|m| Self::message(m)).collect()),
        }
    }

    /// The input reports `End` immediately.
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

/// An approver that answers each ask with its next scripted answer (a
/// `Yes` once the script runs out, so a test only scripts the
/// interesting asks).
struct ScriptedApprover {
    answers: RefCell<VecDeque<ApprovalAnswer>>,
}

impl Approver for ScriptedApprover {
    fn kind(&self) -> ApproverKind {
        ApproverKind::Embedded
    }

    fn ask(
        &self,
        _req: &harness_policy::approval::ApprovalRequest,
        _deadline: Instant,
    ) -> ApprovalAnswer {
        match self.answers.borrow_mut().pop_front() {
            Some(a) => a,
            None => ApprovalAnswer::Yes,
        }
    }
}

// ---------------------------------------------------------------------------
// Drivers and journal readers.
// ---------------------------------------------------------------------------

/// Run a session with explicit everything.
#[allow(clippy::too_many_arguments)]
fn drive(
    fx: &Fixture,
    profile: &Profile,
    policy: &UserPolicy,
    replies: Vec<Result<Completion, ModelError>>,
    input: &dyn UserInput,
    config: &SessionConfig,
    approver: Option<&dyn Approver>,
    confinement: Option<&dyn harness_sandbox::Confinement>,
) -> Result<SessionReport, RunRefused> {
    let reg = registry().unwrap();
    let backend = ScriptedBackend::new(profile.clone(), replies);
    run_session(SessionRun {
        state_root: fx.state_root(),
        workspace: fx.workspace(),
        spec: &fx.spec,
        registry: &reg,
        policy,
        profile,
        backend: &backend,
        probe: &Local,
        env: &FIXED_ENV,
        config,
        approver,
        confinement,
        input,
        instructions: None,
        sink: None,
    })
}

/// A session under the defaults: the conservative default profile, an
/// edits-and-commands-allowed policy, ok replies, messages, no approver
/// and no confinement.
fn go(fx: &Fixture, replies: Vec<Completion>, msgs: &[&str]) -> SessionReport {
    let policy = allow_tools(&[]);
    drive(
        fx,
        &Profile::conservative_default("m"),
        &policy,
        replies.into_iter().map(Ok).collect(),
        &ScriptedInput::of(msgs),
        &SessionConfig::defaults(TOKENS),
        None,
        None,
    )
    .unwrap()
}

/// A policy that allows exactly `tools` without asking (the unattended
/// policy; reads are always allowed).
fn allow_tools(tools: &[&str]) -> UserPolicy {
    UserPolicy::new(&[], &[], tools).unwrap()
}

/// A task spec with the given grants and nothing else.
fn spec(task: &str, grants: &[&str]) -> TaskSpec {
    TaskSpec {
        task: TaskText::new(task.into()),
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

/// A read action.
fn read(p: &str) -> Completion {
    act("harness.fs.read", &format!("{{\"path\":\"{p}\"}}"))
}

/// A replace action.
fn replace(p: &str, old: &str, new: &str) -> Completion {
    act(
        "harness.edit.replace",
        &format!("{{\"path\":\"{p}\",\"old\":\"{old}\",\"new\":\"{new}\"}}"),
    )
}

/// A write action.
fn write_file(p: &str, content: &str) -> Completion {
    act(
        "harness.edit.write",
        &format!("{{\"path\":\"{p}\",\"content\":\"{content}\"}}"),
    )
}

/// A multi-edit action with one `(old, new)` pair.
fn multi(p: &str, old: &str, new: &str) -> Completion {
    act(
        "harness.edit.multi",
        &format!("{{\"path\":\"{p}\",\"edits\":[{{\"old\":\"{old}\",\"new\":\"{new}\"}}]}}"),
    )
}

/// The workspace file's contents.
fn ws_file(fx: &Fixture, rel: &str) -> String {
    fs::read_to_string(fx.workspace().join(rel)).unwrap()
}

fn records(r: &SessionReport) -> Vec<Record> {
    JournalReader::open(&layout::attempt_dir(&r.run.run_dir, r.run.attempt))
        .unwrap()
        .records
}

fn kinds(r: &SessionReport) -> Vec<EventKind> {
    records(r).iter().map(|rec| rec.kind).collect()
}

fn count(r: &SessionReport, k: EventKind) -> usize {
    kinds(r).into_iter().filter(|x| *x == k).count()
}

fn rec_bodies(r: &SessionReport, k: EventKind) -> Vec<serde_json::Map<String, serde_json::Value>> {
    records(r)
        .iter()
        .filter(|x| x.kind == k)
        .map(|x| x.body.clone())
        .collect()
}

fn bodies(recs: &[Record], k: EventKind) -> Vec<&serde_json::Map<String, serde_json::Value>> {
    recs.iter()
        .filter(|r| r.kind == k)
        .map(|r| &r.body)
        .collect()
}

/// A clean session audit under the defaults (the common assertion).
fn audited(fx: &Fixture, r: &SessionReport) {
    harness_testkit::assert_session_audit_clean(fx, r).unwrap();
}

fn journal_path(r: &SessionReport, attempt: u32) -> PathBuf {
    layout::attempt_dir(&r.run.run_dir, attempt).join(layout::JOURNAL_FILE)
}

/// Cut a journal just before its first record of kind `kind` at `step`
/// (a crash mid-session: whole lines survive, `RunStopped` is gone), as
/// `tests/replay_session.rs`.
fn crash_in(path: &Path, step: u64, kind: &str) {
    let text = fs::read_to_string(path).unwrap();
    let mut out = String::new();
    for line in text.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let s = v["step"].as_u64().unwrap();
        if s > step || (s == step && v["kind"] == kind) || v["kind"] == "RunStopped" {
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    fs::write(path, out).unwrap();
}

// ---------------------------------------------------------------------------
// The scenarios.
// ---------------------------------------------------------------------------

/// Scenario 2: add a function to an existing module — read it, write the
/// extended contents back, submit.
#[test]
fn scenario_02_adds_a_function() {
    let fx = Fixture::with_spec(
        "scenario-02-add-fn",
        spec(
            "Add a `two` function to util.rs, then submit.",
            &["harness.fs.read", "harness.edit.write"],
        ),
    )
    .unwrap();
    fx.write("util.rs", "pub fn one() -> u32 { 1 }\n").unwrap();
    let policy = allow_tools(&["harness.edit.write"]);
    let r = drive(
        &fx,
        &Profile::conservative_default("m"),
        &policy,
        vec![
            Ok(read("util.rs")),
            Ok(write_file(
                "util.rs",
                "pub fn one() -> u32 { 1 }\\npub fn two() -> u32 { 2 }\\n",
            )),
            Ok(submit()),
        ],
        &ScriptedInput::of(&["add the two function"]),
        &SessionConfig::defaults(TOKENS),
        None,
        None,
    )
    .unwrap();
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(
        ws_file(&fx, "util.rs"),
        "pub fn one() -> u32 { 1 }\npub fn two() -> u32 { 2 }\n"
    );
    let recs = records(&r);
    assert_eq!(count(&r, EventKind::EditApplied), 1);
    assert_eq!(count(&r, EventKind::SubmitRequested), 1);
    let ends = bodies(&recs, EventKind::TurnEnded);
    assert_eq!(ends[0]["reason"], "submitted");
    assert_eq!(ends[0]["steps"], 3);
    assert_eq!(recs.last().unwrap().kind, EventKind::RunStopped);
    harness_testkit::assert_session_audit_clean_with(
        &fx,
        &policy,
        &Profile::conservative_default("m"),
        &r,
        &SessionConfig::defaults(TOKENS),
        None,
    )
    .unwrap();
}

/// Scenario 3: rename a function across two files with multi-edits —
/// read both, rewrite each occurrence, submit.
#[test]
fn scenario_03_renames_across_files_with_multi_edits() {
    let fx = Fixture::with_spec(
        "scenario-03-rename",
        spec(
            "Rename old_name to new_name everywhere, then submit.",
            &["harness.fs.read", "harness.edit.multi"],
        ),
    )
    .unwrap();
    fx.write("a.rs", "pub fn old_name() -> u32 {\n    1\n}\n")
        .unwrap();
    fx.write("b.rs", "pub fn call() -> u32 {\n    old_name()\n}\n")
        .unwrap();
    let policy = allow_tools(&["harness.edit.multi"]);
    let r = drive(
        &fx,
        &Profile::conservative_default("m"),
        &policy,
        vec![
            Ok(read("a.rs")),
            Ok(read("b.rs")),
            Ok(multi("a.rs", "old_name", "new_name")),
            Ok(multi("b.rs", "old_name", "new_name")),
            Ok(submit()),
        ],
        &ScriptedInput::of(&["rename it"]),
        &SessionConfig::defaults(TOKENS),
        None,
        None,
    )
    .unwrap();
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(
        ws_file(&fx, "a.rs"),
        "pub fn new_name() -> u32 {\n    1\n}\n"
    );
    assert_eq!(
        ws_file(&fx, "b.rs"),
        "pub fn call() -> u32 {\n    new_name()\n}\n"
    );
    assert_eq!(count(&r, EventKind::EditApplied), 2);
    let ends = rec_bodies(&r, EventKind::TurnEnded);
    assert_eq!(ends[0]["reason"], "submitted");
    assert_eq!(ends[0]["steps"], 5);
    harness_testkit::assert_session_audit_clean_with(
        &fx,
        &policy,
        &Profile::conservative_default("m"),
        &r,
        &SessionConfig::defaults(TOKENS),
        None,
    )
    .unwrap();
}

/// Scenario 4: an edit outside the workspace is refused by policy (no
/// tool ran), the turn carries on, and an in-workspace edit succeeds.
#[test]
fn scenario_04_refuses_out_of_workspace_edit_then_recovers() {
    let fx = Fixture::with_spec(
        "scenario-04-escape",
        spec(
            "You may only edit inside the workspace.",
            &["harness.fs.read", "harness.edit.write"],
        ),
    )
    .unwrap();
    fx.write("a.txt", "inside\n").unwrap();
    let policy = allow_tools(&["harness.edit.write"]);
    let r = drive(
        &fx,
        &Profile::conservative_default("m"),
        &policy,
        vec![
            Ok(read("a.txt")),
            Ok(write_file("../escape.txt", "nope\\n")),
            Ok(write_file("a.txt", "fixed\\n")),
            Ok(submit()),
        ],
        &ScriptedInput::of(&["fix a.txt"]),
        &SessionConfig::defaults(TOKENS),
        None,
        None,
    )
    .unwrap();
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    // The escape was refused before any tool ran and wrote nothing.
    assert_eq!(count(&r, EventKind::PolicyDecided), 4);
    let recs = records(&r);
    let denies: Vec<&serde_json::Map<String, serde_json::Value>> =
        bodies(&recs, EventKind::PolicyDecided)
            .into_iter()
            .filter(|b| b["decision"] == "deny")
            .collect();
    assert_eq!(denies.len(), 1);
    assert_eq!(denies[0]["reason"], "path_outside_workspace");
    assert_eq!(count(&r, EventKind::ToolStarted), 3, "no tool for the deny");
    assert!(!fx.base().join("escape.txt").exists());
    assert_eq!(ws_file(&fx, "a.txt"), "fixed\n");
    let ends = rec_bodies(&r, EventKind::TurnEnded);
    assert_eq!(ends[0]["reason"], "submitted");
    assert_eq!(ends[0]["steps"], 4);
    harness_testkit::assert_session_audit_clean_with(
        &fx,
        &policy,
        &Profile::conservative_default("m"),
        &r,
        &SessionConfig::defaults(TOKENS),
        None,
    )
    .unwrap();
}

/// Scenario 5: the file changes outside the harness between turns, the
/// stale edit is refused with the stale-read code, a re-read clears it,
/// and the retried edit applies.
#[test]
fn scenario_05_recovers_from_a_stale_read() {
    let fx = Fixture::with_spec(
        "scenario-05-stale",
        spec(
            "Edit a.txt for me.",
            &["harness.fs.read", "harness.edit.replace"],
        ),
    )
    .unwrap();
    fx.write("a.txt", "alpha beta\n").unwrap();
    let policy = allow_tools(&["harness.edit.replace"]);
    // The second message is computed when polled: before it, the file
    // changes OUTSIDE the harness.
    let ws = fx.workspace().to_path_buf();
    let second: Box<dyn Fn() -> UserInputEvent> = Box::new(move || {
        fs::write(ws.join("a.txt"), "alpha GAMMA\n").unwrap();
        UserInputEvent::Message(UserMessage::new("now change it".into()).unwrap())
    });
    let input = ScriptedInput {
        steps: RefCell::new(
            vec![ScriptedInput::message("read a.txt"), second]
                .into_iter()
                .collect(),
        ),
    };
    let r = drive(
        &fx,
        &Profile::conservative_default("m"),
        &policy,
        vec![
            Ok(read("a.txt")),
            Ok(say("I have read it.")),
            Ok(replace("a.txt", "alpha", "ALPHA")),
            Ok(read("a.txt")),
            Ok(replace("a.txt", "alpha", "ALPHA")),
            Ok(say("Edited after the re-read.")),
        ],
        &input,
        &SessionConfig::defaults(TOKENS),
        None,
        None,
    )
    .unwrap();
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(ws_file(&fx, "a.txt"), "ALPHA GAMMA\n");
    let recs = records(&r);
    // The external change is journaled with the turn that first sees it.
    let turns = bodies(&recs, EventKind::UserTurn);
    assert_eq!(turns[0]["external_change"], false);
    assert_eq!(turns[1]["external_change"], true);
    // The stale edit: a tool error with the stale-read code, no edit.
    let stale: Vec<&serde_json::Map<String, serde_json::Value>> = recs
        .iter()
        .filter(|x| x.kind == EventKind::ToolFinished && x.body["status"] == "error")
        .map(|x| &x.body)
        .collect();
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0]["code"], harness_tools::builtin::code::STALE_READ);
    assert_eq!(
        count(&r, EventKind::EditApplied),
        1,
        "only the retry edited"
    );
    let ends = bodies(&recs, EventKind::TurnEnded);
    assert_eq!(ends[0]["reason"], "answered");
    assert_eq!(ends[1]["reason"], "answered");
    assert_eq!(ends[1]["steps"], 4);
    harness_testkit::assert_session_audit_clean_with(
        &fx,
        &policy,
        &Profile::conservative_default("m"),
        &r,
        &SessionConfig::defaults(TOKENS),
        None,
    )
    .unwrap();
}

/// Scenario 6: three identical reads on an unchanged tree trip the loop
/// detector; the turn ends `loop:repeat` and the session carries on with
/// the next message.
#[test]
fn scenario_06_loop_detector_ends_the_turn() {
    let fx = Fixture::new("scenario-06-loop").unwrap();
    fx.write("a.txt", "hello\n").unwrap();
    let mut replies: Vec<Completion> = (0..6).map(|_| read("a.txt")).collect();
    replies.push(say("done looking"));
    let r = go(&fx, replies, &["read it", "anything else?"]);
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(ws_file(&fx, "a.txt"), "hello\n");
    let recs = records(&r);
    // A stop-level loop detection was journaled and the turn ended for it.
    let loops = bodies(&recs, EventKind::LoopDetected);
    assert!(
        loops
            .iter()
            .any(|b| b["stop"] == true && b["kind"] == "repeat"),
        "{loops:?}"
    );
    let ends = bodies(&recs, EventKind::TurnEnded);
    assert_eq!(ends[0]["reason"], "loop:repeat");
    assert_eq!(ends[1]["reason"], "answered");
    assert_eq!(r.turns, 2);
    audited(&fx, &r);
}

/// Scenario 7: a three-step turn allowance warns on the last step and the
/// submission still ends the turn as a submission.
#[test]
fn scenario_07_budget_notice_then_submit() {
    let fx = Fixture::with_spec(
        "scenario-07-budget",
        spec("Read a.txt and b.txt, then submit.", &["harness.fs.read"]),
    )
    .unwrap();
    fx.write("a.txt", "alpha\n").unwrap();
    fx.write("b.txt", "beta\n").unwrap();
    let mut cfg = SessionConfig::defaults(TOKENS);
    cfg.turn = TurnLimits {
        steps: 3,
        format_errors: 3,
    };
    let r = drive(
        &fx,
        &Profile::conservative_default("m"),
        &allow_tools(&[]),
        vec![
            Ok(read("a.txt")),
            Ok(read("b.txt")),
            Ok(submit()),
            Ok(say("spare turn")),
        ],
        &ScriptedInput::of(&["go", "and now"]),
        &cfg,
        None,
        None,
    )
    .unwrap();
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    // The notice fired once, naming the last step, before the submit.
    let notes = rec_bodies(&r, EventKind::BudgetNotice);
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert_eq!(notes[0]["key"], "last_step");
    assert_eq!(notes[0]["used"], 2);
    assert_eq!(notes[0]["limit"], 3);
    let ends = rec_bodies(&r, EventKind::TurnEnded);
    assert_eq!(ends[0]["reason"], "submitted");
    assert_eq!(ends[0]["steps"], 3);
    assert_eq!(ends[1]["reason"], "answered");
    harness_testkit::assert_session_audit_clean_with(
        &fx,
        &allow_tools(&[]),
        &Profile::conservative_default("m"),
        &r,
        &cfg,
        None,
    )
    .unwrap();
}

/// Scenario 9: the approver refuses the first ask (a replace) and grants
/// the second (a write); the denied ask ran nothing and the turn still
/// ended in an applied edit.
#[test]
fn scenario_09_approval_denied_then_alternative() {
    let fx = Fixture::with_spec(
        "scenario-09-approval",
        spec(
            "Edit a.txt (each edit is approved).",
            &[
                "harness.fs.read",
                "harness.edit.replace",
                "harness.edit.write",
            ],
        ),
    )
    .unwrap();
    fx.write("a.txt", "v1\n").unwrap();
    let approver = ScriptedApprover {
        answers: RefCell::new(VecDeque::from([ApprovalAnswer::No])),
    };
    // The default policy asks for every edit.
    let r = drive(
        &fx,
        &Profile::conservative_default("m"),
        &UserPolicy::default(),
        vec![
            Ok(read("a.txt")),
            Ok(replace("a.txt", "v1", "v2")),
            Ok(write_file("a.txt", "v2\\n")),
            Ok(say("Used the write tool instead.")),
        ],
        &ScriptedInput::of(&["edit a.txt"]),
        &SessionConfig::defaults(TOKENS),
        Some(&approver),
        None,
    )
    .unwrap();
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(ws_file(&fx, "a.txt"), "v2\n");
    let recs = records(&r);
    assert_eq!(count(&r, EventKind::ApprovalRequested), 2);
    assert_eq!(count(&r, EventKind::ApprovalDenied), 1);
    assert_eq!(count(&r, EventKind::ApprovalGranted), 1);
    assert_eq!(count(&r, EventKind::EditApplied), 1);
    let ends = bodies(&recs, EventKind::TurnEnded);
    assert_eq!(ends[0]["reason"], "answered");
    assert_eq!(ends[0]["steps"], 4);
    audited(&fx, &r);
}

/// Scenario 10: a kill between the edit's write-ahead intent and its
/// result; the resume drops the incomplete step, re-runs it live with a
/// re-fed reply, and the new attempt audits clean.
#[test]
fn scenario_10_resume_after_kill_between_intent_and_result() {
    let fx = Fixture::with_spec(
        "scenario-10-resume",
        spec(
            "Edit note.txt.",
            &["harness.fs.read", "harness.edit.replace"],
        ),
    )
    .unwrap();
    fx.write("note.txt", "v1\n").unwrap();
    let policy = allow_tools(&["harness.edit.replace"]);
    let r = drive(
        &fx,
        &Profile::conservative_default("m"),
        &policy,
        vec![
            Ok(read("note.txt")),
            Ok(replace("note.txt", "v1", "v2")),
            Ok(say("Edited it.")),
        ],
        &ScriptedInput::of(&["edit note.txt"]),
        &SessionConfig::defaults(TOKENS),
        None,
        None,
    )
    .unwrap();
    // Kill between step 2's ToolStarted and its ToolFinished, and put the
    // workspace back the way it was before the edit applied (the real run
    // completed; the crash is simulated on the journal only).
    crash_in(&journal_path(&r, 1), 2, "ToolFinished");
    fx.write("note.txt", "v1\n").unwrap();
    let profile = Profile::conservative_default("m");
    let res = {
        let backend = ScriptedBackend::new(
            profile.clone(),
            vec![Ok(replace("note.txt", "v1", "v2")), Ok(say("Edited it."))],
        );
        resume_session(ResumeSession {
            state_root: fx.state_root(),
            run: &r.run.run,
            workspace: Some(fx.workspace()),
            spec: &fx.spec,
            registry: &registry().unwrap(),
            policy: &policy,
            profile: &profile,
            backend: &backend,
            probe: &Local,
            env: &FIXED_ENV,
            config: &SessionConfig::defaults(TOKENS),
            input: &ScriptedInput::ends(InputEnd::Eof),
            approver: None,
            sink: None,
            confinement: None,
        })
        .unwrap()
    };
    assert_eq!(res.run.attempt, 2);
    assert_eq!(res.run.cause, StopCause::SessionEnded);
    assert_eq!(res.turns, 1, "the interrupted turn finished live");
    assert_eq!(ws_file(&fx, "note.txt"), "v2\n");
    assert_eq!(count(&res, EventKind::EditApplied), 1);
    let ends = rec_bodies(&res, EventKind::TurnEnded);
    assert_eq!(ends[0]["reason"], "answered");
    // The resumed attempt audits clean, anchored by its own chain head.
    harness_testkit::assert_session_audit_clean_with(
        &fx,
        &policy,
        &Profile::conservative_default("m"),
        &res,
        &SessionConfig::defaults(TOKENS),
        Some(2),
    )
    .unwrap();
}

/// Scenario 11: a session with a small context window and several large
/// reads compacts within one turn, and the compaction audits clean.
#[test]
fn scenario_11_long_session_compacts() {
    let fx = Fixture::with_spec(
        "scenario-11-compact",
        spec(
            "Read the three big files and say done.",
            &["harness.fs.read"],
        ),
    )
    .unwrap();
    let big = "line of text for the compaction scenario\n".repeat(400);
    fx.write("f1.txt", &big).unwrap();
    fx.write("f2.txt", &big).unwrap();
    fx.write("f3.txt", &big).unwrap();
    let profile = small_window_profile();
    let r = drive(
        &fx,
        &profile,
        &allow_tools(&[]),
        vec![
            Ok(read("f1.txt")),
            Ok(read("f2.txt")),
            Ok(read("f3.txt")),
            Ok(say("done")),
        ],
        &ScriptedInput::of(&["read them all"]),
        &SessionConfig::defaults(TOKENS),
        None,
        None,
    )
    .unwrap();
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    // The first build was whole; a later one was a compaction.
    let builds = rec_bodies(&r, EventKind::ContextBuilt);
    assert!(builds.len() >= 4, "{:?}", builds.len());
    assert_eq!(builds[0]["compacted"], false);
    assert!(
        builds.iter().any(|b| b["compacted"] == true),
        "no build was a compaction"
    );
    let ends = rec_bodies(&r, EventKind::TurnEnded);
    assert_eq!(ends[0]["reason"], "answered");
    harness_testkit::assert_session_audit_clean_with(
        &fx,
        &allow_tools(&[]),
        &profile,
        &r,
        &SessionConfig::defaults(TOKENS),
        None,
    )
    .unwrap();
}

/// A profile with a small context window (the same shape
/// `tests/stable_context.rs` uses), so a few large reads overflow it.
fn small_window_profile() -> Profile {
    Profile::parse(
        r#"{"profile_version":1,"id":"scenarios-small","model":"m","context_window":8192,
        "fill_ratio":0.6,"protocol":"text","tool_choice_required_ok":false,"grammar":"none",
        "max_active_tools":6,"edit_format":"replace","recent_turns":5,
        "sampling":{"temperature":0.2,"top_p":0.95,"seed":7,"max_tokens":1024}}"#
            .as_bytes(),
    )
    .unwrap()
}

/// Scenario 12: a follow-up question in a second turn — both turns are
/// journaled in one attempt in the exact session order, and the audit is
/// clean.
#[test]
fn scenario_12_two_turn_follow_up() {
    let fx = Fixture::new("scenario-12-follow-up").unwrap();
    fx.write("a.txt", "hello from the workspace\n").unwrap();
    let r = go(
        &fx,
        vec![say("first answer"), say("second answer")],
        &["what does a.txt say?", "and in one word?"],
    );
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(r.turns, 2);
    assert_eq!(r.run.steps, 2);
    assert!(r.run.chain_head.is_some());
    let recs = records(&r);
    let names: Vec<EventKind> = recs.iter().map(|x| x.kind).collect();
    assert_eq!(
        names,
        vec![
            EventKind::RunStarted,
            EventKind::UserTurn,
            EventKind::ContextBuilt,
            EventKind::ModelRequested,
            EventKind::ModelReplied,
            EventKind::TurnEnded,
            EventKind::UserTurn,
            EventKind::ContextBuilt,
            EventKind::ModelRequested,
            EventKind::ModelReplied,
            EventKind::TurnEnded,
            EventKind::InputEnded,
            EventKind::RunStopped,
        ]
    );
    let turns = bodies(&recs, EventKind::UserTurn);
    assert_eq!(turns[0]["turn"], 1);
    assert_eq!(turns[1]["turn"], 2);
    for t in &turns {
        assert_eq!(t["shown"], "yes");
    }
    let ends = bodies(&recs, EventKind::TurnEnded);
    assert_eq!(ends[0]["reason"], "answered");
    assert_eq!(ends[1]["reason"], "answered");
    let input = bodies(&recs, EventKind::InputEnded);
    assert_eq!(input[0]["reason"], "eof");
    assert_eq!(input[0]["turn"], 2);
    audited(&fx, &r);
}

// ---------------------------------------------------------------------------
// The macOS-gated scenario 8 (its check is a real sandboxed command).
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod live {
    use super::*;

    const EXEC: &str = "harness.exec.run";

    /// A check that passes only once `fixed.txt` exists.
    const NEEDS_FIXED: &str = "print qq{looking for fixed.txt\\n}; exit(-e q{fixed.txt} ? 0 : 3)";

    /// The production confinement, counting spawns (one live-probed
    /// witness per test binary, as `tests/exec.rs`).
    pub(super) struct Counting(pub(super) std::sync::atomic::AtomicUsize);
    impl harness_sandbox::Confinement for Counting {
        fn require(&self) -> Result<harness_sandbox::Conformed, harness_sandbox::Refused> {
            static W: std::sync::OnceLock<
                Result<harness_sandbox::Conformed, harness_sandbox::Refused>,
            > = std::sync::OnceLock::new();
            W.get_or_init(|| harness_sandbox::SystemConfinement.require())
                .clone()
        }
        fn spawn(
            &self,
            s: &harness_sandbox::ConfinedSpec,
            ev: &harness_sandbox::Conformed,
        ) -> Result<harness_sandbox::ConfinedChild, harness_sandbox::SpawnError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            harness_sandbox::SystemConfinement.spawn(s, ev)
        }
    }

    /// A perl one-liner as a command vector.
    fn perl(script: &str) -> Vec<String> {
        vec!["perl".into(), "-e".into(), script.into()]
    }

    /// The exec section every command here needs: `/usr/bin/perl` alone.
    fn perl_spec() -> harness_run::ExecSpec {
        harness_run::ExecSpec {
            programs: vec![harness_run::ExecProgram {
                name: "perl".into(),
                path: "/usr/bin/perl".into(),
            }],
            ..harness_run::ExecSpec::default()
        }
    }

    /// Scenario 1: fix a failing unit test — read the source, replace the
    /// broken constant, run the allowlisted `cargo` (a fake script that
    /// passes only once the source is fixed) and submit.
    #[test]
    fn scenario_01_fixes_a_failing_test_and_submits() {
        static C: Counting = Counting(std::sync::atomic::AtomicUsize::new(0));
        let mut fx = Fixture::new("scenario-01-fix-test").unwrap();
        fx.write("calc.txt", "answer = BROKEN\n").unwrap();
        let tools = fx.base().join("tools");
        fs::create_dir_all(&tools).unwrap();
        let cargo = tools.join("cargo");
        fs::write(
            &cargo,
            "#!/usr/bin/perl\nopen(my $f, q{<}, q{calc.txt}) or die; local $/; my $c = <$f>;\
             \nif ($c =~ /FIXED/) { print qq{test result: ok\\n}; exit 0 }\
             \nprint qq{test result: FAIL\\n}; exit 1\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let tools = fs::canonicalize(&tools).unwrap();
        fx.spec = TaskSpec {
            task: TaskText::new("Make the failing test pass and submit.".into()),
            grants: vec![
                "harness.fs.read".into(),
                "harness.edit.replace".into(),
                EXEC.into(),
            ],
            workspace_public: false,
            ports: Vec::new(),
            lan_ports: Vec::new(),
            exec: Some(harness_run::ExecSpec {
                programs: vec![harness_run::ExecProgram {
                    name: "cargo".into(),
                    path: tools.join("cargo"),
                }],
                // The program must lie inside a read-only root the sandbox
                // executes from.
                read_only: vec![tools.clone()],
                ..harness_run::ExecSpec::default()
            }),
            presubmit: None,
            post_edit: None,
            protected: Vec::new(),
            kind: harness_run::SessionKind::Coding,
        };
        let policy = allow_tools(&["harness.edit.replace", EXEC]);
        let r = drive(
            &fx,
            &Profile::conservative_default("m"),
            &policy,
            vec![
                Ok(read("calc.txt")),
                Ok(replace("calc.txt", "BROKEN", "FIXED")),
                Ok(act(EXEC, "{\"argv\":[\"cargo\"]}")),
                Ok(submit()),
            ],
            &ScriptedInput::of(&["make the test pass"]),
            &SessionConfig::defaults(TOKENS),
            None,
            Some(&C),
        )
        .unwrap();
        assert_eq!(r.run.cause, StopCause::SessionEnded);
        assert_eq!(ws_file(&fx, "calc.txt"), "answer = FIXED\n");
        let recs = records(&r);
        // The replace applied, the fake test ran and passed, and the turn
        // ended with the accepted submission.
        assert_eq!(count(&r, EventKind::EditApplied), 1);
        let x: Vec<&serde_json::Map<String, serde_json::Value>> = recs
            .iter()
            .filter(|r| r.kind == EventKind::ToolFinished && r.body.contains_key("exec"))
            .map(|r| &r.body)
            .collect();
        assert_eq!(x.len(), 1);
        assert_eq!(x[0]["status"], "ok");
        assert_eq!(x[0]["exec"]["end"], "exited");
        assert_eq!(x[0]["exec"]["code"], 0);
        assert_eq!(x[0]["exec"]["cleanup"], "confirmed");
        let ends = bodies(&recs, EventKind::TurnEnded);
        assert_eq!(ends[0]["reason"], "submitted");
        assert_eq!(count(&r, EventKind::SubmitRequested), 1);
        harness_testkit::assert_session_audit_clean_with(
            &fx,
            &policy,
            &Profile::conservative_default("m"),
            &r,
            &SessionConfig::defaults(TOKENS),
            None,
        )
        .unwrap();
    }

    /// Scenario 8: the first submission's pre-submit check fails, the
    /// submission is turned back, the model repairs the workspace and the
    /// second submission passes — all inside one turn.
    #[test]
    fn scenario_08_presubmit_turn_back_then_pass() {
        static C: Counting = Counting(std::sync::atomic::AtomicUsize::new(0));
        let mut fx = Fixture::new("scenario-08-presubmit").unwrap();
        fx.spec = TaskSpec {
            task: TaskText::new("Provide fixed.txt and submit.".into()),
            grants: vec![
                "harness.fs.read".into(),
                "harness.edit.write".into(),
                EXEC.into(),
            ],
            workspace_public: false,
            ports: Vec::new(),
            lan_ports: Vec::new(),
            exec: Some(perl_spec()),
            presubmit: Some(harness_run::PresubmitSpec {
                commands: vec![perl(NEEDS_FIXED)],
                max_rounds: 2,
            }),
            post_edit: None,
            protected: Vec::new(),
            kind: harness_run::SessionKind::Coding,
        };
        let policy = allow_tools(&["harness.edit.write", EXEC]);
        let r = drive(
            &fx,
            &Profile::conservative_default("m"),
            &policy,
            vec![
                Ok(submit()),
                Ok(write_file("fixed.txt", "ok\\n")),
                Ok(submit()),
            ],
            &ScriptedInput::of(&["do it"]),
            &SessionConfig::defaults(TOKENS),
            None,
            Some(&C),
        )
        .unwrap();
        assert_eq!(r.run.cause, StopCause::SessionEnded);
        assert_eq!(ws_file(&fx, "fixed.txt"), "ok\n");
        // Two check rounds: failed then passed, turned back then accepted.
        let rounds = rec_bodies(&r, EventKind::PresubmitChecked);
        assert_eq!(rounds.len(), 2, "{rounds:?}");
        assert_eq!(rounds[0]["result"], "failed");
        assert_eq!(rounds[0]["accepted"], false);
        assert_eq!(rounds[1]["result"], "passed");
        assert_eq!(rounds[1]["accepted"], true);
        // The turned-back submission is a tool error the turn survives.
        let recs = records(&r);
        let rejected: Vec<&serde_json::Map<String, serde_json::Value>> = recs
            .iter()
            .filter(|x| x.kind == EventKind::ToolFinished && x.body["status"] == "error")
            .map(|x| &x.body)
            .collect();
        assert_eq!(rejected.len(), 1);
        assert!(
            rejected[0]["output"]["inline"]
                .as_str()
                .unwrap_or_default()
                .contains("looking for fixed.txt"),
            "{:?}",
            rejected[0]
        );
        let ends = rec_bodies(&r, EventKind::TurnEnded);
        assert_eq!(ends[0]["reason"], "submitted");
        harness_testkit::assert_session_audit_clean_with(
            &fx,
            &policy,
            &Profile::conservative_default("m"),
            &r,
            &SessionConfig::defaults(TOKENS),
            None,
        )
        .unwrap();
    }
}
