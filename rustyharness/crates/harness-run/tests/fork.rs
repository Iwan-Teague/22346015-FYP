//! P-32: `fork_session`. Whole sessions through the public API: a parent
//! session runs to its end against a scripted model, then a child is
//! forked from it at a recorded step. The child's first record is
//! `ForkedFrom` (the parent run, the kept fork step, the parent's chain
//! head there), its catch-up re-feeds the parent's kept records, the
//! parent's journal is byte for byte untouched, a fork at a step the
//! parent does not carry is refused, the workspace must hold (or be
//! restored to) the tree the kept records end with, and a child whose
//! recorded parent head no longer matches the parent's journal is
//! refused by the audit.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs;
use std::time::Instant;

use gate_outcome::{GateOutcome, IndeterminateKind};
use harness_core::environment::{EnvSample, Unmeasured};
use harness_core::StopCause;
use harness_journal::layout;
use harness_journal::{EventKind, JournalReader, Record};
use harness_model::profile::Profile;
use harness_model::scripted::ScriptedBackend;
use harness_model::{Completion, ModelError, TaskText};
use harness_policy::locality::{FsQuery, LocalityProbe};
use harness_policy::UserPolicy;
use harness_run::{
    audit_session, fork_session, run_session, Audit, ForkSession, InputEnd, RunRefused,
    SessionConfig, SessionReport, SessionRun, TaskSpec, UserInput, UserInputEvent, UserMessage,
};
use harness_testkit::{act, registry, say, Fixture};

/// A fixed environment sample (the real probe is harness-sandbox's; these
/// tests only need the header and records to carry one).
const FIXED_ENV: EnvSample = EnvSample::unmeasured(Unmeasured::NoSafeApi);

/// The token budget every scripted session is given.
const TOKENS: u64 = 1_000_000;

const NOTHING_CHECKED: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::NothingChecked,
};

// ---------------------------------------------------------------------------
// Scripted inputs, policy and runs.
// ---------------------------------------------------------------------------

/// A scripted [`UserInput`]: the messages in order, then `eof`.
struct ScriptedInput {
    messages: RefCell<VecDeque<String>>,
}

impl ScriptedInput {
    fn new(messages: &[&str]) -> Self {
        Self {
            messages: RefCell::new(messages.iter().map(|s| (*s).to_owned()).collect()),
        }
    }
}

impl UserInput for ScriptedInput {
    fn next(&self, _deadline: Instant) -> UserInputEvent {
        match self.messages.borrow_mut().pop_front() {
            Some(text) => UserInputEvent::Message(UserMessage::new(text).expect("message")),
            None => UserInputEvent::End(InputEnd::Eof),
        }
    }
}

struct Local;
impl LocalityProbe for Local {
    fn query(&self, _path: &str) -> FsQuery {
        FsQuery::MacOs {
            mnt_local: true,
            fs_type_name: "apfs".into(),
        }
    }
}

/// The policy a session edits under: the edit tools allowed without
/// asking (reads are always allowed).
fn allow_edits() -> UserPolicy {
    UserPolicy::new(&[], &[], &["harness.edit.write", "harness.edit.delete"]).unwrap()
}

/// A spec granting the read anchor and the edit tools over a private
/// workspace.
fn spec() -> TaskSpec {
    TaskSpec {
        task: TaskText::new("Keep the workspace's notes.".into()),
        grants: vec![
            "harness.fs.read".into(),
            "harness.edit.write".into(),
            "harness.edit.delete".into(),
        ],
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

fn fx(name: &str) -> Fixture {
    let mut fx = Fixture::new(&format!("fork-{name}")).unwrap();
    fx.spec = spec();
    fx
}

fn write(p: &str, content: &str) -> Result<Completion, ModelError> {
    Ok(act(
        "harness.edit.write",
        &serde_json::json!({ "path": p, "content": content }).to_string(),
    ))
}

fn read(p: &str) -> Result<Completion, ModelError> {
    Ok(act("harness.fs.read", &format!("{{\"path\":\"{p}\"}}")))
}

/// The parent these tests fork from: two turns — the first reads and
/// rewrites `a.txt`, the second says goodbye — ending at `eof`.
fn parent_fixture(name: &str) -> (Fixture, SessionReport) {
    let fx = fx(name);
    fx.write("a.txt", "one\n").unwrap();
    let policy = allow_edits();
    let profile = Profile::conservative_default("m");
    let backend = ScriptedBackend::new(
        profile.clone(),
        vec![
            read("a.txt"),
            write("a.txt", "two\n"),
            Ok(say("done")),
            Ok(say("bye")),
        ],
    );
    let input = ScriptedInput::new(&["change a.txt", "that is all"]);
    let r = run_session(SessionRun {
        state_root: fx.state_root(),
        workspace: fx.workspace(),
        spec: &fx.spec,
        registry: &registry().unwrap(),
        policy: &policy,
        profile: &profile,
        backend: &backend,
        probe: &Local,
        env: &FIXED_ENV,
        config: &SessionConfig::defaults(TOKENS),
        approver: None,
        confinement: None,
        input: &input,
        sink: None,
        instructions: None,
    })
    .unwrap();
    (fx, r)
}

fn records(r: &SessionReport) -> Vec<Record> {
    JournalReader::open(&layout::attempt_dir(&r.run.run_dir, r.run.attempt))
        .unwrap()
        .records
}

/// The first turn boundary's step: a complete, mid-conversation fork
/// point (everything up to it is kept, the session's end is after it).
fn first_turn_end(r: &SessionReport) -> u64 {
    records(r)
        .iter()
        .find(|x| x.kind == EventKind::TurnEnded)
        .unwrap()
        .step
}

fn parent_journal_bytes(r: &SessionReport) -> Vec<u8> {
    fs::read(layout::attempt_dir(&r.run.run_dir, r.run.attempt).join(layout::JOURNAL_FILE)).unwrap()
}

/// Fork `parent` at `step`, continuing live with `replies` against the
/// input messages (then `eof`).
fn fork(
    fx: &Fixture,
    parent: &SessionReport,
    step: u64,
    replies: Vec<Result<Completion, ModelError>>,
    messages: &[&str],
) -> Result<SessionReport, RunRefused> {
    let policy = allow_edits();
    let profile = Profile::conservative_default("m");
    let backend = ScriptedBackend::new(profile.clone(), replies);
    let input = ScriptedInput::new(messages);
    fork_session(ForkSession {
        state_root: fx.state_root(),
        parent: &parent.run.run,
        parent_step: step,
        workspace: Some(fx.workspace()),
        spec: &fx.spec,
        registry: &registry().unwrap(),
        policy: &policy,
        profile: &profile,
        backend: &backend,
        probe: &Local,
        env: &FIXED_ENV,
        config: &SessionConfig::defaults(TOKENS),
        approver: None,
        confinement: None,
        input: &input,
        sink: None,
    })
}

/// The child's audit, the way the other session tests run it.
fn audit_child(fx: &Fixture, child: &SessionReport) -> harness_run::AuditReport {
    let config = SessionConfig::defaults(TOKENS);
    let mut limits = config.run.limits.clone();
    limits.format_errors = u32::MAX;
    audit_session(
        Audit {
            state_root: fx.state_root(),
            run: &child.run.run,
            attempt: None,
            anchor: child.run.chain_head,
            spec: &fx.spec,
            registry: &registry().unwrap(),
            policy: &allow_edits(),
            profile: &Profile::conservative_default("m"),
            limits: &limits,
        },
        &config.turn,
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// The slice-card tests.
// ---------------------------------------------------------------------------

// The forked child runs, its first record is `ForkedFrom` naming the
// parent, the kept fork step and the parent's chain head there, and its
// audit — which recomputes that head from the parent's journal — is
// clean.
#[test]
fn fork_child_audits_clean_and_links_parent() {
    let (fx, parent) = parent_fixture("child-clean");
    assert_eq!(parent.run.cause, StopCause::SessionEnded);
    let step = first_turn_end(&parent);
    // The recorded head is the last kept record's hash: the last record
    // at or before the fork step (the fork keeps the whole step, the
    // turn boundary being complete).
    let head = records(&parent)
        .iter()
        .rev()
        .find(|x| x.step <= step)
        .unwrap()
        .hash;
    let child = fork(
        &fx,
        &parent,
        step,
        vec![Ok(say("child here"))],
        &["carry on"],
    )
    .unwrap();
    assert_eq!(child.run.cause, StopCause::SessionEnded);
    assert_ne!(child.run.run, parent.run.run, "a new run");

    let recs = records(&child);
    let forks: Vec<_> = recs
        .iter()
        .filter(|x| x.kind == EventKind::ForkedFrom)
        .collect();
    assert_eq!(forks.len(), 1, "exactly one ForkedFrom, first after header");
    assert_eq!(forks[0].seq, 1, "the first record after the header");
    assert_eq!(
        forks[0].body["parent_run"].as_str().unwrap(),
        parent.run.run.as_str()
    );
    assert_eq!(forks[0].body["parent_step"].as_u64().unwrap(), step);
    assert_eq!(
        forks[0].body["parent_chain_head"].as_str().unwrap(),
        head.to_string(),
        "the parent's chain head at the fork point"
    );

    let a = audit_child(&fx, &child);
    assert_eq!(a.divergence, None, "the child's replay matches its journal");
    assert!(a.stop_recomputed);
    assert_eq!(a.outcome, NOTHING_CHECKED);
}

// A fork only reads the parent: its journal bytes and its run directory
// (no new attempt) are exactly what they were.
#[test]
fn fork_parent_unchanged() {
    let (fx, parent) = parent_fixture("parent-unchanged");
    let step = first_turn_end(&parent);
    let before = parent_journal_bytes(&parent);
    let attempts_before: Vec<_> = fs::read_dir(&parent.run.run_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();

    let child = fork(
        &fx,
        &parent,
        step,
        vec![Ok(say("child here"))],
        &["carry on"],
    )
    .unwrap();

    assert_eq!(
        child.run.run_dir.parent(),
        parent.run.run_dir.parent(),
        "the child lives in the same state root"
    );
    let after = parent_journal_bytes(&parent);
    assert_eq!(
        before, after,
        "the parent journal is byte for byte the same"
    );
    let attempts_after: Vec<_> = fs::read_dir(&parent.run.run_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(attempts_before, attempts_after, "no new parent attempt");
}

// A fork at a step the parent's journal does not carry is refused before
// anything is written.
#[test]
fn fork_at_missing_step_refused() {
    let (fx, parent) = parent_fixture("missing-step");
    let err = fork(
        &fx,
        &parent,
        9_999,
        vec![Ok(say("never asked"))],
        &["carry on"],
    )
    .unwrap_err();
    match err {
        RunRefused::NotResumable(why) => {
            assert!(
                why.contains("no step 9999"),
                "the refusal names the missing step: {why}"
            );
        }
        other => panic!("expected NotResumable, got {other:?}"),
    }
}

// The workspace must hold the tree the kept records end with: when it
// holds the parent's LATER state, the fork first undoes the parent's
// edits after the fork point (a.txt back to its pre-image); when a file
// was changed outside the harness since, the fork is refused and the
// workspace keeps what it holds.
#[test]
fn fork_requires_workspace_digest_match_or_restore() {
    // Restore path: fork at the first turn's end, while the workspace
    // holds the second turn's state — there is no second-turn edit in
    // this parent, so make the mismatch by rewriting the file first and
    // forking before any of it: the parent's edit is after the fork
    // point, so the undo puts `a.txt` back.
    let (fx, parent) = parent_fixture("restore-path");
    let edit_step = records(&parent)
        .iter()
        .find(|x| x.kind == EventKind::EditApplied)
        .unwrap()
        .step;
    // Fork at the step BEFORE the edit (the read's complete step): the
    // kept prefix ends before the write, so the tree the kept records
    // end with is the turn's start tree, while the workspace holds the
    // parent's post-edit state.
    let before_edit = edit_step - 1;
    assert_eq!(
        fs::read_to_string(fx.workspace().join("a.txt")).unwrap(),
        "two\n"
    );
    let child = fork(
        &fx,
        &parent,
        before_edit,
        vec![Ok(say("child here"))],
        &["carry on"],
    )
    .unwrap();
    assert_eq!(child.run.cause, StopCause::SessionEnded);
    assert_eq!(
        fs::read_to_string(fx.workspace().join("a.txt")).unwrap(),
        "one\n",
        "the parent's post-fork-point edit was undone"
    );
    let a = audit_child(&fx, &child);
    assert_eq!(a.divergence, None);

    // Refusal path: the file was changed outside the harness since the
    // parent ran, so no record's digest matches it and the undo cannot
    // proceed. The fork is refused, nothing is journaled, the file keeps
    // what it holds.
    let (fx, parent) = parent_fixture("refuse-path");
    let edit_step = records(&parent)
        .iter()
        .find(|x| x.kind == EventKind::EditApplied)
        .unwrap()
        .step;
    let before_edit = edit_step - 1;
    fs::write(fx.workspace().join("a.txt"), "external\n").unwrap();
    let before = parent_journal_bytes(&parent);
    let err = fork(
        &fx,
        &parent,
        before_edit,
        vec![Ok(say("never asked"))],
        &["carry on"],
    )
    .unwrap_err();
    match err {
        RunRefused::NotResumable(why) => assert!(
            why.contains("restored") || why.contains("differs"),
            "the refusal names the workspace: {why}"
        ),
        other => panic!("expected NotResumable, got {other:?}"),
    }
    assert_eq!(
        fs::read_to_string(fx.workspace().join("a.txt")).unwrap(),
        "external\n",
        "the external edit stands"
    );
    assert_eq!(
        before,
        parent_journal_bytes(&parent),
        "the parent journal is untouched by the refusal"
    );
}

// A child whose recorded `parent_chain_head` no longer matches the
// parent's journal — here because the parent's journal was tampered
// with after the fork — is refused by the audit.
#[test]
fn fork_parent_tampered_refused() {
    let (fx, parent) = parent_fixture("tampered");
    let step = first_turn_end(&parent);
    let child = fork(
        &fx,
        &parent,
        step,
        vec![Ok(say("child here"))],
        &["carry on"],
    )
    .unwrap();
    // Sanity: the untampered child audits clean.
    assert_eq!(audit_child(&fx, &child).divergence, None);

    // Tamper a middle byte of the parent journal: it no longer verifies.
    let path =
        layout::attempt_dir(&parent.run.run_dir, parent.run.attempt).join(layout::JOURNAL_FILE);
    let mut bytes = fs::read(&path).unwrap();
    let at = bytes.len() / 2;
    bytes[at] ^= 0xff;
    fs::write(&path, &bytes).unwrap();

    let a = audit_child(&fx, &child);
    let d = a
        .divergence
        .expect("the tampered parent must diverge the audit");
    assert!(
        d.why.contains("forked parent"),
        "the refusal names the forked parent: {}",
        d.why
    );
}
