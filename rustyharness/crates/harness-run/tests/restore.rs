//! P-26: `/undo` and `/rewind N`. Whole sessions through the public
//! `run_session`: a real state root and workspace on disk, the real
//! journal and tools, a scripted model and a scripted [`UserInput`] that
//! issues a restore command between turns. An undo puts the undone
//! edits' files back byte for byte (a deleted file is recreated, a
//! created one removed), the restored tree must come back at the
//! checkpoint the journal carries, a workspace changed outside the
//! harness refuses the restore, `--force-keep-external` keeps such
//! files, the `Restored` record audits clean, and the model is told
//! through the next request.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs;
use std::time::{Duration, Instant};

use gate_outcome::{GateOutcome, IndeterminateKind};
use harness_core::environment::{EnvSample, Unmeasured};
use harness_core::{Digest, StopCause};
use harness_journal::layout;
use harness_journal::reader::DirBlobSource;
use harness_journal::{EventKind, JournalReader};
use harness_model::profile::Profile;
use harness_model::scripted::ScriptedBackend;
use harness_model::{Completion, ModelBackend, ModelError, ModelIdentity, ModelRequest, TaskText};
use harness_policy::locality::{FsQuery, LocalityProbe};
use harness_policy::UserPolicy;
use harness_run::{
    audit_session, run_session, ApprovalAnswer, Approver, ApproverKind, Audit, InputEnd,
    RestoreCommand, SessionConfig, SessionReport, SessionRun, TaskSpec, UserInput, UserInputEvent,
    UserMessage,
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
// Scripted inputs, policy and journals.
// ---------------------------------------------------------------------------

/// A scripted [`UserInput`]: each step is a closure producing the next
/// event, so a test can act on the workspace between turns (write a file
/// behind the harness's back) before the command is issued. An input
/// that runs out ends the session with `eof`.
struct ScriptedInput {
    steps: RefCell<VecDeque<Box<dyn Fn() -> UserInputEvent>>>,
}

impl ScriptedInput {
    fn new(steps: Vec<Box<dyn Fn() -> UserInputEvent>>) -> Self {
        Self {
            steps: RefCell::new(steps.into()),
        }
    }

    fn message(text: &str) -> Box<dyn Fn() -> UserInputEvent> {
        let text = text.to_owned();
        Box::new(move || UserInputEvent::Message(UserMessage::new(text.clone()).expect("message")))
    }

    /// A `/undo`: the last edit group, refusing a changed-outside file.
    fn undo() -> Box<dyn Fn() -> UserInputEvent> {
        Box::new(|| {
            UserInputEvent::Restore(RestoreCommand {
                steps: 1,
                keep_external: false,
            })
        })
    }

    /// A `/rewind N [--force-keep-external]`, computed when polled (so a
    /// test can disturb the workspace first).
    fn rewind(steps: u64, keep_external: bool) -> Box<dyn Fn() -> UserInputEvent> {
        Box::new(move || {
            UserInputEvent::Restore(RestoreCommand {
                steps,
                keep_external,
            })
        })
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

struct Local;
impl LocalityProbe for Local {
    fn query(&self, _path: &str) -> FsQuery {
        FsQuery::MacOs {
            mnt_local: true,
            fs_type_name: "apfs".into(),
        }
    }
}

/// An approver that grants every ask (the delete/move file operations
/// ask on a confirmation floor no allow rule reaches).
struct Yes;

impl Approver for Yes {
    fn kind(&self) -> ApproverKind {
        ApproverKind::Embedded
    }

    fn ask(
        &self,
        _req: &harness_policy::approval::ApprovalRequest,
        _deadline: Instant,
    ) -> ApprovalAnswer {
        ApprovalAnswer::Yes
    }
}

/// The policy an unattended session edits under: the edit tools allowed
/// without asking (reads are always allowed).
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
    let mut fx = Fixture::new(&format!("restore-{name}")).unwrap();
    fx.spec = spec();
    fx
}

fn read(p: &str) -> Result<Completion, ModelError> {
    Ok(act("harness.fs.read", &format!("{{\"path\":\"{p}\"}}")))
}

fn write(p: &str, content: &str) -> Result<Completion, ModelError> {
    Ok(act(
        "harness.edit.write",
        &serde_json::json!({ "path": p, "content": content }).to_string(),
    ))
}

fn delete(p: &str) -> Result<Completion, ModelError> {
    Ok(act(
        "harness.edit.delete",
        &serde_json::json!({ "path": p }).to_string(),
    ))
}

fn records(r: &SessionReport) -> Vec<harness_journal::Record> {
    JournalReader::open(&layout::attempt_dir(&r.run.run_dir, r.run.attempt))
        .unwrap()
        .records
}

fn count(r: &SessionReport, k: EventKind) -> usize {
    records(r).iter().filter(|x| x.kind == k).count()
}

/// The `Restored` records' body: the checkpoint it went back to (step and
/// tree digest) and the files the undone edits named.
fn restored(r: &SessionReport) -> Vec<(u64, Digest, Vec<String>)> {
    let dir = layout::attempt_dir(&r.run.run_dir, r.run.attempt);
    let blobs = DirBlobSource::new(dir.join(layout::BLOBS_DIR));
    records(r)
        .iter()
        .filter(|x| x.kind == EventKind::Restored)
        .map(|x| {
            let to_step = x.body["to_step"].as_u64().unwrap();
            let tree: Digest = x.body["tree_digest"].as_str().unwrap().parse().unwrap();
            let bytes =
                harness_model::replay::payload_bytes(&x.body["files"], &blobs, x.seq).unwrap();
            let files: Vec<String> = serde_json::from_slice(&bytes).unwrap();
            (to_step, tree, files)
        })
        .collect()
}

fn run(
    fx: &Fixture,
    replies: Vec<Result<Completion, ModelError>>,
    input: &ScriptedInput,
    approver: Option<&dyn Approver>,
) -> SessionReport {
    let policy = allow_edits();
    let profile = Profile::conservative_default("m");
    let backend = ScriptedBackend::new(profile.clone(), replies);
    run_session(SessionRun {
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
        approver,
        confinement: None,
        input,
        instructions: None,
        sink: None,
    })
    .unwrap()
}

// ---------------------------------------------------------------------------
// The slice-card tests.
// ---------------------------------------------------------------------------

// `/undo` puts the last edit's file back byte for byte: the bytes the
// pre-image blob holds, and the tree the turn's checkpoint carried.
#[test]
fn undo_last_edit_restores_bytes() {
    let fx = fx("undo-last");
    fx.write("a.txt", "one\n").unwrap();
    let r = run(
        &fx,
        vec![read("a.txt"), write("a.txt", "two\n"), Ok(say("done"))],
        &ScriptedInput::new(vec![
            ScriptedInput::message("change a.txt"),
            ScriptedInput::undo(),
        ]),
        None,
    );
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(
        fs::read_to_string(fx.workspace().join("a.txt")).unwrap(),
        "one\n"
    );
    // One `Restored`: back to the user turn's checkpoint, naming the file.
    assert_eq!(count(&r, EventKind::Restored), 1);
    let turns: Vec<_> = records(&r)
        .into_iter()
        .filter(|x| x.kind == EventKind::UserTurn)
        .collect();
    assert_eq!(turns.len(), 1);
    let rs = restored(&r);
    assert_eq!(rs[0].0, turns[0].step, "back to the turn's checkpoint");
    assert_eq!(
        rs[0].1.to_string(),
        turns[0].body["workspace_tree"].as_str().unwrap(),
        "the checkpoint's tree digest"
    );
    assert_eq!(rs[0].2, vec!["a.txt".to_owned()]);
}

// `/rewind 3` walks three created files back: each is gone again, and the
// workspace's tree digest is the turn's checkpoint's, measured live.
#[test]
fn rewind_three_edits_tree_digest_matches() {
    let fx = fx("rewind-three");
    let r = run(
        &fx,
        vec![
            write("b.txt", "bee\n"),
            write("c.txt", "sea\n"),
            write("d.txt", "dee\n"),
            Ok(say("done")),
        ],
        &ScriptedInput::new(vec![
            ScriptedInput::message("take three notes"),
            ScriptedInput::rewind(3, false),
        ]),
        None,
    );
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    for name in ["b.txt", "c.txt", "d.txt"] {
        assert!(!fx.workspace().join(name).exists(), "{name} undone");
    }
    let rs = restored(&r);
    assert_eq!(rs.len(), 1);
    assert_eq!(rs[0].2, vec!["b.txt", "c.txt", "d.txt"]);
    let turns: Vec<_> = records(&r)
        .into_iter()
        .filter(|x| x.kind == EventKind::UserTurn)
        .collect();
    assert_eq!(
        rs[0].1.to_string(),
        turns[0].body["workspace_tree"].as_str().unwrap()
    );
    let live = harness_tools::builtin::workspace_tree(
        fx.workspace(),
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(live.digest(), rs[0].1, "the restored tree, measured");
}

// A file changed outside the harness since its last record refuses the
// rewind: nothing is applied, nothing is journaled, the files keep what
// they were left as.
#[test]
fn rewind_refuses_when_file_changed_outside() {
    let fx = fx("rewind-refuses");
    fx.write("a.txt", "one\n").unwrap();
    fx.write("b.txt", "one b\n").unwrap();
    let ws = fx.workspace().to_path_buf();
    let r = run(
        &fx,
        vec![
            read("a.txt"),
            write("a.txt", "two\n"),
            read("b.txt"),
            write("b.txt", "two b\n"),
            Ok(say("done")),
        ],
        &ScriptedInput::new(vec![
            ScriptedInput::message("rewrite both"),
            Box::new(move || {
                // The user edits b.txt behind the harness's back between
                // the turn and the command.
                fs::write(ws.join("b.txt"), "external\n").unwrap();
                UserInputEvent::Restore(RestoreCommand {
                    steps: 2,
                    keep_external: false,
                })
            }),
        ]),
        None,
    );
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(count(&r, EventKind::Restored), 0, "refused: not journaled");
    assert_eq!(
        fs::read_to_string(fx.workspace().join("a.txt")).unwrap(),
        "two\n",
        "nothing applied"
    );
    assert_eq!(
        fs::read_to_string(fx.workspace().join("b.txt")).unwrap(),
        "external\n",
        "the external edit stands"
    );
}

// `--force-keep-external` skips the refusal: the untouched file goes back
// to its pre-image bytes, the file changed outside keeps what it holds,
// and the record names every file the undone edits had touched.
#[test]
fn rewind_force_keep_external_restores_only_owned_files() {
    let fx = fx("rewind-force");
    fx.write("a.txt", "one\n").unwrap();
    fx.write("b.txt", "one b\n").unwrap();
    let ws = fx.workspace().to_path_buf();
    let r = run(
        &fx,
        vec![
            read("a.txt"),
            write("a.txt", "two\n"),
            read("b.txt"),
            write("b.txt", "two b\n"),
            Ok(say("done")),
        ],
        &ScriptedInput::new(vec![
            ScriptedInput::message("rewrite both"),
            Box::new(move || {
                fs::write(ws.join("b.txt"), "external\n").unwrap();
                UserInputEvent::Restore(RestoreCommand {
                    steps: 2,
                    keep_external: true,
                })
            }),
        ]),
        None,
    );
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(count(&r, EventKind::Restored), 1);
    assert_eq!(
        fs::read_to_string(fx.workspace().join("a.txt")).unwrap(),
        "one\n",
        "the owned file is restored"
    );
    assert_eq!(
        fs::read_to_string(fx.workspace().join("b.txt")).unwrap(),
        "external\n",
        "the external edit is kept"
    );
    assert_eq!(
        restored(&r)[0].2,
        vec!["a.txt".to_owned(), "b.txt".to_owned()],
        "every undone edit's file is named"
    );
}

// The `Restored` record is recomputed by an audit's replay from the
// journal's own edit records and the re-fed checkpoint: the audit is
// clean.
#[test]
fn restored_event_audited_clean() {
    let fx = fx("audited");
    fx.write("a.txt", "one\n").unwrap();
    let r = run(
        &fx,
        vec![read("a.txt"), write("a.txt", "two\n"), Ok(say("done"))],
        &ScriptedInput::new(vec![
            ScriptedInput::message("change a.txt"),
            ScriptedInput::undo(),
        ]),
        None,
    );
    assert_eq!(count(&r, EventKind::Restored), 1);
    let config = SessionConfig::defaults(TOKENS);
    let mut limits = config.run.limits.clone();
    limits.format_errors = u32::MAX;
    let a = audit_session(
        Audit {
            state_root: fx.state_root(),
            run: &r.run.run,
            attempt: None,
            anchor: r.run.chain_head,
            spec: &fx.spec,
            registry: &registry().unwrap(),
            policy: &allow_edits(),
            profile: &Profile::conservative_default("m"),
            limits: &limits,
        },
        &config.turn,
    )
    .unwrap();
    assert_eq!(a.divergence, None);
    assert!(a.stop_recomputed);
    assert_eq!(a.outcome, NOTHING_CHECKED);
}

// The model is told through the next request's notice slot: the request
// after the restore carries the restored-to-step text.
#[test]
fn restored_notice_reaches_context() {
    struct Capture {
        inner: ScriptedBackend,
        seen: RefCell<Vec<String>>,
    }
    impl ModelBackend for Capture {
        fn identity(&self) -> ModelIdentity {
            self.inner.identity()
        }

        fn complete(
            &self,
            req: &ModelRequest,
            deadline: Instant,
        ) -> Result<Completion, ModelError> {
            self.seen.borrow_mut().push(format!("{:?}", req.messages));
            self.inner.complete(req, deadline)
        }
    }

    let fx = fx("notice");
    fx.write("a.txt", "one\n").unwrap();
    let profile = Profile::conservative_default("m");
    let backend = Capture {
        inner: ScriptedBackend::new(
            profile.clone(),
            vec![
                read("a.txt"),
                write("a.txt", "two\n"),
                Ok(say("done")),
                Ok(say("noted")),
            ],
        ),
        seen: RefCell::new(Vec::new()),
    };
    let input = ScriptedInput::new(vec![
        ScriptedInput::message("change a.txt"),
        ScriptedInput::undo(),
        ScriptedInput::message("go on"),
    ]);
    let policy = allow_edits();
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
        instructions: None,
        sink: None,
    })
    .unwrap();
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(count(&r, EventKind::Restored), 1);
    assert!(
        backend
            .seen
            .borrow()
            .iter()
            .any(|req| req.contains("restored to its state as of step")),
        "the notice reached a request"
    );
}

// The undo of a delete: the file is recreated from its pre-image blob.
#[test]
fn undo_of_deleted_file_recreates_it() {
    let fx = fx("undo-delete");
    fx.write("a.txt", "one\n").unwrap();
    let r = run(
        &fx,
        vec![read("a.txt"), delete("a.txt"), Ok(say("done"))],
        &ScriptedInput::new(vec![
            ScriptedInput::message("drop a.txt"),
            ScriptedInput::undo(),
        ]),
        Some(&Yes),
    );
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(count(&r, EventKind::Restored), 1);
    assert_eq!(
        fs::read_to_string(fx.workspace().join("a.txt")).unwrap(),
        "one\n"
    );
    assert_eq!(restored(&r)[0].2, vec!["a.txt".to_owned()]);
}

// Nothing to undo (no edit yet): the command says so and journals
// nothing.
#[test]
fn undo_nothing_to_undo_message() {
    let fx = fx("nothing");
    let r = run(
        &fx,
        vec![],
        &ScriptedInput::new(vec![ScriptedInput::undo()]),
        None,
    );
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(count(&r, EventKind::Restored), 0);
    assert_eq!(count(&r, EventKind::EditApplied), 0);
}
