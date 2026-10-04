//! Whole sessions through the public `run_session` (P-13): a real state
//! root and workspace on disk (a `harness-testkit` fixture), the real
//! journal, the real tools, a scripted model and a scripted
//! [`UserInput`]. The batch suite (`tests/run.rs`) stays the record of
//! batch behaviour; everything here is the session's.

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
use harness_core::{BudgetDim, StopCause};
use harness_journal::layout;
use harness_journal::{EventKind, JournalReader};
use harness_model::profile::Profile;
use harness_model::scripted::ScriptedBackend;
use harness_model::{Completion, ModelError, TaskText};
use harness_policy::UserPolicy;
use harness_run::{
    audit, run_session, ApprovalAnswer, Approver, ApproverKind, Audit, EventSink, InputEnd,
    RunRefused, SessionConfig, SessionReport, SessionRun, TaskSpec, TurnLimits, UiEvent, UserInput,
    UserInputEvent, UserMessage,
};
use harness_testkit::{act, registry, run_scripted, say, submit, Fixture, Local};

/// A fixed environment sample (the real probe is harness-sandbox's; these
/// tests only need the header and records to carry one).
const FIXED_ENV: EnvSample = EnvSample::unmeasured(Unmeasured::NoSafeApi);

/// The token budget every scripted session is given.
const TOKENS: u64 = 1_000_000;

const NOTHING_CHECKED: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::NothingChecked,
};

const UNREADABLE: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::UnreadableEvidence,
};

// ---------------------------------------------------------------------------
// Scripted inputs, approver and sink.
// ---------------------------------------------------------------------------

/// A scripted [`UserInput`]: each step is a closure producing the next
/// event, so a test can compute a message from what the run did so far
/// (read the journal between turns).
struct ScriptedInput {
    steps: RefCell<VecDeque<Box<dyn Fn() -> UserInputEvent>>>,
}

impl ScriptedInput {
    fn message(text: &str) -> Box<dyn Fn() -> UserInputEvent> {
        let text = text.to_owned();
        Box::new(move || UserInputEvent::Message(UserMessage::new(text.clone()).expect("message")))
    }

    /// Messages in order; the input ends with `eof` after the last.
    fn of(msgs: &[&str]) -> Self {
        Self {
            steps: RefCell::new(msgs.iter().map(|m| Self::message(m)).collect()),
        }
    }

    /// A message computed when the input is polled (after the previous
    /// turn ended).
    fn then(computed: Box<dyn Fn() -> UserInputEvent>) -> Self {
        Self {
            steps: RefCell::new(VecDeque::from([computed])),
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

/// An approver that grants every ask.
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

/// What the sink saw, in emit order.
#[derive(Default)]
struct Seen {
    events: RefCell<Vec<(u64, u64, EventKind)>>,
    blobs_dir: RefCell<Option<bool>>,
}

impl EventSink for Seen {
    fn emit(&self, ev: &UiEvent<'_>) {
        self.events.borrow_mut().push((ev.seq, ev.step, ev.kind));
        let mut dir = self.blobs_dir.borrow_mut();
        let ok = dir.unwrap_or(true) && ev.blobs.is_dir();
        *dir = Some(ok);
    }
}

// ---------------------------------------------------------------------------
// Drivers.
// ---------------------------------------------------------------------------

/// Run a session with explicit everything.
#[allow(clippy::too_many_arguments)]
fn drive(
    fx: &Fixture,
    replies: Vec<Result<Completion, ModelError>>,
    input: &dyn UserInput,
    config: &SessionConfig,
    approver: Option<&dyn Approver>,
    sink: Option<&dyn EventSink>,
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
        instructions: None,
        sink,
    })
}

/// Run a session with the defaults: ok replies, messages, no approver, no
/// sink.
fn go(fx: &Fixture, replies: Vec<Completion>, msgs: &[&str]) -> SessionReport {
    drive(
        fx,
        replies.into_iter().map(Ok).collect(),
        &ScriptedInput::of(msgs),
        &SessionConfig::defaults(TOKENS),
        None,
        None,
    )
    .unwrap()
}

fn records(r: &SessionReport) -> Vec<harness_journal::Record> {
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

fn bodies(
    recs: &[harness_journal::Record],
    k: EventKind,
) -> Vec<&serde_json::Map<String, serde_json::Value>> {
    recs.iter()
        .filter(|r| r.kind == k)
        .map(|r| &r.body)
        .collect()
}

/// A read-only task spec with the given grants.
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

// ---------------------------------------------------------------------------
// The slice-card tests.
// ---------------------------------------------------------------------------

#[test]
fn session_two_turns_one_journal() {
    let fx = Fixture::new("session-two-turns").unwrap();
    fx.write("a.txt", "hello from the workspace\n").unwrap();
    let r = go(
        &fx,
        vec![say("first answer"), say("second answer")],
        &["one", "two"],
    );
    // The session ran two turns to their answers, then the input ended.
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(r.run.outcome, NOTHING_CHECKED);
    assert_eq!(r.turns, 2);
    assert_eq!(r.run.steps, 2);
    assert!(r.run.chain_head.is_some());
    // Exactly one journal, one attempt, and it verifies.
    assert!(JournalReader::open(&layout::attempt_dir(&r.run.run_dir, r.run.attempt)).is_ok());
    assert!(!layout::attempt_dir(&r.run.run_dir, 2)
        .join("journal.jsonl")
        .exists());
    let recs = records(&r);
    assert_eq!(count(&r, EventKind::UserTurn), 2);
    assert_eq!(count(&r, EventKind::TurnEnded), 2);
    assert_eq!(count(&r, EventKind::InputEnded), 1);
    assert_eq!(recs.last().unwrap().kind, EventKind::RunStopped);
}

#[test]
fn user_turn_recorded_and_in_context_order() {
    let fx = Fixture::new("session-turn-order").unwrap();
    fx.write("a.txt", "hello\n").unwrap();
    let r = go(&fx, vec![say("one"), say("two")], &["first", "second"]);
    let recs = records(&r);
    let names: Vec<EventKind> = recs.iter().map(|x| x.kind).collect();
    // The exact order: each turn's UserTurn before its first build, its
    // TurnEnded after the step's records; InputEnded then RunStopped last.
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
    assert_eq!(turns[0].get("turn").unwrap(), 1);
    assert_eq!(turns[1].get("turn").unwrap(), 2);
    for t in &turns {
        assert_eq!(t.get("shown").unwrap(), "yes");
        assert_eq!(t.get("external_change").unwrap(), false);
        assert_eq!(t.get("turn_steps").unwrap(), 50);
        assert!(t.get("text").is_some());
        assert!(t.get("workspace_tree").is_some());
        assert!(t.get("wall_used_ms").is_some());
    }
    let ends = bodies(&recs, EventKind::TurnEnded);
    assert_eq!(ends[0].get("reason").unwrap(), "answered");
    assert_eq!(ends[0].get("steps").unwrap(), 1);
    assert_eq!(ends[1].get("turn").unwrap(), 2);
    let input = bodies(&recs, EventKind::InputEnded);
    assert_eq!(input[0].get("reason").unwrap(), "eof");
    assert_eq!(input[0].get("turn").unwrap(), 2);
    let stop = recs.last().unwrap();
    assert_eq!(stop.body.get("cause").unwrap(), "session_ended");
}

#[test]
fn plain_answer_ends_turn_in_session_not_in_batch() {
    // Session: the plain text IS the turn's answer.
    let fx = Fixture::new("session-plain-answer").unwrap();
    let r = go(&fx, vec![say("The answer is 42.")], &["what is 6*7?"]);
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(r.run.steps, 1);
    let recs = records(&r);
    let ends = bodies(&recs, EventKind::TurnEnded);
    assert_eq!(ends[0].get("reason").unwrap(), "answered");
    // No FormatError was recorded for it, and the format streak is clean.
    assert_eq!(count(&r, EventKind::FormatError), 0);
    // Batch: the same reply is a format error three times over, and stops.
    let fx2 = Fixture::new("session-plain-answer-batch").unwrap();
    let b = run_scripted(&fx2, vec![say("The answer is 42.")]).unwrap();
    assert_eq!(b.cause, StopCause::FormatErrors);
    assert_eq!(b.steps, 3);
}

#[test]
fn turn_budget_ends_turn_not_session() {
    let fx = Fixture::new("session-turn-budget").unwrap();
    fx.write("a.txt", "hello\n").unwrap();
    let mut cfg = SessionConfig::defaults(TOKENS);
    cfg.turn = TurnLimits {
        steps: 1,
        format_errors: 3,
    };
    let r = drive(
        &fx,
        vec![
            Ok(act("harness.fs.read", "{\"path\":\"a.txt\"}")),
            Ok(say("done reading")),
        ],
        &ScriptedInput::of(&["go", "go on"]),
        &cfg,
        None,
        None,
    )
    .unwrap();
    // The first turn ended on its allowance; the session went on.
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(r.turns, 2);
    assert_eq!(r.run.steps, 2);
    let ends = rec_bodies(&r, EventKind::TurnEnded);
    assert_eq!(ends[0].get("reason").unwrap(), "turn_steps");
    assert_eq!(ends[0].get("steps").unwrap(), 1);
    assert_eq!(ends[1].get("reason").unwrap(), "answered");
}

#[test]
fn session_wall_budget_stops() {
    let fx = Fixture::new("session-wall-stop").unwrap();
    let mut cfg = SessionConfig::defaults(TOKENS);
    cfg.run.limits.wall = Duration::ZERO;
    let r = drive(
        &fx,
        vec![Ok(say("never reached"))],
        &ScriptedInput::of(&["hi"]),
        &cfg,
        None,
        None,
    )
    .unwrap();
    // The wall is working time; it latched before any input was asked.
    assert_eq!(r.run.cause, StopCause::Budget(BudgetDim::Wall));
    assert_eq!(r.run.outcome, NOTHING_CHECKED);
    assert_eq!(r.turns, 0);
    assert_eq!(r.run.steps, 0);
    assert_eq!(
        kinds(&r),
        vec![EventKind::RunStarted, EventKind::RunStopped]
    );
}

#[test]
fn external_edit_between_turns_detected_and_stale_read_forces_reread() {
    let fx = Fixture::new("session-external-edit").unwrap();
    fx.write("a.txt", "version one\n").unwrap();
    // The second message is computed when polled; before it, the workspace
    // file changes OUTSIDE the harness (INV-39: the change is measured and
    // journaled with the turn that first sees it).
    let ws = fx.workspace().to_path_buf();
    let before_second: Box<dyn Fn() -> UserInputEvent> = Box::new(move || {
        fs::write(ws.join("a.txt"), "changed behind the harness\n").unwrap();
        UserInputEvent::Message(UserMessage::new("read it again".into()).unwrap())
    });
    let r = drive(
        &fx,
        vec![
            Ok(act("harness.fs.read", "{\"path\":\"a.txt\"}")),
            Ok(act("harness.fs.read", "{\"path\":\"a.txt\"}")),
            Ok(say("I see the change.")),
        ],
        &ScriptedInput {
            steps: RefCell::new(
                vec![
                    ScriptedInput::message("what does a.txt say?"),
                    before_second,
                ]
                .into_iter()
                .collect(),
            ),
        },
        &SessionConfig::defaults(TOKENS),
        None,
        None,
    )
    .unwrap();
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    let recs = records(&r);
    let turns = bodies(&recs, EventKind::UserTurn);
    assert_eq!(turns[0].get("external_change").unwrap(), false);
    assert_eq!(turns[1].get("external_change").unwrap(), true);
    // The tree digest the second turn started from is the changed one, and
    // the turn carries the old→new pair for its context notice.
    assert_ne!(
        turns[0].get("workspace_tree").unwrap(),
        turns[1].get("workspace_tree").unwrap()
    );
    // The re-read of the changed file succeeded: the read log did not
    // refuse a read (only a stale EDIT is refused), so the model sees the
    // new content without clearing anything.
    assert_eq!(count(&r, EventKind::ToolFinished), 2);
}

#[test]
fn approval_in_turn_two_works() {
    let fx = Fixture::with_spec(
        "session-approval",
        spec(
            "read a.txt then edit it",
            &["harness.fs.read", "harness.edit.write"],
        ),
    )
    .unwrap();
    fx.write("a.txt", "version one\n").unwrap();
    let r = drive(
        &fx,
        vec![
            Ok(act("harness.fs.read", "{\"path\":\"a.txt\"}")),
            Ok(act(
                "harness.edit.write",
                "{\"path\":\"a.txt\",\"content\":\"version two\\n\"}",
            )),
            Ok(say("I updated the file.")),
        ],
        &ScriptedInput::of(&["read it", "now edit it"]),
        &SessionConfig::defaults(TOKENS),
        Some(&Yes),
        None,
    )
    .unwrap();
    // The ask came, was granted, and the edit applied — in turn two — and
    // the session went on to its answer.
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(r.turns, 2);
    assert_eq!(count(&r, EventKind::ApprovalRequested), 1);
    assert_eq!(count(&r, EventKind::ApprovalGranted), 1);
    assert_eq!(count(&r, EventKind::EditApplied), 1);
    assert_eq!(count(&r, EventKind::ToolFinished), 2);
    assert_eq!(
        fs::read_to_string(fx.workspace().join("a.txt")).unwrap(),
        "version two\n"
    );
}

#[test]
fn event_sink_sees_only_journaled_records() {
    let fx = Fixture::new("session-sink").unwrap();
    fx.write("a.txt", "hello\n").unwrap();
    let seen = Seen::default();
    let r = drive(
        &fx,
        vec![
            Ok(act("harness.fs.read", "{\"path\":\"a.txt\"}")),
            Ok(say("done")),
        ],
        &ScriptedInput::of(&["go"]),
        &SessionConfig::defaults(TOKENS),
        None,
        Some(&seen),
    )
    .unwrap();
    let seen_events = seen.events.borrow().clone();
    assert!(!seen_events.is_empty());
    // In seq order, strictly increasing.
    for (a, b) in seen_events.iter().zip(seen_events.iter().skip(1)) {
        assert!(b.0 > a.0);
    }
    // Every event is the journal's own record at that seq. RunStopped is
    // never drained; RunStarted is written before the session can turn the
    // tap on (the writer exists only after the header), so it is not seen
    // either — the sink's first record is the journal's second.
    let recs = records(&r);
    assert_eq!(seen_events.len(), recs.len() - 2);
    assert_ne!(seen_events[0].2, EventKind::RunStarted);
    for (seq, _step, kind) in &seen_events {
        let rec = recs.iter().find(|x| x.seq == *seq).unwrap();
        assert_eq!(*kind, rec.kind);
        assert_ne!(*kind, EventKind::RunStopped);
    }
    // The blobs path named by the events is the attempt's blobs directory.
    assert_eq!(*seen.blobs_dir.borrow(), Some(true));
}

#[test]
fn no_input_means_session_ends_indeterminate_nothing_checked() {
    let fx = Fixture::new("session-no-input").unwrap();
    let r = drive(
        &fx,
        vec![],
        &ScriptedInput::of(&[]),
        &SessionConfig::defaults(TOKENS),
        None,
        None,
    )
    .unwrap();
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(r.run.outcome, NOTHING_CHECKED);
    assert_eq!(r.turns, 0);
    assert_eq!(r.run.steps, 0);
    let recs = records(&r);
    assert_eq!(
        recs.iter().map(|x| x.kind).collect::<Vec<_>>(),
        vec![
            EventKind::RunStarted,
            EventKind::InputEnded,
            EventKind::RunStopped
        ]
    );
    let input = bodies(&recs, EventKind::InputEnded);
    assert_eq!(input[0].get("turn").unwrap(), 0);
    assert_eq!(input[0].get("reason").unwrap(), "eof");
}

#[test]
fn batch_run_behaviour_unchanged() {
    // The batch path still runs, journals and audits exactly as before:
    // no `mode` or `turn_limits` in its header, context format /5, and the
    // audit replay recomputes it.
    let fx = Fixture::new("session-batch-unchanged").unwrap();
    fx.write("a.txt", "hello from the workspace\n").unwrap();
    let r = run_scripted(
        &fx,
        vec![act("harness.fs.read", "{\"path\":\"a.txt\"}"), submit()],
    )
    .unwrap();
    assert_eq!(r.cause, StopCause::Submitted);
    assert_eq!(r.outcome, NOTHING_CHECKED);
    let recs = JournalReader::open(&layout::attempt_dir(&r.run_dir, r.attempt))
        .unwrap()
        .records;
    let head = &recs[0].body;
    assert!(head.get("mode").is_none());
    assert!(head.get("turn_limits").is_none());
    assert_eq!(head.get("context_format").unwrap(), "rh-context/5");
    assert_eq!(head.get("limits").unwrap().get("format_errors").unwrap(), 3);
    harness_testkit::assert_audit_clean(&fx, &r).unwrap();
}

// ---------------------------------------------------------------------------
// Session-only behaviour beyond the card.
// ---------------------------------------------------------------------------

#[test]
fn session_header_has_mode_turn_limits_context_format7() {
    let fx = Fixture::new("session-header").unwrap();
    let r = go(&fx, vec![say("hi")], &["hello"]);
    let head = &records(&r)[0].body;
    assert_eq!(head.get("mode").unwrap(), "session");
    let tl = head.get("turn_limits").unwrap();
    assert_eq!(tl.get("steps").unwrap(), 50);
    assert_eq!(tl.get("format_errors").unwrap(), 3);
    // P-28 added the mode line (rh-context/7); P-30 added the project
    // notes block (rh-context/8).
    assert_eq!(head.get("context_format").unwrap(), "rh-context/8");
    // The meter never latches format errors in a session.
    assert_eq!(
        head.get("limits").unwrap().get("format_errors").unwrap(),
        4294967295u64
    );
}

#[test]
fn batch_audit_refuses_session_journal_by_mode() {
    let fx = Fixture::new("session-batch-audit").unwrap();
    let r = go(&fx, vec![say("hi")], &["hello"]);
    let reg = registry().unwrap();
    // The limits the session ran under (its header's limits object).
    let mut limits = SessionConfig::defaults(TOKENS).run.limits;
    limits.format_errors = u32::MAX;
    let a = audit(Audit {
        state_root: fx.state_root(),
        run: &r.run.run,
        attempt: None,
        anchor: r.run.chain_head,
        spec: &fx.spec,
        registry: &reg,
        policy: &UserPolicy::default(),
        profile: &Profile::conservative_default("m"),
        limits: &limits,
    })
    .unwrap();
    let d = a
        .divergence
        .expect("a batch audit must refuse a session journal");
    // The first refused key decides the wording: the header keys are
    // compared in their declared order, and `context_format` (a session
    // build's is /6) is checked before `mode`. Either refusal is the
    // fail-closed answer: this build must not replay another mode's
    // journal.
    assert!(
        d.why.contains("mode") || d.why.contains("context format"),
        "why: {}",
        d.why
    );
    assert_eq!(a.outcome, UNREADABLE);
}

#[test]
fn turn_limits_out_of_range_refused() {
    let fx = Fixture::new("session-turn-limits").unwrap();
    let refuses = |turn: TurnLimits, run_steps: u32| {
        let mut cfg = SessionConfig::defaults(TOKENS);
        cfg.turn = turn;
        cfg.run.limits.steps = run_steps;
        let err = drive(&fx, vec![], &ScriptedInput::of(&[]), &cfg, None, None).unwrap_err();
        assert!(matches!(err, RunRefused::TurnLimits(_)), "got: {err:?}");
    };
    refuses(
        TurnLimits {
            steps: 0,
            format_errors: 3,
        },
        500,
    );
    refuses(
        TurnLimits {
            steps: 501,
            format_errors: 3,
        },
        5000,
    );
    refuses(
        TurnLimits {
            steps: 200,
            format_errors: 3,
        },
        50,
    );
    refuses(
        TurnLimits {
            steps: 50,
            format_errors: 0,
        },
        500,
    );
    refuses(
        TurnLimits {
            steps: 50,
            format_errors: 11,
        },
        500,
    );
    refuses(
        TurnLimits {
            steps: 50,
            format_errors: 3,
        },
        0,
    );
    // Nothing was written: no run directory at all.
    assert!(!fx.state_root().join("runs").exists());
}

#[test]
fn input_timeout_ends_session() {
    let fx = Fixture::new("session-input-timeout").unwrap();
    let r = drive(
        &fx,
        vec![],
        &ScriptedInput::ends(InputEnd::Timeout),
        &SessionConfig::defaults(TOKENS),
        None,
        None,
    )
    .unwrap();
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    let input = rec_bodies(&r, EventKind::InputEnded);
    assert_eq!(input[0].get("reason").unwrap(), "timeout");
}

#[test]
fn submit_ends_turn_not_session() {
    let fx = Fixture::new("session-submit-turn").unwrap();
    let r = go(
        &fx,
        vec![submit(), say("anything else?")],
        &["do the task", "and now"],
    );
    // The submit ended only its turn; the session took another one.
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(r.turns, 2);
    assert_eq!(count(&r, EventKind::SubmitRequested), 1);
    let ends = rec_bodies(&r, EventKind::TurnEnded);
    assert_eq!(ends[0].get("reason").unwrap(), "submitted");
    assert_eq!(ends[1].get("reason").unwrap(), "answered");
    // The accepted note is the session's deliverable on the final stop.
    let recs = records(&r);
    let stop = recs.last().unwrap();
    assert!(stop.body.get("deliverable").is_some());
}

#[test]
fn model_unavailable_ends_turn() {
    let fx = Fixture::new("session-model-down").unwrap();
    let r = drive(
        &fx,
        vec![
            Ok(say("one")),
            Err(ModelError::Unavailable(
                harness_model::Unavailable::Connect("down".into()),
            )),
            Ok(say("three")),
        ],
        &ScriptedInput::of(&["one", "two", "three"]),
        &SessionConfig::defaults(TOKENS),
        None,
        None,
    )
    .unwrap();
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(r.turns, 3);
    assert_eq!(r.run.steps, 3);
    let ends = rec_bodies(&r, EventKind::TurnEnded);
    assert_eq!(ends[1].get("reason").unwrap(), "model_unavailable");
}

#[test]
fn session_empty_reply_is_not_an_answer() {
    let fx = Fixture::new("session-empty-reply").unwrap();
    let mut cfg = SessionConfig::defaults(TOKENS);
    cfg.turn.format_errors = 1;
    let r = drive(
        &fx,
        vec![Ok(say("   "))],
        &ScriptedInput::of(&["go"]),
        &cfg,
        None,
        None,
    )
    .unwrap();
    // Whitespace alone is still a format error, and one is this turn's
    // whole budget: the turn ends, the session goes on (the input ends).
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(count(&r, EventKind::FormatError), 1);
    let ends = rec_bodies(&r, EventKind::TurnEnded);
    assert_eq!(ends[0].get("reason").unwrap(), "format_errors");
}

#[test]
fn user_turn_with_drawn_nonce_refused_not_shown() {
    let fx = Fixture::new("session-nonce-echo").unwrap();
    fx.write("a.txt", "hello\n").unwrap();
    // The second message is built when polled: it reads the nonce the
    // first turn drew from the journal and tries to hand it to the model.
    let state = fx.state_root().to_path_buf();
    let echo: Box<dyn Fn() -> UserInputEvent> = Box::new(move || {
        let runs = state.join("runs");
        let mut run_dir = None;
        for e in fs::read_dir(&runs).unwrap() {
            run_dir = Some(e.unwrap().path());
        }
        let dir = layout::attempt_dir(&run_dir.unwrap(), 1);
        let v = JournalReader::open(&dir).unwrap();
        let mut nonce = String::new();
        for rec in &v.records {
            if rec.kind == EventKind::ModelRequested {
                if let Some(n) = rec.body.get("nonce") {
                    nonce = n.as_str().unwrap().into();
                }
            }
        }
        assert!(!nonce.is_empty());
        let text = format!("here is your marker: {nonce}");
        UserInputEvent::Message(UserMessage::new(text).unwrap())
    });
    let input = ScriptedInput {
        steps: RefCell::new(
            vec![ScriptedInput::message("go"), echo]
                .into_iter()
                .collect(),
        ),
    };
    let r = drive(
        &fx,
        vec![
            Ok(act("harness.fs.read", "{\"path\":\"a.txt\"}")),
            Ok(say("I read it.")),
        ],
        &input,
        &SessionConfig::defaults(TOKENS),
        None,
        None,
    )
    .unwrap();
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    // Turn 1 made two calls (the read, then the reply); the refused turn
    // made none.
    assert_eq!(
        count(&r, EventKind::ModelRequested),
        2,
        "a refused input makes no model call"
    );
    let recs = records(&r);
    let turns = bodies(&recs, EventKind::UserTurn);
    assert_eq!(turns[1].get("shown").unwrap(), "withheld");
    let ends = bodies(&recs, EventKind::TurnEnded);
    assert_eq!(ends[1].get("reason").unwrap(), "input_refused");
    assert_eq!(ends[1].get("steps").unwrap(), 0);
}

#[test]
fn user_turn_over_share_refused() {
    let fx = Fixture::new("session-over-share").unwrap();
    let big = "x".repeat(60_000);
    let input = ScriptedInput::then(Box::new(move || {
        UserInputEvent::Message(UserMessage::new(big.clone()).unwrap())
    }));
    let r = drive(
        &fx,
        vec![],
        &input,
        &SessionConfig::defaults(TOKENS),
        None,
        None,
    )
    .unwrap();
    assert_eq!(r.run.cause, StopCause::SessionEnded);
    assert_eq!(r.run.steps, 0, "a refused input makes no model call");
    let turns = rec_bodies(&r, EventKind::UserTurn);
    assert_eq!(turns[0].get("shown").unwrap(), "over_share");
    let ends = rec_bodies(&r, EventKind::TurnEnded);
    assert_eq!(ends[0].get("reason").unwrap(), "input_refused");
}

/// P-38: a session header keeps its `mode: session` and gains neither of
/// the child keys, so session headers (and their audits) are unchanged.
#[test]
fn session_header_unchanged_without_delegate() {
    let fx = Fixture::new("session-header-childless").unwrap();
    let r = go(&fx, vec![say("hi")], &["hello"]);
    let head = &records(&r)[0].body;
    assert_eq!(head.get("mode").unwrap(), "session");
    assert!(!head.contains_key("parent"), "{head:?}");
    assert!(!head.contains_key("child"), "{head:?}");
}
