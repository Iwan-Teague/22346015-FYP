//! INV-33 through the real seam: policy authorises, the journal makes the
//! intent durable, and only then can a provider be invoked. Fault injection
//! uses the journal's test-only `FaultFile` (feature `fault-injection`,
//! enabled only as a dev-dependency; the `JournalFile` seam is sealed) that
//! fails the Nth write or fsync (design §7.1 "Testing"); a spy provider
//! counts invocations.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::Cell;
use std::rc::Rc;
use std::time::Instant;

use gate_outcome::{
    run_checked, Check, Coverage, Examination, GateId, GateOutcome, IndeterminateKind, Scope,
};
use harness_core::{sha256, Source, StopCause, Untrusted};
use harness_journal::testing::{FaultFile, FaultPlan, MemBlobs};
use harness_journal::{
    Clock, Event, EventKind, Header, Ident, JournalError, JournalWriter, Journaled, Trusted,
};
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, ProviderName, SemVer, ValidationContext};
use harness_policy::{Authorized, Call, Session, SessionSpec, UserPolicy, WorkspaceDecl};
use harness_tools::{InvokeCtx, ToolError, ToolProvider, ToolResult, ToolStatus};
use serde_json::json;

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

struct Spy {
    ns: ProviderName,
    invoked: Rc<Cell<u32>>,
}

impl ToolProvider for Spy {
    fn namespace(&self) -> &ProviderName {
        &self.ns
    }
    fn invoke(
        &mut self,
        call: Journaled<Authorized<Call>>,
        _ctx: &InvokeCtx,
    ) -> Result<ToolResult, ToolError> {
        self.invoked.set(self.invoked.get() + 1);
        assert!(call.intent_seq() > 0, "the header is seq 0");
        Ok(ToolResult {
            status: ToolStatus::Ok,
            output: Untrusted::new(
                b"file text".to_vec(),
                Source::Tool("harness.fs.read".into()),
            ),
            truncated: false,
            digest: sha256(b"file text"),
            read: None,
        })
    }
}

type W = JournalWriter<FaultFile, MemBlobs, Tick>;

fn session() -> Session {
    let ctx = ValidationContext::new(
        SemVer {
            major: 0,
            minor: 0,
            patch: 1,
        },
        &[],
    )
    .unwrap();
    let reg = Registry::admit(vec![(builtin::manifest(&ctx).unwrap(), Tier::Builtin)]).unwrap();
    Session::plan(
        &SessionSpec {
            grants: vec!["harness.fs.read".into()],
            workspace: Some(WorkspaceDecl::default()),
            approver_present: false,
            personal_data_granted: false,
        },
        &reg,
        &UserPolicy::default(),
    )
    .unwrap()
}

fn writer(
    fail_write: Option<usize>,
    fail_sync: Option<usize>,
) -> Result<W, harness_journal::StartError> {
    JournalWriter::start(
        FaultFile::new(FaultPlan {
            fail_write,
            short_write: false,
            fail_sync,
        }),
        MemBlobs::default(),
        Tick(Cell::new(0)),
        harness_core::RunId::new(33, [0; 10]),
        1,
        Header::new(Ident::of("0.0.1").unwrap()),
    )
}

/// One loop step, §2.2 steps 6-9: decide → journal intent → execute →
/// journal result. Returns the journal error that stopped it, if any.
fn step(w: &mut W, s: &Session, p: &mut Spy, n: u64) -> Result<(), JournalError> {
    let call = Call {
        capability: "harness.fs.read".into(),
        args: json!({"path": "src/lib.rs"}),
    };
    let authorized = s.authorize(call).expect("policy allows a workspace read");
    let intent = Event::new(EventKind::ToolStarted).field(
        "capability",
        Trusted::Id(Ident::of("harness.fs.read").unwrap()),
    );
    let journaled = w.append_intent(n, intent, authorized)?;
    let ctx = InvokeCtx {
        step: n,
        deadline: Instant::now(),
    };
    let result = p.invoke(journaled, &ctx).expect("spy never fails");
    let out = w.untrusted(&result.output)?;
    w.append(
        n,
        Event::new(EventKind::ToolFinished).field("output", Trusted::Untrusted(out)),
    )?;
    Ok(())
}

fn passed() -> GateOutcome {
    struct One;
    impl Check for One {
        type Input = ();
        fn gate(&self) -> GateId {
            GateId::new("check-1").unwrap()
        }
        fn examine(&self, _: &()) -> Examination {
            Examination {
                items: vec![sha256(b"i")],
                set_digest: sha256(b"s"),
                findings: Vec::new(),
                coverage: Coverage::Full,
                scope: Scope::empty(),
            }
        }
    }
    run_checked(&One, &()).outcome().clone()
}

const UNREADABLE: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::UnreadableEvidence,
};

/// Run up to 5 steps, then commit a `Passed` outcome (every check passed).
/// Returns (invocations, invocations after the first journal failure,
/// released outcome).
fn run(fail_write: Option<usize>, fail_sync: Option<usize>) -> (u32, u32, GateOutcome) {
    let s = session();
    let invoked = Rc::new(Cell::new(0));
    let mut p = Spy {
        ns: ProviderName::new("harness").unwrap(),
        invoked: invoked.clone(),
    };
    let mut w = writer(fail_write, fail_sync).unwrap();
    let mut after_failure = None;
    for n in 1..=5 {
        if step(&mut w, &s, &mut p, n).is_err() && after_failure.is_none() {
            after_failure = Some(invoked.get());
        }
    }
    let at_failure = after_failure.unwrap_or(invoked.get());
    let rel = w.commit(6, &StopCause::Submitted, passed(), None);
    (invoked.get(), invoked.get() - at_failure, rel.outcome)
}

#[test]
fn inv_33_control_no_fault_passes_after_five_invocations() {
    let (total, after, outcome) = run(None, None);
    assert_eq!((total, after), (5, 0));
    assert!(matches!(outcome, GateOutcome::Passed(_)));
}

#[test]
fn inv_33_intent_write_failure() {
    // writes: 1 header; then per step 2 (intent, result). #4 = step 2's intent.
    let (total, after, outcome) = run(Some(4), None);
    assert_eq!(total, 1, "only the step before the failure ran");
    assert_eq!(after, 0, "zero invocations after the failure");
    assert_eq!(outcome, UNREADABLE);
}

#[test]
fn inv_33_intent_fsync_failure() {
    // syncs: 1 header; then per step 2 (intent, result). #4 = step 2's intent.
    let (total, after, outcome) = run(None, Some(4));
    assert_eq!((total, after), (1, 0));
    assert_eq!(outcome, UNREADABLE);
}

#[test]
fn inv_33_result_write_failure() {
    // #5 = step 2's result: step 2's tool already ran; nothing after.
    let (total, after, outcome) = run(Some(5), None);
    assert_eq!((total, after), (2, 0));
    assert_eq!(outcome, UNREADABLE);
}

#[test]
fn inv_33_run_stopped_write_failure_after_every_check_passed() {
    // 1 header + 5 steps × 2 = 11 writes; #12 = RunStopped.
    let (total, after, outcome) = run(Some(12), None);
    assert_eq!((total, after), (5, 0));
    assert_eq!(
        outcome, UNREADABLE,
        "Passed released without a durable RunStopped"
    );
    // And its fsync.
    let (_, _, outcome) = run(None, Some(12));
    assert_eq!(outcome, UNREADABLE);
}

#[test]
fn inv_33_header_failure_refuses_to_start() {
    for (fw, fs) in [(Some(1), None), (None, Some(1))] {
        let err = writer(fw, fs).unwrap_err();
        assert_eq!(
            err.outcome(),
            GateOutcome::Indeterminate {
                why: IndeterminateKind::CouldNotRun
            }
        );
    }
}
