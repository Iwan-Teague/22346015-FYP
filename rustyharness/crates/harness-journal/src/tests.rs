//! Journal tests. Invariant tests are named `inv_<n>_…`.
//!
//! Fault injection: [`FaultFile`] is a test-only [`JournalFile`] that keeps
//! the bytes in memory and fails the Nth `write_all` (optionally after a
//! short write that leaves half a line) or the Nth `sync_data`, exactly the
//! seam design §7.1 "Testing" describes. [`MemBlobs`] is a blob store that
//! can be told to fail.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use gate_outcome::{
    run_checked, Check, Coverage, Examination, GateId, GateOutcome, IndeterminateKind, Scope,
};
use harness_core::{sha256, sha256_parts, BudgetDim, Digest, Source, StopCause, Untrusted};
use serde_json::Value;

use crate::*;

// ---- seams ----------------------------------------------------------------

use crate::testing::{FaultFile, FaultPlan, MemBlobs};

#[derive(Default)]
struct TestClock(Cell<u64>);

impl Clock for TestClock {
    fn mono_ms(&self) -> u64 {
        let t = self.0.get() + 5;
        self.0.set(t);
        t
    }
    fn unix_ms(&self) -> u64 {
        1_790_000_000_000 + self.0.get()
    }
}

struct Rig {
    buf: Rc<RefCell<Vec<u8>>>,
    writes: Rc<Cell<usize>>,
    syncs: Rc<Cell<usize>>,
    blobs: MemBlobs,
}

type W = JournalWriter<FaultFile, MemBlobs, TestClock>;

fn rig(plan: FaultPlan) -> (Rig, Result<W, StartError>) {
    let file = FaultFile::new(plan);
    let r = Rig {
        buf: file.buf.clone(),
        writes: file.writes.clone(),
        syncs: file.syncs.clone(),
        blobs: MemBlobs::default(),
    };
    let w = JournalWriter::start(
        file,
        r.blobs.clone(),
        TestClock::default(),
        rid(1),
        1,
        Header::new(id("0.0.1")).field("os", Trusted::Text("test")),
    );
    (r, w)
}

fn id(s: &str) -> Ident {
    Ident::new(s).unwrap()
}

fn bytes(r: &Rig) -> Vec<u8> {
    r.buf.borrow().clone()
}

/// A call whose digest is computed from itself (the journal asks it).
struct TestCall(&'static str);

impl harness_core::CallDigest for TestCall {
    fn call_digest(&self) -> Digest {
        sha256(self.0.as_bytes())
    }
}

fn rid(n: u64) -> harness_core::RunId {
    harness_core::RunId::new(n, [0; 10])
}

fn call_digest() -> Digest {
    sha256(b"call")
}

fn intent() -> Event {
    Event::new(EventKind::ToolStarted).field("capability", Trusted::Id(id("harness.fs.read")))
}

fn result_event() -> Event {
    Event::new(EventKind::ToolFinished).field("status", Trusted::Text("ok"))
}

/// A lawful `Passed`, minted the only way harness code can (INV-4).
fn passed() -> GateOutcome {
    struct One;
    impl Check for One {
        type Input = ();
        fn gate(&self) -> GateId {
            GateId::new("g").unwrap()
        }
        fn examine(&self, _: &()) -> Examination {
            Examination {
                items: vec![sha256(b"item")],
                set_digest: sha256(b"set"),
                findings: Vec::new(),
                coverage: Coverage::Full,
                scope: Scope::empty(),
            }
        }
    }
    let o = run_checked(&One, &()).outcome().clone();
    assert!(matches!(o, GateOutcome::Passed(_)));
    o
}

fn unreadable() -> GateOutcome {
    GateOutcome::Indeterminate {
        why: IndeterminateKind::UnreadableEvidence,
    }
}

/// The §2.2 step 7-8 shape: only a `Journaled` call reaches the provider.
fn step_once(w: &mut W, step: u64, invoked: &Cell<u32>) -> Result<(), JournalError> {
    let j = w.append_intent(step, intent(), TestCall("call"))?;
    invoked.set(invoked.get() + 1); // the provider runs only here
    let _ = j.call();
    w.append(step, result_event())?;
    Ok(())
}

fn lines(b: &[u8]) -> Vec<Vec<u8>> {
    b.split(|c| *c == b'\n')
        .filter(|l| !l.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

fn join(ls: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for l in ls {
        out.extend_from_slice(l);
        out.push(b'\n');
    }
    out
}

/// A full, committed journal of 6 records: header, intent, result,
/// ModelReplied with an inline and a blob payload, BudgetCharged, RunStopped.
fn good_journal() -> (Rig, Vec<u8>, Digest) {
    let (r, w) = rig(FaultPlan::default());
    let mut w = w.unwrap();
    let invoked = Cell::new(0);
    step_once(&mut w, 1, &invoked).unwrap();
    let small = w
        .untrusted(&Untrusted::new(
            "reply \u{1b}[2J\u{202E}".to_owned(),
            Source::Model,
        ))
        .unwrap();
    let big = w
        .untrusted(&Untrusted::new(
            vec![0xffu8; 10_000],
            Source::Tool("harness.fs.read".into()),
        ))
        .unwrap();
    w.append(
        2,
        Event::new(EventKind::ModelReplied)
            .field("content", Trusted::Untrusted(small))
            .field("raw", Trusted::Untrusted(big)),
    )
    .unwrap();
    w.append(
        2,
        Event::new(EventKind::BudgetCharged).field("steps", Trusted::U64(2)),
    )
    .unwrap();
    let rel = w.commit(2, &StopCause::Submitted, passed(), None);
    assert!(matches!(rel.outcome, GateOutcome::Passed(_)));
    let head = rel.chain_head.unwrap();
    let b = bytes(&r);
    (r, b, head)
}

// ---- round trip -----------------------------------------------------------------

#[test]
fn a_committed_journal_verifies_end_to_end() {
    let (r, b, head) = good_journal();
    let v = verify(&b, &r.blobs).unwrap();
    let kinds: Vec<EventKind> = v.records.iter().map(|r| r.kind).collect();
    assert_eq!(
        kinds,
        [
            EventKind::RunStarted,
            EventKind::ToolStarted,
            EventKind::ToolFinished,
            EventKind::ModelReplied,
            EventKind::BudgetCharged,
            EventKind::RunStopped
        ]
    );
    assert!(v.is_complete());
    assert_eq!(v.head, head);
    v.check_anchor(&head).unwrap();
    // The intent carries the call digest, set by the writer.
    assert_eq!(
        v.records[1].body.get("call"),
        Some(&Value::from(call_digest().to_string()))
    );
    assert_eq!(
        v.records[5].body.get("outcome"),
        Some(&Value::from("passed"))
    );
}

#[test]
fn untrusted_text_is_escaped_so_a_viewer_is_not_an_injection_sink() {
    let (_, b, _) = good_journal();
    let text = String::from_utf8(b).unwrap();
    assert!(!text.contains('\u{1b}'), "raw ESC in the journal");
    assert!(
        !text.contains('\u{202E}'),
        "raw bidi override in the journal"
    );
    assert!(text.contains("\"untrusted\":true"));
    // serde_json would write ESC as \u001b; the payload home escapes it
    // itself first, so the JSON holds the literal text `\u{1B}`.
    assert!(text.contains("\\\\u{1B}[2J"));
}

#[test]
fn untrusted_blob_debug_never_shows_the_payload() {
    let (_, w) = rig(FaultPlan::default());
    let mut w = w.unwrap();
    let blob = w
        .untrusted(&Untrusted::new("SECRET-PAYLOAD".to_owned(), Source::Model))
        .unwrap();
    let dbg = format!("{blob:?}");
    assert!(!dbg.contains("SECRET"), "{dbg}");
}

// ---- INV-33: no intent executes unless durable; a poisoned run never passes ----

#[test]
fn inv_33_intent_write_failure_mints_nothing_and_poisons() {
    // write #1 = header, #2 = the first intent.
    let (r, w) = rig(FaultPlan {
        fail_write: Some(2),
        ..Default::default()
    });
    let mut w = w.unwrap();
    let invoked = Cell::new(0);
    let err = step_once(&mut w, 1, &invoked).unwrap_err();
    assert!(matches!(
        err,
        JournalError::Unavailable { op: "append", .. }
    ));
    assert!(w.is_poisoned());
    let before = bytes(&r);
    // Every later step is refused without touching the file.
    for s in 2..5 {
        assert!(step_once(&mut w, s, &invoked).is_err());
    }
    assert_eq!(invoked.get(), 0, "the provider ran after a failed intent");
    assert_eq!(bytes(&r), before, "a poisoned writer touched the file");
    let rel = w.commit(9, &StopCause::Submitted, passed(), None);
    assert_eq!(rel.outcome, unreadable());
    assert!(rel.chain_head.is_none());
    assert!(matches!(
        rel.error.unwrap().stop_cause(),
        StopCause::JournalUnavailable { .. }
    ));
}

#[test]
fn inv_33_intent_fsync_failure_mints_nothing_and_is_never_retried() {
    // sync #1 = header, #2 = the first intent.
    let (r, w) = rig(FaultPlan {
        fail_sync: Some(2),
        ..Default::default()
    });
    let mut w = w.unwrap();
    let invoked = Cell::new(0);
    let err = step_once(&mut w, 1, &invoked).unwrap_err();
    assert!(matches!(err, JournalError::Unavailable { op: "fsync", .. }));
    assert_eq!(invoked.get(), 0);
    let syncs = r.syncs.get();
    let writes = r.writes.get();
    assert!(step_once(&mut w, 2, &invoked).is_err());
    assert!(w.append(2, Event::new(EventKind::ContextBuilt)).is_err());
    assert_eq!(r.syncs.get(), syncs, "fsync retried on a poisoned file");
    assert_eq!(r.writes.get(), writes, "a poisoned writer wrote");
    assert_eq!(invoked.get(), 0);
    assert_eq!(
        w.commit(3, &StopCause::Submitted, passed(), None).outcome,
        unreadable()
    );
}

#[test]
fn inv_33_result_write_failure_stops_every_later_invocation() {
    // writes: #1 header, #2 intent, #3 result (fails, short: half a line).
    let (r, w) = rig(FaultPlan {
        fail_write: Some(3),
        short_write: true,
        ..Default::default()
    });
    let mut w = w.unwrap();
    let invoked = Cell::new(0);
    assert!(step_once(&mut w, 1, &invoked).is_err());
    assert_eq!(invoked.get(), 1, "the first, durable intent did run");
    for s in 2..6 {
        assert!(step_once(&mut w, s, &invoked).is_err());
    }
    assert_eq!(invoked.get(), 1, "zero invocations after the failure");
    assert_eq!(
        w.commit(6, &StopCause::Submitted, passed(), None).outcome,
        unreadable()
    );
    // The torn result line is visible to the reader; the durable prefix
    // (header + intent) is what a resume starts from.
    let v = verify(&bytes(&r), &r.blobs).unwrap();
    assert!(v.torn_tail.is_some());
    assert_eq!(v.records.len(), 2);
    assert!(!v.is_complete());
}

#[test]
fn inv_33_run_stopped_failure_downgrades_a_pass() {
    // Everything succeeds, every check passed, then the RunStopped write fails.
    let (r, w) = rig(FaultPlan::default());
    let mut w = w.unwrap();
    let invoked = Cell::new(0);
    step_once(&mut w, 1, &invoked).unwrap();
    let writes_so_far = r.writes.get();
    drop(r);
    let (r2, w2) = rig(FaultPlan {
        fail_write: Some(writes_so_far + 1),
        ..Default::default()
    });
    let mut w2 = w2.unwrap();
    step_once(&mut w2, 1, &invoked).unwrap();
    let rel = w2.commit(2, &StopCause::Submitted, passed(), None);
    assert_eq!(
        rel.outcome,
        unreadable(),
        "a pass released without a durable RunStopped"
    );
    assert!(rel.chain_head.is_none());
    assert!(!verify(&bytes(&r2), &r2.blobs).unwrap().is_complete());
    drop(w);

    // Same with the RunStopped fsync failing (syncs: header, intent, result, RunStopped).
    let (_, w3) = rig(FaultPlan {
        fail_sync: Some(4),
        ..Default::default()
    });
    let mut w3 = w3.unwrap();
    step_once(&mut w3, 1, &invoked).unwrap();
    assert_eq!(
        w3.commit(2, &StopCause::Submitted, passed(), None).outcome,
        unreadable()
    );
}

#[test]
fn inv_33_header_failure_refuses_to_start() {
    for plan in [
        FaultPlan {
            fail_write: Some(1),
            ..Default::default()
        },
        FaultPlan {
            fail_sync: Some(1),
            ..Default::default()
        },
    ] {
        let (_, w) = rig(plan);
        let err = w.unwrap_err();
        assert_eq!(
            err.outcome(),
            GateOutcome::Indeterminate {
                why: IndeterminateKind::CouldNotRun
            }
        );
    }
}

#[test]
fn inv_33_blob_failure_poisons() {
    let (_, w) = rig(FaultPlan::default());
    let mut w = w.unwrap();
    // A second rig whose blob store fails.
    let (r, w2) = rig(FaultPlan::default());
    let mut w2 = w2.unwrap();
    r.blobs.fail.set(true);
    let big = Untrusted::new(vec![0u8; 5000], Source::Model);
    assert!(matches!(
        w2.untrusted(&big),
        Err(JournalError::Unavailable { op: "blob", .. })
    ));
    assert!(w2.is_poisoned());
    let invoked = Cell::new(0);
    assert!(step_once(&mut w2, 1, &invoked).is_err());
    assert_eq!(invoked.get(), 0);
    // The healthy writer is unaffected.
    assert!(step_once(&mut w, 1, &invoked).is_ok());
}

#[test]
fn refused_events_do_not_poison() {
    let (r, w) = rig(FaultPlan::default());
    let mut w = w.unwrap();
    let before = bytes(&r);
    for ev in [
        Event::new(EventKind::RunStarted),
        Event::new(EventKind::RunStopped),
        Event::new(EventKind::ToolStarted),
        Event::new(EventKind::ContextBuilt)
            .field("a", Trusted::U64(1))
            .field("a", Trusted::U64(2)),
        Event::new(EventKind::ContextBuilt).field("untrusted", Trusted::Bool(true)),
    ] {
        assert!(matches!(
            w.append(1, ev),
            Err(JournalError::InvalidEvent(_))
        ));
    }
    assert!(matches!(
        w.append_intent(1, result_event(), TestCall("x")),
        Err(JournalError::InvalidEvent(_))
    ));
    assert!(matches!(
        w.append_intent(
            1,
            intent().field("call", Trusted::Digest(sha256(b"forged"))),
            TestCall("x")
        ),
        Err(JournalError::InvalidEvent(_))
    ));
    assert_eq!(bytes(&r), before);
    assert!(!w.is_poisoned());
}

// ---- INV-11: the chain detects mutation --------------------------------------------

fn recompute_hash(line: &[u8], prev: &Digest) -> (Vec<u8>, Digest) {
    let mut v: serde_json::Map<String, Value> = serde_json::from_slice(line).unwrap();
    v.insert("prev".into(), Value::from(prev.to_string()));
    v.remove("hash");
    let canon = Value::Object(v.clone()).to_string();
    let h = sha256_parts(&[prev.as_bytes(), canon.as_bytes()]);
    v.insert("hash".into(), Value::from(h.to_string()));
    (Value::Object(v).to_string().into_bytes(), h)
}

fn edit_step(line: &[u8], new_step: u64) -> Vec<u8> {
    let mut v: serde_json::Map<String, Value> = serde_json::from_slice(line).unwrap();
    v.insert("step".into(), Value::from(new_step));
    Value::Object(v).to_string().into_bytes()
}

#[test]
fn inv_11_rewritten_deleted_and_swapped_lines_are_refused() {
    let (r, b, _) = good_journal();
    let ls = lines(&b);

    let mut edited = ls.clone();
    edited[2] = edit_step(&edited[2], 77);
    assert_eq!(
        verify(&join(&edited), &r.blobs).unwrap_err(),
        Broken {
            record: 2,
            why: BreakKind::BadHash
        }
    );

    let mut deleted = ls.clone();
    deleted.remove(2);
    assert_eq!(
        verify(&join(&deleted), &r.blobs).unwrap_err(),
        Broken {
            record: 2,
            why: BreakKind::BadSeq {
                expected: 2,
                found: 3
            }
        }
    );

    let mut swapped = ls.clone();
    swapped.swap(2, 3);
    assert_eq!(
        verify(&join(&swapped), &r.blobs).unwrap_err().record,
        2,
        "the first divergent record is named"
    );
}

#[test]
fn inv_11_an_edit_with_a_recomputed_hash_breaks_the_next_link() {
    let (r, b, head) = good_journal();
    let mut ls = lines(&b);
    let v = verify(&b, &r.blobs).unwrap();
    let (fixed, _) = recompute_hash(&edit_step(&ls[2], 77), &v.records[1].hash);
    ls[2] = fixed;
    assert_eq!(
        verify(&join(&ls), &r.blobs).unwrap_err(),
        Broken {
            record: 3,
            why: BreakKind::BadPrev
        }
    );
    // Rewriting the whole tail consistently verifies locally, but not
    // against the anchored head (§7.1 "Anchoring").
    let mut prev = v.records[1].hash;
    for l in ls.iter_mut().skip(2) {
        let (nl, h) = recompute_hash(l, &prev);
        *l = nl;
        prev = h;
    }
    let forged = verify(&join(&ls), &r.blobs).unwrap();
    assert_eq!(
        forged.check_anchor(&head).unwrap_err().why,
        BreakKind::AnchorMismatch
    );
}

#[test]
fn inv_11_truncation_is_detected() {
    let (r, b, head) = good_journal();
    // Mid-line (a crash): torn tail reported, verified prefix kept.
    let cut = &b[..b.len() - 10];
    let v = verify(cut, &r.blobs).unwrap();
    assert!(v.torn_tail.is_some());
    assert_eq!(v.records.len(), 5);
    assert!(!v.is_complete());
    // By whole lines: not complete, and the anchor does not match.
    let ls = lines(&b);
    let v = verify(&join(&ls[..4]), &r.blobs).unwrap();
    assert!(!v.is_complete());
    assert!(v.check_anchor(&head).is_err());
    // Nothing, or only a torn header.
    assert_eq!(verify(b"", &r.blobs).unwrap_err().why, BreakKind::Empty);
    assert_eq!(
        verify(&ls[0][..20], &r.blobs).unwrap_err().why,
        BreakKind::TornHeader
    );
}

#[test]
fn inv_11_non_canonical_lines_are_refused() {
    let (r, b, _) = good_journal();
    let ls = lines(&b);
    let text = String::from_utf8(ls[1].clone()).unwrap();
    for bad in [
        // duplicate key (INV-22 applied to journal lines)
        text.replacen("{\"attempt\":1,", "{\"attempt\":1,\"attempt\":1,", 1),
        // whitespace
        text.replacen(",\"body\"", ", \"body\"", 1),
        // keys out of canonical order
        text.replacen("{\"attempt\":1,\"body\"", "{\"body\"", 1)
            .replacen("\"kind\"", "\"attempt\":1,\"kind\"", 1),
    ] {
        assert_ne!(bad, text);
        let mut ls2 = ls.clone();
        ls2[1] = bad.into_bytes();
        assert_eq!(
            verify(&join(&ls2), &r.blobs).unwrap_err(),
            Broken {
                record: 1,
                why: BreakKind::NotCanonical
            }
        );
    }
}

#[test]
fn inv_11_records_after_run_stopped_or_from_another_run_are_refused() {
    let (r, b, _) = good_journal();
    let ls = lines(&b);
    let v = verify(&b, &r.blobs).unwrap();
    // Append a validly chained record after RunStopped.
    let mut extra: serde_json::Map<String, Value> = serde_json::from_slice(&ls[4]).unwrap();
    extra.insert("seq".into(), Value::from(6u64));
    extra.insert("t_mono_ms".into(), Value::from(10_000u64));
    let (l6, _) = recompute_hash(
        Value::Object(extra).to_string().as_bytes(),
        &v.records[5].hash,
    );
    let mut ls2 = ls.clone();
    ls2.push(l6);
    assert_eq!(
        verify(&join(&ls2), &r.blobs).unwrap_err().why,
        BreakKind::AfterRunStopped
    );
    // A validly chained record claiming another attempt.
    let mut other: serde_json::Map<String, Value> = serde_json::from_slice(&ls[1]).unwrap();
    other.insert("attempt".into(), Value::from(2u64));
    let (l1, _) = recompute_hash(
        Value::Object(other).to_string().as_bytes(),
        &v.records[0].hash,
    );
    let mut ls3 = ls.clone();
    ls3[1] = l1;
    assert_eq!(
        verify(&join(&ls3[..2]), &r.blobs).unwrap_err().why,
        BreakKind::WrongRun
    );
}

/// H1 phase-exit review F-2: bytes after `RunStopped` with no trailing
/// newline are not a crash's torn tail (no crash writes past a durable
/// `RunStopped`), and the chain head, so the anchor, would not cover them.
/// They are refused like a record there; a torn tail anywhere else is
/// still a crash's, reported and resumable.
#[test]
fn inv_11_bytes_after_run_stopped_are_refused_even_without_a_newline() {
    let (r, b, head) = good_journal();
    assert_eq!(verify(&b, &r.blobs).unwrap().head, head);
    for planted in [
        &br#"{"attempt":1,"body":{"cause":"submitted","outcome":"passed"},"kind":"RunStopped"}"#[..],
        b"x",
    ] {
        let mut tampered = b.clone();
        tampered.extend_from_slice(planted);
        assert_eq!(
            verify(&tampered, &r.blobs).unwrap_err(),
            Broken {
                record: 6,
                why: BreakKind::AfterRunStopped
            }
        );
    }
    // Control: a torn line after any other record is a crash mid-append.
    let ls = lines(&b);
    let mut torn = join(&ls[..5]);
    torn.extend_from_slice(&ls[5][..20]);
    let v = verify(&torn, &r.blobs).unwrap();
    assert!(v.torn_tail.is_some() && !v.is_complete());
    assert_eq!(v.records.len(), 5);
}

#[test]
fn missing_or_altered_payloads_are_detected() {
    let (r, b, _) = good_journal();
    // Missing blob.
    let empty = MemBlobs::default();
    assert_eq!(
        verify(&b, &empty).unwrap_err(),
        Broken {
            record: 3,
            why: BreakKind::MissingBlob
        }
    );
    // Altered blob.
    let altered = MemBlobs::default();
    for (k, v) in r.blobs.map.borrow().iter() {
        let mut v = v.clone();
        v[0] ^= 1;
        altered.map.borrow_mut().insert(k.clone(), v);
    }
    assert_eq!(
        verify(&b, &altered).unwrap_err().why,
        BreakKind::UntrustedMismatch
    );
    // Altered inline text, with the record hash recomputed so only the
    // payload check can catch it.
    let ls = lines(&b);
    let v = verify(&b, &r.blobs).unwrap();
    let t = String::from_utf8(ls[3].clone())
        .unwrap()
        .replacen("reply ", "REPLY ", 1);
    let (l3, _) = recompute_hash(t.as_bytes(), &v.records[2].hash);
    let mut ls2 = ls.clone();
    ls2[3] = l3;
    assert_eq!(
        verify(&join(&ls2[..4]), &r.blobs).unwrap_err().why,
        BreakKind::UntrustedMismatch
    );
}

// ---- standing conditions through the writer ------------------------------------------

#[test]
fn standing_conditions_are_journaled_once_per_state_change() {
    let (r, w) = rig(FaultPlan::default());
    let mut w = w.unwrap();
    let c = Condition {
        kind: ConditionKind::SandboxUnavailable,
        key: id("userns-disabled"),
    };
    let mut written = 0;
    for step in 1..=20 {
        let active = (5..=15).contains(&step);
        if w.observe_condition(step, &c, active).unwrap().is_some() {
            written += 1;
        }
    }
    assert_eq!(written, 2, "one record on entry, one on exit");
    let v = verify(&bytes(&r), &r.blobs).unwrap();
    let conds: Vec<_> = v
        .records
        .iter()
        .filter(|r| r.kind == EventKind::SandboxUnavailable)
        .collect();
    assert_eq!(conds.len(), 2);
    assert_eq!(conds[1].body.get("affected"), Some(&Value::from(11u64)));
}

#[test]
fn run_stopped_names_the_budget_dimension() {
    let (r, w) = rig(FaultPlan::default());
    let w = w.unwrap();
    let rel = w.commit(
        3,
        &StopCause::Budget(BudgetDim::Tokens),
        GateOutcome::Indeterminate {
            why: IndeterminateKind::NothingChecked,
        },
        Some(sha256(b"diff")),
    );
    assert!(rel.chain_head.is_some());
    let v = verify(&bytes(&r), &r.blobs).unwrap();
    let last = v.records.last().unwrap();
    assert_eq!(last.body.get("cause"), Some(&Value::from("budget")));
    assert_eq!(last.body.get("dimension"), Some(&Value::from("tokens")));
    assert_eq!(
        last.body.get("outcome"),
        Some(&Value::from("indeterminate:nothing_checked"))
    );
}

// ---- on disk: create_new, the reader, resume into a new attempt ----------------------

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "harness-journal-test-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn on_disk_journal_round_trips_through_the_reader() {
    let t = TempDir::new("disk");
    let run_dir = t.0.join("runs").join("run-0001");
    std::fs::create_dir_all(&run_dir).unwrap();
    let (mut w, n) =
        JournalWriter::create_next_attempt(&run_dir, rid(1), Header::new(id("0.0.1"))).unwrap();
    assert_eq!(n, 1);
    let big = w
        .untrusted(&Untrusted::new(vec![7u8; 9000], Source::Model))
        .unwrap();
    w.append(
        1,
        Event::new(EventKind::ModelReplied).field("raw", Trusted::Untrusted(big)),
    )
    .unwrap();
    let head = w
        .commit(1, &StopCause::Submitted, unreadable(), None)
        .chain_head
        .unwrap();
    let dir = layout::attempt_dir(&run_dir, 1);
    let v = JournalReader::open(&dir).unwrap();
    assert!(v.is_complete());
    v.check_anchor(&head).unwrap();
    // Delete the blob: the reader names the record that needed it.
    for e in std::fs::read_dir(dir.join(layout::BLOBS_DIR)).unwrap() {
        std::fs::remove_file(e.unwrap().path()).unwrap();
    }
    assert!(matches!(
        JournalReader::open(&dir),
        Err(reader::ReadError::Broken(Broken {
            record: 1,
            why: BreakKind::MissingBlob
        }))
    ));
}

#[test]
fn an_existing_journal_is_never_reopened_for_writing() {
    let t = TempDir::new("reopen");
    let dir = t.0.join("attempt-1");
    std::fs::create_dir_all(&dir).unwrap();
    let w = JournalWriter::create(&dir, rid(99), 1, Header::new(id("0.0.1"))).unwrap();
    drop(w);
    let before = std::fs::read(dir.join(layout::JOURNAL_FILE)).unwrap();
    let err = JournalWriter::create(&dir, rid(99), 1, Header::new(id("0.0.1"))).unwrap_err();
    assert_eq!(err.op, "create journal (create_new)");
    assert_eq!(
        std::fs::read(dir.join(layout::JOURNAL_FILE)).unwrap(),
        before
    );
}

#[test]
fn resume_after_a_poisoned_attempt_opens_a_new_file() {
    let t = TempDir::new("resume");
    let run_dir = t.0.join("run-0002");
    std::fs::create_dir_all(&run_dir).unwrap();
    let (w1, n1) =
        JournalWriter::create_next_attempt(&run_dir, rid(2), Header::new(id("0.0.1"))).unwrap();
    assert_eq!(n1, 1);
    drop(w1); // attempt 1 ends uncommitted (as after a crash or a poison)
    let a1 = layout::attempt_dir(&run_dir, 1).join(layout::JOURNAL_FILE);
    let before = std::fs::read(&a1).unwrap();
    let (w2, n2) =
        JournalWriter::create_next_attempt(&run_dir, rid(2), Header::new(id("0.0.1"))).unwrap();
    assert_eq!(n2, 2);
    let rel = w2.commit(0, &StopCause::Cancelled, unreadable(), None);
    assert!(rel.chain_head.is_some());
    assert_eq!(std::fs::read(&a1).unwrap(), before, "attempt 1 was touched");
    assert!(JournalReader::open(&layout::attempt_dir(&run_dir, 2))
        .unwrap()
        .is_complete());
}

// ---- review F-1: directory entries are made durable -----------------------------

/// Records every directory it is asked to sync; fails for paths ending in
/// `fail_suffix`.
struct SpyDirSync {
    synced: RefCell<Vec<std::path::PathBuf>>,
    fail_suffix: Option<&'static str>,
}

impl crate::writer::DirSync for SpyDirSync {
    fn sync(&self, dir: &std::path::Path) -> std::io::Result<()> {
        self.synced.borrow_mut().push(dir.to_path_buf());
        if self
            .fail_suffix
            .is_some_and(|s| dir.to_string_lossy().ends_with(s))
        {
            return Err(std::io::Error::other("injected directory fsync failure"));
        }
        crate::writer::sync_dir(dir)
    }
}

fn spy(fail_suffix: Option<&'static str>) -> SpyDirSync {
    SpyDirSync {
        synced: RefCell::new(Vec::new()),
        fail_suffix,
    }
}

#[test]
fn new_run_and_attempt_entries_are_fsynced_before_the_header() {
    let t = TempDir::new("dirsync");
    let run_dir = t.0.join("run-0003");
    std::fs::create_dir_all(&run_dir).unwrap();
    let ds = spy(None);
    let (w, n) = JournalWriter::create_next_attempt_with(
        &run_dir,
        rid(3),
        Header::new(id("0.0.1")),
        &ds,
        &|_| Ok(()),
    )
    .unwrap();
    drop(w);
    let attempt = layout::attempt_dir(&run_dir, n);
    assert_eq!(
        *ds.synced.borrow(),
        vec![run_dir.clone(), attempt.clone()],
        "the run dir (new attempt entry) and the attempt dir (journal.jsonl and blobs/ entries)"
    );
}

#[test]
fn attempt_dir_fsync_failure_refuses_to_start() {
    let t = TempDir::new("dirsync-attempt");
    let run_dir = t.0.join("run-0004");
    std::fs::create_dir_all(&run_dir).unwrap();
    let err = JournalWriter::create_next_attempt_with(
        &run_dir,
        rid(4),
        Header::new(id("0.0.1")),
        &spy(Some("attempt-1")),
        &|_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(err.op, "fsync attempt dir");
    assert_eq!(
        err.outcome(),
        GateOutcome::Indeterminate {
            why: IndeterminateKind::CouldNotRun
        }
    );
    // No header was written: the refusal came first.
    let j = layout::attempt_dir(&run_dir, 1).join(layout::JOURNAL_FILE);
    assert_eq!(std::fs::read(j).unwrap(), b"");
}

#[test]
fn run_dir_fsync_failure_refuses_to_start() {
    let t = TempDir::new("dirsync-run");
    let run_dir = t.0.join("run-0005");
    std::fs::create_dir_all(&run_dir).unwrap();
    let err = JournalWriter::create_next_attempt_with(
        &run_dir,
        rid(5),
        Header::new(id("0.0.1")),
        &spy(Some("run-0005")),
        &|_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(err.op, "fsync run dir");
    assert_eq!(
        err.outcome(),
        GateOutcome::Indeterminate {
            why: IndeterminateKind::CouldNotRun
        }
    );
    assert!(
        !layout::attempt_dir(&run_dir, 1)
            .join(layout::JOURNAL_FILE)
            .exists(),
        "no journal after a failed run-dir fsync"
    );
}

// ---- review F-4: no symlinks under the attempt -----------------------------------

#[cfg(unix)]
#[test]
fn a_planted_blobs_symlink_is_refused() {
    let t = TempDir::new("blobs-link");
    let dir = t.0.join("attempt-1");
    let elsewhere = t.0.join("elsewhere");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, dir.join(layout::BLOBS_DIR)).unwrap();
    let err = JournalWriter::create(&dir, rid(99), 1, Header::new(id("0.0.1"))).unwrap_err();
    assert_eq!(err.op, "create blobs dir");
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn a_symlinked_attempt_dir_is_refused() {
    let t = TempDir::new("attempt-link");
    let real = t.0.join("real");
    std::fs::create_dir_all(&real).unwrap();
    let link = t.0.join("attempt-1");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let err = JournalWriter::create(&link, rid(99), 1, Header::new(id("0.0.1"))).unwrap_err();
    assert_eq!(err.op, "attempt dir");
    assert_eq!(std::fs::read_dir(&real).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn the_reader_refuses_a_blobs_symlink_swapped_in_later() {
    let t = TempDir::new("reader-link");
    let dir = t.0.join("attempt-1");
    std::fs::create_dir_all(&dir).unwrap();
    let w = JournalWriter::create(&dir, rid(99), 1, Header::new(id("0.0.1"))).unwrap();
    drop(w);
    let blobs = dir.join(layout::BLOBS_DIR);
    std::fs::rename(&blobs, t.0.join("moved")).unwrap();
    std::os::unix::fs::symlink(t.0.join("moved"), &blobs).unwrap();
    assert!(matches!(
        JournalReader::open(&dir),
        Err(reader::ReadError::NotReal("blobs dir"))
    ));
}

// ---- review F-5: a journal is bound to its attempt ---------------------------------

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &to.join(e.file_name()));
        } else {
            std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
        }
    }
}

#[test]
fn a_journal_copied_into_another_attempt_is_refused() {
    let t = TempDir::new("copied");
    let run_dir = t.0.join("run-0006");
    std::fs::create_dir_all(&run_dir).unwrap();
    let (w, _) =
        JournalWriter::create_next_attempt(&run_dir, rid(6), Header::new(id("0.0.1"))).unwrap();
    let _ = w.commit(1, &StopCause::Submitted, unreadable(), None);
    let a1 = layout::attempt_dir(&run_dir, 1);
    let v = JournalReader::open(&a1).unwrap();
    assert_eq!((v.run.as_str(), v.attempt), (rid(6).as_str(), 1));
    JournalReader::open_expecting(&a1, &rid(6)).unwrap();

    // The copy verifies as a chain, but not as attempt 2.
    let a2 = layout::attempt_dir(&run_dir, 2);
    copy_dir(&a1, &a2);
    assert!(matches!(
        JournalReader::open(&a2),
        Err(reader::ReadError::Broken(Broken {
            why: BreakKind::WrongAttempt,
            ..
        }))
    ));
    // Nor as another run's attempt 1.
    assert!(matches!(
        JournalReader::open_expecting(&a1, &rid(9999)),
        Err(reader::ReadError::Broken(Broken {
            why: BreakKind::WrongAttempt,
            ..
        }))
    ));
    // A directory not named attempt-<n> is not an attempt.
    let odd = t.0.join("renamed");
    copy_dir(&a1, &odd);
    assert!(matches!(
        JournalReader::open(&odd),
        Err(reader::ReadError::NotAnAttemptDir)
    ));
}

// ---- H1c confirming review NF-3: run ids and the durable run directory ------

#[test]
fn run_directories_come_only_from_run_ids_and_are_created_durably() {
    let t = TempDir::new("rundir");
    let run = rid(42);
    let dir = layout::create_run_dir(&t.0, &run).unwrap();
    assert_eq!(dir, t.0.join("runs").join(run.as_str()));
    assert!(dir.is_dir());
    // The same run cannot be created twice.
    assert!(layout::create_run_dir(&t.0, &run).is_err());
    // A second run shares the existing `runs/`.
    assert!(layout::create_run_dir(&t.0, &rid(43)).is_ok());
    // Nothing that is not 32 hex characters is a run id at all.
    for bad in ["..", ".", "../escape", "run-01", "a/b"] {
        assert!(harness_core::RunId::parse(bad).is_none(), "{bad}");
    }
}

#[cfg(unix)]
#[test]
fn a_symlinked_runs_directory_is_refused() {
    let t = TempDir::new("runs-link");
    let elsewhere = t.0.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, t.0.join("runs")).unwrap();
    assert!(layout::create_run_dir(&t.0, &rid(1)).is_err());
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
}

// ---- H1c review F-6: typed provenance for trusted fields ---------------------

#[test]
fn idents_come_from_static_text_or_trusted_types_only() {
    assert!(Ident::of("userns-disabled").is_some());
    assert!(Ident::of("..").is_none());
    let run = rid(7);
    assert_eq!(Ident::from_trusted(&run).unwrap().as_str(), run.as_str());
}

// H1e-1 review: a retry after a failed state_root sync must sync it again.
struct PathSpy {
    fail: Option<std::path::PathBuf>,
    synced: RefCell<Vec<std::path::PathBuf>>,
}

impl crate::writer::DirSync for PathSpy {
    fn sync(&self, dir: &std::path::Path) -> std::io::Result<()> {
        self.synced.borrow_mut().push(dir.to_path_buf());
        if self.fail.as_deref() == Some(dir) {
            return Err(std::io::Error::other("injected directory fsync failure"));
        }
        crate::writer::sync_dir(dir)
    }
}

#[test]
fn create_run_dir_syncs_state_root_even_when_runs_already_exists() {
    let t = TempDir::new("rundir-sync");
    // First call: runs/ is created, but the state_root sync fails.
    let failing = PathSpy {
        fail: Some(t.0.clone()),
        synced: RefCell::new(Vec::new()),
    };
    assert!(layout::create_run_dir_with(&t.0, &rid(1), &failing).is_err());
    assert!(
        t.0.join("runs").is_dir(),
        "runs/ exists after the failed call"
    );
    // Retry: runs/ now exists; state_root must still be synced first.
    let ok = PathSpy {
        fail: None,
        synced: RefCell::new(Vec::new()),
    };
    let dir = layout::create_run_dir_with(&t.0, &rid(2), &ok).unwrap();
    let synced = ok.synced.borrow().clone();
    assert_eq!(synced, vec![t.0.clone(), t.0.join("runs")]);
    assert!(dir.is_dir());
}

// ---- H1e-2b: attempt-directory check, replay directories, header claims ----

#[test]
fn a_failed_attempt_dir_check_refuses_before_the_header() {
    let t = TempDir::new("attempt-check");
    let run_dir = t.0.join("run-0006");
    std::fs::create_dir_all(&run_dir).unwrap();
    let seen = std::cell::RefCell::new(None);
    let err = JournalWriter::create_next_attempt_checked(
        &run_dir,
        rid(6),
        Header::new(id("0.0.1")),
        &|p| {
            *seen.borrow_mut() = Some(p.to_path_buf());
            Err("not local".into())
        },
    )
    .unwrap_err();
    assert_eq!(err.op, "attempt dir check");
    assert_eq!(
        seen.borrow().as_deref(),
        Some(layout::attempt_dir(&run_dir, 1).as_path()),
        "the check sees the new attempt directory itself"
    );
    assert!(!layout::attempt_dir(&run_dir, 1)
        .join(layout::JOURNAL_FILE)
        .exists());
}

#[test]
fn replay_journals_live_beside_the_attempts_and_carry_the_attempt_number() {
    let t = TempDir::new("replay-dir");
    let run_dir = t.0.join("run-0007");
    std::fs::create_dir_all(&run_dir).unwrap();
    let (w, dir) =
        JournalWriter::create_replay(&run_dir, rid(7), 2, Header::new(id("0.0.1"))).unwrap();
    drop(w);
    assert_eq!(dir, layout::replay_dir(&run_dir, 1));
    let bytes = std::fs::read(dir.join(layout::JOURNAL_FILE)).unwrap();
    let v = verify(
        &bytes,
        &reader::DirBlobSource::new(dir.join(layout::BLOBS_DIR)),
    )
    .unwrap();
    assert_eq!(v.attempt, 2);
    let (_, second) =
        JournalWriter::create_replay(&run_dir, rid(7), 2, Header::new(id("0.0.1"))).unwrap();
    assert_eq!(second, layout::replay_dir(&run_dir, 2));
    assert_eq!(layout::latest_attempt(&run_dir).unwrap(), None);
}

#[test]
fn header_claims_are_untrusted_payloads_never_trusted_text() {
    let file = FaultFile::new(FaultPlan::default());
    let buf = file.buf.clone();
    let w = JournalWriter::start(
        file,
        MemBlobs::default(),
        TestClock(Cell::new(0)),
        rid(8),
        1,
        Header::new(id("0.0.1")).claimed(
            "claimed_model",
            Untrusted::new("evil\u{202e}model".into(), Source::Model),
        ),
    )
    .unwrap();
    drop(w);
    let v = verify(&buf.borrow(), &MemBlobs::default()).unwrap();
    let c = v.records[0].body.get("claimed_model").unwrap();
    assert_eq!(c.get("untrusted"), Some(&serde_json::Value::Bool(true)));
    assert!(!c
        .get("inline")
        .unwrap()
        .as_str()
        .unwrap()
        .contains('\u{202e}'));
}

// ---- P-05/P-10: session kinds, the user source and the UI tap --------------

/// The session stop cause's wire name (P-05/P-10), distinct from every
/// other cause's.
#[test]
fn stop_cause_session_ended_wire_name() {
    assert_eq!(
        crate::writer::stop_cause_name(&StopCause::SessionEnded),
        "session_ended"
    );
    let names: std::collections::BTreeSet<&str> = [
        StopCause::Submitted,
        StopCause::SubmittedChecksFailed,
        StopCause::Budget(harness_core::BudgetDim::Steps),
        StopCause::FormatErrors,
        StopCause::Loop(harness_core::LoopKind::Repeat),
        StopCause::ContextExhausted,
        StopCause::PolicyAbort,
        StopCause::ModelUnavailable,
        StopCause::Cancelled,
        StopCause::SessionEnded,
        StopCause::SandboxLost,
        StopCause::JournalUnavailable {
            op: "append".into(),
            error: "e".into(),
        },
    ]
    .iter()
    .map(crate::writer::stop_cause_name)
    .collect();
    assert_eq!(names.len(), 12, "every cause names itself");
}

/// A session-shaped journal: header, one `UserTurn` (its text a user-source
/// payload), `TurnEnded`, `InputEnded`, and `RunStopped{session_ended}`.
fn session_journal() -> (Rig, Vec<u8>, Digest) {
    let (r, w) = rig(FaultPlan::default());
    let mut w = w.unwrap();
    let text = w
        .untrusted(&Untrusted::new("what changed?".to_owned(), Source::User))
        .unwrap();
    w.append(
        0,
        Event::new(EventKind::UserTurn)
            .field("external_change", Trusted::Bool(false))
            .field("shown", Trusted::Text("yes"))
            .field("text", Trusted::Untrusted(text))
            .field("turn", Trusted::U64(1))
            .field("turn_steps", Trusted::U64(50))
            .field("wall_used_ms", Trusted::U64(12))
            .field("workspace_files", Trusted::U64(3))
            .field("workspace_oversize", Trusted::U64(0))
            .field("workspace_tree", Trusted::Digest(sha256(b"tree"))),
    )
    .unwrap();
    w.append(
        2,
        Event::new(EventKind::TurnEnded)
            .field("reason", Trusted::Text("answered"))
            .field("steps", Trusted::U64(2))
            .field("turn", Trusted::U64(1)),
    )
    .unwrap();
    w.append(
        2,
        Event::new(EventKind::InputEnded)
            .field("reason", Trusted::Text("eof"))
            .field("turn", Trusted::U64(1)),
    )
    .unwrap();
    let rel = w.commit(2, &StopCause::SessionEnded, unreadable(), None);
    assert!(rel.chain_head.is_some(), "{rel:?}");
    let head = rel.chain_head.unwrap();
    let b = bytes(&r);
    (r, b, head)
}

/// INV-11 / P-10: the three defined session kinds round trip through the
/// canonical encoding and the verifying reader, with the user text bound by
/// its payload home, and the stop cause names itself.
#[test]
fn new_event_kinds_round_trip_canonical() {
    let (r, b, head) = session_journal();
    let v = verify(&b, &r.blobs).unwrap();
    let kinds: Vec<EventKind> = v.records.iter().map(|x| x.kind).collect();
    assert_eq!(
        kinds,
        [
            EventKind::RunStarted,
            EventKind::UserTurn,
            EventKind::TurnEnded,
            EventKind::InputEnded,
            EventKind::RunStopped
        ]
    );
    assert!(v.is_complete());
    assert_eq!(v.head, head);
    let turn = &v.records[1].body;
    assert_eq!(turn.len(), 9, "exactly the canonical fields");
    let text = turn.get("text").unwrap();
    assert_eq!(
        text.get("source"),
        Some(&serde_json::json!({"kind": "user"}))
    );
    assert_eq!(text.get("inline"), Some(&Value::from("what changed?")));
    assert_eq!(turn.get("shown"), Some(&Value::from("yes")));
    assert_eq!(turn.get("turn"), Some(&Value::from(1u64)));
    // The session stop cause's wire name is on the committed record.
    assert_eq!(
        v.records[4].body.get("cause"),
        Some(&Value::from("session_ended"))
    );
    assert_eq!(
        crate::writer::stop_cause_name(&StopCause::SessionEnded),
        "session_ended"
    );
    // Durable: the header, the three session kinds and the stop are synced.
    assert_eq!(r.syncs.get(), 5);
}

/// A canonical `Egress` body (P-39c, §4.5): the allow path, with the
/// model-supplied URL in its payload home and the resolver answer in
/// order.
fn egress_event(url: UntrustedBlob) -> Event {
    Event::new(EventKind::Egress)
        .field("decision", Trusted::Text("allow"))
        .field("host", Trusted::Text("example.com"))
        .field("hop", Trusted::U64(0))
        .field("ip", Trusted::Text("93.184.216.34"))
        .field("mode", Trusted::Text("direct"))
        .field("port", Trusted::U64(443))
        .field("purpose", Trusted::Text("fetch"))
        .field(
            "resolved",
            Trusted::List(vec![
                Trusted::Text("93.184.216.34"),
                Trusted::Text("2606:2800:220:1:248:1893:25c8:1946"),
            ]),
        )
        .field("url", Trusted::Untrusted(url))
}

/// P-39c (§4.5): a canonical `Egress` body round trips through the writer
/// and the verifying reader carrying exactly the §4.5 fields, sorted on
/// the wire; the verified body is the body that was appended.
#[test]
fn egress_body_round_trips_canonical() {
    let (r, w) = rig(FaultPlan::default());
    let mut w = w.unwrap();
    let url = w
        .untrusted(&Untrusted::new(
            "https://example.com/doc".to_owned(),
            Source::Model,
        ))
        .unwrap();
    let ev = egress_event(url);
    let expected = ev.body().unwrap();
    w.append(3, ev).unwrap();
    let b = bytes(&r);
    let v = verify(&b, &r.blobs).unwrap();
    let rec = v.records.last().unwrap();
    assert_eq!(rec.kind, EventKind::Egress);
    assert_eq!(rec.body, expected, "the verified body is the appended one");
    // Exactly the §4.5 fields; the reader only accepts the line because it
    // is the canonical encoding, so the keys are sorted on the wire.
    let keys: Vec<&str> = rec.body.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        crate::canon::canonical_body_keys(EventKind::Egress).unwrap()
    );
    assert_eq!(
        crate::canon::check_canonical_body(EventKind::Egress, &rec.body),
        Ok(())
    );
    // The URL's payload home says where it came from (§4.5: the model).
    let url_home = rec.body.get("url").unwrap();
    assert_eq!(
        url_home.get("source"),
        Some(&serde_json::json!({"kind": "model"}))
    );
    assert_eq!(
        url_home.get("inline"),
        Some(&Value::from("https://example.com/doc"))
    );
    assert_eq!(
        rec.body.get("resolved"),
        Some(&serde_json::json!([
            "93.184.216.34",
            "2606:2800:220:1:248:1893:25c8:1946"
        ]))
    );
}

/// P-39c: an `Egress` body with a key outside the §4.5 list is refused
/// before anything is written. The writer is NOT poisoned (a malformed
/// event is a harness bug, not an I/O failure) and lawful records still
/// append after the refusal.
#[test]
fn egress_body_with_extra_key_refused() {
    let (r, w) = rig(FaultPlan::default());
    let mut w = w.unwrap();
    let url = w
        .untrusted(&Untrusted::new(
            "https://example.com/doc".to_owned(),
            Source::Model,
        ))
        .unwrap();
    let before = bytes(&r);
    let err = w
        .append(
            3,
            egress_event(url.clone()).field("extra", Trusted::Bool(true)),
        )
        .unwrap_err();
    assert!(matches!(err, JournalError::InvalidEvent(_)), "{err:?}");
    assert!(!w.is_poisoned());
    assert_eq!(bytes(&r), before, "the refused record touched the file");
    w.append(3, egress_event(url)).unwrap();
    let v = verify(&bytes(&r), &r.blobs).unwrap();
    assert_eq!(v.records.last().unwrap().kind, EventKind::Egress);
}

/// P-39c (§6, §7): the research-note kinds round trip, each append is
/// fsynced before it returns (a resume reads its notes back from the
/// journal), and the imported note's bytes ride in their typed home.
#[test]
fn note_kinds_round_trip_and_fsynced() {
    let (r, w) = rig(FaultPlan::default());
    let mut w = w.unwrap();
    assert!(EventKind::NoteSaved.needs_fsync());
    assert!(EventKind::NoteImported.needs_fsync());
    let syncs = r.syncs.get();
    w.append(
        3,
        Event::new(EventKind::NoteSaved)
            .field("bytes", Trusted::U64(2048))
            .field("note", Trusted::Digest(sha256(b"note-1")))
            .field("sources", Trusted::U64(2))
            .field("turn", Trusted::U64(4)),
    )
    .unwrap();
    assert_eq!(r.syncs.get(), syncs + 1, "NoteSaved is fsynced");
    let payload = "note body".to_owned();
    let bytes_home = w
        .untrusted(&Untrusted::new(
            payload.clone(),
            Source::Workspace("research/notes/note-1/note.md".into()),
        ))
        .unwrap();
    let path_home = w
        .untrusted(&Untrusted::new(
            "note-1/note.md".to_owned(),
            Source::Workspace("research/notes".into()),
        ))
        .unwrap();
    w.append(
        4,
        Event::new(EventKind::NoteImported)
            .field("bytes", Trusted::Untrusted(bytes_home))
            .field("confirm", Trusted::Text("typed-id-prefix"))
            .field("note", Trusted::Digest(sha256(b"note-1")))
            .field("path", Trusted::Untrusted(path_home))
            .field("sha256", Trusted::Digest(sha256(payload.as_bytes()))),
    )
    .unwrap();
    assert_eq!(r.syncs.get(), syncs + 2, "NoteImported is fsynced");
    let v = verify(&bytes(&r), &r.blobs).unwrap();
    let kinds: Vec<EventKind> = v.records.iter().map(|x| x.kind).collect();
    assert_eq!(
        kinds,
        [
            EventKind::RunStarted,
            EventKind::NoteSaved,
            EventKind::NoteImported
        ]
    );
    let saved = &v.records[1].body;
    assert_eq!(saved.len(), 4, "exactly the §6 fields");
    assert_eq!(
        crate::canon::check_canonical_body(EventKind::NoteSaved, saved),
        Ok(())
    );
    assert_eq!(
        saved.get("note"),
        Some(&Value::from(sha256(b"note-1").to_string()))
    );
    let imported = &v.records[2].body;
    assert_eq!(imported.len(), 5, "exactly the §7 fields");
    assert_eq!(
        crate::canon::check_canonical_body(EventKind::NoteImported, imported),
        Ok(())
    );
    assert_eq!(
        imported.get("bytes").unwrap().get("inline"),
        Some(&Value::from(payload.as_str()))
    );
    assert_eq!(
        imported.get("sha256"),
        Some(&Value::from(sha256(payload.as_bytes()).to_string()))
    );
    assert_eq!(
        imported.get("confirm"),
        Some(&Value::from("typed-id-prefix"))
    );
}

/// P-39c: a `Source::Web` payload home verifies — the reader accepts the
/// new provenance — and the URL is escaped like every other runtime text
/// in a record: ESC and bidi controls are neutralised on the wire, and
/// `unescape` gives the original back.
#[test]
fn source_web_escaped_in_journal() {
    let (r, w) = rig(FaultPlan::default());
    let mut w = w.unwrap();
    let url = "https://evil.example/p\u{1b}[31m\u{202e}x";
    let page = w
        .untrusted(&Untrusted::new(
            "page".to_owned(),
            Source::Web(url.to_owned()),
        ))
        .unwrap();
    w.append(
        1,
        Event::new(EventKind::ModelReplied).field("content", Trusted::Untrusted(page)),
    )
    .unwrap();
    let b = bytes(&r);
    let v = verify(&b, &r.blobs).unwrap();
    let source = v.records[1]
        .body
        .get("content")
        .unwrap()
        .get("source")
        .unwrap();
    let wire_url = source.get("url").and_then(Value::as_str).unwrap();
    assert_eq!(wire_url, "https://evil.example/p\\u{1B}[31m\\u{202E}x");
    assert_eq!(crate::canon::unescape(wire_url).as_deref(), Some(url));
    let text = String::from_utf8(b).unwrap();
    assert!(!text.contains('\u{1b}'), "raw ESC in the journal");
    assert!(
        !text.contains('\u{202e}'),
        "raw bidi override in the journal"
    );
}

/// The reader's closed set stays closed: a canonical, correctly re-chained
/// record with an unknown kind is refused by name (P-10 added nine kinds,
/// P-39c added two, and nothing else).
#[test]
fn unknown_kind_still_refused() {
    let (r, b, _) = session_journal();
    let ls = lines(&b);
    let v = verify(&b, &r.blobs).unwrap();
    for name in ["ModeChangedLater", "NoteSavedX", "NoteImportedX"] {
        let mut forged: serde_json::Map<String, Value> = serde_json::from_slice(&ls[2]).unwrap();
        forged.insert("kind".into(), Value::from(name));
        let (l2, _) = recompute_hash(
            Value::Object(forged).to_string().as_bytes(),
            &v.records[1].hash,
        );
        let mut ls2 = ls.clone();
        ls2[2] = l2;
        assert_eq!(
            verify(&join(&ls2[..3]), &r.blobs).unwrap_err(),
            Broken {
                record: 2,
                why: BreakKind::UnknownKind
            },
            "{name}"
        );
        assert_eq!(EventKind::parse(name), None, "{name}");
    }
}

/// A user-source payload verifies: the reader recomputes the payload's
/// hash from its escaped inline text and it matches.
#[test]
fn user_source_payload_verifies() {
    let (r, b, _) = session_journal();
    let v = verify(&b, &r.blobs).unwrap();
    let text = v.records[1].body.get("text").unwrap();
    assert_eq!(
        text.get("sha256"),
        Some(&Value::from(sha256(b"what changed?").to_string()))
    );
    assert_eq!(text.get("len"), Some(&Value::from(13u64)));
    assert_eq!(v.records.len(), 5);
}

/// A user message's bytes are evidence: an edit with the record hash
/// recomputed (so only the payload check can catch it) is refused.
#[test]
fn user_source_payload_tamper_detected() {
    let (r, b, _) = session_journal();
    let v = verify(&b, &r.blobs).unwrap();
    let ls = lines(&b);
    let t = String::from_utf8(ls[1].clone())
        .unwrap()
        .replacen("changed", "CHANGED", 1);
    let (l1, _) = recompute_hash(t.as_bytes(), &v.records[0].hash);
    let mut ls2 = ls.clone();
    ls2[1] = l1;
    assert_eq!(
        verify(&join(&ls2[..2]), &r.blobs).unwrap_err().why,
        BreakKind::UntrustedMismatch
    );
    // The unaltered journal still verifies.
    let again = verify(&b, &r.blobs).unwrap();
    assert_eq!(again.head, v.head);
}

/// The wire source `{"kind":"user"}` is exact: any extra field in the
/// source object is a malformed payload home, refused by name.
#[test]
fn user_source_with_extra_field_refused() {
    let (r, b, _) = session_journal();
    let ls = lines(&b);
    let v = verify(&b, &r.blobs).unwrap();
    let mut forged: serde_json::Map<String, Value> = serde_json::from_slice(&ls[1]).unwrap();
    let body = forged.get_mut("body").unwrap().as_object_mut().unwrap();
    let text = body.get_mut("text").unwrap().as_object_mut().unwrap();
    let source = text.get_mut("source").unwrap().as_object_mut().unwrap();
    source.insert("id".into(), Value::from("someone"));
    let (l1, _) = recompute_hash(
        Value::Object(forged).to_string().as_bytes(),
        &v.records[0].hash,
    );
    let mut ls2 = ls.clone();
    ls2[1] = l1;
    assert_eq!(
        verify(&join(&ls2[..2]), &r.blobs).unwrap_err().why,
        BreakKind::UntrustedMalformed
    );
}

/// A journal written by the build before P-10 (bytes pinned from the
/// pre-change build's `good_journal`; every kind in it predates P-39c
/// too) still verifies, kinds and all: adding the web airlock kinds (P-39c)
/// changed no existing encoding.
#[test]
fn old_journal_still_reads() {
    const FIXTURE: [&str; 6] = [
        r#"{"attempt":1,"body":{"harness_version":"0.0.1","os":"test"},"hash":"7cbc47d5a01b397b8a37e074785e0e9789e1b659af44fed5f4dc99a2b4c8b662","kind":"RunStarted","prev":"0000000000000000000000000000000000000000000000000000000000000000","run":"00000000000100000000000000000000","seq":0,"step":0,"t_mono_ms":5,"t_wall":"2026-09-21T14:13:20.005Z"}"#,
        r#"{"attempt":1,"body":{"call":"7edb360f06acaef2cc80dba16cf563f199d347db4443da04da0c8173e3f9e4ed","capability":"harness.fs.read"},"hash":"2dbf1873b2720f4234d3fe75cfacfc94bdafa71c87bd2d7c59baad198822dcd4","kind":"ToolStarted","prev":"7cbc47d5a01b397b8a37e074785e0e9789e1b659af44fed5f4dc99a2b4c8b662","run":"00000000000100000000000000000000","seq":1,"step":1,"t_mono_ms":10,"t_wall":"2026-09-21T14:13:20.010Z"}"#,
        r#"{"attempt":1,"body":{"status":"ok"},"hash":"2691ef4d46a1a4f91b8c5af8b7c397b90590e489a08fcee9d78f39d8fe091ff6","kind":"ToolFinished","prev":"2dbf1873b2720f4234d3fe75cfacfc94bdafa71c87bd2d7c59baad198822dcd4","run":"00000000000100000000000000000000","seq":2,"step":1,"t_mono_ms":15,"t_wall":"2026-09-21T14:13:20.015Z"}"#,
        r#"{"attempt":1,"body":{"content":{"inline":"reply \\u{1B}[2J\\u{202E}","len":13,"sha256":"10a3922feb76ea7fe6a3b739c193e070229a2766a9300345e0ad9b62f9c671ed","source":{"kind":"model"},"untrusted":true},"raw":{"blob":"2bf7158cb3d8f419f1e19ee71df61927cc17017f37ea8820f3bd719d2b4f88f8","len":10000,"sha256":"2bf7158cb3d8f419f1e19ee71df61927cc17017f37ea8820f3bd719d2b4f88f8","source":{"id":"harness.fs.read","kind":"tool"},"untrusted":true}},"hash":"90ebef0579db3e05631bfd6603e6bc9383f86279452df454941461358bc1b444","kind":"ModelReplied","prev":"2691ef4d46a1a4f91b8c5af8b7c397b90590e489a08fcee9d78f39d8fe091ff6","run":"00000000000100000000000000000000","seq":3,"step":2,"t_mono_ms":20,"t_wall":"2026-09-21T14:13:20.020Z"}"#,
        r#"{"attempt":1,"body":{"steps":2},"hash":"07b178cca2baed19b7b2dc739eb3f9cfce3e3543b6b313bf5bd2b0753ce6243e","kind":"BudgetCharged","prev":"90ebef0579db3e05631bfd6603e6bc9383f86279452df454941461358bc1b444","run":"00000000000100000000000000000000","seq":4,"step":2,"t_mono_ms":25,"t_wall":"2026-09-21T14:13:20.025Z"}"#,
        r#"{"attempt":1,"body":{"cause":"submitted","outcome":"passed"},"hash":"5151b3c0bf9c2d0716a6b72d08f27568050c9e99348a9db6e7acd189ab9c5ff3","kind":"RunStopped","prev":"07b178cca2baed19b7b2dc739eb3f9cfce3e3543b6b313bf5bd2b0753ce6243e","run":"00000000000100000000000000000000","seq":5,"step":2,"t_mono_ms":30,"t_wall":"2026-09-21T14:13:20.030Z"}"#,
    ];
    /// The fixture's one blob: 10 000 bytes of 0xff, named by their digest.
    struct FixtureBlobs;
    impl crate::reader::BlobSource for FixtureBlobs {
        fn get(&self, name: &str) -> Option<Vec<u8>> {
            (name == "2bf7158cb3d8f419f1e19ee71df61927cc17017f37ea8820f3bd719d2b4f88f8")
                .then(|| vec![0xffu8; 10_000])
        }
    }
    let bytes = join(
        &FIXTURE
            .iter()
            .map(|l| l.as_bytes().to_vec())
            .collect::<Vec<_>>(),
    );
    let v = verify(&bytes, &FixtureBlobs).unwrap();
    let kinds: Vec<EventKind> = v.records.iter().map(|r| r.kind).collect();
    assert_eq!(
        kinds,
        [
            EventKind::RunStarted,
            EventKind::ToolStarted,
            EventKind::ToolFinished,
            EventKind::ModelReplied,
            EventKind::BudgetCharged,
            EventKind::RunStopped
        ]
    );
    assert!(v.is_complete());
    let anchor: Digest = "5151b3c0bf9c2d0716a6b72d08f27568050c9e99348a9db6e7acd189ab9c5ff3"
        .parse()
        .unwrap();
    v.check_anchor(&anchor).unwrap();
}

// The UI tap (P-05 §1.3): off by default, seq order, nothing from a
// poisoned writer.

#[test]
fn tap_disabled_buffers_nothing() {
    let (_, w) = rig(FaultPlan::default());
    let mut w = w.unwrap();
    let invoked = Cell::new(0);
    step_once(&mut w, 1, &invoked).unwrap();
    assert!(w.drain_tap().is_empty(), "no tap, no records");
}

#[test]
fn tap_drains_records_in_seq_order() {
    let (r, w) = rig(FaultPlan::default());
    let mut w = w.unwrap();
    w.enable_tap();
    let invoked = Cell::new(0);
    step_once(&mut w, 1, &invoked).unwrap();
    w.append(1, Event::new(EventKind::ContextBuilt)).unwrap();
    let tapped = w.drain_tap();
    let seqs: Vec<u64> = tapped.iter().map(|t| t.seq).collect();
    assert_eq!(seqs, [1, 2, 3], "intent, result, ContextBuilt");
    assert_eq!(tapped[0].kind, EventKind::ToolStarted);
    assert_eq!(tapped[0].step, 1);
    assert_eq!(
        tapped[0].body.get("capability"),
        Some(&Value::from("harness.fs.read"))
    );
    // Drained: the next drain is empty until more records are written.
    assert!(w.drain_tap().is_empty());
    w.append(2, Event::new(EventKind::FormatError)).unwrap();
    assert_eq!(w.drain_tap().len(), 1);
    let _ = r;
}

#[test]
fn tap_has_nothing_after_poison() {
    // write #1 = header, #2 = the intent (fails).
    let (r, w) = rig(FaultPlan {
        fail_write: Some(2),
        ..Default::default()
    });
    let mut w = w.unwrap();
    w.enable_tap();
    let invoked = Cell::new(0);
    assert!(step_once(&mut w, 1, &invoked).is_err());
    assert!(w.is_poisoned());
    // The failed record was never written, so nothing is tapped.
    assert!(w.drain_tap().is_empty());
    let _ = r;
}

// ---- fuzz-style robustness (P-54) ----------------------------------------------
//
// The reader/verifier is a parser of untrusted bytes: whatever a crash, an
// edit or an attacker left in the attempt file, `verify` must answer with a
// typed verdict — never a panic, never an unbounded computation. The inputs
// come from `harness_testkit::mutator`, whose seeded xorshift generator makes
// every case reproducible from the seed named in the loop (seed base + case).

use harness_testkit::mutator::{self, XorShift64};

/// The mutated-valid-log loop, at whatever case count the caller asks for.
fn fuzz_reader_over_mutated_logs(cases: usize) {
    let (r, b, _) = good_journal();
    for case in 0..cases {
        let mut rng = XorShift64::new(0x5400_0000_0001 + case as u64);
        let m = mutator::mutate(&b, &mut rng, 24);
        // Either verdict is fine; the test is that there IS one, typed,
        // with the mutated bytes still bounded by len + 24.
        if let Ok(v) = verify(&m, &r.blobs) {
            assert!(v.records.len() * 2 <= m.len() + 2, "case {case}");
        }
        // And the same mutation is reproducible: re-derive and re-verify.
        let mut rng2 = XorShift64::new(0x5400_0000_0001 + case as u64);
        let m2 = mutator::mutate(&b, &mut rng2, 24);
        assert_eq!(m, m2, "case {case}");
    }
}

#[test]
fn fuzz_journal_reader_mutated_valid_log_never_panics() {
    fuzz_reader_over_mutated_logs(mutator::case_count(2_000));
}

/// The long form: `cargo test -- --ignored` with `RH_FUZZ_CASES` set drives
/// the case count up.
#[test]
#[ignore]
fn fuzz_journal_long_cases() {
    fuzz_reader_over_mutated_logs(mutator::case_count(50_000));
}

#[test]
fn fuzz_journal_truncation_at_every_byte_is_typed_error() {
    let (r, b, _) = good_journal();
    // No bytes at all is a typed refusal (no header), not a panic.
    assert!(verify(&[], &r.blobs).is_err());
    // Every proper prefix verifies to a typed verdict, and never claims to
    // be a complete, committed journal: a cut either tears the final line
    // (torn tail) or loses the RunStopped record — a wholesale truncation
    // can only ever look incomplete, never valid-and-done.
    for i in 0..b.len() {
        if let Ok(v) = verify(&b[..i], &r.blobs) {
            assert!(!v.is_complete(), "prefix {i} of {} complete?", b.len());
        }
    }
    // A prefix that cuts only the final newline keeps every record and
    // reports the torn last line (its start offset, after the last `\n`).
    let v = verify(&b[..b.len() - 1], &r.blobs).unwrap();
    assert!(v.torn_tail.is_some());
    assert!(!v.is_complete());
}
