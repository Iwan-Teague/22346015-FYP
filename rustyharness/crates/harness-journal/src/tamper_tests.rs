//! The journal tamper suite (P-34, part a): property-style mutations of a
//! real, writer-produced journal. Every class the roadmap names — single
//! bit flips in every byte of every line, truncation at every offset,
//! line drop / duplicate / reorder, field swaps, non-canonical encodings,
//! bytes after `RunStopped`, and payload tampering — must be reported by
//! [`verify`]. A wholesale re-chain with valid hashes is locally
//! consistent by construction; only an anchor (`check_anchor`) names it.
//! The session-audit halves of the same attacks live in
//! `harness-run/tests/tamper.rs`.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use gate_outcome::{GateOutcome, IndeterminateKind};
use harness_core::{sha256, Digest, RunId, Source, StopCause, Untrusted};
use serde_json::Value;

use crate::canon::{RecordFields, GENESIS};
use crate::testing::{FaultFile, FaultPlan, MemBlobs};
use crate::*;

// ---- the rig (the shape src/tests.rs uses) ---------------------------------

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
    blobs: MemBlobs,
}

type W = JournalWriter<FaultFile, MemBlobs, TestClock>;

fn rig() -> (Rig, W) {
    let file = FaultFile::new(FaultPlan::default());
    let buf = file.buf.clone();
    let blobs = MemBlobs::default();
    let w = JournalWriter::start(
        file,
        blobs.clone(),
        TestClock::default(),
        rid(1),
        1,
        Header::new(id("0.0.1")).field("os", Trusted::Text("test")),
    );
    (Rig { buf, blobs }, w.unwrap())
}

fn id(s: &'static str) -> Ident {
    Ident::of(s).unwrap()
}

fn rid(n: u64) -> harness_core::RunId {
    harness_core::RunId::new(n, [0; 10])
}

/// A call whose digest is computed from itself (the journal asks it).
struct TestCall(&'static str);

impl harness_core::CallDigest for TestCall {
    fn call_digest(&self) -> Digest {
        sha256(self.0.as_bytes())
    }
}

fn unreadable() -> GateOutcome {
    GateOutcome::Indeterminate {
        why: IndeterminateKind::UnreadableEvidence,
    }
}

/// A committed journal of 6 records: header, intent, result, `ModelReplied`
/// with an inline and a blob payload, `BudgetCharged`, `RunStopped`.
fn content_journal() -> (Rig, Vec<u8>, Digest) {
    let (r, mut w) = rig();
    let j = w
        .append_intent(
            1,
            Event::new(EventKind::ToolStarted)
                .field("capability", Trusted::Id(id("harness.fs.read"))),
            TestCall("call"),
        )
        .unwrap();
    let _ = j.call();
    w.append(
        1,
        Event::new(EventKind::ToolFinished).field("status", Trusted::Text("ok")),
    )
    .unwrap();
    let small = w
        .untrusted(&Untrusted::new("reply text".to_owned(), Source::Model))
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
    let head = w
        .commit(2, &StopCause::Submitted, unreadable(), None)
        .chain_head
        .unwrap();
    let b = r.buf.borrow().clone();
    (r, b, head)
}

/// A session-shaped journal of 5 records: header, `UserTurn` (its text a
/// user-source payload), `TurnEnded`, `InputEnded`, `RunStopped`.
fn session_journal() -> (Rig, Vec<u8>, Digest) {
    let (r, mut w) = rig();
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
    let head = w
        .commit(2, &StopCause::SessionEnded, unreadable(), None)
        .chain_head
        .unwrap();
    let b = r.buf.borrow().clone();
    (r, b, head)
}

// ---- byte-level helpers -----------------------------------------------------

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

/// Re-encode every line with `edit` applied and every hash re-chained: the
/// forger who can rewrite anything. Returns the journal bytes and their
/// head. A no-op edit must reproduce the original bytes exactly.
fn rechain(ls: &[Vec<u8>], edit: impl Fn(&mut Value)) -> (Vec<u8>, Digest) {
    let mut prev = GENESIS;
    let mut out = Vec::new();
    for l in ls {
        let mut v: Value = serde_json::from_slice(l).unwrap();
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
        out.extend_from_slice(&bytes);
        out.push(b'\n');
        prev = hash;
    }
    (out, prev)
}

// ---- P-34: the properties ---------------------------------------------------

/// Every single-bit flip in every byte of every line (and of every line
/// separator) is reported by the reader: an in-line flip is refused by
/// name — the canonical encoding, the hash chain and the payload homes
/// leave no bit unaccounted for — and flipping the final newline away
/// turns the stop record into a torn tail, reported as incomplete.
#[test]
fn tamper_every_line_flip_detected() {
    let (r, b, head) = content_journal();
    let ls = lines(&b);
    let starts = {
        let mut starts = Vec::new();
        let mut o = 0usize;
        for l in &ls {
            starts.push(o);
            o += l.len() + 1;
        }
        starts
    };
    let mut flips = 0usize;
    let mut report = |flip: usize, res: &Result<Verified, Broken>| {
        if let Ok(v) = res {
            // Only the final newline can pass: the stop record becomes a
            // torn tail, which the reader reports rather than refuses.
            assert!(
                v.torn_tail.is_some() && flip + 1 == b.len(),
                "flip at byte {flip} was not detected by the reader"
            );
        }
        flips += 1;
    };
    for (li, l) in ls.iter().enumerate() {
        for bi in 0..l.len() {
            for bit in 0..8u8 {
                let mut tampered = b.clone();
                let off = starts[li] + bi;
                tampered[off] ^= 1 << bit;
                report(off, &verify(&tampered, &r.blobs));
            }
        }
    }
    // The line separators too: flipping one merges two lines, which is
    // never a canonical record.
    for (sep, off) in b.iter().enumerate() {
        if *off != b'\n' {
            continue;
        }
        for bit in 0..8u8 {
            let mut tampered = b.clone();
            tampered[sep] ^= 1 << bit;
            report(sep, &verify(&tampered, &r.blobs));
        }
    }
    assert!(flips > 1000, "the sweep covered {flips} flips");

    // Named: the final newline flipped away is a torn stop record —
    // reported, incomplete, and no longer the anchored head.
    let mut torn = b.clone();
    let last = torn.len() - 1;
    torn[last] ^= 0x10;
    let v = verify(&torn, &r.blobs).unwrap();
    let tail_start = torn[..torn.len() - 1]
        .iter()
        .rposition(|b| *b == b'\n')
        .unwrap()
        + 1;
    assert_eq!(v.torn_tail, Some(tail_start));
    assert!(!v.is_complete());
    assert!(v.check_anchor(&head).is_err());
}

/// Truncation at every offset: a cut inside the header is a torn header;
/// a cut anywhere later keeps a verifying prefix, reports the torn tail
/// when the cut lands inside a line, never claims completeness, and never
/// matches the full journal's anchor. Only the uncut journal is complete.
#[test]
fn tamper_truncated_tail_reported() {
    let (r, b, head) = content_journal();
    let ls = lines(&b);
    let whole = verify(&b, &r.blobs).unwrap();
    assert!(whole.is_complete());
    let line0_len = ls[0].len();
    for cut in 0..=b.len() {
        let res = verify(&b[..cut], &r.blobs);
        if cut == 0 {
            assert_eq!(res.unwrap_err().why, BreakKind::Empty);
            continue;
        }
        if cut <= line0_len {
            assert_eq!(res.unwrap_err().why, BreakKind::TornHeader, "cut {cut}");
            continue;
        }
        let v = res.unwrap();
        // The verified prefix is the original chain's prefix, byte for byte.
        for (i, rec) in v.records.iter().enumerate() {
            assert_eq!(rec.hash, whole.records[i].hash, "cut {cut}: record {i}");
        }
        let mid_line = b[cut - 1] != b'\n';
        assert_eq!(
            v.torn_tail.is_some(),
            mid_line,
            "cut {cut}: torn tail reported iff the cut lands inside a line"
        );
        assert_eq!(v.is_complete(), cut == b.len(), "cut {cut}");
        if cut < b.len() {
            assert!(
                v.check_anchor(&head).is_err(),
                "cut {cut}: a truncated journal matched the full head"
            );
        }
    }
}

/// A forger who re-chains: the reader accepts a wholesale rewrite with
/// valid hashes — a no-op re-chain even reproduces the head exactly — so
/// altered content is detected only against an anchor recorded elsewhere.
#[test]
fn tamper_rechain_detected_only_with_anchor() {
    let (r, b, head) = session_journal();
    let ls = lines(&b);
    let v = verify(&b, &r.blobs).unwrap();

    // Control: re-encoding without an edit is byte-exact and re-derives
    // the same head.
    let (noop, noop_head) = rechain(&ls, |_| {});
    assert_eq!(noop, b, "re-encoding is deterministic");
    assert_eq!(noop_head, head);

    // A clock fact forged consistently: locally valid, anchor-named.
    let (forged, _) = rechain(&ls, |v: &mut Value| {
        if v["kind"] == "UserTurn" {
            v["body"]["wall_used_ms"] = Value::from(12_345u64);
        }
    });
    let fv = verify(&forged, &r.blobs).unwrap();
    assert!(fv.is_complete(), "the forgery is locally consistent");
    assert_ne!(
        fv.records[1].body["wall_used_ms"],
        v.records[1].body["wall_used_ms"]
    );
    assert!(fv.check_anchor(&head).is_err());

    // The user's words forged, with the payload home restamped to match:
    // still locally valid, still anchor-named.
    let (words, _) = rechain(&ls, |v: &mut Value| {
        if v["kind"] == "UserTurn" {
            let text = "forget the workspace";
            v["body"]["text"]["inline"] = Value::from(text);
            v["body"]["text"]["sha256"] = Value::from(sha256(text.as_bytes()).to_string());
            v["body"]["text"]["len"] = Value::from(text.len() as u64);
        }
    });
    let wv = verify(&words, &r.blobs).unwrap();
    assert!(wv.is_complete());
    assert_eq!(
        wv.records[1].body["text"]["inline"],
        Value::from("forget the workspace")
    );
    assert!(wv.check_anchor(&head).is_err());

    // And the untampered journal still matches its own head.
    assert_eq!(v.head, head);
    v.check_anchor(&head).unwrap();
}

/// Structural mutations — line drops, duplicates, adjacent swaps, a whole
/// reversal, body field swaps, non-canonical encodings, bytes after
/// `RunStopped`, and payload tampering — are each refused, with the first
/// broken record named. Dropping the final `RunStopped` is the one
/// mutation the reader alone cannot name: the journal still verifies, but
/// is incomplete and no longer matches the anchor.
#[test]
fn tamper_structural_mutations_detected() {
    let (r, b, head) = content_journal();
    let ls = lines(&b);
    let n = ls.len();
    let u = |x: usize| u64::try_from(x).unwrap();

    // Line drop: BadSeq names the displaced successor; the header's
    // absence is named at record 0; dropping the stop is completeness's
    // and the anchor's job.
    for i in 0..n {
        let mut dropped = ls.clone();
        dropped.remove(i);
        let res = verify(&join(&dropped), &r.blobs);
        if i + 1 == n {
            let v = res.unwrap();
            assert!(!v.is_complete(), "dropping the stop stayed complete");
            assert!(v.check_anchor(&head).is_err());
        } else {
            // The header's absence is a sequence break too: the survivor
            // at record 0 carries seq 1.
            assert_eq!(
                res.unwrap_err(),
                Broken {
                    record: i,
                    why: BreakKind::BadSeq {
                        expected: u(i),
                        found: u(i) + 1
                    }
                }
            );
        }
    }

    // Line duplicate: the copy sits at the wrong sequence (the sequence
    // check names it before the stop does); a correctly chained copy
    // after the stop is refused outright.
    for i in 0..n {
        let mut dup = ls.clone();
        dup.insert(i + 1, ls[i].clone());
        assert_eq!(
            verify(&join(&dup), &r.blobs).unwrap_err(),
            Broken {
                record: i + 1,
                why: BreakKind::BadSeq {
                    expected: u(i) + 1,
                    found: u(i)
                }
            }
        );
    }

    // Adjacent swaps and a whole reversal: the first displaced record's
    // sequence is what names it.
    for i in 0..n - 1 {
        let mut sw = ls.clone();
        sw.swap(i, i + 1);
        assert_eq!(
            verify(&join(&sw), &r.blobs).unwrap_err(),
            Broken {
                record: i,
                why: BreakKind::BadSeq {
                    expected: u(i),
                    found: u(i) + 1
                }
            }
        );
    }
    let mut rev = ls.clone();
    rev.reverse();
    assert_eq!(
        verify(&join(&rev), &r.blobs).unwrap_err(),
        Broken {
            record: 0,
            why: BreakKind::BadSeq {
                expected: 0,
                found: u(n) - 1
            }
        }
    );

    // A forged header: a re-chained record at seq 0 that is not a
    // `RunStarted` is refused by name.
    let (fake_header, _) = rechain(&ls, |v: &mut Value| {
        if v["seq"] == 0u64 {
            v["kind"] = Value::from("ContextBuilt");
        }
    });
    assert_eq!(
        verify(&fake_header, &r.blobs).unwrap_err(),
        Broken {
            record: 0,
            why: BreakKind::HeaderMisplaced
        }
    );

    // A body field swap (the `ModelReplied` payload homes traded): the
    // line re-encodes canonically, so the hash is what names it.
    let mut swapped = ls.clone();
    let mut line: Value = serde_json::from_slice(&ls[3]).unwrap();
    let content = line["body"]["content"].clone();
    line["body"]["content"] = line["body"]["raw"].clone();
    line["body"]["raw"] = content;
    swapped[3] = line.to_string().into_bytes();
    assert_eq!(
        verify(&join(&swapped), &r.blobs).unwrap_err(),
        Broken {
            record: 3,
            why: BreakKind::BadHash
        }
    );

    // Non-canonical encodings of every line: a duplicated key, injected
    // whitespace, and keys out of canonical order are each refused at
    // their own record.
    for i in 0..n {
        let text = String::from_utf8(ls[i].clone()).unwrap();
        // The reorder surgery moves `attempt` from the first key to the
        // last: it parses, but is not the canonical encoding.
        let mut reordered = text.replacen("{\"attempt\":1,", "{", 1);
        reordered.pop();
        reordered.push_str(",\"attempt\":1}");
        for bad in [
            text.replacen("{\"attempt\":1,", "{\"attempt\":1,\"attempt\":1,", 1),
            text.replacen(",\"body\"", ", \"body\"", 1),
            reordered,
        ] {
            assert_ne!(bad, text, "line {i}: the surgery changed nothing");
            let mut tampered = ls.clone();
            tampered[i] = bad.into_bytes();
            assert_eq!(
                verify(&join(&tampered), &r.blobs).unwrap_err(),
                Broken {
                    record: i,
                    why: BreakKind::NotCanonical
                },
                "line {i}"
            );
        }
    }

    // Bytes after `RunStopped`: a validly chained extra record, and bare
    // garbage, newline-terminated or not.
    let mut extra: Value = serde_json::from_slice(&ls[4]).unwrap();
    extra["seq"] = Value::from(u(n));
    extra["t_mono_ms"] = Value::from(10_000u64);
    let (chained, _) = rechain(
        &[&ls[..], &[extra.to_string().into_bytes()][..]].concat(),
        |_| {},
    );
    assert_eq!(
        verify(&chained, &r.blobs).unwrap_err().why,
        BreakKind::AfterRunStopped
    );
    for planted in [&b"x"[..], b"x\n", br#"{"attempt":1}"#] {
        let mut tampered = b.clone();
        tampered.extend_from_slice(planted);
        let err = verify(&tampered, &r.blobs).unwrap_err();
        assert_eq!(err.record, n, "planted {:?}", planted);
        assert!(
            matches!(err.why, BreakKind::AfterRunStopped | BreakKind::NotARecord),
            "planted {:?}: {:?}",
            planted,
            err.why
        );
    }

    // Payload tampering: a missing blob names the record that needed it;
    // altered blob bytes fail the payload check.
    assert_eq!(
        verify(&b, &MemBlobs::default()).unwrap_err(),
        Broken {
            record: 3,
            why: BreakKind::MissingBlob
        }
    );
    let altered = MemBlobs::default();
    for (k, val) in r.blobs.map.borrow().iter() {
        let mut val = val.clone();
        val[0] ^= 1;
        altered.map.borrow_mut().insert(k.clone(), val);
    }
    assert_eq!(
        verify(&b, &altered).unwrap_err(),
        Broken {
            record: 3,
            why: BreakKind::UntrustedMismatch
        }
    );

    // Inline text rewritten under a re-chain (only the hash recomputed):
    // the payload home no longer matches the text.
    let (inline_forged, _) = rechain(&ls, |v: &mut Value| {
        if v["kind"] == "ModelReplied" {
            v["body"]["content"]["inline"] = Value::from("REPLY text");
        }
    });
    assert_eq!(
        verify(&inline_forged, &r.blobs).unwrap_err().why,
        BreakKind::UntrustedMismatch
    );

    // A record claiming another attempt, re-chained so only the claim is
    // wrong: refused by name.
    let (other_attempt, _) = rechain(&ls, |v: &mut Value| {
        if v["seq"] == 1u64 {
            v["attempt"] = Value::from(2u64);
        }
    });
    assert_eq!(
        verify(&other_attempt, &r.blobs).unwrap_err().why,
        BreakKind::WrongRun
    );

    // The control: the untouched journal verifies, is complete, and is
    // anchored by its own head.
    let intact = verify(&b, &r.blobs).unwrap();
    assert!(intact.is_complete() && intact.torn_tail.is_none());
    assert_eq!(intact.records.len(), n);
    assert_eq!(intact.head, head);
    intact.check_anchor(&head).unwrap();
}
