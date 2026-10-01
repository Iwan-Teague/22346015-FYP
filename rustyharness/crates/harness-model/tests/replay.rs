//! Replay, audit mode, model half (design §2.9, INV-20 partial): record a
//! run's model exchanges in a journal, read them back, and re-feed them;
//! any different request is a named divergence.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::cell::Cell;
use std::time::{Duration, Instant};

use gate_outcome::{GateOutcome, IndeterminateKind};
use harness_core::{Source, StopCause, Untrusted};
use harness_journal::testing::{FaultFile, FaultPlan, MemBlobs};
use harness_journal::{verify, Clock, Header, Ident, JournalWriter};
use harness_model::profile::Profile;
use harness_model::replay::{replied_event, requested_event, ReplayBackend};
use harness_model::scripted::{text_reply, tool_reply, ScriptedBackend};
use harness_model::wire::render_request;
use harness_model::{
    HarnessText, Message, ModelBackend, ModelError, ModelRequest, RenderNonce, TaskText,
};

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

fn req(turn: u64, obs: &str) -> ModelRequest {
    ModelRequest {
        messages: vec![
            Message::System(HarnessText::from_static("rules")),
            Message::Task(TaskText::new("summarise the repo".into())),
            Message::Observation {
                call: "harness.fs.read".into(),
                body: Untrusted::new(obs.to_owned(), Source::Tool("harness.fs.read".into())),
            },
        ],
        tools: vec![],
        nonce: RenderNonce::new(&format!("{turn:016x}")).unwrap(),
    }
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(1)
}

/// Record three exchanges (a text reply with escape-worthy bytes, a reply
/// big enough for the blob store, a tool call) and one typed error.
fn record() -> (Vec<u8>, MemBlobs, Profile) {
    let profile = Profile::conservative_default("local-model");
    let big = format!("{}\u{1b}[31m", "y".repeat(6000));
    let script = ScriptedBackend::new(
        profile.clone(),
        vec![
            Ok(text_reply(
                "thinking \u{202E} <action>{\"tool\":\"harness.fs.read\",\"args\":{}}</action>",
            )),
            Ok(text_reply(&big)),
            Ok(tool_reply("harness_fs_read", "{\"path\":\"README.md\"}")),
            Err(ModelError::Truncated("finish_reason: length")),
        ],
    );
    let file = FaultFile::new(FaultPlan::default());
    let buf = file.buf.clone();
    let blobs = MemBlobs::default();
    let mut w = JournalWriter::start(
        file,
        blobs.clone(),
        Tick(Cell::new(0)),
        harness_core::RunId::new(20, [0; 10]),
        1,
        Header::new(Ident::of("0.0.1").unwrap()),
    )
    .unwrap();
    for turn in 0..4u64 {
        let r = req(turn, &format!("observation {turn}"));
        let rendered = render_request(&r, &profile).unwrap();
        w.append(turn, requested_event(&rendered, &r.nonce).unwrap())
            .unwrap();
        let result = script.complete(&r, soon());
        let ev = replied_event(&mut w, &result).unwrap();
        w.append(turn, ev).unwrap();
    }
    let rel = w.commit(
        4,
        &StopCause::Submitted,
        GateOutcome::Indeterminate {
            why: IndeterminateKind::NothingChecked,
        },
        None,
    );
    assert!(rel.chain_head.is_some());
    let bytes = buf.borrow().clone();
    (bytes, blobs, profile)
}

#[test]
fn inv_20_model_half_replay_reproduces_every_recorded_exchange() {
    let (bytes, blobs, profile) = record();
    let v = verify(&bytes, &blobs).unwrap();
    let replay = ReplayBackend::from_journal(&v, &blobs, profile.clone()).unwrap();
    assert_eq!(replay.len(), 4);
    assert_eq!(
        replay.recorded_nonce(2).unwrap().as_str(),
        "0000000000000002"
    );

    let a = replay.complete(&req(0, "observation 0"), soon()).unwrap();
    assert!(
        a.content.inspect("test").contains('\u{202E}'),
        "recorded bytes, not the escaped form"
    );
    let b = replay.complete(&req(1, "observation 1"), soon()).unwrap();
    assert_eq!(b.content.inspect("test").len(), 6000 + "\u{1b}[31m".len());
    let c = replay.complete(&req(2, "observation 2"), soon()).unwrap();
    assert_eq!(
        c.tool_calls[0].inspect("test").arguments,
        "{\"path\":\"README.md\"}"
    );
    assert_eq!(
        replay
            .complete(&req(3, "observation 3"), soon())
            .unwrap_err(),
        ModelError::Truncated("finish_reason: length"),
        "a recorded error replays as the same typed error"
    );
    assert!(replay.exhausted());
    // One call more than was recorded: a named divergence, not a guess.
    assert_eq!(
        replay
            .complete(&req(4, "observation 4"), soon())
            .unwrap_err(),
        ModelError::ReplayDiverged {
            exchange: 4,
            why: "no recorded reply for this call"
        }
    );
}

#[test]
fn inv_20_model_half_a_different_context_is_the_first_divergence() {
    let (bytes, blobs, profile) = record();
    let v = verify(&bytes, &blobs).unwrap();
    let replay = ReplayBackend::from_journal(&v, &blobs, profile).unwrap();
    replay.complete(&req(0, "observation 0"), soon()).unwrap();
    // A tampered tool result changes the next context: divergence at 1.
    assert_eq!(
        replay
            .complete(&req(1, "observation 1 (tampered)"), soon())
            .unwrap_err(),
        ModelError::ReplayDiverged {
            exchange: 1,
            why: "the request differs from the recorded one"
        }
    );
    // A different nonce is a different request too.
    assert!(matches!(
        replay.complete(&req(9, "observation 1"), soon()),
        Err(ModelError::ReplayDiverged { exchange: 1, .. })
    ));
}

#[test]
fn replay_needs_the_blob_store() {
    let (bytes, blobs, profile) = record();
    let v = verify(&bytes, &blobs).unwrap();
    let empty = MemBlobs::default();
    assert!(matches!(
        ReplayBackend::from_journal(&v, &empty, profile),
        Err(harness_model::replay::ReplayError::MissingBlob(_))
    ));
}

// H1d review F-6: replay re-hashes every payload against its record.
#[test]
fn replay_refuses_a_blob_that_is_not_the_recorded_one() {
    let (bytes, blobs, profile) = record();
    let v = verify(&bytes, &blobs).unwrap();
    // A different blob store, with the same names but altered bytes.
    let other = MemBlobs::default();
    for (k, val) in blobs.map.borrow().iter() {
        let mut val = val.clone();
        val[0] ^= 1;
        other.map.borrow_mut().insert(k.clone(), val);
    }
    assert!(matches!(
        ReplayBackend::from_journal(&v, &other, profile),
        Err(harness_model::replay::ReplayError::PayloadMismatch(_))
    ));
}
