//! The journal tamper suite, session side (P-34, part a): a real scripted
//! session's journal, attacked one mutation class at a time. Every class
//! the roadmap names — bit flips in each line, line drop / duplicate /
//! reorder, truncation, bytes after `RunStopped`, non-canonical
//! encodings — must surface in `audit_session` (or leave the journal
//! visibly incomplete). A wholesale re-chain with valid hashes replays
//! clean without an anchor and is caught only by `--anchor`; a re-chained
//! content forgery diverges even without one. The reader-level
//! properties, exhaustive over every byte, live in
//! `harness-journal/src/tamper_tests.rs`.

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
use harness_core::{Digest, RunId};
use harness_journal::canon::{RecordFields, GENESIS};
use harness_journal::{layout, EventKind, JournalReader};
use harness_model::profile::Profile;
use harness_model::scripted::ScriptedBackend;
use harness_model::{Completion, ModelError};
use harness_policy::UserPolicy;
use harness_run::{
    audit_session, run_session, ApprovalAnswer, Approver, ApproverKind, Audit, InputEnd,
    SessionConfig, SessionReport, SessionRun, UserInput, UserInputEvent, UserMessage,
};
use harness_testkit::{act, assert_session_audit_clean, registry, say, Fixture, Local};
use serde_json::Value;

/// A fixed environment sample (the real probe is harness-sandbox's; these
/// tests only need the header and records to carry one).
const FIXED_ENV: EnvSample = EnvSample::unmeasured(Unmeasured::NoSafeApi);

/// The token budget every scripted session is given.
const TOKENS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Fixtures, drivers and journals (the shape tests/hostile_session.rs uses).
// ---------------------------------------------------------------------------

fn fx() -> Fixture {
    let mut fx = Fixture::new("tamper-session").unwrap();
    fx.spec = harness_run::TaskSpec {
        task: harness_model::TaskText::new("Tamper probe: read and edit.".into()),
        grants: vec!["harness.fs.read".into(), "harness.edit.write".into()],
        workspace_public: false,
        ports: Vec::new(),
        lan_ports: Vec::new(),
        exec: None,
        presubmit: None,
        post_edit: None,
        protected: Vec::new(),
        kind: harness_run::SessionKind::Coding,
    };
    fx
}

/// A scripted [`UserInput`]: each step is a closure producing the next
/// event.
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

/// Drive the session every tamper case starts from: two turns, a read,
/// an approved edit, an answer.
fn session() -> (Fixture, SessionReport) {
    let fx = fx();
    fx.write("a.txt", "before\n").unwrap();
    let input = ScriptedInput::of(&["read a.txt then rewrite b.txt", "thanks"]);
    let replies: Vec<Result<Completion, ModelError>> = vec![
        Ok(act("harness.fs.read", r#"{"path":"a.txt"}"#)),
        Ok(act(
            "harness.edit.write",
            r#"{"path":"b.txt","content":"after"}"#,
        )),
        Ok(say("done")),
    ];
    let profile = Profile::conservative_default("m");
    let backend = ScriptedBackend::new(profile.clone(), replies);
    let r = run_session(SessionRun {
        state_root: fx.state_root(),
        workspace: fx.workspace(),
        spec: &fx.spec,
        registry: &registry().unwrap(),
        policy: &UserPolicy::default(),
        profile: &profile,
        backend: &backend,
        probe: &Local,
        env: &FIXED_ENV,
        config: &SessionConfig::defaults(TOKENS),
        approver: Some(&Yes),
        confinement: None,
        input: &input,
        sink: None,
        instructions: None,
    })
    .unwrap();
    assert_session_audit_clean(&fx, &r).expect("the baseline session must audit clean");
    (fx, r)
}

fn journal_path(r: &SessionReport) -> PathBuf {
    layout::attempt_dir(&r.run.run_dir, r.run.attempt).join(layout::JOURNAL_FILE)
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

/// Re-encode every line with `edit` applied and every hash re-chained.
fn rechain(ls: &[Vec<u8>], edit: impl Fn(&mut Value)) -> Vec<u8> {
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
    out
}

/// The limits a session's header carries (the shape `session_limits` is
/// not public for): the run's limits with "never" format errors.
fn session_limits() -> harness_core::MeterLimits {
    let mut limits = SessionConfig::defaults(TOKENS).run.limits.clone();
    limits.format_errors = u32::MAX;
    limits
}

/// Audit the (possibly tampered) session journal, with or without an
/// anchor recorded elsewhere.
fn audit(fx: &Fixture, r: &SessionReport, anchor: Option<Digest>) -> harness_run::AuditReport {
    audit_session(
        Audit {
            state_root: fx.state_root(),
            run: &r.run.run,
            attempt: None,
            anchor,
            spec: &fx.spec,
            registry: &registry().unwrap(),
            policy: &UserPolicy::default(),
            profile: &Profile::conservative_default("m"),
            limits: &session_limits(),
        },
        &SessionConfig::defaults(TOKENS).turn,
    )
    .unwrap()
}

/// Whether the audit refuses to vouch for the journal: a divergence, a
/// stop it could not recompute, or — when an anchor was supplied — a
/// chain head that is not the anchor.
fn detected(rep: &harness_run::AuditReport, anchored: bool) -> bool {
    rep.divergence.is_some() || !rep.stop_recomputed || (anchored && !rep.anchored)
}

/// Overwrite the journal with `tampered`, audit, and require detection.
fn expect_detected(fx: &Fixture, r: &SessionReport, path: &Path, tampered: &[u8]) {
    let original = fs::read(path).unwrap();
    fs::write(path, tampered).unwrap();
    let rep = audit(fx, r, None);
    fs::write(path, original).unwrap();
    assert!(
        detected(&rep, false),
        "the tampered journal audited clean: {rep:?}"
    );
}

// ---------------------------------------------------------------------------
// The properties.
// ---------------------------------------------------------------------------

/// Every mutation class, applied to the real session journal, is caught:
/// one single-bit flip per line, a dropped line, a duplicated line, an
/// adjacent swap, a mid-line truncation (which leaves a torn tail the
/// reader reports), bytes planted after `RunStopped`, and a
/// non-canonical re-encoding.
#[test]
fn tamper_session_journal_mutations_detected() {
    let (fx, r) = session();
    let path = journal_path(&r);
    let original = fs::read(&path).unwrap();
    let ls = lines(&original);
    let n = ls.len();
    assert!(n > 4, "the session journal has {n} lines");

    // One flip per line: the first byte of every line, each bit.
    let mut starts = Vec::new();
    let mut off = 0usize;
    for l in &ls {
        starts.push(off);
        off += l.len() + 1;
    }
    for start in starts {
        for bit in 0..8u8 {
            let mut tampered = original.clone();
            tampered[start] ^= 1 << bit;
            expect_detected(&fx, &r, &path, &tampered);
        }
    }

    // Drop a middle line.
    let mut dropped = ls.clone();
    dropped.remove(n / 2);
    expect_detected(&fx, &r, &path, &join(&dropped));

    // Duplicate a middle line.
    let mut dup = ls.clone();
    dup.insert(n / 2 + 1, ls[n / 2].clone());
    expect_detected(&fx, &r, &path, &join(&dup));

    // Swap two adjacent middle lines.
    let mut sw = ls.clone();
    sw.swap(n / 2, n / 2 + 1);
    expect_detected(&fx, &r, &path, &join(&sw));

    // Truncate mid-line: the reader keeps the verified prefix and
    // reports the torn tail; the audit does not vouch for the stop.
    let cut = original.len() - 10;
    fs::write(&path, &original[..cut]).unwrap();
    let rep = audit(&fx, &r, None);
    let v = JournalReader::open(&layout::attempt_dir(&r.run.run_dir, r.run.attempt)).unwrap();
    let tail_start = original[..cut].iter().rposition(|b| *b == b'\n').unwrap() + 1;
    assert_eq!(v.torn_tail, Some(tail_start));
    assert!(!v.is_complete());
    fs::write(&path, &original).unwrap();
    assert!(
        detected(&rep, false),
        "a truncated journal audited clean: {rep:?}"
    );

    // Bytes after `RunStopped`.
    let mut planted = original.clone();
    planted.extend_from_slice(b"{\"smuggled\":true}\n");
    expect_detected(&fx, &r, &path, &planted);

    // A non-canonical line (injected whitespace).
    let text = String::from_utf8(ls[n / 2].clone()).unwrap();
    let mut nc = ls.clone();
    nc[n / 2] = text.replacen(",\"", ", \"\"", 1).into_bytes();
    expect_detected(&fx, &r, &path, &join(&nc));

    // The journal was restored: it audits clean again.
    let rep = audit(&fx, &r, r.run.chain_head);
    assert!(
        !detected(&rep, true),
        "the restored journal failed: {rep:?}"
    );
}

/// The forger who re-chains: a clock fact (`wall_used_ms`, a re-fed
/// measurement the audit cannot recompute) altered with every hash
/// recomputed replays clean WITHOUT an anchor and is caught only by
/// `--anchor`; a re-chained content forgery (the model's words, restamped
/// to match) diverges even without one, and either way the anchor names
/// the replacement journal.
#[test]
fn tamper_rechain_detected_only_with_anchor() {
    let (fx, r) = session();
    let path = journal_path(&r);
    let original = fs::read(&path).unwrap();
    let ls = lines(&original);
    let head = r.run.chain_head.expect("a committed session has a head");

    // A benign-looking re-chain: one re-fed clock fact moved.
    let forged = rechain(&ls, |v: &mut Value| {
        if v["kind"] == "UserTurn" {
            v["body"]["wall_used_ms"] =
                Value::from(v["body"]["wall_used_ms"].as_u64().unwrap() + 1);
        }
    });
    fs::write(&path, &forged).unwrap();
    let clean = audit(&fx, &r, None);
    assert!(
        !detected(&clean, false),
        "the consistent re-chain should replay clean without an anchor: {clean:?}"
    );
    let anchored = audit(&fx, &r, Some(head));
    assert!(
        detected(&anchored, true),
        "the anchor did not catch the re-chain: {anchored:?}"
    );

    // A content forgery: the model's reply rewritten, its payload home
    // restamped to match, every hash re-chained. The replay itself
    // diverges; the anchor names the wholesale replacement.
    let forged = rechain(&ls, |v: &mut Value| {
        if v["kind"] == "ModelReplied" {
            let content = "the model never said this";
            if let Some(home) = v["body"]
                .as_object_mut()
                .unwrap()
                .values_mut()
                .find(|x| x.get("untrusted") == Some(&Value::Bool(true)))
            {
                home["inline"] = Value::from(content);
                home["sha256"] = Value::from(harness_core::sha256(content.as_bytes()).to_string());
                home["len"] = Value::from(content.len() as u64);
            }
        }
    });
    fs::write(&path, &forged).unwrap();
    let plain = audit(&fx, &r, None);
    assert!(
        detected(&plain, false),
        "the content forgery replayed clean without an anchor: {plain:?}"
    );
    let anchored = audit(&fx, &r, Some(head));
    assert!(detected(&anchored, true));

    // Restored: clean and anchored again.
    fs::write(&path, &original).unwrap();
    let rep = audit(&fx, &r, Some(head));
    assert!(
        !detected(&rep, true),
        "the restored journal failed: {rep:?}"
    );
}
