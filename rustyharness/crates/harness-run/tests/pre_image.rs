//! P-22: the pre-image store. An edit's `EditApplied` cites the file's
//! bytes before and after as content-addressed blobs in the attempt's
//! `blobs/` (a create keeps no pre-image: the field's absence is the
//! absent marker), and the audit replays from the blobs — clean while
//! they hold the bytes their digests name, refusing one that does not.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;

use harness_core::{sha256, Digest, StopCause};
use harness_journal::layout;
use harness_journal::{EventKind, JournalReader, Record};
use harness_model::profile::Profile;
use harness_model::{Completion, TaskText};
use harness_policy::UserPolicy;
use harness_run::{audit, Audit, RunConfig, RunReport, TaskSpec};
use harness_testkit::{act, registry, run_scripted_policy, submit, Fixture};
use serde_json::Value;

const OLD: &str = "pub const RETRY_BASE_MS: u64 = 250;\n";
const NEW: &str = "pub const RETRY_BASE_MS: u64 = 375;\n";

/// An edit-granted spec: the read tool (edits anchor on reads) and the
/// two write tools, over a private workspace.
fn spec() -> TaskSpec {
    TaskSpec {
        task: TaskText::new("Set the retry base to 375 ms.".into()),
        grants: vec![
            "harness.fs.read".into(),
            "harness.edit.replace".into(),
            "harness.edit.write".into(),
        ],
        workspace_public: false,
        exec: None,
        presubmit: None,
        protected: Vec::new(),
        kind: harness_run::SessionKind::Coding,
    }
}

/// A fixture with `src/lib.rs` holding [`OLD`], under [`spec`].
fn fx(name: &str) -> Fixture {
    let mut fx = Fixture::new(&format!("pre-image-{name}")).unwrap();
    fx.write("src/lib.rs", OLD).unwrap();
    fx.spec = spec();
    fx
}

/// The policy an unattended run edits under: the edit tools allowed.
fn allow_edits() -> UserPolicy {
    UserPolicy::new(&[], &[], &["harness.edit.replace", "harness.edit.write"]).unwrap()
}

fn read(p: &str) -> Completion {
    act(
        "harness.fs.read",
        &serde_json::json!({ "path": p }).to_string(),
    )
}

fn replace(p: &str, old: &str, new: &str) -> Completion {
    act(
        "harness.edit.replace",
        &serde_json::json!({ "path": p, "old": old, "new": new }).to_string(),
    )
}

fn write(p: &str, content: &str) -> Completion {
    act(
        "harness.edit.write",
        &serde_json::json!({ "path": p, "content": content }).to_string(),
    )
}

fn go(fx: &Fixture, replies: Vec<Completion>) -> RunReport {
    run_scripted_policy(fx, &allow_edits(), replies).unwrap()
}

fn records(r: &RunReport) -> Vec<Record> {
    JournalReader::open(&layout::attempt_dir(&r.run_dir, r.attempt))
        .unwrap()
        .records
}

fn applied(r: &RunReport) -> Record {
    records(r)
        .into_iter()
        .find(|x| x.kind == EventKind::EditApplied)
        .unwrap()
}

/// The attempt's blob named by `digest`'s hex (its content's SHA-256).
fn blob(r: &RunReport, digest: Digest) -> Vec<u8> {
    fs::read(
        layout::attempt_dir(&r.run_dir, r.attempt)
            .join(layout::BLOBS_DIR)
            .join(digest.to_string()),
    )
    .unwrap()
}

// The whole path: read, one replace, submit. The record cites the file's
// bytes before and after by their digests, and the attempt's `blobs/`
// holds each image under its own digest, byte for byte.
#[test]
fn edit_stores_pre_image_blob() {
    let fx = fx("stores-pre-image");
    let r = go(
        &fx,
        vec![
            read("src/lib.rs"),
            replace("src/lib.rs", "= 250;", "= 375;"),
            submit(),
        ],
    );
    assert_eq!(r.cause, StopCause::Submitted);
    assert_eq!(
        fs::read_to_string(fx.workspace().join("src/lib.rs")).unwrap(),
        NEW
    );
    let e = applied(&r).body;
    let before = sha256(OLD.as_bytes());
    let after = sha256(NEW.as_bytes());
    assert_eq!(e["before"], Value::from(before.to_string()));
    assert_eq!(e["before_blob"], Value::from(before.to_string()));
    assert_eq!(e["after"], Value::from(after.to_string()));
    assert_eq!(e["after_blob"], Value::from(after.to_string()));
    assert_eq!(blob(&r, before), OLD.as_bytes());
    assert_eq!(blob(&r, after), NEW.as_bytes());
    assert!(harness_testkit::assert_audit_clean_policy(&fx, &allow_edits(), &r).is_ok());
}

// A create keeps no pre-image: neither `before` nor `before_blob` is
// written (the absence is the absent marker), while the after-blob holds
// the new file's bytes.
#[test]
fn new_file_pre_image_is_absent_marker() {
    let fx = fx("create");
    let body = "pub fn one() {}\n";
    let r = go(
        &fx,
        vec![
            write("src/new.rs", body),
            replace("src/lib.rs", "= 250;", "= 375;"),
            submit(),
        ],
    );
    assert_eq!(r.cause, StopCause::Submitted);
    let e = applied(&r).body;
    assert!(e.get("before").is_none(), "a create");
    assert!(
        e.get("before_blob").is_none(),
        "a create keeps no pre-image"
    );
    let after = sha256(body.as_bytes());
    assert_eq!(e["after_blob"], Value::from(after.to_string()));
    assert_eq!(blob(&r, after), body.as_bytes());
    assert!(harness_testkit::assert_audit_clean_policy(&fx, &allow_edits(), &r).is_ok());
}

// An audit replays a run whose edits cite blobs: clean, with the blobs
// left as the run kept them.
#[test]
fn audit_clean_with_blobs() {
    let fx = fx("audit-clean");
    let r = go(
        &fx,
        vec![
            read("src/lib.rs"),
            replace("src/lib.rs", "= 250;", "= 375;"),
            write("src/new.rs", "pub fn added() {}\n"),
            submit(),
        ],
    );
    assert_eq!(r.cause, StopCause::Submitted);
    assert_eq!(applied(&r).body["before_blob"], applied(&r).body["before"]);
    assert!(harness_testkit::assert_audit_clean_policy(&fx, &allow_edits(), &r).is_ok());
    // The audit did not disturb the store: both images still hold.
    assert_eq!(blob(&r, sha256(OLD.as_bytes())), OLD.as_bytes());
    assert_eq!(blob(&r, sha256(NEW.as_bytes())), NEW.as_bytes());
}

// A blob whose bytes no longer hash to the digest it is cited by is not
// a shape the loop writes: the audit says so instead of re-feeding it.
#[test]
fn blob_tamper_detected_by_audit() {
    let fx = fx("tamper");
    let r = go(
        &fx,
        vec![
            read("src/lib.rs"),
            replace("src/lib.rs", "= 250;", "= 375;"),
            submit(),
        ],
    );
    assert_eq!(r.cause, StopCause::Submitted);
    let dir = layout::attempt_dir(&r.run_dir, r.attempt).join(layout::BLOBS_DIR);
    let name = sha256(OLD.as_bytes()).to_string();
    fs::write(dir.join(&name), b"tampered\n").unwrap();
    let a = audit(Audit {
        state_root: fx.state_root(),
        run: &r.run,
        attempt: None,
        anchor: r.chain_head,
        spec: &fx.spec,
        registry: &registry().unwrap(),
        policy: &allow_edits(),
        profile: &Profile::conservative_default("m"),
        limits: &RunConfig::defaults(1_000_000).limits,
    })
    .unwrap();
    assert_eq!(
        a.divergence.map(|d| d.why),
        Some("a record is not the shape the loop writes")
    );
}
