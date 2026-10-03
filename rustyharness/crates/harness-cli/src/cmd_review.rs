//! The `review` verb (slice P-40) and the `chat` REPL's `/diff`: the whole
//! session's file change as one diff, computed from the journal's own
//! evidence — never from `git`.
//!
//! Every `EditApplied` record cites the file's bytes before and after as
//! content-addressed blobs (P-22). Review re-reads those blobs and checks
//! each against the digest the record cites: the journal's chain verifier
//! checks untrusted payload homes but not trusted blob *citations*, so
//! this re-hash is the tamper check (`review_detects_blob_tamper`). Per
//! path the first pre-image is diffed against the latest after-image —
//! a resumed session re-feeds its earlier edits, so the latest attempt's
//! records cover the whole session.
//!
//! The current workspace is then re-digested against the last after-digest:
//! a file that now differs was changed outside the harness, and review
//! says so instead of staying silent (`review_flags_out_of_band_change`).
//! A missing or symlinked file is flagged the same way; the journal diff
//! still shows what the session did.
//!
//! This is a read-only consumer: nothing is journaled for a review, the
//! session's context is untouched, and no audit-clean requirement applies.
//! Output is human text on stderr; the last line names the journal's chain
//! head (§7.1 "Anchoring"). Exit 0 whenever the review was produced (flags
//! and all), 2 usage, 4 when the journal, its blobs or the workspace
//! cannot be read.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use harness_core::diff;
use harness_core::{sha256, Digest, RunId};
use harness_journal::canon;
use harness_journal::layout::{self, BLOBS_DIR};
use harness_journal::reader::{BlobSource, DirBlobSource};
use harness_journal::{EventKind, JournalReader, Record, Verified};
use harness_policy::workspace_path;
use serde_json::{Map, Value};

use crate::args::{options_with_flags, USAGE};
use crate::report::exit;
use crate::Cx;

/// `review --run <id> --workspace <dir>`: review the run's latest attempt
/// against the workspace it edited.
pub(crate) fn review(cx: &Cx<'_>, rest: &[&str]) -> u8 {
    // The user's config (P-07) applies here too: it may carry the state
    // root. Unreadable config is unreadable input, as for a gate child.
    let cfg = match crate::config::load() {
        Ok(c) => c,
        Err(e) => {
            note!(cx, "{e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    let parsed = match options_with_flags(rest, &["run", "workspace", "state-root"], &[]) {
        Ok(p) => p,
        Err(e) => {
            note!(cx, "{e}\n{USAGE}");
            return exit::USAGE;
        }
    };
    let o = &parsed.opts;
    let Some(run_text) = o.get("run").copied() else {
        note!(cx, "--run is required\n{USAGE}");
        return exit::USAGE;
    };
    let Some(workspace) = o.get("workspace").copied() else {
        note!(cx, "--workspace is required\n{USAGE}");
        return exit::USAGE;
    };
    let Some(run) = RunId::parse(run_text) else {
        note!(cx, "--run is not a run id\n{USAGE}");
        return exit::USAGE;
    };
    let state_root = match crate::config::state_root(o, &cfg) {
        Ok(Some(s)) => s,
        Ok(None) => {
            note!(
                cx,
                "--state-root is required here (no default state root on this platform)\n{USAGE}"
            );
            return exit::USAGE;
        }
        Err(e) => {
            note!(cx, "{e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    let run_dir = layout::run_dir(Path::new(state_root.as_ref()), &run);
    let attempt_dir = match layout::latest_attempt(&run_dir) {
        Ok(Some(n)) => layout::attempt_dir(&run_dir, n),
        Ok(None) => {
            note!(cx, "no run {run} under {}", state_root.as_ref());
            return exit::UNREADABLE_INPUT;
        }
        Err(e) => {
            note!(cx, "cannot read {}: {e}", run_dir.display());
            return exit::UNREADABLE_INPUT;
        }
    };
    let v = match JournalReader::open_expecting(&attempt_dir, &run) {
        Ok(v) => v,
        Err(e) => {
            note!(cx, "cannot read the run's journal: {e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    render(cx, &attempt_dir, &v, workspace)
}

/// `/diff` in the `chat` REPL: the live attempt's session so far, against
/// the workspace the session was started in.
pub(crate) fn review_live(cx: &Cx<'_>, attempt_dir: &Path, workspace: &str) -> u8 {
    let v = match JournalReader::open(attempt_dir) {
        Ok(v) => v,
        Err(e) => {
            note!(cx, "cannot read the run's journal: {e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    render(cx, attempt_dir, &v, workspace)
}

/// One path's whole-session change, from its `EditApplied` records.
struct Change {
    /// The path's first record had no pre-image (a create).
    created: bool,
    /// The first pre-image's bytes.
    before: Option<Vec<u8>>,
    /// The latest after-image: the digest the record cites and the bytes
    /// that hashed to it.
    after: Option<(Digest, Vec<u8>)>,
    /// The first tamper or missing-blob problem found for the path.
    issue: Option<String>,
}

/// The whole review: collect the session's edits, check their blobs, and
/// compare the last after-digests against the workspace as it is now.
fn render(cx: &Cx<'_>, attempt_dir: &Path, v: &Verified, workspace: &str) -> u8 {
    match std::fs::metadata(workspace) {
        Ok(md) if md.is_dir() => {}
        _ => {
            note!(cx, "workspace {workspace} is not a directory");
            return exit::UNREADABLE_INPUT;
        }
    }
    let blobs = DirBlobSource::new(attempt_dir.join(BLOBS_DIR));
    let mut files: BTreeMap<String, Change> = BTreeMap::new();
    for r in &v.records {
        if !matches!(r.kind, EventKind::EditApplied) {
            continue;
        }
        let Some(e) = edit_of(r, &blobs) else {
            note!(cx, "an EditApplied record is not the shape the loop writes");
            return exit::UNREADABLE_INPUT;
        };
        let c = files.entry(e.path).or_insert(Change {
            created: e.before_blob.is_none(),
            before: None,
            after: None,
            issue: None,
        });
        if let Some(d) = e.before_blob {
            match image(&blobs, d) {
                Ok(bytes) => {
                    if c.before.is_none() {
                        c.before = Some(bytes);
                    }
                }
                Err(msg) if c.issue.is_none() => c.issue = Some(msg),
                Err(_) => {}
            }
        }
        match image(&blobs, e.after) {
            Ok(bytes) => c.after = Some((e.after, bytes)),
            Err(msg) if c.issue.is_none() => c.issue = Some(msg),
            Err(_) => {}
        }
    }
    let state = if v.is_complete() {
        "complete"
    } else {
        "torn tail"
    };
    note!(
        cx,
        "review of run {} attempt {} ({})",
        v.run,
        v.attempt,
        state
    );
    note!(cx, "workspace {workspace}");
    if files.is_empty() {
        note!(cx, "no file changes in this session");
    }
    for (path, c) in &files {
        render_file(cx, workspace, path, c);
    }
    note!(cx, "chain head {}", v.head);
    exit::PASSED
}

/// One journalled edit, reduced to what a diff needs. The shape rules are
/// the loop's own (replay/feed.rs): `before_blob` present exactly when
/// `before` is and naming the same bytes, and `after_blob` equal to
/// `after` — anything else is a record the loop does not write.
struct Edit {
    path: String,
    before_blob: Option<Digest>,
    after: Digest,
}

fn edit_of(r: &Record, blobs: &DirBlobSource) -> Option<Edit> {
    let body: &Map<String, Value> = &r.body;
    let digest = |key: &str| -> Option<Digest> {
        body.get(key)
            .and_then(Value::as_str)
            .and_then(|s| s.parse().ok())
    };
    let path = payload_text(body.get("path")?, blobs)?;
    let before = match body.get("before") {
        None => None,
        Some(_) => Some(digest("before")?),
    };
    let before_blob = match body.get("before_blob") {
        None => None,
        Some(_) => Some(digest("before_blob")?),
    };
    if before != before_blob {
        return None;
    }
    let after = digest("after")?;
    let after_blob = digest("after_blob")?;
    if after != after_blob {
        return None;
    }
    Some(Edit {
        path,
        before_blob,
        after,
    })
}

/// The text of an untrusted payload home (the reader has already checked
/// the home's own sha256/len): inline and escaped, or a blob-carried
/// string.
fn payload_text(home: &Value, blobs: &DirBlobSource) -> Option<String> {
    let o = home.as_object()?;
    if let Some(s) = o.get("inline").and_then(Value::as_str) {
        return canon::unescape(s);
    }
    let name = o.get("blob").and_then(Value::as_str)?;
    let bytes = blobs.get(name)?;
    String::from_utf8(bytes).ok()
}

/// The bytes a cited digest names, re-hashed against the digest: a blob's
/// name is its content's SHA-256, so a swap or an edit shows here.
fn image(blobs: &DirBlobSource, d: Digest) -> Result<Vec<u8>, String> {
    let bytes = blobs
        .get(&d.to_string())
        .ok_or_else(|| format!("blob {d} is missing"))?;
    if sha256(&bytes) != d {
        return Err(format!("blob {d} does not hash to its digest"));
    }
    Ok(bytes)
}

/// One file's status line and, when the journal's images are intact, its
/// whole-session diff.
fn render_file(cx: &Cx<'_>, workspace: &str, path: &str, c: &Change) {
    if let Some(issue) = &c.issue {
        note!(cx, "{path}: journal image problem: {issue}");
        return;
    }
    let Some((after, new)) = &c.after else {
        note!(cx, "{path}: no after-image in the journal");
        return;
    };
    let status = match workspace_path(path) {
        Err(e) => format!("path refused: {e}"),
        Ok(wp) => match workspace_digest(workspace, &wp) {
            Ok(d) if d == *after => "clean".to_owned(),
            Ok(_) => "changed outside the harness".to_owned(),
            Err(e) => e,
        },
    };
    note!(cx, "{path}: {status}");
    let empty: &[u8] = &[];
    let old = c.before.as_deref().unwrap_or(empty);
    let (Ok(old_s), Ok(new_s)) = (std::str::from_utf8(old), std::str::from_utf8(new)) else {
        note!(
            cx,
            "{path}: {} -> {} bytes, no text diff (not UTF-8)",
            old.len(),
            new.len()
        );
        return;
    };
    let text = diff::unified(old_s, new_s, diff::DEFAULT_CONTEXT, diff::DEFAULT_MAX_LINES);
    if text.is_empty() {
        return;
    }
    let left = if c.created {
        "/dev/null".to_owned()
    } else {
        format!("a/{path}")
    };
    note!(cx, "--- {left}");
    note!(cx, "+++ b/{path}");
    note!(cx, "{}", text.trim_end_matches('\n'));
}

/// The workspace file's digest, read without following symlinks: every
/// component is checked, like the edit tools' own resolution — a symlinked
/// component is a refusal, not a window.
fn workspace_digest(root: &str, wp: &harness_policy::WorkspacePath) -> Result<Digest, String> {
    let mut cur = PathBuf::from(root);
    let comps: Vec<&str> = wp.components().collect();
    let Some((last, init)) = comps.split_last() else {
        return Err("the journalled path is empty".to_owned());
    };
    for c in init {
        cur.push(c);
        let md = symlink_meta(&cur)?;
        if md.file_type().is_symlink() {
            return Err("a path component is a symlink".to_owned());
        }
        if !md.is_dir() {
            return Err("a path component is not a directory".to_owned());
        }
    }
    cur.push(last);
    let md = symlink_meta(&cur)?;
    if md.file_type().is_symlink() {
        return Err("the file is a symlink".to_owned());
    }
    if !md.is_file() {
        return Err("not a regular file".to_owned());
    }
    let bytes = std::fs::read(&cur).map_err(|e| format!("cannot read: {e}"))?;
    Ok(sha256(&bytes))
}

/// `symlink_metadata`, with a missing file its own word (the common
/// out-of-band case: the file was deleted).
fn symlink_meta(p: &Path) -> Result<std::fs::Metadata, String> {
    std::fs::symlink_metadata(p).map_err(|e| match e.kind() {
        ErrorKind::NotFound => "missing from the workspace".to_owned(),
        _ => format!("cannot read: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gate_outcome::GateOutcome;
    use harness_core::{Source, StopCause, Untrusted};
    use harness_journal::{Event, Header, Ident, JournalWriter, Trusted};
    use harness_testkit::Local;
    use std::cell::RefCell;

    const ONE: &[u8] = b"one\n";
    const TWO: &[u8] = b"one\ntwo\n";

    fn run_id() -> RunId {
        RunId::new(7, [0; 10])
    }

    /// A private temp dir with an empty `ws/` in it.
    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rh-p40-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("ws")).unwrap();
        d
    }

    /// A fresh attempt directory for the test run.
    fn attempt(base: &Path) -> PathBuf {
        let d = base.join("runs").join(run_id().as_str()).join("attempt-1");
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Review the attempt against `base/ws`, returning (exit, stderr).
    fn review_ws(base: &Path) -> (u8, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let cx = Cx {
            probe: &Local,
            gate_ok_file: None,
            out: RefCell::new(&mut out),
            err: RefCell::new(&mut err),
            approver: crate::ApproverSource::None,
            input: crate::InputSource::Given(&[]),
            backend: crate::BackendSource::BuiltIn,
            confinement: &harness_sandbox::SystemConfinement,
        };
        let code = review_live(&cx, &attempt(base), base.join("ws").to_str().unwrap());
        (code, String::from_utf8(err).unwrap())
    }

    /// The loop's own journal shape: a create of `a.txt` (`one\n`) then an
    /// edit to `one\ntwo\n` — images stored as blobs, digests cited.
    fn journal_create_and_edit(dir: &Path) {
        let mut w =
            JournalWriter::create(dir, run_id(), 1, Header::new(Ident::of("0.0.1").unwrap()))
                .unwrap();
        let ws = Source::Workspace("a.txt".into());
        let first = w
            .untrusted_stored(&Untrusted::new(ONE, ws.clone()))
            .unwrap()
            .sha256();
        let path = w
            .untrusted(&Untrusted::new("a.txt", Source::Model))
            .unwrap();
        w.append(
            1,
            Event::new(EventKind::EditApplied)
                .field("intent_seq", Trusted::U64(1))
                .field("path", Trusted::Untrusted(path))
                .field("after", Trusted::Digest(first))
                .field("after_blob", Trusted::Digest(first))
                .field("workspace_tree", Trusted::Digest(sha256(b"tree"))),
        )
        .unwrap();
        let before = w
            .untrusted_stored(&Untrusted::new(ONE, ws.clone()))
            .unwrap()
            .sha256();
        let second = w
            .untrusted_stored(&Untrusted::new(TWO, ws))
            .unwrap()
            .sha256();
        let path = w
            .untrusted(&Untrusted::new("a.txt", Source::Model))
            .unwrap();
        w.append(
            2,
            Event::new(EventKind::EditApplied)
                .field("intent_seq", Trusted::U64(2))
                .field("path", Trusted::Untrusted(path))
                .field("before", Trusted::Digest(before))
                .field("before_blob", Trusted::Digest(before))
                .field("after", Trusted::Digest(second))
                .field("after_blob", Trusted::Digest(second))
                .field("workspace_tree", Trusted::Digest(sha256(b"tree"))),
        )
        .unwrap();
        let _ = w.commit(3, &StopCause::Submitted, GateOutcome::Failed, None);
    }

    /// A journal with no edits at all.
    fn journal_empty(dir: &Path) {
        let w = JournalWriter::create(dir, run_id(), 1, Header::new(Ident::of("0.0.1").unwrap()))
            .unwrap();
        let _ = w.commit(1, &StopCause::Submitted, GateOutcome::Failed, None);
    }

    /// The digest of the session's last after-image.
    fn two_digest() -> Digest {
        sha256(TWO)
    }

    #[test]
    fn review_diff_matches_workspace_changes() {
        let base = tmp("clean");
        journal_create_and_edit(&attempt(&base));
        std::fs::write(base.join("ws").join("a.txt"), TWO).unwrap();
        let (code, err) = review_ws(&base);
        assert_eq!(code, exit::PASSED);
        assert!(err.contains("a.txt: clean"), "{err}");
        assert!(err.contains("--- /dev/null"), "{err}");
        assert!(err.contains("+++ b/a.txt"), "{err}");
        assert!(err.contains("+two"), "{err}");
        assert!(!err.contains("changed outside the harness"), "{err}");
    }

    #[test]
    fn review_flags_out_of_band_change() {
        let base = tmp("out-of-band");
        journal_create_and_edit(&attempt(&base));
        std::fs::write(base.join("ws").join("a.txt"), "edited by hand\n").unwrap();
        let (code, err) = review_ws(&base);
        assert_eq!(code, exit::PASSED);
        assert!(err.contains("a.txt: changed outside the harness"), "{err}");
        // The journal diff is still shown: what the session did is evidence.
        assert!(err.contains("+two"), "{err}");
    }

    #[test]
    fn review_detects_blob_tamper() {
        let base = tmp("tamper");
        let dir = attempt(&base);
        journal_create_and_edit(&dir);
        // Swap the last after-image's bytes under its content-addressed name.
        let blob = dir.join("blobs").join(two_digest().to_string());
        std::fs::write(&blob, b"rewritten\n").unwrap();
        std::fs::write(base.join("ws").join("a.txt"), TWO).unwrap();
        let (code, err) = review_ws(&base);
        assert_eq!(code, exit::PASSED);
        assert!(err.contains("does not hash to its digest"), "{err}");
        // No diff is rendered from tampered bytes.
        assert!(!err.contains("+++ b/a.txt"), "{err}");
        // The untouched blob is still checked and passes; the head still shows.
        assert!(err.contains("chain head "), "{err}");
    }

    #[test]
    fn review_includes_chain_head() {
        let base = tmp("head");
        let dir = attempt(&base);
        journal_create_and_edit(&dir);
        let expected = JournalReader::open(&dir).unwrap().head;
        std::fs::write(base.join("ws").join("a.txt"), TWO).unwrap();
        let (code, err) = review_ws(&base);
        assert_eq!(code, exit::PASSED);
        assert!(err.contains(&format!("chain head {expected}")), "{err}");
    }

    #[test]
    fn review_empty_session_message() {
        let base = tmp("empty");
        journal_empty(&attempt(&base));
        let (code, err) = review_ws(&base);
        assert_eq!(code, exit::PASSED);
        assert!(err.contains("no file changes in this session"), "{err}");
        assert!(err.contains("chain head "), "{err}");
    }
}
