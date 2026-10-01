//! The built-in edit tools through the real seam (H2b): policy authorises
//! (a user allow rule), the journal makes the intent durable, then
//! `EditTools` runs the call against the run's reads. What the model sees
//! is harness text with an error code; a verified edit carries its record.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use harness_core::{sha256, RunId};
use harness_journal::testing::{FaultFile, FaultPlan, MemBlobs};
use harness_journal::{Clock, Event, EventKind, Header, Ident, JournalWriter};
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, SemVer, ValidationContext};
use harness_policy::{Call, Session, SessionSpec, UserPolicy, WorkspaceDecl};
use harness_tools::builtin::code;
use harness_tools::{
    EditTools, InvokeCtx, ReadLog, ReadTools, RefusalKind, ToolProvider, ToolResult, ToolStatus,
};
use serde_json::{json, Value};

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

fn scratch(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("edit-tools-{name}"));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

struct Rig {
    w: JournalWriter<FaultFile, MemBlobs, Tick>,
    s: Session,
    t: EditTools,
    reads: ReadLog,
    step: u64,
}

impl Rig {
    fn new(ws: &Path) -> Self {
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
        let s = Session::plan(
            &SessionSpec {
                grants: vec![
                    "harness.fs.read".into(),
                    "harness.edit.replace".into(),
                    "harness.edit.write".into(),
                    "harness.edit.multi".into(),
                ],
                workspace: Some(WorkspaceDecl::default()),
                approver_present: false,
                personal_data_granted: false,
                conformed: false,
                exec_programs: Vec::new(),
                read_window: None,
            },
            &reg,
            &UserPolicy::new(
                &[],
                &[],
                &[
                    "harness.edit.replace",
                    "harness.edit.write",
                    "harness.edit.multi",
                ],
            )
            .unwrap(),
        )
        .unwrap();
        let w = JournalWriter::start(
            FaultFile::new(FaultPlan::default()),
            MemBlobs::default(),
            Tick(Cell::new(0)),
            RunId::new(1, [0; 10]),
            1,
            Header::new(Ident::of("0.0.1").unwrap()),
        )
        .unwrap();
        Self {
            w,
            s,
            t: EditTools::new(ws).unwrap(),
            reads: ReadLog::default(),
            step: 0,
        }
    }

    fn call_at(&mut self, cap: &str, args: Value, deadline: Instant) -> ToolResult {
        self.step += 1;
        let a = self
            .s
            .authorize(Call {
                capability: cap.into(),
                args,
            })
            .expect("policy allows it");
        let j = self
            .w
            .append_intent(self.step, Event::new(EventKind::ToolStarted), a)
            .unwrap();
        self.t
            .invoke(
                j,
                &InvokeCtx {
                    step: self.step,
                    deadline,
                    reads: &self.reads,
                },
            )
            .unwrap()
    }

    fn call(&mut self, cap: &str, args: Value) -> ToolResult {
        self.call_at(cap, args, Instant::now() + Duration::from_secs(30))
    }

    /// What the run does after a successful `fs.read`.
    fn read(&mut self, ws: &Path, p: &str) {
        self.reads.record(p, sha256(&fs::read(ws.join(p)).unwrap()));
    }
}

fn text(r: &ToolResult) -> String {
    String::from_utf8(r.output.inspect("test").clone()).unwrap()
}

fn is_error(r: &ToolResult, c: u16) -> bool {
    r.status == ToolStatus::Error { code: c } && r.edit.is_none()
}

#[test]
fn a_replace_reports_lines_and_digests_and_carries_its_record() {
    let ws = scratch("replace");
    fs::write(ws.join("a.rs"), "one\nconst X: u8 = 1;\nthree\n").unwrap();
    let mut rig = Rig::new(&ws);
    rig.read(&ws, "a.rs");
    let r = rig.call(
        "harness.edit.replace",
        json!({"path": "a.rs", "old": "= 1;", "new": "= 2;"}),
    );
    assert_eq!(r.status, ToolStatus::Ok, "{}", text(&r));
    let before = sha256(b"one\nconst X: u8 = 1;\nthree\n");
    let after = sha256(b"one\nconst X: u8 = 2;\nthree\n");
    let e = r.edit.as_ref().unwrap();
    assert_eq!(
        (e.path.as_str(), e.before, e.after),
        ("a.rs", Some(before), after)
    );
    let t = text(&r);
    assert!(
        t.starts_with("edited a.rs: replaced 1 match at line 2; the file now has 3 lines;"),
        "{t}"
    );
    assert!(
        t.contains(&after.to_string()) && t.contains(&before.to_string()),
        "{t}"
    );
    // The output is the harness's report: never the file's text.
    assert!(!t.contains("three"), "{t}");
}

#[test]
fn a_write_creates_and_rewrites() {
    let ws = scratch("write");
    let mut rig = Rig::new(&ws);
    let r = rig.call(
        "harness.edit.write",
        json!({"path": "n.md", "content": "a\nb\n"}),
    );
    assert_eq!(r.status, ToolStatus::Ok, "{}", text(&r));
    assert_eq!(r.edit.as_ref().unwrap().before, None);
    assert!(
        text(&r).starts_with("created n.md: 2 lines; sha256 "),
        "{}",
        text(&r)
    );
    rig.reads.record("n.md", sha256(b"a\nb\n"));
    let r = rig.call(
        "harness.edit.write",
        json!({"path": "n.md", "content": "c\n"}),
    );
    assert_eq!(r.status, ToolStatus::Ok, "{}", text(&r));
    assert!(
        text(&r).starts_with("rewrote n.md: 1 line; sha256 "),
        "{}",
        text(&r)
    );
    assert_eq!(fs::read(ws.join("n.md")).unwrap(), b"c\n");
}

#[test]
fn every_refusal_has_its_code_and_harness_words_and_changes_nothing() {
    let ws = scratch("refusals");
    let body = "x = 1\nx = 1\n";
    fs::write(ws.join("f.txt"), body).unwrap();
    fs::write(ws.join("crlf.txt"), "a\r\nb\r\n").unwrap();
    fs::write(ws.join("big.txt"), "l\n".repeat(401)).unwrap();
    fs::create_dir(ws.join("d")).unwrap();
    let mut rig = Rig::new(&ws);
    // Never read.
    let r = rig.call(
        "harness.edit.replace",
        json!({"path": "f.txt", "old": "x", "new": "y"}),
    );
    assert!(is_error(&r, code::STALE_READ), "{}", text(&r));
    assert!(
        text(&r)
            .starts_with("error: file not read in this run; read it first: call harness.fs.read"),
        "{}",
        text(&r)
    );
    rig.read(&ws, "f.txt");
    rig.read(&ws, "crlf.txt");
    rig.read(&ws, "big.txt");
    let cases: Vec<(&str, Value, u16, &str)> = vec![
        (
            "harness.edit.replace",
            json!({"path": "f.txt", "old": "x = 1", "new": "x = 2"}),
            code::MATCH_COUNT,
            "old matches 2 times (line(s) 1, 2), not 1",
        ),
        (
            "harness.edit.replace",
            json!({"path": "f.txt", "old": "nowhere", "new": "y"}),
            code::NO_MATCH,
            "old was not found in the file",
        ),
        (
            "harness.edit.replace",
            json!({"path": "crlf.txt", "old": "a\nb", "new": "c"}),
            code::NO_MATCH,
            "the file uses CRLF line endings and old uses LF",
        ),
        (
            "harness.edit.replace",
            json!({"path": "f.txt", "old": "x", "new": "x"}),
            code::NO_OP,
            "the edit would not change the file",
        ),
        (
            "harness.edit.replace",
            json!({"path": "f.txt", "old": "", "new": "y"}),
            code::BAD_ARGS,
            "old is empty",
        ),
        (
            "harness.edit.write",
            json!({"path": "big.txt", "content": "short\n"}),
            code::LINE_CAP,
            "the file has 401 lines; a whole-file rewrite is limited to 400",
        ),
        (
            "harness.edit.write",
            json!({"path": "d", "content": "x"}),
            code::NOT_A_FILE,
            "not a regular file",
        ),
        (
            "harness.edit.replace",
            json!({"path": "nodir/x.txt", "old": "x", "new": "y"}),
            code::NOT_FOUND,
            "no such file or directory: find the path with harness.fs.glob",
        ),
    ];
    for (cap, args, c, words) in cases {
        let r = rig.call(cap, args.clone());
        assert!(is_error(&r, c), "{args}: {:?} {}", r.status, text(&r));
        assert!(text(&r).contains(words), "{args}: {}", text(&r));
    }
    assert_eq!(fs::read_to_string(ws.join("f.txt")).unwrap(), body);
    // Changed since read.
    fs::write(ws.join("f.txt"), "x = 3\n").unwrap();
    let r = rig.call(
        "harness.edit.replace",
        json!({"path": "f.txt", "old": "x = 3", "new": "x = 4"}),
    );
    assert!(is_error(&r, code::STALE_READ), "{}", text(&r));
    assert!(
        text(&r).starts_with("error: file changed since read; re-read first: call harness.fs.read"),
        "{}",
        text(&r)
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_is_never_followed_by_an_edit() {
    let ws = scratch("symlink");
    let outside = scratch("symlink-outside");
    fs::write(outside.join("t.txt"), "keep\n").unwrap();
    std::os::unix::fs::symlink(outside.join("t.txt"), ws.join("l.txt")).unwrap();
    let mut rig = Rig::new(&ws);
    rig.reads.record("l.txt", sha256(b"keep\n"));
    for (cap, args) in [
        (
            "harness.edit.replace",
            json!({"path": "l.txt", "old": "keep", "new": "gone"}),
        ),
        (
            "harness.edit.write",
            json!({"path": "l.txt", "content": "gone\n"}),
        ),
    ] {
        let r = rig.call(cap, args);
        assert!(is_error(&r, code::SYMLINK), "{}", text(&r));
    }
    assert_eq!(fs::read(outside.join("t.txt")).unwrap(), b"keep\n");
}

#[test]
fn the_built_in_providers_split_the_harness_namespace_by_verb() {
    let ws = scratch("serves");
    let e = EditTools::new(&ws).unwrap();
    let r = ReadTools::new(&ws).unwrap();
    for cap in [
        "harness.edit.replace",
        "harness.edit.write",
        "harness.edit.multi",
    ] {
        assert!(e.serves(cap) && !r.serves(cap), "{cap}");
    }
    for cap in [
        "harness.fs.read",
        "harness.fs.search",
        "harness.fs.list",
        "harness.fs.glob",
    ] {
        assert!(r.serves(cap) && !e.serves(cap), "{cap}");
    }
    for cap in [
        "harness.task.submit",
        "harness.task.todo",
        "harness.exec.run",
        "other.edit.replace",
    ] {
        assert!(!r.serves(cap) && !e.serves(cap), "{cap}");
    }
}

#[test]
fn a_passed_deadline_refuses_before_touching_the_file() {
    let ws = scratch("deadline");
    fs::write(ws.join("a.txt"), "a\n").unwrap();
    let mut rig = Rig::new(&ws);
    rig.read(&ws, "a.txt");
    let r = rig.call_at(
        "harness.edit.replace",
        json!({"path": "a.txt", "old": "a", "new": "b"}),
        Instant::now(),
    );
    assert_eq!(
        r.status,
        ToolStatus::Refused {
            reason: RefusalKind::DeadlinePassed
        }
    );
    assert_eq!(fs::read(ws.join("a.txt")).unwrap(), b"a\n");
}

// ---- H2e: several edits in one file, all or none -------------------------------

const MULTI_SRC: &str = "/// The most upload attempts.\npub const MAX_TRIES: u32 = 3;\n\npub fn tries() -> u32 {\n    MAX_TRIES\n}\n";

// The dev task this tool exists for: rename a constant, and update its doc
// and its one use, in one call; one verified edit, one record.
#[test]
fn h2e_multi_applies_every_edit_in_order_as_one_verified_edit() {
    let ws = scratch("multi");
    fs::write(ws.join("lim.rs"), MULTI_SRC).unwrap();
    let mut rig = Rig::new(&ws);
    rig.read(&ws, "lim.rs");
    let r = rig.call(
        "harness.edit.multi",
        json!({"path": "lim.rs", "edits": [
            {"old": "/// The most upload attempts.", "new": "/// The most upload attempts before giving up."},
            {"old": "pub const MAX_TRIES", "new": "pub const UPLOAD_ATTEMPTS"},
            {"old": "    MAX_TRIES\n", "new": "    UPLOAD_ATTEMPTS\n"}
        ]}),
    );
    assert_eq!(r.status, ToolStatus::Ok, "{}", text(&r));
    let want = "/// The most upload attempts before giving up.\npub const UPLOAD_ATTEMPTS: u32 = 3;\n\npub fn tries() -> u32 {\n    UPLOAD_ATTEMPTS\n}\n";
    assert_eq!(fs::read_to_string(ws.join("lim.rs")).unwrap(), want);
    let e = r.edit.as_ref().unwrap();
    assert_eq!(
        (e.path.as_str(), e.before, e.after),
        (
            "lim.rs",
            Some(sha256(MULTI_SRC.as_bytes())),
            sha256(want.as_bytes())
        )
    );
    let t = text(&r);
    assert!(
        t.starts_with("edited lim.rs: applied 3 edits in order, at lines 1, 2, 5 (each line as the edits before it left the file); the file now has 6 lines;"),
        "{t}"
    );
    assert!(!t.contains("UPLOAD"), "never the file's text: {t}");
    // A later edit may match text an earlier one wrote.
    rig.reads.record("lim.rs", sha256(want.as_bytes()));
    let r = rig.call(
        "harness.edit.multi",
        json!({"path": "lim.rs", "edits": [
            {"old": "= 3;", "new": "= 5; // TUNE"},
            {"old": "// TUNE", "new": "// tuned in H2e"}
        ]}),
    );
    assert_eq!(r.status, ToolStatus::Ok, "{}", text(&r));
    assert!(fs::read_to_string(ws.join("lim.rs"))
        .unwrap()
        .contains("pub const UPLOAD_ATTEMPTS: u32 = 5; // tuned in H2e\n"));
}

#[test]
fn h2e_multi_is_all_or_nothing_and_names_the_failing_edit() {
    let ws = scratch("multi-refusals");
    fs::write(ws.join("lim.rs"), MULTI_SRC).unwrap();
    fs::write(ws.join("never.rs"), "x\n").unwrap();
    let mut rig = Rig::new(&ws);
    rig.read(&ws, "lim.rs");
    let ok = json!({"old": "MAX_TRIES: u32 = 3", "new": "MAX_TRIES: u32 = 4"});
    let cases: Vec<(Value, u16, &str)> = vec![
        (
            json!([ok, {"old": "nowhere", "new": "y"}, {"old": "fn", "new": "fn"}]),
            code::NO_OP,
            "edit 3 of 3",
        ),
        (
            json!([ok, {"old": "nowhere", "new": "y"}]),
            code::NO_MATCH,
            "edit 2 of 2 (checked against the file as the edits before it left it): old was not found in the file",
        ),
        (
            json!([ok, {"old": "MAX_TRIES", "new": "M"}]),
            code::MATCH_COUNT,
            "edit 2 of 2 (checked against the file as the edits before it left it): old matches 2 times (line(s) 2, 5), not 1",
        ),
        (
            // Edit 1's new text makes edit 2's old match twice.
            json!([{"old": "tries()", "new": "tries() /* MAX_TRIES */"}, {"old": "MAX_TRIES:", "new": "X:"}, {"old": "MAX_TRIES", "new": "Y"}]),
            code::MATCH_COUNT,
            "edit 3 of 3",
        ),
        (
            json!([{"old": "", "new": "y"}, ok]),
            code::BAD_ARGS,
            "edit 1 of 2: old is empty",
        ),
        (json!([]), code::BAD_ARGS, "edits has 0 item(s); one call makes 1 to 20 edits"),
        (
            json!((0..21).map(|i| json!({"old": format!("a{i}"), "new": "b"})).collect::<Vec<_>>()),
            code::BAD_ARGS,
            "edits has 21 item(s)",
        ),
        (
            // Two edits that undo each other change nothing.
            json!([{"old": "= 3;", "new": "= 4;"}, {"old": "= 4;", "new": "= 3;"}]),
            code::NO_OP,
            "the edit would not change the file",
        ),
    ];
    for (edits, c, words) in cases {
        let r = rig.call(
            "harness.edit.multi",
            json!({"path": "lim.rs", "edits": edits.clone()}),
        );
        assert!(is_error(&r, c), "{edits}: {:?} {}", r.status, text(&r));
        assert!(text(&r).contains(words), "{edits}: {}", text(&r));
        // A failing edit is named, and the model is told nothing changed.
        if words.starts_with("edit ") {
            assert!(text(&r).ends_with("; nothing was written"), "{}", text(&r));
        }
        // Nothing was written, whatever failed.
        assert_eq!(fs::read_to_string(ws.join("lim.rs")).unwrap(), MULTI_SRC);
    }
    // The stale-read anchor holds as for every edit.
    let r = rig.call(
        "harness.edit.multi",
        json!({"path": "never.rs", "edits": [{"old": "x", "new": "y"}]}),
    );
    assert!(is_error(&r, code::STALE_READ), "{}", text(&r));
    fs::write(ws.join("lim.rs"), "changed\n").unwrap();
    let r = rig.call(
        "harness.edit.multi",
        json!({"path": "lim.rs", "edits": [{"old": "changed", "new": "x"}]}),
    );
    assert!(is_error(&r, code::STALE_READ), "{}", text(&r));
    assert_eq!(fs::read_to_string(ws.join("lim.rs")).unwrap(), "changed\n");
}

#[test]
fn h2e_multi_keeps_crlf_line_endings() {
    let ws = scratch("multi-crlf");
    fs::write(ws.join("w.txt"), "a\r\nb\r\nc\r\n").unwrap();
    let mut rig = Rig::new(&ws);
    rig.read(&ws, "w.txt");
    let r = rig.call(
        "harness.edit.multi",
        json!({"path": "w.txt", "edits": [{"old": "a", "new": "a1\na2"}, {"old": "c", "new": "c1"}]}),
    );
    assert_eq!(r.status, ToolStatus::Ok, "{}", text(&r));
    assert_eq!(
        fs::read(ws.join("w.txt")).unwrap(),
        b"a1\r\na2\r\nb\r\nc1\r\n"
    );
}

// An edit whose result the harness could not read back (over the 4 MiB
// edit cap) is refused before anything is written, for a replace and for
// several edits; before H2e it was written, failed its verification, and
// stopped the run.
#[test]
fn h2e_an_edit_past_the_edit_cap_is_refused_before_writing() {
    let ws = scratch("edit-cap");
    let mut body: String = (0..100).map(|i| format!("marker {i:03} X\n")).collect();
    body.push_str(&"y".repeat(3 * 1024 * 1024));
    body.push('\n');
    fs::write(ws.join("big.txt"), &body).unwrap();
    let mut rig = Rig::new(&ws);
    rig.read(&ws, "big.txt");
    let wide = "z".repeat(60_000);
    let r = rig.call(
        "harness.edit.replace",
        json!({"path": "big.txt", "old": " X\n", "new": format!(" {wide}\n"), "count": 100}),
    );
    assert!(is_error(&r, code::TOO_LARGE), "{}", text(&r));
    let edits: Vec<Value> = (0..20)
        .map(|i| json!({"old": format!("marker {i:03} X"), "new": format!("marker {wide}")}))
        .collect();
    let r = rig.call(
        "harness.edit.multi",
        json!({"path": "big.txt", "edits": edits}),
    );
    assert!(is_error(&r, code::TOO_LARGE), "{}", text(&r));
    assert_eq!(fs::read_to_string(ws.join("big.txt")).unwrap(), body);
}

#[cfg(unix)]
#[test]
fn h2e_multi_never_follows_a_symlink() {
    let ws = scratch("multi-symlink");
    let outside = scratch("multi-symlink-outside");
    fs::write(outside.join("t.txt"), "keep\n").unwrap();
    std::os::unix::fs::symlink(outside.join("t.txt"), ws.join("l.txt")).unwrap();
    let mut rig = Rig::new(&ws);
    rig.reads.record("l.txt", sha256(b"keep\n"));
    let r = rig.call(
        "harness.edit.multi",
        json!({"path": "l.txt", "edits": [{"old": "keep", "new": "gone"}]}),
    );
    assert!(is_error(&r, code::SYMLINK), "{}", text(&r));
    assert_eq!(fs::read(outside.join("t.txt")).unwrap(), b"keep\n");
}

// H2e: an `old` that matches nowhere says where it stops matching, in line
// numbers (a local model sent the same `old`, one doc-comment line short,
// three times), for replace and for an edit of a multi-edit.
#[test]
fn h2e_a_missed_old_says_where_it_stops_matching() {
    let ws = scratch("where-it-stops");
    fs::write(ws.join("lim.rs"), MULTI_SRC).unwrap();
    let mut rig = Rig::new(&ws);
    rig.read(&ws, "lim.rs");
    // Lines 2-3 of the file, then a line the file does not have next.
    let old = "pub const MAX_TRIES: u32 = 3;\n\n/// Tries.\npub fn tries() -> u32 {";
    let r = rig.call(
        "harness.edit.replace",
        json!({"path": "lim.rs", "old": old, "new": "x"}),
    );
    assert!(is_error(&r, code::NO_MATCH), "{}", text(&r));
    let t = text(&r);
    assert!(
        t.contains("old's first 2 line(s) match the file from line 2, and old's line 3 differs from the file's line 4: read the file there and copy old from it"),
        "{t}"
    );
    assert!(!t.contains("Tries") && !t.contains("MAX_TRIES"), "{t}");
    let r = rig.call(
        "harness.edit.multi",
        json!({"path": "lim.rs", "edits": [
            {"old": "MAX_TRIES: u32 = 3", "new": "MAX_TRIES: u32 = 4"},
            {"old": old, "new": "x"}
        ]}),
    );
    assert!(is_error(&r, code::NO_MATCH), "{}", text(&r));
    let t = text(&r);
    // Checked against the text as edit 1 left it: its first line differs
    // now, so there is no run of matching lines to report.
    assert!(t.contains("edit 2 of 2"), "{t}");
    assert!(!t.contains("line(s) match the file from line"), "{t}");
    let old2 = "pub fn tries() -> u32 {\n    MAX_TRIES\n}\n\npub fn more() {}";
    let r = rig.call(
        "harness.edit.multi",
        json!({"path": "lim.rs", "edits": [
            {"old": "MAX_TRIES: u32 = 3", "new": "MAX_TRIES: u32 = 4"},
            {"old": old2, "new": "x"}
        ]}),
    );
    let t = text(&r);
    assert!(
        t.contains("edit 2 of 2 (checked against the file as the edits before it left it): old was not found in the file; it must match exactly, whitespace and line endings included; old's first 3 line(s) match the file from line 4, and the file ends before old's line 4"),
        "{t}"
    );
    // Nothing was written.
    assert_eq!(fs::read_to_string(ws.join("lim.rs")).unwrap(), MULTI_SRC);
}

// H2f: an edit error says what to do next, in static harness words: the
// tool to call or the step to take, never the model's text.
#[test]
fn h2f_edit_errors_name_the_next_action() {
    let ws = scratch("next-action");
    fs::write(ws.join("f.txt"), "one\ntwo\n").unwrap();
    fs::write(ws.join("bin.dat"), [0xff, 0xfe, 0x00]).unwrap();
    fs::create_dir(ws.join("d")).unwrap();
    let mut rig = Rig::new(&ws);
    let secret = "SECRET-MODEL-TEXT";
    rig.read(&ws, "f.txt");
    rig.read(&ws, "bin.dat");
    let cases: Vec<(&str, Value, &str)> = vec![
        (
            "harness.edit.replace",
            json!({"path": "f.txt", "old": secret, "new": "y"}),
            "read the file with harness.fs.read at the place you mean and copy old from that text",
        ),
        (
            "harness.edit.replace",
            json!({"path": "f.txt", "old": "one", "new": "one"}),
            "change new, or submit if the file is already right",
        ),
        (
            "harness.edit.replace",
            json!({"path": "f.txt", "old": "", "new": secret}),
            "give the exact text to replace",
        ),
        (
            "harness.edit.replace",
            json!({"path": "d", "old": "a", "new": "b"}),
            "name a file, not a directory",
        ),
        (
            "harness.edit.replace",
            json!({"path": "bin.dat", "old": "a", "new": "b"}),
            "leave the file alone",
        ),
        (
            "harness.edit.replace",
            json!({"path": "missing.txt", "old": "a", "new": "b"}),
            "to create a new file use harness.edit.write",
        ),
        (
            "harness.edit.multi",
            json!({"path": "f.txt", "edits": []}),
            "split the edits into calls of at most 20",
        ),
    ];
    for (cap, args, next) in cases {
        let r = rig.call(cap, args.clone());
        assert!(text(&r).contains(next), "{args}: {}", text(&r));
        assert!(!text(&r).contains(secret), "no model text: {}", text(&r));
    }
    // A file never read, and one changed since it was read.
    fs::write(ws.join("g.txt"), "g\n").unwrap();
    let r = rig.call(
        "harness.edit.replace",
        json!({"path": "g.txt", "old": "g", "new": "h"}),
    );
    assert!(text(&r).contains("call harness.fs.read on this path"));
}

// H2f: edit.write makes the directories a new file needs, inside the
// workspace, with no link followed; a refused write makes none.
#[test]
fn h2f_a_write_creates_missing_directories_and_says_which() {
    let ws = scratch("write-dirs");
    fs::create_dir(ws.join("src")).unwrap();
    let mut rig = Rig::new(&ws);
    let r = rig.call(
        "harness.edit.write",
        json!({"path": "src/a/b/new.rs", "content": "fn main() {}\n"}),
    );
    assert_eq!(r.status, ToolStatus::Ok, "{}", text(&r));
    assert!(
        text(&r).contains("created src/a/b/new.rs: 1 line;")
            && text(&r).contains("; created directories src/a, src/a/b"),
        "{}",
        text(&r)
    );
    assert_eq!(
        fs::read_to_string(ws.join("src/a/b/new.rs")).unwrap(),
        "fn main() {}\n"
    );
    let rec = r.edit.expect("one edit record");
    assert_eq!(rec.before, None);
    assert_eq!(rec.after, sha256(b"fn main() {}\n"));
    // One directory made: singular; an existing directory is not "made".
    let r = rig.call(
        "harness.edit.write",
        json!({"path": "src/a/c/other.rs", "content": "x\n"}),
    );
    assert!(
        text(&r).contains("; created directory src/a/c\n"),
        "{}",
        text(&r)
    );
    let r = rig.call(
        "harness.edit.write",
        json!({"path": "src/a/plain.rs", "content": "x\n"}),
    );
    assert!(!text(&r).contains("created director"), "{}", text(&r));
    // No leftover temp file anywhere it wrote.
    for d in ["src", "src/a", "src/a/b", "src/a/c"] {
        for e in fs::read_dir(ws.join(d)).unwrap() {
            let n = e.unwrap().file_name().into_string().unwrap();
            assert!(!n.ends_with(".tmp"), "{d}/{n}");
        }
    }
}

#[test]
fn h2f_a_refused_write_creates_no_directory() {
    let ws = scratch("write-dirs-refused");
    fs::write(ws.join("file.txt"), "not a directory\n").unwrap();
    let mut rig = Rig::new(&ws);
    // A component that is a file.
    let r = rig.call(
        "harness.edit.write",
        json!({"path": "file.txt/sub/x.txt", "content": "x"}),
    );
    assert!(matches!(r.status, ToolStatus::Error { .. }), "{}", text(&r));
    assert!(!ws.join("file.txt/sub").exists());
    // Too many new directories (9 > 8): none is made.
    let deep = "d1/d2/d3/d4/d5/d6/d7/d8/d9/x.txt";
    let r = rig.call("harness.edit.write", json!({"path": deep, "content": "x"}));
    assert!(is_error(&r, code::BAD_ARGS), "{}", text(&r));
    assert!(text(&r).contains("nothing was created"), "{}", text(&r));
    assert!(!ws.join("d1").exists());
    // Eight are made.
    let ok8 = "e1/e2/e3/e4/e5/e6/e7/e8/x.txt";
    let r = rig.call("harness.edit.write", json!({"path": ok8, "content": "x"}));
    assert_eq!(r.status, ToolStatus::Ok, "{}", text(&r));
}

// The escape attempts are still refused, and nothing is made outside (or
// through the link).
#[cfg(unix)]
#[test]
fn h2f_a_write_never_creates_directories_through_a_symlink() {
    let ws = scratch("write-dirs-symlink");
    let outside = scratch("write-dirs-outside");
    std::os::unix::fs::symlink(&outside, ws.join("link")).unwrap();
    fs::create_dir(ws.join("real")).unwrap();
    std::os::unix::fs::symlink(&outside, ws.join("real/inner")).unwrap();
    let mut rig = Rig::new(&ws);
    for path in ["link/new/x.txt", "link/x.txt", "real/inner/new/x.txt"] {
        let r = rig.call(
            "harness.edit.write",
            json!({"path": path, "content": "escaped"}),
        );
        assert!(is_error(&r, code::SYMLINK), "{path}: {}", text(&r));
    }
    assert_eq!(
        fs::read_dir(&outside).unwrap().count(),
        0,
        "nothing was made through a link"
    );
    // A dangling link in the way is a link too (never created through).
    std::os::unix::fs::symlink(outside.join("missing"), ws.join("dangling")).unwrap();
    let r = rig.call(
        "harness.edit.write",
        json!({"path": "dangling/x.txt", "content": "escaped"}),
    );
    assert!(is_error(&r, code::SYMLINK), "{}", text(&r));
    assert!(!outside.join("missing").exists());
    // Lexical escapes never reach the tool: policy refuses them first.
    // (`..` and absolute paths are the path rule's, tested with it.)
}
