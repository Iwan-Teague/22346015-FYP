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
                ],
                workspace: Some(WorkspaceDecl::default()),
                approver_present: false,
                personal_data_granted: false,
                conformed: false,
                exec_programs: Vec::new(),
            },
            &reg,
            &UserPolicy::new(&[], &[], &["harness.edit.replace", "harness.edit.write"]).unwrap(),
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
    assert_eq!(text(&r), "error: file not read in this run; read it first");
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
            "harness.edit.write",
            json!({"path": "nodir/x.txt", "content": "x"}),
            code::NOT_FOUND,
            "a new file's directory must already exist",
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
    assert_eq!(text(&r), "error: file changed since read; re-read first");
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
    for cap in ["harness.edit.replace", "harness.edit.write"] {
        assert!(e.serves(cap) && !r.serves(cap), "{cap}");
    }
    for cap in ["harness.fs.read", "harness.fs.search", "harness.fs.list"] {
        assert!(r.serves(cap) && !e.serves(cap), "{cap}");
    }
    for cap in [
        "harness.task.submit",
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
