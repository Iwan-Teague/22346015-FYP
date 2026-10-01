//! The built-in read tools through the real seam: policy authorises, the
//! journal makes the intent durable, then `ReadTools` runs the call. INV-30
//! (confinement) is tested here for the in-process half: a symlink at any
//! component is refused, never followed.

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
use harness_tools::builtin::{code, workspace_facts, RESULT_MAX_BYTES};
use harness_tools::{InvokeCtx, ReadTools, RefusalKind, ToolProvider, ToolResult, ToolStatus};
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

type W = JournalWriter<FaultFile, MemBlobs, Tick>;

fn scratch(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("read-tools-{name}"));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

struct Rig {
    w: W,
    s: Session,
    t: ReadTools,
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
                    "harness.fs.search".into(),
                    "harness.fs.list".into(),
                    "harness.task.submit".into(),
                ],
                workspace: Some(WorkspaceDecl::default()),
                approver_present: false,
                personal_data_granted: false,
            },
            &reg,
            &UserPolicy::default(),
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
            t: ReadTools::new(ws).unwrap(),
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
                },
            )
            .unwrap()
    }

    fn call(&mut self, cap: &str, args: Value) -> ToolResult {
        self.call_at(cap, args, Instant::now() + Duration::from_secs(30))
    }
}

fn text(r: &ToolResult) -> String {
    String::from_utf8(r.output.inspect("test").clone()).unwrap()
}

#[test]
fn read_returns_a_numbered_window_with_the_file_digest() {
    let ws = scratch("read");
    let body: String = (1..=250).map(|i| format!("line {i}\n")).collect();
    fs::write(ws.join("a.txt"), &body).unwrap();
    let mut r = Rig::new(&ws);

    let out = r.call("harness.fs.read", json!({"path": "a.txt"}));
    assert_eq!(out.status, ToolStatus::Ok);
    let t = text(&out);
    let head = format!(
        "a.txt: lines 1-100 of 250; sha256 {}\n",
        sha256(body.as_bytes())
    );
    assert!(t.starts_with(&head), "{t}");
    assert!(t.contains("1\tline 1\n") && t.contains("100\tline 100\n"));
    assert!(!t.contains("line 101"));
    assert_eq!(out.digest, sha256(t.as_bytes()));

    let t = text(&r.call(
        "harness.fs.read",
        json!({"path": "a.txt", "start": 240, "lines": 20}),
    ));
    assert!(t.starts_with("a.txt: lines 240-250 of 250;"), "{t}");

    let out = r.call("harness.fs.read", json!({"path": "a.txt", "start": 251}));
    assert_eq!(out.status, ToolStatus::Error { code: code::WINDOW });
}

#[test]
fn read_errors_are_typed_statuses() {
    let ws = scratch("read-errors");
    fs::create_dir(ws.join("dir")).unwrap();
    fs::write(ws.join("bin"), [0xff, 0xfe, 0x00]).unwrap();
    fs::write(ws.join("empty"), "").unwrap();
    let mut r = Rig::new(&ws);
    for (path, want) in [
        ("missing.txt", code::NOT_FOUND),
        ("dir", code::NOT_A_FILE),
        ("bin", code::NOT_TEXT),
    ] {
        let out = r.call("harness.fs.read", json!({ "path": path }));
        assert_eq!(out.status, ToolStatus::Error { code: want }, "{path}");
        assert!(text(&out).starts_with("error: "));
    }
    let t = text(&r.call("harness.fs.read", json!({"path": "empty"})));
    assert!(t.starts_with("empty: empty file; sha256 "), "{t}");
}

#[test]
fn results_are_cut_at_the_cap_and_digested_whole() {
    let ws = scratch("cap");
    let line = "x".repeat(1000);
    let body: String = (0..100).map(|_| format!("{line}\n")).collect();
    fs::write(ws.join("big.txt"), &body).unwrap();
    let mut r = Rig::new(&ws);
    let out = r.call("harness.fs.read", json!({"path": "big.txt"}));
    assert!(out.truncated);
    let shown = out.output.inspect("test").len();
    assert_eq!(shown, RESULT_MAX_BYTES);
    assert_ne!(out.digest, sha256(out.output.inspect("test")));
}

#[test]
fn search_is_literal_grouped_per_file_and_capped_at_fifty() {
    let ws = scratch("search");
    fs::create_dir(ws.join("src")).unwrap();
    fs::write(ws.join("src/a.rs"), "fn main() {}\nlet x = a.*b;\n").unwrap();
    fs::write(ws.join("src/b.rs"), "no match here\nfn main() {}\n").unwrap();
    fs::write(ws.join("bin"), [0xff, b'f', b'n']).unwrap();
    let many: String = (0..80).map(|i| format!("needle {i}\n")).collect();
    fs::write(ws.join("many.txt"), many).unwrap();
    let mut r = Rig::new(&ws);

    let t = text(&r.call("harness.fs.search", json!({"pattern": "fn main"})));
    assert!(t.starts_with("2 hit(s) in 2 file(s)"), "{t}");
    assert!(
        t.contains("src/a.rs (1 hit(s))\n  1: fn main() {}\n"),
        "{t}"
    );
    assert!(
        t.contains("src/b.rs (1 hit(s))\n  2: fn main() {}\n"),
        "{t}"
    );
    assert!(t.contains("1 file(s) not searched"), "{t}");

    // A regex metacharacter is a literal.
    let t = text(&r.call("harness.fs.search", json!({"pattern": "a.*b"})));
    assert!(t.starts_with("1 hit(s)"), "{t}");

    let t = text(&r.call(
        "harness.fs.search",
        json!({"pattern": "needle", "path": "many.txt"}),
    ));
    assert!(t.starts_with("50 hit(s) in 1 file(s) for a literal match; more hits not shown"));
}

#[test]
fn list_is_sorted_bounded_in_depth_and_count() {
    let ws = scratch("list");
    fs::create_dir_all(ws.join("a/b/c/d/e")).unwrap();
    fs::write(ws.join("a/f.txt"), "12345").unwrap();
    let mut r = Rig::new(&ws);
    let t = text(&r.call("harness.fs.list", json!({"path": ".", "depth": 2})));
    assert_eq!(
        t,
        "3 entr(y/ies) under .\nd a/\nd a/b/\nf a/f.txt 5 bytes\n"
    );
    let t = text(&r.call("harness.fs.list", json!({"path": "a", "depth": 4})));
    assert!(t.contains("d a/b/c/d/e/"), "{t}");
    let t = text(&r.call("harness.fs.list", json!({"path": ".", "depth": 4})));
    assert!(t.contains("d a/b/c/d/") && !t.contains("a/b/c/d/e"), "{t}");

    let many = scratch("list-many");
    for i in 0..510 {
        fs::write(many.join(format!("f{i:03}")), "").unwrap();
    }
    let mut r = Rig::new(&many);
    let t = text(&r.call("harness.fs.list", json!({"path": "."})));
    assert!(
        t.starts_with("500 entr(y/ies) under .; more not shown"),
        "{}",
        &t[..80]
    );
}

#[test]
fn a_deadline_that_already_passed_refuses_before_running() {
    let ws = scratch("deadline");
    let mut r = Rig::new(&ws);
    let out = r.call_at("harness.fs.list", json!({"path": "."}), Instant::now());
    assert_eq!(
        out.status,
        ToolStatus::Refused {
            reason: RefusalKind::DeadlinePassed
        }
    );
}

#[test]
fn a_capability_it_does_not_serve_is_refused() {
    let ws = scratch("unknown");
    let mut r = Rig::new(&ws);
    let out = r.call("harness.task.submit", json!({"note": "x"}));
    assert_eq!(
        out.status,
        ToolStatus::Refused {
            reason: RefusalKind::UnknownCapability
        }
    );
}

#[test]
fn workspace_facts_change_with_content_and_count_files() {
    let ws = scratch("facts");
    fs::create_dir(ws.join("d")).unwrap();
    fs::write(ws.join("d/a"), "1").unwrap();
    fs::write(ws.join("b"), "2").unwrap();
    let far = Instant::now() + Duration::from_secs(60);
    let f1 = workspace_facts(&ws, far).unwrap();
    assert_eq!((f1.files, f1.oversize), (2, 0));
    assert_eq!(workspace_facts(&ws, far).unwrap().tree, f1.tree);
    fs::write(ws.join("d/a"), "3").unwrap();
    assert_ne!(workspace_facts(&ws, far).unwrap().tree, f1.tree);
}

#[cfg(unix)]
mod inv_30 {
    use super::*;
    use std::os::unix::fs::symlink;

    fn rig(name: &str) -> (Rig, PathBuf) {
        let base = scratch(name);
        let outside = base.join("outside");
        let ws = base.join("ws");
        fs::create_dir(&outside).unwrap();
        fs::create_dir(&ws).unwrap();
        fs::write(outside.join("secret.txt"), "TOP-SECRET-CONTENT\n").unwrap();
        fs::create_dir(ws.join("src")).unwrap();
        fs::write(ws.join("src/ok.txt"), "fine\n").unwrap();
        symlink(&outside, ws.join("linkdir")).unwrap();
        symlink(outside.join("secret.txt"), ws.join("src/linkfile")).unwrap();
        (Rig::new(&ws), ws)
    }

    #[test]
    fn inv_30_a_symlink_at_any_component_is_refused_not_followed() {
        let (mut r, _) = rig("inv30-1");
        for path in ["linkdir/secret.txt", "src/linkfile", "linkdir"] {
            let out = r.call("harness.fs.read", json!({ "path": path }));
            assert_eq!(
                out.status,
                ToolStatus::Error {
                    code: code::SYMLINK
                },
                "{path}"
            );
            assert!(!text(&out).contains("TOP-SECRET"), "{path}");
        }
        let out = r.call("harness.fs.list", json!({"path": "linkdir"}));
        assert_eq!(
            out.status,
            ToolStatus::Error {
                code: code::SYMLINK
            }
        );
        let out = r.call(
            "harness.fs.search",
            json!({"pattern": "TOP", "path": "linkdir"}),
        );
        assert_eq!(
            out.status,
            ToolStatus::Error {
                code: code::SYMLINK
            }
        );
    }

    #[test]
    fn inv_30_walks_never_follow_a_symlink() {
        let (mut r, _) = rig("inv30-2");
        let t = text(&r.call("harness.fs.search", json!({"pattern": "TOP-SECRET"})));
        assert!(t.starts_with("0 hit(s)"), "{t}");
        assert!(t.contains("2 symlink(s) not followed"), "{t}");
        let t = text(&r.call("harness.fs.list", json!({"path": ".", "depth": 4})));
        assert!(t.contains("l linkdir (symlink, not followed)"), "{t}");
        assert!(t.contains("l src/linkfile (symlink, not followed)"), "{t}");
        assert!(!t.contains("secret"), "the target is not shown: {t}");
    }

    #[test]
    fn inv_30_lexical_escapes_never_reach_the_tool() {
        let (r, _) = rig("inv30-3");
        for path in ["../outside/secret.txt", "/etc/passwd", "src/../../outside"] {
            let refused = r.s.authorize(Call {
                capability: "harness.fs.read".into(),
                args: json!({ "path": path }),
            });
            assert!(refused.is_err(), "{path}");
        }
    }

    #[test]
    fn inv_30_a_symlinked_workspace_root_is_refused() {
        let base = scratch("inv30-root");
        fs::create_dir(base.join("real")).unwrap();
        symlink(base.join("real"), base.join("ws")).unwrap();
        assert!(ReadTools::new(&base.join("ws")).is_err());
    }
}
