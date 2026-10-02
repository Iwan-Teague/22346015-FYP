//! P-24: `harness.fs.outline`, through the real seam (policy authorises,
//! the journal makes the intent durable, then `ReadTools` runs the call).
//! Deterministic extraction per language, the walk's confinement (no
//! symlink followed, `.git` skipped, denied paths counted, P-12), the
//! entry cap, and the digest that two calls over the same bytes agree on.

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

use harness_core::RunId;
use harness_journal::testing::{FaultFile, FaultPlan, MemBlobs};
use harness_journal::{Clock, Event, EventKind, Header, Ident, JournalWriter};
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, SemVer, ValidationContext};
use harness_policy::{Call, Session, SessionSpec, UserPolicy, WorkspaceDecl};
use harness_tools::builtin::code;
use harness_tools::{InvokeCtx, ReadTools, ToolProvider, ToolResult, ToolStatus};
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
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("outline-tools-{name}"));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

struct Rig {
    w: JournalWriter<FaultFile, MemBlobs, Tick>,
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
                    "harness.fs.glob".into(),
                    "harness.fs.list".into(),
                    "harness.fs.outline".into(),
                    "harness.task.submit".into(),
                ],
                workspace: Some(WorkspaceDecl::default()),
                approver_present: false,
                personal_data_granted: false,
                conformed: false,
                exec_programs: Vec::new(),
                read_window: None,
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

    fn call(&mut self, cap: &str, args: Value) -> ToolResult {
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
                    deadline: Instant::now() + Duration::from_secs(30),
                    reads: &harness_tools::ReadLog::default(),
                },
            )
            .unwrap()
    }
}

fn text(r: &ToolResult) -> String {
    String::from_utf8(r.output.inspect("test").clone()).unwrap()
}

fn outline(r: &mut Rig, args: Value) -> String {
    let out = r.call("harness.fs.outline", args);
    assert_eq!(out.status, ToolStatus::Ok, "{}", text(&out));
    text(&out)
}

#[test]
fn outline_rust_fns_structs_impls() {
    let ws = scratch("rust");
    fs::write(
        ws.join("lib.rs"),
        "//! module doc, not a symbol\n\
         use std::time::Instant;\n\
         \n\
         pub fn retry_base() -> u64 {\n\
         \x20   375\n\
         }\n\
         fn helper() {}\n\
         pub(crate) const fn cap() -> u64 { 0 }\n\
         async unsafe fn raw() {}\n\
         // fn in a comment\n\
         pub struct Config {\n\
         \x20   pub retries: u32,\n\
         }\n\
         pub(crate) enum Mode { On, Off }\n\
         pub trait Run {\n\
         \x20   fn go(&self);\n\
         }\n\
         impl Config {\n\
         \x20   fn new() -> Self { Self { retries: 0 } }\n\
         }\n\
         impl Run for Config {\n\
         \x20   fn go(&self) {}\n\
         }\n",
    )
    .unwrap();
    let mut r = Rig::new(&ws);
    let t = outline(&mut r, json!({"path": "lib.rs"}));
    let body = "lib.rs\n\
                \x20 4: pub fn retry_base() -> u64 {\n\
                \x20 7: fn helper() {}\n\
                \x20 8: pub(crate) const fn cap() -> u64 { 0 }\n\
                \x20 9: async unsafe fn raw() {}\n\
                \x20 11: pub struct Config {\n\
                \x20 14: pub(crate) enum Mode { On, Off }\n\
                \x20 15: pub trait Run {\n\
                \x20 16: fn go(&self);\n\
                \x20 18: impl Config {\n\
                \x20 19: fn new() -> Self { Self { retries: 0 } }\n\
                \x20 21: impl Run for Config {\n\
                \x20 22: fn go(&self) {}\n";
    assert!(
        t.starts_with("12 symbol(s) in 1 file(s) under lib.rs; sha256 "),
        "{t}"
    );
    let (_, got) = t.split_once('\n').unwrap();
    assert_eq!(got, body);
    // The `kind` filter keeps one kind, by any of its spellings.
    let t = outline(&mut r, json!({"path": "lib.rs", "kind": "Fn"}));
    assert!(
        t.starts_with("7 symbol(s) in 1 file(s)")
            && t.contains(" 4: pub fn retry_base()")
            && !t.contains("struct"),
        "{t}"
    );
    let t = outline(&mut r, json!({"path": "lib.rs", "kind": "impl"}));
    assert!(t.starts_with("2 symbol(s) in 1 file(s)"), "{t}");
    // A kind nothing in the file has is an empty outline, not an error.
    let t = outline(&mut r, json!({"path": "lib.rs", "kind": "heading"}));
    assert!(t.starts_with("0 symbol(s) in 0 file(s)"), "{t}");
}

#[test]
fn outline_python_defs_classes() {
    let ws = scratch("python");
    fs::write(
        ws.join("app.py"),
        "#!/usr/bin/env python3\n\
         import os\n\
         \n\
         \n\
         def run(path):\n\
         \x20   return path\n\
         \n\
         \n\
         async def fetch(url):\n\
         \x20   pass\n\
         \n\
         \n\
         class Widget:\n\
         \x20   # def not_a_symbol(self):\n\
         \x20   pass\n",
    )
    .unwrap();
    let mut r = Rig::new(&ws);
    let t = outline(&mut r, json!({"path": "app.py"}));
    let (_, got) = t.split_once('\n').unwrap();
    assert_eq!(
        got,
        "app.py\n\
         \x20 5: def run(path):\n\
         \x20 9: async def fetch(url):\n\
         \x20 13: class Widget:\n"
    );
    assert!(
        t.starts_with("3 symbol(s) in 1 file(s) under app.py; sha256 "),
        "{t}"
    );
    // A class filter keeps only the class.
    let t = outline(&mut r, json!({"path": "app.py", "kind": "class"}));
    assert!(
        t.starts_with("1 symbol(s) in 1 file(s)") && t.contains("  13: class Widget:"),
        "{t}"
    );
}

#[test]
fn outline_ts_exports() {
    let ws = scratch("ts");
    fs::write(
        ws.join("app.ts"),
        "import { x } from \"./x\";\n\
         \n\
         export function boot(): void {}\n\
         export default function main() {}\n\
         function hidden() {}\n\
         export const N = 1;\n\
         let inner = 2;\n\
         export let counter = 0;\n\
         export class App {}\n\
         class AlsoHidden {}\n\
         export interface Opts {\n\
         \x20   retries: number;\n\
         }\n\
         export type Id = string;\n\
         export enum Mode { On, Off }\n",
    )
    .unwrap();
    fs::write(
        ws.join("app.js"),
        "export function js() {}\nconst priv = 1;\nmodule.exports = {};\n",
    )
    .unwrap();
    let mut r = Rig::new(&ws);
    let t = outline(&mut r, json!({}));
    let (_, got) = t.split_once('\n').unwrap();
    assert_eq!(
        got,
        "app.js\n\
         \x20 1: export function js() {}\n\
         app.ts\n\
         \x20 3: export function boot(): void {}\n\
         \x20 4: export default function main() {}\n\
         \x20 6: export const N = 1;\n\
         \x20 8: export let counter = 0;\n\
         \x20 9: export class App {}\n\
         \x20 11: export interface Opts {\n\
         \x20 14: export type Id = string;\n\
         \x20 15: export enum Mode { On, Off }\n"
    );
    assert!(
        t.starts_with("9 symbol(s) in 2 file(s) under .; sha256 "),
        "{t}"
    );
    // Nothing private is named.
    assert!(!t.contains("hidden") && !t.contains("inner"), "{t}");
    // A const filter keeps const/let/var exports.
    let t = outline(&mut r, json!({"path": "app.ts", "kind": "const"}));
    assert!(
        t.starts_with("2 symbol(s) in 1 file(s)")
            && t.contains(" 6: export const N = 1;")
            && t.contains(" 8: export let counter = 0;"),
        "{t}"
    );
}

#[test]
fn outline_dir_bounded_and_sorted() {
    let ws = scratch("bounded");
    fs::create_dir_all(ws.join("a")).unwrap();
    let many = |n: usize| -> String {
        (0..n)
            .map(|i| format!("fn f{i:03}() {{}}\n"))
            .collect::<String>()
    };
    fs::write(ws.join("a/b.rs"), many(150)).unwrap();
    fs::write(ws.join("a-c.rs"), many(100)).unwrap();
    // Not outlined: a binary blob and a 1 MiB text file; an unknown
    // extension is skipped without a word.
    fs::write(ws.join("blob.py"), [0xFFu8, 0xFE, 0x00]).unwrap();
    fs::write(
        ws.join("big.rs"),
        format!("{}\n", "x".repeat(1024 * 1024 + 1)),
    )
    .unwrap();
    fs::write(ws.join("notes.txt"), "fn not_outlined() {}\n").unwrap();
    let mut r = Rig::new(&ws);
    let t = outline(&mut r, json!({}));
    // Component order: `a/b.rs` sorts before `a-c.rs` (byte order would
    // put `a-c.rs` first), and the cap lands on the global order: all of
    // `a/b.rs`, then the first 50 of `a-c.rs`.
    assert!(
        t.starts_with("200 symbol(s) in 2 file(s) under .; sha256 "),
        "{t:.120}"
    );
    assert!(t.contains("more not shown (the cap is 200)"), "{t}");
    let (_, body) = t.split_once('\n').unwrap();
    assert!(
        body.starts_with("a/b.rs\n  1: fn f000() {}\n"),
        "{body:.80}"
    );
    assert!(body.contains("a-c.rs\n  1: fn f000() {}\n"), "{t}");
    assert!(body.contains("  50: fn f049() {}\n"), "{t}");
    // a-c.rs's rows stop at the cap (a/b.rs alone fills 150 of the 200);
    // the last shown row runs straight into the foot.
    assert!(!body.contains("a-c.rs\n  51:"), "{t}");
    assert!(
        t.contains("  50: fn f049() {}\n2 file(s) not outlined"),
        "{t}"
    );
    assert!(t.contains("2 file(s) not outlined"), "{t}");
    // A single file under the cap shows everything.
    let t = outline(&mut r, json!({"path": "a-c.rs"}));
    assert!(t.starts_with("100 symbol(s) in 1 file(s)"), "{t:.80}");
}

#[test]
fn outline_skips_denied_files() {
    let ws = scratch("denied");
    fs::write(ws.join(".env"), "fn denied() {}\n").unwrap();
    fs::write(ws.join(".env.local"), "SECRET=1\n").unwrap();
    fs::create_dir_all(ws.join("keys")).unwrap();
    fs::write(ws.join("keys/server.pem"), "-----BEGIN-----\n").unwrap();
    fs::write(ws.join("keys/server.key"), "raw key material\n").unwrap();
    // A denied path the outline would otherwise show.
    fs::write(ws.join("keys/id_rsa_key.py"), "def leak(): pass\n").unwrap();
    fs::write(ws.join("a.rs"), "fn shown() {}\n").unwrap();
    fs::create_dir(ws.join("sub")).unwrap();
    fs::write(ws.join("sub/b.py"), "class Also:\n    pass\n").unwrap();
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
    let policy = harness_policy::default_denies().unwrap();
    let globs = policy.denied_globs();
    let s = Session::plan(
        &SessionSpec {
            grants: vec![
                "harness.fs.outline".into(),
                "harness.fs.read".into(),
                "harness.fs.search".into(),
                "harness.fs.glob".into(),
                "harness.fs.list".into(),
                "harness.task.submit".into(),
            ],
            workspace: Some(WorkspaceDecl::default()),
            approver_present: false,
            personal_data_granted: false,
            conformed: false,
            exec_programs: Vec::new(),
            read_window: None,
        },
        &reg,
        &policy,
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
    let mut r = Rig {
        w,
        s,
        t: ReadTools::new(&ws).unwrap().with_denied(globs),
        step: 0,
    };
    let t = outline(&mut r, json!({}));
    assert!(t.contains("a.rs\n  1: fn shown() {}\n"), "{t}");
    assert!(t.contains("sub/b.py\n  1: class Also:\n"), "{t}");
    // The denied paths are neither outlined nor named; the count says so
    // (never silently: the model can tell denied from absent).
    assert!(!t.contains("fn denied()"), "{t}");
    assert!(!t.contains("leak"), "{t}");
    assert!(!t.contains(".env"), "{t}");
    assert!(!t.contains("server.pem"), "{t}");
    assert!(!t.contains("BEGIN"), "{t}");
    assert_eq!(
        t.lines().last(),
        Some("5 path(s) skipped (denied by policy)")
    );
    // A start path on a denied file is refused by the policy before the
    // tool runs (the tools re-check as defence in depth).
    let refused = r.s.authorize(Call {
        capability: "harness.fs.outline".into(),
        args: json!({"path": "keys/server.pem"}),
    });
    assert!(refused.is_err());
}

#[test]
fn outline_binary_file_refused() {
    let ws = scratch("binary");
    fs::write(ws.join("blob.py"), [0xFFu8, 0xFE, b'a', 0x00]).unwrap();
    fs::write(ws.join("notes.txt"), "plain\n").unwrap();
    let mut r = Rig::new(&ws);
    let out = r.call("harness.fs.outline", json!({"path": "blob.py"}));
    assert_eq!(
        out.status,
        ToolStatus::Error {
            code: code::NOT_TEXT
        },
        "{}",
        text(&out)
    );
    assert_eq!(text(&out), "error: not UTF-8 text");
    // An extension no language is known for says so, naming the languages.
    let out = r.call("harness.fs.outline", json!({"path": "notes.txt"}));
    assert_eq!(
        out.status,
        ToolStatus::Error {
            code: code::NO_OUTLINE
        },
        "{}",
        text(&out)
    );
    assert!(text(&out).contains("no outline for files of this kind"));
    // A text file over the read cap is too large, not binary.
    fs::write(
        ws.join("big.md"),
        format!("# {}\n", "x".repeat(1024 * 1024 + 1)),
    )
    .unwrap();
    let out = r.call("harness.fs.outline", json!({"path": "big.md"}));
    assert_eq!(
        out.status,
        ToolStatus::Error {
            code: code::TOO_LARGE
        },
        "{}",
        text(&out)
    );
}

#[test]
fn outline_deterministic_digest() {
    let ws = scratch("digest");
    fs::create_dir_all(ws.join("src/net")).unwrap();
    fs::write(ws.join("src/lib.rs"), "pub fn a() {}\npub struct S;\n").unwrap();
    fs::write(ws.join("src/net/util.py"), "def poll():\n    pass\n").unwrap();
    fs::write(ws.join("README.md"), "# Title\n## Sub\n").unwrap();
    let mut r = Rig::new(&ws);
    let one = outline(&mut r, json!({}));
    let two = outline(&mut r, json!({}));
    assert_eq!(one, two);
    let (head, body) = one.split_once('\n').unwrap();
    let (_, digest) = head.rsplit_once("sha256 ").unwrap();
    assert_eq!(digest.len(), 64);
    // The digest is over the shown entries: the body hashes to it.
    assert_eq!(digest, harness_core::sha256(body.as_bytes()).to_string());
    assert!(
        head.starts_with("5 symbol(s) in 3 file(s) under .; sha256 "),
        "{head}"
    );
    assert!(
        body.starts_with("README.md\n  1: # Title\n  2: ## Sub\n"),
        "{body}"
    );
    assert!(
        body.contains("src/lib.rs\n  1: pub fn a() {}\n  2: pub struct S;\n"),
        "{body}"
    );
    assert!(
        body.contains("src/net/util.py\n  1: def poll():\n"),
        "{body}"
    );
    // Any byte of a file's symbols changes the digest.
    fs::write(ws.join("src/lib.rs"), "pub fn a() {}\npub struct T;\n").unwrap();
    assert_ne!(one, outline(&mut r, json!({})));
    // ... but a change the outline never shows does not.
    fs::write(
        ws.join("src/lib.rs"),
        "pub fn a() {}\npub struct S;\n// a trailing note\n",
    )
    .unwrap();
    assert_eq!(outline(&mut r, json!({})), one);
}

#[test]
fn outline_edges() {
    let ws = scratch("edges");
    fs::create_dir(ws.join("src")).unwrap();
    fs::write(ws.join("src/lib.rs"), "fn a() {}\n").unwrap();
    let mut r = Rig::new(&ws);
    // A missing path keeps the read tools' plain message.
    let out = r.call("harness.fs.outline", json!({"path": "nope.rs"}));
    assert_eq!(
        out.status,
        ToolStatus::Error {
            code: code::NOT_FOUND
        }
    );
    // A directory start outlines the directory.
    let t = outline(&mut r, json!({"path": "src"}));
    assert!(t.starts_with("1 symbol(s) in 1 file(s) under src"), "{t}");
    assert!(t.contains("src/lib.rs\n  1: fn a() {}\n"), "{t}");
    // A non-string kind is refused by the manifest schema before the tool
    // runs (the tool's own check is defence in depth).
    assert!(r
        .s
        .authorize(Call {
            capability: "harness.fs.outline".into(),
            args: json!({"kind": 3}),
        })
        .is_err());
    // An empty workspace outlines to an empty result, deterministically.
    let ws = scratch("edges-empty");
    let mut r = Rig::new(&ws);
    let t = outline(&mut r, json!({}));
    assert_eq!(
        t.lines().next().unwrap(),
        format!(
            "0 symbol(s) in 0 file(s) under .; sha256 {}",
            harness_core::sha256(b"")
        )
    );
    assert_eq!(t.lines().count(), 1);
}
