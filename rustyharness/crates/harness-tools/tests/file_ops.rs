//! P-36e byte-identity golden: every built-in file tool and
//! `workspace_tree` runs against a fixed fixture tree through the real
//! seam (policy authorises, the journal makes the intent durable), and
//! every output text is compared byte for byte against the recorded
//! baseline. A refactor that changes one byte of any tool output fails
//! here. Set `RH_GOLDEN_PRINT=1` to (re)print the baseline instead of
//! asserting it.

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
use harness_tools::builtin::{workspace_facts, workspace_tree};
use harness_tools::file_ops::FileOps;
use harness_tools::{
    EditTools, InProcess, InvokeCtx, PatchTools, ReadLog, ReadTools, ToolProvider, ToolResult,
};
use serde_json::{json, Value};

fn printing() -> bool {
    std::env::var("RH_GOLDEN_PRINT").is_ok()
}

/// (label, `format!("{:?}", status)`, output text).
const GOLDENS: &[(&str, &str, &str)] = &[
    (
        "read:readme",
        "Ok",
        "README.md: lines 1-3 of 3; sha256 0c350faeda7a879345a60e12152484b07ad05977d4ac8f429ca1c7b73a1fd422\n1\t# Scratch\n2\t\n3\thello world\n",
    ),
    (
        "read:main",
        "Ok",
        "src/main.rs: lines 1-3 of 3; sha256 e39009458fa0dde309b7053a83a627d94bc4bc6ee30ac2d58c9ae763cbaa866e\n1\tfn main() {\n2\t    retry(3);\n3\t}\n",
    ),
    (
        "read:util",
        "Ok",
        "src/deep/util.py: lines 1-5 of 5; sha256 b2a3b3adcf5ea143cd4acd48f3586f7084ed50a023a6a0004a8a9fa1cc4e0031\n1\timport os\n2\t\n3\tclass Helper:\n4\t    def retry(self, n):\n5\t        return n\n",
    ),
    (
        "read:notes",
        "Ok",
        "docs/notes.md: lines 1-3 of 3; sha256 7181ce578417a3d5eddf19ab27a417c873adb609e985f6471e96bbe87dfa63c4\n1\tretry logic\n2\t# Heading\n3\tcrlf file\n",
    ),
    ("read:bin", "Error { code: 6 }", "error: not UTF-8 text"),
    (
        "read:missing",
        "Error { code: 2 }",
        "error: no such file or directory",
    ),
    (
        "read:git",
        "Ok",
        ".git/config: lines 1-1 of 1; sha256 74d92d2fc80fb8afce7245419a61659ed64df231439f1d37fe2c3449dd2c4625\n1\t[core]\n",
    ),
    (
        "read:link",
        "Error { code: 3 }",
        "error: a path component is a symlink; symlinks are never followed",
    ),
    (
        "read:empty",
        "Ok",
        "empty.txt: empty file; sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n",
    ),
    (
        "read:window",
        "Ok",
        "README.md: lines 3-3 of 3; sha256 0c350faeda7a879345a60e12152484b07ad05977d4ac8f429ca1c7b73a1fd422\n3\thello world\n",
    ),
    (
        "list:root1",
        "Ok",
        "8 entr(y/ies) under .\nd .git\nf README.md 23 bytes\nf data.bin 3 bytes\nd docs\nd empty\nf empty.txt 0 bytes\nl link.md (symlink, not followed)\nd src\n",
    ),
    (
        "list:src2",
        "Ok",
        "3 entr(y/ies) under src\nd src/deep\nf src/deep/util.py 66 bytes\nf src/main.rs 28 bytes\n",
    ),
    (
        "search:retry",
        "Ok",
        "3 hit(s) in 3 file(s) for a literal match\ndocs/notes.md (1 hit(s))\n  1: retry logic\nsrc/deep/util.py (1 hit(s))\n  4:     def retry(self, n):\nsrc/main.rs (1 hit(s))\n  2:     retry(3);\n1 file(s) not searched (larger than 1 MiB, unreadable or not UTF-8)\n1 symlink(s) not followed\n1 .git director(y/ies) skipped\n",
    ),
    (
        "search:regex",
        "Ok",
        "3 hit(s) in 3 file(s) for a regex match\ndocs/notes.md (1 hit(s))\n  1: retry logic\nsrc/deep/util.py (1 hit(s))\n  4:     def retry(self, n):\nsrc/main.rs (1 hit(s))\n  2:     retry(3);\n1 file(s) not searched (larger than 1 MiB, unreadable or not UTF-8)\n1 symlink(s) not followed\n1 .git director(y/ies) skipped\n",
    ),
    (
        "search:include",
        "Ok",
        "1 hit(s) in 1 file(s) for a literal match\nsrc/deep/util.py (1 hit(s))\n  4:     def retry(self, n):\n1 symlink(s) not followed\n1 .git director(y/ies) skipped\n",
    ),
    (
        "search:context",
        "Ok",
        "3 hit(s) in 3 file(s) for a literal match\ndocs/notes.md (1 hit(s))\n  1: retry logic\n  2- # Heading\nsrc/deep/util.py (1 hit(s))\n  3- class Helper:\n  4:     def retry(self, n):\n  5-         return n\nsrc/main.rs (1 hit(s))\n  1- fn main() {\n  2:     retry(3);\n  3- }\n1 file(s) not searched (larger than 1 MiB, unreadable or not UTF-8)\n1 symlink(s) not followed\n1 .git director(y/ies) skipped\n",
    ),
    (
        "glob:md",
        "Ok",
        "2 file(s) match under .\nREADME.md (23 bytes)\ndocs/notes.md (35 bytes)\n1 symlink(s) not followed\n1 .git director(y/ies) skipped\n",
    ),
    (
        "glob:star",
        "Ok",
        "6 file(s) match under .\nREADME.md (23 bytes)\ndata.bin (3 bytes)\ndocs/notes.md (35 bytes)\nempty.txt (0 bytes)\nsrc/deep/util.py (66 bytes)\nsrc/main.rs (28 bytes)\n1 symlink(s) not followed\n1 .git director(y/ies) skipped\n",
    ),
    (
        "outline:notes",
        "Ok",
        "1 symbol(s) in 1 file(s) under docs/notes.md; sha256 89b47233e982fe4072a2f0ff322a36bf619344a69afc6843d39ee90d6e9916eb\ndocs/notes.md\n  2: # Heading\n",
    ),
    (
        "outline:util",
        "Ok",
        "2 symbol(s) in 1 file(s) under src/deep/util.py; sha256 ffaa3761391b8061d2b581a9519101861d7652cfdd3ad349d761e7225d8ce774\nsrc/deep/util.py\n  3: class Helper:\n  4: def retry(self, n):\n",
    ),
    (
        "edit:replace-notes",
        "Ok",
        "edited docs/notes.md: replaced 1 match at line 1; the file now has 3 lines; sha256 da60ded7981d76dbe9b555adc7a13e3aacd877cf71489a82ab5193e5b849a647 (was 7181ce578417a3d5eddf19ab27a417c873adb609e985f6471e96bbe87dfa63c4)\n",
    ),
    (
        "edit:multi-readme",
        "Ok",
        "edited README.md: applied 1 edit in order, at line 3 (each line as the edits before it left the file); the file now has 3 lines; sha256 1f4b2d7f576978502732a298365f95562621cd450fd9cd810a95236c36436898 (was 0c350faeda7a879345a60e12152484b07ad05977d4ac8f429ca1c7b73a1fd422)\n",
    ),
    (
        "edit:write-create",
        "Ok",
        "created new.txt: 2 lines; sha256 c3f9c8c283a2b1f2f1896f27a01cbe3cddc0c9d93f752e4639035a0f5b36f6e8\n",
    ),
    (
        "edit:write-dirs",
        "Ok",
        "created gen/a/b/x.txt: 1 line; sha256 73cb3858a687a8494ca3323053016282f3dad39d42cf62ca4e79dda2aac7d9ac; created directories gen, gen/a, gen/a/b\n",
    ),
    (
        "edit:write-overwrite",
        "Ok",
        "rewrote README.md: 4 lines; sha256 cbf8d7077a5daa44cf7c66492611f4d744cc685f3fa0cff4d617b42df14ee923 (was 1f4b2d7f576978502732a298365f95562621cd450fd9cd810a95236c36436898)\n",
    ),
    (
        "edit:err-stale",
        "Error { code: 11 }",
        "error: file changed since read; re-read first: call harness.fs.read on this path, then copy old from the fresh text and repeat this call",
    ),
    (
        "edit:err-zero",
        "Error { code: 12 }",
        "error: old was not found in the file; it must match exactly, whitespace and line endings included; read the file with harness.fs.read at the place you mean and copy old from that text",
    ),
    (
        "edit:err-count",
        "Error { code: 13 }",
        "error: old matches 1 times (line(s) 1), not 2; include more of the surrounding text so it matches once, or set count",
    ),
    (
        "edit:err-missing",
        "Error { code: 2 }",
        "error: no such file or directory: find the path with harness.fs.glob or harness.fs.list, then repeat; to create a new file use harness.edit.write",
    ),
    (
        "preview:replace",
        "Ok",
        "--- a/docs/notes.md\n+++ b/docs/notes.md\n@@ -1,3 +1,3 @@\n-retried logic\\u{D}\n+retry logic\\u{D}\n # Heading\\u{D}\n crlf file\\u{D}\n",
    ),
    (
        "preview:write",
        "Ok",
        "--- /dev/null\n+++ b/gen2/y.txt\n@@ -0,0 +1 @@\n+fresh\n",
    ),
    (
        "preview:not-edit",
        "Err",
        "NotEdit(\"harness.fs.read\")",
    ),
    ("preview:stale", "Err", "Edit(Stale(Changed))"),
    (
        "patch:patch",
        "Ok",
        "patched 3 file(s):\n- created fresh.txt: 2 line(s); sha256 f901d75669f63501232d35c4ec22b2238c96feaefc71acd4bca85494ff7343ec\n- edited README.md: 3 line(s); sha256 749ace736efff9ece4a887dfe0bf959c6e68e1321ddf22ed1be9b41952ce0702 (was 0c350faeda7a879345a60e12152484b07ad05977d4ac8f429ca1c7b73a1fd422)\n- deleted docs/notes.md: sha256 7181ce578417a3d5eddf19ab27a417c873adb609e985f6471e96bbe87dfa63c4 was kept as a pre-image\n",
    ),
    (
        "patch:delete",
        "Ok",
        "deleted fresh.txt: - deleted fresh.txt: sha256 f901d75669f63501232d35c4ec22b2238c96feaefc71acd4bca85494ff7343ec was kept as a pre-image\n",
    ),
    (
        "patch:move",
        "Ok",
        "moved README.md to docs/readme.md: 3 line(s); sha256 749ace736efff9ece4a887dfe0bf959c6e68e1321ddf22ed1be9b41952ce0702 (the old file's bytes were kept as a pre-image)\n",
    ),
    (
        "patch:err-mismatch",
        "Error { code: 12 }",
        "error: the context of docs/readme.md matches 0 time(s), not exactly once: copy the context lines byte-exactly from the file (whitespace and line endings included) so it matches once",
    ),
    (
        "patch:err-add-exists",
        "Error { code: 9 }",
        "error: docs/readme.md already exists: an Add creates a new file; to change it use an Update, to rewrite it whole use harness.edit.write",
    ),
    (
        "patch:err-same-move",
        "Error { code: 9 }",
        "error: the move's target is its source: give a different `to` path",
    ),
    (
        "tree",
        "Ok",
        "digest 2d87b16672d9aadc6c5ee3e36afb66c684e681fbab4f35fd21aba5bdb398ddf5 files 6 oversize 0",
    ),
    (
        "facts",
        "Ok",
        "digest 2d87b16672d9aadc6c5ee3e36afb66c684e681fbab4f35fd21aba5bdb398ddf5 files 6 oversize 0",
    ),
];

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
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("file-ops-{name}"));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// The fixture tree every rig starts from. Deterministic names, bytes and
/// order (the walk sorts), including CRLF text, a non-UTF-8 file, a
/// symlink and an unreadable-by-policy `.git` entry.
fn build_ws(ws: &Path) {
    fs::create_dir_all(ws.join("src/deep")).unwrap();
    fs::create_dir_all(ws.join("docs")).unwrap();
    fs::create_dir_all(ws.join(".git")).unwrap();
    fs::create_dir(ws.join("empty")).unwrap();
    fs::write(ws.join("README.md"), "# Scratch\n\nhello world\n").unwrap();
    fs::write(ws.join("src/main.rs"), "fn main() {\n    retry(3);\n}\n").unwrap();
    fs::write(
        ws.join("src/deep/util.py"),
        "import os\n\nclass Helper:\n    def retry(self, n):\n        return n\n",
    )
    .unwrap();
    fs::write(
        ws.join("docs/notes.md"),
        "retry logic\r\n# Heading\r\ncrlf file\r\n",
    )
    .unwrap();
    fs::write(ws.join("data.bin"), [0xFFu8, 0xFE, b'a']).unwrap();
    fs::write(ws.join(".git/config"), "[core]\n").unwrap();
    fs::write(ws.join("empty.txt"), "").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("README.md", ws.join("link.md")).unwrap();
}

fn session(grants: &[&str], ask: &[&str]) -> Session {
    plan_session(grants, ask, false)
}

/// The same plan with an approver present, so a `user_confirm` ask is an
/// ask (covered by a redeemed token) instead of a deny.
fn session_with_approver(grants: &[&str], allow: &[&str]) -> Session {
    plan_session(grants, allow, true)
}

fn plan_session(grants: &[&str], allow: &[&str], approver: bool) -> Session {
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
    Session::plan(
        &SessionSpec {
            grants: grants.iter().map(|s| (*s).into()).collect(),
            workspace: Some(WorkspaceDecl::default()),
            approver_present: approver,
            // Every remaining field is the spec's default (including the
            // P-39b session kind, whose default is `Coding`), so the
            // literal names only the fields that differ from it.
            ..Default::default()
        },
        &reg,
        &UserPolicy::new(&[], &[], allow).unwrap(),
    )
    .unwrap()
}

fn journal() -> W {
    JournalWriter::start(
        FaultFile::new(FaultPlan::default()),
        MemBlobs::default(),
        Tick(Cell::new(0)),
        RunId::new(1, [0; 10]),
        1,
        Header::new(Ident::of("0.0.1").unwrap()),
    )
    .unwrap()
}

struct Rig<T> {
    w: W,
    s: Session,
    t: T,
    reads: ReadLog,
    step: u64,
}

impl<T: ToolProvider> Rig<T> {
    fn new(t: T, grants: &[&str], allow: &[&str]) -> Self {
        Self {
            w: journal(),
            s: session(grants, allow),
            t,
            reads: ReadLog::default(),
            step: 0,
        }
    }

    fn call(&mut self, cap: &str, args: Value) -> ToolResult {
        self.call_at(cap, args, Instant::now() + Duration::from_secs(30))
    }

    /// A call the confirmation floor asks about: the approver says yes and
    /// the single-use token is minted and redeemed right away (§5.3).
    fn call_approved(&mut self, cap: &str, args: Value) -> ToolResult {
        use harness_manifest::Confirmation;
        use harness_policy::approval::{
            ApprovalAuthority, ApprovalScope, BoundCall, MintRequest, PrincipalId, StepId,
        };

        self.step += 1;
        let call = Call {
            capability: cap.into(),
            args,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        let bound =
            BoundCall::for_call(1, StepId::new(self.step), &call, Confirmation::UserConfirm)
                .expect("a valid capability");
        let mut auth = ApprovalAuthority::new(RunId::new(1, [0; 10]), [0x11; 32]);
        let req = MintRequest {
            attempt: bound.attempt,
            step: bound.step,
            capability: bound.capability.clone(),
            args_sha256: bound.args_sha256,
            tier: bound.tier,
            scope: ApprovalScope::Once,
            approver: PrincipalId::new("cli").unwrap(),
        };
        let token = auth
            .mint(&req, [0x22; 16], Duration::from_secs(1_000))
            .expect("the tier asks");
        let redeemed = auth
            .redeem(&token, &bound, Duration::from_secs(1))
            .expect("fresh and bound");
        let a = self
            .s
            .authorize_approved(call, redeemed)
            .expect("the ask is covered");
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
                    egress: None,
                },
            )
            .unwrap()
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
                    egress: None,
                },
            )
            .unwrap()
    }

    /// What the run does after a successful `fs.read`.
    fn read(&mut self, ws: &Path, p: &str) {
        self.reads.record(p, sha256(&fs::read(ws.join(p)).unwrap()));
    }
}

fn text(r: &ToolResult) -> String {
    String::from_utf8(r.output.inspect("test").clone()).unwrap()
}

fn snap(label: &str, r: &ToolResult) {
    let t = text(r);
    let s = format!("{:?}", r.status);
    if printing() {
        eprintln!(
            "===== {label}\nSTATUS {s}\nTRUNC {}\nTEXT-START\n{t}TEXT-END",
            r.truncated
        );
        return;
    }
    let want = GOLDENS
        .iter()
        .find(|(l, _, _)| *l == label)
        .unwrap_or_else(|| panic!("no golden recorded for {label}"));
    assert_eq!(want.1, s, "status for {label}\n{t}");
    assert_eq!(want.2, t, "text for {label}");
    assert_eq!(r.digest, sha256(t.as_bytes()), "digest for {label}");
}

fn snap_text(label: &str, s: &str, t: &str) {
    if printing() {
        eprintln!("===== {label}\nSTATUS {s}\nTRUNC 0\nTEXT-START\n{t}TEXT-END");
        return;
    }
    let want = GOLDENS
        .iter()
        .find(|(l, _, _)| *l == label)
        .unwrap_or_else(|| panic!("no golden recorded for {label}"));
    assert_eq!(want.1, s, "status for {label}\n{t}");
    assert_eq!(want.2, t, "text for {label}");
}

#[cfg(unix)]
#[test]
fn file_ops_in_process_results_byte_identical() {
    // -- the read-side tools on a pristine fixture --------------------
    let ws = scratch("read");
    build_ws(&ws);
    let mut r = Rig::new(
        ReadTools::new(&ws).unwrap(),
        &[
            "harness.fs.read",
            "harness.fs.search",
            "harness.fs.list",
            "harness.fs.glob",
            "harness.fs.outline",
        ],
        &[],
    );

    snap(
        "read:readme",
        &r.call("harness.fs.read", json!({"path": "README.md"})),
    );
    snap(
        "read:main",
        &r.call("harness.fs.read", json!({"path": "src/main.rs"})),
    );
    snap(
        "read:util",
        &r.call("harness.fs.read", json!({"path": "src/deep/util.py"})),
    );
    snap(
        "read:notes",
        &r.call("harness.fs.read", json!({"path": "docs/notes.md"})),
    );
    snap(
        "read:bin",
        &r.call("harness.fs.read", json!({"path": "data.bin"})),
    );
    snap(
        "read:missing",
        &r.call("harness.fs.read", json!({"path": "missing.txt"})),
    );
    snap(
        "read:git",
        &r.call("harness.fs.read", json!({"path": ".git/config"})),
    );
    snap(
        "read:link",
        &r.call("harness.fs.read", json!({"path": "link.md"})),
    );
    snap(
        "read:empty",
        &r.call("harness.fs.read", json!({"path": "empty.txt"})),
    );
    snap(
        "read:window",
        &r.call(
            "harness.fs.read",
            json!({"path": "README.md", "start": 3, "lines": 1}),
        ),
    );
    snap(
        "list:root1",
        &r.call("harness.fs.list", json!({"path": ".", "depth": 1})),
    );
    snap(
        "list:src2",
        &r.call("harness.fs.list", json!({"path": "src", "depth": 2})),
    );
    snap(
        "search:retry",
        &r.call("harness.fs.search", json!({"pattern": "retry"})),
    );
    snap(
        "search:regex",
        &r.call(
            "harness.fs.search",
            json!({"pattern": "(?i)RETRY", "regex": true}),
        ),
    );
    snap(
        "search:include",
        &r.call(
            "harness.fs.search",
            json!({"pattern": "retry", "include": "*.py"}),
        ),
    );
    snap(
        "search:context",
        &r.call(
            "harness.fs.search",
            json!({"pattern": "retry", "context": 1}),
        ),
    );
    snap(
        "glob:md",
        &r.call("harness.fs.glob", json!({"pattern": "**/*.md"})),
    );
    snap(
        "glob:star",
        &r.call("harness.fs.glob", json!({"pattern": "*"})),
    );
    snap(
        "outline:notes",
        &r.call("harness.fs.outline", json!({"path": "docs/notes.md"})),
    );
    snap(
        "outline:util",
        &r.call("harness.fs.outline", json!({"path": "src/deep/util.py"})),
    );

    // -- the edit tools ------------------------------------------------
    let ws = scratch("edit");
    build_ws(&ws);
    let mut e = Rig::new(
        EditTools::new(&ws).unwrap(),
        &[
            "harness.fs.read",
            "harness.edit.replace",
            "harness.edit.write",
            "harness.edit.multi",
        ],
        &[
            "harness.edit.replace",
            "harness.edit.write",
            "harness.edit.multi",
        ],
    );
    e.read(&ws, "README.md");
    e.read(&ws, "docs/notes.md");

    snap(
        "edit:replace-notes",
        &e.call(
            "harness.edit.replace",
            json!({"path": "docs/notes.md", "old": "retry logic", "new": "retried logic"}),
        ),
    );
    // The run re-reads what its own edit changed.
    e.read(&ws, "docs/notes.md");
    snap(
        "edit:multi-readme",
        &e.call(
            "harness.edit.multi",
            json!({"path": "README.md", "edits": [
                {"old": "hello world", "new": "hello rust"}
            ]}),
        ),
    );
    // The run re-reads what its own edit changed.
    e.read(&ws, "README.md");

    snap(
        "edit:write-create",
        &e.call(
            "harness.edit.write",
            json!({"path": "new.txt", "content": "one\ntwo\n"}),
        ),
    );
    snap(
        "edit:write-dirs",
        &e.call(
            "harness.edit.write",
            json!({"path": "gen/a/b/x.txt", "content": "x\n"}),
        ),
    );
    snap(
        "edit:write-overwrite",
        &e.call(
            "harness.edit.write",
            json!({"path": "README.md", "content": "# Scratch\n\nhello rust\nappended\n"}),
        ),
    );

    // A change behind the read log makes the next edit stale.
    fs::write(ws.join("README.md"), "changed behind the run\n").unwrap();
    snap(
        "edit:err-stale",
        &e.call(
            "harness.edit.replace",
            json!({"path": "README.md", "old": "changed", "new": "x"}),
        ),
    );
    snap(
        "edit:err-zero",
        &e.call(
            "harness.edit.replace",
            json!({"path": "docs/notes.md", "old": "not present anywhere", "new": "x"}),
        ),
    );
    snap(
        "edit:err-count",
        &e.call(
            "harness.edit.replace",
            json!({"path": "docs/notes.md", "old": "retried", "new": "x", "count": 2}),
        ),
    );
    snap(
        "edit:err-missing",
        &e.call(
            "harness.edit.replace",
            json!({"path": "nope.txt", "old": "a", "new": "b"}),
        ),
    );

    // Previews share the planners and the refusals of the real edits.
    let p = e.t.preview(
        &Call {
            capability: "harness.edit.replace".into(),
            args: json!({"path": "docs/notes.md", "old": "retried logic", "new": "retry logic"}),
        },
        &e.reads,
    );
    match p {
        Ok(s) => snap_text("preview:replace", "Ok", &s),
        Err(err) => snap_text("preview:replace", "Err", &format!("{err:?}")),
    }
    let p = e.t.preview(
        &Call {
            capability: "harness.edit.write".into(),
            args: json!({"path": "gen2/y.txt", "content": "fresh\n"}),
        },
        &e.reads,
    );
    match p {
        Ok(s) => snap_text("preview:write", "Ok", &s),
        Err(err) => snap_text("preview:write", "Err", &format!("{err:?}")),
    }
    let p = e.t.preview(
        &Call {
            capability: "harness.fs.read".into(),
            args: json!({"path": "README.md"}),
        },
        &e.reads,
    );
    match p {
        Ok(s) => snap_text("preview:not-edit", "Ok", &s),
        Err(err) => snap_text("preview:not-edit", "Err", &format!("{err:?}")),
    }
    let p = e.t.preview(
        &Call {
            capability: "harness.edit.replace".into(),
            args: json!({"path": "README.md", "old": "changed", "new": "x"}),
        },
        &e.reads,
    );
    match p {
        Ok(s) => snap_text("preview:stale", "Ok", &s),
        Err(err) => snap_text("preview:stale", "Err", &format!("{err:?}")),
    }

    // -- the patch / delete / move tools --------------------------------
    // delete and move declare `user_confirm`, so the session runs with an
    // approver present and each such call rides a redeemed single-use
    // token (§5.3); the patch script itself is plain edit-class.
    let ws = scratch("patch");
    build_ws(&ws);
    let mut p = Rig {
        w: journal(),
        s: session_with_approver(
            &[
                "harness.fs.read",
                "harness.edit.patch",
                "harness.edit.delete",
                "harness.edit.move",
            ],
            &["harness.edit.patch"],
        ),
        t: PatchTools::new(&ws).unwrap(),
        reads: ReadLog::default(),
        step: 0,
    };
    p.read(&ws, "README.md");
    p.read(&ws, "docs/notes.md");
    p.read(&ws, "data.bin");

    snap(
        "patch:patch",
        &p.call(
            "harness.edit.patch",
            json!({"patch": "*** Begin Patch\n*** Add File: fresh.txt\n+line one\n+line two\n*** Update File: README.md\n-hello world\n+hello patch\n*** Delete File: docs/notes.md\n*** End Patch\n"}),
        ),
    );
    // The run re-reads what the patch script wrote and created.
    p.read(&ws, "fresh.txt");
    p.read(&ws, "README.md");
    snap(
        "patch:delete",
        &p.call_approved("harness.edit.delete", json!({"path": "fresh.txt"})),
    );
    snap(
        "patch:move",
        &p.call_approved(
            "harness.edit.move",
            json!({"path": "README.md", "to": "docs/readme.md"}),
        ),
    );
    p.read(&ws, "docs/readme.md");
    snap(
        "patch:err-mismatch",
        &p.call(
            "harness.edit.patch",
            json!({"patch": "*** Begin Patch\n*** Update File: docs/readme.md\n-not there\n+still not\n*** End Patch\n"}),
        ),
    );
    snap(
        "patch:err-add-exists",
        &p.call(
            "harness.edit.patch",
            json!({"patch": "*** Begin Patch\n*** Add File: docs/readme.md\n+x\n*** End Patch\n"}),
        ),
    );
    snap(
        "patch:err-same-move",
        &p.call_approved(
            "harness.edit.move",
            json!({"path": "docs/readme.md", "to": "docs/readme.md"}),
        ),
    );

    // -- the workspace tree and facts over the mutated fixture ----------
    let deadline = Instant::now() + Duration::from_secs(30);
    let tree = workspace_tree(&ws, deadline).unwrap();
    let s = format!(
        "digest {} files {} oversize {}",
        tree.digest(),
        tree.facts().files,
        tree.facts().oversize
    );
    snap_text("tree", "Ok", &s);
    let f = workspace_facts(&ws, deadline).unwrap();
    let s = format!(
        "digest {} files {} oversize {}",
        f.tree, f.files, f.oversize
    );
    snap_text("facts", "Ok", &s);
}

#[cfg(unix)]
#[test]
fn restore_file_round_trips_an_after_image() {
    let ws = scratch("restore");
    build_ws(&ws);
    let mut e = Rig::new(
        EditTools::new(&ws).unwrap(),
        &["harness.edit.replace"],
        &["harness.edit.replace"],
    );
    e.read(&ws, "src/main.rs");
    let r = e.call(
        "harness.edit.replace",
        json!({"path": "src/main.rs", "old": "retry(3)", "new": "retry(4)"}),
    );
    assert_eq!(r.status, harness_tools::ToolStatus::Ok, "{}", text(&r));
    let rec = r.edits.first().unwrap();
    let img = rec.after_image.clone().unwrap();
    let expect = harness_core::sha256(&fs::read(ws.join("src/main.rs")).unwrap());
    harness_tools::restore_file(&ws, "src/main.rs", &img, expect).unwrap();
    assert_eq!(fs::read(ws.join("src/main.rs")).unwrap(), img.bytes);
}

/// A `Box<dyn FileOps>` clones (the `Clone` on `EditEngine`/`EditTools`
/// rides on it), and the clone serves the same calls as the original.
#[cfg(unix)]
#[test]
fn file_ops_box_dyn_clones_and_the_clone_serves_calls() {
    let ws = scratch("clonebox");
    build_ws(&ws);
    let mut ops: Box<dyn FileOps> = Box::new(InProcess);
    let mut clone = ops.clone();

    let path = ws.join("src/main.rs");
    assert_eq!(ops.lstat(&path).unwrap(), clone.lstat(&path).unwrap());
    assert_eq!(
        ops.read(&path, 1 << 20, None).unwrap(),
        clone.read(&path, 1 << 20, None).unwrap()
    );

    let write = ws.join("clone-write.txt");
    let bytes = b"retry(3);\n";
    ops.write_atomic(&write, bytes, None).unwrap();
    assert_eq!(clone.read(&write, 1 << 20, None).unwrap(), bytes);
}

/// A cloned `EditTools` serves the same workspace as the original (the
/// shape the driver's `edit_tools.clone()` relies on): each registers its
/// read and applies the same replace.
#[cfg(unix)]
#[test]
fn edit_tools_clone_serves_the_same_workspace() {
    let ws = scratch("clonetools");
    build_ws(&ws);
    let tools = EditTools::new(&ws).unwrap();
    let apply_replace = |rig: &mut Rig<EditTools>| {
        rig.read(&ws, "src/main.rs");
        let r = rig.call(
            "harness.edit.replace",
            json!({"path": "src/main.rs", "old": "retry(3)", "new": "retry(4)"}),
        );
        assert_eq!(r.status, harness_tools::ToolStatus::Ok, "{}", text(&r));
    };

    let mut first = Rig::new(
        tools.clone(),
        &["harness.edit.replace"],
        &["harness.edit.replace"],
    );
    apply_replace(&mut first);
    // Back to the pristine fixture for the clone's own read and edit.
    fs::write(ws.join("src/main.rs"), "fn main() {\n    retry(3);\n}\n").unwrap();

    let mut second = Rig::new(tools, &["harness.edit.replace"], &["harness.edit.replace"]);
    apply_replace(&mut second);
    assert_eq!(
        fs::read(ws.join("src/main.rs")).unwrap(),
        b"fn main() {\n    retry(4);\n}\n"
    );
}
