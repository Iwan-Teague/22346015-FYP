//! H2e: `harness.fs.search` with a regular expression, glob filters,
//! context lines and per-file caps, and `harness.fs.glob`, through the real
//! seam (policy authorises, the journal makes the intent durable, then
//! `ReadTools` runs the call). Confinement (INV-30, in-process half) for
//! the glob: no symlink is followed, listed as a file, or walked through.

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
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("search-tools-{name}"));
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

fn search(r: &mut Rig, args: Value) -> String {
    let out = r.call("harness.fs.search", args);
    assert_eq!(out.status, ToolStatus::Ok, "{}", text(&out));
    text(&out)
}

#[test]
fn h2e_a_regex_is_matched_line_by_line_and_a_literal_stays_literal() {
    let ws = scratch("regex");
    fs::create_dir(ws.join("src")).unwrap();
    fs::write(
        ws.join("src/lib.rs"),
        "pub fn retry_base() -> u64 { 375 }\nfn helper() {}\nconst RETRY_CAP: u64 = 12_000;\n// fn in a comment\n",
    )
    .unwrap();
    let mut r = Rig::new(&ws);
    let t = search(
        &mut r,
        json!({"pattern": "^(pub )?fn \\w+\\(", "regex": true}),
    );
    assert!(
        t.starts_with("2 hit(s) in 1 file(s) for a regex match\nsrc/lib.rs (2 hit(s))\n  1: pub fn retry_base() -> u64 { 375 }\n  2: fn helper() {}\n"),
        "{t}"
    );
    // Case-insensitive through the inline flag; alternatives.
    let t = search(
        &mut r,
        json!({"pattern": "(?i)retry_cap|RETRY_BASE", "regex": true}),
    );
    assert!(t.starts_with("2 hit(s) in 1 file(s)"), "{t}");
    // Without regex, the same text is a literal: no line holds it.
    let t = search(&mut r, json!({"pattern": "^(pub )?fn \\w+\\("}));
    assert!(
        t.starts_with("0 hit(s) in 0 file(s) for a literal match\n"),
        "{t}"
    );
    // A numeric literal with an underscore, found by a class.
    let t = search(&mut r, json!({"pattern": "= [0-9_]{5,};", "regex": true}));
    assert!(t.contains("  3: const RETRY_CAP: u64 = 12_000;\n"), "{t}");
}

#[test]
fn h2e_a_bad_regex_is_a_typed_error_in_static_words() {
    let ws = scratch("bad-regex");
    fs::write(ws.join("a.txt"), "x\n").unwrap();
    let mut r = Rig::new(&ws);
    for (pattern, words) in [
        ("ZQX(unclosed", "unbalanced parenthesis"),
        ("ZQX[abc", "no closing ']'"),
        ("ZQX(?=ahead)", "look-around"),
        ("(ZQX)\\1", "backreferences"),
        ("ZQX\\q", "unknown or incomplete escape"),
        ("ZQX{2,1}", "counted repetition"),
        ("*ZQX", "nothing to repeat"),
        ("ZQX\\p{NoSuchClass}", "unknown Unicode class"),
        ("[z-a]ZQX", "character class range"),
        ("(?Q)ZQX", "inline flag"),
    ] {
        let out = r.call(
            "harness.fs.search",
            json!({"pattern": pattern, "regex": true}),
        );
        assert_eq!(
            out.status,
            ToolStatus::Error {
                code: code::BAD_PATTERN
            },
            "{pattern}"
        );
        let t = text(&out);
        assert!(
            t.starts_with("error: ") && t.contains(words),
            "{pattern}: {t}"
        );
        // The pattern is never quoted back.
        assert!(!t.contains("ZQX"), "{pattern}: {t}");
    }
    // A pattern that is valid but compiles past the size limit.
    let huge = format!("(\\w{{50}}){{{}}}", 400);
    let out = r.call("harness.fs.search", json!({"pattern": huge, "regex": true}));
    assert_eq!(
        out.status,
        ToolStatus::Error {
            code: code::BAD_PATTERN
        }
    );
    assert!(text(&out).contains("too large"), "{}", text(&out));
}

// Matching is linear: a pattern that is exponential for a backtracking
// engine finishes at once over a long line.
#[test]
fn h2e_a_hostile_regex_runs_in_linear_time() {
    let ws = scratch("hostile");
    fs::write(ws.join("a.txt"), format!("{}\n", "a".repeat(100_000))).unwrap();
    let mut r = Rig::new(&ws);
    let t0 = Instant::now();
    let t = search(&mut r, json!({"pattern": "(a*)*b", "regex": true}));
    assert!(t.starts_with("0 hit(s)"), "{t}");
    let t = search(&mut r, json!({"pattern": "(a|aa)+$", "regex": true}));
    assert!(t.starts_with("1 hit(s)"), "{t:.200}");
    assert!(t0.elapsed() < Duration::from_secs(10));
}

#[test]
fn h2e_include_and_exclude_are_globs_below_the_search_path() {
    let ws = scratch("filters");
    for (p, body) in [
        ("src/lib.rs", "needle\n"),
        ("src/net/mod.rs", "needle\n"),
        ("src/notes.md", "needle\n"),
        ("target/debug/out.rs", "needle\n"),
        ("docs/a.md", "needle\n"),
        ("Cargo.toml", "needle = 1\n"),
    ] {
        fs::create_dir_all(ws.join(p).parent().unwrap()).unwrap();
        fs::write(ws.join(p), body).unwrap();
    }
    let mut r = Rig::new(&ws);
    let files = |t: &str| -> Vec<String> {
        t.lines()
            .filter(|l| l.ends_with("(1 hit(s))"))
            .map(|l| l.trim_end_matches(" (1 hit(s))").to_owned())
            .collect()
    };
    // A name pattern matches at any depth.
    let t = search(&mut r, json!({"pattern": "needle", "include": "*.rs"}));
    assert_eq!(
        files(&t),
        ["src/lib.rs", "src/net/mod.rs", "target/debug/out.rs"]
    );
    // A path pattern matches below the search path; brace alternatives.
    let t = search(
        &mut r,
        json!({"pattern": "needle", "path": "src", "include": "*/*.{rs,md}"}),
    );
    assert_eq!(files(&t), ["src/net/mod.rs"]);
    let t = search(
        &mut r,
        json!({"pattern": "needle", "path": "src", "include": "*.{rs,md}"}),
    );
    assert_eq!(files(&t), ["src/lib.rs", "src/net/mod.rs", "src/notes.md"]);
    // An excluded directory is not entered; an excluded name is skipped.
    let t = search(
        &mut r,
        json!({"pattern": "needle", "exclude": "target", "include": "*.rs"}),
    );
    assert_eq!(files(&t), ["src/lib.rs", "src/net/mod.rs"]);
    let t = search(&mut r, json!({"pattern": "needle", "exclude": "*.md"}));
    assert_eq!(
        files(&t),
        [
            "Cargo.toml",
            "src/lib.rs",
            "src/net/mod.rs",
            "target/debug/out.rs"
        ]
    );
    let t = search(
        &mut r,
        json!({"pattern": "needle", "exclude": "{target,docs}/**"}),
    );
    assert_eq!(
        files(&t),
        ["Cargo.toml", "src/lib.rs", "src/net/mod.rs", "src/notes.md"]
    );
    // A bad glob is a typed error in static words.
    for (key, bad) in [
        ("include", "../*.rs"),
        ("exclude", "/abs"),
        ("include", "{a,b"),
    ] {
        let out = r.call("harness.fs.search", json!({"pattern": "x", key: bad}));
        assert_eq!(
            out.status,
            ToolStatus::Error {
                code: code::BAD_PATTERN
            },
            "{key} {bad}"
        );
        assert!(text(&out).starts_with(&format!("error: {key}: the glob pattern")));
    }
}

#[test]
fn h2e_context_lines_are_shown_grep_style() {
    let ws = scratch("context");
    let body: String = (1..=30)
        .map(|i| {
            if [5, 7, 20].contains(&i) {
                format!("hit {i}\n")
            } else {
                format!("line {i}\n")
            }
        })
        .collect();
    fs::write(ws.join("a.txt"), body).unwrap();
    let mut r = Rig::new(&ws);
    let t = search(&mut r, json!({"pattern": "hit", "context": 2}));
    assert_eq!(
        t,
        "3 hit(s) in 1 file(s) for a literal match\n\
         a.txt (3 hit(s))\n\
         \x20 3- line 3\n  4- line 4\n  5: hit 5\n  6- line 6\n  7: hit 7\n  8- line 8\n  9- line 9\n\
         \x20 --\n\
         \x20 18- line 18\n  19- line 19\n  20: hit 20\n  21- line 21\n  22- line 22\n"
    );
    // At the file's edges the window is clipped.
    let t = search(
        &mut r,
        json!({"pattern": "line 1\\b", "regex": true, "context": 5}),
    );
    assert!(
        t.contains("a.txt (1 hit(s))\n  1: line 1\n  2- line 2\n"),
        "{t}"
    );
}

// A judge-reviewed run (Qwen3-4B, a real repository): a capped search
// showed two files and hid the one with the answer. Every hit is counted,
// one file shows at most ten, and the files not shown are listed with
// their counts.
#[test]
fn h2e_one_file_cannot_hide_the_others() {
    let ws = scratch("fair");
    let many: String = (0..80).map(|i| format!("grade {i}\n")).collect();
    fs::write(ws.join("a-big.txt"), many).unwrap();
    fs::write(ws.join("z-answer.txt"), "the grade is here\n").unwrap();
    let mut r = Rig::new(&ws);
    let t = search(&mut r, json!({"pattern": "grade"}));
    assert!(
        t.starts_with("81 hit(s) in 2 file(s) for a literal match; 11 shown"),
        "{t}"
    );
    assert!(t.contains("a-big.txt (80 hits, 10 shown)\n"), "{t}");
    assert!(
        t.contains("z-answer.txt (1 hit(s))\n  1: the grade is here\n"),
        "{t}"
    );

    // Past the shown budget, every further file is listed with its count.
    let ws = scratch("fair-many");
    for f in 0..12 {
        let body: String = (0..10).map(|i| format!("grade {f}.{i}\n")).collect();
        fs::write(ws.join(format!("f{f:02}.txt")), body).unwrap();
    }
    let mut r = Rig::new(&ws);
    let t = search(&mut r, json!({"pattern": "grade"}));
    assert!(t.starts_with("120 hit(s) in 12 file(s)"), "{t}");
    assert!(t.contains("f04.txt (10 hit(s))"), "{t}");
    assert!(!t.contains("f05.txt (10 hit(s))"), "{t}");
    assert!(
        t.contains("more hits in: f05.txt (10), f06.txt (10), f07.txt (10), f08.txt (10), f09.txt (10), f10.txt (10), f11.txt (10)\n"),
        "{t}"
    );
    assert!(t.lines().count() <= 100, "{}", t.lines().count());
    assert!(t.len() <= 16 * 1024);
}

#[test]
fn h2e_a_long_hit_line_shows_the_text_around_its_match() {
    let ws = scratch("long");
    let line = format!("{}NEEDLE-HERE{}", "a".repeat(3000), "b".repeat(3000));
    fs::write(ws.join("min.js"), format!("{line}\nshort NEEDLE-HERE\n")).unwrap();
    let mut r = Rig::new(&ws);
    let t = search(&mut r, json!({"pattern": "NEEDLE-HERE"}));
    let first = t.lines().find(|l| l.starts_with("  1: ")).unwrap();
    assert!(first.contains("NEEDLE-HERE"), "{first}");
    assert!(
        first.starts_with("  1: …a") && first.ends_with("b…"),
        "{first}"
    );
    assert!(first.len() < 260, "{}", first.len());
    assert!(t.contains("  2: short NEEDLE-HERE\n"), "{t}");
    assert!(t.contains("read that line to see all of it"), "{t}");
}

#[test]
fn h2e_git_directories_are_skipped_below_the_start() {
    let ws = scratch("git");
    fs::create_dir_all(ws.join(".git/objects")).unwrap();
    fs::create_dir_all(ws.join("sub/.git")).unwrap();
    fs::write(ws.join(".git/objects/x"), "needle\n").unwrap();
    fs::write(ws.join("sub/.git/config"), "needle\n").unwrap();
    fs::write(ws.join("a.txt"), "needle\n").unwrap();
    let mut r = Rig::new(&ws);
    let t = search(&mut r, json!({"pattern": "needle"}));
    assert!(t.starts_with("1 hit(s) in 1 file(s)"), "{t}");
    assert!(t.contains("2 .git director(y/ies) skipped"), "{t}");
    // Asked for by path, it is searched.
    let t = search(&mut r, json!({"pattern": "needle", "path": ".git"}));
    assert!(t.contains(".git/objects/x (1 hit(s))"), "{t}");
    let g = text(&r.call("harness.fs.glob", json!({"pattern": "**/*"})));
    assert!(
        g.starts_with("1 file(s) match under .\na.txt (7 bytes)\n"),
        "{g}"
    );
}

#[test]
fn h2e_zero_hits_say_how_to_search() {
    let ws = scratch("zero");
    fs::write(ws.join("a.txt"), "fn main() {}\n").unwrap();
    let mut r = Rig::new(&ws);
    let t = search(&mut r, json!({"pattern": "the main function"}));
    assert!(
        t.starts_with("0 hit(s) in 0 file(s) for a literal match\n"),
        "{t}"
    );
    assert!(t.contains("exact identifier or word"), "{t}");
    assert!(!t.contains("regex characters"), "{t}");
    let t = search(&mut r, json!({"pattern": "nope\\d", "regex": true}));
    assert!(t.contains("check the expression"), "{t}");
    // A literal that looks like a regex (a local model's zero-hit search):
    // it says it was matched as plain text and how to make it a regex.
    let t = search(&mut r, json!({"pattern": "fn [a-z]+\\(", "regex": false}));
    assert!(t.starts_with("0 hit(s)"), "{t}");
    assert!(
        t.contains("the pattern holds regex characters but was matched as plain text"),
        "{t}"
    );
    assert!(t.contains("set regex true"), "{t}");
    let t = search(&mut r, json!({"pattern": "fn [a-z]+\\(", "regex": true}));
    assert!(
        t.starts_with("1 hit(s) in 1 file(s) for a regex match"),
        "{t}"
    );
}

#[test]
fn h2e_glob_finds_files_in_path_order_with_their_sizes() {
    let ws = scratch("glob");
    for p in [
        "Cargo.toml",
        "src/lib.rs",
        "src/net/mod.rs",
        "src/net/backoff.rs",
        "src/cli/mod.rs",
        "src/cli/args.txt",
        "docs/a.md",
    ] {
        fs::create_dir_all(ws.join(p).parent().unwrap()).unwrap();
        fs::write(ws.join(p), "12345").unwrap();
    }
    let mut r = Rig::new(&ws);
    let glob = |r: &mut Rig, a: Value| {
        let out = r.call("harness.fs.glob", a);
        assert_eq!(out.status, ToolStatus::Ok, "{}", text(&out));
        text(&out)
    };
    assert_eq!(
        glob(&mut r, json!({"pattern": "**/*.rs"})),
        "4 file(s) match under .\nsrc/cli/mod.rs (5 bytes)\nsrc/lib.rs (5 bytes)\nsrc/net/backoff.rs (5 bytes)\nsrc/net/mod.rs (5 bytes)\n"
    );
    assert_eq!(
        glob(&mut r, json!({"pattern": "src/*/mod.rs"})),
        "2 file(s) match under .\nsrc/cli/mod.rs (5 bytes)\nsrc/net/mod.rs (5 bytes)\n"
    );
    // Relative to path; results relative to the workspace root.
    assert_eq!(
        glob(&mut r, json!({"pattern": "*/mod.rs", "path": "src"})),
        "2 file(s) match under src\nsrc/cli/mod.rs (5 bytes)\nsrc/net/mod.rs (5 bytes)\n"
    );
    assert_eq!(
        glob(&mut r, json!({"pattern": "*.{toml,md}"})),
        "2 file(s) match under .\nCargo.toml (5 bytes)\ndocs/a.md (5 bytes)\n"
    );
    // Directories are not files.
    assert_eq!(
        glob(&mut r, json!({"pattern": "src/*"})),
        "1 file(s) match under .\nsrc/lib.rs (5 bytes)\n"
    );
    assert!(glob(&mut r, json!({"pattern": "*.py"})).starts_with("0 file(s) match under ."));
}

#[test]
fn h2e_glob_is_bounded_and_refuses_bad_patterns() {
    let ws = scratch("glob-bounds");
    for i in 0..100 {
        fs::write(ws.join(format!("f{i:03}.rs")), "").unwrap();
    }
    fs::write(ws.join("plain"), "").unwrap();
    let mut r = Rig::new(&ws);
    let t = text(&r.call("harness.fs.glob", json!({"pattern": "*.rs"})));
    assert!(
        t.starts_with("90 file(s) match under .; more not shown (the cap is 90)"),
        "{t:.100}"
    );
    assert!(t.contains("f089.rs") && !t.contains("f090.rs"), "{t}");
    for bad in ["../x", "/etc/*", "a//b", "a\\b", "[ab", "src/./x"] {
        let out = r.call("harness.fs.glob", json!({ "pattern": bad }));
        assert_eq!(
            out.status,
            ToolStatus::Error {
                code: code::BAD_PATTERN
            },
            "{bad}"
        );
        assert!(text(&out).starts_with("error: pattern: the glob pattern"));
    }
    let out = r.call("harness.fs.glob", json!({"pattern": "*", "path": "plain"}));
    assert_eq!(
        out.status,
        ToolStatus::Error {
            code: code::NOT_A_DIR
        }
    );
}

#[cfg(unix)]
mod inv_30 {
    use super::*;
    use std::os::unix::fs::symlink;

    fn rig(name: &str) -> Rig {
        let base = scratch(name);
        let outside = base.join("outside");
        let ws = base.join("ws");
        fs::create_dir_all(outside.join("deep")).unwrap();
        fs::create_dir(&ws).unwrap();
        fs::write(outside.join("secret.rs"), "TOP-SECRET-CONTENT\n").unwrap();
        fs::write(outside.join("deep/more.rs"), "TOP-SECRET-CONTENT\n").unwrap();
        fs::create_dir(ws.join("src")).unwrap();
        fs::write(ws.join("src/ok.rs"), "fine\n").unwrap();
        symlink(&outside, ws.join("linkdir")).unwrap();
        symlink(outside.join("secret.rs"), ws.join("src/linkfile.rs")).unwrap();
        Rig::new(&ws)
    }

    // The glob walks the same confined walk: a symlinked directory is not
    // entered, a symlinked file is not listed, and a start path through a
    // symlink is refused; none of the outside names or content appears.
    #[test]
    fn inv_30_the_glob_never_follows_or_lists_a_symlink() {
        let mut r = rig("inv30-glob");
        let t = text(&r.call("harness.fs.glob", json!({"pattern": "**/*.rs"})));
        assert_eq!(
            t,
            "1 file(s) match under .\nsrc/ok.rs (5 bytes)\n2 symlink(s) not followed\n"
        );
        let t = text(&r.call("harness.fs.glob", json!({"pattern": "linkdir/**"})));
        assert!(t.starts_with("0 file(s)") && !t.contains("secret"), "{t}");
        let out = r.call(
            "harness.fs.glob",
            json!({"pattern": "*", "path": "linkdir"}),
        );
        assert_eq!(
            out.status,
            ToolStatus::Error {
                code: code::SYMLINK
            }
        );
        // The search's filters cannot reach through one either.
        let t = text(&r.call(
            "harness.fs.search",
            json!({"pattern": "TOP-SECRET", "include": "linkdir/**"}),
        ));
        assert!(t.starts_with("0 hit(s)"), "{t}");
        let out = r.call(
            "harness.fs.search",
            json!({"pattern": "TOP", "path": "linkdir/deep", "regex": true}),
        );
        assert_eq!(
            out.status,
            ToolStatus::Error {
                code: code::SYMLINK
            }
        );
    }

    // A path that climbs out is refused by policy before the tool runs, for
    // the glob's path as for every read tool's.
    #[test]
    fn inv_30_a_glob_path_outside_the_workspace_never_reaches_the_tool() {
        let r = rig("inv30-glob-path");
        for path in ["..", "../outside", "/etc", "src/../../outside", ""] {
            let refused = r.s.authorize(Call {
                capability: "harness.fs.glob".into(),
                args: json!({"pattern": "*", "path": path}),
            });
            assert!(refused.is_err(), "{path}");
        }
    }
}

// A pattern where a path belongs is the likely mistake: the error says
// where a pattern goes (a local model searched `path: "src/**"` three times
// and got only "no such file or directory"). A plain missing path keeps the
// plain message.
#[test]
fn h2e_a_pattern_in_a_path_is_answered_with_where_patterns_go() {
    let ws = scratch("pattern-path");
    fs::create_dir(ws.join("src")).unwrap();
    fs::write(ws.join("src/a.rs"), "x\n").unwrap();
    let mut r = Rig::new(&ws);
    for (cap, args) in [
        (
            "harness.fs.search",
            json!({"pattern": "x", "path": "src/**"}),
        ),
        (
            "harness.fs.glob",
            json!({"pattern": "*.rs", "path": "src/*"}),
        ),
        ("harness.fs.read", json!({"path": "src/{a,b}.rs"})),
    ] {
        let out = r.call(cap, args.clone());
        assert_eq!(
            out.status,
            ToolStatus::Error {
                code: code::NOT_FOUND
            },
            "{args}"
        );
        assert!(
            text(&out).contains("not a pattern (a glob goes in the search's include or exclude"),
            "{args}: {}",
            text(&out)
        );
    }
    let out = r.call("harness.fs.read", json!({"path": "src/missing.rs"}));
    assert_eq!(text(&out), "error: no such file or directory");
}

// H2f: a display cut by its size is shown again with less context, so every
// hit is there, and the result says so.
#[test]
fn h2f_less_context_before_fewer_hits() {
    let ws = scratch("shrink");
    for f in 0..6 {
        let body: String = (1..=30)
            .map(|i| {
                if i == 5 || i == 20 {
                    format!("grade {f}.{i}\n")
                } else {
                    format!("filler {i}\n")
                }
            })
            .collect();
        fs::write(ws.join(format!("f{f}.txt")), body).unwrap();
    }
    let mut r = Rig::new(&ws);
    let t = search(&mut r, json!({"pattern": "grade", "context": 3}));
    assert!(
        t.starts_with("12 hit(s) in 6 file(s) for a literal match\n"),
        "{t}"
    );
    assert!(!t.contains("more hits in"), "{t}");
    assert!(
        t.contains("context was reduced from 3 to 1 line(s) so that more hits fit"),
        "{t}"
    );
    for f in 0..6 {
        assert!(t.contains(&format!("grade {f}.5")), "{t}");
        assert!(t.contains(&format!("grade {f}.20")), "{t}");
    }
    // Context that fits is left alone, and no note is made.
    let t = search(&mut r, json!({"pattern": "grade 0.5", "context": 3}));
    assert!(!t.contains("context was reduced"), "{t}");
    // A cut by the hit caps is not made better by less context: no note.
    let ws = scratch("shrink-caps");
    let many: String = (0..80).map(|i| format!("grade {i}\n")).collect();
    fs::write(ws.join("a.txt"), many).unwrap();
    let mut r = Rig::new(&ws);
    let t = search(&mut r, json!({"pattern": "grade", "context": 2}));
    assert!(!t.contains("context was reduced"), "{t}");
}

// H2f: filters that match no file are named, not the pattern.
#[test]
fn h2f_filters_that_match_nothing_are_told() {
    let ws = scratch("filters-none");
    fs::create_dir(ws.join("src")).unwrap();
    fs::write(ws.join("src/a.rs"), "fn a() {}\n").unwrap();
    let mut r = Rig::new(&ws);
    // include is relative to path: the path prefix in it matches nothing.
    let t = search(
        &mut r,
        json!({"pattern": "fn", "path": "src", "include": "src/a.rs"}),
    );
    assert!(t.contains("0 hit(s)"), "{t}");
    assert!(
        t.contains("no file matched the include/exclude filters, so nothing was searched"),
        "{t}"
    );
    assert!(!t.contains("no line matched"), "{t}");
    let t = search(&mut r, json!({"pattern": "fn", "exclude": "**"}));
    assert!(
        t.contains("no file matched the include/exclude filters"),
        "{t}"
    );
    // Filters that match a file, and a pattern that matches nothing in it:
    // the pattern's own hint.
    let t = search(
        &mut r,
        json!({"pattern": "nothing-here", "path": "src", "include": "*.rs"}),
    );
    assert!(t.contains("no line matched"), "{t}");
    assert!(!t.contains("no file matched the include/exclude"), "{t}");
    // No filters, no such words.
    let t = search(&mut r, json!({"pattern": "nothing-here"}));
    assert!(t.contains("no line matched"), "{t}");
    // A filter that matches, with hits: nothing extra.
    let t = search(
        &mut r,
        json!({"pattern": "fn", "path": "src", "include": "a.rs"}),
    );
    assert!(t.starts_with("1 hit(s) in 1 file(s)"), "{t}");
}

// ---- P-12: policy-denied paths are skipped, and the count is said ----------------

/// A rig planned under the CLI's default deny policy, whose tools carry the
/// policy's own compiled globs (the run driver's wiring, P-12).
fn denied_rig(ws: &Path) -> Rig {
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
    Rig {
        w,
        s,
        t: ReadTools::new(ws).unwrap().with_denied(globs),
        step: 0,
    }
}

fn denied_ws(name: &str) -> PathBuf {
    let ws = scratch(name);
    fs::write(ws.join(".env"), "SECRET=1\nneedle\n").unwrap();
    fs::write(ws.join(".env.local"), "SECRET=2\n").unwrap();
    fs::create_dir(ws.join("keys")).unwrap();
    fs::write(ws.join("keys/server.pem"), "needle in pem\n").unwrap();
    fs::write(ws.join("keys/server.key"), "raw key material\n").unwrap();
    fs::write(ws.join("a.txt"), "needle here\n").unwrap();
    fs::create_dir(ws.join("sub")).unwrap();
    fs::write(ws.join("sub/b.txt"), "another needle\n").unwrap();
    fs::write(ws.join("sub/c.txt"), "nothing\n").unwrap();
    ws
}

#[test]
fn search_skips_denied_files_and_counts_them() {
    let ws = denied_ws("denied-search");
    let mut r = denied_rig(&ws);
    let t = search(&mut r, json!({"pattern": "needle"}));
    assert!(
        t.starts_with("2 hit(s) in 2 file(s) for a literal match\n"),
        "{t}"
    );
    assert!(t.contains("a.txt (1 hit(s))\n"), "{t}");
    assert!(t.contains("sub/b.txt (1 hit(s))\n"), "{t}");
    // The denied files are neither searched nor named, and the count says
    // so (never silently: the model can tell denied from absent).
    assert!(!t.contains(".env"), "{t}");
    assert!(!t.contains("SECRET"), "{t}");
    assert!(!t.contains("server.pem"), "{t}");
    assert!(!t.contains("server.key"), "{t}");
    assert_eq!(
        t.lines().last(),
        Some("4 path(s) skipped (denied by policy)")
    );
}

#[test]
fn glob_and_list_hide_denied_but_report_count() {
    let ws = denied_ws("denied-glob-list");
    let mut r = denied_rig(&ws);
    let out = r.call("harness.fs.glob", json!({"pattern": "**"}));
    assert_eq!(out.status, ToolStatus::Ok, "{}", text(&out));
    let t = text(&out);
    assert!(t.starts_with("3 file(s) match under .\n"), "{t}");
    assert!(t.contains("a.txt ("), "{t}");
    assert!(t.contains("sub/b.txt ("), "{t}");
    assert!(t.contains("sub/c.txt ("), "{t}");
    assert!(!t.contains(".env"), "{t}");
    assert!(!t.contains("server.pem"), "{t}");
    assert!(t.contains("4 path(s) skipped (denied by policy)"), "{t}");

    // The listing hides the denied entries too, says how many were skipped,
    // and its count reflects what is shown, not what is on disk.
    let out = r.call("harness.fs.list", json!({"path": ".", "depth": 2}));
    assert_eq!(out.status, ToolStatus::Ok, "{}", text(&out));
    let t = text(&out);
    assert!(t.starts_with("5 entr(y/ies) under .\n"), "{t}");
    assert!(t.contains("f a.txt "), "{t}");
    assert!(t.contains("d keys\n"), "{t}");
    assert!(t.contains("d sub\n"), "{t}");
    assert!(t.contains("f sub/b.txt "), "{t}");
    assert!(t.contains("f sub/c.txt "), "{t}");
    assert!(!t.contains(".env"), "{t}");
    assert!(!t.contains("server.pem"), "{t}");
    assert!(!t.contains("server.key"), "{t}");
    assert_eq!(
        t.lines().last(),
        Some("4 path(s) skipped (denied by policy)")
    );
}
