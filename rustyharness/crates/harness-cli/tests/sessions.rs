//! P-14: the `sessions` verb, the `run` bundle in `runs/<id>/inputs/`, and
//! the `gc` verb, end to end against a mock OpenAI-compatible server. Every
//! invocation here calls the CLI library in process with the permissive
//! probe, so the tests run on every OS.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// A local-APFS answer for any path: the shared testkit probe.
use harness_testkit::Local;

// ---- a mock model server -------------------------------------------------------

struct Mock {
    port: u16,
}

fn read_request(s: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..i]).to_ascii_lowercase();
            let len = head
                .lines()
                .find_map(|l| {
                    l.strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if buf.len() >= i + 4 + len {
                return String::from_utf8_lossy(&buf).into_owned();
            }
        }
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return String::from_utf8_lossy(&buf).into_owned(),
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
}

fn respond(s: &mut TcpStream, body: &str) {
    let _ = write!(
        s,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: mock-llm 1.0\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
}

/// Serves `GET /v1/models` (model `m`) and answers each chat completion
/// with the next scripted content.
fn mock(replies: Vec<String>) -> Mock {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let queue = Arc::new(Mutex::new(VecDeque::from(replies)));
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            let req = read_request(&mut s);
            if req.starts_with("GET /v1/models ") {
                respond(&mut s, r#"{"data":[{"id":"m"}]}"#);
            } else {
                let content = queue.lock().unwrap().pop_front().unwrap_or_default();
                let body = serde_json::json!({
                    "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 100, "completion_tokens": 10}
                })
                .to_string();
                respond(&mut s, &body);
            }
        }
    });
    Mock { port }
}

fn act(tool: &str, args: &str) -> String {
    format!("ok <action>{{\"tool\":\"{tool}\",\"args\":{args}}}</action>")
}

// ---- fixtures ---------------------------------------------------------------------

const PROFILE: &str = r#"{"profile_version":1,"id":"mock-m","model":"m",
  "context_window":32768,"fill_ratio":0.6,"protocol":"text","tool_choice_required_ok":false,
  "grammar":"none","max_active_tools":6,"edit_format":"replace","recent_turns":5,
  "sampling":{"temperature":0.2,"top_p":0.95,"seed":7,"max_tokens":2048}}"#;

struct Fx {
    state: PathBuf,
    ws: PathBuf,
    task: PathBuf,
    profile: PathBuf,
    marker: PathBuf,
}

fn fixture(name: &str) -> Fx {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("sessions-{name}"));
    let _ = std::fs::remove_dir_all(&base);
    let (state, ws) = (base.join("state"), base.join("ws"));
    std::fs::create_dir_all(&state).unwrap();
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::write(ws.join("a.txt"), "the answer is in here\n").unwrap();
    let task = base.join("task.json");
    std::fs::write(
        &task,
        r#"{"task":"What does a.txt say?","grants":["harness.fs.read","harness.fs.list"]}"#,
    )
    .unwrap();
    let profile = base.join("profile.json");
    std::fs::write(&profile, PROFILE).unwrap();
    Fx {
        marker: base.join("gate-ok"),
        state,
        ws,
        task,
        profile,
    }
}

/// What a CLI invocation produced.
struct Output {
    code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Output {
    fn out(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    fn err(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// The CLI library in process, with the permissive probe.
fn cli(args: &[&str], marker: &Path) -> Output {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = {
        let cx = harness_cli::Cx {
            probe: &Local,
            gate_ok_file: Some(marker.to_path_buf()),
            out: RefCell::new(&mut out),
            err: RefCell::new(&mut err),
            approver: harness_cli::ApproverSource::None,
            input: harness_cli::InputSource::Given(&[]),
            backend: harness_cli::BackendSource::BuiltIn,
            confinement: &harness_sandbox::SystemConfinement,
        };
        harness_cli::main_with(&cx, args)
    };
    Output {
        code: i32::from(code),
        stdout: out,
        stderr: err,
    }
}

fn run_args<'a>(fx: &'a Fx, endpoint: &'a str) -> Vec<&'a str> {
    vec![
        "run",
        "--task",
        fx.task.to_str().unwrap(),
        "--workspace",
        fx.ws.to_str().unwrap(),
        "--state-root",
        fx.state.to_str().unwrap(),
        "--profile",
        fx.profile.to_str().unwrap(),
        "--endpoint",
        endpoint,
    ]
}

fn report(o: &Output) -> serde_json::Value {
    serde_json::from_str(o.out().lines().last().unwrap_or("")).unwrap()
}

fn run_id(o: &Output) -> String {
    let err = o.err();
    let at = err.find("run ").unwrap() + 4;
    err[at..at + 32].to_owned()
}

/// One finished run (a read, then a submit; exit 5, nothing checked),
/// identified by its run id.
fn run_once(fx: &Fx, name: &str) -> String {
    let m = mock(vec![
        act("harness.fs.read", r#"{"path":"a.txt"}"#),
        act("harness.task.submit", r#"{"note":"done"}"#),
    ]);
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let o = cli(&run_args(fx, &ep), &fx.marker);
    assert_eq!(o.code, 5, "{name}: stderr: {}", o.err());
    assert_eq!(
        report(&o)["outcome"]["Indeterminate"]["why"],
        "NothingChecked",
        "{name}"
    );
    run_id(&o)
}

fn run_dir_of(fx: &Fx, id: &str) -> PathBuf {
    fx.state.join("runs").join(id)
}

fn journal_of(fx: &Fx, id: &str) -> PathBuf {
    run_dir_of(fx, id).join("attempt-1").join("journal.jsonl")
}

fn inputs_of(fx: &Fx, id: &str) -> PathBuf {
    run_dir_of(fx, id).join("inputs")
}

/// What `replay` says of an attempt it matched (H1 phase-exit review,
/// named item 2).
const REPLAY_MATCHED: &str = "records matched. Re-fed from the journal, not re-run: the model replies, the tool results and the environment samples. Recomputed and compared: every context, parse, loop-detector and policy decision, and the stop.";

// ---- the tests ---------------------------------------------------------------------

#[test]
fn sessions_lists_runs_newest_first() {
    let fx = fixture("list");
    let first = run_once(&fx, "first");
    // Distinct wall-clock starts, so the order is forced.
    thread::sleep(Duration::from_millis(5));
    let second = run_once(&fx, "second");
    let o = cli(
        &["sessions", "--state-root", fx.state.to_str().unwrap()],
        &fx.marker,
    );
    assert_eq!(o.code, 0, "{}", o.err());
    let err = o.err();
    assert!(err.contains("2 run(s) in "), "{err}");
    let out = o.out();
    let rows: Vec<&str> = out.lines().collect();
    assert_eq!(rows.len(), 2, "{out}");
    assert!(rows[0].starts_with(&second), "{out}");
    assert!(rows[1].starts_with(&first), "{out}");
    for r in &rows {
        assert!(r.contains("steps=2"), "{r}");
        assert!(r.contains("stop=submitted"), "{r}");
        assert!(r.contains("outcome=indeterminate:nothing_checked"), "{r}");
        assert!(r.contains("head="), "{r}");
        assert!(r.contains(&format!("workspace={}", fx.ws.display())), "{r}");
        assert!(r.contains("task=\"What does a.txt say?\""), "{r}");
    }
    // `sessions show` adds its words on stderr.
    let o = cli(
        &[
            "sessions",
            "show",
            "--run",
            &first,
            "--state-root",
            fx.state.to_str().unwrap(),
        ],
        &fx.marker,
    );
    assert_eq!(o.code, 0, "{}", o.err());
    assert!(o.err().contains("committed"), "{}", o.err());
    assert_eq!(o.out().lines().count(), 1);
}

#[test]
fn sessions_marks_tampered_journal_unreadable() {
    let fx = fixture("tamper");
    let id = run_once(&fx, "tampered");
    let j = journal_of(&fx, &id);
    let mut bytes = std::fs::read(&j).unwrap();
    // One flipped byte anywhere in the journal breaks the verifying read.
    let at = bytes.len() - 5;
    bytes[at] = if bytes[at] == b'x' { b'y' } else { b'x' };
    std::fs::write(&j, &bytes).unwrap();
    let o = cli(
        &["sessions", "--state-root", fx.state.to_str().unwrap()],
        &fx.marker,
    );
    assert_eq!(o.code, 0, "{}", o.err());
    let out = o.out();
    let rows: Vec<&str> = out.lines().collect();
    assert_eq!(rows.len(), 1, "{out}");
    assert!(rows[0].starts_with(&format!("{id} UNREADABLE (")), "{out}");
    // `show` says the same, fail-closed, never a silent skip.
    let o = cli(
        &[
            "sessions",
            "show",
            "--run",
            &id,
            "--state-root",
            fx.state.to_str().unwrap(),
        ],
        &fx.marker,
    );
    assert_eq!(o.code, 0, "{}", o.err());
    assert!(o.err().contains("unreadable"), "{}", o.err());
}

#[test]
fn sessions_sanitises_task_text() {
    let fx = fixture("sanitise");
    // A task text with a raw escape, a newline and far more bytes than the
    // preview bound.
    let task_text = format!("{} \u{1b}[31mred\u{1b}[0m\nnext line", "a".repeat(100));
    std::fs::write(
        &fx.task,
        serde_json::json!({
            "task": task_text,
            "grants": ["harness.fs.read", "harness.fs.list"]
        })
        .to_string(),
    )
    .unwrap();
    let _ = run_once(&fx, "sanitised");
    let o = cli(
        &["sessions", "--state-root", fx.state.to_str().unwrap()],
        &fx.marker,
    );
    assert_eq!(o.code, 0, "{}", o.err());
    let out = o.out();
    // One line: the raw control bytes never reach the terminal.
    assert_eq!(out.lines().count(), 1, "{out}");
    assert!(!out.contains('\u{1b}'), "{out}");
    // The preview is bounded, and says so.
    assert!(out.contains("bytes cut"), "{out}");
    assert!(out.contains("task=\""), "{out}");
}

#[test]
fn bundle_written_with_matching_digests() {
    let fx = fixture("bundle");
    let id = run_once(&fx, "bundled");
    let inputs = inputs_of(&fx, &id);
    // The copies are byte-for-byte the files the run was given.
    assert_eq!(
        std::fs::read(inputs.join("task.json")).unwrap(),
        std::fs::read(&fx.task).unwrap()
    );
    assert_eq!(
        std::fs::read(inputs.join("profile.json")).unwrap(),
        std::fs::read(&fx.profile).unwrap()
    );
    // No policy file was given, so none is copied, and the bundle says so.
    assert!(!inputs.join("policy.json").exists());
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(inputs.join("bundle.json")).unwrap())
            .unwrap();
    assert_eq!(doc["format"], "rh-bundle/1");
    assert_eq!(doc["policy"], "default");
    assert_eq!(doc["workspace"], fx.ws.to_str().unwrap());
    assert!(
        doc["endpoint"]
            .as_str()
            .unwrap()
            .starts_with("http://127.0.0.1:"),
        "{}",
        doc["endpoint"]
    );
    // The digests are the header's.
    let v = harness_journal::JournalReader::open(&run_dir_of(&fx, &id).join("attempt-1")).unwrap();
    assert_eq!(
        doc["task_sha256"],
        v.records[0].body["task"].as_str().unwrap()
    );
    assert_eq!(
        doc["profile_sha256"],
        v.records[0].body["profile"].as_str().unwrap()
    );
    assert_eq!(
        doc["policy_sha256"],
        v.records[0].body["policy"].as_str().unwrap()
    );
    // Private: the bundle copies are mode 0600, the directory 0700.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(m(&inputs.join("bundle.json")), 0o600);
        assert_eq!(m(&inputs.join("task.json")), 0o600);
        assert_eq!(m(&inputs), 0o700);
    }
}

#[test]
fn replay_with_only_run_id_uses_bundle() {
    let fx = fixture("replay");
    let id = run_once(&fx, "replayed");
    // No --task, no --profile, no --endpoint: the bundle answers for them.
    let o = cli(
        &[
            "replay",
            "--run",
            &id,
            "--state-root",
            fx.state.to_str().unwrap(),
        ],
        &fx.marker,
    );
    assert_eq!(o.code, 5, "{}", o.err());
    assert_eq!(
        report(&o)["outcome"]["Indeterminate"]["why"],
        "NothingChecked"
    );
    assert!(o.err().contains(REPLAY_MATCHED), "{}", o.err());
}

/// The bundle's default-policy digest is the run's own reading of
/// "no --policy": a run under `--no-default-denies` replays only under the
/// same setting, and a replay under the other setting is refused by name
/// (the effective policy — defaults included — is what the header digests).
#[test]
fn replay_under_the_other_default_deny_setting_is_refused() {
    let fx = fixture("deny-setting");
    let m = mock(vec![
        act("harness.fs.read", r#"{"path":"a.txt"}"#),
        act("harness.task.submit", r#"{"note":"done"}"#),
    ]);
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let mut args = run_args(&fx, &ep);
    args.push("--no-default-denies");
    let o = cli(&args, &fx.marker);
    assert_eq!(o.code, 5, "{}", o.err());
    let id = run_id(&o);
    let replay = |extra: &[&str]| {
        let mut a = vec![
            "replay",
            "--run",
            &id,
            "--state-root",
            fx.state.to_str().unwrap(),
        ];
        a.extend_from_slice(extra);
        cli(&a, &fx.marker)
    };
    // The same setting: the recomputed default policy digests to the run's.
    let same = replay(&["--no-default-denies"]);
    assert_eq!(same.code, 5, "{}", same.err());
    assert!(same.err().contains(REPLAY_MATCHED), "{}", same.err());
    // The other setting: a different effective policy, refused before
    // anything runs.
    let other = replay(&[]);
    assert_eq!(other.code, 4, "{}", other.err());
    assert!(
        other.err().contains("does not match the digests recorded"),
        "{}",
        other.err()
    );
}

#[test]
fn bundle_digest_mismatch_refused() {
    let fx = fixture("mismatch");
    let id = run_once(&fx, "mismatched");
    // The copied task no longer digests to what the bundle recorded.
    std::fs::write(
        inputs_of(&fx, &id).join("task.json"),
        r#"{"task":"a different task","grants":["harness.fs.read","harness.fs.list"]}"#,
    )
    .unwrap();
    let o = cli(
        &[
            "replay",
            "--run",
            &id,
            "--state-root",
            fx.state.to_str().unwrap(),
        ],
        &fx.marker,
    );
    assert_eq!(o.code, 4, "{}", o.err());
    assert!(
        o.err().contains("does not match the digests recorded"),
        "{}",
        o.err()
    );
}

#[test]
fn gc_removes_scratch_keeps_journal() {
    let fx = fixture("gc-one");
    let id = run_once(&fx, "cleaned");
    let run_dir = run_dir_of(&fx, &id);
    std::fs::create_dir_all(run_dir.join("scratch")).unwrap();
    std::fs::write(run_dir.join("scratch").join("o.txt"), "bulk").unwrap();
    std::fs::create_dir_all(run_dir.join("workspace")).unwrap();
    std::fs::write(run_dir.join("workspace").join("w.txt"), "w").unwrap();
    let journal_before = std::fs::read(journal_of(&fx, &id)).unwrap();
    let o = cli(
        &[
            "gc",
            "--run",
            &id,
            "--state-root",
            fx.state.to_str().unwrap(),
        ],
        &fx.marker,
    );
    assert_eq!(o.code, 0, "{}", o.err());
    assert!(!run_dir.join("scratch").exists(), "scratch removed");
    assert!(!run_dir.join("workspace").exists(), "workspace removed");
    // The evidence is untouched: journal, attempt dir, blobs, inputs.
    assert_eq!(std::fs::read(journal_of(&fx, &id)).unwrap(), journal_before);
    assert!(run_dir.join("attempt-1").exists());
    assert!(inputs_of(&fx, &id).join("bundle.json").exists());
    assert!(o.err().contains("removed the bulk"), "{}", o.err());
}

#[test]
fn gc_refuses_active_run() {
    let fx = fixture("gc-active");
    let id = run_once(&fx, "active");
    // A run whose latest attempt has not committed may still be active
    // (the journal is single-writer, with no lock to check): drop its
    // final RunStopped line and the run looks uncommitted again.
    let j = journal_of(&fx, &id);
    let text = std::fs::read_to_string(&j).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    assert!(lines.len() > 2);
    lines.pop();
    std::fs::write(&j, format!("{}\n", lines.join("\n"))).unwrap();
    let run_dir = run_dir_of(&fx, &id);
    std::fs::create_dir_all(run_dir.join("scratch")).unwrap();
    let o = cli(
        &[
            "gc",
            "--run",
            &id,
            "--state-root",
            fx.state.to_str().unwrap(),
        ],
        &fx.marker,
    );
    assert_eq!(o.code, 1, "{}", o.err());
    assert!(o.err().contains("may still be active"), "{}", o.err());
    // Nothing was removed.
    assert!(run_dir.join("scratch").exists());
}

#[test]
fn gc_is_idempotent() {
    let fx = fixture("gc-twice");
    let id = run_once(&fx, "twice");
    let run_dir = run_dir_of(&fx, &id);
    std::fs::create_dir_all(run_dir.join("scratch")).unwrap();
    let args = [
        "gc",
        "--run",
        id.as_str(),
        "--state-root",
        fx.state.to_str().unwrap(),
    ];
    let o = cli(&args, &fx.marker);
    assert_eq!(o.code, 0, "{}", o.err());
    assert!(o.err().contains("removed the bulk"), "{}", o.err());
    // The second pass finds nothing to remove, and still succeeds.
    let o = cli(&args, &fx.marker);
    assert_eq!(o.code, 0, "{}", o.err());
    assert!(o.err().contains("nothing to remove"), "{}", o.err());
}
