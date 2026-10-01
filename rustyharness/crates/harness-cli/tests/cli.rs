//! The `rustyharness` CLI as a gate child (design §7.7), end to end against
//! a mock OpenAI-compatible server on loopback.
//!
//! The real binary always uses the real per-OS probe
//! (`harness_sandbox::locality::SystemProbe`, spike S-F1). It measures Linux
//! and macOS; on Windows it refuses every `state_root` until spike S-W1
//! ([`REAL_PROBE_MEASURES`]). Tests that need a run to start on EVERY OS
//! call the CLI library in process with this file's permissive probe; the
//! whole-run test uses the real binary where its probe measures and, on
//! Windows, first proves the real binary refuses. No build of the binary
//! can be switched to another probe, and the tests set the old switch
//! variable to prove it is ignored (H1e-2b review F-2).

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
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use gate_outcome::child::{interpret, ChildRun, ExitKind};
use gate_outcome::{GateId, GateOutcome, IndeterminateKind};
use harness_policy::locality::{FsQuery, LocalityProbe};

const BIN: &str = env!("CARGO_BIN_EXE_rustyharness");

// ---- a mock model server -------------------------------------------------------

struct Mock {
    port: u16,
    /// Every request, GET and POST.
    requests: Arc<Mutex<usize>>,
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
    mock_with(replies, |_| {})
}

/// [`mock`], calling `on_chat` with each chat request (head and body)
/// before answering it, while the harness waits for the reply.
fn mock_with(replies: Vec<String>, on_chat: impl Fn(&str) + Send + 'static) -> Mock {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let queue = Arc::new(Mutex::new(VecDeque::from(replies)));
    let requests = Arc::new(Mutex::new(0usize));
    let p = requests.clone();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            let req = read_request(&mut s);
            *p.lock().unwrap() += 1;
            if req.starts_with("GET /v1/models ") {
                respond(&mut s, r#"{"data":[{"id":"m"}]}"#);
            } else {
                on_chat(&req);
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
    Mock { port, requests }
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
    base: PathBuf,
    state: PathBuf,
    ws: PathBuf,
    task: PathBuf,
    profile: PathBuf,
    marker: PathBuf,
}

fn fixture(name: &str) -> Fx {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("cli-{name}"));
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
        base,
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
    fn code(&self) -> Option<i32> {
        Some(self.code)
    }
}

/// A local-APFS answer for any path: only these tests have it.
struct Local;
impl LocalityProbe for Local {
    fn query(&self, _path: &str) -> FsQuery {
        FsQuery::MacOs {
            mnt_local: true,
            fs_type_name: "apfs".into(),
        }
    }
}

/// Whether the real binary's probe measures this OS (spike S-F1: Linux and
/// macOS). Elsewhere, Windows included until spike S-W1, it answers
/// `Unmeasured` and every `state_root` is refused (design §2.8).
const REAL_PROBE_MEASURES: bool = cfg!(any(target_os = "linux", target_os = "macos"));

/// `local = true`: the CLI library in process with the permissive probe.
/// `local = false`: the real binary (always the real probe), with the
/// variable that once switched the probe set, to show it switches nothing.
fn cli(args: &[&str], local: bool, marker: &Path) -> Output {
    if local {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = {
            let cx = harness_cli::Cx {
                probe: &Local,
                gate_ok_file: Some(marker.to_path_buf()),
                out: RefCell::new(&mut out),
                err: RefCell::new(&mut err),
            };
            harness_cli::main_with(&cx, args)
        };
        return Output {
            code: i32::from(code),
            stdout: out,
            stderr: err,
        };
    }
    let o = Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
        .env("GATE_OK_FILE", marker)
        .env("RUSTYHARNESS_TEST_PROBE", "local")
        .output()
        .unwrap();
    Output {
        code: o.status.code().unwrap(),
        stdout: o.stdout,
        stderr: o.stderr,
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

fn last_line(o: &Output) -> String {
    String::from_utf8(o.stdout.clone())
        .unwrap()
        .lines()
        .last()
        .unwrap_or("")
        .to_owned()
}

fn report(o: &Output) -> serde_json::Value {
    serde_json::from_str(&last_line(o)).unwrap()
}

/// What a parent gate runner makes of this child (UNIFIED §6).
fn as_parent_sees(o: &Output, gate: &str, marker: &Path, speaks: bool) -> GateOutcome {
    let run = ChildRun::new(
        GateId::new(gate).unwrap(),
        ExitKind::Code(o.code().unwrap()),
        last_line(o),
        std::fs::read_to_string(marker).ok(),
        false,
        harness_core::sha256(&o.stdout),
        speaks,
    );
    interpret(&run).outcome().clone()
}

fn run_id(o: &Output) -> String {
    let err = String::from_utf8_lossy(&o.stderr);
    let at = err.find("run ").unwrap() + 4;
    err[at..at + 32].to_owned()
}

const NOTHING_CHECKED: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::NothingChecked,
};

// ---- the tests ---------------------------------------------------------------------

/// The real binary refused `state_root` as not local: before anything was
/// written under it or the model server was asked (design §2.8, INV-35).
fn assert_refused_as_not_local(o: &Output, m: &Mock, state_root: &Path, marker: &Path) {
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.code(), Some(5), "stderr: {err}");
    let r = report(o);
    assert_eq!(r["outcome"]["Indeterminate"]["why"], "CouldNotRun");
    assert_eq!(r["gate"], "rustyharness.run");
    assert!(
        err.contains("not on a filesystem identified as local"),
        "stderr: {err}"
    );
    if !REAL_PROBE_MEASURES {
        // Unmeasured, and the refusal says why (§2.8: the message names
        // what was detected).
        assert!(err.contains("spike S-W1"), "stderr: {err}");
    }
    assert!(!state_root.join("runs").exists(), "nothing was written");
    assert_eq!(
        *m.requests.lock().unwrap(),
        0,
        "the model server was never contacted"
    );
    assert!(!marker.exists());
    assert_eq!(
        as_parent_sees(o, "rustyharness.run", marker, true),
        GateOutcome::Indeterminate {
            why: IndeterminateKind::CouldNotRun
        }
    );
}

#[test]
fn inv_35_the_binary_refuses_a_state_root_not_identified_as_local() {
    // Where the real probe measures, `/dev` is devfs (macOS) or devtmpfs
    // (Linux): not an admitted local filesystem. Where it does not (Windows
    // until spike S-W1), every state root is refused, so the fixture's own
    // is. Either way the refusal comes before anything is written or the
    // model server is asked, even with the old switch variable set.
    let fx = fixture("refused");
    let m = mock(vec![]);
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let state_root = if REAL_PROBE_MEASURES {
        Path::new("/dev")
    } else {
        fx.state.as_path()
    };
    let mut args = run_args(&fx, &ep);
    let at = args.iter().position(|a| *a == "--state-root").unwrap() + 1;
    args[at] = state_root.to_str().unwrap();
    let o = cli(&args, false, &fx.marker);
    assert_refused_as_not_local(&o, &m, state_root, &fx.marker);
}

#[test]
fn a_whole_run_is_nothing_checked_exit_5_no_marker_and_prints_its_chain_head() {
    let fx = fixture("run");
    let m = mock(vec![
        act("harness.fs.read", r#"{"path":"a.txt"}"#),
        act(
            "harness.task.submit",
            r#"{"note":"it says the answer is in here"}"#,
        ),
    ]);
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    // Where the real probe measures (spike S-F1), the real binary runs: the
    // state root under the target directory is on a local disk. Where it
    // does not (Windows until spike S-W1), the real binary must refuse that
    // same state root; the run is then driven in process with the permissive
    // probe, so everything after the locality check is still covered on
    // every OS. The refusal contacted no server, so the replies are unused.
    let o = if REAL_PROBE_MEASURES {
        cli(&run_args(&fx, &ep), false, &fx.marker)
    } else {
        let refused = cli(&run_args(&fx, &ep), false, &fx.marker);
        assert_refused_as_not_local(&refused, &m, &fx.state, &fx.marker);
        cli(&run_args(&fx, &ep), true, &fx.marker)
    };
    let stdout = String::from_utf8(o.stdout.clone()).unwrap();
    assert_eq!(
        o.code(),
        Some(5),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{stdout}");
    let head = lines[0].strip_prefix("chain_head ").unwrap();
    assert_eq!(head.len(), 64);
    let r = report(&o);
    assert_eq!(r["outcome"]["Indeterminate"]["why"], "NothingChecked");
    assert_eq!(
        r["findings"][0]["observed"],
        "stopped: submitted; no checks planned"
    );
    assert!(!fx.marker.exists(), "no marker for a run that did not pass");
    // §9 H1: the outcome is shown to the user in words.
    assert!(String::from_utf8_lossy(&o.stderr).contains(
        "outcome: Indeterminate (NothingChecked): this task plans no checks, so nothing has verified the result; it is not a pass"
    ));
    // The parent's view, under both child conventions: never a pass.
    assert_eq!(
        as_parent_sees(&o, "rustyharness.run", &fx.marker, true),
        NOTHING_CHECKED
    );
    assert!(matches!(
        as_parent_sees(&o, "rustyharness.run", &fx.marker, false),
        GateOutcome::Indeterminate { .. }
    ));
    // The printed head is the journal's.
    let id = run_id(&o);
    let j = fx.state.join("runs").join(&id).join("attempt-1");
    let v = harness_journal::JournalReader::open(&j).unwrap();
    assert_eq!(v.head.to_string(), head);
    // The header carries the server's claims as untrusted payloads.
    let claimed = &v.records[0].body["claimed_server"];
    assert_eq!(claimed["untrusted"], true);
    assert_eq!(claimed["inline"], "mock-llm 1.0");

    // ---- replay: clean, then with the right and a wrong anchor ----
    let replay = |extra: &[&str]| {
        let mut a = vec![
            "replay",
            "--run",
            &id,
            "--task",
            fx.task.to_str().unwrap(),
            "--state-root",
            fx.state.to_str().unwrap(),
            "--profile",
            fx.profile.to_str().unwrap(),
        ];
        a.extend_from_slice(extra);
        cli(&a, false, &fx.marker)
    };
    let clean = replay(&["--anchor", head, "--gate", "audit.h1"]);
    assert_eq!(clean.code(), Some(5));
    let r = report(&clean);
    assert_eq!(r["gate"], "audit.h1");
    assert_eq!(r["outcome"]["Indeterminate"]["why"], "NothingChecked");
    assert!(String::from_utf8_lossy(&clean.stderr).contains("recomputed and matched"));
    let wrong = replay(&["--anchor", &"0".repeat(64)]);
    assert_eq!(wrong.code(), Some(5));
    assert_eq!(
        report(&wrong)["outcome"]["Indeterminate"]["why"],
        "UnreadableEvidence"
    );
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("DIVERGED"));
    assert!(!fx.marker.exists());
}

#[test]
fn a_crashed_run_resumes_through_the_cli_in_a_new_attempt() {
    let fx = fixture("resume");
    let m = mock(vec![
        act("harness.fs.read", r#"{"path":"a.txt"}"#),
        act("harness.fs.list", r#"{"path":"."}"#),
        act("harness.task.submit", r#"{"note":"done"}"#),
        // After the crash: step 2 again live, then submit.
        act("harness.fs.list", r#"{"path":"."}"#),
        act("harness.task.submit", r#"{"note":"done"}"#),
    ]);
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let o = cli(&run_args(&fx, &ep), true, &fx.marker);
    let id = run_id(&o);
    // Crash: keep steps 0-2, lose step 3 and RunStopped.
    let jp = fx
        .state
        .join("runs")
        .join(&id)
        .join("attempt-1/journal.jsonl");
    let kept: String = std::fs::read_to_string(&jp)
        .unwrap()
        .lines()
        .filter(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            v["step"].as_u64().unwrap() < 3 && v["kind"] != "RunStopped"
        })
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(&jp, kept).unwrap();
    let mut a = run_args(&fx, &ep);
    a[0] = "resume";
    a.extend_from_slice(&["--run", &id]);
    let r = cli(&a, true, &fx.marker);
    assert_eq!(r.code(), Some(5), "{}", String::from_utf8_lossy(&r.stderr));
    assert_eq!(
        report(&r)["outcome"]["Indeterminate"]["why"],
        "NothingChecked"
    );
    assert!(String::from_utf8_lossy(&r.stderr).contains("attempt 2"));
    assert!(fx
        .state
        .join("runs")
        .join(&id)
        .join("attempt-2/journal.jsonl")
        .is_file());
    let _ = &fx.base;
}

#[test]
fn usage_and_unreadable_inputs_still_end_with_a_report_line() {
    let fx = fixture("usage");
    let o = cli(&["run", "--bogus", "x"], false, &fx.marker);
    assert_eq!(o.code(), Some(2));
    assert_eq!(report(&o)["outcome"]["Indeterminate"]["why"], "CouldNotRun");
    // Exit 2 with an Indeterminate report: consistent for a parent.
    assert_eq!(
        as_parent_sees(&o, "rustyharness.run", &fx.marker, true),
        GateOutcome::Indeterminate {
            why: IndeterminateKind::CouldNotRun
        }
    );

    // H1e-2b review F-3: an invalid --gate is a usage error with a report
    // line (under the default id), like every other.
    let o = cli(&["run", "--gate", ""], false, &fx.marker);
    assert_eq!(o.code(), Some(2));
    let r = report(&o);
    assert_eq!(r["gate"], "rustyharness.run");
    assert_eq!(r["outcome"]["Indeterminate"]["why"], "CouldNotRun");

    std::fs::write(&fx.task, r#"{"task":"x","grants":[],"surprise":1}"#).unwrap();
    let o = cli(&run_args(&fx, "http://127.0.0.1:9/v1"), true, &fx.marker);
    assert_eq!(o.code(), Some(4));
    assert_eq!(report(&o)["outcome"]["Indeterminate"]["why"], "CouldNotRun");
    assert!(!fx.marker.exists());
}

#[test]
fn profile_check_stamps_a_model_that_calls_the_tool_and_refuses_one_that_does_not() {
    let fx = fixture("profile");
    let paths = [
        "README.md",
        "src/lib.rs",
        "docs/notes.txt",
        "Cargo.toml",
        "tests/basic.rs",
    ];
    let good: Vec<String> = paths
        .iter()
        .map(|p| act("harness.fs.read", &format!("{{\"path\":\"{p}\"}}")))
        .collect();
    let m = mock(good);
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let prof = fx.profile.to_str().unwrap();
    let o = cli(
        &["profile", "check", "--profile", prof, "--endpoint", &ep],
        false,
        &fx.marker,
    );
    assert_eq!(o.code(), Some(0), "{}", String::from_utf8_lossy(&o.stderr));
    let stamp: serde_json::Value = serde_json::from_str(&last_line(&o)).unwrap();
    assert_eq!(
        stamp["validated"]["stamp_sha256"].as_str().unwrap().len(),
        64
    );

    let m = mock(vec!["no action".into(); 5]);
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let o = cli(
        &["profile", "check", "--profile", prof, "--endpoint", &ep],
        false,
        &fx.marker,
    );
    assert_eq!(o.code(), Some(1));
}

/// H1e-2b review F-1: a journal cut after step 1 and ended with a forged,
/// re-chained wall stop is never reported as matched.
#[test]
fn replay_of_a_forged_wall_stop_is_unreadable_evidence_with_a_named_finding() {
    use harness_journal::canon::{RecordFields, GENESIS};
    let fx = fixture("forged-wall");
    let m = mock(vec![
        act("harness.fs.read", r#"{"path":"a.txt"}"#),
        act("harness.fs.list", r#"{"path":"."}"#),
        act("harness.task.submit", r#"{"note":"done"}"#),
    ]);
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let o = cli(&run_args(&fx, &ep), true, &fx.marker);
    let id = run_id(&o);
    let jp = fx
        .state
        .join("runs")
        .join(&id)
        .join("attempt-1/journal.jsonl");
    let fields = |v: &serde_json::Value, prev, body: Option<serde_json::Value>| RecordFields {
        seq: v["seq"].as_u64().unwrap(),
        prev,
        t_mono_ms: v["t_mono_ms"].as_u64().unwrap(),
        t_wall: v["t_wall"].as_str().unwrap().to_owned(),
        run: harness_core::RunId::parse(v["run"].as_str().unwrap()).unwrap(),
        attempt: u32::try_from(v["attempt"].as_u64().unwrap()).unwrap(),
        step: v["step"].as_u64().unwrap(),
        kind: harness_journal::EventKind::parse(v["kind"].as_str().unwrap()).unwrap(),
        body: body
            .unwrap_or_else(|| v["body"].clone())
            .as_object()
            .unwrap()
            .clone(),
    };
    let mut prev = GENESIS;
    let mut out = Vec::new();
    let mut last = None;
    for l in std::fs::read_to_string(&jp).unwrap().lines() {
        let v: serde_json::Value = serde_json::from_str(l).unwrap();
        if v["step"].as_u64().unwrap() > 1 || v["kind"] == "RunStopped" {
            continue;
        }
        let (b, h) = fields(&v, prev, None).encode();
        out.extend(b);
        out.push(b'\n');
        prev = h;
        last = Some(v);
    }
    let mut stop = last.unwrap();
    stop["seq"] = serde_json::Value::from(stop["seq"].as_u64().unwrap() + 1);
    stop["kind"] = serde_json::Value::from("RunStopped");
    let body = serde_json::json!({"cause":"budget","dimension":"wall","outcome":"indeterminate:nothing_checked"});
    out.extend(fields(&stop, prev, Some(body)).encode().0);
    out.push(b'\n');
    std::fs::write(&jp, out).unwrap();

    let r = cli(
        &[
            "replay",
            "--run",
            &id,
            "--task",
            fx.task.to_str().unwrap(),
            "--state-root",
            fx.state.to_str().unwrap(),
            "--profile",
            fx.profile.to_str().unwrap(),
        ],
        false,
        &fx.marker,
    );
    assert_eq!(r.code(), Some(5));
    let rep = report(&r);
    assert_eq!(rep["outcome"]["Indeterminate"]["why"], "UnreadableEvidence");
    assert_eq!(rep["findings"][0]["code"], "harness.replay.stop-unverified");
    assert_eq!(
        rep["findings"][0]["observed"],
        "wall stop not recomputable; only --anchor proves no truncation"
    );
    assert!(!String::from_utf8_lossy(&r.stderr).contains("every record recomputed and matched"));
}

/// INV-1 / INV-22 through the CLI: `manifest check` is the v1 admission
/// parser, not the scaffold's v0 one it used to be. The example validates,
/// with each capability's class and what this build's admission would do
/// with it; v0, a reserved namespace, duplicate keys (top level and nested)
/// are refused (exit 1); a file that is not a JSON document at all, or is
/// too large or missing, is unreadable (exit 4). Refusals never put a raw
/// control or bidi character on the terminal (H1f-2 review F-1).
#[test]
fn inv_1_manifest_check_is_the_v1_admission_parser() {
    let fx = fixture("manifest-check");
    let check = |path: &Path| {
        cli(
            &["manifest", "check", path.to_str().unwrap()],
            false,
            &fx.marker,
        )
    };
    let example =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../adapters/example/manifest.json");
    let o = check(&example);
    let out = String::from_utf8_lossy(&o.stdout);
    assert_eq!(o.code(), Some(0), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(
        out.contains("provider example 0.0.1 (schema v1, transport mcp-stdio), 2 capabilities"),
        "{out}"
    );
    assert!(out.contains("example.config.set: effect write, sensitivity operational, blast own, egress none, content own; confirmation user_confirm"), "{out}");
    assert!(
        out.contains("started only inside a conformed sandbox"),
        "{out}"
    );
    // Valid is not admitted: external providers are H4 (§4.4).
    assert!(out.contains("this build would refuse it"), "{out}");
    assert!(out.contains("arrives in H4"), "{out}");

    let text = std::fs::read_to_string(&example).unwrap();
    let write = |name: &str, body: &str| {
        let p = fx.base.join(name);
        std::fs::write(&p, body).unwrap();
        p
    };
    let refused = |name: &str, body: &str, want_code: i32, why: &str| {
        let o = check(&write(name, body));
        let err = String::from_utf8_lossy(&o.stderr).into_owned();
        assert_eq!(o.code(), Some(want_code), "{name}: {err}");
        assert!(err.contains(why), "{name}: {err}");
        // Nothing from the manifest reaches the terminal raw: one line, no
        // other control character, no bidi or zero-width code point.
        let body = err.strip_suffix('\n').unwrap_or(&err);
        assert!(
            !body.chars().any(|c| c.is_control()
                || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{2028}' | '\u{2029}')),
            "{name}: {err:?}"
        );
        err
    };
    refused(
        "v0.json",
        r#"{"schema_version":0,"app":"example","app_version":"0.0.1","capabilities":[{"id":"example.status.read","summary":"x","effect":"read"}]}"#,
        1,
        "migrate",
    );
    refused(
        "reserved.json",
        &text
            .replace("\"provider\": \"example\"", "\"provider\": \"rustyvault\"")
            .replace("\"example.", "\"rustyvault."),
        1,
        "reserved",
    );
    refused(
        "duplicate.json",
        &text.replacen(
            "\"schema_version\": 1,",
            "\"schema_version\": 1, \"schema_version\": 1,",
            1,
        ),
        1,
        "repeats a JSON key",
    );
    refused(
        "nested-duplicate.json",
        &text.replacen(
            "\"maxLength\": 64",
            "\"maxLength\": 64, \"maxLength\": 64",
            1,
        ),
        1,
        "repeats a JSON key",
    );
    // Hostile text in an unknown field's name and in the key on a null
    // value's path: the refusal shows it escaped, so it cannot redraw the
    // terminal (e.g. print a forged "OK" over its own refusal).
    let esc = "\\u001b[1A\\u001b[2K\\rOK forged \\u202e\\u0007";
    let e = refused(
        "hostile-field.json",
        &text.replacen("{", &format!("{{\"{esc}\": 1, "), 1),
        1,
        "unknown field",
    );
    assert!(e.contains("\\u{1B}"), "{e}");
    refused(
        "hostile-null.json",
        &text.replacen(
            "\"properties\": {}",
            &format!("\"properties\": {{\"{esc}\": null}}"),
            1,
        ),
        1,
        "null value",
    );
    refused("not-json.json", "{\"schema_version\": 1,", 4, "cannot read");
    refused(
        "huge.json",
        &" ".repeat(harness_manifest::MANIFEST_MAX_BYTES + 1),
        4,
        "larger than the manifest cap",
    );
    let o = check(&fx.base.join("absent.json"));
    assert_eq!(o.code(), Some(4));
}

/// Every running process's argv, one string per process: `/proc/*/cmdline`
/// on Linux, `ps` on macOS. A process that exits mid-scan is skipped.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn every_argv() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_dir("/proc")
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .bytes()
                    .all(|b| b.is_ascii_digit())
            })
            .filter_map(|e| std::fs::read(e.path().join("cmdline")).ok())
            .map(|b| String::from_utf8_lossy(&b).replace('\0', " "))
            .collect()
    }
    #[cfg(target_os = "macos")]
    {
        let o = Command::new("/bin/ps")
            .args(["-axww", "-o", "args="])
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

/// What one INV-23 scan saw while the harness waited for a reply.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct Scan {
    /// The canary was in the chat request (so the task was in flight).
    in_request: bool,
    /// Every argv that carried the canary.
    carrying: Vec<String>,
    /// The running harness was seen: an argv naming the binary and the
    /// task FILE.
    harness_seen: bool,
}

/// INV-23: the task text never reaches an argv. The real binary runs a task
/// whose text carries a canary, through a tool step, and at EVERY chat
/// request (the harness is mid-run, waiting for the reply) every process's
/// argv is read: the canary is in each request, in no argv, and the scan
/// saw the harness itself. A witness runs first: a process whose argv[0] is
/// a canary must be found, so the scan is shown able to see one. Named
/// limit: each scan is a snapshot, so a child that starts and exits between
/// two scans is covered only by the static half, purity.sh §2f (every spawn
/// is one of capture.rs's three fixed queries).
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn inv_23_the_task_text_reaches_no_argv() {
    use std::os::unix::process::CommandExt;
    let fx = fixture("inv23");
    let canary = format!("TASK-CANARY-{:x}", std::process::id() ^ 0x5eed_1e55);
    // Witness first (R3 H-04): one process, no shell and no grandchild (a
    // killed `sh` could leave its `sleep` behind), argv[0] the canary.
    let witness = format!("{canary}-WITNESS");
    let mut child = Command::new("/bin/sleep")
        .arg("30")
        .arg0(&witness)
        .spawn()
        .unwrap();
    let until = std::time::Instant::now() + Duration::from_secs(10);
    let found = loop {
        if every_argv().iter().any(|a| a.contains(&witness)) {
            break true;
        }
        if std::time::Instant::now() > until {
            break false;
        }
        thread::sleep(Duration::from_millis(20));
    };
    let _ = child.kill();
    let _ = child.wait();
    assert!(found, "the argv scan cannot see a planted canary");

    std::fs::write(
        &fx.task,
        format!(r#"{{"task":"Find {canary} in a.txt","grants":["harness.fs.read"]}}"#),
    )
    .unwrap();
    let task_path = fx.task.to_str().unwrap().to_owned();
    let scans: Arc<Mutex<Vec<Scan>>> = Arc::new(Mutex::new(Vec::new()));
    let (s, c, t) = (scans.clone(), canary.clone(), task_path.clone());
    let m = mock_with(
        vec![
            act("harness.fs.read", r#"{"path":"a.txt"}"#),
            act("harness.task.submit", r#"{"note":"done"}"#),
        ],
        move |req| {
            let argvs = every_argv();
            s.lock().unwrap().push(Scan {
                in_request: req.contains(&c),
                carrying: argvs.iter().filter(|a| a.contains(&c)).cloned().collect(),
                harness_seen: argvs.iter().any(|a| a.contains(BIN) && a.contains(&t)),
            });
        },
    );
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let o = cli(&run_args(&fx, &ep), false, &fx.marker);
    assert_eq!(o.code(), Some(5), "{}", String::from_utf8_lossy(&o.stderr));
    let scans = std::mem::take(&mut *scans.lock().unwrap());
    // One scan per model call: before the read and after it.
    assert_eq!(scans.len(), 2);
    for (i, scan) in scans.iter().enumerate() {
        assert!(scan.in_request, "scan {i}: the canary was not in flight");
        assert!(
            scan.harness_seen,
            "scan {i}: the running harness was not seen"
        );
        assert!(
            scan.carrying.is_empty(),
            "scan {i}: argv carries the task text: {:?}",
            scan.carrying
        );
    }
}
