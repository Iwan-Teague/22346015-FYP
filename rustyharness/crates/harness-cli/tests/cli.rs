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
// A local-APFS answer for any path: the shared testkit probe.
use harness_testkit::Local;

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
                approver: harness_cli::ApproverSource::None,
                input: harness_cli::InputSource::Given(&[]),
                backend: harness_cli::BackendSource::BuiltIn,
                confinement: &harness_sandbox::SystemConfinement,
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

/// What `replay` says of an attempt it matched, stop included (H1
/// phase-exit review, named item 2).
const REPLAY_MATCHED: &str = "records matched. Re-fed from the journal, not re-run: the model replies, the tool results and the environment samples. Recomputed and compared: every context, parse, loop-detector and policy decision, and the stop.";

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
    // H1 phase-exit review, named item 2: the replay says what it re-fed
    // and what it recomputed, never "every record recomputed".
    let err = String::from_utf8_lossy(&clean.stderr);
    assert!(err.contains(REPLAY_MATCHED), "{err}");
    assert!(
        err.contains("The anchor matched the journal's chain head."),
        "{err}"
    );
    assert!(!err.contains("recomputed and matched"), "{err}");
    assert!(
        r["findings"][0]["observed"].as_str().unwrap().ends_with(
            " records matched (replies, tool results and samples re-fed; contexts, parses and decisions recomputed); anchor matched"
        ),
        "{r}"
    );
    let unanchored = replay(&[]);
    assert_eq!(unanchored.code(), Some(5));
    let err = String::from_utf8_lossy(&unanchored.stderr);
    assert!(err.contains(REPLAY_MATCHED), "{err}");
    assert!(
        err.contains("Without --anchor, a journal rewritten consistently is not detected (the chain is unkeyed)."),
        "{err}"
    );
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
        // After the crash: step 2's call finished, so the catch-up re-feeds
        // it (H2b) and step 3 runs live, then a submit.
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

// ---- H2b: edits through the CLI ------------------------------------------------------

/// The edit task: read a.txt, replace one word, submit.
fn edit_fixture(name: &str) -> (Fx, PathBuf) {
    let fx = fixture(name);
    std::fs::write(
        &fx.task,
        r#"{"task":"Change 'answer' to 'reply' in a.txt.","grants":["harness.fs.read","harness.edit.replace"]}"#,
    )
    .unwrap();
    let allow = fx.base.join("allow-edits.json");
    std::fs::write(
        &allow,
        r#"{"allow":["harness.edit.replace","harness.edit.write"]}"#,
    )
    .unwrap();
    (fx, allow)
}

fn edit_replies() -> Vec<String> {
    vec![
        act("harness.fs.read", r#"{"path":"a.txt"}"#),
        act(
            "harness.edit.replace",
            r#"{"path":"a.txt","old":"answer","new":"reply"}"#,
        ),
        act("harness.task.submit", r#"{"note":"changed"}"#),
    ]
}

fn decided_rules(fx: &Fx, id: &str) -> Vec<String> {
    let jp = fx
        .state
        .join("runs")
        .join(id)
        .join("attempt-1/journal.jsonl");
    std::fs::read_to_string(jp)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|v| v["kind"] == "PolicyDecided")
        .map(|v| v["body"]["rule"].as_str().unwrap_or("user").to_owned())
        .collect()
}

/// §5.2 through the binary: an unattended run (stdin is no terminal, so
/// nobody answers) edits only when its policy file allows the edit tools;
/// without one the edit is denied and the file is untouched. Both replay.
#[test]
fn an_unattended_run_edits_only_when_its_policy_allows_edits() {
    for with_policy in [true, false] {
        let (fx, allow) = edit_fixture(&format!("edit-policy-{with_policy}"));
        let m = mock(edit_replies());
        let ep = format!("http://127.0.0.1:{}/v1", m.port);
        let mut args = run_args(&fx, &ep);
        if with_policy {
            args.extend_from_slice(&["--policy", allow.to_str().unwrap()]);
        }
        let o = cli(&args, !REAL_PROBE_MEASURES, &fx.marker);
        assert_eq!(o.code(), Some(5), "{}", String::from_utf8_lossy(&o.stderr));
        let text = std::fs::read_to_string(fx.ws.join("a.txt")).unwrap();
        let id = run_id(&o);
        let rules = decided_rules(&fx, &id);
        if with_policy {
            assert_eq!(text, "the reply is in here\n");
            assert_eq!(rules[1], "user", "a user allow rule: {rules:?}");
        } else {
            assert_eq!(text, "the answer is in here\n");
            assert_eq!(rules[1], "deny.no-approver");
        }
        // The replay re-feeds the edit and never applies it again.
        std::fs::write(fx.ws.join("a.txt"), "the answer is in here\n").unwrap();
        let head = String::from_utf8(o.stdout.clone())
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .strip_prefix("chain_head ")
            .unwrap()
            .to_owned();
        let mut rargs = vec![
            "replay",
            "--run",
            &id,
            "--task",
            fx.task.to_str().unwrap(),
            "--state-root",
            fx.state.to_str().unwrap(),
            "--profile",
            fx.profile.to_str().unwrap(),
            "--anchor",
            &head,
        ];
        if with_policy {
            rargs.extend_from_slice(&["--policy", allow.to_str().unwrap()]);
        }
        let rp = cli(&rargs, true, &fx.marker);
        assert!(
            String::from_utf8_lossy(&rp.stderr).contains(REPLAY_MATCHED),
            "{}",
            String::from_utf8_lossy(&rp.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(fx.ws.join("a.txt")).unwrap(),
            "the answer is in here\n"
        );
    }
}

/// An approver answering yes, given to the CLI library in process: the
/// edit asks (no policy file), is approved, and runs once.
#[test]
fn an_approver_given_to_the_cli_approves_an_edit() {
    struct Yes;
    impl harness_run::Approver for Yes {
        fn kind(&self) -> harness_run::ApproverKind {
            harness_run::ApproverKind::Embedded
        }
        fn ask(
            &self,
            _req: &harness_policy::approval::ApprovalRequest,
            _deadline: std::time::Instant,
        ) -> harness_run::ApprovalAnswer {
            harness_run::ApprovalAnswer::Yes
        }
    }
    let (fx, _) = edit_fixture("edit-approved");
    let m = mock(edit_replies());
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = {
        let cx = harness_cli::Cx {
            probe: &Local,
            gate_ok_file: Some(fx.marker.clone()),
            out: RefCell::new(&mut out),
            err: RefCell::new(&mut err),
            approver: harness_cli::ApproverSource::Given(&Yes),
            input: harness_cli::InputSource::Given(&[]),
            backend: harness_cli::BackendSource::BuiltIn,
            confinement: &harness_sandbox::SystemConfinement,
        };
        harness_cli::main_with(&cx, &run_args(&fx, &ep))
    };
    assert_eq!(code, 5, "{}", String::from_utf8_lossy(&err));
    assert_eq!(
        std::fs::read_to_string(fx.ws.join("a.txt")).unwrap(),
        "the reply is in here\n"
    );
}

// ---- H2d: commands through the CLI ---------------------------------------------------

/// The exec task: run one perl command that writes a file, then submit.
/// The task file pins perl by path, declares one variable and two limits.
fn exec_fixture(name: &str) -> (Fx, PathBuf) {
    let fx = fixture(name);
    std::fs::write(
        &fx.task,
        r#"{"task":"Write ran.txt.","grants":["harness.fs.read","harness.exec.run"],
  "exec":{"programs":[{"name":"perl","path":"/usr/bin/perl"}],"env":{"RH_TASK":"1"},
          "limits":{"memory_mib":1024,"processes":64}}}"#,
    )
    .unwrap();
    let allow = fx.base.join("allow-exec.json");
    std::fs::write(&allow, r#"{"allow":["harness.exec.run"]}"#).unwrap();
    (fx, allow)
}

fn exec_replies() -> Vec<String> {
    vec![
        act(
            "harness.exec.run",
            r#"{"argv":["perl","-e","open(my $f, q{>}, q{ran.txt}) or die; print $f $ENV{RH_TASK}"]}"#,
        ),
        act("harness.task.submit", r#"{"note":"ran"}"#),
    ]
}

/// P-11: the exec-by-name flags refuse, as unreadable input (exit 4),
/// every disagreement with the task file: an exec section the file already
/// pins, a task that never grants the runner, a name that is not on PATH.
/// None of them starts a run. (The full --allow-exec run is the sandbox's
/// to prove, as with a task-file allowlist; the resolution itself is
/// exec_presets' unit tests.)
#[test]
fn allow_exec_flags_refuse_conflicts_and_names_off_the_path() {
    let fx = fixture("allow-exec-refused");
    let m = mock(vec![act("harness.task.submit", r#"{"note":"done"}"#)]);
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let mut args = run_args(&fx, &ep);
    args.extend_from_slice(&["--allow-exec", "cargo"]);

    // A task file with its own exec section takes none of the flags.
    std::fs::write(
        &fx.task,
        r#"{"task":"x","grants":["harness.exec.run","harness.task.submit"],
  "exec":{"programs":[{"name":"perl","path":"/usr/bin/perl"}]}}"#,
    )
    .unwrap();
    let o = cli(&args, true, &fx.marker);
    assert_eq!(o.code(), Some(4), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("do not go with a task file that has"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );

    // Without the grant, no allowlist is built.
    std::fs::write(&fx.task, r#"{"task":"x","grants":["harness.task.submit"]}"#).unwrap();
    let o = cli(&args, true, &fx.marker);
    assert_eq!(o.code(), Some(4), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stderr).contains("needs the task to grant"));

    // A name nothing on PATH provides is refused by name.
    std::fs::write(
        &fx.task,
        r#"{"task":"x","grants":["harness.exec.run","harness.task.submit"]}"#,
    )
    .unwrap();
    args.pop();
    args.push("rh11-absent-tool");
    let o = cli(&args, true, &fx.marker);
    assert_eq!(o.code(), Some(4), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("no rh11-absent-tool on PATH"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

/// P-11: `--shell` builds the exec section from names (`sh` resolved on
/// this process's own PATH, pinned to its real path), the header stamps
/// `shell_enabled: true`, and the audit of the run matches only when the
/// replay is given the same flag. macOS only, like every run that starts
/// with a command runner here: the header is written only past the
/// witness (INV-6).
#[cfg(target_os = "macos")]
#[test]
fn shell_flag_sets_shell_enabled_in_header() {
    let fx = fixture("shell-header");
    std::fs::write(
        &fx.task,
        r#"{"task":"Say done.","grants":["harness.task.submit","harness.exec.run"]}"#,
    )
    .unwrap();
    let m = mock(vec![act("harness.task.submit", r#"{"note":"done"}"#)]);
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let mut args = run_args(&fx, &ep);
    args.push("--shell");
    let o = cli(&args, true, &fx.marker);
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.code(), Some(5), "{err}");
    // Printed before the run started, name -> pinned real path.
    assert!(err.contains("will allow: sh -> /bin/sh"), "{err}");
    let id = run_id(&o);
    let jp = fx
        .state
        .join("runs")
        .join(&id)
        .join("attempt-1/journal.jsonl");
    let first = std::fs::read_to_string(jp)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_owned();
    let h: serde_json::Value = serde_json::from_str(&first).unwrap();
    assert_eq!(h["kind"], "RunStarted");
    assert_eq!(h["body"]["shell_enabled"], true);
    let head = String::from_utf8(o.stdout.clone())
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .strip_prefix("chain_head ")
        .unwrap()
        .to_owned();
    let rp = |with_shell: bool| {
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
            "--anchor",
            &head,
        ];
        if with_shell {
            a.push("--shell");
        }
        cli(&a, true, &fx.marker)
    };
    // The allowlist is a header input: without the flag the audit
    // diverges, with it the run replays clean.
    let without = rp(false);
    assert!(
        String::from_utf8_lossy(&without.stderr).contains("DIVERGED"),
        "{}",
        String::from_utf8_lossy(&without.stderr)
    );
    let with = rp(true);
    assert!(
        String::from_utf8_lossy(&with.stderr).contains(REPLAY_MATCHED),
        "{}",
        String::from_utf8_lossy(&with.stderr)
    );
}

/// INV-6 through the CLI: a task that executes, on a host whose
/// confinement refuses, exits 3 with an Indeterminate report and writes
/// nothing; the model server is checked but never asked for a step.
#[test]
fn a_task_that_executes_without_confinement_exits_3_and_writes_nothing() {
    let (fx, allow) = exec_fixture("exec-refused");
    // A program that pins on every OS (never run: the refusal comes
    // first), so Windows reaches the refusal path too.
    let tools = fx.base.join("tools");
    std::fs::create_dir_all(&tools).unwrap();
    std::fs::write(tools.join("tool"), b"#!/bin/sh\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tools.join("tool"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }
    let tools = std::fs::canonicalize(&tools).unwrap();
    let task = serde_json::json!({
        "task": "Write ran.txt.",
        "grants": ["harness.fs.read", "harness.exec.run"],
        "exec": {
            "programs": [{"name": "perl", "path": tools.join("tool")}],
            "read_only": [tools],
        },
    });
    std::fs::write(&fx.task, task.to_string()).unwrap();
    let m = mock(exec_replies());
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let mut args = run_args(&fx, &ep);
    args.extend_from_slice(&["--policy", allow.to_str().unwrap()]);
    let refuse = harness_sandbox::NoConfinement(harness_sandbox::Unavailable {
        backend: None,
        reason: harness_sandbox::UnavailableReason::NoBackendForOs,
    });
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = {
        let cx = harness_cli::Cx {
            probe: &Local,
            gate_ok_file: Some(fx.marker.clone()),
            out: RefCell::new(&mut out),
            err: RefCell::new(&mut err),
            approver: harness_cli::ApproverSource::None,
            input: harness_cli::InputSource::Given(&[]),
            backend: harness_cli::BackendSource::BuiltIn,
            confinement: &refuse,
        };
        harness_cli::main_with(&cx, &args)
    };
    let o = Output {
        code: i32::from(code),
        stdout: out,
        stderr: err,
    };
    assert_eq!(o.code(), Some(3), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(
        report(&o)["outcome"]["Indeterminate"]["why"],
        "UnsupportedOs"
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains("no confinement backend"));
    assert!(!fx.state.join("runs").exists());
    assert!(!fx.ws.join("ran.txt").exists());
    assert!(!fx.marker.exists());
}

/// A malformed exec section is unreadable input (exit 4), like any other.
#[test]
fn a_malformed_exec_section_is_unreadable_input() {
    let (fx, _) = exec_fixture("exec-malformed");
    std::fs::write(
        &fx.task,
        r#"{"task":"x","grants":["harness.exec.run"],"exec":{"programz":[]}}"#,
    )
    .unwrap();
    let o = cli(&run_args(&fx, "http://127.0.0.1:9/v1"), true, &fx.marker);
    assert_eq!(o.code(), Some(4), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(report(&o)["outcome"]["Indeterminate"]["why"], "CouldNotRun");
}

/// §5.2 for commands, through the real binary (its confinement is the
/// production `SystemConfinement`): an unattended run executes only when
/// its policy file allows the runner; without one the command is denied
/// and nothing ran. With it, the command ran confined, with the task's
/// variable, and the anchored replay matches without running it again.
#[cfg(target_os = "macos")]
#[test]
fn an_unattended_run_executes_only_when_its_policy_allows_the_runner() {
    for with_policy in [true, false] {
        let (fx, allow) = exec_fixture(&format!("exec-policy-{with_policy}"));
        let m = mock(exec_replies());
        let ep = format!("http://127.0.0.1:{}/v1", m.port);
        let mut args = run_args(&fx, &ep);
        if with_policy {
            args.extend_from_slice(&["--policy", allow.to_str().unwrap()]);
        }
        let o = cli(&args, false, &fx.marker);
        assert_eq!(o.code(), Some(5), "{}", String::from_utf8_lossy(&o.stderr));
        let id = run_id(&o);
        let rules = decided_rules(&fx, &id);
        if !with_policy {
            assert_eq!(rules[0], "deny.no-approver");
            assert!(!fx.ws.join("ran.txt").exists());
            continue;
        }
        assert_eq!(rules[0], "user", "a user allow rule: {rules:?}");
        assert_eq!(std::fs::read_to_string(fx.ws.join("ran.txt")).unwrap(), "1");
        std::fs::remove_file(fx.ws.join("ran.txt")).unwrap();
        let head = String::from_utf8(o.stdout.clone())
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .strip_prefix("chain_head ")
            .unwrap()
            .to_owned();
        let rp = cli(
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
                "--anchor",
                &head,
                "--policy",
                allow.to_str().unwrap(),
            ],
            true,
            &fx.marker,
        );
        assert!(
            String::from_utf8_lossy(&rp.stderr).contains(REPLAY_MATCHED),
            "{}",
            String::from_utf8_lossy(&rp.stderr)
        );
        assert!(!fx.ws.join("ran.txt").exists(), "the replay ran nothing");
    }
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
    let err = String::from_utf8_lossy(&r.stderr);
    assert!(err.contains("the stop was NOT recomputed"), "{err}");
    assert!(!err.contains(REPLAY_MATCHED), "{err}");
}

/// Write `records` as a journal the way a forger who re-chains would: seq
/// renumbered, every result's `intent_seq` pointed at its (renumbered)
/// intent, every hash recomputed.
fn write_chained(path: &Path, records: &[serde_json::Value]) {
    use harness_journal::canon::{RecordFields, GENESIS};
    let mut prev = GENESIS;
    let mut out = Vec::new();
    let mut last_intent = 0u64;
    for (i, v) in records.iter().enumerate() {
        let seq = i as u64;
        let mut body = v["body"].as_object().unwrap().clone();
        if v["kind"] == "ToolStarted" {
            last_intent = seq;
        }
        if body.contains_key("intent_seq") {
            body.insert("intent_seq".into(), serde_json::Value::from(last_intent));
        }
        let (bytes, hash) = RecordFields {
            seq,
            prev,
            t_mono_ms: v["t_mono_ms"].as_u64().unwrap(),
            t_wall: v["t_wall"].as_str().unwrap().to_owned(),
            run: harness_core::RunId::parse(v["run"].as_str().unwrap()).unwrap(),
            attempt: u32::try_from(v["attempt"].as_u64().unwrap()).unwrap(),
            step: v["step"].as_u64().unwrap(),
            kind: harness_journal::EventKind::parse(v["kind"].as_str().unwrap()).unwrap(),
            body,
        }
        .encode();
        out.extend(bytes);
        out.push(b'\n');
        prev = hash;
    }
    std::fs::write(path, out).unwrap();
}

/// `replay` of `id` through the real binary, with `extra` options.
fn replay_bin(fx: &Fx, id: &str, extra: &[&str]) -> Output {
    let mut a = vec![
        "replay",
        "--run",
        id,
        "--task",
        fx.task.to_str().unwrap(),
        "--state-root",
        fx.state.to_str().unwrap(),
        "--profile",
        fx.profile.to_str().unwrap(),
    ];
    a.extend_from_slice(extra);
    cli(&a, false, &fx.marker)
}

/// A three-step run (read, list, submit) in process; its run id, journal
/// path and chain head.
fn three_steps(fx: &Fx) -> (String, PathBuf, String) {
    let m = mock(vec![
        act("harness.fs.read", r#"{"path":"a.txt"}"#),
        act("harness.fs.list", r#"{"path":"."}"#),
        act("harness.task.submit", r#"{"note":"done"}"#),
    ]);
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let o = cli(&run_args(fx, &ep), true, &fx.marker);
    assert_eq!(o.code(), Some(5), "{}", String::from_utf8_lossy(&o.stderr));
    let head = String::from_utf8_lossy(&o.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("chain_head ").map(str::to_owned))
        .unwrap();
    let id = run_id(&o);
    let jp = fx
        .state
        .join("runs")
        .join(&id)
        .join("attempt-1/journal.jsonl");
    (id, jp, head)
}

/// The real binary's replay of a forged journal: exit 5, unreadable
/// evidence, a named divergence whose reason contains `why`, and never the
/// words of a match.
fn assert_replay_diverged(o: &Output, why: &str, marker: &Path) {
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.code(), Some(5), "{err}");
    let rep = report(o);
    assert_eq!(rep["outcome"]["Indeterminate"]["why"], "UnreadableEvidence");
    assert_eq!(rep["findings"][0]["code"], "harness.replay.divergence");
    assert!(
        rep["findings"][0]["observed"]
            .as_str()
            .unwrap()
            .contains(why),
        "{rep}"
    );
    assert!(err.contains("DIVERGED"), "{err}");
    assert!(!err.contains("records matched"), "{err}");
    assert!(!marker.exists());
}

/// H1 phase-exit review F-1 through the real binary (CLI-W1): a journal cut
/// after step 1, its header's step limit lowered to 1, the 80% condition
/// and the steps-budget stop the loop recomputes under that limit added,
/// re-chained. `replay` gives the audit the binary's own limits, so it is
/// a divergence at the header, without an anchor and with the forged
/// journal's own head as one; it once printed "every record recomputed and
/// matched (9 records)".
#[test]
fn replay_of_a_journal_forged_through_its_header_limits_is_unreadable_evidence() {
    let fx = fixture("forged-limits");
    let (id, jp, _) = three_steps(&fx);
    let genuine: Vec<serde_json::Value> = std::fs::read_to_string(&jp)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let step1: Vec<serde_json::Value> =
        genuine.iter().filter(|v| v["step"] == 1).cloned().collect();
    let mut header = genuine[0].clone();
    header["body"]["limits"]["steps"] = serde_json::Value::from(1u64);
    let mut condition = step1[0].clone();
    condition["kind"] = serde_json::Value::from("BudgetCharged");
    condition["body"] = serde_json::json!({"condition": "enter", "key": "steps"});
    let mut stop = step1.last().unwrap().clone();
    stop["step"] = serde_json::Value::from(2u64);
    stop["kind"] = serde_json::Value::from("RunStopped");
    stop["body"] = serde_json::json!({
        "cause": "budget", "dimension": "steps", "outcome": "indeterminate:nothing_checked"
    });
    let mut forged = vec![header, condition];
    forged.extend(step1);
    forged.push(stop);
    write_chained(&jp, &forged);
    let v = harness_journal::JournalReader::open(jp.parent().unwrap()).unwrap();
    assert!(v.is_complete(), "the forged journal verifies");

    let forged_head = v.head.to_string();
    for extra in [&[][..], &["--anchor", forged_head.as_str()][..]] {
        let o = replay_bin(&fx, &id, extra);
        assert_replay_diverged(&o, "budget limits", &fx.marker);
    }
}

/// H1 phase-exit review F-2 through the real binary (CLI-W2): bytes
/// appended after `RunStopped` with no newline (a line reader's last
/// record) are refused by the reader, so `replay --anchor <the genuine
/// head>` is unreadable evidence; it once printed "every record recomputed
/// and matched (16 records)".
#[test]
fn replay_of_a_journal_with_bytes_after_run_stopped_is_unreadable_even_anchored() {
    let fx = fixture("after-stop");
    let (id, jp, head) = three_steps(&fx);
    let mut bytes = std::fs::read(&jp).unwrap();
    let planted = r#"{"attempt":1,"body":{"cause":"submitted","outcome":"passed"},"kind":"RunStopped","note":"planted"}"#;
    bytes.extend_from_slice(planted.as_bytes());
    std::fs::write(&jp, &bytes).unwrap();
    assert_eq!(
        std::fs::read_to_string(&jp).unwrap().lines().last(),
        Some(planted)
    );
    let o = replay_bin(&fx, &id, &["--anchor", &head]);
    assert_replay_diverged(&o, "does not verify", &fx.marker);
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

/// H2e: a task file's `budget` section sets the run's limits. The model is
/// told as it goes (budget notices against the task's limit, not the
/// default 50), the run stops at that limit, the header records it, and
/// `replay` needs the same budget from the task file: with it the audit
/// matches; without it the header's limits differ and the replay says so.
#[test]
fn h2e_a_task_budget_sets_the_limits_and_replay_needs_the_same() {
    let fx = fixture("task-budget");
    let with_budget = r#"{"task":"What does a.txt say?","grants":["harness.fs.read","harness.fs.list"],
        "budget":{"steps":4,"wall_secs":600}}"#;
    std::fs::write(&fx.task, with_budget).unwrap();
    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen = requests.clone();
    // Four different calls and never a submit.
    let m = mock_with(
        vec![
            act("harness.fs.read", r#"{"path":"a.txt"}"#),
            act("harness.fs.list", r#"{"path":"."}"#),
            act("harness.fs.read", r#"{"path":"a.txt","lines":1}"#),
            act("harness.fs.list", r#"{"path":".","depth":1}"#),
        ],
        move |req| seen.lock().unwrap().push(req.to_owned()),
    );
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let o = cli(&run_args(&fx, &ep), true, &fx.marker);
    let err = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.code(), Some(5), "{err}");
    assert!(err.contains("stopped (budget) after"), "{err}");
    let reqs = requests.lock().unwrap().clone();
    // The model was asked four times: the fifth step is refused by the
    // budget before its call.
    assert_eq!(reqs.len(), 4);
    // 50% of 4 after step 2; one step left after step 3.
    assert!(!reqs[2 - 1].contains("Budget:"), "{}", reqs[1]);
    assert!(
        reqs[3 - 1].contains("Budget: 2 of 4 steps used, 2 left."),
        "{}",
        reqs[2]
    );
    assert!(
        reqs[4 - 1].contains("Budget: 3 of 4 steps used; your next reply is your last step."),
        "{}",
        reqs[3]
    );
    let id = run_id(&o);
    let jp = fx
        .state
        .join("runs")
        .join(&id)
        .join("attempt-1/journal.jsonl");
    let header: serde_json::Value = serde_json::from_str(
        std::fs::read_to_string(&jp)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(header["body"]["limits"]["steps"], 4, "{header}");
    assert_eq!(header["body"]["limits"]["wall_ms"], 600_000, "{header}");

    let clean = replay_bin(&fx, &id, &[]);
    let rerr = String::from_utf8_lossy(&clean.stderr);
    assert_eq!(clean.code(), Some(5), "{rerr}");
    assert!(rerr.contains(REPLAY_MATCHED), "{rerr}");
    // The same task without its budget section: the default limits, which
    // the recorded header does not hold.
    std::fs::write(
        &fx.task,
        r#"{"task":"What does a.txt say?","grants":["harness.fs.read","harness.fs.list"]}"#,
    )
    .unwrap();
    let o = replay_bin(&fx, &id, &[]);
    assert_replay_diverged(&o, "budget limits", &fx.marker);
}

/// H2e: a budget out of range, a `null`, or a key the section does not
/// have is unreadable input (exit 4), refused before the model server is
/// contacted.
#[test]
fn h2e_a_task_budget_out_of_range_is_unreadable_input() {
    let fx = fixture("task-budget-bad");
    let m = mock(Vec::new());
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    for (budget, words) in [
        (r#"{"steps":0}"#, "budget: steps must be from 1 to 500"),
        (r#"{"steps":501}"#, "budget: steps must be from 1 to 500"),
        (
            r#"{"wall_secs":0}"#,
            "budget: wall_secs must be from 1 to 86400",
        ),
        (
            r#"{"wall_secs":86401}"#,
            "budget: wall_secs must be from 1 to 86400",
        ),
        (r#"{"steps":null}"#, "does not have the expected shape"),
        (r#"{"steps":-1}"#, "does not have the expected shape"),
        (r#"{"step":10}"#, "does not have the expected shape"),
        (r#"{"tokens":10}"#, "does not have the expected shape"),
    ] {
        std::fs::write(
            &fx.task,
            format!(r#"{{"task":"x","grants":["harness.fs.read"],"budget":{budget}}}"#),
        )
        .unwrap();
        let o = cli(&run_args(&fx, &ep), true, &fx.marker);
        let err = String::from_utf8_lossy(&o.stderr);
        assert_eq!(o.code(), Some(4), "{budget}: {err}");
        assert!(err.contains(words), "{budget}: {err}");
        assert_eq!(report(&o)["outcome"]["Indeterminate"]["why"], "CouldNotRun");
    }
    assert_eq!(*m.requests.lock().unwrap(), 0, "the server was never asked");
    assert!(!fx.marker.exists());
}

// H2f: a task's budget section may set each command's wall clock.
#[test]
fn h2f_an_exec_budget_out_of_range_or_without_an_exec_section_is_unreadable_input() {
    let fx = fixture("task-exec-budget-bad");
    let m = mock(Vec::new());
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let exec = r#","exec":{"programs":[{"name":"perl","path":"/usr/bin/perl"}]}"#;
    for (budget, with_exec, words) in [
        (
            r#"{"exec_secs":0}"#,
            true,
            "budget: exec_secs must be from 1 to 3600",
        ),
        (
            r#"{"exec_secs":3601}"#,
            true,
            "budget: exec_secs must be from 1 to 3600",
        ),
        (
            r#"{"exec_secs":null}"#,
            true,
            "does not have the expected shape",
        ),
        (
            r#"{"exec_secs":30}"#,
            false,
            "budget: exec_secs is for a task with an exec section",
        ),
    ] {
        let grants = if with_exec {
            r#"["harness.fs.read","harness.exec.run"]"#
        } else {
            r#"["harness.fs.read"]"#
        };
        let exec = if with_exec { exec } else { "" };
        std::fs::write(
            &fx.task,
            format!(r#"{{"task":"x","grants":{grants},"budget":{budget}{exec}}}"#),
        )
        .unwrap();
        let o = cli(&run_args(&fx, &ep), true, &fx.marker);
        let err = String::from_utf8_lossy(&o.stderr);
        assert_eq!(o.code(), Some(4), "{budget}: {err}");
        assert!(err.contains(words), "{budget}: {err}");
    }
    assert_eq!(*m.requests.lock().unwrap(), 0, "the server was never asked");
    assert!(!fx.marker.exists());
}

/// The exec budget reaches the run: the header records the command wall
/// (`exec_timeout_ms`), a task without the field keeps the 120 s default,
/// and the anchored replay of the run matches.
#[cfg(target_os = "macos")]
#[test]
fn h2f_an_exec_budget_sets_the_commands_wall_clock_in_the_header() {
    for (secs, want_ms) in [(Some(45u64), 45_000u64), (None, 120_000)] {
        let (fx, allow) = exec_fixture(&format!("exec-budget-{}", secs.unwrap_or(0)));
        if let Some(s) = secs {
            std::fs::write(
                &fx.task,
                format!(
                    r#"{{"task":"Write ran.txt.","grants":["harness.fs.read","harness.exec.run"],
  "exec":{{"programs":[{{"name":"perl","path":"/usr/bin/perl"}}],"env":{{"RH_TASK":"1"}},
          "limits":{{"memory_mib":1024,"processes":64}}}},
  "budget":{{"exec_secs":{s}}}}}"#
                ),
            )
            .unwrap();
        }
        let m = mock(exec_replies());
        let ep = format!("http://127.0.0.1:{}/v1", m.port);
        let mut args = run_args(&fx, &ep);
        args.extend_from_slice(&["--policy", allow.to_str().unwrap()]);
        let o = cli(&args, false, &fx.marker);
        assert_eq!(o.code(), Some(5), "{}", String::from_utf8_lossy(&o.stderr));
        let id = run_id(&o);
        let jp = fx
            .state
            .join("runs")
            .join(&id)
            .join("attempt-1/journal.jsonl");
        let header: serde_json::Value = serde_json::from_str(
            std::fs::read_to_string(&jp)
                .unwrap()
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(header["body"]["exec_timeout_ms"], want_ms, "{header}");
        std::fs::remove_file(fx.ws.join("ran.txt")).unwrap();
        let rp = replay_bin(&fx, &id, &["--policy", allow.to_str().unwrap()]);
        let rerr = String::from_utf8_lossy(&rp.stderr);
        assert!(rerr.contains(REPLAY_MATCHED), "{rerr}");
    }
}

// ---- H3a: pre-submit checks ----------------------------------------------------------

/// A task with the command runner (perl, pinned) and a `presubmit` section.
fn presubmit_task(name: &str, presubmit: &str, grants: &str, with_exec: bool) -> (Fx, PathBuf) {
    let fx = fixture(name);
    let exec = if with_exec {
        r#","exec":{"programs":[{"name":"perl","path":"/usr/bin/perl"}]}"#
    } else {
        ""
    };
    std::fs::write(
        &fx.task,
        format!(r#"{{"task":"Make it pass.","grants":{grants}{exec},"presubmit":{presubmit}}}"#),
    )
    .unwrap();
    let allow = fx.base.join("allow-exec.json");
    std::fs::write(&allow, r#"{"allow":["harness.exec.run"]}"#).unwrap();
    (fx, allow)
}

/// A section that is not a bounded list of commands on the allowlist in a
/// task that grants the runner is unreadable input (exit 4), refused before
/// the model server is contacted, with the reason named.
#[test]
fn h3a_a_bad_presubmit_section_is_unreadable_input() {
    let m = mock(Vec::new());
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let with_runner = r#"["harness.fs.read","harness.exec.run"]"#;
    let five = r#"{"commands":[["perl"],["perl"],["perl"],["perl"],["perl"]]}"#;
    for (i, (presubmit, grants, with_exec, words)) in [
        // The checks are commands in the sandbox: no runner, no checks.
        (
            r#"{"commands":[["perl","-e","1"]]}"#,
            r#"["harness.fs.read"]"#,
            false,
            "presubmit needs the task to grant harness.exec.run",
        ),
        (
            r#"{"commands":[["perl","-e","1"]]}"#,
            r#"["harness.fs.read"]"#,
            true,
            "presubmit needs the task to grant harness.exec.run",
        ),
        (
            r#"{"commands":[]}"#,
            with_runner,
            true,
            "presubmit.commands must hold 1 to 4 commands",
        ),
        (
            five,
            with_runner,
            true,
            "presubmit.commands must hold 1 to 4 commands",
        ),
        (
            r#"{"commands":[["perl","-e","1"],[]]}"#,
            with_runner,
            true,
            "presubmit command 2 must be 1 to 32 arguments",
        ),
        (
            r#"{"commands":[["cargo","build"]]}"#,
            with_runner,
            true,
            "presubmit command 1 does not start with a program name on the exec allowlist",
        ),
        (
            r#"{"commands":[["/usr/bin/perl","-e","1"]]}"#,
            with_runner,
            true,
            "presubmit command 1 does not start with a program name",
        ),
        (
            r#"{"commands":[["perl","-e","1"]],"max_rounds":0}"#,
            with_runner,
            true,
            "presubmit.max_rounds must be from 1 to 5",
        ),
        (
            r#"{"commands":[["perl","-e","1"]],"max_rounds":6}"#,
            with_runner,
            true,
            "presubmit.max_rounds must be from 1 to 5",
        ),
        (
            r#"{"commands":[["perl","-e","1"]],"max_rounds":null}"#,
            with_runner,
            true,
            "does not have the expected shape",
        ),
        (
            r#"{"commands":[["perl","-e","1"]],"rounds":2}"#,
            with_runner,
            true,
            "does not have the expected shape",
        ),
        (
            r#"{}"#,
            with_runner,
            true,
            "does not have the expected shape",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let (fx, _) = presubmit_task(&format!("presubmit-bad-{i}"), presubmit, grants, with_exec);
        let o = cli(&run_args(&fx, &ep), true, &fx.marker);
        let err = String::from_utf8_lossy(&o.stderr);
        assert_eq!(o.code(), Some(4), "{presubmit}: {err}");
        assert!(err.contains(words), "{presubmit}: {err}");
        assert_eq!(report(&o)["outcome"]["Indeterminate"]["why"], "CouldNotRun");
        assert!(!fx.marker.exists());
        assert!(!fx.state.join("runs").exists());
    }
    assert_eq!(*m.requests.lock().unwrap(), 0, "the server was never asked");
}

/// A check the policy would deny (no allow rule and nobody to ask, so the
/// ask is a deny) never starts the run: exit 4 with the reason, nothing
/// written. Every OS: the refusal comes before the sandbox is asked.
#[test]
fn h3a_checks_the_policy_denies_do_not_start_the_run() {
    let (fx, _) = presubmit_task(
        "presubmit-denied",
        r#"{"commands":[["perl","-e","1"]]}"#,
        r#"["harness.fs.read","harness.exec.run"]"#,
        true,
    );
    // A program that pins on every OS (never run): perl's path does not
    // exist on Windows.
    let tools = fx.base.join("tools");
    std::fs::create_dir_all(&tools).unwrap();
    std::fs::write(tools.join("tool"), b"#!/bin/sh\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tools.join("tool"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }
    let tools = std::fs::canonicalize(&tools).unwrap();
    let task = serde_json::json!({
        "task": "Make it pass.",
        "grants": ["harness.fs.read", "harness.exec.run"],
        "exec": {"programs": [{"name": "perl", "path": tools.join("tool")}], "read_only": [tools]},
        "presubmit": {"commands": [["perl", "-e", "1"]]},
    });
    std::fs::write(&fx.task, task.to_string()).unwrap();
    let m = mock(Vec::new());
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let o = cli(&run_args(&fx, &ep), true, &fx.marker);
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.code(), Some(4), "{err}");
    assert!(
        err.contains("the policy denies presubmit command 1"),
        "{err}"
    );
    assert!(!fx.state.join("runs").exists(), "nothing was written");
    assert!(!fx.marker.exists());
}

/// Through the real binary (its confinement is the production
/// `SystemConfinement`): the first submission's check fails, so it is turned
/// back and the model repairs the workspace with a command of its own; the
/// second submission's check passes and it is accepted. The report says so
/// in words and as a finding, and the anchored replay matches without
/// running anything.
#[cfg(target_os = "macos")]
#[test]
fn h3a_the_binary_turns_a_submission_back_and_the_replay_matches() {
    let (fx, allow) = presubmit_task(
        "presubmit-run",
        r#"{"commands":[["perl","-e","exit(-e q{fixed.txt} ? 0 : 3)"]],"max_rounds":2}"#,
        r#"["harness.fs.read","harness.exec.run"]"#,
        true,
    );
    let m = mock(vec![
        act("harness.task.submit", r#"{"note":"first"}"#),
        act(
            "harness.exec.run",
            r#"{"argv":["perl","-e","open(my $f, q{>}, q{fixed.txt}) or die; print $f q{ok}"]}"#,
        ),
        act("harness.task.submit", r#"{"note":"second"}"#),
    ]);
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let mut args = run_args(&fx, &ep);
    args.extend_from_slice(&["--policy", allow.to_str().unwrap()]);
    let o = cli(&args, false, &fx.marker);
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.code(), Some(5), "{err}");
    assert!(err.contains("stopped (submitted) after 3 step(s)"), "{err}");
    assert!(
        err.contains("pre-submit checks: 2 submission(s) ran the checks, 1 turned back (the bound is 2); every check passed"),
        "{err}"
    );
    let rep = report(&o);
    let f = rep["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["code"] == "harness.presubmit")
        .unwrap();
    assert!(
        f["observed"].as_str().unwrap().contains("1 turned back"),
        "{f}"
    );
    let id = run_id(&o);
    let head = String::from_utf8(o.stdout.clone())
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .strip_prefix("chain_head ")
        .unwrap()
        .to_owned();
    std::fs::remove_file(fx.ws.join("fixed.txt")).unwrap();
    let rp = replay_bin(
        &fx,
        &id,
        &["--anchor", &head, "--policy", allow.to_str().unwrap()],
    );
    let rerr = String::from_utf8_lossy(&rp.stderr);
    assert!(rerr.contains(REPLAY_MATCHED), "{rerr}");
    assert!(!fx.ws.join("fixed.txt").exists(), "the replay ran nothing");
    // The same run replayed with the checks left out of the task file is a
    // header mismatch, by name.
    let mut without: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&fx.task).unwrap()).unwrap();
    without.as_object_mut().unwrap().remove("presubmit");
    std::fs::write(&fx.task, without.to_string()).unwrap();
    let o = replay_bin(&fx, &id, &["--policy", allow.to_str().unwrap()]);
    assert_replay_diverged(&o, "pre-submit checks", &fx.marker);
}

/// A submission accepted with a check still failing is said so, in words,
/// as a finding and as its own stop cause.
#[cfg(target_os = "macos")]
#[test]
fn h3a_a_spent_bound_is_reported_as_a_check_still_failing() {
    let (fx, allow) = presubmit_task(
        "presubmit-spent",
        r#"{"commands":[["perl","-e","exit 1"]],"max_rounds":1}"#,
        r#"["harness.fs.read","harness.exec.run"]"#,
        true,
    );
    let m = mock(vec![
        act("harness.task.submit", r#"{"note":"a"}"#),
        act("harness.task.submit", r#"{"note":"b"}"#),
    ]);
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let mut args = run_args(&fx, &ep);
    args.extend_from_slice(&["--policy", allow.to_str().unwrap()]);
    let o = cli(&args, false, &fx.marker);
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.code(), Some(5), "{err}");
    assert!(err.contains("stopped (submitted_checks_failed)"), "{err}");
    assert!(
        err.contains("a check still failed at the last submission, which was accepted anyway"),
        "{err}"
    );
    let rep = report(&o);
    assert_eq!(rep["outcome"]["Indeterminate"]["why"], "NothingChecked");
    let id = run_id(&o);
    let head = String::from_utf8(o.stdout.clone())
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .strip_prefix("chain_head ")
        .unwrap()
        .to_owned();
    let rp = replay_bin(
        &fx,
        &id,
        &["--anchor", &head, "--policy", allow.to_str().unwrap()],
    );
    let rerr = String::from_utf8_lossy(&rp.stderr);
    assert!(rerr.contains(REPLAY_MATCHED), "{rerr}");
}

// ---- P-12: the CLI's sensitive-path default denies --------------------------------

/// Without `--policy` the CLI overlays its default deny list (P-12): the
/// model's read of `.env` is denied at the policy and the denial — never
/// the secret — reaches the model's next prompt. With
/// `--no-default-denies` the same task reads the file.
#[test]
fn read_dot_env_denied_by_default_cli() {
    let fx = fixture("denies-default");
    std::fs::write(fx.ws.join(".env"), "SECRET=1\n").unwrap();
    let captured = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = captured.clone();
    let m = mock_with(
        vec![
            act("harness.fs.read", r#"{"path":".env"}"#),
            act("harness.task.submit", r#"{"note":"done"}"#),
        ],
        move |req| sink.lock().unwrap().push(req.to_owned()),
    );
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let o = cli(&run_args(&fx, &ep), true, &fx.marker);
    assert_eq!(
        o.code(),
        Some(5),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    // Two chat requests: the second carries the denial, not the secret.
    {
        let got = captured.lock().unwrap();
        assert_eq!(got.len(), 2, "{}", got.len());
        assert!(got[1].contains("Policy denied the call."), "{}", got[1]);
        assert!(!got[1].contains("SECRET=1"), "{}", got[1]);
    }
    assert_eq!(
        std::fs::read_to_string(fx.ws.join(".env")).unwrap(),
        "SECRET=1\n"
    );

    // The off-switch: the same task reads `.env` whole.
    let fx = fixture("denies-off");
    std::fs::write(fx.ws.join(".env"), "SECRET=1\n").unwrap();
    let captured = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = captured.clone();
    let m = mock_with(
        vec![
            act("harness.fs.read", r#"{"path":".env"}"#),
            act("harness.task.submit", r#"{"note":"done"}"#),
        ],
        move |req| sink.lock().unwrap().push(req.to_owned()),
    );
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let mut args = run_args(&fx, &ep);
    args.push("--no-default-denies");
    let o = cli(&args, true, &fx.marker);
    assert_eq!(
        o.code(),
        Some(5),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let got = captured.lock().unwrap();
    assert!(got[1].contains("SECRET=1"), "{}", got[1]);
}

/// The bundle and the overlay setting (P-14 × P-12): a run's recorded
/// policy digest is the effective policy's, so a run made with
/// `--no-default-denies` replays from its bundle only under the same
/// setting; replaying with the default overlay on is a different policy,
/// refused by name before the audit (exit 4).
#[test]
fn replay_of_a_no_default_denies_run_needs_the_same_setting() {
    let fx = fixture("denies-off-bundle");
    let m = mock(vec![act("harness.task.submit", r#"{"note":"done"}"#)]);
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let mut args = run_args(&fx, &ep);
    args.push("--no-default-denies");
    let o = cli(&args, true, &fx.marker);
    assert_eq!(o.code(), Some(5), "{}", String::from_utf8_lossy(&o.stderr));
    let id = run_id(&o);

    // The same setting: the bundle fills the policy, the audit matches.
    let rp = replay_bin(&fx, &id, &["--no-default-denies"]);
    let rerr = String::from_utf8_lossy(&rp.stderr);
    assert_eq!(rp.code(), Some(5), "{rerr}");
    assert!(rerr.contains(REPLAY_MATCHED), "{rerr}");

    // The other setting: a different policy digest, refused by the bundle.
    let rp = replay_bin(&fx, &id, &[]);
    let rerr = String::from_utf8_lossy(&rp.stderr);
    assert_eq!(rp.code(), Some(4), "{rerr}");
    assert!(
        rerr.contains("policy the default policy does not match the digests recorded"),
        "{rerr}"
    );
}

/// The bundle records the policy the run digested — the default with the
/// overlay applied (P-12) — so a replay under a different overlay setting
/// is refused by name before anything runs, and the run's own setting
/// replays clean.
#[test]
fn replay_needs_the_runs_default_deny_overlay_setting() {
    let fx = fixture("denies-bundle-on");
    let m = mock(vec![act("harness.task.submit", r#"{"note":"done"}"#)]);
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let o = cli(&run_args(&fx, &ep), true, &fx.marker);
    assert_eq!(
        o.code(),
        Some(5),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let id = run_id(&o);
    let head = String::from_utf8(o.stdout.clone())
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .strip_prefix("chain_head ")
        .unwrap()
        .to_owned();
    // The run's setting: matched.
    let rp = replay_bin(&fx, &id, &["--anchor", &head]);
    let err = String::from_utf8_lossy(&rp.stderr);
    assert!(err.contains(REPLAY_MATCHED), "{err}");
    // The overlay turned off for the replay: refused, by name.
    let rp = replay_bin(&fx, &id, &["--anchor", &head, "--no-default-denies"]);
    assert_eq!(rp.code(), Some(4));
    let err = String::from_utf8_lossy(&rp.stderr);
    assert!(
        err.contains("policy the default policy does not match the digests recorded"),
        "{err}"
    );

    // The mirror image: a run without the overlay, replayed with it.
    let fx = fixture("denies-bundle-off");
    let m = mock(vec![act("harness.task.submit", r#"{"note":"done"}"#)]);
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let mut args = run_args(&fx, &ep);
    args.push("--no-default-denies");
    let o = cli(&args, true, &fx.marker);
    assert_eq!(
        o.code(),
        Some(5),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let id = run_id(&o);
    let head = String::from_utf8(o.stdout.clone())
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .strip_prefix("chain_head ")
        .unwrap()
        .to_owned();
    let rp = replay_bin(&fx, &id, &["--anchor", &head]);
    assert_eq!(rp.code(), Some(4));
    let err = String::from_utf8_lossy(&rp.stderr);
    assert!(
        err.contains("policy the default policy does not match the digests recorded"),
        "{err}"
    );
    let rp = replay_bin(&fx, &id, &["--anchor", &head, "--no-default-denies"]);
    let err = String::from_utf8_lossy(&rp.stderr);
    assert!(err.contains(REPLAY_MATCHED), "{err}");
}

// ---- P-15: the events projection, --follow, and the usage footer ------------

use harness_journal::canon::{EventKind as JK, RecordFields, GENESIS};

/// A mock whose every chat reply reports usage with a cached-token claim
/// (`usage.prompt_tokens_details.cached_tokens`, which the wire layer keeps
/// as the `claimed_stats` untrusted payload).
fn mock_cached(replies: Vec<String>) -> Mock {
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
                let content = queue.lock().unwrap().pop_front().unwrap_or_default();
                let body = serde_json::json!({
                    "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 100, "completion_tokens": 10,
                              "prompt_tokens_details": {"cached_tokens": 64}}
                })
                .to_string();
                respond(&mut s, &body);
            }
        }
    });
    Mock { port, requests }
}

/// Canonical journal bytes (one line per kind) for a hand-built attempt.
fn chain_bytes(run: &str, attempt: u32, kinds: &[JK]) -> Vec<u8> {
    let rid = harness_core::RunId::parse(run).unwrap();
    let mut out = Vec::new();
    let mut prev = GENESIS;
    for (i, kind) in kinds.iter().enumerate() {
        let fields = RecordFields {
            seq: i as u64,
            prev,
            t_mono_ms: 100 * (i as u64 + 1),
            t_wall: "2026-01-01T00:00:00.000Z".into(),
            run: rid.clone(),
            attempt,
            step: 0,
            kind: *kind,
            body: serde_json::Map::new(),
        };
        let (line, hash) = fields.encode();
        out.extend_from_slice(&line);
        out.push(b'\n');
        prev = hash;
    }
    out
}

/// A hand-built `attempt-1` under `state`: the directory names the reader
/// and the tail require.
fn hand_attempt(state: &Path, run: &str) -> PathBuf {
    let dir = state.join("runs").join(run).join("attempt-1");
    std::fs::create_dir_all(dir.join("blobs")).unwrap();
    dir
}

/// A fresh run id-shaped id (32 lowercase hex) for hand-built journals.
fn hand_run(tag: u64) -> String {
    format!("{:032x}", tag)
}

/// An in-process run with its own mock (the usual two replies: read, then
/// submit), returning the output. `extra` appends run options.
fn run_tool_run(fx: &Fx, extra: &[&str], replies: Vec<String>) -> Output {
    let m = mock(replies);
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let mut args = run_args(fx, &ep);
    args.extend_from_slice(extra);
    cli(&args, true, &fx.marker)
}

fn events_args<'a>(fx: &'a Fx, id: &'a str) -> Vec<&'a str> {
    vec![
        "events",
        "--run",
        id,
        "--state-root",
        fx.state.to_str().unwrap(),
    ]
}

const SCHEMA: &str = r#"{"schema":"rh-events/1"}"#;

/// stdout as lines (the schema line first, then one line per record).
fn stream_lines(o: &Output) -> Vec<String> {
    String::from_utf8(o.stdout.clone())
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn events_ndjson_one_line_per_record() {
    let fx = fixture("events-basic");
    let o = run_tool_run(
        &fx,
        &[],
        vec![
            act("harness.fs.read", r#"{"path":"a.txt"}"#),
            act("harness.task.submit", r#"{"note":"done"}"#),
        ],
    );
    assert_eq!(o.code(), Some(5), "{}", String::from_utf8_lossy(&o.stderr));
    let id = run_id(&o);
    let ev = cli(&events_args(&fx, &id), true, &fx.marker);
    assert_eq!(
        ev.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&ev.stderr)
    );
    let lines = stream_lines(&ev);
    assert_eq!(lines[0], SCHEMA, "the first line names the schema");
    let journal = fx
        .state
        .join("runs")
        .join(&id)
        .join("attempt-1")
        .join("journal.jsonl");
    let on_disk = std::fs::read_to_string(&journal).unwrap().lines().count();
    assert_eq!(lines.len() - 1, on_disk, "one line per record");
    for line in &lines[1..] {
        let v: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("{line}: {e}"));
        let obj = v.as_object().unwrap();
        for k in [
            "attempt",
            "body",
            "hash",
            "kind",
            "prev",
            "run",
            "seq",
            "step",
            "t_mono_ms",
            "t_wall",
        ] {
            assert!(obj.contains_key(k), "{k} missing from {line}");
        }
        assert_eq!(obj["run"], id, "every record names the run");
    }
    let last: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    assert_eq!(last["kind"], "RunStopped");
    let first: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
    assert_eq!(first["kind"], "RunStarted");
    assert_eq!(first["seq"], 0);
}

#[test]
fn events_chain_verifiable_from_stream() {
    let fx = fixture("events-chain");
    let o = run_tool_run(
        &fx,
        &[],
        vec![
            act("harness.fs.read", r#"{"path":"a.txt"}"#),
            act("harness.task.submit", r#"{"note":"done"}"#),
        ],
    );
    let id = run_id(&o);
    let head = String::from_utf8(o.stdout.clone())
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .strip_prefix("chain_head ")
        .unwrap()
        .to_owned();
    let ev = cli(&events_args(&fx, &id), true, &fx.marker);
    let lines = stream_lines(&ev);
    // The hash chain, recomputed straight off the stream (§7.1): hash =
    // sha256(prev_raw_bytes || canonical(line without "hash")).
    let mut prev = "0".repeat(64);
    for line in &lines[1..] {
        let mut v: serde_json::Value = serde_json::from_str(line).unwrap();
        let obj = v.as_object_mut().unwrap();
        let stated = obj.remove("hash").unwrap().as_str().unwrap().to_owned();
        assert_eq!(obj["prev"].as_str().unwrap(), prev, "record links back");
        let canonical = serde_json::Value::Object(obj.clone()).to_string();
        let raw: Vec<u8> = (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&prev[i..i + 2], 16).unwrap())
            .collect();
        let digest = harness_core::sha256_parts(&[&raw, canonical.as_bytes()]).to_string();
        assert_eq!(digest, stated, "record {line}");
        prev = stated;
    }
    assert_eq!(prev, head, "the stream's head is the run's chain head");
}

#[test]
fn events_untrusted_payload_sanitised() {
    let fx = fixture("events-sanitised");
    // Zero-width and bidi characters are valid inside the model's JSON, so
    // they reach the journal verbatim in the tool call; the journal's
    // payload escaping (§7.1) must neutralise them in the stream.
    let sneaky = "zero\u{200B}width\u{202E}bidi\u{2066}iso\u{2069}";
    let o = run_tool_run(
        &fx,
        &[],
        vec![
            act("harness.fs.read", r#"{"path":"a.txt"}"#),
            act("harness.task.submit", &format!(r#"{{"note":"{sneaky}"}}"#)),
        ],
    );
    let id = run_id(&o);
    let ev = cli(&events_args(&fx, &id), true, &fx.marker);
    assert_eq!(ev.code(), Some(0));
    let text = String::from_utf8(ev.stdout.clone()).unwrap();
    for raw in ['\u{200b}', '\u{202e}', '\u{2066}', '\u{2069}'] {
        assert!(
            !text.contains(raw),
            "a raw invisible character is in the stream"
        );
    }
    assert!(
        text.contains("\\\\u{200B}"),
        "the escaped spelling should be in the stream: {text}"
    );
    assert!(text.contains("\\\\u{202E}"), "{text}");
}

#[test]
fn events_torn_tail_not_emitted() {
    let fx = fixture("events-torn");
    let id = hand_run(2);
    let dir = hand_attempt(&fx.state, &id);
    let whole = chain_bytes(&id, 1, &[JK::RunStarted, JK::ContextBuilt]);
    let split = whole.iter().position(|b| *b == b'\n').unwrap() + 1;
    let mut torn = whole[..split].to_vec();
    torn.extend_from_slice(&whole[split..split + 20]); // half a line, no newline
    std::fs::write(dir.join("journal.jsonl"), torn).unwrap();
    let ev = cli(&events_args(&fx, &id), true, &fx.marker);
    assert_eq!(
        ev.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&ev.stderr)
    );
    let lines = stream_lines(&ev);
    assert_eq!(lines.len(), 2, "only the verified prefix: {lines:?}");
    assert_eq!(lines[0], SCHEMA);
    let v: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
    assert_eq!(v["kind"], "RunStarted");
    assert!(
        !lines[1].contains("ContextBuilt"),
        "the torn line is not shown"
    );
}

/// stdout that a background thread writes into, so a test can drive a
/// `--follow` tail by appending to the journal while it polls.
struct SharedOut(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for SharedOut {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn wait_until(pred: impl Fn() -> bool) -> bool {
    for _ in 0..200 {
        if pred() {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    false
}

#[test]
fn events_follow_sees_new_records() {
    let fx = fixture("events-follow");
    let id = hand_run(3);
    let dir = hand_attempt(&fx.state, &id);
    let whole = chain_bytes(&id, 1, &[JK::RunStarted, JK::ContextBuilt, JK::RunStopped]);
    let split = whole.iter().position(|b| *b == b'\n').unwrap() + 1;
    let mut partial = whole[..split].to_vec();
    partial.extend_from_slice(&whole[split..split + 10]); // line 2 torn
    std::fs::write(dir.join("journal.jsonl"), partial).unwrap();
    let out = Arc::new(Mutex::new(Vec::new()));
    let args = [
        "events".to_owned(),
        "--run".to_owned(),
        id.clone(),
        "--state-root".to_owned(),
        fx.state.to_str().unwrap().to_owned(),
        "--follow".to_owned(),
    ];
    let watch = out.clone();
    let inner = out.clone();
    let handle = thread::spawn(move || {
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut sink = SharedOut(inner);
        let mut sink_err = SharedOut(Arc::new(Mutex::new(Vec::new())));
        let cx = harness_cli::Cx {
            probe: &Local,
            gate_ok_file: None,
            out: RefCell::new(&mut sink),
            err: RefCell::new(&mut sink_err),
            approver: harness_cli::ApproverSource::None,
            input: harness_cli::InputSource::Given(&[]),
            backend: harness_cli::BackendSource::BuiltIn,
            confinement: &harness_sandbox::SystemConfinement,
        };
        harness_cli::main_with(&cx, &borrowed)
    });
    assert!(
        wait_until(|| {
            let g = watch.lock().unwrap();
            let t = String::from_utf8_lossy(&g);
            t.lines().count() >= 2 && t.contains("RunStarted")
        }),
        "the tail should show the first record: {}",
        String::from_utf8_lossy(&out.lock().unwrap())
    );
    // The run commits: the torn line completes and `RunStopped` lands.
    std::fs::write(dir.join("journal.jsonl"), whole).unwrap();
    let watch2 = out.clone();
    assert!(
        wait_until(|| String::from_utf8_lossy(&watch2.lock().unwrap()).contains("RunStopped")),
        "the tail should see the commit: {}",
        String::from_utf8_lossy(&out.lock().unwrap())
    );
    let code = handle.join().expect("the tail thread");
    assert_eq!(code, 0);
    let text = String::from_utf8(out.lock().unwrap().clone()).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], SCHEMA);
    assert_eq!(lines.len(), 4, "all three records, once each: {text}");
    assert!(lines[1].contains("RunStarted"));
    assert!(lines[2].contains("ContextBuilt"));
    assert!(lines[3].contains("RunStopped"));
    // The torn half-line was never emitted before it completed: the
    // ContextBuilt line appears exactly once.
    assert_eq!(text.matches("ContextBuilt").count(), 1);
}

#[test]
fn usage_matches_budget_charged() {
    let fx = fixture("usage-footer");
    let m = mock_cached(vec![
        act("harness.fs.read", r#"{"path":"a.txt"}"#),
        act("harness.task.submit", r#"{"note":"done"}"#),
    ]);
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let mut args = run_args(&fx, &ep);
    args.extend_from_slice(&["--output", "stream-json"]);
    let o = cli(&args, true, &fx.marker);
    assert_eq!(o.code(), Some(5), "{}", String::from_utf8_lossy(&o.stderr));
    let id = run_id(&o);
    let lines = stream_lines(&o);
    let usage_at = lines
        .iter()
        .position(|l| l.starts_with("usage {"))
        .expect("a usage line");
    let u: serde_json::Value =
        serde_json::from_str(&lines[usage_at][6..]).expect("the usage object");
    // What the server charged (two replies, 100 in / 10 out / 64 claimed
    // cached each) is what the footer says.
    assert_eq!(u["model_calls"], 2);
    assert_eq!(u["tokens"]["in"], 200);
    assert_eq!(u["tokens"]["out"], 20);
    assert_eq!(u["tokens"]["cached"], 128);
    assert_eq!(u["steps"], 2, "the loop's steps, from the journal");
    assert_eq!(
        u["tools"],
        serde_json::json!({"harness.fs.read": 1, "harness.task.submit": 1}),
        "tool calls started, by capability"
    );
    let wall = u["wall_ms"].as_u64().unwrap();
    assert!(wall > 0, "a real run takes some milliseconds");
    // Cross-checked against the journal itself.
    let journal = std::fs::read_to_string(
        fx.state
            .join("runs")
            .join(&id)
            .join("attempt-1")
            .join("journal.jsonl"),
    )
    .unwrap();
    let asked = journal.matches("\"kind\":\"ModelRequested\"").count();
    assert_eq!(u["model_calls"].as_u64().unwrap(), asked as u64);
    assert_eq!(journal.matches("\"kind\":\"ToolStarted\"").count(), 2);
    // The words, for the person at the terminal.
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains(
            "usage: 2 step(s), 2 model call(s), tokens in 200 out 20 (cached 128, server-claimed)"
        ),
        "{err}"
    );
}

#[test]
fn final_stdout_line_still_gatereport() {
    let fx = fixture("stream-report");
    let m = mock_cached(vec![act("harness.task.submit", r#"{"note":"done"}"#)]);
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    let mut args = run_args(&fx, &ep);
    args.extend_from_slice(&["--output", "stream-json"]);
    let o = cli(&args, true, &fx.marker);
    assert_eq!(o.code(), Some(5));
    let lines = stream_lines(&o);
    let last = lines.last().unwrap();
    let rep: serde_json::Value = serde_json::from_str(last).expect("the report line");
    assert_eq!(rep["gate"], "rustyharness.run");
    assert_eq!(rep["outcome"]["Indeterminate"]["why"], "NothingChecked");
    let head_at = lines
        .iter()
        .position(|l| l.starts_with("chain_head "))
        .expect("a chain head line");
    let usage_at = lines
        .iter()
        .position(|l| l.starts_with("usage {"))
        .expect("a usage line");
    assert!(usage_at < head_at, "usage comes before the chain head");
    assert_eq!(head_at, lines.len() - 2, "chain head, then the report");
    assert!(lines[0].starts_with(SCHEMA), "the stream opens the output");
}

#[test]
fn stream_json_run_exit_codes_unchanged() {
    let fx = fixture("stream-exit");
    let replies = vec![act("harness.task.submit", r#"{"note":"done"}"#)];
    let plain = run_tool_run(&fx, &[], replies.clone());
    let streamed = run_tool_run(&fx, &["--output", "stream-json"], replies.clone());
    assert_eq!(plain.code(), streamed.code(), "same exit code");
    assert_eq!(plain.code(), Some(5));
    assert_eq!(
        report(&plain)["outcome"],
        report(&streamed)["outcome"],
        "same verdict"
    );
    let last = last_line(&streamed);
    serde_json::from_str::<serde_json::Value>(&last).expect("still a GateReport");
    assert!(
        !fx.marker.exists(),
        "NothingChecked never writes the marker"
    );
    // An unknown output mode is a usage error through the report path,
    // before anything runs.
    let bad = run_tool_run(&fx, &["--output", "fancy"], replies.clone());
    assert_eq!(
        bad.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&bad.stderr)
    );
    let rep = report(&bad);
    assert_eq!(rep["gate"], "rustyharness.run");
    let err = String::from_utf8_lossy(&bad.stderr);
    assert!(err.contains("--output must be stream-json"), "{err}");
}
