//! The `compare` verb (P-48) end to end, in process against a mock
//! OpenAI-compatible server on loopback: two arms of the same task, each
//! from its own fresh scratch copy, the facts-only report, the hidden
//! mapping and the reveal, the per-arm audit, and the refusals.

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

use gate_outcome::Digest;
use serde_json::Value;

// ---- a mock model server (as tests/cli.rs) -----------------------------------

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

fn endpoint(m: &Mock) -> String {
    format!("http://127.0.0.1:{}/v1", m.port)
}

fn act(tool: &str, args: &str) -> String {
    format!("ok <action>{{\"tool\":\"{tool}\",\"args\":{args}}}</action>")
}

// ---- fixtures -----------------------------------------------------------------

/// Two profiles that differ only in id: the mapping's whole point.
fn profile_json(id: &str) -> String {
    format!(
        r#"{{"profile_version":1,"id":"{id}","model":"m",
  "context_window":32768,"fill_ratio":0.6,"protocol":"text","tool_choice_required_ok":false,
  "grammar":"none","max_active_tools":6,"edit_format":"replace","recent_turns":5,
  "sampling":{{"temperature":0.2,"top_p":0.95,"seed":7,"max_tokens":2048}}}}"#
    )
}

struct Fx {
    base: PathBuf,
    state: PathBuf,
    ws: PathBuf,
    task: PathBuf,
    profile1: PathBuf,
    profile2: PathBuf,
    policy: PathBuf,
    marker: PathBuf,
    cfg_home: PathBuf,
}

fn fixture(name: &str, task: &str) -> Fx {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("cli-compare-{name}"));
    let _ = std::fs::remove_dir_all(&base);
    let (state, ws) = (base.join("state"), base.join("ws"));
    std::fs::create_dir_all(&state).unwrap();
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::create_dir_all(base.join("cfg-home")).unwrap();
    std::fs::write(ws.join("a.txt"), "the answer is in here\n").unwrap();
    let task_path = base.join("task.json");
    std::fs::write(&task_path, task).unwrap();
    let profile1 = base.join("profile-1.json");
    std::fs::write(&profile1, profile_json("mock-1")).unwrap();
    let profile2 = base.join("profile-2.json");
    std::fs::write(&profile2, profile_json("mock-2")).unwrap();
    let policy = base.join("allow-edits.json");
    std::fs::write(
        &policy,
        r#"{"allow":["harness.edit.replace","harness.edit.write"]}"#,
    )
    .unwrap();
    Fx {
        marker: base.join("gate-ok"),
        cfg_home: base.join("cfg-home"),
        base,
        state,
        ws,
        task: task_path,
        profile1,
        profile2,
        policy,
    }
}

// ---- the CLI in process ---------------------------------------------------------

/// The user config must not leak into these runs: every test holds the
/// lock and points the config home at an empty directory.
static ENV_LOCK: Mutex<()> = Mutex::new(());

struct Output {
    code: u8,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn cli(fx: &Fx, args: &[&str]) -> Output {
    std::env::set_var("RUSTYHARNESS_CONFIG_HOME", &fx.cfg_home);
    std::env::set_var("RUSTYHARNESS_STATE_HOME", fx.base.join("state-home"));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = {
        let cx = harness_cli::Cx {
            probe: &harness_testkit::Local,
            gate_ok_file: Some(fx.marker.clone()),
            out: RefCell::new(&mut out),
            err: RefCell::new(&mut err),
            approver: harness_cli::ApproverSource::None,
            input: harness_cli::InputSource::Given(&[]),
            backend: harness_cli::BackendSource::BuiltIn,
            confinement: &harness_sandbox::SystemConfinement,
        };
        harness_cli::main_with(&cx, args)
    };
    std::env::remove_var("RUSTYHARNESS_CONFIG_HOME");
    std::env::remove_var("RUSTYHARNESS_STATE_HOME");
    Output {
        code,
        stdout: out,
        stderr: err,
    }
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn last_line(o: &Output) -> Value {
    let text = String::from_utf8_lossy(&o.stdout);
    serde_json::from_str(text.lines().last().unwrap()).unwrap()
}

/// The one compare directory under the state root.
fn compare_dir(fx: &Fx) -> PathBuf {
    let root = fx.state.join("compare");
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1, "one compare run per test");
    entries.pop().unwrap()
}

/// An arm's fresh copy: `<state-root>/scratch/<stamp>-<label>/`, beside a
/// run's own scratch copies and disjoint from the arm's run state root.
fn arm_copy(fx: &Fx, dir: &Path, label: &str) -> PathBuf {
    let stamp = dir.file_name().unwrap().to_string_lossy().into_owned();
    fx.state.join("scratch").join(format!("{stamp}-{label}"))
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The mapping's label for the arm whose profile id is `model`.
fn label_of(map: &Value, model: &str) -> String {
    for a in map["arms"].as_array().unwrap() {
        if a["model"].as_str().unwrap() == model {
            return a["label"].as_str().unwrap().to_owned();
        }
    }
    panic!("no arm with model {model}");
}

/// Run a two-arm compare; the arms write `b.txt`, each its own content.
fn run_write_compare(fx: &Fx, one: &str, two: &str) -> Output {
    let m = mock(vec![
        act(
            "harness.edit.write",
            &format!(r#"{{"path":"b.txt","content":"{one}\n"}}"#),
        ),
        act("harness.task.submit", r#"{"note":"done"}"#),
        act(
            "harness.edit.write",
            &format!(r#"{{"path":"b.txt","content":"{two}\n"}}"#),
        ),
        act("harness.task.submit", r#"{"note":"done"}"#),
    ]);
    let ep = endpoint(&m);
    let args: Vec<String> = vec![
        "compare".into(),
        "--task".into(),
        fx.task.to_string_lossy().into_owned(),
        "--workspace".into(),
        fx.ws.to_string_lossy().into_owned(),
        "--state-root".into(),
        fx.state.to_string_lossy().into_owned(),
        "--profile".into(),
        fx.profile1.to_string_lossy().into_owned(),
        "--endpoint".into(),
        ep.clone(),
        "--profile".into(),
        fx.profile2.to_string_lossy().into_owned(),
        "--endpoint".into(),
        ep,
        "--policy".into(),
        fx.policy.to_string_lossy().into_owned(),
    ];
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let _g = ENV_LOCK.lock().unwrap();
    cli(fx, &refs)
}

// ---- the tests --------------------------------------------------------------------

/// The same task on two profiles: each arm runs in its own fresh copy of
/// the workspace, the arms cannot see each other's writes, and the
/// original is never touched.
#[test]
fn compare_runs_each_arm_in_fresh_copy() {
    let fx = fixture(
        "fresh",
        r#"{"task":"Write b.txt.","grants":["harness.fs.read","harness.edit.write"]}"#,
    );
    let o = run_write_compare(&fx, "one", "two");
    assert_eq!(o.code, 5, "{}", stderr(&o));
    assert_eq!(
        last_line(&o)["outcome"]["Indeterminate"]["why"],
        "NothingChecked"
    );
    let dir = compare_dir(&fx);
    let report = read_json(&dir.join("report.json"));
    let map = read_json(&dir.join("mapping.json"));
    // Two arms, two runs, two distinct ids.
    let arms = report["arms"].as_array().unwrap();
    assert_eq!(arms.len(), 2);
    assert_ne!(arms[0]["run"], arms[1]["run"]);
    // The source workspace was never written.
    assert_eq!(
        std::fs::read_to_string(fx.ws.join("a.txt")).unwrap(),
        "the answer is in here\n"
    );
    assert!(!fx.ws.join("b.txt").exists());
    // Each arm's copy holds only its own model's write.
    for (model, text) in [("mock-1", "one\n"), ("mock-2", "two\n")] {
        let label = label_of(&map, model);
        let wrote = std::fs::read_to_string(arm_copy(&fx, &dir, &label).join("b.txt")).unwrap();
        assert_eq!(wrote, text, "arm {label} ({model}) wrote its own file");
        assert_eq!(
            std::fs::read_to_string(arm_copy(&fx, &dir, &label).join("a.txt")).unwrap(),
            "the answer is in here\n",
            "each copy starts fresh"
        );
    }
}

/// The report carries labels only; the label→model map lives in
/// mapping.json and is printed only after a winner is recorded.
#[test]
fn compare_labels_hide_model_until_reveal() {
    let fx = fixture(
        "hide",
        r#"{"task":"Write b.txt.","grants":["harness.fs.read","harness.edit.write"]}"#,
    );
    let o = run_write_compare(&fx, "one", "two");
    assert_eq!(o.code, 5, "{}", stderr(&o));
    let dir = compare_dir(&fx);
    let report_path = dir.join("report.json");
    let report_text = std::fs::read_to_string(&report_path).unwrap();
    let map_text = std::fs::read_to_string(dir.join("mapping.json")).unwrap();
    for secret in [
        "mock-1",
        "mock-2",
        "profile-1.json",
        "profile-2.json",
        "127.0.0.1",
    ] {
        assert!(
            !report_text.contains(secret),
            "the report must not name {secret}"
        );
        assert!(map_text.contains(secret), "the mapping names {secret}");
    }
    let map = serde_json::from_str::<Value>(&map_text).unwrap();
    let picked = label_of(&map, "mock-1");

    // No winner, no map.
    let args: Vec<String> = vec![
        "compare".into(),
        "reveal".into(),
        "--report".into(),
        report_path.to_string_lossy().into_owned(),
    ];
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let _g = ENV_LOCK.lock().unwrap();
    let r1 = cli(&fx, &refs);
    assert_eq!(r1.code, 2, "{}", stderr(&r1));
    assert!(stderr(&r1).contains("winner"), "{}", stderr(&r1));

    // The pick is recorded, then the map is printed.
    let args: Vec<String> = vec![
        "compare".into(),
        "reveal".into(),
        "--report".into(),
        report_path.to_string_lossy().into_owned(),
        "--winner".into(),
        picked.clone(),
    ];
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let r2 = cli(&fx, &refs);
    assert_eq!(r2.code, 5, "{}", stderr(&r2));
    assert!(
        String::from_utf8_lossy(&r2.stdout).contains("mock-1"),
        "the reveal prints the map"
    );
    let report = read_json(&report_path);
    assert_eq!(report["winner"].as_str(), Some(picked.as_str()));

    // A later reveal needs no winner again.
    let args: Vec<String> = vec![
        "compare".into(),
        "reveal".into(),
        "--report".into(),
        report_path.to_string_lossy().into_owned(),
    ];
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let r3 = cli(&fx, &refs);
    assert_eq!(r3.code, 5, "{}", stderr(&r3));
}

/// The report lists facts, one fixed field set per arm — never a score,
/// a rank or a harness-picked winner.
#[test]
fn compare_report_lists_facts_not_scores() {
    let fx = fixture(
        "facts",
        r#"{"task":"Write b.txt.","grants":["harness.fs.read","harness.edit.write"]}"#,
    );
    let o = run_write_compare(&fx, "one", "two");
    assert_eq!(o.code, 5, "{}", stderr(&o));
    let dir = compare_dir(&fx);
    let report_text = std::fs::read_to_string(dir.join("report.json")).unwrap();
    assert!(!report_text.contains("score"), "no score anywhere");
    assert!(!report_text.contains("rank"), "no rank anywhere");
    let report: Value = serde_json::from_str(&report_text).unwrap();
    let mut top: Vec<&str> = report
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    top.sort_unstable();
    assert_eq!(top, vec!["arms", "format", "seed", "winner"]);
    assert!(report["winner"].is_null(), "the harness picks no winner");
    let mut fields: Vec<&str> = vec![
        "label",
        "run",
        "attempt",
        "cause",
        "steps",
        "tokens_in",
        "tokens_out",
        "wall_ms",
        "format_errors",
        "tools",
        "diff",
        "presubmit",
        "chain_head",
    ];
    fields.sort_unstable();
    for a in report["arms"].as_array().unwrap() {
        let mut got: Vec<&str> = a.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        got.sort_unstable();
        assert_eq!(got, fields, "exactly the fact fields, nothing scored");
        assert!(a["diff"].is_string());
        assert!(a["chain_head"].is_string());
    }
}

/// Every arm's journal audits clean: the replay of each side-by-side run
/// recomputes every decision and the stop, anchored at the chain head.
#[test]
fn compare_each_arm_audits_clean() {
    let fx = fixture(
        "audit",
        r#"{"task":"What does a.txt say?","grants":["harness.fs.read","harness.fs.list"]}"#,
    );
    let m = mock(vec![
        act("harness.fs.read", r#"{"path":"a.txt"}"#),
        act("harness.task.submit", r#"{"note":"read it"}"#),
        act("harness.fs.read", r#"{"path":"a.txt"}"#),
        act("harness.task.submit", r#"{"note":"read it"}"#),
    ]);
    let ep = endpoint(&m);
    let args: Vec<String> = vec![
        "compare".into(),
        "--task".into(),
        fx.task.to_string_lossy().into_owned(),
        "--workspace".into(),
        fx.ws.to_string_lossy().into_owned(),
        "--state-root".into(),
        fx.state.to_string_lossy().into_owned(),
        "--profile".into(),
        fx.profile1.to_string_lossy().into_owned(),
        "--endpoint".into(),
        ep.clone(),
        "--profile".into(),
        fx.profile2.to_string_lossy().into_owned(),
        "--endpoint".into(),
        ep,
        "--no-default-denies".into(),
    ];
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let _g = ENV_LOCK.lock().unwrap();
    let o = cli(&fx, &refs);
    assert_eq!(o.code, 5, "{}", stderr(&o));

    let dir = compare_dir(&fx);
    let report = read_json(&dir.join("report.json"));
    let map = read_json(&dir.join("mapping.json"));
    let registry = harness_testkit::registry().unwrap();
    let spec = harness_run::TaskSpec {
        task: harness_model::TaskText::new("What does a.txt say?".to_owned()),
        grants: vec!["harness.fs.read".to_owned(), "harness.fs.list".to_owned()],
        workspace_public: false,
        ports: Vec::new(),
        lan_ports: Vec::new(),
        exec: None,
        presubmit: None,
        protected: Vec::new(),
        kind: harness_run::SessionKind::Coding,
    };
    let policy = harness_policy::UserPolicy::default();
    let limits = harness_run::RunConfig::defaults(1_000_000).limits;
    for (a, m) in report["arms"]
        .as_array()
        .unwrap()
        .iter()
        .zip(map["arms"].as_array().unwrap())
    {
        let profile_bytes = std::fs::read(m["profile"].as_str().unwrap()).unwrap();
        let profile = harness_model::profile::Profile::parse(&profile_bytes).unwrap();
        let id = harness_core::RunId::parse(a["run"].as_str().unwrap()).unwrap();
        let arm_state = dir
            .join(format!("arm-{}", m["label"].as_str().unwrap()))
            .join("state");
        let a = harness_run::audit(harness_run::Audit {
            state_root: &arm_state,
            run: &id,
            attempt: Some(a["attempt"].as_u64().unwrap() as u32),
            anchor: a["chain_head"]
                .as_str()
                .and_then(|h| h.parse::<Digest>().ok()),
            spec: &spec,
            registry: &registry,
            policy: &policy,
            profile: &profile,
            limits: &limits,
        })
        .unwrap_or_else(|e| panic!("audit refused for {}: {e}", a["run"]));
        assert!(a.divergence.is_none(), "{}", a.divergence.unwrap().why);
        assert!(a.stop_recomputed);
        assert!(a.anchored);
    }
}

/// One profile is not a comparison: a usage refusal, and nothing runs.
#[test]
fn compare_refuses_one_arm() {
    let fx = fixture(
        "one-arm",
        r#"{"task":"What does a.txt say?","grants":["harness.fs.read","harness.fs.list"]}"#,
    );
    let m = mock(vec![]);
    let ep = endpoint(&m);
    let args: Vec<String> = vec![
        "compare".into(),
        "--task".into(),
        fx.task.to_string_lossy().into_owned(),
        "--workspace".into(),
        fx.ws.to_string_lossy().into_owned(),
        "--state-root".into(),
        fx.state.to_string_lossy().into_owned(),
        "--profile".into(),
        fx.profile1.to_string_lossy().into_owned(),
        "--endpoint".into(),
        ep,
    ];
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let _g = ENV_LOCK.lock().unwrap();
    let o = cli(&fx, &refs);
    assert_eq!(o.code, 2, "{}", stderr(&o));
    assert!(stderr(&o).contains("2 to 4"), "{}", stderr(&o));
    assert!(!fx.state.join("compare").exists(), "nothing was written");
    assert!(!fx.state.join("runs").exists(), "no arm ran");
}
