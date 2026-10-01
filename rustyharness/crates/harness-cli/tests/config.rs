//! The P-07 defaults, end to end against a mock OpenAI-compatible server
//! on loopback: the user config file (`config_flags_override_file`,
//! `config_in_workspace_is_never_read`), the default `state_root`
//! (`default_state_root_created_0700`,
//! `default_state_root_refused_if_not_local`), the workspace default, and
//! `profile init` (`profile_init_writes_conservative_profile_for_listed_model`,
//! `profile_init_refuses_unlisted_model`, `profile_init_stamps_only_on_pass`).
//!
//! Every test here holds [`ENV_LOCK`]: the environment variables and the
//! current directory are process-global, and these tests call the CLI
//! library in process. No test depends on stdin being a terminal (the
//! non-tty `profile init` paths only), so the run is deterministic.

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

use harness_policy::locality::{FsQuery, LocalityProbe};

static ENV_LOCK: Mutex<()> = Mutex::new(());

const CFG_HOME: &str = "RUSTYHARNESS_CONFIG_HOME";
const STATE_HOME: &str = "RUSTYHARNESS_STATE_HOME";

// ---- a mock model server (as tests/cli.rs) ------------------------------------

struct Mock {
    port: u16,
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

/// Serves `GET /v1/models` with `models_body` and answers each chat
/// completion with the next scripted content.
fn mock(models_body: &str, replies: Vec<String>) -> Mock {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let queue = Arc::new(Mutex::new(VecDeque::from(replies)));
    let requests = Arc::new(Mutex::new(0usize));
    let p = requests.clone();
    let models = models_body.to_owned();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            let req = read_request(&mut s);
            *p.lock().unwrap() += 1;
            if req.starts_with("GET /v1/models ") {
                respond(&mut s, &models);
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
    Mock { port, requests }
}

fn hit(m: &Mock) -> usize {
    *m.requests.lock().unwrap()
}

/// The five replies a passing smoke eval needs, in `SMOKE_PATHS` order.
fn smoke_pass_replies() -> Vec<String> {
    [
        "README.md",
        "src/lib.rs",
        "docs/notes.txt",
        "Cargo.toml",
        "tests/basic.rs",
    ]
    .iter()
    .map(|path| {
        format!(
            "ok <action>{{\"tool\":\"harness.fs.read\",\"args\":{{\"path\":\"{path}\"}}}}</action>"
        )
    })
    .collect()
}

// ---- fixtures -----------------------------------------------------------------

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
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("cfg-{name}"));
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

struct Output {
    code: u8,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

struct Local;
impl LocalityProbe for Local {
    fn query(&self, _path: &str) -> FsQuery {
        FsQuery::MacOs {
            mnt_local: true,
            fs_type_name: "apfs".into(),
        }
    }
}

struct NotLocal;
impl LocalityProbe for NotLocal {
    fn query(&self, _path: &str) -> FsQuery {
        FsQuery::MacOs {
            mnt_local: false,
            fs_type_name: "apfs".into(),
        }
    }
}

/// The CLI library in process, with the given probe.
fn cli_with(probe: &dyn LocalityProbe, args: &[&str], marker: &Path) -> Output {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = {
        let cx = harness_cli::Cx {
            probe,
            gate_ok_file: Some(marker.to_path_buf()),
            out: RefCell::new(&mut out),
            err: RefCell::new(&mut err),
            approver: harness_cli::ApproverSource::None,
            confinement: &harness_sandbox::SystemConfinement,
        };
        harness_cli::main_with(&cx, args)
    };
    Output {
        code,
        stdout: out,
        stderr: err,
    }
}

fn endpoint(m: &Mock) -> String {
    format!("http://127.0.0.1:{}/v1", m.port)
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

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

// ---- env helpers ----------------------------------------------------------------

/// Set the two override variables to `cfg`/`state` (absolute dirs; either
/// may be absent on disk). Callers hold [`ENV_LOCK`].
fn set_homes(cfg: &Path, state: &Path) {
    std::env::set_var(CFG_HOME, cfg);
    std::env::set_var(STATE_HOME, state);
}

/// Remove the two override variables again.
fn clear_homes() {
    std::env::remove_var(CFG_HOME);
    std::env::remove_var(STATE_HOME);
}

// ---- the tests --------------------------------------------------------------------

/// A flag beats the config file for every key it covers (P-07): the config
/// points at a dead port and files that do not exist, and the run still
/// starts on the flagged ones.
#[test]
fn config_flags_override_file() {
    let _env = ENV_LOCK.lock().unwrap();
    let fx = fixture("flags-over-file");
    let cfghome = fx.base.join("cfghome");
    std::fs::create_dir_all(&cfghome).unwrap();
    std::fs::write(
        cfghome.join("config.json"),
        r#"{"endpoint":"http://127.0.0.1:1/v1","profile":"/nonexistent/p.json","policy":"/nonexistent/q.json","state_root":"/nonexistent/state"}"#,
    )
    .unwrap();
    set_homes(&cfghome, &fx.base.join("statehome"));
    let m = mock(r#"{"data":[{"id":"m"}]}"#, vec![act_submit()]);
    let o = cli_with(
        &Local,
        &[
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
            &endpoint(&m),
        ],
        &fx.marker,
    );
    clear_homes();
    assert_eq!(o.code, 5, "stderr: {}", stderr(&o));
    assert_eq!(
        report(&o)["outcome"]["Indeterminate"]["why"],
        "NothingChecked"
    );
    assert!(
        hit(&m) >= 2,
        "the flagged endpoint was used, not the config's"
    );
}

/// A `config.json` in the workspace is never read (P-07): the config comes
/// only from the user's config directory, here empty.
#[test]
fn config_in_workspace_is_never_read() {
    let _env = ENV_LOCK.lock().unwrap();
    let fx = fixture("ws-config-ignored");
    let cfghome = fx.base.join("cfghome");
    std::fs::create_dir_all(&cfghome).unwrap();
    std::fs::write(
        fx.ws.join("config.json"),
        r#"{"endpoint":"http://127.0.0.1:1/v1"}"#,
    )
    .unwrap();
    set_homes(&cfghome, &fx.base.join("statehome"));
    let m = mock(r#"{"data":[{"id":"m"}]}"#, vec![act_submit()]);
    let o = cli_with(
        &Local,
        &[
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
            &endpoint(&m),
        ],
        &fx.marker,
    );
    clear_homes();
    assert_eq!(o.code, 5, "stderr: {}", stderr(&o));
    assert_eq!(
        report(&o)["outcome"]["Indeterminate"]["why"],
        "NothingChecked"
    );
    assert!(hit(&m) >= 2, "the workspace config was not read");
}

fn act_submit() -> String {
    "ok <action>{\"tool\":\"harness.task.submit\",\"args\":{\"note\":\"done\"}}</action>".into()
}

/// Without any `--state-root` or config, the run uses the default state
/// root under the state home and creates it owner-only (P-07).
#[test]
fn default_state_root_created_0700() {
    let _env = ENV_LOCK.lock().unwrap();
    let fx = fixture("default-state-root");
    let cfghome = fx.base.join("cfghome");
    let statehome = fx.base.join("statehome");
    std::fs::create_dir_all(&cfghome).unwrap();
    set_homes(&cfghome, &statehome);
    let m = mock(r#"{"data":[{"id":"m"}]}"#, vec![act_submit()]);
    let o = cli_with(
        &Local,
        &[
            "run",
            "--task",
            fx.task.to_str().unwrap(),
            "--workspace",
            fx.ws.to_str().unwrap(),
            "--profile",
            fx.profile.to_str().unwrap(),
            "--endpoint",
            &endpoint(&m),
        ],
        &fx.marker,
    );
    clear_homes();
    assert_eq!(o.code, 5, "stderr: {}", stderr(&o));
    assert_eq!(
        report(&o)["outcome"]["Indeterminate"]["why"],
        "NothingChecked"
    );
    let root = statehome.join("rustyharness");
    assert!(root.is_dir(), "the default state root was created");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&root).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "owner-only permissions");
    }
    assert!(hit(&m) >= 2, "the run used the default state root");
}

/// The default state root is locality-checked like any other (P-07): a
/// refused one stops the run before anything is written under it.
#[test]
fn default_state_root_refused_if_not_local() {
    let _env = ENV_LOCK.lock().unwrap();
    let fx = fixture("default-state-root-not-local");
    let cfghome = fx.base.join("cfghome");
    let statehome = fx.base.join("statehome");
    std::fs::create_dir_all(&cfghome).unwrap();
    set_homes(&cfghome, &statehome);
    let m = mock(r#"{"data":[{"id":"m"}]}"#, vec![act_submit()]);
    let o = cli_with(
        &NotLocal,
        &[
            "run",
            "--task",
            fx.task.to_str().unwrap(),
            "--workspace",
            fx.ws.to_str().unwrap(),
            "--profile",
            fx.profile.to_str().unwrap(),
            "--endpoint",
            &endpoint(&m),
        ],
        &fx.marker,
    );
    clear_homes();
    assert_eq!(o.code, 5, "stderr: {}", stderr(&o));
    assert_eq!(report(&o)["outcome"]["Indeterminate"]["why"], "CouldNotRun");
    assert!(
        stderr(&o).contains("not on a filesystem identified as local"),
        "stderr: {}",
        stderr(&o)
    );
    assert!(
        !statehome.join("rustyharness").join("runs").exists(),
        "nothing was written under the refused state root"
    );
}

/// Without `--workspace`, the run works in the current directory (P-07).
#[test]
fn default_workspace_is_the_current_directory() {
    let _env = ENV_LOCK.lock().unwrap();
    let fx = fixture("default-workspace");
    let cfghome = fx.base.join("cfghome");
    std::fs::create_dir_all(&cfghome).unwrap();
    set_homes(&cfghome, &fx.base.join("statehome"));
    let m = mock(r#"{"data":[{"id":"m"}]}"#, vec![act_submit()]);
    let was = std::env::current_dir().unwrap();
    std::env::set_current_dir(&fx.ws).unwrap();
    let o = cli_with(
        &Local,
        &[
            "run",
            "--task",
            fx.task.to_str().unwrap(),
            "--state-root",
            fx.state.to_str().unwrap(),
            "--profile",
            fx.profile.to_str().unwrap(),
            "--endpoint",
            &endpoint(&m),
        ],
        &fx.marker,
    );
    std::env::set_current_dir(was).unwrap();
    clear_homes();
    assert_eq!(o.code, 5, "stderr: {}", stderr(&o));
    assert_eq!(
        report(&o)["outcome"]["Indeterminate"]["why"],
        "NothingChecked"
    );
    assert!(
        hit(&m) >= 2,
        "the run started in the current directory (the model server was asked)"
    );
}

/// `profile init` for a server that lists exactly one model, run without a
/// terminal: the conservative profile is written, unstamped unless the
/// smoke eval passes; here it passes, so the file is stamped (P-07).
#[test]
fn profile_init_writes_conservative_profile_for_listed_model() {
    let _env = ENV_LOCK.lock().unwrap();
    clear_homes();
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cfg-profile-init-pass");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let out = base.join("out.json");
    let m = mock(r#"{"data":[{"id":"m"}]}"#, smoke_pass_replies());
    let o = cli_with(
        &Local,
        &[
            "profile",
            "init",
            "--endpoint",
            &endpoint(&m),
            "--out",
            out.to_str().unwrap(),
        ],
        &base.join("gate-ok"),
    );
    assert_eq!(o.code, 0, "stderr: {}", stderr(&o));
    let bytes = std::fs::read(&out).unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(doc["id"], "default");
    assert_eq!(doc["model"], "m");
    assert_eq!(doc["profile_version"], 1);
    assert_eq!(doc["context_window"], 8192);
    assert_eq!(doc["protocol"], "text");
    assert_eq!(doc["grammar"], "none");
    assert_eq!(doc["max_active_tools"], 5);
    assert_eq!(doc["edit_format"], "replace");
    assert_eq!(doc["recent_turns"], 4);
    assert_eq!(doc["sampling"]["temperature"], 0.2);
    // The stamp from the passing smoke eval, valid for this content.
    assert!(doc["validated"]["stamp_sha256"].is_string());
    let p = harness_model::profile::Profile::parse(&bytes).unwrap();
    assert!(p.validated(), "the written stamp validates the profile");
    let say = last_line(&o);
    assert!(say.contains("stamp_sha256"), "last stdout line: {say}");
}

/// A choice that is not the server's single listed model is refused
/// without a terminal (P-07): nothing is written.
#[test]
fn profile_init_refuses_unlisted_model() {
    let _env = ENV_LOCK.lock().unwrap();
    clear_homes();
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cfg-profile-init-refuse");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let out = base.join("out.json");
    let m = mock(r#"{"data":[{"id":"m"},{"id":"n"}]}"#, vec![]);
    let o = cli_with(
        &Local,
        &[
            "profile",
            "init",
            "--endpoint",
            &endpoint(&m),
            "--out",
            out.to_str().unwrap(),
        ],
        &base.join("gate-ok"),
    );
    assert_eq!(o.code, 1, "stderr: {}", stderr(&o));
    assert!(
        stderr(&o).contains("terminal"),
        "the refusal says to run from a terminal: {}",
        stderr(&o)
    );
    assert!(!out.exists(), "nothing was written");
}

/// The smoke eval decides the stamp, nothing else (P-07): the same file
/// written by a failing smoke eval stays unstamped and the exit is 1.
#[test]
fn profile_init_stamps_only_on_pass() {
    let _env = ENV_LOCK.lock().unwrap();
    clear_homes();
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cfg-profile-init-nostamp");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let out = base.join("out.json");
    let m = mock(r#"{"data":[{"id":"m"}]}"#, vec!["I will not.".into(); 5]);
    let o = cli_with(
        &Local,
        &[
            "profile",
            "init",
            "--endpoint",
            &endpoint(&m),
            "--out",
            out.to_str().unwrap(),
        ],
        &base.join("gate-ok"),
    );
    assert_eq!(o.code, 1, "stderr: {}", stderr(&o));
    let bytes = std::fs::read(&out).unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(doc["model"], "m");
    assert!(
        doc.get("validated").is_none(),
        "the file stays unstamped: {doc}"
    );
    let p = harness_model::profile::Profile::parse(&bytes).unwrap();
    assert!(!p.validated());
}
