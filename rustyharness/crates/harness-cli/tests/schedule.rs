//! P-49: the `schedule` verb — add (with its confirmation), list, remove
//! and run-now — end to end against a mock OpenAI-compatible server. Every
//! invocation calls the CLI library in process with the permissive probe,
//! so the tests run on every OS the launchers render for.
//!
//! Every test holds [`ENV_LOCK`]: the environment variables are
//! process-global, and the tests point `RUSTYHARNESS_CONFIG_HOME` at an
//! empty directory (no user config may leak in) and
//! `RUSTYHARNESS_SCHEDULE_HOME` at the fixture's launcher directory.

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

static ENV_LOCK: Mutex<()> = Mutex::new(());

const CFG_HOME: &str = "RUSTYHARNESS_CONFIG_HOME";
const SCHED_HOME: &str = "RUSTYHARNESS_SCHEDULE_HOME";

// ---- a mock model server (as tests/sessions.rs) ------------------------------------

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

// ---- fixtures ----------------------------------------------------------------------

/// A profile with a canary id, so a secret-hunting test can prove the
/// launcher never carries profile content.
const PROFILE: &str = r#"{"profile_version":1,"id":"sched-canary-profile","model":"m",
  "context_window":32768,"fill_ratio":0.6,"protocol":"text","tool_choice_required_ok":false,
  "grammar":"none","max_active_tools":6,"edit_format":"replace","recent_turns":5,
  "sampling":{"temperature":0.2,"top_p":0.95,"seed":7,"max_tokens":2048}}"#;

/// The task text's canary, for the same hunt.
const TASK_CANARY: &str = "canary-task-text-9f2c";

struct Fx {
    state: PathBuf,
    ws: PathBuf,
    cfg: PathBuf,
    home: PathBuf,
    task: PathBuf,
    profile: PathBuf,
}

fn fixture(name: &str) -> Fx {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("sched-{name}"));
    let _ = std::fs::remove_dir_all(&base);
    let (state, ws, cfg, home) = (
        base.join("state"),
        base.join("ws"),
        base.join("cfg"),
        base.join("home"),
    );
    for d in [&state, &ws, &cfg, &home] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(ws.join("a.txt"), "hello\n").unwrap();
    let task = base.join("task.json");
    std::fs::write(
        &task,
        serde_json::json!({
            "task": format!("{TASK_CANARY}: replace the greeting in a.txt"),
            "grants": ["harness.fs.read", "harness.fs.list", "harness.edit.replace"],
            "budget": {"steps": 10, "wall_secs": 600}
        })
        .to_string(),
    )
    .unwrap();
    let profile = base.join("profile.json");
    std::fs::write(&profile, PROFILE).unwrap();
    Fx {
        state,
        ws,
        cfg,
        home,
        task,
        profile,
    }
}

impl Fx {
    /// Where the launcher files for this fixture land.
    fn launch_dir(&self) -> PathBuf {
        if cfg!(target_os = "macos") {
            self.home.join("LaunchAgents")
        } else {
            self.home.join("systemd/user")
        }
    }

    /// The launcher file paths one installed schedule has, in the same
    /// order `schedule add` writes them.
    fn launchers(&self, name: &str) -> Vec<PathBuf> {
        if cfg!(target_os = "macos") {
            vec![self
                .launch_dir()
                .join(format!("com.rustyharness.schedule.{name}.plist"))]
        } else {
            vec![
                self.launch_dir()
                    .join(format!("rustyharness-{name}.service")),
                self.launch_dir().join(format!("rustyharness-{name}.timer")),
            ]
        }
    }

    fn bundle(&self, name: &str) -> PathBuf {
        self.state.join("schedules").join(name)
    }

    fn endpoint(&self) -> String {
        "http://127.0.0.1:9/v1".to_owned()
    }
}

/// What a CLI invocation produced.
struct Output {
    code: u8,
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

/// The CLI library in process, with the permissive probe and `lines` as
/// the confirmation feed.
fn cli(args: &[&str], lines: &[String]) -> Output {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = {
        let cx = harness_cli::Cx {
            probe: &Local,
            gate_ok_file: None,
            out: RefCell::new(&mut out),
            err: RefCell::new(&mut err),
            approver: harness_cli::ApproverSource::None,
            input: harness_cli::InputSource::Given(lines),
            backend: harness_cli::BackendSource::BuiltIn,
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

fn str_lines(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

fn add_args<'a>(fx: &'a Fx, name: &'a str, ep: &'a str, cadence: &'a [&'a str]) -> Vec<&'a str> {
    let mut a = vec![
        "schedule",
        "add",
        "--name",
        name,
        "--task",
        fx.task.to_str().unwrap(),
        "--profile",
        fx.profile.to_str().unwrap(),
        "--endpoint",
        ep,
        "--workspace",
        fx.ws.to_str().unwrap(),
        "--state-root",
        fx.state.to_str().unwrap(),
    ];
    a.extend_from_slice(cadence);
    a
}

/// Install `name` with a confirming `y`, asserting the install succeeded.
fn install(fx: &Fx, name: &str, cadence: &[&str]) -> Output {
    let ep = fx.endpoint();
    let o = cli(&add_args(fx, name, &ep, cadence), &str_lines(&["y"]));
    assert_eq!(o.code, 0, "install {name}: {}", o.err());
    o
}

fn report(o: &Output) -> serde_json::Value {
    serde_json::from_str(o.out().lines().last().unwrap_or("")).unwrap()
}

/// The run id a run-now printed on stderr ("run <32 hex> attempt 1: ...").
fn run_id(o: &Output) -> String {
    let err = o.err();
    let at = err.find("run ").unwrap() + 4;
    err[at..at + 32].to_owned()
}

fn attempt_journal(fx: &Fx, id: &str) -> PathBuf {
    fx.state
        .join("runs")
        .join(id)
        .join("attempt-1/journal.jsonl")
}

#[cfg(unix)]
fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

// ---- the tests ---------------------------------------------------------------------

/// `add` prints the exact launcher file (and the manifest it would store)
/// before anything is written, installs only on `y`, and on `y` the files
/// on disk are private and exactly what was printed.
#[test]
fn schedule_add_prints_plist_and_requires_confirmation() {
    let _env = ENV_LOCK.lock().unwrap();
    let fx = fixture("add");
    std::env::set_var(CFG_HOME, &fx.cfg);
    std::env::set_var(SCHED_HOME, &fx.home);
    let marker = if cfg!(target_os = "macos") {
        "StartCalendarInterval"
    } else {
        "OnCalendar"
    };
    // No answer at all (end of input): printed, refused to install, exit 0.
    let ep = fx.endpoint();
    let o = cli(&add_args(&fx, "nightly", &ep, &["--daily", "23:45"]), &[]);
    std::env::remove_var(CFG_HOME);
    std::env::remove_var(SCHED_HOME);
    assert_eq!(o.code, 0, "{}", o.err());
    let out = o.out();
    assert!(out.contains("would install"), "{out}");
    assert!(out.contains(marker), "{out}");
    assert!(o.err().contains("install this schedule?"), "{}", o.err());
    assert!(!fx.bundle("nightly").exists(), "nothing stored");
    for p in fx.launchers("nightly") {
        assert!(!p.exists(), "{} not written before the answer", p.display());
    }
    // An explicit `n`: the same, never installed.
    std::env::set_var(CFG_HOME, &fx.cfg);
    std::env::set_var(SCHED_HOME, &fx.home);
    let o = cli(
        &add_args(&fx, "nightly", &ep, &["--daily", "23:45"]),
        &str_lines(&["n"]),
    );
    std::env::remove_var(CFG_HOME);
    std::env::remove_var(SCHED_HOME);
    assert_eq!(o.code, 0, "{}", o.err());
    assert!(!fx.bundle("nightly").exists(), "a no installs nothing");
    // `y`: the launcher exists, private, and the printed content is what
    // landed on disk.
    std::env::set_var(CFG_HOME, &fx.cfg);
    std::env::set_var(SCHED_HOME, &fx.home);
    let o = install(&fx, "nightly", &["--daily", "23:45"]);
    std::env::remove_var(CFG_HOME);
    std::env::remove_var(SCHED_HOME);
    let out = o.out();
    for p in fx.launchers("nightly") {
        assert!(p.exists(), "{} installed", p.display());
        #[cfg(unix)]
        assert_eq!(mode(&p), 0o600, "{}", p.display());
        let content = std::fs::read_to_string(&p).unwrap();
        assert!(out.contains(&content), "stdout carried the exact file");
        assert!(content.contains("run-now"), "{content}");
    }
    let bundle = fx.bundle("nightly");
    for f in ["task.json", "profile.json", "schedule.json"] {
        #[cfg(unix)]
        assert_eq!(mode(&bundle.join(f)), 0o600, "{f}");
    }
    assert!(
        !bundle.join("policy.json").exists(),
        "no policy file was given"
    );
}

/// A task with no explicit budget is refused before anything is offered
/// or written: a timed run has nobody watching.
#[test]
fn schedule_refuses_task_without_budgets() {
    let _env = ENV_LOCK.lock().unwrap();
    let fx = fixture("no-budget");
    std::fs::write(
        &fx.task,
        serde_json::json!({
            "task": "no budgets here",
            "grants": ["harness.fs.read"]
        })
        .to_string(),
    )
    .unwrap();
    std::env::set_var(CFG_HOME, &fx.cfg);
    std::env::set_var(SCHED_HOME, &fx.home);
    let ep = fx.endpoint();
    let o = cli(
        &add_args(&fx, "nightly", &ep, &["--every", "6h"]),
        &str_lines(&["y"]),
    );
    std::env::remove_var(CFG_HOME);
    std::env::remove_var(SCHED_HOME);
    assert_eq!(o.code, 4, "{}", o.err());
    assert!(o.err().contains("budget"), "{}", o.err());
    assert!(!fx.state.join("schedules").exists(), "nothing stored");
    for p in fx.launchers("nightly") {
        assert!(!p.exists(), "{} not written", p.display());
    }
}

/// `run-now` is the timer's run: unattended even at a terminal, so an
/// edit the default policy only asks about is denied (`no_approver`), the
/// workspace is untouched, and the run still ends NothingChecked (5).
#[test]
fn schedule_run_denies_every_ask() {
    let _env = ENV_LOCK.lock().unwrap();
    let fx = fixture("run-denies");
    let m = mock(vec![
        act(
            "harness.edit.replace",
            r#"{"path":"a.txt","old":"hello","new":"bye"}"#,
        ),
        act("harness.task.submit", r#"{"note":"done"}"#),
    ]);
    let ep = format!("http://127.0.0.1:{}/v1", m.port);
    std::env::set_var(CFG_HOME, &fx.cfg);
    std::env::set_var(SCHED_HOME, &fx.home);
    let o = cli(
        &add_args(&fx, "nightly", &ep, &["--daily", "23:45"]),
        &str_lines(&["y"]),
    );
    assert_eq!(o.code, 0, "{}", o.err());
    let o = cli(
        &[
            "schedule",
            "run-now",
            "--name",
            "nightly",
            "--state-root",
            fx.state.to_str().unwrap(),
        ],
        &[],
    );
    std::env::remove_var(CFG_HOME);
    std::env::remove_var(SCHED_HOME);
    assert_eq!(o.code, 5, "{}", o.err());
    assert_eq!(
        report(&o)["outcome"]["Indeterminate"]["why"],
        "NothingChecked",
        "{}",
        o.out()
    );
    // The edit was denied, so the file is untouched.
    assert_eq!(
        std::fs::read_to_string(fx.ws.join("a.txt")).unwrap(),
        "hello\n"
    );
    // The journal says why: the ask had nobody to answer it.
    let id = run_id(&o);
    let journal = std::fs::read_to_string(attempt_journal(&fx, &id)).unwrap();
    let decided: Vec<serde_json::Value> = journal
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|v| v["kind"] == "PolicyDecided" && v["body"]["decision"] == "deny")
        .collect();
    assert!(
        decided.iter().any(|v| v["body"]["reason"] == "no_approver"),
        "{decided:?}"
    );
}

/// `remove` deletes one schedule's bundle and its own launcher files, and
/// nothing else — other schedules, and any unrelated file in the launcher
/// directory, all stay.
#[test]
fn schedule_remove_deletes_only_its_own_file() {
    let _env = ENV_LOCK.lock().unwrap();
    let fx = fixture("remove");
    std::env::set_var(CFG_HOME, &fx.cfg);
    std::env::set_var(SCHED_HOME, &fx.home);
    install(&fx, "alpha", &["--daily", "07:15"]);
    install(&fx, "beta", &["--every", "6h"]);
    // Decoys: an unrelated file beside the launchers, an unrelated entry
    // in schedules/.
    let decoy = fx.launch_dir().join("unrelated.plist");
    std::fs::create_dir_all(fx.launch_dir()).unwrap();
    std::fs::write(&decoy, "keep me").unwrap();
    let other = fx.state.join("schedules").join("otherdir");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join("junk"), "keep me too").unwrap();
    let o = cli(
        &[
            "schedule",
            "remove",
            "--name",
            "alpha",
            "--state-root",
            fx.state.to_str().unwrap(),
        ],
        &str_lines(&["y"]),
    );
    std::env::remove_var(CFG_HOME);
    std::env::remove_var(SCHED_HOME);
    assert_eq!(o.code, 0, "{}", o.err());
    assert!(!fx.bundle("alpha").exists(), "alpha's bundle gone");
    for p in fx.launchers("alpha") {
        assert!(!p.exists(), "{} gone", p.display());
    }
    assert!(fx.bundle("beta").exists(), "beta kept");
    for p in fx.launchers("beta") {
        assert!(p.exists(), "{} kept", p.display());
    }
    assert!(decoy.exists(), "the decoy is not ours to remove");
    assert!(other.exists(), "the other directory is not ours to remove");
    // Removing it again: there is no schedule named alpha any more.
    std::env::set_var(CFG_HOME, &fx.cfg);
    std::env::set_var(SCHED_HOME, &fx.home);
    let o = cli(
        &[
            "schedule",
            "remove",
            "--name",
            "alpha",
            "--state-root",
            fx.state.to_str().unwrap(),
        ],
        &str_lines(&["y"]),
    );
    std::env::remove_var(CFG_HOME);
    std::env::remove_var(SCHED_HOME);
    assert_eq!(o.code, 4, "{}", o.err());
    assert!(o.err().contains("no schedule named"), "{}", o.err());
}

/// `list` shows every schedule, sorted, with the next daily run as the
/// UTC estimate and `next=-` for a steady interval.
#[test]
fn schedule_list_shows_next_run() {
    let _env = ENV_LOCK.lock().unwrap();
    let fx = fixture("list");
    std::env::set_var(CFG_HOME, &fx.cfg);
    std::env::set_var(SCHED_HOME, &fx.home);
    install(&fx, "nightly", &["--daily", "23:45"]);
    install(&fx, "periodic", &["--every", "6h"]);
    // The expected next slot, the same UTC arithmetic the verb does.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let day = now_ms - (now_ms % 86_400_000);
    let at = day + 23 * 3_600_000 + 45 * 60_000;
    let expected = if at > now_ms { at } else { at + 86_400_000 };
    let expected = harness_journal::rfc3339_utc(expected);
    let o = cli(
        &[
            "schedule",
            "list",
            "--state-root",
            fx.state.to_str().unwrap(),
        ],
        &[],
    );
    std::env::remove_var(CFG_HOME);
    std::env::remove_var(SCHED_HOME);
    assert_eq!(o.code, 0, "{}", o.err());
    let rows: Vec<String> = o.out().lines().map(|l| l.to_owned()).collect();
    assert_eq!(rows.len(), 2, "{}", o.out());
    assert!(rows[0].starts_with("name=nightly "), "{}", rows[0]);
    assert!(rows[0].contains("cadence=daily@23:45"), "{}", rows[0]);
    assert!(rows[0].contains("installed=yes"), "{}", rows[0]);
    assert!(rows[0].contains(&format!("next={expected}")), "{}", rows[0]);
    assert!(
        rows[0].contains(&format!("workspace={}", fx.ws.display())),
        "{}",
        rows[0]
    );
    assert!(rows[1].starts_with("name=periodic "), "{}", rows[1]);
    assert!(rows[1].contains("cadence=every6h"), "{}", rows[1]);
    assert!(rows[1].contains("installed=yes"), "{}", rows[1]);
    assert!(rows[1].contains("next=-"), "{}", rows[1]);
}

/// The installed launcher carries no task text, no profile content and no
/// endpoint: only the command to run and the schedule's name. The inputs
/// live in the 0600 bundle, and `run-now` re-checks their digests.
#[test]
fn plist_has_no_secrets() {
    let _env = ENV_LOCK.lock().unwrap();
    let fx = fixture("secrets");
    std::env::set_var(CFG_HOME, &fx.cfg);
    std::env::set_var(SCHED_HOME, &fx.home);
    install(&fx, "nightly", &["--daily", "23:45"]);
    std::env::remove_var(CFG_HOME);
    std::env::remove_var(SCHED_HOME);
    for p in fx.launchers("nightly") {
        let content = std::fs::read_to_string(&p).unwrap();
        assert!(!content.contains(TASK_CANARY), "{}", content);
        assert!(!content.contains("sched-canary-profile"), "{}", content);
        assert!(!content.contains(&fx.endpoint()), "{}", content);
        // What it does carry: the run-now command for this schedule.
        assert!(content.contains("run-now"), "{content}");
        assert!(content.contains("nightly"), "{content}");
    }
}
