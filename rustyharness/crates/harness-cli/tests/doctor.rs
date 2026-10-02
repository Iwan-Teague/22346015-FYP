//! The `doctor` verb (P-43), end to end against a mock OpenAI-compatible
//! server on loopback, in process with the CLI library.
//!
//! Every test holds [`ENV_LOCK`]: the environment variables and the
//! current directory are process-global, and the tests set the config and
//! state homes (P-07). No test depends on stdin being a terminal: cargo
//! test never runs one on a terminal, so the non-tty WARN is the
//! deterministic case (`doctor_warns_on_non_tty`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::RefCell;
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

// ---- a mock model server (as tests/config.rs) ---------------------------------

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

/// Serves `GET /v1/models` with `models_body`. `doctor` asks for nothing
/// else: no chat completion is scripted.
fn mock(models_body: &str) -> Mock {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let requests = Arc::new(Mutex::new(0usize));
    let p = requests.clone();
    let models = models_body.to_owned();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            let _req = read_request(&mut s);
            *p.lock().unwrap() += 1;
            respond(&mut s, &models);
        }
    });
    Mock { port, requests }
}

fn hit(m: &Mock) -> usize {
    *m.requests.lock().unwrap()
}

// ---- fixtures -----------------------------------------------------------------

/// A profile as the smoke-eval tests write them; the stamp is added by
/// [`stamped_profile_bytes`].
const PROFILE: &str = r#"{"profile_version":1,"id":"mock-m","model":"m",
  "context_window":32768,"fill_ratio":0.6,"protocol":"text","tool_choice_required_ok":false,
  "grammar":"none","max_active_tools":6,"edit_format":"replace","recent_turns":5,
  "sampling":{"temperature":0.2,"top_p":0.95,"seed":7,"max_tokens":2048}}"#;

struct Fx {
    base: PathBuf,
    cfghome: PathBuf,
    statehome: PathBuf,
}

fn fixture(name: &str) -> Fx {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("doctor-{name}"));
    let _ = std::fs::remove_dir_all(&base);
    let (cfghome, statehome) = (base.join("cfghome"), base.join("statehome"));
    std::fs::create_dir_all(&cfghome).unwrap();
    std::fs::create_dir_all(&statehome).unwrap();
    Fx {
        base,
        cfghome,
        statehome,
    }
}

impl Fx {
    /// The stamped default profile in `profile init`'s default location,
    /// which is where `doctor` looks when the config names none.
    fn install_stamped_profile(&self) -> PathBuf {
        let dir = self.cfghome.join("rustyharness").join("profiles");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("default.json");
        std::fs::write(&path, stamped_profile_bytes()).unwrap();
        path
    }

    /// An existing, local state root to pass with `--state-root`.
    fn state(&self) -> PathBuf {
        let s = self.base.join("state");
        std::fs::create_dir_all(&s).unwrap();
        s
    }
}

/// A profile whose stamp is valid for its content — the stamp `profile
/// check` writes: `stamp_sha256 = sha256(content_sha256 ":" report_sha256)`
/// (unkeyed by design; `Profile::validated` recomputes it), over a report
/// digest standing in for a passing smoke eval.
fn stamped_profile_bytes() -> Vec<u8> {
    let p = harness_model::profile::Profile::parse(PROFILE.as_bytes()).unwrap();
    let report = harness_core::sha256(b"doctor: a passing smoke report");
    let stamp = harness_core::sha256(format!("{}:{}", p.content_sha256(), report).as_bytes());
    let mut doc: serde_json::Value = serde_json::from_str(PROFILE).unwrap();
    doc.as_object_mut().unwrap().insert(
        "validated".into(),
        serde_json::json!({
            "report_sha256": report.to_string(),
            "stamp_sha256": stamp.to_string(),
        }),
    );
    serde_json::to_vec(&doc).unwrap()
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

struct Output {
    code: u8,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// The CLI library in process, with the permissive locality probe.
fn cli(args: &[&str]) -> Output {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = {
        let cx = harness_cli::Cx {
            probe: &Local,
            gate_ok_file: None,
            out: RefCell::new(&mut out),
            err: RefCell::new(&mut err),
            approver: harness_cli::ApproverSource::None,
            confinement: &harness_sandbox::SystemConfinement,
            input: harness_cli::InputSource::Stdin,
            backend: harness_cli::BackendSource::BuiltIn,
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

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Set the two override variables to `fx`'s homes. Callers hold
/// [`ENV_LOCK`].
fn set_homes(fx: &Fx) {
    std::env::set_var(CFG_HOME, &fx.cfghome);
    std::env::set_var(STATE_HOME, &fx.statehome);
}

/// Remove the two override variables again.
fn clear_homes() {
    std::env::remove_var(CFG_HOME);
    std::env::remove_var(STATE_HOME);
}

// ---- the tests --------------------------------------------------------------------

/// Everything the mock server can prove passes: the endpoint answers
/// `/v1/models`, the default state root is created owner-only, the config
/// dir is read, the stamped profile validates. The sandbox line PASSes on
/// a conformed host and WARNs where no backend exists (Linux); a FAIL
/// anywhere fails the test, as does the exit code.
#[test]
fn doctor_all_pass_with_mock_server() {
    let _env = ENV_LOCK.lock().unwrap();
    let fx = fixture("all-pass");
    let profile = fx.install_stamped_profile();
    set_homes(&fx);
    let m = mock(r#"{"data":[{"id":"m"},{"id":"n"}]}"#);
    let o = cli(&["doctor", "--endpoint", &endpoint(&m)]);
    clear_homes();
    assert_eq!(o.code, 0, "stderr: {}; stdout: {}", stderr(&o), stdout(&o));
    let out = stdout(&o);
    assert!(!out.contains("FAIL"), "stdout: {out}");
    for line in [
        "PASS config",
        "PASS endpoint",
        "PASS profile",
        "PASS state-root",
    ] {
        assert!(out.contains(line), "expected `{line}` in:\n{out}");
    }
    assert!(
        out.contains("stamp valid") && out.contains("(model m)"),
        "the profile line names the model: {out}"
    );
    // The default state root now exists (created owner-only, P-07).
    assert!(fx.statehome.join("rustyharness").is_dir());
    // The endpoint check really asked the server.
    assert_eq!(hit(&m), 1, "one /v1/models request");
    let _ = profile;
}

/// A state root that is not there is the FAIL case, and the line says how
/// to fix it: the `mkdir -p` (the run verbs never create an explicit
/// state root, so doctor must not pretend it is fine).
#[test]
fn doctor_fails_without_state_root_and_says_how() {
    let _env = ENV_LOCK.lock().unwrap();
    let fx = fixture("no-state-root");
    fx.install_stamped_profile();
    set_homes(&fx);
    let m = mock(r#"{"data":[{"id":"m"}]}"#);
    let missing = fx.base.join("missing-state");
    let o = cli(&[
        "doctor",
        "--endpoint",
        &endpoint(&m),
        "--state-root",
        missing.to_str().unwrap(),
    ]);
    clear_homes();
    assert_eq!(o.code, 1, "stderr: {}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("FAIL state-root"), "stdout: {out}");
    assert!(out.contains("mkdir -p"), "the fix names the command: {out}");
    assert!(!missing.exists(), "doctor did not create it");
}

/// Under cargo test stdin is never a terminal, so the ask-answer check is
/// the deterministic WARN: every ask would be a deny without a policy.
#[test]
fn doctor_warns_on_non_tty() {
    let _env = ENV_LOCK.lock().unwrap();
    let fx = fixture("non-tty");
    fx.install_stamped_profile();
    set_homes(&fx);
    let m = mock(r#"{"data":[{"id":"m"}]}"#);
    let state = fx.state();
    let o = cli(&[
        "doctor",
        "--endpoint",
        &endpoint(&m),
        "--state-root",
        state.to_str().unwrap(),
    ]);
    clear_homes();
    let out = stdout(&o);
    assert!(out.contains("WARN terminal"), "stdout: {out}");
    assert!(!out.contains("PASS terminal"), "stdout: {out}");
}

/// A closed port is a WARN, not a FAIL: the server is simply not up yet,
/// and doctor still exits 0 (unlike the missing state root, which FAILs).
#[test]
fn doctor_reports_unreachable_endpoint() {
    let _env = ENV_LOCK.lock().unwrap();
    let fx = fixture("unreachable");
    fx.install_stamped_profile();
    set_homes(&fx);
    // A loopback port that is bound, then released: connections are
    // refused at once.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let state = fx.state();
    let o = cli(&[
        "doctor",
        "--endpoint",
        &format!("http://127.0.0.1:{port}/v1"),
        "--state-root",
        state.to_str().unwrap(),
    ]);
    clear_homes();
    let out = stdout(&o);
    assert!(out.contains("WARN endpoint"), "stdout: {out}");
    assert!(!out.contains("FAIL endpoint"), "stdout: {out}");
    assert_eq!(o.code, 0, "a WARN is not a FAIL; stderr: {}", stderr(&o));
}

/// Nothing doctor prints carries a raw control byte: the state root named
/// on the command line holds an escape sequence, and the FAIL line that
/// echoes it must come out sanitised (P-04).
#[test]
fn doctor_output_has_no_raw_escapes() {
    let _env = ENV_LOCK.lock().unwrap();
    let fx = fixture("raw-escapes");
    fx.install_stamped_profile();
    set_homes(&fx);
    let m = mock(r#"{"data":[{"id":"m"}]}"#);
    let hostile = format!("{}\u{1b}[31m-not-a-dir", fx.base.join("esc").display());
    let o = cli(&[
        "doctor",
        "--endpoint",
        &endpoint(&m),
        "--state-root",
        &hostile,
    ]);
    clear_homes();
    assert_eq!(o.code, 1);
    let out = stdout(&o);
    let err = stderr(&o);
    assert!(
        !out.bytes().any(|b| b == 0x1b),
        "raw escape in stdout: {out:?}"
    );
    assert!(
        !err.bytes().any(|b| b == 0x1b),
        "raw escape in stderr: {err:?}"
    );
    assert!(
        out.contains("FAIL state-root"),
        "the check still reported: {out}"
    );
}

/// The exit code is 0 exactly when no check FAILed: the same all-pass
/// invocation, then one with the state root missing, flips it to 1.
#[test]
fn doctor_exit_code_follows_fail() {
    let _env = ENV_LOCK.lock().unwrap();
    let fx = fixture("exit-codes");
    fx.install_stamped_profile();
    let m = mock(r#"{"data":[{"id":"m"}]}"#);
    set_homes(&fx);
    let state = fx.state();
    let good = cli(&[
        "doctor",
        "--endpoint",
        &endpoint(&m),
        "--state-root",
        state.to_str().unwrap(),
    ]);
    clear_homes();
    assert_eq!(good.code, 0, "stderr: {}", stderr(&good));
    set_homes(&fx);
    let gone = fx.base.join("gone");
    let bad = cli(&[
        "doctor",
        "--endpoint",
        &endpoint(&m),
        "--state-root",
        gone.to_str().unwrap(),
    ]);
    clear_homes();
    assert_eq!(bad.code, 1);
    assert!(stdout(&bad).contains("FAIL state-root"));
}

/// Windows (S-W1): with no state root given, doctor says plainly that
/// Windows has no default and no volume query yet — a WARN (the known
/// shape of this host), never a FAIL, and never a created directory. The
/// profile check still FAILs on Windows (no config dir until its spike),
/// so only the state-root line is asserted here.
#[cfg(target_os = "windows")]
#[test]
fn doctor_warns_that_windows_has_no_state_root_yet() {
    let _env = ENV_LOCK.lock().unwrap();
    clear_homes();
    let o = cli(&["doctor"]);
    let out = stdout(&o);
    assert!(out.contains("WARN state-root"), "stdout: {out}");
    assert!(out.contains("sessions stay off"), "stdout: {out}");
    assert!(!out.contains("FAIL state-root"), "stdout: {out}");
}
