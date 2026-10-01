//! INV-14, the model half, end to end (H1 phase-exit review, named item 1,
//! condition 3): a loopback model server that takes the chat request and
//! never answers must end the run through the real client
//! (`OpenAiCompatible`) and the real loop, on the real clock (no manual
//! clock), within the budget plus a grace: `Budget(Wall)` when the wall
//! budget is the shorter bound, `ModelUnavailable` when the per-call
//! timeout is. Every request keeps its reply record and the stop is
//! durable.
//!
//! The hanging-TOOL half ("hanging tool → `Budget(Wall)` within budget +
//! kill grace") needs H2's killable file-op helper: an in-process read
//! blocked in the kernel cannot be interrupted (design §11, §9 H2 key
//! tests).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use gate_outcome::{GateOutcome, IndeterminateKind};
use harness_core::environment::{EnvSample, Unmeasured};
use harness_core::{BudgetDim, StopCause};
use harness_journal::{EventKind, JournalReader};
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, SemVer, ValidationContext};
use harness_model::client::{ClientConfig, OpenAiCompatible};
use harness_model::profile::Profile;
use harness_model::TaskText;
use harness_policy::locality::{FsQuery, LocalityProbe};
use harness_policy::UserPolicy;
use harness_run::{run, Run, RunConfig, RunReport, TaskSpec};

const FIXED_ENV: EnvSample = EnvSample::unmeasured(Unmeasured::NoSafeApi);

/// How long past its budget a run may take to journal the failed call and
/// commit its stop: generous, so a loaded CI host does not flake, and far
/// below how long the server would hold (a minute) or the default per-call
/// timeout (300 s).
const GRACE: Duration = Duration::from_secs(5);

/// How long the server holds a connection it never answers.
const HOLD_FOR: Duration = Duration::from_secs(60);

struct Local;
impl LocalityProbe for Local {
    fn query(&self, _path: &str) -> FsQuery {
        FsQuery::MacOs {
            mnt_local: true,
            fs_type_name: "apfs".into(),
        }
    }
}

fn scratch(name: &str) -> (PathBuf, PathBuf) {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("inv14-{name}"));
    let _ = fs::remove_dir_all(&base);
    let (state, ws) = (base.join("state"), base.join("ws"));
    fs::create_dir_all(&state).unwrap();
    fs::create_dir_all(&ws).unwrap();
    fs::write(ws.join("a.txt"), "alpha\n").unwrap();
    (state, ws)
}

fn registry() -> Registry {
    let ctx = ValidationContext::new(
        SemVer {
            major: 0,
            minor: 0,
            patch: 1,
        },
        &[],
    )
    .unwrap();
    Registry::admit(vec![(builtin::manifest(&ctx).unwrap(), Tier::Builtin)]).unwrap()
}

/// A model server that reads each request and then holds the connection,
/// never answering, until the client closes it (or [`HOLD_FOR`] passes).
struct Hold {
    port: u16,
    /// Connections that sent a request.
    requests: Arc<Mutex<usize>>,
}

fn hold() -> Hold {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let requests = Arc::new(Mutex::new(0usize));
    let seen = requests.clone();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            let seen = seen.clone();
            thread::spawn(move || {
                s.set_read_timeout(Some(HOLD_FOR)).unwrap();
                let mut buf = [0u8; 8192];
                let mut counted = false;
                // Read and discard until the client gives up and closes.
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        return;
                    }
                    if !counted {
                        *seen.lock().unwrap() += 1;
                        counted = true;
                    }
                }
            });
        }
    });
    Hold { port, requests }
}

/// A run against the holding server through the real loopback client.
fn go(state: &Path, ws: &Path, server: &Hold, config: &RunConfig) -> (RunReport, Duration) {
    let profile = Profile::conservative_default("m");
    let client = OpenAiCompatible::new(
        &format!("http://127.0.0.1:{}/v1", server.port),
        profile.clone(),
        None,
        ClientConfig::default(),
    )
    .unwrap();
    let t = Instant::now();
    let r = run(Run {
        state_root: state,
        workspace: ws,
        spec: &TaskSpec {
            task: TaskText::new("What does a.txt say?".into()),
            grants: vec!["harness.fs.read".into()],
            workspace_public: false,
            exec: None,
        },
        registry: &registry(),
        policy: &UserPolicy::default(),
        profile: &profile,
        backend: &client,
        probe: &Local,
        env: &FIXED_ENV,
        config,
        approver: None,
        confinement: None,
    })
    .unwrap();
    (r, t.elapsed())
}

/// One request, not retried (a timeout never is, §3.2), journaled with its
/// reply record (the typed timeout), and the stop durable.
fn assert_one_call_paired_and_committed(r: &RunReport, server: &Hold) {
    assert_eq!(
        *server.requests.lock().unwrap(),
        1,
        "one call, never retried"
    );
    assert!(r.chain_head.is_some(), "RunStopped is durable");
    assert!(r.journal_error.is_none());
    assert_eq!(
        r.outcome,
        GateOutcome::Indeterminate {
            why: IndeterminateKind::NothingChecked
        }
    );
    let v = JournalReader::open(&r.run_dir.join("attempt-1")).unwrap();
    assert!(v.is_complete());
    let n = |k: EventKind| v.records.iter().filter(|x| x.kind == k).count();
    assert_eq!(n(EventKind::ModelRequested), 1);
    assert_eq!(n(EventKind::ModelReplied), 1, "the request has its reply");
    assert_eq!(n(EventKind::ToolStarted), 0, "nothing ran");
    let reply = v
        .records
        .iter()
        .find(|x| x.kind == EventKind::ModelReplied)
        .unwrap();
    assert_eq!(reply.body["error"], "unavailable");
    // The client's own read deadline ends the call: at the deadline, or on
    // the per-read timeout it set from the time left, whichever the socket
    // reports first.
    assert!(
        matches!(
            reply.body["kind"].as_str(),
            Some("deadline" | "read_timeout")
        ),
        "{:?}",
        reply.body
    );
}

#[test]
fn inv_14_a_model_server_that_never_answers_ends_the_run_on_its_wall_budget() {
    let (state, ws) = scratch("wall");
    let server = hold();
    let mut config = RunConfig::defaults(1_000_000);
    config.limits.wall = Duration::from_millis(1500);
    // The per-call timeout (300 s by default) is the longer bound, so the
    // call's deadline is the remaining wall budget (§2.2 step 3).
    assert!(config.model_call_timeout > config.limits.wall + GRACE);
    let (r, took) = go(&state, &ws, &server, &config);
    assert_eq!(
        r.cause,
        StopCause::Budget(BudgetDim::Wall),
        "after {took:?}"
    );
    assert!(
        took < config.limits.wall + GRACE,
        "the run outlived its wall budget: {took:?}"
    );
    assert_one_call_paired_and_committed(&r, &server);
}

#[test]
fn inv_14_a_model_server_that_never_answers_past_the_call_timeout_is_model_unavailable() {
    let (state, ws) = scratch("call");
    let server = hold();
    let mut config = RunConfig::defaults(1_000_000);
    config.model_call_timeout = Duration::from_millis(1000);
    // The wall budget (30 min by default) is the longer bound.
    assert!(config.limits.wall > config.model_call_timeout + GRACE);
    let (r, took) = go(&state, &ws, &server, &config);
    assert_eq!(r.cause, StopCause::ModelUnavailable, "after {took:?}");
    assert!(
        took < config.model_call_timeout + GRACE,
        "the call outlived its timeout: {took:?}"
    );
    assert_one_call_paired_and_committed(&r, &server);
}
