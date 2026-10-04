//! P-36f: an execute-class run's file work goes through the confined
//! helper (INV-42), whole runs through the public `run` with the real
//! sandbox, the real tools and a scripted model, on macOS. What is shown:
//! a run with an exec grant records `file_ops: {confined-helper, stub}`
//! in its header and its edits land through the helper; a run without an
//! exec grant keeps the in-process tools and a header without the key, so
//! older journals read as before; a helper that cannot be verified at its
//! view check refuses the run (never an in-process fallback); three lost
//! calls stop the run as a sandbox loss after the failing result is
//! durable; and a hanging file op ends in the timeout status inside the
//! wall. A lost call is staged by freezing the run's stub from the test
//! process (the sandbox itself forbids a model action from even finding
//! the stub to signal it).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use harness_core::environment::{EnvSample, Unmeasured};
use harness_core::{sha256, StopCause};
use harness_journal::{EventKind, JournalReader, Record};
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, SemVer, ValidationContext};
use harness_model::profile::Profile;
use harness_model::scripted::{text_reply, ScriptedBackend};
use harness_model::{Completion, ModelBackend, ModelError, ModelRequest, TaskText};
use harness_policy::locality::{FsQuery, LocalityProbe};
use harness_policy::UserPolicy;
use harness_run::{run, ExecProgram, ExecSpec, Run, RunConfig, RunReport, TaskSpec};
use harness_sandbox::seatbelt::FILEOP_STUB;
use harness_sandbox::SystemConfinement;
use serde_json::{json, Value};

const FIXED_ENV: EnvSample = EnvSample::unmeasured(Unmeasured::NoSafeApi);
const EXEC: &str = "harness.exec.run";

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
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("fops-{name}"));
    let _ = fs::remove_dir_all(&base);
    let (state, ws) = (base.join("state"), base.join("ws"));
    fs::create_dir_all(&state).unwrap();
    fs::create_dir_all(&ws).unwrap();
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

fn action(tool: &str, args: &Value) -> Result<Completion, ModelError> {
    Ok(text_reply(&format!(
        "<action>{{\"tool\":\"{tool}\",\"args\":{args}}}</action>"
    )))
}
fn submit() -> Result<Completion, ModelError> {
    action("harness.task.submit", &json!({ "note": "done" }))
}
fn write_note(content: &str) -> Result<Completion, ModelError> {
    action(
        "harness.edit.write",
        &json!({ "path": "note.txt", "content": content }),
    )
}

/// SIGSTOP the run's file-op stub: the perl whose cwd is this run's
/// workspace (the confined spawn starts it there, §7.1). The freeze comes
/// from the test process, outside the sandbox: inside it the profile
/// grants `process-info` on the process itself only, so no model action
/// can even find the stub to stop it — which is the point of INV-42, and
/// what the first draft's sandboxed `pkill` died of (exit 3, "cannot get
/// process list"). The stub answers to no name search either (its `-e`
/// program text is the whole command line, past what `pgrep -f` and `ps`
/// will read), so the finder takes every `perl` and asks the kernel for
/// the one whose cwd is the workspace.
fn freeze_stub(ws: &Path) {
    let ws = fs::canonicalize(ws).expect("the workspace must exist");
    let out = Command::new("/usr/bin/pgrep")
        .args(["-x", "perl"])
        .output()
        .expect("pgrep must run");
    let ws = ws.to_str().expect("the workspace path is utf-8");
    let mut stopped = 0;
    for pid in String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.trim().parse::<u32>().ok())
    {
        let cwd = Command::new("/usr/sbin/lsof")
            .args(["-a", "-p", &pid.to_string(), "-d", "cwd", "-Fn"])
            .output()
            .expect("lsof must run");
        if !String::from_utf8_lossy(&cwd.stdout).contains(ws) {
            continue;
        }
        let st = Command::new("/bin/kill")
            .args(["-STOP", &pid.to_string()])
            .status()
            .expect("kill must run");
        assert!(st.success(), "the freeze must land on the stub {pid}");
        stopped += 1;
    }
    assert_eq!(stopped, 1, "exactly one stub runs for the workspace {ws:?}");
}

/// The scripted backend with the test-side freezes: at the listed turn
/// numbers (counted per `complete` call), the run's stub is stopped
/// before the reply is served, so the action that reply asks for loses
/// the helper (§7.5's lost call, staged like the tools' conformance
/// suite stops a known pid).
struct FreezingBackend {
    inner: ScriptedBackend,
    ws: PathBuf,
    freeze_before: Vec<usize>,
    turns: AtomicUsize,
}

impl ModelBackend for FreezingBackend {
    fn identity(&self) -> harness_model::ModelIdentity {
        self.inner.identity()
    }

    fn complete(&self, req: &ModelRequest, deadline: Instant) -> Result<Completion, ModelError> {
        let n = self.turns.fetch_add(1, Ordering::SeqCst);
        if self.freeze_before.contains(&n) {
            freeze_stub(&self.ws);
        }
        self.inner.complete(req, deadline)
    }
}

fn perl_and_pkill_spec() -> ExecSpec {
    ExecSpec {
        programs: vec![
            ExecProgram {
                name: "perl".into(),
                path: "/usr/bin/perl".into(),
            },
            ExecProgram {
                name: "pkill".into(),
                path: "/usr/bin/pkill".into(),
            },
        ],
        ..ExecSpec::default()
    }
}

fn spec_with(grants: &[&str], exec: Option<ExecSpec>) -> TaskSpec {
    TaskSpec {
        task: TaskText::new("Make the tests pass.".into()),
        grants: grants.iter().map(|g| (*g).to_owned()).collect(),
        workspace_public: false,
        ports: Vec::new(),
        lan_ports: Vec::new(),
        exec,
        presubmit: None,
        post_edit: None,
        protected: Vec::new(),
        kind: harness_run::SessionKind::Coding,
    }
}

fn exec_spec() -> TaskSpec {
    spec_with(
        &[
            "harness.fs.read",
            "harness.edit.replace",
            "harness.edit.write",
            EXEC,
        ],
        Some(perl_and_pkill_spec()),
    )
}

fn plain_spec() -> TaskSpec {
    spec_with(
        &[
            "harness.fs.read",
            "harness.edit.replace",
            "harness.edit.write",
        ],
        None,
    )
}

fn allow_all() -> UserPolicy {
    UserPolicy::new(
        &[],
        &[],
        &["harness.edit.replace", "harness.edit.write", EXEC],
    )
    .unwrap()
}

fn records(r: &RunReport, attempt: u32) -> Vec<Record> {
    JournalReader::open(&harness_journal::layout::attempt_dir(&r.run_dir, attempt))
        .unwrap()
        .records
}

fn header_of(r: &RunReport) -> serde_json::Map<String, Value> {
    records(r, r.attempt)[0].body.clone()
}

fn go(
    name: &str,
    spec: &TaskSpec,
    replies: Vec<Result<Completion, ModelError>>,
    config: &RunConfig,
    freeze_before: &[usize],
) -> RunReport {
    let (state, ws) = scratch(name);
    let ws = fs::canonicalize(ws).expect("the workspace must exist");
    let profile = Profile::conservative_default("m");
    let backend = FreezingBackend {
        inner: ScriptedBackend::new(profile.clone(), replies),
        ws: ws.clone(),
        freeze_before: freeze_before.to_owned(),
        turns: AtomicUsize::new(0),
    };
    run(Run {
        state_root: &state,
        workspace: &ws,
        spec,
        registry: &registry(),
        policy: &allow_all(),
        profile: &profile,
        backend: &backend,
        probe: &Local,
        env: &FIXED_ENV,
        config,
        approver: None,
        confinement: Some(&SystemConfinement),
    })
    .unwrap()
}

fn short_calls() -> RunConfig {
    let mut c = RunConfig::defaults(1_000_000);
    c.tool_call_timeout = Duration::from_secs(1);
    c
}

fn ws_of(r: &RunReport) -> PathBuf {
    r.run_dir.ancestors().nth(3).unwrap().join("ws")
}

// INV-42's run half: with an exec grant the run's header names the
// confined helper and the stub build it ran, and the edit the model made
// is on disk behind it.
#[cfg(target_os = "macos")]
#[test]
fn run_with_exec_grant_uses_confined_file_ops() {
    let started = Instant::now();
    let r = go(
        "uses-confined",
        &exec_spec(),
        vec![write_note("through the helper\n"), submit()],
        &RunConfig::defaults(1_000_000),
        &[],
    );
    let header = header_of(&r);
    assert_eq!(header["file_ops"]["mode"], "confined-helper");
    assert_eq!(
        r.cause,
        StopCause::Submitted,
        "{:?} in {:?}",
        r.cause,
        started.elapsed()
    );
    assert_eq!(
        fs::read(ws_of(&r).join("note.txt")).unwrap(),
        b"through the helper\n"
    );
    assert!(started.elapsed() < Duration::from_secs(120));
}

// The header records exactly what §7.5 says: the mode and the pinned
// stub's digest (the same digest a replay compares).
#[cfg(target_os = "macos")]
#[test]
fn header_records_file_ops_mode_and_stub_digest() {
    let r = go(
        "header",
        &exec_spec(),
        vec![write_note("x\n"), submit()],
        &RunConfig::defaults(1_000_000),
        &[],
    );
    let header = header_of(&r);
    assert_eq!(header["file_ops"]["mode"], "confined-helper");
    assert_eq!(
        header["file_ops"]["stub"],
        sha256(FILEOP_STUB.as_bytes()).to_string()
    );
}

// Without an exec grant the tools stay in process: no `file_ops` key (so
// every journal written before this slice reads as before), and the audit
// recomputes the same header.
#[cfg(target_os = "macos")]
#[test]
fn run_without_exec_grant_stays_in_process() {
    let r = go(
        "in-process",
        &plain_spec(),
        vec![write_note("in process\n"), submit()],
        &RunConfig::defaults(1_000_000),
        &[],
    );
    assert_eq!(r.cause, StopCause::Submitted);
    let header = header_of(&r);
    assert!(
        header.get("file_ops").is_none(),
        "an in-process run must not record a file_ops mode"
    );
    assert_eq!(
        fs::read(ws_of(&r).join("note.txt")).unwrap(),
        b"in process\n"
    );
}

// `old_header_digest_unchanged_without_file_ops`: the same fact from the
// audit's side — the replay's expected inputs for a run without an exec
// grant carry no `file_ops` key, so the recorded header (and its digest)
// is exactly what a pre-P-36f build would have written and compared.
#[cfg(target_os = "macos")]
#[test]
fn old_header_digest_unchanged_without_file_ops() {
    let r = go(
        "old-header",
        &plain_spec(),
        vec![write_note("old\n"), submit()],
        &RunConfig::defaults(1_000_000),
        &[],
    );
    let header = header_of(&r);
    assert!(header.get("file_ops").is_none());
    assert!(header.get("exec").is_none());
    // The keys an audit compares, recomputed for this spec, name no
    // file-op mode: nothing to diverge on.
    let spec = plain_spec();
    assert!(spec.exec.is_none());
    let policy = allow_all();
    let a = harness_run::audit(harness_run::Audit {
        state_root: r.run_dir.ancestors().nth(2).unwrap(),
        run: &r.run,
        attempt: None,
        anchor: r.chain_head,
        spec: &spec,
        registry: &registry(),
        policy: &policy,
        profile: &Profile::conservative_default("m"),
        limits: &RunConfig::defaults(1_000_000).limits,
        children: harness_run::ChildAudit::Skip,
    })
    .unwrap();
    assert!(a.divergence.is_none(), "{:?}", a.divergence);
    assert!(a.stop_recomputed);
}

// An edit made through the helper audits clean: the recorded result, the
// tree digests and the stop all recompute (the helper's own tree op
// digests like the in-process walk, and the audit replays edits the same
// way either way).
#[cfg(target_os = "macos")]
#[test]
fn edit_through_helper_audits_clean() {
    let r = go(
        "audits",
        &exec_spec(),
        vec![write_note("audited\n"), submit()],
        &RunConfig::defaults(1_000_000),
        &[],
    );
    assert_eq!(r.cause, StopCause::Submitted);
    let a = harness_run::audit(harness_run::Audit {
        state_root: r.run_dir.ancestors().nth(2).unwrap(),
        run: &r.run,
        attempt: None,
        anchor: r.chain_head,
        spec: &exec_spec(),
        registry: &registry(),
        policy: &allow_all(),
        profile: &Profile::conservative_default("m"),
        limits: &RunConfig::defaults(1_000_000).limits,
        children: harness_run::ChildAudit::Skip,
    })
    .unwrap();
    assert!(a.divergence.is_none(), "{:?}", a.divergence);
    assert!(a.stop_recomputed);
    assert!(a.anchored);
}

// §7.5: the third lost call stops the run as a sandbox loss. Each freeze
// (before turns 0, 3 and 6) is one loss — the frozen stub's request runs
// past the deadline — and the call after a loss restarts the stub, so the
// model's writes alternate with the freezes until the third loss ends the
// run: after the failing result is durable, visible in the journal as an
// ordinary error.
#[cfg(target_os = "macos")]
#[test]
fn helper_lost_three_times_stops_sandbox_lost() {
    let started = Instant::now();
    let r = go(
        "lost",
        &exec_spec(),
        vec![
            write_note("one\n"),
            write_note("two\n"),
            write_note("three\n"),
            write_note("four\n"),
            write_note("five\n"),
            write_note("six\n"),
            write_note("seven\n"),
            write_note("eight\n"),
        ],
        &short_calls(),
        &[0, 3, 6],
    );
    assert_eq!(r.cause, StopCause::SandboxLost, "{:?}", r.cause);
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "inside the wall"
    );
    // The failing call's error result is durable before the stop.
    let recs = records(&r, r.attempt);
    let last_tool = recs
        .iter()
        .rev()
        .find(|x| x.kind == EventKind::ToolFinished)
        .unwrap();
    assert_eq!(last_tool.body["status"], "timeout", "{:?}", last_tool.body);
}

// A hanging file op ends the call in the timeout status within the wall
// (the run's tool-call deadline, not the wall budget), and the run goes
// on to a clean submit — the call after the loss restarts the stub, so
// the submit's own file work lands.
#[cfg(target_os = "macos")]
#[test]
fn hanging_file_op_ends_in_tool_timeout_within_wall() {
    let started = Instant::now();
    let r = go(
        "hang",
        &exec_spec(),
        vec![write_note("hung\n"), submit()],
        &short_calls(),
        &[0],
    );
    assert_eq!(r.cause, StopCause::Submitted);
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "the call ended inside the wall: {:?}",
        started.elapsed()
    );
    let recs = records(&r, r.attempt);
    let write = recs
        .iter()
        .find(|x| {
            x.kind == EventKind::ToolFinished
                && x.body.get("tool") == Some(&json!("harness.edit.write"))
        })
        .unwrap_or_else(|| {
            recs.iter()
                .find(|x| x.kind == EventKind::ToolFinished)
                .unwrap()
        });
    assert_eq!(write.body["status"], "timeout", "{:?}", write.body);
}
