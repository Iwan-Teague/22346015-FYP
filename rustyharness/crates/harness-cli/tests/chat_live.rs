//! The P-21 live chat test (design §6, roadmap P-21a): "a two-turn chat
//! over a local model, both protocols, on a real piped stdin". Every turn
//! of the session is journaled; the session ends when the piped input is
//! exhausted (`session_ended`), so its outcome is
//! `Indeterminate { NothingChecked }` (a chat session runs no checks) —
//! and that is shown to the user.
//!
//! It needs a real model server, so it is `#[ignore]`d in the gates and
//! run on purpose:
//!
//! ```text
//! RUSTYHARNESS_EXIT_ENDPOINT=http://127.0.0.1:8080/v1 \
//! RUSTYHARNESS_EXIT_MODEL=<the model id the server lists> \
//!   cargo test -p harness-cli --test chat_live -- --ignored --test-threads=1
//! ```
//!
//! Each protocol's test runs the real `rustyharness chat` binary with a
//! piped stdin (so it runs unattended: the workspace's edit tools must be
//! allowed by an explicit `--policy`, the same rule `run` follows). The
//! first turn asks for a codename hidden in the workspace; the second
//! asks for it to be written to a new file. The test asserts the answer
//! (the codename appears in a model reply), a verified edit (the file is
//! on disk, applied through the journal), and then audits the session
//! journal with the anchored session replay: every record recomputed or
//! re-fed, the stop recomputed, the chain head matched against the anchor.
//! (A session journal cannot go through the `replay` verb — a batch audit
//! refuses a session journal at its header's mode — so the audit is the
//! `audit_session` API the `replay` verb itself would grow into.)

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use gate_outcome::Digest;
use harness_core::RunId;
use harness_journal::{layout, EventKind, JournalReader};
use harness_model::profile::Profile;
use harness_model::TaskText;
use harness_policy::denies::overlay_default_denies;
use harness_policy::UserPolicy;
use harness_run::{audit_session, Audit, SessionConfig, TaskSpec};
use harness_testkit::registry;
use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_rustyharness");

/// The fact the model has to find and then write down.
const CODENAME: &str = "AMBER-OWL-77";

/// The task every chat here starts from (the audit re-parses this exact
/// text and grant list into a `TaskSpec`).
const TASK: &str = "You are helping with a small project in this workspace.";

/// The grants the task carries (read-only discovery plus the edit tools
/// the second turn needs).
const GRANTS: &[&str] = &[
    "harness.fs.read",
    "harness.fs.list",
    "harness.fs.search",
    "harness.edit.write",
    "harness.edit.replace",
];

/// The two user turns, piped in order; EOF afterwards ends the session.
const TURNS: &[&str] = &[
    "What is the project codename? Look through the workspace files to find it, then tell me. Do not change any files yet.",
    "Create a file named p21.txt in the workspace whose entire content is exactly the codename, then tell me you did it.",
];

/// The session's token budget (what `chat` gives every session).
const TOKENS: u64 = 1_000_000;

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| {
        panic!("{k} is not set: this test needs a local model server (see the module docs)")
    })
}

struct Fx {
    state: PathBuf,
    ws: PathBuf,
    task: PathBuf,
    profile: PathBuf,
    policy: PathBuf,
}

fn fixture(protocol: &str) -> Fx {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("chat-live-{protocol}"));
    let _ = std::fs::remove_dir_all(&base);
    let (state, ws) = (base.join("state"), base.join("ws"));
    std::fs::create_dir_all(&state).unwrap();
    std::fs::create_dir_all(ws.join("docs")).unwrap();
    std::fs::write(
        ws.join("README.md"),
        "# A small project\n\nSee docs/ for the project notes.\n",
    )
    .unwrap();
    std::fs::write(
        ws.join("docs/notes.txt"),
        format!("Project notes\n\nThe project codename is {CODENAME}.\nIt ships in spring.\n"),
    )
    .unwrap();
    let task = base.join("task.json");
    std::fs::write(&task, json!({ "task": TASK, "grants": GRANTS }).to_string()).unwrap();
    // Unattended (piped stdin) means no approver: the edit tools must be
    // allowed up front, or the second turn's edit is denied.
    let policy = base.join("policy.json");
    std::fs::write(
        &policy,
        json!({"allow": ["harness.edit.replace", "harness.edit.write"]}).to_string(),
    )
    .unwrap();
    let profile = base.join("profile.json");
    std::fs::write(
        &profile,
        json!({
            "profile_version": 1,
            "id": format!("chat-live-{protocol}"),
            "model": env("RUSTYHARNESS_EXIT_MODEL"),
            "context_window": 32768,
            "fill_ratio": 0.6,
            "protocol": protocol,
            "tool_choice_required_ok": false,
            "grammar": "none",
            "max_active_tools": 6,
            "edit_format": "replace",
            "recent_turns": 5,
            "sampling": {"temperature": 0.2, "top_p": 0.95, "seed": 7, "max_tokens": 8192}
        })
        .to_string(),
    )
    .unwrap();
    Fx {
        state,
        ws,
        task,
        profile,
        policy,
    }
}

/// Run the real binary with the two turns piped on stdin (then EOF).
fn chat(fx: &Fx, endpoint: &str) -> (i32, String, String) {
    let mut child = Command::new(BIN)
        .args([
            "chat",
            "--task",
            fx.task.to_str().unwrap(),
            "--workspace",
            fx.ws.to_str().unwrap(),
            "--state-root",
            fx.state.to_str().unwrap(),
            "--profile",
            fx.profile.to_str().unwrap(),
            "--policy",
            fx.policy.to_str().unwrap(),
            "--endpoint",
            endpoint,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("GATE_OK_FILE")
        .spawn()
        .unwrap();
    {
        let stdin = child.stdin.as_mut().unwrap();
        for turn in TURNS {
            writeln!(stdin, "{turn}").unwrap();
        }
    }
    let o = child.wait_with_output().unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// `session <id> attempt <n>: ...` from the stderr summary line.
fn session_of(stderr: &str) -> (RunId, u32) {
    let at = stderr.find("session ").unwrap() + "session ".len();
    let run = RunId::parse(&stderr[at..at + 32]).unwrap();
    let rest = &stderr[at + 32..];
    let a = rest.find("attempt ").unwrap() + "attempt ".len();
    let digits: String = rest[a..].chars().take_while(char::is_ascii_digit).collect();
    (run, digits.parse().unwrap())
}

/// The journal of the session's first attempt.
fn journal(fx: &Fx, run: &RunId, attempt: u32) -> harness_journal::Verified {
    JournalReader::open(&layout::attempt_dir(
        &layout::run_dir(&fx.state, run),
        attempt,
    ))
    .unwrap()
}

/// Every model reply's text (small payloads are journaled inline).
fn replies(v: &harness_journal::Verified) -> Vec<String> {
    v.records
        .iter()
        .filter(|r| r.kind == EventKind::ModelReplied)
        .map(|r| {
            r.body["content"]["inline"]
                .as_str()
                .unwrap_or("")
                .to_owned()
        })
        .collect()
}

/// The audit's view of the task: exactly what the CLI parsed.
fn spec() -> TaskSpec {
    TaskSpec {
        task: TaskText::new(TASK.to_owned()),
        grants: GRANTS.iter().map(|g| (*g).to_owned()).collect(),
        workspace_public: false,
        ports: Vec::new(),
        lan_ports: Vec::new(),
        exec: None,
        presubmit: None,
        post_edit: None,
        protected: Vec::new(),
        kind: harness_run::SessionKind::Coding,
    }
}

/// The policy the CLI built: the `--policy` file, then the default
/// denies on top (`chat` overlays them unless `--no-default-denies`).
fn policy(fx: &Fx) -> UserPolicy {
    let bytes = std::fs::read(&fx.policy).unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    overlay_default_denies(UserPolicy::from_json(&v).unwrap()).unwrap()
}

fn chat_live(protocol: &str) {
    let endpoint = env("RUSTYHARNESS_EXIT_ENDPOINT");
    let fx = fixture(protocol);
    let (code, stdout, stderr) = chat(&fx, &endpoint);
    eprintln!("--- {protocol} chat stderr ---\n{stderr}");
    assert_eq!(code, 5, "{stderr}");

    // The gate child's ending: `chain_head <hex>` then a GateReport whose
    // last line carries the nothing-checked outcome of a session stop.
    let mut lines = stdout.lines();
    let head_line = lines.next().unwrap();
    let head: Digest = head_line
        .strip_prefix("chain_head ")
        .unwrap()
        .parse()
        .unwrap();
    let report: Value = serde_json::from_str(stdout.lines().last().unwrap()).unwrap();
    assert_eq!(report["outcome"]["Indeterminate"]["why"], "NothingChecked");
    assert_eq!(
        report["findings"][0]["observed"], "stopped: session_ended; no checks planned",
        "the session ends on its piped input's EOF: {report}"
    );
    assert!(stderr.contains("2 turn(s)"), "{stderr}");
    assert!(stderr.contains("stopped (session_ended)"), "{stderr}");

    // The journal: two turns asked and answered, the codename told, and
    // the edit applied through the tools onto disk.
    let (run, attempt) = session_of(&stderr);
    let v = journal(&fx, &run, attempt);
    let turns: Vec<_> = v
        .records
        .iter()
        .filter(|r| r.kind == EventKind::UserTurn)
        .collect();
    assert_eq!(turns.len(), 2, "both piped turns ran");
    let said = replies(&v);
    assert!(
        said.iter().any(|t| t.contains(CODENAME)),
        "the codename appears in an answer: {said:?}"
    );
    assert!(
        v.records.iter().any(|r| r.kind == EventKind::ToolStarted
            && r.body["capability"]
                .as_str()
                .is_some_and(|c| c.starts_with("harness.edit."))),
        "no edit tool ran: {stderr}"
    );
    assert!(
        v.records.iter().any(|r| r.kind == EventKind::EditApplied),
        "the edit was applied: {stderr}"
    );
    let written = std::fs::read_to_string(fx.ws.join("p21.txt")).unwrap();
    assert!(
        written.contains(CODENAME),
        "the verified edit, on disk: {written:?}"
    );

    // The anchored session replay: every record recomputed or re-fed and
    // matched, the stop recomputed, the chain head the anchor. (The CLI's
    // `replay` verb is batch-only; this is the session audit.)
    let config = SessionConfig::defaults(TOKENS);
    let mut session_limits = config.run.limits.clone();
    session_limits.format_errors = u32::MAX; // the meter never latches in a session
    let a = audit_session(
        Audit {
            state_root: &fx.state,
            run: &run,
            attempt: None,
            anchor: Some(head),
            spec: &spec(),
            registry: &registry().unwrap(),
            policy: &policy(&fx),
            profile: &Profile::parse(&std::fs::read(&fx.profile).unwrap()).unwrap(),
            limits: &session_limits,
        },
        &config.turn,
    )
    .unwrap();
    assert_eq!(a.divergence, None, "{a:?}");
    assert!(a.stop_recomputed, "the session_ended stop is recomputed");
    assert!(a.anchored, "the chain head matched the anchor");
    assert_eq!(
        a.outcome,
        gate_outcome::GateOutcome::Indeterminate {
            why: gate_outcome::IndeterminateKind::NothingChecked
        }
    );
}

#[test]
#[ignore = "needs a local model server: set RUSTYHARNESS_EXIT_ENDPOINT and RUSTYHARNESS_EXIT_MODEL"]
fn chat_live_text_two_turns() {
    chat_live("text");
}

#[test]
#[ignore = "needs a local model server: set RUSTYHARNESS_EXIT_ENDPOINT and RUSTYHARNESS_EXIT_MODEL"]
fn chat_live_native_two_turns() {
    chat_live("native");
}
