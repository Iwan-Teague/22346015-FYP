//! The H1 exit test (design §9, H1 row): "A read-only question-answering
//! task runs end to end on a local model with both protocols. Every run's
//! outcome is `Indeterminate { NothingChecked }` (no checks yet), and that
//! is shown to the user."
//!
//! It needs a real model server, so it is `#[ignore]`d in the gates and run
//! on purpose:
//!
//! ```text
//! RUSTYHARNESS_EXIT_ENDPOINT=http://127.0.0.1:8080/v1 \
//! RUSTYHARNESS_EXIT_MODEL=<the model id the server lists> \
//!   cargo test -p harness-cli --test exit_h1 -- --ignored --test-threads=1
//! ```
//!
//! Each protocol's test runs the real `rustyharness` binary, with the real
//! locality probe, on a state root and workspace under the target
//! directory, against the loopback server: `run` must end with the task
//! submitted, the answer found in the workspace, exit 5 and a
//! `NothingChecked` report shown on stderr and in the report line; then
//! `replay` must recompute every record of that run and match.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_rustyharness");

/// The fact the model has to find.
const CODENAME: &str = "BLUE-HERON-42";

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
}

fn fixture(protocol: &str) -> Fx {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("exit-h1-{protocol}"));
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
    std::fs::write(
        &task,
        serde_json::json!({
            "task": "What is the project codename? Look through the workspace files to find it, then submit the codename (and nothing else) as the note of harness.task.submit.",
            "grants": ["harness.fs.read", "harness.fs.list", "harness.fs.search"]
        })
        .to_string(),
    )
    .unwrap();
    let profile = base.join("profile.json");
    std::fs::write(
        &profile,
        serde_json::json!({
            "profile_version": 1,
            "id": format!("exit-{protocol}"),
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
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
        .env_remove("GATE_OK_FILE")
        .output()
        .unwrap()
}

fn last_line(o: &Output) -> serde_json::Value {
    let out = String::from_utf8(o.stdout.clone()).unwrap();
    serde_json::from_str(out.lines().last().unwrap()).unwrap()
}

fn exit_test(protocol: &str) {
    let endpoint = env("RUSTYHARNESS_EXIT_ENDPOINT");
    let fx = fixture(protocol);
    let (task, ws, state, profile) = (
        fx.task.to_str().unwrap(),
        fx.ws.to_str().unwrap(),
        fx.state.to_str().unwrap(),
        fx.profile.to_str().unwrap(),
    );
    let o = run(&[
        "run",
        "--task",
        task,
        "--workspace",
        ws,
        "--state-root",
        state,
        "--profile",
        profile,
        "--endpoint",
        &endpoint,
    ]);
    let stderr = String::from_utf8_lossy(&o.stderr).into_owned();
    eprintln!("--- {protocol} run stderr ---\n{stderr}");
    assert_eq!(o.status.code(), Some(5), "{stderr}");
    let report = last_line(&o);
    assert_eq!(report["outcome"]["Indeterminate"]["why"], "NothingChecked");
    assert_eq!(
        report["findings"][0]["observed"], "stopped: submitted; no checks planned",
        "the task must end with a submit: {report}"
    );
    assert!(stderr.contains("stopped (submitted)"), "{stderr}");
    assert!(
        stderr.contains("outcome: Indeterminate (NothingChecked)"),
        "the outcome is shown to the user: {stderr}"
    );

    // The journal: the model read the workspace and submitted the answer.
    let at = stderr.find("run ").unwrap() + 4;
    let run_id = &stderr[at..at + 32];
    let attempt = fx.state.join("runs").join(run_id).join("attempt-1");
    let v = harness_journal::JournalReader::open(&attempt).unwrap();
    let kinds: Vec<_> = v.records.iter().map(|r| r.kind).collect();
    assert!(
        v.records
            .iter()
            .any(|r| r.kind == harness_journal::EventKind::ToolStarted
                && r.body["capability"] != "harness.task.submit"),
        "no read tool ran: {kinds:?}"
    );
    let note = v
        .records
        .iter()
        .find(|r| r.kind == harness_journal::EventKind::SubmitRequested)
        .map(|r| r.body["note"]["inline"].as_str().unwrap_or("").to_owned())
        .unwrap();
    assert!(note.contains(CODENAME), "submitted note: {note:?}");

    // Replay: every record recomputed and matched.
    let r = run(&[
        "replay",
        "--run",
        run_id,
        "--task",
        task,
        "--state-root",
        state,
        "--profile",
        profile,
    ]);
    let rs = String::from_utf8_lossy(&r.stderr).into_owned();
    eprintln!("--- {protocol} replay stderr ---\n{rs}");
    assert_eq!(r.status.code(), Some(5));
    assert_eq!(
        last_line(&r)["outcome"]["Indeterminate"]["why"],
        "NothingChecked"
    );
    assert!(rs.contains("every record recomputed and matched"), "{rs}");
}

#[test]
#[ignore = "needs a local model server: set RUSTYHARNESS_EXIT_ENDPOINT and RUSTYHARNESS_EXIT_MODEL"]
fn h1_exit_text_protocol() {
    exit_test("text");
}

#[test]
#[ignore = "needs a local model server: set RUSTYHARNESS_EXIT_ENDPOINT and RUSTYHARNESS_EXIT_MODEL"]
fn h1_exit_native_protocol() {
    exit_test("native");
}
