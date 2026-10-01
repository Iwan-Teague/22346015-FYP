//! The kit's own proof tests (slice P-03): one scripted run audited
//! clean, one captured CLI report line, one fixture lifecycle.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use gate_outcome::{GateOutcome, IndeterminateKind};
use harness_core::StopCause;
use harness_journal::EventKind;
use harness_testkit::{act, assert_audit_clean, cli, journal_kinds, run_scripted, submit, Fixture};

/// A profile the CLI can parse (the same shape `harness-cli`'s tests use).
const PROFILE: &str = r#"{"profile_version":1,"id":"mock-m","model":"m",
  "context_window":32768,"fill_ratio":0.6,"protocol":"text","tool_choice_required_ok":false,
  "grammar":"none","max_active_tools":6,"edit_format":"replace","recent_turns":5,
  "sampling":{"temperature":0.2,"top_p":0.95,"seed":7,"max_tokens":2048}}"#;

#[test]
fn testkit_runs_a_scripted_read_task_and_audits_clean() {
    let fx = Fixture::new("scripted-read").unwrap();
    fx.write("a.txt", "hello from the workspace\n").unwrap();
    let r = run_scripted(
        &fx,
        vec![act("harness.fs.read", "{\"path\":\"a.txt\"}"), submit()],
    )
    .unwrap();
    // Every outcome so far is Indeterminate { NothingChecked } (INV-18).
    assert_eq!(r.cause, StopCause::Submitted);
    assert_eq!(
        r.outcome,
        GateOutcome::Indeterminate {
            why: IndeterminateKind::NothingChecked
        }
    );
    assert_audit_clean(&fx, &r).unwrap();
    let kinds = journal_kinds(&r).unwrap();
    assert!(kinds.contains(&EventKind::ToolStarted), "{kinds:?}");
    assert!(kinds.contains(&EventKind::RunStopped), "{kinds:?}");
}

#[test]
fn testkit_cli_driver_captures_report_line() {
    let fx = Fixture::new("cli-driver").unwrap();
    // A missing state root refuses after the inputs parse and the client
    // builds, before anything is written and before any network call: the
    // whole invocation is hermetic.
    std::fs::write(
        fx.base().join("task.json"),
        r#"{"task":"t","grants":["harness.fs.read"]}"#,
    )
    .unwrap();
    std::fs::write(fx.base().join("profile.json"), PROFILE).unwrap();
    let task = fx.base().join("task.json");
    let profile = fx.base().join("profile.json");
    let missing = fx.base().join("missing");
    let args = [
        "run",
        "--task",
        task.to_str().unwrap(),
        "--workspace",
        fx.workspace().to_str().unwrap(),
        "--state-root",
        missing.to_str().unwrap(),
        "--profile",
        profile.to_str().unwrap(),
        "--endpoint",
        "http://127.0.0.1:9/v1",
    ];
    let (code, stdout, stderr) = cli(&fx, &args, &[]);
    assert_eq!(code, 5, "stderr: {stderr}");
    // The last stdout line is the gate report (design §7.7).
    let last = stdout.lines().last().unwrap_or("");
    let report: serde_json::Value = serde_json::from_str(last)
        .unwrap_or_else(|e| panic!("last stdout line {last:?} is not the report: {e}"));
    assert_eq!(report["outcome"]["Indeterminate"]["why"], "CouldNotRun");
    assert!(!stderr.is_empty(), "the refusal says why on stderr");
    assert!(
        !fx.state_root().join("runs").exists(),
        "nothing was written"
    );
}

#[test]
fn testkit_fixture_cleans_up() {
    let base;
    {
        let fx = Fixture::new("cleanup").unwrap();
        base = fx.base().to_path_buf();
        assert!(fx.base().is_dir());
        assert!(fx.state_root().is_dir());
        assert!(fx.workspace().is_dir());
        fx.write("a.txt", "x").unwrap();
    }
    assert!(!base.exists(), "the dropped fixture removed its base");
    // Two fixtures never share a directory.
    let a = Fixture::new("cleanup").unwrap();
    let b = Fixture::new("cleanup").unwrap();
    assert_ne!(a.base(), b.base());
    assert!(a.state_root().is_dir() && b.state_root().is_dir());
}
