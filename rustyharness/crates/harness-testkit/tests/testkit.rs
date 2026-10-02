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
use harness_journal::layout;
use harness_journal::{EventKind, JournalReader};
use harness_policy::UserPolicy;
use harness_run::RunReport;
use harness_testkit::{
    act, assert_audit_clean, assert_audit_clean_policy, cli, journal_kinds, run_scripted,
    run_scripted_policy, submit, Fixture,
};

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

// ---------------------------------------------------------------------------
// P-29 protected paths: the header, the edit refusal, the ask floor.
// ---------------------------------------------------------------------------

fn records(r: &RunReport) -> Vec<harness_journal::Record> {
    JournalReader::open(&layout::attempt_dir(&r.run_dir, r.attempt))
        .unwrap()
        .records
}

#[test]
fn protected_list_in_header() {
    let mut fx = Fixture::new("protected-header").unwrap();
    fx.write("a.txt", "x\n").unwrap();
    fx.spec.protected = vec!["secrets/**".into()];
    let r = run_scripted(
        &fx,
        vec![act("harness.fs.read", "{\"path\":\"a.txt\"}"), submit()],
    )
    .unwrap();
    assert_audit_clean(&fx, &r).unwrap();
    let head = &records(&r)[0];
    let prot = &head.body["protected"];
    let deny = prot["deny_default"].as_array().unwrap();
    assert_eq!(deny[0], ".git/**");
    assert_eq!(deny[1], ".rustyharness/**");
    let ask = prot["ask_default"].as_array().unwrap();
    assert_eq!(ask[0], ".github/**");
    assert_eq!(ask[1], "Cargo.lock");
    let task_digest = prot["task"].as_str().unwrap();
    assert_eq!(
        task_digest.len(),
        64,
        "the task list is recorded as a digest"
    );
    // The digest is of the task's list: a run without one differs.
    let fx2 = Fixture::new("protected-header-empty").unwrap();
    fx2.write("a.txt", "x\n").unwrap();
    let r2 = run_scripted(&fx2, vec![submit()]).unwrap();
    let digest2 = records(&r2)[0].body["protected"]["task"].clone();
    assert_ne!(digest2, prot["task"]);
    // An audit given a DIFFERENT protected list diverges, and names why.
    let mut other = fx.spec.clone();
    other.protected = vec!["other/**".into()];
    fx.spec = other;
    let err = assert_audit_clean(&fx, &r).unwrap_err();
    assert!(
        err.contains("protected-path lists"),
        "the divergence names the protected lists: {err}"
    );
}

#[test]
fn task_declared_protected_path_refused() {
    let mut fx = Fixture::new("protected-refused").unwrap();
    fx.write("secrets/key.txt", "k\n").unwrap();
    fx.spec.grants.push("harness.edit.write".into());
    fx.spec.protected = vec!["secrets/**".into()];
    // The user allows edits outright; the tool still refuses the path.
    let allow = UserPolicy::new(&[], &[], &["harness.edit.write"]).unwrap();
    let r = run_scripted_policy(
        &fx,
        &allow,
        vec![
            act(
                "harness.edit.write",
                "{\"path\":\"secrets/key.txt\",\"content\":\"EVIL\"}",
            ),
            submit(),
        ],
    )
    .unwrap();
    assert_eq!(r.cause, StopCause::Submitted);
    assert_eq!(
        std::fs::read_to_string(fx.workspace().join("secrets/key.txt")).unwrap(),
        "k\n",
        "the protected file is byte-unchanged"
    );
    // The call reached the tool (policy allowed it) and was refused there.
    let kinds = journal_kinds(&r).unwrap();
    assert!(kinds.contains(&EventKind::ToolStarted), "{kinds:?}");
    assert!(!kinds.contains(&EventKind::EditApplied), "{kinds:?}");
    let named = records(&r).iter().any(|rec| {
        serde_json::to_string(&rec.body)
            .unwrap()
            .contains("the path is protected")
    });
    assert!(named, "the refusal names the protection to the model");
    assert_audit_clean_policy(&fx, &allow, &r).unwrap();
}

#[test]
fn lockfile_edit_asks() {
    let mut fx = Fixture::new("lockfile-asks").unwrap();
    fx.write("Cargo.lock", "lock\n").unwrap();
    fx.write("README.md", "readme\n").unwrap();
    fx.spec.grants.push("harness.edit.write".into());
    // Even under a policy that allows edits, the build's ask floor covers
    // the lockfile: with nobody to answer, the edit is a deny.
    let allow = UserPolicy::new(&[], &[], &["harness.edit.write"]).unwrap();
    let r = run_scripted_policy(
        &fx,
        &allow,
        vec![
            act("harness.fs.read", "{\"path\":\"README.md\"}"),
            act(
                "harness.edit.write",
                "{\"path\":\"Cargo.lock\",\"content\":\"tampered\"}",
            ),
            act(
                "harness.edit.write",
                "{\"path\":\"README.md\",\"content\":\"edited\"}",
            ),
            submit(),
        ],
    )
    .unwrap();
    assert_eq!(r.cause, StopCause::Submitted);
    assert_eq!(
        std::fs::read_to_string(fx.workspace().join("Cargo.lock")).unwrap(),
        "lock\n",
        "the lockfile edit never happened"
    );
    for rec in records(&r) {
        eprintln!(
            "DBG {:?} {}",
            rec.kind,
            serde_json::to_string(&rec.body).unwrap_or_default()
        );
    }
    assert_eq!(
        std::fs::read_to_string(fx.workspace().join("README.md")).unwrap(),
        "edited",
        "the ordinary edit went through"
    );
    assert_audit_clean_policy(&fx, &allow, &r).unwrap();
}
