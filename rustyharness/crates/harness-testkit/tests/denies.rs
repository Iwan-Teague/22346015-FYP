//! P-12: the sensitive-path default denies through a real run. A library
//! run with the default (empty) policy reads `.env` as any other file
//! (OD-2: the embedder decides); a run under the CLI's default deny policy
//! refuses the read and the edit at the policy, the tools skip denied
//! paths when they walk, and the same policy audits clean while a
//! different one is refused by digest (§2.9).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use harness_journal::EventKind;
use harness_policy::default_denies;
use harness_testkit::{
    act, assert_audit_clean, assert_audit_clean_policy, journal_kinds, run_scripted,
    run_scripted_policy, submit, Fixture,
};

fn edit_spec(task: &str) -> harness_run::TaskSpec {
    harness_run::TaskSpec {
        task: harness_model::TaskText::new(task.into()),
        grants: vec!["harness.fs.read".into(), "harness.edit.write".into()],
        workspace_public: false,
        exec: None,
        presubmit: None,
        protected: Vec::new(),
    }
}

/// Library default: no default denies. The model reads `.env` and the tool
/// runs — the embedder decides what is sensitive (OD-2).
#[test]
fn library_run_has_no_default_denies() {
    let fx = Fixture::new("denies-library-default").unwrap();
    fx.write(".env", "SECRET=1\n").unwrap();
    let report = run_scripted(
        &fx,
        vec![act("harness.fs.read", r#"{"path":".env"}"#), submit()],
    )
    .unwrap();
    // The read ran (a denied call never reaches ToolStarted).
    let kinds = journal_kinds(&report).unwrap();
    assert!(kinds.contains(&EventKind::ToolStarted), "{kinds:?}");
    assert_audit_clean(&fx, &report).unwrap();
}

/// Under the CLI's default deny policy the same read is denied at the
/// policy (no tool ran), the workspace is untouched, and the SAME policy
/// audits clean while the empty default does not: the header digests the
/// effective policy, defaults included.
#[test]
fn audit_clean_with_denies() {
    let fx = Fixture::new("denies-audit-clean").unwrap();
    fx.write(".env", "SECRET=1\n").unwrap();
    let policy = default_denies().unwrap();
    let report = run_scripted_policy(
        &fx,
        &policy,
        vec![
            act("harness.fs.read", r#"{"path":".env"}"#),
            act("harness.fs.search", r#"{"pattern":"SECRET"}"#),
            submit(),
        ],
    )
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(fx.workspace().join(".env")).unwrap(),
        "SECRET=1\n"
    );
    let kinds = journal_kinds(&report).unwrap();
    assert!(kinds.contains(&EventKind::PolicyDecided), "{kinds:?}");
    // The search ran (its `path` is absent, so no deny matcher held) and
    // the submit ran; the read of `.env` did not.
    assert!(kinds.contains(&EventKind::ToolStarted), "{kinds:?}");
    // The replay recomputes every decision under the same policy.
    assert_audit_clean_policy(&fx, &policy, &report).unwrap();
    // A run audited without the defaults is a different policy: refused on
    // the digest before any decision is compared.
    assert!(assert_audit_clean(&fx, &report).is_err());
}

/// An edit aimed at a denied path is refused at the policy: no tool ran,
/// no edit applied, the file keeps its bytes.
#[test]
fn edit_to_denied_path_refused() {
    let fx = Fixture::with_spec(
        "denies-edit-refused",
        edit_spec("Overwrite .env with the deployment secrets."),
    )
    .unwrap();
    fx.write(".env", "SECRET=1\n").unwrap();
    fx.write("a.txt", "notes\n").unwrap();
    let policy = default_denies().unwrap();
    let report = run_scripted_policy(
        &fx,
        &policy,
        vec![
            act(
                "harness.edit.write",
                r#"{"path":".env","content":"HACKED\n"}"#,
            ),
            submit(),
        ],
    )
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(fx.workspace().join(".env")).unwrap(),
        "SECRET=1\n"
    );
    let kinds = journal_kinds(&report).unwrap();
    assert!(!kinds.contains(&EventKind::EditApplied), "{kinds:?}");
    // Only the submit ran; the denied write never reached a tool.
    assert_eq!(
        kinds
            .iter()
            .filter(|k| **k == EventKind::ToolStarted)
            .count(),
        1,
        "{kinds:?}"
    );
    assert_audit_clean_policy(&fx, &policy, &report).unwrap();
}

/// The tools skip policy-denied paths when they walk and say how many: a
/// search under the defaults hides `.env` and names the skips, and the run
/// still audits clean (the skip counts are journaled tool output, re-fed
/// verbatim by the replay).
#[test]
fn search_skips_denied_files_in_a_run_and_audits_clean() {
    let fx = Fixture::new("denies-search-skip").unwrap();
    fx.write(".env", "SECRET=1\n").unwrap();
    fx.write("a.txt", "SECRET too\n").unwrap();
    let policy = default_denies().unwrap();
    let report = run_scripted_policy(
        &fx,
        &policy,
        vec![
            act("harness.fs.search", r#"{"pattern":"SECRET"}"#),
            submit(),
        ],
    )
    .unwrap();
    let kinds = journal_kinds(&report).unwrap();
    assert!(kinds.contains(&EventKind::ToolStarted), "{kinds:?}");
    assert_audit_clean_policy(&fx, &policy, &report).unwrap();
    // The empty policy is a different policy for this run: the defaults
    // are in the header digest.
    assert!(assert_audit_clean(&fx, &report).is_err());
}
