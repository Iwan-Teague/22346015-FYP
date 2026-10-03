//! P-08: matcher decisions through the real run and the real audit. The
//! run allows/denies calls by matcher under a v2 policy file's rules, and
//! the replay recomputes every matched decision — the same policy audits
//! clean, a different policy is refused by digest before any decision is
//! compared (§2.9, §7.1 header).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use harness_policy::UserPolicy;
use harness_testkit::{
    act, assert_audit_clean, assert_audit_clean_policy, run_scripted_policy, submit, Fixture,
};
use serde_json::json;

/// Grants for an unattended editing task: read (so the edit engine's
/// stale-read guard is satisfied) and the replace tool.
fn edit_spec(task: &str) -> harness_run::TaskSpec {
    harness_run::TaskSpec {
        task: harness_model::TaskText::new(task.into()),
        grants: vec!["harness.fs.read".into(), "harness.edit.replace".into()],
        workspace_public: false,
        exec: None,
        presubmit: None,
        protected: Vec::new(),
        kind: harness_run::SessionKind::Coding,
    }
}

fn policy(deny: serde_json::Value, allow: serde_json::Value) -> UserPolicy {
    UserPolicy::from_json(&json!({"deny": deny, "ask": [], "allow": allow})).unwrap()
}

#[test]
fn audit_recomputes_matcher_decisions() {
    // The allow rule names `src/**` and documents itself with an example.
    let p = policy(
        json!([]),
        json!([{
            "capability": "harness.edit.replace",
            "match": {"path_glob": "src/**"},
            "examples": [
                {"args": {"path": "src/a.rs"}, "expect": "match"},
                {"args": {"path": "docs/b.md"}, "expect": "not_match"}
            ]
        }]),
    );
    let fx = Fixture::with_spec(
        "matcher-audit-allow",
        edit_spec("Fix the typo in src/a.rs."),
    )
    .unwrap();
    fx.write("src/a.rs", "hello\n").unwrap();
    fx.write("docs/b.md", "docs\n").unwrap();
    let report = run_scripted_policy(
        &fx,
        &p,
        vec![
            act("harness.fs.read", r#"{"path":"src/a.rs"}"#),
            act(
                "harness.edit.replace",
                r#"{"path":"src/a.rs","old":"hello","new":"goodbye"}"#,
            ),
            submit(),
        ],
    )
    .unwrap();
    // The matcher allowed the edit with no approver present.
    assert_eq!(
        std::fs::read_to_string(fx.workspace().join("src/a.rs")).unwrap(),
        "goodbye\n"
    );
    assert_eq!(
        std::fs::read_to_string(fx.workspace().join("docs/b.md")).unwrap(),
        "docs\n"
    );
    // The replay recomputes the matched Allow under the SAME policy.
    assert_audit_clean_policy(&fx, &p, &report).unwrap();
    // A different policy is refused on the header digest, before any
    // decision is compared: the default policy is not this run's policy.
    assert!(assert_audit_clean(&fx, &report).is_err());
}

#[test]
fn a_deny_matcher_denies_through_the_real_run_and_audits_clean() {
    let p = policy(
        json!([{
            "capability": "harness.edit.replace",
            "match": {"path_glob": "secrets/**"}
        }]),
        json!([{"capability": "harness.edit.replace", "match": {"path_glob": "**"}}]),
    );
    let fx = Fixture::with_spec(
        "matcher-audit-deny",
        edit_spec("Try to edit secrets/k.env."),
    )
    .unwrap();
    fx.write("secrets/k.env", "key=1\n").unwrap();
    fx.write("src/a.rs", "code\n").unwrap();
    let report = run_scripted_policy(
        &fx,
        &p,
        vec![
            act("harness.fs.read", r#"{"path":"secrets/k.env"}"#),
            act(
                "harness.edit.replace",
                r#"{"path":"secrets/k.env","old":"key=1","new":"key=2"}"#,
            ),
            act("harness.fs.read", r#"{"path":"src/a.rs"}"#),
            act(
                "harness.edit.replace",
                r#"{"path":"src/a.rs","old":"code","new":"CODE"}"#,
            ),
            submit(),
        ],
    )
    .unwrap();
    // The deny matcher beat the broad allow on secrets/ and only there.
    assert_eq!(
        std::fs::read_to_string(fx.workspace().join("secrets/k.env")).unwrap(),
        "key=1\n"
    );
    assert_eq!(
        std::fs::read_to_string(fx.workspace().join("src/a.rs")).unwrap(),
        "CODE\n"
    );
    assert_audit_clean_policy(&fx, &p, &report).unwrap();
}
