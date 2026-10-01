//! Policy tests. Invariant tests are named `inv_<n>_…`.

use super::*;
use harness_manifest::admission::Tier;
use harness_manifest::{builtin, Manifest, SemVer, ValidationContext};
use serde_json::json;

const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ctx() -> ValidationContext {
    ValidationContext::new(
        SemVer {
            major: 0,
            minor: 0,
            patch: 1,
        },
        &[],
    )
    .unwrap()
}

fn builtin_registry() -> Registry {
    Registry::admit(vec![(builtin::manifest(&ctx()).unwrap(), Tier::Builtin)]).unwrap()
}

fn ws() -> Option<WorkspaceDecl> {
    Some(WorkspaceDecl::default())
}

fn spec(grants: &[&str]) -> SessionSpec {
    SessionSpec {
        grants: grants.iter().map(|g| (*g).to_owned()).collect(),
        workspace: ws(),
        approver_present: false,
        personal_data_granted: false,
        conformed: false,
        exec_programs: Vec::new(),
    }
}

fn read_all() -> Session {
    Session::plan(
        &spec(&["harness.fs.read", "harness.fs.search", "harness.fs.list"]),
        &builtin_registry(),
        &UserPolicy::default(),
    )
    .unwrap()
}

fn call(cap: &str, args: Value) -> Call {
    Call {
        capability: cap.to_owned(),
        args,
    }
}

/// One capability JSON for an external fixture manifest.
fn cap_json(verb: &str, dims: [&str; 6]) -> Value {
    let [effect, sensitivity, blast_radius, egress, content, confirmation] = dims;
    json!({
        "id": format!("fixture.{verb}"),
        "mcp_name": verb,
        "summary": "fixture capability",
        "effect": effect, "sensitivity": sensitivity, "blast_radius": blast_radius,
        "egress": egress, "content": content, "confirmation": confirmation,
        "input_schema": {"type": "object", "additionalProperties": false, "properties": {}},
        "schema_sha256": PIN, "description_sha256": PIN
    })
}

fn fixture(caps: Vec<Value>) -> Manifest {
    let m = json!({
        "schema_version": 1, "provider": "fixture", "provider_version": "1",
        "min_harness": "0.0.1",
        "transport": {"kind": "mcp-stdio", "argv": ["/opt/fixture/server"], "env_allow": []},
        "mcp_protocols": ["2025-06-18"],
        "capabilities": caps
    });
    Manifest::parse(m.to_string().as_bytes(), &ctx()).unwrap()
}

const READ_OWN: [&str; 6] = ["read", "operational", "own", "none", "own", "none"];

/// Plan over parsed manifests the H1 admission gate would refuse (test-only
/// private seam), so every dimension reaches the decision order.
fn plan_over(
    ms: &[Manifest],
    spec: &SessionSpec,
    policy: &UserPolicy,
) -> Result<Session, SessionRefused> {
    Session::plan_with(spec, policy, &|g| {
        let hits: Vec<&Capability> = ms
            .iter()
            .flat_map(|m| m.capabilities())
            .filter(|c| c.id().as_str() == g)
            .collect();
        match hits.as_slice() {
            [one] => Lookup::One(one),
            [] => Lookup::NotFound,
            _ => Lookup::Ambiguous,
        }
    })
}

fn is_deny(d: &PolicyDecision, want: &DenyReason) -> bool {
    matches!(d, PolicyDecision::Deny { reason, .. } if reason == want)
}

// ---- the happy path, and its rule id -------------------------------------------

#[test]
fn builtin_reads_inside_the_workspace_are_allowed_with_a_rule_id() {
    let s = read_all();
    for (cap, args) in [
        (
            "harness.fs.read",
            json!({"path": "src/lib.rs", "start": 1, "lines": 100}),
        ),
        ("harness.fs.search", json!({"pattern": "fn main"})),
        ("harness.fs.search", json!({"pattern": "x", "path": "src"})),
        ("harness.fs.list", json!({"path": ".", "depth": 2})),
    ] {
        let d = s.decide(&call(cap, args.clone()));
        assert_eq!(
            d,
            PolicyDecision::Allow {
                rule: RuleId::Builtin("allow.default.read")
            },
            "{cap} {args}"
        );
        let a = s.authorize(call(cap, args)).unwrap();
        assert_eq!(a.rule(), RuleId::Builtin("allow.default.read"));
        assert_eq!(a.call().capability, cap);
    }
}

// ---- fail-closed: unknown capability, unknown class, ambiguity -----------------

#[test]
fn unknown_or_ungranted_capabilities_are_denied() {
    let s = Session::plan(
        &spec(&["harness.fs.read"]),
        &builtin_registry(),
        &UserPolicy::default(),
    )
    .unwrap();
    for cap in [
        "harness.fs.list",  // admitted, not granted
        "harness.fs.write", // not a capability at all
        "Harness.fs.read",  // case variant
        "harness.fs.read ", // trailing space
        "",
        "fixture.item.read",
    ] {
        let d = s.decide(&call(cap, json!({"path": "a"})));
        assert!(is_deny(&d, &DenyReason::NotGranted), "{cap:?}: {d:?}");
        assert!(s.authorize(call(cap, json!({"path": "a"}))).is_err());
    }
}

#[test]
fn planning_refuses_unknown_duplicate_and_workspace_less_grants() {
    let r = builtin_registry();
    let p = UserPolicy::default();
    assert_eq!(
        Session::plan(&spec(&["harness.fs.write"]), &r, &p).unwrap_err(),
        SessionRefused::UnknownCapability("harness.fs.write".into())
    );
    assert_eq!(
        Session::plan(&spec(&["harness.fs.read", "harness.fs.read"]), &r, &p).unwrap_err(),
        SessionRefused::DuplicateGrant("harness.fs.read".into())
    );
    let mut no_ws = spec(&["harness.fs.read"]);
    no_ws.workspace = None;
    assert_eq!(
        Session::plan(&no_ws, &r, &p).unwrap_err(),
        SessionRefused::NoWorkspace("harness.fs.read".into())
    );
    // An empty grant list is a session with no tools, not an error.
    assert!(Session::plan(&spec(&[]), &r, &p).is_ok());
}

#[test]
fn ambiguous_lookup_is_refused_not_resolved() {
    let a = fixture(vec![cap_json("item.read", READ_OWN)]);
    let b = fixture(vec![cap_json("item.read", READ_OWN)]);
    assert_eq!(
        plan_over(
            &[a, b],
            &spec(&["fixture.item.read"]),
            &UserPolicy::default()
        )
        .unwrap_err(),
        SessionRefused::Ambiguous("fixture.item.read".into())
    );
}

#[test]
fn classes_this_slice_does_not_decide_are_refused_at_planning() {
    for (verb, dims, what) in [
        (
            "w",
            ["write", "operational", "own", "none", "own", "none"],
            "a non-read effect class",
        ),
        (
            "x",
            ["execute", "operational", "own", "none", "own", "none"],
            "a non-read effect class",
        ),
        (
            "i",
            ["irreversible", "public", "own", "none", "own", "none"],
            "a non-read effect class",
        ),
        (
            "e",
            ["read", "public", "own", "lan", "own", "none"],
            "egress (the allowlist proxy is H4)",
        ),
    ] {
        let m = fixture(vec![cap_json(verb, dims)]);
        let mut sp = spec(&[&format!("fixture.{verb}")]);
        sp.workspace = None; // keep the trifecta out of the way
        assert_eq!(
            plan_over(&[m], &sp, &UserPolicy::default()).unwrap_err(),
            SessionRefused::OutOfScope {
                capability: format!("fixture.{verb}"),
                what
            },
            "{verb}"
        );
    }
}

/// A session built directly (in-crate only), bypassing planning, to show the
/// DECISION order is fail-closed on its own (defence in depth).
fn raw_session(c: &Capability, allow_idx: Option<usize>) -> Session {
    let mut active = BTreeMap::new();
    active.insert(
        c.id().clone(),
        Active {
            class: effective_class(c, Confirmation::None),
            schema: c.input_schema().clone(),
            user_deny: None,
            user_ask: None,
            user_allow: allow_idx,
            fs_tool: false,
            submit: false,
            edit: false,
            exec: false,
        },
    );
    Session {
        active,
        quarantined: BTreeSet::new(),
        approver_present: true,
        personal_granted: true,
        conformed: false,
        exec_programs: BTreeSet::new(),
    }
}

#[test]
fn deny_rules_cannot_be_overridden_by_a_user_allow() {
    for (verb, dims, want) in [
        (
            "w",
            ["write", "public", "own", "none", "own", "none"],
            DenyReason::ClassOutOfScope(Effect::Write),
        ),
        (
            "x",
            ["execute", "public", "own", "none", "own", "none"],
            DenyReason::ClassOutOfScope(Effect::Execute),
        ),
        (
            "r",
            ["read", "restricted", "own", "none", "own", "none"],
            DenyReason::Restricted,
        ),
        (
            "e",
            ["read", "public", "own", "internet", "own", "none"],
            DenyReason::EgressUnavailable,
        ),
    ] {
        let m = fixture(vec![cap_json(verb, dims)]);
        let s = raw_session(&m.capabilities()[0], Some(0));
        let d = s.decide(&call(&format!("fixture.{verb}"), json!({})));
        assert!(is_deny(&d, &want), "{verb}: {d:?}");
    }
}

// ---- INV-27: restricted --------------------------------------------------------

#[test]
fn inv_27_restricted_capability_refuses_the_session() {
    let m = fixture(vec![
        cap_json("r", ["read", "restricted", "own", "none", "own", "none"]),
        // With a third-party egress capability too: restricted is named first.
        cap_json(
            "t",
            ["read", "public", "own", "internet", "third_party", "none"],
        ),
    ]);
    for (approver, personal) in [(false, false), (true, true)] {
        let mut sp = spec(&["fixture.t", "fixture.r"]);
        sp.approver_present = approver;
        sp.personal_data_granted = personal;
        assert_eq!(
            plan_over(std::slice::from_ref(&m), &sp, &UserPolicy::default()).unwrap_err(),
            SessionRefused::Restricted("fixture.r".into())
        );
    }
}

// ---- INV-9 (pure half): the trifecta --------------------------------------------

#[test]
fn inv_9_trifecta_is_refused_naming_one_source_per_label() {
    let m = fixture(vec![
        cap_json("p", ["read", "personal", "own", "none", "own", "none"]),
        cap_json(
            "u",
            ["read", "public", "own", "none", "third_party", "none"],
        ),
        cap_json("e", ["read", "public", "own", "lan", "own", "none"]),
    ]);
    let mut sp = spec(&["fixture.p", "fixture.u", "fixture.e"]);
    sp.workspace = None;
    assert_eq!(
        plan_over(std::slice::from_ref(&m), &sp, &UserPolicy::default()).unwrap_err(),
        SessionRefused::Trifecta {
            private: "fixture.p".into(),
            untrusted: "fixture.u".into(),
            egress: "fixture.e".into()
        }
    );
    // The workspace alone supplies P and U (private and third-party by default).
    let mut sp = spec(&["fixture.e"]);
    sp.workspace = ws();
    assert_eq!(
        plan_over(std::slice::from_ref(&m), &sp, &UserPolicy::default()).unwrap_err(),
        SessionRefused::Trifecta {
            private: "workspace".into(),
            untrusted: "workspace".into(),
            egress: "fixture.e".into()
        }
    );
    // Declaring the workspace public removes P: no trifecta (egress is then
    // refused for this slice's own reason).
    sp.workspace = Some(WorkspaceDecl {
        declared_public: true,
    });
    assert!(matches!(
        plan_over(std::slice::from_ref(&m), &sp, &UserPolicy::default()).unwrap_err(),
        SessionRefused::OutOfScope { .. }
    ));
    // Any two labels without the third: allowed by the trifecta rule.
    let mut sp = spec(&["fixture.p", "fixture.u"]);
    sp.workspace = None;
    assert!(plan_over(std::slice::from_ref(&m), &sp, &UserPolicy::default()).is_ok());
}

// ---- ask rules, approvers, personal data ---------------------------------------

#[test]
fn personal_data_asks_only_when_granted_and_denies_without_an_approver() {
    let m = fixture(vec![cap_json(
        "p",
        ["read", "personal", "own", "none", "own", "none"],
    )]);
    let run = |approver, personal| {
        let mut sp = spec(&["fixture.p"]);
        sp.workspace = None;
        sp.approver_present = approver;
        sp.personal_data_granted = personal;
        let s = plan_over(std::slice::from_ref(&m), &sp, &UserPolicy::default()).unwrap();
        s.decide(&call("fixture.p", json!({})))
    };
    assert!(is_deny(&run(true, false), &DenyReason::PersonalNotGranted));
    assert!(is_deny(&run(false, true), &DenyReason::NoApprover));
    assert_eq!(
        run(true, true),
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::Builtin("ask.confirmation-floor")
        }
    );
}

#[test]
fn an_ask_never_mints_authorized_without_a_redeemed_token() {
    let m = fixture(vec![cap_json(
        "p",
        ["read", "personal", "own", "none", "own", "none"],
    )]);
    let mut sp = spec(&["fixture.p"]);
    sp.workspace = None;
    sp.approver_present = true;
    sp.personal_data_granted = true;
    let s = plan_over(std::slice::from_ref(&m), &sp, &UserPolicy::default()).unwrap();
    assert!(matches!(
        s.authorize(call("fixture.p", json!({}))),
        Err(PolicyDecision::Ask { .. })
    ));
}

#[test]
fn user_rules_follow_the_decision_order() {
    let r = builtin_registry();
    let grants = spec(&["harness.fs.read", "harness.fs.search"]);
    let args = json!({"path": "a"});

    // A user deny beats the default allow.
    let p = UserPolicy::new(&["harness.fs.read"], &[], &[]).unwrap();
    let s = Session::plan(&grants, &r, &p).unwrap();
    assert_eq!(
        s.decide(&call("harness.fs.read", args.clone())),
        PolicyDecision::Deny {
            reason: DenyReason::UserDenied,
            rule: RuleId::User {
                list: RuleList::Deny,
                index: 0
            }
        }
    );
    // A provider-wide deny beats a capability allow.
    let p = UserPolicy::new(&["harness.*"], &[], &["harness.fs.read"]).unwrap();
    let s = Session::plan(&grants, &r, &p).unwrap();
    assert!(is_deny(
        &s.decide(&call("harness.fs.read", args.clone())),
        &DenyReason::UserDenied
    ));

    // A user ask raises the floor (max-rule); without an approver it denies.
    let p = UserPolicy::new(&[], &["harness.fs.search"], &[]).unwrap();
    let s = Session::plan(&grants, &r, &p).unwrap();
    assert_eq!(
        s.class("harness.fs.search").unwrap().confirmation,
        Confirmation::UserConfirm
    );
    assert!(is_deny(
        &s.decide(&call("harness.fs.search", json!({"pattern": "x"}))),
        &DenyReason::NoApprover
    ));
    let mut with_approver = grants.clone();
    with_approver.approver_present = true;
    let s = Session::plan(&with_approver, &r, &p).unwrap();
    assert_eq!(
        s.decide(&call("harness.fs.search", json!({"pattern": "x"}))),
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::User {
                list: RuleList::Ask,
                index: 0
            }
        }
    );

    // A user allow cannot lower a derived floor.
    let m = fixture(vec![cap_json(
        "p",
        ["read", "personal", "own", "none", "own", "none"],
    )]);
    let p = UserPolicy::new(&[], &[], &["fixture.p"]).unwrap();
    let mut sp = spec(&["fixture.p"]);
    sp.workspace = None;
    sp.approver_present = true;
    sp.personal_data_granted = true;
    let s = plan_over(std::slice::from_ref(&m), &sp, &p).unwrap();
    assert!(matches!(
        s.decide(&call("fixture.p", json!({}))),
        PolicyDecision::Ask { .. }
    ));
}

#[test]
fn ambiguous_or_malformed_user_policy_is_refused() {
    assert!(matches!(
        UserPolicy::new(&["harness.fs.read"], &[], &["harness.fs.read"]),
        Err(PolicyConfigError::Ambiguous(_))
    ));
    assert!(matches!(
        UserPolicy::new(&["harness.*", "harness.*"], &[], &[]),
        Err(PolicyConfigError::Ambiguous(_))
    ));
    for bad in [
        "*",
        "harness",
        "Harness.fs.read",
        "harness.fs.*.x",
        ".*",
        "harness..x",
    ] {
        assert!(
            matches!(
                UserPolicy::new(&[bad], &[], &[]),
                Err(PolicyConfigError::BadSelector(_))
            ),
            "{bad}"
        );
    }
}

// ---- arguments and paths --------------------------------------------------------

#[test]
fn arguments_outside_the_schema_are_denied() {
    let s = read_all();
    for (cap, args) in [
        ("harness.fs.read", json!({})),
        ("harness.fs.read", json!({"path": "a", "mode": "w"})),
        ("harness.fs.read", json!({"path": "a", "lines": 101})),
        ("harness.fs.read", json!({"path": 7})),
        ("harness.fs.search", json!({"path": "a"})),
        ("harness.fs.list", json!("a")),
    ] {
        let d = s.decide(&call(cap, args.clone()));
        assert!(
            matches!(
                d,
                PolicyDecision::Deny {
                    reason: DenyReason::Args(_),
                    ..
                }
            ),
            "{cap} {args}: {d:?}"
        );
    }
}

#[test]
fn inv_30_builtin_reads_cannot_name_a_path_outside_the_workspace() {
    let s = read_all();
    for p in [
        "CON",
        "nul",
        "NUL.txt",
        "COM1",
        "LPT1.log",
        "a/aux.c",
        "CONIN$",
        "/etc/passwd",
        "../x",
        "a/../../x",
        "C:/x",
        "..\\x",
        "a//b",
        "",
        "\\\\host\\share",
    ] {
        for (cap, args) in [
            ("harness.fs.read", json!({"path": p})),
            ("harness.fs.list", json!({"path": p})),
            ("harness.fs.search", json!({"pattern": "x", "path": p})),
        ] {
            let d = s.decide(&call(cap, args));
            assert!(
                matches!(
                    d,
                    PolicyDecision::Deny {
                        reason: DenyReason::Path(_),
                        rule: RuleId::Builtin("deny.path-outside-workspace")
                    }
                ),
                "{cap} {p:?}: {d:?}"
            );
        }
    }
}

#[test]
fn quarantined_capabilities_are_denied() {
    let mut s = read_all();
    s.quarantine(&CapId::new("harness.fs.read").unwrap());
    assert!(is_deny(
        &s.decide(&call("harness.fs.read", json!({"path": "a"}))),
        &DenyReason::Quarantined
    ));
}

#[test]
fn decisions_are_deterministic() {
    let s = read_all();
    let c = call("harness.fs.read", json!({"path": "src/lib.rs"}));
    assert_eq!(s.decide(&c), s.decide(&c));
    assert_eq!(s.decide(&c), read_all().decide(&c));
}

// ---- INV-25 (pure max-rule): effective ≥ max(declared, derived, user) ----------

#[test]
fn inv_25_effective_confirmation_is_never_below_any_floor() {
    let effects = ["read", "write", "execute", "irreversible"];
    let sens = ["public", "operational", "personal", "restricted"];
    let blasts = ["own", "host", "shared"];
    let egresses = ["none", "lan", "internet"];
    let contents = ["own", "third_party"];
    let confs = ["none", "user_confirm", "protected_action"];
    let mut caps = Vec::new();
    let mut n = 0;
    for e in effects {
        for s in sens {
            for b in blasts {
                for g in egresses {
                    for c in contents {
                        for f in confs {
                            caps.push(cap_json(&format!("c{n}"), [e, s, b, g, c, f]));
                            n += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(n, 864);
    let m = fixture(caps);
    let users = [
        Confirmation::None,
        Confirmation::UserConfirm,
        Confirmation::ProtectedAction,
    ];
    for c in m.capabilities() {
        for user in users {
            let cl = effective_class(c, user);
            assert!(cl.confirmation >= c.confirmation(), "{}", c.id());
            assert!(cl.confirmation >= derived_floor(c), "{}", c.id());
            assert!(cl.confirmation >= user, "{}", c.id());
            if c.effect() == Effect::Irreversible || c.blast_radius() == BlastRadius::Shared {
                assert_eq!(cl.confirmation, Confirmation::ProtectedAction, "{}", c.id());
            }
            if c.egress() == Egress::Internet || c.sensitivity() >= Sensitivity::Personal {
                assert!(cl.confirmation >= Confirmation::UserConfirm, "{}", c.id());
            }
            assert_eq!(
                cl.requires_conformed,
                c.effect() >= Effect::Execute,
                "{}",
                c.id()
            );
        }
    }
}

// H1c review F-7: the digest is computed from the authorised call itself.
#[test]
fn the_call_digest_is_computed_from_the_authorised_call() {
    use harness_core::CallDigest;
    let s = read_all();
    let a = s
        .authorize(call("harness.fs.read", json!({"path": "a", "lines": 5})))
        .unwrap();
    let b = s
        .authorize(call("harness.fs.read", json!({"lines": 5, "path": "a"})))
        .unwrap();
    let c = s
        .authorize(call("harness.fs.read", json!({"path": "b", "lines": 5})))
        .unwrap();
    assert_eq!(a.call_digest(), b.call_digest(), "key order is canonical");
    assert_ne!(
        a.call_digest(),
        c.call_digest(),
        "different arguments, different digest"
    );
    assert_eq!(
        a.call_digest(),
        harness_core::sha256(br#"{"args":{"lines":5,"path":"a"},"capability":"harness.fs.read"}"#)
    );
}

// ---- the submit sentinel (§2.5, H1e-2) ------------------------------------------

#[test]
fn the_submit_sentinel_is_allowed_by_its_own_rule_and_nothing_else_is() {
    let r = builtin_registry();
    let mut sp = spec(&["harness.task.submit"]);
    // Not a file tool: it needs no workspace.
    sp.workspace = None;
    let s = Session::plan(&sp, &r, &UserPolicy::default()).unwrap();
    let ok = call("harness.task.submit", json!({"note": "done"}));
    assert_eq!(
        s.decide(&ok),
        PolicyDecision::Allow {
            rule: RuleId::Builtin("allow.task-submit")
        }
    );
    assert_eq!(
        s.authorize(ok).unwrap().rule(),
        RuleId::Builtin("allow.task-submit")
    );
    // Its arguments are schema-checked like any other call.
    for bad in [
        json!({}),
        json!({"note": 1}),
        json!({"note": "x", "extra": true}),
        json!({"note": "x".repeat(2001)}),
    ] {
        let d = s.decide(&call("harness.task.submit", bad.clone()));
        assert!(
            matches!(
                d,
                PolicyDecision::Deny {
                    reason: DenyReason::Args(_),
                    ..
                }
            ),
            "{bad}: {d:?}"
        );
    }
}

#[test]
fn a_user_deny_still_beats_the_submit_rule() {
    let p = UserPolicy::new(&["harness.task.submit"], &[], &[]).unwrap();
    let s = Session::plan(&spec(&["harness.task.submit"]), &builtin_registry(), &p).unwrap();
    let d = s.decide(&call("harness.task.submit", json!({"note": "x"})));
    assert!(is_deny(&d, &DenyReason::UserDenied), "{d:?}");
}

#[test]
fn a_write_capability_that_merely_looks_like_submit_stays_out_of_scope() {
    // Same verb, other provider: not the sentinel, so its write class is
    // refused at planning like every other write.
    let m = fixture(vec![cap_json(
        "task.submit",
        ["write", "public", "own", "none", "own", "none"],
    )]);
    let err = plan_over(
        &[m],
        &spec(&["fixture.task.submit"]),
        &UserPolicy::default(),
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            SessionRefused::OutOfScope {
                what: "a non-read effect class",
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn the_policy_digest_distinguishes_lists_and_order() {
    let a = UserPolicy::new(&["fixture.a"], &[], &[]).unwrap();
    let b = UserPolicy::new(&[], &[], &["fixture.a"]).unwrap();
    let c = UserPolicy::new(&["fixture.a", "fixture.*"], &[], &[]).unwrap();
    let d = UserPolicy::new(&["fixture.*", "fixture.a"], &[], &[]).unwrap();
    assert_eq!(
        a.digest(),
        UserPolicy::new(&["fixture.a"], &[], &[]).unwrap().digest()
    );
    assert_ne!(a.digest(), b.digest());
    assert_ne!(c.digest(), d.digest(), "order matters: first match wins");
    assert_ne!(UserPolicy::default().digest(), a.digest());
}

// ---- §5.3 approval tokens: INV-5 and INV-16 --------------------------------------
//
// Session-level half: a session over a personal-data read (ask floor
// user_confirm) with an approver present. The token mechanics (MAC flips,
// TTL boundary, cross-run, scope) are exercised against the authority in
// `approval.rs`; here the laws are about what the SESSION mints.

use crate::approval::{
    ApprovalAuthority, ApprovalRequest, ApprovalScope, BoundCall, MintRequest, PrincipalId, StepId,
    APPROVAL_TTL,
};
use std::time::Duration;

/// The ask-session fixture: `fixture.p` (personal read, one `path`
/// argument) with an approver present and personal data granted, so
/// `decide` is `Ask(user_confirm)` and `{"path": ...}` calls validate.
fn ask_session() -> Session {
    let mut cap = cap_json("p", ["read", "personal", "own", "none", "own", "none"]);
    cap["input_schema"]["properties"]["path"] = json!({"type": "string"});
    let m = fixture(vec![cap]);
    let mut sp = spec(&["fixture.p"]);
    sp.workspace = None;
    sp.approver_present = true;
    sp.personal_data_granted = true;
    plan_over(std::slice::from_ref(&m), &sp, &UserPolicy::default()).unwrap()
}

fn ask_call() -> Call {
    call("fixture.p", json!({"path": "a"}))
}

fn ask_bound() -> BoundCall {
    BoundCall::for_call(1, StepId::new(3), &ask_call(), Confirmation::UserConfirm).unwrap()
}

fn mint_req(bound: &BoundCall, scope: ApprovalScope) -> MintRequest {
    MintRequest {
        attempt: bound.attempt,
        step: bound.step,
        capability: bound.capability.clone(),
        args_sha256: bound.args_sha256,
        tier: bound.tier,
        scope,
        approver: PrincipalId::new("cli").unwrap(),
    }
}

fn minted(
    bound: &BoundCall,
    scope: ApprovalScope,
    nonce: [u8; 16],
) -> (ApprovalAuthority, crate::approval::Approval) {
    let mut a = ApprovalAuthority::new(harness_core::RunId::new(1_000, [3; 10]), [0x11; 32]);
    let t = a
        .mint(&mint_req(bound, scope), nonce, Duration::from_secs(1_000))
        .unwrap();
    (a, t)
}

#[test]
fn inv_5_an_ask_without_any_approval_refuses_every_time() {
    let s = ask_session();
    // No token at all: an Ask is never minted, however often asked.
    for _ in 0..3 {
        assert!(matches!(
            s.authorize(ask_call()),
            Err(PolicyDecision::Ask { .. })
        ));
    }
}

#[test]
fn inv_5_an_approval_for_different_args_refuses() {
    let s = ask_session();
    let bound = ask_bound();
    let (mut a, t) = minted(&bound, ApprovalScope::Once, [0x22; 16]);
    // Redeem layer: the token's digest is for other arguments.
    let other = call("fixture.p", json!({"path": "b"}));
    let other_bound =
        BoundCall::for_call(1, StepId::new(3), &other, Confirmation::UserConfirm).unwrap();
    assert_eq!(
        a.redeem(&t, &other_bound, Duration::from_secs(1_000)),
        Err(crate::approval::ApprovalRefused::ArgsMismatch)
    );
    // Mint layer: nothing new for the other args; authorize layer: a proof
    // redeemed for THIS call's binding never covers different arguments.
    let redeemed = a.redeem(&t, &bound, Duration::from_secs(1_001)).unwrap();
    assert!(matches!(
        s.authorize_approved(other, redeemed),
        Err(PolicyDecision::Ask { .. })
    ));
}

#[test]
fn inv_5_an_expired_approval_refuses() {
    let bound = ask_bound();
    let (mut a, t) = minted(&bound, ApprovalScope::Once, [0x33; 16]);
    assert_eq!(
        a.redeem(&t, &bound, Duration::from_secs(1_000) + APPROVAL_TTL),
        Err(crate::approval::ApprovalRefused::Expired)
    );
    // No redemption means nothing to show the session: fail closed.
    let s = ask_session();
    assert!(matches!(
        s.authorize(ask_call()),
        Err(PolicyDecision::Ask { .. })
    ));
}

#[test]
fn inv_5_a_reused_approval_refuses() {
    let s = ask_session();
    let bound = ask_bound();
    let (mut a, t) = minted(&bound, ApprovalScope::Once, [0x44; 16]);
    let redeemed = a.redeem(&t, &bound, Duration::from_secs(1_000)).unwrap();
    // The first spend mints the Authorized call...
    assert!(s.authorize_approved(ask_call(), redeemed).is_ok());
    // ...and the token is dead: a replayed redemption refuses, so nothing
    // can ever be minted from it again.
    assert_eq!(
        a.redeem(&t, &bound, Duration::from_secs(1_001)),
        Err(crate::approval::ApprovalRefused::NonceReused)
    );
}

#[test]
fn an_ask_plus_a_matching_token_mints_exactly_this_call() {
    let s = ask_session();
    let bound = ask_bound();
    let (mut a, t) = minted(&bound, ApprovalScope::Once, [0x55; 16]);
    let redeemed = a.redeem(&t, &bound, Duration::from_secs(1_000)).unwrap();
    let authorized = s.authorize_approved(ask_call(), redeemed).unwrap();
    assert_eq!(authorized.call().capability, "fixture.p");
    // The Ask's rule id is what authorised it (journaled with the intent).
    assert_eq!(authorized.rule(), RuleId::Builtin("ask.confirmation-floor"));
}

#[test]
fn an_approval_for_another_tier_or_a_denied_call_never_mints() {
    let s = ask_session();
    // Tier: a protected_action token for the same call does not satisfy a
    // user_confirm ask (and vice versa).
    let bound_pa = BoundCall::for_call(
        1,
        StepId::new(3),
        &ask_call(),
        Confirmation::ProtectedAction,
    )
    .unwrap();
    let (mut a, t) = minted(&bound_pa, ApprovalScope::Once, [0x66; 16]);
    let redeemed = a.redeem(&t, &bound_pa, Duration::from_secs(1_000)).unwrap();
    assert!(matches!(
        s.authorize_approved(ask_call(), redeemed),
        Err(PolicyDecision::Ask { .. })
    ));
    // A Deny decision passes through untouched: no approval can un-deny.
    let (mut a2, t2) = minted(&ask_bound(), ApprovalScope::Once, [0x67; 16]);
    let r2 = a2
        .redeem(&t2, &ask_bound(), Duration::from_secs(1_000))
        .unwrap();
    let denied = call("harness.fs.read", json!({"path": "a"})); // not granted here
    assert!(is_deny(
        &s.authorize_approved(denied, r2).unwrap_err(),
        &DenyReason::NotGranted
    ));
}

#[test]
fn a_run_scoped_approval_covers_identical_calls_only() {
    let s = ask_session();
    let bound = ask_bound();
    let (mut a, t) = minted(&bound, ApprovalScope::Run, [0x77; 16]);
    // Same capability, same arg digest: redeems and re-mints.
    let first = a.redeem(&t, &bound, Duration::from_secs(1_000)).unwrap();
    assert!(s.authorize_approved(ask_call(), first).is_ok());
    let second = a.redeem(&t, &bound, Duration::from_secs(1_001)).unwrap();
    assert!(s.authorize_approved(ask_call(), second).is_ok());
    // Different arguments: the authority refuses, and the session was
    // never even asked with a proof for them.
    let other = call("fixture.p", json!({"path": "b"}));
    let other_bound =
        BoundCall::for_call(1, StepId::new(3), &other, Confirmation::UserConfirm).unwrap();
    assert_eq!(
        a.redeem(&t, &other_bound, Duration::from_secs(1_002)),
        Err(crate::approval::ApprovalRefused::ArgsMismatch)
    );
}

#[test]
fn the_approval_request_shows_the_class_the_args_and_the_step() {
    let m = fixture(vec![cap_json(
        "p",
        ["read", "personal", "own", "none", "own", "none"],
    )]);
    let cap = &m.capabilities()[0];
    let req = ApprovalRequest::new(
        cap.id().clone(),
        "fixture capability".into(),
        effective_class(cap, Confirmation::None),
        json!({"path": "a"}),
        Confirmation::UserConfirm,
        1,
        StepId::new(3),
    );
    assert_eq!(req.tier(), Confirmation::UserConfirm); // derived floor
    assert_eq!(req.step().get(), 3);
    let shown = req.to_string();
    assert!(shown.contains("fixture.p"), "{shown}");
    assert!(shown.contains("personal data"), "{shown}");
    assert!(shown.contains(r#""path":"a""#), "{shown}");
}

// ---- H2b: the built-in workspace edits ----------------------------------------

const EDIT_GRANTS: [&str; 3] = [
    "harness.fs.read",
    "harness.edit.replace",
    "harness.edit.write",
];

fn edit_session(approver: bool, policy: &UserPolicy) -> Session {
    let mut sp = spec(&EDIT_GRANTS);
    sp.approver_present = approver;
    Session::plan(&sp, &builtin_registry(), policy).unwrap()
}

fn replace(path: &str) -> Call {
    call(
        "harness.edit.replace",
        json!({"path": path, "old": "a", "new": "b"}),
    )
}

fn write(path: &str) -> Call {
    call(
        "harness.edit.write",
        json!({"path": path, "content": "fn main() {}\n"}),
    )
}

#[test]
fn h2b_edits_are_planned_only_with_a_workspace() {
    let s = edit_session(false, &UserPolicy::default());
    assert_eq!(
        s.class("harness.edit.replace").map(|c| c.effect),
        Some(Effect::Write)
    );
    for id in EDIT_IDS {
        let mut sp = spec(&[id]);
        sp.workspace = None;
        assert_eq!(
            Session::plan(&sp, &builtin_registry(), &UserPolicy::default()).unwrap_err(),
            SessionRefused::NoWorkspace(id.to_owned()),
            "{id}"
        );
    }
}

// §5.2 as H2b applies it: an edit in place asks, and with no approver the
// ask is a deny; the tier is user_confirm although the class declares none.
#[test]
fn h2b_an_edit_asks_by_default_and_is_denied_without_an_approver() {
    let with = edit_session(true, &UserPolicy::default());
    let without = edit_session(false, &UserPolicy::default());
    for c in [replace("src/lib.rs"), write("src/new.rs")] {
        assert_eq!(
            with.decide(&c),
            PolicyDecision::Ask {
                tier: Confirmation::UserConfirm,
                rule: RuleId::Builtin(EDIT_DEFAULT_RULE),
            },
            "{c:?}"
        );
        assert_eq!(
            without.decide(&c),
            PolicyDecision::Deny {
                reason: DenyReason::NoApprover,
                rule: RuleId::Builtin("deny.no-approver"),
            }
        );
        // Neither mints by itself.
        assert!(with.authorize(c.clone()).is_err());
        assert!(without.authorize(c).is_err());
    }
}

// A user allow rule is how an unattended run edits: it allows without an
// approver. A user deny still wins, and a user ask asks.
#[test]
fn h2b_user_policy_allows_denies_or_asks_for_edits() {
    let allow = UserPolicy::new(&[], &[], &["harness.edit.replace", "harness.edit.write"]).unwrap();
    let s = edit_session(false, &allow);
    assert_eq!(
        s.decide(&replace("src/lib.rs")),
        PolicyDecision::Allow {
            rule: RuleId::User {
                list: RuleList::Allow,
                index: 0
            }
        }
    );
    let a = s.authorize(write("docs/new.md")).unwrap();
    assert_eq!(
        a.rule(),
        RuleId::User {
            list: RuleList::Allow,
            index: 1
        }
    );
    let deny = UserPolicy::new(&["harness.edit.replace"], &[], &[]).unwrap();
    assert!(is_deny(
        &edit_session(true, &deny).decide(&replace("a.txt")),
        &DenyReason::UserDenied
    ));
    let ask = UserPolicy::new(&[], &["harness.edit.write"], &["harness.edit.replace"]).unwrap();
    let s = edit_session(true, &ask);
    assert_eq!(
        s.decide(&write("a.txt")),
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::User {
                list: RuleList::Ask,
                index: 0
            }
        }
    );
    assert!(matches!(
        s.decide(&replace("a.txt")),
        PolicyDecision::Allow { .. }
    ));
}

// The edit's path takes the workspace rule, and its arguments the schema,
// before any allow rule: an allowed edit outside the workspace is denied.
#[test]
fn h2b_an_edit_outside_the_workspace_or_off_schema_is_denied_even_when_allowed() {
    let allow = UserPolicy::new(&[], &[], &["harness.edit.replace"]).unwrap();
    let s = edit_session(true, &allow);
    for p in [
        "../etc/passwd",
        "/etc/passwd",
        "a/../../b",
        "C:\\x",
        ".git/../x",
    ] {
        assert!(
            matches!(
                s.decide(&replace(p)),
                PolicyDecision::Deny {
                    reason: DenyReason::Path(_),
                    ..
                }
            ),
            "{p}"
        );
    }
    for bad in [
        json!({"path": "a", "old": "x"}),
        json!({"path": "a", "old": "x", "new": "y", "count": 0}),
        json!({"path": "a", "old": "x", "new": "y", "extra": 1}),
    ] {
        assert!(
            matches!(
                s.decide(&call("harness.edit.replace", bad.clone())),
                PolicyDecision::Deny {
                    reason: DenyReason::Args(_),
                    ..
                }
            ),
            "{bad}"
        );
    }
}

// The approval path for an edit: the Ask's own tier binds the token, and
// the proof mints exactly the call it was redeemed for.
#[test]
fn h2b_an_approved_edit_mints_only_the_call_it_binds() {
    let s = edit_session(true, &UserPolicy::default());
    let c = replace("src/lib.rs");
    let d = s.decide(&c);
    assert!(
        matches!(
            d,
            PolicyDecision::Ask {
                tier: Confirmation::UserConfirm,
                ..
            }
        ),
        "{d:?}"
    );
    let bound = BoundCall::for_call(1, StepId::new(2), &c, Confirmation::UserConfirm).unwrap();
    let (mut a, t) = minted(&bound, ApprovalScope::Once, [0x42; 16]);
    let proof = a.redeem(&t, &bound, Duration::from_secs(1_000)).unwrap();
    // Another call with this proof stays an Ask; the right one mints.
    let other = replace("src/main.rs");
    let (mut a2, t2) = minted(&bound, ApprovalScope::Once, [0x43; 16]);
    let proof2 = a2.redeem(&t2, &bound, Duration::from_secs(1_000)).unwrap();
    assert!(matches!(
        s.authorize_approved(other, proof2),
        Err(PolicyDecision::Ask { .. })
    ));
    let ok = s.authorize_approved(c, proof).unwrap();
    assert_eq!(ok.rule(), RuleId::Builtin(EDIT_DEFAULT_RULE));
}

// §7.1 display paths: model-chosen arguments reach the approver escaped
// (no ANSI, bidi or zero-width character survives) and bounded.
#[test]
fn h2b_the_approval_request_escapes_and_bounds_the_arguments() {
    let m = builtin::manifest(&ctx()).unwrap();
    let capability = m
        .capabilities()
        .iter()
        .find(|c| c.id().as_str() == "harness.edit.write")
        .unwrap();
    let hostile = "\u{1b}[2K\rapproved: harmless\u{202e}txt.exe\u{200b}";
    let req = ApprovalRequest::new(
        capability.id().clone(),
        capability.summary().to_owned(),
        effective_class(capability, Confirmation::None),
        json!({"path": "a.txt", "content": hostile}),
        Confirmation::UserConfirm,
        1,
        StepId::new(4),
    );
    let shown = req.to_string();
    assert!(
        !shown
            .chars()
            .any(|c| c == '\u{1b}' || c == '\u{202e}' || c == '\u{200b}' || c == '\r'),
        "{shown:?}"
    );
    // JSON already writes the ESC and CR as `\u001b` and `\r` (escaped
    // again, reversibly); the bidi and zero-width characters JSON leaves raw
    // are escaped by the display rule.
    assert!(
        shown.contains("\\\\u001b") && shown.contains("\\\\r"),
        "{shown}"
    );
    assert!(
        shown.contains("\\u{202E}") && shown.contains("\\u{200B}"),
        "{shown}"
    );
    assert!(
        shown.contains("user_confirm") && shown.contains("step 4"),
        "{shown}"
    );
    let long = "x".repeat(10_000);
    let req = ApprovalRequest::new(
        capability.id().clone(),
        capability.summary().to_owned(),
        effective_class(capability, Confirmation::None),
        json!({"path": "a.txt", "content": long}),
        Confirmation::UserConfirm,
        1,
        StepId::new(4),
    );
    let shown = req.to_string();
    assert!(shown.len() < 5_000, "bounded: {} bytes", shown.len());
    assert!(
        shown.contains("more characters not shown; sha256 of the call"),
        "{shown}"
    );
}

// ---- H2d: the built-in command runner ------------------------------------------

const EXEC_GRANTS: [&str; 3] = ["harness.fs.read", "harness.edit.replace", EXEC_ID];

fn exec_spec(approver: bool, programs: &[&str]) -> SessionSpec {
    let mut sp = spec(&EXEC_GRANTS);
    sp.approver_present = approver;
    sp.conformed = true;
    sp.exec_programs = programs.iter().map(|p| (*p).to_owned()).collect();
    sp
}

fn exec_session(approver: bool, programs: &[&str], policy: &UserPolicy) -> Session {
    Session::plan(&exec_spec(approver, programs), &builtin_registry(), policy).unwrap()
}

fn run(argv: &[&str]) -> Call {
    call(EXEC_ID, json!({ "argv": argv }))
}

fn exec_allowed() -> UserPolicy {
    UserPolicy::new(&[], &[], &[EXEC_ID]).unwrap()
}

// INV-6 at planning: an execute-class grant needs the witness and a
// workspace; without the witness the session is refused before anything
// starts, never planned "read-only with exec switched off".
#[test]
fn h2d_exec_is_planned_only_with_a_workspace_and_a_conformed_sandbox() {
    let mut sp = exec_spec(true, &["cargo"]);
    sp.conformed = false;
    assert_eq!(
        Session::plan(&sp, &builtin_registry(), &UserPolicy::default()).unwrap_err(),
        SessionRefused::NoConfinement(EXEC_ID.to_owned())
    );
    let mut sp = exec_spec(true, &["cargo"]);
    sp.workspace = None;
    assert!(matches!(
        Session::plan(&sp, &builtin_registry(), &UserPolicy::default()).unwrap_err(),
        SessionRefused::NoWorkspace(_)
    ));
    let s = exec_session(true, &["cargo"], &UserPolicy::default());
    let class = s.class(EXEC_ID).unwrap();
    assert_eq!(class.effect, Effect::Execute);
    assert!(class.requires_conformed);
    assert!(s.conformed());
    // A session without the grant plans without the witness, as before.
    let mut sp = spec(&["harness.fs.read"]);
    sp.conformed = false;
    assert!(Session::plan(&sp, &builtin_registry(), &UserPolicy::default()).is_ok());
}

// Execute-class asks by default (H2d); with no approver the ask is a deny.
#[test]
fn h2d_a_command_asks_by_default_and_is_denied_without_an_approver() {
    let with = exec_session(true, &["cargo"], &UserPolicy::default());
    let without = exec_session(false, &["cargo"], &UserPolicy::default());
    let c = run(&["cargo", "test"]);
    assert_eq!(
        with.decide(&c),
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::Builtin(EXEC_DEFAULT_RULE),
        }
    );
    assert_eq!(
        without.decide(&c),
        PolicyDecision::Deny {
            reason: DenyReason::NoApprover,
            rule: RuleId::Builtin("deny.no-approver"),
        }
    );
    assert!(with.authorize(c.clone()).is_err());
    assert!(without.authorize(c).is_err());
    // A user allow rule is how an unattended run executes; a user deny wins
    // and a user ask asks under its own rule.
    let s = exec_session(false, &["cargo"], &exec_allowed());
    assert!(s.authorize(run(&["cargo", "test", "--offline"])).is_ok());
    let deny = UserPolicy::new(&[EXEC_ID], &[], &[]).unwrap();
    assert!(is_deny(
        &exec_session(true, &["cargo"], &deny).decide(&run(&["cargo", "test"])),
        &DenyReason::UserDenied
    ));
    let ask = UserPolicy::new(&[], &[EXEC_ID], &[]).unwrap();
    assert_eq!(
        exec_session(true, &["cargo"], &ask).decide(&run(&["cargo", "test"])),
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::User {
                list: RuleList::Ask,
                index: 0
            },
        }
    );
}

// INV-13: argv is resolved by NAME against the task's allowlist, before
// any allow rule. A shell, a path or anything else not on the list is
// denied; a shell the task allowlists explicitly is allowed like any
// program (its header stamps `shell_enabled`, harness-run).
#[test]
fn inv_13_argv_is_resolved_by_name_and_sh_c_is_refused_without_a_shell() {
    let s = exec_session(true, &["cargo"], &exec_allowed());
    let exec_deny = |c: &Call| match s.decide(c) {
        PolicyDecision::Deny {
            reason: DenyReason::Exec(e),
            ..
        } => Some(e),
        _ => None,
    };
    assert_eq!(
        exec_deny(&run(&["sh", "-c", "cargo test"])),
        Some(ExecRefused::NotAllowlisted)
    );
    for argv in [
        vec!["/bin/sh", "-c", "x"],
        vec!["bash", "-c", "x"],
        vec!["/usr/bin/cargo", "test"],
        vec!["./cargo"],
        vec!["cargo test"],
        vec!["Cargo"],
        vec![""],
    ] {
        assert_eq!(
            exec_deny(&run(&argv)),
            Some(ExecRefused::NotAllowlisted),
            "{argv:?}"
        );
    }
    assert_eq!(exec_deny(&run(&[])), Some(ExecRefused::EmptyArgv));
    assert_eq!(exec_deny(&run(&["cargo", "a\0b"])), Some(ExecRefused::Nul));
    let many: Vec<&str> = std::iter::once("cargo")
        .chain(std::iter::repeat_n("x", EXEC_MAX_ARGS))
        .collect();
    assert_eq!(exec_deny(&run(&many)), Some(ExecRefused::TooManyArgs));
    assert!(matches!(
        s.decide(&run(&["cargo", "test"])),
        PolicyDecision::Allow { .. }
    ));
    // The rule ids name the refusal.
    assert_eq!(
        s.decide(&run(&["sh", "-c", "x"])).rule(),
        RuleId::Builtin("deny.exec-not-allowlisted")
    );
    assert_eq!(
        s.decide(&run(&["cargo", "a\0b"])).rule(),
        RuleId::Builtin("deny.exec-argv")
    );
    // Explicitly allowlisted, a shell is a program like any other: the
    // sandbox, not the argv validator, is the control (§4.8).
    let with_sh = exec_session(true, &["cargo", "sh"], &exec_allowed());
    assert!(matches!(
        with_sh.decide(&run(&["sh", "-c", "cargo test"])),
        PolicyDecision::Allow { .. }
    ));
    // Off-schema arguments are the schema's denial.
    for bad in [
        json!({"argv": "cargo test"}),
        json!({"argv": ["cargo", 1]}),
        json!({"cwd": "."}),
        json!({"argv": ["cargo"], "env": {}}),
    ] {
        assert!(
            matches!(
                s.decide(&call(EXEC_ID, bad.clone())),
                PolicyDecision::Deny {
                    reason: DenyReason::Args(_),
                    ..
                }
            ),
            "{bad}"
        );
    }
}

// The working directory takes the workspace path rule, like a file tool's
// path, before any allow rule.
#[test]
fn h2d_the_working_directory_must_stay_in_the_workspace() {
    let s = exec_session(true, &["cargo"], &exec_allowed());
    for cwd in ["../x", "/tmp", "a/../../b", "C:\\x", ""] {
        assert!(
            matches!(
                s.decide(&call(EXEC_ID, json!({"argv": ["cargo"], "cwd": cwd}))),
                PolicyDecision::Deny {
                    reason: DenyReason::Path(_),
                    ..
                }
            ),
            "{cwd:?}"
        );
    }
    assert!(matches!(
        s.decide(&call(
            EXEC_ID,
            json!({"argv": ["cargo"], "cwd": "crates/a"})
        )),
        PolicyDecision::Allow { .. }
    ));
}

// Defence in depth: a session that holds the runner but no witness (built
// directly, bypassing planning) still denies every command.
#[test]
fn h2d_decide_denies_a_command_without_the_witness() {
    let reg = builtin_registry();
    let found = match reg.resolve(EXEC_ID) {
        Resolved::One { capability, .. } => Some(capability),
        _ => None,
    };
    let capability = found.expect("the runner is built in");
    let mut s = raw_session(capability, Some(0));
    if let Some(a) = s.active.get_mut(capability.id()) {
        a.exec = true;
    }
    s.exec_programs.insert("cargo".into());
    assert!(is_deny(
        &s.decide(&run(&["cargo", "test"])),
        &DenyReason::NoConformed
    ));
    s.conformed = true;
    assert!(matches!(
        s.decide(&run(&["cargo", "test"])),
        PolicyDecision::Allow { .. }
    ));
}

// Only the built-in runner, with exactly its labels, is the runner: an
// external execute-class capability stays out of scope.
#[test]
fn h2d_an_external_execute_capability_stays_out_of_scope() {
    let m = fixture(vec![cap_json(
        "run",
        [
            "execute",
            "operational",
            "own",
            "none",
            "third_party",
            "none",
        ],
    )]);
    let mut sp = spec(&["fixture.run"]);
    sp.conformed = true;
    let err = plan_over(&[m], &sp, &UserPolicy::default()).unwrap_err();
    assert!(matches!(err, SessionRefused::OutOfScope { .. }), "{err:?}");
}
