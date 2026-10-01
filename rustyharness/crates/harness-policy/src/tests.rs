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
        },
    );
    Session {
        active,
        quarantined: BTreeSet::new(),
        approver_present: true,
        personal_granted: true,
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
fn an_ask_never_mints_authorized_in_this_build() {
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
