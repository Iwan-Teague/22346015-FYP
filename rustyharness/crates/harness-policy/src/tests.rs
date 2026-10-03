//! Policy tests. Invariant tests are named `inv_<n>_…`.

use super::*;
use harness_manifest::admission::Tier;
use harness_manifest::{builtin, Manifest, SemVer, Sha256Pin, ValidationContext};
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
        // The default fixture host HOLDS a witness: since P-37b an
        // mcp-stdio grant plans only with one (INV-6), and the refusal is
        // asserted explicitly in the tests that are about it.
        conformed: true,
        exec_programs: Vec::new(),
        lan_ports: Vec::new(),
        read_window: None,
        kind: SessionKind::Coding,
    }
}

fn read_all() -> Session {
    Session::plan(
        &spec(&[
            "harness.fs.read",
            "harness.fs.search",
            "harness.fs.list",
            "harness.fs.glob",
        ]),
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

/// One capability JSON for an IN-PROCESS fixture manifest (no `mcp_name`;
/// the pins are still required for a non-builtin transport).
fn cap_json_inproc(verb: &str, dims: [&str; 6]) -> Value {
    let [effect, sensitivity, blast_radius, egress, content, confirmation] = dims;
    json!({
        "id": format!("fixture.{verb}"),
        "summary": "fixture capability",
        "effect": effect, "sensitivity": sensitivity, "blast_radius": blast_radius,
        "egress": egress, "content": content, "confirmation": confirmation,
        "input_schema": {"type": "object", "additionalProperties": false, "properties": {}},
        "schema_sha256": PIN, "description_sha256": PIN
    })
}

/// An in-process fixture manifest: the transport whose classes policy still
/// refuses wholesale, so the pre-P-37b planning order stays exercised.
fn fixture_inproc(caps: Vec<Value>) -> Manifest {
    let m = json!({
        "schema_version": 1, "provider": "fixture", "provider_version": "1",
        "min_harness": "0.0.1",
        "transport": {"kind": "in-process", "feature": "probe"},
        "capabilities": caps
    });
    Manifest::parse(m.to_string().as_bytes(), &ctx()).unwrap()
}

const READ_OWN: [&str; 6] = ["read", "operational", "own", "none", "own", "none"];

/// A registry that admits one parsed mcp-stdio manifest under the pinned
/// tier (what `rustyharness provider add` records; the digest is this
/// file's stand-in pin).
fn pinned(m: Manifest) -> Registry {
    Registry::admit(vec![(
        m,
        Tier::Pinned {
            manifest_sha256: Sha256Pin::parse_hex(PIN).unwrap(),
        },
    )])
    .unwrap()
}

/// Plan over parsed manifests the H1 admission gate would refuse (test-only
/// private seam), so every dimension reaches the decision order. The seam
/// resolves through the PINNED tier: the only tier this build admits an
/// mcp-stdio manifest under.
fn plan_over(
    ms: &[Manifest],
    spec: &SessionSpec,
    policy: &UserPolicy,
) -> Result<Session, SessionRefused> {
    let tier = Tier::Pinned {
        manifest_sha256: Sha256Pin::parse_hex(PIN).unwrap(),
    };
    Session::plan_with(spec, policy, &|g| {
        let mut hits = ms
            .iter()
            .flat_map(|m| m.capabilities().iter().map(move |c| (m, c)))
            .filter(|(_, c)| c.id().as_str() == g);
        match (hits.next(), hits.next()) {
            (Some((m, one)), None) => Lookup::One {
                capability: one,
                manifest: m,
                tier: &tier,
            },
            (None, None) => Lookup::NotFound,
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
    // In-process fixtures: an mcp-stdio write/execute now plans and asks
    // (P-37b, `mcp_write_capability_plans_and_asks`), so the undecided
    // classes are exercised on the transport policy still refuses
    // wholesale. Irreversible stays refused for mcp-stdio too.
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
        let m = fixture_inproc(vec![cap_json_inproc(verb, dims)]);
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
    // An mcp-stdio capability still refuses for an UNDECIDED class: only
    // write and execute plan (P-37b); irreversible does not.
    let m = fixture(vec![cap_json(
        "wipe",
        ["irreversible", "public", "own", "none", "own", "none"],
    )]);
    let mut sp = spec(&["fixture.wipe"]);
    sp.workspace = None;
    assert_eq!(
        plan_over(&[m], &sp, &UserPolicy::default()).unwrap_err(),
        SessionRefused::OutOfScope {
            capability: "fixture.wipe".into(),
            what: "a non-read effect class"
        }
    );
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
            user_deny: Vec::new(),
            user_ask: Vec::new(),
            user_allow: allow_idx
                .map(|index| {
                    vec![UserCandidate {
                        index,
                        matcher: None,
                    }]
                })
                .unwrap_or_default(),
            fs_tool: false,
            submit: false,
            todo: false,
            delegate: false,
            edit: false,
            exec: false,
            web_fetch: false,
            exec_start: false,
            exec_read: false,
            exec_stop: false,
            web_search: false,
            mcp: false,
        },
    );
    Session {
        active,
        quarantined: BTreeSet::new(),
        approver_present: true,
        personal_granted: true,
        conformed: false,
        exec_programs: BTreeSet::new(),
        lan_ports: BTreeSet::new(),
        read_window: None,
        session_deny: BTreeMap::new(),
        session_allow: BTreeMap::new(),
        web: None,
        workspace: None,
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
        // P-37b lift: `t` carries the whole manifest's max sensitivity, so
        // the granted sibling is restricted too and names first (INV-27
        // still refuses the session either way).
        assert_eq!(
            plan_over(std::slice::from_ref(&m), &sp, &UserPolicy::default()).unwrap_err(),
            SessionRefused::Restricted("fixture.t".into())
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
    // P-37b lift: the labels are per process (§5.4), so all three
    // capabilities of the manifest carry the max of each — the first grant
    // names every label's source. The refusal itself is unchanged.
    assert_eq!(
        plan_over(std::slice::from_ref(&m), &sp, &UserPolicy::default()).unwrap_err(),
        SessionRefused::Trifecta {
            private: "fixture.p".into(),
            untrusted: "fixture.p".into(),
            egress: "fixture.p".into()
        }
    );
    // The workspace alone supplies P and U (private and third-party by
    // default) — but P-37b's lift gives the granted `fixture.e` the whole
    // manifest's labels (personal, third_party, lan), so IT names every
    // source before the workspace fallbacks are reached.
    let mut sp = spec(&["fixture.e"]);
    sp.workspace = ws();
    assert_eq!(
        plan_over(std::slice::from_ref(&m), &sp, &UserPolicy::default()).unwrap_err(),
        SessionRefused::Trifecta {
            private: "fixture.e".into(),
            untrusted: "fixture.e".into(),
            egress: "fixture.e".into()
        }
    );
    // Declaring the workspace public used to remove P; since P-37b the
    // lift gives the process itself a personal label, so the trifecta
    // refuses naming the granted capability for every label (§5.4: such a
    // server is usable only in a workspace-less session — and the egress
    // itself is still refused until the proxy, below).
    sp.workspace = Some(WorkspaceDecl {
        declared_public: true,
    });
    assert_eq!(
        plan_over(std::slice::from_ref(&m), &sp, &UserPolicy::default()).unwrap_err(),
        SessionRefused::Trifecta {
            private: "fixture.e".into(),
            untrusted: "fixture.e".into(),
            egress: "fixture.e".into()
        }
    );
    // Any two labels without the third: allowed by the trifecta rule. Two
    // SINGLE-capability manifests (since P-37b one manifest's capabilities
    // share lifted labels, so a third label could not stay out of it).
    let p_only = fixture(vec![cap_json(
        "p",
        ["read", "personal", "own", "none", "own", "none"],
    )]);
    let u_only = fixture(vec![cap_json(
        "u",
        ["read", "public", "own", "none", "third_party", "none"],
    )]);
    let mut sp = spec(&["fixture.p", "fixture.u"]);
    sp.workspace = None;
    assert!(plan_over(&[p_only, u_only], &sp, &UserPolicy::default()).is_ok());
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
        // H2e: the schema's hard maximum is the widest window a profile may
        // set (2000); a run's own window is the tool's to apply.
        ("harness.fs.read", json!({"path": "a", "lines": 2001})),
        ("harness.fs.search", json!({"pattern": "x", "context": 6})),
        ("harness.fs.glob", json!({"path": "a"})),
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
    s.quarantine(&CapId::new("harness.fs.read").unwrap())
        .unwrap();
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
    // Same verb, other provider, in-process transport: not the sentinel, so
    // its write class is refused at planning like every other non-mcp write
    // (an mcp-stdio write plans and asks since P-37b).
    let m = fixture_inproc(vec![cap_json_inproc(
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
// external execute-class capability stays out of scope (in-process: an
// mcp-stdio execute plans and asks since P-37b).
#[test]
fn h2d_an_external_execute_capability_stays_out_of_scope() {
    let m = fixture_inproc(vec![cap_json_inproc(
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

// ---- H2e: the checklist, several edits in one file, the glob ------------------

// The checklist is allowed by its own rule after every deny rule and the
// schema, needs no workspace, and asks nobody: it changes only the run's
// own list.
#[test]
fn h2e_the_checklist_is_allowed_by_its_own_rule() {
    let r = builtin_registry();
    let mut sp = spec(&[TODO_ID]);
    sp.workspace = None;
    let s = Session::plan(&sp, &r, &UserPolicy::default()).unwrap();
    for ok in [
        json!({}),
        json!({"items": [{"text": "read the docs", "status": "in_progress"}]}),
    ] {
        let c = call(TODO_ID, ok);
        assert_eq!(
            s.decide(&c),
            PolicyDecision::Allow {
                rule: RuleId::Builtin(TODO_RULE)
            }
        );
        assert_eq!(s.authorize(c).unwrap().rule(), RuleId::Builtin(TODO_RULE));
    }
    for bad in [
        json!({"items": [{"text": "x", "status": "finished"}]}),
        json!({"items": [{"text": "x"}]}),
        json!({"items": [{"text": "x", "status": "done", "priority": 1}]}),
        json!({"list": []}),
    ] {
        let d = s.decide(&call(TODO_ID, bad.clone()));
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
    // A user deny still wins.
    let p = UserPolicy::new(&[TODO_ID], &[], &[]).unwrap();
    let s = Session::plan(&spec(&[TODO_ID]), &r, &p).unwrap();
    assert!(is_deny(
        &s.decide(&call(TODO_ID, json!({}))),
        &DenyReason::UserDenied
    ));
    // A user ask asks (and with no approver, denies).
    let p = UserPolicy::new(&[], &[TODO_ID], &[]).unwrap();
    let s = Session::plan(&spec(&[TODO_ID]), &r, &p).unwrap();
    assert!(is_deny(
        &s.decide(&call(TODO_ID, json!({}))),
        &DenyReason::NoApprover
    ));
}

// Only the built-in checklist, with exactly its labels, is the checklist.
#[test]
fn h2e_a_capability_that_merely_looks_like_the_checklist_stays_out_of_scope() {
    let m = fixture_inproc(vec![cap_json_inproc(
        "task.todo",
        ["write", "public", "own", "none", "own", "none"],
    )]);
    let err = plan_over(&[m], &spec(&["fixture.task.todo"]), &UserPolicy::default()).unwrap_err();
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

// Several edits in one file are an edit like the others: planned only with
// a workspace, asked about by default (denied with no approver), allowed by
// a user allow rule, and their path takes the workspace rule.
#[test]
fn h2e_several_edits_in_one_file_take_the_edit_rules() {
    let multi = |path: &str| {
        call(
            "harness.edit.multi",
            json!({"path": path, "edits": [{"old": "a", "new": "b"}, {"old": "c", "new": "d"}]}),
        )
    };
    let mut sp = spec(&["harness.fs.read", "harness.edit.multi"]);
    sp.approver_present = true;
    let s = Session::plan(&sp, &builtin_registry(), &UserPolicy::default()).unwrap();
    assert_eq!(
        s.decide(&multi("src/lib.rs")),
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::Builtin(EDIT_DEFAULT_RULE),
        }
    );
    sp.approver_present = false;
    let s = Session::plan(&sp, &builtin_registry(), &UserPolicy::default()).unwrap();
    assert!(is_deny(
        &s.decide(&multi("src/lib.rs")),
        &DenyReason::NoApprover
    ));
    let allow = UserPolicy::new(&[], &[], &["harness.edit.multi"]).unwrap();
    let s = Session::plan(&sp, &builtin_registry(), &allow).unwrap();
    assert!(matches!(
        s.decide(&multi("src/lib.rs")),
        PolicyDecision::Allow { .. }
    ));
    for bad in ["../outside.rs", "/etc/passwd", "src/../x", ""] {
        let d = s.decide(&multi(bad));
        assert!(
            matches!(
                d,
                PolicyDecision::Deny {
                    reason: DenyReason::Path(_),
                    ..
                }
            ),
            "{bad}: {d:?}"
        );
    }
}

// The glob is a read tool: allowed by the default read rule, and its path
// takes the workspace rule (the pattern is checked by the tool, which only
// matches strings its confined walk produced).
#[test]
fn h2e_the_glob_is_a_read_tool_under_the_workspace_rule() {
    let s = Session::plan(
        &spec(&["harness.fs.glob"]),
        &builtin_registry(),
        &UserPolicy::default(),
    )
    .unwrap();
    for ok in [
        json!({"pattern": "**/*.rs"}),
        json!({"pattern": "*.md", "path": "docs"}),
        json!({"pattern": "*", "path": "."}),
    ] {
        assert_eq!(
            s.decide(&call("harness.fs.glob", ok)),
            PolicyDecision::Allow {
                rule: RuleId::Builtin("allow.default.read")
            }
        );
    }
    for (path, why) in [
        ("..", PathRefused::Parent),
        ("/etc", PathRefused::Absolute),
        ("", PathRefused::Empty),
    ] {
        assert_eq!(
            s.decide(&call(
                "harness.fs.glob",
                json!({"pattern": "*", "path": path})
            )),
            PolicyDecision::Deny {
                reason: DenyReason::Path(why),
                rule: RuleId::Builtin("deny.path-outside-workspace"),
            },
            "{path}"
        );
    }
    let mut sp = spec(&["harness.fs.glob"]);
    sp.workspace = None;
    assert_eq!(
        Session::plan(&sp, &builtin_registry(), &UserPolicy::default()).unwrap_err(),
        SessionRefused::NoWorkspace("harness.fs.glob".into())
    );
}

// The run's read window (H2e): a read's lines above it is denied like an
// argument outside the schema the model was shown (the driver names the
// window's bounds); without one, the manifest's maximum (2000) alone.
#[test]
fn h2e_a_read_is_held_to_the_runs_window() {
    let read = |lines: u64| call("harness.fs.read", json!({"path": "a.rs", "lines": lines}));
    for (window, ok, over) in [
        (Some(100), 100, 101),
        (Some(400), 400, 401),
        (None, 2000, 2001),
    ] {
        let mut sp = spec(&["harness.fs.read"]);
        sp.read_window = window;
        let s = Session::plan(&sp, &builtin_registry(), &UserPolicy::default()).unwrap();
        assert_eq!(
            s.decide(&read(ok)),
            PolicyDecision::Allow {
                rule: RuleId::Builtin("allow.default.read")
            },
            "{window:?}"
        );
        let d = s.decide(&read(over));
        assert!(
            matches!(
                &d,
                PolicyDecision::Deny {
                    reason: DenyReason::Args(ArgsError { at, .. }),
                    rule: RuleId::Builtin("deny.args-schema"),
                } if at == "/lines"
            ),
            "{window:?}: {d:?}"
        );
        // A read without lines takes the window; nothing to deny.
        assert!(matches!(
            s.decide(&call("harness.fs.read", json!({"path": "a.rs"}))),
            PolicyDecision::Allow { .. }
        ));
    }
}

// ---- the built-in registration table (P-02) --------------------------------------

/// The per-tool registration table must decide exactly as the scattered id
/// constants and prefix checks it replaced: every built-in tool keeps its
/// default decision, and each of the three user-policy roles moves every
/// tool with it.
#[test]
fn policy_default_table_unchanged() {
    let ids = [
        "harness.fs.read",
        "harness.fs.search",
        "harness.fs.glob",
        "harness.fs.list",
        "harness.fs.outline",
        "harness.edit.replace",
        "harness.edit.write",
        "harness.edit.multi",
        "harness.exec.run",
        "harness.task.todo",
        "harness.task.delegate",
        "harness.task.submit",
    ];
    let valid_args = [
        json!({"path": "a.txt"}),
        json!({"pattern": "x"}),
        json!({"pattern": "*.rs"}),
        json!({"path": "."}),
        json!({"path": "."}),
        json!({"path": "a.txt", "old": "a", "new": "b"}),
        json!({"path": "a.txt", "content": "x"}),
        json!({"path": "a.txt", "edits": [{"old": "a", "new": "b"}]}),
        json!({"argv": ["cargo", "test"]}),
        json!({}),
        json!({"task": "x"}),
        json!({"note": "done"}),
    ];
    let defaults = [
        PolicyDecision::Allow {
            rule: RuleId::Builtin("allow.default.read"),
        },
        PolicyDecision::Allow {
            rule: RuleId::Builtin("allow.default.read"),
        },
        PolicyDecision::Allow {
            rule: RuleId::Builtin("allow.default.read"),
        },
        PolicyDecision::Allow {
            rule: RuleId::Builtin("allow.default.read"),
        },
        PolicyDecision::Allow {
            rule: RuleId::Builtin("allow.default.read"),
        },
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::Builtin(EDIT_DEFAULT_RULE),
        },
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::Builtin(EDIT_DEFAULT_RULE),
        },
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::Builtin(EDIT_DEFAULT_RULE),
        },
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::Builtin(EXEC_DEFAULT_RULE),
        },
        PolicyDecision::Allow {
            rule: RuleId::Builtin(TODO_RULE),
        },
        PolicyDecision::Allow {
            rule: RuleId::Builtin("allow.default.read"),
        },
        PolicyDecision::Allow {
            rule: RuleId::Builtin("allow.task-submit"),
        },
    ];
    let deny_all = UserPolicy::new(&["harness.*"], &[], &[]).unwrap();
    let ask_all = UserPolicy::new(&[], &["harness.*"], &[]).unwrap();
    let allow_all = UserPolicy::new(&[], &[], &["harness.*"]).unwrap();
    for i in 0..ids.len() {
        let plan = |policy: &UserPolicy| {
            let mut sp = spec(&[ids[i]]);
            sp.approver_present = true;
            sp.conformed = true;
            sp.exec_programs = vec!["cargo".to_owned()];
            Session::plan(&sp, &builtin_registry(), policy).unwrap()
        };
        let c = call(ids[i], valid_args[i].clone());
        assert_eq!(
            plan(&UserPolicy::default()).decide(&c),
            defaults[i],
            "{}",
            ids[i]
        );
        assert_eq!(
            plan(&deny_all).decide(&c),
            PolicyDecision::Deny {
                reason: DenyReason::UserDenied,
                rule: RuleId::User {
                    list: RuleList::Deny,
                    index: 0
                },
            },
            "{}",
            ids[i]
        );
        assert_eq!(
            plan(&ask_all).decide(&c),
            PolicyDecision::Ask {
                tier: Confirmation::UserConfirm,
                rule: RuleId::User {
                    list: RuleList::Ask,
                    index: 0
                },
            },
            "{}",
            ids[i]
        );
        assert_eq!(
            plan(&allow_all).decide(&c),
            PolicyDecision::Allow {
                rule: RuleId::User {
                    list: RuleList::Allow,
                    index: 0
                }
            },
            "{}",
            ids[i]
        );
    }
}

// ---- P-08: policy argument matchers ---------------------------------------------

/// The outline tool (P-24) is a read-class built-in like `list`: planned
/// alone under the default policy it decides allow through the default read
/// rule, and the registration table and the compiled-in registries agree:
/// every table id resolves, the web ids only in the research registry
/// (P-39b), todo and the sentinel in both manifests.
#[test]
fn tool_count_policy_default_read_allow() {
    assert_eq!(crate::builtin::BUILTIN_TOOLS.len(), 20);
    let reg = builtin_registry();
    let research = research_registry();
    for t in crate::builtin::BUILTIN_TOOLS {
        let in_coding = matches!(
            reg.resolve(t.id),
            harness_manifest::admission::Resolved::One { .. }
        );
        let in_research = matches!(
            research.resolve(t.id),
            harness_manifest::admission::Resolved::One { .. }
        );
        if crate::builtin::is_web_id(t.id) {
            assert!(!in_coding && in_research, "{}", t.id);
        } else {
            assert!(in_coding, "{}", t.id);
        }
    }
    let s = Session::plan(&spec(&[OUTLINE_ID]), &reg, &UserPolicy::default()).unwrap();
    assert_eq!(
        s.decide(&call(OUTLINE_ID, json!({"path": "."}))),
        PolicyDecision::Allow {
            rule: RuleId::Builtin("allow.default.read"),
        }
    );
}

// ---- P-38: delegate ----------------------------------------------------------------

/// The delegate row keeps the submit sentinel last: it sits after todo and
/// before submit in the registration table, and both ids resolve in the
/// compiled-in registry (P-02 three-way agreement, P-24 style).
#[test]
fn builtin_registry_lists_delegate_before_submit() {
    let pos = |id: &str| {
        crate::builtin::BUILTIN_TOOLS
            .iter()
            .position(|t| t.id == id)
            .unwrap()
    };
    assert!(pos(TODO_ID) < pos(DELEGATE_ID));
    assert!(pos(DELEGATE_ID) < pos(SUBMIT_ID));
    let reg = builtin_registry();
    for id in [DELEGATE_ID, SUBMIT_ID] {
        assert!(
            matches!(
                reg.resolve(id),
                harness_manifest::admission::Resolved::One { .. }
            ),
            "{}",
            id
        );
    }
}

/// Nothing grants the delegate implicitly: without the grant on the session,
/// a delegate call is the plain not-granted deny, at decide and authorize.
#[test]
fn delegate_denied_without_grant() {
    let s = read_all();
    let c = call(DELEGATE_ID, json!({"task": "find the entry point"}));
    let d = s.decide(&c);
    assert!(is_deny(&d, &DenyReason::NotGranted), "{d:?}");
    assert!(s.authorize(c).is_err());
}

/// Granted, the delegate is a read-class tool like `list`: under the default
/// policy it decides allow through the default read rule, and authorize
/// mints the approval with the same rule id.
#[test]
fn delegate_allowed_by_default_read_rule_when_granted() {
    let s = Session::plan(
        &spec(&[DELEGATE_ID, "harness.fs.read"]),
        &builtin_registry(),
        &UserPolicy::default(),
    )
    .unwrap();
    let c = call(DELEGATE_ID, json!({"task": "find the entry point"}));
    assert_eq!(
        s.decide(&c),
        PolicyDecision::Allow {
            rule: RuleId::Builtin("allow.default.read"),
        }
    );
    let a = s.authorize(c).unwrap();
    assert_eq!(a.rule(), RuleId::Builtin("allow.default.read"));
}

/// The delegate explores the workspace, so planning refuses the grant when
/// the session has no workspace (fail-closed, same as the fs tools).
#[test]
fn delegate_refused_without_workspace() {
    let mut sp = spec(&[DELEGATE_ID]);
    sp.workspace = None;
    assert_eq!(
        Session::plan(&sp, &builtin_registry(), &UserPolicy::default()).unwrap_err(),
        SessionRefused::NoWorkspace(DELEGATE_ID.to_owned())
    );
}

/// The delegate args schema is the manifest's: one string `task` of at most
/// 2000 chars, nothing else — an extra field, an over-long task, a missing
/// task and a non-string task are all schema denies; the 2000-char ceiling
/// itself is allowed.
#[test]
fn delegate_args_schema_refuses_extra_field_and_long_task() {
    let s = Session::plan(
        &spec(&[DELEGATE_ID]),
        &builtin_registry(),
        &UserPolicy::default(),
    )
    .unwrap();
    for args in [
        json!({"task": "x", "steps": 3}),
        json!({"task": "a".repeat(2001)}),
        json!({}),
        json!({"task": 7}),
    ] {
        let d = s.decide(&call(DELEGATE_ID, args));
        assert!(
            matches!(
                d,
                PolicyDecision::Deny {
                    reason: DenyReason::Args(_),
                    ..
                }
            ),
            "{d:?}"
        );
    }
    assert_eq!(
        s.decide(&call(DELEGATE_ID, json!({"task": "a".repeat(2000)}))),
        PolicyDecision::Allow {
            rule: RuleId::Builtin("allow.default.read"),
        }
    );
}

/// D12 (P-38 §9): a delegate whose child scope reaches above its own
/// sensitivity is refused at planning. The real manifests never do this, so
/// the fixture plans `harness.fs.read` (the eligible grant string) over a
/// `personal` capability; the same capability under a non-eligible grant
/// string plans fine.
#[test]
fn delegate_refused_when_child_scope_more_sensitive() {
    let builtin_m = builtin::manifest(&ctx()).unwrap();
    let personal_m = fixture(vec![cap_json(
        "recs",
        ["read", "personal", "own", "none", "own", "none"],
    )]);
    let tier = Tier::Pinned {
        manifest_sha256: Sha256Pin::parse_hex(PIN).unwrap(),
    };
    let lookup = |g: &str| -> Lookup<'_> {
        let hit = (g == "harness.fs.read" || g == "fixture.personal.read")
            .then(|| (personal_m.capabilities().first().unwrap(), &personal_m))
            .or_else(|| {
                builtin_m
                    .capabilities()
                    .iter()
                    .find(|c| c.id().as_str() == g)
                    .map(|c| (c, &builtin_m))
            });
        match hit {
            Some((c, m)) => Lookup::One {
                capability: c,
                manifest: m,
                tier: &tier,
            },
            None => Lookup::NotFound,
        }
    };
    let mut sp = spec(&["harness.task.delegate", "harness.fs.read"]);
    sp.personal_data_granted = true;
    assert_eq!(
        Session::plan_with(&sp, &UserPolicy::default(), &lookup).unwrap_err(),
        SessionRefused::DelegateScope(DELEGATE_ID.to_owned())
    );
    // The counterfactual: the child cap is only refused through an
    // eligible grant string; anything else is not the delegate's scope.
    let mut sp = spec(&["harness.task.delegate", "fixture.personal.read"]);
    sp.personal_data_granted = true;
    assert!(Session::plan_with(&sp, &UserPolicy::default(), &lookup).is_ok());
}

/// A helper run may not hold the delegate itself (no nesting), so
/// `plan_child` refuses the grant even though plain planning accepts it.
#[test]
fn plan_child_refuses_delegate_grant() {
    assert_eq!(
        Session::plan_child(
            &spec(&["harness.fs.read", "harness.task.delegate"]),
            &builtin_registry(),
            &UserPolicy::default(),
        )
        .unwrap_err(),
        SessionRefused::ChildScope(DELEGATE_ID.to_owned())
    );
}

/// Edit and exec are refused to a helper run too, once plain planning lets
/// them through (approver present, confinement conformed): the child scope
/// is read-only plus the submit sentinel, nothing else.
#[test]
fn plan_child_refuses_edit_and_exec() {
    let mut sp = spec(&["harness.edit.replace", "harness.exec.run"]);
    sp.approver_present = true;
    sp.conformed = true;
    sp.exec_programs = vec!["cargo".to_owned()];
    assert_eq!(
        Session::plan_child(&sp, &builtin_registry(), &UserPolicy::default()).unwrap_err(),
        SessionRefused::ChildScope("harness.edit.replace".into())
    );
}

/// The child scope itself: fs reads plus the submit sentinel plan fine, and
/// the resulting session still decides through the default read rule.
#[test]
fn plan_child_accepts_fs_and_submit() {
    let mut sp = spec(&[
        "harness.fs.read",
        "harness.fs.search",
        "harness.task.submit",
    ]);
    sp.approver_present = true;
    sp.conformed = true;
    let s = Session::plan_child(&sp, &builtin_registry(), &UserPolicy::default()).unwrap();
    assert_eq!(
        s.decide(&call("harness.fs.read", json!({"path": "a.rs"}))),
        PolicyDecision::Allow {
            rule: RuleId::Builtin("allow.default.read"),
        }
    );
}

/// The user deny rule wins over the read default: a granted delegate under
/// an explicit deny is a user deny citing that rule.
#[test]
fn user_deny_rule_on_delegate_wins() {
    let p = UserPolicy::new(&[DELEGATE_ID], &[], &[]).unwrap();
    let s = Session::plan(&spec(&[DELEGATE_ID]), &builtin_registry(), &p).unwrap();
    assert_eq!(
        s.decide(&call(DELEGATE_ID, json!({"task": "x"}))),
        PolicyDecision::Deny {
            reason: DenyReason::UserDenied,
            rule: RuleId::User {
                list: RuleList::Deny,
                index: 0
            },
        }
    );
}

/// A v2 policy file straight from parsed JSON (what the CLI hands over).
fn policy_json(v: Value) -> UserPolicy {
    UserPolicy::from_json(&v).unwrap()
}

/// An allow rule on `harness.edit.replace` narrowed to `src/**`: edits under
/// `src/` go through without an approver, anything else falls to the edit
/// default (an ask, which with no approver present is a deny, §5.2).
#[test]
fn matcher_path_glob_allows_only_under_src() {
    let p = policy_json(json!({
        "deny": [], "ask": [],
        "allow": [
            {"capability": "harness.edit.replace", "match": {"path_glob": "src/**"}}
        ]
    }));
    let s = edit_session(false, &p);
    assert_eq!(
        s.decide(&replace("src/lib.rs")),
        PolicyDecision::Allow {
            rule: RuleId::User {
                list: RuleList::Allow,
                index: 0
            }
        }
    );
    // `src/**` is "under src", not src itself; outside the glob the allow
    // does not reach, and the un-allowed edit asks (here: denies).
    for path in ["src", "docs/a.md", "srcx/a.rs"] {
        assert!(
            matches!(
                s.decide(&replace(path)),
                PolicyDecision::Deny {
                    reason: DenyReason::NoApprover,
                    ..
                }
            ),
            "{path}"
        );
    }
    // A different edit capability has no rule at all: same default.
    assert!(matches!(
        s.decide(&write("src/a.rs")),
        PolicyDecision::Deny {
            reason: DenyReason::NoApprover,
            ..
        }
    ));
}

/// `allow cargo test` (the slice card): an argv prefix matcher allows
/// exactly the matching commands; within a list, FIRST match wins.
#[test]
fn matcher_argv_prefix_cargo_test() {
    let p = policy_json(json!({
        "deny": [], "ask": [],
        "allow": [
            {"capability": EXEC_ID, "match": {"argv_prefix": ["cargo", "test"]}},
            {"capability": EXEC_ID, "match": {"argv_prefix": ["cargo"]}}
        ]
    }));
    let s = exec_session(false, &["cargo", "git"], &p);
    for (argv, index) in [
        (&["cargo", "test"][..], 0),
        (&["cargo", "test", "--lib"][..], 0),
        (&["cargo", "build"][..], 1),
    ] {
        assert_eq!(
            s.decide(&run(argv)),
            PolicyDecision::Allow {
                rule: RuleId::User {
                    list: RuleList::Allow,
                    index
                }
            },
            "{argv:?}"
        );
    }
    // No allow reaches a git command: the exec default asks, and with no
    // approver an ask denies.
    assert!(matches!(
        s.decide(&run(&["git", "status"])),
        PolicyDecision::Deny {
            reason: DenyReason::NoApprover,
            ..
        }
    ));
}

/// The §5.1 order never moves: a deny matcher beats a (broader) allow
/// matcher on the very calls it covers, and only on them.
#[test]
fn deny_matcher_beats_allow_matcher() {
    let p = policy_json(json!({
        "deny": [
            {"capability": "harness.edit.replace", "match": {"path_glob": "secrets/**"}}
        ],
        "ask": [],
        "allow": [
            {"capability": "harness.edit.replace", "match": {"path_glob": "**"}}
        ]
    }));
    let s = edit_session(true, &p);
    assert_eq!(
        s.decide(&replace("secrets/k.env")),
        PolicyDecision::Deny {
            reason: DenyReason::UserDenied,
            rule: RuleId::User {
                list: RuleList::Deny,
                index: 0
            }
        }
    );
    assert_eq!(
        s.decide(&replace("src/a.rs")),
        PolicyDecision::Allow {
            rule: RuleId::User {
                list: RuleList::Allow,
                index: 0
            }
        }
    );
}

/// A user allow can never lower a floor (§5.2): a `personal` read keeps its
/// derived `user_confirm` even where the matcher matches. The fixture's
/// schema takes a `path` so the allow matcher can genuinely match.
#[test]
fn allow_matcher_cannot_lower_floor() {
    let cap = json!({
        "id": "fixture.p", "mcp_name": "p", "summary": "fixture capability",
        "effect": "read", "sensitivity": "personal", "blast_radius": "own",
        "egress": "none", "content": "own", "confirmation": "none",
        "input_schema": {"type": "object", "additionalProperties": false,
            "properties": {"path": {"type": "string"}}, "required": ["path"]},
        "schema_sha256": PIN, "description_sha256": PIN
    });
    let m = fixture(vec![cap]);
    let p = policy_json(json!({
        "deny": [], "ask": [],
        "allow": [{"capability": "fixture.p", "match": {"path_glob": "**"}}]
    }));
    let mut sp = spec(&["fixture.p"]);
    sp.workspace = None;
    sp.approver_present = true;
    sp.personal_data_granted = true;
    let s = plan_over(std::slice::from_ref(&m), &sp, &p).unwrap();
    assert_eq!(
        s.decide(&call("fixture.p", json!({"path": "a"}))),
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::Builtin("ask.confirmation-floor")
        }
    );
}

/// An ask with a matcher narrows without raising the floor (P-08):
/// `ask git push` must not make `cargo test` ask, but where it matches it
/// is the credited ask rule at its own tier.
#[test]
fn an_ask_matcher_does_not_raise_the_floor_outside_its_match() {
    let p = policy_json(json!({
        "deny": [],
        "ask": [{"capability": EXEC_ID, "match": {"argv_prefix": ["git", "push"]}}],
        "allow": [{"capability": EXEC_ID, "match": {"argv_prefix": ["cargo", "test"]}}]
    }));
    // No approver: the matched ask is a deny; the allowed command is not
    // dragged up with it.
    let s = exec_session(false, &["cargo", "git"], &p);
    assert!(matches!(
        s.decide(&run(&["git", "push"])),
        PolicyDecision::Deny {
            reason: DenyReason::NoApprover,
            ..
        }
    ));
    assert_eq!(
        s.decide(&run(&["cargo", "test"])),
        PolicyDecision::Allow {
            rule: RuleId::User {
                list: RuleList::Allow,
                index: 0
            }
        }
    );
    // With an approver the matched ask is the user rule at `user_confirm`
    // (the class floor is `none`: the matcher ask never raised it).
    let s = exec_session(true, &["cargo", "git"], &p);
    assert_eq!(
        s.decide(&run(&["git", "push"])),
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::User {
                list: RuleList::Ask,
                index: 0
            }
        }
    );
    // An unmatched command consults neither the ask matcher nor the allow:
    // the exec default asks.
    assert!(matches!(
        s.decide(&run(&["cargo", "build"])),
        PolicyDecision::Ask {
            rule: RuleId::Builtin(EXEC_DEFAULT_RULE),
            ..
        }
    ));
}

/// A v1 policy file parses identically and digests identically (v2 is a
/// superset, P-08); a matcher appends its canonical form to the rule's
/// digest line.
#[test]
fn old_policy_file_same_digest() {
    let v1 = json!({
        "deny": ["harness.edit.write"],
        "ask": ["fixture.p"],
        "allow": ["harness.fs.read", "harness.*"]
    });
    let from_file = UserPolicy::from_json(&v1).unwrap();
    let from_new = UserPolicy::new(
        &["harness.edit.write"],
        &["fixture.p"],
        &["harness.fs.read", "harness.*"],
    )
    .unwrap();
    assert_eq!(from_file, from_new);
    assert_eq!(from_file.digest(), from_new.digest());

    let v2 = json!({
        "deny": [], "ask": [],
        "allow": [{"capability": EXEC_ID, "match": {"argv_prefix": ["cargo", "test"]}}]
    });
    let with = UserPolicy::from_json(&v2).unwrap();
    let bare = UserPolicy::new(&[], &[], &[EXEC_ID]).unwrap();
    assert_ne!(with.digest(), bare.digest());
}

/// A rule's `examples` are unit tests run at load (§4.8, R1 §3.1): they
/// pass or the whole file is refused.
#[test]
fn rule_examples_checked_at_load() {
    let good = json!({
        "deny": [], "ask": [],
        "allow": [{
            "capability": EXEC_ID,
            "match": {"argv_prefix": ["cargo"]},
            "examples": [
                {"args": {"argv": ["cargo", "test"]}, "expect": "match"},
                {"args": {"argv": ["git", "push"]}, "expect": "not_match"},
                {"args": {}, "expect": "not_match"}
            ]
        }]
    });
    assert!(UserPolicy::from_json(&good).is_ok());

    // A rule that does not do what its author documented refuses the file.
    let bad = json!({
        "deny": [], "ask": [],
        "allow": [{
            "capability": EXEC_ID,
            "match": {"argv_prefix": ["cargo"]},
            "examples": [{"args": {"argv": ["git", "push"]}, "expect": "match"}]
        }]
    });
    assert!(matches!(
        UserPolicy::from_json(&bad),
        Err(PolicyConfigError::BadExample(_))
    ));

    // Under a provider selector an example must name its capability.
    let no_cap = json!({
        "deny": [], "ask": [],
        "allow": [{
            "capability": "harness.*",
            "match": {"path_glob": "src/**"},
            "examples": [{"args": {"path": "src/a.rs"}, "expect": "match"}]
        }]
    });
    assert!(matches!(
        UserPolicy::from_json(&no_cap),
        Err(PolicyConfigError::BadExample(_))
    ));
    let with_cap = json!({
        "deny": [], "ask": [],
        "allow": [{
            "capability": "harness.*",
            "match": {"path_glob": "src/**"},
            "examples": [{
                "capability": "harness.edit.replace",
                "args": {"path": "src/a.rs"}, "expect": "match"
            }]
        }]
    });
    assert!(UserPolicy::from_json(&with_cap).is_ok());
}

/// A glob the pure matcher refuses refuses the file: a policy never loads
/// with a condition that cannot be evaluated (fail-closed, P-08).
#[test]
fn bad_glob_refused() {
    for pattern in ["../x", "/abs", "[ab", "a//b", "", "a\\b"] {
        let p = json!({
            "deny": [], "ask": [],
            "allow": [
                {"capability": "harness.edit.replace", "match": {"path_glob": pattern}}
            ]
        });
        assert!(
            matches!(
                UserPolicy::from_json(&p),
                Err(PolicyConfigError::BadMatcher(_))
            ),
            "{pattern:?}"
        );
    }
}

/// The v2 shapes fail closed: unknown keys, missing lists, malformed rules
/// and matchers are refused; the same selector with different matchers is
/// two rules, the same rule twice is refused (as in v1).
#[test]
fn v2_policy_files_fail_closed_on_bad_shapes() {
    let bad_file = |v: Value| UserPolicy::from_json(&v).unwrap_err();
    assert!(matches!(bad_file(json!([])), PolicyConfigError::BadRule(_)));
    // An absent list is empty (v1 files rely on it); a mis-typed one is not.
    assert!(UserPolicy::from_json(&json!({"deny": [], "ask": []})).is_ok());
    assert!(matches!(
        bad_file(json!({"deny": [], "ask": [], "allow": {}})),
        PolicyConfigError::BadRule(_)
    ));
    assert!(matches!(
        bad_file(json!({"deny": [], "ask": [], "allow": [], "extra": []})),
        PolicyConfigError::BadRule(_)
    ));
    assert!(matches!(
        bad_file(json!({"deny": [], "ask": [], "allow": [42]})),
        PolicyConfigError::BadRule(_)
    ));
    // A rule that is only `match` lacks its capability (the matcher's own
    // emptiness is checked first, so this is a BadMatcher either way).
    assert!(matches!(
        bad_file(json!({"deny": [], "ask": [], "allow": [{"match": {}}]})),
        PolicyConfigError::BadMatcher(_)
    ));
    // An empty `match` names no condition; unknown match keys are refused.
    for m in [json!({}), json!({"path_glob": "src/**", "argv": ["x"]})] {
        assert!(matches!(
            bad_file(
                json!({"deny": [], "ask": [], "allow": [{"capability": EXEC_ID, "match": m}]})
            ),
            PolicyConfigError::BadMatcher(_)
        ));
    }
    // An empty (or empty-string) prefix would match every argv or none.
    for pre in [json!([]), json!([""])] {
        assert!(matches!(
            bad_file(json!({
                "deny": [], "ask": [],
                "allow": [{"capability": EXEC_ID, "match": {"argv_prefix": pre}}]
            })),
            PolicyConfigError::BadMatcher(_)
        ));
    }
    // The same selector twice with DIFFERENT matchers is two rules; the
    // same rule twice is ambiguous, as in v1.
    let two = json!({
        "deny": [], "ask": [],
        "allow": [
            {"capability": EXEC_ID, "match": {"argv_prefix": ["cargo"]}},
            {"capability": EXEC_ID, "match": {"argv_prefix": ["git"]}}
        ]
    });
    assert!(UserPolicy::from_json(&two).is_ok());
    let dup = json!({
        "deny": [], "ask": [],
        "allow": [
            {"capability": EXEC_ID, "match": {"argv_prefix": ["cargo"]}},
            {"capability": EXEC_ID, "match": {"argv_prefix": ["cargo"]}}
        ]
    });
    assert!(matches!(
        UserPolicy::from_json(&dup),
        Err(PolicyConfigError::Ambiguous(_))
    ));
}

// ---- P-29 protected-path floor: the constructors the driver uses ---------------

#[test]
fn path_glob_ctor_builds_and_refuses_bad_globs() {
    let m = Matcher::path_glob("Cargo.lock").unwrap();
    assert!(m.matches(&json!({"path": "Cargo.lock"})));
    assert!(!m.matches(&json!({"path": "src/lib.rs"})));
    assert!(Matcher::path_glob("[[nope").is_err());
}

#[test]
fn push_ask_appends_then_refuses_any_duplicate_key() {
    let mut p = UserPolicy::new(&[], &[], &["harness.edit.replace"]).unwrap();
    let rule = |pat: &str| Rule {
        selector: Selector::parse("harness.edit.replace").unwrap(),
        matcher: Some(Matcher::path_glob(pat).unwrap()),
    };
    p.push_ask(rule("Cargo.lock")).unwrap();
    assert_eq!(p.ask.len(), 1);
    // Same key twice in ask, and the same key in deny/allow: all ambiguous.
    assert!(p.push_ask(rule("Cargo.lock")).is_err());
    // A bare rule whose key exactly matches an existing deny rule: ambiguous.
    let mut q = UserPolicy::new(&["harness.edit.replace"], &[], &[]).unwrap();
    assert!(q
        .push_ask(Rule {
            selector: Selector::parse("harness.edit.replace").unwrap(),
            matcher: None,
        })
        .is_err());
    // A different pattern is a different key: fine.
    p.push_ask(rule(".github/**")).unwrap();
    assert_eq!(p.ask.len(), 2);
}

// ---- P-12: the sensitive-path default denies ------------------------------------
// ---- P-12: the sensitive-path default denies ------------------------------------

/// The default deny list denies read, search, glob, list and the edits on
/// the documented globs, and every denial names its rule (§5.1: a decision
/// carries the id of the rule that produced it).
#[test]
fn denied_decision_has_rule_id() {
    let p = default_denies().unwrap();
    let s = Session::plan(
        &spec(&["harness.fs.read", "harness.edit.replace"]),
        &builtin_registry(),
        &p,
    )
    .unwrap();
    // read .env: the read list's first glob is `.env`, so deny index 0.
    assert_eq!(
        s.decide(&call("harness.fs.read", json!({"path": ".env"}))),
        PolicyDecision::Deny {
            reason: DenyReason::UserDenied,
            rule: RuleId::User {
                list: RuleList::Deny,
                index: 0
            }
        }
    );
    // A name pattern matches at any depth.
    assert!(is_deny(
        &s.decide(&call(
            "harness.fs.read",
            json!({"path": "deploy/.env.prod"})
        )),
        &DenyReason::UserDenied
    ));
    // A non-denied read is untouched: the default allow (no rule of ours).
    let ok = s.decide(&call("harness.fs.read", json!({"path": "a.txt"})));
    assert!(matches!(ok, PolicyDecision::Allow { .. }), "{ok:?}");
    // The edits are covered too: edit.replace's rules start at 5 × 10.
    assert_eq!(
        s.decide(&call(
            "harness.edit.replace",
            json!({"path": ".env", "old": "A", "new": "B"})
        )),
        PolicyDecision::Deny {
            reason: DenyReason::UserDenied,
            rule: RuleId::User {
                list: RuleList::Deny,
                index: 50
            }
        }
    );
}

/// The CLI's overlay refuses a `--policy` that already names one of the
/// default rules (the duplicate-rule precedent); without the overlay the
/// same file loads.
#[test]
fn overlay_refuses_a_duplicate_default_rule() {
    let file = json!({
        "deny": [{"capability": "harness.fs.read", "match": {"path_glob": ".env"}}]
    });
    let p = UserPolicy::from_json(&file).unwrap();
    assert!(matches!(
        overlay_default_denies(p),
        Err(PolicyConfigError::Ambiguous(key)) if key.contains("harness.fs.read")
    ));
    // The user's own deny works alone (the --no-default-denies reading).
    assert!(UserPolicy::from_json(&file).is_ok());
    // Overlaying the empty policy gives the defaults, appended after
    // whatever was there (nothing), and the digest names the union.
    let bare = overlay_default_denies(UserPolicy::default()).unwrap();
    assert_eq!(bare.digest(), default_denies().unwrap().digest());
}

/// `denied_globs` keeps the surfacing read tools' own `path_glob` denies
/// only: an edit-only rule or an argv-conditioned rule is not a skip
/// predicate for search, glob or list.
#[test]
fn denied_globs_from_read_only_deny() {
    let p = UserPolicy::from_json(&json!({
        "deny": [
            {"capability": "harness.fs.read", "match": {"path_glob": ".env*"}},
            {"capability": "harness.edit.write", "match": {"path_glob": ".env*"}},
            {"capability": "harness.fs.search", "match": {"argv_prefix": ["git"]}}
        ]
    }))
    .unwrap();
    let globs = p.denied_globs();
    assert_eq!(globs.len(), 1, "{globs:?}");
    assert!(globs[0].matches(".env"));
    assert!(globs[0].matches("sub/.env.local"));
    assert!(!globs[0].matches("a.txt"));
    assert!(UserPolicy::default().denied_globs().is_empty());
}

/// The defaults are the documented globs × the documented capabilities, in
/// the stable order (rule indices and the digest must not drift), and the
/// list is not the empty library default (OD-2).
#[test]
fn default_denies_cover_the_documented_globs() {
    let p = default_denies().unwrap();
    assert_eq!(p.deny.len(), 11 * DEFAULT_DENY_GLOBS.len());
    // Per capability: 10 globs each, capability-major order.
    for (cap, base) in [
        ("harness.fs.read", 0),
        ("harness.fs.search", 10),
        ("harness.fs.glob", 20),
        ("harness.fs.list", 30),
        ("harness.fs.outline", 40),
        ("harness.edit.replace", 50),
        ("harness.edit.write", 60),
        ("harness.edit.multi", 70),
        ("harness.edit.patch", 80),
        ("harness.edit.delete", 90),
        ("harness.edit.move", 100),
    ] {
        let mut grants = vec![cap];
        if cap != "harness.fs.read" {
            grants.push("harness.fs.read");
        }
        let s = Session::plan(&spec(&grants), &builtin_registry(), &p).unwrap();
        let first = s.decide(&call(
            cap,
            if cap.starts_with("harness.edit") {
                json!({"path": DEFAULT_DENY_GLOBS[0], "old": "a", "new": "b"})
            } else {
                json!({"path": DEFAULT_DENY_GLOBS[0]})
            },
        ));
        assert_eq!(
            first,
            PolicyDecision::Deny {
                reason: DenyReason::UserDenied,
                rule: RuleId::User {
                    list: RuleList::Deny,
                    index: base
                }
            },
            "{cap} first glob"
        );
        let last = s.decide(&call(
            cap,
            if cap.starts_with("harness.edit") {
                json!({"path": DEFAULT_DENY_GLOBS[9], "old": "a", "new": "b"})
            } else {
                json!({"path": DEFAULT_DENY_GLOBS[9]})
            },
        ));
        assert_eq!(
            last,
            PolicyDecision::Deny {
                reason: DenyReason::UserDenied,
                rule: RuleId::User {
                    list: RuleList::Deny,
                    index: base + 9
                }
            },
            "{cap} last glob"
        );
    }
    // The defaults are not the library default: the digest differs.
    assert_ne!(p.digest(), UserPolicy::default().digest());
}

// ---- fuzz-style robustness (P-54) ----------------------------------------------
//
// The policy file path is two parsers of untrusted bytes: the strict JSON
// reader, then `UserPolicy::from_json`. Whatever the file contains, the load
// must answer with a typed error (or a policy) — never a panic, never a
// half-understood file. The inputs come from `harness_testkit::mutator`,
// whose seeded xorshift generator makes every case reproducible from the
// seed named in the loop (base + case).

use harness_testkit::mutator::{self, XorShift64};

/// The mutated-policy loop, at whatever case count the caller asks for.
fn fuzz_policy_over_mutated_files(cases: usize) {
    // A valid v2 file: v1 selector strings and one object rule with a
    // `path_glob` matcher (examples omitted: they are optional).
    let seed = r#"{"deny":["harness.exec.run"],"ask":[{"capability":"harness.edit.replace","match":{"path_glob":"src/**"}}],"allow":["harness.fs.read"]}"#;
    for case in 0..cases {
        let mut rng = XorShift64::new(0x5400_00C0_0000 + case as u64);
        let m = mutator::mutate(seed.as_bytes(), &mut rng, 24);
        // A file that is not strict JSON is a typed refusal before any
        // rule is read; one that is, is either a policy or a typed
        // PolicyConfigError. Never a panic.
        if let Ok(v) = harness_core::strict_json::parse(&m) {
            let _ = UserPolicy::from_json(&v);
        }
        // Pure garbage too, not only mutations of a valid file.
        let len = rng.below(400);
        let g = mutator::garbage(&mut rng, len);
        if let Ok(v) = harness_core::strict_json::parse(&g) {
            let _ = UserPolicy::from_json(&v);
        }
    }
}

#[test]
fn fuzz_policy_parser_never_panics() {
    fuzz_policy_over_mutated_files(mutator::case_count(2_000));
}

/// The long form: `cargo test -- --ignored` with `RH_FUZZ_CASES` set
/// drives the case count up.
#[test]
#[ignore]
fn fuzz_policy_long_cases() {
    fuzz_policy_over_mutated_files(mutator::case_count(50_000));
}

// ---- P-23: session-scoped grants --------------------------------------------------

/// A session allow grant applies to later calls matching its pattern — for
/// the rest of the session, not once — and only to them.
#[test]
fn session_allow_applies_to_next_matching_call_only() {
    let mut s = exec_session(true, &["cargo"], &UserPolicy::default());
    let index = s.grant(
        RuleList::Allow,
        &CapId::new(EXEC_ID).unwrap(),
        Matcher::argv_prefix(vec!["cargo".into(), "test".into()]).unwrap(),
    );
    assert_eq!(index, 0);
    assert_eq!(
        RuleId::Session {
            list: RuleList::Allow,
            index
        }
        .to_string(),
        "session.allow.0"
    );
    // The matching call no longer asks — and not just the next one: the
    // grant stands until the session ends.
    for _ in 0..2 {
        assert_eq!(
            s.decide(&run(&["cargo", "test", "--offline"])),
            PolicyDecision::Allow {
                rule: RuleId::Session {
                    list: RuleList::Allow,
                    index: 0
                }
            }
        );
    }
    // A non-matching call still asks under the built-in default.
    assert_eq!(
        s.decide(&run(&["cargo", "build"])),
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::Builtin(EXEC_DEFAULT_RULE),
        }
    );
}

/// The grant is matcher-bound: a different argv (even the same program) is
/// not covered, and falls back to the ordinary decision order.
#[test]
fn session_allow_does_not_match_other_argv() {
    let mut s = exec_session(true, &["cargo"], &UserPolicy::default());
    s.grant(
        RuleList::Allow,
        &CapId::new(EXEC_ID).unwrap(),
        Matcher::argv_prefix(vec!["cargo".into(), "test".into()]).unwrap(),
    );
    for argv in [vec!["cargo", "build"], vec!["cargo"]] {
        assert!(
            matches!(s.decide(&run(&argv)), PolicyDecision::Ask { .. }),
            "{argv:?}"
        );
    }
    // A different program is not covered either (and stays allowlisted-gated).
    assert!(matches!(
        s.decide(&run(&["cargo", "test"])),
        PolicyDecision::Allow { .. }
    ));
    let mut other = exec_session(true, &["cargo", "rustc"], &UserPolicy::default());
    other.grant(
        RuleList::Allow,
        &CapId::new(EXEC_ID).unwrap(),
        Matcher::argv_prefix(vec!["cargo".into(), "test".into()]).unwrap(),
    );
    assert!(matches!(
        other.decide(&run(&["rustc", "--version"])),
        PolicyDecision::Ask { .. }
    ));
}

/// A `protected_action` floor stands above any session grant: the class
/// asks at the confirmation stage, before any allow list is consulted, so
/// answering `a` at a prompt can never answer for a protected action.
#[test]
fn session_grant_never_covers_protected_action() {
    let cap = json!({
        "id": "fixture.protect",
        "mcp_name": "protect",
        "summary": "fixture protected capability",
        "effect": "read", "sensitivity": "public", "blast_radius": "shared",
        "egress": "none", "content": "own", "confirmation": "none",
        "input_schema": {"type": "object", "additionalProperties": false,
            "properties": {"path": {"type": "string"}}, "required": ["path"]},
        "schema_sha256": PIN, "description_sha256": PIN
    });
    let m = fixture(vec![cap]);
    let mut sp = spec(&["fixture.protect"]);
    sp.approver_present = true;
    let mut s = plan_over(&[m], &sp, &UserPolicy::default()).unwrap();
    s.grant(
        RuleList::Allow,
        &CapId::new("fixture.protect").unwrap(),
        Matcher::path_glob("**").unwrap(),
    );
    let c = call("fixture.protect", json!({"path": "x"}));
    assert_eq!(
        s.decide(&c),
        PolicyDecision::Ask {
            tier: Confirmation::ProtectedAction,
            rule: RuleId::Builtin("ask.confirmation-floor"),
        }
    );
    assert!(s.authorize(c).is_err());
}

// ---- P-36g: the background exec tools and port grants --------------------------

const BG_GRANTS: [&str; 4] = [EXEC_ID, EXEC_START_ID, EXEC_READ_ID, EXEC_STOP_ID];

/// The background tools ride the command runner's exec setup: like
/// `harness.exec.run`, an `exec.start` call's argv is checked against the
/// task's allowlist (H2d), so the fixture names its programs.
fn bg_spec() -> SessionSpec {
    let mut sp = spec(&BG_GRANTS);
    sp.exec_programs = vec!["cargo".to_owned(), "serve".to_owned()];
    sp
}

/// The default table (P-36 spec §9): the background tools ride the exec
/// grant; `exec.start` asks like the command runner, `exec.read` and
/// `exec.stop` are allowed without an approver.
#[test]
fn policy_default_start_asks_read_and_stop_allow() {
    let mut with = bg_spec();
    with.approver_present = true;
    let s = Session::plan(&with, &builtin_registry(), &UserPolicy::default()).unwrap();
    assert_eq!(
        s.decide(&call(EXEC_START_ID, json!({"argv": ["cargo", "test"]}))),
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::Builtin(EXEC_DEFAULT_RULE),
        }
    );
    assert_eq!(
        s.decide(&call(EXEC_READ_ID, json!({"id": 1}))),
        PolicyDecision::Allow {
            rule: RuleId::Builtin(BG_READ_RULE),
        }
    );
    assert_eq!(
        s.decide(&call(EXEC_STOP_ID, json!({"id": 1}))),
        PolicyDecision::Allow {
            rule: RuleId::Builtin(BG_STOP_RULE),
        }
    );
    // No approver: the start's ask is a deny, the allow decisions stand.
    let without = bg_spec();
    let s = Session::plan(&without, &builtin_registry(), &UserPolicy::default()).unwrap();
    assert_eq!(
        s.decide(&call(EXEC_START_ID, json!({"argv": ["cargo", "test"]}))),
        PolicyDecision::Deny {
            reason: DenyReason::NoApprover,
            rule: RuleId::Builtin("deny.no-approver"),
        }
    );
    assert!(matches!(
        s.decide(&call(EXEC_READ_ID, json!({"id": 1}))),
        PolicyDecision::Allow { .. }
    ));
}

/// A LAN port makes `exec.start` a `protected_action` ask, every time
/// (P-36 spec §6.3): never a session grant, never lowered by a user allow.
#[test]
fn lan_port_start_asks_every_time_protected_action() {
    let mut sp = bg_spec();
    sp.approver_present = true;
    sp.lan_ports = vec![8000];
    sp.workspace = Some(WorkspaceDecl {
        declared_public: true,
    });
    let s = Session::plan(&sp, &builtin_registry(), &UserPolicy::default()).unwrap();
    let c = call(EXEC_START_ID, json!({"argv": ["serve"], "ports": [8000]}));
    assert_eq!(
        s.decide(&c),
        PolicyDecision::Ask {
            tier: Confirmation::ProtectedAction,
            rule: RuleId::Builtin(LAN_BIND_RULE),
        }
    );
    // A user allow rule does not lower the floor: the same call asks again.
    let policy = UserPolicy::new(&[], &[], &[EXEC_START_ID]).unwrap();
    let allowed = Session::plan(&sp, &builtin_registry(), &policy).unwrap();
    assert_eq!(
        allowed.decide(&c),
        PolicyDecision::Ask {
            tier: Confirmation::ProtectedAction,
            rule: RuleId::Builtin(LAN_BIND_RULE),
        }
    );
    // The same tool without a LAN port takes the ordinary path: the
    // default policy's ask, and the user allow's rule where granted.
    let plain = call(EXEC_START_ID, json!({"argv": ["cargo", "test"]}));
    assert_eq!(
        s.decide(&plain),
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::Builtin(EXEC_DEFAULT_RULE),
        }
    );
    assert_eq!(
        allowed.decide(&plain),
        PolicyDecision::Allow {
            rule: RuleId::User {
                list: RuleList::Allow,
                index: 0,
            },
        }
    );
}

/// The LAN grant folds an E label into the trifecta (P-36 spec §6.3) even
/// though every granted capability keeps `egress: none`: with the default
/// private workspace P∧U∧E holds and the session is refused, naming the
/// LAN grant as the egress source (INV-9: no override).
#[test]
fn lan_ports_label_egress_for_trifecta() {
    let mut sp = bg_spec();
    sp.lan_ports = vec![8000];
    assert_eq!(
        Session::plan(&sp, &builtin_registry(), &UserPolicy::default()).unwrap_err(),
        SessionRefused::Trifecta {
            private: "workspace".into(),
            untrusted: EXEC_ID.into(),
            egress: "exec.lan_ports".into(),
        }
    );
}

/// With a public workspace the trifecta is satisfied without the LAN
/// label, so the session plans; binding the port still asks, every time.
#[test]
fn lan_ports_allowed_with_public_workspace_and_ask() {
    let mut sp = bg_spec();
    sp.approver_present = true;
    sp.lan_ports = vec![8000];
    assert!(matches!(
        Session::plan(&sp, &builtin_registry(), &UserPolicy::default()).unwrap_err(),
        SessionRefused::Trifecta { .. }
    ));
    sp.workspace = Some(WorkspaceDecl {
        declared_public: true,
    });
    let s = Session::plan(&sp, &builtin_registry(), &UserPolicy::default()).unwrap();
    assert_eq!(
        s.decide(&call(
            EXEC_START_ID,
            json!({"argv": ["serve"], "ports": [8000]})
        )),
        PolicyDecision::Ask {
            tier: Confirmation::ProtectedAction,
            rule: RuleId::Builtin(LAN_BIND_RULE),
        }
    );
}

/// A session grant stands below the LAN floor (P-36 spec §6.3, like the
/// confirmation floor): answering `a` at the prompt can never answer for a
/// LAN bind.
#[test]
fn session_grant_never_covers_lan_start() {
    let mut sp = bg_spec();
    sp.approver_present = true;
    sp.lan_ports = vec![8000];
    sp.workspace = Some(WorkspaceDecl {
        declared_public: true,
    });
    let mut s = Session::plan(&sp, &builtin_registry(), &UserPolicy::default()).unwrap();
    s.grant(
        RuleList::Allow,
        &CapId::new(EXEC_START_ID).unwrap(),
        Matcher::path_glob("**").unwrap(),
    );
    assert_eq!(
        s.decide(&call(
            EXEC_START_ID,
            json!({"argv": ["serve"], "ports": [8000]})
        )),
        PolicyDecision::Ask {
            tier: Confirmation::ProtectedAction,
            rule: RuleId::Builtin(LAN_BIND_RULE),
        }
    );
}

/// A session deny grant blocks a call a user allow matcher would let
/// through, and its decision names the session rule; outside the denied
/// pattern the allow still applies.
#[test]
fn denied_session_rule_blocks_later_allow_matcher() {
    let policy = UserPolicy::new(&[], &[], &["harness.edit.replace"]).unwrap();
    let mut s = edit_session(true, &policy);
    assert!(matches!(
        s.decide(&replace("src/lib.rs")),
        PolicyDecision::Allow { .. }
    ));
    let index = s.grant(
        RuleList::Deny,
        &CapId::new("harness.edit.replace").unwrap(),
        Matcher::path_glob("src/**").unwrap(),
    );
    assert_eq!(index, 0);
    assert_eq!(
        s.decide(&replace("src/lib.rs")),
        PolicyDecision::Deny {
            reason: DenyReason::SessionDenied,
            rule: RuleId::Session {
                list: RuleList::Deny,
                index: 0
            },
        }
    );
    assert_eq!(
        RuleId::Session {
            list: RuleList::Deny,
            index
        }
        .to_string(),
        "session.deny.0"
    );
    assert!(matches!(
        s.decide(&replace("docs/notes.md")),
        PolicyDecision::Allow { .. }
    ));
}

/// `--accept-edits` is refused when the pre-image store is missing;
/// otherwise it appends one allow rule per edit capability, idempotently
/// (replay re-applies the overlay to the already-overlaid policy).
#[test]
fn accept_edits_refused_without_pre_image_store() {
    assert!(overlay_accept_edits(UserPolicy::default(), false).is_err());
    let once = overlay_accept_edits(UserPolicy::default(), true).unwrap();
    assert_eq!(once.allow.len(), EDIT_IDS.len());
    for (index, id) in EDIT_IDS.iter().enumerate() {
        assert!(
            once.allow[index].selector.matches(&CapId::new(id).unwrap()),
            "{id}"
        );
        assert!(once.allow[index]
            .matcher
            .as_ref()
            .is_some_and(|m| m.matches(&json!({"path": "src/any.rs"}))));
    }
    let twice = overlay_accept_edits(once, true).unwrap();
    assert_eq!(twice.allow.len(), EDIT_IDS.len());
}

// ---- P-39b: the web airlock (§2.2 item 3, §2.3) ---------------------------------

/// A registry holding the research manifest (§2.2: a registry holds exactly
/// one manifest).
fn research_registry() -> Registry {
    Registry::admit(vec![(
        builtin::research_manifest(&ctx()).unwrap(),
        Tier::Builtin,
    )])
    .unwrap()
}

/// A research session spec: the research manifest's grants, no workspace, no
/// personal data, the session-start confirmation given (§2.2 item 3). One
/// allowlist entry, `example.com` (https on 443), and a search endpoint.
fn research_spec(grants: &[&str]) -> SessionSpec {
    SessionSpec {
        grants: grants.iter().map(|g| (*g).to_owned()).collect(),
        workspace: None,
        approver_present: false,
        personal_data_granted: false,
        conformed: false,
        exec_programs: Vec::new(),
        lan_ports: Vec::new(),
        read_window: None,
        kind: SessionKind::Research(WebGrant {
            allowlist: vec!["example.com".to_owned()],
            search: true,
            confirmed: Some(WebConfirmation::Tty),
        }),
    }
}

/// The registry refusal (§2.2): the coding manifest declares no web id, and
/// a coding session granting one is refused by name before anything runs.
#[test]
fn coding_registry_has_no_web_capability() {
    let reg = builtin_registry();
    assert!(matches!(
        reg.resolve(WEB_FETCH_ID),
        harness_manifest::admission::Resolved::NotFound
    ));
    assert!(matches!(
        reg.resolve(WEB_SEARCH_ID),
        harness_manifest::admission::Resolved::NotFound
    ));
    assert_eq!(
        Session::plan(&spec(&[WEB_FETCH_ID]), &reg, &UserPolicy::default()).unwrap_err(),
        SessionRefused::UnknownCapability(WEB_FETCH_ID.to_owned())
    );
}

/// The trifecta refusal (§2.2): a workspace plus a web capability is the
/// lethal triad, named from the labels themselves (P from the private
/// workspace, U and E from the fetch). A public workspace is no trifecta,
/// and a web session is still refused one (§2.2: it has no workspace).
#[test]
fn web_session_refused_with_workspace_grant() {
    let mut sp = research_spec(&[WEB_FETCH_ID]);
    sp.workspace = ws();
    assert_eq!(
        Session::plan(&sp, &research_registry(), &UserPolicy::default()).unwrap_err(),
        SessionRefused::Trifecta {
            private: "workspace".to_owned(),
            untrusted: WEB_FETCH_ID.to_owned(),
            egress: WEB_FETCH_ID.to_owned(),
        }
    );
    let mut sp = research_spec(&[WEB_FETCH_ID]);
    sp.workspace = Some(WorkspaceDecl {
        declared_public: true,
    });
    assert_eq!(
        Session::plan(&sp, &research_registry(), &UserPolicy::default()).unwrap_err(),
        SessionRefused::Web(WebSessionRefused::WorkspaceGranted)
    );
}

/// A research session grants only the four ids the research manifest
/// declares (§2.2): no file tools, no edits, no command runner. Planned over
/// both parsed manifests (the `plan_with` seam), since a real research
/// registry could not resolve them at all.
#[test]
fn research_session_refuses_fs_edit_exec_grants() {
    for g in ["harness.fs.read", "harness.edit.replace", EXEC_ID] {
        let coding = builtin::manifest(&ctx()).unwrap();
        let research = builtin::research_manifest(&ctx()).unwrap();
        assert_eq!(
            plan_over(
                &[coding, research],
                &research_spec(&[g]),
                &UserPolicy::default()
            )
            .unwrap_err(),
            SessionRefused::Web(WebSessionRefused::GrantOutsideResearch(g.to_owned())),
            "{g}"
        );
    }
}

/// A personal capability in a web session is the trifecta (§2.2): P from
/// the fixture cap, U and E from the fetch. The fixture is one the H1 gate
/// would refuse, so the seam plans over it directly.
#[test]
fn research_session_with_personal_capability_refused_by_trifecta() {
    let research = builtin::research_manifest(&ctx()).unwrap();
    let personal = fixture(vec![cap_json(
        "peek",
        ["read", "personal", "own", "none", "own", "none"],
    )]);
    assert_eq!(
        plan_over(
            &[personal, research],
            &research_spec(&["fixture.peek", WEB_FETCH_ID]),
            &UserPolicy::default()
        )
        .unwrap_err(),
        SessionRefused::Trifecta {
            private: "fixture.peek".to_owned(),
            untrusted: WEB_FETCH_ID.to_owned(),
            egress: WEB_FETCH_ID.to_owned(),
        }
    );
}

/// The session-start confirmation (§2.3): without it the session is
/// refused, whatever the grants. The egress floor is met once, for the
/// allowlist, never per fetch.
#[test]
fn research_session_without_confirmation_refused() {
    let mut sp = research_spec(&[WEB_FETCH_ID]);
    sp.kind = SessionKind::Research(WebGrant {
        allowlist: vec!["example.com".to_owned()],
        search: true,
        confirmed: None,
    });
    assert_eq!(
        Session::plan(&sp, &research_registry(), &UserPolicy::default()).unwrap_err(),
        SessionRefused::Web(WebSessionRefused::Unconfirmed)
    );
}

/// The web branch never asks (§2.3): over URL and query samples, with and
/// without an approver, every decision is `Allow` or `Deny`. With no
/// approver the allowlisted fetch and the search are still allowed: the
/// confirmation happened at session start.
#[test]
fn web_decisions_never_ask() {
    let reg = research_registry();
    for approver in [false, true] {
        let mut sp = research_spec(&[WEB_FETCH_ID, WEB_SEARCH_ID]);
        sp.approver_present = approver;
        let s = Session::plan(&sp, &reg, &UserPolicy::default()).unwrap();
        for url in [
            "https://example.com/docs",
            "http://example.com:80/x",
            "https://other.org/a",
            "https://example.com:8443",
            "notaurl",
            "",
            "https://192.0.2.1/",
        ] {
            let d = s.decide(&call(WEB_FETCH_ID, json!({ "url": url })));
            assert!(!matches!(d, PolicyDecision::Ask { .. }), "{url}: {d:?}");
        }
        for q in ["rust async", "", "\u{202e}evil", &"x".repeat(257)] {
            let d = s.decide(&call(WEB_SEARCH_ID, json!({ "query": q })));
            assert!(!matches!(d, PolicyDecision::Ask { .. }), "{q}: {d:?}");
        }
        if !approver {
            assert_eq!(
                s.decide(&call(
                    WEB_FETCH_ID,
                    json!({ "url": "https://example.com/docs" })
                )),
                PolicyDecision::Allow {
                    rule: RuleId::Builtin(WEB_ALLOWLIST_RULE)
                }
            );
            assert_eq!(
                s.decide(&call(WEB_SEARCH_ID, json!({ "query": "rust async" }))),
                PolicyDecision::Allow {
                    rule: RuleId::Builtin(WEB_SEARCH_RULE)
                }
            );
        }
    }
}

/// Per-fetch prompts are never offered (§2.2): an ask rule on a web
/// capability refuses the session at planning.
#[test]
fn ask_rule_on_web_capability_refuses_session() {
    let policy = policy_json(json!({
        "deny": [],
        "ask": [{"capability": WEB_FETCH_ID}],
        "allow": []
    }));
    assert_eq!(
        Session::plan(
            &research_spec(&[WEB_FETCH_ID]),
            &research_registry(),
            &policy
        )
        .unwrap_err(),
        SessionRefused::OutOfScope {
            capability: WEB_FETCH_ID.to_owned(),
            what: "ask rules on web capabilities (per-fetch prompts are never offered)",
        }
    );
}

/// The fetch branch names one rule per refusal (§2.3): the URL rule for a
/// bad URL, scheme when the entry differs only in scheme, port when it
/// differs only in port, and the host rule when no entry names the host.
#[test]
fn fetch_to_unlisted_host_denied_with_rule_id() {
    let s = Session::plan(
        &research_spec(&[WEB_FETCH_ID]),
        &research_registry(),
        &UserPolicy::default(),
    )
    .unwrap();
    let deny_web = |reason| PolicyDecision::Deny {
        reason: DenyReason::Web(reason),
        rule: RuleId::Builtin("deny.web.host-not-allowlisted"),
    };
    assert_eq!(
        s.decide(&call(WEB_FETCH_ID, json!({ "url": "https://other.org/a" }))),
        deny_web(WebCallRefused::HostNotAllowlisted)
    );
    let scheme_deny = |reason, name| PolicyDecision::Deny {
        reason: DenyReason::Web(reason),
        rule: RuleId::Builtin(name),
    };
    assert_eq!(
        s.decide(&call(
            WEB_FETCH_ID,
            json!({ "url": "http://example.com:443" })
        )),
        scheme_deny(WebCallRefused::Scheme, "deny.web.scheme")
    );
    assert_eq!(
        s.decide(&call(
            WEB_FETCH_ID,
            json!({ "url": "https://example.com:8443" })
        )),
        scheme_deny(WebCallRefused::Port, "deny.web.port")
    );
    assert_eq!(
        s.decide(&call(WEB_FETCH_ID, json!({ "url": "ftp://example.com/" }))),
        scheme_deny(WebCallRefused::Url(UrlRefused::Scheme), "deny.web.url")
    );
}

/// The search query's bounds are policy's (§2.3): the schema's `maxLength`
/// alone would let an empty or invisibly corrupted query through; and a
/// session with no search endpoint is refused by name.
#[test]
fn search_query_bounds_enforced() {
    let s = Session::plan(
        &research_spec(&[WEB_SEARCH_ID]),
        &research_registry(),
        &UserPolicy::default(),
    )
    .unwrap();
    for q in ["", "\u{202e}evil", "a\u{0}"] {
        assert_eq!(
            s.decide(&call(WEB_SEARCH_ID, json!({ "query": q }))),
            PolicyDecision::Deny {
                reason: DenyReason::Web(WebCallRefused::Query),
                rule: RuleId::Builtin("deny.web.query"),
            },
            "{q}"
        );
    }
    // 257 characters never reach the branch: the schema's `maxLength`
    // refuses them first, one layer earlier.
    let too_long = "x".repeat(257);
    assert!(is_deny(
        &s.decide(&call(WEB_SEARCH_ID, json!({ "query": too_long }))),
        &DenyReason::Args(ArgsError {
            at: "/query".into(),
            detail: "longer than maxLength 256".into(),
        })
    ));
    // 256 characters is allowed.
    let max = "x".repeat(256);
    assert_eq!(
        s.decide(&call(WEB_SEARCH_ID, json!({ "query": max }))),
        PolicyDecision::Allow {
            rule: RuleId::Builtin(WEB_SEARCH_RULE)
        }
    );
    // No search endpoint configured: refused by name.
    let mut sp = research_spec(&[WEB_SEARCH_ID]);
    sp.kind = SessionKind::Research(WebGrant {
        allowlist: vec!["example.com".to_owned()],
        search: false,
        confirmed: Some(WebConfirmation::Flag),
    });
    let s = Session::plan(&sp, &research_registry(), &UserPolicy::default()).unwrap();
    assert_eq!(
        s.decide(&call(WEB_SEARCH_ID, json!({ "query": "rust" }))),
        PolicyDecision::Deny {
            reason: DenyReason::Web(WebCallRefused::NoSearchEndpoint),
            rule: RuleId::Builtin("deny.web.no-search-endpoint"),
        }
    );
}

/// Defence in depth (§2.2): egress is still out of scope in coding
/// sessions, for any provider's internet capability, and a web id is
/// refused by name even over the seam a registry cannot admit.
#[test]
fn egress_still_out_of_scope_in_coding_sessions() {
    let m = fixture(vec![cap_json(
        "ping",
        [
            "read",
            "operational",
            "own",
            "internet",
            "third_party",
            "none",
        ],
    )]);
    let mut sp = spec(&["fixture.ping"]);
    sp.workspace = None; // keep the trifecta out of the way
    assert_eq!(
        plan_over(&[m], &sp, &UserPolicy::default()).unwrap_err(),
        SessionRefused::OutOfScope {
            capability: "fixture.ping".to_owned(),
            what: "egress (the allowlist proxy is H4)",
        }
    );
    let research = builtin::research_manifest(&ctx()).unwrap();
    let mut sp = spec(&[WEB_FETCH_ID]);
    sp.workspace = None;
    assert_eq!(
        plan_over(&[research], &sp, &UserPolicy::default()).unwrap_err(),
        SessionRefused::Web(WebSessionRefused::WebGrantInCoding(WEB_FETCH_ID.to_owned()))
    );
}

/// The registration table (P-39b): the web entries append after the coding
/// table, which keeps its ids and kinds (the delegate row sits between todo
/// and submit, P-38; the P-36g background tools sit between the command
/// runner and todo; the default decisions themselves are pinned by
/// `policy_default_table_unchanged`, which iterates the twelve coding ids),
/// and the default deny table is untouched.
#[test]
fn web_entries_append_after_the_coding_table() {
    const WANT: [(&str, crate::builtin::ToolKind); 18] = [
        ("harness.fs.read", crate::builtin::ToolKind::Fs),
        ("harness.fs.search", crate::builtin::ToolKind::Fs),
        ("harness.fs.glob", crate::builtin::ToolKind::Fs),
        ("harness.fs.list", crate::builtin::ToolKind::Fs),
        ("harness.fs.outline", crate::builtin::ToolKind::Fs),
        ("harness.edit.replace", crate::builtin::ToolKind::Edit),
        ("harness.edit.write", crate::builtin::ToolKind::Edit),
        ("harness.edit.multi", crate::builtin::ToolKind::Edit),
        ("harness.edit.patch", crate::builtin::ToolKind::Edit),
        ("harness.edit.delete", crate::builtin::ToolKind::Edit),
        ("harness.edit.move", crate::builtin::ToolKind::Edit),
        ("harness.exec.run", crate::builtin::ToolKind::Exec),
        ("harness.exec.start", crate::builtin::ToolKind::ExecBg),
        ("harness.exec.read", crate::builtin::ToolKind::ExecBg),
        ("harness.exec.stop", crate::builtin::ToolKind::ExecBg),
        ("harness.task.todo", crate::builtin::ToolKind::Todo),
        ("harness.task.delegate", crate::builtin::ToolKind::Delegate),
        ("harness.task.submit", crate::builtin::ToolKind::Submit),
    ];
    for (t, want) in crate::builtin::BUILTIN_TOOLS.iter().zip(WANT) {
        assert_eq!(t.id, want.0);
        assert_eq!(t.kind, want.1);
    }
    assert_eq!(crate::builtin::BUILTIN_TOOLS.len(), 20);
    assert_eq!(crate::builtin::BUILTIN_TOOLS[18].id, WEB_FETCH_ID);
    assert_eq!(crate::builtin::BUILTIN_TOOLS[19].id, WEB_SEARCH_ID);
    assert!(matches!(
        crate::builtin::BUILTIN_TOOLS[18].kind,
        crate::builtin::ToolKind::Web
    ));
    assert!(matches!(
        crate::builtin::BUILTIN_TOOLS[19].kind,
        crate::builtin::ToolKind::Web
    ));
    assert_eq!(DEFAULT_DENY_GLOBS.len(), 10);
}

// ---- P-25: the delete/move file operations --------------------------------------

/// The file operations declare `user_confirm`, so the confirmation floor
/// asks no matter what the user's rules say: an allow rule (a section-3
/// check) can never reach them, and with no approver they deny.
#[test]
fn delete_move_ask_always_not_allow_listed() {
    let r = builtin_registry();
    let grants = spec(&[
        "harness.fs.read",
        "harness.edit.delete",
        "harness.edit.move",
    ]);
    let p = UserPolicy::new(&[], &[], &["harness.edit.delete", "harness.edit.move"]).unwrap();

    // No approver: the ask floor is a deny, allow rules unreachable.
    let s = Session::plan(&grants, &r, &p).unwrap();
    for (cap, args) in [
        ("harness.edit.delete", json!({"path": "a.txt"})),
        ("harness.edit.move", json!({"path": "a.txt", "to": "b.txt"})),
    ] {
        assert!(
            is_deny(&s.decide(&call(cap, args)), &DenyReason::NoApprover),
            "{cap} allow-listed anyway"
        );
    }

    // With an approver the ask is the floor's, never the user's rule.
    let mut asker = grants;
    asker.approver_present = true;
    let s = Session::plan(&asker, &r, &p).unwrap();
    assert_eq!(
        s.decide(&call("harness.edit.delete", json!({"path": "a.txt"}))),
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::Builtin("ask.confirmation-floor")
        },
    );
    assert_eq!(
        s.decide(&call(
            "harness.edit.move",
            json!({"path": "a.txt", "to": "b.txt"})
        )),
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::Builtin("ask.confirmation-floor")
        },
    );

    // Deny rules still win (section 1) before the ask.
    let p = UserPolicy::new(&["harness.edit.delete"], &[], &[]).unwrap();
    let s = Session::plan(&asker, &r, &p).unwrap();
    assert!(is_deny(
        &s.decide(&call("harness.edit.delete", json!({"path": "a.txt"}))),
        &DenyReason::UserDenied
    ));
}

/// A move's `to` path is a workspace path like `path`: outside the
/// workspace it denies, a `path_glob` deny rule on it denies, and a
/// `path_glob` ask rule on it raises the ask floor.
#[test]
fn move_target_paths_are_checked_like_the_source() {
    let r = builtin_registry();
    let grants = spec(&["harness.fs.read", "harness.edit.move"]);
    let args = json!({"path": "a.txt", "to": "../escape.txt"});

    // Outside the workspace, allow rule or not.
    let p = UserPolicy::new(&[], &[], &["harness.edit.move"]).unwrap();
    let s = Session::plan(&grants, &r, &p).unwrap();
    assert!(is_deny(
        &s.decide(&call("harness.edit.move", args)),
        &DenyReason::Path(PathRefused::Parent)
    ));

    // A deny glob on the target denies (the source is harmless).
    let mut sp = grants.clone();
    sp.approver_present = true;
    let p = UserPolicy::from_json(&json!({
        "deny": [{"capability": "harness.edit.move", "match": {"path_glob": "secret/**"}}]
    }))
    .unwrap();
    let s = Session::plan(&sp, &r, &p).unwrap();
    assert!(is_deny(
        &s.decide(&call(
            "harness.edit.move",
            json!({"path": "a.txt", "to": "secret/b.txt"})
        )),
        &DenyReason::UserDenied
    ));

    // An ask glob on the target asks even though the source is allowed.
    let p = UserPolicy::from_json(&json!({
        "ask": [{"capability": "harness.edit.move", "match": {"path_glob": "secret/**"}}],
        "allow": ["harness.edit.move"]
    }))
    .unwrap();
    let s = Session::plan(&sp, &r, &p).unwrap();
    assert_eq!(
        s.decide(&call(
            "harness.edit.move",
            json!({"path": "a.txt", "to": "secret/b.txt"})
        )),
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::User {
                list: RuleList::Ask,
                index: 0
            }
        }
    );
}

// ---- P-37b: policy planning for MCP capabilities (§5.4, §6.3, §9 step 1) ------

#[test]
fn mcp_capability_without_conformed_refused_at_planning() {
    let m = fixture(vec![cap_json("read", READ_OWN)]);
    let r = pinned(m);
    let mut sp = spec(&["fixture.read"]);
    // INV-6: the capability is a confined server process; no `Conformed`
    // witness, no session, at planning, before anything starts.
    sp.conformed = false;
    assert_eq!(
        Session::plan(&sp, &r, &UserPolicy::default()).unwrap_err(),
        SessionRefused::NoConfinement("fixture.read".into())
    );
    // With a witness the read plans; there is no unconfined fallback.
    sp.conformed = true;
    assert!(Session::plan(&sp, &r, &UserPolicy::default()).is_ok());
}

#[test]
fn pinned_tier_read_capability_asks_by_default() {
    let m = fixture(vec![cap_json("read", READ_OWN)]);
    let r = pinned(m);
    // §6.3: every pinned capability gets the derived floor `user_confirm`,
    // so it asks unless a user rule covers it — even a plain read that a
    // built-in tool would default-allow.
    let mut sp = spec(&["fixture.read"]);
    sp.approver_present = true;
    let s = Session::plan(&sp, &r, &UserPolicy::default()).unwrap();
    assert_eq!(
        s.decide(&call("fixture.read", json!({}))),
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::Builtin(MCP_DEFAULT_RULE),
        }
    );
    // With nobody to answer, the ask is a deny (§5.2).
    sp.approver_present = false;
    let s = Session::plan(&sp, &r, &UserPolicy::default()).unwrap();
    assert!(is_deny(
        &s.decide(&call("fixture.read", json!({}))),
        &DenyReason::NoApprover
    ));
}

#[test]
fn pinned_tier_allow_rule_allows_unattended() {
    let m = fixture(vec![cap_json("read", READ_OWN)]);
    let r = pinned(m);
    for selector in ["fixture.read", "fixture.*"] {
        let p = UserPolicy::new(&[], &[], &[selector]).unwrap();
        let mut sp = spec(&["fixture.read"]);
        sp.approver_present = false;
        let s = Session::plan(&sp, &r, &p).unwrap();
        // The allow rule is consulted before the pinned default ask, so
        // the capability runs with no approver present.
        assert_eq!(
            s.decide(&call("fixture.read", json!({}))),
            PolicyDecision::Allow {
                rule: RuleId::User {
                    list: RuleList::Allow,
                    index: 0
                }
            },
            "{selector}"
        );
        assert!(
            s.authorize(call("fixture.read", json!({}))).is_ok(),
            "{selector}"
        );
    }
}

#[test]
fn mcp_protected_action_never_allowed_by_rule() {
    // A derived `protected_action` floor (blast radius shared here; an
    // `irreversible` effect refuses at planning, above). Admission would
    // refuse a pinned manifest that declares `shared`, so this plans over
    // the seam — the decision order must still never lower the floor.
    let m = fixture(vec![cap_json(
        "w",
        ["write", "operational", "shared", "none", "own", "none"],
    )]);
    let p = UserPolicy::new(&[], &[], &["fixture.*"]).unwrap();
    let mut sp = spec(&["fixture.w"]);
    sp.workspace = None;
    sp.approver_present = true;
    let s = plan_over(std::slice::from_ref(&m), &sp, &p).unwrap();
    assert_eq!(
        s.class("fixture.w").unwrap().confirmation,
        Confirmation::ProtectedAction
    );
    // The floor asks at step 2, BEFORE any allow rule: the user allow
    // above can never allow it.
    assert_eq!(
        s.decide(&call("fixture.w", json!({}))),
        PolicyDecision::Ask {
            tier: Confirmation::ProtectedAction,
            rule: RuleId::Builtin("ask.confirmation-floor"),
        }
    );
    assert!(s.authorize(call("fixture.w", json!({}))).is_err());
}

#[test]
fn mcp_write_capability_plans_and_asks() {
    let m = fixture(vec![cap_json(
        "w",
        ["write", "operational", "own", "none", "own", "none"],
    )]);
    let r = pinned(m);
    // Planning succeeds where a non-mcp write is refused: the provider
    // declared the class, and the pinned default decides it.
    let mut sp = spec(&["fixture.w"]);
    sp.approver_present = true;
    let s = Session::plan(&sp, &r, &UserPolicy::default()).unwrap();
    assert_eq!(
        s.decide(&call("fixture.w", json!({}))),
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::Builtin(MCP_DEFAULT_RULE),
        }
    );
    assert!(matches!(
        s.authorize(call("fixture.w", json!({}))),
        Err(PolicyDecision::Ask { .. })
    ));
    // No approver: the ask is a deny (§5.2).
    sp.approver_present = false;
    let s = Session::plan(&sp, &r, &UserPolicy::default()).unwrap();
    assert!(is_deny(
        &s.decide(&call("fixture.w", json!({}))),
        &DenyReason::NoApprover
    ));
}

#[test]
fn mcp_egress_capability_refused_until_proxy() {
    let m = fixture(vec![cap_json(
        "fetch",
        ["read", "public", "own", "internet", "third_party", "none"],
    )]);
    let r = pinned(m);
    let mut sp = spec(&["fixture.fetch"]);
    sp.workspace = None; // keep the trifecta out of the way: this is egress
    assert_eq!(
        Session::plan(&sp, &r, &UserPolicy::default()).unwrap_err(),
        SessionRefused::OutOfScope {
            capability: "fixture.fetch".into(),
            what: "egress (the allowlist proxy is H4)",
        }
    );
    // The lift is per process: even the granted sibling of an egress tool
    // carries its egress label, so the session refuses all the same.
    let m = fixture(vec![
        cap_json("read", READ_OWN),
        cap_json(
            "fetch",
            ["read", "public", "own", "lan", "third_party", "none"],
        ),
    ]);
    let r = pinned(m);
    let mut sp = spec(&["fixture.read"]);
    sp.workspace = None;
    assert!(matches!(
        Session::plan(&sp, &r, &UserPolicy::default()).unwrap_err(),
        SessionRefused::OutOfScope {
            what: "egress (the allowlist proxy is H4)",
            ..
        }
    ));
}

#[test]
fn process_label_lift_marks_sibling_capability_third_party() {
    // One manifest, two tools, only the own-content one granted: the
    // labels are per PROCESS (§5.4), so the granted capability carries
    // its sibling's third-party content.
    let m = fixture(vec![
        cap_json("read", READ_OWN),
        cap_json(
            "readweb",
            ["read", "operational", "own", "none", "third_party", "none"],
        ),
    ]);
    let r = pinned(m);
    let sp = spec(&["fixture.read"]);
    let s = Session::plan(&sp, &r, &UserPolicy::default()).unwrap();
    assert_eq!(
        s.class("fixture.read").unwrap().content,
        Content::ThirdParty
    );
    // The lifted labels feed the trifecta: with the workspace supplying P
    // and the process supplying U and E through the GRANTED capability,
    // the session refuses and names the granted capability as the source.
    let m = fixture(vec![
        cap_json("read", READ_OWN),
        cap_json(
            "readweb",
            ["read", "operational", "own", "none", "third_party", "none"],
        ),
        cap_json(
            "net",
            ["read", "public", "own", "internet", "third_party", "none"],
        ),
    ]);
    let r = pinned(m);
    assert_eq!(
        Session::plan(&sp, &r, &UserPolicy::default()).unwrap_err(),
        SessionRefused::Trifecta {
            private: "workspace".into(),
            untrusted: "fixture.read".into(),
            egress: "fixture.read".into(),
        }
    );
    // Sensitivity lifts the same way (the seam: admission refuses a pinned
    // manifest that declares personal data, the decision order still sees it).
    let m = fixture(vec![
        cap_json("read", READ_OWN),
        cap_json(
            "contacts",
            ["read", "personal", "own", "none", "own", "none"],
        ),
    ]);
    let s = plan_over(
        std::slice::from_ref(&m),
        &spec(&["fixture.read"]),
        &UserPolicy::default(),
    )
    .unwrap();
    assert_eq!(
        s.class("fixture.read").unwrap().sensitivity,
        Sensitivity::Personal
    );
}

#[test]
fn quarantined_mcp_capability_denied_with_rule_id() {
    let m = fixture(vec![cap_json("read", READ_OWN)]);
    let r = pinned(m);
    let mut s = Session::plan(&spec(&["fixture.read"]), &r, &UserPolicy::default()).unwrap();
    s.quarantine(&CapId::new("fixture.read").unwrap()).unwrap();
    assert_eq!(
        s.decide(&call("fixture.read", json!({}))),
        PolicyDecision::Deny {
            reason: DenyReason::Quarantined,
            rule: RuleId::Builtin("deny.quarantined"),
        }
    );
}

#[test]
fn quarantine_recomputes_trifecta_and_never_widens() {
    // A planned session whose trifecta inputs are the lifted labels plus
    // the workspace: removing capabilities can only shrink them, so every
    // quarantine recomputes to Ok, and the survivors' labels never widen.
    let m = fixture(vec![
        cap_json("read", READ_OWN),
        cap_json(
            "readweb",
            ["read", "operational", "own", "none", "third_party", "none"],
        ),
    ]);
    let r = pinned(m);
    let mut s = Session::plan(
        &spec(&["fixture.read", "fixture.readweb"]),
        &r,
        &UserPolicy::default(),
    )
    .unwrap();
    let before = s.class("fixture.readweb").unwrap();
    for id in ["fixture.read", "fixture.readweb"] {
        assert!(
            s.quarantine(&CapId::new(id).unwrap()).is_ok(),
            "{id}: removal widened the trifecta"
        );
    }
    assert_eq!(
        s.class("fixture.readweb").unwrap(),
        before,
        "labels never widen"
    );
    // The recompute is real: over a set (unreachable by planning) that
    // still holds P ∧ U ∧ E after a removal, it refuses and names the
    // surviving egress source.
    let mut active = BTreeMap::new();
    for (verb, dims) in [
        ("p", ["read", "personal", "own", "none", "own", "none"]),
        (
            "u",
            ["read", "public", "own", "none", "third_party", "none"],
        ),
        ("e1", ["read", "public", "own", "lan", "own", "none"]),
        ("e2", ["read", "public", "own", "internet", "own", "none"]),
    ] {
        let fm = fixture(vec![cap_json(verb, dims)]);
        let c = &fm.capabilities()[0];
        active.insert(
            c.id().clone(),
            Active {
                class: effective_class(c, Confirmation::None),
                schema: c.input_schema().clone(),
                user_deny: Vec::new(),
                user_ask: Vec::new(),
                user_allow: Vec::new(),
                fs_tool: false,
                submit: false,
                todo: false,
                delegate: false,
                edit: false,
                exec: false,
                web_fetch: false,
                exec_start: false,
                exec_read: false,
                exec_stop: false,
                web_search: false,
                mcp: false,
            },
        );
    }
    let mut s = Session {
        active,
        quarantined: BTreeSet::new(),
        approver_present: true,
        personal_granted: true,
        conformed: true,
        exec_programs: BTreeSet::new(),
        lan_ports: BTreeSet::new(),
        read_window: None,
        session_deny: BTreeMap::new(),
        session_allow: BTreeMap::new(),
        web: None,
        workspace: None,
    };
    assert_eq!(
        s.quarantine(&CapId::new("fixture.e1").unwrap()),
        Err(SessionRefused::Trifecta {
            private: "fixture.p".into(),
            untrusted: "fixture.u".into(),
            egress: "fixture.e2".into(),
        })
    );
    // The refused recompute still quarantined the capability it named.
    assert!(is_deny(
        &s.decide(&call("fixture.e1", json!({}))),
        &DenyReason::Quarantined
    ));
}

#[test]
fn builtin_decisions_unchanged() {
    // P-37b touches the mcp-stdio rows only; the built-in tools decide
    // exactly as before, rule ids included.
    let r = builtin_registry();
    let mut sp = spec(&[
        "harness.fs.read",
        "harness.edit.replace",
        "harness.exec.run",
        "harness.task.submit",
        "harness.task.todo",
    ]);
    sp.approver_present = true;
    sp.conformed = true;
    sp.exec_programs = vec!["cargo".to_owned()];
    let s = Session::plan(&sp, &r, &UserPolicy::default()).unwrap();
    assert_eq!(
        s.decide(&call("harness.fs.read", json!({"path": "a"}))),
        PolicyDecision::Allow {
            rule: RuleId::Builtin("allow.default.read")
        }
    );
    assert_eq!(
        s.decide(&call(
            "harness.edit.replace",
            json!({"path": "a", "old": "x", "new": "y"})
        )),
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::Builtin(EDIT_DEFAULT_RULE),
        }
    );
    assert_eq!(
        s.decide(&call(
            "harness.exec.run",
            json!({"argv": ["cargo", "test"], "cwd": "."})
        )),
        PolicyDecision::Ask {
            tier: Confirmation::UserConfirm,
            rule: RuleId::Builtin(EXEC_DEFAULT_RULE),
        }
    );
    assert_eq!(
        s.decide(&call("harness.task.submit", json!({"note": "done"}))),
        PolicyDecision::Allow {
            rule: RuleId::Builtin("allow.task-submit")
        }
    );
    assert_eq!(
        s.decide(&call("harness.task.todo", json!({}))),
        PolicyDecision::Allow {
            rule: RuleId::Builtin(TODO_RULE)
        }
    );
    // An ungranted capability denies as before, and so do bad arguments.
    assert!(is_deny(
        &s.decide(&call("fixture.read", json!({}))),
        &DenyReason::NotGranted
    ));
    assert!(matches!(
        s.decide(&call("harness.fs.read", json!({}))),
        PolicyDecision::Deny {
            reason: DenyReason::Args(_),
            rule: RuleId::Builtin("deny.args-schema"),
        }
    ));
}
