//! Manifest v1 tests. Invariant tests are named `inv_<n>_…` so the report's
//! INV → test map can be checked with `cargo test inv_`.

use super::admission::{AdmissionError, Registry, Resolved, Tier};
use super::*;
use serde_json::{json, Value};

const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn v(major: u64, minor: u64, patch: u64) -> SemVer {
    SemVer {
        major,
        minor,
        patch,
    }
}

fn ctx() -> ValidationContext {
    ValidationContext::new(v(0, 0, 1), &[]).unwrap()
}

/// A well-formed external (mcp-stdio) manifest for a provider the harness
/// codebase knows nothing about.
fn fixture() -> Value {
    json!({
        "schema_version": 1,
        "provider": "fixture",
        "provider_version": "1.2.3",
        "min_harness": "0.0.1",
        "transport": {"kind": "mcp-stdio", "argv": ["/opt/fixture/bin/server"], "env_allow": ["FIXTURE_HOME"]},
        "mcp_protocols": ["2025-06-18"],
        "capabilities": [{
            "id": "fixture.item.read",
            "mcp_name": "read_item",
            "summary": "Read one item",
            "effect": "read",
            "sensitivity": "operational",
            "blast_radius": "own",
            "egress": "none",
            "content": "own",
            "confirmation": "none",
            "input_schema": {"type": "object", "additionalProperties": false,
                             "properties": {"key": {"type": "string", "maxLength": 64}},
                             "required": ["key"]},
            "schema_sha256": PIN,
            "description_sha256": PIN
        }]
    })
}

fn parse_v(val: &Value) -> Result<Manifest, ManifestError> {
    Manifest::parse(val.to_string().as_bytes(), &ctx())
}

fn parse_s(s: &str) -> Result<Manifest, ManifestError> {
    Manifest::parse(s.as_bytes(), &ctx())
}

fn cap0(val: &mut Value) -> &mut Value {
    &mut val["capabilities"][0]
}

#[test]
fn dimension_names_are_the_wire_names() {
    fn wire<T: serde::de::DeserializeOwned + PartialEq + std::fmt::Debug>(t: T, name: &str) {
        assert_eq!(
            serde_json::from_value::<T>(json!(name)).unwrap(),
            t,
            "{name}"
        );
    }
    // Each list sits behind a wildcard-free match: a new variant does not
    // compile until it has an arm here, next to the list it must join.
    let effects = [
        Effect::Read,
        Effect::Write,
        Effect::Execute,
        Effect::Irreversible,
    ];
    let _ = |e: Effect| match e {
        Effect::Read | Effect::Write | Effect::Execute | Effect::Irreversible => (),
    };
    let sensitivities = [
        Sensitivity::Public,
        Sensitivity::Operational,
        Sensitivity::Personal,
        Sensitivity::Restricted,
    ];
    let _ = |s: Sensitivity| match s {
        Sensitivity::Public
        | Sensitivity::Operational
        | Sensitivity::Personal
        | Sensitivity::Restricted => (),
    };
    let blasts = [BlastRadius::Own, BlastRadius::Host, BlastRadius::Shared];
    let _ = |b: BlastRadius| match b {
        BlastRadius::Own | BlastRadius::Host | BlastRadius::Shared => (),
    };
    let egresses = [Egress::None, Egress::Lan, Egress::Internet];
    let _ = |g: Egress| match g {
        Egress::None | Egress::Lan | Egress::Internet => (),
    };
    let contents = [Content::Own, Content::ThirdParty];
    let _ = |c: Content| match c {
        Content::Own | Content::ThirdParty => (),
    };
    let confirmations = [
        Confirmation::None,
        Confirmation::UserConfirm,
        Confirmation::ProtectedAction,
    ];
    let _ = |c: Confirmation| match c {
        Confirmation::None | Confirmation::UserConfirm | Confirmation::ProtectedAction => (),
    };
    for e in effects {
        wire(e, e.as_str());
    }
    for s in sensitivities {
        wire(s, s.as_str());
    }
    for b in blasts {
        wire(b, b.as_str());
    }
    for g in egresses {
        wire(g, g.as_str());
    }
    for c in contents {
        wire(c, c.as_str());
    }
    for c in confirmations {
        wire(c, c.as_str());
    }
}

/// H1f-2 review F-1: text from a refused manifest reaches a terminal only
/// escaped. Unknown field names, unknown enum values and the keys on a
/// null value's path are all chosen by the manifest's author.
#[test]
fn refusals_never_carry_raw_control_or_bidi_characters() {
    let hostile = "\u{1b}[1A\u{1b}[2K\rOK forged \u{202e}\u{7}\u{2028}";
    // serde_json writes the text escaped, so the strict reader accepts the
    // JSON and the raw characters reach the refusal paths.
    let mut unknown_field = fixture();
    unknown_field[hostile] = json!(1);
    let mut unknown_value = fixture();
    cap0(&mut unknown_value)["effect"] = json!(hostile);
    let mut null_key = fixture();
    cap0(&mut null_key)["input_schema"]["properties"][hostile] = Value::Null;
    for v in [unknown_field, unknown_value, null_key] {
        let e = parse_v(&v).unwrap_err().to_string();
        assert!(
            !e.chars().any(|c| c.is_control()
                || is_invisible_or_bidi(c)
                || matches!(c, '\u{2028}' | '\u{2029}')),
            "{e:?}"
        );
        assert!(e.contains("\\u{1B}"), "the ESC is shown escaped: {e}");
    }
    assert_eq!(display_safe("a\\b", 80), "a\\\\b");
    assert_eq!(display_safe("abcdef", 3), "abc");
}

#[test]
fn fixture_manifest_validates() {
    let m = parse_v(&fixture()).unwrap();
    assert_eq!(m.provider().as_str(), "fixture");
    assert_eq!(m.origin(), Origin::External);
    assert_eq!(m.capabilities().len(), 1);
    assert_eq!(m.capabilities()[0].schema_sha256, Sha256Pin::parse_hex(PIN));
}

// ---- built-in manifest ------------------------------------------------------

#[test]
fn builtin_manifest_declares_exactly_the_h1_read_tools_and_the_sentinel() {
    let m = builtin::manifest(&ctx()).unwrap();
    assert_eq!(m.provider().as_str(), BUILTIN_NAMESPACE);
    assert_eq!(m.origin(), Origin::Compiled);
    assert_eq!(m.transport(), &Transport::Builtin);
    let ids: Vec<&str> = m.capabilities().iter().map(|c| c.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "harness.fs.read",
            "harness.fs.search",
            "harness.fs.list",
            "harness.task.submit"
        ]
    );
    let submit = &m.capabilities()[3];
    assert_eq!(
        (submit.effect, submit.sensitivity, submit.content),
        (Effect::Write, Sensitivity::Public, Content::Own)
    );
    for c in m.capabilities().iter().take(3) {
        assert_eq!(c.effect, Effect::Read, "{}", c.id);
        assert_eq!(c.sensitivity, Sensitivity::Operational, "{}", c.id);
        assert_eq!(c.blast_radius, BlastRadius::Own, "{}", c.id);
        assert_eq!(c.egress, Egress::None, "{}", c.id);
        assert_eq!(c.confirmation, Confirmation::None, "{}", c.id);
        assert!(c.secrets.is_empty() && c.mcp_name.is_none() && c.schema_sha256.is_none());
    }
}

#[test]
fn builtin_manifest_refused_by_an_older_harness() {
    let old = ValidationContext::new(v(0, 0, 0), &[]).unwrap();
    assert!(matches!(
        builtin::manifest(&old),
        Err(ManifestError::HarnessTooOld { .. })
    ));
}

#[test]
fn builtin_text_is_refused_when_loaded_from_outside() {
    // The same bytes, arriving as an external manifest: reserved namespace.
    assert_eq!(
        parse_s(builtin::BUILTIN_MANIFEST_JSON),
        Err(ManifestError::ReservedProvider("harness".into()))
    );
    // Renamed to dodge the reserved name, it still cannot claim `builtin`.
    let renamed = builtin::BUILTIN_MANIFEST_JSON
        .replace("\"provider\": \"harness\"", "\"provider\": \"imposter\"")
        .replace("\"harness.fs.", "\"imposter.fs.");
    assert_eq!(
        parse_s(&renamed),
        Err(ManifestError::BuiltinTransportExternal)
    );
}

// ---- INV-1: closed sets, versions, reserved names -----------------------------

#[test]
fn inv_1_unknown_fields_refused_at_every_level() {
    let mut top = fixture();
    top["surprise"] = json!(1);
    let mut cap = fixture();
    cap0(&mut cap)["risk_tier"] = json!("low");
    let mut transport = fixture();
    transport["transport"]["cwd"] = json!("/");
    let mut limits = fixture();
    cap0(&mut limits)["limits"] = json!({"timeout_ms": 5, "retries": 3});
    for (name, m) in [
        ("top", top),
        ("capability", cap),
        ("transport", transport),
        ("limits", limits),
    ] {
        assert!(
            matches!(
                parse_v(&m),
                Err(ManifestError::Shape {
                    kind: ShapeKind::UnknownField,
                    ..
                })
            ),
            "{name}: {:?}",
            parse_v(&m)
        );
    }
}

#[test]
fn inv_1_unknown_dimension_values_refused() {
    for (field, bad) in [
        ("effect", "delete"),
        ("sensitivity", "secret"),
        ("blast_radius", "third_party"),
        ("egress", "wan"),
        ("content", "mixed"),
        ("confirmation", "maybe"),
    ] {
        let mut m = fixture();
        cap0(&mut m)[field] = json!(bad);
        assert!(
            matches!(
                parse_v(&m),
                Err(ManifestError::Shape {
                    kind: ShapeKind::UnknownValue,
                    ..
                })
            ),
            "{field}={bad}: {:?}",
            parse_v(&m)
        );
    }
    // Absent dimension: refused, never defaulted to the harmless end.
    let mut m = fixture();
    cap0(&mut m).as_object_mut().unwrap().remove("sensitivity");
    assert!(matches!(
        parse_v(&m),
        Err(ManifestError::Shape {
            kind: ShapeKind::MissingField,
            ..
        })
    ));
}

#[test]
fn inv_1_versions_v0_and_v2_refused_naming_both() {
    let v0 = r#"{"schema_version":0,"app":"example","app_version":"0.0.1",
        "capabilities":[{"id":"example.status.read","summary":"s","effect":"read"}]}"#;
    let e = parse_s(v0).unwrap_err();
    assert_eq!(e, ManifestError::SchemaV0 { supported: &[1] });
    assert!(e.to_string().contains("migrate"), "{e}");

    let mut v2 = fixture();
    v2["schema_version"] = json!(2);
    let e = parse_v(&v2).unwrap_err();
    assert_eq!(
        e,
        ManifestError::UnsupportedSchema {
            found: 2,
            supported: &[1]
        }
    );
    let msg = e.to_string();
    assert!(msg.contains('2') && msg.contains("[1]"), "{msg}");

    for bad in [json!("1"), json!(1.0), json!(-1), Value::Null] {
        let mut m = fixture();
        m["schema_version"] = bad.clone();
        assert!(parse_v(&m).is_err(), "schema_version {bad} must be refused");
    }
}

#[test]
fn inv_1_reserved_names_refused_whatever_the_config_says() {
    let configs: [&[String]; 3] = [
        &[],
        &["other".to_string()],
        &["harness-x".to_string(), "vault".to_string()],
    ];
    for extra in configs {
        let c = ValidationContext::new(v(0, 0, 1), extra).unwrap();
        for name in RESERVED_NAMESPACES {
            let mut m = fixture();
            m["provider"] = json!(name);
            cap0(&mut m)["id"] = json!(format!("{name}.item.read"));
            assert_eq!(
                Manifest::parse(m.to_string().as_bytes(), &c),
                Err(ManifestError::ReservedProvider((*name).into())),
                "{name} with extra_reserved {extra:?}"
            );
        }
    }
}

#[test]
fn inv_1_config_adds_reserved_names_but_cannot_remove() {
    let c = ValidationContext::new(v(0, 0, 1), &["fixture".to_string()]).unwrap();
    assert_eq!(
        Manifest::parse(fixture().to_string().as_bytes(), &c),
        Err(ManifestError::ReservedProvider("fixture".into()))
    );
    for name in RESERVED_NAMESPACES {
        assert!(c.is_reserved(name));
    }
    // A malformed extra name is a config error, not silently ignored.
    assert!(ValidationContext::new(v(0, 0, 1), &["Bad Name".to_string()]).is_err());
}

#[test]
fn inv_1_reserved_name_checked_before_capabilities() {
    // Every capability is broken, but the refusal names the reserved provider.
    let mut m = fixture();
    m["provider"] = json!("rustyvault");
    cap0(&mut m)["id"] = json!("NOT AN ID");
    cap0(&mut m)["effect"] = json!("delete");
    assert_eq!(
        parse_v(&m),
        Err(ManifestError::ReservedProvider("rustyvault".into()))
    );
}

// ---- INV-22: duplicate keys ------------------------------------------------------

#[test]
fn inv_22_duplicate_keys_refused_at_every_depth() {
    let body = fixture().to_string();
    // Top level: a second schema_version (the version-confusion case).
    let top = body.replacen('{', r#"{"schema_version":0,"#, 1);
    // Capability level.
    let cap = body.replacen(
        r#""effect":"read""#,
        r#""effect":"read","effect":"write""#,
        1,
    );
    // Inside the input schema.
    let schema = body.replacen(
        r#""additionalProperties":false"#,
        r#""additionalProperties":false,"additionalProperties":true"#,
        1,
    );
    // Inside the transport.
    let transport = body.replacen(
        r#""kind":"mcp-stdio""#,
        r#""kind":"mcp-stdio","kind":"builtin""#,
        1,
    );
    for (name, s) in [
        ("top", top),
        ("capability", cap),
        ("schema", schema),
        ("transport", transport),
    ] {
        assert_ne!(s, body, "{name}: the duplicate was not planted");
        assert!(
            matches!(parse_s(&s), Err(ManifestError::DuplicateKey(_))),
            "{name}: {:?}",
            parse_s(&s)
        );
    }
}

// ---- INV-8 (manifest half): ids stay inside their namespace ----------------------

#[test]
fn inv_8_foreign_namespace_ids_refused() {
    for id in [
        "rustyvault.secret.read",
        "fixturex.item.read",
        "other.fixture.item",
    ] {
        let mut m = fixture();
        cap0(&mut m)["id"] = json!(id);
        assert!(
            matches!(parse_v(&m), Err(ManifestError::ForeignNamespace { .. })),
            "{id}"
        );
    }
}

#[test]
fn inv_8_two_providers_cannot_share_a_namespace() {
    let a = parse_v(&fixture()).unwrap();
    let b = parse_v(&fixture()).unwrap();
    let pin = Sha256Pin::parse_hex(PIN).unwrap();
    let err = Registry::admit(vec![
        (
            a,
            Tier::Pinned {
                manifest_sha256: pin,
            },
        ),
        (b, Tier::Signed { key_id: "k".into() }),
    ])
    .unwrap_err();
    assert_eq!(err, AdmissionError::Shadowed("fixture".into()));
}

// ---- other §4.3 content checks ---------------------------------------------------

#[test]
fn duplicate_ids_empty_list_and_double_mcp_mapping_refused() {
    let mut dup = fixture();
    let c = cap0(&mut dup).clone();
    let mut c2 = c.clone();
    c2["mcp_name"] = json!("read_item_2");
    dup["capabilities"].as_array_mut().unwrap().push(c2);
    assert_eq!(
        parse_v(&dup),
        Err(ManifestError::DuplicateId("fixture.item.read".into()))
    );

    let mut empty = fixture();
    empty["capabilities"] = json!([]);
    assert_eq!(
        parse_v(&empty),
        Err(ManifestError::NoCapabilities("fixture".into()))
    );

    let mut twice = fixture();
    let mut c3 = c;
    c3["id"] = json!("fixture.item.list");
    twice["capabilities"].as_array_mut().unwrap().push(c3);
    assert_eq!(
        parse_v(&twice),
        Err(ManifestError::DuplicateMcpName("read_item".into()))
    );
}

#[test]
fn name_grammar_from_the_scaffold_review_holds() {
    for bad in [
        "",
        "Fixture",
        "fix ture",
        "fix.ture",
        "fixture\t",
        "fixt\u{FF0E}ure",
    ] {
        let mut m = fixture();
        m["provider"] = json!(bad);
        assert!(parse_v(&m).is_err(), "provider {bad:?}");
    }
    let mut long = fixture();
    long["provider"] = json!("a".repeat(65));
    assert!(parse_v(&long).is_err());
    for bad in [
        "fixture.",
        "fixture..read",
        "fixture.item.",
        "fixture.Item.read",
        "fixture.item.re ad",
        "fixture.item.re\u{1F600}ad",
        ".fixture.item",
    ] {
        let mut m = fixture();
        cap0(&mut m)["id"] = json!(bad);
        assert!(parse_v(&m).is_err(), "id {bad:?}");
    }
    let mut m = fixture();
    cap0(&mut m)["id"] = json!(format!("fixture.{}", "a".repeat(200)));
    assert!(parse_v(&m).is_err());
}

#[test]
fn summaries_with_control_zero_width_or_bidi_refused_not_stripped() {
    for bad in [
        "Read\u{0007}",
        "Read\u{200B}item",
        "Read\u{202E}meti",
        "Read\u{2066}x",
        "Read\u{FEFF}",
        "Read\u{E0041}",
        "Read\nitem",
        "",
        "Read \u{1F600}",
        // Review F-6: Hangul fillers are `Lo` (alphabetic) yet invisible;
        // only the explicit exclusion list refuses them.
        "Read\u{3164}x",
        "Read\u{115F}x",
        "\u{1160}",
        "Read\u{FFA0}x",
    ] {
        let mut m = fixture();
        cap0(&mut m)["summary"] = json!(bad);
        assert!(parse_v(&m).is_err(), "summary {bad:?} must be refused");
    }
    let mut ok = fixture();
    cap0(&mut ok)["summary"] = json!("Lire l'élément (état) — 100%");
    // The em dash is not a letter: refused by the allowlist.
    assert!(parse_v(&ok).is_err());
    cap0(&mut ok)["summary"] = json!("Lire l'élément (état), 100% sûr");
    assert!(parse_v(&ok).is_ok(), "{:?}", parse_v(&ok));
}

#[test]
fn per_transport_fields_must_be_present_exactly_when_meaningful() {
    let mut no_name = fixture();
    cap0(&mut no_name)
        .as_object_mut()
        .unwrap()
        .remove("mcp_name");
    assert!(matches!(
        parse_v(&no_name),
        Err(ManifestError::TransportField {
            field: "mcp_name",
            required: true,
            ..
        })
    ));
    let mut no_pin = fixture();
    cap0(&mut no_pin)
        .as_object_mut()
        .unwrap()
        .remove("schema_sha256");
    assert!(matches!(
        parse_v(&no_pin),
        Err(ManifestError::TransportField {
            field: "schema_sha256",
            required: true,
            ..
        })
    ));
    let mut no_proto = fixture();
    no_proto["mcp_protocols"] = json!([]);
    assert!(matches!(
        parse_v(&no_proto),
        Err(ManifestError::TransportField {
            field: "mcp_protocols",
            required: true,
            ..
        })
    ));
    // in-process: mcp_name and mcp_protocols mean nothing there.
    let mut inproc = fixture();
    inproc["transport"] = json!({"kind": "in-process", "feature": "addon-fixture"});
    assert!(matches!(
        parse_v(&inproc),
        Err(ManifestError::TransportField {
            field: "mcp_protocols",
            required: false,
            ..
        })
    ));
    inproc.as_object_mut().unwrap().remove("mcp_protocols");
    assert!(matches!(
        parse_v(&inproc),
        Err(ManifestError::TransportField {
            field: "mcp_name",
            required: false,
            ..
        })
    ));
    cap0(&mut inproc)
        .as_object_mut()
        .unwrap()
        .remove("mcp_name");
    assert!(parse_v(&inproc).is_ok(), "{:?}", parse_v(&inproc));
}

#[test]
fn transport_content_is_checked() {
    for (argv, env) in [
        (json!([]), json!([])),
        (json!(["server"]), json!([])),
        (json!(["./server"]), json!([])),
        (json!(["/bin/server", "a\nb"]), json!([])),
        (json!(["/bin/server"]), json!(["lower"])),
        (json!(["/bin/server"]), json!(["A", "A"])),
        (json!(["/bin/server"]), json!(["1A"])),
    ] {
        let mut m = fixture();
        m["transport"] = json!({"kind": "mcp-stdio", "argv": argv, "env_allow": env});
        assert!(
            matches!(parse_v(&m), Err(ManifestError::BadTransport { .. })),
            "argv {argv} env {env}: {:?}",
            parse_v(&m)
        );
    }
    let mut win = fixture();
    win["transport"]["argv"] = json!(["C:\\fixture\\server.exe"]);
    assert!(parse_v(&win).is_ok());
    for bad in ["2025-6-18", "latest", "2025-06-18x"] {
        let mut m = fixture();
        m["mcp_protocols"] = json!([bad]);
        assert!(parse_v(&m).is_err(), "{bad}");
    }
    let mut unknown_kind = fixture();
    unknown_kind["transport"] = json!({"kind": "mcp-http", "url": "http://x"});
    assert!(matches!(
        parse_v(&unknown_kind),
        Err(ManifestError::Shape {
            kind: ShapeKind::UnknownValue,
            ..
        })
    ));
}

#[test]
fn versions_pins_and_limits_are_content_checked() {
    for bad in [
        "1",
        "1.2",
        "1.2.3-rc1",
        "01.2.3",
        "1.2.3.beta",
        "v1.2.3",
        "",
    ] {
        let mut m = fixture();
        m["min_harness"] = json!(bad);
        assert!(
            matches!(parse_v(&m), Err(ManifestError::BadSemVer { .. })),
            "{bad}"
        );
    }
    let mut future = fixture();
    future["min_harness"] = json!("0.1.0");
    assert_eq!(
        parse_v(&future),
        Err(ManifestError::HarnessTooOld {
            need: v(0, 1, 0),
            have: v(0, 0, 1)
        })
    );
    for bad in [&PIN[1..], &PIN.to_uppercase(), &format!("{}g", &PIN[1..])] {
        let mut m = fixture();
        cap0(&mut m)["description_sha256"] = json!(bad);
        assert!(
            matches!(parse_v(&m), Err(ManifestError::BadPin { .. })),
            "{bad}"
        );
    }
    for bad in [
        json!({}),
        json!({"timeout_ms": 0}),
        json!({"max_result_bytes": 0}),
    ] {
        let mut m = fixture();
        cap0(&mut m)["limits"] = bad.clone();
        assert!(
            matches!(parse_v(&m), Err(ManifestError::BadLimits(_))),
            "{bad}"
        );
    }
    for bad in ["", "provider_version with spaces", &"x".repeat(33)] {
        let mut m = fixture();
        m["provider_version"] = json!(bad);
        assert!(parse_v(&m).is_err(), "{bad:?}");
    }
    let mut secret = fixture();
    cap0(&mut secret)["secrets"] = json!(["tok", "tok"]);
    assert!(parse_v(&secret).is_err());
}

#[test]
fn limits_only_tighten() {
    let l = Limits {
        timeout_ms: Some(5_000),
        max_result_bytes: Some(1 << 30),
    };
    assert_eq!(l.tighten(30_000, 1 << 20), (5_000, 1 << 20));
    assert_eq!(Limits::default().tighten(30_000, 7), (30_000, 7));
}

#[test]
fn schema_outside_subset_refused_with_capability_named() {
    let mut m = fixture();
    cap0(&mut m)["input_schema"] = json!({"type": "object", "properties": {}});
    assert!(matches!(
        parse_v(&m),
        Err(ManifestError::Schema { capability, .. }) if capability == "fixture.item.read"
    ));
}

#[test]
fn oversized_and_malformed_bytes_refused() {
    let big = vec![b' '; MANIFEST_MAX_BYTES + 1];
    assert!(matches!(
        Manifest::parse(&big, &ctx()),
        Err(ManifestError::TooLarge { .. })
    ));
    assert!(matches!(parse_s("{"), Err(ManifestError::Json(_))));
    assert!(matches!(parse_s("[]"), Err(ManifestError::NoSchemaVersion)));
    let two = format!("{} {}", fixture(), fixture());
    assert!(matches!(parse_s(&two), Err(ManifestError::Json(_))));
}

// ---- admission (§4.4) ------------------------------------------------------------

#[test]
fn builtin_admits_and_resolves() {
    let r = Registry::admit(vec![(builtin::manifest(&ctx()).unwrap(), Tier::Builtin)]).unwrap();
    assert!(matches!(r.resolve("harness.fs.read"), Resolved::One { .. }));
    assert!(matches!(r.resolve("harness.fs.write"), Resolved::NotFound));
    assert!(matches!(r.resolve(""), Resolved::NotFound));
}

#[test]
fn tier_must_match_origin() {
    let b = builtin::manifest(&ctx()).unwrap();
    assert!(matches!(
        Registry::admit(vec![(b, Tier::Signed { key_id: "k".into() })]),
        Err(AdmissionError::TierMismatch { .. })
    ));
    let f = parse_v(&fixture()).unwrap();
    assert!(matches!(
        Registry::admit(vec![(f, Tier::Builtin)]),
        Err(AdmissionError::TierMismatch { .. })
    ));
}

#[test]
fn pinned_tier_data_rules_run_before_the_phase_gate() {
    let pin = Sha256Pin::parse_hex(PIN).unwrap();
    for (field, val, what) in [
        ("sensitivity", "personal", "sensitivity above operational"),
        ("sensitivity", "restricted", "sensitivity above operational"),
        ("blast_radius", "shared", "blast_radius shared"),
    ] {
        let mut m = fixture();
        cap0(&mut m)[field] = json!(val);
        let m = parse_v(&m).unwrap();
        assert!(
            matches!(
                Registry::admit(vec![(m, Tier::Pinned { manifest_sha256: pin })]),
                Err(AdmissionError::TierExceeded { what: w, .. }) if w == what
            ),
            "{field}={val}"
        );
    }
}

#[test]
fn what_h1_cannot_honour_is_refused_not_trusted() {
    let pin = Sha256Pin::parse_hex(PIN).unwrap();
    let f = || parse_v(&fixture()).unwrap();
    for tier in [
        Tier::Pinned {
            manifest_sha256: pin,
        },
        Tier::Signed { key_id: "k".into() },
    ] {
        assert!(matches!(
            Registry::admit(vec![(f(), tier)]),
            Err(AdmissionError::NotInThisPhase { phase: "H4", .. })
        ));
    }
}

#[test]
fn unit_transport_variant_still_refuses_unknown_fields() {
    // Internally tagged unit variant: an extra field must not be ignored.
    let mut m = fixture();
    m["transport"] = json!({"kind": "builtin", "argv": ["/bin/sh"]});
    assert!(
        matches!(
            parse_v(&m),
            Err(ManifestError::Shape {
                kind: ShapeKind::UnknownField,
                ..
            })
        ),
        "{:?}",
        parse_v(&m)
    );
}

// Review F-3: an explicit null is refused, never read as "absent".
#[test]
fn explicit_null_is_refused_not_read_as_absent() {
    let mut inproc = fixture();
    inproc["transport"] = json!({"kind": "in-process", "feature": "addon-fixture"});
    inproc.as_object_mut().unwrap().remove("mcp_protocols");
    cap0(&mut inproc)
        .as_object_mut()
        .unwrap()
        .remove("mcp_name");
    assert!(parse_v(&inproc).is_ok(), "control: {:?}", parse_v(&inproc));

    let mut rows: Vec<(&str, Value)> = Vec::new();
    let mut m = inproc.clone();
    cap0(&mut m)["mcp_name"] = Value::Null;
    rows.push(("mcp_name", m));
    let mut m = inproc.clone();
    cap0(&mut m)["limits"] = Value::Null;
    rows.push(("limits", m));
    let mut m = inproc.clone();
    cap0(&mut m)["limits"] = json!({"timeout_ms": null, "max_result_bytes": 5});
    rows.push(("limits.timeout_ms", m));
    let mut m = inproc.clone();
    cap0(&mut m)["limits"] = json!({"timeout_ms": 5, "max_result_bytes": null});
    rows.push(("limits.max_result_bytes", m));
    let mut m = inproc.clone();
    m["mcp_protocols"] = Value::Null;
    rows.push(("mcp_protocols", m));
    let mut m = inproc.clone();
    cap0(&mut m)["secrets"] = Value::Null;
    rows.push(("secrets", m));
    let mut m = fixture();
    cap0(&mut m)["schema_sha256"] = Value::Null;
    rows.push(("schema_sha256", m));
    let mut m = fixture();
    cap0(&mut m)["description_sha256"] = Value::Null;
    rows.push(("description_sha256", m));
    for (field, m) in rows {
        assert!(
            matches!(parse_v(&m), Err(ManifestError::NullValue(_))),
            "{field}: {:?}",
            parse_v(&m)
        );
    }
}

// Review F-8: the mcp-stdio program path cannot be UNC or climb with `..`.
#[test]
fn mcp_stdio_program_path_refuses_unc_and_parent_components() {
    for prog in [
        "//evil/share/server.exe",
        "\\\\evil\\share\\server.exe",
        "/\\evil/share/x",
        "\\/evil/share/x",
        "/opt/../../var/x",
        "/opt/fixture/..",
        "C:\\fixture\\..\\x.exe",
        "C:\\a/../x.exe",
    ] {
        let mut m = fixture();
        m["transport"]["argv"] = json!([prog]);
        assert!(
            matches!(parse_v(&m), Err(ManifestError::BadTransport { .. })),
            "{prog:?}: {:?}",
            parse_v(&m)
        );
    }
    for ok in [
        "/opt/fixture/bin/server",
        "C:\\fixture\\server.exe",
        "/opt/..x/y",
    ] {
        let mut m = fixture();
        m["transport"]["argv"] = json!([ok]);
        assert!(parse_v(&m).is_ok(), "{ok:?}: {:?}", parse_v(&m));
    }
}

// H1b confirming review NF-1: the null walk runs AFTER the version and
// reserved-name checks, so those keep their own messages.
#[test]
fn null_check_runs_after_version_and_reserved_name_checks() {
    let v0 = r#"{"schema_version":0,"app":"example","app_version":null,
        "capabilities":[{"id":"example.status.read","summary":"s","effect":"read"}]}"#;
    assert_eq!(
        parse_s(v0),
        Err(ManifestError::SchemaV0 { supported: &[1] })
    );

    let mut reserved = fixture();
    reserved["provider"] = json!("rustyvault");
    cap0(&mut reserved)["id"] = json!("rustyvault.item.read");
    cap0(&mut reserved)["limits"] = Value::Null;
    assert_eq!(
        parse_v(&reserved),
        Err(ManifestError::ReservedProvider("rustyvault".into()))
    );

    // A null is still refused once those checks pass.
    let mut m = fixture();
    cap0(&mut m)["limits"] = Value::Null;
    assert!(matches!(parse_v(&m), Err(ManifestError::NullValue(_))));
}
