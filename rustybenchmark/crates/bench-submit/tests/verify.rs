mod common;
use bench_submit::canon::{canonical_bytes, content_hash};
use bench_submit::verify::{verify_bytes, VerifyOptions};
use bench_submit::{build, BuildInputs};
use common::*;
use serde_json::{json, Value};

fn fresh() -> Vec<u8> {
    build(
        &BuildInputs {
            journal: &sample_journal(),
            hw_json: &hw_profile_json(),
            identity_json: None,
            run_id: None,
        },
        &opts(),
    )
    .unwrap()
    .bytes
}

fn opts_v() -> VerifyOptions {
    VerifyOptions {
        facts: facts(),
        rederive: true,
    }
}

/// An attacker who edits the body AND recomputes the hash and re-canonicalises: the strongest
/// edit a file-only adversary can make.
fn forge(bytes: &[u8], edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(bytes).unwrap();
    edit(&mut v["body"]);
    v["content_hash"] = json!(content_hash(&v["body"]));
    let mut out = canonical_bytes(&v);
    out.push(b'\n');
    out
}

fn failed(report: &bench_submit::verify::VerifyReport) -> Vec<&'static str> {
    report
        .checks
        .iter()
        .filter(|c| !c.ok)
        .map(|c| c.name)
        .collect()
}

#[test]
fn a_fresh_bundle_verifies_clean() {
    let r = verify_bytes(&fresh(), &opts_v());
    assert!(r.ok(), "{}", r.render());
    assert_eq!(r.units, 20);
    let names: Vec<_> = r.checks.iter().map(|c| c.name).collect();
    for n in [
        "parse",
        "schema",
        "canonical-form",
        "content-hash",
        "grammar",
        "leak-scan",
        "consent",
        "structure",
        "oracle-consistency",
        "rederived-stats",
        "run-id",
    ] {
        assert!(names.contains(&n), "missing check {n}");
    }
}

#[test]
fn flipping_a_byte_of_a_score_breaks_the_hash() {
    let text = String::from_utf8(fresh()).unwrap();
    let tampered = text.replacen("\"gen_ms\":1000", "\"gen_ms\":1001", 1);
    assert_ne!(tampered, text);
    let r = verify_bytes(tampered.as_bytes(), &opts_v());
    assert!(failed(&r).contains(&"content-hash"), "{}", r.render());
}

#[test]
fn a_forged_unit_with_a_fixed_up_hash_is_still_caught() {
    // Make a failing unit look like a pass by editing its score, then recompute the hash.
    let b = forge(&fresh(), |body| {
        let units = body["units"].as_array_mut().unwrap();
        let u = units
            .iter_mut()
            .find(|u| u["oracle"]["compile_ok"] == json!(false))
            .unwrap();
        u["oracle"]["score"] = json!(1.0);
    });
    let r = verify_bytes(&b, &opts_v());
    assert!(!r.ok());
    let f = failed(&r);
    assert!(f.contains(&"oracle-consistency"), "{}", r.render());
    assert!(f.contains(&"rederived-stats"), "{}", r.render());
    assert!(!f.contains(&"content-hash"), "the forger fixed the hash");
}

#[test]
fn a_coherent_forgery_of_the_unit_table_still_cannot_move_the_aggregates() {
    // Flip a failed unit into a fully coherent pass; the reported aggregates no longer follow.
    let b = forge(&fresh(), |body| {
        let units = body["units"].as_array_mut().unwrap();
        let u = units
            .iter_mut()
            .find(|u| u["oracle"]["compile_ok"] == json!(false))
            .unwrap();
        u["oracle"]["compile_ok"] = json!(true);
        u["oracle"]["error_codes"] = json!([]);
        u["oracle"]["behavior"] = json!({"unit":1.0,"property":1.0,"differential":1.0,"score":1.0});
        u["oracle"]["constraint"]["alloc_ok"] = json!(true);
        u["oracle"]["constraint"]["score"] = json!(1.0);
        u["oracle"]["score"] = json!(1.0);
        u["oracle"]["failure_class"] = json!("none");
    });
    let r = verify_bytes(&b, &opts_v());
    assert_eq!(
        failed(&r),
        vec!["rederived-stats", "run-id"],
        "the derived run id also binds the units: {}",
        r.render()
    );
}

#[test]
fn editing_the_reported_headline_is_caught() {
    let b = forge(&fresh(), |body| {
        body["report"]["stats"]["capability_score"] = json!(0.999);
    });
    let r = verify_bytes(&b, &opts_v());
    assert_eq!(failed(&r), vec!["rederived-stats"], "{}", r.render());
}

#[test]
fn extra_fields_and_noncanonical_bytes_are_rejected() {
    let mut v: Value = serde_json::from_slice(&fresh()).unwrap();
    v["body"]["units"][0]["seed"] = json!(12345);
    let r = verify_bytes(v.to_string().as_bytes(), &opts_v());
    assert!(failed(&r).contains(&"parse"), "{}", r.render());

    // Same content, pretty-printed: parses, but is not the canonical byte string.
    let v: Value = serde_json::from_slice(&fresh()).unwrap();
    let pretty = serde_json::to_string_pretty(&v).unwrap();
    let r = verify_bytes(pretty.as_bytes(), &opts_v());
    assert_eq!(failed(&r), vec!["canonical-form"], "{}", r.render());
}

#[test]
fn a_planted_leak_is_caught_even_with_a_valid_hash() {
    for planted in [
        "/Users/jdoe42/x.rs",
        "192.168.1.5",
        "jdoe42",
        "aa:bb:cc:dd:ee:ff",
    ] {
        let b = forge(&fresh(), |body| {
            body["units"][0]["oracle"]["constraint"]["violations"] = json!([planted]);
        });
        let r = verify_bytes(&b, &opts_v());
        assert!(
            failed(&r).contains(&"leak-scan"),
            "{planted}: {}",
            r.render()
        );
    }
    // And the verifier's own username is a leak even when no pattern would flag it.
    let b = forge(&fresh(), |body| {
        body["model"]["name"] = json!("jdoe42-finetune");
    });
    assert!(failed(&verify_bytes(&b, &opts_v())).contains(&"leak-scan"));
    // ... but a verifier that does not know that name has only the patterns.
    let blank = VerifyOptions::default();
    assert!(!failed(&verify_bytes(&b, &blank)).contains(&"leak-scan"));
}

#[test]
fn consent_must_be_granted_and_terms_must_match() {
    let b = forge(&fresh(), |body| {
        body["consents"]["public_scores"] = json!(false)
    });
    assert!(failed(&verify_bytes(&b, &opts_v())).contains(&"consent"));
    let b = forge(&fresh(), |body| {
        body["consents"]["terms_hash"] = json!(format!("blake3:{}", "0".repeat(64)))
    });
    assert!(failed(&verify_bytes(&b, &opts_v())).contains(&"consent"));
    let b = forge(&fresh(), |body| {
        body["consents"]["replay_artifacts"] = json!(true)
    });
    assert!(failed(&verify_bytes(&b, &opts_v())).contains(&"consent"));
    // A terms version this build does not know is flagged in the detail, not failed.
    let b = forge(&fresh(), |body| {
        body["consents"]["terms_version"] = json!("2099-01-01")
    });
    let r = verify_bytes(&b, &opts_v());
    assert!(
        r.checks
            .iter()
            .any(|c| c.name == "consent" && c.ok && c.detail.contains("unknown")),
        "{}",
        r.render()
    );
}

#[test]
fn structural_forgeries_are_caught() {
    // Reordered units.
    let b = forge(&fresh(), |body| {
        body["units"].as_array_mut().unwrap().reverse()
    });
    assert!(failed(&verify_bytes(&b, &opts_v())).contains(&"structure"));
    // Duplicate unit id.
    let b = forge(&fresh(), |body| {
        let id = body["units"][0]["unit_id"].clone();
        body["units"][1]["unit_id"] = id;
    });
    assert!(failed(&verify_bytes(&b, &opts_v())).contains(&"structure"));
    // A unit claiming different hardware from the bundle.
    let b = forge(&fresh(), |body| {
        body["units"][3]["hw_class"] = json!("vram-24")
    });
    assert!(failed(&verify_bytes(&b, &opts_v())).contains(&"structure"));
    // Claiming a division that was never recorded makes `unrecorded` lie.
    let b = forge(&fresh(), |body| {
        body["identity"]["division"] = json!("pinned")
    });
    assert!(failed(&verify_bytes(&b, &opts_v())).contains(&"structure"));
    // Wrong derived run id.
    let b = forge(&fresh(), |body| {
        body["run_id"] = json!("rb-0000000000000000")
    });
    assert!(failed(&verify_bytes(&b, &opts_v())).contains(&"run-id"));
    // Unknown schema major.
    let mut v: Value = serde_json::from_slice(&fresh()).unwrap();
    v["schema"] = json!(2);
    let mut out = canonical_bytes(&v);
    out.push(b'\n');
    assert!(failed(&verify_bytes(&out, &opts_v())).contains(&"schema"));
}

type Edit = Box<dyn Fn(&mut Value)>;

#[test]
fn oracle_incoherence_is_caught_per_rule() {
    let cases: Vec<(&str, Edit)> = vec![
        (
            "score without compile",
            Box::new(|u| {
                let f = u
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|u| u["oracle"]["compile_ok"] == json!(false))
                    .unwrap();
                f["oracle"]["score"] = json!(0.5);
            }),
        ),
        (
            "class vs codes",
            Box::new(|u| {
                let f = u
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|u| u["oracle"]["compile_ok"] == json!(false))
                    .unwrap();
                f["oracle"]["failure_class"] = json!("trait");
            }),
        ),
        (
            "borrowck completeness",
            Box::new(|u| {
                let f = u
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|u| u["oracle"]["compile_ok"] == json!(false))
                    .unwrap();
                f["oracle"]["diagnostic_completeness"] = json!("typeck_only");
            }),
        ),
        (
            "behaviour mean",
            Box::new(|u| {
                let f = u
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|u| u["oracle"]["compile_ok"] == json!(true))
                    .unwrap();
                f["oracle"]["behavior"]["unit"] = json!(0.0);
            }),
        ),
        (
            "pass class on logic miss",
            Box::new(|u| {
                let f = u
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|u| u["oracle"]["compile_ok"] == json!(true))
                    .unwrap();
                f["oracle"]["behavior"] =
                    json!({"unit":0.5,"property":0.5,"differential":0.5,"score":0.5});
            }),
        ),
    ];
    for (name, edit) in cases {
        let b = forge(&fresh(), |body| edit(&mut body["units"]));
        let r = verify_bytes(&b, &opts_v());
        assert!(
            failed(&r).contains(&"oracle-consistency"),
            "{name}: {}",
            r.render()
        );
    }
}

#[test]
fn no_rederive_skips_only_the_slow_check() {
    let b = forge(&fresh(), |body| {
        body["report"]["stats"]["capability_score"] = json!(0.5)
    });
    let r = verify_bytes(
        &b,
        &VerifyOptions {
            facts: facts(),
            rederive: false,
        },
    );
    assert!(r.ok(), "{}", r.render());
}

#[test]
fn hostile_input_never_panics() {
    let good = fresh();
    for n in [0usize, 1, 7, 100, good.len() / 2, good.len() - 1] {
        let r = verify_bytes(&good[..n], &opts_v());
        assert!(!r.ok());
    }
    for junk in [
        &b"null"[..],
        b"[]",
        b"{}",
        b"\xff\xfe\x00",
        b"{\"schema\":1}",
    ] {
        assert!(!verify_bytes(junk, &opts_v()).ok());
    }
    // Absurd bootstrap count in a forged report is refused, not run.
    let b = forge(&good, |body| {
        body["report"]["stats"]["bootstrap_iters"] = json!(u64::MAX)
    });
    let r = verify_bytes(&b, &opts_v());
    assert!(failed(&r).contains(&"rederived-stats"));
}

#[test]
fn error_messages_never_echo_planted_content() {
    let b = forge(&fresh(), |body| {
        body["units"][0]["oracle"]["constraint"]["violations"] = json!(["/Users/jdoe42/secret"]);
    });
    let r = verify_bytes(&b, &opts_v());
    assert!(!r.render().contains("jdoe42"), "{}", r.render());
}
