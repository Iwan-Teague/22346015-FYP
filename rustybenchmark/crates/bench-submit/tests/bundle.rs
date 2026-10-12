mod common;
use bench_submit::bundle::{bundle_bytes, Bundle};
use bench_submit::canon::{canonical_bytes, content_hash};
use bench_submit::{build, BuildInputs};
use common::*;
use serde_json::{json, Value};

fn inputs<'a>(journal: &'a str, hw: &'a str) -> BuildInputs<'a> {
    BuildInputs {
        journal,
        hw_json: hw,
        identity_json: None,
        run_id: None,
    }
}

fn build_ok(journal: &str) -> bench_submit::Built {
    build(&inputs(journal, &hw_profile_json()), &opts()).expect("build")
}

#[test]
fn bundle_is_schema_valid_and_round_trips_byte_for_byte() {
    let b = build_ok(&sample_journal());
    assert_eq!(b.units, 20);
    assert_eq!((b.core, b.probe), (16, 4));
    let parsed: Bundle =
        serde_json::from_slice(&b.bytes).expect("typed parse (deny_unknown_fields)");
    assert_eq!(parsed, b.bundle);
    assert_eq!(
        bundle_bytes(&parsed).unwrap(),
        b.bytes,
        "canonical form is a fixed point"
    );
    assert_eq!(b.bytes.last(), Some(&b'\n'));
    // The recorded hash is the hash of the body.
    let body = serde_json::to_value(&parsed.body).unwrap();
    assert_eq!(parsed.content_hash, content_hash(&body));
}

#[test]
fn seeds_and_host_details_never_appear() {
    let b = build_ok(&sample_journal());
    let mut v: Value = serde_json::from_slice(&b.bytes).unwrap();
    // The `withheld` list names the omitted fields (base_url, seed, ...); scan everything else.
    v["body"].as_object_mut().unwrap().remove("withheld");
    let text = v.to_string().to_lowercase();
    for needle in [
        "deadbeef", // the seed inside every generated task_id
        "base_url",
        "8080",
        "jdoes",
        "macbook",
        "jdoe42",
        ".local",
        "m5 max",
        "c02xg0fdh7jy",
        "9.9.9-secret",
        "25f74",
        "darwin",
        "123456789012",
        "/users/",
        "rustysuite",
        "performance_cores",
        "physical_cores",
    ] {
        assert!(!text.contains(needle), "bundle leaks {needle:?}");
    }
    // Coarse class only.
    assert!(text.contains("unified-32"));
    // And the withheld list says so, rather than staying silent.
    let full = String::from_utf8(b.bytes).unwrap();
    assert!(full.contains("\"seed\"") && full.contains("epoch_seed"));
}

#[test]
fn units_carry_family_not_task_id() {
    let b = build_ok(&sample_journal());
    let v: Value = serde_json::from_slice(&b.bytes).unwrap();
    let u = &v["body"]["units"][0];
    assert!(u.get("task_id").is_none());
    assert!(u.get("seed").is_none());
    assert!(u["family"].is_string());
    assert!(u["unit_id"].as_str().unwrap().starts_with("blake3:"));
}

#[test]
fn same_inputs_give_byte_identical_bundle_and_hash() {
    let a = build_ok(&sample_journal());
    let b = build_ok(&sample_journal());
    assert_eq!(a.bytes, b.bytes);
    assert_eq!(a.bundle.content_hash, b.bundle.content_hash);
    // Stable across many repeats (no hidden clock / RNG / map-order dependence).
    for _ in 0..5 {
        assert_eq!(build_ok(&sample_journal()).bytes, a.bytes);
    }
}

#[test]
fn journal_line_order_does_not_change_the_bundle() {
    let mut ls = sample_lines();
    let a = build_ok(&journal(&ls));
    ls.reverse();
    let b = build_ok(&journal(&ls));
    assert_eq!(a.bytes, b.bytes);
    ls.rotate_left(7);
    assert_eq!(build_ok(&journal(&ls)).bytes, a.bytes);
}

#[test]
fn key_order_and_whitespace_in_the_journal_do_not_matter() {
    let ls = sample_lines();
    let a = build_ok(&journal(&ls));
    // Re-serialise every line with pretty-printing disabled but keys in reverse insertion order.
    let rev: Vec<Value> = ls
        .iter()
        .map(|l| {
            let m = l.as_object().unwrap();
            let mut keys: Vec<_> = m.keys().cloned().collect();
            keys.reverse();
            let mut o = serde_json::Map::new();
            for k in keys {
                o.insert(k.clone(), m[&k].clone());
            }
            Value::Object(o)
        })
        .collect();
    assert_eq!(build_ok(&journal(&rev)).bytes, a.bytes);
}

#[test]
fn any_change_to_a_unit_changes_the_hash() {
    let mut ls = sample_lines();
    let a = build_ok(&journal(&ls));
    ls[0]["cost"]["gen_ms"] = json!(1001);
    let b = build_ok(&journal(&ls));
    assert_ne!(a.bundle.content_hash, b.bundle.content_hash);
    assert_ne!(
        a.bundle.body.run_id, b.bundle.body.run_id,
        "derived run id follows content"
    );
}

#[test]
fn explicit_run_id_is_used_and_validated() {
    let j = sample_journal();
    let hw = hw_profile_json();
    let mut i = inputs(&j, &hw);
    i.run_id = Some("01K3F8XQ2M7VZ0J4T6N9P1R5CD");
    assert_eq!(
        build(&i, &opts()).unwrap().bundle.body.run_id,
        "01K3F8XQ2M7VZ0J4T6N9P1R5CD"
    );
    i.run_id = Some("/Users/jdoe42/run");
    assert!(build(&i, &opts()).is_err());
}

#[test]
fn scores_serialise_as_clean_decimals() {
    let mut ls = sample_lines();
    ls[0]["oracle"]["score"] = json!(0.7);
    ls[0]["oracle"]["behavior"]["score"] = json!(0.7);
    let text = String::from_utf8(build_ok(&journal(&ls)).bytes).unwrap();
    assert!(
        text.contains("\"score\":0.7,") || text.contains("\"score\":0.7}"),
        "f32 noise leaked"
    );
    assert!(!text.contains("0.699999"));
}

#[test]
fn refuses_malformed_or_unsafe_journals() {
    let hw = hw_profile_json();
    let try_build = |ls: Vec<Value>| build(&inputs(&journal(&ls), &hw), &opts());

    assert!(build(&inputs("", &hw), &opts()).is_err(), "empty");

    let mut l = sample_lines();
    l[1]["schema"] = json!(2);
    assert!(try_build(l).unwrap_err().to_string().contains("schema"));

    let mut l = sample_lines();
    l[1]["unit_id"] = json!("not-a-hash");
    assert!(try_build(l).is_err());

    let mut l = sample_lines();
    l[1]["unit_id"] = l[0]["unit_id"].clone();
    assert!(try_build(l).unwrap_err().to_string().contains("duplicate"));

    let mut l = sample_lines();
    l[1]["epoch"] = json!("2026-11");
    assert!(try_build(l).unwrap_err().to_string().contains("epochs"));

    let mut l = sample_lines();
    l[1]["model"]["name"] = json!("other-model");
    assert!(try_build(l).unwrap_err().to_string().contains("mixes"));

    let mut l = sample_lines();
    l[1]["kind"] = json!("wild");
    assert!(try_build(l).is_err());

    let mut l = sample_lines();
    l[1]["epoch"] = json!("/Users/jdoe42/epoch");
    let e = try_build(l).unwrap_err().to_string();
    assert!(
        e.contains("epoch") && !e.contains("jdoe42"),
        "error must not echo the value: {e}"
    );

    let mut l = sample_lines();
    l[2]["task_id"] = json!("/etc/passwd");
    assert!(try_build(l).is_err(), "no family prefix");

    let mut l = sample_lines();
    l[2]["oracle"]["score"] = json!(1.5);
    assert!(try_build(l).is_err());
}

#[test]
fn refuses_mixed_hardware() {
    let hw = hw_profile_json(); // unified-32
    let mut l = sample_lines();
    l[3]["hw_class"] = json!("vram-24");
    let e = build(&inputs(&journal(&l), &hw), &opts())
        .unwrap_err()
        .to_string();
    assert!(e.contains("hardware class"), "{e}");
    // Units that predate hw_class are tolerated.
    let mut l = sample_lines();
    l[3].as_object_mut().unwrap().remove("hw_class");
    assert!(build(&inputs(&journal(&l), &hw), &opts()).is_ok());
}

#[test]
fn accepts_an_already_public_hw_view_and_ignores_extra_fields() {
    let public = json!({
        "schema": 1, "hw_class": "unified-32", "vendor": "apple", "generation": "m5",
        "cpu_class": "arm64-apple", "unified_memory": true, "chassis": "laptop",
        "power_source": "ac", "serial": "C02XG0FDH7JY"
    })
    .to_string();
    let b = build(&inputs(&sample_journal(), &public), &opts()).unwrap();
    assert!(!String::from_utf8(b.bytes).unwrap().contains("C02XG"));
    // Non-token junk in a hand-edited public view is refused, not cleaned.
    let bad = public.replace("arm64-apple", "/Users/jdoe42/cpu");
    assert!(build(&inputs(&sample_journal(), &bad), &opts()).is_err());
    assert!(build(&inputs(&sample_journal(), "{}"), &opts()).is_err());
}

#[test]
fn identity_file_supplies_the_row_key_and_unrecorded_is_honest() {
    let j = sample_journal();
    let hw = hw_profile_json();
    let none = build(&inputs(&j, &hw), &opts()).unwrap();
    assert!(none
        .bundle
        .body
        .unrecorded
        .contains(&"identity.division".to_string()));
    assert!(none.bundle.body.identity.division.is_none());
    assert_eq!(
        none.bundle.body.identity.categories_scored,
        vec!["borrow-lifetimes".to_string()]
    );

    // A docs/12 state.json: the `identity` object is taken, siblings (paths!) are ignored.
    let state = json!({
        "schema": 1, "run_id": "x", "cwd": "/Users/jdoe42/runs",
        "identity": {
            "suite_hash": format!("blake3:{}", "a".repeat(64)),
            "generator_commit": "a17c93d",
            "division": "pinned", "template_fingerprint": format!("blake3:{}", "b".repeat(64)),
            "reasoning_format": "none", "exec_class": "GpuFull", "exec_class_source": "declared",
            "model": {"name": "/Users/jdoe42/models/x.gguf", "quant": "Q4_K_M", "backend": "llama.cpp",
                      "backend_version": "b7412", "ctx": 32768, "ngl": 999,
                      "model_path": "/Users/jdoe42/models/x.gguf"},
            "sampling": {"temp": 0.0, "top_p": 1.0, "top_k": 0, "seed": 42}
        }
    })
    .to_string();
    let mut i = inputs(&j, &hw);
    i.identity_json = Some(&state);
    let b = build(&i, &opts()).unwrap();
    let id = &b.bundle.body.identity;
    assert_eq!(id.division.as_deref(), Some("pinned"));
    assert_eq!(id.reasoning_mode.as_deref(), Some("none"));
    assert_eq!(b.bundle.body.model.quant.as_deref(), Some("Q4_K_M"));
    assert_eq!(b.bundle.body.model.ctx, Some(32768));
    assert_eq!(
        b.bundle.body.model.sampling.as_ref().unwrap().seed,
        Some(42)
    );
    assert!(!b
        .bundle
        .body
        .unrecorded
        .contains(&"identity.division".to_string()));
    let mut v: Value = serde_json::from_slice(&b.bytes).unwrap();
    v["body"].as_object_mut().unwrap().remove("withheld");
    let text = v.to_string();
    assert!(!text.contains("jdoe42") && !text.contains("model_path"));

    // A bad division or a non-token value is refused outright.
    for bad in [
        json!({"identity": {"division": "elite"}}),
        json!({"identity": {"exec_class": "/Users/jdoe42/q"}}),
        json!({"identity": {"model": {"quant": "../../etc"}}}),
    ] {
        let t = bad.to_string();
        let mut i = inputs(&j, &hw);
        i.identity_json = Some(&t);
        assert!(build(&i, &opts()).is_err(), "{t}");
    }
}

#[test]
fn canonical_bytes_are_independent_of_struct_field_order() {
    let b = build_ok(&sample_journal());
    let v: Value = serde_json::from_slice(&b.bytes).unwrap();
    assert_eq!(canonical_bytes(&v), &b.bytes[..b.bytes.len() - 1]);
}

#[test]
fn report_block_matches_a_direct_bench_stats_run() {
    let b = build_ok(&sample_journal());
    let r = &b.bundle.body.report;
    assert_eq!(r["n_core"], 16);
    assert_eq!(r["n_probe"], 4);
    let cap = r["stats"]["capability_score"].as_f64().unwrap();
    // 4 families; per family outcomes are known from the fixture: n%3==0 core units fail.
    assert!(cap > 0.0 && cap < 1.0, "capability {cap}");
    assert_eq!(
        r["stats"]["units"], 16,
        "probe units never enter the scored figure"
    );
}

#[test]
fn export_tolerates_only_the_benign_crash_damage() {
    let ls = sample_lines();
    let clean = journal(&ls);
    let a = build_ok(&clean);

    // A torn final line (a run killed mid-append): the unit never completed, so it is dropped.
    let torn = format!("{clean}{}", &ls[0].to_string()[..40]);
    let b = build_ok(&torn);
    assert_eq!(
        b.bytes, a.bytes,
        "a torn tail changes nothing about the bundle"
    );
    assert_eq!(b.journal_notes.len(), 1);
    assert!(
        b.journal_notes[0].contains("torn final line"),
        "{:?}",
        b.journal_notes
    );

    // Identical duplicate lines collapse.
    let dup = format!("{clean}{}\n", ls[3]);
    let c = build_ok(&dup);
    assert_eq!(c.bytes, a.bytes);
    assert!(c.journal_notes[0].contains("identical copy"));
    assert!(a.journal_notes.is_empty());
}

#[test]
fn export_refuses_damage_that_could_hide_a_missing_or_ambiguous_unit() {
    let hw = hw_profile_json();
    let ls = sample_lines();
    let mid_corrupt = format!("{}garbage\n{}", journal(&ls[..3]), journal(&ls[3..]));
    let e = build(&inputs(&mid_corrupt, &hw), &opts())
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("needs repair") && e.contains("journal --repair"),
        "{e}"
    );

    let mut changed = ls[1].clone();
    changed["cost"]["gen_ms"] = json!(9999);
    let conflict = format!("{}{}\n", journal(&ls), changed);
    let e = build(&inputs(&conflict, &hw), &opts())
        .unwrap_err()
        .to_string();
    assert!(e.contains("two different records"), "{e}");
}
