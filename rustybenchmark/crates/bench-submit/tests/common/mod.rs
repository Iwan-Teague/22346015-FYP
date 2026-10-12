//! Shared fixtures: journal lines in the shape `rustybench run-suite` emits (docs/12 "Current
//! emission"), plus a full local hardware profile that is full of things that must not leave.
#![allow(dead_code)]

use bench_submit::redact::LocalFacts;
use serde_json::{json, Value};

pub const USER: &str = "jdoe42";

/// The identity of the fictional machine the fixtures were "run on".
pub fn facts() -> LocalFacts {
    LocalFacts {
        usernames: vec![USER.to_string()],
        homes: vec![format!("/Users/{USER}")],
        hostnames: vec!["Jdoes-MacBook-Pro".to_string()],
    }
}

pub fn unit_id(n: u64) -> String {
    format!(
        "blake3:{}",
        blake3::hash(format!("unit-{n}").as_bytes()).to_hex()
    )
}

/// A passing unit.
pub fn line(n: u64, family: &str, kind: &str, index: u32) -> Value {
    json!({
        "schema": 1,
        "unit_id": unit_id(n),
        "task_id": format!("{family}/{:016x}", 0xdead_beef_0000_0000u64 + n),
        "category": "borrow-lifetimes",
        "seed": 0xdead_beef_0000_0000u64 + n,
        "index": index,
        "epoch": "2026-10",
        "kind": kind,
        "segment": 0,
        "segment_position": n,
        "hw_class": "unified-32",
        "model": {"name": "qwen2.5-coder", "base_url": "http://jdoes-macbook-pro.local:8080", "finish_reason": "stop"},
        "sandbox": "seatbelt",
        "oracle": {
            "apply_ok": true, "compile_ok": true, "error_codes": [], "warn_count": 0,
            "diagnostic_completeness": "full",
            "behavior": {"unit": 1.0, "property": 1.0, "differential": 1.0, "score": 1.0},
            "constraint": {"alloc_ok": true, "clippy_clean": null, "fmt_ok": null,
                           "unsafe_blocks": null, "unsafe_ok": null, "paths_ok": null,
                           "violations": [], "score": 1.0},
            "score": 1.0, "failure_class": "none", "flags": []
        },
        "cost": {"prompt_tokens": 100, "completion_tokens": 50, "gen_ms": 1000, "grade_ms": 500},
        "failure_class": "none"
    })
}

/// A unit that failed to compile with the given codes.
pub fn failing(n: u64, family: &str, kind: &str, index: u32, codes: &[&str]) -> Value {
    let mut v = line(n, family, kind, index);
    v["oracle"]["compile_ok"] = json!(false);
    v["oracle"]["error_codes"] = json!(codes);
    v["oracle"]["behavior"] =
        json!({"unit": null, "property": null, "differential": null, "score": null});
    v["oracle"]["constraint"] = json!({"alloc_ok": null, "clippy_clean": null, "fmt_ok": null,
        "unsafe_blocks": null, "unsafe_ok": null, "paths_ok": null, "violations": [], "score": null});
    v["oracle"]["score"] = json!(0.0);
    v["oracle"]["failure_class"] = json!("borrowck");
    v["oracle"]["diagnostic_completeness"] = json!("full");
    v["failure_class"] = json!("borrowck");
    v
}

pub fn journal(lines: &[Value]) -> String {
    lines
        .iter()
        .map(|l| l.to_string())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// A modest but realistic journal: 4 families x (4 core + 1 probe), mixed outcomes.
pub fn sample_lines() -> Vec<Value> {
    let mut ls = Vec::new();
    let mut n = 0u64;
    for fam in ["window-op", "ring-buffer", "trie", "fenwick"] {
        for i in 0..4u32 {
            n += 1;
            if n.is_multiple_of(3) {
                ls.push(failing(n, fam, "core", i, &["E0499"]));
            } else {
                ls.push(line(n, fam, "core", i));
            }
        }
        n += 1;
        ls.push(line(n, fam, "probe", 0));
    }
    ls
}

pub fn sample_journal() -> String {
    journal(&sample_lines())
}

/// A full local `hw.json`, deliberately stuffed with identifying detail.
pub fn hw_profile_json() -> String {
    json!({
        "schema": 1,
        "cpu": {"model": "Apple M5 Max (jdoe42's)", "vendor": "apple", "arch": "arm64",
                "physical_cores": 18, "logical_cores": 18, "performance_cores": 12,
                "efficiency_cores": 6, "features": ["neon"]},
        "ram": {"total_bytes": 25769803776u64, "available_bytes": 20000000000u64},
        "gpus": [{"vendor": "apple", "model": "Apple M5 Max 40-core serial C02XG0FDH7JY",
                  "mem_total_bytes": null, "mem_free_bytes": null, "driver_version": "9.9.9-secret",
                  "cores": 40, "shares_system_memory": true}],
        "os": {"family": "macos", "version": "26.5.1", "build": "25F74", "kernel": "Darwin 25.5.0"},
        "storage": {"kind": "nvme", "scratch_free_bytes": 123456789012u64},
        "power": {"source": "ac", "chassis": "laptop"},
        "unified_memory": true,
        "provenance": {"cpu.model": "sysctl"},
        "warnings": ["probe failed in /Users/jdoe42/Desktop/rustysuite on Jdoes-MacBook-Pro.local"]
    })
    .to_string()
}

/// A fast bootstrap count so tests do not spend seconds in the CI estimator.
pub const ITERS: usize = 200;

pub fn opts() -> bench_submit::BuildOptions {
    bench_submit::BuildOptions {
        bootstrap_iters: ITERS,
        facts: facts(),
        ..Default::default()
    }
}
