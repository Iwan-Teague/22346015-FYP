//! `verify-bundle`: everything a reader can re-establish about a bundle **without the server and
//! without the model**. It is the offline slice of docs/10's "the server re-derives" column:
//!
//! | docs/10 claim | what is checked here | what is *not* (and why) |
//! |---|---|---|
//! | "this bundle is what was produced" | canonical form is a fixed point; content hash recomputed | signature (no key policy; embedded key is T0-only, docs/10) |
//! | "these figures follow from these units" | `bench-stats` re-run over the units; every number compared | — |
//! | "the oracle vector is internally coherent" | score gating, sub-score recomputation, failure class vs error codes, borrowck-completeness vs codes | T1 replay: re-running the oracle over model output needs the output (private, encrypted, not in this bundle) |
//! | "nothing private is in it" | grammar + the same leak scan the exporter ran, with *this* machine's facts too | — |
//!
//! A passing verify means the bundle is **self-consistent and clean**. It does not mean the scores
//! are true: that needs T1 replay (L0-L3) which only the server can do, and docs/10 is explicit that
//! hardware throughput and model attribution are never verifiable. No trust tier is assigned here.

use crate::bundle::{
    bundle_bytes, derive_report, is_error_code, is_flag, is_ident, is_token, leak_check, Bundle,
    Unit, KIND, MAX_BOOTSTRAP_ITERS, MAX_BUNDLE_BYTES, SCHEMA, WITHHELD,
};
use crate::canon::{content_hash, is_blake3_id, CANON_VERSION};
use crate::redact::{LocalFacts, Redactor};
use bench_core::{
    classify_error_codes, classify_graded, diagnostic_completeness, DiagnosticCompleteness,
    FailureClass, OracleVector,
};
use serde_json::Value;
use std::collections::BTreeSet;

/// One named check and its outcome.
#[derive(Clone, Debug)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Default)]
pub struct VerifyReport {
    pub checks: Vec<Check>,
    pub content_hash: Option<String>,
    pub units: usize,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        !self.checks.is_empty() && self.checks.iter().all(|c| c.ok)
    }

    fn push(&mut self, name: &'static str, ok: bool, detail: impl Into<String>) {
        self.checks.push(Check {
            name,
            ok,
            detail: detail.into(),
        });
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        for c in &self.checks {
            s.push_str(&format!(
                "{} {:<20} {}\n",
                if c.ok { "ok  " } else { "FAIL" },
                c.name,
                c.detail
            ));
        }
        s.push_str(if self.ok() {
            "bundle is self-consistent and clean (this is not T1 replay: scores are not re-graded)\n"
        } else {
            "bundle FAILED verification\n"
        });
        s
    }
}

pub struct VerifyOptions {
    /// Facts about *this* machine, so a verifier can also catch its own username in a bundle.
    pub facts: LocalFacts,
    /// Re-run `bench-stats` over the units (the slow check). On by default.
    pub rederive: bool,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        VerifyOptions {
            facts: LocalFacts::default(),
            rederive: true,
        }
    }
}

/// Verify the bytes of a bundle file. Never panics on hostile input.
pub fn verify_bytes(bytes: &[u8], opts: &VerifyOptions) -> VerifyReport {
    let mut r = VerifyReport::default();

    if bytes.len() > MAX_BUNDLE_BYTES {
        r.push(
            "size",
            false,
            format!("{} bytes exceeds the {MAX_BUNDLE_BYTES} cap", bytes.len()),
        );
        return r;
    }
    let bundle: Bundle = match serde_json::from_slice(bytes) {
        Ok(b) => b,
        Err(e) => {
            // serde messages can quote content; report category and column only.
            r.push(
                "parse",
                false,
                format!(
                    "not a valid bundle ({:?} at line {} column {})",
                    e.classify(),
                    e.line(),
                    e.column()
                ),
            );
            return r;
        }
    };
    r.push("parse", true, "typed parse; unknown fields are rejected");
    r.units = bundle.body.units.len();
    r.content_hash = Some(bundle.content_hash.clone());

    // -- header ------------------------------------------------------------------------------
    let header_ok =
        bundle.schema == SCHEMA && bundle.canon == CANON_VERSION && bundle.body.kind == KIND;
    r.push(
        "schema",
        header_ok,
        if header_ok {
            format!("schema {SCHEMA}, {CANON_VERSION}")
        } else {
            format!(
                "expected schema {SCHEMA} / {CANON_VERSION} / {KIND}; readers reject unknown majors rather than guess"
            )
        },
    );

    // -- canonical form + hash ---------------------------------------------------------------
    match bundle_bytes(&bundle) {
        Ok(canon) if canon == bytes => r.push(
            "canonical-form",
            true,
            "re-serialising reproduces the file byte for byte",
        ),
        Ok(canon) => {
            let at = canon
                .iter()
                .zip(bytes)
                .position(|(a, b)| a != b)
                .unwrap_or(canon.len().min(bytes.len()));
            r.push(
                "canonical-form",
                false,
                format!("not in canonical form (first difference at byte {at}): reordered keys, whitespace, or a value outside the schema"),
            );
        }
        Err(e) => r.push("canonical-form", false, e.to_string()),
    }
    let body_value = serde_json::to_value(&bundle.body).unwrap_or(Value::Null);
    let want = content_hash(&body_value);
    r.push(
        "content-hash",
        want == bundle.content_hash,
        if want == bundle.content_hash {
            bundle.content_hash.clone()
        } else {
            format!("recorded {} but body hashes to {want}", bundle.content_hash)
        },
    );

    // -- grammar + leak scan -----------------------------------------------------------------
    let bad = grammar_problems(&bundle);
    r.push(
        "grammar",
        bad.is_empty(),
        if bad.is_empty() {
            "every identifier-shaped field matches its token grammar".to_string()
        } else {
            bad.into_iter().take(5).collect::<Vec<_>>().join("; ")
        },
    );
    let redactor = Redactor::new(&opts.facts);
    match leak_check(&redactor, &body_value) {
        Ok(()) => r.push(
            "leak-scan",
            true,
            "no path, host, address, serial, env reference or local identity found",
        ),
        Err(e) => r.push("leak-scan", false, e.to_string()),
    }

    // -- consent -----------------------------------------------------------------------------
    let c = &bundle.body.consents;
    let known = c.terms_version == crate::consent::TERMS_VERSION;
    let consent_ok = c.public_scores
        && !c.replay_artifacts
        && !c.audit_contact
        && (!known || c.terms_hash == crate::consent::terms_hash())
        && is_blake3_id(&c.terms_hash);
    r.push(
        "consent",
        consent_ok,
        if consent_ok {
            format!(
                "public_scores under terms {}{}",
                c.terms_version,
                if known { "" } else { " (terms version unknown to this build: hash not checked)" }
            )
        } else {
            "public_scores must be true, the unavailable consents false, and the terms hash must match the terms version".to_string()
        },
    );

    // -- structure ---------------------------------------------------------------------------
    let sp = structure_problems(&bundle);
    r.push(
        "structure",
        sp.is_empty(),
        if sp.is_empty() {
            "units unique and canonically ordered; counts, categories, hardware class, withheld/unrecorded lists agree".to_string()
        } else {
            sp.into_iter().take(5).collect::<Vec<_>>().join("; ")
        },
    );

    // -- oracle vectors ----------------------------------------------------------------------
    let mut op = Vec::new();
    for (i, u) in bundle.body.units.iter().enumerate() {
        for p in oracle_problems(u) {
            op.push(format!("unit {i}: {p}"));
        }
    }
    r.push(
        "oracle-consistency",
        op.is_empty(),
        if op.is_empty() {
            "score gating, sub-score recomputation, failure class and borrowck completeness agree with the error codes".to_string()
        } else {
            let n = op.len();
            format!("{n} problem(s); first: {}", op.into_iter().take(3).collect::<Vec<_>>().join("; "))
        },
    );

    // -- re-derive the statistics ------------------------------------------------------------
    if opts.rederive {
        let iters = bundle
            .body
            .report
            .pointer("/stats/bootstrap_iters")
            .and_then(Value::as_u64)
            .map(|n| n as usize);
        match iters {
            Some(n) if (1..=MAX_BOOTSTRAP_ITERS).contains(&n) => {
                match derive_report(&bundle.body.units, &bundle.body.epoch, n) {
                    Ok(fresh) => match first_mismatch(&fresh, &bundle.body.report, "/report") {
                        None => {
                            let cap = bundle
                                .body
                                .report
                                .pointer("/stats/capability_score")
                                .and_then(Value::as_f64);
                            r.push(
                                "rederived-stats",
                                true,
                                format!(
                                    "bench-stats over the {} units reproduces every reported figure (capability_score {}, {n} bootstrap resamples)",
                                    bundle.body.units.len(),
                                    cap.map_or("n/a".to_string(), |c| format!("{c:.4}"))
                                ),
                            );
                        }
                        Some(m) => r.push(
                            "rederived-stats",
                            false,
                            format!("reported figures do not follow from the units: {m}"),
                        ),
                    },
                    Err(e) => r.push("rederived-stats", false, e.to_string()),
                }
            }
            _ => r.push(
                "rederived-stats",
                false,
                format!(
                    "report.stats.bootstrap_iters missing or outside 1..={MAX_BOOTSTRAP_ITERS}"
                ),
            ),
        }
    } else {
        r.push("rederived-stats", true, "skipped (--no-rederive)");
    }

    // -- run id ------------------------------------------------------------------------------
    let (ok, detail) = run_id_check(&bundle);
    r.push("run-id", ok, detail);
    r
}

fn run_id_check(b: &Bundle) -> (bool, String) {
    let id = &b.body.run_id;
    if !is_token(id, 64) {
        return (false, "run_id is not a plain token".to_string());
    }
    // A derived id is `rb-` + 16 hex chars; recompute it. Anything else is an explicit id.
    let looks_derived =
        id.len() == 19 && id.starts_with("rb-") && id[3..].bytes().all(|c| c.is_ascii_hexdigit());
    if !looks_derived {
        return (true, format!("explicit run id {id}"));
    }
    if crate::bundle::derived_run_id(&b.body.units) == *id {
        (
            true,
            format!("{id} is derived from, and matches, the units"),
        )
    } else {
        (
            false,
            format!("{id} looks derived but does not match the units"),
        )
    }
}

fn grammar_problems(b: &Bundle) -> Vec<String> {
    let mut p = Vec::new();
    let body = &b.body;
    if body.harness_version.is_empty() || !is_token(&body.harness_version, 32) {
        p.push("harness_version is not a plain token".to_string());
    }
    if !is_token(&body.run_id, 64) {
        p.push("run_id is not a plain token".to_string());
    }
    if !is_ident(&body.epoch, 64) {
        p.push("epoch is not a plain identifier".to_string());
    }
    if body.model.name.is_empty()
        || body.model.name.len() > 128
        || !body.model.name.bytes().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'+' | b'-' | b'/')
        })
    {
        p.push("model.name outside [A-Za-z0-9._:+/-]{1,128}".to_string());
    }
    let id = &body.identity;
    for (n, v, max) in [
        ("identity.suite", &id.suite, 32),
        ("identity.suite_hash", &id.suite_hash, 80),
        ("identity.generator_commit", &id.generator_commit, 64),
        ("identity.division", &id.division, 16),
        ("identity.sampling_profile_id", &id.sampling_profile_id, 64),
        ("identity.prompt_pack_hash", &id.prompt_pack_hash, 80),
        ("identity.weights_id", &id.weights_id, 64),
        ("identity.profile_hash", &id.profile_hash, 80),
        (
            "identity.template_fingerprint",
            &id.template_fingerprint,
            80,
        ),
        ("identity.reasoning_mode", &id.reasoning_mode, 32),
        ("identity.exec_class", &id.exec_class, 32),
        ("identity.exec_class_source", &id.exec_class_source, 32),
        ("model.quant", &body.model.quant, 32),
        ("model.backend", &body.model.backend, 32),
        ("model.backend_version", &body.model.backend_version, 48),
    ] {
        if let Some(s) = v {
            if !is_token(s, max) {
                p.push(format!("{n} is not a plain token"));
            }
        }
    }
    if let Some(d) = &id.division {
        if !matches!(d.as_str(), "pinned" | "tuned" | "open") {
            p.push("identity.division must be pinned, tuned or open".to_string());
        }
    }
    for c in &id.categories_scored {
        if !is_ident(c, 64) {
            p.push("identity.categories_scored has a non-identifier".to_string());
        }
    }
    let hw = &body.hw_public;
    for (n, s) in [
        ("hw_class", Some(&hw.hw_class)),
        ("vendor", Some(&hw.vendor)),
        ("cpu_class", Some(&hw.cpu_class)),
        ("generation", hw.generation.as_ref()),
    ] {
        if let Some(s) = s {
            if !is_token(s, 48) {
                p.push(format!("hw_public.{n} is not a plain token"));
            }
        }
    }
    for (i, u) in body.units.iter().enumerate() {
        let mut bad = |what: &str| p.push(format!("unit {i}: {what}"));
        if !is_blake3_id(&u.unit_id) {
            bad("unit_id is not blake3:<64 hex>");
        }
        if !is_ident(&u.family, 64) || !is_ident(&u.category, 64) || !is_ident(&u.sandbox, 32) {
            bad("family / category / sandbox is not a plain identifier");
        }
        if u.kind != "core" && u.kind != "probe" {
            bad("kind is neither core nor probe");
        }
        if u.hw_class.as_deref().is_some_and(|h| !is_token(h, 48)) {
            bad("hw_class is not a plain token");
        }
        if u.finish_reason.as_deref().is_some_and(|f| !is_ident(f, 32)) {
            bad("finish_reason is not a plain identifier");
        }
        if u.oracle.error_codes.iter().any(|c| !is_error_code(c)) {
            bad("an error code is not a rustc code or lint name");
        }
        if u.oracle.flags.iter().any(|f| !is_flag(f)) {
            bad("a flag is outside the flag vocabulary");
        }
        if u.oracle.constraint.violations.len() > 32
            || u.oracle
                .constraint
                .violations
                .iter()
                .any(|v| v.chars().count() > 200)
        {
            bad("violation text over its caps");
        }
    }
    p
}

fn structure_problems(b: &Bundle) -> Vec<String> {
    let mut p = Vec::new();
    let body = &b.body;
    if body.units.is_empty() {
        p.push("no units".to_string());
    }
    let mut seen = BTreeSet::new();
    for (i, u) in body.units.iter().enumerate() {
        if !seen.insert(&u.unit_id) {
            p.push(format!("unit {i}: duplicate unit_id"));
        }
    }
    let mut sorted = body.units.clone();
    crate::bundle::sort_units(&mut sorted);
    if sorted != body.units {
        p.push("units are not in canonical order".to_string());
    }
    let n_core = body.units.iter().filter(|u| u.kind == "core").count();
    let counts = (
        body.report.get("n_core").and_then(Value::as_u64),
        body.report.get("n_probe").and_then(Value::as_u64),
    );
    if counts
        != (
            Some(n_core as u64),
            Some((body.units.len() - n_core) as u64),
        )
    {
        p.push("report.n_core / n_probe disagree with the units".to_string());
    }
    let cats: Vec<String> = body
        .units
        .iter()
        .map(|u| u.category.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if cats != body.identity.categories_scored {
        p.push("identity.categories_scored is not the set of unit categories".to_string());
    }
    if body.units.iter().any(|u| {
        u.hw_class
            .as_deref()
            .is_some_and(|h| h != body.hw_public.hw_class)
    }) {
        p.push(
            "a unit's hw_class differs from hw_public.hw_class (mixed hardware, docs/06)"
                .to_string(),
        );
    }
    let withheld: Vec<&str> = WITHHELD.to_vec();
    if body.withheld.iter().map(String::as_str).collect::<Vec<_>>() != withheld {
        p.push("withheld list is not this build's list".to_string());
    }
    if body.unrecorded != crate::bundle::unrecorded_of(&body.identity, &body.model) {
        p.push("unrecorded list disagrees with the null identity / model fields".to_string());
    }
    p
}

/// Internal coherence of one oracle vector, using only `bench-core`'s own rules.
fn oracle_problems(u: &Unit) -> Vec<String> {
    let mut p = Vec::new();
    let o = &u.oracle;
    let v: OracleVector = match serde_json::to_value(o).and_then(serde_json::from_value) {
        Ok(v) => v,
        Err(_) => return vec!["does not map to an OracleVector".to_string()],
    };
    let in01 = |x: f64| (0.0..=1.0).contains(&x);
    let all_scores = [
        o.behavior.unit,
        o.behavior.property,
        o.behavior.differential,
        o.behavior.score,
        o.constraint.score,
        Some(o.score),
    ];
    if all_scores.iter().flatten().any(|x| !in01(*x)) {
        p.push("a score is outside [0,1]".to_string());
    }
    if !o.apply_ok {
        if o.compile_ok
            || o.score != 0.0
            || !o.error_codes.is_empty()
            || o.behavior.score.is_some()
            || o.constraint.score.is_some()
        {
            p.push("apply failed but later layers are populated".to_string());
        }
        if o.failure_class != FailureClass::Other {
            p.push("apply failed but failure_class is not `other`".to_string());
        }
        return p;
    }
    if !o.compile_ok {
        if o.score != 0.0 {
            p.push("did not compile but score is non-zero".to_string());
        }
        if o.behavior.score.is_some() || o.constraint.score.is_some() {
            p.push("did not compile but behaviour/constraint scores are present".to_string());
        }
        if o.diagnostic_completeness != diagnostic_completeness(&o.error_codes) {
            p.push("diagnostic_completeness disagrees with the error codes".to_string());
        }
        // A message-only `Send` failure carries no code and is classified from the message.
        if o.failure_class != classify_error_codes(&o.error_codes)
            && o.failure_class != FailureClass::AsyncSend
        {
            p.push("failure_class disagrees with the error codes".to_string());
        }
        return p;
    }
    // Compiled: borrowck ran, and the class follows from the layer outcomes.
    if o.diagnostic_completeness != DiagnosticCompleteness::Full {
        p.push("compiled but diagnostic_completeness is not full".to_string());
    }
    let mut b = v.behavior.clone();
    b.recompute();
    if !close_opt(b.score, v.behavior.score) {
        p.push("behavior.score is not the weighted mean of its sub-scores".to_string());
    }
    let mut c = v.constraint.clone();
    c.recompute();
    if !close_opt(c.score, v.constraint.score) {
        p.push("constraint.score is not the mean of its checks".to_string());
    }
    if o.failure_class
        != classify_graded(
            v.behavior.score,
            v.constraint.clippy_clean,
            v.constraint.score,
        )
    {
        p.push("failure_class disagrees with the behaviour/constraint outcome".to_string());
    }
    p
}

fn close_opt(a: Option<f32>, b: Option<f32>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => (x - y).abs() <= 1e-6,
        _ => false,
    }
}

/// First path at which two JSON values differ, comparing numbers with a small tolerance (a
/// verifier on another libm may differ in the last bits of a bootstrap quantile).
pub fn first_mismatch(a: &Value, b: &Value, path: &str) -> Option<String> {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            let (x, y) = (x.as_f64()?, y.as_f64()?);
            let tol = 1e-9 * x.abs().max(y.abs()).max(1.0);
            ((x - y).abs() > tol).then(|| format!("{path}: {x} vs {y}"))
        }
        (Value::Array(x), Value::Array(y)) => {
            if x.len() != y.len() {
                return Some(format!("{path}: length {} vs {}", x.len(), y.len()));
            }
            x.iter()
                .zip(y)
                .enumerate()
                .find_map(|(i, (p, q))| first_mismatch(p, q, &format!("{path}/{i}")))
        }
        (Value::Object(x), Value::Object(y)) => {
            if x.len() != y.len() || x.keys().any(|k| !y.contains_key(k)) {
                return Some(format!("{path}: different keys"));
            }
            x.iter()
                .find_map(|(k, p)| first_mismatch(p, &y[k], &format!("{path}/{k}")))
        }
        _ => (a != b).then(|| format!("{path}: {a} vs {b}")),
    }
}
