//! The upload bundle: journal + hardware profile -> a redacted, schema-validated, canonically
//! serialised document with a content hash (docs/11 "What is uploaded", docs/12).
//!
//! # Design
//!
//! * **Allow-list.** A journal line is parsed into a struct that *names* the fields we take.
//!   Everything else (`seed`, `model.base_url`, `canary`, ...) is never read, so it cannot leak by
//!   omission from a deny-list (REVIEW-5 `redaction-is-a-denylist`).
//! * **Strict grammar.** Identifier-shaped fields must match a token grammar or the export is
//!   refused; they are not "cleaned". Only the genuinely free-text fields are scrubbed.
//! * **Seeds stay home.** Generated `task_id`s are `family/{seed:016x}` — the seed is in the id.
//!   Publishing `task_id` would publish every seed immediately, contradicting docs/11 ("WITHHELD
//!   until the epoch closes", REVIEW-5 R5-S7). The bundle carries `family` + `index` + `kind` and
//!   the opaque `unit_id` (a blake3 over task id + seed + index) instead.
//! * **Fail closed.** After construction the whole body is scanned again; any hit aborts.
//! * **Deterministic.** Units are sorted; maps are ordered; floats are shortest-round-trip; there
//!   is no clock and no RNG. Same inputs, same bytes, same hash.

use crate::canon::{canonical_bytes, content_hash, is_blake3_id, CANON_VERSION};
use crate::error::SubmitError;
use crate::redact::{Kind, LocalFacts, RedactionStats, Redactor};
use bench_core::{DiagnosticCompleteness, FailureClass, OracleVector};
use bench_hw::{HwProfile, HwPublic};
use bench_stats::Record;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub const SCHEMA: u32 = 1;
pub const KIND: &str = "rustybench.upload-bundle";
/// Refuse to build or accept a bundle larger than this (a sanity bound, not a server limit).
pub const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
/// Verifier-side cap on the bootstrap count it will re-run (a hostile bundle must not buy CPU).
pub const MAX_BOOTSTRAP_ITERS: usize = 100_000;

/// Fields deliberately NOT in the bundle, listed in it so a reader can see the omission is a
/// decision. (`task_id` is present only as its seed-free `family` prefix.)
pub const WITHHELD: &[&str] = &[
    "base_url",
    "batch_nonce",
    "calibration_raw",
    "canary",
    "completed_at",
    "epoch_seed",
    "machine_uuid",
    "model_output",
    "model_path",
    "seed",
    "task_id_seed_suffix",
];

// ---------------------------------------------------------------------------
// Bundle types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub schema: u32,
    /// Names the canonical byte form (see `canon.rs`).
    pub canon: String,
    /// `blake3:` hash over the domain-separated canonical bytes of `body`.
    pub content_hash: String,
    pub body: Body,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Body {
    pub kind: String,
    pub harness_version: String,
    pub run_id: String,
    pub epoch: String,
    pub identity: Identity,
    pub model: ModelPublic,
    pub hw_public: HwPublic,
    pub units: Vec<Unit>,
    /// Aggregates re-derivable from `units` by `verify-bundle` (`n_core`, `n_probe`, `stats`).
    pub report: Value,
    pub consents: Consents,
    pub withheld: Vec<String>,
    /// Row-key / model fields (docs/15 §10.1, REVIEW-6 R6-S4) the journal did not carry, so the
    /// server can see what is unknown instead of guessing.
    pub unrecorded: Vec<String>,
}

/// The comparability key (docs/15 §10.1) as far as it is recorded locally. Every field is always
/// present; `null` means "not recorded", never "empty".
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub suite: Option<String>,
    pub suite_hash: Option<String>,
    pub generator_commit: Option<String>,
    pub division: Option<String>,
    pub sampling_profile_id: Option<String>,
    pub prompt_pack_hash: Option<String>,
    pub weights_id: Option<String>,
    pub profile_hash: Option<String>,
    pub template_fingerprint: Option<String>,
    pub reasoning_mode: Option<String>,
    pub exec_class: Option<String>,
    pub exec_class_source: Option<String>,
    pub tools_offered: Option<bool>,
    /// Derived from the units, not declared: the distinct categories that have a unit.
    pub categories_scored: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPublic {
    pub name: String,
    pub quant: Option<String>,
    pub backend: Option<String>,
    pub backend_version: Option<String>,
    pub ctx: Option<u32>,
    pub ngl: Option<u32>,
    pub sampling: Option<Sampling>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sampling {
    pub temp: Option<f64>,
    pub top_p: Option<f64>,
    pub top_k: Option<u32>,
    pub seed: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consents {
    pub public_scores: bool,
    /// Not available in this build (needs a server key); always false.
    pub replay_artifacts: bool,
    /// Not available in this build (needs an identity channel); always false.
    pub audit_contact: bool,
    pub terms_version: String,
    pub terms_hash: String,
}

impl Consents {
    pub fn public_scores_granted() -> Consents {
        Consents {
            public_scores: true,
            replay_artifacts: false,
            audit_contact: false,
            terms_version: crate::consent::TERMS_VERSION.to_string(),
            terms_hash: crate::consent::terms_hash(),
        }
    }
}

/// One graded unit, public form. No seed, no canary, no timestamps, no model text.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unit {
    pub unit_id: String,
    /// The task family: `task_id` up to the first `/` (the seed-bearing suffix is dropped).
    pub family: String,
    pub category: String,
    /// `core` (scored) or `probe` (detector only), ADR-0009.
    pub kind: String,
    pub index: u32,
    pub segment: Option<u32>,
    pub segment_position: Option<u32>,
    pub hw_class: Option<String>,
    pub sandbox: String,
    pub finish_reason: Option<String>,
    pub oracle: UnitOracle,
    pub cost: UnitCost,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitOracle {
    pub apply_ok: bool,
    pub compile_ok: bool,
    pub error_codes: Vec<String>,
    pub warn_count: u32,
    pub diagnostic_completeness: DiagnosticCompleteness,
    pub behavior: UBehavior,
    pub constraint: UConstraint,
    pub score: f64,
    pub failure_class: FailureClass,
    pub flags: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UBehavior {
    pub unit: Option<f64>,
    pub property: Option<f64>,
    pub differential: Option<f64>,
    pub score: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UConstraint {
    pub alloc_ok: Option<bool>,
    pub clippy_clean: Option<bool>,
    pub fmt_ok: Option<bool>,
    pub unsafe_blocks: Option<u32>,
    pub unsafe_ok: Option<bool>,
    pub paths_ok: Option<bool>,
    pub violations: Vec<String>,
    pub score: Option<f64>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitCost {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub gen_ms: u64,
    pub grade_ms: u64,
}

// ---------------------------------------------------------------------------
// Grammar
// ---------------------------------------------------------------------------

/// `[A-Za-z0-9][A-Za-z0-9._-]*`, at most `max` bytes: family, category, epoch, sandbox, finish reason.
pub fn is_ident(s: &str, max: usize) -> bool {
    is_token(s, max) && !s.contains([':', '+'])
}

/// `[A-Za-z0-9][A-Za-z0-9._:+-]*`, at most `max` bytes. Every identifier-shaped field must match.
pub fn is_token(s: &str, max: usize) -> bool {
    let mut b = s.bytes();
    match b.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    s.len() <= max
        && b.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'+' | b'-'))
}

/// Lower-case words joined by single underscores: `network_attempt`, `no_summary`. No digits:
/// the harness's flag vocabulary has none, and a digit-bearing token is where a serial hides.
fn is_snake_words(p: &str) -> bool {
    !p.is_empty()
        && p.split('_')
            .all(|w| !w.is_empty() && w.bytes().all(|c| c.is_ascii_lowercase()))
}

/// `timeout`, `timeout:build`, `behavior:no_summary` (docs/12 `flags`).
pub fn is_flag(s: &str) -> bool {
    s.len() <= 48 && s.split(':').all(is_snake_words)
}

/// A rustc error code (`E0499`) or a lint name (`dead_code`, `clippy::needless_range_loop`,
/// optionally ending `_10` as in `from_str_radix_10`). Anything else is not a diagnostic code.
pub fn is_error_code(s: &str) -> bool {
    if s.len() > 48 {
        return false;
    }
    if s.len() == 5 && s.starts_with('E') && s[1..].bytes().all(|c| c.is_ascii_digit()) {
        return true;
    }
    let seg = |p: &str| {
        let p = match p.rsplit_once('_') {
            Some((head, tail))
                if !tail.is_empty()
                    && tail.bytes().all(|c| c.is_ascii_digit())
                    && tail.len() <= 3 =>
            {
                head
            }
            _ => p,
        };
        is_snake_words(p)
    };
    s.split("::").count() <= 2 && s.split("::").all(seg)
}

// ---------------------------------------------------------------------------
// Journal parsing (the allow-list)
// ---------------------------------------------------------------------------

fn d_local() -> String {
    "local".to_string()
}
fn d_core() -> String {
    "core".to_string()
}

#[derive(Deserialize)]
struct RawModel {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Deserialize, Default)]
struct RawCost {
    #[serde(default)]
    prompt_tokens: u32,
    #[serde(default)]
    completion_tokens: u32,
    #[serde(default)]
    gen_ms: u64,
    #[serde(default)]
    grade_ms: u64,
}

/// The only journal fields this crate reads. Anything not named here is invisible to it.
#[derive(Deserialize)]
struct RawLine {
    #[serde(default)]
    schema: Option<u32>,
    unit_id: String,
    task_id: String,
    category: String,
    #[serde(default)]
    index: u32,
    #[serde(default = "d_local")]
    epoch: String,
    #[serde(default = "d_core")]
    kind: String,
    #[serde(default)]
    segment: Option<u32>,
    #[serde(default)]
    segment_position: Option<u32>,
    #[serde(default)]
    hw_class: Option<String>,
    #[serde(default)]
    model: Option<RawModel>,
    #[serde(default)]
    sandbox: Option<String>,
    oracle: OracleVector,
    #[serde(default)]
    cost: RawCost,
}

fn f64_of(x: f32, what: &str) -> Result<f64, SubmitError> {
    if !x.is_finite() || !(0.0..=1.0).contains(&x) {
        return Err(SubmitError::Input(format!(
            "{what}: score outside [0,1] or non-finite"
        )));
    }
    format!("{x}")
        .parse::<f64>()
        .map_err(|_| SubmitError::Input(format!("{what}: unparsable score")))
}

fn opt_f64(x: Option<f32>, what: &str) -> Result<Option<f64>, SubmitError> {
    x.map(|v| f64_of(v, what)).transpose()
}

struct Scrub<'a> {
    redactor: &'a Redactor,
    stats: RedactionStats,
}

impl Scrub<'_> {
    fn text(&mut self, s: &str, max_chars: usize) -> String {
        let r = self.redactor.scrub(s);
        self.stats.add(&r.hits);
        r.text.chars().take(max_chars).collect()
    }

    fn error_code(&mut self, s: &str) -> String {
        // A grammar match is not enough: IPs, MACs and hostnames are also `[A-Za-z0-9_:.-]+`.
        if is_error_code(s) && self.redactor.scrub(s).text == s {
            return s.to_string();
        }
        let t = self.text(s, 48);
        if is_error_code(&t) && !t.contains('<') {
            t
        } else {
            self.stats.add(&[Kind::Id]);
            "unrecognised".to_string()
        }
    }

    fn flag(&mut self, s: &str) -> String {
        if is_flag(s) && self.redactor.scrub(s).text == s && self.redactor.find_leaks(s).is_empty()
        {
            return s.to_string();
        }
        let t = self.text(s, 48);
        if is_flag(&t) {
            t
        } else {
            self.stats.add(&[Kind::Id]);
            "other".to_string()
        }
    }
}

struct Parsed {
    units: Vec<Unit>,
    models: BTreeSet<String>,
    epochs: BTreeSet<String>,
}

/// Parse a journal into public units (sorted), plus the raw model names and epochs seen.
fn parse_journal(text: &str, sc: &mut Scrub<'_>) -> Result<Parsed, SubmitError> {
    let mut units = Vec::new();
    let mut models = BTreeSet::new();
    let mut epochs = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let n = i + 1;
        let bad = |field: &str, why: &str| {
            SubmitError::Refused(format!("journal line {n}: field `{field}` {why}"))
        };
        let raw: RawLine = serde_json::from_str(line)
            .map_err(|e| SubmitError::Input(format!("journal line {n}: {}", e.classify_msg())))?;
        if let Some(s) = raw.schema {
            if s != 1 {
                return Err(SubmitError::Input(format!(
                    "journal line {n}: unknown schema major {s} (this build reads 1)"
                )));
            }
        }
        if !is_blake3_id(&raw.unit_id) {
            return Err(bad("unit_id", "is not blake3:<64 hex>"));
        }
        if !seen.insert(raw.unit_id.clone()) {
            return Err(bad("unit_id", "is a duplicate"));
        }
        let family = raw.task_id.split('/').next().unwrap_or("").to_string();
        if !is_ident(&family, 64) {
            return Err(bad("task_id", "has no publishable family prefix"));
        }
        if !is_ident(&raw.category, 64) {
            return Err(bad("category", "is not a plain token"));
        }
        if raw.kind != "core" && raw.kind != "probe" {
            return Err(bad("kind", "is neither `core` nor `probe`"));
        }
        if !is_ident(&raw.epoch, 64) {
            return Err(bad(
                "epoch",
                "is not a plain token (an epoch label must be publishable)",
            ));
        }
        if let Some(h) = &raw.hw_class {
            if !is_token(h, 48) {
                return Err(bad("hw_class", "is not a plain token"));
            }
        }
        let sandbox = match raw.sandbox {
            Some(s) if is_ident(&s, 32) => s,
            Some(_) => return Err(bad("sandbox", "is not a plain token")),
            None => "unrecorded".to_string(),
        };
        let (model_name, finish_reason) = match raw.model {
            Some(m) => (m.name, m.finish_reason),
            None => (None, None),
        };
        if let Some(f) = &finish_reason {
            if !is_ident(f, 32) {
                return Err(bad("model.finish_reason", "is not a plain token"));
            }
        }
        models.insert(model_name.unwrap_or_default());

        let o = &raw.oracle;
        let mut error_codes: Vec<String> = o
            .error_codes
            .iter()
            .take(64)
            .map(|c| sc.error_code(c))
            .collect();
        error_codes.sort();
        let violations: Vec<String> = o
            .constraint
            .violations
            .iter()
            .take(32)
            .map(|v| sc.text(v, 200))
            .collect();
        let mut flags: Vec<String> = o.flags.iter().take(32).map(|f| sc.flag(f)).collect();
        flags.sort();
        let oracle = UnitOracle {
            apply_ok: o.apply_ok,
            compile_ok: o.compile_ok,
            error_codes,
            warn_count: o.warn_count,
            diagnostic_completeness: o.diagnostic_completeness,
            behavior: UBehavior {
                unit: opt_f64(o.behavior.unit, "behavior.unit")?,
                property: opt_f64(o.behavior.property, "behavior.property")?,
                differential: opt_f64(o.behavior.differential, "behavior.differential")?,
                score: opt_f64(o.behavior.score, "behavior.score")?,
            },
            constraint: UConstraint {
                alloc_ok: o.constraint.alloc_ok,
                clippy_clean: o.constraint.clippy_clean,
                fmt_ok: o.constraint.fmt_ok,
                unsafe_blocks: o.constraint.unsafe_blocks,
                unsafe_ok: o.constraint.unsafe_ok,
                paths_ok: o.constraint.paths_ok,
                violations,
                score: opt_f64(o.constraint.score, "constraint.score")?,
            },
            score: f64_of(o.score, "score")?,
            failure_class: o.failure_class,
            flags,
        };
        units.push(Unit {
            unit_id: raw.unit_id,
            family,
            category: raw.category,
            kind: raw.kind,
            index: raw.index,
            segment: raw.segment,
            segment_position: raw.segment_position,
            hw_class: raw.hw_class,
            sandbox,
            finish_reason,
            oracle,
            cost: UnitCost {
                prompt_tokens: raw.cost.prompt_tokens,
                completion_tokens: raw.cost.completion_tokens,
                gen_ms: raw.cost.gen_ms,
                grade_ms: raw.cost.grade_ms,
            },
        });
        epochs.insert(raw.epoch);
    }
    sort_units(&mut units);
    Ok(Parsed {
        units,
        models,
        epochs,
    })
}

trait ClassifyMsg {
    fn classify_msg(&self) -> String;
}
impl ClassifyMsg for serde_json::Error {
    /// serde_json messages can quote input text; keep only the category and position.
    fn classify_msg(&self) -> String {
        format!("{:?} at column {}", self.classify(), self.column())
    }
}

/// Canonical unit order: core before probe, then family, index, unit id.
pub fn sort_units(units: &mut [Unit]) {
    units.sort_by(|a, b| {
        (&a.kind, &a.family, a.index, &a.unit_id).cmp(&(&b.kind, &b.family, b.index, &b.unit_id))
    });
}

// ---------------------------------------------------------------------------
// Identity input
// ---------------------------------------------------------------------------

#[derive(Default)]
struct IdentityInput {
    identity: Identity,
    model: ModelPublic,
}

fn get_str(
    obj: &serde_json::Map<String, Value>,
    keys: &[&str],
    max: usize,
) -> Result<Option<String>, SubmitError> {
    for k in keys {
        match obj.get(*k) {
            None | Some(Value::Null) => continue,
            Some(Value::String(s)) if is_token(s, max) => return Ok(Some(s.clone())),
            Some(_) => {
                return Err(SubmitError::Refused(format!(
                    "identity file: `{k}` is not a plain token of at most {max} characters"
                )))
            }
        }
    }
    Ok(None)
}

fn get_u32(obj: &serde_json::Map<String, Value>, key: &str) -> Result<Option<u32>, SubmitError> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| SubmitError::Refused(format!("identity file: `{key}` is not a u32"))),
    }
}

fn get_f(obj: &serde_json::Map<String, Value>, key: &str) -> Result<Option<f64>, SubmitError> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_f64()
            .filter(|x| x.is_finite())
            .map(Some)
            .ok_or_else(|| {
                SubmitError::Refused(format!("identity file: `{key}` is not a finite number"))
            }),
    }
}

/// Read an identity description: either a docs/12 `state.json` (the `identity` object is taken)
/// or the identity object itself. Only the named keys are read; everything else is ignored.
fn parse_identity(text: &str) -> Result<IdentityInput, SubmitError> {
    let v: Value = serde_json::from_str(text)
        .map_err(|e| SubmitError::Input(format!("identity file: {}", e.classify_msg())))?;
    let obj = v
        .get("identity")
        .and_then(Value::as_object)
        .or_else(|| v.as_object())
        .ok_or_else(|| SubmitError::Input("identity file: not a JSON object".into()))?;

    let mut id = Identity {
        suite: get_str(obj, &["suite"], 32)?,
        suite_hash: get_str(obj, &["suite_hash"], 80)?,
        generator_commit: get_str(obj, &["generator_commit"], 64)?,
        division: get_str(obj, &["division"], 16)?,
        sampling_profile_id: get_str(obj, &["sampling_profile_id"], 64)?,
        prompt_pack_hash: get_str(obj, &["prompt_pack_hash"], 80)?,
        weights_id: get_str(obj, &["weights_id"], 64)?,
        profile_hash: get_str(obj, &["profile_hash"], 80)?,
        template_fingerprint: get_str(obj, &["template_fingerprint"], 80)?,
        reasoning_mode: get_str(obj, &["reasoning_mode", "reasoning_format"], 32)?,
        exec_class: get_str(obj, &["exec_class"], 32)?,
        exec_class_source: get_str(obj, &["exec_class_source"], 32)?,
        tools_offered: obj.get("tools_offered").and_then(Value::as_bool),
        categories_scored: Vec::new(),
    };
    if let Some(d) = &id.division {
        if !matches!(d.as_str(), "pinned" | "tuned" | "open") {
            return Err(SubmitError::Refused(
                "identity file: `division` must be pinned, tuned or open".into(),
            ));
        }
    }
    id.categories_scored.clear();

    let mut model = ModelPublic::default();
    if let Some(m) = obj.get("model").and_then(Value::as_object) {
        model.quant = get_str(m, &["quant"], 32)?;
        model.backend = get_str(m, &["backend"], 32)?;
        model.backend_version = get_str(m, &["backend_version"], 48)?;
        model.ctx = get_u32(m, "ctx")?;
        model.ngl = get_u32(m, "ngl")?;
    }
    if let Some(s) = obj.get("sampling").and_then(Value::as_object) {
        model.sampling = Some(Sampling {
            temp: get_f(s, "temp")?,
            top_p: get_f(s, "top_p")?,
            top_k: get_u32(s, "top_k")?,
            seed: match s.get("seed") {
                None | Some(Value::Null) => None,
                Some(v) => Some(v.as_u64().ok_or_else(|| {
                    SubmitError::Refused(
                        "identity file: `sampling.seed` is not an unsigned integer".into(),
                    )
                })?),
            },
        });
    }
    Ok(IdentityInput {
        identity: id,
        model,
    })
}

// ---------------------------------------------------------------------------
// Hardware
// ---------------------------------------------------------------------------

/// Accept the full local `hw.json` (and reduce it with bench-hw's own bucketing) or an
/// already-public view. Raw host details never reach the bundle either way.
fn parse_hw(text: &str) -> Result<HwPublic, SubmitError> {
    let public = if let Ok(p) = serde_json::from_str::<HwProfile>(text) {
        p.public()
    } else {
        serde_json::from_str::<HwPublic>(text).map_err(|e| {
            SubmitError::Input(format!(
                "hw file: neither a hw profile nor a public view ({})",
                e.classify_msg()
            ))
        })?
    };
    for (name, v) in [
        ("hw_class", Some(&public.hw_class)),
        ("vendor", Some(&public.vendor)),
        ("cpu_class", Some(&public.cpu_class)),
        ("generation", public.generation.as_ref()),
    ] {
        if let Some(v) = v {
            if !(is_token(v, 48) || v.ends_with('+') && is_token(&v[..v.len() - 1], 47)) {
                return Err(SubmitError::Refused(format!(
                    "hw file: `{name}` is not a plain token"
                )));
            }
        }
    }
    Ok(public)
}

// ---------------------------------------------------------------------------
// Report (shared by the builder and by verify-bundle)
// ---------------------------------------------------------------------------

/// Map a public unit to the record `bench-stats` reads. Round-trips through JSON so the exact
/// deserialiser the `stats` command uses is the one applied.
pub fn record_of(u: &Unit, epoch: &str) -> Result<Record, SubmitError> {
    let v = json!({
        "task_id": u.family,
        "category": u.category,
        "oracle": u.oracle,
        "kind": u.kind,
        "index": u.index,
        "epoch": epoch,
        "segment": u.segment,
        "segment_position": u.segment_position,
        "hw_class": u.hw_class,
        "cost": u.cost,
    });
    serde_json::from_value(v)
        .map_err(|e| SubmitError::Input(format!("unit does not map to a stats record: {e}")))
}

/// The aggregates block: the same `bench-stats` computation a server (or `rustybench stats`)
/// would run over these units.
pub fn derive_report(units: &[Unit], epoch: &str, iters: usize) -> Result<Value, SubmitError> {
    let records = units
        .iter()
        .map(|u| record_of(u, epoch))
        .collect::<Result<Vec<_>, _>>()?;
    let stats = bench_stats::report_with(&records, iters);
    let n_core = units.iter().filter(|u| u.kind == "core").count();
    Ok(json!({
        "n_core": n_core,
        "n_probe": units.len() - n_core,
        "stats": stats,
    }))
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

pub struct BuildInputs<'a> {
    pub journal: &'a str,
    pub hw_json: &'a str,
    pub identity_json: Option<&'a str>,
    /// Explicit run id; otherwise one is derived from the units (identical results dedupe).
    pub run_id: Option<&'a str>,
}

pub struct BuildOptions {
    pub bootstrap_iters: usize,
    pub facts: LocalFacts,
    pub consents: Consents,
}

impl Default for BuildOptions {
    fn default() -> Self {
        BuildOptions {
            bootstrap_iters: bench_stats::BOOTSTRAP_ITERS,
            facts: LocalFacts::default(),
            consents: Consents::public_scores_granted(),
        }
    }
}

#[derive(Debug)]
pub struct Built {
    pub bundle: Bundle,
    /// Exactly the bytes that would be uploaded / written (canonical JSON plus `\n`).
    pub bytes: Vec<u8>,
    pub units: usize,
    pub core: usize,
    pub probe: usize,
    pub redactions: RedactionStats,
    /// Benign journal repairs applied before building (a torn final line dropped, identical
    /// duplicate lines collapsed). Anything else refuses the export instead.
    pub journal_notes: Vec<String>,
}

pub fn derived_run_id(units: &[Unit]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"rustybench.run-id.v1\0");
    for u in units {
        h.update(&canonical_bytes(
            &serde_json::to_value(u).unwrap_or(Value::Null),
        ));
        h.update(&[0]);
    }
    format!("rb-{}", &h.finalize().to_hex()[..16])
}

pub fn build(inputs: &BuildInputs<'_>, opts: &BuildOptions) -> Result<Built, SubmitError> {
    if opts.bootstrap_iters == 0 || opts.bootstrap_iters > MAX_BOOTSTRAP_ITERS {
        return Err(SubmitError::Input(format!(
            "bootstrap iterations must be 1..={MAX_BOOTSTRAP_ITERS}"
        )));
    }
    let redactor = Redactor::new(&opts.facts);
    let mut sc = Scrub {
        redactor: &redactor,
        stats: RedactionStats::default(),
    };

    // docs/09 crash recovery, as far as export may go: a torn final line (an interrupted append) and
    // identical duplicate lines are benign and are dropped with a note. Anything else means a unit
    // may be missing or ambiguous, so the export is refused rather than silently partial.
    let scanned = bench_core::journal::scan(inputs.journal);
    if scanned.has_conflicting_duplicates() {
        return Err(SubmitError::Refused(
            "journal holds two different records for one unit (duplicate unit_id); run `rustybench journal --repair`".into(),
        ));
    }
    if scanned.repairs.iter().any(|r| {
        !matches!(
            r.kind,
            bench_core::journal::RepairKind::TornTail
                | bench_core::journal::RepairKind::Duplicate { identical: true }
        )
    }) {
        return Err(SubmitError::Input(format!(
            "journal needs repair before export ({}); run `rustybench journal --repair`",
            scanned
                .summary()
                .into_iter()
                .take(3)
                .collect::<Vec<_>>()
                .join("; ")
        )));
    }
    let journal_notes = scanned.summary();
    let Parsed {
        units,
        models,
        epochs,
    } = parse_journal(&scanned.clean, &mut sc)?;
    if units.is_empty() {
        return Err(SubmitError::Input("journal has no units".into()));
    }
    if epochs.len() != 1 {
        return Err(SubmitError::Refused(format!(
            "journal spans {} epochs; export one epoch at a time",
            epochs.len()
        )));
    }
    let epoch = epochs.into_iter().next().unwrap_or_default();
    if models.len() != 1 {
        return Err(SubmitError::Refused(format!(
            "journal mixes {} model names; split it per model before exporting",
            models.len()
        )));
    }
    let raw_model = models.into_iter().next().unwrap_or_default();

    let hw_public = parse_hw(inputs.hw_json)?;
    for u in &units {
        if let Some(h) = &u.hw_class {
            if *h != hw_public.hw_class {
                return Err(SubmitError::Refused(format!(
                    "journal hardware class does not match the hw file ({} unit(s) differ); throughput from different machines is not comparable (docs/06)",
                    units.iter().filter(|x| x.hw_class.as_deref().is_some_and(|c| c != hw_public.hw_class)).count()
                )));
            }
        }
    }

    let IdentityInput {
        mut identity,
        mut model,
    } = match inputs.identity_json {
        Some(t) => parse_identity(t)?,
        None => IdentityInput::default(),
    };
    let mut name_hits = Vec::new();
    model.name = redactor.sanitize_model_name(&raw_model, &mut name_hits);
    sc.stats.add(&name_hits);
    identity.categories_scored = units
        .iter()
        .map(|u| u.category.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let run_id = match inputs.run_id {
        Some(r) if is_token(r, 64) => r.to_string(),
        Some(_) => {
            return Err(SubmitError::Refused(
                "--run-id is not a plain token of at most 64 characters".into(),
            ))
        }
        None => derived_run_id(&units),
    };

    let unrecorded = unrecorded_of(&identity, &model);

    let report = derive_report(&units, &epoch, opts.bootstrap_iters)?;
    let n_core = units.iter().filter(|u| u.kind == "core").count();
    let n_units = units.len();

    let body = Body {
        kind: KIND.to_string(),
        harness_version: env!("CARGO_PKG_VERSION").to_string(),
        run_id,
        epoch,
        identity,
        model,
        hw_public,
        units,
        report,
        consents: opts.consents.clone(),
        withheld: WITHHELD.iter().map(|s| s.to_string()).collect(),
        unrecorded,
    };
    let body_value = serde_json::to_value(&body).map_err(|e| SubmitError::Io(e.to_string()))?;
    leak_check(&redactor, &body_value)?;

    let bundle = Bundle {
        schema: SCHEMA,
        canon: CANON_VERSION.to_string(),
        content_hash: content_hash(&body_value),
        body,
    };
    let bytes = bundle_bytes(&bundle)?;
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(SubmitError::Refused(format!(
            "bundle is {} bytes, over the {MAX_BUNDLE_BYTES} cap",
            bytes.len()
        )));
    }
    Ok(Built {
        bundle,
        bytes,
        units: n_units,
        core: n_core,
        probe: n_units - n_core,
        redactions: sc.stats,
        journal_notes,
    })
}

/// Canonical bytes of the whole bundle plus a trailing newline: the upload payload.
pub fn bundle_bytes(b: &Bundle) -> Result<Vec<u8>, SubmitError> {
    let v = serde_json::to_value(b).map_err(|e| SubmitError::Io(e.to_string()))?;
    let mut bytes = canonical_bytes(&v);
    bytes.push(b'\n');
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Leak scan (fail closed)
// ---------------------------------------------------------------------------

/// Scan every string *value* in `v` (schema keys are constants, not data). Structural ids
/// (`blake3:<hex>`) and a hex `generator_commit` are exempt; everything else must be clean.
/// Errors name the JSON pointer and the kinds found, never the matched text.
pub fn leak_check(redactor: &Redactor, v: &Value) -> Result<(), SubmitError> {
    let mut found = Vec::new();
    walk(redactor, v, &mut String::new(), &mut found);
    if found.is_empty() {
        Ok(())
    } else {
        Err(SubmitError::Leak(
            found
                .iter()
                .take(5)
                .map(|(p, k)| {
                    format!(
                        "{p}: {}",
                        k.iter().map(|x| x.name()).collect::<Vec<_>>().join("+")
                    )
                })
                .collect::<Vec<_>>()
                .join("; "),
        ))
    }
}

fn walk(r: &Redactor, v: &Value, path: &mut String, found: &mut Vec<(String, Vec<Kind>)>) {
    match v {
        Value::String(s) => {
            let exempt = is_blake3_id(s)
                || (path.ends_with("/generator_commit")
                    && (7..=64).contains(&s.len())
                    && s.bytes().all(|b| b.is_ascii_hexdigit()));
            if !exempt {
                let k = r.find_leaks(s);
                if !k.is_empty() {
                    found.push((path.clone(), k));
                }
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                let n = path.len();
                path.push_str(&format!("/{i}"));
                walk(r, x, path, found);
                path.truncate(n);
            }
        }
        Value::Object(m) => {
            for (k, x) in m {
                let n = path.len();
                path.push('/');
                path.push_str(k);
                // Map keys under `report` are category / hw-class names, i.e. data.
                if path.starts_with("/report") {
                    let kk = r.find_leaks(k);
                    if !kk.is_empty() {
                        found.push((path.clone(), kk));
                    }
                }
                walk(r, x, path, found);
                path.truncate(n);
            }
        }
        _ => {}
    }
}

/// The row-key / model fields (docs/15 §10.1, REVIEW-6 R6-S4) that are `null` in this bundle.
pub fn unrecorded_of(identity: &Identity, model: &ModelPublic) -> Vec<String> {
    [
        ("identity.suite_hash", identity.suite_hash.is_some()),
        (
            "identity.prompt_pack_hash",
            identity.prompt_pack_hash.is_some(),
        ),
        (
            "identity.sampling_profile_id",
            identity.sampling_profile_id.is_some(),
        ),
        ("identity.division", identity.division.is_some()),
        ("identity.weights_id", identity.weights_id.is_some()),
        (
            "identity.template_fingerprint",
            identity.template_fingerprint.is_some(),
        ),
        ("identity.reasoning_mode", identity.reasoning_mode.is_some()),
        ("identity.exec_class", identity.exec_class.is_some()),
        ("model.quant", model.quant.is_some()),
        ("model.backend", model.backend.is_some()),
        ("model.backend_version", model.backend_version.is_some()),
        ("model.ctx", model.ctx.is_some()),
    ]
    .into_iter()
    .filter(|(_, present)| !present)
    .map(|(n, _)| n.to_string())
    .collect()
}
