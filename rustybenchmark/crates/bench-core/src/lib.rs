//! `bench-core` — the shared vocabulary of Rustybenchmark.
//!
//! This crate is pure: no I/O, no async, no process spawning. It depends on
//! nothing else in the workspace, and everything else depends on it. That
//! invariant (docs/13-architecture.md) is what keeps the type system coherent
//! as the leaf crates grow.
//!
//! Scope so far: identifiers, the instance a model is graded on, the layered
//! oracle *vector*, the scoring arithmetic, the rustc-diagnostic → `FailureClass`
//! classification (error codes, message patterns, and compiled-unit layer
//! outcomes), and per-layer weight renormalisation. L2 behaviour and the L3
//! allocation/clippy constraints are populated; L2 property and L4 quality are
//! declared but not yet filled.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/// A task family identifier, e.g. `"borrowck/split-mut-window"`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaskId(pub String);

impl std::fmt::Display for TaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A per-instance seed. Frozen tasks use a fixed value; generated tasks derive
/// it from the epoch / challenge nonce (docs/02-task-format.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Seed(pub u64);

/// The blake3 identity of a work unit, rendered as `"blake3:<hex>"`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UnitId(pub String);

/// The atom of execution and checkpointing: one `(task, seed)` at a fixed plan
/// position. Independent and idempotent — re-running one reproduces both the
/// instance (generation is deterministic) and the grade (the oracle is).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkUnit {
    pub task_id: TaskId,
    pub seed: Seed,
    pub index: u32,
}

impl WorkUnit {
    /// Deterministic identity. Same inputs → same id, which is what makes
    /// resume and replay-verification trivially correct.
    pub fn unit_id(&self) -> UnitId {
        let mut h = blake3::Hasher::new();
        h.update(self.task_id.0.as_bytes());
        h.update(&[0u8]); // domain separator between the two length-varying fields
        h.update(&self.seed.0.to_le_bytes());
        h.update(&self.index.to_le_bytes());
        UnitId(format!("blake3:{}", h.finalize().to_hex()))
    }
}

// ---------------------------------------------------------------------------
// Task manifest (the struct; parsing lives in the crate that reads task.toml)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskKind {
    /// A fixed instance with no generation. Development and smoke only — refused
    /// by scored suites (docs/02-task-format.md).
    Frozen,
    Seeded,
    Mined,
}

/// Per-category oracle weights. Global defaults are wrong for several
/// categories (docs/04-categories.md); they are overridable per family
/// (`[weights]` in task.toml).
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct OracleWeights {
    pub behavior: f32,
    pub constraint: f32,
    pub quality: f32,
}

impl Default for OracleWeights {
    fn default() -> Self {
        // docs/03-oracle.md global default. behavior 0.70 / constraint 0.20 /
        // quality 0.10. Per-category overrides come in P2.
        OracleWeights {
            behavior: 0.70,
            constraint: 0.20,
            quality: 0.10,
        }
    }
}

// ---------------------------------------------------------------------------
// Instance — the concrete problem handed to a model
// ---------------------------------------------------------------------------

/// A materialised problem. `files` are shown to the model; `hidden` (the
/// oracle) is injected into a *separate* grading workspace after the model's
/// turn, never present while the model runs (docs/03-oracle.md).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Instance {
    pub prompt: String,
    pub files: BTreeMap<PathBuf, String>,
    pub hidden: BTreeMap<PathBuf, String>,
    /// A unique low-frequency string embedded in the prompt; its later
    /// appearance in a public corpus is direct evidence of leakage.
    pub canary: String,
}

// ---------------------------------------------------------------------------
// The oracle vector — a graded result is a vector, never a bit
// ---------------------------------------------------------------------------

/// Behaviour layer (L2). Sub-oracles are `Option` because a gate failure below
/// them short-circuits: a solution that does not compile has no behaviour score.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct BehaviorScore {
    /// Fraction of hidden example tests passed.
    pub unit: Option<f32>,
    /// Fraction of invariant properties held.
    pub property: Option<f32>,
    /// Agreement with the hidden reference over generated inputs. This is what
    /// catches a solution that passes every visible test and is still wrong —
    /// unit tests overstate correctness by 30–32% (docs/01, docs/03).
    pub differential: Option<f32>,
    /// Weighted combination of whichever sub-oracles ran, in [0, 1].
    pub score: Option<f32>,
}

impl BehaviorScore {
    /// Recompute `score` from the sub-oracles that ran, using the docs/03
    /// weights (unit 0.3 / property 0.5 / differential 0.2) renormalised over
    /// those present. `None` if none ran.
    pub fn recompute(&mut self) {
        const W_UNIT: f32 = 0.3;
        const W_PROP: f32 = 0.5;
        const W_DIFF: f32 = 0.2;
        let mut num = 0.0f32;
        let mut den = 0.0f32;
        if let Some(u) = self.unit {
            num += W_UNIT * u;
            den += W_UNIT;
        }
        if let Some(p) = self.property {
            num += W_PROP * p;
            den += W_PROP;
        }
        if let Some(d) = self.differential {
            num += W_DIFF * d;
            den += W_DIFF;
        }
        self.score = (den > f32::EPSILON).then(|| num / den);
    }
}

/// Constraint layer (L3). Each check is optional — it contributes to the layer
/// score only when it ran. The layer score is the mean of the boolean checks
/// that produced a verdict. Allocation is the first check implemented; clippy,
/// fmt and `syn`-based checks follow.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ConstraintScore {
    /// The hot path stayed within its allocation budget (docs/03-oracle.md:
    /// allocation is measured, not name-blacklisted).
    pub alloc_ok: Option<bool>,
    pub clippy_clean: Option<bool>,
    pub fmt_ok: Option<bool>,
    /// Count of `unsafe` usages found by the AST check (informational).
    pub unsafe_blocks: Option<u32>,
    /// `unsafe` count within the task's limit.
    pub unsafe_ok: Option<bool>,
    /// No forbidden type/function path present.
    pub paths_ok: Option<bool>,
    /// Human-readable violations, e.g. `"alloc: hot path allocated"`.
    pub violations: Vec<String>,
    /// Mean of the boolean checks that ran, in [0, 1]; `None` if none ran.
    pub score: Option<f32>,
}

impl ConstraintScore {
    /// Recompute `score` as the mean of the boolean checks present. `unsafe_blocks`
    /// is the raw count and is recorded, not scored; `unsafe_ok` carries the
    /// verdict.
    pub fn recompute(&mut self) {
        let mut sum = 0.0f32;
        let mut n = 0u32;
        for b in [
            self.alloc_ok,
            self.clippy_clean,
            self.fmt_ok,
            self.unsafe_ok,
            self.paths_ok,
        ]
        .into_iter()
        .flatten()
        {
            sum += if b { 1.0 } else { 0.0 };
            n += 1;
        }
        self.score = (n > 0).then(|| sum / n as f32);
    }
}

/// Derived from rustc error codes. This is the per-category diagnostic no
/// general-purpose coding benchmark can produce (docs/03-oracle.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureClass {
    Borrowck,
    Trait,
    Type,
    Lifetime,
    AsyncSend,
    Syntax,
    Resolve,
    Idiom,
    /// Compiled, failed L2 behaviour.
    Logic,
    /// Compiled, passed L2, failed L3 constraint.
    Constraint,
    Other,
    /// No failure — the unit passed.
    None,
    /// The grade did not produce a trustworthy outcome: a mandatory check could
    /// not run, so neither a pass nor a genuine failure was established
    /// (AQ-202: an `unsafe-core` grade without a miri verdict). A refused row is
    /// never scored and never counted as a pass.
    Indeterminate,
}

/// Whether compilation reached borrow checking (docs/03-oracle.md §L1). Type
/// checking aborts before borrowck runs, so a solution with a type/trait/resolve/
/// syntax error never reaches borrowck and any borrow bug it also has is *masked*
/// — the error histogram then systematically undercounts borrow failures in
/// exactly this project's niche. Recording this lets borrow-failure counts be
/// published as the lower bound they are.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCompleteness {
    /// Borrowck was reached — the unit compiled, or the errors shown are themselves
    /// borrow/lifetime errors (so borrowck ran and emitted them).
    #[default]
    Full,
    /// An earlier phase aborted before borrowck ran; borrow counts are a lower bound.
    TypeckOnly,
}

impl FailureClass {
    /// The kebab-case name (matches the serde representation), for histograms and
    /// human-readable reports.
    pub fn as_str(&self) -> &'static str {
        match self {
            FailureClass::Borrowck => "borrowck",
            FailureClass::Trait => "trait",
            FailureClass::Type => "type",
            FailureClass::Lifetime => "lifetime",
            FailureClass::AsyncSend => "async-send",
            FailureClass::Syntax => "syntax",
            FailureClass::Resolve => "resolve",
            FailureClass::Idiom => "idiom",
            FailureClass::Logic => "logic",
            FailureClass::Constraint => "constraint",
            FailureClass::Other => "other",
            FailureClass::None => "none",
            FailureClass::Indeterminate => "indeterminate",
        }
    }
}

// ---------------------------------------------------------------------------
// AQ-202: mandatory-miri refusal vocabulary (owner decision OI-36c)
// ---------------------------------------------------------------------------

/// The only category for which miri is mandatory (docs/03-oracle.md §miri).
pub const MIRI_CATEGORY: &str = "unsafe-core";

/// The mandatory stage could not run: no nightly+miri toolchain on the host.
pub const MIRI_UNAVAILABLE: &str = "miri:unavailable";
/// The mandatory stage had no test target to interpret.
pub const MIRI_NO_TARGETS: &str = "miri:no_targets";
/// Miri ran but its output yielded no parseable verdict.
pub const MIRI_NO_SUMMARY: &str = "miri:no_summary";
/// The miri interpreter run hit the wall clock.
pub const MIRI_TIMEOUT: &str = "timeout:miri";

/// Flags that say the mandatory miri stage did **not** produce a verdict. Any of
/// these on an `unsafe-core` row makes the row a refused/indeterminate outcome.
pub const MIRI_GAP_FLAGS: [&str; 4] = [
    MIRI_UNAVAILABLE,
    MIRI_NO_TARGETS,
    MIRI_NO_SUMMARY,
    MIRI_TIMEOUT,
];

/// The recorded verdict "miri ran and reported no UB".
pub const MIRI_CLEAN_FLAG: &str = "miri:clean";

/// The recorded verdict "miri ran and reported UB" (a hard behaviour failure).
pub const MIRI_UB_FLAG: &str = "miri:ub";

/// Whether any gap flag is present.
pub fn has_miri_gap(flags: &[String]) -> bool {
    flags.iter().any(|f| MIRI_GAP_FLAGS.contains(&f.as_str()))
}

/// Whether a definitive miri verdict (`miri:clean` or `miri:ub`) is recorded.
pub fn miri_verdict_recorded(flags: &[String]) -> bool {
    flags
        .iter()
        .any(|f| f == MIRI_CLEAN_FLAG || f == MIRI_UB_FLAG)
}

/// Whether this graded row must be **refused** rather than scored (AQ-202,
/// OI-36c): the task is in the miri-mandatory category, compilation got far
/// enough that miri was supposed to run, and no miri verdict was recorded.
///
/// A row with `compile_ok == false` is *not* refused: it is a genuine failure
/// that could never have passed, and excluding it would inflate the pass-rate
/// denominator (fail-open in the other direction).
pub fn miri_refused(category: &str, compile_ok: bool, flags: &[String]) -> bool {
    category == MIRI_CATEGORY && compile_ok && !miri_verdict_recorded(flags)
}

/// The full graded result for one attempt. Layers run in order; a failed gate
/// short-circuits later layers but every field is recorded.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OracleVector {
    // L0 apply gate
    pub apply_ok: bool,
    // L1 compile gate
    pub compile_ok: bool,
    pub error_codes: Vec<String>,
    pub warn_count: u32,
    /// Whether borrowck was reached (docs/03 §L1). `#[serde(default)]` = `Full` so
    /// journals predating this field parse unchanged.
    #[serde(default)]
    pub diagnostic_completeness: DiagnosticCompleteness,
    // L2 behavior
    pub behavior: BehaviorScore,
    // L3 constraint
    pub constraint: ConstraintScore,
    // Composite in [0, 1]; 0.0 unless both gates pass.
    pub score: f32,
    pub failure_class: FailureClass,
    /// Non-scoring event markers, e.g. `"timeout:test"`, `"network_attempt"`.
    /// docs/12-schemas.md and REVIEW-6 R6-S8: a timeout is a *flag*, not a
    /// failure class.
    pub flags: Vec<String>,
}

impl OracleVector {
    /// A vector for a unit whose model response could not even be applied.
    pub fn apply_failed() -> Self {
        OracleVector {
            apply_ok: false,
            compile_ok: false,
            error_codes: Vec::new(),
            warn_count: 0,
            diagnostic_completeness: DiagnosticCompleteness::Full,
            behavior: BehaviorScore::default(),
            constraint: ConstraintScore::default(),
            score: 0.0,
            failure_class: FailureClass::Other,
            flags: Vec::new(),
        }
    }

    /// The pre-registered **pass predicate** (docs/07-statistics.md, Q28). A task
    /// is *solved* iff it applied (L0), compiled (L1), is behaviourally correct
    /// (every L2 test passed, so `behavior.score == 1.0`), and satisfies the hard
    /// L3 constraints it declared — no disallowed `unsafe`, no forbidden path, and
    /// the allocation budget met.
    ///
    /// This is deliberately **structural, not a threshold on `composite_score`**.
    /// It is binary and *weight-independent*: re-tuning the per-category composite
    /// weights cannot move pass rates, which removes the cut-sweeping that made a
    /// score threshold gameable (REVIEW-6: 23.3% type-I error from a swept cut).
    /// The continuous `composite_score` remains the capability headline; `passed`
    /// feeds only the binary consumers (throughput, time-to-first-pass, McNemar,
    /// the sign-test detector, `budget_exhausted`).
    ///
    /// Semantics of the constraint clauses: a check that did not run (`None`) is
    /// *not* a barrier — the family did not require it. Only an explicit `false`
    /// fails the task. Quality checks (clippy/fmt, and L4) are **not** part of pass.
    /// A task with no behaviour oracle at all cannot pass — there is nothing that
    /// confirmed it correct.
    ///
    /// AQ-202/OI-36c: an `unsafe-core` row without a recorded miri verdict is
    /// indeterminate, and an indeterminate row can never pass — miri is the only
    /// oracle that could have confirmed the absence of undefined behaviour.
    pub fn passed(&self) -> bool {
        self.apply_ok
            && self.compile_ok
            && self.behavior.score == Some(1.0)
            && self.constraint.unsafe_ok != Some(false)
            && self.constraint.paths_ok != Some(false)
            && self.constraint.alloc_ok != Some(false)
            && self.failure_class != FailureClass::Indeterminate
            && !has_miri_gap(&self.flags)
    }
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/// The composite score, gated on apply + compile.
///
/// ```text
/// task_score = (apply_ok && compile_ok) ? Σ w_layer·score_layer / Σ w_layer : 0.0
/// ```
///
/// The sum runs over whichever layers actually produced a score, renormalised by
/// their weights. So a task with no L3 constraint check scores purely on
/// behaviour, and a constraint-dominant task (docs/04, `borrow-lifetimes`:
/// behavior 0.35 / constraint 0.55) penalises a behaviourally-correct but
/// allocation-heavy solution — the fix for REVIEW.md S6. Quality (L4) slots into
/// the same sum when it arrives, without changing the gate.
pub fn composite_score(v: &OracleVector, w: &OracleWeights) -> f32 {
    if !(v.apply_ok && v.compile_ok) {
        return 0.0;
    }
    let mut num = 0.0f32;
    let mut den = 0.0f32;
    if let Some(b) = v.behavior.score {
        num += w.behavior * b;
        den += w.behavior;
    }
    if let Some(c) = v.constraint.score {
        num += w.constraint * c;
        den += w.constraint;
    }
    // quality (L4) joins here in a later increment.
    if den <= f32::EPSILON {
        return 0.0;
    }
    (num / den).clamp(0.0, 1.0)
}

/// Map rustc error codes to a `FailureClass`, most-specific first. When a unit
/// compiled, the caller passes the behaviour outcome instead of codes.
pub fn classify_error_codes(codes: &[String]) -> FailureClass {
    // Order matters: the first matching family wins, so borrow/lifetime beats
    // the generic type bucket.
    const BORROWCK: &[&str] = &[
        "E0499", "E0502", "E0503", "E0505", "E0506", "E0382", "E0384",
    ];
    const LIFETIME: &[&str] = &["E0597", "E0515", "E0521", "E0623", "E0495", "E0700"];
    const TRAIT: &[&str] = &["E0277", "E0119", "E0210", "E0271", "E0599"];
    const TYPE: &[&str] = &["E0308", "E0053", "E0061", "E0069"];
    const RESOLVE: &[&str] = &["E0425", "E0433", "E0412", "E0405"];
    const SYNTAX: &[&str] = &["E0001"];

    let has = |set: &[&str]| codes.iter().any(|c| set.contains(&c.as_str()));

    if has(BORROWCK) {
        FailureClass::Borrowck
    } else if has(LIFETIME) {
        FailureClass::Lifetime
    } else if has(TRAIT) {
        FailureClass::Trait
    } else if has(TYPE) {
        FailureClass::Type
    } else if has(RESOLVE) {
        FailureClass::Resolve
    } else if has(SYNTAX) {
        FailureClass::Syntax
    } else if codes.is_empty() {
        FailureClass::None
    } else {
        FailureClass::Other
    }
}

/// Rendered-message substrings that pin a failure class the error code cannot
/// (docs/03-oracle.md): 18% of realistic Rust failures carry **no** error code —
/// most importantly the characteristic async one, `future cannot be sent between
/// threads safely`, which is `code: None`. And `E0277` spans four categories, so a
/// `Send`/`Sync` bound failure (message `… cannot be sent/shared between threads
/// safely`) is upgraded to `AsyncSend` before the code table can bucket it as a
/// generic `Trait`. Matched case-insensitively, most-specific first.
const MESSAGE_PATTERNS: &[(&str, FailureClass)] = &[
    (
        "cannot be sent between threads safely",
        FailureClass::AsyncSend,
    ),
    (
        "cannot be shared between threads safely",
        FailureClass::AsyncSend,
    ),
    (
        "future cannot be sent between threads",
        FailureClass::AsyncSend,
    ),
];

/// Classify a **compile failure** from its rustc error codes *and* rendered
/// messages (docs/03-oracle.md: `classify(error_code, message_pattern, …)`). The
/// message table is consulted first, so codeless errors and `Send`/`Sync` bounds
/// are classified where the code table alone is blind or ambiguous; otherwise it
/// falls back to [`classify_error_codes`].
pub fn classify_compile_error(codes: &[String], messages: &[String]) -> FailureClass {
    let matches = |needle: &str| messages.iter().any(|m| m.to_lowercase().contains(needle));
    for (needle, class) in MESSAGE_PATTERNS {
        if matches(needle) {
            return *class;
        }
    }
    classify_error_codes(codes)
}

/// Classify a unit that **compiled**, from its layer outcomes (docs/03-oracle.md).
/// Order: a behaviour miss is `Logic`; otherwise a clippy violation is `Idiom` —
/// non-idiomatic code compiles and passes behaviour, so clippy is the *only* signal
/// it produces, which is why `idiom-refactor` classifies from clippy (docs/03 §L1);
/// any other constraint miss is `Constraint`; a clean unit is `None`.
pub fn classify_graded(
    behavior_score: Option<f32>,
    clippy_clean: Option<bool>,
    constraint_score: Option<f32>,
) -> FailureClass {
    if behavior_score.map(|s| s < 1.0).unwrap_or(true) {
        FailureClass::Logic
    } else if clippy_clean == Some(false) {
        FailureClass::Idiom
    } else if constraint_score.map(|s| s < 1.0).unwrap_or(false) {
        FailureClass::Constraint
    } else {
        FailureClass::None
    }
}

/// Whether a **compile failure** reached borrow checking (docs/03-oracle.md §L1).
/// Reuses the phase ordering baked into [`classify_error_codes`]: a borrow/lifetime
/// error means borrowck ran and emitted it (`Full`); an earlier-phase error
/// (syntax / resolve / type / trait) with no borrow/lifetime error means borrowck
/// was never reached (`TypeckOnly`) and any borrow bug is masked. `None`/`Other`
/// carry no evidence borrowck was skipped, so they stay `Full`.
pub fn diagnostic_completeness(codes: &[String]) -> DiagnosticCompleteness {
    match classify_error_codes(codes) {
        FailureClass::Syntax | FailureClass::Resolve | FailureClass::Type | FailureClass::Trait => {
            DiagnosticCompleteness::TypeckOnly
        }
        _ => DiagnosticCompleteness::Full,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_id_is_deterministic() {
        let u = WorkUnit {
            task_id: TaskId("borrowck/x".into()),
            seed: Seed(42),
            index: 0,
        };
        assert_eq!(u.unit_id(), u.unit_id());
    }

    #[test]
    fn unit_id_separates_task_from_seed() {
        // "a" + seed 0 must not collide with "" + seed derived from "a"'s bytes.
        let a = WorkUnit {
            task_id: TaskId("a".into()),
            seed: Seed(0),
            index: 0,
        };
        let b = WorkUnit {
            task_id: TaskId("".into()),
            seed: Seed(0),
            index: 0,
        };
        assert_ne!(a.unit_id(), b.unit_id());
    }

    #[test]
    fn gate_zeroes_the_score() {
        let mut v = OracleVector::apply_failed();
        v.behavior.score = Some(1.0);
        assert_eq!(composite_score(&v, &OracleWeights::default()), 0.0);
    }

    fn vector(behavior: Option<f32>, constraint: Option<f32>) -> OracleVector {
        let constraint_score = ConstraintScore {
            alloc_ok: constraint.map(|s| s >= 1.0),
            score: constraint,
            ..Default::default()
        };
        OracleVector {
            apply_ok: true,
            compile_ok: true,
            error_codes: vec![],
            warn_count: 0,
            diagnostic_completeness: DiagnosticCompleteness::Full,
            behavior: BehaviorScore {
                unit: behavior,
                property: None,
                differential: None,
                score: behavior,
            },
            constraint: constraint_score,
            score: 0.0,
            failure_class: FailureClass::None,
            flags: Vec::new(),
        }
    }

    #[test]
    fn passing_behavior_scores_full_when_gates_pass() {
        assert!(
            (composite_score(&vector(Some(1.0), None), &OracleWeights::default()) - 1.0).abs()
                < 1e-6
        );
    }

    #[test]
    fn half_behavior_scores_half() {
        assert!(
            (composite_score(&vector(Some(0.5), None), &OracleWeights::default()) - 0.5).abs()
                < 1e-6
        );
    }

    #[test]
    fn constraint_dominant_weights_penalise_clone_everything() {
        // A behaviourally-correct (1.0) but allocation-failing (0.0) solution
        // under borrow-lifetimes weights (behavior 0.35 / constraint 0.55).
        let w = OracleWeights {
            behavior: 0.35,
            constraint: 0.55,
            quality: 0.10,
        };
        let v = vector(Some(1.0), Some(0.0));
        let s = composite_score(&v, &w);
        // (0.35*1 + 0.55*0) / (0.35 + 0.55) = 0.389
        assert!((s - 0.35 / 0.90).abs() < 1e-4, "got {s}");
        // The same answer under behaviour-dominant defaults scores much higher
        // (0.70/0.90 = 0.778): constraint weighting roughly halves it.
        let behav_dom = composite_score(&v, &OracleWeights::default());
        assert!(
            behav_dom > s + 0.3,
            "constraint weighting must move the score: {behav_dom} vs {s}"
        );
    }

    #[test]
    fn pass_is_structural_and_weight_independent() {
        // Full marks on behaviour, no constraint declared → pass.
        assert!(vector(Some(1.0), None).passed());
        // Behaviourally imperfect → not a pass, however high the composite is.
        assert!(!vector(Some(0.8), None).passed());
        // The clone-everything case: behaviour 1.0 but the allocation constraint
        // failed (alloc_ok = Some(false)) → NOT a pass, and this holds regardless
        // of the composite weights. This is the Q28 thesis in one assertion.
        assert!(!vector(Some(1.0), Some(0.0)).passed());
        // Behaviour 1.0 with the constraint satisfied → pass.
        assert!(vector(Some(1.0), Some(1.0)).passed());
    }

    #[test]
    fn pass_requires_a_behaviour_oracle_and_the_gates() {
        // No behaviour ran → cannot be confirmed correct → not a pass.
        assert!(!vector(None, None).passed());
        // Did not compile → not a pass even with a (stale) behaviour score.
        let mut v = vector(Some(1.0), None);
        v.compile_ok = false;
        assert!(!v.passed());
        // A constraint that did not run (None) is not a barrier: an unsafe_ok of
        // None must not block a pass.
        let mut v = vector(Some(1.0), None);
        v.constraint.unsafe_ok = None;
        assert!(v.passed());
        // An explicit forbidden-path violation fails the task.
        v.constraint.paths_ok = Some(false);
        assert!(!v.passed());
    }

    #[test]
    fn differential_catches_unit_passing_but_wrong() {
        // The headline: a solution that passes every example test (unit 1.0) but
        // disagrees with the reference (differential 0.0). docs/03 weights make
        // behaviour 0.6, not the 1.0 a unit-only oracle would report.
        let mut b = BehaviorScore {
            unit: Some(1.0),
            differential: Some(0.0),
            ..Default::default()
        };
        b.recompute();
        // (0.3*1 + 0.2*0) / (0.3 + 0.2) = 0.6
        assert!((b.score.unwrap() - 0.6).abs() < 1e-4, "got {:?}", b.score);
    }

    #[test]
    fn behavior_score_renormalises_over_present_suboracles() {
        // unit only: behaviour == unit.
        let mut b = BehaviorScore {
            unit: Some(0.8),
            ..Default::default()
        };
        b.recompute();
        assert!((b.score.unwrap() - 0.8).abs() < 1e-6);
        // none ran: None.
        let mut empty = BehaviorScore::default();
        empty.recompute();
        assert_eq!(empty.score, None);
    }

    #[test]
    fn constraint_score_is_mean_of_present_checks() {
        let mut c = ConstraintScore {
            alloc_ok: Some(true),
            fmt_ok: Some(false),
            ..Default::default()
        };
        c.recompute();
        assert_eq!(c.score, Some(0.5));
    }

    #[test]
    fn borrowck_beats_type_bucket() {
        // A response that trips both E0499 (borrow) and E0308 (type) is a
        // borrow-checker failure first.
        assert_eq!(
            classify_error_codes(&["E0308".into(), "E0499".into()]),
            FailureClass::Borrowck
        );
    }

    #[test]
    fn empty_codes_is_none() {
        assert_eq!(classify_error_codes(&[]), FailureClass::None);
    }

    #[test]
    fn unknown_code_is_other() {
        assert_eq!(classify_error_codes(&["E9999".into()]), FailureClass::Other);
    }

    #[test]
    fn codeless_async_failure_is_classified_by_message() {
        // The single most characteristic async failure carries no error code — the
        // code table would call it `None`, but the message names it.
        let msg = vec!["future cannot be sent between threads safely".to_string()];
        assert_eq!(classify_compile_error(&[], &msg), FailureClass::AsyncSend);
    }

    #[test]
    fn e0277_send_bound_upgrades_to_async_but_plain_e0277_stays_trait() {
        // E0277 spans categories. A Send bound (message says "cannot be sent…") is
        // async; a bare E0277 with no such message is a generic trait failure.
        let send = vec!["`Rc<i32>` cannot be sent between threads safely".to_string()];
        assert_eq!(
            classify_compile_error(&["E0277".into()], &send),
            FailureClass::AsyncSend
        );
        let plain = vec!["the trait bound `T: Foo` is not satisfied".to_string()];
        assert_eq!(
            classify_compile_error(&["E0277".into()], &plain),
            FailureClass::Trait
        );
    }

    #[test]
    fn compile_error_without_message_match_falls_back_to_codes() {
        // No message pattern → identical to the code-only classifier.
        assert_eq!(
            classify_compile_error(&["E0499".into()], &["some borrow error".into()]),
            FailureClass::Borrowck
        );
        assert_eq!(classify_compile_error(&[], &[]), FailureClass::None);
    }

    #[test]
    fn diagnostic_completeness_flags_masked_borrowck() {
        // A type error with no borrow error: borrowck was never reached, so borrow
        // counts are a lower bound (docs/03's measured case).
        assert_eq!(
            diagnostic_completeness(&["E0308".into()]),
            DiagnosticCompleteness::TypeckOnly
        );
        // A pure borrow failure: borrowck ran and emitted it.
        assert_eq!(
            diagnostic_completeness(&["E0499".into()]),
            DiagnosticCompleteness::Full
        );
        // Type + borrow together: the borrow error is present, so borrowck ran.
        assert_eq!(
            diagnostic_completeness(&["E0308".into(), "E0499".into()]),
            DiagnosticCompleteness::Full
        );
        // No codes / unknown: no evidence borrowck was skipped.
        assert_eq!(diagnostic_completeness(&[]), DiagnosticCompleteness::Full);
    }

    #[test]
    fn failure_class_as_str_is_kebab() {
        assert_eq!(FailureClass::Borrowck.as_str(), "borrowck");
        assert_eq!(FailureClass::AsyncSend.as_str(), "async-send");
        assert_eq!(FailureClass::None.as_str(), "none");
    }

    #[test]
    fn graded_classification_orders_logic_idiom_constraint_none() {
        // Behaviour miss dominates.
        assert_eq!(
            classify_graded(Some(0.5), Some(false), Some(0.0)),
            FailureClass::Logic
        );
        // Behaviour perfect but clippy-dirty → Idiom (the idiom-refactor signal),
        // ahead of a generic Constraint even if another constraint also failed.
        assert_eq!(
            classify_graded(Some(1.0), Some(false), Some(0.0)),
            FailureClass::Idiom
        );
        // Behaviour perfect, no clippy check, another constraint failed → Constraint.
        assert_eq!(
            classify_graded(Some(1.0), None, Some(0.5)),
            FailureClass::Constraint
        );
        // Everything clean → None.
        assert_eq!(classify_graded(Some(1.0), None, None), FailureClass::None);
        assert_eq!(
            classify_graded(Some(1.0), Some(true), Some(1.0)),
            FailureClass::None
        );
    }

    #[test]
    fn unit_id_separates_index_and_seed() {
        let base = WorkUnit {
            task_id: TaskId("gen/f".into()),
            seed: Seed(7),
            index: 0,
        };
        let mut other = base.clone();
        other.index = 1;
        assert_ne!(base.unit_id(), other.unit_id());
        let mut other = base.clone();
        other.seed = Seed(8);
        assert_ne!(base.unit_id(), other.unit_id());
    }

    #[test]
    fn unit_id_has_blake3_prefix_and_hex_shape() {
        let u = WorkUnit {
            task_id: TaskId("x".into()),
            seed: Seed(1),
            index: 2,
        };
        let id = u.unit_id().0;
        let hex = id.strip_prefix("blake3:").expect("blake3 prefix");
        assert_eq!(hex.len(), 64);
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn oracle_weights_default_matches_docs() {
        let w = OracleWeights::default();
        assert_eq!(w.behavior, 0.70);
        assert_eq!(w.constraint, 0.20);
        assert_eq!(w.quality, 0.10);
    }

    #[test]
    fn behavior_recompute_combines_all_three_suboracles() {
        // (0.3*1.0 + 0.5*0.4 + 0.2*1.0) / 1.0 = 0.7
        let mut b = BehaviorScore {
            unit: Some(1.0),
            property: Some(0.4),
            differential: Some(1.0),
            score: None,
        };
        b.recompute();
        assert!((b.score.unwrap() - 0.7).abs() < 1e-4, "got {:?}", b.score);
    }

    #[test]
    fn behavior_recompute_property_only_renormalises_to_property() {
        let mut b = BehaviorScore {
            property: Some(0.6),
            ..Default::default()
        };
        b.recompute();
        assert!((b.score.unwrap() - 0.6).abs() < 1e-6);
    }

    #[test]
    fn constraint_unsafe_blocks_is_recorded_not_scored() {
        // unsafe_blocks is informational; only unsafe_ok carries the verdict.
        let mut c = ConstraintScore {
            alloc_ok: Some(true),
            unsafe_blocks: Some(9),
            ..Default::default()
        };
        c.recompute();
        assert_eq!(c.score, Some(1.0));
    }

    #[test]
    fn constraint_all_checks_true_scores_one() {
        let mut c = ConstraintScore {
            alloc_ok: Some(true),
            clippy_clean: Some(true),
            fmt_ok: Some(true),
            unsafe_ok: Some(true),
            paths_ok: Some(true),
            ..Default::default()
        };
        c.recompute();
        assert_eq!(c.score, Some(1.0));
    }

    #[test]
    fn composite_renormalises_over_present_layers() {
        // (0.7*0.8 + 0.2*0.5) / (0.7 + 0.2) = 0.7333
        let s = composite_score(&vector(Some(0.8), Some(0.5)), &OracleWeights::default());
        assert!((s - 0.66 / 0.9).abs() < 1e-4, "got {s}");
    }

    #[test]
    fn composite_with_gates_but_no_layer_scores_is_zero_not_nan() {
        let v = OracleVector {
            apply_ok: true,
            compile_ok: true,
            ..OracleVector::apply_failed()
        };
        let s = composite_score(&v, &OracleWeights::default());
        assert_eq!(s, 0.0);
        assert!(!s.is_nan());
    }

    #[test]
    fn apply_gate_alone_zeroes_the_composite() {
        let mut v = vector(Some(1.0), Some(1.0));
        v.apply_ok = false;
        assert_eq!(composite_score(&v, &OracleWeights::default()), 0.0);
    }

    #[test]
    fn classify_lifetime_beats_trait_bucket() {
        assert_eq!(
            classify_error_codes(&["E0597".into(), "E0277".into()]),
            FailureClass::Lifetime
        );
    }

    #[test]
    fn classify_each_bucket_representative_code() {
        assert_eq!(
            classify_error_codes(&["E0382".into()]),
            FailureClass::Borrowck
        );
        assert_eq!(
            classify_error_codes(&["E0597".into()]),
            FailureClass::Lifetime
        );
        assert_eq!(classify_error_codes(&["E0119".into()]), FailureClass::Trait);
        assert_eq!(classify_error_codes(&["E0061".into()]), FailureClass::Type);
        assert_eq!(
            classify_error_codes(&["E0425".into()]),
            FailureClass::Resolve
        );
        assert_eq!(
            classify_error_codes(&["E0001".into()]),
            FailureClass::Syntax
        );
    }

    #[test]
    fn message_match_is_case_insensitive() {
        let msg = vec!["Future Cannot Be Sent Between Threads Safely".to_string()];
        assert_eq!(classify_compile_error(&[], &msg), FailureClass::AsyncSend);
    }

    #[test]
    fn shared_between_threads_message_is_async_send() {
        // The Sync variant of the characteristic bound failure.
        let msg = vec!["`Rc<i32>` cannot be shared between threads safely".to_string()];
        assert_eq!(classify_compile_error(&[], &msg), FailureClass::AsyncSend);
    }

    #[test]
    fn lifetime_errors_keep_borrowck_reached_evidence() {
        // A lifetime error is *emitted by borrowck*, so it is Full — only the
        // earlier-phase buckets flip to TypeckOnly.
        assert_eq!(
            diagnostic_completeness(&["E0597".into()]),
            DiagnosticCompleteness::Full
        );
        assert_eq!(
            diagnostic_completeness(&["E0433".into()]),
            DiagnosticCompleteness::TypeckOnly
        );
    }

    #[test]
    fn failure_class_serde_is_kebab_and_round_trips() {
        assert_eq!(
            serde_json::to_string(&FailureClass::AsyncSend).unwrap(),
            "\"async-send\""
        );
        let class: FailureClass = serde_json::from_str("\"logic\"").unwrap();
        assert_eq!(class, FailureClass::Logic);
        let class: FailureClass = serde_json::from_str("\"none\"").unwrap();
        assert_eq!(class, FailureClass::None);
    }

    #[test]
    fn diagnostic_completeness_defaults_to_full_in_old_journals() {
        // A journal line written before the field existed must still parse;
        // `#[serde(default)]` fills Full (docs/03 §L1 back-compat).
        let line = r#"{
            "apply_ok": true,
            "compile_ok": false,
            "error_codes": ["E0308"],
            "warn_count": 0,
            "behavior": {"unit": null, "property": null, "differential": null, "score": null},
            "constraint": {"alloc_ok": null, "clippy_clean": null, "fmt_ok": null,
                           "unsafe_blocks": null, "unsafe_ok": null, "paths_ok": null,
                           "violations": [], "score": null},
            "score": 0.0,
            "failure_class": "type",
            "flags": []
        }"#;
        let v: OracleVector = serde_json::from_str(line).unwrap();
        assert_eq!(v.failure_class, FailureClass::Type);
        // serde(default) fills the *stored* default Full — completeness is a
        // recorded fact about the run, not re-derived from the codes here.
        assert_eq!(v.diagnostic_completeness, DiagnosticCompleteness::Full);
        // And the field round-trips when present.
        let text = serde_json::to_string(&v).unwrap();
        assert!(text.contains("diagnostic_completeness"));
    }

    #[test]
    fn task_kind_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&TaskKind::Frozen).unwrap(),
            "\"frozen\""
        );
        let kind: TaskKind = serde_json::from_str("\"mined\"").unwrap();
        assert_eq!(kind, TaskKind::Mined);
    }

    // -- AQ-202 / OI-36c: mandatory-miri refusal predicates -------------------

    #[test]
    fn indeterminate_serializes_kebab_case() {
        assert_eq!(
            serde_json::to_string(&FailureClass::Indeterminate).unwrap(),
            "\"indeterminate\""
        );
        let class: FailureClass = serde_json::from_str("\"indeterminate\"").unwrap();
        assert_eq!(class, FailureClass::Indeterminate);
        assert_eq!(FailureClass::Indeterminate.as_str(), "indeterminate");
    }

    #[test]
    fn miri_gap_flags_are_detected_individually() {
        for flag in MIRI_GAP_FLAGS {
            let flags = vec![flag.to_string()];
            assert!(has_miri_gap(&flags), "gap flag {flag} must be detected");
            assert!(!miri_verdict_recorded(&flags));
        }
        assert!(!has_miri_gap(&[]));
        assert!(!has_miri_gap(&["timeout:test".to_string()]));
    }

    #[test]
    fn miri_verdict_recorded_requires_clean_or_ub() {
        assert!(miri_verdict_recorded(&[MIRI_CLEAN_FLAG.to_string()]));
        assert!(miri_verdict_recorded(&[MIRI_UB_FLAG.to_string()]));
        // A pre-AQ-202 unsafe-core row carries no verdict at all.
        assert!(!miri_verdict_recorded(&[]));
        assert!(!miri_verdict_recorded(&["network_attempt".to_string()]));
    }

    #[test]
    fn miri_refused_truth_table() {
        // Old-journal shape: compile_ok, no verdict recorded ⇒ refused.
        assert!(miri_refused(MIRI_CATEGORY, true, &[]));
        for flag in MIRI_GAP_FLAGS {
            assert!(miri_refused(MIRI_CATEGORY, true, &[flag.to_string()]));
        }
        // A recorded verdict (clean or ub) means the row is scoreable.
        assert!(!miri_refused(
            MIRI_CATEGORY,
            true,
            &[MIRI_CLEAN_FLAG.to_string()]
        ));
        assert!(!miri_refused(
            MIRI_CATEGORY,
            true,
            &[MIRI_UB_FLAG.to_string()]
        ));
        // Other categories keep the old best-effort semantics.
        assert!(!miri_refused("idiom-loop", true, &[]));
        // A compile failure is a genuine 0 that can never pass: keep scoring it.
        assert!(!miri_refused(MIRI_CATEGORY, false, &[]));
    }

    #[test]
    fn passed_vetoes_indeterminate_and_miri_gap_rows() {
        // An otherwise all-pass vector...
        let mut v = vector(Some(1.0), None);
        assert!(v.passed(), "witness: all-pass row passes without flags");
        // ...with a miri gap flag must NOT pass (old behaviour: it did).
        v.flags = vec!["miri:unavailable".to_string()];
        assert!(!v.passed());
        // A clean verdict restores passability.
        v.flags = vec![MIRI_CLEAN_FLAG.to_string()];
        assert!(v.passed());
        // Explicit indeterminate class vetoes even a perfect vector.
        let mut w = vector(Some(1.0), None);
        w.failure_class = FailureClass::Indeterminate;
        assert!(!w.passed());
    }
}
