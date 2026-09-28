//! `bench-stats` — turn a journal of graded units into the published figures.
//!
//! This crate is the concrete implementation of the decisions in
//! [docs/07-statistics.md](../../../docs/07-statistics.md):
//!
//! - **`capability_score`** is the *equal-weight mean of the per-category means*
//!   (docs/04), not a pooled mean of units — so a small probe category counts the
//!   same as a large core one.
//! - **Pass** is the structural predicate `OracleVector::passed()` (Q28), never a
//!   threshold on the continuous score. It drives the binary metrics (pass-rate);
//!   the continuous `oracle.score` drives capability.
//! - **Confidence intervals are the cluster bootstrap** (Q29), never the
//!   design-effect formula. Specifically the **studentised (percentile-t) wild
//!   cluster bootstrap** (Q29.5): Rademacher sign-flips on per-family residual
//!   sums, with each replicate carrying its own cluster-robust SE so the CI
//!   inverts bootstrap t-quantiles. Measured coverage 0.95 at 12 clusters, versus
//!   0.90 for the raw percentile form and worse for naive resampling. The cluster
//!   is the **family** for now — shapes are not labelled yet (needs Q24), so every
//!   CI is still a lower bound on width (it cannot see the shape clustering).
//!   Categories with too few families are marked **directional-only**.
//! - **Multiplicity**: per-category CIs shown together are **simultaneous** —
//!   Bonferroni level `1 − α/K` across the `K` categories reported (Q29.4).
//! - **Model comparison** is McNemar on the shared `passed` bits plus a paired,
//!   family-clustered wild-bootstrap CI on the pass-rate difference; the
//!   **precomputation detector** is the one-sided sign test on `pick-one`
//!   core-vs-probe bits (Q29.1).
//! - **ICC** (Q29.2) is the one-way ANOVA estimate, clamped to [0,1] and
//!   empirical-Bayes-shrunk toward the pooled value, reported per category with its
//!   design effect. It is **diagnostic/sizing only** — never an input to a CI, which
//!   is why a bad or unestimable ICC cannot narrow a published interval.
//!
//! Not yet implemented (tracked): shape-level resampling and `icc_within_shape`
//! (both need the Q24 shape labels); and the sign test is a pure statistic here —
//! it starts running on real data once the epoch protocol emits labelled
//! fresh-probe units (ADR-0009).

use bench_core::{DiagnosticCompleteness, OracleVector};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// The confidence level for the overall figure.
pub const ALPHA: f64 = 0.05;

/// A category with fewer than this many families cannot support a family cluster
/// bootstrap (resampling one or two clusters gives a near-zero-width, over-confident
/// interval). Such categories are reported **directional-only**. Provisional — the
/// real floor is fixed at the Q24 shape audit against measured coverage.
pub const CLUSTER_FLOOR: usize = 8;

/// Default bootstrap resamples.
pub const BOOTSTRAP_ITERS: usize = 10_000;

/// Units at the start of each run *segment* excluded from the throughput aggregate
/// for cache warmth (docs/08). The first unit of a session compiles cold — the
/// dependency crates and the shared `target/` are unwarmed — while later units
/// reuse the warm cache, so counting the cold lead unit would understate
/// steady-state throughput. Conservative (only the coldest lead unit per segment),
/// and it touches *timing only*: capability scoring still uses every unit. Recorded
/// via `segment_position` so the exclusion is auditable rather than magic.
pub const SEGMENT_WARMUP_UNITS: u32 = 1;

fn default_kind() -> String {
    "core".to_string()
}
fn default_epoch() -> String {
    "local".to_string()
}

/// Per-unit cost, as journalled. All fields default so older or hand-written journals
/// (and the synthetic test records) parse with zero timing.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
pub struct Cost {
    #[serde(default)]
    pub prompt_tokens: u32,
    #[serde(default)]
    pub completion_tokens: u32,
    #[serde(default)]
    pub gen_ms: u64,
    #[serde(default)]
    pub grade_ms: u64,
}

/// One graded unit, as read from a journal line. Only the fields statistics needs
/// are declared; serde ignores the rest (`model`, …). `kind`, `index`,
/// `epoch` and `cost` default for journals that predate them.
#[derive(Clone, Debug, Deserialize)]
pub struct Record {
    pub task_id: String,
    pub category: String,
    pub oracle: OracleVector,
    #[serde(default = "default_kind")]
    pub kind: String,
    #[serde(default)]
    pub index: u32,
    #[serde(default = "default_epoch")]
    pub epoch: String,
    /// Which run session produced this unit (docs/09). `None` for single-unit `run`
    /// and journals that predate segments.
    #[serde(default)]
    pub segment: Option<u32>,
    /// 0-based position within the segment; drives the cache-warmth exclusion
    /// ([`SEGMENT_WARMUP_UNITS`]). `None` = never treated as warmup.
    #[serde(default)]
    pub segment_position: Option<u32>,
    #[serde(default)]
    pub cost: Cost,
    /// The journal line's `sandbox` value (`"seatbelt"` when the row was
    /// graded under containment). Absent in journals that predate the field —
    /// classified as *uncontained* (fail closed), so rows of unknown
    /// provenance are never aggregated as if they were sandboxed (AQ-194).
    #[serde(default)]
    pub sandbox: Option<String>,
}

impl Record {
    /// The family a unit belongs to: the `task_id` up to the first `/` (generated
    /// ids are `family/{seed}`), or the whole id for a frozen task.
    pub fn family(&self) -> &str {
        self.task_id.split('/').next().unwrap_or(&self.task_id)
    }

    /// The continuous capability contribution — the composite computed at grade time.
    pub fn score(&self) -> f64 {
        self.oracle.score as f64
    }

    /// The structural pass bit (Q28).
    pub fn passed(&self) -> bool {
        self.oracle.passed()
    }

    /// A synthetic core unit for tests: `epoch = "local"`, `kind = "core"`, `index = unit`.
    pub fn synthetic(category: &str, family: &str, unit: u64, score: f64, passed: bool) -> Record {
        Record::synthetic_unit(
            category,
            family,
            "local",
            "core",
            unit as u32,
            score,
            passed,
        )
    }

    /// A synthetic record with an explicit epoch/kind/index — used by detector tests
    /// that need paired core and probe units. A passing record has `behaviour == 1.0`
    /// and no failing constraint; a failing one has behaviour `0.5`.
    #[allow(clippy::too_many_arguments)]
    pub fn synthetic_unit(
        category: &str,
        family: &str,
        epoch: &str,
        kind: &str,
        index: u32,
        score: f64,
        passed: bool,
    ) -> Record {
        let mut oracle = OracleVector::apply_failed();
        oracle.apply_ok = true;
        oracle.compile_ok = true;
        oracle.behavior.score = Some(if passed { 1.0 } else { 0.5 });
        oracle.score = score as f32;
        Record {
            task_id: format!("{family}/{index:016x}"),
            category: category.to_string(),
            oracle,
            kind: kind.to_string(),
            index,
            epoch: epoch.to_string(),
            segment: None,
            segment_position: None,
            cost: Cost::default(),
            sandbox: None,
        }
    }
}

/// The containment class of a journal row (AQ-194). Only `"seatbelt"` is
/// contained today; anything else — absent (older journals), `"unsupported"`
/// (including the `sandbox_opted_in` rows), or an unknown future backend
/// string — counts as *uncontained*, fail closed, so scores produced with no
/// containment can never be silently aggregated as if they were sandboxed.
pub fn containment_class(sandbox: Option<&str>) -> &'static str {
    match sandbox {
        Some("seatbelt") => "contained",
        _ => "uncontained",
    }
}

/// Refuse to aggregate a journal that *mixes* contained and uncontained rows
/// (AQ-194): scores from uncontained grading are not comparable with sandboxed
/// ones — the model's code could observe or influence the grader — so a mixed
/// journal is an error, not a warning. A homogeneous journal of either class
/// aggregates; the class is a property of where the suite ran, not a per-row
/// surprise.
pub fn check_containment_mix(records: &[Record]) -> Result<(), String> {
    let contained = records
        .iter()
        .filter(|r| containment_class(r.sandbox.as_deref()) == "contained")
        .count();
    let uncontained = records.len() - contained;
    if contained > 0 && uncontained > 0 {
        return Err(format!(
            "journal mixes contained and uncontained rows ({contained} seatbelt, \
             {uncontained} uncontained) — scores from uncontained grading are not \
             comparable; split the journal or re-run the uncontained rows sandboxed"
        ));
    }
    Ok(())
}

/// Read a JSONL journal into records, skipping blank lines. Refuses (fail
/// closed, AQ-194) a journal that mixes contained and uncontained rows.
pub fn load_journal(path: &Path) -> std::io::Result<Vec<Record>> {
    let text = std::fs::read_to_string(path)?;
    let records = parse_journal(&text)?;
    check_containment_mix(&records)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(records)
}

/// The containment class of a whole journal (AQ-194, r54 R2): `"contained"`
/// only when every row was graded under containment, `"uncontained"` when none
/// was; a mixed journal is `Err` (it must never have loaded —
/// [`check_containment_mix`] refuses it at [`load_journal`] time — this guard
/// is the same predicate, kept next to the classification so the two cannot
/// drift). An **all-uncontained** journal still has one class — the caller
/// must then refuse to aggregate it silently and label its output
/// (`containment_note`); the class is how `stats`/`report`/`compare` know.
pub fn journal_containment_class(records: &[Record]) -> Result<&'static str, String> {
    check_containment_mix(records)?;
    if records
        .iter()
        .any(|r| containment_class(r.sandbox.as_deref()) == "contained")
    {
        Ok("contained")
    } else {
        Ok("uncontained")
    }
}

/// The human-readable label for a journal class (AQ-194, r54 R2). Every
/// aggregate produced from an uncontained journal must carry this marker in
/// its output, so a reader can never mistake uncontained numbers for
/// sandboxed ones.
pub fn containment_note(class: &str) -> &'static str {
    match class {
        "contained" => "contained (macOS seatbelt)",
        _ => "UNCONTAINED — graded with no sandbox; not comparable with contained runs",
    }
}

/// Parse JSONL text into records.
pub fn parse_journal(text: &str) -> std::io::Result<Vec<Record>> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let rec: Record = serde_json::from_str(line).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("line {}: {e}", i + 1),
            )
        })?;
        out.push(rec);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Grouping
// ---------------------------------------------------------------------------

/// `category -> family -> [unit values]`, for a chosen per-unit metric.
type Grouped = BTreeMap<String, BTreeMap<String, Vec<f64>>>;

fn group_by(records: &[Record], value: impl Fn(&Record) -> f64) -> Grouped {
    let mut g: Grouped = BTreeMap::new();
    for r in records {
        g.entry(r.category.clone())
            .or_default()
            .entry(r.family().to_string())
            .or_default()
            .push(value(r));
    }
    g
}

/// Mean over every unit in a category (flattening families). `None` if empty.
fn category_mean(families: &BTreeMap<String, Vec<f64>>) -> Option<f64> {
    let mut sum = 0.0;
    let mut n = 0usize;
    for units in families.values() {
        for &v in units {
            sum += v;
            n += 1;
        }
    }
    (n > 0).then(|| sum / n as f64)
}

/// The equal-weight mean of category means — `capability_score` (docs/04).
fn equal_weight_overall(g: &Grouped) -> Option<f64> {
    let means: Vec<f64> = g.values().filter_map(category_mean).collect();
    (!means.is_empty()).then(|| means.iter().sum::<f64>() / means.len() as f64)
}

// ---------------------------------------------------------------------------
// Deterministic RNG (SplitMix64) — same journal → same CI.
// ---------------------------------------------------------------------------

struct Rng {
    state: u64,
}
impl Rng {
    fn new(seed: u64) -> Self {
        Rng {
            state: seed.wrapping_add(0x9E3779B97F4A7C15),
        }
    }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

// ---------------------------------------------------------------------------
// Cluster bootstrap
// ---------------------------------------------------------------------------

/// Negligible-SE guard — below this a cluster set is treated as having no variance.
const SE_EPS: f64 = 1e-12;

/// Precomputed **wild cluster bootstrap** state for one cluster set (the families of a
/// category): the point mean, each family's residual sum `e_g = Σ_{i∈g}(y_i − μ)`, each
/// family's unit count, and the total. The wild cluster bootstrap (Cameron–Gelbach–Miller,
/// Q29.5) flips each `e_g` by an i.i.d. Rademacher sign per replicate.
///
/// The interval is the **studentised** (percentile-t) form: each replicate carries its
/// *own* cluster-robust SE computed from the sign-flipped residuals, and the CI inverts the
/// quantiles of the bootstrap t-statistic. Studentising is what lifts few-cluster coverage
/// from ~0.90 (raw percentile) toward the nominal 0.95, because the t-pivot cancels the
/// small-sample noise in the SE estimate. A homogeneous cluster set has zero SE and gets a
/// zero-width interval, correctly.
struct WildCat {
    mu: f64,
    e: Vec<f64>,
    n_g: Vec<usize>,
    n: usize,
}

impl WildCat {
    fn new(families: &[&Vec<f64>]) -> Option<WildCat> {
        let n: usize = families.iter().map(|f| f.len()).sum();
        if n == 0 {
            return None;
        }
        let mu = families.iter().flat_map(|f| f.iter()).sum::<f64>() / n as f64;
        let e: Vec<f64> = families
            .iter()
            .map(|f| f.iter().map(|&y| y - mu).sum::<f64>())
            .collect();
        let n_g = families.iter().map(|f| f.len()).collect();
        Some(WildCat { mu, e, n_g, n })
    }

    /// Cluster-robust variance of the point mean: `(Σ_g e_g²) / N²`.
    fn point_var(&self) -> f64 {
        self.e.iter().map(|&eg| eg * eg).sum::<f64>() / (self.n as f64).powi(2)
    }

    /// One Rademacher sign-flip replicate. Returns `(Δ, var*)` where `Δ = μ* − μ` is the
    /// shift of the category mean and `var*` is the bootstrap cluster-robust variance of
    /// `μ*` under the flip: with `e*_g = w_g e_g − n_g Δ`, `var* = (Σ_g e*_g²)/N²`.
    fn draw_parts(&self, rng: &mut Rng) -> (f64, f64) {
        let w: Vec<f64> = self
            .e
            .iter()
            .map(|_| if rng.next_u64() & 1 == 0 { 1.0 } else { -1.0 })
            .collect();
        let n = self.n as f64;
        let delta = w.iter().zip(&self.e).map(|(wi, ei)| wi * ei).sum::<f64>() / n;
        let var_star = w
            .iter()
            .zip(&self.e)
            .zip(&self.n_g)
            .map(|((wi, ei), &ng)| {
                let eg_star = wi * ei - ng as f64 * delta;
                eg_star * eg_star
            })
            .sum::<f64>()
            / (n * n);
        (delta, var_star)
    }
}

fn wildcat(families: &BTreeMap<String, Vec<f64>>) -> Option<WildCat> {
    let fams: Vec<&Vec<f64>> = families.values().collect();
    WildCat::new(&fams)
}

/// Clamp a CI to a bounded parameter's feasible range. Scores, means and pass-rates
/// live in [0, 1], so a percentile-t interval that overshoots the boundary (which the
/// studentised bootstrap can do near a boundary or with very few clusters) is reported as
/// its intersection with the feasible set — the overshoot carries no extra information.
fn clamp_ci(ci: (f64, f64), lo: f64, hi: f64) -> (f64, f64) {
    (ci.0.clamp(lo, hi), ci.1.clamp(lo, hi))
}

/// Turn a set of bootstrap t-statistics and the point `(mu, se)` into a studentised
/// (equal-tailed percentile-t) CI: `[μ − se·q_{1−α/2}, μ − se·q_{α/2}]`.
fn studentized_ci(mu: f64, se: f64, mut ts: Vec<f64>, alpha: f64) -> (f64, f64) {
    if se <= SE_EPS {
        return (mu, mu); // no variance to report
    }
    if ts.len() < 2 {
        // Degenerate bootstrap (too few informative replicates): fall back to normal.
        return (mu - 1.959_964 * se, mu + 1.959_964 * se);
    }
    ts.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let q = |p: f64| ts[(((ts.len() - 1) as f64) * p).round() as usize];
    (mu - se * q(1.0 - alpha / 2.0), mu - se * q(alpha / 2.0))
}

/// Studentised wild cluster bootstrap for the overall equal-weight statistic. Each
/// replicate flips family signs within every category, forms the equal-weight mean shift
/// `Δ` and its bootstrap SE, and records the t-pivot; the CI inverts those quantiles.
fn bootstrap_overall(g: &Grouped, iters: usize, alpha: f64, rng: &mut Rng) -> (f64, f64) {
    let cats: Vec<WildCat> = g.values().filter_map(wildcat).collect();
    if cats.is_empty() {
        return (f64::NAN, f64::NAN);
    }
    let c = cats.len() as f64;
    let theta = cats.iter().map(|w| w.mu).sum::<f64>() / c;
    let se = (cats.iter().map(|w| w.point_var()).sum::<f64>() / (c * c)).sqrt();
    let mut ts = Vec::with_capacity(iters);
    for _ in 0..iters {
        let mut dsum = 0.0;
        let mut vsum = 0.0;
        for w in &cats {
            let (d, v) = w.draw_parts(rng);
            dsum += d;
            vsum += v;
        }
        let delta = dsum / c;
        let se_star = (vsum / (c * c)).sqrt();
        if se_star > SE_EPS {
            ts.push(delta / se_star);
        }
    }
    studentized_ci(theta, se, ts, alpha)
}

/// Studentised wild cluster bootstrap for a single category mean.
fn bootstrap_category(
    families: &BTreeMap<String, Vec<f64>>,
    iters: usize,
    alpha: f64,
    rng: &mut Rng,
) -> (f64, f64) {
    let wc = match wildcat(families) {
        None => return (f64::NAN, f64::NAN),
        Some(wc) => wc,
    };
    let se = wc.point_var().sqrt();
    let mut ts = Vec::with_capacity(iters);
    for _ in 0..iters {
        let (delta, var_star) = wc.draw_parts(rng);
        let se_star = var_star.sqrt();
        if se_star > SE_EPS {
            ts.push(delta / se_star);
        }
    }
    studentized_ci(wc.mu, se, ts, alpha)
}

// ---------------------------------------------------------------------------
// ICC (intra-class correlation) — diagnostic / sizing only, never a CI input (Q29.2)
// ---------------------------------------------------------------------------

/// Empirical-Bayes shrinkage strength for per-category ICC: a category is trusted on its
/// own estimate once its between-family df comfortably exceeds this. Provisional — the
/// real value is tuned at the Q24 shape audit; the estimate feeds sizing, not any CI.
pub const ICC_SHRINK_TAU: f64 = 4.0;

/// Sufficient statistics for the one-way (families-within-a-set) ANOVA ICC. Additive
/// across categories, which is how the pooled estimate is formed (each category
/// contributes its between-family SS around its *own* mean, so category effects cancel).
#[derive(Clone, Copy, Debug, Default)]
struct IccComponents {
    ssb: f64,    // between-family sum of squares
    ssw: f64,    // within-family sum of squares
    df_b: f64,   // Σ (families − 1)
    df_w: f64,   // Σ (units − families)
    n0_num: f64, // Σ (N − Σ n_g²/N); pooled n0 = n0_num / df_b
}

impl IccComponents {
    fn add(&mut self, o: &IccComponents) {
        self.ssb += o.ssb;
        self.ssw += o.ssw;
        self.df_b += o.df_b;
        self.df_w += o.df_w;
        self.n0_num += o.n0_num;
    }
}

fn icc_components(families: &BTreeMap<String, Vec<f64>>) -> IccComponents {
    let k = families.len();
    let n_total: usize = families.values().map(|f| f.len()).sum();
    if n_total == 0 {
        return IccComponents::default();
    }
    let grand = families.values().flatten().sum::<f64>() / n_total as f64;
    let mut ssb = 0.0;
    let mut ssw = 0.0;
    let mut sum_nsq = 0.0;
    for f in families.values() {
        let ng = f.len();
        if ng == 0 {
            continue;
        }
        let gm = f.iter().sum::<f64>() / ng as f64;
        ssb += ng as f64 * (gm - grand).powi(2);
        for &y in f {
            ssw += (y - gm).powi(2);
        }
        sum_nsq += (ng * ng) as f64;
    }
    IccComponents {
        ssb,
        ssw,
        df_b: (k as f64 - 1.0).max(0.0),
        df_w: (n_total as f64 - k as f64).max(0.0),
        n0_num: n_total as f64 - sum_nsq / n_total as f64,
    }
}

/// The one-way random-effects ICC(1) from ANOVA components, clamped to [0, 1].
/// `None` when it is not estimable: fewer than two families (no between df) or no
/// within-family replication (no within df — one seed per family cannot separate the
/// two variance components).
fn icc_from(c: &IccComponents) -> Option<f64> {
    if c.df_b < 1.0 || c.df_w < 1.0 {
        return None;
    }
    let msb = c.ssb / c.df_b;
    let msw = c.ssw / c.df_w;
    let n0 = c.n0_num / c.df_b;
    let denom = msb + (n0 - 1.0) * msw;
    if denom.abs() < SE_EPS {
        return Some(0.0);
    }
    Some(((msb - msw) / denom).clamp(0.0, 1.0))
}

/// Design effect `1 + (m − 1)·ICC` for `m` seeds per family, floored at 1 — you can never
/// claim more precision than an independent sample (Q29.2). Matches
/// `bench_invariants::design_effect` for integer `m`.
fn design_effect(m: f64, icc: f64) -> f64 {
    (1.0 + (m - 1.0) * icc).max(1.0)
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, serde::Serialize)]
pub struct CategoryReport {
    pub category: String,
    pub mean_score: f64,
    pub pass_rate: f64,
    pub families: usize,
    pub units: usize,
    /// Simultaneous CI on `mean_score` (Bonferroni across the reported categories).
    pub score_ci: (f64, f64),
    /// True when the category has too few families to bootstrap honestly
    /// (`families < CLUSTER_FLOOR`): its CI is not trustworthy and it must be shown
    /// directional-only, never ranked.
    pub directional_only: bool,
    /// Empirical-Bayes-shrunk within-family ICC (Q29.2), or `None` when not estimable
    /// (fewer than two families, or one seed per family). Diagnostic/sizing only — it is
    /// **not** an input to `score_ci`, which comes from the bootstrap.
    pub icc: Option<f64>,
    /// Design effect `1 + (m − 1)·ICC` at this category's mean seeds-per-family — how
    /// many nominal units one effective unit costs. `None` when `icc` is.
    pub design_effect: Option<f64>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct StatReport {
    pub capability_score: f64,
    /// Overall CI at level `1 − ALPHA` (not simultaneity-adjusted — it is one figure).
    pub capability_ci: (f64, f64),
    pub pass_rate: f64,
    pub categories: Vec<CategoryReport>,
    pub units: usize,
    pub bootstrap_iters: usize,
    /// Number of categories the per-category CIs are corrected over (the `K` in
    /// the simultaneous `α/K`).
    pub simultaneous_k: usize,
    /// Throughput over every executed unit (core + probe); `None` if the journal
    /// carried no timing. The second headline number beside `capability_score`.
    pub throughput: Option<ThroughputReport>,
    /// Pooled within-family ICC across all categories (families compared within their
    /// own category, so category effects cancel). The shrink target for the per-category
    /// estimates; `None` when not estimable. Diagnostic only (Q29.2).
    pub pooled_icc: Option<f64>,
    /// AQ-202/OI-36c: miri-mandatory (`unsafe-core`) rows that carried no miri
    /// verdict and were therefore **refused** — excluded from every figure in
    /// this report (scored set, denominators, diagnostics, detect/compare).
    /// Published so the exclusion is loud, never a silent shrink.
    pub miri_refused: usize,
}

/// Compute the full report from a set of graded records.
pub fn report(records: &[Record]) -> StatReport {
    report_with(records, BOOTSTRAP_ITERS)
}

/// As [`report`], with an explicit bootstrap resample count (tests use a smaller one).
pub fn report_with(records: &[Record], iters: usize) -> StatReport {
    // AQ-202/OI-36c: a miri-mandatory row without a miri verdict is a refused
    // outcome — it is excluded from every scored figure below and only
    // *counted*. (Pre-AQ-202 journals carry no `miri:clean`/`miri:ub` flag, so
    // their unsafe-core rows are refused here too; compile-failed rows stay —
    // a genuine 0 can never pass.)
    let miri_refused = records.iter().filter(|r| is_miri_refused(r)).count();

    // Throughput is measured over *every* executed unit (core + probe both cost wall
    // time), so compute it before the core filter below.
    let throughput = throughput(records);

    // Only the paired **core** is scored — the fresh probe is the precomputation
    // detector and never enters a published figure (ADR-0009). Filtering here is the
    // one place that rule is enforced for capability, pass-rate, CIs and ICC.
    let records: Vec<Record> = records
        .iter()
        .filter(|r| r.kind == "core" && !is_miri_refused(r))
        .cloned()
        .collect();

    let by_score = group_by(&records, Record::score);
    let by_pass = group_by(&records, |r| if r.passed() { 1.0 } else { 0.0 });

    let capability_score = equal_weight_overall(&by_score).unwrap_or(f64::NAN);
    let pass_rate = equal_weight_overall(&by_pass).unwrap_or(f64::NAN);

    let k = by_score.len().max(1);
    let cat_alpha = ALPHA / k as f64; // Bonferroni simultaneous

    // One deterministic RNG stream for the whole report → reproducible CIs.
    let mut rng = Rng::new(0x5EED_5747_5747_5747);
    let capability_ci = clamp_ci(
        bootstrap_overall(&by_score, iters, ALPHA, &mut rng),
        0.0,
        1.0,
    );

    // ICC (Q29.2): per-category ANOVA estimate, empirical-Bayes-shrunk toward the pooled
    // value; the shrink target falls back to the design assumption when nothing is
    // estimable. Diagnostic only — never used in a CI above.
    let mut pooled_comp = IccComponents::default();
    for fams in by_score.values() {
        pooled_comp.add(&icc_components(fams));
    }
    let pooled_icc = icc_from(&pooled_comp);
    let shrink_target = pooled_icc.unwrap_or(bench_invariants::ICC);

    let mut categories = Vec::new();
    for (cat, fams) in &by_score {
        let mean_score = category_mean(fams).unwrap_or(f64::NAN);
        let pass_rate = by_pass.get(cat).and_then(category_mean).unwrap_or(f64::NAN);
        let families = fams.len();
        let units: usize = fams.values().map(|u| u.len()).sum();
        let score_ci = clamp_ci(
            bootstrap_category(fams, iters, cat_alpha, &mut rng),
            0.0,
            1.0,
        );

        let comp = icc_components(fams);
        let icc = icc_from(&comp).map(|raw| {
            // Shrink toward the pooled target by between-family df.
            let w = comp.df_b / (comp.df_b + ICC_SHRINK_TAU);
            w * raw + (1.0 - w) * shrink_target
        });
        let design_effect = icc.map(|i| design_effect(units as f64 / families.max(1) as f64, i));

        categories.push(CategoryReport {
            category: cat.clone(),
            mean_score,
            pass_rate,
            families,
            units,
            score_ci,
            directional_only: families < CLUSTER_FLOOR,
            icc,
            design_effect,
        });
    }

    StatReport {
        capability_score,
        capability_ci,
        pass_rate,
        categories,
        units: records.len(),
        bootstrap_iters: iters,
        simultaneous_k: k,
        pooled_icc,
        throughput,
        miri_refused,
    }
}

/// AQ-202/OI-36c: is this record a refused miri-mandatory row? An `unsafe-core`
/// row that compiled but carries no recorded miri verdict (`miri:clean` /
/// `miri:ub`) proves nothing about undefined behaviour, so it is neither a pass
/// nor a comparable failure — it is refused. Lives here (not only in
/// bench-core's `passed`) because aggregation must *drop* the row entirely,
/// not merely veto its pass bit.
pub fn is_miri_refused(r: &Record) -> bool {
    bench_core::miri_refused(&r.category, r.oracle.compile_ok, &r.oracle.flags)
}

// ---------------------------------------------------------------------------
// Diagnostics — apply/compile rates and the failure-class / error-code histograms
// ---------------------------------------------------------------------------

/// The per-model diagnostic aggregates (docs/03): apply/compile rates and the
/// failure-class + rustc-error-code histograms — the signal that says *which part
/// of Rust* a model is weak at, which no general-purpose benchmark produces.
#[derive(Clone, Debug, serde::Serialize)]
pub struct DiagnosticsReport {
    /// Scored (core) units the diagnostics are computed over.
    pub units: usize,
    /// Fraction of core units whose response applied (L0). A model that solves the
    /// problem but cannot emit an extractable answer is a distinct failure (docs/03).
    pub apply_rate: f64,
    /// Fraction of *applied* core units that compiled (L1).
    pub compile_rate: f64,
    /// `failure_class → count`, most frequent first.
    pub failure_classes: Vec<(String, usize)>,
    /// `rustc error code → count` across core units, most frequent first. Borrow
    /// failures are a lower bound (typeck aborts before borrowck — docs/03).
    pub error_codes: Vec<(String, usize)>,
    /// Core units whose compile failed *before* borrowck was reached
    /// (`diagnostic_completeness == typeck_only`). This is how many failures could
    /// be hiding a borrow bug, i.e. the size of the borrow-count undercount.
    pub typeck_only: usize,
}

/// Compute [`DiagnosticsReport`] over the **core** units only (the fresh probe is
/// never reported, ADR-0009 — matching [`report`]). AQ-202/OI-36c: refused
/// miri-mandatory rows are excluded as well — their counts live in
/// [`StatReport::miri_refused`], not in the failure histogram.
pub fn diagnostics(records: &[Record]) -> DiagnosticsReport {
    let core: Vec<&Record> = records
        .iter()
        .filter(|r| r.kind == "core" && !is_miri_refused(r))
        .collect();
    let units = core.len();
    let applied = core.iter().filter(|r| r.oracle.apply_ok).count();
    let compiled = core
        .iter()
        .filter(|r| r.oracle.apply_ok && r.oracle.compile_ok)
        .count();
    let apply_rate = if units > 0 {
        applied as f64 / units as f64
    } else {
        0.0
    };
    let compile_rate = if applied > 0 {
        compiled as f64 / applied as f64
    } else {
        0.0
    };
    let typeck_only = core
        .iter()
        .filter(|r| r.oracle.diagnostic_completeness == DiagnosticCompleteness::TypeckOnly)
        .count();

    let mut fc: BTreeMap<String, usize> = BTreeMap::new();
    let mut codes: BTreeMap<String, usize> = BTreeMap::new();
    for r in &core {
        *fc.entry(r.oracle.failure_class.as_str().to_string())
            .or_default() += 1;
        for c in &r.oracle.error_codes {
            *codes.entry(c.clone()).or_default() += 1;
        }
    }
    // Sort by descending count, then name for a deterministic order.
    let sort_desc = |m: BTreeMap<String, usize>| -> Vec<(String, usize)> {
        let mut v: Vec<(String, usize)> = m.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    };
    DiagnosticsReport {
        units,
        apply_rate,
        compile_rate,
        failure_classes: sort_desc(fc),
        error_codes: sort_desc(codes),
        typeck_only,
    }
}

// ---------------------------------------------------------------------------
// Binomial tail helpers (exact for small n, normal approx for large)
// ---------------------------------------------------------------------------

/// Above this cluster/discordant count the exact `0.5^n` term underflows f64, so the
/// binomial tail switches to the continuity-corrected normal approximation.
const EXACT_BINOM_MAX: u32 = 1024;

/// erf via Abramowitz–Stegun 7.1.26 (abs error < 1.5e-7). Used only for the large-n
/// normal approximation of the binomial tail.
fn erf(x: f64) -> f64 {
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();
    let t = 1.0 / (1.0 + 0.327_591_1 * x);
    let y = 1.0
        - (((((1.061_405_429 * t - 1.453_152_027) * t) + 1.421_413_741) * t - 0.284_496_736) * t
            + 0.254_829_592)
            * t
            * (-x * x).exp();
    sign * y
}

fn normal_cdf(z: f64) -> f64 {
    0.5 * (1.0 + erf(z / std::f64::consts::SQRT_2))
}

/// `P(X ≤ m)` for `X ~ Binomial(n, 0.5)`. Exact for `n ≤ EXACT_BINOM_MAX` via a stable
/// pmf recursion (`pmf(k) = pmf(k−1)·(n−k+1)/k`), else a continuity-corrected normal
/// approximation. The engine behind both the McNemar and sign-test p-values.
fn binom_cdf_le_half(n: u32, m: u32) -> f64 {
    if n == 0 || m >= n {
        return 1.0;
    }
    if n <= EXACT_BINOM_MAX {
        let mut pmf = 0.5f64.powi(n as i32);
        let mut cdf = pmf;
        for k in 1..=m {
            pmf *= (n - k + 1) as f64 / k as f64;
            cdf += pmf;
        }
        cdf.min(1.0)
    } else {
        let mean = n as f64 / 2.0;
        let sd = (n as f64 / 4.0).sqrt();
        normal_cdf((m as f64 + 0.5 - mean) / sd)
    }
}

// ---------------------------------------------------------------------------
// Model comparison (McNemar) and precomputation detection (sign test)
// ---------------------------------------------------------------------------

/// Detector significance level for the sign test: a precomputation *accusation* wants a
/// low false-positive rate, so the default is stricter than a typical 0.05.
pub const DETECTOR_ALPHA: f64 = 0.01;

fn family_of(task_id: &str) -> &str {
    task_id.split('/').next().unwrap_or(task_id)
}

/// McNemar's test on paired binary outcomes (docs/07: model comparison on the shared
/// `passed` bit). `discordant_a_only` = A passed while B failed; `discordant_b_only` the
/// reverse. Concordant pairs carry no information and are ignored. `p_value` is the
/// **exact** two-sided binomial test on the discordant split (normal-approx above
/// `EXACT_BINOM_MAX`); `statistic` is the continuity-corrected χ² for reference.
#[derive(Clone, Debug)]
pub struct McNemar {
    pub discordant_a_only: u32,
    pub discordant_b_only: u32,
    pub statistic: f64,
    pub p_value: f64,
}

pub fn mcnemar(pairs: &[(bool, bool)]) -> McNemar {
    let mut a_only = 0u32;
    let mut b_only = 0u32;
    for &(a, b) in pairs {
        match (a, b) {
            (true, false) => a_only += 1,
            (false, true) => b_only += 1,
            _ => {}
        }
    }
    let n = a_only + b_only;
    let statistic = if n == 0 {
        0.0
    } else {
        let d = (a_only as f64 - b_only as f64).abs() - 1.0;
        d.max(0.0).powi(2) / n as f64
    };
    let p_value = if n == 0 {
        1.0
    } else {
        (2.0 * binom_cdf_le_half(n, a_only.min(b_only))).min(1.0)
    };
    McNemar {
        discordant_a_only: a_only,
        discordant_b_only: b_only,
        statistic,
        p_value,
    }
}

/// One-sided sign test for precomputation (docs/07, Q29.1). Each pair is
/// `(core_bit, probe_bit)` for one family, where the core bit is the **pick-one**
/// collapse (a single designated core seed) — the only collapse that preserves the null.
/// `core_wins` = core passed while the fresh probe failed. Under H0 (no precomputation,
/// core and probe equally hard) `core_wins ~ Binomial(n_discordant, 0.5)`; `p_value` is
/// the upper tail `P(X ≥ core_wins)`, and `flagged` is `p < threshold`.
#[derive(Clone, Debug)]
pub struct SignTest {
    pub core_wins: u32,
    pub probe_wins: u32,
    pub p_value: f64,
    pub flagged: bool,
}

pub fn sign_test(pairs: &[(bool, bool)], threshold: f64) -> SignTest {
    let mut core_wins = 0u32;
    let mut probe_wins = 0u32;
    for &(core, probe) in pairs {
        match (core, probe) {
            (true, false) => core_wins += 1,
            (false, true) => probe_wins += 1,
            _ => {}
        }
    }
    let n = core_wins + probe_wins;
    // P(X ≥ core_wins) = P(X ≤ n − core_wins) by the symmetry of Binomial(n, 0.5).
    let p_value = if n == 0 {
        1.0
    } else {
        binom_cdf_le_half(n, n - core_wins)
    };
    SignTest {
        core_wins,
        probe_wins,
        p_value,
        flagged: p_value < threshold,
    }
}

/// A paired model-vs-model comparison over the shared scored units.
#[derive(Clone, Debug)]
pub struct ModelComparison {
    pub n_paired: usize,
    pub mcnemar: McNemar,
    /// Pooled pass-rate difference, model B minus model A.
    pub delta_pass_rate: f64,
    /// Studentised wild cluster bootstrap CI of the pass-rate difference, clustered by
    /// family — the clustered interval to state alongside McNemar's discordant count.
    pub delta_ci: (f64, f64),
    /// AQ-202/OI-36c (r70 F-1): refused miri-mandatory core rows dropped from
    /// journal A and journal B before pairing. Published so a shrunken
    /// `n_paired` is always explained, never a silent shrink.
    pub miri_refused_a: usize,
    pub miri_refused_b: usize,
}

/// Compare two models graded on the identical seed set (the paired design, docs/07).
/// Units are aligned by `task_id`; only shared units are used.
pub fn compare_models(a: &[Record], b: &[Record]) -> ModelComparison {
    compare_models_with(a, b, BOOTSTRAP_ITERS)
}

pub fn compare_models_with(a: &[Record], b: &[Record], iters: usize) -> ModelComparison {
    // Compare on scored **core** units only; the probe is the detector (ADR-0009).
    // AQ-202/OI-36c: refused miri-mandatory rows are dropped from both sides —
    // their `passed()` bit is forced-false for the right reason, but keeping
    // them would still shift the paired n and the deltas with a row that
    // proves nothing.
    let index = |recs: &[Record]| -> BTreeMap<String, bool> {
        recs.iter()
            .filter(|r| r.kind == "core" && !is_miri_refused(r))
            .map(|r| (r.task_id.clone(), r.passed()))
            .collect()
    };
    let refused = |recs: &[Record]| -> usize {
        recs.iter()
            .filter(|r| r.kind == "core" && is_miri_refused(r))
            .count()
    };
    let ma = index(a);
    let mb = index(b);

    let mut pairs = Vec::new();
    let mut diffs: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for (tid, &ap) in &ma {
        if let Some(&bp) = mb.get(tid) {
            pairs.push((ap, bp));
            let d = (bp as i32 - ap as i32) as f64;
            diffs.entry(family_of(tid).to_string()).or_default().push(d);
        }
    }

    let mcnemar = mcnemar(&pairs);
    let n_paired = pairs.len();
    let total: f64 = diffs.values().flatten().sum();
    let count: usize = diffs.values().map(|v| v.len()).sum();
    let delta_pass_rate = if count == 0 {
        f64::NAN
    } else {
        total / count as f64
    };
    let mut rng = Rng::new(0x5EED_C0DE_D1FF_0001);
    // Pass-rate difference lives in [-1, 1].
    let delta_ci = clamp_ci(
        bootstrap_category(&diffs, iters, ALPHA, &mut rng),
        -1.0,
        1.0,
    );

    ModelComparison {
        n_paired,
        mcnemar,
        delta_pass_rate,
        delta_ci,
        miri_refused_a: refused(a),
        miri_refused_b: refused(b),
    }
}

/// The precomputation-detector result for one epoch (ADR-0009, Q29.1).
#[derive(Clone, Debug)]
pub struct DetectorReport {
    pub epoch: String,
    /// Families that had both an index-0 core and an index-0 probe unit to pair.
    pub families_paired: usize,
    pub sign: SignTest,
}

/// Run the precomputation detector over a journal (ADR-0009). Within each epoch, take
/// each family's **pick-one** core bit (the index-0 core unit — the only collapse that
/// preserves the null, Q29.1) and pair it with that family's index-0 fresh-probe bit; the
/// one-sided sign test flags a family-paired core advantage. Returns one report per epoch
/// that has at least one paired family. `threshold` is the accusation α (e.g.
/// [`DETECTOR_ALPHA`]).
pub fn detect(records: &[Record], threshold: f64) -> Vec<DetectorReport> {
    // (core index-0 bit, probe index-0 bit) for one family.
    type CoreProbe = (Option<bool>, Option<bool>);
    // epoch -> family -> CoreProbe
    let mut by: BTreeMap<String, BTreeMap<String, CoreProbe>> = BTreeMap::new();
    for r in records {
        if r.index != 0 {
            continue; // pick-one: only the index-0 unit of each set
        }
        // AQ-202/OI-36c: a refused miri-mandatory core row contributes no bit
        // — the family simply does not pair in this epoch (a genuine gap, and
        // the report counts refusals elsewhere).
        if is_miri_refused(r) {
            continue;
        }
        let slot = by
            .entry(r.epoch.clone())
            .or_default()
            .entry(r.family().to_string())
            .or_default();
        match r.kind.as_str() {
            "core" => slot.0 = Some(r.passed()),
            "probe" => slot.1 = Some(r.passed()),
            _ => {}
        }
    }

    let mut out = Vec::new();
    for (epoch, fams) in by {
        let pairs: Vec<(bool, bool)> = fams.values().filter_map(|&(c, p)| Some((c?, p?))).collect();
        if pairs.is_empty() {
            continue; // no family had both a core and a probe to pair
        }
        out.push(DetectorReport {
            epoch,
            families_paired: pairs.len(),
            sign: sign_test(&pairs, threshold),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Throughput — the second headline number (docs/00 two-number thesis, docs/07)
// ---------------------------------------------------------------------------

/// What the machine delivered while running the suite. Computed over **every executed
/// unit** (core *and* probe both consume wall-clock time), except `passes_per_hour`,
/// which counts only scored core passes (the probe is never scored, ADR-0009).
#[derive(Clone, Debug, serde::Serialize)]
pub struct ThroughputReport {
    /// Executed units that carried timing.
    pub units: usize,
    /// Aggregate decode rate: completion tokens ÷ generate seconds. GPU-bound, so this
    /// is the model/hardware number, largely insensitive to CPU contention.
    pub decode_tok_per_s: f64,
    pub gen_s: f64,
    pub grade_s: f64,
    pub wall_s: f64,
    /// Executed units per hour of wall clock.
    pub units_per_hour: f64,
    /// Scored core passes per hour — docs/07's `throughput_score`.
    pub passes_per_hour: f64,
    /// Fraction of wall spent grading rather than generating.
    pub grade_share: f64,
    /// Timed units dropped from this aggregate as segment cache-warmth
    /// ([`SEGMENT_WARMUP_UNITS`]); 0 if the journal carries no segment positions.
    pub warmup_excluded: usize,
}

/// Fold a journal's per-unit costs into the throughput report. `None` when no unit
/// carried timing (e.g. synthetic records), so the caller can omit the section rather
/// than print zeros.
///
/// The first [`SEGMENT_WARMUP_UNITS`] of each segment are excluded for cache warmth
/// (docs/08): a unit is warmup iff it carries a `segment_position` below the
/// threshold. Units with no position (single `run`, older journals) are never
/// excluded. If excluding warmup would drop *every* timed unit (e.g. a one-unit
/// segment), all timed units are kept instead — a warm-biased number beats none.
pub fn throughput(records: &[Record]) -> Option<ThroughputReport> {
    let timed = |r: &Record| r.cost.gen_ms != 0 || r.cost.grade_ms != 0;
    let is_warmup = |r: &Record| r.segment_position.is_some_and(|p| p < SEGMENT_WARMUP_UNITS);
    // Only exclude warmup if some timed steady-state unit remains to measure.
    let exclude_warmup = records.iter().any(|r| timed(r) && !is_warmup(r));

    let mut gen_ms = 0u64;
    let mut grade_ms = 0u64;
    let mut ctoks = 0u64;
    let mut units = 0usize;
    let mut core_passes = 0usize;
    let mut warmup_excluded = 0usize;
    for r in records {
        if !timed(r) {
            continue; // no timing recorded for this unit
        }
        if exclude_warmup && is_warmup(r) {
            warmup_excluded += 1;
            continue;
        }
        let c = &r.cost;
        gen_ms += c.gen_ms;
        grade_ms += c.grade_ms;
        ctoks += c.completion_tokens as u64;
        units += 1;
        if r.kind == "core" && r.passed() {
            core_passes += 1;
        }
    }
    if units == 0 {
        return None;
    }
    let gen_s = gen_ms as f64 / 1000.0;
    let grade_s = grade_ms as f64 / 1000.0;
    let wall_s = gen_s + grade_s;
    let per_hour = |n: f64| {
        if wall_s > 0.0 {
            n * 3600.0 / wall_s
        } else {
            0.0
        }
    };
    Some(ThroughputReport {
        units,
        decode_tok_per_s: if gen_s > 0.0 {
            ctoks as f64 / gen_s
        } else {
            0.0
        },
        gen_s,
        grade_s,
        wall_s,
        units_per_hour: per_hour(units as f64),
        passes_per_hour: per_hour(core_passes as f64),
        grade_share: if wall_s > 0.0 { grade_s / wall_s } else { 0.0 },
        warmup_excluded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dataset() -> Vec<Record> {
        // Two categories. Cat A: 2 families × 3 units, all passing, score 1.0.
        // Cat B: 1 family × 3 units, none passing, score 0.0.
        let mut v = Vec::new();
        for fam in ["a1", "a2"] {
            for u in 0..3 {
                v.push(Record::synthetic("cat-a", fam, u, 1.0, true));
            }
        }
        for u in 0..3 {
            v.push(Record::synthetic("cat-b", "b1", u, 0.0, false));
        }
        v
    }

    #[test]
    fn capability_is_equal_weight_over_categories() {
        // Cat A mean 1.0, Cat B mean 0.0 → equal-weight overall 0.5, NOT the pooled
        // 6/9 = 0.67 that unit-weighting would give.
        let r = report_with(&dataset(), 200);
        assert!(
            (r.capability_score - 0.5).abs() < 1e-9,
            "got {}",
            r.capability_score
        );
        assert!((r.pass_rate - 0.5).abs() < 1e-9, "got {}", r.pass_rate);
    }

    #[test]
    fn family_is_derived_from_task_id() {
        let r = Record::synthetic("c", "window-op", 7, 1.0, true);
        assert_eq!(r.family(), "window-op");
    }

    #[test]
    fn pass_uses_the_structural_predicate() {
        assert!(Record::synthetic("c", "f", 0, 0.9, true).passed());
        // A high composite score does not imply a pass — behaviour must be 1.0.
        assert!(!Record::synthetic("c", "f", 0, 0.99, false).passed());
    }

    #[test]
    fn few_family_categories_are_directional_only() {
        let r = report_with(&dataset(), 200);
        let a = r.categories.iter().find(|c| c.category == "cat-a").unwrap();
        let b = r.categories.iter().find(|c| c.category == "cat-b").unwrap();
        // Both have < CLUSTER_FLOOR families, so both are flagged.
        assert!(a.directional_only && b.directional_only);
        assert_eq!(a.families, 2);
        assert_eq!(b.families, 1);
    }

    #[test]
    fn per_category_ci_is_simultaneous_over_k() {
        let r = report_with(&dataset(), 200);
        assert_eq!(r.simultaneous_k, 2, "two categories → corrected over 2");
    }

    #[test]
    fn ci_brackets_the_point_estimate() {
        let r = report_with(&dataset(), 2000);
        let (lo, hi) = r.capability_ci;
        assert!(lo <= r.capability_score + 1e-9 && r.capability_score <= hi + 1e-9);
        assert!(lo <= hi);
    }

    #[test]
    fn homogeneous_category_has_zero_width_ci() {
        // Cat A is all-1.0: every family residual is zero, so the wild bootstrap can
        // never move the mean and the CI has zero width — correct (there is no
        // variance to report), and the category is still flagged directional-only.
        let r = report_with(&dataset(), 500);
        let a = r.categories.iter().find(|c| c.category == "cat-a").unwrap();
        assert!((a.score_ci.0 - 1.0).abs() < 1e-9 && (a.score_ci.1 - 1.0).abs() < 1e-9);
        assert!(a.directional_only, "and it is flagged as not trustworthy");
    }

    #[test]
    fn wild_ci_reflects_between_family_variance() {
        // One category, six families spread evenly 0.0..1.0 (mean 0.5). The
        // studentised wild bootstrap produces a non-trivial interval bracketing the
        // mean — it picks up the between-family spread rather than collapsing.
        // (Studentising is degenerate at 2 clusters, which is exactly why sub-floor
        // categories are directional-only; six clusters is enough to be well-defined.)
        let mut v = Vec::new();
        for (i, s) in [0.0, 0.2, 0.4, 0.6, 0.8, 1.0].into_iter().enumerate() {
            for u in 0..2 {
                v.push(Record::synthetic("c", &format!("f{i}"), u, s, s >= 0.5));
            }
        }
        let r = report_with(&v, 4000);
        let c = &r.categories[0];
        assert!((c.mean_score - 0.5).abs() < 1e-6); // f32-origin scores
        let width = c.score_ci.1 - c.score_ci.0;
        assert!(width > 0.05, "expected a non-trivial interval, got {width}");
        assert!(c.score_ci.0 <= 0.5 && 0.5 <= c.score_ci.1);
    }

    #[test]
    fn wild_bootstrap_coverage_is_near_nominal() {
        // Q29.5's validation: simulate clustered data whose population mean is 0
        // (cluster effects and noise both mean-zero), and check the 95% studentised
        // wild CI covers 0 close to 95% of the time. Measured 0.953 at G=12 (the raw
        // percentile form managed only 0.90, and the naive resample-families
        // bootstrap under-covers this design further). Bound at 0.90 to guard the
        // studentised improvement while tolerating simulation noise.
        let mut rng = Rng::new(0xC0FF_EE12_3400);
        let uni = |r: &mut Rng| (r.next_u64() >> 11) as f64 / (1u64 << 53) as f64; // [0,1)
        let trials = 600;
        let (g, n) = (12usize, 4usize);
        let mut covered = 0;
        for _ in 0..trials {
            let mut fams: BTreeMap<String, Vec<f64>> = BTreeMap::new();
            for gi in 0..g {
                let eff = uni(&mut rng) * 2.0 - 1.0; // cluster effect in [-1, 1)
                let units: Vec<f64> = (0..n).map(|_| eff + uni(&mut rng) * 0.6 - 0.3).collect();
                fams.insert(format!("f{gi:02}"), units);
            }
            let (lo, hi) = bootstrap_category(&fams, 400, 0.05, &mut rng);
            if lo <= 0.0 && 0.0 <= hi {
                covered += 1;
            }
        }
        let coverage = covered as f64 / trials as f64;
        assert!(
            coverage >= 0.90,
            "studentised wild CI coverage {coverage} is too low (nominal 0.95)"
        );
    }

    #[test]
    fn parse_journal_reads_real_shaped_lines() {
        // A minimal journal line with extra fields serde must ignore.
        let line = r#"{"schema":1,"unit_id":"x","task_id":"window-op/0000000000000001","category":"borrow-lifetimes","seed":1,"index":0,"model":{"name":"m"},"sandbox":"seatbelt","oracle":{"apply_ok":true,"compile_ok":true,"error_codes":[],"warn_count":0,"behavior":{"unit":null,"property":null,"differential":null,"score":1.0},"constraint":{"alloc_ok":null,"clippy_clean":null,"fmt_ok":null,"unsafe_blocks":null,"unsafe_ok":null,"paths_ok":null,"violations":[],"score":null},"score":0.9,"failure_class":"none","flags":[]},"cost":{},"failure_class":"none"}"#;
        let recs = parse_journal(line).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].family(), "window-op");
        assert!(
            recs[0].passed(),
            "behaviour 1.0, no failing constraint → pass"
        );
        assert!((recs[0].score() - 0.9).abs() < 1e-6); // score is f32-origin
    }

    #[test]
    fn binomial_tail_matches_known_values() {
        // P(X ≤ 5) for Binomial(10, 0.5) = 0.6230; P(X ≤ 10) for Binomial(20, 0.5) = 0.5881.
        assert!((binom_cdf_le_half(10, 5) - 0.6230).abs() < 1e-3);
        assert!((binom_cdf_le_half(20, 10) - 0.5881).abs() < 1e-3);
        assert_eq!(binom_cdf_le_half(10, 10), 1.0);
        assert!((normal_cdf(0.0) - 0.5).abs() < 1e-6);
        assert!((normal_cdf(1.959_964) - 0.975).abs() < 1e-3);
    }

    #[test]
    fn mcnemar_counts_and_significance() {
        // Balanced discordant split → not significant.
        let balanced = vec![(true, false), (false, true), (true, true), (false, false)];
        let m = mcnemar(&balanced);
        assert_eq!((m.discordant_a_only, m.discordant_b_only), (1, 1));
        assert!(m.p_value > 0.5);
        // Lopsided: A beats B on 10 units, none the other way → significant.
        let lopsided: Vec<(bool, bool)> = (0..10).map(|_| (true, false)).collect();
        let m = mcnemar(&lopsided);
        assert_eq!((m.discordant_a_only, m.discordant_b_only), (10, 0));
        assert!(m.p_value < 0.01, "p = {}", m.p_value);
        // No discordant pairs → no evidence.
        assert_eq!(mcnemar(&[(true, true), (false, false)]).p_value, 1.0);
    }

    #[test]
    fn sign_test_flags_only_a_core_advantage() {
        // Core systematically beats the fresh probe → precomputation flagged.
        let suspicious: Vec<(bool, bool)> = (0..10).map(|_| (true, false)).collect();
        let s = sign_test(&suspicious, DETECTOR_ALPHA);
        assert_eq!((s.core_wins, s.probe_wins), (10, 0));
        assert!(s.flagged && s.p_value < DETECTOR_ALPHA);
        // Balanced discordance (honest run) → not flagged, one-sided p near 0.5+.
        let honest = vec![(true, false), (false, true), (true, false), (false, true)];
        let s = sign_test(&honest, DETECTOR_ALPHA);
        assert!(!s.flagged);
        // A probe *advantage* is never precomputation, so never flagged.
        let probe_better: Vec<(bool, bool)> = (0..10).map(|_| (false, true)).collect();
        assert!(!sign_test(&probe_better, DETECTOR_ALPHA).flagged);
    }

    #[test]
    fn compare_models_pairs_by_task_id() {
        // Model A passes families f0,f1 (2 seeds each); model B passes only f0.
        let mut a = Vec::new();
        let mut b = Vec::new();
        for fam in ["f0", "f1"] {
            for u in 0..2 {
                a.push(Record::synthetic("c", fam, u, 1.0, true));
                let b_pass = fam == "f0";
                b.push(Record::synthetic("c", fam, u, 1.0, b_pass));
            }
        }
        let cmp = compare_models_with(&a, &b, 2000);
        assert_eq!(cmp.n_paired, 4);
        // On f1's 2 units A passed and B failed → 2 discordant, all A-only.
        assert_eq!(cmp.mcnemar.discordant_a_only, 2);
        assert_eq!(cmp.mcnemar.discordant_b_only, 0);
        // B minus A pass-rate is negative (B is worse).
        assert!(cmp.delta_pass_rate < 0.0);
        assert!(cmp.delta_ci.0 <= cmp.delta_pass_rate && cmp.delta_pass_rate <= cmp.delta_ci.1);
    }

    fn fam_map(fams: &[(&str, &[f64])]) -> BTreeMap<String, Vec<f64>> {
        fams.iter()
            .map(|(k, v)| (k.to_string(), v.to_vec()))
            .collect()
    }

    #[test]
    fn icc_captures_pure_between_family_variance() {
        // Each family is internally constant, families differ → all variance is
        // between families → ICC = 1.
        let m = fam_map(&[("a", &[0.0, 0.0]), ("b", &[0.5, 0.5]), ("c", &[1.0, 1.0])]);
        let icc = icc_from(&icc_components(&m)).unwrap();
        assert!((icc - 1.0).abs() < 1e-9, "got {icc}");
    }

    #[test]
    fn icc_captures_pure_within_family_variance() {
        // Every family has the same mean (0.5) with variance inside → no between
        // variance → ICC = 0.
        let m = fam_map(&[
            ("a", &[0.0, 1.0, 0.0, 1.0]),
            ("b", &[1.0, 0.0, 1.0, 0.0]),
            ("c", &[0.0, 1.0, 1.0, 0.0]),
        ]);
        let icc = icc_from(&icc_components(&m)).unwrap();
        assert!(icc < 1e-9, "got {icc}");
    }

    #[test]
    fn icc_not_estimable_without_replication() {
        // One seed per family: no within-family df, so the two variance components
        // cannot be separated → not estimable.
        let m = fam_map(&[("a", &[1.0]), ("b", &[0.0]), ("c", &[0.5])]);
        assert_eq!(icc_from(&icc_components(&m)), None);
        // Fewer than two families is also not estimable.
        let m1 = fam_map(&[("a", &[0.0, 1.0, 0.5])]);
        assert_eq!(icc_from(&icc_components(&m1)), None);
    }

    #[test]
    fn report_shrinks_icc_and_derives_design_effect() {
        // Two categories, each with a few families that have within-family
        // replication so ICC is estimable. Check the report exposes a pooled ICC,
        // per-category shrunk ICC in [0,1], and a design effect >= 1.
        let mut v = Vec::new();
        for (cat, base) in [("cat-a", 0.0f64), ("cat-b", 0.5f64)] {
            for (fi, off) in [0.0f64, 0.3, 0.6].into_iter().enumerate() {
                // within-family spread so df_w > 0, plus a between-family offset
                for (u, d) in [-0.05f64, 0.05].into_iter().enumerate() {
                    let s: f64 = (base + off + d).clamp(0.0, 1.0);
                    v.push(Record::synthetic(
                        cat,
                        &format!("f{fi}"),
                        u as u64,
                        s,
                        s >= 0.5,
                    ));
                }
            }
        }
        let r = report_with(&v, 500);
        assert!(r.pooled_icc.is_some(), "pooled ICC should be estimable");
        for c in &r.categories {
            let icc = c.icc.expect("per-category ICC estimable");
            assert!((0.0..=1.0).contains(&icc), "icc out of range: {icc}");
            let de = c.design_effect.unwrap();
            assert!(de >= 1.0, "design effect must be >= 1, got {de}");
        }
    }

    #[test]
    fn detector_flags_precomputation_and_clears_honest_runs() {
        // Precompute signature: on every family the predictable core (index 0) passes
        // while the fresh probe fails → one-directional core advantage → flagged.
        let fams = ["f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7"];
        let mut cheat = Vec::new();
        for f in fams {
            cheat.push(Record::synthetic_unit("c", f, "e", "core", 0, 1.0, true));
            cheat.push(Record::synthetic_unit("c", f, "e", "probe", 0, 0.5, false));
        }
        let d = detect(&cheat, DETECTOR_ALPHA);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].families_paired, 8);
        assert!(d[0].sign.flagged, "p={}", d[0].sign.p_value);
        assert_eq!((d[0].sign.core_wins, d[0].sign.probe_wins), (8, 0));

        // Honest run: core and probe agree (both pass) → no discordance → not flagged.
        let mut honest = Vec::new();
        for f in fams {
            honest.push(Record::synthetic_unit("c", f, "e", "core", 0, 1.0, true));
            honest.push(Record::synthetic_unit("c", f, "e", "probe", 0, 1.0, true));
        }
        let d = detect(&honest, DETECTOR_ALPHA);
        assert!(!d[0].sign.flagged);
    }

    #[test]
    fn detector_uses_pick_one_and_groups_by_epoch() {
        // Non-index-0 core units must be ignored (pick-one), and separate epochs are
        // reported separately.
        let recs = vec![
            Record::synthetic_unit("c", "f", "e1", "core", 0, 1.0, true),
            Record::synthetic_unit("c", "f", "e1", "core", 1, 0.5, false), // ignored (index 1)
            Record::synthetic_unit("c", "f", "e1", "probe", 0, 0.5, false),
            Record::synthetic_unit("c", "f", "e2", "core", 0, 0.5, false),
            Record::synthetic_unit("c", "f", "e2", "probe", 0, 0.5, false),
        ];
        let d = detect(&recs, DETECTOR_ALPHA);
        assert_eq!(d.len(), 2, "two epochs → two reports");
        let e1 = d.iter().find(|r| r.epoch == "e1").unwrap();
        // e1: core index-0 passed, probe failed → one core win.
        assert_eq!((e1.sign.core_wins, e1.sign.probe_wins), (1, 0));
        let e2 = d.iter().find(|r| r.epoch == "e2").unwrap();
        // e2: core and probe both failed → concordant → no discordance.
        assert_eq!((e2.sign.core_wins, e2.sign.probe_wins), (0, 0));
    }

    #[test]
    fn throughput_folds_cost_over_all_units() {
        // Two core units and one probe, each with timing. Throughput counts all three
        // for wall/tok/s but only the passing core toward passes/hour.
        let mk = |kind: &str, passed: bool, ctoks: u32, gen_ms: u64, grade_ms: u64| {
            let line = format!(
                r#"{{"task_id":"f/{ct:016x}","category":"c","kind":"{kind}","index":0,"epoch":"e","cost":{{"prompt_tokens":100,"completion_tokens":{ct},"gen_ms":{gen_ms},"grade_ms":{grade_ms}}},"oracle":{{"apply_ok":true,"compile_ok":true,"error_codes":[],"warn_count":0,"behavior":{{"unit":null,"property":null,"differential":null,"score":{beh}}},"constraint":{{"alloc_ok":null,"clippy_clean":null,"fmt_ok":null,"unsafe_blocks":null,"unsafe_ok":null,"paths_ok":null,"violations":[],"score":null}},"score":0.5,"failure_class":"none","flags":[]}}}}"#,
                ct = ctoks,
                beh = if passed { "1.0" } else { "0.5" },
            );
            parse_journal(&line).unwrap().pop().unwrap()
        };
        let recs = vec![
            mk("core", true, 100, 2000, 500),  // 50 tok/s
            mk("core", false, 100, 2000, 500), // compiled? behaviour 0.5 -> not a pass
            mk("probe", true, 100, 2000, 500),
        ];
        let t = throughput(&recs).unwrap();
        assert_eq!(t.units, 3);
        assert!(
            (t.decode_tok_per_s - 50.0).abs() < 1e-6,
            "{}",
            t.decode_tok_per_s
        );
        assert!((t.wall_s - 7.5).abs() < 1e-6); // 3 * (2.0 + 0.5)
        assert!((t.grade_share - 0.2).abs() < 1e-6); // 1.5 / 7.5
                                                     // 3 units in 7.5s -> 1440/hour; 1 core pass in 7.5s -> 480/hour.
        assert!((t.units_per_hour - 1440.0).abs() < 1e-3);
        assert!((t.passes_per_hour - 480.0).abs() < 1e-3);
        // Synthetic records (no timing) → None.
        assert!(throughput(&[Record::synthetic("c", "f", 0, 1.0, true)]).is_none());
    }

    #[test]
    fn diagnostics_rates_and_histograms() {
        use bench_core::FailureClass;
        let mk = |compile: bool, fc: FailureClass, codes: &[&str]| {
            let mut r = Record::synthetic("c", "f", 0, if compile { 0.5 } else { 0.0 }, false);
            r.oracle.apply_ok = true;
            r.oracle.compile_ok = compile;
            r.oracle.failure_class = fc;
            r.oracle.error_codes = codes.iter().map(|s| s.to_string()).collect();
            r
        };
        let mut recs = vec![
            mk(false, FailureClass::Borrowck, &["E0499"]),
            mk(false, FailureClass::Borrowck, &["E0499", "E0502"]),
            mk(true, FailureClass::Logic, &[]),
            mk(true, FailureClass::None, &[]),
        ];
        // A non-applying core unit (didn't emit extractable code).
        let mut na = Record::synthetic("c", "f", 0, 0.0, false);
        na.oracle.apply_ok = false;
        na.oracle.compile_ok = false;
        na.oracle.failure_class = FailureClass::Other;
        recs.push(na);
        // A probe unit that must be ignored (ADR-0009).
        recs.push(Record::synthetic_unit(
            "c", "f", "e", "probe", 0, 0.0, false,
        ));
        // Two of the core failures had borrowck masked by an earlier-phase error.
        recs[0].oracle.diagnostic_completeness = DiagnosticCompleteness::TypeckOnly;
        recs[1].oracle.diagnostic_completeness = DiagnosticCompleteness::TypeckOnly;

        let d = diagnostics(&recs);
        assert_eq!(d.units, 5, "5 core units; probe excluded");
        assert_eq!(d.typeck_only, 2, "two core failures were typeck-only");
        assert!((d.apply_rate - 4.0 / 5.0).abs() < 1e-9, "{}", d.apply_rate); // 4 of 5 applied
        assert!(
            (d.compile_rate - 2.0 / 4.0).abs() < 1e-9,
            "{}",
            d.compile_rate
        ); // 2 of 4 compiled
        assert_eq!(d.failure_classes[0], ("borrowck".to_string(), 2)); // most frequent
        assert_eq!(d.error_codes[0], ("E0499".to_string(), 2));
        assert!(d.error_codes.contains(&("E0502".to_string(), 1)));
    }

    #[test]
    fn parses_current_emission_journal_line() {
        // Pins docs/12's "Current emission" block: the exact line `run`/`run-suite`
        // write must deserialise into `Record`. A drift in the reader breaks CI —
        // that is the point (schemas were drifting behind the code).
        let line = r#"{"schema":1,"unit_id":"blake3:x","task_id":"window-op/0000000000000000","category":"borrow-lifetimes","seed":8412739123,"index":0,"epoch":"2026-08","kind":"core","segment":0,"segment_position":0,"model":{"name":"m","base_url":"u","finish_reason":"stop"},"sandbox":"seatbelt","oracle":{"apply_ok":true,"compile_ok":false,"error_codes":["E0499"],"warn_count":2,"diagnostic_completeness":"full","behavior":{"unit":null,"property":null,"differential":null,"score":null},"constraint":{"alloc_ok":null,"clippy_clean":null,"fmt_ok":null,"unsafe_blocks":null,"unsafe_ok":null,"paths_ok":null,"violations":[],"score":null},"score":0.0,"failure_class":"borrowck","flags":[]},"cost":{"prompt_tokens":1842,"completion_tokens":611,"gen_ms":30410,"grade_ms":1880},"failure_class":"borrowck"}"#;
        let recs = parse_journal(line).unwrap();
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r.kind, "core");
        assert_eq!(r.epoch, "2026-08");
        assert_eq!(r.segment, Some(0));
        assert_eq!(r.segment_position, Some(0));
        assert_eq!(r.family(), "window-op");
        assert_eq!(r.cost.gen_ms, 30410);
        assert!(!r.oracle.compile_ok);
        assert_eq!(
            r.oracle.diagnostic_completeness,
            bench_core::DiagnosticCompleteness::Full
        );
        assert_eq!(r.oracle.error_codes, vec!["E0499".to_string()]);
        assert_eq!(r.oracle.failure_class, bench_core::FailureClass::Borrowck);
    }

    #[test]
    fn throughput_excludes_segment_warmup() {
        // Units at segment position < SEGMENT_WARMUP_UNITS are dropped from the
        // timing aggregate (docs/08). One cold lead unit (position 0) followed by
        // two warm ones (positions 1, 2), all in segment 0.
        let mk = |pos: u32, gen_ms: u64, grade_ms: u64| {
            let line = format!(
                r#"{{"task_id":"f/{pos:016x}","category":"c","kind":"core","index":{pos},"epoch":"e","segment":0,"segment_position":{pos},"cost":{{"prompt_tokens":100,"completion_tokens":100,"gen_ms":{gen_ms},"grade_ms":{grade_ms}}},"oracle":{{"apply_ok":true,"compile_ok":true,"error_codes":[],"warn_count":0,"behavior":{{"unit":null,"property":null,"differential":null,"score":1.0}},"constraint":{{"alloc_ok":null,"clippy_clean":null,"fmt_ok":null,"unsafe_blocks":null,"unsafe_ok":null,"paths_ok":null,"violations":[],"score":null}},"score":1.0,"failure_class":"none","flags":[]}}}}"#,
            );
            parse_journal(&line).unwrap().pop().unwrap()
        };
        // Cold lead unit is slow (1 tok/s); the two warm units are fast (100 tok/s).
        let recs = vec![
            mk(0, 100_000, 0), // warmup: excluded
            mk(1, 1000, 0),    // 100 tok/s
            mk(2, 1000, 0),    // 100 tok/s
        ];
        let t = throughput(&recs).unwrap();
        assert_eq!(t.units, 2, "the cold lead unit is excluded");
        assert_eq!(t.warmup_excluded, 1);
        // Steady-state decode is the warm rate, not dragged down by the cold unit.
        assert!(
            (t.decode_tok_per_s - 100.0).abs() < 1e-6,
            "got {}",
            t.decode_tok_per_s
        );

        // A one-unit segment is all warmup; rather than report nothing, fall back to
        // using it (a warm-biased number beats None).
        let solo = vec![mk(0, 2000, 500)];
        let ts = throughput(&solo).unwrap();
        assert_eq!(ts.units, 1);
        assert_eq!(ts.warmup_excluded, 0);
    }

    #[test]
    fn report_scores_core_only_never_probe() {
        // One category, one family: two core units at 1.0 (pass) and a probe at 0.0
        // (fail). Capability/pass must reflect the core only (ADR-0009) — the probe
        // must not drag them down.
        let recs = vec![
            Record::synthetic_unit("c", "f", "e", "core", 0, 1.0, true),
            Record::synthetic_unit("c", "f", "e", "core", 1, 1.0, true),
            Record::synthetic_unit("c", "f", "e", "probe", 0, 0.0, false),
        ];
        let r = report_with(&recs, 200);
        assert_eq!(r.units, 2, "probe unit excluded from the scored count");
        assert!(
            (r.capability_score - 1.0).abs() < 1e-9,
            "got {}",
            r.capability_score
        );
        assert!((r.pass_rate - 1.0).abs() < 1e-9, "got {}", r.pass_rate);
    }

    #[test]
    fn detector_empty_when_no_probe() {
        let recs = vec![Record::synthetic_unit("c", "f", "e", "core", 0, 1.0, true)];
        assert!(
            detect(&recs, DETECTOR_ALPHA).is_empty(),
            "no probe → nothing to pair"
        );
    }

    #[test]
    fn compare_models_uses_only_shared_units() {
        // A has an extra unit B never ran; it must be dropped from the pairing.
        let a = vec![
            Record::synthetic("c", "f", 0, 1.0, true),
            Record::synthetic("c", "f", 1, 1.0, true),
        ];
        let b = vec![Record::synthetic("c", "f", 0, 1.0, false)];
        let cmp = compare_models_with(&a, &b, 500);
        assert_eq!(cmp.n_paired, 1, "only the shared unit is compared");
    }

    /// A passing oracle blob — the fields `OracleVector` requires (behavior and
    /// constraint have no serde default).
    const OK_ORACLE: &str = r#"{"apply_ok":true,"compile_ok":true,"error_codes":[],"warn_count":0,"behavior":{"unit":null,"property":null,"differential":null,"score":1.0},"constraint":{"alloc_ok":null,"clippy_clean":null,"fmt_ok":null,"unsafe_blocks":null,"unsafe_ok":null,"paths_ok":null,"violations":[],"score":null},"score":1.0,"failure_class":"none","flags":[]}"#;

    #[test]
    fn parse_journal_rejects_bad_json_naming_the_line() {
        let text = format!(
            "{{\"task_id\":\"a/1\",\"category\":\"c\",\"oracle\":{OK_ORACLE}}}\nnot json\n"
        );
        let err = parse_journal(&text).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("line 2"),
            "error must name the offending line, got {err}"
        );
    }

    #[test]
    fn parse_journal_skips_blank_lines() {
        let text =
            format!("\n{{\"task_id\":\"a/1\",\"category\":\"c\",\"oracle\":{OK_ORACLE}}}\n   \n");
        assert_eq!(parse_journal(&text).unwrap().len(), 1);
    }

    #[test]
    fn load_journal_reads_a_temp_file() {
        let path =
            std::env::temp_dir().join(format!("rb-stats-journal-{}.jsonl", std::process::id()));
        let line_a = format!("{{\"task_id\":\"a/1\",\"category\":\"c\",\"oracle\":{OK_ORACLE}}}");
        let line_b = format!("{{\"task_id\":\"b/2\",\"category\":\"c\",\"oracle\":{OK_ORACLE}}}");
        std::fs::write(&path, format!("{line_a}\n\n{line_b}\n")).unwrap();
        let recs = load_journal(&path).unwrap();
        assert_eq!(recs.len(), 2);
        let _ = std::fs::remove_file(&path);
    }

    // --- AQ-194: contained and uncontained rows must not be mixed silently ---

    #[test]
    fn load_journal_refuses_to_mix_contained_and_uncontained_rows() {
        let path = std::env::temp_dir().join(format!("rb-stats-mix-{}.jsonl", std::process::id()));
        let seatbelt =
            format!("{{\"task_id\":\"a/1\",\"category\":\"c\",\"sandbox\":\"seatbelt\",\"oracle\":{OK_ORACLE}}}");
        let opted_in_unsupported = format!(
            "{{\"task_id\":\"a/2\",\"category\":\"c\",\"sandbox\":\"unsupported\",\"sandbox_opted_in\":true,\"oracle\":{OK_ORACLE}}}"
        );
        std::fs::write(&path, format!("{seatbelt}\n{opted_in_unsupported}\n")).unwrap();
        let err = load_journal(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let msg = err.to_string();
        assert!(
            msg.contains("not comparable"),
            "refusal must say why the mix is refused, got: {msg}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_journal_accepts_homogeneous_journals_of_either_class() {
        let path =
            std::env::temp_dir().join(format!("rb-stats-homog-{}.jsonl", std::process::id()));
        let unsupported =
            format!("{{\"task_id\":\"a/1\",\"category\":\"c\",\"sandbox\":\"unsupported\",\"oracle\":{OK_ORACLE}}}");
        std::fs::write(&path, format!("{unsupported}\n{unsupported}\n")).unwrap();
        assert_eq!(
            load_journal(&path).unwrap().len(),
            2,
            "an all-uncontained journal is homogeneous and aggregates"
        );
        let seatbelt =
            format!("{{\"task_id\":\"b/1\",\"category\":\"c\",\"sandbox\":\"seatbelt\",\"oracle\":{OK_ORACLE}}}");
        std::fs::write(&path, format!("{seatbelt}\n")).unwrap();
        assert_eq!(
            load_journal(&path).unwrap().len(),
            1,
            "an all-contained journal aggregates"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unknown_or_absent_sandbox_counts_as_uncontained_not_contained() {
        // Fail closed: only a known-contained value is contained.
        assert_eq!(containment_class(None), "uncontained");
        assert_eq!(containment_class(Some("unsupported")), "uncontained");
        assert_eq!(containment_class(Some("netns")), "uncontained");
        assert_eq!(containment_class(Some("seatbelt")), "contained");
        // A legacy journal with no `sandbox` field at all is homogeneous
        // (all-uncontained) and still loads.
        let path =
            std::env::temp_dir().join(format!("rb-stats-legacy-{}.jsonl", std::process::id()));
        let legacy = format!("{{\"task_id\":\"a/1\",\"category\":\"c\",\"oracle\":{OK_ORACLE}}}");
        std::fs::write(&path, format!("{legacy}\n")).unwrap();
        assert_eq!(load_journal(&path).unwrap().len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    // --- AQ-194 r54 R2: the journal's class drives the stats-side opt-in ---

    /// A Record whose `sandbox` field is `sb`, parsed from the same shape the
    /// journal carries (so the classification under test is the serde one).
    fn record_with_sandbox(sb: &str) -> Record {
        let line = format!(
            "{{\"task_id\":\"a/1\",\"category\":\"c\",\"sandbox\":\"{sb}\",\"oracle\":{OK_ORACLE}}}"
        );
        serde_json::from_str::<Record>(&line).expect("test journal line must parse")
    }

    #[test]
    fn journal_class_is_homogeneous_class_and_refuses_mix() {
        let seatbelt = record_with_sandbox("seatbelt");
        let unsupported = record_with_sandbox("unsupported");
        assert_eq!(
            journal_containment_class(&[seatbelt.clone(), seatbelt.clone()]).unwrap(),
            "contained"
        );
        assert_eq!(
            journal_containment_class(&[
                unsupported.clone(),
                unsupported,
                record_with_sandbox("unsupported")
            ])
            .unwrap(),
            "uncontained"
        );
        let mixed = journal_containment_class(&[seatbelt, record_with_sandbox("unsupported")]);
        assert!(mixed.is_err(), "a mixed journal has no class to report");
        // Legacy rows (no `sandbox` field) are uncontained, not contained.
        let legacy: Record = serde_json::from_str(&format!(
            "{{\"task_id\":\"a/1\",\"category\":\"c\",\"oracle\":{OK_ORACLE}}}"
        ))
        .unwrap();
        assert_eq!(legacy.sandbox, None);
        assert_eq!(journal_containment_class(&[legacy]).unwrap(), "uncontained");
    }

    #[test]
    fn containment_note_labels_both_classes_and_never_confuses_them() {
        let contained = containment_note("contained");
        let uncontained = containment_note("uncontained");
        assert!(contained.contains("contained") && !contained.contains("UNCONTAINED"));
        assert!(
            uncontained.contains("UNCONTAINED"),
            "the uncontained label must be loud, got: {uncontained}"
        );
        assert_ne!(contained, uncontained);
    }

    #[test]
    fn family_of_a_frozen_task_is_the_whole_id() {
        // Generated ids are family/{seed}; frozen ids have no slash and are their
        // own family.
        let mut frozen = Record::synthetic("c", "x", 3, 1.0, true);
        frozen.task_id = "blake3:frozen-slice".to_string();
        assert_eq!(frozen.family(), "blake3:frozen-slice");
        assert_eq!(
            frozen.task_id.split('/').next().unwrap_or(&frozen.task_id),
            "blake3:frozen-slice",
            "no slash → whole id, not truncated at a colon"
        );
    }

    #[test]
    fn defaults_fill_for_old_journals() {
        // A line with no kind/epoch/index/segment/cost still parses with the
        // documented defaults (core / local / 0 / None / empty cost). The
        // OracleVector fields themselves are required even in old lines.
        let recs = parse_journal(&format!(
            "{{\"task_id\":\"a/1\",\"category\":\"c\",\"oracle\":{OK_ORACLE}}}"
        ))
        .unwrap();
        let r = &recs[0];
        assert_eq!(r.kind, "core");
        assert_eq!(r.epoch, "local");
        assert_eq!(r.index, 0);
        assert_eq!(r.segment, None);
        assert_eq!(r.segment_position, None);
        assert_eq!(r.cost, Cost::default());
    }

    #[test]
    fn mcnemar_statistic_is_continuity_corrected() {
        // d = (|10 - 0| - 1)^2 / 10 = 8.1; empty input → statistic 0.
        let lopsided: Vec<(bool, bool)> = (0..10).map(|_| (true, false)).collect();
        assert!((mcnemar(&lopsided).statistic - 8.1).abs() < 1e-9);
        assert_eq!(mcnemar(&[]).statistic, 0.0);
        assert_eq!(mcnemar(&[]).p_value, 1.0);
    }

    #[test]
    fn mcnemar_switches_to_normal_approx_for_large_n() {
        // Above EXACT_BINOM_MAX the tail goes normal; a balanced split stays
        // non-significant and a total sweep stays overwhelming.
        let balanced: Vec<(bool, bool)> = (0..2000)
            .map(|i| {
                if i % 2 == 0 {
                    (true, false)
                } else {
                    (false, true)
                }
            })
            .collect();
        let m = mcnemar(&balanced);
        assert_eq!((m.discordant_a_only, m.discordant_b_only), (1000, 1000));
        assert!(m.p_value > 0.99, "balanced large-n p = {}", m.p_value);

        let swept: Vec<(bool, bool)> = (0..2000).map(|_| (true, false)).collect();
        let m = mcnemar(&swept);
        assert!(m.p_value < 1e-6, "swept large-n p = {}", m.p_value);
    }

    #[test]
    fn sign_test_threshold_boundary_is_strict() {
        // 4 discordant, all core wins → p = 1/16 = 0.0625 exactly.
        let pairs: Vec<(bool, bool)> = (0..4).map(|_| (true, false)).collect();
        let s = sign_test(&pairs, 0.05);
        assert!((s.p_value - 0.0625).abs() < 1e-12);
        assert!(!s.flagged, "0.0625 >= 0.05 → not flagged");
        let s = sign_test(&pairs, 0.07);
        assert!(s.flagged, "0.0625 < 0.07 → flagged");
    }

    #[test]
    fn sign_test_concordant_only_has_no_evidence() {
        let pairs = vec![(true, true), (false, false), (true, true)];
        let s = sign_test(&pairs, DETECTOR_ALPHA);
        assert_eq!((s.core_wins, s.probe_wins), (0, 0));
        assert_eq!(s.p_value, 1.0);
        assert!(!s.flagged);
    }

    #[test]
    fn clamp_ci_intersects_the_feasible_range() {
        assert_eq!(clamp_ci((-0.5, 1.5), 0.0, 1.0), (0.0, 1.0));
        assert_eq!(clamp_ci((0.2, 0.4), 0.0, 1.0), (0.2, 0.4));
        assert_eq!(clamp_ci((-1.0, -0.5), 0.0, 1.0), (0.0, 0.0));
        // Delta CIs live in [-1, 1].
        assert_eq!(clamp_ci((0.5, 2.0), -1.0, 1.0), (0.5, 1.0));
    }

    #[test]
    fn studentized_ci_degenerate_and_normal_fallback() {
        // Zero SE → a zero-width interval at the point estimate.
        assert_eq!(studentized_ci(0.5, 0.0, vec![3.0], ALPHA), (0.5, 0.5));
        // Fewer than two informative replicates → the normal fallback.
        let (lo, hi) = studentized_ci(0.5, 0.1, vec![], ALPHA);
        assert!((lo - (0.5 - 1.959_964 * 0.1)).abs() < 1e-9);
        assert!((hi - (0.5 + 1.959_964 * 0.1)).abs() < 1e-9);
    }

    #[test]
    fn rng_is_deterministic_per_seed() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        let mut c = Rng::new(43);
        let sa: Vec<u64> = (0..8).map(|_| a.next_u64()).collect();
        let sb: Vec<u64> = (0..8).map(|_| b.next_u64()).collect();
        let sc: Vec<u64> = (0..8).map(|_| c.next_u64()).collect();
        assert_eq!(sa, sb, "same journal → same CI requires this");
        assert_ne!(sa[0], sc[0]);
        assert!(sa.windows(2).any(|w| w[0] != w[1]), "stream must advance");
    }

    #[test]
    fn design_effect_floor_and_values() {
        assert!((design_effect(2.0, 0.5) - 1.5).abs() < 1e-12);
        assert!(
            (design_effect(1.0, 0.9) - 1.0).abs() < 1e-12,
            "m=1 → no clustering penalty"
        );
        assert!((design_effect(10.0, 0.25) - 3.25).abs() < 1e-12);
        assert!(design_effect(5.0, 0.0) >= 1.0);
    }

    #[test]
    fn report_on_empty_journal_is_safe() {
        let r = report_with(&[], 100);
        assert_eq!(r.units, 0);
        assert!(r.categories.is_empty());
        assert!(r.capability_score.is_nan(), "no data → NaN, not a fake 0");
        assert!(r.capability_ci.0.is_nan());
        assert!(r.throughput.is_none());
        assert_eq!(
            r.simultaneous_k, 1,
            "k floors at 1 so Bonferroni never divides by zero"
        );
    }

    #[test]
    fn throughput_counts_grade_only_units_as_timed() {
        let line = format!(
            "{{\"task_id\":\"f/0\",\"category\":\"c\",\"kind\":\"core\",\"index\":0,\"epoch\":\"e\",\"cost\":{{\"completion_tokens\":10,\"gen_ms\":0,\"grade_ms\":500}},\"oracle\":{OK_ORACLE}}}"
        );
        let recs = parse_journal(&line).unwrap();
        let t = throughput(&recs).unwrap();
        assert_eq!(t.units, 1, "gen_ms=0 but grade_ms>0 is still timed");
        assert!((t.gen_s - 0.0).abs() < 1e-12);
        assert!((t.grade_s - 0.5).abs() < 1e-12);
        assert!(
            (t.decode_tok_per_s - 0.0).abs() < 1e-12,
            "no generate time → no decode rate"
        );
        assert!((t.grade_share - 1.0).abs() < 1e-12);
        assert!(
            (t.units_per_hour - 7200.0).abs() < 1e-9,
            "one unit per 0.5s = 7200/hour"
        );
    }

    #[test]
    fn detector_ignores_non_core_probe_kinds() {
        // An unknown kind at index 0 must not enter any slot; only the f1 pair counts.
        let recs = vec![
            Record::synthetic_unit("c", "fx", "e", "warmup", 0, 1.0, true),
            Record::synthetic_unit("c", "f1", "e", "core", 0, 1.0, true),
            Record::synthetic_unit("c", "f1", "e", "probe", 0, 0.5, false),
        ];
        let d = detect(&recs, DETECTOR_ALPHA);
        assert_eq!(d.len(), 1);
        assert_eq!(
            d[0].families_paired, 1,
            "the warmup-kind family has no pair"
        );
    }

    #[test]
    fn erf_matches_reference_values() {
        // Abramowitz–Stegun 7.1.26 variant used here: abs error ~1e-7 at x=1,
        // erf(0) is 1e-9 (not exact 0) from the rounded coefficients.
        assert!(erf(0.0).abs() < 5e-9);
        assert!((erf(1.0) - 0.842_700_8).abs() < 2e-7);
        assert!((erf(-1.0) + 0.842_700_8).abs() < 2e-7, "odd function");
        assert!((erf(3.0) - 1.0).abs() < 1e-4, "saturates");
    }

    // --- AQ-202/OI-36c: refused miri-mandatory rows ---

    /// An `unsafe-core` row in the shape the journal carries: score/pass as the
    /// oracle scored it *before* refusal, plus the recorded flags and compile
    /// gate outcome.
    fn miri_row(family: &str, index: u32, flags: &[&str], compile_ok: bool, pass: bool) -> Record {
        let mut r = Record::synthetic_unit(
            bench_core::MIRI_CATEGORY,
            family,
            "local",
            "core",
            index,
            if pass { 1.0 } else { 0.0 },
            pass,
        );
        r.oracle.compile_ok = compile_ok;
        r.oracle.flags = flags.iter().map(|f| f.to_string()).collect();
        r
    }

    #[test]
    fn unsafe_core_rows_without_a_miri_verdict_are_refused_and_counted() {
        // Old-journal shape: a compiled, "perfect" unsafe-core row with NO
        // miri flag at all. Pre-AQ-202 this scored as a clean pass — the
        // fail-open hole this test pins shut.
        let mut row = miri_row("raw-ptr-mut", 0, &[], true, true);
        assert!(row.passed(), "witness: the old shape did pass");
        let recs = vec![row.clone()];
        let r = report_with(&recs, 50);
        assert_eq!(r.miri_refused, 1, "refused and counted");
        assert_eq!(r.units, 0, "excluded from the scored set");

        // Every explicit gap flag refuses too.
        for flag in bench_core::MIRI_GAP_FLAGS {
            row.oracle.flags = vec![flag.to_string()];
            assert!(is_miri_refused(&row), "{flag} must refuse");
        }
    }

    #[test]
    fn a_recorded_miri_verdict_keeps_the_row_scoreable() {
        let clean = miri_row("raw-ptr-mut", 0, &[bench_core::MIRI_CLEAN_FLAG], true, true);
        assert!(clean.passed() && !is_miri_refused(&clean));
        let r = report_with(&[clean], 50);
        assert_eq!(r.miri_refused, 0);
        assert_eq!(r.units, 1);
        assert!(r.pass_rate > 0.999);

        // A UB verdict is a genuine failure — still scoreable, still counted.
        let ub = miri_row("raw-ptr-mut", 0, &[bench_core::MIRI_UB_FLAG], true, false);
        assert!(!is_miri_refused(&ub));
        let r = report_with(&[ub], 50);
        assert_eq!(r.miri_refused, 0);
        assert_eq!(r.units, 1);
    }

    #[test]
    fn compile_failed_unsafe_core_rows_stay_in_the_scored_set() {
        // A compile failure is a real 0 that can never pass; refusing it would
        // inflate the pass-rate denominator (fail-open in the other direction).
        let row = miri_row("raw-ptr-mut", 0, &[], false, false);
        assert!(!row.passed() && !is_miri_refused(&row));
        let r = report_with(&[row], 50);
        assert_eq!(r.miri_refused, 0);
        assert_eq!(r.units, 1);
    }

    #[test]
    fn compare_counts_refused_rows_on_each_side() {
        // r70 F-1: a refused row shrinks n_paired; the shrink must be reported.
        let clean = miri_row("raw-ptr-mut", 0, &[bench_core::MIRI_CLEAN_FLAG], true, true);
        let refused = miri_row(
            "raw-ptr-mut",
            1,
            &[bench_core::MIRI_UNAVAILABLE],
            true,
            true,
        );
        let a = vec![clean.clone(), refused];
        let b = vec![
            clean,
            miri_row("raw-ptr-mut", 1, &[bench_core::MIRI_CLEAN_FLAG], true, true),
        ];
        let cmp = compare_models_with(&a, &b, 50);
        assert_eq!(
            cmp.n_paired, 1,
            "the refused unit is dropped from the pairing"
        );
        assert_eq!(cmp.miri_refused_a, 1, "and counted on A's side");
        assert_eq!(cmp.miri_refused_b, 0);
        let cmp = compare_models_with(&b, &a, 50);
        assert_eq!((cmp.miri_refused_a, cmp.miri_refused_b), (0, 1));
    }

    #[test]
    fn non_miri_categories_are_never_refused() {
        let mut row = Record::synthetic("perf-grid", "grid-reduce", 0, 1.0, true);
        row.oracle.flags = vec![bench_core::MIRI_UNAVAILABLE.to_string()];
        assert!(!is_miri_refused(&row));
        let r = report_with(&[row], 50);
        assert_eq!(r.miri_refused, 0);
    }

    #[test]
    fn refused_rows_are_dropped_from_detect_and_compare() {
        let refused = miri_row("raw-ptr-mut", 0, &[], true, true);
        let clean_probe = miri_row("raw-ptr-mut", 0, &[bench_core::MIRI_CLEAN_FLAG], true, true);

        // detect: the refused core never pairs, so the family contributes nothing.
        let probe = Record::synthetic_unit("x", "f", "e", "probe", 0, 1.0, false);
        let mut refused_core =
            Record::synthetic_unit(bench_core::MIRI_CATEGORY, "f", "e", "core", 0, 1.0, true);
        refused_core.oracle.flags = vec![bench_core::MIRI_UNAVAILABLE.to_string()];
        let d = detect(&[refused_core, probe], DETECTOR_ALPHA);
        assert!(d.is_empty(), "a refused core must not pair with its probe");

        // compare: the refused row vanishes from both sides; n_paired shrinks.
        let other_a = Record::synthetic("x", "fa", 0, 1.0, true);
        let other_b = Record::synthetic("x", "fa", 0, 1.0, true);
        let cmp = compare_models_with(
            &[other_a.clone(), refused.clone()],
            &[other_b, clean_probe],
            50,
        );
        assert_eq!(cmp.n_paired, 1, "only the non-refused pair survives");
    }
}
