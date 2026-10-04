//! `bench-invariants` — the single source of truth for the published statistics,
//! and a CI gate that fails when a doc figure stops following from its formula.
//!
//! Round 6 (docs/REVIEW-6.md) asked for exactly this: *"one script that
//! recomputes every published table from its stated formulae and fails CI on a
//! hand-edited cell."* The same defect class recurred across three rounds —
//! R1-S1 (statistics tables arithmetically wrong), round 5's arithmetic block,
//! and R6-S1/R6-S7 (`standard` published two different CIs for one quantity).
//! Every one of them would have failed the test below.
//!
//! The formulae here are canonical. If the docs and this file disagree, one of
//! them is wrong — and the test says which cell.

/// Intra-class correlation assumed corpus-wide (docs/07). Provisional until
/// Phase 3.5 measures it; when that lands, change it here and the docs must
/// follow or the test fails.
pub const ICC: f64 = 0.3;

/// `design_effect = 1 + (seeds − 1)·ICC` (docs/07).
pub fn design_effect(seeds: u32, icc: f64) -> f64 {
    1.0 + (seeds as f64 - 1.0) * icc
}

/// 95% CI half-width in percentage points at the worst-case p = 0.5, on an
/// effective N: `1.96·√(0.25/N)·100` (docs/07). A conservative upper bound for
/// the continuous score.
pub fn ci_pct(eff_n: f64) -> f64 {
    1.96 * (0.25 / eff_n).sqrt() * 100.0
}

/// Effective N of one category: `families · seeds / design_effect`.
pub fn category_eff_n(families: u32, seeds: u32, icc: f64) -> f64 {
    families as f64 * seeds as f64 / design_effect(seeds, icc)
}

/// Overall CI as a **stratified equal-weight mean of category means**
/// (docs/07, the R5 correction): `Var = (1/k²)·Σ_c 0.25/eff_N_c`, then
/// `1.96·√Var·100`. NOT the pooled-unit CI — that was R6-S1.
pub fn overall_ci_pct(core_cats: u32, probe_cats: u32, core_eff: f64, probe_eff: f64) -> f64 {
    let k = (core_cats + probe_cats) as f64;
    let var =
        (core_cats as f64 * (0.25 / core_eff) + probe_cats as f64 * (0.25 / probe_eff)) / (k * k);
    1.96 * var.sqrt() * 100.0
}

/// The precision ceiling as seeds → ∞: `F / ICC` (docs/07, ADR-0008).
pub fn ceiling_eff_n(families_per_category: u32, icc: f64) -> f64 {
    families_per_category as f64 / icc
}

/// Canonical description of one suite.
pub struct Suite {
    pub name: &'static str,
    pub families: u32,
    pub core_cats: u32,
    pub probe_cats: u32,
    pub core_fam_per_cat: u32,
    pub probe_fam_per_cat: u32,
    pub seeds: u32,
    /// Extra un-scored probe units for the wall-clock (0 for `smoke`).
    pub probe_units: u32,
    /// Per-unit token-bound seconds at the 20 tok/s reference.
    pub token_bound_20: f64,
    /// Per-unit fixed seconds (build/grade, plus L4 where mandatory).
    pub fixed: f64,
}

impl Suite {
    pub fn scored_units(&self) -> u32 {
        self.families * self.seeds
    }
    pub fn pooled_eff_n(&self) -> f64 {
        self.scored_units() as f64 / design_effect(self.seeds, ICC)
    }
    pub fn core_cat_eff(&self) -> f64 {
        category_eff_n(self.core_fam_per_cat, self.seeds, ICC)
    }
    pub fn probe_cat_eff(&self) -> f64 {
        category_eff_n(self.probe_fam_per_cat, self.seeds, ICC)
    }
    pub fn overall_ci(&self) -> f64 {
        if self.core_cats + self.probe_cats == 0 {
            // `smoke` has no category structure — its CI is the pooled one.
            ci_pct(self.pooled_eff_n())
        } else {
            overall_ci_pct(
                self.core_cats,
                self.probe_cats,
                self.core_cat_eff(),
                self.probe_cat_eff(),
            )
        }
    }
    /// Wall-clock hours at a tok/s multiple of the 20 reference (`mult` = 1 → 20,
    /// 3 → 60). Fixed cost does not scale with throughput (docs/07 deep @60).
    pub fn wall_hours(&self, mult: f64) -> f64 {
        let per_unit = self.token_bound_20 / mult + self.fixed;
        let units = (self.scored_units() + self.probe_units) as f64;
        units * per_unit / 3600.0
    }
}

/// The canonical suites. Change a number here only when the design changes, and
/// the docs must move with it (or the test fails).
pub fn suites() -> Vec<Suite> {
    vec![
        Suite {
            name: "smoke",
            families: 60,
            core_cats: 0,
            probe_cats: 0,
            core_fam_per_cat: 40,
            probe_fam_per_cat: 12,
            seeds: 1,
            probe_units: 0,
            token_bound_20: 45.0, // single-shot: 45 token-bound + 10 fixed = 55s @20, 25s @60
            fixed: 10.0,
        },
        Suite {
            name: "standard",
            families: 208, // tier rule excludes 64 deep-only families (docs/04)
            core_cats: 4,
            probe_cats: 4,
            core_fam_per_cat: 40,
            probe_fam_per_cat: 12,
            seeds: 2,
            probe_units: 62,
            token_bound_20: 64.0,
            fixed: 24.0, // repair: build/grade over 2 attempts, no L4
        },
        Suite {
            name: "deep",
            families: 272,
            core_cats: 5,
            probe_cats: 6,
            core_fam_per_cat: 40,
            probe_fam_per_cat: 12,
            seeds: 4,
            probe_units: 163,
            token_bound_20: 64.0,
            fixed: 64.0, // repair + mandatory L4
        },
    ]
}

/// Canonical corpus split (docs/04, ADR-0008): 5 core × 40 + 6 probe × 12, of
/// which two probe categories are mined.
pub struct Corpus {
    pub total: u32,
    pub synthetic: u32,
    pub mined: u32,
}
pub fn corpus() -> Corpus {
    let core = 5 * 40;
    let probe_synth = 4 * 12;
    let probe_mined = 2 * 12;
    Corpus {
        total: core + probe_synth + probe_mined,
        synthetic: core + probe_synth,
        mined: probe_mined,
    }
}

#[cfg(test)]
mod checks {
    use super::*;

    fn doc(name: &str) -> String {
        let path = format!("{}/../../docs/{}", env!("CARGO_MANIFEST_DIR"), name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
    }

    /// The numeric value of a markdown table cell: keep digits and the decimal
    /// point, drop everything else (`±`, `~`, `**`, `%`, `h`, `+`).
    fn num(cell: &str) -> Option<f64> {
        let s: String = cell
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        s.parse().ok()
    }

    /// The `|`-split cells of the table row whose first backticked cell is `key`.
    fn row(md: &str, key: &str) -> Vec<String> {
        let needle = format!("| `{key}`");
        let line = md
            .lines()
            .find(|l| l.trim_start().starts_with(&needle))
            .unwrap_or_else(|| panic!("no `{key}` row found"));
        line.split('|').map(|c| c.trim().to_string()).collect()
    }

    fn approx(a: f64, b: f64, tol: f64, what: &str) {
        assert!(
            (a - b).abs() <= tol,
            "{what}: doc says {a}, formula gives {b:.4} (tol {tol})"
        );
    }

    #[test]
    fn corpus_split_arithmetic() {
        let c = corpus();
        assert_eq!(c.total, 272);
        assert_eq!(c.synthetic, 248);
        assert_eq!(c.mined, 24);
        assert_eq!(c.synthetic + c.mined, c.total);

        let d = doc("04-categories.md");
        assert!(
            d.contains("272 families — 248 synthetic, 24 mined"),
            "04 corpus split line does not match the canonical 272 / 248 / 24"
        );
    }

    #[test]
    fn suite_table_matches_formulae() {
        let md = doc("07-statistics.md");
        for s in suites() {
            let cells = row(&md, s.name);
            // Column layout (after the leading empty from the first `|`):
            // 1 name · 2 families · 3 seeds · 4 scored · 5 +probe · 6 mode ·
            // 7 eff N · 8 overall CI · 9 core-cat CI · 10 probe-cat CI ·
            // 11 @20 · 12 @60
            approx(
                num(&cells[2]).unwrap(),
                s.families as f64,
                0.0,
                &format!("{} families", s.name),
            );
            approx(
                num(&cells[3]).unwrap(),
                s.seeds as f64,
                0.0,
                &format!("{} seeds", s.name),
            );
            approx(
                num(&cells[4]).unwrap(),
                s.scored_units() as f64,
                0.0,
                &format!("{} scored units", s.name),
            );
            approx(
                num(&cells[7]).unwrap(),
                s.pooled_eff_n(),
                1.0,
                &format!("{} eff N", s.name),
            );
            approx(
                num(&cells[8]).unwrap(),
                s.overall_ci(),
                0.15,
                &format!("{} overall CI", s.name),
            );

            // Per-category CIs and probe units only exist for the scored suites.
            if s.core_cats > 0 {
                approx(
                    num(&cells[9]).unwrap(),
                    ci_pct(s.core_cat_eff()),
                    0.15,
                    &format!("{} core-cat CI", s.name),
                );
                approx(
                    num(&cells[10]).unwrap(),
                    ci_pct(s.probe_cat_eff()),
                    0.15,
                    &format!("{} probe-cat CI", s.name),
                );
                approx(
                    num(&cells[5]).unwrap(),
                    s.probe_units as f64,
                    0.0,
                    &format!("{} probe units", s.name),
                );
            }

            // Wall clock, @20 (mult 1) and @60 (mult 3). The cell may be in
            // hours or minutes ("~55 min" for smoke); scale to match.
            let wall_expected = |mult: f64, cell: &str| {
                let h = s.wall_hours(mult);
                if cell.contains("min") {
                    h * 60.0
                } else {
                    h
                }
            };
            approx(
                num(&cells[11]).unwrap(),
                wall_expected(1.0, &cells[11]),
                0.5,
                &format!("{} wall @20", s.name),
            );
            approx(
                num(&cells[12]).unwrap(),
                wall_expected(3.0, &cells[12]),
                0.5,
                &format!("{} wall @60", s.name),
            );
        }
    }

    #[test]
    fn deep_is_the_canonical_44_5_hours() {
        // The figure the whole resume/checkpointing story quotes. Pin it so a
        // stale "39h" cannot creep back (it did once).
        let deep = suites().into_iter().find(|s| s.name == "deep").unwrap();
        approx(deep.wall_hours(1.0), 44.5, 0.3, "deep @20 headline");
        assert!(
            !doc("09-resume-and-checkpointing.md").contains("39 hour"),
            "09 still references a stale 39-hour deep suite"
        );
    }

    #[test]
    fn ceiling_table_matches_f_over_icc() {
        // ADR-0008 / 07: at 40 families, ICC 0.3, ceiling ±8.5%.
        approx(
            ci_pct(ceiling_eff_n(40, 0.3)),
            8.5,
            0.15,
            "ceiling 40 fam @ICC 0.3",
        );
        // At 20 families the radar was unbuildable: ±12.0%.
        approx(
            ci_pct(ceiling_eff_n(20, 0.3)),
            12.0,
            0.15,
            "ceiling 20 fam @ICC 0.3",
        );
    }

    // ---- pure formulae (no docs read) ----

    #[test]
    fn icc_pin_is_the_documented_value() {
        // docs/07 provisional ICC; an accidental bump here invalidates every
        // published eff-N and CI at once.
        assert_eq!(ICC, 0.3);
    }

    #[test]
    fn design_effect_is_one_for_a_single_seed() {
        assert_eq!(design_effect(1, 0.3), 1.0);
        assert_eq!(design_effect(1, 0.0), 1.0);
    }

    #[test]
    fn design_effect_grows_linearly_in_seeds() {
        approx(design_effect(2, 0.3), 1.3, 1e-12, "de @2 seeds");
        approx(design_effect(4, 0.3), 1.9, 1e-12, "de @4 seeds");
        // Perfect clustering (ICC 1) collapses eff N to a single draw.
        assert_eq!(design_effect(10, 1.0), 10.0);
        // No clustering (ICC 0) is the i.i.d. baseline.
        assert_eq!(design_effect(10, 0.0), 1.0);
    }

    #[test]
    fn ci_pct_matches_hand_computation_and_shrinks_with_n() {
        approx(ci_pct(100.0), 9.8, 1e-9, "ci at eff N 100");
        assert!(ci_pct(400.0) < ci_pct(100.0));
        // Doubling eff N divides the half-width by √2.
        approx(
            ci_pct(200.0),
            ci_pct(100.0) / 2f64.sqrt(),
            1e-9,
            "sqrt-2 law",
        );
    }

    #[test]
    fn category_eff_n_divides_by_design_effect() {
        // 40 families × 4 seeds, ICC 0.3 → 160 / 1.9.
        approx(category_eff_n(40, 4, 0.3), 160.0 / 1.9, 1e-9, "cat eff N");
        assert_eq!(category_eff_n(40, 1, 0.3), 40.0);
    }

    #[test]
    fn overall_ci_is_the_stratified_mean_not_the_pool() {
        // With EQUAL eff N per category the stratified mean and the naive pool
        // coincide, so divergence only shows on unequal strata (the R6-S1
        // defect): the stratified form must weight each category's variance by
        // 1/k², not collapse to one pooled 0.25/N.
        let e_core = 100.0_f64;
        let e_probe = 400.0_f64;
        let k = 4.0_f64;
        let var: f64 = (2.0 * (0.25 / e_core) + 2.0 * (0.25 / e_probe)) / (k * k);
        let expected = 1.96 * var.sqrt() * 100.0;
        approx(
            overall_ci_pct(2, 2, e_core, e_probe),
            expected,
            1e-9,
            "stratified hand computation",
        );
        // The pooled shortcut at the summed eff N understates the width.
        let pooled = ci_pct(2.0 * e_core + 2.0 * e_probe);
        assert!(
            overall_ci_pct(2, 2, e_core, e_probe) > pooled,
            "stratified CI must exceed the naive pooled CI on unequal strata"
        );
    }

    #[test]
    fn ceiling_eff_n_is_families_over_icc() {
        approx(ceiling_eff_n(40, 0.3), 40.0 / 0.3, 1e-9, "ceiling");
    }

    #[test]
    fn smoke_has_no_category_structure_so_uses_the_pooled_ci() {
        let smoke = suites().into_iter().find(|s| s.name == "smoke").unwrap();
        assert_eq!(smoke.core_cats + smoke.probe_cats, 0);
        approx(
            smoke.overall_ci(),
            ci_pct(smoke.pooled_eff_n()),
            1e-12,
            "smoke pooled CI",
        );
    }

    #[test]
    fn standard_is_deep_minus_the_deep_only_tier() {
        let s = suites();
        let deep = s.iter().find(|x| x.name == "deep").unwrap().families;
        let standard = s.iter().find(|x| x.name == "standard").unwrap().families;
        assert_eq!(deep - standard, 64); // docs/04 tier rule
    }

    #[test]
    fn fixed_cost_does_not_scale_with_throughput() {
        // wall_hours(mult) = units·tb/(mult·3600) + units·fixed/3600 — so the
        // infinite-throughput limit isolates the fixed term exactly.
        for s in suites() {
            let units = (s.scored_units() + s.probe_units) as f64;
            let fixed_only = units * s.fixed / 3600.0;
            approx(
                s.wall_hours(f64::INFINITY),
                fixed_only,
                1e-12,
                &format!("{} fixed floor", s.name),
            );
        }
    }

    #[test]
    fn wall_hours_scale_linearly_in_units_at_fixed_mult() {
        let mut deep2 = suites().into_iter().find(|s| s.name == "deep").unwrap();
        deep2.families *= 2;
        deep2.probe_units *= 2;
        let base = suites().into_iter().find(|s| s.name == "deep").unwrap();
        approx(
            deep2.wall_hours(1.0),
            2.0 * base.wall_hours(1.0),
            1e-9,
            "linear in units",
        );
    }

    #[test]
    fn scored_units_are_families_times_seeds() {
        for s in suites() {
            assert_eq!(s.scored_units(), s.families * s.seeds);
        }
    }

    #[test]
    fn cell_parser_keeps_only_digits_and_dots() {
        assert_eq!(num("±8.5%"), Some(8.5));
        assert_eq!(num("~55 min"), Some(55.0));
        assert_eq!(num("**44.5 h**"), Some(44.5));
        assert_eq!(num("no digits here"), None);
        assert_eq!(num(""), None);
    }
}
