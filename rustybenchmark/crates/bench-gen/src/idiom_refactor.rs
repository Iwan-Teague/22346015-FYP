//! The `idiom-loop` family (category `idiom-refactor`).
//!
//! The one *compositional* family: instead of ablating a reference to `todo!()`,
//! it **de-idiomatises** it. The model is given a working but non-idiomatic
//! function — an explicit `for i in 0..xs.len()` index loop — and must rewrite it
//! in idiomatic, clippy-clean iterator style, preserving behaviour exactly. So the
//! ablation is quality, not correctness: the given code is behaviourally correct
//! and *only clippy distinguishes it* (docs/03: "non-idiomatic code compiles;
//! clippy catches all of it"). This is why the family needs the L3 clippy oracle
//! (built in the previous increment) and why it is **constraint-dominant** — docs/04
//! weights `idiom-refactor` behavior 0.30 / constraint 0.60 / quality 0.10.
//!
//! Seed-selected on two axes, which together define the loop body:
//!
//! 1. **Filter** — which elements contribute: All / Positive / Even / Nonzero.
//! 2. **Map** — how each contributing element is transformed before summing:
//!    Identity / Double / Square / Negate.
//!
//! The whole thing folds to a sum, so the idiomatic form is a
//! `xs.iter().copied()[.filter(…)][.map(…)].sum()` chain. 4 × 4 = **16 distinct
//! skills**; the function name is cosmetic and there are no numeric constants — both
//! excluded from `spec_signature`.
//!
//! **Q14 (the `clippy --fix` trap).** `idiom-refactor` is only meaningful if the
//! task is not trivially auto-solvable. Measured: `cargo clippy --fix` does **not**
//! rewrite `needless_range_loop` (its suggestion is not machine-applicable), so the
//! index loop survives `--fix` unchanged — the model must actually reason about the
//! rewrite. And all 16 idiomatic references are clippy-clean (verified), so the
//! reference scores 1.000 while the unchanged index loop scores ~0.33.
//!
//! Correct-by-construction (ADR-0003): native `eval`, the emitted idiomatic
//! reference, and the de-idiomatised skeleton are three renderings of the same
//! filter/map/sum, sharing the `pred_expr`/`map_expr` fragments; the differential
//! fuzzes 3000 slices (values ∈ -50..=50, len 0..20, so no overflow).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Axis 1 — which elements contribute to the sum.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Filter {
    All,
    Positive,
    Even,
    Nonzero,
}

/// Axis 2 — how each contributing element is transformed before summing.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Map {
    Identity,
    Double,
    Square,
    Negate,
}

struct Spec {
    filter: Filter,
    map: Map,
    fn_name: &'static str,
}

const NAMES: &[&str] = &[
    "compute",
    "total",
    "aggregate",
    "reduce_xs",
    "tally",
    "fold_slice",
];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let filter = match rng.below(4) {
        0 => Filter::All,
        1 => Filter::Positive,
        2 => Filter::Even,
        _ => Filter::Nonzero,
    };
    let map = match rng.below(4) {
        0 => Map::Identity,
        1 => Map::Double,
        2 => Map::Square,
        _ => Map::Negate,
    };
    let fn_name = NAMES[rng.below(NAMES.len() as u64) as usize];
    Spec {
        filter,
        map,
        fn_name,
    }
}

// ---- native reference (mirrors the emitted sources exactly) ---------------

fn keep(filter: Filter, x: i64) -> bool {
    match filter {
        Filter::All => true,
        Filter::Positive => x > 0,
        Filter::Even => x % 2 == 0,
        Filter::Nonzero => x != 0,
    }
}

fn map_val(map: Map, x: i64) -> i64 {
    match map {
        Map::Identity => x,
        Map::Double => x * 2,
        Map::Square => x * x,
        Map::Negate => -x,
    }
}

/// The answer: sum `map(x)` over the elements that pass `filter`. Source of truth
/// for both emitted renderings.
fn eval(spec: &Spec, xs: &[i64]) -> i64 {
    let mut total = 0i64;
    for &x in xs {
        if keep(spec.filter, x) {
            total += map_val(spec.map, x);
        }
    }
    total
}

// ---- shared emitted-source fragments --------------------------------------

/// The filter predicate as source over an operand expression (`x` in the iterator
/// chain, `xs[i]` in the index loop). `None` for `All` (no predicate).
fn pred_expr(filter: Filter, op: &str) -> Option<String> {
    match filter {
        Filter::All => None,
        Filter::Positive => Some(format!("{op} > 0")),
        Filter::Even => Some(format!("{op} % 2 == 0")),
        Filter::Nonzero => Some(format!("{op} != 0")),
    }
}

/// The per-element map as source over an operand expression. `None` for `Identity`
/// (no `.map(…)` in the chain).
fn map_expr(map: Map, op: &str) -> Option<String> {
    match map {
        Map::Identity => None,
        Map::Double => Some(format!("{op} * 2")),
        Map::Square => Some(format!("{op} * {op}")),
        Map::Negate => Some(format!("-{op}")),
    }
}

/// The map as an always-present expression (used inside the loop body, where the
/// element is always added).
fn map_expr_always(map: Map, op: &str) -> String {
    map_expr(map, op).unwrap_or_else(|| op.to_string())
}

// ---- the idiomatic reference (the answer) ---------------------------------

fn reference_src(spec: &Spec) -> String {
    let mut chain = String::from("xs.iter().copied()");
    if let Some(p) = pred_expr(spec.filter, "x") {
        chain.push_str(&format!(".filter(|&x| {p})"));
    }
    if let Some(m) = map_expr(spec.map, "x") {
        chain.push_str(&format!(".map(|x| {m})"));
    }
    chain.push_str(".sum()");
    format!(
        "pub fn {name}(xs: &[i64]) -> i64 {{\n\
         \x20   {chain}\n\
         }}\n",
        name = spec.fn_name,
        chain = chain,
    )
}

// ---- the de-idiomatised skeleton (what the model is given) ----------------

/// The non-idiomatic index loop. It is behaviourally correct but trips
/// `clippy::needless_range_loop` (the `for i in 0..xs.len()` + `xs[i]` shape),
/// which `cargo clippy --fix` will not mechanically rewrite (Q14).
fn deidiom_src(spec: &Spec) -> String {
    let body = match pred_expr(spec.filter, "xs[i]") {
        Some(p) => format!(
            "if {p} {{\n\
             \x20           total += {m};\n\
             \x20       }}",
            m = map_expr_always(spec.map, "xs[i]"),
        ),
        None => format!("total += {m};", m = map_expr_always(spec.map, "xs[i]")),
    };
    format!(
        "pub fn {name}(xs: &[i64]) -> i64 {{\n\
         \x20   let mut total = 0;\n\
         \x20   for i in 0..xs.len() {{\n\
         \x20       {body}\n\
         \x20   }}\n\
         \x20   total\n\
         }}\n",
        name = spec.fn_name,
        body = body,
    )
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    // The model's starting file IS the working non-idiomatic function (plus the
    // worked examples as a doc comment). The task is to rewrite it, so unlike the
    // other families the skeleton is behaviourally complete — it fails on clippy,
    // not on behaviour.
    let examples = worked_examples_prose(spec, seed);
    let doc = examples
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "//! Rewrite `{name}` below in idiomatic, clippy-clean Rust, preserving its\n\
         //! exact behaviour.\n\
         //!\n\
         {doc}\n\
         {deidiom}",
        name = spec.fn_name,
        doc = doc,
        deidiom = deidiom_src(spec),
    )
}

// ---- worked examples ------------------------------------------------------

type ExampleCase = (Vec<i64>, i64);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0x1D10_0000_0000_0037);
    let mut inputs: Vec<Vec<i64>> = vec![vec![1, 2, 3, 4]];
    for _ in 0..3 {
        let len = 2 + rng.below(7) as usize; // 2..=8
        let input: Vec<i64> = (0..len).map(|_| rng.below(21) as i64 - 10).collect(); // -10..=10
        inputs.push(input);
    }
    inputs
        .into_iter()
        .map(|input| {
            let out = eval(spec, &input);
            (input, out)
        })
        .collect()
}

fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for (input, out) in worked_examples(spec, seed) {
        s.push_str(&format!("  {input:?}  ->  {out}\n"));
    }
    s
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    format!(
        "The function `{name}` in `src/lib.rs` works but is written in a\n\
         non-idiomatic, imperative style. Rewrite it in **idiomatic Rust** — iterator\n\
         adaptors rather than an index loop — so that it is `clippy`-clean, while\n\
         preserving its exact behaviour and its signature.\n\
         \n\
         Here is the current implementation:\n\
         \n\
         ```rust\n\
         {current}\n\
         ```\n\
         \n\
         It computes the same value for these inputs, which your rewrite must match:\n\
         {examples}\n\
         Constraints:\n\
         - Keep the signature `pub fn {name}(xs: &[i64]) -> i64` exactly.\n\
         - The rewrite must produce **no** `clippy` warnings.\n\
         - Do not use `unsafe`.\n\
         \n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        name = spec.fn_name,
        current = deidiom_src(spec).trim_end(),
        examples = worked_examples_prose(spec, seed),
    )
}

fn cargo_toml() -> String {
    "[package]\n\
     name = \"task\"\n\
     version = \"0.0.0\"\n\
     edition = \"2021\"\n\
     \n\
     [lib]\n\
     path = \"src/lib.rs\"\n\
     \n\
     [workspace]\n"
        .to_string()
}

fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let mut body = format!("use task::{};\n\n", spec.fn_name);
    for (i, (input, out)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   let xs: Vec<i64> = vec!{input:?};\n\
             \x20   assert_eq!({name}(&xs), {out});\n\
             }}\n\n",
            name = spec.fn_name,
        ));
    }
    body.push_str(&format!(
        "#[test]\nfn empty_is_zero() {{\n\
         \x20   assert_eq!({name}(&[]), 0);\n\
         }}\n",
        name = spec.fn_name,
    ));
    body
}

/// The differential's reference — a plain loop (in a test file, so never clippy'd),
/// mirroring `eval`.
fn differential_test_src(spec: &Spec) -> String {
    let body = match pred_expr(spec.filter, "x") {
        Some(p) => format!(
            "if {p} {{ total += {m}; }}",
            m = map_expr_always(spec.map, "x")
        ),
        None => format!("total += {m};", m = map_expr_always(spec.map, "x")),
    };
    format!(
        "use task::{name};\n\
         \n\
         fn reference(xs: &[i64]) -> i64 {{\n\
         \x20   let mut total = 0i64;\n\
         \x20   for &x in xs {{\n\
         \x20       {body}\n\
         \x20   }}\n\
         \x20   total\n\
         }}\n\
         \n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0x1D10_ED00_0000_0042;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       (state >> 33) as u64\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let len = (next() % 20) as usize;\n\
         \x20       let xs: Vec<i64> = (0..len).map(|_| (next() % 101) as i64 - 50).collect();\n\
         \x20       assert_eq!({name}(&xs), reference(&xs), \"mismatch: {{xs:?}}\");\n\
         \x20   }}\n\
         }}\n",
        name = spec.fn_name,
        body = body,
    )
}

/// The "lazy copy-paste" baseline: the unchanged non-idiomatic loop. Behaviourally
/// correct, so it fails only on clippy — which is exactly the point of the family.
fn unchanged(spec: &Spec) -> String {
    deidiom_src(spec)
}

/// A behaviourally-wrong baseline: returns 0 regardless.
fn const_zero(spec: &Spec) -> String {
    format!(
        "pub fn {name}(xs: &[i64]) -> i64 {{ let _ = xs; 0 }}\n",
        name = spec.fn_name,
    )
}

pub struct IdiomRefactorFamily;

impl Generator for IdiomRefactorFamily {
    fn id(&self) -> &str {
        "idiom-loop"
    }
    fn category(&self) -> &str {
        "idiom-refactor"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("idiom-loop", seed);

        let mut files = BTreeMap::new();
        files.insert(PathBuf::from("Cargo.toml"), cargo_toml());
        // The model's starting file is the non-idiomatic function (it rewrites it).
        files.insert(PathBuf::from("src/lib.rs"), skeleton_src(&spec, seed));

        let mut hidden = BTreeMap::new();
        hidden.insert(
            PathBuf::from("tests/behavior.rs"),
            behavior_test_src(&spec, seed),
        );
        hidden.insert(
            PathBuf::from("tests/differential.rs"),
            differential_test_src(&spec),
        );

        GeneratedTask {
            id: format!("idiom-loop/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // `unsafe` is irrelevant here; opting the check out keeps the L3
            // constraint layer purely clippy (the idiomaticity signal).
            max_unsafe: None,
            forbidden_paths: Vec::new(),
            check_clippy: true,
            clippy_allow: Vec::new(),
            // docs/04 idiom-refactor weights: the task *is* the constraint (clippy).
            weights: (0.30, 0.60, 0.10),
        }
    }

    fn reference_code(&self, seed: u64) -> String {
        reference_src(&sample(seed))
    }
    fn skeleton_code(&self, seed: u64) -> String {
        skeleton_src(&sample(seed), seed)
    }
    fn trivial_baselines(&self, seed: u64) -> Vec<(String, String)> {
        let spec = sample(seed);
        vec![
            // The load-bearing baseline: returning the code unchanged is
            // behaviourally correct but not idiomatic — caught by clippy, not behaviour.
            ("unchanged".to_string(), unchanged(&spec)),
            ("const-zero".to_string(), const_zero(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        let filter = match spec.filter {
            Filter::All => "all",
            Filter::Positive => "positive",
            Filter::Even => "even",
            Filter::Nonzero => "nonzero",
        };
        let map = match spec.map {
            Map::Identity => "identity",
            Map::Double => "double",
            Map::Square => "square",
            Map::Negate => "negate",
        };
        vec![format!("filter:{filter}"), format!("map:{map}")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = IdiomRefactorFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn eval_matches_intent() {
        let mk = |filter, map| Spec {
            filter,
            map,
            fn_name: "f",
        };
        // Positive + Identity: sum of positives in [1,-2,3] = 4.
        assert_eq!(eval(&mk(Filter::Positive, Map::Identity), &[1, -2, 3]), 4);
        // Even + Square: 2^2 + 4^2 = 20.
        assert_eq!(eval(&mk(Filter::Even, Map::Square), &[2, 3, 4]), 20);
        // All + Negate: -(1+2+3) = -6.
        assert_eq!(eval(&mk(Filter::All, Map::Negate), &[1, 2, 3]), -6);
        // Nonzero + Double: (1+3)*2 with the 0 skipped = 8.
        assert_eq!(eval(&mk(Filter::Nonzero, Map::Double), &[1, 0, 3]), 8);
    }

    #[test]
    fn seeds_vary_filter_and_map() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..300u64 {
            let s = sample(seed);
            variants.insert(format!("{:?}/{:?}", s.filter, s.map));
        }
        assert!(
            variants.len() >= 14,
            "expected wide structural variety, got {}",
            variants.len()
        );
    }

    #[test]
    fn canonical_result_is_nonzero() {
        // The const-zero baseline is caught on every seed only if the canonical
        // [1,2,3,4] evaluates to a non-zero answer under every (filter, map) combo.
        let canonical = [1i64, 2, 3, 4];
        for &filter in &[Filter::All, Filter::Positive, Filter::Even, Filter::Nonzero] {
            for &map in &[Map::Identity, Map::Double, Map::Square, Map::Negate] {
                let spec = Spec {
                    filter,
                    map,
                    fn_name: "f",
                };
                assert_ne!(
                    eval(&spec, &canonical),
                    0,
                    "canonical is zero under {filter:?}/{map:?}"
                );
            }
        }
    }

    #[test]
    fn reference_matches_native_eval() {
        // The idiomatic reference is a rendering of eval; the worked examples pin
        // agreement (the 3000-input differential is the exhaustive version).
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (input, out) in worked_examples(&spec, seed) {
                assert_eq!(eval(&spec, &input), out, "seed {seed}");
            }
        }
    }

    #[test]
    fn skeleton_is_a_needless_range_loop() {
        // The de-idiomatised skeleton must contain the index-loop shape that trips
        // clippy::needless_range_loop (the whole task). A structural check here; the
        // clippy oracle confirms it end-to-end in validate-family.
        let s = deidiom_src(&sample(0));
        assert!(s.contains("for i in 0..xs.len()"), "not an index loop: {s}");
        assert!(s.contains("xs[i]"), "does not index xs: {s}");
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = IdiomRefactorFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
