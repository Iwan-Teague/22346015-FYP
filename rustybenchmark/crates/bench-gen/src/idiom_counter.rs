//! The `idiom-counter` family (category `idiom-refactor`) — the second
//! idiom-refactor family.
//!
//! Same *de-idiomatisation* move as `idiom-loop`, a different lint: the model is
//! given a working function written around an **explicit running counter**
//! (`let mut i = 0; for &x in xs { … i += 1; }`) and must rewrite it in
//! idiomatic iterator style, preserving behaviour exactly. The given code is
//! behaviourally correct and *only clippy distinguishes it*
//! (`clippy::explicit_counter_loop`). Measured in a scratch crate (Q14):
//! `explicit_counter_loop` is **MaybeIncorrect**, so its suggestion does not
//! survive `cargo clippy --fix` — the counter loop survives unchanged, unlike
//! e.g. `manual_flatten` (machine-applicable, auto-fixed, rejected as a family).
//! Constraint-dominant per docs/04 `idiom-refactor` weights
//! behavior 0.30 / constraint 0.60 / quality 0.10.
//!
//! Seed-selected on two axes, which together define the weighted sum:
//!
//! 1. **Weight** — how index contributes: Linear (`i+1`, forward position),
//!    Reverse (`n-i`, distance from the end), Parity (`±1` alternating).
//! 2. **Map** — how each element is transformed before weighting:
//!    Identity / Double / Square / Negate.
//!
//! The idiomatic answer folds to an iterator chain —
//! `xs.iter()[.rev()].enumerate().map(|…| weight * mapped).sum()` (Reverse via
//! `.rev().enumerate()`, so the *reversed* position is the weight; Parity via an
//! `if i % 2` inside the closure). 3 × 4 = **12 distinct skills**; the function
//! name is cosmetic and there are no numeric constants — both excluded from
//! `spec_signature`.
//!
//! All three idiomatic references are clippy-clean under `-D warnings`
//! (verified in a scratch crate before authoring), and all three de-idiomatised
//! skeletons fire exactly one lint class — the running counter.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Axis 1 — how the element's index contributes to the sum.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Weight {
    /// Position from the front: `i + 1`.
    Linear,
    /// Distance from the end: `n - i`.
    Reverse,
    /// Alternating sign: `+1` at even indices, `-1` at odd.
    Parity,
}

/// Axis 2 — how each element is transformed before being weighted.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Map {
    Identity,
    Double,
    Square,
    Negate,
}

struct Spec {
    weight: Weight,
    map: Map,
    fn_name: &'static str,
}

const NAMES: &[&str] = &[
    "weighted_sum",
    "score",
    "tally",
    "accumulate",
    "fold_weights",
    "measure",
];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let weight = match rng.below(3) {
        0 => Weight::Linear,
        1 => Weight::Reverse,
        _ => Weight::Parity,
    };
    let map = match rng.below(4) {
        0 => Map::Identity,
        1 => Map::Double,
        2 => Map::Square,
        _ => Map::Negate,
    };
    let fn_name = NAMES[rng.below(NAMES.len() as u64) as usize];
    Spec {
        weight,
        map,
        fn_name,
    }
}

// ---- native reference (mirrors the emitted sources exactly) ---------------

/// The weight of the element at index `i` in a slice of length `len`.
fn weight_val(weight: Weight, i: usize, len: usize) -> i64 {
    match weight {
        Weight::Linear => i as i64 + 1,
        Weight::Reverse => len as i64 - i as i64,
        Weight::Parity => {
            if i.is_multiple_of(2) {
                1
            } else {
                -1
            }
        }
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

/// The answer: sum `weight(i) * map(xs[i])`. Source of truth for both emitted
/// renderings. A `while` loop keeps our own generator clippy-clean.
fn eval(spec: &Spec, xs: &[i64]) -> i64 {
    let mut total = 0i64;
    let mut i = 0usize;
    while i < xs.len() {
        total += weight_val(spec.weight, i, xs.len()) * map_val(spec.map, xs[i]);
        i += 1;
    }
    total
}

// ---- shared emitted-source fragments --------------------------------------

/// The per-element map as source over an operand expression (`x` inside the
/// closures, `xs[i]` never needed here — the counter loop carries `x` directly).
fn map_expr(map: Map, op: &str) -> Option<String> {
    match map {
        Map::Identity => None,
        Map::Double => Some(format!("{op} * 2")),
        Map::Square => Some(format!("{op} * {op}")),
        Map::Negate => Some(format!("-{op}")),
    }
}

/// The map as an always-present expression.
fn map_expr_always(map: Map, op: &str) -> String {
    map_expr(map, op).unwrap_or_else(|| op.to_string())
}

// ---- the idiomatic reference (the answer) ---------------------------------

fn reference_src(spec: &Spec) -> String {
    match spec.weight {
        // Forward position: plain `enumerate`.
        Weight::Linear => {
            let m = map_expr_always(spec.map, "x");
            format!(
                "pub fn {name}(xs: &[i64]) -> i64 {{\n\
                 \x20   xs\n\
                 \x20       .iter()\n\
                 \x20       .copied()\n\
                 \x20       .enumerate()\n\
                 \x20       .map(|(i, x)| (i as i64 + 1) * {m})\n\
                 \x20       .sum()\n\
                 }}\n",
                name = spec.fn_name,
                m = m,
            )
        }
        // Distance from the end: walk backwards so the *reversed* position IS
        // the weight — no length arithmetic at all.
        Weight::Reverse => {
            let m = map_expr_always(spec.map, "x");
            format!(
                "pub fn {name}(xs: &[i64]) -> i64 {{\n\
                 \x20   xs\n\
                 \x20       .iter()\n\
                 \x20       .rev()\n\
                 \x20       .enumerate()\n\
                 \x20       .map(|(r, &x)| (r as i64 + 1) * {m})\n\
                 \x20       .sum()\n\
                 }}\n",
                name = spec.fn_name,
                m = m,
            )
        }
        // Alternating sign: fold it into the closure.
        Weight::Parity => {
            let m = map_expr_always(spec.map, "x");
            format!(
                "pub fn {name}(xs: &[i64]) -> i64 {{\n\
                 \x20   xs\n\
                 \x20       .iter()\n\
                 \x20       .enumerate()\n\
                 \x20       .map(|(i, &x)| {{\n\
                 \x20           let w: i64 = if i % 2 == 0 {{ 1 }} else {{ -1 }};\n\
                 \x20           w * {m}\n\
                 \x20       }})\n\
                 \x20       .sum()\n\
                 }}\n",
                name = spec.fn_name,
                m = m,
            )
        }
    }
}

// ---- the de-idiomatised skeleton (what the model is given) ----------------

/// The non-idiomatic running-counter loop. Behaviourally correct but trips
/// `clippy::explicit_counter_loop`, whose suggestion is MaybeIncorrect and so
/// survives `cargo clippy --fix` unchanged (Q14, measured).
fn deidiom_src(spec: &Spec) -> String {
    let m = map_expr_always(spec.map, "x");
    let head = match spec.weight {
        Weight::Linear => String::new(),
        Weight::Reverse => "    let n = xs.len() as i64;\n".to_string(),
        Weight::Parity => String::new(),
    };
    let step = match spec.weight {
        Weight::Linear => format!("total += (i as i64 + 1) * {m};"),
        Weight::Reverse => format!("total += (n - i as i64) * {m};"),
        Weight::Parity => {
            format!("let w: i64 = if i % 2 == 0 {{ 1 }} else {{ -1 }};\n        total += w * {m};")
        }
    };
    format!(
        "pub fn {name}(xs: &[i64]) -> i64 {{\n\
         \x20   let mut total = 0;\n\
         {head}\
         \x20   let mut i = 0usize;\n\
         \x20   for &x in xs {{\n\
         \x20       {step}\n\
         \x20       i += 1;\n\
         \x20   }}\n\
         \x20   total\n\
         }}\n",
        name = spec.fn_name,
        head = head,
        step = step,
    )
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    // The model's starting file IS the working non-idiomatic function (plus the
    // worked examples as a doc comment). It fails on clippy, not behaviour.
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
    let mut rng = Rng::new(seed ^ 0x1D20_0000_0000_0067);
    let mut inputs: Vec<Vec<i64>> = vec![vec![3, 1, 4, 2]];
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
         non-idiomatic, imperative style built around a manually incremented index\n\
         counter. Rewrite it in **idiomatic Rust** — iterator adaptors rather than a\n\
         running counter — so that it is `clippy`-clean, while preserving its exact\n\
         behaviour and its signature.\n\
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

/// The differential's reference — an enumerate-based plain loop (in a test file,
/// so never clippy'd), mirroring `eval`.
fn differential_test_src(spec: &Spec) -> String {
    let m = map_expr_always(spec.map, "x");
    let w = match spec.weight {
        Weight::Linear => "(i as i64 + 1)".to_string(),
        Weight::Reverse => "(xs.len() as i64 - i as i64)".to_string(),
        Weight::Parity => "(if i % 2 == 0 { 1 } else { -1 })".to_string(),
    };
    format!(
        "use task::{name};\n\
         \n\
         fn reference(xs: &[i64]) -> i64 {{\n\
         \x20   let mut total = 0i64;\n\
         \x20   for (i, &x) in xs.iter().enumerate() {{\n\
         \x20       total += {w} * {m};\n\
         \x20   }}\n\
         \x20   total\n\
         }}\n\
         \n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0x1D20_ED00_0000_0043;\n\
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
        w = w,
        m = m,
    )
}

/// The "lazy copy-paste" baseline: the unchanged running-counter loop.
/// Behaviourally correct, so it fails only on clippy.
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

pub struct IdiomCounterFamily;

impl Generator for IdiomCounterFamily {
    fn id(&self) -> &str {
        "idiom-counter"
    }
    fn category(&self) -> &str {
        "idiom-refactor"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("idiom-counter", seed);

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
            id: format!("idiom-counter/{seed:016x}"),
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
            // Load-bearing baseline: returning the code unchanged is behaviourally
            // correct but not idiomatic — caught by clippy, not behaviour.
            ("unchanged".to_string(), unchanged(&spec)),
            ("const-zero".to_string(), const_zero(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        let weight = match spec.weight {
            Weight::Linear => "linear",
            Weight::Reverse => "reverse",
            Weight::Parity => "parity",
        };
        let map = match spec.map {
            Map::Identity => "identity",
            Map::Double => "double",
            Map::Square => "square",
            Map::Negate => "negate",
        };
        vec![format!("weight:{weight}"), format!("map:{map}")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = IdiomCounterFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn eval_matches_intent() {
        let mk = |weight, map| Spec {
            weight,
            map,
            fn_name: "f",
        };
        // Linear + Double: 1*(1*2) + 2*(2*2) + 3*(3*2) = 28.
        assert_eq!(eval(&mk(Weight::Linear, Map::Double), &[1, 2, 3]), 28);
        // Reverse + Identity: 3*1 + 2*2 + 1*3 = 10.
        assert_eq!(eval(&mk(Weight::Reverse, Map::Identity), &[1, 2, 3]), 10);
        // Parity + Square: 1*1 - 1*4 + 1*9 = 6.
        assert_eq!(eval(&mk(Weight::Parity, Map::Square), &[1, 2, 3]), 6);
        // Linear + Negate: 1*(-1) + 2*(-2) = -5.
        assert_eq!(eval(&mk(Weight::Linear, Map::Negate), &[1, 2]), -5);
    }

    #[test]
    fn seeds_vary_weight_and_map() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..300u64 {
            let s = sample(seed);
            variants.insert(format!("{:?}/{:?}", s.weight, s.map));
        }
        assert!(
            variants.len() >= 10,
            "expected wide structural variety, got {}",
            variants.len()
        );
    }

    #[test]
    fn canonical_result_is_nonzero() {
        // The const-zero baseline is caught on every seed only if the canonical
        // [3,1,4,2] evaluates to a non-zero answer under every (weight, map) combo.
        let canonical = [3i64, 1, 4, 2];
        for &weight in &[Weight::Linear, Weight::Reverse, Weight::Parity] {
            for &map in &[Map::Identity, Map::Double, Map::Square, Map::Negate] {
                let spec = Spec {
                    weight,
                    map,
                    fn_name: "f",
                };
                assert_ne!(
                    eval(&spec, &canonical),
                    0,
                    "canonical is zero under {weight:?}/{map:?}"
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
    fn skeleton_has_a_running_counter() {
        // The de-idiomatised skeleton must contain the explicit-counter shape that
        // trips clippy::explicit_counter_loop (the whole task). A structural check
        // here; the clippy oracle confirms it end-to-end in validate-family.
        for weight in [Weight::Linear, Weight::Reverse, Weight::Parity] {
            let s = deidiom_src(&Spec {
                weight,
                map: Map::Double,
                fn_name: "f",
            });
            assert!(s.contains("for &x in xs"), "not an element loop: {s}");
            assert!(s.contains("let mut i"), "no declared counter: {s}");
            assert!(s.contains("i += 1;"), "counter never incremented: {s}");
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = IdiomCounterFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
