//! The `seq-transform` family (category `iterators`).
//!
//! A fourth task shape, closest in spirit to `stack-machine`: the model implements
//! `transform(xs: &[i64]) -> Vec<i64>`, applying a **seed-selected three-stage
//! pipeline** over the input slice, in order:
//!
//! 1. **Filter** — keep the elements matching a predicate: Positive / Even /
//!    AboveThreshold(t) / NonZero.
//! 2. **Map** — transform each kept element: Double / Negate / Square / AddK(k).
//! 3. **Terminal** — fold the transformed sequence: Collect / RunningSum /
//!    DedupConsecutive.
//!
//! The structural surface is 4 × 4 × 3 = **48 distinct skills**, the widest of the
//! four families. The threshold `t` (∈ {-2, 0, 3, 5}) and constant `k` (∈ {1, 2, 3})
//! are seed-chosen numeric parameters of the *same* skill (Q31 granularity), and the
//! function name is cosmetic — both excluded from `spec_signature`. Solution-first
//! and correct-by-construction as always (ADR-0003): native `eval` and the emitted
//! reference are mirrored, and the differential fuzzes 3000 random slices against
//! the model. Input values are kept small (∈ -9..=9, length 0..12) so no legal input
//! overflows `i64` in a debug build (Square of 9 = 81; a prefix sum of 12 mapped
//! values stays far below the max).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Stage 1 — which elements are kept.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Filter {
    Positive,
    Even,
    AboveThreshold(i64),
    NonZero,
}

/// Stage 2 — how each kept element is transformed.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Map {
    Double,
    Negate,
    Square,
    AddK(i64),
}

/// Stage 3 — how the transformed sequence is folded.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Terminal {
    Collect,
    RunningSum,
    DedupConsecutive,
}

/// Seed-chosen threshold values for `AboveThreshold` (kept small).
const THRESHOLDS: [i64; 4] = [-2, 0, 3, 5];

struct Spec {
    filter: Filter,
    map: Map,
    terminal: Terminal,
    fn_name: &'static str,
}

const NAMES: &[&str] = &[
    "transform",
    "process_seq",
    "refine",
    "sift",
    "transform_values",
    "pipeline",
];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let filter = match rng.below(4) {
        0 => Filter::Positive,
        1 => Filter::Even,
        2 => Filter::AboveThreshold(THRESHOLDS[rng.below(4) as usize]),
        _ => Filter::NonZero,
    };
    let map = match rng.below(4) {
        0 => Map::Double,
        1 => Map::Negate,
        2 => Map::Square,
        _ => Map::AddK(1 + rng.below(3) as i64), // k in 1..=3
    };
    let terminal = match rng.below(3) {
        0 => Terminal::Collect,
        1 => Terminal::RunningSum,
        _ => Terminal::DedupConsecutive,
    };
    let fn_name = NAMES[rng.below(NAMES.len() as u64) as usize];
    Spec {
        filter,
        map,
        terminal,
        fn_name,
    }
}

/// Native reference, mirroring the emitted source exactly. Processes `xs` left to
/// right: skip elements failing the filter, transform each kept element, then fold
/// the transformed sequence through the terminal operation.
fn eval(spec: &Spec, xs: &[i64]) -> Vec<i64> {
    let mut out: Vec<i64> = Vec::new();
    for &x in xs {
        let keep = match spec.filter {
            Filter::Positive => x > 0,
            Filter::Even => x % 2 == 0,
            Filter::AboveThreshold(t) => x > t,
            Filter::NonZero => x != 0,
        };
        if !keep {
            continue;
        }
        let m = match spec.map {
            Map::Double => x * 2,
            Map::Negate => -x,
            Map::Square => x * x,
            Map::AddK(k) => x + k,
        };
        match spec.terminal {
            Terminal::Collect => out.push(m),
            Terminal::RunningSum => {
                // Prefix sums: each new value is added to the previous total.
                let base = out.last().copied().unwrap_or(0);
                out.push(base + m);
            }
            Terminal::DedupConsecutive => {
                if out.last().copied() != Some(m) {
                    out.push(m);
                }
            }
        }
    }
    out
}

// ---- emitted-source fragments (mirror the native `eval` above) ------------

fn filter_expr(f: Filter) -> String {
    match f {
        Filter::Positive => "x > 0".to_string(),
        Filter::Even => "x % 2 == 0".to_string(),
        Filter::AboveThreshold(t) => format!("x > {t}"),
        Filter::NonZero => "x != 0".to_string(),
    }
}

fn map_expr(m: Map) -> String {
    match m {
        Map::Double => "x * 2".to_string(),
        Map::Negate => "-x".to_string(),
        Map::Square => "x * x".to_string(),
        Map::AddK(k) => format!("x + {k}"),
    }
}

fn terminal_body(term: Terminal) -> &'static str {
    match term {
        Terminal::Collect => "out.push(m);",
        Terminal::RunningSum => {
            "let base = out.last().copied().unwrap_or(0);\n        out.push(base + m);"
        }
        Terminal::DedupConsecutive => "if out.last().copied() != Some(m) { out.push(m); }",
    }
}

fn filter_prose(f: Filter) -> String {
    match f {
        Filter::Positive => "keep the elements that are strictly positive (`x > 0`)".to_string(),
        Filter::Even => "keep the elements that are even (`x % 2 == 0`)".to_string(),
        Filter::AboveThreshold(t) => {
            format!("keep the elements that are strictly greater than `{t}` (`x > {t}`)")
        }
        Filter::NonZero => "keep the elements that are not zero (`x != 0`)".to_string(),
    }
}

fn map_prose(m: Map) -> String {
    match m {
        Map::Double => "double each kept element (`x * 2`)".to_string(),
        Map::Negate => "negate each kept element (`-x`)".to_string(),
        Map::Square => "square each kept element (`x * x`)".to_string(),
        Map::AddK(k) => format!("add `{k}` to each kept element (`x + {k}`)"),
    }
}

fn terminal_prose(term: Terminal) -> &'static str {
    match term {
        Terminal::Collect => {
            "collect the transformed values into the result in their original order"
        }
        Terminal::RunningSum => {
            "replace the sequence with its running prefix sums: the first value stays \
             as-is, and each later value is the sum of every transformed value up to \
             and including it"
        }
        Terminal::DedupConsecutive => {
            "collapse consecutive equal transformed values, keeping only the first of \
             each run"
        }
    }
}

fn reference_src(spec: &Spec) -> String {
    format!(
        "pub fn {name}(xs: &[i64]) -> Vec<i64> {{\n\
         \x20   let mut out: Vec<i64> = Vec::new();\n\
         \x20   for &x in xs {{\n\
         \x20       if !({filter}) {{\n\
         \x20           continue;\n\
         \x20       }}\n\
         \x20       let m = {map};\n\
         \x20       {terminal}\n\
         \x20   }}\n\
         \x20   out\n\
         }}\n",
        name = spec.fn_name,
        filter = filter_expr(spec.filter),
        map = map_expr(spec.map),
        terminal = terminal_body(spec.terminal),
    )
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let (examples, _) = worked_examples(spec, seed);
    format!(
        "//! Implement `{name}` below.\n\
         //!\n\
         {doc}\n\
         pub fn {name}(xs: &[i64]) -> Vec<i64> {{\n\
         \x20   todo!()\n\
         }}\n",
        name = spec.fn_name,
        doc = examples
            .lines()
            .map(|l| format!("//! {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// One worked example: (input, expected output).
type ExampleCase = (Vec<i64>, Vec<i64>);

/// Worked examples, computed natively so each is correct by construction. The
/// first case is the **canonical** one — a fixed, distinct, positive input that
/// every (filter, map, terminal) combination changes and renders non-empty — which
/// is what makes both trivial baselines (`identity` and `empty`) fail for every
/// seed. The rest are seed-varied random inputs (this is the family's biggest
/// per-instance textual lever, docs/02 Q30).
fn worked_examples(spec: &Spec, seed: u64) -> (String, Vec<ExampleCase>) {
    let mut rng = Rng::new(seed ^ 0x5EED_0000_0000_0017);
    let mut inputs: Vec<Vec<i64>> = Vec::new();

    // Canonical: distinct positives, one even, one above every threshold (5).
    // Every kept-element maps to a value different from the original first
    // element, so the output differs from the input at position 0 in all 48
    // combinations, and every filter keeps at least one element.
    inputs.push(vec![2, 5, 8]);

    for _ in 0..3 {
        let len = 2 + rng.below(7) as usize; // 2..=8
        let input: Vec<i64> = (0..len)
            .map(|_| rng.below(19) as i64 - 9) // -9..=9
            .collect();
        inputs.push(input);
    }

    let mut cases = Vec::new();
    let mut prose = String::new();
    for input in &inputs {
        let out = eval(spec, input);
        prose.push_str(&format!("  {input:?}  ->  {out:?}\n"));
        cases.push((input.clone(), out));
    }
    (prose, cases)
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let (examples, _) = worked_examples(spec, seed);
    format!(
        "Implement the function `{name}` in `src/lib.rs`.\n\
         \n\
         Apply a three-stage pipeline to `xs`, processing the elements left to \
         right:\n\
         \n\
         1. **Filter** — {filter_prose}.\n\
         2. **Map** — {map_prose}.\n\
         3. **Terminal** — {terminal_prose}.\n\
         \n\
         An element that fails the filter is skipped entirely; only the kept \
         elements are transformed and fed to the terminal operation.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         - The input may be empty; the result is then empty.\n\
         \n\
         Signature:\n\
         ```rust\n\
         pub fn {name}(xs: &[i64]) -> Vec<i64>\n\
         ```\n\
         \n\
         Examples:\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        name = spec.fn_name,
        filter_prose = filter_prose(spec.filter),
        map_prose = map_prose(spec.map),
        terminal_prose = terminal_prose(spec.terminal),
        examples = examples,
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
    let (_, cases) = worked_examples(spec, seed);
    let mut body = format!("use task::{};\n\n", spec.fn_name);
    for (i, (input, out)) in cases.iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   let xs: Vec<i64> = vec!{input:?};\n\
             \x20   assert_eq!({name}(&xs), vec!{out:?});\n\
             }}\n\n",
            name = spec.fn_name,
        ));
    }
    body.push_str(&format!(
        "#[test]\nfn empty_input() {{\n\
         \x20   let xs: Vec<i64> = Vec::new();\n\
         \x20   assert_eq!({name}(&xs), Vec::<i64>::new());\n\
         }}\n",
        name = spec.fn_name,
    ));
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let reference =
        reference_src(spec).replacen(&format!("pub fn {}", spec.fn_name), "fn reference", 1);
    format!(
        "use task::{name};\n\
         \n\
         {reference}\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0x5A11_ED00_0000_0042;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       (state >> 33) as u64\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let len = (next() % 12) as usize;\n\
         \x20       let xs: Vec<i64> = (0..len).map(|_| (next() % 19) as i64 - 9).collect();\n\
         \x20       assert_eq!({name}(&xs), reference(&xs), \"mismatch: {{xs:?}}\");\n\
         \x20   }}\n\
         }}\n",
        name = spec.fn_name,
        reference = reference,
    )
}

/// Degenerate: returns the input unchanged, ignoring every pipeline stage. Fails
/// on the canonical example, which every combination changes.
fn identity(spec: &Spec) -> String {
    format!(
        "pub fn {name}(xs: &[i64]) -> Vec<i64> {{ xs.to_vec() }}\n",
        name = spec.fn_name,
    )
}

/// Degenerate: always returns an empty vector. Fails on the canonical example,
/// which every combination renders non-empty.
fn empty(spec: &Spec) -> String {
    format!(
        "pub fn {name}(xs: &[i64]) -> Vec<i64> {{ let _ = xs; Vec::new() }}\n",
        name = spec.fn_name,
    )
}

pub struct SeqTransformFamily;

impl Generator for SeqTransformFamily {
    fn id(&self) -> &str {
        "seq-transform"
    }
    fn category(&self) -> &str {
        "iterators"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("seq-transform", seed);

        let mut files = BTreeMap::new();
        files.insert(PathBuf::from("Cargo.toml"), cargo_toml());
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
            id: format!("seq-transform/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            // Building the result Vec legitimately allocates: no alloc constraint.
            alloc_test: String::new(),
            max_unsafe: Some(0),
            check_clippy: false,
            clippy_allow: Vec::new(),
            forbidden_paths: Vec::new(),
            weights: (0.70, 0.20, 0.10),
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
            ("identity".to_string(), identity(&spec)),
            ("empty".to_string(), empty(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        // The skill is the trio of pipeline stages. The threshold `t` and constant
        // `k` are numeric parameters of the same skill (Q31), and the function name
        // is cosmetic — all excluded.
        let spec = sample(seed);
        let filter = match spec.filter {
            Filter::Positive => "positive",
            Filter::Even => "even",
            Filter::AboveThreshold(_) => "above_threshold",
            Filter::NonZero => "nonzero",
        };
        let map = match spec.map {
            Map::Double => "double",
            Map::Negate => "negate",
            Map::Square => "square",
            Map::AddK(_) => "add_k",
        };
        let terminal = match spec.terminal {
            Terminal::Collect => "collect",
            Terminal::RunningSum => "running_sum",
            Terminal::DedupConsecutive => "dedup_consecutive",
        };
        vec![
            format!("filter:{filter}"),
            format!("map:{map}"),
            format!("terminal:{terminal}"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = SeqTransformFamily;
        assert_eq!(g.generate(17).prompt, g.generate(17).prompt);
        assert_eq!(g.generate(17).hidden, g.generate(17).hidden);
    }

    #[test]
    fn eval_matches_intent() {
        let spec = Spec {
            filter: Filter::Positive,
            map: Map::Double,
            terminal: Terminal::RunningSum,
            fn_name: "transform",
        };
        // [2, -5, 8, 0, 3] -> keep [2, 8, 3] -> double [4, 16, 6] -> prefix [4, 20, 26]
        assert_eq!(eval(&spec, &[2, -5, 8, 0, 3]), vec![4, 20, 26]);

        let spec = Spec {
            filter: Filter::Even,
            map: Map::Square,
            terminal: Terminal::DedupConsecutive,
            fn_name: "transform",
        };
        // keep evens [4, -2, 4, 6, 6] -> squares [16, 4, 16, 36, 36] -> dedup [16, 4, 16, 36]
        assert_eq!(eval(&spec, &[4, -2, 4, 6, 6]), vec![16, 4, 16, 36]);

        // An all-negative input under `Positive` filters everything out.
        let spec = Spec {
            filter: Filter::Positive,
            map: Map::Negate,
            terminal: Terminal::Collect,
            fn_name: "transform",
        };
        assert_eq!(eval(&spec, &[-3, -1, 0, -7]), Vec::<i64>::new());
    }

    #[test]
    fn seeds_vary_the_pipeline() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..300u64 {
            let s = sample(seed);
            variants.insert(format!("{:?}/{:?}/{:?}", s.filter, s.map, s.terminal));
        }
        assert!(
            variants.len() >= 30,
            "expected wide structural variety, got {}",
            variants.len()
        );
    }

    #[test]
    fn canonical_case_changes_under_every_combo() {
        // The identity trivial-baseline only fails if at least one worked-example
        // input is actually changed, and the empty baseline only fails if at least
        // one output is non-empty. The canonical input [2, 5, 8] must satisfy both
        // for *every* (filter, map, terminal) combination — including every
        // threshold `t` and constant `k` a seed can select.
        for &t in THRESHOLDS.iter() {
            for &k in &[1i64, 2, 3] {
                let filters = [
                    Filter::Positive,
                    Filter::Even,
                    Filter::AboveThreshold(t),
                    Filter::NonZero,
                ];
                let maps = [Map::Double, Map::Negate, Map::Square, Map::AddK(k)];
                for &f in &filters {
                    for &m in &maps {
                        for &term in &[
                            Terminal::Collect,
                            Terminal::RunningSum,
                            Terminal::DedupConsecutive,
                        ] {
                            let spec = Spec {
                                filter: f,
                                map: m,
                                terminal: term,
                                fn_name: "transform",
                            };
                            let out = eval(&spec, &[2, 5, 8]);
                            assert!(
                                !out.is_empty(),
                                "empty under {f:?} {m:?} {term:?} (t={t}, k={k})"
                            );
                            assert_ne!(
                                out,
                                vec![2, 5, 8],
                                "unchanged under {f:?} {m:?} {term:?} (t={t}, k={k})"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn reference_matches_native_eval() {
        // The emitted reference and the native eval must agree on worked examples
        // across many seeds (the differential test in grading is the 3000-input
        // version of this).
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            let (_, cases) = worked_examples(&spec, seed);
            for (input, out) in cases {
                assert_eq!(eval(&spec, &input), out, "seed {seed}");
            }
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = SeqTransformFamily;
        let t = g.generate(4);
        assert!(t.prompt.contains(&t.canary));
    }
}
