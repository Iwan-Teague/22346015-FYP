//! The `trait-impl` family (category `traits-generics`).
//!
//! A task shape whose *distinctive* skill is implementing a **trait with an
//! associated type** for a provided type, consumed by a **generic driver with a
//! where-bound**. The interface is pinned in the skeleton (like `error-handling`
//! pins its enum): the trait `Aggregate`, the generic function
//! `fn driver<A: Aggregate<Item = i64>>(agg: &A, xs: &[i64]) -> i64`, and a unit
//! struct are all given; the model writes the `impl Aggregate for … { type Item =
//! i64; … }` block. Getting the associated type or a method signature wrong makes
//! the driver's `A: Aggregate<Item = i64>` bound unsatisfiable, so the hidden
//! tests fail to build and the answer scores zero — which is exactly the
//! "L1 + signature match" emphasis docs/04 assigns this category.
//!
//! The reduction the model must implement is seed-selected on two axes:
//!
//! 1. **Keep** — which elements are folded: Positive / Even / NonNegative / Odd.
//! 2. **Reduce** — how kept elements combine: Sum / Product / Count / SumOfSquares
//!    / SumOfAbs (each with its identity).
//!
//! The structural surface is 4 × 5 = **20 distinct skills**. Solution-first and
//! correct-by-construction (ADR-0003): the native `eval` and the emitted `impl`
//! are mirrored, and the differential fuzzes 3000 random slices against the
//! driver. Input values are kept small (∈ -9..=9, length 0..12) so no legal input
//! overflows `i64` in a debug build — the tightest case is `Product` over eleven
//! `9`s (9¹¹ ≈ 3.1e10, far below `i64::MAX`).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Axis 1 — which elements are folded.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Keep {
    Positive,
    Even,
    NonNegative,
    Odd,
}

/// Axis 2 — how kept elements combine (with an identity element).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Reduce {
    Sum,
    Product,
    Count,
    SumOfSquares,
    SumOfAbs,
}

struct Spec {
    keep: Keep,
    reduce: Reduce,
    /// The aggregator struct's name — cosmetic, seed-varied for prompt freshness.
    struct_name: &'static str,
    /// The generic driver function's name — cosmetic, seed-varied.
    driver_name: &'static str,
}

/// Cosmetic struct names (PascalCase, never the trait name `Aggregate`).
const STRUCT_NAMES: &[&str] = &["Agg", "Reducer", "Folder", "Tally", "Collector", "Combiner"];
/// Cosmetic driver names (never a trait method name: keep/identity/combine).
const DRIVER_NAMES: &[&str] = &[
    "aggregate",
    "run_fold",
    "reduce_slice",
    "fold_all",
    "drive",
    "apply",
];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let keep = match rng.below(4) {
        0 => Keep::Positive,
        1 => Keep::Even,
        2 => Keep::NonNegative,
        _ => Keep::Odd,
    };
    let reduce = match rng.below(5) {
        0 => Reduce::Sum,
        1 => Reduce::Product,
        2 => Reduce::Count,
        3 => Reduce::SumOfSquares,
        _ => Reduce::SumOfAbs,
    };
    let struct_name = STRUCT_NAMES[rng.below(STRUCT_NAMES.len() as u64) as usize];
    let driver_name = DRIVER_NAMES[rng.below(DRIVER_NAMES.len() as u64) as usize];
    Spec {
        keep,
        reduce,
        struct_name,
        driver_name,
    }
}

// ---- native reference (mirrors the emitted impl + driver exactly) ---------

fn kept(keep: Keep, x: i64) -> bool {
    match keep {
        Keep::Positive => x > 0,
        Keep::Even => x % 2 == 0,
        Keep::NonNegative => x >= 0,
        Keep::Odd => x % 2 != 0,
    }
}

fn identity_val(reduce: Reduce) -> i64 {
    match reduce {
        Reduce::Product => 1,
        _ => 0,
    }
}

fn step(reduce: Reduce, acc: i64, x: i64) -> i64 {
    match reduce {
        Reduce::Sum => acc + x,
        Reduce::Product => acc * x,
        Reduce::Count => acc + 1,
        Reduce::SumOfSquares => acc + x * x,
        Reduce::SumOfAbs => acc + x.abs(),
    }
}

/// The answer: fold every kept element left to right from the identity. This is
/// the source of truth the emitted `impl` + driver must reproduce.
fn eval(spec: &Spec, xs: &[i64]) -> i64 {
    let mut acc = identity_val(spec.reduce);
    for &x in xs {
        if kept(spec.keep, x) {
            acc = step(spec.reduce, acc, x);
        }
    }
    acc
}

// ---- emitted-source fragments (mirror the native functions above) ---------

/// The keep predicate as source, over a given operand expression (`*item` inside
/// the trait method where `item: &Self::Item`, `x` inside the free reference).
fn keep_expr(keep: Keep, operand: &str) -> String {
    match keep {
        Keep::Positive => format!("{operand} > 0"),
        Keep::Even => format!("{operand} % 2 == 0"),
        Keep::NonNegative => format!("{operand} >= 0"),
        Keep::Odd => format!("{operand} % 2 != 0"),
    }
}

fn identity_expr(reduce: Reduce) -> &'static str {
    match reduce {
        Reduce::Product => "1",
        _ => "0",
    }
}

/// The combine step as source, over a value operand (`item` in the trait method,
/// `x` in the free reference).
fn combine_expr(reduce: Reduce, operand: &str) -> String {
    match reduce {
        Reduce::Sum => format!("acc + {operand}"),
        Reduce::Product => format!("acc * {operand}"),
        Reduce::Count => "acc + 1".to_string(),
        Reduce::SumOfSquares => format!("acc + {operand} * {operand}"),
        Reduce::SumOfAbs => format!("acc + {operand}.abs()"),
    }
}

fn keep_prose(keep: Keep) -> &'static str {
    match keep {
        Keep::Positive => "strictly positive (`x > 0`)",
        Keep::Even => "even (`x % 2 == 0`)",
        Keep::NonNegative => "non-negative (`x >= 0`)",
        Keep::Odd => "odd (`x % 2 != 0`)",
    }
}

fn reduce_prose(reduce: Reduce) -> &'static str {
    match reduce {
        Reduce::Sum => "their sum (identity `0`)",
        Reduce::Product => "their product (identity `1`)",
        Reduce::Count => "the count of kept elements (identity `0`)",
        Reduce::SumOfSquares => "the sum of their squares (identity `0`)",
        Reduce::SumOfAbs => "the sum of their absolute values (identity `0`)",
    }
}

/// The pinned trait — the "provided interface" the model must keep.
const TRAIT_SRC: &str = "pub trait Aggregate {\n\
     \x20   /// The element type consumed from the slice.\n\
     \x20   type Item;\n\
     \x20   /// Keep this element in the fold?\n\
     \x20   fn keep(&self, item: &Self::Item) -> bool;\n\
     \x20   /// The accumulator's starting value.\n\
     \x20   fn identity(&self) -> i64;\n\
     \x20   /// Fold one kept element into the accumulator.\n\
     \x20   fn combine(&self, acc: i64, item: Self::Item) -> i64;\n\
     }\n";

/// The pinned generic driver (name seed-varied). Provided; the model keeps it.
fn driver_src(spec: &Spec) -> String {
    format!(
        "/// Fold `xs` through `agg`: start at `identity`, then `combine` every kept\n\
         /// element left to right. (Provided — keep it as-is.)\n\
         pub fn {driver}<A: Aggregate<Item = i64>>(agg: &A, xs: &[i64]) -> i64 {{\n\
         \x20   let mut acc = agg.identity();\n\
         \x20   for &x in xs {{\n\
         \x20       if agg.keep(&x) {{\n\
         \x20           acc = agg.combine(acc, x);\n\
         \x20       }}\n\
         \x20   }}\n\
         \x20   acc\n\
         }}\n",
        driver = spec.driver_name,
    )
}

/// The trait `impl` the model must write — the ablated part of the skeleton.
/// `Count` ignores `item`, so its `combine` binds `_ = item` to stay warning-free.
fn impl_src(spec: &Spec) -> String {
    let combine_body = match spec.reduce {
        Reduce::Count => "let _ = item;\n        acc + 1".to_string(),
        r => combine_expr(r, "item"),
    };
    format!(
        "impl Aggregate for {name} {{\n\
         \x20   type Item = i64;\n\
         \x20   fn keep(&self, item: &Self::Item) -> bool {{\n\
         \x20       {keep}\n\
         \x20   }}\n\
         \x20   fn identity(&self) -> i64 {{\n\
         \x20       {identity}\n\
         \x20   }}\n\
         \x20   fn combine(&self, acc: i64, item: Self::Item) -> i64 {{\n\
         \x20       {combine}\n\
         \x20   }}\n\
         }}\n",
        name = spec.struct_name,
        keep = keep_expr(spec.keep, "*item"),
        identity = identity_expr(spec.reduce),
        combine = combine_body,
    )
}

fn reference_src(spec: &Spec) -> String {
    format!(
        "{trait_src}\n\
         {driver}\n\
         /// The aggregator to implement `Aggregate` for.\n\
         pub struct {name};\n\
         \n\
         {impl_src}",
        trait_src = TRAIT_SRC,
        driver = driver_src(spec),
        name = spec.struct_name,
        impl_src = impl_src(spec),
    )
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let (examples, _) = worked_examples(spec, seed);
    format!(
        "//! Implement `Aggregate` for `{name}` below (fill in the three method\n\
         //! bodies). The trait and the `{driver_name}` driver are provided — keep them.\n\
         //!\n\
         {doc}\n\
         {trait_src}\n\
         {driver_body}\n\
         /// The aggregator to implement `Aggregate` for.\n\
         pub struct {name};\n\
         \n\
         impl Aggregate for {name} {{\n\
         \x20   type Item = i64;\n\
         \x20   fn keep(&self, item: &Self::Item) -> bool {{\n\
         \x20       todo!()\n\
         \x20   }}\n\
         \x20   fn identity(&self) -> i64 {{\n\
         \x20       todo!()\n\
         \x20   }}\n\
         \x20   fn combine(&self, acc: i64, item: Self::Item) -> i64 {{\n\
         \x20       todo!()\n\
         \x20   }}\n\
         }}\n",
        name = spec.struct_name,
        driver_name = spec.driver_name,
        trait_src = TRAIT_SRC,
        driver_body = driver_src(spec),
        doc = examples
            .lines()
            .map(|l| format!("//! {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// One worked example: (input, expected scalar).
type ExampleCase = (Vec<i64>, i64);

/// Worked examples, computed natively so each is correct by construction. The
/// first case is the **canonical** one — the fixed input `[2, 3, 4, 5]`, whose
/// answer is provably never `0` or `1` under any (keep, reduce) combination and
/// under which every keep predicate keeps at least two elements. That is what
/// makes both trivial baselines (`const-zero`, `const-one`) fail for every seed.
/// The rest are seed-varied random inputs — the family's biggest per-instance
/// textual lever (docs/02 Q30, appears in both prompt and skeleton doc).
fn worked_examples(spec: &Spec, seed: u64) -> (String, Vec<ExampleCase>) {
    let mut rng = Rng::new(seed ^ 0x7A17_0000_0000_0011);
    let mut inputs: Vec<Vec<i64>> = Vec::new();

    // Canonical: two evens, two odds, all positive — see doc comment above.
    inputs.push(vec![2, 3, 4, 5]);

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
        prose.push_str(&format!("  {input:?}  ->  {out}\n"));
        cases.push((input.clone(), out));
    }
    (prose, cases)
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let (examples, _) = worked_examples(spec, seed);
    format!(
        "Implement the `Aggregate` trait for the `{name}` struct in `src/lib.rs`. \
         The trait and the generic `{driver}` driver are already provided; keep \
         them unchanged and fill in the three method bodies of the `impl`.\n\
         \n\
         `{driver}` folds a slice by starting from `identity()`, then calling \
         `combine(acc, x)` for every element `x` that `keep(&x)` returns true for, \
         left to right. Implement the three methods so that the aggregation keeps \
         the elements that are {keep_prose} and reduces them to {reduce_prose}.\n\
         \n\
         So `keep` returns whether an element is kept, `identity` returns the \
         starting accumulator, and `combine` folds one kept element into the \
         accumulator. An empty slice (or one where nothing is kept) yields the \
         identity.\n\
         \n\
         Constraints:\n\
         - Keep the associated type as `type Item = i64;` and keep every method \
         signature exactly as given.\n\
         - Do not use `unsafe`.\n\
         \n\
         Provided interface (in `src/lib.rs`):\n\
         ```rust\n\
         pub trait Aggregate {{\n\
         \x20   type Item;\n\
         \x20   fn keep(&self, item: &Self::Item) -> bool;\n\
         \x20   fn identity(&self) -> i64;\n\
         \x20   fn combine(&self, acc: i64, item: Self::Item) -> i64;\n\
         }}\n\
         pub fn {driver}<A: Aggregate<Item = i64>>(agg: &A, xs: &[i64]) -> i64;\n\
         pub struct {name};\n\
         ```\n\
         \n\
         Examples (`{driver}(&{name}, xs)`):\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        name = spec.struct_name,
        driver = spec.driver_name,
        keep_prose = keep_prose(spec.keep),
        reduce_prose = reduce_prose(spec.reduce),
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
    let mut body = format!(
        "use task::{{{}, {}}};\n\n",
        spec.struct_name, spec.driver_name
    );
    for (i, (input, out)) in cases.iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   let xs: Vec<i64> = vec!{input:?};\n\
             \x20   assert_eq!({driver}(&{name}, &xs), {out});\n\
             }}\n\n",
            driver = spec.driver_name,
            name = spec.struct_name,
        ));
    }
    body.push_str(&format!(
        "#[test]\nfn empty_input() {{\n\
         \x20   let xs: Vec<i64> = Vec::new();\n\
         \x20   assert_eq!({driver}(&{name}, &xs), {identity});\n\
         }}\n",
        driver = spec.driver_name,
        name = spec.struct_name,
        identity = identity_val(spec.reduce),
    ));
    body
}

fn differential_test_src(spec: &Spec) -> String {
    // A free reference mirroring `eval`; `x: i64` in the loop, so operands are `x`.
    let reference = format!(
        "fn reference(xs: &[i64]) -> i64 {{\n\
         \x20   let mut acc: i64 = {identity};\n\
         \x20   for &x in xs {{\n\
         \x20       if {keep} {{\n\
         \x20           acc = {combine};\n\
         \x20       }}\n\
         \x20   }}\n\
         \x20   acc\n\
         }}\n",
        identity = identity_expr(spec.reduce),
        keep = keep_expr(spec.keep, "x"),
        combine = combine_expr(spec.reduce, "x"),
    );
    format!(
        "use task::{{{name}, {driver}}};\n\
         \n\
         {reference}\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0x7A17_ED00_0000_0042;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       (state >> 33) as u64\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let len = (next() % 12) as usize;\n\
         \x20       let xs: Vec<i64> = (0..len).map(|_| (next() % 19) as i64 - 9).collect();\n\
         \x20       assert_eq!({driver}(&{name}, &xs), reference(&xs), \"mismatch: {{xs:?}}\");\n\
         \x20   }}\n\
         }}\n",
        name = spec.struct_name,
        driver = spec.driver_name,
        reference = reference,
    )
}

/// Degenerate: every method stubbed so the driver returns `0` regardless of input.
/// Fails on the canonical example, whose answer is never `0`.
fn const_zero(spec: &Spec) -> String {
    degenerate(spec, "0")
}

/// Degenerate: `identity` returns `1`, nothing is kept, so the driver returns `1`.
/// Fails on the canonical example, whose answer is never `1`. Both constant
/// baselines are used because any *shaped* baseline (sum-everything, length)
/// coincides with exactly one real spec and so would pass on that seed.
fn const_one(spec: &Spec) -> String {
    degenerate(spec, "1")
}

fn degenerate(spec: &Spec, identity: &str) -> String {
    format!(
        "{trait_src}\n\
         {driver}\n\
         pub struct {name};\n\
         \n\
         impl Aggregate for {name} {{\n\
         \x20   type Item = i64;\n\
         \x20   fn keep(&self, _item: &Self::Item) -> bool {{ false }}\n\
         \x20   fn identity(&self) -> i64 {{ {identity} }}\n\
         \x20   fn combine(&self, acc: i64, _item: Self::Item) -> i64 {{ acc }}\n\
         }}\n",
        trait_src = TRAIT_SRC,
        driver = driver_src(spec),
        name = spec.struct_name,
        identity = identity,
    )
}

pub struct TraitsGenericsFamily;

impl Generator for TraitsGenericsFamily {
    fn id(&self) -> &str {
        "trait-impl"
    }
    fn category(&self) -> &str {
        "traits-generics"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("trait-impl", seed);

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
            id: format!("trait-impl/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            // Folding into a scalar does not allocate meaningfully: no alloc layer.
            alloc_test: String::new(),
            max_unsafe: Some(0),
            check_clippy: false,
            clippy_allow: Vec::new(),
            forbidden_paths: Vec::new(),
            // traits-generics uses docs/04 default weights (L1 + signature match
            // dominate via the compile gate and the differential).
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
            ("const-zero".to_string(), const_zero(&spec)),
            ("const-one".to_string(), const_one(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        // The skill is the (keep, reduce) pair. There are no numeric constants;
        // the struct and driver names are cosmetic — all excluded (Q31).
        let spec = sample(seed);
        let keep = match spec.keep {
            Keep::Positive => "positive",
            Keep::Even => "even",
            Keep::NonNegative => "nonnegative",
            Keep::Odd => "odd",
        };
        let reduce = match spec.reduce {
            Reduce::Sum => "sum",
            Reduce::Product => "product",
            Reduce::Count => "count",
            Reduce::SumOfSquares => "sum_of_squares",
            Reduce::SumOfAbs => "sum_of_abs",
        };
        vec![format!("keep:{keep}"), format!("reduce:{reduce}")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = TraitsGenericsFamily;
        assert_eq!(g.generate(23).prompt, g.generate(23).prompt);
        assert_eq!(g.generate(23).hidden, g.generate(23).hidden);
    }

    #[test]
    fn eval_matches_intent() {
        // Positive + Sum: keep [2,4,5] from [2,-1,4,0,5] -> 11.
        let spec = Spec {
            keep: Keep::Positive,
            reduce: Reduce::Sum,
            struct_name: "Agg",
            driver_name: "aggregate",
        };
        assert_eq!(eval(&spec, &[2, -1, 4, 0, 5]), 11);

        // Even + Product: keep [2,4,6] -> 48; identity 1 so empty -> 1.
        let spec = Spec {
            keep: Keep::Even,
            reduce: Reduce::Product,
            struct_name: "Agg",
            driver_name: "aggregate",
        };
        assert_eq!(eval(&spec, &[2, 3, 4, 5, 6]), 48);
        assert_eq!(eval(&spec, &[]), 1);
        assert_eq!(eval(&spec, &[1, 3, 5]), 1); // nothing kept -> identity

        // Odd + Count: count the odds in [1,2,3,4,5] -> 3.
        let spec = Spec {
            keep: Keep::Odd,
            reduce: Reduce::Count,
            struct_name: "Agg",
            driver_name: "aggregate",
        };
        assert_eq!(eval(&spec, &[1, 2, 3, 4, 5]), 3);

        // NonNegative + SumOfSquares: keep [0,2,3] -> 0+4+9 = 13.
        let spec = Spec {
            keep: Keep::NonNegative,
            reduce: Reduce::SumOfSquares,
            struct_name: "Agg",
            driver_name: "aggregate",
        };
        assert_eq!(eval(&spec, &[-1, 0, 2, 3]), 13);
    }

    #[test]
    fn seeds_vary_the_reduction() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..300u64 {
            let s = sample(seed);
            variants.insert(format!("{:?}/{:?}", s.keep, s.reduce));
        }
        assert!(
            variants.len() >= 16,
            "expected wide structural variety, got {}",
            variants.len()
        );
    }

    #[test]
    fn canonical_answer_is_never_zero_or_one() {
        // The const-zero / const-one baselines are caught on every seed only if
        // the canonical input [2,3,4,5] never reduces to 0 or 1 under any combo,
        // and every keep predicate keeps at least two of its elements.
        let canonical = [2i64, 3, 4, 5];
        for &keep in &[Keep::Positive, Keep::Even, Keep::NonNegative, Keep::Odd] {
            let n_kept = canonical.iter().filter(|&&x| kept(keep, x)).count();
            assert!(n_kept >= 2, "{keep:?} keeps only {n_kept} of the canonical");
            for &reduce in &[
                Reduce::Sum,
                Reduce::Product,
                Reduce::Count,
                Reduce::SumOfSquares,
                Reduce::SumOfAbs,
            ] {
                let spec = Spec {
                    keep,
                    reduce,
                    struct_name: "Agg",
                    driver_name: "aggregate",
                };
                let ans = eval(&spec, &canonical);
                assert!(
                    ans != 0 && ans != 1,
                    "canonical answer {ans} is 0 or 1 under {keep:?}/{reduce:?}"
                );
            }
        }
    }

    #[test]
    fn reference_matches_native_eval() {
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
        let g = TraitsGenericsFamily;
        let t = g.generate(5);
        assert!(t.prompt.contains(&t.canary));
    }
}
