//! The `raw-ptr` family (category `unsafe-core`).
//!
//! The distinctive skill is writing **correct `unsafe` raw-pointer code**: the
//! model implements `fn f(ptr: *const i64, len: usize) -> i64`, and there is *no
//! safe way* to read through a `*const i64`, so the answer must contain an
//! `unsafe { *ptr.add(i) }` (or `std::slice::from_raw_parts`) — `unsafe` is forced
//! by the signature, not merely permitted.
//!
//! The reduction is seed-selected on two axes:
//!
//! 1. **Access pattern** — which indices are read (via pointer arithmetic):
//!    Forward (all), EveryOther (0,2,4,…), OddIndices (1,3,5,…), FirstHalf (0..len/2).
//! 2. **Reduce** — how the read values combine: Sum / Product / SumOfSquares /
//!    SumOfAbs / SumOfPositives.
//!
//! The structural surface is 4 × 5 = **20 distinct skills**. Solution-first and
//! correct-by-construction (ADR-0003): the native `eval`, the emitted unsafe
//! reference, and the differential's safe reference are three mirrors of the same
//! index-walk; the differential fuzzes 3000 random slices, passing `xs.as_ptr()` /
//! `xs.len()` to the model and comparing against the safe reference. Values are
//! bounded (∈ -9..=9, len 0..12) so no legal input overflows `i64` — the tightest
//! case is `Product` over a Forward walk of eleven `9`s (9¹¹ ≈ 3.1e10).
//!
//! **Miri is deferred (roadmap P7).** docs/04 makes miri mandatory for this
//! category because behaviour testing catches *wrong* answers and gross
//! out-of-bounds (a mismatch or a crash) but not subtle *unsoundness* that still
//! produces the right values on the fuzzed inputs. Until the miri layer lands,
//! this family grades on behaviour + the differential only; it is correct-by-
//! construction and passes every construction gate today, and the honest gap is
//! recorded here rather than papered over.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Axis 1 — which indices are read, expressed as (start, stride, bound).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Access {
    Forward,
    EveryOther,
    OddIndices,
    FirstHalf,
}

/// Axis 2 — how the read values combine (with an identity element).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Reduce {
    Sum,
    Product,
    SumOfSquares,
    SumOfAbs,
    SumOfPositives,
}

struct Spec {
    access: Access,
    reduce: Reduce,
    fn_name: &'static str,
}

const NAMES: &[&str] = &["f", "reduce_raw", "walk", "fold_ptr", "scan", "gather"];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let access = match rng.below(4) {
        0 => Access::Forward,
        1 => Access::EveryOther,
        2 => Access::OddIndices,
        _ => Access::FirstHalf,
    };
    let reduce = match rng.below(5) {
        0 => Reduce::Sum,
        1 => Reduce::Product,
        2 => Reduce::SumOfSquares,
        3 => Reduce::SumOfAbs,
        _ => Reduce::SumOfPositives,
    };
    let fn_name = NAMES[rng.below(NAMES.len() as u64) as usize];
    Spec {
        access,
        reduce,
        fn_name,
    }
}

// ---- native reference (mirrors the two emitted sources exactly) -----------

fn start(access: Access) -> usize {
    match access {
        Access::OddIndices => 1,
        _ => 0,
    }
}

fn stride(access: Access) -> usize {
    match access {
        Access::EveryOther | Access::OddIndices => 2,
        _ => 1,
    }
}

fn bound(access: Access, len: usize) -> usize {
    match access {
        Access::FirstHalf => len / 2,
        _ => len,
    }
}

fn identity_val(reduce: Reduce) -> i64 {
    match reduce {
        Reduce::Product => 1,
        _ => 0,
    }
}

fn step(reduce: Reduce, acc: i64, v: i64) -> i64 {
    match reduce {
        Reduce::Sum => acc + v,
        Reduce::Product => acc * v,
        Reduce::SumOfSquares => acc + v * v,
        Reduce::SumOfAbs => acc + v.abs(),
        Reduce::SumOfPositives => {
            if v > 0 {
                acc + v
            } else {
                acc
            }
        }
    }
}

/// The answer: walk the selected indices and fold the values. Source of truth for
/// both the emitted unsafe reference and the differential's safe reference.
fn eval(spec: &Spec, xs: &[i64]) -> i64 {
    let mut acc = identity_val(spec.reduce);
    let mut i = start(spec.access);
    let b = bound(spec.access, xs.len());
    while i < b {
        acc = step(spec.reduce, acc, xs[i]);
        i += stride(spec.access);
    }
    acc
}

// ---- emitted-source fragments (mirror the native functions above) ---------

fn bound_expr(access: Access, len_var: &str) -> String {
    match access {
        Access::FirstHalf => format!("{len_var} / 2"),
        _ => len_var.to_string(),
    }
}

/// The fold step as a source statement over value variable `v`.
fn step_stmt(reduce: Reduce) -> &'static str {
    match reduce {
        Reduce::Sum => "acc += v;",
        Reduce::Product => "acc *= v;",
        Reduce::SumOfSquares => "acc += v * v;",
        Reduce::SumOfAbs => "acc += v.abs();",
        Reduce::SumOfPositives => "if v > 0 { acc += v; }",
    }
}

fn access_prose(access: Access) -> &'static str {
    match access {
        Access::Forward => "every element, from index 0 to `len - 1`",
        Access::EveryOther => "the even indices 0, 2, 4, … that are below `len`",
        Access::OddIndices => "the odd indices 1, 3, 5, … that are below `len`",
        Access::FirstHalf => "the first half of the elements, indices 0 to `len / 2 - 1`",
    }
}

fn reduce_prose(reduce: Reduce) -> &'static str {
    match reduce {
        Reduce::Sum => "their sum (identity `0`)",
        Reduce::Product => "their product (identity `1`)",
        Reduce::SumOfSquares => "the sum of their squares (identity `0`)",
        Reduce::SumOfAbs => "the sum of their absolute values (identity `0`)",
        Reduce::SumOfPositives => "the sum of the strictly-positive ones (identity `0`)",
    }
}

/// The correct unsafe reference — reads each selected element through the pointer.
fn reference_src(spec: &Spec) -> String {
    format!(
        "pub fn {name}(ptr: *const i64, len: usize) -> i64 {{\n\
         \x20   let mut acc: i64 = {identity};\n\
         \x20   let mut i: usize = {start};\n\
         \x20   while i < {bound} {{\n\
         \x20       let v = unsafe {{ *ptr.add(i) }};\n\
         \x20       {step}\n\
         \x20       i += {stride};\n\
         \x20   }}\n\
         \x20   acc\n\
         }}\n",
        name = spec.fn_name,
        identity = identity_val(spec.reduce),
        start = start(spec.access),
        bound = bound_expr(spec.access, "len"),
        step = step_stmt(spec.reduce),
        stride = stride(spec.access),
    )
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let (examples, _) = worked_examples(spec, seed);
    format!(
        "//! Implement `{name}` below. You must read the elements through the raw\n\
         //! pointer — there is no safe way to dereference `*const i64`.\n\
         //!\n\
         {doc}\n\
         pub fn {name}(ptr: *const i64, len: usize) -> i64 {{\n\
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

/// One worked example: (input slice, expected scalar).
type ExampleCase = (Vec<i64>, i64);

/// Worked examples, computed natively so each is correct by construction. The
/// first case is the **canonical** one — the fixed input `[3, 1, 4, 2]`, chosen so
/// every access pattern selects at least two elements and the answer is provably
/// never `0` or `1` under any of the 20 combinations. That is what makes both
/// trivial baselines (`const-zero`, `const-one`) fail on every seed. The rest are
/// seed-varied random inputs (the family's biggest per-instance textual lever,
/// docs/02 Q30).
fn worked_examples(spec: &Spec, seed: u64) -> (String, Vec<ExampleCase>) {
    let mut rng = Rng::new(seed ^ 0x00FF_0000_0000_0053);
    let mut inputs: Vec<Vec<i64>> = vec![vec![3, 1, 4, 2]];
    for _ in 0..3 {
        let len = 2 + rng.below(7) as usize; // 2..=8
        let input: Vec<i64> = (0..len).map(|_| rng.below(19) as i64 - 9).collect();
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
        "Implement the function `{name}` in `src/lib.rs`.\n\
         \n\
         `ptr` points to the first of `len` consecutive `i64` values (a raw slice). \
         Read {access_prose} through the pointer, and return {reduce_prose}.\n\
         \n\
         There is no safe way to dereference a `*const i64`, so you must use an \
         `unsafe` block with pointer arithmetic (`*ptr.add(i)` or \
         `std::slice::from_raw_parts`). The caller guarantees `ptr` is valid for \
         `len` elements, so reading indices `0..len` is sound.\n\
         \n\
         Constraints:\n\
         - `len` may be 0; the result is then the identity.\n\
         - Read only indices in `0..len`; reading out of bounds is undefined \
         behaviour.\n\
         \n\
         Signature:\n\
         ```rust\n\
         pub fn {name}(ptr: *const i64, len: usize) -> i64\n\
         ```\n\
         \n\
         Examples (`{name}(xs.as_ptr(), xs.len())` for the shown slice `xs`):\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        name = spec.fn_name,
        access_prose = access_prose(spec.access),
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
    let mut body = format!("use task::{};\n\n", spec.fn_name);
    for (i, (input, out)) in cases.iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   let xs: Vec<i64> = vec!{input:?};\n\
             \x20   assert_eq!({name}(xs.as_ptr(), xs.len()), {out});\n\
             }}\n\n",
            name = spec.fn_name,
        ));
    }
    body.push_str(&format!(
        "#[test]\nfn empty_input() {{\n\
         \x20   let xs: Vec<i64> = Vec::new();\n\
         \x20   assert_eq!({name}(xs.as_ptr(), xs.len()), {identity});\n\
         }}\n",
        name = spec.fn_name,
        identity = identity_val(spec.reduce),
    ));
    body
}

fn differential_test_src(spec: &Spec) -> String {
    // The safe mirror of the reference — indexes `xs` instead of dereferencing.
    let reference = format!(
        "fn reference(xs: &[i64]) -> i64 {{\n\
         \x20   let mut acc: i64 = {identity};\n\
         \x20   let mut i: usize = {start};\n\
         \x20   while i < {bound} {{\n\
         \x20       let v = xs[i];\n\
         \x20       {step}\n\
         \x20       i += {stride};\n\
         \x20   }}\n\
         \x20   acc\n\
         }}\n",
        identity = identity_val(spec.reduce),
        start = start(spec.access),
        bound = bound_expr(spec.access, "xs.len()"),
        step = step_stmt(spec.reduce),
        stride = stride(spec.access),
    );
    format!(
        "use task::{name};\n\
         \n\
         {reference}\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0x00FF_ED00_0000_0042;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       (state >> 33) as u64\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let len = (next() % 12) as usize;\n\
         \x20       let xs: Vec<i64> = (0..len).map(|_| (next() % 19) as i64 - 9).collect();\n\
         \x20       assert_eq!({name}(xs.as_ptr(), xs.len()), reference(&xs), \"mismatch: {{xs:?}}\");\n\
         \x20   }}\n\
         }}\n",
        name = spec.fn_name,
        reference = reference,
    )
}

/// Degenerate: reads nothing, returns 0. Fails on the canonical example, whose
/// answer is never 0. (UB-free — dereferences no pointer.)
fn const_zero(spec: &Spec) -> String {
    format!(
        "pub fn {name}(ptr: *const i64, len: usize) -> i64 {{ let _ = (ptr, len); 0 }}\n",
        name = spec.fn_name,
    )
}

/// Degenerate: returns 1. Fails on the canonical example, whose answer is never 1.
/// Both baselines are constants because any *shaped* degenerate (first-element,
/// length) coincides with some real spec on the canonical input.
fn const_one(spec: &Spec) -> String {
    format!(
        "pub fn {name}(ptr: *const i64, len: usize) -> i64 {{ let _ = (ptr, len); 1 }}\n",
        name = spec.fn_name,
    )
}

pub struct UnsafeCoreFamily;

impl Generator for UnsafeCoreFamily {
    fn id(&self) -> &str {
        "raw-ptr"
    }
    fn category(&self) -> &str {
        "unsafe-core"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("raw-ptr", seed);

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
            id: format!("raw-ptr/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // unsafe is REQUIRED here (the signature forces it), so it is not
            // constrained (limit = unlimited). Miri, the real constraint layer for
            // this category, is deferred (docs/04, roadmap P7) — see the module doc.
            max_unsafe: None,
            check_clippy: false,
            clippy_allow: Vec::new(),
            forbidden_paths: Vec::new(),
            // docs/04 unsafe-core weights (behaviour-dominant; the constraint slot
            // is miri, deferred, so scoring currently renormalises to behaviour).
            weights: (0.70, 0.30, 0.0),
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
        // The skill is the (access pattern, reduce) pair. The function name is
        // cosmetic; there are no numeric constants — all excluded (Q31).
        let spec = sample(seed);
        let access = match spec.access {
            Access::Forward => "forward",
            Access::EveryOther => "every_other",
            Access::OddIndices => "odd_indices",
            Access::FirstHalf => "first_half",
        };
        let reduce = match spec.reduce {
            Reduce::Sum => "sum",
            Reduce::Product => "product",
            Reduce::SumOfSquares => "sum_of_squares",
            Reduce::SumOfAbs => "sum_of_abs",
            Reduce::SumOfPositives => "sum_of_positives",
        };
        vec![format!("access:{access}"), format!("reduce:{reduce}")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = UnsafeCoreFamily;
        assert_eq!(g.generate(31).prompt, g.generate(31).prompt);
        assert_eq!(g.generate(31).hidden, g.generate(31).hidden);
    }

    #[test]
    fn eval_matches_intent() {
        // Forward + Sum over [3,1,4,2] = 10.
        let spec = Spec {
            access: Access::Forward,
            reduce: Reduce::Sum,
            fn_name: "f",
        };
        assert_eq!(eval(&spec, &[3, 1, 4, 2]), 10);

        // EveryOther + Product: indices 0,2 -> [3,4] -> 12.
        let spec = Spec {
            access: Access::EveryOther,
            reduce: Reduce::Product,
            fn_name: "f",
        };
        assert_eq!(eval(&spec, &[3, 1, 4, 2]), 12);
        assert_eq!(eval(&spec, &[]), 1); // empty -> identity 1

        // OddIndices + Sum: indices 1,3 -> [1,2] -> 3.
        let spec = Spec {
            access: Access::OddIndices,
            reduce: Reduce::Sum,
            fn_name: "f",
        };
        assert_eq!(eval(&spec, &[3, 1, 4, 2]), 3);

        // FirstHalf + SumOfPositives: indices 0,1 of [3,-1,4,2] -> [3,-1] -> 3.
        let spec = Spec {
            access: Access::FirstHalf,
            reduce: Reduce::SumOfPositives,
            fn_name: "f",
        };
        assert_eq!(eval(&spec, &[3, -1, 4, 2]), 3);
    }

    #[test]
    fn seeds_vary_the_task() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..300u64 {
            let s = sample(seed);
            variants.insert(format!("{:?}/{:?}", s.access, s.reduce));
        }
        assert!(
            variants.len() >= 16,
            "expected wide structural variety, got {}",
            variants.len()
        );
    }

    #[test]
    fn canonical_answer_is_never_zero_or_one() {
        // Both constant baselines are caught on every seed only if the canonical
        // input [3,1,4,2] never reduces to 0 or 1 under any combo, and every access
        // pattern selects at least two elements.
        let canonical = [3i64, 1, 4, 2];
        for &access in &[
            Access::Forward,
            Access::EveryOther,
            Access::OddIndices,
            Access::FirstHalf,
        ] {
            let mut n = 0;
            let mut i = start(access);
            while i < bound(access, canonical.len()) {
                n += 1;
                i += stride(access);
            }
            assert!(n >= 2, "{access:?} selects only {n} of the canonical");
            for &reduce in &[
                Reduce::Sum,
                Reduce::Product,
                Reduce::SumOfSquares,
                Reduce::SumOfAbs,
                Reduce::SumOfPositives,
            ] {
                let spec = Spec {
                    access,
                    reduce,
                    fn_name: "f",
                };
                let ans = eval(&spec, &canonical);
                assert!(
                    ans != 0 && ans != 1,
                    "canonical answer {ans} is 0 or 1 under {access:?}/{reduce:?}"
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
        let g = UnsafeCoreFamily;
        let t = g.generate(9);
        assert!(t.prompt.contains(&t.canary));
    }
}
