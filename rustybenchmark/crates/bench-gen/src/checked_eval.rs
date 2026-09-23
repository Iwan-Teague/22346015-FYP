//! The `checked-eval` family (category `error-handling`).
//!
//! A *second* `error-handling` family, testing a sub-skill the first one does not:
//! **checked arithmetic and overflow propagation**. The model implements
//! `fn f(xs: &[i64]) -> Result<i64, MathError>`, folding the slice with a
//! seed-selected checked operation and short-circuiting on the first error — an
//! element that fails a seed-selected guard (`MathError::OutOfRange`) or an
//! arithmetic overflow (`MathError::Overflow`). Where `error-handling` (#1) is
//! parse-then-validate over `&[&str]`, this is `checked_add`/`checked_mul` +
//! `.ok_or(…)?` over `&[i64]`: the "don't panic on overflow, propagate" skill.
//!
//! Seed-selected on two axes:
//!
//! 1. **Fold** — the checked reduction (`checked_*` throughout): Sum / Product /
//!    SumSquares (each `→ Overflow` on overflow).
//! 2. **Guard** — the per-element precondition: Positive / NonZero / AtMost(b) /
//!    InRange(lo, hi) (failure `→ OutOfRange(x)`).
//!
//! The structural surface is 3 × 4 = **12 distinct skills**; the guard bounds are
//! constant parameters of the same skill (Q31), excluded from `spec_signature`
//! along with the function name. The `MathError` enum is pinned in the skeleton
//! (docs/04: error-handling pins the public error type). Solution-first and
//! correct-by-construction (ADR-0003): native `eval` and the emitted reference are
//! mirrored, and the differential fuzzes 3000 random slices — with values wide
//! enough that `CheckedProduct`/`CheckedSumSquares` overflow, which is what makes
//! the differential punish a model that reaches for plain `+`/`*` (it panics in the
//! debug build and scores 0). Every arithmetic path in the reference is checked, so
//! the reference itself never panics.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Axis 1 — the checked reduction (all steps use `checked_*` arithmetic).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Fold {
    Sum,
    Product,
    SumSquares,
}

/// Axis 2 — the per-element guard.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Guard {
    Positive,
    NonZero,
    AtMost(i64),
    InRange(i64, i64),
}

struct Spec {
    fold: Fold,
    guard: Guard,
    fn_name: &'static str,
}

const NAMES: &[&str] = &[
    "f",
    "checked_reduce",
    "fold_checked",
    "evaluate",
    "accumulate",
    "run",
];

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let fold = match rng.below(3) {
        0 => Fold::Sum,
        1 => Fold::Product,
        _ => Fold::SumSquares,
    };
    let guard = match rng.below(4) {
        0 => Guard::Positive,
        1 => Guard::NonZero,
        2 => Guard::AtMost([50, 100, 1000][rng.below(3) as usize]),
        _ => {
            let (lo, hi) = [(0, 100), (1, 50), (-100, 100)][rng.below(3) as usize];
            Guard::InRange(lo, hi)
        }
    };
    let fn_name = NAMES[rng.below(NAMES.len() as u64) as usize];
    Spec {
        fold,
        guard,
        fn_name,
    }
}

// ---- native reference (mirrors the emitted source exactly) ----------------

fn init_val(fold: Fold) -> i64 {
    match fold {
        Fold::Product => 1,
        _ => 0,
    }
}

fn init_expr(fold: Fold) -> &'static str {
    match fold {
        Fold::Product => "1",
        _ => "0",
    }
}

/// The checked fold step: `None` signals overflow. Mirrors the emitted expression.
fn step(fold: Fold, acc: i64, x: i64) -> Option<i64> {
    match fold {
        Fold::Sum => acc.checked_add(x),
        Fold::Product => acc.checked_mul(x),
        Fold::SumSquares => x.checked_mul(x).and_then(|sq| acc.checked_add(sq)),
    }
}

fn guard_ok(guard: Guard, x: i64) -> bool {
    match guard {
        Guard::Positive => x > 0,
        Guard::NonZero => x != 0,
        Guard::AtMost(b) => x <= b,
        Guard::InRange(lo, hi) => x >= lo && x <= hi,
    }
}

/// The answer: fold with the guard checked before each step, returning the first
/// error (a tag string, matching how the emitted `MathError` derives `PartialEq`).
fn eval(spec: &Spec, xs: &[i64]) -> Result<i64, String> {
    let mut acc = init_val(spec.fold);
    for &x in xs {
        if !guard_ok(spec.guard, x) {
            return Err(format!("OutOfRange({x})"));
        }
        acc = step(spec.fold, acc, x).ok_or_else(|| "Overflow".to_string())?;
    }
    Ok(acc)
}

// ---- emitted-source fragments (mirror the native functions above) ---------

fn step_expr(fold: Fold) -> &'static str {
    match fold {
        Fold::Sum => "acc.checked_add(x)",
        Fold::Product => "acc.checked_mul(x)",
        Fold::SumSquares => "x.checked_mul(x).and_then(|sq| acc.checked_add(sq))",
    }
}

fn guard_cond(guard: Guard) -> String {
    match guard {
        Guard::Positive => "x > 0".to_string(),
        Guard::NonZero => "x != 0".to_string(),
        Guard::AtMost(b) => format!("x <= {b}"),
        Guard::InRange(lo, hi) => format!("x >= {lo} && x <= {hi}"),
    }
}

fn fold_prose(fold: Fold) -> &'static str {
    match fold {
        Fold::Sum => "their sum",
        Fold::Product => "their product",
        Fold::SumSquares => "the sum of their squares",
    }
}

fn guard_prose(guard: Guard) -> String {
    match guard {
        Guard::Positive => "be strictly positive (`> 0`)".to_string(),
        Guard::NonZero => "be non-zero".to_string(),
        Guard::AtMost(b) => format!("be at most `{b}`"),
        Guard::InRange(lo, hi) => format!("be in the range `{lo}..={hi}` inclusive"),
    }
}

/// A value that passes any guard the sampler can pick (used as the clean lead of
/// the guard-failure example). `2` satisfies Positive, NonZero, every `AtMost`
/// (bounds ≥ 50) and every `InRange` (all bounds contain 2).
fn pass_value() -> i64 {
    2
}

/// A value guaranteed to fail `guard` — the violator in the guard-failure example.
fn violating_value(guard: Guard) -> i64 {
    match guard {
        Guard::Positive => 0,
        Guard::NonZero => 0,
        Guard::AtMost(b) => b + 1,
        Guard::InRange(_, hi) => hi + 1,
    }
}

const ENUM_SRC: &str = "#[derive(Debug, PartialEq)]\n\
     pub enum MathError {\n\
     \x20   Overflow,\n\
     \x20   OutOfRange(i64),\n\
     }\n";

fn reference_src(spec: &Spec) -> String {
    format!(
        "{enum_src}\n\
         pub fn {name}(xs: &[i64]) -> Result<i64, MathError> {{\n\
         \x20   let mut acc: i64 = {init};\n\
         \x20   for &x in xs {{\n\
         \x20       if !({guard}) {{\n\
         \x20           return Err(MathError::OutOfRange(x));\n\
         \x20       }}\n\
         \x20       acc = {step}.ok_or(MathError::Overflow)?;\n\
         \x20   }}\n\
         \x20   Ok(acc)\n\
         }}\n",
        enum_src = ENUM_SRC,
        name = spec.fn_name,
        init = init_expr(spec.fold),
        guard = guard_cond(spec.guard),
        step = step_expr(spec.fold),
    )
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let examples = worked_examples_prose(spec, seed);
    format!(
        "//! Implement `{name}` below. The `MathError` enum is provided; keep it.\n\
         //!\n\
         {doc}\n\
         {enum_src}\n\
         pub fn {name}(xs: &[i64]) -> Result<i64, MathError> {{\n\
         \x20   todo!()\n\
         }}\n",
        name = spec.fn_name,
        enum_src = ENUM_SRC,
        doc = examples
            .lines()
            .map(|l| format!("//! {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// Worked examples: `(input, expected)`, expected computed natively so each is
/// correct by construction. The set always includes the **canonical** all-valid
/// case `[2, 3, 4]` (valid under every guard the sampler can pick, so its answer is
/// `Ok(v)` with `v` never `0` — which catches the `const-ok` baseline), a
/// constructed **guard-failure** case (a clean value then a violator, so its answer
/// is `Err(OutOfRange)` — which catches the `no-guard` baseline), two seed-varied
/// random cases, and the empty case. Seed-varying is the biggest per-instance
/// textual lever (docs/02 Q30).
fn worked_examples(spec: &Spec, seed: u64) -> Vec<(Vec<i64>, Result<i64, String>)> {
    let mut rng = Rng::new(seed ^ 0xC4EC_0000_0000_0011);
    let mut out: Vec<(Vec<i64>, Result<i64, String>)> = Vec::new();

    // Canonical all-valid case (see doc comment).
    out.push((vec![2, 3, 4], eval(spec, &[2, 3, 4])));

    // Two seed-varied random cases (values kept modest so they mostly pass and
    // rarely overflow — the differential exercises the wide/overflowing range).
    for _ in 0..2 {
        let len = 2 + rng.below(3) as usize; // 2..=4
        let input: Vec<i64> = (0..len).map(|_| rng.below(21) as i64 - 5).collect(); // -5..=15
        out.push((input.clone(), eval(spec, &input)));
    }

    // Constructed guard-failure case.
    let gf = vec![pass_value(), violating_value(spec.guard)];
    out.push((gf.clone(), eval(spec, &gf)));

    // Empty case.
    out.push((Vec::new(), eval(spec, &[])));
    out
}

fn render_expected(res: &Result<i64, String>) -> String {
    match res {
        Ok(v) => format!("Ok({v})"),
        Err(e) => {
            if e == "Overflow" {
                "Err(MathError::Overflow)".to_string()
            } else if let Some(inner) = e
                .strip_prefix("OutOfRange(")
                .and_then(|r| r.strip_suffix(')'))
            {
                format!("Err(MathError::OutOfRange({inner}))")
            } else {
                unreachable!("unexpected error tag: {e}")
            }
        }
    }
}

fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for (input, res) in worked_examples(spec, seed) {
        let r = match res {
            Ok(v) => format!("Ok({v})"),
            Err(e) => format!("Err(MathError::{e})"),
        };
        s.push_str(&format!("  {input:?}  ->  {r}\n"));
    }
    s
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let examples = worked_examples_prose(spec, seed);
    format!(
        "Implement the function `{name}` in `src/lib.rs`. The `MathError` enum is \
         already provided; keep it.\n\
         \n\
         Fold `xs` left to right into an accumulator that starts at `{init}`. Each \
         element must {guard}; if one does not, return \
         `Err(MathError::OutOfRange(value))`. Otherwise combine the elements into \
         {fold}. If any arithmetic step overflows `i64`, return \
         `Err(MathError::Overflow)` rather than panicking — use the checked \
         operations. An empty input returns `Ok({init})`.\n\
         \n\
         Constraints:\n\
         - Do not panic on overflow; propagate `MathError::Overflow` via the \
         `checked_*` methods.\n\
         - Do not use `unsafe`.\n\
         \n\
         Signature:\n\
         ```rust\n\
         pub fn {name}(xs: &[i64]) -> Result<i64, MathError>\n\
         ```\n\
         \n\
         Examples:\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        name = spec.fn_name,
        init = init_val(spec.fold),
        guard = guard_prose(spec.guard),
        fold = fold_prose(spec.fold),
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
    let mut body = format!("use task::{{MathError, {}}};\n\n", spec.fn_name);
    for (i, (input, res)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   let xs: Vec<i64> = vec!{input:?};\n\
             \x20   assert_eq!({name}(&xs), {expect});\n\
             }}\n\n",
            name = spec.fn_name,
            expect = render_expected(res),
        ));
    }
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec).replacen(ENUM_SRC, "", 1).replacen(
        &format!("pub fn {}", spec.fn_name),
        "fn reference",
        1,
    );
    format!(
        "use task::{{MathError, {name}}};\n\
         \n\
         {reference}\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0xC4EC_ED00_0000_0042;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       (state >> 33) as u64\n\
         \x20   }};\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let len = (next() % 8) as usize;\n\
         \x20       // Wide values so CheckedProduct / CheckedSumSquares overflow — a\n\
         \x20       // model using plain `*` would panic here and score zero.\n\
         \x20       let xs: Vec<i64> = (0..len)\n\
         \x20           .map(|_| (next() % 6_000_000_001) as i64 - 3_000_000_000)\n\
         \x20           .collect();\n\
         \x20       assert_eq!({name}(&xs), reference(&xs), \"mismatch on {{xs:?}}\");\n\
         \x20   }}\n\
         }}\n",
        name = spec.fn_name,
        reference = reference,
    )
}

/// Degenerate: always `Ok(0)`. Fails the canonical example (`Ok(v)`, `v != 0`) and
/// the guard-failure example (`Err`).
fn const_ok(spec: &Spec) -> String {
    format!(
        "{enum_src}\n\
         pub fn {name}(xs: &[i64]) -> Result<i64, MathError> {{ let _ = xs; Ok(0) }}\n",
        enum_src = ENUM_SRC,
        name = spec.fn_name,
    )
}

/// Degenerate: folds correctly but omits the guard, so it never returns
/// `OutOfRange`. Fails the guard-failure example.
fn no_guard(spec: &Spec) -> String {
    format!(
        "{enum_src}\n\
         pub fn {name}(xs: &[i64]) -> Result<i64, MathError> {{\n\
         \x20   let mut acc: i64 = {init};\n\
         \x20   for &x in xs {{\n\
         \x20       acc = {step}.ok_or(MathError::Overflow)?;\n\
         \x20   }}\n\
         \x20   Ok(acc)\n\
         }}\n",
        enum_src = ENUM_SRC,
        name = spec.fn_name,
        init = init_expr(spec.fold),
        step = step_expr(spec.fold),
    )
}

pub struct CheckedEvalFamily;

impl Generator for CheckedEvalFamily {
    fn id(&self) -> &str {
        "checked-eval"
    }
    fn category(&self) -> &str {
        "error-handling"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("checked-eval", seed);

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
            id: format!("checked-eval/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
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
            ("const-ok".to_string(), const_ok(&spec)),
            ("no-guard".to_string(), no_guard(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        // The skill is the (fold, guard type). Guard bounds are constant parameters
        // of the same skill (Q31); the function name is cosmetic — both excluded.
        let spec = sample(seed);
        let fold = match spec.fold {
            Fold::Sum => "sum",
            Fold::Product => "product",
            Fold::SumSquares => "sum_squares",
        };
        let guard = match spec.guard {
            Guard::Positive => "positive",
            Guard::NonZero => "nonzero",
            Guard::AtMost(_) => "at_most",
            Guard::InRange(_, _) => "in_range",
        };
        vec![format!("fold:{fold}"), format!("guard:{guard}")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = CheckedEvalFamily;
        assert_eq!(g.generate(29).prompt, g.generate(29).prompt);
        assert_eq!(g.generate(29).hidden, g.generate(29).hidden);
    }

    #[test]
    fn eval_matches_intent() {
        let mk = |fold, guard| Spec {
            fold,
            guard,
            fn_name: "f",
        };
        // Sum + Positive over [2,3,4] = 9.
        assert_eq!(eval(&mk(Fold::Sum, Guard::Positive), &[2, 3, 4]), Ok(9));
        // Product + Positive = 24.
        assert_eq!(
            eval(&mk(Fold::Product, Guard::Positive), &[2, 3, 4]),
            Ok(24)
        );
        // SumSquares + Positive = 4+9+16 = 29.
        assert_eq!(
            eval(&mk(Fold::SumSquares, Guard::Positive), &[2, 3, 4]),
            Ok(29)
        );
        // Guard failure short-circuits at the first bad element.
        assert_eq!(
            eval(&mk(Fold::Sum, Guard::Positive), &[2, -1, 4]),
            Err("OutOfRange(-1)".to_string())
        );
        // Overflow is reported, not panicked.
        assert_eq!(
            eval(
                &mk(Fold::Product, Guard::NonZero),
                &[3_000_000_000, 3_000_000_000, 3]
            ),
            Err("Overflow".to_string())
        );
        // Empty → identity.
        assert_eq!(eval(&mk(Fold::Product, Guard::Positive), &[]), Ok(1));
    }

    #[test]
    fn seeds_vary_fold_and_guard() {
        let mut variants = std::collections::HashSet::new();
        for seed in 0..200u64 {
            let s = sample(seed);
            variants.insert(format!("{:?}/{:?}", s.fold, s.guard));
        }
        assert!(
            variants.len() >= 10,
            "expected wide structural variety, got {}",
            variants.len()
        );
    }

    #[test]
    fn canonical_is_valid_under_every_guard() {
        // const-ok is caught only if the canonical [2,3,4] is Ok(v != 0) under every
        // guard/fold; no-guard is caught only if the guard-failure example is Err.
        let canonical = [2i64, 3, 4];
        for &guard in &[
            Guard::Positive,
            Guard::NonZero,
            Guard::AtMost(50),
            Guard::AtMost(100),
            Guard::AtMost(1000),
            Guard::InRange(0, 100),
            Guard::InRange(1, 50),
            Guard::InRange(-100, 100),
        ] {
            for &fold in &[Fold::Sum, Fold::Product, Fold::SumSquares] {
                let spec = Spec {
                    fold,
                    guard,
                    fn_name: "f",
                };
                match eval(&spec, &canonical) {
                    Ok(v) => assert_ne!(v, 0, "canonical is Ok(0) under {fold:?}/{guard:?}"),
                    Err(e) => panic!("canonical rejected under {fold:?}/{guard:?}: {e}"),
                }
                // The guard-failure example must actually be an Err.
                let gf = vec![pass_value(), violating_value(guard)];
                assert!(
                    eval(&spec, &gf).is_err(),
                    "guard-failure example is Ok under {fold:?}/{guard:?}"
                );
            }
        }
    }

    #[test]
    fn reference_matches_native_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (input, res) in worked_examples(&spec, seed) {
                assert_eq!(eval(&spec, &input), res, "seed {seed}");
            }
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = CheckedEvalFamily;
        let t = g.generate(14);
        assert!(t.prompt.contains(&t.canary));
    }
}
