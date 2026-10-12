//! The `minmax` family (category `order-statistics`) — extremum queries
//! over a seeded bag of signed integers.
//!
//! Where `parity` reduces a bag with counting/xor/popcount folds, this
//! family exercises **order statistics**: locating the minimum and the
//! maximum, the span between them, and how many entries tie at each end.
//! The domain is one `&[i64]` bag (values may be negative); every op is a
//! pure function of it. The seed prunes which two of five query ops are
//! required: `min`, `max`, `range`, `num_maxima`, `num_minima`.
//! C(5,2) = **10 distinct skills**, above the diversity floor; op names
//! are semantic.
//!
//! The canonical bag is sampled until its anchor facts hold: a nonzero
//! minimum and maximum, a nonzero span, exactly two entries tied at the
//! top, exactly two tied at the bottom (one duplicate of each extreme is
//! forced into the bag), and a wrapping total distinct from all five
//! answers. Those make every op separate from `const-zero` outright and
//! keep the `sum-everything` cheat inexact on every op, so both baselines
//! are caught under EVERY pair.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential fuzzes
//! 3000 random bags (signed values included) against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the
//! canonical bag) and `sum-everything` (every query answered with the
//! wrapping total).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    Min,
    Max,
    Range,
    NumMaxima,
    NumMinima,
}

const OP_ALL: [Op; 5] = [Op::Min, Op::Max, Op::Range, Op::NumMaxima, Op::NumMinima];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::Min => "min",
            Op::Max => "max",
            Op::Range => "range",
            Op::NumMaxima => "num_maxima",
            Op::NumMinima => "num_minima",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::Min => {
                "the smallest value in `xs`; an empty slice has \
                        none, yielding `0`"
            }
            Op::Max => {
                "the largest value in `xs`; an empty slice has \
                        none, yielding `0`"
            }
            Op::Range => {
                "the span from smallest to largest value, saturating \
                 instead of overflowing; an empty slice spans `0`"
            }
            Op::NumMaxima => {
                "how many entries tie for the largest value; an empty \
                 slice has none"
            }
            Op::NumMinima => {
                "how many entries tie for the smallest value; an empty \
                 slice has none"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Spec {
    ops: [Op; 2],
}

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let i1 = rng.below(5);
    let mut i2 = rng.below(5);
    while i2 == i1 {
        i2 = rng.below(5);
    }
    Spec {
        ops: [OP_ALL[i1 as usize], OP_ALL[i2 as usize]],
    }
}

// ---- native mirror (the answer; identical shape to the emitted code) ------

fn b_min(xs: &[i64]) -> i64 {
    let mut best = match xs.first() {
        Some(&v) => v,
        None => return 0,
    };
    for &v in &xs[1..] {
        if v < best {
            best = v;
        }
    }
    best
}

fn b_max(xs: &[i64]) -> i64 {
    let mut best = match xs.first() {
        Some(&v) => v,
        None => return 0,
    };
    for &v in &xs[1..] {
        if v > best {
            best = v;
        }
    }
    best
}

fn b_range(xs: &[i64]) -> i64 {
    b_max(xs).saturating_sub(b_min(xs))
}

fn b_num_maxima(xs: &[i64]) -> i64 {
    if xs.is_empty() {
        return 0;
    }
    let hi = b_max(xs);
    xs.iter().filter(|&&v| v == hi).count() as i64
}

fn b_num_minima(xs: &[i64]) -> i64 {
    if xs.is_empty() {
        return 0;
    }
    let lo = b_min(xs);
    xs.iter().filter(|&&v| v == lo).count() as i64
}

/// The wrapping total — not a query op, but the `sum-everything`
/// baseline's answer and an anchor ingredient.
fn total_of(xs: &[i64]) -> i64 {
    let mut t = 0i64;
    for &v in xs {
        t = t.wrapping_add(v);
    }
    t
}

/// Every op here answers with an `i64`.
type Out = i64;

fn op_eval(op: Op, xs: &[i64]) -> Out {
    match op {
        Op::Min => b_min(xs),
        Op::Max => b_max(xs),
        Op::Range => b_range(xs),
        Op::NumMaxima => b_num_maxima(xs),
        Op::NumMinima => b_num_minima(xs),
    }
}

// ---- canonical bag ----------------------------------------------------------

/// The canonical bag: two to five signed values in `±500k`, plus one forced
/// duplicate of the largest and one of the smallest entry, retried until the
/// anchor facts hold.
///
/// Guaranteed for every seed: nonzero minimum and maximum, a nonzero span,
/// exactly two entries tied at the top, exactly two tied at the bottom, and
/// a wrapping total distinct from all five answers. Together those make
/// every op separate from `const-zero` outright and keep `sum-everything`
/// inexact everywhere.
fn canonical(seed: u64) -> Vec<i64> {
    let mut rng = Rng::new(seed ^ 0x5ABB_1E55);
    for _ in 0..100_000 {
        let len = 2 + rng.below(4) as usize;
        let mut cand: Vec<i64> = (0..len)
            .map(|_| rng.below(1_000_000) as i64 - 500_000)
            .collect();
        // Pin the tie counts at two by duplicating both extremes.
        let hi = b_max(&cand);
        let lo = b_min(&cand);
        cand.push(hi);
        cand.push(lo);
        if anchors_hold(&cand) {
            return cand;
        }
    }
    unreachable!("canonical bag sampling failed to satisfy anchors");
}

fn anchors_hold(xs: &[i64]) -> bool {
    b_min(xs) != 0
        && b_max(xs) != 0
        && b_range(xs) != 0
        && b_num_maxima(xs) == 2
        && b_num_minima(xs) == 2
        && total_of(xs) != b_min(xs)
        && total_of(xs) != b_max(xs)
        && total_of(xs) != b_range(xs)
        && total_of(xs) != b_num_maxima(xs)
        && total_of(xs) != b_num_minima(xs)
}

// ---- worked examples --------------------------------------------------------

type ExampleCase = (Vec<i64>, Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_0102);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical bag first.
    let can = canonical(seed);
    cases.push((
        can.clone(),
        spec.ops.map(|op| (op, op_eval(op, &can))).to_vec(),
    ));
    // Empty slice: pins every zero convention at once.
    cases.push((vec![], spec.ops.map(|op| (op, op_eval(op, &[]))).to_vec()));
    // Wrap corner: MAX plus 1 totals back around to MIN while the span
    // saturates at i64::MAX.
    cases.push((
        vec![i64::MAX, 1],
        spec.ops
            .map(|op| (op, op_eval(op, &[i64::MAX, 1])))
            .to_vec(),
    ));
    for _ in 0..3 {
        let len = 1 + rng.below(6) as usize;
        let v: Vec<i64> = (0..len)
            .map(|_| rng.below(1_000_000) as i64 - 500_000)
            .collect();
        let outs = spec.ops.map(|op| (op, op_eval(op, &v))).to_vec();
        cases.push((v, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the first-element suffix types the
/// whole slice, and the empty form is typed by the function signature.
fn render_i64s(xs: &[i64]) -> String {
    if xs.is_empty() {
        return "&[]".to_string();
    }
    let items = xs
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!("&[{items}i64]")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let sig = "(xs: &[i64]) -> i64";
    let body = match op {
        Op::Min => [
            "if xs.is_empty() {",
            "    return 0;",
            "}",
            "let mut best = xs[0];",
            "for &v in &xs[1..] {",
            "    if v < best {",
            "        best = v;",
            "    }",
            "}",
            "best",
        ]
        .join("\n    "),
        Op::Max => [
            "if xs.is_empty() {",
            "    return 0;",
            "}",
            "let mut best = xs[0];",
            "for &v in &xs[1..] {",
            "    if v > best {",
            "        best = v;",
            "    }",
            "}",
            "best",
        ]
        .join("\n    "),
        Op::Range => [
            "if xs.is_empty() {",
            "    return 0;",
            "}",
            "let mut lo = xs[0];",
            "let mut hi = xs[0];",
            "for &v in &xs[1..] {",
            "    if v < lo {",
            "        lo = v;",
            "    }",
            "    if v > hi {",
            "        hi = v;",
            "    }",
            "}",
            "hi.saturating_sub(lo)",
        ]
        .join("\n    "),
        Op::NumMaxima => [
            "if xs.is_empty() {",
            "    return 0;",
            "}",
            "let mut hi = xs[0];",
            "for &v in &xs[1..] {",
            "    if v > hi {",
            "        hi = v;",
            "    }",
            "}",
            "let mut n = 0i64;",
            "for &v in xs {",
            "    if v == hi {",
            "        n += 1;",
            "    }",
            "}",
            "n",
        ]
        .join("\n    "),
        Op::NumMinima => [
            "if xs.is_empty() {",
            "    return 0;",
            "}",
            "let mut lo = xs[0];",
            "for &v in &xs[1..] {",
            "    if v < lo {",
            "        lo = v;",
            "    }",
            "}",
            "let mut n = 0i64;",
            "for &v in xs {",
            "    if v == lo {",
            "        n += 1;",
            "    }",
            "}",
            "n",
        ]
        .join("\n    "),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(xs: &[i64]) -> i64 {{\n    todo!()\n}}\n",
        op.name()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(xs: &[i64]) -> i64", op.name())
}

fn reference_src(spec: &Spec) -> String {
    spec.ops.iter().map(|op| op_fn_src(*op)).collect()
}

/// The call expression for one op in an emitted assertion.
fn call_src(op: Op, var: &str) -> String {
    format!("{}({})", op.name(), var)
}

fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for (xs, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  xs {}  ->  {}\n", render_i64s(&xs), results));
    }
    s
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples_prose(spec, seed)
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    let fns = spec.ops.map(op_stub_src).concat();
    format!(
        "//! Implement the two query functions below.\n\
         //!\n\
         //! Examples:\n\
         {doc}\n\
         {fns}",
        doc = doc,
        fns = fns,
    )
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let mut reqs = String::new();
    for op in spec.ops {
        reqs.push_str(&format!("- `{}`: {}.\n", op.name(), op.prose()));
    }
    format!(
        "Implement the two query functions in `src/lib.rs`. The input is \
         given as `xs`, a slice of integers of type `i64` (values may be \
         negative); queries are order statistics over the whole slice.\n\
         \n\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         \n\
         Signatures:\n\
         ```rust\n\
         {signatures}\
         ```\n\
         \n\
         Examples:\n\
         {examples}\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        reqs = reqs,
        signatures = spec
            .ops
            .iter()
            .map(|op| format!("{}\n", op_sig_src(*op)))
            .collect::<Vec<_>>()
            .join(""),
        examples = worked_examples_prose(spec, seed),
        canary = canary,
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
    let imports = spec
        .ops
        .iter()
        .map(|op| op.name())
        .collect::<Vec<_>>()
        .join(", ");
    let mut body = format!("use task::{{{imports}}};\n\n");
    for (i, (xs, outs)) in worked_examples(spec, seed).iter().enumerate() {
        // The rendered literal already carries the leading `&`, so bind it
        // once and pass the bare name at each call site.
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let xs = {};\n",
            render_i64s(xs),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "xs"),
                out,
            ));
        }
        body.push_str("}\n\n");
    }
    body
}

/// The differential's reference — the two selected ops, pasted into the test
/// file under `ref_*` names.
fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec)
        .replacen(
            &format!("pub fn {}", spec.ops[0].name()),
            &format!("fn ref_{}", spec.ops[0].name()),
            1,
        )
        .replacen(
            &format!("pub fn {}", spec.ops[1].name()),
            &format!("fn ref_{}", spec.ops[1].name()),
            1,
        );
    let asserts = spec
        .ops
        .iter()
        .map(|op| {
            let call = call_src(*op, "&vals");
            format!("        assert_eq!({call}, ref_{call});\n")
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "use task::{{{imports}}};\n\
         \n\
         {reference}\
         fn nx(state: &mut u64) -> u64 {{\n\
         \x20   *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20   *state >> 33\n\
         }}\n\
         \n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0104;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let mut vals: Vec<i64> = Vec::new();\n\
         \x20       let n = (nx(&mut state) % 6) + 1;\n\
         \x20       for _ in 0..n {{\n\
         \x20           vals.push((nx(&mut state) % 1001) as i64 - 500);\n\
         \x20       }}\n\
         {asserts}\
         \x20   }}\n\
         }}\n",
        imports = spec
            .ops
            .iter()
            .map(|op| op.name())
            .collect::<Vec<_>>()
            .join(", "),
        reference = reference,
        asserts = asserts,
    )
}

/// Degenerate: everything zero.
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            format!("{sig} {{\n    let _ = xs;\n    0\n}}\n", sig = sig,)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer the wrapping total no matter what was
/// asked. The canonical anchors make every extremum, span, and tie count
/// disagree with the total, so it is inexact on every op and any pair
/// catches it on the canonical example alone.
fn sum_everything(spec: &Spec) -> String {
    let sum_body = [
        "let mut t = 0i64;",
        "for &v in xs {",
        "    t = t.wrapping_add(v);",
        "}",
        "t",
    ]
    .join("\n    ");
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            format!("{sig} {{\n    {sum_body}\n}}\n", sig = sig,)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct MinMaxFamily;

impl Generator for MinMaxFamily {
    fn id(&self) -> &str {
        "minmax"
    }
    fn category(&self) -> &str {
        "order-statistics"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("minmax", seed);

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
            id: format!("minmax/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure integer bookkeeping — no unsafe anywhere near it.
            max_unsafe: None,
            forbidden_paths: Vec::new(),
            check_clippy: false,
            clippy_allow: Vec::new(),
            // Default oracle weights (docs/04).
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
            ("sum-everything".to_string(), sum_everything(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let mut names: Vec<&str> = sample(seed).ops.iter().map(|op| op.name()).collect();
        names.sort_unstable();
        vec![format!("q:{}/{}", names[0], names[1])]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = MinMaxFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Extremes.
        assert_eq!(b_min(&[3, -1, 7]), -1);
        assert_eq!(b_min(&[5]), 5);
        assert_eq!(b_min(&[2, 2]), 2);
        assert_eq!(b_min(&[]), 0);
        assert_eq!(b_max(&[3, -1, 7]), 7);
        assert_eq!(b_max(&[2, 2]), 2);
        assert_eq!(b_max(&[]), 0);
        // Span, saturating at the i64 extremes rather than overflowing.
        assert_eq!(b_range(&[3, -1, 7]), 8);
        assert_eq!(b_range(&[5]), 0);
        assert_eq!(b_range(&[i64::MIN, i64::MAX]), i64::MAX);
        assert_eq!(b_range(&[]), 0);
        // Tie counts.
        assert_eq!(b_num_maxima(&[3, 7, -1, 7]), 2);
        assert_eq!(b_num_maxima(&[5]), 1);
        assert_eq!(b_num_maxima(&[2, 2, 2]), 3);
        assert_eq!(b_num_maxima(&[]), 0);
        assert_eq!(b_num_minima(&[3, -1, 7, -1]), 2);
        assert_eq!(b_num_minima(&[5]), 1);
        assert_eq!(b_num_minima(&[2, 2, 2]), 3);
        assert_eq!(b_num_minima(&[]), 0);
        // The anchor total wraps at the extremes.
        assert_eq!(total_of(&[1, 2, 3]), 6);
        assert_eq!(total_of(&[i64::MAX, 1]), i64::MIN);
        assert_eq!(total_of(&[]), 0);
    }

    #[test]
    fn seeds_vary_query_pairs() {
        let mut sigs = std::collections::HashSet::new();
        for seed in 0..300u64 {
            sigs.insert(sample(seed));
        }
        // C(5,2) = 10 unordered pairs; demand near-full coverage.
        assert!(
            sigs.len() >= 9,
            "expected wide query-pair variety, got {}",
            sigs.len()
        );
    }

    #[test]
    fn canonical_answers_are_non_degenerate_for_every_op() {
        // Both baselines must fail under EVERY pair. The anchors make the
        // canonical bag nonzero on all five answers and the total distinct
        // from each of them, so neither `const-zero` nor `sum-everything`
        // is exact anywhere on it — no skips needed.
        for seed in 0..200u64 {
            let xs = canonical(seed);
            // Anchor facts the sampler enforces.
            assert_ne!(b_min(&xs), 0, "seed {seed}");
            assert_ne!(b_max(&xs), 0, "seed {seed}");
            assert_ne!(b_range(&xs), 0, "seed {seed}");
            assert_eq!(b_num_maxima(&xs), 2, "seed {seed}");
            assert_eq!(b_num_minima(&xs), 2, "seed {seed}");
            for op in OP_ALL {
                let truth = op_eval(op, &xs);
                assert_ne!(truth, 0, "const-zero survives {op:?} seed {seed}");
                assert_ne!(
                    truth,
                    total_of(&xs),
                    "sum-everything survives {op:?} seed {seed}"
                );
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (xs, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, &xs), out, "seed {seed}");
                }
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        for seed in [0u64, 1, 2] {
            let spec = sample(seed);
            let src = reference_src(&spec);
            for op in OP_ALL {
                // Match the `pub fn` line so no bare-name substring leaks.
                let fn_line = format!("pub fn {}", op.name());
                if spec.ops.contains(&op) {
                    assert!(src.contains(&fn_line));
                } else {
                    assert!(!src.contains(&fn_line), "{op:?} leaked");
                }
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        for seed in [0u64, 1, 2] {
            let spec = sample(seed);
            let sk = skeleton_src(&spec, seed);
            assert!(sk.contains("todo!()"), "skeleton must be stubbed");
            // Solution-shaped leak tokens must stay out of the skeleton.
            assert!(!sk.contains(".max("));
            assert!(!sk.contains(".min("));
            assert!(!sk.contains("saturating_sub"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains(".max("));
            assert!(!p.contains(".min("));
            assert!(!p.contains("saturating_sub"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Regression pin in the spirit of fsm's arity check: every op is
        // unary here, so no call site may carry a comma at all.
        for op in OP_ALL {
            let call = call_src(op, "xs");
            assert_eq!(
                call.matches(',').count(),
                op_sig_src(op).matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{}`",
                op_sig_src(op)
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = MinMaxFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
