//! The `parity` family (category `slice-aggregates`) — reduction queries
//! over a seeded bag of unsigned integers.
//!
//! Where `digits` decomposes one integer and `poly` indexes coefficient
//! slots, this family exercises **whole-slice reductions**: counting
//! predicates, a wrapping total, a fold-xor, and a popcount roll-up. The
//! domain is one `&[u64]` bag; every op is a pure function of it. The seed
//! prunes which two of five query ops are required: `num_even`, `num_odd`,
//! `sum`, `xor_all`, `count_set_bits`. C(5,2) = **10 distinct skills**,
//! above the diversity floor; op names are semantic.
//!
//! The canonical bag is sampled until its anchor facts hold: at least one
//! even and one odd element, a nonzero total, a nonzero fold-xor, and a
//! total distinct from every count/xor/popcount answer. Those make all
//! five answers nonzero (defeating `const-zero` outright — this family has
//! no boolean op) and separate four of the five ops from the
//! `sum-everything` cheat, which is exact only for `sum`; any pair
//! containing it is caught by its partner.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential fuzzes
//! 3000 random bags against the model.
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
    NumEven,
    NumOdd,
    Sum,
    XorAll,
    CountSetBits,
}

const OP_ALL: [Op; 5] = [
    Op::NumEven,
    Op::NumOdd,
    Op::Sum,
    Op::XorAll,
    Op::CountSetBits,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::NumEven => "num_even",
            Op::NumOdd => "num_odd",
            Op::Sum => "sum",
            Op::XorAll => "xor_all",
            Op::CountSetBits => "count_set_bits",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::NumEven => "how many elements of `xs` are even; an empty bag has none",
            Op::NumOdd => "how many elements of `xs` are odd; an empty bag has none",
            Op::Sum => {
                "the total of all elements, wrapping on overflow; an empty \
                 bag totals 0"
            }
            Op::XorAll => {
                "the fold-xor of all elements: bits set in an odd number of \
                 them survive; an empty bag xors to 0"
            }
            Op::CountSetBits => {
                "the total number of set bits across every element; an \
                 empty bag has none"
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

fn b_num_even(xs: &[u64]) -> i64 {
    let mut n = 0i64;
    for &v in xs {
        if v % 2 == 0 {
            n += 1;
        }
    }
    n
}

fn b_num_odd(xs: &[u64]) -> i64 {
    let mut n = 0i64;
    for &v in xs {
        if v % 2 != 0 {
            n += 1;
        }
    }
    n
}

fn b_sum(xs: &[u64]) -> i64 {
    let mut t = 0i64;
    for &v in xs {
        t = t.wrapping_add(v as i64);
    }
    t
}

fn b_xor_all(xs: &[u64]) -> i64 {
    let mut acc = 0i64;
    for &v in xs {
        acc ^= v as i64;
    }
    acc
}

fn b_count_set_bits(xs: &[u64]) -> i64 {
    let mut n = 0i64;
    for &v in xs {
        n += v.count_ones() as i64;
    }
    n
}

/// Every op here answers with an `i64`.
type Out = i64;

fn op_eval(op: Op, xs: &[u64]) -> Out {
    match op {
        Op::NumEven => b_num_even(xs),
        Op::NumOdd => b_num_odd(xs),
        Op::Sum => b_sum(xs),
        Op::XorAll => b_xor_all(xs),
        Op::CountSetBits => b_count_set_bits(xs),
    }
}

// ---- canonical bag ----------------------------------------------------------

/// The canonical bag: two to six values below one million, retried until
/// the anchor facts hold.
///
/// Guaranteed for every seed: at least one even and one odd element (so
/// both counts are positive), a nonzero total, a nonzero fold-xor, and a
/// total distinct from each of the other four answers. Together those make
/// every op separate from `const-zero` and keep `sum-everything` exact only
/// on `sum` itself.
fn canonical(seed: u64) -> Vec<u64> {
    let mut rng = Rng::new(seed ^ 0x0DD_BA11);
    for _ in 0..100_000 {
        let len = 2 + rng.below(5) as usize;
        let cand: Vec<u64> = (0..len).map(|_| rng.below(1_000_000)).collect();
        if anchors_hold(&cand) {
            return cand;
        }
    }
    unreachable!("canonical bag sampling failed to satisfy anchors");
}

fn anchors_hold(xs: &[u64]) -> bool {
    b_num_even(xs) >= 1
        && b_num_odd(xs) >= 1
        && b_sum(xs) != 0
        && b_xor_all(xs) != 0
        && b_sum(xs) != b_num_even(xs)
        && b_sum(xs) != b_num_odd(xs)
        && b_sum(xs) != b_xor_all(xs)
        && b_sum(xs) != b_count_set_bits(xs)
}

// ---- worked examples --------------------------------------------------------

type ExampleCase = (Vec<u64>, Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_00F1);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical bag first.
    let can = canonical(seed);
    cases.push((
        can.clone(),
        spec.ops.map(|op| (op, op_eval(op, &can))).to_vec(),
    ));
    // Empty bag: pins every zero convention at once.
    cases.push((vec![], spec.ops.map(|op| (op, op_eval(op, &[]))).to_vec()));
    // Wrap corner: u64::MAX plus 1 totals back to 0 while the xor stays
    // huge and the popcount rolls to 65.
    cases.push((
        vec![u64::MAX, 1],
        spec.ops
            .map(|op| (op, op_eval(op, &[u64::MAX, 1])))
            .to_vec(),
    ));
    for _ in 0..3 {
        let len = 1 + rng.below(6) as usize;
        let v: Vec<u64> = (0..len).map(|_| rng.below(1_000_000)).collect();
        let outs = spec.ops.map(|op| (op, op_eval(op, &v))).to_vec();
        cases.push((v, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the first-element suffix types the
/// whole slice, and the empty form is typed by the function signature.
fn render_u64s(xs: &[u64]) -> String {
    if xs.is_empty() {
        return "&[]".to_string();
    }
    let items = xs
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!("&[{items}u64]")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let sig = "(xs: &[u64]) -> i64";
    let body = match op {
        Op::NumEven => [
            "let mut n = 0i64;",
            "for &v in xs {",
            "    if v % 2 == 0 {",
            "        n += 1;",
            "    }",
            "}",
            "n",
        ]
        .join("\n    "),
        Op::NumOdd => [
            "let mut n = 0i64;",
            "for &v in xs {",
            "    if v % 2 != 0 {",
            "        n += 1;",
            "    }",
            "}",
            "n",
        ]
        .join("\n    "),
        Op::Sum => [
            "let mut t = 0i64;",
            "for &v in xs {",
            "    t = t.wrapping_add(v as i64);",
            "}",
            "t",
        ]
        .join("\n    "),
        Op::XorAll => [
            "let mut acc = 0i64;",
            "for &v in xs {",
            "    acc ^= v as i64;",
            "}",
            "acc",
        ]
        .join("\n    "),
        Op::CountSetBits => [
            "let mut n = 0i64;",
            "for &v in xs {",
            "    n += v.count_ones() as i64;",
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
        "pub fn {}(xs: &[u64]) -> i64 {{\n    todo!()\n}}\n",
        op.name()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(xs: &[u64]) -> i64", op.name())
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
        s.push_str(&format!("  xs {}  ->  {}\n", render_u64s(&xs), results));
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
         given as `xs`, a slice of non-negative integers of type `u64`; \
         queries are reductions over the whole slice.\n\
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
            render_u64s(xs),
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_00F2;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let mut vals: Vec<u64> = Vec::new();\n\
         \x20       let n = (nx(&mut state) % 6) + 1;\n\
         \x20       for _ in 0..n {{\n\
         \x20           vals.push(nx(&mut state) % 1000);\n\
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
/// asked. The canonical anchors make the counts, xor, and popcount
/// disagree with the total; `sum` itself is exact, and any pair containing
/// it is caught by its partner.
fn sum_everything(spec: &Spec) -> String {
    let sum_body = [
        "let mut t = 0i64;",
        "for &v in xs {",
        "    t = t.wrapping_add(v as i64);",
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

pub struct ParityFamily;

impl Generator for ParityFamily {
    fn id(&self) -> &str {
        "parity"
    }
    fn category(&self) -> &str {
        "slice-aggregates"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("parity", seed);

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
            id: format!("parity/{seed:016x}"),
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
        let g = ParityFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Even count: zero counts as even.
        assert_eq!(b_num_even(&[1, 2, 3, 4, 6]), 3);
        assert_eq!(b_num_even(&[1, 3, 5]), 0);
        assert_eq!(b_num_even(&[0]), 1);
        assert_eq!(b_num_even(&[]), 0);
        // Odd count.
        assert_eq!(b_num_odd(&[1, 2, 3, 4, 7]), 3);
        assert_eq!(b_num_odd(&[2, 4, 8]), 0);
        assert_eq!(b_num_odd(&[]), 0);
        // Total wraps: MAX + 1 lands back on 0.
        assert_eq!(b_sum(&[1, 2, 3, 4]), 10);
        assert_eq!(b_sum(&[u64::MAX, 1]), 0);
        assert_eq!(b_sum(&[]), 0);
        // Fold-xor keeps bits set an odd number of times.
        assert_eq!(b_xor_all(&[1, 2, 1]), 2);
        assert_eq!(b_xor_all(&[u64::MAX, u64::MAX]), 0);
        assert_eq!(b_xor_all(&[]), 0);
        // Popcount roll-up.
        assert_eq!(b_count_set_bits(&[1, 2, 3]), 4); // 1+1+2
        assert_eq!(b_count_set_bits(&[u64::MAX, 1]), 65);
        assert_eq!(b_count_set_bits(&[]), 0);
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
        // canonical bag nonzero on all five answers (this family has no
        // boolean op, so const-zero separates everywhere), and
        // `sum-everything` is exact only for `sum` — pairs carrying it are
        // caught by their partner scalar.
        for seed in 0..200u64 {
            let xs = canonical(seed);
            // Anchor facts the sampler enforces.
            assert!(b_num_even(&xs) >= 1, "seed {seed}");
            assert!(b_num_odd(&xs) >= 1, "seed {seed}");
            assert_ne!(b_sum(&xs), 0, "seed {seed}");
            assert_ne!(b_xor_all(&xs), 0, "seed {seed}");
            assert_ne!(b_sum(&xs), b_num_even(&xs), "seed {seed}");
            assert_ne!(b_sum(&xs), b_num_odd(&xs), "seed {seed}");
            assert_ne!(b_sum(&xs), b_xor_all(&xs), "seed {seed}");
            assert_ne!(b_sum(&xs), b_count_set_bits(&xs), "seed {seed}");
            for op in OP_ALL {
                let truth = op_eval(op, &xs);
                assert_ne!(truth, 0, "const-zero survives {op:?} seed {seed}");
                if matches!(op, Op::Sum) {
                    continue;
                }
                assert_ne!(
                    truth,
                    b_sum(&xs),
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
            assert!(!sk.contains("% 2"));
            assert!(!sk.contains("^="));
            assert!(!sk.contains("wrapping_add"));
            assert!(!sk.contains("count_ones"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("% 2"));
            assert!(!p.contains("^="));
            assert!(!p.contains("wrapping_add"));
            assert!(!p.contains("count_ones"));
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
        let g = ParityFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
