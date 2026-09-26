//! The `digitroot` family (category `digit-reduction`) — digit-sum
//! reduction queries over one seeded non-negative integer.
//!
//! Where `digits` decomposes an integer into its digits and `base_convert`
//! measures its width across bases, this family exercises **iterated
//! digit reduction**: the digital root, the number of reduction rounds,
//! one pass of the digit sum, the decimal width, and whether the input is
//! already a single digit. The domain is one `u64`; every op is a pure
//! function of it. The seed prunes which two of five query ops are
//! required: `digital_root`, `additive_persistence`, `digit_sum_once`,
//! `is_single_digit`, `num_digits`. C(5,2) = **10 distinct skills**,
//! above the diversity floor; op names are semantic.
//!
//! The canonical input is sampled until its anchor facts hold: at least
//! two digits (so the persistence is positive and every scalar answer is
//! nonzero), and the digital root, the round count, and the width all
//! distinct from the one-pass digit sum. Those make `const-zero` fail on
//! every scalar and keep the `digit-sum-everything` cheat exact only on
//! `digit_sum_once` itself; any pair containing it is caught by its
//! partner, and pairs without it are wrong twice over. The boolean
//! `is_single_digit` is false on the canonical input (where both cheats'
//! hardcoded `false` agrees) and flipped by the pinned single-digit
//! example.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential fuzzes
//! 3000 random inputs against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the
//! canonical input) and `digit-sum-everything` (every query answered with
//! the one-pass digit sum).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    DigitalRoot,
    AdditivePersistence,
    DigitSumOnce,
    IsSingleDigit,
    NumDigits,
}

const OP_ALL: [Op; 5] = [
    Op::DigitalRoot,
    Op::AdditivePersistence,
    Op::DigitSumOnce,
    Op::IsSingleDigit,
    Op::NumDigits,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::DigitalRoot => "digital_root",
            Op::AdditivePersistence => "additive_persistence",
            Op::DigitSumOnce => "digit_sum_once",
            Op::IsSingleDigit => "is_single_digit",
            Op::NumDigits => "num_digits",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::DigitalRoot => {
                "the digital root of `n`: repeat the digit sum until a \
                 single digit remains; `0` stays `0`"
            }
            Op::AdditivePersistence => {
                "how many digit-sum rounds it takes for `n` to reach a \
                 single digit; a single digit needs none"
            }
            Op::DigitSumOnce => {
                "the sum of the decimal digits of `n`, computed once \
                 without repeating"
            }
            Op::IsSingleDigit => "whether `n` already has just one digit",
            Op::NumDigits => "how many digits `n` has in base ten; zero counts as one",
        }
    }

    /// Return type used in signatures, stubs, and the prompt fence.
    fn ret(self) -> &'static str {
        match self {
            Op::IsSingleDigit => "bool",
            _ => "i64",
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

fn b_digital_root(n: u64) -> i64 {
    let mut m = n;
    while m >= 10 {
        let mut s = 0u64;
        while m > 0 {
            s += m % 10;
            m /= 10;
        }
        m = s;
    }
    m as i64
}

fn b_additive_persistence(n: u64) -> i64 {
    let mut m = n;
    let mut rounds = 0i64;
    while m >= 10 {
        let mut s = 0u64;
        while m > 0 {
            s += m % 10;
            m /= 10;
        }
        m = s;
        rounds += 1;
    }
    rounds
}

fn b_digit_sum_once(n: u64) -> i64 {
    let mut m = n;
    let mut s = 0u64;
    while m > 0 {
        s += m % 10;
        m /= 10;
    }
    s as i64
}

fn b_is_single_digit(n: u64) -> bool {
    n < 10
}

fn b_num_digits(n: u64) -> i64 {
    let mut m = n;
    let mut d = 1i64;
    while m >= 10 {
        d += 1;
        m /= 10;
    }
    d
}

/// One op's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Flag(bool),
}

impl Out {
    /// The literal rendered into an emitted assertion.
    fn lit(self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            Out::Flag(b) => b.to_string(),
        }
    }
}

fn op_eval(op: Op, n: u64) -> Out {
    match op {
        Op::DigitalRoot => Out::Num(b_digital_root(n)),
        Op::AdditivePersistence => Out::Num(b_additive_persistence(n)),
        Op::DigitSumOnce => Out::Num(b_digit_sum_once(n)),
        Op::IsSingleDigit => Out::Flag(b_is_single_digit(n)),
        Op::NumDigits => Out::Num(b_num_digits(n)),
    }
}

// ---- canonical input --------------------------------------------------------

/// The canonical input: a value below one million, retried until the
/// anchor facts hold.
///
/// Guaranteed for every seed: at least two digits (so the round count is
/// positive and every scalar answer is nonzero), and the digital root,
/// round count, and width all distinct from the one-pass digit sum. Those
/// make `const-zero` fail on every scalar outright and keep
/// `digit-sum-everything` exact only on `digit_sum_once`.
fn canonical(seed: u64) -> u64 {
    let mut rng = Rng::new(seed ^ 0xD007_27A7);
    for _ in 0..100_000 {
        let cand = rng.below(1_000_000);
        if anchors_hold(cand) {
            return cand;
        }
    }
    unreachable!("canonical input sampling failed to satisfy anchors");
}

fn anchors_hold(n: u64) -> bool {
    n >= 10
        && b_digital_root(n) != b_digit_sum_once(n)
        && b_additive_persistence(n) != b_digit_sum_once(n)
        && b_num_digits(n) != b_digit_sum_once(n)
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (u64, Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_011C);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical input first.
    let can = canonical(seed);
    cases.push((can, spec.ops.map(|op| (op, op_eval(op, can))).to_vec()));
    // Zero: pins every zero convention at once (and flips both cheats'
    // hardcoded `false` on the flag).
    cases.push((0, spec.ops.map(|op| (op, op_eval(op, 0))).to_vec()));
    // A single digit: the root is the input, the persistence is none,
    // and the boolean flips to true.
    cases.push((7, spec.ops.map(|op| (op, op_eval(op, 7))).to_vec()));
    // Maximal width corner: twenty digits summing to 87.
    cases.push((
        u64::MAX,
        spec.ops.map(|op| (op, op_eval(op, u64::MAX))).to_vec(),
    ));
    for _ in 0..3 {
        let v = rng.below(1_000_000);
        let outs = spec.ops.map(|op| (op, op_eval(op, v))).to_vec();
        cases.push((v, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the suffix types it as `u64`.
fn render_u64(n: u64) -> String {
    format!("{n}u64")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let sig = match op.ret() {
        "bool" => "(n: u64) -> bool",
        _ => "(n: u64) -> i64",
    };
    let body = match op {
        Op::DigitalRoot => [
            "let mut m = n;",
            "while m >= 10 {",
            "    let mut s = 0u64;",
            "    while m > 0 {",
            "        s += m % 10;",
            "        m /= 10;",
            "    }",
            "    m = s;",
            "}",
            "m as i64",
        ]
        .join("\n    "),
        Op::AdditivePersistence => [
            "let mut m = n;",
            "let mut rounds = 0i64;",
            "while m >= 10 {",
            "    let mut s = 0u64;",
            "    while m > 0 {",
            "        s += m % 10;",
            "        m /= 10;",
            "    }",
            "    m = s;",
            "    rounds += 1;",
            "}",
            "rounds",
        ]
        .join("\n    "),
        Op::DigitSumOnce => [
            "let mut m = n;",
            "let mut s = 0u64;",
            "while m > 0 {",
            "    s += m % 10;",
            "    m /= 10;",
            "}",
            "s as i64",
        ]
        .join("\n    "),
        Op::IsSingleDigit => ["n < 10"].join("\n    "),
        Op::NumDigits => [
            "let mut m = n;",
            "let mut d = 1i64;",
            "while m >= 10 {",
            "    d += 1;",
            "    m /= 10;",
            "}",
            "d",
        ]
        .join("\n    "),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    let sig = match op.ret() {
        "bool" => "(n: u64) -> bool",
        _ => "(n: u64) -> i64",
    };
    format!("pub fn {}{sig} {{\n    todo!()\n}}\n", op.name(), sig = sig,)
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(n: u64) -> {}", op.name(), op.ret())
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
    for (n, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  n {}  ->  {}\n", render_u64(n), results));
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
         given as `n`, one non-negative integer of type `u64`; queries are \
         digit-reduction properties of it.\n\
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
    for (i, (n, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let n = {};\n",
            render_u64(*n),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "n"),
                out.lit(),
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
            let call = call_src(*op, "n");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_011C;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let n = nx(&mut state) % 100000;\n\
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
/// Degenerate: everything zero (and a hardcoded `false` on the boolean).
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => format!("{sig} {{\n    let _ = n;\n    false\n}}\n"),
                _ => format!("{sig} {{\n    let _ = n;\n    0\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer the one-pass digit sum no matter what was
/// asked. The canonical anchors make the root, round count, and width all
/// disagree with it; `digit_sum_once` itself is exact, and any pair
/// containing it is caught by its partner.
fn digit_sum_everything(spec: &Spec) -> String {
    let sum_body = [
        "let mut m = n;",
        "let mut s = 0u64;",
        "while m > 0 {",
        "    s += m % 10;",
        "    m /= 10;",
        "}",
        "s as i64",
    ]
    .join("\n    ");
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => format!("{sig} {{\n    let _ = n;\n    false\n}}\n"),
                _ => format!("{sig} {{\n    {sum_body}\n}}\n", sig = sig,),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct DigitRootFamily;

impl Generator for DigitRootFamily {
    fn id(&self) -> &str {
        "digitroot"
    }
    fn category(&self) -> &str {
        "digit-reduction"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("digitroot", seed);

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
            id: format!("digitroot/{seed:016x}"),
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
            (
                "digit-sum-everything".to_string(),
                digit_sum_everything(&spec),
            ),
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
        let g = DigitRootFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Digital root collapses to one digit.
        assert_eq!(b_digital_root(9875), 2); // 29 -> 11 -> 2
        assert_eq!(b_digital_root(38), 2);
        assert_eq!(b_digital_root(7), 7);
        assert_eq!(b_digital_root(0), 0);
        assert_eq!(b_digital_root(81), 9);
        // Round count.
        assert_eq!(b_additive_persistence(9875), 3);
        assert_eq!(b_additive_persistence(38), 2);
        assert_eq!(b_additive_persistence(7), 0);
        assert_eq!(b_additive_persistence(0), 0);
        assert_eq!(b_additive_persistence(u64::MAX), 3);
        // One pass of the digit sum.
        assert_eq!(b_digit_sum_once(9875), 29);
        assert_eq!(b_digit_sum_once(38), 11);
        assert_eq!(b_digit_sum_once(7), 7);
        assert_eq!(b_digit_sum_once(0), 0);
        assert_eq!(b_digit_sum_once(u64::MAX), 87);
        // Single-digit check, boundary inclusive at both ends.
        assert!(b_is_single_digit(0));
        assert!(b_is_single_digit(9));
        assert!(!b_is_single_digit(10));
        assert!(!b_is_single_digit(9875));
        // Decimal width.
        assert_eq!(b_num_digits(0), 1);
        assert_eq!(b_num_digits(7), 1);
        assert_eq!(b_num_digits(38), 2);
        assert_eq!(b_num_digits(9875), 4);
        assert_eq!(b_num_digits(1_000_000), 7);
        assert_eq!(b_num_digits(u64::MAX), 20);
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
        // Both baselines must fail under EVERY pair. The anchors keep the
        // canonical input multi-digit (positive persistence, nonzero
        // scalars) with root/rounds/width all distinct from the one-pass
        // digit sum, so `const-zero` separates on every scalar and
        // `digit-sum-everything` is exact only on `digit_sum_once` — pairs
        // carrying it are caught by their partner. The boolean is false on
        // the canonical input (where the cheats' hardcoded `false`
        // agrees); it flips on the pinned single-digit example instead.
        for seed in 0..200u64 {
            let n = canonical(seed);
            assert!(n >= 10, "seed {seed}");
            assert!(!b_is_single_digit(n), "seed {seed}");
            let dso = b_digit_sum_once(n);
            for op in OP_ALL {
                if matches!(op, Op::DigitSumOnce | Op::IsSingleDigit) {
                    continue;
                }
                let truth = match op_eval(op, n) {
                    Out::Num(v) => v,
                    Out::Flag(_) => unreachable!("only scalars here"),
                };
                assert_ne!(truth, 0, "const-zero survives {op:?} seed {seed}");
                assert_ne!(
                    truth, dso,
                    "digit-sum-everything survives {op:?} seed {seed}"
                );
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (n, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, n), out, "seed {seed}");
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
            assert!(!sk.contains("% 10"));
            assert!(!sk.contains("/ 10"));
            assert!(!sk.contains(">= 10"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("% 10"));
            assert!(!p.contains("/ 10"));
            assert!(!p.contains(">= 10"));
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
            let call = call_src(op, "n");
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
        let g = DigitRootFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
