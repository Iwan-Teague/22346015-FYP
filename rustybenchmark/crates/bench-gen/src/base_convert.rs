//! The `base-convert` family (category `base-representation`) — digit-count
//! queries over one seeded unsigned integer.
//!
//! Where `digits` decomposes the decimal digits of a number, this family
//! asks how the SAME value looks across bases: how many digits it needs in
//! base 2, base 10, and base 16, plus two bit-level shape checks. The
//! domain is one `u64`; every op is a pure function of it. The seed prunes
//! which two of five query ops are required: `num_binary_digits`,
//! `num_decimal_digits`, `num_hex_digits`, `num_set_bits`,
//! `num_trailing_zeros_binary`. C(5,2) = **10 distinct skills**, above the
//! diversity floor; op names are semantic.
//!
//! The canonical input is sampled until its anchor facts hold: a deep
//! trailing-zero run (at least four zero bits), and all five answers
//! pairwise distinct. Those make every answer nonzero (defeating
//! `const-zero` outright — this family has no boolean op) and keep every
//! non-binary op separate from the `bit-length-everything` cheat, which is
//! exact only for `num_binary_digits`; any pair containing it is caught by
//! its partner.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential fuzzes
//! 3000 random inputs against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the
//! canonical input) and `bit-length-everything` (every query answered with
//! the binary digit count).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
// The shared `Num` prefix is semantic (all are counts), not noise.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    NumBinaryDigits,
    NumDecimalDigits,
    NumHexDigits,
    NumSetBits,
    NumTrailingZerosBinary,
}

const OP_ALL: [Op; 5] = [
    Op::NumBinaryDigits,
    Op::NumDecimalDigits,
    Op::NumHexDigits,
    Op::NumSetBits,
    Op::NumTrailingZerosBinary,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::NumBinaryDigits => "num_binary_digits",
            Op::NumDecimalDigits => "num_decimal_digits",
            Op::NumHexDigits => "num_hex_digits",
            Op::NumSetBits => "num_set_bits",
            Op::NumTrailingZerosBinary => "num_trailing_zeros_binary",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::NumBinaryDigits => {
                "how many digits `n` needs when written in base 2; plain \
                 `0` needs one digit"
            }
            Op::NumDecimalDigits => {
                "how many digits `n` needs when written in base 10; plain \
                 `0` needs one digit"
            }
            Op::NumHexDigits => {
                "how many digits `n` needs when written in base 16; plain \
                 `0` needs one digit"
            }
            Op::NumSetBits => "how many bits of `n` are set to 1",
            Op::NumTrailingZerosBinary => {
                "how many zero bits trail the lowest set bit of `n`; plain \
                 `0` yields `0` under this task's convention"
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

fn b_num_binary_digits(n: u64) -> i64 {
    if n == 0 {
        return 1;
    }
    (u64::BITS - n.leading_zeros()) as i64
}

fn b_num_decimal_digits(n: u64) -> i64 {
    if n == 0 {
        return 1;
    }
    let mut m = n;
    let mut d = 0i64;
    while m > 0 {
        d += 1;
        m /= 10;
    }
    d
}

fn b_num_hex_digits(n: u64) -> i64 {
    if n == 0 {
        return 1;
    }
    ((u64::BITS - n.leading_zeros()).div_ceil(4)) as i64
}

fn b_num_set_bits(n: u64) -> i64 {
    n.count_ones() as i64
}

fn b_num_trailing_zeros_binary(n: u64) -> i64 {
    if n == 0 {
        return 0;
    }
    n.trailing_zeros() as i64
}

/// Every op here answers with an `i64`.
type Out = i64;

fn op_eval(op: Op, n: u64) -> Out {
    match op {
        Op::NumBinaryDigits => b_num_binary_digits(n),
        Op::NumDecimalDigits => b_num_decimal_digits(n),
        Op::NumHexDigits => b_num_hex_digits(n),
        Op::NumSetBits => b_num_set_bits(n),
        Op::NumTrailingZerosBinary => b_num_trailing_zeros_binary(n),
    }
}

// ---- canonical input --------------------------------------------------------

/// The canonical input: a value below one million, retried until the anchor
/// facts hold.
///
/// Guaranteed for every seed: at least four trailing zero bits (so the
/// trailing-zero answer is comfortably nonzero), a binary width of at least
/// two digits, and all five answers pairwise distinct. Together those make
/// every op separate from `const-zero` outright and keep every op except
/// the binary count separate from `bit-length-everything`.
fn canonical(seed: u64) -> u64 {
    let mut rng = Rng::new(seed ^ 0xB45E_1A11);
    for _ in 0..100_000 {
        let cand = rng.below(1_000_000);
        if anchors_hold(cand) {
            return cand;
        }
    }
    unreachable!("canonical input sampling failed to satisfy anchors");
}

fn anchors_hold(n: u64) -> bool {
    let bin = b_num_binary_digits(n);
    let dec = b_num_decimal_digits(n);
    let hex = b_num_hex_digits(n);
    let set = b_num_set_bits(n);
    let tz = b_num_trailing_zeros_binary(n);
    bin >= 2
        && tz >= 4
        && bin != dec
        && bin != hex
        && dec != hex
        && set != bin
        && set != dec
        && set != hex
        && set != tz
        && tz != bin
        && tz != dec
        && tz != hex
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (u64, Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_0118);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical input first.
    let can = canonical(seed);
    cases.push((can, spec.ops.map(|op| (op, op_eval(op, can))).to_vec()));
    // Zero: pins every digit-count convention at once (one digit in every
    // base) and the bit conventions (no set bits, no trailing zeros).
    cases.push((0, spec.ops.map(|op| (op, op_eval(op, 0))).to_vec()));
    // Power of two: base-2 width is one past the exponent while the hex
    // count rounds up per nibble.
    let p2 = 1u64 << 20;
    cases.push((p2, spec.ops.map(|op| (op, op_eval(op, p2))).to_vec()));
    // All-ones: maximal width in every base with zero trailing zeros.
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

/// Emitted literal for a call site; the `u64` suffix types the argument.
fn render_u64(n: u64) -> String {
    format!("{n}u64")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let sig = "(n: u64) -> i64";
    let body = match op {
        Op::NumBinaryDigits => [
            "if n == 0 {",
            "    return 1;",
            "}",
            "(u64::BITS - n.leading_zeros()) as i64",
        ]
        .join("\n    "),
        Op::NumDecimalDigits => [
            "if n == 0 {",
            "    return 1;",
            "}",
            "let mut m = n;",
            "let mut d = 0i64;",
            "while m > 0 {",
            "    d += 1;",
            "    m /= 10;",
            "}",
            "d",
        ]
        .join("\n    "),
        Op::NumHexDigits => [
            "if n == 0 {",
            "    return 1;",
            "}",
            "((u64::BITS - n.leading_zeros() + 3) / 4) as i64",
        ]
        .join("\n    "),
        Op::NumSetBits => ["n.count_ones() as i64"].join("\n    "),
        Op::NumTrailingZerosBinary => [
            "if n == 0 {",
            "    return 0;",
            "}",
            "n.trailing_zeros() as i64",
        ]
        .join("\n    "),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!("pub fn {}(n: u64) -> i64 {{\n    todo!()\n}}\n", op.name())
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(n: u64) -> i64", op.name())
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
            .map(|(op, out)| format!("{} = {}", op.name(), out))
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
         given as `n`, a single non-negative integer of type `u64`; \
         queries are representation checks across bases.\n\
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0118;\n\
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

/// Degenerate: everything zero.
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            format!("{sig} {{\n    let _ = n;\n    0\n}}\n", sig = sig,)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer the base-2 width no matter what was asked.
/// The canonical anchors make the decimal/hex widths, popcount, and
/// trailing-zero run all disagree with it; `num_binary_digits` itself is
/// exact, and any pair containing it is caught by its partner.
fn bit_length_everything(spec: &Spec) -> String {
    let bin_body = [
        "if n == 0 {",
        "    return 1;",
        "}",
        "(u64::BITS - n.leading_zeros()) as i64",
    ]
    .join("\n    ");
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            format!("{sig} {{\n    {bin_body}\n}}\n", sig = sig,)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct BaseConvertFamily;

impl Generator for BaseConvertFamily {
    fn id(&self) -> &str {
        "base-convert"
    }
    fn category(&self) -> &str {
        "base-representation"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("base-convert", seed);

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
            id: format!("base-convert/{seed:016x}"),
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
                "bit-length-everything".to_string(),
                bit_length_everything(&spec),
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

    /// The `bit-length-everything` cheat's answer for one op.
    fn bit_len(n: u64) -> i64 {
        b_num_binary_digits(n)
    }

    #[test]
    fn generation_is_deterministic() {
        let g = BaseConvertFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Base-2 width via bit length.
        assert_eq!(b_num_binary_digits(0), 1);
        assert_eq!(b_num_binary_digits(1), 1);
        assert_eq!(b_num_binary_digits(2), 2);
        assert_eq!(b_num_binary_digits(5), 3);
        assert_eq!(b_num_binary_digits(u64::MAX), 64);
        // Base-10 width via division.
        assert_eq!(b_num_decimal_digits(0), 1);
        assert_eq!(b_num_decimal_digits(9), 1);
        assert_eq!(b_num_decimal_digits(10), 2);
        assert_eq!(b_num_decimal_digits(u64::MAX), 20);
        // Base-16 width rounds up per nibble.
        assert_eq!(b_num_hex_digits(0), 1);
        assert_eq!(b_num_hex_digits(15), 1);
        assert_eq!(b_num_hex_digits(16), 2);
        assert_eq!(b_num_hex_digits(255), 2);
        assert_eq!(b_num_hex_digits(256), 3);
        assert_eq!(b_num_hex_digits(u64::MAX), 16);
        // Popcount.
        assert_eq!(b_num_set_bits(0), 0);
        assert_eq!(b_num_set_bits(255), 8);
        assert_eq!(b_num_set_bits(u64::MAX), 64);
        // Trailing zeros, with the task's own zero convention.
        assert_eq!(b_num_trailing_zeros_binary(0), 0);
        assert_eq!(b_num_trailing_zeros_binary(1), 0);
        assert_eq!(b_num_trailing_zeros_binary(2), 1);
        assert_eq!(b_num_trailing_zeros_binary(48), 4);
        assert_eq!(b_num_trailing_zeros_binary(1 << 63), 63);
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
        // Both baselines must fail under EVERY pair. The anchors make all
        // five answers pairwise distinct and nonzero on the canonical input,
        // so `const-zero` separates everywhere and the base-2 width is
        // distinct from every other answer — `bit-length-everything` is
        // exact only on `num_binary_digits`, whose pairs its partner catches.
        for seed in 0..200u64 {
            let n = canonical(seed);
            let answers: Vec<i64> = OP_ALL.map(|op| op_eval(op, n)).to_vec();
            // Anchor facts the sampler enforces: nonzero and pairwise
            // distinct across ALL five ops.
            for (i, a) in answers.iter().enumerate() {
                assert_ne!(*a, 0, "op {:?} zero on canonical, seed {seed}", OP_ALL[i]);
                for b in &answers[i + 1..] {
                    assert_ne!(a, b, "collision on canonical, seed {seed}");
                }
            }
            for op in OP_ALL {
                let truth = op_eval(op, n);
                if matches!(op, Op::NumBinaryDigits) {
                    continue;
                }
                assert_ne!(
                    truth,
                    bit_len(n),
                    "bit-length-everything survives {op:?} seed {seed}"
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
            assert!(!sk.contains(".count_ones("));
            assert!(!sk.contains(".leading_zeros("));
            assert!(!sk.contains(".trailing_zeros("));
            assert!(!sk.contains("/= 10"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains(".count_ones("));
            assert!(!p.contains(".leading_zeros("));
            assert!(!p.contains(".trailing_zeros("));
            assert!(!p.contains("/= 10"));
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
        let g = BaseConvertFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
