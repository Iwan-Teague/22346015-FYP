//! The `hamming` family (category `bit-comparison`) — bit-level
//! comparison queries over one seeded pair of unsigned integers.
//!
//! Where `bitset` inspects one value's own bits, this family compares
//! **two** values position by position: the Hamming distance between
//! them, each side's popcount, the bits shared by both, and the bits
//! set in either. The domain is a pair `(x, y)` of `u64`; every op is a
//! pure function of it. The seed prunes which two of five query ops are
//! required: `hamming_distance`, `popcount_a`, `popcount_b`,
//! `bits_in_common`, `bits_in_either`. C(5,2) = **10 distinct skills**,
//! above the diversity floor; op names are semantic.
//!
//! The canonical pair is sampled until its anchor facts hold: the pair
//! disagrees somewhere (positive distance) yet shares at least one set
//! bit, both sides carry a set bit, and every answer stays distinct from
//! the distance. Those make `const-zero` fail on every scalar and keep
//! the `xor-everything` cheat exact only on `hamming_distance` itself;
//! any pair containing it is caught by its partner, and pairs without
//! it are wrong twice over.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random pairs against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the
//! canonical pair) and `xor-everything` (every query answered with the
//! Hamming distance).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    HammingDistance,
    PopcountA,
    PopcountB,
    BitsInCommon,
    BitsInEither,
}

const OP_ALL: [Op; 5] = [
    Op::HammingDistance,
    Op::PopcountA,
    Op::PopcountB,
    Op::BitsInCommon,
    Op::BitsInEither,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::HammingDistance => "hamming_distance",
            Op::PopcountA => "popcount_a",
            Op::PopcountB => "popcount_b",
            Op::BitsInCommon => "bits_in_common",
            Op::BitsInEither => "bits_in_either",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::HammingDistance => {
                "how many bit positions hold different values across the \
                 two inputs"
            }
            Op::PopcountA => "how many one-bits the first input holds",
            Op::PopcountB => "how many one-bits the second input holds",
            Op::BitsInCommon => "how many positions hold a one-bit in both inputs at once",
            Op::BitsInEither => {
                "how many positions hold a one-bit in at least one of the \
                 two inputs"
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

fn b_hamming_distance(x: u64, y: u64) -> i64 {
    (x ^ y).count_ones() as i64
}

fn b_popcount_a(x: u64, y: u64) -> i64 {
    let _ = y;
    x.count_ones() as i64
}

fn b_popcount_b(x: u64, y: u64) -> i64 {
    let _ = x;
    y.count_ones() as i64
}

fn b_bits_in_common(x: u64, y: u64) -> i64 {
    (x & y).count_ones() as i64
}

fn b_bits_in_either(x: u64, y: u64) -> i64 {
    (x | y).count_ones() as i64
}

/// One op's answer. Every op here is a scalar count, so the answer type
/// is a plain `i64` — no enum needed.
type Out = i64;

fn op_eval(op: Op, x: u64, y: u64) -> Out {
    match op {
        Op::HammingDistance => b_hamming_distance(x, y),
        Op::PopcountA => b_popcount_a(x, y),
        Op::PopcountB => b_popcount_b(x, y),
        Op::BitsInCommon => b_bits_in_common(x, y),
        Op::BitsInEither => b_bits_in_either(x, y),
    }
}

// ---- canonical input --------------------------------------------------------

/// The canonical pair: two values below one million, retried until the
/// anchor facts hold.
///
/// Guaranteed for every seed: the pair disagrees somewhere (positive
/// distance), both sides carry at least one set bit, the pair shares at
/// least one set bit, and every answer stays distinct from the distance.
/// Those make `const-zero` fail on every scalar outright and keep
/// `xor-everything` exact only on `hamming_distance`.
fn canonical(seed: u64) -> (u64, u64) {
    let mut rng = Rng::new(seed ^ 0x4A4D_4D11);
    for _ in 0..100_000 {
        let x = rng.below(1_000_000);
        let y = rng.below(1_000_000);
        if anchors_hold(x, y) {
            return (x, y);
        }
    }
    unreachable!("canonical input sampling failed to satisfy anchors");
}

fn anchors_hold(x: u64, y: u64) -> bool {
    let d = b_hamming_distance(x, y);
    d >= 1
        && b_popcount_a(x, y) >= 1
        && b_popcount_b(x, y) >= 1
        && b_bits_in_common(x, y) >= 1
        && b_popcount_a(x, y) != d
        && b_popcount_b(x, y) != d
        && b_bits_in_common(x, y) != d
        && b_bits_in_either(x, y) != d
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = ((u64, u64), Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_011E);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical pair first.
    let can = canonical(seed);
    cases.push((
        can,
        spec.ops.map(|op| (op, op_eval(op, can.0, can.1))).to_vec(),
    ));
    // All-zero pair: pins every zero convention at once.
    cases.push(((0, 0), spec.ops.map(|op| (op, op_eval(op, 0, 0))).to_vec()));
    // Maximal asymmetry: all ones against zero.
    cases.push((
        (u64::MAX, 0),
        spec.ops.map(|op| (op, op_eval(op, u64::MAX, 0))).to_vec(),
    ));
    // Identical pair: the distance collapses to zero while both
    // popcounts stay positive.
    cases.push(((9, 9), spec.ops.map(|op| (op, op_eval(op, 9, 9))).to_vec()));
    for _ in 0..3 {
        let p = (rng.below(1_000_000), rng.below(1_000_000));
        let outs = spec.ops.map(|op| (op, op_eval(op, p.0, p.1))).to_vec();
        cases.push((p, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the suffix types the first element.
fn render_pair(p: &(u64, u64)) -> String {
    format!("({}u64, {})", p.0, p.1)
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let body = match op {
        Op::HammingDistance => ["(x ^ y).count_ones() as i64"].join("\n    "),
        Op::PopcountA => ["let _ = y;", "x.count_ones() as i64"].join("\n    "),
        Op::PopcountB => ["let _ = x;", "y.count_ones() as i64"].join("\n    "),
        Op::BitsInCommon => ["(x & y).count_ones() as i64"].join("\n    "),
        Op::BitsInEither => ["(x | y).count_ones() as i64"].join("\n    "),
    };
    format!("pub fn {name}(x: u64, y: u64) -> i64 {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(x: u64, y: u64) -> i64 {{\n    todo!()\n}}\n",
        op.name()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(x: u64, y: u64) -> i64", op.name())
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
    for (pair, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  inputs {}  ->  {}\n",
            render_pair(&pair),
            results
        ));
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
         given as two unsigned integers `x` and `y`, each of type `u64`; \
         queries are bit-level comparison properties of the pair.\n\
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
    for (i, (pair, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let (x, y) = {};\n",
            render_pair(pair),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "x, y"),
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
            let call = call_src(*op, "x, y");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_011E;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let x = nx(&mut state) % 1000;\n\
         \x20       let y = nx(&mut state) % 1000;\n\
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
            format!(
                "{} {{\n    let _ = x;\n    let _ = y;\n    0\n}}\n",
                op_sig_src(*op)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer the Hamming distance no matter what was
/// asked. The canonical anchors keep every other answer distinct from it;
/// `hamming_distance` itself is exact, and any pair containing it is
/// caught by its partner.
fn xor_everything(spec: &Spec) -> String {
    let dist_body = "(x ^ y).count_ones() as i64";
    spec.ops
        .iter()
        .map(|op| format!("{} {{\n    {}\n}}\n", op_sig_src(*op), dist_body))
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct HammingFamily;

impl Generator for HammingFamily {
    fn id(&self) -> &str {
        "hamming"
    }
    fn category(&self) -> &str {
        "bit-comparison"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("hamming", seed);

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
            id: format!("hamming/{seed:016x}"),
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
            ("xor-everything".to_string(), xor_everything(&spec)),
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
        let g = HammingFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Distance counts differing positions.
        assert_eq!(b_hamming_distance(5, 2), 3);
        assert_eq!(b_hamming_distance(7, 7), 0);
        assert_eq!(b_hamming_distance(0, 1), 1);
        assert_eq!(b_hamming_distance(u64::MAX, 0), 64);
        assert_eq!(b_hamming_distance(0, 0), 0);
        // Per-side popcounts ignore the other input.
        assert_eq!(b_popcount_a(9, 21), 2);
        assert_eq!(b_popcount_b(9, 21), 3);
        assert_eq!(b_popcount_a(0, u64::MAX), 0);
        assert_eq!(b_popcount_b(u64::MAX, 0), 0);
        // Shared and union bits.
        assert_eq!(b_bits_in_common(12, 10), 1);
        assert_eq!(b_bits_in_common(7, 8), 0);
        assert_eq!(b_bits_in_common(9, 9), 2);
        assert_eq!(b_bits_in_either(12, 10), 3);
        assert_eq!(b_bits_in_either(7, 8), 4);
        assert_eq!(b_bits_in_either(0, 0), 0);
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
        // canonical pair disagreeing somewhere yet sharing a set bit with
        // both popcounts positive, so `const-zero` separates on every
        // scalar; `xor-everything` is exact only on `hamming_distance`
        // itself — pairs carrying it are caught by their partner.
        for seed in 0..200u64 {
            let (x, y) = canonical(seed);
            let d = b_hamming_distance(x, y);
            assert!(d >= 1, "seed {seed}");
            for op in OP_ALL {
                let truth = op_eval(op, x, y);
                assert_ne!(truth, 0, "const-zero survives {op:?} seed {seed}");
                if !matches!(op, Op::HammingDistance) {
                    assert_ne!(truth, d, "xor-everything survives {op:?} seed {seed}");
                }
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (pair, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, pair.0, pair.1), out, "seed {seed}");
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
            assert!(!sk.contains(" ^ "));
            assert!(!sk.contains(" & "));
            assert!(!sk.contains(" | "));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains(".count_ones("));
            assert!(!p.contains(" ^ "));
            assert!(!p.contains(" & "));
            assert!(!p.contains(" | "));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Regression pin in the spirit of fsm's arity check: every op is
        // binary here, so each call site carries exactly one comma — the
        // same count as its signature.
        for op in OP_ALL {
            let call = call_src(op, "x, y");
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
        let g = HammingFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
