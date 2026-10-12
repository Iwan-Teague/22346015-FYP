//! The `gcd` family (category `number-theory`) — divisor queries over a
//! seeded pair of unsigned integers.
//!
//! Where `digits` decomposes one integer into decimal digits and `minmax`
//! scans a whole bag, this family exercises **pairwise number theory**:
//! greatest common divisors, least common multiples, coprimality, and the
//! saturating product/total of the pair. The seed prunes which two of five
//! query ops are required: `gcd`, `lcm`, `is_coprime`, `product`, `sum`.
//! C(5,2) = **10 distinct skills**, above the diversity floor; op names
//! are semantic.
//!
//! The canonical pair is sampled until its anchor facts hold: both entries
//! nonzero, a common divisor greater than one (so coprimality is false),
//! and a saturating total distinct from the gcd, lcm, and product. Those
//! make every scalar answer separate from `const-zero` outright and keep
//! the `sum-everything` cheat inexact on every scalar op; the coprimality
//! flag agrees with both cheats on the canonical pair by design and is
//! flipped by a pinned coprime worked example instead.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies (each self-contained —
//! the Euclid loop is inlined wherever it is needed, since a seed's pair
//! may not select `gcd`); the differential fuzzes 3000 random pairs
//! against the model.
//!
//! Trivial baselines: `const-zero` (`0` everywhere, `false` for the flag)
//! and `sum-everything` (every scalar answered with the saturating total,
//! the flag with `false`).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    Gcd,
    Lcm,
    IsCoprime,
    Product,
    Sum,
}

const OP_ALL: [Op; 5] = [Op::Gcd, Op::Lcm, Op::IsCoprime, Op::Product, Op::Sum];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::Gcd => "gcd",
            Op::Lcm => "lcm",
            Op::IsCoprime => "is_coprime",
            Op::Product => "product",
            Op::Sum => "sum",
        }
    }

    /// Return type used in signatures, stubs, and the prompt fence.
    fn ret(self) -> &'static str {
        match self {
            Op::IsCoprime => "bool",
            _ => "u64",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::Gcd => {
                "the greatest common divisor of `x` and `y`; \
                 `gcd(x, 0) = x` and `gcd(0, 0) = 0`"
            }
            Op::Lcm => {
                "the least common multiple of `x` and `y`, saturating \
                 instead of overflowing; either argument `0` gives `0`"
            }
            Op::IsCoprime => {
                "whether `x` and `y` share no common divisor greater \
                 than one; the only value coprime with `0` is `1`"
            }
            Op::Product => {
                "the product of `x` and `y`, saturating instead of \
                 overflowing"
            }
            Op::Sum => {
                "the total of `x` and `y`, saturating instead of \
                 overflowing"
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

fn b_gcd(x: u64, y: u64) -> u64 {
    let (mut a, mut b) = (x, y);
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

fn b_lcm(x: u64, y: u64) -> u64 {
    if x == 0 || y == 0 {
        return 0;
    }
    let g = b_gcd(x, y);
    (x / g).saturating_mul(y)
}

fn b_is_coprime(x: u64, y: u64) -> bool {
    b_gcd(x, y) == 1
}

fn b_product(x: u64, y: u64) -> u64 {
    x.saturating_mul(y)
}

fn b_sum(x: u64, y: u64) -> u64 {
    x.saturating_add(y)
}

/// One answered value: a number or a flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    Num(u64),
    Flag(bool),
}

impl Out {
    /// Literal rendering for an emitted assertion.
    fn lit(self) -> String {
        match self {
            Out::Num(n) => n.to_string(),
            Out::Flag(b) => b.to_string(),
        }
    }
}

fn op_eval(op: Op, x: u64, y: u64) -> Out {
    match op {
        Op::Gcd => Out::Num(b_gcd(x, y)),
        Op::Lcm => Out::Num(b_lcm(x, y)),
        Op::IsCoprime => Out::Flag(b_is_coprime(x, y)),
        Op::Product => Out::Num(b_product(x, y)),
        Op::Sum => Out::Num(b_sum(x, y)),
    }
}
// ---- canonical pair ---------------------------------------------------------

/// The canonical pair: two values below one million, retried until the
/// anchor facts hold.
///
/// Guaranteed for every seed: both entries nonzero, a common divisor
/// greater than one, and a saturating total distinct from the gcd, lcm,
/// and product. Together those make every scalar op separate from
/// `const-zero` outright and keep `sum-everything` inexact on every
/// scalar; the flag is handled by a pinned coprime example instead.
fn canonical(seed: u64) -> (u64, u64) {
    let mut rng = Rng::new(seed ^ 0x6CD1_A7E5);
    for _ in 0..100_000 {
        let x = rng.below(1_000_000);
        let y = rng.below(1_000_000);
        if anchors_hold(x, y) {
            return (x, y);
        }
    }
    unreachable!("canonical pair sampling failed to satisfy anchors");
}

fn anchors_hold(x: u64, y: u64) -> bool {
    x > 0
        && y > 0
        && b_gcd(x, y) > 1
        && b_sum(x, y) != b_gcd(x, y)
        && b_sum(x, y) != b_lcm(x, y)
        && b_sum(x, y) != b_product(x, y)
}

// ---- worked examples --------------------------------------------------------

type ExampleCase = ((u64, u64), Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_010A);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical pair first.
    let can = canonical(seed);
    cases.push((
        can,
        spec.ops.map(|op| (op, op_eval(op, can.0, can.1))).to_vec(),
    ));
    // All-zero pair: pins every zero convention at once.
    cases.push(((0, 0), spec.ops.map(|op| (op, op_eval(op, 0, 0))).to_vec()));
    // Coprime pair: flips the flag against both cheats and keeps the
    // divisor answers minimal (gcd 1).
    cases.push((
        (17, 4),
        spec.ops.map(|op| (op, op_eval(op, 17, 4))).to_vec(),
    ));
    // Saturation corner: MAX with MAX saturates the product and total
    // while the divisor answers collapse to MAX itself.
    cases.push((
        (u64::MAX, u64::MAX),
        spec.ops
            .map(|op| (op, op_eval(op, u64::MAX, u64::MAX)))
            .to_vec(),
    ));
    for _ in 0..3 {
        let x = rng.below(1_000_000);
        let y = rng.below(1_000_000);
        let outs = spec.ops.map(|op| (op, op_eval(op, x, y))).to_vec();
        cases.push(((x, y), outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a pair call site; the first-element suffix types
/// the tuple.
fn render_pair(x: u64, y: u64) -> String {
    format!("({x}u64, {y})")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let sig = format!("(x: u64, y: u64) -> {}", op.ret());
    let body = match op {
        Op::Gcd => [
            "let mut a = x;",
            "let mut b = y;",
            "while b != 0 {",
            "    let r = a % b;",
            "    a = b;",
            "    b = r;",
            "}",
            "a",
        ]
        .join("\n    "),
        // Self-contained: the Euclid loop is inlined because a seed's
        // pair may not select `gcd`, so the emitted reference cannot
        // depend on it.
        Op::Lcm => [
            "if x == 0 || y == 0 {",
            "    return 0;",
            "}",
            "let mut a = x;",
            "let mut b = y;",
            "while b != 0 {",
            "    let r = a % b;",
            "    a = b;",
            "    b = r;",
            "}",
            "(x / a).saturating_mul(y)",
        ]
        .join("\n    "),
        Op::IsCoprime => [
            "let mut a = x;",
            "let mut b = y;",
            "while b != 0 {",
            "    let r = a % b;",
            "    a = b;",
            "    b = r;",
            "}",
            "a == 1",
        ]
        .join("\n    "),
        Op::Product => ["x.saturating_mul(y)"].join("\n    "),
        Op::Sum => ["x.saturating_add(y)"].join("\n    "),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(x: u64, y: u64) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(x: u64, y: u64) -> {}", op.name(), op.ret())
}

fn reference_src(spec: &Spec) -> String {
    spec.ops.iter().map(|op| op_fn_src(*op)).collect()
}

/// The call expression for one op over two bound arguments.
fn call_src(op: Op, args: &str) -> String {
    format!("{}({})", op.name(), args)
}

fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for ((x, y), outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  (x, y) = {}  ->  {}\n",
            render_pair(x, y),
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
        "Implement the two query functions in `src/lib.rs`. The inputs \
         are two non-negative integers `x` and `y` of type `u64`; queries \
         relate the pair through divisibility and arithmetic.\n\
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
    for (i, ((x, y), outs)) in worked_examples(spec, seed).iter().enumerate() {
        // The rendered literal carries the `u64` suffix on the first
        // element; both arguments go straight into each call site.
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let (x, y) = {};\n",
            render_pair(*x, *y),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "x, y"),
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_010C;\n\
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

/// Degenerate: everything zero / false.
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            if matches!(op, Op::IsCoprime) {
                return format!("{sig} {{\n    let _ = (x, y);\n    false\n}}\n", sig = sig);
            }
            format!("{sig} {{\n    let _ = (x, y);\n    0\n}}\n", sig = sig,)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer the saturating total no matter what was
/// asked. The canonical anchors make gcd, lcm, and product disagree with
/// it; it is exact only for `sum`, and any pair containing `sum` is caught
/// by its partner. The flag arm returns `false`, which agrees with the
/// canonical pair by design and is flipped by the pinned coprime example.
fn sum_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            if matches!(op, Op::IsCoprime) {
                return format!("{sig} {{\n    false\n}}\n", sig = sig);
            }
            format!("{sig} {{\n    x.saturating_add(y)\n}}\n", sig = sig,)
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct GcdFamily;

impl Generator for GcdFamily {
    fn id(&self) -> &str {
        "gcd"
    }
    fn category(&self) -> &str {
        "number-theory"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("gcd", seed);

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
            id: format!("gcd/{seed:016x}"),
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
        let g = GcdFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Euclid, both orders.
        assert_eq!(b_gcd(48, 18), 6);
        assert_eq!(b_gcd(18, 48), 6);
        // Zero conventions fall out of the loop.
        assert_eq!(b_gcd(9, 0), 9);
        assert_eq!(b_gcd(0, 7), 7);
        assert_eq!(b_gcd(0, 0), 0);
        // Lcm saturates and honours the zero rule.
        assert_eq!(b_lcm(4, 6), 12);
        assert_eq!(b_lcm(0, 5), 0);
        let big = u64::MAX / 2 + 1;
        assert_eq!(b_lcm(big, big), big);
        // Coprimality.
        assert!(b_is_coprime(17, 4));
        assert!(!b_is_coprime(48, 18));
        assert!(!b_is_coprime(0, 0));
        assert!(b_is_coprime(1, 0));
        // Product and total saturate at the top.
        assert_eq!(b_product(3, 4), 12);
        assert_eq!(b_product(u64::MAX, 2), u64::MAX);
        assert_eq!(b_sum(u64::MAX, 2), u64::MAX);
        assert_eq!(b_sum(2, 3), 5);
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
        // four scalar answers nonzero on the canonical pair (const-zero
        // dies everywhere except its flag arm, which agrees by design and
        // is flipped by the pinned coprime example), and `sum-everything`
        // is exact only for `sum` — pairs carrying it are caught by their
        // partner scalar.
        for seed in 0..200u64 {
            let (x, y) = canonical(seed);
            // Anchor facts the sampler enforces.
            assert!(x > 0 && y > 0, "seed {seed}");
            assert!(b_gcd(x, y) > 1, "seed {seed}");
            assert_ne!(b_sum(x, y), b_gcd(x, y), "seed {seed}");
            assert_ne!(b_sum(x, y), b_lcm(x, y), "seed {seed}");
            assert_ne!(b_sum(x, y), b_product(x, y), "seed {seed}");
            for op in OP_ALL {
                let truth = op_eval(op, x, y);
                if matches!(op, Op::IsCoprime) {
                    assert_eq!(
                        truth,
                        Out::Flag(false),
                        "canonical must be non-coprime, seed {seed}"
                    );
                    continue;
                }
                assert_ne!(truth, Out::Num(0), "const-zero survives {op:?} seed {seed}");
                if matches!(op, Op::Sum) {
                    continue;
                }
                assert_ne!(
                    truth,
                    Out::Num(b_sum(x, y)),
                    "sum-everything survives {op:?} seed {seed}"
                );
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for ((x, y), outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, x, y), out, "seed {seed}");
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
            // Solution-shaped leak tokens must stay out of the skeleton:
            // the modulo step IS the Euclid algorithm.
            assert!(!sk.contains('%'));
            assert!(!sk.contains("while"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains('%'));
            assert!(!p.contains("while"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every op takes exactly two arguments here: one comma in the
        // call site, one comma in the signature.
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
        let g = GcdFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
