//! The `primes` family (category `factorization`) — divisor-arithmetic
//! queries over one seeded integer.
//!
//! Where `gcd` works a pair with Euclid and `collatz` walks an orbit, this
//! family drills into a single integer's multiplicative structure:
//! primality, the divisor count, the extreme prime factors, and the
//! divisor sum. The domain is one `n: u64`; every op is a pure function of
//! it. The seed prunes which two of five query ops are required:
//! `is_prime`, `num_divisors`, `smallest_factor`, `largest_factor`,
//! `sum_of_divisors`. C(5,2) = **10 distinct skills**, above the diversity
//! floor; op names are semantic.
//!
//! The canonical integer is sampled until its anchor facts hold: at least
//! two and composite. Every composite has at least three divisors, a
//! smallest factor strictly below `n`, a largest factor strictly below
//! `n`, and a divisor sum strictly above `n + 1` — so the
//! `assumes-prime` cheat misses on all five ops at once, and `const-zero`
//! misses on every scalar (its `false` agrees with primality on composites,
//! which the pinned prime worked example flips).
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential fuzzes
//! 3000 random integers against the model.
//!
//! Trivial baselines: `const-zero` (fails every scalar outright on the
//! canonical integer) and `assumes-prime` (every query answered as if `n`
//! were prime).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    IsPrime,
    NumDivisors,
    SmallestFactor,
    LargestFactor,
    SumOfDivisors,
}

const OP_ALL: [Op; 5] = [
    Op::IsPrime,
    Op::NumDivisors,
    Op::SmallestFactor,
    Op::LargestFactor,
    Op::SumOfDivisors,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::IsPrime => "is_prime",
            Op::NumDivisors => "num_divisors",
            Op::SmallestFactor => "smallest_factor",
            Op::LargestFactor => "largest_factor",
            Op::SumOfDivisors => "sum_of_divisors",
        }
    }

    fn ret(self) -> &'static str {
        match self {
            Op::IsPrime => "bool",
            _ => "u64",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::IsPrime => {
                "whether `n` is prime: greater than one with no divisor \
                 other than 1 and itself"
            }
            Op::NumDivisors => {
                "how many positive integers divide `n` evenly; zero has \
                 none"
            }
            Op::SmallestFactor => {
                "the smallest factor of `n` above 1; a prime is its own \
                 smallest factor, and zero yields `0`"
            }
            Op::LargestFactor => {
                "the largest prime factor of `n`; a prime is its own \
                 largest factor, and zero yields `0`"
            }
            Op::SumOfDivisors => {
                "the sum of every positive integer that divides `n` \
                 evenly, including 1 and `n` themselves; zero sums to `0`"
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

fn b_is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    let mut d = 2u64;
    while d * d <= n {
        if n.is_multiple_of(d) {
            return false;
        }
        d += 1;
    }
    true
}

fn b_num_divisors(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut count = 0u64;
    let mut d = 1u64;
    while d * d <= n {
        if n.is_multiple_of(d) {
            count += if d * d == n { 1 } else { 2 };
        }
        d += 1;
    }
    count
}

fn b_smallest_factor(n: u64) -> u64 {
    let mut d = 2u64;
    while d * d <= n {
        if n.is_multiple_of(d) {
            return d;
        }
        d += 1;
    }
    n
}

fn b_largest_factor(n: u64) -> u64 {
    let mut m = n;
    let mut largest = n;
    let mut d = 2u64;
    while d * d <= m {
        while m.is_multiple_of(d) {
            m /= d;
            largest = d;
        }
        d += 1;
    }
    if m > 1 {
        largest = m;
    }
    largest
}

fn b_sum_of_divisors(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut total = 0u64;
    let mut d = 1u64;
    while d * d <= n {
        if n.is_multiple_of(d) {
            total += if d * d == n { d } else { d + n / d };
        }
        d += 1;
    }
    total
}

/// One query answer: scalars carry a number, primality carries a flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    Num(u64),
    Flag(bool),
}

impl Out {
    /// Rust literal for an emitted assertion.
    fn lit(self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            Out::Flag(b) => b.to_string(),
        }
    }
}

fn op_eval(op: Op, n: u64) -> Out {
    match op {
        Op::IsPrime => Out::Flag(b_is_prime(n)),
        Op::NumDivisors => Out::Num(b_num_divisors(n)),
        Op::SmallestFactor => Out::Num(b_smallest_factor(n)),
        Op::LargestFactor => Out::Num(b_largest_factor(n)),
        Op::SumOfDivisors => Out::Num(b_sum_of_divisors(n)),
    }
}

// ---- canonical integer ------------------------------------------------------

/// The canonical integer: below one million, retried until the anchor
/// facts hold.
///
/// Guaranteed for every seed: `n >= 2` and composite. Every composite has
/// three or more divisors, both extreme factors strictly below `n`, and a
/// divisor sum strictly above `n + 1`, so `assumes-prime` misses on all
/// five ops and `const-zero` misses on every scalar.
fn canonical(seed: u64) -> u64 {
    let mut rng = Rng::new(seed ^ 0x5EED_FA75);
    for _ in 0..100_000 {
        let cand = rng.below(1_000_000);
        if anchors_hold(cand) {
            return cand;
        }
    }
    unreachable!("canonical integer sampling failed to satisfy anchors");
}

fn anchors_hold(n: u64) -> bool {
    n >= 2 && !b_is_prime(n)
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (u64, Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_0112);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical composite first.
    let can = canonical(seed);
    cases.push((can, spec.ops.map(|op| (op, op_eval(op, can))).to_vec()));
    // Zero: pins every zero convention at once.
    cases.push((0, spec.ops.map(|op| (op, op_eval(op, 0))).to_vec()));
    // A prime: flips `const-zero`'s primality flag.
    cases.push((97, spec.ops.map(|op| (op, op_eval(op, 97))).to_vec()));
    // Perfect square: root counted once — 16 has five divisors.
    cases.push((16, spec.ops.map(|op| (op, op_eval(op, 16))).to_vec()));
    for _ in 0..3 {
        let n = rng.below(1_000_000);
        let outs = spec.ops.map(|op| (op, op_eval(op, n))).to_vec();
        cases.push((n, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let sig = format!("(n: u64) -> {}", op.ret());
    let body = match op {
        Op::IsPrime => [
            "if n < 2 {",
            "    return false;",
            "}",
            "let mut d = 2u64;",
            "while d * d <= n {",
            "    if n % d == 0 {",
            "        return false;",
            "    }",
            "    d += 1;",
            "}",
            "true",
        ]
        .join("\n    "),
        Op::NumDivisors => [
            "if n == 0 {",
            "    return 0;",
            "}",
            "let mut count = 0u64;",
            "let mut d = 1u64;",
            "while d * d <= n {",
            "    if n % d == 0 {",
            "        count += if d * d == n { 1 } else { 2 };",
            "    }",
            "    d += 1;",
            "}",
            "count",
        ]
        .join("\n    "),
        Op::SmallestFactor => [
            "let mut d = 2u64;",
            "while d * d <= n {",
            "    if n % d == 0 {",
            "        return d;",
            "    }",
            "    d += 1;",
            "}",
            "n",
        ]
        .join("\n    "),
        Op::LargestFactor => [
            "let mut m = n;",
            "let mut largest = n;",
            "let mut d = 2u64;",
            "while d * d <= m {",
            "    while m % d == 0 {",
            "        m /= d;",
            "        largest = d;",
            "    }",
            "    d += 1;",
            "}",
            "if m > 1 {",
            "    largest = m;",
            "}",
            "largest",
        ]
        .join("\n    "),
        Op::SumOfDivisors => [
            "if n == 0 {",
            "    return 0;",
            "}",
            "let mut total = 0u64;",
            "let mut d = 1u64;",
            "while d * d <= n {",
            "    if n % d == 0 {",
            "        total += if d * d == n { d } else { d + n / d };",
            "    }",
            "    d += 1;",
            "}",
            "total",
        ]
        .join("\n    "),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(n: u64) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
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
        s.push_str(&format!("  n {n}  ->  {}\n", results));
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
         one non-negative integer `n` of type `u64`; queries probe its \
         multiplicative structure.\n\
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
        body.push_str(&format!("#[test]\nfn ex{i}() {{\n    let n = {n}u64;\n",));
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0116;\n\
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
/// Degenerate: everything zero / false.
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            let body = match op {
                Op::IsPrime => "let _ = n;\n    false".to_string(),
                _ => "let _ = n;\n    0".to_string(),
            };
            format!("{sig} {{\n    {body}\n}}\n", sig = sig,)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer as if `n` were prime — flag true, exactly
/// two divisors, both extreme factors equal `n` itself, divisor sum
/// `n + 1`. The canonical integer is composite, so every one of those is
/// wrong on it at once.
fn assumes_prime(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            let body = match op {
                Op::IsPrime => "true".to_string(),
                Op::NumDivisors => "2".to_string(),
                Op::SmallestFactor | Op::LargestFactor => "n".to_string(),
                Op::SumOfDivisors => "n.saturating_add(1)".to_string(),
            };
            format!("{sig} {{\n    {body}\n}}\n", sig = sig,)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct PrimesFamily;

impl Generator for PrimesFamily {
    fn id(&self) -> &str {
        "primes"
    }
    fn category(&self) -> &str {
        "factorization"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("primes", seed);

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
            id: format!("primes/{seed:016x}"),
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
            ("assumes-prime".to_string(), assumes_prime(&spec)),
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
        let g = PrimesFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Primality by trial division.
        assert!(b_is_prime(2));
        assert!(!b_is_prime(4));
        // 91 = 7 * 13 — the classic composite that looks prime.
        assert!(!b_is_prime(91));
        assert!(b_is_prime(7919));
        assert!(!b_is_prime(0));
        assert!(!b_is_prime(1));
        // Divisor counts: primes have exactly two; squares count the root
        // once.
        assert_eq!(b_num_divisors(97), 2);
        assert_eq!(b_num_divisors(12), 6);
        assert_eq!(b_num_divisors(16), 5);
        assert_eq!(b_num_divisors(1), 1);
        assert_eq!(b_num_divisors(0), 0);
        // Extreme factors.
        assert_eq!(b_smallest_factor(91), 7);
        assert_eq!(b_smallest_factor(12), 2);
        assert_eq!(b_smallest_factor(97), 97);
        assert_eq!(b_largest_factor(91), 13);
        assert_eq!(b_largest_factor(12), 3);
        assert_eq!(b_largest_factor(16), 2);
        assert_eq!(b_largest_factor(7919), 7919);
        assert_eq!(b_largest_factor(0), 0);
        // Divisor sums, including the perfect number 6.
        assert_eq!(b_sum_of_divisors(97), 98);
        assert_eq!(b_sum_of_divisors(12), 28);
        assert_eq!(b_sum_of_divisors(16), 31);
        assert_eq!(b_sum_of_divisors(6), 12);
        assert_eq!(b_sum_of_divisors(0), 0);
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

    /// What [`assumes_prime`] would answer for one op.
    fn assumes_prime_value(op: Op, n: u64) -> Out {
        match op {
            Op::IsPrime => Out::Flag(true),
            Op::NumDivisors => Out::Num(2),
            Op::SmallestFactor | Op::LargestFactor => Out::Num(n),
            Op::SumOfDivisors => Out::Num(n.saturating_add(1)),
        }
    }

    #[test]
    fn canonical_answers_are_non_degenerate_for_every_op() {
        // Both baselines must fail under EVERY pair. The canonical integer
        // is composite with n >= 2, which makes every scalar answer
        // nonzero (defeating `const-zero`; its `false` agrees with
        // primality there, flipped by the pinned prime example) and every
        // op disagrees with `assumes-prime` at once — no skips needed for
        // either cheat.
        for seed in 0..200u64 {
            let n = canonical(seed);
            // Anchor facts the sampler enforces.
            assert!(n >= 2, "seed {seed}");
            assert!(!b_is_prime(n), "seed {seed}");
            for op in OP_ALL {
                let truth = op_eval(op, n);
                if let Out::Num(v) = truth {
                    assert_ne!(v, 0, "const-zero survives {op:?} seed {seed}");
                }
                assert_ne!(
                    truth,
                    assumes_prime_value(op, n),
                    "assumes-prime survives {op:?} seed {seed}"
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
            assert!(!sk.contains('%'));
            assert!(!sk.contains("d * d"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains('%'));
            assert!(!p.contains("d * d"));
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
        let g = PrimesFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
