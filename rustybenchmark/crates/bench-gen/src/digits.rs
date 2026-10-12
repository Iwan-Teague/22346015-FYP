//! The `digits` family (category `digit-arithmetic`) — queries over the
//! base-10 digit sequence of one seeded `u64`.
//!
//! Where `bitset` works the binary word and `poly` indexes coefficient
//! slots, this family exercises **positional decomposition**: peeling
//! decimal digits with `% 10` / `/ 10` loops under explicit zero
//! conventions. The domain is one non-negative integer; every op is a pure
//! function of it. The seed prunes which two of five query ops are
//! required: `digit_sum`, `num_digits`, `max_digit`, `min_digit`,
//! `is_palindrome`. C(5,2) = **10 distinct skills**, above the diversity
//! floor; op names are semantic.
//!
//! The canonical integer is sampled until its anchor facts hold: at least
//! two digits, no zero digit at all, not a palindrome, and a digit sum that
//! equals neither the digit count nor the extreme digits. Those make every
//! scalar answer positive (defeating `const-zero`) and separate four of the
//! five ops from the `sum-everything` cheat — `is_palindrome` excepted,
//! which that baseline answers `false` against a false truth on the
//! canonical input; the pinned zero example flips it, and any pair is also
//! caught through its partner scalar.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential fuzzes
//! 3000 random integers against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the
//! canonical integer) and `sum-everything` (every scalar query answered
//! with the digit sum, palindrome always `false`).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    DigitSum,
    NumDigits,
    MaxDigit,
    MinDigit,
    IsPalindrome,
}

const OP_ALL: [Op; 5] = [
    Op::DigitSum,
    Op::NumDigits,
    Op::MaxDigit,
    Op::MinDigit,
    Op::IsPalindrome,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::DigitSum => "digit_sum",
            Op::NumDigits => "num_digits",
            Op::MaxDigit => "max_digit",
            Op::MinDigit => "min_digit",
            Op::IsPalindrome => "is_palindrome",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::DigitSum => {
                "the sum of the decimal digits of `x`; `x = 0` has digit \
                 sum 0"
            }
            Op::NumDigits => {
                "how many decimal digits `x` has; `x = 0` counts as one \
                 digit"
            }
            Op::MaxDigit => {
                "the largest decimal digit appearing in `x`; `x = 0` has \
                 largest digit 0"
            }
            Op::MinDigit => {
                "the smallest decimal digit appearing in `x`; `x = 0` has \
                 smallest digit 0"
            }
            Op::IsPalindrome => {
                "whether the decimal digits of `x` read the same forwards \
                 and backwards (e.g. `12321`); `0` is a palindrome"
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

fn b_digit_sum(mut x: u64) -> i64 {
    let mut s = 0i64;
    while x > 0 {
        s += (x % 10) as i64;
        x /= 10;
    }
    s
}

fn b_num_digits(mut x: u64) -> i64 {
    if x == 0 {
        return 1;
    }
    let mut n = 0i64;
    while x > 0 {
        n += 1;
        x /= 10;
    }
    n
}

fn b_max_digit(mut x: u64) -> i64 {
    let mut m = 0i64;
    while x > 0 {
        m = m.max((x % 10) as i64);
        x /= 10;
    }
    m
}

fn b_min_digit(mut x: u64) -> i64 {
    if x == 0 {
        return 0;
    }
    let mut m = 9i64;
    while x > 0 {
        m = m.min((x % 10) as i64);
        x /= 10;
    }
    m
}

fn b_is_palindrome(x: u64) -> bool {
    let mut n = x;
    let mut rev = 0u64;
    while n > 0 {
        rev = rev * 10 + n % 10;
        n /= 10;
    }
    rev == x
}

/// Two result shapes: scalars and one boolean flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
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

fn op_eval(op: Op, x: u64) -> Out {
    match op {
        Op::DigitSum => Out::Num(b_digit_sum(x)),
        Op::NumDigits => Out::Num(b_num_digits(x)),
        Op::MaxDigit => Out::Num(b_max_digit(x)),
        Op::MinDigit => Out::Num(b_min_digit(x)),
        Op::IsPalindrome => Out::Flag(b_is_palindrome(x)),
    }
}

// ---- canonical integer ------------------------------------------------------

/// The canonical integer: seeded value below one million, retried until the
/// anchor facts hold.
///
/// Guaranteed for every seed: at least two digits, no zero digit anywhere,
/// not a palindrome, and a digit sum distinct from the digit count and from
/// both extreme digits. Together those defeat `const-zero` on every scalar
/// op and `sum-everything` on its three non-exact scalars; the boolean flag
/// agrees with both cheats on the canonical input (`false`) and is flipped
/// by the pinned zero worked example.
fn canonical(seed: u64) -> u64 {
    let mut rng = Rng::new(seed ^ 0x1D16_17A1);
    for _ in 0..100_000 {
        let cand = rng.below(1_000_000);
        if anchors_hold(cand) {
            return cand;
        }
    }
    unreachable!("canonical integer sampling failed to satisfy anchors");
}

fn anchors_hold(x: u64) -> bool {
    x > 9
        && b_min_digit(x) >= 1
        && !b_is_palindrome(x)
        && b_digit_sum(x) != b_num_digits(x)
        && b_digit_sum(x) != b_max_digit(x)
        && b_digit_sum(x) != b_min_digit(x)
}

// ---- worked examples --------------------------------------------------------

type ExampleCase = (u64, Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_00E4);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical integer first.
    let can = canonical(seed);
    cases.push((can, spec.ops.map(|op| (op, op_eval(op, can))).to_vec()));
    // Zero: pins every convention at once (sum 0, one digit, digits 0/0,
    // palindrome true).
    cases.push((0, spec.ops.map(|op| (op, op_eval(op, 0))).to_vec()));
    // A lone digit: count 1 while sum/max/min collapse onto the digit.
    cases.push((7, spec.ops.map(|op| (op, op_eval(op, 7))).to_vec()));
    for _ in 0..3 {
        let v = rng.below(1_000_000);
        let outs = spec.ops.map(|op| (op, op_eval(op, v))).to_vec();
        cases.push((v, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; plain decimal text infers `u64`.
fn render_u64(x: u64) -> String {
    x.to_string()
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let (sig, body) = match op {
        Op::DigitSum => (
            "(mut x: u64) -> i64",
            [
                "let mut s = 0i64;",
                "while x > 0 {",
                "    s += (x % 10) as i64;",
                "    x /= 10;",
                "}",
                "s",
            ]
            .join("\n    "),
        ),
        Op::NumDigits => (
            "(mut x: u64) -> i64",
            [
                "if x == 0 {",
                "    return 1;",
                "}",
                "let mut n = 0i64;",
                "while x > 0 {",
                "    n += 1;",
                "    x /= 10;",
                "}",
                "n",
            ]
            .join("\n    "),
        ),
        Op::MaxDigit => (
            "(mut x: u64) -> i64",
            [
                "let mut m = 0i64;",
                "while x > 0 {",
                "    m = m.max((x % 10) as i64);",
                "    x /= 10;",
                "}",
                "m",
            ]
            .join("\n    "),
        ),
        Op::MinDigit => (
            "(mut x: u64) -> i64",
            [
                "if x == 0 {",
                "    return 0;",
                "}",
                "let mut m = 9i64;",
                "while x > 0 {",
                "    m = m.min((x % 10) as i64);",
                "    x /= 10;",
                "}",
                "m",
            ]
            .join("\n    "),
        ),
        Op::IsPalindrome => (
            "(x: u64) -> bool",
            [
                "let mut n = x;",
                "let mut rev = 0u64;",
                "while n > 0 {",
                "    rev = rev * 10 + n % 10;",
                "    n /= 10;",
                "}",
                "rev == x",
            ]
            .join("\n    "),
        ),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    let (name, sig) = match op {
        Op::IsPalindrome => ("is_palindrome", "(x: u64) -> bool"),
        _ => (op.name(), "(mut x: u64) -> i64"),
    };
    format!("pub fn {name}{sig} {{\n    todo!()\n}}\n")
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    match op {
        Op::IsPalindrome => "pub fn is_palindrome(x: u64) -> bool".to_string(),
        _ => format!("pub fn {}(mut x: u64) -> i64", op.name()),
    }
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
    for (v, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  x {}  ->  {}\n", render_u64(v), results));
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
         given as `x`, a single non-negative integer of type `u64`; queries \
         concern its ordinary base-10 (decimal) digit sequence.\n\
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
    for (i, (v, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let v = {};\n",
            render_u64(*v),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "v"),
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
            let call = call_src(*op, "x");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_00E8;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let x = nx(&mut state);\n\
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

/// Degenerate: everything zero/false.
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let body = match op {
                Op::IsPalindrome => "false".to_string(),
                _ => "0".to_string(),
            };
            let sig = op_sig_src(*op);
            format!(
                "{sig} {{\n    let _ = x;\n    {body}\n}}\n",
                sig = sig,
                body = body,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer the digit sum no matter what was asked (and
/// always `false` for the flag). The canonical anchors make the three other
/// scalars disagree; `digit_sum` itself is exact, and any pair containing it
/// is caught by its partner.
fn sum_everything(spec: &Spec) -> String {
    let sum_body = [
        "let mut s = 0i64;",
        "while x > 0 {",
        "    s += (x % 10) as i64;",
        "    x /= 10;",
        "}",
        "s",
    ]
    .join("\n    ");
    spec.ops
        .iter()
        .map(|op| {
            let body = match op {
                Op::DigitSum | Op::NumDigits | Op::MaxDigit | Op::MinDigit => sum_body.clone(),
                Op::IsPalindrome => "let _ = x;\n    false".to_string(),
            };
            let sig = op_sig_src(*op);
            format!("{sig} {{\n    {body}\n}}\n", sig = sig, body = body,)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct DigitsFamily;

impl Generator for DigitsFamily {
    fn id(&self) -> &str {
        "digits"
    }
    fn category(&self) -> &str {
        "digit-arithmetic"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("digits", seed);

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
            id: format!("digits/{seed:016x}"),
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
        let g = DigitsFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Digit sum: additive across positions; zeros contribute nothing.
        assert_eq!(b_digit_sum(0), 0);
        assert_eq!(b_digit_sum(7), 7);
        assert_eq!(b_digit_sum(1234), 10);
        assert_eq!(b_digit_sum(1000), 1);
        // Digit count: 0 has one digit by convention.
        assert_eq!(b_num_digits(0), 1);
        assert_eq!(b_num_digits(9), 1);
        assert_eq!(b_num_digits(10), 2);
        assert_eq!(b_num_digits(999_999), 6);
        // Extremes: extremes are not position-bound.
        assert_eq!(b_max_digit(392), 9);
        assert_eq!(b_max_digit(1204), 4);
        assert_eq!(b_max_digit(0), 0);
        assert_eq!(b_min_digit(392), 2);
        assert_eq!(b_min_digit(907), 0);
        assert_eq!(b_min_digit(0), 0);
        // Palindrome: reversal compare; 0 is one, 10 is not.
        assert!(b_is_palindrome(0));
        assert!(b_is_palindrome(7));
        assert!(b_is_palindrome(12321));
        assert!(!b_is_palindrome(10));
        assert!(!b_is_palindrome(392));
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
        // canonical integer separate from const-zero on all four scalars;
        // `sum-everything` is exact only for `digit_sum` (and answers the
        // flag `false`), so a pair containing either skip-op is caught by
        // its partner scalar.
        for seed in 0..200u64 {
            let x = canonical(seed);
            // Anchor facts the sampler enforces.
            assert!(x > 9, "seed {seed}");
            assert!(b_min_digit(x) >= 1, "seed {seed}");
            assert!(!b_is_palindrome(x), "seed {seed}");
            assert_ne!(b_digit_sum(x), b_num_digits(x), "seed {seed}");
            assert_ne!(b_digit_sum(x), b_max_digit(x), "seed {seed}");
            assert_ne!(b_digit_sum(x), b_min_digit(x), "seed {seed}");
            for op in OP_ALL {
                let truth = op_eval(op, x);
                // const-zero separates everywhere except the flag (false ==
                // false on the canonical input; the zero example flips it).
                match truth {
                    Out::Num(v) => {
                        assert_ne!(v, 0, "const-zero survives {op:?} seed {seed}")
                    }
                    Out::Flag(_) => continue,
                }
                // sum-everything answers: the three non-sum scalars get the
                // digit sum (distinct by anchors); digit_sum is exact (skip);
                // the flag reads false == false (skip).
                let cheat = Out::Num(b_digit_sum(x));
                if matches!(op, Op::DigitSum | Op::IsPalindrome) {
                    continue;
                }
                assert_ne!(truth, cheat, "sum-everything survives {op:?} seed {seed}");
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (v, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, v), out, "seed {seed}");
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
            assert!(!sk.contains("* 10"));
            assert!(!sk.contains("rev"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("% 10"));
            assert!(!p.contains("/ 10"));
            assert!(!p.contains("* 10"));
            assert!(!p.contains("rev"));
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
            let call = call_src(op, "x");
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
        let g = DigitsFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
