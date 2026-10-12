//! `luhn` — checksum queries over seeded decimal digit sequences.
//!
//! A task instance is a short sequence of digits in `0..=9`. The seed
//! picks two of five query operations; the model must implement both
//! exactly as specified and match a hidden reference implementation on
//! thousands of random sequences.
//!
//! Category: `checksums`.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    /// Luhn validity: right-to-left scan doubling every second digit.
    IsValid,
    /// The plain arithmetic sum of every digit.
    DigitSum,
    /// The digit that would make the sequence valid once appended.
    CheckDigit,
    /// Sum with EVERY digit doubled in place.
    DoubledSum,
    /// Count of digits that overflow when doubled.
    CarryCount,
}

const OP_ALL: [Op; 5] = [
    Op::IsValid,
    Op::DigitSum,
    Op::CheckDigit,
    Op::DoubledSum,
    Op::CarryCount,
];

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::IsValid => "is_valid",
            Op::DigitSum => "digit_sum",
            Op::CheckDigit => "check_digit",
            Op::DoubledSum => "doubled_sum",
            Op::CarryCount => "carry_count",
        }
    }

    fn ret(self) -> &'static str {
        match self {
            Op::IsValid => "bool",
            _ => "i64",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::IsValid => "whether the digit sequence passes the Luhn checksum: scanning from the right, double every second digit (subtracting nine when a doubled digit reaches two figures) and require the total to be a multiple of ten; the empty sequence passes vacuously",
            Op::DigitSum => "the plain sum of every digit with no positional treatment at all",
            Op::CheckDigit => "the check digit that would make this sequence valid once appended at its right end: shift the doubling one position (double every digit sitting on an even offset from the right of the given sequence) and return the digit that brings the extended total to a multiple of ten",
            Op::DoubledSum => "the sum obtained by doubling EVERY digit in place (subtracting nine whenever a doubling reaches two figures), ignoring position entirely",
            Op::CarryCount => "how many digits are five or larger — exactly those whose doubling reaches two figures and collapses by nine",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Spec {
    ops: [Op; 2],
}

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let i = rng.below(OP_ALL.len() as u64) as usize;
    let mut j = rng.below(OP_ALL.len() as u64) as usize;
    while j == i {
        j = rng.below(OP_ALL.len() as u64) as usize;
    }
    Spec {
        ops: [OP_ALL[i], OP_ALL[j]],
    }
}
// ---------------------------------------------------------------------------
// Native mirrors of the emitted query bodies.
// ---------------------------------------------------------------------------

fn b_is_valid(digits: &[u8]) -> bool {
    let mut sum = 0usize;
    for (i, &d) in digits.iter().rev().enumerate() {
        let d = d as usize;
        if i % 2 == 1 {
            let dd = d * 2;
            sum += if dd > 9 { dd - 9 } else { dd };
        } else {
            sum += d;
        }
    }
    sum.is_multiple_of(10)
}

fn b_digit_sum(digits: &[u8]) -> i64 {
    digits.iter().map(|&d| d as i64).sum()
}

fn b_check_digit(digits: &[u8]) -> i64 {
    let mut sum = 0usize;
    for (i, &d) in digits.iter().rev().enumerate() {
        let d = d as usize;
        if i % 2 == 0 {
            // Lands on a doubled position once the check digit appends.
            let dd = d * 2;
            sum += if dd > 9 { dd - 9 } else { dd };
        } else {
            sum += d;
        }
    }
    ((10 - sum % 10) % 10) as i64
}

fn b_doubled_sum(digits: &[u8]) -> i64 {
    digits
        .iter()
        .map(|&d| {
            let dd = d as usize * 2;
            if dd > 9 {
                dd - 9
            } else {
                dd
            }
        })
        .sum::<usize>() as i64
}

fn b_carry_count(digits: &[u8]) -> i64 {
    digits.iter().filter(|&&d| d >= 5).count() as i64
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Flag(bool),
}

impl Out {
    fn lit(self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            Out::Flag(b) => b.to_string(),
        }
    }
}

fn op_eval(op: Op, digits: &[u8]) -> Out {
    match op {
        Op::IsValid => Out::Flag(b_is_valid(digits)),
        Op::DigitSum => Out::Num(b_digit_sum(digits)),
        Op::CheckDigit => Out::Num(b_check_digit(digits)),
        Op::DoubledSum => Out::Num(b_doubled_sum(digits)),
        Op::CarryCount => Out::Num(b_carry_count(digits)),
    }
}

const CANONICAL_SEED: u64 = 0x1C8A_11A5;

/// The canonical sequence is deliberately INVALID so any cheat assuming
/// validity answers wrongly, while every scalar answer stays nonzero and
/// pairwise distinct — so a plain-sum cheat that happens to be exact on
/// `digit_sum` still misses its partner query on the same instance.
fn canonical(seed: u64) -> Vec<u8> {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let len = 4 + rng.below(8) as usize;
        let digits: Vec<u8> = (0..len).map(|_| rng.below(10) as u8).collect();
        if anchors_hold(&digits) {
            return digits;
        }
    }
    unreachable!("luhn canonical anchor search exhausted");
}

fn anchors_hold(digits: &[u8]) -> bool {
    if b_is_valid(digits) {
        // Must NOT pass the checksum.
        return false;
    }
    if !(4..=11).contains(&digits.len()) {
        return false;
    }
    let ds = b_digit_sum(digits);
    let cd = b_check_digit(digits);
    let ds2 = b_doubled_sum(digits);
    let cc = b_carry_count(digits);
    if cd == 0 || ds2 == 0 || cc < 1 || ds < 5 {
        return false;
    }
    // All four scalars pairwise distinct.
    let scalars = [ds, cd, ds2, cc];
    for i in 0..scalars.len() {
        for j in (i + 1)..scalars.len() {
            if scalars[i] == scalars[j] {
                return false;
            }
        }
    }
    true
}
// ---------------------------------------------------------------------------
// Worked examples, rendering, and emitted-source builders.
// ---------------------------------------------------------------------------

type ExampleCase = (Vec<u8>, Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0x0000_1222;

fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    // ex0: the canonical INVALID sequence.
    // ex1: the empty sequence pins every zero convention AND a vacuous
    //      `true` from the validity query — flipping both cheats' `false`.
    // ex2: a small VALID sequence ("18") flipping the flag with content.
    let canon = canonical(seed);
    let mut examples: Vec<ExampleCase> = vec![
        (
            canon.clone(),
            OP_ALL.iter().map(|&op| (op, op_eval(op, &canon))).collect(),
        ),
        (
            Vec::new(),
            OP_ALL
                .iter()
                .map(|&op| (op, op_eval(op, &Vec::new())))
                .collect(),
        ),
        (
            vec![1u8, 8],
            OP_ALL
                .iter()
                .map(|&op| (op, op_eval(op, &[1u8, 8])))
                .collect(),
        ),
    ];
    for _ in 0..3 {
        let len = 1 + rng.below(8) as usize;
        let digits: Vec<u8> = (0..len).map(|_| rng.below(10) as u8).collect();
        let answers = OP_ALL
            .iter()
            .map(|&op| (op, op_eval(op, &digits)))
            .collect();
        examples.push((digits, answers));
    }
    examples
}

fn render_digits(digits: &[u8]) -> String {
    if digits.is_empty() {
        return "&[]".to_string();
    }
    let items: Vec<String> = digits.iter().map(|d| d.to_string()).collect();
    format!("&[{}u8, {}]", items[0], items[1..].join(", "))
}

fn call_src(op: Op, var: &str) -> String {
    format!("{}({})", op.name(), var)
}

fn op_fn_src(op: Op) -> String {
    let body: String = match op {
        Op::IsValid => [
            "let mut sum = 0usize;",
            "for (i, &d) in digits.iter().rev().enumerate() {",
            "        let d = d as usize;",
            "        if i % 2 == 1 {",
            "            let dd = d * 2;",
            "            sum += if dd > 9 { dd - 9 } else { dd };",
            "        } else {",
            "            sum += d;",
            "        }",
            "    }",
            "sum % 10 == 0",
        ]
        .join("\n    "),
        Op::DigitSum => ["digits.iter().map(|&d| d as i64).sum()"].join("\n    "),
        Op::CheckDigit => [
            "let mut sum = 0usize;",
            "for (i, &d) in digits.iter().rev().enumerate() {",
            "        let d = d as usize;",
            "        if i % 2 == 0 {",
            "            // Doubled once the check digit appends.",
            "            let dd = d * 2;",
            "            sum += if dd > 9 { dd - 9 } else { dd };",
            "        } else {",
            "            sum += d;",
            "        }",
            "    }",
            "((10 - sum % 10) % 10) as i64",
        ]
        .join("\n    "),
        Op::DoubledSum => [
            "digits",
            "    .iter()",
            "    .map(|&d| {",
            "        let dd = d as usize * 2;",
            "        if dd > 9 { dd - 9 } else { dd }",
            "    })",
            "    .sum::<usize>() as i64",
        ]
        .join("\n    "),
        Op::CarryCount => ["digits.iter().filter(|&&d| d >= 5).count() as i64"].join("\n    "),
    };
    format!(
        "pub fn {}(digits: &[u8]) -> {} {{\n    {}\n}}\n",
        op.name(),
        op.ret(),
        body
    )
}

fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(digits: &[u8]) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(digits: &[u8]) -> {}", op.name(), op.ret())
}

fn reference_src() -> String {
    OP_ALL
        .iter()
        .map(|&op| op_fn_src(op))
        .collect::<Vec<_>>()
        .join("\n")
}
// ---------------------------------------------------------------------------
// Emitted task surfaces: examples prose, skeleton, prompt, manifest.
// ---------------------------------------------------------------------------

fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for (digits, outs) in worked_examples(seed) {
        let results = outs
            .iter()
            .filter(|(op, _)| spec.ops.contains(op))
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  digits {}  ->  {}\n",
            render_digits(&digits),
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
         given as `digits`, a slice of decimal digit values (`u8`, each in \
         zero-to-nine); queries are checksum properties of the sequence.\n\
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
// ---------------------------------------------------------------------------
// Hidden tests and trivial baselines.
// ---------------------------------------------------------------------------

fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let imports = spec
        .ops
        .iter()
        .map(|op| op.name())
        .collect::<Vec<_>>()
        .join(", ");
    let mut body = format!("use task::{{{imports}}};\n\n");
    for (i, (digits, outs)) in worked_examples(seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let digits = {};\n",
            render_digits(digits),
        ));
        for (op, out) in outs {
            if !spec.ops.contains(op) {
                continue;
            }
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "digits"),
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
    let reference = reference_src()
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
            let call = call_src(*op, "&digits");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0122;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let len = (nx(&mut state) % 6) + 1;\n\
         \x20       let mut digits: Vec<u8> = Vec::with_capacity(len as usize);\n\
         \x20       for _ in 0..len {{\n\
         \x20           digits.push((nx(&mut state) % 10) as u8);\n\
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

/// Degenerate: everything zero (and a hardcoded `false` on the boolean).
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => format!("{sig} {{\n    let _ = digits;\n    false\n}}\n"),
                _ => format!("{sig} {{\n    let _ = digits;\n    0\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer the plain digit sum no matter what was
/// asked. The canonical anchors make check digit, doubled sum, and carry
/// count all disagree with it; `digit_sum` itself is exact, and any pair
/// containing it is caught by its partner. The validity flag agrees with
/// this cheat on the (invalid) canonical but flips on the empty and "18"
/// worked examples.
fn plain_sum_everything(spec: &Spec) -> String {
    let sum_body = "digits.iter().map(|&d| d as i64).sum()";
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => format!("{sig} {{\n    let _ = digits;\n    false\n}}\n"),
                _ => format!("{sig} {{\n    {sum_body}\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct LuhnFamily;

impl Generator for LuhnFamily {
    fn id(&self) -> &str {
        "luhn"
    }
    fn category(&self) -> &str {
        "checksums"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("luhn", seed);

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
            id: format!("luhn/{seed:016x}"),
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

    fn reference_code(&self, _seed: u64) -> String {
        reference_src()
    }
    fn skeleton_code(&self, seed: u64) -> String {
        skeleton_src(&sample(seed), seed)
    }
    fn trivial_baselines(&self, seed: u64) -> Vec<(String, String)> {
        let spec = sample(seed);
        vec![
            ("const-zero".to_string(), const_zero(&spec)),
            (
                "plain-sum-everything".to_string(),
                plain_sum_everything(&spec),
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
        let g = LuhnFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // The classic "45393" example is valid.
        let classic = [4u8, 5, 3, 9, 3];
        assert!(b_is_valid(&classic));
        // Plain sum ignores position entirely.
        assert_eq!(b_digit_sum(&[4, 5, 3, 9]), 21);
        // Appending the check digit makes the sequence valid.
        assert_eq!(b_check_digit(&[4, 5, 3, 9]), 3);
        assert!(b_is_valid(&[4, 5, 3, 9, 3]));
        // Doubling every digit collapses nine overflow points.
        assert_eq!(b_doubled_sum(&[4, 5, 3, 9]), 24);
        // Five and nine both overflow when doubled.
        assert_eq!(b_carry_count(&[4, 5, 3, 9]), 2);
        // Empty-sequence conventions.
        assert!(b_is_valid(&[]));
        assert_eq!(b_digit_sum(&[]), 0);
        assert_eq!(b_check_digit(&[]), 0);
        assert_eq!(b_doubled_sum(&[]), 0);
        assert_eq!(b_carry_count(&[]), 0);
        // A small valid pair.
        assert!(b_is_valid(&[1, 8]));
        // Boundary: exactly five carries when doubled.
        assert_eq!(b_carry_count(&(0..=9).collect::<Vec<u8>>()), 5);
    }

    #[test]
    fn seeds_vary_query_pairs() {
        let mut seen = std::collections::HashSet::new();
        for seed in 0..300u64 {
            seen.insert(sample(seed));
        }
        assert!(seen.len() >= 9, "only {} distinct pairs", seen.len());
    }

    #[test]
    fn canonical_answers_are_non_degenerate_for_every_op() {
        for seed in 0..200u64 {
            let digits = canonical(seed);
            assert!(
                anchors_hold(&digits),
                "seed {seed}: canonical anchors violated"
            );
            assert!(!b_is_valid(&digits));
            let ds = b_digit_sum(&digits);
            let cd = b_check_digit(&digits);
            let ds2 = b_doubled_sum(&digits);
            let cc = b_carry_count(&digits);
            // const-zero: every scalar answer must be nonzero on canonical
            // (the flag agrees with `false` here — flipped by the empty and
            // "18" worked examples).
            for v in [ds, cd, ds2, cc] {
                assert_ne!(v, 0, "seed {seed}");
            }
            // plain-sum-everything: exact only on digit_sum; the flag agrees
            // on canonical (invalid) and flips on valid examples.
            assert_ne!(cd, ds, "seed {seed}");
            assert_ne!(ds2, ds, "seed {seed}");
            assert_ne!(cc, ds, "seed {seed}");
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            for (digits, outs) in worked_examples(seed) {
                for (op, out) in outs {
                    assert_eq!(out, op_eval(op, &digits), "seed {seed} op {}", op.name());
                }
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        let g = LuhnFamily;
        for seed in 0..50u64 {
            let reference = g.reference_code(seed);
            for op in sample(seed).ops {
                let marker = format!("pub fn {}(", op.name());
                assert_eq!(
                    reference.lines().filter(|l| l.starts_with(&marker)).count(),
                    1,
                    "seed {seed} op {}",
                    op.name()
                );
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        let g = LuhnFamily;
        for seed in 0..50u64 {
            let sk = g.skeleton_code(seed);
            let task = g.generate(seed);
            for leak in ["% 10", "iter().rev()", "- 9", "is_multiple_of"] {
                assert!(!sk.contains(leak), "skeleton leaks {leak}");
                assert!(!task.prompt.contains(leak), "prompt leaks {leak}");
            }
            assert_eq!(sk.matches("todo!()").count(), 2);
            for op in sample(seed).ops {
                assert!(
                    task.prompt.contains(&op_sig_src(op)),
                    "prompt missing signature for {}",
                    op.name()
                );
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        for _seed in 0..50u64 {
            for op in OP_ALL {
                let call = call_src(op, "digits");
                let sig = op_sig_src(op);
                assert_eq!(
                    call.matches(',').count(),
                    sig.matches(',').count(),
                    "op {}",
                    op.name()
                );
            }
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = LuhnFamily;
        let task = g.generate(7);
        assert!(task.prompt.contains(&task.canary));
    }
}
