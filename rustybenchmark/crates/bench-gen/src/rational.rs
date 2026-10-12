//! `rational` — exact-fraction queries over a seeded integer ratio.
//!
//! A task instance is one integer ratio `n / d` (`d` never zero; either
//! sign allowed). The seed picks two of five query operations; the model
//! must implement both exactly as specified and match a hidden reference
//! implementation on thousands of random ratios.
//!
//! Category: `rational-arithmetic`.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    /// Numerator in lowest terms, sign carried here.
    SimplifiedNum,
    /// Denominator in lowest terms, always positive.
    SimplifiedDen,
    /// Whether the fraction denotes an integer.
    IsInteger,
    /// Evenness of the reduced numerator.
    NumeratorParity,
    /// Absolute value as a reduced pair.
    AbsValue,
}

const OP_ALL: [Op; 5] = [
    Op::SimplifiedNum,
    Op::SimplifiedDen,
    Op::IsInteger,
    Op::NumeratorParity,
    Op::AbsValue,
];

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::SimplifiedNum => "simplified_num",
            Op::SimplifiedDen => "simplified_den",
            Op::IsInteger => "is_integer",
            Op::NumeratorParity => "numerator_parity",
            Op::AbsValue => "abs_value",
        }
    }

    fn ret(self) -> &'static str {
        match self {
            Op::IsInteger => "bool",
            Op::AbsValue => "(i64, i64)",
            _ => "i64",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::SimplifiedNum => "the numerator after reducing the fraction to lowest terms with a positive denominator, carrying the sign on the numerator alone",
            Op::SimplifiedDen => "the denominator after reducing the fraction to lowest terms; always strictly positive, and exactly one when the value is an integer",
            Op::IsInteger => "whether the fraction denotes a whole number",
            Op::NumeratorParity => "zero when the reduced numerator is even, one when it is odd — parity is read AFTER reduction, so signs never matter",
            Op::AbsValue => "the absolute value of the fraction as a reduced numerator-denominator pair with a positive denominator",
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

fn b_simplified_num(n: i64, d: i64) -> i64 {
    let mut a = n.abs();
    let mut b = d.abs();
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    let s = if d < 0 { -1 } else { 1 };
    n * s / a
}

fn b_simplified_den(n: i64, d: i64) -> i64 {
    let mut a = n.abs();
    let mut b = d.abs();
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    d.abs() / a
}

fn b_is_integer(n: i64, d: i64) -> bool {
    n % d == 0
}

fn b_numerator_parity(n: i64, d: i64) -> i64 {
    b_simplified_num(n, d).rem_euclid(2)
}

fn b_abs_value(n: i64, d: i64) -> (i64, i64) {
    (b_simplified_num(n, d).abs(), b_simplified_den(n, d))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Flag(bool),
    Pair(i64, i64),
}

impl Out {
    fn lit(self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            Out::Flag(b) => b.to_string(),
            Out::Pair(a, b) => format!("({a}i64, {b})"),
        }
    }
}

fn op_eval(op: Op, n: i64, d: i64) -> Out {
    match op {
        Op::SimplifiedNum => Out::Num(b_simplified_num(n, d)),
        Op::SimplifiedDen => Out::Num(b_simplified_den(n, d)),
        Op::IsInteger => Out::Flag(b_is_integer(n, d)),
        Op::NumeratorParity => Out::Num(b_numerator_parity(n, d)),
        Op::AbsValue => {
            let (a, b) = b_abs_value(n, d);
            Out::Pair(a, b)
        }
    }
}

const CANONICAL_SEED: u64 = 0x9A71_0F11;

/// The canonical ratio is deliberately NON-integral with every scalar
/// answer nonzero and pairwise distinct — so const-zero misses everything
/// scalar and the parity-everything cheat stays exact only on its own
/// query.
fn canonical(seed: u64) -> (i64, i64) {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let n = rng.below(41) as i64 - 20;
        let d = rng.below(21) as i64 - 20;
        if anchors_hold(n, d) {
            return (n, d);
        }
    }
    unreachable!("rational canonical anchor search exhausted");
}

fn anchors_hold(n: i64, d: i64) -> bool {
    if d == 0 || b_is_integer(n, d) {
        return false;
    }
    let sn = b_simplified_num(n, d);
    let sd = b_simplified_den(n, d);
    let p = b_numerator_parity(n, d);
    let an = sn.abs();
    if sn == 0 {
        return false;
    }
    // All four scalars pairwise distinct (this also forces |sn| >= 2).
    let scalars = [sn, sd, p, an];
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

type ExampleCase = ((i64, i64), Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_012C;

fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    // ex0: the canonical non-integral ratio.
    // ex1: zero over five pins the 0/1 conventions AND a `true` from
    //      is_integer — flipping both cheats' hardcoded `false`.
    // ex2: eight over negative four reduces to -2/1: sign normalization.
    let canon = canonical(seed);
    let mut examples: Vec<ExampleCase> = vec![
        (
            canon,
            OP_ALL
                .iter()
                .map(|&op| (op, op_eval(op, canon.0, canon.1)))
                .collect(),
        ),
        (
            (0, 5),
            OP_ALL.iter().map(|&op| (op, op_eval(op, 0, 5))).collect(),
        ),
        (
            (8, -4),
            OP_ALL.iter().map(|&op| (op, op_eval(op, 8, -4))).collect(),
        ),
    ];
    for _ in 0..3 {
        let n = rng.below(41) as i64 - 20;
        let d = (1 + rng.below(10)) as i64;
        let p = (n, d);
        let answers = OP_ALL
            .iter()
            .map(|&op| (op, op_eval(op, p.0, p.1)))
            .collect();
        examples.push((p, answers));
    }
    examples
}

fn render_ratio(p: (i64, i64)) -> String {
    format!("({}i64, {})", p.0, p.1)
}

fn call_src(op: Op, var: &str) -> String {
    format!("{}({})", op.name(), var)
}

fn op_fn_src(op: Op) -> String {
    let body: String = match op {
        Op::SimplifiedNum => [
            "let mut a = n.abs();",
            "let mut b = d.abs();",
            "while b != 0 {",
            "    let t = a % b;",
            "    a = b;",
            "    b = t;",
            "}",
            "let s = if d < 0 { -1 } else { 1 };",
            "n * s / a",
        ]
        .join("\n    "),
        Op::SimplifiedDen => [
            "let mut a = n.abs();",
            "let mut b = d.abs();",
            "while b != 0 {",
            "    let t = a % b;",
            "    a = b;",
            "    b = t;",
            "}",
            "d.abs() / a",
        ]
        .join("\n    "),
        Op::IsInteger => ["n % d == 0"].join("\n    "),
        Op::NumeratorParity => [
            "let mut a = n.abs();",
            "let mut b = d.abs();",
            "while b != 0 {",
            "    let t = a % b;",
            "    a = b;",
            "    b = t;",
            "}",
            "let s = if d < 0 { -1 } else { 1 };",
            "(n * s / a).rem_euclid(2)",
        ]
        .join("\n    "),
        Op::AbsValue => [
            "let mut a = n.abs();",
            "let mut b = d.abs();",
            "while b != 0 {",
            "    let t = a % b;",
            "    a = b;",
            "    b = t;",
            "}",
            "let s = if d < 0 { -1 } else { 1 };",
            "((n * s / a).abs(), d.abs() / a)",
        ]
        .join("\n    "),
    };
    format!(
        "pub fn {}(n: i64, d: i64) -> {} {{\n    {}\n}}\n",
        op.name(),
        op.ret(),
        body
    )
}

fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(n: i64, d: i64) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(n: i64, d: i64) -> {}", op.name(), op.ret())
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
    for (p, outs) in worked_examples(seed) {
        let results = outs
            .iter()
            .filter(|(op, _)| spec.ops.contains(op))
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  ratio {}  ->  {}\n", render_ratio(p), results));
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
         given as two integers `n` and `d` describing the ratio `n / d`; \
         the denominator is never zero and either sign may appear. \
         Queries are exact-fraction properties of that ratio.\n\
         \n\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         - Work with exact integer arithmetic only; no floating point.\n\
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
    for (i, (p, outs)) in worked_examples(seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let (n, d) = {};\n",
            render_ratio(*p),
        ));
        for (op, out) in outs {
            if !spec.ops.contains(op) {
                continue;
            }
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "n, d"),
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
            let call = call_src(*op, "n, d");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_012E;\n\
         \x20   for _ in 0..3000 {{\n\
          \x20       let n = (nx(&mut state) % 41) as i64 - 20;\n\
          \x20       let roll = nx(&mut state) % 3;\n\
          \x20       let d = if roll == 0 {{ -((nx(&mut state) % 19 + 1) as i64) }} else {{ (nx(&mut state) % 19 + 1) as i64 }};\n\
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

/// Degenerate: everything zero (hardcoded `false` on the boolean, the zero
/// ratio on the pair).
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => format!("{sig} {{\n    let _ = (n, d);\n    false\n}}\n"),
                "(i64, i64)" => {
                    format!("{sig} {{\n    let _ = (n, d);\n    (0, 1)\n}}\n")
                }
                _ => format!("{sig} {{\n    let _ = (n, d);\n    0\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer the reduced numerator's parity no matter
/// what was asked. The canonical anchors make both reduced components and
/// their magnitude disagree with a bare parity bit; `numerator_parity`
/// itself is exact, and any pair containing it is caught by its partner.
/// The is_integer flag agrees with this cheat on the canonical but flips
/// on the whole-number worked examples.
fn parity_everything(spec: &Spec) -> String {
    let p_body = [
        "let mut a = n.abs();",
        "let mut b = d.abs();",
        "while b != 0 {",
        "    let t = a % b;",
        "    a = b;",
        "    b = t;",
        "}",
        "let s = if d < 0 { -1 } else { 1 };",
        "(n * s / a).rem_euclid(2)",
    ]
    .join("\n    ");
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => format!("{sig} {{\n    let _ = (n, d);\n    false\n}}\n"),
                "(i64, i64)" => {
                    format!("{sig} {{\n    let _ = (n, d);\n    (0, 1)\n}}\n")
                }
                _ => format!("{sig} {{\n    {p_body}\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct RationalFamily;

impl Generator for RationalFamily {
    fn id(&self) -> &str {
        "rational"
    }
    fn category(&self) -> &str {
        "rational-arithmetic"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("rational", seed);

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
            id: format!("rational/{seed:016x}"),
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
                "numerator-parity-everything".to_string(),
                parity_everything(&spec),
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
        let g = RationalFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // 8/12 reduces to 2/3.
        assert_eq!(b_simplified_num(8, 12), 2);
        assert_eq!(b_simplified_den(8, 12), 3);
        // Sign normalization lands on the numerator alone.
        assert_eq!(b_simplified_num(-8, -12), 2);
        assert_eq!(b_simplified_num(8, -12), -2);
        assert!(!b_is_integer(8, 12));
        assert!(b_is_integer(-8, -4));
        // Parity is read after reduction: -9/6 -> -3/2 -> odd.
        assert_eq!(b_numerator_parity(-9, 6), 1);
        assert_eq!(b_numerator_parity(0, 5), 0);
        assert_eq!(b_abs_value(-8, 12), (2, 3));
        assert_eq!(b_abs_value(0, -5), (0, 1));
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
            let (n, d) = canonical(seed);
            assert!(
                anchors_hold(n, d),
                "seed {seed}: canonical anchors violated"
            );
            let sn = b_simplified_num(n, d);
            let sd = b_simplified_den(n, d);
            let p = b_numerator_parity(n, d);
            let pair = b_abs_value(n, d);
            assert!(!b_is_integer(n, d));
            assert_ne!(sn, 0);
            // const-zero: reduced components nonzero and the pair is not
            // the zero ratio. Parity is skipped: it is zero by definition
            // whenever the reduced numerator is even, agreeing with the
            // cheat there — const-zero is still caught by sn/sd/pair on
            // every canonical and by the flag flips on whole examples.
            for v in [sn, sd] {
                assert_ne!(v, 0, "seed {seed}");
            }
            assert_ne!(pair, (0, 0), "seed {seed}");
            // parity-everything: exact only on numerator_parity; the pair
            // cheat answer is the zero ratio.
            assert_ne!(sn, p, "seed {seed}");
            assert_ne!(sd, p, "seed {seed}");
            assert_ne!(pair, (p, 1), "seed {seed}");
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            for (p, outs) in worked_examples(seed) {
                for (op, out) in outs {
                    assert_eq!(out, op_eval(op, p.0, p.1), "seed {seed} op {}", op.name());
                }
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        let g = RationalFamily;
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
        let g = RationalFamily;
        for seed in 0..50u64 {
            let sk = g.skeleton_code(seed);
            let task = g.generate(seed);
            for leak in ["% d", "* s / a", "while b != 0"] {
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
        for seed in 0..50u64 {
            let _ = seed;
            for op in OP_ALL {
                let call = call_src(op, "n, d");
                let sig = op_sig_src(op);
                // Count commas in the parameter list only — tuple return
                // types carry commas of their own.
                let params = sig.split("->").next().unwrap();
                assert_eq!(
                    call.matches(',').count(),
                    params.matches(',').count(),
                    "op {}",
                    op.name()
                );
            }
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = RationalFamily;
        let task = g.generate(7);
        assert!(task.prompt.contains(&task.canary));
    }
}
