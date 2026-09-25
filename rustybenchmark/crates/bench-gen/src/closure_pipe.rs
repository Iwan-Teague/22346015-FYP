//! Higher-order pipelines over signed readings and caller-supplied transforms.
//!
//! Every query receives its arithmetic as an `impl Fn(i64) -> i64`
//! parameter, so a correct answer depends on invoking the parameter —
//! never on guessing its formula. Hidden tests drive each function with
//! two different closures (an identity and a shifting one); solutions
//! that ignore the parameter agree on one and fail the other. The model's
//! job is the plumbing: accept the bound, call it per element or twice,
//! and keep empty-input conventions without special cases.

use crate::{mint_canary, GeneratedTask, Generator, Rng};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    MapTotal,
    CountPositiveAfter,
    MaxTransformed,
    FirstNegativeAfter,
    ApplyTwice,
}

pub const OP_ALL: [Op; 5] = [
    Op::MapTotal,
    Op::CountPositiveAfter,
    Op::MaxTransformed,
    Op::FirstNegativeAfter,
    Op::ApplyTwice,
];

/// The identity transform used by half of every hidden assertion.
pub const IDENTITY_SRC: &str = "|v: i64| v";
/// The shifting transform used by the other half.
pub const SHIFT_SRC: &str = "|v: i64| 2 * v + 1";

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::MapTotal => "map_total",
            Op::CountPositiveAfter => "count_positive_after",
            Op::MaxTransformed => "max_transformed",
            Op::FirstNegativeAfter => "first_negative_after",
            Op::ApplyTwice => "apply_twice",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::MapTotal => "sum every reading after running it through the given transform",
            Op::CountPositiveAfter => {
                "count how many readings end up strictly positive once transformed"
            }
            Op::MaxTransformed => "report the heaviest transformed reading, minus one when the bag is empty",
            Op::FirstNegativeAfter => {
                "give the first position whose transformed value dips below zero, minus one if none do"
            }
            Op::ApplyTwice => "apply the given transform to its own output starting from one value",
        }
    }

    /// The extra non-closure parameters this op takes ahead of the transform.
    pub fn extra_arg(self) -> &'static str {
        match self {
            Op::ApplyTwice => ", x: i64",
            _ => "",
        }
    }

    /// Extra arguments passed at the call site (after the bag, before the closure).
    pub fn extra_call(self) -> &'static str {
        match self {
            Op::ApplyTwice => ", x",
            _ => "",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let a = rng.below(5) as usize;
    let mut b = rng.below(5) as usize;
    while b == a {
        b = rng.below(5) as usize;
    }
    let mut ops = [OP_ALL[a], OP_ALL[b]];
    ops.sort();
    Spec { ops }
}
pub type Out = i64;

pub fn b_map_total(xs: &[i64], f: impl Fn(i64) -> i64) -> i64 {
    xs.iter().map(|&x| f(x)).sum()
}

pub fn b_count_positive_after(xs: &[i64], f: impl Fn(i64) -> i64) -> i64 {
    xs.iter().filter(|&&x| f(x) > 0).count() as i64
}

pub fn b_max_transformed(xs: &[i64], f: impl Fn(i64) -> i64) -> i64 {
    let mut it = xs.iter().map(|&x| f(x));
    match it.next() {
        None => -1,
        Some(first) => it.fold(first, |best, v| if v > best { v } else { best }),
    }
}

pub fn b_first_negative_after(xs: &[i64], f: impl Fn(i64) -> i64) -> i64 {
    for (i, &x) in xs.iter().enumerate() {
        if f(x) < 0 {
            return i as i64;
        }
    }
    -1
}

pub fn b_apply_twice(x: i64, f: impl Fn(i64) -> i64) -> i64 {
    f(f(x))
}

/// Answers for one op under one transform.
fn eval(op: Op, bag: &[i64], x: i64, f: impl Fn(i64) -> i64) -> Out {
    match op {
        Op::MapTotal => b_map_total(bag, f),
        Op::CountPositiveAfter => b_count_positive_after(bag, f),
        Op::MaxTransformed => b_max_transformed(bag, f),
        Op::FirstNegativeAfter => b_first_negative_after(bag, f),
        Op::ApplyTwice => b_apply_twice(x, f),
    }
}

const CANONICAL_SEED: u64 = 0xC10C_FA11;

type CanonicalCase = (Vec<i64>, i64);

fn canonical(seed: u64) -> CanonicalCase {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let n = 3 + rng.below(4) as usize;
        let mut bag = Vec::new();
        for _ in 0..n {
            bag.push(rng.below(25) as i64 - 12);
        }
        let x = rng.below(11) as i64 - 3;
        if !anchors_hold(&bag, x) {
            continue;
        }
        return (bag, x);
    }
    unreachable!("canonical search never converged");
}

/// The canonical shifting transform, mirrored by SHIFT_SRC in emitted tests.
fn shift(v: i64) -> i64 {
    2 * v + 1
}

fn anchors_hold(bag: &[i64], x: i64) -> bool {
    if x == -1 {
        return false; // the only fixed point of the shift transform
    }
    let t_shift = b_map_total(bag, shift);
    if t_shift == 0 || t_shift == b_map_total(bag, |v| v) {
        return false;
    }
    // Increasing closures preserve the positive count and the first-negative
    // index, so those two ops are NOT required to differ from identity. The
    // ignore-closure cheat is instead defeated by forcing truths nonzero.
    let p_shift = b_count_positive_after(bag, shift);
    if p_shift == 0 {
        return false;
    }
    let m_shift = b_max_transformed(bag, shift);
    if m_shift < 1 || m_shift == b_max_transformed(bag, |v| v) {
        return false;
    }
    let a_shift = b_apply_twice(x, shift);
    if a_shift == 0 || a_shift == x {
        return false;
    }
    let fneg_shift = b_first_negative_after(bag, shift);
    if fneg_shift < 1 {
        return false;
    }
    let answers = [t_shift, p_shift, m_shift, a_shift, fneg_shift];
    for i in 0..answers.len() {
        for j in (i + 1)..answers.len() {
            if answers[i] == answers[j] {
                return false;
            }
        }
    }
    true
}
pub struct ExampleCase {
    pub bag: Vec<i64>,
    pub x: i64,
    /// Answers under the identity transform, in OP_ALL order.
    pub answers_g: Vec<Out>,
    /// Answers under the shifting transform, in OP_ALL order.
    pub answers_k: Vec<Out>,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_018C;

fn case(bag: Vec<i64>, x: i64) -> ExampleCase {
    let answers_g = OP_ALL.iter().map(|&op| eval(op, &bag, x, |v| v)).collect();
    let answers_k = OP_ALL
        .iter()
        .map(|&op| eval(op, &bag, x, |v| 2 * v + 1))
        .collect();
    ExampleCase {
        bag,
        x,
        answers_g,
        answers_k,
    }
}

fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![{
        let (bag, x) = canonical(seed);
        case(bag, x)
    }];
    out.push(case(Vec::new(), 3));
    out.push(case(vec![4], 2));
    out.push(case(vec![-2, 5], 0));
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    for _ in 0..3 {
        let n = rng.below(5) as usize;
        let mut bag = Vec::new();
        for _ in 0..n {
            bag.push(rng.below(13) as i64 - 6);
        }
        let x = rng.below(11) as i64 - 3;
        out.push(case(bag, x));
    }
    out
}

fn render_bag(bag: &[i64]) -> String {
    if bag.is_empty() {
        return "&[]".to_string();
    }
    let items: Vec<String> = bag.iter().map(|v| v.to_string()).collect();
    format!("&[{}i64, {}]", bag[0], items[1..].join(", "))
}

/// The call expression for one op; `xs` is the bound bag, `x` the scalar.
fn call_src(op: Op) -> String {
    match op {
        Op::MapTotal => "map_total(xs, f)".to_string(),
        Op::CountPositiveAfter => "count_positive_after(xs, f)".to_string(),
        Op::MaxTransformed => "max_transformed(xs, f)".to_string(),
        Op::FirstNegativeAfter => "first_negative_after(xs, f)".to_string(),
        Op::ApplyTwice => "apply_twice(x, f)".to_string(),
    }
}

pub fn op_sig_src(op: Op) -> String {
    match op {
        Op::ApplyTwice => "pub fn apply_twice(x: i64, f: impl Fn(i64) -> i64) -> i64".to_string(),
        _ => format!(
            "pub fn {}(xs: &[i64], f: impl Fn(i64) -> i64) -> i64",
            op.name()
        ),
    }
}

fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::MapTotal => &["xs.iter().map(|&x| f(x)).sum()"],
        Op::CountPositiveAfter => &["xs.iter().filter(|&&x| f(x) > 0).count() as i64"],
        Op::MaxTransformed => &[
            "let mut it = xs.iter().map(|&x| f(x));",
            "match it.next() {",
            "    None => -1,",
            "    Some(first) => it.fold(first, |best, v| if v > best { v } else { best }),",
            "}",
        ],
        Op::FirstNegativeAfter => &[
            "for (i, &x) in xs.iter().enumerate() {",
            "    if f(x) < 0 {",
            "        return i as i64;",
            "    }",
            "}",
            "-1",
        ],
        Op::ApplyTwice => &["f(f(x))"],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

fn reference_src(spec: Spec) -> String {
    spec.ops
        .iter()
        .map(|&op| op_fn_src(op))
        .collect::<Vec<_>>()
        .join("\n")
}
fn worked_examples_prose(examples: &[ExampleCase]) -> String {
    let mut s = String::new();
    for (i, ex) in examples.iter().enumerate() {
        for (closure_name, answers) in [("identity", &ex.answers_g), ("shifting", &ex.answers_k)] {
            let parts: Vec<String> = OP_ALL
                .iter()
                .zip(answers.iter())
                .map(|(op, out)| format!("{} = {}", op.name(), out))
                .collect();
            s.push_str(&format!(
                "//! ex{} bag {:?} x {} under the {} closure:\n",
                i, ex.bag, ex.x, closure_name
            ));
            s.push_str(&format!("//!   {}\n", parts.join(", ")));
        }
    }
    s
}

fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Fill in each function so it computes its answer by CALLING the\n\
         //! transform parameter it receives. The tests drive every function\n\
         //! with two different closures; a solution that ignores the closure\n\
         //! agrees with one and fails the other.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    for &op in spec.ops.iter() {
        s.push_str(&op_stub_src(op));
        s.push('\n');
    }
    s
}

fn prompt_intro() -> &'static str {
    "Implement the required functions. Each one takes its arithmetic as a \
     final `f: impl Fn(i64) -> i64` parameter and must produce its answer by \
     invoking that parameter - never by assuming what it computes."
}

fn prompt_src(spec: Spec, examples: &[ExampleCase], canary: &str) -> String {
    let mut s = String::from(prompt_intro());
    s.push_str("\n\nRequirements:\n");
    for &op in spec.ops.iter() {
        s.push_str(&format!("- {}.\n", op.prose()));
    }
    s.push_str("\nConstraints:\n");
    s.push_str("- Keep the exact function signatures, including the `impl Fn` bounds.\n");
    s.push_str("- The answer must change when the caller passes a different closure.\n");
    s.push_str("- No unsafe code.\n");
    s.push_str("\nSignatures:\n```rust\n");
    for &op in spec.ops.iter() {
        s.push_str(&op_sig_src(op));
        s.push('\n');
    }
    s.push_str("```\n\nWorked examples (answers shown per test closure):\n");
    s.push_str(&worked_examples_prose(examples));
    s.push_str(&format!(
        "\nYour answer must still contain the canary string \"{canary}\" in its doc comment.\n"
    ));
    s
}

fn cargo_toml() -> String {
    String::from(
        "[package]\nname = \"task\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
         [lib]\npath = \"src/lib.rs\"\n\n[workspace]\n",
    )
}
fn behavior_test_src(spec: &Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::new();
    s.push_str(
            "// Behavior tests: every function must call its transform parameter,\n// because each example runs under two different closures.\n",
        );
    let names = spec
        .ops
        .iter()
        .map(|o| o.name())
        .collect::<Vec<_>>()
        .join(", ");
    s.push_str(&format!("use task::{{{}}};\n", names));
    let phases = [
        ("identity_closure", "let f = |v: i64| v;"),
        ("shifting_closure", "let f = |v: i64| 2 * v + 1;"),
    ];
    for (i, ex) in examples.iter().enumerate() {
        for (phase_i, (fname, closure_line)) in phases.iter().enumerate() {
            let answers = if phase_i == 0 {
                &ex.answers_g
            } else {
                &ex.answers_k
            };
            s.push_str("\n#[test]\n");
            s.push_str(&format!("fn ex{}_{}() {{\n", i, fname));
            s.push_str(&format!("    let xs = {};\n", render_bag(&ex.bag)));
            s.push_str(&format!("    let x = {}i64;\n", ex.x));
            s.push_str(&format!("    {}\n", closure_line));
            for op in spec.ops {
                let idx = OP_ALL.iter().position(|o| *o == op).unwrap();
                s.push_str(&format!(
                    "    assert_eq!({}, {});\n",
                    call_src(op),
                    answers[idx]
                ));
            }
            s.push_str("}\n");
        }
    }
    s
}

fn differential_test_src(spec: &Spec) -> String {
    let mut s = String::new();
    let names = spec
        .ops
        .iter()
        .map(|o| o.name())
        .collect::<Vec<_>>()
        .join(", ");
    s.push_str(&format!("use task::{{{}}};\n\n", names));
    let mut pasted = reference_src(*spec);
    for op in spec.ops {
        let target = format!("pub fn {}(", op.name());
        let repl = format!("fn ref_{}(", op.name());
        assert_eq!(pasted.matches(&target).count(), 1);
        pasted = pasted.replacen(&target, &repl, 1);
    }
    s.push_str(&pasted);
    s.push_str("\n#[test]\nfn differential_matches_reference() {\n");
    s.push_str("    let mut state: u64 = 0xE7EE_ED00_0000_018C;\n");
    s.push_str("    for _ in 0..3000 {\n");
    s.push_str("        let n = (nx(&mut state) % 6) as usize;\n");
    s.push_str("        let mut bag: Vec<i64> = Vec::new();\n");
    s.push_str("        for _ in 0..n {\n");
    s.push_str("            bag.push((nx(&mut state) % 13) as i64 - 6);\n");
    s.push_str("        }\n");
    s.push_str("        let x = (nx(&mut state) % 11) as i64 - 3;\n");
    for op in spec.ops {
        let call = call_src(op).replace("xs, f", "&bag, |v: i64| 2 * v + 1");
        let call = if op.extra_call().is_empty() {
            call
        } else {
            // ApplyTwice carries its own x argument already substituted below.
            call.replace("x, f", "x, |v: i64| 2 * v + 1")
        };
        let ref_call = call.replacen(
            &format!("{}(", op.name()),
            &format!("ref_{}(", op.name()),
            1,
        );
        s.push_str(&format!("        assert_eq!({}, {});\n", call, ref_call));
    }
    s.push_str("    }\n}\n\nfn nx(state: &mut u64) -> u64 {\n");
    s.push_str("    *state = state\n");
    s.push_str("        .wrapping_mul(6364136223846793005)\n");
    s.push_str("        .wrapping_add(1442695040888963407);\n");
    s.push_str("    *state >> 33\n");
    s.push_str("}\n");
    s
}

fn const_zero_src(spec: &Spec) -> String {
    spec.ops
        .iter()
        .copied()
        .map(|op| {
            let silencer = if op.extra_arg().is_empty() {
                "    let _ = xs;"
            } else {
                "    let _ = (x, f);"
            };
            format!("{}\n{}\n    0\n}}\n", op_sig_src(op), silencer)
        })
        .collect::<String>()
}

fn ignore_closure_src(spec: &Spec) -> String {
    spec.ops
        .iter()
        .copied()
        .map(|op| {
            let body: &[&str] = match op {
                Op::MapTotal => &["    let _ = f;", "    xs.iter().sum::<i64>()"],
                Op::CountPositiveAfter => &["    let _ = (f, xs);", "    0"],
                Op::MaxTransformed => &[
                    "    let _ = f;",
                    "    xs.iter().copied().max().unwrap_or(-1)",
                ],
                Op::FirstNegativeAfter => &["    let _ = (f, xs);", "    0"],
                Op::ApplyTwice => &["    let _ = f;", "    x"],
            };
            format!("{}\n{}\n}}\n", op_sig_src(op), body.join("\n"))
        })
        .collect::<String>()
}
pub struct ClosurePipeFamily;

impl Generator for ClosurePipeFamily {
    fn id(&self) -> &'static str {
        "closure-pipe"
    }

    fn category(&self) -> &'static str {
        "higher-order-functions"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("closure-pipe", seed);
        let mut files = std::collections::BTreeMap::new();
        files.insert(std::path::PathBuf::from("Cargo.toml"), cargo_toml());
        files.insert(
            std::path::PathBuf::from("src/lib.rs"),
            skeleton_src(spec, &examples),
        );
        let mut hidden = std::collections::BTreeMap::new();
        hidden.insert(
            std::path::PathBuf::from("tests/behavior.rs"),
            behavior_test_src(&spec, &examples),
        );
        hidden.insert(
            std::path::PathBuf::from("tests/differential.rs"),
            differential_test_src(&spec),
        );
        GeneratedTask {
            id: format!("closure-pipe/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt_src(spec, &examples, &canary),
            canary,
            answer_path: String::from("src/lib.rs"),
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            files,
            hidden,
            weights: (0.70, 0.20, 0.10),
            alloc_test: String::new(),
            max_unsafe: None,
            forbidden_paths: vec![],
            check_clippy: false,
            clippy_allow: vec![],
        }
    }

    fn reference_code(&self, seed: u64) -> String {
        reference_src(sample(seed))
    }

    fn skeleton_code(&self, seed: u64) -> String {
        let spec = sample(seed);
        skeleton_src(spec, &worked_examples(seed))
    }

    fn trivial_baselines(&self, seed: u64) -> Vec<(String, String)> {
        let spec = sample(seed);
        vec![
            ("const-zero".to_string(), const_zero_src(&spec)),
            ("ignore-closure".to_string(), ignore_closure_src(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        sample(seed)
            .ops
            .iter()
            .map(|op| format!("q:{}", op.name()))
            .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    const IDENTITY: fn(i64) -> i64 = |v| v;
    fn shift(v: i64) -> i64 {
        2 * v + 1
    }

    #[test]
    fn generation_is_deterministic() {
        let a = ClosurePipeFamily.generate(81);
        let b = ClosurePipeFamily.generate(81);
        assert_eq!(a.id, b.id);
        assert_eq!(a.prompt, b.prompt);
        assert_eq!(a.files, b.files);
        assert_eq!(a.hidden, b.hidden);
    }

    #[test]
    fn native_ops_track_the_closure_parameter() {
        let bag = vec![3, -1, 4];
        assert_eq!(b_map_total(&bag, IDENTITY), 6);
        assert_eq!(b_map_total(&bag, shift), 15);
        assert_eq!(b_count_positive_after(&bag, shift), 2);
        assert_eq!(b_count_positive_after(&bag, |v| v * v - 9), 1);
        assert_eq!(b_max_transformed(&[], shift), -1);
        assert_eq!(b_max_transformed(&bag, |v| v * v), 16);
        assert_eq!(b_first_negative_after(&bag, |v| v * v), -1);
        assert_eq!(b_first_negative_after(&bag, IDENTITY), 1);
        assert_eq!(b_apply_twice(5, |v| v + 3), 11);
        assert_eq!(b_apply_twice(5, IDENTITY), 5);
    }

    #[test]
    fn seeds_vary_query_pairs() {
        let mut seen = std::collections::HashSet::new();
        for seed in 0..300u64 {
            seen.insert(sample(seed));
        }
        assert!(seen.len() >= 9);
    }

    #[test]
    fn canonical_answers_are_non_degenerate_for_every_op() {
        for seed in 0..200u64 {
            let case = canonical(seed ^ CANONICAL_SEED);
            let raw = &case.0;
            let x = case.1;
            let mut truths: Vec<i64> = Vec::new();
            for op in OP_ALL {
                let under_shift = eval(op, raw, x, shift);
                let raw_answer = eval(op, raw, x, IDENTITY);
                assert_ne!(under_shift, 0, "seed {seed} op {op:?}");
                if matches!(op, Op::MapTotal | Op::MaxTransformed | Op::ApplyTwice) {
                    assert_ne!(
                        under_shift, raw_answer,
                        "seed {seed} op {op:?}: value ops must expose the closure"
                    );
                }
                truths.push(under_shift);
            }
            for i in 0..truths.len() {
                for j in (i + 1)..truths.len() {
                    assert_ne!(
                        truths[i], truths[j],
                        "seed {seed}: answers {} and {} collide",
                        truths[i], truths[j]
                    );
                }
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for ex in worked_examples(seed) {
                for op in spec.ops {
                    let idx = OP_ALL.iter().position(|o| *o == op).unwrap();
                    assert_eq!(eval(op, &ex.bag, ex.x, IDENTITY), ex.answers_g[idx]);
                    assert_eq!(eval(op, &ex.bag, ex.x, shift), ex.answers_k[idx]);
                }
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        for seed in 0..50u64 {
            let spec = sample(seed);
            let reference = reference_src(spec);
            for op in OP_ALL {
                let marker = format!("pub fn {}(", op.name());
                let expected = usize::from(spec.ops.contains(&op));
                assert_eq!(
                    reference.matches(&marker).count(),
                    expected,
                    "seed {seed} op {op:?}"
                );
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        for seed in 0..50u64 {
            let spec = sample(seed);
            let sk = skeleton_src(spec, &worked_examples(seed));
            let prompt = prompt_src(spec, &worked_examples(seed), "rb-canary-check");
            assert_eq!(sk.matches("todo!()").count(), spec.ops.len());
            for token in [".map(", ".filter(", ".fold("] {
                assert!(!sk.contains(token), "seed {seed} leaks {token}");
                assert!(!prompt.contains(token), "seed {seed} prompt leaks {token}");
            }
            for op in spec.ops.iter().copied() {
                assert!(prompt.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        for seed in 0..50u64 {
            let spec = sample(seed);
            for op in spec.ops.iter().copied() {
                let params = op_sig_src(op)
                    .split("->")
                    .next()
                    .unwrap()
                    .matches(',')
                    .count();
                let call = call_src(op).matches(',').count();
                assert_eq!(params, call, "seed {seed} op {op:?}");
            }
        }
    }

    #[test]
    fn ignore_closure_baseline_never_calls_the_transform() {
        for seed in 0..50u64 {
            let spec = sample(seed);
            let baseline = ignore_closure_src(&spec);
            let reference = reference_src(spec);
            assert!(
                !baseline.contains("f("),
                "seed {seed}: ignore-closure cheat calls f"
            );
            assert!(
                reference.matches("f(").count() >= spec.ops.len(),
                "seed {seed}: reference must route through f"
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let task = ClosurePipeFamily.generate(9);
        assert!(task.prompt.contains(&task.canary));
    }
}
