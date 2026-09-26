//! The `dice` family (category `dice-games`) — pair-of-dice game
//! arithmetic.
//!
//! Where `playing-card` reads one card and `coins` decomposes cash,
//! this family exercises **table-game conventions over a roll**: the
//! total, the product, the doubles predicate, the higher face, and the
//! craps come-out natural. The domain is an ordered pair of faces,
//! each `u64` from one through six. The seed prunes which two of five
//! query ops are required: `total`, `product`, `is_doubles`,
//! `higher_roll`, `pass_line_win`. C(5,2) = **10 distinct skills**,
//! above the diversity floor; op names are semantic.
//!
//! The canonical roll is sampled until its anchor facts hold: it is a
//! HIGH DOUBLE — both faces equal and at least three — so the doubles
//! predicate answers TRUE there (constant-false cheats die outright on
//! every op) while the three scalars stay pairwise distinct (two times
//! the face, its square, and the face itself). The come-out natural is
//! impossible on a double — doubles sum even, naturals are odd — so
//! that predicate answers FALSE on the canonical roll and constant-true
//! cheats die there too (the pinned natural examples flip cheats that
//! answer false).
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random rolls against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the
//! canonical roll) and `total-everything` (every query answered with
//! the sum of the faces — exact only for the total itself).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    Total,
    Product,
    IsDoubles,
    HigherRoll,
    PassLineWin,
}

const OP_ALL: [Op; 5] = [
    Op::Total,
    Op::Product,
    Op::IsDoubles,
    Op::HigherRoll,
    Op::PassLineWin,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::Total => "total",
            Op::Product => "product",
            Op::IsDoubles => "is_doubles",
            Op::HigherRoll => "higher_roll",
            Op::PassLineWin => "pass_line_win",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::Total => "the sum of the two faces",
            Op::Product => "the product of the two faces",
            Op::IsDoubles => "whether both faces match — a hard-way roll",
            Op::HigherRoll => {
                "the larger of the two faces; on a tie either face is \
                 the answer"
            }
            Op::PassLineWin => {
                "whether the roll is a craps come-out natural — a sum \
                 of seven or eleven"
            }
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::IsDoubles | Op::PassLineWin => "bool",
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

/// The sum of the two faces.
fn b_total(first: u64, second: u64) -> i64 {
    (first + second) as i64
}

/// The product of the two faces.
fn b_product(first: u64, second: u64) -> i64 {
    (first * second) as i64
}

/// Doubles: both faces match.
fn b_is_doubles(first: u64, second: u64) -> bool {
    first == second
}

/// The larger face; ties return the shared value.
fn b_higher_roll(first: u64, second: u64) -> i64 {
    (if second > first { second } else { first }) as i64
}

/// Craps come-out natural: the sum is seven or eleven.
fn b_pass_line_win(first: u64, second: u64) -> bool {
    let total = b_total(first, second);
    total == 7 || total == 11
}

/// The answer shape: scalars as `Num`, predicates as `Flag`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Flag(bool),
}

impl Out {
    fn lit(&self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            Out::Flag(b) => b.to_string(),
        }
    }
}

fn op_eval(op: Op, first: u64, second: u64) -> Out {
    match op {
        Op::Total => Out::Num(b_total(first, second)),
        Op::Product => Out::Num(b_product(first, second)),
        Op::IsDoubles => Out::Flag(b_is_doubles(first, second)),
        Op::HigherRoll => Out::Num(b_higher_roll(first, second)),
        Op::PassLineWin => Out::Flag(b_pass_line_win(first, second)),
    }
}

// ---- canonical roll -------------------------------------------------------

/// The canonical roll: sampled from the full table and retried until the
/// anchor facts hold.
///
/// Guaranteed for every seed: a HIGH DOUBLE — both faces equal and at
/// least three. The doubles predicate answers TRUE there (constant-false
/// cheats die outright), the natural predicate answers FALSE (a double's
/// sum is even; naturals are odd — constant-true cheats die too and the
/// pinned winner examples flip cheats that answer false), and the three
/// scalars stay pairwise distinct: twice the face, its square, and the
/// face itself never collide at a face of three or more.
fn canonical(seed: u64) -> (u64, u64) {
    let mut rng = Rng::new(seed ^ 0xD1CE_FA11);
    for _ in 0..100_000 {
        let first = 1 + rng.below(6);
        let second = 1 + rng.below(6);
        if anchors_hold(first, second) {
            return (first, second);
        }
    }
    unreachable!("canonical roll sampling failed to satisfy anchors");
}

fn anchors_hold(first: u64, second: u64) -> bool {
    // A high double keeps the three scalars apart: total 2d, product
    // d^2, higher d collide only at d = 2 (4 vs 4) and d = 1 (product
    // meets higher at one).
    b_is_doubles(first, second)
        && b_total(first, second) != b_product(first, second)
        && b_product(first, second) != b_higher_roll(first, second)
        && b_higher_roll(first, second) != b_total(first, second)
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = ((u64, u64), Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_015E);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical high double first.
    let can = canonical(seed);
    cases.push((
        can,
        spec.ops.map(|op| (op, op_eval(op, can.0, can.1))).to_vec(),
    ));
    // Snake eyes: a double (flag TRUE) that is no natural.
    cases.push(((1, 1), spec.ops.map(|op| (op, op_eval(op, 1, 1))).to_vec()));
    // A come-out natural winner — flips constant-false cheats.
    cases.push(((3, 4), spec.ops.map(|op| (op, op_eval(op, 3, 4))).to_vec()));
    // A craps loser.
    cases.push(((2, 3), spec.ops.map(|op| (op, op_eval(op, 2, 3))).to_vec()));
    // Yo-leven: the other natural.
    cases.push(((5, 6), spec.ops.map(|op| (op, op_eval(op, 5, 6))).to_vec()));
    for _ in 0..3 {
        let first = 1 + rng.below(6);
        let second = 1 + rng.below(6);
        let outs = spec.ops.map(|op| (op, op_eval(op, first, second))).to_vec();
        cases.push(((first, second), outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the first element types the tuple.
fn render_pair(first: u64, second: u64) -> String {
    format!("({first}u64, {second})")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    let sig = format!("(first: u64, second: u64) -> {ret}");
    let body = match op {
        Op::Total => ["(first + second) as i64"].join("\n    "),
        Op::Product => ["(first * second) as i64"].join("\n    "),
        Op::IsDoubles => ["first == second"].join("\n    "),
        Op::HigherRoll => "(if second > first { second } else { first }) as i64".to_string(),
        Op::PassLineWin => [
            "let total = (first + second) as i64;",
            "total == 7 || total == 11",
        ]
        .join("\n    "),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(first: u64, second: u64) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!(
        "pub fn {}(first: u64, second: u64) -> {}",
        op.name(),
        op.ret()
    )
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
    for ((first, second), outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  roll {}  ->  {}\n",
            render_pair(first, second),
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
         an ordered pair `(first, second)`: the two dice faces, each \
         `u64` from one through six as they landed.\n\
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
fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let imports = spec
        .ops
        .iter()
        .map(|op| op.name())
        .collect::<Vec<_>>()
        .join(", ");
    let mut body = format!("use task::{{{imports}}};\n\n");
    for (i, ((first, second), outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let (first, second) = {};\n",
            render_pair(*first, *second),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "first, second"),
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
            let call = call_src(*op, "first, second");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_015E;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let first = (nx(&mut state) % 6) + 1;\n\
         \x20       let second = (nx(&mut state) % 6) + 1;\n\
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
/// Degenerate: zero answers everywhere.
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            let tail = match op.ret() {
                "bool" => "false",
                _ => "0",
            };
            format!("{sig} {{\n    let _ = (first, second);\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every query with the sum of the faces.
/// On the canonical high double this misses everywhere — the product,
/// the higher face, and the doubles predicate all disagree with the
/// total, and the natural predicate disagrees with its constant false.
fn total_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => format!("{sig} {{\n    false\n}}\n"),
                _ => format!("{sig} {{\n    (first + second) as i64\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct DiceFamily;

impl Generator for DiceFamily {
    fn id(&self) -> &str {
        "dice"
    }
    fn category(&self) -> &str {
        "dice-games"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("dice", seed);

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
            id: format!("dice/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure lookup and integer queries — no unsafe anywhere.
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
            ("total-everything".to_string(), total_everything(&spec)),
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
        let g = DiceFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Totals: snake eyes, boxcars, order-blind.
        assert_eq!(b_total(1, 1), 2);
        assert_eq!(b_total(6, 6), 12);
        assert_eq!(b_total(3, 4), b_total(4, 3));
        // Products.
        assert_eq!(b_product(1, 1), 1);
        assert_eq!(b_product(6, 6), 36);
        assert_eq!(b_product(3, 4), b_product(4, 3));
        // Doubles boundary: all six hard ways, mixed pairs lose.
        for face in 1..=6u64 {
            assert!(b_is_doubles(face, face));
            assert!(!b_is_doubles(face, face % 6 + 1));
        }
        // Higher roll: ties and both orders.
        assert_eq!(b_higher_roll(4, 4), 4);
        assert_eq!(b_higher_roll(2, 5), 5);
        assert_eq!(b_higher_roll(5, 2), 5);
        assert_eq!(b_higher_roll(1, 6), 6);
        // Naturals are seven or eleven only; doubles never win.
        assert!(b_pass_line_win(3, 4));
        assert!(b_pass_line_win(5, 6));
        assert!(!b_pass_line_win(6, 4));
        assert!(!b_pass_line_win(1, 2));
        for face in 1..=6u64 {
            assert!(!b_pass_line_win(face, face));
        }
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
        // The canonical roll is a HIGH DOUBLE, so NO skips anywhere
        // except total-everything on the total itself: const-zero dies
        // on all five ops outright (scalars nonzero, the doubles flag
        // true); total-everything misses product/higher/both flags —
        // its false flags lose to the canonical TRUE. The pinned
        // natural examples flip cheats that answer false everywhere.
        for seed in 0..200u64 {
            let (first, second) = canonical(seed);
            let t = b_total(first, second);
            let p = b_product(first, second);
            let h = b_higher_roll(first, second);
            // Anchor facts the sampler enforces.
            assert!(b_is_doubles(first, second), "seed {seed}: must be a double");
            assert_ne!(t, p, "seed {seed}: total must differ from product");
            assert_ne!(p, h, "seed {seed}: product must differ from higher");
            assert_ne!(h, t, "seed {seed}: higher must differ from total");
            // const-zero survives nowhere.
            assert_ne!(t, 0, "const-zero survives at seed {seed}");
            assert_ne!(p, 0, "seed {seed}");
            assert_ne!(h, 0, "seed {seed}");
            assert!(b_is_doubles(first, second), "seed {seed}");
            // total-everything survives nowhere but the total itself.
            assert_ne!(
                p,
                b_total(first, second),
                "total-everything survives product at seed {seed}"
            );
            assert_ne!(
                h,
                b_total(first, second),
                "total-everything survives higher at seed {seed}"
            );
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for ((first, second), outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, first, second), out, "seed {seed}");
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
                // Match the `pub fn` line plus the paren so no bare-name
                // substring leaks.
                let fn_line = format!("pub fn {}(", op.name());
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
            // Solution-shaped leak tokens must stay out of the skeleton;
            // the worked examples legitimately show outputs, never
            // rules — so tokens carry implementation shapes.
            assert!(!sk.contains("+ second"));
            assert!(!sk.contains("* second"));
            assert!(!sk.contains("== second"));
            assert!(!sk.contains("== 7"));
            assert!(!sk.contains("else {"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("+ second"));
            assert!(!p.contains("* second"));
            assert!(!p.contains("== second"));
            assert!(!p.contains("== 7"));
            assert!(!p.contains("else {"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every op here takes the pair: exactly one comma on both sides.
        for op in OP_ALL {
            let sig = op_sig_src(op);
            let params = sig.split("->").next().unwrap();
            let call = call_src(op, "first, second");
            assert_eq!(
                call.matches(',').count(),
                params.matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{sig}`"
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = DiceFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
