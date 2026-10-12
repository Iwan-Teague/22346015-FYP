//! The `triangle` family (category `triangle-geometry`) — classic
//! properties of one triangle given by its three side lengths.
//!
//! The domain is one unordered triple of side lengths (`u64` each).
//! The seed prunes which two of five query ops are required:
//! `perimeter`, `is_valid`, `longest_side`, `is_right`,
//! `num_distinct_sides`. C(5,2) = **10 distinct skills**, above the
//! diversity floor; op names are semantic.
//!
//! Canonical inputs are CONSTRUCTED, not blind-sampled: a primitive
//! Pythagorean triple is scaled and its slots rotated, so the canonical
//! triangle is always valid AND right-angled with three distinct
//! lengths. Both flags therefore read TRUE — separating them from any
//! cheat that answers `false` — while the scalars stay nonzero,
//! pairwise-separated from the longest side, and strictly larger than
//! the inputs they summarize. `const-zero` fails everywhere and
//! `longest-everything` (every query answered with the longest side) is
//! exact only on its own op.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random triples against the model.
//!
//! Trivial baselines: `const-zero` (fails outright on the canonical
//! triangle) and `longest-everything`.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    Perimeter,
    IsValid,
    LongestSide,
    IsRight,
    NumDistinctSides,
}

const OP_ALL: [Op; 5] = [
    Op::Perimeter,
    Op::IsValid,
    Op::LongestSide,
    Op::IsRight,
    Op::NumDistinctSides,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::Perimeter => "perimeter",
            Op::IsValid => "is_valid",
            Op::LongestSide => "longest_side",
            Op::IsRight => "is_right",
            Op::NumDistinctSides => "num_distinct_sides",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::Perimeter => "the sum of the three side lengths",
            Op::IsValid => {
                "whether the lengths form a proper triangle at all: \
                 every side strictly shorter than the other two \
                 combined, with no zero-length sides"
            }
            Op::LongestSide => "the largest of the three lengths",
            Op::IsRight => {
                "whether the sides satisfy the Pythagorean theorem in \
                 some order: the square of the largest length equals \
                 the sum of squares of the other two"
            }
            Op::NumDistinctSides => {
                "how many different lengths appear among the three \
                 sides (one for equilateral, two for isosceles, three \
                 for scalene)"
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

fn b_perimeter(a: u64, b: u64, c: u64) -> i64 {
    (a + b + c) as i64
}

fn b_is_valid(a: u64, b: u64, c: u64) -> bool {
    a + b > c && a + c > b && b + c > a && a > 0 && b > 0 && c > 0
}

fn b_longest_side(a: u64, b: u64, c: u64) -> i64 {
    a.max(b).max(c) as i64
}

fn b_is_right(a: u64, b: u64, c: u64) -> bool {
    let mut sides = [a as u128, b as u128, c as u128];
    sides.sort_unstable();
    let (x, y, z) = (sides[0], sides[1], sides[2]);
    x * x + y * y == z * z
}

fn b_num_distinct_sides(a: u64, b: u64, c: u64) -> i64 {
    let mut sides = [a, b, c];
    sides.sort_unstable();
    if sides[0] == sides[2] {
        1
    } else if sides[0] == sides[1] || sides[1] == sides[2] {
        2
    } else {
        3
    }
}

/// One op's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Flag(bool),
}

impl Out {
    fn lit(self) -> String {
        match self {
            Out::Num(n) => n.to_string(),
            Out::Flag(f) => f.to_string(),
        }
    }
}

/// Return-type string for the uniform signatures.
fn ret(op: Op) -> &'static str {
    match op {
        Op::IsValid | Op::IsRight => "bool",
        _ => "i64",
    }
}

fn out_of(op: Op, value: i64, flag: bool) -> Out {
    match ret(op) {
        "bool" => Out::Flag(flag),
        _ => Out::Num(value),
    }
}

fn op_eval(op: Op, a: u64, b: u64, c: u64) -> Out {
    match op {
        Op::Perimeter => out_of(op, b_perimeter(a, b, c), false),
        Op::IsValid => out_of(op, 0, b_is_valid(a, b, c)),
        Op::LongestSide => out_of(op, b_longest_side(a, b, c), false),
        Op::IsRight => out_of(op, 0, b_is_right(a, b, c)),
        Op::NumDistinctSides => out_of(op, b_num_distinct_sides(a, b, c), false),
    }
}
// ---- canonical input --------------------------------------------------------

/// Primitive triples whose scalings give right triangles with three
/// distinct sides — canonical inputs are CONSTRUCTED from these, not
/// blind-sampled, so the flag anchors hold by arithmetic.
const RIGHT_TRIPLES: [(u64, u64, u64); 5] = [
    (3, 4, 5),
    (5, 12, 13),
    (8, 15, 17),
    (7, 24, 25),
    (20, 21, 29),
];

fn rand_sides(rng: &mut Rng) -> (u64, u64, u64) {
    (1 + rng.below(30), 1 + rng.below(30), 1 + rng.below(30))
}

const CANONICAL_SEED: u64 = 0xA11E_51DE;

/// The canonical triangle: a scaled primitive right triple in a random
/// slot order. Right triangles are valid, have positive perimeter and
/// longest side, and (with distinct legs) exactly three distinct
/// lengths, so both flags are TRUE and every scalar separates —
/// `const-zero` fails everywhere and `longest-everything` is exact only
/// on its own op. No skips.
fn canonical(seed: u64) -> (u64, u64, u64) {
    let mut rng = Rng::new(seed ^ CANONICAL_SEED);
    for _ in 0..100_000 {
        let k = 1 + rng.below(60);
        let t = RIGHT_TRIPLES[rng.below(RIGHT_TRIPLES.len() as u64) as usize];
        let mut sides = [t.0 * k, t.1 * k, t.2 * k];
        // Rotate the slots so position does not leak the answer.
        let rot = rng.below(6) as usize;
        sides.rotate_left(rot % 3);
        if rot >= 3 {
            sides.swap(1, 2);
        }
        let (a, b, c) = (sides[0], sides[1], sides[2]);
        if anchors_hold(a, b, c) {
            return (a, b, c);
        }
    }
    unreachable!("canonical input sampling failed to satisfy anchors");
}

fn anchors_hold(a: u64, b: u64, c: u64) -> bool {
    b_is_valid(a, b, c)
        && b_is_right(a, b, c)
        && b_perimeter(a, b, c) != b_longest_side(a, b, c)
        && b_num_distinct_sides(a, b, c) != b_longest_side(a, b, c)
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = ((u64, u64, u64), Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_013A;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    let push = |cases: &mut Vec<ExampleCase>, sides: (u64, u64, u64)| {
        cases.push((
            sides,
            spec.ops
                .map(|op| (op, op_eval(op, sides.0, sides.1, sides.2)))
                .to_vec(),
        ));
    };
    // Canonical right triangle first.
    push(&mut cases, canonical(seed));
    // All-zero corner pins every zero convention — including the
    // vacuous Pythagorean equality.
    push(&mut cases, (0, 0, 0));
    // Equilateral: valid, not right, one distinct length.
    push(&mut cases, (6, 6, 6));
    // Degenerate flat: fails the strict inequality.
    push(&mut cases, (1, 2, 3));
    for _ in 0..3 {
        let sides = rand_sides(&mut rng);
        push(&mut cases, sides);
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for the triple: only the first element is
/// suffix-typed so inference types the rest.
fn render_sides(sides: (u64, u64, u64)) -> String {
    format!("({}u64, {}, {})", sides.0, sides.1, sides.2)
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let sig = format!("(a: u64, b: u64, c: u64) -> {}", ret(op));
    let body = match op {
        Op::Perimeter => "(a + b + c) as i64".to_string(),
        Op::IsValid => "a + b > c && a + c > b && b + c > a && a > 0 && b > 0 && c > 0".to_string(),
        Op::LongestSide => "a.max(b).max(c) as i64".to_string(),
        Op::IsRight => [
            "let mut sides = [a as u128, b as u128, c as u128];",
            "sides.sort_unstable();",
            "let (x, y, z) = (sides[0], sides[1], sides[2]);",
            "x * x + y * y == z * z",
        ]
        .join("\n    "),
        Op::NumDistinctSides => [
            "let mut sides = [a, b, c];",
            "sides.sort_unstable();",
            "if sides[0] == sides[2] {",
            "    1",
            "} else if sides[0] == sides[1] || sides[1] == sides[2] {",
            "    2",
            "} else {",
            "    3",
            "}",
        ]
        .join("\n    "),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(a: u64, b: u64, c: u64) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        ret(op)
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!(
        "pub fn {}(a: u64, b: u64, c: u64) -> {}",
        op.name(),
        ret(op)
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
    for (sides, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  sides {}  ->  {}\n",
            render_sides(sides),
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
         one triangle given as three side lengths; queries read classic \
         triangle properties off that triple. The sides arrive in no \
         particular order. Handle zero-length and degenerate inputs \
         gracefully.\n\
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
    for (i, (sides, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let (a, b, c) = {};\n",
            render_sides(*sides),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "a, b, c"),
                out.lit()
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
            let call = call_src(*op, "a, b, c");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_013A;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let a = (nx(&mut state) % 40) as u64;\n\
         \x20       let b = (nx(&mut state) % 40) as u64;\n\
         \x20       let c = (nx(&mut state) % 40) as u64;\n\
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
            let tail = match ret(*op) {
                "bool" => "false",
                _ => "0",
            };
            format!("{sig} {{\n    let _ = (a, b, c);\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every query with the longest side. The
/// canonical anchors keep every other answer away from that number and
/// both flags TRUE, so this is exact only on its own op.
fn longest_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            let tail = match ret(*op) {
                "bool" => "false".to_string(),
                _ => "a.max(b).max(c) as i64".to_string(),
            };
            format!("{sig} {{\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct TriangleFamily;

impl Generator for TriangleFamily {
    fn id(&self) -> &str {
        "triangle"
    }
    fn category(&self) -> &str {
        "triangle-geometry"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("triangle", seed);

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
            id: format!("triangle/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure integer geometry — no unsafe anywhere near it.
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
            ("longest-everything".to_string(), longest_everything(&spec)),
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
        let g = TriangleFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Perimeter sums all three sides regardless of order.
        assert_eq!(b_perimeter(3, 4, 5), 12);
        assert_eq!(b_perimeter(5, 3, 4), 12);
        // Validity: strict inequality plus positivity.
        assert!(b_is_valid(3, 4, 5));
        assert!(b_is_valid(7, 7, 7));
        assert!(!b_is_valid(1, 2, 3));
        assert!(!b_is_valid(10, 4, 5));
        assert!(!b_is_valid(0, 0, 0));
        // Longest side is position-blind.
        assert_eq!(b_longest_side(9, 4, 7), 9);
        assert_eq!(b_longest_side(4, 9, 7), 9);
        assert_eq!(b_longest_side(4, 7, 9), 9);
        // Rightness: Pythagoras over permutations — including orders
        // where the hypotenuse is NOT the last argument, pinning that
        // the triple is sorted before comparing.
        assert!(b_is_right(3, 4, 5));
        assert!(b_is_right(5, 12, 13));
        assert!(b_is_right(4, 5, 3));
        assert!(b_is_right(13, 5, 12));
        assert!(b_is_right(17, 8, 15));
        assert!(!b_is_right(2, 2, 3));
        assert!(!b_is_right(7, 7, 7));
        assert!(!b_is_right(6, 2, 3));
        // Distinct-length classification.
        assert_eq!(b_num_distinct_sides(7, 7, 7), 1);
        assert_eq!(b_num_distinct_sides(6, 6, 2), 2);
        assert_eq!(b_num_distinct_sides(2, 6, 6), 2);
        assert_eq!(b_num_distinct_sides(3, 4, 5), 3);
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
        // Both baselines must fail under EVERY pair with no skips: the
        // canonical triangle is valid AND right (both flags TRUE, so
        // any cheat answering false dies) and every scalar is nonzero
        // and different from the longest side.
        for seed in 0..200u64 {
            let (a, b, c) = canonical(seed);
            let longest = b_longest_side(a, b, c);
            for op in OP_ALL {
                match op_eval(op, a, b, c) {
                    Out::Num(n) => {
                        assert_ne!(n, 0, "const-zero survives {op:?} seed {seed}");
                        if !matches!(op, Op::LongestSide) {
                            assert_ne!(n, longest, "longest-cheat survives {op:?} seed {seed}");
                        }
                    }
                    Out::Flag(f) => {
                        assert!(f, "flag cheat survives {op:?} seed {seed}");
                    }
                }
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (sides, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, sides.0, sides.1, sides.2), out, "seed {seed}");
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
            assert!(!sk.contains(".max("));
            assert!(!sk.contains(".sort_unstable("));
            assert!(!sk.contains("* z"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains(".max("));
            assert!(!p.contains(".sort_unstable("));
            assert!(!p.contains("* z"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every call site passes exactly three arguments — two commas —
        // matching the parameter list of its signature.
        for op in OP_ALL {
            let call = call_src(op, "a, b, c");
            let sig = op_sig_src(op);
            let params = sig.split("->").next().unwrap();
            assert_eq!(
                call.matches(',').count(),
                params.matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{sig}`"
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = TriangleFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
