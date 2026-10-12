//! The `rectangle` family (category `rectangle-geometry`) — measurements of
//! an axis-aligned rectangle over seeded unsigned side pairs.
//!
//! Where `triangle-geometry` relates three free sides and `gaussian-plane`
//! reads norms off one signed point, this family fixes the classic
//! rectangle facts: covered area, boundary length, squareness, the squared
//! diagonal, and the longer dimension. Every op is a pure function of the
//! `(width, height)` pair, and the squared diagonal stays purely integral
//! (no square root). The seed prunes which two of five query ops are
//! required: `area`, `perimeter`, `is_square`, `diagonal_squared`,
//! `longer_side`. C(5,2) = **10 distinct skills**, above the diversity
//! floor; op names are semantic.
//!
//! Generator-emitted tasks always carry small positive sides; the canonical
//! pair is sampled until the sides differ and every scalar answer is
//! nonzero, mutually distinct, and different from both raw sides — so
//! `const-zero` fails everywhere and a side-echo cheat is exact nowhere.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random rectangles against the model.
//!
//! Trivial baselines: `const-zero` (fails outright on the canonical
//! rectangle) and `longer-everything` (every query answered with the
//! longer side).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    Area,
    Perimeter,
    IsSquare,
    DiagonalSquared,
    LongerSide,
}

const OP_ALL: [Op; 5] = [
    Op::Area,
    Op::Perimeter,
    Op::IsSquare,
    Op::DiagonalSquared,
    Op::LongerSide,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::Area => "area",
            Op::Perimeter => "perimeter",
            Op::IsSquare => "is_square",
            Op::DiagonalSquared => "diagonal_squared",
            Op::LongerSide => "longer_side",
        }
    }

    /// The required return type.
    fn ret(self) -> &'static str {
        match self {
            Op::IsSquare => "bool",
            _ => "i64",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::Area => {
                "the product of the two sides — how many unit squares the \
                 rectangle covers"
            }
            Op::Perimeter => "the full boundary length — twice the sum of the two sides",
            Op::IsSquare => "whether the two sides are equal",
            Op::DiagonalSquared => {
                "the squared corner-to-corner distance — each side times \
                 itself and the two results added together"
            }
            Op::LongerSide => {
                "whichever side is greater; on equal sides either value is \
                 correct"
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

fn b_area(width: u64, height: u64) -> i64 {
    (width * height) as i64
}

fn b_perimeter(width: u64, height: u64) -> i64 {
    ((width + height) * 2) as i64
}

fn b_is_square(width: u64, height: u64) -> bool {
    width == height
}

fn b_diagonal_squared(width: u64, height: u64) -> i64 {
    (width * width + height * height) as i64
}

fn b_longer_side(width: u64, height: u64) -> i64 {
    (if height > width { height } else { width }) as i64
}

/// One op's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Flag(bool),
}

impl Out {
    /// The literal this answer renders as at an emitted call site.
    fn lit(&self) -> String {
        match self {
            Out::Num(n) => n.to_string(),
            Out::Flag(b) => b.to_string(),
        }
    }
}

fn op_eval(op: Op, width: u64, height: u64) -> Out {
    match op {
        Op::Area => Out::Num(b_area(width, height)),
        Op::Perimeter => Out::Num(b_perimeter(width, height)),
        Op::IsSquare => Out::Flag(b_is_square(width, height)),
        Op::DiagonalSquared => Out::Num(b_diagonal_squared(width, height)),
        Op::LongerSide => Out::Num(b_longer_side(width, height)),
    }
}

// ---- canonical input --------------------------------------------------------

const CANONICAL_SEED: u64 = 0x2E0C_7A11;
/// The canonical rectangle: sampled until both sides are alive and
/// different, every scalar answer is nonzero, the four scalar answers are
/// mutually distinct, and none of them equals a raw side — `const-zero`
/// fails everywhere and a side-echo cheat is exact nowhere.
fn canonical(seed: u64) -> (u64, u64) {
    let mut rng = Rng::new(seed ^ CANONICAL_SEED);
    for _ in 0..100_000 {
        let width = 1 + rng.below(50);
        let height = 1 + rng.below(50);
        if anchors_hold(width, height) {
            return (width, height);
        }
    }
    unreachable!("canonical input sampling failed to satisfy anchors");
}

fn anchors_hold(width: u64, height: u64) -> bool {
    if width == 0 || height == 0 || width == height {
        return false;
    }
    // The longer side IS one of the raw sides by definition, so the
    // side-echo defense applies only to the other three scalars.
    let echo_free = [
        b_area(width, height),
        b_perimeter(width, height),
        b_diagonal_squared(width, height),
    ];
    for &a in &echo_free {
        if a == width as i64 || a == height as i64 {
            return false;
        }
    }
    let answers = [
        b_area(width, height),
        b_perimeter(width, height),
        b_diagonal_squared(width, height),
        b_longer_side(width, height),
    ];
    for (i, &a) in answers.iter().enumerate() {
        for &other in &answers[i + 1..] {
            if a == other {
                return false;
            }
        }
    }
    true
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = ((u64, u64), Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_014A;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    let push = |cases: &mut Vec<ExampleCase>, width: u64, height: u64| {
        cases.push((
            (width, height),
            spec.ops.map(|op| (op, op_eval(op, width, height))).to_vec(),
        ));
    };
    // Canonical rectangle first.
    let (cw, ch) = canonical(seed);
    push(&mut cases, cw, ch);
    // Square corner: flag true — flips every cheating `false`.
    push(&mut cases, 1, 1);
    // Degenerate strip: zero-side conventions with the other side alive.
    push(&mut cases, 0, 7);
    for _ in 0..3 {
        let width = 1 + rng.below(50);
        let height = 1 + rng.below(50);
        push(&mut cases, width, height);
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a rectangle: a tuple with only the first element
/// suffix-typed so inference types the rest.
fn render_pair(width: u64, height: u64) -> String {
    format!("({}u64, {})", width, height)
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let sig = format!("(width: u64, height: u64) -> {}", op.ret());
    let body = match op {
        Op::Area => "(width * height) as i64".to_string(),
        Op::Perimeter => "((width + height) * 2) as i64".to_string(),
        Op::IsSquare => "width == height".to_string(),
        Op::DiagonalSquared => "(width * width + height * height) as i64".to_string(),
        Op::LongerSide => "(if height > width { height } else { width }) as i64".to_string(),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(width: u64, height: u64) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!(
        "pub fn {}(width: u64, height: u64) -> {}",
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
    for ((width, height), outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  rect {}  ->  {}\n",
            render_pair(width, height),
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
         one axis-aligned rectangle written as a pair of whole-unit side \
         lengths: a width and a height. Queries are pure geometric facts \
         about that rectangle — how much ground it covers, how far it is \
         around, and how its two dimensions relate.\n\
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
    for (i, ((width, height), outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let (width, height) = {};\n",
            render_pair(*width, *height),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "width, height"),
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
            let call = call_src(*op, "width, height");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_014A;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let width = (nx(&mut state) % 50) + 1;\n\
         \x20       let height = (nx(&mut state) % 50) + 1;\n\
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
            let answer = match op.ret() {
                "bool" => "false",
                _ => "0",
            };
            format!("{sig} {{\n    let _ = (width, height);\n    {answer}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every query with the longer side; flags
/// answered false. The canonical anchors keep the three other scalar
/// answers away from it, so this is exact only on its own op.
fn longer_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            let answer = match op.ret() {
                "bool" => "false",
                _ => "(if height > width { height } else { width }) as i64",
            };
            format!("{sig} {{\n    {answer}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct RectangleFamily;

impl Generator for RectangleFamily {
    fn id(&self) -> &str {
        "rectangle"
    }
    fn category(&self) -> &str {
        "rectangle-geometry"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("rectangle", seed);

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
            id: format!("rectangle/{seed:016x}"),
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
            ("longer-everything".to_string(), longer_everything(&spec)),
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
        let g = RectangleFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Area multiplies the sides and ignores their order.
        assert_eq!(b_area(3, 4), 12);
        assert_eq!(b_area(4, 3), 12);
        assert_eq!(b_area(1, 1), 1);
        assert_eq!(b_area(0, 9), 0);
        assert_eq!(b_area(9, 0), 0);
        // Perimeter doubles the side sum.
        assert_eq!(b_perimeter(3, 4), 14);
        assert_eq!(b_perimeter(4, 3), 14);
        assert_eq!(b_perimeter(1, 1), 4);
        assert_eq!(b_perimeter(0, 9), 18);
        // Squareness means equal sides.
        assert!(b_is_square(5, 5));
        assert!(b_is_square(1, 1));
        assert!(!b_is_square(3, 4));
        assert!(!b_is_square(6, 7));
        assert!(!b_is_square(0, 9));
        // Squared diagonal stays integral.
        assert_eq!(b_diagonal_squared(3, 4), 25);
        assert_eq!(b_diagonal_squared(4, 3), 25);
        assert_eq!(b_diagonal_squared(1, 1), 2);
        assert_eq!(b_diagonal_squared(0, 9), 81);
        // Longer side picks the greater dimension.
        assert_eq!(b_longer_side(3, 4), 4);
        assert_eq!(b_longer_side(4, 3), 4);
        assert_eq!(b_longer_side(6, 6), 6);
        assert_eq!(b_longer_side(0, 9), 9);
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
        // Both baselines must fail under EVERY pair. On the canonical
        // rectangle the sides differ, every scalar answer is nonzero,
        // the four scalars are mutually distinct, and none of them
        // equals a raw side — so `const-zero` separates everywhere and
        // a side-echo cheat is exact nowhere. `longer-everything` is
        // exact only on its own op (skip documented); its `false` flag
        // agrees on the canonical rectangle but is flipped by the
        // square worked example.
        for seed in 0..200u64 {
            let (width, height) = canonical(seed);
            assert!(width > 0 && height > 0, "dead side at seed {seed}");
            assert_ne!(width, height, "square at seed {seed}");
            assert!(!b_is_square(width, height));
            let longer = b_longer_side(width, height);
            // The four scalar answers must stay mutually distinct —
            // the property the doc header promises and `anchors_hold`
            // samples for, asserted here so an anchors regression
            // cannot silently survive.
            let scalars = [
                b_area(width, height),
                b_perimeter(width, height),
                b_diagonal_squared(width, height),
                longer,
            ];
            for (i, &a) in scalars.iter().enumerate() {
                for &b in &scalars[i + 1..] {
                    assert_ne!(a, b, "scalar collision at seed {seed}");
                }
            }
            for op in OP_ALL {
                match op_eval(op, width, height) {
                    Out::Flag(_) => {}
                    Out::Num(n) => {
                        assert_ne!(n, 0, "const-zero survives {op:?} seed {seed}");
                        // Side-echo checks skip the longer side — it IS
                        // a raw side by definition.
                        if !matches!(op, Op::LongerSide) {
                            assert_ne!(n, width as i64, "width-echo survives {op:?} seed {seed}");
                            assert_ne!(n, height as i64, "height-echo survives {op:?} seed {seed}");
                            assert_ne!(n, longer, "longer-cheat survives {op:?} seed {seed}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for ((width, height), outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    let truth = op_eval(op, width, height);
                    assert_eq!(truth.lit(), out.lit(), "seed {seed}");
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
                // Match the `pub fn (` line so no bare-name substring leaks.
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
            // Solution-shaped leak tokens must stay out of the skeleton.
            assert!(!sk.contains("* height"));
            assert!(!sk.contains("+ height"));
            assert!(!sk.contains("== height"));
            assert!(!sk.contains("width * width"));
            assert!(!sk.contains("else {"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("* height"));
            assert!(!p.contains("+ height"));
            assert!(!p.contains("== height"));
            assert!(!p.contains("width * width"));
            assert!(!p.contains("else {"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every call site passes exactly two arguments — one comma —
        // matching the parameter list of its signature.
        for op in OP_ALL {
            let call = call_src(op, "width, height");
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
        let g = RectangleFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
