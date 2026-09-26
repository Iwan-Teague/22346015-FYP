//! The `complex-plane` family (category `gaussian-plane`) — magnitude
//! measures over one seeded integer point.
//!
//! Where `vector-geometry` relates TWO points, this family reads classic
//! norms off a single point of the plane written as a `(re, im)` pair of
//! integer components: the squared modulus, the taxicab distance, the
//! chessboard distance, the signed component product, and whether the
//! point sits on the real axis. Every op is a pure function of the pair,
//! and the squared modulus never needs a square root. The seed prunes
//! which two of five query ops are required: `norm_squared`,
//! `manhattan_norm`, `chebyshev_norm`, `component_product`, `is_real`.
//! C(5,2) = **10 distinct skills**, above the diversity floor; op names
//! are semantic.
//!
//! The canonical point is sampled until both components are alive,
//! every scalar answer is nonzero, the four scalar answers are mutually
//! distinct, and none of them equals a raw component — so `const-zero`
//! fails everywhere and the component-echo cheats (answering every
//! query with `re` or `im`, flags answered false) are exact nowhere.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random points against the model.
//!
//! Trivial baselines: `const-zero` (fails outright on the canonical
//! point) and `manhattan-everything` (every query answered with the
//! taxicab norm).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    NormSquared,
    ManhattanNorm,
    ChebyshevNorm,
    ComponentProduct,
    IsReal,
}

const OP_ALL: [Op; 5] = [
    Op::NormSquared,
    Op::ManhattanNorm,
    Op::ChebyshevNorm,
    Op::ComponentProduct,
    Op::IsReal,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::NormSquared => "norm_squared",
            Op::ManhattanNorm => "manhattan_norm",
            Op::ChebyshevNorm => "chebyshev_norm",
            Op::ComponentProduct => "component_product",
            Op::IsReal => "is_real",
        }
    }

    /// The required return type.
    fn ret(self) -> &'static str {
        match self {
            Op::IsReal => "bool",
            _ => "i64",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::NormSquared => {
                "the squared modulus of the point — the sum of each \
                 component times itself, kept purely integral"
            }
            Op::ManhattanNorm => {
                "the taxicab distance from the origin — the two \
                 absolute components added together"
            }
            Op::ChebyshevNorm => {
                "the chessboard distance from the origin — the larger \
                 of the two absolute components"
            }
            Op::ComponentProduct => {
                "the product of the two components, keeping the sign \
                 the quadrant gives it"
            }
            Op::IsReal => {
                "whether the point lies on the horizontal axis — the \
                 imaginary component exactly zero"
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

fn b_norm_squared(re: i64, im: i64) -> i64 {
    re * re + im * im
}

fn b_manhattan_norm(re: i64, im: i64) -> i64 {
    re.abs() + im.abs()
}

fn b_chebyshev_norm(re: i64, im: i64) -> i64 {
    re.abs().max(im.abs())
}

fn b_component_product(re: i64, im: i64) -> i64 {
    re * im
}

fn b_is_real(re: i64, im: i64) -> bool {
    let _ = re;
    im == 0
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

fn op_eval(op: Op, re: i64, im: i64) -> Out {
    match op {
        Op::NormSquared => Out::Num(b_norm_squared(re, im)),
        Op::ManhattanNorm => Out::Num(b_manhattan_norm(re, im)),
        Op::ChebyshevNorm => Out::Num(b_chebyshev_norm(re, im)),
        Op::ComponentProduct => Out::Num(b_component_product(re, im)),
        Op::IsReal => Out::Flag(b_is_real(re, im)),
    }
}

// ---- canonical input --------------------------------------------------------

const CANONICAL_SEED: u64 = 0xC94A_7E11;

/// The canonical point: sampled until both components are alive, every
/// scalar answer is nonzero, the four scalar answers are mutually
/// distinct, and none of them equals a raw component — `const-zero`
/// fails everywhere and both component-echo cheats are exact nowhere.
fn canonical(seed: u64) -> (i64, i64) {
    let mut rng = Rng::new(seed ^ CANONICAL_SEED);
    for _ in 0..100_000 {
        let re = rng.below(41) as i64 - 20;
        let im = rng.below(41) as i64 - 20;
        if anchors_hold(re, im) {
            return (re, im);
        }
    }
    unreachable!("canonical input sampling failed to satisfy anchors");
}

fn anchors_hold(re: i64, im: i64) -> bool {
    if re == 0 || im == 0 {
        return false;
    }
    let answers = [
        b_norm_squared(re, im),
        b_manhattan_norm(re, im),
        b_chebyshev_norm(re, im),
        b_component_product(re, im),
    ];
    for (i, &a) in answers.iter().enumerate() {
        // Echo cheats answer with a raw component; the truth must
        // stay away from both.
        if a == re || a == im {
            return false;
        }
        for &other in &answers[i + 1..] {
            if a == other {
                return false;
            }
        }
    }
    true
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = ((i64, i64), Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_013C;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    let push = |cases: &mut Vec<ExampleCase>, re: i64, im: i64| {
        cases.push((
            (re, im),
            spec.ops.map(|op| (op, op_eval(op, re, im))).to_vec(),
        ));
    };
    // Canonical point first.
    let (cre, cim) = canonical(seed);
    push(&mut cases, cre, cim);
    // Origin: zero conventions everywhere; real-axis flag true.
    push(&mut cases, 0, 0);
    // Real-axis point: flag true, product collapses to zero.
    push(&mut cases, 7, 0);
    // Imaginary-axis point: flag false, still off the origin.
    push(&mut cases, 0, -3);
    for _ in 0..3 {
        let re = rng.below(41) as i64 - 20;
        let im = rng.below(41) as i64 - 20;
        push(&mut cases, re, im);
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a point: a tuple with only the first element
/// suffix-typed so inference types the rest.
fn render_pair(re: i64, im: i64) -> String {
    format!("({}i64, {})", re, im)
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let sig = format!("(re: i64, im: i64) -> {}", op.ret());
    let body = match op {
        Op::NormSquared => "re * re + im * im".to_string(),
        Op::ManhattanNorm => "re.abs() + im.abs()".to_string(),
        Op::ChebyshevNorm => "re.abs().max(im.abs())".to_string(),
        Op::ComponentProduct => "re * im".to_string(),
        Op::IsReal => "im == 0".to_string(),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(re: i64, im: i64) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(re: i64, im: i64) -> {}", op.name(), op.ret())
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
    for ((re, im), outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  point {}  ->  {}\n",
            render_pair(re, im),
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
         one point of the complex plane written as a pair of integer \
         components: a real part and an imaginary part. Queries are pure \
         arithmetic facts about that point — its distances from the \
         origin and how its components combine.\n\
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
    for (i, ((re, im), outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let (re, im) = {};\n",
            render_pair(*re, *im),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "re, im"),
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
            let call = call_src(*op, "re, im");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_013C;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let re = (nx(&mut state) % 41) as i64 - 20;\n\
         \x20       let im = (nx(&mut state) % 41) as i64 - 20;\n\
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
            format!("{sig} {{\n    let _ = (re, im);\n    {answer}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every query with the taxicab norm;
/// flags answered false. The canonical anchors keep the three other
/// scalar answers away from it, so this is exact only on its own op.
fn manhattan_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            let answer = match op.ret() {
                "bool" => "false",
                _ => "re.abs() + im.abs()",
            };
            format!("{sig} {{\n    {answer}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct ComplexPlaneFamily;

impl Generator for ComplexPlaneFamily {
    fn id(&self) -> &str {
        "complex-plane"
    }
    fn category(&self) -> &str {
        "gaussian-plane"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("complex-plane", seed);

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
            id: format!("complex-plane/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure integer plane bookkeeping — no unsafe anywhere near it.
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
            (
                "manhattan-everything".to_string(),
                manhattan_everything(&spec),
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
        let g = ComplexPlaneFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Squared modulus stays integral.
        assert_eq!(b_norm_squared(3, 4), 25);
        assert_eq!(b_norm_squared(-3, -4), 25);
        assert_eq!(b_norm_squared(0, -4), 16);
        assert_eq!(b_norm_squared(0, 0), 0);
        // Taxicab distance ignores signs.
        assert_eq!(b_manhattan_norm(3, 4), 7);
        assert_eq!(b_manhattan_norm(-3, 4), 7);
        assert_eq!(b_manhattan_norm(5, 0), 5);
        // Chessboard distance takes the larger absolute component.
        assert_eq!(b_chebyshev_norm(3, 4), 4);
        assert_eq!(b_chebyshev_norm(-4, -3), 4);
        assert_eq!(b_chebyshev_norm(5, 5), 5);
        // Component product carries the quadrant's sign.
        assert_eq!(b_component_product(3, 4), 12);
        assert_eq!(b_component_product(-3, 4), -12);
        assert_eq!(b_component_product(6, 0), 0);
        // Real axis means exactly-zero imaginary part.
        assert!(b_is_real(7, 0));
        assert!(b_is_real(0, 0));
        assert!(!b_is_real(0, 1));
        assert!(!b_is_real(3, -4));
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
        // point both components are alive, every scalar answer is
        // nonzero, the four scalars are mutually distinct, and none of
        // them equals a raw component — so `const-zero` separates
        // everywhere and the echo cheats are exact nowhere.
        // `manhattan-everything` is exact only on its own op (skip
        // documented); its `false` flag agrees on the canonical point
        // but is flipped by the origin and real-axis worked examples.
        for seed in 0..200u64 {
            let (re, im) = canonical(seed);
            assert!(re != 0 && im != 0, "axis point at seed {seed}");
            assert!(!b_is_real(re, im));
            let man = b_manhattan_norm(re, im);
            // The four scalar answers must stay mutually distinct —
            // the property the doc header promises and `anchors_hold`
            // samples for, asserted here so an anchors regression
            // cannot silently survive.
            let scalars = [
                b_norm_squared(re, im),
                man,
                b_chebyshev_norm(re, im),
                b_component_product(re, im),
            ];
            for (i, &a) in scalars.iter().enumerate() {
                for &b in &scalars[i + 1..] {
                    assert_ne!(a, b, "scalar collision at seed {seed}");
                }
            }
            for op in OP_ALL {
                match op_eval(op, re, im) {
                    Out::Flag(_) => {}
                    Out::Num(n) => {
                        assert_ne!(n, 0, "const-zero survives {op:?} seed {seed}");
                        assert_ne!(n, re, "re-echo survives {op:?} seed {seed}");
                        assert_ne!(n, im, "im-echo survives {op:?} seed {seed}");
                        if !matches!(op, Op::ManhattanNorm) {
                            assert_ne!(n, man, "manhattan-cheat survives {op:?} seed {seed}");
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
            for ((re, im), outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    let truth = op_eval(op, re, im);
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
            assert!(!sk.contains(".abs("));
            assert!(!sk.contains("* re"));
            assert!(!sk.contains("* im"));
            assert!(!sk.contains(".max("));
            assert!(!sk.contains("pow("));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains(".abs("));
            assert!(!p.contains("* re"));
            assert!(!p.contains("* im"));
            assert!(!p.contains(".max("));
            assert!(!p.contains("pow("));
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
            let call = call_src(op, "re, im");
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
        let g = ComplexPlaneFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
