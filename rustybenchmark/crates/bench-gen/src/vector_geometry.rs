//! `vector-geometry` — integer plane queries over a seeded point pair.
//!
//! A task instance is two integer points `A = (ax, ay)` and `B = (bx, by)`.
//! The seed picks two of five query operations; the model must implement
//! both exactly as specified and match a hidden reference implementation
//! on thousands of random point pairs.
//!
//! Category: `plane-geometry`.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    /// Dot product of the two position vectors.
    Dot,
    /// 2-D scalar cross product (signed area factor).
    Cross,
    /// Whether A and B sit on one line through the origin.
    IsCollinear,
    /// Grid-walking distance between the points.
    Manhattan,
    /// Straight-line distance squared.
    EuclidSquared,
}

const OP_ALL: [Op; 5] = [
    Op::Dot,
    Op::Cross,
    Op::IsCollinear,
    Op::Manhattan,
    Op::EuclidSquared,
];

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::Dot => "dot",
            Op::Cross => "cross",
            Op::IsCollinear => "is_collinear",
            Op::Manhattan => "manhattan",
            Op::EuclidSquared => "euclid_squared",
        }
    }

    fn ret(self) -> &'static str {
        match self {
            Op::IsCollinear => "bool",
            _ => "i64",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::Dot => "the sum of the products of matching components of the two position vectors",
            Op::Cross => "the determinant-style product difference of the components (first component times the other point's second, minus second times the other point's first)",
            Op::IsCollinear => "whether both points lie on one common line through the origin",
            Op::Manhattan => "the grid-walking distance between the points: the two component gaps summed with signs dropped",
            Op::EuclidSquared => "the straight-line distance between the points, squared, so no root is ever taken",
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

fn b_dot(ax: i64, ay: i64, bx: i64, by: i64) -> i64 {
    ax * bx + ay * by
}

fn b_cross(ax: i64, ay: i64, bx: i64, by: i64) -> i64 {
    ax * by - ay * bx
}

fn b_is_collinear(ax: i64, ay: i64, bx: i64, by: i64) -> bool {
    ax * by - ay * bx == 0
}

fn b_manhattan(ax: i64, ay: i64, bx: i64, by: i64) -> i64 {
    (ax - bx).abs() + (ay - by).abs()
}

fn b_euclid_squared(ax: i64, ay: i64, bx: i64, by: i64) -> i64 {
    let dx = ax - bx;
    let dy = ay - by;
    dx * dx + dy * dy
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

fn op_eval(op: Op, ax: i64, ay: i64, bx: i64, by: i64) -> Out {
    match op {
        Op::Dot => Out::Num(b_dot(ax, ay, bx, by)),
        Op::Cross => Out::Num(b_cross(ax, ay, bx, by)),
        Op::IsCollinear => Out::Flag(b_is_collinear(ax, ay, bx, by)),
        Op::Manhattan => Out::Num(b_manhattan(ax, ay, bx, by)),
        Op::EuclidSquared => Out::Num(b_euclid_squared(ax, ay, bx, by)),
    }
}

const CANONICAL_SEED: u64 = 0x5ECC_71A1;

/// The canonical pair is deliberately NON-collinear with every scalar
/// answer nonzero and pairwise distinct — so the const-zero cheat misses
/// every scalar and the manhattan-everything cheat stays exact only on
/// its own query.
fn canonical(seed: u64) -> (i64, i64, i64, i64) {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let ax = rng.below(25) as i64 - 12;
        let ay = rng.below(25) as i64 - 12;
        let bx = rng.below(25) as i64 - 12;
        let by = rng.below(25) as i64 - 12;
        if anchors_hold(ax, ay, bx, by) {
            return (ax, ay, bx, by);
        }
    }
    unreachable!("vector-geometry canonical anchor search exhausted");
}

fn anchors_hold(ax: i64, ay: i64, bx: i64, by: i64) -> bool {
    if b_is_collinear(ax, ay, bx, by) {
        return false;
    }
    let d = b_dot(ax, ay, bx, by);
    let c = b_cross(ax, ay, bx, by);
    let m = b_manhattan(ax, ay, bx, by);
    let e = b_euclid_squared(ax, ay, bx, by);
    if d == 0 || m == 0 || e == 0 {
        return false;
    }
    // All four scalars pairwise distinct.
    let scalars = [d, c, m, e];
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

type ExampleCase = ((i64, i64, i64, i64), Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0124;

fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    // ex0: the canonical non-collinear pair.
    // ex1: the all-zero corner pins every zero convention AND a vacuous
    //      `true` from collinearity — flipping both cheats' `false`.
    // ex2: the unit axes corner (dot zero, cross one).
    let canon = canonical(seed);
    let mut examples: Vec<ExampleCase> = vec![
        (
            canon,
            OP_ALL
                .iter()
                .map(|&op| (op, op_eval(op, canon.0, canon.1, canon.2, canon.3)))
                .collect(),
        ),
        (
            (0, 0, 0, 0),
            OP_ALL
                .iter()
                .map(|&op| (op, op_eval(op, 0, 0, 0, 0)))
                .collect(),
        ),
        (
            (1, 0, 0, 1),
            OP_ALL
                .iter()
                .map(|&op| (op, op_eval(op, 1, 0, 0, 1)))
                .collect(),
        ),
    ];
    for _ in 0..3 {
        let p = (
            rng.below(25) as i64 - 12,
            rng.below(25) as i64 - 12,
            rng.below(25) as i64 - 12,
            rng.below(25) as i64 - 12,
        );
        let answers = OP_ALL
            .iter()
            .map(|&op| (op, op_eval(op, p.0, p.1, p.2, p.3)))
            .collect();
        examples.push((p, answers));
    }
    examples
}

fn render_quad(p: (i64, i64, i64, i64)) -> String {
    format!("({}i64, {}, {}, {})", p.0, p.1, p.2, p.3)
}

fn call_src(op: Op, var: &str) -> String {
    format!("{}({})", op.name(), var)
}

fn op_fn_src(op: Op) -> String {
    let body: String = match op {
        Op::Dot => ["ax * bx + ay * by"].join("\n    "),
        Op::Cross => ["ax * by - ay * bx"].join("\n    "),
        Op::IsCollinear => ["ax * by - ay * bx == 0"].join("\n    "),
        Op::Manhattan => ["(ax - bx).abs() + (ay - by).abs()"].join("\n    "),
        Op::EuclidSquared => [
            "let dx = ax - bx;",
            "let dy = ay - by;",
            "dx * dx + dy * dy",
        ]
        .join("\n    "),
    };
    format!(
        "pub fn {}(ax: i64, ay: i64, bx: i64, by: i64) -> {} {{\n    {}\n}}\n",
        op.name(),
        op.ret(),
        body
    )
}

fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(ax: i64, ay: i64, bx: i64, by: i64) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

fn op_sig_src(op: Op) -> String {
    format!(
        "pub fn {}(ax: i64, ay: i64, bx: i64, by: i64) -> {}",
        op.name(),
        op.ret()
    )
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
        s.push_str(&format!("  points {}  ->  {}\n", render_quad(p), results));
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
         given as four coordinates `ax`, `ay`, `bx`, `by` describing two \
         integer points in the plane; queries are geometric properties of \
         the pair.\n\
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
    for (i, (p, outs)) in worked_examples(seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let (ax, ay, bx, by) = {};\n",
            render_quad(*p),
        ));
        for (op, out) in outs {
            if !spec.ops.contains(op) {
                continue;
            }
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "ax, ay, bx, by"),
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
            let call = call_src(*op, "ax, ay, bx, by");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_012A;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let ax = (nx(&mut state) % 25) as i64 - 12;\n\
         \x20       let ay = (nx(&mut state) % 25) as i64 - 12;\n\
         \x20       let bx = (nx(&mut state) % 25) as i64 - 12;\n\
         \x20       let by = (nx(&mut state) % 25) as i64 - 12;\n\
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
                "bool" => format!("{sig} {{\n    let _ = (ax, ay, bx, by);\n    false\n}}\n"),
                _ => format!("{sig} {{\n    let _ = (ax, ay, bx, by);\n    0\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer the grid-walking distance no matter what
/// was asked. The canonical anchors make dot, cross, and squared distance
/// all disagree with it; `manhattan` itself is exact, and any pair
/// containing it is caught by its partner. The collinearity flag agrees
/// with this cheat on the (non-collinear) canonical but flips on the
/// all-zero worked example.
fn manhattan_everything(spec: &Spec) -> String {
    let m_body = "(ax - bx).abs() + (ay - by).abs()";
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => format!("{sig} {{\n    let _ = (ax, ay, bx, by);\n    false\n}}\n"),
                _ => format!("{sig} {{\n    {m_body}\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct VectorGeometryFamily;

impl Generator for VectorGeometryFamily {
    fn id(&self) -> &str {
        "vector-geometry"
    }
    fn category(&self) -> &str {
        "plane-geometry"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("vector-geometry", seed);

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
            id: format!("vector-geometry/{seed:016x}"),
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
        let g = VectorGeometryFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        assert_eq!(b_dot(3, 4, 5, 6), 39);
        assert_eq!(b_cross(3, 4, 5, 6), -2);
        // Parallel vectors are collinear with the origin.
        assert!(b_is_collinear(1, 2, 2, 4));
        assert!(!b_is_collinear(3, 4, 5, 6));
        // The zero vector is degenerate-collinear with anything.
        assert!(b_is_collinear(0, 0, 9, -3));
        // Grid distance sums absolute component gaps.
        assert_eq!(b_manhattan(1, 2, 4, 6), 7);
        // Squared straight-line distance needs no root: 3-4-5 triangle.
        assert_eq!(b_euclid_squared(1, 2, 4, 6), 25);
        // Coincident points.
        assert_eq!(b_manhattan(3, -8, 3, -8), 0);
        assert_eq!(b_euclid_squared(3, -8, 3, -8), 0);
        // Unit axes: dot zero, cross one.
        assert_eq!(b_dot(1, 0, 0, 1), 0);
        assert_eq!(b_cross(1, 0, 0, 1), 1);
        // Signs vanish inside squares and absolute values.
        assert_eq!(b_euclid_squared(-6, 2, -4, 9), 53);
        assert_eq!(b_manhattan(-3, -3, -1, -1), 4);
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
            let (ax, ay, bx, by) = canonical(seed);
            assert!(
                anchors_hold(ax, ay, bx, by),
                "seed {seed}: canonical anchors violated"
            );
            assert!(!b_is_collinear(ax, ay, bx, by));
            let d = b_dot(ax, ay, bx, by);
            let c = b_cross(ax, ay, bx, by);
            let m = b_manhattan(ax, ay, bx, by);
            let e = b_euclid_squared(ax, ay, bx, by);
            // const-zero: every scalar answer must be nonzero on canonical
            // (the flag agrees with `false` here — flipped by the all-zero
            // worked example).
            for v in [d, c, m, e] {
                assert_ne!(v, 0, "seed {seed}");
            }
            // manhattan-everything: exact only on manhattan.
            assert_ne!(d, m, "seed {seed}");
            assert_ne!(c, m, "seed {seed}");
            assert_ne!(e, m, "seed {seed}");
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            for (p, outs) in worked_examples(seed) {
                for (op, out) in outs {
                    assert_eq!(
                        out,
                        op_eval(op, p.0, p.1, p.2, p.3),
                        "seed {seed} op {}",
                        op.name()
                    );
                }
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        let g = VectorGeometryFamily;
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
        let g = VectorGeometryFamily;
        for seed in 0..50u64 {
            let sk = g.skeleton_code(seed);
            let task = g.generate(seed);
            for leak in ["* bx", "* by", ".abs(", "dx * dx"] {
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
                let call = call_src(op, "ax, ay, bx, by");
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
        let g = VectorGeometryFamily;
        let task = g.generate(7);
        assert!(task.prompt.contains(&task.canary));
    }
}
