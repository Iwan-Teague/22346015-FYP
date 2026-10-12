//! The `matrix` family (category `linear-algebra`) — index-algebra queries
//! over a fixed 3×3 matrix of `i64`.
//!
//! Where `interval-map` folds ranges, `value-tree` recurses through an owned
//! tree and `fsm` walks a transition graph, this family exercises **2-D
//! numeric indexing**: main diagonal, anti-diagonal, centre cross,
//! symmetry, and off-diagonal magnitudes. Every op is a pure function of the
//! index set it reads. The seed prunes which two of five query ops are
//! required: `trace`, `anti_trace`, `cross_sum`, `is_symmetric`,
//! `max_abs_off_diag`. C(5,2) = **10 distinct skills**, above the diversity
//! floor; op names are semantic.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops and
//! the emitted reference share the same bodies; the differential fuzzes 3000
//! random matrices against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the canonical
//! matrix) and `diagonal-only` (reads nothing but the main diagonal — exact
//! for `trace`, which is inherently diagonal, but wrong on the canonical
//! matrix for every other op, so every pair catches it through its partner).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    Trace,
    AntiTrace,
    CrossSum,
    Symmetric,
    MaxAbsOffDiag,
}

const OP_ALL: [Op; 5] = [
    Op::Trace,
    Op::AntiTrace,
    Op::CrossSum,
    Op::Symmetric,
    Op::MaxAbsOffDiag,
];

/// Matrix side length, fixed for the whole family.
const N: usize = 3;

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::Trace => "trace",
            Op::AntiTrace => "anti_trace",
            Op::CrossSum => "cross_sum",
            Op::Symmetric => "is_symmetric",
            Op::MaxAbsOffDiag => "max_abs_off_diag",
        }
    }

    fn ret(self) -> &'static str {
        match self {
            Op::Symmetric => "bool",
            Op::Trace | Op::AntiTrace | Op::CrossSum | Op::MaxAbsOffDiag => "i64",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::Trace => {
                "the sum of the main diagonal `m[0][0] + m[1][1] + \
                          m[2][2]`"
            }
            Op::AntiTrace => {
                "the sum of the anti-diagonal `m[0][2] + m[1][1] + \
                                 m[2][0]`"
            }
            Op::CrossSum => {
                "the sum of the centre cross: row 1 plus column 1, \
                            counting the shared centre once — `m[0][1] + \
                            m[1][0] + m[1][1] + m[1][2] + m[2][1]`"
            }
            Op::Symmetric => {
                "whether the matrix equals its transpose, i.e. `m[i][j] \
                               == m[j][i]` for every pair of indices"
            }
            Op::MaxAbsOffDiag => {
                "the largest absolute value among the **off-diagonal** \
                                      entries `m[i][j]` with `i != j` (a \
                                      3×3 matrix always has six of them)"
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

type Mat = [[i64; N]; N];

fn m_trace(m: &Mat) -> i64 {
    m[0][0] + m[1][1] + m[2][2]
}

fn m_anti_trace(m: &Mat) -> i64 {
    m[0][2] + m[1][1] + m[2][0]
}

fn m_cross_sum(m: &Mat) -> i64 {
    m[0][1] + m[1][0] + m[1][1] + m[1][2] + m[2][1]
}

fn m_is_symmetric(m: &Mat) -> bool {
    (0..N).all(|i| (0..N).all(|j| m[i][j] == m[j][i]))
}

fn m_max_abs_off_diag(m: &Mat) -> i64 {
    (0..N)
        .flat_map(|i| (0..N).map(move |j| (i, j)))
        .filter(|&(i, j)| i != j)
        .map(|(i, j)| m[i][j].abs())
        .max()
        .unwrap_or(0)
}

fn op_eval(op: Op, m: &Mat) -> Out {
    match op {
        Op::Trace => Out::Num(m_trace(m)),
        Op::AntiTrace => Out::Num(m_anti_trace(m)),
        Op::CrossSum => Out::Num(m_cross_sum(m)),
        Op::Symmetric => Out::Flag(m_is_symmetric(m)),
        Op::MaxAbsOffDiag => Out::Num(m_max_abs_off_diag(m)),
    }
}

/// A query result, typed because the ops return two different shapes.
#[derive(Clone, Debug, PartialEq)]
enum Out {
    Num(i64),
    Flag(bool),
}

impl Out {
    /// The result as emitted-source syntax for behavior-test assertions.
    fn lit(&self) -> String {
        match self {
            Out::Num(x) => x.to_string(),
            Out::Flag(b) => b.to_string(),
        }
    }
}

// ---- canonical matrix -------------------------------------------------------

/// The canonical matrix: nine seeded nonzero entries, retried until the
/// anchor facts hold.
///
/// Guaranteed for every seed: not symmetric, `trace != anti_trace`, all three
/// scalar sums nonzero, `max_abs_off_diag > 0`, and `cross_sum != m[1][1]`
/// (so the diagonal-only baseline's cross answer is wrong too).
fn canonical(seed: u64) -> Mat {
    let mut rng = Rng::new(seed ^ 0x4D_41_54_A1);
    for _ in 0..100_000 {
        let cand: Mat =
            std::array::from_fn(|_| std::array::from_fn(|_| (rng.below(18) as i64) - 9));
        if anchors_hold(&cand) {
            return cand;
        }
    }
    unreachable!("canonical matrix sampling failed to satisfy anchors");
}

fn anchors_hold(m: &Mat) -> bool {
    !m_is_symmetric(m)
        && m_trace(m) != m_anti_trace(m)
        && m_trace(m) != 0
        && m_anti_trace(m) != 0
        && m_cross_sum(m) != 0
        && m_cross_sum(m) != m[1][1]
        && m_max_abs_off_diag(m) > 0
}

/// Uniformly random matrix from the allowed envelope: entries in -9..=9.
fn rand_matrix(rng: &mut Rng) -> Mat {
    std::array::from_fn(|_| std::array::from_fn(|_| (rng.below(19) as i64) - 9))
}

// ---- worked examples --------------------------------------------------------

type ExampleCase = (Mat, Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_0047);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical matrix first.
    let can_m = canonical(seed);
    cases.push((can_m, spec.ops.map(|op| (op, op_eval(op, &can_m))).to_vec()));
    // Identity: perfectly symmetric, zero off-diagonal magnitude — the
    // degenerate corner the sums must still survive.
    let identity: Mat = [[1, 0, 0], [0, 1, 0], [0, 0, 1]];
    cases.push((
        identity,
        spec.ops.map(|op| (op, op_eval(op, &identity))).to_vec(),
    ));
    for _ in 0..3 {
        let m = rand_matrix(&mut rng);
        let outs = spec.ops.map(|op| (op, op_eval(op, &m))).to_vec();
        cases.push((m, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Render a native matrix as emitted-source syntax: `&[[1, -2, 3], ...]`.
fn render_matrix(m: &Mat) -> String {
    format!(
        "&[{}]",
        m.iter()
            .map(|row| format!(
                "[{}]",
                row.iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// One-line indented prose form for prompt readability.
fn prose_matrix(m: &Mat) -> String {
    let rows: Vec<String> = m
        .iter()
        .map(|row| {
            format!(
                "[{}]",
                row.iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        })
        .collect();
    format!("[{}]", rows.join(" / "))
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    let body = match op {
        Op::Trace => "m[0][0] + m[1][1] + m[2][2]".to_string(),
        Op::AntiTrace => "m[0][2] + m[1][1] + m[2][0]".to_string(),
        Op::CrossSum => "m[0][1] + m[1][0] + m[1][1] + m[1][2] + m[2][1]".to_string(),
        Op::Symmetric => "(0..3).all(|i| (0..3).all(|j| m[i][j] == m[j][i]))".to_string(),
        Op::MaxAbsOffDiag => "(0..3).flat_map(|i| (0..3).map(move |j| (i, j)))\n\
             \x20   .filter(|&(i, j)| i != j)\n\
             \x20   .map(|(i, j)| m[i][j].abs())\n\
             \x20   .max()\n\
             \x20   .unwrap_or(0)"
            .to_string(),
    };
    format!(
        "pub fn {name}(m: &[[i64; 3]; 3]) -> {ret} {{\n\
         \x20   {body}\n\
         }}\n",
        name = name,
        ret = ret,
        body = body,
    )
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {name}(m: &[[i64; 3]; 3]) -> {ret} {{\n\
         \x20   todo!()\n\
         }}\n",
        name = op.name(),
        ret = op.ret(),
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(m: &[[i64; 3]; 3]) -> {}", op.name(), op.ret())
}

fn reference_src(spec: &Spec) -> String {
    spec.ops.iter().map(|op| op_fn_src(*op)).collect()
}

/// The call expression for one op in an emitted assertion.
fn call_src(op: Op, mat: &str) -> String {
    format!("{}({})", op.name(), mat)
}

fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for (m, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  matrix {}  ->  {}\n", prose_matrix(&m), results));
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
        "Implement the two query functions in `src/lib.rs`. The matrix is \
         given as `m`, a `&[[i64; 3]; 3]`: `m[row][col]`, indices starting at \
         0.\n\
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
    for (i, (m, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   let m = {m};\n",
            m = render_matrix(m),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "m"),
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
    let reference = spec
        .ops
        .iter()
        .map(|op| op_fn_src(*op))
        .collect::<Vec<_>>()
        .join("")
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0057;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let m: [[i64; 3]; 3] = std::array::from_fn(|_| \
         std::array::from_fn(|_| (nx(&mut state) % 19) as i64 - 9));\n\
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
        asserts = spec
            .ops
            .iter()
            .map(|op| {
                format!(
                    "        assert_eq!({call}, ref_{call});\n",
                    call = call_src(*op, "&m"),
                )
            })
            .collect::<Vec<_>>()
            .join(""),
    )
}

/// Degenerate: everything zero/false.
fn const_zero(spec: &Spec) -> String {
    let fns = spec
        .ops
        .iter()
        .map(|op| {
            let body = match op {
                Op::Symmetric => "let _ = m;\n    false",
                Op::Trace | Op::AntiTrace | Op::CrossSum => "let _ = m;\n    0",
                Op::MaxAbsOffDiag => "let _ = m;\n    0",
            };
            format!(
                "pub fn {name}(m: &[[i64; 3]; 3]) -> {ret} {{\n\
                 \x20   {body}\n\
                 }}\n",
                name = op.name(),
                ret = op.ret(),
                body = body,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    fns
}

/// The structural cheat: read nothing but the main diagonal. Exact for
/// `trace` (inherently diagonal); wrong on the canonical matrix for every
/// other op.
fn diagonal_only(spec: &Spec) -> String {
    let fns = spec
        .ops
        .iter()
        .map(|op| {
            let body = match op {
                // Exact by construction.
                Op::Trace => "m[0][0] + m[1][1] + m[2][2]".to_string(),
                // Confuses anti-diagonal with main diagonal.
                Op::AntiTrace => "m[0][0] + m[1][1] + m[2][2]".to_string(),
                // Only the centre survives its index filter.
                Op::CrossSum => "m[1][1]".to_string(),
                // A purely diagonal matrix is trivially symmetric.
                Op::Symmetric => "true".to_string(),
                // No off-diagonal entry is ever read.
                Op::MaxAbsOffDiag => "0".to_string(),
            };
            format!(
                "pub fn {name}(m: &[[i64; 3]; 3]) -> {ret} {{\n\
                 \x20   {body}\n\
                 }}\n",
                name = op.name(),
                ret = op.ret(),
                body = body,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    fns
}

pub struct MatrixFamily;

impl Generator for MatrixFamily {
    fn id(&self) -> &str {
        "matrix"
    }
    fn category(&self) -> &str {
        "linear-algebra"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("matrix", seed);

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
            id: format!("matrix/{seed:016x}"),
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
            ("diagonal-only".to_string(), diagonal_only(&spec)),
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
        let g = MatrixFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Hand-checked asymmetric matrix.
        let m: Mat = [[1, 2, 3], [4, 5, 6], [7, 8, 9]];
        assert_eq!(m_trace(&m), 15);
        assert_eq!(m_anti_trace(&m), 15); // coincidentally equal here
        assert_eq!(m_cross_sum(&m), 25);
        assert!(!m_is_symmetric(&m));
        assert_eq!(m_max_abs_off_diag(&m), 8);
        // A symmetric non-identity matrix separates trace from anti-trace.
        let sym: Mat = [[1, 2, 3], [2, 4, 5], [3, 5, 6]];
        assert!(m_is_symmetric(&sym));
        assert_eq!(m_trace(&sym), 11);
        assert_eq!(m_anti_trace(&sym), 10);
        // Identity is the degenerate corner.
        let eye: Mat = [[1, 0, 0], [0, 1, 0], [0, 0, 1]];
        assert_eq!(m_trace(&eye), 3);
        assert_eq!(m_anti_trace(&eye), 1);
        assert_eq!(m_cross_sum(&eye), 1);
        assert!(m_is_symmetric(&eye));
        assert_eq!(m_max_abs_off_diag(&eye), 0);
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
        // Both baselines must fail under EVERY pair: const-zero fails all
        // five outright on the canonical matrix; diagonal-only is exact only
        // for trace, so every pair containing trace also carries a separator.
        for seed in 0..200u64 {
            let m = canonical(seed);
            // Anchor facts the sampler enforces.
            assert!(!m_is_symmetric(&m), "seed {seed}");
            assert_ne!(m_trace(&m), m_anti_trace(&m), "seed {seed}");
            assert_ne!(m_trace(&m), 0, "seed {seed}");
            assert_ne!(m_anti_trace(&m), 0, "seed {seed}");
            assert_ne!(m_cross_sum(&m), 0, "seed {seed}");
            assert_ne!(m_cross_sum(&m), m[1][1], "seed {seed}");
            assert!(m_max_abs_off_diag(&m) > 0, "seed {seed}");
            // const-zero separates on every scalar op; the bool op happens to
            // agree with const-zero's `false` on an asymmetric canonical, but
            // the identity worked example flips it.
            for op in OP_ALL {
                if op == Op::Symmetric {
                    continue;
                }
                let truth = op_eval(op, &m);
                let zero = match op {
                    Op::Trace | Op::AntiTrace | Op::CrossSum | Op::MaxAbsOffDiag => Out::Num(0),
                    _ => Out::Flag(false),
                };
                assert_ne!(truth, zero, "const-zero survives {op:?} seed {seed}");
            }
            // diagonal-only separates everywhere except trace.
            let diag = |op: Op| -> Out {
                match op {
                    Op::Trace | Op::AntiTrace => Out::Num(m_trace(&m)),
                    Op::CrossSum => Out::Num(m[1][1]),
                    Op::Symmetric => Out::Flag(true),
                    Op::MaxAbsOffDiag => Out::Num(0),
                }
            };
            for op in OP_ALL {
                if matches!(op, Op::Trace) {
                    continue; // inherently diagonal; partner op carries the pair
                }
                let truth = op_eval(op, &m);
                assert_ne!(truth, diag(op), "diagonal-only survives {op:?} seed {seed}");
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (m, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, &m), out, "seed {seed}");
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
                // Match the `pub fn` line: bare names substring-collide
                // (`is_symmetric` contains `symmetric`, etc.).
                let fn_line = format!("pub fn {}", op.name());
                if spec.ops.contains(&op) {
                    assert!(src.contains(&fn_line));
                } else {
                    assert!(!src.contains(&fn_line), "{:?} leaked", op);
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
            assert!(!sk.contains(".abs()"), "skeleton leaks the answer");
            assert!(!sk.contains("(0..3).all"), "skeleton leaks the answer");
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains(".abs()"));
            assert!(!p.contains("(0..3).all"));
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
            let call = call_src(op, "m");
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
        let g = MatrixFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
