//! The `triangular` family (category `figurate-numbers`) — bowling-pin
//! counts and their inverses over one non-negative integer.
//!
//! Where `primes` factors multiplicatively and `fib` walks a recurrence,
//! this family exercises **additive figurate structure**: the nth
//! triangular number stacks rows of pins, the predicate spots exact
//! racks, and three inverse queries locate a value between racks. The
//! domain is one `u64` from zero upward (worked examples stay far below
//! a million, where `n * (n + 1)` still sits comfortably inside the
//! type). The seed prunes which two of five query ops are required:
//! `triangular`, `is_triangular`, `triangular_root`, `largest_leq`,
//! `steps_to_next`. C(5,2) = **10 distinct skills**, above the diversity
//! floor; op names are semantic.
//!
//! The canonical input is sampled until its anchor facts hold: it is NOT
//! an exact rack — the root query answers with the minus-one sentinel,
//! the gap up to the next rack is positive, and the last full rack holds
//! at least four pins — so constant-zero cheats die on every scalar
//! outright, while the not-a-rack flag FALSE agrees with cheating flags
//! and is flipped by pinned rack examples.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random inputs against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the
//! canonical input) and `gauss-everything` (every query answered with
//! the schoolroom sum of the raw input — exact only for the stack
//! itself, and its always-a-rack flag loses to the canonical FALSE).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    Triangular,
    IsTriangular,
    TriangularRoot,
    LargestLeq,
    StepsToNext,
}

const OP_ALL: [Op; 5] = [
    Op::Triangular,
    Op::IsTriangular,
    Op::TriangularRoot,
    Op::LargestLeq,
    Op::StepsToNext,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::Triangular => "triangular",
            Op::IsTriangular => "is_triangular",
            Op::TriangularRoot => "triangular_root",
            Op::LargestLeq => "largest_leq",
            Op::StepsToNext => "steps_to_next",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::Triangular => "how many pins sit in a rack with that many rows",
            Op::IsTriangular => {
                "whether the count forms an exact rack — some row count \
                 fills it precisely"
            }
            Op::TriangularRoot => {
                "the row count that fills a rack of exactly this size, or \
                 minus one when the size falls between racks"
            }
            Op::LargestLeq => {
                "the largest row count whose full rack does not exceed \
                 the count"
            }
            Op::StepsToNext => {
                "how many more pins are needed to complete the next \
                 larger rack; an exact rack needs none"
            }
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::IsTriangular => "bool",
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

/// Pins in a rack of n rows.
fn b_triangular(n: u64) -> u64 {
    n * (n + 1) / 2
}

/// Whether x completes some rack exactly.
fn b_is_triangular(x: u64) -> bool {
    let probe = 8 * x + 1;
    let r = (probe as f64).sqrt() as u64;
    r * r == probe || (r + 1) * (r + 1) == probe
}

/// The row that fills a rack of exactly x, else minus one.
fn b_triangular_root(x: u64) -> i64 {
    let mut k: u64 = 0;
    while b_triangular(k) < x {
        k += 1;
    }
    if b_triangular(k) == x {
        k as i64
    } else {
        -1
    }
}

/// The largest row whose rack does not exceed x.
fn b_largest_leq(x: u64) -> i64 {
    let mut k: u64 = 0;
    while b_triangular(k + 1) <= x {
        k += 1;
    }
    k as i64
}

/// Pins still needed for the next larger rack; an exact rack needs none.
fn b_steps_to_next(x: u64) -> i64 {
    if b_is_triangular(x) {
        return 0;
    }
    let below = b_largest_leq(x) as u64;
    (b_triangular(below + 1) - x) as i64
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
            Out::Flag(v) => v.to_string(),
        }
    }
}

fn op_eval(op: Op, x: u64) -> Out {
    match op {
        Op::Triangular => Out::Num(b_triangular(x) as i64),
        Op::IsTriangular => Out::Flag(b_is_triangular(x)),
        Op::TriangularRoot => Out::Num(b_triangular_root(x)),
        Op::LargestLeq => Out::Num(b_largest_leq(x)),
        Op::StepsToNext => Out::Num(b_steps_to_next(x)),
    }
}

// ---- canonical input ------------------------------------------------------

const CANONICAL_SEED: u64 = 0x7EA1_4E11;

/// The canonical input: sampled from the full table and retried until
/// the anchor facts hold.
///
/// Guaranteed for every seed: NOT an exact rack — the root answers with
/// the minus-one sentinel (never zero), the gap up to the next rack is
/// positive, and the last full rack holds at least four pins — so
/// constant-zero cheats die on every scalar outright. The not-a-rack
/// flag FALSE agrees with cheating flags; pinned rack examples flip
/// them.
fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let x = rng.below(10_000);
        if anchors_hold(x) {
            return x;
        }
    }
    unreachable!("canonical input sampling failed to satisfy anchors");
}

fn anchors_hold(x: u64) -> bool {
    !b_is_triangular(x) && x >= 10 && b_largest_leq(x) >= 3 && b_steps_to_next(x) >= 1
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (u64, Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_016A;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical between-racks input first.
    let can = canonical(seed);
    cases.push((can, spec.ops.map(|op| (op, op_eval(op, can))).to_vec()));
    // The empty rack: every scalar answers zero, the flag TRUE —
    // constant-false cheats die here.
    cases.push((0, spec.ops.map(|op| (op, op_eval(op, 0))).to_vec()));
    // The classic ten-pin rack: exact, flag TRUE.
    cases.push((10, spec.ops.map(|op| (op, op_eval(op, 10))).to_vec()));
    // One pin short of the rack.
    cases.push((9, spec.ops.map(|op| (op, op_eval(op, 9))).to_vec()));
    // A mid-size rack.
    cases.push((55, spec.ops.map(|op| (op, op_eval(op, 55))).to_vec()));
    for _ in 0..3 {
        let x = rng.below(10_000);
        let outs = spec.ops.map(|op| (op, op_eval(op, x))).to_vec();
        cases.push((x, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site.
fn render_u64(x: u64) -> String {
    format!("{x}u64")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    let body = match op {
        Op::Triangular => ["((x * (x + 1)) / 2) as i64"].join("\n    "),
        Op::IsTriangular => [
            "let probe = 8 * x + 1;",
            "let r = (probe as f64).sqrt() as u64;",
            "r * r == probe || (r + 1) * (r + 1) == probe",
        ]
        .join("\n    "),
        Op::TriangularRoot => [
            "let mut k: u64 = 0;",
            "while k * (k + 1) / 2 < x {",
            "    k += 1;",
            "}",
            "if k * (k + 1) / 2 == x {",
            "    k as i64",
            "} else {",
            "    -1",
            "}",
        ]
        .join("\n    "),
        Op::LargestLeq => [
            "let mut k: u64 = 0;",
            "while (k + 1) * (k + 2) / 2 <= x {",
            "    k += 1;",
            "}",
            "k as i64",
        ]
        .join("\n    "),
        Op::StepsToNext => [
            "let probe = 8 * x + 1;",
            "let r = (probe as f64).sqrt() as u64;",
            "if r * r == probe || (r + 1) * (r + 1) == probe {",
            "    return 0;",
            "}",
            "let mut k: u64 = 0;",
            "while (k + 1) * (k + 2) / 2 <= x {",
            "    k += 1;",
            "}",
            "(((k + 1) * (k + 2)) / 2 - x) as i64",
        ]
        .join("\n    "),
    };
    format!("pub fn {name}(x: u64) -> {ret} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(x: u64) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(x: u64) -> {}", op.name(), op.ret())
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
    for (x, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  count {}  ->  {}\n", render_u64(x), results));
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
         one pin count `x`: a `u64`. A rack with n rows holds one pin in \
         the first row, two in the second, and so on; counts that some \
         row count fills exactly are complete racks, and every other \
         count falls between two racks. The root query answers minus one \
         for such between-rack counts.\n\
         \n\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         - Work with exact integer arithmetic only; no floating point \
         beyond an internal square-root probe if you want it.\n\
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
    for (i, (x, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let x = {};\n",
            render_u64(*x),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "x"),
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_016A;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let x = nx(&mut state) % 10000;\n\
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
            format!("{sig} {{\n    let _ = x;\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every query with the schoolroom sum of
/// the raw input. On the canonical between-racks input this misses
/// everywhere but the stack itself — the root sentinel, the last rack,
/// the gap, and the always-a-rack flag all disagree.
fn gauss_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => format!("{sig} {{\n    true\n}}\n"),
                _ => format!("{sig} {{\n    ((x * (x + 1)) / 2) as i64\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct TriangularFamily;

impl Generator for TriangularFamily {
    fn id(&self) -> &str {
        "triangular"
    }
    fn category(&self) -> &str {
        "figurate-numbers"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("triangular", seed);

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
            id: format!("triangular/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure integer queries — no unsafe anywhere.
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
            ("gauss-everything".to_string(), gauss_everything(&spec)),
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
        let g = TriangularFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Stack rungs: empty, first rows, ten-pin rack, Gauss sum.
        assert_eq!(b_triangular(0), 0);
        assert_eq!(b_triangular(1), 1);
        assert_eq!(b_triangular(4), 10);
        assert_eq!(b_triangular(100), 5050);
        // Exact racks spotted, near-misses rejected.
        for rack in [0u64, 1, 3, 6, 10, 55, 5050] {
            assert!(b_is_triangular(rack));
        }
        for miss in [2u64, 4, 5, 7, 8, 9, 11, 54, 56] {
            assert!(!b_is_triangular(miss));
        }
        // Root: exact rows invert; between-racks answer minus one.
        assert_eq!(b_triangular_root(10), 4);
        assert_eq!(b_triangular_root(5050), 100);
        assert_eq!(b_triangular_root(9), -1);
        assert_eq!(b_triangular_root(56), -1);
        // Last full rack: below-one is the empty rack.
        assert_eq!(b_largest_leq(0), 0);
        assert_eq!(b_largest_leq(2), 1);
        assert_eq!(b_largest_leq(9), 3);
        assert_eq!(b_largest_leq(54), 9);
        assert_eq!(b_largest_leq(56), 10);
        // Gap up: exact racks need none.
        assert_eq!(b_steps_to_next(10), 0);
        assert_eq!(b_steps_to_next(9), 1);
        assert_eq!(b_steps_to_next(56), 10);
        assert_eq!(b_steps_to_next(4), 2);
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
        // The canonical input is NOT an exact rack: root answers minus
        // one (const-zero dies there outright), the gap up is positive,
        // and the stack of the raw input dwarfs both inverse answers —
        // gauss-everything survives only on the stack itself. The
        // not-a-rack flag FALSE agrees with cheating flags; pinned rack
        // examples flip them.
        for seed in 0..200u64 {
            let x = canonical(seed);
            let t = b_triangular(x) as i64;
            let root = b_triangular_root(x);
            let last = b_largest_leq(x);
            let gap = b_steps_to_next(x);
            // Anchor facts the sampler enforces.
            assert!(!b_is_triangular(x), "seed {seed}: must fall between racks");
            assert!(x >= 10, "seed {seed}");
            assert_eq!(root, -1, "seed {seed}: between-racks sentinel");
            assert!(last >= 3, "seed {seed}: last rack must clear three");
            assert!(gap >= 1, "seed {seed}: next rack must need pins");
            // const-zero survives nowhere on the scalars.
            assert_ne!(t, 0, "const-zero survives at seed {seed}");
            assert_ne!(last, 0, "seed {seed}");
            assert_ne!(gap, 0, "seed {seed}");
            // gauss-everything survives nowhere but the stack itself:
            // the raw-input sum dwarfs the small inverse answers here
            // (rows stay under ~150 while the stack clears fifty-five).
            assert!(t > last + gap, "gauss survives at seed {seed}");
            assert_ne!(
                root,
                b_triangular(x) as i64,
                "gauss survives root at seed {seed}"
            );
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (x, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, x), out, "seed {seed}");
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
            assert!(!sk.contains("* ("));
            assert!(!sk.contains("8 *"));
            assert!(!sk.contains("/ 2"));
            assert!(!sk.contains("while"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("* ("));
            assert!(!p.contains("8 *"));
            assert!(!p.contains("/ 2"));
            assert!(!p.contains("while"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every op here is unary: zero commas on both sides.
        for op in OP_ALL {
            let sig = op_sig_src(op);
            let params = sig.split("->").next().unwrap();
            let call = call_src(op, "x");
            assert_eq!(
                call.matches(',').count(),
                params.matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{sig}`"
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = TriangularFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
