//! The `sorted` family (category `sequence-order`) — monotonicity queries
//! over a seeded sequence of signed integers.
//!
//! Where `parity` folds a bag and `minmax` locates its extremes, this
//! family asks **ordering questions**: is the sequence ascending, how far
//! from sorted is it (inversion count), and where do its local rises and
//! falls sit. The domain is one `&[i64]` sequence (values may be negative);
//! every op is a pure function of it. The seed prunes which two of five
//! query ops are required: `is_ascending`, `num_inversions`,
//! `longest_ascending_run`, `num_ascents`, `num_descents`. C(5,2) =
//! **10 distinct skills**, above the diversity floor; op names are
//! semantic.
//!
//! The canonical sequence is sampled until its anchor facts hold: it is
//! NOT ascending yet mixes ascents and descents, carries at least one
//! inversion and one descent, and its longest strictly-ascending run is a
//! proper middle length. Those make every scalar answer nonzero on the
//! canonical (defeating `const-zero` on the four numeric ops) and keep the
//! `always-sorted` cheat inexact on every op; the pinned ascending example
//! flips the boolean against both cheats' `false`.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential fuzzes
//! 3000 random sequences (signed values included) against the model.
//!
//! Trivial baselines: `const-zero` (zeros everywhere, `false` for the
//! flag) and `always-sorted` (every query answered as if the input were
//! already sorted).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    IsAscending,
    NumInversions,
    LongestRun,
    NumAscents,
    NumDescents,
}

const OP_ALL: [Op; 5] = [
    Op::IsAscending,
    Op::NumInversions,
    Op::LongestRun,
    Op::NumAscents,
    Op::NumDescents,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::IsAscending => "is_ascending",
            Op::NumInversions => "num_inversions",
            Op::LongestRun => "longest_ascending_run",
            Op::NumAscents => "num_ascents",
            Op::NumDescents => "num_descents",
        }
    }

    fn ret(self) -> &'static str {
        match self {
            Op::IsAscending => "bool",
            _ => "i64",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::IsAscending => {
                "whether every element is `<=` the next one; the empty and \
                 single-element sequences are trivially ascending, and \
                 equal neighbours do not break the property"
            }
            Op::NumInversions => {
                "how many index pairs `i < j` are out of order \
                 (`xs[i] > xs[j]`)"
            }
            Op::LongestRun => {
                "the length of the longest strictly-ascending contiguous \
                 run (each element `<` its successor); the empty sequence \
                 has none (`0`) and a lone element is a run of one"
            }
            Op::NumAscents => {
                "how many adjacent positions step upward (`xs[i] < \
                 xs[i+1]`); equal neighbours step neither way"
            }
            Op::NumDescents => {
                "how many adjacent positions step downward (`xs[i] > \
                 xs[i+1]`); equal neighbours step neither way"
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

fn b_is_ascending(xs: &[i64]) -> bool {
    for w in xs.windows(2) {
        if w[0] > w[1] {
            return false;
        }
    }
    true
}

fn b_num_inversions(xs: &[i64]) -> i64 {
    let mut count = 0i64;
    for i in 0..xs.len() {
        for j in (i + 1)..xs.len() {
            if xs[i] > xs[j] {
                count += 1;
            }
        }
    }
    count
}

fn b_longest_run(xs: &[i64]) -> i64 {
    if xs.is_empty() {
        return 0;
    }
    let mut best = 1usize;
    let mut cur = 1usize;
    for w in xs.windows(2) {
        if w[0] < w[1] {
            cur += 1;
            if cur > best {
                best = cur;
            }
        } else {
            cur = 1;
        }
    }
    best as i64
}

fn b_num_ascents(xs: &[i64]) -> i64 {
    let mut n = 0i64;
    for w in xs.windows(2) {
        if w[0] < w[1] {
            n += 1;
        }
    }
    n
}

fn b_num_descents(xs: &[i64]) -> i64 {
    let mut n = 0i64;
    for w in xs.windows(2) {
        if w[0] > w[1] {
            n += 1;
        }
    }
    n
}

/// Answer shape: numbers plus one boolean op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Flag(bool),
}

impl Out {
    /// Literal rendering for an emitted assertion.
    fn lit(self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            Out::Flag(true) => "true".to_string(),
            Out::Flag(false) => "false".to_string(),
        }
    }
}

fn op_eval(op: Op, xs: &[i64]) -> Out {
    match op {
        Op::IsAscending => Out::Flag(b_is_ascending(xs)),
        Op::NumInversions => Out::Num(b_num_inversions(xs)),
        Op::LongestRun => Out::Num(b_longest_run(xs)),
        Op::NumAscents => Out::Num(b_num_ascents(xs)),
        Op::NumDescents => Out::Num(b_num_descents(xs)),
    }
}
// ---- canonical sequence -----------------------------------------------------

/// The canonical sequence: three to six signed values in `±500k`, retried
/// until the anchor facts hold.
///
/// Guaranteed for every seed: not ascending, at least one ascent AND one
/// descent step (a mixed shape), at least one inversion, and a longest
/// strictly-ascending run that is neither trivial nor the whole sequence.
fn canonical(seed: u64) -> Vec<i64> {
    let mut rng = Rng::new(seed ^ 0x50A7_17E5);
    for _ in 0..100_000 {
        let len = 3 + rng.below(4) as usize;
        let cand: Vec<i64> = (0..len)
            .map(|_| rng.below(1_000_000) as i64 - 500_000)
            .collect();
        if anchors_hold(&cand) {
            return cand;
        }
    }
    unreachable!("canonical sampling failed to satisfy anchors");
}

fn anchors_hold(xs: &[i64]) -> bool {
    !b_is_ascending(xs)
        && b_num_ascents(xs) >= 1
        && b_num_descents(xs) >= 1
        && b_num_inversions(xs) >= 1
        && b_longest_run(xs) >= 2
        && b_longest_run(xs) < xs.len() as i64
}

// ---- worked examples --------------------------------------------------------

type ExampleCase = (Vec<i64>, Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_0106);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical (non-ascending) first.
    let can = canonical(seed);
    cases.push((
        can.clone(),
        spec.ops.map(|op| (op, op_eval(op, &can))).to_vec(),
    ));
    // Empty: pins every zero/false convention at once.
    cases.push((vec![], spec.ops.map(|op| (op, op_eval(op, &[]))).to_vec()));
    // Fully ascending: flips any always-false flag.
    cases.push((
        vec![1, 2, 3],
        spec.ops.map(|op| (op, op_eval(op, &[1, 2, 3]))).to_vec(),
    ));
    // Fully descending: maximal inversions and descents, no ascents.
    cases.push((
        vec![9, 5, 1],
        spec.ops.map(|op| (op, op_eval(op, &[9, 5, 1]))).to_vec(),
    ));
    for _ in 0..3 {
        let len = 1 + rng.below(6) as usize;
        let v: Vec<i64> = (0..len)
            .map(|_| rng.below(1_000_000) as i64 - 500_000)
            .collect();
        let outs = spec.ops.map(|op| (op, op_eval(op, &v))).to_vec();
        cases.push((v, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the first-element suffix types the
/// whole slice, and the empty form is typed by the function signature.
fn render_i64s(xs: &[i64]) -> String {
    if xs.is_empty() {
        return "&[]".to_string();
    }
    let items = xs
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!("&[{items}i64]")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    let body = match op {
        Op::IsAscending => [
            "for w in xs.windows(2) {",
            "    if w[0] > w[1] {",
            "        return false;",
            "    }",
            "}",
            "true",
        ]
        .join("\n    "),
        Op::NumInversions => [
            "let mut count = 0i64;",
            "for i in 0..xs.len() {",
            "    for j in (i + 1)..xs.len() {",
            "        if xs[i] > xs[j] {",
            "            count += 1;",
            "        }",
            "    }",
            "}",
            "count",
        ]
        .join("\n    "),
        Op::LongestRun => [
            "if xs.is_empty() {",
            "    return 0;",
            "}",
            "let mut best = 1usize;",
            "let mut cur = 1usize;",
            "for w in xs.windows(2) {",
            "    if w[0] < w[1] {",
            "        cur += 1;",
            "        if cur > best {",
            "            best = cur;",
            "        }",
            "    } else {",
            "        cur = 1;",
            "    }",
            "}",
            "best as i64",
        ]
        .join("\n    "),
        Op::NumAscents => [
            "let mut n = 0i64;",
            "for w in xs.windows(2) {",
            "    if w[0] < w[1] {",
            "        n += 1;",
            "    }",
            "}",
            "n",
        ]
        .join("\n    "),
        Op::NumDescents => [
            "let mut n = 0i64;",
            "for w in xs.windows(2) {",
            "    if w[0] > w[1] {",
            "        n += 1;",
            "    }",
            "}",
            "n",
        ]
        .join("\n    "),
    };
    format!("pub fn {name}(xs: &[i64]) -> {ret} {{\n    {body}\n}}\n")
}
/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(xs: &[i64]) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(xs: &[i64]) -> {}", op.name(), op.ret())
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
    for (xs, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  xs {}  ->  {}\n", render_i64s(&xs), results));
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
         given as `xs`, a slice of integers of type `i64` (values may be \
         negative); queries are ordering properties of the whole slice.\n\
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
    for (i, (xs, outs)) in worked_examples(spec, seed).iter().enumerate() {
        // The rendered literal already carries the leading `&`, so bind it
        // once and pass the bare name at each call site.
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let xs = {};\n",
            render_i64s(xs),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "xs"),
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
            let call = call_src(*op, "&vals");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0108;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let mut vals: Vec<i64> = Vec::new();\n\
         \x20       let n = (nx(&mut state) % 6) + 1;\n\
         \x20       for _ in 0..n {{\n\
         \x20           vals.push((nx(&mut state) % 1001) as i64 - 500);\n\
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

/// Degenerate: zeros everywhere, `false` for the flag.
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op {
                Op::IsAscending => {
                    format!("{sig} {{\n    let _ = xs;\n    false\n}}\n")
                }
                _ => format!("{sig} {{\n    let _ = xs;\n    0\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every query as if the input were already
/// sorted. On the canonical sequence — which is NOT ascending — every op
/// disagrees with it, so both baselines are caught under EVERY pair; the
/// pinned ascending example flips the boolean back against them too.
fn always_sorted(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            let body = match op {
                Op::IsAscending => "true".to_string(),
                Op::NumInversions => "0".to_string(),
                Op::NumDescents => "0".to_string(),
                Op::NumAscents => "(xs.len() as i64 - 1)".to_string(),
                Op::LongestRun => "(xs.len() as i64)".to_string(),
            };
            format!("{sig} {{\n    {body}\n}}\n", sig = sig,)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct SortedFamily;

impl Generator for SortedFamily {
    fn id(&self) -> &str {
        "sorted"
    }
    fn category(&self) -> &str {
        "sequence-order"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("sorted", seed);

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
            id: format!("sorted/{seed:016x}"),
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
            ("always-sorted".to_string(), always_sorted(&spec)),
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
        let g = SortedFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Ascendingness: equal neighbours are fine, order breaks it.
        assert!(b_is_ascending(&[1, 2, 2, 7]));
        assert!(!b_is_ascending(&[1, 3, 2]));
        assert!(b_is_ascending(&[5]));
        assert!(b_is_ascending(&[]));
        // Inversions: out-of-order index pairs.
        assert_eq!(b_num_inversions(&[3, 1, 2]), 2);
        assert_eq!(b_num_inversions(&[1, 2, 3]), 0);
        assert_eq!(b_num_inversions(&[3, 2, 1]), 3);
        assert_eq!(b_num_inversions(&[2, 2]), 0);
        assert_eq!(b_num_inversions(&[]), 0);
        // Longest strictly-ascending run.
        assert_eq!(b_longest_run(&[3, 1, 2]), 2);
        assert_eq!(b_longest_run(&[1, 2, 2, 3]), 2);
        assert_eq!(b_longest_run(&[9, 1, 5, 8, 0, 4]), 3);
        assert_eq!(b_longest_run(&[7, 6, 5]), 1);
        assert_eq!(b_longest_run(&[5]), 1);
        assert_eq!(b_longest_run(&[]), 0);
        // Ascents and descents: strict adjacent steps.
        assert_eq!(b_num_ascents(&[1, 3, 7]), 2);
        assert_eq!(b_num_ascents(&[1, 2, 2, 7]), 2);
        assert_eq!(b_num_ascents(&[9, 4, 1]), 0);
        assert_eq!(b_num_ascents(&[]), 0);
        assert_eq!(b_num_descents(&[7, 3, 1]), 2);
        assert_eq!(b_num_descents(&[9, 4, 4, 0]), 2);
        assert_eq!(b_num_descents(&[1, 2, 5]), 0);
        assert_eq!(b_num_descents(&[]), 0);
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
        // Both baselines must fail under EVERY pair. The anchors make the
        // canonical non-ascending with mixed steps, so every scalar answer
        // is nonzero (defeating const-zero on the numerics) and every op
        // disagrees with `always-sorted`; the flag itself is flipped by the
        // pinned ascending example rather than the canonical.
        for seed in 0..200u64 {
            let xs = canonical(seed);
            // Anchor facts the sampler enforces.
            assert!(!b_is_ascending(&xs), "seed {seed}");
            assert!(b_num_ascents(&xs) >= 1, "seed {seed}");
            assert!(b_num_descents(&xs) >= 1, "seed {seed}");
            assert!(b_num_inversions(&xs) >= 1, "seed {seed}");
            let run = b_longest_run(&xs);
            assert!(run >= 2 && run < xs.len() as i64, "seed {seed}");
            for op in OP_ALL {
                match op_eval(op, &xs) {
                    Out::Flag(_) => {} // false==false on canonical; ascending example flips it
                    Out::Num(truth) => {
                        assert_ne!(truth, 0, "const-zero survives {op:?} seed {seed}");
                    }
                }
                // always-sorted disagrees everywhere on the canonical.
                let cheat = always_sorted_cheat_value(op, &xs);
                let truth = op_eval(op, &xs);
                if let (Out::Num(t), Out::Num(c)) = (truth, cheat) {
                    assert_ne!(t, c, "always-sorted survives {op:?} seed {seed}");
                }
            }
        }
    }

    /// The value `always_sorted` would emit for one op — used to pin the
    /// cheat-separation argument without string-compiling anything.
    fn always_sorted_cheat_value(op: Op, xs: &[i64]) -> Out {
        match op {
            Op::IsAscending => Out::Flag(true),
            Op::NumInversions => Out::Num(0),
            Op::LongestRun => Out::Num(xs.len() as i64),
            Op::NumAscents => Out::Num(xs.len() as i64 - 1),
            Op::NumDescents => Out::Num(0),
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (xs, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, &xs).lit(), out.lit(), "seed {seed}");
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
            assert!(!sk.contains("windows("));
            assert!(!sk.contains("count += 1"));
            assert!(!sk.contains("best"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("windows("));
            assert!(!p.contains("count += 1"));
            assert!(!p.contains("best"));
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
            let call = call_src(op, "xs");
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
        let g = SortedFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
