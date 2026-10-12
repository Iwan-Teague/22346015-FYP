//! The `interval-map` family (category `data-structures`) — half-open range
//! algebra over `Vec<(i64, i64)>`.
//!
//! Where `value-tree` recurses through a heterogeneous tree, this family
//! maintains a **sorted disjoint-cover invariant**: ranges must be sorted by
//! start and coalesced whenever they overlap *or touch* (`[1,3)` + `[3,5)` is
//! one segment). The seed prunes which two of five query ops are required:
//! `normalize`, `covered`, `contains`, `count`, `largest`. C(5,2) = **10
//! distinct skills**, above the diversity floor; op names are semantic.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops and
//! the emitted reference share one `norm` fold; the differential fuzzes 3000
//! random range sets against the model.
//!
//! Trivial baselines: `const-zero` and `no-coalesce` (sorts but never merges,
//! so overlaps double-count). The canonical example always contains a genuine
//! interior overlap plus one disjoint segment, so every op except `contains`
//! separates `no-coalesce`; pairs containing `contains` are caught by their
//! partner (membership alone is merge-invariant by construction).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    Normalize,
    Covered,
    Contains,
    Count,
    Largest,
}

const OP_ALL: [Op; 5] = [
    Op::Normalize,
    Op::Covered,
    Op::Contains,
    Op::Count,
    Op::Largest,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::Normalize => "normalize",
            Op::Covered => "covered",
            Op::Contains => "contains",
            Op::Count => "count",
            Op::Largest => "largest",
        }
    }

    fn ret(self) -> &'static str {
        match self {
            Op::Normalize => "Vec<(i64, i64)>",
            Op::Contains => "bool",
            Op::Count => "usize",
            _ => "i64",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::Normalize => {
                "the canonical form: sort the ranges by start and coalesce \
                           every pair that overlaps or touches"
            }
            Op::Covered => {
                "the total length of the union of all ranges \
                        (overlaps count once)"
            }
            Op::Contains => {
                "whether x lies inside any range \
                            (start inclusive, end exclusive)"
            }
            Op::Count => "how many disjoint segments remain after coalescing",
            Op::Largest => {
                "the length of the longest segment after coalescing \
                          (0 if there are none)"
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

/// Sort by start, then fuse overlapping-or-touching neighbours.
fn norm(rs: &[(i64, i64)]) -> Vec<(i64, i64)> {
    let mut v: Vec<(i64, i64)> = rs.to_vec();
    v.sort();
    let mut out: Vec<(i64, i64)> = Vec::new();
    for (lo, hi) in v {
        match out.last_mut() {
            Some(last) if lo <= last.1 => last.1 = last.1.max(hi),
            _ => out.push((lo, hi)),
        }
    }
    out
}

/// Total union length.
fn covered_len(rs: &[(i64, i64)]) -> i64 {
    norm(rs).iter().map(|(a, b)| b - a).sum()
}

/// Point membership under half-open semantics.
fn in_union(rs: &[(i64, i64)], x: i64) -> bool {
    norm(rs).iter().any(|&(a, b)| a <= x && x < b)
}

/// Disjoint-segment count after coalescing.
fn seg_count(rs: &[(i64, i64)]) -> usize {
    norm(rs).len()
}

/// Longest segment length, 0 when empty.
fn longest_seg(rs: &[(i64, i64)]) -> i64 {
    norm(rs).iter().map(|(a, b)| b - a).max().unwrap_or(0)
}

fn op_eval(op: Op, rs: &[(i64, i64)], probe: i64) -> Out {
    match op {
        Op::Normalize => Out::Segs(norm(rs)),
        Op::Covered => Out::Int(covered_len(rs)),
        Op::Contains => Out::Bool(in_union(rs, probe)),
        Op::Count => Out::Count(seg_count(rs)),
        Op::Largest => Out::Int(longest_seg(rs)),
    }
}

/// A query result, typed because the ops return four different shapes.
#[derive(Clone, Debug, PartialEq)]
enum Out {
    Segs(Vec<(i64, i64)>),
    Int(i64),
    Bool(bool),
    Count(usize),
}

impl Out {
    /// The result as emitted-source syntax for behavior-test assertions.
    fn lit(&self) -> String {
        match self {
            Out::Segs(v) => render_ranges(v),
            Out::Int(x) => x.to_string(),
            Out::Bool(b) => b.to_string(),
            Out::Count(n) => n.to_string(),
        }
    }
}

// ---- emitted-source fragments ---------------------------------------------

/// The shared coalescing helper, emitted whenever any non-normalize op runs;
/// `normalize` wraps it when it is itself selected.
fn norm_src() -> String {
    "fn norm(rs: &[(i64, i64)]) -> Vec<(i64, i64)> {\n\
     \x20   let mut v: Vec<(i64, i64)> = rs.to_vec();\n\
     \x20   v.sort();\n\
     \x20   let mut out: Vec<(i64, i64)> = Vec::new();\n\
     \x20   for (lo, hi) in v {\n\
     \x20       match out.last_mut() {\n\
     \x20           Some(last) if lo <= last.1 => last.1 = last.1.max(hi),\n\
     \x20           _ => out.push((lo, hi)),\n\
     \x20       }\n\
     \x20   }\n\
     \x20   out\n\
     }\n"
    .to_string()
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    match op {
        Op::Normalize => format!(
            "pub fn {name}(rs: &[(i64, i64)]) -> {ret} {{\n\
             \x20   norm(rs)\n\
             }}\n",
            name = name,
            ret = op.ret(),
        ),
        Op::Covered => format!(
            "pub fn {name}(rs: &[(i64, i64)]) -> {ret} {{\n\
             \x20   norm(rs).iter().map(|(a, b)| b - a).sum()\n\
             }}\n",
            name = name,
            ret = op.ret(),
        ),
        Op::Contains => format!(
            "pub fn {name}(rs: &[(i64, i64)], x: i64) -> {ret} {{\n\
             \x20   norm(rs).iter().any(|&(a, b)| a <= x && x < b)\n\
             }}\n",
            name = name,
            ret = op.ret(),
        ),
        Op::Count => format!(
            "pub fn {name}(rs: &[(i64, i64)]) -> {ret} {{\n\
             \x20   norm(rs).len()\n\
             }}\n",
            name = name,
            ret = op.ret(),
        ),
        Op::Largest => format!(
            "pub fn {name}(rs: &[(i64, i64)]) -> {ret} {{\n\
             \x20   norm(rs).iter().map(|(a, b)| b - a).max().unwrap_or(0)\n\
             }}\n",
            name = name,
            ret = op.ret(),
        ),
    }
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    if op == Op::Contains {
        "pub fn contains(rs: &[(i64, i64)], x: i64) -> bool {\n\
         \x20   todo!()\n\
         }\n"
        .to_string()
    } else {
        format!(
            "pub fn {name}(rs: &[(i64, i64)]) -> {ret} {{\n\
             \x20   todo!()\n\
             }}\n",
            name = op.name(),
            ret = op.ret(),
        )
    }
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    if op == Op::Contains {
        "pub fn contains(rs: &[(i64, i64)], x: i64) -> bool".to_string()
    } else {
        format!("pub fn {}(rs: &[(i64, i64)]) -> {}", op.name(), op.ret())
    }
}

fn reference_src(spec: &Spec) -> String {
    let needs_norm = spec.ops.iter().any(|op| *op != Op::Normalize);
    let mut s = String::new();
    if needs_norm {
        s.push_str(&norm_src());
    }
    for op in spec.ops {
        s.push_str(&op_fn_src(op));
    }
    s
}

// ---- worked examples ------------------------------------------------------

/// The canonical example: `[a, a+6)` overlapped by `[a+4, a+4+b)` (a genuine
/// interior overlap that kills `no-coalesce`) plus one strictly disjoint
/// segment `[c, c+d)` after a gap, fed in scrambled order so sorting matters.
///
/// Pinned structure for every seed: normalized = [(a, a+4+b), (c, c+d)],
/// count = 2, covered = (4+b)+d, largest = 4+b (> d), contains(a+5) = true.
struct Canonical {
    rs: Vec<(i64, i64)>,
    probe: i64,
    // Expectation anchors, consumed by the in-file tests only.
    #[allow(dead_code)]
    first_end: i64,
    #[allow(dead_code)]
    second_cover: i64,
}

fn canonical(seed: u64) -> Canonical {
    let mut rng = Rng::new(seed ^ 0x17_7E_8A_C0);
    // Hoisted locals: two-phase borrows don't apply across fn-call args.
    let a = 1 + rng.below(9) as i64;
    let b = 2 + rng.below(5) as i64;
    let e = 1 + rng.below(4) as i64;
    let d = 2 + rng.below(4) as i64;
    let r1 = (a, a + 6);
    let r2 = (a + 4, a + 4 + b);
    let c = a + 4 + b + e;
    let r3 = (c, c + d);
    Canonical {
        // Scrambled on purpose: unsorted input exercises the sort step.
        rs: vec![r3, r1, r2],
        probe: a + 5,
        first_end: a + 4 + b,
        second_cover: d,
    }
}

/// Random range set from the allowed envelope. Small lens over a ±20 span
/// keep natural collisions frequent enough for the fuzz to bite.
fn rand_ranges(rng: &mut Rng) -> Vec<(i64, i64)> {
    let n = 1 + rng.below(5);
    (0..n)
        .map(|_| {
            let lo = -(rng.below(21) as i64) + rng.below(21) as i64;
            let len = 1 + rng.below(9) as i64;
            (lo, lo + len)
        })
        .collect()
}

type ExampleCase = (Vec<(i64, i64)>, Vec<(Op, Out)>, i64);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_0036);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical first, empty second, then three fuzzed sets.
    let can = canonical(seed);
    cases.push((
        can.rs.clone(),
        spec.ops
            .map(|op| (op, op_eval(op, &can.rs, can.probe)))
            .to_vec(),
        can.probe,
    ));
    cases.push((
        Vec::new(),
        spec.ops.map(|op| (op, op_eval(op, &[], 0))).to_vec(),
        0,
    ));
    for _ in 0..3 {
        let rs = rand_ranges(&mut rng);
        let probe = rs.first().map(|(lo, _)| *lo).unwrap_or(0);
        let outs = spec.ops.map(|op| (op, op_eval(op, &rs, probe))).to_vec();
        cases.push((rs, outs, probe));
    }
    cases
}

/// Render a native slice as emitted-source syntax: `vec![(1, 7), (11, 14)]`.
fn render_ranges(rs: &[(i64, i64)]) -> String {
    format!(
        "vec![{}]",
        rs.iter()
            .map(|(a, b)| format!("({a}, {b})"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// One-line indented prose form for prompt readability.
fn prose_ranges(rs: &[(i64, i64)]) -> String {
    format!(
        "[{}]",
        rs.iter()
            .map(|(a, b)| format!("({a}, {b})"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// The call expression for one op in an emitted assertion.
fn call_src(op: Op, ranges: &str, probe: i64) -> String {
    if op == Op::Contains {
        format!("contains({ranges}, {probe})")
    } else {
        format!("{}({})", op.name(), ranges)
    }
}

fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for (rs, outs, _) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  {}  ->  {}\n", prose_ranges(&rs), results));
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
        "Implement the two query functions in `src/lib.rs`. A range `(lo, hi)` \
         is **half-open**: it covers integers `lo <= t < hi`. Input slices may \
         be unsorted and may overlap or touch.\n\
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
    for (i, (rs, outs, probe)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   let rs = {rs};\n",
            rs = render_ranges(rs),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({call}, {expected});\n",
                call = call_src(*op, "&rs", *probe),
                expected = out.lit(),
            ));
        }
        body.push_str("}\n\n");
    }
    body
}

/// The differential's reference — the norm helper plus the two selected ops,
/// pasted into the test file under `ref_*` names.
fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec)
        .replacen("pub fn normalize", "fn ref_normalize", 1)
        .replacen("pub fn covered", "fn ref_covered", 1)
        .replacen("pub fn contains", "fn ref_contains", 1)
        .replacen("pub fn count", "fn ref_count", 1)
        .replacen("pub fn largest", "fn ref_largest", 1);
    format!(
        "use task::{{{imports}}};\n\
         \n\
         {reference}\
         fn nx(state: &mut u64) -> u64 {{\n\
         \x20   *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20   *state >> 33\n\
         }}\n\
         \n\
         fn gen_ranges(state: &mut u64) -> Vec<(i64, i64)> {{\n\
         \x20   let n = (nx(state) % 5 + 1) as usize;\n\
         \x20   let mut rs = Vec::new();\n\
         \x20   for _ in 0..n {{\n\
         \x20       let lo = (nx(state) % 41) as i64 - 20;\n\
         \x20       let len = ((nx(state) % 9) + 1) as i64;\n\
         \x20       rs.push((lo, lo + len));\n\
         \x20   }}\n\
         \x20   rs\n\
         }}\n\
         \n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0046;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let rs = gen_ranges(&mut state);\n\
         \x20       let x = (nx(&mut state) % 61) as i64 - 30;\n\
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
                let call = call_src(*op, "&rs", 0).replace(", 0)", ", x)");
                format!("        assert_eq!({call}, {ref_call});\n",
                    ref_call = {
                        let name = op.name();
                        if *op == Op::Contains {
                            "ref_contains(&rs, x)".to_string()
                        } else {
                            format!("ref_{name}(&rs)")
                        }
                    },
                )
            })
            .collect::<Vec<_>>()
            .join(""),
    )
}

/// Degenerate: everything empty/zero/false.
fn const_zero(spec: &Spec) -> String {
    let fns = spec
        .ops
        .iter()
        .map(|op| {
            let body = match op {
                Op::Normalize => "Vec::new()",
                Op::Contains => "false",
                Op::Count => "0usize",
                _ => "0",
            };
            if *op == Op::Contains {
                "pub fn contains(rs: &[(i64, i64)], x: i64) -> bool {\n\
                 \x20   let _ = (rs, x);\n\
                 \x20   false\n\
                 }\n"
                .to_string()
            } else {
                format!(
                    "pub fn {name}(rs: &[(i64, i64)]) -> {ret} {{\n\
                     \x20   let _ = rs;\n\
                     \x20   {body}\n\
                     }}\n",
                    name = op.name(),
                    ret = op.ret(),
                    body = body,
                )
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    fns
}

/// The structural cheat: sort but never coalesce. Exact for `contains`
/// (membership is merge-invariant); wrong on the canonical example for every
/// other op, so every pair catches it.
fn no_coalesce(spec: &Spec) -> String {
    let fns = spec
        .ops
        .iter()
        .map(|op| {
            let body = match op {
                Op::Normalize => {
                    "{\n\
                     \x20   let mut v = rs.to_vec();\n\
                     \x20   v.sort();\n\
                     \x20   v\n\
                     \x20 }"
                }
                Op::Covered => "rs.iter().map(|(a, b)| b - a).sum()",
                Op::Contains => "rs.iter().any(|&(a, b)| a <= x && x < b)",
                Op::Count => "rs.len()",
                Op::Largest => "rs.iter().map(|(a, b)| b - a).max().unwrap_or(0)",
            };
            if *op == Op::Contains {
                format!(
                    "pub fn contains(rs: &[(i64, i64)], x: i64) -> bool {{\n\
                     \x20   {body}\n\
                     }}\n",
                    body = body,
                )
            } else {
                format!(
                    "pub fn {name}(rs: &[(i64, i64)]) -> {ret} {{\n\
                     \x20   {body}\n\
                     }}\n",
                    name = op.name(),
                    ret = op.ret(),
                    body = body,
                )
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    fns
}

pub struct IntervalMapFamily;

impl Generator for IntervalMapFamily {
    fn id(&self) -> &str {
        "interval-map"
    }
    fn category(&self) -> &str {
        "data-structures"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("interval-map", seed);

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
            id: format!("interval-map/{seed:016x}"),
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
            // Default oracle weights (docs/04): data-structures starts
            // unweighted until the corpus grows around it.
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
            ("no-coalesce".to_string(), no_coalesce(&spec)),
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
        let g = IntervalMapFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Overlap fuses; containment absorbs; touching fuses; gaps survive.
        assert_eq!(norm(&[(1, 7), (4, 9)]), vec![(1, 9)]);
        assert_eq!(norm(&[(1, 9), (3, 5)]), vec![(1, 9)]);
        assert_eq!(norm(&[(1, 3), (3, 5)]), vec![(1, 5)]);
        assert_eq!(norm(&[(1, 3), (5, 7)]), vec![(1, 3), (5, 7)]);
        assert_eq!(norm(&[]), Vec::<(i64, i64)>::new());
        // Unsorted input is normalized, not rejected.
        assert_eq!(norm(&[(10, 12), (0, 2)]), vec![(0, 2), (10, 12)]);
        // Nested wider-later case: the max-hi arm must win, not the neighbour.
        assert_eq!(norm(&[(0, 2), (1, 10), (3, 4)]), vec![(0, 10)]);

        let mixed = [(0, 4), (6, 10)];
        assert_eq!(covered_len(&mixed), 8);
        assert_eq!(seg_count(&mixed), 2);
        assert_eq!(longest_seg(&mixed), 4);
        assert!(in_union(&mixed, 3));
        assert!(!in_union(&mixed, 4));
        assert!(in_union(&mixed, 6));
        assert!(!in_union(&mixed, 5));
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
        // Both baselines must fail under EVERY pair: const-zero fails all five
        // outright; no-coalesce fails every op except contains, and every pair
        // containing contains also carries a separator.
        for seed in 0..200u64 {
            let can = canonical(seed);
            let n = norm(&can.rs);
            assert_eq!(seg_count(&can.rs), 2);
            assert_eq!(n, vec![(can.rs[1].0, can.first_end), (n[1].0, n[1].1)]);
            let expect_cover = (can.first_end - can.rs[1].0) + can.second_cover;
            assert_eq!(covered_len(&can.rs), expect_cover);
            assert_eq!(longest_seg(&can.rs), can.first_end - can.rs[1].0);
            assert!(in_union(&can.rs, can.probe));
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (rs, outs, probe) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, &rs, probe), out, "seed {seed}");
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
                // Match the `pub fn` line: bare names substring-collide.
                let fn_line = format!("pub fn {}", op.name());
                if spec.ops.contains(&op) {
                    assert!(src.contains(&fn_line));
                } else {
                    assert!(!src.contains(&fn_line), "{:?} leaked", op);
                }
            }
            // The helper appears iff some op needs the canonical form.
            let needs_norm = spec.ops.iter().any(|op| *op != Op::Normalize);
            assert_eq!(src.contains("fn norm("), needs_norm);
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        for seed in [0u64, 1, 2] {
            let spec = sample(seed);
            let sk = skeleton_src(&spec, seed);
            assert!(sk.contains("todo!()"), "skeleton must be stubbed");
            assert!(!sk.contains("last_mut"), "skeleton leaks the fold");
            assert!(!sk.contains(".sort()"), "skeleton leaks the fold");
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("last_mut"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = IntervalMapFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
