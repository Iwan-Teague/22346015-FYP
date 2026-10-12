//! The `letter-grade` family (category `threshold-grading`) — band
//! classification over a seeded exam score.
//!
//! Where `coins` decomposes an amount and `temp-scale` converts between
//! scales, this family exercises **threshold classification**: mapping a
//! raw score onto letter bands, grade points, a band index counting from
//! the bottom, the pass/fail predicate, and the distance to the next
//! boundary. The domain is one score `score: u64` from zero through one
//! hundred; bands follow the classic cutoffs with every boundary
//! inclusive. The seed prunes which two of five query ops are required:
//! `letter_grade`, `grade_points`, `grade_step`, `is_passing`,
//! `points_to_next`. C(5,2) = **10 distinct skills**, above the diversity
//! floor; op names are semantic.
//!
//! The canonical score is sampled until its anchor facts hold: strictly
//! inside the D or B band (so grade points and band index differ, both
//! nonzero), passing (so the predicate answers true and a cheating
//! `false` dies immediately), and with the next-boundary distance distinct
//! from both scalar answers. That makes `const-zero` wrong on all five ops
//! there, and `score-everything` wrong on all five too — the letter never
//! equals the raw score rendered as text because digits are not letters.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential fuzzes
//! 3000 random scores against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the
//! canonical example) and `score-everything` (every query answered with
//! the raw score).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    LetterGrade,
    GradePoints,
    GradeStep,
    IsPassing,
    PointsToNext,
}

const OP_ALL: [Op; 5] = [
    Op::LetterGrade,
    Op::GradePoints,
    Op::GradeStep,
    Op::IsPassing,
    Op::PointsToNext,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::LetterGrade => "letter_grade",
            Op::GradePoints => "grade_points",
            Op::GradeStep => "grade_step",
            Op::IsPassing => "is_passing",
            Op::PointsToNext => "points_to_next",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::LetterGrade => {
                "the letter band: A from ninety points, B from eighty, \
                 C from seventy, D from sixty — each boundary inclusive — \
                 otherwise F"
            }
            Op::GradePoints => {
                "the grade points for the band: four for A, three for B, \
                 two for C, one for D, zero for F"
            }
            Op::GradeStep => {
                "the band index counting up from the bottom: F is zero \
                 and A is four — always four minus the grade points"
            }
            Op::IsPassing => {
                "whether the score earns credit — the D boundary at \
                 sixty itself counts as passing"
            }
            Op::PointsToNext => {
                "how many more points the next letter up requires: sixty \
                 minus the score below passing, seventy in the D band, \
                 eighty in C, ninety in B, and zero once A is reached"
            }
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::LetterGrade => "String",
            Op::IsPassing => "bool",
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

/// The letter band; every boundary inclusive.
fn b_letter_grade(score: u64) -> String {
    if score >= 90 {
        "A".to_string()
    } else if score >= 80 {
        "B".to_string()
    } else if score >= 70 {
        "C".to_string()
    } else if score >= 60 {
        "D".to_string()
    } else {
        "F".to_string()
    }
}

/// Grade points: four for A down to zero for F.
fn b_grade_points(score: u64) -> i64 {
    if score >= 90 {
        4
    } else if score >= 80 {
        3
    } else if score >= 70 {
        2
    } else if score >= 60 {
        1
    } else {
        0
    }
}

/// Band index from the bottom; always four minus the grade points.
fn b_grade_step(score: u64) -> i64 {
    if score >= 90 {
        0
    } else if score >= 80 {
        1
    } else if score >= 70 {
        2
    } else if score >= 60 {
        3
    } else {
        4
    }
}

/// Passing means sixty or better; the boundary counts.
fn b_is_passing(score: u64) -> bool {
    score >= 60
}

/// Points missing for the next letter up; zero in the top band.
fn b_points_to_next(score: u64) -> i64 {
    if score >= 90 {
        0
    } else if score >= 80 {
        90 - score as i64
    } else if score >= 70 {
        80 - score as i64
    } else if score >= 60 {
        70 - score as i64
    } else {
        60 - score as i64
    }
}

/// The answer shape: scalars as `Num`, predicates as `Flag`, the letter as
/// `Str`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Flag(bool),
    Str(String),
}

impl Out {
    fn lit(&self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            Out::Flag(b) => b.to_string(),
            Out::Str(s) => format!("{s:?}"),
        }
    }
}

fn op_eval(op: Op, score: u64) -> Out {
    match op {
        Op::LetterGrade => Out::Str(b_letter_grade(score)),
        Op::GradePoints => Out::Num(b_grade_points(score)),
        Op::GradeStep => Out::Num(b_grade_step(score)),
        Op::IsPassing => Out::Flag(b_is_passing(score)),
        Op::PointsToNext => Out::Num(b_points_to_next(score)),
    }
}

// ---- canonical score --------------------------------------------------------

/// The canonical score: sampled 0..=100 and retried until the anchor facts
/// hold.
///
/// Guaranteed for every seed: inside the D or B band (grade points and band
/// index are 1 and 3 — nonzero and distinct), passing (the predicate
/// answers true, killing any cheating `false` outright), and with the
/// next-boundary distance distinct from both scalar answers. That makes
/// `const-zero` wrong on all five ops there, and `score-everything` wrong
/// on all five too.
fn canonical(seed: u64) -> u64 {
    let mut rng = Rng::new(seed ^ 0x6C37_ADE1);
    for _ in 0..100_000 {
        let s = rng.below(101);
        if anchors_hold(s) {
            return s;
        }
    }
    unreachable!("canonical score sampling failed to satisfy anchors");
}

fn anchors_hold(score: u64) -> bool {
    let gp = b_grade_points(score);
    let st = b_grade_step(score);
    let nx = b_points_to_next(score);
    (61..=89).contains(&score)
        && !matches!(score, 70..=79)
        && b_is_passing(score)
        && gp != st
        && nx != gp
        && nx != st
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (u64, Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_0140);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical score first.
    let can = canonical(seed);
    cases.push((can, spec.ops.map(|op| (op, op_eval(op, can))).to_vec()));
    // Zero: the F corner — grade points zero, band index four, sixty
    // points short of passing.
    cases.push((0, spec.ops.map(|op| (op, op_eval(op, 0))).to_vec()));
    // One below the pass boundary: still failing, one point short.
    cases.push((59, spec.ops.map(|op| (op, op_eval(op, 59))).to_vec()));
    // The pass boundary itself: inclusive, ten points from a C.
    cases.push((60, spec.ops.map(|op| (op, op_eval(op, 60))).to_vec()));
    // The A boundary: top band, nothing further to reach.
    cases.push((90, spec.ops.map(|op| (op, op_eval(op, 90))).to_vec()));
    // The maximum score.
    cases.push((100, spec.ops.map(|op| (op, op_eval(op, 100))).to_vec()));
    for _ in 0..3 {
        let s = rng.below(101);
        let outs = spec.ops.map(|op| (op, op_eval(op, s))).to_vec();
        cases.push((s, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the suffix types it as `u64`.
fn render_u64(s: u64) -> String {
    format!("{s}u64")
}

const BAND_CHAIN: &[&str] = &[
    "if score >= 90 {",
    "    \"A\".to_string()",
    "} else if score >= 80 {",
    "    \"B\".to_string()",
    "} else if score >= 70 {",
    "    \"C\".to_string()",
    "} else if score >= 60 {",
    "    \"D\".to_string()",
    "} else {",
    "    \"F\".to_string()",
    "}",
];

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    let sig = format!("(score: u64) -> {ret}");
    let body = match op {
        Op::LetterGrade => BAND_CHAIN.join("\n    "),
        Op::GradePoints => [
            "if score >= 90 {",
            "    4",
            "} else if score >= 80 {",
            "    3",
            "} else if score >= 70 {",
            "    2",
            "} else if score >= 60 {",
            "    1",
            "} else {",
            "    0",
            "}",
        ]
        .join("\n    "),
        Op::GradeStep => [
            "if score >= 90 {",
            "    0",
            "} else if score >= 80 {",
            "    1",
            "} else if score >= 70 {",
            "    2",
            "} else if score >= 60 {",
            "    3",
            "} else {",
            "    4",
            "}",
        ]
        .join("\n    "),
        // A property of the raw score alone.
        Op::IsPassing => "score >= 60".to_string(),
        Op::PointsToNext => [
            "if score >= 90 {",
            "    0",
            "} else if score >= 80 {",
            "    90 - score as i64",
            "} else if score >= 70 {",
            "    80 - score as i64",
            "} else if score >= 60 {",
            "    70 - score as i64",
            "} else {",
            "    60 - score as i64",
            "}",
        ]
        .join("\n    "),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(score: u64) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(score: u64) -> {}", op.name(), op.ret())
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
    for (score, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  score {}  ->  {}\n", render_u64(score), results));
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
         one exam score `score` of type `u64`, from zero through one \
         hundred; letter bands follow the classic cutoffs and every \
         boundary is inclusive.\n\
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
    for (i, (score, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let score = {};\n",
            render_u64(*score),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "score"),
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
            let call = call_src(*op, "score");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0140;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let score = nx(&mut state) % 101;\n\
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
                "String" => "String::new()",
                _ => "0",
            };
            format!("{sig} {{\n    let _ = score;\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer the raw score no matter what was asked.
/// The canonical anchors keep every scalar answer small and nonzero, the
/// letter is never the score rendered as text (digits are not letters),
/// and the pass predicate answers true there — wrong on all five ops.
fn score_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => format!("{sig} {{\n    false\n}}\n"),
                "String" => format!("{sig} {{\n    score.to_string()\n}}\n"),
                _ => format!("{sig} {{\n    score as i64\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct LetterGradeFamily;

impl Generator for LetterGradeFamily {
    fn id(&self) -> &str {
        "letter-grade"
    }
    fn category(&self) -> &str {
        "threshold-grading"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("letter-grade", seed);

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
            id: format!("letter-grade/{seed:016x}"),
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
            ("score-everything".to_string(), score_everything(&spec)),
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
        let g = LetterGradeFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Letters at every boundary.
        assert_eq!(b_letter_grade(100), "A");
        assert_eq!(b_letter_grade(90), "A");
        assert_eq!(b_letter_grade(89), "B");
        assert_eq!(b_letter_grade(70), "C");
        assert_eq!(b_letter_grade(69), "D");
        assert_eq!(b_letter_grade(59), "F");
        // Grade points and their complement band index.
        assert_eq!(b_grade_points(95), 4);
        assert_eq!(b_grade_points(65), 1);
        assert_eq!(b_grade_points(0), 0);
        assert_eq!(b_grade_step(95), 0);
        assert_eq!(b_grade_step(65), 3);
        assert_eq!(b_grade_step(59), 4);
        for s in [0u64, 60, 61, 75, 85, 100] {
            assert_eq!(b_grade_points(s) + b_grade_step(s), 4);
        }
        // Pass boundary inclusive.
        assert!(b_is_passing(60));
        assert!(!b_is_passing(59));
        // Distance to the next boundary, per band.
        assert_eq!(b_points_to_next(59), 1);
        assert_eq!(b_points_to_next(0), 60);
        assert_eq!(b_points_to_next(65), 5);
        assert_eq!(b_points_to_next(89), 1);
        assert_eq!(b_points_to_next(90), 0);
        assert_eq!(b_points_to_next(100), 0);
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
        // anchors force a passing D-or-B-band score whose scalars are
        // nonzero, mutually distinct, and tiny next to the raw score.
        for seed in 0..200u64 {
            let s = canonical(seed);
            // Anchor facts the sampler enforces.
            assert!((61..=89).contains(&s), "seed {seed}");
            assert!(!(70..=79).contains(&s), "seed {seed}");
            assert!(b_is_passing(s), "seed {seed}");
            let gp = b_grade_points(s);
            let st = b_grade_step(s);
            let nx = b_points_to_next(s);
            for v in [gp, st, nx] {
                assert_ne!(v, 0, "const-zero survives at score {s} seed {seed}");
                assert_ne!(
                    v, s as i64,
                    "score-everything survives at score {s} seed {seed}"
                );
            }
            assert_ne!(gp, st, "seed {seed}");
            assert_ne!(nx, gp, "seed {seed}");
            assert_ne!(nx, st, "seed {seed}");
            assert_ne!(b_letter_grade(s), s.to_string(), "seed {seed}");
            // The flag kills both cheats' `false` directly on canonical.
            assert!(b_is_passing(s));
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (score, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, score), out, "seed {seed}");
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
            assert!(!sk.contains(">= 90"));
            assert!(!sk.contains(">= 80"));
            assert!(!sk.contains(">= 70"));
            assert!(!sk.contains(">= 60"));
            assert!(!sk.contains("- 90"));
            assert!(!sk.contains("- 60"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains(">= 90"));
            assert!(!p.contains(">= 80"));
            assert!(!p.contains(">= 70"));
            assert!(!p.contains(">= 60"));
            assert!(!p.contains("- 90"));
            assert!(!p.contains("- 60"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every op here is unary: no call site may carry a comma.
        for op in OP_ALL {
            let call = call_src(op, "score");
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
        let g = LetterGradeFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
