//! The `golf` family (category `golf-scoring`) — stroke-play scoring
//! over a single played hole.
//!
//! Where `dice` totals two faces and `text-wrap` packs words into
//! lines, this family exercises **score-card conventions**: the signed
//! comparison against par, the traditional birdie/bogey ladder name,
//! the two side-of-par predicates, and the five-point amateur
//! Stableford scale. The domain is an ordered pair: a stroke count
//! `u64` from one through twelve and a par `u64` drawn from the
//! standard hole values three, four, and five. The seed prunes which
//! two of five query ops are required: `relative_score`,
//! `stroke_name`, `is_under_par`, `is_over_par`, `stableford_points`.
//! C(5,2) = **10 distinct skills**, above the diversity floor; op
//! names are semantic.
//!
//! The canonical hole is sampled until its anchor fact holds: it went
//! UNDER PAR — so the relative score is negative, the ladder name is
//! a sub-par word, the points land above the par value, and the
//! under-par predicate answers TRUE there. Constant-false cheats and
//! the all-par structural baseline die outright on every scalar op
//! (the pinned bogey example flips their agreeing over-par flags).
//!
//! Solution-first and correct-by-construction (ADR-0003): the native
//! ops and the emitted reference share the same bodies; the
//! differential fuzzes 3000 random holes against the model.
//!
//! Trivial baselines: `const-zero` (fails every scalar op outright on
//! the canonical hole) and `par-everything` (every query answered as
//! if the hole were played at level par — wrong on all four scalars
//! for an under-par round).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    RelativeScore,
    StrokeName,
    IsUnderPar,
    IsOverPar,
    StablefordPoints,
}

const OP_ALL: [Op; 5] = [
    Op::RelativeScore,
    Op::StrokeName,
    Op::IsUnderPar,
    Op::IsOverPar,
    Op::StablefordPoints,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::RelativeScore => "relative_score",
            Op::StrokeName => "stroke_name",
            Op::IsUnderPar => "is_under_par",
            Op::IsOverPar => "is_over_par",
            Op::StablefordPoints => "stableford_points",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::RelativeScore => {
                "the signed difference between strokes taken and par — \
                 negative when the golfer finished below par"
            }
            Op::StrokeName => {
                "the traditional name for the result on the birdie/bogey \
                 ladder: three or more below par is an albatross, two \
                 below an eagle, one below a birdie, level par is \
                 called par, one above a bogey, two above a double \
                 bogey, and beyond that a plain over-count such as \
                 three-over"
            }
            Op::IsUnderPar => "whether the golfer took fewer strokes than the hole's par",
            Op::IsOverPar => "whether the golfer took more strokes than the hole's par",
            Op::StablefordPoints => {
                "the hole's Stableford points on the five-point amateur \
                 scale: albatross or better scores five, eagle four, \
                 birdie three, par two, bogey one, anything worse zero"
            }
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::StrokeName => "String",
            Op::IsUnderPar | Op::IsOverPar => "bool",
            Op::RelativeScore | Op::StablefordPoints => "i64",
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

/// Signed comparison of strokes against par.
fn b_relative_score(strokes: u64, par: u64) -> i64 {
    strokes as i64 - par as i64
}

/// Traditional ladder name for the result.
fn b_stroke_name(strokes: u64, par: u64) -> String {
    match b_relative_score(strokes, par) {
        d if d <= -3 => "albatross".to_string(),
        -2 => "eagle".to_string(),
        -1 => "birdie".to_string(),
        0 => "par".to_string(),
        1 => "bogey".to_string(),
        2 => "double bogey".to_string(),
        d => format!("{}-over", d),
    }
}

/// Fewer strokes than par.
fn b_is_under_par(strokes: u64, par: u64) -> bool {
    b_relative_score(strokes, par) < 0
}

/// More strokes than par.
fn b_is_over_par(strokes: u64, par: u64) -> bool {
    b_relative_score(strokes, par) > 0
}

/// Five-point amateur Stableford scale.
fn b_stableford_points(strokes: u64, par: u64) -> i64 {
    match b_relative_score(strokes, par) {
        d if d <= -3 => 5,
        -2 => 4,
        -1 => 3,
        0 => 2,
        1 => 1,
        _ => 0,
    }
}

/// The answer shape: scalars as `Num`, predicates as `Flag`, text as `Str`.
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

fn op_eval(op: Op, strokes: u64, par: u64) -> Out {
    match op {
        Op::RelativeScore => Out::Num(b_relative_score(strokes, par)),
        Op::StrokeName => Out::Str(b_stroke_name(strokes, par)),
        Op::IsUnderPar => Out::Flag(b_is_under_par(strokes, par)),
        Op::IsOverPar => Out::Flag(b_is_over_par(strokes, par)),
        Op::StablefordPoints => Out::Num(b_stableford_points(strokes, par)),
    }
}

// ---- canonical hole -------------------------------------------------------

/// The canonical hole: sampled from the full domain and retried until
/// the anchor fact holds.
///
/// Guaranteed for every seed: the golfer went UNDER PAR — the signed
/// score is negative (never zero), the ladder name is a sub-par word
/// (never "par"), the Stableford points land at three or better
/// (never the par value two), and the under-par predicate answers
/// TRUE. Constant-false cheats and the all-par baseline die on every
/// scalar op there; their agreeing over-par flags are flipped by the
/// pinned bogey example.
fn canonical(seed: u64) -> (u64, u64) {
    let mut rng = Rng::new(seed ^ 0x601F_C0A5);
    for _ in 0..100_000 {
        let strokes = 1 + rng.below(12);
        let pars = [3u64, 4, 5];
        let par = pars[rng.below(3) as usize];
        if anchors_hold(strokes, par) {
            return (strokes, par);
        }
    }
    unreachable!("canonical hole sampling failed to satisfy anchors");
}

fn anchors_hold(strokes: u64, par: u64) -> bool {
    // Under par is the single load-bearing anchor: it forces the
    // score negative, the name sub-par, and the points above two.
    b_is_under_par(strokes, par)
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = ((u64, u64), Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_0162);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical under-par hole first.
    let can = canonical(seed);
    cases.push((
        can,
        spec.ops.map(|op| (op, op_eval(op, can.0, can.1))).to_vec(),
    ));
    // Level par on a par four: neither predicate holds — the all-par
    // baseline is exact here, so this pins its exactness zone.
    cases.push(((4, 4), spec.ops.map(|op| (op, op_eval(op, 4, 4))).to_vec()));
    // Bogey on a par four: over-par TRUE — flips constant-false cheats.
    cases.push(((5, 4), spec.ops.map(|op| (op, op_eval(op, 5, 4))).to_vec()));
    // Ace on a par four: albatross, deep under par.
    cases.push(((1, 4), spec.ops.map(|op| (op, op_eval(op, 1, 4))).to_vec()));
    for _ in 0..3 {
        let strokes = 1 + rng.below(12);
        let pars = [3u64, 4, 5];
        let par = pars[rng.below(3) as usize];
        let outs = spec.ops.map(|op| (op, op_eval(op, strokes, par))).to_vec();
        cases.push(((strokes, par), outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the first element types the tuple.
fn render_pair(strokes: u64, par: u64) -> String {
    format!("({strokes}u64, {par})")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    let sig = format!("(strokes: u64, par: u64) -> {ret}");
    let body = match op {
        Op::RelativeScore => ["(strokes as i64) - (par as i64)"].join("\n    "),
        Op::StrokeName => [
            "match (strokes as i64) - (par as i64) {",
            "    d if d <= -3 => \"albatross\".to_string(),",
            "    -2 => \"eagle\".to_string(),",
            "    -1 => \"birdie\".to_string(),",
            "    0 => \"par\".to_string(),",
            "    1 => \"bogey\".to_string(),",
            "    2 => \"double bogey\".to_string(),",
            "    d => format!(\"{}-over\", d),",
            "}",
        ]
        .join("\n    "),
        Op::IsUnderPar => ["(strokes as i64) - (par as i64) < 0"].join("\n    "),
        Op::IsOverPar => ["(strokes as i64) - (par as i64) > 0"].join("\n    "),
        Op::StablefordPoints => [
            "match (strokes as i64) - (par as i64) {",
            "    d if d <= -3 => 5,",
            "    -2 => 4,",
            "    -1 => 3,",
            "    0 => 2,",
            "    1 => 1,",
            "    _ => 0,",
            "}",
        ]
        .join("\n    "),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}
/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(strokes: u64, par: u64) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!(
        "pub fn {}(strokes: u64, par: u64) -> {}",
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
    for ((strokes, par), outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  hole {}  ->  {}\n",
            render_pair(strokes, par),
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
         an ordered pair `(strokes, par)`: a stroke count `u64` from one \
         through twelve and a par `u64` that is always one of three, \
         four, or five.\n\
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
    for (i, ((strokes, par), outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let (strokes, par) = {};\n",
            render_pair(*strokes, *par),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "strokes, par"),
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
            let call = call_src(*op, "strokes, par");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0162;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let strokes = (nx(&mut state) % 12) + 1;\n\
         \x20       let pars = [3u64, 4, 5];\n\
         \x20       let par = pars[(nx(&mut state) % 3) as usize];\n\
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
            format!("{sig} {{\n    let _ = (strokes, par);\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every query as if the hole were played
/// at level par. On the canonical under-par hole this misses on all
/// four scalar ops — the score is not zero, the name is not "par", and
/// the points are not the par value two. Only its over-par flag agrees
/// there; the pinned bogey example flips it.
fn par_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.name() {
                "stroke_name" => format!("{sig} {{\n    \"par\".to_string()\n}}\n"),
                "stableford_points" => format!("{sig} {{\n    2\n}}\n"),
                _ => format!("{sig} {{\n    let _ = (strokes, par);\n    false\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct GolfFamily;

impl Generator for GolfFamily {
    fn id(&self) -> &str {
        "golf"
    }
    fn category(&self) -> &str {
        "golf-scoring"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("golf", seed);

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
            id: format!("golf/{seed:016x}"),
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
            ("par-everything".to_string(), par_everything(&spec)),
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
        let g = GolfFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Signed scores across the whole ladder.
        assert_eq!(b_relative_score(3, 4), -1);
        assert_eq!(b_relative_score(5, 4), 1);
        assert_eq!(b_relative_score(3, 3), 0);
        assert_eq!(b_relative_score(3, 5), -2);
        assert_eq!(b_relative_score(6, 3), 3);
        // Ladder names, including the over-count tail.
        assert_eq!(b_stroke_name(1, 4), "albatross");
        assert_eq!(b_stroke_name(2, 5), "albatross");
        assert_eq!(b_stroke_name(3, 5), "eagle");
        assert_eq!(b_stroke_name(4, 5), "birdie");
        assert_eq!(b_stroke_name(4, 4), "par");
        assert_eq!(b_stroke_name(5, 4), "bogey");
        assert_eq!(b_stroke_name(6, 4), "double bogey");
        assert_eq!(b_stroke_name(7, 4), "3-over");
        // Par-dependence: four strokes is a bogey on a par three.
        assert_eq!(b_stroke_name(4, 3), "bogey");
        // Side-of-par predicates split at level.
        assert!(b_is_under_par(2, 4));
        assert!(!b_is_under_par(4, 4));
        assert!(!b_is_over_par(2, 4));
        assert!(b_is_over_par(6, 4));
        for par in [3u64, 4, 5] {
            assert!(!b_is_under_par(par, par));
            assert!(!b_is_over_par(par, par));
        }
        // Five-point Stableford scale.
        assert_eq!(b_stableford_points(1, 4), 5);
        assert_eq!(b_stableford_points(2, 4), 4);
        assert_eq!(b_stableford_points(3, 5), 4);
        assert_eq!(b_stableford_points(4, 5), 3);
        assert_eq!(b_stableford_points(4, 4), 2);
        assert_eq!(b_stableford_points(5, 4), 1);
        assert_eq!(b_stableford_points(6, 4), 0);
        assert_eq!(b_stableford_points(8, 3), 0);
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
        // The canonical hole went UNDER PAR, so NO skips on scalars:
        // const-zero dies outright (score negative, spelled sub-par
        // name, points at three or better); par-everything dies too
        // (its zero score, "par" name, and two points are all wrong
        // under par; its false under-flag loses to the canonical
        // TRUE). Only the over-par flag agrees with both cheats
        // mid-canonical — the pinned bogey example flips it.
        for seed in 0..200u64 {
            let (strokes, par) = canonical(seed);
            let rel = b_relative_score(strokes, par);
            let name = b_stroke_name(strokes, par);
            let pts = b_stableford_points(strokes, par);
            // Anchor facts the sampler enforces.
            assert!(
                b_is_under_par(strokes, par),
                "seed {seed}: must be under par"
            );
            // const-zero survives nowhere.
            assert!(rel < 0, "const-zero survives relative_score at seed {seed}");
            assert!(!name.is_empty(), "seed {seed}");
            assert_ne!(
                name, "par",
                "const-zero survives stroke_name at seed {seed}"
            );
            assert!(
                pts != 0,
                "const-zero survives stableford_points at seed {seed}"
            );
            assert!(b_is_under_par(strokes, par), "seed {seed}");
            // par-everything survives nowhere on this hole.
            assert_ne!(
                rel, 0,
                "par-everything survives relative_score at seed {seed}"
            );
            assert_ne!(
                name, "par",
                "par-everything survives stroke_name at seed {seed}"
            );
            assert_ne!(
                pts, 2,
                "par-everything survives stableford_points at seed {seed}"
            );
            assert!(
                b_is_under_par(strokes, par),
                "par-everything survives is_under_par at seed {seed}"
            );
            // The over-par flag is genuinely FALSE here — documented
            // skip for both cheats, flipped by the bogey example.
            assert!(!b_is_over_par(strokes, par), "seed {seed}");
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for ((strokes, par), outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, strokes, par), out, "seed {seed}");
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
            // the worked examples legitimately show outputs like
            // "birdie" — so tokens carry implementation shapes.
            assert!(!sk.contains("<= -3"));
            assert!(!sk.contains("=> \""));
            assert!(!sk.contains("{}-over"));
            assert!(!sk.contains("< 0"));
            assert!(!sk.contains("> 0"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("<= -3"));
            assert!(!p.contains("=> \""));
            assert!(!p.contains("{}-over"));
            assert!(!p.contains("< 0"));
            assert!(!p.contains("> 0"));
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
            let call = call_src(op, "strokes, par");
            assert_eq!(
                call.matches(',').count(),
                params.matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{sig}`"
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = GolfFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
