//! The `pitch` family (category `pitch-class`) — arithmetic over pairs of
//! MIDI note numbers.
//!
//! Where `clock` reads a wall clock and `complex-plane` measures points,
//! this family exercises **lookup-table music semantics**: the semitone
//! distance, the interval class folded onto the twelve-semitone circle,
//! the octave-register span, the white/black key-color predicate, and the
//! sharps-spelled name of the lower note. The domain is an ordered pair of
//! note numbers, each `u64` from zero through one hundred twenty-seven.
//! The seed prunes which two of five query ops are required:
//! `semitone_distance`, `interval_class`, `octave_span`, `same_color`,
//! `lower_note`. C(5,2) = **10 distinct skills**, above the diversity
//! floor; op names are semantic.
//!
//! The canonical pair is sampled until its anchor facts hold: the notes
//! are ordered (`a < b`), share a key color, sit more than a semitone
//! circle away from class zero, cross a register boundary, and give three
//! mutually distinct answers — so any solution echoing one query's answer
//! for another dies immediately, and both trivial baselines fail on every
//! op (the color predicate answers TRUE on the canonical pair, killing
//! constant-false cheats outright; the pinned mixed-color example flips
//! constant-true ones).
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential fuzzes
//! 3000 random note pairs against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the
//! canonical example) and `distance-everything` (every scalar query
//! answered with the raw semitone distance; exact only on
//! `semitone_distance`, which its partner catches).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    SemitoneDistance,
    IntervalClass,
    OctaveSpan,
    SameColor,
    LowerNote,
}

const OP_ALL: [Op; 5] = [
    Op::SemitoneDistance,
    Op::IntervalClass,
    Op::OctaveSpan,
    Op::SameColor,
    Op::LowerNote,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::SemitoneDistance => "semitone_distance",
            Op::IntervalClass => "interval_class",
            Op::OctaveSpan => "octave_span",
            Op::SameColor => "same_color",
            Op::LowerNote => "lower_note",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::SemitoneDistance => "the absolute distance between the two notes in semitones",
            Op::IntervalClass => {
                "the smallest gap between the notes measured on the \
                 twelve-semitone circle: a distance of d counts as the \
                 smaller of its remainder on division by twelve and twelve \
                 minus that remainder"
            }
            Op::OctaveSpan => {
                "how many octave registers separate the notes — the gap \
                 between their positions after dividing each note number \
                 by twelve"
            }
            Op::SameColor => {
                "whether both notes are piano-white or both piano-black; \
                 black keys sit at pitch classes one, three, six, eight, \
                 and ten within an octave"
            }
            Op::LowerNote => {
                "the note name of the lower of the two MIDI numbers, \
                 sharps spelling"
            }
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::LowerNote => "String",
            Op::SameColor => "bool",
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

/// Absolute distance between the two notes in semitones.
fn b_semitone_distance(a: u64, b: u64) -> i64 {
    a.abs_diff(b) as i64
}

/// Smallest gap on the twelve-semitone circle.
fn b_interval_class(a: u64, b: u64) -> i64 {
    let d = (a.abs_diff(b) % 12) as i64;
    d.min(12 - d)
}

/// Register-index gap.
fn b_octave_span(a: u64, b: u64) -> i64 {
    (a / 12).abs_diff(b / 12) as i64
}

/// Whether both notes are white keys or both black keys.
fn b_same_color(a: u64, b: u64) -> bool {
    fn is_black(n: u64) -> bool {
        matches!(n % 12, 1 | 3 | 6 | 8 | 10)
    }
    is_black(a) == is_black(b)
}

/// Sharps-spelled name of the lower note.
fn b_lower_note(a: u64, b: u64) -> String {
    const NAMES: [&str; 12] = [
        "C", "C#", "D", "D#", "E", "F", "F#", "G", "G#", "A", "A#", "B",
    ];
    NAMES[(a.min(b) % 12) as usize].to_string()
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

fn op_eval(op: Op, a: u64, b: u64) -> Out {
    match op {
        Op::SemitoneDistance => Out::Num(b_semitone_distance(a, b)),
        Op::IntervalClass => Out::Num(b_interval_class(a, b)),
        Op::OctaveSpan => Out::Num(b_octave_span(a, b)),
        Op::SameColor => Out::Flag(b_same_color(a, b)),
        Op::LowerNote => Out::Str(b_lower_note(a, b)),
    }
}

// ---- canonical note pair ------------------------------------------------------

/// The canonical pair: sampled from the full MIDI range and retried until
/// the anchor facts hold.
///
/// Guaranteed for every seed: ordered (`a < b`, so the distance and span
/// are nonzero), same key color (the color predicate answers TRUE there —
/// constant-false cheats die outright; the pinned mixed-color example
/// flips constant-true ones), off all interval-class zeros (not an
/// octave-multiple apart, which also forces the two names to differ),
/// across a register boundary, and with three mutually distinct scalar
/// answers — echoing one query's answer for another is wrong everywhere.
fn canonical(seed: u64) -> (u64, u64) {
    let mut rng = Rng::new(seed ^ 0xC07A_C1A5);
    for _ in 0..100_000 {
        let a = rng.below(128);
        let b = rng.below(128);
        if anchors_hold(a, b) {
            return (a, b);
        }
    }
    unreachable!("canonical pair sampling failed to satisfy anchors");
}

fn anchors_hold(a: u64, b: u64) -> bool {
    let sd = b_semitone_distance(a, b);
    let ic = b_interval_class(a, b);
    let sp = b_octave_span(a, b);
    // Ordered, same color, off class zero (which also makes the two note
    // names differ), across registers, three distinct scalars. The
    // distance itself is nonzero by ordering.
    a < b && b_same_color(a, b) && ic != 0 && sp != 0 && sd != ic && sd != sp && ic != sp
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = ((u64, u64), Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_014C);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical pair first.
    let can = canonical(seed);
    cases.push((
        can,
        spec.ops.map(|op| (op, op_eval(op, can.0, can.1))).to_vec(),
    ));
    // Unison: every scalar collapses to zero; the color matches.
    cases.push(((0, 0), spec.ops.map(|op| (op, op_eval(op, 0, 0))).to_vec()));
    // Adjacent white/black: mixed colors flip constant-true cheats.
    cases.push(((0, 1), spec.ops.map(|op| (op, op_eval(op, 0, 1))).to_vec()));
    // A clean octave: distance twelve, class zero, one register apart.
    cases.push((
        (60, 72),
        spec.ops.map(|op| (op, op_eval(op, 60, 72))).to_vec(),
    ));
    for _ in 0..3 {
        let a = rng.below(128);
        let b = rng.below(128);
        let outs = spec.ops.map(|op| (op, op_eval(op, a, b))).to_vec();
        cases.push(((a, b), outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the first element types the tuple.
fn render_pair(a: u64, b: u64) -> String {
    format!("({a}u64, {b})")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    let sig = format!("(a: u64, b: u64) -> {ret}");
    let body = match op {
        Op::SemitoneDistance => "a.abs_diff(b) as i64".to_string(),
        Op::IntervalClass => {
            ["let d = (a.abs_diff(b) % 12) as i64;", "d.min(12 - d)"].join("\n    ")
        }
        Op::OctaveSpan => "(a / 12).abs_diff(b / 12) as i64".to_string(),
        Op::SameColor => {
            [
                "fn is_black(n: u64) -> bool {",
                "    matches!(n % 12, 1 | 3 | 6 | 8 | 10)",
                "}",
                "is_black(a) == is_black(b)",
            ]
            .join("\n    ")
        }
        Op::LowerNote => [
            "const NAMES: [&str; 12] = [",
            "    \"C\", \"C#\", \"D\", \"D#\", \"E\", \"F\", \"F#\", \"G\", \"G#\", \"A\", \"A#\", \"B\",",
            "];",
            "NAMES[(a.min(b) % 12) as usize].to_string()",
        ]
        .join("\n    "),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(a: u64, b: u64) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(a: u64, b: u64) -> {}", op.name(), op.ret())
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
    for ((a, b), outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  notes {}  ->  {}\n", render_pair(a, b), results));
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
         an ordered pair of MIDI note numbers `a` and `b`, each of type \
         `u64` from zero through one hundred twenty-seven; note names use \
         sharps spelling and piano key colors follow from pitch class.\n\
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
    for (i, ((a, b), outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let (a, b) = {};\n",
            render_pair(*a, *b),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "a, b"),
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
            let call = call_src(*op, "a, b");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_014C;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let a = nx(&mut state) % 128;\n\
         \x20       let b = nx(&mut state) % 128;\n\
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
            format!("{sig} {{\n    let _ = (a, b);\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every scalar query with the raw semitone
/// distance. The canonical anchors keep the distance distinct from the
/// class and the span, so this is exact only on `semitone_distance` — its
/// partner op catches every pair. The color flag answers false where the
/// canonical pair answers true, and the name slot is empty where a real
/// note name belongs.
fn distance_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => format!("{sig} {{\n    false\n}}\n"),
                "String" => format!("{sig} {{\n    String::new()\n}}\n"),
                _ => format!("{sig} {{\n    a.abs_diff(b) as i64\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct PitchFamily;

impl Generator for PitchFamily {
    fn id(&self) -> &str {
        "pitch"
    }
    fn category(&self) -> &str {
        "pitch-class"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("pitch", seed);

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
            id: format!("pitch/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure integer and table-lookup queries — no unsafe anywhere.
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
                "distance-everything".to_string(),
                distance_everything(&spec),
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
        let g = PitchFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Distances across the range, order-blind.
        assert_eq!(b_semitone_distance(60, 62), 2);
        assert_eq!(b_semitone_distance(62, 60), 2);
        assert_eq!(b_semitone_distance(69, 69), 0);
        assert_eq!(b_semitone_distance(60, 72), 12);
        assert_eq!(b_semitone_distance(0, 127), 127);
        // Classes fold onto the circle.
        assert_eq!(b_interval_class(60, 60), 0);
        assert_eq!(b_interval_class(60, 72), 0);
        assert_eq!(b_interval_class(60, 61), 1);
        assert_eq!(b_interval_class(60, 71), 1);
        assert_eq!(b_interval_class(71, 60), 1);
        assert_eq!(b_interval_class(60, 66), 6);
        assert_eq!(b_interval_class(48, 79), 5);
        // Register spans floor per note number.
        assert_eq!(b_octave_span(60, 72), 1);
        assert_eq!(b_octave_span(69, 69), 0);
        assert_eq!(b_octave_span(72, 60), 1);
        assert_eq!(b_octave_span(59, 60), 1);
        assert_eq!(b_octave_span(0, 127), 10);
        assert_eq!(b_octave_span(60, 71), 0);
        // Colors follow pitch class across registers.
        assert!(b_same_color(60, 64));
        assert!(b_same_color(61, 63));
        assert!(!b_same_color(60, 61));
        assert!(b_same_color(60, 72));
        assert!(!b_same_color(65, 68));
        assert!(b_same_color(118, 121));
        // Names pick the lower note, sharps spelling.
        assert_eq!(b_lower_note(60, 62), "C");
        assert_eq!(b_lower_note(62, 60), "C");
        assert_eq!(b_lower_note(69, 67), "G");
        assert_eq!(b_lower_note(61, 63), "C#");
        assert_eq!(b_lower_note(72, 72), "C");
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
        // Both baselines must fail under EVERY pair with one documented
        // skip: the anchors force an ordered same-color pair that is off
        // every interval-class zero and register boundary, with three
        // mutually distinct scalars — so const-zero dies on all five ops,
        // distance-everything is exact only on semitone_distance (partner
        // catches), its false flag loses to the canonical TRUE color, and
        // its empty name loses to a real note. The pinned mixed-color
        // example (0, 1) flips constant-true flag cheats.
        for seed in 0..200u64 {
            let (a, b) = canonical(seed);
            let sd = b_semitone_distance(a, b);
            let ic = b_interval_class(a, b);
            let sp = b_octave_span(a, b);
            // Anchor facts the sampler enforces.
            assert!(a < b, "seed {seed}");
            assert!(b_same_color(a, b), "seed {seed}: color flag must be true");
            assert_ne!(ic, 0, "seed {seed}");
            assert_ne!(sp, 0, "seed {seed}");
            assert_ne!(sd, ic, "seed {seed}");
            assert_ne!(sd, sp, "seed {seed}");
            assert_ne!(ic, sp, "seed {seed}");
            // const-zero survives nowhere on the scalars or the name.

            for v in [sd, ic, sp] {
                assert_ne!(v, 0, "const-zero survives at ({a}, {b}) seed {seed}");
            }
            assert!(!b_lower_note(a, b).is_empty(), "seed {seed}");
            // distance-everything echoes the distance everywhere.
            for (op, truth) in [(Op::IntervalClass, ic), (Op::OctaveSpan, sp)] {
                assert_ne!(
                    truth, sd,
                    "distance-everything survives {op:?} at ({a}, {b}) seed {seed}"
                );
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for ((a, b), outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, a, b), out, "seed {seed}");
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
            // the worked examples legitimately show outputs, never rules.
            assert!(!sk.contains("% 12"));
            assert!(!sk.contains("/ 12"));
            assert!(!sk.contains(".min("));
            assert!(!sk.contains("matches!"));
            assert!(!sk.contains("NAMES"));
            assert!(!sk.contains("abs_diff"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("% 12"));
            assert!(!p.contains("/ 12"));
            assert!(!p.contains(".min("));
            assert!(!p.contains("matches!"));
            assert!(!p.contains("NAMES"));
            assert!(!p.contains("abs_diff"));
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
            let call = call_src(op, "a, b");
            assert_eq!(
                call.matches(',').count(),
                params.matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{sig}`"
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = PitchFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
