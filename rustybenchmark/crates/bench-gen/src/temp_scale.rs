//! The `temp-scale` family (category `unit-conversion`) — conversions and
//! threshold predicates over a seeded Celsius reading.
//!
//! Where `coins` decomposes an amount and `clock` folds angles, this family
//! exercises **unit conversion between scales**: the Fahrenheit equivalent,
//! the Kelvin offset, the historic Réaumur scale, and the two physical
//! anchor predicates (at-or-below freezing, at-or-above boiling). The
//! domain is one reading `celsius: i64`, sampled from −60 through 150 so
//! both anchor predicates are reachable. Conversions use plain `i64`
//! arithmetic; the ratio conversions truncate toward zero on the division,
//! and that truncation is part of the spec. The seed prunes which two of
//! five query ops are required: `to_fahrenheit`, `to_kelvin`,
//! `to_reaumur`, `is_freezing`, `is_boiling`. C(5,2) = **10 distinct
//! skills**, above the diversity floor; op names are semantic.
//!
//! The canonical reading is sampled until its anchor facts hold: strictly
//! between the two anchor points, far enough from zero that every scaled
//! answer is nonzero, and with all three converted answers mutually
//! distinct and distinct from the raw reading (which rules out the famous
//! −40 equality and the −18 Fahrenheit-zero coincidence). Those make
//! `const-zero` wrong on all three scalar ops there, and
//! `kelvin-everything` wrong on the other two scalars; the flags agree
//! with a cheating `false` mid-range, so the worked examples pin readings
//! where each predicate answers true.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential fuzzes
//! 3000 random readings against the model.
//!
//! Trivial baselines: `const-zero` (fails every scalar outright on the
//! canonical example) and `kelvin-everything` (every query answered with
//! the Kelvin offset).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    ToFahrenheit,
    ToKelvin,
    ToReaumur,
    IsFreezing,
    IsBoiling,
}

const OP_ALL: [Op; 5] = [
    Op::ToFahrenheit,
    Op::ToKelvin,
    Op::ToReaumur,
    Op::IsFreezing,
    Op::IsBoiling,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::ToFahrenheit => "to_fahrenheit",
            Op::ToKelvin => "to_kelvin",
            Op::ToReaumur => "to_reaumur",
            Op::IsFreezing => "is_freezing",
            Op::IsBoiling => "is_boiling",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::ToFahrenheit => {
                "the Fahrenheit equivalent: scale by nine fifths \
                 (truncating toward zero), then shift up thirty-two degrees"
            }
            Op::ToKelvin => {
                "the Kelvin equivalent on the older convention where zero \
                 Kelvin sits two hundred seventy-three below zero Celsius"
            }
            Op::ToReaumur => {
                "the Réaumur equivalent, the historic scale whose boiling \
                 point is eighty degrees: scale by four fifths, truncating \
                 toward zero"
            }
            Op::IsFreezing => {
                "whether the reading is at or below the freezing point of \
                 water (the boundary itself counts)"
            }
            Op::IsBoiling => {
                "whether the reading is at or above the boiling point of \
                 water (the boundary itself counts)"
            }
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::IsFreezing | Op::IsBoiling => "bool",
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

/// Fahrenheit: nine fifths (truncating) plus thirty-two.
fn b_to_fahrenheit(c: i64) -> i64 {
    c * 9 / 5 + 32
}

/// Kelvin: fixed offset, pre-2019 convention.
fn b_to_kelvin(c: i64) -> i64 {
    c + 273
}

/// Réaumur: four fifths, truncating toward zero.
fn b_to_reaumur(c: i64) -> i64 {
    c * 4 / 5
}

/// At or below the freezing point; the boundary counts.
fn b_is_freezing(c: i64) -> bool {
    c <= 0
}

/// At or above the boiling point; the boundary counts.
fn b_is_boiling(c: i64) -> bool {
    c >= 100
}

/// The answer shape: converted values as `Num`, predicates as `Flag`.
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

fn op_eval(op: Op, c: i64) -> Out {
    match op {
        Op::ToFahrenheit => Out::Num(b_to_fahrenheit(c)),
        Op::ToKelvin => Out::Num(b_to_kelvin(c)),
        Op::ToReaumur => Out::Num(b_to_reaumur(c)),
        Op::IsFreezing => Out::Flag(b_is_freezing(c)),
        Op::IsBoiling => Out::Flag(b_is_boiling(c)),
    }
}

// ---- canonical reading ------------------------------------------------------

/// The canonical reading: sampled from −60..150 and retried until the
/// anchor facts hold.
///
/// Guaranteed for every seed: strictly between freezing and boiling (so
/// both predicates answer false), far enough from zero that every scaled
/// answer is nonzero, and with the three conversions mutually distinct and
/// none equal to the raw reading — ruling out the −40 equality and the
/// −18 Fahrenheit-zero coincidence. That makes `const-zero` wrong on all
/// three scalars and `kelvin-everything` wrong on the other two; the flags
/// agree with a cheating `false` there and are flipped by worked examples.
fn canonical(seed: u64) -> i64 {
    let mut rng = Rng::new(seed ^ 0x7E3D_51A1);
    for _ in 0..100_000 {
        let c = rng.below(211) as i64 - 60;
        if anchors_hold(c) {
            return c;
        }
    }
    unreachable!("canonical reading sampling failed to satisfy anchors");
}

fn anchors_hold(c: i64) -> bool {
    let f = b_to_fahrenheit(c);
    let k = b_to_kelvin(c);
    let r = b_to_reaumur(c);
    c != 0
        && !b_is_freezing(c)
        && !b_is_boiling(c)
        && f != 0
        && r != 0
        && f != k
        && f != r
        && k != r
        && f != c
        && k != c
        && r != c
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (i64, Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_013E);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical reading first.
    let can = canonical(seed);
    cases.push((can, spec.ops.map(|op| (op, op_eval(op, can))).to_vec()));
    // The famous equality: −40 reads the same on both common scales, and
    // the freezing predicate answers true — flipping any cheating `false`.
    cases.push(((-40), spec.ops.map(|op| (op, op_eval(op, -40))).to_vec()));
    // Zero: pins every convention at once and answers true for freezing.
    cases.push((0, spec.ops.map(|op| (op, op_eval(op, 0))).to_vec()));
    // The boiling anchor: round conversions (two-twelve, three-seventy-three,
    // eighty) and a true boiling predicate.
    cases.push((100, spec.ops.map(|op| (op, op_eval(op, 100))).to_vec()));
    // Body temperature: all three conversions distinct, nonzero, truncated.
    cases.push((37, spec.ops.map(|op| (op, op_eval(op, 37))).to_vec()));
    for _ in 0..3 {
        let c = rng.below(211) as i64 - 60;
        let outs = spec.ops.map(|op| (op, op_eval(op, c))).to_vec();
        cases.push((c, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the suffix types it as `i64`.
fn render_i64(c: i64) -> String {
    format!("{c}i64")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    let sig = format!("(celsius: i64) -> {ret}");
    let body = match op {
        Op::ToFahrenheit => "celsius * 9 / 5 + 32",
        Op::ToKelvin => "celsius + 273",
        Op::ToReaumur => "celsius * 4 / 5",
        Op::IsFreezing => "celsius <= 0",
        Op::IsBoiling => "celsius >= 100",
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(celsius: i64) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(celsius: i64) -> {}", op.name(), op.ret())
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
    for (c, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  celsius {}  ->  {}\n", render_i64(c), results));
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
         one temperature reading `celsius` of type `i64`, typically between \
         minus sixty and one hundred fifty; conversions use plain integer \
         arithmetic, and where a ratio is involved the division truncates \
         toward zero. Threshold predicates include their boundary.\n\
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
    for (i, (c, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let celsius = {};\n",
            render_i64(*c),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "celsius"),
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
            let call = call_src(*op, "celsius");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_013E;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let celsius = (nx(&mut state) % 211) as i64 - 60;\n\
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
            format!("{sig} {{\n    let _ = celsius;\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer the Kelvin offset no matter what was asked.
/// The canonical anchors make the other two conversions differ from it, and
/// the worked examples pin readings where each predicate answers true — so
/// it is exact only on its own op and wrong elsewhere.
fn kelvin_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            if op.ret() == "bool" {
                format!("{sig} {{\n    false\n}}\n")
            } else {
                format!("{sig} {{\n    celsius + 273\n}}\n")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct TempScaleFamily;

impl Generator for TempScaleFamily {
    fn id(&self) -> &str {
        "temp-scale"
    }
    fn category(&self) -> &str {
        "unit-conversion"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("temp-scale", seed);

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
            id: format!("temp-scale/{seed:016x}"),
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
            ("kelvin-everything".to_string(), kelvin_everything(&spec)),
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
        let g = TempScaleFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Conversions, hand-pinned against the truncating formulas.
        assert_eq!(b_to_fahrenheit(0), 32);
        assert_eq!(b_to_fahrenheit(100), 212);
        assert_eq!(b_to_fahrenheit(-40), -40); // the famous equality
        assert_eq!(b_to_fahrenheit(37), 98); // truncated
        assert_eq!(b_to_fahrenheit(1), 33);
        assert_eq!(b_to_kelvin(0), 273);
        assert_eq!(b_to_kelvin(-273), 0); // absolute zero convention
        assert_eq!(b_to_reaumur(100), 80); // the scale's boiling point
        assert_eq!(b_to_reaumur(-1), 0); // truncation toward zero
        assert_eq!(b_to_reaumur(-40), -32);
        // Threshold predicates include their boundaries.
        assert!(b_is_freezing(0));
        assert!(!b_is_freezing(1));
        assert!(b_is_boiling(100));
        assert!(!b_is_boiling(99));
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
        // `const-zero` must fail on every scalar (no zero answers) and
        // `kelvin-everything` on the two non-Kelvin scalars. Both flags
        // answer false mid-range — that agreement is deliberate and is
        // flipped by the pinned freezing/boiling worked examples below.
        for seed in 0..200u64 {
            let c = canonical(seed);
            // Anchor facts the sampler enforces.
            assert_ne!(c, 0, "seed {seed}");
            assert!(!b_is_freezing(c), "seed {seed}");
            assert!(!b_is_boiling(c), "seed {seed}");
            let answers = [b_to_fahrenheit(c), b_to_kelvin(c), b_to_reaumur(c)];
            for v in answers {
                assert_ne!(v, 0, "const-zero survives at celsius {c} seed {seed}");
            }
            // All three conversions mutually distinct...
            assert_ne!(answers[0], answers[1], "seed {seed}");
            assert_ne!(answers[0], answers[2], "seed {seed}");
            assert_ne!(answers[1], answers[2], "seed {seed}");
            // ...and none echoes the raw reading (kills echo cheats).
            for v in answers {
                assert_ne!(v, c, "echo survives at celsius {c} seed {seed}");
            }
            // kelvin-everything is exact only on its own op; the other
            // two conversions must differ from it under the canonical
            // reading.
            let k = answers[1];
            assert_ne!(answers[0], k, "seed {seed}");
            assert_ne!(answers[2], k, "seed {seed}");
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (c, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, c), out, "seed {seed}");
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
            assert!(!sk.contains("* 9"));
            assert!(!sk.contains("/ 5"));
            assert!(!sk.contains("+ 32"));
            assert!(!sk.contains("+ 273"));
            assert!(!sk.contains("* 4"));
            assert!(!sk.contains("<= 0"));
            assert!(!sk.contains(">= 100"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("* 9"));
            assert!(!p.contains("/ 5"));
            assert!(!p.contains("+ 32"));
            assert!(!p.contains("+ 273"));
            assert!(!p.contains("* 4"));
            assert!(!p.contains("<= 0"));
            assert!(!p.contains(">= 100"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every op here is unary: no call site may carry a comma.
        for op in OP_ALL {
            let call = call_src(op, "celsius");
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
        let g = TempScaleFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
