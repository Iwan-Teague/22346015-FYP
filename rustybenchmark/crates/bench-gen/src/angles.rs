//! The `angles` family (category `angular-measure`) — circle arithmetic over
//! a seeded signed degree reading.
//!
//! Where `clock` reasons about two hands on a dial, this family exercises
//! **normalization of an arbitrary reading onto one circle**: folding it
//! into the half-open `[0, 360)` range with Euclidean remainder semantics,
//! counting complete revolutions with floor division (so readings below
//! zero count backwards), looking up the quadrant, measuring the shortest
//! hop to a ninety-degree axis, and detecting exact compass cardinals. The
//! domain is one reading `deg: i64`, sampled from −360 through 720 so both
//! wrap directions and multi-turn readings occur. The seed prunes which two
//! of five query ops are required: `normalized`, `turns`, `quadrant`,
//! `axis_distance`, `is_cardinal`. C(5,2) = **10 distinct skills**, above
//! the diversity floor; op names are semantic.
//!
//! The canonical reading is sampled until its anchor facts hold: off every
//! ninety-degree axis (so the distance answer is nonzero), out of quadrant
//! one (defeating constant-quadrant cheats), not a cardinal, and with all
//! four scalar answers mutually distinct and none echoing the raw reading.
//! That makes `const-zero` wrong on all four scalars there, and
//! `normalized-everything` wrong on the other three; the cardinal flag
//! answers false on the canonical reading — that agreement is deliberate
//! and is flipped by worked examples pinned on exact axes (including
//! negative and multi-turn ones).
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential fuzzes
//! 3000 random readings against the model.
//!
//! Trivial baselines: `const-zero` (fails every scalar outright on the
//! canonical example) and `normalized-everything` (every query answered
//! with the wrapped reading).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    Normalized,
    Turns,
    Quadrant,
    AxisDistance,
    IsCardinal,
}

const OP_ALL: [Op; 5] = [
    Op::Normalized,
    Op::Turns,
    Op::Quadrant,
    Op::AxisDistance,
    Op::IsCardinal,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::Normalized => "normalized",
            Op::Turns => "turns",
            Op::Quadrant => "quadrant",
            Op::AxisDistance => "axis_distance",
            Op::IsCardinal => "is_cardinal",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::Normalized => {
                "the reading folded into the half-open circle from zero \
                 inclusive to three hundred sixty exclusive, where negative \
                 readings wrap forward instead of going negative"
            }
            Op::Turns => {
                "the count of complete full-circle revolutions under floor \
                 semantics, so anything below zero is already one turn short \
                 and never zero"
            }
            Op::Quadrant => {
                "which quadrant of the folded circle the reading opens, \
                 numbered one through four starting at due east and rotating \
                 counter-clockwise; readings exactly on an axis belong to the \
                 quadrant they open"
            }
            Op::AxisDistance => {
                "the shortest hop in degrees to the nearest axis multiple of \
                 ninety, always between zero and forty-five inclusive; the \
                 midpoint between two axes is the farthest a reading can sit"
            }
            Op::IsCardinal => {
                "whether the folded reading lands exactly on a compass \
                 cardinal — north, east, south or west — that is, on a \
                 multiple of ninety degrees"
            }
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::IsCardinal => "bool",
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

/// Fold into `[0, 360)` with Euclidean remainder semantics.
fn b_normalized(deg: i64) -> i64 {
    deg.rem_euclid(360)
}

/// Complete revolutions under floor semantics.
fn b_turns(deg: i64) -> i64 {
    deg.div_euclid(360)
}

/// Quadrant of the folded reading, one through four, axes opening forward.
fn b_quadrant(deg: i64) -> i64 {
    b_normalized(deg) / 90 + 1
}

/// Shortest hop to a ninety-degree axis, in `[0, 45]`.
fn b_axis_distance(deg: i64) -> i64 {
    let n = b_normalized(deg) % 90;
    n.min(90 - n)
}

/// True exactly on a compass cardinal (a multiple of ninety).
fn b_is_cardinal(deg: i64) -> bool {
    (b_normalized(deg) as u64).is_multiple_of(90)
}

/// The answer shape: measures as `Num`, the cardinal predicate as `Flag`.
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

fn op_eval(op: Op, deg: i64) -> Out {
    match op {
        Op::Normalized => Out::Num(b_normalized(deg)),
        Op::Turns => Out::Num(b_turns(deg)),
        Op::Quadrant => Out::Num(b_quadrant(deg)),
        Op::AxisDistance => Out::Num(b_axis_distance(deg)),
        Op::IsCardinal => Out::Flag(b_is_cardinal(deg)),
    }
}

// ---- canonical reading ------------------------------------------------------

/// The canonical reading: sampled from −360..=720 and retried until the
/// anchor facts hold.
///
/// Guaranteed for every seed: off every axis (nonzero distance answer), out
/// of quadrant one, not a cardinal, and with all four scalar answers
/// mutually distinct and none equal to the raw reading. That makes
/// `const-zero` wrong on all four scalars and `normalized-everything` wrong
/// on the other three; the cardinal flag agrees with a cheating `false`
/// there and is flipped by worked examples pinned on exact axes.
fn canonical(seed: u64) -> i64 {
    let mut rng = Rng::new(seed ^ 0xA46E_11A1);
    for _ in 0..100_000 {
        let deg = rng.below(1081) as i64 - 360;
        if anchors_hold(deg) {
            return deg;
        }
    }
    unreachable!("canonical reading sampling failed to satisfy anchors");
}

fn anchors_hold(deg: i64) -> bool {
    if b_is_cardinal(deg) {
        return false;
    }
    let nd = b_normalized(deg);
    let tn = b_turns(deg);
    let q = b_quadrant(deg);
    let ad = b_axis_distance(deg);
    // Off-axis keeps every scalar away from zero and defeats const-zero.
    if ad == 0 {
        return false;
    }
    // Out of quadrant one defeats constant-quadrant cheats anchored there.
    if q == 1 {
        return false;
    }
    let scalars = [nd, tn, q, ad];
    for i in 0..scalars.len() {
        if scalars[i] == deg {
            return false;
        }
        for j in (i + 1)..scalars.len() {
            if scalars[i] == scalars[j] {
                return false;
            }
        }
    }
    true
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (i64, Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_0146);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical reading first.
    let can = canonical(seed);
    cases.push((can, spec.ops.map(|op| (op, op_eval(op, can))).to_vec()));
    // Zero: pins every convention at once — folded to zero, zero turns,
    // quadrant one, on-axis, and a true cardinal predicate flipping any
    // cheating `false`.
    cases.push((0, spec.ops.map(|op| (op, op_eval(op, 0))).to_vec()));
    // A positive axis reading one quarter turn along.
    cases.push((90, spec.ops.map(|op| (op, op_eval(op, 90))).to_vec()));
    // Negative readings wrap forward and count backwards by turns.
    cases.push((-10, spec.ops.map(|op| (op, op_eval(op, -10))).to_vec()));
    // Multi-turn readings collapse onto one circle but keep the turn count.
    cases.push((720, spec.ops.map(|op| (op, op_eval(op, 720))).to_vec()));
    for _ in 0..3 {
        let deg = rng.below(1081) as i64 - 360;
        let outs = spec.ops.map(|op| (op, op_eval(op, deg))).to_vec();
        cases.push((deg, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the suffix types it as `i64`.
fn render_i64(deg: i64) -> String {
    format!("{deg}i64")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    let sig = format!("(deg: i64) -> {ret}");
    let body = match op {
        Op::Normalized => "deg.rem_euclid(360)".to_string(),
        Op::Turns => "deg.div_euclid(360)".to_string(),
        Op::Quadrant => "deg.rem_euclid(360) / 90 + 1".to_string(),
        Op::AxisDistance => ["let n = deg.rem_euclid(360) % 90;", "n.min(90 - n)"].join("\n    "),
        Op::IsCardinal => "(deg.rem_euclid(360) as u64).is_multiple_of(90)".to_string(),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(deg: i64) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(deg: i64) -> {}", op.name(), op.ret())
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
    for (deg, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  deg {}  ->  {}\n", render_i64(deg), results));
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
         one angle reading `deg` of type `i64`; it may be negative or larger \
         than a full circle, so fold it onto one circle before answering. \
         Folding uses Euclidean remainder semantics: negatives wrap forward \
         into the half-open circle from zero inclusive to three hundred \
         sixty exclusive. Turn counts use floor division, so anything below \
         zero is already one turn short. Axis readings belong to the \
         quadrant they open, and the cardinal predicate includes every \
         exact multiple of ninety.\n\
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
    for (i, (deg, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let deg = {};\n",
            render_i64(*deg),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "deg"),
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
            let call = call_src(*op, "deg");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0146;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let deg = (nx(&mut state) % 1081) as i64 - 360;\n\
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
            format!("{sig} {{\n    let _ = deg;\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer the folded reading no matter what was asked.
/// The canonical anchors make the other three measures differ from it, and
/// the worked examples pin readings where the cardinal predicate answers
/// true — so it is exact only on its own op and wrong elsewhere.
fn normalized_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            if op.ret() == "bool" {
                format!("{sig} {{\n    false\n}}\n")
            } else {
                format!("{sig} {{\n    deg.rem_euclid(360)\n}}\n")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct AngleFamily;

impl Generator for AngleFamily {
    fn id(&self) -> &str {
        "angles"
    }
    fn category(&self) -> &str {
        "angular-measure"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("angles", seed);

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
            id: format!("angles/{seed:016x}"),
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
            (
                "normalized-everything".to_string(),
                normalized_everything(&spec),
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
        let g = AngleFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Folding wraps negatives forward and collapses multi-turn readings.
        assert_eq!(b_normalized(0), 0);
        assert_eq!(b_normalized(725), 5);
        assert_eq!(b_normalized(360), 0);
        assert_eq!(b_normalized(-1), 359);
        assert_eq!(b_normalized(-370), 350);
        // Turn counts use floor semantics: below zero is one turn short.
        assert_eq!(b_turns(359), 0);
        assert_eq!(b_turns(360), 1);
        assert_eq!(b_turns(-1), -1);
        assert_eq!(b_turns(-361), -2);
        assert_eq!(b_turns(725), 2);
        // Quadrants number one through four; axes open forward.
        assert_eq!(b_quadrant(45), 1);
        assert_eq!(b_quadrant(89), 1);
        assert_eq!(b_quadrant(90), 2);
        assert_eq!(b_quadrant(180), 3);
        assert_eq!(b_quadrant(270), 4);
        assert_eq!(b_quadrant(-10), 4); // folded to 350
                                        // Distance folds across the axis and saturates at the midpoint.
        assert_eq!(b_axis_distance(90), 0);
        assert_eq!(b_axis_distance(45), 45);
        assert_eq!(b_axis_distance(44), 44);
        assert_eq!(b_axis_distance(46), 44);
        assert_eq!(b_axis_distance(-10), 10); // 350: 80 vs 10
        assert_eq!(b_axis_distance(725), 5);
        // Cardinals sit exactly on multiples of ninety after folding.
        for deg in [0, 90, -90, 720] {
            assert!(b_is_cardinal(deg), "{deg} should be cardinal");
        }
        for deg in [45, 91, -10] {
            assert!(!b_is_cardinal(deg), "{deg} should not be cardinal");
        }
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
        // `normalized-everything` on the three non-fold scalars. The
        // cardinal flag answers false on the canonical reading — that
        // agreement is deliberate and is flipped by the pinned axis
        // worked examples (0, 90 and 720 all answer true).
        for seed in 0..200u64 {
            let deg = canonical(seed);
            // Anchor facts the sampler enforces.
            assert!(!b_is_cardinal(deg), "seed {seed}");
            assert_ne!(b_axis_distance(deg), 0, "seed {seed}");
            assert_ne!(b_quadrant(deg), 1, "seed {seed}");
            let answers = [
                b_normalized(deg),
                b_turns(deg),
                b_quadrant(deg),
                b_axis_distance(deg),
            ];
            for v in answers {
                assert_ne!(v, 0, "const-zero survives at deg {deg} seed {seed}");
            }
            // All four measures mutually distinct...
            for i in 0..answers.len() {
                for j in (i + 1)..answers.len() {
                    assert_ne!(answers[i], answers[j], "seed {seed}");
                }
            }
            // ...and none echoes the raw reading (kills echo cheats).
            for v in answers {
                assert_ne!(v, deg, "echo survives at deg {deg} seed {seed}");
            }
            // normalized-everything is exact only on its own op; the other
            // three measures must differ from it under the canonical
            // reading.
            let nd = answers[0];
            for v in &answers[1..] {
                assert_ne!(*v, nd, "seed {seed}");
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (deg, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, deg), out, "seed {seed}");
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
            assert!(!sk.contains("rem_euclid"));
            assert!(!sk.contains("div_euclid"));
            assert!(!sk.contains("% 360"));
            assert!(!sk.contains("/ 90"));
            assert!(!sk.contains("% 90"));
            assert!(!sk.contains(".min("));
            assert!(!sk.contains("is_multiple_of"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("rem_euclid"));
            assert!(!p.contains("div_euclid"));
            assert!(!p.contains("% 360"));
            assert!(!p.contains("/ 90"));
            assert!(!p.contains("% 90"));
            assert!(!p.contains(".min("));
            assert!(!p.contains("is_multiple_of"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every op here is unary: no call site may carry a comma.
        for op in OP_ALL {
            let call = call_src(op, "deg");
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
        let g = AngleFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
