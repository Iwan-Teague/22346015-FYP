//! The `collatz` family (category `integer-orbits`) — trajectory queries
//! over the Collatz orbit of a seeded start value.
//!
//! Where `gcd` inspects one arithmetic pair and `digits` decomposes one
//! decimal representation, this family exercises **orbit dynamics**: the
//! map `n → n/2` when even, `n → 3n + 1` when odd, walked until it reaches
//! `1`. The domain is one positive `u64` start; every op is a pure function
//! of that walk. The seed prunes which two of five query ops are required:
//! `steps_to_one`, `max_value`, `num_even_steps`, `num_odd_steps`,
//! `peak_ratio`. C(5,2) = **10 distinct skills**, above the diversity
//! floor; op names are semantic.
//!
//! The canonical start is sampled until its anchor facts hold: a real
//! orbit (more than one step) visiting at least one even and one odd
//! value, whose stopping time disagrees with every other answer. Those
//! make every op separate from `const-zero` outright and keep the
//! `steps-everything` cheat exact only on `steps_to_one` itself, so any
//! pair containing it is caught by its partner.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random starts against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the
//! canonical start) and `steps-everything` (every query answered with the
//! stopping time).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    StepsToOne,
    MaxValue,
    NumEvenSteps,
    NumOddSteps,
    PeakRatio,
}

const OP_ALL: [Op; 5] = [
    Op::StepsToOne,
    Op::MaxValue,
    Op::NumEvenSteps,
    Op::NumOddSteps,
    Op::PeakRatio,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::StepsToOne => "steps_to_one",
            Op::MaxValue => "max_value",
            Op::NumEvenSteps => "num_even_steps",
            Op::NumOddSteps => "num_odd_steps",
            Op::PeakRatio => "peak_ratio",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::StepsToOne => {
                "the stopping time: how many applications of the map it \
                 takes to reach 1; a start of 1 takes none"
            }
            Op::MaxValue => {
                "the largest value visited along the orbit, counting the \
                 start itself"
            }
            Op::NumEvenSteps => {
                "how many even values the orbit visits before reaching 1 \
                 (the start included)"
            }
            Op::NumOddSteps => {
                "how many odd values the orbit visits before reaching 1 \
                 (the terminal 1 itself is not counted)"
            }
            Op::PeakRatio => {
                "the peak overshoot: the largest visited value divided by \
                 the start, using integer division"
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

fn advance(n: u64) -> u64 {
    if n.is_multiple_of(2) {
        n / 2
    } else {
        n.saturating_mul(3).saturating_add(1)
    }
}

fn b_steps_to_one(start: u64) -> u64 {
    let mut n = start;
    let mut steps = 0u64;
    while n > 1 {
        n = advance(n);
        steps += 1;
    }
    steps
}

fn b_max_value(start: u64) -> u64 {
    let mut n = start;
    let mut peak = n;
    while n > 1 {
        n = advance(n);
        if n > peak {
            peak = n;
        }
    }
    peak
}

fn b_num_even_steps(start: u64) -> u64 {
    let mut n = start;
    let mut evens = 0u64;
    while n > 1 {
        if n.is_multiple_of(2) {
            evens += 1;
        }
        n = advance(n);
    }
    evens
}

fn b_num_odd_steps(start: u64) -> u64 {
    let mut n = start;
    let mut odds = 0u64;
    while n > 1 {
        if !n.is_multiple_of(2) {
            odds += 1;
        }
        n = advance(n);
    }
    odds
}

fn b_peak_ratio(start: u64) -> u64 {
    b_max_value(start) / start
}

/// Every op here answers with a `u64`.
type Out = u64;

fn op_eval(op: Op, start: u64) -> Out {
    match op {
        Op::StepsToOne => b_steps_to_one(start),
        Op::MaxValue => b_max_value(start),
        Op::NumEvenSteps => b_num_even_steps(start),
        Op::NumOddSteps => b_num_odd_steps(start),
        Op::PeakRatio => b_peak_ratio(start),
    }
}

// ---- canonical start --------------------------------------------------------

/// The canonical start: a value below one million, retried until the
/// anchor facts hold.
///
/// Guaranteed for every seed: a genuine multi-step orbit touching even and
/// odd values alike, and a stopping time distinct from every other answer.
/// Together those make every op separate from `const-zero` outright and
/// keep `steps-everything` inexact everywhere except its own op.
fn canonical(seed: u64) -> u64 {
    let mut rng = Rng::new(seed ^ 0xC01A_77A1);
    for _ in 0..100_000 {
        let cand = rng.below(1_000_000);
        if anchors_hold(cand) {
            return cand;
        }
    }
    unreachable!("canonical start sampling failed to satisfy anchors");
}

fn anchors_hold(start: u64) -> bool {
    start > 1
        && b_num_even_steps(start) >= 1
        && b_num_odd_steps(start) >= 1
        && b_steps_to_one(start) != b_max_value(start)
        && b_steps_to_one(start) != b_num_even_steps(start)
        && b_steps_to_one(start) != b_num_odd_steps(start)
        && b_steps_to_one(start) != b_peak_ratio(start)
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (u64, Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_010E);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical start first.
    let can = canonical(seed);
    cases.push((can, spec.ops.map(|op| (op, op_eval(op, can))).to_vec()));
    // Terminal start: pins every zero convention at once.
    cases.push((1, spec.ops.map(|op| (op, op_eval(op, 1))).to_vec()));
    // Power of two: pure halving, so no odd stops and no overshoot.
    cases.push((1024, spec.ops.map(|op| (op, op_eval(op, 1024))).to_vec()));
    // The famous long orbit from 27 (111 steps, peaking at 9232).
    cases.push((27, spec.ops.map(|op| (op, op_eval(op, 27))).to_vec()));
    for _ in 0..3 {
        // The domain is a positive start, and `peak_ratio` divides by it, so a
        // draw of 0 is remapped to 1_000_000 rather than resampled: a resample
        // would shift the rng stream and change the prompt of every seed after
        // it, while this touches only the seeds whose generation used to panic.
        let v = match rng.below(1_000_000) {
            0 => 1_000_000,
            v => v,
        };
        let outs = spec.ops.map(|op| (op, op_eval(op, v))).to_vec();
        cases.push((v, outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; a bare integer infers `u64` from the
/// function signature.
fn render_u64(start: u64) -> String {
    start.to_string()
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let sig = "(start: u64) -> u64";
    let body = match op {
        Op::StepsToOne => [
            "let mut n = start;",
            "let mut steps = 0u64;",
            "while n > 1 {",
            "    if n % 2 == 0 {",
            "        n /= 2;",
            "    } else {",
            "        n = n * 3 + 1;",
            "    }",
            "    steps += 1;",
            "}",
            "steps",
        ]
        .join("\n    "),
        Op::MaxValue => [
            "let mut n = start;",
            "let mut peak = start;",
            "while n > 1 {",
            "    if n % 2 == 0 {",
            "        n /= 2;",
            "    } else {",
            "        n = n * 3 + 1;",
            "    }",
            "    if n > peak {",
            "        peak = n;",
            "    }",
            "}",
            "peak",
        ]
        .join("\n    "),
        Op::NumEvenSteps => [
            "let mut n = start;",
            "let mut evens = 0u64;",
            "while n > 1 {",
            "    if n % 2 == 0 {",
            "        evens += 1;",
            "        n /= 2;",
            "    } else {",
            "        n = n * 3 + 1;",
            "    }",
            "}",
            "evens",
        ]
        .join("\n    "),
        Op::NumOddSteps => [
            "let mut n = start;",
            "let mut odds = 0u64;",
            "while n > 1 {",
            "    if n % 2 == 0 {",
            "        n /= 2;",
            "    } else {",
            "        odds += 1;",
            "        n = n * 3 + 1;",
            "    }",
            "}",
            "odds",
        ]
        .join("\n    "),
        Op::PeakRatio => [
            "let mut n = start;",
            "let mut peak = start;",
            "while n > 1 {",
            "    if n % 2 == 0 {",
            "        n /= 2;",
            "    } else {",
            "        n = n * 3 + 1;",
            "    }",
            "    if n > peak {",
            "        peak = n;",
            "    }",
            "}",
            "peak / start",
        ]
        .join("\n    "),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(start: u64) -> u64 {{\n    todo!()\n}}\n",
        op.name()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(start: u64) -> u64", op.name())
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
    for (start, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  start {}  ->  {}\n", render_u64(start), results));
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
         given as `start`, a positive integer of type `u64`; each query \
         walks its Collatz orbit (halving on even values, otherwise \
         tripling and adding one) until it reaches 1.\n\
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
    for (i, (start, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let start = {}u64;\n",
            render_u64(*start),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "start"),
                out,
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
            let call = call_src(*op, "start");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0110;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let start = (nx(&mut state) % 1000) + 1;\n\
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

/// Degenerate: everything zero.
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            format!("{sig} {{\n    let _ = start;\n    0\n}}\n", sig = sig,)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer the stopping time no matter what was
/// asked. The canonical anchors make every other answer disagree with it;
/// `steps_to_one` itself is exact, and any pair containing it is caught by
/// its partner.
fn steps_everything(spec: &Spec) -> String {
    let walk_body = [
        "let mut n = start;",
        "let mut steps = 0u64;",
        "while n > 1 {",
        "    if n % 2 == 0 {",
        "        n /= 2;",
        "    } else {",
        "        n = n * 3 + 1;",
        "    }",
        "    steps += 1;",
        "}",
        "steps",
    ]
    .join("\n    ");
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            format!("{sig} {{\n    {walk_body}\n}}\n", sig = sig,)
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct CollatzFamily;

impl Generator for CollatzFamily {
    fn id(&self) -> &str {
        "collatz"
    }
    fn category(&self) -> &str {
        "integer-orbits"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("collatz", seed);

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
            id: format!("collatz/{seed:016x}"),
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
            ("steps-everything".to_string(), steps_everything(&spec)),
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
        let g = CollatzFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Stopping times.
        assert_eq!(b_steps_to_one(1), 0);
        assert_eq!(b_steps_to_one(2), 1);
        assert_eq!(b_steps_to_one(6), 8);
        assert_eq!(b_steps_to_one(27), 111);
        // Peaks along the orbit.
        assert_eq!(b_max_value(1), 1);
        assert_eq!(b_max_value(6), 16);
        assert_eq!(b_max_value(7), 52);
        // Even/odd partition of the visited values.
        assert_eq!(b_num_even_steps(6), 6);
        assert_eq!(b_num_even_steps(27), 70);
        assert_eq!(b_num_odd_steps(3), 2);
        assert_eq!(b_num_odd_steps(27), 41);
        for start in [6u64, 7, 27, 97] {
            assert_eq!(
                b_num_even_steps(start) + b_num_odd_steps(start),
                b_steps_to_one(start),
                "start {start}"
            );
        }
        // Peak overshoot in integer division.
        assert_eq!(b_peak_ratio(8), 1);
        assert_eq!(b_peak_ratio(7), 7);
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
        // canonical start nonzero on all five answers and the stopping
        // time distinct from each of them, so neither `const-zero` nor
        // `steps-everything` is exact anywhere on it — no skips needed.
        for seed in 0..200u64 {
            let s = canonical(seed);
            // Anchor facts the sampler enforces.
            assert!(s > 1, "seed {seed}");
            assert!(b_num_even_steps(s) >= 1, "seed {seed}");
            assert!(b_num_odd_steps(s) >= 1, "seed {seed}");
            for op in OP_ALL {
                let truth = op_eval(op, s);
                assert_ne!(truth, 0, "const-zero survives {op:?} seed {seed}");
                if matches!(op, Op::StepsToOne) {
                    continue;
                }
                assert_ne!(
                    truth,
                    b_steps_to_one(s),
                    "steps-everything survives {op:?} seed {seed}"
                );
            }
        }
    }

    #[test]
    fn generate_survives_a_zero_example_draw() {
        // This seed's worked-example rng drew 0, which reached `peak_ratio`
        // as a divisor and panicked generate(). Found by sweeping 200k seeds
        // per family; reference_code() alone never builds the examples.
        let seed = 16_402_579_194_654_151_462u64;
        let spec = sample(seed);
        for (start, _) in worked_examples(&spec, seed) {
            assert!(start >= 1, "worked example start {start}");
        }
        CollatzFamily.generate(seed);
    }

    #[test]
    fn worked_example_starts_are_positive() {
        for seed in 0..20_000u64 {
            let spec = sample(seed);
            for (start, _) in worked_examples(&spec, seed) {
                assert!(start >= 1, "seed {seed} start {start}");
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (start, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, start), out, "seed {seed}");
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
            // The walk itself is the answer: its modulo test and update
            // rule must stay out of the skeleton AND the prompt.
            assert!(!sk.contains("%"));
            assert!(!sk.contains("* 3"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("%"));
            assert!(!p.contains("* 3"));
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
            let call = call_src(op, "start");
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
        let g = CollatzFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
