//! The `clock` family (category `clock-arithmetic`) — arithmetic over
//! one seeded wall-clock reading.
//!
//! Where `datecalc` reasons about calendar days, this family measures a
//! single instant on an analogue face: minutes elapsed since midnight,
//! which half of the day the reading falls in, where the two hands
//! point, and how far apart they sit. The domain is one `(hour,
//! minute)` pair in 24-hour form (`hour < 24`, `minute < 60`); every
//! op is a pure function of the pair. The seed prunes which two of five
//! query ops are required: `minutes_since_midnight`, `is_afternoon`,
//! `hour_angle`, `minute_angle`, `hands_separation`. C(5,2) = **10
//! distinct skills**, above the diversity floor; op names are semantic.
//!
//! The canonical reading is sampled until every scalar answer is
//! nonzero, stays away from the raw minute value, and lands in the
//! afternoon half — so `const-zero` fails everywhere and the
//! `minute-everything` cheat (every query answered with the minute
//! itself, flags answered false) is exact nowhere.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random readings against the model.
//!
//! Trivial baselines: `const-zero` (fails outright on the canonical
//! reading) and `minute-everything` (every query answered with the
//! minute component).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    MinutesSinceMidnight,
    IsAfternoon,
    HourAngle,
    MinuteAngle,
    HandsSeparation,
}

const OP_ALL: [Op; 5] = [
    Op::MinutesSinceMidnight,
    Op::IsAfternoon,
    Op::HourAngle,
    Op::MinuteAngle,
    Op::HandsSeparation,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::MinutesSinceMidnight => "minutes_since_midnight",
            Op::IsAfternoon => "is_afternoon",
            Op::HourAngle => "hour_angle",
            Op::MinuteAngle => "minute_angle",
            Op::HandsSeparation => "hands_separation",
        }
    }

    /// The required return type.
    fn ret(self) -> &'static str {
        match self {
            Op::IsAfternoon => "bool",
            _ => "i64",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::MinutesSinceMidnight => "how many minutes have elapsed since midnight",
            Op::IsAfternoon => {
                "whether the reading falls in the afternoon half of \
                 the day (from noon onward)"
            }
            Op::HourAngle => {
                "the clock-face angle of the hour hand in whole \
                 degrees, counting partway through the current hour"
            }
            Op::MinuteAngle => {
                "the clock-face angle of the minute hand in whole \
                 degrees"
            }
            Op::HandsSeparation => {
                "the smaller angle between the two hands in whole \
                 degrees, folding around the dial"
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

fn b_minutes_since_midnight(hour: u32, minute: u32) -> i64 {
    (hour * 60 + minute) as i64
}

fn b_is_afternoon(hour: u32, minute: u32) -> bool {
    let _ = minute;
    hour >= 12
}

fn b_hour_angle(hour: u32, minute: u32) -> i64 {
    ((hour % 12) * 30 + minute / 2) as i64
}

fn b_minute_angle(hour: u32, minute: u32) -> i64 {
    let _ = hour;
    (minute * 6) as i64
}

fn b_hands_separation(hour: u32, minute: u32) -> i64 {
    let h = b_hour_angle(hour, minute);
    let m = b_minute_angle(hour, minute);
    let diff = h.abs_diff(m);
    diff.min(360 - diff) as i64
}

/// One op's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Flag(bool),
}

impl Out {
    /// The literal this answer renders as at an emitted call site.
    fn lit(&self) -> String {
        match self {
            Out::Num(n) => n.to_string(),
            Out::Flag(b) => b.to_string(),
        }
    }
}

fn op_eval(op: Op, hour: u32, minute: u32) -> Out {
    match op {
        Op::MinutesSinceMidnight => Out::Num(b_minutes_since_midnight(hour, minute)),
        Op::IsAfternoon => Out::Flag(b_is_afternoon(hour, minute)),
        Op::HourAngle => Out::Num(b_hour_angle(hour, minute)),
        Op::MinuteAngle => Out::Num(b_minute_angle(hour, minute)),
        Op::HandsSeparation => Out::Num(b_hands_separation(hour, minute)),
    }
}

// ---- canonical input --------------------------------------------------------

const CANONICAL_SEED: u64 = 0xC10C_4A11;

/// The canonical reading: sampled until every scalar answer is nonzero,
/// stays away from the raw minute value, and the afternoon flag is
/// true — `const-zero` fails everywhere and `minute-everything` is
/// exact nowhere.
fn canonical(seed: u64) -> (u32, u32) {
    let mut rng = Rng::new(seed ^ CANONICAL_SEED);
    for _ in 0..100_000 {
        let hour = rng.below(24) as u32;
        let minute = rng.below(60) as u32;
        if anchors_hold(hour, minute) {
            return (hour, minute);
        }
    }
    unreachable!("canonical input sampling failed to satisfy anchors");
}

fn anchors_hold(hour: u32, minute: u32) -> bool {
    let msm = b_minutes_since_midnight(hour, minute);
    let ha = b_hour_angle(hour, minute);
    let ma = b_minute_angle(hour, minute);
    let sep = b_hands_separation(hour, minute);
    b_is_afternoon(hour, minute)
        && msm != 0
        && ha != 0
        && ma != 0
        && sep != 0
        && msm != minute as i64
        && ha != minute as i64
        && sep != minute as i64
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = ((u32, u32), Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0136;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    let push = |cases: &mut Vec<ExampleCase>, hour: u32, minute: u32| {
        cases.push((
            (hour, minute),
            spec.ops.map(|op| (op, op_eval(op, hour, minute))).to_vec(),
        ));
    };
    // Canonical reading first.
    let (ch, cm) = canonical(seed);
    push(&mut cases, ch, cm);
    // Midnight: zero conventions everywhere; afternoon flag false.
    push(&mut cases, 0, 0);
    // Noon: boundary of the afternoon half.
    push(&mut cases, 12, 0);
    // Last minute of the day.
    push(&mut cases, 23, 59);
    for _ in 0..3 {
        let h = rng.below(24) as u32;
        let m = rng.below(60) as u32;
        push(&mut cases, h, m);
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a reading: a tuple with only the first element
/// suffix-typed so inference types the rest.
fn render_pair(hour: u32, minute: u32) -> String {
    format!("({}u32, {})", hour, minute)
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let sig = format!("(hour: u32, minute: u32) -> {}", op.ret());
    let body = match op {
        Op::MinutesSinceMidnight => "(hour * 60 + minute) as i64".to_string(),
        Op::IsAfternoon => "hour >= 12".to_string(),
        Op::HourAngle => "((hour % 12) * 30 + minute / 2) as i64".to_string(),
        Op::MinuteAngle => "(minute * 6) as i64".to_string(),
        Op::HandsSeparation => [
            "let h = ((hour % 12) * 30 + minute / 2) as i64;",
            "let m = (minute * 6) as i64;",
            "let diff = h.abs_diff(m);",
            "diff.min(360 - diff) as i64",
        ]
        .join("\n    "),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(hour: u32, minute: u32) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!(
        "pub fn {}(hour: u32, minute: u32) -> {}",
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
    for ((hour, minute), outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  time {}  ->  {}\n",
            render_pair(hour, minute),
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
         one wall-clock reading in 24-hour form: an hour and a minute. \
         Queries are arithmetic facts about that instant or about the \
         positions of the two hands of an analogue clock face.\n\
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
    for (i, ((hour, minute), outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let (hour, minute) = {};\n",
            render_pair(*hour, *minute),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "hour, minute"),
                out.lit()
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
            let call = call_src(*op, "hour, minute");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0136;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let hour = (nx(&mut state) % 24) as u32;\n\
         \x20       let minute = (nx(&mut state) % 60) as u32;\n\
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
/// Degenerate: everything zero / false.
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            let answer = match op.ret() {
                "bool" => "false",
                _ => "0",
            };
            format!("{sig} {{\n    let _ = (hour, minute);\n    {answer}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every query with the minute component
/// itself; flags answered false. The canonical anchors keep every
/// scalar away from that value and pin the flag true, so this is
/// exact nowhere.
fn minute_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            let answer = match op.ret() {
                "bool" => "false",
                _ => "minute as i64",
            };
            format!("{sig} {{\n    {answer}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct ClockFamily;

impl Generator for ClockFamily {
    fn id(&self) -> &str {
        "clock"
    }
    fn category(&self) -> &str {
        "clock-arithmetic"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("clock", seed);

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
            id: format!("clock/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure integer clock bookkeeping — no unsafe anywhere near it.
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
            ("minute-everything".to_string(), minute_everything(&spec)),
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
        let g = ClockFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Positional minutes.
        assert_eq!(b_minutes_since_midnight(0, 0), 0);
        assert_eq!(b_minutes_since_midnight(1, 30), 90);
        assert_eq!(b_minutes_since_midnight(23, 59), 1439);
        // Afternoon splits at noon, inclusive.
        assert!(!b_is_afternoon(11, 59));
        assert!(b_is_afternoon(12, 0));
        // Hour hand: thirty degrees per hour plus half a degree per minute.
        assert_eq!(b_hour_angle(3, 0), 90);
        assert_eq!(b_hour_angle(15, 0), 90);
        assert_eq!(b_hour_angle(3, 30), 105);
        // Minute hand: six degrees per minute, hour-blind.
        assert_eq!(b_minute_angle(4, 15), 90);
        assert_eq!(b_minute_angle(9, 59), 354);
        // Separation folds around the dial.
        assert_eq!(b_hands_separation(6, 0), 180);
        assert_eq!(b_hands_separation(9, 0), 90);
        assert_eq!(b_hands_separation(12, 0), 0);
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
        // Both baselines must fail under EVERY pair. On the canonical
        // reading the afternoon flag is true and every scalar is
        // nonzero and away from the minute value: `const-zero`
        // separates everywhere (flag checked separately) and
        // `minute-everything` is exact nowhere — no skips.
        for seed in 0..200u64 {
            let (hour, minute) = canonical(seed);
            assert!(b_is_afternoon(hour, minute), "flag seed {seed}");
            for op in OP_ALL {
                match op_eval(op, hour, minute) {
                    Out::Flag(_) => {}
                    Out::Num(n) => {
                        assert_ne!(n, 0, "const-zero survives {op:?} seed {seed}");
                        assert_ne!(n, minute as i64, "minute-cheat survives {op:?} seed {seed}");
                    }
                }
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for ((hour, minute), outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    let truth = op_eval(op, hour, minute);
                    assert_eq!(truth.lit(), out.lit(), "seed {seed}");
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
            assert!(!sk.contains("% 12"));
            assert!(!sk.contains("* 60"));
            assert!(!sk.contains("* 6"));
            assert!(!sk.contains("abs_diff"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("% 12"));
            assert!(!p.contains("* 60"));
            assert!(!p.contains("* 6"));
            assert!(!p.contains("abs_diff"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every call site passes exactly two arguments — one comma —
        // matching the parameter list of its signature.
        for op in OP_ALL {
            let call = call_src(op, "hour, minute");
            let sig = op_sig_src(op);
            let params = sig.split("->").next().unwrap();
            assert_eq!(
                call.matches(',').count(),
                params.matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{sig}`"
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = ClockFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
