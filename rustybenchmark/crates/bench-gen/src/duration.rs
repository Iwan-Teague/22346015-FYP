//! The `duration` family (category `time-decomposition`) — aggregate
//! spans and wall-clock components of one duration in seconds.
//!
//! The domain is one non-negative count of seconds that may exceed a
//! full day. The seed prunes which two of five query ops are required:
//! `total_minutes`, `total_hours`, `hours_part`, `minutes_part`,
//! `seconds_part`. C(5,2) = **10 distinct skills**, above the diversity
//! floor; op names are semantic.
//!
//! The two "part" ops are the family's trap: the hour hand wraps at the
//! day boundary and the minute hand resets on the hour, so answering
//! with the aggregate totals mis-reads every input past one hour. The
//! canonical duration is sampled until every answer is nonzero and the
//! five answers stay mutually distinct, which makes `const-zero` fail
//! everywhere and the `minutes-everything` cheat (every query answered
//! with the whole-minute span) exact only on its own op.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random durations against the model.
//!
//! Trivial baselines: `const-zero` (fails outright on the canonical
//! duration) and `minutes-everything`.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    TotalMinutes,
    TotalHours,
    HoursPart,
    MinutesPart,
    SecondsPart,
}

const OP_ALL: [Op; 5] = [
    Op::TotalMinutes,
    Op::TotalHours,
    Op::HoursPart,
    Op::MinutesPart,
    Op::SecondsPart,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::TotalMinutes => "total_minutes",
            Op::TotalHours => "total_hours",
            Op::HoursPart => "hours_part",
            Op::MinutesPart => "minutes_part",
            Op::SecondsPart => "seconds_part",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::TotalMinutes => "how many whole minutes the duration spans",
            Op::TotalHours => "how many whole hours the duration spans",
            Op::HoursPart => {
                "the hour hand of the wall clock the duration ends \
                 on (it wraps back to zero each day)"
            }
            Op::MinutesPart => {
                "the minute hand of the wall clock the duration \
                 ends on (it resets on every hour)"
            }
            Op::SecondsPart => {
                "the second hand of the wall clock the duration \
                 ends on (it resets on every minute)"
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

fn b_total_minutes(seconds: u64) -> i64 {
    (seconds / 60) as i64
}

fn b_total_hours(seconds: u64) -> i64 {
    (seconds / 3_600) as i64
}

fn b_hours_part(seconds: u64) -> i64 {
    ((seconds / 3_600) % 24) as i64
}

fn b_minutes_part(seconds: u64) -> i64 {
    ((seconds % 3_600) / 60) as i64
}

fn b_seconds_part(seconds: u64) -> i64 {
    (seconds % 60) as i64
}

/// One op's answer. All five ops return scalars here, so `Out` is a
/// plain alias — no flag variant needed.
type Out = i64;

fn op_eval(op: Op, seconds: u64) -> Out {
    match op {
        Op::TotalMinutes => b_total_minutes(seconds),
        Op::TotalHours => b_total_hours(seconds),
        Op::HoursPart => b_hours_part(seconds),
        Op::MinutesPart => b_minutes_part(seconds),
        Op::SecondsPart => b_seconds_part(seconds),
    }
}

// ---- canonical input --------------------------------------------------------

fn rand_duration(rng: &mut Rng) -> u64 {
    rng.below(1_000_000)
}

const CANONICAL_SEED: u64 = 0xD3A7_1A11;

/// The canonical duration: sampled until every answer is nonzero and
/// the five answers stay mutually distinct. Durations of at least one
/// full day also keep the aggregate totals away from the small hand
/// values (the hour total reaches twenty-four while the hour hand
/// never passes twenty-three), and every answer stays far below the
/// duration itself — so `const-zero`, `minutes-everything` and
/// echo-the-input are all separated by construction.
fn canonical(seed: u64) -> u64 {
    let mut rng = Rng::new(seed ^ CANONICAL_SEED);
    for _ in 0..100_000 {
        let seconds = rand_duration(&mut rng);
        if anchors_hold(seconds) {
            return seconds;
        }
    }
    unreachable!("canonical input sampling failed to satisfy anchors");
}

fn anchors_hold(seconds: u64) -> bool {
    let answers = [
        b_total_minutes(seconds),
        b_total_hours(seconds),
        b_hours_part(seconds),
        b_minutes_part(seconds),
        b_seconds_part(seconds),
    ];
    seconds >= 86_400 && answers.iter().all(|&a| a != 0) && {
        for i in 0..answers.len() {
            for j in (i + 1)..answers.len() {
                if answers[i] == answers[j] {
                    return false;
                }
            }
        }
        true
    }
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (u64, Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0142;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    let push = |cases: &mut Vec<ExampleCase>, seconds: u64| {
        cases.push((
            seconds,
            spec.ops.map(|op| (op, op_eval(op, seconds))).to_vec(),
        ));
    };
    // Canonical duration first.
    push(&mut cases, canonical(seed));
    // Zero seconds: zero conventions everywhere.
    push(&mut cases, 0);
    // 23:59:59 — one tick before the day boundary.
    push(&mut cases, 86_399);
    // The day rollover itself: hour hand back to zero.
    push(&mut cases, 86_400);
    for _ in 0..3 {
        let seconds = rand_duration(&mut rng);
        push(&mut cases, seconds);
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for the duration: suffix-typed so it infers
/// correctly at every call site.
fn render_duration(seconds: u64) -> String {
    format!("{seconds}u64")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let sig = "(seconds: u64) -> i64";
    let body = match op {
        Op::TotalMinutes => "(seconds / 60) as i64".to_string(),
        Op::TotalHours => "(seconds / 3600) as i64".to_string(),
        Op::HoursPart => "((seconds / 3600) % 24) as i64".to_string(),
        Op::MinutesPart => "((seconds % 3600) / 60) as i64".to_string(),
        Op::SecondsPart => "(seconds % 60) as i64".to_string(),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(seconds: u64) -> i64 {{\n    todo!()\n}}\n",
        op.name()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(seconds: u64) -> i64", op.name())
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
    for (seconds, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  seconds {}  ->  {}\n",
            render_duration(seconds),
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
         one duration expressed in seconds (it may exceed a full day); \
         queries read aggregate spans and wall-clock hand positions off \
         it. Handle zero gracefully.\n\
         \n\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         - Durations stay below one million seconds; you need not handle larger spans.\n\
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
    for (i, (seconds, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let seconds = {};\n",
            render_duration(*seconds),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "seconds"),
                out
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
            let call = call_src(*op, "seconds");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0142;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let seconds = nx(&mut state) % 1000000;\n\
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
            format!("{sig} {{\n    let _ = seconds;\n    0\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every query with the whole-minute span.
/// The canonical anchors keep every other answer away from that number,
/// so this is exact only on its own op.
fn minutes_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            format!("{sig} {{\n    (seconds / 60) as i64\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct DurationFamily;

impl Generator for DurationFamily {
    fn id(&self) -> &str {
        "duration"
    }
    fn category(&self) -> &str {
        "time-decomposition"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("duration", seed);

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
            id: format!("duration/{seed:016x}"),
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
            ("minutes-everything".to_string(), minutes_everything(&spec)),
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
        let g = DurationFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Whole minutes: plain floor of the minute count.
        assert_eq!(b_total_minutes(0), 0);
        assert_eq!(b_total_minutes(59), 0);
        assert_eq!(b_total_minutes(90), 1);
        assert_eq!(b_total_minutes(86_399), 1_439);
        // Whole hours: plain floor of the hour count.
        assert_eq!(b_total_hours(0), 0);
        assert_eq!(b_total_hours(3_599), 0);
        assert_eq!(b_total_hours(7_200), 2);
        assert_eq!(b_total_hours(86_400), 24);
        // Hour hand wraps at the day boundary — the family trap.
        assert_eq!(b_hours_part(0), 0);
        assert_eq!(b_hours_part(43_200), 12);
        assert_eq!(b_hours_part(82_800), 23);
        assert_eq!(b_hours_part(86_400), 0);
        assert_eq!(b_hours_part(91_800), 1);
        // Minute hand resets on the hour.
        assert_eq!(b_minutes_part(0), 0);
        assert_eq!(b_minutes_part(59), 0);
        assert_eq!(b_minutes_part(3_599), 59);
        assert_eq!(b_minutes_part(3_600), 0);
        assert_eq!(b_minutes_part(91_800), 30);
        // Second hand resets on the minute.
        assert_eq!(b_seconds_part(0), 0);
        assert_eq!(b_seconds_part(59), 59);
        assert_eq!(b_seconds_part(60), 0);
        assert_eq!(b_seconds_part(86_399), 59);
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
        // duration every answer is nonzero and all five stay mutually
        // distinct — only `total_minutes` itself matches the
        // minutes-everything cheat, and that one skip is documented.
        for seed in 0..200u64 {
            let seconds = canonical(seed);
            let answers = [
                b_total_minutes(seconds),
                b_total_hours(seconds),
                b_hours_part(seconds),
                b_minutes_part(seconds),
                b_seconds_part(seconds),
            ];
            assert!(
                seconds >= 86_400 && answers.iter().all(|&a| a != 0),
                "anchors broken seed {seed}"
            );
            for i in 0..answers.len() {
                for j in (i + 1)..answers.len() {
                    assert_ne!(answers[i], answers[j], "answers collide seed {seed}");
                }
            }
            for op in OP_ALL {
                let truth = op_eval(op, seconds);
                assert_ne!(truth, 0, "const-zero survives {op:?} seed {seed}");
                if matches!(op, Op::TotalMinutes) {
                    continue;
                }
                assert_ne!(
                    truth, answers[0],
                    "minutes-cheat survives {op:?} seed {seed}"
                );
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (seconds, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, seconds), out, "seed {seed}");
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
            assert!(!sk.contains("/ 60"));
            assert!(!sk.contains("% 60"));
            assert!(!sk.contains("/ 3600"));
            assert!(!sk.contains("% 3600"));
            assert!(!sk.contains("% 24"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("/ 60"));
            assert!(!p.contains("% 60"));
            assert!(!p.contains("/ 3600"));
            assert!(!p.contains("% 3600"));
            assert!(!p.contains("% 24"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every call site passes exactly one argument — no commas —
        // matching the parameter list of its signature.
        for op in OP_ALL {
            let call = call_src(op, "seconds");
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
        let g = DurationFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
