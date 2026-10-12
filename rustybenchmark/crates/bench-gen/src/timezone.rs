//! The `timezone` family (category `timezones`) — wall-clock
//! arithmetic over a UTC reading and a fixed zone offset.
//!
//! Where `clock` measures hand angles and `duration` decomposes spans,
//! this family exercises **offset wrap-around semantics**: the local
//! hour modulo twenty-four, whether the raw sum leaves the day, which
//! way the calendar rolled, and the label for the offset itself. The
//! domain is an ordered pair `(hour, offset)` — a whole-hour UTC
//! reading zero through twenty-three and a whole-hour offset reaching
//! past either edge of the dial. The seed prunes which two of five
//! query ops are required: `local_hour`, `crosses_day_boundary`,
//! `is_afternoon_local`, `day_shift`, `offset_label`.
//! C(5,2) = **10 distinct skills**, above the diversity floor; op names
//! are semantic.
//!
//! The canonical reading is sampled until its anchor facts hold: the
//! offset runs EAST and the raw sum lands deep enough past midnight
//! that the crossing predicate answers TRUE, the calendar shifted one
//! day forward, AND the local dial sits inside the afternoon band — so
//! constant-false cheats die outright on every op while the naive
//! identity answers (raw hour, zero shift, a fixed zero-offset label)
//! all miss too. Backward rolls are pinned worked examples.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random readings against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the
//! canonical reading) and `identity-everything` (answers as if the
//! offset did nothing — exact nowhere on the canonical forward roll).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    LocalHour,
    CrossesDayBoundary,
    IsAfternoonLocal,
    DayShift,
    OffsetLabel,
}

const OP_ALL: [Op; 5] = [
    Op::LocalHour,
    Op::CrossesDayBoundary,
    Op::IsAfternoonLocal,
    Op::DayShift,
    Op::OffsetLabel,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::LocalHour => "local_hour",
            Op::CrossesDayBoundary => "crosses_day_boundary",
            Op::IsAfternoonLocal => "is_afternoon_local",
            Op::DayShift => "day_shift",
            Op::OffsetLabel => "offset_label",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::LocalHour => {
                "the local wall-clock hour once the offset lands — \
                 Euclidean remainder keeps both forward and backward \
                 rolls inside one dial"
            }
            Op::CrossesDayBoundary => {
                "whether the raw sum leaves the zero-to-twenty-three day \
                 at all, rolling past midnight either way"
            }
            Op::IsAfternoonLocal => {
                "whether the LOCAL reading sits between noon and five in \
                 the evening, both ends included"
            }
            Op::DayShift => {
                "which calendar day the local reading lands on relative \
                 to the UTC day — one later, the same, or one earlier"
            }
            Op::OffsetLabel => {
                "the dial's label, east positive and west negative, with \
                 zero kept explicit rather than dropped"
            }
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::CrossesDayBoundary | Op::IsAfternoonLocal => "bool",
            Op::OffsetLabel => "String",
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

/// The local hour once the offset lands.
fn b_local_hour(hour: u64, offset: i64) -> i64 {
    (hour as i64 + offset).rem_euclid(24)
}

/// Whether the raw sum leaves the day at all.
fn b_crosses_day_boundary(hour: u64, offset: i64) -> bool {
    let sum = hour as i64 + offset;
    !(0..24).contains(&sum)
}

/// Whether the LOCAL hour sits in the afternoon band.
fn b_is_afternoon_local(hour: u64, offset: i64) -> bool {
    (12..=17).contains(&b_local_hour(hour, offset))
}

/// Which calendar day the local reading lands on.
fn b_day_shift(hour: u64, offset: i64) -> i64 {
    let sum = hour as i64 + offset;
    if sum >= 24 {
        1
    } else if sum < 0 {
        -1
    } else {
        0
    }
}

/// The dial's label; zero keeps its explicit plus-zero shape.
fn b_offset_label(hour: u64, offset: i64) -> String {
    let _ = hour;
    if offset < 0 {
        format!("UTC-{}", -offset)
    } else {
        format!("UTC+{}", offset)
    }
}

/// The answer shape: scalars as `Num`, predicates as `Flag`, labels
/// as `Str`.
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
            Out::Flag(v) => v.to_string(),
            Out::Str(s) => format!("{s:?}"),
        }
    }
}

fn op_eval(op: Op, hour: u64, offset: i64) -> Out {
    match op {
        Op::LocalHour => Out::Num(b_local_hour(hour, offset)),
        Op::CrossesDayBoundary => Out::Flag(b_crosses_day_boundary(hour, offset)),
        Op::IsAfternoonLocal => Out::Flag(b_is_afternoon_local(hour, offset)),
        Op::DayShift => Out::Num(b_day_shift(hour, offset)),
        Op::OffsetLabel => Out::Str(b_offset_label(hour, offset)),
    }
}

// ---- canonical reading ----------------------------------------------------

const CANONICAL_SEED: u64 = 0x71C5_0FA5;

/// The canonical reading: sampled from the full table and retried until
/// the anchor facts hold.
///
/// Guaranteed for every seed: an EASTWARD offset whose raw sum lands
/// deep enough past midnight that the crossing predicate answers TRUE,
/// the calendar shifted one day forward, AND the local dial sits inside
/// the afternoon band. Constant-false cheats therefore die outright on
/// every op, and the naive identity answers — the raw UTC hour, a zero
/// shift, a fixed zero-offset label — all miss too (a forward roll of
/// at least twelve hours can never leave the local hour equal to the
/// input).
fn canonical(seed: u64) -> (u64, i64) {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let hour = rng.below(24);
        let offset = rng.below(29) as i64 - 12;
        if anchors_hold(hour, offset) {
            return (hour, offset);
        }
    }
    unreachable!("canonical reading sampling failed to satisfy anchors");
}

fn anchors_hold(hour: u64, offset: i64) -> bool {
    // Forward roll into tomorrow's afternoon band: the sum must reach
    // thirty-six (local noon) but stay under forty-two (local evening)
    // while remaining reachable inside one extra day.
    b_crosses_day_boundary(hour, offset)
        && offset > 0
        && b_is_afternoon_local(hour, offset)
        && b_day_shift(hour, offset) == 1
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = ((u64, i64), Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0170;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical forward roll into tomorrow afternoon first.
    let can = canonical(seed);
    cases.push((
        can,
        spec.ops.map(|op| (op, op_eval(op, can.0, can.1))).to_vec(),
    ));
    // Noon UTC, zero offset: the band's opening hour with no roll.
    cases.push((
        (12, 0),
        spec.ops.map(|op| (op, op_eval(op, 12, 0))).to_vec(),
    ));
    // A backward roll lands yesterday evening.
    cases.push((
        (2, -5),
        spec.ops.map(|op| (op, op_eval(op, 2, -5))).to_vec(),
    ));
    // Backward onto the band's final hour.
    cases.push((
        (22, -5),
        spec.ops.map(|op| (op, op_eval(op, 22, -5))).to_vec(),
    ));
    // Zero conventions across the board.
    cases.push(((0, 0), spec.ops.map(|op| (op, op_eval(op, 0, 0))).to_vec()));
    for _ in 0..3 {
        let hour = rng.below(24);
        let offset = rng.below(29) as i64 - 12;
        let outs = spec.ops.map(|op| (op, op_eval(op, hour, offset))).to_vec();
        cases.push(((hour, offset), outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the first element types the tuple.
fn render_pair(hour: u64, offset: i64) -> String {
    format!("({hour}u64, {offset}i64)")
}

fn op_fn_src(op: Op) -> String {
    match op {
        Op::LocalHour => format!(
            "pub fn local_hour(hour: u64, offset: i64) -> {} {{\n    {}\n}}\n",
            op.ret(),
            "(hour as i64 + offset).rem_euclid(24)"
        ),
        Op::CrossesDayBoundary => format!(
            "pub fn crosses_day_boundary(hour: u64, offset: i64) -> {} {{\n    {}\n}}\n",
            op.ret(),
            ["let sum = hour as i64 + offset;", "!(0..24).contains(&sum)",].join("\n    ")
        ),
        Op::IsAfternoonLocal => format!(
            "pub fn is_afternoon_local(hour: u64, offset: i64) -> {} {{\n    {}\n}}\n",
            op.ret(),
            "(12..=17).contains(&(hour as i64 + offset).rem_euclid(24))"
        ),
        Op::DayShift => format!(
            "pub fn day_shift(hour: u64, offset: i64) -> {} {{\n    {}\n}}\n",
            op.ret(),
            [
                "let sum = hour as i64 + offset;",
                "if sum >= 24 {",
                "    1",
                "} else if sum < 0 {",
                "    -1",
                "} else {",
                "    0",
                "}",
            ]
            .join("\n    ")
        ),
        Op::OffsetLabel => format!(
            "pub fn offset_label(hour: u64, offset: i64) -> {} {{\n    {}\n}}\n",
            op.ret(),
            [
                "let _ = hour;",
                "if offset < 0 {",
                r#"    format!("UTC-{}", -offset)"#,
                "} else {",
                r#"    format!("UTC+{}", offset)"#,
                "}",
            ]
            .join("\n    ")
        ),
    }
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!(
        "pub fn {}(hour: u64, offset: i64) -> {}",
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
    for ((hour, offset), outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  dial {}  ->  {}\n",
            render_pair(hour, offset),
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
         an ordered pair `(hour, offset)`: a whole-hour UTC reading zero \
         through twenty-three and a whole-hour zone offset that may be \
         negative and may reach past either edge of the dial.\n\
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
    for (i, ((hour, offset), outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let (hour, offset) = {};\n",
            render_pair(*hour, *offset),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "hour, offset"),
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
            let call = call_src(*op, "hour, offset");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0170;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let hour = nx(&mut state) % 24;\n\
         \x20       let offset = (nx(&mut state) % 29) as i64 - 12;\n\
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
            match op.ret() {
                "bool" => format!("{sig} {{\n    let _ = (hour, offset);\n    false\n}}\n"),
                "String" => {
                    format!("{sig} {{\n    let _ = (hour, offset);\n    String::new()\n}}\n")
                }
                _ => format!("{sig} {{\n    let _ = (hour, offset);\n    0\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every query as if the offset did
/// nothing. On the canonical forward roll this misses everywhere — the
/// local dial has rolled off the raw hour, the calendar moved, both
/// predicates disagree with their constant false, and the label is not
/// the fixed zero-offset string.
fn identity_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op {
                Op::LocalHour => format!("{sig} {{\n    hour as i64\n}}\n"),
                Op::CrossesDayBoundary | Op::IsAfternoonLocal => {
                    format!("{sig} {{\n    false\n}}\n")
                }
                Op::DayShift => format!("{sig} {{\n    0\n}}\n"),
                Op::OffsetLabel => format!("{sig} {{\n    \"UTC+0\".to_string()\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct TimezoneFamily;

impl Generator for TimezoneFamily {
    fn id(&self) -> &str {
        "timezone"
    }
    fn category(&self) -> &str {
        "timezones"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("timezone", seed);

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
            id: format!("timezone/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure integer queries — no unsafe anywhere.
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
                "identity-everything".to_string(),
                identity_everything(&spec),
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
        let g = TimezoneFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Local dial: plain shift, forward roll, backward roll, identity.
        assert_eq!(b_local_hour(12, 3), 15);
        assert_eq!(b_local_hour(22, 5), 3);
        assert_eq!(b_local_hour(2, -5), 21);
        assert_eq!(b_local_hour(17, 0), 17);
        assert_eq!(b_local_hour(23, 1), 0);
        assert_eq!(b_local_hour(0, -1), 23);
        // Crossing needs the sum out of the day; the upper edge counts.
        assert!(!b_crosses_day_boundary(12, 0));
        assert!(!b_crosses_day_boundary(1, -1));
        assert!(b_crosses_day_boundary(22, 5));
        assert!(b_crosses_day_boundary(22, 2));
        assert!(b_crosses_day_boundary(2, -5));
        // Afternoon reads the local dial: UTC morning can be a local
        // afternoon, and a rolled-back reading can land on seventeen.
        assert!(b_is_afternoon_local(9, 5));
        assert!(!b_is_afternoon_local(8, 0));
        assert!(b_is_afternoon_local(22, -5));
        assert!(!b_is_afternoon_local(11, 0));
        assert!(!b_is_afternoon_local(18, 0));
        // Day shift: forward rolls move one day, backward one earlier,
        // and a whole extra day still measures as one here.
        assert_eq!(b_day_shift(22, 5), 1);
        assert_eq!(b_day_shift(2, -5), -1);
        assert_eq!(b_day_shift(1, -1), 0);
        assert_eq!(b_day_shift(9, 30), 1);
        // Labels: east positive, west negative, zero explicit.
        assert_eq!(b_offset_label(9, 5), "UTC+5");
        assert_eq!(b_offset_label(3, -7), "UTC-7");
        assert_eq!(b_offset_label(12, 0), "UTC+0");
        assert_eq!(b_offset_label(1, 14), "UTC+14");
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
        // The canonical reading is a FORWARD ROLL into tomorrow's
        // afternoon band, so NO skips anywhere: const-zero loses on both
        // scalars (nonzero) and both predicates (true beats false); the
        // naive identity cheat loses everywhere too — a roll of at least
        // twelve hours never leaves the local hour equal to the input,
        // the calendar moved off zero, both flags beat false, and the
        // label is not the fixed zero-offset string.
        for seed in 0..200u64 {
            let (hour, offset) = canonical(seed);
            let local = b_local_hour(hour, offset);
            let shift = b_day_shift(hour, offset);
            // Anchor facts the sampler enforces.
            assert!(offset > 0, "seed {seed}: must run east");
            assert!(
                b_crosses_day_boundary(hour, offset),
                "seed {seed}: must leave the day"
            );
            assert_eq!(shift, 1, "seed {seed}: must land tomorrow");
            assert!(
                b_is_afternoon_local(hour, offset),
                "seed {seed}: must land in the band"
            );
            // const-zero survives nowhere.
            assert_ne!(local, 0, "const-zero survives at seed {seed}");
            assert_ne!(shift, 0, "seed {seed}");
            // identity-everything survives nowhere.
            assert_ne!(local, hour as i64, "identity survives local at seed {seed}");
            assert_ne!(
                b_offset_label(hour, offset),
                "UTC+0",
                "identity survives label at seed {seed}"
            );
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for ((hour, offset), outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, hour, offset), out, "seed {seed}");
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
            // the worked examples legitimately show outputs, never
            // rules — so tokens carry implementation shapes.
            assert!(!sk.contains("rem_euclid"));
            assert!(!sk.contains("(0..24)"));
            assert!(!sk.contains("12..=17"));
            assert!(!sk.contains(">= 24"));
            assert!(!sk.contains("< 0"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("rem_euclid"));
            assert!(!p.contains("(0..24)"));
            assert!(!p.contains("12..=17"));
            assert!(!p.contains(">= 24"));
            assert!(!p.contains("< 0"));
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
            let call = call_src(op, "hour, offset");
            assert_eq!(
                call.matches(',').count(),
                params.matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{sig}`"
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = TimezoneFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
