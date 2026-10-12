//! The `parking` family (category `metered-parking`) — fee arithmetic
//! over a parked stretch.
//!
//! Where `dice` reads a roll and `tennis` scores points, this family
//! exercises **billing conventions over a stay**: ceiling-billed hours,
//! the cents owed, the grace window, the overflow past the first hour,
//! and the per-minute dilution. The domain is an ordered pair of whole
//! numbers — minutes parked (at least one) and the meter's hourly rate
//! in whole cents (multiples of one hundred from one to nine dollars).
//! The seed prunes which two of five query ops are required:
//! `hours_charged`, `fee_cents`, `within_free_window`,
//! `minutes_beyond_first_hour`, `average_cents_per_minute`.
//! C(5,2) = **10 distinct skills**, above the diversity floor; op names
//! are semantic.
//!
//! The canonical stay is sampled until its anchor facts hold: it sits
//! in the partial-second-or-third-hour zone (sixty-one through one
//! hundred eighty minutes) so billed hours run two or three, the grace
//! window has lapsed, and every scalar answer stays distinct from the
//! raw rate (defeating flat-rate cheats outright). The grace window's
//! predicate answers FALSE there — agreeing with constant-false cheats —
//! and the pinned short-stay example flips them.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random stays against the model.
//!
//! Trivial baselines: `const-zero` (fails every scalar outright on the
//! canonical stay) and `flat-rate-everything` (every query answered with
//! the raw hourly rate — exact nowhere once hours exceed one).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    HoursCharged,
    FeeCents,
    WithinFreeWindow,
    MinutesBeyondFirstHour,
    AverageCentsPerMinute,
}

const OP_ALL: [Op; 5] = [
    Op::HoursCharged,
    Op::FeeCents,
    Op::WithinFreeWindow,
    Op::MinutesBeyondFirstHour,
    Op::AverageCentsPerMinute,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::HoursCharged => "hours_charged",
            Op::FeeCents => "fee_cents",
            Op::WithinFreeWindow => "within_free_window",
            Op::MinutesBeyondFirstHour => "minutes_beyond_first_hour",
            Op::AverageCentsPerMinute => "average_cents_per_minute",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::HoursCharged => {
                "the whole hours the stay bills — any partial hour rounds \
                 up to a complete one"
            }
            Op::FeeCents => {
                "the total cents owed — billed hours times the hourly \
                 rate"
            }
            Op::WithinFreeWindow => {
                "whether the stay fits the free grace window of a quarter \
                 hour or less"
            }
            Op::MinutesBeyondFirstHour => {
                "the minutes parked past the first billed hour — zero \
                 while the stay still fits inside it"
            }
            Op::AverageCentsPerMinute => {
                "whole cents owed per minute parked — the fee diluted \
                 over the stay, floored"
            }
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::WithinFreeWindow => "bool",
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

/// Hours billed — any partial hour bills in full.
fn b_hours_charged(minutes: u64, _rate: u64) -> i64 {
    minutes.div_ceil(60) as i64
}

/// Total cents owed: billed hours times the rate.
fn b_fee_cents(minutes: u64, rate: u64) -> i64 {
    b_hours_charged(minutes, rate) * rate as i64
}

/// The free grace window: fifteen minutes or fewer.
fn b_within_free_window(minutes: u64, _rate: u64) -> bool {
    minutes <= 15
}

/// Minutes parked past the first billed hour.
fn b_minutes_beyond_first_hour(minutes: u64, _rate: u64) -> i64 {
    minutes.saturating_sub(60) as i64
}

/// Whole cents owed per minute parked, floored.
fn b_average_cents_per_minute(minutes: u64, rate: u64) -> i64 {
    b_fee_cents(minutes, rate) / minutes as i64
}

/// The answer shape: scalars as `Num`, predicates as `Flag`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Flag(bool),
}

impl Out {
    fn lit(&self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            Out::Flag(v) => v.to_string(),
        }
    }
}

fn op_eval(op: Op, minutes: u64, rate: u64) -> Out {
    match op {
        Op::HoursCharged => Out::Num(b_hours_charged(minutes, rate)),
        Op::FeeCents => Out::Num(b_fee_cents(minutes, rate)),
        Op::WithinFreeWindow => Out::Flag(b_within_free_window(minutes, rate)),
        Op::MinutesBeyondFirstHour => Out::Num(b_minutes_beyond_first_hour(minutes, rate)),
        Op::AverageCentsPerMinute => Out::Num(b_average_cents_per_minute(minutes, rate)),
    }
}

// ---- canonical stay -------------------------------------------------------

const CANONICAL_SEED: u64 = 0x0B4E_FA11;

/// The canonical stay: sampled from the full table and retried until
/// the anchor facts hold.
///
/// Guaranteed for every seed: a partial-second-or-third-hour stay
/// (sixty-one through one hundred eighty minutes) so billed hours run
/// two or three and overflow past the first hour exists; the grace
/// window has lapsed; and every scalar answer stays distinct from every
/// other AND from the raw rate — flat-rate cheats die outright on all
/// four scalars. The window predicate answers FALSE on canonical,
/// agreeing with constant-false cheats; the pinned short-stay example
/// flips them.
fn canonical(seed: u64) -> (u64, u64) {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let minutes = 61 + rng.below(120);
        let rate = 100 * (1 + rng.below(9));
        if anchors_hold(minutes, rate) {
            return (minutes, rate);
        }
    }
    unreachable!("canonical stay sampling failed to satisfy anchors");
}

fn anchors_hold(minutes: u64, rate: u64) -> bool {
    if !(61..=180).contains(&minutes) {
        return false;
    }
    if b_within_free_window(minutes, rate) {
        return false;
    }
    let h = b_hours_charged(minutes, rate);
    let fee = b_fee_cents(minutes, rate);
    let beyond = b_minutes_beyond_first_hour(minutes, rate);
    let avg = b_average_cents_per_minute(minutes, rate);
    let vals = [h, fee, beyond, avg];
    // Flat-rate separation: no scalar may equal the raw rate.
    if vals.contains(&(rate as i64)) {
        return false;
    }
    // Pairwise distinct scalars.
    for i in 0..vals.len() {
        for j in (i + 1)..vals.len() {
            if vals[i] == vals[j] {
                return false;
            }
        }
    }
    h >= 2 && fee > h && beyond >= 1 && avg >= 1 && avg < rate as i64
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = ((u64, u64), Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_016C;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical partial-second-hour stay first.
    let can = canonical(seed);
    cases.push((
        can,
        spec.ops.map(|op| (op, op_eval(op, can.0, can.1))).to_vec(),
    ));
    // A short grace-window stay: the window predicate flips cheats.
    cases.push((
        (10, 300),
        spec.ops.map(|op| (op, op_eval(op, 10, 300))).to_vec(),
    ));
    // Exactly one hour on the boundary.
    cases.push((
        (60, 250),
        spec.ops.map(|op| (op, op_eval(op, 60, 250))).to_vec(),
    ));
    // The long cheap stay: ten exact hours at a dollar.
    cases.push((
        (600, 100),
        spec.ops.map(|op| (op, op_eval(op, 600, 100))).to_vec(),
    ));
    for _ in 0..3 {
        let minutes = 1 + rng.below(600);
        let rate = 100 * (1 + rng.below(9));
        let outs = spec.ops.map(|op| (op, op_eval(op, minutes, rate))).to_vec();
        cases.push(((minutes, rate), outs));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the first element types the tuple.
fn render_pair(minutes: u64, rate: u64) -> String {
    format!("({minutes}u64, {rate})")
}

fn op_fn_src(op: Op) -> String {
    match op {
        Op::HoursCharged => format!(
            "pub fn hours_charged(minutes: u64, rate: u64) -> {} {{\n    {}\n}}\n",
            op.ret(),
            ["let _ = rate;", "minutes.div_ceil(60) as i64"].join("\n    ")
        ),
        Op::FeeCents => format!(
            "pub fn fee_cents(minutes: u64, rate: u64) -> {} {{\n    {}\n}}\n",
            op.ret(),
            ["minutes.div_ceil(60) as i64 * rate as i64"].join("\n    ")
        ),
        Op::WithinFreeWindow => format!(
            "pub fn within_free_window(minutes: u64, rate: u64) -> {} {{\n    {}\n}}\n",
            op.ret(),
            ["let _ = rate;", "minutes <= 15"].join("\n    ")
        ),
        Op::MinutesBeyondFirstHour => format!(
            "pub fn minutes_beyond_first_hour(minutes: u64, rate: u64) -> {} {{\n    {}\n}}\n",
            op.ret(),
            ["let _ = rate;", "minutes.saturating_sub(60) as i64"].join("\n    ")
        ),
        Op::AverageCentsPerMinute => format!(
            "pub fn average_cents_per_minute(minutes: u64, rate: u64) -> {} {{\n    {}\n}}\n",
            op.ret(),
            [
                "let fee = minutes.div_ceil(60) as i64 * rate as i64;",
                "fee / minutes as i64",
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
        "pub fn {}(minutes: u64, rate: u64) -> {}",
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
    for ((minutes, rate), outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  stay {}  ->  {}\n",
            render_pair(minutes, rate),
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
         an ordered pair `(minutes, rate)`: minutes parked (at least one) \
         and the meter's hourly rate in whole cents. Billing rounds any \
         partial hour up to a complete one.\n\
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
    for (i, ((minutes, rate), outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let (minutes, rate) = {};\n",
            render_pair(*minutes, *rate),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "minutes, rate"),
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
            let call = call_src(*op, "minutes, rate");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_016C;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let minutes = (nx(&mut state) % 600) + 1;\n\
         \x20       let rate = 100 * ((nx(&mut state) % 9) + 1);\n\
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
            format!("{sig} {{\n    let _ = (minutes, rate);\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every query with the raw hourly rate.
/// On the canonical stay this misses everywhere — billed hours run two
/// or three against a three-digit rate, the fee multiplies past it, the
/// overflow stays below it by anchor, and the dilution lands under it.
/// Its constant-false window predicate loses to the pinned grace-window
/// example.
fn flat_rate_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => format!("{sig} {{\n    false\n}}\n"),
                _ => format!("{sig} {{\n    rate as i64\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct ParkingFamily;

impl Generator for ParkingFamily {
    fn id(&self) -> &str {
        "parking"
    }
    fn category(&self) -> &str {
        "metered-parking"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("parking", seed);

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
            id: format!("parking/{seed:016x}"),
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
                "flat-rate-everything".to_string(),
                flat_rate_everything(&spec),
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
        let g = ParkingFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Ceiling billing: face value on the hour, partial rounds up.
        assert_eq!(b_hours_charged(60, 300), 1);
        assert_eq!(b_hours_charged(120, 100), 2);
        assert_eq!(b_hours_charged(61, 100), 2);
        assert_eq!(b_hours_charged(119, 100), 2);
        assert_eq!(b_hours_charged(181, 100), 4);
        assert_eq!(b_hours_charged(1, 100), 1);
        // Fees bill whole.
        assert_eq!(b_fee_cents(60, 300), 300);
        assert_eq!(b_fee_cents(90, 200), 400);
        // Grace window: boundary inclusive, rate-blind.
        assert!(b_within_free_window(15, 300));
        assert!(!b_within_free_window(16, 300));
        for rate in [100u64, 250, 900] {
            assert!(b_within_free_window(10, rate));
            assert!(!b_within_free_window(20, rate));
        }
        // Overflow past the first hour.
        assert_eq!(b_minutes_beyond_first_hour(60, 300), 0);
        assert_eq!(b_minutes_beyond_first_hour(59, 100), 0);
        assert_eq!(b_minutes_beyond_first_hour(61, 100), 1);
        assert_eq!(b_minutes_beyond_first_hour(185, 100), 125);
        // Dilution: short stays average high, long cheap ones dilute.
        assert_eq!(b_average_cents_per_minute(60, 300), 5);
        assert_eq!(b_average_cents_per_minute(600, 100), 1);
        assert_eq!(b_average_cents_per_minute(61, 200), 6);
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
        // The canonical stay bills two or three hours with overflow and
        // a lapsed grace window: const-zero dies on every scalar
        // outright, flat-rate-everything dies because no scalar equals
        // the raw rate (anchor-enforced). The window predicate agrees
        // (false) with both cheats on canonical — the pinned ten-minute
        // example flips them.
        for seed in 0..200u64 {
            let (minutes, rate) = canonical(seed);
            let h = b_hours_charged(minutes, rate);
            let fee = b_fee_cents(minutes, rate);
            let beyond = b_minutes_beyond_first_hour(minutes, rate);
            let avg = b_average_cents_per_minute(minutes, rate);
            // Anchor facts the sampler enforces.
            assert!((61..=180).contains(&minutes), "seed {seed}: partial zone");
            assert!(!b_within_free_window(minutes, rate), "seed {seed}");
            assert!(h >= 2, "seed {seed}: at least two billed hours");
            assert!(beyond >= 1 && avg >= 1, "seed {seed}");
            let vals = [h, fee, beyond, avg];
            for i in 0..vals.len() {
                for j in (i + 1)..vals.len() {
                    assert_ne!(vals[i], vals[j], "seed {seed}: scalars must separate");
                }
                assert_ne!(
                    vals[i], rate as i64,
                    "flat-rate survives scalar at seed {seed}"
                );
                assert_ne!(vals[i], 0, "const-zero survives at seed {seed}");
            }
            assert!(fee > h, "seed {seed}");
            assert!(avg < rate as i64, "seed {seed}");
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for ((minutes, rate), outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, minutes, rate), out, "seed {seed}");
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
            assert!(!sk.contains("div_ceil"));
            assert!(!sk.contains("<= 15"));
            assert!(!sk.contains("saturating_sub"));
            assert!(!sk.contains("* rate"));
            assert!(!sk.contains("/ minutes"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("div_ceil"));
            assert!(!p.contains("<= 15"));
            assert!(!p.contains("saturating_sub"));
            assert!(!p.contains("* rate"));
            assert!(!p.contains("/ minutes"));
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
            let call = call_src(op, "minutes, rate");
            assert_eq!(
                call.matches(',').count(),
                params.matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{sig}`"
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = ParkingFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
