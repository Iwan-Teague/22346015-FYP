//! The `gray-code-counter` family (category `numeric-encoding`) —
//! deterministic counting puzzles where *the reflected binary code* is
//! the data structure.
//!
//! Every puzzle mirrors a real Gray-code counter: `advance` walks to the
//! next code (successive codes always differ in exactly one bit),
//! `retreat` walks back but cannot go below zero, and `peek_next` /
//! `steps_taken` / `gray_value` expose the encoding any shortcut
//! distorts. The seed picks which two of five ops are required:
//! `gray_value`, `advance`, `retreat`, `steps_taken`, `peek_next`.
//! A counter that forgets to re-encode is wrong on its very first
//! answered step.

/// One Gray-code counter over an internal plain counter. The public
/// value is always `count ^ (count >> 1)` — the reflected binary code.
#[derive(Clone)]
pub struct GrayInstance {
    count: u64,
}

impl GrayInstance {
    /// A counter parked at `start` steps past zero.
    pub fn new(start: u64) -> Self {
        GrayInstance { count: start }
    }

    fn encode(count: u64) -> u64 {
        count ^ (count >> 1)
    }

    /// The current Gray-encoded value.
    pub fn gray_value(&self) -> u64 {
        Self::encode(self.count)
    }

    /// Steps forward one code and answers the new value. Adjacent
    /// answers always differ in exactly one bit.
    pub fn advance(&mut self) -> u64 {
        self.count += 1;
        Self::encode(self.count)
    }

    /// Steps back one code and answers the new value, or None when the
    /// counter already sits at zero — it never wraps below zero.
    pub fn retreat(&mut self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(Self::encode(self.count))
    }

    /// How many net steps the counter sits past zero.
    pub fn steps_taken(&self) -> u64 {
        self.count
    }

    /// What `advance` would answer next, without moving.
    pub fn peek_next(&self) -> u64 {
        Self::encode(self.count + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advancing_from_zero_walks_the_reflected_sequence() {
        let mut g = GrayInstance::new(0);
        assert_eq!(g.advance(), 1);
        assert_eq!(g.advance(), 3);
        assert_eq!(g.advance(), 2);
        assert_eq!(g.advance(), 6);
        assert_eq!(g.steps_taken(), 4);
        assert_eq!(g.gray_value(), 6);
    }

    #[test]
    fn retreating_reverses_exactly_and_never_passes_zero() {
        let mut g = GrayInstance::new(0);
        for _ in 0..4u64 {
            g.advance();
        }
        assert_eq!(g.retreat(), Some(2));
        assert_eq!(g.retreat(), Some(3));
        assert_eq!(g.retreat(), Some(1));
        assert_eq!(g.retreat(), Some(0));
        assert_eq!(g.retreat(), None);
        assert_eq!(g.steps_taken(), 0);
        assert_eq!(g.retreat(), None);
    }

    #[test]
    fn successive_answers_differ_in_exactly_one_bit() {
        let mut g = GrayInstance::new(5);
        let mut prev = g.gray_value();
        for _ in 0..200u64 {
            let cur = g.advance();
            assert_eq!((prev ^ cur).count_ones(), 1);
            prev = cur;
        }
    }

    #[test]
    fn peek_next_matches_advance_without_moving() {
        let mut g = GrayInstance::new(41);
        let before = g.steps_taken();
        let p = g.peek_next();
        assert_eq!(g.steps_taken(), before);
        let a = g.advance();
        assert_eq!(a, p);
        assert_eq!(g.gray_value(), p);
    }

    #[test]
    fn starting_offset_is_honored() {
        let g = GrayInstance::new(9);
        // 9 = 0b1001, gray = 0b1001 ^ 0b0100 = 0b1101.
        assert_eq!(g.gray_value(), 13);
        assert_eq!(g.steps_taken(), 9);
        assert_eq!(g.peek_next(), 15); // gray(10) = 0b1010 ^ 0b0101 = 0b1111
    }

    #[test]
    fn soak_matches_a_shadow_counter_under_random_traffic() {
        let mut g = GrayInstance::new(3);
        let mut shadow: u64 = 3;
        let mut st: u64 = 0x5EED_60A7;
        for _ in 0..600u64 {
            st = st
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            if (st >> 33) & 1 == 0 {
                g.advance();
                shadow += 1;
            } else if let Some(v) = g.retreat() {
                shadow -= 1;
                assert_eq!(v, shadow ^ (shadow >> 1));
            } else {
                assert_eq!(shadow, 0);
            }
            assert_eq!(g.steps_taken(), shadow);
            assert_eq!(g.gray_value(), shadow ^ (shadow >> 1));
        }
    }
}

use crate::{mint_canary, GeneratedTask, Generator, Rng};

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    GrayValue,
    Advance,
    Retreat,
    StepsTaken,
    PeekNext,
}

pub const OP_ALL: [Op; 5] = [
    Op::GrayValue,
    Op::Advance,
    Op::Retreat,
    Op::StepsTaken,
    Op::PeekNext,
];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::GrayValue => "gray_value",
            Op::Advance => "advance",
            Op::Retreat => "retreat",
            Op::StepsTaken => "steps_taken",
            Op::PeekNext => "peek_next",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::GrayValue => "answers the reflected binary code of the current step count - the count XORed with itself shifted right by one bit position",
            Op::Advance => "moves forward one step and answers the new code - successive codes always differ in exactly one bit",
            Op::Retreat => "moves back one step and answers the new code, or None when already sitting at the zero floor - it never wraps below zero",
            Op::StepsTaken => "answers how many net steps the counter sits past zero, including its starting offset",
            Op::PeekNext => "answers what advance would return next without moving the counter",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::GrayValue => "pub fn gray_value(&self) -> u64",
            Op::Advance => "pub fn advance(&mut self) -> u64",
            Op::Retreat => "pub fn retreat(&mut self) -> Option<u64>",
            Op::StepsTaken => "pub fn steps_taken(&self) -> u64",
            Op::PeekNext => "pub fn peek_next(&self) -> u64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub const CANONICAL_SEED: u64 = 0x60A7_FA11;

pub fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let mut idx = [rng.below(5), rng.below(5)];
    while idx[0] == idx[1] {
        idx[1] = rng.below(5);
    }
    idx.sort_unstable();
    Spec {
        ops: [OP_ALL[idx[0] as usize], OP_ALL[idx[1] as usize]],
    }
}

/// Advance is the fill primitive every scenario needs; when the seed did
/// not sample it, it ships as given infrastructure alongside the pair.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    if spec.ops.contains(&Op::Advance) {
        spec.ops.to_vec()
    } else {
        let mut v = vec![Op::Advance];
        v.extend_from_slice(&spec.ops);
        v
    }
}

/// The canonical scenario: a counter parked at a small offset then
/// hammered by dozens of advances, so the encoding is wrong from the
/// very first answered step for any solution that forgets to re-encode.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical gray-code scenario");
}

fn fresh_gray(start: u64) -> GrayInstance {
    GrayInstance::new(start)
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub start: u64,
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01C2;

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![
        ExampleCase {
            start: 7,
            warmup: canonical(seed),
        },
        ExampleCase {
            start: 0,
            warmup: 3,
        },
        ExampleCase {
            start: 1,
            warmup: 4,
        },
        ExampleCase {
            start: 3,
            warmup: 17,
        },
    ];
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    for _ in 0..8 {
        let start = rng.below(24);
        out.push(ExampleCase {
            start,
            warmup: rng.below(40) + 2,
        });
    }
    out
}

/// Drives `warmup` advances into a fresh counter parked at `start`.
/// Advancing takes no argument, so no randomness is involved.
fn driven_gray(start: u64, warmup: u64) -> GrayInstance {
    let mut g = fresh_gray(start);
    for _ in 0..warmup {
        g.advance();
    }
    g
}

// ---- emitted-source fragments -----------------------------------------------

pub const STRUCT_SRC: &str = "#[derive(Clone)]\npub struct Gray {\n    count: u64,\n}\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::GrayValue => &["self.count ^ (self.count >> 1)"],
        Op::Advance => &["self.count += 1;", "self.count ^ (self.count >> 1)"],
        Op::Retreat => &[
            "if self.count == 0 {",
            "    return None;",
            "}",
            "self.count -= 1;",
            "Some(self.count ^ (self.count >> 1))",
        ],
        Op::StepsTaken => &["self.count"],
        Op::PeekNext => &["(self.count + 1) ^ ((self.count + 1) >> 1)"],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub const GRAY_NEW_SRC: &str = "impl Gray {\n    pub fn new(start: u64) -> Self {\n        Gray {\n            count: start,\n        }\n    }\n}\n\n";

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen("pub struct Gray {", "pub struct GrayRef {", 1);
    s.push_str(
        &GRAY_NEW_SRC
            .replace("impl Gray {", "impl GrayRef {")
            .replace("Gray {\n", "GrayRef {\n"),
    );
    s.push_str("impl GrayRef {\n");
    for &op in &ops {
        let body = op_fn_src(op);
        let renamed = body.replacen(
            &format!("pub fn {}(", op.name()),
            &format!("fn ref_{}(", op.name()),
            1,
        );
        assert!(renamed != body, "rename failed");
        s.push_str(&renamed);
    }
    s.push_str("}\n");
    s
}

pub fn worked_examples_prose(examples: &[ExampleCase]) -> String {
    let mut s = String::new();
    for (i, ex) in examples.iter().enumerate() {
        let g = driven_gray(ex.start, ex.warmup);
        s.push_str(&format!(
            "//! ex{i}: parked at {st}, then {n} advances -> code {v}, steps {s}\n",
            i = i,
            st = ex.start,
            n = ex.warmup,
            v = g.gray_value(),
            s = g.steps_taken()
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested reflected-binary counting operations over\n\
         //! one internal step count. The exposed value is a Gray code whose\n\
         //! successive answers flip exactly one bit; walking backwards must\n\
         //! reverse the walk exactly and stop dead at the zero floor. The\n\
         //! hidden tests drive thousands of interleaved operations and\n\
         //! compare every returned value.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(GRAY_NEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested Gray-code counter operations with an exactly maintained internal count.\n\nRequirements:\n- `Gray::new(start)` parks the counter `start` steps past zero.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- The exposed value is always the reflected binary encoding: the internal step count n XORed with n shifted right by one bit, so successive advanced answers differ in exactly one bit and every answer must be freshly re-encoded from the current count.\n- Retreating past the zero floor answers None and leaves the counter exactly where it was - it never wraps below zero.\n- Peeking never mutates; the step tally tracks every net move including the starting offset.\n- No floating point; no unsafe code; standard library only.\n\nSignatures:\n```rust\n");
    for &op in &effective_ops(spec) {
        s.push_str(op.sig());
        s.push('\n');
    }
    s.push_str("```\n");
    s.push_str(&format!(
        "\nYour answer must still contain the canary string \"{can}\" in its doc comment.\n",
        can = canary
    ));
    s
}

pub fn cargo_toml() -> String {
    "[package]\nname = \"task\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[workspace]\n"
        .to_string()
}

pub fn behavior_test_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from("use task::Gray;\n\n");
    for (i, ex) in examples.iter().enumerate() {
        let g = driven_gray(ex.start, ex.warmup);
        let val_now = g.gray_value();
        let steps_now = g.steps_taken();
        let peek_now = g.peek_next();
        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let mut drive = Gray::new({start});\n    for _ in 0..{n} {{\n        drive.advance();\n    }}\n",
            i = i,
            start = ex.start,
            n = ex.warmup
        ));
        for &op in &spec.ops {
            s.push_str("    let mut r = drive.clone();\n");
            match op {
                Op::GrayValue => {
                    s.push_str(&format!("    assert_eq!(r.gray_value(), {val_now});\n"));
                }
                Op::StepsTaken => {
                    s.push_str(&format!("    assert_eq!(r.steps_taken(), {steps_now});\n"));
                }
                Op::Advance => {
                    let want = g.clone().advance();
                    s.push_str(&format!("    assert_eq!(r.advance(), {want});\n"));
                }
                Op::Retreat => {
                    let want = g
                        .clone()
                        .retreat()
                        .map_or_else(|| "None".to_string(), |x| format!("Some({x})"));
                    s.push_str(&format!("    assert_eq!(r.retreat(), {want});\n"));
                }
                Op::PeekNext => {
                    s.push_str(&format!("    assert_eq!(r.peek_next(), {peek_now});\n"));
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Scripted reversal probe: walking back must undo every advance in
    // exact reverse order and stop dead at the zero floor.
    if spec.ops.contains(&Op::Advance) && spec.ops.contains(&Op::Retreat) {
        s.push_str("#[test]\nfn scripted_walk_reverses_exactly_at_the_zero_floor() {\n    let mut r = Gray::new(0);\n    assert_eq!(r.advance(), 1);\n    assert_eq!(r.advance(), 3);\n    assert_eq!(r.advance(), 2);\n    assert_eq!(r.retreat(), Some(3));\n    assert_eq!(r.retreat(), Some(1));\n    assert_eq!(r.retreat(), Some(0));\n    assert_eq!(r.retreat(), None);\n    assert_eq!(r.retreat(), None);\n}\n");
    }
    // Fill soak: eight hundred advances must each flip exactly one bit
    // against the previous answer.
    if spec.ops.contains(&Op::Advance) && spec.ops.contains(&Op::GrayValue) {
        s.push_str("#[test]\nfn fill_soak_flips_exactly_one_bit_per_step() {\n    let mut r = Gray::new(9);\n    let mut prev = r.gray_value();\n    for _ in 0..800u64 {\n        let cur = r.advance();\n        assert_eq!((prev ^ cur).count_ones(), 1);\n        prev = cur;\n    }\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::Gray;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    let ops = effective_ops(spec);
    s.push_str("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {\n    let start0: u64 = 5;\n    let mut cand = Gray::new(start0);\n    let mut refr = GrayRef::new(start0);\n");
    if ops.contains(&Op::Advance) {
        s.push_str("    assert_eq!(cand.advance(), refr.ref_advance());\n");
    }
    if ops.contains(&Op::Retreat) {
        s.push_str("    assert_eq!(cand.retreat(), refr.ref_retreat());\n");
        s.push_str("    assert_eq!(cand.retreat(), refr.ref_retreat());\n");
    }
    if ops.contains(&Op::GrayValue) {
        s.push_str("    assert_eq!(cand.gray_value(), refr.ref_gray_value());\n");
    }
    if ops.contains(&Op::StepsTaken) {
        s.push_str("    assert_eq!(cand.steps_taken(), refr.ref_steps_taken());\n");
    }
    if ops.contains(&Op::PeekNext) {
        s.push_str("    assert_eq!(cand.peek_next(), refr.ref_peek_next());\n");
    }
    let arm_count = ops.len();
    s.push_str(&format!("    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_01C2;\n    for _ in 0..3000 {{\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in ops.iter().enumerate() {
        let body = match op {
            Op::Advance => "assert_eq!(cand.advance(), refr.ref_advance());".to_string(),
            Op::Retreat => "assert_eq!(cand.retreat(), refr.ref_retreat());".to_string(),
            Op::GrayValue => "assert_eq!(cand.gray_value(), refr.ref_gray_value());".to_string(),
            Op::StepsTaken => "assert_eq!(cand.steps_taken(), refr.ref_steps_taken());".to_string(),
            Op::PeekNext => "assert_eq!(cand.peek_next(), refr.ref_peek_next());".to_string(),
        };
        s.push_str(&format!("            {} => {{ {} }}\n", i, body));
    }
    s.push_str("            _ => { unreachable!() }\n        }\n    }\n}\n");
    s
}

pub fn const_zero_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(GRAY_NEW_SRC);
    s.push_str("impl Gray {\n");
    for &op in &ops {
        let body = match op {
            Op::Retreat => "None",
            _ => "0",
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s.push_str("}\n");
    s
}

/// The plausible cheat: identical bookkeeping, but advance answers the
/// raw incremented count instead of re-encoding it into the Gray code —
/// the walk looks perfectly ordered yet every answered value drifts.
pub fn binary_increment_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(GRAY_NEW_SRC);
    s.push_str("impl Gray {\n");
    for &op in &ops {
        if op == Op::Advance {
            let body = &["self.count += 1;", "self.count"];
            s.push_str(&format!(
                "{} {{\n    {}\n}}\n",
                op_sig_src(op),
                body.join("\n    ")
            ));
        } else {
            s.push_str(&op_fn_src(op));
        }
    }
    s.push_str("}\n");
    s
}

pub struct GrayCodeFamily;

impl Generator for GrayCodeFamily {
    fn id(&self) -> &'static str {
        "gray-code-counter"
    }

    fn category(&self) -> &'static str {
        "numeric-encoding"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("gray-code-counter", seed);
        let mut files = std::collections::BTreeMap::new();
        files.insert(std::path::PathBuf::from("Cargo.toml"), cargo_toml());
        files.insert(
            std::path::PathBuf::from("src/lib.rs"),
            skeleton_src(spec, &examples),
        );
        let mut hidden = std::collections::BTreeMap::new();
        hidden.insert(
            std::path::PathBuf::from("tests/behavior.rs"),
            behavior_test_src(spec, &examples),
        );
        hidden.insert(
            std::path::PathBuf::from("tests/differential.rs"),
            differential_test_src(spec),
        );
        GeneratedTask {
            id: format!("gray-code-counter/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt_src(spec, &canary),
            canary,
            answer_path: String::from("src/lib.rs"),
            files,
            hidden,
            behavior_test: String::from("behavior"),
            differential_test: String::from("differential"),
            alloc_test: String::new(),
            max_unsafe: None,
            forbidden_paths: vec![],
            check_clippy: false,
            clippy_allow: vec![],
            weights: (0.70, 0.20, 0.10),
        }
    }

    fn reference_code(&self, seed: u64) -> String {
        let mut s = String::from(STRUCT_SRC);
        s.push('\n');
        s.push_str(GRAY_NEW_SRC);
        s.push_str("impl Gray {\n");
        for &op in &effective_ops(sample(seed)) {
            s.push_str(&op_fn_src(op));
        }
        s.push_str("}\n");
        s
    }

    fn skeleton_code(&self, seed: u64) -> String {
        let spec = sample(seed);
        skeleton_src(spec, &worked_examples(seed))
    }

    fn trivial_baselines(&self, seed: u64) -> Vec<(String, String)> {
        let spec = sample(seed);
        vec![
            ("const-zero".to_string(), const_zero_src(spec)),
            ("binary-increment".to_string(), binary_increment_src(spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let mut names: Vec<String> = sample(seed)
            .ops
            .iter()
            .map(|op| format!("q:{}", op.name()))
            .collect();
        names.sort();
        names
    }
}

#[cfg(test)]
mod gen_tests {
    use super::*;

    const HOUSE_SEEDS: [u64; 7] = [1, 2, 3, 7, 42, 99, 2024];

    #[test]
    fn generation_is_deterministic() {
        let a = GrayCodeFamily.generate(55);
        let b = GrayCodeFamily.generate(55);
        assert_eq!(a.prompt, b.prompt);
        assert_eq!(a.files, b.files);
        assert_eq!(a.hidden, b.hidden);
    }

    #[test]
    fn seeds_vary_query_pairs() {
        let mut seen = std::collections::HashSet::new();
        for seed in 0..300u64 {
            seen.insert(sample(seed));
        }
        assert!(seen.len() >= 9, "only {} distinct pairs", seen.len());
    }

    #[test]
    fn canonical_scenarios_stay_bounded() {
        for seed in 0..200u64 {
            let warmup = canonical(seed);
            assert!(warmup >= 24 && warmup.is_multiple_of(8));
            let g = driven_gray(6, warmup);
            assert_eq!(g.steps_taken(), 6 + warmup);
            assert_eq!(g.gray_value(), (6 + warmup) ^ ((6 + warmup) >> 1));
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let g = driven_gray(ex.start, ex.warmup);
                assert_eq!(g.steps_taken(), ex.start + ex.warmup);
                assert!(ex.warmup >= 2);
                assert!(ex.start < 24);
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct GrayRef"));
            assert!(
                src.matches("GrayRef {").count() >= 2,
                "constructor body must be renamed too"
            );
            assert!(!src.contains("pub fn advance"));
            assert!(src.contains("pub fn new"));
            let eff = effective_ops(spec);
            for op in OP_ALL {
                let want = eff.contains(&op);
                assert_eq!(
                    src.contains(&format!("fn ref_{}(", op.name())),
                    want,
                    "{:?} misaligned for seed {seed}",
                    op.name()
                );
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let sk = skeleton_src(spec, &worked_examples(seed));
            let canary = mint_canary("gray-code-counter", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in [">> 1", "count ^", "fn encode"] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("one bit"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("GrayRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soaks() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            let scripted = spec.ops.contains(&Op::Advance) && spec.ops.contains(&Op::Retreat);
            let flips = spec.ops.contains(&Op::Advance) && spec.ops.contains(&Op::GrayValue);
            assert_eq!(
                behavior.contains("scripted_walk_reverses_exactly_at_the_zero_floor"),
                scripted,
                "seed {seed}: reversal soak misaligned"
            );
            assert_eq!(
                behavior.contains("fill_soak_flips_exactly_one_bit_per_step"),
                flips,
                "seed {seed}: flip soak misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_counter_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let single = binary_increment_src(spec);
        assert!(!cz.contains("todo!()"));
        assert!(single.contains("fn advance"));
        let ps = single.find("fn advance").unwrap();
        let pe = ps + single[ps..].find("\n}\n").unwrap();
        let pb = &single[ps..pe];
        assert!(pb.contains("+= 1"), "cheat must keep the bookkeeping real");
        assert!(!pb.contains("^"), "the forgotten re-encode is the bug");
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("gray-code-counter", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
