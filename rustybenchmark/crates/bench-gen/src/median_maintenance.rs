//! Median-maintenance natives: a two-half running median over a stream.
//! The smaller half lives in a max-heap, the larger half in a min-heap,
//! the halves never differ by more than one element, and every push
//! answers the freshly updated running median scaled by 256.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

#[derive(Clone, Default)]
pub struct MedianInstance {
    /// Smaller half as a max-heap; holds either the same count as `high`
    /// or exactly one more.
    low: BinaryHeap<u64>,
    /// Larger half as a min-heap (via Reverse).
    high: BinaryHeap<Reverse<u64>>,
}

impl MedianInstance {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn med_len(&self) -> u64 {
        (self.low.len() + self.high.len()) as u64
    }

    /// Route the value to the correct half, rebalance so neither half is
    /// more than one ahead of the other, then answer the running median
    /// times 256: an odd count answers its middle value times 256 and an
    /// even count answers the mean of the two middle values times 256.
    pub fn push(&mut self, value: u64) -> u64 {
        let goes_high = match self.high.peek() {
            Some(top) => value > top.0,
            None => false,
        };
        if goes_high {
            self.high.push(Reverse(value));
        } else {
            self.low.push(value);
        }
        if self.low.len() > self.high.len() + 1 {
            let moved = self.low.pop().unwrap();
            self.high.push(Reverse(moved));
        } else if self.high.len() > self.low.len() {
            let moved = self.high.pop().unwrap().0;
            self.low.push(moved);
        }
        let total = self.low.len() + self.high.len();
        let l = self.low.peek().copied();
        let h = self.high.peek().map(|r| r.0);
        if total % 2 == 1 {
            l.unwrap_or(0) * 256
        } else {
            match (l, h) {
                (Some(l), Some(h)) => (l + h) * 128,
                _ => 0,
            }
        }
    }

    /// The current running median times 256, or None on an empty stream:
    /// odd counts answer middle*256, even counts answer the mean of the
    /// two middles times 256.
    pub fn median_x256(&self) -> Option<u64> {
        let l = self.low.peek().copied();
        let h = self.high.peek().map(|r| r.0);
        match (self.low.len() + self.high.len()) % 2 {
            1 => Some(l.unwrap_or(0) * 256),
            _ => match (l, h) {
                (Some(l), Some(h)) => Some((l + h) * 128),
                _ => None,
            },
        }
    }

    /// The largest value of the lower half (the odd-count median), or None
    /// when empty.
    pub fn low_max(&self) -> Option<u64> {
        self.low.peek().copied()
    }

    /// The smallest value of the upper half (the even-count upper middle),
    /// or None when empty.
    pub fn high_min(&self) -> Option<u64> {
        self.high.peek().map(|r| r.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_answers_the_running_median() {
        let mut m = MedianInstance::new();
        assert_eq!(m.push(3), 3 * 256);
        assert_eq!(m.push(9), (3 + 9) * 128);
        assert_eq!(m.push(4), 4 * 256);
        assert_eq!(m.push(8), (4 + 8) * 128);
        assert_eq!(m.med_len(), 4);
    }

    #[test]
    fn halves_stay_adjacent_under_every_push() {
        let mut m = MedianInstance::new();
        for v in [7u64, 2, 9, 4, 11, 6, 6, 1, 15] {
            m.push(v);
            assert!((m.low.len() as i64 - m.high.len() as i64).abs() <= 1);
            assert!(m
                .low
                .iter()
                .all(|&x| x <= *m.high.peek().map(|r| &r.0).unwrap_or(&u64::MAX)));
        }
        assert_eq!(m.median_x256(), Some(6 * 256));
    }

    #[test]
    fn fresh_stream_answers_none_everywhere() {
        let m = MedianInstance::new();
        assert_eq!(m.med_len(), 0);
        assert_eq!(m.median_x256(), None);
        assert_eq!(m.low_max(), None);
        assert_eq!(m.high_min(), None);
    }

    #[test]
    fn duplicates_keep_the_median_exact() {
        let mut m = MedianInstance::new();
        assert_eq!(m.push(5), 5 * 256);
        assert_eq!(m.push(5), (5 + 5) * 128);
        assert_eq!(m.push(5), 5 * 256);
        assert_eq!(m.push(5), (5 + 5) * 128);
        assert_eq!(m.low_max(), Some(5));
        assert_eq!(m.high_min(), Some(5));
    }

    #[test]
    fn queries_agree_with_each_other_on_odd_and_even_counts() {
        let mut m = MedianInstance::new();
        for v in [10u64, 20] {
            m.push(v);
        }
        // even: two middles 10 and 20
        assert_eq!(m.median_x256(), Some((10 + 20) * 128));
        assert_eq!(m.low_max(), Some(10));
        assert_eq!(m.high_min(), Some(20));
        m.push(30);
        // odd: single middle 20
        assert_eq!(m.median_x256(), Some(20 * 256));
        assert_eq!(m.low_max(), Some(20));
        assert_eq!(m.high_min(), Some(30));
    }

    #[test]
    fn soak_matches_a_sorted_shadow_under_random_traffic() {
        let mut shadow: Vec<u64> = Vec::new();
        let mut m = MedianInstance::new();
        let mut st: u64 = 0x5EED_6E04;
        for _ in 0..600 {
            let v = (st >> 33) % 200;
            m.push(v);
            shadow.push(v);
            shadow.sort_unstable();
            let n = shadow.len();
            let want = if n % 2 == 1 {
                shadow[n / 2] * 256
            } else {
                (shadow[(n - 1) / 2] + shadow[n / 2]) * 128
            };
            assert_eq!(m.median_x256(), Some(want));
            assert_eq!(m.med_len() as usize, n);
            assert_eq!(m.low_max(), Some(shadow[(n - 1) / 2]));
            assert_eq!(
                m.high_min(),
                if n > 1 {
                    Some(shadow[n.div_ceil(2)])
                } else {
                    None
                }
            );
            st = st
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
        }
    }
}

use crate::{mint_canary, GeneratedTask, Generator, Rng};

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    MedLen,
    Push,
    MedianX256,
    LowMax,
    HighMin,
}

pub const OP_ALL: [Op; 5] = [
    Op::MedLen,
    Op::Push,
    Op::MedianX256,
    Op::LowMax,
    Op::HighMin,
];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::MedLen => "med_len",
            Op::Push => "push",
            Op::MedianX256 => "median_x256",
            Op::LowMax => "low_max",
            Op::HighMin => "high_min",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::MedLen => "answers how many values the stream currently holds",
            Op::Push => "routes one incoming value into the correct half, rebalances so neither half leads by more than one, and answers the freshly updated running median times 256",
            Op::MedianX256 => "answers the current running median times 256 - an odd count answers its single middle value times 256, an even count answers the mean of the two middle values times 256 - or None while the stream is empty",
            Op::LowMax => "answers the largest value sitting in the lower half, or None while the stream is empty",
            Op::HighMin => "answers the smallest value sitting in the upper half, or None until the upper half receives a value",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::MedLen => "pub fn med_len(&self) -> u64",
            Op::Push => "pub fn push(&mut self, value: u64) -> u64",
            Op::MedianX256 => "pub fn median_x256(&self) -> Option<u64>",
            Op::LowMax => "pub fn low_max(&self) -> Option<u64>",
            Op::HighMin => "pub fn high_min(&self) -> Option<u64>",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub const CANONICAL_SEED: u64 = 0x6E04_FA11;

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

/// Push is the fill primitive and the median query is the audit probe;
/// both ship as given infrastructure alongside the sampled pair, so a
/// solution with honest halves that still answers the lower middle on
/// every even count drifts on the very next push no matter which pair
/// was drawn.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    let mut v = vec![Op::Push];
    if !spec.ops.contains(&Op::MedianX256) {
        v.push(Op::MedianX256);
    }
    for o in spec.ops {
        if !v.contains(&o) {
            v.push(o);
        }
    }
    v
}

/// The canonical scenario: dozens of pushes over a wide span so odd and
/// even counts alternate constantly.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical median-maintenance scenario");
}

fn fresh_median() -> MedianInstance {
    MedianInstance::new()
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub span: u64,
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01D0;

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![
        ExampleCase {
            span: 32,
            warmup: canonical(seed),
        },
        ExampleCase { span: 5, warmup: 3 },
        ExampleCase { span: 8, warmup: 4 },
        ExampleCase {
            span: 16,
            warmup: 17,
        },
    ];
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    for _ in 0..8 {
        let span = 3 + rng.below(46);
        out.push(ExampleCase {
            span,
            warmup: rng.below(span * 3) + 2,
        });
    }
    out
}

const NX_MUL: u64 = 6364136223846793005;
const NX_ADD: u64 = 1442695040888963407;

fn drive_init(span: u64, warmup: u64) -> u64 {
    0x6E04_CAFEu64 ^ span.wrapping_mul(0x9E37).wrapping_add(warmup)
}

/// Drives `warmup` random pushes (values below `span`) into a fresh stream.
fn driven_median(span: u64, warmup: u64) -> MedianInstance {
    let mut m = fresh_median();
    let mut st = drive_init(span, warmup);
    for _ in 0..warmup {
        m.push((st >> 33) % span);
        st = st.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    }
    m
}

/// The probe-continuation state after the drive loop (one advance per push).
fn drive_final_state(span: u64, warmup: u64) -> u64 {
    let mut st = drive_init(span, warmup);
    for _ in 0..warmup {
        st = st.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    }
    st
}

/// One LCG draw: advance then take the high bits.
fn nx(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    *state >> 33
}

fn opt_fmt(v: Option<u64>) -> String {
    v.map_or_else(|| "None".to_string(), |x| format!("Some({x})"))
}

// ---- emitted-source fragments -----------------------------------------------

pub const STRUCT_SRC: &str =
    "#[derive(Clone)]\npub struct MedianTracker {\n    low: Vec<u64>,\n    high: Vec<u64>,\n}\n";

pub const TRACKER_NEW_SRC: &str = "impl MedianTracker {\n    pub fn new() -> Self {\n        MedianTracker {\n            low: Vec::new(),\n            high: Vec::new(),\n        }\n    }\n}\n\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

const PUSH_BODY: &[&str] = &[
    "let goes_high = match self.high.first() {",
    "    Some(top) => value > *top,",
    "    None => false,",
    "};",
    "if goes_high {",
    "    let mut at = self.high.len();",
    "    while at > 0 && self.high[at - 1] > value {",
    "        at -= 1;",
    "    }",
    "    self.high.insert(at, value);",
    "} else {",
    "    let mut at = self.low.len();",
    "    while at > 0 && self.low[at - 1] < value {",
    "        at -= 1;",
    "    }",
    "    self.low.insert(at, value);",
    "}",
    "if self.low.len() > self.high.len() + 1 {",
    "    let moved = self.low.remove(0);",
    "    self.high.insert(0, moved);",
    "} else if self.high.len() > self.low.len() {",
    "    let moved = self.high.remove(0);",
    "    let mut at = self.low.len();",
    "    while at > 0 && self.low[at - 1] < moved {",
    "        at -= 1;",
    "    }",
    "    self.low.insert(at, moved);",
    "}",
    "if (self.low.len() + self.high.len()) % 2 == 1 {",
    "    self.low[0] * 256",
    "} else {",
    "    (self.low[0] + self.high[0]) * 128",
    "}",
];

const MEDIAN_BODY: &str = "let l = self.low.first().copied();\nlet h = self.high.first().copied();\nif (self.low.len() + self.high.len()) % 2 == 1 {\n    Some(l.unwrap_or(0) * 256)\n} else {\n    match (l, h) {\n        (Some(l), Some(h)) => Some((l + h) * 128),\n        _ => None,\n    }\n}";

pub fn op_fn_src(op: Op) -> String {
    let body: String = match op {
        Op::MedLen => "(self.low.len() + self.high.len()) as u64".to_string(),
        Op::Push => PUSH_BODY.join("\n    "),
        Op::MedianX256 => MEDIAN_BODY.to_string(),
        Op::LowMax => "self.low.first().copied()".to_string(),
        Op::HighMin => "self.high.first().copied()".to_string(),
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body)
}

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen(
        "pub struct MedianTracker {",
        "pub struct MedianTrackerRef {",
        1,
    );
    s.push_str(
        &TRACKER_NEW_SRC
            .replace("impl MedianTracker {", "impl MedianTrackerRef {")
            .replace("MedianTracker {\n", "MedianTrackerRef {\n"),
    );
    s.push_str("impl MedianTrackerRef {\n");
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
        let m = driven_median(ex.span, ex.warmup);
        s.push_str(&format!(
            "//! ex{i}: {w} pushed values below {span} -> holds {l}, median x256 {m}, lower-middle {lm}\n",
            i = i,
            w = ex.warmup,
            span = ex.span,
            l = m.med_len(),
            m = opt_fmt(m.median_x256()),
            lm = opt_fmt(m.low_max()),
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested running-median operations over one\n\
         //! internal two-half collection: the smaller values form the lower\n\
         //! half, the larger values form the upper half, the halves never\n\
         //! differ by more than one element, and every push answers the\n\
         //! freshly updated median scaled by 256. The hidden tests drive\n\
         //! thousands of interleaved operations and compare every returned\n\
         //! value.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(TRACKER_NEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested running-median operations with exactly maintained bookkeeping.\n\nRequirements:\n- `MedianTracker::new()` starts with an empty stream; the constructor is given.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- The lower half holds the smaller values and the upper half holds the larger values; after every push the two halves differ in size by at most one, and every lower value stays at or below every upper value.\n- An odd count of values answers its single middle value times 256; an even count answers the mean of the two middle values times 256. Every push answers the freshly updated running median under this rule.\n- Queries never mutate the stream; on an empty stream the median query, low_max and high_min all answer None.\n- No floating point; no unsafe code; standard library only.\n\nSignatures:\n```rust\n");
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
    let mut s = String::from("use task::MedianTracker;\n\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n");
    for (i, ex) in examples.iter().enumerate() {
        let h = driven_median(ex.span, ex.warmup);
        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let mut drive = MedianTracker::new();\n    let mut st: u64 = {init};\n    for _ in 0..{w} {{\n        drive.push((st >> 33) % {span}u64);\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    }}\n",
            i = i,
            w = ex.warmup,
            span = ex.span,
            init = drive_init(ex.span, ex.warmup)
        ));
        s.push_str(&format!(
            "    let mut ps: u64 = {};\n",
            drive_final_state(ex.span, ex.warmup)
        ));
        let mut ps = drive_final_state(ex.span, ex.warmup);
        for &op in &spec.ops {
            match op {
                Op::MedLen => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.med_len(), {});\n",
                        h.med_len()
                    ));
                }
                Op::MedianX256 => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.median_x256(), {});\n",
                        opt_fmt(h.median_x256())
                    ));
                }
                Op::LowMax => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.low_max(), {});\n",
                        opt_fmt(h.low_max())
                    ));
                }
                Op::HighMin => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.high_min(), {});\n",
                        opt_fmt(h.high_min())
                    ));
                }
                Op::Push => {
                    let v = nx(&mut ps) % ex.span;
                    let want = h.clone().push(v);
                    s.push_str(&format!(
                        "    let mut r = drive.clone();\n    let v = nx(&mut ps) % {span}u64;\n    assert_eq!(r.push(v), {want});\n",
                        span = ex.span,
                        want = want
                    ));
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Scripted probe: even counts must average the two middles - a solution
    // that always answers the lower middle fails from the second push on.
    if spec.ops.contains(&Op::Push) && spec.ops.contains(&Op::MedianX256) {
        s.push_str("#[test]\nfn scripted_even_counts_average_the_two_middles() {\n    let mut r = MedianTracker::new();\n    assert_eq!(r.push(10), 2560);\n    assert_eq!(r.push(20), 3840);\n    assert_eq!(r.push(30), 5120);\n    assert_eq!(r.push(25), 5760);\n    assert_eq!(r.median_x256(), Some(5760));\n}\n");
    }
    // Scripted probe: odd counts answer the lower middle exactly.
    if spec.ops.contains(&Op::Push) && spec.ops.contains(&Op::LowMax) {
        s.push_str("#[test]\nfn scripted_odd_counts_answer_the_lower_middle() {\n    let mut r = MedianTracker::new();\n    assert_eq!(r.low_max(), None);\n    assert_eq!(r.push(7), 1792);\n    assert_eq!(r.low_max(), Some(7));\n    assert_eq!(r.push(9), 2048);\n    assert_eq!(r.low_max(), Some(7));\n    assert_eq!(r.push(8), 2048);\n    assert_eq!(r.low_max(), Some(8));\n}\n");
    }
    // Fill soak: eight hundred random pushes must keep both the answered
    // median and the upper middle pinned to a sorted shadow.
    if spec.ops.contains(&Op::Push) && spec.ops.contains(&Op::HighMin) {
        s.push_str("#[test]\nfn fill_soak_keeps_the_upper_middle_pinned_to_a_shadow() {\n    let mut r = MedianTracker::new();\n    let mut shadow: Vec<u64> = Vec::new();\n    let mut st: u64 = 0x5EED_0000_0000_01D2;\n    for _ in 0..800usize {\n        let v = (st >> 33) % 60;\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        let answered = r.push(v);\n        shadow.push(v);\n        shadow.sort_unstable();\n        let n = shadow.len();\n        let want = if n % 2 == 1 {\n            shadow[n / 2] * 256\n        } else {\n            (shadow[(n - 1) / 2] + shadow[n / 2]) * 128\n        };\n        assert_eq!(answered, want);\n        let expect = if n > 1 {\n            Some(shadow[n.div_ceil(2)])\n        } else {\n            None\n        };\n        assert_eq!(r.high_min(), expect);\n    }\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::MedianTracker;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    let ops = effective_ops(spec);
    s.push_str("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {\n    let mut cand = MedianTracker::new();\n    let mut refr = MedianTrackerRef::new();\n");
    if ops.contains(&Op::MedLen) {
        s.push_str("    assert_eq!(cand.med_len(), refr.ref_med_len());\n");
    }
    if ops.contains(&Op::MedianX256) {
        s.push_str("    assert_eq!(cand.median_x256(), refr.ref_median_x256());\n");
    }
    if ops.contains(&Op::LowMax) {
        s.push_str("    assert_eq!(cand.low_max(), refr.ref_low_max());\n");
    }
    if ops.contains(&Op::HighMin) {
        s.push_str("    assert_eq!(cand.high_min(), refr.ref_high_min());\n");
    }
    if ops.contains(&Op::Push) {
        for v in [40u64, 41, 42, 43, 44, 45, 12, 99, 3, 77] {
            s.push_str(&format!(
                "    assert_eq!(cand.push({v}), refr.ref_push({v}));\n"
            ));
        }
    }
    let arm_count = ops.len();
    s.push_str(&format!("    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_01D0;\n    for _ in 0..3000 {{\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in ops.iter().enumerate() {
        let body = match op {
            Op::MedLen => "assert_eq!(cand.med_len(), refr.ref_med_len());".to_string(),
            Op::Push => "let v = nx(&mut state) % 97;\n            assert_eq!(cand.push(v), refr.ref_push(v));".to_string(),
            Op::MedianX256 => "assert_eq!(cand.median_x256(), refr.ref_median_x256());".to_string(),
            Op::LowMax => "assert_eq!(cand.low_max(), refr.ref_low_max());".to_string(),
            Op::HighMin => "assert_eq!(cand.high_min(), refr.ref_high_min());".to_string(),
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
    s.push_str(TRACKER_NEW_SRC);
    s.push_str("impl MedianTracker {\n");
    for &op in &ops {
        let body = match op {
            Op::MedianX256 | Op::LowMax | Op::HighMin => "None",
            _ => "0",
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s.push_str("}\n");
    s
}

/// The plausible cheat: routing and rebalancing stay honest, but the parity
/// branch is skipped - every count is treated as odd, so the answer is always
/// the lower middle times 256 and even-count means are never taken.
pub fn lower_middle_always_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(TRACKER_NEW_SRC);
    s.push_str("impl MedianTracker {\n");
    for &op in &ops {
        match op {
            Op::Push => {
                let mut body: Vec<&str> = PUSH_BODY[..PUSH_BODY.len() - 6].to_vec();
                body.push("self.low[0] * 256");
                s.push_str(&format!(
                    "{} {{\n    {}\n}}\n",
                    op_sig_src(op),
                    body.join("\n    ")
                ));
            }
            Op::MedianX256 => {
                s.push_str(&format!(
                    "{} {{\n    match self.low.first() {{\n        Some(top) => Some(*top * 256),\n        None => None,\n    }}\n}}\n",
                    op_sig_src(op)
                ));
            }
            _ => s.push_str(&op_fn_src(op)),
        }
    }
    s.push_str("}\n");
    s
}

pub struct MedianMaintenanceFamily;

impl Generator for MedianMaintenanceFamily {
    fn id(&self) -> &'static str {
        "median-maintenance"
    }

    fn category(&self) -> &'static str {
        "running-median"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("median-maintenance", seed);
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
            id: format!("median-maintenance/{seed:016x}"),
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
        s.push_str(TRACKER_NEW_SRC);
        s.push_str("impl MedianTracker {\n");
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
            (
                "lower-middle-always".to_string(),
                lower_middle_always_src(spec),
            ),
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
        let a = MedianMaintenanceFamily.generate(55);
        let b = MedianMaintenanceFamily.generate(55);
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
            let m = driven_median(32, warmup);
            assert_eq!(m.med_len(), warmup);
            let med = m.median_x256();
            assert!(med.is_some());
            assert!(med.unwrap() <= 32 * 256);
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let m = driven_median(ex.span, ex.warmup);
                assert_eq!(m.med_len(), ex.warmup);
                assert!(ex.warmup >= 2);
                assert!(ex.span >= 3 && ex.span < 49);
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct MedianTrackerRef"));
            assert!(
                src.matches("MedianTrackerRef {").count() >= 2,
                "constructor body must be renamed too"
            );
            assert!(!src.contains("pub fn push"));
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
            let canary = mint_canary("median-maintenance", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in ["* 128", ".remove(", "div_ceil"] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("median"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("MedianTrackerRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soaks() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            let avg_gate = spec.ops.contains(&Op::Push) && spec.ops.contains(&Op::MedianX256);
            let odd_gate = spec.ops.contains(&Op::Push) && spec.ops.contains(&Op::LowMax);
            let soak_gate = spec.ops.contains(&Op::Push) && spec.ops.contains(&Op::HighMin);
            assert_eq!(
                behavior.contains("scripted_even_counts_average_the_two_middles"),
                avg_gate,
                "seed {seed}: even script misaligned"
            );
            assert_eq!(
                behavior.contains("scripted_odd_counts_answer_the_lower_middle"),
                odd_gate,
                "seed {seed}: odd script misaligned"
            );
            assert_eq!(
                behavior.contains("fill_soak_keeps_the_upper_middle_pinned_to_a_shadow"),
                soak_gate,
                "seed {seed}: shadow soak misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_running_median_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let cheat = lower_middle_always_src(spec);
        assert!(!cz.contains("todo!()"));
        assert!(cheat.contains("fn push"));
        let us = cheat.find("fn push").unwrap();
        let ue = us + cheat[us..].find("\n}\n").unwrap();
        let ub = &cheat[us..ue];
        assert!(
            ub.contains("self.low[0] * 256"),
            "cheat must keep the routing real but skip parity"
        );
        assert!(!ub.contains("% 2"), "the skipped parity branch is the bug");
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("median-maintenance", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
