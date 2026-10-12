//! The `moving-average-window` family (category `window-aggregate`) —
//! sliding-window puzzles where *what leaves* matters as much as what
//! enters.
//!
//! Every puzzle mirrors a fixed-capacity FIFO window over a running
//! sum: `push` evicts the oldest value once full and reports it,
//! `oldest` peeks the next victim, `mean_times_256` publishes the
//! fixed-point average the running total must stay exact for, and
//! `window_len`/`window_cap` expose the fill state any shortcut
//! distorts. The seed picks which two of five ops are required:
//! `window_cap`, `push`, `oldest`, `mean_times_256`, `window_len`.
//! Eviction must be reported — every silent cheat drifts the total.

/// One sliding window of at most `cap` values. `total` accumulates in
/// 128 bits so the fixed-point mean stays exact under heavy traffic.
#[derive(Clone)]
pub struct MovingWindowInstance {
    buf: std::collections::VecDeque<u64>,
    cap: usize,
    total: u128,
}

impl MovingWindowInstance {
    /// A fresh empty window.
    ///
    /// # Panics
    /// Panics when `capacity` is zero — a window that can hold nothing
    /// cannot aggregate, so it is rejected up front.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity >= 1, "window needs capacity");
        MovingWindowInstance {
            buf: std::collections::VecDeque::new(),
            cap: capacity,
            total: 0,
        }
    }

    /// The fixed capacity the window evicts against.
    pub fn window_cap(&self) -> u64 {
        self.cap as u64
    }

    /// How many values the window currently holds.
    pub fn window_len(&self) -> u64 {
        self.buf.len() as u64
    }

    /// Appends `value`; when the window was full the oldest value is
    /// evicted and answered as `Some(victim)`, otherwise `None`.
    pub fn push(&mut self, value: u64) -> Option<u64> {
        self.buf.push_back(value);
        self.total += value as u128;
        if self.buf.len() > self.cap {
            let victim = self.buf.pop_front().unwrap();
            self.total -= victim as u128;
            Some(victim)
        } else {
            None
        }
    }

    /// The oldest stored value — the next one `push` would evict.
    pub fn oldest(&self) -> Option<u64> {
        self.buf.front().copied()
    }

    /// The exact fixed-point mean scaled by 256 (zero while empty).
    pub fn mean_times_256(&self) -> u64 {
        if self.buf.is_empty() {
            0
        } else {
            ((self.total * 256) / self.buf.len() as u128) as u64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_then_reports_evictions() {
        let mut w = MovingWindowInstance::new(3);
        assert_eq!(w.window_cap(), 3);
        assert_eq!(w.push(10), None);
        assert_eq!(w.push(20), None);
        assert_eq!(w.push(30), None);
        assert_eq!(w.push(40), Some(10));
        assert_eq!(w.push(50), Some(20));
        assert_eq!(w.window_len(), 3);
    }

    #[test]
    fn oldest_tracks_the_next_victim() {
        let mut w = MovingWindowInstance::new(2);
        assert_eq!(w.oldest(), None);
        w.push(7);
        assert_eq!(w.oldest(), Some(7));
        w.push(9);
        assert_eq!(w.oldest(), Some(7));
        w.push(11);
        assert_eq!(w.oldest(), Some(9));
    }

    #[test]
    fn mean_stays_exact_across_evictions() {
        let mut w = MovingWindowInstance::new(3);
        assert_eq!(w.mean_times_256(), 0);
        w.push(1);
        assert_eq!(w.mean_times_256(), 256);
        w.push(2);
        assert_eq!(w.mean_times_256(), 384);
        w.push(3);
        assert_eq!(w.mean_times_256(), 512);
        w.push(4);
        // Window now holds 2, 3, 4.
        assert_eq!(w.mean_times_256(), 768);
    }

    #[test]
    fn rounding_floors_like_integer_division() {
        let mut w = MovingWindowInstance::new(2);
        w.push(1);
        w.push(2);
        assert_eq!(w.mean_times_256(), 384);
        w.push(1);
        // (2 + 1) / 2 = 1.5 -> 384 exactly; try an odd split instead.
        let mut x = MovingWindowInstance::new(3);
        x.push(1);
        x.push(1);
        x.push(2);
        assert_eq!(x.mean_times_256(), (4 * 256) / 3);
    }

    #[test]
    fn huge_values_do_not_overflow_the_running_total() {
        let big = u64::MAX / 4;
        let mut w = MovingWindowInstance::new(3);
        for _ in 0..5 {
            w.push(big);
        }
        assert_eq!(w.mean_times_256(), ((big as u128 * 3 * 256) / 3) as u64);
        assert_eq!(w.oldest(), Some(big));
    }

    #[test]
    fn soak_matches_a_shadow_window_under_random_traffic() {
        use std::collections::VecDeque;
        let mut w = MovingWindowInstance::new(8);
        let mut shadow: VecDeque<u64> = VecDeque::new();
        let mut st: u64 = 0x5EED_4D07;
        for _ in 0..600u64 {
            st = st
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let v = (st >> 33) % 1000;
            let expected = if shadow.len() == 8 {
                Some(shadow.pop_front().unwrap())
            } else {
                None
            };
            shadow.push_back(v);
            assert_eq!(w.push(v), expected);
            assert_eq!(w.window_len(), shadow.len() as u64);
            assert_eq!(
                w.mean_times_256(),
                ((shadow.iter().copied().sum::<u64>() as u128) * 256 / shadow.len() as u128) as u64
            );
        }
        assert_eq!(w.oldest(), shadow.front().copied());
    }
}

use crate::{mint_canary, GeneratedTask, Generator, Rng};

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    WindowCap,
    Push,
    Oldest,
    MeanTimes256,
    WindowLen,
}

pub const OP_ALL: [Op; 5] = [
    Op::WindowCap,
    Op::Push,
    Op::Oldest,
    Op::MeanTimes256,
    Op::WindowLen,
];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::WindowCap => "window_cap",
            Op::Push => "push",
            Op::Oldest => "oldest",
            Op::MeanTimes256 => "mean_times_256",
            Op::WindowLen => "window_len",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::WindowCap => "answers the fixed capacity the window evicts against",
            Op::Push => "appends value and answers the evicted oldest value as Some, or None when room remained",
            Op::Oldest => "answers the oldest stored value - the next one push would evict - or None while empty",
            Op::MeanTimes256 => "answers the exact fixed-point mean of the stored values scaled by 256, floored like integer division, and 0 while empty",
            Op::WindowLen => "answers how many values the window currently holds",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::WindowCap => "pub fn window_cap(&self) -> u64",
            Op::Push => "pub fn push(&mut self, value: u64) -> Option<u64>",
            Op::Oldest => "pub fn oldest(&self) -> Option<u64>",
            Op::MeanTimes256 => "pub fn mean_times_256(&self) -> u64",
            Op::WindowLen => "pub fn window_len(&self) -> u64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub const CANONICAL_SEED: u64 = 0x4D07_FA11;

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

/// Push is the fill primitive every scenario needs; when the seed did
/// not sample it, it ships as given infrastructure alongside the pair.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    if spec.ops.contains(&Op::Push) {
        spec.ops.to_vec()
    } else {
        let mut v = vec![Op::Push];
        v.extend_from_slice(&spec.ops);
        v
    }
}

/// The canonical scenario: a nine-slot window hammered by dozens of
/// pseudo-random pushes, so eviction starts early and any solution
/// that mis-reports a victim or drifts the running total is wrong
/// before the first probe.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical moving-window scenario");
}

fn fresh_window(cap: u64) -> MovingWindowInstance {
    MovingWindowInstance::new(cap as usize)
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub cap: u64,
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01BC;

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![
        ExampleCase {
            cap: 9,
            warmup: canonical(seed),
        },
        ExampleCase { cap: 2, warmup: 3 },
        ExampleCase { cap: 4, warmup: 4 },
        ExampleCase {
            cap: 16,
            warmup: 17,
        },
    ];
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    for _ in 0..8 {
        let cap = 1 + rng.below(24);
        out.push(ExampleCase {
            cap,
            warmup: rng.below(cap * 3) + 3,
        });
    }
    out
}

const NX_MUL: u64 = 6364136223846793005;
const NX_ADD: u64 = 1442695040888963407;

/// One LCG draw.
fn nxt(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    *state >> 33
}

/// The drive's LCG state after `warmup` draws (one bounded value per
/// push). Emitted tests re-derive this to probe one step past the end.
fn drive_base(cap: u64, warmup: u64) -> u64 {
    let mut s = 0x4D07_CAFE ^ cap.wrapping_mul(0x9E37).wrapping_add(warmup);
    for _ in 0..warmup {
        s = s.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    }
    s
}

/// Drives `warmup` pseudo-random pushes into a fresh window; values
/// stay below 1000 so the exact mean stays easy to reason about.
fn driven_window(cap: u64, warmup: u64) -> (MovingWindowInstance, Vec<u64>) {
    let mut w = fresh_window(cap);
    let mut st = 0x4D07_CAFE ^ cap.wrapping_mul(0x9E37).wrapping_add(warmup);
    let mut pushed = Vec::new();
    for _ in 0..warmup {
        let v = nxt(&mut st) % 1000;
        w.push(v);
        pushed.push(v);
    }
    (w, pushed)
}

// ---- emitted-source fragments -----------------------------------------------

pub const STRUCT_SRC: &str = "#[derive(Clone)]\npub struct MovingWindow {\n    buf: std::collections::VecDeque<u64>,\n    cap: usize,\n    total: u128,\n}\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::WindowCap => &["self.cap as u64"],
        Op::WindowLen => &["self.buf.len() as u64"],
        Op::Push => &[
            "self.buf.push_back(value);",
            "self.total += value as u128;",
            "if self.buf.len() > self.cap {",
            "    let victim = self.buf.pop_front().unwrap();",
            "    self.total -= victim as u128;",
            "    Some(victim)",
            "} else {",
            "    None",
            "}",
        ],
        Op::Oldest => &["self.buf.front().copied()"],
        Op::MeanTimes256 => &[
            "if self.buf.is_empty() {",
            "    0",
            "} else {",
            "    ((self.total * 256) / self.buf.len() as u128) as u64",
            "}",
        ],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub const WINDOW_NEW_SRC: &str = "impl MovingWindow {\n    pub fn new(capacity: usize) -> Self {\n        assert!(capacity >= 1);\n        MovingWindow {\n            buf: std::collections::VecDeque::new(),\n            cap: capacity,\n            total: 0,\n        }\n    }\n}\n\n";

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen(
        "pub struct MovingWindow {",
        "pub struct MovingWindowRef {",
        1,
    );
    s.push_str(
        &WINDOW_NEW_SRC
            .replace("impl MovingWindow {", "impl MovingWindowRef {")
            .replace("MovingWindow {\n", "MovingWindowRef {\n"),
    );
    s.push_str("impl MovingWindowRef {\n");
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
        let (w, _) = driven_window(ex.cap, ex.warmup);
        s.push_str(&format!(
            "//! ex{i}: capacity {c}, then {n} pseudo-random pushes -> len {l}, mean*256 {m}\n",
            i = i,
            c = ex.cap,
            n = ex.warmup,
            l = w.window_len(),
            m = w.mean_times_256()
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested sliding-window operations over one\n\
         //! fixed-capacity FIFO of values. Appends evict the oldest value\n\
         //! once full and must report every victim; queries expose the\n\
         //! exact running aggregate. The hidden tests drive thousands\n\
         //! of interleaved operations and compare every returned\n\
         //! value.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(WINDOW_NEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested sliding-window operations with an exactly maintained aggregate.\n\nRequirements:\n- `MovingWindow::new(capacity)` starts empty and rejects a zero capacity.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- Once the window holds `capacity` values every further push first evicts the oldest value, and the evicted victim must be answered; pushes into room answer `None`. Nothing may be dropped silently.\n- The mean must be computed over exactly the values currently stored - eviction has to unwind the victim's contribution before the next query.\n- The mean scale is 256 with floor rounding, and an empty window answers 0. No floating point; no unsafe code; standard library only.\n\nSignatures:\n```rust\n");
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
    let mut s = String::from(
        "use task::MovingWindow;\n\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n",
    );
    for (i, ex) in examples.iter().enumerate() {
        let (h, _) = driven_window(ex.cap, ex.warmup);
        // Draw the probe arguments exactly one step past the warmup.
        let mut ps = drive_base(ex.cap, ex.warmup);
        let cap_now = h.window_cap();
        let len_now = h.window_len();
        let mean_now = h.mean_times_256();
        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let mut drive = MovingWindow::new({c});\n    let mut st: u64 = 0x4D07_CAFE ^ ({c}u64.wrapping_mul(0x9E37).wrapping_add({n}));\n    for _ in 0..{n} {{\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        drive.push((st >> 33) % 1000);\n    }}\n",
            i = i,
            c = ex.cap,
            n = ex.warmup
        ));
        for &op in &spec.ops {
            s.push_str("    let mut r = drive.clone();\n");
            match op {
                Op::WindowCap => {
                    s.push_str(&format!("    assert_eq!(r.window_cap(), {cap_now});\n"));
                }
                Op::WindowLen => {
                    s.push_str(&format!("    assert_eq!(r.window_len(), {len_now});\n"));
                }
                Op::MeanTimes256 => {
                    s.push_str(&format!(
                        "    assert_eq!(r.mean_times_256(), {mean_now});\n"
                    ));
                }
                Op::Push => {
                    let v = nxt(&mut ps) % 1000;
                    let want = h
                        .clone()
                        .push(v)
                        .map_or_else(|| "None".to_string(), |x| format!("Some({x})"));
                    s.push_str(&format!("    assert_eq!(r.push({v}), {want});\n"));
                }
                Op::Oldest => {
                    let want = h
                        .oldest()
                        .map_or_else(|| "None".to_string(), |x| format!("Some({x})"));
                    s.push_str(&format!("    assert_eq!(r.oldest(), {want});\n"));
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Scripted exact-mean probe: five pushes through a three-slot
    // window pin both the eviction reports and the running mean.
    if spec.ops.contains(&Op::Push) && spec.ops.contains(&Op::MeanTimes256) {
        s.push_str("#[test]\nfn scripted_eviction_keeps_the_running_mean_exact() {\n    let mut r = MovingWindow::new(3);\n    assert_eq!(r.push(1), None);\n    assert_eq!(r.mean_times_256(), 256);\n    assert_eq!(r.push(2), None);\n    assert_eq!(r.mean_times_256(), 384);\n    assert_eq!(r.push(3), None);\n    assert_eq!(r.mean_times_256(), 512);\n    assert_eq!(r.push(4), Some(1));\n    assert_eq!(r.mean_times_256(), 768);\n    assert_eq!(r.push(5), Some(2));\n    assert_eq!(r.mean_times_256(), 1024);\n}\n");
    }
    // Fill soak: random pushes over a four-slot window must keep the
    // eviction report and the oldest value pinned to a shadow mirror.
    if spec.ops.contains(&Op::Push) && spec.ops.contains(&Op::Oldest) {
        s.push_str("#[test]\nfn fill_soak_matches_a_shadow_front() {\n    let mut r = MovingWindow::new(4);\n    let mut shadow = std::collections::VecDeque::new();\n    let mut st: u64 = 0x5EED_0000_0000_01BC;\n    for _ in 0..800u64 {\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        let v = (st >> 33) % 1000;\n        let expected = if shadow.len() == 4 { Some(shadow.pop_front().unwrap()) } else { None };\n        shadow.push_back(v);\n        assert_eq!(r.push(v), expected);\n        assert_eq!(r.oldest(), shadow.front().copied());\n    }\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::MovingWindow;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    let ops = effective_ops(spec);
    s.push_str("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {\n    let mut cand = MovingWindow::new(12);\n    let mut refr = MovingWindowRef::new(12);\n");
    if ops.contains(&Op::Push) {
        s.push_str("    assert_eq!(cand.push(7), refr.ref_push(7));\n");
    }
    if ops.contains(&Op::Oldest) {
        s.push_str("    assert_eq!(cand.oldest(), refr.ref_oldest());\n");
    }
    if ops.contains(&Op::MeanTimes256) {
        s.push_str("    assert_eq!(cand.mean_times_256(), refr.ref_mean_times_256());\n");
    }
    if ops.contains(&Op::WindowLen) {
        s.push_str("    assert_eq!(cand.window_len(), refr.ref_window_len());\n");
    }
    if ops.contains(&Op::WindowCap) {
        s.push_str("    assert_eq!(cand.window_cap(), refr.ref_window_cap());\n");
    }
    let arm_count = ops.len();
    s.push_str(&format!("    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_01BC;\n    for _ in 0..3000 {{\n        let arg = nx(&mut state);\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in ops.iter().enumerate() {
        let body = match op {
            Op::Push => "assert_eq!(cand.push(arg % 97), refr.ref_push(arg % 97));".to_string(),
            Op::Oldest => "assert_eq!(cand.oldest(), refr.ref_oldest());".to_string(),
            Op::MeanTimes256 => {
                "assert_eq!(cand.mean_times_256(), refr.ref_mean_times_256());".to_string()
            }
            Op::WindowLen => "assert_eq!(cand.window_len(), refr.ref_window_len());".to_string(),
            Op::WindowCap => "assert_eq!(cand.window_cap(), refr.ref_window_cap());".to_string(),
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
    s.push_str(WINDOW_NEW_SRC);
    s.push_str("impl MovingWindow {\n");
    for &op in &ops {
        let body = match op {
            Op::WindowCap | Op::MeanTimes256 | Op::WindowLen => "0",
            Op::Push | Op::Oldest => "None",
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s.push_str("}\n");
    s
}

/// The plausible silent-evict cheat: identical bookkeeping, but the
/// evicted victim is dropped without being reported — every push into
/// a full window answers None. Singleton pushes look fine; the first
/// overflow lies about what left the window.
pub fn silent_evict_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(WINDOW_NEW_SRC);
    s.push_str("impl MovingWindow {\n");
    for &op in &ops {
        if op == Op::Push {
            let body = &[
                "self.buf.push_back(value);",
                "self.total += value as u128;",
                "if self.buf.len() > self.cap {",
                "    let victim = self.buf.pop_front().unwrap();",
                "    self.total -= victim as u128;",
                "}",
                "None",
            ];
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

pub struct MovingAverageFamily;

impl Generator for MovingAverageFamily {
    fn id(&self) -> &'static str {
        "moving-average"
    }

    fn category(&self) -> &'static str {
        "window-aggregate"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("moving-average", seed);
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
            id: format!("moving-average/{seed:016x}"),
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
        s.push_str(WINDOW_NEW_SRC);
        s.push_str("impl MovingWindow {\n");
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
            ("silent-evict".to_string(), silent_evict_src(spec)),
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
        let a = MovingAverageFamily.generate(55);
        let b = MovingAverageFamily.generate(55);
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
            let (w, pushed) = driven_window(9, warmup);
            assert_eq!(pushed.len(), warmup as usize);
            assert!(w.window_len() <= 9);
            assert_eq!(w.window_cap(), 9);
            assert!(w.oldest().is_some());
            assert!(w.mean_times_256() <= 256_000);
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let (w, _) = driven_window(ex.cap, ex.warmup);
                assert!(w.window_len() <= ex.cap);
                assert_eq!(w.window_cap(), ex.cap);
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct MovingWindowRef"));
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
            let canary = mint_canary("moving-average", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in [".front()", "pop_front", "as u128"] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("evicted"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("MovingWindowRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soaks() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            let scripted = spec.ops.contains(&Op::Push) && spec.ops.contains(&Op::MeanTimes256);
            let pins = spec.ops.contains(&Op::Push) && spec.ops.contains(&Op::Oldest);
            assert_eq!(
                behavior.contains("scripted_eviction_keeps_the_running_mean_exact"),
                scripted,
                "seed {seed}: mean soak misaligned"
            );
            assert_eq!(
                behavior.contains("fill_soak_matches_a_shadow_front"),
                pins,
                "seed {seed}: front soak misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_window_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let single = silent_evict_src(spec);
        assert!(!cz.contains("push_back"));
        assert!(single.contains("fn push"));
        let ps = single.find("fn push").unwrap();
        let pe = ps + single[ps..].find("\n}\n").unwrap();
        let pb = &single[ps..pe];
        assert!(
            pb.contains("pop_front"),
            "cheat must still evict internally"
        );
        assert!(!pb.contains("Some("), "cheat must drop the eviction report");
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("moving-average", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
