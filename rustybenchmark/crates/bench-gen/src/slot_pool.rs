//! Slot-pool natives: a fixed-capacity slot allocator. Allocation always
//! hands out the lowest-numbered free slot, release refuses both unknown
//! and already-free slots, and every liveness query must stay exact even
//! as slots churn.

#[derive(Clone)]
pub struct SlotPoolInstance {
    /// slots[i] is true while slot i is live.
    slots: Vec<bool>,
}

impl SlotPoolInstance {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity >= 1);
        Self {
            slots: vec![false; capacity],
        }
    }

    pub fn pool_cap(&self) -> u64 {
        self.slots.len() as u64
    }

    pub fn live_count(&self) -> u64 {
        self.slots.iter().filter(|&&live| live).count() as u64
    }

    /// Hands out the lowest-numbered free slot, marking it live; None when
    /// the pool is full.
    pub fn alloc(&mut self) -> Option<u32> {
        let at = self.slots.iter().position(|&live| !live)?;
        self.slots[at] = true;
        Some(at as u32)
    }

    /// Frees a live slot; false when the slot is out of range or already
    /// free (double release).
    pub fn release(&mut self, slot: u32) -> bool {
        let i = slot as usize;
        if i >= self.slots.len() || !self.slots[i] {
            return false;
        }
        self.slots[i] = false;
        true
    }

    /// Liveness of a slot; false when out of range.
    pub fn is_live(&self, slot: u32) -> bool {
        self.slots.get(slot as usize).copied().unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_fills_the_lowest_slots_first() {
        let mut p = SlotPoolInstance::new(4);
        assert_eq!(p.alloc(), Some(0));
        assert_eq!(p.alloc(), Some(1));
        assert_eq!(p.alloc(), Some(2));
        assert_eq!(p.alloc(), Some(3));
        assert_eq!(p.alloc(), None);
        assert_eq!(p.pool_cap(), 4);
        assert_eq!(p.live_count(), 4);
    }

    #[test]
    fn released_slots_are_reused_lowest_first() {
        let mut p = SlotPoolInstance::new(3);
        for _ in 0..3 {
            p.alloc();
        }
        assert!(p.release(1));
        assert_eq!(p.alloc(), Some(1));
        assert!(p.release(0));
        assert!(p.release(2));
        assert_eq!(p.alloc(), Some(0));
        assert_eq!(p.live_count(), 2);
    }

    #[test]
    fn release_rejects_out_of_range_and_double_release() {
        let mut p = SlotPoolInstance::new(2);
        assert!(!p.release(0));
        assert!(!p.release(9));
        assert!(!p.release(u32::MAX));
        p.alloc();
        assert!(p.release(0));
        assert!(!p.release(0), "second release must be refused");
        assert_eq!(p.live_count(), 0);
    }

    #[test]
    fn live_count_tracks_every_transition() {
        let mut p = SlotPoolInstance::new(5);
        assert_eq!(p.live_count(), 0);
        for _ in 0..4 {
            p.alloc();
            assert_eq!(p.live_count(), 1);
            p.release(0);
            assert_eq!(p.live_count(), 0);
        }
        p.alloc();
        p.alloc();
        assert_eq!(p.live_count(), 2);
    }

    #[test]
    fn is_live_is_bounds_guarded() {
        let mut p = SlotPoolInstance::new(2);
        assert!(!p.is_live(0));
        assert!(!p.is_live(7));
        assert!(!p.is_live(u32::MAX));
        assert_eq!(p.alloc(), Some(0));
        assert!(p.is_live(0));
        assert!(!p.is_live(1));
        p.release(0);
        assert!(!p.is_live(0));
    }

    #[test]
    fn soak_matches_a_shadow_bitmap_under_random_traffic() {
        let mut shadow = [false; 8];
        let mut p = SlotPoolInstance::new(8);
        let mut st: u64 = 0x5EED_5107;
        for _ in 0..600 {
            let idx = ((st >> 33) % 8) as u32;
            match (st >> 13) % 3 {
                0 => {
                    let want = shadow.iter().position(|&live| !live).map(|a| a as u32);
                    assert_eq!(p.alloc(), want);
                    if let Some(at) = want {
                        shadow[at as usize] = true;
                    }
                }
                _ => {
                    let want = shadow.get(idx as usize).copied().unwrap_or(false);
                    if want && (st >> 41).is_multiple_of(2) {
                        assert!(p.release(idx));
                        shadow[idx as usize] = false;
                        assert!(!p.release(idx), "double release");
                    } else {
                        assert_eq!(p.is_live(idx), want);
                    }
                }
            }
            assert_eq!(p.live_count(), shadow.iter().filter(|&&l| l).count() as u64);
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
    PoolCap,
    Alloc,
    Release,
    LiveCount,
    IsLive,
}

pub const OP_ALL: [Op; 5] = [
    Op::PoolCap,
    Op::Alloc,
    Op::Release,
    Op::LiveCount,
    Op::IsLive,
];

/// The fixed capacity every scenario shares.
pub const POOL_CAP: usize = 12;

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::PoolCap => "pool_cap",
            Op::Alloc => "alloc",
            Op::Release => "release",
            Op::LiveCount => "live_count",
            Op::IsLive => "is_live",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::PoolCap => "answers how many slots the pool holds in total",
            Op::Alloc => "hands out the lowest-numbered free slot, marks it live, and answers its index, or None once every slot is already live",
            Op::Release => "frees one live slot and answers true; a slot that is out of range or already free is refused with false",
            Op::LiveCount => "answers how many slots are currently live",
            Op::IsLive => "answers whether one slot is currently live; out-of-range slots are never live",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::PoolCap => "pub fn pool_cap(&self) -> u64",
            Op::Alloc => "pub fn alloc(&mut self) -> Option<u32>",
            Op::Release => "pub fn release(&mut self, slot: u32) -> bool",
            Op::LiveCount => "pub fn live_count(&self) -> u64",
            Op::IsLive => "pub fn is_live(&self, slot: u32) -> bool",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub const CANONICAL_SEED: u64 = 0x5107_FA11;

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

/// Alloc is the fill primitive and liveness is the audit probe; both ship
/// as given infrastructure alongside the sampled pair, so a solution that
/// hands back slot zero without ever scanning drifts on the very next
/// allocation no matter which pair was drawn.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    let mut v = vec![Op::Alloc];
    if !spec.ops.contains(&Op::IsLive) {
        v.push(Op::IsLive);
    }
    for o in spec.ops {
        if !v.contains(&o) {
            v.push(o);
        }
    }
    v
}

/// The canonical scenario: dozens of allocations against a small fixed
/// pool, so the pool fills and starts refusing well inside the run.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical slot-pool scenario");
}

fn fresh_pool() -> SlotPoolInstance {
    SlotPoolInstance::new(POOL_CAP)
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01DC;

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![
        ExampleCase {
            warmup: canonical(seed),
        },
        ExampleCase { warmup: 3 },
        ExampleCase { warmup: 4 },
        ExampleCase { warmup: 17 },
    ];
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    for _ in 0..16 {
        out.push(ExampleCase {
            warmup: rng.below(600) + 2,
        });
    }
    out
}

const NX_MUL: u64 = 6364136223846793005;
const NX_ADD: u64 = 1442695040888963407;

/// Allocation takes no argument, so drives carry no randomness; this seed
/// only feeds the liveness/release probe draws.
fn probe_seed(warmup: u64) -> u64 {
    0x5107_CAFEu64 ^ warmup.wrapping_mul(0x9E37)
}

/// Drives `warmup` allocations into a fresh pool (answers discarded once
/// full).
fn driven_pool(warmup: u64) -> SlotPoolInstance {
    let mut p = fresh_pool();
    for _ in 0..warmup {
        p.alloc();
    }
    p
}

/// One LCG draw: advance then take the high bits.
fn nx(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    *state >> 33
}

fn opt_fmt(v: Option<u32>) -> String {
    v.map_or_else(|| "None".to_string(), |x| format!("Some({x})"))
}

// ---- emitted-source fragments -----------------------------------------------

pub const STRUCT_SRC: &str = "#[derive(Clone)]\npub struct SlotPool {\n    slots: Vec<bool>,\n}\n";

pub const POOL_NEW_SRC: &str = "impl SlotPool {\n    pub fn new(capacity: usize) -> Self {\n        assert!(capacity >= 1);\n        SlotPool {\n            slots: vec![false; capacity],\n        }\n    }\n}\n\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

const ALLOC_BODY: &[&str] = &[
    "let at = self.slots.iter().position(|&live| !live)?;",
    "self.slots[at] = true;",
    "Some(at as u32)",
];

const RELEASE_BODY: &[&str] = &[
    "let i = slot as usize;",
    "if i >= self.slots.len() || !self.slots[i] {",
    "    return false;",
    "}",
    "self.slots[i] = false;",
    "true",
];

pub fn op_fn_src(op: Op) -> String {
    let body: String = match op {
        Op::PoolCap => "self.slots.len() as u64".to_string(),
        Op::Alloc => ALLOC_BODY.join("\n    "),
        Op::Release => RELEASE_BODY.join("\n    "),
        Op::LiveCount => "self.slots.iter().filter(|&&live| live).count() as u64".to_string(),
        Op::IsLive => "self.slots.get(slot as usize).copied().unwrap_or(false)".to_string(),
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body)
}

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen("pub struct SlotPool {", "pub struct SlotPoolRef {", 1);
    s.push_str(
        &POOL_NEW_SRC
            .replace("impl SlotPool {", "impl SlotPoolRef {")
            .replace("SlotPool {\n", "SlotPoolRef {\n"),
    );
    s.push_str("impl SlotPoolRef {\n");
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
        let p = driven_pool(ex.warmup);
        s.push_str(&format!(
            "//! ex{i}: {w} allocations -> {l} of {c} slots live\n",
            i = i,
            w = ex.warmup,
            l = p.live_count(),
            c = p.pool_cap(),
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested slot-pool operations over one internal\n\
         //! boolean bitmap: allocation always hands out the lowest-numbered\n\
         //! free slot, release refuses unknown and already-free slots, and\n\
         //! every tally and liveness query must stay exact even as slots\n\
         //! churn. The hidden tests drive thousands of interleaved\n\
         //! operations and compare every returned value.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(POOL_NEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested slot-pool operations with exactly maintained bookkeeping.\n\nRequirements:\n- `SlotPool::new(capacity)` starts with every slot free; the constructor is given.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- The pool holds a fixed number of slots; allocation always hands out the lowest-numbered free slot and answers None once every slot is live.\n- A release frees exactly one live slot and answers true; an out-of-range slot or one that is already free is refused with false.\n- Queries never mutate the pool; liveness answers false for out-of-range slots, and the live tally stays exact across every transition.\n- No floating point; no unsafe code; standard library only.\n\nSignatures:\n```rust\n");
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
    let mut s = String::from("use task::SlotPool;\n\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n");
    for (i, ex) in examples.iter().enumerate() {
        let h = driven_pool(ex.warmup);
        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let mut drive = SlotPool::new({cap});\n    for _ in 0..{w} {{\n        drive.alloc();\n    }}\n",
            i = i,
            w = ex.warmup,
            cap = POOL_CAP
        ));
        s.push_str(&format!(
            "    let mut ps: u64 = {};\n",
            probe_seed(ex.warmup)
        ));
        let mut ps = probe_seed(ex.warmup);
        for &op in &spec.ops {
            match op {
                Op::PoolCap => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.pool_cap(), {});\n",
                        h.pool_cap()
                    ));
                }
                Op::LiveCount => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.live_count(), {});\n",
                        h.live_count()
                    ));
                }
                Op::IsLive => {
                    let idx = (nx(&mut ps) % POOL_CAP as u64) as u32;
                    let want = h.is_live(idx);
                    s.push_str(&format!(
                        "    let r = drive.clone();\n    let s = (nx(&mut ps) % {cap}u64) as u32;\n    assert_eq!(r.is_live(s), {want});\n    assert!(!r.is_live(999));\n",
                        cap = POOL_CAP,
                        want = want
                    ));
                }
                Op::Release => {
                    let idx = (nx(&mut ps) % POOL_CAP as u64) as u32;
                    let want = h.clone().release(idx);
                    s.push_str(&format!(
                        "    let mut r = drive.clone();\n    let s = (nx(&mut ps) % {cap}u64) as u32;\n    assert_eq!(r.release(s), {want});\n",
                        cap = POOL_CAP,
                        want = want
                    ));
                }
                Op::Alloc => {
                    let want = h.clone().alloc();
                    s.push_str(&format!(
                        "    let mut r = drive.clone();\n    assert_eq!(r.alloc(), {});\n",
                        opt_fmt(want)
                    ));
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Scripted probe: the freed lowest slot must be handed back out again -
    // a solution that always answers slot zero fails on the second alloc.
    if spec.ops.contains(&Op::Alloc) && spec.ops.contains(&Op::IsLive) {
        s.push_str("#[test]\nfn scripted_lowest_slot_is_always_reused() {\n    let mut r = SlotPool::new(4);\n    assert_eq!(r.alloc(), Some(0));\n    assert!(r.is_live(0));\n    assert!(!r.is_live(1));\n    assert_eq!(r.alloc(), Some(1));\n    assert_eq!(r.alloc(), Some(2));\n}\n");
    }
    // Fill soak: eight hundred random allocs/releases must keep the pool
    // pinned to a shadow bitmap.
    if spec.ops.contains(&Op::Alloc) && spec.ops.contains(&Op::Release) {
        s.push_str("#[test]\nfn fill_soak_churns_against_a_shadow_bitmap() {\n    let mut r = SlotPool::new(12);\n    let mut shadow: Vec<bool> = vec![false; 12];\n    let mut st: u64 = 0x5EED_0000_0000_01DE;\n    for _ in 0..800usize {\n        let pick = (st >> 13) % 2;\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        if pick == 0 {\n            let want = shadow.iter().position(|&live| !live).map(|a| a as u32);\n            assert_eq!(r.alloc(), want);\n            if let Some(at) = want {\n                shadow[at as usize] = true;\n            }\n        } else {\n            let s = ((st >> 33) % 15) as u32;\n            let live = shadow.get(s as usize).copied().unwrap_or(false);\n            assert_eq!(r.release(s), live);\n            if live {\n                shadow[s as usize] = false;\n            }\n        }\n    }\n}\n");
    }
    // Tally soak: pure allocation traffic must pin the live tally.
    if spec.ops.contains(&Op::Alloc) && spec.ops.contains(&Op::LiveCount) {
        s.push_str("#[test]\nfn fill_soak_counts_every_allocation() {\n    let mut r = SlotPool::new(12);\n    for i in 0..800usize {\n        let want = if i < 12 { Some(i as u32) } else { None };\n        assert_eq!(r.alloc(), want);\n        assert_eq!(r.live_count(), (i + 1).min(12) as u64);\n    }\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::SlotPool;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    let ops = effective_ops(spec);
    s.push_str("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {\n    let mut cand = SlotPool::new(9);\n    let mut refr = SlotPoolRef::new(9);\n    // A naive vector model recomputed from scratch every step: live slots\n    // live in an unsorted Vec and every answer is a fresh scan.\n    let mut naive: Vec<u32> = Vec::new();\n");
    if ops.contains(&Op::PoolCap) {
        s.push_str("    assert_eq!(cand.pool_cap(), refr.ref_pool_cap());\n");
        s.push_str("    assert_eq!(cand.pool_cap(), 9);\n");
    }
    if ops.contains(&Op::LiveCount) {
        s.push_str("    assert_eq!(cand.live_count(), refr.ref_live_count());\n");
        s.push_str("    assert_eq!(cand.live_count(), naive.len() as u64);\n");
    }
    if ops.contains(&Op::IsLive) {
        s.push_str("    assert_eq!(cand.is_live(999), refr.ref_is_live(999));\n");
        s.push_str("    assert!(!naive.contains(&999));\n");
    }
    if ops.contains(&Op::Release) {
        s.push_str("    assert_eq!(cand.release(0), refr.ref_release(0));\n");
        s.push_str("    assert_eq!(cand.release(0), naive.contains(&0));\n");
    }
    let arm_count = ops.len();
    s.push_str(&format!("    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_01DC;\n    for _ in 0..3000 {{\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in ops.iter().enumerate() {
        let body = match op {
            Op::PoolCap => "assert_eq!(cand.pool_cap(), refr.ref_pool_cap());".to_string(),
            Op::Alloc => {
                "let naive_at = (0..9u32).find(|s| !naive.contains(s));\n            assert_eq!(cand.alloc(), naive_at);\n            assert_eq!(refr.ref_alloc(), naive_at);\n            if let Some(at) = naive_at {\n                naive.push(at);\n            }"
                    .to_string()
            }
            Op::Release => {
                "let s = (nx(&mut state) % 14) as u32;\n            let naive_was = naive.contains(&s);\n            assert_eq!(cand.release(s), naive_was);\n            assert_eq!(refr.ref_release(s), naive_was);\n            if naive_was {\n                naive.retain(|&x| x != s);\n            }"
                    .to_string()
            }
            Op::LiveCount => {
                "assert_eq!(cand.live_count(), refr.ref_live_count());\n            assert_eq!(cand.live_count(), naive.len() as u64);"
                    .to_string()
            }
            Op::IsLive => {
                "let s = (nx(&mut state) % 14) as u32;\n            let naive_live = naive.contains(&s);\n            assert_eq!(cand.is_live(s), naive_live);\n            assert_eq!(refr.ref_is_live(s), naive_live);"
                    .to_string()
            }
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
    s.push_str(POOL_NEW_SRC);
    s.push_str("impl SlotPool {\n");
    for &op in &ops {
        let body = match op {
            Op::Alloc => "None",
            Op::Release | Op::IsLive => "false",
            _ => "0",
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s.push_str("}\n");
    s
}

/// The plausible cheat: slot zero is handed out unconditionally - no scan,
/// no fullness check - while every query stays honest.
pub fn sticky_alloc_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(POOL_NEW_SRC);
    s.push_str("impl SlotPool {\n");
    for &op in &ops {
        if op == Op::Alloc {
            s.push_str(&format!(
                "{} {{\n    {}\n}}\n",
                op_sig_src(op),
                ["self.slots[0] = true;", "Some(0)"].join("\n    ")
            ));
        } else {
            s.push_str(&op_fn_src(op));
        }
    }
    s.push_str("}\n");
    s
}

pub struct SlotPoolFamily;

impl Generator for SlotPoolFamily {
    fn id(&self) -> &'static str {
        "slot-pool"
    }

    fn category(&self) -> &'static str {
        "resource-allocation"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("slot-pool", seed);
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
            id: format!("slot-pool/{seed:016x}"),
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
        s.push_str(POOL_NEW_SRC);
        s.push_str("impl SlotPool {\n");
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
            ("sticky-alloc".to_string(), sticky_alloc_src(spec)),
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
        let a = SlotPoolFamily.generate(55);
        let b = SlotPoolFamily.generate(55);
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
            let p = driven_pool(warmup);
            assert_eq!(p.pool_cap(), POOL_CAP as u64);
            assert_eq!(p.live_count(), (warmup as usize).min(POOL_CAP) as u64);
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let p = driven_pool(ex.warmup);
                assert_eq!(p.live_count(), (ex.warmup as usize).min(POOL_CAP) as u64);
                assert!(ex.warmup >= 2);
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct SlotPoolRef"));
            assert!(
                src.matches("SlotPoolRef {").count() >= 2,
                "constructor body must be renamed too"
            );
            assert!(!src.contains("pub fn alloc"));
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
            let canary = mint_canary("slot-pool", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in ["position(", ".iter()", "unwrap_or(false)"] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("lowest"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("SlotPoolRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
            assert!(
                src.contains("let mut naive: Vec<u32>"),
                "differential must fuzz a naive vector model"
            );
            assert!(src.contains("naive.contains("));
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soaks() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            let reuse_gate = spec.ops.contains(&Op::Alloc) && spec.ops.contains(&Op::IsLive);
            let churn_gate = spec.ops.contains(&Op::Alloc) && spec.ops.contains(&Op::Release);
            let tally_gate = spec.ops.contains(&Op::Alloc) && spec.ops.contains(&Op::LiveCount);
            assert_eq!(
                behavior.contains("scripted_lowest_slot_is_always_reused"),
                reuse_gate,
                "seed {seed}: reuse script misaligned"
            );
            assert_eq!(
                behavior.contains("fill_soak_churns_against_a_shadow_bitmap"),
                churn_gate,
                "seed {seed}: churn soak misaligned"
            );
            assert_eq!(
                behavior.contains("fill_soak_counts_every_allocation"),
                tally_gate,
                "seed {seed}: tally soak misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_pooling_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let cheat = sticky_alloc_src(spec);
        assert!(!cz.contains("todo!()"));
        assert!(cheat.contains("fn alloc"));
        let us = cheat.find("fn alloc").unwrap();
        let ue = us + cheat[us..].find("\n}\n").unwrap();
        let ub = &cheat[us..ue];
        assert!(ub.contains("Some(0)"), "the sticky handout is the bug");
        assert!(!ub.contains("position"), "the skipped scan is the bug");
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("slot-pool", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
