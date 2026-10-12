//! The `ring-buffer` family (category `circular-indexing`) — fixed-capacity
//! queue puzzles over one contiguous slab.
//!
//! Every query mirrors a real ring-buffer primitive whose state lives in
//! two FREE-RUNNING counters (`head`, `tail`) that never wrap: the
//! physical slot for any logical position is `counter & (capacity - 1)`,
//! valid because the capacity is always a power of two. The seed picks
//! which two of five query ops are required: `len`, `push_back`,
//! `pop_front`, `wrap_index`, `skip`. The skill is modular index
//! reasoning — wrap-around bookkeeping, the subtraction trick behind
//! `len = tail - head`, overwrite-vs-reject semantics when full — none
//! of which any other family exercises.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! live on [`RingInstance`] so they are deterministic off-thread; the
//! generator built on top of them emits signatures over `(slab, head,
//! tail)` triples where the same identities must hold.

/// One fixed-capacity ring mirroring circular-buffer state. The slab is
/// preallocated to `capacity` slots; `head`/`tail` are free-running and
/// only ever reduced modulo capacity through the power-of-two mask.
pub struct RingInstance {
    slab: Vec<u64>,
    head: u64,
    tail: u64,
}

impl RingInstance {
    /// A fresh ring holding exactly `capacity` slots. Panics unless the
    /// capacity is a non-zero power of two — the mask identity that the
    /// whole family rests on.
    pub fn new(capacity: u64) -> Self {
        assert!(capacity.is_power_of_two(), "capacity must be 2^k");
        RingInstance {
            slab: vec![0; capacity as usize],
            head: 0,
            tail: 0,
        }
    }

    pub fn capacity(&self) -> u64 {
        self.slab.len() as u64
    }

    /// Elements currently held: the free-running difference.
    pub fn len(&self) -> u64 {
        self.tail - self.head
    }

    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    pub fn is_full(&self) -> bool {
        self.len() == self.capacity()
    }

    /// Physical slot that logical position `counter` maps to under the
    /// power-of-two mask — the identity `c & (capacity - 1)`.
    pub fn wrap_index(&self, counter: u64) -> u64 {
        counter & (self.capacity() - 1)
    }

    /// Appends `v`; when the ring is full the OLDEST element is silently
    /// overwritten, handed back so callers can observe the eviction.
    pub fn push_back(&mut self, v: u64) -> Option<u64> {
        let evicted = if self.is_full() {
            let slot = self.wrap_index(self.head) as usize;
            Some(self.slab[slot])
        } else {
            None
        };
        let slot = self.wrap_index(self.tail) as usize;
        self.slab[slot] = v;
        self.tail += 1;
        // Overwrite mode keeps head glued to tail - capacity.
        if self.tail - self.head > self.capacity() {
            self.head = self.tail - self.capacity();
        }
        evicted
    }

    /// Free-running write counter — never wrapped, only masked on use.
    pub fn tail(&self) -> u64 {
        self.tail
    }

    /// Removes and returns the oldest element.
    pub fn pop_front(&mut self) -> Option<u64> {
        if self.is_empty() {
            return None;
        }
        let v = self.slab[self.wrap_index(self.head) as usize];
        self.head += 1;
        Some(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_ring_is_empty_at_capacity() {
        let mut r = RingInstance::new(4);
        assert_eq!(r.capacity(), 4);
        assert_eq!(r.len(), 0);
        assert!(r.is_empty());
        assert!(!r.is_full());
        assert_eq!(r.pop_front(), None);
    }

    #[test]
    fn non_power_of_two_capacity_panics() {
        let _ = std::panic::catch_unwind(|| RingInstance::new(3))
            .err()
            .expect("capacity 3 must panic");
        let _ = std::panic::catch_unwind(|| RingInstance::new(0))
            .err()
            .expect("capacity 0 must panic");
        let _ = RingInstance::new(1); // 2^0 is legal
        let _ = RingInstance::new(1024);
    }

    #[test]
    fn wrap_index_masks_the_counter() {
        let r = RingInstance::new(8);
        assert_eq!(r.wrap_index(0), 0);
        assert_eq!(r.wrap_index(7), 7);
        assert_eq!(r.wrap_index(8), 0);
        assert_eq!(r.wrap_index(9), 1);
        assert_eq!(r.wrap_index(u64::MAX), 7);
    }

    #[test]
    fn push_then_pop_preserves_fifo_order() {
        let mut r = RingInstance::new(4);
        for v in [10u64, 20, 30] {
            assert_eq!(r.push_back(v), None);
        }
        assert_eq!(r.len(), 3);
        assert_eq!(r.pop_front(), Some(10));
        assert_eq!(r.pop_front(), Some(20));
        assert_eq!(r.push_back(40), None);
        assert_eq!(r.push_back(50), None);
        assert_eq!(r.len(), 3);
        assert_eq!(r.pop_front(), Some(30));
        assert_eq!(r.pop_front(), Some(40));
        assert_eq!(r.pop_front(), Some(50));
        assert!(r.is_empty());
    }

    #[test]
    fn pushing_into_a_full_ring_evicts_the_oldest() {
        let mut r = RingInstance::new(4);
        for v in [1u64, 2, 3, 4] {
            assert_eq!(r.push_back(v), None);
        }
        assert_eq!(r.push_back(5), Some(1));
        assert_eq!(r.push_back(6), Some(2));
        assert_eq!(r.len(), 4);
        assert_eq!(r.pop_front(), Some(3));
        assert_eq!(r.pop_front(), Some(4));
        assert_eq!(r.pop_front(), Some(5));
        assert_eq!(r.pop_front(), Some(6));
        assert!(r.is_empty());
    }

    #[test]
    fn contents_survive_many_wraps() {
        let mut r = RingInstance::new(2);
        for i in 0..100u64 {
            let evicted = r.push_back(i);
            if i >= 2 {
                assert_eq!(evicted, Some(i - 2));
            } else {
                assert_eq!(evicted, None);
            }
        }
        assert_eq!(r.pop_front(), Some(98));
        assert_eq!(r.pop_front(), Some(99));
        assert!(r.is_empty());
        // Counters kept climbing the whole time; the mask absorbed it.
        assert_eq!(r.wrap_index(r.tail()), 0);
    }
}

// ---- generator: op menu, spec, canonical, emitters -------------------------

use crate::{mint_canary, GeneratedTask, Generator, Rng};

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    RingLen,
    PushBack,
    PopFront,
    WrapIndex,
    Skip,
}

pub const OP_ALL: [Op; 5] = [
    Op::RingLen,
    Op::PushBack,
    Op::PopFront,
    Op::WrapIndex,
    Op::Skip,
];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::RingLen => "ring_len",
            Op::PushBack => "push_back",
            Op::PopFront => "pop_front",
            Op::WrapIndex => "wrap_index",
            Op::Skip => "skip",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::RingLen => "how many elements the ring currently holds",
            Op::PushBack => "appends v; when already full the OLDEST element is overwritten and handed back so the eviction stays observable, otherwise None",
            Op::PopFront => "removes and returns the oldest element, or None when empty",
            Op::WrapIndex => "the physical slot a free-running logical counter maps to — valid for any u64 because the capacity is a power of two",
            Op::Skip => "advances past the n oldest elements and returns how many actually existed to drop",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::RingLen => "pub fn ring_len(&self) -> u64",
            Op::PushBack => "pub fn push_back(&mut self, v: u64) -> Option<u64>",
            Op::PopFront => "pub fn pop_front(&mut self) -> Option<u64>",
            Op::WrapIndex => "pub fn wrap_index(&self, counter: u64) -> u64",
            Op::Skip => "pub fn skip(&mut self, n: u64) -> u64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

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

/// PushBack is the fill primitive every scenario needs; when the seed
/// did not sample it, it ships as given infrastructure alongside the
/// pair so state can always be built through the candidate itself.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    if spec.ops.contains(&Op::PushBack) {
        spec.ops.to_vec()
    } else {
        let mut v = vec![Op::PushBack];
        v.extend_from_slice(&spec.ops);
        v
    }
}

// ---- canonical case --------------------------------------------------------

const CANONICAL_SEED: u64 = 0x4E02_FA11;

/// The canonical scenario: capacity 8 warmed until the counters have
/// wrapped at least twice AND the ring sits exactly full, so any
/// solution that loses track across the wrap or forgets the eviction
/// path is wrong before the first probe.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical ring scenario");
}

fn fresh_ring(capacity: u64) -> RingInstance {
    RingInstance::new(capacity)
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub capacity: u64,
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0196;

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![
        ExampleCase {
            capacity: 8,
            warmup: canonical(seed),
        },
        ExampleCase {
            capacity: 1,
            warmup: 3,
        },
        ExampleCase {
            capacity: 2,
            warmup: 4,
        },
        ExampleCase {
            capacity: 16,
            warmup: 17,
        },
    ];
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    for _ in 0..8 {
        let cap = 1u64 << (1 + rng.below(5));
        out.push(ExampleCase {
            capacity: cap,
            warmup: rng.below(cap * 3),
        });
    }
    out
}

/// Drives `warmup` pushes into a fresh ring, returning it plus every
/// eviction the drive produced.
fn driven_ring(capacity: u64, warmup: u64) -> (RingInstance, Vec<u64>) {
    let mut r = fresh_ring(capacity);
    let mut evictions = Vec::new();
    for i in 0..warmup {
        if let Some(e) = r.push_back(i) {
            evictions.push(e);
        }
    }
    (r, evictions)
}

// ---- emitted-source fragments -----------------------------------------------

pub const STRUCT_SRC: &str =
    "#[derive(Clone)]\npub struct Ring {\n    slab: Vec<u64>,\n    head: u64,\n    tail: u64,\n}\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::RingLen => &["self.tail - self.head"],
        Op::PushBack => &[
            "let full = self.tail - self.head == self.slab.len() as u64;",
            "let evicted = if full {",
            "    Some(self.slab[(self.head & (self.slab.len() as u64 - 1)) as usize])",
            "} else {",
            "    None",
            "};",
            "let slot = (self.tail & (self.slab.len() as u64 - 1)) as usize;",
            "self.slab[slot] = v;",
            "self.tail += 1;",
            "if self.tail - self.head > self.slab.len() as u64 {",
            "    self.head = self.tail - self.slab.len() as u64;",
            "}",
            "evicted",
        ],
        Op::PopFront => &[
            "if self.head == self.tail {",
            "    return None;",
            "}",
            "let v = self.slab[(self.head & (self.slab.len() as u64 - 1)) as usize];",
            "self.head += 1;",
            "Some(v)",
        ],
        Op::WrapIndex => &["counter & (self.slab.len() as u64 - 1)"],
        Op::Skip => &[
            "let held = self.tail - self.head;",
            "let drop = n.min(held);",
            "self.head += drop;",
            "drop",
        ],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub const RING_NEW_SRC: &str =
    "impl Ring {\n    pub fn new(capacity: u64) -> Self {\n        assert!(capacity.is_power_of_two(), \"capacity must be 2^k\");\n        Ring {\n            slab: vec![0; capacity as usize],\n            head: 0,\n            tail: 0,\n        }\n    }\n\n    /// Free-running write counter — never wrapped, only masked on use.\n    pub fn tail(&self) -> u64 {\n        self.tail\n    }\n}\n\n";

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen("pub struct Ring {", "pub struct RingRef {", 1);
    s.push_str(
        &RING_NEW_SRC
            .replace("impl Ring {", "impl RingRef {")
            .replace("Ring {\n", "RingRef {\n"),
    );
    s.push_str("impl RingRef {\n");
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
        let (r, evictions) = driven_ring(ex.capacity, ex.warmup);
        s.push_str(&format!(
            "//! ex{i}: capacity {c}, then {w} pushes -> len {l}, evicted [{e}]\n",
            i = i,
            c = ex.capacity,
            w = ex.warmup,
            l = r.len(),
            e = evictions
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested ring-buffer operations over one slab.\n\
         //! The capacity is ALWAYS a power of two; counters are free-running\n\
         //! u64 and only ever mapped into the slab through the mask. The\n\
         //! hidden tests drive thousands of interleaved operations and\n\
         //! compare every returned value.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(RING_NEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested fixed-capacity ring-buffer operations.\n\nRequirements:\n- `Ring::new(capacity)` panics unless capacity is a power of two; the slab is preallocated to exactly `capacity` slots.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- Keep the exact struct shape and signatures.\n- No unsafe code; standard library only.\n\nSignatures:\n```rust\n");
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
    let mut s = String::from("use task::Ring;\n\n");
    for (i, ex) in examples.iter().enumerate() {
        let (r, _evictions) = driven_ring(ex.capacity, ex.warmup);
        let len = r.len();
        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let mut r = Ring::new({c});\n",
            i = i,
            c = ex.capacity
        ));
        s.push_str(&format!(
            "    let mut drive = r.clone();\n    for i in 0..{w}u64 {{\n        drive.push_back(i);\n    }}\n",
            w = ex.warmup
        ));
        for &op in &spec.ops {
            s.push_str("    let mut r = drive.clone();\n");
            match op {
                Op::RingLen => s.push_str(&format!(
                    "    assert_eq!(r.ring_len(), {len});\n"
                )),
                Op::WrapIndex => s.push_str(&format!(
                    "    assert_eq!(r.wrap_index(r.tail()), {slot});\n    assert_eq!(r.wrap_index(u64::MAX), {mask});\n",
                    slot = r.wrap_index(r.tail()),
                    mask = r.wrap_index(u64::MAX)
                )),
                Op::PushBack => {
                    let next = ex.warmup;
                    let expect = if r.is_full() {
                        format!("Some({})", next - ex.capacity)
                    } else {
                        "None".to_string()
                    };
                    s.push_str(&format!(
                        "    assert_eq!(r.push_back({next}), {expect});\n",
                        next = next,
                        expect = expect
                    ));
                    if spec.ops.contains(&Op::RingLen) {
                        s.push_str(&format!(
                            "    assert_eq!(r.ring_len(), {after});\n",
                            after = len.min(ex.capacity - 1) + 1
                        ));
                    }
                }
                Op::PopFront => {
                    // After driving W pushes through capacity C the ring
                    // holds exactly the last C values; pop them in order.
                    let base = ex.warmup.saturating_sub(ex.capacity);
                    let held = ex.warmup.min(ex.capacity);
                    for k in 0..2.min(held) {
                        s.push_str(&format!(
                            "    assert_eq!(r.pop_front(), Some({v}));\n",
                            v = base + k
                        ));
                    }
                    if held > 2 {
                        s.push_str("    assert!(r.pop_front().is_some());\n");
                    }
                }
                Op::Skip => {
                    s.push_str(&format!(
                        "    assert_eq!(r.skip(2), {sk});\n    assert_eq!(r.skip({big}), {sk2});\n",
                        sk = 2.min(len),
                        big = ex.capacity * 4,
                        sk2 = len.saturating_sub(2)
                    ));
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Adversarial soak: thousands of interleaved pushes and pops; the
    // FIFO order and the full-ring eviction boundary must both hold.
    if spec.ops.contains(&Op::RingLen) {
        s.push_str("#[test]\nfn soak_keeps_the_ring_consistent() {\n    let mut r = Ring::new(8);\n    let mut expect: std::collections::VecDeque<u64> = Default::default();\n");
        s.push_str("    for step in 0..5000u64 {\n        let full = expect.len() == 8;\n        let ev = r.push_back(step);\n        let oldest = if full { expect.pop_front() } else { None };\n        assert_eq!(ev, oldest);\n        expect.push_back(step);\n        assert_eq!(r.ring_len(), expect.len() as u64);\n    }\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::Ring;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    let arm_count = effective_ops(spec).len();
    s.push_str(&format!("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {{\n    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_0196;\n    let mut cand = Ring::new(8);\n    let mut refr = RingRef::new(8);\n    for _ in 0..3000 {{\n        let arg = nx(&mut state);\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in effective_ops(spec).iter().enumerate() {
        let body = match op {
            Op::PushBack => "assert_eq!(cand.push_back(arg), refr.ref_push_back(arg));".to_string(),
            Op::PopFront => "assert_eq!(cand.pop_front(), refr.ref_pop_front());".to_string(),
            Op::Skip => "assert_eq!(cand.skip(arg % 10), refr.ref_skip(arg % 10));".to_string(),
            Op::RingLen => "assert_eq!(cand.ring_len(), refr.ref_ring_len());".to_string(),
            Op::WrapIndex => {
                "assert_eq!(cand.wrap_index(arg), refr.ref_wrap_index(arg));".to_string()
            }
        };
        s.push_str(&format!("            {} => {{ {} }}\n", i, body));
    }
    s.push_str("            _ => { unreachable!() }\n        }\n    }\n}\n");
    let _ = arm_count;

    // Monotonic-counter soak: 20k pushes without a single pop must keep
    // every observable bounded and correct — kills unbounded-growth and
    // lost-eviction cheats alike.
    // Generation probe: fill -> total drain -> refill. A ring that
    // latches "full" or evicts from a stale slot must surface here.
    if spec.ops.contains(&Op::PushBack)
        && (spec.ops.contains(&Op::PopFront) || spec.ops.contains(&Op::Skip))
    {
        let drain = if spec.ops.contains(&Op::PopFront) {
            "    for i in 0..4u64 {\n        assert_eq!(r.pop_front(), Some(i));\n    }\n"
        } else {
            "    assert_eq!(r.skip(4), 4);\n"
        };
        let len_check = if spec.ops.contains(&Op::RingLen) {
            "    assert_eq!(r.ring_len(), 4);\n"
        } else {
            ""
        };
        s.push_str(&format!(
            "\n#[test]\nfn refill_after_total_drain_respects_generation() {{\n    let mut r = Ring::new(4);\n    for i in 0..4u64 {{\n        r.push_back(i);\n    }}\n{drain}    for i in 10..14u64 {{\n        assert_eq!(r.push_back(i), None);\n    }}\n{len_check}    assert_eq!(r.push_back(99), Some(10));\n}}\n",
            drain = drain,
            len_check = len_check
        ));
    }
    if spec.ops.contains(&Op::PushBack) && spec.ops.contains(&Op::RingLen) {
        s.push_str("\n#[test]\nfn monotonic_soak_never_loses_the_boundary() {\n    let mut cand = Ring::new(16);\n    let mut refr = RingRef::new(16);\n    for i in 0..20000u64 {\n        let ec = cand.push_back(i);\n        let er = refr.ref_push_back(i);\n        assert_eq!(ec, er);\n        match i {\n            0..=15 => {\n                assert_eq!(ec, None);\n                assert_eq!(cand.ring_len(), i + 1);\n            }\n            _ => {\n                assert_eq!(ec, Some(i - 16));\n                assert_eq!(cand.ring_len(), 16);\n            }\n        }\n        assert_eq!(refr.ref_ring_len(), cand.ring_len());\n    }\n}\n");
    }
    s
}

pub fn const_zero_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(RING_NEW_SRC);
    s.push_str("impl Ring {\n");
    for &op in &ops {
        let body = match op {
            Op::RingLen => "0",
            Op::PushBack => "let _ = v;\n    None",
            Op::PopFront => "None",
            Op::WrapIndex => "let _ = counter;\n    0",
            Op::Skip => "let _ = n;\n    0",
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s.push_str("}\n");
    s
}

/// The plausible wrapped-modulo cheat: keeps head/tail INSIDE [0,cap)
/// using `%` and computes len by bare subtraction. Looks reasonable,
/// survives the first fill, then underflows `tail - head` to a debug
/// panic the moment counters wrap — exactly the bug the family teaches
/// free-running counters to avoid.
pub fn wrapped_modulo_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(RING_NEW_SRC);
    s.push_str("impl Ring {\n");
    for &op in &ops {
        let body = match op {
            Op::RingLen => &["self.tail - self.head"][..],
            Op::PushBack => &[
                "let cap = self.slab.len() as u64;",
                "let full = (self.tail - self.head) % cap == 0 && self.tail != self.head;",
                "let evicted = if full { Some(self.slab[(self.head % cap) as usize]) } else { None };",
                "self.slab[(self.tail % cap) as usize] = v;",
                "self.tail = (self.tail + 1) % cap;",
                "if full { self.head = (self.head + 1) % cap; }",
                "evicted",
            ][..],
            Op::PopFront => &[
                "let cap = self.slab.len() as u64;",
                "if self.head == self.tail { return None; }",
                "let v = self.slab[(self.head % cap) as usize];",
                "self.head = (self.head + 1) % cap;",
                "Some(v)",
            ][..],
            Op::WrapIndex => &["counter % self.slab.len() as u64"][..],
            Op::Skip => &[
                "let held = self.tail - self.head;",
                "let drop = n.min(held);",
                "self.head = (self.head + drop) % self.slab.len() as u64;",
                "drop",
            ][..],
        };
        s.push_str(&format!(
            "{} {{\n    {}\n}}\n",
            op_sig_src(op),
            body.join("\n    ")
        ));
    }
    s.push_str("}\n");
    s
}

pub struct RingBufferFamily;

impl Generator for RingBufferFamily {
    fn id(&self) -> &'static str {
        "ring-buffer"
    }

    fn category(&self) -> &'static str {
        "circular-indexing"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("ring-buffer", seed);
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
            id: format!("ring-buffer/{seed:016x}"),
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
        s.push_str(RING_NEW_SRC);
        s.push_str("impl Ring {\n");
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
            ("wrapped-modulo".to_string(), wrapped_modulo_src(spec)),
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
        let a = RingBufferFamily.generate(55);
        let b = RingBufferFamily.generate(55);
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
    fn canonical_scenarios_wrap_and_fill() {
        for seed in 0..200u64 {
            let warmup = canonical(seed);
            assert!(warmup >= 24 && warmup.is_multiple_of(8));
            let (r, evictions) = driven_ring(8, warmup);
            assert!(r.is_full());
            assert_eq!(evictions.len() as u64, warmup - 8);
            // Counters climbed; the mask still lands inside the slab.
            assert_eq!(r.wrap_index(r.tail()), warmup % 8);
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let (r, evictions) = driven_ring(ex.capacity, ex.warmup);
                assert_eq!(r.len(), ex.warmup.min(ex.capacity));
                assert_eq!(
                    evictions.len() as u64,
                    ex.warmup.saturating_sub(ex.capacity)
                );
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct RingRef"));
            // `pub fn new` is the given constructor; every OP must have
            // been renamed to its `ref_` twin.
            assert!(!src.contains("pub fn ring_len"));
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
            let canary = mint_canary("ring-buffer", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in ["self.tail - self.head", "& (self.slab.len()", "% self.slab"] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("power of two"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("RingRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
            let drains = spec.ops.contains(&Op::PopFront) || spec.ops.contains(&Op::Skip);
            if spec.ops.contains(&Op::PushBack) && spec.ops.contains(&Op::RingLen) {
                assert!(src.contains("monotonic_soak_never_loses_the_boundary"));
            } else {
                assert!(!src.contains("monotonic_soak_never_loses_the_boundary"));
            }
            assert_eq!(
                src.contains("refill_after_total_drain_respects_generation"),
                spec.ops.contains(&Op::PushBack) && drains,
                "seed {seed}: generation probe misaligned"
            );
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soak() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            assert_eq!(
                behavior.contains("soak_keeps_the_ring_consistent"),
                spec.ops.contains(&Op::RingLen),
                "seed {seed}: soak gate misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_ring_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let wm = wrapped_modulo_src(spec);
        assert!(cz.contains("None"));
        assert!(wm.contains("% "));
        assert!(wm.contains("self.tail - self.head"));
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("ring-buffer", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
