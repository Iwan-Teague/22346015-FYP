//! The `lru-cache` family (category `recency-tracking`) — bounded-cache
//! puzzles where the *order of use* is the data structure.
//!
//! Every puzzle mirrors a real fixed-capacity cache stored as one
//! `Vec<(u64, u64)>` kept ordered least-recently-used first: reads
//! (`get`) promote their key to the back, writes (`put`) either update
//! an existing entry in place or evict the front victim when full, and
//! `peek`/`touch` expose the difference between observing recency and
//! changing it. The seed picks which two of five query ops are
//! required: `lru_len`, `get`, `peek`, `touch`, `put`. None of the
//! other families exercise use-order bookkeeping.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! live on [`LruInstance`] so they are deterministic off-thread; the
//! generator built on top of them emits signatures over the same shape
//! where the identical invariants must hold.

/// One bounded cache. `entries` is ordered least-recently-used first,
/// most-recently-used last; `cap` bounds its length.
#[derive(Clone)]
pub struct LruInstance {
    cap: usize,
    entries: Vec<(u64, u64)>,
}

impl LruInstance {
    /// A fresh empty cache holding at most `capacity` entries.
    ///
    /// # Panics
    /// Panics when `capacity` is zero — a cache that can hold nothing
    /// cannot serve reads, so it is rejected up front.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity >= 1, "cache capacity must be at least 1");
        LruInstance {
            cap: capacity,
            entries: Vec::new(),
        }
    }

    fn slot_of(&self, key: u64) -> Option<usize> {
        self.entries.iter().position(|&(k, _)| k == key)
    }

    /// Moves whichever entry sits at `slot` to the most-recently-used
    /// position (the back).
    fn promote(&mut self, slot: usize) {
        let entry = self.entries.remove(slot);
        self.entries.push(entry);
    }

    /// Reads `key` and promotes it to most-recently-used.
    pub fn get(&mut self, key: u64) -> Option<u64> {
        let slot = self.slot_of(key)?;
        let value = self.entries[slot].1;
        self.promote(slot);
        Some(value)
    }

    /// Reads `key` WITHOUT disturbing the recency order.
    pub fn peek(&self, key: u64) -> Option<u64> {
        let slot = self.slot_of(key)?;
        Some(self.entries[slot].1)
    }

    /// The key sitting in the least-recently-used position — the next
    /// eviction victim. Answers `None` only when the cache is empty.
    pub fn lru_front(&self) -> Option<u64> {
        self.entries.first().map(|&(k, _)| k)
    }

    /// Promotes `key` if present; answers whether it lived in the cache.
    pub fn touch(&mut self, key: u64) -> bool {
        match self.slot_of(key) {
            Some(slot) => {
                self.promote(slot);
                true
            }
            None => false,
        }
    }

    /// Inserts or updates `key`. Updating an existing entry refreshes it
    /// and answers `None`. Inserting into a full cache evicts the
    /// least-recently-used victim first and answers `Some(victim_key)`.
    pub fn put(&mut self, key: u64, value: u64) -> Option<u64> {
        if let Some(slot) = self.slot_of(key) {
            self.entries[slot].1 = value;
            self.promote(slot);
            return None;
        }
        let evicted = if self.entries.len() == self.cap {
            let (victim, _) = self.entries.remove(0);
            Some(victim)
        } else {
            None
        };
        self.entries.push((key, value));
        evicted
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_then_get_roundtrips() {
        let mut c = LruInstance::new(4);
        assert_eq!(c.put(7, 700), None);
        assert_eq!(c.put(3, 300), None);
        assert_eq!(c.get(7), Some(700));
        assert_eq!(c.get(3), Some(300));
        assert_eq!(c.get(9), None);
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn get_promotes_over_the_front_victim() {
        let mut c = LruInstance::new(3);
        c.put(1, 10);
        c.put(2, 20);
        c.put(3, 30);
        // Reading 1 makes 2 the least-recently-used victim.
        assert_eq!(c.get(1), Some(10));
        assert_eq!(c.put(4, 40), Some(2));
        assert_eq!(c.peek(2), None);
        assert_eq!(c.peek(1), Some(10));
        assert_eq!(c.peek(3), Some(30));
        assert_eq!(c.peek(4), Some(40));
    }

    #[test]
    fn updating_an_existing_key_never_evicts() {
        let mut c = LruInstance::new(2);
        c.put(5, 50);
        c.put(6, 60);
        assert_eq!(c.put(5, 55), None);
        assert_eq!(c.len(), 2);
        assert_eq!(c.get(5), Some(55));
        assert_eq!(c.get(6), Some(60));
    }

    #[test]
    fn peek_leaves_the_victim_order_alone() {
        let mut c = LruInstance::new(2);
        c.put(1, 10);
        c.put(2, 20);
        // Peeking 1 must NOT rescue it from eviction.
        assert_eq!(c.peek(1), Some(10));
        assert_eq!(c.put(3, 30), Some(1));
        assert_eq!(c.peek(1), None);
        assert_eq!(c.peek(2), Some(20));
    }

    #[test]
    fn touch_promotes_and_reports_presence() {
        let mut c = LruInstance::new(2);
        c.put(1, 10);
        c.put(2, 20);
        assert!(c.touch(1));
        assert!(!c.touch(99));
        // 1 was promoted, so 2 is now the victim.
        assert_eq!(c.put(3, 30), Some(2));
        assert_eq!(c.peek(1), Some(10));
        assert_eq!(c.peek(2), None);
    }

    #[test]
    fn soak_matches_a_shadow_model_under_random_traffic() {
        let mut c = LruInstance::new(8);
        let mut shadow: Vec<(u64, u64)> = Vec::new();
        let mut st: u64 = 0x5EED_CACE;
        for _ in 0..600 {
            st = st
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let key = (st >> 33) % 16;
            st = st
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let val = st >> 33;
            let evicted = c.put(key, val);
            if let Some(slot) = shadow.iter().position(|&(k, _)| k == key) {
                shadow[slot].1 = val;
                let e = shadow.remove(slot);
                shadow.push(e);
                assert_eq!(evicted, None);
            } else if shadow.len() == 8 {
                let victim = shadow.remove(0);
                assert_eq!(evicted, Some(victim.0));
                shadow.push((key, val));
            } else {
                assert_eq!(evicted, None);
                shadow.push((key, val));
            }
            assert_eq!(c.len(), shadow.len());
            assert!(c.len() <= 8);
        }
        // Every surviving entry agrees with the shadow model.
        for key in 0..16u64 {
            assert_eq!(
                c.peek(key),
                shadow.iter().find(|&&(k, _)| k == key).map(|&(_, v)| v)
            );
        }
        assert_eq!(c.lru_front(), shadow.first().map(|&(k, _)| k));
    }
}

use crate::{mint_canary, GeneratedTask, Generator, Rng};

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    LruLen,
    Get,
    Put,
    Peek,
    Touch,
}

pub const OP_ALL: [Op; 5] = [Op::LruLen, Op::Get, Op::Put, Op::Peek, Op::Touch];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::LruLen => "lru_len",
            Op::Get => "get",
            Op::Put => "put",
            Op::Peek => "peek",
            Op::Touch => "touch",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::LruLen => "how many entries the cache currently holds",
            Op::Get => "reads key and promotes it to most-recently-used; None on a miss",
            Op::Put => "inserts or updates key: updating refreshes in place and answers None; inserting into a full cache evicts the least-recently-used victim first and answers Some(victim_key)",
            Op::Peek => "reads key without disturbing the recency order; None on a miss",
            Op::Touch => "promotes key if present and answers whether it lived in the cache",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::LruLen => "pub fn lru_len(&self) -> u64",
            Op::Get => "pub fn get(&mut self, key: u64) -> Option<u64>",
            Op::Put => "pub fn put(&mut self, key: u64, value: u64) -> Option<u64>",
            Op::Peek => "pub fn peek(&self, key: u64) -> Option<u64>",
            Op::Touch => "pub fn touch(&mut self, key: u64) -> bool",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub const CANONICAL_SEED: u64 = 0x18C0_FA11;

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

/// Put is the fill primitive every scenario needs; when the seed did
/// not sample it, it ships as given infrastructure alongside the pair.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    if spec.ops.contains(&Op::Put) {
        spec.ops.to_vec()
    } else {
        let mut v = vec![Op::Put];
        v.extend_from_slice(&spec.ops);
        v
    }
}

/// The canonical scenario: a capacity-8 cache hammered by dozens of
/// pseudo-random puts, so any solution that mis-tracks recency (or
/// evicts the wrong victim) is wrong before the first probe.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical lru scenario");
}

fn fresh_lru(capacity: u64) -> LruInstance {
    LruInstance::new(capacity as usize)
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub capacity: u64,
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01A4;

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

const NX_MUL: u64 = 6364136223846793005;
const NX_ADD: u64 = 1442695040888963407;

/// One LCG draw.
fn nxt(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    *state >> 33
}

/// The drive's LCG state after `2 * warmup` draws (key then value per
/// put). Emitted tests re-derive this to probe one step past the end.
fn drive_base(capacity: u64, warmup: u64) -> u64 {
    let mut s = 0x5EED_CAFE ^ capacity.wrapping_mul(0x9E37).wrapping_add(warmup);
    for _ in 0..(2 * warmup) {
        s = s.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    }
    s
}

/// Drives `warmup` pseudo-random puts into a fresh cache; keys live in
/// 0..32 so collisions exercise the update-in-place path.
fn driven_lru(capacity: u64, warmup: u64) -> (LruInstance, Vec<(u64, u64)>) {
    let mut c = fresh_lru(capacity);
    let mut st = 0x5EED_CAFE ^ capacity.wrapping_mul(0x9E37).wrapping_add(warmup);
    let mut puts = Vec::new();
    for _ in 0..warmup {
        let k = nxt(&mut st) % 32;
        let v = nxt(&mut st);
        c.put(k, v);
        puts.push((k, v));
    }
    (c, puts)
}

fn opt(v: Option<u64>) -> String {
    v.map_or_else(|| "None".to_string(), |x| format!("Some({x})"))
}

// ---- emitted-source fragments -----------------------------------------------

pub const STRUCT_SRC: &str =
    "#[derive(Clone)]\npub struct Lru {\n    cap: usize,\n    entries: Vec<(u64, u64)>,\n}\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::LruLen => &["self.entries.len() as u64"],
        Op::Get => &[
            "let slot = self.entries.iter().position(|&(k, _)| k == key)?;",
            "let value = self.entries[slot].1;",
            "let entry = self.entries.remove(slot);",
            "self.entries.push(entry);",
            "Some(value)",
        ],
        Op::Put => &[
            "if let Some(slot) = self.entries.iter().position(|&(k, _)| k == key) {",
            "    self.entries[slot].1 = value;",
            "    let entry = self.entries.remove(slot);",
            "    self.entries.push(entry);",
            "    return None;",
            "}",
            "let evicted = if self.entries.len() == self.cap {",
            "    let (victim, _) = self.entries.remove(0);",
            "    Some(victim)",
            "} else {",
            "    None",
            "};",
            "self.entries.push((key, value));",
            "evicted",
        ],
        Op::Peek => &[
            "let slot = self.entries.iter().position(|&(k, _)| k == key)?;",
            "Some(self.entries[slot].1)",
        ],
        Op::Touch => &[
            "let slot = match self.entries.iter().position(|&(k, _)| k == key) {",
            "    Some(s) => s,",
            "    None => return false,",
            "};",
            "let entry = self.entries.remove(slot);",
            "self.entries.push(entry);",
            "true",
        ],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub const LRUNEW_SRC: &str =
    "impl Lru {\n    pub fn new(capacity: usize) -> Self {\n        assert!(capacity >= 1);\n        Lru {\n            cap: capacity,\n            entries: Vec::new(),\n        }\n    }\n\n    pub fn len(&self) -> usize {\n        self.entries.len()\n    }\n\n    pub fn is_empty(&self) -> bool {\n        self.entries.is_empty()\n    }\n}\n\n";

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen("pub struct Lru {", "pub struct LruRef {", 1);
    s.push_str(
        &LRUNEW_SRC
            .replace("impl Lru {", "impl LruRef {")
            .replace("Lru {\n", "LruRef {\n"),
    );
    s.push_str("impl LruRef {\n");
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
        let (c, _) = driven_lru(ex.capacity, ex.warmup);
        s.push_str(&format!(
            "//! ex{i}: capacity {c}, then {w} pseudo-random puts -> len {l}, next victim {v}\n",
            i = i,
            c = ex.capacity,
            w = ex.warmup,
            l = c.len(),
            v = c.lru_front().map_or("None".to_string(), |k| k.to_string())
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested bounded-cache operations over one\n\
         //! ordered entry list kept least-recently-used first. Reads of\n\
         //! live keys promote them; only writes may evict, and they\n\
         //! evict from the front. The hidden tests drive thousands of\n\
         //! interleaved operations and compare every returned value.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(LRUNEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested bounded-cache operations with exact least-recently-used bookkeeping.\n\nRequirements:\n- `Lru::new(capacity)` starts empty and holds at most `capacity` entries; capacity is always at least 1.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- Keep the exact struct shape and signatures.\n- Eviction always removes the current least-recently-used entry; reads promote their key so victims follow true use recency, `peek` never does.\n- No unsafe code; standard library only.\n\nSignatures:\n```rust\n");
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
        "use task::Lru;\n\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n",
    );
    for (i, ex) in examples.iter().enumerate() {
        let (h, _) = driven_lru(ex.capacity, ex.warmup);
        // Draw the probe arguments exactly one step past the warmup.
        let mut ps = drive_base(ex.capacity, ex.warmup);
        let len_now = h.len();

        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let mut drive = Lru::new({c});\n    let mut st: u64 = 0x5EED_CAFE ^ ({c}u64.wrapping_mul(0x9E37).wrapping_add({w}));\n    for _ in 0..{w} {{\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        let k = (st >> 33) % 32;\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        drive.put(k, st >> 33);\n    }}\n",
            i = i,
            c = ex.capacity,
            w = ex.warmup
        ));
        for &op in &spec.ops {
            s.push_str("    let mut r = drive.clone();\n");
            match op {
                Op::LruLen => s.push_str(&format!("    assert_eq!(r.lru_len(), {len_now});\n")),
                Op::Get => {
                    let k = nxt(&mut ps) % 32;
                    let want = h.clone().get(k);
                    s.push_str(&format!("    assert_eq!(r.get({k}), {});\n", opt(want)));
                }
                Op::Peek => {
                    let k = nxt(&mut ps) % 32;
                    let want = h.peek(k);
                    s.push_str(&format!("    assert_eq!(r.peek({k}), {});\n", opt(want)));
                }
                Op::Touch => {
                    let k = nxt(&mut ps) % 32;
                    let want = h.clone().touch(k);
                    s.push_str(&format!("    assert_eq!(r.touch({k}), {want});\n"));
                }
                Op::Put => {
                    let k = nxt(&mut ps) % 32;
                    let v = nxt(&mut ps);
                    let mut pc = h.clone();
                    let evicted = pc.put(k, v);
                    s.push_str(&format!(
                        "    assert_eq!(r.put({k}, {v}), {});\n",
                        opt(evicted)
                    ));
                    if spec.ops.contains(&Op::LruLen) {
                        s.push_str(&format!("    assert_eq!(r.lru_len(), {});\n", pc.len()));
                    }
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Scripted recency chain: a fixed put/get script whose eviction
    // victims differ between true LRU and FIFO — the no-promotion cheat
    // dies exactly at the third write.
    if spec.ops.contains(&Op::Put) && spec.ops.contains(&Op::Get) {
        s.push_str("#[test]\nfn scripted_recency_chain_evicts_the_read_victim() {\n    let mut r = Lru::new(4);\n");
        s.push_str("    assert_eq!(r.put(0, 0), None);\n    assert_eq!(r.put(1, 10), None);\n    assert_eq!(r.put(2, 20), None);\n    assert_eq!(r.put(3, 30), None);\n    assert_eq!(r.put(4, 40), Some(0));\n");
        s.push_str("    assert_eq!(r.get(1), Some(10));\n    assert_eq!(r.put(5, 50), Some(2));\n");
        if spec.ops.contains(&Op::Peek) {
            s.push_str("    assert_eq!(r.peek(2), None);\n    assert_eq!(r.peek(3), Some(30));\n");
        }
        s.push_str("    assert_eq!(r.get(4), Some(40));\n    assert_eq!(r.put(6, 60), Some(3));\n    assert_eq!(r.get(1), Some(10));\n    assert_eq!(r.put(7, 70), Some(5));\n");
        if spec.ops.contains(&Op::Peek) {
            s.push_str("    assert_eq!(r.peek(5), None);\n    assert_eq!(r.peek(4), Some(40));\n");
        }
        if spec.ops.contains(&Op::LruLen) {
            s.push_str("    assert_eq!(r.lru_len(), 4);\n");
        }
        s.push_str("}\n");
    }
    // Bounded fill soak: random keys over a tiny cache must keep the
    // count pinned at capacity once full.
    if spec.ops.contains(&Op::Put) && spec.ops.contains(&Op::LruLen) {
        s.push_str("#[test]\nfn bounded_fill_soak_pins_the_count() {\n    let mut r = Lru::new(4);\n    let mut st: u64 = 0x5EED_0000_0000_01A6;\n    for i in 0..1200u64 {\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        let k = (st >> 33) % 16;\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        r.put(k, st >> 33);\n        assert_eq!(r.lru_len(), std::cmp::min(i + 1, 4));\n    }\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::Lru;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    let ops = effective_ops(spec);
    s.push_str("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {\n    let mut cand = Lru::new(6);\n    let mut refr = LruRef::new(6);\n");
    if ops.contains(&Op::Get) {
        s.push_str("    assert_eq!(cand.get(9999), refr.ref_get(9999));\n");
    }
    if ops.contains(&Op::Peek) {
        s.push_str("    assert_eq!(cand.peek(9999), refr.ref_peek(9999));\n");
    }
    if ops.contains(&Op::Touch) {
        s.push_str("    assert!(!cand.touch(9999));\n    assert!(!refr.ref_touch(9999));\n");
    }
    let arm_count = ops.len();
    s.push_str(&format!("    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_01A4;\n    for _ in 0..3000 {{\n        let arg = nx(&mut state);\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in ops.iter().enumerate() {
        let body = match op {
            Op::Put => {
                "assert_eq!(cand.put(arg % 12, arg), refr.ref_put(arg % 12, arg));".to_string()
            }
            Op::Get => "assert_eq!(cand.get(arg % 12), refr.ref_get(arg % 12));".to_string(),
            Op::Peek => "assert_eq!(cand.peek(arg % 12), refr.ref_peek(arg % 12));".to_string(),
            Op::Touch => "assert_eq!(cand.touch(arg % 12), refr.ref_touch(arg % 12));".to_string(),
            Op::LruLen => "assert_eq!(cand.lru_len(), refr.ref_lru_len());".to_string(),
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
    s.push_str(LRUNEW_SRC);
    s.push_str("impl Lru {\n");
    for &op in &ops {
        let body = match op {
            Op::LruLen => "0",
            Op::Get | Op::Peek | Op::Put => "None",
            Op::Touch => "false",
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s.push_str("}\n");
    s
}

/// The plausible FIFO cheat: identical API and eviction-on-full, but
/// reads never promote — so the victim order silently becomes insertion
/// order. Looks like a cache, survives the first few puts on a cold
/// cache, then starts evicting freshly-read keys — exactly what the
/// scripted recency chain exists to catch.
pub fn fifo_no_promote_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(LRUNEW_SRC);
    s.push_str("impl Lru {\n");
    for &op in &ops {
        let body: &[&str] = match op {
            Op::LruLen => &["self.entries.len() as u64"],
            Op::Get | Op::Peek => &[
                "let slot = self.entries.iter().position(|&(k, _)| k == key)?;",
                "Some(self.entries[slot].1)",
            ],
            Op::Touch => &["self.entries.iter().any(|&(k, _)| k == key)"],
            Op::Put => &[
                "if let Some(slot) = self.entries.iter().position(|&(k, _)| k == key) {",
                "    self.entries[slot].1 = value;",
                "    return None;",
                "}",
                "let evicted = if self.entries.len() == self.cap {",
                "    let (victim, _) = self.entries.remove(0);",
                "    Some(victim)",
                "} else {",
                "    None",
                "};",
                "self.entries.push((key, value));",
                "evicted",
            ],
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

pub struct LruCacheFamily;

impl Generator for LruCacheFamily {
    fn id(&self) -> &'static str {
        "lru-cache"
    }

    fn category(&self) -> &'static str {
        "recency-tracking"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("lru-cache", seed);
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
            id: format!("lru-cache/{seed:016x}"),
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
        s.push_str(LRUNEW_SRC);
        s.push_str("impl Lru {\n");
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
            ("fifo-no-promote".to_string(), fifo_no_promote_src(spec)),
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
        let a = LruCacheFamily.generate(55);
        let b = LruCacheFamily.generate(55);
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
            let (c, puts) = driven_lru(8, warmup);
            assert_eq!(puts.len(), warmup as usize);
            assert!(!c.is_empty() && c.len() <= 8);
            assert!(c.lru_front().is_some());
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let (c, _) = driven_lru(ex.capacity, ex.warmup);
                assert!(c.len() <= ex.capacity as usize);
                assert_eq!(c.lru_front().is_some(), !c.is_empty());
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct LruRef"));
            assert!(!src.contains("pub fn get"));
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
            let canary = mint_canary("lru-cache", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in ["iter().position(", ".remove(", "entries[0]", "remove(0)"] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("recency"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("LruRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soaks() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            let chain = spec.ops.contains(&Op::Put) && spec.ops.contains(&Op::Get);
            let pins = spec.ops.contains(&Op::Put) && spec.ops.contains(&Op::LruLen);
            assert_eq!(
                behavior.contains("scripted_recency_chain_evicts_the_read_victim"),
                chain,
                "seed {seed}: chain soak misaligned"
            );
            assert_eq!(
                behavior.contains("bounded_fill_soak_pins_the_count"),
                pins,
                "seed {seed}: count soak misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_cache_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let fifo = fifo_no_promote_src(spec);
        assert!(cz.contains("None"));
        assert!(!fifo.contains("remove(slot)"));
        assert!(fifo.contains("remove(0)"));
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("lru-cache", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
