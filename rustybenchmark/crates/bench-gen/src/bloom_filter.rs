//! The `bloom-filter` family (category `membership-sketch`) — probabilistic
//! set-membership puzzles where the *bit pattern* is the data structure.
//!
//! Every puzzle mirrors a real fixed-size Bloom filter stored as one
//! `Vec<u64>` of 64-bit words: `insert` flips all k probe slots for a
//! value, `might_contain` answers whether every slot is set, and
//! `slot_for`/`bit_at` expose the double-hashing index math directly so
//! any shortcut in it is observable. The seed picks which two of five
//! ops are required: `bloom_bits`, `insert`, `might_contain`, `bit_at`,
//! `slot_for`. No false negatives is the invariant every cheat breaks.

/// One fixed-size filter. `words` holds `64 * words.len()` bits; every
/// value probes exactly `hashes` slots derived by double hashing.
#[derive(Clone)]
pub struct BloomInstance {
    words: Vec<u64>,
    hashes: usize,
}

impl BloomInstance {
    /// A fresh all-zero filter with at least one word and one hash.
    ///
    /// # Panics
    /// Panics when `bits` or `hashes` is zero — a filter that can hold
    /// no bits or probe no slots cannot answer membership, so it is
    /// rejected up front.
    pub fn new(bits: usize, hashes: usize) -> Self {
        assert!(bits >= 1, "filter needs at least one bit");
        assert!(hashes >= 1, "filter needs at least one probe hash");
        BloomInstance {
            words: vec![0; bits.div_ceil(64)],
            hashes,
        }
    }

    pub fn total_bits(&self) -> usize {
        self.words.len() * 64
    }

    fn h1(value: u64) -> u64 {
        value.wrapping_mul(0x9E37_79B9_7F4A_7C15)
    }

    fn h2(value: u64) -> u64 {
        (value >> 17) | 1
    }

    /// The absolute bit index of the `which`-th probe slot for `value`.
    /// `which` reduces modulo the hash count, so indexes beyond `k`
    /// wrap onto real probes.
    pub fn slot_for(&self, value: u64, which: u64) -> u64 {
        let total = self.total_bits() as u64;
        let stride = which % self.hashes as u64;
        Self::h1(value).wrapping_add(stride.wrapping_mul(Self::h2(value))) % total
    }

    fn slot_mask(slot: u64) -> u64 {
        1u64 << (slot % 64)
    }

    /// Sets all probe slots for `value`; answers how many bits flipped
    /// from 0 to 1 (0 when the value was already fully present).
    pub fn insert(&mut self, value: u64) -> u64 {
        let total = self.total_bits() as u64;
        let mut fresh = 0u64;
        for i in 0..self.hashes as u64 {
            let slot = Self::h1(value).wrapping_add(i.wrapping_mul(Self::h2(value))) % total;
            let mask = Self::slot_mask(slot);
            if self.words[(slot / 64) as usize] & mask == 0 {
                self.words[(slot / 64) as usize] |= mask;
                fresh += 1;
            }
        }
        fresh
    }

    /// Answers whether every probe slot for `value` is set. Inserted
    /// values always answer true — that is the no-false-negatives
    /// invariant.
    pub fn might_contain(&self, value: u64) -> bool {
        let total = self.total_bits() as u64;
        (0..self.hashes as u64).all(|i| {
            let slot = Self::h1(value).wrapping_add(i.wrapping_mul(Self::h2(value))) % total;
            self.words[(slot / 64) as usize] & Self::slot_mask(slot) != 0
        })
    }

    /// Direct bit observation: `Some(set)` inside the filter, `None`
    /// past its end.
    pub fn bit_at(&self, index: u64) -> Option<bool> {
        if index >= self.total_bits() as u64 {
            return None;
        }
        Some(self.words[(index / 64) as usize] & Self::slot_mask(index) != 0)
    }

    /// Population count — how many bits of the filter are currently set.
    pub fn bits_set(&self) -> u64 {
        self.words.iter().map(|word| word.count_ones()).sum::<u32>() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_then_might_contain_roundtrips() {
        let mut b = BloomInstance::new(128, 3);
        assert_eq!(b.bits_set(), 0);
        for v in 0..20u64 {
            let value = v * 7919;
            b.insert(value);
            assert!(b.might_contain(value));
        }
        assert!(b.bits_set() > 0 && b.bits_set() <= 128);
    }

    #[test]
    fn duplicate_insert_flips_no_new_bits() {
        let mut b = BloomInstance::new(256, 4);
        let first = b.insert(42);
        assert!(first >= 1);
        assert_eq!(b.insert(42), 0);
        assert_eq!(b.insert(42), 0);
        assert_eq!(b.bits_set(), first);
    }

    #[test]
    fn bit_at_agrees_with_slots_and_bounds() {
        let mut b = BloomInstance::new(192, 3);
        assert_eq!(b.bit_at(0), Some(false));
        for v in [1u64, 50, 999_999] {
            b.insert(v);
            for i in 0..3u64 {
                let slot = b.slot_for(v, i);
                assert_eq!(b.bit_at(slot), Some(true));
            }
        }
        assert_eq!(b.bit_at(b.total_bits() as u64), None);
        assert_eq!(b.bit_at(u64::MAX), None);
    }

    #[test]
    fn slot_for_is_deterministic_and_wraps_which() {
        let b = BloomInstance::new(320, 3);
        for v in [0u64, 7, 12345, u64::MAX] {
            assert_eq!(b.slot_for(v, 5), b.slot_for(v, 2));
            assert_eq!(b.slot_for(v, 0), b.slot_for(v, 3));
            assert!(b.slot_for(v, 11) < 320);
        }
    }

    #[test]
    fn distinct_values_spread_probe_bits() {
        let mut b = BloomInstance::new(256, 3);
        for v in 0..30u64 {
            b.insert((v + 1).wrapping_mul(0x1234_5678_9ABC_DEF1));
        }
        // 90 probe writes over 256 bits must land well past 60 distinct
        // positions even under collisions.
        assert!(b.bits_set() >= 60, "spread collapsed to {}", b.bits_set());
    }

    #[test]
    fn soak_matches_a_shadow_bitmap_under_random_traffic() {
        let mut b = BloomInstance::new(512, 4);
        let mut shadow = vec![false; 512];
        let inserted: Vec<u64> = Vec::new();
        let mut st: u64 = 0x5EED_B100;
        let mut ins = inserted;
        for _ in 0..600 {
            st = st
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let v = st >> 33;
            ins.push(v);
            b.insert(v);
            let h1 = v.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            let h2 = (v >> 17) | 1;
            for i in 0..4u64 {
                let slot = h1.wrapping_add(i.wrapping_mul(h2)) % 512;
                shadow[slot as usize] = true;
            }
            assert_eq!(
                b.bits_set(),
                shadow.iter().copied().filter(|set| *set).count() as u64
            );
        }
        // Membership agrees with the shadow bitmap on fresh queries too.
        for _ in 0..200 {
            st = st
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let q = st >> 33;
            let expected = (0..4u64).all(|i| {
                let slot = q
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .wrapping_add(i.wrapping_mul((q >> 17) | 1))
                    % 512;
                shadow[slot as usize]
            });
            assert_eq!(b.might_contain(q), expected);
        }
        assert!(ins.iter().all(|&v| b.might_contain(v)));
    }
}

use crate::{mint_canary, GeneratedTask, Generator, Rng};

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    BloomBits,
    Insert,
    MightContain,
    BitAt,
    SlotFor,
}

pub const OP_ALL: [Op; 5] = [
    Op::BloomBits,
    Op::Insert,
    Op::MightContain,
    Op::BitAt,
    Op::SlotFor,
];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::BloomBits => "bloom_bits",
            Op::Insert => "insert",
            Op::MightContain => "might_contain",
            Op::BitAt => "bit_at",
            Op::SlotFor => "slot_for",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::BloomBits => "how many bits of the filter are currently set",
            Op::Insert => "sets every probe slot for value and answers how many bits flipped from 0 to 1",
            Op::MightContain => "answers whether every probe slot for value is set; an inserted value always answers true",
            Op::BitAt => "answers whether the filter's bit at absolute index is set, or None past the end",
            Op::SlotFor => "answers the absolute bit index of the which-th probe slot for value",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::BloomBits => "pub fn bloom_bits(&self) -> u64",
            Op::Insert => "pub fn insert(&mut self, value: u64) -> u64",
            Op::MightContain => "pub fn might_contain(&self, value: u64) -> bool",
            Op::BitAt => "pub fn bit_at(&self, index: u64) -> Option<bool>",
            Op::SlotFor => "pub fn slot_for(&self, value: u64, which: u64) -> u64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub const CANONICAL_SEED: u64 = 0xB100_FA11;

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

/// Insert is the fill primitive every scenario needs; when the seed did
/// not sample it, it ships as given infrastructure alongside the pair.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    if spec.ops.contains(&Op::Insert) {
        spec.ops.to_vec()
    } else {
        let mut v = vec![Op::Insert];
        v.extend_from_slice(&spec.ops);
        v
    }
}

/// The canonical scenario: a 4-word (256-bit) filter hammered by dozens
/// of pseudo-random inserts, so any solution that mis-computes even one
/// probe slot is wrong before the first probe.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical bloom scenario");
}

fn fresh_bloom(words: u64) -> BloomInstance {
    BloomInstance::new((words * 64) as usize, 3)
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub words: u64,
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01AC;

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![
        ExampleCase {
            words: 4,
            warmup: canonical(seed),
        },
        ExampleCase {
            words: 1,
            warmup: 3,
        },
        ExampleCase {
            words: 2,
            warmup: 4,
        },
        ExampleCase {
            words: 8,
            warmup: 17,
        },
    ];
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    for _ in 0..3 {
        let words = 1u64 << rng.below(4);
        out.push(ExampleCase {
            words,
            warmup: rng.below(words * 16) + 1,
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

/// The drive's LCG state after `warmup` draws (one full value per
/// insert). Emitted tests re-derive this to probe one step past the end.
fn drive_base(words: u64, warmup: u64) -> u64 {
    let mut s = 0xB100_CAFE ^ words.wrapping_mul(0x9E37).wrapping_add(warmup);
    for _ in 0..warmup {
        s = s.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    }
    s
}

/// Drives `warmup` pseudo-random inserts into a fresh 3-hash filter;
/// values span the full u64 range so the hash spread is exercised.
fn driven_bloom(words: u64, warmup: u64) -> (BloomInstance, Vec<u64>) {
    let mut b = fresh_bloom(words);
    let mut st = 0xB100_CAFE ^ words.wrapping_mul(0x9E37).wrapping_add(warmup);
    let mut inserted = Vec::new();
    for _ in 0..warmup {
        let v = nxt(&mut st);
        b.insert(v);
        inserted.push(v);
    }
    (b, inserted)
}

// ---- emitted-source fragments -----------------------------------------------

pub const STRUCT_SRC: &str =
    "#[derive(Clone)]\npub struct Bloom {\n    words: Vec<u64>,\n    hashes: usize,\n}\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::BloomBits => &["self.words.iter().map(|word| word.count_ones()).sum::<u32>() as u64"],
        Op::Insert => &[
            "let total = self.total_bits() as u64;",
            "let h1 = value.wrapping_mul(0x9E37_79B9_7F4A_7C15);",
            "let h2 = (value >> 17) | 1;",
            "let mut fresh = 0u64;",
            "for i in 0..self.hashes as u64 {",
            "    let slot = h1.wrapping_add(i.wrapping_mul(h2)) % total;",
            "    let mask = 1u64 << (slot % 64);",
            "    if self.words[(slot / 64) as usize] & mask == 0 {",
            "        self.words[(slot / 64) as usize] |= mask;",
            "        fresh += 1;",
            "    }",
            "}",
            "fresh",
        ],
        Op::MightContain => &[
            "let total = self.total_bits() as u64;",
            "let h1 = value.wrapping_mul(0x9E37_79B9_7F4A_7C15);",
            "let h2 = (value >> 17) | 1;",
            "(0..self.hashes as u64).all(|i| {",
            "    let slot = h1.wrapping_add(i.wrapping_mul(h2)) % total;",
            "    self.words[(slot / 64) as usize] & (1u64 << (slot % 64)) != 0",
            "})",
        ],
        Op::BitAt => &[
            "if index >= self.total_bits() as u64 {",
            "    return None;",
            "}",
            "Some(self.words[(index / 64) as usize] & (1u64 << (index % 64)) != 0)",
        ],
        Op::SlotFor => &[
            "let total = self.total_bits() as u64;",
            "let stride = which % self.hashes as u64;",
            "value.wrapping_mul(0x9E37_79B9_7F4A_7C15)",
            "    .wrapping_add(stride.wrapping_mul((value >> 17) | 1))",
            "    % total",
        ],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub const BLOOMNEW_SRC: &str = "impl Bloom {\n    pub fn new(bits: usize, hashes: usize) -> Self {\n        assert!(bits >= 1 && hashes >= 1);\n        Bloom {\n            words: vec![0; bits.div_ceil(64)],\n            hashes,\n        }\n    }\n\n    pub fn total_bits(&self) -> usize {\n        self.words.len() * 64\n    }\n}\n\n";

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen("pub struct Bloom {", "pub struct BloomRef {", 1);
    s.push_str(
        &BLOOMNEW_SRC
            .replace("impl Bloom {", "impl BloomRef {")
            .replace("Bloom {\n", "BloomRef {\n"),
    );
    s.push_str("impl BloomRef {\n");
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
        let (b, _) = driven_bloom(ex.words, ex.warmup);
        s.push_str(&format!(
            "//! ex{i}: {w} words ({t} bits), then {n} pseudo-random inserts -> bits_set {b}\n",
            i = i,
            w = ex.words,
            t = ex.words * 64,
            n = ex.warmup,
            b = b.bits_set()
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested Bloom-filter operations over one\n\
         //! bitmap of 64-bit words. Inserts set every probe slot for a\n\
         //! value; queries answer whether all slots are set and never\n\
         //! lie about an inserted value. The hidden tests drive\n\
         //! thousands of interleaved operations and compare every\n\
         //! returned value.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(BLOOMNEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested Bloom-filter operations with exact double-hashing index math.\n\nRequirements:\n- `Bloom::new(bits, hashes)` allocates one zeroed 64-bit word per 64 requested bits; both arguments are always at least 1.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- Probe slots come from double hashing: h1(v) = v.wrapping_mul(0x9E3779B97F4A7C15), h2(v) = (v >> 17) | 1, and slot i = h1.wrapping_add(i.wrapping_mul(h2)) modulo total_bits.\n- `slot_for` reduces `which` modulo the hash count before computing; `bit_at` answers None past the last bit.\n- An inserted value must always query true; no unsafe code; standard library only.\n\nSignatures:\n```rust\n");
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
        "use task::Bloom;\n\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n",
    );
    for (i, ex) in examples.iter().enumerate() {
        let (h, ins) = driven_bloom(ex.words, ex.warmup);
        // Draw the probe arguments exactly one step past the warmup.
        let mut ps = drive_base(ex.words, ex.warmup);
        let bits_now = h.bits_set();
        let total = ex.words * 64;
        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let mut drive = Bloom::new({w} * 64, 3);\n    let mut st: u64 = 0xB100_CAFE ^ ({w}u64.wrapping_mul(0x9E37).wrapping_add({n}));\n    for _ in 0..{n} {{\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        drive.insert(st >> 33);\n    }}\n",
            i = i,
            w = ex.words,
            n = ex.warmup
        ));
        for &op in &spec.ops {
            s.push_str("    let mut r = drive.clone();\n");
            match op {
                Op::BloomBits => {
                    s.push_str(&format!("    assert_eq!(r.bloom_bits(), {bits_now});\n"));
                }
                Op::Insert => {
                    let v = nxt(&mut ps);
                    let want = h.clone().insert(v);
                    s.push_str(&format!("    assert_eq!(r.insert({v}), {want});\n"));
                }
                Op::MightContain => {
                    let v = nxt(&mut ps);
                    let want = h.might_contain(v);
                    s.push_str(&format!("    assert_eq!(r.might_contain({v}), {want});\n"));
                    // A freshly inserted value must always query true —
                    // the no-false-negatives invariant pinned literally.
                    let pinned = ins.last().copied().unwrap_or_default();
                    s.push_str(&format!("    assert!(r.might_contain({pinned}));\n"));
                }
                Op::BitAt => {
                    let idx = nxt(&mut ps) % total;
                    let want = h
                        .bit_at(idx)
                        .map_or_else(|| "None".to_string(), |b| format!("Some({b})"));
                    s.push_str(&format!("    assert_eq!(r.bit_at({idx}), {want});\n"));
                    s.push_str(&format!("    assert_eq!(r.bit_at({total}), None);\n"));
                }
                Op::SlotFor => {
                    let v = nxt(&mut ps);
                    let which = nxt(&mut ps) % 5;
                    let want = h.slot_for(v, which);
                    s.push_str(&format!(
                        "    assert_eq!(r.slot_for({v}, {which}), {want});\n"
                    ));
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Scripted requery: every inserted value must still answer true
    // after the whole batch lands — a filter that drops or misplaces
    // any probe bit trips here.
    if spec.ops.contains(&Op::Insert) && spec.ops.contains(&Op::MightContain) {
        s.push_str("#[test]\nfn scripted_requery_never_gives_a_false_negative() {\n    let mut r = Bloom::new(256, 3);\n    for v in 0..24u64 {\n        let value = v.wrapping_mul(6131).wrapping_add(7);\n        r.insert(value);\n        assert!(r.might_contain(value));\n    }\n    for v in 0..24u64 {\n        assert!(r.might_contain(v.wrapping_mul(6131).wrapping_add(7)));\n    }\n}\n");
    }
    // Fill soak: random inserts over a 4-word filter must keep the
    // population pinned to an incrementally maintained shadow bitmap.
    if spec.ops.contains(&Op::Insert) && spec.ops.contains(&Op::BloomBits) {
        s.push_str("#[test]\nfn fill_soak_tracks_the_shadow_popcount() {\n    let mut r = Bloom::new(512, 4);\n    let mut shadow = vec![false; 512];\n    let mut st: u64 = 0x5EED_0000_0000_01AE;\n    for _ in 0..800u64 {\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        let v = st >> 33;\n        r.insert(v);\n        let h1 = v.wrapping_mul(0x9E37_79B9_7F4A_7C15);\n        let h2 = (v >> 17) | 1;\n        for i in 0..4u64 {\n            shadow[(h1.wrapping_add(i.wrapping_mul(h2)) % 512) as usize] = true;\n        }\n        assert_eq!(r.bloom_bits(), shadow.iter().copied().filter(|set| *set).count() as u64);\n    }\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::Bloom;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    let ops = effective_ops(spec);
    s.push_str("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {\n    let mut cand = Bloom::new(384, 3);\n    let mut refr = BloomRef::new(384, 3);\n");
    if ops.contains(&Op::Insert) {
        s.push_str("    assert_eq!(cand.insert(7777), refr.ref_insert(7777));\n");
    }
    if ops.contains(&Op::MightContain) {
        s.push_str("    assert_eq!(cand.might_contain(9999), refr.ref_might_contain(9999));\n");
    }
    if ops.contains(&Op::BitAt) {
        s.push_str("    assert_eq!(cand.bit_at(4096), refr.ref_bit_at(4096));\n");
    }
    if ops.contains(&Op::SlotFor) {
        s.push_str("    assert_eq!(cand.slot_for(8888, 11), refr.ref_slot_for(8888, 11));\n");
    }
    if ops.contains(&Op::BloomBits) {
        s.push_str("    assert_eq!(cand.bloom_bits(), refr.ref_bloom_bits());\n");
    }
    let arm_count = ops.len();
    s.push_str(&format!("    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_01AC;\n    for _ in 0..3000 {{\n        let arg = nx(&mut state);\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in ops.iter().enumerate() {
        let body = match op {
            Op::Insert => "assert_eq!(cand.insert(arg), refr.ref_insert(arg));".to_string(),
            Op::MightContain => {
                "assert_eq!(cand.might_contain(arg), refr.ref_might_contain(arg));".to_string()
            }
            Op::BitAt => {
                "assert_eq!(cand.bit_at(arg % 384), refr.ref_bit_at(arg % 384));".to_string()
            }
            Op::SlotFor => {
                "assert_eq!(cand.slot_for(arg, arg % 5), refr.ref_slot_for(arg, arg % 5));"
                    .to_string()
            }
            Op::BloomBits => "assert_eq!(cand.bloom_bits(), refr.ref_bloom_bits());".to_string(),
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
    s.push_str(BLOOMNEW_SRC);
    s.push_str("impl Bloom {\n");
    for &op in &ops {
        let body = match op {
            Op::BloomBits | Op::Insert | Op::SlotFor => "0",
            Op::MightContain => "false",
            Op::BitAt => "None",
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s.push_str("}\n");
    s
}

/// The plausible one-hash cheat: identical API and hash function, but
/// every probe collapses onto the h1 slot — the stride term vanishes.
/// Looks like a working filter on singleton lookups, then diverges the
/// moment `slot_for` observes an index or two values collide on h1.
pub fn single_hash_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(BLOOMNEW_SRC);
    s.push_str("impl Bloom {\n");
    for &op in &ops {
        let body: &[&str] = match op {
            Op::BloomBits => {
                &["self.words.iter().map(|word| word.count_ones()).sum::<u32>() as u64"]
            }
            Op::Insert => &[
                "let total = self.total_bits() as u64;",
                "let h1 = value.wrapping_mul(0x9E37_79B9_7F4A_7C15);",
                "let slot = h1 % total;",
                "let mask = 1u64 << (slot % 64);",
                "let fresh = u64::from(self.words[(slot / 64) as usize] & mask == 0);",
                "self.words[(slot / 64) as usize] |= mask;",
                "fresh",
            ],
            Op::MightContain => &[
                "let total = self.total_bits() as u64;",
                "let h1 = value.wrapping_mul(0x9E37_79B9_7F4A_7C15);",
                "let slot = h1 % total;",
                "self.words[(slot / 64) as usize] & (1u64 << (slot % 64)) != 0",
            ],
            Op::BitAt => &[
                "if index >= self.total_bits() as u64 {",
                "    return None;",
                "}",
                "Some(self.words[(index / 64) as usize] & (1u64 << (index % 64)) != 0)",
            ],
            Op::SlotFor => &[
                "let total = self.total_bits() as u64;",
                "value.wrapping_mul(0x9E37_79B9_7F4A_7C15) % total",
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

pub struct BloomFilterFamily;

impl Generator for BloomFilterFamily {
    fn id(&self) -> &'static str {
        "bloom-filter"
    }

    fn category(&self) -> &'static str {
        "membership-sketch"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("bloom-filter", seed);
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
            id: format!("bloom-filter/{seed:016x}"),
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
        s.push_str(BLOOMNEW_SRC);
        s.push_str("impl Bloom {\n");
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
            ("single-hash".to_string(), single_hash_src(spec)),
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
        let a = BloomFilterFamily.generate(55);
        let b = BloomFilterFamily.generate(55);
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
            let (b, inserted) = driven_bloom(4, warmup);
            assert_eq!(inserted.len(), warmup as usize);
            assert!(b.bits_set() > 0 && b.bits_set() <= 256);
            assert!(b.might_contain(inserted[inserted.len() - 1]));
            assert!(b.slot_for(inserted[0], 2) < 256);
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let (b, inserted) = driven_bloom(ex.words, ex.warmup);
                assert!(b.bits_set() <= ex.words * 64);
                assert!(b.might_contain(inserted[inserted.len() - 1]));
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct BloomRef"));
            assert!(!src.contains("pub fn insert"));
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
            let canary = mint_canary("bloom-filter", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in [".count_ones(", "/ 64", "% 64)", "<< (slot"] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("double hashing"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("BloomRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soaks() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            let requery = spec.ops.contains(&Op::Insert) && spec.ops.contains(&Op::MightContain);
            let pins = spec.ops.contains(&Op::Insert) && spec.ops.contains(&Op::BloomBits);
            assert_eq!(
                behavior.contains("scripted_requery_never_gives_a_false_negative"),
                requery,
                "seed {seed}: requery soak misaligned"
            );
            assert_eq!(
                behavior.contains("fill_soak_tracks_the_shadow_popcount"),
                pins,
                "seed {seed}: popcount soak misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_filter_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let single = single_hash_src(spec);
        assert!(!cz.contains("wrapping_mul"));
        assert!(single.contains("h1 % total"));
        assert!(!single.contains("wrapping_mul(h2)"));
        assert!(single.contains("fn insert"));
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("bloom-filter", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
