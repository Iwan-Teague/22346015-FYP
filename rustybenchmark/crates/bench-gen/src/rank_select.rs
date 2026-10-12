//! Rank-select natives: a fixed-capacity bitmap with exact ordering
//! queries. `rank` counts set bits inclusively up to a probe index,
//! `select` answers where the (k+1)-th set bit lives, and both must stay
//! exact as bits flip on and stay on.

/// Scenario capacity in bits; every scenario shares this fixed width.
pub const RS_BITS: usize = 96;

#[derive(Clone)]
pub struct RankSelectInstance {
    /// Packed words; bit j of words[i] is index i * 64 + j, low to high.
    words: Vec<u64>,
    /// Logical width in bits (may sit inside the last word).
    cap: usize,
    total_set: u64,
}

impl RankSelectInstance {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity >= 1);
        Self {
            words: vec![0u64; capacity.div_ceil(64)],
            cap: capacity,
            total_set: 0,
        }
    }

    /// Total width in bits the bitmap can address.
    pub fn rs_len(&self) -> u64 {
        self.cap as u64
    }

    /// Sets one bit and answers whether it was ALREADY set (false when
    /// freshly set). Panics past the end.
    pub fn set_bit(&mut self, index: usize) -> bool {
        let was = self.bit_at(index).expect("bit index out of range");
        if !was {
            let word = index / 64;
            self.words[word] |= 1u64 << (index % 64);
            self.total_set += 1;
        }
        was
    }

    /// Liveness of one bit; None out of range.
    pub fn bit_at(&self, index: usize) -> Option<bool> {
        if index >= self.cap {
            return None;
        }
        Some(self.words[index / 64] & (1u64 << (index % 64)) != 0)
    }

    /// Number of set bits in 0..=index inclusive; an index at or past the
    /// end clamps to the full popcount.
    pub fn rank(&self, index: usize) -> u64 {
        let mut n = 0u64;
        for i in 0..=index.min(self.cap - 1) {
            if self.bit_at(i) == Some(true) {
                n += 1;
            }
        }
        n
    }

    /// 0-based: the index of the (k+1)-th set bit scanning low to high;
    /// None when k is at least the number of set bits.
    pub fn select(&self, k: usize) -> Option<u64> {
        if k >= self.total_set as usize {
            return None;
        }
        let mut seen = 0usize;
        for i in 0..self.cap {
            if self.bit_at(i) == Some(true) {
                if seen == k {
                    return Some(i as u64);
                }
                seen += 1;
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_bitat_rank_roundtrip_on_picked_indices() {
        let mut rs = RankSelectInstance::new(RS_BITS);
        assert_eq!(rs.rs_len(), RS_BITS as u64);
        for idx in [0usize, 1, 63, 64, 65, 95] {
            assert!(!rs.set_bit(idx), "freshly set must answer false");
            assert_eq!(rs.bit_at(idx), Some(true));
            assert!(rs.set_bit(idx), "already-set must answer true");
        }
        assert_eq!(rs.rank(95), 6);
    }

    #[test]
    fn double_set_answers_true_and_keeps_single_counting() {
        let mut rs = RankSelectInstance::new(RS_BITS);
        assert!(!rs.set_bit(40));
        for _ in 0..5 {
            assert!(rs.set_bit(40));
            assert_eq!(rs.rank(95), 1);
            assert_eq!(rs.rank(40), 1);
        }
        rs.set_bit(41);
        assert!(rs.set_bit(41));
        assert_eq!(rs.rank(41), 2);
        assert_eq!(rs.rank(95), 2);
    }

    #[test]
    fn select_enumerates_set_positions_in_order_then_none() {
        let mut rs = RankSelectInstance::new(RS_BITS);
        for idx in [70usize, 3, 12, 90] {
            rs.set_bit(idx);
        }
        assert_eq!(rs.select(0), Some(3));
        assert_eq!(rs.select(1), Some(12));
        assert_eq!(rs.select(2), Some(70));
        assert_eq!(rs.select(3), Some(90));
        assert_eq!(rs.select(4), None);
        assert_eq!(rs.select(200), None);
        assert_eq!(rs.select(0), Some(3), "select never mutates");
    }

    #[test]
    fn rank_is_inclusive_and_clamps_past_the_end() {
        let mut rs = RankSelectInstance::new(RS_BITS);
        for idx in [0usize, 31, 32, 94] {
            rs.set_bit(idx);
        }
        assert_eq!(rs.rank(0), 1);
        assert_eq!(rs.rank(30), 1);
        assert_eq!(rs.rank(31), 2);
        assert_eq!(rs.rank(32), 3);
        assert_eq!(rs.rank(93), 3);
        assert_eq!(rs.rank(94), 4);
        assert_eq!(rs.rank(95), 4);
        assert_eq!(rs.rank(96), 4);
        assert_eq!(rs.rank(500), 4);
        assert_eq!(rs.rank(500), rs.rank(95));
    }

    #[test]
    fn bounds_are_guarded_exactly_at_the_edge() {
        let rs = RankSelectInstance::new(RS_BITS);
        assert_eq!(rs.bit_at(95), Some(false));
        assert_eq!(rs.bit_at(96), None);
        assert_eq!(rs.bit_at(97), None);
        assert_eq!(rs.bit_at(10000), None);
    }

    #[test]
    #[should_panic]
    fn set_bit_panics_past_the_end() {
        let mut rs = RankSelectInstance::new(RS_BITS);
        rs.set_bit(96);
    }

    #[test]
    fn soak_matches_a_shadow_bitmap_under_random_traffic() {
        let mut shadow = vec![false; RS_BITS];
        let mut rs = RankSelectInstance::new(RS_BITS);
        let mut st: u64 = 0x5EED_0A11;
        let linear_select = |shadow: &[bool], k: usize| -> Option<usize> {
            let mut seen = 0usize;
            for (i, &b) in shadow.iter().enumerate() {
                if b {
                    if seen == k {
                        return Some(i);
                    }
                    seen += 1;
                }
            }
            None
        };
        for _ in 0..600 {
            let idx = ((st >> 33) % RS_BITS as u64) as usize;
            let want = shadow[idx];
            assert_eq!(rs.set_bit(idx), want, "set_bit answer at {idx}");
            shadow[idx] = true;
            assert_eq!(
                rs.rank(idx),
                shadow[..=idx].iter().filter(|&&b| b).count() as u64
            );
            let k = ((st >> 21) % 24) as usize;
            assert_eq!(
                rs.select(k).map(|v| v as usize),
                linear_select(&shadow, k),
                "select({k}) drifted"
            );
            let probe = ((st >> 45) % (RS_BITS as u64 + 3)) as usize;
            assert_eq!(rs.bit_at(probe), shadow.get(probe).copied());
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
    RsLen,
    SetBit,
    BitAt,
    Rank,
    Select,
}

pub const OP_ALL: [Op; 5] = [Op::RsLen, Op::SetBit, Op::BitAt, Op::Rank, Op::Select];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::RsLen => "rs_len",
            Op::SetBit => "set_bit",
            Op::BitAt => "bit_at",
            Op::Rank => "rank",
            Op::Select => "select",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::RsLen => "answers how many bits the bitmap spans in total",
            Op::SetBit => "sets one bit and answers whether that bit was ALREADY live - false when the bit was freshly set, true when it was live before; an index at or past the end panics",
            Op::BitAt => "answers whether one bit is live, or None when the index is at or past the end",
            Op::Rank => "answers how many live bits sit at indices 0..=probe inclusive; a probe at or past the end answers the total number of live bits",
            Op::Select => "answers the 0-based index of the (k+1)-th live bit scanning low to high, or None when k reaches the number of live bits",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::RsLen => "pub fn rs_len(&self) -> u64",
            Op::SetBit => "pub fn set_bit(&mut self, index: usize) -> bool",
            Op::BitAt => "pub fn bit_at(&self, index: usize) -> Option<bool>",
            Op::Rank => "pub fn rank(&self, index: usize) -> u64",
            Op::Select => "pub fn select(&self, k: usize) -> Option<u64>",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub const CANONICAL_SEED: u64 = 0x0A11_FA11;

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

/// SetBit is the fill primitive and Select is the audit probe; both ship
/// as given infrastructure alongside the sampled pair, so a solution whose
/// select drifts escapes no seed - a tally-breaking cheat is invisible to
/// set_bit/rank alone unless select ships on every scenario.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    let mut v = vec![Op::SetBit];
    if !spec.ops.contains(&Op::Select) {
        v.push(Op::Select);
    }
    for o in spec.ops {
        if !v.contains(&o) {
            v.push(o);
        }
    }
    v
}

/// The canonical scenario: dozens of sets across the fixed width, so
/// collisions, ordering and boundary probes all show up repeatedly.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical rank-select scenario");
}

fn fresh_bitmap() -> RankSelectInstance {
    RankSelectInstance::new(RS_BITS)
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01E4;

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

fn drive_init(warmup: u64) -> u64 {
    0x0A11_CAFEu64 ^ warmup.wrapping_mul(0x9E37)
}

/// Drives `warmup` random set_bits into a fresh bitmap.
fn driven_bitmap(warmup: u64) -> RankSelectInstance {
    let mut b = fresh_bitmap();
    let mut st = drive_init(warmup);
    for _ in 0..warmup {
        let idx = ((st >> 33) % RS_BITS as u64) as usize;
        b.set_bit(idx);
        st = st.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    }
    b
}

/// The probe-continuation state after the drive loop (one advance per set).
fn drive_final_state(warmup: u64) -> u64 {
    let mut st = drive_init(warmup);
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

fn opt_fmt(v: Option<bool>) -> String {
    v.map_or_else(|| "None".to_string(), |b| format!("Some({b})"))
}

fn sel_fmt(v: Option<u64>) -> String {
    v.map_or_else(|| "None".to_string(), |x| format!("Some({x})"))
}

// ---- emitted-source fragments -----------------------------------------------

pub const STRUCT_SRC: &str = "#[derive(Clone)]\npub struct RankSelect {\n    words: Vec<u64>,\n    cap: usize,\n    total: u64,\n}\n";

pub const BITMAP_NEW_SRC: &str = "impl RankSelect {\n    pub fn new(capacity: usize) -> Self {\n        assert!(capacity >= 1);\n        RankSelect {\n            words: vec![0u64; capacity.div_ceil(64)],\n            cap: capacity,\n            total: 0,\n        }\n    }\n}\n\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

const SET_BODY: &[&str] = &[
    "assert!(index < self.cap);",
    "let word = index / 64;",
    "let mask = 1u64 << (index % 64);",
    "let was = self.words[word] & mask != 0;",
    "if !was {",
    "    self.words[word] |= mask;",
    "    self.total += 1;",
    "}",
    "was",
];

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::RsLen => &["self.cap as u64"],
        Op::SetBit => SET_BODY,
        Op::BitAt => &[
            "if index >= self.cap {",
            "    return None;",
            "}",
            "Some(self.words[index / 64] & (1u64 << (index % 64)) != 0)",
        ],
        Op::Rank => &[
            "let end = index.min(self.cap - 1);",
            "let mut n = 0u64;",
            "for i in 0..=end {",
            "    if self.words[i / 64] & (1u64 << (i % 64)) != 0 {",
            "        n += 1;",
            "    }",
            "}",
            "n",
        ],
        Op::Select => &[
            "if k >= self.total as usize {",
            "    return None;",
            "}",
            "let mut seen = 0usize;",
            "for i in 0..self.cap {",
            "    if self.words[i / 64] & (1u64 << (i % 64)) != 0 {",
            "        if seen == k {",
            "            return Some(i as u64);",
            "        }",
            "        seen += 1;",
            "    }",
            "}",
            "None",
        ],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen("pub struct RankSelect {", "pub struct RankSelectRef {", 1);
    s.push_str(
        &BITMAP_NEW_SRC
            .replace("impl RankSelect {", "impl RankSelectRef {")
            .replace("RankSelect {\n", "RankSelectRef {\n"),
    );
    s.push_str("impl RankSelectRef {\n");
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
        let b = driven_bitmap(ex.warmup);
        s.push_str(&format!(
            "//! ex{i}: {w} random sets -> {t} of {c} bits live\n",
            i = i,
            w = ex.warmup,
            t = b.rank(RS_BITS - 1),
            c = b.rs_len(),
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested bitmap-ordering operations over one\n\
          //! internal packed-word structure: bits live in whole 64-bit words\n\
          //! low bits first, the width is fixed once and never grows, and\n\
          //! every tally and position query must stay exact even as bits\n\
          //! flip on. The hidden tests drive thousands of interleaved\n\
          //! operations and compare every returned value.\n\
          //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(BITMAP_NEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested bitmap-ordering operations with exactly maintained bookkeeping.\n\nRequirements:\n- `RankSelect::new(capacity)` starts with every bit clear at exactly that capacity; the constructor is given.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- The bitmap holds a fixed capacity in bits, packed into whole 64-bit words with bit index 0 as the lowest bit of word zero; it never grows or shrinks.\n- `set_bit` answers the previous liveness: false when it flips a bit on, true when the bit was already live, and setting a live bit changes nothing.\n- `rank` counts inclusively over indices 0..=probe; a probe at or past the end answers the full tally of live bits.\n- `select` is 0-based: it answers the index of the (k+1)-th live bit scanning low to high, or None when fewer than k+1 bits are live; `bit_at` answers None past the end.\n- Queries never mutate the bitmap; no floating point; no unsafe code; standard library only.\n\nSignatures:\n```rust\n");
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
    let mut s = String::from("use task::RankSelect;\n\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n");
    for (i, ex) in examples.iter().enumerate() {
        let h = driven_bitmap(ex.warmup);
        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let mut drive = RankSelect::new({cap});\n    let mut st: u64 = {init};\n    for _ in 0..{w} {{\n        let idx = ((st >> 33) % {bits}) as usize;\n        drive.set_bit(idx);\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    }}\n",
            i = i,
            w = ex.warmup,
            cap = RS_BITS,
            bits = RS_BITS,
            init = drive_init(ex.warmup)
        ));
        s.push_str(&format!(
            "    let mut ps: u64 = {};\n",
            drive_final_state(ex.warmup)
        ));
        let mut ps = drive_final_state(ex.warmup);
        for &op in &spec.ops {
            match op {
                Op::RsLen => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.rs_len(), {});\n",
                        h.rs_len()
                    ));
                }
                Op::SetBit => {
                    let idx = (nx(&mut ps) % RS_BITS as u64) as usize;
                    let want = h.clone().set_bit(idx);
                    s.push_str(&format!(
                        "    let mut r = drive.clone();\n    let idx = ((nx(&mut ps) % {bits}) as usize);\n    assert_eq!(r.set_bit(idx), {want});\n",
                        bits = RS_BITS,
                        want = want
                    ));
                }
                Op::BitAt => {
                    let idx = (nx(&mut ps) % RS_BITS as u64) as usize;
                    let want = h.bit_at(idx);
                    s.push_str(&format!(
                        "    let r = drive.clone();\n    let idx = ((nx(&mut ps) % {bits}) as usize);\n    assert_eq!(r.bit_at(idx), {want});\n    assert_eq!(drive.bit_at({bits}), None);\n",
                        bits = RS_BITS,
                        want = opt_fmt(want)
                    ));
                }
                Op::Rank => {
                    let idx = (nx(&mut ps) % RS_BITS as u64) as usize;
                    let want = h.rank(idx);
                    s.push_str(&format!(
                        "    let r = drive.clone();\n    let idx = ((nx(&mut ps) % {bits}) as usize);\n    assert_eq!(r.rank(idx), {want});\n",
                        bits = RS_BITS,
                        want = want
                    ));
                }
                Op::Select => {
                    let k = (nx(&mut ps) % 24) as usize;
                    let want = h.select(k);
                    s.push_str(&format!(
                        "    let r = drive.clone();\n    let k = ((nx(&mut ps) % 24) as usize);\n    assert_eq!(r.select(k), {want});\n    assert_eq!(drive.select(200), None);\n",
                        want = sel_fmt(want)
                    ));
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Scripted probe: select enumerates the live positions low to high and
    // re-setting a live bit shifts nothing.
    if spec.ops.contains(&Op::SetBit) && spec.ops.contains(&Op::Select) {
        s.push_str("#[test]\nfn scripted_select_enumerates_positions_in_order() {\n    let mut r = RankSelect::new(96);\n    assert_eq!(r.select(0), None);\n    r.set_bit(70);\n    r.set_bit(3);\n    r.set_bit(12);\n    r.set_bit(90);\n    assert_eq!(r.select(0), Some(3));\n    assert_eq!(r.select(1), Some(12));\n    assert_eq!(r.select(2), Some(70));\n    assert_eq!(r.select(3), Some(90));\n    assert_eq!(r.select(4), None);\n    assert!(r.set_bit(12));\n    assert_eq!(r.select(1), Some(12));\n}\n");
    }
    // Scripted probe: set_bit echoes previous liveness and reads stay exact.
    if spec.ops.contains(&Op::SetBit) && spec.ops.contains(&Op::BitAt) {
        s.push_str("#[test]\nfn scripted_bitat_echoes_previous_liveness() {\n    let mut r = RankSelect::new(96);\n    assert_eq!(r.bit_at(5), Some(false));\n    assert_eq!(r.set_bit(5), false);\n    assert_eq!(r.bit_at(5), Some(true));\n    assert_eq!(r.set_bit(5), true);\n    assert_eq!(r.bit_at(96), None);\n}\n");
    }
    // Scripted probe: the width is fixed and setting bits never grows it.
    if spec.ops.contains(&Op::SetBit) && spec.ops.contains(&Op::RsLen) {
        s.push_str("#[test]\nfn scripted_rslen_stays_the_fixed_width() {\n    let mut r = RankSelect::new(96);\n    assert_eq!(r.rs_len(), 96);\n    r.set_bit(95);\n    assert_eq!(r.rs_len(), 96);\n}\n");
    }
    // Fill soak: six hundred random sets must keep every inclusive rank
    // pinned to a shadow prefix of a plain boolean mirror.
    if spec.ops.contains(&Op::SetBit) && spec.ops.contains(&Op::Rank) {
        s.push_str("#[test]\nfn fill_soak_pins_rank_to_a_shadow_prefix() {\n    let mut r = RankSelect::new(96);\n    let mut shadow: Vec<bool> = vec![false; 96];\n    let mut st: u64 = 0x5EED_0000_0000_01E6;\n    for _ in 0..600usize {\n        let idx = ((st >> 33) % 96) as usize;\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        let want = shadow[idx];\n        assert_eq!(r.set_bit(idx), want);\n        shadow[idx] = true;\n        assert_eq!(r.rank(idx), shadow[..=idx].iter().filter(|&&b| b).count() as u64);\n    }\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::RankSelect;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    let ops = effective_ops(spec);
    s.push_str("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {\n    let mut cand = RankSelect::new(112);\n    let mut refr = RankSelectRef::new(112);\n");
    if ops.contains(&Op::Select) {
        s.push_str("    assert_eq!(cand.select(9999), refr.ref_select(9999));\n");
    }
    if ops.contains(&Op::BitAt) {
        s.push_str("    assert_eq!(cand.bit_at(9999), refr.ref_bit_at(9999));\n");
    }
    if ops.contains(&Op::Rank) {
        s.push_str("    assert_eq!(cand.rank(200), refr.ref_rank(200));\n");
    }
    if ops.contains(&Op::RsLen) {
        s.push_str("    assert_eq!(cand.rs_len(), refr.ref_rs_len());\n");
    }
    if ops.contains(&Op::SetBit) {
        let mut pre: u64 = 0x0A11_D1FF;
        for _ in 0..12u64 {
            let idx = (nx(&mut pre) % 96) as usize;
            s.push_str(&format!(
                "    assert_eq!(cand.set_bit({idx}), refr.ref_set_bit({idx}));\n"
            ));
        }
    }
    let arm_count = ops.len();
    s.push_str(&format!("    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_01E4;\n    for _ in 0..3000 {{\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in ops.iter().enumerate() {
        let body = match op {
            Op::RsLen => "assert_eq!(cand.rs_len(), refr.ref_rs_len());".to_string(),
            Op::SetBit => {
                "let idx = ((nx(&mut state) % 96) as usize);\n            assert_eq!(cand.set_bit(idx), refr.ref_set_bit(idx));".to_string()
            }
            Op::BitAt => {
                "let idx = ((nx(&mut state) % 96) as usize);\n            assert_eq!(cand.bit_at(idx), refr.ref_bit_at(idx));".to_string()
            }
            Op::Rank => {
                "let idx = ((nx(&mut state) % 96) as usize);\n            assert_eq!(cand.rank(idx), refr.ref_rank(idx));".to_string()
            }
            Op::Select => {
                "let k = ((nx(&mut state) % 24) as usize);\n            assert_eq!(cand.select(k), refr.ref_select(k));".to_string()
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
    s.push_str(BITMAP_NEW_SRC);
    s.push_str("impl RankSelect {\n");
    for &op in &ops {
        let body = match op {
            Op::SetBit => "false",
            Op::BitAt | Op::Select => "None",
            _ => "0",
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s.push_str("}\n");
    s
}

/// The plausible cheat: the word flip happens but the tally is forgotten -
/// storage stays honest, yet every None-boundary in `select` reads the
/// frozen zero tally, so select denies bits that demonstrably live.
pub fn forgetful_tally_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(BITMAP_NEW_SRC);
    s.push_str("impl RankSelect {\n");
    for &op in &ops {
        match op {
            Op::SetBit => {
                let body = &[
                    "assert!(index < self.cap);",
                    "let word = index / 64;",
                    "self.words[word] |= 1u64 << (index % 64);",
                    "false",
                ];
                s.push_str(&format!(
                    "{} {{\n    {}\n}}\n",
                    op_sig_src(op),
                    body.join("\n    ")
                ));
            }
            _ => s.push_str(&op_fn_src(op)),
        }
    }
    s.push_str("}\n");
    s
}

pub struct RankSelectFamily;

impl Generator for RankSelectFamily {
    fn id(&self) -> &'static str {
        "rank-select"
    }

    fn category(&self) -> &'static str {
        "bitmap-ordering"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("rank-select", seed);
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
            id: format!("rank-select/{seed:016x}"),
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
        s.push_str(BITMAP_NEW_SRC);
        s.push_str("impl RankSelect {\n");
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
            ("forgetful-tally".to_string(), forgetful_tally_src(spec)),
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
        let a = RankSelectFamily.generate(55);
        let b = RankSelectFamily.generate(55);
        assert_eq!(a.prompt, b.prompt);
        assert_eq!(a.files, b.files);
        assert_eq!(a.hidden, b.hidden);
    }

    #[test]
    fn seeds_vary_query_pairs() {
        let mut seen = std::collections::HashSet::new();
        for seed in 0..199u64 {
            seen.insert(sample(seed));
        }
        assert!(seen.len() >= 9, "only {} distinct pairs", seen.len());
    }

    #[test]
    fn canonical_scenarios_stay_bounded() {
        for seed in 0..200u64 {
            let warmup = canonical(seed);
            assert!(warmup >= 24 && warmup.is_multiple_of(8));
            let b = driven_bitmap(warmup);
            assert_eq!(b.rs_len(), RS_BITS as u64);
            assert!(b.rank(RS_BITS - 1) <= warmup);
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let b = driven_bitmap(ex.warmup);
                assert_eq!(b.rs_len(), RS_BITS as u64);
                assert!(b.rank(RS_BITS - 1) <= ex.warmup);
                assert!(ex.warmup >= 2);
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct RankSelectRef"));
            assert!(
                src.matches("RankSelectRef {").count() >= 2,
                "constructor body must be renamed too"
            );
            assert!(!src.contains("pub fn set_bit"));
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
            let canary = mint_canary("rank-select", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in [".count_ones(", "trailing_zeros", ".rotate_("] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("bitmap"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("RankSelectRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soaks() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            let rank_gate = spec.ops.contains(&Op::SetBit) && spec.ops.contains(&Op::Rank);
            let select_gate = spec.ops.contains(&Op::SetBit) && spec.ops.contains(&Op::Select);
            let bitat_gate = spec.ops.contains(&Op::SetBit) && spec.ops.contains(&Op::BitAt);
            let rslen_gate = spec.ops.contains(&Op::SetBit) && spec.ops.contains(&Op::RsLen);
            assert_eq!(
                behavior.contains("fill_soak_pins_rank_to_a_shadow_prefix"),
                rank_gate,
                "seed {seed}: rank soak misaligned"
            );
            assert_eq!(
                behavior.contains("scripted_select_enumerates_positions_in_order"),
                select_gate,
                "seed {seed}: select script misaligned"
            );
            assert_eq!(
                behavior.contains("scripted_bitat_echoes_previous_liveness"),
                bitat_gate,
                "seed {seed}: liveness script misaligned"
            );
            assert_eq!(
                behavior.contains("scripted_rslen_stays_the_fixed_width"),
                rslen_gate,
                "seed {seed}: width script misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_bitmap_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let cheat = forgetful_tally_src(spec);
        assert!(!cz.contains("todo!()"));
        assert!(cheat.contains("fn set_bit"));
        let us = cheat.find("fn set_bit").unwrap();
        let ue = us + cheat[us..].find("\n}\n").unwrap();
        let ub = &cheat[us..ue];
        assert!(
            ub.contains("self.words[word] |="),
            "cheat must keep the word flip honest"
        );
        assert!(!ub.contains("self.total"), "the forgotten tally is the bug");
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("rank-select", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
