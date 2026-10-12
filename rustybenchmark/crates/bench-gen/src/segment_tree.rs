//! Segment-tree natives: a fixed-capacity array-backed segment tree whose
//! point writes refresh every ancestor by dominance and whose inclusive
//! range queries climb both boundaries of the covered span.

/// Every scenario uses the same power-of-two capacity.
pub const SEG_CAP: usize = 32;

#[derive(Clone)]
pub struct SegmentTreeInstance {
    tree: Vec<u64>,
    cap: usize,
}

impl SegmentTreeInstance {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity >= 1, "capacity must be at least one slot");
        assert!(
            capacity.is_power_of_two(),
            "capacity {capacity} must be a power of two"
        );
        Self {
            tree: vec![0; capacity * 2],
            cap: capacity,
        }
    }

    pub fn seg_len(&self) -> u64 {
        self.cap as u64
    }

    fn total_slots(&self) -> usize {
        self.cap
    }

    /// Stores `value` at `index` (overwriting whatever sat there), rebuilds
    /// every ancestor as the maximum of its two children, and answers the
    /// freshly stored value.
    pub fn update(&mut self, index: usize, value: u64) -> u64 {
        let slots = self.total_slots();
        assert!(index < slots, "index {index} out of range");
        let mut pos = index + self.cap;
        self.tree[pos] = value;
        while pos > 1 {
            pos /= 2;
            self.tree[pos] = self.tree[pos * 2].max(self.tree[pos * 2 + 1]);
        }
        value
    }

    /// Inclusive range maximum over `[lo, hi]`; untouched slots weigh zero.
    pub fn range_max(&self, lo: usize, hi: usize) -> u64 {
        assert!(
            lo <= hi && hi < self.cap,
            "range [{lo}, {hi}] out of order or out of range"
        );
        let mut l = lo + self.cap;
        let mut r = hi + self.cap + 1;
        let mut best = 0;
        while l < r {
            if l & 1 == 1 {
                best = best.max(self.tree[l]);
                l += 1;
            }
            if r & 1 == 1 {
                r -= 1;
                best = best.max(self.tree[r]);
            }
            l /= 2;
            r /= 2;
        }
        best
    }

    /// Reads the raw slot at `index`, or `None` past the end.
    pub fn point(&self, index: usize) -> Option<u64> {
        if index >= self.cap {
            None
        } else {
            Some(self.tree[index + self.cap])
        }
    }

    pub fn total(&self) -> u64 {
        self.tree[1]
    }
}

#[cfg(test)]
mod tests {
    use super::SegmentTreeInstance;

    #[test]
    fn update_overwrites_and_answers_the_stored_value() {
        let mut h = SegmentTreeInstance::new(8);
        assert_eq!(h.update(3, 5), 5);
        assert_eq!(h.update(3, 42), 42);
        assert_eq!(h.update(0, 7), 7);
        assert_eq!(h.seg_len(), 8);
    }

    #[test]
    fn ranges_match_a_shadow_slice() {
        let mut h = SegmentTreeInstance::new(8);
        let mut shadow = [0u64; 8];
        for (idx, value) in [(2usize, 9u64), (5, 3), (2, 4), (7, 6), (0, 11)] {
            h.update(idx, value);
            shadow[idx] = value;
            for lo in 0..8 {
                for hi in lo..8 {
                    let want = shadow[lo..=hi].iter().max().copied().unwrap_or(0);
                    assert_eq!(h.range_max(lo, hi), want, "max [{lo},{hi}]");
                }
            }
        }
    }

    #[test]
    fn full_range_equals_the_total() {
        let mut h = SegmentTreeInstance::new(16);
        for (idx, value) in [(0usize, 10u64), (5, 60), (9, 100), (15, 160)] {
            h.update(idx, value);
        }
        assert_eq!(h.range_max(0, 15), h.total());
        assert_eq!(h.range_max(0, 15), 160);
        assert_eq!(h.total(), 160);
    }

    #[test]
    fn overwrites_retire_old_peaks_instead_of_accumulating() {
        let mut h = SegmentTreeInstance::new(8);
        h.update(4, 90);
        assert_eq!(h.range_max(0, 7), 90);
        h.update(4, 40);
        assert_eq!(h.range_max(0, 7), 40);
        assert_eq!(h.point(4), Some(40));
        assert_eq!(h.total(), 40);
    }

    #[test]
    fn fresh_tree_and_point_bounds() {
        let h = SegmentTreeInstance::new(4);
        assert_eq!(h.seg_len(), 4);
        assert_eq!(h.range_max(0, 3), 0);
        assert_eq!(h.point(2), Some(0));
        assert_eq!(h.point(4), None);
        assert_eq!(h.point(999), None);
        assert_eq!(h.total(), 0);
    }

    #[test]
    #[should_panic]
    fn rejects_unsorted_or_out_of_range_queries() {
        let h = SegmentTreeInstance::new(4);
        let _ = h.range_max(3, 1);
    }

    #[test]
    fn soak_matches_a_shadow_vec_under_random_traffic() {
        let mut h = SegmentTreeInstance::new(16);
        let mut shadow = [0u64; 16];
        let mul: u64 = 6364136223846793005;
        let add: u64 = 1442695040888963407;
        let mut st: u64 = 0x5EED_5E6A;
        for _ in 0..600 {
            let idx = ((st >> 33) % 16) as usize;
            let v = (st >> 7) % 200;
            h.update(idx, v);
            shadow[idx] = v;
            let lo = ((st >> 41) % 16) as usize;
            let span = ((st >> 17) % 16) as usize;
            let hi = (lo + span).min(15);
            if lo <= hi {
                let want = shadow[lo..=hi].iter().max().copied().unwrap_or(0);
                assert_eq!(h.range_max(lo, hi), want, "soak max [{lo},{hi}]");
            }
            assert_eq!(h.total(), shadow.iter().max().copied().unwrap_or(0));
            st = st.wrapping_mul(mul).wrapping_add(add);
        }
    }
}

// ---- generator --------------------------------------------------------------

use crate::{mint_canary, GeneratedTask, Generator, Rng};

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    SegLen,
    Update,
    RangeMax,
    Point,
    Total,
}

pub const OP_ALL: [Op; 5] = [Op::SegLen, Op::Update, Op::RangeMax, Op::Point, Op::Total];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::SegLen => "seg_len",
            Op::Update => "update",
            Op::RangeMax => "range_max",
            Op::Point => "point",
            Op::Total => "total",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::SegLen => "answers how many slots the fixed-width tree spans",
            Op::Update => "stores the incoming value outright - it replaces whatever occupied the slot rather than adding to it - then refreshes every ancestor on the climb toward the root and answers the stored value; an index at or past the end panics",
            Op::RangeMax => "answers the largest stored value across the inclusive span, or zero when nothing inside the span was ever written",
            Op::Point => "reads back the raw stored slot, answering None past the end",
            Op::Total => "answers the largest value anywhere in the tree by reading the single root cell",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::SegLen => "pub fn seg_len(&self) -> u64",
            Op::Update => "pub fn update(&mut self, index: usize, value: u64) -> u64",
            Op::RangeMax => "pub fn range_max(&self, lo: usize, hi: usize) -> u64",
            Op::Point => "pub fn point(&self, index: usize) -> Option<u64>",
            Op::Total => "pub fn total(&self) -> u64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub const CANONICAL_SEED: u64 = 0x5E6A_FA11;

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

/// Update is the fill primitive and RangeMax is the audit probe; both ship
/// as given infrastructure alongside the sampled pair, so a solution whose
/// ancestors go stale escapes no seed - a write that skips the climb leaves
/// every range answer drifting unless the query ships on every scenario.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    let mut v = vec![Op::Update];
    if !spec.ops.contains(&Op::RangeMax) {
        v.push(Op::RangeMax);
    }
    for o in spec.ops {
        if !v.contains(&o) {
            v.push(o);
        }
    }
    v
}

/// The canonical scenario: dozens of writes across the fixed width, so
/// overwrites, boundary spans and stale-ancestor probes all show up.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical segment-tree scenario");
}

fn fresh_tree() -> SegmentTreeInstance {
    SegmentTreeInstance::new(SEG_CAP)
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub span: u64,
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01EC;

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![
        ExampleCase {
            span: 40,
            warmup: canonical(seed),
        },
        ExampleCase { span: 6, warmup: 3 },
        ExampleCase {
            span: 12,
            warmup: 4,
        },
        ExampleCase {
            span: 20,
            warmup: 17,
        },
    ];
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    for _ in 0..8 {
        let span = 4 + rng.below(60);
        out.push(ExampleCase {
            span,
            warmup: rng.below(span * 2) + 2,
        });
    }
    out
}

const NX_MUL: u64 = 6364136223846793005;
const NX_ADD: u64 = 1442695040888963407;

fn drive_init(span: u64, warmup: u64) -> u64 {
    0x5E6A_CAFEu64 ^ span.wrapping_mul(0x9E37).wrapping_add(warmup)
}

/// Drives `warmup` random overwrites into a fresh width-32 tree.
fn driven_tree(span: u64, warmup: u64) -> SegmentTreeInstance {
    let mut t = fresh_tree();
    let mut st = drive_init(span, warmup);
    for _ in 0..warmup {
        let idx = ((st >> 33) % SEG_CAP as u64) as usize;
        let value = (st >> 7) % span;
        t.update(idx, value);
        st = st.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    }
    t
}

/// The probe-continuation state after the drive loop (one advance per write).
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

fn sel_fmt(v: Option<u64>) -> String {
    v.map_or_else(|| "None".to_string(), |x| format!("Some({x})"))
}

// ---- emitted-source fragments -----------------------------------------------

pub const STRUCT_SRC: &str =
    "#[derive(Clone)]\npub struct SegmentTree {\n    tree: Vec<u64>,\n    cap: usize,\n}\n";

pub const TREE_NEW_SRC: &str = "impl SegmentTree {\n    pub fn new(capacity: usize) -> Self {\n        assert!(capacity >= 1);\n        assert!(capacity.is_power_of_two());\n        SegmentTree {\n            tree: vec![0u64; capacity * 2],\n            cap: capacity,\n        }\n    }\n}\n\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

const UPDATE_BODY: &[&str] = &[
    "let slots = self.cap;",
    "assert!(index < slots);",
    "let mut pos = index + self.cap;",
    "self.tree[pos] = value;",
    "while pos > 1 {",
    "    pos /= 2;",
    "    self.tree[pos] = self.tree[pos * 2].max(self.tree[pos * 2 + 1]);",
    "}",
    "value",
];

const RANGE_BODY: &[&str] = &[
    "assert!(lo <= hi && hi < self.cap);",
    "let mut l = lo + self.cap;",
    "let mut r = hi + self.cap + 1;",
    "let mut best = 0u64;",
    "while l < r {",
    "    if l & 1 == 1 {",
    "        best = best.max(self.tree[l]);",
    "        l += 1;",
    "    }",
    "    if r & 1 == 1 {",
    "        r -= 1;",
    "        best = best.max(self.tree[r]);",
    "    }",
    "    l /= 2;",
    "    r /= 2;",
    "}",
    "best",
];

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::SegLen => &["self.cap as u64"],
        Op::Update => UPDATE_BODY,
        Op::RangeMax => RANGE_BODY,
        Op::Point => &[
            "if index >= self.cap {",
            "    return None;",
            "}",
            "Some(self.tree[index + self.cap])",
        ],
        Op::Total => &["self.tree[1]"],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen("pub struct SegmentTree {", "pub struct SegmentTreeRef {", 1);
    s.push_str(
        &TREE_NEW_SRC
            .replace("impl SegmentTree {", "impl SegmentTreeRef {")
            .replace("SegmentTree {\n", "SegmentTreeRef {\n"),
    );
    s.push_str("impl SegmentTreeRef {\n");
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
        let t = driven_tree(ex.span, ex.warmup);
        s.push_str(&format!(
            "//! ex{i}: {w} overwrites with values below {span} -> peak {t} across {c} slots\n",
            i = i,
            w = ex.warmup,
            span = ex.span,
            t = t.total(),
            c = t.seg_len(),
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested range-dominance operations over one\n\
           //! internal array-backed structure: each slot owns a leaf cell,\n\
           //! every parent summarizes its two children, and the whole span\n\
           //! collapses into the single root cell. Writes replace slot\n\
           //! contents outright and rebuild the ancestry above them; queries\n\
           //! must stay exact even after thousands of interleaved writes.\n\
           //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(TREE_NEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested range-dominance operations with exactly maintained bookkeeping.\n\nRequirements:\n- `SegmentTree::new(capacity)` allocates exactly twice as many cells as slots with every slot reading zero; the constructor is given.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- The capacity is fixed once and must be a power of two; slot j lives at cell j + capacity inside an internal array whose length is twice the capacity.\n- A write stores the incoming value outright - it replaces whatever occupied the slot rather than adding to it - and then rebuilds each ancestor on the climb toward the root as the larger of that ancestor's two children.\n- An inclusive maximum query walks both boundaries of the covered span inward from the leaves; whenever a boundary rests on an odd cell the query absorbs that cell and steps inward, and both boundaries halve together until they cross.\n- Untouched slots weigh zero, so a query over virgin ground answers zero; `point` reads the raw slot and answers None past the end; `total` is the single root cell.\n- Queries never mutate the tree; no floating point; no unsafe code; standard library only.\n\nSignatures:\n```rust\n");
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
    let mut s = String::from("use task::SegmentTree;\n\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n");
    for (i, ex) in examples.iter().enumerate() {
        let h = driven_tree(ex.span, ex.warmup);
        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let mut drive = SegmentTree::new({cap});\n    let mut st: u64 = {init};\n    for _ in 0..{w} {{\n        let idx = ((st >> 33) % {bits}) as usize;\n        drive.update(idx, (st >> 7) % {span});\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    }}\n",
            i = i,
            w = ex.warmup,
            cap = SEG_CAP,
            bits = SEG_CAP,
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
                Op::SegLen => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.seg_len(), {});\n",
                        h.seg_len()
                    ));
                }
                Op::Update => {
                    let idx = (nx(&mut ps) % SEG_CAP as u64) as usize;
                    let v = nx(&mut ps) % ex.span;
                    let want = h.clone().update(idx, v);
                    s.push_str(&format!(
                        "    let mut r = drive.clone();\n    let idx = ((nx(&mut ps) % {bits}) as usize);\n    let v = nx(&mut ps) % {span};\n    assert_eq!(r.update(idx, v), {want});\n",
                        bits = SEG_CAP,
                        span = ex.span,
                        want = want
                    ));
                }
                Op::RangeMax => {
                    let lo = (nx(&mut ps) % SEG_CAP as u64) as usize;
                    let hi = (lo + (nx(&mut ps) % SEG_CAP as u64) as usize).min(SEG_CAP - 1);
                    let want = h.range_max(lo, hi);
                    s.push_str(&format!(
                        "    let r = drive.clone();\n    let lo = ((nx(&mut ps) % {bits}) as usize);\n    let hi = (lo + ((nx(&mut ps) % {bits}) as usize)).min({top});\n    assert_eq!(r.range_max(lo, hi), {want});\n",
                        bits = SEG_CAP,
                        top = SEG_CAP - 1,
                        want = want
                    ));
                }
                Op::Point => {
                    let idx = (nx(&mut ps) % SEG_CAP as u64) as usize;
                    let want = h.point(idx);
                    s.push_str(&format!(
                        "    let r = drive.clone();\n    let idx = ((nx(&mut ps) % {bits}) as usize);\n    assert_eq!(r.point(idx), {want});\n    assert_eq!(drive.point({bits}), None);\n",
                        bits = SEG_CAP,
                        want = sel_fmt(want)
                    ));
                }
                Op::Total => {
                    s.push_str(&format!("    assert_eq!(drive.total(), {});\n", h.total()));
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Scripted probe: an overwrite retires the old peak instead of stacking
    // on top of it, so dominance - not accumulation - rules the tree.
    if spec.ops.contains(&Op::Update) && spec.ops.contains(&Op::RangeMax) {
        s.push_str("#[test]\nfn scripted_overwrites_retire_old_peaks() {\n    let mut r = SegmentTree::new(8);\n    assert_eq!(r.update(4, 90), 90);\n    assert_eq!(r.range_max(0, 7), 90);\n    assert_eq!(r.update(4, 40), 40);\n    assert_eq!(r.range_max(0, 7), 40);\n    assert_eq!(r.update(2, 100), 100);\n    assert_eq!(r.range_max(3, 6), 40);\n    assert_eq!(r.range_max(0, 7), 100);\n}\n");
    }
    // Scripted probe: point reads back the raw slot through later rewrites.
    if spec.ops.contains(&Op::Update) && spec.ops.contains(&Op::Point) {
        s.push_str("#[test]\nfn scripted_point_reads_back_the_raw_slot() {\n    let mut r = SegmentTree::new(8);\n    assert_eq!(r.point(5), Some(0));\n    assert_eq!(r.update(5, 7), 7);\n    assert_eq!(r.point(5), Some(7));\n    assert_eq!(r.update(5, 9), 9);\n    assert_eq!(r.point(5), Some(9));\n    assert_eq!(r.point(8), None);\n}\n");
    }
    // Scripted probe: the width is fixed and writes never grow it.
    if spec.ops.contains(&Op::Update) && spec.ops.contains(&Op::SegLen) {
        s.push_str("#[test]\nfn scripted_width_stays_fixed() {\n    let mut r = SegmentTree::new(8);\n    assert_eq!(r.seg_len(), 8);\n    assert_eq!(r.update(7, 3), 3);\n    assert_eq!(r.seg_len(), 8);\n}\n");
    }
    // Scripted probe: the root cell answers the global peak, and retiring
    // the peak retires it from the total too.
    if spec.ops.contains(&Op::Update) && spec.ops.contains(&Op::Total) {
        s.push_str("#[test]\nfn scripted_total_answers_the_global_peak() {\n    let mut r = SegmentTree::new(16);\n    assert_eq!(r.update(2, 30), 30);\n    assert_eq!(r.total(), 30);\n    assert_eq!(r.update(9, 70), 70);\n    assert_eq!(r.total(), 70);\n    assert_eq!(r.update(9, 50), 50);\n    assert_eq!(r.total(), 50);\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::SegmentTree;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    let ops = effective_ops(spec);
    s.push_str("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {\n    let mut cand = SegmentTree::new(64);\n    let mut refr = SegmentTreeRef::new(64);\n");
    if ops.contains(&Op::Point) {
        s.push_str("    assert_eq!(cand.point(9999), refr.ref_point(9999));\n");
    }
    if ops.contains(&Op::RangeMax) {
        s.push_str("    assert_eq!(cand.range_max(0, 31), refr.ref_range_max(0, 63));\n");
    }
    if ops.contains(&Op::Total) {
        s.push_str("    assert_eq!(cand.total(), refr.ref_total());\n");
    }
    if ops.contains(&Op::SegLen) {
        s.push_str("    assert_eq!(cand.seg_len(), refr.ref_seg_len());\n");
    }
    if ops.contains(&Op::Update) {
        let mut pre: u64 = 0x5E6A_D1FF;
        for _ in 0..12u64 {
            let idx = (nx(&mut pre) % 32) as usize;
            let v = nx(&mut pre) % 23;
            s.push_str(&format!(
                "    assert_eq!(cand.update({idx}, {v}), refr.ref_update({idx}, {v}));\n"
            ));
        }
    }
    let arm_count = ops.len();
    s.push_str(&format!("    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_01EC;\n    for _ in 0..3000 {{\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in ops.iter().enumerate() {
        let body = match op {
            Op::SegLen => "assert_eq!(cand.seg_len(), refr.ref_seg_len());".to_string(),
            Op::Update => {
                "let idx = ((nx(&mut state) % 32) as usize);\n            let v = nx(&mut state) % 23;\n            assert_eq!(cand.update(idx, v), refr.ref_update(idx, v));".to_string()
            }
            Op::RangeMax => {
                "let lo = ((nx(&mut state) % 32) as usize);\n            let hi = (lo + ((nx(&mut state) % 32) as usize)).min(31);\n            assert_eq!(cand.range_max(lo, hi), refr.ref_range_max(lo, hi));".to_string()
            }
            Op::Point => {
                "let idx = ((nx(&mut state) % 32) as usize);\n            assert_eq!(cand.point(idx), refr.ref_point(idx));".to_string()
            }
            Op::Total => "assert_eq!(cand.total(), refr.ref_total());".to_string(),
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
    s.push_str(TREE_NEW_SRC);
    s.push_str("impl SegmentTree {\n");
    for &op in &ops {
        let body = match op {
            Op::Point => "None",
            _ => "0",
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s.push_str("}\n");
    s
}

/// The plausible cheat: the leaf stores the write but the climb is skipped -
/// the slot itself stays honest, yet every ancestor freezes stale, so any
/// range away from the last-written index answers the ghost of old peaks.
pub fn stale_ancestors_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(TREE_NEW_SRC);
    s.push_str("impl SegmentTree {\n");
    for &op in &ops {
        match op {
            Op::Update => {
                let body = &[
                    "assert!(index < self.cap);",
                    "self.tree[index + self.cap] = value;",
                    "value",
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

pub struct SegmentTreeFamily;

impl Generator for SegmentTreeFamily {
    fn id(&self) -> &'static str {
        "segment-tree"
    }

    fn category(&self) -> &'static str {
        "range-dominance"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("segment-tree", seed);
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
            id: format!("segment-tree/{seed:016x}"),
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
        s.push_str(TREE_NEW_SRC);
        s.push_str("impl SegmentTree {\n");
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
            ("stale-ancestors".to_string(), stale_ancestors_src(spec)),
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
        let a = SegmentTreeFamily.generate(55);
        let b = SegmentTreeFamily.generate(55);
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
            let t = driven_tree(40, warmup);
            assert_eq!(t.seg_len(), SEG_CAP as u64);
            assert!(t.total() < 40);
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let t = driven_tree(ex.span, ex.warmup);
                assert_eq!(t.seg_len(), SEG_CAP as u64);
                assert!(t.total() < ex.span);
                assert!(ex.warmup >= 2);
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct SegmentTreeRef"));
            assert!(
                src.matches("SegmentTreeRef {").count() >= 2,
                "constructor body must be renamed too"
            );
            assert!(!src.contains("pub fn update"));
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
            let canary = mint_canary("segment-tree", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in ["pos /= 2", ".max(self.tree", "l & 1"] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("maximum"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("SegmentTreeRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soaks() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            let rmax_gate = spec.ops.contains(&Op::Update) && spec.ops.contains(&Op::RangeMax);
            let point_gate = spec.ops.contains(&Op::Update) && spec.ops.contains(&Op::Point);
            let seglen_gate = spec.ops.contains(&Op::Update) && spec.ops.contains(&Op::SegLen);
            let total_gate = spec.ops.contains(&Op::Update) && spec.ops.contains(&Op::Total);
            assert_eq!(
                behavior.contains("scripted_overwrites_retire_old_peaks"),
                rmax_gate,
                "seed {seed}: dominance script misaligned"
            );
            assert_eq!(
                behavior.contains("scripted_point_reads_back_the_raw_slot"),
                point_gate,
                "seed {seed}: point script misaligned"
            );
            assert_eq!(
                behavior.contains("scripted_width_stays_fixed"),
                seglen_gate,
                "seed {seed}: width script misaligned"
            );
            assert_eq!(
                behavior.contains("scripted_total_answers_the_global_peak"),
                total_gate,
                "seed {seed}: total script misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_tree_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let cheat = stale_ancestors_src(spec);
        assert!(!cz.contains("todo!()"));
        assert!(cheat.contains("fn update"));
        let us = cheat.find("fn update").unwrap();
        let ue = us + cheat[us..].find("\n}\n").unwrap();
        let ub = &cheat[us..ue];
        assert!(
            ub.contains("self.tree[index + self.cap] = value;"),
            "cheat must keep the leaf write honest"
        );
        assert!(!ub.contains(".max("), "the skipped climb is the bug");
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("segment-tree", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
