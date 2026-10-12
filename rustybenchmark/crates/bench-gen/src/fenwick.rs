//! Prefix-sum-fenwick natives: a Fenwick tree (binary indexed tree) over a
//! fixed capacity. Every add walks the update path, every prefix walks the
//! query path, and an add answers the freshly updated prefix sum through
//! its own index.

#[derive(Clone)]
pub struct FenwickInstance {
    /// 1-indexed tree; `tree[0]` is unused padding.
    tree: Vec<u64>,
}

impl FenwickInstance {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity >= 1);
        Self {
            tree: vec![0; capacity + 1],
        }
    }

    pub fn fen_len(&self) -> u64 {
        (self.tree.len() - 1) as u64
    }

    fn total_slots(&self) -> usize {
        self.tree.len() - 1
    }

    /// Add `value` at 0-based `index`, then answer the freshly updated
    /// prefix sum through that same index.
    pub fn add(&mut self, index: usize, value: u64) -> u64 {
        assert!(index < self.total_slots());
        let mut i = index + 1;
        while i <= self.total_slots() {
            self.tree[i] += value;
            i += i & i.wrapping_neg();
        }
        self.prefix(index)
    }

    /// Sum of positions 0 through `index` inclusive (0-based).
    pub fn prefix(&self, index: usize) -> u64 {
        if index >= self.total_slots() {
            return self.total();
        }
        let mut i = index + 1;
        let mut sum = 0;
        while i > 0 {
            sum += self.tree[i];
            i -= i & i.wrapping_neg();
        }
        sum
    }

    /// The whole-array sum.
    pub fn total(&self) -> u64 {
        let mut i = self.total_slots();
        let mut sum = 0;
        while i > 0 {
            sum += self.tree[i];
            i -= i & i.wrapping_neg();
        }
        sum
    }

    /// The single value stored at 0-based `index`, or None out of range:
    /// the difference of two prefixes.
    pub fn point(&self, index: usize) -> Option<u64> {
        if index >= self.total_slots() {
            return None;
        }
        if index == 0 {
            return Some(self.prefix(0));
        }
        Some(self.prefix(index) - self.prefix(index - 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_then_prefix_roundtrips() {
        let mut f = FenwickInstance::new(8);
        assert_eq!(f.add(2, 5), 5);
        assert_eq!(f.add(4, 7), 12);
        assert_eq!(f.add(6, 3), 15);
        assert_eq!(f.prefix(0), 0);
        assert_eq!(f.prefix(1), 0);
        assert_eq!(f.prefix(2), 5);
        assert_eq!(f.prefix(5), 12);
        assert_eq!(f.prefix(7), 15);
    }

    #[test]
    fn point_difference_reads_back_each_add() {
        let mut f = FenwickInstance::new(6);
        f.add(0, 9);
        f.add(3, 4);
        f.add(3, 2);
        assert_eq!(f.point(0), Some(9));
        assert_eq!(f.point(2), Some(0));
        assert_eq!(f.point(3), Some(6));
        assert_eq!(f.point(5), Some(0));
        assert_eq!(f.point(6), None);
        assert_eq!(f.point(999), None);
    }

    #[test]
    fn prefix_clamps_past_the_end_and_matches_total() {
        let mut f = FenwickInstance::new(4);
        f.add(1, 6);
        f.add(2, 8);
        assert_eq!(f.prefix(3), 14);
        assert_eq!(f.prefix(40), 14);
        assert_eq!(f.prefix(usize::MAX), 14);
        assert_eq!(f.total(), 14);
    }

    #[test]
    fn fresh_tree_answers_zero_everywhere() {
        let f = FenwickInstance::new(10);
        assert_eq!(f.fen_len(), 10);
        assert_eq!(f.total(), 0);
        for idx in [0usize, 3, 7, 9] {
            assert_eq!(f.prefix(idx), 0);
            assert_eq!(f.point(idx), Some(0));
        }
    }

    #[test]
    fn repeated_adds_accumulate_at_one_position() {
        let mut f = FenwickInstance::new(5);
        assert_eq!(f.add(3, 7), 7);
        assert_eq!(f.add(3, 7), 14);
        assert_eq!(f.add(3, 1), 15);
        assert_eq!(f.point(3), Some(15));
        assert_eq!(f.total(), 15);
        assert_eq!(f.prefix(2), 0);
    }

    #[test]
    fn soak_matches_a_shadow_vec_under_random_traffic() {
        let cap = 24usize;
        let mut f = FenwickInstance::new(cap);
        let mut shadow = vec![0u64; cap];
        let mut st: u64 = 0x5EED_B17E;
        for _ in 0..600 {
            let idx = ((st >> 33) % 24) as usize;
            let v = (st >> 7) % 30;
            let want: u64 = shadow[..=idx].iter().sum();
            assert_eq!(f.add(idx, v), want + v);
            shadow[idx] += v;
            let probe = ((st >> 41) % 24) as usize;
            assert_eq!(f.prefix(probe), shadow[..=probe].iter().sum::<u64>());
            assert_eq!(f.total(), shadow.iter().sum::<u64>());
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
    FenLen,
    Add,
    Prefix,
    Total,
    Point,
}

pub const OP_ALL: [Op; 5] = [Op::FenLen, Op::Add, Op::Prefix, Op::Total, Op::Point];

/// The fixed capacity every scenario shares.
pub const FEN_CAP: usize = 24;

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::FenLen => "fen_len",
            Op::Add => "add",
            Op::Prefix => "prefix",
            Op::Total => "total",
            Op::Point => "point",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::FenLen => "answers how many addressable slots the array holds",
            Op::Add => "records `value` at an index by climbing the update path, bumping every cell it visits, and answers the freshly updated prefix sum through that same index",
            Op::Prefix => "answers the sum of positions zero through the index inclusive; past the last slot it answers the whole-array sum",
            Op::Total => "answers the whole-array sum",
            Op::Point => "answers the single value stored at an index - the difference of two adjacent prefixes - or None when out of range",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::FenLen => "pub fn fen_len(&self) -> u64",
            Op::Add => "pub fn add(&mut self, index: usize, value: u64) -> u64",
            Op::Prefix => "pub fn prefix(&self, index: usize) -> u64",
            Op::Total => "pub fn total(&self) -> u64",
            Op::Point => "pub fn point(&self, index: usize) -> Option<u64>",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub const CANONICAL_SEED: u64 = 0xB17E_FA11;

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

/// Add is the fill primitive and the prefix query is the audit probe;
/// both ship as given infrastructure alongside the sampled pair, so a
/// solution that bumps only the leaf cell instead of walking the full
/// update path drifts on the very next arrival no matter which pair was
/// drawn.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    let mut v = vec![Op::Add];
    if !spec.ops.contains(&Op::Prefix) {
        v.push(Op::Prefix);
    }
    for o in spec.ops {
        if !v.contains(&o) {
            v.push(o);
        }
    }
    v
}

/// The canonical scenario: dozens of updates over a wide span so shared
/// paths and repeated positions both show up.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical prefix-sum-fenwick scenario");
}

fn fresh_tree() -> FenwickInstance {
    FenwickInstance::new(FEN_CAP)
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub span: u64,
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01D8;

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![
        ExampleCase {
            span: 30,
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
        let span = 3 + rng.below(28);
        out.push(ExampleCase {
            span,
            warmup: rng.below(span * 4) + 2,
        });
    }
    out
}

const NX_MUL: u64 = 6364136223846793005;
const NX_ADD: u64 = 1442695040888963407;

fn drive_init(span: u64, warmup: u64) -> u64 {
    0xB17E_CAFEu64 ^ span.wrapping_mul(0x9E37).wrapping_add(warmup)
}

/// Drives `warmup` random updates into a fresh tree: one state advance per
/// iteration, the index taken from the high bits and the value below `span`.
fn driven_fenwick(span: u64, warmup: u64) -> FenwickInstance {
    let mut f = fresh_tree();
    let mut st = drive_init(span, warmup);
    for _ in 0..warmup {
        let idx = ((st >> 33) % FEN_CAP as u64) as usize;
        f.add(idx, (st >> 7) % span);
        st = st.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    }
    f
}

/// The probe-continuation state after the drive loop (one advance per update).
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

pub const STRUCT_SRC: &str = "#[derive(Clone)]\npub struct Fenwick {\n    tree: Vec<u64>,\n}\n";

pub const FEN_NEW_SRC: &str = "impl Fenwick {\n    pub fn new(capacity: usize) -> Self {\n        assert!(capacity >= 1);\n        Fenwick {\n            tree: vec![0; capacity + 1],\n        }\n    }\n}\n\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

const ADD_BODY: &[&str] = &[
    "assert!(index < self.tree.len() - 1);",
    "let mut i = index + 1;",
    "while i <= self.tree.len() - 1 {",
    "    self.tree[i] += value;",
    "    i += i & i.wrapping_neg();",
    "}",
    "self.prefix(index)",
];

const PREFIX_BODY: &[&str] = &[
    "if index >= self.tree.len() - 1 {",
    "    let mut i = self.tree.len() - 1;",
    "    let mut sum = 0;",
    "    while i > 0 {",
    "        sum += self.tree[i];",
    "        i -= i & i.wrapping_neg();",
    "    }",
    "    return sum;",
    "}",
    "let mut i = index + 1;",
    "let mut sum = 0;",
    "while i > 0 {",
    "    sum += self.tree[i];",
    "    i -= i & i.wrapping_neg();",
    "}",
    "sum",
];

const TOTAL_BODY: &[&str] = &[
    "let mut i = self.tree.len() - 1;",
    "let mut sum = 0;",
    "while i > 0 {",
    "    sum += self.tree[i];",
    "    i -= i & i.wrapping_neg();",
    "}",
    "sum",
];

const POINT_BODY: &[&str] = &[
    "if index >= self.tree.len() - 1 {",
    "    return None;",
    "}",
    "if index == 0 {",
    "    return Some(self.prefix(0));",
    "}",
    "Some(self.prefix(index) - self.prefix(index - 1))",
];

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::FenLen => &["(self.tree.len() - 1) as u64"],
        Op::Add => ADD_BODY,
        Op::Prefix => PREFIX_BODY,
        Op::Total => TOTAL_BODY,
        Op::Point => POINT_BODY,
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen("pub struct Fenwick {", "pub struct FenwickRef {", 1);
    s.push_str(
        &FEN_NEW_SRC
            .replace("impl Fenwick {", "impl FenwickRef {")
            .replace("Fenwick {\n", "FenwickRef {\n"),
    );
    s.push_str("impl FenwickRef {\n");
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
    for &op in &ops {
        s = s.replace(
            &format!("self.{}(", op.name()),
            &format!("self.ref_{}(", op.name()),
        );
    }
    s
}

pub fn worked_examples_prose(examples: &[ExampleCase]) -> String {
    let mut s = String::new();
    for (i, ex) in examples.iter().enumerate() {
        let f = driven_fenwick(ex.span, ex.warmup);
        s.push_str(&format!(
            "//! ex{i}: {w} updates below {span} -> slots {sl}, whole-sum {t}, last prefix {lp}\n",
            i = i,
            w = ex.warmup,
            span = ex.span,
            sl = f.fen_len(),
            t = f.total(),
            lp = f.prefix(FEN_CAP - 1),
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested partial-sum operations over one internal\n\
         //! array backed by a binary indexed layout: every update climbs the\n\
         //! update path bumping each visited cell, every query descends the\n\
         //! same ladder to accumulate a prefix, and the two ladders together\n\
         //! keep every prefix exact. The hidden tests drive thousands of\n\
         //! interleaved operations and compare every returned value.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(FEN_NEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested partial-sum operations with exactly maintained bookkeeping.\n\nRequirements:\n- `Fenwick::new(capacity)` allocates a one-indexed internal array of length capacity plus one unused padding slot; the constructor is given.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- The update path starts at `index + 1` and climbs upward while the position stays inside the array, each step advancing by the position's own lowest set bit; every visited cell grows by the added value.\n- The query path starts at `index + 1` and descends the same ladder downward, accumulating each visited cell until the position reaches zero; asking past the last slot answers the whole-array sum.\n- Every add answers the freshly updated prefix through its own index; queries never mutate the tree.\n- A point read is the difference of two adjacent prefixes; out of range it answers None, and index zero needs its own branch rather than wrapping arithmetic.\n- No floating point; no unsafe code; standard library only.\n\nSignatures:\n```rust\n");
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
    let mut s = String::from("use task::Fenwick;\n\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n");
    for (i, ex) in examples.iter().enumerate() {
        let h = driven_fenwick(ex.span, ex.warmup);
        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let mut drive = Fenwick::new({cap});\n    let mut st: u64 = {init};\n    for _ in 0..{w} {{\n        drive.add(((st >> 33) % {cap}) as usize, (st >> 7) % {span}u64);\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    }}\n",
            i = i,
            w = ex.warmup,
            span = ex.span,
            init = drive_init(ex.span, ex.warmup),
            cap = FEN_CAP,
        ));
        s.push_str(&format!(
            "    let mut ps: u64 = {};\n",
            drive_final_state(ex.span, ex.warmup)
        ));
        let mut ps = drive_final_state(ex.span, ex.warmup);
        for &op in &spec.ops {
            match op {
                Op::FenLen => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.fen_len(), {});\n",
                        h.fen_len()
                    ));
                }
                Op::Total => {
                    s.push_str(&format!("    assert_eq!(drive.total(), {});\n", h.total()));
                }
                Op::Point => {
                    let idx = (nx(&mut ps) % 28) as usize;
                    let want = h.clone().point(idx);
                    s.push_str(&format!(
                        "    let r = drive.clone();\n    let idx = (nx(&mut ps) % 28u64) as usize;\n    assert_eq!(r.point(idx), {want});\n    assert_eq!(r.point({cap}), None);\n",
                        want = opt_fmt(want),
                        cap = FEN_CAP,
                    ));
                }
                Op::Prefix => {
                    let idx = (nx(&mut ps) % FEN_CAP as u64) as usize;
                    let want = h.clone().prefix(idx);
                    s.push_str(&format!(
                        "    let r = drive.clone();\n    let idx = (nx(&mut ps) % {cap}u64) as usize;\n    assert_eq!(r.prefix(idx), {want});\n",
                        cap = FEN_CAP,
                        want = want
                    ));
                }
                Op::Add => {
                    let idx = (nx(&mut ps) % FEN_CAP as u64) as usize;
                    let v = nx(&mut ps) % ex.span;
                    let want = h.clone().add(idx, v);
                    s.push_str(&format!(
                        "    let mut r = drive.clone();\n    let idx = (nx(&mut ps) % {cap}u64) as usize;\n    let v = nx(&mut ps) % {span}u64;\n    assert_eq!(r.add(idx, v), {want});\n",
                        cap = FEN_CAP,
                        span = ex.span,
                        want = want
                    ));
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Scripted probe: the tally sums every position exactly.
    if spec.ops.contains(&Op::Add) && spec.ops.contains(&Op::Total) {
        s.push_str("#[test]\nfn scripted_tally_sums_every_position() {\n    let mut r = Fenwick::new(6);\n    assert_eq!(r.add(1, 5), 5);\n    assert_eq!(r.add(4, 7), 12);\n    assert_eq!(r.total(), 12);\n    assert_eq!(r.add(2, 3), 8);\n    assert_eq!(r.total(), 15);\n}\n");
    }
    // Scripted probe: point reads are the difference of adjacent prefixes.
    if spec.ops.contains(&Op::Add) && spec.ops.contains(&Op::Point) {
        s.push_str("#[test]\nfn scripted_point_difference_reads_each_add() {\n    let mut r = Fenwick::new(6);\n    assert_eq!(r.add(0, 9), 9);\n    assert_eq!(r.point(0), Some(9));\n    assert_eq!(r.add(3, 4), 13);\n    assert_eq!(r.point(3), Some(4));\n    assert_eq!(r.point(2), Some(0));\n    assert_eq!(r.point(5), Some(0));\n    assert_eq!(r.point(6), None);\n}\n");
    }
    // Fill soak: eight hundred random updates must keep every probed prefix
    // pinned to a shadow vector.
    if spec.ops.contains(&Op::Add) && spec.ops.contains(&Op::Prefix) {
        s.push_str("#[test]\nfn fill_soak_pins_prefixes_to_a_shadow_vector() {\n    let mut r = Fenwick::new(16);\n    let mut shadow = vec![0u64; 16];\n    let mut st: u64 = 0x5EED_0000_0000_01DA;\n    for _ in 0..800usize {\n        let idx = ((st >> 33) % 16) as usize;\n        let v = (st >> 7) % 40;\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        let want: u64 = shadow[..=idx].iter().sum();\n        assert_eq!(r.add(idx, v), want + v);\n        shadow[idx] += v;\n        let probe = ((st >> 41) % 16) as usize;\n        assert_eq!(r.prefix(probe), shadow[..=probe].iter().sum::<u64>());\n    }\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::Fenwick;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    let ops = effective_ops(spec);
    s.push_str("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {\n    let mut cand = Fenwick::new(18);\n    let mut refr = FenwickRef::new(18);\n");
    if ops.contains(&Op::FenLen) {
        s.push_str("    assert_eq!(cand.fen_len(), refr.ref_fen_len());\n");
    }
    if ops.contains(&Op::Total) {
        s.push_str("    assert_eq!(cand.total(), refr.ref_total());\n");
    }
    if ops.contains(&Op::Prefix) {
        s.push_str("    assert_eq!(cand.prefix(999), refr.ref_prefix(999));\n");
    }
    if ops.contains(&Op::Point) {
        s.push_str("    assert_eq!(cand.point(9999), refr.ref_point(9999));\n");
    }
    if ops.contains(&Op::Add) {
        for (i, v) in [(1usize, 4u64), (5, 9), (1, 3), (17, 2), (9, 6)] {
            s.push_str(&format!(
                "    assert_eq!(cand.add({i}, {v}), refr.ref_add({i}, {v}));\n"
            ));
        }
        if ops.contains(&Op::Prefix) {
            s.push_str("    assert_eq!(cand.prefix(9), refr.ref_prefix(9));\n");
        }
        if ops.contains(&Op::Total) {
            s.push_str("    assert_eq!(cand.total(), refr.ref_total());\n");
        }
        if ops.contains(&Op::Point) {
            s.push_str("    assert_eq!(cand.point(5), refr.ref_point(5));\n");
        }
    }
    let arm_count = ops.len();
    s.push_str(&format!("    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_01D8;\n    for _ in 0..3000 {{\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in ops.iter().enumerate() {
        let body = match op {
            Op::FenLen => "assert_eq!(cand.fen_len(), refr.ref_fen_len());".to_string(),
            Op::Add => {
                "let idx = (nx(&mut state) % 18u64) as usize;\n            let v = nx(&mut state) % 29;\n            assert_eq!(cand.add(idx, v), refr.ref_add(idx, v));"
                    .to_string()
            }
            Op::Prefix => {
                "let idx = (nx(&mut state) % 21u64) as usize;\n            assert_eq!(cand.prefix(idx), refr.ref_prefix(idx));"
                    .to_string()
            }
            Op::Total => "assert_eq!(cand.total(), refr.ref_total());".to_string(),
            Op::Point => {
                "let idx = (nx(&mut state) % 21u64) as usize;\n            assert_eq!(cand.point(idx), refr.ref_point(idx));"
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
    s.push_str(FEN_NEW_SRC);
    s.push_str("impl Fenwick {\n");
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

/// The plausible cheat: only the leaf cell is bumped instead of walking the
/// full update path, so single-cell trees look right while any prefix that
/// spans several cells drifts.
pub fn skip_parents_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(FEN_NEW_SRC);
    s.push_str("impl Fenwick {\n");
    for &op in &ops {
        match op {
            Op::Add => {
                s.push_str(&format!(
                    "{} {{\n    {}\n}}\n",
                    op_sig_src(op),
                    [
                        "assert!(index < self.tree.len() - 1);",
                        "self.tree[index + 1] += value;",
                        "self.prefix(index)",
                    ]
                    .join("\n    ")
                ));
            }
            _ => s.push_str(&op_fn_src(op)),
        }
    }
    s.push_str("}\n");
    s
}

pub struct FenwickFamily;

impl Generator for FenwickFamily {
    fn id(&self) -> &'static str {
        "prefix-sum-fenwick"
    }

    fn category(&self) -> &'static str {
        "partial-sums"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("prefix-sum-fenwick", seed);
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
            id: format!("prefix-sum-fenwick/{seed:016x}"),
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
        s.push_str(FEN_NEW_SRC);
        s.push_str("impl Fenwick {\n");
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
            ("skip-parents".to_string(), skip_parents_src(spec)),
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
        let a = FenwickFamily.generate(55);
        let b = FenwickFamily.generate(55);
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
            let f = driven_fenwick(30, warmup);
            assert_eq!(f.fen_len(), FEN_CAP as u64);
            assert_eq!(f.prefix(FEN_CAP - 1), f.total());
            assert!(f.total() <= warmup * 29);
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let f = driven_fenwick(ex.span, ex.warmup);
                assert_eq!(f.fen_len(), FEN_CAP as u64);
                assert!(ex.warmup >= 2);
                assert!(ex.span >= 3 && ex.span < 31);
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct FenwickRef"));
            assert!(
                src.matches("FenwickRef {").count() >= 2,
                "constructor body must be renamed too"
            );
            assert!(!src.contains("pub fn add"));
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
            let canary = mint_canary("prefix-sum-fenwick", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in ["i & i.wrapping_neg", "i += i", "tree[i] +="] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("prefix"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("FenwickRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soaks() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            let tally_gate = spec.ops.contains(&Op::Add) && spec.ops.contains(&Op::Total);
            let point_gate = spec.ops.contains(&Op::Add) && spec.ops.contains(&Op::Point);
            let soak_gate = spec.ops.contains(&Op::Add) && spec.ops.contains(&Op::Prefix);
            assert_eq!(
                behavior.contains("scripted_tally_sums_every_position"),
                tally_gate,
                "seed {seed}: tally script misaligned"
            );
            assert_eq!(
                behavior.contains("scripted_point_difference_reads_each_add"),
                point_gate,
                "seed {seed}: point script misaligned"
            );
            assert_eq!(
                behavior.contains("fill_soak_pins_prefixes_to_a_shadow_vector"),
                soak_gate,
                "seed {seed}: shadow soak misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_tree_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let cheat = skip_parents_src(spec);
        assert!(!cz.contains("todo!()"));
        assert!(cheat.contains("fn add"));
        let us = cheat.find("fn add").unwrap();
        let ue = us + cheat[us..].find("\n}\n").unwrap();
        let ub = &cheat[us..ue];
        assert!(
            ub.contains("index + 1"),
            "cheat must still touch the leaf cell"
        );
        assert!(
            !ub.contains("wrapping_neg"),
            "the dropped parent climb is the bug"
        );
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("prefix-sum-fenwick", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
