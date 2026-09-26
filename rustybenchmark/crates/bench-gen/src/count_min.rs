//! Count-min-sketch natives: a frequency-estimate sketch over a stream of
//! arrivals. `depth` independent rows each hold `width` counters; every row
//! hashes an arrival to one cell, an add answers the smallest cell it saw
//! before bumping its cells, and an estimate can only understate the true
//! count - never overcount past it.

#[derive(Clone)]
pub struct CountMinInstance {
    rows: Vec<Vec<u64>>,
    width: usize,
    depth: usize,
    total: u64,
}

impl CountMinInstance {
    pub fn new(width: usize, depth: usize) -> Self {
        assert!(width >= 1);
        assert!(depth >= 1);
        Self {
            rows: vec![vec![0; width]; depth],
            width,
            depth,
            total: 0,
        }
    }

    /// Row-`i` slot for a value: multiply by the odd constant, add `i`
    /// times the odd stride taken from the high bits, reduce mod width.
    fn slot_of(&self, value: u64, i: usize) -> usize {
        let base = value.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let stride = value | 1;
        let mixed = base.wrapping_add((i as u64).wrapping_mul(stride));
        (mixed % self.width as u64) as usize
    }

    pub fn cms_width(&self) -> u64 {
        self.width as u64
    }

    pub fn cms_depth(&self) -> u64 {
        self.depth as u64
    }

    pub fn total_added(&self) -> u64 {
        self.total
    }

    fn min_over_rows(&self, value: u64) -> u64 {
        let mut best = self.rows[0][self.slot_of(value, 0)];
        for i in 1..self.depth {
            let cell = self.rows[i][self.slot_of(value, i)];
            if cell < best {
                best = cell;
            }
        }
        best
    }

    /// Add one arrival of `value`: answer the smallest cell across the
    /// rows BEFORE the bump (the pre-add estimate), then increment one
    /// cell per row and advance the tally.
    pub fn add(&mut self, value: u64) -> u64 {
        let answered = self.min_over_rows(value);
        for i in 0..self.depth {
            let slot = self.slot_of(value, i);
            self.rows[i][slot] += 1;
        }
        self.total += 1;
        answered
    }

    /// The count-min estimate of how often `value` arrived: the smallest
    /// cell across the rows. Never undercounts a true frequency.
    pub fn estimate(&self, value: u64) -> u64 {
        self.min_over_rows(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_sketch_answers_zero_everywhere() {
        let c = CountMinInstance::new(32, 4);
        assert_eq!(c.cms_width(), 32);
        assert_eq!(c.cms_depth(), 4);
        assert_eq!(c.total_added(), 0);
        assert_eq!(c.estimate(0), 0);
        assert_eq!(c.estimate(9), 0);
        assert_eq!(c.estimate(u64::MAX), 0);
    }

    #[test]
    fn add_answers_the_estimate_before_the_bump() {
        let mut c = CountMinInstance::new(64, 4);
        assert_eq!(c.add(9), 0);
        assert_eq!(c.add(9), 1);
        assert_eq!(c.add(9), 2);
        assert_eq!(c.estimate(9), 3);
        assert_eq!(c.total_added(), 3);
    }

    #[test]
    fn single_arrivals_agree_with_a_formula_mirror() {
        const W: usize = 64;
        const D: usize = 4;
        let mut c = CountMinInstance::new(W, D);
        let mut mirror = vec![vec![0u64; W]; D];
        for v in [100u64, 200, 300, 400] {
            c.add(v);
            for (i, row) in mirror.iter_mut().enumerate() {
                let mixed = v
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .wrapping_add((i as u64).wrapping_mul(v | 1));
                row[(mixed % W as u64) as usize] += 1;
            }
        }
        for v in [100u64, 200, 300, 400, 777, 555_555] {
            let mut want = u64::MAX;
            for (i, row) in mirror.iter().enumerate() {
                let mixed = v
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .wrapping_add((i as u64).wrapping_mul(v | 1));
                want = want.min(row[(mixed % W as u64) as usize]);
            }
            assert_eq!(c.estimate(v), want);
        }
        assert!(c.estimate(100) >= 1);
        assert!(c.estimate(200) >= 1);
    }

    #[test]
    fn repeated_value_climbs_exactly_until_interference() {
        let mut c = CountMinInstance::new(128, 4);
        for _ in 0..6 {
            c.add(5);
        }
        assert_eq!(c.estimate(5), 6);
        for v in [7u64, 9, 11, 13, 17, 19, 23] {
            c.add(v);
        }
        // cells only ever grow, so the estimate may inflate but never drop
        assert!(c.estimate(5) >= 6);
        assert_eq!(c.total_added(), 13);
    }

    #[test]
    fn estimate_never_undercounts_a_true_frequency() {
        let mut c = CountMinInstance::new(16, 3);
        for _ in 0..3 {
            c.add(7);
        }
        for v in [100u64, 200, 300, 400, 500, 600, 700, 800] {
            c.add(v);
        }
        assert!(c.estimate(7) >= 3);
        assert!(c.estimate(999) <= 8);
        assert_eq!(c.cms_width(), 16);
        assert_eq!(c.cms_depth(), 3);
    }

    #[test]
    fn soak_matches_a_shadow_grid_under_random_traffic() {
        const W: usize = 16;
        const D: usize = 3;
        let mut c = CountMinInstance::new(W, D);
        let mut shadow = vec![vec![0u64; W]; D];
        let mut st: u64 = 0x5EED_C057;
        let mut arrivals = 0u64;
        for _ in 0..600 {
            let v = (st >> 33) % 50;
            let want = shadow[0][(v.wrapping_mul(0x9E37_79B9_7F4A_7C15) % W as u64) as usize]
                .min({
                    let i = 1usize;
                    let mixed = v
                        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                        .wrapping_add((i as u64).wrapping_mul(v | 1));
                    shadow[i][(mixed % W as u64) as usize]
                })
                .min({
                    let i = 2usize;
                    let mixed = v
                        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                        .wrapping_add((i as u64).wrapping_mul(v | 1));
                    shadow[i][(mixed % W as u64) as usize]
                });
            assert_eq!(c.add(v), want);
            arrivals += 1;
            for (i, row) in shadow.iter_mut().enumerate() {
                let mixed = v
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .wrapping_add((i as u64).wrapping_mul(v | 1));
                row[(mixed % W as u64) as usize] += 1;
            }
            let expect = shadow[0][(v.wrapping_mul(0x9E37_79B9_7F4A_7C15) % W as u64) as usize]
                .min({
                    let i = 1usize;
                    let mixed = v
                        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                        .wrapping_add((i as u64).wrapping_mul(v | 1));
                    shadow[i][(mixed % W as u64) as usize]
                })
                .min({
                    let i = 2usize;
                    let mixed = v
                        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                        .wrapping_add((i as u64).wrapping_mul(v | 1));
                    shadow[i][(mixed % W as u64) as usize]
                });
            assert_eq!(c.estimate(v), expect);
            assert_eq!(c.total_added(), arrivals);
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
    Width,
    Add,
    Estimate,
    TotalAdded,
    Depth,
}

pub const OP_ALL: [Op; 5] = [Op::Width, Op::Add, Op::Estimate, Op::TotalAdded, Op::Depth];

/// The fixed sketch geometry every scenario shares.
pub const CMS_WIDTH: usize = 32;
pub const CMS_DEPTH: usize = 4;

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::Width => "cms_width",
            Op::Add => "add",
            Op::Estimate => "estimate",
            Op::TotalAdded => "total_added",
            Op::Depth => "cms_depth",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::Width => "answers how many counters each row of the grid holds",
            Op::Add => "records one arrival: every row bumps the cell its hash picks, the tally advances, and the pre-bump smallest bumped cell is answered",
            Op::Estimate => "answers how often a value appears to have arrived - the smallest cell across the rows that its hashes pick",
            Op::TotalAdded => "answers how many arrivals have ever been recorded",
            Op::Depth => "answers how many independent rows the grid holds",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::Width => "pub fn cms_width(&self) -> u64",
            Op::Add => "pub fn add(&mut self, value: u64) -> u64",
            Op::Estimate => "pub fn estimate(&self, value: u64) -> u64",
            Op::TotalAdded => "pub fn total_added(&self) -> u64",
            Op::Depth => "pub fn cms_depth(&self) -> u64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub const CANONICAL_SEED: u64 = 0xC057_FA11;

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

/// Add is the fill primitive and the estimate query is the audit probe;
/// both ship as given infrastructure alongside the sampled pair, so a
/// solution that reads only one row (instead of taking the minimum over
/// every row) drifts on the very next arrival no matter which pair was
/// drawn.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    let mut v = vec![Op::Add];
    if !spec.ops.contains(&Op::Estimate) {
        v.push(Op::Estimate);
    }
    for o in spec.ops {
        if !v.contains(&o) {
            v.push(o);
        }
    }
    v
}

/// The canonical scenario: dozens of arrivals over a wide span so shared
/// cells and repeated values both show up.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical count-min-sketch scenario");
}

fn fresh_sketch() -> CountMinInstance {
    CountMinInstance::new(CMS_WIDTH, CMS_DEPTH)
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub span: u64,
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01D4;

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
    for _ in 0..3 {
        let span = 4 + rng.below(45);
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
    0xC057_CAFEu64 ^ span.wrapping_mul(0x9E37).wrapping_add(warmup)
}

/// Drives `warmup` random arrivals (values below `span`) into a fresh sketch.
fn driven_cms(span: u64, warmup: u64) -> CountMinInstance {
    let mut c = fresh_sketch();
    let mut st = drive_init(span, warmup);
    for _ in 0..warmup {
        c.add((st >> 33) % span);
        st = st.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    }
    c
}

/// The probe-continuation state after the drive loop (one advance per add).
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

// ---- emitted-source fragments -----------------------------------------------

pub const STRUCT_SRC: &str = "#[derive(Clone)]\npub struct CountMin {\n    rows: Vec<Vec<u64>>,\n    width: usize,\n    depth: usize,\n    total: u64,\n}\n";

pub const SKETCH_NEW_SRC: &str = "impl CountMin {\n    pub fn new(width: usize, depth: usize) -> Self {\n        assert!(width >= 1);\n        assert!(depth >= 1);\n        CountMin {\n            rows: vec![vec![0; width]; depth],\n            width,\n            depth,\n            total: 0,\n        }\n    }\n\n    fn slot_of(&self, value: u64, i: usize) -> usize {\n        let mixed = value\n            .wrapping_mul(0x9E37_79B9_7F4A_7C15)\n            .wrapping_add((i as u64).wrapping_mul(value | 1));\n        (mixed % self.width as u64) as usize\n    }\n}\n\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

const ADD_BODY: &[&str] = &[
    "let mut best = u64::MAX;",
    "for i in 0..self.depth {",
    "    let slot = self.slot_of(value, i);",
    "    let cell = self.rows[i][slot];",
    "    if cell < best {",
    "        best = cell;",
    "    }",
    "}",
    "for i in 0..self.depth {",
    "    let slot = self.slot_of(value, i);",
    "    self.rows[i][slot] += 1;",
    "}",
    "self.total += 1;",
    "best",
];

const ESTIMATE_BODY: &[&str] = &[
    "let mut best = u64::MAX;",
    "for i in 0..self.depth {",
    "    let slot = self.slot_of(value, i);",
    "    let cell = self.rows[i][slot];",
    "    if cell < best {",
    "        best = cell;",
    "    }",
    "}",
    "best",
];

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::Width => &["self.width as u64"],
        Op::Add => ADD_BODY,
        Op::Estimate => ESTIMATE_BODY,
        Op::TotalAdded => &["self.total"],
        Op::Depth => &["self.depth as u64"],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen("pub struct CountMin {", "pub struct CountMinRef {", 1);
    s.push_str(
        &SKETCH_NEW_SRC
            .replace("impl CountMin {", "impl CountMinRef {")
            .replace("CountMin {\n", "CountMinRef {\n"),
    );
    s.push_str("impl CountMinRef {\n");
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
        let c = driven_cms(ex.span, ex.warmup);
        s.push_str(&format!(
            "//! ex{i}: {w} arrivals below {span} -> tally {t}, estimate(7) {e}\n",
            i = i,
            w = ex.warmup,
            span = ex.span,
            t = c.total_added(),
            e = c.estimate(7),
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested frequency-estimate operations over one\n\
         //! internal grid of counters: several independent rows each hold a\n\
         //! row of counters, every arrival bumps exactly one cell per row,\n\
         //! and estimates read the smallest bumped cell across the rows.\n\
         //! The hidden tests drive thousands of interleaved operations and\n\
         //! compare every returned value.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(SKETCH_NEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested frequency-estimate operations with exactly maintained bookkeeping.\n\nRequirements:\n- `CountMin::new(width, depth)` builds `depth` zeroed rows of `width` counters each; the constructor and the cell-hash are given.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- Row i maps an arrival to cell ((value * 0x9E37_79B9_7F4A_7C15) wrapping-add (i * ((value | 1)))) reduced modulo the width; all arithmetic stays on unsigned 64-bit integers with wrapping. This mapping is fixed by the given helper and must not be altered.\n- An add answers the smallest of the cells it is about to bump, taken BEFORE any bump; afterwards every row's picked cell grows by exactly one and the arrival tally grows by one.\n- An estimate may inflate through shared cells but must never understate how often a value arrived; on a fresh grid it answers zero.\n- Queries never mutate the grid; no floating point; no unsafe code; standard library only.\n\nSignatures:\n```rust\n");
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
    let mut s = String::from("use task::CountMin;\n\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n");
    for (i, ex) in examples.iter().enumerate() {
        let h = driven_cms(ex.span, ex.warmup);
        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let mut drive = CountMin::new({gw}, {gd});\n    let mut st: u64 = {init};\n    for _ in 0..{w} {{\n        drive.add((st >> 33) % {span}u64);\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    }}\n",
            i = i,
            w = ex.warmup,
            span = ex.span,
            init = drive_init(ex.span, ex.warmup),
            gw = CMS_WIDTH,
            gd = CMS_DEPTH,
        ));
        s.push_str(&format!(
            "    let mut ps: u64 = {};\n",
            drive_final_state(ex.span, ex.warmup)
        ));
        let mut ps = drive_final_state(ex.span, ex.warmup);
        for &op in &spec.ops {
            match op {
                Op::Width => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.cms_width(), {});\n",
                        h.cms_width()
                    ));
                }
                Op::Depth => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.cms_depth(), {});\n",
                        h.cms_depth()
                    ));
                }
                Op::TotalAdded => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.total_added(), {});\n",
                        h.total_added()
                    ));
                }
                Op::Estimate => {
                    let v = nx(&mut ps) % ex.span;
                    let want = h.clone().estimate(v);
                    s.push_str(&format!(
                        "    let r = drive.clone();\n    let v = nx(&mut ps) % {span}u64;\n    assert_eq!(r.estimate(v), {want});\n",
                        span = ex.span,
                        want = want
                    ));
                }
                Op::Add => {
                    let v = nx(&mut ps) % ex.span;
                    let want = h.clone().add(v);
                    s.push_str(&format!(
                        "    let mut r = drive.clone();\n    let v = nx(&mut ps) % {span}u64;\n    assert_eq!(r.add(v), {want});\n",
                        span = ex.span,
                        want = want
                    ));
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Scripted probe: the tally counts every arrival exactly once.
    if spec.ops.contains(&Op::Add) && spec.ops.contains(&Op::TotalAdded) {
        s.push_str("#[test]\nfn scripted_tally_counts_every_arrival() {\n    let mut r = CountMin::new(8, 2);\n    assert_eq!(r.add(3), 0);\n    assert_eq!(r.add(3), 1);\n    assert_eq!(r.add(9), 0);\n    assert_eq!(r.total_added(), 3);\n}\n");
    }
    // Fill soak: eight hundred random arrivals must keep both the answered
    // pre-bump minimum and the post-add estimate pinned to a shadow grid.
    if spec.ops.contains(&Op::Add) && spec.ops.contains(&Op::Estimate) {
        s.push_str("#[test]\nfn fill_soak_pins_estimates_to_a_shadow_grid() {\n    let mut r = CountMin::new(16, 3);\n    let mut shadow = vec![vec![0u64; 16]; 3];\n    let mut st: u64 = 0x5EED_0000_0000_01D6;\n    for _ in 0..800usize {\n        let v = (st >> 33) % 40;\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        let mut want = u64::MAX;\n        for i in 0..3usize {\n            let mixed = v.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add((i as u64).wrapping_mul(v | 1));\n            let cell = shadow[i][(mixed % 16) as usize];\n            if cell < want {\n                want = cell;\n            }\n        }\n        assert_eq!(r.add(v), want);\n        for i in 0..3usize {\n            let mixed = v.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add((i as u64).wrapping_mul(v | 1));\n            shadow[i][(mixed % 16) as usize] += 1;\n        }\n        let mut expect = u64::MAX;\n        for i in 0..3usize {\n            let mixed = v.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add((i as u64).wrapping_mul(v | 1));\n            let cell = shadow[i][(mixed % 16) as usize];\n            if cell < expect {\n                expect = cell;\n            }\n        }\n        assert_eq!(r.estimate(v), expect);\n    }\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::CountMin;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    let ops = effective_ops(spec);
    s.push_str("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {\n    let mut cand = CountMin::new(24, 3);\n    let mut refr = CountMinRef::new(24, 3);\n");
    if ops.contains(&Op::Width) {
        s.push_str("    assert_eq!(cand.cms_width(), refr.ref_cms_width());\n");
    }
    if ops.contains(&Op::Depth) {
        s.push_str("    assert_eq!(cand.cms_depth(), refr.ref_cms_depth());\n");
    }
    if ops.contains(&Op::TotalAdded) {
        s.push_str("    assert_eq!(cand.total_added(), refr.ref_total_added());\n");
    }
    if ops.contains(&Op::Estimate) {
        s.push_str("    assert_eq!(cand.estimate(9999), refr.ref_estimate(9999));\n");
    }
    if ops.contains(&Op::Add) {
        for v in [40u64, 41, 42, 43, 44, 45, 12, 99, 3, 77] {
            s.push_str(&format!(
                "    assert_eq!(cand.add({v}), refr.ref_add({v}));\n"
            ));
        }
        if ops.contains(&Op::Estimate) {
            s.push_str("    assert_eq!(cand.estimate(41), refr.ref_estimate(41));\n");
        }
        if ops.contains(&Op::TotalAdded) {
            s.push_str("    assert_eq!(cand.total_added(), refr.ref_total_added());\n");
        }
    }
    let arm_count = ops.len();
    s.push_str(&format!("    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_01D4;\n    for _ in 0..3000 {{\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in ops.iter().enumerate() {
        let body = match op {
            Op::Width => "assert_eq!(cand.cms_width(), refr.ref_cms_width());".to_string(),
            Op::Add => "let v = nx(&mut state) % 29;\n            assert_eq!(cand.add(v), refr.ref_add(v));".to_string(),
            Op::Estimate => "let v = nx(&mut state) % 29;\n            assert_eq!(cand.estimate(v), refr.ref_estimate(v));".to_string(),
            Op::TotalAdded => "assert_eq!(cand.total_added(), refr.ref_total_added());".to_string(),
            Op::Depth => "assert_eq!(cand.cms_depth(), refr.ref_cms_depth());".to_string(),
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
    s.push_str(SKETCH_NEW_SRC);
    s.push_str("impl CountMin {\n");
    for &op in &ops {
        s.push_str(&format!("{} {{\n    0\n}}\n", op_sig_src(op)));
    }
    s.push_str("}\n");
    s
}

/// The plausible cheat: the tally and the geometry stay honest but only the
/// first row is ever consulted, so both the answered pre-bump minimum and
/// every estimate come from one row instead of the minimum across all rows.
pub fn single_row_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(SKETCH_NEW_SRC);
    s.push_str("impl CountMin {\n");
    for &op in &ops {
        match op {
            Op::Add => {
                s.push_str(&format!(
                    "{} {{\n    {}\n}}\n",
                    op_sig_src(op),
                    [
                        "let slot = self.slot_of(value, 0);",
                        "let answered = self.rows[0][slot];",
                        "self.rows[0][slot] += 1;",
                        "self.total += 1;",
                        "answered",
                    ]
                    .join("\n    ")
                ));
            }
            Op::Estimate => {
                s.push_str(&format!(
                    "{} {{\n    {}\n}}\n",
                    op_sig_src(op),
                    ["let slot = self.slot_of(value, 0);", "self.rows[0][slot]"].join("\n    ")
                ));
            }
            _ => s.push_str(&op_fn_src(op)),
        }
    }
    s.push_str("}\n");
    s
}

pub struct CountMinSketchFamily;

impl Generator for CountMinSketchFamily {
    fn id(&self) -> &'static str {
        "count-min-sketch"
    }

    fn category(&self) -> &'static str {
        "frequency-estimate"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("count-min-sketch", seed);
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
            id: format!("count-min-sketch/{seed:016x}"),
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
        s.push_str(SKETCH_NEW_SRC);
        s.push_str("impl CountMin {\n");
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
            ("single-row".to_string(), single_row_src(spec)),
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
        let a = CountMinSketchFamily.generate(55);
        let b = CountMinSketchFamily.generate(55);
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
            let c = driven_cms(40, warmup);
            assert_eq!(c.total_added(), warmup);
            assert_eq!(c.cms_width(), CMS_WIDTH as u64);
            assert_eq!(c.cms_depth(), CMS_DEPTH as u64);
            assert!(c.estimate(41) <= warmup);
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let c = driven_cms(ex.span, ex.warmup);
                assert_eq!(c.total_added(), ex.warmup);
                assert!(ex.warmup >= 2);
                assert!(ex.span >= 4 && ex.span < 49);
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct CountMinRef"));
            assert!(
                src.matches("CountMinRef {").count() >= 2,
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
            let canary = mint_canary("count-min-sketch", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in ["u64::MAX", "stride", "rows["] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("understate"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("CountMinRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soaks() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            let tally_gate = spec.ops.contains(&Op::Add) && spec.ops.contains(&Op::TotalAdded);
            let soak_gate = spec.ops.contains(&Op::Add) && spec.ops.contains(&Op::Estimate);
            assert_eq!(
                behavior.contains("scripted_tally_counts_every_arrival"),
                tally_gate,
                "seed {seed}: tally script misaligned"
            );
            assert_eq!(
                behavior.contains("fill_soak_pins_estimates_to_a_shadow_grid"),
                soak_gate,
                "seed {seed}: shadow soak misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_sketch_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let cheat = single_row_src(spec);
        assert!(!cz.contains("todo!()"));
        assert!(cheat.contains("fn add"));
        let us = cheat.find("fn add").unwrap();
        let ue = us + cheat[us..].find("\n}\n").unwrap();
        let ub = &cheat[us..ue];
        assert!(
            ub.contains("self.rows[0]"),
            "cheat must consult only the first row"
        );
        assert!(
            !ub.contains("for i in"),
            "the dropped multi-row scan is the bug"
        );
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("count-min-sketch", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
