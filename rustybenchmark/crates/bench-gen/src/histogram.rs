//! The `histogram-bucket` family (category `bucket-aggregate`) —
//! deterministic bucketing puzzles where *boundary math* is the data
//! structure.
//!
//! Every puzzle mirrors a real fixed-boundary histogram: `record`
//! answers which bucket swallowed a value (a value sitting exactly on a
//! boundary belongs to the upper side), `count_in`/`total_recorded`
//! expose the tallies any shortcut distorts, and `bucket_count`/
//! `boundary_at` publish the layout itself. The seed picks which two of
//! five ops are required: `bucket_count`, `record`, `count_in`,
//! `boundary_at`, `total_recorded`. Boundary values must go up — every
//! cheat sends them down and the tallies notice.

/// One fixed-boundary histogram. `bounds` is strictly ascending; there
/// is one more bucket than bounds, and the last bucket is unbounded
/// above.
#[derive(Clone)]
pub struct HistogramInstance {
    bounds: Vec<u64>,
    counts: Vec<u64>,
}

impl HistogramInstance {
    /// A fresh histogram with zeroed tallies.
    ///
    /// # Panics
    /// Panics when `bounds` is empty or not strictly ascending — the
    /// bucket layout would be ambiguous, so it is rejected up front.
    pub fn new(bounds: &[u64]) -> Self {
        assert!(!bounds.is_empty(), "histogram needs at least one bound");
        for pair in bounds.windows(2) {
            assert!(pair[0] < pair[1], "bounds must strictly ascend");
        }
        HistogramInstance {
            counts: vec![0; bounds.len() + 1],
            bounds: bounds.to_vec(),
        }
    }

    /// How many buckets the layout defines.
    pub fn bucket_count(&self) -> u64 {
        self.counts.len() as u64
    }

    /// The `index`-th boundary value, or None past the last bound.
    pub fn boundary_at(&self, index: usize) -> Option<u64> {
        self.bounds.get(index).copied()
    }

    /// Records `value` into its bucket and answers the bucket index:
    /// the count of bounds less than or equal to the value, so a value
    /// exactly on a bound lands in the upper side.
    pub fn record(&mut self, value: u64) -> u64 {
        let idx = self.bounds.partition_point(|&b| b <= value);
        self.counts[idx] += 1;
        idx as u64
    }

    /// The tally stored in `bucket`, or None past the last bucket.
    pub fn count_in(&self, bucket: usize) -> Option<u64> {
        self.counts.get(bucket).copied()
    }

    /// How many values have been recorded in total.
    pub fn total_recorded(&self) -> u64 {
        self.counts.iter().sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_land_by_the_upper_bound_rule() {
        let mut h = HistogramInstance::new(&[10, 20]);
        assert_eq!(h.record(5), 0);
        assert_eq!(h.record(10), 1);
        assert_eq!(h.record(19), 1);
        assert_eq!(h.record(20), 2);
        assert_eq!(h.record(1_000), 2);
        assert_eq!(h.bucket_count(), 3);
    }

    #[test]
    fn below_everything_lands_in_bucket_zero() {
        let mut h = HistogramInstance::new(&[7, 70, 700]);
        assert_eq!(h.record(0), 0);
        assert_eq!(h.record(6), 0);
        assert_eq!(h.record(7), 1);
        assert_eq!(h.count_in(0), Some(2));
        assert_eq!(h.count_in(1), Some(1));
    }

    #[test]
    fn boundaries_and_counts_answer_or_none() {
        let mut h = HistogramInstance::new(&[10, 20, 30]);
        assert_eq!(h.boundary_at(0), Some(10));
        assert_eq!(h.boundary_at(2), Some(30));
        assert_eq!(h.boundary_at(3), None);
        assert_eq!(h.count_in(5), None);
        h.record(30);
        assert_eq!(h.count_in(3), Some(1));
        assert_eq!(h.count_in(0), Some(0));
    }

    #[test]
    fn total_tracks_every_record() {
        let mut h = HistogramInstance::new(&[4, 8]);
        assert_eq!(h.total_recorded(), 0);
        for v in 0..9u64 {
            h.record(v * 3);
        }
        assert_eq!(h.total_recorded(), 9);
    }

    #[test]
    #[should_panic]
    fn rejects_descending_bounds() {
        let _ = HistogramInstance::new(&[10, 5]);
    }

    #[test]
    fn soak_matches_a_shadow_histogram_under_random_traffic() {
        let mut h = HistogramInstance::new(&[5, 25, 45]);
        let mut shadow = [0u64; 4];
        let mut st: u64 = 0x5EED_9A11;
        for _ in 0..600u64 {
            st = st
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let v = (st >> 33) % 90;
            let want = shadow.iter().sum::<u64>();
            h.record(v);
            let idx = [5u64, 25, 45].iter().filter(|&&b| b <= v).count();
            shadow[idx] += 1;
            for (b, &want_count) in shadow.iter().enumerate() {
                assert_eq!(h.count_in(b), Some(want_count));
            }
            assert_eq!(h.total_recorded(), want + 1);
        }
    }
}

use crate::{mint_canary, GeneratedTask, Generator, Rng};

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    BucketCount,
    Record,
    CountIn,
    BoundaryAt,
    TotalRecorded,
}

pub const OP_ALL: [Op; 5] = [
    Op::BucketCount,
    Op::Record,
    Op::CountIn,
    Op::BoundaryAt,
    Op::TotalRecorded,
];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::BucketCount => "bucket_count",
            Op::Record => "record",
            Op::CountIn => "count_in",
            Op::BoundaryAt => "boundary_at",
            Op::TotalRecorded => "total_recorded",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::BucketCount => "answers how many buckets the layout defines - one more than the number of bounds",
            Op::Record => "records value into its bucket and answers the bucket index - counting every bound less than or equal to the value, so a value exactly on a bound lands in the upper side",
            Op::CountIn => "answers the tally stored in bucket, or None past the last bucket",
            Op::BoundaryAt => "answers the index-th boundary value, or None past the last bound",
            Op::TotalRecorded => "answers how many values have been recorded in total",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::BucketCount => "pub fn bucket_count(&self) -> u64",
            Op::Record => "pub fn record(&mut self, value: u64) -> u64",
            Op::CountIn => "pub fn count_in(&self, bucket: usize) -> Option<u64>",
            Op::BoundaryAt => "pub fn boundary_at(&self, index: usize) -> Option<u64>",
            Op::TotalRecorded => "pub fn total_recorded(&self) -> u64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub const CANONICAL_SEED: u64 = 0x9A11_FA11;

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

/// Record is the fill primitive every scenario needs; when the seed did
/// not sample it, it ships as given infrastructure alongside the pair.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    if spec.ops.contains(&Op::Record) {
        spec.ops.to_vec()
    } else {
        let mut v = vec![Op::Record];
        v.extend_from_slice(&spec.ops);
        v
    }
}

/// The canonical scenario: a nine-bucket layout hammered by dozens of
/// pseudo-random records, so boundary values land early and any
/// solution that misfiles one or drifts the tallies is wrong before
/// the first probe.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical histogram scenario");
}

fn fresh_histogram(stride: u64) -> HistogramInstance {
    let bounds: Vec<u64> = (1..=8).map(|k| k * stride).collect();
    HistogramInstance::new(&bounds)
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub stride: u64,
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01BE;

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![
        ExampleCase {
            stride: 4,
            warmup: canonical(seed),
        },
        ExampleCase {
            stride: 2,
            warmup: 3,
        },
        ExampleCase {
            stride: 8,
            warmup: 4,
        },
        ExampleCase {
            stride: 1,
            warmup: 17,
        },
    ];
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    for _ in 0..8 {
        let stride = 1 << rng.below(4);
        out.push(ExampleCase {
            stride,
            warmup: rng.below(stride * 16) + 2,
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
/// record). Emitted tests re-derive this to probe one step past the end.
fn drive_base(stride: u64, warmup: u64) -> u64 {
    let mut s = 0x9A11_CAFE ^ stride.wrapping_mul(0x9E37).wrapping_add(warmup);
    for _ in 0..warmup {
        s = s.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    }
    s
}

/// Drives `warmup` pseudo-random records into a fresh nine-bucket
/// layout with bounds at every multiple of `stride`; values stay below
/// nine strides so multiples land exactly on boundaries regularly.
fn driven_histogram(stride: u64, warmup: u64) -> (HistogramInstance, Vec<u64>) {
    let mut h = fresh_histogram(stride);
    let mut st = 0x9A11_CAFE ^ stride.wrapping_mul(0x9E37).wrapping_add(warmup);
    let mut seen = Vec::new();
    for _ in 0..warmup {
        let v = nxt(&mut st) % (stride * 9);
        h.record(v);
        seen.push(v);
    }
    (h, seen)
}

// ---- emitted-source fragments -----------------------------------------------

pub const STRUCT_SRC: &str =
    "#[derive(Clone)]\npub struct Histogram {\n    bounds: Vec<u64>,\n    counts: Vec<u64>,\n}\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::BucketCount => &["self.counts.len() as u64"],
        Op::BoundaryAt => &["self.bounds.get(index).copied()"],
        Op::Record => &[
            "let idx = self.bounds.partition_point(|&bound| bound <= value);",
            "self.counts[idx] += 1;",
            "idx as u64",
        ],
        Op::CountIn => &["self.counts.get(bucket).copied()"],
        Op::TotalRecorded => &["self.counts.iter().sum()"],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub const HISTO_NEW_SRC: &str = "impl Histogram {\n    pub fn new(bounds: &[u64]) -> Self {\n        assert!(!bounds.is_empty());\n        let mut ascending = true;\n        for i in 1..bounds.len() {\n            ascending &= bounds[i - 1] < bounds[i];\n        }\n        assert!(ascending);\n        let mut counts = Vec::new();\n        counts.resize(bounds.len() + 1, 0);\n        Histogram {\n            bounds: bounds.iter().copied().collect(),\n            counts,\n        }\n    }\n}\n\n";

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen("pub struct Histogram {", "pub struct HistogramRef {", 1);
    s.push_str(
        &HISTO_NEW_SRC
            .replace("impl Histogram {", "impl HistogramRef {")
            .replace("Histogram {\n", "HistogramRef {\n"),
    );
    s.push_str("impl HistogramRef {\n");
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
        let (h, _) = driven_histogram(ex.stride, ex.warmup);
        let busiest = (0..h.bucket_count())
            .filter_map(|b| h.count_in(b as usize))
            .max()
            .unwrap_or(0);
        s.push_str(&format!(
            "//! ex{i}: stride {st}, then {n} pseudo-random records -> total {t}, buckets {b}, busiest holds {m}\n",
            i = i,
            st = ex.stride,
            n = ex.warmup,
            t = h.total_recorded(),
            b = h.bucket_count(),
            m = busiest
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested fixed-boundary histogram operations over\n\
         //! one layout of strictly ascending bounds. Recording files each\n\
         //! value into its bucket and must answer where it landed; queries\n\
         //! expose the tallies and layout any shortcut distorts. The hidden\n\
         //! tests drive thousands of interleaved operations and compare\n\
         //! every returned value.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(HISTO_NEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested histogram operations with an exactly maintained tally.\n\nRequirements:\n- `Histogram::new(bounds)` stores the strictly ascending bounds and starts every tally at zero; empty or non-ascending layouts are rejected.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- There is exactly one more bucket than bounds; the last bucket catches everything above the final bound.\n- A value sitting exactly on a boundary belongs to the upper side: the answered bucket index counts every bound less than or equal to the recorded value, and that bucket's tally grows by exactly one.\n- Out-of-range queries answer `None`; an in-range tally never lies about a single record.\n- The grand total must count every recorded value exactly once. No floating point; no unsafe code; standard library only.\n\nSignatures:\n```rust\n");
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
        "use task::Histogram;\n\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n",
    );
    for (i, ex) in examples.iter().enumerate() {
        let (h, _) = driven_histogram(ex.stride, ex.warmup);
        // Draw the probe arguments exactly one step past the warmup.
        let mut ps = drive_base(ex.stride, ex.warmup);
        let bc_now = h.bucket_count();
        let tot_now = h.total_recorded();
        let bounds_list = (1..=8)
            .map(|k| (k * ex.stride).to_string())
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let bounds: [u64; 8] = [{bl}];\n    let mut drive = Histogram::new(&bounds);\n    let mut st: u64 = 0x9A11_CAFE ^ ({s}u64.wrapping_mul(0x9E37).wrapping_add({n}));\n    for _ in 0..{n} {{\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        drive.record((st >> 33) % ({s} * 9));\n    }}\n",
            i = i,
            bl = bounds_list,
            s = ex.stride,
            n = ex.warmup
        ));
        for &op in &spec.ops {
            s.push_str("    let mut r = drive.clone();\n");
            match op {
                Op::BucketCount => {
                    s.push_str(&format!("    assert_eq!(r.bucket_count(), {bc_now});\n"));
                }
                Op::TotalRecorded => {
                    s.push_str(&format!("    assert_eq!(r.total_recorded(), {tot_now});\n"));
                }
                Op::Record => {
                    let v = nxt(&mut ps) % (ex.stride * 9);
                    let want = h.clone().record(v);
                    s.push_str(&format!("    assert_eq!(r.record({v}), {want});\n"));
                }
                Op::CountIn => {
                    let b = (nxt(&mut ps) as usize) % 9;
                    let want = h
                        .count_in(b)
                        .map_or_else(|| "None".to_string(), |x| format!("Some({x})"));
                    s.push_str(&format!("    assert_eq!(r.count_in({b}), {want});\n"));
                }
                Op::BoundaryAt => {
                    let ix = (nxt(&mut ps) as usize) % 9;
                    let want = h
                        .boundary_at(ix)
                        .map_or_else(|| "None".to_string(), |x| format!("Some({x})"));
                    s.push_str(&format!("    assert_eq!(r.boundary_at({ix}), {want});\n"));
                    s.push_str("    assert_eq!(r.boundary_at(9), None);\n");
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Scripted upper-bound probe: values sitting exactly on the bounds
    // 10 and 20 must file upward, and the tallies must agree.
    if spec.ops.contains(&Op::Record) && spec.ops.contains(&Op::CountIn) {
        s.push_str("#[test]\nfn scripted_upper_bound_rule_holds_for_boundary_values() {\n    let mut r = Histogram::new(&[10, 20]);\n    assert_eq!(r.record(5), 0);\n    assert_eq!(r.count_in(0), Some(1));\n    assert_eq!(r.record(10), 1);\n    assert_eq!(r.count_in(1), Some(1));\n    assert_eq!(r.record(19), 1);\n    assert_eq!(r.count_in(1), Some(2));\n    assert_eq!(r.record(20), 2);\n    assert_eq!(r.count_in(2), Some(1));\n}\n");
    }
    // Fill soak: random records over a four-bucket layout must keep the
    // answered index pinned to a shadow mirror and the total exact.
    if spec.ops.contains(&Op::Record) && spec.ops.contains(&Op::TotalRecorded) {
        s.push_str("#[test]\nfn fill_soak_keeps_the_total_pinned_to_a_shadow() {\n    let bounds: [u64; 3] = [5, 25, 45];\n    let mut r = Histogram::new(&bounds);\n    let mut shadow = [0u64; 4];\n    let mut st: u64 = 0x5EED_0000_0000_01C0;\n    for _ in 0..800u64 {\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        let v = (st >> 33) % 90;\n        let want = shadow.iter().sum::<u64>();\n        let idx = bounds.iter().filter(|&&b| b <= v).count();\n        shadow[idx] += 1;\n        assert_eq!(r.record(v), idx as u64);\n        assert_eq!(r.total_recorded(), want + 1);\n    }\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::Histogram;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    let ops = effective_ops(spec);
    s.push_str("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {\n    let shared: [u64; 3] = [5, 25, 45];\n    let mut cand = Histogram::new(&shared);\n    let mut refr = HistogramRef::new(&shared);\n");
    if ops.contains(&Op::Record) {
        s.push_str("    assert_eq!(cand.record(45), refr.ref_record(45));\n");
    }
    if ops.contains(&Op::CountIn) {
        s.push_str("    assert_eq!(cand.count_in(3), refr.ref_count_in(3));\n");
        s.push_str("    assert_eq!(cand.count_in(9), refr.ref_count_in(9));\n");
    }
    if ops.contains(&Op::BoundaryAt) {
        s.push_str("    assert_eq!(cand.boundary_at(2), refr.ref_boundary_at(2));\n");
        s.push_str("    assert_eq!(cand.boundary_at(3), refr.ref_boundary_at(3));\n");
    }
    if ops.contains(&Op::BucketCount) {
        s.push_str("    assert_eq!(cand.bucket_count(), refr.ref_bucket_count());\n");
    }
    if ops.contains(&Op::TotalRecorded) {
        s.push_str("    assert_eq!(cand.total_recorded(), refr.ref_total_recorded());\n");
    }
    let arm_count = ops.len();
    s.push_str(&format!("    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_01BE;\n    for _ in 0..3000 {{\n        let arg = nx(&mut state);\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in ops.iter().enumerate() {
        let body = match op {
            Op::Record => "assert_eq!(cand.record(arg % 60), refr.ref_record(arg % 60));".to_string(),
            Op::CountIn => {
                "assert_eq!(cand.count_in((arg % 9) as usize), refr.ref_count_in((arg % 9) as usize));"
                    .to_string()
            }
            Op::BoundaryAt => {
                "assert_eq!(cand.boundary_at((arg % 9) as usize), refr.ref_boundary_at((arg % 9) as usize));"
                    .to_string()
            }
            Op::BucketCount => {
                "assert_eq!(cand.bucket_count(), refr.ref_bucket_count());".to_string()
            }
            Op::TotalRecorded => {
                "assert_eq!(cand.total_recorded(), refr.ref_total_recorded());".to_string()
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
    s.push_str(HISTO_NEW_SRC);
    s.push_str("impl Histogram {\n");
    for &op in &ops {
        let body = match op {
            Op::BucketCount | Op::Record | Op::TotalRecorded => "0",
            Op::CountIn | Op::BoundaryAt => "None",
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s.push_str("}\n");
    s
}

/// The plausible off-by-one cheat: identical bookkeeping, but the
/// partition compares strictly less-than, so a value sitting exactly on
/// a boundary falls into the lower bucket — records away from bounds
/// look perfect; the first boundary value misfiles.
pub fn off_by_one_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(HISTO_NEW_SRC);
    s.push_str("impl Histogram {\n");
    for &op in &ops {
        if op == Op::Record {
            let body = &[
                "let idx = self.bounds.partition_point(|&bound| bound < value);",
                "self.counts[idx] += 1;",
                "idx as u64",
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

pub struct HistogramFamily;

impl Generator for HistogramFamily {
    fn id(&self) -> &'static str {
        "histogram-bucket"
    }

    fn category(&self) -> &'static str {
        "bucket-aggregate"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("histogram-bucket", seed);
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
            id: format!("histogram-bucket/{seed:016x}"),
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
        s.push_str(HISTO_NEW_SRC);
        s.push_str("impl Histogram {\n");
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
            ("off-by-one".to_string(), off_by_one_src(spec)),
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
        let a = HistogramFamily.generate(55);
        let b = HistogramFamily.generate(55);
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
            let (h, seen) = driven_histogram(4, warmup);
            assert_eq!(seen.len(), warmup as usize);
            assert_eq!(h.bucket_count(), 9);
            assert_eq!(h.total_recorded(), warmup);
            assert!(h.count_in(8).is_some());
            assert_eq!(h.count_in(9), None);
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let (h, _) = driven_histogram(ex.stride, ex.warmup);
                assert_eq!(h.bucket_count(), 9);
                assert_eq!(h.total_recorded(), ex.warmup);
                assert!((1..=8).contains(&ex.stride));
                assert!(ex.warmup >= 2);
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct HistogramRef"));
            assert!(!src.contains("pub fn record"));
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
            let canary = mint_canary("histogram-bucket", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in ["partition_point", ".get(bucket)", ".iter().sum()"] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("boundary"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("HistogramRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soaks() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            let scripted = spec.ops.contains(&Op::Record) && spec.ops.contains(&Op::CountIn);
            let pins = spec.ops.contains(&Op::Record) && spec.ops.contains(&Op::TotalRecorded);
            assert_eq!(
                behavior.contains("scripted_upper_bound_rule_holds_for_boundary_values"),
                scripted,
                "seed {seed}: bound-rule soak misaligned"
            );
            assert_eq!(
                behavior.contains("fill_soak_keeps_the_total_pinned_to_a_shadow"),
                pins,
                "seed {seed}: total soak misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_bucket_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let single = off_by_one_src(spec);
        assert!(!cz.contains("partition_point"));
        assert!(single.contains("fn record"));
        let ps = single.find("fn record").unwrap();
        let pe = ps + single[ps..].find("\n}\n").unwrap();
        let pb = &single[ps..pe];
        assert!(
            pb.contains("partition_point"),
            "cheat must still partition internally"
        );
        assert!(pb.contains("bound < value"), "cheat must compare strictly");
        assert!(
            !pb.contains("bound <= value"),
            "the strict compare is the bug"
        );
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("histogram-bucket", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
