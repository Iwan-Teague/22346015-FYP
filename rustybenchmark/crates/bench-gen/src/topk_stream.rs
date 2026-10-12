//! Top-k-stream natives: the exercise family models a bounded selection
//! over a stream of offers — the largest `capacity` values seen so far stay
//! live, the admission floor opens once the collection is full, and every
//! tally and rank must stay exact.

#[derive(Clone)]
pub struct TopKInstance {
    cap: usize,
    /// Live values kept sorted DESCENDING: index 0 is the largest.
    live: Vec<u64>,
    total: u64,
}

impl TopKInstance {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity >= 1);
        Self {
            cap: capacity,
            live: Vec::new(),
            total: 0,
        }
    }

    pub fn topk_len(&self) -> u64 {
        self.live.len() as u64
    }

    pub fn total_offered(&self) -> u64 {
        self.total
    }

    /// Offer one value to the bounded selection. While there is room the
    /// value simply joins; once full, a value above the floor evicts the
    /// floor (the smallest live value) and answers it, while a value at or
    /// below the floor is rejected. Answers the evicted victim or None.
    pub fn offer(&mut self, value: u64) -> Option<u64> {
        self.total += 1;
        if self.live.len() == self.cap {
            if value <= self.live[self.cap - 1] {
                return None;
            }
            let victim = self.live.pop().unwrap();
            self.insert_desc(value);
            return Some(victim);
        }
        self.insert_desc(value);
        None
    }

    fn insert_desc(&mut self, value: u64) {
        let mut at = self.live.len();
        while at > 0 && self.live[at - 1] < value {
            at -= 1;
        }
        self.live.insert(at, value);
    }

    /// The rank-`k` live value with 0 = the largest; None past the end.
    pub fn kth_best(&self, k: usize) -> Option<u64> {
        self.live.get(k).copied()
    }

    /// The admission floor: None while the collection still has room, then
    /// Some(smallest live value) once it holds its capacity.
    pub fn threshold(&self) -> Option<u64> {
        if self.live.len() == self.cap {
            self.live.last().copied()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offer_fills_then_evicts_the_floor() {
        let mut t = TopKInstance::new(3);
        assert_eq!(t.offer(5), None);
        assert_eq!(t.offer(7), None);
        assert_eq!(t.offer(3), None);
        assert_eq!(t.topk_len(), 3);
        assert_eq!(t.offer(9), Some(3));
        assert_eq!(t.topk_len(), 3);
        assert_eq!(t.offer(4), None);
        assert_eq!(t.offer(6), Some(5));
        assert_eq!(t.kth_best(0), Some(9));
        assert_eq!(t.kth_best(1), Some(7));
        assert_eq!(t.kth_best(2), Some(6));
    }

    #[test]
    fn values_at_the_floor_are_rejected() {
        let mut t = TopKInstance::new(2);
        assert_eq!(t.offer(6), None);
        assert_eq!(t.offer(6), None);
        assert_eq!(t.threshold(), Some(6));
        assert_eq!(t.offer(6), None);
        assert_eq!(t.offer(5), None);
        assert_eq!(t.topk_len(), 2);
        assert_eq!(t.kth_best(0), Some(6));
        assert_eq!(t.total_offered(), 4);
    }

    #[test]
    fn threshold_opens_only_at_capacity() {
        let mut t = TopKInstance::new(2);
        assert_eq!(t.threshold(), None);
        assert_eq!(t.offer(8), None);
        assert_eq!(t.threshold(), None);
        assert_eq!(t.offer(9), None);
        assert_eq!(t.threshold(), Some(8));
        assert_eq!(t.offer(10), Some(8));
        assert_eq!(t.threshold(), Some(9));
        assert_eq!(t.offer(1), None);
        assert_eq!(t.threshold(), Some(9));
    }

    #[test]
    fn kth_best_ranks_from_the_largest_with_none_past_the_end() {
        let mut t = TopKInstance::new(4);
        for v in [11u64, 4, 27, 19] {
            t.offer(v);
        }
        assert_eq!(t.kth_best(0), Some(27));
        assert_eq!(t.kth_best(1), Some(19));
        assert_eq!(t.kth_best(2), Some(11));
        assert_eq!(t.kth_best(3), Some(4));
        assert_eq!(t.kth_best(4), None);
        assert_eq!(t.kth_best(999), None);
    }

    #[test]
    fn total_offered_counts_every_offer_including_rejections() {
        let mut t = TopKInstance::new(1);
        t.offer(9);
        t.offer(2);
        t.offer(2);
        t.offer(12);
        assert_eq!(t.total_offered(), 4);
        assert_eq!(t.kth_best(0), Some(12));
        assert_eq!(t.topk_len(), 1);
    }

    #[test]
    fn soak_matches_a_shadow_multiset_under_random_traffic() {
        let mut t = TopKInstance::new(5);
        let mut shadow: Vec<u64> = Vec::new();
        let mut st: u64 = 0x5EED_70A5;
        for _ in 0..600u64 {
            st = st
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let v = (st >> 33) % 40;
            let want = if shadow.len() < 5 || v <= shadow[0] {
                None
            } else {
                Some(shadow[0])
            };
            if shadow.len() < 5 || v > shadow[0] {
                shadow.push(v);
                shadow.sort_unstable();
                if shadow.len() > 5 {
                    shadow.remove(0);
                }
            }
            assert_eq!(t.offer(v), want);
            assert_eq!(t.topk_len(), shadow.len() as u64);
            assert_eq!(
                t.threshold(),
                if shadow.len() == 5 {
                    Some(shadow[0])
                } else {
                    None
                }
            );
        }
    }
}

use crate::{mint_canary, GeneratedTask, Generator, Rng};

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    TopKLen,
    Offer,
    KthBest,
    Threshold,
    TotalOffered,
}

pub const OP_ALL: [Op; 5] = [
    Op::TopKLen,
    Op::Offer,
    Op::KthBest,
    Op::Threshold,
    Op::TotalOffered,
];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::TopKLen => "topk_len",
            Op::Offer => "offer",
            Op::KthBest => "kth_best",
            Op::Threshold => "threshold",
            Op::TotalOffered => "total_offered",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::TopKLen => "answers how many values the selection currently holds",
            Op::Offer => "submits one value to the bounded selection: while there is room it simply joins and None is answered; once full, a value above the floor evicts that floor value and answers it, while a value at or below the floor is rejected with None",
            Op::KthBest => "answers the rank-k live value counting down from the largest at rank 0, or None when k is past the end",
            Op::Threshold => "answers the admission floor - Some(smallest live value) once the selection holds its capacity, or None while there is still room",
            Op::TotalOffered => "answers how many values have ever been offered, rejected ones included",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::TopKLen => "pub fn topk_len(&self) -> u64",
            Op::Offer => "pub fn offer(&mut self, value: u64) -> Option<u64>",
            Op::KthBest => "pub fn kth_best(&self, k: usize) -> Option<u64>",
            Op::Threshold => "pub fn threshold(&self) -> Option<u64>",
            Op::TotalOffered => "pub fn total_offered(&self) -> u64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub const CANONICAL_SEED: u64 = 0x70A5_FA11;

/// The fixed capacity every scenario shares.
pub const STREAM_CAP: usize = 5;

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

/// Offer is the fill primitive and the admission floor is the audit probe;
/// both ship as given infrastructure alongside the sampled pair, so any
/// solution whose live collection silently freezes after filling drifts on
/// the very next offer no matter which pair was drawn.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    let mut v = vec![Op::Offer];
    if !spec.ops.contains(&Op::Threshold) {
        v.push(Op::Threshold);
    }
    for o in spec.ops {
        if !v.contains(&o) {
            v.push(o);
        }
    }
    v
}

/// The canonical scenario: a wide value span hammered by dozens of offers,
/// so rejections, evictions and floor movement all show up repeatedly.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical topk-stream scenario");
}

fn fresh_topk() -> TopKInstance {
    TopKInstance::new(STREAM_CAP)
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub span: u64,
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01CC;

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![
        ExampleCase {
            span: 24,
            warmup: canonical(seed),
        },
        ExampleCase { span: 4, warmup: 3 },
        ExampleCase { span: 6, warmup: 4 },
        ExampleCase {
            span: 12,
            warmup: 17,
        },
    ];
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    for _ in 0..8 {
        let span = 3 + rng.below(38);
        out.push(ExampleCase {
            span,
            warmup: rng.below(span * 4) + 3,
        });
    }
    out
}

const NX_MUL: u64 = 6364136223846793005;
const NX_ADD: u64 = 1442695040888963407;

fn drive_init(span: u64, warmup: u64) -> u64 {
    0x70A5_CAFEu64 ^ span.wrapping_mul(0x9E37).wrapping_add(warmup)
}

/// Drives `warmup` random offers (values below `span`) into a fresh selection.
fn driven_topk(span: u64, warmup: u64) -> TopKInstance {
    let mut t = fresh_topk();
    let mut st = drive_init(span, warmup);
    for _ in 0..warmup {
        t.offer((st >> 33) % span);
        st = st.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    }
    t
}

/// The probe-continuation state after the drive loop (one advance per offer).
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

pub const STRUCT_SRC: &str =
    "#[derive(Clone)]\npub struct TopK {\n    cap: usize,\n    live: Vec<u64>,\n    total: u64,\n}\n";

pub const TOPK_NEW_SRC: &str = "impl TopK {\n    pub fn new(capacity: usize) -> Self {\n        assert!(capacity >= 1);\n        TopK {\n            cap: capacity,\n            live: Vec::new(),\n            total: 0,\n        }\n    }\n}\n\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

const OFFER_BODY: &[&str] = &[
    "self.total += 1;",
    "if self.live.len() == self.cap {",
    "    if value <= self.live[self.cap - 1] {",
    "        return None;",
    "    }",
    "    let victim = self.live.pop().unwrap();",
    "    let mut at = self.live.len();",
    "    while at > 0 && self.live[at - 1] < value {",
    "        at -= 1;",
    "    }",
    "    self.live.insert(at, value);",
    "    return Some(victim);",
    "}",
    "let mut at = self.live.len();",
    "while at > 0 && self.live[at - 1] < value {",
    "    at -= 1;",
    "}",
    "self.live.insert(at, value);",
    "None",
];

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::TopKLen => &["self.live.len() as u64"],
        Op::Offer => OFFER_BODY,
        Op::KthBest => &["self.live.get(k).copied()"],
        Op::Threshold => &["if self.live.len() == self.cap {\n    self.live.last().copied()\n} else {\n    None\n}"],
        Op::TotalOffered => &["self.total"],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen("pub struct TopK {", "pub struct TopKRef {", 1);
    s.push_str(
        &TOPK_NEW_SRC
            .replace("impl TopK {", "impl TopKRef {")
            .replace("TopK {\n", "TopKRef {\n"),
    );
    s.push_str("impl TopKRef {\n");
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
        let t = driven_topk(ex.span, ex.warmup);
        s.push_str(&format!(
            "//! ex{i}: {w} offers of values below {span} -> {l} held, rank 0 = {top}, floor {fl}\n",
            i = i,
            w = ex.warmup,
            span = ex.span,
            l = t.topk_len(),
            top = opt_fmt(t.kth_best(0)),
            fl = opt_fmt(t.threshold())
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested streaming-selection operations over one\n\
         //! internal bounded collection. The largest values seen so far stay\n\
         //! live, a full collection admits only values above its floor, and\n\
         //! every tally and rank must stay exact. The hidden tests drive\n\
         //! thousands of interleaved operations and compare every returned\n\
         //! value.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(TOPK_NEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested streaming-selection operations with exactly maintained bookkeeping.\n\nRequirements:\n- `TopK::new(capacity)` starts empty; the constructor is given.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- The selection keeps only the largest values seen so far, never more than its capacity; a full collection admits an offered value exactly when that value beats the current floor, and the displaced floor value is answered.\n- A rejected offer changes nothing about the live values yet still counts toward total_offered.\n- Queries never mutate the selection; kth_best past the end answers None, and threshold stays closed until the capacity is reached.\n- No floating point; no unsafe code; standard library only.\n\nSignatures:\n```rust\n");
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
    let mut s = String::from("use task::TopK;\n\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n");
    for (i, ex) in examples.iter().enumerate() {
        let h = driven_topk(ex.span, ex.warmup);
        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let mut drive = TopK::new(5);\n    let mut st: u64 = {init};\n    for _ in 0..{w} {{\n        drive.offer((st >> 33) % {span}u64);\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    }}\n",
            i = i,
            w = ex.warmup,
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
                Op::TopKLen => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.topk_len(), {});\n",
                        h.topk_len()
                    ));
                }
                Op::TotalOffered => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.total_offered(), {});\n",
                        h.total_offered()
                    ));
                }
                Op::Threshold => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.threshold(), {});\n",
                        opt_fmt(h.threshold())
                    ));
                }
                Op::KthBest => {
                    let k = nx(&mut ps) % 7;
                    let want = h.clone().kth_best(k as usize);
                    s.push_str(&format!(
                        "    let r = drive.clone();\n    let k = nx(&mut ps) % 7u64;\n    assert_eq!(r.kth_best(k as usize), {});\n",
                        opt_fmt(want)
                    ));
                }
                Op::Offer => {
                    let v = nx(&mut ps) % ex.span;
                    let want = h.clone().offer(v);
                    s.push_str(&format!(
                        "    let mut r = drive.clone();\n    let v = nx(&mut ps) % {span}u64;\n    assert_eq!(r.offer(v), {want});\n",
                        span = ex.span,
                        want = opt_fmt(want)
                    ));
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Scripted probe: the floor opens exactly when the capacity is reached
    // and moves only when a newcomer beats it.
    if spec.ops.contains(&Op::Offer) && spec.ops.contains(&Op::Threshold) {
        s.push_str("#[test]\nfn scripted_floor_opens_only_at_capacity() {\n    let mut r = TopK::new(3);\n    assert_eq!(r.threshold(), None);\n    assert_eq!(r.offer(5), None);\n    assert_eq!(r.threshold(), None);\n    assert_eq!(r.offer(7), None);\n    assert_eq!(r.threshold(), None);\n    assert_eq!(r.offer(3), None);\n    assert_eq!(r.threshold(), Some(3));\n    assert_eq!(r.offer(9), Some(3));\n    assert_eq!(r.threshold(), Some(5));\n    assert_eq!(r.offer(2), None);\n    assert_eq!(r.threshold(), Some(5));\n}\n");
    }
    // Scripted probe: rejected offers still advance the arrival tally.
    if spec.ops.contains(&Op::Offer) && spec.ops.contains(&Op::TotalOffered) {
        s.push_str("#[test]\nfn scripted_tally_counts_rejected_offers_too() {\n    let mut r = TopK::new(1);\n    assert_eq!(r.offer(9), None);\n    assert_eq!(r.offer(4), None);\n    assert_eq!(r.offer(11), Some(9));\n    assert_eq!(r.total_offered(), 3);\n}\n");
    }
    // Fill soak: eight hundred random offers must keep every rank pinned to
    // a shadow multiset.
    if spec.ops.contains(&Op::Offer) && spec.ops.contains(&Op::KthBest) {
        s.push_str("#[test]\nfn fill_soak_ranks_against_a_shadow_multiset() {\n    let mut r = TopK::new(5);\n    let mut shadow: Vec<u64> = Vec::new();\n    let mut st: u64 = 0x5EED_0000_0000_01CE;\n    for _ in 0..800usize {\n        let v = (st >> 33) % 25;\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        let want = if shadow.len() < 5 || v <= shadow[0] {\n            None\n        } else {\n            Some(shadow[0])\n        };\n        if shadow.len() < 5 || v > shadow[0] {\n            shadow.push(v);\n            shadow.sort_unstable();\n            if shadow.len() > 5 {\n                shadow.remove(0);\n            }\n        }\n        assert_eq!(r.offer(v), want);\n        let k = (st >> 7) as usize % 8;\n        let expect = if k < shadow.len() {\n            Some(shadow[shadow.len() - 1 - k])\n        } else {\n            None\n        };\n        assert_eq!(r.kth_best(k), expect);\n    }\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::TopK;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    let ops = effective_ops(spec);
    s.push_str("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {\n    let mut cand = TopK::new(6);\n    let mut refr = TopKRef::new(6);\n");
    if ops.contains(&Op::Offer) {
        for v in [20u64, 19, 18, 17, 16, 15] {
            s.push_str(&format!(
                "    assert_eq!(cand.offer({v}), refr.ref_offer({v}));\n"
            ));
        }
        s.push_str("    assert_eq!(cand.offer(3), refr.ref_offer(3));\n");
    }
    if ops.contains(&Op::Threshold) {
        s.push_str("    assert_eq!(cand.threshold(), refr.ref_threshold());\n");
    }
    if ops.contains(&Op::KthBest) {
        s.push_str("    assert_eq!(cand.kth_best(0), refr.ref_kth_best(0));\n");
        s.push_str("    assert_eq!(cand.kth_best(2), refr.ref_kth_best(2));\n");
        s.push_str("    assert_eq!(cand.kth_best(99), refr.ref_kth_best(99));\n");
    }
    if ops.contains(&Op::TopKLen) {
        s.push_str("    assert_eq!(cand.topk_len(), refr.ref_topk_len());\n");
    }
    if ops.contains(&Op::TotalOffered) {
        s.push_str("    assert_eq!(cand.total_offered(), refr.ref_total_offered());\n");
    }
    let arm_count = ops.len();
    s.push_str(&format!("    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_01CC;\n    for _ in 0..3000 {{\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in ops.iter().enumerate() {
        let body = match op {
            Op::TopKLen => "assert_eq!(cand.topk_len(), refr.ref_topk_len());".to_string(),
            Op::Offer => "let v = nx(&mut state) % 23;\n            assert_eq!(cand.offer(v), refr.ref_offer(v));".to_string(),
            Op::KthBest => "let k = nx(&mut state) % 8;\n            assert_eq!(cand.kth_best(k as usize), refr.ref_kth_best(k as usize));".to_string(),
            Op::Threshold => "assert_eq!(cand.threshold(), refr.ref_threshold());".to_string(),
            Op::TotalOffered => {
                "assert_eq!(cand.total_offered(), refr.ref_total_offered());".to_string()
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
    s.push_str(TOPK_NEW_SRC);
    s.push_str("impl TopK {\n");
    for &op in &ops {
        let body = match op {
            Op::Offer | Op::KthBest | Op::Threshold => "None",
            _ => "0",
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s.push_str("}\n");
    s
}

/// The plausible cheat: offers fill the collection and the tally keeps
/// counting, but once full nothing is ever admitted or evicted again - the
/// live set freezes and the floor never moves.
pub fn frozen_topk_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(TOPK_NEW_SRC);
    s.push_str("impl TopK {\n");
    for &op in &ops {
        if op == Op::Offer {
            let body = &[
                "self.total += 1;",
                "if self.live.len() < self.cap {",
                "    let mut at = self.live.len();",
                "    while at > 0 && self.live[at - 1] < value {",
                "        at -= 1;",
                "    }",
                "    self.live.insert(at, value);",
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

pub struct TopKStreamFamily;

impl Generator for TopKStreamFamily {
    fn id(&self) -> &'static str {
        "topk-stream"
    }

    fn category(&self) -> &'static str {
        "bounded-selection"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("topk-stream", seed);
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
            id: format!("topk-stream/{seed:016x}"),
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
        s.push_str(TOPK_NEW_SRC);
        s.push_str("impl TopK {\n");
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
            ("frozen-topk".to_string(), frozen_topk_src(spec)),
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
        let a = TopKStreamFamily.generate(55);
        let b = TopKStreamFamily.generate(55);
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
            let t = driven_topk(24, warmup);
            assert_eq!(t.topk_len(), (warmup as usize).min(STREAM_CAP) as u64);
            assert_eq!(t.total_offered(), warmup);
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let t = driven_topk(ex.span, ex.warmup);
                assert_eq!(t.total_offered(), ex.warmup);
                assert!(ex.warmup >= 3);
                assert!(ex.span >= 3 && ex.span < 41);
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct TopKRef"));
            assert!(
                src.matches("TopKRef {").count() >= 2,
                "constructor body must be renamed too"
            );
            assert!(!src.contains("pub fn offer"));
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
            let canary = mint_canary("topk-stream", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in ["let victim", "at -= 1", "self.cap - 1"] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("floor"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("TopKRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soaks() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            let floor_gate = spec.ops.contains(&Op::Offer) && spec.ops.contains(&Op::Threshold);
            let tally_gate = spec.ops.contains(&Op::Offer) && spec.ops.contains(&Op::TotalOffered);
            let soak_gate = spec.ops.contains(&Op::Offer) && spec.ops.contains(&Op::KthBest);
            assert_eq!(
                behavior.contains("scripted_floor_opens_only_at_capacity"),
                floor_gate,
                "seed {seed}: floor script misaligned"
            );
            assert_eq!(
                behavior.contains("scripted_tally_counts_rejected_offers_too"),
                tally_gate,
                "seed {seed}: tally script misaligned"
            );
            assert_eq!(
                behavior.contains("fill_soak_ranks_against_a_shadow_multiset"),
                soak_gate,
                "seed {seed}: shadow soak misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_selection_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let cheat = frozen_topk_src(spec);
        assert!(!cz.contains("todo!()"));
        assert!(cheat.contains("fn offer"));
        let us = cheat.find("fn offer").unwrap();
        let ue = us + cheat[us..].find("\n}\n").unwrap();
        let ub = &cheat[us..ue];
        assert!(
            ub.contains("self.total += 1;"),
            "cheat must keep the tally real"
        );
        assert!(ub.contains("None"));
        assert!(!ub.contains("victim"), "the frozen admission is the bug");
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("topk-stream", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
