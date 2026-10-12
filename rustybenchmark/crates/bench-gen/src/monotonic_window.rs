//! Monotonic-window natives: the exercise family models a sliding window
//! whose candidate values are kept in a strictly increasing monotonic
//! deque, so dominated values are evicted the moment a smaller successor
//! arrives and every tally must stay exact.

#[derive(Clone, Default)]
pub struct MinQueueInstance {
    /// Strictly increasing `(arrival_seq, value)` pairs, front = current min.
    buf: std::collections::VecDeque<(u64, u64)>,
    pushed: u64,
}

impl MinQueueInstance {
    pub fn new() -> Self {
        Self {
            buf: std::collections::VecDeque::new(),
            pushed: 0,
        }
    }

    pub fn queue_len(&self) -> u64 {
        self.buf.len() as u64
    }

    pub fn total_pushed(&self) -> u64 {
        self.pushed
    }

    /// Push a value into the window and answer how many DOMINATED tail
    /// entries (values `>=` the newcomer) were evicted from the back.
    pub fn push_back(&mut self, value: u64) -> u64 {
        let mut evicted = 0u64;
        while let Some(&(_, top)) = self.buf.back() {
            if top >= value {
                self.buf.pop_back();
                evicted += 1;
            } else {
                break;
            }
        }
        self.buf.push_back((self.pushed, value));
        self.pushed += 1;
        evicted
    }

    /// The smallest live value, i.e. the front of the monotonic run.
    pub fn current_min(&self) -> Option<u64> {
        self.buf.front().map(|&(_, v)| v)
    }

    /// Retire the oldest live entry (the front of the deque) and answer the
    /// value that left the window, or None when nothing is live.
    pub fn advance(&mut self) -> Option<u64> {
        self.buf.pop_front().map(|(_, v)| v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_and_current_min_roundtrip() {
        let mut q = MinQueueInstance::new();
        assert_eq!(q.push_back(7), 0);
        assert_eq!(q.current_min(), Some(7));
        assert_eq!(q.queue_len(), 1);
        assert_eq!(q.push_back(9), 0);
        assert_eq!(q.current_min(), Some(7));
        assert_eq!(q.queue_len(), 2);
        assert_eq!(q.push_back(4), 2);
        assert_eq!(q.current_min(), Some(4));
        assert_eq!(q.queue_len(), 1);
    }

    #[test]
    fn advance_retires_the_front_minimum() {
        let mut q = MinQueueInstance::new();
        q.push_back(6);
        q.push_back(10);
        assert_eq!(q.advance(), Some(6));
        assert_eq!(q.current_min(), Some(10));
        assert_eq!(q.advance(), Some(10));
        assert_eq!(q.advance(), None);
        assert_eq!(q.current_min(), None);
    }

    #[test]
    fn duplicate_values_dominate_each_other() {
        let mut q = MinQueueInstance::new();
        assert_eq!(q.push_back(5), 0);
        assert_eq!(q.push_back(5), 1);
        assert_eq!(q.queue_len(), 1);
        assert_eq!(q.current_min(), Some(5));
    }

    #[test]
    fn total_pushed_counts_every_arrival() {
        let mut q = MinQueueInstance::new();
        q.push_back(3);
        q.push_back(1);
        q.push_back(2);
        assert_eq!(q.total_pushed(), 3);
        assert_eq!(q.queue_len(), 2);
        assert_eq!(q.advance(), Some(1));
        assert_eq!(q.total_pushed(), 3);
    }

    #[test]
    fn mixed_sequence_matches_hand_computed_shape() {
        let mut q = MinQueueInstance::new();
        assert_eq!(q.push_back(2), 0);
        assert_eq!(q.push_back(1), 1);
        assert_eq!(q.push_back(4), 0);
        assert_eq!(q.push_back(3), 1);
        assert_eq!(q.queue_len(), 2);
        assert_eq!(q.current_min(), Some(1));
        assert_eq!(q.advance(), Some(1));
        assert_eq!(q.current_min(), Some(3));
        assert_eq!(q.advance(), Some(3));
        assert_eq!(q.queue_len(), 0);
        assert_eq!(q.total_pushed(), 4);
    }

    #[test]
    fn soak_matches_a_naive_shadow_under_random_traffic() {
        let mut q = MinQueueInstance::new();
        let mut live: Vec<u64> = Vec::new();
        let mut st: u64 = 0x5EED_CA7E;
        for _ in 0..600u64 {
            st = st
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let v = (st >> 33) % 20;
            if (st >> 13).is_multiple_of(3) && !live.is_empty() {
                let want = live.remove(0);
                assert_eq!(q.advance(), Some(want));
            } else {
                let mut evicted = 0u64;
                while let Some(&top) = live.last() {
                    if top >= v {
                        live.pop();
                        evicted += 1;
                    } else {
                        break;
                    }
                }
                live.insert(0, v);
                live.sort_unstable();
                assert_eq!(q.push_back(v), evicted);
            }
            assert_eq!(q.queue_len(), live.len() as u64);
            assert_eq!(q.current_min(), live.first().copied());
        }
    }
}

use crate::{mint_canary, GeneratedTask, Generator, Rng};

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    QueueLen,
    PushBack,
    CurrentMin,
    Advance,
    TotalPushed,
}

pub const OP_ALL: [Op; 5] = [
    Op::QueueLen,
    Op::PushBack,
    Op::CurrentMin,
    Op::Advance,
    Op::TotalPushed,
];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::QueueLen => "queue_len",
            Op::PushBack => "push_back",
            Op::CurrentMin => "current_min",
            Op::Advance => "advance",
            Op::TotalPushed => "total_pushed",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::QueueLen => "answers how many entries are currently live in the window",
            Op::PushBack => "appends the newcomer after evicting every tail entry whose value is greater than or equal to it, and answers how many tail entries were evicted",
            Op::CurrentMin => "answers the smallest live value, or None when the window is empty",
            Op::Advance => "retires the oldest live entry and answers its value, or None when the window is empty",
            Op::TotalPushed => "answers how many values have ever arrived, including ones later evicted or retired",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::QueueLen => "pub fn queue_len(&self) -> u64",
            Op::PushBack => "pub fn push_back(&mut self, value: u64) -> u64",
            Op::CurrentMin => "pub fn current_min(&self) -> Option<u64>",
            Op::Advance => "pub fn advance(&mut self) -> Option<u64>",
            Op::TotalPushed => "pub fn total_pushed(&self) -> u64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub const CANONICAL_SEED: u64 = 0xCA7E_FA11;

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

/// PushBack is the fill primitive and the live-entry tally is the audit
/// counter; both ship as given infrastructure alongside the sampled pair,
/// so any solution that appends without evicting dominated tails drifts
/// from the very first push no matter which pair was drawn.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    let mut v = vec![Op::PushBack];
    if !spec.ops.contains(&Op::QueueLen) {
        v.push(Op::QueueLen);
    }
    for o in spec.ops {
        if !v.contains(&o) {
            v.push(o);
        }
    }
    v
}

/// The canonical scenario: a mid-size value span hammered by dozens of
/// pushes, so duplicates and dominated tails show up constantly.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical monotonic-window scenario");
}

fn fresh_queue() -> MinQueueInstance {
    MinQueueInstance::new()
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub span: u64,
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01C8;

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![
        ExampleCase {
            span: 16,
            warmup: canonical(seed),
        },
        ExampleCase { span: 3, warmup: 3 },
        ExampleCase { span: 5, warmup: 4 },
        ExampleCase {
            span: 9,
            warmup: 17,
        },
    ];
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    for _ in 0..8 {
        let span = 2 + rng.below(23);
        out.push(ExampleCase {
            span,
            warmup: rng.below(span * 6) + 2,
        });
    }
    out
}

const NX_MUL: u64 = 6364136223846793005;
const NX_ADD: u64 = 1442695040888963407;

fn drive_init(span: u64, warmup: u64) -> u64 {
    0xCA7E_CAFEu64 ^ span.wrapping_mul(0x9E37).wrapping_add(warmup)
}

/// Drives `warmup` random pushes (values below `span`) into a fresh window.
fn driven_queue(span: u64, warmup: u64) -> MinQueueInstance {
    let mut q = fresh_queue();
    let mut st = drive_init(span, warmup);
    for _ in 0..warmup {
        q.push_back((st >> 33) % span);
        st = st.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    }
    q
}

/// The probe-continuation state after the drive loop (one advance per push).
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
    "#[derive(Clone)]\npub struct MinQueue {\n    buf: std::collections::VecDeque<(u64, u64)>,\n    pushed: u64,\n}\n";

pub const MINQ_NEW_SRC: &str = "impl MinQueue {\n    pub fn new() -> Self {\n        MinQueue {\n            buf: std::collections::VecDeque::new(),\n            pushed: 0,\n        }\n    }\n}\n\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::QueueLen => &["self.buf.len() as u64"],
        Op::PushBack => &[
            "let mut evicted = 0u64;",
            "while let Some(&(_, top)) = self.buf.back() {",
            "    if top >= value {",
            "        self.buf.pop_back();",
            "        evicted += 1;",
            "    } else {",
            "        break;",
            "    }",
            "}",
            "self.buf.push_back((self.pushed, value));",
            "self.pushed += 1;",
            "evicted",
        ],
        Op::CurrentMin => &["self.buf.front().map(|&(_, v)| v)"],
        Op::Advance => &["self.buf.pop_front().map(|(_, v)| v)"],
        Op::TotalPushed => &["self.pushed"],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen("pub struct MinQueue {", "pub struct MinQueueRef {", 1);
    s.push_str(
        &MINQ_NEW_SRC
            .replace("impl MinQueue {", "impl MinQueueRef {")
            .replace("MinQueue {\n", "MinQueueRef {\n"),
    );
    s.push_str("impl MinQueueRef {\n");
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
        let q = driven_queue(ex.span, ex.warmup);
        s.push_str(&format!(
            "//! ex{i}: {w} pushes of values below {span} -> {l} stay live, min {m}\n",
            i = i,
            w = ex.warmup,
            span = ex.span,
            l = q.queue_len(),
            m = opt_fmt(q.current_min())
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested sliding-window operations over one internal\n\
         //! strictly increasing run of `(arrival, value)` pairs. Dominated\n\
         //! values leave the tail the moment a smaller-or-equal successor\n\
         //! arrives, the front always holds the live minimum, and every\n\
         //! tally must stay exact. The hidden tests drive thousands of\n\
         //! interleaved operations and compare every returned value.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(MINQ_NEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested sliding-window operations with exactly maintained bookkeeping.\n\nRequirements:\n- `MinQueue::new()` starts with an empty window; the constructor is given.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- The window keeps a strictly increasing run of `(arrival_seq, value)` pairs so its front is always the live minimum; before a newcomer joins, every tail entry whose value is greater than or equal to it gets evicted, and push_back answers exactly how many were evicted.\n- The arrival sequence number keeps counting for every push whether or not the value survives; total_pushed reports that count.\n- Queries never mutate the window; advance on an empty window answers None.\n- No floating point; no unsafe code; standard library only.\n\nSignatures:\n```rust\n");
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
    let mut s = String::from("use task::MinQueue;\n\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n");
    for (i, ex) in examples.iter().enumerate() {
        let h = driven_queue(ex.span, ex.warmup);
        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let mut drive = MinQueue::new();\n    let mut st: u64 = {init};\n    for _ in 0..{w} {{\n        drive.push_back((st >> 33) % {span}u64);\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    }}\n",
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
                Op::QueueLen => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.queue_len(), {});\n",
                        h.queue_len()
                    ));
                }
                Op::TotalPushed => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.total_pushed(), {});\n",
                        h.total_pushed()
                    ));
                }
                Op::CurrentMin => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.current_min(), {});\n",
                        opt_fmt(h.current_min())
                    ));
                }
                Op::Advance => {
                    let want = h.clone().advance();
                    s.push_str(&format!(
                        "    let mut r = drive.clone();\n    assert_eq!(r.advance(), {});\n",
                        opt_fmt(want)
                    ));
                }
                Op::PushBack => {
                    let v = nx(&mut ps) % ex.span;
                    let want = h.clone().push_back(v);
                    s.push_str(&format!(
                        "    let mut r = drive.clone();\n    let v = nx(&mut ps) % {span}u64;\n    assert_eq!(r.push_back(v), {want});\n",
                        span = ex.span,
                        want = want
                    ));
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Scripted probe: a newcomer evicts every dominated-or-equal tail entry
    // and answers the exact eviction tally.
    if spec.ops.contains(&Op::PushBack) && spec.ops.contains(&Op::CurrentMin) {
        s.push_str("#[test]\nfn scripted_dominated_tails_are_evicted_and_counted() {\n    let mut r = MinQueue::new();\n    assert_eq!(r.push_back(7), 0);\n    assert_eq!(r.current_min(), Some(7));\n    assert_eq!(r.push_back(4), 1);\n    assert_eq!(r.current_min(), Some(4));\n    assert_eq!(r.push_back(9), 0);\n    assert_eq!(r.current_min(), Some(4));\n    assert_eq!(r.push_back(4), 2);\n    assert_eq!(r.current_min(), Some(4));\n    assert_eq!(r.queue_len(), 1);\n}\n");
    }
    // Scripted probe: retirements answer the retired values in arrival order.
    if spec.ops.contains(&Op::PushBack) && spec.ops.contains(&Op::Advance) {
        s.push_str("#[test]\nfn scripted_retirements_answer_the_live_values_in_order() {\n    let mut r = MinQueue::new();\n    assert_eq!(r.push_back(6), 0);\n    assert_eq!(r.push_back(10), 0);\n    assert_eq!(r.advance(), Some(6));\n    assert_eq!(r.push_back(2), 1);\n    assert_eq!(r.advance(), Some(2));\n    assert_eq!(r.advance(), None);\n    assert_eq!(r.queue_len(), 0);\n}\n");
    }
    // Fill soak: eight hundred random pushes must keep the push tally and
    // the live-entry tally pinned to a shadow run.
    if spec.ops.contains(&Op::PushBack) && spec.ops.contains(&Op::TotalPushed) {
        s.push_str("#[test]\nfn fill_soak_pins_the_push_tally_to_a_shadow_run() {\n    let mut r = MinQueue::new();\n    let mut live: Vec<u64> = Vec::new();\n    let mut pushed: u64 = 0;\n    let mut st: u64 = 0x5EED_0000_0000_01CA;\n    for _ in 0..800usize {\n        let v = (st >> 33) % 13;\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        let mut evicted = 0u64;\n        while let Some(&top) = live.last() {\n            if top >= v {\n                live.pop();\n                evicted += 1;\n            } else {\n                break;\n            }\n        }\n        live.insert(0, v);\n        live.sort_unstable();\n        pushed += 1;\n        assert_eq!(r.push_back(v), evicted);\n        assert_eq!(r.total_pushed(), pushed);\n        assert_eq!(r.queue_len(), live.len() as u64);\n    }\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::MinQueue;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    let ops = effective_ops(spec);
    s.push_str("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {\n    let mut cand = MinQueue::new();\n    let mut refr = MinQueueRef::new();\n");
    if ops.contains(&Op::PushBack) {
        s.push_str("    assert_eq!(cand.push_back(7), refr.ref_push_back(7));\n");
        s.push_str("    assert_eq!(cand.push_back(3), refr.ref_push_back(3));\n");
        s.push_str("    assert_eq!(cand.push_back(3), refr.ref_push_back(3));\n");
    }
    if ops.contains(&Op::QueueLen) {
        s.push_str("    assert_eq!(cand.queue_len(), refr.ref_queue_len());\n");
    }
    if ops.contains(&Op::CurrentMin) {
        s.push_str("    assert_eq!(cand.current_min(), refr.ref_current_min());\n");
    }
    if ops.contains(&Op::Advance) {
        s.push_str("    assert_eq!(cand.advance(), refr.ref_advance());\n");
        s.push_str("    assert_eq!(cand.advance(), refr.ref_advance());\n");
    }
    if ops.contains(&Op::TotalPushed) {
        s.push_str("    assert_eq!(cand.total_pushed(), refr.ref_total_pushed());\n");
    }
    let arm_count = ops.len();
    s.push_str(&format!("    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_01C8;\n    for _ in 0..3000 {{\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in ops.iter().enumerate() {
        let body = match op {
            Op::QueueLen => "assert_eq!(cand.queue_len(), refr.ref_queue_len());".to_string(),
            Op::PushBack => "let v = nx(&mut state) % 11;\n            assert_eq!(cand.push_back(v), refr.ref_push_back(v));".to_string(),
            Op::CurrentMin => "assert_eq!(cand.current_min(), refr.ref_current_min());".to_string(),
            Op::Advance => "assert_eq!(cand.advance(), refr.ref_advance());".to_string(),
            Op::TotalPushed => {
                "assert_eq!(cand.total_pushed(), refr.ref_total_pushed());".to_string()
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
    s.push_str(MINQ_NEW_SRC);
    s.push_str("impl MinQueue {\n");
    for &op in &ops {
        let body = match op {
            Op::CurrentMin | Op::Advance => "None",
            _ => "0",
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s.push_str("}\n");
    s
}

/// The plausible cheat: arrivals land and counters tick, but nothing ever
/// evicts the dominated tail - the live-run length drifts immediately even
/// when no sampled query would ever look at the minimum.
pub fn blind_append_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(MINQ_NEW_SRC);
    s.push_str("impl MinQueue {\n");
    for &op in &ops {
        if op == Op::PushBack {
            let body = &[
                "self.buf.push_back((self.pushed, value));",
                "self.pushed += 1;",
                "0",
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

pub struct MonotonicWindowFamily;

impl Generator for MonotonicWindowFamily {
    fn id(&self) -> &'static str {
        "monotonic-window"
    }

    fn category(&self) -> &'static str {
        "sliding-minimum"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("monotonic-window", seed);
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
            id: format!("monotonic-window/{seed:016x}"),
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
        s.push_str(MINQ_NEW_SRC);
        s.push_str("impl MinQueue {\n");
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
            ("blind-append".to_string(), blind_append_src(spec)),
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
        let a = MonotonicWindowFamily.generate(55);
        let b = MonotonicWindowFamily.generate(55);
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
            let q = driven_queue(16, warmup);
            assert!(q.queue_len() <= warmup);
            assert_eq!(q.total_pushed(), warmup);
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let q = driven_queue(ex.span, ex.warmup);
                assert_eq!(q.total_pushed(), ex.warmup);
                assert!(ex.warmup >= 2);
                assert!(ex.span >= 2 && ex.span < 25);
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct MinQueueRef"));
            assert!(
                src.matches("MinQueueRef {").count() >= 2,
                "constructor body must be renamed too"
            );
            assert!(!src.contains("pub fn push_back"));
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
            let canary = mint_canary("monotonic-window", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in ["while let Some", ".back()", "pop_front"] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("evicted"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("MinQueueRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soaks() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            let min_gate = spec.ops.contains(&Op::PushBack) && spec.ops.contains(&Op::CurrentMin);
            let retire_gate = spec.ops.contains(&Op::PushBack) && spec.ops.contains(&Op::Advance);
            let soak_gate = spec.ops.contains(&Op::PushBack) && spec.ops.contains(&Op::TotalPushed);
            assert_eq!(
                behavior.contains("scripted_dominated_tails_are_evicted_and_counted"),
                min_gate,
                "seed {seed}: domination script misaligned"
            );
            assert_eq!(
                behavior.contains("scripted_retirements_answer_the_live_values_in_order"),
                retire_gate,
                "seed {seed}: retirement script misaligned"
            );
            assert_eq!(
                behavior.contains("fill_soak_pins_the_push_tally_to_a_shadow_run"),
                soak_gate,
                "seed {seed}: shadow soak misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_window_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let cheat = blind_append_src(spec);
        assert!(!cz.contains("todo!()"));
        assert!(cheat.contains("fn push_back"));
        let us = cheat.find("fn push_back").unwrap();
        let ue = us + cheat[us..].find("\n}\n").unwrap();
        let ub = &cheat[us..ue];
        assert!(
            ub.contains("self.buf.push_back((self.pushed, value));"),
            "cheat must keep the append real"
        );
        assert!(ub.contains("self.pushed += 1;"));
        assert!(!ub.contains("while let"), "the missing eviction is the bug");
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("monotonic-window", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
