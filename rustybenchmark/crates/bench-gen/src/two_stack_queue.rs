//! Two-stack-queue natives: an amortized FIFO queue over two stacks.
//! Values land on the inbox stack; the outbox serves the oldest value
//! and is refilled by draining the inbox in reverse exactly once per
//! refill — and the rebalance counter must stay exact as traffic
//! interleaves.

#[derive(Clone, Default)]
pub struct TwoStackQueue {
    /// Freshly pushed values; newest on top.
    inbox: Vec<u64>,
    /// Reversed inbox; the oldest value sits on top.
    outbox: Vec<u64>,
    /// Running count of rebalance operations performed.
    balances: u64,
}

impl TwoStackQueue {
    pub fn new() -> Self {
        Self {
            inbox: Vec::new(),
            outbox: Vec::new(),
            balances: 0,
        }
    }

    /// Total values held across both stacks.
    pub fn q_len(&self) -> u64 {
        (self.inbox.len() + self.outbox.len()) as u64
    }

    /// Pushes onto the inbox and answers the fresh total length.
    pub fn push_back(&mut self, value: u64) -> u64 {
        self.inbox.push(value);
        (self.inbox.len() + self.outbox.len()) as u64
    }

    /// Serves the oldest value; when the outbox is empty and the inbox
    /// holds values, drains the inbox reversed onto the outbox counting
    /// exactly one rebalance. None once both stacks are empty.
    pub fn pop_front(&mut self) -> Option<u64> {
        if self.inbox.is_empty() && self.outbox.is_empty() {
            return None;
        }
        if self.outbox.is_empty() {
            while let Some(v) = self.inbox.pop() {
                self.outbox.push(v);
            }
            self.balances += 1;
        }
        self.outbox.pop()
    }

    /// The value a pop would serve next; never mutates or rebalances.
    pub fn front_peek(&self) -> Option<u64> {
        if let Some(top) = self.outbox.last() {
            return Some(*top);
        }
        self.inbox.first().copied()
    }

    /// How many rebalances have happened so far.
    pub fn balances(&self) -> u64 {
        self.balances
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_pop_roundtrips_in_fifo_order() {
        let mut q = TwoStackQueue::new();
        assert_eq!(q.push_back(10), 1);
        assert_eq!(q.push_back(20), 2);
        assert_eq!(q.pop_front(), Some(10));
        assert_eq!(q.push_back(30), 2);
        assert_eq!(q.pop_front(), Some(20));
        assert_eq!(q.pop_front(), Some(30));
        assert_eq!(q.pop_front(), None);
    }

    #[test]
    fn interleaved_traffic_preserves_fifo_order() {
        let mut q = TwoStackQueue::new();
        q.push_back(1);
        q.push_back(2);
        q.push_back(3);
        assert_eq!(q.pop_front(), Some(1));
        q.push_back(4);
        q.push_back(5);
        assert_eq!(q.pop_front(), Some(2));
        assert_eq!(q.pop_front(), Some(3));
        assert_eq!(q.pop_front(), Some(4));
        assert_eq!(q.pop_front(), Some(5));
        assert_eq!(q.pop_front(), None);
    }

    #[test]
    fn front_peek_never_mutates_or_rebalances() {
        let mut q = TwoStackQueue::new();
        for v in 1..=4u64 {
            q.push_back(v);
        }
        let before = q.balances();
        assert_eq!(q.front_peek(), Some(1));
        assert_eq!(q.front_peek(), Some(1));
        assert_eq!(q.balances(), before);
        assert_eq!(q.q_len(), 4);
        assert_eq!(q.pop_front(), Some(1));
        assert_eq!(q.q_len(), 3);
    }

    #[test]
    fn balance_happens_once_per_drain_and_only_when_needed() {
        let mut q = TwoStackQueue::new();
        assert_eq!(q.balances(), 0);
        q.push_back(1);
        q.push_back(2);
        q.push_back(3);
        assert_eq!(q.front_peek(), Some(1));
        assert_eq!(q.balances(), 0);
        assert_eq!(q.pop_front(), Some(1));
        assert_eq!(q.balances(), 1);
        assert_eq!(q.pop_front(), Some(2));
        assert_eq!(q.pop_front(), Some(3));
        assert_eq!(q.balances(), 1);
        q.push_back(4);
        assert_eq!(q.pop_front(), Some(4));
        assert_eq!(q.balances(), 2);
        assert_eq!(q.pop_front(), None);
        assert_eq!(q.balances(), 2);
    }

    #[test]
    fn empty_queue_answers_none_everywhere() {
        let mut q = TwoStackQueue::new();
        assert_eq!(q.pop_front(), None);
        assert_eq!(q.front_peek(), None);
        assert_eq!(q.q_len(), 0);
        assert_eq!(q.balances(), 0);
    }

    #[test]
    fn soak_matches_a_shadow_vec_under_random_traffic() {
        let mut shadow: Vec<u64> = Vec::new();
        let mut q = TwoStackQueue::new();
        let mut st: u64 = 0x5EED_05CA;
        let mut popped = false;
        for _ in 0..600 {
            match (st >> 13) % 3 {
                0 => {
                    let v = (st >> 33) % 1000;
                    assert_eq!(q.push_back(v), shadow.len() as u64 + 1);
                    shadow.push(v);
                }
                1 => {
                    let want = shadow.first().copied();
                    assert_eq!(q.pop_front(), want);
                    if !shadow.is_empty() {
                        shadow.remove(0);
                        popped = true;
                    }
                }
                _ => {
                    assert_eq!(q.front_peek(), shadow.first().copied());
                }
            }
            assert_eq!(q.q_len(), shadow.len() as u64);
            if popped {
                assert!(q.balances() >= 1);
            }
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
    QLen,
    PushBack,
    PopFront,
    FrontPeek,
    Balances,
}

pub const OP_ALL: [Op; 5] = [
    Op::QLen,
    Op::PushBack,
    Op::PopFront,
    Op::FrontPeek,
    Op::Balances,
];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::QLen => "q_len",
            Op::PushBack => "push_back",
            Op::PopFront => "pop_front",
            Op::FrontPeek => "front_peek",
            Op::Balances => "balances",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::QLen => "answers how many values the queue holds across both stacks",
            Op::PushBack => "appends one value at the back and answers the fresh total length across both stacks",
            Op::PopFront => "serves the oldest value, draining the inbox reversed onto the outbox first when needed; None once both stacks are empty",
            Op::FrontPeek => "answers the value a pop would serve next without mutating anything; None when both stacks are empty",
            Op::Balances => "answers how many rebalance drains have happened so far",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::QLen => "pub fn q_len(&self) -> u64",
            Op::PushBack => "pub fn push_back(&mut self, value: u64) -> u64",
            Op::PopFront => "pub fn pop_front(&mut self) -> Option<u64>",
            Op::FrontPeek => "pub fn front_peek(&self) -> Option<u64>",
            Op::Balances => "pub fn balances(&self) -> u64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub const CANONICAL_SEED: u64 = 0x05CA_FA11;

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

/// PushBack is the fill primitive; PopFront and Balances ship as given
/// infrastructure alongside the sampled pair. A cheat that pops straight
/// off the inbox serves identical values but skips the rebalance tally -
/// and without a pop in the stream no refill ever happens, so the drift
/// would stay invisible; shipping the pop guarantees the trigger fires
/// and shipping the counter makes the skipped accounting observable.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    let mut v = vec![Op::PushBack];
    if !spec.ops.contains(&Op::PopFront) {
        v.push(Op::PopFront);
    }
    if !spec.ops.contains(&Op::Balances) {
        v.push(Op::Balances);
    }
    for o in spec.ops {
        if !v.contains(&o) {
            v.push(o);
        }
    }
    v
}

/// The canonical scenario: dozens of pushes with no pops, so the queue is
/// deep in inbox-only state where a wrong refill rule would show on the
/// very first pop.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical two-stack-queue scenario");
}

fn fresh_queue() -> TwoStackQueue {
    TwoStackQueue::new()
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01E8;

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
    for _ in 0..8 {
        out.push(ExampleCase {
            warmup: rng.below(40) + 2,
        });
    }
    out
}

const NX_MUL: u64 = 6364136223846793005;
const NX_ADD: u64 = 1442695040888963407;

fn drive_init(warmup: u64) -> u64 {
    0x05CA_CAFEu64 ^ warmup.wrapping_mul(0x9E37)
}

/// Drives `warmup` random pushes into a fresh queue.
fn driven_queue(warmup: u64) -> TwoStackQueue {
    let mut q = fresh_queue();
    let mut st = drive_init(warmup);
    for _ in 0..warmup {
        let v = (st >> 33) % 97;
        q.push_back(v);
        st = st.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    }
    q
}

/// The probe-continuation state after the drive loop (one advance per push).
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

fn opt_fmt(v: Option<u64>) -> String {
    v.map_or_else(|| "None".to_string(), |x| format!("Some({x})"))
}

// ---- emitted-source fragments -----------------------------------------------

pub const STRUCT_SRC: &str = "#[derive(Clone)]\npub struct Fifo {\n    inbox: Vec<u64>,\n    outbox: Vec<u64>,\n    balances: u64,\n}\n";

pub const QUEUE_NEW_SRC: &str = "impl Fifo {\n    pub fn new() -> Self {\n        Fifo {\n            inbox: Vec::new(),\n            outbox: Vec::new(),\n            balances: 0,\n        }\n    }\n}\n\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::QLen => &["(self.inbox.len() + self.outbox.len()) as u64"],
        Op::PushBack => &[
            "self.inbox.push(value);",
            "(self.inbox.len() + self.outbox.len()) as u64",
        ],
        Op::PopFront => &[
            "if self.inbox.is_empty() && self.outbox.is_empty() {",
            "    return None;",
            "}",
            "if self.outbox.is_empty() {",
            "    while let Some(v) = self.inbox.pop() {",
            "        self.outbox.push(v);",
            "    }",
            "    self.balances += 1;",
            "}",
            "self.outbox.pop()",
        ],
        Op::FrontPeek => &[
            "if let Some(top) = self.outbox.last() {",
            "    return Some(*top);",
            "}",
            "self.inbox.first().copied()",
        ],
        Op::Balances => &["self.balances"],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen("pub struct Fifo {", "pub struct FifoRef {", 1);
    s.push_str(
        &QUEUE_NEW_SRC
            .replace("impl Fifo {", "impl FifoRef {")
            .replace("Fifo {\n", "FifoRef {\n"),
    );
    s.push_str("impl FifoRef {\n");
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
        let q = driven_queue(ex.warmup);
        s.push_str(&format!(
            "//! ex{i}: {w} random pushes -> queue holds {n} values\n",
            i = i,
            w = ex.warmup,
            n = q.q_len(),
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested amortized-queue operations over two\n\
          //! internal stacks: pushes land on the inbox stack newest-on-top,\n\
          //! pops are served from the outbox stack oldest-first, and the\n\
          //! outbox is refilled by draining the whole inbox in reverse\n\
          //! exactly once per refill - each drain counted once. The hidden\n\
          //! tests drive thousands of interleaved operations and compare\n\
          //! every returned value.\n\
          //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(QUEUE_NEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested amortized-queue operations with exactly maintained bookkeeping.\n\nRequirements:\n- `Fifo::new()` starts an empty queue with a zero rebalance count; the constructor is given.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- The inbox stack receives every pushed value newest-on-top; the outbox stack serves the oldest value from its top.\n- When a pop finds the outbox empty, the whole inbox is drained onto it in reverse and that refill counts as exactly one rebalance; a rebalance never happens at any other time.\n- `front_peek` never mutates or triggers a rebalance; `pop_front` and `front_peek` answer None only when both stacks are empty.\n- `push_back` answers the fresh total length across both stacks; queries never mutate the queue; no floating point; no unsafe code; standard library only.\n\nSignatures:\n```rust\n");
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
    let mut s = String::from("use task::Fifo;\n\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n");
    for (i, ex) in examples.iter().enumerate() {
        let h = driven_queue(ex.warmup);
        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let mut drive = Fifo::new();\n    let mut st: u64 = {init};\n    for _ in 0..{w} {{\n        drive.push_back((st >> 33) % 97);\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    }}\n",
            i = i,
            w = ex.warmup,
            init = drive_init(ex.warmup)
        ));
        s.push_str(&format!(
            "    let mut ps: u64 = {};\n",
            drive_final_state(ex.warmup)
        ));
        let mut ps = drive_final_state(ex.warmup);
        for &op in &spec.ops {
            match op {
                Op::QLen => {
                    s.push_str(&format!("    assert_eq!(drive.q_len(), {});\n", h.q_len()));
                }
                Op::PushBack => {
                    let v = nx(&mut ps) % 97;
                    let want = h.clone().push_back(v);
                    s.push_str(&format!(
                        "    let mut r = drive.clone();\n    let v = nx(&mut ps) % 97;\n    assert_eq!(r.push_back(v), {want});\n",
                        want = want
                    ));
                }
                Op::PopFront => {
                    let want = h.clone().pop_front();
                    s.push_str(&format!(
                        "    let mut r = drive.clone();\n    assert_eq!(r.pop_front(), {want});\n",
                        want = opt_fmt(want)
                    ));
                }
                Op::FrontPeek => {
                    let want = h.front_peek();
                    s.push_str(&format!(
                        "    let r = drive.clone();\n    assert_eq!(r.front_peek(), {want});\n    assert_eq!(drive.front_peek(), {want});\n",
                        want = opt_fmt(want)
                    ));
                }
                Op::Balances => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.balances(), {});\n",
                        h.balances()
                    ));
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Scripted probe: interleaved traffic must come out in fifo order even
    // when pushes resume while the outbox still holds served values.
    if spec.ops.contains(&Op::PushBack) && spec.ops.contains(&Op::PopFront) {
        s.push_str("#[test]\nfn scripted_interleaving_keeps_fifo_order() {\n    let mut r = Fifo::new();\n    r.push_back(1);\n    r.push_back(2);\n    r.push_back(3);\n    assert_eq!(r.pop_front(), Some(1));\n    r.push_back(4);\n    r.push_back(5);\n    assert_eq!(r.pop_front(), Some(2));\n    assert_eq!(r.pop_front(), Some(3));\n    assert_eq!(r.pop_front(), Some(4));\n    assert_eq!(r.pop_front(), Some(5));\n    assert_eq!(r.pop_front(), None);\n}\n");
    }
    // Scripted probe: pushing alone never triggers a rebalance.
    if spec.ops.contains(&Op::PushBack) && spec.ops.contains(&Op::QLen) {
        s.push_str("#[test]\nfn scripted_push_answers_the_fresh_length() {\n    let mut r = Fifo::new();\n    for i in 1..=5u64 {\n        assert_eq!(r.push_back(i * 11), i);\n        assert_eq!(r.q_len(), i);\n    }\n}\n");
    }
    // Scripted probe: peeks are stable and never disturb what a pop serves.
    if spec.ops.contains(&Op::PushBack) && spec.ops.contains(&Op::FrontPeek) {
        s.push_str("#[test]\nfn scripted_peek_never_reorders() {\n    let mut r = Fifo::new();\n    r.push_back(7);\n    r.push_back(8);\n    r.push_back(9);\n    assert_eq!(r.front_peek(), Some(7));\n    assert_eq!(r.front_peek(), Some(7));\n    r.push_back(10);\n    assert_eq!(r.front_peek(), Some(7));\n}\n");
    }
    // Fill soak: eight hundred pushes must leave the rebalance tally pinned
    // at zero - a queue that balances during pushes breaks amortization.
    if spec.ops.contains(&Op::PushBack) && spec.ops.contains(&Op::Balances) {
        s.push_str("#[test]\nfn fill_soak_pushes_never_rebalance() {\n    let mut r = Fifo::new();\n    let mut st: u64 = 0x5EED_0000_0000_01EA;\n    for _ in 0..800u64 {\n        r.push_back((st >> 33) % 97);\n        assert_eq!(r.balances(), 0);\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    }\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::Fifo;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    let ops = effective_ops(spec);
    s.push_str("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {\n    let mut cand = Fifo::new();\n    let mut refr = FifoRef::new();\n");
    if ops.contains(&Op::PopFront) {
        s.push_str("    assert_eq!(cand.pop_front(), refr.ref_pop_front());\n");
    }
    if ops.contains(&Op::FrontPeek) {
        s.push_str("    assert_eq!(cand.front_peek(), refr.ref_front_peek());\n");
    }
    if ops.contains(&Op::QLen) {
        s.push_str("    assert_eq!(cand.q_len(), refr.ref_q_len());\n");
    }
    if ops.contains(&Op::Balances) {
        s.push_str("    assert_eq!(cand.balances(), refr.ref_balances());\n");
    }
    if ops.contains(&Op::PushBack) {
        let mut pre: u64 = 0x05CA_D1FF;
        for _ in 0..12u64 {
            let v = nx(&mut pre) % 97;
            s.push_str(&format!(
                "    assert_eq!(cand.push_back({v}), refr.ref_push_back({v}));\n"
            ));
        }
    }
    let arm_count = ops.len();
    s.push_str(&format!("    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_01E8;\n    for _ in 0..3000 {{\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in ops.iter().enumerate() {
        let body = match op {
            Op::QLen => "assert_eq!(cand.q_len(), refr.ref_q_len());".to_string(),
            Op::PushBack => {
                "let v = nx(&mut state) % 97;\n            assert_eq!(cand.push_back(v), refr.ref_push_back(v));".to_string()
            }
            Op::PopFront => "assert_eq!(cand.pop_front(), refr.ref_pop_front());".to_string(),
            Op::FrontPeek => {
                "assert_eq!(cand.front_peek(), refr.ref_front_peek());".to_string()
            }
            Op::Balances => "assert_eq!(cand.balances(), refr.ref_balances());".to_string(),
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
    s.push_str(QUEUE_NEW_SRC);
    s.push_str("impl Fifo {\n");
    for &op in &ops {
        let body = match op {
            Op::PopFront | Op::FrontPeek => "None",
            _ => "0",
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s.push_str("}\n");
    s
}

/// The plausible cheat: pops serve the same values by lifting straight off
/// the inbox when the outbox runs dry - every returned value matches, yet
/// the rebalance tally stays frozen, so the always-shipped `balances`
/// probe exposes the missing accounting.
pub fn pop_from_inbox_src(_spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(QUEUE_NEW_SRC);
    s.push_str("impl Fifo {\n");
    for &op in &OP_ALL {
        match op {
            Op::PopFront => {
                let body = &[
                    "if self.inbox.is_empty() && self.outbox.is_empty() {",
                    "    return None;",
                    "}",
                    "if self.outbox.is_empty() {",
                    "    return self.inbox.pop();",
                    "}",
                    "self.outbox.pop()",
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

pub struct TwoStackQueueFamily;

impl Generator for TwoStackQueueFamily {
    fn id(&self) -> &'static str {
        "two-stack-queue"
    }

    fn category(&self) -> &'static str {
        "amortized-queue"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("two-stack-queue", seed);
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
            id: format!("two-stack-queue/{seed:016x}"),
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
        s.push_str(QUEUE_NEW_SRC);
        s.push_str("impl Fifo {\n");
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
            ("pop-from-inbox".to_string(), pop_from_inbox_src(spec)),
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
        let a = TwoStackQueueFamily.generate(55);
        let b = TwoStackQueueFamily.generate(55);
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
            let q = driven_queue(warmup);
            assert_eq!(q.q_len(), warmup);
            assert_eq!(q.balances(), 0);
            assert_eq!(q.front_peek(), Some((drive_init(warmup) >> 33) % 97));
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let q = driven_queue(ex.warmup);
                assert_eq!(q.q_len(), ex.warmup);
                assert_eq!(q.balances(), 0);
                assert!(ex.warmup >= 2);
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct FifoRef"));
            assert!(
                src.matches("FifoRef {").count() >= 2,
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
            let canary = mint_canary("two-stack-queue", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in [".rev(", "swap(", "rotate_("] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("rebalance"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("FifoRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soaks() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            let fifo_gate = spec.ops.contains(&Op::PushBack) && spec.ops.contains(&Op::PopFront);
            let qlen_gate = spec.ops.contains(&Op::PushBack) && spec.ops.contains(&Op::QLen);
            let peek_gate = spec.ops.contains(&Op::PushBack) && spec.ops.contains(&Op::FrontPeek);
            let bal_gate = spec.ops.contains(&Op::PushBack) && spec.ops.contains(&Op::Balances);
            assert_eq!(
                behavior.contains("scripted_interleaving_keeps_fifo_order"),
                fifo_gate,
                "seed {seed}: fifo script misaligned"
            );
            assert_eq!(
                behavior.contains("scripted_push_answers_the_fresh_length"),
                qlen_gate,
                "seed {seed}: length script misaligned"
            );
            assert_eq!(
                behavior.contains("scripted_peek_never_reorders"),
                peek_gate,
                "seed {seed}: peek script misaligned"
            );
            assert_eq!(
                behavior.contains("fill_soak_pushes_never_rebalance"),
                bal_gate,
                "seed {seed}: balance soak misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_queue_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let cheat = pop_from_inbox_src(spec);
        assert!(!cz.contains("todo!()"));
        assert!(cheat.contains("fn pop_front"));
        let us = cheat.find("fn pop_front").unwrap();
        let ue = us + cheat[us..].find("\n}\n").unwrap();
        let ub = &cheat[us..ue];
        assert!(
            ub.contains("self.inbox.pop()"),
            "cheat must still serve the same values"
        );
        assert!(
            !ub.contains("balances += 1"),
            "the skipped tally is the bug"
        );
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("two-stack-queue", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
