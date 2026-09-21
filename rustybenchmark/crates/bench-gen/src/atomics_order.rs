//! The `atomics-order` family (category `atomic-semantics`) — atomic
//! read-modify-write puzzles over one shared counter.
//!
//! Every query mirrors an `AtomicU64` operation: it returns the value the
//! cell held BEFORE the update and leaves the updated state behind, so the
//! skill is knowing which fetch operation produces which
//! previous-value/after-state pair. Hidden tests additionally spawn real
//! threads that contend on one shared counter; every assertion there is
//! interleaving-invariant (unique ticket multisets, exact bit unions,
//! value-chain permutations, even-parity cancels), so verdicts stay
//! deterministic while genuinely exercising atomicity. Memory-ordering
//! constants cannot be distinguished by any deterministic test, so this
//! family tests fetch semantics and atomicity honestly rather than
//! pretending otherwise.
//!
//! The seed picks which two of five query ops are required:
//! `fetch_add`, `fetch_or`, `fetch_xor`, `swap`, `negate`.
//! C(5,2) = **10 distinct skills**, above the diversity floor; op names
//! mirror the real `AtomicU64` methods they exercise.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! live on [`AtomicsInstance`] over a plain `Cell<u64>` so they are
//! deterministic off-thread; the emitted reference spells the identical
//! arithmetic against a real `AtomicU64`. The differential fuzzes 3000
//! random sequential steps AND two contending thread teams — one driving
//! the candidate, one the embedded reference — comparing them on
//! invariants that hold under any interleaving.
//!
//! Trivial baselines: `const-zero` (answers zero everywhere) and
//! `returns-new` (computes the right new state but hands back the AFTER
//! value instead of the previous one — the classic misuse, and under
//! contention also a lost-update machine because its load/store RMW is
//! not atomic).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::cell::Cell;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    FetchAdd,
    FetchOr,
    FetchXor,
    Swap,
    Negate,
}

pub const OP_ALL: [Op; 5] = [
    Op::FetchAdd,
    Op::FetchOr,
    Op::FetchXor,
    Op::Swap,
    Op::Negate,
];

impl Op {
    /// The required function name — mirrors the real atomic method.
    pub fn name(self) -> &'static str {
        match self {
            Op::FetchAdd => "fetch_add",
            Op::FetchOr => "fetch_or",
            Op::FetchXor => "fetch_xor",
            Op::Swap => "swap",
            Op::Negate => "negate",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::FetchAdd => "adds n and hands back the previous count",
            Op::FetchOr => "sets exactly the masked bits and hands back the previous value",
            Op::FetchXor => "flips exactly the masked bits and hands back the previous value",
            Op::Swap => "stores v verbatim and hands back the previous value",
            Op::Negate => "stores the two's-complement opposite and hands back the previous value",
        }
    }

    pub fn extra_arg(self) -> &'static str {
        match self {
            Op::FetchAdd => ", n: u64",
            Op::FetchOr | Op::FetchXor => ", mask: u64",
            Op::Swap => ", v: u64",
            Op::Negate => "",
        }
    }

    pub fn ret(self) -> &'static str {
        "u64"
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

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

// ---- native mirror (the answer; identical shape to the emitted code) ------

/// One shared cell mirroring atomic state. Runs the same arithmetic as
/// the emitted `AtomicU64` helpers, deterministically and off-thread.
pub struct AtomicsInstance(pub Cell<u64>);

impl AtomicsInstance {
    /// `fetch_add`: hands back the previous counter and stores prev + n.
    pub fn fetch_add(&self, n: u64) -> u64 {
        let prev = self.0.get();
        self.0.set(prev.wrapping_add(n));
        prev
    }

    /// `fetch_or`: hands back the previous value and stores prev | mask.
    pub fn fetch_or(&self, mask: u64) -> u64 {
        let prev = self.0.get();
        self.0.set(prev | mask);
        prev
    }

    /// `fetch_xor`: hands back the previous value and stores prev ^ mask;
    /// xoring the cell's own contents clears it entirely.
    pub fn fetch_xor(&self, mask: u64) -> u64 {
        let prev = self.0.get();
        self.0.set(prev ^ mask);
        prev
    }

    /// `swap`: hands back the previous value and stores the replacement
    /// verbatim — the one fetch operation that ignores the old contents.
    pub fn swap(&self, v: u64) -> u64 {
        let prev = self.0.get();
        self.0.set(v);
        prev
    }

    /// Arithmetic negation via `wrapping_neg`: hands back the previous
    /// value and stores its two's-complement opposite (zero is its own).
    pub fn negate(&self) -> u64 {
        let prev = self.0.get();
        self.0.set(prev.wrapping_neg());
        prev
    }
}

/// Applies `op` to a fresh mirror cell seeded with `(v0, arg)` and returns
/// the (previous, after-state) pair the emitted atomic must produce.
fn eval_pair(op: Op, v0: u64, arg: u64) -> (u64, u64) {
    let inst = AtomicsInstance(Cell::new(v0));
    let prev = match op {
        Op::FetchAdd => inst.fetch_add(arg),
        Op::FetchOr => inst.fetch_or(arg),
        Op::FetchXor => inst.fetch_xor(arg),
        Op::Swap => inst.swap(arg),
        Op::Negate => inst.negate(),
    };
    (prev, inst.0.get())
}

// ---- canonical case --------------------------------------------------------

const CANONICAL_SEED: u64 = 0xA70C_FA11;

/// A starting value and operand whose four distinct after-states all miss
/// the start value, so every cheat answering "the new value" or a constant
/// is wrong on the canonical case for every operation.
pub fn canonical(seed: u64) -> (u64, u64) {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let v0 = 1 + rng.below(15);
        let arg = 1 + rng.below(15);
        if v0 == arg {
            continue;
        }
        let states = [
            eval_pair(Op::FetchAdd, v0, arg).1,
            eval_pair(Op::FetchOr, v0, arg).1,
            eval_pair(Op::FetchXor, v0, arg).1,
            eval_pair(Op::Negate, v0, arg).1,
            eval_pair(Op::Swap, v0, arg).1,
        ];
        let mut ok = true;
        for i in 0..states.len() {
            if states[i] == v0 {
                ok = false;
            }
            for j in (i + 1)..states.len() {
                if states[i] == states[j] {
                    ok = false;
                }
            }
        }
        if ok {
            return (v0, arg);
        }
    }
    unreachable!("canonical atomics case");
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub v0: u64,
    pub arg: u64,
    pub results: Vec<(Op, u64, u64)>,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0190;

fn case(v0: u64, arg: u64) -> ExampleCase {
    ExampleCase {
        v0,
        arg,
        results: OP_ALL
            .iter()
            .map(|&op| {
                let (prev, after) = eval_pair(op, v0, arg);
                (op, prev, after)
            })
            .collect(),
    }
}

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![case(canonical(seed).0, canonical(seed).1)];
    out.push(case(0, 3));
    out.push(case(u64::MAX, 1));
    for _ in 0..3 {
        let mut rng = Rng::new(seed ^ EXAMPLES_SEED.wrapping_add(out.len() as u64));
        out.push(case(rng.below(20), rng.below(20)));
    }
    out
}

// ---- emitted-source fragments -----------------------------------------------

pub fn op_sig_src(op: Op) -> String {
    format!(
        "pub fn {}(cell: &AtomicU64{}) -> u64",
        op.name(),
        op.extra_arg()
    )
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::FetchAdd => &["cell.fetch_add(n, Ordering::SeqCst)"],
        Op::FetchOr => &["cell.fetch_or(mask, Ordering::SeqCst)"],
        Op::FetchXor => &["cell.fetch_xor(mask, Ordering::SeqCst)"],
        Op::Swap => &["cell.swap(v, Ordering::SeqCst)"],
        Op::Negate => &[
            "let prev = cell.load(Ordering::SeqCst);",
            "cell.store(prev.wrapping_neg(), Ordering::SeqCst);",
            "prev",
        ],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

const USE_LINE: &str = "use std::sync::atomic::{AtomicU64, Ordering};\n\n";

pub fn reference_src(spec: Spec) -> String {
    let mut s = String::from(USE_LINE);
    for &op in &spec.ops {
        s.push_str(&op_fn_src(op));
    }
    s
}

/// The call expression for `op` against a binding named `cell`, with the
/// operation's extra argument spelled at the call site.
pub fn call_src(op: Op) -> String {
    let args = match op {
        Op::FetchAdd => "cell, n".to_string(),
        Op::FetchOr | Op::FetchXor => "cell, mask".to_string(),
        Op::Swap => "cell, v".to_string(),
        Op::Negate => "cell".to_string(),
    };
    format!("{}({})", op.name(), args)
}

pub fn worked_examples_prose(examples: &[ExampleCase]) -> String {
    let mut s = String::new();
    for (i, ex) in examples.iter().enumerate() {
        s.push_str(&format!(
            "//! ex{i} starting value {v} operand {a}\n",
            i = i,
            v = ex.v0,
            a = ex.arg
        ));
        for (op, prev, after) in &ex.results {
            s.push_str(&format!(
                "//!   {name}: previous {p}, after {a2}\n",
                name = op.name(),
                p = prev,
                a2 = after
            ));
        }
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Fill in each function so it performs its atomic update on the\n\
         //! shared counter and hands back the value the counter held BEFORE\n\
         //! the update. The hidden tests also spawn real threads that\n\
         //! contend on one counter; your updates must survive that\n\
         //! contention without losing any.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(USE_LINE);
    for &op in &spec.ops {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested atomic read-modify-write helpers over one shared AtomicU64.\n\nRequirements:\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("- Every helper returns the value the counter held BEFORE the update.\n");
    s.push_str("- The hidden tests spawn threads that contend on one counter; every update must survive (no lost updates).\n\nConstraints:\n- Keep the exact function signatures.\n- Use `std::sync::atomic::AtomicU64` operations; no unsafe code.\n\nSignatures:\n```rust\n");
    for &op in &spec.ops {
        s.push_str(&op_sig_src(op));
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

/// The call expression for `op` against a caller-chosen binding, spelled
/// with the operation's parameter names (`operand`) so emitted tests can
/// pass a locally-bound argument.
fn call_with_arg_src(op: Op, binding: &str) -> String {
    match op {
        Op::FetchAdd => format!("fetch_add({}, operand)", binding),
        Op::FetchOr => format!("fetch_or({}, operand)", binding),
        Op::FetchXor => format!("fetch_xor({}, operand)", binding),
        Op::Swap => format!("swap({}, operand)", binding),
        Op::Negate => format!("negate({})", binding),
    }
}

/// One contending behavior-test block for `op`: real threads hammer ONE
/// shared counter; every assertion is interleaving-invariant.
fn behavior_contention_block(op: Op) -> String {
    match op {
        Op::FetchAdd => "\
#[test]
fn concurrent_fetch_add_issues_unique_tickets() {
    let cell = std::sync::Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let c = std::sync::Arc::clone(&cell);
        handles.push(std::thread::spawn(move || fetch_add(&c, 1)));
    }
    let mut tickets: Vec<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    tickets.sort();
    assert_eq!(tickets, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(cell.load(Ordering::SeqCst), 8);
}
"
        .to_string(),
        Op::FetchOr => "\
#[test]
fn concurrent_disjoint_ors_cover_every_bit() {
    let cell = std::sync::Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for i in 0..8u64 {
        let c = std::sync::Arc::clone(&cell);
        handles.push(std::thread::spawn(move || fetch_or(&c, 1u64 << i)));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(cell.load(Ordering::SeqCst), 0xFF);
}
"
        .to_string(),
        Op::FetchXor => "\
#[test]
fn concurrent_double_flips_return_to_start() {
    let cell = std::sync::Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for i in 0..8u64 {
        let c = std::sync::Arc::clone(&cell);
        handles.push(std::thread::spawn(move || {
            fetch_xor(&c, 1u64 << i);
            fetch_xor(&c, 1u64 << i);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // Every bit was flipped an even number of times, so any lost update
    // leaves its bit stuck set: the final state must be exactly the start.
    assert_eq!(cell.load(Ordering::SeqCst), 0);
}
"
        .to_string(),
        Op::Swap => "\
#[test]
fn concurrent_swaps_preserve_the_value_chain() {
    let cell = std::sync::Arc::new(AtomicU64::new(7));
    let mut handles = Vec::new();
    for i in 0..8u64 {
        let c = std::sync::Arc::clone(&cell);
        handles.push(std::thread::spawn(move || swap(&c, 100 + i)));
    }
    let mut observed: Vec<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    observed.push(cell.load(Ordering::SeqCst));
    // Under atomicity the cell's contents form one chain: the start value
    // read out by whichever swap lands first, then every stored value read
    // out exactly once by the swap that replaces it, with the last write
    // surviving as the final state. So the multiset of returned values
    // together with the final state is EXACTLY the start plus the writes.
    let mut expected: Vec<u64> = (100u64..108).collect();
    expected.push(7);
    observed.sort();
    expected.sort();
    assert_eq!(observed, expected);
}
"
        .to_string(),
        Op::Negate => "\
#[test]
fn concurrent_negates_cancel_in_pairs() {
    let cell = std::sync::Arc::new(AtomicU64::new(5));
    let flip = 5u64.wrapping_neg();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let c = std::sync::Arc::clone(&cell);
        handles.push(std::thread::spawn(move || [negate(&c), negate(&c)]));
    }
    let returns: Vec<u64> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    // Negation is an involution, so sixteen contending negates compose
    // back to the start under ANY interleaving; every observation must be
    // one of its two fixed alternating states.
    for r in returns {
        assert!(r == 5 || r == flip, \"impossible negate return {r}\");
    }
    assert_eq!(cell.load(Ordering::SeqCst), 5);
}
"
        .to_string(),
    }
}

/// Contention probes appended to the behavior target when the selected ops
/// include the operations they exercise. Every assertion inside is
/// interleaving-invariant, so the verdicts stay deterministic while
/// genuinely spawning and joining threads.
fn contention_tests_src(spec: Spec) -> String {
    let mut s = String::new();
    for &op in &spec.ops {
        s.push('\n');
        s.push_str(&behavior_contention_block(op));
    }
    s
}

pub fn behavior_test_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let names: Vec<&str> = spec.ops.iter().map(|o| o.name()).collect();
    let mut s = format!(
        "use std::sync::atomic::{{AtomicU64, Ordering}};\nuse task::{{{}}};\n\n",
        names.join(", ")
    );
    for (i, ex) in examples.iter().enumerate() {
        for &(op, prev, after) in &ex.results {
            if !spec.ops.contains(&op) {
                continue;
            }
            let arg_bind = match op {
                Op::Negate => String::new(),
                _ => format!("let operand = {}u64;\n    ", ex.arg),
            };
            let call_args = match op {
                Op::Negate => "&cell".to_string(),
                _ => "&cell, operand".to_string(),
            };
            s.push_str(&format!(
                "#[test]\nfn ex{i}_{name}() {{\n    let cell = AtomicU64::new({v0});\n    {arg_bind}let got = {name}({call});\n    assert_eq!(got, {p});\n    assert_eq!(cell.load(Ordering::SeqCst), {a});\n}}\n\n",
                i = i,
                name = op.name(),
                v0 = ex.v0,
                arg_bind = arg_bind,
                call = call_args,
                p = prev,
                a = after,
            ));
        }
    }
    s.push_str(&contention_tests_src(spec));
    s
}

/// The reference implementation pasted into the differential target under
/// `ref_*` names, one function per selected op.
fn differential_reference_src(spec: Spec) -> String {
    let mut s = String::new();
    for &op in &spec.ops {
        let body = op_fn_src(op);
        let renamed = body.replacen(
            &format!("pub fn {}(", op.name()),
            &format!("fn ref_{}(", op.name()),
            1,
        );
        assert!(renamed != body, "rename failed");
        s.push_str(&renamed);
    }
    s
}

/// The per-roll sequential arms: each branch pairs the candidate call on
/// cell `a` with the reference call on cell `b`, fully specialized so the
/// emitted source never mentions the generator-side spec.
fn sequential_arms_src(spec: Spec) -> String {
    let arm = |op: Op| -> String {
        format!(
            "({}, {})",
            call_with_arg_src(op, "&a"),
            call_with_arg_src(op, "&b")
                .replacen("fetch_", "ref_fetch_", 1)
                .replacen("swap(", "ref_swap(", 1)
                .replacen("negate(", "ref_negate(", 1)
        )
    };
    format!(
        "let (got, want) = if pick == 0 {{\n        {}\n    }} else {{\n        {}\n    }};",
        arm(spec.ops[0]),
        arm(spec.ops[1])
    )
}

/// One contending differential phase for `op`: six threads drive the
/// candidate counter, six more drive the reference counter through the
/// SAME workload shape, and both teams are held to identical
/// interleaving-invariant outcomes.
fn differential_contention_block(op: Op) -> String {
    match op {
        Op::FetchAdd => "\
    let cand = std::sync::Arc::new(AtomicU64::new(0));
    let refr = std::sync::Arc::new(AtomicU64::new(0));
    let mut hc = Vec::new();
    let mut hr = Vec::new();
    for _ in 0..6 {
        let c = std::sync::Arc::clone(&cand);
        let r = std::sync::Arc::clone(&refr);
        hc.push(std::thread::spawn(move || {
            (0..3).map(|_| fetch_add(&c, 1)).collect::<Vec<u64>>()
        }));
        hr.push(std::thread::spawn(move || {
            (0..3).map(|_| ref_fetch_add(&r, 1)).collect::<Vec<u64>>()
        }));
    }
    let mut tc: Vec<u64> = hc.into_iter().flat_map(|h| h.join().unwrap()).collect();
    let mut tr: Vec<u64> = hr.into_iter().flat_map(|h| h.join().unwrap()).collect();
    tc.sort();
    tr.sort();
    assert_eq!(tc, tr, \"ticket multisets diverged\");
    assert_eq!(tc.first().copied(), Some(0));
    assert_eq!(tc.len(), 18);
    assert_eq!(cand.load(Ordering::SeqCst), 18);
    assert_eq!(refr.load(Ordering::SeqCst), 18);
"
        .to_string(),
        Op::FetchOr => "\
    let cand = std::sync::Arc::new(AtomicU64::new(0));
    let refr = std::sync::Arc::new(AtomicU64::new(0));
    let mut hc = Vec::new();
    let mut hr = Vec::new();
    for i in 0..6u64 {
        let c = std::sync::Arc::clone(&cand);
        let r = std::sync::Arc::clone(&refr);
        hc.push(std::thread::spawn(move || fetch_or(&c, 1u64 << i)));
        hr.push(std::thread::spawn(move || ref_fetch_or(&r, 1u64 << i)));
    }
    for h in hc {
        h.join().unwrap();
    }
    for h in hr {
        h.join().unwrap();
    }
    assert_eq!(cand.load(Ordering::SeqCst), 0x3F);
    assert_eq!(refr.load(Ordering::SeqCst), 0x3F);
"
        .to_string(),
        Op::FetchXor => "\
    let cand = std::sync::Arc::new(AtomicU64::new(9));
    let refr = std::sync::Arc::new(AtomicU64::new(9));
    let mut hc = Vec::new();
    let mut hr = Vec::new();
    for i in 0..6u64 {
        let c = std::sync::Arc::clone(&cand);
        let r = std::sync::Arc::clone(&refr);
        hc.push(std::thread::spawn(move || {
            fetch_xor(&c, 1u64 << i);
            fetch_xor(&c, 1u64 << i);
        }));
        hr.push(std::thread::spawn(move || {
            ref_fetch_xor(&r, 1u64 << i);
            ref_fetch_xor(&r, 1u64 << i);
        }));
    }
    for h in hc {
        h.join().unwrap();
    }
    for h in hr {
        h.join().unwrap();
    }
    assert_eq!(cand.load(Ordering::SeqCst), 9, \"candidate lost a flip\");
    assert_eq!(refr.load(Ordering::SeqCst), 9, \"reference lost a flip\");
"
        .to_string(),
        Op::Swap => "\
    let cand = std::sync::Arc::new(AtomicU64::new(7));
    let refr = std::sync::Arc::new(AtomicU64::new(7));
    let mut hc = Vec::new();
    let mut hr = Vec::new();
    for i in 0..6u64 {
        let c = std::sync::Arc::clone(&cand);
        let r = std::sync::Arc::clone(&refr);
        hc.push(std::thread::spawn(move || swap(&c, 100 + i)));
        hr.push(std::thread::spawn(move || ref_swap(&r, 100 + i)));
    }
    let mut oc: Vec<u64> = hc.into_iter().map(|h| h.join().unwrap()).collect();
    let mut orr: Vec<u64> = hr.into_iter().map(|h| h.join().unwrap()).collect();
    oc.push(cand.load(Ordering::SeqCst));
    orr.push(refr.load(Ordering::SeqCst));
    let mut want: Vec<u64> = (100u64..106).collect();
    want.push(7);
    oc.sort();
    orr.sort();
    want.sort();
    assert_eq!(oc, want, \"candidate broke the value chain\");
    assert_eq!(orr, want, \"reference broke the value chain\");
"
        .to_string(),
        Op::Negate => "\
    let cand = std::sync::Arc::new(AtomicU64::new(5));
    let refr = std::sync::Arc::new(AtomicU64::new(5));
    let flip = 5u64.wrapping_neg();
    let mut hc = Vec::new();
    let mut hr = Vec::new();
    for _ in 0..6 {
        let c = std::sync::Arc::clone(&cand);
        let r = std::sync::Arc::clone(&refr);
        hc.push(std::thread::spawn(move || [negate(&c), negate(&c)]));
        hr.push(std::thread::spawn(move || [ref_negate(&r), ref_negate(&r)]));
    }
    let rc: Vec<u64> = hc.into_iter().flat_map(|h| h.join().unwrap()).collect();
    let rr: Vec<u64> = hr.into_iter().flat_map(|h| h.join().unwrap()).collect();
    for x in rc.iter().chain(rr.iter()) {
        assert!(*x == 5 || *x == flip, \"impossible negate return {x}\");
    }
    assert_eq!(rc.len(), 12);
    assert_eq!(rr.len(), 12);
    assert_eq!(cand.load(Ordering::SeqCst), 5, \"candidate parity broke\");
    assert_eq!(refr.load(Ordering::SeqCst), 5, \"reference parity broke\");
"
        .to_string(),
    }
}

pub fn differential_test_src(spec: Spec) -> String {
    let names: Vec<&str> = spec.ops.iter().map(|o| o.name()).collect();
    let mut s = format!(
        "use std::sync::atomic::{{AtomicU64, Ordering}};\nuse task::{{{}}};\n\n",
        names.join(", ")
    );
    s.push_str(&differential_reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    s.push_str("\n#[test]\nfn differential_vs_reference() {\n    let mut state: u64 = 0xE7EE_ED00_0000_0192;\n    for _ in 0..3000 {\n        let start = nx(&mut state) % 40;\n        let roll = (nx(&mut state) % 5) as usize;\n        let operand = nx(&mut state) % 20;\n        let a = AtomicU64::new(start);\n        let b = AtomicU64::new(start);\n        let pick = roll % 2;\n        ");
    s.push_str(&sequential_arms_src(spec));
    s.push_str("\n        assert_eq!(got, want);\n        assert_eq!(a.load(Ordering::SeqCst), b.load(Ordering::SeqCst));\n    }\n}\n");
    s.push_str("\n#[test]\nfn differential_contention_tracks_reference_under_threads() {\n");
    s.push_str(&format!(
        "    // Phase one: contending {}.\n",
        spec.ops[0].name()
    ));
    s.push_str(&differential_contention_block(spec.ops[0]));
    s.push_str(&format!(
        "    // Phase two: contending {}.\n",
        spec.ops[1].name()
    ));
    s.push_str(&differential_contention_block(spec.ops[1]));
    s.push_str("}\n");
    s
}

pub fn const_zero_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    s.push_str("use std::sync::atomic::{AtomicU64, Ordering};\n\n");
    for &op in &spec.ops {
        let args = match op.extra_arg() {
            "" => "let _ = cell;".to_string(),
            extra => {
                let names: Vec<String> = extra
                    .split(',')
                    .map(|p| p.trim())
                    .filter(|p| !p.is_empty())
                    .map(|p| p.split(':').next().unwrap().trim().to_string())
                    .collect();
                format!("let _ = (cell, {});", names.join(", "))
            }
        };
        s.push_str(&format!("{} {{\n    {}\n    0\n}}\n", op_sig_src(op), args));
    }
    s
}

/// The classic misuse: computing the right new value but handing back the
/// AFTER state instead of the previous one. Wrong whenever before != after,
/// and its non-atomic load/store RMW loses updates under contention.
pub fn returns_new_src(spec: Spec) -> String {
    let mut s = String::from(USE_LINE);
    for &op in &spec.ops {
        let body: &[&str] = match op {
            Op::FetchAdd => &[
                "let new = cell.load(Ordering::SeqCst).wrapping_add(n);",
                "cell.store(new, Ordering::SeqCst);",
                "new",
            ],
            Op::FetchOr => &[
                "let new = cell.load(Ordering::SeqCst) | mask;",
                "cell.store(new, Ordering::SeqCst);",
                "new",
            ],
            Op::FetchXor => &[
                "let new = cell.load(Ordering::SeqCst) ^ mask;",
                "cell.store(new, Ordering::SeqCst);",
                "new",
            ],
            Op::Swap => &["cell.store(v, Ordering::SeqCst);", "v"],
            Op::Negate => &[
                "let new = cell.load(Ordering::SeqCst).wrapping_neg();",
                "cell.store(new, Ordering::SeqCst);",
                "new",
            ],
        };
        s.push_str(&format!(
            "{} {{\n    {}\n}}\n",
            op_sig_src(op),
            body.join("\n    ")
        ));
    }
    s
}

pub struct AtomicsOrderFamily;

impl Generator for AtomicsOrderFamily {
    fn id(&self) -> &'static str {
        "atomics-order"
    }

    fn category(&self) -> &'static str {
        "atomic-semantics"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("atomics-order", seed);
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
            id: format!("atomics-order/{seed:016x}"),
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
        reference_src(sample(seed))
    }

    fn skeleton_code(&self, seed: u64) -> String {
        let spec = sample(seed);
        skeleton_src(spec, &worked_examples(seed))
    }

    fn trivial_baselines(&self, seed: u64) -> Vec<(String, String)> {
        let spec = sample(seed);
        vec![
            ("const-zero".to_string(), const_zero_src(spec)),
            ("returns-new".to_string(), returns_new_src(spec)),
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
mod tests {
    use super::*;

    const HOUSE_SEEDS: [u64; 7] = [1, 2, 3, 7, 42, 99, 2024];

    #[test]
    fn generation_is_deterministic() {
        let a = AtomicsOrderFamily.generate(81);
        let b = AtomicsOrderFamily.generate(81);
        assert_eq!(a.id, b.id);
        assert_eq!(a.prompt, b.prompt);
        assert_eq!(a.files, b.files);
        assert_eq!(a.hidden, b.hidden);
    }

    #[test]
    fn fetch_add_hands_back_the_previous_value() {
        let a = AtomicsInstance(Cell::new(10));
        assert_eq!(a.fetch_add(5), 10);
        assert_eq!(a.0.get(), 15);
        assert_eq!(a.fetch_add(0), 15);
        assert_eq!(a.0.get(), 15);
        assert_eq!(a.fetch_add(u64::MAX - 14), 15);
        assert_eq!(a.0.get(), 0);
    }

    #[test]
    fn fetch_or_sets_only_the_masked_bits() {
        let a = AtomicsInstance(Cell::new(0b1010));
        assert_eq!(a.fetch_or(0b0110), 0b1010);
        assert_eq!(a.0.get(), 0b1110);
        assert_eq!(a.fetch_or(0), 0b1110);
        assert_eq!(a.0.get(), 0b1110);
        let b = AtomicsInstance(Cell::new(u64::MAX));
        assert_eq!(b.fetch_or(u64::MAX), u64::MAX);
        assert_eq!(b.0.get(), u64::MAX);
    }

    #[test]
    fn fetch_xor_flips_exactly_the_masked_bits() {
        let a = AtomicsInstance(Cell::new(0b1100));
        assert_eq!(a.fetch_xor(0b1010), 0b1100);
        assert_eq!(a.0.get(), 0b0110);
        assert_eq!(a.fetch_xor(0), 0b0110);
        assert_eq!(a.0.get(), 0b0110);
        assert_eq!(a.fetch_xor(0b0110), 0b0110);
        assert_eq!(a.0.get(), 0);
    }

    #[test]
    fn swap_replaces_regardless_of_contents() {
        let a = AtomicsInstance(Cell::new(0b1100));
        assert_eq!(a.swap(9), 0b1100);
        assert_eq!(a.0.get(), 9);
        assert_eq!(a.swap(0), 9);
        assert_eq!(a.0.get(), 0);
        assert_eq!(a.swap(u64::MAX), 0);
        assert_eq!(a.0.get(), u64::MAX);
    }

    #[test]
    fn negate_flips_to_the_twos_complement() {
        let a = AtomicsInstance(Cell::new(5));
        assert_eq!(a.negate(), 5);
        assert_eq!(a.0.get(), u64::MAX - 4);
        assert_eq!(a.negate(), u64::MAX - 4);
        assert_eq!(a.0.get(), 5);
    }

    #[test]
    fn negate_keeps_zero_at_zero() {
        let a = AtomicsInstance(Cell::new(0));
        assert_eq!(a.negate(), 0);
        assert_eq!(a.0.get(), 0);
    }

    #[test]
    fn fresh_cell_starts_at_zero() {
        let a = AtomicsInstance(Cell::new(0));
        assert_eq!(a.fetch_add(7), 0);
        assert_eq!(a.0.get(), 7);
    }

    #[test]
    fn eval_pair_routes_through_the_instance_methods() {
        // Every (previous, after) pair must come straight off the natives.
        for &(v0, arg) in &[(0u64, 3u64), (15, 1), (u64::MAX, 2), (7, 7)] {
            let inst = AtomicsInstance(Cell::new(v0));
            assert_eq!(eval_pair(Op::FetchAdd, v0, arg).0, inst.fetch_add(arg));
            assert_eq!(eval_pair(Op::FetchOr, v0, arg).0, {
                let i = AtomicsInstance(Cell::new(v0));
                i.fetch_or(arg)
            });
            assert_eq!(eval_pair(Op::FetchXor, v0, arg).1, {
                let i = AtomicsInstance(Cell::new(v0));
                i.fetch_xor(arg);
                i.0.get()
            });
            assert_eq!(eval_pair(Op::Swap, v0, arg).1, arg);
            assert_eq!(eval_pair(Op::Negate, v0, arg).1, v0.wrapping_neg());
        }
    }

    #[test]
    fn seeds_vary_query_pairs() {
        let mut seen = std::collections::HashSet::new();
        for seed in 0..300 {
            seen.insert(sample(seed));
        }
        assert!(seen.len() >= 9, "only {} distinct pairs", seen.len());
    }

    #[test]
    fn canonical_answers_are_non_degenerate_for_every_op() {
        for seed in 0..200u64 {
            let (v0, arg) = canonical(seed);
            assert!((1..=15).contains(&v0) && (1..=15).contains(&arg) && v0 != arg);
            let mut afters = Vec::new();
            for op in OP_ALL {
                let (prev, after) = eval_pair(op, v0, arg);
                // Every query answers with the BEFORE value: the classic
                // returns-new misuse must differ on every single op.
                assert_eq!(prev, v0);
                assert_ne!(after, v0, "{op:?} after == start for seed {seed}");
                afters.push(after);
            }
            for i in 0..afters.len() {
                for j in (i + 1)..afters.len() {
                    assert_ne!(afters[i], afters[j], "after-states collide for seed {seed}");
                }
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                for &(op, prev, after) in &ex.results {
                    let (p, a) = eval_pair(op, ex.v0, ex.arg);
                    assert_eq!((p, a), (prev, after));
                }
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            for &op in &spec.ops {
                assert!(
                    src.contains(&format!("pub fn {}(", op.name())),
                    "{} missing from reference for seed {seed}",
                    op.name()
                );
            }
            for op in OP_ALL {
                if !spec.ops.contains(&op) {
                    assert!(
                        !src.contains(&format!("pub fn {}(", op.name())),
                        "unselected {} leaked into reference for seed {seed}",
                        op.name()
                    );
                }
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let examples = worked_examples(seed);
            let canary = mint_canary("atomics-order", seed);
            let sk = skeleton_src(spec, &examples);
            let prompt = prompt_src(spec, &canary);
            // The skeleton stubs exactly the selected ops.
            assert!(sk.matches("todo!()").count() == spec.ops.len());
            // Implementation-shaped tokens only: op NAMES legitimately appear
            // in both surfaces as the required signature fence.
            for token in ["wrapping_neg", "SeqCst", ".fetch_add("] {
                assert!(
                    !sk.contains(token) && !prompt.contains(token),
                    "leak token {token} escaped for seed {seed}"
                );
            }
            for &op in &spec.ops {
                assert!(
                    prompt.contains(&op_sig_src(op)),
                    "signature for {} missing from prompt for seed {seed}",
                    op.name()
                );
            }
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        for seed in HOUSE_SEEDS {
            for &op in &sample(seed).ops {
                let sig = op_sig_src(op);
                let params = sig.split("->").next().unwrap();
                let want = params.matches(',').count();
                let call = call_src(op);
                let got = if call.contains("(cell)") { 0 } else { 1 };
                assert_eq!(got, want, "{} arity drift for seed {seed}", op.name());
            }
        }
    }

    /// Marker each op's emitted contention block carries, so the house can
    /// prove every selected op rides with a real-thread probe.
    fn contention_marker(op: Op) -> &'static str {
        match op {
            Op::FetchAdd => "concurrent_fetch_add_issues_unique_tickets",
            Op::FetchOr => "concurrent_disjoint_ors_cover_every_bit",
            Op::FetchXor => "concurrent_double_flips_return_to_start",
            Op::Swap => "concurrent_swaps_preserve_the_value_chain",
            Op::Negate => "concurrent_negates_cancel_in_pairs",
        }
    }

    #[test]
    fn every_selected_op_rides_a_contending_thread_probe() {
        // Each of the five ops finds seeds selecting it, and its probe is
        // present exactly when the op is.
        for op in OP_ALL {
            let mut found = false;
            for seed in 0..300u64 {
                let spec = sample(seed);
                let behavior = behavior_test_src(spec, &worked_examples(seed));
                let marker = contention_marker(op);
                assert_eq!(
                    behavior.contains(marker),
                    spec.ops.contains(&op),
                    "seed {seed}: marker {marker} misaligned"
                );
                if spec.ops.contains(&op) {
                    found = true;
                    assert!(behavior.contains("std::thread::spawn"));
                } else {
                    // Unselected probes never leak into another seed's file.
                    assert!(!behavior.contains(marker));
                }
            }
            assert!(found, "op {} never sampled", op.name());
        }
    }

    #[test]
    fn differential_specializes_both_ops_and_contends_across_threads() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            // Fully specialized: no generator-side spec may leak.
            assert!(!src.contains("spec."), "generator leak for seed {seed}");
            // Both selected ops appear as embedded reference functions.
            for &op in &spec.ops {
                assert!(src.contains(&format!("fn ref_{}(", op.name())));
            }
            for op in OP_ALL {
                if !spec.ops.contains(&op) {
                    assert!(
                        !src.contains(&format!("ref_{}(", op.name())),
                        "unselected {} leaked into differential for seed {seed}",
                        op.name()
                    );
                }
            }
            // Real contention: spawned threads on both implementations,
            // joined before any assertion reads the counters.
            assert!(src.matches("std::thread::spawn").count() >= 4);
            assert!(src.contains("differential_vs_reference"));
            assert!(src.contains("differential_contention_tracks_reference_under_threads"));
            // Candidate drives `cand`, reference drives `refr` — the two
            // teams never share a counter.
            assert!(src.contains("&cand") || src.contains("(&c,"));
        }
    }

    #[test]
    fn swap_chain_and_negate_parity_invariants_hold_off_thread() {
        // The multiset invariant the emitted swap probe asserts is a fact
        // about pure swaps; rehearse it sequentially through the natives.
        let cell = AtomicsInstance(Cell::new(7));
        let writes = [100u64, 101, 102];
        let mut observed: Vec<u64> = writes.iter().map(|&w| cell.swap(w)).collect();
        observed.push(cell.0.get());
        let mut expected: Vec<u64> = writes.to_vec();
        expected.push(7);
        observed.sort();
        expected.sort();
        assert_eq!(observed, expected);
        // Negation parity: any even number of negates returns to start.
        let cell = AtomicsInstance(Cell::new(5));
        for _ in 0..16 {
            cell.negate();
        }
        assert_eq!(cell.0.get(), 5);
    }

    #[test]
    fn returns_new_baseline_mimics_the_classic_misuse() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = returns_new_src(spec);
            // It stores correct new values but returns them — never the
            // previous value the real fetch ops hand back.
            assert!(src.contains(".store("));
            assert!(!src.contains(".fetch_add(") || src.contains("returns_new"));
            let (v0, arg) = canonical(seed);
            for &op in &spec.ops {
                let (prev, after) = eval_pair(op, v0, arg);
                assert_ne!(prev, after, "{op:?}: anchor requires divergence");
            }
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("atomics-order", seed);
            let prompt = prompt_src(sample(seed), &canary);
            assert!(prompt.contains(&canary));
        }
    }
}
