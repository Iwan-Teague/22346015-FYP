//! The `binary-heap` family (category `heap-indexing`) — priority-queue
//! puzzles over one flat slab.
//!
//! Every query mirrors a real min-heap primitive stored in a `Vec<u64>`
//! with NO per-node pointers: the whole skill is implicit-tree index
//! arithmetic — parent `(i-1)/2`, children `2i+1`/`2i+2`, last-live-slot
//! swaps during `pop_min`, and the sift loops that restore the heap
//! ordering invariant afterwards. The seed picks which two of five query
//! ops are required: `parent_index`, `left_child_index`, `push`,
//! `pop_min`, `is_heap`. None of the other families exercise
//! complete-binary-tree reasoning.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! live on [`HeapInstance`] so they are deterministic off-thread; the
//! generator built on top of them emits signatures over the same shape
//! where the identical invariants must hold.

/// One min-heap over a flat slab. `len` marks the live prefix; slots at
/// or past `len` are scratch.
pub struct HeapInstance {
    slab: Vec<u64>,
    len: usize,
}

impl HeapInstance {
    /// A fresh heap whose slab is preallocated to `capacity` slots.
    pub fn new(capacity: usize) -> Self {
        HeapInstance {
            slab: vec![0; capacity],
            len: 0,
        }
    }

    /// Parent slot of the node at `i`. The root (0) is its own parent by
    /// definition here — saturating instead of underflowing.
    pub fn parent_index(&self, i: u64) -> u64 {
        i.saturating_sub(1) / 2
    }

    /// Left child slot; right is this plus one. Saturates instead of
    /// overflowing near `u64::MAX`.
    pub fn left_child_index(&self, i: u64) -> u64 {
        i.saturating_mul(2).saturating_add(1)
    }

    /// Appends `v` and sifts it up; hands back the slot it settled in.
    pub fn push(&mut self, v: u64) -> u64 {
        let mut i = self.len;
        if i >= self.slab.len() {
            self.slab.push(v);
        } else {
            self.slab[i] = v;
        }
        self.len += 1;
        while i > 0 {
            let p = self.parent_index(i as u64) as usize;
            if self.slab[p] <= self.slab[i] {
                break;
            }
            self.slab.swap(p, i);
            i = p;
        }
        i as u64
    }

    /// Removes and returns the minimum; the last live slot fills the
    /// root before sifting down. Empty answers `None`.
    pub fn pop_min(&mut self) -> Option<u64> {
        if self.len == 0 {
            return None;
        }
        let min = self.slab[0];
        self.len -= 1;
        if self.len > 0 {
            self.slab[0] = self.slab[self.len];
            let mut i = 0usize;
            loop {
                let l = self.left_child_index(i as u64) as usize;
                let r = l + 1;
                let mut small = i;
                if l < self.len && self.slab[l] < self.slab[small] {
                    small = l;
                }
                if r < self.len && self.slab[r] < self.slab[small] {
                    small = r;
                }
                if small == i {
                    break;
                }
                self.slab.swap(i, small);
                i = small;
            }
        }
        Some(min)
    }

    /// True when every live parent is <= both children.
    pub fn is_heap(&self) -> bool {
        for i in 1..self.len {
            let p = self.parent_index(i as u64) as usize;
            if self.slab[p] > self.slab[i] {
                return false;
            }
        }
        true
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_heap_is_empty() {
        let mut h = HeapInstance::new(8);
        assert_eq!(h.len(), 0);
        assert!(h.is_heap());
        assert_eq!(h.pop_min(), None);
    }

    #[test]
    fn parent_index_saturates_at_the_root() {
        let h = HeapInstance::new(8);
        assert_eq!(h.parent_index(0), 0);
        assert_eq!(h.parent_index(1), 0);
        assert_eq!(h.parent_index(2), 0);
        assert_eq!(h.parent_index(3), 1);
        assert_eq!(h.parent_index(6), 2);
        assert_eq!(h.parent_index(7), 3);
        assert_eq!(h.parent_index(u64::MAX), (u64::MAX - 1) / 2);
    }

    #[test]
    fn left_child_index_never_overflows() {
        let h = HeapInstance::new(8);
        assert_eq!(h.left_child_index(0), 1);
        assert_eq!(h.left_child_index(1), 3);
        assert_eq!(h.left_child_index(2), 5);
        assert_eq!(h.left_child_index(u64::MAX), u64::MAX);
        // Right child is always the left plus one.
        for i in [0u64, 1, 4, 100] {
            assert_eq!(h.left_child_index(i) + 1, h.left_child_index(i) + 1);
        }
    }

    #[test]
    fn pushes_settle_in_sorted_prefix_order_for_ascending_input() {
        let mut h = HeapInstance::new(8);
        for v in [1u64, 2, 3, 4, 5] {
            let slot = h.push(v);
            // Ascending input never needs to bubble up: v lands at the end.
            assert_eq!(slot as usize, h.len() - 1);
            assert!(h.is_heap());
        }
        assert_eq!(h.len(), 5);
    }

    #[test]
    fn descending_input_bubbles_each_new_min_to_the_root() {
        let mut h = HeapInstance::new(8);
        assert_eq!(h.push(5), 0);
        assert_eq!(h.push(4), 0); // new min bubbles to root
        assert_eq!(h.push(3), 0);
        assert!(h.is_heap());
        assert_eq!(h.slab[0], 3);
    }

    #[test]
    fn pop_min_drains_in_ascending_order() {
        let mut h = HeapInstance::new(16);
        for v in [7u64, 3, 9, 1, 5, 3] {
            h.push(v);
        }
        assert_eq!(h.pop_min(), Some(1));
        assert_eq!(h.pop_min(), Some(3));
        assert_eq!(h.pop_min(), Some(3));
        assert_eq!(h.pop_min(), Some(5));
        assert_eq!(h.pop_min(), Some(7));
        assert_eq!(h.pop_min(), Some(9));
        assert_eq!(h.pop_min(), None);
        assert!(h.is_heap());
    }

    #[test]
    fn duplicates_are_indistinguishable_and_stay_ordered() {
        let mut h = HeapInstance::new(8);
        for _ in 0..5 {
            h.push(42);
        }
        assert!(h.is_heap());
        for _ in 0..5 {
            assert_eq!(h.pop_min(), Some(42));
        }
        assert_eq!(h.pop_min(), None);
    }

    #[test]
    fn heap_property_holds_after_every_interleaving() {
        let mut h = HeapInstance::new(64);
        let mut state: u64 = 0xDEAD_BEEF;
        let mut nx = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state >> 33
        };
        for _ in 0..500 {
            if nx() % 3 == 0 && !h.is_empty() {
                h.pop_min();
            } else {
                h.push(nx() % 1000);
            }
            assert!(h.is_heap());
        }
    }
}

// ---- generator: op menu, spec, canonical, emitters -------------------------

const CANONICAL_SEED: u64 = 0x9E02_FA11;

use crate::{mint_canary, GeneratedTask, Generator, Rng};

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    HeapLen,
    ParentIndex,
    LeftChildIndex,
    Push,
    PopMin,
}

pub const OP_ALL: [Op; 5] = [
    Op::HeapLen,
    Op::ParentIndex,
    Op::LeftChildIndex,
    Op::Push,
    Op::PopMin,
];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::HeapLen => "heap_len",
            Op::ParentIndex => "parent_index",
            Op::LeftChildIndex => "left_child_index",
            Op::Push => "push",
            Op::PopMin => "pop_min",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::HeapLen => "how many elements the heap currently holds",
            Op::ParentIndex => "the slot of the parent of the node at i — the root is its own parent rather than underflowing",
            Op::LeftChildIndex => "the slot of the left child of the node at i (right is one more); saturates instead of overflowing",
            Op::Push => "appends v and sifts it up, handing back the slot it settled in",
            Op::PopMin => "removes the minimum: the last live slot moves to the root and sifts down; None when empty",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::HeapLen => "pub fn heap_len(&self) -> usize",
            Op::ParentIndex => "pub fn parent_index(&self, i: u64) -> u64",
            Op::LeftChildIndex => "pub fn left_child_index(&self, i: u64) -> u64",
            Op::Push => "pub fn push(&mut self, v: u64) -> u64",
            Op::PopMin => "pub fn pop_min(&mut self) -> Option<u64>",
        }
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

/// Push is the fill primitive every scenario needs; when the seed did
/// not sample it, it ships as given infrastructure alongside the pair.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    if spec.ops.contains(&Op::Push) {
        spec.ops.to_vec()
    } else {
        let mut v = vec![Op::Push];
        v.extend_from_slice(&spec.ops);
        v
    }
}

/// The canonical scenario: a capacity-8 slab warmed with dozens of
/// pseudo-random pushes, so any solution that mis-sifts (or settles a
/// pushed value in the wrong slot) is wrong before the first probe.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical heap scenario");
}

fn fresh_heap(capacity: u64) -> HeapInstance {
    HeapInstance::new(capacity as usize)
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub capacity: u64,
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01A0;

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![
        ExampleCase {
            capacity: 8,
            warmup: canonical(seed),
        },
        ExampleCase {
            capacity: 1,
            warmup: 3,
        },
        ExampleCase {
            capacity: 2,
            warmup: 4,
        },
        ExampleCase {
            capacity: 16,
            warmup: 17,
        },
    ];
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    for _ in 0..3 {
        let cap = 1u64 << (1 + rng.below(5));
        out.push(ExampleCase {
            capacity: cap,
            warmup: rng.below(cap * 3),
        });
    }
    out
}

/// Drives `warmup` pseudo-random pushes into a fresh heap, returning it
/// plus every value that went in (order preserved).
fn driven_heap(capacity: u64, warmup: u64) -> (HeapInstance, Vec<u64>) {
    let mut h = fresh_heap(capacity);
    let mut state = 0x5EED_C0FF ^ capacity.wrapping_mul(0x9E37).wrapping_add(warmup);
    let mut pushed = Vec::new();
    for _ in 0..warmup {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let v = state >> 33;
        h.push(v);
        pushed.push(v);
    }
    (h, pushed)
}

// ---- emitted-source fragments -----------------------------------------------

pub const STRUCT_SRC: &str =
    "#[derive(Clone)]\npub struct Heap {\n    slab: Vec<u64>,\n    len: usize,\n}\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::HeapLen => &["self.len"],
        Op::ParentIndex => &["i.saturating_sub(1) / 2"],
        Op::LeftChildIndex => &["i.saturating_mul(2).saturating_add(1)"],
        Op::Push => &[
            "let mut i = self.len;",
            "if i >= self.slab.len() {",
            "    self.slab.push(v);",
            "} else {",
            "    self.slab[i] = v;",
            "}",
            "self.len += 1;",
            "while i > 0 {",
            "    let p = (i - 1) / 2;",
            "    if self.slab[p] <= self.slab[i] {",
            "        break;",
            "    }",
            "    self.slab.swap(p, i);",
            "    i = p;",
            "}",
            "i as u64",
        ],
        Op::PopMin => &[
            "if self.len == 0 {",
            "    return None;",
            "}",
            "let min = self.slab[0];",
            "self.len -= 1;",
            "if self.len > 0 {",
            "    self.slab[0] = self.slab[self.len];",
            "    let mut i = 0usize;",
            "    loop {",
            "        let l = 2 * i + 1;",
            "        let r = l + 1;",
            "        let mut small = i;",
            "        if l < self.len && self.slab[l] < self.slab[small] {",
            "            small = l;",
            "        }",
            "        if r < self.len && self.slab[r] < self.slab[small] {",
            "            small = r;",
            "        }",
            "        if small == i {",
            "            break;",
            "        }",
            "        self.slab.swap(i, small);",
            "        i = small;",
            "    }",
            "}",
            "Some(min)",
        ],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub const HEAP_NEW_SRC: &str =
    "impl Heap {\n    pub fn new(capacity: usize) -> Self {\n        Heap {\n            slab: vec![0; capacity],\n            len: 0,\n        }\n    }\n\n    pub fn len(&self) -> usize {\n        self.len\n    }\n\n    pub fn is_empty(&self) -> bool {\n        self.len == 0\n    }\n}\n\n";

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen("pub struct Heap {", "pub struct HeapRef {", 1);
    s.push_str(
        &HEAP_NEW_SRC
            .replace("impl Heap {", "impl HeapRef {")
            .replace("Heap {\n", "HeapRef {\n"),
    );
    s.push_str("impl HeapRef {\n");
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
        let (h, pushed) = driven_heap(ex.capacity, ex.warmup);
        s.push_str(&format!(
            "//! ex{i}: capacity {c}, then {w} pseudo-random pushes -> len {l}, smallest few [{m}]\n",
            i = i,
            c = ex.capacity,
            w = ex.warmup,
            l = h.len(),
            m = {
                let mut sorted = pushed.clone();
                sorted.sort_unstable();
                sorted
                    .iter()
                    .take(3)
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested binary min-heap operations over one\n\
         //! array-backed slab. Index math is done on u64 slots and must\n\
         //! SATURATE near the top of the range instead of overflowing.\n\
         //! The hidden tests drive thousands of interleaved operations\n\
         //! and compare every returned value.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(HEAP_NEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested array-backed binary min-heap operations.\n\nRequirements:\n- `Heap::new(capacity)` preallocates the slab to `capacity` zeroed slots and starts empty; pushes past the preallocation still work by growing the slab.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- Keep the exact struct shape and signatures.\n- Slot arithmetic saturates rather than wrapping or panicking.\n- No unsafe code; standard library only.\n\nSignatures:\n```rust\n");
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
    let mut s = String::from("use task::Heap;\n\n");
    for (i, ex) in examples.iter().enumerate() {
        let (h, pushed) = driven_heap(ex.capacity, ex.warmup);
        let mut sorted = pushed.clone();
        sorted.sort_unstable();
        // Reproduce the drive's LCG one step past its last push so the
        // emitted probe uses the exact value the natives saw next.
        let mut state = 0x5EED_C0FF ^ ex.capacity.wrapping_mul(0x9E37).wrapping_add(ex.warmup);
        for _ in 0..ex.warmup {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
        }
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let v_next = state >> 33;
        let mut probe = fresh_heap(ex.capacity);
        for &v in &pushed {
            probe.push(v);
        }
        let slot_next = probe.push(v_next);

        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let mut drive = Heap::new({c});\n    let mut st: u64 = 0x5EED_C0FF ^ ({c}u64.wrapping_mul(0x9E37).wrapping_add({w}));\n    for _ in 0..{w} {{\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        drive.push(st >> 33);\n    }}\n",
            i = i,
            c = ex.capacity,
            w = ex.warmup
        ));
        for &op in &spec.ops {
            s.push_str("    let mut r = drive.clone();\n");
            match op {
                Op::HeapLen => s.push_str(&format!("    assert_eq!(r.heap_len(), {});\n", h.len())),
                Op::ParentIndex => {
                    for (label, arg) in [("z", 0u64), ("t", ex.warmup), ("m", u64::MAX)] {
                        s.push_str(&format!(
                            "    assert_eq!(r.parent_index({a}), {e}); // {label}\n",
                            a = arg,
                            e = h.parent_index(arg),
                            label = label
                        ));
                    }
                }
                Op::LeftChildIndex => {
                    for (label, arg) in [("z", 0u64), ("t", ex.warmup), ("m", u64::MAX)] {
                        s.push_str(&format!(
                            "    assert_eq!(r.left_child_index({a}), {e}); // {label}\n",
                            a = arg,
                            e = h.left_child_index(arg),
                            label = label
                        ));
                    }
                }
                Op::Push => {
                    s.push_str(&format!(
                        "    assert_eq!(r.push({v}), {slot});\n",
                        v = v_next,
                        slot = slot_next
                    ));
                    if spec.ops.contains(&Op::HeapLen) {
                        s.push_str(&format!("    assert_eq!(r.heap_len(), {});\n", h.len() + 1));
                    }
                }
                Op::PopMin => {
                    if sorted.is_empty() {
                        s.push_str("    assert_eq!(r.pop_min(), None);\n");
                    } else {
                        s.push_str(&format!(
                            "    assert_eq!(r.pop_min(), Some({m0}));\n",
                            m0 = sorted[0]
                        ));
                        match sorted.get(1) {
                            Some(&m1) => {
                                s.push_str(&format!("    assert_eq!(r.pop_min(), Some({m1}));\n"));
                                if sorted.len() > 2 {
                                    s.push_str("    assert!(r.pop_min().is_some());\n");
                                }
                            }
                            None => s.push_str("    assert_eq!(r.pop_min(), None);\n"),
                        }
                    }
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Drain soak: thousands of pseudo-random pushes must come back out
    // in exact ascending order — kills lost-element and unstable-sift
    // cheats alike.
    if spec.ops.contains(&Op::Push) && spec.ops.contains(&Op::PopMin) {
        s.push_str("#[test]\nfn soak_drains_in_ascending_order() {\n    let mut r = Heap::new(16);\n    let mut st: u64 = 0x5EED_0000_0000_01A2;\n    let mut pushed: Vec<u64> = Vec::new();\n");
        s.push_str("    for _ in 0..500u64 {\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        let v = st >> 33;\n        r.push(v);\n        pushed.push(v);\n    }\n");
        s.push_str("    pushed.sort_unstable();\n    for want in pushed {\n        assert_eq!(r.pop_min(), Some(want));\n    }\n    assert_eq!(r.pop_min(), None);\n");
        if spec.ops.contains(&Op::HeapLen) {
            s.push_str("    assert_eq!(r.heap_len(), 0);\n");
        }
        s.push_str("}\n");
    }
    // Fill soak: monotonic pushes must keep the count honest.
    if spec.ops.contains(&Op::Push) && spec.ops.contains(&Op::HeapLen) {
        s.push_str("#[test]\nfn fill_soak_tracks_the_count() {\n    let mut r = Heap::new(4);\n    let mut st: u64 = 0x5EED_0000_0000_01A2;\n    for i in 0..2000u64 {\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        r.push(st >> 33);\n        assert_eq!(r.heap_len(), (i + 1) as usize);\n    }\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::Heap;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    let ops = effective_ops(spec);
    s.push_str("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {\n    let mut cand = Heap::new(8);\n    let mut refr = HeapRef::new(8);\n");
    if ops.contains(&Op::ParentIndex) {
        s.push_str("    assert_eq!(cand.parent_index(0), refr.ref_parent_index(0));\n    assert_eq!(cand.parent_index(u64::MAX), refr.ref_parent_index(u64::MAX));\n");
    }
    if ops.contains(&Op::LeftChildIndex) {
        s.push_str("    assert_eq!(cand.left_child_index(0), refr.ref_left_child_index(0));\n    assert_eq!(cand.left_child_index(u64::MAX), refr.ref_left_child_index(u64::MAX));\n");
    }
    let arm_count = ops.len();
    s.push_str(&format!("    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_01A0;\n    for _ in 0..3000 {{\n        let arg = nx(&mut state);\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in ops.iter().enumerate() {
        let body = match op {
            Op::Push => "assert_eq!(cand.push(arg % 97), refr.ref_push(arg % 97));".to_string(),
            Op::PopMin => "assert_eq!(cand.pop_min(), refr.ref_pop_min());".to_string(),
            Op::HeapLen => "assert_eq!(cand.heap_len(), refr.ref_heap_len());".to_string(),
            Op::ParentIndex => {
                "assert_eq!(cand.parent_index(arg), refr.ref_parent_index(arg));".to_string()
            }
            Op::LeftChildIndex => {
                "assert_eq!(cand.left_child_index(arg), refr.ref_left_child_index(arg));"
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
    s.push_str(HEAP_NEW_SRC);
    s.push_str("impl Heap {\n");
    for &op in &ops {
        let body = match op {
            Op::HeapLen => "0",
            Op::ParentIndex | Op::LeftChildIndex => "let _ = i;\n    0",
            Op::Push => "let _ = v;\n    0",
            Op::PopMin => "None",
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s.push_str("}\n");
    s
}

/// The plausible approximate-parent cheat: `i / 2` halves one step too
/// fast for even slots and `2 * i` aims the sift-down at the node
/// itself. Looks like textbook index math, survives the first few
/// pushes on tiny heaps, then settles pushed values into wrong slots
/// and drains out of order — exactly what the family's index probes
/// and the drain soak exist to catch.
pub fn naive_parent_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(HEAP_NEW_SRC);
    s.push_str("impl Heap {\n");
    for &op in &ops {
        let body: &[&str] = match op {
            Op::HeapLen => &["self.len"],
            Op::ParentIndex => &["i / 2"],
            Op::LeftChildIndex => &["2 * i"],
            Op::Push => &[
                "let mut i = self.len;",
                "if i >= self.slab.len() {",
                "    self.slab.push(v);",
                "} else {",
                "    self.slab[i] = v;",
                "}",
                "self.len += 1;",
                "while i > 0 {",
                "    let p = i / 2;",
                "    if self.slab[p] <= self.slab[i] {",
                "        break;",
                "    }",
                "    self.slab.swap(p, i);",
                "    i = p;",
                "}",
                "i as u64",
            ],
            Op::PopMin => &[
                "if self.len == 0 {",
                "    return None;",
                "}",
                "let min = self.slab[0];",
                "self.len -= 1;",
                "if self.len > 0 {",
                "    self.slab[0] = self.slab[self.len];",
                "    let mut i = 0usize;",
                "    loop {",
                "        let l = 2 * i;",
                "        let r = l + 1;",
                "        let mut small = i;",
                "        if l < self.len && self.slab[l] < self.slab[small] {",
                "            small = l;",
                "        }",
                "        if r < self.len && self.slab[r] < self.slab[small] {",
                "            small = r;",
                "        }",
                "        if small == i {",
                "            break;",
                "        }",
                "        self.slab.swap(i, small);",
                "        i = small;",
                "    }",
                "}",
                "Some(min)",
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

pub struct BinaryHeapFamily;

impl Generator for BinaryHeapFamily {
    fn id(&self) -> &'static str {
        "binary-heap"
    }

    fn category(&self) -> &'static str {
        "heap-indexing"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("binary-heap", seed);
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
            id: format!("binary-heap/{seed:016x}"),
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
        s.push_str(HEAP_NEW_SRC);
        s.push_str("impl Heap {\n");
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
            ("naive-parent".to_string(), naive_parent_src(spec)),
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
        let a = BinaryHeapFamily.generate(55);
        let b = BinaryHeapFamily.generate(55);
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
    fn canonical_scenarios_fill_the_slab() {
        for seed in 0..200u64 {
            let warmup = canonical(seed);
            assert!(warmup >= 24 && warmup.is_multiple_of(8));
            let (h, pushed) = driven_heap(8, warmup);
            assert_eq!(h.len(), warmup as usize);
            assert!(h.len() >= 8);
            assert!(h.is_heap());
            assert_eq!(pushed.len(), warmup as usize);
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let (h, pushed) = driven_heap(ex.capacity, ex.warmup);
                assert_eq!(h.len(), ex.warmup as usize);
                assert_eq!(pushed.len(), ex.warmup as usize);
                assert!(h.is_heap());
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct HeapRef"));
            // `pub fn new` is the given constructor; every OP must have
            // been renamed to its `ref_` twin.
            assert!(!src.contains("pub fn heap_len"));
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
            let canary = mint_canary("binary-heap", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in ["(i - 1) / 2", "saturating_mul", "swap(", "2 * i"] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("saturates"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("HeapRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
            let drains = spec.ops.contains(&Op::Push) && spec.ops.contains(&Op::PopMin);
            let fills = spec.ops.contains(&Op::Push) && spec.ops.contains(&Op::HeapLen);
            assert_eq!(
                src.contains("soak_drains_in_ascending_order"),
                drains,
                "seed {seed}: drain soak misaligned"
            );
            assert_eq!(
                src.contains("fill_soak_tracks_the_count"),
                fills,
                "seed {seed}: fill soak misaligned"
            );
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soaks() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            let drains = spec.ops.contains(&Op::Push) && spec.ops.contains(&Op::PopMin);
            let fills = spec.ops.contains(&Op::Push) && spec.ops.contains(&Op::HeapLen);
            assert_eq!(
                behavior.contains("soak_drains_in_ascending_order"),
                drains,
                "seed {seed}: drain soak misaligned"
            );
            assert_eq!(
                behavior.contains("fill_soak_tracks_the_count"),
                fills,
                "seed {seed}: fill soak misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_heap_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let np = naive_parent_src(spec);
        assert!(cz.contains("None"));
        assert!(np.contains("i / 2"));
        assert!(np.contains("2 * i"));
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("binary-heap", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
