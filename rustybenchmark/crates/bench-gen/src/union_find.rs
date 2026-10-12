//! Disjoint-set (union-find) natives: the exercise family models a partition
//! of `n` elements into components that only ever coalesce through weighted
//! linking, with component bookkeeping that must stay exact.

#[derive(Clone)]
pub struct UnionFindInstance {
    parent: Vec<u64>,
    size: Vec<u64>,
    count: u64,
}

impl UnionFindInstance {
    pub fn new(n: usize) -> Self {
        assert!(n >= 1, "union-find needs at least one element");
        Self {
            parent: (0..n as u64).collect(),
            size: vec![1; n],
            count: n as u64,
        }
    }

    /// The root representative of `x`'s component.
    pub fn find(&self, x: u64) -> u64 {
        assert!((x as usize) < self.parent.len(), "element out of range");
        let mut cur = x;
        while self.parent[cur as usize] != cur {
            cur = self.parent[cur as usize];
        }
        cur
    }

    /// Link two different components by size and answer whether a NEW merge
    /// happened (false when both elements already shared a root).
    pub fn union(&mut self, a: u64, b: u64) -> bool {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb {
            return false;
        }
        let (big, small) = if self.size[ra as usize] >= self.size[rb as usize] {
            (ra, rb)
        } else {
            (rb, ra)
        };
        self.parent[small as usize] = big;
        self.size[big as usize] += self.size[small as usize];
        self.count -= 1;
        true
    }

    pub fn same_set(&self, a: u64, b: u64) -> bool {
        self.find(a) == self.find(b)
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// How many elements share `x`'s root.
    pub fn size_of(&self, x: u64) -> u64 {
        self.size[self.find(x) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn singletons_start_separate() {
        let uf = UnionFindInstance::new(5);
        assert_eq!(uf.count(), 5);
        for x in 0..5u64 {
            assert_eq!(uf.find(x), x);
            assert_eq!(uf.size_of(x), 1);
        }
        assert!(!uf.same_set(0, 4));
    }

    #[test]
    fn union_answers_true_once_per_pair() {
        let mut uf = UnionFindInstance::new(4);
        assert!(uf.union(0, 1));
        assert!(!uf.union(0, 1));
        assert!(!uf.union(1, 0));
        assert_eq!(uf.count(), 3);
        assert!(uf.same_set(0, 1));
    }

    #[test]
    fn chain_merges_transitively() {
        let mut uf = UnionFindInstance::new(6);
        assert!(uf.union(0, 1));
        assert!(uf.union(1, 2));
        assert!(uf.union(3, 4));
        assert!(uf.same_set(0, 2));
        assert!(!uf.same_set(0, 3));
        assert!(!uf.same_set(2, 5));
        assert_eq!(uf.count(), 3);
    }

    #[test]
    fn size_of_tracks_component_growth() {
        let mut uf = UnionFindInstance::new(6);
        uf.union(0, 1);
        uf.union(1, 2);
        assert_eq!(uf.size_of(2), 3);
        assert_eq!(uf.size_of(0), 3);
        assert_eq!(uf.size_of(4), 1);
    }

    #[test]
    #[should_panic]
    fn out_of_range_element_panics() {
        let uf = UnionFindInstance::new(3);
        let _ = uf.find(9);
    }

    #[test]
    fn soak_matches_shadow_labels_under_random_traffic() {
        let mut uf = UnionFindInstance::new(12);
        let mut labels: Vec<u64> = (0..12).collect();
        let mut st: u64 = 0x5EED_D15E;
        for step in 0..500u64 {
            st = st
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let a = (st >> 33) % 12;
            let b = (st >> 7) % 12;
            let (la, lb) = (labels[a as usize], labels[b as usize]);
            let merged = uf.union(a, b);
            assert_eq!(merged, la != lb);
            if la != lb {
                for l in labels.iter_mut() {
                    if *l == la {
                        *l = lb;
                    }
                }
            }
            if step % 25 == 24 {
                let distinct = labels.iter().copied().collect::<BTreeSet<_>>().len() as u64;
                assert_eq!(uf.count(), distinct);
            }
        }
        for a in 0..12u64 {
            for b in 0..12u64 {
                assert_eq!(uf.same_set(a, b), labels[a as usize] == labels[b as usize]);
            }
        }
        for x in 0..12u64 {
            let members = labels.iter().filter(|&&l| l == labels[x as usize]).count() as u64;
            assert_eq!(uf.size_of(x), members);
        }
    }
}
use crate::{mint_canary, GeneratedTask, Generator, Rng};

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    ComponentCount,
    Union,
    Find,
    SameSet,
    SizeOf,
}

pub const OP_ALL: [Op; 5] = [
    Op::ComponentCount,
    Op::Union,
    Op::Find,
    Op::SameSet,
    Op::SizeOf,
];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::ComponentCount => "count",
            Op::Union => "union",
            Op::Find => "find",
            Op::SameSet => "same_set",
            Op::SizeOf => "size_of",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::ComponentCount => {
                "answers how many separate components the partition currently holds"
            }
            Op::Union => "links the components holding a and b - the smaller side joins under the larger root - and answers whether a fresh merge happened (false when both already shared a root)",
            Op::Find => "answers the root representative of the component holding x",
            Op::SameSet => "answers whether a and b belong to one component",
            Op::SizeOf => "answers how many elements belong to the component holding x",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::ComponentCount => "pub fn count(&self) -> u64",
            Op::Union => "pub fn union(&mut self, a: u64, b: u64) -> bool",
            Op::Find => "pub fn find(&self, x: u64) -> u64",
            Op::SameSet => "pub fn same_set(&self, a: u64, b: u64) -> bool",
            Op::SizeOf => "pub fn size_of(&self, x: u64) -> u64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub const CANONICAL_SEED: u64 = 0xD15E_FA11;

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

/// Union is the fill primitive and the component tally is the audit
/// counter; both ship as given infrastructure alongside the sampled pair,
/// so any solution whose tally drifts is caught no matter the pair.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    let mut v = vec![Op::Union];
    if !spec.ops.contains(&Op::ComponentCount) {
        v.push(Op::ComponentCount);
    }
    for o in spec.ops {
        if !v.contains(&o) {
            v.push(o);
        }
    }
    v
}

/// The canonical scenario: a mid-size partition hammered by dozens of
/// unions, so any solution that forgets to maintain its component tally
/// drifts from the very first merge.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical union-find scenario");
}

fn fresh_dsu(n: u64) -> UnionFindInstance {
    UnionFindInstance::new(n as usize)
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub n: u64,
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01C4;

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![
        ExampleCase {
            n: 12,
            warmup: canonical(seed),
        },
        ExampleCase { n: 3, warmup: 3 },
        ExampleCase { n: 5, warmup: 4 },
        ExampleCase { n: 8, warmup: 17 },
    ];
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    for _ in 0..8 {
        let n = 2 + rng.below(23);
        out.push(ExampleCase {
            n,
            warmup: rng.below(n * 6) + 2,
        });
    }
    out
}

const NX_MUL: u64 = 6364136223846793005;
const NX_ADD: u64 = 1442695040888963407;

fn drive_init(n: u64, warmup: u64) -> u64 {
    0xD15E_CAFEu64 ^ n.wrapping_mul(0x9E37).wrapping_add(warmup)
}

/// Drives `warmup` random unions into a fresh `n`-element partition.
fn driven_dsu(n: u64, warmup: u64) -> UnionFindInstance {
    let mut d = fresh_dsu(n);
    let mut st = drive_init(n, warmup);
    for _ in 0..warmup {
        let a = (st >> 33) % n;
        let b = (st >> 7) % n;
        d.union(a, b);
        st = st.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    }
    d
}

/// The probe-continuation state after the drive loop (one advance per union).
fn drive_final_state(n: u64, warmup: u64) -> u64 {
    let mut st = drive_init(n, warmup);
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

pub const STRUCT_SRC: &str =
    "#[derive(Clone)]\npub struct Dsu {\n    parent: Vec<u64>,\n    size: Vec<u64>,\n    count: u64,\n}\n";

pub const DSU_NEW_SRC: &str = "impl Dsu {\n    pub fn new(n: usize) -> Self {\n        assert!(n >= 1);\n        Dsu {\n            parent: (0..n as u64).collect(),\n            size: vec![1; n],\n            count: n as u64,\n        }\n    }\n\n    /// Internal root walk shared by every operation.\n    fn root(&self, x: u64) -> u64 {\n        let mut cur = x;\n        while self.parent[cur as usize] != cur {\n            cur = self.parent[cur as usize];\n        }\n        cur\n    }\n}\n\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::ComponentCount => &["self.count"],
        Op::Union => &[
            "let ra = self.root(a);",
            "let rb = self.root(b);",
            "if ra == rb {",
            "    return false;",
            "}",
            "if self.size[ra as usize] < self.size[rb as usize] {",
            "    self.parent[ra as usize] = rb;",
            "    self.size[rb as usize] += self.size[ra as usize];",
            "} else {",
            "    self.parent[rb as usize] = ra;",
            "    self.size[ra as usize] += self.size[rb as usize];",
            "}",
            "self.count -= 1;",
            "true",
        ],
        Op::Find => &["assert!((x as usize) < self.parent.len());", "self.root(x)"],
        Op::SameSet => &["self.root(a) == self.root(b)"],
        Op::SizeOf => &["self.size[self.root(x) as usize]"],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen("pub struct Dsu {", "pub struct DsuRef {", 1);
    s.push_str(
        &DSU_NEW_SRC
            .replace("impl Dsu {", "impl DsuRef {")
            .replace("Dsu {\n", "DsuRef {\n"),
    );
    s.push_str("impl DsuRef {\n");
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
        let d = driven_dsu(ex.n, ex.warmup);
        s.push_str(&format!(
            "//! ex{i}: {n} elements, then {w} random unions -> {c} components remain\n",
            i = i,
            n = ex.n,
            w = ex.warmup,
            c = d.count()
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested disjoint-set operations over one internal\n\
         //! partition. Elements start as singletons and only ever coalesce;\n\
         //! merges are weighted so the smaller side joins under the larger\n\
         //! root, and every bookkeeping tally must stay exact. The hidden\n\
         //! tests drive thousands of interleaved operations and compare\n\
         //! every returned value.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(DSU_NEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested disjoint-set operations with exactly maintained component bookkeeping.\n\nRequirements:\n- `Dsu::new(n)` starts with `n` singleton components; the private root-walking helper is given.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- A union of two elements from different components must answer true and shrink the component tally by exactly one; two elements that already shared a root must answer false and change nothing.\n- The component count answers how many distinct roots remain at all times, starting at n.\n- Queries never mutate the partition; size_of counts members through the shared root.\n- No floating point; no unsafe code; standard library only.\n\nSignatures:\n```rust\n");
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
    let mut s = String::from("use task::Dsu;\n\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n");
    for (i, ex) in examples.iter().enumerate() {
        let h = driven_dsu(ex.n, ex.warmup);
        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let mut drive = Dsu::new({n} as usize);\n    let mut st: u64 = {init};\n    for _ in 0..{w} {{\n        let a = (st >> 33) % {n}u64;\n        let b = (st >> 7) % {n}u64;\n        drive.union(a, b);\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    }}\n",
            i = i,
            n = ex.n,
            w = ex.warmup,
            init = drive_init(ex.n, ex.warmup)
        ));
        s.push_str(&format!(
            "    let mut ps: u64 = {};\n",
            drive_final_state(ex.n, ex.warmup)
        ));
        let mut ps = drive_final_state(ex.n, ex.warmup);
        for &op in &spec.ops {
            match op {
                Op::ComponentCount => {
                    s.push_str(&format!("    assert_eq!(drive.count(), {});\n", h.count()));
                }
                Op::Union => {
                    let ua = nx(&mut ps) % ex.n;
                    let ub = nx(&mut ps) % ex.n;
                    let want = h.clone().union(ua, ub);
                    s.push_str(&format!(
                        "    let mut r = drive.clone();\n    let ua = nx(&mut ps) % {n}u64;\n    let ub = nx(&mut ps) % {n}u64;\n    assert_eq!(r.union(ua, ub), {want});\n",
                        n = ex.n,
                        want = want
                    ));
                }
                Op::Find => {
                    let fx = nx(&mut ps) % ex.n;
                    let want = h.clone().find(fx);
                    s.push_str(&format!(
                        "    let r = drive.clone();\n    let fx = nx(&mut ps) % {n}u64;\n    assert_eq!(r.find(fx), {want});\n",
                        n = ex.n,
                        want = want
                    ));
                }
                Op::SameSet => {
                    let sa = nx(&mut ps) % ex.n;
                    let sb = nx(&mut ps) % ex.n;
                    let want = h.clone().same_set(sa, sb);
                    s.push_str(&format!(
                        "    let r = drive.clone();\n    let sa = nx(&mut ps) % {n}u64;\n    let sb = nx(&mut ps) % {n}u64;\n    assert_eq!(r.same_set(sa, sb), {want});\n",
                        n = ex.n,
                        want = want
                    ));
                }
                Op::SizeOf => {
                    let zx = nx(&mut ps) % ex.n;
                    let want = h.clone().size_of(zx);
                    s.push_str(&format!(
                        "    let r = drive.clone();\n    let zx = nx(&mut ps) % {n}u64;\n    assert_eq!(r.size_of(zx), {want});\n",
                        n = ex.n,
                        want = want
                    ));
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Scripted probe: repeated merges answer true only once per pair and the
    // tally shrinks by exactly one per fresh merge.
    if spec.ops.contains(&Op::Union) && spec.ops.contains(&Op::ComponentCount) {
        s.push_str("#[test]\nfn scripted_merges_shrink_the_component_tally() {\n    let mut r = Dsu::new(6);\n    assert_eq!(r.union(0, 1), true);\n    assert_eq!(r.union(2, 1), true);\n    assert_eq!(r.union(0, 2), false);\n    assert_eq!(r.count(), 4);\n    assert_eq!(r.union(3, 4), true);\n    assert_eq!(r.count(), 3);\n    assert_eq!(r.union(5, 5), false);\n    assert_eq!(r.count(), 3);\n}\n");
    }
    // Fill soak: eight hundred random unions must keep every member tally
    // pinned to the shadow label partition.
    if spec.ops.contains(&Op::Union) && spec.ops.contains(&Op::SizeOf) {
        s.push_str("#[test]\nfn fill_soak_pins_member_counts_to_a_shadow_partition() {\n    let mut r = Dsu::new(12);\n    let mut labels: Vec<u64> = (0..12).collect();\n    let mut st: u64 = 0x5EED_0000_0000_01C6;\n    for _ in 0..800usize {\n        let a = (st >> 33) % 12;\n        let b = (st >> 7) % 12;\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        let (la, lb) = (labels[a as usize], labels[b as usize]);\n        let merged = r.union(a, b);\n        assert_eq!(merged, la != lb);\n        if la != lb {\n            for l in labels.iter_mut() {\n                if *l == la {\n                    *l = lb;\n                }\n            }\n        }\n        let members = labels.iter().filter(|&&l| l == labels[a as usize]).count() as u64;\n        assert_eq!(r.size_of(a), members);\n    }\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::Dsu;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    let ops = effective_ops(spec);
    s.push_str("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {\n    let n0: u64 = 9;\n    let mut cand = Dsu::new(n0 as usize);\n    let mut refr = DsuRef::new(n0 as usize);\n");
    if ops.contains(&Op::Union) {
        s.push_str("    assert_eq!(cand.union(0, 1), refr.ref_union(0, 1));\n");
        s.push_str("    assert_eq!(cand.union(1, 0), refr.ref_union(1, 0));\n");
    }
    if ops.contains(&Op::ComponentCount) {
        s.push_str("    assert_eq!(cand.count(), refr.ref_count());\n");
    }
    if ops.contains(&Op::Find) {
        s.push_str("    assert_eq!(cand.find(8), refr.ref_find(8));\n");
    }
    if ops.contains(&Op::SameSet) {
        s.push_str("    assert_eq!(cand.same_set(2, 3), refr.ref_same_set(2, 3));\n");
    }
    if ops.contains(&Op::SizeOf) {
        s.push_str("    assert_eq!(cand.size_of(4), refr.ref_size_of(4));\n");
    }
    let arm_count = ops.len();
    s.push_str(&format!("    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_01C4;\n    for _ in 0..3000 {{\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in ops.iter().enumerate() {
        let body = match op {
            Op::ComponentCount => "assert_eq!(cand.count(), refr.ref_count());".to_string(),
            Op::Union => "let ua = nx(&mut state) % n0;\n            let ub = nx(&mut state) % n0;\n            assert_eq!(cand.union(ua, ub), refr.ref_union(ua, ub));".to_string(),
            Op::Find => "let fx = nx(&mut state) % n0;\n            assert_eq!(cand.find(fx), refr.ref_find(fx));".to_string(),
            Op::SameSet => "let sa = nx(&mut state) % n0;\n            let sb = nx(&mut state) % n0;\n            assert_eq!(cand.same_set(sa, sb), refr.ref_same_set(sa, sb));".to_string(),
            Op::SizeOf => "let zx = nx(&mut state) % n0;\n            assert_eq!(cand.size_of(zx), refr.ref_size_of(zx));".to_string(),
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
    s.push_str(DSU_NEW_SRC);
    s.push_str("impl Dsu {\n");
    for &op in &ops {
        let body = match op {
            Op::Union | Op::SameSet => "false",
            _ => "0",
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s.push_str("}\n");
    s
}

/// The plausible cheat: identical weighted linking and correct answers, but
/// the component tally never shrinks - every merge quietly forgets to
/// decrement the count.
pub fn forgotten_decrement_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(DSU_NEW_SRC);
    s.push_str("impl Dsu {\n");
    for &op in &ops {
        if op == Op::Union {
            let body = &[
                "let ra = self.root(a);",
                "let rb = self.root(b);",
                "if ra == rb {",
                "    return false;",
                "}",
                "if self.size[ra as usize] < self.size[rb as usize] {",
                "    self.parent[ra as usize] = rb;",
                "    self.size[rb as usize] += self.size[ra as usize];",
                "} else {",
                "    self.parent[rb as usize] = ra;",
                "    self.size[ra as usize] += self.size[rb as usize];",
                "}",
                "true",
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

pub struct UnionFindFamily;

impl Generator for UnionFindFamily {
    fn id(&self) -> &'static str {
        "union-find"
    }

    fn category(&self) -> &'static str {
        "disjoint-set"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("union-find", seed);
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
            id: format!("union-find/{seed:016x}"),
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
        s.push_str(DSU_NEW_SRC);
        s.push_str("impl Dsu {\n");
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
            (
                "forgotten-decrement".to_string(),
                forgotten_decrement_src(spec),
            ),
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
        let a = UnionFindFamily.generate(55);
        let b = UnionFindFamily.generate(55);
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
            let d = driven_dsu(10, warmup);
            assert!((1..=10).contains(&d.count()));
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let d = driven_dsu(ex.n, ex.warmup);
                let c = d.count();
                assert!(c >= 1 && c <= ex.n);
                assert!(ex.warmup >= 2);
                assert!(ex.n >= 2 && ex.n < 25);
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct DsuRef"));
            assert!(
                src.matches("DsuRef {").count() >= 2,
                "constructor body must be renamed too"
            );
            assert!(!src.contains("pub fn union"));
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
            let canary = mint_canary("union-find", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in ["count -= 1", ".size[", "partition_point"] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("shared a root"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("DsuRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soaks() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            let scripted = spec.ops.contains(&Op::Union) && spec.ops.contains(&Op::ComponentCount);
            let soak = spec.ops.contains(&Op::Union) && spec.ops.contains(&Op::SizeOf);
            assert_eq!(
                behavior.contains("scripted_merges_shrink_the_component_tally"),
                scripted,
                "seed {seed}: scripted probe misaligned"
            );
            assert_eq!(
                behavior.contains("fill_soak_pins_member_counts_to_a_shadow_partition"),
                soak,
                "seed {seed}: shadow soak misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_partition_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let cheat = forgotten_decrement_src(spec);
        assert!(!cz.contains("todo!()"));
        assert!(cheat.contains("fn union"));
        let us = cheat.find("fn union").unwrap();
        let ue = us + cheat[us..].find("\n}\n").unwrap();
        let ub = &cheat[us..ue];
        assert!(
            ub.contains("self.parent[ra"),
            "cheat must keep the linking real"
        );
        assert!(ub.contains("true"));
        assert!(!ub.contains("-= 1"), "the forgotten decrement is the bug");
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("union-find", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
