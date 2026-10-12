//! Skip-list natives: a deterministic multi-level ordered map. Promotion
//! is not random - each key's tower height is derived from its own hashed
//! bits, so the same key always climbs to the same level and every level
//! stays a sorted subsequence of the base list.

use std::collections::BTreeMap;

pub const MAX_HEIGHT: usize = 8;

#[derive(Clone, Default)]
pub struct SkipListInstance {
    /// levels[0] holds every entry; level i > 0 holds the promoted subset.
    levels: Vec<BTreeMap<u64, u64>>,
}

impl SkipListInstance {
    pub fn new() -> Self {
        Self {
            levels: vec![BTreeMap::new(); MAX_HEIGHT],
        }
    }

    /// Deterministic tower height: trailing zero bits of the hashed key,
    /// capped so at least one key must land purely on the base level.
    fn height_of(key: u64) -> usize {
        let h = key.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        (h.trailing_zeros() as usize + 1).min(MAX_HEIGHT)
    }

    pub fn skip_len(&self) -> u64 {
        self.levels[0].len() as u64
    }

    /// Insert or overwrite; answers the displaced value (None when fresh).
    /// The key joins every level up to its deterministic height.
    pub fn set(&mut self, key: u64, value: u64) -> Option<u64> {
        let displaced = self.levels[0].insert(key, value);
        for lvl in self.levels.iter_mut().take(Self::height_of(key)) {
            lvl.insert(key, value);
        }
        displaced
    }

    pub fn get(&self, key: u64) -> Option<u64> {
        self.levels[0].get(&key).copied()
    }

    /// The greatest stored key that does not exceed `key`; None when every
    /// stored key is larger.
    pub fn floor_key(&self, key: u64) -> Option<u64> {
        self.levels[0].range(..=key).next_back().map(|(k, _)| *k)
    }

    /// The highest occupied level index; 0 on an empty list.
    pub fn top_level(&self) -> u64 {
        for (i, lvl) in self.levels.iter().enumerate().rev() {
            if !lvl.is_empty() {
                return i as u64;
            }
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_roundtrips_and_reports_displacement() {
        let mut s = SkipListInstance::new();
        assert_eq!(s.set(5, 50), None);
        assert_eq!(s.set(9, 90), None);
        assert_eq!(s.get(5), Some(50));
        assert_eq!(s.set(5, 55), Some(50));
        assert_eq!(s.get(5), Some(55));
        assert_eq!(s.get(6), None);
        assert_eq!(s.skip_len(), 2);
    }

    #[test]
    fn duplicate_set_never_grows_the_list() {
        let mut s = SkipListInstance::new();
        for v in 0..10u64 {
            s.set(3, v * 7);
            assert_eq!(s.skip_len(), 1);
        }
        assert_eq!(s.get(3), Some(63));
    }

    #[test]
    fn floor_key_answers_the_greatest_key_not_past_the_probe() {
        let mut s = SkipListInstance::new();
        for k in [4u64, 12, 20] {
            s.set(k, k * 100);
        }
        assert_eq!(s.floor_key(3), None);
        assert_eq!(s.floor_key(4), Some(4));
        assert_eq!(s.floor_key(11), Some(4));
        assert_eq!(s.floor_key(12), Some(12));
        assert_eq!(s.floor_key(999), Some(20));
    }

    #[test]
    fn promotion_is_deterministic_per_key() {
        let mut s = SkipListInstance::new();
        s.set(7, 1);
        let h = s.top_level();
        for _ in 0..5 {
            let mut again = SkipListInstance::new();
            again.set(7, 1);
            assert_eq!(again.top_level(), h);
        }
        // A tall tower exists somewhere among a spread of keys.
        let mut spread = SkipListInstance::new();
        for k in 0..200u64 {
            spread.set(k * 37 + 11, k);
        }
        assert!(spread.top_level() >= 2, "no promotions across 200 keys");
        assert!(h >= 1 || spread.top_level() >= 1);
    }

    #[test]
    fn higher_levels_hold_only_promoted_subsets() {
        let mut s = SkipListInstance::new();
        for k in 0..32u64 {
            s.set(k * 13 + 5, k);
        }
        let top = s.top_level() as usize;
        for lvl in 1..=top {
            for &k in s.levels[lvl].keys() {
                assert!(s.levels[lvl - 1].contains_key(&k));
                assert_eq!(s.levels[lvl][&k], s.levels[0][&k]);
            }
            assert!(s.levels[lvl].len() <= s.levels[lvl - 1].len());
        }
    }

    #[test]
    fn towers_reach_exactly_their_formula_heights() {
        let mut s = SkipListInstance::new();
        let mut tallest = 0usize;
        let mut capped_seen = false;
        for k in 0..600u64 {
            let key = k * 37 + 11;
            s.set(key, k);
            let h = SkipListInstance::height_of(key);
            tallest = tallest.max(h);
            if h == MAX_HEIGHT {
                capped_seen = true;
            }
            for lvl in 0..MAX_HEIGHT {
                assert_eq!(
                    s.levels[lvl].contains_key(&key),
                    lvl < h,
                    "key {key} sits on level {lvl} but its height is {h}"
                );
            }
        }
        assert!(capped_seen, "no key reached the height cap");
        assert_eq!(s.top_level(), tallest as u64 - 1);
    }

    #[test]
    fn soak_matches_a_shadow_map_under_random_traffic() {
        use std::collections::BTreeMap;
        let mut shadow: BTreeMap<u64, u64> = BTreeMap::new();
        let mut s = SkipListInstance::new();
        let mut st: u64 = 0x5EED_5A11;
        for _ in 0..600 {
            let k = (st >> 33) % 60;
            let v = (st >> 7) % 500;
            let want = shadow.insert(k, v);
            assert_eq!(s.set(k, v), want);
            assert_eq!(s.skip_len(), shadow.len() as u64);
            assert_eq!(
                s.get((st >> 41) % 60),
                shadow.get(&((st >> 41) % 60)).copied()
            );
            let probe = (st >> 17) % 70;
            assert_eq!(
                s.floor_key(probe),
                shadow.range(..=probe).next_back().map(|(k, _)| *k)
            );
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
    SkipLen,
    Set,
    Get,
    FloorKey,
    TopLevel,
}

pub const OP_ALL: [Op; 5] = [Op::SkipLen, Op::Set, Op::Get, Op::FloorKey, Op::TopLevel];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::SkipLen => "skip_len",
            Op::Set => "set",
            Op::Get => "get",
            Op::FloorKey => "floor_key",
            Op::TopLevel => "top_level",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::SkipLen => "answers how many distinct keys the base level holds",
            Op::Set => "inserts or overwrites one key: the key joins every level up to its deterministic tower height and the displaced value is answered (None when the key was fresh)",
            Op::Get => "answers the value stored at a key, or None when the key is absent",
            Op::FloorKey => "answers the greatest stored key that does not exceed the probe, or None when every stored key is larger",
            Op::TopLevel => "answers the highest occupied level index, or 0 on an empty list",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::SkipLen => "pub fn skip_len(&self) -> u64",
            Op::Set => "pub fn set(&mut self, key: u64, value: u64) -> Option<u64>",
            Op::Get => "pub fn get(&self, key: u64) -> Option<u64>",
            Op::FloorKey => "pub fn floor_key(&self, key: u64) -> Option<u64>",
            Op::TopLevel => "pub fn top_level(&self) -> u64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub const CANONICAL_SEED: u64 = 0x5A11_FA11;

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

/// Set is the fill primitive and TopLevel is the audit probe; both ship as
/// given infrastructure alongside the sampled pair, so a solution that
/// stores into a flat base list without promoting any key drifts on tower
/// queries no matter which pair was drawn - a promotion-skipping cheat is
/// invisible to get/skip_len alone.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    let mut v = vec![Op::Set];
    if !spec.ops.contains(&Op::TopLevel) {
        v.push(Op::TopLevel);
    }
    for o in spec.ops {
        if !v.contains(&o) {
            v.push(o);
        }
    }
    v
}

/// The canonical scenario: dozens of sets over a span wide enough that
/// promotions, overwrites and floor probes all show up repeatedly.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical skip-list scenario");
}

fn fresh_skiplist() -> SkipListInstance {
    SkipListInstance::new()
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub span: u64,
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01E0;

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![
        ExampleCase {
            span: 30,
            warmup: canonical(seed),
        },
        ExampleCase { span: 5, warmup: 3 },
        ExampleCase { span: 9, warmup: 4 },
        ExampleCase {
            span: 18,
            warmup: 17,
        },
    ];
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    for _ in 0..8 {
        let span = 4 + rng.below(27);
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
    0x5A11_CAFEu64 ^ span.wrapping_mul(0x9E37).wrapping_add(warmup)
}

/// Drives `warmup` random sets into a fresh list; each drawn key stores
/// the derived value `key * 7 + 3`.
fn driven_skiplist(span: u64, warmup: u64) -> SkipListInstance {
    let mut s = fresh_skiplist();
    let mut st = drive_init(span, warmup);
    for _ in 0..warmup {
        let k = (st >> 33) % span;
        s.set(k, k * 7 + 3);
        st = st.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    }
    s
}

/// The probe-continuation state after the drive loop (one advance per set).
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

pub const STRUCT_SRC: &str = "#[derive(Clone)]\npub struct SkipList {\n    levels: Vec<std::collections::BTreeMap<u64, u64>>,\n}\n";

pub const LIST_NEW_SRC: &str = "impl SkipList {\n    pub fn new() -> Self {\n        SkipList {\n            levels: vec![std::collections::BTreeMap::new(); 8],\n        }\n    }\n\n    fn tower_height(key: u64) -> usize {\n        let h = key.wrapping_mul(0x9E37_79B9_7F4A_7C15);\n        (h.trailing_zeros() as usize + 1).min(8)\n    }\n}\n\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

const SET_BODY: &[&str] = &[
    "let displaced = self.levels[0].insert(key, value);",
    "for lvl in self.levels.iter_mut().take(Self::tower_height(key)) {",
    "    lvl.insert(key, value);",
    "}",
    "displaced",
];

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::SkipLen => &["self.levels[0].len() as u64"],
        Op::Set => SET_BODY,
        Op::Get => &["self.levels[0].get(&key).copied()"],
        Op::FloorKey => &["self.levels[0]\n    .range(..=key)\n    .next_back()\n    .map(|(k, _)| *k)"],
        Op::TopLevel => &[
            "self.levels",
            "    .iter()\n    .enumerate()\n    .rev()\n    .find(|(_, lvl)| !lvl.is_empty())\n    .map_or(0, |(i, _)| i as u64)",
        ],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen("pub struct SkipList {", "pub struct SkipListRef {", 1);
    s.push_str(
        &LIST_NEW_SRC
            .replace("impl SkipList {", "impl SkipListRef {")
            .replace("SkipList {\n", "SkipListRef {\n"),
    );
    s.push_str("impl SkipListRef {\n");
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
        let t = driven_skiplist(ex.span, ex.warmup);
        s.push_str(&format!(
            "//! ex{i}: {w} set keys below {span} -> holds {l}, top level {t}, floor of {span} {f}\n",
            i = i,
            w = ex.warmup,
            span = ex.span,
            l = t.skip_len(),
            t = t.top_level(),
            f = opt_fmt(t.floor_key(ex.span)),
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested ordered-map operations over one internal\n\
         //! multi-level structure: every entry lives on the base level, keys\n\
         //! are additionally promoted onto higher levels by their own hashed\n\
         //! bits, and each higher level holds a sorted subset of the one below.\n\
         //! The hidden tests drive thousands of interleaved operations and\n\
         //! compare every returned value.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(LIST_NEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested multi-level ordered-map operations with exactly maintained bookkeeping.\n\nRequirements:\n- `SkipList::new()` starts with eight empty levels; the constructor and the tower-height helper are given.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- Level 0 holds every entry; a stored key is copied onto every level whose index is below its tower height, so each higher level is a sorted subset of the level beneath it and every copy carries the same value.\n- The tower height of a key is one plus the count of its hashed trailing zero bits - hash the key by multiplying with 0x9E37_79B9_7F4A_7C15 - capped at eight; the same key always climbs to the same height.\n- Overwriting keeps the tower shape, replaces the value on every level the key occupies, and answers the displaced value; queries never mutate the list.\n- No floating point; no unsafe code; standard library only.\n\nSignatures:\n```rust\n");
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
    let mut s = String::from("use task::SkipList;\n\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n");
    for (i, ex) in examples.iter().enumerate() {
        let h = driven_skiplist(ex.span, ex.warmup);
        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let mut drive = SkipList::new();\n    let mut st: u64 = {init};\n    for _ in 0..{w} {{\n        let k = (st >> 33) % {span}u64;\n        drive.set(k, k * 7 + 3);\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    }}\n",
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
                Op::SkipLen => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.skip_len(), {});\n",
                        h.skip_len()
                    ));
                }
                Op::TopLevel => {
                    s.push_str(&format!(
                        "    assert_eq!(drive.top_level(), {});\n",
                        h.top_level()
                    ));
                }
                Op::Get => {
                    let k = nx(&mut ps) % ex.span;
                    let want = h.get(k);
                    s.push_str(&format!(
                        "    let r = drive.clone();\n    let k = nx(&mut ps) % {span}u64;\n    assert_eq!(r.get(k), {want});\n",
                        span = ex.span,
                        want = opt_fmt(want)
                    ));
                }
                Op::FloorKey => {
                    let k = nx(&mut ps) % ex.span;
                    let want = h.floor_key(k);
                    s.push_str(&format!(
                        "    let r = drive.clone();\n    let k = nx(&mut ps) % {span}u64;\n    assert_eq!(r.floor_key(k), {want});\n",
                        span = ex.span,
                        want = opt_fmt(want)
                    ));
                }
                Op::Set => {
                    let k = nx(&mut ps) % ex.span;
                    let want = h.clone().set(k, k * 7 + 3);
                    s.push_str(&format!(
                        "    let mut r = drive.clone();\n    let k = nx(&mut ps) % {span}u64;\n    assert_eq!(r.set(k, k * 7 + 3), {want});\n",
                        span = ex.span,
                        want = opt_fmt(want)
                    ));
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Scripted probe: overwrites answer the displaced value and reads see
    // only the newest value on every level of the key's tower.
    if spec.ops.contains(&Op::Set) && spec.ops.contains(&Op::Get) {
        s.push_str("#[test]\nfn scripted_overwrite_answers_the_displaced_value() {\n    let mut r = SkipList::new();\n    assert_eq!(r.set(5, 50), None);\n    assert_eq!(r.get(5), Some(50));\n    assert_eq!(r.set(5, 55), Some(50));\n    assert_eq!(r.get(5), Some(55));\n}\n");
    }
    // Scripted probe: floor walks the ordered base list.
    if spec.ops.contains(&Op::Set) && spec.ops.contains(&Op::FloorKey) {
        s.push_str("#[test]\nfn scripted_floor_walks_the_ordered_base() {\n    let mut r = SkipList::new();\n    r.set(4, 400);\n    r.set(12, 1200);\n    r.set(20, 2000);\n    assert_eq!(r.floor_key(3), None);\n    assert_eq!(r.floor_key(11), Some(4));\n    assert_eq!(r.floor_key(12), Some(12));\n    assert_eq!(r.floor_key(999), Some(20));\n}\n");
    }
    // Fill soak: six hundred random sets must keep every tower pinned to a
    // shadow of per-level maps.
    if spec.ops.contains(&Op::Set) && spec.ops.contains(&Op::TopLevel) {
        s.push_str("#[test]\nfn fill_soak_keeps_towers_pinned_to_a_shadow() {\n    use std::collections::BTreeMap;\n    let mut r = SkipList::new();\n    let mut shadow: Vec<BTreeMap<u64, u64>> = vec![BTreeMap::new(); 8];\n    let mut st: u64 = 0x5EED_0000_0000_01E2;\n    for _ in 0..600usize {\n        let k = (st >> 33) % 45;\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        r.set(k, k * 7 + 3);\n        let hh = ((k.wrapping_mul(0x9E37_79B9_7F4A_7C15).trailing_zeros() as usize) + 1).min(8);\n        for lvl in shadow.iter_mut().take(hh) {\n            lvl.insert(k, k * 7 + 3);\n        }\n        let want_top = shadow\n            .iter()\n            .enumerate()\n            .rev()\n            .find(|(_, m)| !m.is_empty())\n            .map_or(0, |(i, _)| i as u64);\n        assert_eq!(r.top_level(), want_top);\n    }\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::SkipList;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    let ops = effective_ops(spec);
    s.push_str("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {\n    let mut cand = SkipList::new();\n    let mut refr = SkipListRef::new();\n");
    if ops.contains(&Op::SkipLen) {
        s.push_str("    assert_eq!(cand.skip_len(), refr.ref_skip_len());\n");
    }
    if ops.contains(&Op::Get) {
        s.push_str("    assert_eq!(cand.get(7777), refr.ref_get(7777));\n");
    }
    if ops.contains(&Op::FloorKey) {
        s.push_str("    assert_eq!(cand.floor_key(7777), refr.ref_floor_key(7777));\n");
    }
    if ops.contains(&Op::TopLevel) {
        s.push_str("    assert_eq!(cand.top_level(), refr.ref_top_level());\n");
    }
    if ops.contains(&Op::Set) {
        for _ in 0..12u64 {
            let k = nx(&mut 0x5A11_D1FF) % 29;
            let v = k * 7 + 3;
            s.push_str(&format!(
                "    assert_eq!(cand.set({k}, {v}), refr.ref_set({k}, {v}));\n"
            ));
        }
        if ops.contains(&Op::FloorKey) {
            let fk = nx(&mut 0x5A11_D1FF) % 35;
            s.push_str(&format!(
                "    assert_eq!(cand.floor_key({fk}), refr.ref_floor_key({fk}));\n"
            ));
        }
        if ops.contains(&Op::TopLevel) {
            s.push_str("    assert_eq!(cand.top_level(), refr.ref_top_level());\n");
        }
    }
    let arm_count = ops.len();
    s.push_str(&format!("    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_01E0;\n    for _ in 0..3000 {{\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in ops.iter().enumerate() {
        let body = match op {
            Op::SkipLen => "assert_eq!(cand.skip_len(), refr.ref_skip_len());".to_string(),
            Op::Set => "let k = nx(&mut state) % 29;\n            let v = nx(&mut state) % 97;\n            assert_eq!(cand.set(k, v), refr.ref_set(k, v));".to_string(),
            Op::Get => "let k = nx(&mut state) % 35;\n            assert_eq!(cand.get(k), refr.ref_get(k));".to_string(),
            Op::FloorKey => "let k = nx(&mut state) % 35;\n            assert_eq!(cand.floor_key(k), refr.ref_floor_key(k));".to_string(),
            Op::TopLevel => "assert_eq!(cand.top_level(), refr.ref_top_level());".to_string(),
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
    s.push_str(LIST_NEW_SRC);
    s.push_str("impl SkipList {\n");
    for &op in &ops {
        let body = match op {
            Op::Set | Op::Get | Op::FloorKey => "None",
            _ => "0",
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s.push_str("}\n");
    s
}

/// The plausible cheat: sets land on the base level only - values and
/// displacement stay honest, but no key is ever promoted so the tower
/// collapses to a flat list.
pub fn flat_list_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(LIST_NEW_SRC);
    s.push_str("impl SkipList {\n");
    for &op in &ops {
        match op {
            Op::Set => {
                let body = &[
                    "let displaced = self.levels[0].insert(key, value);",
                    "displaced",
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

pub struct SkipListFamily;

impl Generator for SkipListFamily {
    fn id(&self) -> &'static str {
        "skip-list"
    }

    fn category(&self) -> &'static str {
        "layered-indexing"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("skip-list", seed);
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
            id: format!("skip-list/{seed:016x}"),
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
        s.push_str(LIST_NEW_SRC);
        s.push_str("impl SkipList {\n");
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
            ("flat-list".to_string(), flat_list_src(spec)),
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
        let a = SkipListFamily.generate(55);
        let b = SkipListFamily.generate(55);
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
            let t = driven_skiplist(30, warmup);
            assert!(t.skip_len() <= 30);
            assert!(t.top_level() < MAX_HEIGHT as u64);
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let t = driven_skiplist(ex.span, ex.warmup);
                assert!(t.skip_len() <= ex.span);
                assert!(ex.warmup >= 2);
                assert!(ex.span >= 4 && ex.span < 31);
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct SkipListRef"));
            assert!(
                src.matches("SkipListRef {").count() >= 2,
                "constructor body must be renamed too"
            );
            assert!(!src.contains("pub fn set"));
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
            let canary = mint_canary("skip-list", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in ["next_back(", ".range("] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("tower"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("SkipListRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soaks() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            let disp_gate = spec.ops.contains(&Op::Set) && spec.ops.contains(&Op::Get);
            let floor_gate = spec.ops.contains(&Op::Set) && spec.ops.contains(&Op::FloorKey);
            let soak_gate = spec.ops.contains(&Op::Set) && spec.ops.contains(&Op::TopLevel);
            assert_eq!(
                behavior.contains("scripted_overwrite_answers_the_displaced_value"),
                disp_gate,
                "seed {seed}: displacement script misaligned"
            );
            assert_eq!(
                behavior.contains("scripted_floor_walks_the_ordered_base"),
                floor_gate,
                "seed {seed}: floor script misaligned"
            );
            assert_eq!(
                behavior.contains("fill_soak_keeps_towers_pinned_to_a_shadow"),
                soak_gate,
                "seed {seed}: tower soak misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_indexing_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let cheat = flat_list_src(spec);
        assert!(!cz.contains("todo!()"));
        assert!(cheat.contains("fn set"));
        let us = cheat.find("fn set").unwrap();
        let ue = us + cheat[us..].find("\n}\n").unwrap();
        let ub = &cheat[us..ue];
        assert!(
            ub.contains("levels[0].insert"),
            "cheat must keep base storage honest"
        );
        assert!(
            !ub.contains("tower_height"),
            "the missing promotion is the bug"
        );
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("skip-list", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
