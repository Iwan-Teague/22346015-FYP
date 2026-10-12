//! The `trie` family (category `prefix-indexing`) — deterministic
//! prefix-tree puzzles where *shared structure* is the data structure.
//!
//! Every puzzle mirrors an ordered byte trie: `insert` walks and extends
//! child chains, allocating one node per unseen byte, `contains` demands
//! the terminal flag (a mere path is not a word), `is_prefix` only asks
//! whether the walk survives, and `trie_words`/`trie_nodes` expose the
//! two counters any shortcut distorts. The seed picks which two of five
//! ops are required: `trie_words`, `insert`, `contains`, `is_prefix`,
//! `trie_nodes`. Sharing a prefix must allocate once — every cheat
//! re-walks or re-allocates and the counters notice.

#[derive(Clone, Default)]
pub struct TrieNode {
    terminal: bool,
    /// Child edges sorted by byte so traversal order is deterministic.
    children: Vec<(u8, TrieNode)>,
}

/// One ordered byte trie. `nodes` counts the root, so a fresh trie has
/// exactly one node and zero words.
#[derive(Clone, Default)]
pub struct TrieInstance {
    root: TrieNode,
    words: u64,
    nodes: u64,
}

impl TrieInstance {
    pub fn new() -> Self {
        TrieInstance {
            root: TrieNode::default(),
            words: 0,
            nodes: 1,
        }
    }

    /// How many words the trie currently stores.
    pub fn trie_words(&self) -> u64 {
        self.words
    }

    /// How many nodes the trie currently holds, root included.
    pub fn trie_nodes(&self) -> u64 {
        self.nodes
    }

    fn slot_of(node: &TrieNode, byte: u8) -> Result<usize, usize> {
        node.children.binary_search_by(|(b, _)| b.cmp(&byte))
    }

    /// Inserts `word`, returning how many nodes were freshly allocated.
    /// A word that was already present allocates nothing; a word that
    /// merely extends existing prefixes (e.g. `band` after `ban`) also
    /// allocates nothing but still grows the stored-word count.
    pub fn insert(&mut self, word: &[u8]) -> u64 {
        let mut fresh = 0u64;
        let mut cursor = &mut self.root;
        for &byte in word {
            match Self::slot_of(cursor, byte) {
                Ok(idx) => cursor = &mut cursor.children[idx].1,
                Err(pos) => {
                    cursor.children.insert(pos, (byte, TrieNode::default()));
                    cursor = &mut cursor.children[pos].1;
                    fresh += 1;
                    self.nodes += 1;
                }
            }
        }
        if !cursor.terminal {
            cursor.terminal = true;
            self.words += 1;
        }
        fresh
    }

    /// True only when `word` was inserted verbatim — a shared path
    /// without its own terminal flag does not count.
    pub fn contains(&self, word: &[u8]) -> bool {
        let mut cursor = &self.root;
        for &byte in word {
            match Self::slot_of(cursor, byte) {
                Ok(idx) => cursor = &cursor.children[idx].1,
                Err(_) => return false,
            }
        }
        cursor.terminal
    }

    /// True when some stored word starts with `prefix`; the empty
    /// prefix always matches.
    pub fn is_prefix(&self, prefix: &[u8]) -> bool {
        let mut cursor = &self.root;
        for &byte in prefix {
            match Self::slot_of(cursor, byte) {
                Ok(idx) => cursor = &cursor.children[idx].1,
                Err(_) => return false,
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn insert_then_contains_roundtrips() {
        let mut t = TrieInstance::new();
        assert_eq!(t.trie_words(), 0);
        assert_eq!(t.trie_nodes(), 1);
        for word in [&b"car"[..], &b"card"[..], &b"care"[..]] {
            t.insert(word);
            assert!(t.contains(word));
        }
        assert!(!t.contains(b"ca"));
        assert!(!t.contains(b"cars"));
        assert!(t.is_prefix(b"ca"));
    }

    #[test]
    fn duplicate_insert_allocates_nothing_new() {
        let mut t = TrieInstance::new();
        let first = t.insert(b"cab");
        assert_eq!(first, 3);
        assert_eq!(t.insert(b"cab"), 0);
        assert_eq!(t.insert(b"cab"), 0);
        assert_eq!(t.trie_words(), 1);
        assert_eq!(t.trie_nodes(), 4);
    }

    #[test]
    fn shared_prefix_counts_nodes_once() {
        let mut t = TrieInstance::new();
        assert_eq!(t.insert(b"ab"), 2);
        assert_eq!(t.insert(b"ac"), 1);
        assert_eq!(t.trie_words(), 2);
        assert_eq!(t.trie_nodes(), 4);
    }

    #[test]
    fn prefix_promotion_adds_word_without_new_nodes() {
        let mut t = TrieInstance::new();
        t.insert(b"band");
        let promoted = t.insert(b"ban");
        assert_eq!(promoted, 0);
        assert_eq!(t.trie_words(), 2);
        assert_eq!(t.trie_nodes(), 5);
        assert!(t.contains(b"ban"));
        assert!(t.contains(b"band"));
    }

    #[test]
    fn empty_word_is_root_terminal_and_empty_prefix_always_matches() {
        let mut t = TrieInstance::new();
        assert!(t.is_prefix(b""));
        assert_eq!(t.insert(b""), 0);
        assert!(t.contains(b""));
        assert_eq!(t.trie_words(), 1);
        assert_eq!(t.trie_nodes(), 1);
    }

    fn shadow_prefixes(words: &BTreeSet<Vec<u8>>) -> BTreeSet<Vec<u8>> {
        let mut prefixes = BTreeSet::new();
        for word in words {
            for end in 1..=word.len() {
                prefixes.insert(word[..end].to_vec());
            }
        }
        prefixes
    }

    #[test]
    fn soak_matches_a_shadow_set_under_random_traffic() {
        let mut t = TrieInstance::new();
        let mut shadow: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut st: u64 = 0x5EED_7BEE;
        for _ in 0..500u64 {
            st = st
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let draw = st >> 33;
            let alpha = 4u64;
            let len = (draw % 4) + 1;
            let word: Vec<u8> = (0..len)
                .map(|i| b'a' + ((draw >> (3 * i)) % alpha) as u8)
                .collect();
            t.insert(&word);
            shadow.insert(word.clone());
            assert_eq!(t.trie_words(), shadow.len() as u64);
            assert_eq!(t.trie_nodes(), shadow_prefixes(&shadow).len() as u64 + 1);
        }
        for word in &shadow {
            assert!(t.contains(word));
        }
        for probe in [&b"aazz"[..], &b"dddd"[..], &b"bb"[..]] {
            assert_eq!(t.contains(probe), shadow.contains(probe));
        }
    }
}

use crate::{mint_canary, GeneratedTask, Generator, Rng};

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    TrieWords,
    Insert,
    Contains,
    IsPrefix,
    TrieNodes,
}

pub const OP_ALL: [Op; 5] = [
    Op::TrieWords,
    Op::Insert,
    Op::Contains,
    Op::IsPrefix,
    Op::TrieNodes,
];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::TrieWords => "trie_words",
            Op::Insert => "insert",
            Op::Contains => "contains",
            Op::IsPrefix => "is_prefix",
            Op::TrieNodes => "trie_nodes",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::TrieWords => "answers how many distinct words the trie currently stores",
            Op::Insert => "extends the tree with word and answers how many nodes were freshly allocated",
            Op::Contains => "answers whether word was stored verbatim; a shared path alone is not enough",
            Op::IsPrefix => "answers whether any stored word starts with prefix; the empty prefix always matches",
            Op::TrieNodes => "answers how many nodes the trie holds, root included",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::TrieWords => "pub fn trie_words(&self) -> u64",
            Op::Insert => "pub fn insert(&mut self, word: &[u8]) -> u64",
            Op::Contains => "pub fn contains(&self, word: &[u8]) -> bool",
            Op::IsPrefix => "pub fn is_prefix(&self, prefix: &[u8]) -> bool",
            Op::TrieNodes => "pub fn trie_nodes(&self) -> u64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub const CANONICAL_SEED: u64 = 0x7BE5_FA11;

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

/// Insert is the fill primitive every scenario needs; when the seed did
/// not sample it, it ships as given infrastructure alongside the pair.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    if spec.ops.contains(&Op::Insert) {
        spec.ops.to_vec()
    } else {
        let mut v = vec![Op::Insert];
        v.extend_from_slice(&spec.ops);
        v
    }
}

/// The canonical scenario: an alphabet of five bytes hammered by dozens
/// of pseudo-random inserts, so shared prefixes collide early and any
/// solution that miscounts a fresh node or skips a terminal flag is
/// wrong before the first probe.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical trie scenario");
}

fn fresh_trie() -> TrieInstance {
    TrieInstance::new()
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub alpha: u64,
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01B0;

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![
        ExampleCase {
            alpha: 5,
            warmup: canonical(seed),
        },
        ExampleCase {
            alpha: 2,
            warmup: 3,
        },
        ExampleCase {
            alpha: 3,
            warmup: 4,
        },
        ExampleCase {
            alpha: 6,
            warmup: 17,
        },
    ];
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    for _ in 0..8 {
        let alpha = 2 + rng.below(5);
        out.push(ExampleCase {
            alpha,
            warmup: rng.below(alpha * 20) + 1,
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

/// Derives the insert word for one draw: length 1-4, bytes drawn from
/// `alpha` letters starting at `a`. Emitted tests re-derive this inline.
fn word_of(value: u64, alpha: u64) -> Vec<u8> {
    let len = (value % 4) + 1;
    (0..len)
        .map(|i| b'a' + ((value >> (3 * i)) % alpha) as u8)
        .collect()
}

/// The drive's LCG state after `warmup` draws. Emitted tests re-derive
/// this to probe one step past the end of the warmup.
fn drive_base(alpha: u64, warmup: u64) -> u64 {
    let mut s = 0x7BE5_CAFE ^ alpha.wrapping_mul(0x9E37).wrapping_add(warmup);
    for _ in 0..warmup {
        s = s.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    }
    s
}

/// Drives `warmup` pseudo-random inserts into a fresh trie over an
/// `alpha`-letter alphabet; short words make prefix collisions frequent.
fn driven_trie(alpha: u64, warmup: u64) -> (TrieInstance, Vec<Vec<u8>>) {
    let mut t = fresh_trie();
    let mut st = 0x7BE5_CAFE ^ alpha.wrapping_mul(0x9E37).wrapping_add(warmup);
    let mut inserted = Vec::new();
    for _ in 0..warmup {
        let v = nxt(&mut st);
        let word = word_of(v, alpha);
        t.insert(&word);
        inserted.push(word);
    }
    (t, inserted)
}

// ---- emitted-source fragments -----------------------------------------------

pub const STRUCT_SRC: &str = "#[derive(Clone, Default)]\npub struct TrieNode {\n    terminal: bool,\n    children: Vec<(u8, TrieNode)>,\n}\n\n#[derive(Clone, Default)]\npub struct Trie {\n    root: TrieNode,\n    words: u64,\n    nodes: u64,\n}\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::TrieWords => &["self.words"],
        Op::TrieNodes => &["self.nodes"],
        Op::Insert => &[
            "let mut fresh = 0u64;",
            "let mut walk = &mut self.root;",
            "for &byte in word {",
            "    match walk.children.binary_search_by(|(b, _)| b.cmp(&byte)) {",
            "        Ok(idx) => walk = &mut walk.children[idx].1,",
            "        Err(pos) => {",
            "            walk.children.insert(pos, (byte, TrieNode::default()));",
            "            walk = &mut walk.children[pos].1;",
            "            fresh += 1;",
            "            self.nodes += 1;",
            "        }",
            "    }",
            "}",
            "if !walk.terminal {",
            "    walk.terminal = true;",
            "    self.words += 1;",
            "}",
            "fresh",
        ],
        Op::Contains => &[
            "let mut walk = &self.root;",
            "for &byte in word {",
            "    match walk.children.binary_search_by(|(b, _)| b.cmp(&byte)) {",
            "        Ok(idx) => walk = &walk.children[idx].1,",
            "        Err(_) => return false,",
            "    }",
            "}",
            "walk.terminal",
        ],
        Op::IsPrefix => &[
            "let mut walk = &self.root;",
            "for &byte in prefix {",
            "    match walk.children.binary_search_by(|(b, _)| b.cmp(&byte)) {",
            "        Ok(idx) => walk = &walk.children[idx].1,",
            "        Err(_) => return false,",
            "    }",
            "}",
            "true",
        ],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub const TRIE_NEW_SRC: &str = "impl Trie {\n    pub fn new() -> Self {\n        Trie {\n            root: TrieNode::default(),\n            words: 0,\n            nodes: 1,\n        }\n    }\n}\n\n";

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen("pub struct Trie {", "pub struct TrieRef {", 1);
    s.push_str(
        &TRIE_NEW_SRC
            .replace("impl Trie {", "impl TrieRef {")
            .replace("Trie {\n", "TrieRef {\n"),
    );
    s.push_str("impl TrieRef {\n");
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
        let (t, _) = driven_trie(ex.alpha, ex.warmup);
        s.push_str(&format!(
            "//! ex{i}: alphabet of {a} bytes, then {n} pseudo-random inserts -> {w} words / {nd} nodes\n",
            i = i,
            a = ex.alpha,
            n = ex.warmup,
            w = t.trie_words(),
            nd = t.trie_nodes()
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested trie operations over one byte-wise\n\
         //! prefix tree. Inserts extend shared paths one node at a time;\n\
         //! queries distinguish exact stored words from mere prefixes.\n\
         //! The hidden tests drive thousands of interleaved operations\n\
         //! and compare every returned value.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(TRIE_NEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested trie operations over one byte-wise prefix tree.\n\nRequirements:\n- `Trie::new()` starts with the root only: zero stored words and exactly one node.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- Walk from the root one byte at a time; extend the tree with one freshly allocated node per unseen byte. How children are organized is up to you - only returned values and counters are checked.\n- Re-inserting a stored word allocates nothing; a word that only extends already-stored words promotes to a word without allocating new nodes.\n- A shared path without its own end-of-word marker is not a word for `contains`; the empty prefix always matches, and inserting the empty word marks the root itself.\n- `trie_words` counts distinct stored words; `trie_nodes` counts every node including the root. No unsafe code; standard library only.\n\nSignatures:\n```rust\n");
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
        "use task::Trie;\n\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\nfn wof(value: u64, alpha: u64) -> Vec<u8> {\n    let len = (value % 4) + 1;\n    (0..len).map(|i| b'a' + ((value >> (3 * i)) % alpha) as u8).collect()\n}\n\n",
    );
    for (i, ex) in examples.iter().enumerate() {
        let (h, _) = driven_trie(ex.alpha, ex.warmup);
        // Draw the probe arguments exactly one step past the warmup.
        let mut ps = drive_base(ex.alpha, ex.warmup);
        let words_now = h.trie_words();
        let nodes_now = h.trie_nodes();
        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let mut drive = Trie::new();\n    let mut st: u64 = 0x7BE5_CAFE ^ ({a}u64.wrapping_mul(0x9E37).wrapping_add({n}));\n    for _ in 0..{n} {{\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        drive.insert(&wof(st >> 33, {a}));\n    }}\n",
            i = i,
            a = ex.alpha,
            n = ex.warmup
        ));
        for &op in &spec.ops {
            s.push_str("    let mut r = drive.clone();\n");
            match op {
                Op::TrieWords => {
                    s.push_str(&format!("    assert_eq!(r.trie_words(), {words_now});\n"));
                }
                Op::TrieNodes => {
                    s.push_str(&format!("    assert_eq!(r.trie_nodes(), {nodes_now});\n"));
                }
                Op::Insert => {
                    let v = nxt(&mut ps);
                    let want = h.clone().insert(&word_of(v, ex.alpha));
                    s.push_str(&format!(
                        "    assert_eq!(r.insert(&wof({v}, {a})), {want});\n",
                        a = ex.alpha
                    ));
                }
                Op::Contains => {
                    let v = nxt(&mut ps);
                    let want = h.contains(&word_of(v, ex.alpha));
                    s.push_str(&format!(
                        "    assert_eq!(r.contains(&wof({v}, {a})), {want});\n",
                        a = ex.alpha
                    ));
                }
                Op::IsPrefix => {
                    let v = nxt(&mut ps);
                    let want = h.is_prefix(&word_of(v, ex.alpha));
                    s.push_str(&format!(
                        "    assert_eq!(r.is_prefix(&wof({v}, {a})), {want});\n",
                        a = ex.alpha
                    ));
                    // The empty prefix always matches — pinned literally.
                    s.push_str("    assert!(r.is_prefix(b\"\"));\n");
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Scripted terminal-flag probe: `ban` shares band's path and must
    // NOT answer contains until promoted — a solution that conflates
    // paths with words trips immediately. Uses only insert/contains so
    // it ships whenever both ops are present.
    if spec.ops.contains(&Op::Insert) && spec.ops.contains(&Op::Contains) {
        s.push_str("#[test]\nfn scripted_terminal_flag_separates_words_from_prefixes() {\n    let mut r = Trie::new();\n    assert_eq!(r.insert(b\"band\"), 4);\n    assert!(!r.contains(b\"ban\"));\n    assert_eq!(r.insert(b\"ban\"), 0);\n    assert!(r.contains(b\"ban\"));\n    assert!(r.contains(b\"band\"));\n    assert_eq!(r.insert(b\"bar\"), 1);\n    assert!(!r.contains(b\"ba\"));\n}\n");
    }
    // Fill soak: random inserts must keep the node counter pinned to an
    // incrementally maintained shadow set of all stored words.
    if spec.ops.contains(&Op::Insert) && spec.ops.contains(&Op::TrieNodes) {
        s.push_str("#[test]\nfn fill_soak_tracks_the_shadow_node_count() {\n    let mut r = Trie::new();\n    let mut seen: std::collections::BTreeSet<Vec<u8>> = std::collections::BTreeSet::new();\n    let mut st: u64 = 0x5EED_0000_0000_01B2;\n    for _ in 0..500u64 {\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        let word = wof(st >> 33, 4);\n        r.insert(&word);\n        seen.insert(word);\n        let mut prefixes = std::collections::BTreeSet::new();\n        for w in &seen {\n            for end in 1..=w.len() {\n                prefixes.insert(w[..end].to_vec());\n            }\n        }\n        assert_eq!(r.trie_nodes(), prefixes.len() as u64 + 1);\n    }\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::Trie;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n/// Differential queries use long words over a seven-letter alphabet:\n/// the word universe is far too large to saturate, so a path that\n/// survives without its own end-of-word flag shows up constantly.\nfn wq(value: u64) -> Vec<u8> {\n    let len = (value % 12) + 1;\n    (0..len).map(|i| b'a' + ((value >> (3 * i)) % 7) as u8).collect()\n}\n");
    let ops = effective_ops(spec);
    s.push_str("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {\n    let mut cand = Trie::new();\n    let mut refr = TrieRef::new();\n");
    if ops.contains(&Op::Insert) {
        s.push_str("    assert_eq!(cand.insert(&wq(7777)), refr.ref_insert(&wq(7777)));\n");
    }
    if ops.contains(&Op::Contains) {
        s.push_str("    assert_eq!(cand.contains(&wq(9999)), refr.ref_contains(&wq(9999)));\n");
    }
    if ops.contains(&Op::IsPrefix) {
        s.push_str("    assert_eq!(cand.is_prefix(&wq(8888)), refr.ref_is_prefix(&wq(8888)));\n");
        s.push_str("    assert_eq!(cand.is_prefix(b\"\"), refr.ref_is_prefix(b\"\"));\n");
    }
    if ops.contains(&Op::TrieWords) {
        s.push_str("    assert_eq!(cand.trie_words(), refr.ref_trie_words());\n");
    }
    if ops.contains(&Op::TrieNodes) {
        s.push_str("    assert_eq!(cand.trie_nodes(), refr.ref_trie_nodes());\n");
    }
    let arm_count = ops.len();
    s.push_str(&format!("    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_01B0;\n    for _ in 0..3000 {{\n        let arg = nx(&mut state);\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in ops.iter().enumerate() {
        let body = match op {
            Op::Insert => "{ let word = wq(arg); assert_eq!(cand.insert(&word), refr.ref_insert(&word)); }".to_string(),
            Op::Contains => "{ let word = wq(arg); assert_eq!(cand.contains(&word), refr.ref_contains(&word)); }".to_string(),
            Op::IsPrefix => "{ let word = wq(arg); assert_eq!(cand.is_prefix(&word), refr.ref_is_prefix(&word)); }".to_string(),
            Op::TrieWords => "assert_eq!(cand.trie_words(), refr.ref_trie_words());".to_string(),
            Op::TrieNodes => "assert_eq!(cand.trie_nodes(), refr.ref_trie_nodes());".to_string(),
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
    s.push_str(TRIE_NEW_SRC);
    s.push_str("impl Trie {\n");
    for &op in &ops {
        let body = match op {
            Op::TrieWords | Op::Insert | Op::TrieNodes => "0",
            Op::Contains | Op::IsPrefix => "false",
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s.push_str("}\n");
    s
}

/// The plausible no-sharing cheat: identical API and counters, but
/// `insert` appends a brand-new child for every byte instead of looking
/// up existing ones — shared prefixes are never reused. Singleton
/// roundtrips still look right; the freshly-allocated count, the node
/// counter, and every walk over a duplicated path diverge immediately.
pub fn no_share_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(TRIE_NEW_SRC);
    s.push_str("impl Trie {\n");
    for &op in &ops {
        if op == Op::Insert {
            let body = &[
                "let mut fresh = 0u64;",
                "let mut walk = &mut self.root;",
                "for &byte in word {",
                "    walk.children.push((byte, TrieNode::default()));",
                "    let next = walk.children.len() - 1;",
                "    walk = &mut walk.children[next].1;",
                "    fresh += 1;",
                "    self.nodes += 1;",
                "}",
                "if !walk.terminal {",
                "    walk.terminal = true;",
                "    self.words += 1;",
                "}",
                "fresh",
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

pub struct TrieFamily;

impl Generator for TrieFamily {
    fn id(&self) -> &'static str {
        "trie"
    }

    fn category(&self) -> &'static str {
        "prefix-indexing"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("trie", seed);
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
            id: format!("trie/{seed:016x}"),
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
        s.push_str(TRIE_NEW_SRC);
        s.push_str("impl Trie {\n");
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
            ("no-share".to_string(), no_share_src(spec)),
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
        let a = TrieFamily.generate(55);
        let b = TrieFamily.generate(55);
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
            let (t, inserted) = driven_trie(5, warmup);
            assert_eq!(inserted.len(), warmup as usize);
            assert!(t.trie_words() >= 1 && t.trie_words() <= warmup);
            assert!(t.trie_nodes() > 1 && t.trie_nodes() <= 4 * warmup + 1);
            assert!(t.contains(&inserted[inserted.len() - 1]));
            assert!(t.is_prefix(&inserted[0][..1]));
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let (t, inserted) = driven_trie(ex.alpha, ex.warmup);
                assert!(t.trie_words() <= ex.warmup);
                assert!(t.contains(&inserted[inserted.len() - 1]));
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct TrieRef"));
            assert!(!src.contains("pub fn insert"));
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
            let canary = mint_canary("trie", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in ["binary_search", "children.insert(", "cursor"] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("prefix"));
            assert!(prompt.contains("freshly allocated"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("TrieRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soaks() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            let scripted = spec.ops.contains(&Op::Insert) && spec.ops.contains(&Op::Contains);
            let pins = spec.ops.contains(&Op::Insert) && spec.ops.contains(&Op::TrieNodes);
            assert_eq!(
                behavior.contains("scripted_terminal_flag_separates_words_from_prefixes"),
                scripted,
                "seed {seed}: terminal soak misaligned"
            );
            assert_eq!(
                behavior.contains("fill_soak_tracks_the_shadow_node_count"),
                pins,
                "seed {seed}: node soak misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_trie_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let single = no_share_src(spec);
        assert!(!cz.contains("wrapping_mul"));
        assert!(single.contains("fn insert"));
        let ins = single.find("fn insert").unwrap();
        let ie = ins + single[ins..].find("\n}\n").unwrap();
        let ib = &single[ins..ie];
        assert!(
            ib.contains("children.push("),
            "cheat must re-allocate every byte"
        );
        assert!(
            !ib.contains("binary_search"),
            "cheat must skip the dedup lookup"
        );
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("trie", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
