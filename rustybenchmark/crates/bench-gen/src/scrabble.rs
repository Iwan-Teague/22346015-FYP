//! The `scrabble` family (category `letter-values`) — probing a seeded
//! lowercase word through the standard English tile-value table.
//!
//! Where `brackets` scans balance and `caesar` shifts letters, this family
//! exercises **lookup-table aggregation**: mapping every character through
//! one fixed value ladder and reducing it different ways. One-pointers are
//! `{a,e,i,l,n,o,r,s,t,u}`, two-pointers `{d,g}`, three-pointers
//! `{b,c,m,p}`, four-pointers `{f,h,v,w,y}`, five for `k`, eight for
//! `{j,x}`, ten for `{q,z}`. The seed prunes which two of five query ops
//! are required: `first_tile_value`, `word_score`, `max_tile_value`,
//! `vowel_score`, `has_rare_tile`. C(5,2) = **10 distinct skills**, above
//! the diversity floor; op names are semantic.
//!
//! The canonical word is sampled until its anchor facts hold: nonempty, it
//! holds at least one rare high-value tile, all four numeric answers are
//! nonzero and mutually distinct. That makes `const-zero` wrong on every
//! answer there — including the boolean, because a rare tile is present —
//! and makes `first-everything` wrong on the other three scalars; its
//! `false` rare-flag also dies mid-canonical.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential fuzzes
//! 3000 random words against the model.
//!
//! Trivial baselines: `const-zero` (zeroes and a false flag everywhere) and
//! `first-everything` (every scalar answered with the leading tile's value).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    FirstTileValue,
    WordScore,
    MaxTileValue,
    VowelScore,
    HasRareTile,
}

const OP_ALL: [Op; 5] = [
    Op::FirstTileValue,
    Op::WordScore,
    Op::MaxTileValue,
    Op::VowelScore,
    Op::HasRareTile,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::FirstTileValue => "first_tile_value",
            Op::WordScore => "word_score",
            Op::MaxTileValue => "max_tile_value",
            Op::VowelScore => "vowel_score",
            Op::HasRareTile => "has_rare_tile",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::FirstTileValue => {
                "the value of the first character of the word under the \
                 tile table; zero for an empty word"
            }
            Op::WordScore => "the sum of the values of every character in the word",
            Op::MaxTileValue => {
                "the highest single-character value appearing anywhere in \
                 the word; zero for an empty word"
            }
            Op::VowelScore => {
                "the combined value of the vowel characters (a, e, i, o, \
                 u) in the word; zero when none appear"
            }
            Op::HasRareTile => {
                "whether the word contains any of the four rarest letters \
                 j, q, x, or z — the tiles worth eight or ten points"
            }
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::HasRareTile => "bool",
            _ => "i64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Spec {
    ops: [Op; 2],
}

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let i1 = rng.below(5);
    let mut i2 = rng.below(5);
    while i2 == i1 {
        i2 = rng.below(5);
    }
    Spec {
        ops: [OP_ALL[i1 as usize], OP_ALL[i2 as usize]],
    }
}
// ---- native mirror (the answer; identical shape to the emitted code) ------

/// The tile table itself, shared by the native queries.
fn letter_value(c: u8) -> i64 {
    match c {
        b'd' | b'g' => 2,
        b'b' | b'c' | b'm' | b'p' => 3,
        b'f' | b'h' | b'v' | b'w' | b'y' => 4,
        b'k' => 5,
        b'j' | b'x' => 8,
        b'q' | b'z' => 10,
        c if c.is_ascii_lowercase() => 1,
        _ => 0,
    }
}

fn b_first_tile_value(text: &str) -> i64 {
    text.as_bytes().first().map_or(0, |&c| letter_value(c))
}

fn b_word_score(text: &str) -> i64 {
    text.as_bytes().iter().map(|&c| letter_value(c)).sum()
}

fn b_max_tile_value(text: &str) -> i64 {
    text.as_bytes()
        .iter()
        .map(|&c| letter_value(c))
        .max()
        .unwrap_or(0)
}

fn b_vowel_score(text: &str) -> i64 {
    text.as_bytes()
        .iter()
        .filter(|&&c| matches!(c, b'a' | b'e' | b'i' | b'o' | b'u'))
        .map(|&c| letter_value(c))
        .sum()
}

fn b_has_rare_tile(text: &str) -> bool {
    text.as_bytes().iter().any(|&c| letter_value(c) >= 8)
}

/// The answer shape: numeric queries as `Num`, the rarity flag as `Flag`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Flag(bool),
}

impl Out {
    fn lit(self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            Out::Flag(b) => b.to_string(),
        }
    }
}

fn op_eval(op: Op, text: &str) -> Out {
    match op {
        Op::FirstTileValue => Out::Num(b_first_tile_value(text)),
        Op::WordScore => Out::Num(b_word_score(text)),
        Op::MaxTileValue => Out::Num(b_max_tile_value(text)),
        Op::VowelScore => Out::Num(b_vowel_score(text)),
        Op::HasRareTile => Out::Flag(b_has_rare_tile(text)),
    }
}

// ---- canonical word ----------------------------------------------------------

const CANONICAL_SEED: u64 = 0x5CA8_BB1E;

/// Uniform random lowercase word.
fn rand_word(rng: &mut Rng) -> String {
    let n = 1 + rng.below(9);
    let mut s = String::new();
    for _ in 0..n {
        s.push((b'a' + rng.below(26) as u8) as char);
    }
    s
}

/// The canonical word: sampled and retried until the anchor facts hold.
///
/// Guaranteed for every seed: nonempty, holds a rare high-value tile (so
/// `has_rare_tile` is true and every zero-answering cheat dies on the flag
/// directly), and all four numeric answers are nonzero and mutually
/// distinct — which also kills `first-everything` on the other three
/// scalars.
fn canonical(seed: u64) -> String {
    let mut rng = Rng::new(seed ^ CANONICAL_SEED);
    for _ in 0..100_000 {
        let w = rand_word(&mut rng);
        if anchors_hold(&w) {
            return w;
        }
    }
    unreachable!("canonical word sampling failed to satisfy anchors");
}

fn anchors_hold(word: &str) -> bool {
    let first = b_first_tile_value(word);
    let score = b_word_score(word);
    let max = b_max_tile_value(word);
    let vowel = b_vowel_score(word);
    !word.is_empty()
        && b_has_rare_tile(word)
        && first != 0
        && score != 0
        && max != 0
        && vowel != 0
        && first != score
        && first != max
        && first != vowel
        && score != max
        && score != vowel
        && max != vowel
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (String, Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0158;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    let push = |cases: &mut Vec<ExampleCase>, c: &str| {
        cases.push((
            c.to_string(),
            spec.ops.map(|op| (op, op_eval(op, c))).to_vec(),
        ));
    };
    // Canonical word first.
    push(&mut cases, &canonical(seed));
    // Empty: every query answers zero; the rarity flag is vacuously false,
    // flipping any constant-true cheat.
    push(&mut cases, "");
    // The classic rare pair: q and z both carry ten points.
    push(&mut cases, "quiz");
    for _ in 0..3 {
        let w = rand_word(&mut rng);
        push(&mut cases, &w);
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site — a quoted string.
fn render_text(t: &str) -> String {
    format!("{t:?}")
}

/// The tile-table match shared by the emitted bodies. Built by string
/// concatenation because the arms are brace-heavy.
fn tile_match_src() -> &'static str {
    "match c {\n                b'd' | b'g' => 2,\n                b'b' | b'c' | b'm' | b'p' => 3,\n                b'f' | b'h' | b'v' | b'w' | b'y' => 4,\n                b'k' => 5,\n                b'j' | b'x' => 8,\n                b'q' | b'z' => 10,\n                c if c.is_ascii_lowercase() => 1,\n                _ => 0,\n            }"
}

/// Emitted body for a plain whole-word reduction over the tile table.
/// `head` is the leading iterator chain, `tail` the closing reducer.
fn reduce_body(head: &[&str], tail: &[&str]) -> String {
    let mut s = String::new();
    for l in head {
        s.push_str(l);
        s.push('\n');
    }
    s.push_str("        .map(|&c| ");
    s.push_str(tile_match_src());
    s.push_str(")\n");
    for l in tail {
        s.push_str(l);
        s.push('\n');
    }
    s
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    let body = match op {
        Op::FirstTileValue => {
            let mut s = String::new();
            s.push_str("    text\n");
            s.push_str("        .as_bytes()\n");
            s.push_str("        .first()\n");
            s.push_str("        .map(|&c| ");
            s.push_str(tile_match_src());
            s.push_str(")\n");
            s.push_str("        .unwrap_or(0)\n");
            s
        }
        Op::WordScore => reduce_body(
            &["    text", "        .as_bytes()", "        .iter()"],
            &["        .sum()"],
        ),
        Op::MaxTileValue => reduce_body(
            &["    text", "        .as_bytes()", "        .iter()"],
            &["        .max()", "        .unwrap_or(0)"],
        ),
        Op::VowelScore => {
            let mut s = String::new();
            s.push_str("    text\n");
            s.push_str("        .as_bytes()\n");
            s.push_str("        .iter()\n");
            s.push_str("        .filter(|&&c| matches!(c, b'a' | b'e' | b'i' | b'o' | b'u'))\n");
            s.push_str("        .map(|&c| ");
            s.push_str(tile_match_src());
            s.push_str(")\n");
            s.push_str("        .sum()\n");
            s
        }
        Op::HasRareTile => {
            let mut s = String::new();
            s.push_str("    text\n");
            s.push_str("        .as_bytes()\n");
            s.push_str("        .iter()\n");
            s.push_str("        .any(|&c| matches!(c, b'j' | b'q' | b'x' | b'z'))\n");
            s
        }
    };
    format!("pub fn {name}(text: &str) -> {ret} {{\n{body}}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(text: &str) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(text: &str) -> {}", op.name(), op.ret())
}

fn reference_src(spec: &Spec) -> String {
    spec.ops.iter().map(|op| op_fn_src(*op)).collect()
}

/// The call expression for one op in an emitted assertion.
fn call_src(op: Op, var: &str) -> String {
    format!("{}({})", op.name(), var)
}
fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for (t, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  text {}  ->  {}\n", render_text(&t), results));
    }
    s
}
fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples_prose(spec, seed)
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    let fns = spec.ops.map(op_stub_src).concat();
    format!(
        "//! Implement the two query functions below.\n\
         //!\n\
         //! Examples:\n\
         {doc}\n\
         {fns}",
        doc = doc,
        fns = fns,
    )
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let mut reqs = String::new();
    for op in spec.ops {
        reqs.push_str(&format!("- `{}`: {}.\n", op.name(), op.prose()));
    }
    format!(
        "Implement the two query functions in `src/lib.rs`. The input is \
         one lowercase word `text` of type `&str`. Score every character \
         with the standard English tile table: the letters a, e, i, l, n, \
         o, r, s, t, and u are worth one point; d and g two; b, c, m, and \
         p three; f, h, v, w, and y four; k five; j and x eight; q and z \
         ten. Any character outside that alphabet scores zero.\n\
         \n\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         - One pass over the characters is enough for every query here.\n\
         - Work with exact integer arithmetic only.\n\
         \n\
         Signatures:\n\
         ```rust\n\
         {signatures}\
         ```\n\
         \n\
         Examples:\n\
         {examples}\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        reqs = reqs,
        signatures = spec
            .ops
            .iter()
            .map(|op| format!("{}\n", op_sig_src(*op)))
            .collect::<Vec<_>>()
            .join(""),
        examples = worked_examples_prose(spec, seed),
        canary = canary,
    )
}

fn cargo_toml() -> String {
    "[package]\n\
     name = \"task\"\n\
     version = \"0.0.0\"\n\
     edition = \"2021\"\n\
     \n\
     [lib]\n\
     path = \"src/lib.rs\"\n\
     \n\
     [workspace]\n"
        .to_string()
}
fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let imports = spec
        .ops
        .iter()
        .map(|op| op.name())
        .collect::<Vec<_>>()
        .join(", ");
    let mut body = format!("use task::{{{imports}}};\n\n");
    for (i, (t, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let text = {}.to_string();\n",
            render_text(t),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "&text"),
                out.lit(),
            ));
        }
        body.push_str("}\n\n");
    }
    body
}

/// The differential's reference — the two selected ops, pasted into the test
/// file under `ref_*` names.
fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec)
        .replacen(
            &format!("pub fn {}", spec.ops[0].name()),
            &format!("fn ref_{}", spec.ops[0].name()),
            1,
        )
        .replacen(
            &format!("pub fn {}", spec.ops[1].name()),
            &format!("fn ref_{}", spec.ops[1].name()),
            1,
        );
    let asserts = spec
        .ops
        .iter()
        .map(|op| {
            let call = call_src(*op, "&word");
            format!("        assert_eq!({call}, ref_{call});\n")
        })
        .collect::<Vec<_>>()
        .join("");
    let mut s = String::new();
    s.push_str(&format!(
        "use task::{{{}}};\n\n",
        spec.ops
            .iter()
            .map(|op| op.name())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    s.push_str(&reference);
    s.push_str("fn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n");
    s.push_str("#[test]\nfn differential_vs_reference() {\n    let mut state: u64 = 0xE7EE_ED00_0000_0158;\n    for _ in 0..3000 {\n");
    s.push_str("        let mut word = String::new();\n        let n = (nx(&mut state) % 8) + 1;\n        for _ in 0..n {\n            word.push((b'a' + (nx(&mut state) % 26) as u8) as char);\n        }\n");
    s.push_str(&asserts);
    s.push_str("    }\n}\n");
    s
}
/// Degenerate: zero answers everywhere.
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            let tail = match op.ret() {
                "bool" => "false",
                _ => "0",
            };
            format!("{sig} {{\n    let _ = text;\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every scalar with the leading tile's value.
/// The canonical anchors keep the other three scalars distinct from it, so
/// it is wrong there; its `false` rarity flag also dies mid-canonical
/// because the canonical word always holds a rare tile.
fn first_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            if op.ret() == "bool" {
                format!("{sig} {{\n    false\n}}\n")
            } else {
                format!(
                    "{sig} {{\n    text\n        .as_bytes()\n        .first()\n        .map(|&c| {tile_match})\n        .unwrap_or(0)\n}}\n",
                    tile_match = tile_match_src()
                )
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct ScrabbleFamily;

impl Generator for ScrabbleFamily {
    fn id(&self) -> &str {
        "scrabble"
    }
    fn category(&self) -> &str {
        "letter-values"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("scrabble", seed);

        let mut files = BTreeMap::new();
        files.insert(PathBuf::from("Cargo.toml"), cargo_toml());
        files.insert(PathBuf::from("src/lib.rs"), skeleton_src(&spec, seed));

        let mut hidden = BTreeMap::new();
        hidden.insert(
            PathBuf::from("tests/behavior.rs"),
            behavior_test_src(&spec, seed),
        );
        hidden.insert(
            PathBuf::from("tests/differential.rs"),
            differential_test_src(&spec),
        );

        GeneratedTask {
            id: format!("scrabble/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure table lookups — no unsafe anywhere near it.
            max_unsafe: None,
            forbidden_paths: Vec::new(),
            check_clippy: false,
            clippy_allow: Vec::new(),
            // Default oracle weights (docs/04).
            weights: (0.70, 0.20, 0.10),
        }
    }

    fn reference_code(&self, seed: u64) -> String {
        reference_src(&sample(seed))
    }
    fn skeleton_code(&self, seed: u64) -> String {
        skeleton_src(&sample(seed), seed)
    }
    fn trivial_baselines(&self, seed: u64) -> Vec<(String, String)> {
        let spec = sample(seed);
        vec![
            ("const-zero".to_string(), const_zero(&spec)),
            ("first-everything".to_string(), first_everything(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let mut names: Vec<&str> = sample(seed).ops.iter().map(|op| op.name()).collect();
        names.sort_unstable();
        vec![format!("q:{}/{}", names[0], names[1])]
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = ScrabbleFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // The tile table, pinned independently of the helper.
        assert_eq!(letter_value(b'q'), 10);
        assert_eq!(letter_value(b'z'), 10);
        assert_eq!(letter_value(b'j'), 8);
        assert_eq!(letter_value(b'd'), 2);
        assert_eq!(letter_value(b'a'), 1);
        assert_eq!(letter_value(b'k'), 5);
        assert_eq!(letter_value(b'?'), 0, "unknown characters score zero");
        // Leading tile.
        assert_eq!(b_first_tile_value("quiz"), 10);
        assert_eq!(b_first_tile_value(""), 0);
        // Whole-word totals.
        assert_eq!(b_word_score("quiz"), 22); // 10+1+1+10
        assert_eq!(b_word_score("dog"), 5); // 2+1+2
        assert_eq!(b_word_score(""), 0);
        // Best single tile.
        assert_eq!(b_max_tile_value("jinx"), 8);
        assert_eq!(b_max_tile_value("aeiou"), 1);
        assert_eq!(b_max_tile_value(""), 0);
        // Vowel-only totals.
        assert_eq!(b_vowel_score("aeiou"), 5);
        assert_eq!(b_vowel_score("bcdfg"), 0);
        assert_eq!(b_vowel_score("quiz"), 2); // u and i only
                                              // Rarity is exactly the j/q/x/z club — a five-pointer like k is
                                              // high-value but common, so the boundary sits between 5 and 8.
        assert!(b_has_rare_tile("quiz"));
        assert!(b_has_rare_tile("jinx"));
        assert!(!b_has_rare_tile("hello"));
        assert!(
            !b_has_rare_tile("kite"),
            "k scores five but is not a rare tile"
        );
        assert!(!b_has_rare_tile(""));
    }

    #[test]
    fn seeds_vary_query_pairs() {
        let mut sigs = std::collections::HashSet::new();
        for seed in 0..300u64 {
            sigs.insert(sample(seed));
        }
        // C(5,2) = 10 unordered pairs; demand near-full coverage.
        assert!(
            sigs.len() >= 9,
            "expected wide query-pair variety, got {}",
            sigs.len()
        );
    }

    #[test]
    fn canonical_answers_are_non_degenerate_for_every_op() {
        // `const-zero` fails on every answer at the canonical: all four
        // numeric results are nonzero and distinct, and the rarity flag is
        // true there. `first-everything` fails on the other three scalars —
        // its answer agrees only on `first_tile_value` itself (documented
        // skip) — and its `false` rarity flag dies mid-canonical too.
        for seed in 0..200u64 {
            let w = canonical(seed);
            let first = b_first_tile_value(&w);
            let score = b_word_score(&w);
            let max = b_max_tile_value(&w);
            let vowel = b_vowel_score(&w);
            assert!(!w.is_empty(), "seed {seed}");
            assert!(b_has_rare_tile(&w), "seed {seed}");
            for v in [first, score, max, vowel] {
                assert_ne!(v, 0, "const-zero survives at {w} seed {seed}");
            }
            assert_ne!(first, score, "first cheat survives at {w} seed {seed}");
            assert_ne!(first, max, "seed {seed}");
            assert_ne!(first, vowel, "seed {seed}");
            assert_ne!(score, max, "seed {seed}");
            assert_ne!(score, vowel, "seed {seed}");
            assert_ne!(max, vowel, "seed {seed}");
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (t, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, &t), out, "seed {seed}");
                }
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        for seed in [0u64, 1, 2] {
            let spec = sample(seed);
            let src = reference_src(&spec);
            for op in OP_ALL {
                // Match the `pub fn` line so no bare-name substring leaks.
                let fn_line = format!("pub fn {}(", op.name());
                if spec.ops.contains(&op) {
                    assert!(src.contains(&fn_line));
                } else {
                    assert!(!src.contains(&fn_line), "{op:?} leaked");
                }
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        for seed in [0u64, 1, 2] {
            let spec = sample(seed);
            let sk = skeleton_src(&spec, seed);
            assert!(sk.contains("todo!()"), "skeleton must be stubbed");
            // Solution-shaped leak tokens must stay out of the skeleton.
            assert!(!sk.contains("match c"));
            assert!(!sk.contains("matches!"));
            assert!(!sk.contains("as_bytes"));
            assert!(!sk.contains(".filter("));
            assert!(!sk.contains(".any("));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("match c"));
            assert!(!p.contains("matches!"));
            assert!(!p.contains("as_bytes"));
            assert!(!p.contains(".filter("));
            assert!(!p.contains(".any("));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every op here is unary: no call site may carry a comma.
        for op in OP_ALL {
            let call = call_src(op, "&text");
            let sig = op_sig_src(op);
            assert_eq!(
                call.matches(',').count(),
                sig.matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{sig}`"
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = ScrabbleFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
