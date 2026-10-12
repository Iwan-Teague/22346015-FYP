//! The `text-stats` family (category `text-analysis`) — character- and
//! word-level statistics over one seeded text sample.
//!
//! Where `str-transform` reshapes strings and `string-processing` slices
//! them, this family measures them: word count, vowel count, the longest
//! word's length, distinct-character count, and total length. The domain
//! is one `&str` of lowercase ASCII words separated by single spaces
//! (ops tolerate arbitrary whitespace); every op is a pure function of
//! it. The seed prunes which two of five query ops are required:
//! `word_count`, `vowel_count`, `longest_word_len`, `distinct_chars`,
//! `char_count`. C(5,2) = **10 distinct skills**, above the diversity
//! floor; op names are semantic.
//!
//! The canonical text is sampled until every scalar answer is nonzero
//! and pairwise distinct, so `const-zero` fails everywhere and the
//! `total-length-everything` cheat (every query answered with the whole
//! text's length) is exact only on `char_count` itself; any pair
//! carrying it is caught by its partner, and pairs without it are wrong
//! twice over.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random texts against the model.
//!
//! Trivial baselines: `const-zero` (fails outright on the canonical
//! text) and `total-length-everything` (every query answered with the
//! text's total length).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    WordCount,
    VowelCount,
    LongestWordLen,
    DistinctChars,
    CharCount,
}

const OP_ALL: [Op; 5] = [
    Op::WordCount,
    Op::VowelCount,
    Op::LongestWordLen,
    Op::DistinctChars,
    Op::CharCount,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::WordCount => "word_count",
            Op::VowelCount => "vowel_count",
            Op::LongestWordLen => "longest_word_len",
            Op::DistinctChars => "distinct_chars",
            Op::CharCount => "char_count",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::WordCount => "how many whitespace-separated words the text holds",
            Op::VowelCount => {
                "how many vowels the text holds (the letters a, e, i, \
                 o, u — case-insensitive)"
            }
            Op::LongestWordLen => {
                "the length of the longest whitespace-separated word \
                 (zero for empty text)"
            }
            Op::DistinctChars => {
                "how many distinct characters appear anywhere in the \
                 text"
            }
            Op::CharCount => "the total number of characters, including spaces",
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

fn b_word_count(text: &str) -> i64 {
    text.split_whitespace().count() as i64
}

fn b_vowel_count(text: &str) -> i64 {
    text.chars()
        .filter(|c| matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u'))
        .count() as i64
}

fn b_longest_word_len(text: &str) -> i64 {
    text.split_whitespace()
        .map(|w| w.chars().count())
        .max()
        .unwrap_or(0) as i64
}

fn b_distinct_chars(text: &str) -> i64 {
    let mut seen = [false; 256];
    for c in text.bytes() {
        seen[c as usize] = true;
    }
    seen.into_iter().filter(|&s| s).count() as i64
}

fn b_char_count(text: &str) -> i64 {
    text.chars().count() as i64
}

/// One op's answer. All five ops return scalars here, so `Out` is a
/// plain alias — no flag variant needed.
type Out = i64;

fn op_eval(op: Op, text: &str) -> Out {
    match op {
        Op::WordCount => b_word_count(text),
        Op::VowelCount => b_vowel_count(text),
        Op::LongestWordLen => b_longest_word_len(text),
        Op::DistinctChars => b_distinct_chars(text),
        Op::CharCount => b_char_count(text),
    }
}

// ---- canonical input --------------------------------------------------------

/// Sample a lowercase-ASCII text of single-space-separated words.
fn rand_text(rng: &mut Rng) -> String {
    let words = 1 + rng.below(5);
    let mut parts: Vec<String> = Vec::new();
    for _ in 0..words {
        let wl = 1 + rng.below(7);
        let mut w = String::new();
        for _ in 0..wl {
            w.push((b'a' + rng.below(26) as u8) as char);
        }
        parts.push(w);
    }
    parts.join(" ")
}

const CANONICAL_SEED: u64 = 0x7E47_57A7;

/// The canonical text: sampled until every scalar answer is nonzero and
/// pairwise distinct across `[word_count, vowel_count,
/// longest_word_len, distinct_chars]`, with the total length outside
/// that set too (automatic once a space is present, but pinned anyway).
fn canonical(seed: u64) -> String {
    let mut rng = Rng::new(seed ^ CANONICAL_SEED);
    for _ in 0..100_000 {
        let text = rand_text(&mut rng);
        if anchors_hold(&text) {
            return text;
        }
    }
    unreachable!("canonical input sampling failed to satisfy anchors");
}

fn anchors_hold(text: &str) -> bool {
    let answers = [
        op_eval(Op::WordCount, text),
        op_eval(Op::VowelCount, text),
        op_eval(Op::LongestWordLen, text),
        op_eval(Op::DistinctChars, text),
    ];
    let total = op_eval(Op::CharCount, text);
    total > 0
        && !answers.contains(&0)
        && answers.iter().all(|a| *a != total)
        && (0..4).all(|i| (i + 1..4).all(|j| answers[i] != answers[j]))
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = (String, Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0132;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    let push = |cases: &mut Vec<ExampleCase>, text: String| {
        cases.push((
            text.clone(),
            spec.ops.map(|op| (op, op_eval(op, &text))).to_vec(),
        ));
    };
    // Canonical text first.
    let can = canonical(seed);
    push(&mut cases, can);
    // Empty text: zero conventions everywhere.
    push(&mut cases, String::new());
    // Solo word.
    push(&mut cases, "solo".to_string());
    // No vowels at all.
    push(&mut cases, "rhythm bcdfg".to_string());
    for _ in 0..3 {
        let t = rand_text(&mut rng);
        push(&mut cases, t);
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site: a quoted string literal.
fn render_text(t: &str) -> String {
    format!("{t:?}")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let sig = "(text: &str) -> i64";
    let body = match op {
        Op::WordCount => "text.split_whitespace().count() as i64".to_string(),
        Op::VowelCount => [
            "text.chars()",
            "    .filter(|c| matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u'))",
            "    .count() as i64",
        ]
        .join("\n    "),
        Op::LongestWordLen => [
            "text.split_whitespace()",
            "    .map(|w| w.chars().count())",
            "    .max()",
            "    .unwrap_or(0) as i64",
        ]
        .join("\n    "),
        Op::DistinctChars => [
            "let mut seen = [false; 256];",
            "for c in text.bytes() {",
            "    seen[c as usize] = true;",
            "}",
            "seen.into_iter().filter(|&s| s).count() as i64",
        ]
        .join("\n    "),
        Op::CharCount => "text.chars().count() as i64".to_string(),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(text: &str) -> i64 {{\n    todo!()\n}}\n",
        op.name()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!("pub fn {}(text: &str) -> i64", op.name())
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
    for (text, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("  text {}  ->  {}\n", render_text(&text), results));
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
         one text sample: a borrowed string slice of lowercase ASCII \
         words separated by single spaces; queries are character- and \
         word-level statistics of the text. Handle the empty string and \
         whitespace runs gracefully.\n\
         \n\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
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
    for (i, (text, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let text = {};\n",
            render_text(text),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "text"),
                out
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
            let call = call_src(*op, "&text");
            format!("        assert_eq!({call}, ref_{call});\n")
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "use task::{{{imports}}};\n\
         \n\
         {reference}\
         fn nx(state: &mut u64) -> u64 {{\n\
         \x20   *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20   *state >> 33\n\
         }}\n\
         \n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0132;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let mut text = String::new();\n\
         \x20       let n = (nx(&mut state) % 24 + 1) as usize;\n\
         \x20       for _ in 0..n {{\n\
         \x20           // One draw in seven is a space; the rest are\n\
         \x20           // lowercase letters.\n\
         \x20           if nx(&mut state) % 7 == 0 {{\n\
         \x20               text.push(' ');\n\
         \x20           }} else {{\n\
         \x20               text.push((b'a' + (nx(&mut state) % 26) as u8) as char);\n\
         \x20           }}\n\
         \x20       }}\n\
         {asserts}\
         \x20   }}\n\
         }}\n",
        imports = spec
            .ops
            .iter()
            .map(|op| op.name())
            .collect::<Vec<_>>()
            .join(", "),
        reference = reference,
        asserts = asserts,
    )
}
/// Degenerate: everything zero.
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            format!("{sig} {{\n    let _ = text;\n    0\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every query with the text's total
/// length. The canonical anchors keep the other four answers away from
/// it; `char_count` itself is exact, and any pair containing it is
/// caught by its partner.
fn total_length_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            format!("{sig} {{\n    text.chars().count() as i64\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct TextStatsFamily;

impl Generator for TextStatsFamily {
    fn id(&self) -> &str {
        "text-stats"
    }
    fn category(&self) -> &str {
        "text-analysis"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("text-stats", seed);

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
            id: format!("text-stats/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure string bookkeeping — no unsafe anywhere near it.
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
            (
                "total-length-everything".to_string(),
                total_length_everything(&spec),
            ),
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
        let g = TextStatsFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Word count collapses whitespace runs.
        assert_eq!(b_word_count("the quick brown fox"), 4);
        assert_eq!(b_word_count("a  b"), 2);
        assert_eq!(b_word_count(""), 0);
        // Vowels, case-insensitively.
        assert_eq!(b_vowel_count("the quick brown fox"), 5);
        assert_eq!(b_vowel_count("rhythm"), 0);
        assert_eq!(b_vowel_count("AbE"), 2);
        // Longest word, not necessarily first.
        assert_eq!(b_longest_word_len("the quick brown fox"), 5);
        assert_eq!(b_longest_word_len("hi there"), 5);
        assert_eq!(b_longest_word_len(""), 0);
        // Distinct characters collapse repeats; spaces count.
        assert_eq!(b_distinct_chars("banana"), 3);
        assert_eq!(b_distinct_chars("a a"), 2);
        assert_eq!(b_distinct_chars(""), 0);
        // Total length includes spaces.
        assert_eq!(b_char_count("the quick brown fox"), 19);
        assert_eq!(b_char_count(""), 0);
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
        // Both baselines must fail under EVERY pair. The canonical text's
        // five answers are nonzero and pairwise distinct: `const-zero`
        // separates everywhere, and `total-length-everything` is exact
        // only on `char_count` — pairs carrying it are caught by their
        // partner.
        for seed in 0..200u64 {
            let text = canonical(seed);
            let total = b_char_count(&text);
            let answers = [
                b_word_count(&text),
                b_vowel_count(&text),
                b_longest_word_len(&text),
                b_distinct_chars(&text),
            ];
            assert_ne!(total, 0, "seed {seed}");
            for a in answers {
                assert_ne!(a, 0, "const-zero survives seed {seed}");
                assert_ne!(a, total, "length-cheat survives seed {seed}");
            }
            for i in 0..4 {
                for j in (i + 1)..4 {
                    assert_ne!(
                        answers[i], answers[j],
                        "answers collide seed {seed}: {:?}",
                        answers
                    );
                }
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (text, outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, &text), out, "seed {seed}");
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
                let fn_line = format!("pub fn {}", op.name());
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
            assert!(!sk.contains("split_whitespace"));
            assert!(!sk.contains(".chars()"));
            assert!(!sk.contains("[false;"));
            assert!(!sk.contains("to_ascii_lowercase"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("split_whitespace"));
            assert!(!p.contains(".chars()"));
            assert!(!p.contains("[false;"));
            assert!(!p.contains("to_ascii_lowercase"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every op is unary here, so each call site carries zero commas —
        // the same count as its signature.
        for op in OP_ALL {
            let call = call_src(op, "text");
            assert_eq!(
                call.matches(',').count(),
                op_sig_src(op).matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{}`",
                op_sig_src(op)
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = TextStatsFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
