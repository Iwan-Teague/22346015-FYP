//! The `text-wrap` family (category `line-layout`) — greedy word-wrap
//! simulation.
//!
//! Where `brackets` scans balance and `scrabble` looks tile values up,
//! this family exercises a **greedy layout simulation**: pack words onto
//! lines left to right under a column budget. The domain is a lowercase,
//! single-space-separated word list plus a width in columns. The seed
//! prunes which two of five query ops are required: `lines_needed`,
//! `widest_line`, `last_line_len`, `fits_one_line`,
//! `words_on_first_line`. C(5,2) = **10 distinct skills**, above the
//! diversity floor; op names are semantic.
//!
//! The greedy rule: place each word onto the current line while the
//! line plus a separating space plus the word stays within the width;
//! otherwise close the line and start a new one. A word longer than the
//! width occupies a line by itself and can never fit.
//!
//! The canonical case is sampled until it wraps onto **two or more
//! lines**: every scalar answer is nonzero there, the four answers stay
//! mutually distinct, and the one-line predicate answers FALSE. Both
//! trivial baselines die outright on every op at such a case; the
//! pinned one-line example flips constant-false flags instead.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random layouts against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the
//! canonical case) and `one-line-everything` (pretends everything fits
//! on one line — wrong on all five ops whenever wrapping happens, which
//! the canonical anchor guarantees).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    LinesNeeded,
    WidestLine,
    LastLineLen,
    FitsOneLine,
    WordsOnFirstLine,
}

const OP_ALL: [Op; 5] = [
    Op::LinesNeeded,
    Op::WidestLine,
    Op::LastLineLen,
    Op::FitsOneLine,
    Op::WordsOnFirstLine,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::LinesNeeded => "lines_needed",
            Op::WidestLine => "widest_line",
            Op::LastLineLen => "last_line_len",
            Op::FitsOneLine => "fits_one_line",
            Op::WordsOnFirstLine => "words_on_first_line",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::LinesNeeded => "how many lines the greedy layout produces",
            Op::WidestLine => "the length of the longest produced line",
            Op::LastLineLen => "the length of the final line after laying out every word",
            Op::FitsOneLine => {
                "whether the whole text packs onto a single line within \
                 the width — a word longer than the width never fits"
            }
            Op::WordsOnFirstLine => "how many words land on the first line",
        }
    }

    /// The return type this op's emitted signature declares.
    fn ret(self) -> &'static str {
        match self {
            Op::FitsOneLine => "bool",
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

/// The greedy walk shared in spirit by every op: pack words while the
/// current line plus a space plus the next word stays within `width`.
fn b_lines_needed(text: &str, width: u64) -> i64 {
    let mut lines = 0i64;
    let mut cur = 0usize;
    for word in text.split_whitespace() {
        let l = word.chars().count();
        if cur == 0 {
            cur = l;
        } else if cur + 1 + l <= width as usize {
            cur += 1 + l;
        } else {
            lines += 1;
            cur = l;
        }
    }
    if cur > 0 {
        lines += 1;
    }
    lines
}

/// The longest produced line.
fn b_widest_line(text: &str, width: u64) -> i64 {
    let mut cur = 0usize;
    let mut best = 0i64;
    for word in text.split_whitespace() {
        let l = word.chars().count();
        if cur == 0 {
            cur = l;
        } else if cur + 1 + l <= width as usize {
            cur += 1 + l;
        } else {
            best = (cur as i64).max(best);
            cur = l;
        }
    }
    best.max(cur as i64)
}

/// The final line's length after laying out every word.
fn b_last_line_len(text: &str, width: u64) -> i64 {
    let mut cur = 0usize;
    for word in text.split_whitespace() {
        let l = word.chars().count();
        if cur == 0 {
            cur = l;
        } else if cur + 1 + l <= width as usize {
            cur += 1 + l;
        } else {
            cur = l;
        }
    }
    cur as i64
}

/// Whether everything packs onto one line. A word longer than the
/// width occupies its own line and can never fit.
fn b_fits_one_line(text: &str, width: u64) -> bool {
    let mut cur = 0usize;
    for word in text.split_whitespace() {
        let l = word.chars().count();
        if cur == 0 {
            cur = l;
        } else if cur + 1 + l <= width as usize {
            cur += 1 + l;
        } else {
            return false;
        }
    }
    cur > 0 && cur <= width as usize
}

/// How many words land on the first packed line.
fn b_words_on_first_line(text: &str, width: u64) -> i64 {
    let mut cur = 0usize;
    let mut words = 0i64;
    for word in text.split_whitespace() {
        let l = word.chars().count();
        if cur == 0 {
            cur = l;
            words += 1;
        } else if cur + 1 + l <= width as usize {
            cur += 1 + l;
            words += 1;
        } else {
            break;
        }
    }
    words
}

/// The answer shape: scalars as `Num`, predicates as `Flag`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Flag(bool),
}

impl Out {
    fn lit(&self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            Out::Flag(b) => b.to_string(),
        }
    }
}

fn op_eval(op: Op, text: &str, width: u64) -> Out {
    match op {
        Op::LinesNeeded => Out::Num(b_lines_needed(text, width)),
        Op::WidestLine => Out::Num(b_widest_line(text, width)),
        Op::LastLineLen => Out::Num(b_last_line_len(text, width)),
        Op::FitsOneLine => Out::Flag(b_fits_one_line(text, width)),
        Op::WordsOnFirstLine => Out::Num(b_words_on_first_line(text, width)),
    }
}
// ---- canonical case -------------------------------------------------------

/// The canonical layout: sampled until it wraps onto two or more lines
/// with all four scalar answers nonzero and mutually distinct.
///
/// Guaranteed for every seed: the greedy rule does real work (the
/// one-line-everything cheat misses everywhere), `fits_one_line` answers
/// FALSE there (constant-true cheats die; constant-false flags agree and
/// are flipped by the pinned one-line example), and no answer collides
/// with another or with zero.
fn canonical(seed: u64) -> (String, u64) {
    let mut rng = Rng::new(seed ^ 0x71E7_7A91);
    for _ in 0..100_000 {
        let n_words = 2 + rng.below(3);
        let mut words = Vec::new();
        for _ in 0..n_words {
            let wl = 1 + rng.below(4);
            let mut w = String::new();
            for _ in 0..wl {
                w.push((b'a' + rng.below(26) as u8) as char);
            }
            words.push(w);
        }
        let text = words.join(" ");
        let width = 3 + rng.below(8);
        if anchors_hold(&text, width) {
            return (text, width);
        }
    }
    unreachable!("canonical layout sampling failed to satisfy anchors");
}

fn anchors_hold(text: &str, width: u64) -> bool {
    let lines = b_lines_needed(text, width);
    if lines < 2 || b_fits_one_line(text, width) {
        return false;
    }
    let ws = [
        b_lines_needed(text, width),
        b_widest_line(text, width),
        b_last_line_len(text, width),
        b_words_on_first_line(text, width),
    ];
    for i in 0..ws.len() {
        if ws[i] == 0 {
            return false;
        }
        for j in (i + 1)..ws.len() {
            if ws[i] == ws[j] {
                return false;
            }
        }
    }
    true
}

// ---- worked examples --------------------------------------------------------

type ExampleCase = ((String, u64), Vec<(Op, Out)>);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_0160);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical multi-line layout first.
    let can = canonical(seed);
    cases.push((
        can.clone(),
        spec.ops.map(|op| (op, op_eval(op, &can.0, can.1))).to_vec(),
    ));
    // Empty input: zero conventions on every query.
    cases.push((
        (String::new(), 10),
        spec.ops.map(|op| (op, op_eval(op, "", 10))).to_vec(),
    ));
    // A one-line case — flips constant-false flags.
    cases.push((
        ("a b".to_string(), 10),
        spec.ops.map(|op| (op, op_eval(op, "a b", 10))).to_vec(),
    ));
    // An over-long word takes its own line and never fits.
    cases.push((
        ("toolong x".to_string(), 4),
        spec.ops
            .map(|op| (op, op_eval(op, "toolong x", 4)))
            .to_vec(),
    ));
    for _ in 0..3 {
        let n_words = 2 + rng.below(3);
        let mut parts = Vec::new();
        for _ in 0..n_words {
            let wl = 1 + rng.below(4);
            let mut w = String::new();
            for _ in 0..wl {
                w.push((b'a' + rng.below(26) as u8) as char);
            }
            parts.push(w);
        }
        let text = parts.join(" ");
        let width = 3 + rng.below(8);
        let outs = spec.ops.map(|op| (op, op_eval(op, &text, width))).to_vec();
        cases.push(((text, width), outs));
    }
    cases
}
// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site: quoted text plus a typed width.
fn render_case(text: &str, width: u64) -> String {
    format!("({text:?}, {width}u64)")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    let sig = format!("(text: &str, width: u64) -> {ret}");
    let body = match op {
        Op::LinesNeeded => [
            "let w = width as usize;",
            "let mut lines = 0i64;",
            "let mut cur = 0usize;",
            "for word in text.split_whitespace() {",
            "    let l = word.chars().count();",
            "    if cur == 0 {",
            "        cur = l;",
            "    } else if cur + 1 + l <= w {",
            "        cur += 1 + l;",
            "    } else {",
            "        lines += 1;",
            "        cur = l;",
            "    }",
            "}",
            "if cur > 0 {",
            "    lines += 1;",
            "}",
            "lines",
        ]
        .join("\n    "),
        Op::WidestLine => [
            "let w = width as usize;",
            "let mut best = 0i64;",
            "let mut cur = 0usize;",
            "for word in text.split_whitespace() {",
            "    let l = word.chars().count();",
            "    if cur == 0 {",
            "        cur = l;",
            "    } else if cur + 1 + l <= w {",
            "        cur += 1 + l;",
            "    } else {",
            "        best = (cur as i64).max(best);",
            "        cur = l;",
            "    }",
            "}",
            "best.max(cur as i64)",
        ]
        .join("\n    "),
        Op::LastLineLen => [
            "let w = width as usize;",
            "let mut cur = 0usize;",
            "for word in text.split_whitespace() {",
            "    let l = word.chars().count();",
            "    if cur == 0 {",
            "        cur = l;",
            "    } else if cur + 1 + l <= w {",
            "        cur += 1 + l;",
            "    } else {",
            "        cur = l;",
            "    }",
            "}",
            "cur as i64",
        ]
        .join("\n    "),
        Op::FitsOneLine => [
            "let w = width as usize;",
            "let mut cur = 0usize;",
            "for word in text.split_whitespace() {",
            "    let l = word.chars().count();",
            "    if cur == 0 {",
            "        cur = l;",
            "    } else if cur + 1 + l <= w {",
            "        cur += 1 + l;",
            "    } else {",
            "        return false;",
            "    }",
            "}",
            "cur > 0 && cur <= w",
        ]
        .join("\n    "),
        Op::WordsOnFirstLine => [
            "let w = width as usize;",
            "let mut words = 0i64;",
            "let mut cur = 0usize;",
            "for word in text.split_whitespace() {",
            "    let l = word.chars().count();",
            "    if cur == 0 {",
            "        cur = l;",
            "        words += 1;",
            "    } else if cur + 1 + l <= w {",
            "        cur += 1 + l;",
            "        words += 1;",
            "    } else {",
            "        break;",
            "    }",
            "}",
            "words",
        ]
        .join("\n    "),
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}
/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(text: &str, width: u64) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!(
        "pub fn {}(text: &str, width: u64) -> {}",
        op.name(),
        op.ret()
    )
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
    for ((text, width), outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  input {}  ->  {}\n",
            render_case(&text, width),
            results
        ));
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
         a pair `(text, width)`: `text` is a lowercase word list separated \
         by single spaces, and `width` is the line budget in columns. Lay \
         words out greedily left to right — keep a word on the current \
         line while the line, one separating space, and the word together \
         stay within the width; otherwise close that line and start a new \
         one. A word longer than the width occupies a line by itself and \
         can never fit.\n\
         \n\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         - Work with exact integer arithmetic only; no floating point.\n\
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
    for (i, ((text, width), outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let text = {:?}.to_string();\n    let width = {}u64;\n",
            text, width,
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "&text, width"),
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
            let call = call_src(*op, "&text, width");
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
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0160;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let n_words = (nx(&mut state) % 4) + 1;\n\
         \x20       let mut text = String::new();\n\
         \x20       for _ in 0..n_words {{\n\
         \x20           let wl = (nx(&mut state) % 4) + 1;\n\
         \x20           for _ in 0..wl {{\n\
         \x20               text.push((b'a' + (nx(&mut state) % 26) as u8) as char);\n\
         \x20           }}\n\
         \x20           text.push(' ');\n\
         \x20       }}\n\
         \x20       let width = (nx(&mut state) % 8) + 3;\n\
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
            format!("{sig} {{\n    let _ = (text, width);\n    {tail}\n}}\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: pretend everything fits on one line. Whenever
/// the input actually wraps — which the canonical anchor guarantees —
/// all five answers are wrong at once, including the flag.
fn one_line_everything(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op {
                Op::FitsOneLine => format!("{sig} {{\n    true\n}}\n"),
                Op::LinesNeeded => {
                    format!("{sig} {{\n    let _ = width;\n    1\n}}\n")
                }
                Op::WidestLine | Op::LastLineLen => {
                    format!("{sig} {{\n    text.chars().count() as i64\n}}\n")
                }
                Op::WordsOnFirstLine => {
                    format!("{sig} {{\n    text.split_whitespace().count() as i64\n}}\n")
                }
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
pub struct TextWrapFamily;

impl Generator for TextWrapFamily {
    fn id(&self) -> &str {
        "text-wrap"
    }
    fn category(&self) -> &str {
        "line-layout"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("text-wrap", seed);

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
            id: format!("text-wrap/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure scanning and counting — no unsafe anywhere.
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
                "one-line-everything".to_string(),
                one_line_everything(&spec),
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
        let g = TextWrapFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Greedy counts: exact fit packs everything on one line.
        assert_eq!(b_lines_needed("aa bb cc", 8), 1);
        assert_eq!(b_lines_needed("aa bb cc dd", 8), 2);
        assert_eq!(b_lines_needed("hello world", 5), 2);
        assert_eq!(b_lines_needed("", 10), 0);
        // Widest line: a later line can be wider.
        assert_eq!(b_widest_line("aaa bbbb", 4), 4);
        assert_eq!(b_widest_line("", 4), 0);
        // Last line: short trailing word.
        assert_eq!(b_last_line_len("bbbbb aa", 5), 2);
        // Strict one-line fit: an over-long word never fits.
        assert!(!b_fits_one_line("toolong", 4));
        assert!(b_fits_one_line("aa bb", 5));
        assert!(!b_fits_one_line("", 4));
        // First-line packing: exact fit takes all three words.
        assert_eq!(b_words_on_first_line("aa bb cc dd", 8), 3);
        assert_eq!(b_words_on_first_line("", 8), 0);
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
        // The canonical case wraps onto two or more lines, so BOTH
        // baselines die outright on every op — const-zero on the
        // nonzero scalars, one-line-everything on all five answers
        // including its constant-true flag. No skips anywhere.
        for seed in 0..200u64 {
            let (text, width) = canonical(seed);
            let lines = b_lines_needed(&text, width);
            let widest = b_widest_line(&text, width);
            let last = b_last_line_len(&text, width);
            let first_words = b_words_on_first_line(&text, width);
            assert!(lines >= 2, "seed {seed}: must wrap");
            assert!(!b_fits_one_line(&text, width), "seed {seed}");
            let ws = [lines, widest, last, first_words];
            for i in 0..ws.len() {
                assert_ne!(ws[i], 0, "const-zero survives at seed {seed}");
                for j in (i + 1)..ws.len() {
                    assert_ne!(
                        ws[i], ws[j],
                        "answers collide at seed {seed}: {} vs {}",
                        ws[i], ws[j]
                    );
                }
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for ((text, width), outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, &text, width), out, "seed {seed}");
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
                // Match the `pub fn` line plus the paren so no bare-name
                // substring leaks.
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
            // Solution-shaped leak tokens must stay out of the skeleton;
            // the worked examples legitimately show outputs, never
            // rules — so tokens carry implementation shapes.
            assert!(!sk.contains("split_whitespace"));
            assert!(!sk.contains("chars().count"));
            assert!(!sk.contains("+= 1"));
            assert!(!sk.contains("break"));
            assert!(!sk.contains("else {"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("split_whitespace"));
            assert!(!p.contains("chars().count"));
            assert!(!p.contains("+= 1"));
            assert!(!p.contains("break"));
            assert!(!p.contains("else {"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every op here takes (text, width): exactly one comma on both sides.
        for op in OP_ALL {
            let sig = op_sig_src(op);
            let params = sig.split("->").next().unwrap();
            let call = call_src(op, "&text, width");
            assert_eq!(
                call.matches(',').count(),
                params.matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{sig}`"
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = TextWrapFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
