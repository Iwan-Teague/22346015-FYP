//! Borrow-or-own puzzles over one piece of text.
//!
//! Every query returns a `Cow<'_, str>`. The discipline under test: borrow
//! the input slice whenever it already satisfies the request and allocate
//! a fresh string only when a real transformation is needed. Hidden tests
//! pin not just the answer but the ownership verdict, so unconditional
//! cloners answer correctly and still fail, while never-cloners fail the
//! one query whose result cannot be a slice of the input.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    TrimView,
    ShoutView,
    PadTo,
    StripPrefixView,
    ReverseView,
}

pub const OP_ALL: [Op; 5] = [
    Op::TrimView,
    Op::ShoutView,
    Op::PadTo,
    Op::StripPrefixView,
    Op::ReverseView,
];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::TrimView => "trim_view",
            Op::ShoutView => "shout_view",
            Op::PadTo => "pad_to",
            Op::StripPrefixView => "strip_prefix_view",
            Op::ReverseView => "reverse_view",
        }
    }

    /// Extra driver parameter beyond the text itself.
    pub fn extra_arg(self) -> &'static str {
        match self {
            Op::PadTo => ", width: usize",
            Op::StripPrefixView => ", prefix: &str",
            _ => "",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::TrimView => "the whitespace-trimmed view, borrowing the input when nothing needed trimming",
            Op::ShoutView => "the uppercased view, borrowing inputs that were already shouting (or had no letters)",
            Op::PadTo => "the text padded with trailing spaces up to the width, borrowing inputs already long enough",
            Op::StripPrefixView => "the remainder after the prefix, borrowing either way and never allocating",
            Op::ReverseView => "the character-reversed text, which always needs a fresh allocation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let a = rng.below(5) as usize;
    let mut b = rng.below(5) as usize;
    while b == a {
        b = rng.below(5) as usize;
    }
    let mut ops = [OP_ALL[a], OP_ALL[b]];
    ops.sort();
    Spec { ops }
}

/// One recorded outcome: the produced text plus whether a fresh
/// allocation was made.
pub type Verdict = (String, bool);

pub fn verdict_of(out: Cow<'_, str>) -> Verdict {
    (out.to_string(), matches!(out, Cow::Owned(_)))
}

pub fn b_trim_view(text: &str) -> Cow<'_, str> {
    let t = text.trim();
    if t.len() == text.len() {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(t.to_string())
    }
}

pub fn b_shout_view(text: &str) -> Cow<'_, str> {
    let up = text.to_uppercase();
    if up == text {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(up)
    }
}

pub fn b_pad_to(text: &str, width: usize) -> Cow<'_, str> {
    if text.len() >= width {
        Cow::Borrowed(text)
    } else {
        let mut s = String::from(text);
        while s.len() < width {
            s.push(' ');
        }
        Cow::Owned(s)
    }
}

pub fn b_strip_prefix_view<'a>(text: &'a str, prefix: &str) -> Cow<'a, str> {
    match text.strip_prefix(prefix) {
        Some(rest) => Cow::Borrowed(rest),
        None => Cow::Borrowed(text),
    }
}

pub fn b_reverse_view(text: &str) -> Cow<'_, str> {
    Cow::Owned(text.chars().rev().collect::<String>())
}

/// Answer and ownership verdict for one query on one input.
pub fn eval(op: Op, text: &str, width: usize, prefix: &str) -> Verdict {
    match op {
        Op::TrimView => verdict_of(b_trim_view(text)),
        Op::ShoutView => verdict_of(b_shout_view(text)),
        Op::PadTo => verdict_of(b_pad_to(text, width)),
        Op::StripPrefixView => verdict_of(b_strip_prefix_view(text, prefix)),
        Op::ReverseView => verdict_of(b_reverse_view(text)),
    }
}

pub const CANONICAL_SEED: u64 = 0xC07E_FA11;

const TEXT_ALPHABET: &[u8] = b"ABZ042";

/// Canonical inputs sit firmly in borrow territory: already trimmed,
/// already shouting, long enough, and the reversal alone allocates.
pub fn canonical(seed: u64) -> (String, usize, String) {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let n = 3 + rng.below(5) as usize;
        let mut text = String::new();
        for _ in 0..n {
            text.push(TEXT_ALPHABET[rng.below(6) as usize] as char);
        }
        let width = 1 + rng.below(text.len() as u64) as usize;
        let cut = 1 + rng.below(2) as usize;
        let prefix: String = text.chars().take(cut.min(text.len())).collect();
        if anchors_hold(&text, width, &prefix) {
            return (text, width, prefix);
        }
    }
    unreachable!("canonical search never converged");
}

fn anchors_hold(text: &str, width: usize, prefix: &str) -> bool {
    if text.is_empty() || width == 0 || text.len() < width {
        return false;
    }
    // Borrow territory: trimming and shouting are no-ops here by
    // construction (alphabet has no lowercase and no spaces); padding
    // must also be a no-op; stripping must actually consume the prefix
    // so the remainder differs from the whole.
    let (tv, _) = eval(Op::TrimView, text, width, prefix);
    let (sv, _) = eval(Op::ShoutView, text, width, prefix);
    let (pv, owned) = eval(Op::PadTo, text, width, prefix);
    let (rv, r_owned) = eval(Op::ReverseView, text, width, prefix);
    let (stv, _) = eval(Op::StripPrefixView, text, width, prefix);
    !owned && r_owned && tv == text && sv == text && pv == text && stv != text && rv != *text
}
pub struct ExampleCase {
    pub text: String,
    pub width: usize,
    pub prefix: String,
    /// OP_ALL answers, computed once at construction.
    pub answers: Vec<(Op, Verdict)>,
}

pub const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_018E;

fn case(text: &str, width: usize, prefix: &str) -> ExampleCase {
    let answers = OP_ALL
        .iter()
        .map(|&op| (op, eval(op, text, width, prefix)))
        .collect();
    ExampleCase {
        text: text.to_string(),
        width,
        prefix: prefix.to_string(),
        answers,
    }
}

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut out = vec![case_from(canonical(seed))];
    // Owned zone: every transform fires except the never-allocating strip.
    out.push(case(" a9 ", 9, "zz"));
    // Zero conventions.
    out.push(case("", 0, ""));
    // Solo corner: padding must allocate, exact prefix consumption empties.
    out.push(case("x", 3, "x"));
    for _ in 0..3 {
        let n = rng.below(8) as usize;
        let mut text = String::new();
        for _ in 0..n {
            let pick = rng.below(10);
            let c = match pick {
                0..=2 => (b'a' + rng.below(3) as u8) as char,
                3..=5 => (b'A' + rng.below(3) as u8) as char,
                6..=7 => (b'0' + rng.below(4) as u8) as char,
                _ => ' ',
            };
            text.push(c);
        }
        let width = rng.below(6) as usize;
        let plen = 1 + rng.below(2) as usize;
        let mut prefix = String::new();
        for _ in 0..plen {
            prefix.push((b'a' + rng.below(3) as u8) as char);
        }
        out.push(case(&text, width, &prefix));
    }
    out
}

fn case_from(inputs: (String, usize, String)) -> ExampleCase {
    let (text, width, prefix) = inputs;
    case(&text, width, &prefix)
}

pub fn render_text(text: &str) -> String {
    format!("{text:?}")
}

/// Driver call expression for one op over the standard local bindings.
pub fn call_src(op: Op) -> String {
    match op {
        Op::TrimView => "trim_view(&text)".to_string(),
        Op::ShoutView => "shout_view(&text)".to_string(),
        Op::PadTo => "pad_to(&text, width)".to_string(),
        Op::StripPrefixView => "strip_prefix_view(&text, &prefix)".to_string(),
        Op::ReverseView => "reverse_view(&text)".to_string(),
    }
}

pub fn op_sig_src(op: Op) -> String {
    match op {
        Op::PadTo => "pub fn pad_to(text: &str, width: usize) -> Cow<'_, str>".to_string(),
        // Two input lifetimes: elision cannot tell which one the Cow borrows.
        Op::StripPrefixView => {
            "pub fn strip_prefix_view<'a>(text: &'a str, prefix: &str) -> Cow<'a, str>".to_string()
        }
        other => format!("pub fn {}(text: &str) -> Cow<'_, str>", other.name()),
    }
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::TrimView => &[
            "let t = text.trim();",
            "if t.len() == text.len() {",
            "    Cow::Borrowed(text)",
            "} else {",
            "    Cow::Owned(t.to_string())",
            "}",
        ],
        Op::ShoutView => &[
            "let up = text.to_uppercase();",
            "if up == text {",
            "    Cow::Borrowed(text)",
            "} else {",
            "    Cow::Owned(up)",
            "}",
        ],
        Op::PadTo => &[
            "if text.len() >= width {",
            "    Cow::Borrowed(text)",
            "} else {",
            "    let mut s = String::from(text);",
            "    while s.len() < width {",
            "        s.push(' ');",
            "    }",
            "    Cow::Owned(s)",
            "}",
        ],
        Op::StripPrefixView => &[
            "match text.strip_prefix(prefix) {",
            "    Some(rest) => Cow::Borrowed(rest),",
            "    None => Cow::Borrowed(text),",
            "}",
        ],
        Op::ReverseView => &["Cow::Owned(text.chars().rev().collect::<String>())"],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub fn reference_src(spec: Spec) -> String {
    let mut s = String::from("use std::borrow::Cow;\n\n");
    for &op in spec.ops.iter() {
        s.push_str(&op_fn_src(op));
        s.push('\n');
    }
    s
}
pub fn worked_examples_prose(examples: &[ExampleCase]) -> String {
    let mut s = String::new();
    for (i, ex) in examples.iter().enumerate() {
        s.push_str(&format!(
            "//! ex{} text {:?} width {} prefix {:?}\n",
            i, ex.text, ex.width, ex.prefix
        ));
        for (op, (value, owned)) in ex.answers.iter() {
            s.push_str(&format!(
                "//!   {} = {:?} ({})\n",
                op.name(),
                value,
                if *owned { "owned" } else { "borrowed" }
            ));
        }
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Borrow-or-own queries over one piece of text.\n\
         //!\n\
         //! A `Cow<'_, str>` is either a borrowed slice of the input or a\n\
         //! freshly owned string. Borrow the input whenever it already\n\
         //! satisfies the request; allocate only when a real transformation\n\
         //! was needed. The hidden tests check the ownership verdict as well\n\
         //! as the answer, so unconditional cloning fails even with perfect\n\
        //! answers.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push_str("\nuse std::borrow::Cow;\n\n");
    for &op in spec.ops.iter() {
        s.push_str(&op_stub_src(op));
        s.push('\n');
    }
    s
}

pub const PROMPT_INTRO: &str = "Fill in the missing functions so each returns the right view of the input text as a Cow<'_, str>.\n";

pub fn prompt_src(spec: Spec, examples: &[ExampleCase], canary: &str) -> String {
    let mut s = String::from(PROMPT_INTRO);
    s.push_str("\nRequirements:\n");
    for &op in spec.ops.iter() {
        s.push_str(&format!("- Provide {}.\n", op.prose()));
    }
    s.push_str(
        "\nConstraints:\n\
         - Keep the exact function signatures.\n\
         - Return Cow::Borrowed whenever the input already qualifies; return Cow::Owned only when a fresh string had to be built. The tests inspect which variant you returned.\n\
         - No unsafe code.\n",
    );
    s.push_str("\nSignatures:\n```rust\n");
    for &op in spec.ops.iter() {
        s.push_str(&op_sig_src(op));
        s.push('\n');
    }
    s.push_str("```\n");
    let prose = worked_examples_prose(examples);
    for line in prose.lines() {
        s.push_str(&format!("{}\n", line.trim_start_matches("//! ")));
    }
    s.push_str(&format!(
        "\nYour answer must still contain the canary string \"{canary}\" in its doc comment.\n"
    ));
    s
}

pub fn cargo_toml() -> String {
    "[package]\nname = \"task\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[workspace]\n"
        .to_string()
}
pub fn behavior_test_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from("use std::borrow::Cow;\n");
    s.push_str("use task::{");
    let names: Vec<&str> = spec.ops.iter().map(|o| o.name()).collect();
    s.push_str(&names.join(", "));
    s.push_str("};\n\n");
    for (i, ex) in examples.iter().enumerate() {
        for &op in spec.ops.iter() {
            let (value, owned) = ex
                .answers
                .iter()
                .find(|(o, _)| *o == op)
                .map(|(_, v)| v.clone())
                .unwrap();
            s.push_str(&format!("#[test]\nfn ex{}_{}() {{\n", i, op.name()));
            s.push_str(&format!("    let text = {:?}.to_string();\n", ex.text));
            if op == Op::PadTo {
                s.push_str(&format!("    let width = {}usize;\n", ex.width));
            }
            if op == Op::StripPrefixView {
                s.push_str(&format!("    let prefix = {:?}.to_string();\n", ex.prefix));
            }
            s.push_str(&format!("    let out = {};\n", call_src(op)));
            s.push_str(&format!("    assert_eq!(&*out, {:?});\n", value));
            if owned {
                s.push_str("    assert!(matches!(out, Cow::Owned(_)));\n}\n\n");
            } else {
                s.push_str("    assert!(matches!(out, Cow::Borrowed(_)));\n}\n\n");
            }
        }
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::{");
    let names: Vec<&str> = spec.ops.iter().map(|o| o.name()).collect();
    s.push_str(&names.join(", "));
    s.push_str("};\n\n");

    // Paste the reference under ref_* names.
    let mut pasted = reference_src(spec);
    for &op in spec.ops.iter() {
        let needle = format!("pub fn {}", op.name());
        let replacement = format!("fn ref_{}", op.name());
        let count = pasted.matches(&needle).count();
        assert_eq!(count, 1, "reference rename missed {}", op.name());
        pasted = pasted.replacen(&needle, &replacement, 1);
    }
    s.push_str(&pasted);

    s.push_str("\n#[test]\nfn differential_vs_reference() {\n");
    s.push_str("    fn nx(state: &mut u64) -> u64 {\n");
    s.push_str("        *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n");
    s.push_str("        *state >> 33\n    }\n");
    s.push_str("    const POOL: &[u8] = b\"abzAZ 90\";\n");
    s.push_str("    let mut state: u64 = 0xE7EE_ED00_0000_018E;\n");
    s.push_str("    for _ in 0..3000 {\n");
    s.push_str("        let n = (nx(&mut state) % 7) as usize + 1;\n");
    s.push_str("        let mut t = String::new();\n");
    s.push_str("        for _ in 0..n {\n");
    s.push_str("            t.push(POOL[(nx(&mut state) % 8) as usize] as char);\n");
    s.push_str("        }\n");
    s.push_str("        let width = (nx(&mut state) % 6) as usize;\n");
    s.push_str("        let plen = (nx(&mut state) % 2) as usize + 1;\n");
    s.push_str("        let mut prefix = String::new();\n");
    s.push_str("        for _ in 0..plen {\n");
    s.push_str("            prefix.push((b'a' + (nx(&mut state) % 3) as u8) as char);\n");
    s.push_str("        }\n");
    for &op in spec.ops.iter() {
        let call = match op {
            Op::PadTo => format!("{}(&t, width)", op.name()),
            Op::StripPrefixView => format!("{}(&t, &prefix)", op.name()),
            other => format!("{}(&t)", other.name()),
        };
        let rcall = match op {
            Op::PadTo => format!("ref_{}(&t, width)", op.name()),
            Op::StripPrefixView => format!("ref_{}(&t, &prefix)", op.name()),
            other => format!("ref_{}(&t)", other.name()),
        };
        s.push_str(&format!("        assert_eq!({}, {});\n", call, rcall));
    }
    s.push_str("    }\n}\n");
    s
}

pub fn always_owned_src(spec: Spec) -> String {
    let mut s = String::from("use std::borrow::Cow;\n\n");
    for &op in spec.ops.iter() {
        let body: &[&str] = match op {
            Op::TrimView => &["Cow::Owned(text.trim().to_string())"],
            Op::ShoutView => &["Cow::Owned(text.to_uppercase())"],
            Op::PadTo => &[
                "let mut s = String::from(text);",
                "while s.len() < width {",
                "    s.push(' ');",
                "}",
                "Cow::Owned(s)",
            ],
            Op::StripPrefixView => &[
                "match text.strip_prefix(prefix) {",
                "    Some(rest) => Cow::Owned(rest.to_string()),",
                "    None => Cow::Owned(text.to_string()),",
                "}",
            ],
            Op::ReverseView => &["Cow::Owned(text.chars().rev().collect::<String>())"],
        };
        s.push_str(&format!(
            "{} {{\n    {}\n}}\n\n",
            op_sig_src(op),
            body.join("\n    ")
        ));
    }
    s
}

pub fn always_borrowed_src(spec: Spec) -> String {
    let mut s = String::from("use std::borrow::Cow;\n\n");
    for &op in spec.ops.iter() {
        let body: &[&str] = match op {
            // The reversal can never be a slice of the input; this cheat
            // fails its ownership pin everywhere.
            Op::ReverseView => &["Cow::Borrowed(text)"],
            Op::StripPrefixView => &["Cow::Borrowed(text)"],
            _ => &["Cow::Borrowed(text)"],
        };
        s.push_str(&format!(
            "{} {{\n    {}\n}}\n\n",
            op_sig_src(op),
            body.join("\n    ")
        ));
    }
    s
}
pub struct CowStrFamily;

impl Generator for CowStrFamily {
    fn id(&self) -> &'static str {
        "cow-str"
    }

    fn category(&self) -> &'static str {
        "clone-on-write"
    }

    fn reference_code(&self, seed: u64) -> String {
        reference_src(sample(seed))
    }

    fn skeleton_code(&self, seed: u64) -> String {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        skeleton_src(spec, &examples)
    }

    fn trivial_baselines(&self, seed: u64) -> Vec<(String, String)> {
        let spec = sample(seed);
        vec![
            ("always-owned".to_string(), always_owned_src(spec)),
            ("always-borrowed".to_string(), always_borrowed_src(spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let mut sigs: Vec<String> = sample(seed)
            .ops
            .iter()
            .map(|o| format!("q:{}", o.name()))
            .collect();
        sigs.sort();
        sigs
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("cow-str", seed);
        GeneratedTask {
            id: format!("cow-str/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt_src(spec, &examples, &canary),
            canary,
            answer_path: String::from("src/lib.rs"),
            files: BTreeMap::from([
                (PathBuf::from("Cargo.toml"), cargo_toml()),
                (PathBuf::from("src/lib.rs"), skeleton_src(spec, &examples)),
            ]),
            hidden: BTreeMap::from([
                (
                    PathBuf::from("tests/behavior.rs"),
                    behavior_test_src(spec, &examples),
                ),
                (
                    PathBuf::from("tests/differential.rs"),
                    differential_test_src(spec),
                ),
            ]),
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            max_unsafe: None,
            forbidden_paths: vec![],
            check_clippy: false,
            clippy_allow: vec![],
            weights: (0.70, 0.20, 0.10),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generation_is_deterministic() {
        let a = CowStrFamily.generate(7);
        let b = CowStrFamily.generate(7);
        assert_eq!(a.id, b.id);
        assert_eq!(a.prompt, b.prompt);
        assert_eq!(a.files, b.files);
    }

    #[test]
    fn native_ops_match_intent() {
        // trim: borrow unchanged, own trimmed
        let (v, owned) = eval(Op::TrimView, "hi", 0, "");
        assert_eq!(v, "hi");
        assert!(!owned);
        let (v, owned) = eval(Op::TrimView, " hi ", 0, "");
        assert_eq!(v, "hi");
        assert!(owned);
        // shout: digits-only borrows; letters change owns
        let (v, owned) = eval(Op::ShoutView, "123", 0, "");
        assert_eq!(v, "123");
        assert!(!owned);
        let (v, owned) = eval(Op::ShoutView, "h1!", 0, "");
        assert_eq!(v, "H1!");
        assert!(owned);
        // pad: exact boundary borrows, short owns
        let (v, owned) = eval(Op::PadTo, "abcde", 5, "");
        assert_eq!(v, "abcde");
        assert!(!owned);
        let (v, owned) = eval(Op::PadTo, "ab", 5, "");
        assert_eq!(v, "ab   ");
        assert!(owned);
        // strip never allocates either way
        let (v, owned) = eval(Op::StripPrefixView, "cargo/home", 0, "cargo/");
        assert_eq!(v, "home");
        assert!(!owned);
        let (v, owned) = eval(Op::StripPrefixView, "rust/lib", 0, "cargo/");
        assert_eq!(v, "rust/lib");
        assert!(!owned);
        // reverse always owns
        let (v, owned) = eval(Op::ReverseView, "cargo", 0, "");
        assert_eq!(v, "ograc");
        assert!(owned);
    }

    #[test]
    fn seeds_vary_query_pairs() {
        let mut seen = HashSet::new();
        for seed in 0..300u64 {
            seen.insert(sample(seed));
        }
        assert!(seen.len() >= 9);
    }

    #[test]
    fn canonical_answers_are_non_degenerate_for_every_op() {
        for seed in 0..200u64 {
            let (text, width, prefix) = canonical(seed);
            assert!(!text.is_empty());
            assert!(width >= 1);
            assert!(text.len() >= width);
            for &op in OP_ALL.iter() {
                let (value, owned) = eval(op, &text, width, &prefix);
                match op {
                    // Borrow territory on canonical inputs.
                    Op::TrimView | Op::ShoutView | Op::PadTo | Op::StripPrefixView => {
                        assert!(!owned, "seed {seed} op {} should borrow", op.name());
                        // An unconditional cloner returns the right value
                        // with the wrong verdict.
                        if op != Op::StripPrefixView {
                            assert_eq!(value, text, "seed {seed} op {}", op.name());
                        } else {
                            assert_ne!(value, text, "strip must consume its prefix at seed {seed}");
                        }
                    }
                    // Reversal always allocates and can never echo input.
                    Op::ReverseView => {
                        assert!(owned, "seed {seed} reverse must own");
                        assert_ne!(value, text);
                    }
                }
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for ex in worked_examples(seed).iter() {
                for &(op, ref expected) in ex.answers.iter() {
                    if !spec.ops.contains(&op) {
                        continue;
                    }
                    let got = eval(op, &ex.text, ex.width, &ex.prefix);
                    assert_eq!(&got, expected, "seed {seed}");
                }
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        for seed in [0u64, 5, 31] {
            let spec = sample(seed);
            let src = reference_src(spec);
            for &op in spec.ops.iter() {
                let marker = format!("pub fn {}(", op.name());
                let loose = format!("pub fn {}", op.name());
                assert!(
                    src.contains(&marker) || src.contains(&loose),
                    "seed {seed} missing {}",
                    op.name()
                );
            }
            for &op in OP_ALL.iter() {
                if !spec.ops.contains(&op) {
                    assert!(
                        !src.contains(&format!("pub fn {}", op.name())),
                        "seed {seed} leaked {}",
                        op.name()
                    );
                }
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        for seed in [0u64, 9, 44] {
            let spec = sample(seed);
            let examples = worked_examples(seed);
            let sk = skeleton_src(spec, &examples);
            let prompt = prompt_src(spec, &examples, &crate::mint_canary("cow-str", seed));
            for token in ["to_string(", ".trim()", "to_uppercase()", "chars().rev()"] {
                assert!(!sk.contains(token), "skeleton leaks {token}");
                assert!(!prompt.contains(token), "prompt leaks {token}");
            }
            assert_eq!(sk.matches("todo!()").count(), spec.ops.len());
            for &op in spec.ops.iter() {
                assert!(prompt.contains(&op_sig_src(op)), "prompt lacks sig");
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        for seed in [2u64, 11, 77] {
            let spec = sample(seed);
            for &op in spec.ops.iter() {
                let sig = op_sig_src(op);
                let params = sig.split("->").next().unwrap();
                let want = params.matches(',').count();
                let call = call_src(op);
                let got = call.matches(',').count();
                assert_eq!(want, got, "{} arity drift", op.name());
            }
        }
    }

    #[test]
    fn baselines_diverge_from_reference_verdicts() {
        for seed in [3u64, 17, 29] {
            let spec = sample(seed);
            let owned_src = always_owned_src(spec);
            let borrowed_src = always_borrowed_src(spec);
            // The cloner never borrows; the reference does whenever the
            // canonical inputs already qualify.
            assert!(owned_src.contains("Cow::Owned"));
            assert!(!owned_src.contains("Cow::Borrowed"));
            // The never-cloner cannot produce the reversal.
            assert!(borrowed_src.contains("Cow::Borrowed"));
            assert!(!borrowed_src.contains("rev()"));
            let (text, width, prefix) = canonical(seed);
            let (_, r_owned) = eval(Op::ReverseView, &text, width, &prefix);
            assert!(r_owned);
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let seed = 12u64;
        let canary = crate::mint_canary("cow-str", seed);
        let spec = sample(seed);
        let prompt = prompt_src(spec, &worked_examples(seed), &canary);
        assert!(prompt.contains(&canary));
    }
}
