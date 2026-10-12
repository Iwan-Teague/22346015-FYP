//! The `own-tokens` family (category `borrow-lifetimes`) — **avoid the self-referential struct**:
//! store byte spans, not `&str`s, so the value owns its text and can outlive the caller's.
//!
//! docs/04 lists "avoiding self-reference" under `borrow-lifetimes`. The trap here is the most
//! common way to meet it. A tokenizer is asked for `Tokens::new(text: &str) -> Tokens` whose
//! queries hand back `&str` slices of the text. The tempting design keeps `Vec<&str>` next to the
//! `String` those slices point into, which cannot be written (a struct cannot borrow from its own
//! field); the next tempting design is `Tokens<'a>` borrowing the caller's `&str`, which compiles —
//! and is wrong for this API, because the hidden tests **drop the source `String` first** and keep
//! using the `Tokens` (`E0505` / `E0597` otherwise). The design that works owns a `String` plus
//! `Vec<(usize, usize)>` byte spans and slices on demand.
//!
//! Seed-selected on two axes:
//!
//! 1. **Tokenizer** — runs of non-whitespace; comma-separated trimmed segments (empty ones
//!    skipped); non-empty lines (a trailing `\r` is stripped); fixed-width byte chunks.
//! 2. **Queries** — 3 of 5: `word(i)`, `longest()`, `find(prefix)`, `span(i)` (byte range in the
//!    original text), `rest_from(i)` (the original text from token `i` on).
//!
//! 4 x C(5,3) = **40 distinct skills**; the chunk width is cosmetic and excluded from
//! `spec_signature` (Q31). Constraint-dominant per docs/04: `leak` is forbidden (the leaked-`'static`
//! escape) and `unsafe` is capped at 0. Solution-first (ADR-0003): the native tokenizer and the
//! emitted one are mirrored and the differential compares every query on 3000 random texts.

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Tok {
    Whitespace,
    Comma,
    Lines,
    Fixed(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Query {
    Word,
    Longest,
    Find,
    Span,
    RestFrom,
}

const ALL_QUERIES: [Query; 5] = [
    Query::Word,
    Query::Longest,
    Query::Find,
    Query::Span,
    Query::RestFrom,
];

struct Spec {
    tok: Tok,
    queries: Vec<Query>,
}

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let tok = match rng.below(4) {
        0 => Tok::Whitespace,
        1 => Tok::Comma,
        2 => Tok::Lines,
        _ => Tok::Fixed(2 + rng.below(4) as usize),
    };
    let mut idx = [0usize, 1, 2, 3, 4];
    for i in 0..3 {
        let j = i + rng.below((5 - i) as u64) as usize;
        idx.swap(i, j);
    }
    let mut queries: Vec<Query> = idx[..3].iter().map(|&i| ALL_QUERIES[i]).collect();
    queries.sort();
    Spec { tok, queries }
}

// ---- native reference ---------------------------------------------------------------

fn spans(tok: Tok, text: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    match tok {
        Tok::Whitespace => {
            let mut start: Option<usize> = None;
            for (i, c) in text.char_indices() {
                if c.is_whitespace() {
                    if let Some(s) = start.take() {
                        out.push((s, i));
                    }
                } else if start.is_none() {
                    start = Some(i);
                }
            }
            if let Some(s) = start {
                out.push((s, text.len()));
            }
        }
        Tok::Comma => {
            let mut pos = 0;
            for seg in text.split(',') {
                let end = pos + seg.len();
                let lead = seg.len() - seg.trim_start().len();
                let t = seg.trim();
                if !t.is_empty() {
                    out.push((pos + lead, pos + lead + t.len()));
                }
                pos = end + 1;
            }
        }
        Tok::Lines => {
            let mut pos = 0;
            for line in text.split('\n') {
                let l = line.strip_suffix('\r').unwrap_or(line);
                if !l.is_empty() {
                    out.push((pos, pos + l.len()));
                }
                pos += line.len() + 1;
            }
        }
        Tok::Fixed(k) => {
            let mut s = 0;
            while s < text.len() {
                let e = (s + k).min(text.len());
                out.push((s, e));
                s = e;
            }
        }
    }
    out
}

/// One query's result rendered as a Rust literal.
fn answer(tok: Tok, q: Query, text: &str, arg: usize, prefix: &str) -> String {
    let sp = spans(tok, text);
    let word = |i: usize| sp.get(i).map(|&(s, e)| &text[s..e]);
    let opt_str = |o: Option<&str>| match o {
        Some(s) => format!("Some({s:?})"),
        None => "None".to_string(),
    };
    match q {
        Query::Word => opt_str(word(arg)),
        Query::Longest => {
            let mut best: Option<&str> = None;
            for &(s, e) in &sp {
                if best.is_none_or(|b| e - s > b.len()) {
                    best = Some(&text[s..e]);
                }
            }
            opt_str(best)
        }
        Query::Find => opt_str(
            sp.iter()
                .map(|&(s, e)| &text[s..e])
                .find(|w| w.starts_with(prefix)),
        ),
        Query::Span => match sp.get(arg) {
            Some(&(s, e)) => format!("Some(({s}, {e}))"),
            None => "None".to_string(),
        },
        Query::RestFrom => match sp.get(arg) {
            Some(&(s, _)) => format!("{:?}", &text[s..]),
            None => "\"\"".to_string(),
        },
    }
}

// ---- emitted source ------------------------------------------------------------------------

fn spans_body(tok: Tok) -> String {
    match tok {
        Tok::Whitespace => "        let mut spans = Vec::new();\n        let mut start: Option<usize> = None;\n        for (i, c) in text.char_indices() {\n            if c.is_whitespace() {\n                if let Some(s) = start.take() {\n                    spans.push((s, i));\n                }\n            } else if start.is_none() {\n                start = Some(i);\n            }\n        }\n        if let Some(s) = start {\n            spans.push((s, text.len()));\n        }\n".to_string(),
        Tok::Comma => "        let mut spans = Vec::new();\n        let mut pos = 0;\n        for seg in text.split(',') {\n            let end = pos + seg.len();\n            let lead = seg.len() - seg.trim_start().len();\n            let t = seg.trim();\n            if !t.is_empty() {\n                spans.push((pos + lead, pos + lead + t.len()));\n            }\n            pos = end + 1;\n        }\n".to_string(),
        Tok::Lines => "        let mut spans = Vec::new();\n        let mut pos = 0;\n        for line in text.split('\\n') {\n            let l = line.strip_suffix('\\r').unwrap_or(line);\n            if !l.is_empty() {\n                spans.push((pos, pos + l.len()));\n            }\n            pos += line.len() + 1;\n        }\n".to_string(),
        Tok::Fixed(k) => format!("        let mut spans = Vec::new();\n        let mut s = 0;\n        while s < text.len() {{\n            let e = (s + {k}).min(text.len());\n            spans.push((s, e));\n            s = e;\n        }}\n"),
    }
}

fn query_sig(q: Query) -> &'static str {
    match q {
        Query::Word => "pub fn word(&self, i: usize) -> Option<&str>",
        Query::Longest => "pub fn longest(&self) -> Option<&str>",
        Query::Find => "pub fn find(&self, prefix: &str) -> Option<&str>",
        Query::Span => "pub fn span(&self, i: usize) -> Option<(usize, usize)>",
        Query::RestFrom => "pub fn rest_from(&self, i: usize) -> &str",
    }
}

fn query_body(q: Query) -> &'static str {
    match q {
        Query::Word => "        self.spans.get(i).map(|&(s, e)| &self.text[s..e])\n",
        Query::Longest => "        let mut best: Option<(usize, usize)> = None;\n        for &(s, e) in &self.spans {\n            if best.is_none_or(|(bs, be)| e - s > be - bs) {\n                best = Some((s, e));\n            }\n        }\n        best.map(|(s, e)| &self.text[s..e])\n",
        Query::Find => "        self.spans\n            .iter()\n            .map(|&(s, e)| &self.text[s..e])\n            .find(|w| w.starts_with(prefix))\n",
        Query::Span => "        self.spans.get(i).copied()\n",
        Query::RestFrom => "        match self.spans.get(i) {\n            Some(&(s, _)) => &self.text[s..],\n            None => \"\",\n        }\n",
    }
}

fn reference_src(spec: &Spec) -> String {
    let mut s = String::from(
        "pub struct Tokens {\n    text: String,\n    spans: Vec<(usize, usize)>,\n}\n\nimpl Tokens {\n    pub fn new(text: &str) -> Tokens {\n",
    );
    s.push_str(&spans_body(spec.tok));
    s.push_str("        Tokens {\n            text: text.to_string(),\n            spans,\n        }\n    }\n");
    for &q in &spec.queries {
        s.push_str(&format!(
            "\n    {} {{\n{}    }}\n",
            query_sig(q),
            query_body(q)
        ));
    }
    s.push_str("}\n");
    s
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples(spec, seed)
        .1
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut s = format!(
        "//! Implement `Tokens` below: define its fields and the methods. The signatures are fixed.\n//!\n{doc}\npub struct Tokens {{\n    // your fields\n}}\n\nimpl Tokens {{\n    pub fn new(text: &str) -> Tokens {{\n        todo!()\n    }}\n"
    );
    for &q in &spec.queries {
        s.push_str(&format!(
            "\n    {} {{\n        todo!()\n    }}\n",
            query_sig(q)
        ));
    }
    s.push_str("}\n");
    s
}

// ---- examples --------------------------------------------------------------------------------

const WORDS: &[&str] = &[
    "alpha", "beta", "gamma", "delta", "kappa", "omega", "sigma", "theta", "pi", "mu", "xi",
];

fn random_text(tok: Tok, rng: &mut Rng) -> String {
    let n = rng.below(6) as usize;
    let w = |rng: &mut Rng| WORDS[rng.below(WORDS.len() as u64) as usize];
    match tok {
        Tok::Whitespace => {
            let mut s = String::new();
            for i in 0..n {
                if i > 0 || rng.below(3) == 0 {
                    s.push_str([" ", "  ", "\t", "\n"][rng.below(4) as usize]);
                }
                s.push_str(w(rng));
            }
            if rng.below(3) == 0 {
                s.push(' ');
            }
            s
        }
        Tok::Comma => {
            let mut parts = Vec::new();
            for _ in 0..n + 1 {
                let pad = ["", " ", "  "][rng.below(3) as usize];
                let body = if rng.below(4) == 0 { "" } else { w(rng) };
                parts.push(format!("{pad}{body}{pad}"));
            }
            parts.join(",")
        }
        Tok::Lines => {
            let mut s = String::new();
            for i in 0..n + 1 {
                if i > 0 {
                    s.push_str(["\n", "\r\n", "\n\n"][rng.below(3) as usize]);
                }
                s.push_str(w(rng));
            }
            s
        }
        Tok::Fixed(_) => (0..rng.below(20))
            .map(|_| (b'a' + rng.below(26) as u8) as char)
            .collect(),
    }
}

/// The canonical text: several tokens of different lengths, with leading/inner/trailing
/// separators, so every tokenizer produces at least three tokens and `longest` is unambiguous.
fn canonical(tok: Tok) -> String {
    match tok {
        Tok::Whitespace => "  alpha  gamma\tpi\nomegas ".to_string(),
        Tok::Comma => " alpha ,gamma, ,pi,  omegas ".to_string(),
        Tok::Lines => "alpha\r\n\ngamma\npi\nomegas".to_string(),
        Tok::Fixed(_) => "alphagammapiomegas".to_string(),
    }
}

fn worked_examples(spec: &Spec, seed: u64) -> (Vec<String>, String) {
    let mut rng = Rng::new(seed ^ 0x070C_0000_0000_0B01);
    let mut texts = vec![canonical(spec.tok)];
    for _ in 0..3 {
        texts.push(random_text(spec.tok, &mut rng));
    }
    let mut prose = String::new();
    for t in &texts {
        for &q in &spec.queries {
            let (call, arg) = call_src(q, 1, "al");
            prose.push_str(&format!(
                "  Tokens::new({t:?}){call}  ->  {}\n",
                answer(spec.tok, q, t, arg, "al")
            ));
        }
    }
    (texts, prose)
}

/// The method call text and the numeric argument it uses.
fn call_src(q: Query, i: usize, prefix: &str) -> (String, usize) {
    match q {
        Query::Word => (format!(".word({i})"), i),
        Query::Longest => (".longest()".to_string(), 0),
        Query::Find => (format!(".find({prefix:?})"), 0),
        Query::Span => (format!(".span({i})"), i),
        Query::RestFrom => (format!(".rest_from({i})"), i),
    }
}

fn tok_prose(tok: Tok) -> String {
    match tok {
        Tok::Whitespace => "A token is a maximal run of non-whitespace characters (`char::is_whitespace`).".to_string(),
        Tok::Comma => "Split the text at every `,`; each segment is trimmed of surrounding whitespace and **skipped if it is then empty**. A token's span is that of the trimmed segment.".to_string(),
        Tok::Lines => "Split the text at every `\\n`; strip one trailing `\\r` from each line; **skip empty lines**. A token's span is that of the line without the `\\r`.".to_string(),
        Tok::Fixed(k) => format!("Cut the text into consecutive chunks of {k} bytes (the last may be shorter). The input is ASCII."),
    }
}

fn query_prose(q: Query) -> &'static str {
    match q {
        Query::Word => "`word(i)`: token `i` (0-based) as a slice of the text, or `None`.",
        Query::Longest => "`longest()`: the longest token by byte length (the **earliest** on a tie), or `None` with no tokens.",
        Query::Find => "`find(prefix)`: the first token that starts with `prefix`, or `None`.",
        Query::Span => "`span(i)`: token `i`'s byte range `(start, end)` in the original text, or `None`.",
        Query::RestFrom => "`rest_from(i)`: the original text from the start of token `i` to its end, or `\"\"` if there is no token `i`.",
    }
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let qs: String = spec
        .queries
        .iter()
        .map(|&q| format!("  - {}\n", query_prose(q)))
        .collect();
    let (_, examples) = worked_examples(spec, seed);
    let sigs: String = spec
        .queries
        .iter()
        .map(|&q| format!("{}\n", query_sig(q)))
        .collect();
    format!(
        "Implement `Tokens` in `src/lib.rs`: `Tokens::new(text: &str) -> Tokens` tokenizes `text`, and the queries below \
         return slices of that text.\n\
         \n\
         {tok}\n\
         \n\
         Queries:\n\
         {qs}\
         \n\
         **`Tokens` must own its data.** The caller may drop the `String` it built the text from and keep using the \
         `Tokens` (there is no lifetime parameter on `Tokens`, and the query results borrow from the `Tokens`). Define \
         `Tokens`' fields yourself; do not copy each token into its own `String`, and do not leak memory.\n\
         \n\
         Constraints:\n\
         - Keep the signatures below exactly. Do not use `unsafe`.\n\
         \n\
         ```rust\n\
         pub fn new(text: &str) -> Tokens\n\
         {sigs}```\n\
         \n\
         Examples:\n\
         {examples}\n\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        tok = tok_prose(spec.tok),
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

/// The queries as `assert_eq!` lines over `t`, for arguments `0..=2` and `prefix`.
fn assertions(spec: &Spec, text: &str) -> String {
    let mut s = String::new();
    for &q in &spec.queries {
        let args: Vec<(usize, &str)> = match q {
            Query::Longest => vec![(0, "")],
            Query::Find => vec![(0, "al"), (0, "pi"), (0, "zz"), (0, "o")],
            _ => vec![(0, ""), (1, ""), (2, ""), (99, "")],
        };
        for (i, prefix) in args {
            let (call, arg) = call_src(q, i, prefix);
            s.push_str(&format!(
                "        assert_eq!(t{call}, {});\n",
                answer(spec.tok, q, text, arg, prefix)
            ));
        }
    }
    s
}

fn scoped(spec: &Spec, text: &str) -> String {
    format!(
        "    let t;\n    {{\n        let source = String::from({text:?});\n        t = Tokens::new(&source);\n    }}\n    // `source` is gone; `t` must still work.\n    {{\n{}    }}\n",
        assertions(spec, text)
    )
}

fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let (texts, _) = worked_examples(spec, seed);
    let mut body = String::from("use task::Tokens;\n\n");
    for (i, t) in texts.iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn text{i}() {{\n{}}}\n\n",
            scoped(spec, t)
        ));
    }
    body
}

fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec);
    let indented: String = reference.lines().map(|l| format!("    {l}\n")).collect();
    let mut checks = String::new();
    for &q in &spec.queries {
        let line = match q {
            Query::Word | Query::Span | Query::RestFrom => {
                let m = match q {
                    Query::Word => "word",
                    Query::Span => "span",
                    _ => "rest_from",
                };
                format!("for i in 0..8 {{ assert_eq!(t.{m}(i), r.{m}(i), \"{m}({{i}}) of {{text:?}}\"); }}")
            }
            Query::Longest => "assert_eq!(t.longest(), r.longest(), \"longest of {text:?}\");".to_string(),
            Query::Find => "for p in [\"a\", \"al\", \"pi\", \"o\", \"zz\", \"\"] { assert_eq!(t.find(p), r.find(p), \"find({p:?}) of {text:?}\"); }".to_string(),
        };
        checks.push_str(&format!("        {line}\n"));
    }
    let alphabet = match spec.tok {
        Tok::Whitespace => "ab \\t\\n",
        Tok::Comma => "ab ,",
        Tok::Lines => "ab\\n\\r",
        Tok::Fixed(_) => "abc",
    };
    format!(
        "mod reference {{\n{indented}}}\n\n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0x070C_ED00_0000_0052;\n\
         \x20   let mut next = || {{\n\
         \x20       state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20       state >> 33\n\
         \x20   }};\n\
         \x20   let alphabet: Vec<char> = \"{alphabet}\".chars().collect();\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let len = (next() % 16) as usize;\n\
         \x20       let text: String = (0..len).map(|_| alphabet[(next() as usize) % alphabet.len()]).collect();\n\
         \x20       let r = reference::Tokens::new(&text);\n\
         \x20       let t;\n\
         \x20       {{\n\
         \x20           let owned = text.clone();\n\
         \x20           t = task::Tokens::new(&owned);\n\
         \x20       }}\n\
         {checks}\
         \x20   }}\n\
         }}\n"
    )
}

/// Degenerate: no tokens at all.
fn empty(spec: &Spec) -> String {
    let mut s = String::from(
        "pub struct Tokens;\n\nimpl Tokens {\n    pub fn new(text: &str) -> Tokens {\n        let _ = text;\n        Tokens\n    }\n",
    );
    for &q in &spec.queries {
        let body = match q {
            Query::Word | Query::Longest | Query::Find => "None",
            Query::Span => "None",
            Query::RestFrom => "\"\"",
        };
        s.push_str(&format!(
            "\n    {} {{\n        {}\n    }}\n",
            query_sig(q)
                .replace(", i: usize", ", _i: usize")
                .replace("prefix", "_prefix"),
            body
        ));
    }
    s.push_str("}\n");
    s
}

/// Degenerate: the whole text is one token.
fn whole_text(spec: &Spec) -> String {
    let mut s = String::from(
        "pub struct Tokens {\n    text: String,\n}\n\nimpl Tokens {\n    pub fn new(text: &str) -> Tokens {\n        Tokens { text: text.to_string() }\n    }\n",
    );
    for &q in &spec.queries {
        let (sig, body) = match q {
            Query::Word => (
                query_sig(q).to_string(),
                "if i == 0 { Some(&self.text) } else { None }".to_string(),
            ),
            Query::Longest => (query_sig(q).to_string(), "Some(&self.text)".to_string()),
            Query::Find => (
                query_sig(q).to_string(),
                "if self.text.starts_with(prefix) { Some(&self.text) } else { None }".to_string(),
            ),
            Query::Span => (
                query_sig(q).to_string(),
                "if i == 0 { Some((0, self.text.len())) } else { None }".to_string(),
            ),
            Query::RestFrom => (
                query_sig(q).to_string(),
                "if i == 0 { &self.text } else { \"\" }".to_string(),
            ),
        };
        s.push_str(&format!("\n    {sig} {{\n        {body}\n    }}\n"));
    }
    s.push_str("}\n");
    s
}

pub struct OwnTokensFamily;

impl Generator for OwnTokensFamily {
    fn id(&self) -> &str {
        "own-tokens"
    }
    fn category(&self) -> &str {
        "borrow-lifetimes"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("own-tokens", seed);

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
            id: format!("own-tokens/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            max_unsafe: Some(0),
            forbidden_paths: vec!["leak".to_string()],
            check_clippy: false,
            clippy_allow: Vec::new(),
            // borrow-lifetimes is constraint-dominant (docs/04).
            weights: (0.35, 0.55, 0.10),
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
            ("empty".to_string(), empty(&spec)),
            ("whole-text".to_string(), whole_text(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let spec = sample(seed);
        let tok = match spec.tok {
            Tok::Whitespace => "whitespace",
            Tok::Comma => "comma",
            Tok::Lines => "lines",
            Tok::Fixed(_) => "fixed",
        };
        let qs: Vec<&str> = spec
            .queries
            .iter()
            .map(|q| match q {
                Query::Word => "word",
                Query::Longest => "longest",
                Query::Find => "find",
                Query::Span => "span",
                Query::RestFrom => "rest_from",
            })
            .collect();
        vec![format!("tok:{tok}"), format!("queries:{}", qs.join("+"))]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = OwnTokensFamily;
        assert_eq!(g.generate(21).prompt, g.generate(21).prompt);
        assert_eq!(g.generate(21).hidden, g.generate(21).hidden);
    }

    #[test]
    fn tokenizers_match_intent() {
        assert_eq!(
            spans(Tok::Whitespace, "  ab  c\td\n"),
            vec![(2, 4), (6, 7), (8, 9)]
        );
        assert_eq!(spans(Tok::Comma, " ab ,, c,"), vec![(1, 3), (7, 8)]);
        assert_eq!(spans(Tok::Lines, "ab\r\n\ncd"), vec![(0, 2), (5, 7)]);
        assert_eq!(
            spans(Tok::Fixed(3), "abcdefgh"),
            vec![(0, 3), (3, 6), (6, 8)]
        );
        assert!(spans(Tok::Whitespace, "").is_empty());
        assert!(spans(Tok::Fixed(3), "").is_empty());
    }

    #[test]
    fn the_canonical_text_has_enough_tokens_and_a_unique_longest() {
        for tok in [
            Tok::Whitespace,
            Tok::Comma,
            Tok::Lines,
            Tok::Fixed(2),
            Tok::Fixed(5),
        ] {
            let t = canonical(tok);
            let sp = spans(tok, &t);
            assert!(sp.len() >= 3, "{tok:?}: {sp:?}");
        }
        // Whitespace/Comma/Lines: `omegas` is the unique longest.
        for tok in [Tok::Whitespace, Tok::Comma, Tok::Lines] {
            assert_eq!(
                answer(tok, Query::Longest, &canonical(tok), 0, ""),
                "Some(\"omegas\")"
            );
        }
    }

    #[test]
    fn longest_ties_go_to_the_earliest() {
        assert_eq!(
            answer(Tok::Whitespace, Query::Longest, "ab cd e", 0, ""),
            "Some(\"ab\")"
        );
    }

    #[test]
    fn rest_from_returns_the_original_text_tail() {
        assert_eq!(
            answer(Tok::Comma, Query::RestFrom, "x, yy ,zz", 1, ""),
            "\"yy ,zz\""
        );
        assert_eq!(answer(Tok::Comma, Query::RestFrom, "x", 5, ""), "\"\"");
    }

    #[test]
    fn the_tests_drop_the_source_first_and_the_reference_owns_a_string() {
        for seed in 0..40u64 {
            let t = OwnTokensFamily.generate(seed);
            let b = &t.hidden[&PathBuf::from("tests/behavior.rs")];
            assert!(b.contains("`source` is gone") || b.contains("source is gone"));
            let r = reference_src(&sample(seed));
            assert!(r.contains("text: String") && !r.contains("<'a>"));
        }
    }

    #[test]
    fn seeds_vary_both_axes() {
        let mut s = std::collections::HashSet::new();
        for seed in 0..1200u64 {
            s.insert(OwnTokensFamily.spec_signature(seed).join("|"));
        }
        assert_eq!(s.len(), 40);
    }

    #[test]
    fn leak_is_forbidden_and_canary_present() {
        let t = OwnTokensFamily.generate(3);
        assert_eq!(t.forbidden_paths, vec!["leak".to_string()]);
        assert!(t.prompt.contains(&t.canary));
    }
}
