//! Glob patterns over workspace-relative paths (design row H2e): the
//! pattern of `harness.fs.glob` and the `include` / `exclude` filters of
//! `harness.fs.search`. Written here rather than taken from a crate: the
//! syntax is small, and the matcher below is linear by construction.
//!
//! **Syntax.** Paths are `/`-separated and relative (the walk's own
//! strings, never the host's):
//! - `*` matches any run of characters except `/`; `?` one character
//!   except `/`;
//! - `[abc]`, `[a-z]` one character in the set, `[!a-z]` (or `[^a-z]`)
//!   one character not in it (never `/`); a `]` right after the opening
//!   `[` (or `[!`) is literal;
//! - `{a,b,c}` alternatives (no nesting; at most [`MAX_ALTERNATIVES`]
//!   patterns after expansion);
//! - `**` as a whole component matches zero or more components: `**/x`
//!   matches `x` and `a/b/x`, `a/**/b` matches `a/b` and `a/x/y/b`, and a
//!   final `a/**` everything below `a`; a `**` inside a component is `*`.
//!
//! A pattern (after brace expansion) without a `/` matches the entry's
//! NAME, its last component, at any depth (`*.rs` finds every Rust file);
//! one with a `/` matches the whole path.
//!
//! **Refused**, with a typed [`GlobError`] (the tools report static text,
//! never the pattern): an empty pattern, one over [`MAX_PATTERN_BYTES`], a
//! leading `/`, a `\`, a control character, an empty component (`a//b`, a
//! trailing `/`), a `.` or `..` component, an unclosed `[` or `{`, a
//! nested `{`, a stray `}`, and too many alternatives. A refused pattern
//! can never be made to match outside the walk (matching is on strings the
//! confined walk produced), but a `..` or an absolute path says the caller
//! meant something the tools do not do, so it is refused rather than left
//! to match nothing.
//!
//! **Matching is linear**: each alternative compiles to a token list, and a
//! path is matched by simulating the set of reachable token positions one
//! character at a time (no backtracking), so a pattern like `*a*a*a*a*b`
//! costs `O(tokens × path length)`, never exponential time.

use std::fmt;

/// Longest pattern accepted, in bytes.
pub const MAX_PATTERN_BYTES: usize = 256;
/// Most patterns a brace expansion may produce.
pub const MAX_ALTERNATIVES: usize = 64;

/// Why a glob pattern was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobError {
    /// The pattern is empty.
    Empty,
    /// Longer than [`MAX_PATTERN_BYTES`].
    TooLong,
    /// It starts with `/`: patterns are relative.
    Absolute,
    /// A `\`: paths use `/`, and there is no escape character.
    Backslash,
    /// A control character.
    Control,
    /// An empty component (`a//b`, a trailing `/`).
    EmptyComponent,
    /// A `.` or `..` component.
    DotComponent,
    /// A `[` with no closing `]`.
    UnclosedClass,
    /// A `{` with no closing `}`, a `{` inside braces, or a stray `}`.
    Braces,
    /// More than [`MAX_ALTERNATIVES`] patterns after brace expansion.
    TooManyAlternatives,
}

impl fmt::Display for GlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl GlobError {
    /// Static harness text for the error (what the tools show the model).
    pub fn message(&self) -> &'static str {
        match self {
            GlobError::Empty => "the glob pattern is empty",
            GlobError::TooLong => "the glob pattern is longer than 256 bytes",
            GlobError::Absolute => "the glob pattern must be relative (no leading '/')",
            GlobError::Backslash => "the glob pattern may not contain '\\'; paths use '/'",
            GlobError::Control => "the glob pattern contains a control character",
            GlobError::EmptyComponent => {
                "the glob pattern has an empty component ('//' or a trailing '/')"
            }
            GlobError::DotComponent => "the glob pattern may not have a '.' or '..' component",
            GlobError::UnclosedClass => "the glob pattern has a '[' with no closing ']'",
            GlobError::Braces => {
                "the glob pattern's braces are unbalanced or nested ({a,b} alternatives do not nest)"
            }
            GlobError::TooManyAlternatives => {
                "the glob pattern expands to more than 64 alternatives"
            }
        }
    }
}

/// One compiled element of a pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// This character.
    Lit(char),
    /// `?`: any one character except `/`.
    One,
    /// `[...]`: one character (not `/`) in (or, negated, not in) the ranges.
    Class {
        neg: bool,
        ranges: Vec<(char, char)>,
    },
    /// `*`: any run of characters except `/`.
    Star,
    /// `**/` (a whole component, not last): zero or more complete
    /// components, each with its `/`.
    Dirs,
    /// `**` as the last component: anything, `/` included.
    All,
}

/// One alternative of a pattern, compiled.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Alt {
    toks: Vec<Tok>,
    /// No `/` in the alternative: it matches the last component only.
    name_only: bool,
}

/// A checked, compiled glob pattern (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Glob {
    alts: Vec<Alt>,
    /// The deepest path (in components) any alternative can match, or
    /// `None` when one has `**` or matches names at any depth.
    depth: Option<usize>,
}

impl Glob {
    /// Check and compile `pattern`.
    pub fn new(pattern: &str) -> Result<Self, GlobError> {
        if pattern.is_empty() {
            return Err(GlobError::Empty);
        }
        if pattern.len() > MAX_PATTERN_BYTES {
            return Err(GlobError::TooLong);
        }
        if pattern.starts_with('/') {
            return Err(GlobError::Absolute);
        }
        if pattern.contains('\\') {
            return Err(GlobError::Backslash);
        }
        if pattern.chars().any(char::is_control) {
            return Err(GlobError::Control);
        }
        let mut alts = Vec::new();
        let mut depth = Some(0usize);
        for a in expand(pattern)? {
            let comps: Vec<&str> = a.split('/').collect();
            if comps.iter().any(|c| c.is_empty()) {
                return Err(GlobError::EmptyComponent);
            }
            if comps.iter().any(|c| *c == "." || *c == "..") {
                return Err(GlobError::DotComponent);
            }
            let name_only = comps.len() == 1;
            let mut toks = Vec::new();
            let last = comps.len() - 1;
            let mut deep = name_only;
            for (i, c) in comps.iter().enumerate() {
                if *c == "**" {
                    deep = true;
                    if i == last {
                        toks.push(Tok::All);
                    } else {
                        toks.push(Tok::Dirs);
                    }
                    continue;
                }
                compile_component(c, &mut toks)?;
                if i != last {
                    toks.push(Tok::Lit('/'));
                }
            }
            depth = match (depth, deep) {
                (Some(d), false) => Some(d.max(comps.len())),
                _ => None,
            };
            alts.push(Alt { toks, name_only });
        }
        Ok(Self { alts, depth })
    }

    /// Whether the `/`-separated relative `path` matches.
    pub fn matches(&self, path: &str) -> bool {
        let name = path.rsplit('/').next().unwrap_or(path);
        self.alts
            .iter()
            .any(|a| run(&a.toks, if a.name_only { name } else { path }))
    }

    /// The deepest path, in components, the pattern can match (a walk need
    /// not descend further), or `None` when it can match at any depth.
    pub fn max_depth(&self) -> Option<usize> {
        self.depth
    }
}

/// Expand `{a,b}` groups (not nested) into every combination, in order.
fn expand(pattern: &str) -> Result<Vec<String>, GlobError> {
    let mut out = vec![String::new()];
    let mut rest = pattern;
    while let Some(open) = rest.find(['{', '}']) {
        let (head, tail) = rest.split_at(open);
        if tail.starts_with('}') {
            return Err(GlobError::Braces);
        }
        let tail = tail.get(1..).unwrap_or("");
        let close = tail.find('}').ok_or(GlobError::Braces)?;
        let (group, after) = tail.split_at(close);
        if group.contains('{') {
            return Err(GlobError::Braces);
        }
        let choices: Vec<&str> = group.split(',').collect();
        let mut next = Vec::new();
        for prefix in &out {
            for c in &choices {
                if next.len() == MAX_ALTERNATIVES {
                    return Err(GlobError::TooManyAlternatives);
                }
                next.push(format!("{prefix}{head}{c}"));
            }
        }
        out = next;
        rest = after.get(1..).unwrap_or("");
    }
    for s in &mut out {
        s.push_str(rest);
    }
    Ok(out)
}

/// Compile one component (no `/` in it, not `**`) onto `toks`.
fn compile_component(c: &str, toks: &mut Vec<Tok>) -> Result<(), GlobError> {
    let chars: Vec<char> = c.chars().collect();
    let mut i = 0;
    while let Some(&ch) = chars.get(i) {
        match ch {
            '*' => {
                // A run of stars inside a component is one `*`.
                if toks.last() != Some(&Tok::Star) {
                    toks.push(Tok::Star);
                }
                i += 1;
            }
            '?' => {
                toks.push(Tok::One);
                i += 1;
            }
            '[' => {
                let (tok, used) = class(chars.get(i + 1..).unwrap_or(&[]))?;
                toks.push(tok);
                i += 1 + used;
            }
            _ => {
                toks.push(Tok::Lit(ch));
                i += 1;
            }
        }
    }
    Ok(())
}

/// Parse a class after its `[`: returns the token and how many characters
/// it used (the closing `]` included).
fn class(s: &[char]) -> Result<(Tok, usize), GlobError> {
    let mut i = 0;
    let neg = matches!(s.first(), Some('!' | '^'));
    if neg {
        i += 1;
    }
    let mut ranges = Vec::new();
    let mut first = true;
    loop {
        let Some(&c) = s.get(i) else {
            return Err(GlobError::UnclosedClass);
        };
        if c == ']' && !first {
            return Ok((Tok::Class { neg, ranges }, i + 1));
        }
        first = false;
        match (s.get(i + 1), s.get(i + 2)) {
            (Some('-'), Some(&hi)) if hi != ']' => {
                ranges.push((c, hi));
                i += 3;
            }
            _ => {
                ranges.push((c, c));
                i += 1;
            }
        }
    }
}

fn class_has(neg: bool, ranges: &[(char, char)], c: char) -> bool {
    c != '/' && (ranges.iter().any(|&(lo, hi)| lo <= c && c <= hi) != neg)
}

/// Simulate the pattern over `path`: the set of reachable positions (and,
/// for [`Tok::Dirs`], whether a component is part-way consumed), advanced
/// one character at a time. Linear in `toks.len() × path.len()`.
fn run(toks: &[Tok], path: &str) -> bool {
    let n = toks.len();
    // State 2i: at token i; 2i + 1: inside a component consumed by the
    // `Dirs` at token i (needs a `/` to return to 2i).
    let mut cur = vec![false; 2 * (n + 1)];
    let mut next = vec![false; 2 * (n + 1)];
    add(toks, &mut cur, 0);
    for c in path.chars() {
        next.iter_mut().for_each(|b| *b = false);
        for s in 0..cur.len() {
            if !cur.get(s).copied().unwrap_or(false) {
                continue;
            }
            let i = s / 2;
            let inside = s % 2 == 1;
            let Some(t) = toks.get(i) else { continue };
            match t {
                Tok::Lit(l) if !inside && *l == c => add(toks, &mut next, 2 * (i + 1)),
                Tok::One if !inside && c != '/' => add(toks, &mut next, 2 * (i + 1)),
                Tok::Class { neg, ranges } if !inside && class_has(*neg, ranges, c) => {
                    add(toks, &mut next, 2 * (i + 1));
                }
                Tok::Star if c != '/' => add(toks, &mut next, 2 * i),
                Tok::All => add(toks, &mut next, 2 * i),
                Tok::Dirs if c == '/' && inside => add(toks, &mut next, 2 * i),
                Tok::Dirs if c != '/' => add(toks, &mut next, 2 * i + 1),
                _ => {}
            }
        }
        std::mem::swap(&mut cur, &mut next);
        if !cur.iter().any(|&b| b) {
            return false;
        }
    }
    cur.get(2 * n).copied().unwrap_or(false)
}

/// Add state `s` and everything reachable from it without a character.
fn add(toks: &[Tok], set: &mut [bool], s: usize) {
    let mut s = s;
    loop {
        match set.get_mut(s) {
            Some(b) if !*b => *b = true,
            _ => return,
        }
        // Only an outer state (not inside a component) of a star-like token
        // may skip it.
        if s % 2 == 1 {
            return;
        }
        match toks.get(s / 2) {
            Some(Tok::Star | Tok::All | Tok::Dirs) => s += 2,
            _ => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, path: &str) -> bool {
        Glob::new(p).unwrap().matches(path)
    }

    #[test]
    fn a_pattern_without_a_slash_matches_names_at_any_depth() {
        assert!(m("*.rs", "lib.rs"));
        assert!(m("*.rs", "src/net/mod.rs"));
        assert!(!m("*.rs", "src/lib.rsx"));
        assert!(m("mod.rs", "src/net/mod.rs"));
        assert!(!m("mod.rs", "src/net/amod.rs"));
        assert!(m("?at", "x/cat"));
        assert!(!m("?at", "x/at"));
    }

    #[test]
    fn a_pattern_with_a_slash_matches_the_whole_path() {
        assert!(m("src/*.rs", "src/lib.rs"));
        assert!(!m("src/*.rs", "src/net/mod.rs"));
        assert!(!m("src/*.rs", "a/src/lib.rs"));
        assert!(m("src/*/mod.rs", "src/net/mod.rs"));
        assert!(!m("src/*/mod.rs", "src/mod.rs"));
        // `*` never crosses a `/`.
        assert!(!m("src/*", "src/net/mod.rs"));
    }

    #[test]
    fn a_double_star_component_spans_any_number_of_components() {
        assert!(m("**/*.rs", "lib.rs"));
        assert!(m("**/*.rs", "src/net/mod.rs"));
        assert!(m("src/**/mod.rs", "src/mod.rs"));
        assert!(m("src/**/mod.rs", "src/a/b/c/mod.rs"));
        assert!(!m("src/**/mod.rs", "srcx/mod.rs"));
        assert!(m("src/**", "src/a"));
        assert!(m("src/**", "src/a/b.rs"));
        assert!(!m("src/**", "src"));
        assert!(!m("src/**", "other/a"));
        assert!(m("**", "anything/at/all"));
        // A `**` inside a component is a `*`.
        assert!(m("a**b", "axxb"));
        assert!(!m("x/a**b", "x/a/b"));
    }

    #[test]
    fn classes_and_braces() {
        assert!(m("[abc].rs", "b.rs"));
        assert!(!m("[abc].rs", "d.rs"));
        assert!(m("[a-c]x", "bx"));
        assert!(m("[!a-c]x", "dx"));
        assert!(m("[^a-c]x", "dx"));
        assert!(!m("[!a-c]x", "ax"));
        assert!(m("[]]", "]"));
        assert!(m("[a-]", "-"));
        assert!(m("*.{rs,toml}", "Cargo.toml"));
        assert!(m("*.{rs,toml}", "src/lib.rs"));
        assert!(!m("*.{rs,toml}", "README.md"));
        assert!(m("{src,docs}/*.md", "docs/a.md"));
        assert!(!m("{src,docs}/*.md", "x/docs/a.md"));
        assert!(m("a{,.bak}", "a.bak"));
        assert!(m("a{,.bak}", "a"));
        // A class never matches `/`.
        assert!(!m("a[!x]b", "a/b"));
    }

    #[test]
    fn bad_patterns_are_typed_errors() {
        let e = |p: &str| Glob::new(p).unwrap_err();
        assert_eq!(e(""), GlobError::Empty);
        assert_eq!(e(&"a".repeat(257)), GlobError::TooLong);
        assert_eq!(e("/etc/*"), GlobError::Absolute);
        assert_eq!(e("a\\b"), GlobError::Backslash);
        assert_eq!(e("a\nb"), GlobError::Control);
        assert_eq!(e("a//b"), GlobError::EmptyComponent);
        assert_eq!(e("a/"), GlobError::EmptyComponent);
        assert_eq!(e("../x"), GlobError::DotComponent);
        assert_eq!(e("a/./b"), GlobError::DotComponent);
        assert_eq!(e("{..,a}/x"), GlobError::DotComponent);
        assert_eq!(e("[ab"), GlobError::UnclosedClass);
        assert_eq!(e("{a,b"), GlobError::Braces);
        assert_eq!(e("a}"), GlobError::Braces);
        assert_eq!(e("{a,{b,c}}"), GlobError::Braces);
        assert_eq!(
            e("{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}"),
            GlobError::TooManyAlternatives
        );
        assert!(Glob::new(&"a".repeat(256)).is_ok());
        assert!(Glob::new("{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}").is_ok());
        for err in [GlobError::Empty, GlobError::Braces, GlobError::DotComponent] {
            assert!(!err.message().is_empty());
        }
    }

    #[test]
    fn depth_bounds_the_walk_only_without_double_stars_or_names() {
        assert_eq!(Glob::new("src/*/mod.rs").unwrap().max_depth(), Some(3));
        assert_eq!(Glob::new("{a,b/c}/x").unwrap().max_depth(), Some(3));
        assert_eq!(Glob::new("*.rs").unwrap().max_depth(), None);
        assert_eq!(Glob::new("src/**/x").unwrap().max_depth(), None);
    }

    // No backtracking: a pattern that is exponential for a naive matcher
    // over a long non-matching path finishes at once.
    #[test]
    fn matching_is_linear_on_hostile_patterns() {
        let p = format!("{}b", "*a".repeat(40));
        let path = "a".repeat(200);
        let t = std::time::Instant::now();
        assert!(!m(&p, &path));
        let q = format!("{}/x", vec!["**"; 20].join("/"));
        assert!(!m(&q, "a/".repeat(90).trim_end_matches('/')));
        assert!(t.elapsed() < std::time::Duration::from_secs(2));
    }
}
