//! `harness.fs.search` and `harness.fs.glob` (design §4.8; row H2e): text
//! search, literal or by regular expression, with glob filters and context
//! lines, and finding files by a glob pattern. Both walk the workspace with
//! the read tools' confinement ([`crate::builtin`]): the start path is
//! resolved component by component with no symlink at any component, the
//! walk never follows or descends into a symlink, and it is bounded in
//! entries, depth and time.
//!
//! **Search.** `pattern` is a literal substring by default, as before H2e;
//! with `regex: true` it is a regular expression in the syntax of the
//! `regex` crate, whose matching is linear in pattern × input (finite
//! automata: no backtracking, no look-around, no backreferences), with the
//! compiled program and its lazy DFA held to fixed sizes. Either way it is
//! matched line by line. A pattern that does not compile is a typed error
//! whose text is static harness words chosen by the error's kind
//! ([`regex_problem`]), never the parser's message (which quotes the
//! pattern). `include` and `exclude` are globs ([`crate::glob`]) over each
//! path relative to the search's `path`: a file is searched when it matches
//! `include` (if given) and not `exclude`; a directory that matches
//! `exclude` is not entered. `context` (0-5) adds that many lines before
//! and after each hit, grep-style (`12: hit`, `11- context`, `--` between
//! separate groups).
//!
//! **Bounds.** Every hit is counted. At most [`SEARCH_MAX_HITS`] are
//! shown, at most [`SEARCH_MAX_HITS_PER_FILE`] per file (one noisy file must
//! not hide the others: a judge-reviewed run's capped search hid the file
//! with the answer), within [`SEARCH_MAX_LINES`] lines and
//! [`SEARCH_MAX_BODY_BYTES`] bytes, so a result always fits the context's
//! per-observation cap and is never cut there. A file shown in part says so
//! (`(80 hits, 10 shown)`); the files with hits that were not shown are
//! named with their counts (up to [`SEARCH_MAX_MORE_FILES`]; past that the
//! count stops and says so): nothing is dropped silently. A hit line over
//! [`SEARCH_LINE_MAX_BYTES`] shows the bytes around its match, a context
//! line its head. Files over [`SEARCH_FILE_MAX_BYTES`] and non-UTF-8 files
//! are skipped and counted. Hits are grouped by file, in path order. Zero
//! hits say how to search (an exact identifier or word; `regex: true` for
//! alternatives).
//!
//! **Glob.** `harness.fs.glob {pattern, path?}` lists the regular files
//! under `path` whose path relative to `path` matches `pattern`, in path
//! order, with their sizes, at most [`GLOB_MAX_RESULTS`] of them. A pattern
//! without `**` bounds how deep the walk goes.
//!
//! **`.git` is skipped.** A directory named `.git` below the start of a
//! search or a glob is neither entered nor matched (a repository's object
//! store is never what a task asks for, and its entries would use up the
//! walk's limit); the result says how many were skipped. Starting a search
//! AT a `.git` directory searches it.
//!
//! **Policy-denied paths are skipped, never silent (P-12).** The read tools
//! may carry deny globs from the run's policy ([`ReadTools::with_denied`]):
//! a directory a glob names is neither entered nor matched, a file it names
//! is not searched or matched, and the result says how many paths were
//! skipped. The start path itself is not pre-checked here — a call whose
//! `path` names a denied path is refused by the policy before the tools run
//! (the same matcher), so what arrives here is a walk that stays inside
//! what the policy allows.

use std::time::Instant;

use harness_policy::WorkspacePath;
use serde_json::Value;

use crate::builtin::{
    arg_path, arg_u64, code, err, ok, read_bounded, shown_path, timeout, Entry, Out, ReadTools,
    Walk, SEARCH_FILE_MAX_BYTES, SEARCH_LINE_MAX_BYTES, WALK_MAX_DEPTH, WALK_MAX_ENTRIES,
};
use crate::glob::Glob;

/// Most search hits shown (§4.8); every hit is still counted.
pub const SEARCH_MAX_HITS: usize = 50;
/// Most hits shown for one file, so one file cannot use the whole budget
/// and hide the others (a judge-reviewed run: the file that held the
/// answer was never shown behind a capped result).
pub const SEARCH_MAX_HITS_PER_FILE: usize = 10;
/// Most lines of the shown hits (hit lines, context lines, file headers and
/// group separators).
pub const SEARCH_MAX_LINES: usize = 60;
/// Most bytes of the shown hits.
pub const SEARCH_MAX_BODY_BYTES: usize = 10 * 1024;
/// Most files with hits listed after the shown ones (name and hit count).
pub const SEARCH_MAX_MORE_FILES: usize = 200;
/// Most bytes of that list; past it, the rest are counted in one line.
const SEARCH_MORE_BYTES: usize = 4 * 1024;
/// Most context lines before and after a hit.
pub const SEARCH_MAX_CONTEXT: u64 = 5;
/// Most files `harness.fs.glob` lists (the head and foot fit beside them
/// under the context's per-observation cap).
pub const GLOB_MAX_RESULTS: usize = 90;
/// The compiled regular expression's size limit, in bytes.
const REGEX_SIZE_LIMIT: usize = 1 << 20;
/// The lazy DFA's cache limit, in bytes.
const REGEX_DFA_LIMIT: usize = 2 << 20;
/// Deepest nesting a regular expression may have.
const REGEX_NEST_LIMIT: u32 = 64;

/// How a search matches a line.
enum Matcher {
    Literal(String),
    Regex(regex::Regex),
}

impl Matcher {
    /// The first match in `line`, as a byte range.
    fn find(&self, line: &str) -> Option<(usize, usize)> {
        match self {
            Matcher::Literal(p) => line.find(p.as_str()).map(|s| (s, s + p.len())),
            Matcher::Regex(r) => r.find(line).map(|m| (m.start(), m.end())),
        }
    }
}

/// A hit line as shown: whole when it is at most `max` bytes; otherwise
/// the `max` bytes around its first match, marked `…` where cut (a head
/// cut could hide the very text that matched).
fn excerpt(line: &str, span: Option<(usize, usize)>, max: usize) -> (String, bool) {
    if line.len() <= max {
        return (line.to_owned(), false);
    }
    let Some((s, e)) = span else {
        return (crate::builtin::cut(line, max), false);
    };
    let room = max.saturating_sub(e.saturating_sub(s).min(max)) / 2;
    let mut from = s.saturating_sub(room);
    while !line.is_char_boundary(from) {
        from -= 1;
    }
    let mut to = (from + max).min(line.len());
    while !line.is_char_boundary(to) {
        to -= 1;
    }
    let mut out = String::new();
    if from > 0 {
        out.push('…');
    }
    out.push_str(line.get(from..to).unwrap_or(""));
    if to < line.len() {
        out.push('…');
    }
    (out, true)
}

/// What one file shows.
struct Block {
    rel: String,
    /// Its hits.
    total: usize,
    /// Of them, shown.
    shown: usize,
    /// Rendered lines (without the file's header).
    body: Vec<String>,
}

/// The shown hits' budget, across files.
#[derive(Default)]
struct Budget {
    hits: usize,
    lines: usize,
    bytes: usize,
    /// No more hits will be shown: every later file is only counted.
    full: bool,
    /// A long hit line was shown as the window around its match.
    windowed: bool,
    /// The shown budget ended on its lines or bytes, not on a hit cap: a
    /// smaller context would have let more hits in (H2f).
    cut_by_size: bool,
}

impl Budget {
    /// Render up to [`SEARCH_MAX_HITS_PER_FILE`] of a file's hits with
    /// `context` lines around each, grep-style, within what is left of the
    /// budget; a hit inside the previous hit's window is re-marked as a hit.
    fn render(
        &mut self,
        rel: &str,
        all: &[&str],
        hits: &[usize],
        context: usize,
        m: &Matcher,
    ) -> Block {
        let mut block = Block {
            rel: rel.to_owned(),
            total: hits.len(),
            shown: 0,
            body: Vec::new(),
        };
        // The last line index the current group shows.
        let mut group_end: Option<usize> = None;
        for &i in hits.iter().take(SEARCH_MAX_HITS_PER_FILE) {
            if self.hits == SEARCH_MAX_HITS {
                self.full = true;
                break;
            }
            let lo = i.saturating_sub(context);
            let hi = (i + context).min(all.len().saturating_sub(1));
            let (from, sep) = match group_end {
                Some(end) if lo <= end + 1 => (end + 1, false),
                Some(_) => (lo, true),
                None => (lo, false),
            };
            let mut add: Vec<String> = Vec::new();
            let mut windowed = false;
            if sep {
                add.push("  --".to_owned());
            }
            for j in from..=hi {
                let Some(l) = all.get(j) else { break };
                let (text, w) = if j == i {
                    excerpt(l, m.find(l), SEARCH_LINE_MAX_BYTES)
                } else {
                    (crate::builtin::cut(l, SEARCH_LINE_MAX_BYTES), false)
                };
                windowed |= w;
                add.push(format!(
                    "  {}{} {text}",
                    j + 1,
                    if j == i { ':' } else { '-' }
                ));
            }
            let header = usize::from(block.shown == 0);
            let add_bytes =
                add.iter().map(|l| l.len() + 1).sum::<usize>() + header * (rel.len() + 24);
            if self.lines + add.len() + header > SEARCH_MAX_LINES
                || self.bytes + add_bytes > SEARCH_MAX_BODY_BYTES
            {
                self.full = true;
                self.cut_by_size = true;
                break;
            }
            // A hit already shown as the previous hit's context.
            if from > i {
                let was = format!("  {}- ", i + 1);
                if let Some(prev) = block.body.iter_mut().rev().find(|l| l.starts_with(&was)) {
                    let (text, w) = excerpt(
                        all.get(i).copied().unwrap_or(""),
                        all.get(i).and_then(|l| m.find(l)),
                        SEARCH_LINE_MAX_BYTES,
                    );
                    windowed |= w;
                    *prev = format!("  {}: {text}", i + 1);
                }
            }
            self.windowed |= windowed;
            self.lines += add.len() + header;
            self.bytes += add_bytes;
            self.hits += 1;
            block.shown += 1;
            block.body.extend(add);
            group_end = Some(hi.max(group_end.unwrap_or(0)));
        }
        block
    }
}

/// The files with hits that were not shown, with their counts, packed a
/// few to a line, within [`SEARCH_MORE_BYTES`]; the rest in one count.
fn more_list(s: &mut String, more: &[(String, usize)]) {
    if more.is_empty() {
        return;
    }
    let mut line = String::from("more hits in:");
    let mut used = 0usize;
    let mut listed = 0usize;
    for (rel, n) in more {
        let item = format!(" {rel} ({n}),");
        if used + item.len() > SEARCH_MORE_BYTES {
            break;
        }
        if line.len() + item.len() > 200 {
            s.push_str(line.trim_end_matches(','));
            s.push('\n');
            line = String::from(" ");
        }
        used += item.len();
        line.push_str(&item);
        listed += 1;
    }
    s.push_str(line.trim_end_matches(','));
    s.push('\n');
    if listed < more.len() {
        s.push_str(&format!(
            "and {} more file(s) with hits\n",
            more.len() - listed
        ));
    }
}

/// Static harness words for why a regular expression was refused, chosen
/// by the parser's typed error kind. The pattern itself is never quoted.
pub fn regex_problem(pattern: &str) -> Option<&'static str> {
    use regex_syntax::ast::ErrorKind as A;
    use regex_syntax::hir::ErrorKind as H;
    let ast = match regex_syntax::ast::parse::ParserBuilder::new()
        .nest_limit(REGEX_NEST_LIMIT)
        .build()
        .parse(pattern)
    {
        Ok(ast) => ast,
        Err(e) => {
            return Some(match e.kind() {
                A::GroupUnclosed | A::GroupUnopened => {
                    "the regular expression has an unbalanced parenthesis"
                }
                A::ClassUnclosed => "the regular expression has a '[' with no closing ']'",
                A::RepetitionMissing => {
                    "a repetition operator (*, +, ? or {n}) in the regular expression has nothing to repeat"
                }
                A::RepetitionCountInvalid
                | A::RepetitionCountUnclosed
                | A::RepetitionCountDecimalEmpty
                | A::DecimalEmpty
                | A::DecimalInvalid => "a counted repetition {n,m} in the regular expression is malformed",
                A::EscapeUnrecognized
                | A::EscapeUnexpectedEof
                | A::EscapeHexEmpty
                | A::EscapeHexInvalid
                | A::EscapeHexInvalidDigit => {
                    "the regular expression has an unknown or incomplete escape (a literal dot is \\., a literal backslash \\\\)"
                }
                A::UnsupportedLookAround => {
                    "look-around ((?=...), (?!...), (?<=...), (?<!...)) is not supported; match the text itself"
                }
                A::UnsupportedBackreference => "backreferences (\\1) are not supported",
                A::NestLimitExceeded(_) => "the regular expression is nested too deeply",
                A::FlagUnrecognized
                | A::FlagUnexpectedEof
                | A::FlagDanglingNegation
                | A::FlagDuplicate { .. }
                | A::FlagRepeatedNegation { .. } => {
                    "an inline flag group in the regular expression is malformed (the flags are i, m, s, U, u, x, as in (?i))"
                }
                A::ClassRangeInvalid | A::ClassRangeLiteral | A::ClassEscapeInvalid => {
                    "a character class range in the regular expression is invalid"
                }
                A::UnicodeClassInvalid => "the regular expression names an unknown Unicode class",
                A::GroupNameDuplicate { .. }
                | A::GroupNameEmpty
                | A::GroupNameInvalid
                | A::GroupNameUnexpectedEof => "a capture group name in the regular expression is invalid",
                A::CaptureLimitExceeded => "the regular expression has too many groups",
                _ => "the pattern is not a valid regular expression",
            })
        }
    };
    if let Err(e) = regex_syntax::hir::translate::TranslatorBuilder::new()
        .build()
        .translate(pattern, &ast)
    {
        return Some(match e.kind() {
            H::UnicodePropertyNotFound
            | H::UnicodePropertyValueNotFound
            | H::UnicodePerlClassNotFound
            | H::UnicodeCaseUnavailable => "the regular expression names an unknown Unicode class",
            _ => "the pattern is not a valid regular expression",
        });
    }
    None
}

/// Compile a model-supplied regular expression under the size limits, or
/// the static words for why not.
fn compile(pattern: &str) -> Result<regex::Regex, &'static str> {
    if let Some(why) = regex_problem(pattern) {
        return Err(why);
    }
    regex::RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_DFA_LIMIT)
        .nest_limit(REGEX_NEST_LIMIT)
        .build()
        .map_err(|e| match e {
            regex::Error::CompiledTooBig(_) => {
                "the regular expression compiles too large; make it simpler or narrower"
            }
            _ => "the pattern is not a valid regular expression",
        })
}

/// An optional glob argument.
fn arg_glob(args: &Value, key: &str) -> Result<Option<Glob>, Out> {
    match args.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => Glob::new(s)
            .map(Some)
            .map_err(|e| err(code::BAD_PATTERN, &format!("{key}: {}", e.message()))),
        Some(_) => Err(err(code::BAD_ARGS, "a glob argument is not a string")),
    }
}

/// The path of a walked entry relative to the walk's start (what the globs
/// match): its path below the start, or its own name for the start itself.
fn below<'a>(start: &WorkspacePath, rel: &'a str) -> &'a str {
    let s = start.as_str();
    if s.is_empty() {
        return rel;
    }
    match rel.strip_prefix(s).and_then(|r| r.strip_prefix('/')) {
        Some(r) => r,
        None => rel.rsplit('/').next().unwrap_or(rel),
    }
}

/// Whether a walked directory is entered: not a `.git` below the start, not
/// a policy-denied path (counted when skipped, P-12), and not excluded.
fn enter(
    e: &Entry,
    start: &WorkspacePath,
    exclude: Option<&Glob>,
    gits: &mut usize,
    denied: &[Glob],
    denied_count: &mut usize,
) -> bool {
    if e.depth == 0 {
        return true;
    }
    if e.rel.rsplit('/').next() == Some(".git") {
        *gits += 1;
        return false;
    }
    if denied.iter().any(|g| g.matches(&e.rel)) {
        *denied_count += 1;
        return false;
    }
    !exclude.is_some_and(|g| g.matches(below(start, &e.rel)))
}

/// The walk's counters, for the result's foot.
fn foot(s: &mut String, walk: &Walk, skipped: usize, gits: usize, denied: usize) {
    if denied > 0 {
        s.push_str(&format!("{denied} path(s) skipped (denied by policy)\n"));
    }
    if skipped > 0 {
        s.push_str(&format!(
            "{skipped} file(s) not searched (larger than 1 MiB, unreadable or not UTF-8)\n"
        ));
    }
    if walk.symlinks > 0 {
        s.push_str(&format!("{} symlink(s) not followed\n", walk.symlinks));
    }
    if gits > 0 {
        s.push_str(&format!("{gits} .git director(y/ies) skipped\n"));
    }
    if walk.stopped {
        s.push_str("the walk stopped at its entry limit\n");
    }
    if walk.unreadable > 0 {
        s.push_str(&format!(
            "{} entr(y/ies) could not be read\n",
            walk.unreadable
        ));
    }
}

impl ReadTools {
    pub(crate) fn search(&mut self, args: &Value, deadline: Instant) -> Out {
        match self.try_search(args, deadline) {
            Ok(o) | Err(o) => o,
        }
    }

    fn try_search(&mut self, args: &Value, deadline: Instant) -> Result<Out, Out> {
        let pattern = match args.get("pattern") {
            Some(Value::String(p)) if !p.is_empty() => p.clone(),
            _ => {
                return Err(err(
                    code::BAD_ARGS,
                    "the pattern must be a non-empty string",
                ))
            }
        };
        let regex = match args.get("regex") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(err(code::BAD_ARGS, "regex must be true or false")),
        };
        let wp = arg_path(args, "path", Some("."))?;
        let include = arg_glob(args, "include")?;
        let exclude = arg_glob(args, "exclude")?;
        let context =
            usize::try_from(arg_u64(args, "context", 0, 0, SEARCH_MAX_CONTEXT)?).unwrap_or(0);
        // A literal that looks like a regex and matches nothing is worth a
        // word (H2e: a local model searched `MAX_[A-Z_]+_RETRIES` with
        // `regex: false` and got zero hits and no hint).
        let looks_regex =
            !regex && pattern.contains(['[', '(', '*', '+', '?', '|', '\\', '^', '$', '{']);
        let matcher = if regex {
            Matcher::Regex(compile(&pattern).map_err(|why| err(code::BAD_PATTERN, why))?)
        } else {
            Matcher::Literal(pattern)
        };
        let (start, meta) = self.resolve(&wp)?;
        // One pass of the search at a context; a pass cut by the size of
        // its display is run again with less context (H2f), below.
        let mut pass = |context: usize| -> Result<(String, bool), Out> {
            let denied_globs = self.denied().to_vec();
            let mut walk = Walk::new(
                self.ops.as_mut(),
                start.clone(),
                wp.as_str().to_owned(),
                meta.clone(),
                WALK_MAX_DEPTH,
                WALK_MAX_ENTRIES,
            )
            .until(deadline);
            let mut shown: Vec<Block> = Vec::new();
            let mut more: Vec<(String, usize)> = Vec::new();
            let mut budget = Budget::default();
            let (mut total, mut skipped, mut gits, mut denied) = (0usize, 0usize, 0usize, 0usize);
            let mut matched_files = 0usize;
            let mut counted_all = true;
            while let Some(entry) = walk.next_entry_if(&mut |e| {
                enter(
                    e,
                    &wp,
                    exclude.as_ref(),
                    &mut gits,
                    &denied_globs,
                    &mut denied,
                )
            }) {
                if Instant::now() >= deadline {
                    return Err(timeout());
                }
                if !entry.meta.kind.is_file() {
                    continue;
                }
                if denied_globs.iter().any(|g| g.matches(&entry.rel)) {
                    denied += 1;
                    continue;
                }
                let rel_below = below(&wp, &entry.rel);
                if include.as_ref().is_some_and(|g| !g.matches(rel_below))
                    || (entry.depth > 0 && exclude.as_ref().is_some_and(|g| g.matches(rel_below)))
                {
                    continue;
                }
                matched_files += 1;
                if entry.meta.len > SEARCH_FILE_MAX_BYTES {
                    skipped += 1;
                    continue;
                }
                // Bounded even if the file grew after the size check above
                // (H1e-2a review F-2).
                let Some(raw) = read_bounded(walk.ops(), &entry.path, SEARCH_FILE_MAX_BYTES) else {
                    skipped += 1;
                    continue;
                };
                let Ok(text) = String::from_utf8(raw) else {
                    skipped += 1;
                    continue;
                };
                let all: Vec<&str> = text.lines().collect();
                let hits: Vec<usize> = all
                    .iter()
                    .enumerate()
                    .filter(|(_, l)| matcher.find(l).is_some())
                    .map(|(i, _)| i)
                    .collect();
                if hits.is_empty() {
                    continue;
                }
                // Past the shown budget, a file is only counted, and the count
                // stops at a bound (the walk's own bounds hold as well).
                if budget.full {
                    if more.len() == SEARCH_MAX_MORE_FILES {
                        counted_all = false;
                        break;
                    }
                    total += hits.len();
                    more.push((entry.rel, hits.len()));
                    continue;
                }
                total += hits.len();
                let block = budget.render(&entry.rel, &all, &hits, context, &matcher);
                if block.shown == 0 {
                    more.push((entry.rel, hits.len()));
                } else {
                    shown.push(block);
                }
            }
            if walk.timed_out {
                return Err(timeout());
            }
            let files = shown.len() + more.len();
            let shown_hits: usize = shown.iter().map(|b| b.shown).sum();
            let mut s = format!(
                "{total} hit(s) in {files} file(s) for a {} match",
                if regex { "regex" } else { "literal" }
            );
            if shown_hits < total || !counted_all {
                s.push_str(&format!(
                "; {shown_hits} shown (at most {SEARCH_MAX_HITS} hits, {SEARCH_MAX_HITS_PER_FILE} per file and {SEARCH_MAX_LINES} lines)"
            ));
            }
            s.push('\n');
            for b in &shown {
                if b.shown < b.total {
                    s.push_str(&format!(
                        "{} ({} hits, {} shown)\n",
                        b.rel, b.total, b.shown
                    ));
                } else {
                    s.push_str(&format!("{} ({} hit(s))\n", b.rel, b.total));
                }
                for l in &b.body {
                    s.push_str(l);
                    s.push('\n');
                }
            }
            more_list(&mut s, &more);
            if !counted_all {
                s.push_str(&format!(
                "counting stopped after {SEARCH_MAX_MORE_FILES} more files with hits: narrow the path, add include or exclude, or make the pattern more specific\n"
            ));
            }
            if total == 0 && (include.is_some() || exclude.is_some()) && matched_files == 0 {
                // The filters, not the pattern, are the likely fault (H2f: a
                // judge-reviewed run gave `include: "src/upload/queue.rs"` with
                // `path: "src"` and was told to check the expression).
                s.push_str(
                "no file matched the include/exclude filters, so nothing was searched: they are globs over paths relative to path (leave the path itself out of them; a name such as *.rs matches at any depth); harness.fs.glob shows what a pattern matches\n",
            );
            } else if total == 0 {
                s.push_str(if regex {
                "no line matched: check the expression, or search for one exact identifier or word that appears in the code\n"
            } else if looks_regex {
                "no line matched: the pattern holds regex characters but was matched as plain text, exactly; set regex true to use it as a regex, or search for one exact identifier or word that appears in the code\n"
            } else {
                "no line matched: a literal is matched exactly, case included; search for one exact identifier or word that appears in the code, or set regex true to match alternatives, for example (?i)retry|backoff\n"
            });
            }
            if budget.windowed {
                s.push_str(
                "a hit line longer than 200 bytes is shown as the 200 bytes around its match; read that line to see all of it\n",
            );
            }
            foot(&mut s, &walk, skipped, gits, denied);
            Ok((s, budget.cut_by_size))
        };
        let mut used = context;
        let (mut s, mut cut) = pass(used)?;
        while cut && used > 0 {
            used -= 1;
            (s, cut) = pass(used)?;
        }
        if used < context {
            s.push_str(&format!(
                "context was reduced from {context} to {used} line(s) so that more hits fit; ask for a smaller context, or read a file, to see more around a hit\n"
            ));
        }
        Ok(ok(s))
    }

    pub(crate) fn glob(&mut self, args: &Value, deadline: Instant) -> Out {
        match self.try_glob(args, deadline) {
            Ok(o) | Err(o) => o,
        }
    }

    fn try_glob(&mut self, args: &Value, deadline: Instant) -> Result<Out, Out> {
        let glob = match arg_glob(args, "pattern")? {
            Some(g) => g,
            None => return Err(err(code::BAD_ARGS, "missing pattern")),
        };
        let wp = arg_path(args, "path", Some("."))?;
        let (start, meta) = self.resolve(&wp)?;
        if !meta.kind.is_dir() {
            return Err(err(code::NOT_A_DIR, "not a directory"));
        }
        let depth = glob.max_depth().unwrap_or(WALK_MAX_DEPTH);
        let denied_globs = self.denied().to_vec();
        let mut walk = Walk::new(
            self.ops.as_mut(),
            start,
            wp.as_str().to_owned(),
            meta,
            depth,
            WALK_MAX_ENTRIES,
        )
        .until(deadline);
        let mut gits = 0usize;
        let mut denied = 0usize;
        let mut found: Vec<(String, u64)> = Vec::new();
        let mut more = false;
        while let Some(e) =
            walk.next_entry_if(&mut |e| enter(e, &wp, None, &mut gits, &denied_globs, &mut denied))
        {
            if Instant::now() >= deadline {
                return Err(timeout());
            }
            if e.depth == 0 || !e.meta.kind.is_file() {
                continue;
            }
            if denied_globs.iter().any(|g| g.matches(&e.rel)) {
                denied += 1;
                continue;
            }
            if !glob.matches(below(&wp, &e.rel)) {
                continue;
            }
            if found.len() == GLOB_MAX_RESULTS {
                more = true;
                break;
            }
            found.push((e.rel, e.meta.len));
        }
        if walk.timed_out {
            return Err(timeout());
        }
        let mut s = format!(
            "{} file(s) match under {}{}\n",
            found.len(),
            shown_path(&wp),
            if more {
                "; more not shown (the cap is 90): narrow the pattern or the path"
            } else {
                ""
            }
        );
        for (rel, len) in &found {
            s.push_str(&format!("{rel} ({len} bytes)\n"));
        }
        foot(&mut s, &walk, 0, gits, denied);
        Ok(ok(s))
    }
}
