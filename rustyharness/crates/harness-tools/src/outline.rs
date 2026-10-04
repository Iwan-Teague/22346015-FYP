//! `harness.fs.outline` (P-24): repo-map-lite symbol extraction, deterministic
//! regexes per language (ROADMAP §"harness.fs.outline": no tree-sitter
//! dependency). One file or a whole directory; a directory walks the
//! workspace with the read tools' confinement ([`crate::builtin`]): the start
//! path is resolved component by component with no symlink at any component,
//! the walk never follows or descends into a symlink, `.git` below the start
//! is skipped, policy-denied paths are neither entered nor matched (P-12),
//! and the walk is bounded in entries, depth and time.
//!
//! **Extraction.** A file's language is its extension: Rust, Python, JS/TS,
//! Go, the C family and Markdown headings. Symbols are found line by line
//! with fixed regular expressions — declarations only, never bodies — so the
//! same bytes always give the same outline. A comment line is never a symbol.
//! JS/TS shows exported declarations only (a module's private helpers are
//! noise in a map of the repo). A signature is the declaration's own line,
//! trimmed and cut at [`OUTLINE_LINE_MAX_BYTES`]; enough to know what is
//! where, not what it does (read the file for that).
//!
//! **Bounds.** At most [`OUTLINE_MAX_ENTRIES`] symbols are shown, sorted by
//! path (component order, the walk's own order) then line; the head digests
//! the shown entries with SHA-256, so two calls over the same bytes give the
//! same digest. Files over [`SEARCH_FILE_MAX_BYTES`] and non-UTF-8 files are
//! skipped and counted, like the search's. A `kind` argument filters the
//! symbol kinds (case-insensitive; an unknown kind matches nothing).

use std::cmp::Ordering;
use std::time::Instant;

use regex::Regex;
use serde_json::Value;

use crate::builtin::{
    arg_path, code, err, ok, read_bounded, shown_path, timeout, Entry, Out, ReadTools, Walk,
    SEARCH_FILE_MAX_BYTES, WALK_MAX_DEPTH, WALK_MAX_ENTRIES,
};

/// Most symbols one call shows (the manifest summary's "bounded"); every
/// symbol past the cap is omitted and said so.
pub const OUTLINE_MAX_ENTRIES: usize = 200;
/// Most bytes of one symbol's signature line.
pub const OUTLINE_LINE_MAX_BYTES: usize = 160;

/// The languages the outline knows, by file extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lang {
    Rust,
    Python,
    Js,
    Ts,
    Go,
    CFamily,
    Markdown,
}

/// The language of a path's extension, if any.
fn lang_of(rel: &str) -> Option<Lang> {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let ext = name.rsplit_once('.')?.1.to_ascii_lowercase();
    match ext.as_str() {
        "rs" => Some(Lang::Rust),
        "py" | "pyi" => Some(Lang::Python),
        "js" | "mjs" | "cjs" | "jsx" => Some(Lang::Js),
        "ts" | "mts" | "cts" | "tsx" => Some(Lang::Ts),
        "go" => Some(Lang::Go),
        "c" | "h" | "cc" | "cpp" | "cxx" | "hpp" | "hh" => Some(Lang::CFamily),
        "md" | "markdown" => Some(Lang::Markdown),
        _ => None,
    }
}

/// One extracted symbol: its 1-based line, its kind and its signature (the
/// trimmed declaration line).
struct Symbol {
    line: usize,
    kind: &'static str,
    sig: String,
}

/// The per-language line matchers, compiled once per call.
struct Extractor {
    rust_fn: Regex,
    rust_item: Regex,
    py_def: Regex,
    py_class: Regex,
    js_fn: Regex,
    js_class: Regex,
    js_const: Regex,
    js_interface: Regex,
    js_type: Regex,
    js_enum: Regex,
    go_func: Regex,
    go_type: Regex,
    c_decl: Regex,
    c_tag: Regex,
    md_heading: Regex,
}

impl Extractor {
    fn new() -> Option<Self> {
        Some(Self {
            // `fn` with its prefixes; the signature is the whole line, so
            // qualifiers stay visible.
            rust_fn: Regex::new(
                r#"^\s*(pub(\([^)]*\))?\s+)?(const\s+)?(async\s+)?(unsafe\s+)?(extern(\s+"[^"]*")?\s+)?fn\s+\w"#,
            )
            .ok()?,
            rust_item: Regex::new(r"^\s*(pub(\([^)]*\))?\s+)?(struct|enum|trait|impl)\b").ok()?,
            py_def: Regex::new(r"^\s*(async\s+)?def\s+\w").ok()?,
            py_class: Regex::new(r"^\s*class\s+\w").ok()?,
            js_fn: Regex::new(
                r"^export\s+(default\s+)?(declare\s+)?(abstract\s+)?(async\s+)?function\s*\*?\s*\w?",
            )
            .ok()?,
            js_class: Regex::new(r"^export\s+(default\s+)?(declare\s+)?(abstract\s+)?class\s+\w")
                .ok()?,
            js_const: Regex::new(r"^export\s+(declare\s+)?(const|let|var)\s").ok()?,
            js_interface: Regex::new(r"^export\s+(declare\s+)?interface\s+\w").ok()?,
            js_type: Regex::new(r"^export\s+(declare\s+)?type\s+\w").ok()?,
            js_enum: Regex::new(r"^export\s+(declare\s+)?(const\s+)?enum\s+\w").ok()?,
            go_func: Regex::new(r"^func\s*(\([^)]*\))?\s*\w").ok()?,
            go_type: Regex::new(r"^type\s+\w").ok()?,
            // A C-family function definition: column 0, an argument list,
            // no semicolon, and not a control keyword or a typedef.
            c_decl: Regex::new(
                r"^\S[^(]*\([^;]*$",
            )
            .ok()?,
            c_tag: Regex::new(r"^(typedef\s+)?(struct|enum|union)\s+\w").ok()?,
            md_heading: Regex::new(r"^#{1,6}(\s|$)").ok()?,
        })
    }

    /// Whether the line is a comment (or, for the C family, a preprocessor
    /// line): never a symbol.
    fn is_comment(lang: Lang, trimmed: &str) -> bool {
        match lang {
            Lang::Rust | Lang::Js | Lang::Ts | Lang::Go => {
                trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*')
            }
            Lang::CFamily => {
                trimmed.starts_with("//")
                    || trimmed.starts_with("/*")
                    || trimmed.starts_with('*')
                    || trimmed.starts_with('#')
            }
            Lang::Python => trimmed.starts_with('#'),
            Lang::Markdown => false,
        }
    }

    /// The symbols of one text file, in line order.
    fn extract(&self, lang: Lang, text: &str) -> Vec<Symbol> {
        fn sym(line: usize, trimmed: &str, kind: &'static str) -> Symbol {
            Symbol {
                line,
                kind,
                sig: crate::builtin::cut(trimmed, OUTLINE_LINE_MAX_BYTES),
            }
        }
        let mut out = Vec::new();
        for (i, raw) in text.lines().enumerate() {
            let trimmed = raw.trim();
            if trimmed.is_empty() || Self::is_comment(lang, trimmed) {
                continue;
            }
            let line = i + 1;
            let hit: Option<&'static str> = match lang {
                Lang::Rust => {
                    if self.rust_fn.is_match(raw) {
                        Some("fn")
                    } else if self.rust_item.is_match(raw) {
                        // impl blocks: the whole trimmed line names the type.
                        trimmed
                            .split_whitespace()
                            .find(|w| matches!(*w, "struct" | "enum" | "trait" | "impl"))
                            .and_then(|w| tag_kind(w))
                    } else {
                        None
                    }
                }
                Lang::Python => {
                    if self.py_def.is_match(raw) {
                        Some("def")
                    } else if self.py_class.is_match(raw) {
                        Some("class")
                    } else {
                        None
                    }
                }
                Lang::Js | Lang::Ts => {
                    if self.js_fn.is_match(raw) {
                        Some("function")
                    } else if self.js_class.is_match(raw) {
                        Some("class")
                    } else if self.js_interface.is_match(raw) {
                        Some("interface")
                    } else if self.js_type.is_match(raw) {
                        Some("type")
                    } else if self.js_enum.is_match(raw) {
                        Some("enum")
                    } else if self.js_const.is_match(raw) {
                        Some("const")
                    } else {
                        None
                    }
                }
                Lang::Go => {
                    if self.go_func.is_match(raw) {
                        Some("func")
                    } else if self.go_type.is_match(raw) {
                        Some("type")
                    } else {
                        None
                    }
                }
                Lang::CFamily => {
                    if self.c_tag.is_match(raw) {
                        trimmed
                            .split_whitespace()
                            .find(|w| matches!(*w, "struct" | "enum" | "union"))
                            .and_then(|w| tag_kind(w))
                    } else if self.c_decl.is_match(raw)
                        && !trimmed.starts_with("typedef")
                        && !starts_keyword(trimmed)
                    {
                        Some("function")
                    } else {
                        None
                    }
                }
                Lang::Markdown => self.md_heading.is_match(raw).then_some("heading"),
            };
            if let Some(k) = hit {
                out.push(sym(line, trimmed, k));
            }
        }
        out
    }
}

/// The static kind name of a declaration keyword (`struct`, `enum`,
/// `trait`, `impl`, `union`); `None` for any other word.
fn tag_kind(w: &str) -> Option<&'static str> {
    match w {
        "struct" => Some("struct"),
        "enum" => Some("enum"),
        "trait" => Some("trait"),
        "impl" => Some("impl"),
        "union" => Some("union"),
        _ => None,
    }
}

/// A C-family control keyword a function-like line must not start with.
fn starts_keyword(trimmed: &str) -> bool {
    ["return", "if", "for", "while", "switch", "else", "do"]
        .iter()
        .any(|k| {
            trimmed
                .strip_prefix(k)
                .is_some_and(|rest| rest.starts_with(|c: char| c.is_whitespace() || c == '('))
        })
}

/// Whether a symbol's `kind` matches a `kind` argument (case-insensitive;
/// `fn`, `func` and `function` are one kind spelled per language).
fn kind_matches(filter: &str, kind: &str) -> bool {
    let f = filter.to_ascii_lowercase();
    if f == kind {
        return true;
    }
    let function = |k: &str| matches!(k, "fn" | "func" | "function");
    (function(&f) && function(kind)) || (f == "const" && matches!(kind, "const" | "let" | "var"))
}

/// The optional `kind` argument: a string of at most 16 characters (the
/// schema's cap), or absent.
fn arg_kind(args: &Value) -> Result<Option<String>, Out> {
    match args.get("kind") {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.to_ascii_lowercase())),
        Some(_) => Err(err(code::BAD_ARGS, "kind is not a string")),
    }
}

/// Whether a walked directory is entered: not a `.git` below the start
/// (counted), not a policy-denied path (counted when skipped, P-12).
fn enter(
    e: &Entry,
    denied_globs: &[crate::glob::Glob],
    gits: &mut usize,
    denied: &mut usize,
) -> bool {
    if e.depth == 0 {
        return true;
    }
    if e.rel.rsplit('/').next() == Some(".git") {
        *gits += 1;
        return false;
    }
    if denied_globs.iter().any(|g| g.matches(&e.rel)) {
        *denied += 1;
        return false;
    }
    true
}

/// Compare two relative paths the way the walk orders them: component by
/// component (so `a/b` sorts before `a-c`, although `-` < `/`).
fn walk_order(a: &str, b: &str) -> Ordering {
    a.split('/').cmp(b.split('/'))
}

/// One outlined file's shown entries.
struct FileOutline {
    rel: String,
    rows: Vec<(usize, String)>,
}

impl ReadTools {
    pub(crate) fn outline(&mut self, args: &Value, deadline: Instant) -> Out {
        match self.try_outline(args, deadline) {
            Ok(o) | Err(o) => o,
        }
    }

    fn try_outline(&mut self, args: &Value, deadline: Instant) -> Result<Out, Out> {
        let Some(ex) = Extractor::new() else {
            return Err(err(code::IO, "the outline matchers did not compile"));
        };
        let filter = arg_kind(args)?;
        let wp = arg_path(args, "path", Some("."))?;
        let (start, meta) = self.resolve(&wp)?;
        // Collect every file's symbols, then sort, filter and cap once, so
        // the cap lands on the global order (a file-first cap would hide a
        // sorted-later file's symbols).
        let mut files: Vec<(String, Vec<Symbol>)> = Vec::new();
        let (mut skipped, mut denied, mut gits) = (0usize, 0usize, 0usize);
        // The walk's own counters, for the foot (a single file has none).
        let (mut symlinks, mut stopped) = (0usize, false);
        if meta.kind.is_file() {
            let Some(lang) = lang_of(wp.as_str()) else {
                return Err(err(
                    code::NO_OUTLINE,
                    "no outline for files of this kind: the outline knows Rust, Python, JavaScript, TypeScript, Go, C-family and Markdown files by extension",
                ));
            };
            let Some(raw) = read_bounded(self.ops.as_mut(), &start, SEARCH_FILE_MAX_BYTES) else {
                return Err(err(code::TOO_LARGE, "the file is larger than the read cap"));
            };
            let Ok(text) = String::from_utf8(raw) else {
                return Err(err(code::NOT_TEXT, "not UTF-8 text"));
            };
            let syms = ex.extract(lang, &text);
            if !syms.is_empty() {
                files.push((wp.as_str().to_owned(), syms));
            }
        } else if !meta.kind.is_dir() {
            return Err(err(code::NOT_A_DIR, "not a directory"));
        } else {
            let denied_globs = self.denied().to_vec();
            let mut walk = Walk::new(
                self.ops.as_mut(),
                start,
                wp.as_str().to_owned(),
                meta,
                WALK_MAX_DEPTH,
                WALK_MAX_ENTRIES,
            )
            .until(deadline);
            while let Some(e) =
                walk.next_entry_if(&mut |e| enter(e, &denied_globs, &mut gits, &mut denied))
            {
                if Instant::now() >= deadline {
                    return Err(timeout());
                }
                if e.depth == 0 || !e.meta.kind.is_file() || e.symlink {
                    continue;
                }
                if denied_globs.iter().any(|g| g.matches(&e.rel)) {
                    denied += 1;
                    continue;
                }
                let Some(lang) = lang_of(&e.rel) else {
                    continue;
                };
                if let Some(syms) = outline_file(walk.ops(), &ex, lang, &e.path) {
                    if !syms.is_empty() {
                        files.push((e.rel, syms));
                    }
                } else {
                    skipped += 1;
                }
            }
            if walk.timed_out {
                return Err(timeout());
            }
            symlinks = walk.symlinks;
            stopped = walk.stopped;
        }
        // Component-wise path order (the walk's own), then line; then the
        // kind filter, then the cap.
        files.sort_by(|a, b| walk_order(&a.0, &b.0));
        let mut shown: Vec<FileOutline> = Vec::new();
        let mut total = 0usize;
        let mut more = false;
        for (rel, syms) in &files {
            let mut rows = Vec::new();
            for s in syms {
                if let Some(f) = &filter {
                    if !kind_matches(f, s.kind) {
                        continue;
                    }
                }
                if total == OUTLINE_MAX_ENTRIES {
                    more = true;
                    break;
                }
                total += 1;
                rows.push((s.line, s.sig.clone()));
            }
            if !rows.is_empty() {
                shown.push(FileOutline {
                    rel: rel.clone(),
                    rows,
                });
            }
            if more {
                break;
            }
        }
        // The head digests the shown entries, so two calls over the same
        // bytes agree byte for byte.
        let mut body = String::new();
        for f in &shown {
            body.push_str(&f.rel);
            body.push('\n');
            for (line, sig) in &f.rows {
                body.push_str(&format!("  {line}: {sig}\n"));
            }
        }
        let digest = harness_core::sha256(body.as_bytes());
        let file_count = shown.len();
        let mut s = format!(
            "{total} symbol(s) in {file_count} file(s) under {}; sha256 {digest}",
            shown_path(&wp)
        );
        if more {
            s.push_str(&format!(
                "; more not shown (the cap is {OUTLINE_MAX_ENTRIES})"
            ));
        }
        s.push('\n');
        s.push_str(&body);
        if denied > 0 {
            s.push_str(&format!("{denied} path(s) skipped (denied by policy)\n"));
        }
        if skipped > 0 {
            s.push_str(&format!(
                "{skipped} file(s) not outlined (larger than 1 MiB, unreadable or not UTF-8)\n"
            ));
        }
        if symlinks > 0 {
            s.push_str(&format!("{symlinks} symlink(s) not followed\n"));
        }
        if gits > 0 {
            s.push_str(&format!("{gits} .git director(y/ies) skipped\n"));
        }
        if stopped {
            s.push_str("the walk stopped at its entry limit\n");
        }
        Ok(ok(s))
    }
}

/// One file's symbols; `None` when the file is over
/// [`SEARCH_FILE_MAX_BYTES`] or not UTF-8 (counted by the caller).
fn outline_file(
    ops: &mut dyn crate::file_ops::FileOps,
    ex: &Extractor,
    lang: Lang,
    path: &std::path::Path,
) -> Option<Vec<Symbol>> {
    let raw = read_bounded(ops, path, SEARCH_FILE_MAX_BYTES)?;
    let text = String::from_utf8(raw).ok()?;
    Some(ex.extract(lang, &text))
}

/// One file's outline as a repo map shows it (P-33): the path, then one
/// `  {line}: {sig}` line per symbol, at most [`OUTLINE_MAX_ENTRIES`] of
/// them. `None` when the file kind has no outline language or the text
/// shows no symbols. Pure — text in, text out, no I/O — so the harness's
/// repo map is a pure function of the file bytes, and a live run and a
/// replay that reads the same bytes render the same lines.
pub fn file_outline_text(rel: &str, text: &str) -> Option<String> {
    let lang = lang_of(rel)?;
    let ex = Extractor::new()?;
    let syms = ex.extract(lang, text);
    if syms.is_empty() {
        return None;
    }
    let mut rows = String::new();
    for sym in syms.iter().take(OUTLINE_MAX_ENTRIES) {
        rows.push_str(&format!("  {}: {}\n", sym.line, sym.sig));
    }
    let mut s = String::with_capacity(rel.len() + 1 + rows.len());
    s.push_str(rel);
    s.push('\n');
    s.push_str(&rows);
    Some(s)
}
