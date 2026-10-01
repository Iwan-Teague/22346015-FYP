//! The built-in read tools, in process (design §4.8, §9 H1): `harness.fs.read`,
//! `harness.fs.search`, `harness.fs.list`.
//!
//! [`ReadTools`] is a [`ToolProvider`], so it runs only a
//! `Journaled<Authorized<Call>>`: policy allowed the call (its `path` passed
//! the lexical workspace rule, INV-30 lexical half) and the intent is
//! durable (INV-33) before any byte is read.
//!
//! **Confinement (INV-30, in-process half).** Every path is resolved from
//! the workspace root one component at a time with `symlink_metadata`; a
//! symlink at ANY component (the final one included) is refused, never
//! followed, so a link inside the workspace cannot make the harness read
//! outside it. Walks (search, list) never descend into or read through a
//! symlink either; list shows one as a symlink, without its target. The
//! workspace root itself must be a real directory. The lexical rule is
//! re-checked here (defence in depth; the policy already refused).
//!
//! **Named residuals** (the design's H1 position, §4.8): the check and the
//! open are separate calls, so a process that could create a symlink between
//! them could still redirect a read; in an H1 session nothing the agent can
//! do creates one (no write or exec tools), and H2's confined file-op helper
//! makes the kernel enforce the view. A hard link inside the workspace to a
//! file outside it is indistinguishable from a file (materialisation, H2,
//! controls what the workspace contains).
//!
//! **Bounds.** A read returns at most 100 lines of a text file of at most
//! [`READ_MAX_BYTES`]; search reports at most [`SEARCH_MAX_HITS`] hits,
//! grouped per file, skipping files over [`SEARCH_FILE_MAX_BYTES`] and
//! non-UTF-8 files, and stops after [`WALK_MAX_ENTRIES`] entries; list shows
//! at most [`LIST_MAX_ENTRIES`] entries to depth ≤ 4. Every result is cut at
//! [`RESULT_MAX_BYTES`] (`truncated`), and its digest is over the full
//! output. The per-call deadline is checked before and during every walk.
//!
//! **Search is a literal substring match**, not a regular expression: H1
//! adds no regex crate (a recorded §4.8 deviation).
//!
//! Errors are `ToolStatus::Error { code }` with a harness-authored message
//! as the output (see [`code`]); none is a provider failure.

use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;

use harness_core::{sha256, Digest, Sha256Stream, Source, Untrusted};
use harness_journal::Journaled;
use harness_manifest::ProviderName;
use harness_policy::{workspace_path, Authorized, Call, WorkspacePath};
use serde_json::Value;

use crate::provider::{
    InvokeCtx, ReadRecord, RefusalKind, ToolError, ToolProvider, ToolResult, ToolStatus,
};

/// Largest file `fs.read` reads.
pub const READ_MAX_BYTES: u64 = 4 * 1024 * 1024;
/// Default and maximum `fs.read` window, in lines (§4.8).
pub const READ_MAX_LINES: u64 = 100;
/// Most search hits reported (§4.8).
pub const SEARCH_MAX_HITS: usize = 50;
/// Files larger than this are not searched.
pub const SEARCH_FILE_MAX_BYTES: u64 = 1024 * 1024;
/// A hit's line is shown up to this many bytes.
pub const SEARCH_LINE_MAX_BYTES: usize = 200;
/// Most directory entries a walk visits.
pub const WALK_MAX_ENTRIES: usize = 20_000;
/// Deepest a search descends.
pub const WALK_MAX_DEPTH: usize = 32;
/// Most entries the workspace-facts walk visits.
pub const FACTS_MAX_ENTRIES: usize = 200_000;
/// Most entries `fs.list` shows.
pub const LIST_MAX_ENTRIES: usize = 500;
/// Deepest `fs.list` descends (§4.8, the schema's maximum).
pub const LIST_MAX_DEPTH: u64 = 4;
/// Every result is cut here.
pub const RESULT_MAX_BYTES: usize = 64 * 1024;

/// Tool-level error codes (`ToolStatus::Error { code }`).
pub mod code {
    /// The path argument fails the lexical workspace rule.
    pub const PATH_REFUSED: u16 = 1;
    /// Nothing at that path.
    pub const NOT_FOUND: u16 = 2;
    /// A component of the path is a symlink (never followed).
    pub const SYMLINK: u16 = 3;
    /// Not a regular file.
    pub const NOT_A_FILE: u16 = 4;
    /// Not a directory.
    pub const NOT_A_DIR: u16 = 5;
    /// Not UTF-8 text.
    pub const NOT_TEXT: u16 = 6;
    /// Larger than the read cap.
    pub const TOO_LARGE: u16 = 7;
    /// Any other I/O error.
    pub const IO: u16 = 8;
    /// Arguments the schema should have refused (defence in depth).
    pub const BAD_ARGS: u16 = 9;
    /// The line window starts past the end of the file.
    pub const WINDOW: u16 = 10;
}

const READ: &str = "harness.fs.read";
const SEARCH: &str = "harness.fs.search";
const LIST: &str = "harness.fs.list";

/// The in-process read tools over one workspace.
#[derive(Debug)]
pub struct ReadTools {
    ns: ProviderName,
    root: PathBuf,
}

/// Why the workspace root was refused.
#[derive(Debug, thiserror::Error)]
pub enum RootRefused {
    /// The root is a symlink.
    #[error("the workspace root is a symlink")]
    Symlink,
    /// The root is not a directory.
    #[error("the workspace root is not a directory")]
    NotADir,
    /// It could not be examined.
    #[error("the workspace root cannot be examined: {0}")]
    Io(#[from] io::Error),
}

impl ReadTools {
    /// Read tools over the workspace at `root`, which must be a real
    /// directory (not a symlink). It is canonicalised once here: ancestors
    /// of the workspace may be symlinks (`/tmp` on macOS), its contents may
    /// not.
    pub fn new(root: &Path) -> Result<Self, RootRefused> {
        let m = fs::symlink_metadata(root)?;
        if m.file_type().is_symlink() {
            return Err(RootRefused::Symlink);
        }
        if !m.is_dir() {
            return Err(RootRefused::NotADir);
        }
        let root = fs::canonicalize(root)?;
        let ns = ProviderName::new(harness_manifest::BUILTIN_NAMESPACE)
            .map_err(|_| RootRefused::Io(io::Error::other("builtin namespace")))?;
        Ok(Self { ns, root })
    }

    /// The canonical workspace root.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// A finished tool call, before capping.
struct Out {
    status: ToolStatus,
    text: String,
    read: Option<ReadRecord>,
}

fn err(code: u16, msg: &str) -> Out {
    Out {
        status: ToolStatus::Error { code },
        text: format!("error: {msg}"),
        read: None,
    }
}

fn ok(text: String) -> Out {
    Out {
        status: ToolStatus::Ok,
        text,
        read: None,
    }
}

fn timeout() -> Out {
    Out {
        status: ToolStatus::Timeout,
        text: "error: the per-call deadline passed".into(),
        read: None,
    }
}

impl ToolProvider for ReadTools {
    fn namespace(&self) -> &ProviderName {
        &self.ns
    }

    fn invoke(
        &mut self,
        call: Journaled<Authorized<Call>>,
        ctx: &InvokeCtx,
    ) -> Result<ToolResult, ToolError> {
        let c = call.call().call();
        let cap = c.capability.as_str();
        if !matches!(cap, READ | SEARCH | LIST) {
            return Ok(refused(cap, RefusalKind::UnknownCapability));
        }
        if Instant::now() >= ctx.deadline {
            return Ok(refused(cap, RefusalKind::DeadlinePassed));
        }
        let out = match cap {
            READ => self.read(&c.args),
            SEARCH => self.search(&c.args, ctx.deadline),
            _ => self.list(&c.args, ctx.deadline),
        };
        Ok(finish(cap, out))
    }
}

fn refused(cap: &str, reason: RefusalKind) -> ToolResult {
    let text = b"error: refused before running".to_vec();
    ToolResult {
        status: ToolStatus::Refused { reason },
        digest: sha256(&text),
        output: Untrusted::new(text, Source::Tool(cap.to_owned())),
        truncated: false,
        read: None,
    }
}

/// Cap the output at [`RESULT_MAX_BYTES`] (on a character boundary); the
/// digest is over the full output.
fn finish(cap: &str, out: Out) -> ToolResult {
    let digest = sha256(out.text.as_bytes());
    let mut text = out.text;
    let truncated = text.len() > RESULT_MAX_BYTES;
    if truncated {
        let mut end = RESULT_MAX_BYTES;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    ToolResult {
        status: out.status,
        output: Untrusted::new(text.into_bytes(), Source::Tool(cap.to_owned())),
        truncated,
        digest,
        read: out.read,
    }
}

fn arg_path(args: &Value, key: &str, default: Option<&str>) -> Result<WorkspacePath, Out> {
    let s = match args.get(key) {
        Some(Value::String(s)) => s.as_str(),
        Some(_) => return Err(err(code::BAD_ARGS, "the path is not a string")),
        None => match default {
            Some(d) => d,
            None => return Err(err(code::BAD_ARGS, "missing path")),
        },
    };
    workspace_path(s).map_err(|e| err(code::PATH_REFUSED, &e.to_string()))
}

fn arg_u64(args: &Value, key: &str, default: u64, min: u64, max: u64) -> Result<u64, Out> {
    match args.get(key) {
        None => Ok(default),
        Some(v) => match v.as_u64() {
            Some(n) if (min..=max).contains(&n) => Ok(n),
            _ => Err(err(code::BAD_ARGS, "an integer argument is out of range")),
        },
    }
}

impl ReadTools {
    /// Resolve a workspace path component by component, refusing a symlink
    /// at any component. Returns the path and its (not followed) metadata.
    fn resolve(&self, p: &WorkspacePath) -> Result<(PathBuf, Metadata), Out> {
        let mut cur = self.root.clone();
        let mut meta = fs::symlink_metadata(&cur).map_err(io_out)?;
        for c in p.components() {
            cur.push(c);
            meta = fs::symlink_metadata(&cur).map_err(io_out)?;
            if meta.file_type().is_symlink() {
                return Err(err(
                    code::SYMLINK,
                    "a path component is a symlink; symlinks are never followed",
                ));
            }
        }
        Ok((cur, meta))
    }

    fn read(&self, args: &Value) -> Out {
        match self.try_read(args) {
            Ok(o) | Err(o) => o,
        }
    }

    fn try_read(&self, args: &Value) -> Result<Out, Out> {
        let wp = arg_path(args, "path", None)?;
        let start = arg_u64(args, "start", 1, 1, u64::MAX)?;
        let want = arg_u64(args, "lines", READ_MAX_LINES, 1, READ_MAX_LINES)?;
        let (path, meta) = self.resolve(&wp)?;
        if !meta.is_file() {
            return Err(err(code::NOT_A_FILE, "not a regular file"));
        }
        if meta.len() > READ_MAX_BYTES {
            return Err(err(code::TOO_LARGE, "the file is larger than the read cap"));
        }
        let mut bytes = Vec::new();
        File::open(&path)
            .and_then(|f| f.take(READ_MAX_BYTES + 1).read_to_end(&mut bytes))
            .map_err(io_out)?;
        if u64::try_from(bytes.len()).map_or(true, |n| n > READ_MAX_BYTES) {
            return Err(err(code::TOO_LARGE, "the file is larger than the read cap"));
        }
        let digest = sha256(&bytes);
        let text = String::from_utf8(bytes).map_err(|_| err(code::NOT_TEXT, "not UTF-8 text"))?;
        let total = text.lines().count() as u64;
        let record = ReadRecord {
            path: wp.clone(),
            sha256: digest,
        };
        if total == 0 {
            let mut o = ok(format!(
                "{}: empty file; sha256 {digest}\n",
                shown_path(&wp)
            ));
            o.read = Some(record);
            return Ok(o);
        }
        if start > total {
            return Err(err(
                code::WINDOW,
                &format!("the file has {total} lines; start is past the end"),
            ));
        }
        let end = start.saturating_add(want - 1).min(total);
        let mut s = format!(
            "{}: lines {start}-{end} of {total}; sha256 {digest}\n",
            shown_path(&wp)
        );
        let skip = usize::try_from(start - 1).unwrap_or(usize::MAX);
        let take = usize::try_from(end - start + 1).unwrap_or(0);
        for (i, line) in text.lines().skip(skip).take(take).enumerate() {
            s.push_str(&format!("{}\t{line}\n", start + i as u64));
        }
        let mut o = ok(s);
        o.read = Some(record);
        Ok(o)
    }

    fn search(&self, args: &Value, deadline: Instant) -> Out {
        match self.try_search(args, deadline) {
            Ok(o) | Err(o) => o,
        }
    }

    fn try_search(&self, args: &Value, deadline: Instant) -> Result<Out, Out> {
        let pattern = match args.get("pattern") {
            Some(Value::String(p)) if !p.is_empty() => p.clone(),
            _ => {
                return Err(err(
                    code::BAD_ARGS,
                    "the pattern must be a non-empty string",
                ))
            }
        };
        let wp = arg_path(args, "path", Some("."))?;
        let (start, meta) = self.resolve(&wp)?;
        let mut files: Vec<(String, Vec<(usize, String)>)> = Vec::new();
        let mut hits = 0usize;
        let mut more = false;
        let mut skipped = 0usize;
        let mut walk = Walk::new(
            start,
            wp.as_str().to_owned(),
            meta,
            WALK_MAX_DEPTH,
            WALK_MAX_ENTRIES,
        )
        .until(deadline);
        while let Some(entry) = walk.next_entry() {
            if Instant::now() >= deadline {
                return Err(timeout());
            }
            let Entry {
                path, rel, meta, ..
            } = entry;
            if !meta.is_file() {
                continue;
            }
            if meta.len() > SEARCH_FILE_MAX_BYTES {
                skipped += 1;
                continue;
            }
            // Bounded even if the file grew after the size check above
            // (H1e-2a review F-2).
            let Some(bytes) = read_bounded(&path, SEARCH_FILE_MAX_BYTES) else {
                skipped += 1;
                continue;
            };
            let Ok(text) = String::from_utf8(bytes) else {
                skipped += 1;
                continue;
            };
            let mut in_file = Vec::new();
            for (n, line) in text.lines().enumerate() {
                if line.contains(&pattern) {
                    if hits == SEARCH_MAX_HITS {
                        more = true;
                        break;
                    }
                    hits += 1;
                    in_file.push((n + 1, cut(line, SEARCH_LINE_MAX_BYTES)));
                }
            }
            if !in_file.is_empty() {
                files.push((rel, in_file));
            }
            if more {
                break;
            }
        }
        if walk.timed_out {
            return Err(timeout());
        }
        let mut s = format!(
            "{hits} hit(s) in {} file(s) for a literal match{}\n",
            files.len(),
            if more {
                "; more hits not shown (the cap is 50)"
            } else {
                ""
            }
        );
        for (rel, lines) in &files {
            s.push_str(&format!("{rel} ({} hit(s))\n", lines.len()));
            for (n, line) in lines {
                s.push_str(&format!("  {n}: {line}\n"));
            }
        }
        if skipped > 0 {
            s.push_str(&format!(
                "{skipped} file(s) not searched (larger than 1 MiB, unreadable or not UTF-8)\n"
            ));
        }
        if walk.symlinks > 0 {
            s.push_str(&format!("{} symlink(s) not followed\n", walk.symlinks));
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
        Ok(ok(s))
    }

    fn list(&self, args: &Value, deadline: Instant) -> Out {
        match self.try_list(args, deadline) {
            Ok(o) | Err(o) => o,
        }
    }

    fn try_list(&self, args: &Value, deadline: Instant) -> Result<Out, Out> {
        let wp = arg_path(args, "path", None)?;
        let depth = arg_u64(args, "depth", 1, 1, LIST_MAX_DEPTH)?;
        let (start, meta) = self.resolve(&wp)?;
        if !meta.is_dir() {
            return Err(err(code::NOT_A_DIR, "not a directory"));
        }
        let depth = usize::try_from(depth).unwrap_or(1);
        let mut walk =
            Walk::new(start, wp.as_str().to_owned(), meta, depth, WALK_MAX_ENTRIES).until(deadline);
        let mut s = String::new();
        let mut shown = 0usize;
        let mut more = false;
        while let Some(e) = walk.next_entry() {
            if Instant::now() >= deadline {
                return Err(timeout());
            }
            if e.depth == 0 {
                continue; // the directory itself
            }
            if shown == LIST_MAX_ENTRIES {
                more = true;
                break;
            }
            shown += 1;
            let line = if e.symlink {
                format!("l {} (symlink, not followed)\n", e.rel)
            } else if e.meta.is_dir() {
                format!("d {}/\n", e.rel)
            } else if e.meta.is_file() {
                format!("f {} {} bytes\n", e.rel, e.meta.len())
            } else {
                format!("o {}\n", e.rel)
            };
            s.push_str(&line);
        }
        if walk.timed_out {
            return Err(timeout());
        }
        let mut head = format!("{} entr(y/ies) under {}", shown, shown_path(&wp));
        if more {
            head.push_str("; more not shown (the cap is 500)");
        }
        head.push('\n');
        Ok(ok(head + &s))
    }
}

/// Read at most `max` bytes of `path`; `None` if it is longer (or cannot be
/// read).
fn read_bounded(path: &Path, max: u64) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|f| f.take(max + 1).read_to_end(&mut bytes))
        .ok()?;
    (u64::try_from(bytes.len()).ok()? <= max).then_some(bytes)
}

fn shown_path(wp: &WorkspacePath) -> &str {
    if wp.as_str().is_empty() {
        "."
    } else {
        wp.as_str()
    }
}

fn cut(line: &str, max: usize) -> String {
    if line.len() <= max {
        return line.to_owned();
    }
    let mut end = max;
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", line.get(..end).unwrap_or(""))
}

fn io_out(e: io::Error) -> Out {
    if e.kind() == io::ErrorKind::NotFound {
        err(code::NOT_FOUND, "no such file or directory")
    } else {
        err(code::IO, "the file system refused the operation")
    }
}

/// One walked entry.
struct Entry {
    path: PathBuf,
    rel: String,
    meta: Metadata,
    depth: usize,
    symlink: bool,
}

/// A bounded, deterministic (name-sorted, depth-first) walk that never
/// follows or descends into a symlink. The entry limit and the deadline are
/// checked while a directory is being listed, not only between entries, so
/// a huge directory is never enumerated in full (H1e-2a review F-2). A
/// directory cut short by the limit makes the walk `stopped`.
struct Walk {
    stack: Vec<Entry>,
    max_depth: usize,
    limit: usize,
    deadline: Option<Instant>,
    timed_out: bool,
    unreadable: usize,
    visited: usize,
    symlinks: usize,
    stopped: bool,
}

impl Walk {
    fn new(start: PathBuf, rel: String, meta: Metadata, max_depth: usize, limit: usize) -> Self {
        Self {
            stack: vec![Entry {
                path: start,
                rel,
                meta,
                depth: 0,
                symlink: false,
            }],
            max_depth,
            limit,
            deadline: None,
            timed_out: false,
            unreadable: 0,
            visited: 0,
            symlinks: 0,
            stopped: false,
        }
    }

    /// Stop (with `timed_out`) once `deadline` has passed.
    fn until(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    fn next_entry(&mut self) -> Option<Entry> {
        if self.timed_out {
            return None;
        }
        let e = self.stack.pop()?;
        self.visited += 1;
        if self.visited > self.limit {
            self.stopped = true;
            self.stack.clear();
            return None;
        }
        if e.meta.is_dir() && !e.symlink && e.depth < self.max_depth {
            let Ok(rd) = fs::read_dir(&e.path) else {
                self.unreadable += 1;
                return Some(e);
            };
            let mut kids: Vec<Entry> = Vec::new();
            for d in rd {
                if self.deadline.is_some_and(|t| Instant::now() >= t) {
                    self.timed_out = true;
                    self.stack.clear();
                    return None;
                }
                if self.visited + self.stack.len() + kids.len() >= self.limit {
                    self.stopped = true;
                    break;
                }
                let Ok(d) = d else {
                    self.unreadable += 1;
                    continue;
                };
                // A non-UTF-8 name is shown lossily (it stays in the
                // tree digest); `path` keeps the real name.
                let name = d.file_name().to_string_lossy().into_owned();
                let path = d.path();
                let Ok(meta) = fs::symlink_metadata(&path) else {
                    self.unreadable += 1;
                    continue;
                };
                let symlink = meta.file_type().is_symlink();
                if symlink {
                    self.symlinks += 1;
                }
                let rel = if e.rel.is_empty() {
                    name.to_owned()
                } else {
                    format!("{}/{name}", e.rel)
                };
                kids.push(Entry {
                    path,
                    rel,
                    meta,
                    depth: e.depth + 1,
                    symlink,
                });
            }
            // Reverse name order on the stack = name order when popped.
            kids.sort_by(|a, b| b.rel.cmp(&a.rel));
            self.stack.extend(kids);
        }
        Some(e)
    }
}

/// Files larger than this contribute their size, not their content, to
/// the workspace tree digest (H1e-2a confirming review NF-1).
pub const FACTS_FILE_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Chunk size of the streaming file hash.
const FACTS_CHUNK_BYTES: usize = 64 * 1024;

/// The harness facts of a workspace (§2.3 block 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceFacts {
    /// The tree digest.
    pub tree: Digest,
    /// Regular files.
    pub files: u64,
    /// Files over [`FACTS_FILE_MAX_BYTES`], digested by size only.
    pub oversize: u64,
}

/// Measure the workspace facts: a full walk that follows no symlink, in
/// name order, digesting every entry as `kind ‖ path ‖ NUL ‖ content` where
/// the content is a file's SHA-256 (streamed in 64 KiB chunks, never read
/// whole) or, for a file over [`FACTS_FILE_MAX_BYTES`], its size (kind
/// `F`). So the digest changes when any name, kind or (capped) file
/// content changes. Refused (an `Err`) past [`FACTS_MAX_ENTRIES`] entries,
/// on any unreadable entry, or when `deadline` passes: a fact the harness
/// cannot measure is not stated.
pub fn workspace_facts(root: &Path, deadline: Instant) -> io::Result<WorkspaceFacts> {
    facts_with(root, deadline, FACTS_FILE_MAX_BYTES)
}

fn facts_with(root: &Path, deadline: Instant, file_cap: u64) -> io::Result<WorkspaceFacts> {
    let m = fs::symlink_metadata(root)?;
    if m.file_type().is_symlink() || !m.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the workspace root is not a real directory",
        ));
    }
    let late = || {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "the facts walk passed its deadline",
        )
    };
    let mut walk = Walk::new(
        root.to_path_buf(),
        String::new(),
        m,
        usize::MAX,
        FACTS_MAX_ENTRIES,
    )
    .until(deadline);
    let mut tree = Sha256Stream::new();
    let mut files = 0u64;
    let mut oversize = 0u64;
    while let Some(e) = walk.next_entry() {
        if Instant::now() >= deadline {
            return Err(late());
        }
        if e.depth == 0 {
            continue;
        }
        let (kind, content) = if e.symlink {
            (b'l', String::new())
        } else if e.meta.is_dir() {
            (b'd', String::new())
        } else if e.meta.is_file() {
            files += 1;
            match hash_capped(&e.path, file_cap, deadline)? {
                Some(d) => (b'f', d.to_string()),
                None => {
                    oversize += 1;
                    (b'F', format!("len:{}", e.meta.len()))
                }
            }
        } else {
            (b'o', String::new())
        };
        tree.update(&[kind]);
        tree.update(e.rel.as_bytes());
        tree.update(&[0]);
        tree.update(content.as_bytes());
        tree.update(b"\n");
    }
    if walk.timed_out {
        return Err(late());
    }
    if walk.stopped {
        return Err(io::Error::other(
            "the workspace has more entries than the facts walk limit",
        ));
    }
    if walk.unreadable > 0 {
        return Err(io::Error::other("a workspace entry could not be read"));
    }
    Ok(WorkspaceFacts {
        tree: tree.finish(),
        files,
        oversize,
    })
}

/// SHA-256 of a file read in chunks, at most `cap + 1` bytes: `None` when
/// the file is longer than `cap` (by its metadata, or because it grew
/// while being read). The deadline is checked between chunks.
fn hash_capped(path: &Path, cap: u64, deadline: Instant) -> io::Result<Option<Digest>> {
    if fs::symlink_metadata(path)?.len() > cap {
        return Ok(None);
    }
    let mut f = File::open(path)?.take(cap + 1);
    let mut h = Sha256Stream::new();
    let mut buf = vec![0u8; FACTS_CHUNK_BYTES];
    let mut total: u64 = 0;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the facts walk passed its deadline",
            ));
        }
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        h.update(buf.get(..n).unwrap_or(&[]));
    }
    Ok((total <= cap).then(|| h.finish()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn dir(name: &str, files: usize) -> PathBuf {
        let d = std::env::temp_dir().join(format!("harness-walk-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        for i in 0..files {
            fs::write(d.join(format!("f{i:03}")), "x").unwrap();
        }
        d
    }

    fn walk(d: &Path, limit: usize) -> Walk {
        Walk::new(
            d.to_path_buf(),
            String::new(),
            fs::symlink_metadata(d).unwrap(),
            4,
            limit,
        )
    }

    #[test]
    fn a_large_directory_is_not_listed_past_the_entry_limit() {
        let d = dir("limit", 200);
        let mut w = walk(&d, 10);
        assert!(w.next_entry().is_some(), "the root");
        assert!(w.stack.len() < 10, "listed {} entries", w.stack.len());
        assert!(w.stopped);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_passed_deadline_stops_the_listing() {
        let d = dir("deadline", 20);
        let mut w = walk(&d, 1000).until(Instant::now());
        assert!(w.next_entry().is_none());
        assert!(w.timed_out && w.stack.is_empty());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn nf_1_a_huge_file_is_digested_by_size_and_never_read() {
        let d = dir("huge", 1);
        // A sparse file far larger than the cap: metadata says too big, so
        // it is never opened for hashing.
        let f = File::create(d.join("huge.bin")).unwrap();
        f.set_len(8 * 1024 * 1024 * 1024).unwrap();
        let far = Instant::now() + Duration::from_secs(60);
        let a = workspace_facts(&d, far).unwrap();
        assert_eq!((a.files, a.oversize), (2, 1));
        // Its size still counts: a different size is a different tree.
        f.set_len(8 * 1024 * 1024 * 1024 + 1).unwrap();
        assert_ne!(workspace_facts(&d, far).unwrap().tree, a.tree);
        // Under a small cap a file just over it is size-only too, and one
        // at the cap is hashed.
        fs::write(d.join("f000"), vec![b'a'; 1025]).unwrap();
        assert_eq!(facts_with(&d, far, 1024).unwrap().oversize, 2);
        fs::write(d.join("f000"), vec![b'a'; 1024]).unwrap();
        assert_eq!(facts_with(&d, far, 1024).unwrap().oversize, 1);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn nf_1_the_facts_walk_stops_at_its_deadline() {
        let d = dir("facts-deadline", 5);
        let err = workspace_facts(&d, Instant::now()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_bounded_read_refuses_one_byte_more() {
        let d = dir("bounded", 0);
        let f = d.join("f");
        fs::write(&f, vec![b'a'; 11]).unwrap();
        assert!(read_bounded(&f, 10).is_none());
        assert_eq!(read_bounded(&f, 11).unwrap().len(), 11);
        let _ = fs::remove_dir_all(&d);
    }
}
