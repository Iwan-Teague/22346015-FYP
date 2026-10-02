//! The built-in read tools, in process (design §4.8, §9 H1): `harness.fs.read`,
//! `harness.fs.search`, `harness.fs.list`, (H2e) `harness.fs.glob` and
//! (P-24) `harness.fs.outline`; the search and the glob are in
//! [`crate::search`], the outline in [`crate::outline`].
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
//! them could still redirect a read; nothing the agent can do creates one
//! (no exec tool; the edit tools write only regular files, through an
//! exclusive temp file and a rename), and H2's confined file-op helper
//! makes the kernel enforce the view. A hard link inside the workspace to a
//! file outside it is indistinguishable from a file, and a mount point
//! inside the workspace (a bind, network or FUSE mount, a disk image) is
//! read through like a directory (materialisation, H2, controls what the
//! workspace contains; H1 phase-exit review F-7). The per-call deadline is
//! cooperative (checked before a call and between a walk's entries), so a
//! read blocked in the kernel is not interrupted (design §11).
//!
//! **Bounds.** A read returns at most the run's read window of a text file
//! of at most [`READ_MAX_BYTES`]: [`READ_MAX_LINES`] lines by default, or
//! the profile's `max_read_lines` (H2e), and at most the window's bytes,
//! stopping at a line boundary and saying where to continue; search
//! reports at most [`SEARCH_MAX_HITS`] hits, grouped per file, skipping
//! files over [`SEARCH_FILE_MAX_BYTES`] and non-UTF-8 files, and stops
//! after [`WALK_MAX_ENTRIES`] entries; list shows at most
//! [`LIST_MAX_ENTRIES`] entries to depth ≤ 4. Every result is cut at
//! [`RESULT_MAX_BYTES`] (`truncated`), and its digest is over the full
//! output. The per-call deadline is checked before and during every walk.
//!
//! **Search** matches a literal substring, or with `regex: true` a regular
//! expression (H2e; before H2e only the literal, a recorded §4.8
//! deviation): see [`crate::search`].
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

use crate::glob::Glob;
use crate::provider::{
    InvokeCtx, ReadRecord, RefusalKind, ToolError, ToolProvider, ToolResult, ToolStatus,
};

/// Largest file `fs.read` reads.
pub const READ_MAX_BYTES: u64 = 4 * 1024 * 1024;
/// The default `fs.read` window, in lines (§4.8); a profile may set another
/// (`max_read_lines`, H2e).
pub const READ_MAX_LINES: u64 = 100;
/// The default `fs.read` window, in bytes of the result (the context's
/// default per-observation cap, so a read is never cut there).
pub const READ_WINDOW_BYTES: usize = 16 * 1024;
/// The widest window any profile may set, in lines: the manifest schema's
/// hard maximum for `lines` (H2e). A run's window is at most this.
pub const READ_WINDOW_MAX_LINES: u64 = 2000;
/// Room a read keeps for its first line (the path, the range, the digest)
/// within the window's bytes.
const READ_HEAD_ROOM: usize = 256;
pub use crate::search::SEARCH_MAX_HITS;
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
    /// An edit's file was not read in this run, or changed since it was
    /// read (§2.3 "Stale reads"; H2b).
    pub const STALE_READ: u16 = 11;
    /// An edit's `old` text matches nowhere (H2b).
    pub const NO_MATCH: u16 = 12;
    /// An edit's `old` text matches a different number of times than
    /// `count` (H2b).
    pub const MATCH_COUNT: u16 = 13;
    /// The edit would not change the file (H2b).
    pub const NO_OP: u16 = 14;
    /// A whole-file rewrite of a file over the line cap (H2b).
    pub const LINE_CAP: u16 = 15;
    /// The edit was written but could not be verified afterwards (§4.9
    /// step 4; H2b): the file may have changed.
    pub const UNVERIFIED: u16 = 16;
    /// `argv[0]` is not a program on the task's exec allowlist (H2d; policy
    /// refuses it first, so this is defence in depth).
    pub const EXEC_NOT_ALLOWED: u16 = 17;
    /// The sandbox refused the command's setup or could not start: nothing
    /// ran (H2d).
    pub const EXEC_SPAWN: u16 = 18;
    /// The program could not be started inside the sandbox (H2d).
    pub const EXEC_FAILED: u16 = 19;
    /// The command held more processes than its cap, so its sandbox was
    /// swept (FT-5, H2d).
    pub const EXEC_PROCESS_LIMIT: u16 = 20;
    /// A search's regular expression, or a glob pattern, does not compile;
    /// the message is static harness text for the kind of problem (H2e).
    pub const BAD_PATTERN: u16 = 21;
    /// A submission a failing pre-submit check turned back (H3a): the
    /// journal code of that submission's result; the model sees the failing
    /// check's output and a harness notice.
    pub const PRESUBMIT_REJECTED: u16 = 22;
    /// The path is protected (P-29): the edit tools refuse it, by the
    /// build's deny globs or the task's declared list.
    pub const PROTECTED: u16 = 23;
    /// The outline tool was pointed at a file whose extension names no
    /// language it knows (P-24).
    pub const NO_OUTLINE: u16 = 24;
}

const READ: &str = "harness.fs.read";
const SEARCH: &str = "harness.fs.search";
const LIST: &str = "harness.fs.list";
/// `harness.fs.glob` (H2e).
pub const GLOB: &str = "harness.fs.glob";
/// `harness.fs.outline` (P-24).
pub const OUTLINE: &str = "harness.fs.outline";

/// The in-process read tools over one workspace.
#[derive(Debug)]
pub struct ReadTools {
    ns: ProviderName,
    root: PathBuf,
    /// The read window: most lines per read (H2e).
    window_lines: u64,
    /// The read window: most bytes of a read's result (H2e).
    window_bytes: usize,
    /// Workspace-relative globs the policy denies on these tools (P-12):
    /// search, glob and list skip what they match and say how many. Empty
    /// by default — a library embedder decides (OD-2); the run's driver
    /// fills it from the policy.
    denied: Vec<Glob>,
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
        let root = canonical_root(root)?;
        let ns = ProviderName::new(harness_manifest::BUILTIN_NAMESPACE)
            .map_err(|_| RootRefused::Io(io::Error::other("builtin namespace")))?;
        Ok(Self {
            ns,
            root,
            window_lines: READ_MAX_LINES,
            window_bytes: READ_WINDOW_BYTES,
            denied: Vec::new(),
        })
    }

    /// The same tools with another read window (H2e: the profile's
    /// `max_read_lines`, and the bytes the context shows of one
    /// observation): a read returns at most `lines` lines (at most
    /// [`READ_WINDOW_MAX_LINES`]) and at most `bytes` bytes, stopping at a
    /// line boundary. A `lines` argument above the window is read as the
    /// window (the result's first line says which lines it holds).
    #[must_use]
    pub fn with_window(mut self, lines: u64, bytes: usize) -> Self {
        self.window_lines = lines.clamp(1, READ_WINDOW_MAX_LINES);
        self.window_bytes = bytes.clamp(READ_HEAD_ROOM * 2, RESULT_MAX_BYTES);
        self
    }

    /// The read window: (most lines, most bytes) per read.
    pub fn window(&self) -> (u64, usize) {
        (self.window_lines, self.window_bytes)
    }

    /// The same tools with policy-denied path globs (P-12): search, glob
    /// and list skip what the globs match and say how many paths they
    /// skipped, instead of showing denied paths or pretending nothing was
    /// there. The globs match workspace-relative, `/`-separated paths (the
    /// policy's own compiled [`Glob`]s, from `UserPolicy::denied_globs`).
    #[must_use]
    pub fn with_denied(mut self, denied: Vec<Glob>) -> Self {
        self.denied = denied;
        self
    }

    /// The policy-denied globs (P-12): what search and glob skip per path.
    pub(crate) fn denied(&self) -> &[Glob] {
        &self.denied
    }

    /// Whether a workspace-relative path is denied on these tools.
    pub(crate) fn denied_hit(&self, rel: &str) -> bool {
        self.denied.iter().any(|g| g.matches(rel))
    }

    /// The canonical workspace root.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// A finished tool call, before capping.
#[derive(Debug)]
pub(crate) struct Out {
    pub(crate) status: ToolStatus,
    pub(crate) text: String,
    pub(crate) read: Option<ReadRecord>,
}

pub(crate) fn err(code: u16, msg: &str) -> Out {
    Out {
        status: ToolStatus::Error { code },
        text: format!("error: {msg}"),
        read: None,
    }
}

pub(crate) fn ok(text: String) -> Out {
    Out {
        status: ToolStatus::Ok,
        text,
        read: None,
    }
}

pub(crate) fn timeout() -> Out {
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

    fn serves(&self, capability: &str) -> bool {
        matches!(capability, READ | SEARCH | LIST | GLOB | OUTLINE)
    }

    fn invoke(
        &mut self,
        call: Journaled<Authorized<Call>>,
        ctx: &InvokeCtx<'_>,
    ) -> Result<ToolResult, ToolError> {
        let c = call.call().call();
        let cap = c.capability.as_str();
        if !matches!(cap, READ | SEARCH | LIST | GLOB | OUTLINE) {
            return Ok(refused(cap, RefusalKind::UnknownCapability));
        }
        if Instant::now() >= ctx.deadline {
            return Ok(refused(cap, RefusalKind::DeadlinePassed));
        }
        let out = match cap {
            READ => self.read(&c.args),
            SEARCH => self.search(&c.args, ctx.deadline),
            GLOB => self.glob(&c.args, ctx.deadline),
            OUTLINE => self.outline(&c.args, ctx.deadline),
            _ => self.list(&c.args, ctx.deadline),
        };
        Ok(finish(cap, out))
    }
}

pub(crate) fn refused(cap: &str, reason: RefusalKind) -> ToolResult {
    let text = b"error: refused before running".to_vec();
    ToolResult {
        status: ToolStatus::Refused { reason },
        digest: sha256(&text),
        output: Untrusted::new(text, Source::Tool(cap.to_owned())),
        truncated: false,
        read: None,
        edit: None,
        exec: None,
    }
}

/// Cap the output at [`RESULT_MAX_BYTES`] (on a character boundary); the
/// digest is over the full output.
pub(crate) fn finish(cap: &str, out: Out) -> ToolResult {
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
        edit: None,
        exec: None,
    }
}

pub(crate) fn arg_path(
    args: &Value,
    key: &str,
    default: Option<&str>,
) -> Result<WorkspacePath, Out> {
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

pub(crate) fn arg_u64(
    args: &Value,
    key: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, Out> {
    match args.get(key) {
        None => Ok(default),
        Some(v) => match v.as_u64() {
            Some(n) if (min..=max).contains(&n) => Ok(n),
            _ => Err(err(code::BAD_ARGS, "an integer argument is out of range")),
        },
    }
}

/// Check and canonicalise a workspace root: a real directory, never a
/// symlink (ancestors of the workspace may be symlinks — `/tmp` on
/// macOS — its contents may not). Shared by the read tools (§4.8) and
/// the edit engine (§4.9).
pub(crate) fn canonical_root(root: &Path) -> Result<PathBuf, RootRefused> {
    // The root as its components: a trailing separator or `.` makes the
    // OS resolve a final symlink (`symlink_metadata("link/")` follows
    // the link), and `components()` drops both (H1 phase-exit review
    // F-9 item 10).
    let root: PathBuf = root.components().collect();
    let m = fs::symlink_metadata(&root)?;
    if m.file_type().is_symlink() {
        return Err(RootRefused::Symlink);
    }
    if !m.is_dir() {
        return Err(RootRefused::NotADir);
    }
    fs::canonicalize(root).map_err(RootRefused::from)
}

/// Why a workspace path could not be resolved by [`resolve`].
#[derive(Debug)]
pub(crate) enum ResolveErr {
    /// A component of the path (or the root) does not exist.
    NotFound,
    /// A component of the path is a symlink (never followed).
    Symlink,
    /// A component could not be examined.
    Io(io::Error),
}

impl From<io::Error> for ResolveErr {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::NotFound {
            ResolveErr::NotFound
        } else {
            ResolveErr::Io(e)
        }
    }
}

/// Resolve `p` from `root` one component at a time with
/// `symlink_metadata`, refusing a symlink at ANY component (INV-30,
/// in-process half): a link inside the workspace can never make the
/// harness touch a file outside it. `Ok((path, None))` means only the
/// FINAL component is missing — a create candidate for the edit engine
/// (§4.9); a missing intermediate component, or the root, is
/// [`ResolveErr::NotFound`]. The metadata returned is the final
/// component's own (not followed through).
pub(crate) fn resolve(
    root: &Path,
    p: &WorkspacePath,
) -> Result<(PathBuf, Option<Metadata>), ResolveErr> {
    let mut cur = root.to_path_buf();
    let mut meta = fs::symlink_metadata(&cur)?;
    let comps: Vec<&str> = p.components().collect();
    let last = comps.len();
    for (i, c) in comps.into_iter().enumerate() {
        cur.push(c);
        let m = match fs::symlink_metadata(&cur) {
            Ok(m) => m,
            // Only the final component may be missing (create case).
            Err(e) if i + 1 == last && e.kind() == io::ErrorKind::NotFound => {
                return Ok((cur, None))
            }
            Err(e) => return Err(e.into()),
        };
        if m.file_type().is_symlink() {
            return Err(ResolveErr::Symlink);
        }
        meta = m;
    }
    Ok((cur, Some(meta)))
}

impl ReadTools {
    /// Resolve a workspace path component by component, refusing a symlink
    /// at any component. Returns the path and its (not followed) metadata.
    pub(crate) fn resolve(&self, p: &WorkspacePath) -> Result<(PathBuf, Metadata), Out> {
        match resolve(&self.root, p) {
            Ok((path, Some(meta))) => Ok((path, meta)),
            // A pattern in a path is the likely mistake (H2e: a local model gave
            // `path: "src/**"` to two searches and a glob, and got only "no
            // such file or directory"): say where a pattern goes, in harness
            // words that never quote the path.
            Ok((_, None)) | Err(ResolveErr::NotFound) => Err(err(
                code::NOT_FOUND,
                if p.as_str().contains(['*', '?', '[', '{']) {
                    "no such file or directory: a path names one file or directory, not a pattern (a glob goes in the search's include or exclude, or in the glob tool's pattern)"
                } else {
                    "no such file or directory"
                },
            )),
            Err(ResolveErr::Symlink) => Err(err(
                code::SYMLINK,
                "a path component is a symlink; symlinks are never followed",
            )),
            Err(ResolveErr::Io(e)) => Err(io_out(e)),
        }
    }

    fn read(&self, args: &Value) -> Out {
        match self.try_read(args) {
            Ok(o) | Err(o) => o,
        }
    }

    fn try_read(&self, args: &Value) -> Result<Out, Out> {
        let wp = arg_path(args, "path", None)?;
        let start = arg_u64(args, "start", 1, 1, u64::MAX)?;
        // The schema's hard maximum is the widest window any profile may
        // set; this run's window is the profile's (H2e).
        let want = arg_u64(args, "lines", self.window_lines, 1, READ_WINDOW_MAX_LINES)?
            .min(self.window_lines);
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
        let last = start.saturating_add(want - 1).min(total);
        // The lines, within the window's bytes (H2e): whole lines only,
        // stopping before the one that would pass the budget; the first
        // line is always shown, cut when it alone is over the budget.
        let budget = self
            .window_bytes
            .saturating_sub(READ_HEAD_ROOM + shown_path(&wp).len());
        let skip = usize::try_from(start - 1).unwrap_or(usize::MAX);
        let take = usize::try_from(last - start + 1).unwrap_or(0);
        let mut body = String::new();
        let mut end = start;
        let mut stopped = false;
        let mut long_first = false;
        for (i, line) in text.lines().skip(skip).take(take).enumerate() {
            let n = start + i as u64;
            let row = format!("{n}\t{line}\n");
            if body.len() + row.len() > budget {
                if i == 0 {
                    long_first = true;
                    body = format!("{}\n", cut(&row, budget.saturating_sub(4)).trim_end());
                    end = n;
                }
                stopped = true;
                break;
            }
            body.push_str(&row);
            end = n;
        }
        let head = if long_first {
            format!(
                "{}: line {start} of {total}, cut: it alone is longer than the read window's {} bytes; sha256 {digest}\n",
                shown_path(&wp),
                self.window_bytes
            )
        } else if stopped {
            format!(
                "{}: lines {start}-{end} of {total} (the read window's {} bytes end here; continue with start {}); sha256 {digest}\n",
                shown_path(&wp),
                self.window_bytes,
                end + 1
            )
        } else {
            format!(
                "{}: lines {start}-{end} of {total}; sha256 {digest}\n",
                shown_path(&wp)
            )
        };
        let mut o = ok(head + &body);
        o.read = Some(record);
        Ok(o)
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
        let mut denied = 0usize;
        // A denied directory is neither entered nor listed (its children
        // are denied with it); the entry itself is still walked, and the
        // file check below skips it from the listing.
        while let Some(e) = walk.next_entry_if(&mut |e| {
            if e.depth > 0 && self.denied_hit(&e.rel) {
                denied += 1;
                false
            } else {
                true
            }
        }) {
            if Instant::now() >= deadline {
                return Err(timeout());
            }
            if e.depth == 0 {
                continue; // the directory itself
            }
            if !e.meta.is_dir() && self.denied_hit(&e.rel) {
                denied += 1;
                continue;
            }
            if shown == LIST_MAX_ENTRIES {
                more = true;
                break;
            }
            shown += 1;
            let line = if e.symlink {
                format!("l {} (symlink, not followed)\n", e.rel)
            } else if e.meta.is_dir() {
                // No trailing '/': the listing is the model's vocabulary for
                // the next call's path argument, and the workspace-path rule
                // refuses a trailing slash (EmptyComponent). Never show the
                // model a string the policy would refuse.
                format!("d {}\n", e.rel)
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
        s.insert_str(0, &head);
        if denied > 0 {
            s.push_str(&format!("{denied} path(s) skipped (denied by policy)\n"));
        }
        Ok(ok(s))
    }
}

/// Read at most `max` bytes of `path`; `None` if it is longer (or cannot be
/// read).
pub(crate) fn read_bounded(path: &Path, max: u64) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|f| f.take(max + 1).read_to_end(&mut bytes))
        .ok()?;
    (u64::try_from(bytes.len()).ok()? <= max).then_some(bytes)
}

pub(crate) fn shown_path(wp: &WorkspacePath) -> &str {
    if wp.as_str().is_empty() {
        "."
    } else {
        wp.as_str()
    }
}

pub(crate) fn cut(line: &str, max: usize) -> String {
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
pub(crate) struct Entry {
    pub(crate) path: PathBuf,
    pub(crate) rel: String,
    pub(crate) meta: Metadata,
    pub(crate) depth: usize,
    pub(crate) symlink: bool,
}

/// A bounded, deterministic (name-sorted, depth-first) walk that never
/// follows or descends into a symlink. The entry limit and the deadline are
/// checked while a directory is being listed, not only between entries, so
/// a huge directory is never enumerated in full (H1e-2a review F-2). A
/// directory cut short by the limit makes the walk `stopped`.
pub(crate) struct Walk {
    stack: Vec<Entry>,
    max_depth: usize,
    limit: usize,
    deadline: Option<Instant>,
    pub(crate) timed_out: bool,
    pub(crate) unreadable: usize,
    visited: usize,
    pub(crate) symlinks: usize,
    pub(crate) stopped: bool,
}

impl Walk {
    pub(crate) fn new(
        start: PathBuf,
        rel: String,
        meta: Metadata,
        max_depth: usize,
        limit: usize,
    ) -> Self {
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
    pub(crate) fn until(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    fn next_entry(&mut self) -> Option<Entry> {
        self.next_entry_if(&mut |_| true)
    }

    /// The next entry. A directory's children are listed only when `enter`
    /// says so (H2e: search and glob skip `.git` and excluded directories
    /// without listing them); the directory itself is still returned.
    pub(crate) fn next_entry_if(&mut self, enter: &mut dyn FnMut(&Entry) -> bool) -> Option<Entry> {
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
        if e.meta.is_dir() && !e.symlink && e.depth < self.max_depth && enter(&e) {
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
                // A non-UTF-8 name is shown lossily, and the tree digest
                // hashes that lossy form too, so two names that differ
                // only in their invalid bytes hash alike (a named
                // residual, design row H1g); `path` keeps the real name.
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
/// the path is the relative path in its lossy UTF-8 form and the content is
/// a file's SHA-256 (streamed in 64 KiB chunks, never read whole) or, for a
/// file over [`FACTS_FILE_MAX_BYTES`], its size (kind `F`). So the digest
/// changes when any name, kind or (capped) file content changes, except a
/// rename between two non-UTF-8 names with the same lossy form. Refused
/// (an `Err`) past [`FACTS_MAX_ENTRIES`] entries, on any unreadable entry,
/// or when `deadline` passes: a fact the harness cannot measure is not
/// stated. The deadline is cooperative: it is checked between entries and
/// between chunks, so a read blocked in the kernel (a network or FUSE mount
/// inside the workspace) is not interrupted (design §11).
pub fn workspace_facts(root: &Path, deadline: Instant) -> io::Result<WorkspaceFacts> {
    facts_with(root, deadline, FACTS_FILE_MAX_BYTES)
}

/// [`workspace_facts`], keeping the listing the digest was computed over
/// (design §2.8 "snapshots": a path and a digest per entry, empty
/// directories included), so the run can keep the tree digest current
/// after its own edits without walking the workspace again
/// ([`WorkspaceTree::record_edit`]).
pub fn workspace_tree(root: &Path, deadline: Instant) -> io::Result<WorkspaceTree> {
    tree_with(root, deadline, FACTS_FILE_MAX_BYTES)
}

fn facts_with(root: &Path, deadline: Instant, file_cap: u64) -> io::Result<WorkspaceFacts> {
    tree_with(root, deadline, file_cap).map(|t| t.facts())
}

/// One entry of a [`WorkspaceTree`]: what the facts walk digests for it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TreeEntry {
    /// The relative path, `/`-separated, in its lossy UTF-8 form.
    rel: String,
    /// `d` directory, `f` file (content digested), `F` file over the cap
    /// (size only), `l` symlink (never followed), `o` anything else.
    kind: u8,
    /// A file's SHA-256 in hex, `len:<n>` for kind `F`, empty otherwise.
    content: String,
}

/// The workspace as the facts walk measured it: every entry in walk order
/// with what the tree digest covers for it, and the facts derived from
/// them. The walk visits siblings in name order, depth first, so walk
/// order is the lexicographic order of the paths' component sequences;
/// [`WorkspaceTree::record_edit`] keeps that order when it adds a file, so
/// the digest it recomputes is the digest a fresh walk would measure when
/// nothing but the run's own edits changed the workspace. Resume compares
/// the two (design §2.10): a workspace changed any other way is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceTree {
    entries: Vec<TreeEntry>,
    files: u64,
    oversize: u64,
    tree: Digest,
}

/// Compare two relative paths the way the walk orders them: component by
/// component (so `a/b` sorts before `a-c`, although `-` < `/`).
fn walk_order(a: &str, b: &str) -> std::cmp::Ordering {
    a.split('/').cmp(b.split('/'))
}

impl WorkspaceTree {
    fn from_entries(entries: Vec<TreeEntry>, files: u64, oversize: u64) -> Self {
        let mut t = Self {
            entries,
            files,
            oversize,
            tree: sha256(b""),
        };
        t.tree = t.digest_entries();
        t
    }

    fn digest_entries(&self) -> Digest {
        let mut tree = Sha256Stream::new();
        for e in &self.entries {
            tree.update(&[e.kind]);
            tree.update(e.rel.as_bytes());
            tree.update(&[0]);
            tree.update(e.content.as_bytes());
            tree.update(b"\n");
        }
        tree.finish()
    }

    /// The facts: tree digest, regular files, files digested by size only.
    pub fn facts(&self) -> WorkspaceFacts {
        WorkspaceFacts {
            tree: self.tree,
            files: self.files,
            oversize: self.oversize,
        }
    }

    /// The current tree digest.
    pub fn digest(&self) -> Digest {
        self.tree
    }

    /// Record the run's own edit: `path` is now a regular file whose
    /// content has SHA-256 `after` (an edit only ever leaves a regular file
    /// of at most the edit cap, so it is always digested by content). A
    /// path not in the listing is a created file, added in walk order.
    /// Returns the new tree digest.
    pub fn record_edit(&mut self, path: &WorkspacePath, after: Digest) -> Digest {
        let rel = path.as_str();
        // A create may have made directories on the way (H2f): each is an
        // entry of the tree, and one already there is left as it is.
        let mut prefix = String::new();
        let comps: Vec<&str> = rel.split('/').collect();
        for c in comps.iter().take(comps.len().saturating_sub(1)) {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(c);
            let at = self
                .entries
                .partition_point(|e| walk_order(&e.rel, &prefix) == std::cmp::Ordering::Less);
            if self.entries.get(at).is_none_or(|e| e.rel != prefix) {
                self.entries.insert(
                    at,
                    TreeEntry {
                        rel: prefix.clone(),
                        kind: b'd',
                        content: String::new(),
                    },
                );
            }
        }
        let at = self
            .entries
            .partition_point(|e| walk_order(&e.rel, rel) == std::cmp::Ordering::Less);
        let content = after.to_string();
        match self.entries.get_mut(at) {
            Some(e) if e.rel == rel => {
                match e.kind {
                    b'f' => {}
                    b'F' => {
                        self.oversize = self.oversize.saturating_sub(1);
                    }
                    // Not a file before: it is one now.
                    _ => self.files = self.files.saturating_add(1),
                }
                e.kind = b'f';
                e.content = content;
            }
            _ => {
                self.entries.insert(
                    at,
                    TreeEntry {
                        rel: rel.to_owned(),
                        kind: b'f',
                        content,
                    },
                );
                self.files = self.files.saturating_add(1);
            }
        }
        self.tree = self.digest_entries();
        self.tree
    }
}

fn tree_with(root: &Path, deadline: Instant, file_cap: u64) -> io::Result<WorkspaceTree> {
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
    let mut entries = Vec::new();
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
        entries.push(TreeEntry {
            rel: e.rel,
            kind,
            content,
        });
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
    Ok(WorkspaceTree::from_entries(entries, files, oversize))
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

    // H2b: the digest a tree keeps current through the run's own edits is
    // the digest a fresh walk measures, whatever the created file's place
    // in walk order (component order: `a/b` before `a-c` although `-` <
    // `/`), for a changed file, and from an empty workspace.
    #[test]
    fn an_edited_tree_digests_as_a_fresh_walk_measures() {
        let d = dir("tree-edits", 0);
        fs::create_dir_all(d.join("a/deep")).unwrap();
        fs::create_dir_all(d.join("z")).unwrap();
        fs::write(d.join("a/b.txt"), "b\n").unwrap();
        fs::write(d.join("a-c.txt"), "c\n").unwrap();
        fs::write(d.join("a/deep/x.rs"), "x\n").unwrap();
        let far = Instant::now() + Duration::from_secs(60);
        let mut t = workspace_tree(&d, far).unwrap();
        assert_eq!(t.facts(), workspace_facts(&d, far).unwrap());
        let edits: &[(&str, &str)] = &[
            ("a/b.txt", "b changed\n"),    // an existing file
            ("a/a.txt", "new before b\n"), // created, first in a/
            ("a/deep0.txt", "between deep/ and deep0\n"),
            ("a.txt", "before the a/ directory\n"),
            ("a-b.txt", "after a/, before a-c\n"),
            ("0.txt", "first of all\n"),
            ("z/zz.txt", "last of all\n"),
            ("zz.txt", "after z/\n"),
            ("a/deep/x.rs", "x changed\n"),
            // Created with the directories it needs (H2f).
            ("n/m/new.rs", "two new directories\n"),
            ("n/other.rs", "into one made before\n"),
            ("a/deep/sub/y.rs", "one new directory in an old one\n"),
        ];
        for (path, text) in edits {
            fs::create_dir_all(d.join(path).parent().unwrap()).unwrap();
            fs::write(d.join(path), text).unwrap();
            let wp = workspace_path(path).unwrap();
            let got = t.record_edit(&wp, sha256(text.as_bytes()));
            let fresh = workspace_facts(&d, far).unwrap();
            assert_eq!(got, fresh.tree, "after editing {path}");
            assert_eq!(t.facts(), fresh, "after editing {path}");
        }
        // From an empty workspace too.
        let e = dir("tree-empty", 0);
        let mut t = workspace_tree(&e, far).unwrap();
        assert_eq!(t.facts().files, 0);
        fs::write(e.join("new.rs"), "fn main() {}\n").unwrap();
        let got = t.record_edit(
            &workspace_path("new.rs").unwrap(),
            sha256(b"fn main() {}\n"),
        );
        assert_eq!(got, workspace_facts(&e, far).unwrap().tree);
        assert_eq!(t.facts().files, 1);
        let _ = fs::remove_dir_all(&d);
        let _ = fs::remove_dir_all(&e);
    }

    #[test]
    fn walk_order_is_component_order() {
        use std::cmp::Ordering::*;
        assert_eq!(walk_order("a/b", "a-c"), Less);
        assert_eq!(walk_order("a", "a/b"), Less);
        assert_eq!(walk_order("a/b", "a/b"), Equal);
        assert_eq!(walk_order("b", "a/z"), Greater);
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

    // P-29: protected paths gate EDITS only — reads inside `.git` stay
    // allowed (the read tools have no protected notion at all).
    #[test]
    fn read_of_dot_git_allowed() {
        let d = dir("read-dot-git", 0);
        fs::create_dir(d.join(".git")).unwrap();
        fs::write(
            d.join(".git/config"),
            "[core]\n\trepositoryformatversion = 0\n",
        )
        .unwrap();
        let t = ReadTools::new(&d).unwrap();
        let out = t.read(&serde_json::json!({ "path": ".git/config" }));
        match out.status {
            ToolStatus::Ok => {
                assert!(out.text.contains("repositoryformatversion"), "{}", out.text);
                let r = out.read.expect("a read records its digest");
                assert_eq!(r.path.as_str(), ".git/config");
                assert_eq!(r.sha256, sha256(b"[core]\n\trepositoryformatversion = 0\n"));
            }
            other => panic!("reading .git/config must be allowed, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&d);
    }
}
