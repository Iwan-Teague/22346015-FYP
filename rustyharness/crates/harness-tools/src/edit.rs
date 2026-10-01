//! The in-process edit engine (design §4.9, D9): exact search/replace
//! and whole-file write, over one workspace, with the same confinement
//! walk as the read tools (INV-30 in-process half: every path is
//! resolved from the workspace root one component at a time with
//! `symlink_metadata`; a symlink at ANY component is refused, never
//! followed), and [`EditTools`], which serves it to the model as
//! `harness.edit.replace` and `harness.edit.write` through the
//! [`ToolProvider`] seam (H2b): a call reaches the engine only as a
//! `Journaled<Authorized<Call>>`, anchored on the run's reads.
//!
//! **Stale reads (§2.3, R1 §2).** An edit is anchored on an earlier
//! read: the file must have been read this run ([`ReadLog`]) and its
//! current SHA-256 must still equal the recorded one, else the edit is
//! refused with [`StaleRead`] before anything is matched or written.
//!
//! **Replace.** `old` must be non-empty and differ from `new`; the
//! byte-exact matches of `old` must number exactly `count` (default 1,
//! the unique match of R1 §1.5). Zero matches reports the nearest
//! match after line-ending normalisation plus, when the file is CRLF
//! and `old` uses LF, a hint saying so; a wrong number of matches
//! reports the match line numbers. Either way the file is untouched.
//!
//! **Write (§4.8 `harness.edit.write`).** The §4.8 schema is one
//! capability with no mode flag, so the regime follows existence: a
//! free path (whose parent exists) is created — the "CREATING: must
//! not exist" rule holds by construction — while an existing file is
//! the OVERWRITING regime: a fresh read of at most
//! [`WRITE_OVERWRITE_MAX_LINES`] lines.
//!
//! **Atomic apply (D9).** The new content is written to a temp file
//! created exclusively (`O_EXCL`: a planted name, symlink or not, is
//! never opened) in the SAME directory, given the original's
//! permissions through its handle, fsynced, then renamed over the target
//! (atomic on one filesystem); on any failure the temp file is removed
//! and the original is untouched. Existing
//! line endings are preserved: when the file is CRLF-dominant, bare
//! LFs in the replacement text become CRLF. Then the file is re-read
//! and its SHA-256 must equal the in-memory expected splice AND differ
//! from the pre-edit hash — an edit that silently changed nothing is
//! reported as failed, never as success (R1 §2 "silent no-op" class).
//!
//! **Bounds.** Only UTF-8 files of at most [`EDIT_MAX_BYTES`] — the
//! same cap as `fs.read` — are edited; a write body over the cap is
//! refused. All checks run in this order: lexical workspace path,
//! argument sanity, existence, size, stale read, UTF-8, line cap,
//! no-op.
//!
//! **Named residual (the design's H1 position, §4.8):** like the read
//! tools' check-then-open gap, the check-then-rename here is not one
//! kernel transaction; H2's confined file-op helper closes it. A hard
//! link inside the workspace is indistinguishable from a file
//! (materialisation, H2, controls what the workspace contains).

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use harness_core::{sha256, Digest};
use harness_journal::Journaled;
use harness_manifest::ProviderName;
use harness_policy::{workspace_path, Authorized, Call, WorkspacePath};
use serde_json::Value;

use crate::builtin::{
    canonical_root, code, err, finish, ok, refused, resolve as resolve_path, Out, ResolveErr,
    RootRefused,
};
use crate::provider::{EditRecord, InvokeCtx, RefusalKind, ToolError, ToolProvider, ToolResult};

/// Largest file the edit engine reads or writes — the same cap as
/// `fs.read` ([`READ_MAX_BYTES`](crate::builtin::READ_MAX_BYTES)), so a
/// file the harness can read whole is one it can edit.
pub const EDIT_MAX_BYTES: u64 = crate::builtin::READ_MAX_BYTES;
/// Most lines a whole-file overwrite may target (§4.8: 400).
pub const WRITE_OVERWRITE_MAX_LINES: usize = 400;
/// Most "nearest match" line numbers a [`EditError::ZeroMatches`] lists.
const NEAREST_MAX: usize = 10;

/// The files read this run, with the SHA-256 of each file's whole
/// content at its latest read (design §2.3 "Stale reads"). The driver
/// records each `fs.read`; the edit engine calls [`ReadLog::check`],
/// which refuses an edit to a file that changed since it was read, or
/// was never read.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReadLog {
    files: BTreeMap<String, Digest>,
}

/// Why an edit anchored on an earlier read is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StaleRead {
    /// The file was never read in this run.
    #[error("file not read in this run; read it first")]
    NeverRead,
    /// The file changed since it was last read.
    #[error("file changed since read; re-read first")]
    Changed,
}

impl ReadLog {
    /// Record a read.
    pub fn record(&mut self, path: &str, sha256: Digest) {
        self.files.insert(path.to_owned(), sha256);
    }

    /// The digest recorded for `path`, if any.
    pub fn get(&self, path: &str) -> Option<Digest> {
        self.files.get(path).copied()
    }

    /// Whether an edit may rely on the last read of `path`, given the
    /// file's current digest.
    pub fn check(&self, path: &str, current: Digest) -> Result<(), StaleRead> {
        match self.files.get(path) {
            None => Err(StaleRead::NeverRead),
            Some(d) if *d == current => Ok(()),
            Some(_) => Err(StaleRead::Changed),
        }
    }
}

/// An exact search/replace request (§4.9 `harness.edit.replace`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplaceReq {
    /// Workspace path of the file.
    pub path: String,
    /// The byte-exact text to replace; non-empty.
    pub old: String,
    /// The replacement.
    pub new: String,
    /// How many matches `old` must have; 1 is the unique match.
    pub count: usize,
}

/// A whole-file write request (§4.8 `harness.edit.write`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteReq {
    /// Workspace path of the file.
    pub path: String,
    /// The full new content.
    pub content: String,
}

/// A successful edit: the before/after digests the H2 journal wants
/// (§4.9 step 5). `before` is `None` for a create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The workspace path edited.
    pub path: WorkspacePath,
    /// The file's SHA-256 before the edit (`None` for a create).
    pub before: Option<Digest>,
    /// The file's SHA-256 after the edit.
    pub after: Digest,
    /// A replace's matches: the 1-based line of each in the file before
    /// the edit. Empty for a write.
    pub lines: Vec<usize>,
    /// How many lines the file has after the edit.
    pub lines_after: usize,
}

/// Why an edit was refused or failed. Only [`EditError::Unverified`] can
/// mean the file changed: every other variant is reported before the
/// atomic apply, with the file untouched. `Unverified` wraps whatever
/// the re-read after the rename found (`Verify`, `NoChange`, or the
/// file gone, a symlink, unreadable); even then the file holds
/// either the intended content or the original, never a partial splice.
#[derive(Debug, thiserror::Error)]
pub enum EditError {
    /// The path fails the lexical workspace rule (§4.8).
    #[error("the path is refused: {0}")]
    PathRefused(harness_policy::PathRefused),
    /// `count` is zero; it must be at least 1.
    #[error("`count` must be at least 1")]
    BadCount,
    /// `old` is empty.
    #[error("`old` is empty")]
    EmptyOld,
    /// The edit would not change anything (`old` equals `new`, or the
    /// write body equals the file).
    #[error("the edit would not change the file")]
    NoOp,
    /// Nothing exists at the path (or an intermediate component).
    #[error("no such file or directory")]
    NotFound,
    /// A component of the path is a symlink (never followed).
    #[error("a path component is a symlink; symlinks are never followed")]
    Symlink,
    /// Not a regular file.
    #[error("not a regular file")]
    NotAFile,
    /// Not UTF-8 text.
    #[error("not UTF-8 text")]
    NotUtf8,
    /// Larger than the edit cap.
    #[error("{len} bytes is over the {cap}-byte cap")]
    TooLarge {
        /// The offending size.
        len: u64,
        /// The cap.
        cap: u64,
    },
    /// A whole-file overwrite of a file over the line cap (§4.8).
    #[error("{lines} lines is over the {cap}-line overwrite cap")]
    TooManyLines {
        /// The file's line count.
        lines: usize,
        /// The cap.
        cap: usize,
    },
    /// The edit is anchored on a read that is missing or stale (§2.3).
    #[error(transparent)]
    Stale(#[from] StaleRead),
    /// `old` matches nowhere; `nearest` lists the line numbers (after
    /// line-ending normalisation, at most [`NEAREST_MAX`]) of the
    /// closest thing that does match, and `crlf_hint` is set when the
    /// file uses CRLF line endings while `old` uses LF.
    #[error("`old` matches nowhere; nearest line-ending-normalised match line(s): {nearest:?}; the file uses CRLF while `old` uses LF: {crlf_hint}")]
    ZeroMatches {
        /// Nearest normalised-match line numbers, ascending.
        nearest: Vec<usize>,
        /// The file is CRLF and `old` uses bare LF.
        crlf_hint: bool,
    },
    /// `old` matched a different number of times than `count`; `lines`
    /// lists every match's line number.
    #[error("`old` matches {found} time(s), not the expected {expected}: line(s) {lines:?}")]
    MatchCount {
        /// The requested match count.
        expected: usize,
        /// The number of byte-exact matches found.
        found: usize,
        /// The 1-based line number of every match.
        lines: Vec<usize>,
    },
    /// Post-apply verification failed: the file does not hash to the
    /// expected splice.
    #[error("verification failed: the file hashes to {found}, expected {expected}")]
    Verify {
        /// The digest the splice should have.
        expected: Digest,
        /// The digest found on re-read.
        found: Digest,
    },
    /// The applied edit did not change the file's digest (R1 §2 silent
    /// no-op class): reported as a failure, never a success.
    #[error("the edit left the file unchanged (sha256 {sha256})")]
    NoChange {
        /// The unchanged digest.
        sha256: Digest,
    },
    /// Any other file-system error.
    #[error("the file system refused the operation: {0}")]
    Io(#[from] io::Error),
    /// The new content was renamed over the file, but the re-read after it
    /// (§4.9 step 4) did not find the expected splice: the inner error says
    /// what it found. The only variant after which the workspace may have
    /// changed (H2b: the run treats it so).
    #[error("the edit was written but not verified: {0}")]
    Unverified(Box<EditError>),
}

impl EditError {
    /// Whether the workspace may have changed: only after the rename,
    /// when verification failed ([`EditError::Unverified`]).
    pub fn may_have_changed(&self) -> bool {
        matches!(self, EditError::Unverified(_))
    }
}

impl From<ResolveErr> for EditError {
    fn from(e: ResolveErr) -> Self {
        match e {
            ResolveErr::NotFound => EditError::NotFound,
            ResolveErr::Symlink => EditError::Symlink,
            ResolveErr::Io(e) => EditError::Io(e),
        }
    }
}

/// The in-process edit engine over one workspace (§4.9).
#[derive(Debug)]
pub struct EditEngine {
    root: PathBuf,
}

impl EditEngine {
    /// An edit engine over the workspace at `root`, which must be a
    /// real directory (not a symlink) — the same root rule as the read
    /// tools. The root is canonicalised once here.
    pub fn new(root: &Path) -> Result<Self, RootRefused> {
        Ok(Self {
            root: canonical_root(root)?,
        })
    }

    /// The canonical workspace root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Exact search/replace (§4.9): `old` must match `count` times,
    /// byte-exactly, in a file read this run whose content still
    /// hashes to the recorded digest. On success the file holds the
    /// spliced content (atomic apply, line endings preserved) and the
    /// re-read digest equals the expected splice.
    pub fn replace(&self, req: &ReplaceReq, reads: &ReadLog) -> Result<Applied, EditError> {
        let wp = workspace_path(&req.path).map_err(EditError::PathRefused)?;
        if req.count == 0 {
            return Err(EditError::BadCount);
        }
        if req.old.is_empty() {
            return Err(EditError::EmptyOld);
        }
        if req.old == req.new {
            return Err(EditError::NoOp);
        }
        let (path, meta) = resolve_path(&self.root, &wp)?;
        let Some(meta) = meta else {
            return Err(EditError::NotFound);
        };
        if !meta.is_file() {
            return Err(EditError::NotAFile);
        }
        let bytes = read_capped(&path, meta.len(), EDIT_MAX_BYTES)?;
        let before = sha256(&bytes);
        reads.check(wp.as_str(), before)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| EditError::NotUtf8)?;
        let offsets = find_offsets(text, &req.old);
        if offsets.is_empty() {
            return Err(zero_matches(text, &req.old));
        }
        if offsets.len() != req.count {
            return Err(EditError::MatchCount {
                expected: req.count,
                found: offsets.len(),
                lines: offsets.iter().map(|&o| line_of(text, o)).collect(),
            });
        }
        // The replacement takes the file's dominant line endings.
        let new = if crlf_dominant(text) {
            lf_to_crlf(&req.new)
        } else {
            req.new.clone()
        };
        let spliced = splice(&bytes, &offsets, req.old.len(), new.as_bytes());
        if spliced == bytes {
            // Cannot happen with `old != new` unless line-ending
            // conversion maps `new` back onto `old`; still refused as
            // the silent no-op it is.
            return Err(EditError::NoChange { sha256: before });
        }
        let expected = sha256(&spliced);
        atomic_write(&path, &spliced, Some(meta.permissions()))?;
        let mut applied = self.verify(&wp, Some(before), expected, line_count(&spliced))?;
        applied.lines = offsets.iter().map(|&o| line_of(text, o)).collect();
        Ok(applied)
    }

    /// Whole-file write (§4.8 `harness.edit.write`). A free path is
    /// created (its parent must exist); an existing file is
    /// overwritten, which requires a fresh read of at most
    /// [`WRITE_OVERWRITE_MAX_LINES`] lines.
    pub fn write(&self, req: &WriteReq, reads: &ReadLog) -> Result<Applied, EditError> {
        let wp = workspace_path(&req.path).map_err(EditError::PathRefused)?;
        let (path, meta) = resolve_path(&self.root, &wp)?;
        match meta {
            // Create: nothing at the path, so nothing to be stale
            // about ("CREATING: must not exist", §4.8, holds by
            // construction).
            None => {
                let content = req.content.as_bytes();
                let len = u64::try_from(content.len()).unwrap_or(u64::MAX);
                if len > EDIT_MAX_BYTES {
                    return Err(EditError::TooLarge {
                        len,
                        cap: EDIT_MAX_BYTES,
                    });
                }
                let expected = sha256(content);
                atomic_write(&path, content, None)?;
                self.verify(&wp, None, expected, line_count(content))
            }
            Some(meta) => {
                if !meta.is_file() {
                    return Err(EditError::NotAFile);
                }
                let bytes = read_capped(&path, meta.len(), EDIT_MAX_BYTES)?;
                let before = sha256(&bytes);
                reads.check(wp.as_str(), before)?;
                let text = std::str::from_utf8(&bytes).map_err(|_| EditError::NotUtf8)?;
                let lines = text.lines().count();
                if lines > WRITE_OVERWRITE_MAX_LINES {
                    return Err(EditError::TooManyLines {
                        lines,
                        cap: WRITE_OVERWRITE_MAX_LINES,
                    });
                }
                // The body takes the file's dominant line endings; a
                // body that only differs in line endings is still a
                // no-op once converted.
                let out = if crlf_dominant(text) {
                    lf_to_crlf(&req.content)
                } else {
                    req.content.clone()
                };
                let out_bytes = out.as_bytes();
                if out_bytes == bytes.as_slice() {
                    return Err(EditError::NoOp);
                }
                let expected = sha256(out_bytes);
                atomic_write(&path, out_bytes, Some(meta.permissions()))?;
                self.verify(&wp, Some(before), expected, line_count(out_bytes))
            }
        }
    }

    /// Re-read the file (§4.9 step 4): the digest must equal the
    /// expected splice and, when there was a before, differ from it. The
    /// re-read takes the same component-by-component walk and the same
    /// cap as every other access, so a target that became a symlink (or
    /// grew past the cap) after the rename fails the edit instead of
    /// being followed.
    fn verify(
        &self,
        wp: &WorkspacePath,
        before: Option<Digest>,
        expected: Digest,
        lines_after: usize,
    ) -> Result<Applied, EditError> {
        self.reread(wp, before, expected)
            .map(|after| Applied {
                path: wp.clone(),
                before,
                after,
                lines: Vec::new(),
                lines_after,
            })
            .map_err(|e| EditError::Unverified(Box::new(e)))
    }

    /// The re-read of [`EditEngine::verify`]: the digest found, when it is
    /// the expected one and differs from `before`.
    fn reread(
        &self,
        wp: &WorkspacePath,
        before: Option<Digest>,
        expected: Digest,
    ) -> Result<Digest, EditError> {
        let (path, meta) = resolve_path(&self.root, wp)?;
        let Some(meta) = meta else {
            return Err(EditError::NotFound);
        };
        if !meta.is_file() {
            return Err(EditError::NotAFile);
        }
        let after = sha256(&read_capped(&path, meta.len(), EDIT_MAX_BYTES)?);
        if before == Some(after) {
            return Err(EditError::NoChange { sha256: after });
        }
        if after != expected {
            return Err(EditError::Verify {
                expected,
                found: after,
            });
        }
        Ok(after)
    }
}

/// How many lines `bytes` has, as `str::lines` counts them (a final line
/// without a newline counts; a trailing newline adds none).
fn line_count(bytes: &[u8]) -> usize {
    let nl = bytes.iter().filter(|&&b| b == b'\n').count();
    match bytes.last() {
        None => 0,
        Some(b'\n') => nl,
        Some(_) => nl + 1,
    }
}

/// Read at most `cap` bytes of `path` (`len` its metadata size, so an
/// oversize file is refused without opening it; the bounded read also
/// refuses a file that grew between the two).
fn read_capped(path: &Path, len: u64, cap: u64) -> Result<Vec<u8>, EditError> {
    if len > cap {
        return Err(EditError::TooLarge { len, cap });
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|f| f.take(cap + 1).read_to_end(&mut bytes))
        .map_err(EditError::from)?;
    if u64::try_from(bytes.len()).map_or(true, |n| n > cap) {
        return Err(EditError::TooLarge {
            len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            cap,
        });
    }
    Ok(bytes)
}

/// Build the zero-match error: the nearest line numbers (after CRLF→LF
/// normalisation of file and `old` — line numbers map 1:1 because
/// normalisation deletes no `\n`) and the CRLF-vs-LF hint of §4.9.
fn zero_matches(text: &str, old: &str) -> EditError {
    let norm = normalize_lf(text);
    let mut nearest: Vec<usize> = find_offsets(&norm, &normalize_lf(old))
        .iter()
        .map(|&o| line_of(&norm, o))
        .collect();
    nearest.truncate(NEAREST_MAX);
    let crlf_hint = text.contains("\r\n") && old.contains('\n') && !old.contains("\r\n");
    EditError::ZeroMatches { nearest, crlf_hint }
}

/// Byte offsets of the non-overlapping occurrences of `needle` in
/// `text`.
fn find_offsets(text: &str, needle: &str) -> Vec<usize> {
    text.match_indices(needle).map(|(o, _)| o).collect()
}

/// The 1-based line number of byte offset `off` (a char boundary, as
/// every match offset is).
fn line_of(text: &str, off: usize) -> usize {
    1 + text
        .as_bytes()
        .get(..off)
        .map_or(0, |p| p.iter().filter(|&&b| b == b'\n').count())
}

/// `s` with every `\r\n` reduced to `\n`.
fn normalize_lf(s: &str) -> String {
    if s.contains("\r\n") {
        s.replace("\r\n", "\n")
    } else {
        s.to_owned()
    }
}

/// Whether CRLF is the file's dominant line ending: at least one CRLF
/// and at least as many CRLFs as bare LFs.
fn crlf_dominant(s: &str) -> bool {
    let b = s.as_bytes();
    let lf = b.iter().filter(|&&x| x == b'\n').count();
    let crlf = b.windows(2).filter(|w| w == b"\r\n").count();
    let bare = lf - crlf;
    crlf > 0 && crlf >= bare
}

/// `s` with every bare LF turned into CRLF (existing CRLFs stay).
fn lf_to_crlf(s: &str) -> String {
    // `'\r'`/`'\n'` are ASCII, so char-level insertion is sound UTF-8.
    let mut out = String::with_capacity(s.len() + s.len() / 8);
    let mut prev = '\0';
    for ch in s.chars() {
        if ch == '\n' && prev != '\r' {
            out.push('\r');
        }
        out.push(ch);
        prev = ch;
    }
    out
}

/// Replace `old_len` bytes at each offset in `offsets` (ascending,
/// non-overlapping, in bounds — as match offsets are) with `new`.
fn splice(original: &[u8], offsets: &[usize], old_len: usize, new: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(original.len());
    let mut at = 0usize;
    for &o in offsets {
        if let Some(chunk) = original.get(at..o) {
            out.extend_from_slice(chunk);
        }
        out.extend_from_slice(new);
        at = o + old_len;
    }
    if let Some(chunk) = original.get(at..) {
        out.extend_from_slice(chunk);
    }
    out
}

/// Monotonic temp-file suffix, so concurrent edits never collide.
static TEMP_N: AtomicU64 = AtomicU64::new(0);

/// How many temp names [`atomic_write`] tries before giving up. A name
/// that already exists is never opened (it may be a planted symlink), so
/// a workspace that squats on every tried name makes the edit fail
/// closed, never write through.
const TEMP_TRIES: usize = 16;

/// Create a fresh temp file next to `target`, exclusively
/// (`O_CREAT | O_EXCL`): an existing name, a symlink included, is never
/// opened or followed. The name is predictable, and once H2 runs model
/// code the workspace may hold anything at it; this engine runs outside
/// the sandbox, so following a planted link would write outside the
/// workspace as the harness user.
fn create_temp(dir: &Path) -> io::Result<(PathBuf, File)> {
    for _ in 0..TEMP_TRIES {
        let tmp = dir.join(format!(
            ".rh-edit-{}-{}.tmp",
            std::process::id(),
            TEMP_N.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
        {
            Ok(f) => return Ok((tmp, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "every temp-file name tried already exists",
    ))
}

/// Write `bytes` to `target` atomically: a temp file created exclusively
/// in the SAME directory (same filesystem, so the rename is atomic),
/// given `perms` through its open handle when supplied, fsynced, then
/// renamed over the target. On any failure the temp file is removed and
/// the target is untouched. The directory is not fsynced — the tested
/// property is the rename's atomicity, not power-loss durability.
fn atomic_write(target: &Path, bytes: &[u8], perms: Option<fs::Permissions>) -> io::Result<()> {
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let (tmp, mut f) = create_temp(dir)?;
    let done = (|| -> io::Result<()> {
        f.write_all(bytes)?;
        if let Some(p) = perms {
            f.set_permissions(p)?;
        }
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, target)
    })();
    if done.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    done
}

// ---------------------------------------------------------------------------
// The edit tools as a provider (§4.8, H2b).
// ---------------------------------------------------------------------------

/// `harness.edit.replace`.
pub const REPLACE: &str = "harness.edit.replace";
/// `harness.edit.write`.
pub const WRITE: &str = "harness.edit.write";

/// The built-in edit tools, `harness.edit.replace` and `harness.edit.write`
/// (§4.8, §4.9), as a [`ToolProvider`] over one workspace: every call is a
/// `Journaled<Authorized<Call>>` (policy decided it, its intent is durable),
/// and every edit is anchored on the run's reads ([`InvokeCtx::reads`]).
///
/// The result is harness text about what changed (the path, the lines of
/// the matches, the line count, the digests), never the file's content:
/// hence `content: own` in the manifest. A verified edit carries an
/// [`EditRecord`]; the run journals it (`EditApplied`), records the after
/// digest as the file's latest read, and keeps its tree digest current. An
/// [`EditError::Unverified`] result is the one error after which the file
/// may have changed ([`code::UNVERIFIED`]).
#[derive(Debug)]
pub struct EditTools {
    ns: ProviderName,
    engine: EditEngine,
}

impl EditTools {
    /// The edit tools over the workspace at `root`, under the read tools'
    /// root rule (a real directory, never a symlink).
    pub fn new(root: &Path) -> Result<Self, RootRefused> {
        let ns = ProviderName::new(harness_manifest::BUILTIN_NAMESPACE)
            .map_err(|_| RootRefused::Io(io::Error::other("builtin namespace")))?;
        Ok(Self {
            ns,
            engine: EditEngine::new(root)?,
        })
    }

    /// The canonical workspace root.
    pub fn root(&self) -> &Path {
        self.engine.root()
    }

    fn replace(&self, args: &Value, reads: &ReadLog) -> (Out, Option<EditRecord>) {
        let (Some(path), Some(old), Some(new)) = (
            args.get("path").and_then(Value::as_str),
            args.get("old").and_then(Value::as_str),
            args.get("new").and_then(Value::as_str),
        ) else {
            return (
                err(code::BAD_ARGS, "path, old and new must be strings"),
                None,
            );
        };
        let count = match args.get("count") {
            None => 1,
            Some(v) => match v.as_u64().and_then(|n| usize::try_from(n).ok()) {
                Some(n) => n,
                None => {
                    return (
                        err(code::BAD_ARGS, "count must be a positive integer"),
                        None,
                    )
                }
            },
        };
        let req = ReplaceReq {
            path: path.to_owned(),
            old: old.to_owned(),
            new: new.to_owned(),
            count,
        };
        match self.engine.replace(&req, reads) {
            Ok(a) => {
                let at: Vec<String> = a.lines.iter().map(usize::to_string).collect();
                let text = format!(
                    "edited {}: replaced {} match{} at line{} {}; the file now has {} line{}; sha256 {} (was {})\n",
                    a.path.as_str(),
                    a.lines.len(),
                    if a.lines.len() == 1 { "" } else { "es" },
                    if a.lines.len() == 1 { "" } else { "s" },
                    at.join(", "),
                    a.lines_after,
                    if a.lines_after == 1 { "" } else { "s" },
                    a.after,
                    a.before.map_or_else(|| "absent".to_owned(), |d| d.to_string()),
                );
                (ok(text), Some(record(&a)))
            }
            Err(e) => (edit_err(&e), None),
        }
    }

    fn write(&self, args: &Value, reads: &ReadLog) -> (Out, Option<EditRecord>) {
        let (Some(path), Some(content)) = (
            args.get("path").and_then(Value::as_str),
            args.get("content").and_then(Value::as_str),
        ) else {
            return (
                err(code::BAD_ARGS, "path and content must be strings"),
                None,
            );
        };
        let req = WriteReq {
            path: path.to_owned(),
            content: content.to_owned(),
        };
        match self.engine.write(&req, reads) {
            Ok(a) => {
                let text = match a.before {
                    None => format!(
                        "created {}: {} line{}; sha256 {}\n",
                        a.path.as_str(),
                        a.lines_after,
                        if a.lines_after == 1 { "" } else { "s" },
                        a.after
                    ),
                    Some(before) => format!(
                        "rewrote {}: {} line{}; sha256 {} (was {})\n",
                        a.path.as_str(),
                        a.lines_after,
                        if a.lines_after == 1 { "" } else { "s" },
                        a.after,
                        before
                    ),
                };
                (ok(text), Some(record(&a)))
            }
            Err(e) => (edit_err(&e), None),
        }
    }
}

fn record(a: &Applied) -> EditRecord {
    EditRecord {
        path: a.path.clone(),
        before: a.before,
        after: a.after,
    }
}

/// An edit error as the model sees it: an error code and harness words
/// (the only runtime values are line numbers, counts and caps).
fn edit_err(e: &EditError) -> Out {
    let lines = |v: &[usize]| {
        v.iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    match e {
        EditError::PathRefused(p) => err(code::PATH_REFUSED, &format!("the path is refused: {p}")),
        EditError::BadCount => err(code::BAD_ARGS, "count must be at least 1"),
        EditError::EmptyOld => err(code::BAD_ARGS, "old is empty"),
        EditError::NoOp => err(code::NO_OP, "the edit would not change the file"),
        EditError::NotFound => err(
            code::NOT_FOUND,
            "no such file or directory (a new file's directory must already exist)",
        ),
        EditError::Symlink => err(
            code::SYMLINK,
            "a path component is a symlink; symlinks are never followed",
        ),
        EditError::NotAFile => err(code::NOT_A_FILE, "not a regular file"),
        EditError::NotUtf8 => err(code::NOT_TEXT, "not UTF-8 text"),
        EditError::TooLarge { .. } => err(code::TOO_LARGE, "the file is larger than the edit cap"),
        EditError::TooManyLines { lines, cap } => err(
            code::LINE_CAP,
            &format!(
                "the file has {lines} lines; a whole-file rewrite is limited to {cap}; use harness.edit.replace"
            ),
        ),
        EditError::Stale(StaleRead::NeverRead) => {
            err(code::STALE_READ, "file not read in this run; read it first")
        }
        EditError::Stale(StaleRead::Changed) => {
            err(code::STALE_READ, "file changed since read; re-read first")
        }
        EditError::ZeroMatches { nearest, crlf_hint } => {
            let mut m = String::from(
                "old was not found in the file; it must match exactly, whitespace and line endings included",
            );
            if !nearest.is_empty() {
                m.push_str(&format!(
                    "; the same text with other line endings is at line(s) {}",
                    lines(nearest)
                ));
            }
            if *crlf_hint {
                m.push_str("; the file uses CRLF line endings and old uses LF");
            }
            err(code::NO_MATCH, &m)
        }
        EditError::MatchCount {
            expected,
            found,
            lines: at,
        } => err(
            code::MATCH_COUNT,
            &format!(
                "old matches {found} times (line(s) {}), not {expected}; include more of the surrounding text so it matches once, or set count",
                lines(at)
            ),
        ),
        EditError::NoChange { .. } => err(
            code::NO_OP,
            "the edit would not change the file (after its line endings were converted)",
        ),
        EditError::Verify { .. } => err(
            code::UNVERIFIED,
            "the edit was written but the file does not hold the expected content",
        ),
        EditError::Io(_) => err(code::IO, "the file system refused the operation"),
        EditError::Unverified(_) => err(
            code::UNVERIFIED,
            "the edit was written but could not be verified; the file may have changed",
        ),
    }
}

impl ToolProvider for EditTools {
    fn namespace(&self) -> &ProviderName {
        &self.ns
    }

    fn serves(&self, capability: &str) -> bool {
        matches!(capability, REPLACE | WRITE)
    }

    fn invoke(
        &mut self,
        call: Journaled<Authorized<Call>>,
        ctx: &InvokeCtx<'_>,
    ) -> Result<ToolResult, ToolError> {
        let c = call.call().call();
        let cap = c.capability.as_str();
        if !self.serves(cap) {
            return Ok(refused(cap, RefusalKind::UnknownCapability));
        }
        if Instant::now() >= ctx.deadline {
            return Ok(refused(cap, RefusalKind::DeadlinePassed));
        }
        let (out, edit) = if cap == REPLACE {
            self.replace(&c.args, ctx.reads)
        } else {
            self.write(&c.args, ctx.reads)
        };
        let mut res = finish(cap, out);
        res.edit = edit;
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_are_byte_offsets_and_non_overlapping() {
        assert_eq!(find_offsets("aaa", "aa"), vec![0]);
        assert_eq!(find_offsets("aXbXc", "X"), vec![1, 3]);
        assert_eq!(find_offsets("abc", "z"), Vec::<usize>::new());
    }

    #[test]
    fn line_numbers_are_one_based() {
        let t = "l1\nl2\nl3";
        assert_eq!(line_of(t, 0), 1);
        assert_eq!(line_of(t, 4), 2);
        assert_eq!(line_of(t, 7), 3);
    }

    #[test]
    fn normalisation_only_strips_the_cr() {
        assert_eq!(normalize_lf("a\r\nb\r\n"), "a\nb\n");
        assert_eq!(normalize_lf("a\nb"), "a\nb");
        assert_eq!(normalize_lf("a\rb"), "a\rb");
    }

    #[test]
    fn crlf_dominance_needs_a_crlf_majority_or_tie() {
        assert!(crlf_dominant("a\r\nb\r\n"));
        assert!(crlf_dominant("a\r\nb\n")); // a tie goes to CRLF
        assert!(!crlf_dominant("a\nb\n"));
        assert!(!crlf_dominant("no endings"));
        assert!(!crlf_dominant(""));
    }

    #[test]
    fn only_bare_lfs_become_crlf() {
        assert_eq!(lf_to_crlf("a\nb"), "a\r\nb");
        assert_eq!(lf_to_crlf("a\r\nb"), "a\r\nb");
        assert_eq!(lf_to_crlf("\n"), "\r\n");
        assert_eq!(lf_to_crlf(""), "");
    }

    #[test]
    fn splice_replaces_every_offset() {
        assert_eq!(splice(b"aXbXc", &[1, 3], 1, b"YY"), b"aYYbYYc".to_vec());
        assert_eq!(splice(b"abc", &[], 1, b"Z"), b"abc".to_vec());
    }

    #[test]
    fn zero_matches_names_nearest_lines_after_normalisation() {
        let text = "one\r\ntwo\r\nthree\r\n";
        match zero_matches(text, "two\nthree") {
            EditError::ZeroMatches { nearest, crlf_hint } => {
                assert_eq!(nearest, vec![2]);
                assert!(crlf_hint);
            }
            other => panic!("wrong error: {other:?}"),
        }
        // Normalising `old` (CRLF) lets it match an LF file, line 3.
        match zero_matches("a\nb\nc\n", "b\r\nc") {
            EditError::ZeroMatches { nearest, crlf_hint } => {
                assert_eq!(nearest, vec![2]);
                assert!(!crlf_hint);
            }
            other => panic!("wrong error: {other:?}"),
        }
        // Nothing close: no nearest lines, no hint.
        match zero_matches(text, "four") {
            EditError::ZeroMatches { nearest, crlf_hint } => {
                assert!(nearest.is_empty());
                assert!(!crlf_hint);
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn a_read_log_round_trips() {
        let mut log = ReadLog::default();
        assert_eq!(
            log.check("f", Digest::from_bytes([0; 32])),
            Err(StaleRead::NeverRead)
        );
        let d = sha256(b"x");
        log.record("f", d);
        assert_eq!(log.get("f"), Some(d));
        assert_eq!(log.check("f", d), Ok(()));
        assert_eq!(log.check("f", sha256(b"y")), Err(StaleRead::Changed));
    }
}
