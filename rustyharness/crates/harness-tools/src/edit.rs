//! The in-process edit engine (design §4.9, D9): exact search/replace
//! and whole-file write, over one workspace, with the same confinement
//! walk as the read tools (INV-30 in-process half: every path is
//! resolved from the workspace root one component at a time with
//! `symlink_metadata`; a symlink at ANY component is refused, never
//! followed), and [`EditTools`], which serves it to the model as
//! `harness.edit.replace` and `harness.edit.write` (H2b) and
//! `harness.edit.multi` (H2e) through the [`ToolProvider`] seam: a call
//! reaches the engine only as a `Journaled<Authorized<Call>>`, anchored on
//! the run's reads.
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
//! and `old` uses LF, a hint saying so, and, for a multi-line `old`, where
//! it stops matching ([`PartialMatch`], H2e: line numbers, never text); a
//! wrong number of matches reports the match line numbers. Either way the
//! file is untouched.
//!
//! **Multi (H2e, `harness.edit.multi`).** Up to [`MULTI_MAX_EDITS`]
//! replacements in one file, all or none: each `old` must be non-empty,
//! differ from its `new` and match exactly once in the text as the
//! replacements before it left it; the first that fails is named and
//! nothing is written. The result is written once and verified like a
//! replace, so it is one edit in the journal (one `EditApplied`).
//!
//! **Write (§4.8 `harness.edit.write`).** The §4.8 schema is one
//! capability with no mode flag, so the regime follows existence: a
//! free path is created (H2f: with the directories it needs) — the "CREATING: must
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

use harness_core::diff::{self, DEFAULT_CONTEXT, DEFAULT_MAX_LINES};
use harness_core::display::{sanitize_for_terminal, DisplayMode};
use harness_core::{sha256, Digest};
use harness_journal::Journaled;
use harness_manifest::ProviderName;
use harness_policy::{workspace_path, Authorized, Call, WorkspacePath};
use serde_json::Value;

use crate::builtin::{
    canonical_root, code, err, finish, ok, refused, resolve as resolve_path, Out, ResolveErr,
    RootRefused,
};
use crate::protected::Protected;
use crate::provider::{
    EditRecord, Image, InvokeCtx, RefusalKind, ToolError, ToolProvider, ToolResult,
};

/// Largest file the edit engine reads or writes — the same cap as
/// `fs.read` ([`READ_MAX_BYTES`](crate::builtin::READ_MAX_BYTES)), so a
/// file the harness can read whole is one it can edit.
pub const EDIT_MAX_BYTES: u64 = crate::builtin::READ_MAX_BYTES;
/// Largest file the pre-image store keeps (P-22, 2 MiB): an edit to a
/// file whose prior bytes are over this is refused, fail closed, so
/// every applied edit keeps a restorable pre-image (a file the read
/// tools can show whole but the store cannot keep is one the harness
/// does not edit).
pub const PRE_IMAGE_MAX_BYTES: u64 = 2 * 1024 * 1024;
/// Most lines a whole-file overwrite may target (§4.8: 400).
pub const WRITE_OVERWRITE_MAX_LINES: usize = 400;
/// Most "nearest match" line numbers a [`EditError::ZeroMatches`] lists.
const NEAREST_MAX: usize = 10;
/// Most lines of `old` a zero-match diagnosis compares.
const PARTIAL_MAX_OLD_LINES: usize = 400;
/// Most file lines a zero-match diagnosis tries as a start.
const PARTIAL_MAX_STARTS: usize = 1000;

/// Where a multi-line `old` that matches nowhere stops matching (H2e):
/// the longest run of its leading lines that matches the file line by line
/// (its first line as the end of a file line, its middle lines whole, its
/// last line as the start of one), earliest first. The zero-match message
/// gives these numbers, never the text: a local model sent the same
/// `old` three times, missing one doc-comment line in its middle, and was
/// told only that it matched nowhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartialMatch {
    /// The file line (1-based) where `old`'s first line matches.
    pub at: usize,
    /// How many of `old`'s leading lines match from there: at least one,
    /// fewer than all.
    pub matched: usize,
    /// The file ends before `old`'s next line.
    pub file_ended: bool,
}

/// [`PartialMatch`] of `old` in `text`, both LF-normalised; `None` for a
/// one-line `old`, one longer than [`PARTIAL_MAX_OLD_LINES`], or one whose
/// first line matches no line's end.
fn partial_match(text: &str, old: &str) -> Option<PartialMatch> {
    let want: Vec<&str> = old.split('\n').collect();
    if want.len() < 2 || want.len() > PARTIAL_MAX_OLD_LINES {
        return None;
    }
    let mut file: Vec<&str> = text.split('\n').collect();
    // A final newline ends the last line; it does not start another.
    if text.ends_with('\n') {
        file.pop();
    }
    let first = want.first()?;
    let mut best: Option<PartialMatch> = None;
    let starts = file
        .iter()
        .enumerate()
        .filter(|(_, l)| l.ends_with(first))
        .take(PARTIAL_MAX_STARTS);
    for (i, _) in starts {
        let mut k = 1;
        while let (Some(w), Some(f)) = (want.get(k), file.get(i + k)) {
            let same = if k + 1 == want.len() {
                f.starts_with(w)
            } else {
                f == w
            };
            if !same {
                break;
            }
            k += 1;
        }
        if k < want.len() && best.is_none_or(|b| k > b.matched) {
            best = Some(PartialMatch {
                at: i + 1,
                matched: k,
                file_ended: i + k >= file.len(),
            });
        }
    }
    best
}

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

/// Most replacements one `harness.edit.multi` call makes (H2e; the schema
/// subset has no `maxItems`, so the engine bounds it).
pub const MULTI_MAX_EDITS: usize = 20;

/// One replacement of a [`MultiReq`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replacement {
    /// The byte-exact text to replace; non-empty, and matching exactly once
    /// in the file as the replacements before it left it.
    pub old: String,
    /// The replacement.
    pub new: String,
}

/// Several exact replacements in one file, all or none (H2e,
/// `harness.edit.multi`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiReq {
    /// Workspace path of the file.
    pub path: String,
    /// The replacements, applied in order.
    pub edits: Vec<Replacement>,
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
/// (§4.9 step 5). `before` is `None` for a create. The images (P-22)
/// carry the file's whole bytes before and after, for the pre-image
/// store: the run keeps them as content-addressed blobs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The workspace path edited.
    pub path: WorkspacePath,
    /// The file's SHA-256 before the edit (`None` for a create).
    pub before: Option<Digest>,
    /// The file's SHA-256 after the edit.
    pub after: Digest,
    /// The file's bytes before the edit, with their digest (`None` for a
    /// create; P-22). Its digest is [`Applied::before`].
    pub before_image: Option<Image>,
    /// The file's verified bytes after the edit, with their digest
    /// [`Applied::after`] (P-22).
    pub after_image: Image,
    /// A replace's matches: the 1-based line of each in the file before
    /// the edit. Empty for a write.
    pub lines: Vec<usize>,
    /// How many lines the file has after the edit.
    pub lines_after: usize,
    /// The directories a write created for a new file (H2f), as paths
    /// relative to the workspace root, shallowest first. Empty otherwise.
    pub dirs: Vec<String>,
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
    /// The file's prior bytes are over the pre-image cap (P-22): the
    /// pre-image store could not keep them, so the edit is refused, fail
    /// closed, with the file untouched.
    #[error("{len} bytes is over the {cap}-byte pre-image cap")]
    PreImageTooLarge {
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
    /// file uses CRLF line endings while `old` uses LF. `partial` says
    /// where a multi-line `old` stops matching (H2e).
    #[error("`old` matches nowhere; nearest line-ending-normalised match line(s): {nearest:?}; the file uses CRLF while `old` uses LF: {crlf_hint}; partial: {partial:?}")]
    ZeroMatches {
        /// Nearest normalised-match line numbers, ascending.
        nearest: Vec<usize>,
        /// The file is CRLF and `old` uses bare LF.
        crlf_hint: bool,
        /// Where the longest run of `old`'s leading lines matches the file.
        partial: Option<PartialMatch>,
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
    /// A directory a new file needs cannot be made (H2f): a component of its
    /// path is a file, not a directory.
    #[error("a component of the path is a file, not a directory")]
    NotADirectory,
    /// A new file's path needs more new directories than one write makes
    /// (H2f).
    #[error("the path needs more than {WRITE_MAX_NEW_DIRS} new directories")]
    TooManyDirs,
    /// The new content was renamed over the file, but the re-read after it
    /// (§4.9 step 4) did not find the expected splice: the inner error says
    /// what it found. The only variant after which the workspace may have
    /// changed (H2b: the run treats it so).
    #[error("the edit was written but not verified: {0}")]
    Unverified(Box<EditError>),
    /// A `harness.edit.multi` call with no replacements, or more than
    /// [`MULTI_MAX_EDITS`] (H2e).
    #[error("{count} edits; one call makes 1 to {max}")]
    EditCount {
        /// The number given.
        count: usize,
        /// The most allowed.
        max: usize,
    },
    /// Replacement `index` (1-based) of `total` failed (H2e): nothing was
    /// written. `error` is what failed (empty or no-op `old`, no match,
    /// several matches), checked against the file as the replacements
    /// before it left it.
    #[error("edit {index} of {total}: {error}")]
    Item {
        /// Which replacement, 1-based.
        index: usize,
        /// How many the call made.
        total: usize,
        /// Why it failed.
        error: Box<EditError>,
    },
    /// The path is protected (P-29, ROADMAP §4.3): it matches the build's
    /// deny globs or the task's declared list, and the edit tools do not
    /// edit it. Reported before anything is read, created or written;
    /// `pattern` names the glob that matched.
    #[error("the path is protected ({pattern})")]
    Protected {
        /// The glob that matched.
        pattern: String,
    },
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
    protected: Protected,
}

impl EditEngine {
    /// An edit engine over the workspace at `root`, which must be a
    /// real directory (not a symlink) — the same root rule as the read
    /// tools. The root is canonicalised once here. Protected paths
    /// start empty; the driver installs the run's list with
    /// [`EditEngine::with_protected`].
    pub fn new(root: &Path) -> Result<Self, RootRefused> {
        Ok(Self {
            root: canonical_root(root)?,
            protected: Protected::empty(),
        })
    }

    /// The same engine with a protected-path deny list (P-29): every
    /// edit to a path matching one is refused before anything is read
    /// or written.
    #[must_use]
    pub fn with_protected(mut self, protected: Protected) -> Self {
        self.protected = protected;
        self
    }

    /// The canonical workspace root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The P-29 floor: a workspace path matching a deny glob is refused
    /// before anything else looks at it.
    fn guard(&self, wp: &WorkspacePath) -> Result<(), EditError> {
        match self.protected.matched(wp.as_str()) {
            None => Ok(()),
            Some(pattern) => Err(EditError::Protected {
                pattern: pattern.to_owned(),
            }),
        }
    }

    /// Exact search/replace (§4.9): `old` must match `count` times,
    /// byte-exactly, in a file read this run whose content still
    /// hashes to the recorded digest. On success the file holds the
    /// spliced content (atomic apply, line endings preserved) and the
    /// re-read digest equals the expected splice.
    pub fn replace(&self, req: &ReplaceReq, reads: &ReadLog) -> Result<Applied, EditError> {
        let wp = workspace_path(&req.path).map_err(EditError::PathRefused)?;
        self.guard(&wp)?;
        check_replace_args(req)?;
        let (path, meta) = resolve_path(&self.root, &wp)?;
        let Some(meta) = meta else {
            return Err(EditError::NotFound);
        };
        if !meta.is_file() {
            return Err(EditError::NotAFile);
        }
        check_pre_image(meta.len())?;
        let bytes = read_capped(&path, meta.len(), EDIT_MAX_BYTES)?;
        let before = sha256(&bytes);
        reads.check(wp.as_str(), before).map_err(EditError::from)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| EditError::NotUtf8)?;
        let (spliced, lines) = plan_replace(req, text, &bytes)?;
        let expected = sha256(&spliced);
        let lines_after = line_count(&spliced);
        atomic_write(&path, &spliced, Some(meta.permissions()))?;
        let mut applied = self.verify(
            &wp,
            Some(Image {
                sha256: before,
                bytes,
            }),
            expected,
            spliced,
            lines_after,
        )?;
        applied.lines = lines;
        Ok(applied)
    }

    /// Several exact replacements in one file, all or none (H2e,
    /// `harness.edit.multi`). The file is anchored on the run's reads like
    /// every edit (§2.3); the replacements are applied in order to the text
    /// in memory, and each `old` must be non-empty, differ from its `new`,
    /// and match exactly once in the text as the replacements before it
    /// left it. The first that fails is named ([`EditError::Item`]) and
    /// nothing is written. Then the result is written once, atomically, and
    /// verified, exactly as [`EditEngine::replace`] does; `lines` holds the
    /// line of each match, in the text each replacement was matched in.
    pub fn multi(&self, req: &MultiReq, reads: &ReadLog) -> Result<Applied, EditError> {
        let wp = workspace_path(&req.path).map_err(EditError::PathRefused)?;
        self.guard(&wp)?;
        let total = req.edits.len();
        if total == 0 || total > MULTI_MAX_EDITS {
            return Err(EditError::EditCount {
                count: total,
                max: MULTI_MAX_EDITS,
            });
        }
        check_multi_edits(req)?;
        let (path, meta) = resolve_path(&self.root, &wp)?;
        let Some(meta) = meta else {
            return Err(EditError::NotFound);
        };
        if !meta.is_file() {
            return Err(EditError::NotAFile);
        }
        check_pre_image(meta.len())?;
        let bytes = read_capped(&path, meta.len(), EDIT_MAX_BYTES)?;
        let before = sha256(&bytes);
        reads.check(wp.as_str(), before).map_err(EditError::from)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| EditError::NotUtf8)?;
        let (spliced, lines) = plan_multi(req, text, &bytes)?;
        let expected = sha256(&spliced);
        let lines_after = line_count(&spliced);
        atomic_write(&path, &spliced, Some(meta.permissions()))?;
        let mut applied = self.verify(
            &wp,
            Some(Image {
                sha256: before,
                bytes,
            }),
            expected,
            spliced,
            lines_after,
        )?;
        applied.lines = lines;
        Ok(applied)
    }

    /// Whole-file write (§4.8 `harness.edit.write`). A free path is
    /// created, with the directories it needs (H2f: [`create_parents`], at
    /// most [`WRITE_MAX_NEW_DIRS`], no link followed); an existing file is
    /// overwritten, which requires a fresh read of at most
    /// [`WRITE_OVERWRITE_MAX_LINES`] lines.
    pub fn write(&self, req: &WriteReq, reads: &ReadLog) -> Result<Applied, EditError> {
        let wp = workspace_path(&req.path).map_err(EditError::PathRefused)?;
        self.guard(&wp)?;
        let mut made: Vec<String> = Vec::new();
        let (path, meta) = match resolve_path(&self.root, &wp) {
            Ok(x) => x,
            // A directory on the way is missing (H2f): a new file makes
            // it. The size is checked first, so nothing is created for a
            // write that would be refused anyway.
            Err(ResolveErr::NotFound) => {
                check_cap(req.content.as_bytes())?;
                made = create_parents(&self.root, &wp)?;
                match resolve_path(&self.root, &wp) {
                    Ok(x) => x,
                    Err(e) => {
                        remove_dirs(&self.root, &made);
                        return Err(e.into());
                    }
                }
            }
            Err(e) => return Err(e.into()),
        };
        match meta {
            // Create: nothing at the path, so nothing to be stale
            // about ("CREATING: must not exist", §4.8, holds by
            // construction).
            None => {
                let content = req.content.as_bytes();
                check_cap(content)?;
                let expected = sha256(content);
                if let Err(e) = atomic_write(&path, content, None) {
                    remove_dirs(&self.root, &made);
                    return Err(e.into());
                }
                let mut applied =
                    self.verify(&wp, None, expected, content.to_vec(), line_count(content))?;
                applied.dirs = made;
                Ok(applied)
            }
            Some(meta) => {
                if !meta.is_file() {
                    return Err(EditError::NotAFile);
                }
                check_pre_image(meta.len())?;
                let bytes = read_capped(&path, meta.len(), EDIT_MAX_BYTES)?;
                let before = sha256(&bytes);
                reads.check(wp.as_str(), before).map_err(EditError::from)?;
                let text = std::str::from_utf8(&bytes).map_err(|_| EditError::NotUtf8)?;
                let out_bytes = plan_write_overwrite(req, text, &bytes)?;
                let expected = sha256(&out_bytes);
                let lines_after = line_count(&out_bytes);
                atomic_write(&path, &out_bytes, Some(meta.permissions()))?;
                self.verify(
                    &wp,
                    Some(Image {
                        sha256: before,
                        bytes,
                    }),
                    expected,
                    out_bytes,
                    lines_after,
                )
            }
        }
    }

    /// Re-read the file (§4.9 step 4): the digest must equal the
    /// expected splice and, when there was a before, differ from it. The
    /// re-read takes the same component-by-component walk and the same
    /// cap as every other access, so a target that became a symlink (or
    /// grew past the cap) after the rename fails the edit instead of
    /// being followed. The images travel with the result (P-22): they
    /// were captured before anything was written.
    fn verify(
        &self,
        wp: &WorkspacePath,
        before_image: Option<Image>,
        expected: Digest,
        after_bytes: Vec<u8>,
        lines_after: usize,
    ) -> Result<Applied, EditError> {
        self.reread(wp, before_image.as_ref().map(|i| i.sha256), expected)
            .map(|after| Applied {
                path: wp.clone(),
                before: before_image.as_ref().map(|i| i.sha256),
                after,
                before_image,
                after_image: Image {
                    sha256: after,
                    bytes: after_bytes,
                },
                lines: Vec::new(),
                lines_after,
                dirs: Vec::new(),
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

/// Most directories one `harness.edit.write` may create for a new file (H2f).
pub const WRITE_MAX_NEW_DIRS: usize = 8;

/// Create the directories a new file's path needs (H2f), one at a time and
/// never through a link: each existing component is looked at without being
/// followed and must be a real directory (a symlink is refused, as
/// everywhere), each missing one is made with a single `mkdir` and looked at
/// again, so a link planted in its place is refused too. At most
/// [`WRITE_MAX_NEW_DIRS`]. Returns the paths made, relative to the
/// workspace root, shallowest first; when it fails, what it made is removed
/// again. The path was checked lexically ([`WorkspacePath`]: no `..`, no
/// absolute path, no empty component), so the walk stays below `root`.
fn create_parents(root: &Path, wp: &WorkspacePath) -> Result<Vec<String>, EditError> {
    let comps: Vec<&str> = wp.components().collect();
    let parents = comps.len().saturating_sub(1);
    let mut made: Vec<String> = Vec::new();
    let mut cur = root.to_path_buf();
    let fail = |made: &[String], e: EditError| {
        remove_dirs(root, made);
        Err(e)
    };
    for (i, c) in comps.iter().take(parents).enumerate() {
        cur.push(c);
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => return fail(&made, EditError::Symlink),
            Ok(m) if m.is_dir() => continue,
            Ok(_) => return fail(&made, EditError::NotADirectory),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return fail(&made, EditError::Io(e)),
        }
        if made.len() >= WRITE_MAX_NEW_DIRS {
            return fail(&made, EditError::TooManyDirs);
        }
        match fs::create_dir(&cur) {
            Ok(()) => made.push(
                comps
                    .iter()
                    .take(i + 1)
                    .copied()
                    .collect::<Vec<_>>()
                    .join("/"),
            ),
            Err(e) => return fail(&made, EditError::Io(e)),
        }
        // What is there now must be the directory just made.
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
            Ok(m) if m.file_type().is_symlink() => return fail(&made, EditError::Symlink),
            Ok(_) => return fail(&made, EditError::NotADirectory),
            Err(e) => return fail(&made, EditError::Io(e)),
        }
    }
    Ok(made)
}

/// Remove directories [`create_parents`] made, deepest first. Best effort:
/// `remove_dir` removes an empty directory only, so it never removes
/// anything the edit did not make.
fn remove_dirs(root: &Path, made: &[String]) {
    for rel in made.iter().rev() {
        let _ = fs::remove_dir(root.join(rel));
    }
}

// ---------------------------------------------------------------------------
// In-memory planning (P-16): the pure half of every edit, shared by the
// apply path and `EditTools::preview`, so a preview can only show what an
// apply would write.
// ---------------------------------------------------------------------------

/// The argument-sanity checks apply and preview both run before the file
/// is resolved: `count` at least 1, non-empty `old`, `old` differing
/// from `new`.
fn check_replace_args(req: &ReplaceReq) -> Result<(), EditError> {
    if req.count == 0 {
        return Err(EditError::BadCount);
    }
    if req.old.is_empty() {
        return Err(EditError::EmptyOld);
    }
    if req.old == req.new {
        return Err(EditError::NoOp);
    }
    Ok(())
}

/// The per-item checks apply and preview both run for a multi edit
/// before the file is resolved: every `old` non-empty and differing
/// from its `new`, the first failure named ([`EditError::Item`]).
fn check_multi_edits(req: &MultiReq) -> Result<(), EditError> {
    let total = req.edits.len();
    let item = |index: usize, error: EditError| EditError::Item {
        index,
        total,
        error: Box::new(error),
    };
    for (i, e) in req.edits.iter().enumerate() {
        if e.old.is_empty() {
            return Err(item(i + 1, EditError::EmptyOld));
        }
        if e.old == e.new {
            return Err(item(i + 1, EditError::NoOp));
        }
    }
    Ok(())
}

/// The in-memory half of an exact replace ([`EditEngine::replace`] and
/// [`EditTools::preview`]): match checks, line-ending conversion and the
/// splice, no I/O. Returns the spliced bytes and the 1-based line of each
/// match in `text` (the file before the edit).
fn plan_replace(
    req: &ReplaceReq,
    text: &str,
    bytes: &[u8],
) -> Result<(Vec<u8>, Vec<usize>), EditError> {
    let offsets = find_offsets(text, &req.old);
    if offsets.is_empty() {
        return Err(zero_matches(text, &req.old));
    }
    let lines: Vec<usize> = offsets.iter().map(|&o| line_of(text, o)).collect();
    if offsets.len() != req.count {
        return Err(EditError::MatchCount {
            expected: req.count,
            found: offsets.len(),
            lines,
        });
    }
    // The replacement takes the file's dominant line endings.
    let new = if crlf_dominant(text) {
        lf_to_crlf(&req.new)
    } else {
        req.new.clone()
    };
    let spliced = splice(bytes, &offsets, req.old.len(), new.as_bytes());
    if spliced == bytes {
        // Cannot happen with `old != new` unless line-ending
        // conversion maps `new` back onto `old`; still refused as
        // the silent no-op it is.
        return Err(EditError::NoChange {
            sha256: sha256(&spliced),
        });
    }
    // An edit that would leave a file the harness cannot read back is
    // refused before anything is written (H2e).
    check_cap(&spliced)?;
    Ok((spliced, lines))
}

/// The in-memory half of a multi edit ([`EditEngine::multi`] and
/// [`EditTools::preview`]): every replacement in order against the text
/// as the ones before it left it, all or none, no I/O. Returns the
/// spliced bytes and the 1-based line of each match, in the text each
/// replacement was matched in. The `old`-emptiness and no-op checks are
/// the caller's ([`check_multi_edits`]): they run before the file is
/// even resolved.
fn plan_multi(
    req: &MultiReq,
    text: &str,
    bytes: &[u8],
) -> Result<(Vec<u8>, Vec<usize>), EditError> {
    let total = req.edits.len();
    let item = |index: usize, error: EditError| EditError::Item {
        index,
        total,
        error: Box::new(error),
    };
    // Every replacement takes the file's dominant line endings, as the
    // file was before the call.
    let crlf = crlf_dominant(text);
    let mut cur = text.to_owned();
    let mut lines = Vec::with_capacity(total);
    for (i, e) in req.edits.iter().enumerate() {
        let offsets = find_offsets(&cur, &e.old);
        if offsets.is_empty() {
            return Err(item(i + 1, zero_matches(&cur, &e.old)));
        }
        if offsets.len() != 1 {
            return Err(item(
                i + 1,
                EditError::MatchCount {
                    expected: 1,
                    found: offsets.len(),
                    lines: offsets.iter().map(|&o| line_of(&cur, o)).collect(),
                },
            ));
        }
        lines.extend(offsets.iter().map(|&o| line_of(&cur, o)));
        let new = if crlf {
            lf_to_crlf(&e.new)
        } else {
            e.new.clone()
        };
        // A match starts and ends on character boundaries, so the
        // splice of UTF-8 into UTF-8 is UTF-8.
        let spliced = splice(cur.as_bytes(), &offsets, e.old.len(), new.as_bytes());
        cur = String::from_utf8(spliced).map_err(|_| EditError::NotUtf8)?;
        if cur.len() as u64 > EDIT_MAX_BYTES {
            return Err(item(
                i + 1,
                EditError::TooLarge {
                    len: cur.len() as u64,
                    cap: EDIT_MAX_BYTES,
                },
            ));
        }
    }
    let spliced = cur.into_bytes();
    if spliced == bytes {
        // The replacements undo each other.
        return Err(EditError::NoChange {
            sha256: sha256(&spliced),
        });
    }
    Ok((spliced, lines))
}

/// The in-memory half of a whole-file overwrite (the overwriting regime
/// of [`EditEngine::write`] and [`EditTools::preview`]): the line cap,
/// the file's dominant line endings and the no-op check, no I/O.
/// Returns the bytes the file would hold.
fn plan_write_overwrite(req: &WriteReq, text: &str, bytes: &[u8]) -> Result<Vec<u8>, EditError> {
    let lines = text.lines().count();
    if lines > WRITE_OVERWRITE_MAX_LINES {
        return Err(EditError::TooManyLines {
            lines,
            cap: WRITE_OVERWRITE_MAX_LINES,
        });
    }
    // The body takes the file's dominant line endings; a body that only
    // differs in line endings is still a no-op once converted.
    let out = if crlf_dominant(text) {
        lf_to_crlf(&req.content)
    } else {
        req.content.clone()
    };
    if out.as_bytes() == bytes {
        return Err(EditError::NoOp);
    }
    Ok(out.into_bytes())
}

/// Whether a new file's directories COULD be made, without making them:
/// the preview's read-only mirror of [`create_parents`] (H2f) — each
/// existing component must be a real directory (a symlink is refused,
/// as everywhere), and at most [`WRITE_MAX_NEW_DIRS`] may be missing.
fn check_new_parents(root: &Path, wp: &WorkspacePath) -> Result<(), EditError> {
    let comps: Vec<&str> = wp.components().collect();
    let parents = comps.len().saturating_sub(1);
    let mut missing = 0usize;
    let mut cur = root.to_path_buf();
    for c in comps.iter().take(parents) {
        cur.push(c);
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => return Err(EditError::Symlink),
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(EditError::NotADirectory),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                missing += 1;
                if missing > WRITE_MAX_NEW_DIRS {
                    return Err(EditError::TooManyDirs);
                }
            }
            Err(e) => return Err(EditError::Io(e)),
        }
    }
    Ok(())
}

/// Parse a `harness.edit.replace` call's arguments; the [`Out`] is the
/// BAD_ARGS result the tool call would return.
fn parse_replace_args(args: &Value) -> Result<ReplaceReq, Out> {
    let (Some(path), Some(old), Some(new)) = (
        args.get("path").and_then(Value::as_str),
        args.get("old").and_then(Value::as_str),
        args.get("new").and_then(Value::as_str),
    ) else {
        return Err(err(code::BAD_ARGS, "path, old and new must be strings"));
    };
    let count = match args.get("count") {
        None => 1,
        Some(v) => match v.as_u64().and_then(|n| usize::try_from(n).ok()) {
            Some(n) => n,
            None => return Err(err(code::BAD_ARGS, "count must be a positive integer")),
        },
    };
    Ok(ReplaceReq {
        path: path.to_owned(),
        old: old.to_owned(),
        new: new.to_owned(),
        count,
    })
}

/// Parse a `harness.edit.multi` call's arguments; the [`Out`] is the
/// BAD_ARGS result the tool call would return.
fn parse_multi_args(args: &Value) -> Result<MultiReq, Out> {
    let (Some(path), Some(list)) = (
        args.get("path").and_then(Value::as_str),
        args.get("edits").and_then(Value::as_array),
    ) else {
        return Err(err(
            code::BAD_ARGS,
            "path must be a string and edits a list of {old, new} strings",
        ));
    };
    let mut edits = Vec::with_capacity(list.len());
    for e in list {
        let (Some(old), Some(new)) = (
            e.get("old").and_then(Value::as_str),
            e.get("new").and_then(Value::as_str),
        ) else {
            return Err(err(
                code::BAD_ARGS,
                "path must be a string and edits a list of {old, new} strings",
            ));
        };
        edits.push(Replacement {
            old: old.to_owned(),
            new: new.to_owned(),
        });
    }
    Ok(MultiReq {
        path: path.to_owned(),
        edits,
    })
}

/// Parse a `harness.edit.write` call's arguments; the [`Out`] is the
/// BAD_ARGS result the tool call would return.
fn parse_write_args(args: &Value) -> Result<WriteReq, Out> {
    let (Some(path), Some(content)) = (
        args.get("path").and_then(Value::as_str),
        args.get("content").and_then(Value::as_str),
    ) else {
        return Err(err(code::BAD_ARGS, "path and content must be strings"));
    };
    Ok(WriteReq {
        path: path.to_owned(),
        content: content.to_owned(),
    })
}

/// The message of a parse [`Out`], without the tool's `error: ` prefix.
fn bad_args_text(out: &Out) -> String {
    out.text
        .strip_prefix("error: ")
        .unwrap_or(&out.text)
        .to_owned()
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

/// Refuse content over the edit cap before it is written: the re-read of
/// the verification could not read it back.
fn check_cap(content: &[u8]) -> Result<(), EditError> {
    let len = u64::try_from(content.len()).unwrap_or(u64::MAX);
    if len > EDIT_MAX_BYTES {
        return Err(EditError::TooLarge {
            len,
            cap: EDIT_MAX_BYTES,
        });
    }
    Ok(())
}

/// Refuse an edit to a file whose prior bytes are over the pre-image cap
/// (P-22), before anything is read into a plan or written: the pre-image
/// store could not keep them, so the edit is refused, fail closed. `len`
/// is the file's metadata size, so an oversize file is refused without
/// being read.
fn check_pre_image(len: u64) -> Result<(), EditError> {
    if len > PRE_IMAGE_MAX_BYTES {
        return Err(EditError::PreImageTooLarge {
            len,
            cap: PRE_IMAGE_MAX_BYTES,
        });
    }
    Ok(())
}

/// Read at most `cap` bytes of `path` (`len` its metadata size, so an
/// oversize file is refused without opening it; the bounded read also
/// refuses a file that grew between the two). Crate-visible for the
/// restore primitive's read-back.
pub(crate) fn read_capped(path: &Path, len: u64, cap: u64) -> Result<Vec<u8>, EditError> {
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
    // Only when line endings are not the explanation.
    let partial = if nearest.is_empty() {
        partial_match(&norm, &normalize_lf(old))
    } else {
        None
    };
    EditError::ZeroMatches {
        nearest,
        crlf_hint,
        partial,
    }
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
/// Crate-visible for the restore primitive (P-22), which applies the
/// same way.
pub(crate) fn atomic_write(
    target: &Path,
    bytes: &[u8],
    perms: Option<fs::Permissions>,
) -> io::Result<()> {
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
/// `harness.edit.multi` (H2e).
pub const MULTI: &str = "harness.edit.multi";

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

    /// The same tools with a protected-path deny list (P-29): edits and
    /// previews of matching paths are refused with
    /// [`EditError::Protected`] before anything is touched.
    #[must_use]
    pub fn with_protected(self, protected: Protected) -> Self {
        Self {
            ns: self.ns,
            engine: self.engine.with_protected(protected),
        }
    }

    /// The canonical workspace root.
    pub fn root(&self) -> &Path {
        self.engine.root()
    }

    fn replace(&self, args: &Value, reads: &ReadLog) -> (Out, Option<EditRecord>) {
        let req = match parse_replace_args(args) {
            Ok(req) => req,
            Err(out) => return (out, None),
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

    fn multi(&self, args: &Value, reads: &ReadLog) -> (Out, Option<EditRecord>) {
        let req = match parse_multi_args(args) {
            Ok(req) => req,
            Err(out) => return (out, None),
        };
        match self.engine.multi(&req, reads) {
            Ok(a) => {
                let at: Vec<String> = a.lines.iter().map(usize::to_string).collect();
                let text = format!(
                    "edited {}: applied {} edit{} in order, at line{} {} (each line as the edits before it left the file); the file now has {} line{}; sha256 {} (was {})\n",
                    a.path.as_str(),
                    a.lines.len(),
                    if a.lines.len() == 1 { "" } else { "s" },
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
        let req = match parse_write_args(args) {
            Ok(req) => req,
            Err(out) => return (out, None),
        };
        match self.engine.write(&req, reads) {
            Ok(a) => {
                let text = match a.before {
                    None => format!(
                        "created {}: {} line{}; sha256 {}{}\n",
                        a.path.as_str(),
                        a.lines_after,
                        if a.lines_after == 1 { "" } else { "s" },
                        a.after,
                        if a.dirs.is_empty() {
                            String::new()
                        } else {
                            format!(
                                "; created director{} {}",
                                if a.dirs.len() == 1 { "y" } else { "ies" },
                                a.dirs.join(", ")
                            )
                        }
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

    /// The diff a call would produce (P-16): the edit is planned in
    /// memory exactly as the apply path plans it — the same argument
    /// parse, the same confinement walk, the same stale-read check
    /// ([`ReadLog`]), the same planners — and rendered as a bounded
    /// unified diff of the whole file, sanitised for a terminal like
    /// every harness block. Nothing is written, nothing is journalled,
    /// no directory is created; a refusal is the apply path's own
    /// pre-write refusal ([`PreviewRefused`]).
    ///
    /// Deterministic: no clock (a preview is not a provider invoke), no
    /// randomness — the same call, file and read log give the same text.
    pub fn preview(&self, call: &Call, reads: &ReadLog) -> Result<String, PreviewRefused> {
        match call.capability.as_str() {
            REPLACE => {
                let req = parse_replace_args(&call.args)
                    .map_err(|out| PreviewRefused::BadArgs(bad_args_text(&out)))?;
                self.preview_replace(&req, reads)
            }
            MULTI => {
                let req = parse_multi_args(&call.args)
                    .map_err(|out| PreviewRefused::BadArgs(bad_args_text(&out)))?;
                self.preview_multi(&req, reads)
            }
            WRITE => {
                let req = parse_write_args(&call.args)
                    .map_err(|out| PreviewRefused::BadArgs(bad_args_text(&out)))?;
                self.preview_write(&req, reads)
            }
            other => Err(PreviewRefused::NotEdit(other.to_owned())),
        }
    }

    fn preview_replace(&self, req: &ReplaceReq, reads: &ReadLog) -> Result<String, PreviewRefused> {
        let wp = workspace_path(&req.path).map_err(EditError::PathRefused)?;
        self.engine.guard(&wp)?;
        check_replace_args(req)?;
        let (path, meta) = resolve_path(&self.engine.root, &wp).map_err(EditError::from)?;
        let Some(meta) = meta else {
            return Err(EditError::NotFound.into());
        };
        if !meta.is_file() {
            return Err(EditError::NotAFile.into());
        }
        check_pre_image(meta.len())?;
        let bytes = read_capped(&path, meta.len(), EDIT_MAX_BYTES)?;
        let before = sha256(&bytes);
        reads.check(wp.as_str(), before).map_err(EditError::from)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| EditError::NotUtf8)?;
        let (spliced, _) = plan_replace(req, text, &bytes)?;
        let new_text = String::from_utf8(spliced).map_err(|_| EditError::NotUtf8)?;
        Ok(render_diff(wp.as_str(), false, text, &new_text))
    }

    fn preview_multi(&self, req: &MultiReq, reads: &ReadLog) -> Result<String, PreviewRefused> {
        let wp = workspace_path(&req.path).map_err(EditError::PathRefused)?;
        self.engine.guard(&wp)?;
        let total = req.edits.len();
        if total == 0 || total > MULTI_MAX_EDITS {
            return Err(EditError::EditCount {
                count: total,
                max: MULTI_MAX_EDITS,
            }
            .into());
        }
        check_multi_edits(req)?;
        let (path, meta) = resolve_path(&self.engine.root, &wp).map_err(EditError::from)?;
        let Some(meta) = meta else {
            return Err(EditError::NotFound.into());
        };
        if !meta.is_file() {
            return Err(EditError::NotAFile.into());
        }
        check_pre_image(meta.len())?;
        let bytes = read_capped(&path, meta.len(), EDIT_MAX_BYTES)?;
        let before = sha256(&bytes);
        reads.check(wp.as_str(), before).map_err(EditError::from)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| EditError::NotUtf8)?;
        let (spliced, _) = plan_multi(req, text, &bytes)?;
        let new_text = String::from_utf8(spliced).map_err(|_| EditError::NotUtf8)?;
        Ok(render_diff(wp.as_str(), false, text, &new_text))
    }

    fn preview_write(&self, req: &WriteReq, reads: &ReadLog) -> Result<String, PreviewRefused> {
        let wp = workspace_path(&req.path).map_err(EditError::PathRefused)?;
        self.engine.guard(&wp)?;
        let (path, meta) = match resolve_path(&self.engine.root, &wp) {
            Ok(x) => x,
            // A directory on the way is missing (H2f): apply would make
            // it; the preview only checks that it could, making nothing.
            Err(ResolveErr::NotFound) => {
                check_cap(req.content.as_bytes())?;
                check_new_parents(&self.engine.root, &wp)?;
                return Ok(render_diff(wp.as_str(), true, "", &req.content));
            }
            Err(e) => return Err(EditError::from(e).into()),
        };
        match meta {
            // Create: nothing at the path, so nothing to be stale about
            // ("CREATING: must not exist", §4.8, holds by construction).
            // Apply would make the directories; the preview only checks
            // that it could, making nothing.
            None => {
                check_cap(req.content.as_bytes())?;
                check_new_parents(&self.engine.root, &wp)?;
                Ok(render_diff(wp.as_str(), true, "", &req.content))
            }
            Some(meta) => {
                if !meta.is_file() {
                    return Err(EditError::NotAFile.into());
                }
                check_pre_image(meta.len())?;
                let bytes = read_capped(&path, meta.len(), EDIT_MAX_BYTES)?;
                let before = sha256(&bytes);
                reads.check(wp.as_str(), before).map_err(EditError::from)?;
                let text = std::str::from_utf8(&bytes).map_err(|_| EditError::NotUtf8)?;
                let out = plan_write_overwrite(req, text, &bytes)?;
                let new_text = String::from_utf8(out).map_err(|_| EditError::NotUtf8)?;
                Ok(render_diff(wp.as_str(), false, text, &new_text))
            }
        }
    }
}

/// Why a preview was refused (P-16). Never mutates the workspace: every
/// variant is reported before anything would have been written, and the
/// [`EditError`] cases are exactly the apply path's pre-write refusals.
#[derive(Debug, thiserror::Error)]
pub enum PreviewRefused {
    /// The call is not one of the edit capabilities this previews.
    #[error("not an edit capability: {0}")]
    NotEdit(String),
    /// The arguments fail the same parse the tool call would.
    #[error("bad arguments: {0}")]
    BadArgs(String),
    /// The edit is refused, exactly as apply would refuse it.
    #[error(transparent)]
    Edit(#[from] EditError),
}

/// The preview text for a planned edit: file headers, then the bounded
/// unified diff ([`harness_core::diff::unified`] at its defaults:
/// context 3, at most 200 lines, a `[N lines cut]` marker past that),
/// sanitised for a terminal as a block (P-04) — control bytes, hidden
/// characters and oversize output all rendered harmlessly. A create
/// diffs against the empty file and is headed `--- /dev/null`.
fn render_diff(path: &str, is_create: bool, old: &str, new: &str) -> String {
    let mut s = String::new();
    if is_create {
        s.push_str("--- /dev/null\n");
    } else {
        s.push_str(&format!("--- a/{path}\n"));
    }
    s.push_str(&format!("+++ b/{path}\n"));
    s.push_str(&diff::unified(old, new, DEFAULT_CONTEXT, DEFAULT_MAX_LINES));
    sanitize_for_terminal(&s, DisplayMode::Block)
}

fn record(a: &Applied) -> EditRecord {
    EditRecord {
        path: a.path.clone(),
        before: a.before,
        after: a.after,
        before_image: a.before_image.clone(),
        after_image: a.after_image.clone(),
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
        EditError::PathRefused(p) => err(
            code::PATH_REFUSED,
            &format!("the path is refused: {p}; write it relative to the workspace root, like src/lib.rs"),
        ),
        EditError::Protected { pattern } => err(
            code::PROTECTED,
            &format!("the path is protected ({pattern}); this harness does not edit it, so leave it alone and say so in the submit note"),
        ),
        EditError::BadCount => err(code::BAD_ARGS, "count must be at least 1; leave count out for one replacement"),
        EditError::EmptyOld => err(code::BAD_ARGS, "old is empty; give the exact text to replace, copied from the file (to make a new file use harness.edit.write)"),
        EditError::NoOp => err(code::NO_OP, "the edit would not change the file: old and new are the same text; change new, or submit if the file is already right"),
        EditError::NotFound => err(
            code::NOT_FOUND,
            "no such file or directory: find the path with harness.fs.glob or harness.fs.list, then repeat; to create a new file use harness.edit.write",
        ),
        EditError::Symlink => err(
            code::SYMLINK,
            "a path component is a symlink; symlinks are never followed: use the real path, or leave that file alone and say so in the submit note",
        ),
        EditError::NotADirectory => err(
            code::NOT_A_FILE,
            "a component of the path is a file, not a directory: nothing was created; choose a path whose directories are directories",
        ),
        EditError::TooManyDirs => err(
            code::BAD_ARGS,
            &format!(
                "the path needs more than {WRITE_MAX_NEW_DIRS} new directories; nothing was created: use a path with fewer new directories, or an existing directory"
            ),
        ),
        EditError::NotAFile => err(code::NOT_A_FILE, "not a regular file: name a file, not a directory (harness.fs.list shows what a directory holds)"),
        EditError::NotUtf8 => err(code::NOT_TEXT, "not UTF-8 text: this tool edits text files only; leave the file alone"),
        EditError::TooLarge { .. } => err(code::TOO_LARGE, "the file is larger than the edit cap: this tool cannot edit it; leave it alone and say so in the submit note"),
        EditError::PreImageTooLarge { .. } => err(code::TOO_LARGE, "the file is larger than the pre-image cap: an edit keeps the file's prior bytes so it can be undone, and these would not fit; leave the file alone and say so in the submit note"),
        EditError::TooManyLines { lines, cap } => err(
            code::LINE_CAP,
            &format!(
                "the file has {lines} lines; a whole-file rewrite is limited to {cap}; use harness.edit.replace"
            ),
        ),
        EditError::Stale(StaleRead::NeverRead) => {
            err(code::STALE_READ, "file not read in this run; read it first: call harness.fs.read on this path (a search does not count as a read), then repeat this call")
        }
        EditError::Stale(StaleRead::Changed) => {
            err(code::STALE_READ, "file changed since read; re-read first: call harness.fs.read on this path, then copy old from the fresh text and repeat this call")
        }
        EditError::ZeroMatches {
            nearest,
            crlf_hint,
            partial,
        } => {
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
            // Numbers only: where old stops matching, never its text.
            if let Some(p) = partial {
                let next = p.matched + 1;
                if p.file_ended {
                    m.push_str(&format!(
                        "; old's first {} line(s) match the file from line {}, and the file ends before old's line {next}",
                        p.matched, p.at
                    ));
                } else {
                    m.push_str(&format!(
                        "; old's first {} line(s) match the file from line {}, and old's line {next} differs from the file's line {}: read the file there and copy old from it",
                        p.matched,
                        p.at,
                        p.at + p.matched
                    ));
                }
            }
            if partial.is_none() {
                m.push_str("; read the file with harness.fs.read at the place you mean and copy old from that text");
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
            "the edit would not change the file (after its line endings were converted): the file already holds this text; submit if that is what the task asks",
        ),
        EditError::Verify { .. } => err(
            code::UNVERIFIED,
            "the edit was written but the file does not hold the expected content: read the file with harness.fs.read to see what it holds now before any other edit",
        ),
        EditError::Io(_) => err(code::IO, "the file system refused the operation: check the path with harness.fs.list; if it keeps failing, leave the file and say so in the submit note"),
        EditError::Unverified(_) => err(
            code::UNVERIFIED,
            "the edit was written but could not be verified; the file may have changed: read the file with harness.fs.read to see what it holds now before any other edit",
        ),
        EditError::EditCount { count, max } => err(
            code::BAD_ARGS,
            &format!("edits has {count} item(s); one call makes 1 to {max} edits: split the edits into calls of at most {max}"),
        ),
        // The failing replacement's own error, named, with its code (H2e).
        EditError::Item {
            index,
            total,
            error,
        } => {
            let inner = edit_err(error);
            let msg = inner.text.strip_prefix("error: ").unwrap_or(&inner.text);
            let code = match inner.status {
                crate::provider::ToolStatus::Error { code } => code,
                _ => code::BAD_ARGS,
            };
            let when = if *index > 1 {
                " (checked against the file as the edits before it left it)"
            } else {
                ""
            };
            err(
                code,
                &format!("edit {index} of {total}{when}: {msg}; nothing was written"),
            )
        }
    }
}

impl ToolProvider for EditTools {
    fn namespace(&self) -> &ProviderName {
        &self.ns
    }

    fn serves(&self, capability: &str) -> bool {
        matches!(capability, REPLACE | WRITE | MULTI)
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
        let (out, edit) = match cap {
            REPLACE => self.replace(&c.args, ctx.reads),
            MULTI => self.multi(&c.args, ctx.reads),
            _ => self.write(&c.args, ctx.reads),
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
            EditError::ZeroMatches {
                nearest, crlf_hint, ..
            } => {
                assert_eq!(nearest, vec![2]);
                assert!(crlf_hint);
            }
            other => panic!("wrong error: {other:?}"),
        }
        // Normalising `old` (CRLF) lets it match an LF file, line 3.
        match zero_matches("a\nb\nc\n", "b\r\nc") {
            EditError::ZeroMatches {
                nearest, crlf_hint, ..
            } => {
                assert_eq!(nearest, vec![2]);
                assert!(!crlf_hint);
            }
            other => panic!("wrong error: {other:?}"),
        }
        // Nothing close: no nearest lines, no hint.
        match zero_matches(text, "four") {
            EditError::ZeroMatches {
                nearest, crlf_hint, ..
            } => {
                assert!(nearest.is_empty());
                assert!(!crlf_hint);
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    // H2e: where a multi-line `old` stops matching, in line numbers.
    #[test]
    fn h2e_zero_matches_say_where_a_multi_line_old_stops_matching() {
        let partial = |text: &str, old: &str| match zero_matches(text, old) {
            EditError::ZeroMatches { partial, .. } => partial,
            other => panic!("wrong error: {other:?}"),
        };
        // The local model's edit: one doc-comment line missing in the middle.
        let units = "//! Units.\n\n/// cm per foot.\npub const CM_PER_FOOT: f64 = 30.48;\n\n/// cm to ft.\npub fn cm_to_ft(cm: f64) -> f64 {\n    cm / 3.048\n}\n\n/// ft to cm.\npub fn ft_to_cm(ft: f64) -> f64 {\n    ft * CM_PER_FOOT\n}\n";
        let old = "pub fn cm_to_ft(cm: f64) -> f64 {\n    cm / 3.048\n}\n\npub fn ft_to_cm(ft: f64) -> f64 {";
        assert_eq!(
            partial(units, old),
            Some(PartialMatch {
                at: 7,
                matched: 4,
                file_ended: false
            })
        );
        // `old` may start and end inside a line; the longest run wins, and
        // the earliest of equal runs.
        assert_eq!(
            partial("x = 1;\ny = 2;\nx = 1;\ny = 2;\nz = 3;\n", "1;\ny = 2;\nq"),
            Some(PartialMatch {
                at: 1,
                matched: 2,
                file_ended: false
            })
        );
        assert_eq!(
            partial("a\nb\nc\nb\nc\nd\n", "b\nc\nd\ne"),
            Some(PartialMatch {
                at: 4,
                matched: 3,
                file_ended: true
            })
        );
        // Past the file's end (a final newline starts no line).
        assert_eq!(
            partial("a\nb\n", "a\nb\nc"),
            Some(PartialMatch {
                at: 1,
                matched: 2,
                file_ended: true
            })
        );
        // One line, a first line found nowhere, or a line-ending cause: none.
        assert_eq!(partial(units, "cm / 3.049"), None);
        assert_eq!(partial(units, "nowhere\n    cm / 3.048"), None);
        assert_eq!(partial("one\r\ntwo\r\nthree\r\n", "two\nthree"), None);
        // The message gives numbers and harness words, never old's text.
        let t = edit_err(&zero_matches(units, old)).text;
        assert!(
            t.contains("old's first 4 line(s) match the file from line 7, and old's line 5 differs from the file's line 11: read the file there and copy old from it"),
            "{t}"
        );
        assert!(!t.contains("ft_to_cm") && !t.contains("3.048"), "{t}");
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

    // --- P-16: the preview ---

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rh-preview-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    // The preview's diff is what applying the call really produces: the
    // same call, run for real in a scratch workspace, leaves exactly the
    // file the diff shows.
    #[test]
    fn preview_replace_matches_applied_result() {
        let ws = scratch("replace-matches-apply");
        let tools = EditTools::new(&ws).expect("tools");
        let file = ws.join("notes.txt");
        std::fs::write(&file, "alpha\nbeta\ngamma\n").expect("seed");
        let mut reads = ReadLog::default();
        reads.record("notes.txt", sha256(b"alpha\nbeta\ngamma\n"));
        let call = Call {
            capability: REPLACE.to_owned(),
            args: serde_json::json!({ "path": "notes.txt", "old": "beta", "new": "BETA" }),
        };
        let shown = tools.preview(&call, &reads).expect("preview");
        let applied = EditEngine::new(&ws)
            .expect("engine")
            .replace(
                &ReplaceReq {
                    path: "notes.txt".into(),
                    old: "beta".into(),
                    new: "BETA".into(),
                    count: 1,
                },
                &reads,
            )
            .expect("apply");
        assert_eq!(
            applied.after,
            sha256(&std::fs::read(&file).expect("read back"))
        );
        assert_eq!(
            shown,
            "--- a/notes.txt\n+++ b/notes.txt\n@@ -1,3 +1,3 @@\n alpha\n-beta\n+BETA\n gamma\n"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn preview_does_not_modify_file() {
        let ws = scratch("no-modify");
        let tools = EditTools::new(&ws).expect("tools");
        let file = ws.join("notes.txt");
        std::fs::write(&file, "keep\nthis\n").expect("seed");
        let before = std::fs::read(&file).expect("read");
        let mut reads = ReadLog::default();
        reads.record("notes.txt", sha256(&before));
        let call = Call {
            capability: REPLACE.to_owned(),
            args: serde_json::json!({ "path": "notes.txt", "old": "keep", "new": "changed" }),
        };
        let shown = tools.preview(&call, &reads).expect("preview");
        assert!(shown.contains("+changed"), "{shown}");
        assert_eq!(
            std::fs::read(&file).expect("read"),
            before,
            "the file is untouched"
        );
        // No temp file left behind either: the directory holds the file
        // and nothing else.
        assert_eq!(std::fs::read_dir(&ws).expect("dir").count(), 1);
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn preview_refuses_stale_read_like_apply() {
        let ws = scratch("stale");
        let tools = EditTools::new(&ws).expect("tools");
        let engine = EditEngine::new(&ws).expect("engine");
        std::fs::write(ws.join("notes.txt"), "one\ntwo\n").expect("seed");
        let req = ReplaceReq {
            path: "notes.txt".into(),
            old: "one".into(),
            new: "ONE".into(),
            count: 1,
        };
        let call = Call {
            capability: REPLACE.to_owned(),
            args: serde_json::json!({ "path": "notes.txt", "old": "one", "new": "ONE" }),
        };
        // Never read: both paths refuse, with the same error.
        assert!(matches!(
            engine.replace(&req, &ReadLog::default()),
            Err(EditError::Stale(StaleRead::NeverRead))
        ));
        assert!(matches!(
            tools.preview(&call, &ReadLog::default()),
            Err(PreviewRefused::Edit(EditError::Stale(StaleRead::NeverRead)))
        ));
        // A digest that does not match the file: the same on both paths.
        let mut stale = ReadLog::default();
        stale.record("notes.txt", sha256(b"old content"));
        assert!(matches!(
            engine.replace(&req, &stale),
            Err(EditError::Stale(StaleRead::Changed))
        ));
        assert!(matches!(
            tools.preview(&call, &stale),
            Err(PreviewRefused::Edit(EditError::Stale(StaleRead::Changed)))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // A create previews against /dev/null and makes nothing; the
    // create-time refusals are the apply path's own.
    #[test]
    fn preview_write_create_heads_dev_null_and_refuses_like_apply() {
        let ws = scratch("write-create");
        let tools = EditTools::new(&ws).expect("tools");
        let call = Call {
            capability: WRITE.to_owned(),
            args: serde_json::json!({ "path": "new/dir/file.txt", "content": "h1\nh2\n" }),
        };
        let shown = tools.preview(&call, &ReadLog::default()).expect("preview");
        assert_eq!(
            shown,
            "--- /dev/null\n+++ b/new/dir/file.txt\n@@ -0,0 +1,2 @@\n+h1\n+h2\n"
        );
        assert!(!ws.join("new").exists(), "a preview creates nothing");
        // More new directories than one write makes: refused, unmade.
        let call = Call {
            capability: WRITE.to_owned(),
            args: serde_json::json!({ "path": "a/b/c/d/e/f/g/h/i/deep.txt", "content": "x\n" }),
        };
        assert!(matches!(
            tools.preview(&call, &ReadLog::default()),
            Err(PreviewRefused::Edit(EditError::TooManyDirs))
        ));
        // A file where a directory belongs: resolve itself fails with
        // ENOTDIR before any create regime, and preview reports exactly
        // what apply reports.
        std::fs::write(ws.join("blocker"), "x").expect("seed");
        let call = Call {
            capability: WRITE.to_owned(),
            args: serde_json::json!({ "path": "blocker/file.txt", "content": "x\n" }),
        };
        let res = tools.preview(&call, &ReadLog::default());
        let apply = EditEngine::new(&ws)
            .expect("engine")
            .write(
                &WriteReq {
                    path: "blocker/file.txt".into(),
                    content: "x\n".into(),
                },
                &ReadLog::default(),
            )
            .err();
        match (&res, &apply) {
            (Err(PreviewRefused::Edit(EditError::Io(e))), Some(EditError::Io(a))) => {
                assert_eq!(e.kind(), a.kind(), "preview and apply agree");
                assert_eq!(e.kind(), std::io::ErrorKind::NotADirectory);
            }
            _ => panic!("wrong results: preview {res:?}, apply {apply:?}"),
        }
        assert!(!ws.join("blocker").exists() || ws.join("blocker").is_file());
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn preview_refuses_a_non_edit_call() {
        let ws = scratch("not-edit");
        let tools = EditTools::new(&ws).expect("tools");
        let call = Call {
            capability: "harness.fs.read".to_owned(),
            args: serde_json::json!({}),
        };
        assert!(matches!(
            tools.preview(&call, &ReadLog::default()),
            Err(PreviewRefused::NotEdit(cap)) if cap == "harness.fs.read"
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // --- P-29: protected paths ---

    // The default deny globs (no task list) refuse every edit route into
    // `.git` — replace, multi, write-overwrite and write-create, apply
    // and preview alike — before anything is read or created; a
    // non-protected file still edits.
    #[test]
    fn edit_into_dot_git_refused() {
        let ws = scratch("protected-git");
        let protected = crate::protected::Protected::new(&[]).expect("defaults compile");
        let tools = EditTools::new(&ws)
            .expect("tools")
            .with_protected(protected.clone());
        let engine = EditEngine::new(&ws)
            .expect("engine")
            .with_protected(protected);
        std::fs::create_dir_all(ws.join(".git")).expect("git dir");
        std::fs::write(ws.join(".git/config"), "[core]\n").expect("seed");
        std::fs::write(ws.join("README.md"), "hello\n").expect("seed");
        let mut reads = ReadLog::default();
        reads.record(".git/config", sha256(b"[core]\n"));
        reads.record("README.md", sha256(b"hello\n"));

        let refused_protected = |r: &Result<Applied, EditError>| match r {
            Err(EditError::Protected { pattern }) => assert_eq!(pattern, ".git/**"),
            other => panic!("expected Protected refusal, got {other:?}"),
        };
        refused_protected(&engine.replace(
            &ReplaceReq {
                path: ".git/config".into(),
                old: "[core]".into(),
                new: "[hacked]".into(),
                count: 1,
            },
            &reads,
        ));
        refused_protected(&engine.write(
            &WriteReq {
                path: ".git/config".into(),
                content: "x\n".into(),
            },
            &reads,
        ));
        // A create inside `.git` makes nothing, not even directories.
        refused_protected(&engine.write(
            &WriteReq {
                path: ".git/hooks/x".into(),
                content: "y\n".into(),
            },
            &ReadLog::default(),
        ));
        assert!(!ws.join(".git/hooks").exists(), "nothing created");
        refused_protected(&engine.multi(
            &MultiReq {
                path: ".git/config".into(),
                edits: vec![Replacement {
                    old: "[core]".into(),
                    new: "[m]".into(),
                }],
            },
            &reads,
        ));

        // The previews refuse exactly like apply.
        let protected_preview = |r: Result<String, PreviewRefused>| match r {
            Err(PreviewRefused::Edit(EditError::Protected { pattern })) => {
                assert_eq!(pattern, ".git/**")
            }
            other => panic!("expected Protected refusal, got {other:?}"),
        };
        protected_preview(tools.preview(
            &Call {
                capability: REPLACE.to_owned(),
                args: serde_json::json!({"path": ".git/config", "old": "[core]", "new": "z"}),
            },
            &reads,
        ));
        protected_preview(tools.preview(
            &Call {
                capability: MULTI.to_owned(),
                args: serde_json::json!({"path": ".git/config", "edits": [{"old": "[core]", "new": "z"}]}),
            },
            &reads,
        ));
        protected_preview(tools.preview(
            &Call {
                capability: WRITE.to_owned(),
                args: serde_json::json!({"path": ".git/hooks/y", "content": "z\n"}),
            },
            &ReadLog::default(),
        ));
        assert!(!ws.join(".git/hooks").exists(), "a preview creates nothing");

        // The file is unchanged, byte for byte.
        assert_eq!(
            std::fs::read_to_string(ws.join(".git/config")).expect("read back"),
            "[core]\n"
        );

        // The same engine still edits a non-protected file.
        let applied = engine
            .replace(
                &ReplaceReq {
                    path: "README.md".into(),
                    old: "hello".into(),
                    new: "HELLO".into(),
                    count: 1,
                },
                &reads,
            )
            .expect("non-protected edit goes through");
        assert_eq!(applied.after, sha256(b"HELLO\n"));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // --- P-22: the pre-image store ---

    // A verified edit carries the file's images (P-22): the bytes before
    // (with their digest) and the verified bytes after, so the run can
    // keep both as content-addressed blobs.
    #[test]
    fn applied_carries_pre_and_post_images() {
        let ws = scratch("p22-images");
        std::fs::write(ws.join("f.txt"), b"alpha\nbeta\n").expect("seed");
        let engine = EditEngine::new(&ws).expect("engine");
        let mut reads = ReadLog::default();
        reads.record("f.txt", sha256(b"alpha\nbeta\n"));
        let applied = engine
            .replace(
                &ReplaceReq {
                    path: "f.txt".into(),
                    old: "beta".into(),
                    new: "delta".into(),
                    count: 1,
                },
                &reads,
            )
            .expect("edit");
        assert_eq!(applied.before, Some(sha256(b"alpha\nbeta\n")));
        assert_eq!(
            applied.before_image.as_ref().expect("pre-image").bytes,
            b"alpha\nbeta\n".to_vec()
        );
        assert_eq!(
            applied.before_image.as_ref().expect("pre-image").sha256,
            sha256(b"alpha\nbeta\n")
        );
        assert_eq!(applied.after, sha256(b"alpha\ndelta\n"));
        assert_eq!(applied.after_image.bytes, b"alpha\ndelta\n".to_vec());
        assert_eq!(applied.after_image.sha256, applied.after);
        // A create carries no pre-image, and its post-image is the body.
        let applied = engine
            .write(
                &WriteReq {
                    path: "new.txt".into(),
                    content: "fresh\n".into(),
                },
                &ReadLog::default(),
            )
            .expect("create");
        assert!(applied.before.is_none() && applied.before_image.is_none());
        assert_eq!(applied.after_image.bytes, b"fresh\n".to_vec());
        let _ = std::fs::remove_dir_all(&ws);
    }

    // The pre-image cap (P-22): a file whose prior bytes are over 2 MiB is
    // refused, fail closed, before anything is read into a plan or written
    // — by apply and preview alike, for every edit route — with the file
    // untouched. A file of exactly the cap still edits.
    #[test]
    fn pre_image_over_cap_refuses_edit() {
        let ws = scratch("p22-over-cap");
        let over = PRE_IMAGE_MAX_BYTES + 1;
        std::fs::write(ws.join("big.txt"), vec![b'a'; over as usize]).expect("seed");
        // The edge file is at the cap and carries one unique needle (its
        // last `ab`): an edit must still go through at exactly the cap.
        let mut edge = vec![b'a'; PRE_IMAGE_MAX_BYTES as usize];
        edge[PRE_IMAGE_MAX_BYTES as usize - 1] = b'b';
        std::fs::write(ws.join("edge.txt"), &edge).expect("seed");
        let engine = EditEngine::new(&ws).expect("engine");
        let mut reads = ReadLog::default();
        reads.record("big.txt", sha256(&vec![b'a'; over as usize]));
        reads.record("edge.txt", sha256(&edge));

        let over_req = ReplaceReq {
            path: "big.txt".into(),
            old: "a".into(),
            new: "b".into(),
            count: 1,
        };
        match engine.replace(&over_req, &reads) {
            Err(EditError::PreImageTooLarge { len, cap }) => {
                assert_eq!(len, over);
                assert_eq!(cap, PRE_IMAGE_MAX_BYTES);
            }
            other => panic!("expected PreImageTooLarge, got {other:?}"),
        }
        // Multi and write-overwrite refuse the same way.
        assert!(matches!(
            engine.multi(
                &MultiReq {
                    path: "big.txt".into(),
                    edits: vec![Replacement {
                        old: "a".into(),
                        new: "b".into(),
                    }],
                },
                &reads,
            ),
            Err(EditError::PreImageTooLarge { .. })
        ));
        assert!(matches!(
            engine.write(
                &WriteReq {
                    path: "big.txt".into(),
                    content: "small\n".into(),
                },
                &reads,
            ),
            Err(EditError::PreImageTooLarge { .. })
        ));
        // The file is untouched, byte for byte.
        assert_eq!(
            std::fs::metadata(ws.join("big.txt")).expect("meta").len(),
            over
        );

        // The preview refuses exactly like apply.
        let tools = EditTools::new(&ws).expect("tools");
        assert!(matches!(
            tools.preview(
                &Call {
                    capability: REPLACE.to_owned(),
                    args: serde_json::json!({
                        "path": "big.txt", "old": "a", "new": "b", "count": 1
                    }),
                },
                &reads,
            ),
            Err(PreviewRefused::Edit(EditError::PreImageTooLarge { .. }))
        ));
        // A file of exactly the cap still edits (the unique `ab`).
        let applied = engine
            .replace(
                &ReplaceReq {
                    path: "edge.txt".into(),
                    old: "ab".into(),
                    new: "ba".into(),
                    count: 1,
                },
                &reads,
            )
            .expect("at-cap edit goes through");
        assert_eq!(
            applied
                .before_image
                .as_ref()
                .expect("pre-image")
                .bytes
                .len() as u64,
            PRE_IMAGE_MAX_BYTES
        );
        let _ = std::fs::remove_dir_all(&ws);
    }
}
