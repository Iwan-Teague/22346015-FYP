//! The P-25 edit script and file operations: `harness.edit.patch` (a
//! `*** Begin Patch` script across several files, all or none),
//! `harness.edit.delete` and `harness.edit.move`, served by [`PatchTools`]
//! through the same [`ToolProvider`] seam as the edit tools of §4.9.
//!
//! Every op runs inside the same rules as the edit engine: a lexically
//! checked [`WorkspacePath`], the confined component-by-component walk
//! (a symlink at any component is refused, never followed), the P-29
//! protected-path guard, the §2.3 stale-read anchor (the file must have
//! been read this run and still hash to it; a delete or a move's source
//! *forgets* the read, so a later edit needs a fresh one), the edit and
//! pre-image caps, and the atomic apply with a verified re-read (the
//! file must hold exactly the planned bytes, or the op fails — the one
//! failure class after which the workspace may have changed,
//! [`PatchError::Unverified`]).
//!
//! **The patch format.** Strictly parsed: the first line is
//! `*** Begin Patch`, the last is `*** End Patch`, and between them
//! sections, each headed `*** Add File: <path>`, `*** Update File:
//! <path>` or `*** Delete File: <path>`. An Add's following lines are
//! the new file's content (they may be empty); an Update's following
//! lines are one hunk of ` ` context, `-` removed and `+` added lines
//! (a bare empty line is a context line); a Delete has no body. A file
//! may be named by at most one section. All-or-none: every section is
//! planned against the file as it was read (the hunk's context and
//! removed lines must match it exactly once, after line-ending
//! normalisation, as every edit's match does) before anything is
//! written; if a later section's write or verification fails, the
//! earlier ones are rolled back from their in-memory pre-images, and a
//! rollback that itself fails is the `Unverified` failure. An Add makes
//! the directories its path needs (H2f) and refuses a path that
//! exists; a Delete refuses a path that does not.
//!
//! **Delete and move.** One file per call, anchored and pre-imaged like
//! every edit (P-22): the bytes are kept before the file goes. A move
//! writes the source's bytes to the target (refusing an existing
//! target, and the source itself), making the target's directories,
//! then removes the source: two journal records, the target's create
//! and the source's delete. Policy sees the source as `path`, so every
//! `path_glob` rule matches it; the `to` path is checked by policy too
//! (harness-policy).
//!
//! The result is harness text about what changed (paths, line counts,
//! digests), never file content: hence `content: own` in the manifest.

use std::io;
use std::path::{Path, PathBuf};
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
use crate::edit::{
    check_cap, check_new_parents, check_pre_image, create_parents, crlf_dominant, find_offsets,
    lf_to_crlf, line_count, normalize_lf, read_capped, remove_dirs, EditError, ReadLog, StaleRead,
    EDIT_MAX_BYTES, WRITE_MAX_NEW_DIRS,
};
use crate::file_ops::{FileOps, InProcess};
use crate::protected::Protected;
use crate::provider::{
    EditRecord, Image, InvokeCtx, RefusalKind, ToolError, ToolProvider, ToolResult,
};

/// `harness.edit.patch` (P-25).
pub const PATCH: &str = "harness.edit.patch";
/// `harness.edit.delete` (P-25).
pub const DELETE: &str = "harness.edit.delete";
/// `harness.edit.move` (P-25).
pub const MOVE: &str = "harness.edit.move";

const BEGIN: &str = "*** Begin Patch";
const END: &str = "*** End Patch";
const ADD_HEAD: &str = "*** Add File: ";
const UPDATE_HEAD: &str = "*** Update File: ";
const DELETE_HEAD: &str = "*** Delete File: ";

/// Why a patch script was refused before anything was planned (a bad
/// argument or a malformed script): the file system was not touched.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The `patch` argument is missing or not a string.
    #[error("missing the patch script")]
    NoPatch,
    /// The script is malformed; `line` is its 1-based line, `why` says
    /// what that line may be instead.
    #[error("line {line}: {why}")]
    Line {
        /// The 1-based line of the script the refusal is about.
        line: usize,
        /// What the line may be.
        why: String,
    },
    /// The script names the same file twice (in any two sections).
    #[error("{0} is named by more than one section")]
    Duplicate(String),
}

/// One section of a parsed patch script.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Section {
    /// `*** Add File: <path>` and its content lines.
    Add {
        /// The file to create.
        path: String,
        /// Its content, the section's lines joined with newlines (with a
        /// trailing one when there is content).
        content: String,
    },
    /// `*** Update File: <path>` and its hunk lines.
    Update {
        /// The file to change.
        path: String,
        /// The hunk: context (`' '`), removed (`'-'`) and added (`'+'`)
        /// lines in order, without the tag byte.
        hunk: Vec<(u8, String)>,
    },
    /// `*** Delete File: <path>`.
    Delete {
        /// The file to delete.
        path: String,
    },
}

impl Section {
    fn path(&self) -> &str {
        match self {
            Section::Add { path, .. } | Section::Update { path, .. } | Section::Delete { path } => {
                path
            }
        }
    }
}

/// Parse a patch script body (between the markers) into sections.
/// Strict: anything but a section head, a hunk line or the end marker
/// is refused with the line it was found on.
fn parse_sections(body: &str) -> Result<Vec<Section>, ParseError> {
    // Line endings are stripped, so the script's own endings never leak
    // into matched text.
    let lines: Vec<&str> = body.split('\n').collect();
    let last_is_empty = lines.last().is_some_and(|l| l.is_empty());
    let lines: Vec<&str> = if last_is_empty {
        let n = lines.len().saturating_sub(1);
        lines.into_iter().take(n).collect()
    } else {
        lines
    };
    let mut sections: Vec<Section> = Vec::new();
    let mut at = 0usize;
    while let Some(line) = lines.get(at) {
        let line = *line;
        at += 1;
        if let Some(p) = line.strip_prefix(ADD_HEAD) {
            let body = take_body(&lines, &mut at, false)?;
            let mut content = body.join("\n");
            if !content.is_empty() {
                content.push('\n');
            }
            sections.push(Section::Add {
                path: head_path(p).map_err(|why| ParseError::Line { line: at, why })?,
                content,
            });
        } else if let Some(p) = line.strip_prefix(UPDATE_HEAD) {
            let path = head_path(p).map_err(|why| ParseError::Line { line: at, why })?;
            let start = at + 1;
            let body = take_body(&lines, &mut at, true)?;
            let mut hunk: Vec<(u8, String)> = Vec::new();
            for (i, l) in body.iter().enumerate() {
                let rest = match l.strip_prefix(' ') {
                    Some(r) => r,
                    None => match l.strip_prefix('-') {
                        Some(r) => r,
                        None => match l.strip_prefix('+') {
                            Some(r) => r,
                            // A bare empty line is a context line of no
                            // content.
                            None if l.is_empty() => "",
                            None => {
                                return Err(ParseError::Line {
                                    line: start + i,
                                    why: "an update's lines start with a space, a minus or a plus (context, removed, added)".into(),
                                })
                            }
                        },
                    },
                };
                let tag = match (l.as_bytes().first(), l.is_empty()) {
                    (Some(b' '), _) | (None, _) => b' ',
                    (Some(b'-'), _) => b'-',
                    (Some(b'+'), _) => b'+',
                    _ => b' ',
                };
                hunk.push((tag, rest.to_owned()));
            }
            sections.push(Section::Update { path, hunk });
        } else if let Some(p) = line.strip_prefix(DELETE_HEAD) {
            sections.push(Section::Delete {
                path: head_path(p).map_err(|why| ParseError::Line { line: at, why })?,
            });
        } else {
            return Err(ParseError::Line {
                line: at,
                why: "expected a section head (`*** Add File:`, `*** Update File:` or `*** Delete File:`)".into(),
            });
        }
    }
    Ok(sections)
}

/// The path on a section head: non-empty, no padding.
fn head_path(p: &str) -> Result<String, String> {
    let t = p.trim();
    if t.is_empty() || t != p {
        Err("the section head names exactly one workspace path".into())
    } else {
        Ok(t.to_owned())
    }
}

/// The body lines of a section, up to (not including) the next section
/// head or the end marker. `hunk` demands at least one body line (a
/// Delete may have none).
fn take_body<'a>(
    lines: &[&'a str],
    at: &mut usize,
    hunk: bool,
) -> Result<Vec<&'a str>, ParseError> {
    let start = *at;
    while let Some(l) = lines.get(*at) {
        if l.starts_with("*** ") {
            break;
        }
        *at += 1;
    }
    let empty: &[&str] = &[];
    let body = lines.get(start..*at).unwrap_or(empty);
    if hunk && body.is_empty() {
        return Err(ParseError::Line {
            line: start.saturating_sub(1) + 1,
            why: "an update needs at least one hunk line (a space, a minus or a plus, then the line's text)".into(),
        });
    }
    Ok(body.to_vec())
}

/// Parse the whole script: the markers, the sections, and the
/// one-section-per-file rule.
fn parse_patch(text: &str) -> Result<Vec<Section>, ParseError> {
    let mut split = text.split('\n');
    let first = split.next().unwrap_or("");
    if first != BEGIN {
        return Err(ParseError::Line {
            line: 1,
            why: format!("the script starts `{BEGIN}`"),
        });
    }
    let mut body = String::new();
    let mut end_at = None;
    for (i, l) in split.enumerate() {
        if l == END {
            end_at = Some(i + 2);
            break;
        }
        body.push_str(l);
        body.push('\n');
    }
    let Some(end_at) = end_at else {
        return Err(ParseError::Line {
            line: 2,
            why: format!("the script ends `{END}`"),
        });
    };
    // Nothing may follow the end marker but empty lines (the last
    // newline of a string is one).
    let rest: Vec<&str> = text
        .split('\n')
        .skip(end_at)
        .filter(|l| !l.is_empty())
        .collect();
    if !rest.is_empty() {
        return Err(ParseError::Line {
            line: end_at + 1,
            why: format!("nothing follows `{END}`"),
        });
    }
    let sections = parse_sections(&body)?;
    let mut seen: Vec<&str> = Vec::new();
    for s in &sections {
        if seen.contains(&s.path()) {
            return Err(ParseError::Duplicate(s.path().to_owned()));
        }
        seen.push(s.path());
    }
    Ok(sections)
}

/// Why a planned or applied op failed. Only [`PatchError::Unverified`]
/// can mean the workspace changed: every other variant is reported
/// before the first write (during the all-or-none plan) or, for a
/// single-file op, before that file's own write.
#[derive(Debug, thiserror::Error)]
pub enum PatchError {
    /// The script fails its parse.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// The path fails the lexical workspace rule (§4.8).
    #[error("the path is refused: {0}")]
    PathRefused(harness_policy::PathRefused),
    /// The path is protected (P-29): `pattern` names the glob that
    /// matched. Reported before anything is read or written.
    #[error("the path is protected ({pattern})")]
    Protected {
        /// The glob that matched.
        pattern: String,
    },
    /// A section's hunk does not match its file exactly once; `found`
    /// is how many times it matched after line-ending normalisation.
    #[error("the context of {path} matches {found} time(s), not exactly once")]
    HunkMismatch {
        /// The file the hunk was matched against.
        path: String,
        /// How many matches the normalised context had.
        found: usize,
    },
    /// An Add names a path that exists; nothing was written.
    #[error("{0} already exists; an Add creates a new file")]
    AddExists(String),
    /// A Delete or a patch Delete names a path that does not exist.
    #[error("no such file or directory")]
    NotFound,
    /// A move's target is the source itself.
    #[error("the move's target is its source")]
    SameMove,
    /// A move's target path exists; nothing was written.
    #[error("{0} already exists; a move refuses to overwrite")]
    MoveTargetExists(String),
    /// An update section would not change its file (no removed or added
    /// lines beyond context, or the added text equals the removed text).
    #[error("the update would not change {0}")]
    NoOp(String),
    /// The op was written but not verified (the re-read after the write
    /// did not find the planned content), or a rollback of an earlier
    /// file of the same call failed: the workspace may have changed.
    #[error("{0}")]
    Unverified(String),
    /// Everything else the engine under [`EditError`] reports (a
    /// symlink, an oversize file, a stale read, I/O, non-UTF-8 text,
    /// too many new directories).
    #[error(transparent)]
    Edit(#[from] EditError),
}

impl PatchError {
    /// Whether the workspace may have changed.
    pub fn may_have_changed(&self) -> bool {
        matches!(self, PatchError::Unverified(_))
    }
}

impl From<ResolveErr> for PatchError {
    fn from(e: ResolveErr) -> Self {
        match e {
            ResolveErr::NotFound => PatchError::NotFound,
            ResolveErr::Symlink => PatchError::Edit(EditError::Symlink),
            ResolveErr::Io(e) => PatchError::Edit(EditError::Io(e)),
        }
    }
}

/// One planned file change: the in-memory plan of a section (or a
/// single-file op), checked against the file as it was read, waiting to
/// be applied. The after-digest is filled in by the apply.
struct Planned {
    /// The workspace path the record will name.
    wp: WorkspacePath,
    /// The file's full path under the root.
    path: PathBuf,
    /// What to write: `None` for a delete.
    new_bytes: Option<Vec<u8>>,
    /// The digest before (`None` for a create).
    before: Option<Digest>,
    /// The digest after (`None` for a delete), set by the apply.
    after: Option<Digest>,
    /// The pre-image bytes (P-22), for the journal's blob store and the
    /// rollback. `None` for a create.
    before_image: Option<Image>,
}

/// The planned ops of one call, in order.
struct Plan {
    ops: Vec<Planned>,
}

impl Plan {
    /// Roll back every applied op in reverse: each earlier file is
    /// restored from its in-memory pre-image (a create is removed), and
    /// each restored file must hash back to its before-digest. One
    /// failure anywhere is the `Unverified` failure the driver stops a
    /// run on.
    fn rollback(
        &self,
        ops: &mut dyn FileOps,
        root: &Path,
        applied: usize,
    ) -> Result<(), PatchError> {
        for op in self.ops.iter().take(applied).rev() {
            match (&op.before_image, op.before) {
                (Some(img), Some(before)) => {
                    ops.write_atomic(&op.path, &img.bytes, None).map_err(|e| {
                        PatchError::Unverified(format!(
                            "the rollback of {} failed: {e}",
                            op.wp.as_str()
                        ))
                    })?;
                    match reread_digest(ops, root, &op.wp) {
                        Ok(got) if got == before => {}
                        Ok(_) => {
                            return Err(PatchError::Unverified(format!(
                                "the rollback of {} left a different file than before",
                                op.wp.as_str()
                            )))
                        }
                        Err(e) => {
                            return Err(PatchError::Unverified(format!(
                                "the rollback of {} could not be verified: {e}",
                                op.wp.as_str()
                            )))
                        }
                    }
                }
                (None, None) => {
                    // A create: remove it again; a missing file is
                    // already gone, which is what the rollback wants.
                    if let Err(e) = ops.remove_file(&op.path) {
                        if e.kind() != io::ErrorKind::NotFound {
                            return Err(PatchError::Unverified(format!(
                                "the rollback (removing {}) failed: {e}",
                                op.wp.as_str()
                            )));
                        }
                    }
                }
                // A planned op always has its before image or is a
                // create; anything else is a plan bug, reported as the
                // verified-change failure it would be.
                _ => {
                    return Err(PatchError::Unverified(format!(
                        "the rollback of {} has no pre-image",
                        op.wp.as_str()
                    )))
                }
            }
        }
        Ok(())
    }
}

/// The digest of the file at `wp`, through the confined walk and cap.
fn reread_digest(
    ops: &mut dyn FileOps,
    root: &Path,
    wp: &WorkspacePath,
) -> Result<Digest, EditError> {
    let (path, meta) = resolve_path(ops, root, wp)?;
    let Some(meta) = meta else {
        return Err(EditError::NotFound);
    };
    if !meta.kind.is_file() {
        return Err(EditError::NotAFile);
    }
    let bytes = read_capped(ops, &path, meta.len, EDIT_MAX_BYTES)?;
    Ok(sha256(&bytes))
}

/// Whether a path is verified gone: the confined walk finds the final
/// component missing (a walk error is not a verification).
fn verified_gone(
    ops: &mut dyn FileOps,
    root: &Path,
    wp: &WorkspacePath,
) -> Result<bool, PatchError> {
    match resolve_path(ops, root, wp) {
        Ok((_, None)) => Ok(true),
        Ok((_, Some(_))) => Ok(false),
        Err(ResolveErr::NotFound) => Ok(true),
        Err(ResolveErr::Symlink) => Err(PatchError::Edit(EditError::Symlink)),
        Err(ResolveErr::Io(e)) => Err(PatchError::Edit(EditError::Io(e))),
    }
}

/// The P-25 provider: the patch script and the delete/move file
/// operations, over one workspace. Built like [`crate::edit::EditTools`];
/// the driver installs the run's protected-path list with
/// [`PatchTools::with_protected`].
#[derive(Debug)]
pub struct PatchTools {
    ns: ProviderName,
    root: PathBuf,
    protected: Protected,
    /// Every filesystem access of these tools goes through here (P-36e).
    ops: Box<dyn FileOps>,
}

impl PatchTools {
    /// The P-25 tools over the workspace at `root`, under the read
    /// tools' root rule (a real directory, never a symlink).
    pub fn new(root: &Path) -> Result<Self, RootRefused> {
        let mut ops: Box<dyn FileOps> = Box::new(InProcess);
        Ok(Self {
            ns: ProviderName::new(harness_manifest::BUILTIN_NAMESPACE)
                .map_err(|_| RootRefused::Io(io::Error::other("builtin namespace")))?,
            root: canonical_root(ops.as_mut(), root)?,
            protected: Protected::empty(),
            ops,
        })
    }

    /// The same tools over another [`FileOps`] implementation (P-36e):
    /// the root check runs against it too. Results are the implementation's.
    #[must_use]
    pub fn with_file_ops(mut self, ops: Box<dyn FileOps>) -> Self {
        self.ops = ops;
        self
    }

    /// The same tools with a protected-path deny list (P-29): ops on
    /// matching paths are refused with [`PatchError::Protected`] before
    /// anything is touched.
    #[must_use]
    pub fn with_protected(self, protected: Protected) -> Self {
        Self { protected, ..self }
    }

    /// The canonical workspace root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The P-29 floor, shared with the edit engine.
    fn guard(&self, wp: &WorkspacePath) -> Result<(), PatchError> {
        match self.protected.matched(wp.as_str()) {
            None => Ok(()),
            Some(pattern) => Err(PatchError::Protected {
                pattern: pattern.to_owned(),
            }),
        }
    }

    /// Read the file at `wp` whole (the caps and the stale anchor
    /// included), returning its resolved path, bytes and digest.
    fn read_anchored(
        &mut self,
        wp: &WorkspacePath,
        reads: &ReadLog,
    ) -> Result<(PathBuf, Vec<u8>, Digest), PatchError> {
        let (path, meta) = resolve_path(self.ops.as_mut(), &self.root, wp)?;
        let Some(meta) = meta else {
            return Err(PatchError::NotFound);
        };
        if !meta.kind.is_file() {
            return Err(EditError::NotAFile.into());
        }
        check_pre_image(meta.len)?;
        let bytes = read_capped(self.ops.as_mut(), &path, meta.len, EDIT_MAX_BYTES)?;
        let before = sha256(&bytes);
        reads
            .check(wp.as_str(), before)
            .map_err(|e| PatchError::Edit(EditError::Stale(e)))?;
        Ok((path, bytes, before))
    }

    /// The plan half of `harness.edit.patch`: parse the script, plan
    /// every section against the file as it was read, write nothing.
    /// Every refusal here leaves the workspace as it was.
    fn plan_patch(&mut self, args: &Value, reads: &ReadLog) -> Result<Plan, PatchError> {
        let text = match args.get("patch").and_then(Value::as_str) {
            Some(t) => t,
            None => return Err(ParseError::NoPatch.into()),
        };
        let sections = parse_patch(text)?;
        let mut ops: Vec<Planned> = Vec::new();
        for s in sections {
            let wp = workspace_path(s.path()).map_err(PatchError::PathRefused)?;
            self.guard(&wp)?;
            match s {
                Section::Add { content, .. } => {
                    let (path, meta) = resolve_path(self.ops.as_mut(), &self.root, &wp)?;
                    if meta.is_some() {
                        return Err(PatchError::AddExists(wp.as_str().to_owned()));
                    }
                    let bytes = content.into_bytes();
                    check_cap(&bytes)?;
                    check_new_parents(self.ops.as_mut(), &self.root, &wp)?;
                    ops.push(Planned {
                        wp,
                        path,
                        new_bytes: Some(bytes),
                        before: None,
                        after: None,
                        before_image: None,
                    });
                }
                Section::Update { hunk, .. } => {
                    let (path, bytes, before) = self.read_anchored(&wp, reads)?;
                    let new_bytes = plan_hunk(&wp, &bytes, &hunk)?;
                    ops.push(Planned {
                        wp,
                        path,
                        new_bytes: Some(new_bytes),
                        before: Some(before),
                        after: None,
                        before_image: Some(Image {
                            sha256: before,
                            bytes,
                        }),
                    });
                }
                Section::Delete { .. } => {
                    let (path, bytes, before) = self.read_anchored(&wp, reads)?;
                    ops.push(Planned {
                        wp,
                        path,
                        new_bytes: None,
                        before: Some(before),
                        after: None,
                        before_image: Some(Image {
                            sha256: before,
                            bytes,
                        }),
                    });
                }
            }
        }
        Ok(Plan { ops })
    }

    /// `harness.edit.patch`: plan all sections, then apply them in
    /// order, all or none (a later failure rolls the earlier ones back).
    fn patch(&mut self, args: &Value, reads: &ReadLog) -> (Out, Vec<EditRecord>) {
        let mut plan = match self.plan_patch(args, reads) {
            Ok(p) => p,
            Err(e) => return (patch_err(&e), Vec::new()),
        };
        let mut lines: Vec<String> = Vec::new();
        let mut applied = 0usize;
        for op in plan.ops.iter_mut() {
            match self.apply(op) {
                Ok(l) => {
                    lines.push(l);
                    applied += 1;
                }
                Err(e) => {
                    // All or none: undo what this call already wrote.
                    let rolled = plan.rollback(self.ops.as_mut(), &self.root, applied);
                    return match rolled {
                        Ok(()) => (patch_err(&e), Vec::new()),
                        Err(rb) => (patch_err(&rb), Vec::new()),
                    };
                }
            }
        }
        let mut text = format!("patched {} file(s):\n", plan.ops.len());
        for l in lines {
            text.push_str(&l);
        }
        let records = plan
            .ops
            .iter()
            .map(|op| EditRecord {
                path: op.wp.clone(),
                before: op.before,
                after: op.after,
                before_image: op.before_image.clone(),
                after_image: match (&op.after, &op.new_bytes) {
                    (Some(after), Some(bytes)) => Some(Image {
                        sha256: *after,
                        bytes: bytes.clone(),
                    }),
                    _ => None,
                },
            })
            .collect();
        (ok(text), records)
    }

    /// Apply one planned op and verify it: the write (or delete) is
    /// atomic, the re-read must hold exactly the planned bytes (or be
    /// gone), and the plan is filled in with the after-digest. The
    /// caller collects the record and the result line.
    fn apply(&mut self, op: &mut Planned) -> Result<String, PatchError> {
        let new_bytes = op.new_bytes.clone();
        match new_bytes {
            None => {
                // Delete: remove, then verify it is gone through the
                // same confined walk.
                self.ops
                    .remove_file(&op.path)
                    .map_err(|e| PatchError::Edit(EditError::Io(e)))?;
                if !verified_gone(self.ops.as_mut(), &self.root, &op.wp)? {
                    return Err(PatchError::Unverified(format!(
                        "{} still exists after the delete",
                        op.wp.as_str()
                    )));
                }
                op.after = None;
                Ok(format!(
                    "- deleted {}: sha256 {} was kept as a pre-image\n",
                    op.wp.as_str(),
                    op.before.map_or_else(String::new, |d| d.to_string())
                ))
            }
            Some(new_bytes) => {
                let made = create_parents(self.ops.as_mut(), &self.root, &op.wp)?;
                let expected = sha256(&new_bytes);
                if let Err(e) = self.ops.write_atomic(&op.path, &new_bytes, None) {
                    remove_dirs(self.ops.as_mut(), &self.root, &made);
                    return Err(PatchError::Edit(EditError::Io(e)));
                }
                match reread_digest(self.ops.as_mut(), &self.root, &op.wp) {
                    Ok(got) if got == expected => {}
                    Ok(_) | Err(_) => {
                        remove_dirs(self.ops.as_mut(), &self.root, &made);
                        return Err(PatchError::Unverified(format!(
                            "{} was written but holds different bytes than planned",
                            op.wp.as_str()
                        )));
                    }
                }
                let created = op.before.is_none();
                op.after = Some(expected);
                Ok(if created {
                    format!(
                        "- created {}: {} line(s); sha256 {}\n",
                        op.wp.as_str(),
                        line_count(&new_bytes),
                        expected
                    )
                } else {
                    format!(
                        "- edited {}: {} line(s); sha256 {} (was {})\n",
                        op.wp.as_str(),
                        line_count(&new_bytes),
                        expected,
                        op.before.map_or_else(String::new, |d| d.to_string())
                    )
                })
            }
        }
    }

    /// `harness.edit.delete`: one file, anchored and pre-imaged, then
    /// removed and verified gone.
    fn delete(&mut self, args: &Value, reads: &ReadLog) -> (Out, Vec<EditRecord>) {
        let wp = match arg_path(args) {
            Ok(w) => w,
            Err(out) => return (out, Vec::new()),
        };
        if let Err(e) = self.guard(&wp) {
            return (patch_err(&e), Vec::new());
        }
        let (path, bytes, before) = match self.read_anchored(&wp, reads) {
            Ok(x) => x,
            Err(e) => return (patch_err(&e), Vec::new()),
        };
        let mut op = Planned {
            wp: wp.clone(),
            path,
            new_bytes: None,
            before: Some(before),
            after: None,
            before_image: Some(Image {
                sha256: before,
                bytes,
            }),
        };
        let text = match self.apply(&mut op) {
            Ok(t) => t,
            Err(e) => return (patch_err(&e), Vec::new()),
        };
        (
            ok(format!("deleted {}: {text}", wp.as_str())),
            vec![EditRecord {
                path: wp,
                before: op.before,
                after: None,
                before_image: op.before_image,
                after_image: None,
            }],
        )
    }

    /// `harness.edit.move`: the source anchored and pre-imaged, the
    /// target refused when it exists, then the source's bytes written to
    /// the target (verified) and the source removed (verified gone): two
    /// records, target create then source delete.
    fn move_file(&mut self, args: &Value, reads: &ReadLog) -> (Out, Vec<EditRecord>) {
        let wp = match arg_path(args) {
            Ok(w) => w,
            Err(out) => return (out, Vec::new()),
        };
        let to = match args.get("to").and_then(Value::as_str) {
            Some(t) => match workspace_path(t) {
                Ok(x) => x,
                Err(e) => return (err(code::PATH_REFUSED, &e.to_string()), Vec::new()),
            },
            None => {
                return (
                    err(code::BAD_ARGS, "missing the move's target `to`"),
                    Vec::new(),
                )
            }
        };
        for p in [&wp, &to] {
            if let Err(e) = self.guard(p) {
                return (patch_err(&e), Vec::new());
            }
        }
        if wp == to {
            return (patch_err(&PatchError::SameMove), Vec::new());
        }
        let (path, bytes, before) = match self.read_anchored(&wp, reads) {
            Ok(x) => x,
            Err(e) => return (patch_err(&e), Vec::new()),
        };
        let (to_path, to_meta) = match resolve_path(self.ops.as_mut(), &self.root, &to) {
            Ok(x) => x,
            Err(e) => return (patch_err(&PatchError::from(e)), Vec::new()),
        };
        if to_meta.is_some() {
            return (
                patch_err(&PatchError::MoveTargetExists(to.as_str().to_owned())),
                Vec::new(),
            );
        }
        if let Err(e) = check_new_parents(self.ops.as_mut(), &self.root, &to) {
            return (patch_err(&PatchError::Edit(e)), Vec::new());
        }
        // The target write, verified like every apply.
        let made = match create_parents(self.ops.as_mut(), &self.root, &to) {
            Ok(m) => m,
            Err(e) => return (patch_err(&PatchError::Edit(e)), Vec::new()),
        };
        let expected = sha256(&bytes);
        if let Err(e) = self.ops.write_atomic(&to_path, &bytes, None) {
            remove_dirs(self.ops.as_mut(), &self.root, &made);
            return (patch_err(&PatchError::Edit(EditError::Io(e))), Vec::new());
        }
        match reread_digest(self.ops.as_mut(), &self.root, &to) {
            Ok(got) if got == expected => {}
            _ => {
                remove_dirs(self.ops.as_mut(), &self.root, &made);
                return (
                    patch_err(&PatchError::Unverified(format!(
                        "{} was written but holds different bytes than planned",
                        to.as_str()
                    ))),
                    Vec::new(),
                );
            }
        }
        // The source removal, verified gone; if it fails, the copy the
        // target now holds is taken back out, so the workspace keeps
        // looking as it did.
        if let Err(e) = self.ops.remove_file(&path) {
            let _ = self.ops.remove_file(&to_path);
            remove_dirs(self.ops.as_mut(), &self.root, &made);
            return (patch_err(&PatchError::Edit(EditError::Io(e))), Vec::new());
        }
        match verified_gone(self.ops.as_mut(), &self.root, &wp) {
            Ok(true) => {}
            Ok(false) => {
                return (
                    patch_err(&PatchError::Unverified(format!(
                        "{} still exists after the move",
                        wp.as_str()
                    ))),
                    Vec::new(),
                )
            }
            Err(e) => return (patch_err(&e), Vec::new()),
        }
        let text = format!(
            "moved {} to {}: {} line(s); sha256 {expected} (the old file's bytes were kept as a pre-image)\n",
            wp.as_str(),
            to.as_str(),
            line_count(&bytes)
        );
        (
            ok(text),
            vec![
                EditRecord {
                    path: to,
                    before: None,
                    after: Some(expected),
                    before_image: None,
                    after_image: Some(Image {
                        sha256: expected,
                        bytes: bytes.clone(),
                    }),
                },
                EditRecord {
                    path: wp,
                    before: Some(before),
                    after: None,
                    before_image: Some(Image {
                        sha256: before,
                        bytes,
                    }),
                    after_image: None,
                },
            ],
        )
    }
}

/// The plan half of an Update section: the hunk's context and removed
/// lines must match the file exactly once (after line-ending
/// normalisation, on both sides), and the result takes the file's
/// dominant line endings, as every edit's replacement does.
fn plan_hunk(
    wp: &WorkspacePath,
    file_bytes: &[u8],
    hunk: &[(u8, String)],
) -> Result<Vec<u8>, PatchError> {
    let text = std::str::from_utf8(file_bytes).map_err(|_| EditError::NotUtf8)?;
    let joined = |tag: u8| -> String {
        let parts: Vec<&str> = hunk
            .iter()
            .filter(|(t, _)| *t == tag)
            .map(|(_, l)| l.as_str())
            .collect();
        let mut s = parts.join("\n");
        if !s.is_empty() {
            s.push('\n');
        }
        s
    };
    // Context counts as removed for the text that must match, and as
    // added for the text that replaces it.
    let old = normalize_lf(&joined(b' '));
    let old = format!("{}{}", old, normalize_lf(&joined(b'-')));
    let new = format!("{}{}", joined(b' '), joined(b'+'));
    if old.is_empty() || old == new {
        return Err(PatchError::NoOp(wp.as_str().to_owned()));
    }
    let norm = normalize_lf(text);
    let offsets = find_offsets(&norm, &old);
    if offsets.len() != 1 {
        return Err(PatchError::HunkMismatch {
            path: wp.as_str().to_owned(),
            found: offsets.len(),
        });
    }
    let off = match offsets.first() {
        Some(&o) => o,
        None => {
            return Err(PatchError::HunkMismatch {
                path: wp.as_str().to_owned(),
                found: 0,
            })
        }
    };
    // The match starts and ends on character boundaries (find_offsets
    // works on `char_indices`), so the pieces are valid UTF-8.
    let spliced = match (norm.get(..off), norm.get(off + old.len()..)) {
        (Some(h), Some(t)) => format!("{h}{new}{t}"),
        _ => {
            return Err(PatchError::HunkMismatch {
                path: wp.as_str().to_owned(),
                found: offsets.len(),
            })
        }
    };
    let out = if crlf_dominant(text) {
        lf_to_crlf(&spliced)
    } else {
        spliced
    };
    check_cap(out.as_bytes())?;
    Ok(out.into_bytes())
}

/// An argument path (`{"path": "..."}`), lexically checked.
fn arg_path(args: &Value) -> Result<WorkspacePath, Out> {
    match args.get("path") {
        Some(Value::String(s)) => {
            workspace_path(s).map_err(|e| err(code::PATH_REFUSED, &e.to_string()))
        }
        Some(_) => Err(err(code::BAD_ARGS, "the path is not a string")),
        None => Err(err(code::BAD_ARGS, "missing path")),
    }
}

/// A patch error as the model sees it: an error code and harness words
/// (no file content, no script text).
fn patch_err(e: &PatchError) -> Out {
    match e {
        PatchError::Parse(ParseError::NoPatch) => err(
            code::BAD_ARGS,
            "missing the patch script: give the script as the string argument `patch`",
        ),
        PatchError::Parse(ParseError::Line { line, why }) => err(
            code::BAD_ARGS,
            &format!("the patch script is refused at line {line}: {why}"),
        ),
        PatchError::Parse(ParseError::Duplicate(p)) => err(
            code::BAD_ARGS,
            &format!("the patch script names {p} in more than one section: one section per file"),
        ),
        PatchError::PathRefused(p) => err(
            code::PATH_REFUSED,
            &format!("the path is refused: {p}; write it relative to the workspace root, like src/lib.rs"),
        ),
        PatchError::Protected { pattern } => err(
            code::PROTECTED,
            &format!("the path is protected ({pattern}); this harness does not edit it, so leave it alone and say so in the submit note"),
        ),
        PatchError::HunkMismatch { path, found } => err(
            code::NO_MATCH,
            &format!(
                "the context of {path} matches {found} time(s), not exactly once: copy the context lines byte-exactly from the file (whitespace and line endings included) so it matches once"
            ),
        ),
        PatchError::AddExists(p) => err(
            code::BAD_ARGS,
            &format!("{p} already exists: an Add creates a new file; to change it use an Update, to rewrite it whole use harness.edit.write"),
        ),
        PatchError::NotFound => err(
            code::NOT_FOUND,
            "no such file or directory: find the path with harness.fs.glob or harness.fs.list, then repeat",
        ),
        PatchError::SameMove => err(
            code::BAD_ARGS,
            "the move's target is its source: give a different `to` path",
        ),
        PatchError::MoveTargetExists(p) => err(
            code::BAD_ARGS,
            &format!("{p} already exists: a move refuses to overwrite; read it and merge the contents yourself, or choose another name"),
        ),
        PatchError::NoOp(p) => err(
            code::NO_OP,
            &format!("the update would not change {p}: its removed and added lines are the same; change the added lines, or drop the section"),
        ),
        PatchError::Unverified(m) => err(
            code::UNVERIFIED,
            &format!("{m}; the workspace may have changed: read the files with harness.fs.read to see what they hold now before any other edit"),
        ),
        PatchError::Edit(e) => edit_like_err(e),
    }
}

/// The shared [`EditError`] cases, in the edit tools' words.
fn edit_like_err(e: &EditError) -> Out {
    match e {
        EditError::Symlink => err(
            code::SYMLINK,
            "a path component is a symlink; symlinks are never followed: use the real path, or leave that file alone and say so in the submit note",
        ),
        EditError::NotFound => err(
            code::NOT_FOUND,
            "no such file or directory: find the path with harness.fs.glob or harness.fs.list, then repeat",
        ),
        EditError::NotAFile => err(code::NOT_A_FILE, "not a regular file: name a file, not a directory (harness.fs.list shows what a directory holds)"),
        EditError::NotADirectory => err(
            code::NOT_A_FILE,
            "a component of the path is a file, not a directory: nothing was created; choose a path whose directories are directories",
        ),
        EditError::NotUtf8 => err(code::NOT_TEXT, "not UTF-8 text: this tool edits text files only; leave the file alone"),
        EditError::TooLarge { .. } => err(code::TOO_LARGE, "the file is larger than the edit cap: this tool cannot edit it; leave it alone and say so in the submit note"),
        EditError::PreImageTooLarge { .. } => err(code::TOO_LARGE, "the file is larger than the pre-image cap: an edit keeps the file's prior bytes so it can be undone, and these would not fit; leave the file alone and say so in the submit note"),
        EditError::TooManyDirs => err(
            code::BAD_ARGS,
            &format!(
                "the path needs more than {WRITE_MAX_NEW_DIRS} new directories; nothing was created: use a path with fewer new directories, or an existing directory"
            ),
        ),
        EditError::Stale(StaleRead::NeverRead) => err(
            code::STALE_READ,
            "file not read in this run; read it first: call harness.fs.read on this path (a search does not count as a read), then repeat this call",
        ),
        EditError::Stale(StaleRead::Changed) => err(
            code::STALE_READ,
            "file changed since read; re-read first: call harness.fs.read on this path, then copy the section's context from the fresh text and repeat this call",
        ),
        EditError::Io(_) => err(code::IO, "the file system refused the operation: check the path with harness.fs.list; if it keeps failing, leave the file and say so in the submit note"),
        other => err(
            code::IO,
            &format!("the operation failed: {other}; read the file with harness.fs.read to see what it holds before any other edit"),
        ),
    }
}

impl ToolProvider for PatchTools {
    fn namespace(&self) -> &ProviderName {
        &self.ns
    }

    fn serves(&self, capability: &str) -> bool {
        matches!(capability, PATCH | DELETE | MOVE)
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
        let (out, edits) = match cap {
            PATCH => self.patch(&c.args, ctx.reads),
            DELETE => self.delete(&c.args, ctx.reads),
            _ => self.move_file(&c.args, ctx.reads),
        };
        let mut res = finish(cap, out);
        res.edits = edits;
        Ok(res)
    }
}
