//! The workspace modes (P-52): what `run` and `chat` do to the workspace
//! before the run, and the apply engine the `apply` verb and the chat's
//! `/apply` share.
//!
//! `in-place` (the default) is exactly the behaviour before P-52: the run
//! sees the workspace as it is. `scratch` copies the workspace to
//! `<state-root>/scratch/<name>/` first and the run sees only the copy, so
//! no edit can touch an original file; the CLI, as trust base, records a
//! copy manifest — the source path, the copy path and every file's content
//! digest — and the journal header records the manifest's digest plus the
//! per-file digests, so `apply` can later prove which bytes it copies back.
//! Host paths are never journal fields (`Trusted` text is compile-time
//! only): they travel in the manifest file, which the header's digest
//! binds byte for byte. `worktree` would run `git worktree add`; this
//! build refuses it (INV-23: the one spawn module is the sandbox's, and
//! only the sandbox slices touch it) — fail-closed, before anything runs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use gate_outcome::{Finding, FindingCode, Severity};
use harness_core::{sha256, Digest};
use harness_run::WorkspaceModeRecord;

use crate::report::exit;
use crate::Cx;

/// The scratch copy's caps (P-52): a workspace over either is refused with
/// a clear message, before anything is copied. Generous on purpose: the
/// point is a stopped run, not a silent truncation.
pub(crate) const SCRATCH_MAX_FILES: usize = 20_000;
pub(crate) const SCRATCH_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// Directory names the scratch copy never descends into (build output and
/// dependency trees; the model cannot need them to read or edit source).
const SKIPPED_DIRS: [&str; 2] = ["target", "node_modules"];
/// The git internals directory, copied only with `--scratch-with-git`.
const GIT_DIR: &str = ".git";

/// The workspace-mode option's value. `worktree` is refused in
/// [`parse_mode`] (INV-23), so it is not a variant here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Mode {
    InPlace,
    Scratch { with_git: bool },
}

/// What `--workspace-mode` (and `--scratch-with-git`) choose. A bad value,
/// or a flag that does not go with its mode, is a usage error.
pub(crate) fn parse_mode(o: &BTreeMap<&str, &str>) -> Result<Mode, String> {
    let with_git = o.contains_key("scratch-with-git");
    let mode = match o.get("workspace-mode") {
        None => {
            if with_git {
                return Err("--scratch-with-git needs --workspace-mode scratch".into());
            }
            Mode::InPlace
        }
        Some(&"in-place") => {
            if with_git {
                return Err("--scratch-with-git needs --workspace-mode scratch".into());
            }
            Mode::InPlace
        }
        Some(&"scratch") => Mode::Scratch { with_git },
        Some(&"worktree") => {
            return Err(
                "--workspace-mode worktree is refused in this build (INV-23: it would run git \
                 worktree add, and this build has exactly one spawn module, the sandbox's)"
                    .into(),
            )
        }
        Some(other) => {
            return Err(format!(
                "--workspace-mode must be in-place, scratch or worktree, not {other:?}"
            ))
        }
    };
    Ok(mode)
}

/// One file in the copy manifest: its path relative to the workspace root
/// (forward slashes), its content digest and its size.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManifestFile {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

/// The copy manifest (`rh-scratch/1`): the host paths and per-file digests
/// the journal cannot carry. Its exact bytes are what the header's
/// `workspace_mode.manifest` digest names.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManifestDoc {
    pub format: String,
    pub mode: String,
    pub source: String,
    pub copy: String,
    pub files: Vec<ManifestFile>,
}

pub(crate) const MANIFEST_FORMAT: &str = "rh-scratch/1";

/// The header's `workspace_mode` object, as the `apply` verb reads it: the
/// manifest digest and the per-file digests, in manifest order. `None`
/// when the field is absent (an in-place run) or not one this build
/// writes.
pub(crate) fn record_from_header(v: &serde_json::Value) -> Option<(Digest, Vec<Digest>)> {
    let o = v.as_object()?;
    if o.len() != 3 || o.get("mode")?.as_str()? != "scratch" {
        return None;
    }
    let manifest = o.get("manifest")?.as_str()?.parse().ok()?;
    let files = o
        .get("files")?
        .as_array()?
        .iter()
        .map(|f| f.as_str()?.parse().ok())
        .collect::<Option<Vec<Digest>>>()?;
    Some((manifest, files))
}

/// A prepared scratch copy: what the run needs to publish the manifest.
#[derive(Debug, Clone)]
pub(crate) struct ScratchPrep {
    /// The manifest beside the copy (`<copy>.manifest.json`).
    pub manifest_path: PathBuf,
    /// The manifest bytes' digest (the header's record).
    pub manifest: Digest,
}

/// What [`prepare`] hands back: the workspace the run sees, the header's
/// workspace-mode record (absent in-place), and the scratch details.
pub(crate) struct Prepared {
    /// The workspace to hand to `Run`/`SessionRun` and the run bundle.
    pub workspace: String,
    /// The journal header's `workspace_mode` record; `None` in-place.
    pub record: Option<WorkspaceModeRecord>,
    /// Present only for a scratch copy.
    pub scratch: Option<ScratchPrep>,
}

/// A refusal from [`prepare`]: the exit code it maps to and why.
pub(crate) struct PrepRefused {
    pub code: u8,
    pub why: String,
}

impl PrepRefused {
    fn could_not_run(why: impl Into<String>) -> Self {
        Self {
            code: exit::INDETERMINATE,
            why: why.into(),
        }
    }
}

/// Do what the mode says before anything runs: nothing (in-place), or the
/// scratch copy. `worktree` never gets here (refused in [`parse_mode`]).
/// A copy that cannot be made, or is over the caps, refuses the run before
/// it starts: nothing ran, nothing was journaled (`CouldNotRun`).
pub(crate) fn prepare(
    cx: &Cx<'_>,
    mode: &Mode,
    source: &str,
    state_root: &str,
) -> Result<Prepared, PrepRefused> {
    match mode {
        Mode::InPlace => Ok(Prepared {
            workspace: source.to_owned(),
            record: None,
            scratch: None,
        }),
        Mode::Scratch { with_git } => {
            let src = Path::new(source);
            let entries = copy_walk(src, *with_git)
                .map_err(|e| PrepRefused::could_not_run(format!("the scratch copy failed: {e}")))?;
            let total: u64 = entries.iter().map(|f| f.bytes).sum();
            if entries.len() > SCRATCH_MAX_FILES {
                return Err(PrepRefused::could_not_run(format!(
                    "the workspace has {} files; the scratch cap is {SCRATCH_MAX_FILES} \
                     (--workspace-mode scratch refuses rather than copy a partial workspace)",
                    entries.len()
                )));
            }
            if total > SCRATCH_MAX_BYTES {
                return Err(PrepRefused::could_not_run(format!(
                    "the workspace is {total} bytes; the scratch cap is {SCRATCH_MAX_BYTES} \
                     bytes (--workspace-mode scratch refuses rather than copy a partial \
                     workspace)"
                )));
            }
            let root = Path::new(state_root).join("scratch");
            crate::config::create_private_dir(&root)
                .map_err(|e| PrepRefused::could_not_run(format!("the scratch root failed: {e}")))?;
            let copy = root.join(scratch_name());
            let manifest_path = root.join(format!(
                "{}.manifest.json",
                copy.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("scratch")
            ));
            let source_abs = std::fs::canonicalize(src)
                .map_err(|e| PrepRefused::could_not_run(format!("cannot read {source}: {e}")))?;
            let files: Vec<ManifestFile> = entries
                .iter()
                .map(|f| ManifestFile {
                    path: f.rel.clone(),
                    sha256: f.digest.to_string(),
                    bytes: f.bytes,
                })
                .collect();
            let doc = ManifestDoc {
                format: MANIFEST_FORMAT.to_owned(),
                mode: "scratch".to_owned(),
                source: source_abs.to_string_lossy().into_owned(),
                copy: copy.to_string_lossy().into_owned(),
                files,
            };
            // The copy itself, file by file, then the manifest beside it.
            for f in &entries {
                let from = src.join(&f.rel);
                let to = copy.join(&f.rel);
                let parent = to.parent().ok_or_else(|| {
                    PrepRefused::could_not_run(format!("{} has no parent directory", to.display()))
                })?;
                std::fs::create_dir_all(parent).map_err(|e| {
                    PrepRefused::could_not_run(format!("cannot create {}: {e}", parent.display()))
                })?;
                let bytes = std::fs::read(&from).map_err(|e| {
                    PrepRefused::could_not_run(format!("cannot read {}: {e}", from.display()))
                })?;
                std::fs::write(&to, &bytes).map_err(|e| {
                    PrepRefused::could_not_run(format!("cannot write {}: {e}", to.display()))
                })?;
            }
            let manifest_bytes = serde_json::to_vec_pretty(&doc).map_err(|e| {
                PrepRefused::could_not_run(format!("cannot render the manifest: {e}"))
            })?;
            let manifest = sha256(&manifest_bytes);
            crate::cmd_profile::write_private(&manifest_path, &manifest_bytes).map_err(|e| {
                PrepRefused::could_not_run(format!("cannot write {}: {e}", manifest_path.display()))
            })?;
            note!(
                cx,
                "workspace copied to {} ({} file(s), {total} bytes); the run sees only the copy",
                copy.display(),
                entries.len()
            );
            let record =
                WorkspaceModeRecord::scratch(manifest, entries.iter().map(|f| f.digest).collect());
            Ok(Prepared {
                workspace: copy.to_string_lossy().into_owned(),
                record: Some(record),
                scratch: Some(ScratchPrep {
                    manifest_path,
                    manifest,
                }),
            })
        }
    }
}

/// A timestamp-plus-pid stamp for files written under the state root.
pub(crate) fn stamp() -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let t: String = harness_journal::rfc3339_utc(ms)
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("{t}-{}", std::process::id())
}

/// A scratch directory name no session can collide with: the UTC wall time
/// to the second plus the process id.
fn scratch_name() -> String {
    stamp()
}

/// One file found by the copy walk.
struct CopyFile {
    rel: String,
    digest: Digest,
    bytes: u64,
}

/// Walk `root`, collecting every regular file's relative path (forward
/// slashes), content digest and size, sorted by path. `target/` and
/// `node_modules/` are never entered; `.git` only with `with_git`;
/// symlinks are never followed (a symlink is skipped, never copied).
fn copy_walk(root: &Path, with_git: bool) -> Result<Vec<CopyFile>, String> {
    let mut files = Vec::new();
    walk(root, root, with_git, &mut files)?;
    files.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(files)
}

fn walk(base: &Path, dir: &Path, with_git: bool, out: &mut Vec<CopyFile>) -> Result<(), String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in rd {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let ft = entry
            .file_type()
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            if name == GIT_DIR && !with_git {
                continue;
            }
            if SKIPPED_DIRS.contains(&name.as_str()) {
                continue;
            }
            walk(base, &path, with_git, out)?;
            continue;
        }
        let bytes =
            std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let rel = path
            .strip_prefix(base)
            .map_err(|_| format!("{} is not under {}", path.display(), base.display()))?
            .to_string_lossy()
            .replace('\\', "/");
        out.push(CopyFile {
            rel,
            digest: sha256(&bytes),
            bytes: bytes.len() as u64,
        });
    }
    Ok(())
}

/// Copy the manifest into `runs/<id>/` once the run is committed, like the
/// run bundle: re-read and digest-checked against the header's record. A
/// failure never changes the outcome (the run is done); it costs a note
/// and a Low finding — `apply` needs this file.
pub(crate) fn publish_manifest(
    cx: &Cx<'_>,
    run_dir: &Path,
    prep: &ScratchPrep,
    findings: &mut Vec<Finding>,
) {
    let why = (|| -> Result<(), String> {
        let to = run_dir.join("workspace-manifest.json");
        let bytes = std::fs::read(&prep.manifest_path)
            .map_err(|e| format!("cannot read {}: {e}", prep.manifest_path.display()))?;
        if sha256(&bytes) != prep.manifest {
            return Err("the manifest's bytes no longer digest to the header's record".into());
        }
        crate::cmd_profile::write_private(&to, &bytes)
            .map_err(|e| format!("cannot write {}: {e}", to.display()))?;
        let back = std::fs::read(&to).map_err(|e| format!("cannot re-read {e}"))?;
        if sha256(&back) != prep.manifest {
            return Err("the published manifest failed its self-check".into());
        }
        Ok(())
    })();
    if let Err(e) = why {
        note!(cx, "workspace manifest not published: {e}");
        if let Ok(f) = Finding::new(
            Severity::Low,
            FindingCode("harness.workspace-manifest".to_owned()),
            format!("{}", run_dir.display()),
            "the scratch copy's manifest, for apply",
            e,
        ) {
            findings.push(f);
        }
    }
}

// ---------------------------------------------------------------------------
// The apply engine, shared by the `apply` verb and the chat's `/apply`.
// ---------------------------------------------------------------------------

/// The plan's text for one file, or the action taken, in the report.
#[derive(Debug, Default)]
pub(crate) struct ApplyResult {
    /// Files written back, `(path, sha256, bytes)` as applied.
    pub applied: Vec<ManifestFile>,
    /// Files created in the original (new in the scratch copy).
    pub created: Vec<ManifestFile>,
    /// Originals that changed since the copy: never overwritten.
    pub conflicts: Vec<String>,
    /// Paths deleted in the copy: this build never deletes an original.
    pub skipped_deletions: Vec<String>,
    /// The diff/plan shown before the confirmation.
    pub plan: String,
}

impl ApplyResult {
    /// Whether anything was (or would be) written.
    pub(crate) fn any_change(&self) -> bool {
        !self.applied.is_empty() || !self.created.is_empty()
    }
}

/// Build the plan: compare every manifest file's recorded digest with the
/// original now and the copy now, and walk the copy for new files. Nothing
/// is written here; the diff is the plan.
pub(crate) fn plan_apply(source: &Path, copy: &Path, files: &[ManifestFile]) -> ApplyResult {
    let mut r = ApplyResult::default();
    let mut shown = 0usize;
    let mut plan = String::new();
    for f in files {
        let orig = read_if_clean(source, f);
        match orig {
            Err(conflict) => r.conflicts.push(conflict),
            Ok(orig_bytes) => {
                let scratch_path = copy.join(&f.path);
                match std::fs::read(&scratch_path) {
                    Err(_) => r.skipped_deletions.push(f.path.clone()),
                    Ok(scratch_bytes) => {
                        let scratch_digest = sha256(&scratch_bytes);
                        if scratch_digest.to_string() == f.sha256 {
                            continue; // unchanged: nothing to apply
                        }
                        let old = String::from_utf8_lossy(&orig_bytes);
                        let new = String::from_utf8_lossy(&scratch_bytes);
                        let diff = harness_core::diff::unified(
                            &old,
                            &new,
                            harness_core::diff::DEFAULT_CONTEXT,
                            harness_core::diff::DEFAULT_MAX_LINES,
                        );
                        if !diff.is_empty() {
                            plan.push_str(&format!("--- {}\n", f.path));
                            plan.push_str(&diff);
                            plan.push('\n');
                            shown += 1;
                        }
                        r.applied.push(f.clone());
                    }
                }
            }
        }
    }
    // New files: in the copy, not in the manifest.
    let known: BTreeSet<&str> = files.iter().map(|f| f.path.as_str()).collect();
    if let Ok(new_files) = copy_walk(copy, false) {
        for nf in new_files {
            if known.contains(nf.rel.as_str()) {
                continue;
            }
            if let Ok(bytes) = std::fs::read(copy.join(&nf.rel)) {
                let text = String::from_utf8_lossy(&bytes);
                plan.push_str(&format!("+++ {} (new file)\n{text}\n", nf.rel));
                shown += 1;
                r.created.push(ManifestFile {
                    path: nf.rel,
                    sha256: nf.digest.to_string(),
                    bytes: nf.bytes,
                });
            }
        }
    }
    if shown == 0 {
        plan.push_str("(no textual differences)\n");
    }
    r.plan = plan;
    r
}

/// The original's bytes, if it is still exactly the recorded file. Anything
/// else is a conflict: apply never overwrites a changed original.
fn read_if_clean(source: &Path, f: &ManifestFile) -> Result<Vec<u8>, String> {
    let path = source.join(&f.path);
    let bytes =
        std::fs::read(&path).map_err(|_| format!("{} (missing in the original)", f.path))?;
    if bytes.len() as u64 != f.bytes || sha256(&bytes).to_string() != f.sha256 {
        return Err(format!(
            "{} (changed since the scratch copy was made)",
            f.path
        ));
    }
    Ok(bytes)
}

/// The confirmation the person at the terminal must type: exactly this.
pub(crate) const CONFIRM_WORD: &str = "apply";

/// Apply the plan (the caller has shown it and got the typed
/// confirmation). Every original is re-checked immediately before its
/// write, so a file changed between the plan and the write is a conflict,
/// never an overwrite. New files are created, never over an existing
/// original.
pub(crate) fn apply_planned(
    source: &Path,
    copy: &Path,
    result: &mut ApplyResult,
) -> Result<(), String> {
    let applied = std::mem::take(&mut result.applied);
    for f in applied {
        if read_if_clean(source, &f).is_err() {
            result.conflicts.push(format!(
                "{} (changed between the plan and the apply)",
                f.path
            ));
            continue;
        }
        let to = source.join(&f.path);
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        let bytes = std::fs::read(copy.join(&f.path))
            .map_err(|e| format!("cannot read the copy of {}: {e}", f.path))?;
        std::fs::write(&to, &bytes).map_err(|e| format!("cannot write {}: {e}", to.display()))?;
        result.applied.push(f);
    }
    let created = std::mem::take(&mut result.created);
    for f in created {
        let to = source.join(&f.path);
        if to.exists() {
            result.conflicts.push(format!(
                "{} (appeared in the original since the plan)",
                f.path
            ));
            continue;
        }
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        let bytes = std::fs::read(copy.join(&f.path))
            .map_err(|e| format!("cannot read the copy of {}: {e}", f.path))?;
        std::fs::write(&to, &bytes).map_err(|e| format!("cannot write {}: {e}", to.display()))?;
        result.created.push(f);
    }
    Ok(())
}

/// The one-line summary after an apply.
pub(crate) fn summary(r: &ApplyResult) -> String {
    format!(
        "applied {} file(s), created {}, {} conflict(s) skipped, {} deletion(s) skipped",
        r.applied.len(),
        r.created.len(),
        r.conflicts.len(),
        r.skipped_deletions.len()
    )
}
