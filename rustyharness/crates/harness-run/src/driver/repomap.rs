//! The repo map (P-33): an outline of the session's recently touched
//! files, shown to the model beside the ledger. The map is the harness's
//! own text — extracted from the files themselves with the P-24 outline
//! extractor (`harness_tools::outline::file_outline_text`) — ranked by
//! journal-derived recency, so a replay re-derives the same ranking from
//! the same records. The ranking's recency is the step of a file's last
//! edit (the journal's own counter), not a wall-clock mtime: the journal
//! is what an audit can recompute, a file system's mtimes are not.
//!
//! **Recomputed here, re-fed in a replay.** A live run reads the files and
//! extracts their outlines at every build. An audit never reads the
//! workspace (fail closed: the workspace may not even exist where the
//! audit runs), so the loop re-feeds the map the journal carries: each
//! session `ContextBuilt` record names the map text it showed as an
//! untrusted workspace payload, the replay takes that text and writes the
//! identical record back. The text is digest-covered through the context
//! digest either way, and the journal's own hash chain covers the payload.
//! A resume's catch-up re-feeds the recorded steps exactly the same way,
//! and its live continuation computes as a live run does.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use harness_core::{Digest, Source, Untrusted};

use crate::restore::RestoreMark;

/// The repo map's name in its digest-named block and payloads.
pub(crate) const REPO_MAP_NAME: &str = "repo-map";

/// Most files the map outlines (fail-closed bound: the walk is bounded by
/// the ledger's files table, but a session may touch many).
pub(crate) const REPO_MAP_MAX_FILES: usize = 8;

/// A file read for the map may not be larger than this (the outline's own
/// read cap): a larger file is skipped, like the outline tool skips it.
const REPO_MAP_FILE_MAX_BYTES: u64 = 1024 * 1024;

/// Where a build's repo map comes from: computed live, or re-fed from the
/// journal up to the last recorded step (an audit: every step).
pub(crate) struct RepoMapFeed {
    recorded: BTreeMap<u64, String>,
    recorded_through: u64,
}

impl RepoMapFeed {
    /// A live run: no recorded maps, every map computed.
    pub(crate) fn live() -> Self {
        Self {
            recorded: BTreeMap::new(),
            recorded_through: 0,
        }
    }

    /// A replay: the recorded maps, trusted up to `through` (an audit
    /// re-feeds every step; a resume's catch-up stops at the recorded
    /// prefix's last step, and its live continuation computes).
    pub(crate) fn re_feed(recorded: BTreeMap<u64, String>, through: u64) -> Self {
        Self {
            recorded,
            recorded_through: through,
        }
    }

    /// The map of step `step`, when the journal recorded one for it.
    fn take(&mut self, step: u64) -> Option<String> {
        if step > self.recorded_through {
            return None;
        }
        self.recorded.remove(&step)
    }
}

/// One touched file's ledger facts, from the restore marks (P-26): the
/// path, its edit count, its last edit's step and after-digest.
pub(crate) struct TouchedFile {
    pub(crate) path: String,
    pub(crate) edits: u64,
    pub(crate) last_step: u64,
    pub(crate) last: Option<Digest>,
}

/// The files-touched table behind the ledger and the repo map: one entry
/// per path, in path order, from the restore log's edit marks. A pure
/// function of the marks, so a replay re-derives it.
pub(crate) fn touched_files(marks: &[RestoreMark]) -> Vec<TouchedFile> {
    let mut files: Vec<TouchedFile> = Vec::new();
    for m in marks {
        let RestoreMark::Edit {
            step, path, after, ..
        } = m
        else {
            continue;
        };
        match files.iter_mut().find(|f| f.path == *path) {
            Some(f) => {
                f.edits = f.edits.saturating_add(1);
                f.last_step = *step;
                f.last = *after;
            }
            None => files.push(TouchedFile {
                path: path.clone(),
                edits: 1,
                last_step: *step,
                last: *after,
            }),
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files
}

/// Whether `rel` is a plain workspace-relative path: no absolute form, no
/// `..` component, no empty component. The paths come from the journal's
/// `EditApplied` records (already confined when they were written), and
/// this re-checks the shape before the map reads anything (fail closed).
fn plain_relative(rel: &str) -> bool {
    !rel.is_empty()
        && !rel.starts_with('/')
        && !rel
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
}

/// The repo map's text for a live build: the top files by (last edit's
/// step, edit count, path), outlined from their bytes. `None` when there
/// is nothing to show: no touched file, none readable, none with an
/// outline. Every read is bounded (1 MiB, UTF-8 only, no symlink), and a
/// file that cannot be shown is skipped — the map is a best-effort aid,
/// never a fact the run depends on.
pub(crate) fn build_live(root: &Path, marks: &[RestoreMark]) -> Option<String> {
    let files = touched_files(marks);
    let mut ranked: Vec<&TouchedFile> = files.iter().collect();
    ranked.sort_by(|a, b| {
        b.last_step
            .cmp(&a.last_step)
            .then(b.edits.cmp(&a.edits))
            .then(a.path.cmp(&b.path))
    });
    let mut out = String::new();
    let mut shown = 0usize;
    for f in ranked {
        if shown == REPO_MAP_MAX_FILES {
            break;
        }
        if !plain_relative(&f.path) {
            continue;
        }
        let path: PathBuf = root.join(&f.path);
        // No symlinks (the walk's own rule): a symlinked file is skipped.
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.is_file() => {}
            _ => continue,
        }
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if meta.len() > REPO_MAP_FILE_MAX_BYTES {
            continue;
        }
        let Ok(raw) = std::fs::read(&path) else {
            continue;
        };
        let Ok(text) = String::from_utf8(raw) else {
            continue;
        };
        if let Some(block) = harness_tools::outline::file_outline_text(&f.path, &text) {
            out.push_str(&block);
            shown += 1;
        }
    }
    if shown == 0 {
        return None;
    }
    Some(out)
}

/// The repo map as this build shows it: the recorded text when replaying
/// (re-fed, never recomputed), otherwise the live extraction. `Some(_)`
/// exactly when the context carries a map, so the `ContextBuilt` record's
/// `repo_map` payload is written exactly when the map is in the request.
pub(crate) fn for_build(
    feed: &mut RepoMapFeed,
    root: Option<&Path>,
    step: u64,
    marks: &[RestoreMark],
) -> Option<Untrusted<String>> {
    if let Some(text) = feed.take(step) {
        return Some(Untrusted::new(
            text,
            Source::Workspace(REPO_MAP_NAME.into()),
        ));
    }
    let root = root?;
    let text = build_live(root, marks)?;
    Some(Untrusted::new(
        text,
        Source::Workspace(REPO_MAP_NAME.into()),
    ))
}
