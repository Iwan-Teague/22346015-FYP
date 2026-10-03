//! Restore to an earlier workspace state (P-26): the `/undo` and
//! `/rewind N` of a session.
//!
//! The loop records a [`RestoreMark`] for every workspace state it knows
//! the journal carries — each user turn's measured tree, each verified
//! edit (with the pre-image digest its blob store keeps), and each
//! command's measured tree. An undo picks the last N edit groups, and the
//! tree checkpoint just before them is the target: every mark after it is
//! undone by replaying the edit records backwards, each file put back only
//! where it still holds the digest that edit produced (a restore never
//! clobbers a change the harness has not seen). The restored workspace's
//! tree digest must come back equal to the checkpoint's, or the undo stops
//! and reports what differs: fail closed.
//!
//! The whole move is journaled as one `Restored` record (the step and the
//! tree digest it went back to, and the files the undone edits named), and
//! the model is told through the same notice slot the other harness
//! messages use. An audit recomputes the record from the journal's own
//! edit records and the re-fed checkpoint — the blobs, never a live
//! workspace — so a replayed journal must carry the identical record or
//! the audit diverges.
//!
//! A refusal journals nothing (the replay never sees the command happened)
//! and the caller's interface shows why: a workspace that changed outside
//! the harness since the last record is refused, naming the files whose
//! digests left their journaled values. `--force-keep-external` skips that
//! refusal and restores only the harness-edited files that are still
//! untouched; the journal then names every file the undone edits had
//! touched, so the record stays deterministic either way.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use gate_outcome::Digest;
use harness_core::{Source, StopCause, Untrusted};
use harness_journal::reader::{BlobSource, DirBlobSource, Verified};
use harness_journal::{Event, EventKind, Trusted};
use harness_model::context::restored_notice_text;
use harness_tools::builtin::workspace_tree;
use harness_tools::Image;
use harness_tools::{recreate_file, restore_file, uncreate_file};
use serde_json::Value;

use crate::driver::step::{journal, Loop};

// ---------------------------------------------------------------------------
// The marks.
// ---------------------------------------------------------------------------

/// One workspace state the loop knows the journal carries, in journal
/// order: a tree checkpoint ([`RestoreMark::Tree`]) or one verified edit's
/// record ([`RestoreMark::Edit`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreMark {
    /// A checkpoint: a user turn's measured tree, or the tree a command's
    /// result was journaled with.
    Tree {
        /// The loop step the checkpoint was journaled at.
        step: u64,
        /// The tree digest measured (or re-fed) there.
        tree: Digest,
    },
    /// One `EditApplied`'s restorable parts: the file, the digests the
    /// edit moved between (`None` for a create's before, and for a
    /// delete's after), and the tree digest the journal recorded after
    /// it. The pre-image's bytes are in the attempt's blob store under
    /// `before`.
    Edit {
        /// The loop step the record was journaled at.
        step: u64,
        /// The tool call the edit belongs to: the edits of one call (a
        /// patch, a move) undo as one group.
        intent_seq: u64,
        /// The file's workspace-relative path.
        path: String,
        /// The digest before the edit (absent for a create).
        before: Option<Digest>,
        /// The digest after the edit (absent for a delete).
        after: Option<Digest>,
        /// The tree digest recorded after the edit.
        tree: Digest,
    },
}

/// The marks the loop has seen so far, in journal order. Rebuilt by every
/// mode that drives the loop (a live run, an audit, a resume's catch-up),
/// because the marks are read back from the loop's own edit records.
#[derive(Debug, Default)]
pub struct RestoreLog {
    marks: Vec<RestoreMark>,
}

impl RestoreLog {
    /// Record a tree checkpoint.
    pub(crate) fn push_tree(&mut self, step: u64, tree: Digest) {
        self.marks.push(RestoreMark::Tree { step, tree });
    }

    /// Record a verified edit's restorable parts.
    pub(crate) fn push_edit(
        &mut self,
        step: u64,
        intent_seq: u64,
        path: &str,
        before: Option<Digest>,
        after: Option<Digest>,
        tree: Digest,
    ) {
        self.marks.push(RestoreMark::Edit {
            step,
            intent_seq,
            path: path.to_owned(),
            before,
            after,
            tree,
        });
    }

    /// The marks so far, in journal order.
    pub(crate) fn marks(&self) -> &[RestoreMark] {
        &self.marks
    }

    /// Keep only the first `keep` marks: the journal now stands at the
    /// target checkpoint, so everything after it is undone.
    pub(crate) fn truncate(&mut self, keep: usize) {
        self.marks.truncate(keep);
    }
}

// ---------------------------------------------------------------------------
// The plan.
// ---------------------------------------------------------------------------

/// Why no plan was derived: nothing was refused on disk (nothing was
/// touched), there is just nothing this command can verify and undo.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RestorePlanRefused {
    /// Fewer edit groups than the command asks to undo (or none at all).
    #[error("nothing to undo")]
    NothingToUndo,
    /// The earliest undone edit has no tree checkpoint before it, so the
    /// restore could not be verified against a journaled state.
    #[error("no journaled state to restore to")]
    NoAnchor,
    /// The journal's records do not describe a restorable edit (a path or
    /// digest a record should carry is missing or unreadable).
    #[error("the journal's edit records are not restorable")]
    NotRestorable,
}

/// A derived restore: the checkpoint to go back to and the edits after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePlan {
    /// The loop step the target checkpoint was journaled at.
    pub to_step: u64,
    /// The tree digest the workspace must hold afterwards.
    pub tree_digest: Digest,
    /// The files the undone edits named, in journal order.
    pub files: Vec<String>,
    /// The index of the target checkpoint in the marks.
    pub target_idx: usize,
    /// The index of the earliest undone edit in the marks.
    pub first_undone: usize,
}

/// The plan for undoing the last `groups` edit groups: the target is the
/// tree checkpoint immediately before the earliest of them. Every mark
/// after the checkpoint is undone (a checkpoint in between names a state
/// the restore passes back through, not one to keep).
pub fn plan(marks: &[RestoreMark], groups: u64) -> Result<RestorePlan, RestorePlanRefused> {
    // A group starts at an edit mark whose predecessor is not an edit of
    // the same call: the records of one call are consecutive.
    let mut starts: Vec<usize> = Vec::new();
    for (i, m) in marks.iter().enumerate() {
        let RestoreMark::Edit {
            intent_seq: seq, ..
        } = m
        else {
            continue;
        };
        let same_call_before = matches!(
            i.checked_sub(1).and_then(|prev_at| marks.get(prev_at)),
            Some(RestoreMark::Edit {
                intent_seq: prev,
                ..
            }) if prev == seq
        );
        if !same_call_before {
            starts.push(i);
        }
    }
    let wanted = usize::try_from(groups).unwrap_or(usize::MAX);
    if wanted == 0 || starts.len() < wanted {
        return Err(RestorePlanRefused::NothingToUndo);
    }
    let Some(first) = starts
        .len()
        .checked_sub(wanted)
        .and_then(|at| starts.get(at))
    else {
        return Err(RestorePlanRefused::NothingToUndo);
    };
    let first = *first;
    let Some(RestoreMark::Tree { step, tree }) = first.checked_sub(1).and_then(|i| marks.get(i))
    else {
        return Err(RestorePlanRefused::NoAnchor);
    };
    let Some(undone) = marks.get(first..) else {
        return Err(RestorePlanRefused::NotRestorable);
    };
    let files = undone
        .iter()
        .filter_map(|m| match m {
            RestoreMark::Edit { path, .. } => Some(path.clone()),
            RestoreMark::Tree { .. } => None,
        })
        .collect();
    Ok(RestorePlan {
        to_step: *step,
        tree_digest: *tree,
        files,
        target_idx: first - 1,
        first_undone: first,
    })
}

/// The marks a verified journal describes, for a caller that reads a
/// session's journal itself (the CLI's pre-check): edit records, user
/// turns and command results in, marks out. A record whose path or tree
/// cannot be read back refuses the plan — fail closed, nothing is
/// restored from a journal that cannot be re-read.
pub fn marks_from_records(
    v: &Verified,
    blobs: &dyn BlobSource,
) -> Result<Vec<RestoreMark>, RestorePlanRefused> {
    let mut marks = Vec::new();
    for r in &v.records {
        match r.kind {
            EventKind::EditApplied => {
                let seq =
                    body_u64(&r.body, "intent_seq").ok_or(RestorePlanRefused::NotRestorable)?;
                let path = path_of(&r.body, blobs, r.seq)?;
                let before = body_digest(&r.body, "before");
                if r.body.contains_key("before") && before.is_none() {
                    return Err(RestorePlanRefused::NotRestorable);
                }
                let after = body_digest(&r.body, "after");
                if r.body.contains_key("after") && after.is_none() {
                    return Err(RestorePlanRefused::NotRestorable);
                }
                let tree = body_digest(&r.body, "workspace_tree")
                    .ok_or(RestorePlanRefused::NotRestorable)?;
                marks.push(RestoreMark::Edit {
                    step: r.step,
                    intent_seq: seq,
                    path,
                    before,
                    after,
                    tree,
                });
            }
            EventKind::UserTurn => {
                let tree = body_digest(&r.body, "workspace_tree")
                    .ok_or(RestorePlanRefused::NotRestorable)?;
                marks.push(RestoreMark::Tree { step: r.step, tree });
            }
            EventKind::ToolFinished => {
                if let Some(tree) = body_digest(&r.body, "workspace_tree") {
                    marks.push(RestoreMark::Tree { step: r.step, tree });
                }
            }
            _ => {}
        }
    }
    Ok(marks)
}

/// One file whose current state has left its last journaled digest: what
/// a refusal names, and what `--force-keep-external` keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Differ {
    /// The file's workspace-relative path.
    pub path: String,
    /// The last digest the journal carries (absent when the journal says
    /// the file was deleted).
    pub journaled: Option<Digest>,
    /// The digest the file holds now (absent when it is gone).
    pub found: Option<Digest>,
}

/// The files whose current state differs from their last journaled digest,
/// from the marks alone. A reporting helper (the CLI's refusal text): it
/// reads the workspace, decides nothing, and touches nothing.
pub fn external_differ(root: &Path, marks: &[RestoreMark]) -> Vec<Differ> {
    let mut known: BTreeMap<&str, Option<Digest>> = BTreeMap::new();
    for m in marks {
        if let RestoreMark::Edit { path, after, .. } = m {
            known.insert(path.as_str(), *after);
        }
    }
    known
        .into_iter()
        .filter_map(|(path, journaled)| {
            let found = current_digest(root, path);
            if found == journaled {
                None
            } else {
                Some(Differ {
                    path: path.to_owned(),
                    journaled,
                    found,
                })
            }
        })
        .collect()
}

/// The digest of the file at `path`, or `None` when it is not there. A
/// read for the report only: the workspace rule still bounds the path, and
/// nothing is ever written through here.
fn current_digest(root: &Path, path: &str) -> Option<Digest> {
    let wp = harness_policy::workspace_path(path).ok()?;
    let bytes = std::fs::read(root.join(wp.as_str())).ok()?;
    Some(harness_core::sha256(&bytes))
}

/// A record body's `u64` field.
fn body_u64(body: &serde_json::Map<String, Value>, key: &str) -> Option<u64> {
    body.get(key).and_then(Value::as_u64)
}

/// A record body's digest field: present, and a parseable digest.
fn body_digest(body: &serde_json::Map<String, Value>, key: &str) -> Option<Digest> {
    body.get(key)
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
}

/// A record body's untrusted path payload, read back and checked.
fn path_of(
    body: &serde_json::Map<String, Value>,
    blobs: &dyn BlobSource,
    seq: u64,
) -> Result<String, RestorePlanRefused> {
    use harness_model::replay::payload_bytes;
    let bytes = body
        .get("path")
        .ok_or(RestorePlanRefused::NotRestorable)
        .and_then(|p| {
            payload_bytes(p, blobs, seq).map_err(|_| RestorePlanRefused::NotRestorable)
        })?;
    String::from_utf8(bytes).map_err(|_| RestorePlanRefused::NotRestorable)
}

// ---------------------------------------------------------------------------
// The command.
// ---------------------------------------------------------------------------

/// A user's restore command (`/undo`, `/rewind N`): how many edit groups
/// to undo, and whether files changed outside the harness are kept rather
/// than refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreCommand {
    /// How many of the last edit groups to undo (1 is `/undo`).
    pub steps: u64,
    /// `--force-keep-external`: skip the changed-outside refusal, and
    /// restore only the files that still hold the digest their edit
    /// produced.
    pub keep_external: bool,
}

impl<'a> Loop<'a> {
    /// Run a live restore command between turns (P-26): plan it, refuse it
    /// when the workspace left the journal's state, otherwise replay the
    /// undone edits backwards through the verified restore primitives,
    /// journal the `Restored` record and tell the model through the next
    /// request's notice. Nothing is journaled unless the restore was
    /// applied: a refusal, and an undo stopped midway by a file that no
    /// longer holds its expected digest, leave the journal (and the
    /// replay) untouched — the caller's interface shows why, and the next
    /// turn's measurement names any change the harness did not make.
    pub(crate) fn restore_to_step<
        F: harness_journal::JournalFile,
        B: harness_journal::BlobSink,
        K: harness_journal::Clock,
    >(
        &mut self,
        w: &mut harness_journal::JournalWriter<F, B, K>,
        cmd: RestoreCommand,
    ) -> Result<(), StopCause> {
        let Some(u) = self.user.as_ref() else {
            // A batch run has no input channel, so no command reaches it.
            return Err(StopCause::PolicyAbort);
        };
        let Some(root) = u.root.clone() else {
            // No live workspace to verify against: fail closed.
            return Err(StopCause::PolicyAbort);
        };
        let plan = match plan(self.restore.marks(), cmd.steps) {
            Ok(p) => p,
            // Nothing to undo: nothing applied, nothing journaled, no
            // notice (the replay would otherwise have to re-derive a
            // message about a command it never saw).
            Err(RestorePlanRefused::NothingToUndo) => return Ok(()),
            Err(_) => return Err(StopCause::PolicyAbort),
        };
        // The changed-outside refusal: the workspace must still be at the
        // tree the journal's last record carries.
        if !cmd.keep_external {
            let deadline = Instant::now() + self.config.facts_timeout;
            let measured = workspace_tree(&root, deadline).map_err(|_| StopCause::PolicyAbort)?;
            if measured.facts().tree != self.tree {
                return Ok(());
            }
        }
        // Replay the undone edits backwards. Each file moves only where it
        // still holds the digest its edit produced (or is still absent,
        // for a delete's undo); under `--force-keep-external` such a file
        // is kept instead, and the tree is not verified afterwards (that
        // is the point of keeping).
        let blobs = DirBlobSource::new(u.blobs.clone());
        let strict = !cmd.keep_external;
        let mut applied: Vec<usize> = Vec::new();
        for i in (plan.first_undone..self.restore.marks().len()).rev() {
            let Some(mark) = self.restore.marks().get(i) else {
                continue;
            };
            let RestoreMark::Edit {
                path,
                before,
                after,
                ..
            } = mark.clone()
            else {
                continue;
            };
            if strict {
                // The trajectory: after undoing the later edits, the file
                // must sit at the tree digest this edit's record carries.
                let deadline = Instant::now() + self.config.facts_timeout;
                let measured =
                    workspace_tree(&root, deadline).map_err(|_| StopCause::PolicyAbort)?;
                let want = mark.edit_tree().ok_or(StopCause::PolicyAbort)?;
                if measured.facts().tree != want {
                    return Ok(());
                }
            }
            let done = match (before, after) {
                (Some(b), Some(a)) => match blobs.get(&b.to_string()) {
                    Some(bytes) => restore_file(&root, &path, &Image { sha256: b, bytes }, a),
                    None => Err(harness_tools::RestoreError::NotFound),
                },
                // A create's undo: the file must still be the one the
                // edit made.
                (None, Some(a)) => uncreate_file(&root, &path, a),
                // A delete's undo: the path must still be free.
                (Some(b), None) => match blobs.get(&b.to_string()) {
                    Some(bytes) => recreate_file(&root, &path, &Image { sha256: b, bytes }),
                    None => Err(harness_tools::RestoreError::NotFound),
                },
                // Neither digest: not a record this loop writes.
                (None, None) => return Err(StopCause::PolicyAbort),
            };
            match done {
                Ok(()) => applied.push(i),
                Err(
                    harness_tools::RestoreError::ChangedSince { .. }
                    | harness_tools::RestoreError::Exists,
                ) if !strict => {
                    // Kept: the file changed outside the harness, which is
                    // what this mode is for.
                }
                Err(_) => {
                    // A file no longer where its record left it: stop, keep
                    // what was already undone, journal nothing.
                    return Ok(());
                }
            }
        }
        if strict {
            let deadline = Instant::now() + self.config.facts_timeout;
            let measured = workspace_tree(&root, deadline).map_err(|_| StopCause::PolicyAbort)?;
            if measured.facts().tree != plan.tree_digest {
                return Ok(());
            }
        }
        self.journal_restored(w, plan.to_step, plan.tree_digest, &plan.files)?;
        self.restore.truncate(plan.target_idx + 1);
        Ok(())
    }

    /// Recompute a restore from the journal alone (an audit's replay, or a
    /// resume's catch-up): the re-fed checkpoint names the target, the
    /// marks name the edits after it, and the same `Restored` record must
    /// come out. No workspace is touched — the replay never had one.
    pub(crate) fn recompute_restore<
        F: harness_journal::JournalFile,
        B: harness_journal::BlobSink,
        K: harness_journal::Clock,
    >(
        &mut self,
        w: &mut harness_journal::JournalWriter<F, B, K>,
        to_step: u64,
        tree_digest: Digest,
    ) -> Result<(), StopCause> {
        let idx = self.restore.marks().iter().rposition(|m| {
            matches!(m, RestoreMark::Tree { step, tree } if *step == to_step && *tree == tree_digest)
        });
        let Some(target_idx) = idx else {
            // A checkpoint the journal does not carry: a record no replay
            // can recompute. The audit stops here and diverges.
            return Err(StopCause::PolicyAbort);
        };
        let Some(rest) = self.restore.marks().get(target_idx + 1..) else {
            // The marks stop before the checkpoint: a replay cannot
            // recompute the restore. The audit stops here and diverges.
            return Err(StopCause::PolicyAbort);
        };
        let files: Vec<String> = rest
            .iter()
            .filter_map(|m| match m {
                RestoreMark::Edit { path, .. } => Some(path.clone()),
                RestoreMark::Tree { .. } => None,
            })
            .collect();
        self.journal_restored(w, to_step, tree_digest, &files)?;
        self.restore.truncate(target_idx + 1);
        Ok(())
    }

    /// The `Restored` record and the model's notice: one place, so the
    /// live run and the recompute cannot drift.
    fn journal_restored<
        F: harness_journal::JournalFile,
        B: harness_journal::BlobSink,
        K: harness_journal::Clock,
    >(
        &mut self,
        w: &mut harness_journal::JournalWriter<F, B, K>,
        to_step: u64,
        tree_digest: Digest,
        files: &[String],
    ) -> Result<(), StopCause> {
        let payload = serde_json::to_string(&files).map_err(|_| StopCause::PolicyAbort)?;
        let f = w
            .untrusted(&Untrusted::new(payload, Source::Model))
            .map_err(journal)?;
        let ev = Event::new(EventKind::Restored)
            .field("to_step", Trusted::U64(to_step))
            .field("tree_digest", Trusted::Digest(tree_digest))
            .field("files", Trusted::Untrusted(f));
        w.append(self.step, ev).map_err(journal)?;
        // The model is told through the next request (the same slot the
        // other harness notices use): its later edits no longer stand.
        let text = restored_notice_text(files.len(), to_step);
        if let Some(t) = self.turns.last_mut().filter(|t| t.step == self.step) {
            t.notice = Some(match t.notice.take() {
                Some(prev) => prev.joined(&text),
                None => text,
            });
        }
        Ok(())
    }
}

impl RestoreMark {
    /// The tree digest the mark carries (an edit's after-tree, a
    /// checkpoint's own).
    pub(crate) fn edit_tree(&self) -> Option<Digest> {
        match self {
            RestoreMark::Tree { tree, .. } | RestoreMark::Edit { tree, .. } => Some(*tree),
        }
    }
}
