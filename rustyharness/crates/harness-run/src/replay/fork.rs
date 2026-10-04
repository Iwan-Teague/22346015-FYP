//! Fork (P-32): start a NEW session run whose first record, `ForkedFrom`,
//! names the parent run, the parent step forked at, and the parent's
//! chain head there. The child's context and workspace are reconstructed
//! by the same catch-up machinery a resume uses (P-17 §7): the parent's
//! kept records up to the fork step are re-fed — recorded replies, tool
//! results, edits, approvals and turn inputs — and the child then runs
//! live. The parent's journal is only read, never appended to.
//!
//! Fail closed:
//!
//! - the fork point must name a step the parent's LATEST attempt carries
//!   (a step in an earlier attempt is refused: this build re-feeds only
//!   one attempt's records), and must not sit at or after the session's
//!   end (`RunStopped`/`InputEnded` in the prefix): a fork continues a
//!   live conversation, it does not reopen a finished one;
//! - the workspace must hold the tree the kept records end with. Where a
//!   resume refuses a mismatch (this build keeps no content snapshot),
//!   a fork first tries the P-26 restore: the parent's edits after the
//!   fork point are undone backwards through the verified restore
//!   primitives, each file only where it still holds the digest its
//!   record carries. A restore that cannot be completed — or a tree that
//!   still differs — refuses the fork; the parent journal is untouched
//!   either way;
//! - the child's audit recomputes the parent's kept prefix and its chain
//!   head from the parent run's journal and refuses to pass a child
//!   whose recorded `parent_chain_head` no longer matches (see
//!   [`crate::replay::audit`]).
//!
//! The recorded `parent_step` is the last KEPT step (a fork at an
//! incomplete step keeps the step before it, as a resume keeps its
//! catch-up), so a fork and its child's audit derive the same prefix from
//! the same recorded fields.

use std::cell::Cell;
use std::path::Path;
use std::time::{Duration, Instant};

use harness_core::environment::EnvProbe;
use harness_core::{Digest, LoopDetector, RunId};
use harness_journal::reader::DirBlobSource;
use harness_journal::writer::SystemClock;
use harness_journal::{
    layout, BlobSource, Event, EventKind, Ident, JournalReader, JournalWriter, Record, Trusted,
    Verified,
};
use harness_manifest::admission::Registry;
use harness_model::context::Renderings;
use harness_model::profile::Profile;
use harness_model::replay::ReplayBackend;
use harness_model::{Completion, ModelBackend, ModelError, ModelIdentity, ModelRequest};
use harness_policy::locality::{self, LocalityProbe};
use harness_policy::{SessionKind, UserPolicy};
use serde_json::Value;

use crate::approve::{Approver, RecordedApproval};
use crate::driver::step::UserState;
use crate::driver::{
    attempt_check, commit, create_run, exec_tools, header, loop_facts, new_meter_resumed, prepare,
    todo_for, Approvals, BudgetNotices, ExecHeader, HeaderInputs, Loop, LoopInit, NonceSource,
    PortsHeader, Prepared, ReadLog, RepoMapFeed, WorkspaceModeRecord,
};
use crate::postedit::PostEditState;
use crate::presubmit::PresubmitState;
use crate::restore::{marks_from_records, RestoreMark};
use crate::session::{
    check_turn_limits, session_limits, EventSink, SessionConfig, SessionInputs, SessionReport,
    UserInput,
};
use crate::{RunRefused, RunReport, TaskSpec};

use super::audit::{attempts_desc, has_header, UNREADABLE};
use super::compare::{check_header, expected_inputs};
use super::feed::{digest_at, instructions_of, recorded, recorded_facts};

/// A backend that replays the recorded exchanges first, then goes live
/// (the same chain a resume runs; see [`super::resume`]).
struct Chain<'a> {
    replay: ReplayBackend,
    live: &'a dyn ModelBackend,
    diverged: Cell<bool>,
}

impl ModelBackend for Chain<'_> {
    fn identity(&self) -> ModelIdentity {
        self.live.identity()
    }

    fn complete(&self, req: &ModelRequest, deadline: Instant) -> Result<Completion, ModelError> {
        if self.replay.exhausted() {
            return self.live.complete(req, deadline);
        }
        let r = self.replay.complete(req, deadline);
        if matches!(r, Err(ModelError::ReplayDiverged { .. })) {
            self.diverged.set(true);
        }
        r
    }
}

fn not_resumable(w: impl Into<std::borrow::Cow<'static, str>>) -> RunRefused {
    RunRefused::NotResumable(w.into())
}

/// Why a parent prefix could not be re-derived (one place, so a fork and
/// its child's audit name the same reasons).
pub(crate) enum ParentRefused {
    /// No `runs/<parent>` directory.
    NoRun,
    /// No attempt with a durable header.
    NoAttempt,
    /// The latest attempt's journal does not verify.
    NotVerified,
    /// The fork step is not in the journal (a gap, or past its end).
    MissingStep,
    /// The session ended at or before the fork step.
    Ended,
}

/// The refusal a parent check stands for.
fn parent_refused(e: ParentRefused) -> RunRefused {
    match e {
        ParentRefused::NoRun => not_resumable("no such parent run directory"),
        ParentRefused::NoAttempt => {
            not_resumable("the parent run has no attempt with a durable header")
        }
        ParentRefused::NotVerified => {
            not_resumable("the parent's latest attempt's journal does not verify")
        }
        ParentRefused::MissingStep => {
            not_resumable("the fork point is not in the parent's latest attempt's journal")
        }
        ParentRefused::Ended => {
            not_resumable("the parent session ended at or before the fork point")
        }
    }
}

/// The parent's latest attempt that carries evidence (a resume's rule:
/// an attempt with no header, and a resumed attempt that stopped at its
/// header, are passed over), read back and verified.
fn parent_attempt(run_dir: &Path, parent: &RunId) -> Result<Verified, ParentRefused> {
    for n in attempts_desc(run_dir).map_err(|_| ParentRefused::NoRun)? {
        let dir = layout::attempt_dir(run_dir, n);
        if !has_header(&dir).map_err(|_| ParentRefused::NoRun)? {
            continue;
        }
        return JournalReader::open_expecting(&dir, parent).map_err(|_| ParentRefused::NotVerified);
    }
    Err(ParentRefused::NoAttempt)
}

/// The kept prefix of `v` at `parent_step` (a resume's kept rule applied
/// to the records up to the fork step) and its chain head: the last kept
/// record's hash, or the header's when the prefix keeps nothing (a fork
/// at the very start).
fn kept_prefix(v: &Verified, parent_step: u64) -> Result<(Vec<Record>, Digest), ParentRefused> {
    let ended = v
        .records
        .iter()
        .find(|x| x.step <= parent_step)
        .is_some_and(|x| matches!(x.kind, EventKind::RunStopped | EventKind::InputEnded));
    if ended {
        return Err(ParentRefused::Ended);
    }
    if !v.records.iter().any(|x| x.step == parent_step) {
        return Err(ParentRefused::MissingStep);
    }
    let last = v
        .records
        .iter()
        .filter(|x| x.step <= parent_step)
        .map(|x| x.step)
        .max()
        .unwrap_or(0);
    let last_done = v.records.iter().any(|x| {
        x.step == last && matches!(x.kind, EventKind::ToolFinished | EventKind::TurnEnded)
    });
    let kept: Vec<Record> = v
        .records
        .iter()
        .filter(|x| x.step <= parent_step && (x.step < last || (last_done && x.step == last)))
        .cloned()
        .collect();
    let head = match kept.last() {
        Some(r) => r.hash,
        None => v
            .records
            .first()
            .map(|h| h.hash)
            .ok_or(ParentRefused::NoAttempt)?,
    };
    Ok((kept, head))
}

/// Recompute a parent's kept-prefix chain head from its run directory
/// alone: what a fork records and what a child's audit re-derives. One
/// place, so the two cannot drift.
pub(crate) fn parent_prefix_head(
    state_root: &Path,
    parent: &RunId,
    parent_step: u64,
) -> Result<Digest, ParentRefused> {
    let run_dir = layout::run_dir(state_root, parent);
    match std::fs::symlink_metadata(&run_dir) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
        _ => return Err(ParentRefused::NoRun),
    }
    let v = parent_attempt(&run_dir, parent)?;
    kept_prefix(&v, parent_step).map(|(_, head)| head)
}

/// Undo the parent's edits after the fork step, so the workspace holds
/// the tree the kept records end with (the card's P-26 restore). Strict
/// and fail closed: every undone file must still hold the digest its
/// record carries (the verified restore primitives check, which also
/// refuses a state a later parent restore already undid), and the
/// re-measured tree must equal the target. Nothing is journaled either
/// way: a refusal is the caller's, before the child exists.
fn restore_workspace(
    root: &Path,
    v: &Verified,
    blobs: &dyn BlobSource,
    after_step: u64,
    target: Digest,
    timeout: Duration,
) -> Result<(), RunRefused> {
    let marks = marks_from_records(v, blobs)
        .map_err(|_| not_resumable("the parent's records cannot be read back as restore marks"))?;
    let undone: Vec<&RestoreMark> = marks
        .iter()
        .filter(|m| matches!(m, RestoreMark::Edit { step, .. } if *step > after_step))
        .collect();
    for m in undone.into_iter().rev() {
        let RestoreMark::Edit {
            path,
            before,
            after,
            ..
        } = m
        else {
            continue;
        };
        let done = match (before, after) {
            (Some(b), Some(a)) => match blobs.get(&b.to_string()) {
                Some(bytes) => harness_tools::restore_file(
                    root,
                    path,
                    &harness_tools::Image { sha256: *b, bytes },
                    *a,
                ),
                None => Err(harness_tools::RestoreError::NotFound),
            },
            // A create's undo: the file must still be the one the edit made.
            (None, Some(a)) => harness_tools::uncreate_file(root, path, *a),
            // A delete's undo: the path must still be free.
            (Some(b), None) => match blobs.get(&b.to_string()) {
                Some(bytes) => harness_tools::recreate_file(
                    root,
                    path,
                    &harness_tools::Image { sha256: *b, bytes },
                ),
                None => Err(harness_tools::RestoreError::NotFound),
            },
            // Neither digest: not a record this loop writes.
            (None, None) => {
                return Err(not_resumable("the parent's edit record is not restorable"))
            }
        };
        if done.is_err() {
            return Err(not_resumable(
                "the workspace could not be restored to the fork point (a file no longer holds \
                 the digest its record carries); the fork is refused, the parent journal is \
                 untouched",
            ));
        }
    }
    let measured = harness_tools::builtin::workspace_tree(root, Instant::now() + timeout)
        .map_err(RunRefused::Facts)?;
    if measured.facts().tree != target {
        return Err(not_resumable(
            "the workspace still differs from the parent's records at the fork point after the \
             restore; the fork is refused",
        ));
    }
    Ok(())
}

/// What [`fork_session`] needs (P-32): a session's inputs plus the parent
/// run and the step to fork at.
pub struct ForkSession<'a> {
    /// The state root.
    pub state_root: &'a Path,
    /// The run to fork from. Its journal is only read.
    pub parent: &'a RunId,
    /// The parent step to fork at: the child continues from the context
    /// and workspace the parent's kept records up to this step carry.
    pub parent_step: u64,
    /// The workspace the child works in. It must hold (or be restorable
    /// to) the tree the kept records end with. `None` is refused: a fork
    /// continues a coding session, and this build does not fork research
    /// sessions.
    pub workspace: Option<&'a Path>,
    /// The task spec (must match the parent's recorded header).
    pub spec: &'a TaskSpec,
    /// Admitted providers.
    pub registry: &'a Registry,
    /// User policy (must match the parent's recorded header).
    pub policy: &'a UserPolicy,
    /// The model profile (must match the parent's recorded header).
    pub profile: &'a Profile,
    /// The live model backend.
    pub backend: &'a dyn ModelBackend,
    /// The locality probe.
    pub probe: &'a dyn LocalityProbe,
    /// The environment probe (§7.1).
    pub env: &'a dyn EnvProbe,
    /// Budgets, timeouts and the child's turn limits. The budget limits
    /// must equal the parent's recorded ones; the turn limits are the
    /// child session's own (the conversation restarts its turn count).
    pub config: &'a SessionConfig,
    /// Who the child asks for its first message once the catch-up has
    /// re-fed the parent's kept turns.
    pub input: &'a dyn UserInput,
    /// Who answers an ask (§5.3). Present exactly when the parent had one
    /// (the header's `approver_present`), or the fork is refused.
    pub approver: Option<&'a dyn Approver>,
    /// Where the child's records are shown as they are written; `None`
    /// shows nothing.
    pub sink: Option<&'a dyn EventSink>,
    /// Where commands are confined after the catch-up (H2d).
    pub confinement: Option<&'a dyn harness_sandbox::Confinement>,
}

/// Fork a session (P-32): a new run whose first record is `ForkedFrom`,
/// whose catch-up re-feeds the parent's kept records up to the fork step,
/// and whose live part starts where they end. `Err` means the child did
/// not start; the parent journal is untouched either way.
pub fn fork_session(f: ForkSession<'_>) -> Result<SessionReport, RunRefused> {
    // A fork continues a coding session's conversation in a workspace;
    // research sessions have neither.
    if let SessionKind::Research(_) = f.spec.kind {
        return Err(RunRefused::Research(
            "a research session cannot be forked in this build",
        ));
    }
    check_turn_limits(f.config)?;
    let limits = session_limits(f.config);

    // ---- Before anything is written. `prepare` measures the workspace
    // as it is NOW (the fork-point check below runs against it). ----
    let pre = prepare(
        f.spec,
        f.registry,
        f.policy,
        f.profile,
        f.workspace,
        f.state_root,
        f.probe,
        &f.config.run,
        f.approver.is_some(),
        f.confinement,
        f.backend.identity().endpoint,
    )?;
    let parent_dir = layout::run_dir(&pre.state_root, f.parent);
    match std::fs::symlink_metadata(&parent_dir) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
        _ => return Err(not_resumable("no such parent run directory")),
    }
    let v = parent_attempt(&parent_dir, f.parent).map_err(parent_refused)?;
    let head = v
        .records
        .first()
        .ok_or_else(|| not_resumable("the parent's latest attempt has no header"))?;
    // The project instructions (P-30): parsed from the journal before the
    // header check, so the header's `instructions` digest can be
    // recomputed from exactly what the journal carries. A shape this loop
    // does not write refuses the fork, like any bad record.
    let attempt_dir = layout::attempt_dir(
        &parent_dir,
        u32::try_from(v.attempt)
            .map_err(|_| not_resumable("the parent attempt number is out of range"))?,
    );
    let blobs = DirBlobSource::new(attempt_dir.join(layout::BLOBS_DIR));
    let recorded_instructions = instructions_of(&v, &blobs).map_err(|d| not_resumable(d.why))?;
    // The parent's recorded header inputs must equal this fork's (the
    // same task, policy, profile, limits), as a resume's must (H1
    // phase-exit review F-1): the catch-up re-renders the recorded
    // requests, and they only render as recorded when the inputs are the
    // same. The port grant is recomputed with a fresh probe.
    let ports_header = PortsHeader::of(f.spec, &f.config.run, pre.ports.as_ref());
    check_header(
        head,
        &expected_inputs(
            f.spec,
            f.registry,
            f.policy,
            f.profile,
            &limits,
            Some(&f.config.turn),
            ports_header.as_ref(),
            recorded_instructions.as_ref(),
        ),
    )
    .map_err(|d| not_resumable(d.why))?;
    if head.body.get("approver_present").and_then(Value::as_bool) != Some(f.approver.is_some()) {
        return Err(not_resumable(
            "the approver differs from the parent's recorded header: a session started with an \
             approver forks with one, and one started without forks without",
        ));
    }
    // ---- The fork point: a step the journal carries, before the
    // session's end. The kept prefix is the catch-up: the records up to
    // the fork step, minus an incomplete last one (a resume's kept
    // rule). ----
    let (kept, parent_chain_head) = kept_prefix(&v, f.parent_step).map_err(|e| match e {
        ParentRefused::Ended => not_resumable(
            "the parent session ended at or before the fork point; a fork continues a live \
             session, it does not reopen a finished one",
        ),
        ParentRefused::MissingStep => {
            not_resumable(format!("no step {} in the parent journal", f.parent_step))
        }
        ParentRefused::NoAttempt => not_resumable("the parent's latest attempt has no header"),
        ParentRefused::NoRun | ParentRefused::NotVerified => {
            not_resumable("the parent's journal could not be read back")
        }
    })?;
    // The kept prefix as a verified journal: what the catch-up re-feeds.
    let kept_v = Verified {
        records: kept,
        torn_tail: None,
        head: v.head,
        run: v.run.clone(),
        attempt: v.attempt,
    };
    let Some(start) = recorded_facts(head) else {
        return Err(not_resumable(
            "the parent's header lacks the workspace facts",
        ));
    };
    // ---- The workspace at the fork point: the last tree digest a kept
    // record states (a turn start's measurement, an edit's, a command's,
    // or a restore's), or the parent's start tree. Unlike a resume (which
    // only refuses), a fork first tries the P-26 undo of the parent's
    // edits after the fork point; a tree that still differs refuses.
    let expected = kept_v
        .records
        .iter()
        .rev()
        .filter(|x| {
            matches!(
                x.kind,
                EventKind::EditApplied
                    | EventKind::ToolFinished
                    | EventKind::Restored
                    | EventKind::UserTurn
            )
        })
        .find_map(|x| {
            digest_at(&x.body, "workspace_tree").or_else(|| digest_at(&x.body, "tree_digest"))
        })
        .unwrap_or(start.tree);
    if pre.tree.is_some() && pre.facts.tree != expected {
        let Some(root) = f.workspace else {
            return Err(not_resumable(
                "the workspace differs from the parent's records at the fork point",
            ));
        };
        let kept_through = kept_v.records.iter().map(|x| x.step).max().unwrap_or(0);
        restore_workspace(
            root,
            &v,
            &blobs,
            kept_through,
            expected,
            f.config.run.facts_timeout,
        )?;
    }
    // The allowlisted programs must be the ones the parent started with
    // (H2d): their content was measured then and is measured again now.
    if let Some((p, _)) = &pre.exec {
        if digest_at(&head.body, "exec_programs_sha256") != Some(p.programs_digest()) {
            return Err(not_resumable(
                "the allowlisted programs differ from the ones the parent started with (their \
                 content digest changed)",
            ));
        }
    }
    let rec = recorded(&kept_v, &blobs, f.profile)
        .map_err(|_| not_resumable("the parent's records cannot be replayed"))?;
    // The last step the catch-up re-feeds (H2e: its wall notices too); it
    // is also the fork step the record names (a fork at an incomplete
    // step keeps the step before it, so what is recorded is what was
    // kept).
    let kept_through = kept_v.records.iter().map(|x| x.step).max().unwrap_or(0);
    // The wall time already spent: the parent's own carried-in time, plus
    // what its kept records measure (the same computation a resume
    // makes; the waits between turns count for nothing).
    let carried_ms = match kept_v
        .records
        .iter()
        .rev()
        .find(|x| x.kind == EventKind::UserTurn)
    {
        Some(u) => {
            let wall = u
                .body
                .get("wall_used_ms")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let since = kept_v
                .records
                .last()
                .map_or(0, |x| x.t_mono_ms)
                .saturating_sub(u.t_mono_ms);
            wall.saturating_add(since)
        }
        None => head
            .body
            .get("resumed_from")
            .and_then(|f| f.get("wall_carried_ms"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
    };
    // The workspace-mode record (P-52): the child names the same scratch
    // copy, re-stated from the parent's header. A recorded value that is
    // not one this build writes refuses the fork.
    let workspace_mode = match head.body.get("workspace_mode") {
        Some(v) => match WorkspaceModeRecord::parse(v) {
            Some(m) => Some(m),
            None => {
                return Err(not_resumable(
                    "the parent header's workspace-mode record is not one this build writes",
                ))
            }
        },
        None => None,
    };

    // ---- The child: its own run, its own header, the `ForkedFrom`
    // record first. ----
    let (run_id, run_dir) = create_run(&pre.state_root)?;
    if let Some(str) = run_dir.to_str() {
        locality::check(f.probe, str)?;
    }
    let exec_header = pre
        .exec
        .as_ref()
        .map(|(p, w)| ExecHeader::live(p, w, &f.config.run));
    let exec_tools = exec_tools(&pre, &run_dir, f.confinement, &f.config.run)?;
    let hdr = header(&HeaderInputs {
        spec: f.spec,
        registry: f.registry,
        policy: f.policy,
        profile: f.profile,
        identity: &f.backend.identity(),
        facts: start,
        limits: &limits,
        resumed_from: None,
        environment: f.env.sample(),
        environment_recorded: false,
        approver_present: f.approver.is_some(),
        session: Some(f.config.turn),
        exec: exec_header,
        ports: ports_header,
        instructions: recorded_instructions.as_ref(),
        workspace_mode: workspace_mode.as_ref(),
        parent: None,
        child: None,
    })?;
    let (mut w, attempt) = JournalWriter::create_next_attempt_checked(
        &run_dir,
        run_id.clone(),
        hdr,
        &attempt_check(f.probe),
    )?;
    // The link: the parent run, the fork step kept, and the parent's
    // chain head there — the head a child's audit recomputes the parent's
    // prefix against.
    let parent_id = Ident::from_trusted(f.parent).ok_or(not_resumable(
        "the parent run id is not a journaled identifier",
    ))?;
    let ev = Event::new(EventKind::ForkedFrom)
        .field("parent_run", Trusted::Id(parent_id))
        .field("parent_step", Trusted::U64(kept_through))
        .field("parent_chain_head", Trusted::Digest(parent_chain_head));
    w.append(0, ev).map_err(|e| {
        RunRefused::Start(harness_journal::StartError {
            op: "the ForkedFrom record",
            error: e.to_string(),
        })
    })?;
    // The UI drain (P-05 §1.3), as for any session.
    if f.sink.is_some() {
        w.enable_tap();
    }
    let child_blobs = layout::attempt_dir(&run_dir, attempt).join(layout::BLOBS_DIR);
    let chain = Chain {
        replay: rec.backend,
        live: f.backend,
        diverged: Cell::new(false),
    };
    // A recorded `RuleGranted` re-applies exactly as it was granted
    // (P-23), whether or not this fork opted in again; an opt-in also
    // lets new `a`/`d` answers grant. The edit previews come from the
    // re-planned tools.
    let edit_tools = pre.edit_tools.clone();
    let granted = rec.approvals.iter().any(|a| {
        matches!(
            a,
            RecordedApproval::AllowSession { .. } | RecordedApproval::DenySession { .. }
        )
    });
    let mut lp = Loop::new(LoopInit {
        session: pre.session,
        registry: f.registry,
        tools: pre.tools,
        task: &f.spec.task,
        facts: loop_facts(&start, f.spec),
        profile: f.profile,
        backend: &chain,
        providers: Prepared::providers(pre.read_tools, pre.edit_tools, pre.patch_tools, exec_tools),
        meter: new_meter_resumed(
            limits.clone(),
            f.profile.pricing(),
            Box::new(SystemClock::default()),
            Duration::from_millis(carried_ms),
        ),
        detector: LoopDetector::new(),
        turns: Vec::new(),
        config: &f.config.run,
        step: 0,
        nonces: NonceSource {
            recorded: rec.nonces,
            assigned: Renderings::new(),
        },
        feed: rec.feed,
        reads: ReadLog::default(),
        // The catch-up re-feeds each recorded edit's tree digest; the
        // listing measured now (restored, or checked) already holds every
        // one of them.
        tree: start.tree,
        workspace: pre.tree,
        research: false,
        approvals: Approvals::new(&run_id, attempt, f.approver, rec.approvals)
            .may_grant(f.config.run.allow_session_grants || granted)
            .with_edits(edit_tools),
        env: f.env,
        pressure: Vec::new(),
        reads_seen: Default::default(),
        todo: todo_for(&f.spec.grants),
        // The kept steps' wall notices are re-fed; the live steps after
        // them measure the meter, which carries the parent's working wall.
        notices: BudgetNotices {
            wall_limit: f.config.run.limits.wall,
            recorded: rec.walls,
            recorded_through: kept_through,
            wall_announced: 0,
        },
        presubmit: PresubmitState::of(&f.spec.presubmit),
        post_edit: PostEditState::of(&f.spec.post_edit),
        workspace_root: f.workspace.map(std::path::Path::to_path_buf),
        restore: Default::default(),
        // The kept steps' repo maps are re-fed (P-33); the child's live
        // steps compute from the touched files, like any live run.
        repo_feed: RepoMapFeed::re_feed(rec.repo_maps, kept_through),
        // The forked session re-derives the instructions from the parent's
        // journal (P-30) and rewrites the identical `InstructionsLoaded`
        // record in its catch-up, before any recorded input.
        instructions: recorded_instructions.as_ref(),
        // The child opens turns: the catch-up re-feeds the kept turns'
        // inputs, then the live source is asked for the child's own first
        // message.
        user: Some(UserState {
            limits: f.config.turn,
            turn: 1,
            allowance: 0,
            used: 0,
            users: Vec::new(),
            deliverable: None,
            root: f.workspace.map(std::path::Path::to_path_buf),
            blobs: child_blobs,
            sink: f.sink,
        }),
        // A resumed session cannot delegate yet: the reconstruction slice
        // rebuilds the context (P-38f); until then the branch fails closed.
        delegate: None,
    });
    let end = lp.drive_session(
        &mut w,
        SessionInputs::Resume {
            recorded: rec.inputs,
            live: f.input,
        },
        f.config.input_timeout,
    );
    let turns = lp.user.as_ref().map_or(0, |u| u.turn.saturating_sub(1));
    let outcome = chain.diverged.get().then_some(UNREADABLE);
    let released = commit(w, &end, outcome);
    Ok(SessionReport {
        run: RunReport {
            run: run_id,
            attempt,
            run_dir,
            cause: end.cause,
            outcome: released.outcome,
            chain_head: released.chain_head,
            steps: end.step,
            journal_error: released.error,
            possibly_environmental: lp.pressure,
            presubmit: lp.presubmit.as_ref().map(PresubmitState::report),
            post_edit: lp.post_edit.as_ref().map(PostEditState::report),
        },
        turns,
    })
}
