//! Resume (design §2.10): continue an attempt that has no `RunStopped`
//! (a crash or a kill) in a NEW attempt directory, replaying every
//! completed step as catch-up (see the [`crate::replay`] module docs).

use std::cell::Cell;
use std::path::Path;
use std::time::{Duration, Instant};

use harness_core::environment::EnvProbe;
use harness_core::{LoopDetector, RunId};
use harness_journal::reader::DirBlobSource;
use harness_journal::writer::SystemClock;
use harness_journal::{layout, EventKind, JournalReader, JournalWriter, Verified};
use harness_manifest::admission::Registry;
use harness_model::context::Renderings;
use harness_model::profile::Profile;
use harness_model::replay::ReplayBackend;
use harness_model::{Completion, ModelBackend, ModelError, ModelIdentity, ModelRequest};
use harness_policy::locality::LocalityProbe;
use harness_policy::{SessionKind, UserPolicy};
use serde_json::Value;

use crate::approve::{Approver, RecordedApproval};
use crate::driver::step::UserState;
use crate::driver::{
    attempt_check, commit, exec_tools, header, loop_facts, new_meter_resumed, prepare, todo_for,
    Approvals, BudgetNotices, ExecHeader, HeaderInputs, Loop, LoopInit, NonceSource, PortsHeader,
    Prepared, ReadLog, WorkspaceModeRecord,
};
use crate::postedit::PostEditState;
use crate::presubmit::PresubmitState;
use crate::session::{
    check_turn_limits, session_limits, EventSink, SessionConfig, SessionInputs, SessionReport,
    UserInput,
};
use crate::{RunConfig, RunRefused, RunReport, TaskSpec};

use super::audit::{attempts_desc, has_header, UNREADABLE};
use super::compare::{check_header, expected_inputs};
use super::feed::{digest_at, instructions_of, recorded, recorded_facts};

/// A backend that replays the recorded exchanges first, then goes live. A
/// replayed request that differs from the recorded one (a divergence) is
/// remembered; the resumed run's outcome is then unreadable evidence.
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

/// What [`resume`] needs: [`crate::Run`]'s inputs plus the run to resume.
pub struct Resume<'a> {
    /// The state root.
    pub state_root: &'a Path,
    /// The run to resume.
    pub run: &'a RunId,
    /// The workspace. It must be exactly as the interrupted attempt's last
    /// durable record left it (the tree digest after its last recorded
    /// edit, or at its start), or the resume is refused. A research session
    /// (P-39i) has no workspace: `None` (and `Some` is refused by
    /// `prepare`).
    pub workspace: Option<&'a Path>,
    /// The task spec (must match the recorded header).
    pub spec: &'a TaskSpec,
    /// Admitted providers.
    pub registry: &'a Registry,
    /// User policy (must match the recorded header).
    pub policy: &'a UserPolicy,
    /// The model profile (must match the recorded header).
    pub profile: &'a Profile,
    /// The live model backend.
    pub backend: &'a dyn ModelBackend,
    /// The locality probe.
    pub probe: &'a dyn LocalityProbe,
    /// The environment probe (§7.1).
    pub env: &'a dyn EnvProbe,
    /// Budgets and timeouts. The limits must equal the recorded ones (the
    /// resume is refused otherwise, never adopting the journal's: H1
    /// phase-exit review F-1).
    pub config: &'a RunConfig,
    /// Who answers an ask after the catch-up (§5.3). Present exactly when
    /// the interrupted run had one (the header's `approver_present`), or the
    /// resume is refused: it decides every ask.
    pub approver: Option<&'a dyn Approver>,
    /// Where commands are confined after the catch-up (H2d): a run with an
    /// exec grant needs a witness again, obtained before anything is
    /// written; the catch-up itself never runs a recorded command again.
    pub confinement: Option<&'a dyn harness_sandbox::Confinement>,
}

/// The attempt a resume continues: the latest one holding evidence. Passed
/// over, highest first: an attempt with no header (a start that failed:
/// H1 phase-exit review F-5), and a resumed attempt that stopped before
/// its first step (a header alone: nothing of the attempt it continued was
/// re-recorded there, so resuming it would lose that attempt's steps).
/// A resume refusal that names what it saw (`Cow`: a session's stop cause
/// is read back from the journal, so the message may be owned).
fn not_resumable(w: impl Into<std::borrow::Cow<'static, str>>) -> RunRefused {
    RunRefused::NotResumable(w.into())
}

fn resumable_attempt(run_dir: &Path, run: &RunId) -> Result<(u32, Verified, Vec<u32>), RunRefused> {
    let mut skipped = Vec::new();
    for n in attempts_desc(run_dir).map_err(RunRefused::RunDir)? {
        let dir = layout::attempt_dir(run_dir, n);
        if !has_header(&dir).map_err(RunRefused::RunDir)? {
            skipped.push(n);
            continue;
        }
        let v = JournalReader::open_expecting(&dir, run)
            .map_err(|_| not_resumable("the last attempt's journal does not verify"))?;
        let only_header = v.records.len() == 1;
        let resumed = v
            .records
            .first()
            .is_some_and(|h| h.body.contains_key("resumed_from"));
        if only_header && resumed {
            skipped.push(n);
            continue;
        }
        return Ok((n, v, skipped));
    }
    Err(not_resumable(
        "the run has no attempt with a durable header",
    ))
}

/// Resume an interrupted run in a new attempt (see the module docs).
pub fn resume(r: Resume<'_>) -> Result<RunReport, RunRefused> {
    // A research session (P-39i) is a session: it resumes with
    // `resume_session`, whose loop carries the conversation.
    if let SessionKind::Research(_) = r.spec.kind {
        return Err(not_resumable(
            "a research session is not resumed as a batch run; resume it with resume_session",
        ));
    }
    let pre = prepare(
        r.spec,
        r.registry,
        r.policy,
        r.profile,
        r.workspace,
        r.state_root,
        r.probe,
        r.config,
        r.approver.is_some(),
        r.confinement,
        r.backend.identity().endpoint,
    )?;
    let run_dir = layout::run_dir(&pre.state_root, r.run);
    match std::fs::symlink_metadata(&run_dir) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
        _ => return Err(not_resumable("no such run directory")),
    }
    let (n, v, skipped) = resumable_attempt(&run_dir, r.run)?;
    let attempt_dir = layout::attempt_dir(&run_dir, n);
    if v.records.iter().any(|x| x.kind == EventKind::RunStopped) {
        return Err(not_resumable(
            "the run already stopped; there is nothing to resume",
        ));
    }
    let head = v
        .records
        .first()
        .ok_or(not_resumable("the last attempt has no header"))?;
    // The limits included: a resume runs under the caller's limits, which
    // must be the recorded ones (H1 phase-exit review F-1). The port grant
    // (P-36g §6.1) is recomputed with a fresh probe: the ports and the
    // reserved list must match the recorded ones, and so must what the
    // probe observes now.
    let ports_header = PortsHeader::of(r.spec, r.config, pre.ports.as_ref());
    // A batch run loads no project instructions (P-30): `None` recomputes
    // a header without the key, and a journal that carries one (or the
    // record) is refused.
    check_header(
        head,
        &expected_inputs(
            r.spec,
            r.registry,
            r.policy,
            r.profile,
            &r.config.limits,
            None,
            ports_header.as_ref(),
            None,
        ),
    )
    .map_err(|d| not_resumable(d.why))?;
    if head.body.get("approver_present").and_then(Value::as_bool) != Some(r.approver.is_some()) {
        return Err(not_resumable(
            "the approver differs from the recorded header: a run started with an approver \
             resumes with one, and one started without resumes without",
        ));
    }
    // The catch-up covers every step whose tool call finished (H2b, the
    // H1e-2b row's H2 condition): a step with a durable `ToolFinished` is
    // complete, so its result is re-fed, never run again, and a completed
    // edit is never repeated. Every earlier step is complete too. Only the
    // last step, when its call has no result (the crash cut it: a trailing
    // intent, or no call yet), runs again live, and policy decides it
    // again.
    let last = v.records.iter().map(|x| x.step).max().unwrap_or(0);
    let last_done = v
        .records
        .iter()
        .any(|x| x.step == last && x.kind == EventKind::ToolFinished);
    let kept = Verified {
        records: v
            .records
            .iter()
            .filter(|x| x.step < last || (last_done && x.step == last))
            .cloned()
            .collect(),
        torn_tail: None,
        head: v.head,
        run: v.run.clone(),
        attempt: v.attempt,
    };
    // The workspace must be as the kept records leave it: the tree digest
    // after the last recorded edit, or the attempt's own at its start. The
    // harness keeps no content snapshot to restore (materialisation, H2),
    // so an edit applied without a durable result, or a change made
    // outside the run, refuses the resume instead of being built on.
    let Some(start) = recorded_facts(head) else {
        return Err(not_resumable(
            "the last attempt's header lacks the workspace facts",
        ));
    };
    // The last tree digest a kept record states: an edit's `EditApplied`,
    // or a command's `ToolFinished` (H2d: measured after the command), or
    // a post-edit check's rollback (P-27, whose `Restored` names the tree
    // it put back).
    let expected = kept
        .records
        .iter()
        .rev()
        .filter(|x| {
            matches!(
                x.kind,
                EventKind::EditApplied | EventKind::ToolFinished | EventKind::Restored
            )
        })
        .find_map(|x| {
            digest_at(&x.body, "workspace_tree").or_else(|| digest_at(&x.body, "tree_digest"))
        })
        .unwrap_or(start.tree);
    // A research session (P-39i) has no workspace to check against, so the
    // tree check is skipped (`pre.tree` is `None`; its facts are the
    // no-workspace facts, which the header recorded unchanged).
    if pre.tree.is_some() && pre.facts.tree != expected {
        return Err(not_resumable(
            "the workspace differs from the interrupted attempt's last durable record (an edit \
             applied without its result, or a change made outside the run); this build keeps no \
             snapshot to restore",
        ));
    }
    // The allowlisted programs must be the ones the run started with (H2d):
    // their content was measured then and is measured again now.
    if let Some((p, _)) = &pre.exec {
        if digest_at(&head.body, "exec_programs_sha256") != Some(p.programs_digest()) {
            return Err(not_resumable(
                "the allowlisted programs differ from the ones the run started with (their content digest changed)",
            ));
        }
    }
    let blobs = DirBlobSource::new(attempt_dir.join(layout::BLOBS_DIR));
    let rec = recorded(&kept, &blobs, r.profile)
        .map_err(|_| not_resumable("the last attempt's records cannot be replayed"))?;
    // The last step the catch-up re-feeds (H2e: its wall notices too).
    let kept_through = kept.records.iter().map(|x| x.step).max().unwrap_or(0);
    // The wall time already spent: what the old attempt carried in (itself
    // a resumed attempt, H1e-2b confirming review NF-1) plus what its own
    // writer measured (its last record's monotonic time).
    let carried_in = head
        .body
        .get("resumed_from")
        .and_then(|f| f.get("wall_carried_ms"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let carried_ms = carried_in.saturating_add(v.records.last().map_or(0, |x| x.t_mono_ms));
    // The facts of block 4 are the run's, measured at its start and
    // carried from attempt to attempt, so the catch-up renders every
    // recorded request byte for byte; the workspace as it is now was
    // checked against the journal above.
    // The workspace-mode record (P-52): the resumed attempt names the
    // same scratch copy, re-stated from the recorded header. A recorded
    // value that is not one this build writes refuses the resume.
    let workspace_mode = match head.body.get("workspace_mode") {
        Some(v) => match WorkspaceModeRecord::parse(v) {
            Some(m) => Some(m),
            None => {
                return Err(not_resumable(
                    "the header's workspace-mode record is not one this build writes",
                ))
            }
        },
        None => None,
    };
    let hdr = header(&HeaderInputs {
        spec: r.spec,
        registry: r.registry,
        policy: r.policy,
        profile: r.profile,
        identity: &r.backend.identity(),
        facts: start,
        limits: &r.config.limits,
        resumed_from: Some((n, v.head, carried_ms, skipped)),
        environment: r.env.sample(),
        environment_recorded: false,
        approver_present: r.approver.is_some(),
        session: None,
        exec: pre
            .exec
            .as_ref()
            .map(|(p, w)| ExecHeader::live(p, w, r.config)),
        ports: ports_header,
        instructions: None,
        workspace_mode: workspace_mode.as_ref(),
        parent: None,
        child: None,
    })?;
    let exec = exec_tools(&pre, &run_dir, r.confinement, r.config)?;
    let (mut w, attempt) = JournalWriter::create_next_attempt_checked(
        &run_dir,
        r.run.clone(),
        hdr,
        &attempt_check(r.probe),
    )?;
    let chain = Chain {
        replay: rec.backend,
        live: r.backend,
        diverged: Cell::new(false),
    };
    // A recorded `RuleGranted` re-applies exactly as it was granted (P-23),
    // whether or not this resume opted in again; an opt-in also lets new
    // `a`/`d` answers grant. The edit previews come from the re-planned
    // tools.
    let edit_tools = pre.edit_tools.clone();
    let granted = rec.approvals.iter().any(|a| {
        matches!(
            a,
            RecordedApproval::AllowSession { .. } | RecordedApproval::DenySession { .. }
        )
    });
    let mut lp = Loop::new(LoopInit {
        session: pre.session,
        registry: r.registry,
        tools: pre.tools,
        task: &r.spec.task,
        facts: loop_facts(&start, r.spec),
        profile: r.profile,
        backend: &chain,
        providers: Prepared::providers(pre.read_tools, pre.edit_tools, pre.patch_tools, exec),
        meter: new_meter_resumed(
            r.config.limits.clone(),
            r.profile.pricing(),
            Box::new(SystemClock::default()),
            Duration::from_millis(carried_ms),
        ),
        detector: LoopDetector::new(),
        turns: Vec::new(),
        config: r.config,
        step: 0,
        nonces: NonceSource {
            recorded: rec.nonces,
            assigned: Renderings::new(),
        },
        feed: rec.feed,
        reads: ReadLog::default(),
        // The catch-up re-feeds each recorded edit's tree digest; the
        // listing measured now already holds every one of them.
        tree: start.tree,
        workspace: pre.tree,
        research: false,
        approvals: Approvals::new(r.run, attempt, r.approver, rec.approvals)
            .may_grant(r.config.allow_session_grants || granted)
            .with_edits(edit_tools),
        env: r.env,
        pressure: Vec::new(),
        reads_seen: Default::default(),
        todo: todo_for(&r.spec.grants),
        // The kept steps' wall notices are re-fed; the live steps after them
        // measure the meter, which carries the wall time already spent.
        notices: BudgetNotices {
            wall_limit: r.config.limits.wall,
            recorded: rec.walls,
            recorded_through: kept_through,
            wall_announced: 0,
        },
        presubmit: PresubmitState::of(&r.spec.presubmit),
        post_edit: PostEditState::of(&r.spec.post_edit),
        workspace_root: r.workspace.map(std::path::Path::to_path_buf),
        restore: Default::default(),
        instructions: None,
        user: None,
    });
    let end = lp.drive(&mut w);
    let outcome = chain.diverged.get().then_some(UNREADABLE);
    let released = commit(w, &end, outcome);
    Ok(RunReport {
        run: r.run.clone(),
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
    })
}

/// What [`resume_session`] needs (P-17 §7): a session's inputs — its
/// config carries the turn limits — plus who is asked for the next
/// message, and where the records are shown.
pub struct ResumeSession<'a> {
    /// The state root.
    pub state_root: &'a Path,
    /// The run to resume.
    pub run: &'a RunId,
    /// The workspace. Mid-turn it must be exactly as the kept records
    /// left it (the tree digest after the turn's last recorded edit,
    /// command or turn start); at a turn boundary it may have changed —
    /// the next turn measures it and says so. A research session (P-39i)
    /// has no workspace: `None`, and no tree check is made at a turn
    /// start.
    pub workspace: Option<&'a Path>,
    /// The task spec (must match the recorded header).
    pub spec: &'a TaskSpec,
    /// Admitted providers.
    pub registry: &'a Registry,
    /// User policy (must match the recorded header).
    pub policy: &'a UserPolicy,
    /// The model profile (must match the recorded header).
    pub profile: &'a Profile,
    /// The live model backend.
    pub backend: &'a dyn ModelBackend,
    /// The locality probe.
    pub probe: &'a dyn LocalityProbe,
    /// The environment probe (§7.1).
    pub env: &'a dyn EnvProbe,
    /// Budgets, timeouts and the turn limits. The limits must equal the
    /// recorded ones (the resume is refused otherwise, never adopting the
    /// journal's: H1 phase-exit review F-1).
    pub config: &'a SessionConfig,
    /// Who the session asks for the next message after the catch-up (a
    /// resume at a turn boundary waits for input; a mid-turn one runs the
    /// interrupted step live first).
    pub input: &'a dyn UserInput,
    /// Who answers an ask after the catch-up (§5.3). Present exactly when
    /// the session had one (the header's `approver_present`), or the
    /// resume is refused: it decides every ask.
    pub approver: Option<&'a dyn Approver>,
    /// Where the resumed records are shown as they are written; `None`
    /// shows nothing.
    pub sink: Option<&'a dyn EventSink>,
    /// Where commands are confined after the catch-up (H2d).
    pub confinement: Option<&'a dyn harness_sandbox::Confinement>,
}

/// Resume a session (P-17 §7): continue at a turn boundary (ask for the
/// next message) or mid-turn (the catch-up re-feeds the kept turns and
/// the interrupted step runs live). A session attempt that committed is
/// reopened only where it ended — the input's end, then the stop; any
/// other stop ended the session for good.
pub fn resume_session(r: ResumeSession<'_>) -> Result<SessionReport, RunRefused> {
    check_turn_limits(r.config)?;
    let limits = session_limits(r.config);
    let pre = prepare(
        r.spec,
        r.registry,
        r.policy,
        r.profile,
        r.workspace,
        r.state_root,
        r.probe,
        &r.config.run,
        r.approver.is_some(),
        r.confinement,
        r.backend.identity().endpoint,
    )?;
    let run_dir = layout::run_dir(&pre.state_root, r.run);
    match std::fs::symlink_metadata(&run_dir) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
        _ => return Err(not_resumable("no such run directory")),
    }
    let (n, v, skipped) = resumable_attempt(&run_dir, r.run)?;
    // The project instructions (P-30): parsed from the journal before any
    // record moves out of `v` and before the header check, so the header's
    // `instructions` digest can be recomputed from exactly what the
    // journal carries.
    let blobs = DirBlobSource::new(layout::attempt_dir(&run_dir, n).join(layout::BLOBS_DIR));
    let recorded_instructions = instructions_of(&v, &blobs).map_err(|d| not_resumable(d.why))?;
    // ---- Reopen (P-17 §7). A committed session attempt is reopened by
    // dropping its last two records — the `InputEnded`, then the
    // `RunStopped` (`session_ended`), the only stop a session may commit.
    // Anything else stopped the session for good: refused, fail closed.
    let mut records = v.records;
    if let Some(last) = records.last() {
        if last.kind == EventKind::RunStopped {
            let cause = last
                .body
                .get("cause")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned();
            let ended = cause == "session_ended"
                && records.len() >= 2
                && records
                    .get(records.len() - 2)
                    .is_some_and(|x| x.kind == EventKind::InputEnded);
            if !ended {
                return Err(not_resumable(format!(
                    "the session stopped ({cause}); start a new session"
                )));
            }
            records.pop();
            records.pop();
        }
    }
    // A stop or an input end anywhere else is not a journal this loop
    // writes; nothing of it may be built on.
    if let Some(x) = records.iter().find(|x| x.kind == EventKind::RunStopped) {
        let cause = x
            .body
            .get("cause")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        return Err(not_resumable(format!(
            "the session stopped ({cause}); start a new session"
        )));
    }
    if records.iter().any(|x| x.kind == EventKind::InputEnded) {
        return Err(not_resumable(
            "the session's input ended before its records do; start a new session",
        ));
    }
    let head = records
        .first()
        .ok_or(not_resumable("the last attempt has no header"))?;
    let ports_header = PortsHeader::of(r.spec, &r.config.run, pre.ports.as_ref());
    check_header(
        head,
        &expected_inputs(
            r.spec,
            r.registry,
            r.policy,
            r.profile,
            &limits,
            Some(&r.config.turn),
            ports_header.as_ref(),
            recorded_instructions.as_ref(),
        ),
    )
    .map_err(|d| not_resumable(d.why))?;
    if head.body.get("approver_present").and_then(Value::as_bool) != Some(r.approver.is_some()) {
        return Err(not_resumable(
            "the approver differs from the recorded header: a run started with an approver \
             resumes with one, and one started without resumes without",
        ));
    }
    // ---- The kept steps (the catch-up), as a batch resume keeps them
    // (H2b): every step whose call finished durably — a `ToolFinished`, or
    // a session's `TurnEnded` — is complete, so it is re-fed, never run
    // again. Only an incomplete last step runs again live.
    let last = records.iter().map(|x| x.step).max().unwrap_or(0);
    let last_done = records.iter().any(|x| {
        x.step == last && matches!(x.kind, EventKind::ToolFinished | EventKind::TurnEnded)
    });
    let kept = Verified {
        records: records
            .iter()
            .filter(|x| x.step < last || (last_done && x.step == last))
            .cloned()
            .collect(),
        torn_tail: None,
        head: v.head,
        run: v.run.clone(),
        attempt: v.attempt,
    };
    let Some(start) = recorded_facts(head) else {
        return Err(not_resumable(
            "the last attempt's header lacks the workspace facts",
        ));
    };
    // ---- Boundary or mid-turn (P-17 §7)? The last kept turn record
    // decides: a `TurnEnded` (or no turn record at all) is a boundary —
    // the workspace may have changed while nobody worked, the next turn
    // measures it and says so, so NO check is made. A `UserTurn` is a turn
    // in flight: the records state what the workspace must still be — the
    // last tree digest a kept turn start, edit or command left.
    let mid_turn = kept
        .records
        .iter()
        .rev()
        .find(|x| matches!(x.kind, EventKind::UserTurn | EventKind::TurnEnded))
        .is_some_and(|x| x.kind == EventKind::UserTurn);
    if mid_turn {
        let expected = kept
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
        // A research session (P-39i) has no workspace: the turn-start tree
        // check is skipped (there is nothing to re-measure, and the
        // records' facts are the no-workspace facts throughout).
        if pre.tree.is_some() && pre.facts.tree != expected {
            return Err(not_resumable(
                "the workspace differs from the session's records since its last turn started \
                 (a change made mid-turn outside the run); this build keeps no snapshot to \
                 restore",
            ));
        }
    }
    // The allowlisted programs must be the ones the run started with (H2d):
    // their content was measured then and is measured again now.
    if let Some((p, _)) = &pre.exec {
        if digest_at(&head.body, "exec_programs_sha256") != Some(p.programs_digest()) {
            return Err(not_resumable(
                "the allowlisted programs differ from the ones the run started with (their \
                 content digest changed)",
            ));
        }
    }
    let rec = recorded(&kept, &blobs, r.profile)
        .map_err(|_| not_resumable("the last attempt's records cannot be replayed"))?;
    // The last step the catch-up re-feeds (H2e: its wall notices too).
    let kept_through = kept.records.iter().map(|x| x.step).max().unwrap_or(0);
    // ---- The wall time already spent (P-17 §7): the session's WORKING
    // wall, never the idle waits between turns. Since its last turn
    // started — the last `UserTurn` in the kept records — the clock moved
    // exactly as that turn's own re-fed wall time says, plus whatever the
    // records after it took (their monotonic times). The waits after the
    // last turn boundary count for nothing: the kept records end at a
    // step's last record, never at an `InputEnded` or a stop.
    let carried_ms = match kept
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
            let since = kept
                .records
                .last()
                .map_or(0, |x| x.t_mono_ms)
                .saturating_sub(u.t_mono_ms);
            wall.saturating_add(since)
        }
        // No turn was ever journaled: the attempt carried in whatever its
        // own header says (a resumed attempt), or nothing.
        None => head
            .body
            .get("resumed_from")
            .and_then(|f| f.get("wall_carried_ms"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
    };
    // The workspace-mode record (P-52): the resumed session names the
    // same scratch copy, re-stated from the recorded header. A recorded
    // value that is not one this build writes refuses the resume.
    let workspace_mode = match head.body.get("workspace_mode") {
        Some(v) => match WorkspaceModeRecord::parse(v) {
            Some(m) => Some(m),
            None => {
                return Err(not_resumable(
                    "the header's workspace-mode record is not one this build writes",
                ))
            }
        },
        None => None,
    };
    let hdr = header(&HeaderInputs {
        spec: r.spec,
        registry: r.registry,
        policy: r.policy,
        profile: r.profile,
        identity: &r.backend.identity(),
        facts: start,
        limits: &limits,
        resumed_from: Some((n, v.head, carried_ms, skipped)),
        environment: r.env.sample(),
        environment_recorded: false,
        approver_present: r.approver.is_some(),
        session: Some(r.config.turn),
        exec: pre
            .exec
            .as_ref()
            .map(|(p, w)| ExecHeader::live(p, w, &r.config.run)),
        ports: ports_header,
        instructions: recorded_instructions.as_ref(),
        workspace_mode: workspace_mode.as_ref(),
        parent: None,
        child: None,
    })?;
    let exec = exec_tools(&pre, &run_dir, r.confinement, &r.config.run)?;
    let (mut w, attempt) = JournalWriter::create_next_attempt_checked(
        &run_dir,
        r.run.clone(),
        hdr,
        &attempt_check(r.probe),
    )?;
    // The UI drain (P-05 §1.3), for the resumed session like the original.
    if r.sink.is_some() {
        w.enable_tap();
    }
    let chain = Chain {
        replay: rec.backend,
        live: r.backend,
        diverged: Cell::new(false),
    };
    // A recorded `RuleGranted` re-applies exactly as it was granted (P-23),
    // whether or not this resume opted in again; an opt-in also lets new
    // `a`/`d` answers grant. The edit previews come from the re-planned
    // tools.
    let edit_tools = pre.edit_tools.clone();
    let granted = rec.approvals.iter().any(|a| {
        matches!(
            a,
            RecordedApproval::AllowSession { .. } | RecordedApproval::DenySession { .. }
        )
    });
    let mut lp = Loop::new(LoopInit {
        session: pre.session,
        registry: r.registry,
        tools: pre.tools,
        task: &r.spec.task,
        facts: loop_facts(&start, r.spec),
        profile: r.profile,
        backend: &chain,
        providers: Prepared::providers(pre.read_tools, pre.edit_tools, pre.patch_tools, exec),
        meter: new_meter_resumed(
            limits.clone(),
            r.profile.pricing(),
            Box::new(SystemClock::default()),
            Duration::from_millis(carried_ms),
        ),
        detector: LoopDetector::new(),
        turns: Vec::new(),
        config: &r.config.run,
        step: 0,
        nonces: NonceSource {
            recorded: rec.nonces,
            assigned: Renderings::new(),
        },
        feed: rec.feed,
        reads: ReadLog::default(),
        // The catch-up re-feeds each recorded edit's tree digest; the
        // listing measured now already holds every one of them.
        tree: start.tree,
        workspace: pre.tree,
        research: matches!(r.spec.kind, SessionKind::Research(_)),
        approvals: Approvals::new(r.run, attempt, r.approver, rec.approvals)
            .may_grant(r.config.run.allow_session_grants || granted)
            .with_edits(edit_tools),
        env: r.env,
        pressure: Vec::new(),
        reads_seen: Default::default(),
        todo: todo_for(&r.spec.grants),
        // The kept steps' wall notices are re-fed; the live steps after
        // them measure the meter, which carries the working wall already
        // spent.
        notices: BudgetNotices {
            wall_limit: r.config.run.limits.wall,
            recorded: rec.walls,
            recorded_through: kept_through,
            wall_announced: 0,
        },
        presubmit: PresubmitState::of(&r.spec.presubmit),
        post_edit: PostEditState::of(&r.spec.post_edit),
        workspace_root: r.workspace.map(std::path::Path::to_path_buf),
        restore: Default::default(),
        // The resumed session re-derives the instructions from the journal
        // (P-30) and rewrites the identical `InstructionsLoaded` record in
        // its catch-up, before any recorded input.
        instructions: recorded_instructions.as_ref(),
        // The resumed session opens turns: the catch-up re-feeds the kept
        // turns' inputs, then the live source is asked (a boundary) or the
        // interrupted turn keeps running (mid-turn).
        user: Some(UserState {
            limits: r.config.turn,
            turn: 1,
            allowance: 0,
            used: 0,
            users: Vec::new(),
            deliverable: None,
            // A research session (P-39i) has no workspace: a turn's start
            // re-measures nothing, so `external_change` is always false.
            root: r.workspace.map(std::path::Path::to_path_buf),
            blobs: layout::attempt_dir(&run_dir, attempt).join(layout::BLOBS_DIR),
            sink: r.sink,
        }),
    });
    let end = lp.drive_session(
        &mut w,
        SessionInputs::Resume {
            recorded: rec.inputs,
            live: r.input,
        },
        r.config.input_timeout,
    );
    let turns = lp.user.as_ref().map_or(0, |u| u.turn.saturating_sub(1));
    let outcome = chain.diverged.get().then_some(UNREADABLE);
    let released = commit(w, &end, outcome);
    Ok(SessionReport {
        run: RunReport {
            run: r.run.clone(),
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
