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
use harness_policy::UserPolicy;
use serde_json::Value;

use crate::approve::Approver;
use crate::driver::{
    attempt_check, commit, exec_tools, header, loop_facts, new_meter_resumed, prepare, todo_for,
    Approvals, BudgetNotices, ExecHeader, HeaderInputs, Loop, LoopInit, NonceSource, Prepared,
    ReadLog,
};
use crate::presubmit::PresubmitState;
use crate::{RunConfig, RunRefused, RunReport, TaskSpec};

use super::audit::{attempts_desc, has_header, UNREADABLE};
use super::compare::{check_header, expected_inputs};
use super::feed::{digest_at, recorded, recorded_facts};

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
    /// edit, or at its start), or the resume is refused.
    pub workspace: &'a Path,
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
fn resumable_attempt(run_dir: &Path, run: &RunId) -> Result<(u32, Verified, Vec<u32>), RunRefused> {
    let nope = RunRefused::NotResumable;
    let mut skipped = Vec::new();
    for n in attempts_desc(run_dir).map_err(RunRefused::RunDir)? {
        let dir = layout::attempt_dir(run_dir, n);
        if !has_header(&dir).map_err(RunRefused::RunDir)? {
            skipped.push(n);
            continue;
        }
        let v = JournalReader::open_expecting(&dir, run)
            .map_err(|_| nope("the last attempt's journal does not verify"))?;
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
    Err(nope("the run has no attempt with a durable header"))
}

/// Resume an interrupted run in a new attempt (see the module docs).
pub fn resume(r: Resume<'_>) -> Result<RunReport, RunRefused> {
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
    )?;
    let nope = RunRefused::NotResumable;
    let run_dir = layout::run_dir(&pre.state_root, r.run);
    match std::fs::symlink_metadata(&run_dir) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
        _ => return Err(nope("no such run directory")),
    }
    let (n, v, skipped) = resumable_attempt(&run_dir, r.run)?;
    let attempt_dir = layout::attempt_dir(&run_dir, n);
    if v.records.iter().any(|x| x.kind == EventKind::RunStopped) {
        return Err(nope("the run already stopped; there is nothing to resume"));
    }
    let head = v
        .records
        .first()
        .ok_or(nope("the last attempt has no header"))?;
    // The limits included: a resume runs under the caller's limits, which
    // must be the recorded ones (H1 phase-exit review F-1).
    check_header(
        head,
        &expected_inputs(r.spec, r.registry, r.policy, r.profile, &r.config.limits),
    )
    .map_err(|d| nope(d.why))?;
    if head.body.get("approver_present").and_then(Value::as_bool) != Some(r.approver.is_some()) {
        return Err(nope(
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
        return Err(nope("the last attempt's header lacks the workspace facts"));
    };
    // The last tree digest a kept record states: an edit's `EditApplied`,
    // or a command's `ToolFinished` (H2d: measured after the command).
    let expected = kept
        .records
        .iter()
        .rev()
        .filter(|x| matches!(x.kind, EventKind::EditApplied | EventKind::ToolFinished))
        .find_map(|x| digest_at(&x.body, "workspace_tree"))
        .unwrap_or(start.tree);
    if pre.facts.tree != expected {
        return Err(nope(
            "the workspace differs from the interrupted attempt's last durable record (an edit \
             applied without its result, or a change made outside the run); this build keeps no \
             snapshot to restore",
        ));
    }
    // The allowlisted programs must be the ones the run started with (H2d):
    // their content was measured then and is measured again now.
    if let Some((p, _)) = &pre.exec {
        if digest_at(&head.body, "exec_programs_sha256") != Some(p.programs_digest()) {
            return Err(nope(
                "the allowlisted programs differ from the ones the run started with (their content digest changed)",
            ));
        }
    }
    let blobs = DirBlobSource::new(attempt_dir.join(layout::BLOBS_DIR));
    let rec = recorded(&kept, &blobs, r.profile)
        .map_err(|_| nope("the last attempt's records cannot be replayed"))?;
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
        exec: pre
            .exec
            .as_ref()
            .map(|(p, w)| ExecHeader::live(p, w, r.config)),
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
    let mut lp = Loop::new(LoopInit {
        session: pre.session,
        registry: r.registry,
        tools: pre.tools,
        task: &r.spec.task,
        facts: loop_facts(&start, r.spec),
        profile: r.profile,
        backend: &chain,
        providers: Prepared::providers(pre.read_tools, pre.edit_tools, exec),
        meter: new_meter_resumed(
            r.config.limits.clone(),
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
        workspace: Some(pre.tree),
        approvals: Approvals::new(r.run, attempt, r.approver, rec.approvals),
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
    })
}
