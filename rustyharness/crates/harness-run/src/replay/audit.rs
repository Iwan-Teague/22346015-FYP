//! Audit replay (design §2.9, INV-20): re-drive the loop over what a
//! journal recorded, write the replay into a fresh journal, and compare
//! the two record by record (see the [`crate::replay`] module docs).

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use gate_outcome::{Digest, GateOutcome, IndeterminateKind};
use harness_core::environment::{EnvSample, Unmeasured};
use harness_core::{LoopDetector, MeterLimits, RunId};
use harness_journal::reader::DirBlobSource;
use harness_journal::writer::SystemClock;
use harness_journal::{
    canon::{EventKind, Ident},
    event::{Event, Trusted},
    layout, verify, JournalReader, JournalWriter, StartError, Verified,
};
use harness_manifest::admission::Registry;
use harness_model::context::Renderings;
use harness_model::profile::Profile;
use harness_model::ModelBackend;
use harness_policy::{SessionKind, UserPolicy};
use serde_json::Value;

use crate::approve::RecordedApproval;
use crate::driver::step::UserState;
use crate::driver::{
    commit, header, loop_facts, new_meter, plan, todo_for, Approvals, BudgetNotices, ExecHeader,
    HeaderInputs, Loop, LoopInit, NonceSource, PortsHeader, ReadLog, RepoMapFeed, SandboxRecord,
    WorkspaceModeRecord,
};
use crate::postedit::PostEditState;
use crate::presubmit::PresubmitState;
use crate::sample;
use crate::session::{SessionInputs, TurnLimits};
use crate::{RunConfig, RunRefused, TaskSpec};

use super::compare::{check_header, compare, diverge, expected_inputs, Divergence};
use super::feed::{digest_at, instructions_of, recorded, recorded_facts};

/// The audit's probe: a replay never measures a host.
const NOT_SAMPLED: EnvSample = EnvSample::unmeasured(Unmeasured::NotSampled);

/// What an audit replay needs: the run, and the inputs the run was given.
pub struct Audit<'a> {
    /// The state root holding `runs/<run-id>`.
    pub state_root: &'a Path,
    /// The run.
    pub run: &'a RunId,
    /// The attempt (default: the latest).
    pub attempt: Option<u32>,
    /// A chain head recorded elsewhere (the run report), if the caller has
    /// one: the only defence against wholesale replacement (§7.1).
    pub anchor: Option<Digest>,
    /// The task spec the run was given.
    pub spec: &'a TaskSpec,
    /// Admitted providers.
    pub registry: &'a Registry,
    /// User policy.
    pub policy: &'a UserPolicy,
    /// The model profile.
    pub profile: &'a Profile,
    /// The budget limits the run was given (the CLI's are
    /// `RunConfig::defaults(1_000_000).limits`). They must equal the
    /// recorded ones, which are otherwise a divergence at the header: the
    /// replay recomputes every budget stop from them (H1 phase-exit review
    /// F-1).
    pub limits: &'a MeterLimits,
}

/// What an audit found.
#[derive(Debug)]
pub struct AuditReport {
    /// The attempt replayed.
    pub attempt: u32,
    /// Later attempts passed over because they hold no durable header (a
    /// start that failed before it: H1 phase-exit review F-5), highest
    /// first. Empty when an attempt was asked for by number.
    pub skipped_attempts: Vec<u32>,
    /// Where the recomputed journal was written, when the replay ran.
    pub replay_dir: Option<PathBuf>,
    /// Records that matched (header and wall-budget records excluded).
    pub matched: usize,
    /// Wall-budget condition records (`BudgetCharged`, key `wall`) left out
    /// of the comparison, since when the clock crossed 80% is not
    /// recomputable. 0 or 1: at most one was admitted, and only the
    /// entry `{condition: enter, key: wall}`, the one record the loop
    /// writes for the wall dimension (H1g confirming review NF-1).
    pub wall_skipped: usize,
    /// Whether the recorded stop was recomputed by the replay. False for a
    /// wall-budget stop (the clock is not replayable) and for an attempt
    /// that never committed. A journal cut short and ended with a forged
    /// wall stop is indistinguishable from a real one: only the anchor
    /// proves nothing was removed.
    pub stop_recomputed: bool,
    /// Whether a caller-supplied anchor matched the journal's chain head.
    pub anchored: bool,
    /// The first divergence, if any.
    pub divergence: Option<Divergence>,
    /// `Indeterminate { UnreadableEvidence }` on any divergence, and for a
    /// committed stop the replay could not recompute (a wall stop) unless
    /// an anchor matched; otherwise the recorded outcome (`CouldNotRun`
    /// for an attempt that never committed).
    pub outcome: GateOutcome,
}

/// An audit that could not even start (nothing to replay).
#[derive(Debug, thiserror::Error)]
pub enum AuditRefused {
    /// No such run directory.
    #[error("no run directory: {0}")]
    NoRun(io::Error),
    /// The run has no attempt.
    #[error("the run has no attempt")]
    NoAttempt,
    /// The inputs do not plan (task spec, grants).
    #[error("{0}")]
    Plan(RunRefused),
    /// The replay journal could not be started.
    #[error("{0}")]
    Start(StartError),
}

pub(crate) const UNREADABLE: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::UnreadableEvidence,
};

/// The attempt numbers under `run_dir`, highest first.
pub(crate) fn attempts_desc(run_dir: &Path) -> io::Result<Vec<u32>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(run_dir)? {
        let name = entry?.file_name();
        if let Some(n) = name.to_str().and_then(layout::parse_attempt_name) {
            out.push(n);
        }
    }
    out.sort_unstable_by(|a, b| b.cmp(a));
    Ok(out)
}

/// Whether an attempt directory holds a header at all: its journal has a
/// complete first line. A start that failed before its header was written
/// (the new attempt directory's locality check, ENOSPC or EIO on the
/// header) leaves no journal, an empty one, or a torn first line (H1
/// phase-exit review F-5); such an attempt holds no evidence, so resume
/// and the default audit pass over it. Anything with a complete line is
/// evidence, and must verify.
pub(crate) fn has_header(attempt_dir: &Path) -> io::Result<bool> {
    match std::fs::read(attempt_dir.join(layout::JOURNAL_FILE)) {
        Ok(bytes) => Ok(bytes.contains(&b'\n')),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn run_dir_of(state_root: &Path, run: &RunId) -> io::Result<PathBuf> {
    let root = std::fs::canonicalize(state_root)?;
    let dir = layout::run_dir(&root, run);
    let m = std::fs::symlink_metadata(&dir)?;
    if m.file_type().is_symlink() || !m.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the run directory is not a real directory",
        ));
    }
    Ok(dir)
}

/// The recorded outcome, as the audit reports it after a match. H1 can
/// only record `Indeterminate`; a recorded pass or failure is not
/// something a replay can vouch for, so it is unreadable evidence.
fn recorded_outcome(v: &Verified) -> GateOutcome {
    let kind = |why| GateOutcome::Indeterminate { why };
    let Some(last) = v.records.last().filter(|r| r.kind == EventKind::RunStopped) else {
        return kind(IndeterminateKind::CouldNotRun);
    };
    match last.body.get("outcome").and_then(Value::as_str) {
        Some("indeterminate:nothing_checked") => kind(IndeterminateKind::NothingChecked),
        Some("indeterminate:could_not_run") => kind(IndeterminateKind::CouldNotRun),
        Some("indeterminate:unsupported_os") => kind(IndeterminateKind::UnsupportedOs),
        Some("indeterminate:stale_binary") => kind(IndeterminateKind::StaleBinary),
        _ => kind(IndeterminateKind::UnreadableEvidence),
    }
}

/// Replay a recorded attempt and compare (see the module docs).
pub fn audit(a: Audit<'_>) -> Result<AuditReport, AuditRefused> {
    audit_inner(a, None)
}

/// Replay a recorded session attempt and compare (P-17 §6): the re-drive
/// re-feeds each recorded `UserTurn` (its text, facts and wall time) and
/// each `InputEnded` (its reason), recomputes everything else — the turn
/// boundaries, the per-turn allowances, whether the workspace changed —
/// and stops `Cancelled` where the recorded inputs run out. `turn` must be
/// the session's recorded turn limits, which the header check enforces.
pub fn audit_session(a: Audit<'_>, turn: &TurnLimits) -> Result<AuditReport, AuditRefused> {
    audit_inner(a, Some(turn))
}

fn audit_inner(a: Audit<'_>, turn: Option<&TurnLimits>) -> Result<AuditReport, AuditRefused> {
    let run_dir = run_dir_of(a.state_root, a.run).map_err(AuditRefused::NoRun)?;
    // By default the latest attempt with a durable header: a start that
    // failed before its header is skipped, and named (H1 phase-exit review
    // F-5). An attempt asked for by number is audited whatever it holds.
    let (attempt, skipped_attempts) = match a.attempt {
        Some(n) => (n, Vec::new()),
        None => {
            let mut skipped = Vec::new();
            let mut found = None;
            for n in attempts_desc(&run_dir).map_err(AuditRefused::NoRun)? {
                if has_header(&layout::attempt_dir(&run_dir, n)).map_err(AuditRefused::NoRun)? {
                    found = Some(n);
                    break;
                }
                skipped.push(n);
            }
            (found.ok_or(AuditRefused::NoAttempt)?, skipped)
        }
    };
    let failed = |d: Divergence, replay_dir| AuditReport {
        attempt,
        skipped_attempts: skipped_attempts.clone(),
        replay_dir,
        matched: 0,
        wall_skipped: 0,
        stop_recomputed: false,
        anchored: false,
        divergence: Some(d),
        outcome: UNREADABLE,
    };
    let attempt_dir = layout::attempt_dir(&run_dir, attempt);
    let v = match JournalReader::open_expecting(&attempt_dir, a.run) {
        Ok(v) => v,
        Err(_) => {
            return Ok(failed(
                diverge(
                    0,
                    0,
                    "the journal does not verify, or belongs to another run or attempt",
                ),
                None,
            ))
        }
    };
    if let Some(anchor) = a.anchor {
        if v.check_anchor(&anchor).is_err() {
            return Ok(failed(
                diverge(
                    v.records.last().map_or(0, |r| r.seq),
                    0,
                    "the journal's chain head is not the anchor",
                ),
                None,
            ));
        }
    }
    let Some(head) = v.records.first() else {
        return Ok(failed(diverge(0, 0, "the journal is empty"), None));
    };
    // The task's port grants (P-36g §6.1): the probe's observation is a
    // past host's, not recomputable, so it is re-stated; the granted lists
    // in it are still checked against the inputs given, by `check_header`
    // below. A task with ports whose journal does not hold the object, or
    // holds one this build does not write, is refused by name.
    let recorded_ports = if a.spec.ports.is_empty() {
        None
    } else {
        match head.body.get("ports").and_then(PortsHeader::parse) {
            Some(p) => Some(p),
            None => {
                return Ok(failed(
                    diverge(0, 0, "the header does not record the run's port grants"),
                    None,
                ))
            }
        }
    };
    // The project instructions (P-30): parsed from the journal before the
    // header check, so the header's `instructions` digest can be
    // recomputed from exactly what the journal carries. A shape this loop
    // does not write refuses here, like any bad record.
    let blobs = DirBlobSource::new(attempt_dir.join(layout::BLOBS_DIR));
    let recorded_instructions = match instructions_of(&v, &blobs) {
        Ok(n) => n,
        Err(d) => return Ok(failed(d, None)),
    };
    if let Err(d) = check_header(
        head,
        &expected_inputs(
            a.spec,
            a.registry,
            a.policy,
            a.profile,
            a.limits,
            turn,
            recorded_ports.as_ref(),
            recorded_instructions.as_ref(),
        ),
    ) {
        return Ok(failed(d, None));
    }
    let (Some(facts), Some(environment)) = (
        recorded_facts(head),
        head.body.get("environment").and_then(sample::from_value),
    ) else {
        return Ok(failed(
            diverge(
                0,
                0,
                "the header lacks the workspace facts or the environment sample",
            ),
            None,
        ));
    };
    let mut rec = match recorded(&v, &blobs, a.profile) {
        Ok(r) => r,
        Err(d) => return Ok(failed(d, None)),
    };
    // Whether anyone answered asks is the run's, like its approvers'
    // answers (H2b): the audit plans with the recorded value and re-feeds
    // the recorded answers. A forged value only makes the replay's asks and
    // denials differ from the recorded ones (a divergence), unless the
    // approval records are forged with it (anchor-only, like a tool result).
    let Some(approver_present) = head.body.get("approver_present").and_then(Value::as_bool) else {
        return Ok(failed(
            diverge(
                0,
                0,
                "the header does not say whether an approver was present",
            ),
            None,
        ));
    };
    // Whether the run held a sandbox witness is the run's (H2d), like the
    // approver's presence: the audit plans with the recorded value and
    // re-states the recorded sandbox in its own header; nothing runs here.
    let exec_header = match (&a.spec.exec, head.body.get("sandbox")) {
        (None, _) => None,
        (Some(e), Some(sb)) => {
            let rec = SandboxRecord::parse(sb);
            let sha = digest_at(&head.body, "exec_programs_sha256");
            let timeout = head.body.get("exec_timeout_ms").and_then(Value::as_u64);
            match (rec, sha, timeout) {
                (Some(sandbox), Some(programs_sha256), Some(timeout_ms)) => Some(ExecHeader {
                    sandbox,
                    shell_enabled: e.shell_enabled(),
                    spec: e.digest(),
                    programs: e.programs.len() as u64,
                    programs_sha256,
                    timeout_ms,
                }),
                _ => {
                    return Ok(failed(
                        diverge(
                            0,
                            0,
                            "the header's sandbox or exec record is not one this build writes",
                        ),
                        None,
                    ))
                }
            }
        }
        (Some(_), None) => {
            return Ok(failed(
                diverge(0, 0, "the header does not say which sandbox the run held"),
                None,
            ))
        }
    };
    // The workspace-mode record (P-52): the replay cannot re-measure the
    // host files it names, so it re-states the recorded value verbatim. A
    // recorded value that is not one this build writes refuses by name.
    let workspace_mode = match head.body.get("workspace_mode") {
        Some(v) => match WorkspaceModeRecord::parse(v) {
            Some(m) => Some(m),
            None => {
                return Ok(failed(
                    diverge(
                        0,
                        0,
                        "the header's workspace-mode record is not one this build writes",
                    ),
                    None,
                ))
            }
        },
        None => None,
    };
    let (session, tools) = plan(
        a.spec,
        a.registry,
        a.policy,
        a.profile,
        approver_present,
        exec_header.is_some(),
    )
    .map_err(AuditRefused::Plan)?;
    let hdr = header(&HeaderInputs {
        spec: a.spec,
        registry: a.registry,
        policy: a.policy,
        profile: a.profile,
        identity: &rec.backend.identity(),
        facts,
        limits: a.limits,
        resumed_from: None,
        // The replay journal repeats the recorded sample, marked as such:
        // a past host cannot be re-measured, and the header is not compared.
        environment,
        environment_recorded: true,
        approver_present,
        session: turn.copied(),
        exec: exec_header,
        ports: recorded_ports,
        instructions: recorded_instructions.as_ref(),
        workspace_mode: workspace_mode.as_ref(),
        parent: None,
        child: None,
    })
    .map_err(AuditRefused::Plan)?;
    let (mut w, replay_dir) = JournalWriter::create_replay(&run_dir, a.run.clone(), attempt, hdr)
        .map_err(AuditRefused::Start)?;
    // A fork's journal (P-32): the recorded `ForkedFrom` head is held
    // against the parent's own records in this state root — the parent's
    // kept prefix is re-derived the way `fork_session` did, and a head
    // that no longer matches (a changed or tampered parent, a parent
    // resumed into a later attempt) is a divergence. The record is then
    // re-written into the replay journal, so the comparison carries it.
    if let Some(fork) = rec.fork.take() {
        let seq = v
            .records
            .iter()
            .find(|r| r.kind == EventKind::ForkedFrom)
            .map_or(0, |r| r.seq);
        let head =
            match super::fork::parent_prefix_head(a.state_root, &fork.parent_run, fork.parent_step)
            {
                Ok(h) => h,
                Err(_) => {
                    return Ok(failed(
                        diverge(seq, 0, "the forked parent's prefix does not verify"),
                        Some(replay_dir),
                    ))
                }
            };
        if head != fork.parent_chain_head {
            return Ok(failed(
                diverge(
                    seq,
                    0,
                    "the forked parent's prefix does not match the recorded chain head",
                ),
                Some(replay_dir),
            ));
        }
        let Some(parent_id) = Ident::from_trusted(&fork.parent_run) else {
            return Ok(failed(
                diverge(seq, 0, "the forked parent's prefix does not verify"),
                Some(replay_dir),
            ));
        };
        let ev = Event::new(EventKind::ForkedFrom)
            .field("parent_run", Trusted::Id(parent_id))
            .field("parent_step", Trusted::U64(fork.parent_step))
            .field("parent_chain_head", Trusted::Digest(fork.parent_chain_head));
        if w.append(0, ev).is_err() {
            return Ok(failed(
                diverge(0, 0, "the replay journal could not be written"),
                Some(replay_dir),
            ));
        }
    }
    // The replay does not re-measure wall time (it cannot recompute it):
    // its meter has no wall limit, so a replay never stops on the clock.
    let limits = MeterLimits {
        wall: Duration::MAX,
        ..a.limits.clone()
    };
    let config = RunConfig {
        limits: limits.clone(),
        ..RunConfig::defaults(limits.tokens)
    };
    // The grants re-feed with the answers (P-23): allow them exactly when
    // the journal holds one, and never ask (an audit has no approver).
    let granted = rec.approvals.iter().any(|a| {
        matches!(
            a,
            RecordedApproval::AllowSession { .. } | RecordedApproval::DenySession { .. }
        )
    });
    let mut lp = Loop::new(LoopInit {
        session,
        registry: a.registry,
        tools,
        task: &a.spec.task,
        facts: loop_facts(&facts, a.spec),
        profile: a.profile,
        backend: &rec.backend,
        providers: Vec::new(),
        // The profile's price table (P-31): the audit recomputes the cost
        // charges, so a budget stop in the `Cost` dimension replays too.
        meter: new_meter(
            limits,
            a.profile.pricing(),
            Box::new(SystemClock::default()),
        ),
        detector: LoopDetector::new(),
        turns: Vec::new(),
        config: &config,
        step: 0,
        nonces: NonceSource {
            recorded: rec.nonces,
            assigned: Renderings::new(),
        },
        feed: rec.feed,
        reads: ReadLog::default(),
        tree: facts.tree,
        workspace: None,
        research: matches!(a.spec.kind, SessionKind::Research(_)),
        // Nobody is asked in an audit: the recorded answers are re-fed and
        // re-minted with their recorded nonces (a reused one refuses).
        approvals: Approvals::new(a.run, attempt, None, rec.approvals).may_grant(granted),
        // No provider runs in an audit: a recorded result is re-fed with its
        // recorded sample. A step with no recorded result (an intent a crash
        // cut) ends as a provider failure, whose sample says it was not
        // sampled rather than borrowing the header's (confirming NF-1).
        env: &NOT_SAMPLED,
        pressure: Vec::new(),
        reads_seen: Default::default(),
        todo: todo_for(&a.spec.grants),
        // Every wall notice is re-fed (the clock is not replayable), and
        // measured against the run's own wall budget.
        notices: BudgetNotices {
            wall_limit: a.limits.wall,
            recorded: rec.walls,
            recorded_through: u64::MAX,
            wall_announced: 0,
        },
        presubmit: PresubmitState::of(&a.spec.presubmit),
        post_edit: PostEditState::of(&a.spec.post_edit),
        workspace_root: None,
        restore: Default::default(),
        // Every repo map is re-fed (P-33): an audit never reads the
        // workspace, so the recorded payload stands and is written back
        // identically.
        repo_feed: RepoMapFeed::re_feed(rec.repo_maps, u64::MAX),
        // The replay re-derives the instructions from the journal (P-30)
        // and rewrites the identical `InstructionsLoaded` record.
        instructions: recorded_instructions.as_ref(),
        // A session replay opens turns (P-17 §6): the re-fed texts build
        // the users' share of the context, and each turn's budgets are
        // recomputed from the recorded turn limits. It measures nothing
        // and waits for nobody (root and sink stay unset); a refused
        // replayed turn is the recorded one's shape to match.
        user: turn.map(|t| UserState {
            limits: *t,
            turn: 1,
            allowance: 0,
            used: 0,
            users: Vec::new(),
            deliverable: None,
            root: None,
            blobs: replay_dir.join(layout::BLOBS_DIR),
            sink: None,
        }),
        // An audit never builds a child: a delegate call diverges here
        // (P-38f owns the proper re-feed of `ChildRun` and its result).
        delegate: None,
    });
    let end = match turn {
        None => lp.drive(&mut w),
        // The replayed session consumes the recorded inputs; when they
        // run out it stops `Cancelled` with no `InputEnded` (P-17 §6),
        // which only a prefix of an uncommitted journal compares against.
        Some(_) => lp.drive_session(&mut w, SessionInputs::Replay(rec.inputs), Duration::ZERO),
    };
    let released = commit(w, &end, None);
    if released.error.is_some() {
        return Ok(failed(
            diverge(0, 0, "the replay journal could not be written"),
            Some(replay_dir),
        ));
    }
    let replayed = match std::fs::read(replay_dir.join(layout::JOURNAL_FILE))
        .ok()
        .and_then(|b| verify(&b, &DirBlobSource::new(replay_dir.join(layout::BLOBS_DIR))).ok())
    {
        Some(r) => r,
        None => {
            return Ok(failed(
                diverge(0, 0, "the replay journal does not verify"),
                Some(replay_dir),
            ))
        }
    };
    let anchored = a.anchor.is_some();
    Ok(match compare(&v.records, &replayed.records) {
        Ok(c) => {
            let committed = v
                .records
                .last()
                .is_some_and(|r| r.kind == EventKind::RunStopped);
            // A committed stop the replay could not recompute (a wall
            // stop) proves nothing about what may have been cut after the
            // last matching record, unless the anchor pins the whole
            // journal (H1e-2b review F-1).
            let outcome = if committed && !c.stop_recomputed && !anchored {
                UNREADABLE
            } else {
                recorded_outcome(&v)
            };
            AuditReport {
                attempt,
                skipped_attempts,
                replay_dir: Some(replay_dir),
                matched: c.matched,
                wall_skipped: c.wall_skipped,
                stop_recomputed: c.stop_recomputed,
                anchored,
                divergence: None,
                outcome,
            }
        }
        Err(d) => failed(d, Some(replay_dir)),
    })
}
