//! Audit replay (design §2.9, INV-20) and resume (§2.10).
//!
//! Both re-drive the SAME loop as a live run over what a journal recorded:
//! the recorded model replies through `ReplayBackend` (which re-renders each
//! request and refuses one whose digest differs), the recorded tool results
//! in place of running the tools, and the recorded render nonces, so every
//! request renders byte for byte. Everything else is recomputed: the
//! context (its digest is journaled as `ContextBuilt`), the parse, loop
//! detection, every policy decision, the meter.
//!
//! **Audit** ([`audit`]) writes what it recomputes into a fresh journal,
//! `runs/<run-id>/replay-<k>/`, next to the attempts (never inside one),
//! then compares it with the recorded attempt record by record (kind, step
//! and body; the time fields and the header's own run-specific fields
//! excepted). The first difference is reported with its record and step,
//! and the audit's outcome is `Indeterminate { UnreadableEvidence }`. A
//! journal that does not verify, belongs to another run or attempt, or
//! does not match a caller-supplied chain head (the anchor) is the same.
//! Two recorded facts are not recomputable and are handled explicitly:
//! - **wall time.** A `BudgetCharged` record for the `wall` dimension is
//!   left out of the comparison on both sides, and the replay's meter has
//!   no wall limit. A run stopped by the wall budget can only be checked
//!   up to its last record: every recorded record must match, but the stop
//!   itself is NOT recomputed (`AuditReport::stop_recomputed` is false).
//!   Since a journal cut at any step boundary and ended with a forged wall
//!   stop, re-chained, looks exactly the same (H1e-2b review F-1), such an
//!   audit is `Indeterminate { UnreadableEvidence }` unless the caller's
//!   anchor matched the journal's chain head; only the anchor proves that
//!   nothing was removed.
//! - **the workspace.** Audit mode re-feeds tool output; it never reads the
//!   workspace. The workspace facts come from the recorded header.
//!
//! **Resume** ([`resume`]) continues an attempt that has no `RunStopped`
//! (a crash or a kill) in a NEW attempt directory: the old journal is only
//! read, never appended to, poisoned or not. Its header records the attempt
//! it continues and that journal's chain head. The new attempt first
//! replays every step of the old one except the last (catch-up: recorded
//! replies and tool results, checked exactly like an audit), then runs the
//! last step again live, so a trailing intent with no result is decided
//! again by policy, never executed blindly. A catch-up that diverges makes
//! the resumed run `Indeterminate { UnreadableEvidence }`. H1 sessions
//! cannot change the workspace, so the snapshot of §2.10 is the recorded
//! tree digest: a resume is refused when the workspace no longer has it.
//! The wall time the interrupted attempt spent (its journal's last
//! monotonic time, the writer's elapsed time) is charged to the resumed
//! attempt's meter from the start, so a kill and resume buys no fresh wall
//! budget; steps and tokens are re-charged by the catch-up.

use std::cell::Cell;
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use gate_outcome::{Digest, GateOutcome, IndeterminateKind};
use harness_core::environment::{EnvProbe, EnvSample, Unmeasured};
use harness_core::{LoopDetector, MeterLimits, Nonce, RunId};
use harness_journal::reader::DirBlobSource;
use harness_journal::writer::SystemClock;
use harness_journal::{
    layout, verify, BlobSource, EventKind, JournalReader, JournalWriter, Record, StartError,
    Verified,
};
use harness_manifest::admission::{Registry, Resolved};
use harness_model::profile::{Profile, Protocol};
use harness_model::replay::{payload_bytes, ReplayBackend};
use harness_model::{Completion, ModelBackend, ModelError, ModelIdentity, ModelRequest};
use harness_policy::locality::LocalityProbe;
use harness_policy::{UserPolicy, SUBMIT_ID};
use harness_tools::builtin::WorkspaceFacts;
use harness_tools::{RefusalKind, ToolStatus};
use serde_json::{Map, Value};

use crate::driver::{
    attempt_check, builtin_manifest_sha256, commit, facts_block, header, new_meter,
    new_meter_resumed, plan, prepare, HeaderInputs, Loop, NonceSource, ReadLog, RecordedResult,
    HEADER_INPUT_KEYS,
};
use crate::sample;

/// The audit's probe: a replay never measures a host.
const NOT_SAMPLED: EnvSample = EnvSample::unmeasured(Unmeasured::NotSampled);
use crate::{RunConfig, RunRefused, RunReport, TaskSpec};

// ---------------------------------------------------------------------------
// What a journal recorded.
// ---------------------------------------------------------------------------

/// Where a journal and the replay first disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Divergence {
    /// The recorded record's sequence number (0 = the header).
    pub seq: u64,
    /// Its loop step.
    pub step: u64,
    /// What differs (harness text).
    pub why: &'static str,
}

fn diverge(seq: u64, step: u64, why: &'static str) -> Divergence {
    Divergence { seq, step, why }
}

/// The replay inputs recorded in a journal.
struct Recorded {
    backend: ReplayBackend,
    nonces: VecDeque<Nonce>,
    feed: VecDeque<RecordedResult>,
}

fn status_of(b: &Map<String, Value>) -> Option<Option<ToolStatus>> {
    Some(match b.get("status")?.as_str()? {
        "ok" => Some(ToolStatus::Ok),
        "error" => Some(ToolStatus::Error {
            code: u16::try_from(b.get("code")?.as_u64()?).ok()?,
        }),
        "timeout" => Some(ToolStatus::Timeout),
        // The signal and the refusal reason are not journaled; the status
        // name is, and that is what the replayed record carries.
        "crashed" => Some(ToolStatus::Crashed { signal: None }),
        "refused" => Some(ToolStatus::Refused {
            reason: RefusalKind::UnknownCapability,
        }),
        "provider_error" => None,
        _ => return None,
    })
}

fn digest_at(b: &Map<String, Value>, key: &str) -> Option<Digest> {
    b.get(key)?.as_str()?.parse().ok()
}

/// Read the replay inputs from `records` (already verified).
fn recorded(
    v: &Verified,
    blobs: &dyn BlobSource,
    profile: &Profile,
) -> Result<Recorded, Divergence> {
    let backend = ReplayBackend::from_journal(v, blobs, profile.clone())
        .map_err(|_| diverge(0, 0, "the model records cannot be replayed"))?;
    let mut nonces = VecDeque::new();
    let mut feed = VecDeque::new();
    let mut intents: BTreeMap<u64, String> = BTreeMap::new();
    for r in &v.records {
        let bad = || diverge(r.seq, r.step, "a record is not the shape the loop writes");
        match r.kind {
            EventKind::ModelRequested => {
                let n = r
                    .body
                    .get("nonce")
                    .and_then(Value::as_str)
                    .and_then(Nonce::new)
                    .ok_or_else(bad)?;
                nonces.push_back(n);
            }
            EventKind::ToolStarted => {
                let cap = r
                    .body
                    .get("capability")
                    .and_then(Value::as_str)
                    .ok_or_else(bad)?;
                intents.insert(r.seq, cap.to_owned());
            }
            EventKind::ToolFinished => {
                let seq = r
                    .body
                    .get("intent_seq")
                    .and_then(Value::as_u64)
                    .ok_or_else(bad)?;
                let cap = intents.get(&seq).ok_or_else(bad)?.clone();
                if cap == SUBMIT_ID {
                    continue;
                }
                let status = status_of(&r.body).ok_or_else(bad)?;
                let (output, truncated, digest) = if status.is_some() {
                    let out = payload_bytes(r.body.get("output").ok_or_else(bad)?, blobs, r.seq)
                        .map_err(|_| bad())?;
                    let t = r
                        .body
                        .get("truncated")
                        .and_then(Value::as_bool)
                        .ok_or_else(bad)?;
                    (out, t, digest_at(&r.body, "digest").ok_or_else(bad)?)
                } else {
                    (Vec::new(), false, harness_core::sha256(b""))
                };
                // §7.1: exactly the timeout, crashed and provider-failure
                // (None) results carry a sample, in exactly the shape the
                // loop writes; only an ok read carries a read digest.
                let sampled = matches!(
                    status,
                    None | Some(ToolStatus::Timeout | ToolStatus::Crashed { .. })
                );
                if r.body.contains_key("read_sha256") && status != Some(ToolStatus::Ok) {
                    return Err(bad());
                }
                let environment = match (sampled, r.body.get("environment")) {
                    (true, Some(v)) => Some(sample::from_value(v).ok_or_else(bad)?),
                    (false, None) => None,
                    _ => return Err(bad()),
                };
                feed.push_back(RecordedResult {
                    capability: cap,
                    status,
                    output,
                    truncated,
                    digest,
                    read_sha256: digest_at(&r.body, "read_sha256"),
                    environment,
                });
            }
            _ => {}
        }
    }
    Ok(Recorded {
        backend,
        nonces,
        feed,
    })
}

/// The header values an audit or a resume recomputes from its own inputs
/// (task grants, workspace declaration, protocol, profile, policy, number
/// of checks), as the header writes them.
fn expected_inputs(
    spec: &TaskSpec,
    registry: &Registry,
    policy: &UserPolicy,
    profile: &Profile,
) -> Map<String, Value> {
    let mut grants: Vec<Value> = Vec::new();
    let mut names: Vec<&str> = spec.grants.iter().map(String::as_str).collect();
    if !names.contains(&SUBMIT_ID) {
        names.push(SUBMIT_ID);
    }
    for g in names {
        if let Resolved::One { capability, .. } = registry.resolve(g) {
            grants.push(Value::from(capability.id().as_str()));
        }
    }
    let mut m = Map::new();
    m.insert(
        "task".into(),
        Value::from(harness_core::sha256(spec.task.as_str().as_bytes()).to_string()),
    );
    m.insert("grants".into(), Value::Array(grants));
    m.insert(
        "workspace_public".into(),
        Value::Bool(spec.workspace_public),
    );
    m.insert(
        "protocol".into(),
        Value::from(match profile.protocol() {
            Protocol::Text => "text",
            Protocol::Native => "native",
        }),
    );
    m.insert(
        "profile".into(),
        Value::from(profile.content_sha256().to_string()),
    );
    m.insert("policy".into(), Value::from(policy.digest().to_string()));
    m.insert("checks".into(), Value::from(0u64));
    m.insert(
        "builtin_manifest".into(),
        Value::from(builtin_manifest_sha256().to_string()),
    );
    m.insert("shell_enabled".into(), Value::Bool(false));
    m
}

fn check_header(recorded: &Record, expected: &Map<String, Value>) -> Result<(), Divergence> {
    for k in HEADER_INPUT_KEYS {
        if recorded.body.get(k) != expected.get(k) {
            return Err(diverge(0, 0, header_mismatch(k)));
        }
    }
    Ok(())
}

/// What a differing header input means (H1f-3 review F-5): most are the
/// caller's inputs; `builtin_manifest` and `shell_enabled` belong to the
/// harness build, so a journal written by another build (every journal
/// from before H1f-3 included) cannot be audited or resumed by this one.
fn header_mismatch(key: &str) -> &'static str {
    match key {
        "task" => "the task given differs from the recorded header",
        "grants" => "the grants given differ from the recorded header",
        "workspace_public" => "the workspace declaration differs from the recorded header",
        "protocol" | "profile" => "the profile given differs from the recorded header",
        "policy" => "the policy given differs from the recorded header",
        "checks" => "the verification plan differs from the recorded header",
        "builtin_manifest" | "shell_enabled" => {
            "another harness build wrote this journal (its built-in manifest or shell setting differs)"
        }
        _ => "a header input differs from the recorded header",
    }
}

fn recorded_facts(h: &Record) -> Option<WorkspaceFacts> {
    Some(WorkspaceFacts {
        tree: digest_at(&h.body, "workspace_tree")?,
        files: h.body.get("workspace_files")?.as_u64()?,
        oversize: h.body.get("workspace_oversize")?.as_u64()?,
    })
}

fn recorded_limits(h: &Record) -> Option<MeterLimits> {
    let l = h.body.get("limits")?;
    let n = |k: &str| l.get(k).and_then(Value::as_u64);
    Some(MeterLimits {
        steps: u32::try_from(n("steps")?).ok()?,
        tokens: n("tokens")?,
        wall: Duration::from_millis(n("wall_ms")?),
        cost_micros: n("cost_micros")?,
        format_errors: u32::try_from(n("format_errors")?).ok()?,
        repair_rounds: u32::try_from(n("repair_rounds")?).ok()?,
    })
}

/// A record the comparison looks at: everything but the clock-dependent
/// wall-budget condition.
fn comparable(r: &Record) -> bool {
    !(r.kind == EventKind::BudgetCharged
        && r.body.get("key").and_then(Value::as_str) == Some("wall"))
}

/// How a recorded attempt compared with its replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Compared {
    /// Records that matched (header excluded).
    matched: usize,
    /// Whether the recorded stop itself was recomputed: false for a
    /// wall-budget stop (the clock is not replayable) and for an attempt
    /// that never committed.
    stop_recomputed: bool,
}

/// Compare the recorded attempt with its replay, header excluded.
fn compare(recorded: &[Record], replayed: &[Record]) -> Result<Compared, Divergence> {
    let rec: Vec<&Record> = recorded.iter().skip(1).filter(|r| comparable(r)).collect();
    let rep: Vec<&Record> = replayed.iter().skip(1).filter(|r| comparable(r)).collect();
    let (rec_body, rec_stop) = match rec.split_last() {
        Some((last, body)) if last.kind == EventKind::RunStopped => (body, Some(*last)),
        _ => (rec.as_slice(), None),
    };
    for (i, r) in rec_body.iter().enumerate() {
        let Some(p) = rep.get(i) else {
            return Err(diverge(
                r.seq,
                r.step,
                "the replay stopped before this recorded record",
            ));
        };
        if p.kind != r.kind || p.step != r.step {
            return Err(diverge(
                r.seq,
                r.step,
                "the replay wrote a different record here",
            ));
        }
        if p.body != r.body {
            return Err(diverge(
                r.seq,
                r.step,
                "the replay recomputed a different body for this record",
            ));
        }
    }
    let Some(stop) = rec_stop else {
        // An attempt that never committed: its recorded prefix matched.
        return Ok(Compared {
            matched: rec_body.len(),
            stop_recomputed: false,
        });
    };
    let s = |r: &Record, k: &str| r.body.get(k).cloned();
    if s(stop, "cause") == Some(Value::from("budget"))
        && s(stop, "dimension") == Some(Value::from("wall"))
    {
        // The wall clock is not replayable. Every recorded record matched,
        // but the stop was NOT recomputed: a journal cut at any step and
        // ended with a forged wall stop (re-chained) looks exactly like
        // this, so the caller must not call it verified without an anchor
        // (H1e-2b review F-1).
        return Ok(Compared {
            matched: rec_body.len(),
            stop_recomputed: false,
        });
    }
    let Some(p) = rep.get(rec_body.len()) else {
        return Err(diverge(stop.seq, stop.step, "the replay did not stop here"));
    };
    if p.kind != EventKind::RunStopped || rep.len() != rec_body.len() + 1 {
        return Err(diverge(
            stop.seq,
            stop.step,
            "the replay went on past the recorded stop",
        ));
    }
    if p.body != stop.body || p.step != stop.step {
        return Err(diverge(
            stop.seq,
            stop.step,
            "the replay stopped for another reason or with another outcome",
        ));
    }
    Ok(Compared {
        matched: rec_body.len() + 1,
        stop_recomputed: true,
    })
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

// ---------------------------------------------------------------------------
// Audit.
// ---------------------------------------------------------------------------

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
}

/// What an audit found.
#[derive(Debug)]
pub struct AuditReport {
    /// The attempt replayed.
    pub attempt: u32,
    /// Where the recomputed journal was written, when the replay ran.
    pub replay_dir: Option<PathBuf>,
    /// Records that matched (header excluded).
    pub matched: usize,
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

const UNREADABLE: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::UnreadableEvidence,
};

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

/// Replay a recorded attempt and compare (see the module docs).
pub fn audit(a: Audit<'_>) -> Result<AuditReport, AuditRefused> {
    let run_dir = run_dir_of(a.state_root, a.run).map_err(AuditRefused::NoRun)?;
    let attempt = match a.attempt {
        Some(n) => n,
        None => layout::latest_attempt(&run_dir)
            .map_err(AuditRefused::NoRun)?
            .ok_or(AuditRefused::NoAttempt)?,
    };
    let failed = |d: Divergence, replay_dir| AuditReport {
        attempt,
        replay_dir,
        matched: 0,
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
    if let Err(d) = check_header(
        head,
        &expected_inputs(a.spec, a.registry, a.policy, a.profile),
    ) {
        return Ok(failed(d, None));
    }
    let (Some(facts), Some(limits), Some(environment)) = (
        recorded_facts(head),
        recorded_limits(head),
        head.body.get("environment").and_then(sample::from_value),
    ) else {
        return Ok(failed(
            diverge(
                0,
                0,
                "the header lacks the workspace facts, the limits or the environment sample",
            ),
            None,
        ));
    };
    let blobs = DirBlobSource::new(attempt_dir.join(layout::BLOBS_DIR));
    let rec = match recorded(&v, &blobs, a.profile) {
        Ok(r) => r,
        Err(d) => return Ok(failed(d, None)),
    };
    let (session, tools) =
        plan(a.spec, a.registry, a.policy, a.profile).map_err(AuditRefused::Plan)?;
    let hdr = header(&HeaderInputs {
        spec: a.spec,
        registry: a.registry,
        policy: a.policy,
        profile: a.profile,
        identity: &rec.backend.identity(),
        facts,
        limits: &limits,
        resumed_from: None,
        // The replay journal repeats the recorded sample, marked as such:
        // a past host cannot be re-measured, and the header is not compared.
        environment,
        environment_recorded: true,
    })
    .map_err(AuditRefused::Plan)?;
    let (mut w, replay_dir) = JournalWriter::create_replay(&run_dir, a.run.clone(), attempt, hdr)
        .map_err(AuditRefused::Start)?;
    // The replay does not re-measure wall time (it cannot recompute it):
    // its meter has no wall limit, so a replay never stops on the clock.
    let limits = MeterLimits {
        wall: Duration::MAX,
        ..limits
    };
    let config = RunConfig {
        limits: limits.clone(),
        ..RunConfig::defaults(limits.tokens)
    };
    let mut lp = Loop {
        session,
        registry: a.registry,
        tools,
        task: &a.spec.task,
        facts: facts_block(&facts),
        profile: a.profile,
        backend: &rec.backend,
        providers: Vec::new(),
        meter: new_meter(limits, Box::new(SystemClock::default())),
        detector: LoopDetector::new(),
        turns: Vec::new(),
        config: &config,
        step: 0,
        nonces: NonceSource {
            recorded: rec.nonces,
        },
        feed: rec.feed,
        reads: ReadLog::default(),
        // No provider runs in an audit: a recorded result is re-fed with its
        // recorded sample. A step with no recorded result (an intent a crash
        // cut) ends as a provider failure, whose sample says it was not
        // sampled rather than borrowing the header's (confirming NF-1).
        env: &NOT_SAMPLED,
        pressure: Vec::new(),
    };
    let end = lp.drive(&mut w);
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
                replay_dir: Some(replay_dir),
                matched: c.matched,
                stop_recomputed: c.stop_recomputed,
                anchored,
                divergence: None,
                outcome,
            }
        }
        Err(d) => failed(d, Some(replay_dir)),
    })
}

// ---------------------------------------------------------------------------
// Resume.
// ---------------------------------------------------------------------------

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
    /// The workspace (must still have the recorded tree digest).
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
    /// Budgets and timeouts (the recorded limits apply; timeouts from here).
    pub config: &'a RunConfig,
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
    )?;
    let nope = RunRefused::NotResumable;
    let run_dir = layout::run_dir(&pre.state_root, r.run);
    match std::fs::symlink_metadata(&run_dir) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
        _ => return Err(nope("no such run directory")),
    }
    let n = layout::latest_attempt(&run_dir)
        .map_err(RunRefused::RunDir)?
        .ok_or(nope("the run has no attempt"))?;
    let attempt_dir = layout::attempt_dir(&run_dir, n);
    let v = JournalReader::open_expecting(&attempt_dir, r.run)
        .map_err(|_| nope("the last attempt's journal does not verify"))?;
    if v.records.iter().any(|x| x.kind == EventKind::RunStopped) {
        return Err(nope("the run already stopped; there is nothing to resume"));
    }
    let head = v
        .records
        .first()
        .ok_or(nope("the last attempt has no header"))?;
    check_header(
        head,
        &expected_inputs(r.spec, r.registry, r.policy, r.profile),
    )
    .map_err(|d| nope(d.why))?;
    if recorded_facts(head).map(|f| f.tree) != Some(pre.facts.tree) {
        return Err(nope(
            "the workspace changed since the attempt, and an H1 run keeps no snapshot to restore",
        ));
    }
    let limits = recorded_limits(head).ok_or(nope("the recorded header lacks the limits"))?;
    // Every step but the last is replayed; the last (possibly cut short)
    // runs again live.
    let last = v.records.iter().map(|x| x.step).max().unwrap_or(0);
    let kept = Verified {
        records: v
            .records
            .iter()
            .filter(|x| x.step < last)
            .cloned()
            .collect(),
        torn_tail: None,
        head: v.head,
        run: v.run.clone(),
        attempt: v.attempt,
    };
    let blobs = DirBlobSource::new(attempt_dir.join(layout::BLOBS_DIR));
    let rec = recorded(&kept, &blobs, r.profile)
        .map_err(|_| nope("the last attempt's records cannot be replayed"))?;
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
    let hdr = header(&HeaderInputs {
        spec: r.spec,
        registry: r.registry,
        policy: r.policy,
        profile: r.profile,
        identity: &r.backend.identity(),
        facts: pre.facts,
        limits: &limits,
        resumed_from: Some((n, v.head, carried_ms)),
        environment: r.env.sample(),
        environment_recorded: false,
    })?;
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
    let config = RunConfig {
        limits: limits.clone(),
        ..r.config.clone()
    };
    let mut lp = Loop {
        session: pre.session,
        registry: r.registry,
        tools: pre.tools,
        task: &r.spec.task,
        facts: facts_block(&pre.facts),
        profile: r.profile,
        backend: &chain,
        providers: vec![Box::new(pre.read_tools)],
        meter: new_meter_resumed(
            limits,
            Box::new(SystemClock::default()),
            Duration::from_millis(carried_ms),
        ),
        detector: LoopDetector::new(),
        turns: Vec::new(),
        config: &config,
        step: 0,
        nonces: NonceSource {
            recorded: rec.nonces,
        },
        feed: rec.feed,
        reads: ReadLog::default(),
        env: r.env,
        pressure: Vec::new(),
    };
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
    })
}
