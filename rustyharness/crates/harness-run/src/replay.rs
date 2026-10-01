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
//! The header inputs, the budget limits among them, are the CALLER's and
//! must equal the recorded ones: the replay recomputes every budget stop
//! from the limits, so limits read from the journal would let a re-chained
//! edit choose the stop it then "recomputes" (H1 phase-exit review F-1).
//! Two recorded facts are not recomputable and are handled explicitly:
//! - **wall time.** A `BudgetCharged` record for the `wall` dimension is
//!   left out of the comparison on both sides, and the replay's meter has
//!   no wall limit. What is left out must be exactly what the loop writes
//!   for the wall dimension: at most one record per attempt, the entry
//!   `{condition: enter, key: wall}` (wall time never decreases within an
//!   attempt, so the loop never writes a wall exit; H1g confirming review
//!   NF-1); anything else is a divergence, and how many were left out is
//!   reported
//!   (`AuditReport::wall_skipped`). A run stopped by the wall budget can
//!   only be checked up to its last record: every recorded record must
//!   match, but the stop itself is NOT recomputed
//!   (`AuditReport::stop_recomputed` is false). Since a journal cut at any
//!   step boundary and ended with a forged wall stop, re-chained, looks
//!   exactly the same (H1e-2b review F-1), such an audit is
//!   `Indeterminate { UnreadableEvidence }` unless the caller's anchor
//!   matched the journal's chain head; only the anchor proves that nothing
//!   was removed.
//! - **the workspace.** Audit mode re-feeds tool output; it never reads the
//!   workspace. The workspace facts come from the recorded header.
//!
//! **Resume** ([`resume`]) continues an attempt that has no `RunStopped`
//! (a crash or a kill) in a NEW attempt directory: the old journal is only
//! read, never appended to, poisoned or not. Its header records the attempt
//! it continues and that journal's chain head. The new attempt first
//! replays every COMPLETED step of the old one (catch-up: recorded
//! replies, tool results, edits and approvals re-fed; each model request
//! the catch-up renders must have its recorded digest, but the other
//! records it recomputes are NOT compared with the old attempt's: to check
//! those, audit the old attempt, `replay --attempt <n>`; H1 phase-exit
//! review F-3). A step is completed when its call has a durable
//! `ToolFinished` (H2b, the H1e-2b row's H2 condition): it is re-fed and
//! never run again, so a completed edit is never repeated. Only a last step
//! the crash cut (a trailing intent without a result, or no call yet) runs
//! again live, so policy decides it again, never executing it blindly. A
//! request that differs makes the resumed run `Indeterminate
//! { UnreadableEvidence }`. The header inputs, the budget limits included,
//! must equal the recorded ones, and the approver's presence too, or the
//! resume is refused. The harness keeps no content snapshot to restore
//! (materialisation, H2), so the snapshot of §2.10 is a tree digest: the
//! workspace must hold the one the kept records end with (the last
//! `EditApplied`'s, or the header's), and a resume is refused otherwise
//! (an edit applied without its result, or a change made outside the run).
//! The resumed header carries the run-start facts, so block 4 renders as
//! it did. An attempt with no header (a start that failed) and a resumed
//! attempt that stopped at its header are passed over and named (H1
//! phase-exit review F-5).
//! The wall time the interrupted attempt spent (its journal's last
//! monotonic time, the writer's elapsed time) is charged to the resumed
//! attempt's meter from the start, so a kill and resume buys no fresh wall
//! budget up to the interrupted attempt's last durable record; the time
//! after it, up to one model call (300 s by default), is not charged, so
//! each kill and resume can regain that much (H1 phase-exit review F-13).
//! Steps and tokens are re-charged by the catch-up. That wall time
//! is taken from the interrupted attempt's journal (the header's
//! `resumed_from.wall_carried_ms` and the last record's `t_mono_ms`). An
//! interrupted attempt has no printed chain head, and resume takes no
//! anchor, so a consistent edit made to it before the resume is not
//! detected; after it, the resumed header's `resumed_from.chain_head` pins
//! what was resumed from, and an anchored audit of the resumed attempt
//! covers that (H1g confirming review NF-2).

use std::borrow::Cow;
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
use harness_model::context::CONTEXT_FORMAT;
use harness_model::profile::{Profile, Protocol};
use harness_model::replay::{payload_bytes, ReplayBackend};
use harness_model::{Completion, ModelBackend, ModelError, ModelIdentity, ModelRequest};
use harness_policy::locality::LocalityProbe;
use harness_policy::{UserPolicy, SUBMIT_ID};
use harness_tools::builtin::WorkspaceFacts;
use harness_tools::{RefusalKind, ToolStatus};
use serde_json::{Map, Value};

use crate::approve::{nonce_bytes, Approver, ApproverKind, RecordedApproval};
use crate::driver::{
    attempt_check, builtin_manifest_sha256, commit, facts_block, header, is_edit, limits_fields,
    new_meter, new_meter_resumed, plan, prepare, Approvals, HeaderInputs, Loop, NonceSource,
    Prepared, ReadLog, RecordedEdit, RecordedResult, HEADER_INPUT_KEYS,
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
    /// The approvers' recorded answers, in order (H2b).
    approvals: VecDeque<RecordedApproval>,
}

/// A recorded approval answer, in exactly the shape the loop writes: the
/// capability, argument digest and tier of every approval record, then the
/// approver kind (granted, denied) and the nonce (granted).
fn approval_of(r: &Record) -> Option<RecordedApproval> {
    let b = &r.body;
    let mut keys = vec!["capability", "args", "tier"];
    match r.kind {
        EventKind::ApprovalGranted => keys.extend(["approver", "nonce", "scope"]),
        EventKind::ApprovalDenied => keys.push("approver"),
        _ => {}
    }
    if b.len() != keys.len() || !keys.iter().all(|k| b.contains_key(*k)) {
        return None;
    }
    digest_at(b, "args")?;
    b.get("capability")?.as_str()?;
    b.get("tier")?.as_str()?;
    let kind = || ApproverKind::parse(b.get("approver")?.as_str()?);
    Some(match r.kind {
        EventKind::ApprovalGranted => {
            if b.get("scope")?.as_str()? != "once" {
                return None;
            }
            RecordedApproval::Granted {
                kind: kind()?,
                nonce: nonce_bytes(b.get("nonce")?.as_str()?)?,
            }
        }
        EventKind::ApprovalDenied => RecordedApproval::Denied { kind: kind()? },
        _ => RecordedApproval::Expired,
    })
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
    let mut approvals = VecDeque::new();
    let mut intents: BTreeMap<u64, String> = BTreeMap::new();
    // `EditApplied` records waiting for their `ToolFinished` (H2b), by the
    // intent they answer, with the record's own seq.
    let mut edits: BTreeMap<u64, (u64, RecordedEdit)> = BTreeMap::new();
    let last_seq = v.records.last().map_or(0, |r| r.seq);
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
            EventKind::EditApplied => {
                // The loop writes one for a verified edit, right before its
                // result: an edit intent's, with the path as an untrusted
                // payload, `before` only when the file existed, and the
                // after and tree digests.
                let seq = r
                    .body
                    .get("intent_seq")
                    .and_then(Value::as_u64)
                    .ok_or_else(bad)?;
                let cap = intents.get(&seq).ok_or_else(bad)?;
                let shape = r.body.keys().all(|k| {
                    matches!(
                        k.as_str(),
                        "intent_seq" | "path" | "before" | "after" | "workspace_tree"
                    )
                });
                if !is_edit(cap) || !shape || !r.body.contains_key("path") {
                    return Err(bad());
                }
                let before = match r.body.get("before") {
                    None => None,
                    Some(_) => Some(digest_at(&r.body, "before").ok_or_else(bad)?),
                };
                let e = RecordedEdit {
                    before,
                    after: digest_at(&r.body, "after").ok_or_else(bad)?,
                    tree: digest_at(&r.body, "workspace_tree").ok_or_else(bad)?,
                };
                if edits.insert(seq, (r.seq, e)).is_some() {
                    return Err(bad());
                }
            }
            EventKind::ToolFinished => {
                let seq = r
                    .body
                    .get("intent_seq")
                    .and_then(Value::as_u64)
                    .ok_or_else(bad)?;
                let cap = intents.get(&seq).ok_or_else(bad)?.clone();
                let edit = edits.remove(&seq).map(|(_, e)| e);
                if cap == SUBMIT_ID {
                    continue;
                }
                let status = status_of(&r.body).ok_or_else(bad)?;
                // An ok edit has exactly its `EditApplied`, nothing else has
                // one (H2b).
                if edit.is_some() != (is_edit(&cap) && status == Some(ToolStatus::Ok)) {
                    return Err(bad());
                }
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
                    edit,
                });
            }
            EventKind::ApprovalGranted | EventKind::ApprovalDenied | EventKind::ApprovalExpired => {
                approvals.push_back(approval_of(r).ok_or_else(bad)?);
            }
            _ => {}
        }
    }
    // An `EditApplied` with no result can only be the journal's last record:
    // a crash between the two. Re-fed as the edit it records (its result's
    // own fields were never written, so nothing after it is compared).
    for (seq, (at, e)) in edits {
        if at != last_seq {
            return Err(diverge(at, 0, "a record is not the shape the loop writes"));
        }
        feed.push_back(RecordedResult {
            capability: intents.get(&seq).cloned().unwrap_or_default(),
            status: Some(ToolStatus::Ok),
            output: Vec::new(),
            truncated: false,
            digest: harness_core::sha256(b""),
            read_sha256: None,
            environment: None,
            edit: Some(e),
        });
    }
    Ok(Recorded {
        backend,
        nonces,
        feed,
        approvals,
    })
}

/// The header values an audit or a resume recomputes from its own inputs
/// (task grants, workspace declaration, protocol, profile, policy, number
/// of checks, budget limits), as the header writes them.
fn expected_inputs(
    spec: &TaskSpec,
    registry: &Registry,
    policy: &UserPolicy,
    profile: &Profile,
    limits: &MeterLimits,
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
    m.insert("context_format".into(), Value::from(CONTEXT_FORMAT));
    m.insert(
        "limits".into(),
        Value::Object(
            limits_fields(limits)
                .into_iter()
                .map(|(k, v)| (k.to_owned(), Value::from(v)))
                .collect(),
        ),
    );
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
/// caller's inputs; `builtin_manifest`, `shell_enabled` and
/// `context_format` belong to the harness build, so a journal written by
/// another build (every journal from before H1f-3 included, and, for the
/// context format, every journal from before H1h) cannot be audited or
/// resumed by this one, and says so.
fn header_mismatch(key: &str) -> &'static str {
    match key {
        "task" => "the task given differs from the recorded header",
        "grants" => "the grants given differ from the recorded header",
        "workspace_public" => "the workspace declaration differs from the recorded header",
        "protocol" | "profile" => "the profile given differs from the recorded header",
        "policy" => "the policy given differs from the recorded header",
        "checks" => "the verification plan differs from the recorded header",
        "limits" => "the budget limits given differ from the recorded header",
        "builtin_manifest" | "shell_enabled" => {
            "another harness build wrote this journal (its built-in manifest or shell setting differs)"
        }
        "context_format" => {
            "another harness build wrote this journal (its context format differs: since H1h the \
             native protocol shows past actions as tool calls, so an older journal's contexts \
             cannot be recomputed; audit it with the build that wrote it)"
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

/// A wall-budget condition record: when the clock crossed 80% of the wall
/// budget is not recomputable, so the comparison leaves these out.
fn is_wall_condition(r: &Record) -> bool {
    r.kind == EventKind::BudgetCharged && r.body.get("key").and_then(Value::as_str) == Some("wall")
}

/// Check the recorded wall-budget condition records before they are left
/// out of the comparison (H1 phase-exit review F-1): each must be exactly
/// what the loop writes (`StandingConditions::observe`). For the wall
/// dimension that is at most one record per attempt, the entry
/// `{condition: enter, key: wall}`: the meter's wall time never decreases
/// within an attempt and its limit is fixed, so the 80% condition turns
/// true at most once and never turns false again, and the loop never
/// writes a wall exit (H1g confirming review NF-1). A second record, an
/// exit, or any other body is a record the loop did not write. Returns
/// how many were left out (0 or 1).
pub(crate) fn check_wall_conditions(recorded: &[Record]) -> Result<usize, Divergence> {
    let mut n = 0;
    for r in recorded.iter().filter(|r| is_wall_condition(r)) {
        let b = &r.body;
        let loop_wrote =
            n == 0 && b.len() == 2 && b.get("condition").and_then(Value::as_str) == Some("enter");
        if !loop_wrote {
            return Err(diverge(
                r.seq,
                r.step,
                "a wall-budget record is not one the loop writes",
            ));
        }
        n += 1;
    }
    Ok(n)
}

/// How a recorded attempt compared with its replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Compared {
    /// Records that matched (header and wall-budget records excluded).
    matched: usize,
    /// Wall-budget condition records left out of the comparison, each
    /// checked to be a record the loop writes.
    wall_skipped: usize,
    /// Whether the recorded stop itself was recomputed: false for a
    /// wall-budget stop (the clock is not replayable) and for an attempt
    /// that never committed.
    stop_recomputed: bool,
}

/// Compare the recorded attempt with its replay, header excluded: the
/// first divergence in record order, whether it is a record the replay
/// recomputed differently or a wall-budget record the loop does not write.
fn compare(recorded: &[Record], replayed: &[Record]) -> Result<Compared, Divergence> {
    match (
        check_wall_conditions(recorded),
        compare_recomputed(recorded, replayed),
    ) {
        (Ok(wall_skipped), Ok(c)) => Ok(Compared { wall_skipped, ..c }),
        (Err(w), Err(d)) => Err(if w.seq < d.seq { w } else { d }),
        (Err(w), Ok(_)) => Err(w),
        (Ok(_), Err(d)) => Err(d),
    }
}

/// The seqs of a journal's wall-budget condition records, in order.
fn wall_seqs(records: &[Record]) -> Vec<u64> {
    records
        .iter()
        .filter(|r| is_wall_condition(r))
        .map(|r| r.seq)
        .collect()
}

/// A body as the comparison sees it. A result's `intent_seq` (the seq of
/// the intent it answers) is counted among the records compared, without
/// the wall-budget records before it: the replay writes none, so each one
/// the recorded journal holds shifts every later seq by one, and a run
/// that crossed 80% of its wall budget before a later tool result would
/// otherwise never match (found fixing H1 phase-exit review F-1). One
/// that points at a wall-budget record points at no intent: it never
/// matches.
fn compared_body<'r>(r: &'r Record, walls: &[u64]) -> Cow<'r, Map<String, Value>> {
    match r.body.get("intent_seq").and_then(Value::as_u64) {
        Some(n) => {
            let counted = match walls.binary_search(&n) {
                Ok(_) => Value::Null,
                Err(before) => Value::from(n.saturating_sub(before as u64)),
            };
            let mut b = r.body.clone();
            b.insert("intent_seq".into(), counted);
            Cow::Owned(b)
        }
        None => Cow::Borrowed(&r.body),
    }
}

/// Compare every recorded record the replay recomputes (all but the header
/// and the wall-budget records) with the replay's.
fn compare_recomputed(recorded: &[Record], replayed: &[Record]) -> Result<Compared, Divergence> {
    let (rec_walls, rep_walls) = (wall_seqs(recorded), wall_seqs(replayed));
    let rec: Vec<&Record> = recorded
        .iter()
        .skip(1)
        .filter(|r| !is_wall_condition(r))
        .collect();
    let rep: Vec<&Record> = replayed
        .iter()
        .skip(1)
        .filter(|r| !is_wall_condition(r))
        .collect();
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
        if compared_body(p, &rep_walls) != compared_body(r, &rec_walls) {
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
            wall_skipped: 0,
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
            wall_skipped: 0,
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
        wall_skipped: 0,
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

const UNREADABLE: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::UnreadableEvidence,
};

/// The attempt numbers under `run_dir`, highest first.
fn attempts_desc(run_dir: &Path) -> io::Result<Vec<u32>> {
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
fn has_header(attempt_dir: &Path) -> io::Result<bool> {
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

/// Replay a recorded attempt and compare (see the module docs).
pub fn audit(a: Audit<'_>) -> Result<AuditReport, AuditRefused> {
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
    if let Err(d) = check_header(
        head,
        &expected_inputs(a.spec, a.registry, a.policy, a.profile, a.limits),
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
    let blobs = DirBlobSource::new(attempt_dir.join(layout::BLOBS_DIR));
    let rec = match recorded(&v, &blobs, a.profile) {
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
    let (session, tools) = plan(a.spec, a.registry, a.policy, a.profile, approver_present)
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
    })
    .map_err(AuditRefused::Plan)?;
    let (mut w, replay_dir) = JournalWriter::create_replay(&run_dir, a.run.clone(), attempt, hdr)
        .map_err(AuditRefused::Start)?;
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
        tree: facts.tree,
        workspace: None,
        // Nobody is asked in an audit: the recorded answers are re-fed and
        // re-minted with their recorded nonces (a reused one refuses).
        approvals: Approvals::new(a.run, attempt, None, rec.approvals),
        // No provider runs in an audit: a recorded result is re-fed with its
        // recorded sample. A step with no recorded result (an intent a crash
        // cut) ends as a provider failure, whose sample says it was not
        // sampled rather than borrowing the header's (confirming NF-1).
        env: &NOT_SAMPLED,
        pressure: Vec::new(),
        reads_seen: Default::default(),
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
    let expected = kept
        .records
        .iter()
        .rev()
        .filter(|x| x.kind == EventKind::EditApplied)
        .find_map(|x| digest_at(&x.body, "workspace_tree"))
        .unwrap_or(start.tree);
    if pre.facts.tree != expected {
        return Err(nope(
            "the workspace differs from the interrupted attempt's last durable record (an edit \
             applied without its result, or a change made outside the run); this build keeps no \
             snapshot to restore",
        ));
    }
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
    let mut lp = Loop {
        session: pre.session,
        registry: r.registry,
        tools: pre.tools,
        task: &r.spec.task,
        facts: facts_block(&start),
        profile: r.profile,
        backend: &chain,
        providers: Prepared::providers(pre.read_tools, pre.edit_tools),
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
