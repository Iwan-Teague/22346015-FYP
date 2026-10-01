//! What a journal recorded, read back as replay inputs.

use std::collections::{BTreeMap, VecDeque};

use gate_outcome::Digest;
use harness_core::Nonce;
use harness_journal::{BlobSource, EventKind, Record, Verified};
use harness_model::profile::Profile;
use harness_model::replay::{payload_bytes, ReplayBackend};
use harness_policy::{SUBMIT_ID, TODO_ID};
use harness_tools::builtin::WorkspaceFacts;
use harness_tools::{RefusalKind, ToolStatus};
use serde_json::{Map, Value};

use super::compare::{diverge, Divergence};
use crate::approve::{nonce_bytes, ApproverKind, RecordedApproval};
use crate::driver::{is_edit, is_exec, parse_exec, RecordedEdit, RecordedResult};
use crate::sample;

/// The replay inputs recorded in a journal.
pub(crate) struct Recorded {
    pub(crate) backend: ReplayBackend,
    /// Each observation's nonce, by the step of the observation (H1i).
    pub(crate) nonces: BTreeMap<u64, Nonce>,
    pub(crate) feed: VecDeque<RecordedResult>,
    /// The approvers' recorded answers, in order (H2b).
    pub(crate) approvals: VecDeque<RecordedApproval>,
    /// The recorded wall-budget notices, by step: (percent, milliseconds
    /// used) (H2e). The clock is not recomputable, so these are re-fed; the
    /// loop re-writes each and refuses one it would not write.
    pub(crate) walls: BTreeMap<u64, (u64, u64)>,
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

pub(crate) fn digest_at(b: &Map<String, Value>, key: &str) -> Option<Digest> {
    b.get(key)?.as_str()?.parse().ok()
}

/// Read the replay inputs from `records` (already verified).
pub(crate) fn recorded(
    v: &Verified,
    blobs: &dyn BlobSource,
    profile: &Profile,
) -> Result<Recorded, Divergence> {
    let backend = ReplayBackend::from_journal(v, blobs, profile.clone())
        .map_err(|_| diverge(0, 0, "the model records cannot be replayed"))?;
    let mut nonces = BTreeMap::new();
    let mut feed = VecDeque::new();
    let mut approvals = VecDeque::new();
    let mut walls = BTreeMap::new();
    let mut intents: BTreeMap<u64, String> = BTreeMap::new();
    // `EditApplied` records waiting for their `ToolFinished` (H2b), by the
    // intent they answer, with the record's own seq.
    let mut edits: BTreeMap<u64, (u64, RecordedEdit)> = BTreeMap::new();
    let last_seq = v.records.last().map_or(0, |r| r.seq);
    for r in &v.records {
        let bad = || diverge(r.seq, r.step, "a record is not the shape the loop writes");
        match r.kind {
            // The nonce drawn for the observation a request showed first
            // (H1i), re-fed at that observation's first render. Whether an
            // observation was withheld is recomputed, not re-fed.
            EventKind::ModelRequested => match (r.body.get("nonce"), r.body.get("nonce_step")) {
                (None, None) => {}
                (Some(n), Some(s)) => {
                    let n = n.as_str().and_then(Nonce::new).ok_or_else(bad)?;
                    let s = s.as_u64().ok_or_else(bad)?;
                    if nonces.insert(s, n).is_some() {
                        return Err(bad());
                    }
                }
                _ => return Err(bad()),
            },
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
                // The sentinel's and the checklist's results are the loop's
                // own, recomputed, never re-fed (H2e: the checklist).
                if cap == SUBMIT_ID || cap == TODO_ID {
                    if edit.is_some() {
                        return Err(bad());
                    }
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
                // A command's record (H2d): only on the runner's result, in
                // exactly the shape the loop writes, with the tree digest
                // measured after it where there was one; nothing else
                // carries either.
                let exec = match r.body.get("exec") {
                    None if r.body.contains_key("workspace_tree") => return Err(bad()),
                    None => None,
                    Some(_) if !is_exec(&cap) || status.is_none() => return Err(bad()),
                    Some(v) => {
                        let tree = match r.body.get("workspace_tree") {
                            None => None,
                            Some(_) => Some(digest_at(&r.body, "workspace_tree").ok_or_else(bad)?),
                        };
                        Some((parse_exec(v).ok_or_else(bad)?, tree))
                    }
                };
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
                    exec,
                });
            }
            EventKind::ApprovalGranted | EventKind::ApprovalDenied | EventKind::ApprovalExpired => {
                approvals.push_back(approval_of(r).ok_or_else(bad)?);
            }
            // A wall-budget notice (H2e), in exactly the shape the loop
            // writes, at most one per step; the step notices are recomputed.
            EventKind::BudgetNotice
                if r.body.get("key").and_then(Value::as_str) == Some("wall") =>
            {
                let n = |k: &str| r.body.get(k).and_then(Value::as_u64);
                let (Some(percent), Some(used_ms), Some(_)) =
                    (n("percent"), n("used_ms"), n("limit_ms"))
                else {
                    return Err(bad());
                };
                if r.body.len() != 4 || walls.insert(r.step, (percent, used_ms)).is_some() {
                    return Err(bad());
                }
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
            exec: None,
        });
    }
    Ok(Recorded {
        backend,
        nonces,
        feed,
        approvals,
        walls,
    })
}

/// The workspace facts a header records, read back for the replay's
/// planning (audit) and its workspace check (resume).
pub(crate) fn recorded_facts(h: &Record) -> Option<WorkspaceFacts> {
    Some(WorkspaceFacts {
        tree: digest_at(&h.body, "workspace_tree")?,
        files: h.body.get("workspace_files")?.as_u64()?,
        oversize: h.body.get("workspace_oversize")?.as_u64()?,
    })
}
