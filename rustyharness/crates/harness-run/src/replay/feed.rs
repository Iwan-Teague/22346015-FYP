//! What a journal recorded, read back as replay inputs.

use std::collections::{BTreeMap, VecDeque};

use gate_outcome::Digest;
use harness_core::{Nonce, RunId};
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
use crate::session::{parse_input_end, RecordedInput};

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
    /// The session's recorded inputs, in order (P-17 §6): each `UserTurn`'s
    /// re-fed text, facts and wall time, and each `InputEnded`'s reason.
    /// The turn boundaries (`TurnEnded`) are re-fed by nothing: the replay
    /// recomputes them. Empty for a batch journal.
    pub(crate) inputs: VecDeque<RecordedInput>,
    /// The `ForkedFrom` record (P-32), if the journal is a fork's: the
    /// parent run, the parent step the child forked at (the last kept
    /// step) and the parent prefix's chain head the child recorded. The
    /// audit re-derives the head from the parent's records and refuses a
    /// child whose recorded head does not match.
    pub(crate) fork: Option<RecordedFork>,
    /// The repo map each session `ContextBuilt` carried (P-33), by step:
    /// the untrusted workspace payload's text. An audit and a resume's
    /// catch-up re-feed it (the workspace is not read in a replay); the
    /// replay writes the identical payload back, and the context digest
    /// covers the text either way.
    pub(crate) repo_maps: BTreeMap<u64, String>,
}

/// A fork journal's `ForkedFrom` record, read back (P-32).
pub(crate) struct RecordedFork {
    pub(crate) parent_run: RunId,
    pub(crate) parent_step: u64,
    pub(crate) parent_chain_head: Digest,
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

/// A recorded session grant (P-23), in exactly the shape the loop writes:
/// the capability, the list it joined, the matcher's canonical digest and
/// the approver kind.
fn rule_grant_of(r: &Record) -> Option<RecordedApproval> {
    let b = &r.body;
    if b.len() != 4
        || !["capability", "list", "matcher", "approver"]
            .iter()
            .all(|k| b.contains_key(*k))
    {
        return None;
    }
    b.get("capability")?.as_str()?;
    let matcher = digest_at(b, "matcher")?;
    let kind = ApproverKind::parse(b.get("approver")?.as_str()?)?;
    Some(match b.get("list")?.as_str()? {
        "allow" => RecordedApproval::AllowSession { kind, matcher },
        "deny" => RecordedApproval::DenySession { kind, matcher },
        _ => return None,
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

/// The project instructions one `InstructionsLoaded` records (P-30), in
/// exactly the shape the loop writes: three fields, the file name one of
/// the two the loop loads, the digest over the full text, and the text as
/// an untrusted workspace payload whose digest matches the named one.
fn instructions_record(r: &Record, blobs: &dyn BlobSource) -> Option<crate::session::Instructions> {
    if r.body.len() != 3
        || !["path", "digest", "text"]
            .iter()
            .all(|k| r.body.contains_key(*k))
    {
        return None;
    }
    let name = match r.body.get("path")?.as_str()? {
        "AGENTS.md" => "AGENTS.md",
        "CLAUDE.md" => "CLAUDE.md",
        _ => return None,
    };
    // The text payload names the workspace file it came from as its
    // source: anything else is not an `InstructionsLoaded` this loop
    // writes.
    let source_kind = r
        .body
        .get("text")
        .and_then(|t| t.get("source"))
        .and_then(|s| s.get("kind"))
        .and_then(Value::as_str);
    if source_kind != Some("workspace") {
        return None;
    }
    let bytes = payload_bytes(r.body.get("text")?, blobs, r.seq).ok()?;
    let instructions = crate::session::Instructions::new(name, &bytes).ok()?;
    if instructions.digest != digest_at(&r.body, "digest")? {
        return None;
    }
    Some(instructions)
}

/// The journal's project instructions (P-30): at most one
/// `InstructionsLoaded`, and only in a session journal. Scanned before the
/// header check, so an audit or a resume can recompute the header's
/// `instructions` digest from what the journal carries.
pub(crate) fn instructions_of(
    v: &Verified,
    blobs: &dyn BlobSource,
) -> Result<Option<crate::session::Instructions>, Divergence> {
    let session = v
        .records
        .first()
        .and_then(|h| h.body.get("mode").and_then(Value::as_str))
        == Some("session");
    let mut found = None;
    for r in &v.records {
        if r.kind != EventKind::InstructionsLoaded {
            continue;
        }
        let bad = || diverge(r.seq, r.step, "a record is not the shape the loop writes");
        if !session || found.is_some() {
            return Err(bad());
        }
        found = Some(instructions_record(r, blobs).ok_or_else(bad)?);
    }
    Ok(found)
}

/// Read the replay inputs from `records` (already verified).
pub(crate) fn recorded(
    v: &Verified,
    blobs: &dyn BlobSource,
    profile: &Profile,
) -> Result<Recorded, Divergence> {
    let backend = ReplayBackend::from_journal(v, blobs, profile.clone())
        .map_err(|_| diverge(0, 0, "the model records cannot be replayed"))?;
    // Only a session journal holds session records (`UserTurn`, `TurnEnded`,
    // `InputEnded`); in any other, they are not records this loop writes.
    let session = v
        .records
        .first()
        .and_then(|h| h.body.get("mode").and_then(Value::as_str))
        == Some("session");
    let mut nonces = BTreeMap::new();
    let mut feed = VecDeque::new();
    let mut approvals = VecDeque::new();
    let mut walls = BTreeMap::new();
    let mut inputs = VecDeque::new();
    let mut repo_maps = BTreeMap::new();
    let mut fork: Option<RecordedFork> = None;
    // The last `UserTurn`'s wall time: a later one's cannot be smaller
    // (P-17 §6) — the clock only moves forward, and an audit re-feeds this
    // rather than recomputing it, so the order is checked here.
    let mut last_turn_wall: Option<u64> = None;
    let mut intents: BTreeMap<u64, String> = BTreeMap::new();
    // `EditApplied` records waiting for their `ToolFinished` (H2b), by the
    // intent they answer, with each record's own seq: several since P-25
    // (a patch touches several files, a move two), in journal order.
    let mut edits: BTreeMap<u64, Vec<(u64, RecordedEdit)>> = BTreeMap::new();
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
                // The loop writes one per verified file change, right
                // before the result: an edit intent's, with the file's own
                // path as an untrusted payload, `before` only when the file
                // existed, the `after` and tree digests only when it still
                // exists (P-25: a delete carries neither), and the pre/
                // after images' blob digests (P-22: `before_blob` only when
                // there was a before; the after-blob is what a `/diff`
                // shows).
                let seq = r
                    .body
                    .get("intent_seq")
                    .and_then(Value::as_u64)
                    .ok_or_else(bad)?;
                let cap = intents.get(&seq).ok_or_else(bad)?;
                let shape = r.body.keys().all(|k| {
                    matches!(
                        k.as_str(),
                        "intent_seq"
                            | "path"
                            | "before"
                            | "after"
                            | "before_blob"
                            | "after_blob"
                            | "workspace_tree"
                    )
                });
                if !is_edit(cap) || !shape || !r.body.contains_key("path") {
                    return Err(bad());
                }
                // The path is an untrusted payload (re-hashed against its
                // record), and it must be a workspace path for the tree to
                // accept it (fail closed on anything else).
                let path = payload_bytes(r.body.get("path").ok_or_else(bad)?, blobs, r.seq)
                    .map_err(|_| bad())
                    .and_then(|b| String::from_utf8(b).map_err(|_| bad()))
                    .and_then(|p| {
                        harness_policy::workspace_path(&p)
                            .map(|_| p)
                            .map_err(|_| bad())
                    })?;
                let before = match r.body.get("before") {
                    None => None,
                    Some(_) => Some(digest_at(&r.body, "before").ok_or_else(bad)?),
                };
                // A cited image (P-22) is the blob its digest names, and the
                // bytes must hash to that digest: a blob's name is its
                // content's SHA-256, so a tampered or missing blob is a
                // shape the loop does not write.
                let image = |digest: Digest| -> Option<harness_tools::Image> {
                    let bytes = blobs.get(&digest.to_string())?;
                    (harness_core::sha256(&bytes) == digest).then_some(harness_tools::Image {
                        sha256: digest,
                        bytes,
                    })
                };
                let cited = |key: &str| digest_at(&r.body, key).ok_or_else(bad);
                // `before_blob` is present exactly when `before` is, and
                // names the same bytes the `before` digest is of.
                let before_image = match r.body.get("before_blob") {
                    None if before.is_some() => return Err(bad()),
                    None => None,
                    Some(_) => {
                        let d = cited("before_blob")?;
                        if before != Some(d) {
                            return Err(bad());
                        }
                        Some(image(d).ok_or_else(bad)?)
                    }
                };
                // `after_blob` likewise, present exactly when `after` is
                // (P-25: a delete carries neither).
                let after = match r.body.get("after") {
                    None => None,
                    Some(_) => Some(digest_at(&r.body, "after").ok_or_else(bad)?),
                };
                let after_image = match r.body.get("after_blob") {
                    None if after.is_some() => return Err(bad()),
                    None => None,
                    Some(_) => {
                        let d = cited("after_blob")?;
                        if after != Some(d) {
                            return Err(bad());
                        }
                        Some(image(d).ok_or_else(bad)?)
                    }
                };
                let e = RecordedEdit {
                    path,
                    before,
                    after,
                    tree: cited("workspace_tree")?,
                    before_image,
                    after_image,
                };
                edits.entry(seq).or_default().push((r.seq, e));
            }
            EventKind::ToolFinished => {
                let seq = r
                    .body
                    .get("intent_seq")
                    .and_then(Value::as_u64)
                    .ok_or_else(bad)?;
                let cap = intents.get(&seq).ok_or_else(bad)?.clone();
                let edit = edits.remove(&seq).unwrap_or_default();
                // The sentinel's and the checklist's results are the loop's
                // own, recomputed, never re-fed (H2e: the checklist).
                if cap == SUBMIT_ID || cap == TODO_ID {
                    if !edit.is_empty() {
                        return Err(bad());
                    }
                    continue;
                }
                let status = status_of(&r.body).ok_or_else(bad)?;
                // An ok edit has exactly its `EditApplied` records, nothing
                // else has any (H2b; P-25: one or more per touched file).
                if edit.is_empty() != !(is_edit(&cap) && status == Some(ToolStatus::Ok)) {
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
                    edits: edit.into_iter().map(|(_, e)| e).collect(),
                    exec,
                });
            }
            EventKind::ApprovalGranted | EventKind::ApprovalDenied | EventKind::ApprovalExpired => {
                approvals.push_back(approval_of(r).ok_or_else(bad)?);
            }
            // A session grant (P-23) rides the approvals queue like any
            // other answer: the replayed loop rebuilds the matcher from the
            // call it is recorded against and must reach the same digest.
            EventKind::RuleGranted => {
                approvals.push_back(rule_grant_of(r).ok_or_else(bad)?);
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
            // A session record in a journal that claims no session: not a
            // shape this loop writes (P-17 §6; the batch audit refuses a
            // session journal at its header's `mode` first, so this guards
            // the headerless case).
            EventKind::UserTurn | EventKind::TurnEnded | EventKind::InputEnded if !session => {
                return Err(bad())
            }
            // P-26: a `Restored` is re-fed by its checkpoint — the step and
            // the tree digest the record names; everything else (the files
            // the undone edits named, the notice) is recomputed from the
            // journal's own edit records and compared by the record's body.
            // P-27: a post-edit rollback names the edit's own step
            // (`to_step` = the record's step); the hook recomputes it in
            // place, so it is checked for shape but not re-fed as an input
            // — only a `/undo` (a step earlier than its own) is.
            EventKind::Restored => {
                if r.body.len() != 3
                    || !["to_step", "tree_digest", "files"]
                        .iter()
                        .all(|k| r.body.contains_key(*k))
                {
                    return Err(bad());
                }
                let to_step = r
                    .body
                    .get("to_step")
                    .and_then(Value::as_u64)
                    .ok_or_else(bad)?;
                let tree_digest = digest_at(&r.body, "tree_digest").ok_or_else(bad)?;
                // The files payload is a JSON array of path strings: the
                // shape the loop writes, checked here so a record that
                // could never be recomputed is refused at the source.
                let bytes = payload_bytes(r.body.get("files").ok_or_else(bad)?, blobs, r.seq)
                    .map_err(|_| bad())?;
                let files: Vec<Value> = serde_json::from_slice(&bytes).map_err(|_| bad())?;
                if files.iter().any(|f| !f.is_string()) {
                    return Err(bad());
                }
                if to_step != r.step {
                    if !session {
                        return Err(bad());
                    }
                    inputs.push_back(RecordedInput::Restore {
                        to_step,
                        tree_digest,
                    });
                }
            }
            // P-17 §6: a `UserTurn` is re-fed in exactly its re-fed parts —
            // the text, the facts it was measured with, and its wall time —
            // in exactly the shape the loop writes (nine fields). Everything
            // else about the turn (its number, the shown decision, whether
            // the workspace changed, its allowance) is recomputed.
            EventKind::UserTurn => {
                let shape = r.body.len() == 9
                    && [
                        "external_change",
                        "shown",
                        "text",
                        "turn",
                        "turn_steps",
                        "wall_used_ms",
                        "workspace_files",
                        "workspace_oversize",
                        "workspace_tree",
                    ]
                    .iter()
                    .all(|k| r.body.contains_key(*k));
                if !shape {
                    return Err(bad());
                }
                // The text payload names the user as its source: anything
                // else is not a `UserTurn` this loop writes.
                let source_kind = r
                    .body
                    .get("text")
                    .and_then(|t| t.get("source"))
                    .and_then(|s| s.get("kind"))
                    .and_then(Value::as_str);
                if source_kind != Some("user") {
                    return Err(bad());
                }
                let bytes = payload_bytes(r.body.get("text").ok_or_else(bad)?, blobs, r.seq)
                    .map_err(|_| bad())?;
                let text = String::from_utf8(bytes).map_err(|_| bad())?;
                let n = |k: &str| r.body.get(k).and_then(Value::as_u64);
                let (Some(wall_used_ms), Some(files), Some(oversize)) = (
                    n("wall_used_ms"),
                    n("workspace_files"),
                    n("workspace_oversize"),
                ) else {
                    return Err(bad());
                };
                if last_turn_wall.is_some_and(|prev| wall_used_ms < prev) {
                    return Err(diverge(
                        r.seq,
                        r.step,
                        "a user turn's wall time is before the last one's",
                    ));
                }
                last_turn_wall = Some(wall_used_ms);
                let facts = WorkspaceFacts {
                    tree: digest_at(&r.body, "workspace_tree").ok_or_else(bad)?,
                    files,
                    oversize,
                };
                inputs.push_back(RecordedInput::Message {
                    text,
                    facts,
                    wall_used_ms,
                });
            }
            // An `InputEnded` is re-fed by its reason; its turn number is
            // recomputed, and exactly the two fields are written.
            EventKind::InputEnded => {
                if r.body.len() != 2 || !r.body.contains_key("turn") {
                    return Err(bad());
                }
                let reason = r
                    .body
                    .get("reason")
                    .and_then(Value::as_str)
                    .and_then(parse_input_end)
                    .ok_or_else(bad)?;
                inputs.push_back(RecordedInput::End(reason));
            }
            // A turn boundary is the loop's own: recomputed, never re-fed.
            EventKind::TurnEnded => {}
            // P-28: a session's mode changes re-feed as the input they were
            // (`/plan`, `/build`); the replay re-derives the state each
            // names and the record bodies are compared. Only a session
            // writes them (a batch loop has no user to answer).
            EventKind::ModeChanged if session => {
                let mode = r.body.get("mode").and_then(Value::as_str).ok_or_else(bad)?;
                match mode {
                    "plan" if r.body.len() == 1 => inputs.push_back(RecordedInput::PlanMode),
                    "build" if r.body.len() == 2 => {
                        // The digest itself is recomputed from the re-driven
                        // plan call; here it only has to be a digest.
                        r.body
                            .get("plan_digest")
                            .and_then(Value::as_str)
                            .is_some_and(|d| {
                                d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit())
                            })
                            .then_some(())
                            .ok_or_else(bad)?;
                        inputs.push_back(RecordedInput::BuildPlan);
                    }
                    _ => return Err(bad()),
                }
            }
            // P-30: the project instructions re-derive as loop state (the
            // replay rewrites the record from it, and the shapes are
            // compared); `instructions_of` parsed the same record. Only a
            // session writes it (a batch loop loads nothing).
            EventKind::InstructionsLoaded if session => {
                instructions_record(r, blobs).ok_or_else(bad)?;
            }
            // P-33: the repo map a coding session's context showed, as an
            // untrusted workspace payload. Re-fed, never recomputed: an
            // audit never reads the workspace. Its source must name the
            // workspace (the only source the loop writes it with), and its
            // bytes must be UTF-8 text (the map is text by construction).
            EventKind::ContextBuilt => {
                if let Some(t) = r.body.get("repo_map") {
                    let source_kind = t
                        .get("source")
                        .and_then(|s| s.get("kind"))
                        .and_then(Value::as_str);
                    if source_kind != Some("workspace") {
                        return Err(bad());
                    }
                    let bytes = payload_bytes(t, blobs, r.seq).map_err(|_| bad())?;
                    let text = String::from_utf8(bytes).map_err(|_| bad())?;
                    repo_maps.insert(r.step, text);
                }
            }
            // A fork's first record (P-32): the parent run, the kept step
            // and the parent prefix's chain head. Exactly one, at step 0,
            // directly after the header.
            EventKind::ForkedFrom if session => {
                if fork.is_some() || r.step != 0 || r.body.len() != 3 {
                    return Err(bad());
                }
                let parent_run = r
                    .body
                    .get("parent_run")
                    .and_then(Value::as_str)
                    .and_then(RunId::parse)
                    .ok_or_else(bad)?;
                let parent_step = r
                    .body
                    .get("parent_step")
                    .and_then(Value::as_u64)
                    .ok_or_else(bad)?;
                let parent_chain_head = digest_at(&r.body, "parent_chain_head").ok_or_else(bad)?;
                fork = Some(RecordedFork {
                    parent_run,
                    parent_step,
                    parent_chain_head,
                });
            }
            // A record no slice owns yet is not a shape this loop writes
            // (P-17 §6). The background-process kinds are owned from P-36h
            // (canon, the record shapes), but nothing writes them until
            // P-36j/P-36l, and their re-feed is P-36k: until then they are
            // refused like the other reserved names.
            EventKind::ModeChanged
            | EventKind::InstructionsLoaded
            | EventKind::ChildRun
            | EventKind::BgStopped
            | EventKind::OrphanCheck => return Err(bad()),
            _ => {}
        }
    }
    // An `EditApplied` with no result can only be the journal's last record:
    // a crash between the two. Re-fed as the edit it records (its result's
    // own fields were never written, so nothing after it is compared).
    for (seq, group) in edits {
        // Only the journal's very last record may dangle; but a whole edit
        // group (P-25) was written together, so any but its last member
        // dangling is a shape the loop does not write either.
        let last = group.last().map_or(0, |(at, _)| *at);
        if last != last_seq {
            return Err(diverge(
                last,
                0,
                "a record is not the shape the loop writes",
            ));
        }
        let cap = intents.get(&seq).cloned().unwrap_or_default();
        for (_, e) in group {
            feed.push_back(RecordedResult {
                capability: cap.clone(),
                status: Some(ToolStatus::Ok),
                output: Vec::new(),
                truncated: false,
                digest: harness_core::sha256(b""),
                read_sha256: None,
                environment: None,
                edits: vec![e],
                exec: None,
            });
        }
    }
    Ok(Recorded {
        backend,
        nonces,
        feed,
        approvals,
        walls,
        inputs,
        fork,
        repo_maps,
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
