//! Replay, audit mode (design §2.9, INV-20): model half.
//!
//! **Recording.** Every call is journaled as a pair:
//! - `ModelRequested { request: <sha256 of the rendered request>, nonce }`
//!   ([`requested_event`]);
//! - `ModelReplied { … }` ([`replied_event`]) carrying either the completion
//!   (content and each tool call's name and arguments as `UntrustedBlob`s;
//!   finish reason; usage; byte counts; retried statuses) or the typed
//!   error (`error` + its details).
//!
//! **Replaying.** [`ReplayBackend::from_journal`] reads those pairs from a
//! verified journal (and its blob store) and implements [`ModelBackend`]:
//! each call re-renders the request the driver built, compares its digest
//! with the recorded one, and only on a match returns the recorded reply.
//! A different request, or a call past the end of the recording, is
//! [`ModelError::ReplayDiverged`] naming the exchange: the first
//! divergence, never a best-effort answer.
//!
//! **What is NOT here (H1e).** Recomputing every context digest and policy
//! decision of a whole run, comparing them with the journal, and reporting
//! `Indeterminate { UnreadableEvidence }` at the first divergent step is the
//! audit DRIVER; it needs the H1e loop (context builder, policy session,
//! journaled tool results). This module gives it the backend, the recorded
//! outputs, the recorded nonces, and the request-digest check.

use std::cell::Cell;
use std::time::Instant;

use harness_core::{Digest, Source, Untrusted};
use harness_journal::canon::unescape;
use harness_journal::{
    BlobSink, BlobSource, Clock, Event, EventKind, Ident, JournalError, JournalFile, JournalWriter,
    Trusted, Verified,
};
use serde_json::{Map, Value};

use crate::profile::Profile;
use crate::wire::{render_request, request_digest};
use crate::{
    Completion, EndpointClass, FinishReason, ModelBackend, ModelError, ModelIdentity, ModelRequest,
    RawToolCall, RenderNonce, ServerUsage, Unavailable,
};

/// The `ModelRequested` event for a rendered request.
pub fn requested_event(rendered: &Value, nonce: &RenderNonce) -> Option<Event> {
    Some(
        Event::new(EventKind::ModelRequested)
            .field("request", Trusted::Digest(request_digest(rendered)))
            .field("nonce", Trusted::Id(Ident::from_trusted(nonce)?)),
    )
}

fn error_fields(e: &ModelError) -> Vec<(&'static str, Trusted)> {
    let t = |s| Trusted::Text(s);
    match e {
        ModelError::Empty => vec![("error", t("empty"))],
        ModelError::Truncated(why) => vec![("error", t("truncated")), ("why", t(why))],
        ModelError::Unusable(_) => vec![("error", t("unusable"))],
        ModelError::RateLimited { statuses } => vec![
            ("error", t("rate_limited")),
            ("statuses", statuses_list(statuses)),
        ],
        ModelError::ReplayDiverged { .. } => vec![("error", t("replay_diverged"))],
        ModelError::Unavailable(u) => {
            let (kind, extra) = match u {
                Unavailable::Connect(_) => ("connect", None),
                Unavailable::ConnectTimeout => ("connect_timeout", None),
                Unavailable::ReadTimeout => ("read_timeout", None),
                Unavailable::Deadline => ("deadline", None),
                Unavailable::Status { code, statuses } => ("status", Some((*code, statuses))),
            };
            let mut v = vec![("error", t("unavailable")), ("kind", t(kind))];
            if let Some((code, statuses)) = extra {
                v.push(("code", Trusted::U64(u64::from(code))));
                v.push(("statuses", statuses_list(statuses)));
            }
            v
        }
    }
}

fn statuses_list(s: &[u16]) -> Trusted {
    Trusted::List(s.iter().map(|c| Trusted::U64(u64::from(*c))).collect())
}

/// The `ModelReplied` event for a call's result. Model-authored text goes
/// into the journal's untrusted payload home (blobs written first).
pub fn replied_event<F: JournalFile, B: BlobSink, K: Clock>(
    w: &mut JournalWriter<F, B, K>,
    result: &Result<Completion, ModelError>,
) -> Result<Event, JournalError> {
    let mut ev = Event::new(EventKind::ModelReplied);
    let c = match result {
        Err(e) => {
            for (k, v) in error_fields(e) {
                ev = ev.field(k, v);
            }
            return Ok(ev);
        }
        Ok(c) => c,
    };
    let content = w.untrusted(&c.content)?;
    let mut calls = Vec::with_capacity(c.tool_calls.len());
    for call in &c.tool_calls {
        let raw = call.inspect("journal: record tool call");
        let name = w.untrusted(&Untrusted::new(raw.name.clone(), Source::Model))?;
        let args = w.untrusted(&Untrusted::new(raw.arguments.clone(), Source::Model))?;
        calls.push(Trusted::Obj(vec![
            ("name", Trusted::Untrusted(name)),
            ("arguments", Trusted::Untrusted(args)),
        ]));
    }
    ev = ev
        .field("content", Trusted::Untrusted(content))
        .field("tool_calls", Trusted::List(calls))
        .field("finish", Trusted::Text(c.finish.as_str()))
        .field("request_bytes", Trusted::U64(c.request_bytes))
        .field("reply_bytes", Trusted::U64(c.reply_bytes))
        .field(
            "retried",
            Trusted::List(
                c.retried
                    .iter()
                    .map(|s| Trusted::U64(u64::from(*s)))
                    .collect(),
            ),
        );
    if let Some(u) = c.usage {
        ev = ev.field(
            "usage",
            Trusted::Obj(vec![
                ("input", Trusted::U64(u.input)),
                ("output", Trusted::U64(u.output)),
            ]),
        );
    }
    Ok(ev)
}

/// Why a journal could not be turned into a replay.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplayError {
    /// A `ModelReplied` without a preceding `ModelRequested`, or two
    /// requests in a row.
    #[error("model records are not request/reply pairs (record {0})")]
    Unpaired(u64),
    /// A record body is not the shape this module writes.
    #[error("model record {0} is malformed")]
    Malformed(u64),
    /// A payload's blob is missing.
    #[error("model record {0} references a missing blob")]
    MissingBlob(u64),
    /// A payload does not hash to its recorded `sha256`/`len`.
    #[error("model record {0}: a payload does not match its recorded digest")]
    PayloadMismatch(u64),
}

#[derive(Debug, Clone)]
struct Recorded {
    request: Digest,
    nonce: String,
    reply: RecordedReply,
}

#[derive(Debug, Clone)]
enum RecordedReply {
    Ok {
        content: String,
        calls: Vec<(String, String)>,
        finish: FinishReason,
        usage: Option<ServerUsage>,
        request_bytes: u64,
        reply_bytes: u64,
        retried: Vec<u16>,
    },
    Err(ModelError),
}

/// Read one untrusted payload back, and re-hash it against the record's
/// `sha256` and `len` (H1d review F-6): whatever blob source the caller
/// passes, a payload that is not the recorded one is refused.
fn payload(v: &Value, blobs: &dyn BlobSource, seq: u64) -> Result<String, ReplayError> {
    String::from_utf8(payload_bytes(v, blobs, seq)?).map_err(|_| ReplayError::Malformed(seq))
}

/// Read one untrusted payload of record `seq` back as bytes (inline text or
/// its blob), re-hashed against its recorded `sha256` and `len`. The audit
/// driver uses it to re-feed recorded tool output.
pub fn payload_bytes(v: &Value, blobs: &dyn BlobSource, seq: u64) -> Result<Vec<u8>, ReplayError> {
    let m = ReplayError::Malformed(seq);
    let o = v.as_object().ok_or(m.clone())?;
    if o.get("untrusted") != Some(&Value::Bool(true)) {
        return Err(m);
    }
    let want: Digest = o
        .get("sha256")
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or(m.clone())?;
    let len = o.get("len").and_then(Value::as_u64).ok_or(m.clone())?;
    let bytes = if let Some(i) = o.get("inline").and_then(Value::as_str) {
        unescape(i).ok_or(m.clone())?.into_bytes()
    } else {
        let name = o.get("blob").and_then(Value::as_str).ok_or(m.clone())?;
        blobs.get(name).ok_or(ReplayError::MissingBlob(seq))?
    };
    if harness_core::sha256(&bytes) != want || u64::try_from(bytes.len()).ok() != Some(len) {
        return Err(ReplayError::PayloadMismatch(seq));
    }
    Ok(bytes)
}

fn statuses_of(b: &Map<String, Value>) -> Option<Vec<u16>> {
    b.get("statuses")?
        .as_array()?
        .iter()
        .map(|v| v.as_u64().and_then(|x| u16::try_from(x).ok()))
        .collect()
}

fn decode_error(b: &Map<String, Value>, seq: u64) -> Result<ModelError, ReplayError> {
    let m = ReplayError::Malformed(seq);
    let s = |k: &str| b.get(k).and_then(Value::as_str);
    let n = |k: &str| {
        b.get(k)
            .and_then(Value::as_u64)
            .and_then(|x| u32::try_from(x).ok())
    };
    Ok(match s("error") {
        Some("empty") => ModelError::Empty,
        Some("truncated") => ModelError::Truncated(match s("why") {
            Some("finish_reason: length") => "finish_reason: length",
            Some("no finish_reason") => "no finish_reason",
            _ => return Err(m),
        }),
        Some("unusable") => ModelError::Unusable("recorded unusable reply".into()),
        Some("rate_limited") => ModelError::RateLimited {
            statuses: statuses_of(b).ok_or(m)?,
        },
        Some("unavailable") => ModelError::Unavailable(match s("kind") {
            Some("connect") => Unavailable::Connect("recorded".into()),
            Some("connect_timeout") => Unavailable::ConnectTimeout,
            Some("read_timeout") => Unavailable::ReadTimeout,
            Some("deadline") => Unavailable::Deadline,
            Some("status") => Unavailable::Status {
                code: n("code")
                    .and_then(|c| u16::try_from(c).ok())
                    .ok_or(m.clone())?,
                statuses: statuses_of(b).ok_or(m)?,
            },
            _ => return Err(m),
        }),
        _ => return Err(m),
    })
}

fn decode_reply(
    b: &Map<String, Value>,
    blobs: &dyn BlobSource,
    seq: u64,
) -> Result<RecordedReply, ReplayError> {
    if b.contains_key("error") {
        return decode_error(b, seq).map(RecordedReply::Err);
    }
    let m = || ReplayError::Malformed(seq);
    let content = payload(b.get("content").ok_or_else(m)?, blobs, seq)?;
    let mut calls = Vec::new();
    for c in b
        .get("tool_calls")
        .and_then(Value::as_array)
        .ok_or_else(m)?
    {
        calls.push((
            payload(c.get("name").ok_or_else(m)?, blobs, seq)?,
            payload(c.get("arguments").ok_or_else(m)?, blobs, seq)?,
        ));
    }
    let finish = match b.get("finish").and_then(Value::as_str) {
        Some("stop") => FinishReason::Stop,
        Some("tool_calls") => FinishReason::ToolCalls,
        _ => return Err(m()),
    };
    let usage = match b.get("usage") {
        None => None,
        Some(u) => Some(ServerUsage {
            input: u.get("input").and_then(Value::as_u64).ok_or_else(m)?,
            output: u.get("output").and_then(Value::as_u64).ok_or_else(m)?,
        }),
    };
    let num = |k: &str| b.get(k).and_then(Value::as_u64).ok_or_else(m);
    let retried = b
        .get("retried")
        .and_then(Value::as_array)
        .ok_or_else(m)?
        .iter()
        .map(|v| v.as_u64().and_then(|x| u16::try_from(x).ok()).ok_or_else(m))
        .collect::<Result<_, _>>()?;
    Ok(RecordedReply::Ok {
        content,
        calls,
        finish,
        usage,
        request_bytes: num("request_bytes")?,
        reply_bytes: num("reply_bytes")?,
        retried,
    })
}

/// Re-feeds recorded model outputs (§2.9 audit mode).
#[derive(Debug)]
pub struct ReplayBackend {
    profile: Profile,
    exchanges: Vec<Recorded>,
    next: Cell<usize>,
}

impl ReplayBackend {
    /// Read the model request/reply pairs of a verified journal. `profile`
    /// must be the run's profile (its digest is in the header), so requests
    /// re-render byte-for-byte.
    pub fn from_journal(
        v: &Verified,
        blobs: &dyn BlobSource,
        profile: Profile,
    ) -> Result<Self, ReplayError> {
        let mut exchanges = Vec::new();
        let mut pending: Option<(Digest, String)> = None;
        for r in &v.records {
            match r.kind {
                EventKind::ModelRequested => {
                    if pending.is_some() {
                        return Err(ReplayError::Unpaired(r.seq));
                    }
                    let d = r
                        .body
                        .get("request")
                        .and_then(Value::as_str)
                        .and_then(|s| s.parse().ok())
                        .ok_or(ReplayError::Malformed(r.seq))?;
                    let n = r
                        .body
                        .get("nonce")
                        .and_then(Value::as_str)
                        .ok_or(ReplayError::Malformed(r.seq))?;
                    pending = Some((d, n.to_owned()));
                }
                EventKind::ModelReplied => {
                    let (request, nonce) = pending.take().ok_or(ReplayError::Unpaired(r.seq))?;
                    exchanges.push(Recorded {
                        request,
                        nonce,
                        reply: decode_reply(&r.body, blobs, r.seq)?,
                    });
                }
                _ => {}
            }
        }
        if let Some(r) = v.records.last().filter(|_| pending.is_some()) {
            return Err(ReplayError::Unpaired(r.seq));
        }
        Ok(Self {
            profile,
            exchanges,
            next: Cell::new(0),
        })
    }

    /// Recorded exchanges.
    pub fn len(&self) -> usize {
        self.exchanges.len()
    }

    /// Whether nothing was recorded.
    pub fn is_empty(&self) -> bool {
        self.exchanges.is_empty()
    }

    /// The nonce recorded for exchange `i` (the driver reuses it so the
    /// request re-renders identically).
    pub fn recorded_nonce(&self, i: usize) -> Option<RenderNonce> {
        self.exchanges
            .get(i)
            .and_then(|e| RenderNonce::new(&e.nonce))
    }

    /// Whether every recorded exchange has been replayed.
    pub fn exhausted(&self) -> bool {
        self.next.get() >= self.exchanges.len()
    }
}

impl ModelBackend for ReplayBackend {
    fn identity(&self) -> ModelIdentity {
        ModelIdentity {
            endpoint: EndpointClass::Replay,
            profile_id: self.profile.id().to_owned(),
            profile_sha256: self.profile.sha256().map(|d| d.to_string()),
            profile_validated: self.profile.validated(),
            profile_stamp_sha256: self.profile.stamp_sha256().map(str::to_owned),
            api_key_handle: None,
            claimed: crate::ServerClaims::default(),
        }
    }

    fn complete(&self, req: &ModelRequest, _deadline: Instant) -> Result<Completion, ModelError> {
        let i = self.next.get();
        let Some(rec) = self.exchanges.get(i) else {
            return Err(ModelError::ReplayDiverged {
                exchange: i,
                why: "no recorded reply for this call",
            });
        };
        let rendered =
            render_request(req, &self.profile).map_err(|_| ModelError::ReplayDiverged {
                exchange: i,
                why: "the request does not render",
            })?;
        if request_digest(&rendered) != rec.request {
            return Err(ModelError::ReplayDiverged {
                exchange: i,
                why: "the request differs from the recorded one",
            });
        }
        self.next.set(i + 1);
        match &rec.reply {
            RecordedReply::Err(e) => Err(e.clone()),
            RecordedReply::Ok {
                content,
                calls,
                finish,
                usage,
                request_bytes,
                reply_bytes,
                retried,
            } => Ok(Completion {
                content: Untrusted::new(content.clone(), Source::Model),
                tool_calls: calls
                    .iter()
                    .map(|(n, a)| {
                        Untrusted::new(
                            RawToolCall {
                                name: n.clone(),
                                arguments: a.clone(),
                            },
                            Source::Model,
                        )
                    })
                    .collect(),
                finish: *finish,
                usage: *usage,
                request_bytes: *request_bytes,
                reply_bytes: *reply_bytes,
                retried: retried.clone(),
            }),
        }
    }
}
