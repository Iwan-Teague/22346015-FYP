//! The bridges between the ACP wire and the session loop's three seams
//! (P-35): [`AcpInput`] (`UserInput`: prompts in, the prompt's response
//! out at each turn boundary), [`AcpSink`] (`EventSink`: journal records
//! out as `session/update` notifications) and [`AcpApprover`]
//! (`Approver`: asks out as `session/request_permission` requests, the
//! client's answer in).
//!
//! Threading: ONE reader thread owns the client's side of the pipe and
//! posts parsed lines into a shared inbox; everything else — every
//! write to the client, every note — happens on the caller's thread,
//! so the protocol stream is written by one thread only. The inbox is
//! an `Arc<(Mutex, Condvar)>`; the writer is an `Rc<RefCell<…>>`
//! (the session loop is synchronous, so the bridges all live on the
//! caller's thread, exactly like the CLI's REPL).
//!
//! Cancel (fail-closed, see docs/slices/P-35.md): the loop has no
//! mid-turn cancel input (P-05 O-7) and the journal's record kinds are
//! closed (P-10), so `session/cancel` never interrupts a running turn —
//! it marks the pending prompt response `cancelled` and (at a
//! boundary, before an accepted prompt starts) can drop a queued
//! prompt instead of running it. Nothing the loop journaled changes,
//! so the session still audits clean.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::rc::Rc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

use harness_core::display::{sanitize_for_terminal_bounded, DisplayMode};
use harness_journal::EventKind;
use harness_run::{
    ApprovalAnswer, ApprovalAnswer as AA, Approver, ApproverKind, EventSink, InputEnd, UiEvent,
    UserInput, UserInputEvent, UserMessage,
};
use serde_json::Value;

use crate::wire;

/// How much of a model reply is streamed to the client.
const REPLY_BYTES: usize = 8192;
/// How much of a tool call's arguments the one-line title shows.
const ARGS_BYTES: usize = 120;
/// How much of a tool's output the finished call carries.
const OUTPUT_BYTES: usize = 512;

/// One parsed line from the client, as the reader thread posts it.
#[derive(Debug)]
pub(crate) enum Incoming {
    /// A client request.
    Request {
        /// The id to answer.
        id: Value,
        /// The method.
        method: String,
        /// The params.
        params: Value,
    },
    /// A client notification.
    Notification {
        /// The method.
        method: String,
        /// The params.
        params: Value,
    },
    /// A response to one of our requests.
    Response {
        /// The id we minted.
        id: Value,
        /// The result.
        result: Value,
    },
    /// Not JSON at all: the server answers `-32700` with id `null`.
    Malformed,
    /// JSON that is not a usable envelope: answered `-32600`.
    Invalid {
        /// The id to answer with.
        id: Value,
    },
    /// The client's side of the pipe is closed.
    Eof,
}

/// The shared inbox: the reader thread pushes, the caller's thread
/// pops.
pub(crate) type InboxSync = Arc<(Mutex<Inbox>, Condvar)>;

/// The queue and the end-of-stream mark.
#[derive(Default)]
pub(crate) struct Inbox {
    /// Pending lines, in arrival order.
    pub(crate) queue: VecDeque<Incoming>,
    /// The reader saw end-of-file (or gave up): nothing more will
    /// arrive.
    pub(crate) eof: bool,
}

/// The one place lines arrive from, shared with the reader thread.
pub(crate) fn new_inbox() -> InboxSync {
    Arc::new((Mutex::new(Inbox::default()), Condvar::new()))
}

/// Where a turn's answer went, recorded by the sink and the input.
#[derive(Default)]
pub(crate) struct TurnState {
    /// The last model reply's `(name, arguments)` calls, for
    /// correlating a `ToolStarted`'s call digest (display only, as in
    /// the CLI's sink).
    pub(crate) last_calls: Vec<(String, String)>,
    /// `ToolStarted`s awaiting their `ToolFinished`, by seq.
    pub(crate) pending: BTreeMap<u64, (String, String)>,
    /// The last `TurnEnded`'s reason (the journal's wire name).
    pub(crate) last_turn_reason: Option<String>,
    /// The prompt request whose response is pending (its turn ran, or
    /// is running).
    pub(crate) finished: Option<Value>,
    /// A `session/cancel` for the pending response was seen.
    pub(crate) cancel_seen: bool,
    /// The reader saw end-of-file; the session ends at the next
    /// boundary (a prompt already accepted still runs).
    pub(crate) eof_seen: bool,
}

/// The client side of the pipe: every write happens here, on the
/// caller's thread. A failed write marks the bus broken; the server
/// then stops serving (the pipe is gone).
pub(crate) struct Out<W: Write> {
    /// The writer.
    w: RefCell<W>,
    /// Set when a write failed: send nothing more.
    pub(crate) broken: Cell<bool>,
}

impl<W: Write> Out<W> {
    pub(crate) fn new(w: W) -> Rc<Self> {
        Rc::new(Self {
            w: RefCell::new(w),
            broken: Cell::new(false),
        })
    }

    /// One JSON-RPC line, flushed. `false` when the pipe broke.
    pub(crate) fn send(&self, v: &Value) -> bool {
        if self.broken.get() {
            return false;
        }
        let mut w = self.w.borrow_mut();
        let ok = writeln!(w, "{v}").is_ok() && w.flush().is_ok();
        if !ok {
            self.broken.set(true);
        }
        ok
    }
}

/// Human-facing notes (stderr for the CLI): shared by the bridges.
pub(crate) struct Notes<'a>(RefCell<&'a mut dyn FnMut(&str)>);

impl<'a> Notes<'a> {
    pub(crate) fn new(f: &'a mut dyn FnMut(&str)) -> Rc<Self> {
        Rc::new(Self(RefCell::new(f)))
    }

    pub(crate) fn say(&self, s: &str) {
        (self.0.borrow_mut())(s);
    }
}

/// Everything the bridges share: the inbox, the writer, the turn
/// state, the ACP session id, whether session grants are on, and the
/// notes.
pub(crate) struct Bus<'a, W: Write> {
    /// The shared inbox.
    pub(crate) inbox: InboxSync,
    /// The protocol stream.
    pub(crate) out: Rc<Out<W>>,
    /// The turn state.
    pub(crate) state: Rc<RefCell<TurnState>>,
    /// The ACP session id every notification carries.
    pub(crate) session: String,
    /// Whether `allow_always`/`reject_always` options are offered (the
    /// run must have session grants on; P-23).
    pub(crate) grants: bool,
    /// The notes.
    pub(crate) notes: Rc<Notes<'a>>,
}

impl<'a, W: Write> Bus<'a, W> {
    /// A `session/update` line on the wire; a failed write is noted
    /// once and the bus turns broken.
    fn send_update(&self, one: Value) {
        if !self.out.send(&wire::update(&self.session, one)) && !self.broken_noted() {
            self.notes.say("acp: the client's stream broke; stopping");
        }
    }

    fn broken_noted(&self) -> bool {
        self.out.broken.get()
    }
}

/// The journal's stop-cause / turn-end reason name, to the ACP
/// `stopReason` (see docs/slices/P-35-acp-spec-notes.md).
pub(crate) fn stop_reason(reason: &str) -> &'static str {
    match reason {
        "answered" | "submitted" | "submitted_checks_failed" | "session_ended" => "end_turn",
        "turn_steps" | "format_errors" | "loop:repeat" | "loop:edit_churn" | "loop:no_progress"
        | "loop:denied" => "max_turn_requests",
        "budget" | "context_exhausted" => "max_tokens",
        // `input_refused`, `policy_abort`, `model_unavailable`,
        // `sandbox_lost`, `journal_unavailable`, anything unknown: the
        // fail-closed reading is a refusal.
        _ => "refusal",
    }
}

/// Resolve an untrusted payload exactly as the CLI's sink does:
/// `inline` text unescapes, a `blob` hash names a file in the
/// attempt's blobs directory. `None` when it cannot be resolved — the
/// client then sees less, never something raw.
fn blob_text(blobs: &std::path::Path, v: &Value) -> Option<String> {
    if let Some(inline) = v.get("inline").and_then(Value::as_str) {
        return harness_journal::canon::unescape(inline);
    }
    let sha = v.get("blob").and_then(Value::as_str)?;
    // The hash is a single path component from the journal's own
    // writer; `join` cannot escape the blobs directory.
    let bytes = std::fs::read(blobs.join(sha)).ok()?;
    String::from_utf8(bytes).ok()
}

/// The canonical call digest the journal records for a `ToolStarted`,
/// recomputed for correlation only (as the CLI's sink does).
fn call_digest(name: &str, args_text: &str) -> Option<String> {
    let args: Value = serde_json::from_str(args_text).ok()?;
    let canon = serde_json::json!({ "args": args, "capability": name }).to_string();
    Some(harness_core::sha256(canon.as_bytes()).to_string())
}

/// A body field's plain text, sanitized for one line (these come from
/// the journal's own writers, but defence in depth is cheap).
fn text(v: Option<&Value>) -> String {
    let s = v.and_then(Value::as_str).unwrap_or("-");
    sanitize_for_terminal_bounded(s, DisplayMode::Line, 200)
}

/// The prompt source: prompts arrive as `session/prompt` requests on
/// the shared inbox; the response to a prompt is written at the turn
/// boundary after its turn (or by the server after the session ends).
pub(crate) struct AcpInput<'a, W: Write> {
    /// What the input shares with the server and the other bridges.
    pub(crate) bus: Rc<Bus<'a, W>>,
}

impl<W: Write> AcpInput<'_, W> {
    /// Answer the pending prompt response, if one is due: its turn has
    /// ended, so the client may send the next prompt.
    fn answer_finished(&self, guard_st: &mut TurnState) {
        let Some(id) = guard_st.finished.take() else {
            return;
        };
        let reason = guard_st
            .last_turn_reason
            .take()
            .unwrap_or_else(|| "refusal".to_owned());
        let stop = if guard_st.cancel_seen {
            "cancelled"
        } else {
            stop_reason(&reason)
        };
        guard_st.cancel_seen = false;
        self.bus.out.send(&wire::response(
            &id,
            serde_json::json!({"stopReason": stop}),
        ));
    }
}

impl<W: Write> UserInput for AcpInput<'_, W> {
    fn next(&self, deadline: Instant) -> UserInputEvent {
        let (lock, cv) = &*self.bus.inbox;
        let mut guard = match lock.lock() {
            Ok(g) => g,
            Err(_) => return UserInputEvent::End(InputEnd::Eof),
        };
        loop {
            // One boundary: drain the inbox (under the lock, so
            // re-queued lines keep their arrival order against the
            // reader thread), answer the finished turn, then start the
            // next prompt (FIFO).
            let mut candidate: Option<(Value, String)> = None;
            let mut leftover: Vec<Incoming> = Vec::new();
            let items: Vec<Incoming> = guard.queue.drain(..).collect();
            for item in items {
                match item {
                    Incoming::Request { id, method, params } if method == "session/prompt" => {
                        let sid = params.get("sessionId").and_then(Value::as_str);
                        if sid != Some(self.bus.session.as_str()) {
                            self.bus.out.send(&wire::error(
                                &id,
                                wire::NO_SESSION,
                                "unknown session",
                            ));
                            continue;
                        }
                        match wire::prompt_text(&params) {
                            Ok(t) if candidate.is_none() => candidate = Some((id, t)),
                            Ok(_) => leftover.push(Incoming::Request { id, method, params }),
                            Err(why) => {
                                self.bus
                                    .out
                                    .send(&wire::error(&id, wire::INVALID_PARAMS, &why));
                            }
                        }
                    }
                    Incoming::Notification { method, params } if method == "session/cancel" => {
                        let sid = params.get("sessionId").and_then(Value::as_str);
                        if sid != Some(self.bus.session.as_str()) {
                            continue;
                        }
                        let mut st = self.bus.state.borrow_mut();
                        if let Some((id, _)) = candidate.take() {
                            // Cancel a prompt that had not started:
                            // answer it cancelled, run nothing.
                            self.bus.out.send(&wire::response(
                                &id,
                                serde_json::json!({"stopReason": "cancelled"}),
                            ));
                        } else if st.finished.is_some() {
                            // The turn in flight (or just ended): its
                            // response is `cancelled`.
                            st.cancel_seen = true;
                        }
                        // A cancel while nothing is pending is
                        // ignored (fail closed: it cancels nothing).
                    }
                    Incoming::Request { id, method, .. } if method == "session/new" => {
                        self.bus.out.send(&wire::error(
                            &id,
                            wire::BUSY,
                            "an ACP session is already active",
                        ));
                    }
                    Incoming::Request { id, method, .. } if method == "initialize" => {
                        self.bus.out.send(&wire::error(
                            &id,
                            wire::METHOD_NOT_FOUND,
                            "already initialized",
                        ));
                    }
                    Incoming::Request { id, method, .. } => {
                        self.bus.out.send(&wire::error(
                            &id,
                            wire::METHOD_NOT_FOUND,
                            &format!("unknown method while a turn is not running: {method}"),
                        ));
                    }
                    Incoming::Response { id, .. } => {
                        self.bus.notes.say(&format!(
                            "acp: stray response to {id} (no permission is pending)"
                        ));
                    }
                    Incoming::Notification { .. } => {}
                    Incoming::Malformed => {
                        self.bus.out.send(&wire::error(
                            &Value::Null,
                            wire::PARSE_ERROR,
                            "parse error",
                        ));
                    }
                    Incoming::Invalid { id } => {
                        self.bus.out.send(&wire::error(
                            &id,
                            wire::INVALID_REQUEST,
                            "invalid request",
                        ));
                    }
                    // The reader saw end-of-file: the session ends at
                    // this boundary — but a prompt already taken still
                    // runs first (its response is written before the
                    // end is reported).
                    Incoming::Eof => self.bus.state.borrow_mut().eof_seen = true,
                }
            }
            for x in leftover {
                guard.queue.push_back(x);
            }
            // The finished turn's response: a cancel seen for it wins
            // over the turn's own reason.
            {
                let mut st = self.bus.state.borrow_mut();
                self.answer_finished(&mut st);
            }
            if let Some((id, text)) = candidate {
                match UserMessage::new(text) {
                    Ok(m) => {
                        self.bus.state.borrow_mut().finished = Some(id);
                        return UserInputEvent::Message(m);
                    }
                    Err(_) => {
                        // The harness refuses the message (empty after
                        // trim, or over 64 KiB): the client's prompt is
                        // refused at the wire and no turn runs.
                        self.bus.out.send(&wire::error(
                            &id,
                            wire::INVALID_PARAMS,
                            "the prompt is empty or too large for a user turn",
                        ));
                    }
                }
            }
            if self.bus.state.borrow().eof_seen || guard.eof {
                return UserInputEvent::End(InputEnd::Eof);
            }
            let now = Instant::now();
            if now >= deadline {
                return UserInputEvent::End(InputEnd::Timeout);
            }
            let (g, _) = match cv.wait_timeout(guard, deadline - now) {
                Ok(x) => x,
                Err(_) => return UserInputEvent::End(InputEnd::Eof),
            };
            guard = g;
        }
    }
}

/// The sink: journal records the client can see, as `session/update`
/// notifications (P-35): model replies as `agent_message_chunk`, tool
/// calls as `tool_call` / `tool_call_update`. Everything else is
/// display-only noise the protocol has no shape for (approval lines,
/// budget notices, policy decisions) and is left to the notes.
pub(crate) struct AcpSink<'a, W: Write> {
    /// What the sink shares with the server and the other bridges.
    pub(crate) bus: Rc<Bus<'a, W>>,
}

impl<W: Write> EventSink for AcpSink<'_, W> {
    fn emit(&self, ev: &UiEvent<'_>) {
        match ev.kind {
            EventKind::ModelReplied => self.model_replied(ev),
            EventKind::ToolStarted => self.tool_started(ev),
            EventKind::ToolFinished => self.tool_finished(ev),
            EventKind::TurnEnded => {
                let reason = text(ev.body.get("reason"));
                self.bus.state.borrow_mut().last_turn_reason = Some(reason);
            }
            _ => {}
        }
    }
}

impl<W: Write> AcpSink<'_, W> {
    fn model_replied(&self, ev: &UiEvent<'_>) {
        let content = ev.body.get("content").cloned().unwrap_or(Value::Null);
        let full = blob_text(ev.blobs, &content).unwrap_or_default();
        // Everything before the first `<action>` is the model's spoken
        // text (the action itself becomes the tool call).
        let spoken = match full.find("<action>") {
            Some(i) => &full[..i],
            None => full.as_str(),
        };
        if !spoken.trim().is_empty() {
            let clean =
                sanitize_for_terminal_bounded(spoken.trim_end(), DisplayMode::Block, REPLY_BYTES);
            self.bus.send_update(wire::agent_message_chunk(&clean));
        }
        let mut calls: Vec<(String, String)> = Vec::new();
        if let Some(list) = ev.body.get("tool_calls").and_then(Value::as_array) {
            for c in list {
                let name = blob_text(ev.blobs, &c.get("name").cloned().unwrap_or(Value::Null))
                    .unwrap_or_default();
                let args = blob_text(
                    ev.blobs,
                    &c.get("arguments").cloned().unwrap_or(Value::Null),
                )
                .unwrap_or_default();
                calls.push((name, args));
            }
        }
        self.bus.state.borrow_mut().last_calls = calls;
    }

    fn tool_started(&self, ev: &UiEvent<'_>) {
        let capability = text(ev.body.get("capability"));
        let want = text(ev.body.get("call"));
        let args = self
            .bus
            .state
            .borrow()
            .last_calls
            .iter()
            .find(|(n, a)| call_digest(n, a).as_deref() == Some(want.as_str()))
            .map(|(_, a)| a.clone())
            .unwrap_or_default();
        self.bus
            .state
            .borrow_mut()
            .pending
            .insert(ev.seq, (capability.clone(), args.clone()));
        let title = if args.is_empty() {
            capability.clone()
        } else {
            let shown = sanitize_for_terminal_bounded(&args, DisplayMode::Line, ARGS_BYTES);
            format!("{capability} {shown}")
        };
        self.bus.send_update(wire::tool_call(
            &format!("c{}", ev.seq),
            &capability,
            &title,
            wire::tool_kind(&capability),
        ));
    }

    fn tool_finished(&self, ev: &UiEvent<'_>) {
        let seq = ev.body.get("intent_seq").and_then(Value::as_u64);
        let (capability, _args) =
            match seq.and_then(|s| self.bus.state.borrow_mut().pending.remove(&s)) {
                Some(p) => p,
                None => (text(ev.body.get("capability")), String::new()),
            };
        let id = match seq {
            Some(s) => format!("c{s}"),
            None => {
                // A finish that does not correlate to a start we showed
                // cannot update a call the client knows; the notes say
                // so instead (fail closed: nothing invented).
                self.bus.notes.say(&format!(
                    "acp: tool finished without a shown start ({capability})"
                ));
                return;
            }
        };
        let ok = text(ev.body.get("status")) == "ok";
        let status = if ok { "completed" } else { "failed" };
        let mut content = None;
        if ok {
            if let Some(out) = ev.body.get("output").cloned() {
                if let Some(t) = blob_text(ev.blobs, &out) {
                    let preview = sanitize_for_terminal_bounded(
                        t.trim_end(),
                        DisplayMode::Line,
                        OUTPUT_BYTES,
                    );
                    if !preview.is_empty() {
                        content = Some(preview);
                    }
                }
            }
        }
        self.bus
            .send_update(wire::tool_call_update(&id, status, content.as_deref()));
    }
}

/// The approver: the ACP client answers an ask through
/// `session/request_permission` (kind `embedded` in the journal).
/// Fail closed: a cancelled outcome, an error, or no answer by the
/// deadline is a deny.
pub(crate) struct AcpApprover<'a, W: Write> {
    /// What the approver shares with the server and the other bridges.
    pub(crate) bus: Rc<Bus<'a, W>>,
    /// The server request counter (`srv-<n>`).
    pub(crate) counter: Cell<u64>,
}

impl<W: Write> Approver for AcpApprover<'_, W> {
    fn kind(&self) -> ApproverKind {
        ApproverKind::Embedded
    }

    fn ask(
        &self,
        req: &harness_policy::approval::ApprovalRequest,
        deadline: Instant,
    ) -> ApprovalAnswer {
        let n = self.counter.get() + 1;
        self.counter.set(n);
        let req_id = format!("srv-{n}");
        let call_id = format!("ask-{n}");
        let capability = req.capability().to_string();
        // The title: the request's own first line ("approval needed:
        // …"), bounded and sanitized.
        let first_line = req
            .to_string()
            .lines()
            .next()
            .unwrap_or_default()
            .strip_prefix("approval needed: ")
            .unwrap_or_default()
            .to_owned();
        let title = if first_line.is_empty() {
            capability.clone()
        } else {
            sanitize_for_terminal_bounded(&first_line, DisplayMode::Line, 200)
        };
        // The lifecycle the client expects: a pending tool call, then
        // the permission request for it.
        self.bus.send_update(wire::tool_call(
            &call_id,
            &capability,
            &title,
            wire::tool_kind(&capability),
        ));
        let mut options = vec![
            serde_json::json!({"optionId":"allow-once","name":"Allow once","kind":"allow_once"}),
            serde_json::json!({"optionId":"reject-once","name":"Reject once","kind":"reject_once"}),
        ];
        if self.bus.grants {
            options.insert(
                0,
                serde_json::json!({"optionId":"allow-always","name":"Allow for this session (pattern)","kind":"allow_always"}),
            );
            options.push(serde_json::json!({"optionId":"reject-always","name":"Reject for this session (pattern)","kind":"reject_always"}));
        }
        let params = serde_json::json!({
            "sessionId": self.bus.session,
            "toolCall": {"toolCallId": call_id},
            "options": options,
        });
        if !self.bus.out.send(&wire::server_request(
            &req_id,
            "session/request_permission",
            params,
        )) {
            return AA::No;
        }
        let answer = self.wait_answer(&req_id, deadline);
        let status = match answer {
            AA::Yes | AA::AllowSession => "completed",
            _ => "failed",
        };
        self.bus
            .send_update(wire::tool_call_update(&call_id, status, None));
        answer
    }
}

impl<W: Write> AcpApprover<'_, W> {
    /// Wait for the client's response to `req_id` until `deadline`.
    /// Every other line is put back in arrival order (the input's
    /// boundary will see it; nothing is lost).
    fn wait_answer(&self, req_id: &str, deadline: Instant) -> ApprovalAnswer {
        let (lock, cv) = &*self.bus.inbox;
        let mut guard = match lock.lock() {
            Ok(g) => g,
            Err(_) => return AA::No,
        };
        loop {
            let items: Vec<Incoming> = guard.queue.drain(..).collect();
            let mut leftover: Vec<Incoming> = Vec::new();
            let mut found: Option<Value> = None;
            for item in items {
                match item {
                    Incoming::Response { id, result }
                        if id.as_str() == Some(req_id) && found.is_none() =>
                    {
                        found = Some(result);
                    }
                    other => leftover.push(other),
                }
            }
            for x in leftover {
                guard.queue.push_back(x);
            }
            if let Some(result) = found {
                return selected(&result);
            }
            let now = Instant::now();
            if now >= deadline {
                // §5.3: no answer by the deadline is a deny.
                return AA::NoAnswer;
            }
            let (g, _) = match cv.wait_timeout(guard, deadline - now) {
                Ok(x) => x,
                Err(_) => return AA::No,
            };
            guard = g;
        }
    }
}

/// The client's `session/request_permission` result, to an approval
/// answer: `selected` maps the option; `cancelled` (or anything else)
/// denies; a session-grant option is honoured only when the run
/// allowed session grants (the options were only offered then).
fn selected(result: &Value) -> ApprovalAnswer {
    let outcome = result.get("outcome");
    let kind = outcome
        .and_then(|o| o.get("outcome"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if kind != "selected" {
        return AA::No;
    }
    match outcome
        .and_then(|o| o.get("optionId"))
        .and_then(Value::as_str)
        .unwrap_or("")
    {
        "allow-once" => AA::Yes,
        "allow-always" => AA::AllowSession,
        "reject-always" => AA::DenySession,
        // `reject-once`, or an optionId we did not offer: deny.
        _ => AA::No,
    }
}
