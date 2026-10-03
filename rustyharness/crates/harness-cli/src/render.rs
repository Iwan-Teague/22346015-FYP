//! The `chat` sink (P-18): every record the session journals, as one
//! human line on stderr as it is written. Display only.
//!
//! Everything the model or a tool produced is untrusted (README): it is
//! resolved out of the event's blob home (`inline` text is unescaped;
//! larger payloads are read from the blobs directory) and pushed through
//! `harness_core::display`'s sanitizer before it reaches the terminal —
//! an ESC, an OSC, a bidi mark or a control byte in a model reply or tool
//! output can never reach the terminal raw. Tool arguments are correlated
//! to their `ToolStarted` by the call digest the journal records; a call
//! that does not correlate is shown with its capability alone (display
//! only, fail closed).

use std::cell::RefCell;
use std::rc::Rc;

use harness_core::display::{sanitize_for_terminal_bounded, DisplayMode};
use harness_journal::EventKind;
use harness_run::{EventSink, UiEvent};
use serde_json::Value;

use crate::repl::{ChatState, Pending};
use crate::Cx;

/// How much of a model reply is streamed to the terminal.
const REPLY_BYTES: usize = 8192;
/// How much of a tool call's arguments the one-line tool record shows.
const ARGS_BYTES: usize = 120;
/// How much of a tool's output the tool line previews.
const OUTPUT_BYTES: usize = 120;

/// The chat sink: one line per shown record, on `cx`'s stderr.
pub(crate) struct SinkRenderer<'c, 'a> {
    cx: &'c Cx<'a>,
    state: Rc<RefCell<ChatState>>,
}

impl<'c, 'a> SinkRenderer<'c, 'a> {
    pub(crate) fn new(cx: &'c Cx<'a>, state: Rc<RefCell<ChatState>>) -> Self {
        Self { cx, state }
    }
}

impl EventSink for SinkRenderer<'_, '_> {
    fn emit(&self, ev: &UiEvent<'_>) {
        {
            let mut st = self.state.borrow_mut();
            if st.attempt_dir.is_none() {
                st.attempt_dir = ev.blobs.parent().map(std::path::Path::to_path_buf);
            }
            st.steps = st.steps.max(ev.step);
        }
        match ev.kind {
            EventKind::ModelReplied => self.model_replied(ev),
            EventKind::ToolStarted => self.tool_started(ev),
            EventKind::ToolFinished => self.tool_finished(ev),
            EventKind::EditApplied => self.edit_applied(ev),
            EventKind::Restored => self.restored(ev),
            EventKind::ApprovalRequested => {
                let cap = text(ev.body.get("capability"));
                let tier = text(ev.body.get("tier"));
                note!(self.cx, "[approve] {cap} ({tier}) needs approval");
            }
            EventKind::ApprovalGranted => note!(self.cx, "[approve] granted"),
            EventKind::ApprovalDenied => note!(self.cx, "[approve] denied"),
            EventKind::ApprovalExpired => note!(self.cx, "[approve] expired (no answer)"),
            EventKind::FormatError => {
                note!(self.cx, "[format] {}", text(ev.body.get("error")));
            }
            EventKind::LoopDetected => {
                note!(self.cx, "[loop] {}", text(ev.body.get("kind")));
            }
            EventKind::BudgetNotice => note!(self.cx, "[budget] {}", self.budget(ev)),
            EventKind::PolicyDecided => self.policy_decided(ev),
            EventKind::UserTurn => self.user_turn(ev),
            EventKind::TurnEnded => {
                let reason = text(ev.body.get("reason"));
                let steps = ev.body.get("steps").and_then(Value::as_u64).unwrap_or(0);
                note!(self.cx, "[turn] {reason} ({steps} step(s))");
            }
            _ => {}
        }
    }
}

impl<'c, 'a> SinkRenderer<'c, 'a> {
    /// The model's text, streamed: everything before the first
    /// `<action>` span (the action itself shows as the tool line), then
    /// sanitized. `<action>` cutting is display only — the parser, not
    /// the renderer, decides what the reply meant.
    fn model_replied(&self, ev: &UiEvent<'_>) {
        let content = ev.body.get("content").cloned().unwrap_or(Value::Null);
        let full = blob_text(ev.blobs, &content).unwrap_or_default();
        let spoken = match full.find("<action>") {
            Some(i) => &full[..i],
            None => full.as_str(),
        };
        if !spoken.trim().is_empty() {
            note!(
                self.cx,
                "{}",
                sanitize_for_terminal_bounded(spoken.trim_end(), DisplayMode::Block, REPLY_BYTES)
            );
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
        self.state.borrow_mut().last_calls = calls;
    }

    /// Hold the call so `ToolFinished` can show one line with arguments
    /// and duration. Correlation: the journal's `call` digest is the
    /// canonical digest of `{"args":…,"capability":…}`; a call that does
    /// not correlate to the last reply shows capability only.
    fn tool_started(&self, ev: &UiEvent<'_>) {
        let capability = text(ev.body.get("capability"));
        let want = text(ev.body.get("call"));
        let args = self
            .state
            .borrow()
            .last_calls
            .iter()
            .find(|(n, a)| call_digest(n, a).as_deref() == Some(want.as_str()))
            .map(|(_, a)| a.clone())
            .unwrap_or_default();
        self.state.borrow_mut().pending.insert(
            ev.seq,
            Pending {
                capability,
                args,
                started: std::time::Instant::now(),
            },
        );
    }

    fn tool_finished(&self, ev: &UiEvent<'_>) {
        let seq = ev.body.get("intent_seq").and_then(Value::as_u64);
        let pending = seq.and_then(|s| self.state.borrow_mut().pending.remove(&s));
        let (capability, args, started) = match pending {
            Some(p) => (p.capability, p.args, Some(p.started)),
            None => (text(ev.body.get("capability")), String::new(), None),
        };
        // The wall time the line shows is the span between the
        // `ToolStarted` and this `ToolFinished` reaching the sink.
        let ms = started.map(|t| t.elapsed().as_millis());
        let status = text(ev.body.get("status"));
        let mut line = if args.is_empty() {
            format!("[tool] {capability} -> {status}")
        } else {
            let shown = sanitize_for_terminal_bounded(&args, DisplayMode::Line, ARGS_BYTES);
            format!("[tool] {capability} {shown} -> {status}")
        };
        if let Some(ms) = ms {
            line.push_str(&format!(" ({ms} ms)"));
        }
        if ev.body.get("truncated").and_then(Value::as_bool) == Some(true) {
            line.push_str(" (truncated)");
        }
        if let Some(code) = ev.body.get("code").and_then(Value::as_i64) {
            line.push_str(&format!(" (exit {code})"));
        }
        if status == "ok" {
            if let Some(out) = ev.body.get("output").cloned() {
                if let Some(t) = blob_text(ev.blobs, &out) {
                    let preview = sanitize_for_terminal_bounded(
                        t.trim_end(),
                        DisplayMode::Line,
                        OUTPUT_BYTES,
                    );
                    if !preview.is_empty() {
                        line.push_str(&format!(" = {preview}"));
                    }
                }
            }
        }
        note!(self.cx, "{line}");
    }

    fn edit_applied(&self, ev: &UiEvent<'_>) {
        let path = ev
            .body
            .get("path")
            .cloned()
            .map(|p| blob_text(ev.blobs, &p).unwrap_or_default())
            .unwrap_or_default();
        let shown = sanitize_for_terminal_bounded(&path, DisplayMode::Line, 200);
        note!(self.cx, "[edit] {shown} applied");
    }

    /// A restore's one line: the checkpoint it went back to and how many
    /// file edits it undid (the files themselves were shown as `[edit]`
    /// lines when they were made).
    fn restored(&self, ev: &UiEvent<'_>) {
        let to_step = ev.body.get("to_step").and_then(Value::as_u64).unwrap_or(0);
        let files = ev
            .body
            .get("files")
            .cloned()
            .map(|f| {
                blob_text(ev.blobs, &f)
                    .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
                    .map(|f| f.len())
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        note!(
            self.cx,
            "[restore] back to step {to_step}: {files} file edit(s) undone"
        );
    }

    fn user_turn(&self, ev: &UiEvent<'_>) {
        let shown = text(ev.body.get("shown"));
        if let Some(t) = ev.body.get("turn").and_then(Value::as_u64) {
            let mut st = self.state.borrow_mut();
            st.turns = st.turns.max(t);
        }
        match shown.as_str() {
            "withheld" => note!(
                self.cx,
                "(your message echoed a secret nonce, so it was not shown to the model)"
            ),
            "over_share" => note!(
                self.cx,
                "(your message repeated too much of the workspace, so it was refused)"
            ),
            _ => {}
        }
    }

    fn budget(&self, ev: &UiEvent<'_>) -> String {
        let key = text(ev.body.get("key"));
        if key == "wall" {
            let percent = ev.body.get("percent").and_then(Value::as_u64).unwrap_or(0);
            let used = ev.body.get("used_ms").and_then(Value::as_u64).unwrap_or(0);
            let limit = ev.body.get("limit_ms").and_then(Value::as_u64).unwrap_or(0);
            format!("wall {percent}% ({used} ms of {limit} ms used)")
        } else {
            let used = ev.body.get("used").and_then(Value::as_u64).unwrap_or(0);
            let limit = ev.body.get("limit").and_then(Value::as_u64).unwrap_or(0);
            format!("{key}: {used} of {limit}")
        }
    }

    /// A denial the person should see (an allow or an ask is silent here:
    /// the ask's own records follow). With no approver present, every ask
    /// is denied with reason `no_approver`, so a piped chat shows why
    /// nothing ran.
    fn policy_decided(&self, ev: &UiEvent<'_>) {
        if text(ev.body.get("decision")) != "deny" {
            return;
        }
        let rule = match ev.body.get("rule") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Object(o)) => {
                let list = o.get("list").and_then(Value::as_str).unwrap_or("?");
                let index = o.get("index").and_then(Value::as_u64).unwrap_or(0);
                format!("{list}[{index}]")
            }
            _ => "?".to_owned(),
        };
        let reason = ev
            .body
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("refused");
        note!(self.cx, "[deny] {rule} ({reason})");
    }
}

/// A body field's plain text, sanitized for one line (defence in depth:
/// these come from the journal's own writers).
fn text(v: Option<&Value>) -> String {
    let s = v.and_then(Value::as_str).unwrap_or("-");
    sanitize_for_terminal_bounded(s, DisplayMode::Line, 200)
}

/// Resolve an untrusted payload: `inline` text unescapes; a `blob` hash
/// names a file in the attempt's blobs directory. `None` when it cannot
/// be resolved — the line says less, never something raw.
pub(crate) fn blob_text(blobs: &std::path::Path, v: &Value) -> Option<String> {
    if let Some(inline) = v.get("inline").and_then(Value::as_str) {
        return harness_journal::canon::unescape(inline);
    }
    let sha = v.get("blob").and_then(Value::as_str)?;
    let bytes = std::fs::read(blobs.join(sha)).ok()?;
    String::from_utf8(bytes).ok()
}

/// The canonical call digest the journal records for a `ToolStarted`
/// (`harness-policy`'s digest of the sorted, compact
/// `{"args":…,"capability":…}`), recomputed for display correlation only.
fn call_digest(name: &str, args_text: &str) -> Option<String> {
    let args: Value = serde_json::from_str(args_text).ok()?;
    let canon = serde_json::json!({ "args": args, "capability": name }).to_string();
    Some(harness_core::sha256(canon.as_bytes()).to_string())
}

/// One bounded, sanitized line (slash-command display of untrusted-ish
/// text, e.g. `/todo`'s last output).
pub(crate) fn cut_line(s: &str) -> String {
    sanitize_for_terminal_bounded(s, DisplayMode::Line, 200)
}
