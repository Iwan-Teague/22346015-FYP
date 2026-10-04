//! The ACP server loop (P-35): one reader thread turns the client's
//! stdio into parsed lines; the caller's thread runs everything else —
//! the JSON-RPC dispatch, at most one live ACP session, and inside it
//! `harness_run::run_session`, whose input, sink and approver are the
//! bridges in [`crate::bridge`].
//!
//! Fail-closed readings (details in docs/slices/P-35.md): `initialize`
//! must come first; exactly one ACP session at a time (a second
//! `session/new` is refused `-32000`); the workspace is each session's
//! own `cwd` from `session/new` (the spec's own rule), never the
//! process's; no MCP servers, no `session/load`/`session/resume`/
//! `session/close` (no such capability is advertised; refused
//! `-32601`).

use std::cell::{Cell, RefCell};
use std::io::{BufRead, Write};
use std::rc::Rc;
use std::sync::Arc;

use harness_core::environment::EnvProbe;
use harness_manifest::admission::Registry;
use harness_model::ModelBackend;
use harness_policy::locality::LocalityProbe;
use harness_policy::UserPolicy;
use harness_run::{run_session, RunRefused, SessionConfig, SessionReport, TaskSpec};
use serde_json::{json, Value};

use crate::bridge::{
    new_inbox, stop_reason, AcpApprover, AcpInput, AcpSink, Bus, Incoming, Notes, Out, TurnState,
};
use crate::wire::{self, Line};

/// Everything one `serve` runs with: the session inputs (as the CLI
/// verbs read them), the probes, and the notes the bridges may write.
pub struct ServeParams<'a> {
    /// The per-user state root (§2.8), as for any session.
    pub state_root: &'a std::path::Path,
    /// The task.
    pub spec: &'a TaskSpec,
    /// Admitted providers.
    pub registry: &'a Registry,
    /// User policy.
    pub policy: &'a UserPolicy,
    /// The model profile.
    pub profile: &'a harness_model::profile::Profile,
    /// The model backend.
    pub backend: &'a dyn ModelBackend,
    /// The filesystem-locality probe.
    pub probe: &'a dyn LocalityProbe,
    /// The environment probe (§7.1).
    pub env: &'a dyn EnvProbe,
    /// Where commands are confined (H2d); asked for only with an exec
    /// grant.
    pub confinement: Option<&'a dyn harness_sandbox::Confinement>,
    /// The session's budgets (the CLI passes the P-05 defaults with the
    /// session-grants flag applied).
    pub config: SessionConfig,
    /// Whether asks may offer the session-grant options (P-23).
    pub allow_session_grants: bool,
    /// Human-facing notes (the CLI's stderr). Never protocol output.
    pub notes: &'a mut dyn FnMut(&str),
}

/// What a `serve` ended with.
pub struct ServeOutput {
    /// Every ACP session that ran, in order, with its report (the
    /// caller audits them).
    pub sessions: Vec<(String, SessionReport)>,
    /// A run that refused to start (its prompt was answered with a
    /// server error; the ACP session is gone).
    pub start_refused: Option<RunRefused>,
}

/// The serve's shared inputs, split from the notes borrow (the notes
/// are `&mut`, so they cannot travel with `&ServeParams`).
struct ServerInputs<'a> {
    /// The per-user state root.
    state_root: &'a std::path::Path,
    /// The task.
    spec: &'a TaskSpec,
    /// Admitted providers.
    registry: &'a Registry,
    /// User policy.
    policy: &'a UserPolicy,
    /// The model profile.
    profile: &'a harness_model::profile::Profile,
    /// The model backend.
    backend: &'a dyn ModelBackend,
    /// The filesystem-locality probe.
    probe: &'a dyn LocalityProbe,
    /// The environment probe.
    env: &'a dyn EnvProbe,
    /// Where commands are confined.
    confinement: Option<&'a dyn harness_sandbox::Confinement>,
    /// The session's budgets.
    config: &'a SessionConfig,
    /// Whether asks may offer the session-grant options (P-23).
    grants: bool,
}

/// Serve ACP v1 over `reader` → `writer` (stdio for the CLI; the tests
/// pass pipes). Blocks until the client closes its side, a write
/// fails, or nothing is left to serve.
pub fn serve<R, W>(p: ServeParams<'_>, reader: R, writer: W) -> ServeOutput
where
    R: BufRead + Send + 'static,
    W: Write,
{
    let ServeParams {
        state_root,
        spec,
        registry,
        policy,
        profile,
        backend,
        probe,
        env,
        confinement,
        config,
        allow_session_grants,
        notes,
    } = p;
    let inp = ServerInputs {
        state_root,
        spec,
        registry,
        policy,
        profile,
        backend,
        probe,
        env,
        confinement,
        config: &config,
        grants: allow_session_grants,
    };
    let notes = Notes::new(notes);
    let out = Out::new(writer);
    let inbox = new_inbox();
    // The one reader thread: it parses, it never writes.
    let thread_inbox = Arc::clone(&inbox);
    let reader = std::thread::Builder::new()
        .name("acp-stdin".into())
        .spawn(move || reader_loop(reader, thread_inbox));
    // No reader: nothing will ever arrive; serve an empty stream.
    let reader = reader.ok();
    let mut sessions: Vec<(String, SessionReport)> = Vec::new();
    let mut start_refused = None;
    let mut initialized = false;
    let mut next_session: u64 = 1;
    // The live ACP session, if one exists (its run may be between
    // prompts, or finished).
    let mut current: Option<(String, std::path::PathBuf)> = None;
    loop {
        if out.broken.get() {
            break;
        }
        match wait_pop(&inbox) {
            Incoming::Eof => break,
            Incoming::Malformed => {
                out.send(&wire::error(&Value::Null, wire::PARSE_ERROR, "parse error"));
            }
            Incoming::Invalid { id } => {
                out.send(&wire::error(&id, wire::INVALID_REQUEST, "invalid request"));
            }
            Incoming::Response { id, .. } => {
                notes.say(&format!("acp: stray response to {id} (nothing is pending)"));
            }
            Incoming::Notification { method, params } => {
                if method == "session/cancel" {
                    // No turn is running on this thread: a cancel now
                    // cancels nothing (the run, if any, sees it at its
                    // own boundary).
                    notes.say("acp: session/cancel ignored (no turn is running)");
                }
                let _ = params;
            }
            Incoming::Request { id, method, params } => {
                handle_request(
                    &id,
                    &method,
                    &params,
                    &mut initialized,
                    &mut next_session,
                    &mut current,
                    &inbox,
                    &out,
                    &notes,
                    &inp,
                    &mut sessions,
                    &mut start_refused,
                );
            }
        }
    }
    drop(out);
    if let Some(h) = reader {
        // The reader exits on its own once the stream ends; never wait
        // longer than the stream itself (it cannot outlive `break`).
        let _ = h.join();
    }
    ServeOutput {
        sessions,
        start_refused,
    }
}

/// One client request at the server's own boundary (no run in
/// progress).
#[allow(clippy::too_many_arguments)]
fn handle_request<W: Write>(
    id: &Value,
    method: &str,
    params: &Value,
    initialized: &mut bool,
    next_session: &mut u64,
    current: &mut Option<(String, std::path::PathBuf)>,
    inbox: &crate::bridge::InboxSync,
    out: &Rc<Out<W>>,
    notes: &Rc<Notes<'_>>,
    inp: &ServerInputs<'_>,
    sessions: &mut Vec<(String, SessionReport)>,
    start_refused: &mut Option<RunRefused>,
) {
    match method {
        "initialize" => {
            if *initialized {
                out.send(&wire::error(
                    id,
                    wire::METHOD_NOT_FOUND,
                    "already initialized",
                ));
                return;
            }
            match params.get("protocolVersion").and_then(Value::as_i64) {
                Some(_) => {
                    *initialized = true;
                    out.send(&wire::response(id, wire::initialize_result(1)));
                }
                None => {
                    out.send(&wire::error(
                        id,
                        wire::INVALID_PARAMS,
                        "params.protocolVersion must be an integer",
                    ));
                }
            }
        }
        "session/new" => {
            if !*initialized {
                out.send(&wire::error(
                    id,
                    wire::NOT_INITIALIZED,
                    "initialize must come first",
                ));
                return;
            }
            if current.is_some() {
                out.send(&wire::error(
                    id,
                    wire::BUSY,
                    "an ACP session is already active",
                ));
                return;
            }
            let cwd = params.get("cwd").and_then(Value::as_str);
            let cwd = match cwd {
                Some(c) => std::path::PathBuf::from(c),
                None => {
                    out.send(&wire::error(
                        id,
                        wire::INVALID_PARAMS,
                        "params.cwd is required",
                    ));
                    return;
                }
            };
            if !cwd.is_absolute() || !cwd.is_dir() {
                out.send(&wire::error(
                    id,
                    wire::INVALID_PARAMS,
                    "params.cwd must be an absolute path to a directory",
                ));
                return;
            }
            match params.get("mcpServers") {
                None | Some(Value::Null) => {}
                Some(Value::Array(a)) if a.is_empty() => {}
                Some(_) => {
                    out.send(&wire::error(
                        id,
                        wire::INVALID_PARAMS,
                        "mcpServers must be empty (no mcp capability is advertised)",
                    ));
                    return;
                }
            }
            let sid = format!("sess-rh-{next_session}");
            *next_session += 1;
            *current = Some((sid.clone(), cwd));
            notes.say(&format!(
                "acp: session {sid} created (the first prompt starts it)"
            ));
            out.send(&wire::response(id, json!({"sessionId": sid})));
        }
        "session/prompt" => {
            if !*initialized {
                out.send(&wire::error(
                    id,
                    wire::NOT_INITIALIZED,
                    "initialize must come first",
                ));
                return;
            }
            let Some((sid, cwd)) = current else {
                out.send(&wire::error(id, wire::NO_SESSION, "unknown session"));
                return;
            };
            let sid_of = params.get("sessionId").and_then(Value::as_str);
            if sid_of != Some(sid.as_str()) {
                out.send(&wire::error(id, wire::NO_SESSION, "unknown session"));
                return;
            }
            if let Err(why) = wire::prompt_text(params) {
                out.send(&wire::error(id, wire::INVALID_PARAMS, &why));
                return;
            }
            // The prompt becomes turn 1: queued like any other line,
            // the run's input bridge takes it at the first boundary.
            if let Ok(mut g) = inbox.0.lock() {
                g.queue.push_back(Incoming::Request {
                    id: id.clone(),
                    method: method.to_owned(),
                    params: params.clone(),
                });
                inbox.1.notify_all();
            }
            run_one(inp, sid, cwd, inbox, out, notes, sessions, start_refused);
            *current = None;
        }
        "session/load" | "session/resume" | "session/close" | "session/unload" => {
            out.send(&wire::error(
                id,
                wire::METHOD_NOT_FOUND,
                "the capability is not advertised",
            ));
        }
        other => {
            out.send(&wire::error(
                id,
                wire::METHOD_NOT_FOUND,
                &format!("unknown method: {other}"),
            ));
        }
    }
}

/// One `run_session`: one ACP session, one journal, many prompts (one
/// user turn each). Blocks until the client's side closes, the input
/// idles past its timeout, or the session stops.
#[allow(clippy::too_many_arguments)]
fn run_one<W: Write>(
    inp: &ServerInputs<'_>,
    sid: &str,
    cwd: &std::path::Path,
    inbox: &crate::bridge::InboxSync,
    out: &Rc<Out<W>>,
    notes: &Rc<Notes<'_>>,
    sessions: &mut Vec<(String, SessionReport)>,
    start_refused: &mut Option<RunRefused>,
) {
    let state = Rc::new(RefCell::new(TurnState::default()));
    let bus = Rc::new(Bus {
        inbox: Arc::clone(inbox),
        out: Rc::clone(out),
        state: Rc::clone(&state),
        session: sid.to_owned(),
        grants: inp.grants,
        notes: Rc::clone(notes),
    });
    let input = AcpInput {
        bus: Rc::clone(&bus),
    };
    let sink = AcpSink {
        bus: Rc::clone(&bus),
    };
    let approver = AcpApprover {
        bus: Rc::clone(&bus),
        counter: Cell::new(0),
    };
    notes.say(&format!(
        "acp: session {sid} starts (workspace {})",
        cwd.display()
    ));
    match run_session(harness_run::SessionRun {
        state_root: inp.state_root,
        workspace: cwd,
        spec: inp.spec,
        registry: inp.registry,
        policy: inp.policy,
        profile: inp.profile,
        backend: inp.backend,
        probe: inp.probe,
        env: inp.env,
        config: inp.config,
        approver: Some(&approver),
        confinement: inp.confinement,
        input: &input,
        // P-30: the ACP server loads no project instructions (only the
        // CLI asks the user to trust a workspace file).
        instructions: None,
        sink: Some(&sink),
    }) {
        Ok(report) => {
            notes.say(&format!(
                "acp: session {sid} ended: {} turn(s), {} step(s), stopped ({})",
                report.turns,
                report.run.steps,
                harness_journal::writer::stop_cause_name(&report.run.cause)
            ));
            // A session-level stop after the last turn leaves the
            // prompt unanswered at a boundary; answer it from the
            // recorded reason (or the session's own stop cause).
            let finished = state.borrow_mut().finished.take();
            if let Some(id) = finished {
                let st = state.borrow();
                let stop = if st.cancel_seen {
                    "cancelled"
                } else {
                    stop_reason(st.last_turn_reason.as_deref().unwrap_or_else(|| {
                        harness_journal::writer::stop_cause_name(&report.run.cause)
                    }))
                };
                drop(st);
                out.send(&wire::response(&id, json!({ "stopReason": stop })));
            }
            sessions.push((sid.to_owned(), report));
        }
        Err(e) => {
            // Nothing ran (the refusals are pre-run): the pending
            // prompt gets a server error and the ACP session is gone.
            notes.say(&format!("acp: session {sid} did not start: {e}"));
            if let Some(id) = state.borrow_mut().finished.take() {
                out.send(&wire::error(
                    &id,
                    wire::BUSY,
                    &format!("the session did not run: {e}"),
                ));
            }
            *start_refused = Some(e);
        }
    }
}

/// Block until one line is available (or the stream is over).
fn wait_pop(shared: &crate::bridge::InboxSync) -> Incoming {
    let (lock, cv) = (&shared.0, &shared.1);
    let mut guard = match lock.lock() {
        Ok(g) => g,
        Err(_) => return Incoming::Eof,
    };
    loop {
        if let Some(x) = guard.queue.pop_front() {
            return x;
        }
        if guard.eof {
            return Incoming::Eof;
        }
        guard = match cv.wait(guard) {
            Ok(g) => g,
            Err(_) => return Incoming::Eof,
        };
    }
}

/// The reader thread: lines in, parsed `Incoming`s in the inbox,
/// end-of-file marked. It never writes and never panics (a poisoned
/// lock is read as end-of-stream everywhere).
fn reader_loop<R: BufRead>(mut r: R, shared: crate::bridge::InboxSync) {
    let (lock, cv) = (&shared.0, &shared.1);
    let mut line = String::new();
    loop {
        line.clear();
        match r.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let inc = match wire::parse_line(&line) {
                    Ok(Line::Request { id, method, params }) => {
                        Incoming::Request { id, method, params }
                    }
                    Ok(Line::Notification { method, params }) => {
                        Incoming::Notification { method, params }
                    }
                    Ok(Line::Response { id, result }) => Incoming::Response { id, result },
                    Err(None) => Incoming::Malformed,
                    Err(Some(id)) => Incoming::Invalid { id },
                };
                if let Ok(mut g) = lock.lock() {
                    g.queue.push_back(inc);
                    cv.notify_all();
                } else {
                    return;
                }
            }
            Err(_) => break,
        }
    }
    if let Ok(mut g) = lock.lock() {
        g.eof = true;
        cv.notify_all();
    }
}
