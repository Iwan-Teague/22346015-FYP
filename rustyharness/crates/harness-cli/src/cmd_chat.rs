//! The `chat` verb (P-18): the interactive line REPL, a gate child like
//! `run` — the LAST stdout line is the session's `GateReport`. It reads
//! its inputs exactly as `run` does (task, policy, profile, locality),
//! shows a banner, then hands the session to `harness_run::run_session`
//! with the REPL's input, approver and sink, and ends every session
//! `Indeterminate { NothingChecked }` (exit 5) until H3.
//!
//! Fail-closed readings this build makes (see docs/slices/P-18.md):
//! - `--resume`/`--continue` resolve the target run (the newest session
//!   for the picker form) and then refuse: reopening a session journal
//!   needs P-17, which is not in this build. Nothing runs.
//! - The P-16 diff preview is not wireable at this layer (the call and
//!   the read log live inside the run loop), so an ask shows the sink's
//!   `[approve]` line and the approver's `y/N` prompt instead.
//! - The session runs under the P-05 default budgets (500 steps, 4 h
//!   wall, 50 steps and 3 format errors per turn, 24 h input idle); the
//!   task file's `budget` section is not applied to sessions here.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

use gate_outcome::{Finding, FindingCode, GateId};
use harness_core::RunId;
use harness_model::client::{ClientConfig, OpenAiCompatible};
use harness_run::session::{run_session, SessionConfig, SessionRun};
use harness_run::{fork_session, Approver, ForkSession, RunRefused};

use crate::approver::ApproverSource;
use crate::render::SinkRenderer;
use crate::repl::{
    BackendSource, ChatApprover, ChatInput, ChatState, CommandSources, InputSource, LineFeed,
};
use crate::report::{emit, exit, info, refused, Outcome};
use crate::Cx;

/// The default gate id, as in `dispatch` (a report line is never missing).
const DEFAULT_GATE: &str = "rustyharness.run";

/// The chat verb's options (a subset of `run`'s; `--gate` as in every
/// gate child; `pub` for the usage-completeness tests, P-58).
pub(crate) const ALLOWED: &[&str] = &[
    "task",
    "workspace",
    "state-root",
    "profile",
    "endpoint",
    "policy",
    "gate",
    "allow-exec",
    "preset",
    "shell",
    "no-default-denies",
    "allow-session-grants",
    "accept-edits",
    "workspace-mode",
];

/// The chat verb's valueless flags (`--scratch-with-git` goes with
/// `--workspace-mode scratch`, P-52; the session-grant flags as on the
/// gate children, P-23/P-58).
pub(crate) const FLAGS: &[&str] = &[
    "shell",
    "no-default-denies",
    "allow-session-grants",
    "accept-edits",
    "scratch-with-git",
];

/// The token budget every CLI run is given (`inputs.rs`; the profile
/// derived default; the task's `budget` section does not set tokens).
const TOKEN_BUDGET: u64 = 1_000_000;

pub(crate) fn chat(cx: &Cx<'_>, rest: &[&str]) -> u8 {
    // `--resume [<run-id>]`, `--continue` and `--fork RUN@STEP` are
    // pre-passed: the picker form takes no value, the others consume one.
    // A duplicate of any is a usage error, as anywhere.
    let usage = |cx: &Cx<'_>, why: &str| {
        note!(cx, "{why}\n{}", crate::args::USAGE);
        match GateId::new(DEFAULT_GATE) {
            Ok(g) => emit(cx, &g, refused(exit::USAGE, why.to_owned())),
            Err(_) => exit::USAGE,
        }
    };
    let mut resume: Option<Option<String>> = None;
    let mut fork: Option<(RunId, u64)> = None;
    let mut filtered: Vec<&str> = Vec::with_capacity(rest.len());
    let mut it = rest.iter();
    while let Some(tok) = it.next() {
        let was_resume = *tok == "--resume";
        match *tok {
            "--resume" | "--continue" => {
                if resume.is_some() {
                    return usage(cx, "--resume given twice");
                }
                resume = Some(None);
                if was_resume {
                    match it.next() {
                        Some(v) if !v.starts_with("--") => resume = Some(Some((*v).to_owned())),
                        Some(v) => filtered.push(*v),
                        None => {}
                    }
                }
            }
            "--fork" => match it.next() {
                Some(v) if !v.starts_with("--") => match parse_fork(v) {
                    Some(f) => {
                        if fork.is_some() {
                            return usage(cx, "--fork given twice");
                        }
                        fork = Some(f);
                    }
                    None => return usage(cx, "--fork is RUN@STEP (a run id and a step)"),
                },
                _ => return usage(cx, "--fork needs a RUN@STEP value"),
            },
            other => filtered.push(other),
        }
    }
    if resume.is_some() && fork.is_some() {
        return usage(cx, "--resume and --fork cannot be combined");
    }
    let parsed = crate::args::options_with_flags(&filtered, ALLOWED, FLAGS);
    let gate_text = parsed
        .as_ref()
        .ok()
        .and_then(|p| p.opts.get("gate").copied())
        .unwrap_or(DEFAULT_GATE);
    let gate = match GateId::new(gate_text) {
        Ok(g) => g,
        Err(_) => return exit::USAGE,
    };
    let cfg = match crate::config::load() {
        Ok(c) => c,
        Err(e) => {
            note!(cx, "{e}");
            return emit(cx, &gate, refused(exit::UNREADABLE_INPUT, e));
        }
    };
    match parsed {
        Err(e) => {
            note!(cx, "{e}\n{}", crate::args::USAGE);
            emit(cx, &gate, refused(exit::USAGE, "usage error".into()))
        }
        Ok(o) => {
            let mut owned: BTreeMap<&str, String> =
                o.opts.into_iter().map(|(k, v)| (k, v.to_owned())).collect();
            if let Err(x) = crate::bundle::fill(cx, &mut owned, &cfg) {
                return emit(cx, &gate, x);
            }
            let filled: BTreeMap<&str, &str> =
                owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
            // Session reopen needs P-17 (not in this build): resolve the
            // target so the refusal names it, then refuse. Nothing runs.
            if let Some(pick) = &resume {
                return emit(cx, &gate, resume_refusal(cx, pick, &filled, &cfg));
            }
            emit(cx, &gate, try_chat(cx, &filled, &cfg, fork))
        }
    }
}

/// A `--fork`/`/fork` argument, `RUN@STEP`: the parent run id and the
/// step to fork at. Anything else is not one.
pub(crate) fn parse_fork(s: &str) -> Option<(RunId, u64)> {
    let (run, step) = s.split_once('@')?;
    let step = step.parse::<u64>().ok()?;
    RunId::parse(run).map(|r| (r, step))
}

/// The `--resume` refusal: fail closed (P-17 is not in this build), but
/// name the run that would be reopened. An id that does not parse, or a
/// picker that finds no session, is refused as usual.
fn resume_refusal(
    cx: &Cx<'_>,
    pick: &Option<String>,
    o: &BTreeMap<&str, &str>,
    cfg: &Option<crate::config::UserConfig>,
) -> Outcome {
    let id = match pick {
        Some(id) => match RunId::parse(id) {
            Some(r) => r,
            None => {
                note!(cx, "--resume is not a run id");
                return refused(exit::USAGE, "--resume is not a run id".into());
            }
        },
        None => {
            let state_root = match crate::config::state_root(o, cfg) {
                Ok(Some(s)) => s.into_owned(),
                Ok(None) => {
                    note!(cx, "--state-root is required for the session picker");
                    return refused(exit::USAGE, "--state-root missing".into());
                }
                Err(e) => {
                    note!(cx, "{e}");
                    return refused(exit::UNREADABLE_INPUT, e);
                }
            };
            match newest_session(std::path::Path::new(&state_root)) {
                Some(r) => r,
                None => {
                    note!(cx, "no session to resume in {state_root}");
                    return refused(exit::UNREADABLE_INPUT, "no session found".into());
                }
            }
        }
    };
    note!(
        cx,
        "session reopen needs P-17 (not in this build); would resume {id}"
    );
    refused(
        exit::UNREADABLE_INPUT,
        format!("session reopen needs P-17 (not in this build); would resume {id}"),
    )
}

/// The newest session in a state root, for `--continue` (the picker
/// without a terminal UI): the highest `RunStarted` wall clock wins.
fn newest_session(state_root: &std::path::Path) -> Option<RunId> {
    let scanned = harness_journal::scan_runs(state_root).ok()?;
    let mut best: Option<(String, RunId)> = None;
    for s in &scanned {
        let Ok(v) = &s.journal else { continue };
        let start = v
            .records
            .first()
            .map(|r| r.t_wall.clone())
            .unwrap_or_default();
        if best.as_ref().is_none_or(|(b, _)| start > *b) {
            best = Some((start, s.run.clone()));
        }
    }
    best.map(|(_, r)| r)
}

fn try_chat(
    cx: &Cx<'_>,
    o: &BTreeMap<&str, &str>,
    cfg: &Option<crate::config::UserConfig>,
    fork: Option<(RunId, u64)>,
) -> Outcome {
    let inp = match crate::inputs::inputs(cx, o, cfg) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let workspace: std::borrow::Cow<'_, str> = match crate::config::value(o, cfg, "workspace") {
        Some(w) => std::borrow::Cow::Borrowed(w),
        None => match std::env::current_dir() {
            Ok(d) => std::borrow::Cow::Owned(d.to_string_lossy().into_owned()),
            Err(e) => {
                let why = format!("cannot determine the current directory for --workspace: {e}");
                note!(cx, "{why}");
                return refused(exit::INDETERMINATE, why);
            }
        },
    };
    let state_root = match crate::config::state_root(o, cfg) {
        Ok(Some(s)) => s,
        Ok(None) => {
            note!(
                cx,
                "--state-root is required here (no default state root on this platform)\n{}",
                crate::args::USAGE
            );
            return refused(exit::USAGE, "--state-root missing".into());
        }
        Err(e) => {
            note!(cx, "{e}");
            return refused(exit::UNREADABLE_INPUT, e);
        }
    };
    // The state root's locality first (§2.8): a session that cannot start
    // does not contact the model server.
    let root = match std::fs::canonicalize(state_root.as_ref()) {
        Ok(r) => r,
        Err(e) => {
            let why = format!("cannot read the state root: {e}");
            note!(cx, "{why}");
            return refused(exit::INDETERMINATE, why);
        }
    };
    if let Err(e) = harness_policy::locality::check(cx.probe, &root.to_string_lossy()) {
        let why = format!("the state root is not usable here: {e}");
        note!(cx, "{why}");
        return refused(exit::INDETERMINATE, why);
    }
    // The workspace mode (P-52): in-place (the default, unchanged) or a
    // scratch copy the session sees instead of the original. `worktree` is
    // refused at the option parser (INV-23); a copy failure refuses before
    // anything runs.
    let mode = match crate::workspace_mode::parse_mode(o) {
        Ok(m) => m,
        Err(e) => {
            note!(cx, "{e}\n{}", crate::args::USAGE);
            return refused(exit::USAGE, e);
        }
    };
    let prep = match crate::workspace_mode::prepare(cx, &mode, &workspace, &state_root) {
        Ok(p) => p,
        Err(r) => {
            note!(cx, "{}", r.why);
            return refused(r.code, r.why);
        }
    };
    let workspace: std::borrow::Cow<'_, str> = std::borrow::Cow::Owned(prep.workspace);
    // The backend: the shipped binary builds the OpenAI-compatible client
    // from --endpoint (and checks the server); an embedder hands one over
    // and no endpoint is needed.
    let endpoint = crate::config::value(o, cfg, "endpoint");
    let client;
    let backend: &dyn harness_model::ModelBackend = match cx.backend {
        BackendSource::Given(b) => b,
        BackendSource::BuiltIn => {
            let Some(url) = endpoint else {
                note!(cx, "--endpoint is required\n{}", crate::args::USAGE);
                return refused(exit::USAGE, "--endpoint missing".into());
            };
            client = match OpenAiCompatible::new(
                url,
                inp.profile.clone(),
                None,
                ClientConfig::default(),
            ) {
                Ok(c) => c,
                Err(e) => {
                    note!(cx, "endpoint refused: {e}");
                    return refused(exit::UNREADABLE_INPUT, format!("endpoint refused: {e}"));
                }
            };
            if let Err(e) = client.startup_check(Instant::now() + Duration::from_secs(30)) {
                note!(cx, "model server check failed: {e}");
                return refused(
                    exit::INDETERMINATE,
                    format!("model server check failed: {e}"),
                );
            }
            &client
        }
    };
    banner(
        cx,
        &inp,
        &workspace,
        std::path::Path::new(state_root.as_ref()),
        endpoint,
    );
    run_sessions(
        cx,
        &inp,
        &workspace,
        std::path::Path::new(state_root.as_ref()),
        backend,
        o,
        cfg,
        fork,
    )
}

/// The banner (stderr): where we are, what the model is, what confinement
/// and tools the session has, and the policy digest. The confinement
/// witness is asked for only when the task grants `harness.exec.run` (the
/// run itself asks again, lazily, the same way).
fn banner(
    cx: &Cx<'_>,
    inp: &crate::inputs::Inputs,
    workspace: &str,
    state_root: &std::path::Path,
    endpoint: Option<&str>,
) {
    note!(
        cx,
        "rustyharness chat (the exit is Indeterminate until H3: nothing here has checked the result)"
    );
    note!(cx, "workspace {workspace}");
    note!(cx, "state root {}", state_root.display());
    note!(
        cx,
        "model {} ({})",
        inp.profile.id(),
        endpoint.unwrap_or("(a backend given to the library)")
    );
    // The hosted disclosure (P-31): said in the banner and in `/status`,
    // every session, while the profile declares a hosted upstream.
    if inp.profile.hosted() {
        note!(cx, "context is sent to a hosted provider");
    }
    if inp.spec.exec.is_some() {
        match harness_sandbox::available() {
            harness_sandbox::Containment::Available(b) => {
                note!(cx, "confinement: {}", b.matrix_row());
            }
            harness_sandbox::Containment::Unavailable(u) => note!(
                cx,
                "confinement unavailable ({}); commands will be refused",
                u.reason
            ),
        }
    } else {
        note!(cx, "no confinement: read/edit only");
    }
    note!(cx, "tools: {}", inp.spec.grants.join(", "));
    note!(cx, "policy digest: {}", inp.policy.digest());
}

/// The command template sources (P-30): the user's config dir (trusted by
/// location) and the workspace's `.rustyharness/commands` (trusted per
/// template digest through the same trust store as the project notes).
fn commands_for(workspace: &str, trust: &Rc<RefCell<crate::trust::Trust>>) -> Rc<CommandSources> {
    Rc::new(CommandSources {
        config_dir: crate::config::config_dir().ok().flatten(),
        workspace: PathBuf::from(workspace),
        trust: trust.clone(),
    })
}

/// The project notes (P-30): find the workspace's `AGENTS.md` (preferred)
/// or `CLAUDE.md`, show its size and digest, and load it only when its
/// digest is already trusted — or the person at a real terminal answers
/// `y` once, which remembers the digest for later chats. A file that
/// exists but cannot be read, is over the cap, or is not UTF-8 refuses
/// loading entirely (fail closed; no fall-through to the other name).
/// Without a terminal nothing is loaded and nothing is asked.
fn load_notes(
    cx: &Cx<'_>,
    workspace: &str,
    trust: &Rc<RefCell<crate::trust::Trust>>,
    feed_slot: &Option<Rc<LineFeed>>,
) -> Option<harness_run::Instructions> {
    let root = Path::new(workspace);
    let mut file = None;
    for name in ["AGENTS.md", "CLAUDE.md"] {
        let path = root.join(name);
        match std::fs::read(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                note!(
                    cx,
                    "cannot read {}: {e}; loading no project notes",
                    path.display()
                );
                return None;
            }
            Ok(bytes) => {
                file = Some((name, bytes));
                break;
            }
        }
    }
    let (name, bytes) = file?;
    if bytes.len() > harness_run::Instructions::MAX_BYTES {
        note!(
            cx,
            "{name} is {} bytes, over the {}-byte cap; loading no project notes",
            bytes.len(),
            harness_run::Instructions::MAX_BYTES
        );
        return None;
    }
    let notes = match harness_run::Instructions::new(name, &bytes) {
        Ok(n) => n,
        Err(e) => {
            note!(cx, "{name} refused ({e}); loading no project notes");
            return None;
        }
    };
    note!(
        cx,
        "project notes: {name}, {} bytes, sha256 {}",
        bytes.len(),
        notes.digest()
    );
    let digest = notes.digest().to_string();
    if trust.borrow().has_instruction(&digest) {
        note!(
            cx,
            "{name} is trusted; it enters the context as untrusted project notes"
        );
        return Some(notes);
    }
    let Some(feed) = feed_slot else {
        note!(cx, "{name} is not trusted yet; loading no project notes");
        return None;
    };
    feed.drain();
    cx.note("trust these project notes for this and later chats? [y/N]: ");
    let trusted = match feed.next_line(Instant::now() + std::time::Duration::from_secs(300)) {
        Some(line) => {
            let a = line.trim().to_ascii_lowercase();
            a == "y" || a == "yes"
        }
        None => false,
    };
    if !trusted {
        note!(cx, "not trusted: loading no project notes");
        return None;
    }
    trust.borrow_mut().trust_instruction(&digest);
    if let Err(e) = trust.borrow().save() {
        note!(cx, "cannot remember the trust decision: {e}");
    }
    note!(cx, "{name} is trusted for this and later chats");
    Some(notes)
}

/// The outer session loop: one `run_session` per session; `/clear` ends
/// the current one and starts a fresh session in the same chat. A fork —
/// `--fork RUN@STEP`, or `/fork RUN@STEP` mid-chat — replaces the NEXT
/// session with `fork_session`: a new run that catches up on the parent's
/// recorded conversation to the fork step, then continues live.
// The chat's inputs are one flat list (as `cmd_compare`'s replay is);
// the count, not the shape, trips the lint.
#[allow(clippy::too_many_arguments)]
fn run_sessions(
    cx: &Cx<'_>,
    inp: &crate::inputs::Inputs,
    workspace: &str,
    state_root: &std::path::Path,
    backend: &dyn harness_model::ModelBackend,
    o: &BTreeMap<&str, &str>,
    cfg: &Option<crate::config::UserConfig>,
    fork: Option<(RunId, u64)>,
) -> Outcome {
    let state = Rc::new(RefCell::new(ChatState {
        workspace: workspace.to_owned(),
        state_root: state_root.to_string_lossy().into_owned(),
        profile: inp.profile.id().to_owned(),
        endpoint: crate::config::value(o, cfg, "endpoint")
            .unwrap_or("(a backend given to the library)")
            .to_owned(),
        tools: inp.spec.grants.clone(),
        policy_digest: inp.policy.digest().to_string(),
        turns: 0,
        steps: 0,
        attempt_dir: None,
        last_calls: Vec::new(),
        pending: BTreeMap::new(),
        last_todo: None,
        clear: false,
        exit: false,
        fork,
        hosted: inp.profile.hosted(),
        pricing: inp.profile.pricing(),
    }));
    let sink = SinkRenderer::new(cx, state.clone());
    // P-30: the trust store (in the user's config dir). Unreadable or
    // malformed: refuse rather than silently forgetting prior decisions.
    let trust = match crate::trust::Trust::load() {
        Ok(t) => Rc::new(RefCell::new(t)),
        Err(e) => return refused(crate::report::exit::UNREADABLE_INPUT, e),
    };
    // One stdin reader for the whole chat (input and approver share it);
    // injected lines end after their last line.
    let (feed_slot, chat_input): (Option<Rc<LineFeed>>, ChatInput) = match &cx.input {
        InputSource::Stdin => {
            let feed = Rc::new(LineFeed::spawn());
            let commands = commands_for(workspace, &trust);
            let input = ChatInput::from_feed(cx, state.clone(), feed.clone(), Some(commands));
            (Some(feed), input)
        }
        InputSource::Given(lines) => {
            let commands = commands_for(workspace, &trust);
            (
                None,
                ChatInput::from_lines(cx, state.clone(), lines.to_vec(), Some(commands)),
            )
        }
    };
    // The project notes (P-30): found once per chat, before any session.
    let instructions_slot = load_notes(cx, workspace, &trust, &feed_slot);
    // Who answers an ask (§5.3): at a real terminal the chat's own prompt
    // over the shared feed; an approver given to the library wins; with
    // nobody, every ask is a deny (§5.2). A config `approver: "none"`
    // says nobody is at the terminal (P-07).
    let wants_terminal = match cfg {
        Some(c) => c.approver == crate::config::ApproverSetting::Terminal,
        None => true,
    };
    let mut chat_approver_slot: Option<ChatApprover> = None;
    let approver: Option<&dyn Approver> = match cx.approver {
        ApproverSource::None => None,
        ApproverSource::Given(a) => Some(a),
        ApproverSource::StdinIfTerminal => {
            use std::io::IsTerminal;
            if wants_terminal && std::io::stdin().is_terminal() {
                if let Some(feed) = &feed_slot {
                    chat_approver_slot = Some(ChatApprover::new(cx, feed.clone()));
                }
            }
            chat_approver_slot.as_ref().map(|a| a as &dyn Approver)
        }
    };
    // The session budgets are the P-05 defaults (see the module docs).
    let mut session_config = SessionConfig::defaults(TOKEN_BUDGET);
    // Session-scoped grants (P-23, Q-4): default off; the flag lets the
    // person answer `a`/`d` at an approval prompt.
    session_config.run.allow_session_grants = o.contains_key("allow-session-grants");
    let report = loop {
        // The fork pending for this session, if any: the first one from
        // `--fork`, later ones from `/fork` (at most one per session).
        // (The borrow must end before the session runs: the renderer
        // reads the same state as events stream.)
        let pending_fork = state.borrow_mut().fork.take();
        let (parent, parent_step) = match pending_fork {
            Some((p, s)) => (p, s),
            None => {
                match run_session(SessionRun {
                    state_root,
                    workspace: std::path::Path::new(workspace),
                    spec: &inp.spec,
                    registry: &inp.registry,
                    policy: &inp.policy,
                    profile: &inp.profile,
                    backend,
                    probe: cx.probe,
                    env: &harness_sandbox::environment::SystemEnv,
                    config: &session_config,
                    approver,
                    confinement: Some(cx.confinement),
                    input: &chat_input,
                    sink: Some(&sink),
                    instructions: instructions_slot.as_ref(),
                }) {
                    Ok(r) => {
                        note!(
                            cx,
                            "session {} attempt {}: {} turn(s), {} step(s), stopped ({})",
                            r.run.run,
                            r.run.attempt,
                            r.turns,
                            r.run.steps,
                            harness_journal::writer::stop_cause_name(&r.run.cause)
                        );
                        note!(
                            cx,
                            "outcome: indeterminate (NothingChecked): nothing has verified the result"
                        );
                        let (clear, exit_chat) = {
                            let st = state.borrow_mut();
                            (st.clear, st.exit)
                        };
                        if clear && !exit_chat {
                            {
                                let mut st = state.borrow_mut();
                                st.clear = false;
                                st.turns = 0;
                                st.steps = 0;
                                st.last_calls.clear();
                                st.pending.clear();
                            }
                            note!(cx, "new session:");
                            continue;
                        }
                        break r;
                    }
                    Err(e) => return from_refusal(cx, &e),
                }
            }
        };
        note!(cx, "forking {}@{}:", parent, parent_step);
        match fork_session(ForkSession {
            state_root,
            parent: &parent,
            parent_step,
            workspace: Some(std::path::Path::new(workspace)),
            spec: &inp.spec,
            registry: &inp.registry,
            policy: &inp.policy,
            profile: &inp.profile,
            backend,
            probe: cx.probe,
            env: &harness_sandbox::environment::SystemEnv,
            config: &session_config,
            approver,
            confinement: Some(cx.confinement),
            input: &chat_input,
            sink: Some(&sink),
        }) {
            Ok(r) => {
                note!(
                    cx,
                    "session {} attempt {}: {} turn(s), {} step(s), stopped ({})",
                    r.run.run,
                    r.run.attempt,
                    r.turns,
                    r.run.steps,
                    harness_journal::writer::stop_cause_name(&r.run.cause)
                );
                note!(
                    cx,
                    "outcome: indeterminate (NothingChecked): nothing has verified the result"
                );
                let exit_chat = state.borrow().exit;
                if exit_chat {
                    break r;
                }
                note!(cx, "new session:");
                continue;
            }
            Err(e) => return from_refusal(cx, &e),
        }
    };
    if let Some(e) = &report.run.journal_error {
        note!(cx, "journal failure: {e}");
    }
    // The run bundle (P-14), as `run` writes it: best effort, never
    // outcome-changing.
    let bundle_src = crate::bundle::BundleSource::new(
        crate::config::value(o, cfg, "task"),
        crate::config::value(o, cfg, "profile"),
        crate::config::value(o, cfg, "policy"),
    );
    if let Err(e) = crate::bundle::write_run_bundle(
        &report.run.run_dir,
        &bundle_src,
        crate::config::value(o, cfg, "endpoint").unwrap_or("(a backend given to the library)"),
        workspace,
        &inp.digests,
        // The policy was digested under the run's own overlay settings
        // (P-12 default denies; P-23 accept-edits); the bundle self-check
        // must digest it the same way.
        !o.contains_key("no-default-denies"),
        o.contains_key("accept-edits"),
    ) {
        note!(cx, "run bundle not written: {e}");
    }
    let where_ = format!("session {} attempt {}", report.run.run, report.run.attempt);
    let mut findings = info(
        "harness.chat",
        &where_,
        "a verification plan (H1 tasks have none)",
        format!(
            "stopped: {}; no checks planned",
            harness_journal::writer::stop_cause_name(&report.run.cause)
        ),
    )
    .into_iter()
    .collect::<Vec<Finding>>();
    if let Ok(f) = Finding::new(
        gate_outcome::Severity::Info,
        FindingCode("harness.chat.turns".to_owned()),
        &where_,
        "the turns the session journaled",
        format!("{} turn(s)", report.turns),
    ) {
        findings.push(f);
    }
    Outcome {
        outcome: report.run.outcome,
        findings,
        chain_head: report.run.chain_head.map(|d| d.to_string()),
        exit_override: None,
    }
}

fn from_refusal(cx: &Cx<'_>, e: &RunRefused) -> Outcome {
    note!(cx, "the session did not start: {e}");
    let code = match e {
        RunRefused::Confinement(_) => exit::CONFINEMENT_REFUSED,
        RunRefused::Presubmit(_) => exit::UNREADABLE_INPUT,
        _ => exit::INDETERMINATE,
    };
    let mut out = refused(code, format!("the session did not start: {e}"));
    out.outcome = e.outcome();
    out
}
