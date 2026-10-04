//! The `chat` REPL's input side (P-18): where the session's messages come
//! from, the slash commands, and who answers an ask at a real terminal.
//!
//! One line reader serves both the session's [`UserInput`] and the
//! [`ChatApprover`]: at a real terminal one background thread
//! ("chat-stdin", the twin of the approver thread in `approver`) forwards
//! stdin lines over a channel, and `run`'s [`TerminalApprover`] is never
//! used here — two readers would steal each other's lines. Tests inject
//! lines instead (`InputSource::Given`), and an approver given by the test
//! binary answers asks.
//!
//! Slash commands are handled between turns, under the paused wall clock,
//! before a line becomes a [`UserMessage`]: nothing a slash command prints
//! reaches the model or the journal. A line that `UserMessage::new`
//! refuses (empty after trim, over 64 KiB) is noted and dropped — it never
//! reaches the session either.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::io::BufRead;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use harness_core::{Digest, RunId};
use harness_journal::layout;
use harness_journal::reader::DirBlobSource;
use harness_policy::approval::ApprovalRequest;
use harness_run::{
    external_differ, marks_from_records, plan, ApprovalAnswer, Approver, ApproverKind, InputEnd,
    RestoreCommand, RestoreMark, UserInput, UserInputEvent, UserMessage, UserMessageRefused,
};
use harness_tools::builtin::workspace_tree;

use crate::Cx;

/// Where the REPL's lines come from (P-18). The shipped binary reads this
/// process's stdin; an embedder (the test kit) injects the lines.
pub enum InputSource<'a> {
    /// This process's stdin, line by line.
    Stdin,
    /// These lines, in order, then end of input (tests; an embedder).
    Given(&'a [String]),
}

/// Which model backend `chat` talks to (P-18). The shipped binary builds
/// one from `--endpoint`; an embedder injects a scripted one.
pub enum BackendSource<'a> {
    /// Build the OpenAI-compatible client from `--endpoint` (the shipped
    /// binary; the startup check runs before anything else).
    BuiltIn,
    /// This backend (tests; an embedder driving the CLI library).
    Given(&'a dyn harness_model::ModelBackend),
}

/// What the REPL and the sink share (display state only, P-18): what the
/// banner said, what the session has done so far, the last reply's tool
/// calls (for showing `ToolStarted` its arguments), and the `/clear` and
/// `/exit` requests. Never an input to a decision.
pub(crate) struct ChatState {
    pub workspace: String,
    pub state_root: String,
    pub profile: String,
    pub endpoint: String,
    pub tools: Vec<String>,
    pub policy_digest: String,
    pub turns: u64,
    pub steps: u64,
    /// The current attempt's directory (from the events' blobs path), for
    /// `/usage`.
    pub attempt_dir: Option<std::path::PathBuf>,
    /// The last `ModelReplied`'s tool calls, `(name, arguments)` as text.
    pub last_calls: Vec<(String, String)>,
    /// `ToolStarted` records awaiting their `ToolFinished`.
    pub pending: BTreeMap<u64, Pending>,
    /// The last `harness.task.todo` output, for `/todo`.
    pub last_todo: Option<String>,
    /// `/clear` seen: end this session, start a fresh one.
    pub clear: bool,
    /// `/exit` seen: end the session and the chat.
    pub exit: bool,
    /// A fork pending for the NEXT session (`/fork RUN@STEP`, P-32): the
    /// outer loop in `cmd_chat` runs it as `fork_session` instead of a
    /// fresh `run_session`. Like `clear`/`exit`, a display-state request,
    /// never an input to a journaled decision.
    pub fork: Option<(RunId, u64)>,
    /// The profile declares a hosted upstream (P-31): the session's
    /// context is sent to a hosted provider. Display only.
    pub hosted: bool,
    /// The profile's price table (P-31), for `/usage`'s cost. Display only.
    pub pricing: Option<harness_core::Pricing>,
}

/// One tool call in flight, as the tool line needs it.
pub(crate) struct Pending {
    pub capability: String,
    pub args: String,
    pub started: Instant,
}

/// The stdin line reader shared by the input and the approver at a real
/// terminal. Lines typed before anybody asks are held in the channel (the
/// approver drains stale ones before each ask, so a late answer to an
/// earlier request can never approve this one).
pub(crate) struct LineFeed {
    rx: mpsc::Receiver<String>,
}

impl LineFeed {
    /// Start the one "chat-stdin" thread. If it cannot start, every read
    /// finds the channel closed: end of input, a deny.
    pub(crate) fn spawn() -> Self {
        let (tx, rx) = mpsc::channel();
        let _ = std::thread::Builder::new()
            .name("chat-stdin".into())
            .spawn(move || {
                for line in std::io::stdin().lock().lines() {
                    let Ok(line) = line else { break };
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
        Self { rx }
    }

    /// The next line, or `None` past `deadline` (or when stdin closes).
    pub(crate) fn next_line(&self, deadline: Instant) -> Option<String> {
        let wait = deadline.saturating_duration_since(Instant::now());
        self.rx.recv_timeout(wait).ok()
    }

    /// Discard lines typed before the current ask appeared.
    pub(crate) fn drain(&self) {
        while self.rx.try_recv().is_ok() {}
    }
}

enum Lines {
    Feed(Rc<LineFeed>),
    Given(RefCell<VecDeque<String>>),
}

impl Lines {
    /// The next raw line, `None` at end of input or past `deadline`.
    fn next(&self, deadline: Instant) -> Option<String> {
        match self {
            Lines::Feed(f) => f.next_line(deadline),
            Lines::Given(q) => q.borrow_mut().pop_front(),
        }
    }
}

/// The chat REPL as the session's [`UserInput`] (P-18): one line, or a
/// `"""` block, or one slash command, per message. A refused line is
/// noted and dropped; `/clear` and `/exit` end the session (the outer
/// loop in `cmd_chat` starts a fresh one for `/clear`).
pub(crate) struct ChatInput<'c, 'a> {
    cx: &'c Cx<'a>,
    state: Rc<RefCell<ChatState>>,
    lines: Lines,
    /// Command templates (P-30): `None` disables them (never expected;
    /// fail closed to the built-ins only).
    commands: Option<Rc<CommandSources>>,
}

impl<'c, 'a> ChatInput<'c, 'a> {
    /// Read this process's stdin through `feed`.
    pub(crate) fn from_feed(
        cx: &'c Cx<'a>,
        state: Rc<RefCell<ChatState>>,
        feed: Rc<LineFeed>,
        commands: Option<Rc<CommandSources>>,
    ) -> Self {
        Self {
            cx,
            state,
            lines: Lines::Feed(feed),
            commands,
        }
    }

    /// Read the injected `lines` (tests; an embedder).
    pub(crate) fn from_lines(
        cx: &'c Cx<'a>,
        state: Rc<RefCell<ChatState>>,
        lines: Vec<String>,
        commands: Option<Rc<CommandSources>>,
    ) -> Self {
        Self {
            cx,
            state,
            lines: Lines::Given(RefCell::new(lines.into())),
            commands,
        }
    }
}

impl UserInput for ChatInput<'_, '_> {
    fn next(&self, deadline: Instant) -> UserInputEvent {
        loop {
            let Some(first) = self.lines.next(deadline) else {
                return UserInputEvent::End(InputEnd::Eof);
            };
            let text = if first.trim() == "\"\"\"" {
                // A `"""` block: raw lines until the closing `"""` (or end
                // of input, which closes it with a note).
                let mut block: Vec<String> = Vec::new();
                loop {
                    match self.lines.next(deadline) {
                        None => {
                            note!(
                                self.cx,
                                "(unterminated \"\"\" block: closed by end of input)"
                            );
                            break;
                        }
                        Some(l) if l.trim() == "\"\"\"" => break,
                        Some(l) => block.push(l),
                    }
                }
                block.join("\n")
            } else if first.trim().starts_with('/') {
                match self.slash(first.trim(), deadline) {
                    Slash::Continue => continue,
                    Slash::EndSession => return UserInputEvent::End(InputEnd::Exit),
                    Slash::Restore(cmd) => return UserInputEvent::Restore(cmd),
                    Slash::Plan => return UserInputEvent::Plan,
                    Slash::Build => return UserInputEvent::Build,
                    Slash::Message(text) => text,
                    Slash::Fork => return UserInputEvent::End(InputEnd::Exit),
                }
            } else {
                first
            };
            match UserMessage::new(text) {
                Ok(m) => return UserInputEvent::Message(m),
                Err(UserMessageRefused::Empty) => continue,
                Err(UserMessageRefused::TooLong { len, max }) => {
                    note!(
                        self.cx,
                        "message dropped: {len} bytes is over the {max}-byte limit"
                    );
                }
            }
        }
    }
}

enum Slash {
    /// The command was handled; read the next line.
    Continue,
    /// The command ended the session (`/clear`, `/exit`).
    EndSession,
    /// A restore command whose pre-check passed (`/undo`, `/rewind`): the
    /// loop applies and journals it, re-verifying everything.
    Restore(RestoreCommand),
    /// Plan mode (`/plan`, P-28): the loop narrows the session.
    Plan,
    /// The plan approval (`/build`, P-28): the loop widens the session if
    /// a plan is pending.
    Build,
    /// A command template's expanded text (P-30): the user's message.
    Message(String),
    /// A fork was queued (`/fork RUN@STEP`, P-32): end this session; the
    /// outer loop starts the forked one.
    Fork,
}

/// Where command templates come from (P-30), shared by the chat's input.
/// A template in the user's config dir (`<config dir>/commands/<name>.md`)
/// is trusted by its location — only that user can write there. One in
/// the workspace (`.rustyharness/commands/<name>.md`) is trusted per
/// template digest, remembered in the trust store like the project notes.
pub(crate) struct CommandSources {
    /// The user's config dir, if this platform has one.
    pub(crate) config_dir: Option<PathBuf>,
    /// The workspace the session runs in.
    pub(crate) workspace: PathBuf,
    /// The trust store the workspace-command approvals go to.
    pub(crate) trust: Rc<RefCell<crate::trust::Trust>>,
}

/// The cap on one command template's size, in bytes.
const TEMPLATE_MAX_BYTES: usize = 64 * 1024;

/// A command template's name: `/name` with a letter first, then letters,
/// digits, `_` or `-` (a plain file stem; no paths, no dots).
fn command_name(cmd: &str) -> Option<&str> {
    let mut chars = cmd.chars();
    if !chars.next().is_some_and(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    cmd.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        .then_some(cmd)
}

impl ChatInput<'_, '_> {
    /// The `Lines`' stdin feed, when the input is this process's stdin
    /// (the only place a trust prompt can be answered).
    fn feed(&self) -> Option<Rc<LineFeed>> {
        match &self.lines {
            Lines::Feed(f) => Some(f.clone()),
            Lines::Given(_) => None,
        }
    }

    /// A `/name args…` line that no built-in command claims (P-30): a
    /// command template, expanded and handed back as the user's message.
    /// The config dir's template is trusted by location; the workspace's
    /// must have its digest approved (asked once at a terminal, then
    /// remembered). `None` when there is no such command, or it is
    /// refused.
    fn expand_command(&self, line: &str, sources: &CommandSources) -> Option<String> {
        let mut words = line.splitn(2, char::is_whitespace);
        let name = command_name(words.next()?.trim_start_matches('/'))?;
        let args = words.next().unwrap_or("").trim();
        let candidates = [
            (
                sources.config_dir.as_deref().map(|d| d.join("commands")),
                true,
            ),
            (
                Some(sources.workspace.join(".rustyharness").join("commands")),
                false,
            ),
        ];
        for (dir, by_location) in candidates {
            let Some(dir) = dir else { continue };
            let path = dir.join(format!("{name}.md"));
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    note!(self.cx, "cannot read {}: {e}", path.display());
                    return None;
                }
            };
            if bytes.len() > TEMPLATE_MAX_BYTES {
                note!(
                    self.cx,
                    "{} is over the {TEMPLATE_MAX_BYTES}-byte cap; command refused",
                    path.display()
                );
                return None;
            }
            let Ok(template) = String::from_utf8(bytes) else {
                note!(
                    self.cx,
                    "{} is not UTF-8 text; command refused",
                    path.display()
                );
                return None;
            };
            if !by_location {
                let digest = harness_core::sha256(template.as_bytes()).to_string();
                if !sources.trust.borrow().has_command(&digest)
                    && !self.approve_template(sources, name, &digest)
                {
                    return None;
                }
            }
            return Some(template.replace("$ARGUMENTS", args));
        }
        None
    }

    /// The workspace template's trust prompt (P-30): once at a real
    /// terminal, then remembered in the trust store by template digest.
    fn approve_template(&self, sources: &CommandSources, name: &str, digest: &str) -> bool {
        let Some(feed) = self.feed() else {
            note!(
                self.cx,
                "the workspace command /{name} is not trusted (nobody at a terminal to ask)"
            );
            return false;
        };
        feed.drain();
        self.cx.note(&format!(
            "trust the workspace command template {name} (sha256 {digest}) for this and later chats? [y/N]: "
        ));
        let answer = match feed.next_line(Instant::now() + Duration::from_secs(300)) {
            Some(line) => {
                let a = line.trim().to_ascii_lowercase();
                a == "y" || a == "yes"
            }
            None => false,
        };
        if !answer {
            note!(self.cx, "not trusted: command refused");
            return false;
        }
        sources.trust.borrow_mut().trust_command(digest);
        if let Err(e) = sources.trust.borrow().save() {
            note!(self.cx, "cannot remember the trust decision: {e}");
        }
        true
    }
}

impl ChatInput<'_, '_> {
    fn slash(&self, line: &str, _deadline: Instant) -> Slash {
        let mut words = line.split_whitespace();
        let cmd = words.next().unwrap_or("");
        let arg = words.next();
        let st = self.state.borrow();
        match (cmd, arg) {
            ("/clear", _) | ("/exit", _) => {
                let exit = cmd == "/exit";
                drop(st);
                let mut st = self.state.borrow_mut();
                if exit {
                    st.exit = true;
                } else {
                    st.clear = true;
                    note!(self.cx, "clearing: the next message starts a fresh session");
                }
                return Slash::EndSession;
            }
            ("/help", _) => note!(self.cx, "{HELP}"),
            ("/status", _) => {
                let hosted = if st.hosted {
                    " | context is sent to a hosted provider"
                } else {
                    ""
                };
                note!(
                    self.cx,
                    "workspace {} | state root {} | profile {} | model {} | {} turn(s), {} step(s) so far{}",
                    st.workspace,
                    st.state_root,
                    st.profile,
                    st.endpoint,
                    st.turns,
                    st.steps,
                    hosted
                )
            }
            ("/tools", _) => {
                for t in &st.tools {
                    note!(self.cx, "{t}");
                }
            }
            ("/policy", _) => note!(self.cx, "policy digest: {}", st.policy_digest),
            ("/sessions", _) => {
                let root = st.state_root.clone();
                drop(st);
                crate::cmd_sessions::sessions(self.cx, &["--state-root", root.as_str()]);
            }
            ("/resume", id) => {
                drop(st);
                match id {
                    Some(id) => note!(
                        self.cx,
                        "session reopen needs P-17 (not in this build); would resume {id}"
                    ),
                    None => note!(self.cx, "session reopen needs P-17 (not in this build)"),
                }
            }
            ("/todo", _) => {
                let shown = st.last_todo.clone();
                drop(st);
                match shown {
                    Some(t) => note!(self.cx, "{}", crate::render::cut_line(&t)),
                    None => note!(self.cx, "no todo list yet"),
                }
            }
            ("/usage", _) => {
                let dir = st.attempt_dir.clone();
                let pricing = st.pricing;
                drop(st);
                match dir.and_then(|d| harness_journal::JournalReader::open(&d).ok()) {
                    Some(v) => note!(
                        self.cx,
                        "{}",
                        crate::usage::Usage::from_journal(&v)
                            .priced(pricing)
                            .in_words()
                    ),
                    None => note!(self.cx, "no journal yet"),
                }
            }
            ("/diff", _) => {
                let dir = st.attempt_dir.clone();
                let ws = st.workspace.clone();
                drop(st);
                match dir {
                    Some(d) => {
                        crate::cmd_review::review_live(self.cx, &d, &ws);
                    }
                    None => note!(self.cx, "no journal yet"),
                }
            }
            ("/undo", _) => {
                let dir = st.attempt_dir.clone();
                let ws = st.workspace.clone();
                drop(st);
                return self.plan_restore(dir, &ws, 1, false);
            }
            ("/rewind", _) => {
                let dir = st.attempt_dir.clone();
                let ws = st.workspace.clone();
                drop(st);
                let mut steps = 1u64;
                let mut keep = false;
                for w in words {
                    if w == "--force-keep-external" {
                        keep = true;
                    } else if let Ok(n) = w.parse::<u64>() {
                        steps = n;
                    } else {
                        note!(self.cx, "usage: /rewind [N] [--force-keep-external]");
                        return Slash::Continue;
                    }
                }
                return self.plan_restore(dir, &ws, steps, keep);
            }
            // P-28: plan and build. The loop journals and applies them (a
            // `/build` with nothing pending journals nothing); this side
            // only hands them over.
            ("/plan", _) => return Slash::Plan,
            ("/build", _) => return Slash::Build,
            ("/fork", arg) => {
                let parsed = arg.and_then(crate::cmd_chat::parse_fork);
                drop(st);
                match parsed {
                    Some((run, step)) => {
                        note!(self.cx, "forking: the next session continues {run}@{step}");
                        let mut st = self.state.borrow_mut();
                        st.clear = false;
                        st.fork = Some((run, step));
                        return Slash::Fork;
                    }
                    None => note!(self.cx, "usage: /fork RUN@STEP"),
                }
            }
            // P-30: a command template, expanded into the user's message.
            _ => {
                let sources = match &self.commands {
                    Some(c) => c.clone(),
                    None => {
                        note!(self.cx, "unknown command; {HELP}");
                        return Slash::Continue;
                    }
                };
                match self.expand_command(line, &sources) {
                    Some(text) => return Slash::Message(text),
                    None => note!(self.cx, "unknown command; {HELP}"),
                }
            }
        }
        Slash::Continue
    }

    /// The pre-check and command for `/undo` and `/rewind` (P-26): the
    /// plan comes from the journal, and — unless keeping external edits —
    /// a workspace that left the journal's state is refused here, naming
    /// the files whose digests differ. What passes is handed to the loop
    /// as a [`UserInputEvent::Restore`]: the loop re-verifies everything
    /// (the workspace may move between this check and the command) and
    /// fails closed there. This side only decides what to show.
    fn plan_restore(&self, dir: Option<PathBuf>, ws: &str, steps: u64, keep: bool) -> Slash {
        let Some(dir) = dir else {
            note!(self.cx, "no journal yet");
            return Slash::Continue;
        };
        let Ok(v) = harness_journal::JournalReader::open(&dir) else {
            note!(self.cx, "no journal yet");
            return Slash::Continue;
        };
        let blobs = DirBlobSource::new(dir.join(layout::BLOBS_DIR));
        let marks = match marks_from_records(&v, &blobs) {
            Ok(m) => m,
            Err(e) => {
                note!(self.cx, "cannot restore from this journal: {e}");
                return Slash::Continue;
            }
        };
        let planned = match plan(&marks, steps) {
            Ok(p) => p,
            Err(e) => {
                note!(self.cx, "{e}");
                return Slash::Continue;
            }
        };
        if !keep {
            let Some(want) = marks.last().and_then(mark_tree) else {
                note!(self.cx, "the journal carries no workspace state yet");
                return Slash::Continue;
            };
            let deadline = Instant::now() + Duration::from_secs(30);
            let root = std::path::Path::new(ws);
            let measured = match workspace_tree(root, deadline) {
                Ok(t) => t,
                Err(e) => {
                    note!(self.cx, "cannot read the workspace: {e}");
                    return Slash::Continue;
                }
            };
            if measured.facts().tree != want {
                note!(
                    self.cx,
                    "the workspace changed outside the harness since the last record; restore refused. Files that differ:"
                );
                for d in external_differ(root, &marks) {
                    let journaled = d
                        .journaled
                        .map(|x| x.to_string())
                        .unwrap_or_else(|| "(deleted)".into());
                    let found = d
                        .found
                        .map(|x| x.to_string())
                        .unwrap_or_else(|| "(gone)".into());
                    note!(self.cx, "  {}: journal {journaled}, now {found}", d.path);
                }
                note!(
                    self.cx,
                    "/rewind --force-keep-external restores only the files still as the harness left them"
                );
                return Slash::Continue;
            }
        }
        note!(
            self.cx,
            "undoing {} file edit(s) back to step {}",
            planned.files.len(),
            planned.to_step
        );
        Slash::Restore(RestoreCommand {
            steps,
            keep_external: keep,
        })
    }
}

/// The tree digest a mark carries.
fn mark_tree(m: &RestoreMark) -> Option<Digest> {
    match m {
        RestoreMark::Tree { tree, .. } | RestoreMark::Edit { tree, .. } => Some(*tree),
    }
}

/// The slash commands, as `/help` prints them. P-30: a `/name` the
/// built-ins do not claim runs a command template (`$ARGUMENTS` becomes
/// the rest of the line) from `<config dir>/commands/name.md` (trusted by
/// location) or `<workspace>/.rustyharness/commands/name.md` (trusted per
/// template digest).
const HELP: &str = "commands: /help /status /tools /policy /sessions /resume /fork RUN@STEP /todo /usage /diff /undo /rewind [N] [--force-keep-external] /plan /build /clear /exit; command templates: /name args (commands/*.md)";

/// The terminal prompt for an ask, over the chat's own stdin feed (P-18):
/// the request itself is shown by the sink's `[approve]` line, so this
/// only asks for the answer — one reader, one prompt. Same rules as
/// `approver.rs`: `y`/`yes` approves this one call, any other line
/// declines, no line by the deadline (or stdin closed) is no answer, and
/// lines typed before the prompt are discarded.
pub(crate) struct ChatApprover<'c, 'a> {
    cx: &'c Cx<'a>,
    feed: Rc<LineFeed>,
}

impl<'c, 'a> ChatApprover<'c, 'a> {
    pub(crate) fn new(cx: &'c Cx<'a>, feed: Rc<LineFeed>) -> Self {
        Self { cx, feed }
    }
}

impl Approver for ChatApprover<'_, '_> {
    fn kind(&self) -> ApproverKind {
        ApproverKind::Terminal
    }

    fn ask(&self, _req: &ApprovalRequest, deadline: Instant) -> ApprovalAnswer {
        self.feed.drain();
        self.cx
            .note("approve this one call? [y/N] (no answer by the deadline is a no): ");
        match self.feed.next_line(deadline) {
            Some(line) => {
                let a = line.trim().to_ascii_lowercase();
                if a == "y" || a == "yes" {
                    ApprovalAnswer::Yes
                } else {
                    ApprovalAnswer::No
                }
            }
            None => ApprovalAnswer::NoAnswer,
        }
    }
}
