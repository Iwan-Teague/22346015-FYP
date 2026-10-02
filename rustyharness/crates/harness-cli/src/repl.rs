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
use std::rc::Rc;
use std::sync::mpsc;
use std::time::Instant;

use harness_policy::approval::ApprovalRequest;
use harness_run::{
    ApprovalAnswer, Approver, ApproverKind, InputEnd, UserInput, UserInputEvent, UserMessage,
    UserMessageRefused,
};

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
}

impl<'c, 'a> ChatInput<'c, 'a> {
    /// Read this process's stdin through `feed`.
    pub(crate) fn from_feed(
        cx: &'c Cx<'a>,
        state: Rc<RefCell<ChatState>>,
        feed: Rc<LineFeed>,
    ) -> Self {
        Self {
            cx,
            state,
            lines: Lines::Feed(feed),
        }
    }

    /// Read the injected `lines` (tests; an embedder).
    pub(crate) fn from_lines(
        cx: &'c Cx<'a>,
        state: Rc<RefCell<ChatState>>,
        lines: Vec<String>,
    ) -> Self {
        Self {
            cx,
            state,
            lines: Lines::Given(RefCell::new(lines.into())),
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
            ("/status", _) => note!(
                self.cx,
                "workspace {} | state root {} | profile {} | model {} | {} turn(s), {} step(s) so far",
                st.workspace,
                st.state_root,
                st.profile,
                st.endpoint,
                st.turns,
                st.steps
            ),
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
                drop(st);
                match dir.and_then(|d| harness_journal::JournalReader::open(&d).ok()) {
                    Some(v) => note!(self.cx, "{}", crate::usage::Usage::from_journal(&v).in_words()),
                    None => note!(self.cx, "no journal yet"),
                }
            }
            ("/diff", _) => note!(self.cx, "/diff needs P-40 (not in this build)"),
            _ => note!(self.cx, "unknown command; {HELP}"),
        }
        Slash::Continue
    }
}

/// The slash commands, as `/help` prints them.
const HELP: &str =
    "commands: /help /status /tools /policy /sessions /resume /todo /usage /diff /clear /exit";

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
