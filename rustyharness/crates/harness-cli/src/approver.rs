//! Who answers an ask in `run` and `resume` (§5.3, H2b): nobody, the
//! person at the terminal, or an approver an embedder gives.

use std::time::Instant;

use harness_policy::approval::ApprovalRequest;
use harness_run::{ApprovalAnswer, Approver, ApproverKind};

use crate::Cx;

/// Who answers an ask (§5.3, H2b).
pub enum ApproverSource<'a> {
    /// Nobody: every ask is a deny (§5.2).
    None,
    /// The person at the terminal, when stdin is a terminal
    /// ([`TerminalApprover`]); nobody otherwise (a pipe, a file, CI), so an
    /// unattended run never waits for an answer that cannot come.
    StdinIfTerminal,
    /// This approver (tests; an embedder driving the CLI library).
    Given(&'a dyn Approver),
}

/// The terminal prompt (§5.3): shows the request on stderr (the approval
/// request's own display: plain words, the arguments escaped for a
/// terminal and bounded) and reads one line from stdin. `y` or `yes`
/// approves this one call; any other line declines; no line by the
/// deadline, or stdin closed, is no answer (a deny). Lines typed before
/// the prompt appears are discarded, so a late answer to an earlier
/// request can never approve this one.
///
/// Stdin is read by one background thread for the life of the process
/// (a blocked read cannot be given a deadline otherwise); it only forwards
/// lines, and nothing it reads reaches an argv, a prompt or the journal.
pub struct TerminalApprover<'c, 'a> {
    cx: &'c Cx<'a>,
    lines: std::sync::mpsc::Receiver<String>,
}

impl<'c, 'a> TerminalApprover<'c, 'a> {
    /// A prompt on `cx`'s stderr, answered on this process's stdin.
    pub fn new(cx: &'c Cx<'a>) -> Self {
        let (tx, lines) = std::sync::mpsc::channel();
        // If the thread cannot start, `tx` is dropped with it: every ask
        // then finds the channel closed, which is no answer (a deny).
        let _ = std::thread::Builder::new()
            .name("approver-stdin".into())
            .spawn(move || {
                use std::io::BufRead;
                for line in std::io::stdin().lock().lines() {
                    let Ok(line) = line else { break };
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
        Self { cx, lines }
    }
}

impl Approver for TerminalApprover<'_, '_> {
    fn kind(&self) -> ApproverKind {
        ApproverKind::Terminal
    }

    fn ask(&self, req: &ApprovalRequest, deadline: Instant) -> ApprovalAnswer {
        while self.lines.try_recv().is_ok() {}
        self.cx.note(&format!(
            "{req}\napprove this one call? [y/N] (no answer by the deadline is a no): "
        ));
        let wait = deadline.saturating_duration_since(Instant::now());
        match self.lines.recv_timeout(wait) {
            Ok(line) => {
                let a = line.trim().to_ascii_lowercase();
                if a == "y" || a == "yes" {
                    ApprovalAnswer::Yes
                } else {
                    ApprovalAnswer::No
                }
            }
            Err(_) => ApprovalAnswer::NoAnswer,
        }
    }
}
