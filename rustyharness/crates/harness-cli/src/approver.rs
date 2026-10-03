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
/// terminal and bounded, plus the edit diff preview the loop attaches) and
/// reads one line from stdin. `y` or `yes` approves this one call;
/// `a` allows the call's pattern for the session and `d` denies it for the
/// session (P-23: journaled as a `RuleGranted`, applied like a policy
/// rule); `?` shows the request again; any other line declines; no line by
/// the deadline, or stdin closed, is no answer (a deny). Lines typed
/// before the prompt appears are discarded, so a late answer to an earlier
/// request can never approve this one.
///
/// Stdin is read by one background thread for the life of the process
/// (a blocked read cannot be given a deadline otherwise); it only forwards
/// lines, and nothing it reads reaches an argv, a prompt or the journal.
pub struct TerminalApprover<'c, 'a> {
    cx: &'c Cx<'a>,
    lines: std::sync::mpsc::Receiver<String>,
}

/// The choices an approval prompt offers (P-23).
const PROMPT: &str = "approve this one call? [y] once [n] no \
[a] allow this pattern for the session [d] deny this pattern for the session \
[?] details: ";

/// One line at the prompt, parsed: an answer, or `?` (show the details
/// again, then prompt once more). Anything else is a decline.
enum Parsed {
    Answer(ApprovalAnswer),
    Details,
}

fn answer_of(line: &str) -> Parsed {
    match line.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Parsed::Answer(ApprovalAnswer::Yes),
        "a" => Parsed::Answer(ApprovalAnswer::AllowSession),
        "d" => Parsed::Answer(ApprovalAnswer::DenySession),
        "?" => Parsed::Details,
        _ => Parsed::Answer(ApprovalAnswer::No),
    }
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
        self.cx.note(&format!("{req}\n{PROMPT}"));
        loop {
            let wait = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(wait) {
                Ok(line) => match answer_of(&line) {
                    Parsed::Answer(a) => return a,
                    Parsed::Details => self.cx.note(&format!("{req}\n{PROMPT}")),
                },
                Err(_) => return ApprovalAnswer::NoAnswer,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::answer_of;
    use super::Parsed;
    use harness_run::ApprovalAnswer;

    /// The prompt's answers (P-23): once, no, session-allow, session-deny,
    /// details (`?`, prompt again), and any other line declines.
    #[test]
    fn answers_map_and_other_lines_decline() {
        let ans = |s: &str| -> Option<ApprovalAnswer> {
            match answer_of(s) {
                Parsed::Answer(a) => Some(a),
                Parsed::Details => None,
            }
        };
        assert!(matches!(ans("y"), Some(ApprovalAnswer::Yes)));
        assert!(matches!(ans("YES"), Some(ApprovalAnswer::Yes)));
        assert!(matches!(ans(" a "), Some(ApprovalAnswer::AllowSession)));
        assert!(matches!(ans("d"), Some(ApprovalAnswer::DenySession)));
        assert!(matches!(ans("n"), Some(ApprovalAnswer::No)));
        assert!(matches!(ans("later"), Some(ApprovalAnswer::No)));
        assert!(matches!(answer_of("?"), Parsed::Details));
    }
}
