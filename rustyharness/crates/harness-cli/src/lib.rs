//! `rustyharness`: the command line (design §7.7, §2.9, §2.10, §3.4), as a
//! library the binary (`src/main.rs`) calls with the real per-OS locality
//! probe (`harness_sandbox::locality::SystemProbe`). Tests call
//! [`main_with`] in process with their own probe; no build of the binary
//! can switch its probe (H1e-2b review F-2).
//!
//! `run`, `resume` and `replay` are **gate children** (§7.7): whatever
//! happens after the arguments are read, the LAST stdout line is the
//! run's `GateReport` as JSON (UNIFIED §6.1), and the exit code agrees
//! with it:
//!
//! | Exit | Meaning |
//! |---|---|
//! | 0 | `Passed`; the `GATE_OK_FILE` marker is written only then, after `RunStopped` is durable and the report line is out |
//! | 1 | `Failed` |
//! | 2 | usage error |
//! | 3 | confinement refused: the task grants `harness.exec.run` and this host has no conformed sandbox (INV-6: nothing ran, nothing was journaled) |
//! | 4 | unreadable input (task spec, policy, profile; a manifest for `manifest check`) |
//! | 5 | `Indeterminate` (the kind is in the JSON): every H1 run, a refused run (e.g. the locality check), a journal failure, a replay divergence |
//!
//! Every run so far is `Indeterminate { NothingChecked }` (no task has
//! checks before H3) and exits 5 with no marker, whatever the agent did,
//! edits included. An edit asks unless the `--policy` file allows the edit
//! tools; the binary's approver is the person at the terminal, only when
//! stdin is a terminal, so an unattended run (a pipe, CI, `< /dev/null`)
//! has nobody to ask and every ask is a deny (§5.2, §5.3; H2b). A command
//! (`harness.exec.run`, H2d) asks the same way unless the policy allows the
//! runner; it runs only in the conformed sandbox of this host (the binary
//! passes `harness_sandbox::SystemConfinement`), with the programs the task
//! file's `exec` section pins. Before the
//! report line, one line
//! `chain_head <sha256>` names the journal's final chain head (§7.1
//! "Anchoring"): keep it to detect a replaced journal later
//! (`replay --anchor`).
//!
//! The commit order (§7.1): `RunStopped` durable (inside the run), then the
//! report line, then the marker (only for `Passed`), then exit. If writing
//! the report line or the marker fails, the exit is 5, never 0.
//!
//! `profile check` runs the smoke eval against a live server and prints the
//! stamp to add to the profile (it is not a gate child).
//!
//! `manifest check` validates a provider manifest with the admission parser
//! (not a gate child either): exit 0 valid, 1 refused on content, 4 not
//! readable as a JSON document at all (missing, too large, not well-formed
//! JSON), 5 if the harness cannot check (its own version is not SemVer). A
//! valid manifest is not an admitted one.
//!
//! The verb implementations live in their own modules (`cmd_run`,
//! `cmd_replay`, `cmd_profile`, `cmd_manifest`), with the option parsing
//! (`args`), the input readers (`inputs`), the approver (`approver`), the
//! gate-child ending (`report`) and the dispatch (`dispatch`) beside them.
//!
//! `events` (slice P-15) is not a gate child either: it projects an
//! attempt's journal to stdout as newline-delimited JSON — a schema line,
//! then one line per record, byte-for-byte the journal's canonical line —
//! and `--follow` tails a live journal until the run commits. `run` and
//! `resume` accept `--output stream-json` to print the same stream, plus a
//! `usage {...}` line, before the `chain_head` line (the usage module
//! computes the footer from the journal).

#![forbid(unsafe_code)]
// The panic-set lints ratchet production code; unit tests may assert loosely.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

use std::cell::RefCell;
use std::io::Write;
use std::path::PathBuf;

use harness_policy::locality::LocalityProbe;

// The two output helpers, textually in scope in every module below (§7.7:
// human lines on stderr, machine lines on stdout).
macro_rules! note {
    ($cx:expr, $($t:tt)*) => { $cx.note(&format!($($t)*)) };
}
macro_rules! say {
    ($cx:expr, $($t:tt)*) => { $cx.say(&format!($($t)*)) };
}

mod approver;
mod args;
mod cmd_events;
mod cmd_manifest;
mod cmd_profile;
mod cmd_replay;
mod cmd_run;
mod config;
mod dispatch;
mod exec_presets;
mod inputs;
mod report;
mod usage;

pub use approver::{ApproverSource, TerminalApprover};
pub use dispatch::main_with;

/// Where the CLI writes, and what it is given from outside: the locality
/// probe and the `GATE_OK_FILE` marker path. The shipped binary
/// (`src/main.rs`) always passes the real per-OS probe
/// (`harness_sandbox::locality::SystemProbe`, spike S-F1; on Windows it
/// refuses every `state_root` until spike S-W1) and the marker path from the
/// environment; only this crate's tests pass another probe, in process. No
/// build of the binary carries a way to switch the probe (H1e-2b review F-2).
pub struct Cx<'a> {
    /// The filesystem-locality probe.
    pub probe: &'a dyn LocalityProbe,
    /// The `GATE_OK_FILE` path, if the parent set one.
    pub gate_ok_file: Option<PathBuf>,
    /// Standard output.
    pub out: RefCell<&'a mut dyn Write>,
    /// Standard error.
    pub err: RefCell<&'a mut dyn Write>,
    /// Who answers an ask in `run` and `resume` (§5.3). The shipped binary
    /// passes [`ApproverSource::StdinIfTerminal`].
    pub approver: ApproverSource<'a>,
    /// Where commands are confined in `run` and `resume` (H2d). The shipped
    /// binary passes `harness_sandbox::SystemConfinement`; it is asked for a
    /// witness only when the task grants `harness.exec.run`.
    pub confinement: &'a dyn harness_sandbox::Confinement,
}

impl Cx<'_> {
    pub(crate) fn note(&self, s: &str) {
        let _ = writeln!(self.err.borrow_mut(), "{s}");
    }
    pub(crate) fn say(&self, s: &str) {
        let _ = writeln!(self.out.borrow_mut(), "{s}");
    }
}
