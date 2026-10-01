//! The tool-provider seam (design §4.5, §2.2 steps 7-8). The built-in read
//! tools ([`crate::builtin`], H1e-2) and edit tools ([`crate::edit`], H2b)
//! implement it, and the loop in `harness-run` drives it, sending each call
//! to the first provider that serves its capability
//! ([`ToolProvider::serves`]); the MCP adapter is H4.
//!
//! `ToolProvider::invoke` accepts exactly one argument type for the call,
//! `Journaled<Authorized<Call>>`:
//! - `Authorized<Call>` is minted only by `harness_policy::Session::authorize`,
//!   and only for an `Allow` decision;
//! - `Journaled<_>` is minted only by
//!   `harness_journal::JournalWriter::append_intent`, after the intent record
//!   was written and fsynced.
//!
//! So no provider can be driven by an unvalidated call, or by one whose
//! intent is not durably journaled: those are not merely forbidden, they do
//! not typecheck (F-01, INV-33).
//!
//! ```compile_fail,E0308
//! // An authorised but unjournaled call is the wrong type.
//! fn drive<P: harness_tools::ToolProvider>(
//!     p: &mut P,
//!     call: harness_policy::Authorized<harness_policy::Call>,
//!     ctx: &harness_tools::InvokeCtx,
//! ) {
//!     let _ = p.invoke(call, ctx);
//! }
//! ```
//!
//! ```compile_fail,E0308
//! // A journaled but unauthorised call is the wrong type too.
//! fn drive<P: harness_tools::ToolProvider>(
//!     p: &mut P,
//!     call: harness_journal::Journaled<harness_policy::Call>,
//!     ctx: &harness_tools::InvokeCtx,
//! ) {
//!     let _ = p.invoke(call, ctx);
//! }
//! ```
//!
//! **Synchronous in H1.** Design §4.5 sketches `async fn invoke`, and an
//! `async fn` in a public trait needs a decision on `Send` bounds. H1e
//! decided: `ToolProvider`, like `ModelBackend`, stays synchronous for H1,
//! and the question returns with rmcp (H4). The argument type, which is
//! what F-01 is about, is fixed here.

use std::time::Instant;

use harness_core::{Digest, Untrusted};
use harness_journal::Journaled;
use harness_manifest::ProviderName;
use harness_policy::{Authorized, Call};

use crate::edit::ReadLog;

/// Why a provider refused a call it was handed (§4.5 `ToolStatus::Refused`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    /// The capability is not one this provider serves.
    UnknownCapability,
    /// The call needs a conformed sandbox and none was given.
    NoConformed,
    /// The per-call deadline had already passed.
    DeadlinePassed,
    /// The provider is quarantined.
    Quarantined,
}

/// How a call ended (§4.5). Not a verdict (§1.4): no variant says a run passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolStatus {
    /// Completed.
    Ok,
    /// Completed with a tool-level error code.
    Error {
        /// The code.
        code: u16,
    },
    /// Killed at its deadline.
    Timeout,
    /// Crashed.
    Crashed {
        /// The signal, where the platform has one.
        signal: Option<i32>,
    },
    /// Refused before doing anything.
    Refused {
        /// Why.
        reason: RefusalKind,
    },
}

/// What a call produced (§2.2 step 8).
#[derive(Debug)]
pub struct ToolResult {
    /// How it ended.
    pub status: ToolStatus,
    /// Output, untrusted like everything from outside the harness.
    pub output: Untrusted<Vec<u8>>,
    /// Whether the output was cut at the result cap.
    pub truncated: bool,
    /// SHA-256 of the full output (computed by the harness, §1.4).
    pub digest: Digest,
    /// For a successful `fs.read`: which file, and the SHA-256 of its whole
    /// content when read (§2.3 "Stale reads"; the run keeps these so an
    /// edit can refuse a file that changed since it was read).
    pub read: Option<ReadRecord>,
    /// For a successful, verified edit (§4.9 step 5, H2b): which file, its
    /// digest before (absent for a create) and after. The run journals it
    /// (`EditApplied`), records the after digest as the file's latest read,
    /// and keeps its workspace tree digest current with it.
    pub edit: Option<EditRecord>,
    /// For a command `harness.exec.run` started (H2d): how it ended,
    /// whether everything it started is confirmed gone, what it wrote, and
    /// the workspace re-measured after it. `None` when no command started.
    pub exec: Option<ExecRecord>,
}

/// What a command did (H2d). The run journals it with the command's
/// `ToolFinished`, keeps its tree digest current with `workspace`, and stops
/// the run when `cleanup` is not confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRecord {
    /// How the program ended.
    pub end: ExecEnd,
    /// Whether every process the command started is confirmed gone.
    pub cleanup: ExecCleanup,
    /// Bytes of stdout kept (at most the output cap).
    pub stdout_bytes: u64,
    /// Bytes of stderr kept (at most the output cap).
    pub stderr_bytes: u64,
    /// Stdout wrote more than the cap; the rest was dropped.
    pub stdout_cut: bool,
    /// Stderr wrote more than the cap; the rest was dropped.
    pub stderr_cut: bool,
    /// Wall time from spawn to the end of cleanup, in milliseconds.
    pub elapsed_ms: u64,
    /// The workspace measured again after the command (a live call whose
    /// cleanup was confirmed). `None` when it was not measured: the
    /// cleanup was not confirmed, the walk failed, or the result was
    /// re-fed from a journal (which carries the tree digest instead).
    pub workspace: Option<crate::builtin::WorkspaceTree>,
}

/// How a command's program ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecEnd {
    /// It exited with this code.
    Exited(i32),
    /// A signal ended it.
    Signaled(i32),
    /// Its wall clock (the call's deadline) ran out and it was killed.
    TimedOut,
    /// It held more processes than the cap, so its sandbox was swept.
    ProcessLimit,
    /// The program could not be started in the sandbox.
    ExecFailed,
    /// The sandbox gave no status the harness can trust.
    Unknown,
}

impl ExecEnd {
    /// The limit that ended the command, where the harness can tell: the
    /// wall clock, the process watchdog, or the CPU-time and file-size
    /// limits by their signals (SIGXCPU, SIGXFSZ). A process that met its
    /// memory budget sees an allocation fail and ends as its code decides,
    /// so that limit is not named.
    pub fn guard(&self) -> Option<&'static str> {
        match self {
            ExecEnd::TimedOut => Some("wall"),
            ExecEnd::ProcessLimit => Some("processes"),
            ExecEnd::Signaled(24) => Some("cpu"),
            ExecEnd::Signaled(25) => Some("file_size"),
            _ => None,
        }
    }
}

/// Whether everything a command started is gone (its kill domain).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecCleanup {
    /// Every process is confirmed gone; this many were killed.
    Confirmed {
        /// Processes the sweep killed.
        kills: u32,
    },
    /// Not confirmed: a process may have survived.
    Unconfirmed,
}

/// A file read and its content digest (§2.3 "Stale reads").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRecord {
    /// The workspace path (lexically checked).
    pub path: harness_policy::WorkspacePath,
    /// SHA-256 of the whole file at read time.
    pub sha256: Digest,
}

/// A verified edit (§4.9 step 5): the file, and its whole content's
/// SHA-256 before and after. `before` is `None` for a created file (the
/// journal's convention for a create: no `before` key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditRecord {
    /// The workspace path (lexically checked).
    pub path: harness_policy::WorkspacePath,
    /// SHA-256 of the file before the edit; `None` when the edit created it.
    pub before: Option<Digest>,
    /// SHA-256 of the file after the edit, as re-read and verified.
    pub after: Digest,
}

/// A provider-level failure (the provider could not even report a status).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("tool provider failed: {0}")]
pub struct ToolError(pub String);

/// Per-invocation context (§4.5). `conformed` joins when `Conformed`
/// exists (H2); secrets handles join with §5.5 (H2).
#[derive(Debug, Clone, Copy)]
pub struct InvokeCtx<'a> {
    /// The loop step.
    pub step: u64,
    /// The per-call deadline.
    pub deadline: Instant,
    /// The files read in this run and their digests at the latest read
    /// (§2.3 "Stale reads"): an edit is anchored on them (H2b). Read-only,
    /// so no provider can mark a file as read; the run records reads from
    /// results.
    pub reads: &'a ReadLog,
}

/// A provider of capabilities (§4.5).
pub trait ToolProvider {
    /// The namespace this provider serves.
    fn namespace(&self) -> &ProviderName;

    /// Whether this provider runs `capability` (an admitted capability id).
    /// By default, every capability in its namespace; the built-in
    /// providers share the `harness` namespace and split it by verb
    /// (H2b), so the run dispatches a call to the first provider that
    /// serves its capability.
    fn serves(&self, capability: &str) -> bool {
        capability
            .split_once('.')
            .is_some_and(|(ns, _)| ns == self.namespace().as_str())
    }

    /// Run one call. The only accepted call type is a policy-authorised call
    /// whose intent is durably journaled.
    fn invoke(
        &mut self,
        call: Journaled<Authorized<Call>>,
        ctx: &InvokeCtx<'_>,
    ) -> Result<ToolResult, ToolError>;
}
