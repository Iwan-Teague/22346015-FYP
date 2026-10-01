//! The tool-provider seam (design §4.5, §2.2 steps 7-8). Signature only:
//! built-in tools, the MCP adapter and the loop that drives them are later
//! slices (H1e, H4).
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
//! **Sync for now.** Design §4.5 sketches `async fn invoke`. The async
//! runtime arrives with the I/O slices (H1d/H1e, rmcp in H4), and an `async
//! fn` in a public trait needs a decision on `Send` bounds; that decision is
//! left to H1e. The argument type, which is what F-01 is about, is fixed
//! here.

use std::time::Instant;

use harness_core::{Digest, Untrusted};
use harness_journal::Journaled;
use harness_manifest::ProviderName;
use harness_policy::{Authorized, Call};

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
    /// edit (H2) can refuse a file that changed since it was read).
    pub read: Option<ReadRecord>,
}

/// A file read and its content digest (§2.3 "Stale reads").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRecord {
    /// The workspace path (lexically checked).
    pub path: harness_policy::WorkspacePath,
    /// SHA-256 of the whole file at read time.
    pub sha256: Digest,
}

/// A provider-level failure (the provider could not even report a status).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("tool provider failed: {0}")]
pub struct ToolError(pub String);

/// Per-invocation context (§4.5). `conformed` joins when `Conformed`
/// exists (H2); secrets handles join with §5.5 (H2).
#[derive(Debug, Clone, Copy)]
pub struct InvokeCtx {
    /// The loop step.
    pub step: u64,
    /// The per-call deadline.
    pub deadline: Instant,
}

/// A provider of capabilities (§4.5).
pub trait ToolProvider {
    /// The namespace this provider serves.
    fn namespace(&self) -> &ProviderName;

    /// Run one call. The only accepted call type is a policy-authorised call
    /// whose intent is durably journaled.
    fn invoke(
        &mut self,
        call: Journaled<Authorized<Call>>,
        ctx: &InvokeCtx,
    ) -> Result<ToolResult, ToolError>;
}
