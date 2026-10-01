//! The provider half of the tool layer (design §4.5, §4.8): the
//! [`ToolProvider`] seam, which accepts only a `Journaled<Authorized<Call>>`
//! (a call policy allowed and whose intent is durably journaled, §2.2), and
//! the built-in read tools (`harness.fs.read`, `harness.fs.search`,
//! `harness.fs.list`), run in process and confined to the workspace.
//!
//! The capability manifest (schema v1, validation, admission) is
//! `harness-manifest`; the scaffold's v0 manifest types that used to live
//! here are gone (v0 is refused there with a migration message).

#![forbid(unsafe_code)]
// The panic-set lints ratchet production code; unit tests may assert loosely.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

pub mod builtin;
pub mod provider;
pub use builtin::ReadTools;
pub use provider::{
    InvokeCtx, ReadRecord, RefusalKind, ToolError, ToolProvider, ToolResult, ToolStatus,
};
