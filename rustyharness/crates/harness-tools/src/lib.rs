//! The provider half of the tool layer (design §4.5, §4.8): the
//! [`ToolProvider`] seam, which accepts only a `Journaled<Authorized<Call>>`
//! (a call policy allowed and whose intent is durably journaled, §2.2), the
//! built-in read tools (`harness.fs.read`, `harness.fs.search`,
//! `harness.fs.list`) and the built-in edit tools (`harness.edit.replace`,
//! `harness.edit.write`, over the edit engine of §4.9, D9; H2b), all run in
//! process and confined to the workspace. The built-in providers share the
//! `harness` namespace; each says which capabilities it serves
//! ([`ToolProvider::serves`]).
//!
//! The capability manifest (schema v1, validation, admission) is
//! `harness-manifest`; the scaffold's v0 manifest types that used to live
//! here are gone (v0 is refused there with a migration message).

#![forbid(unsafe_code)]
// The panic-set lints ratchet production code; unit tests may assert loosely.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

pub mod builtin;
pub mod edit;
pub mod provider;
pub use builtin::{workspace_tree, ReadTools, WorkspaceTree};
pub use edit::{EditEngine, EditTools, ReadLog, StaleRead};
pub use provider::{
    EditRecord, InvokeCtx, ReadRecord, RefusalKind, ToolError, ToolProvider, ToolResult, ToolStatus,
};
