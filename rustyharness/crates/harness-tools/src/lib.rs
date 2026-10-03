//! The provider half of the tool layer (design §4.5, §4.8): the
//! [`ToolProvider`] seam, which accepts only a `Journaled<Authorized<Call>>`
//! (a call policy allowed and whose intent is durably journaled, §2.2), the
//! built-in read tools (`harness.fs.read`, `harness.fs.search`,
//! `harness.fs.list`) and the built-in edit tools (`harness.edit.replace`,
//! `harness.edit.write`, over the edit engine of §4.9, D9; H2b), run in
//! process and confined to the workspace, and the command runner
//! (`harness.exec.run`, H2d), which starts every command through the
//! sandbox's `Confinement` seam under the run's `Conformed` witness. The
//! built-in providers share the `harness` namespace; each says which
//! capabilities it serves ([`ToolProvider::serves`]).
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
pub mod exec;
pub mod file_ops;
pub mod outline;
pub mod patch;
pub mod protected;
pub mod provider;
pub mod registry;
pub mod restore;
pub mod search;
pub mod todo;
pub mod web;
// The pure glob matcher (H2e, P-08) lives in `harness-core`; re-exported so
// `crate::glob::Glob` paths and the public `harness_tools::glob` keep working.
pub use builtin::{workspace_tree, ReadTools, WorkspaceTree};
pub use edit::{
    EditEngine, EditTools, MultiReq, ReadLog, Replacement, StaleRead, PRE_IMAGE_MAX_BYTES,
    PRE_IMAGE_STORE,
};
pub use exec::{
    plain_name, ExecLimits, ExecProgram, ExecSetupError, ExecSpec, ExecTools, Pinned, MAX_PROGRAMS,
};
pub use file_ops::{FileOps, InProcess};
pub use harness_core::glob;
pub use outline::OUTLINE_MAX_ENTRIES;
pub use patch::{PatchError, PatchTools, DELETE, MOVE, PATCH};
pub use provider::{
    EditRecord, ExecCleanup, ExecEnd, ExecRecord, Image, InvokeCtx, McpRecord, ReadRecord,
    RefusalKind, ToolError, ToolProvider, ToolResult, ToolStatus,
};
pub use restore::{recreate_file, restore_file, uncreate_file, RestoreError};
pub use todo::{TodoError, TodoItem, TodoList, TodoStatus};
pub use web::{
    BoxConnector, ConfinedHopRunner, Egress, FetcherPin, HopRun, HopRunner, RunnerError,
    WebBudgets, WebHop, WebRecord, WebSetupError, WebTools,
};
