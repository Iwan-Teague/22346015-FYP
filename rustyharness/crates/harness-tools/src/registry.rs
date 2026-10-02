//! The built-in dispatch table (P-02): one entry per capability the
//! compiled-in manifest declares, pairing the tool's id with how its
//! provider is built. The run driver still builds its providers directly
//! (three providers split the `harness` namespace by verb, H2b); this table
//! is the seam a new built-in registers at, so adding one is a table entry,
//! not a new dispatch site. Entries with run-owned state name that state
//! instead of a constructor: the command runner needs the run's witnesses
//! (H2d), and the checklist and the submit sentinel are run-loop state, not
//! providers at all.

use std::path::Path;

use crate::builtin::RootRefused;
use crate::provider::ToolProvider;
use crate::{EditTools, ReadTools};

/// A provider a dispatch entry builds, boxed for the run's provider list.
pub type BoxedProvider = Box<dyn ToolProvider>;

/// Build a provider over the workspace at `root`.
pub type BuildProvider = fn(&Path) -> Result<BoxedProvider, RootRefused>;

/// How a dispatch entry builds its provider.
pub enum ProviderCtor {
    /// Built from the workspace root alone (the read and edit tools).
    Workspace(BuildProvider),
    /// The command runner (§4.8, H2d): it also needs the run's witnesses
    /// (the pinned root, the sandbox and the conformed token), which the
    /// run driver owns.
    Exec,
    /// Run-loop state, not a provider: the checklist (H2e) and the submit
    /// sentinel (§2.5) are driven by the run loop.
    RunLoop,
}

/// One built-in dispatch entry: the capability id and how its provider is
/// built.
pub struct BuiltinTool {
    /// The capability id in the compiled-in manifest.
    pub id: &'static str,
    /// How the tool's provider is built.
    pub ctor: ProviderCtor,
}

fn read_tools(root: &Path) -> Result<BoxedProvider, RootRefused> {
    Ok(Box::new(ReadTools::new(root)?))
}

fn edit_tools(root: &Path) -> Result<BoxedProvider, RootRefused> {
    Ok(Box::new(EditTools::new(root)?))
}

/// The built-in tools, in manifest order: one entry per capability, the
/// single place a new built-in dispatches from (P-02).
pub const BUILTIN_TOOLS: &[BuiltinTool] = &[
    BuiltinTool {
        id: "harness.fs.read",
        ctor: ProviderCtor::Workspace(read_tools),
    },
    BuiltinTool {
        id: "harness.fs.search",
        ctor: ProviderCtor::Workspace(read_tools),
    },
    BuiltinTool {
        id: "harness.fs.glob",
        ctor: ProviderCtor::Workspace(read_tools),
    },
    BuiltinTool {
        id: "harness.fs.list",
        ctor: ProviderCtor::Workspace(read_tools),
    },
    BuiltinTool {
        id: "harness.fs.outline",
        ctor: ProviderCtor::Workspace(read_tools),
    },
    BuiltinTool {
        id: "harness.edit.replace",
        ctor: ProviderCtor::Workspace(edit_tools),
    },
    BuiltinTool {
        id: "harness.edit.write",
        ctor: ProviderCtor::Workspace(edit_tools),
    },
    BuiltinTool {
        id: "harness.edit.multi",
        ctor: ProviderCtor::Workspace(edit_tools),
    },
    BuiltinTool {
        id: "harness.exec.run",
        ctor: ProviderCtor::Exec,
    },
    BuiltinTool {
        id: "harness.task.todo",
        ctor: ProviderCtor::RunLoop,
    },
    BuiltinTool {
        id: "harness.task.submit",
        ctor: ProviderCtor::RunLoop,
    },
];

/// The dispatch entry for a built-in id, if any.
pub fn entry(id: &str) -> Option<&'static BuiltinTool> {
    BUILTIN_TOOLS.iter().find(|t| t.id == id)
}

/// Build the provider serving `id` over the workspace at `root`. `Ok(None)`
/// when the id is not a workspace-constructed tool (unknown, run-owned or
/// run-loop state); the caller decides what that means.
pub fn build(id: &str, root: &Path) -> Result<Option<BoxedProvider>, RootRefused> {
    match entry(id).map(|t| &t.ctor) {
        Some(ProviderCtor::Workspace(build_provider)) => build_provider(root).map(Some),
        Some(ProviderCtor::Exec) | Some(ProviderCtor::RunLoop) | None => Ok(None),
    }
}
