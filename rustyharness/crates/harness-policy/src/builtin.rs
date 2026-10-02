//! The built-in tools' registration table (P-02): one entry per capability
//! the compiled-in manifest declares, with the tool's kind, its id and rule
//! constants, and the §4.8 labels predicate that decides whether a
//! capability under that id really is this tool. Planning consults this
//! table by id where it used scattered prefix and list checks; the
//! equivalence is exact because the `harness` namespace is reserved (§4.3):
//! the compiled-in manifest is the only manifest that may use it, so the
//! only `harness.*` ids planning can ever see are the ones in
//! [`BUILTIN_TOOLS`].

use harness_manifest::{
    BlastRadius, Capability, Confirmation, Content, Effect, Egress, Sensitivity, BUILTIN_NAMESPACE,
};

/// The `harness.fs.*` id prefix (§4.8): the built-in read tools, recognized
/// by id because policy needs nothing but their read class.
pub(crate) const FS_PREFIX: &str = "harness.fs.";

/// The built-in read tool, whose `lines` the run's read window bounds.
pub const READ_ID: &str = "harness.fs.read";

/// The built-in workspace search tool (§4.8).
pub const SEARCH_ID: &str = "harness.fs.search";

/// The built-in glob tool (§4.8).
pub const GLOB_ID: &str = "harness.fs.glob";

/// The built-in list tool (§4.8).
pub const LIST_ID: &str = "harness.fs.list";

/// The built-in outline tool (P-24): repo-map-lite symbol extraction, in
/// the read class like the other `harness.fs.*` tools.
pub const OUTLINE_ID: &str = "harness.fs.outline";

/// The submit sentinel's id (§2.5, §4.8). Only the compiled-in `harness`
/// manifest can declare it (the namespace is reserved, §4.3).
pub const SUBMIT_ID: &str = "harness.task.submit";

/// The delegate capability's id (P-38): one call starts one read-only
/// helper run. Only the compiled-in `harness` manifest can declare it.
pub const DELEGATE_ID: &str = "harness.task.delegate";

/// Whether `c` is the built-in submit sentinel with exactly the labels §4.8
/// gives it (write / public / own / none, content own, no confirmation). A
/// manifest that labelled it anything else would not be the sentinel, and
/// its write class is then out of scope like any other.
pub(crate) fn is_submit_sentinel(c: &Capability) -> bool {
    c.id().as_str() == SUBMIT_ID
        && c.id().provider() == BUILTIN_NAMESPACE
        && c.effect() == Effect::Write
        && c.sensitivity() == Sensitivity::Public
        && c.blast_radius() == BlastRadius::Own
        && c.egress() == Egress::None
        && c.content() == Content::Own
        && c.confirmation() == Confirmation::None
}

/// The built-in workspace edit tools (§4.8, §4.9; H2b; `harness.edit.multi`
/// since H2e).
pub const EDIT_IDS: [&str; 3] = [
    "harness.edit.replace",
    "harness.edit.write",
    "harness.edit.multi",
];

/// The rule id of the built-in edits' default decision in this build (§5.2,
/// H2b): an ask, since the workspace is edited in place.
pub const EDIT_DEFAULT_RULE: &str = "ask.edit.in-place";

/// Whether `c` is a built-in workspace edit with exactly the labels §4.8
/// gives it (write / operational / own / none, content own, no declared
/// confirmation). Anything else under those ids would not be the harness's
/// edit tool, and its write class is then out of scope like any other.
pub(crate) fn is_builtin_edit(c: &Capability) -> bool {
    EDIT_IDS.contains(&c.id().as_str())
        && c.id().provider() == BUILTIN_NAMESPACE
        && c.effect() == Effect::Write
        && c.sensitivity() == Sensitivity::Operational
        && c.blast_radius() == BlastRadius::Own
        && c.egress() == Egress::None
        && c.content() == Content::Own
        && c.confirmation() == Confirmation::None
}

/// The built-in checklist (H2e): the model's own list of steps, kept in the
/// run's state and echoed in its result. It touches nothing outside the run.
pub const TODO_ID: &str = "harness.task.todo";

/// The rule that allows the checklist (H2e), after every deny rule and the
/// schema, like the sentinel's.
pub const TODO_RULE: &str = "allow.task-todo";

/// Whether `c` is the built-in checklist with exactly the labels the
/// manifest gives it (write / public / own / none, content own, no declared
/// confirmation), like the sentinel. Anything else under that id would not
/// be the harness's checklist, and its write class is then out of scope.
pub(crate) fn is_builtin_todo(c: &Capability) -> bool {
    c.id().as_str() == TODO_ID
        && c.id().provider() == BUILTIN_NAMESPACE
        && c.effect() == Effect::Write
        && c.sensitivity() == Sensitivity::Public
        && c.blast_radius() == BlastRadius::Own
        && c.egress() == Egress::None
        && c.content() == Content::Own
        && c.confirmation() == Confirmation::None
}

/// Whether `c` is the built-in delegate (P-38) with exactly the labels the
/// manifest gives it: read / operational / own / none, `content:
/// third_party` (the helper's report is other people's text by default,
/// like the read tools' results) and no declared confirmation. Anything
/// else under that id would not be the harness's delegate.
pub(crate) fn is_builtin_delegate(c: &Capability) -> bool {
    c.id().as_str() == DELEGATE_ID
        && c.id().provider() == BUILTIN_NAMESPACE
        && c.effect() == Effect::Read
        && c.sensitivity() == Sensitivity::Operational
        && c.blast_radius() == BlastRadius::Own
        && c.egress() == Egress::None
        && c.content() == Content::ThirdParty
        && c.confirmation() == Confirmation::None
}

/// The grants a helper run may hold, in the fixed priority order the
/// profile's tool cap cuts them in (P-38 §2.2): the parent's own `harness.fs.*`
/// reads, never more than the parent holds; the caller appends the submit
/// sentinel. Nothing else (no edit, no exec, no todo, no delegate) is
/// eligible, which is how the depth limit binds at grant time.
pub const CHILD_ELIGIBLE: [&str; 5] = [READ_ID, SEARCH_ID, LIST_ID, GLOB_ID, OUTLINE_ID];

/// The built-in command runner (§4.8; H2d).
pub const EXEC_ID: &str = "harness.exec.run";

/// The rule id of the command runner's default decision in this build
/// (H2d): an ask, like the edits (the workspace is changed in place, with no
/// snapshot to undo a command).
pub const EXEC_DEFAULT_RULE: &str = "ask.exec.default";

/// Whether `c` is the built-in command runner with exactly the labels §4.8
/// gives it (execute / operational / own / none), `content: third_party`
/// and no declared confirmation.
pub(crate) fn is_builtin_exec(c: &Capability) -> bool {
    c.id().as_str() == EXEC_ID
        && c.id().provider() == BUILTIN_NAMESPACE
        && c.effect() == Effect::Execute
        && c.sensitivity() == Sensitivity::Operational
        && c.blast_radius() == BlastRadius::Own
        && c.egress() == Egress::None
        && c.content() == Content::ThirdParty
        && c.confirmation() == Confirmation::None
}

/// What kind of built-in tool a registration entry declares. Drives the
/// planning refusals that used to be scattered id checks: which tools
/// operate inside the workspace, and which are recognized by labels rather
/// than by id alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolKind {
    /// A built-in read tool (`harness.fs.*`): recognized by id, so it
    /// carries no label predicate; a non-read class under an fs id is out
    /// of scope like any provider's.
    Fs,
    /// The submit sentinel (§2.5).
    Submit,
    /// The checklist (H2e).
    Todo,
    /// The delegate capability (P-38): one call starts one read-only
    /// helper run.
    Delegate,
    /// A workspace edit (§4.9, H2b).
    Edit,
    /// The command runner (§4.8, H2d).
    Exec,
}

impl ToolKind {
    /// Whether the tool operates inside the workspace, so a session
    /// granting it is refused without one (§4.8; formerly the prefix, list
    /// and id checks in [`Session::plan`]). The delegate needs one too: a
    /// helper with nothing to read is waste (P-38 §1).
    pub fn needs_workspace(self) -> bool {
        matches!(
            self,
            ToolKind::Fs | ToolKind::Edit | ToolKind::Exec | ToolKind::Delegate
        )
    }
}

/// One built-in tool's registration: its manifest id, its kind, and the
/// labels predicate deciding whether a capability under that id really is
/// this tool (§4.8's exact labels), which keeps an out-of-scope class
/// refused like any provider's.
pub struct BuiltinTool {
    /// The capability id in the compiled-in manifest.
    pub id: &'static str,
    /// The tool's kind.
    pub kind: ToolKind,
    /// Whether `c` is this tool with exactly its declared labels.
    pub labels: fn(&Capability) -> bool,
}

/// The fs tools carry no label predicate: they are recognized by id, and
/// their read class is all policy needs (§4.8).
fn no_labels(_: &Capability) -> bool {
    false
}

/// The built-in tools, in manifest order: one entry per capability, the
/// single place a new built-in registers (P-02).
pub const BUILTIN_TOOLS: &[BuiltinTool] = &[
    BuiltinTool {
        id: "harness.fs.read",
        kind: ToolKind::Fs,
        labels: no_labels,
    },
    BuiltinTool {
        id: "harness.fs.search",
        kind: ToolKind::Fs,
        labels: no_labels,
    },
    BuiltinTool {
        id: "harness.fs.glob",
        kind: ToolKind::Fs,
        labels: no_labels,
    },
    BuiltinTool {
        id: "harness.fs.list",
        kind: ToolKind::Fs,
        labels: no_labels,
    },
    BuiltinTool {
        id: "harness.fs.outline",
        kind: ToolKind::Fs,
        labels: no_labels,
    },
    BuiltinTool {
        id: "harness.edit.replace",
        kind: ToolKind::Edit,
        labels: is_builtin_edit,
    },
    BuiltinTool {
        id: "harness.edit.write",
        kind: ToolKind::Edit,
        labels: is_builtin_edit,
    },
    BuiltinTool {
        id: "harness.edit.multi",
        kind: ToolKind::Edit,
        labels: is_builtin_edit,
    },
    BuiltinTool {
        id: "harness.exec.run",
        kind: ToolKind::Exec,
        labels: is_builtin_exec,
    },
    BuiltinTool {
        id: "harness.task.todo",
        kind: ToolKind::Todo,
        labels: is_builtin_todo,
    },
    BuiltinTool {
        id: "harness.task.delegate",
        kind: ToolKind::Delegate,
        labels: is_builtin_delegate,
    },
    BuiltinTool {
        id: "harness.task.submit",
        kind: ToolKind::Submit,
        labels: is_submit_sentinel,
    },
];

/// The registration entry for a built-in id, if any.
pub fn registration(id: &str) -> Option<&'static BuiltinTool> {
    BUILTIN_TOOLS.iter().find(|t| t.id == id)
}
