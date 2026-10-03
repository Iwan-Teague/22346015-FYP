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
/// since H2e; the patch script and the delete/move file operations since
/// P-25). The first three are the confirmation-`none` edit class; the last
/// three are [`FILEOP_IDS`], which declare `user_confirm` and so always ask
/// (§5.2's confirmation floor) — a user allow rule cannot reach them.
pub const EDIT_IDS: [&str; 6] = [
    "harness.edit.replace",
    "harness.edit.write",
    "harness.edit.multi",
    "harness.edit.patch",
    "harness.edit.delete",
    "harness.edit.move",
];

/// The P-25 file operations, the `EDIT_IDS` members whose manifest
/// confirmation is `user_confirm`: `harness.edit.delete` and
/// `harness.edit.move`.
pub const FILEOP_IDS: [&str; 2] = ["harness.edit.delete", "harness.edit.move"];

/// The rule id of the built-in edits' default decision in this build (§5.2,
/// H2b): an ask, since the workspace is edited in place.
pub const EDIT_DEFAULT_RULE: &str = "ask.edit.in-place";

/// Whether `c` is a built-in workspace edit with exactly the labels §4.8
/// gives it (write / operational / own / none, content own, no declared
/// confirmation). Anything else under those ids would not be the harness's
/// edit tool, and its write class is then out of scope like any other.
/// Only the confirmation-`none` edits pass; the file operations'
/// `user_confirm` keeps them out of here and in [`is_builtin_fileop`].
pub(crate) fn is_builtin_edit(c: &Capability) -> bool {
    EDIT_IDS.contains(&c.id().as_str())
        && !FILEOP_IDS.contains(&c.id().as_str())
        && c.id().provider() == BUILTIN_NAMESPACE
        && c.effect() == Effect::Write
        && c.sensitivity() == Sensitivity::Operational
        && c.blast_radius() == BlastRadius::Own
        && c.egress() == Egress::None
        && c.content() == Content::Own
        && c.confirmation() == Confirmation::None
}

/// Whether `c` is a built-in P-25 file operation with exactly the labels
/// §4.8 gives the edits, except the declared confirmation: `user_confirm`,
/// which policy's floor turns into an ask no matter what the user's rules
/// say (§5.2). Anything else under those ids is out of scope like any
/// provider's.
pub(crate) fn is_builtin_fileop(c: &Capability) -> bool {
    FILEOP_IDS.contains(&c.id().as_str())
        && c.id().provider() == BUILTIN_NAMESPACE
        && c.effect() == Effect::Write
        && c.sensitivity() == Sensitivity::Operational
        && c.blast_radius() == BlastRadius::Own
        && c.egress() == Egress::None
        && c.content() == Content::Own
        && c.confirmation() == Confirmation::UserConfirm
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

/// The built-in plan sentinel (P-28, §5.4): the planning mode's one way to
/// hand work back — the model submits its plan (a summary, the files it
/// names, its steps) and the turn ends so the user can read it. Like the
/// checklist and the sentinel, it touches nothing outside the run: the
/// paths it lists are text for the user, not arguments anything runs.
pub const PLAN_SUBMIT_ID: &str = "harness.plan.submit";

/// The rule that allows the plan sentinel (P-28), after every deny rule
/// and the schema, like the checklist's.
pub const PLAN_SUBMIT_RULE: &str = "allow.plan-submit";

/// The rule that allows an edit call on a file the approved plan names
/// (P-28, §5.4): the ask the edit would otherwise take was answered when
/// the user approved the plan.
pub const PLAN_ALLOW_RULE: &str = "plan.allow";

/// Whether `c` is the built-in plan sentinel with exactly the labels the
/// manifest gives it — the checklist's row (write / public / own / none,
/// content own, no declared confirmation). Anything else under that id
/// would not be the harness's plan sentinel, and its write class is then
/// out of scope.
pub(crate) fn is_builtin_plan_submit(c: &Capability) -> bool {
    c.id().as_str() == PLAN_SUBMIT_ID
        && c.id().provider() == BUILTIN_NAMESPACE
        && c.effect() == Effect::Write
        && c.sensitivity() == Sensitivity::Public
        && c.blast_radius() == BlastRadius::Own
        && c.egress() == Egress::None
        && c.content() == Content::Own
        && c.confirmation() == Confirmation::None
}

/// Whether `id` is one of the tools a plan-mode session keeps active
/// (P-28): the read-class fs tools, the checklist and the plan sentinel.
/// The loop filters its declared tool list with this, so a plan-mode
/// request names no edit or exec tool; `decide` refuses the rest by the
/// ordinary not-granted path.
pub fn is_plan_tool_id(id: &str) -> bool {
    matches!(
        id,
        READ_ID | SEARCH_ID | GLOB_ID | LIST_ID | OUTLINE_ID | TODO_ID | PLAN_SUBMIT_ID
    )
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

/// The built-in fetch tool (§2.3, P-39b): one URL from the session's
/// allowlist, in the research manifest only.
pub const WEB_FETCH_ID: &str = "harness.web.fetch";

/// The built-in web search tool (§2.3, P-39b): the session's configured
/// search endpoint, in the research manifest only.
pub const WEB_SEARCH_ID: &str = "harness.web.search";

/// The rule that allows a fetch whose URL is exactly on the session's
/// allowlist (§2.3).
pub const WEB_ALLOWLIST_RULE: &str = "allow.web.session-allowlist";

/// The rule that allows a search against the session's configured endpoint
/// (§2.3).
pub const WEB_SEARCH_RULE: &str = "allow.web.search-endpoint";

/// Whether `c` is one of the two built-in web tools with exactly the labels
/// §2.3 gives them (read / operational / own / internet, content
/// `third_party`, no declared confirmation). Anything else under those ids
/// would not be the harness's web tool, and its egress class is then out of
/// scope like any provider's.
fn is_builtin_web(c: &Capability, id: &str) -> bool {
    c.id().as_str() == id
        && c.id().provider() == BUILTIN_NAMESPACE
        && c.effect() == Effect::Read
        && c.sensitivity() == Sensitivity::Operational
        && c.blast_radius() == BlastRadius::Own
        && c.egress() == Egress::Internet
        && c.content() == Content::ThirdParty
        && c.confirmation() == Confirmation::None
}

/// Whether `c` is the built-in fetch tool with exactly the §2.3 labels.
pub(crate) fn is_builtin_web_fetch(c: &Capability) -> bool {
    is_builtin_web(c, WEB_FETCH_ID)
}

/// Whether `c` is the built-in search tool with exactly the §2.3 labels.
pub(crate) fn is_builtin_web_search(c: &Capability) -> bool {
    is_builtin_web(c, WEB_SEARCH_ID)
}

/// Whether `id` is one of the two web tool ids (§2.3). Only a research
/// session can hold one; a coding session granting one is refused (§2.2).
pub(crate) fn is_web_id(id: &str) -> bool {
    matches!(id, WEB_FETCH_ID | WEB_SEARCH_ID)
}

/// Whether `id` is one of the four capabilities the research manifest
/// declares (§2.2): the web tools plus the checklist and the submit
/// sentinel. A research session grants nothing else.
pub(crate) fn is_research_id(id: &str) -> bool {
    matches!(id, WEB_FETCH_ID | WEB_SEARCH_ID | TODO_ID | SUBMIT_ID)
}

/// The rule id of the command runner's default decision in this build
/// (H2d): an ask, like the edits (the workspace is changed in place, with no
/// snapshot to undo a command).
pub const EXEC_DEFAULT_RULE: &str = "ask.exec.default";

/// The rule id of an mcp-stdio capability's default decision in this build
/// (P-37b, §6.3): the pinned tier's derived `user_confirm` floor. The
/// capability asks by default; a user allow rule (consulted first) allows it
/// unattended, and with no approver present the ask is a deny (§5.2).
pub const MCP_DEFAULT_RULE: &str = "ask.mcp.pinned";

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

/// The background starter's id (P-36g, §3): starts one allowed program in
/// the background. Only the compiled-in `harness` manifest can declare it.
pub const EXEC_START_ID: &str = "harness.exec.start";

/// The background reader's id (P-36g, §3): reads one background process's
/// output without blocking.
pub const EXEC_READ_ID: &str = "harness.exec.read";

/// The background stopper's id (P-36g, §3): stops one background process.
pub const EXEC_STOP_ID: &str = "harness.exec.stop";

/// The rule that allows a background read (§9): like the fs reads, a plain
/// allow — the process is the run's own.
pub const BG_READ_RULE: &str = "allow.exec.bg-read";

/// The rule that allows a background stop (§9): the run stops what it
/// started.
pub const BG_STOP_RULE: &str = "allow.exec.bg-stop";

/// The floor rule behind every `harness.exec.start` naming a LAN port
/// (§6.3): a protected action, asked every time, never covered by a session
/// grant or lowered by a user allow rule.
pub const LAN_BIND_RULE: &str = "ask.exec.lan-bind";

/// Whether `c` is the built-in background starter with exactly the labels
/// §9 gives it: the runner's labels (execute / operational / own / none,
/// `content: third_party`, no declared confirmation). The capability stays
/// `egress: none` even though a LAN port grant binds a socket — the egress
/// label rides the task's `lan_ports` (§6.3), not the tool.
pub(crate) fn is_builtin_exec_start(c: &Capability) -> bool {
    c.id().as_str() == EXEC_START_ID
        && c.id().provider() == BUILTIN_NAMESPACE
        && c.effect() == Effect::Execute
        && c.sensitivity() == Sensitivity::Operational
        && c.blast_radius() == BlastRadius::Own
        && c.egress() == Egress::None
        && c.content() == Content::ThirdParty
        && c.confirmation() == Confirmation::None
}

/// Whether `c` is the built-in background reader with exactly the labels
/// §9 gives it (read / operational / own / none, `content: third_party`,
/// no declared confirmation).
pub(crate) fn is_builtin_exec_read(c: &Capability) -> bool {
    c.id().as_str() == EXEC_READ_ID
        && c.id().provider() == BUILTIN_NAMESPACE
        && c.effect() == Effect::Read
        && c.sensitivity() == Sensitivity::Operational
        && c.blast_radius() == BlastRadius::Own
        && c.egress() == Egress::None
        && c.content() == Content::ThirdParty
        && c.confirmation() == Confirmation::None
}

/// Whether `c` is the built-in background stopper with exactly the labels
/// §9 gives it (write / operational / own / none, `content: own` — its
/// result is the harness's own report of the stop).
pub(crate) fn is_builtin_exec_stop(c: &Capability) -> bool {
    c.id().as_str() == EXEC_STOP_ID
        && c.id().provider() == BUILTIN_NAMESPACE
        && c.effect() == Effect::Write
        && c.sensitivity() == Sensitivity::Operational
        && c.blast_radius() == BlastRadius::Own
        && c.egress() == Egress::None
        && c.content() == Content::Own
        && c.confirmation() == Confirmation::None
}

/// Whether `id` is one of the three background tools (§3): they exist only
/// when the task grants them and holds an exec setup. Planning (the run
/// crate) uses this on the task's grant list.
pub fn is_bg_id(id: &str) -> bool {
    matches!(id, EXEC_START_ID | EXEC_READ_ID | EXEC_STOP_ID)
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
    /// The plan sentinel (P-28): records the submitted plan and ends the
    /// turn; touches nothing in or outside the workspace.
    PlanSubmit,
    /// The delegate capability (P-38): one call starts one read-only
    /// helper run.
    Delegate,
    /// A workspace edit (§4.9, H2b).
    Edit,
    /// The command runner (§4.8, H2d).
    Exec,
    /// A background tool (P-36g, §3): start, read or stop, all operating
    /// inside the workspace and only with an exec setup held.
    ExecBg,
    /// A web airlock tool (§2.3, P-39b): needs no workspace; a session
    /// holding one must be a research session.
    Web,
}

impl ToolKind {
    /// Whether the tool operates inside the workspace, so a session
    /// granting it is refused without one (§4.8; formerly the prefix, list
    /// and id checks in [`Session::plan`]). The delegate needs one too: a
    /// helper with nothing to read is waste (P-38 §1).
    pub fn needs_workspace(self) -> bool {
        matches!(
            self,
            ToolKind::Fs | ToolKind::Edit | ToolKind::Exec | ToolKind::ExecBg | ToolKind::Delegate
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
        id: "harness.edit.patch",
        kind: ToolKind::Edit,
        labels: is_builtin_edit,
    },
    BuiltinTool {
        id: "harness.edit.delete",
        kind: ToolKind::Edit,
        labels: is_builtin_fileop,
    },
    BuiltinTool {
        id: "harness.edit.move",
        kind: ToolKind::Edit,
        labels: is_builtin_fileop,
    },
    BuiltinTool {
        id: "harness.exec.run",
        kind: ToolKind::Exec,
        labels: is_builtin_exec,
    },
    // The background tools (P-36g, §3) extend the runner: start, read and
    // stop, in manifest order.
    BuiltinTool {
        id: EXEC_START_ID,
        kind: ToolKind::ExecBg,
        labels: is_builtin_exec_start,
    },
    BuiltinTool {
        id: EXEC_READ_ID,
        kind: ToolKind::ExecBg,
        labels: is_builtin_exec_read,
    },
    BuiltinTool {
        id: EXEC_STOP_ID,
        kind: ToolKind::ExecBg,
        labels: is_builtin_exec_stop,
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
    // The plan sentinel (P-28, §5.4) sits with the other task tools, in
    // manifest order (between the delegate and the submit sentinel): it
    // records the submitted plan and ends the turn, so it needs no
    // workspace, and it is not a research id (a research session has no
    // plan to build).
    BuiltinTool {
        id: PLAN_SUBMIT_ID,
        kind: ToolKind::PlanSubmit,
        labels: is_builtin_plan_submit,
    },
    BuiltinTool {
        id: "harness.task.submit",
        kind: ToolKind::Submit,
        labels: is_submit_sentinel,
    },
    // The web airlock (P-39b, §2.3) lives only in the research manifest; the
    // entries sit here so registration, and with it every planning check,
    // consults one table. Appending them changes no coding-session decision
    // (pinned by `tests::policy_default_table_unchanged`).
    BuiltinTool {
        id: WEB_FETCH_ID,
        kind: ToolKind::Web,
        labels: is_builtin_web_fetch,
    },
    BuiltinTool {
        id: WEB_SEARCH_ID,
        kind: ToolKind::Web,
        labels: is_builtin_web_search,
    },
];

/// The registration entry for a built-in id, if any.
pub fn registration(id: &str) -> Option<&'static BuiltinTool> {
    BUILTIN_TOOLS.iter().find(|t| t.id == id)
}
