//! Planning a run: the pre-start checks ([`prepare`], shared with a
//! resume), the session and tool plan ([`plan`]), the loop's opening facts
//! and the checklist a session with the checklist grant starts with, and
//! the `runs/<run-id>` directory an attempt goes into.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use harness_core::RunId;
use harness_journal::layout;
use harness_manifest::admission::{Registry, Resolved};
use harness_model::context::{self, Fact, FactValue};
use harness_model::profile::Profile;
use harness_model::ToolSpec;
use harness_policy::locality::{self, LocalityProbe};
use harness_policy::{
    Matcher, PolicyDecision, Rule, Selector, Session, SessionSpec, UserPolicy, WorkspaceDecl,
    EXEC_ID, SUBMIT_ID, TODO_ID,
};
use harness_sandbox::{Confinement, Conformed};
use harness_tools::builtin::{workspace_tree, WorkspaceFacts, WorkspaceTree};
use harness_tools::protected::{Protected, ProtectedError, DEFAULT_ASK};
use harness_tools::{EditTools, ExecSpec, ExecTools, Pinned, ReadTools, TodoList, ToolProvider};

use super::{new_run_id, RunConfig, RunRefused, TaskSpec};
use crate::presubmit::PresubmitRefused;

/// What `prepare` established before anything was written.
pub(crate) struct Prepared {
    pub(crate) session: Session,
    pub(crate) tools: Vec<ToolSpec>,
    pub(crate) read_tools: ReadTools,
    pub(crate) edit_tools: EditTools,
    pub(crate) state_root: PathBuf,
    pub(crate) facts: WorkspaceFacts,
    /// The listing the facts were measured over, kept so the tree digest
    /// follows the run's own edits (H2b).
    pub(crate) tree: WorkspaceTree,
    /// For an exec grant (H2d): the pinned setup and the witness obtained
    /// before anything was written.
    pub(crate) exec: Option<(Pinned, Conformed)>,
    /// The merged protected-path deny sources (P-29): the build's
    /// [`DEFAULT_DENY`] plus the task's declared list, compiled.
    pub(crate) protected: Protected,
}

impl Prepared {
    /// The built-in providers: the read tools, the edit tools and, with an
    /// exec grant, the command runner, which share the `harness` namespace
    /// and split it by verb (H2b, H2d).
    pub(crate) fn providers<'p>(
        read: ReadTools,
        edit: EditTools,
        exec: Option<ExecTools<'p>>,
    ) -> Vec<Box<dyn ToolProvider + 'p>> {
        let mut v: Vec<Box<dyn ToolProvider + 'p>> = vec![Box::new(read), Box::new(edit)];
        if let Some(x) = exec {
            v.push(Box::new(x));
        }
        v
    }
}

/// The pre-start checks shared by `run` and `resume` (§2.1): plan the
/// session, open the workspace, canonicalise `state_root`, refuse an
/// overlap, check locality, measure the workspace facts.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare(
    spec: &TaskSpec,
    registry: &Registry,
    policy: &UserPolicy,
    profile: &Profile,
    workspace: &Path,
    state_root: &Path,
    probe: &dyn LocalityProbe,
    config: &RunConfig,
    approver_present: bool,
    confinement: Option<&dyn Confinement>,
) -> Result<Prepared, RunRefused> {
    // The exec grant and its setup agree, and the setup pins (H2d), before
    // the session is planned with the witness it will need.
    let pinned = exec_setup(spec)?;
    let (session, tools) = plan(
        spec,
        registry,
        policy,
        profile,
        approver_present,
        pinned.is_some(),
    )?;
    // The read window is the profile's (H2e): what a read returns, and what
    // the context shows of one observation.
    let window = profile.read_window();
    let read_tools = ReadTools::new(workspace)?
        .with_window(
            window.lines,
            usize::try_from(window.bytes).unwrap_or(usize::MAX),
        )
        // P-12: the policy's own deny globs for the surfacing read
        // tools (empty unless the policy names such rules), so search,
        // glob and list skip denied paths and say how many. A library
        // embedder passes an empty default policy and gets no skips
        // (OD-2); the CLI overlays its default deny list.
        .with_denied(policy.denied_globs());
    let edit_tools = EditTools::new(workspace)?.with_protected(
        Protected::new(&spec.protected)
            .map_err(|ProtectedError::Glob(m)| RunRefused::Protected(m))?,
    );
    let ws = read_tools.root().to_path_buf();
    let state_root = std::fs::canonicalize(state_root).map_err(RunRefused::StateRoot)?;
    if state_root.starts_with(&ws) || ws.starts_with(&state_root) {
        return Err(RunRefused::Overlap);
    }
    let state_str = state_root.to_str().ok_or_else(|| {
        RunRefused::StateRoot(io::Error::new(
            io::ErrorKind::InvalidInput,
            "state_root is not valid UTF-8",
        ))
    })?;
    locality::check(probe, state_str)?;
    let tree =
        workspace_tree(&ws, Instant::now() + config.facts_timeout).map_err(RunRefused::Facts)?;
    // INV-6: the witness, last, before anything is written; no confinement,
    // or a refusal, refuses the run (there is no unconfined fallback).
    let exec = match pinned {
        None => None,
        Some(p) => {
            let c = confinement.ok_or(RunRefused::ExecGrant(
                "harness.exec.run is granted but the run was given no confinement",
            ))?;
            Some((p, c.require().map_err(RunRefused::Confinement)?))
        }
    };
    Ok(Prepared {
        session,
        tools,
        read_tools,
        edit_tools,
        state_root,
        facts: tree.facts(),
        tree,
        exec,
        protected: Protected::new(&spec.protected)
            .map_err(|ProtectedError::Glob(m)| RunRefused::Protected(m))?,
    })
}

/// The capabilities the ask floor covers (P-29): every edit cap, the only
/// write path a model has today.
const EDIT_CAPS: [&str; 3] = [
    "harness.edit.replace",
    "harness.edit.write",
    "harness.edit.multi",
];

/// The P-29 ask floor: [`DEFAULT_ASK`] globs over every edit cap, appended
/// to the user's own ask rules. Runs against the returned policy, so a live
/// run, a resume and an audit replay all decide with the same floor; a
/// floor rule the user policy already states exactly is refused (fail
/// closed, not silently doubled).
pub(crate) fn protected_policy(user: &UserPolicy) -> Result<UserPolicy, RunRefused> {
    let refused = |what: &'static str| RunRefused::Protected(what);
    let mut p = user.clone();
    for glob in DEFAULT_ASK {
        for cap in EDIT_CAPS {
            let rule =
                Rule {
                    selector: Selector::parse(cap)
                        .map_err(|_| refused("an edit selector of this build is not a selector"))?,
                    matcher: Some(Matcher::path_glob(glob).map_err(|_| {
                        refused("a protected-path glob of this build is not a glob")
                    })?),
                };
            p.push_ask(rule).map_err(|_| {
                refused("the user policy already states a protected-path ask rule verbatim")
            })?;
        }
    }
    Ok(p)
}

/// The exec setup of a task (H2d): `None` without an exec grant; the pinned
/// setup with one. A grant without an exec section, or a section without
/// the grant, is refused.
pub(crate) fn exec_setup(spec: &TaskSpec) -> Result<Option<Pinned>, RunRefused> {
    let granted = spec.grants.iter().any(|g| g == EXEC_ID);
    match (granted, &spec.exec) {
        (false, None) => Ok(None),
        (true, None) => Err(RunRefused::ExecGrant(
            "harness.exec.run is granted but the task has no exec section (its allowlist)",
        )),
        (false, Some(_)) => Err(RunRefused::ExecGrant(
            "the task has an exec section but does not grant harness.exec.run",
        )),
        (true, Some(e)) => Ok(Some(Pinned::check(e)?)),
    }
}

/// The locality check run on each new attempt directory (§2.8).
pub(crate) fn attempt_check(
    probe: &dyn LocalityProbe,
) -> impl Fn(&Path) -> Result<(), String> + '_ {
    move |dir: &Path| {
        let s = dir
            .to_str()
            .ok_or_else(|| "the attempt directory is not valid UTF-8".to_owned())?;
        locality::check(probe, s)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// Context block 4 of a run: the measured facts, then those of the task's
/// pre-submit checks (H3a), when it has any.
pub(crate) fn loop_facts(f: &WorkspaceFacts, spec: &TaskSpec) -> Vec<Fact> {
    let mut facts = facts_block(f);
    if let Some(p) = &spec.presubmit {
        facts.extend(context::presubmit_facts(
            p.commands.len() as u64,
            u64::from(p.max_rounds),
        ));
    }
    facts
}

/// Context block 4 from the measured facts.
pub(crate) fn facts_block(f: &WorkspaceFacts) -> Vec<Fact> {
    vec![
        Fact {
            name: "workspace tree digest",
            value: FactValue::Digest(f.tree),
            method: "walk of the workspace in name order, symlinks not followed, sha256 of each file up to 64 MiB, size only above",
        },
        Fact {
            name: "workspace file count",
            value: FactValue::Count(f.files),
            method: "the same walk",
        },
        Fact {
            name: "workspace files over 64 MiB (size only)",
            value: FactValue::Count(f.oversize),
            method: "the same walk",
        },
    ]
}

/// Plan the session and the tool definitions (§2.1 "plan session").
/// `approver_present`: whether anyone answers an ask (§5.2: with nobody,
/// every ask is a deny). `conformed`: whether the run holds (or, in an
/// audit, held) a `Conformed` witness (H2d: an exec grant plans only with
/// one, INV-6).
pub(crate) fn plan(
    spec: &TaskSpec,
    registry: &Registry,
    policy: &UserPolicy,
    profile: &Profile,
    approver_present: bool,
    conformed: bool,
) -> Result<(Session, Vec<ToolSpec>), RunRefused> {
    let mut grants = spec.grants.clone();
    if !grants.iter().any(|g| g == SUBMIT_ID) {
        grants.push(SUBMIT_ID.to_owned());
    }
    // The P-29 ask floor (Cargo.lock, .github/**): decided with here, so a
    // live run, a resume and an audit replay all ask about the same edits.
    let policy = protected_policy(policy)?;
    let session = Session::plan(
        &SessionSpec {
            grants: grants.clone(),
            workspace: Some(WorkspaceDecl {
                declared_public: spec.workspace_public,
            }),
            approver_present,
            personal_data_granted: false,
            conformed,
            exec_programs: spec.exec.as_ref().map(ExecSpec::names).unwrap_or_default(),
            // The run's read window bounds a read's lines (H2e).
            read_window: Some(profile.read_window().lines),
        },
        registry,
        &policy,
    )?;
    // Pre-submit checks (H3a): bounded and on the allowlist, and none of them
    // denied by policy (a pure decision, the same the model's own command
    // would meet), or the run does not start.
    if let Some(p) = &spec.presubmit {
        p.check(&spec.grants, spec.exec.as_ref())?;
        for i in 0..p.commands.len() {
            let denied = p
                .call(i)
                .is_none_or(|c| matches!(session.decide(&c), PolicyDecision::Deny { .. }));
            if denied {
                return Err(PresubmitRefused::Denied(i + 1).into());
            }
        }
    }
    let mut tools = Vec::with_capacity(grants.len());
    for g in &grants {
        // Planning resolved every grant to exactly one capability.
        if let Resolved::One { capability, .. } = registry.resolve(g) {
            // The read tool as this run offers it: its window (H2e); then
            // the tool docs the profile asks for (P-53: a terse-docs
            // profile's one-sentence fixed table, argument names kept;
            // schema untouched).
            tools.push(
                ToolSpec::from_capability(capability)
                    .with_read_window(profile.read_window())
                    .with_tool_docs(profile.tool_docs()),
            );
        }
    }
    let max = profile.max_active_tools();
    if u32::try_from(tools.len()).map_or(true, |n| n > max) {
        return Err(RunRefused::TooManyTools {
            active: tools.len(),
            max,
        });
    }
    Ok((session, tools))
}

pub(crate) fn create_run(state_root: &Path) -> Result<(RunId, PathBuf), RunRefused> {
    let mut last = io::Error::other("no attempt");
    for _ in 0..3 {
        let id = new_run_id();
        match layout::create_run_dir(state_root, &id) {
            Ok(dir) => return Ok((id, dir)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = e,
            Err(e) => return Err(RunRefused::RunDir(e)),
        }
    }
    Err(RunRefused::RunDir(last))
}

/// The checklist of a session with these grants (H2e): an empty one when
/// `harness.task.todo` is granted, else none.
pub(crate) fn todo_for(grants: &[String]) -> Option<TodoList> {
    grants.iter().any(|g| g == TODO_ID).then(TodoList::default)
}
