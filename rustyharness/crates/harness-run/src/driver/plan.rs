//! Planning a run: the pre-start checks ([`prepare`], shared with a
//! resume), the session and tool plan ([`plan`]), the loop's opening facts
//! and the checklist a session with the checklist grant starts with, and
//! the `runs/<run-id>` directory an attempt goes into.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use harness_core::{sha256, RunId};
use harness_journal::layout;
use harness_manifest::admission::{Registry, Resolved};
use harness_manifest::Sensitivity;
use harness_model::context::{self, Fact, FactValue};
use harness_model::profile::Profile;
use harness_model::{EndpointClass, ToolSpec};
use harness_policy::locality::{self, LocalityProbe};
use harness_policy::{
    is_bg_id, Matcher, PolicyDecision, Rule, Selector, Session, SessionKind, SessionMode,
    SessionSpec, UserPolicy, WorkspaceDecl, DELEGATE_ID, EXEC_ID, EXEC_START_ID, PLAN_SUBMIT_ID,
    SUBMIT_ID, TODO_ID, WEB_FETCH_ID, WEB_SEARCH_ID,
};
use harness_sandbox::{Confinement, Conformed, PortsWitness};
use harness_tools::builtin::{workspace_tree, WorkspaceFacts, WorkspaceTree};
use harness_tools::protected::{Protected, ProtectedError, DEFAULT_ASK};
use harness_tools::{
    EditTools, ExecSpec, ExecTools, PatchTools, Pinned, ReadTools, TodoList, ToolProvider,
};

use super::{new_run_id, RunConfig, RunRefused, TaskSpec, PORTS_PER_TASK};
use crate::delegate;
use crate::postedit::PostEditRefused;
use crate::presubmit::PresubmitRefused;

/// What `prepare` established before anything was written.
pub(crate) struct Prepared {
    pub(crate) session: Session,
    pub(crate) tools: Vec<ToolSpec>,
    /// None for a research session (P-39i): no workspace, no file tools.
    pub(crate) read_tools: Option<ReadTools>,
    pub(crate) edit_tools: Option<EditTools>,
    pub(crate) patch_tools: Option<PatchTools>,
    pub(crate) state_root: PathBuf,
    /// The facts of the workspace (a coding run's measured walk) or, for a
    /// research session, [`no_workspace_facts`] — present either way, so a
    /// header and the turn records keep their fact fields.
    pub(crate) facts: WorkspaceFacts,
    /// The listing the facts were measured over, kept so the tree digest
    /// follows the run's own edits (H2b). None for a research session: no
    /// workspace, so the loop's tree stays the digest of nothing.
    pub(crate) tree: Option<WorkspaceTree>,
    /// For an exec grant (H2d): the pinned setup and the witness obtained
    /// before anything was written. None for a research session (P-39i: it
    /// grants no exec).
    pub(crate) exec: Option<(Pinned, Conformed)>,
    /// For a port grant (P-36g §6.1): the ports witness, probed before
    /// anything was written; `Some` exactly when the task holds ports.
    pub(crate) ports: Option<PortsWitness>,
    /// The merged protected-path deny sources (P-29): the build's
    /// [`DEFAULT_DENY`] plus the task's declared list, compiled. Empty for
    /// a research session (P-39i: no workspace, no protected paths).
    pub(crate) protected: Protected,
}

impl Prepared {
    /// The built-in providers: the read tools, the edit tools, the P-25
    /// patch/delete/move provider and, with an exec grant, the command
    /// runner, which share the `harness` namespace and split it by verb
    /// (H2b, H2d, P-25). A research session (P-39i) carries none of them
    /// (no workspace, no exec), so its providers are empty: the task tools
    /// it grants are the loop's own, not provider-served.
    pub(crate) fn providers<'p>(
        read: Option<ReadTools>,
        edit: Option<EditTools>,
        patch: Option<PatchTools>,
        exec: Option<ExecTools<'p>>,
    ) -> Vec<Box<dyn ToolProvider + 'p>> {
        let mut v: Vec<Box<dyn ToolProvider + 'p>> = Vec::new();
        if let Some(r) = read {
            v.push(Box::new(r));
        }
        if let Some(e) = edit {
            v.push(Box::new(e));
        }
        if let Some(p) = patch {
            v.push(Box::new(p));
        }
        if let Some(x) = exec {
            v.push(Box::new(x));
        }
        v
    }
}

/// The pre-start checks shared by `run`, `run_research` and `resume` (§2.1,
/// P-39i): plan the session; for a coding run, open the workspace,
/// canonicalise `state_root`, refuse an overlap, check locality, measure the
/// workspace facts; for a research session, refuse a workspace and require
/// the web airlock's witness (§2.4, INV-42).
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare(
    spec: &TaskSpec,
    registry: &Registry,
    policy: &UserPolicy,
    profile: &Profile,
    workspace: Option<&Path>,
    state_root: &Path,
    probe: &dyn LocalityProbe,
    config: &RunConfig,
    approver_present: bool,
    confinement: Option<&dyn Confinement>,
    endpoint: EndpointClass,
) -> Result<Prepared, RunRefused> {
    // P-38, fail closed, before anything runs: a task that may delegate
    // (harness.task.delegate) must hold at least one harness.fs.* grant —
    // it is the only way it can answer the child's question — and its
    // profile's context budget must fit the child floor. A profile under
    // [`CHILD_MIN_BUDGET_TOKENS`] cannot host a useful read-only helper,
    // so delegation refuses rather than degrade.
    if spec.grants.iter().any(|g| g == DELEGATE_ID) {
        if !spec.grants.iter().any(|g| g.starts_with("harness.fs.")) {
            return Err(RunRefused::Delegate(delegate::REFUSAL_NO_FS));
        }
        if context::budget_tokens(profile) < delegate::CHILD_MIN_BUDGET_TOKENS {
            return Err(RunRefused::Delegate(delegate::REFUSAL_TINY));
        }
    }
    match &spec.kind {
        SessionKind::Research(_) => {
            if workspace.is_some() {
                return Err(RunRefused::Research(
                    "a research session takes no workspace",
                ));
            }
            // P-39i research checks (fail closed): web ids (P-39j wires
            // them), exec, pre-submit, protected paths, a workspace.
            check_research_spec(spec)?;
            let (session, tools) = plan(
                spec,
                registry,
                policy,
                profile,
                approver_present,
                true,
                true,
            )?;
            let state_root = std::fs::canonicalize(state_root).map_err(RunRefused::StateRoot)?;
            let state_str = state_root.to_str().ok_or_else(|| {
                RunRefused::StateRoot(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "state_root is not valid UTF-8",
                ))
            })?;
            locality::check(probe, state_str)?;
            // INV-42: the witness, last, before anything is written; no
            // confinement or a refusal refuses the session (no unconfined
            // fallback). §5.3/INV-46: a session that may fetch demands the
            // witness cover the web airlock's cases — the proxy profile is
            // part of the fetch path, not of plain execution. This slice
            // grants no web capability (`check_research_spec` refused
            // them), so the demand is armed but unreachable; it goes live
            // the moment P-39j makes web ids grantable.
            let c = confinement.ok_or(RunRefused::Research(
                "a research session runs behind the web airlock and was given no confinement",
            ))?;
            let witness = c.require().map_err(RunRefused::Confinement)?;
            if spec
                .grants
                .iter()
                .any(|g| g == WEB_FETCH_ID || g == WEB_SEARCH_ID)
            {
                witness
                    .covers(harness_sandbox::conformance::AIRLOCK_CASES)
                    .map_err(|_missing| {
                        RunRefused::Research(
                            "the sandbox witness does not cover the web airlock's cases",
                        )
                    })?;
            }
            Ok(Prepared {
                session,
                tools,
                read_tools: None,
                edit_tools: None,
                patch_tools: None,
                state_root,
                facts: no_workspace_facts(),
                tree: None,
                exec: None,
                ports: None,
                protected: Protected::new(&[])
                    .map_err(|ProtectedError::Glob(m)| RunRefused::Protected(m))?,
            })
        }
        SessionKind::Coding => {
            let Some(workspace) = workspace else {
                return Err(RunRefused::Facts(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a coding run needs a workspace",
                )));
            };
            // The exec grant and its setup agree, and the setup pins (H2d),
            // before the session is planned with the witness it will need.
            // P-36g: the background tools ride the exec setup, and a port
            // grant needs `harness.exec.start`; then the port list itself is
            // checked, and the model's own ports are known.
            let pinned = exec_setup(spec)?;
            check_ports(spec, config, endpoint)?;
            let (session, tools) = plan(
                spec,
                registry,
                policy,
                profile,
                approver_present,
                pinned.is_some(),
                true,
            )?;
            // The read window is the profile's (H2e): what a read returns,
            // and what the context shows of one observation.
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
            let patch_tools = PatchTools::new(workspace)?.with_protected(
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
            let tree = workspace_tree(workspace, Instant::now() + config.facts_timeout)
                .map_err(RunRefused::Facts)?;
            // INV-6: the witness, last, before anything is written; no
            // confinement, or a refusal, refuses the run (there is no
            // unconfined fallback). A port grant (P-36g §6.1) probes the
            // same way, after the checks above, and keeps its own witness
            // for the header.
            let mut witness: Option<Conformed> = None;
            let exec = match pinned {
                None => None,
                Some(p) => {
                    let c = confinement.ok_or(RunRefused::ExecGrant(
                        "harness.exec.run is granted but the run was given no confinement",
                    ))?;
                    let w = c.require().map_err(RunRefused::Confinement)?;
                    witness = Some(w.clone());
                    Some((p, w))
                }
            };
            let ports = if spec.ports.is_empty() {
                None
            } else {
                let c = confinement.ok_or(RunRefused::ExecGrant(
                    "ports are granted but the run was given no confinement",
                ))?;
                let w = match witness {
                    Some(w) => w,
                    None => c.require().map_err(RunRefused::Confinement)?,
                };
                Some(
                    c.probe_ports(&w, &spec.ports, &config.reserved_ports)
                        .map_err(|e| RunRefused::Confinement(harness_sandbox::Refused(e)))?,
                )
            };
            Ok(Prepared {
                session,
                tools,
                read_tools: Some(read_tools),
                edit_tools: Some(edit_tools),
                patch_tools: Some(patch_tools),
                state_root,
                facts: tree.facts(),
                tree: Some(tree),
                exec,
                ports,
                protected: Protected::new(&spec.protected)
                    .map_err(|ProtectedError::Glob(m)| RunRefused::Protected(m))?,
            })
        }
    }
}

/// The research-session spec checks (P-39i, fail closed), shared by
/// `prepare` and `plan` so a live run, a resume and an audit replay refuse
/// alike: this build wires no web capabilities into its driver (P-39j
/// does), and a research session has no workspace, so it takes no exec
/// section, no pre-submit commands and no protected paths.
pub(crate) fn check_research_spec(spec: &TaskSpec) -> Result<(), RunRefused> {
    if let SessionKind::Coding = spec.kind {
        return Ok(());
    }
    if spec
        .grants
        .iter()
        .any(|g| g == WEB_FETCH_ID || g == WEB_SEARCH_ID)
    {
        return Err(RunRefused::Research(
            "this build wires no web capabilities into its driver; a research session grants only the task tools",
        ));
    }
    if spec.exec.is_some() {
        return Err(RunRefused::Research(
            "a research session takes no exec section",
        ));
    }
    // P-36g, fail closed: a port grant needs `harness.exec.start` and a
    // sandbox to bind in; a research session takes neither, so a port
    // grant is refused rather than silently dropped.
    if !spec.ports.is_empty() || !spec.lan_ports.is_empty() {
        return Err(RunRefused::Research(
            "a research session grants no ports (it runs no commands to bind them)",
        ));
    }
    if spec.presubmit.is_some() {
        return Err(RunRefused::Research(
            "a research session runs no pre-submit commands",
        ));
    }
    if !spec.protected.is_empty() {
        return Err(RunRefused::Research(
            "a research session has no workspace, so it has no protected paths",
        ));
    }
    Ok(())
}

/// The hosted-profile checks (P-31, fail closed), shared by `prepare`'s
/// [`plan`] call so a live run, a resume and an audit replay refuse alike:
/// a hosted run without a price table refuses to start (§2.4), and it takes
/// no grant at personal sensitivity or above (Q-2: the context — the task,
/// the rules, every observation — leaves the machine through the loopback
/// proxy, so it may carry no personal data). Grants that resolve to nothing
/// here are left to the session plan's own refusal.
fn check_hosted(spec: &TaskSpec, registry: &Registry, profile: &Profile) -> Result<(), RunRefused> {
    if !profile.hosted() {
        return Ok(());
    }
    if profile.pricing().is_none() {
        return Err(RunRefused::Hosted(
            "a hosted run needs a price table in the profile (a hosted run without one refuses to start, design §2.4)",
        ));
    }
    for g in &spec.grants {
        if let Resolved::One { capability, .. } = registry.resolve(g) {
            if hosted_takes_no_personal([capability.sensitivity()]) {
                return Err(RunRefused::Hosted(
                    "a hosted run takes no grant at personal sensitivity or above (Q-2: its context is sent to a hosted provider)",
                ));
            }
        }
    }
    Ok(())
}

/// Q-2 (pure, so the rule is testable without a registry): whether the
/// sensitivities of the grants a hosted run was given reach personal. In
/// this build no admitted registry can carry such a capability (a Signed
/// tier waits for H4's signature verification; a Pinned tier refuses the
/// sensitivity), so this is defence in depth for H4 — and the rule the
/// day the gate opens.
pub(crate) fn hosted_takes_no_personal(
    sensitivities: impl IntoIterator<Item = Sensitivity>,
) -> bool {
    sensitivities
        .into_iter()
        .any(|s| s >= Sensitivity::Personal)
}

/// The facts of a session with no workspace (P-39i): an empty walk's
/// values, so the header and the turn records keep their fact fields (an
/// audit re-feeds them unchanged) and the loop's tree digest is the digest
/// of nothing.
pub(crate) fn no_workspace_facts() -> WorkspaceFacts {
    WorkspaceFacts {
        tree: sha256(b""),
        files: 0,
        oversize: 0,
    }
}

/// The capabilities the ask floor covers (P-29): every edit cap, the only
/// write path a model has today (P-25: the patch script joins it; the
/// delete/move file operations declare `user_confirm`, so the confirmation
/// floor already asks for them everywhere, protected paths included).
const EDIT_CAPS: [&str; 4] = [
    "harness.edit.replace",
    "harness.edit.write",
    "harness.edit.multi",
    "harness.edit.patch",
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
/// the grant, is refused. The P-36g background tools ride the same setup:
/// they are refused without the `harness.exec.run` grant and section they
/// run under, and a port grant is refused without `harness.exec.start`, the
/// tool that would use the ports (§3, §6.1).
pub(crate) fn exec_setup(spec: &TaskSpec) -> Result<Option<Pinned>, RunRefused> {
    let granted = spec.grants.iter().any(|g| g == EXEC_ID);
    let bg = spec.grants.iter().any(|g| is_bg_id(g));
    if bg && !granted {
        return Err(RunRefused::ExecGrant(
            "a background exec tool is granted but harness.exec.run is not",
        ));
    }
    if bg && spec.exec.is_none() {
        return Err(RunRefused::ExecGrant(
            "a background exec tool is granted but the task has no exec section (its allowlist)",
        ));
    }
    if (!spec.ports.is_empty() || !spec.lan_ports.is_empty())
        && !spec.grants.iter().any(|g| g == EXEC_START_ID)
    {
        return Err(RunRefused::ExecGrant(
            "ports are granted but harness.exec.start is not",
        ));
    }
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

/// The port grant of a task (P-36g §6.1): bounded, each port a real
/// high port, no duplicates, the LAN subset inside it, and never one of the
/// model's own reserved ports. With a loopback endpoint and no reserved
/// ports the harness cannot tell a granted port from the model server's,
/// so it refuses ([`RunRefused::ModelPortUnknown`]) rather than guess.
fn check_ports(
    spec: &TaskSpec,
    config: &RunConfig,
    endpoint: EndpointClass,
) -> Result<(), RunRefused> {
    if spec.ports.len() > PORTS_PER_TASK {
        return Err(RunRefused::ExecGrant(
            "more ports are granted than a task may hold",
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for p in &spec.ports {
        if *p < harness_sandbox::PORT_MIN {
            return Err(RunRefused::ExecGrant(
                "a granted port is below 1024 (the reserved range)",
            ));
        }
        if !seen.insert(*p) {
            return Err(RunRefused::ExecGrant("a port is granted twice"));
        }
    }
    // No duplicates within the LAN list either; a LAN port is one of the
    // ports again (their subset), which is not a duplicate.
    let mut seen_lan = std::collections::BTreeSet::new();
    for p in &spec.lan_ports {
        if !spec.ports.contains(p) {
            return Err(RunRefused::ExecGrant(
                "a lan port is granted that is not among the task's ports",
            ));
        }
        if !seen_lan.insert(*p) {
            return Err(RunRefused::ExecGrant("a lan port is granted twice"));
        }
    }
    if spec.ports.is_empty() {
        return Ok(());
    }
    if endpoint == EndpointClass::Loopback && config.reserved_ports.is_empty() {
        return Err(RunRefused::ModelPortUnknown);
    }
    if config.reserved_ports.iter().any(|r| spec.ports.contains(r)) {
        return Err(RunRefused::ExecGrant(
            "a granted port is a reserved (model) port",
        ));
    }
    Ok(())
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
/// pre-submit checks (H3a), when it has any. A research session (P-39i)
/// renders the research facts (its kind, allowlist and web configuration)
/// instead — it grants no pre-submit commands.
pub(crate) fn loop_facts(f: &WorkspaceFacts, spec: &TaskSpec) -> Vec<Fact> {
    let mut facts = match &spec.kind {
        SessionKind::Research(g) => {
            let mut hosts = g.allowlist.clone();
            hosts.sort();
            context::research_facts(&hosts, g.search)
        }
        SessionKind::Coding => facts_block(f),
    };
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
/// one, INV-6; P-39i: a research session plans only with one covering the
/// web airlock — `prepare` has checked the witness, so it passes `true`).
/// `floor`: whether the protected-path ask floor still has to be applied
/// to the policy (P-38g: a delegate child's audit plans with the policy
/// that already carries it, as the live child did).
pub(crate) fn plan(
    spec: &TaskSpec,
    registry: &Registry,
    policy: &UserPolicy,
    profile: &Profile,
    approver_present: bool,
    conformed: bool,
    floor: bool,
) -> Result<(Session, Vec<ToolSpec>), RunRefused> {
    // P-39i: the research-spec checks, so the audit path (which plans
    // without `prepare`'s witness work) refuses the same specs a live run
    // refuses.
    check_research_spec(spec)?;
    // P-31: the hosted declaration's own refusals, before anything else
    // plans, so a live run, a resume and an audit replay all refuse alike.
    check_hosted(spec, registry, profile)?;
    if let SessionKind::Research(_) = spec.kind {
        // The kind must agree with the registry (§2.2): a research session
        // runs over the research registry, whose web capabilities are
        // admitted (their driver wiring is P-39j).
        if !matches!(registry.resolve(WEB_FETCH_ID), Resolved::One { .. }) {
            return Err(RunRefused::Research(
                "a research session needs the research registry (its web capabilities admitted)",
            ));
        }
    }
    let mut grants = spec.grants.clone();
    if !grants.iter().any(|g| g == SUBMIT_ID) {
        grants.push(SUBMIT_ID.to_owned());
    }
    let research = matches!(spec.kind, SessionKind::Research(_));
    // P-28: the plan sentinel is granted like the submit sentinel, so the
    // plan tool is always declared to a coding session's model (a research
    // session has no plan tool: the research manifest does not admit it).
    if !research && !grants.iter().any(|g| g == PLAN_SUBMIT_ID) {
        grants.push(PLAN_SUBMIT_ID.to_owned());
    }
    // The P-29 ask floor (Cargo.lock, .github/**): decided with here, so a
    // live run, a resume and an audit replay all ask about the same edits.
    // A research session (P-39i) has no edit tools, so it takes no floor.
    let policy = if research || !floor {
        policy.clone()
    } else {
        protected_policy(policy)?
    };
    let session = Session::plan(
        &SessionSpec {
            grants: grants.clone(),
            workspace: (!research).then_some(WorkspaceDecl {
                declared_public: spec.workspace_public,
            }),
            approver_present,
            personal_data_granted: false,
            conformed,
            exec_programs: spec.exec.as_ref().map(ExecSpec::names).unwrap_or_default(),
            // P-36g: the ports that make an exec.start a protected ask.
            lan_ports: spec.lan_ports.clone(),
            // The run's read window bounds a read's lines (H2e); a research
            // session (P-39i) has no read tools, so no window.
            read_window: (!research).then(|| profile.read_window().lines),
            kind: spec.kind.clone(),
            // P-28: every session starts in build mode; `/plan` narrows the
            // active set mid-run and `/build` widens it back.
            mode: SessionMode::Build,
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
    // Post-edit checks (P-27): the same rules. The deny probe leaves the
    // `{path}` placeholder literal: a path-glob rule cannot match it, and a
    // denial that only fires on the real path still fails closed at run
    // time (the check is not run, and the edit is rolled back).
    if let Some(p) = &spec.post_edit {
        p.check(&spec.grants, spec.exec.as_ref())?;
        for i in 0..p.checks.len() {
            let denied = p
                .call(i, "{path}")
                .is_none_or(|c| matches!(session.decide(&c), PolicyDecision::Deny { .. }));
            if denied {
                return Err(PostEditRefused::Denied(i + 1).into());
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
    // The active-tool bound counts what the start (build) mode declares
    // (P-28): the plan sentinel rides in the list for `/plan`'s narrowed
    // declaration, but it is not declared in build mode, so it takes no
    // slot of the profile's budget.
    let max = profile.max_active_tools();
    let declared = tools.iter().filter(|t| t.id != PLAN_SUBMIT_ID).count();
    if u32::try_from(declared).map_or(true, |n| n > max) {
        return Err(RunRefused::TooManyTools {
            active: declared,
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
