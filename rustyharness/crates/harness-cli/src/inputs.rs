//! The files a gate-child verb reads before anything runs: the task spec
//! (with its `exec`, `budget` and `presubmit` sections), the policy and
//! the profile, each strict JSON, bounded, and refused by name when
//! unusable.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, SemVer, ValidationContext};
use harness_model::profile::Profile;
use harness_model::TaskText;
use harness_policy::UserPolicy;
use harness_run::{RunConfig, TaskSpec};
use serde::Deserialize;

use crate::args::USAGE;
use crate::report::{exit, refused, Outcome};
use crate::Cx;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskFile {
    task: String,
    grants: Vec<String>,
    #[serde(default)]
    workspace_public: bool,
    /// The command runner's setup (H2d), required exactly when the grants
    /// include `harness.exec.run`.
    #[serde(default)]
    exec: Option<ExecFile>,
    /// The run's budgets (§2.1: the task spec declares them; H2e).
    #[serde(default)]
    budget: Option<BudgetFile>,
    /// Commands the harness runs when the model submits (H3a), in a task
    /// that grants `harness.exec.run`.
    #[serde(default)]
    presubmit: Option<PresubmitFile>,
    /// Task-declared protected-path globs (P-29): edits under them are
    /// refused, exec sees them read-only. Absent: only the defaults.
    #[serde(default)]
    protected: Vec<String>,
}

/// A task file's `presubmit` section (H3a): the commands run, in the
/// sandbox, when the model calls `harness.task.submit` (each an argv whose
/// first item is a program name on the exec allowlist, at most 4), and how
/// many submissions a failing one turns back (`max_rounds`, 1 to 5, 2 when
/// absent). It is a header input, so an audit or a resume must be given the
/// task file the run was given.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PresubmitFile {
    commands: Vec<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    max_rounds: Option<u32>,
}

impl PresubmitFile {
    fn spec(self) -> harness_run::PresubmitSpec {
        harness_run::PresubmitSpec {
            commands: self.commands,
            max_rounds: self
                .max_rounds
                .unwrap_or(harness_run::presubmit::DEFAULT_ROUNDS),
        }
    }
}

/// A task file's `budget` section (H2e): the step budget and the wall-clock
/// budget, each optional, the §2.4 default (50 steps, 30 minutes) when
/// absent. The limits are header inputs (H1g F-1), so an audit or a resume
/// given another budget is refused by name, and the budget notices (H2e)
/// count against these limits.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BudgetFile {
    #[serde(default, deserialize_with = "present")]
    steps: Option<u32>,
    #[serde(default, deserialize_with = "present")]
    wall_secs: Option<u64>,
    /// Each command's wall clock (H2f), in a task that grants the runner:
    /// 1 second to an hour, 120 s when absent. It is a header input
    /// (`exec_timeout_ms`), so an audit reads it from the journal.
    #[serde(default, deserialize_with = "present")]
    exec_secs: Option<u64>,
}

/// The widest step budget a task may set.
const BUDGET_MAX_STEPS: u32 = 500;
/// The longest wall-clock budget a task may set: a day.
const BUDGET_MAX_WALL_SECS: u64 = 24 * 60 * 60;
/// The longest wall clock a task may give one command (H2f): an hour.
const BUDGET_MAX_EXEC_SECS: u64 = 60 * 60;

/// An optional field is absent or a value, never `null`.
fn present<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(d).map(Some)
}

/// A task file's `exec` section (H2d): the allowlist (each program's name
/// and its absolute, canonical path), the read-only roots the programs
/// need, the toolchain variables the task declares, and the limits per
/// command (defaults: 2048 MiB per process, 128 processes, 600 s of CPU
/// per process, 1024 MiB files, 1024 KiB kept per stream).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecFile {
    programs: Vec<ProgramFile>,
    #[serde(default)]
    read_only: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    limits: LimitsFile,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramFile {
    name: String,
    path: String,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct LimitsFile {
    memory_mib: Option<u64>,
    processes: Option<u32>,
    cpu_secs: Option<u64>,
    file_size_mib: Option<u64>,
    output_kib: Option<u64>,
}

impl ExecFile {
    fn spec(self) -> Result<harness_run::ExecSpec, String> {
        let d = harness_run::ExecLimits::default();
        let bytes = |v: Option<u64>, shift: u32, default: u64, what: &str| match v {
            None => Ok(default),
            Some(n) => n
                .checked_mul(1u64 << shift)
                .ok_or_else(|| format!("exec limits: {what} is too large")),
        };
        Ok(harness_run::ExecSpec {
            programs: self
                .programs
                .into_iter()
                .map(|p| harness_run::ExecProgram {
                    name: p.name,
                    path: p.path.into(),
                })
                .collect(),
            read_only: self.read_only.into_iter().map(PathBuf::from).collect(),
            env: self.env.into_iter().collect(),
            limits: harness_run::ExecLimits {
                memory: bytes(self.limits.memory_mib, 20, d.memory, "memory_mib")?,
                processes: self.limits.processes.unwrap_or(d.processes),
                cpu: self.limits.cpu_secs.map_or(d.cpu, Duration::from_secs),
                file_size: bytes(self.limits.file_size_mib, 20, d.file_size, "file_size_mib")?,
                output_bytes: bytes(self.limits.output_kib, 10, d.output_bytes, "output_kib")?,
            },
        })
    }
}

/// Largest input file read (task, policy, profile).
pub(crate) const INPUT_MAX_BYTES: u64 = 1024 * 1024;

pub(crate) fn read_input(path: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(INPUT_MAX_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|e| format!("cannot read {path}: {e}"))?;
    if bytes.len() as u64 > INPUT_MAX_BYTES {
        return Err(format!("{path} is larger than 1 MiB"));
    }
    Ok(bytes)
}

fn strict<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, String> {
    let bytes = read_input(path)?;
    let v = harness_core::strict_json::parse(&bytes)
        .map_err(|e| format!("{path} is not strict JSON: {e}"))?;
    serde_json::from_value(v).map_err(|e| format!("{path} does not have the expected shape: {e}"))
}

pub(crate) struct Inputs {
    pub(crate) spec: TaskSpec,
    pub(crate) policy: UserPolicy,
    pub(crate) profile: Profile,
    pub(crate) registry: Registry,
    /// The budgets and timeouts, the task's budget section applied.
    pub(crate) config: RunConfig,
    /// The header's input digests (the same ones `harness_run` journals):
    /// sha256 of the task text, the profile's content digest, the policy's
    /// digest. The run bundle records these, and its self-check compares
    /// against them.
    pub(crate) digests: InputDigests,
}

/// The three input digests a journal header and a run bundle carry.
#[derive(Debug, Clone, Copy)]
pub(crate) struct InputDigests {
    pub(crate) task: harness_core::Digest,
    pub(crate) profile: harness_core::Digest,
    pub(crate) policy: harness_core::Digest,
}

pub(crate) fn required<'a>(
    cx: &Cx<'_>,
    o: &BTreeMap<&str, &'a str>,
    k: &str,
) -> Result<&'a str, Outcome> {
    o.get(k).copied().ok_or_else(|| {
        note!(cx, "--{k} is required\n{USAGE}");
        refused(exit::USAGE, format!("--{k} missing"))
    })
}

pub(crate) fn inputs(
    cx: &Cx<'_>,
    o: &BTreeMap<&str, &str>,
    cfg: &Option<crate::config::UserConfig>,
) -> Result<Inputs, Outcome> {
    let unreadable = |e: String| {
        note!(cx, "{e}");
        refused(exit::UNREADABLE_INPUT, e)
    };
    let task: TaskFile = strict(required(cx, o, "task")?).map_err(unreadable)?;
    // The sensitive-path default denies (P-12): unless the flag turns the
    // overlay off, the CLI's default deny list is applied on top of the
    // given policy (or the empty one), for run, resume and replay alike.
    // The effective policy — defaults included — is what the run header
    // digests, so replay under a different overlay setting is refused.
    let no_default_denies = o.contains_key("no-default-denies");
    // The edit auto-allow (P-23): `--accept-edits` overlays an allow rule
    // for the workspace edits (undoable through the P-22 pre-image store,
    // so the flag is refused when a build has no store). The effective
    // policy — this overlay included — is what the header digests.
    let accept_edits = o.contains_key("accept-edits");
    let policy = match crate::config::value(o, cfg, "policy") {
        None => default_policy(no_default_denies, accept_edits).map_err(unreadable)?,
        Some(p) => {
            // v2 (P-08): the policy crate parses the file itself, so the
            // CLI and the audit read one grammar; unknown keys, malformed
            // rules and failing `examples` refuse the file here, by name.
            let bytes = read_input(p).map_err(unreadable)?;
            let v = harness_core::strict_json::parse(&bytes)
                .map_err(|e| unreadable(format!("{p} is not strict JSON: {e}")))?;
            let policy =
                UserPolicy::from_json(&v).map_err(|e| unreadable(format!("policy: {e}")))?;
            let policy = if no_default_denies {
                policy
            } else {
                harness_policy::denies::overlay_default_denies(policy)
                    .map_err(|e| unreadable(format!("policy: {e}")))?
            };
            if accept_edits {
                harness_policy::overlay_accept_edits(policy, harness_tools::PRE_IMAGE_STORE)
                    .map_err(|e| unreadable(format!("policy: {e}")))?
            } else {
                policy
            }
        }
    };
    let profile_path = crate::config::value(o, cfg, "profile").ok_or_else(|| {
        note!(cx, "--profile is required\n{USAGE}");
        refused(exit::USAGE, "--profile missing".into())
    })?;
    let profile = Profile::parse(&read_input(profile_path).map_err(unreadable)?)
        .map_err(|e| unreadable(format!("{profile_path}: {e}")))?;
    let registry = builtin_registry().map_err(unreadable)?;
    // The digests the header will carry, from the values the run uses.
    let task_text_for_digest = task.task.clone();
    let profile_sha = profile.content_sha256();
    let policy_digest = policy.digest();
    // The exec section (H2d): the task file's own, or the one --allow-exec,
    // --preset and --shell describe (P-11). The two never mix: a task file
    // with an exec section already pins its programs, and exec_presets
    // refuses every disagreement as unreadable input (exit 4).
    let exec = match task.exec {
        Some(e) => {
            if crate::exec_presets::request(o, cfg).is_some() {
                return Err(unreadable(
                    "--allow-exec, --preset and --shell do not go with a task file that has \
                     its own exec section"
                        .into(),
                ));
            }
            Some(e.spec().map_err(unreadable)?)
        }
        None => crate::exec_presets::section(cx, o, cfg, &task.grants)?,
    };
    let mut config = run_config(task.budget.as_ref(), exec.is_some()).map_err(unreadable)?;
    // Session-scoped grants (P-23, Q-4): default off; the flag lets the
    // person answer `a`/`d` at an approval prompt.
    config.allow_session_grants = o.contains_key("allow-session-grants");
    // The checks (H3a): bounded and on the allowlist, in a task that grants
    // the command runner, or the task file is unusable input (exit 4).
    let presubmit = task.presubmit.map(PresubmitFile::spec);
    if let Some(p) = &presubmit {
        p.check(&task.grants, exec.as_ref())
            .map_err(|e| unreadable(format!("presubmit: {e}")))?;
    }
    Ok(Inputs {
        spec: TaskSpec {
            task: TaskText::new(task.task),
            grants: task.grants,
            workspace_public: task.workspace_public,
            exec,
            presubmit,
            protected: task.protected,
            // P-39i: the CLI's verbs run coding sessions; the research
            // session's verbs arrive with the web slice (P-39j/§11).
            kind: harness_run::SessionKind::Coding,
        },
        policy,
        profile,
        registry,
        config,
        digests: InputDigests {
            task: harness_core::sha256(task_text_for_digest.as_bytes()),
            profile: profile_sha,
            policy: policy_digest,
        },
    })
}

/// The task text in task-file bytes (bundle self-check and `sessions`).
pub(crate) fn task_text(bytes: &[u8]) -> Result<String, String> {
    let v = harness_core::strict_json::parse(bytes)
        .map_err(|e| format!("task file is not strict JSON: {e}"))?;
    let t: TaskFile = serde_json::from_value(v).map_err(|e| format!("task file: {e}"))?;
    Ok(t.task)
}

/// The explicit budgets a task file sets (P-49): `(steps, wall_secs)`,
/// each as the file spelled it or absent.
pub(crate) type Budget = (Option<u32>, Option<u64>);

/// The task file's explicit budgets (P-49): `(steps, wall_secs)` when its
/// `budget` section sets at least one of the two, `None` when it does not
/// (a section that sets only `exec_secs`, or none at all). A schedule must
/// carry an explicit budget: the §2.4 defaults exist for a person's run,
/// not for one that fires on a timer with nobody watching.
pub(crate) fn task_budget(bytes: &[u8]) -> Result<Option<Budget>, String> {
    let v = harness_core::strict_json::parse(bytes)
        .map_err(|e| format!("task file is not strict JSON: {e}"))?;
    let t: TaskFile = serde_json::from_value(v).map_err(|e| format!("task file: {e}"))?;
    match t.budget {
        Some(b) if b.steps.is_some() || b.wall_secs.is_some() => Ok(Some((b.steps, b.wall_secs))),
        _ => Ok(None),
    }
}
/// The policy a run uses when no `--policy` is given: the empty library
/// default (OD-2) with the CLI's sensitive-path default denies overlaid
/// (P-12), unless `--no-default-denies` turns the overlay off, and the
/// edit auto-allow overlaid when `--accept-edits` is on (P-23). One
/// spelling for the run here and for the bundle's recomputation on
/// `replay` and `resume` (`bundle::check_against_bundle`), so the digest
/// a run records and the digest a replay recomputes cannot drift.
pub(crate) fn default_policy(
    no_default_denies: bool,
    accept_edits: bool,
) -> Result<UserPolicy, String> {
    let mut policy = UserPolicy::default();
    if !no_default_denies {
        policy = harness_policy::denies::overlay_default_denies(policy)
            .map_err(|e| format!("policy: {e}"))?;
    }
    if accept_edits {
        policy = harness_policy::overlay_accept_edits(policy, harness_tools::PRE_IMAGE_STORE)
            .map_err(|e| format!("policy: {e}"))?;
    }
    Ok(policy)
}

/// The digest of the policy in policy-file bytes, as the run digests it:
/// the v2 grammar (P-08) lives in the policy crate, and the effective
/// policy — the CLI's overlays (P-12 default denies, P-23 accept-edits) as
/// the run's flags set them — is what the header and the bundle record.
pub(crate) fn policy_digest(
    bytes: &[u8],
    overlay: bool,
    accept_edits: bool,
) -> Result<harness_core::Digest, String> {
    let v = harness_core::strict_json::parse(bytes)
        .map_err(|e| format!("policy file is not strict JSON: {e}"))?;
    let policy = UserPolicy::from_json(&v).map_err(|e| format!("policy: {e}"))?;
    let policy = if overlay {
        harness_policy::denies::overlay_default_denies(policy)
            .map_err(|e| format!("policy: {e}"))?
    } else {
        policy
    };
    let policy = if accept_edits {
        harness_policy::overlay_accept_edits(policy, harness_tools::PRE_IMAGE_STORE)
            .map_err(|e| format!("policy: {e}"))?
    } else {
        policy
    };
    Ok(policy.digest())
}

/// The content digest of the profile in profile bytes.
pub(crate) fn profile_digest(bytes: &[u8]) -> Result<harness_core::Digest, String> {
    Profile::parse(bytes)
        .map(|p| p.content_sha256())
        .map_err(|e| format!("profile: {e}"))
}

/// The budgets and timeouts of a run or resume this binary starts: the
/// §2.4 defaults, with the task's budget section (H2e) applied. `replay`
/// passes the same limits to the audit, which requires them to equal the
/// recorded ones (H1 phase-exit review F-1), so an audit or a resume must
/// be given the task file the run was given.
fn run_config(budget: Option<&BudgetFile>, has_exec: bool) -> Result<RunConfig, String> {
    let mut c = RunConfig::defaults(1_000_000);
    let Some(b) = budget else { return Ok(c) };
    if let Some(s) = b.steps {
        if !(1..=BUDGET_MAX_STEPS).contains(&s) {
            return Err(format!(
                "budget: steps must be from 1 to {BUDGET_MAX_STEPS}"
            ));
        }
        c.limits.steps = s;
    }
    if let Some(w) = b.wall_secs {
        if !(1..=BUDGET_MAX_WALL_SECS).contains(&w) {
            return Err(format!(
                "budget: wall_secs must be from 1 to {BUDGET_MAX_WALL_SECS}"
            ));
        }
        c.limits.wall = Duration::from_secs(w);
    }
    if let Some(x) = b.exec_secs {
        if !has_exec {
            return Err(
                "budget: exec_secs is for a task with an exec section; this task has none".into(),
            );
        }
        if !(1..=BUDGET_MAX_EXEC_SECS).contains(&x) {
            return Err(format!(
                "budget: exec_secs must be from 1 to {BUDGET_MAX_EXEC_SECS}"
            ));
        }
        c.exec_call_timeout = Duration::from_secs(x);
    }
    Ok(c)
}

fn builtin_registry() -> Result<Registry, String> {
    let v = SemVer::parse(env!("CARGO_PKG_VERSION")).ok_or("harness version")?;
    let ctx = ValidationContext::new(v, &[]).map_err(|e| e.to_string())?;
    let m = builtin::manifest(&ctx).map_err(|e| e.to_string())?;
    Registry::admit(vec![(m, Tier::Builtin)]).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::TaskFile;

    /// The `protected` section (P-29): present globs parse; absent, the
    /// task carries only the build's defaults (`None` here, the CLI maps
    /// that to an empty task list).
    #[test]
    fn protected_parses_when_present_and_is_empty_when_absent() {
        let with: TaskFile = serde_json::from_str(
            r#"{"task":"t","grants":[],"protected":["secrets/**",".git/**"]}"#,
        )
        .unwrap();
        assert_eq!(
            with.protected,
            vec!["secrets/**".to_owned(), ".git/**".to_owned()]
        );
        let without: TaskFile = serde_json::from_str(r#"{"task":"t","grants":[]}"#).unwrap();
        assert!(without.protected.is_empty());
    }
}
