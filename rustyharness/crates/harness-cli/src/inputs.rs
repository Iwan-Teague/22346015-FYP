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
const INPUT_MAX_BYTES: u64 = 1024 * 1024;

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
    let policy = match crate::config::value(o, cfg, "policy") {
        None => UserPolicy::default(),
        Some(p) => {
            // v2 (P-08): the policy crate parses the file itself, so the
            // CLI and the audit read one grammar; unknown keys, malformed
            // rules and failing `examples` refuse the file here, by name.
            let bytes = read_input(p).map_err(unreadable)?;
            let v = harness_core::strict_json::parse(&bytes)
                .map_err(|e| unreadable(format!("{p} is not strict JSON: {e}")))?;
            UserPolicy::from_json(&v).map_err(|e| unreadable(format!("policy: {e}")))?
        }
    };
    let profile_path = crate::config::value(o, cfg, "profile").ok_or_else(|| {
        note!(cx, "--profile is required\n{USAGE}");
        refused(exit::USAGE, "--profile missing".into())
    })?;
    let profile = Profile::parse(&read_input(profile_path).map_err(unreadable)?)
        .map_err(|e| unreadable(format!("{profile_path}: {e}")))?;
    let registry = builtin_registry().map_err(unreadable)?;
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
    let config = run_config(task.budget.as_ref(), exec.is_some()).map_err(unreadable)?;
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
        },
        policy,
        profile,
        registry,
        config,
    })
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
