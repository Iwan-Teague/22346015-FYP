//! The developer mini-benchmark (P-21b): every fixture task under
//! `fixtures/bench/<name>/` is run through the real driver — the real
//! policy, journal, presubmit checks and sandbox — and each run's verdict
//! is recorded as one row of a TSV keyed by the harness version and the
//! profile's digest.
//!
//! A fixture is a directory with two things: a `task.json` in the same
//! shape the CLI's task files use (plus a `script`), and a `repo/` with
//! the files the task starts from. The `presubmit.commands` are the
//! expected check: a fixture passes when the driver releases `Passed`,
//! which only happens when every check said so. The `script` is the
//! fixture's scripted solution — the tool calls and the submit — used by
//! the gate self-test (`minibench_scripted_all_pass`) so the fixtures,
//! the checks and the driver are exercised without a model.
//!
//! ```text
//! cargo run -p harness-minibench -- \
//!   --endpoint http://127.0.0.1:8080/v1 --model <id> --out bench.tsv
//! cargo test -p harness-minibench  # the scripted self-test
//! ```

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use harness_core::StopCause;
use harness_journal::{layout, EventKind, JournalReader};
use harness_model::client::{ClientConfig, OpenAiCompatible};
use harness_model::profile::Profile;
use harness_model::ModelBackend;
use harness_model::TaskText;
#[cfg_attr(not(test), allow(unused_imports))]
use harness_model::{Completion, ModelError};
use harness_policy::denies::overlay_default_denies;
use harness_policy::UserPolicy;
use harness_run::{
    presubmit::DEFAULT_ROUNDS, ExecLimits, ExecProgram, ExecSpec, Run, RunConfig, RunRefused,
    RunReport, TaskSpec,
};
use harness_sandbox::environment::SystemEnv;
use harness_sandbox::SystemConfinement;
use harness_testkit::{act, say, submit, Fixture, Local};
use serde::Deserialize;
use serde_json::Value;

/// The token budget a bench run is given (the profile's window is the
/// real cap; this mirrors the CLI's session budget).
const TOKENS: u64 = 1_000_000;

/// The policy every bench run uses: the tools a fixture's task may need
/// are allowed up front (a bench is unattended — there is nobody to ask).
const POLICY_JSON: &str =
    r#"{"allow":["harness.edit.replace","harness.edit.write","harness.exec.run"]}"#;

// ---------------------------------------------------------------------------
// The fixture file.
// ---------------------------------------------------------------------------

/// A fixture's `task.json`: the CLI's task-file shape, plus the scripted
/// solution the self-test replays.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskFile {
    /// The task text.
    task: String,
    /// The tool grants.
    #[serde(default)]
    grants: Vec<String>,
    /// The command runner (needed by a task with pre-submit checks).
    #[serde(default)]
    exec: Option<ExecFile>,
    /// The checks a submission must pass.
    #[serde(default)]
    presubmit: Option<PresubmitFile>,
    /// Budget overrides.
    #[serde(default)]
    budget: Option<BudgetFile>,
    /// The scripted solution: tool calls, a say, and a final submit. The
    /// self-test replays it; the bench run parses it and leaves it be.
    #[cfg_attr(not(test), allow(dead_code))]
    #[serde(default)]
    script: Vec<Step>,
}

/// A fixture's exec section: programs pinned by absolute path, with the
/// read-only roots and declared variables it needs.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecFile {
    /// The exec allowlist.
    programs: Vec<ProgramFile>,
    /// Read-only roots the programs need, absolute.
    #[serde(default)]
    read_only: Vec<PathBuf>,
    /// Declared toolchain variables.
    #[serde(default)]
    env: BTreeMap<String, String>,
}

/// One allowlisted program.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramFile {
    /// What `argv[0]` must say.
    name: String,
    /// The file it runs, absolute.
    path: PathBuf,
}

/// A fixture's pre-submit checks.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PresubmitFile {
    /// The commands, each an argv starting with an allowlisted name.
    commands: Vec<Vec<String>>,
    /// Most submissions a failing check turns back.
    max_rounds: Option<u32>,
}

/// A fixture's budget overrides, as in a CLI task file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BudgetFile {
    /// Loop steps.
    steps: Option<u32>,
    /// Wall clock, seconds.
    wall_secs: Option<u64>,
    /// One command's wall clock, seconds.
    exec_secs: Option<u64>,
}

/// One step of a fixture's scripted solution.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Step {
    /// Call a tool.
    Tool {
        /// The tool's name.
        tool: String,
        /// Its arguments.
        args: Value,
    },
    /// Reply with text only.
    Say {
        /// The text.
        say: String,
    },
    /// Submit (the script's last step).
    Submit {
        /// True.
        submit: bool,
    },
}

// ---------------------------------------------------------------------------
// The bench.
// ---------------------------------------------------------------------------

/// One TSV row: what a fixture's run did.
#[derive(Debug)]
struct Row {
    /// The fixture's name.
    task: String,
    /// Whether the run released `Passed` (every check said so).
    pass: bool,
    /// Loop steps taken.
    steps: u64,
    /// Model tokens the journal recorded (input + output).
    tokens: u64,
    /// Model replies the loop could not parse.
    format_errors: u64,
    /// Why the loop stopped.
    cause: String,
}

fn main() -> ExitCode {
    match bench() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("minibench: {e}");
            ExitCode::from(2)
        }
    }
}

fn bench() -> Result<ExitCode, String> {
    let args = Args::parse(std::env::args().skip(1))?;
    let profile = match (&args.endpoint, &args.model) {
        (Some(url), Some(model)) => {
            let p = Profile::conservative_default(model);
            let client = OpenAiCompatible::new(url, p.clone(), None, ClientConfig::default())
                .map_err(|e| format!("endpoint refused: {e}"))?;
            client
                .startup_check(Instant::now() + Duration::from_secs(30))
                .map_err(|e| format!("the model server did not answer: {e}"))?;
            p
        }
        _ => return Err(usage("both --endpoint and --model are needed".to_owned())),
    };
    let policy = bench_policy()?;
    let dir = fixtures_dir()?;
    let names = list_fixtures(&dir)?;
    if names.is_empty() {
        return Err(format!("no fixtures under {}", dir.display()));
    }
    let backend = OpenAiCompatible::new(
        args.endpoint.as_deref().unwrap_or_default(),
        profile.clone(),
        None,
        ClientConfig::default(),
    )
    .map_err(|e| format!("endpoint refused: {e}"))?;
    let mut rows = Vec::new();
    for name in &names {
        let fx = dir.join(name);
        let row = run_one(name, &fx, &policy, &profile, args.tokens, &backend)?;
        println!(
            "{}",
            row.tsv(
                env!("CARGO_PKG_VERSION"),
                &profile.content_sha256().to_string()
            )
        );
        rows.push(row);
    }
    if let Some(out) = &args.out {
        write_tsv(out, env!("CARGO_PKG_VERSION"), &profile, &rows)?;
    }
    Ok(if rows.iter().all(|r| r.pass) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// The command line.
struct Args {
    /// Where the fixtures live (default: the repo's `fixtures/bench`).
    fixtures: Option<PathBuf>,
    /// Where the TSV goes (default: stdout only).
    out: Option<PathBuf>,
    /// The model server's endpoint.
    endpoint: Option<String>,
    /// The model id the server lists.
    model: Option<String>,
    /// The token budget (default: the CLI's session budget).
    tokens: u64,
}

impl Args {
    fn parse(args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut parsed = Self {
            fixtures: None,
            out: None,
            endpoint: None,
            model: None,
            tokens: TOKENS,
        };
        let mut it = args;
        while let Some(a) = it.next() {
            match a.as_str() {
                "--fixtures" => {
                    parsed.fixtures = Some(PathBuf::from(next_value("--fixtures", &mut it)?))
                }
                "--out" => parsed.out = Some(PathBuf::from(next_value("--out", &mut it)?)),
                "--endpoint" => parsed.endpoint = Some(next_value("--endpoint", &mut it)?),
                "--model" => parsed.model = Some(next_value("--model", &mut it)?),
                "--tokens" => {
                    parsed.tokens = next_value("--tokens", &mut it)?
                        .parse()
                        .map_err(|_| usage("--tokens needs a number".to_owned()))?;
                }
                _ => return Err(usage(format!("unknown argument {a}"))),
            }
        }
        Ok(parsed)
    }
}

fn next_value(name: &str, it: &mut impl Iterator<Item = String>) -> Result<String, String> {
    it.next()
        .ok_or_else(|| usage(format!("{name} needs a value")))
}

fn usage(why: String) -> String {
    format!(
        "{why}\nusage: harness-minibench --endpoint URL --model ID \
         [--fixtures DIR] [--out FILE] [--tokens N]"
    )
}

/// The repo's fixture directory, resolved from this crate's location.
fn fixtures_dir() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/bench")
        .canonicalize()
        .map_err(|e| format!("the fixtures directory is missing ({e}); run from the repo"))
}

/// Every fixture: a directory under `fixtures/bench` holding `task.json`,
/// in name order.
fn list_fixtures(dir: &Path) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    let rd = dir
        .read_dir()
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in rd {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.path().join("task.json").is_file() {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// The bench's policy: the fixture tools allowed, the default denies
/// still underneath (exactly what the CLI builds from a `--policy` file).
fn bench_policy() -> Result<UserPolicy, String> {
    let v: Value = serde_json::from_str(POLICY_JSON)
        .map_err(|e| format!("the bench policy is broken: {e}"))?;
    overlay_default_denies(UserPolicy::from_json(&v).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

/// Load and check one fixture's `task.json`.
fn load_task(dir: &Path) -> Result<TaskFile, String> {
    let path = dir.join("task.json");
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

/// The run's task spec, as the CLI would have built it.
fn spec_of(t: &TaskFile) -> TaskSpec {
    TaskSpec {
        task: TaskText::new(t.task.clone()),
        grants: t.grants.clone(),
        workspace_public: false,
        exec: t.exec.as_ref().map(|e| ExecSpec {
            programs: e
                .programs
                .iter()
                .map(|p| ExecProgram {
                    name: p.name.clone(),
                    path: p.path.clone(),
                })
                .collect(),
            read_only: e.read_only.clone(),
            env: e.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            limits: ExecLimits::default(),
        }),
        presubmit: t.presubmit.as_ref().map(|p| harness_run::PresubmitSpec {
            commands: p.commands.clone(),
            max_rounds: p.max_rounds.unwrap_or(DEFAULT_ROUNDS),
        }),
        protected: Vec::new(),
    }
}

/// The run's budgets: the §2.4 defaults with the fixture's overrides.
fn config_of(t: &TaskFile, tokens: u64) -> RunConfig {
    let mut c = RunConfig::defaults(tokens);
    if let Some(b) = &t.budget {
        if let Some(steps) = b.steps {
            c.limits.steps = steps;
        }
        if let Some(wall) = b.wall_secs {
            c.limits.wall = Duration::from_secs(wall);
        }
        if let Some(exec) = b.exec_secs {
            c.exec_call_timeout = Duration::from_secs(exec);
        }
    }
    c
}

/// Copy a fixture's `repo/` into a fresh workspace.
fn copy_repo(src: &Path, dst: &Path) -> std::io::Result<()> {
    for entry in src.read_dir()? {
        let entry = entry?;
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            std::fs::create_dir_all(&to)?;
            copy_repo(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

/// Run one fixture through the real driver and measure it.
fn run_one(
    name: &str,
    dir: &Path,
    policy: &UserPolicy,
    profile: &Profile,
    tokens: u64,
    backend: &dyn ModelBackend,
) -> Result<Row, String> {
    let t = load_task(dir)?;
    let spec = spec_of(&t);
    let fx = Fixture::new(&format!("minibench-{name}")).map_err(|e| format!("{name}: {e}"))?;
    let repo = dir.join("repo");
    if repo.is_dir() {
        copy_repo(&repo, fx.workspace())
            .map_err(|e| format!("{name}: the repo did not copy: {e}"))?;
    }
    let config = config_of(&t, tokens);
    let confinement = SystemConfinement;
    let reg = harness_testkit::registry().map_err(|e| format!("{name}: {e}"))?;
    let report = harness_run::run(Run {
        state_root: fx.state_root(),
        workspace: fx.workspace(),
        spec: &spec,
        registry: &reg,
        policy,
        profile,
        backend,
        probe: &Local,
        env: &SystemEnv,
        config: &config,
        approver: None,
        confinement: Some(&confinement),
    });
    let report = match report {
        Ok(r) => r,
        Err(e) => {
            return Ok(Row {
                task: name.to_owned(),
                pass: false,
                steps: 0,
                tokens: 0,
                format_errors: 0,
                cause: refused_words(&e),
            })
        }
    };
    let (tokens_used, format_errors) = journal_stats(&report).unwrap_or((0, 0));
    // The loop never releases `Passed` — a submitted run stops
    // `Indeterminate { NothingChecked }` and the gate decides. A fixture
    // passes when its submission was accepted and (with checks) every
    // check said so first time.
    let submitted = report.cause == StopCause::Submitted;
    let checks_passed = match &report.presubmit {
        Some(p) => p.turned_back == 0 && p.last == Some(harness_run::PresubmitResult::Passed),
        None => true,
    };
    Ok(Row {
        task: name.to_owned(),
        pass: submitted && checks_passed,
        steps: report.steps,
        tokens: tokens_used,
        format_errors,
        cause: format!("{:?}", report.cause),
    })
}

/// Why a run that did not start counts as a fail, in one line.
fn refused_words(e: &RunRefused) -> String {
    format!("did not start: {e}")
}

/// What the journal says about one run: the model's tokens (input plus
/// output over every reply) and the loop's format errors.
fn journal_stats(report: &RunReport) -> Result<(u64, u64), String> {
    let v = JournalReader::open(&layout::attempt_dir(&report.run_dir, report.attempt))
        .map_err(|e| format!("{}: {e}", report.run_dir.display()))?;
    let mut tokens = 0;
    let mut format_errors = 0;
    for r in &v.records {
        match r.kind {
            EventKind::ModelReplied => {
                if let Some(usage) = r.body.get("usage") {
                    tokens += usage["input"].as_u64().unwrap_or(0);
                    tokens += usage["output"].as_u64().unwrap_or(0);
                }
            }
            EventKind::FormatError => format_errors += 1,
            _ => {}
        }
    }
    Ok((tokens, format_errors))
}

impl Row {
    /// The row as TSV, keyed by the harness version and profile digest.
    fn tsv(&self, harness: &str, profile_sha: &str) -> String {
        [
            harness,
            profile_sha,
            &self.task,
            if self.pass { "pass" } else { "fail" },
            &self.steps.to_string(),
            &self.tokens.to_string(),
            &self.format_errors.to_string(),
            &cell(&self.cause),
        ]
        .join("\t")
    }
}

/// A TSV cell: tabs and newlines have no business in one.
fn cell(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

/// The whole bench as a TSV file: a header, then a row per fixture.
fn write_tsv(path: &Path, harness: &str, profile: &Profile, rows: &[Row]) -> Result<(), String> {
    let mut text =
        String::from("harness\tprofile_sha\ttask\tpass\tsteps\ttokens\tformat_errors\tcause\n");
    for r in rows {
        text.push_str(&r.tsv(harness, &profile.content_sha256().to_string()));
        text.push('\n');
    }
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// A fixture's scripted solution as a backend: what the self-test runs.
#[cfg_attr(not(test), allow(dead_code))]
fn scripted_of(steps: &[Step]) -> Result<Vec<Result<Completion, ModelError>>, String> {
    let mut out = Vec::new();
    for s in steps {
        let c = match s {
            Step::Tool { tool, args } => act(tool, &args.to_string()),
            Step::Say { say: text } => say(text),
            Step::Submit { submit: true } => submit(),
            Step::Submit { .. } => {
                return Err("a fixture's script ends with {\"submit\": true}".to_owned())
            }
        };
        out.push(Ok(c));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// The gate self-test.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use harness_model::scripted::ScriptedBackend;

    /// Every fixture, driven by its own scripted solution: all ten pass
    /// their pre-submit checks, take no shortcuts (the checks really ran,
    /// the model never fumbled a format error), and the TSV row each
    /// would record is well-formed.
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs a conformed sandbox")]
    fn minibench_scripted_all_pass() {
        let dir = fixtures_dir().unwrap();
        let names = list_fixtures(&dir).unwrap();
        assert_eq!(
            names.len(),
            10,
            "the mini-bench keeps ten fixtures: {names:?}"
        );
        let policy = bench_policy().unwrap();
        let profile = Profile::conservative_default("minibench");
        for name in &names {
            let t = load_task(&dir.join(name)).unwrap();
            let backend = ScriptedBackend::new(profile.clone(), scripted_of(&t.script).unwrap());
            let row = run_one(name, &dir.join(name), &policy, &profile, TOKENS, &backend).unwrap();
            assert!(row.pass, "{name} did not pass: {row:?}");
            assert_eq!(row.format_errors, 0, "{name} fumbled a reply");
            let line = row.tsv(
                env!("CARGO_PKG_VERSION"),
                &profile.content_sha256().to_string(),
            );
            assert_eq!(line.split('\t').count(), 8, "row shape: {line}");
        }
    }
}
