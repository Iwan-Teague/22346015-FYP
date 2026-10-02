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
//! The profile is `Profile::conservative_default` for `--model`, or a
//! recorded profile file with `--profile` (strict-validated, so the text
//! and native protocols and the recorded profiles run; the TSV's
//! `profile_sha` is always the profile's `content_sha256`). Around the
//! runs: `--only NAME[,NAME]` runs named fixtures only, `--keep DIR`
//! copies every run's journal out of the fixture's state root, `--audit`
//! replays each produced journal (no divergence, the run's chain head
//! anchoring it — otherwise the row is marked `audit_fail`), `--baseline
//! FILE` compares against a recorded TSV (a task that passed there and
//! fails now, or steps grown by more than 50% and at least 3, fails the
//! gate; rows recorded by another harness version are compared but
//! flagged), and `--repeat N` runs each fixture N times, a task passing
//! the gate on a majority of its rows.
//!
//! ```text
//! cargo run -p harness-minibench -- \
//!   --endpoint http://127.0.0.1:8080/v1 --model <id> --out bench.tsv
//! cargo test -p harness-minibench  # the scripted self-test
//! ```

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
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
#[derive(Debug, Clone)]
struct Row {
    /// The fixture's name.
    task: String,
    /// Whether the run released `Passed` (every check said so), and —
    /// under `--audit` — its journal replayed clean. An audit failure
    /// turns a passing run into a failing row.
    pass: bool,
    /// Loop steps taken.
    steps: u64,
    /// Model tokens the journal recorded (input + output).
    tokens: u64,
    /// Model replies the loop could not parse.
    format_errors: u64,
    /// Whether `--audit` refused this run's journal (divergence, or the
    /// chain head did not anchor it). The TSV's cause cell says
    /// `audit_fail` for such a row.
    audit_fail: bool,
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
    // The profile: a recorded one from `--profile`, or the conservative
    // default for `--model`. Exactly one of the two; a profile carries its
    // own model, so taking both would leave which model ran ambiguous.
    let profile = match (&args.profile, &args.model) {
        (Some(file), None) => load_profile(file)?,
        (None, Some(model)) => Profile::conservative_default(model),
        (Some(_), Some(_)) => {
            return Err(usage(
                "--profile and --model are alternatives; give one".to_owned(),
            ))
        }
        (None, None) => {
            return Err(usage(
                "--endpoint and one of --model or --profile are needed".to_owned(),
            ))
        }
    };
    let endpoint = args
        .endpoint
        .as_deref()
        .ok_or_else(|| usage("--endpoint is needed".to_owned()))?;
    // The server must answer before anything runs (both paths need it).
    let check = OpenAiCompatible::new(endpoint, profile.clone(), None, ClientConfig::default())
        .map_err(|e| format!("endpoint refused: {e}"))?;
    check
        .startup_check(Instant::now() + Duration::from_secs(30))
        .map_err(|e| format!("the model server did not answer: {e}"))?;
    let policy = bench_policy()?;
    let dir = fixtures_dir()?;
    let all = list_fixtures(&dir)?;
    let names = select_names(&all, args.only.as_deref())?;
    if names.is_empty() {
        return Err(format!("no fixtures under {}", dir.display()));
    }
    let baseline = match &args.baseline {
        Some(file) => Some(parse_baseline(file)?),
        None => None,
    };
    let backend = OpenAiCompatible::new(endpoint, profile.clone(), None, ClientConfig::default())
        .map_err(|e| format!("endpoint refused: {e}"))?;
    let opts = RunOpts {
        policy: &policy,
        profile: &profile,
        tokens: args.tokens,
        keep: args.keep.as_deref(),
        audit: args.audit,
    };
    let mut rows = Vec::new();
    for name in &names {
        for _ in 0..args.repeat {
            let (row, _) = run_one(name, &dir.join(name), &opts, &backend)?;
            println!(
                "{}",
                row.tsv(
                    env!("CARGO_PKG_VERSION"),
                    &profile.content_sha256().to_string()
                )
            );
            rows.push(row);
        }
    }
    if let Some(out) = &args.out {
        write_tsv(out, env!("CARGO_PKG_VERSION"), &profile, &rows)?;
    }
    // The gate: a task passes on a majority of its rows; one audited-away
    // journal fails the whole bench; a baseline regression does too.
    let mut ok = gate_ok(&rows) && !rows.iter().any(|r| r.audit_fail);
    if let (Some(b), Some(file)) = (&baseline, args.baseline.as_deref()) {
        let verdict = compare_baseline(b, &rows, env!("CARGO_PKG_VERSION"));
        for note in &verdict.notes {
            eprintln!("minibench: baseline: {note}");
        }
        if verdict.failed {
            eprintln!("minibench: baseline: regression against {}", file.display());
            ok = false;
        }
    }
    Ok(if ok {
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
    /// The model id the server lists (the conservative default profile).
    model: Option<String>,
    /// A recorded profile file (strict-validated; `--model`'s
    /// alternative).
    profile: Option<PathBuf>,
    /// The named fixtures only (`--only NAME[,NAME]`).
    only: Option<Vec<String>>,
    /// Copy every run's journal here (`--keep DIR`).
    keep: Option<PathBuf>,
    /// Replay every produced journal (`--audit`); a divergence marks the
    /// row `audit_fail` and fails the bench.
    audit: bool,
    /// A recorded TSV to compare against (`--baseline FILE`).
    baseline: Option<PathBuf>,
    /// Runs per fixture (`--repeat N`); a task passes the gate on a
    /// majority of its rows.
    repeat: u32,
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
            profile: None,
            only: None,
            keep: None,
            audit: false,
            baseline: None,
            repeat: 1,
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
                "--profile" => {
                    parsed.profile = Some(PathBuf::from(next_value("--profile", &mut it)?))
                }
                "--only" => {
                    let v = next_value("--only", &mut it)?;
                    let mut names = Vec::new();
                    for part in v.split(',') {
                        let n = part.trim();
                        if n.is_empty() {
                            return Err(usage(
                                "--only needs fixture names, comma-separated".to_owned(),
                            ));
                        }
                        names.push(n.to_owned());
                    }
                    parsed.only = Some(names);
                }
                "--keep" => parsed.keep = Some(PathBuf::from(next_value("--keep", &mut it)?)),
                "--audit" => parsed.audit = true,
                "--baseline" => {
                    parsed.baseline = Some(PathBuf::from(next_value("--baseline", &mut it)?))
                }
                "--repeat" => {
                    let n: u32 = next_value("--repeat", &mut it)?
                        .parse()
                        .map_err(|_| usage("--repeat needs a number".to_owned()))?;
                    if n == 0 {
                        return Err(usage("--repeat needs at least 1".to_owned()));
                    }
                    parsed.repeat = n;
                }
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
        "{why}\nusage: harness-minibench --endpoint URL (--model ID | --profile FILE) \
         [--fixtures DIR] [--out FILE] [--tokens N] [--only NAME[,NAME]] \
         [--keep DIR] [--audit] [--baseline FILE] [--repeat N]"
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

/// Load and validate a recorded profile (`--profile FILE`): the same
/// strict parse the CLI's `--profile` does — duplicate keys and unknown
/// fields refused, every number in range, nothing this build cannot
/// honour.
fn load_profile(path: &Path) -> Result<Profile, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Profile::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

/// The fixtures to run: all of them, or the `--only NAME[,NAME]` subset,
/// in the order given. A name that is no fixture is refused: a typo must
/// not silently shrink the bench.
fn select_names(all: &[String], only: Option<&[String]>) -> Result<Vec<String>, String> {
    let Some(want) = only else {
        return Ok(all.to_vec());
    };
    let mut out = Vec::new();
    for w in want {
        match all.iter().find(|n| n == &w) {
            Some(hit) => out.push(hit.clone()),
            None => {
                return Err(format!(
                    "--only {w}: no such fixture (have {})",
                    all.join(", ")
                ))
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// The baseline (`--baseline FILE`).
// ---------------------------------------------------------------------------

/// One row of a recorded baseline TSV: the fields the gate compares.
#[derive(Debug)]
struct BaselineRow {
    /// The harness version that recorded it.
    harness: String,
    /// The fixture's name.
    task: String,
    /// Whether the run passed.
    pass: bool,
    /// Loop steps taken.
    steps: u64,
}

/// A recorded baseline: one row per task, as a past bench wrote it.
#[derive(Debug)]
struct Baseline {
    rows: Vec<BaselineRow>,
}

/// Read a recorded TSV (`--baseline FILE`): the bench's own shape, read
/// by column name so an older file with the same columns parses. One row
/// per task — two rows for a task is a recording this gate cannot
/// reason about, so it is refused.
fn parse_baseline(path: &Path) -> Result<Baseline, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let text =
        String::from_utf8(bytes).map_err(|e| format!("{}: not utf-8: {e}", path.display()))?;
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let header: Vec<&str> = lines
        .next()
        .ok_or_else(|| format!("{}: empty", path.display()))?
        .split('\t')
        .collect();
    let col = |name: &str| {
        header.iter().position(|h| *h == name).ok_or_else(|| {
            format!(
                "{}: the header has no {} column (have {})",
                path.display(),
                name,
                header.join(", ")
            )
        })
    };
    let (h, t, p, s) = (col("harness")?, col("task")?, col("pass")?, col("steps")?);
    let mut rows = Vec::new();
    for line in lines {
        let c: Vec<&str> = line.split('\t').collect();
        if c.len() != header.len() {
            return Err(format!(
                "{}: a row has {} fields, the header has {}",
                path.display(),
                c.len(),
                header.len()
            ));
        }
        let get = |i: usize| -> Result<&str, String> {
            c.get(i).copied().ok_or_else(|| {
                format!(
                    "{}: a row has {} fields, the header has {}",
                    path.display(),
                    c.len(),
                    header.len()
                )
            })
        };
        let pass = match get(p)? {
            "pass" => true,
            "fail" => false,
            other => {
                return Err(format!(
                    "{}: pass is {other:?}, not \"pass\" or \"fail\"",
                    path.display()
                ))
            }
        };
        let steps_cell = get(s)?;
        let steps: u64 = steps_cell
            .parse()
            .map_err(|_| format!("{}: steps {steps_cell:?} is not a number", path.display()))?;
        rows.push(BaselineRow {
            harness: get(h)?.to_owned(),
            task: get(t)?.to_owned(),
            pass,
            steps,
        });
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for r in &rows {
        if !seen.insert(r.task.as_str()) {
            return Err(format!(
                "{}: two recorded rows for task {}",
                path.display(),
                r.task
            ));
        }
    }
    Ok(Baseline { rows })
}

/// What comparing today's rows to a baseline found.
#[derive(Debug)]
struct BaselineVerdict {
    /// The gate fails: a task that passed in the baseline fails now, or
    /// steps grew by more than 50% and at least 3.
    failed: bool,
    /// Everything worth reading: regressions, step growth, version
    /// flags, tasks not compared.
    notes: Vec<String>,
}

/// Compare today's rows against a recorded baseline. Rows are per
/// attempt (`--repeat`), so a task's pass is its majority; step growth
/// flags when any attempt grew past the recorded steps. Rows recorded by
/// another harness version are compared but flagged: the harness, not
/// the model, may account for the difference.
fn compare_baseline(b: &Baseline, rows: &[Row], harness: &str) -> BaselineVerdict {
    let mut v = BaselineVerdict {
        failed: false,
        notes: Vec::new(),
    };
    // Today's tasks: attempt count, passing attempts, every attempt's steps.
    let mut today: BTreeMap<&str, (u32, u32, Vec<u64>)> = BTreeMap::new();
    for r in rows {
        let e = today.entry(r.task.as_str()).or_insert((0, 0, Vec::new()));
        e.0 += 1;
        if r.pass {
            e.1 += 1;
        }
        e.2.push(r.steps);
    }
    let mut recorded: BTreeMap<&str, &BaselineRow> = BTreeMap::new();
    for r in &b.rows {
        recorded.insert(r.task.as_str(), r);
    }
    for (task, (total, passes, steps)) in &today {
        let Some(bv) = recorded.get(task) else {
            v.notes
                .push(format!("{task}: not in the baseline; not compared"));
            continue;
        };
        if bv.harness != harness {
            v.notes.push(format!(
                "{task}: recorded by harness {}, this is {harness}; compared but flagged",
                bv.harness
            ));
        }
        if bv.pass && passes * 2 <= *total {
            v.failed = true;
            v.notes.push(format!(
                "{task}: REGRESSION: passed in the baseline (harness {}), fails now",
                bv.harness
            ));
        }
        for &s in steps {
            let growth = s.saturating_sub(bv.steps);
            if s > bv.steps && growth.saturating_mul(2) > bv.steps && growth >= 3 {
                v.failed = true;
                v.notes.push(format!(
                    "{task}: steps grew {} -> {s} (+{growth}: more than 50% and at least 3)",
                    bv.steps
                ));
                break;
            }
        }
    }
    for task in recorded.keys() {
        if !today.contains_key(task) {
            v.notes
                .push(format!("{task}: in the baseline, not run now"));
        }
    }
    v
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

/// Copy a whole directory tree to a new destination (created, never
/// symlinked through): what `--keep` uses to lift a run's journal out of
/// the fixture's state root before it is dropped.
fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in src.read_dir()? {
        let entry = entry?;
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

/// What one bench run is given, beyond the fixture itself.
struct RunOpts<'a> {
    /// The bench policy (the fixture tools allowed, default denies under).
    policy: &'a UserPolicy,
    /// The model profile (default or recorded).
    profile: &'a Profile,
    /// The token budget.
    tokens: u64,
    /// `--keep DIR`: copy every run's journal here.
    keep: Option<&'a Path>,
    /// `--audit`: replay every produced journal after the run.
    audit: bool,
}

/// Copy a run's journal directory out (`--keep DIR`): the attempt's
/// journal and blobs land under `<DIR>/<task>/<run-id>/`, so they
/// outlive the fixture's state root.
fn keep_journal(keep: &Path, name: &str, report: &RunReport) -> Result<(), String> {
    let src = layout::attempt_dir(&report.run_dir, report.attempt);
    let dst = keep.join(name).join(report.run.as_str());
    copy_tree(&src, &dst).map_err(|e| format!("{} -> {}: {e}", src.display(), dst.display()))
}

/// Audit a produced journal (`--audit`): the same replay the `replay`
/// verb runs, given the run's own task, policy, profile and budgets, and
/// anchored by the run's own chain head. Clean means: no divergence, and
/// the chain head matched — nothing was cut from the journal.
fn audit_run(
    report: &RunReport,
    state_root: &Path,
    spec: &TaskSpec,
    policy: &UserPolicy,
    profile: &Profile,
    limits: &harness_core::MeterLimits,
) -> Result<(), String> {
    let Some(anchor) = report.chain_head else {
        return Err("the run left no durable chain head to anchor the journal".to_owned());
    };
    let reg = harness_testkit::registry().map_err(|e| format!("registry: {e}"))?;
    let a = harness_run::audit(harness_run::Audit {
        state_root,
        run: &report.run,
        attempt: Some(report.attempt),
        anchor: Some(anchor),
        spec,
        registry: &reg,
        policy,
        profile,
        limits,
    })
    .map_err(|e| format!("the audit did not start: {e}"))?;
    if let Some(d) = &a.divergence {
        return Err(format!(
            "the replay diverged at record {} (step {}): {}",
            d.seq, d.step, d.why
        ));
    }
    if !a.anchored {
        return Err("the run's chain head did not anchor the journal".into());
    }
    Ok(())
}

/// Mark a row whose journal failed the audit (`--audit`): a fail,
/// whatever the checks said — an unauditable run proves nothing.
fn mark_audit_fail(mut row: Row) -> Row {
    row.pass = false;
    row.audit_fail = true;
    row
}

/// Run one fixture through the real driver and measure it. The run's
/// journal is copied out under `--keep` and replayed under `--audit`;
/// the report goes back with the row for the callers that want it.
fn run_one(
    name: &str,
    dir: &Path,
    opts: &RunOpts<'_>,
    backend: &dyn ModelBackend,
) -> Result<(Row, Option<RunReport>), String> {
    let t = load_task(dir)?;
    let spec = spec_of(&t);
    let fx = Fixture::new(&format!("minibench-{name}")).map_err(|e| format!("{name}: {e}"))?;
    let repo = dir.join("repo");
    if repo.is_dir() {
        copy_repo(&repo, fx.workspace())
            .map_err(|e| format!("{name}: the repo did not copy: {e}"))?;
    }
    let config = config_of(&t, opts.tokens);
    let confinement = SystemConfinement;
    let reg = harness_testkit::registry().map_err(|e| format!("{name}: {e}"))?;
    let report = harness_run::run(Run {
        state_root: fx.state_root(),
        workspace: fx.workspace(),
        spec: &spec,
        registry: &reg,
        policy: opts.policy,
        profile: opts.profile,
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
            return Ok((
                Row {
                    task: name.to_owned(),
                    pass: false,
                    steps: 0,
                    tokens: 0,
                    format_errors: 0,
                    audit_fail: false,
                    cause: refused_words(&e),
                },
                None,
            ))
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
    let mut row = Row {
        task: name.to_owned(),
        pass: submitted && checks_passed,
        steps: report.steps,
        tokens: tokens_used,
        format_errors,
        audit_fail: false,
        cause: format!("{:?}", report.cause),
    };
    if let Some(keep) = opts.keep {
        keep_journal(keep, name, &report)?;
    }
    if opts.audit {
        if let Err(why) = audit_run(
            &report,
            fx.state_root(),
            &spec,
            opts.policy,
            opts.profile,
            &config.limits,
        ) {
            eprintln!("minibench: {name}: audit failed: {why}");
            row = mark_audit_fail(row);
        }
    }
    Ok((row, Some(report)))
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
    /// An audit-failed row says so in the cause cell.
    fn tsv(&self, harness: &str, profile_sha: &str) -> String {
        [
            harness,
            profile_sha,
            &self.task,
            if self.pass { "pass" } else { "fail" },
            &self.steps.to_string(),
            &self.tokens.to_string(),
            &self.format_errors.to_string(),
            &if self.audit_fail {
                "audit_fail".to_owned()
            } else {
                cell(&self.cause)
            },
        ]
        .join("\t")
    }
}

/// A TSV cell: tabs and newlines have no business in one.
fn cell(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

/// The whole bench as a TSV file: a header, then a row per run (rows are
/// per attempt under `--repeat`).
fn write_tsv(path: &Path, harness: &str, profile: &Profile, rows: &[Row]) -> Result<(), String> {
    let mut text =
        String::from("harness\tprofile_sha\ttask\tpass\tsteps\ttokens\tformat_errors\tcause\n");
    for r in rows {
        text.push_str(&r.tsv(harness, &profile.content_sha256().to_string()));
        text.push('\n');
    }
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Whether every task passes the `--repeat` gate: a task passes when a
/// majority of its rows do (one row per attempt). A tie is a fail —
/// half the attempts failing is no evidence of a pass.
fn gate_ok(rows: &[Row]) -> bool {
    let mut per_task: BTreeMap<&str, (u32, u32)> = BTreeMap::new();
    for r in rows {
        let e = per_task.entry(r.task.as_str()).or_insert((0, 0));
        e.0 += 1;
        if r.pass {
            e.1 += 1;
        }
    }
    per_task.values().all(|(total, passes)| passes * 2 > *total)
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
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    use super::*;
    use harness_model::scripted::ScriptedBackend;

    /// A recorded profile file's content: the strict shape `--profile`
    /// must accept (§3.4 fields, text protocol).
    const PROFILE_JSON: &str = r#"{"profile_version":1,"id":"minibench-profile","model":"m",
        "context_window":32768,"fill_ratio":0.6,"protocol":"text","tool_choice_required_ok":false,
        "grammar":"none","max_active_tools":5,"edit_format":"replace","recent_turns":4,
        "sampling":{"temperature":0.2,"top_p":0.95,"max_tokens":1024}}"#;

    /// The bench's profile, policy and per-run options for a scripted run.
    struct Scripted {
        dir: PathBuf,
        names: Vec<String>,
        policy: UserPolicy,
        profile: Profile,
    }

    impl Scripted {
        /// The whole fixture list, ready to run.
        fn all() -> Self {
            let dir = fixtures_dir().unwrap();
            let names = list_fixtures(&dir).unwrap();
            let policy = bench_policy().unwrap();
            let profile = Profile::conservative_default("minibench");
            Self {
                dir,
                names,
                policy,
                profile,
            }
        }

        /// Run one fixture by name against its own scripted solution,
        /// with these `--keep`/`--audit` settings.
        fn run(&self, name: &str, keep: Option<&Path>, audit: bool) -> (Row, RunReport) {
            let t = load_task(&self.dir.join(name)).unwrap();
            let backend =
                ScriptedBackend::new(self.profile.clone(), scripted_of(&t.script).unwrap());
            let opts = RunOpts {
                policy: &self.policy,
                profile: &self.profile,
                tokens: TOKENS,
                keep,
                audit,
            };
            let (row, report) = run_one(name, &self.dir.join(name), &opts, &backend).unwrap();
            (row, report.unwrap())
        }
    }

    /// Every fixture, driven by its own scripted solution: all ten pass
    /// their pre-submit checks, take no shortcuts (the checks really ran,
    /// the model never fumbled a format error), and the TSV row each
    /// would record is well-formed.
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs a conformed sandbox")]
    fn minibench_scripted_all_pass() {
        let s = Scripted::all();
        assert_eq!(
            s.names.len(),
            10,
            "the mini-bench keeps ten fixtures: {:?}",
            s.names
        );
        for name in &s.names {
            let (row, _) = s.run(name, None, false);
            assert!(row.pass, "{name} did not pass: {row:?}");
            assert!(!row.audit_fail, "{name} was marked audit_fail");
            assert_eq!(row.format_errors, 0, "{name} fumbled a reply");
            let line = row.tsv(
                env!("CARGO_PKG_VERSION"),
                &s.profile.content_sha256().to_string(),
            );
            assert_eq!(line.split('\t').count(), 8, "row shape: {line}");
        }
    }

    /// `--audit` over a scripted run: the journal replays clean — no
    /// divergence, the run's own chain head anchoring it — so the row
    /// stays a pass, not `audit_fail`.
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs a conformed sandbox")]
    fn minibench_audit_flag_passes_on_scripted_run() {
        let s = Scripted::all();
        let name = &s.names[0];
        let (row, _) = s.run(name, None, true);
        assert!(row.pass, "{name} did not pass: {row:?}");
        assert!(!row.audit_fail, "{name} was marked audit_fail");
        assert_eq!(row.cause, "Submitted");
    }

    /// A doctored journal copy must not audit clean: the replay reports
    /// the divergence, and the marking turns the row into an
    /// `audit_fail` fail.
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs a conformed sandbox")]
    fn audit_flag_marks_divergence_as_audit_fail() {
        let s = Scripted::all();
        let name = &s.names[0];
        let keeper = Fixture::new("minibench-audit-doctor").unwrap();
        let kept = keeper.base().join("kept");
        let (row, report) = s.run(name, Some(&kept), false);
        assert!(row.pass);

        // A state root of our own holding a copy of the kept journal,
        // with one byte flipped in the middle: the chain cannot verify.
        let root = keeper.base().join("doctored-state");
        let att = root
            .join("runs")
            .join(report.run.as_str())
            .join(format!("attempt-{}", report.attempt));
        copy_tree(&kept.join(name).join(report.run.as_str()), &att).unwrap();
        let journal = att.join("journal.jsonl");
        let mut bytes = std::fs::read(&journal).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] = if bytes[mid] == b'a' { b'b' } else { b'c' };
        std::fs::write(&journal, &bytes).unwrap();

        let t = load_task(&s.dir.join(name)).unwrap();
        let spec = spec_of(&t);
        let limits = config_of(&t, TOKENS).limits;
        let why = audit_run(&report, &root, &spec, &s.policy, &s.profile, &limits).unwrap_err();
        assert!(
            why.contains("diverged") || why.contains("anchor"),
            "unexpected why: {why}"
        );
        let marked = mark_audit_fail(row);
        assert!(!marked.pass);
        assert!(marked.audit_fail);
        assert!(
            marked
                .tsv("0.0.1", "sha")
                .split('\t')
                .next_back()
                .unwrap()
                .contains("audit_fail"),
            "cause cell: {}",
            marked.tsv("0.0.1", "sha")
        );
    }

    /// `--keep DIR` receives every run's journal: one directory per run
    /// id under the task, each holding the attempt's journal file.
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs a conformed sandbox")]
    fn keep_dir_receives_every_journal() {
        let s = Scripted::all();
        let name = &s.names[0];
        let keeper = Fixture::new("minibench-keep").unwrap();
        let kept = keeper.base().join("kept");
        let (_, first) = s.run(name, Some(&kept), false);
        let (_, second) = s.run(name, Some(&kept), false);
        assert_ne!(first.run, second.run, "two runs, two ids");
        for report in [&first, &second] {
            let journal = kept
                .join(name.as_str())
                .join(report.run.as_str())
                .join("journal.jsonl");
            assert!(
                journal.is_file(),
                "no kept journal at {}",
                journal.display()
            );
            assert!(!std::fs::read(&journal).unwrap().is_empty());
        }
    }

    /// `--only NAME[,NAME]` runs the named fixtures only; a name that is
    /// no fixture is refused.
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs a conformed sandbox")]
    fn only_filter_runs_named_fixtures() {
        let s = Scripted::all();
        let want = vec![s.names[0].clone(), s.names[6].clone()];
        let names = select_names(&s.names, Some(&want)).unwrap();
        assert_eq!(names, want, "only the named fixtures, in order");
        assert!(
            select_names(&s.names, Some(&["no-such-fixture".to_owned()])).is_err(),
            "an unknown name is refused"
        );
        for name in &names {
            let (row, _) = s.run(name, None, false);
            assert_eq!(row.task, *name);
        }
    }

    /// `--profile FILE` is accepted and the row's `profile_sha` is that
    /// profile's `content_sha256` — the recorded profile's own digest,
    /// not the conservative default's.
    #[test]
    fn profile_file_sets_profile_sha_in_row() {
        let fx = Fixture::new("minibench-profile-file").unwrap();
        let file = fx.base().join("profile.json");
        std::fs::write(&file, PROFILE_JSON).unwrap();
        let profile = load_profile(&file).unwrap();
        let sha = profile.content_sha256().to_string();
        assert_ne!(
            sha,
            Profile::conservative_default("m")
                .content_sha256()
                .to_string(),
            "the recorded profile's digest is its own"
        );
        let row = Row {
            task: "t".into(),
            pass: true,
            steps: 1,
            tokens: 2,
            format_errors: 0,
            audit_fail: false,
            cause: "Submitted".into(),
        };
        let line = row.tsv("0.0.1", &sha);
        assert_eq!(line.split('\t').nth(1), Some(sha.as_str()), "line: {line}");
    }

    /// A profile file that does not validate (unknown field, bad shape,
    /// or missing) is refused before anything runs.
    #[test]
    fn invalid_profile_file_refused() {
        let fx = Fixture::new("minibench-profile-bad").unwrap();
        let file = fx.base().join("profile.json");
        std::fs::write(&file, r#"{"profile_version":1,"wat":true}"#).unwrap();
        let e = load_profile(&file).unwrap_err();
        assert!(e.contains("profile.json"), "{e}");
        let gone = fx.base().join("absent.json");
        assert!(load_profile(&gone).is_err(), "a missing file is refused");
    }

    /// A task that passed in the baseline and fails now is a regression:
    /// the gate fails.
    #[test]
    fn baseline_regression_on_newly_failing_task() {
        let fx = Fixture::new("minibench-baseline-regression").unwrap();
        let file = fx.base().join("baseline.tsv");
        std::fs::write(
            &file,
            "harness\tprofile_sha\ttask\tpass\tsteps\ttokens\tformat_errors\tcause\n\
             0.0.1\tsha\tt\tpass\t5\t0\t0\tSubmitted\n",
        )
        .unwrap();
        let b = parse_baseline(&file).unwrap();
        let now = Row {
            task: "t".into(),
            pass: false,
            steps: 5,
            tokens: 0,
            format_errors: 0,
            audit_fail: false,
            cause: "Submitted".into(),
        };
        let v = compare_baseline(&b, &[now], "0.0.1");
        assert!(v.failed, "a newly failing task fails the gate");
        assert!(v.notes.iter().any(|n| n.contains("REGRESSION")), "{v:?}");
    }

    /// Step growth is flagged and fails the gate only past both
    /// thresholds: more than 50% AND at least 3 steps.
    #[test]
    fn baseline_step_growth_flagged() {
        let row = |steps: u64| Row {
            task: "t".into(),
            pass: true,
            steps,
            tokens: 0,
            format_errors: 0,
            audit_fail: false,
            cause: "Submitted".into(),
        };
        let b = Baseline {
            rows: vec![BaselineRow {
                harness: "0.0.1".into(),
                task: "t".into(),
                pass: true,
                steps: 2,
            }],
        };
        let grown = compare_baseline(&b, &[row(6)], "0.0.1");
        assert!(grown.failed, "+4 on 2 is more than 50% and at least 3");
        assert!(grown.notes.iter().any(|n| n.contains("steps grew")));
        let small = compare_baseline(&b, &[row(4)], "0.0.1");
        assert!(!small.failed, "+2 is below the 3-step floor: {small:?}");
        let cheap = compare_baseline(&b, &[row(20)], "0.0.1");
        assert!(cheap.failed, "+18 on 2 is far past both thresholds");
    }

    /// Rows recorded by another harness version are still compared, but
    /// flagged — and alone they do not fail the gate.
    #[test]
    fn baseline_other_harness_version_flagged_not_failed() {
        let b = Baseline {
            rows: vec![BaselineRow {
                harness: "9.9.9".into(),
                task: "t".into(),
                pass: true,
                steps: 5,
            }],
        };
        let now = Row {
            task: "t".into(),
            pass: true,
            steps: 5,
            tokens: 0,
            format_errors: 0,
            audit_fail: false,
            cause: "Submitted".into(),
        };
        let v = compare_baseline(&b, &[now], "0.0.1");
        assert!(!v.failed, "a version difference alone is not a failure");
        assert!(
            v.notes
                .iter()
                .any(|n| n.contains("9.9.9") && n.contains("flagged")),
            "{v:?}"
        );
    }

    /// The `--repeat` gate: a task passes on a majority of its rows; a
    /// tie is a fail; tasks decide independently.
    #[test]
    fn repeat_majority_rule() {
        let row = |task: &str, pass: bool| Row {
            task: task.into(),
            pass,
            steps: 1,
            tokens: 0,
            format_errors: 0,
            audit_fail: false,
            cause: "Submitted".into(),
        };
        // 2 of 3: pass.
        assert!(gate_ok(&[row("t", true), row("t", false), row("t", true)]));
        // 1 of 2, a tie: fail.
        assert!(!gate_ok(&[row("t", true), row("t", false)]));
        // 0 of 2: fail.
        assert!(!gate_ok(&[row("t", false), row("t", false)]));
        // 1 of 1: pass.
        assert!(gate_ok(&[row("t", true)]));
        // Every task must pass: one failing task fails the gate.
        assert!(!gate_ok(
            &[row("a", true), row("b", true), row("b", false),]
        ));
    }

    /// The scripted bench against a recorded baseline of its own rows:
    /// the baseline passes, and doctoring one attempt into a failure is
    /// detected as a regression.
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs a conformed sandbox")]
    fn minibench_baseline_regression_detected() {
        let s = Scripted::all();
        let name = s.names[0].clone();
        let (row, _) = s.run(&name, None, false);
        let sha = s.profile.content_sha256().to_string();
        let fx = Fixture::new("minibench-baseline-scripted").unwrap();
        let file = fx.base().join("baseline.tsv");
        let mut text =
            String::from("harness\tprofile_sha\ttask\tpass\tsteps\ttokens\tformat_errors\tcause\n");
        text.push_str(&row.tsv(env!("CARGO_PKG_VERSION"), &sha));
        text.push('\n');
        std::fs::write(&file, &text).unwrap();
        let b = parse_baseline(&file).unwrap();

        // As recorded: no regression.
        let ok = compare_baseline(&b, std::slice::from_ref(&row), env!("CARGO_PKG_VERSION"));
        assert!(!ok.failed, "the baseline of its own rows passes: {ok:?}");

        // The same task failing now: detected.
        let mut failed_row = row.clone();
        failed_row.pass = false;
        let v = compare_baseline(&b, &[failed_row], env!("CARGO_PKG_VERSION"));
        assert!(v.failed, "a scripted pass turned fail is a regression");
        assert!(v.notes.iter().any(|n| n.contains("REGRESSION")));
    }
}
