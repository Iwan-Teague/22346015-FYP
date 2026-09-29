//! `rustybench` — the CLI. Grades a task (frozen file or seeded generator)
//! against an OpenAI-compatible model, under the sandbox, and appends a scored
//! JSONL line. Also `validate-family`, which runs a family's own construction
//! gates: the reference must score 1.0, the skeleton must fail, generation must
//! be deterministic (ADR-0003).

use bench_core::{
    FailureClass, Instance, OracleVector, OracleWeights, Seed, TaskId, WorkUnit, MIRI_CATEGORY,
};
use bench_model::{ModelClient, SamplingConfig};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "rustybench",
    version,
    about = "Rust coding benchmark for local LLMs"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a task against a model and append a graded journal line.
    Run {
        /// A frozen task directory (contains task.toml). Mutually exclusive with --family.
        #[arg(long)]
        task: Option<PathBuf>,
        /// A generator family id (e.g. `window-op`), used with --seed.
        #[arg(long)]
        family: Option<String>,
        /// The seed for --family.
        #[arg(long)]
        seed: Option<u64>,
        /// OpenAI-compatible base URL, e.g. http://localhost:8080
        #[arg(long)]
        model: String,
        #[arg(long, default_value = "local")]
        model_name: String,
        #[arg(long, default_value = "runs/journal.jsonl")]
        out: PathBuf,
        #[arg(long, default_value = "runs/ws")]
        scratch: PathBuf,
        #[arg(long, default_value_t = 120)]
        wall_timeout_secs: u64,
        /// Explicitly accept grading with no containment (AQ-194). Off-macOS
        /// the run refuses without this; the journal row records the opt-in.
        #[arg(long)]
        allow_unsandboxed: bool,
    },
    /// Run a family's construction gates over a range of seeds (no model).
    ValidateFamily {
        #[arg(long)]
        family: String,
        /// Number of seeds to check, starting from 0.
        #[arg(long, default_value_t = 8)]
        seeds: u64,
        #[arg(long, default_value = "runs/validate")]
        scratch: PathBuf,
        /// Explicitly accept executing code with no containment (AQ-194).
        /// The code is the family's own in-tree reference/skeleton, but it is
        /// still compiled and run, so the gate applies here too.
        #[arg(long)]
        allow_unsandboxed: bool,
    },
    /// Aggregate a graded journal into capability/pass-rate and cluster-bootstrap CIs.
    Stats {
        /// Path to a JSONL journal written by `run`.
        #[arg(long, default_value = "runs/journal.jsonl")]
        journal: PathBuf,
        /// Explicitly accept aggregating a journal graded with NO containment
        /// (AQ-194, r54 R2). The output is labelled UNCONTAINED throughout.
        #[arg(long)]
        allow_uncontained: bool,
    },
    /// Render a journal into a formatted report: headline numbers, per-category
    /// table with CIs, and the failure-class/error-code histograms (docs/08, P5).
    Report {
        #[arg(long, default_value = "runs/journal.jsonl")]
        journal: PathBuf,
        /// Output format: `md` (default) or `json`.
        #[arg(long, default_value = "md")]
        format: String,
        /// Explicitly accept reporting a journal graded with NO containment
        /// (AQ-194, r54 R2). The output is labelled UNCONTAINED throughout.
        #[arg(long)]
        allow_uncontained: bool,
    },
    /// Compare two models (McNemar on the shared pass bits + paired pass-rate CI).
    Compare {
        #[arg(long)]
        journal_a: PathBuf,
        #[arg(long)]
        journal_b: PathBuf,
        /// Explicitly accept comparing journals graded with NO containment
        /// (AQ-194, r54 R2). Both journals must be uncontained; the output is
        /// labelled UNCONTAINED throughout. A contained/uncontained pair is
        /// refused regardless.
        #[arg(long)]
        allow_uncontained: bool,
    },
    /// Precomputation detector: sign test on family-paired core-vs-probe discordance.
    Detect {
        #[arg(long, default_value = "runs/journal.jsonl")]
        journal: PathBuf,
        /// Explicitly accept running the detector over a journal graded with NO
        /// containment (AQ-194, r59 F-1). The verdicts are labelled UNCONTAINED.
        #[arg(long)]
        allow_uncontained: bool,
    },
    /// Progress, ETA and segment history for an epoch — the resume readout (docs/08).
    Status {
        #[arg(long, default_value = "runs/journal.jsonl")]
        journal: PathBuf,
        /// Epoch to report; defaults to the most recent epoch in the journal.
        #[arg(long)]
        epoch: Option<String>,
        /// Paired-core seeds per family the run targets (to size the plan).
        #[arg(long, default_value_t = 4)]
        seeds_core: u32,
        /// Fresh-probe seeds per family the run targets.
        #[arg(long, default_value_t = 1)]
        seeds_probe: u32,
    },
    /// Run a whole epoch over every family: paired-core + fresh-probe seeds, resumable.
    RunSuite {
        #[arg(long)]
        model: String,
        #[arg(long, default_value = "local")]
        model_name: String,
        /// Epoch label — fixes the paired-core seed set (ADR-0009).
        #[arg(long)]
        epoch: String,
        /// Paired-core seeds per family (scored).
        #[arg(long, default_value_t = 4)]
        seeds_core: u32,
        /// Fresh-probe seeds per family (precomputation detector; never scored).
        #[arg(long, default_value_t = 1)]
        seeds_probe: u32,
        #[arg(long, default_value = "runs/journal.jsonl")]
        out: PathBuf,
        #[arg(long, default_value = "runs/ws")]
        scratch: PathBuf,
        #[arg(long, default_value_t = 120)]
        wall_timeout_secs: u64,
        /// Print the plan (after resume filtering) without calling the model.
        #[arg(long)]
        dry_run: bool,
        /// Explicitly accept grading with no containment (AQ-194). Off-macOS
        /// the epoch refuses without this; every journalled row records it.
        #[arg(long)]
        allow_unsandboxed: bool,
    },
}

/// Everything needed to grade one task, from either source.
struct Task {
    id: String,
    category: String,
    system_prompt: String,
    prompt: String,
    instance: Instance,
    answer_path: String,
    weights: OracleWeights,
    behavior_test: Option<String>,
    differential_test: Option<String>,
    alloc_test: Option<String>,
    max_unsafe: Option<u32>,
    forbidden_paths: Vec<String>,
    check_clippy: bool,
    clippy_allow: Vec<String>,
}

// The one category whose oracle runs miri (docs/04 category 5). `ffi-boundary`
// is deliberately excluded: miri cannot execute foreign calls. The constant
// lives in bench-core next to the refusal vocabulary (AQ-202) so the gate, the
// oracle and the stats side cannot drift apart.

const GENERIC_SYSTEM_PROMPT: &str = "You are an expert Rust programmer. Respond with a SINGLE ```rust code block containing the complete contents of src/lib.rs. No prose, no explanation, no other text.";

/// The gate a `--allow-unsandboxed` flag selects (AQ-194). The default is the
/// fail-closed one: grade only where containment exists.
fn containment_gate(allow_unsandboxed: bool) -> bench_sandbox::Gate {
    if allow_unsandboxed {
        bench_sandbox::Gate::AllowUnsandboxed
    } else {
        bench_sandbox::Gate::RequireContained
    }
}

/// Fail-closed pre-flight, run BEFORE the model is contacted or anything is
/// built. This is the same single predicate ([`bench_sandbox::check_gate`]) the
/// sandbox layer enforces again at spawn time, so the refusal is stated once
/// and enforced twice — a command that forgets this pre-flight still hits the
/// gate. `Some(message)` = refuse with a non-zero exit.
fn unsandboxed_refusal(
    containment: bench_sandbox::Containment,
    gate: bench_sandbox::Gate,
) -> Option<String> {
    bench_sandbox::check_gate(gate, containment)
        .err()
        .map(|e| e.to_string())
}

/// AQ-202/OI-36c pre-flight (predicate half): miri is *mandatory* for
/// `unsafe-core`, so a command that cannot run miri refuses the whole task
/// BEFORE the model is contacted or anything is built. `miri_ok` is the result
/// of [`bench_oracle::miri_preflight`]. `Some(message)` = refuse with a
/// non-zero exit.
fn miri_available_refusal(miri_ok: bool) -> Option<String> {
    (!miri_ok).then(|| {
        "refusing: miri is MANDATORY for unsafe-core tasks (AQ-202, OI-36c) but this host \
         has no nightly toolchain with the miri component. Install it with: \
         `rustup toolchain install nightly --component miri` — or grade a non-miri task."
            .to_string()
    })
}

/// AQ-202/OI-36c pre-flight (predicate half) for a whole suite or family: the
/// same refusal as [`miri_available_refusal`], plus the task-shape clause — a
/// `unsafe-core` grade with neither a behaviour nor a differential test target
/// gives miri nothing to interpret, so the mandatory stage can never produce a
/// verdict and the command refuses up front instead of burning a build first.
/// `Some(message)` = refuse with a non-zero exit.
fn miri_task_refusal(
    miri_ok: bool,
    category: &str,
    behavior_test: Option<&str>,
    differential_test: Option<&str>,
) -> Option<String> {
    if category != MIRI_CATEGORY {
        return None;
    }
    if behavior_test.is_none() && differential_test.is_none() {
        return Some(format!(
            "refusing: task category '{MIRI_CATEGORY}' is miri-mandatory (AQ-202, OI-36c) \
             but declares no behaviour/differential test target, so miri has nothing to \
             interpret — the task cannot be graded"
        ));
    }
    miri_available_refusal(miri_ok)
}

/// The journal's `sandbox` value plus the explicit opt-in marker (AQ-194).
/// Uncontained rows are `"unsupported"`; one produced under
/// [`bench_sandbox::Gate::AllowUnsandboxed`] additionally carries
/// `sandbox_opted_in = true`, which `bench-stats` treats as non-comparable.
fn journal_sandbox_fields(
    containment: bench_sandbox::Containment,
    gate: bench_sandbox::Gate,
) -> (&'static str, Option<bool>) {
    match (containment, gate) {
        (bench_sandbox::Containment::Seatbelt, _) => ("seatbelt", None),
        (bench_sandbox::Containment::Unsupported, bench_sandbox::Gate::AllowUnsandboxed) => {
            ("unsupported", Some(true))
        }
        (bench_sandbox::Containment::Unsupported, bench_sandbox::Gate::RequireContained) => {
            // Only reachable in the journal of a row that predates the gate;
            // `run`/`run-suite` refuse this combination up front.
            ("unsupported", None)
        }
    }
}

/// The aggregation-side twin of the execution gate (AQ-194, r54 R2): an
/// all-uncontained journal must not produce capability/pass-rate numbers
/// silently — the operator must opt in here too, exactly as `run` required
/// `--allow-unsandboxed`. `Some(message)` = refuse with a non-zero exit.
fn uncontained_aggregation_refusal(class: &str, allow_uncontained: bool) -> Option<String> {
    if class != "uncontained" || allow_uncontained {
        return None;
    }
    Some(
        "every row in this journal was graded with NO containment — refusing to \
         aggregate it silently (the numbers are not comparable with sandboxed \
         runs); pass --allow-uncontained to accept, and the output will be \
         labelled UNCONTAINED"
            .to_string(),
    )
}

/// The label every aggregate output carries when its journal is uncontained
/// (AQ-194, r54 R2). `None` for a contained journal — contained output is not
/// annotated.
fn uncontained_banner(class: &str) -> Option<&'static str> {
    (class != "contained").then(|| bench_stats::containment_note(class))
}

/// The per-line suffix stats and detect append to every number they print when
/// the journal is uncontained (AQ-194, r54 R2; r59 F-1 extends it to detect).
fn uncontained_suffix(class: &str) -> &'static str {
    if class == "uncontained" {
        " (UNCONTAINED)"
    } else {
        ""
    }
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Run {
            task,
            family,
            seed,
            model,
            model_name,
            out,
            scratch,
            wall_timeout_secs,
            allow_unsandboxed,
        } => {
            let t = load_task(task.as_deref(), family.as_deref(), seed)?;
            run(
                t,
                &model,
                &model_name,
                &out,
                &scratch,
                wall_timeout_secs,
                containment_gate(allow_unsandboxed),
            )
        }
        Command::ValidateFamily {
            family,
            seeds,
            scratch,
            allow_unsandboxed,
        } => validate_family(
            &family,
            seeds,
            &scratch,
            containment_gate(allow_unsandboxed),
        ),
        Command::Stats {
            journal,
            allow_uncontained,
        } => stats(&journal, allow_uncontained),
        Command::Report {
            journal,
            format,
            allow_uncontained,
        } => report(&journal, &format, allow_uncontained),
        Command::Compare {
            journal_a,
            journal_b,
            allow_uncontained,
        } => compare(&journal_a, &journal_b, allow_uncontained),
        Command::Detect {
            journal,
            allow_uncontained,
        } => detect(&journal, allow_uncontained),
        Command::Status {
            journal,
            epoch,
            seeds_core,
            seeds_probe,
        } => status(&journal, epoch.as_deref(), seeds_core, seeds_probe),
        Command::RunSuite {
            model,
            model_name,
            epoch,
            seeds_core,
            seeds_probe,
            out,
            scratch,
            wall_timeout_secs,
            dry_run,
            allow_unsandboxed,
        } => run_suite(
            &model,
            &model_name,
            &epoch,
            seeds_core,
            seeds_probe,
            &out,
            &scratch,
            wall_timeout_secs,
            dry_run,
            containment_gate(allow_unsandboxed),
        ),
    }
}

// ---------------------------------------------------------------------------
// Task loading
// ---------------------------------------------------------------------------

fn load_task(
    task_dir: Option<&Path>,
    family: Option<&str>,
    seed: Option<u64>,
) -> Result<Task, Box<dyn std::error::Error>> {
    match (task_dir, family) {
        (Some(dir), None) => load_frozen(dir),
        (None, Some(fam)) => {
            let seed = seed.ok_or("--family requires --seed")?;
            load_generated(fam, seed)
        }
        _ => Err("provide exactly one of --task or --family".into()),
    }
}

#[derive(Deserialize)]
struct TaskManifest {
    id: String,
    category: String,
    #[allow(dead_code)]
    kind: String,
    answer_path: String,
    system_prompt: String,
    #[serde(default)]
    weights: Option<Weights>,
    #[serde(default)]
    oracle: Option<OracleCfg>,
    #[serde(default)]
    constraint: Option<ConstraintCfg>,
}
#[derive(Deserialize)]
struct Weights {
    behavior: f32,
    constraint: f32,
    quality: f32,
}
#[derive(Deserialize, Default)]
struct OracleCfg {
    behavior_test: Option<String>,
    differential_test: Option<String>,
    alloc_test: Option<String>,
}
#[derive(Deserialize, Default)]
struct ConstraintCfg {
    max_unsafe: Option<u32>,
    #[serde(default)]
    forbidden_paths: Vec<String>,
}

fn load_frozen(task_dir: &Path) -> Result<Task, Box<dyn std::error::Error>> {
    let manifest_text = std::fs::read_to_string(task_dir.join("task.toml"))
        .map_err(|e| format!("reading task.toml in {}: {e}", task_dir.display()))?;
    let m: TaskManifest = toml::from_str(&manifest_text)?;
    let files = read_tree(&task_dir.join("template"))?;
    let hidden = read_tree(&task_dir.join("oracle"))?;
    let prompt = std::fs::read_to_string(task_dir.join("prompt.md"))
        .map_err(|e| format!("reading prompt.md: {e}"))?;
    let ocfg = m.oracle.unwrap_or_default();
    let ccfg = m.constraint.unwrap_or_default();
    let weights = m
        .weights
        .map(|w| OracleWeights {
            behavior: w.behavior,
            constraint: w.constraint,
            quality: w.quality,
        })
        .unwrap_or_default();
    let canary = format!("rb-frozen-{}", m.id);
    Ok(Task {
        id: m.id.clone(),
        category: m.category,
        system_prompt: m.system_prompt,
        prompt: prompt.clone(),
        instance: Instance {
            prompt,
            files,
            hidden,
            canary,
        },
        answer_path: m.answer_path,
        weights,
        behavior_test: ocfg.behavior_test,
        differential_test: ocfg.differential_test,
        alloc_test: ocfg.alloc_test,
        max_unsafe: ccfg.max_unsafe,
        forbidden_paths: ccfg.forbidden_paths,
        // Frozen tasks do not declare clippy grading (no idiom-refactor frozen task).
        check_clippy: false,
        clippy_allow: Vec::new(),
    })
}

fn load_generated(fam: &str, seed: u64) -> Result<Task, Box<dyn std::error::Error>> {
    let g = bench_gen::family(fam).ok_or_else(|| format!("unknown family `{fam}`"))?;
    Ok(task_from_generated(&g.generate(seed)))
}

/// Map an empty test-target name to `None` (a family opts out of a layer by
/// leaving its target blank).
fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn task_from_generated(gt: &bench_gen::GeneratedTask) -> Task {
    Task {
        id: gt.id.clone(),
        category: gt.category.clone(),
        system_prompt: GENERIC_SYSTEM_PROMPT.to_string(),
        prompt: gt.prompt.clone(),
        instance: gt.instance(),
        answer_path: gt.answer_path.clone(),
        weights: OracleWeights {
            behavior: gt.weights.0,
            constraint: gt.weights.1,
            quality: gt.weights.2,
        },
        behavior_test: non_empty(&gt.behavior_test),
        differential_test: non_empty(&gt.differential_test),
        alloc_test: non_empty(&gt.alloc_test),
        max_unsafe: gt.max_unsafe,
        forbidden_paths: gt.forbidden_paths.clone(),
        check_clippy: gt.check_clippy,
        clippy_allow: gt.clippy_allow.clone(),
    }
}

// ---------------------------------------------------------------------------
// Grading
// ---------------------------------------------------------------------------

/// Grade a response string against a task in a fresh workspace under `scratch`.
/// `gate` carries the operator's containment decision (AQ-194): `RequireContained`
/// for model output unless `--allow-unsandboxed` was passed.
#[allow(clippy::too_many_arguments)]
fn grade(
    task: &Task,
    response: &str,
    scratch_root: &Path,
    tag: &str,
    wall_timeout_secs: u64,
    gate: bench_sandbox::Gate,
) -> Result<OracleVector, Box<dyn std::error::Error>> {
    let ws = scratch_root.join(tag);
    if ws.exists() {
        std::fs::remove_dir_all(&ws)?;
    }
    std::fs::create_dir_all(&ws)?;
    let limits = bench_sandbox::Limits {
        wall: std::time::Duration::from_secs(wall_timeout_secs),
        cpu: std::time::Duration::from_secs(wall_timeout_secs.saturating_mul(30)),
        address_space: None,
    };
    let spec = bench_oracle::GradeSpec {
        answer_path: Path::new(&task.answer_path),
        weights: &task.weights,
        behavior_test: task.behavior_test.as_deref(),
        differential_test: task.differential_test.as_deref(),
        alloc_test: task.alloc_test.as_deref(),
        limits,
        max_unsafe: task.max_unsafe,
        forbidden_paths: task.forbidden_paths.clone(),
        check_clippy: task.check_clippy,
        clippy_allow: task.clippy_allow.clone(),
        // docs/03 §L3 and docs/04 category 5: miri is mandatory for
        // `unsafe-core` and off everywhere else (it is slow). The mandate is a
        // property of the category, not of the family, so it is derived here
        // rather than declared per family.
        check_miri: task.category == MIRI_CATEGORY,
        gate,
        // AQ-215: the workspace is created under `scratch_root` (line above),
        // so the oracle's config-discovery bound and harness cargo home pin
        // use exactly that root.
        scratch_root: scratch_root.to_path_buf(),
    };
    Ok(bench_oracle::grade(&task.instance, response, &spec, &ws)?)
}

fn run(
    task: Task,
    base_url: &str,
    model_name: &str,
    out: &Path,
    scratch_root: &Path,
    wall_timeout_secs: u64,
    gate: bench_sandbox::Gate,
) -> Result<(), Box<dyn std::error::Error>> {
    // AQ-194: refuse BEFORE contacting the model or building anything, unless
    // the operator explicitly opted in.
    if let Some(msg) = unsandboxed_refusal(bench_sandbox::available(), gate) {
        return Err(msg.into());
    }
    // AQ-202/OI-36c: a miri-mandatory task refuses before model contact when
    // this host cannot run the mandatory stage — a grade without miri can
    // never be a legitimate pass, so it must not even start.
    if task.category == MIRI_CATEGORY {
        let miri_ok = bench_oracle::miri_preflight(scratch_root, wall_timeout_secs, gate).is_ok();
        if let Some(msg) = miri_task_refusal(
            miri_ok,
            &task.category,
            task.behavior_test.as_deref(),
            task.differential_test.as_deref(),
        ) {
            return Err(msg.into());
        }
    }
    let containment = match bench_sandbox::available() {
        bench_sandbox::Containment::Seatbelt => "seatbelt",
        bench_sandbox::Containment::Unsupported => "unsupported",
    };
    if containment == "unsupported" {
        eprintln!("  ! WARNING: grading UNSANDBOXED by explicit --allow-unsandboxed — model code runs with full host access; journal rows are marked non-comparable");
    }
    println!(
        "→ {} against {base_url} ({model_name}) [sandbox: {containment}]",
        task.id
    );

    let line = grade_and_line(
        &task,
        base_url,
        model_name,
        scratch_root,
        wall_timeout_secs,
        "local",
        "core",
        0,
        0,
        None,
        None,
        gate,
    )?;
    append_journal(out, &line)?;

    let v = &line.oracle;
    println!(
        "  score {:.3}  apply={} compile={} unit={:?} diff={:?} behavior={:?} constraint={:?} failure={:?}",
        v.score,
        v.apply_ok,
        v.compile_ok,
        v.behavior.unit,
        v.behavior.differential,
        v.behavior.score,
        v.constraint.score,
        v.failure_class
    );
    // AQ-202/OI-36c: the mandatory stage ran mid-grade and produced no verdict.
    // The row is already journalled (with an Indeterminate class and zero
    // score); say loudly that it will not be scored.
    if line.failure_class == FailureClass::Indeterminate {
        eprintln!(
            "  ! REFUSED: mandatory miri stage produced no verdict — row journalled but \
             excluded from stats/report (AQ-202/OI-36c)"
        );
    }
    if !v.error_codes.is_empty() {
        println!("  rustc: {}", v.error_codes.join(", "));
    }
    if !v.flags.is_empty() {
        println!("  flags: {}", v.flags.join(", "));
    }
    println!("  journal → {}", out.display());
    Ok(())
}

/// Call the model on one task, grade the response under the sandbox, and build the
/// journal line — the single-unit core shared by `run` and `run-suite`.
#[allow(clippy::too_many_arguments)]
fn grade_and_line(
    task: &Task,
    base_url: &str,
    model_name: &str,
    scratch_root: &Path,
    wall_timeout_secs: u64,
    epoch: &str,
    kind: &str,
    seed: u64,
    index: u32,
    segment: Option<u32>,
    segment_position: Option<u32>,
    gate: bench_sandbox::Gate,
) -> Result<JournalLine, Box<dyn std::error::Error>> {
    let (containment, sandbox_opted_in) = journal_sandbox_fields(bench_sandbox::available(), gate);
    let client = ModelClient::new(base_url, model_name);
    let completion = client.complete(
        &task.system_prompt,
        &task.prompt,
        &SamplingConfig::default(),
    )?;
    println!(
        "  ← {} completion tokens, finish={}, {} ms",
        completion.completion_tokens, completion.finish_reason, completion.elapsed_ms
    );

    let unit = WorkUnit {
        task_id: TaskId(task.id.clone()),
        seed: Seed(seed),
        index,
    };
    let tag = unit.unit_id().0.replace(':', "_");
    let grade_start = std::time::Instant::now();
    let vector = grade(
        task,
        &completion.text,
        scratch_root,
        &tag,
        wall_timeout_secs,
        gate,
    )?;
    let grade_ms = grade_start.elapsed().as_millis() as u64;

    Ok(JournalLine {
        schema: 1,
        unit_id: unit.unit_id().0,
        task_id: task.id.clone(),
        category: task.category.clone(),
        seed,
        index,
        epoch: epoch.to_string(),
        kind: kind.to_string(),
        segment,
        segment_position,
        model: ModelInfo {
            name: model_name.to_string(),
            base_url: base_url.to_string(),
            finish_reason: completion.finish_reason.clone(),
        },
        sandbox: containment.to_string(),
        sandbox_opted_in,
        oracle: vector.clone(),
        cost: Cost {
            prompt_tokens: completion.prompt_tokens,
            completion_tokens: completion.completion_tokens,
            gen_ms: completion.elapsed_ms,
            grade_ms,
        },
        failure_class: vector.failure_class,
    })
}

// ---------------------------------------------------------------------------
// run-suite — epoch orchestration with paired-core / fresh-probe + resume
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn run_suite(
    base_url: &str,
    model_name: &str,
    epoch: &str,
    n_core: u32,
    n_probe: u32,
    out: &Path,
    scratch_root: &Path,
    wall_timeout_secs: u64,
    dry_run: bool,
    gate: bench_sandbox::Gate,
) -> Result<(), Box<dyn std::error::Error>> {
    let plan = bench_gen::epoch::plan_run(bench_gen::FAMILY_IDS, epoch, n_core, n_probe);
    let done = read_done_keys(out, epoch)?;
    let todo = bench_gen::epoch::remaining(&plan, &done);
    println!(
        "epoch {epoch}: {} units planned ({} core + {} probe over {} families), {} done, {} to run",
        plan.len(),
        n_core as usize * bench_gen::FAMILY_IDS.len(),
        n_probe as usize * bench_gen::FAMILY_IDS.len(),
        bench_gen::FAMILY_IDS.len(),
        plan.len() - todo.len(),
        todo.len(),
    );

    if dry_run {
        for u in &todo {
            println!(
                "  [plan] {:<14} {:<5} idx={} seed={:016x}",
                u.family,
                u.kind.as_str(),
                u.index,
                u.seed
            );
        }
        println!("(dry run — no model calls)");
        return Ok(());
    }

    // AQ-194: refuse before any model call, but only for runs that would
    // actually execute code — a dry run contacts nothing and builds nothing.
    if let Some(msg) = unsandboxed_refusal(bench_sandbox::available(), gate) {
        return Err(msg.into());
    }
    // AQ-202/OI-36c: if ANY unit still to run in this suite is miri-mandatory,
    // the whole suite refuses when miri is unavailable. Grading everything
    // else and skipping the unsafe-core units would silently punch a hole in
    // the epoch's coverage that no journal/status view exposes; refusing the
    // suite makes the gap loud instead. (Already-done unsafe-core units are
    // exempt here — they were graded under the pre-AQ-202 rule and are
    // refused at aggregation time by bench-stats.)
    let any_unsafe_core = todo.iter().any(|u| {
        bench_gen::family(&u.family)
            .map(|g| g.category() == MIRI_CATEGORY)
            .unwrap_or(false)
    });
    if any_unsafe_core {
        let miri_ok = bench_oracle::miri_preflight(scratch_root, wall_timeout_secs, gate).is_ok();
        if let Some(msg) = miri_available_refusal(miri_ok) {
            return Err(msg.into());
        }
    }
    if bench_sandbox::available() == bench_sandbox::Containment::Unsupported {
        eprintln!("  ! WARNING: grading UNSANDBOXED by explicit --allow-unsandboxed — model code runs with full host access; journal rows are marked non-comparable");
    }
    // A segment is this run session (docs/09). A resume starts a fresh segment, so
    // its first units are cold-cache and excluded from throughput (docs/08). The
    // index is one past the highest already journalled for this epoch.
    let segment = next_segment(out, epoch)?;
    println!("epoch {epoch}: segment {segment} (this session)");

    let mut ran = 0usize;
    for (pos, u) in todo.iter().enumerate() {
        let g =
            bench_gen::family(&u.family).ok_or_else(|| format!("unknown family {}", u.family))?;
        let task = task_from_generated(&g.generate(u.seed));
        println!(
            "→ {} {} idx={} (seed {:016x})  [seg {segment} pos {pos}]",
            u.family,
            u.kind.as_str(),
            u.index,
            u.seed
        );
        let line = grade_and_line(
            &task,
            base_url,
            model_name,
            scratch_root,
            wall_timeout_secs,
            epoch,
            u.kind.as_str(),
            u.seed,
            u.index,
            Some(segment),
            Some(pos as u32),
            gate,
        )?;
        println!(
            "  score {:.3} pass={}",
            line.oracle.score,
            line.oracle.passed()
        );
        // AQ-202/OI-36c: mid-run gap in a miri-mandatory grade. The row is
        // journalled Indeterminate/zero-score; say it will not be scored.
        if line.failure_class == FailureClass::Indeterminate {
            eprintln!(
                "  ! REFUSED: mandatory miri stage produced no verdict — row journalled but \
                 excluded from stats/report (AQ-202/OI-36c)"
            );
        }
        append_journal(out, &line)?;
        ran += 1;
    }
    println!(
        "epoch {epoch}: segment {segment} ran {ran} unit(s); journal → {}",
        out.display()
    );
    Ok(())
}

/// The next segment index for `epoch`: one past the highest already recorded, or 0
/// if this is the epoch's first session. Units carry `segment` so a resumed run
/// (a new session, cold caches) is distinguishable from the original (docs/09).
fn next_segment(out: &Path, epoch: &str) -> Result<u32, Box<dyn std::error::Error>> {
    #[derive(Deserialize)]
    struct SegLine {
        #[serde(default)]
        epoch: String,
        #[serde(default)]
        segment: Option<u32>,
    }
    let text = match std::fs::read_to_string(out) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    let mut max_seg: Option<u32> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let s: SegLine = serde_json::from_str(line)?;
        if s.epoch != epoch {
            continue;
        }
        if let Some(seg) = s.segment {
            max_seg = Some(max_seg.map_or(seg, |m| m.max(seg)));
        }
    }
    Ok(max_seg.map_or(0, |m| m + 1))
}

/// Read the resume set: the `family|kind|index` keys already recorded for `epoch`.
fn read_done_keys(
    out: &Path,
    epoch: &str,
) -> Result<std::collections::HashSet<String>, Box<dyn std::error::Error>> {
    #[derive(Deserialize)]
    struct DoneLine {
        task_id: String,
        index: u32,
        #[serde(default)]
        epoch: String,
        #[serde(default)]
        kind: String,
    }
    let mut done = std::collections::HashSet::new();
    let text = match std::fs::read_to_string(out) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(done),
        Err(e) => return Err(e.into()),
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let d: DoneLine = serde_json::from_str(line)?;
        if d.epoch != epoch {
            continue;
        }
        let family = d.task_id.split('/').next().unwrap_or(&d.task_id);
        done.insert(format!("{}|{}|{}", family, d.kind, d.index));
    }
    Ok(done)
}

// ---------------------------------------------------------------------------
// validate-family
// ---------------------------------------------------------------------------

fn validate_family(
    fam: &str,
    seeds: u64,
    scratch: &Path,
    gate: bench_sandbox::Gate,
) -> Result<(), Box<dyn std::error::Error>> {
    // AQ-194: the family's own reference/skeleton/baselines are in-tree and
    // trusted, but they are still *compiled and executed* (proc macros run at
    // build time), so the same containment gate applies.
    if let Some(msg) = unsandboxed_refusal(bench_sandbox::available(), gate) {
        return Err(msg.into());
    }
    let g = bench_gen::family(fam).ok_or_else(|| format!("unknown family `{fam}`"))?;
    // AQ-202/OI-36c: a miri-mandatory family can only be certified when the
    // mandatory stage can actually run — validating it without miri would
    // bless a family whose real grades always refuse.
    if g.category() == MIRI_CATEGORY {
        let miri_ok = bench_oracle::miri_preflight(scratch, 120, gate).is_ok();
        if let Some(msg) = miri_available_refusal(miri_ok) {
            return Err(msg.into());
        }
    }
    println!("validate-family {fam}: {seeds} seed(s)");
    let mut failures = 0u32;
    let mut views: Vec<String> = Vec::new();

    for seed in 0..seeds {
        let gt = g.generate(seed);
        let task = task_from_generated(&gt);
        views.push(bench_gen::epoch::view_of(&gt));

        let gt2 = g.generate(seed);
        let deterministic =
            gt.prompt == gt2.prompt && gt.files == gt2.files && gt.hidden == gt2.hidden;

        let ref_v = grade(
            &task,
            &g.reference_code(seed),
            scratch,
            &format!("ref-{seed}"),
            120,
            gate,
        )?;

        let skel_v = grade(
            &task,
            &g.skeleton_code(seed),
            scratch,
            &format!("skel-{seed}"),
            120,
            gate,
        )?;
        let skel_behavior = skel_v.behavior.score.unwrap_or(0.0);

        // A degenerate answer is "caught" iff it does not achieve a full pass — i.e.
        // its *composite* is below 1.0. Gating on the composite (not behaviour)
        // generalises to quality-ablated families like `idiom-refactor`, whose
        // skeleton and `unchanged` baseline are behaviourally correct but fail the
        // clippy constraint. For the todo!()-ablated families the composite is ~0, so
        // the gate is unchanged in practice.
        let caught = |v: &OracleVector| v.score < 0.99;

        let mut baselines_ok = true;
        let mut baseline_note = String::new();
        for (label, code) in g.trivial_baselines(seed) {
            let v = grade(
                &task,
                &code,
                scratch,
                &format!("base-{seed}-{label}"),
                120,
                gate,
            )?;
            if !caught(&v) {
                baselines_ok = false;
                baseline_note =
                    format!(" <-- baseline `{label}` not caught (score {:.3})", v.score);
            }
        }

        let canary_ok = gt.prompt.contains(&gt.canary);

        // Q14 gate — clippy-graded families only: `cargo clippy --fix` must NOT
        // mechanically solve the given (skeleton) code, or the task is trivially
        // auto-solvable and measures transcription, not reasoning. Passes iff clippy
        // lints remain after `--fix`.
        let (clippy_fix_ok, clippy_fix_note) = if task.check_clippy {
            let fix_ws = scratch.join(format!("fix-{seed}"));
            if fix_ws.exists() {
                std::fs::remove_dir_all(&fix_ws)?;
            }
            std::fs::create_dir_all(&fix_ws)?;
            let limits = bench_sandbox::Limits {
                wall: std::time::Duration::from_secs(120),
                cpu: std::time::Duration::from_secs(120 * 30),
                address_space: None,
            };
            let remaining = bench_oracle::clippy_fix_remaining_lints(
                &gt.files,
                &task.clippy_allow,
                limits,
                gate,
                &fix_ws,
                scratch,
            )?;
            let ok = !remaining.is_empty();
            let note = if ok {
                format!(
                    " clippy_fix_safe=true ({} lint(s) survive --fix)",
                    remaining.len()
                )
            } else {
                " clippy_fix_safe=false <-- clippy --fix solves it (Q14)".to_string()
            };
            (ok, note)
        } else {
            (true, String::new())
        };

        let ref_ok = ref_v.score >= 0.99;
        let skel_ok = caught(&skel_v);
        let all = deterministic && ref_ok && skel_ok && baselines_ok && canary_ok && clippy_fix_ok;
        if !all {
            failures += 1;
        }
        println!(
            "  seed {seed:>3}: {} determinism={} reference={:.3}{} skeleton={:.3} (behavior {:.3}){} baselines_caught={}{} canary={}{}",
            if all { "OK  " } else { "FAIL" },
            deterministic,
            ref_v.score,
            if ref_ok { "" } else { " <-- expected 1.0" },
            skel_v.score,
            skel_behavior,
            if skel_ok { "" } else { " <-- expected <1.0" },
            baselines_ok,
            baseline_note,
            canary_ok,
            clippy_fix_note,
        );
    }

    if views.len() >= 2 {
        let floor = bench_gen::epoch::MIN_INSTANCE_DISTANCE;

        // (min, median, near-twin pairs, total pairs) over a set of texts.
        fn dist_stats(items: &[String], floor: f64) -> (f64, f64, u32, usize) {
            let mut all_d: Vec<f64> = Vec::new();
            let mut near = 0u32;
            for i in 0..items.len() {
                for j in (i + 1)..items.len() {
                    let d = bench_gen::distance::shingle_distance(
                        &items[i],
                        &items[j],
                        bench_gen::distance::K,
                    );
                    all_d.push(d);
                    if d < floor {
                        near += 1;
                    }
                }
            }
            all_d.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let min = all_d.first().copied().unwrap_or(1.0);
            let median = all_d[all_d.len() / 2];
            (min, median, near, all_d.len())
        }

        // What the model sees. Gameable: seed-varied worked examples inflate this
        // without changing the answer (Q31), so a healthy line here is necessary
        // but NOT sufficient.
        let (vmin, vmed, vnear, vtot) = dist_stats(&views, floor);
        println!(
            "  anti-twin  view (prompt+skeleton): min={vmin:.3} median={vmed:.3} near-twin pairs (<{floor})={vnear}/{vtot}"
        );

        // The honest anti-memorisation-of-solution measure: distance between the
        // references. Not inflated by example variation (but deflated by shared
        // boilerplate — see Q31).
        let refs: Vec<String> = (0..seeds).map(|s| g.reference_code(s)).collect();
        let (rmin, rmed, rnear, rtot) = dist_stats(&refs, floor);
        println!(
            "  anti-twin  reference (solution) : min={rmin:.3} median={rmed:.3} near-twin pairs (<{floor})={rnear}/{rtot}"
        );

        // Distinct-at-floor capacity on each basis. view-capacity via the epoch
        // sampler (what it currently serves on); reference-capacity is the honest
        // solution-diversity ceiling.
        let want = views.len();
        let budget = ((want as u32) * 100).clamp(500, 4000);
        let view_cap =
            match bench_gen::epoch::plan_epoch_from(g.as_ref(), 0u64.., want, floor, budget) {
                Ok(plan) => format!(
                    "{}+ (asked {want}, rejected {})",
                    plan.seeds.len(),
                    plan.rejected()
                ),
                Err(e) => format!("{} (exhausted at {} candidates)", e.accepted, e.attempts),
            };
        let ref_cap = bench_gen::epoch::reference_capacity(g.as_ref(), 400, floor);
        println!(
            "  capacity   view={view_cap}  reference={ref_cap}  (text proxies — view over-counts, reference under-counts)"
        );

        // The authoritative diversity number (Q31, decided): distinct structural
        // specs, ungameable by example noise and undeflated by boilerplate. This is
        // the count a family is authored against; view-distance is a separate gate
        // for prompt freshness (contamination-resistance).
        let diversity = bench_gen::spec_diversity(g.as_ref(), 4000);
        println!("  spec-diversity: {diversity} distinct skills (the authoritative task-diversity measure — Q31)");

        // The spec-aware epoch serve-path: cover distinct skills, not just distinct
        // prompts. Request the validated count; it should serve that many skills so
        // long as the count is within the family's diversity.
        match bench_gen::epoch::plan_epoch_distinct_skills(g.as_ref(), 0u64.., want, floor, 5000) {
            Ok(plan) => println!(
                "  distinct-skills epoch: served {} seed(s) covering {} distinct skills",
                plan.seeds.len(),
                plan.distinct_skills(),
            ),
            Err(e) => println!(
                "  distinct-skills epoch: only {} distinct skills available (asked {want}) — family too narrow for this per-epoch count",
                e.accepted,
            ),
        }
    }

    let _ = std::fs::remove_dir_all(scratch);
    if failures == 0 {
        println!("all gates passed");
        Ok(())
    } else {
        Err(format!("{failures} seed(s) failed validation").into())
    }
}

// ---------------------------------------------------------------------------
// stats
// ---------------------------------------------------------------------------

fn stats(journal: &Path, allow_uncontained: bool) -> Result<(), Box<dyn std::error::Error>> {
    let records = bench_stats::load_journal(journal)
        .map_err(|e| format!("reading {}: {e}", journal.display()))?;
    if records.is_empty() {
        return Err(format!("no graded units in {}", journal.display()).into());
    }
    // AQ-194 r54 R2: an all-uncontained journal aggregates only on explicit
    // opt-in, and its output is labelled UNCONTAINED throughout.
    let class = bench_stats::journal_containment_class(&records)?;
    if let Some(msg) = uncontained_aggregation_refusal(class, allow_uncontained) {
        return Err(msg.into());
    }
    if let Some(banner) = uncontained_banner(class) {
        println!("!! {banner}");
    }
    let r = bench_stats::report(&records);

    println!(
        "capability_score{} = {:.3}  [{:.3}, {:.3}]  (95% overall CI, cluster bootstrap)",
        uncontained_suffix(class),
        r.capability_score,
        r.capability_ci.0,
        r.capability_ci.1
    );
    println!(
        "pass_rate{}        = {:.3}  over {} units in {} categor{}",
        uncontained_suffix(class),
        r.pass_rate,
        r.units,
        r.categories.len(),
        if r.categories.len() == 1 { "y" } else { "ies" }
    );
    println!(
        "per-category (simultaneous CIs at 1 - 0.05/{}):",
        r.simultaneous_k
    );
    // AQ-202/OI-36c: refused miri-mandatory rows are excluded above; the count
    // must say so rather than let the denominators shrink silently.
    if r.miri_refused > 0 {
        println!(
            "miri_refused       = {} unsafe-core row(s) EXCLUDED (no miri verdict — not scored, not failures)",
            r.miri_refused
        );
    }
    for c in &r.categories {
        let icc = c
            .icc
            .map(|i| format!("icc={i:.2}"))
            .unwrap_or_else(|| "icc=n/a".to_string());
        let de = c
            .design_effect
            .map(|d| format!(" de={d:.2}"))
            .unwrap_or_default();
        println!(
            "  {:<18} score={:.3} [{:.3}, {:.3}]  pass={:.3}  fams={} units={}  {icc}{de}{}",
            c.category,
            c.mean_score,
            c.score_ci.0,
            c.score_ci.1,
            c.pass_rate,
            c.families,
            c.units,
            if c.directional_only {
                "  <-- directional-only (too few families)"
            } else {
                ""
            },
        );
    }
    match r.pooled_icc {
        Some(icc) => {
            println!("pooled ICC = {icc:.3} (diagnostic/sizing only, not in any CI — Q29.2)")
        }
        None => println!("pooled ICC = n/a (needs >=2 families with >=2 seeds each to estimate)"),
    }
    match &r.throughput {
        Some(t) => {
            let warm = if t.warmup_excluded > 0 {
                format!(", {} segment-warmup unit(s) excluded", t.warmup_excluded)
            } else {
                String::new()
            };
            println!(
                "throughput (over {} executed units, core+probe{warm}):",
                t.units
            );
            println!(
                "  decode {:.1} tok/s  |  {:.1} s/unit ({:.1}s gen + {:.1}s grade, grade {:.0}% of wall)",
                t.decode_tok_per_s,
                t.wall_s / t.units as f64,
                t.gen_s / t.units as f64,
                t.grade_s / t.units as f64,
                t.grade_share * 100.0,
            );
            println!(
                "  {:.0} units/hour  |  {:.0} passes/hour (throughput_score)",
                t.units_per_hour, t.passes_per_hour
            );
        }
        None => println!("throughput = n/a (journal carries no timing)"),
    }
    println!(
        "note: family-level cluster bootstrap ({} resamples) — a lower bound on CI width until shapes are labelled (Q24).",
        r.bootstrap_iters
    );
    if class == "uncontained" {
        println!(
            "note: every figure above is UNCONTAINED (graded with no sandbox; see the !! line)."
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// report — journal → formatted deliverable (docs/08, P5)
// ---------------------------------------------------------------------------

fn report(
    journal: &Path,
    format: &str,
    allow_uncontained: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let records = bench_stats::load_journal(journal)
        .map_err(|e| format!("reading {}: {e}", journal.display()))?;
    if records.is_empty() {
        return Err(format!("no graded units in {}", journal.display()).into());
    }
    // AQ-194 r54 R2: same explicit opt-in and UNCONTAINED labelling as stats.
    let class = bench_stats::journal_containment_class(&records)?;
    if let Some(msg) = uncontained_aggregation_refusal(class, allow_uncontained) {
        return Err(msg.into());
    }
    let r = bench_stats::report(&records);
    let d = bench_stats::diagnostics(&records);
    match format {
        "md" => {
            if let Some(banner) = uncontained_banner(class) {
                println!("> **!! {banner}**\n");
            }
            print!("{}", render_report_md(&r, &d));
        }
        "json" => print!("{}", render_report_json(&r, &d, class)?),
        other => {
            return Err(format!(
                "unsupported format `{other}` — use `md` or `json` (`html` not yet implemented)"
            )
            .into())
        }
    }
    Ok(())
}

fn render_report_md(r: &bench_stats::StatReport, d: &bench_stats::DiagnosticsReport) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "# Rustybenchmark report\n");
    let _ = writeln!(s, "## Headline\n");
    let _ = writeln!(
        s,
        "- **capability_score** {:.3}  [{:.3}, {:.3}]  (95% overall CI, cluster bootstrap)",
        r.capability_score, r.capability_ci.0, r.capability_ci.1
    );
    match &r.throughput {
        Some(t) => {
            let _ = writeln!(
                s,
                "- **throughput** {:.1} tok/s decode · {:.0} units/hour · {:.0} passes/hour",
                t.decode_tok_per_s, t.units_per_hour, t.passes_per_hour
            );
        }
        None => {
            let _ = writeln!(s, "- **throughput** n/a (journal carries no timing)");
        }
    }
    let _ = writeln!(
        s,
        "- **pass_rate** {:.3}  over {} scored core units in {} categor{}",
        r.pass_rate,
        r.units,
        r.categories.len(),
        if r.categories.len() == 1 { "y" } else { "ies" }
    );
    // AQ-202/OI-36c: refusal accounting is a headline bullet, not a table
    // column — the per-category table's schema is frozen (docs/12-schemas.md).
    if r.miri_refused > 0 {
        let _ = writeln!(
            s,
            "- **miri_refused** {} unsafe-core row(s) excluded (no miri verdict — not scored, not failures; AQ-202/OI-36c)",
            r.miri_refused
        );
    }

    let _ = writeln!(s, "\n## Per category\n");
    let _ = writeln!(
        s,
        "Simultaneous CIs at 1 − 0.05/{}. Categories with fewer than {} families are directional-only (not rankable).\n",
        r.simultaneous_k,
        bench_stats::CLUSTER_FLOOR
    );
    let _ = writeln!(
        s,
        "| category | score | 95% CI | pass | families | units | icc | |"
    );
    let _ = writeln!(s, "|---|---|---|---|---|---|---|---|");
    let mut cats = r.categories.clone();
    cats.sort_by(|a, b| a.category.cmp(&b.category));
    for c in &cats {
        let icc = c
            .icc
            .map(|i| format!("{i:.2}"))
            .unwrap_or_else(|| "—".into());
        let flag = if c.directional_only {
            "directional-only"
        } else {
            ""
        };
        let _ = writeln!(
            s,
            "| {} | {:.3} | [{:.3}, {:.3}] | {:.3} | {} | {} | {} | {} |",
            c.category,
            c.mean_score,
            c.score_ci.0,
            c.score_ci.1,
            c.pass_rate,
            c.families,
            c.units,
            icc,
            flag
        );
    }

    let _ = writeln!(s, "\n## Diagnostics (core units)\n");
    let _ = writeln!(
        s,
        "- **apply_rate** {:.3} · **compile_rate** {:.3}  (over {} units)",
        d.apply_rate, d.compile_rate, d.units
    );
    let join = |v: &[(String, usize)], n: usize| {
        let parts: Vec<String> = v.iter().take(n).map(|(k, c)| format!("{k}×{c}")).collect();
        if parts.is_empty() {
            "—".to_string()
        } else {
            parts.join(", ")
        }
    };
    let _ = writeln!(
        s,
        "- **failure classes**: {}",
        join(&d.failure_classes, d.failure_classes.len())
    );
    let _ = writeln!(s, "- **top error codes**: {}", join(&d.error_codes, 10));
    if d.typeck_only > 0 {
        let _ = writeln!(
            s,
            "- **borrowck masked**: {} failure(s) aborted before borrow checking — borrow-failure counts are a lower bound",
            d.typeck_only
        );
    }

    let _ = writeln!(s, "\n---");
    let _ = writeln!(
        s,
        "_Family-level cluster bootstrap, {} resamples — a lower bound on CI width until shapes are labelled (Q24). Only core units are scored (ADR-0009); borrow-failure counts are a lower bound, since type checking aborts before borrowck (docs/03)._",
        r.bootstrap_iters
    );
    s
}

fn render_report_json(
    r: &bench_stats::StatReport,
    d: &bench_stats::DiagnosticsReport,
    containment_class: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let v = serde_json::json!({
        // AQ-194 r54 R2: machine-readable containment class so a JSON report
        // from an uncontained journal can never be mistaken for a sandboxed one.
        "containment": containment_class,
        "stats": serde_json::to_value(r)?,
        "diagnostics": serde_json::to_value(d)?,
    });
    Ok(format!("{}\n", serde_json::to_string_pretty(&v)?))
}

fn compare(a: &Path, b: &Path, allow_uncontained: bool) -> Result<(), Box<dyn std::error::Error>> {
    let ra = bench_stats::load_journal(a).map_err(|e| format!("reading {}: {e}", a.display()))?;
    let rb = bench_stats::load_journal(b).map_err(|e| format!("reading {}: {e}", b.display()))?;
    // AQ-194 r54 R2: comparing numbers from different containment classes is
    // refused outright (the mix refusal of load_journal cannot see across two
    // files); two uncontained journals compare only on explicit opt-in, and
    // the output is labelled UNCONTAINED.
    let class_a = bench_stats::journal_containment_class(&ra)?;
    let class_b = bench_stats::journal_containment_class(&rb)?;
    if class_a != class_b {
        return Err(format!(
            "cannot compare a {class_a} journal with a {class_b} one — scores from \
             uncontained grading are not comparable with sandboxed scores"
        )
        .into());
    }
    if let Some(msg) = uncontained_aggregation_refusal(class_a, allow_uncontained) {
        return Err(msg.into());
    }
    if let Some(banner) = uncontained_banner(class_a) {
        println!("!! {banner}");
    }
    let cmp = bench_stats::compare_models(&ra, &rb);
    if cmp.n_paired == 0 {
        return Err("the two journals share no units (compare needs the paired seed set)".into());
    }
    let m = &cmp.mcnemar;
    println!("paired over {} shared units", cmp.n_paired);
    // AQ-202/OI-36c (r70 F-1): say why n_paired shrank, never shrink silently.
    println!(
        "miri-refused unsafe-core rows excluded: A={} B={}",
        cmp.miri_refused_a, cmp.miri_refused_b
    );
    println!(
        "McNemar: A-only={} B-only={} (discordant {}), chi2={:.3}, p={:.4}",
        m.discordant_a_only,
        m.discordant_b_only,
        m.discordant_a_only + m.discordant_b_only,
        m.statistic,
        m.p_value,
    );
    println!(
        "pass-rate difference (B - A) = {:+.3}  [{:+.3}, {:+.3}]  (95% paired wild cluster bootstrap)",
        cmp.delta_pass_rate, cmp.delta_ci.0, cmp.delta_ci.1
    );
    let verdict = if m.p_value >= 0.05 {
        "no significant difference (p >= 0.05)"
    } else if cmp.delta_pass_rate > 0.0 {
        "B significantly better (p < 0.05)"
    } else {
        "A significantly better (p < 0.05)"
    };
    println!("verdict: {verdict}");
    Ok(())
}

fn detect(journal: &Path, allow_uncontained: bool) -> Result<(), Box<dyn std::error::Error>> {
    let records = bench_stats::load_journal(journal)
        .map_err(|e| format!("reading {}: {e}", journal.display()))?;
    if records.is_empty() {
        // An empty journal is no data, not uncontained data — keep the
        // pre-existing readout instead of refusing it (the class below would
        // classify an empty slice as "uncontained", bench-stats lib.rs:233).
        println!(
            "no core/probe pairs in {} — run an epoch with --seeds-probe > 0 first",
            journal.display()
        );
        return Ok(());
    }
    // AQ-194 r59 F-1: detect reads graded pass bits just like stats, so an
    // all-uncontained journal needs the same explicit opt-in and labelling —
    // a verdict over uncontained rows must never read as a sandboxed one.
    let class = bench_stats::journal_containment_class(&records)?;
    if let Some(msg) = uncontained_aggregation_refusal(class, allow_uncontained) {
        return Err(msg.into());
    }
    if let Some(banner) = uncontained_banner(class) {
        println!("!! {banner}");
    }
    let reports = bench_stats::detect(&records, bench_stats::DETECTOR_ALPHA);
    if reports.is_empty() {
        println!(
            "no core/probe pairs in {} — run an epoch with --seeds-probe > 0 first",
            journal.display()
        );
        return Ok(());
    }
    println!(
        "precomputation detector (sign test, alpha={}):",
        bench_stats::DETECTOR_ALPHA
    );
    for r in &reports {
        let s = &r.sign;
        println!(
            "  epoch {:<10} families_paired={} core_wins={} probe_wins={} p={:.4}  {}{}",
            r.epoch,
            r.families_paired,
            s.core_wins,
            s.probe_wins,
            s.p_value,
            if s.flagged {
                "*** FLAGGED: core beats fresh probe — possible precomputation"
            } else {
                "ok (no significant core advantage)"
            },
            uncontained_suffix(class),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// status — the resume readout
// ---------------------------------------------------------------------------

/// Read-only progress readout for an epoch: how much of the planned suite is done,
/// an ETA for the rest from the measured steady-state pace, and the per-segment
/// history (docs/08). This *is* the resume readout — it says exactly what a
/// `run-suite --epoch <e>` would still have to run, without calling a model.
fn status(
    journal: &Path,
    epoch: Option<&str>,
    n_core: u32,
    n_probe: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let records = match bench_stats::load_journal(journal) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("no journal at {} yet — nothing has run", journal.display());
            return Ok(());
        }
        Err(e) => return Err(format!("reading {}: {e}", journal.display()).into()),
    };
    if records.is_empty() {
        println!("journal {} is empty — nothing has run", journal.display());
        return Ok(());
    }
    // AQ-194 r59 F-2: status is a read-only readout, so it does not refuse —
    // but a plan/ETA over an uncontained journal must not be mistaken for a
    // contained one. One labelled line, same text every other command prints.
    let class = bench_stats::journal_containment_class(&records)?;
    if let Some(banner) = uncontained_banner(class) {
        println!("!! {banner}");
    }

    // Which epoch: the requested one, else the most recent non-"local" epoch seen
    // (falling back to the last record's epoch if only single-`run` units exist).
    let epoch = match epoch {
        Some(e) => e.to_string(),
        None => records
            .iter()
            .rev()
            .map(|r| r.epoch.as_str())
            .find(|e| *e != "local")
            .or_else(|| records.last().map(|r| r.epoch.as_str()))
            .unwrap()
            .to_string(),
    };

    // Plan vs done for this epoch (same call path `run-suite` resumes on).
    let plan = bench_gen::epoch::plan_run(bench_gen::FAMILY_IDS, &epoch, n_core, n_probe);
    let done_keys = read_done_keys(journal, &epoch)?;
    let todo = bench_gen::epoch::remaining(&plan, &done_keys);
    let planned = plan.len();
    let remaining = todo.len();
    let done = planned.saturating_sub(remaining);
    let pct = if planned > 0 {
        100.0 * done as f64 / planned as f64
    } else {
        0.0
    };

    let recs: Vec<bench_stats::Record> = records.into_iter().filter(|r| r.epoch == epoch).collect();

    println!("status: epoch {epoch}");
    println!(
        "  plan      {planned} units ({} core + {} probe over {} families)",
        n_core as usize * bench_gen::FAMILY_IDS.len(),
        n_probe as usize * bench_gen::FAMILY_IDS.len(),
        bench_gen::FAMILY_IDS.len(),
    );
    println!("  done      {done}/{planned}  ({pct:.0}%)");
    println!("  remaining {remaining}");

    // ETA from the measured steady-state pace (throughput excludes cache-warmth).
    match bench_stats::throughput(&recs) {
        Some(t) if t.units > 0 => {
            let per_unit = t.wall_s / t.units as f64;
            let warm = if t.warmup_excluded > 0 {
                format!(", {} warmup excluded", t.warmup_excluded)
            } else {
                String::new()
            };
            println!(
                "  pace      {per_unit:.1} s/unit (steady-state over {} timed unit(s){warm})",
                t.units
            );
            if remaining > 0 {
                println!(
                    "  ETA       ~{} for the remaining {remaining}",
                    fmt_duration(per_unit * remaining as f64)
                );
            } else {
                println!("  ETA       complete");
            }
        }
        _ => println!("  pace      n/a (no timing recorded yet)"),
    }

    // Per-segment history — the record of each run session over this epoch.
    let mut segs: BTreeMap<Option<u32>, (usize, u64)> = BTreeMap::new();
    for r in &recs {
        let e = segs.entry(r.segment).or_insert((0, 0));
        e.0 += 1;
        e.1 += r.cost.gen_ms + r.cost.grade_ms;
    }
    if !segs.is_empty() {
        println!("  segments:");
        for (seg, (units, wall_ms)) in &segs {
            let label = seg
                .map(|s| format!("seg {s}"))
                .unwrap_or_else(|| "seg —".to_string());
            let mean = if *units > 0 {
                *wall_ms as f64 / 1000.0 / *units as f64
            } else {
                0.0
            };
            println!("    {label}: {units} unit(s), mean {mean:.1} s/unit");
        }
    }

    // The resume readout proper — the next units run-suite would execute.
    if remaining > 0 {
        let peek = remaining.min(5);
        println!("  next up ({peek} of {remaining}):");
        for u in todo.iter().take(peek) {
            println!(
                "    {:<14} {:<5} idx={} seed={:016x}",
                u.family,
                u.kind.as_str(),
                u.index,
                u.seed
            );
        }
    } else {
        println!("  → epoch complete; nothing to resume");
    }
    Ok(())
}

/// Humanise a duration in seconds as `Ns` / `N.Nm` / `N.Nh`.
fn fmt_duration(secs: f64) -> String {
    if secs < 90.0 {
        format!("{secs:.0}s")
    } else if secs < 5400.0 {
        format!("{:.1}m", secs / 60.0)
    } else {
        format!("{:.1}h", secs / 3600.0)
    }
}

// ---------------------------------------------------------------------------
// Journal + fs
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct JournalLine {
    schema: u32,
    unit_id: String,
    task_id: String,
    category: String,
    seed: u64,
    index: u32,
    /// Epoch label; `"local"` for a single-unit `run`.
    epoch: String,
    /// `"core"` or `"probe"` (ADR-0009).
    kind: String,
    /// Which run *session* produced this unit. A segment is one `run-suite`
    /// invocation over an epoch; a resume starts a new segment. `None` for the
    /// single-unit `run` (no segment structure). docs/08, docs/09.
    #[serde(skip_serializing_if = "Option::is_none")]
    segment: Option<u32>,
    /// 0-based position of this unit within its segment. The first few units of a
    /// segment run against cold caches, so `bench-stats` excludes them from the
    /// throughput aggregate (docs/08) — recorded so that exclusion is auditable
    /// rather than magic. `None` for the single-unit `run`.
    #[serde(skip_serializing_if = "Option::is_none")]
    segment_position: Option<u32>,
    model: ModelInfo,
    sandbox: String,
    /// Recorded only when this row was graded with no containment under an
    /// explicit `--allow-unsandboxed` opt-in (AQ-194). Absent for contained
    /// rows and for legacy `unsupported` rows written before the gate existed.
    /// `bench-stats` refuses to aggregate a journal that mixes these rows with
    /// contained ones.
    #[serde(skip_serializing_if = "Option::is_none")]
    sandbox_opted_in: Option<bool>,
    oracle: OracleVector,
    cost: Cost,
    failure_class: FailureClass,
}
#[derive(Serialize)]
struct ModelInfo {
    name: String,
    base_url: String,
    finish_reason: String,
}
#[derive(Serialize)]
struct Cost {
    prompt_tokens: u32,
    completion_tokens: u32,
    gen_ms: u64,
    grade_ms: u64,
}

fn read_tree(root: &Path) -> std::io::Result<BTreeMap<PathBuf, String>> {
    let mut map = BTreeMap::new();
    if !root.exists() {
        return Ok(map);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let rel = path.strip_prefix(root).unwrap().to_path_buf();
                map.insert(rel, std::fs::read_to_string(&path)?);
            }
        }
    }
    Ok(map)
}

fn append_journal(out: &Path, line: &JournalLine) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(out)?;
    writeln!(f, "{}", serde_json::to_string(line)?)?;
    f.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_humanises_by_scale() {
        // Seconds under 90s, minutes up to 90 min, hours beyond.
        assert_eq!(fmt_duration(8.0), "8s");
        assert_eq!(fmt_duration(89.0), "89s");
        assert_eq!(fmt_duration(126.0), "2.1m");
        assert_eq!(fmt_duration(3600.0), "60.0m");
        assert_eq!(fmt_duration(7200.0), "2.0h");
    }

    #[test]
    fn duration_boundaries_flip_at_90s_and_90min() {
        assert_eq!(fmt_duration(0.0), "0s");
        assert_eq!(fmt_duration(89.9), "90s"); // still the seconds band
        assert_eq!(fmt_duration(90.0), "1.5m"); // first minute reading
        assert_eq!(fmt_duration(5399.9), "90.0m"); // still minutes
        assert_eq!(fmt_duration(5400.0), "1.5h"); // first hour reading
    }

    #[test]
    fn non_empty_maps_blank_to_none_and_keeps_whitespace_verbatim() {
        assert_eq!(non_empty(""), None);
        assert_eq!(non_empty("behavior"), Some("behavior".to_string()));
        // Only literally-empty opts out; whitespace is a real target name.
        assert_eq!(non_empty(" "), Some(" ".to_string()));
    }

    // --- task_from_generated ---

    #[test]
    fn generated_task_maps_into_the_run_task_shape() {
        let g = bench_gen::family("grid-reduce").expect("family exists");
        let gt = g.generate(7);
        let t = task_from_generated(&gt);
        assert_eq!(t.id, gt.id);
        assert_eq!(t.category, gt.category);
        assert_eq!(t.prompt, gt.prompt);
        assert_eq!(t.system_prompt, GENERIC_SYSTEM_PROMPT);
        assert_eq!(t.answer_path, gt.answer_path);
        assert_eq!(t.weights.behavior, gt.weights.0);
        assert_eq!(t.weights.constraint, gt.weights.1);
        assert_eq!(t.weights.quality, gt.weights.2);
        assert_eq!(t.max_unsafe, gt.max_unsafe);
        assert_eq!(t.check_clippy, gt.check_clippy);
    }

    #[test]
    fn the_miri_category_is_a_category_some_family_actually_declares() {
        // The miri mandate is derived from the category string, so a rename in
        // bench-gen would silently disable the mandatory layer for
        // `unsafe-core` (docs/03 §L3) with nothing failing. This pins the link.
        let declared = bench_gen::FAMILY_IDS
            .iter()
            .filter_map(|id| bench_gen::family(id))
            .any(|f| f.category() == MIRI_CATEGORY);
        assert!(
            declared,
            "no family declares category `{MIRI_CATEGORY}` — the miri layer is dead code"
        );
    }

    // --- AQ-202/OI-36c pre-flight refusals ---

    #[test]
    fn miri_availability_refusal_fires_only_when_miri_is_missing() {
        assert!(miri_available_refusal(false).is_some());
        assert!(miri_available_refusal(true).is_none());
        let msg = miri_available_refusal(false).unwrap();
        assert!(msg.contains("MANDATORY"), "message must state the mandate");
        assert!(
            msg.contains("rustup toolchain install nightly --component miri"),
            "message must name the remedy"
        );
    }

    #[test]
    fn miri_task_refusal_truth_table() {
        // Not the miri category: never refuses, never needs the probe.
        assert!(miri_task_refusal(false, "idiom-loop", Some("t"), None).is_none());
        // Miri category, miri present, has a target: allowed.
        assert!(miri_task_refusal(true, MIRI_CATEGORY, Some("behaviour"), None).is_none());
        assert!(miri_task_refusal(true, MIRI_CATEGORY, None, Some("differential")).is_none());
        // Miri category, miri absent: refuse.
        assert!(miri_task_refusal(false, MIRI_CATEGORY, Some("behaviour"), None).is_some());
        // Miri category but NO target at all: refuse even with miri present —
        // the mandatory stage could never produce a verdict.
        let msg = miri_task_refusal(true, MIRI_CATEGORY, None, None).unwrap();
        assert!(msg.contains("nothing to interpret"), "{msg}");
    }

    #[test]
    fn an_unsafe_core_suite_member_is_detected_through_its_family() {
        // The run-suite gate elects via the family's declared category, so a
        // todo unit of raw-ptr-mut must be recognised as miri-mandatory, and a
        // non-miri family must not be.
        let unsafe_family = bench_gen::family("raw-ptr-mut").expect("family exists");
        assert_eq!(unsafe_family.category(), MIRI_CATEGORY);
        let other = bench_gen::family("grid-reduce").expect("family exists");
        assert_ne!(other.category(), MIRI_CATEGORY);
    }

    #[test]
    fn blank_layer_targets_become_none_not_empty_strings() {
        let g = bench_gen::family("grid-reduce").unwrap();
        let t = task_from_generated(&g.generate(3));
        // grid-reduce ships behavior + differential but no alloc test.
        assert!(t.behavior_test.is_some());
        assert!(t.differential_test.is_some());
        assert_eq!(t.alloc_test, None);
    }

    #[test]
    fn load_generated_rejects_unknown_family_and_resolves_known() {
        assert!(load_generated("no-such-family", 1).is_err());
        let t = load_generated("window-op", 11).expect("known family loads");
        assert!(t.id.starts_with("window-op/"));
    }

    // --- next_segment (resume bookkeeping, docs/09) ---

    fn tempdir(name: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("rustybench-cli-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn next_segment_is_zero_for_a_missing_journal() {
        let dir = tempdir("seg-missing");
        assert_eq!(next_segment(&dir.join("j.jsonl"), "e1").unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn next_segment_is_one_past_the_highest_recorded_segment_of_that_epoch() {
        let dir = tempdir("seg-max");
        let out = dir.join("j.jsonl");
        std::fs::write(
            &out,
            concat!(
                "{\"epoch\":\"other\",\"segment\":5}\n",
                "\n", // blank lines are tolerated
                "{\"epoch\":\"e1\",\"segment\":0}\n",
                "{\"epoch\":\"e1\"}\n", // matching epoch, no segment field
                "{\"epoch\":\"e1\",\"segment\":2}\n",
            ),
        )
        .unwrap();
        assert_eq!(next_segment(&out, "e1").unwrap(), 3);
        assert_eq!(next_segment(&out, "other").unwrap(), 6);
        assert_eq!(
            next_segment(&out, "untouched-epoch").unwrap(),
            0,
            "an epoch with no lines starts at segment 0"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn next_segment_treats_segmentless_matching_lines_as_zero() {
        let dir = tempdir("seg-none");
        let out = dir.join("j.jsonl");
        std::fs::write(&out, "{\"epoch\":\"e1\"}\n{\"epoch\":\"e1\"}\n").unwrap();
        assert_eq!(next_segment(&out, "e1").unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- read_done_keys (resume set) ---

    #[test]
    fn done_keys_are_family_kind_index_triples_scoped_to_the_epoch() {
        let dir = tempdir("done");
        let out = dir.join("j.jsonl");
        std::fs::write(
            &out,
            concat!(
                "{\"task_id\":\"grid-reduce/0001\",\"index\":4,\"epoch\":\"e1\",\"kind\":\"core\"}\n",
                "{\"task_id\":\"noslash\",\"index\":9,\"epoch\":\"e1\",\"kind\":\"probe\"}\n",
                "{\"task_id\":\"window-op/x\",\"index\":4,\"epoch\":\"other\",\"kind\":\"core\"}\n",
            ),
        )
        .unwrap();
        let done = read_done_keys(&out, "e1").unwrap();
        assert_eq!(done.len(), 2, "other-epoch lines are excluded");
        assert!(done.contains("grid-reduce|core|4"));
        assert!(
            done.contains("noslash|probe|9"),
            "id without '/' is its own family"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn done_keys_of_a_missing_journal_form_an_empty_resume_set() {
        let dir = tempdir("done-missing");
        let done = read_done_keys(&dir.join("none.jsonl"), "e1").unwrap();
        assert!(done.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- append_journal + journal shape ---

    fn sample_line(unit: &str, epoch: &str, index: u32) -> JournalLine {
        JournalLine {
            schema: 1,
            unit_id: unit.to_string(),
            task_id: format!("grid-reduce/{unit}"),
            category: "perf-grid".to_string(),
            seed: 42,
            index,
            epoch: epoch.to_string(),
            kind: "core".to_string(),
            segment: Some(2),
            segment_position: Some(index),
            model: ModelInfo {
                name: "mock".to_string(),
                base_url: "http://localhost:1".to_string(),
                finish_reason: "stop".to_string(),
            },
            sandbox: "seatbelt".to_string(),
            sandbox_opted_in: None,
            oracle: bench_core::OracleVector::apply_failed(),
            cost: Cost {
                prompt_tokens: 10,
                completion_tokens: 5,
                gen_ms: 1,
                grade_ms: 1,
            },
            failure_class: bench_core::FailureClass::None,
        }
    }

    #[test]
    fn append_journal_appends_one_json_object_per_line_and_creates_parents() {
        let dir = tempdir("journal");
        let out = dir.join("nested/deeper/j.jsonl");
        append_journal(&out, &sample_line("a", "e1", 0)).unwrap();
        append_journal(&out, &sample_line("b", "e1", 1)).unwrap();

        let text = std::fs::read_to_string(&out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "one JSON object per line, no separators");

        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["unit_id"], "a");
        assert_eq!(first["schema"], 1);
        assert_eq!(first["oracle"]["apply_ok"], false);
        assert_eq!(first["failure_class"], "none");
        assert_eq!(first["model"]["name"], "mock");
        // Segment fields are recorded so cache-warmth exclusion is auditable.
        assert_eq!(first["segment"], 2);
        assert_eq!(first["segment_position"], 0);

        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["segment_position"], 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn appended_journal_feeds_next_segment_and_read_done_keys_back() {
        let dir = tempdir("roundtrip");
        let out = dir.join("j.jsonl");
        for i in 0..3u32 {
            append_journal(&out, &sample_line(&format!("u{i}"), "e1", i)).unwrap();
        }
        assert_eq!(next_segment(&out, "e1").unwrap(), 3);
        let done = read_done_keys(&out, "e1").unwrap();
        assert_eq!(done.len(), 3);
        assert!(done.contains("grid-reduce|core|2"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- read_tree ---

    #[test]
    fn read_tree_walks_nested_files_to_root_relative_keys() {
        let dir = tempdir("tree");
        let root = dir.join("ws");
        std::fs::create_dir_all(root.join("src/deep")).unwrap();
        std::fs::write(root.join("Cargo.toml"), "[package]").unwrap();
        std::fs::write(root.join("src/lib.rs"), "fn f() {}").unwrap();
        std::fs::write(root.join("src/deep/a.txt"), "x").unwrap();

        let map = read_tree(&root).unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(
            map.get(std::path::Path::new("Cargo.toml")).unwrap(),
            "[package]"
        );
        assert_eq!(
            map.get(std::path::Path::new("src/lib.rs")).unwrap(),
            "fn f() {}"
        );
        assert_eq!(
            map.get(std::path::Path::new("src/deep/a.txt")).unwrap(),
            "x"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_tree_of_a_missing_root_is_an_empty_map_not_an_error() {
        let dir = tempdir("tree-missing");
        let map = read_tree(&dir.join("absent")).unwrap();
        assert!(map.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- AQ-194: the containment gate ---

    #[test]
    fn unsandboxed_refusal_fires_only_for_unopted_unsupported() {
        let refusal = unsandboxed_refusal(
            bench_sandbox::Containment::Unsupported,
            bench_sandbox::Gate::RequireContained,
        );
        let msg = refusal.expect("unsupported + no opt-in must refuse");
        assert!(
            msg.contains("--allow-unsandboxed"),
            "refusal must name the opt-in flag, got: {msg}"
        );
        assert_eq!(
            unsandboxed_refusal(
                bench_sandbox::Containment::Unsupported,
                bench_sandbox::Gate::AllowUnsandboxed,
            ),
            None,
            "an explicit opt-in must get past the pre-flight"
        );
        assert_eq!(
            unsandboxed_refusal(
                bench_sandbox::Containment::Seatbelt,
                bench_sandbox::Gate::RequireContained
            ),
            None,
            "a contained platform never refuses"
        );
    }

    #[test]
    fn containment_gate_defaults_to_fail_closed() {
        assert_eq!(
            containment_gate(false),
            bench_sandbox::Gate::RequireContained
        );
        assert_eq!(
            containment_gate(true),
            bench_sandbox::Gate::AllowUnsandboxed
        );
    }

    #[test]
    fn journal_marks_only_opted_in_unsandboxed_rows() {
        use bench_sandbox::Containment as C;
        use bench_sandbox::Gate as G;
        assert_eq!(
            journal_sandbox_fields(C::Unsupported, G::AllowUnsandboxed),
            ("unsupported", Some(true)),
            "the opted-in uncontained row must carry the marker"
        );
        assert_eq!(
            journal_sandbox_fields(C::Seatbelt, G::AllowUnsandboxed),
            ("seatbelt", None),
            "a contained row never carries the marker, flag or no flag"
        );
        assert_eq!(
            journal_sandbox_fields(C::Seatbelt, G::RequireContained),
            ("seatbelt", None)
        );
        assert_eq!(
            journal_sandbox_fields(C::Unsupported, G::RequireContained),
            ("unsupported", None),
            "legacy shape only; run/run-suite refuse this before journalling"
        );
    }

    #[test]
    fn journalled_opt_in_marker_is_serialised() {
        let mut line = sample_line("optin", "e1", 0);
        line.sandbox = "unsupported".to_string();
        line.sandbox_opted_in = Some(true);
        let json = serde_json::to_value(&line).unwrap();
        assert_eq!(json["sandbox"], "unsupported");
        assert_eq!(json["sandbox_opted_in"], true);
        let contained = sample_line("contained", "e1", 1);
        let json = serde_json::to_value(&contained).unwrap();
        assert_eq!(json["sandbox"], "seatbelt");
        assert!(
            json.get("sandbox_opted_in").is_none(),
            "contained rows omit the marker entirely"
        );
    }

    // --- AQ-194 r54 R2: all-uncontained journals do not aggregate silently ---

    #[test]
    fn uncontained_journals_aggregate_only_on_explicit_opt_in() {
        let refusal = uncontained_aggregation_refusal("uncontained", false);
        let msg = refusal.expect("an all-uncontained journal must refuse without the flag");
        assert!(
            msg.contains("--allow-uncontained"),
            "refusal must name the stats-side flag, got: {msg}"
        );
        assert_eq!(
            uncontained_aggregation_refusal("uncontained", true),
            None,
            "the explicit opt-in gets past the aggregation gate"
        );
        assert_eq!(
            uncontained_aggregation_refusal("contained", false),
            None,
            "a contained journal never refuses, flag or no flag"
        );
    }

    #[test]
    fn uncontained_output_is_labelled_and_contained_output_is_not() {
        let banner =
            uncontained_banner("uncontained").expect("uncontained output must be labelled");
        assert!(
            banner.contains("UNCONTAINED"),
            "the label must say UNCONTAINED, got: {banner}"
        );
        assert_eq!(
            uncontained_banner("contained"),
            None,
            "contained output carries no label"
        );
    }

    #[test]
    fn stats_labels_headline_for_uncontained_class_only() {
        // The exact suffix stats and detect append to every number they print,
        // so an uncontained run cannot be visually confused with a contained
        // one (r59 F-1 extends the stats suffix to detect verdict lines).
        assert_eq!(uncontained_suffix("uncontained"), " (UNCONTAINED)");
        assert_eq!(uncontained_suffix("contained"), "");
    }

    /// A minimal paired journal (one family: index-0 core + index-0 probe in
    /// epoch `e1`) with every row carrying the given `sandbox` value.
    fn paired_journal(dir: &Path, sandbox: &str) -> PathBuf {
        const OK_ORACLE: &str = r#"{"apply_ok":true,"compile_ok":true,"error_codes":[],"warn_count":0,"behavior":{"unit":null,"property":null,"differential":null,"score":1.0},"constraint":{"alloc_ok":null,"clippy_clean":null,"fmt_ok":null,"unsafe_blocks":null,"unsafe_ok":null,"paths_ok":null,"violations":[],"score":null},"score":1.0,"failure_class":"none","flags":[]}"#;
        let p = dir.join("j.jsonl");
        let mut text = String::new();
        for kind in ["core", "probe"] {
            text.push_str(&format!(
                "{{\"task_id\":\"fam/0\",\"category\":\"c\",\"kind\":\"{kind}\",\
                 \"index\":0,\"epoch\":\"e1\",\"sandbox\":\"{sandbox}\",\
                 \"oracle\":{OK_ORACLE}}}\n"
            ));
        }
        std::fs::write(&p, text).unwrap();
        p
    }

    #[test]
    fn detect_is_gated_like_the_aggregators() {
        // r59 F-1: an all-uncontained journal must refuse without the flag —
        // on the pre-fix code `detect` printed verdicts with rc 0 here.
        let dir = tempdir("detect-uncontained");
        let j = paired_journal(&dir, "unsupported");
        let err = detect(&j, false)
            .expect_err("all-uncontained detect must refuse without --allow-uncontained");
        assert!(
            err.to_string().contains("--allow-uncontained"),
            "refusal must name the opt-in flag, got: {err}"
        );
        // The opt-in runs the detector over the paired family.
        detect(&j, true).expect("the explicit opt-in lets the detector run");
        let _ = std::fs::remove_dir_all(&dir);

        // A contained journal never refuses, flag or no flag.
        let dir = tempdir("detect-contained");
        let j = paired_journal(&dir, "seatbelt");
        detect(&j, false).expect("contained detect never refuses");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
