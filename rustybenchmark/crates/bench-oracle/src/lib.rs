//! `bench-oracle` — the layered grader.
//!
//! P0 spine: L0 apply, L1 compile (with rustc-error-code extraction), and the
//! L2 unit sub-oracle. L2 property/differential and the L3/L4 layers arrive in
//! P2. Grading runs the real `cargo`/`rustc` toolchain in a materialised
//! workspace that is separate from anything the model ever saw — the oracle
//! files are injected only here (docs/03-oracle.md).
//!
//! Model-authored code runs under containment: every `cargo` invocation goes
//! through `bench-sandbox` (P1), which on macOS denies network and confines
//! writes to the workspace. The seam is deliberately narrow — one `run_cargo`
//! helper — so containment is applied in exactly one place.

pub mod ast;

use bench_core::{
    classify_compile_error, classify_graded, composite_score, diagnostic_completeness,
    miri_verdict_recorded, BehaviorScore, ConstraintScore, DiagnosticCompleteness, FailureClass,
    Instance, OracleVector, OracleWeights, MIRI_CLEAN_FLAG, MIRI_NO_SUMMARY, MIRI_NO_TARGETS,
    MIRI_TIMEOUT, MIRI_UB_FLAG, MIRI_UNAVAILABLE,
};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum OracleError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("workspace {0} is not an empty directory")]
    DirtyWorkspace(String),
}

/// Everything the oracle needs beyond the instance and the response. Grows one
/// field per layer as the oracle deepens.
pub struct GradeSpec<'a> {
    /// Where in the crate the model's answer is written, e.g. `src/lib.rs`.
    pub answer_path: &'a Path,
    pub weights: &'a OracleWeights,
    /// The `cargo test --test <name>` target for the L2 behaviour tests. `None`
    /// runs every test, which is fine when the task has no separate L3 target.
    pub behavior_test: Option<&'a str>,
    /// The `cargo test --test <name>` target for the L2 differential sub-oracle
    /// (candidate vs hidden reference over generated inputs). `None` skips it.
    pub differential_test: Option<&'a str>,
    /// The `cargo test --test <name>` target carrying the L3 allocation
    /// instrumentation. `None` skips the constraint layer.
    pub alloc_test: Option<&'a str>,
    /// Resource limits (harness-owned wall clock, rlimits) for every cargo call.
    pub limits: bench_sandbox::Limits,
    /// L3 AST constraint: maximum `unsafe` usages allowed. `None` = unchecked.
    pub max_unsafe: Option<u32>,
    /// L3 AST constraint: forbidden type/function paths (`RefCell`, `transmute`).
    pub forbidden_paths: Vec<String>,
    /// L3 constraint: run `cargo clippy --lib` on the answer and score its
    /// cleanliness (docs/03 — the idiomaticity signal). `false` skips it.
    pub check_clippy: bool,
    /// Clippy lints not counted against cleanliness, e.g.
    /// `"clippy::needless_range_loop"`.
    pub clippy_allow: Vec<String>,
    /// Run the behaviour+differential test targets under miri (`cargo +nightly
    /// miri test`) and treat an interpreter UB report as a HARD BEHAVIOUR
    /// FAILURE (docs/03 §L3: "UB is not a style issue" — mandatory for the
    /// `unsafe-core` category). `false` skips the stage, which is why it is off
    /// everywhere else: miri is slow.
    ///
    /// AQ-202/OI-36c: because the stage is mandatory for the category that sets
    /// this flag, a grade that ends without a recorded miri verdict (a gap flag
    /// such as `miri:unavailable`, or no `miri:clean`/`miri:ub` at all) is
    /// marked `FailureClass::Indeterminate` with score 0.0 — callers must
    /// refuse the row instead of scoring it. Callers gate earlier still:
    /// `miri_preflight` refuses the whole command before any model contact.
    pub check_miri: bool,
    /// The containment gate (AQ-194) applied to every cargo call of this grade.
    /// Grading *model* output must pass `Gate::RequireContained` (default) —
    /// the sandbox layer then refuses to spawn cargo on an Unsupported
    /// platform. Only an explicit operator opt-in may use
    /// `Gate::AllowUnsandboxed`, and the caller must journal the row as
    /// uncontained. Trusted in-tree code (validate-family's reference builds)
    /// threads whatever gate the operator chose for the command.
    pub gate: bench_sandbox::Gate,
    /// AQ-215: the harness scratch root the grading workspace lives under.
    /// Bounds cargo's config discovery walk (a config in an ancestor up to —
    /// but not above — this root refuses the grade) and holds the pinned
    /// harness-made cargo home. Callers must pass the same scratch root they
    /// created `workspace` inside.
    pub scratch_root: std::path::PathBuf,
}

/// Grade one model response for one instance.
///
/// `workspace` must be an existing empty directory; the oracle materialises the
/// crate there (skeleton files + the model's applied answer + hidden oracle
/// files), builds it, and tests it.
pub fn grade(
    instance: &Instance,
    response: &str,
    spec: &GradeSpec,
    workspace: &Path,
) -> Result<OracleVector, OracleError> {
    if workspace.read_dir()?.next().is_some() {
        return Err(OracleError::DirtyWorkspace(workspace.display().to_string()));
    }

    // ---- L0: apply ----
    let code = match extract_code(response) {
        Some(c) => c,
        None => return Ok(OracleVector::apply_failed()),
    };

    // Materialise the model's view (skeleton), overwrite the answer file with
    // the extracted code, then inject the hidden oracle files.
    for (rel, contents) in &instance.files {
        write_under(workspace, rel, contents)?;
    }
    write_under(workspace, spec.answer_path, &code)?;
    for (rel, contents) in &instance.hidden {
        write_under(workspace, rel, contents)?;
    }

    // Containment for every model-code execution below. Built once; the model
    // has already produced its response (unsandboxed HTTP), and nothing it
    // wrote runs until now. The spec's gate is consulted by `run` before any
    // spawn, so an unopted Unsupported platform fails here — before building.
    // AQ-215: the policy is scoped to the spec's scratch root, which also
    // replaces the ambient cargo home with a harness-made one inside it.
    let policy = bench_sandbox::Policy::for_workspace_with_scratch(workspace, &spec.scratch_root)?
        .with_limits(spec.limits)
        .with_gate(spec.gate);
    let mut flags: Vec<String> = Vec::new();

    // ---- L1: compile ----
    let build = run_cargo(&policy, &["build", "--offline", "--message-format=json"])?;
    if build.timed_out {
        flags.push("timeout:build".into());
    }
    let (error_codes, error_messages, warn_count) = parse_diagnostics(&build.stdout);
    let compile_ok = build.success;

    if !compile_ok {
        let failure_class = classify_compile_error(&error_codes, &error_messages);
        let completeness = diagnostic_completeness(&error_codes);
        let mut v = OracleVector {
            apply_ok: true,
            compile_ok: false,
            error_codes,
            warn_count,
            diagnostic_completeness: completeness,
            behavior: BehaviorScore::default(),
            constraint: ConstraintScore::default(),
            score: 0.0,
            failure_class,
            flags: flags.clone(),
        };
        v.score = composite_score(&v, spec.weights);
        return Ok(v);
    }

    // ---- L2: behaviour ----
    let mut targs = vec!["test"];
    if let Some(name) = spec.behavior_test {
        targs.push("--test");
        targs.push(name);
    }
    targs.extend_from_slice(&["--offline", "--quiet"]);
    let test = run_cargo(&policy, &targs)?;
    if test.timed_out {
        flags.push("timeout:test".into());
    }
    let unit = parse_test_summary(&test.stdout).or_else(|| parse_test_summary(&test.stderr));
    // A configured behaviour stage that yields no summary means the test target
    // did not build against this answer (e.g. it changed a required interface,
    // or it timed out). That is a behaviour *failure* scored 0.0 — never absent,
    // or a non-conforming answer would inflate its score on the remaining layers.
    let unit_score = match unit {
        Some((_, 0)) => Some(0.0),
        Some((passed, total)) => Some(passed as f32 / total as f32),
        None => {
            if !test.timed_out {
                flags.push("behavior:no_summary".into());
            }
            Some(0.0)
        }
    };

    let mut behavior = BehaviorScore {
        unit: unit_score,
        property: None,
        differential: None,
        score: None,
    };

    // ---- L2 differential: candidate vs hidden reference over generated inputs ----
    if let Some(name) = spec.differential_test {
        let out = run_cargo(&policy, &["test", "--test", name, "--offline", "--quiet"])?;
        if out.timed_out {
            flags.push("timeout:differential".into());
        }
        behavior.differential =
            match parse_test_summary(&out.stdout).or_else(|| parse_test_summary(&out.stderr)) {
                Some((_, 0)) => Some(0.0),
                Some((passed, total)) => Some(passed as f32 / total as f32),
                None => {
                    if !out.timed_out {
                        flags.push("differential:no_summary".into());
                    }
                    Some(0.0)
                }
            };
    }
    behavior.recompute();

    // ---- miri (docs/03 §L3): interpreter check over the behaviour targets ----
    // Mandatory for `unsafe-core` and off elsewhere (it is slow). A miri UB
    // report is a HARD BEHAVIOUR FAILURE — undefined behaviour is not a style
    // issue — so it zeroes the behaviour layer instead of deducting constraint.
    // AQ-202/OI-36c: a mandatory grade that ends without a verdict is recorded
    // as `Indeterminate` below — the flag says why, the refusal is explicit.
    // The refusal itself is flags-based (`miri_verdict_recorded`): the
    // `targets.is_empty()` and `!miri_available` branches push only a gap flag
    // and never reach the clean-verdict push, so the row is refused on flags
    // alone; `miri_gap` is only needed inside the interpreter arm, to suppress
    // `miri:clean` when one target ran clean but another did not reach a
    // verdict.
    if spec.check_miri && compile_ok {
        let mut targets: Vec<&str> = Vec::new();
        if let Some(t) = spec.behavior_test {
            targets.push(t);
        }
        if let Some(t) = spec.differential_test {
            if !targets.contains(&t) {
                targets.push(t);
            }
        }
        if targets.is_empty() {
            flags.push(MIRI_NO_TARGETS.into());
        } else if !miri_available(&policy) {
            // No nightly+miri toolchain on this host. The mandatory layer did
            // NOT run; the flag records why and the row is refused downstream
            // rather than silently scored (AQ-202).
            flags.push(MIRI_UNAVAILABLE.into());
        } else {
            let mut ub = false;
            let mut miri_gap = false;
            for t in &targets {
                let out = run_cargo(
                    &policy,
                    &[
                        "+nightly",
                        "miri",
                        "test",
                        "--test",
                        t,
                        "--offline",
                        "--quiet",
                    ],
                )?;
                if out.timed_out {
                    flags.push(MIRI_TIMEOUT.into());
                    miri_gap = true;
                    continue;
                }
                match parse_miri_verdict(&out.stdout, &out.stderr) {
                    MiriVerdict::Ub => {
                        ub = true;
                        break;
                    }
                    MiriVerdict::Clean => {}
                    MiriVerdict::Unknown => {
                        flags.push(MIRI_NO_SUMMARY.into());
                        miri_gap = true;
                    }
                }
            }
            if ub {
                flags.push(MIRI_UB_FLAG.into());
                // Zero every sub-oracle that ran — the answer is wrong in the
                // way this category exists to catch.
                behavior.unit = behavior.unit.map(|_| 0.0);
                behavior.differential = behavior.differential.map(|_| 0.0);
                behavior.recompute();
            } else if !miri_gap {
                // The mandatory stage ran to a verdict: record it so the row is
                // provably scoreable (AQ-202 — no verdict, no pass).
                flags.push(MIRI_CLEAN_FLAG.into());
            }
        }
    }

    // ---- L3: constraint (allocation) ----
    let mut constraint = ConstraintScore::default();
    if let Some(name) = spec.alloc_test {
        let out = run_cargo(&policy, &["test", "--test", name, "--offline", "--quiet"])?;
        if out.timed_out {
            flags.push("timeout:alloc".into());
        }
        match parse_test_summary(&out.stdout).or_else(|| parse_test_summary(&out.stderr)) {
            Some((passed, total)) if total > 0 => {
                let ok = passed == total;
                constraint.alloc_ok = Some(ok);
                if !ok {
                    constraint
                        .violations
                        .push("alloc: hot path allocated".into());
                }
            }
            // The allocation target did not build against this answer — the
            // answer does not conform, so it fails the check (not "absent").
            _ => {
                constraint.alloc_ok = Some(false);
                constraint
                    .violations
                    .push("alloc: test target did not run".into());
                if !out.timed_out {
                    flags.push("alloc:no_summary".into());
                }
            }
        }
        constraint.recompute();
    }

    // ---- L3 constraint: AST checks (unsafe, forbidden paths) ----
    if spec.max_unsafe.is_some() || !spec.forbidden_paths.is_empty() {
        if let Some(limit) = spec.max_unsafe {
            if let Some(n) = ast::count_unsafe(&code) {
                constraint.unsafe_blocks = Some(n);
                let ok = n <= limit;
                constraint.unsafe_ok = Some(ok);
                if !ok {
                    constraint
                        .violations
                        .push(format!("unsafe: {n} usage(s), limit {limit}"));
                }
            }
        }
        if !spec.forbidden_paths.is_empty() {
            if let Some(hits) = ast::find_forbidden_paths(&code, &spec.forbidden_paths) {
                let ok = hits.is_empty();
                constraint.paths_ok = Some(ok);
                if !ok {
                    constraint
                        .violations
                        .push(format!("forbidden path(s): {}", hits.join(", ")));
                }
            }
        }
        constraint.recompute();
    }

    // ---- L3 constraint: clippy (idiomaticity, docs/03) ----
    // The dominant signal for `idiom-refactor`: non-idiomatic code compiles and is
    // behaviourally correct, so only clippy distinguishes it. Runs on the answer's
    // library only (`--lib`), so the hidden test targets never contribute lints.
    if spec.check_clippy {
        let mut args: Vec<String> = vec![
            "clippy".into(),
            "--lib".into(),
            "--offline".into(),
            "--message-format=json".into(),
        ];
        if !spec.clippy_allow.is_empty() {
            args.push("--".into());
            for lint in &spec.clippy_allow {
                args.push("-A".into());
                args.push(lint.clone());
            }
        }
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let out = run_cargo(&policy, &arg_refs)?;
        if out.timed_out {
            flags.push("timeout:clippy".into());
        }
        let lints = parse_clippy_lints(&out.stdout);
        let clean = lints.is_empty();
        constraint.clippy_clean = Some(clean);
        if !clean {
            constraint
                .violations
                .push(format!("clippy: {}", lints.join(", ")));
        }
        constraint.recompute();
    }

    // Failure class from the layer outcomes (docs/03): behaviour miss → Logic;
    // else a clippy violation → Idiom; else another constraint miss → Constraint;
    // else clean. Kept in `bench-core` so it is pure and unit-tested there.
    let failure_class = classify_graded(behavior.score, constraint.clippy_clean, constraint.score);

    // AQ-202/OI-36c: a mandatory-miri grade that produced no verdict is not a
    // scoreable outcome — mark it Indeterminate and zero the score. The CLI
    // refuses such rows explicitly; stats/report exclude and count them.
    let miri_refused = spec.check_miri && compile_ok && !miri_verdict_recorded(&flags);

    let mut v = OracleVector {
        apply_ok: true,
        compile_ok: true,
        error_codes,
        warn_count,
        // It compiled, so borrowck ran — the diagnostic is complete.
        diagnostic_completeness: DiagnosticCompleteness::Full,
        behavior,
        constraint,
        score: 0.0,
        failure_class,
        flags,
    };
    if miri_refused {
        v.failure_class = FailureClass::Indeterminate;
    }
    v.score = composite_score(&v, spec.weights);
    if miri_refused {
        v.score = 0.0;
    }
    Ok(v)
}

/// Q14 gate helper: run `cargo clippy --fix` on the given files and report the
/// clippy lints that **remain** afterwards.
///
/// Materialises `files` (the model-visible skeleton — Cargo.toml + the answer's
/// `src/lib.rs`) into an empty `workspace`, applies clippy's machine-applicable
/// fixes to the library in place, then re-lints. An **empty** result means
/// `clippy --fix` produced clippy-clean code — i.e. the instance is *trivially
/// auto-solvable*, which a `clippy`-graded family (e.g. `idiom-refactor`) must not
/// be (docs/OPEN-QUESTIONS.md Q14: "clippy --fix must not solve the instance").
/// A non-empty result means the model must genuinely reason about the rewrite.
pub fn clippy_fix_remaining_lints(
    files: &std::collections::BTreeMap<std::path::PathBuf, String>,
    clippy_allow: &[String],
    limits: bench_sandbox::Limits,
    gate: bench_sandbox::Gate,
    workspace: &Path,
    scratch_root: &Path,
) -> Result<Vec<String>, OracleError> {
    if workspace.read_dir()?.next().is_some() {
        return Err(OracleError::DirtyWorkspace(workspace.display().to_string()));
    }
    for (rel, contents) in files {
        write_under(workspace, rel, contents)?;
    }
    // AQ-215: scoped policy — bounded config discovery + harness-made cargo
    // home, exactly as a graded build gets.
    let policy = bench_sandbox::Policy::for_workspace_with_scratch(workspace, scratch_root)?
        .with_limits(limits)
        .with_gate(gate);

    // `-A <lint>` for allowed lints so `--fix`/lint never touch them.
    let allow_flags = |args: &mut Vec<String>| {
        if !clippy_allow.is_empty() {
            args.push("--".into());
            for l in clippy_allow {
                args.push("-A".into());
                args.push(l.clone());
            }
        }
    };

    // Apply machine-applicable fixes in place (best-effort — ignore its status).
    let mut fix = vec![
        "clippy".to_string(),
        "--fix".into(),
        "--allow-dirty".into(),
        "--allow-no-vcs".into(),
        "--lib".into(),
        "--offline".into(),
    ];
    allow_flags(&mut fix);
    let fix_refs: Vec<&str> = fix.iter().map(|s| s.as_str()).collect();
    let _ = run_cargo(&policy, &fix_refs)?;

    // Re-lint the (possibly rewritten) library and report what clippy still finds.
    let mut lint = vec![
        "clippy".to_string(),
        "--lib".into(),
        "--offline".into(),
        "--message-format=json".into(),
    ];
    allow_flags(&mut lint);
    let lint_refs: Vec<&str> = lint.iter().map(|s| s.as_str()).collect();
    let out = run_cargo(&policy, &lint_refs)?;
    Ok(parse_clippy_lints(&out.stdout))
}

/// Extract the answer from a model response. Prefers the first fenced code
/// block (``` optionally tagged `rust`); falls back to the whole trimmed
/// response when the model returned bare code.
pub fn extract_code(response: &str) -> Option<String> {
    if let Some(block) = first_fenced_block(response) {
        let trimmed = block.trim();
        if trimmed.is_empty() {
            return None;
        }
        return Some(trimmed.to_string());
    }
    let trimmed = response.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn first_fenced_block(s: &str) -> Option<String> {
    let mut lines = s.lines();
    let mut inside = false;
    let mut buf = String::new();
    for line in &mut lines {
        let is_fence = line.trim_start().starts_with("```");
        if is_fence {
            if inside {
                return Some(buf);
            } else {
                inside = true;
                continue;
            }
        }
        if inside {
            buf.push_str(line);
            buf.push('\n');
        }
    }
    None
}

fn write_under(root: &Path, rel: &Path, contents: &str) -> std::io::Result<()> {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)
}

struct CargoRun {
    success: bool,
    stdout: String,
    stderr: String,
    timed_out: bool,
}

/// Whether the toolchain can actually run miri: a nightly with the miri
/// component must already be installed. Probed through the same containment
/// policy as every other cargo call, so a probe can never download a toolchain
/// or otherwise mutate the host — offline it fails fast and the caller records
/// `miri:unavailable` instead of pretending the layer ran.
fn miri_available(policy: &bench_sandbox::Policy) -> bool {
    let Ok(out) = run_cargo(policy, &["+nightly", "miri", "--version"]) else {
        return false;
    };
    out.success && out.stdout.contains("miri")
}

/// AQ-202/OI-36c pre-flight: can this host run the mandatory miri stage at all?
///
/// Probes `cargo +nightly miri --version` through the same containment seam as
/// a real grade (a throwaway empty workspace under `scratch_root`, the caller's
/// gate, a wall clock of `wall_timeout_secs`), then cleans the workspace up.
/// `Ok(())` means a miri-mandatory grade may start; `Err(_)` says refuse the
/// command *before* any model contact or build — the message names the remedy.
pub fn miri_preflight(
    scratch_root: &Path,
    wall_timeout_secs: u64,
    gate: bench_sandbox::Gate,
) -> Result<(), String> {
    let dir = scratch_root.join(format!("miri-preflight-{}", std::process::id()));
    // Start from a clean throwaway dir; stale leftovers from a crashed run
    // would trip the DirtyWorkspace gate.
    let _ = std::fs::remove_dir_all(&dir);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return Err(format!(
            "miri preflight: cannot create scratch workspace {}: {e}",
            dir.display()
        ));
    }
    let probe = (|| {
        // AQ-215: the throwaway probe workspace is scoped to the scratch root
        // like any graded build, so the preflight measures the same
        // containment the miri stage will actually run under.
        let policy = bench_sandbox::Policy::for_workspace_with_scratch(&dir, scratch_root)
            .map_err(|e| format!("miri preflight: {e}"))?
            .with_limits(bench_sandbox::Limits {
                wall: std::time::Duration::from_secs(wall_timeout_secs),
                ..Default::default()
            })
            .with_gate(gate);
        Ok::<bool, String>(miri_available(&policy))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    match probe {
        Ok(true) => Ok(()),
        Ok(false) => Err(
            "miri is MANDATORY for unsafe-core tasks (AQ-202, OI-36c) but this host has no \
             nightly toolchain with the miri component. Install it with: \
             `rustup toolchain install nightly --component miri` — or grade a non-miri task."
                .to_string(),
        ),
        Err(m) => Err(m),
    }
}

/// What one miri run's captured output says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MiriVerdict {
    /// The run completed under the interpreter with no UB report.
    Clean,
    /// Miri reported undefined behaviour (or an equivalent hard interpreter
    /// abort — an unsupported operation also stops the program). Hard behaviour
    /// failure (docs/03 §L3).
    Ub,
    /// No interpretable outcome: the target did not build under miri, crashed,
    /// or never produced a summary. Recorded via flags, not scored.
    Unknown,
}

/// Classify captured miri output. Miri prints its reports in the shape
/// `error: Undefined Behavior: …` / `error[E0080]` / `error: unsupported
/// operation: …`; leak detection is deliberately NOT treated as UB here (a leak
/// is a resource report, not an undefined-behaviour report — docs/03 mandates
/// the latter), so a leak surfaces as a plain test failure instead of
/// `miri:ub`. Absent any UB marker, a run counts as `Clean` only if it produced
/// a test summary — that summary is the only evidence the interpreter actually
/// executed the target rather than failing to build it.
pub fn parse_miri_verdict(stdout: &str, stderr: &str) -> MiriVerdict {
    let ub_markers = [
        "Undefined Behavior",           // `error: Undefined Behavior: <cause>`
        "error[E0080]",                 // const-eval abort (UB at compile time)
        "error: unsupported operation", // miri cannot execute this (hard stop)
    ];
    for line in stdout.lines().chain(stderr.lines()) {
        let t = line.trim_start();
        if ub_markers.iter().any(|m| t.contains(m)) {
            return MiriVerdict::Ub;
        }
    }
    if parse_test_summary(stdout)
        .or_else(|| parse_test_summary(stderr))
        .is_some()
    {
        MiriVerdict::Clean
    } else {
        MiriVerdict::Unknown
    }
}

/// The AQ-211 measurement-integrity predicate: `Some(reason)` when the grading
/// workspace carries a cargo config cargo would honour — `.cargo/config.toml`
/// or the legacy extensionless `.cargo/config` (r76 F-1: cargo reads either).
/// r89b probed live that the sandboxed cargo honours such a file: its
/// `build.target-dir` redirects artifacts OUTSIDE the workspace (a completion
/// can warm a cross-run cache at a fixed path or steer measured artifact
/// size), its `[env]` table feeds build scripts (P8), and its
/// `[target.*] runner`/`linker` replace the very programs the oracle believes
/// it invoked; `rustflags`, `[alias]`, `[source]` replacement and `[net]`
/// reach the same runs. The workspace is harness-materialised (docs/03), so
/// no legitimate benchmark task ships one — hence the decision is REFUSE
/// (fail closed, wholesale) rather than neutralise with `--config`
/// overrides: an override list cannot cover keys cargo adds later, and
/// `[alias]`/`[source]` have no safe override at all. Deliberately not
/// platform-gated so the predicate is unit-tested everywhere; the seatbelt
/// backend is the only place model code runs until gate G1. Pure filesystem
/// inspection — nothing is opened, so a planted FIFO cannot hang the harness
/// (the AQ-209 lesson).
fn workspace_cargo_config_refusal_reason(workspace: &Path) -> Option<String> {
    for name in ["config.toml", "config"] {
        let path = workspace.join(".cargo").join(name);
        // `symlink_metadata` does not follow a final symlink: ANY presence —
        // regular file, directory, FIFO, dangling symlink — refuses. If it
        // exists cargo would read it (or fail trying); neither outcome may be
        // reachable by planting a path.
        if std::fs::symlink_metadata(&path).is_ok() {
            return Some(format!(
                "the grading workspace keeps a cargo config at {} — a workspace \
                 config steers the measurement (build.target-dir, [env], \
                 [target.*] runner/linker, rustflags, [alias], [source] \
                 replacement, [net]) and no benchmark task ships one — \
                 refusing to grade (AQ-211, fail closed)",
                path.display()
            ));
        }
    }
    None
}

/// The AQ-215 measurement-integrity predicate: `Some(reason)` when cargo's
/// config discovery — over the grading workspace AND its bounded ancestors —
/// can find a file the oracle does not control. Three channels, all from
/// review r94, all refused wholesale rather than neutralised (the AQ-211
/// argument applies verbatim: an override list cannot cover keys cargo adds
/// later):
///
/// 1. the pinned cargo home (r94 F-2, probe C): the harness-made home must be
///    config-FREE — the AQ-205 token predicate only rejects *credential* keys,
///    and any other operator or planted setting (an `[env]` table most of all)
///    reaches graded code. The home is wiped at policy build; ANY presence of
///    a config file (child-writable by design, for the `.package-cache` lock)
///    refuses the NEXT spawn before cargo honours it — fail closed, never
///    honoured.
/// 2. the workspace and its ancestors (r94 F-1, probe B): cargo reads
///    `.cargo/config{.toml}` by walking UP from the working directory, so a
///    config in a scratch ancestor steers the grade exactly as a workspace
///    one would. The walk is bounded at [`bench_sandbox::Policy::scratch_root`]:
///    the harness owns that root, configs above it are the operator's, and a
///    workspace that is not inside the root refuses outright.
/// 3. toolchain pins (r94 F-3): `rust-toolchain.toml` and the legacy
///    `rust-toolchain` at the workspace or any bounded ancestor refuse — rustup
///    discovers them by the same ancestor walk, and no benchmark task ships
///    one. The repo-root pin sits ABOVE the scratch root, so the harness's own
///    toolchain choice is never self-refused.
///
/// Pure filesystem inspection via `symlink_metadata` — nothing is opened, so a
/// planted FIFO cannot hang the harness (the AQ-209 lesson). Checked before
/// every spawn in [`run_cargo`], so a mid-grade plant makes the NEXT
/// invocation refuse.
fn grading_cargo_config_refusal_reason(policy: &bench_sandbox::Policy) -> Option<String> {
    // Channel 1: the pinned (harness-made) cargo home must hold no config.
    for name in ["config.toml", "config"] {
        let path = policy.cargo_home.join(name);
        if std::fs::symlink_metadata(&path).is_ok() {
            return Some(format!(
                "the harness cargo home at {} keeps a cargo config at {} — the \
                 oracle pins a config-free cargo home (AQ-215, r94 F-2): any \
                 config there would steer the graded run, so refusing to \
                 grade (fail closed)",
                policy.cargo_home.display(),
                path.display()
            ));
        }
    }
    // Channels 2+3: walk the canonicalised ancestors, workspace first, up to
    // and including the scratch root. Never open anything (FIFO-safe).
    let ws = &policy.workspace;
    let mut depth = 0usize;
    let mut cur: &Path = ws;
    loop {
        if depth > 64 {
            return Some(format!(
                "the grading workspace {} has more than 64 ancestors — \
                 cannot bound cargo's config discovery, refusing to grade \
                 (AQ-215, fail closed)",
                ws.display()
            ));
        }
        depth += 1;
        if let Some(reason) = workspace_cargo_config_refusal_reason(cur) {
            return Some(reason);
        }
        for name in ["rust-toolchain.toml", "rust-toolchain"] {
            let path = cur.join(name);
            if std::fs::symlink_metadata(&path).is_ok() {
                return Some(format!(
                    "a toolchain pin exists at {} — rustup discovers it by \
                     walking up from the graded workspace, so it would replace \
                     the harness-pinned toolchain for the measurement, and no \
                     benchmark task ships one — refusing to grade (AQ-215, \
                     r94 F-3, fail closed)",
                    path.display()
                ));
            }
        }
        if cur == policy.scratch_root {
            break;
        }
        match cur.parent() {
            Some(p) => cur = p,
            None => {
                return Some(format!(
                    "the grading workspace {} is not inside the harness scratch \
                     root {} — the config-discovery bound cannot be applied, \
                     refusing to grade (AQ-215, fail closed)",
                    ws.display(),
                    policy.scratch_root.display()
                ));
            }
        }
    }
    None
}

fn run_cargo(policy: &bench_sandbox::Policy, args: &[&str]) -> std::io::Result<CargoRun> {
    // AQ-211 + AQ-215: checked before EVERY spawn at this single seam, so a
    // completion that plants a config (or toolchain pin) mid-grade — in the
    // workspace, a bounded ancestor, or the pinned cargo home — makes the
    // NEXT invocation refuse instead of being steered (cargo reads config at
    // startup, so only later runs are at risk; refusal closes exactly that
    // window).
    if let Some(reason) = grading_cargo_config_refusal_reason(policy) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            reason,
        ));
    }
    // Pin the target directory inside the run's own scratch. Environment
    // beats config files (Cargo Book precedence; probed r89b P7), so this
    // both defeats a `build.target-dir` redirect and stops an ambient
    // harness-level CARGO_TARGET_DIR from pointing every run's build at one
    // shared, cache-warmed directory. Non-UTF-8 workspaces refuse: a path we
    // cannot name exactly is a path we cannot pin (fail closed).
    let target_dir = policy.workspace.join("target");
    let target_dir = target_dir.to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "the grading workspace {} is not representable as UTF-8; \
                 cannot pin CARGO_TARGET_DIR (AQ-211, fail closed)",
                policy.workspace.display()
            ),
        )
    })?;
    // AQ-215 (r94 F-2): pin the harness-made cargo home the same way —
    // `CARGO_HOME` wins over the ambient one, so an operator-exported home
    // (and every setting in its config.toml, credential or not) cannot reach
    // the graded run. Same non-UTF-8 refusal as the target pin.
    let cargo_home = policy.cargo_home.to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "the pinned cargo home {} is not representable as UTF-8; \
                 cannot pin CARGO_HOME (AQ-215, fail closed)",
                policy.cargo_home.display()
            ),
        )
    })?;
    // The single external-command seam — every model-code execution the oracle
    // performs (compile, since proc macros run at build time; and every test
    // binary) goes through here, and here alone gets containment.
    let out = bench_sandbox::run(
        policy,
        "cargo",
        args,
        &[
            ("CARGO_TERM_COLOR", "never"),
            ("CARGO_TARGET_DIR", target_dir),
            ("CARGO_HOME", cargo_home),
        ],
    )?;
    Ok(CargoRun {
        success: out.success(),
        stdout: out.stdout,
        stderr: out.stderr,
        timed_out: out.timed_out,
    })
}

/// Parse `cargo build --message-format=json` output for every rustc diagnostic
/// code, and count warnings. Every code is kept, not just success/failure —
/// the histogram is the richest Rust-specific signal (docs/03-oracle.md).
fn parse_diagnostics(stdout: &str) -> (Vec<String>, Vec<String>, u32) {
    let mut codes = Vec::new();
    let mut messages = Vec::new();
    let mut warns = 0u32;
    for line in stdout.lines() {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("reason").and_then(|r| r.as_str()) != Some("compiler-message") {
            continue;
        }
        let msg = match v.get("message") {
            Some(m) => m,
            None => continue,
        };
        let level = msg.get("level").and_then(|l| l.as_str()).unwrap_or("");
        if level == "warning" {
            warns += 1;
        }
        if level == "error" {
            // Keep the rendered message so codeless errors (e.g. async `Send`
            // bounds carry `code: None`) can be classified by pattern (docs/03).
            if let Some(text) = msg.get("message").and_then(|m| m.as_str()) {
                messages.push(text.to_string());
            }
            if let Some(code) = msg
                .get("code")
                .and_then(|c| c.get("code"))
                .and_then(|c| c.as_str())
            {
                codes.push(code.to_string());
            }
        }
    }
    codes.sort();
    codes.dedup();
    (codes, messages, warns)
}

/// Parse `cargo clippy --message-format=json` output for the clippy lint codes it
/// emitted at `warning` level — the `clippy::*` codes only, so ordinary rustc
/// warnings (unused variables) do not count against idiomaticity. Deduplicated;
/// empty means clippy-clean. Allowed lints were suppressed by `-A` upstream and so
/// never appear here.
fn parse_clippy_lints(stdout: &str) -> Vec<String> {
    let mut lints = Vec::new();
    for line in stdout.lines() {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("reason").and_then(|r| r.as_str()) != Some("compiler-message") {
            continue;
        }
        let msg = match v.get("message") {
            Some(m) => m,
            None => continue,
        };
        if msg.get("level").and_then(|l| l.as_str()) != Some("warning") {
            continue;
        }
        if let Some(code) = msg
            .get("code")
            .and_then(|c| c.get("code"))
            .and_then(|c| c.as_str())
        {
            if code.starts_with("clippy::") {
                lints.push(code.to_string());
            }
        }
    }
    lints.sort();
    lints.dedup();
    lints
}

/// Parse libtest's human summary lines: `test result: ok. 3 passed; 0 failed; …`.
/// Returns `(passed, passed + failed)` **summed across every section** — a
/// `cargo test` run emits one summary per target (lib unit tests, each
/// integration test, and doc tests), so taking only the last would read the
/// empty doc-test section and score a passing solution zero. libtest JSON
/// output needs nightly, so the spine scans the stable text; P4 can switch to
/// JSON once the toolchain pin is decided.
fn parse_test_summary(s: &str) -> Option<(u32, u32)> {
    let marker = "test result:";
    let mut passed = 0u32;
    let mut total = 0u32;
    let mut seen = false;
    for line in s.lines() {
        let Some(pos) = line.find(marker) else {
            continue;
        };
        let after = &line[pos + marker.len()..];
        if let (Some(p), Some(fail)) = (
            extract_count(after, "passed"),
            extract_count(after, "failed"),
        ) {
            passed += p;
            total += p + fail;
            seen = true;
        }
    }
    seen.then_some((passed, total))
}

fn extract_count(s: &str, label: &str) -> Option<u32> {
    let idx = s.find(label)?;
    // Walk backwards over whitespace and digits to read the number before `label`.
    let prefix = s[..idx].trim_end();
    let num: String = prefix
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    num.chars().rev().collect::<String>().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_fenced_rust_block() {
        let r = "Here you go:\n```rust\nfn f() {}\n```\nDone.";
        assert_eq!(extract_code(r).unwrap(), "fn f() {}");
    }

    #[test]
    fn extracts_untagged_fence() {
        let r = "```\nfn f() {}\n```";
        assert_eq!(extract_code(r).unwrap(), "fn f() {}");
    }

    #[test]
    fn falls_back_to_bare_code() {
        assert_eq!(extract_code("fn f() {}").unwrap(), "fn f() {}");
    }

    #[test]
    fn empty_response_has_no_code() {
        assert!(extract_code("   \n  ").is_none());
    }

    #[test]
    fn parses_error_codes_and_warns() {
        let json = r#"{"reason":"compiler-message","message":{"level":"error","code":{"code":"E0499"},"message":"x"}}
{"reason":"compiler-message","message":{"level":"warning","code":{"code":"unused_variables"},"message":"y"}}
{"reason":"compiler-artifact"}"#;
        let (codes, messages, warns) = parse_diagnostics(json);
        assert_eq!(codes, vec!["E0499".to_string()]);
        // Only the error-level message is captured (for pattern classification);
        // the warning's message ("y") is not.
        assert_eq!(messages, vec!["x".to_string()]);
        assert_eq!(warns, 1);
    }

    #[test]
    fn parses_test_summary() {
        assert_eq!(
            parse_test_summary("test result: ok. 3 passed; 0 failed; 0 ignored"),
            Some((3, 3))
        );
        assert_eq!(
            parse_test_summary("test result: FAILED. 1 passed; 2 failed; 0 ignored"),
            Some((1, 3))
        );
    }

    #[test]
    fn sums_across_sections() {
        // lib unit tests (0) + integration (5 passed) + doc tests (0): the
        // real shape of a `cargo test` run. Must be (5, 5), not the last (0, 0).
        let out = "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored\n\
                   running 5 tests\ntest result: ok. 5 passed; 0 failed; 0 ignored\n\
                   running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored";
        assert_eq!(parse_test_summary(out), Some((5, 5)));
    }

    #[test]
    fn no_summary_is_none() {
        assert_eq!(parse_test_summary("error: could not compile"), None);
    }

    #[test]
    fn parses_only_clippy_warnings() {
        // A clippy lint, an ordinary rustc warning (must be ignored), a second
        // clippy lint, a duplicate clippy lint (deduped), and a non-message line.
        let json = r#"{"reason":"compiler-message","message":{"level":"warning","code":{"code":"clippy::needless_range_loop"},"message":"x"}}
{"reason":"compiler-message","message":{"level":"warning","code":{"code":"unused_variables"},"message":"y"}}
{"reason":"compiler-message","message":{"level":"warning","code":{"code":"clippy::manual_map"},"message":"z"}}
{"reason":"compiler-message","message":{"level":"warning","code":{"code":"clippy::needless_range_loop"},"message":"dup"}}
{"reason":"compiler-artifact"}"#;
        assert_eq!(
            parse_clippy_lints(json),
            vec![
                "clippy::manual_map".to_string(),
                "clippy::needless_range_loop".to_string()
            ]
        );
        // Clean output → no lints.
        assert!(parse_clippy_lints(r#"{"reason":"compiler-artifact"}"#).is_empty());
    }

    #[test]
    fn first_fence_wins_over_later_ones() {
        let r = "```rust\nfn a() {}\n```\ntext\n```rust\nfn b() {}\n```";
        assert_eq!(extract_code(r).unwrap(), "fn a() {}");
    }

    #[test]
    fn empty_fenced_block_is_no_code() {
        // A fence that closes around only whitespace is an *empty* answer,
        // not a prompt to fall back to the raw response (which still has the
        // fences in it).
        assert!(extract_code("before\n```\n   \n```").is_none());
    }

    #[test]
    fn unterminated_fence_falls_back_to_raw_response() {
        // No closing fence: first_fenced_block finds nothing, so the bare-code
        // fallback returns the whole trimmed response — fences included. The
        // compile layer, not extraction, then fails it.
        let r = "```rust\nfn f() {}\n";
        assert_eq!(extract_code(r).unwrap(), "```rust\nfn f() {}");
    }

    #[test]
    fn indented_fence_marker_still_opens_a_block() {
        let r = "x\n   ```rust\nfn f() {}\n   ```";
        assert_eq!(extract_code(r).unwrap(), "fn f() {}");
    }

    #[test]
    fn parse_diagnostics_sorts_and_dedups_codes() {
        let json = r#"{"reason":"compiler-message","message":{"level":"error","code":{"code":"E0499"},"message":"a"}}
{"reason":"compiler-message","message":{"level":"error","code":{"code":"E0308"},"message":"b"}}
{"reason":"compiler-message","message":{"level":"error","code":{"code":"E0308"},"message":"b again"}}
{"reason":"compiler-message","message":{"level":"warning","code":{"code":"dead_code"},"message":"w1"}}
{"reason":"compiler-message","message":{"level":"warning","code":{"code":"unused_variables"},"message":"w2"}}"#;
        let (codes, _messages, warns) = parse_diagnostics(json);
        assert_eq!(codes, vec!["E0308".to_string(), "E0499".to_string()]);
        assert_eq!(warns, 2);
    }

    #[test]
    fn codeless_error_is_kept_in_messages_only() {
        let json = r#"{"reason":"compiler-message","message":{"level":"error","message":"`x` cannot be sent between threads"}} "#;
        let (codes, messages, _) = parse_diagnostics(json);
        assert!(codes.is_empty());
        assert_eq!(
            messages,
            vec!["`x` cannot be sent between threads".to_string()]
        );
    }

    #[test]
    fn parse_diagnostics_skips_non_json_lines() {
        let out = "Compiling playground v0.1.0\nerror: could not compile\nnot json at all\n";
        let (codes, messages, warns) = parse_diagnostics(out);
        assert!(codes.is_empty());
        assert!(messages.is_empty());
        assert_eq!(warns, 0);
    }

    #[test]
    fn ignored_tests_count_in_neither_passed_nor_total() {
        let s = "test result: ok. 3 passed; 2 failed; 5 ignored; 0 measured";
        assert_eq!(parse_test_summary(s), Some((3, 5)));
    }

    #[test]
    fn summary_without_counts_is_none() {
        // The marker is present but no `N passed; M failed` follows — must be
        // None so the caller flags `no_summary` instead of dividing by zero.
        assert_eq!(parse_test_summary("test result: FAILED."), None);
    }

    #[test]
    fn miri_ub_report_is_classified_as_ub() {
        // Miri prints its UB report on stderr while the harness summary may
        // still land on stdout — UB wins regardless of which stream carries it.
        let stderr = "error: Undefined Behavior: attempting a read access using \
                      <2593> at alloc1[0x0], but that tag does not exist";
        assert_eq!(parse_miri_verdict("", stderr), MiriVerdict::Ub);
        assert_eq!(
            parse_miri_verdict("error: unsupported operation: `foo`", ""),
            MiriVerdict::Ub
        );
        assert_eq!(
            parse_miri_verdict("", "error[E0080]: evaluation failed"),
            MiriVerdict::Ub
        );
    }

    #[test]
    fn miri_clean_run_needs_a_summary_and_reports_clean() {
        // The regression this pins: a clean run must be Clean, not Unknown —
        // otherwise every passing unsafe-core unit collects a bogus
        // `miri:no_summary` flag.
        assert_eq!(
            parse_miri_verdict("test result: ok. 3 passed; 0 failed", ""),
            MiriVerdict::Clean
        );
        assert_eq!(
            parse_miri_verdict("", "test result: ok. 1 passed; 0 failed"),
            MiriVerdict::Clean
        );
    }

    #[test]
    fn miri_no_summary_is_unknown_not_clean() {
        // Failed to build under miri: no UB marker and no summary. Unknown, so
        // the caller flags it instead of crediting a clean interpreter run.
        assert_eq!(parse_miri_verdict("", ""), MiriVerdict::Unknown);
        assert_eq!(
            parse_miri_verdict("", "error[E0432]: unresolved import"),
            MiriVerdict::Unknown
        );
    }

    #[test]
    fn miri_leak_report_is_not_ub() {
        // A leak is a resource report, not an undefined-behaviour report
        // (docs/03 mandates the latter). The verdict is Clean — "miri saw no
        // UB" — and the failing summary already zeroes the behaviour layer
        // through the ordinary L2 path, so the leak still costs the answer.
        let stderr = "error: memory leaked: alloc1 (Rust heap, size: 4, align: 4)";
        assert_eq!(
            parse_miri_verdict("test result: FAILED. 0 passed; 1 failed", stderr),
            MiriVerdict::Clean
        );
    }

    #[test]
    fn grade_rejects_dirty_workspace_before_touching_it() {
        let ws = std::env::temp_dir().join(format!("rb-oracle-dirty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ws);
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join("stale.txt"), "leftover").unwrap();
        let instance = Instance {
            prompt: String::new(),
            files: Default::default(),
            hidden: Default::default(),
            canary: String::new(),
        };
        let spec = GradeSpec {
            answer_path: Path::new("src/lib.rs"),
            weights: &OracleWeights::default(),
            behavior_test: None,
            differential_test: None,
            alloc_test: None,
            limits: bench_sandbox::Limits::default(),
            max_unsafe: None,
            forbidden_paths: Vec::new(),
            check_clippy: false,
            clippy_allow: Vec::new(),
            check_miri: false,
            gate: bench_sandbox::Gate::default(),
            // Neither test reaches policy construction (both short-circuit
            // earlier), so the bound is never consulted; the workspace's own
            // parent is the honest value.
            scratch_root: ws.parent().unwrap().to_path_buf(),
        };
        let err = grade(&instance, "", &spec, &ws).unwrap_err();
        match err {
            OracleError::DirtyWorkspace(p) => assert!(p.contains("rb-oracle-dirty")),
            other => panic!("expected DirtyWorkspace, got {other:?}"),
        }
        std::fs::remove_dir_all(&ws).ok();
    }

    #[test]
    fn grade_empty_response_short_circuits_to_apply_failed() {
        // An empty response has no code to extract: the oracle returns before
        // materialising anything — no cargo run, and the workspace stays empty.
        let ws = std::env::temp_dir().join(format!("rb-oracle-apply-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ws);
        std::fs::create_dir_all(&ws).unwrap();
        let instance = Instance {
            prompt: "p".into(),
            files: Default::default(),
            hidden: Default::default(),
            canary: "c".into(),
        };
        let spec = GradeSpec {
            answer_path: Path::new("src/lib.rs"),
            weights: &OracleWeights::default(),
            behavior_test: None,
            differential_test: None,
            alloc_test: None,
            limits: bench_sandbox::Limits::default(),
            max_unsafe: None,
            forbidden_paths: Vec::new(),
            check_clippy: false,
            clippy_allow: Vec::new(),
            check_miri: false,
            gate: bench_sandbox::Gate::default(),
            // Neither test reaches policy construction (both short-circuit
            // earlier), so the bound is never consulted; the workspace's own
            // parent is the honest value.
            scratch_root: ws.parent().unwrap().to_path_buf(),
        };
        let v = grade(&instance, "  \n\t", &spec, &ws).unwrap();
        assert!(!v.apply_ok);
        assert!(!v.compile_ok);
        assert_eq!(v.score, 0.0);
        // Nothing was written: L0 fails before any file lands.
        assert!(ws.read_dir().unwrap().next().is_none());
        std::fs::remove_dir_all(&ws).ok();
    }

    // AQ-202/OI-36c: the literal flags this crate pushes in the miri stage must
    // stay in lock-step with the refusal vocabulary in bench-core — a rename
    // here that misses there would silently re-open the fail-open hole.
    #[test]
    fn miri_flag_vocabulary_matches_bench_core() {
        let pushed: Vec<&str> = vec![
            MIRI_NO_TARGETS,
            MIRI_UNAVAILABLE,
            MIRI_TIMEOUT,
            MIRI_NO_SUMMARY,
            MIRI_CLEAN_FLAG,
            MIRI_UB_FLAG,
        ];
        for flag in &pushed[..4] {
            assert!(
                bench_core::MIRI_GAP_FLAGS.contains(flag),
                "oracle pushes {flag} as a gap; bench-core must classify it as one"
            );
        }
        assert_eq!(bench_core::MIRI_CLEAN_FLAG, pushed[4]);
        assert_eq!(bench_core::MIRI_UB_FLAG, pushed[5]);
        // And every gap flag really blocks a verdict.
        assert!(!bench_core::miri_verdict_recorded(
            &pushed[..4]
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<String>>()
        ));
        assert!(bench_core::miri_verdict_recorded(&[
            MIRI_CLEAN_FLAG.to_string()
        ]));
    }

    // ---- AQ-211 (r89b P7/P8): a workspace `.cargo/config*` steers the
    // measurement. These witnesses need a real sandboxed cargo run, so they
    // are gated like the bench-sandbox execution tests (macOS seatbelt is the
    // only backend until gate G1).

    /// A minimal dependency-free crate in a fresh workspace under the system
    /// temp dir — the shape `grade` materialises (docs/03-oracle.md).
    #[cfg(target_os = "macos")]
    fn aq211_workspace(tag: &str) -> std::path::PathBuf {
        let ws = std::env::temp_dir().join(format!("rb-aq211-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ws);
        std::fs::create_dir_all(ws.join("src")).unwrap();
        std::fs::write(
            ws.join("Cargo.toml"),
            "[package]\nname = \"aq211\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(ws.join("src/lib.rs"), "pub fn f() -> u32 { 1 }\n").unwrap();
        ws
    }

    #[cfg(target_os = "macos")]
    fn aq211_policy(ws: &Path) -> bench_sandbox::Policy {
        bench_sandbox::Policy::for_workspace(ws).unwrap()
    }

    /// Assert the run REFUSED (fail closed) and hand back the reason.
    #[cfg(target_os = "macos")]
    fn aq211_expect_refusal(run: std::io::Result<CargoRun>) -> std::io::Error {
        match run {
            Ok(_) => panic!("grading must refuse a workspace .cargo/config* (AQ-211)"),
            Err(e) => e,
        }
    }

    /// Serialise the macOS end-to-end witnesses: they spawn real cargo under a
    /// policy derived from the process environment, and AQ-215's ambient-env
    /// witness temporarily rewrites `CARGO_HOME` — a global — so concurrent
    /// policy construction in sibling tests must not observe it mid-flight.
    #[cfg(target_os = "macos")]
    fn e2e_lock() -> std::sync::MutexGuard<'static, ()> {
        static E2E_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        E2E_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    // The predicate behind the refusal is pure filesystem inspection, so its
    // table is unit-tested on every platform the workspace builds on — no
    // sandboxed run needed.

    #[test]
    fn workspace_config_predicate_refuses_config_toml() {
        let ws = std::env::temp_dir().join(format!("rb-aq211-p1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ws);
        std::fs::create_dir_all(ws.join(".cargo")).unwrap();
        std::fs::write(ws.join(".cargo/config.toml"), "[env]\nX = \"1\"\n").unwrap();
        let reason = workspace_cargo_config_refusal_reason(&ws).expect("must refuse");
        assert!(reason.contains("config.toml"), "{reason}");
        std::fs::remove_dir_all(&ws).ok();
    }

    #[test]
    fn workspace_config_predicate_refuses_legacy_config() {
        let ws = std::env::temp_dir().join(format!("rb-aq211-p2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ws);
        std::fs::create_dir_all(ws.join(".cargo")).unwrap();
        std::fs::write(ws.join(".cargo/config"), "[net]\nretry = 1\n").unwrap();
        let reason = workspace_cargo_config_refusal_reason(&ws).expect("must refuse");
        assert!(
            reason.contains("config\"") || reason.contains("config "),
            "{reason}"
        );
        std::fs::remove_dir_all(&ws).ok();
    }

    #[test]
    #[cfg(unix)]
    fn workspace_config_predicate_refuses_dangling_symlink() {
        let ws = std::env::temp_dir().join(format!("rb-aq211-p3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ws);
        std::fs::create_dir_all(ws.join(".cargo")).unwrap();
        std::os::unix::fs::symlink("nowhere", ws.join(".cargo/config.toml")).unwrap();
        assert!(workspace_cargo_config_refusal_reason(&ws).is_some());
        std::fs::remove_dir_all(&ws).ok();
    }

    #[test]
    fn workspace_config_predicate_refuses_directory_at_config_path() {
        // A non-regular presence (the AQ-209 lesson, here std-only): refuse
        // without opening anything.
        let ws = std::env::temp_dir().join(format!("rb-aq211-p4-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ws);
        std::fs::create_dir_all(ws.join(".cargo/config.toml")).unwrap();
        assert!(workspace_cargo_config_refusal_reason(&ws).is_some());
        std::fs::remove_dir_all(&ws).ok();
    }

    #[test]
    fn workspace_config_predicate_allows_no_cargo_directory() {
        let ws = std::env::temp_dir().join(format!("rb-aq211-p5-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ws);
        std::fs::create_dir_all(ws.join("src")).unwrap();
        assert!(workspace_cargo_config_refusal_reason(&ws).is_none());
        std::fs::remove_dir_all(&ws).ok();
    }

    #[test]
    fn workspace_config_predicate_allows_cargo_dir_without_config_files() {
        // Over-refusal guard: a `.cargo` directory that carries no config at
        // either name is not itself a steering channel.
        let ws = std::env::temp_dir().join(format!("rb-aq211-p6-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ws);
        std::fs::create_dir_all(ws.join(".cargo")).unwrap();
        std::fs::write(ws.join(".cargo/README.txt"), "not a config\n").unwrap();
        assert!(workspace_cargo_config_refusal_reason(&ws).is_none());
        std::fs::remove_dir_all(&ws).ok();
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn grading_refuses_workspace_config_target_dir_redirect() {
        let _e2e = e2e_lock();
        let ws = aq211_workspace("tardir");
        // A fixed path OUTSIDE the workspace (r89b P7): artifacts landing here
        // survive the run's scratch cleanup, so a completion can warm a
        // cross-run cache or steer measured artifact size.
        let stolen = std::env::temp_dir().join(format!("rb-aq211-stolen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&stolen);
        std::fs::create_dir_all(ws.join(".cargo")).unwrap();
        std::fs::write(
            ws.join(".cargo/config.toml"),
            format!("[build]\ntarget-dir = \"{}\"\n", stolen.display()),
        )
        .unwrap();
        let err = aq211_expect_refusal(run_cargo(
            &aq211_policy(&ws),
            &["build", "--offline", "--message-format=json"],
        ));
        assert!(
            err.to_string().contains(".cargo"),
            "refusal must name the workspace config: {err}"
        );
        // The redirect must never take effect: no artifacts outside the
        // workspace, so no cross-run cache can be warmed at a fixed path.
        assert!(
            !stolen.exists(),
            "artifacts must never land outside the grading workspace"
        );
        std::fs::remove_dir_all(&ws).ok();
        std::fs::remove_dir_all(&stolen).ok();
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn grading_refuses_workspace_config_env_injection_to_build_scripts() {
        let _e2e = e2e_lock();
        let ws = aq211_workspace("env");
        // Build scripts are model-authored (docs/03: proc macros and build
        // scripts run at build time, under containment) — r89b P8 proved the
        // `[env]` table hands them values. Here the script records receipt.
        std::fs::write(
            ws.join("build.rs"),
            "use std::path::PathBuf;\n\
             fn main() {\n\
             \x20   if let Ok(v) = std::env::var(\"AQ211_CANARY\") {\n\
             \x20       let out = PathBuf::from(std::env::var(\"CARGO_MANIFEST_DIR\").unwrap());\n\
             \x20       std::fs::write(out.join(\"aq211-env-proof.txt\"), v).unwrap();\n\
             \x20   }\n\
             }\n",
        )
        .unwrap();
        std::fs::create_dir_all(ws.join(".cargo")).unwrap();
        std::fs::write(
            ws.join(".cargo/config.toml"),
            "[env]\nAQ211_CANARY = \"stolen-value\"\n",
        )
        .unwrap();
        let err = aq211_expect_refusal(run_cargo(
            &aq211_policy(&ws),
            &["build", "--offline", "--message-format=json"],
        ));
        assert!(
            err.to_string().contains(".cargo"),
            "refusal must name the workspace config: {err}"
        );
        // The build script must never have run: the proof file is the record
        // that the injected env value reached model code.
        assert!(
            !ws.join("aq211-env-proof.txt").exists(),
            "the [env] table must not reach a build script"
        );
        std::fs::remove_dir_all(&ws).ok();
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn grading_refuses_workspace_config_target_runner_replacement() {
        let _e2e = e2e_lock();
        let ws = aq211_workspace("runner");
        std::fs::write(
            ws.join("src/lib.rs"),
            "#[cfg(test)]\n#[test]\nfn passes() { assert_eq!(1 + 1, 2); }\n",
        )
        .unwrap();
        std::fs::create_dir_all(ws.join(".cargo")).unwrap();
        // With this honoured, `cargo test` never executes the test harness:
        // the binary is merely echoed (exit 0, no summary) — the oracle would
        // read a run shape the harness did not produce (r89b residual table).
        std::fs::write(
            ws.join(".cargo/config.toml"),
            "[target.'cfg(all())']\nrunner = \"/bin/echo\"\n",
        )
        .unwrap();
        let err = aq211_expect_refusal(run_cargo(
            &aq211_policy(&ws),
            &["test", "--offline", "--quiet"],
        ));
        assert!(
            err.to_string().contains(".cargo"),
            "refusal must name the workspace config: {err}"
        );
        std::fs::remove_dir_all(&ws).ok();
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn grading_passes_legitimate_task_without_workspace_cargo_config() {
        let _e2e = e2e_lock();
        // The over-refusal guard: a task whose workspace carries no `.cargo`
        // directory — the only shape a benchmark task legitimately has — must
        // still build and test normally, with artifacts in the run's own
        // scratch and a real test summary (the harness really ran).
        let ws = aq211_workspace("clean");
        std::fs::write(
            ws.join("src/lib.rs"),
            "#[cfg(test)]\n#[test]\nfn passes() { assert_eq!(1 + 1, 2); }\n",
        )
        .unwrap();
        let build = run_cargo(
            &aq211_policy(&ws),
            &["build", "--offline", "--message-format=json"],
        )
        .expect("a task with no .cargo directory must still grade");
        assert!(build.success, "clean build failed: {}", build.stderr);
        let test = run_cargo(&aq211_policy(&ws), &["test", "--offline", "--quiet"])
            .expect("a task with no .cargo directory must still grade");
        assert!(test.success, "clean test run failed: {}", test.stderr);
        assert!(
            parse_test_summary(&test.stdout)
                .or_else(|| parse_test_summary(&test.stderr))
                .is_some(),
            "the real test harness must have run: {}/{}",
            test.stdout,
            test.stderr
        );
        assert!(
            ws.join("target").exists(),
            "artifacts must land in the run's own scratch"
        );
        std::fs::remove_dir_all(&ws).ok();
    }

    // ------------------------------------------------------------------
    // AQ-215 (review r94): the three adjacent cargo-config channels.
    // W1 — ancestor .cargo/config (F-1, probe B);
    // W2 — rust-toolchain{.toml} pins (F-3);
    // W3 — a NON-credential config in the cargo home (F-2, probe C);
    // W4 — an ambient CARGO_HOME must lose to the pinned harness home.
    // The refusal witnesses are written against the pre-existing
    // [`Policy::for_workspace`] surface on purpose: they must compile (and
    // FAIL) on the unpatched commit, proving the hole was real.
    // ------------------------------------------------------------------

    /// W1 (r94 F-1, probe B): cargo walks UP from the working directory for
    /// `.cargo/config.toml`, so a config in a scratch ANCESTOR steers the
    /// grade exactly as a workspace one does. Planted at the scratch root
    /// with an `[env]` canary + a recorder build script: the grade must
    /// refuse before any spawn, and the build script must never run.
    #[test]
    #[cfg(target_os = "macos")]
    fn grading_refuses_ancestor_dir_config_env_canary() {
        let _e2e = e2e_lock();
        // A scratch root with the graded workspace nested inside it — the
        // shape every harness grade has.
        let root = std::env::temp_dir().join(format!("rb-aq215-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let ws = root.join("grade-ws");
        std::fs::create_dir_all(ws.join("src")).unwrap();
        std::fs::write(
            ws.join("Cargo.toml"),
            "[package]\nname = \"aq215-anc\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(ws.join("src/lib.rs"), "pub fn f() -> u32 { 1 }\n").unwrap();
        // The recorder: proof that the ancestor `[env]` reached model code.
        std::fs::write(
            ws.join("build.rs"),
            "use std::path::PathBuf;\n\
             fn main() {\n\
             \x20   if let Ok(v) = std::env::var(\"AQ215_CANARY\") {\n\
             \x20       let out = PathBuf::from(std::env::var(\"CARGO_MANIFEST_DIR\").unwrap());\n\
             \x20       std::fs::write(out.join(\"aq215-ancestor-proof.txt\"), v).unwrap();\n\
             \x20   }\n\
             }\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join(".cargo")).unwrap();
        std::fs::write(
            root.join(".cargo/config.toml"),
            "[env]\nAQ215_CANARY = \"stolen-ancestor\"\n",
        )
        .unwrap();
        let err = aq211_expect_refusal(run_cargo(
            &aq211_policy(&ws),
            &["build", "--offline", "--message-format=json"],
        ));
        // Name the channel precisely: the refusal must point at the ANCESTOR
        // config (inside the scratch root), not anywhere else.
        assert!(
            err.to_string()
                .contains(root.join(".cargo/config.toml").to_str().unwrap()),
            "refusal must name the ancestor config: {err}"
        );
        assert!(
            !ws.join("aq215-ancestor-proof.txt").exists(),
            "the ancestor [env] table must not reach a build script"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// W2 (r94 F-3): a `rust-toolchain.toml` in the graded workspace must
    /// refuse — rustup discovers toolchain pins by the same ancestor walk,
    /// and no benchmark task ships one. The legacy extensionless spelling
    /// refuses identically.
    #[test]
    #[cfg(target_os = "macos")]
    fn grading_refuses_workspace_rust_toolchain_file() {
        let _e2e = e2e_lock();
        for variant in ["rust-toolchain.toml", "rust-toolchain"] {
            let ws = aq211_workspace("aq215-toolchain");
            std::fs::write(ws.join(variant), "[toolchain]\nchannel = \"1.88.0\"\n").unwrap();
            let err = aq211_expect_refusal(run_cargo(
                &aq211_policy(&ws),
                &["build", "--offline", "--message-format=json"],
            ));
            assert!(
                err.to_string().contains("rust-toolchain") && err.to_string().contains("AQ-215"),
                "{variant}: refusal must name the toolchain pin: {err}"
            );
            std::fs::remove_dir_all(&ws).ok();
        }
    }

    /// W3 (r94 F-2, probe C): the AQ-205 token predicate only rejects
    /// CREDENTIAL keys in the cargo home — a config carrying anything else
    /// (here an `[env]` table) reached graded code. The oracle's cargo home
    /// must be config-FREE: any presence refuses.
    #[test]
    #[cfg(target_os = "macos")]
    fn grading_refuses_noncredential_cargo_home_config_env() {
        let _e2e = e2e_lock();
        let ws = aq211_workspace("aq215-ch");
        // A planted cargo home whose config carries NO credential key —
        // exactly the shape the AQ-205 predicate deliberately lets through.
        let planted = std::env::temp_dir().join(format!("rb-aq215-ch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&planted);
        std::fs::create_dir_all(&planted).unwrap();
        let planted = planted.canonicalize().unwrap();
        std::fs::write(
            planted.join("config.toml"),
            "[env]\nAQ215_CH_CANARY = \"stolen-home\"\n",
        )
        .unwrap();
        let mut policy = aq211_policy(&ws);
        policy.cargo_home = planted.clone();
        let err = aq211_expect_refusal(run_cargo(
            &policy,
            &["build", "--offline", "--message-format=json"],
        ));
        assert!(
            err.to_string().contains("cargo home") && err.to_string().contains("AQ-215"),
            "refusal must name the cargo-home config: {err}"
        );
        std::fs::remove_dir_all(&ws).ok();
        std::fs::remove_dir_all(&planted).ok();
    }

    /// W4 (r94 F-2, probe C, env spelling): an AMBIENT `CARGO_HOME` pointing
    /// at a canary-config home must lose to the oracle's pinned home — the
    /// build must succeed and the canary must never reach the build script.
    /// On the unpatched commit the child simply inherits the ambient home,
    /// the canary lands in the proof file, and this fails — the RED state.
    #[test]
    #[cfg(target_os = "macos")]
    fn grading_cargo_home_pin_beats_ambient_env() {
        let _e2e = e2e_lock();
        let ws = aq211_workspace("aq215-pin");
        std::fs::write(
            ws.join("src/lib.rs"),
            "#[cfg(test)]\n#[test]\nfn passes() { assert_eq!(1 + 1, 2); }\n",
        )
        .unwrap();
        std::fs::write(
            ws.join("build.rs"),
            "use std::path::PathBuf;\n\
             fn main() {\n\
             \x20   if let Ok(v) = std::env::var(\"AQ215_AMBIENT_CANARY\") {\n\
             \x20       let out = PathBuf::from(std::env::var(\"CARGO_MANIFEST_DIR\").unwrap());\n\
             \x20       std::fs::write(out.join(\"aq215-ambient-proof.txt\"), v).unwrap();\n\
             \x20   }\n\
             }\n",
        )
        .unwrap();
        // The ambient (operator) home, carrying a non-credential [env] table.
        let ambient = std::env::temp_dir().join(format!("rb-aq215-ambient-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ambient);
        std::fs::create_dir_all(&ambient).unwrap();
        let ambient = ambient.canonicalize().unwrap();
        std::fs::write(
            ambient.join("config.toml"),
            "[env]\nAQ215_AMBIENT_CANARY = \"stolen-ambient\"\n",
        )
        .unwrap();
        // The policy's own home: a fresh harness-made directory (the pinned
        // home), config-free by construction.
        let pinned = std::env::temp_dir().join(format!("rb-aq215-pinned-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&pinned);
        std::fs::create_dir_all(&pinned).unwrap();
        let pinned = pinned.canonicalize().unwrap();
        let mut policy = aq211_policy(&ws);
        policy.cargo_home = pinned.clone();
        // Ambient injection — the thing the pin must defeat. Process-global:
        // restored before the lock is dropped.
        let saved = std::env::var_os("CARGO_HOME");
        std::env::set_var("CARGO_HOME", &ambient);
        let build = run_cargo(&policy, &["build", "--offline", "--message-format=json"]);
        match saved {
            Some(v) => std::env::set_var("CARGO_HOME", v),
            None => std::env::remove_var("CARGO_HOME"),
        }
        let build = build.expect("the pinned home is config-free: the build must run");
        assert!(build.success, "clean build failed: {}", build.stderr);
        assert!(
            !ws.join("aq215-ambient-proof.txt").exists(),
            "the ambient CARGO_HOME config must not reach a build script — \
             the pin must win (AQ-215)"
        );
        assert!(
            ws.join("target").exists(),
            "artifacts must land in the run's own scratch"
        );
        std::fs::remove_dir_all(&ws).ok();
        std::fs::remove_dir_all(&ambient).ok();
        std::fs::remove_dir_all(&pinned).ok();
    }

    /// W5 — the integration witness: a CLEAN task through the real [`grade`]
    /// path still scores 1.0 with every AQ-215 measure active — the policy
    /// scoped to the spec's scratch root, the harness-made cargo home pinned
    /// over any ambient one, the narrowed seatbelt profile, and the TMPDIR
    /// pin. This is the over-refusal guard for the whole patch: the measures
    /// must cost the measurement nothing.
    #[test]
    #[cfg(target_os = "macos")]
    fn grade_routes_through_harness_scratch_and_home_score_one() {
        let _e2e = e2e_lock();
        let scratch = std::env::temp_dir().join(format!("rb-aq215-scratch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let scratch = scratch.canonicalize().unwrap();
        let ws = scratch.join("grade-ws");
        std::fs::create_dir_all(&ws).unwrap();
        let instance = Instance {
            prompt: "implement double".into(),
            files: [
                (
                    std::path::PathBuf::from("Cargo.toml"),
                    "[package]\nname = \"aq215-w5\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
                        .to_string(),
                ),
                (
                    std::path::PathBuf::from("src/lib.rs"),
                    "pub fn double(x: u32) -> u32 { 0 }\n".to_string(),
                ),
            ]
            .into_iter()
            .collect(),
            hidden: [(
                std::path::PathBuf::from("tests/behavior.rs"),
                "#[test]\nfn doubles() { assert_eq!(aq215_w5::double(21), 42); }\n".to_string(),
            )]
            .into_iter()
            .collect(),
            canary: "aq215-w5-canary".into(),
        };
        let response = "```rust\npub fn double(x: u32) -> u32 { x * 2 }\n```";
        let spec = GradeSpec {
            answer_path: Path::new("src/lib.rs"),
            weights: &OracleWeights::default(),
            behavior_test: Some("behavior"),
            differential_test: None,
            alloc_test: None,
            limits: bench_sandbox::Limits::default(),
            max_unsafe: None,
            forbidden_paths: Vec::new(),
            check_clippy: false,
            clippy_allow: Vec::new(),
            check_miri: false,
            gate: bench_sandbox::Gate::default(),
            scratch_root: scratch.clone(),
        };
        let v = grade(&instance, response, &spec, &ws).expect("a clean grade must succeed");
        assert!(v.apply_ok);
        assert!(
            v.compile_ok,
            "flags={:?} errors={:?}",
            v.flags, v.error_codes
        );
        assert_eq!(v.behavior.unit, Some(1.0));
        assert_eq!(v.score, 1.0, "the clean task must still score one");
        assert!(v.flags.is_empty(), "{:?}", v.flags);
        // The harness home was made inside the scratch root and used.
        assert!(scratch.join(".cargo-home").exists());
        std::fs::remove_dir_all(&scratch).ok();
    }
}
