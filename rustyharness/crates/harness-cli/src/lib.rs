//! `rustyharness`: the command line (design §7.7, §2.9, §2.10, §3.4), as a
//! library the binary (`src/main.rs`) calls with the real per-OS locality
//! probe (`harness_sandbox::locality::SystemProbe`). Tests call
//! [`main_with`] in process with their own probe; no build of the binary
//! can switch its probe (H1e-2b review F-2).
//!
//! `run`, `resume` and `replay` are **gate children** (§7.7): whatever
//! happens after the arguments are read, the LAST stdout line is the
//! run's `GateReport` as JSON (UNIFIED §6.1), and the exit code agrees
//! with it:
//!
//! | Exit | Meaning |
//! |---|---|
//! | 0 | `Passed`; the `GATE_OK_FILE` marker is written only then, after `RunStopped` is durable and the report line is out |
//! | 1 | `Failed` |
//! | 2 | usage error |
//! | 3 | confinement refused (never in H1: no session may hold an execute grant) |
//! | 4 | unreadable input (task spec, policy, profile; a manifest for `manifest check`) |
//! | 5 | `Indeterminate` (the kind is in the JSON): every H1 run, a refused run (e.g. the locality check), a journal failure, a replay divergence |
//!
//! Every H1 run is `Indeterminate { NothingChecked }` and exits 5 with no
//! marker, whatever the agent did. Before the report line, one line
//! `chain_head <sha256>` names the journal's final chain head (§7.1
//! "Anchoring"): keep it to detect a replaced journal later
//! (`replay --anchor`).
//!
//! The commit order (§7.1): `RunStopped` durable (inside the run), then the
//! report line, then the marker (only for `Passed`), then exit. If writing
//! the report line or the marker fails, the exit is 5, never 0.
//!
//! `profile check` runs the smoke eval against a live server and prints the
//! stamp to add to the profile (it is not a gate child).
//!
//! `manifest check` validates a provider manifest with the admission parser
//! (not a gate child either): exit 0 valid, 1 refused on content, 4 not
//! readable as a JSON document at all (missing, too large, not well-formed
//! JSON), 5 if the harness cannot check (its own version is not SemVer). A
//! valid manifest is not an admitted one.

#![forbid(unsafe_code)]
// The panic-set lints ratchet production code; unit tests may assert loosely.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use gate_outcome::{
    Coverage, Finding, FindingCode, GateId, GateOutcome, GateReport, IndeterminateKind, Scope,
    Severity,
};
use harness_core::RunId;
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, ManifestError, SemVer, ValidationContext};
use harness_model::client::{ClientConfig, OpenAiCompatible};
use harness_model::profile::{CheckResult, Profile};
use harness_model::TaskText;
use harness_policy::locality::LocalityProbe;
use harness_policy::UserPolicy;
use harness_run::{Audit, Resume, Run, RunConfig, RunRefused, TaskSpec};
use harness_sandbox::environment::SystemEnv;
use serde::Deserialize;

const USAGE: &str = "usage:
  rustyharness version
  rustyharness sandbox             report confinement (refuses to run anything without it)
  rustyharness manifest check <file.json>   exit 0 valid (valid is not admitted), 1 refused, 4 unreadable
  rustyharness run    --task <task.json> --workspace <dir> --state-root <dir>
                      --profile <profile.json> --endpoint <http://127.0.0.1:PORT/v1>
                      [--policy <policy.json>] [--gate <gate-id>]
  rustyharness resume --run <run-id> + the run options
  rustyharness replay --run <run-id> --task <task.json> --state-root <dir>
                      --profile <profile.json> [--attempt <n>] [--anchor <sha256>]
                      [--policy <policy.json>] [--gate <gate-id>]
  rustyharness profile check --profile <profile.json> --endpoint <url>";

/// The gate id the report names when `--gate` is not given.
const DEFAULT_GATE: &str = "rustyharness.run";

mod exit {
    pub const PASSED: u8 = 0;
    pub const FAILED: u8 = 1;
    pub const USAGE: u8 = 2;
    pub const UNREADABLE_INPUT: u8 = 4;
    pub const INDETERMINATE: u8 = 5;
}

/// Where the CLI writes, and what it is given from outside: the locality
/// probe and the `GATE_OK_FILE` marker path. The shipped binary
/// (`src/main.rs`) always passes the real per-OS probe
/// (`harness_sandbox::locality::SystemProbe`, spike S-F1; on Windows it
/// refuses every `state_root` until spike S-W1) and the marker path from the
/// environment; only this crate's tests pass another probe, in process. No
/// build of the binary carries a way to switch the probe (H1e-2b review F-2).
pub struct Cx<'a> {
    /// The filesystem-locality probe.
    pub probe: &'a dyn LocalityProbe,
    /// The `GATE_OK_FILE` path, if the parent set one.
    pub gate_ok_file: Option<PathBuf>,
    /// Standard output.
    pub out: RefCell<&'a mut dyn Write>,
    /// Standard error.
    pub err: RefCell<&'a mut dyn Write>,
}

impl Cx<'_> {
    fn note(&self, s: &str) {
        let _ = writeln!(self.err.borrow_mut(), "{s}");
    }
    fn say(&self, s: &str) {
        let _ = writeln!(self.out.borrow_mut(), "{s}");
    }
}

macro_rules! note {
    ($cx:expr, $($t:tt)*) => { $cx.note(&format!($($t)*)) };
}
macro_rules! say {
    ($cx:expr, $($t:tt)*) => { $cx.say(&format!($($t)*)) };
}

/// Run the command line `args` (without the program name). Returns the
/// process exit code.
pub fn main_with(cx: &Cx<'_>, args: &[&str]) -> u8 {
    match args {
        ["version"] => {
            say!(cx, "rustyharness {}", env!("CARGO_PKG_VERSION"));
            0
        }
        ["sandbox"] => match harness_sandbox::require() {
            Ok(b) => {
                say!(cx, "confinement available: {b:?}");
                0
            }
            Err(e) => {
                note!(cx, "{e}");
                3
            }
        },
        ["manifest", "check", path] => manifest_check(cx, path),
        ["run", rest @ ..] => gate_child(cx, rest, Verb::Run),
        ["resume", rest @ ..] => gate_child(cx, rest, Verb::Resume),
        ["replay", rest @ ..] => gate_child(cx, rest, Verb::Replay),
        ["profile", "check", rest @ ..] => profile_check(cx, rest),
        _ => {
            note!(cx, "{USAGE}");
            exit::USAGE
        }
    }
}

// ---------------------------------------------------------------------------
// Gate-child plumbing.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Verb {
    Run,
    Resume,
    Replay,
}

/// What a gate-child verb ends with.
struct Outcome {
    outcome: GateOutcome,
    findings: Vec<Finding>,
    chain_head: Option<String>,
    /// The exit code for a non-verdict ending (usage, unreadable input).
    exit_override: Option<u8>,
}

fn info(code: &str, location: &str, expected: &str, observed: String) -> Option<Finding> {
    Finding::new(
        Severity::Info,
        FindingCode(code.to_owned()),
        location,
        expected,
        observed,
    )
    .ok()
}

fn indeterminate(why: IndeterminateKind) -> GateOutcome {
    GateOutcome::Indeterminate { why }
}

fn refused(exit_code: u8, observed: String) -> Outcome {
    Outcome {
        outcome: indeterminate(IndeterminateKind::CouldNotRun),
        findings: info(
            "harness.refused",
            "rustyharness",
            "a run that starts",
            observed,
        )
        .into_iter()
        .collect(),
        chain_head: None,
        exit_override: Some(exit_code),
    }
}

/// Parse `--key value` pairs; a repeated or unknown key is a usage error.
fn options<'a>(rest: &[&'a str], allowed: &[&str]) -> Result<BTreeMap<&'a str, &'a str>, String> {
    let mut out = BTreeMap::new();
    let mut it = rest.iter();
    while let Some(k) = it.next() {
        let key = k
            .strip_prefix("--")
            .filter(|k| allowed.contains(k))
            .ok_or_else(|| format!("unknown option {k}"))?;
        let v = it.next().ok_or_else(|| format!("--{key} needs a value"))?;
        if out.insert(key, *v).is_some() {
            return Err(format!("--{key} given twice"));
        }
    }
    Ok(out)
}

fn gate_child(cx: &Cx<'_>, rest: &[&str], verb: Verb) -> u8 {
    let allowed: &[&str] = match verb {
        Verb::Run => &[
            "task",
            "workspace",
            "state-root",
            "profile",
            "endpoint",
            "policy",
            "gate",
        ],
        Verb::Resume => &[
            "run",
            "task",
            "workspace",
            "state-root",
            "profile",
            "endpoint",
            "policy",
            "gate",
        ],
        Verb::Replay => &[
            "run",
            "task",
            "state-root",
            "profile",
            "attempt",
            "anchor",
            "policy",
            "gate",
        ],
    };
    let parsed = options(rest, allowed);
    let gate_text = parsed
        .as_ref()
        .ok()
        .and_then(|o| o.get("gate").copied())
        .unwrap_or(DEFAULT_GATE);
    // An invalid --gate is a usage error like any other, reported under
    // the default id (H1e-2b review F-3): the report line is never missing.
    let (gate, bad_gate) = match GateId::new(gate_text) {
        Ok(g) => (g, false),
        Err(_) => match GateId::new(DEFAULT_GATE) {
            Ok(g) => (g, true),
            Err(_) => return exit::USAGE,
        },
    };
    if bad_gate {
        note!(cx, "--gate is not a valid gate id\n{USAGE}");
        return emit(
            cx,
            &gate,
            refused(exit::USAGE, "--gate is not a valid gate id".into()),
        );
    }
    let result = match parsed {
        Err(e) => {
            note!(cx, "{e}\n{USAGE}");
            refused(exit::USAGE, "usage error".into())
        }
        Ok(o) => match verb {
            Verb::Run | Verb::Resume => run_or_resume(cx, &o, verb),
            Verb::Replay => replay(cx, &o),
        },
    };
    emit(cx, &gate, result)
}

/// The commit sequence after the run (§7.1): the chain head, the report
/// line (last stdout line), the marker only for `Passed`, then exit.
fn emit(cx: &Cx<'_>, gate: &GateId, o: Outcome) -> u8 {
    let code = match (&o.exit_override, &o.outcome) {
        (Some(c), _) => *c,
        (None, GateOutcome::Passed(_)) => exit::PASSED,
        (None, GateOutcome::Failed) => exit::FAILED,
        (None, GateOutcome::Indeterminate { .. }) => exit::INDETERMINATE,
    };
    let is_pass = matches!(o.outcome, GateOutcome::Passed(_));
    // `GateReport::new` refuses `Passed` (a witness is minted only inside
    // gate-outcome); H1 never produces one, and if some later slice did,
    // this line would fail closed to CouldNotRun below.
    let report = GateReport::new(
        gate.clone(),
        o.outcome,
        o.findings,
        Coverage::Full,
        Scope::empty(),
    )
    .or_else(|_| {
        GateReport::new(
            gate.clone(),
            indeterminate(IndeterminateKind::CouldNotRun),
            Vec::new(),
            Coverage::Full,
            Scope::empty(),
        )
    });
    let Ok(report) = report else {
        return exit::INDETERMINATE;
    };
    let Ok(line) = serde_json::to_string(&report) else {
        return exit::INDETERMINATE;
    };
    let mut out = cx.out.borrow_mut();
    let mut written = true;
    if let Some(h) = &o.chain_head {
        written &= writeln!(out, "chain_head {h}").is_ok();
    }
    written &= writeln!(out, "{line}").is_ok() && out.flush().is_ok();
    if !written {
        // §7.1 (review r65 L-01): no green exit without the report.
        return exit::INDETERMINATE;
    }
    if is_pass && code == exit::PASSED {
        let marker_ok = cx
            .gate_ok_file
            .as_ref()
            .is_some_and(|p| std::fs::write(p, format!("ok {}\n", gate.as_str())).is_ok());
        if !marker_ok {
            return exit::INDETERMINATE;
        }
    }
    code
}

// ---------------------------------------------------------------------------
// Inputs.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskFile {
    task: String,
    grants: Vec<String>,
    #[serde(default)]
    workspace_public: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    deny: Vec<String>,
    #[serde(default)]
    ask: Vec<String>,
    #[serde(default)]
    allow: Vec<String>,
}

/// Largest input file read (task, policy, profile).
const INPUT_MAX_BYTES: u64 = 1024 * 1024;

fn read_input(path: &str) -> Result<Vec<u8>, String> {
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

struct Inputs {
    spec: TaskSpec,
    policy: UserPolicy,
    profile: Profile,
    registry: Registry,
}

fn required<'a>(cx: &Cx<'_>, o: &BTreeMap<&str, &'a str>, k: &str) -> Result<&'a str, Outcome> {
    o.get(k).copied().ok_or_else(|| {
        note!(cx, "--{k} is required\n{USAGE}");
        refused(exit::USAGE, format!("--{k} missing"))
    })
}

fn inputs(cx: &Cx<'_>, o: &BTreeMap<&str, &str>) -> Result<Inputs, Outcome> {
    let unreadable = |e: String| {
        note!(cx, "{e}");
        refused(exit::UNREADABLE_INPUT, e)
    };
    let task: TaskFile = strict(required(cx, o, "task")?).map_err(unreadable)?;
    let policy = match o.get("policy") {
        None => UserPolicy::default(),
        Some(p) => {
            let f: PolicyFile = strict(p).map_err(unreadable)?;
            fn v(l: &[String]) -> Vec<&str> {
                l.iter().map(String::as_str).collect()
            }
            UserPolicy::new(&v(&f.deny), &v(&f.ask), &v(&f.allow))
                .map_err(|e| unreadable(format!("policy: {e}")))?
        }
    };
    let profile_path = required(cx, o, "profile")?;
    let profile = Profile::parse(&read_input(profile_path).map_err(unreadable)?)
        .map_err(|e| unreadable(format!("{profile_path}: {e}")))?;
    let registry = builtin_registry().map_err(unreadable)?;
    Ok(Inputs {
        spec: TaskSpec {
            task: TaskText::new(task.task),
            grants: task.grants,
            workspace_public: task.workspace_public,
        },
        policy,
        profile,
        registry,
    })
}

fn builtin_registry() -> Result<Registry, String> {
    let v = SemVer::parse(env!("CARGO_PKG_VERSION")).ok_or("harness version")?;
    let ctx = ValidationContext::new(v, &[]).map_err(|e| e.to_string())?;
    let m = builtin::manifest(&ctx).map_err(|e| e.to_string())?;
    Registry::admit(vec![(m, Tier::Builtin)]).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Verbs.
// ---------------------------------------------------------------------------

fn from_refusal(cx: &Cx<'_>, e: &RunRefused) -> Outcome {
    note!(cx, "the run did not start: {e}");
    let mut o = refused(exit::INDETERMINATE, format!("the run did not start: {e}"));
    o.outcome = e.outcome();
    o
}

fn run_or_resume(cx: &Cx<'_>, o: &BTreeMap<&str, &str>, verb: Verb) -> Outcome {
    match try_run(cx, o, verb) {
        Ok(x) | Err(x) => x,
    }
}

fn try_run(cx: &Cx<'_>, o: &BTreeMap<&str, &str>, verb: Verb) -> Result<Outcome, Outcome> {
    let inp = inputs(cx, o)?;
    let workspace = required(cx, o, "workspace")?;
    let state_root = required(cx, o, "state-root")?;
    let endpoint = required(cx, o, "endpoint")?;
    let run_id = match verb {
        Verb::Resume => Some(RunId::parse(required(cx, o, "run")?).ok_or_else(|| {
            note!(cx, "--run is not a run id");
            refused(exit::USAGE, "--run is not a run id".into())
        })?),
        _ => None,
    };
    let client =
        OpenAiCompatible::new(endpoint, inp.profile.clone(), None, ClientConfig::default())
            .map_err(|e| {
                note!(cx, "endpoint refused: {e}");
                refused(exit::UNREADABLE_INPUT, format!("endpoint refused: {e}"))
            })?;
    let probe = cx.probe;
    let config = RunConfig::defaults(1_000_000);
    // The state root's locality first (§2.8): a run that cannot start does
    // not contact the model server. The run checks it again itself.
    let root = std::fs::canonicalize(state_root)
        .map_err(|e| from_refusal(cx, &RunRefused::StateRoot(e)))?;
    harness_policy::locality::check(probe, &root.to_string_lossy())
        .map_err(|e| from_refusal(cx, &RunRefused::Locality(e)))?;
    if let Err(e) = client.startup_check(Instant::now() + Duration::from_secs(30)) {
        note!(cx, "model server check failed: {e}");
        return Err(refused(
            exit::INDETERMINATE,
            format!("model server check failed: {e}"),
        ));
    }
    let report = match run_id {
        None => harness_run::run(Run {
            state_root: std::path::Path::new(state_root),
            workspace: std::path::Path::new(workspace),
            spec: &inp.spec,
            registry: &inp.registry,
            policy: &inp.policy,
            profile: &inp.profile,
            backend: &client,
            probe,
            env: &SystemEnv,
            config: &config,
        }),
        Some(id) => harness_run::resume(Resume {
            state_root: std::path::Path::new(state_root),
            run: &id,
            workspace: std::path::Path::new(workspace),
            spec: &inp.spec,
            registry: &inp.registry,
            policy: &inp.policy,
            profile: &inp.profile,
            backend: &client,
            probe,
            env: &SystemEnv,
            config: &config,
        }),
    }
    .map_err(|e| from_refusal(cx, &e))?;
    note!(
        cx,
        "run {} attempt {}: stopped ({}) after {} step(s)",
        report.run,
        report.attempt,
        harness_journal_cause(&report.cause),
        report.steps
    );
    if let Some(e) = &report.journal_error {
        note!(cx, "journal failure: {e}");
    }
    // Design §9 H1: the outcome is shown to the user, in words, not only
    // in the report line and the exit code.
    note!(cx, "outcome: {}", outcome_in_words(&report.outcome));
    let mut findings: Vec<Finding> = info(
        "harness.run",
        &format!("run {} attempt {}", report.run, report.attempt),
        "a verification plan (H1 tasks have none)",
        format!(
            "stopped: {}; no checks planned",
            harness_journal_cause(&report.cause)
        ),
    )
    .into_iter()
    .collect();
    if let Some(f) = possibly_environmental(
        &format!("run {} attempt {}", report.run, report.attempt),
        &report.possibly_environmental,
    ) {
        note!(cx, "possibly environmental: {}", f.observed);
        findings.push(f);
    }
    Ok(Outcome {
        outcome: report.outcome,
        findings,
        chain_head: report.chain_head.map(|d| d.to_string()),
        exit_override: None,
    })
}

/// §7.1: a tool call that timed out, crashed or could not run while the
/// host was under pressure is marked, so a human can tell a pressed host
/// from a broken tool. An Info finding: it never changes the outcome.
fn possibly_environmental(location: &str, steps: &[u64]) -> Option<Finding> {
    if steps.is_empty() {
        return None;
    }
    let steps: Vec<String> = steps.iter().map(u64::to_string).collect();
    info(
        "harness.possibly-environmental",
        location,
        "tool calls on an unpressed host",
        format!(
            "a tool call timed out, crashed or could not run at step(s) {} while memory available was under 5% or the load above twice the CPUs",
            steps.join(", ")
        ),
    )
}

/// The run's outcome, said plainly for the person at the terminal.
fn outcome_in_words(o: &GateOutcome) -> &'static str {
    match o {
        GateOutcome::Passed(_) => "Passed: every planned check passed",
        GateOutcome::Failed => "Failed: a planned check failed",
        GateOutcome::Indeterminate { why } => match why {
            IndeterminateKind::NothingChecked => {
                "Indeterminate (NothingChecked): this task plans no checks, so nothing has verified the result; it is not a pass"
            }
            IndeterminateKind::UnreadableEvidence => {
                "Indeterminate (UnreadableEvidence): the run's record cannot be trusted; it is not a pass"
            }
            IndeterminateKind::CouldNotRun => "Indeterminate (CouldNotRun): it is not a pass",
            IndeterminateKind::UnsupportedOs => "Indeterminate (UnsupportedOs): it is not a pass",
            IndeterminateKind::StaleBinary => "Indeterminate (StaleBinary): it is not a pass",
        },
    }
}

fn harness_journal_cause(c: &harness_core::StopCause) -> &'static str {
    harness_journal::writer::stop_cause_name(c)
}

fn replay(cx: &Cx<'_>, o: &BTreeMap<&str, &str>) -> Outcome {
    match try_replay(cx, o) {
        Ok(x) | Err(x) => x,
    }
}

fn try_replay(cx: &Cx<'_>, o: &BTreeMap<&str, &str>) -> Result<Outcome, Outcome> {
    let inp = inputs(cx, o)?;
    let state_root = required(cx, o, "state-root")?;
    let usage = |what: &str| {
        note!(cx, "{what}\n{USAGE}");
        refused(exit::USAGE, what.to_owned())
    };
    let run =
        RunId::parse(required(cx, o, "run")?).ok_or_else(|| usage("--run is not a run id"))?;
    let attempt = match o.get("attempt") {
        None => None,
        Some(a) => Some(
            a.parse::<u32>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| usage("--attempt is not a positive number"))?,
        ),
    };
    let anchor = match o.get("anchor") {
        None => None,
        Some(a) => Some(
            a.parse()
                .map_err(|_| usage("--anchor is not a sha256 in hex"))?,
        ),
    };
    let rep = harness_run::audit(Audit {
        state_root: std::path::Path::new(state_root),
        run: &run,
        attempt,
        anchor,
        spec: &inp.spec,
        registry: &inp.registry,
        policy: &inp.policy,
        profile: &inp.profile,
    })
    .map_err(|e| {
        note!(cx, "the replay did not start: {e}");
        refused(
            exit::INDETERMINATE,
            format!("the replay did not start: {e}"),
        )
    })?;
    let findings = match &rep.divergence {
        None if rep.stop_recomputed => {
            note!(
                cx,
                "replay of run {run} attempt {}: every record recomputed and matched ({} records)",
                rep.attempt,
                rep.matched
            );
            info(
                "harness.replay",
                &format!("run {run} attempt {}", rep.attempt),
                "the recorded journal",
                format!("{} records recomputed and matched", rep.matched),
            )
        }
        None if matches!(
            rep.outcome,
            GateOutcome::Indeterminate {
                why: IndeterminateKind::CouldNotRun
            }
        ) =>
        {
            note!(
                cx,
                "replay of run {run} attempt {}: the attempt never committed (no RunStopped); its {} records matched",
                rep.attempt,
                rep.matched
            );
            info(
                "harness.replay.incomplete",
                &format!("run {run} attempt {}", rep.attempt),
                "a committed attempt",
                format!("no RunStopped; {} records matched", rep.matched),
            )
        }
        None if rep.anchored => {
            note!(
                    cx,
                    "replay of run {run} attempt {}: {} records matched; the stop is not recomputable, and the anchor pins the whole journal",
                    rep.attempt,
                    rep.matched
                );
            info(
                "harness.replay.anchored",
                &format!("run {run} attempt {}", rep.attempt),
                "the recorded journal",
                format!(
                    "{} records matched; stop not recomputable; the anchor matched",
                    rep.matched
                ),
            )
        }
        None => {
            // H1e-2b review F-1: never "every record matched" for a
            // stop the replay could not recompute.
            note!(
                    cx,
                    "replay of run {run} attempt {}: {} records matched, but the stop was NOT recomputed: wall stop not recomputable; only --anchor proves no truncation",
                    rep.attempt,
                    rep.matched
                );
            info(
                "harness.replay.stop-unverified",
                &format!("run {run} attempt {}", rep.attempt),
                "a stop the replay recomputes, or a matching --anchor",
                "wall stop not recomputable; only --anchor proves no truncation".to_owned(),
            )
        }
        Some(d) => {
            note!(
                cx,
                "replay of run {run} attempt {}: DIVERGED at record {} (step {}): {}",
                rep.attempt,
                d.seq,
                d.step,
                d.why
            );
            info(
                "harness.replay.divergence",
                &format!(
                    "run {run} attempt {} record {} step {}",
                    rep.attempt, d.seq, d.step
                ),
                "the recorded journal",
                d.why.to_owned(),
            )
        }
    };
    Ok(Outcome {
        outcome: rep.outcome,
        findings: findings.into_iter().collect(),
        chain_head: None,
        exit_override: None,
    })
}

fn profile_check(cx: &Cx<'_>, rest: &[&str]) -> u8 {
    let o = match options(rest, &["profile", "endpoint"]) {
        Ok(o) => o,
        Err(e) => {
            note!(cx, "{e}\n{USAGE}");
            return exit::USAGE;
        }
    };
    let (Some(path), Some(endpoint)) = (o.get("profile"), o.get("endpoint")) else {
        note!(cx, "--profile and --endpoint are required\n{USAGE}");
        return exit::USAGE;
    };
    let profile = match read_input(path).and_then(|b| Profile::parse(&b).map_err(|e| e.to_string()))
    {
        Ok(p) => p,
        Err(e) => {
            note!(cx, "{e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    let client =
        match OpenAiCompatible::new(endpoint, profile.clone(), None, ClientConfig::default()) {
            Ok(c) => c,
            Err(e) => {
                note!(cx, "endpoint refused: {e}");
                return exit::UNREADABLE_INPUT;
            }
        };
    if let Err(e) = client.startup_check(Instant::now() + Duration::from_secs(30)) {
        note!(cx, "model server check failed: {e}");
        return exit::INDETERMINATE;
    }
    let (r, verdict) = harness_model::smoke::run(&client, &profile, Duration::from_secs(120));
    note!(cx,
        "profile check: {} case(s), {} valid tool call(s), {} format error(s), {} failed call(s); edit format unchecked",
        r.cases, r.valid_tool_calls, r.format_errors, r.call_failures
    );
    match verdict {
        CheckResult::Stamp(s) => {
            say!(
                cx,
                "{}",
                serde_json::json!({"validated": {
                    "report_sha256": s.report_sha256,
                    "stamp_sha256": s.stamp_sha256,
                }})
            );
            note!(cx, "add the \"validated\" object above to the profile");
            exit::PASSED
        }
        CheckResult::NoStamp(why) => {
            note!(cx, "no stamp: {why}");
            exit::FAILED
        }
    }
}

/// `manifest check`: validate a provider's manifest with the parser
/// admission uses (`harness_manifest::Manifest::parse`: schema v1, strict
/// JSON, reserved namespaces, §4.3 content rules), show each capability's
/// §4.2 class and the floors its transport and the pinned tier add, and say
/// what this build's admission would do if the user pinned these exact
/// bytes. Exit codes: see the crate docs.
///
/// Named residuals (H1f-2 review F-7): the reserved set is the core
/// constant only (H1 has no harness config, so no `extra_reserved`); only
/// the pinned tier is tried (a manifest refused as pinned may be admissible
/// as signed, from H4); user policy can raise a class further at run time.
fn manifest_check(cx: &Cx<'_>, path: &str) -> u8 {
    use std::io::Read;
    let mut bytes = Vec::new();
    let read = std::fs::File::open(path).and_then(|f| {
        // One byte past the cap is enough to know it is too large.
        f.take(harness_manifest::MANIFEST_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
    });
    if let Err(e) = read {
        note!(cx, "cannot read {path}: {e}");
        return exit::UNREADABLE_INPUT;
    }
    if bytes.len() > harness_manifest::MANIFEST_MAX_BYTES {
        note!(
            cx,
            "cannot read {path}: larger than the manifest cap of {} bytes",
            harness_manifest::MANIFEST_MAX_BYTES
        );
        return exit::UNREADABLE_INPUT;
    }
    let ctx = match SemVer::parse(env!("CARGO_PKG_VERSION"))
        .ok_or_else(|| "the harness version is not SemVer".to_owned())
        .and_then(|v| ValidationContext::new(v, &[]).map_err(|e| e.to_string()))
    {
        Ok(c) => c,
        Err(e) => {
            note!(cx, "cannot check manifests: {e}");
            return exit::INDETERMINATE;
        }
    };
    let m = match harness_manifest::Manifest::parse(&bytes, &ctx) {
        Ok(m) => m,
        // Not a JSON document at all: unreadable input (§7.7).
        Err(e @ (ManifestError::Json(_) | ManifestError::TooLarge { .. })) => {
            note!(cx, "cannot read {path}: {e}");
            return exit::UNREADABLE_INPUT;
        }
        // A JSON document that is not a valid manifest. Every message here
        // shows manifest-chosen text escaped or Debug-quoted (§7.1).
        Err(e) => {
            note!(cx, "REFUSED {path}: {e}");
            return exit::FAILED;
        }
    };
    let digest = harness_core::sha256(&bytes);
    say!(
        cx,
        "OK {path}: provider {} {} (schema v{}, transport {}), {} capabilit{}",
        m.provider(),
        m.provider_version(),
        m.schema_version(),
        m.transport().kind(),
        m.capabilities().len(),
        if m.capabilities().len() == 1 {
            "y"
        } else {
            "ies"
        }
    );
    say!(cx, "  manifest sha256 {digest}");
    say!(
        cx,
        "  capability classes (§4.2: declared confirmation raised by the derived floors, before user policy and tier floors):"
    );
    for c in m.capabilities() {
        let e = harness_policy::effective_class(c, harness_manifest::Confirmation::None);
        say!(
            cx,
            "  {}: effect {}, sensitivity {}, blast {}, egress {}, content {}; confirmation {} (declared {}){}",
            c.id(),
            e.effect.as_str(),
            e.sensitivity.as_str(),
            e.blast_radius.as_str(),
            e.egress.as_str(),
            e.content.as_str(),
            e.confirmation.as_str(),
            c.confirmation().as_str(),
            if e.requires_conformed {
                "; needs a conformed sandbox"
            } else {
                ""
            }
        );
    }
    if let harness_manifest::Transport::McpStdio { .. } = m.transport() {
        say!(
            cx,
            "  transport mcp-stdio: the server is started only inside a conformed sandbox, never unconfined (§4.5)"
        );
    }
    // What admission would say if the user pinned exactly these bytes: the
    // same code a run uses. In H1 it always refuses (pinning is H4).
    let admission = harness_manifest::Sha256Pin::parse_hex(&digest.to_string())
        .ok_or_else(|| "the manifest digest is not a pin".to_owned())
        .and_then(|pin| {
            Registry::admit(vec![(
                m,
                Tier::Pinned {
                    manifest_sha256: pin,
                },
            )])
            .map_err(|e| e.to_string())
        });
    match admission {
        Ok(_) => say!(
            cx,
            "  if pinned as sha256 {digest}, this build would admit it"
        ),
        Err(e) => say!(
            cx,
            "  if pinned as sha256 {digest}, this build would refuse it: {e}"
        ),
    }
    say!(
        cx,
        "  a pinned provider is always sandboxed, confirms at least user_confirm and never shares a session with personal or restricted capabilities (§4.4)"
    );
    exit::PASSED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pressed_step_is_an_info_finding_and_no_step_is_none() {
        assert!(possibly_environmental("run r attempt 1", &[]).is_none());
        let f = possibly_environmental("run r attempt 1", &[3, 7]).unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.code.0, "harness.possibly-environmental");
        assert!(f.observed.contains("step(s) 3, 7"), "{}", f.observed);
    }
}
