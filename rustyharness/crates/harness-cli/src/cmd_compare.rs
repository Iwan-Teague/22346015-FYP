//! The `compare` verb (P-48, OD-3): the same task — the same workspace
//! snapshot, policy and budgets — run on two to four model profiles one
//! after another (endpoint concurrency 1), each from a fresh scratch copy
//! of the same source workspace. It writes a comparison report whose arms
//! carry labels A/B/… in a random-but-recorded order, and per arm only
//! facts: steps, tokens, wall time, format errors, tool counts, the final
//! diff, the pre-submit check result and the chain head.
//!
//! The harness never grades: there is no score, no ranking, and the
//! report's own outcome is always `Indeterminate { NothingChecked }`
//! (INV-18) — a compare run checks nothing by itself. The person at the
//! terminal picks a winner, and only `compare reveal --winner <label>`
//! records that pick and unfolds which label was which model: until then
//! the report names no model, profile path or endpoint, and the mapping
//! file (0600, beside the report) is the only place the two meet. Every
//! arm is an ordinary run — bundle, scratch manifest and all — so each
//! replays with `replay --run`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use gate_outcome::{GateId, GateOutcome, IndeterminateKind};
use harness_journal::canon::EventKind;
use harness_model::client::{ClientConfig, OpenAiCompatible};
use harness_run::{Approver, Run, WorkspaceModeRecord};
use harness_sandbox::environment::SystemEnv;
use serde::{Deserialize, Serialize};

use crate::approver::{ApproverSource, TerminalApprover};
use crate::args::{options, USAGE};
use crate::report::{emit, exit, info, refused, Outcome};
use crate::Cx;

/// The gate id a compare run names when `--gate` is not given.
const DEFAULT_GATE: &str = "rustyharness.compare";

/// The comparison report's format tag.
const REPORT_FORMAT: &str = "rh-compare/1";

/// The label→model mapping's format tag (the reveal file).
const MAPPING_FORMAT: &str = "rh-compare-map/1";

/// The labels; arm *i* takes `LABELS[order[i]]` for the recorded shuffle.
const LABELS: [&str; 4] = ["A", "B", "C", "D"];

/// Most arms: a compare is for a person reading a short list side by side,
/// not a sweep.
const MAX_ARMS: usize = 4;

/// A compare report can carry four arms' diffs; far above that and far
/// below anything sane to parse.
const REPORT_MAX_BYTES: u64 = 32 * 1024 * 1024;

/// The options a compare takes besides its repeated `--profile`/`--endpoint`
/// pairs (which the pre-pass takes first: they repeat, the parser refuses
/// repeats).
const ALLOWED: &[&str] = &["task", "workspace", "state-root", "policy", "gate"];

/// The options that are flags.
const VALUELESS: &[&str] = &["no-default-denies"];

/// The comparison report: arms in label order, facts only, and the winner
/// once the person has picked one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompareReport {
    format: String,
    /// The label shuffle's seed, so the assignment is recomputable.
    seed: u64,
    arms: Vec<ArmRecord>,
    /// Set only by `compare reveal --winner`.
    winner: Option<String>,
}

/// One arm's facts. Nothing here names a model, a profile path or an
/// endpoint: those live in the mapping file until the reveal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArmRecord {
    label: String,
    run: String,
    attempt: u32,
    cause: String,
    steps: u64,
    tokens_in: u64,
    tokens_out: u64,
    wall_ms: u64,
    format_errors: u64,
    tools: BTreeMap<String, u64>,
    diff: String,
    presubmit: String,
    chain_head: Option<String>,
}

/// The mapping file: which label was which model. 0600, beside the report;
/// the reveal reads it and nothing else does.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Mapping {
    format: String,
    seed: u64,
    arms: Vec<ArmMap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArmMap {
    label: String,
    model: String,
    profile: String,
    endpoint: String,
    profile_sha256: String,
}

/// One arm, ready to run: its inputs as `run` would have built them, its
/// client, and the paths the bundle names. Consumed by the arm loop.
struct Arm {
    label: String,
    task_path: String,
    profile_path: String,
    policy_path: Option<String>,
    endpoint: String,
    inp: crate::inputs::Inputs,
    client: OpenAiCompatible,
}

pub(crate) fn compare(cx: &Cx<'_>, rest: &[&str]) -> u8 {
    // "rustyharness.compare" is a valid id by construction; the Err arm
    // only keeps this total (a bare usage exit, like dispatch's).
    let default = match GateId::new(DEFAULT_GATE) {
        Ok(g) => g,
        Err(_) => return exit::USAGE,
    };
    match rest {
        ["reveal", rest @ ..] => emit(cx, &default, try_reveal(cx, rest)),
        _ => match try_arms(cx, rest, default) {
            Ok((gate, o)) => emit(cx, &gate, o),
            Err(boxed) => {
                let (gate, o) = *boxed;
                emit(cx, &gate, o)
            }
        },
    }
}

/// The arm runs, under the gate the options name (else the default). Every
/// pre-parse error reports under the default id, like every gate child, so
/// the report line is never missing.
fn try_arms(
    cx: &Cx<'_>,
    rest: &[&str],
    default: GateId,
) -> Result<(GateId, Outcome), Box<(GateId, Outcome)>> {
    // The repeated pairs first (the chat pre-pass pattern): each arm is
    // one `--profile` and one `--endpoint`, paired in the order given.
    // The parser after this refuses a stray one as unknown, so a typo'd
    // pair can never silently become an arm.
    let mut profiles: Vec<&str> = Vec::new();
    let mut endpoints: Vec<&str> = Vec::new();
    let mut others: Vec<&str> = Vec::new();
    let mut it = rest.iter();
    while let Some(&tok) = it.next() {
        match tok {
            "--profile" => match it.next() {
                Some(&v) => profiles.push(v),
                None => {
                    return Err(Box::new((
                        default.clone(),
                        usage(cx, "--profile needs a value"),
                    )));
                }
            },
            "--endpoint" => match it.next() {
                Some(&v) => endpoints.push(v),
                None => {
                    return Err(Box::new((
                        default.clone(),
                        usage(cx, "--endpoint needs a value"),
                    )));
                }
            },
            _ => others.push(tok),
        }
    }
    if profiles.len() != endpoints.len() {
        return Err(Box::new((
            default.clone(),
            usage(
                cx,
                "each --profile needs one --endpoint, paired in the order given",
            ),
        )));
    }
    if profiles.len() < 2 || profiles.len() > MAX_ARMS {
        return Err(Box::new((
            default.clone(),
            usage(
                cx,
                &format!(
                    "compare needs 2 to {MAX_ARMS} --profile/--endpoint pairs, not {}",
                    profiles.len()
                ),
            ),
        )));
    }
    let parsed = match options(&others, ALLOWED, VALUELESS) {
        Ok(p) => p,
        Err(e) => {
            note!(cx, "{e}\n{USAGE}");
            return Err(Box::new((
                default.clone(),
                refused(exit::USAGE, "usage error".into()),
            )));
        }
    };
    // The gate id the report names: from `--gate`, else the compare
    // default. A bad one is a usage error under the default id, so the
    // report line is never missing.
    let gate = match GateId::new(parsed.get("gate").copied().unwrap_or(DEFAULT_GATE)) {
        Ok(g) => g,
        Err(_) => {
            return Err(Box::new((
                default.clone(),
                usage(cx, "--gate is not a valid gate id"),
            )))
        }
    };
    let pairs: Vec<(&str, &str)> = profiles.into_iter().zip(endpoints).collect();
    match arms_parsed(cx, &parsed, &pairs) {
        Ok(o) => Ok((gate, o)),
        Err(o) => Err(Box::new((gate, o))),
    }
}

/// Everything is validated and every model server is checked before the
/// first arm runs: an unusable arm never leaves the others half-run.
fn arms_parsed(
    cx: &Cx<'_>,
    parsed: &BTreeMap<&str, &str>,
    pairs: &[(&str, &str)],
) -> Result<Outcome, Outcome> {
    // The user's config file, once per command (P-07): flags override it.
    // (It is not consulted for arms: a compare's profiles and endpoints
    // are on the command line by definition — there is no single one to
    // default to.)
    let cfg = match crate::config::load() {
        Ok(c) => c,
        Err(e) => {
            note!(cx, "{e}");
            return Err(refused(exit::UNREADABLE_INPUT, e));
        }
    };
    let task = crate::inputs::required(cx, parsed, "task")?;
    // The source workspace is required, not the run verbs' cwd default: a
    // compare copies it once per arm, so guessing a directory is a copy
    // this verb should not make.
    let workspace = crate::inputs::required(cx, parsed, "workspace")?;
    let state_root = match crate::config::state_root(parsed, &cfg) {
        Ok(Some(s)) => s,
        Ok(None) => {
            note!(
                cx,
                "--state-root is required here (no default state root on this platform)\n{USAGE}"
            );
            return Err(refused(exit::USAGE, "--state-root missing".into()));
        }
        Err(e) => {
            note!(cx, "{e}");
            return Err(refused(exit::UNREADABLE_INPUT, e));
        }
    };
    let policy_opt = crate::config::value(parsed, &cfg, "policy");
    let overlay = !parsed.contains_key("no-default-denies");
    let mut arms: Vec<Arm> = Vec::new();
    for (profile, endpoint) in pairs {
        // Each arm's inputs exactly as `run` would have built them: the
        // same task, policy, budgets — only the profile and endpoint
        // differ between arms.
        let mut owned: BTreeMap<&str, String> = BTreeMap::new();
        owned.insert("task", (*task).to_owned());
        owned.insert("workspace", (*workspace).to_owned());
        owned.insert("state-root", state_root.as_ref().to_owned());
        if let Some(p) = policy_opt {
            owned.insert("policy", p.to_owned());
        }
        if !overlay {
            owned.insert("no-default-denies", "true".to_owned());
        }
        owned.insert("profile", (*profile).to_owned());
        owned.insert("endpoint", (*endpoint).to_owned());
        let opts: BTreeMap<&str, &str> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let inp = crate::inputs::inputs(cx, &opts, &cfg)?;
        let client =
            OpenAiCompatible::new(endpoint, inp.profile.clone(), None, ClientConfig::default())
                .map_err(|e| {
                    note!(cx, "endpoint refused: {e}");
                    refused(exit::UNREADABLE_INPUT, format!("endpoint refused: {e}"))
                })?;
        arms.push(Arm {
            label: String::new(),
            task_path: (*task).to_owned(),
            profile_path: (*profile).to_owned(),
            policy_path: policy_opt.map(str::to_owned),
            endpoint: (*endpoint).to_owned(),
            inp,
            client,
        });
    }
    // The state root's locality first (§2.8): the copies live under it, so
    // a compare that cannot start never contacts a model server.
    let root = std::fs::canonicalize(state_root.as_ref()).map_err(|e| {
        note!(cx, "cannot read the state root: {e}");
        refused(
            exit::INDETERMINATE,
            format!("cannot read the state root: {e}"),
        )
    })?;
    harness_policy::locality::check(cx.probe, &root.to_string_lossy()).map_err(|e| {
        note!(cx, "{e}");
        refused(exit::INDETERMINATE, e.to_string())
    })?;
    for arm in &arms {
        if let Err(e) = arm
            .client
            .startup_check(Instant::now() + Duration::from_secs(30))
        {
            note!(cx, "model server check failed: {e}");
            return Err(refused(
                exit::INDETERMINATE,
                format!("model server check failed: {e}"),
            ));
        }
    }
    // Who answers an ask (§5.3), exactly as `run` decides it: with nobody,
    // every ask is a deny, so an unattended arm edits only where its
    // policy allows edits.
    let terminal;
    let wants_terminal = match &cfg {
        Some(c) => c.approver == crate::config::ApproverSetting::Terminal,
        None => true,
    };
    let approver: Option<&dyn Approver> = match cx.approver {
        ApproverSource::None => None,
        ApproverSource::Given(a) => Some(a),
        ApproverSource::StdinIfTerminal if wants_terminal => {
            use std::io::IsTerminal;
            if std::io::stdin().is_terminal() {
                terminal = TerminalApprover::new(cx);
                Some(&terminal)
            } else {
                None
            }
        }
        ApproverSource::StdinIfTerminal => None,
    };
    // The labels: a seeded shuffle of A/B/… over the arms, recorded in the
    // report so the assignment can be recomputed later. The arms run in
    // the order given (endpoint concurrency 1); only their labels are
    // shuffled, so the report cannot be read as a ranking by order.
    let seed = shuffle_seed();
    let order = label_order(seed, arms.len());
    for (i, arm) in arms.iter_mut().enumerate() {
        // Both branches are unreachable (label_order yields 0..n over
        // LABELS, n ≤ MAX_ARMS), and fail closed if they were not.
        let Some(&oi) = order.get(i) else {
            return Err(usage(cx, "the label shuffle left an arm unnamed"));
        };
        let Some(label) = LABELS.get(oi) else {
            return Err(usage(cx, "the label shuffle named an unknown label"));
        };
        arm.label = (*label).to_owned();
    }
    // The layout: the report under `<state-root>/compare/<stamp>/`, each
    // arm's copy under `<state-root>/scratch/<stamp>-<label>/` (beside a
    // run's own scratch copies) and each arm's run under
    // `<compare>/arm-<label>/state/`. A run refuses a state root that
    // overlaps its workspace, so the copy and the run's own state root
    // are kept in disjoint branches of the state tree; everything stays
    // under the private state root.
    let stamp = crate::workspace_mode::stamp();
    let compare_dir = root.join("compare").join(&stamp);
    crate::config::create_private_dir(&compare_dir).map_err(|e| {
        note!(cx, "{e}");
        refused(exit::INDETERMINATE, e)
    })?;
    crate::config::create_private_dir(&root.join("scratch")).map_err(|e| {
        note!(cx, "{e}");
        refused(exit::INDETERMINATE, e)
    })?;
    let mut records: Vec<ArmRecord> = Vec::new();
    let mut maps: Vec<ArmMap> = Vec::new();
    let mut findings: Vec<gate_outcome::Finding> = Vec::new();
    for arm in arms {
        let (record, map, arm_findings) = run_arm(
            cx,
            arm,
            workspace,
            &root,
            &compare_dir,
            &stamp,
            approver,
            overlay,
        )?;
        findings.extend(arm_findings);
        records.push(record);
        maps.push(map);
    }
    write_report_files(cx, &compare_dir, seed, records, maps)?;
    let report_path = compare_dir.join("report.json");
    note!(
        cx,
        "compare report: {} (the mapping hides which label was which model until `compare reveal`)",
        report_path.display()
    );
    note!(
        cx,
        "each arm's run lives in arm-<label>/state here; replay it with --state-root set to that directory"
    );
    findings.extend(info(
        "harness.compare",
        report_path.to_string_lossy().as_ref(),
        "each arm's facts beside mapping.json; reveal with --winner",
        "no winner picked: the harness does not grade".to_owned(),
    ));
    Ok(Outcome {
        // A compare checks nothing itself (OD-3): the arms' facts are the
        // product, the pick is the person's, so this is never a verdict.
        outcome: GateOutcome::Indeterminate {
            why: IndeterminateKind::NothingChecked,
        },
        findings,
        chain_head: None,
        exit_override: None,
    })
}

/// One arm: a fresh scratch copy of the source workspace, an ordinary run
/// into the arm's own state directory, then the arm's facts read back from
/// the journal and the copy. The source workspace is never written.
#[allow(clippy::too_many_arguments)]
fn run_arm(
    cx: &Cx<'_>,
    arm: Arm,
    workspace: &str,
    root: &Path,
    compare_dir: &Path,
    stamp: &str,
    approver: Option<&dyn Approver>,
    overlay: bool,
) -> Result<(ArmRecord, ArmMap, Vec<gate_outcome::Finding>), Outcome> {
    let src = Path::new(workspace);
    let copy_dir = root.join("scratch").join(format!("{stamp}-{}", arm.label));
    let entries = harness_run::scratch::copy_workspace(src, &copy_dir, false).map_err(|e| {
        note!(cx, "the scratch copy failed: {e}");
        refused(exit::INDETERMINATE, format!("the scratch copy failed: {e}"))
    })?;
    // The arm's own state root, disjoint from its copy (a run refuses a
    // state root that overlaps its workspace) and from the other arms'.
    let arm_state = compare_dir.join(format!("arm-{}", arm.label)).join("state");
    crate::config::create_private_dir(&arm_state).map_err(|e| {
        note!(cx, "{e}");
        refused(exit::INDETERMINATE, e)
    })?;
    let files: Vec<crate::workspace_mode::ManifestFile> = entries
        .iter()
        .map(|f| crate::workspace_mode::ManifestFile {
            path: f.rel.clone(),
            sha256: f.digest.to_string(),
            bytes: f.bytes,
        })
        .collect();
    // The copy manifest, beside the copy like a run's scratch manifest:
    // its exact bytes are what the header's workspace_mode record binds.
    let manifest_path = compare_dir.join(format!("workspace-{}.manifest.json", arm.label));
    let source_abs = std::fs::canonicalize(src).map_err(|e| {
        note!(cx, "cannot read the source workspace: {e}");
        refused(
            exit::INDETERMINATE,
            format!("cannot read the source workspace: {e}"),
        )
    })?;
    let doc = crate::workspace_mode::ManifestDoc {
        format: crate::workspace_mode::MANIFEST_FORMAT.to_owned(),
        mode: "scratch".to_owned(),
        source: source_abs.to_string_lossy().into_owned(),
        copy: copy_dir.to_string_lossy().into_owned(),
        files: files.clone(),
    };
    let manifest_bytes = serde_json::to_vec_pretty(&doc)
        .map_err(|e| refused(exit::INDETERMINATE, format!("manifest: {e}")))?;
    let manifest = harness_core::sha256(&manifest_bytes);
    crate::cmd_profile::write_private(&manifest_path, &manifest_bytes).map_err(|e| {
        note!(cx, "{e}");
        refused(exit::INDETERMINATE, e)
    })?;
    let mut inp = arm.inp;
    inp.config.workspace_mode = Some(WorkspaceModeRecord::scratch(
        manifest,
        entries.iter().map(|f| f.digest).collect(),
    ));
    let config = &inp.config;
    let report = harness_run::run(Run {
        state_root: &arm_state,
        workspace: &copy_dir,
        spec: &inp.spec,
        registry: &inp.registry,
        policy: &inp.policy,
        profile: &inp.profile,
        backend: &arm.client,
        probe: cx.probe,
        env: &SystemEnv,
        config,
        approver,
        confinement: Some(cx.confinement),
    })
    .map_err(|e| crate::cmd_run::from_refusal(cx, &e))?;
    note!(
        cx,
        "arm {}: run {} attempt {}: stopped ({}) after {} step(s)",
        arm.label,
        report.run,
        report.attempt,
        harness_journal::writer::stop_cause_name(&report.cause),
        report.steps
    );
    let mut findings: Vec<gate_outcome::Finding> = Vec::new();
    // The copy's manifest, published into the run directory, and the run
    // bundle: both exactly as `run` writes them, so each arm replays with
    // `replay --run`. Best effort, never outcome-changing.
    crate::workspace_mode::publish_manifest(
        cx,
        &report.run_dir,
        &crate::workspace_mode::ScratchPrep {
            manifest_path,
            manifest,
        },
        &mut findings,
    );
    let bundle_src = crate::bundle::BundleSource::new(
        Some(&arm.task_path),
        Some(&arm.profile_path),
        arm.policy_path.as_deref(),
    );
    if let Err(e) = crate::bundle::write_run_bundle(
        &report.run_dir,
        &bundle_src,
        &arm.endpoint,
        copy_dir.to_string_lossy().as_ref(),
        &inp.digests,
        // The policy was digested under the arm's own overlay settings
        // (P-12 default denies; P-23 accept-edits); the bundle self-check
        // must digest it the same way. A compare takes no `--accept-edits`
        // (its arm options are the run verbs' minus the session flags), so
        // the overlay is always off here.
        overlay,
        false,
    ) {
        note!(cx, "run bundle not written: {e}");
    }
    // The facts, from the verified attempt journal (the same source the
    // usage footer reads) and from the copy itself.
    let attempt_dir = harness_journal::layout::attempt_dir(&report.run_dir, report.attempt);
    let verified = harness_journal::JournalReader::open(&attempt_dir).map_err(|e| {
        note!(cx, "cannot read the arm's journal: {e}");
        refused(
            exit::INDETERMINATE,
            format!("cannot read the arm's journal: {e}"),
        )
    })?;
    let usage = crate::usage::Usage::from_journal(&verified);
    let format_errors = verified
        .records
        .iter()
        .filter(|r| r.kind == EventKind::FormatError)
        .count() as u64;
    // The final diff: what the arm changed in ITS copy, against the
    // source. A fact for the person, never applied.
    let diff = crate::workspace_mode::plan_apply(src, &copy_dir, &files).plan;
    let presubmit = match &report.presubmit {
        None => "not-run".to_owned(),
        Some(p) => format!(
            "{}; {} submission(s), {} turned back",
            p.last.map(|r| r.name()).unwrap_or("not_run"),
            p.submissions,
            p.turned_back
        ),
    };
    note!(
        cx,
        "arm {}: {} token(s) in, {} out, {} format error(s)",
        arm.label,
        usage.tokens_in(),
        usage.tokens_out(),
        format_errors
    );
    let record = ArmRecord {
        label: arm.label.clone(),
        run: report.run.to_string(),
        attempt: report.attempt,
        cause: harness_journal::writer::stop_cause_name(&report.cause).to_owned(),
        steps: report.steps,
        tokens_in: usage.tokens_in(),
        tokens_out: usage.tokens_out(),
        wall_ms: usage.wall_ms(),
        format_errors,
        tools: usage.tools().clone(),
        diff,
        presubmit,
        chain_head: report.chain_head.map(|d| d.to_string()),
    };
    let map = ArmMap {
        label: arm.label.clone(),
        model: inp.profile.id().to_owned(),
        profile: arm.profile_path.clone(),
        endpoint: arm.endpoint.clone(),
        profile_sha256: inp.profile.content_sha256().to_string(),
    };
    Ok((record, map, findings))
}

/// The label shuffle's seed: the wall clock and the process id. Nothing
/// rides on its quality — the assignment is hidden by the mapping file,
/// not by the seed's strength — and the seed is recorded either way.
fn shuffle_seed() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 ^ d.as_secs())
        .unwrap_or(0);
    let pid = u64::from(std::process::id());
    nanos ^ (pid << 32) ^ pid
}

fn xor(mut x: u64) -> u64 {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

/// A Fisher-Yates shuffle of `0..n` from the seed (the testkit's xorshift
/// shape; n is at most [`MAX_ARMS`], so the modulo bias is beside the
/// point — the recorded seed makes the order recomputable, which is the
/// requirement).
fn label_order(seed: u64, n: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..n).collect();
    let mut state = xor(seed | 1);
    let mut i = n;
    while i > 1 {
        state = xor(state);
        let j = (state >> 11) as usize % i;
        i -= 1;
        order.swap(i, j);
    }
    order
}

/// The report and the mapping: the report's arms carry facts only; the
/// mapping alone says which label was which model. Both 0600 under the
/// compare directory.
fn write_report_files(
    cx: &Cx<'_>,
    compare_dir: &Path,
    seed: u64,
    records: Vec<ArmRecord>,
    maps: Vec<ArmMap>,
) -> Result<(), Outcome> {
    let report = CompareReport {
        format: REPORT_FORMAT.to_owned(),
        seed,
        arms: records,
        winner: None,
    };
    let mapping = Mapping {
        format: MAPPING_FORMAT.to_owned(),
        seed,
        arms: maps,
    };
    let report_bytes = serde_json::to_vec_pretty(&report)
        .map_err(|e| refused(exit::INDETERMINATE, format!("report: {e}")))?;
    let map_bytes = serde_json::to_vec_pretty(&mapping)
        .map_err(|e| refused(exit::INDETERMINATE, format!("mapping: {e}")))?;
    let report_path = compare_dir.join("report.json");
    let map_path = compare_dir.join("mapping.json");
    crate::cmd_profile::write_private(&report_path, &report_bytes).map_err(|e| {
        note!(cx, "{e}");
        refused(exit::INDETERMINATE, e)
    })?;
    crate::cmd_profile::write_private(&map_path, &map_bytes).map_err(|e| {
        note!(cx, "{e}");
        refused(exit::INDETERMINATE, e)
    })?;
    note!(
        cx,
        "mapping (do not read before choosing): {}",
        map_path.display()
    );
    Ok(())
}

/// `compare reveal --report <path> [--winner <label>]`: record the pick,
/// then show which label was which model. Without a winner there is
/// nothing to reveal — the map stays hidden until the report records one.
fn try_reveal(cx: &Cx<'_>, rest: &[&str]) -> Outcome {
    let parsed = match options(rest, &["report", "winner"], &[]) {
        Ok(p) => p,
        Err(e) => {
            note!(cx, "{e}\n{USAGE}");
            return refused(exit::USAGE, "usage error".into());
        }
    };
    let report_path = match crate::inputs::required(cx, &parsed, "report") {
        Ok(p) => PathBuf::from(p),
        Err(o) => return o,
    };
    let report = match read_compare_file::<CompareReport>(&report_path) {
        Ok(r) => r,
        Err(o) => return o,
    };
    // The mapping must sit beside the report, and its seed must match:
    // any other pairing is a file from another compare.
    let map_path = match report_path.parent() {
        Some(d) => d.join("mapping.json"),
        None => PathBuf::from("mapping.json"),
    };
    let mapping = match read_compare_file::<Mapping>(&map_path) {
        Ok(m) => m,
        Err(o) => return o,
    };
    if mapping.seed != report.seed {
        let why = "mapping.json does not belong to this report (seed differs)".to_owned();
        note!(cx, "{why}");
        return refused(exit::UNREADABLE_INPUT, why);
    }
    match parsed.get("winner").copied() {
        Some(w) => {
            if !report.arms.iter().any(|a| a.label == w) {
                return usage(cx, "--winner is one of the report's labels (A, B, C, D)");
            }
            let mut picked = report;
            picked.winner = Some(w.to_owned());
            let bytes = match serde_json::to_vec_pretty(&picked) {
                Ok(b) => b,
                Err(e) => return refused(exit::INDETERMINATE, format!("report: {e}")),
            };
            if let Err(e) = crate::cmd_profile::write_private(&report_path, &bytes) {
                note!(cx, "{e}");
                return refused(exit::INDETERMINATE, e);
            }
            note!(cx, "winner recorded: {w}");
        }
        None if report.winner.is_none() => {
            return usage(cx, "reveal needs a winner first: pass --winner <label>");
        }
        None => note!(cx, "winner: {}", report.winner.as_deref().unwrap_or("")),
    }
    let mut said = String::new();
    for m in &mapping.arms {
        let line = format!(
            "{} = {} (profile {}, endpoint {}, sha256 {})",
            m.label, m.model, m.profile, m.endpoint, m.profile_sha256
        );
        say!(cx, "{line}");
        if !said.is_empty() {
            said.push_str("; ");
        }
        said.push_str(&line);
    }
    Outcome {
        outcome: GateOutcome::Indeterminate {
            why: IndeterminateKind::NothingChecked,
        },
        findings: info(
            "harness.compare.reveal",
            report_path.to_string_lossy().as_ref(),
            "the label→model map, after the winner was picked",
            said,
        )
        .into_iter()
        .collect(),
        chain_head: None,
        exit_override: None,
    }
}

/// A compare-side JSON file, bounded and strict: read, strict-JSON parse,
/// then typed parse. Anything else is unreadable input.
fn read_compare_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, Outcome> {
    let bytes = std::fs::read(path).map_err(|e| {
        refused(
            exit::UNREADABLE_INPUT,
            format!("cannot read {}: {e}", path.display()),
        )
    })?;
    if bytes.len() as u64 > REPORT_MAX_BYTES {
        let why = format!("{} is larger than {REPORT_MAX_BYTES} bytes", path.display());
        return Err(refused(exit::UNREADABLE_INPUT, why));
    }
    let v = harness_core::strict_json::parse(&bytes)
        .map_err(|e| refused(exit::UNREADABLE_INPUT, format!("{}: {e}", path.display())))?;
    serde_json::from_value(v)
        .map_err(|e| refused(exit::UNREADABLE_INPUT, format!("{}: {e}", path.display())))
}

fn usage(cx: &Cx<'_>, why: &str) -> Outcome {
    note!(cx, "{why}\n{USAGE}");
    refused(exit::USAGE, why.to_owned())
}
