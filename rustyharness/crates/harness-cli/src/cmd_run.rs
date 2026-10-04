//! The `run` and `resume` verbs: read the inputs, check the state root's
//! locality and the model server, hand everything to `harness_run`, and
//! turn the run's report into words on stderr and an [`Outcome`].

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use gate_outcome::{Finding, FindingCode, GateOutcome, IndeterminateKind, Severity};
use harness_core::{Pricing, RunId};
use harness_model::client::{ClientConfig, OpenAiCompatible};
use harness_run::{Approver, Resume, Run, RunRefused};
use harness_sandbox::environment::SystemEnv;

use crate::approver::{ApproverSource, TerminalApprover};
use crate::dispatch::Verb;
use crate::inputs::{inputs, required};
use crate::report::{exit, info, refused, Outcome};
use crate::Cx;

/// How a run that never started becomes an outcome — shared with
/// `compare` (P-48), whose arms are ordinary runs.
pub(crate) fn from_refusal(cx: &Cx<'_>, e: &RunRefused) -> Outcome {
    note!(cx, "the run did not start: {e}");
    // No conformed sandbox for a task that executes (INV-6): its own exit.
    let code = match e {
        RunRefused::Confinement(_) => exit::CONFINEMENT_REFUSED,
        // A task whose checks the policy denies is a task and a policy that
        // do not go together: unusable input, as a malformed section is (H3a).
        RunRefused::Presubmit(_) => exit::UNREADABLE_INPUT,
        _ => exit::INDETERMINATE,
    };
    let mut o = refused(code, format!("the run did not start: {e}"));
    o.outcome = e.outcome();
    o
}

pub(crate) fn run_or_resume(
    cx: &Cx<'_>,
    o: &BTreeMap<&str, &str>,
    verb: Verb,
    cfg: &Option<crate::config::UserConfig>,
) -> Outcome {
    run_with(cx, o, verb, cfg, false)
}

/// `schedule run-now` (P-49) runs the same pipeline, but always
/// unattended: every ask is a deny even at a real terminal, because the
/// run it previews is one a timer would start with nobody watching (§5.3).
pub(crate) fn run_or_resume_unattended(
    cx: &Cx<'_>,
    o: &BTreeMap<&str, &str>,
    cfg: &Option<crate::config::UserConfig>,
) -> Outcome {
    run_with(cx, o, Verb::Run, cfg, true)
}

fn run_with(
    cx: &Cx<'_>,
    o: &BTreeMap<&str, &str>,
    verb: Verb,
    cfg: &Option<crate::config::UserConfig>,
    force_unattended: bool,
) -> Outcome {
    match try_run(cx, o, verb, cfg, force_unattended) {
        Ok(x) | Err(x) => x,
    }
}

fn try_run(
    cx: &Cx<'_>,
    o: &BTreeMap<&str, &str>,
    verb: Verb,
    cfg: &Option<crate::config::UserConfig>,
    force_unattended: bool,
) -> Result<Outcome, Outcome> {
    // `--output stream-json` (P-15): the only output mode. A usage error
    // here stops before anything runs.
    let stream = match o.get("output") {
        None => false,
        Some(&"stream-json") => true,
        Some(other) => {
            note!(
                cx,
                "--output must be stream-json, not {other:?}\n{}",
                crate::args::USAGE
            );
            return Err(refused(exit::USAGE, "--output must be stream-json".into()));
        }
    };
    let inp = inputs(cx, o, cfg)?;
    // The workspace mode (P-52): in-place (the default, unchanged), or a
    // scratch copy the run sees instead of the original. `worktree` is
    // refused at the option parser (INV-23: this build has no way to run
    // `git worktree add`). A copy failure refuses before anything runs.
    let mode = match crate::workspace_mode::parse_mode(o) {
        Ok(m) => m,
        Err(e) => {
            note!(cx, "{e}\n{}", crate::args::USAGE);
            return Err(refused(exit::USAGE, e));
        }
    }; // The workspace (P-07): the flag, else the current directory. A cwd
       // that cannot be determined is fail-closed (Indeterminate), not a
       // silent other directory.
    let workspace: std::borrow::Cow<'_, str> = match crate::config::value(o, cfg, "workspace") {
        Some(w) => std::borrow::Cow::Borrowed(w),
        None => match std::env::current_dir() {
            Ok(d) => std::borrow::Cow::Owned(d.to_string_lossy().into_owned()),
            Err(e) => {
                let why = format!("cannot determine the current directory for --workspace: {e}");
                note!(cx, "{why}");
                return Err(refused(exit::INDETERMINATE, why));
            }
        },
    };
    let state_root = match crate::config::state_root(o, cfg) {
        Ok(Some(s)) => s,
        Ok(None) => {
            note!(
                cx,
                "--state-root is required here (no default state root on this platform)\n{}",
                crate::args::USAGE
            );
            return Err(refused(exit::USAGE, "--state-root missing".into()));
        }
        Err(e) => {
            note!(cx, "{e}");
            return Err(refused(exit::UNREADABLE_INPUT, e));
        }
    };
    let endpoint = crate::config::value(o, cfg, "endpoint").ok_or_else(|| {
        note!(cx, "--endpoint is required\n{}", crate::args::USAGE);
        refused(exit::USAGE, "--endpoint missing".into())
    })?;
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
    // The scratch copy (P-52) before anything else talks to the host or
    // the server; `mut` so the header record can be set on the config.
    let mut inp = inp;
    let prep = match crate::workspace_mode::prepare(cx, &mode, &workspace, &state_root) {
        Ok(p) => p,
        Err(r) => {
            note!(cx, "{}", r.why);
            return Err(refused(r.code, r.why));
        }
    };
    inp.config.workspace_mode = prep.record;
    let workspace: std::borrow::Cow<'_, str> = std::borrow::Cow::Owned(prep.workspace);
    let config = &inp.config;
    // The state root's locality first (§2.8): a run that cannot start does
    // not contact the model server. The run checks it again itself.
    let root = std::fs::canonicalize(state_root.as_ref())
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
    // Who answers an ask (§5.3): with nobody, every ask is a deny (§5.2),
    // so an unattended run edits only where its policy allows edits. A
    // `schedule run-now` (P-49) forces nobody: the run it previews is one
    // a timer would start, which can never ask.
    let terminal;
    // A config `approver: "none"` says nobody is at the terminal (P-07):
    // every ask is a deny, even at a real terminal. `--approver` does not
    // exist, and an approver given by the test binary always wins.
    let wants_terminal = match cfg {
        Some(c) => c.approver == crate::config::ApproverSetting::Terminal,
        None => true,
    };
    let approver: Option<&dyn Approver> = if force_unattended {
        None
    } else {
        match cx.approver {
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
        }
    };
    let report = match run_id {
        None => harness_run::run(Run {
            state_root: std::path::Path::new(state_root.as_ref()),
            workspace: std::path::Path::new(workspace.as_ref()),
            spec: &inp.spec,
            registry: &inp.registry,
            policy: &inp.policy,
            profile: &inp.profile,
            backend: &client,
            probe,
            env: &SystemEnv,
            config,
            approver,
            confinement: Some(cx.confinement),
        }),
        Some(id) => harness_run::resume(Resume {
            state_root: std::path::Path::new(state_root.as_ref()),
            run: &id,
            workspace: Some(std::path::Path::new(workspace.as_ref())),
            spec: &inp.spec,
            registry: &inp.registry,
            policy: &inp.policy,
            profile: &inp.profile,
            backend: &client,
            probe,
            env: &SystemEnv,
            config,
            approver,
            confinement: Some(cx.confinement),
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
    // The task's pre-submit checks (H3a): what they did, in words and as an
    // Info finding, so a run that was accepted with a check still failing is
    // never read as a plain submit.
    if let Some(p) = &report.presubmit {
        let words = presubmit_in_words(p, &report.cause);
        note!(cx, "pre-submit checks: {words}");
        findings.extend(info(
            "harness.presubmit",
            &format!("run {} attempt {}", report.run, report.attempt),
            "every pre-submit check passing at the accepted submission",
            words,
        ));
    }
    // The scratch copy's manifest (P-52), published into the run
    // directory like the bundle: `apply` binds it to the header's
    // workspace-mode record. Best effort, never outcome-changing.
    if let Some(s) = &prep.scratch {
        crate::workspace_mode::publish_manifest(cx, &report.run_dir, s, &mut findings);
    }
    // The run bundle (P-14, OD-5(d)): copy the resolved inputs into
    // `runs/<id>/inputs/` so `replay --run`/`resume --run` need no other
    // flags. The run is already committed, so a bundle that fails to write
    // (or fails its self-check) never changes the outcome: a Low finding
    // and a note say the convenience is missing.
    let bundle_src = crate::bundle::BundleSource::new(
        crate::config::value(o, cfg, "task"),
        crate::config::value(o, cfg, "profile"),
        crate::config::value(o, cfg, "policy"),
    );
    if let Err(e) = crate::bundle::write_run_bundle(
        &report.run_dir,
        &bundle_src,
        endpoint,
        workspace.as_ref(),
        &inp.digests,
        // The policy was digested under the run's own overlay settings
        // (P-12 default denies; P-23 accept-edits); the bundle self-check
        // must digest it the same way.
        !o.contains_key("no-default-denies"),
        o.contains_key("accept-edits"),
    ) {
        note!(cx, "run bundle not written: {e}");
        if let Ok(f) = Finding::new(
            Severity::Low,
            FindingCode("harness.bundle".to_owned()),
            format!("run {} inputs/", report.run),
            "the run's inputs copied into the state root",
            e,
        ) {
            findings.push(f);
        }
    }
    if stream {
        stream_json(cx, &report, inp.profile.pricing());
    }
    Ok(Outcome {
        outcome: report.outcome,
        findings,
        chain_head: report.chain_head.map(|d| d.to_string()),
        exit_override: None,
    })
}

/// `--output stream-json` (P-15): the attempt journal as newline-delimited
/// JSON on stdout — the schema line, one line per record (byte-for-byte the
/// journal's canonical lines), then the `usage {...}` footer — all BEFORE
/// the `chain_head` line and the report, which stay the last stdout lines.
/// A journal that cannot be read does not change the run's report or exit
/// code: it is noted on stderr and the stream is simply absent.
fn stream_json(cx: &Cx<'_>, report: &harness_run::RunReport, pricing: Option<Pricing>) {
    let attempt_dir = harness_journal::layout::attempt_dir(&report.run_dir, report.attempt);
    let v = match harness_journal::JournalReader::open_expecting(&attempt_dir, &report.run) {
        Ok(v) => v,
        Err(e) => {
            note!(cx, "stream-json: cannot read the attempt journal: {e}");
            return;
        }
    };
    say!(cx, "{}", crate::cmd_events::SCHEMA_LINE);
    for i in 0..v.records.len() {
        if let Some(line) = v.line_bytes(i) {
            say!(cx, "{}", String::from_utf8_lossy(&line));
        }
    }
    let usage = crate::usage::Usage::from_journal(&v).priced(pricing);
    say!(cx, "usage {}", usage.to_json());
    note!(cx, "{}", usage.in_words());
}

/// What a run's pre-submit checks did, said plainly (H3a): how many
/// submissions ran them and how many a failing check turned back, and how
/// the last one ended. A submission accepted with a check still failing, or
/// with the checks not run, says so.
fn presubmit_in_words(p: &harness_run::PresubmitReport, cause: &harness_core::StopCause) -> String {
    use harness_run::PresubmitResult as R;
    let last = match (p.last, cause) {
        (None, _) => "the run stopped before it submitted, so no check ran".to_owned(),
        (Some(R::Passed), _) => "every check passed at the last submission".to_owned(),
        (Some(R::Failed), harness_core::StopCause::SubmittedChecksFailed) => {
            "a check still failed at the last submission, which was accepted anyway once the \
             bound was spent (stop cause submitted_checks_failed)"
                .to_owned()
        }
        (Some(R::Failed), _) => {
            "a check failed at the last submission, which was turned back; the run then \
             stopped for another reason"
                .to_owned()
        }
        (Some(R::NotRun), _) => {
            "a check could not be run at the last submission (declined or unanswered \
             approval, or no runner), which was accepted; nothing checked it"
                .to_owned()
        }
    };
    format!(
        "{} submission(s) ran the checks, {} turned back (the bound is {}); {last}",
        p.submissions, p.turned_back, p.max_rounds
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use gate_outcome::Severity;

    #[test]
    fn a_pressed_step_is_an_info_finding_and_no_step_is_none() {
        assert!(possibly_environmental("run r attempt 1", &[]).is_none());
        let f = possibly_environmental("run r attempt 1", &[3, 7]).unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.code.0, "harness.possibly-environmental");
        assert!(f.observed.contains("step(s) 3, 7"), "{}", f.observed);
    }
}
