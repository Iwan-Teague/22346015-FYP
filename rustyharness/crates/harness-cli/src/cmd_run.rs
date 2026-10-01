//! The `run` and `resume` verbs: read the inputs, check the state root's
//! locality and the model server, hand everything to `harness_run`, and
//! turn the run's report into words on stderr and an [`Outcome`].

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use gate_outcome::{Finding, GateOutcome, IndeterminateKind};
use harness_core::RunId;
use harness_model::client::{ClientConfig, OpenAiCompatible};
use harness_run::{Approver, Resume, Run, RunRefused};
use harness_sandbox::environment::SystemEnv;

use crate::approver::{ApproverSource, TerminalApprover};
use crate::dispatch::Verb;
use crate::inputs::{inputs, required};
use crate::report::{exit, info, refused, Outcome};
use crate::Cx;

fn from_refusal(cx: &Cx<'_>, e: &RunRefused) -> Outcome {
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

pub(crate) fn run_or_resume(cx: &Cx<'_>, o: &BTreeMap<&str, &str>, verb: Verb) -> Outcome {
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
    let config = &inp.config;
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
    // Who answers an ask (§5.3): with nobody, every ask is a deny (§5.2),
    // so an unattended run edits only where its policy allows edits.
    let terminal;
    let approver: Option<&dyn Approver> = match cx.approver {
        ApproverSource::None => None,
        ApproverSource::Given(a) => Some(a),
        ApproverSource::StdinIfTerminal => {
            use std::io::IsTerminal;
            if std::io::stdin().is_terminal() {
                terminal = TerminalApprover::new(cx);
                Some(&terminal)
            } else {
                None
            }
        }
    };
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
            config,
            approver,
            confinement: Some(cx.confinement),
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
    Ok(Outcome {
        outcome: report.outcome,
        findings,
        chain_head: report.chain_head.map(|d| d.to_string()),
        exit_override: None,
    })
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
