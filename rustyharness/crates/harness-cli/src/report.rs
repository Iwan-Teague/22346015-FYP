//! A gate child's ending (§7.7): the [`Outcome`] a verb returns, and
//! [`emit`], which prints the chain head, the report line (the last stdout
//! line) and the `GATE_OK_FILE` marker, and turns the outcome into the
//! exit code.

use gate_outcome::{
    Coverage, Finding, FindingCode, GateId, GateOutcome, GateReport, IndeterminateKind, Scope,
    Severity,
};

use crate::Cx;

/// The exit codes (§7.7).
pub(crate) mod exit {
    pub const PASSED: u8 = 0;
    pub const FAILED: u8 = 1;
    pub const USAGE: u8 = 2;
    pub const CONFINEMENT_REFUSED: u8 = 3;
    pub const UNREADABLE_INPUT: u8 = 4;
    pub const INDETERMINATE: u8 = 5;
}

/// What a gate-child verb ends with.
pub(crate) struct Outcome {
    pub outcome: GateOutcome,
    pub findings: Vec<Finding>,
    pub chain_head: Option<String>,
    /// The exit code for a non-verdict ending (usage, unreadable input).
    pub exit_override: Option<u8>,
}

pub(crate) fn info(
    code: &str,
    location: &str,
    expected: &str,
    observed: String,
) -> Option<Finding> {
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

pub(crate) fn refused(exit_code: u8, observed: String) -> Outcome {
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

/// The commit sequence after the run (§7.1): the chain head, the report
/// line (last stdout line), the marker only for `Passed`, then exit.
pub(crate) fn emit(cx: &Cx<'_>, gate: &GateId, o: Outcome) -> u8 {
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
