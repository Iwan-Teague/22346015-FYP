//! The public API of the CLI library is a contract with the binary
//! (`src/main.rs`), with embedders and with the tests: `Cx`, `main_with`,
//! `ApproverSource` and `TerminalApprover` must stay nameable and
//! constructible from outside the crate (slice P-01 split `lib.rs` into
//! modules without moving any of them). Compile-only use: the types are
//! built and the functions taken as values; nothing runs.

use std::cell::RefCell;

use harness_cli::{main_with, ApproverSource, Cx, TerminalApprover};
use harness_policy::approval::ApprovalRequest;
use harness_run::{ApprovalAnswer, Approver, ApproverKind};

/// An approver an embedder passes as [`ApproverSource::Given`].
struct Yes;

impl Approver for Yes {
    fn kind(&self) -> ApproverKind {
        ApproverKind::Embedded
    }
    fn ask(&self, _req: &ApprovalRequest, _deadline: std::time::Instant) -> ApprovalAnswer {
        ApprovalAnswer::Yes
    }
}

#[test]
fn cli_public_api_unchanged() {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let cx: Cx<'_> = Cx {
        probe: &harness_sandbox::locality::SystemProbe,
        gate_ok_file: None,
        out: RefCell::new(&mut out),
        err: RefCell::new(&mut err),
        approver: ApproverSource::Given(&Yes),
        input: harness_cli::InputSource::Given(&[]),
        backend: harness_cli::BackendSource::BuiltIn,
        confinement: &harness_sandbox::SystemConfinement,
    };
    let dispatch: fn(&Cx<'_>, &[&str]) -> u8 = main_with;
    let _ = dispatch;
    // Constructing the prompt starts its stdin reader; nothing asks it
    // anything here, and the reader ends with the test process.
    let prompt = TerminalApprover::new(&cx);
    let _ = prompt;
}
