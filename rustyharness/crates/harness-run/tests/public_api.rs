//! A compile-time guard for the public paths. The P-09 split of the big
//! `driver.rs`/`replay.rs` files into submodules must not move anything a
//! reader of the crate can reach. Every re-exported path (and the paths
//! that live in the two public `driver`/`replay` modules) is named here;
//! if one moves, this file stops compiling.

fn t<T>() {}

#[test]
fn public_api_paths_unchanged() {
    // The crate root re-exports (lib.rs).
    let run: fn(harness_run::Run<'_>) -> Result<harness_run::RunReport, harness_run::RunRefused> =
        harness_run::run;
    let audit: fn(
        harness_run::Audit,
    ) -> Result<harness_run::AuditReport, harness_run::AuditRefused> = harness_run::audit;
    let resume: fn(harness_run::Resume) -> Result<harness_run::RunReport, harness_run::RunRefused> =
        harness_run::resume;

    t::<harness_run::TaskSpec>();
    t::<harness_run::RunConfig>();
    t::<harness_run::RunRefused>();
    t::<harness_run::RunReport>();
    t::<harness_run::ReadLog>();
    t::<harness_run::StaleRead>();
    t::<harness_run::Audit>();
    t::<harness_run::AuditRefused>();
    t::<harness_run::AuditReport>();
    t::<harness_run::Divergence>();
    t::<harness_run::Resume>();
    t::<harness_run::ApprovalAnswer>();
    t::<harness_run::ApproverKind>();
    t::<harness_run::PresubmitRefused>();
    t::<harness_run::PresubmitReport>();
    t::<harness_run::PresubmitResult>();
    t::<harness_run::PresubmitSpec>();
    t::<harness_run::ExecSpec>();
    t::<harness_run::ExecProgram>();
    t::<harness_run::ExecLimits>();

    // The `driver` module keeps its own public paths.
    let driver_run: fn(
        harness_run::driver::Run<'_>,
    )
        -> Result<harness_run::driver::RunReport, harness_run::driver::RunRefused> =
        harness_run::driver::run;
    t::<harness_run::driver::TaskSpec>();
    t::<harness_run::driver::RunConfig>();
    t::<harness_run::driver::RunRefused>();
    t::<harness_run::driver::RunReport>();
    t::<harness_run::driver::ReadLog>();
    t::<harness_run::driver::StaleRead>();

    // The `replay` module keeps its own public paths.
    let replay_audit: fn(
        harness_run::replay::Audit,
    ) -> Result<
        harness_run::replay::AuditReport,
        harness_run::replay::AuditRefused,
    > = harness_run::replay::audit;
    let replay_resume: fn(
        harness_run::replay::Resume,
    ) -> Result<harness_run::RunReport, harness_run::RunRefused> = harness_run::replay::resume;
    t::<harness_run::replay::Audit>();
    t::<harness_run::replay::AuditRefused>();
    t::<harness_run::replay::AuditReport>();
    t::<harness_run::replay::Divergence>();
    t::<harness_run::replay::Resume>();

    // The `approve`, `presubmit` and `postedit` modules stay public too.
    t::<harness_run::approve::ApprovalAnswer>();
    t::<harness_run::approve::ApproverKind>();
    t::<harness_run::presubmit::PresubmitRefused>();
    t::<harness_run::presubmit::PresubmitReport>();
    t::<harness_run::presubmit::PresubmitResult>();
    t::<harness_run::presubmit::PresubmitSpec>();
    t::<harness_run::postedit::PostEditRefused>();
    t::<harness_run::postedit::PostEditReport>();
    t::<harness_run::postedit::PostEditResult>();
    t::<harness_run::postedit::PostEditSpec>();
    t::<harness_run::postedit::PostEditCheck>();

    // A trait object path and a public record are nameable as before.
    let no_approver: Option<&'static dyn harness_run::Approver> = None;
    let divergence = harness_run::Divergence {
        seq: 0,
        step: 0,
        why: "paths unchanged",
    };

    // Values are used so the check reads as a real binding, not a wish.
    let _ = (
        run,
        audit,
        resume,
        driver_run,
        replay_audit,
        replay_resume,
        no_approver,
        divergence,
    );
}
