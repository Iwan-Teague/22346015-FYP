//! The loop's approvals (§5.3, H2b): where the answers to asks come from
//! — recorded answers first, then the live approver, if any — and the
//! authority that mints and redeems every approval token.

use std::time::Instant;

use harness_core::{RunId, StopCause};
use harness_journal::{
    BlobSink, Clock, Event, EventKind, Ident, JournalFile, JournalWriter, Trusted,
};
use harness_manifest::{Capability, Confirmation};
use harness_model::HarnessText;
use harness_policy::approval::{
    ApprovalAuthority, ApprovalRequest, ApprovalScope, BoundCall, MintRequest, PrincipalId, StepId,
};
use harness_policy::{Authorized, Call};

use super::step::{journal, Loop};
use crate::approve::{nonce_name, ApprovalAnswer, Approver, RecordedApproval};
use crate::driver::random_bytes;

/// Where the answers to asks come from (§5.3, H2b): recorded answers first
/// (an audit, a resume's catch-up), then the live approver, if any. The
/// attempt's approval authority mints and redeems every token with a key
/// drawn here from OS randomness, held only in this struct.
pub(crate) struct Approvals<'a> {
    /// The live approver; `None` when nobody answers.
    pub(crate) approver: Option<&'a dyn Approver>,
    /// Recorded answers, re-fed in order before the approver is asked.
    pub(crate) recorded: std::collections::VecDeque<RecordedApproval>,
    /// The attempt's minter and verifier of approval tokens.
    pub(crate) authority: ApprovalAuthority,
    /// The attempt the tokens bind.
    pub(crate) attempt: u32,
    /// The authority's time origin (expiry is measured from it).
    pub(crate) epoch: Instant,
}

impl<'a> Approvals<'a> {
    /// The approvals of attempt `attempt` of `run`: a fresh per-attempt key
    /// (the run-id randomness, §2.8), so no token outlives its attempt.
    pub(crate) fn new(
        run: &RunId,
        attempt: u32,
        approver: Option<&'a dyn Approver>,
        recorded: std::collections::VecDeque<RecordedApproval>,
    ) -> Self {
        Self {
            approver,
            recorded,
            authority: ApprovalAuthority::new(run.clone(), random_bytes::<32>()),
            attempt,
            epoch: Instant::now(),
        }
    }
}

impl<'a> Loop<'a> {
    /// §5.3: an `Ask` becomes a call only with a yes for exactly this call.
    /// Journals `ApprovalRequested`, takes the answer (recorded, when
    /// replaying; else the live approver's, with the wall clock paused and
    /// the approval timeout as its deadline; else none), and on a yes mints
    /// a single-use token bound to this attempt, step, capability, argument
    /// digest and tier, redeems it at once, and authorises the call with
    /// the proof (`ApprovalGranted` records the consumed nonce, never the
    /// MAC). A no is `ApprovalDenied`, no answer `ApprovalExpired`: the
    /// call does not run and the model is told so in static text. A token
    /// that fails to mint, redeem or authorise (a recorded nonce reused, a
    /// harness bug) stops the run: `PolicyAbort`, never a call.
    pub(crate) fn approve<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
        step: u64,
        capability: &Capability,
        call: Call,
        tier: Confirmation,
    ) -> Result<Result<Authorized<Call>, HarnessText>, StopCause> {
        let abort = StopCause::PolicyAbort;
        let cap_id = Ident::from_capability(capability).ok_or(abort.clone())?;
        let class = self
            .session
            .class(capability.id().as_str())
            .ok_or(abort.clone())?;
        let at = StepId::new(step);
        let attempt = self.approvals.attempt;
        let bound = BoundCall::for_call(attempt, at, &call, tier).ok_or(abort.clone())?;
        let about = |kind| {
            Event::new(kind)
                .field("capability", Trusted::Id(cap_id.clone()))
                .field("args", Trusted::Digest(bound.args_sha256))
                .field("tier", Trusted::Text(tier.as_str()))
        };
        w.append(step, about(EventKind::ApprovalRequested))
            .map_err(journal)?;
        let answer = match self.approvals.recorded.pop_front() {
            Some(recorded) => recorded,
            None => match self.approvals.approver {
                Some(a) => {
                    let req = ApprovalRequest::new(
                        capability.id().clone(),
                        capability.summary().to_owned(),
                        class,
                        call.args.clone(),
                        tier,
                        attempt,
                        at,
                    );
                    let deadline = Instant::now() + self.config.approval_timeout;
                    // P-05 §8: the sink has seen the ask (and every record
                    // before it) before the human is waited on.
                    self.ui_drain(w);
                    // §2.4: the wait for a human is not charged to the
                    // wall budget (the guard resumes the clock on drop).
                    let pause = self.meter.pause_wall()?;
                    let said = a.ask(&req, deadline);
                    drop(pause);
                    match said {
                        ApprovalAnswer::Yes => RecordedApproval::Granted {
                            kind: a.kind(),
                            nonce: random_bytes::<16>(),
                        },
                        ApprovalAnswer::No => RecordedApproval::Denied { kind: a.kind() },
                        ApprovalAnswer::NoAnswer => RecordedApproval::Expired,
                    }
                }
                // Policy asked with nobody here to answer (an audit whose
                // journal ends in the wait): no yes, so no call.
                None => RecordedApproval::Expired,
            },
        };
        match answer {
            RecordedApproval::Granted { kind, nonce } => {
                let a = &mut self.approvals;
                let now = a.epoch.elapsed();
                let token = a
                    .authority
                    .mint(
                        &MintRequest {
                            attempt,
                            step: at,
                            capability: bound.capability.clone(),
                            args_sha256: bound.args_sha256,
                            tier,
                            scope: ApprovalScope::Once,
                            approver: PrincipalId::new(kind.as_str()).map_err(|_| abort.clone())?,
                        },
                        nonce,
                        now,
                    )
                    .map_err(|_| abort.clone())?;
                let redeemed = a
                    .authority
                    .redeem(&token, &bound, now)
                    .map_err(|_| abort.clone())?;
                let authorized = self
                    .session
                    .authorize_approved(call, redeemed)
                    .map_err(|_| abort.clone())?;
                let name = nonce_name(nonce).ok_or(abort.clone())?;
                let nonce_id = Ident::from_trusted(&name).ok_or(abort)?;
                w.append(
                    step,
                    about(EventKind::ApprovalGranted)
                        .field("approver", Trusted::Text(kind.as_str()))
                        .field("nonce", Trusted::Id(nonce_id))
                        .field("scope", Trusted::Text("once")),
                )
                .map_err(journal)?;
                Ok(Ok(authorized))
            }
            RecordedApproval::Denied { kind } => {
                w.append(
                    step,
                    about(EventKind::ApprovalDenied)
                        .field("approver", Trusted::Text(kind.as_str())),
                )
                .map_err(journal)?;
                Ok(Err(HarnessText::from_static(
                    "The approver declined the call, so it did not run.",
                )))
            }
            RecordedApproval::Expired => {
                w.append(step, about(EventKind::ApprovalExpired))
                    .map_err(journal)?;
                Ok(Err(HarnessText::from_static(
                    "No approval arrived in time, so the call did not run.",
                )))
            }
        }
    }
}
