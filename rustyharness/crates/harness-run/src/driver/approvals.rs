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
use super::tools::{is_edit, is_exec, is_read};
use crate::approve::{nonce_name, ApprovalAnswer, Approver, ApproverKind, RecordedApproval};
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
    /// Whether an `a`/`d` answer may become a session rule (P-23, Q-4:
    /// default off). A replay turns this on exactly when the journal it
    /// re-feeds holds a `RuleGranted`.
    pub(crate) session_grants: bool,
    /// The edit tools, for the diff preview shown at an edit prompt
    /// (P-16 through P-23). `None` on replay paths that never ask.
    pub(crate) edits: Option<harness_tools::EditTools>,
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
            session_grants: false,
            edits: None,
        }
    }

    /// Set whether session grants are allowed (P-23).
    #[must_use]
    pub(crate) fn may_grant(mut self, on: bool) -> Self {
        self.session_grants = on;
        self
    }

    /// Set the edit tools whose previews an edit prompt shows (P-23).
    #[must_use]
    pub(crate) fn with_edits(mut self, edits: Option<harness_tools::EditTools>) -> Self {
        self.edits = edits;
        self
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
                    // An edit prompt shows the diff the call would produce
                    // (P-16's preview, reached through P-23): the same
                    // plan the apply path would run, as sanitised text.
                    let mut summary = capability.summary().to_owned();
                    if let (true, Some(edits)) =
                        (is_edit(capability.id().as_str()), &self.approvals.edits)
                    {
                        if let Ok(diff) = edits.preview(&call, &self.reads) {
                            summary.push_str("\n\nproposed diff:\n");
                            summary.push_str(&diff);
                        }
                    }
                    let req = ApprovalRequest::new(
                        capability.id().clone(),
                        summary,
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
                    let kind = a.kind();
                    match said {
                        ApprovalAnswer::Yes => RecordedApproval::Granted {
                            kind,
                            nonce: random_bytes::<16>(),
                        },
                        ApprovalAnswer::No => RecordedApproval::Denied { kind },
                        ApprovalAnswer::NoAnswer => RecordedApproval::Expired,
                        // A session answer is distilled to the matcher's
                        // digest now: the recorded answer carries it so the
                        // replayed loop can check the matcher it rebuilds
                        // from the call is the same one (P-23).
                        ApprovalAnswer::AllowSession => {
                            match session_matcher(capability.id().as_str(), &call.args) {
                                Some(m) => RecordedApproval::AllowSession {
                                    kind,
                                    matcher: harness_core::sha256(m.canonical().as_bytes()),
                                },
                                // Nothing minimal to grant: a plain denial,
                                // deterministically.
                                None => RecordedApproval::Denied { kind },
                            }
                        }
                        ApprovalAnswer::DenySession => {
                            match session_matcher(capability.id().as_str(), &call.args) {
                                Some(m) => RecordedApproval::DenySession {
                                    kind,
                                    matcher: harness_core::sha256(m.canonical().as_bytes()),
                                },
                                None => RecordedApproval::Denied { kind },
                            }
                        }
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
            RecordedApproval::AllowSession { kind, matcher } => self.grant_session(
                w,
                step,
                capability,
                call,
                tier,
                about,
                true,
                kind,
                Some(matcher),
            ),
            RecordedApproval::DenySession { kind, matcher } => self.grant_session(
                w,
                step,
                capability,
                call,
                tier,
                about,
                false,
                kind,
                Some(matcher),
            ),
        }
    }

    /// A session answer (`a`/`d`, P-23): distil the call into one minimal
    /// matcher, add it to the session's rule lists, journal `RuleGranted`,
    /// and re-decide — the grant applies exactly as a policy rule, so a
    /// user deny, a confirmation floor or an off-schema argument still
    /// says no. A `protected_action` ask is never lowered: one answer
    /// cannot stand for every such call, so the answer degrades to a
    /// plain denial of this call. So does an answer when the run did not
    /// opt in (`--allow-session-grants`, Q-4), or when the call names no
    /// minimal pattern.
    #[allow(clippy::too_many_arguments)]
    fn grant_session<F: JournalFile, B: BlobSink, K: Clock>(
        &mut self,
        w: &mut JournalWriter<F, B, K>,
        step: u64,
        capability: &Capability,
        call: Call,
        tier: Confirmation,
        about: impl Fn(EventKind) -> Event,
        allow: bool,
        kind: ApproverKind,
        recorded_matcher: Option<gate_outcome::Digest>,
    ) -> Result<Result<Authorized<Call>, HarnessText>, StopCause> {
        let abort = StopCause::PolicyAbort;
        // A degraded answer is the plain decline, exactly as a `no` reads:
        // the journal holds `ApprovalDenied`, so the replay re-feeds a
        // `Denied` and must say the same thing to the model.
        let denied = |w: &mut JournalWriter<F, B, K>, kind: ApproverKind| {
            w.append(
                step,
                about(EventKind::ApprovalDenied).field("approver", Trusted::Text(kind.as_str())),
            )
            .map_err(journal)?;
            Ok(Err(HarnessText::from_static(
                "The approver declined the call, so it did not run.",
            )))
        };
        if tier == Confirmation::ProtectedAction
            || !self.approvals.session_grants
            || self.session.class(capability.id().as_str()).is_none()
        {
            return denied(w, kind);
        }
        let Some(matcher) = session_matcher(capability.id().as_str(), &call.args) else {
            return denied(w, kind);
        };
        let digest = harness_core::sha256(matcher.canonical().as_bytes());
        if let Some(recorded) = recorded_matcher {
            if recorded != digest {
                // The journal's grant and the call it rides disagree: the
                // evidence does not re-derive (INV-16 territory).
                return Err(abort);
            }
        }
        let list = if allow {
            harness_policy::RuleList::Allow
        } else {
            harness_policy::RuleList::Deny
        };
        let cap =
            harness_manifest::CapId::new(capability.id().as_str()).map_err(|_| abort.clone())?;
        let _index = self.session.grant(list, &cap, matcher);
        let cap_ident = Ident::from_capability(capability).ok_or(abort.clone())?;
        w.append(
            step,
            Event::new(EventKind::RuleGranted)
                .field("capability", Trusted::Id(cap_ident))
                .field("list", Trusted::Text(if allow { "allow" } else { "deny" }))
                .field("matcher", Trusted::Digest(digest))
                .field("approver", Trusted::Text(kind.as_str())),
        )
        .map_err(journal)?;
        let decision = self.session.decide(&call);
        w.append(step, super::stop::decided(&decision))
            .map_err(journal)?;
        match decision {
            harness_policy::PolicyDecision::Allow { .. } => {
                let authorized = self.session.authorize(call).map_err(|_| abort.clone())?;
                Ok(Ok(authorized))
            }
            harness_policy::PolicyDecision::Deny {
                reason: harness_policy::DenyReason::SessionDenied,
                ..
            } => Ok(Err(HarnessText::from_static(
                "The pattern is denied for the session, so the call did not run.",
            ))),
            _ => Ok(Err(HarnessText::from_static(
                "The session grant cannot allow this call: policy still asks about it, and one approval cannot answer for the session. It did not run.",
            ))),
        }
    }
}

/// The minimal matcher a session grant covers one call with (P-23): the
/// first two argv items for the command runner, the file itself for a
/// workspace edit, the directory (and everything below it) for a read
/// tool. `None` where nothing minimal names the call — a session grant is
/// matcher-bound or it is nothing.
fn session_matcher(cap: &str, args: &serde_json::Value) -> Option<harness_policy::Matcher> {
    if is_exec(cap) {
        let argv: Vec<String> = args
            .get("argv")?
            .as_array()?
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<_>>()?;
        let cut = argv.len().min(2);
        harness_policy::Matcher::argv_prefix(argv.into_iter().take(cut).collect()).ok()
    } else if is_edit(cap) {
        let path = args.get("path")?.as_str()?;
        harness_policy::Matcher::path_glob(path).ok()
    } else if is_read(cap) {
        let path = args.get("path")?.as_str()?;
        let dir = match path.rsplit_once('/') {
            Some((dir, _)) if !dir.is_empty() => dir.to_owned(),
            _ => ".".to_owned(),
        };
        // `a/**` covers what is BELOW a but not a itself; `{a,a/**}` is
        // the directory and everything below it. The root reads as `**`.
        let pattern = if dir == "." {
            "**".to_owned()
        } else {
            format!("{dir}{{,/**}}")
        };
        harness_policy::Matcher::path_glob(&pattern).ok()
    } else {
        None
    }
}
