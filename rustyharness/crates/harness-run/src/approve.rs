//! Who answers an `Ask` (design §5.3, H2b): the [`Approver`] seam, and how
//! an answer is journaled and re-fed.
//!
//! When policy decides `Ask`, the loop journals `ApprovalRequested`, shows
//! the approver an [`ApprovalRequest`] (the capability's summary, its class
//! in plain words, the arguments escaped for a terminal, the step) and
//! waits, with the run's wall clock paused (§2.4), until the approval
//! timeout. A yes mints a token through the attempt's
//! `ApprovalAuthority` (a key and a nonce from OS randomness, never
//! written anywhere), redeems it against exactly this call and step, and
//! turns the `Ask` into an `Authorized` call with
//! `Session::authorize_approved`: `ApprovalGranted` records the consumed
//! nonce (§5.3: "consumed nonces are journaled, so reuse is detectable in
//! replay"), never the MAC. A no is `ApprovalDenied`; no answer by the
//! deadline is `ApprovalExpired`, a deny (§5.3: never an auto-approve).
//! With no approver present, policy has already turned the ask into a deny
//! (§5.2), so the approver is never asked.
//!
//! Every approval is single-use and bound to its step: the scope "for
//! identical calls in this run" is never offered (the owner kept the strict
//! step binding, so such a token would reach no other call anyway).
//!
//! **Replay.** An approver's answer is an input, like a model reply: an
//! audit, and a resume's catch-up, re-feed the recorded answers in order
//! (the approver kind and the nonce), and re-mint with the recorded nonce
//! through their own authority. A journal whose approvals reuse a nonce
//! therefore fails to re-mint, and the replay diverges (INV-16).
//!
//! **Approver ids.** The journal holds only trusted text, so the approver
//! is named by its kind, a closed set the harness owns
//! ([`ApproverKind`]), not by a person's runtime name.

use std::time::Instant;

use harness_core::Nonce;
use harness_policy::approval::ApprovalRequest;

/// What kind of approver answered: the closed set of names the journal
/// records (§5.3 "approver id").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproverKind {
    /// The person at the terminal running `rustyharness` (the CLI prompt,
    /// only when stdin is a terminal).
    Terminal,
    /// An embedding application's own approval UI (`harness-run` API).
    Embedded,
}

impl ApproverKind {
    /// The journal's name for it.
    pub fn as_str(self) -> &'static str {
        match self {
            ApproverKind::Terminal => "terminal",
            ApproverKind::Embedded => "embedded",
        }
    }

    /// Parse a journal name; `None` outside the closed set.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "terminal" => Some(ApproverKind::Terminal),
            "embedded" => Some(ApproverKind::Embedded),
            _ => None,
        }
    }
}

/// An approver's answer to one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalAnswer {
    /// Yes, for this one call.
    Yes,
    /// No.
    No,
    /// No answer before the deadline: a deny (§5.3).
    NoAnswer,
    /// Yes for the call's PATTERN, for the rest of the session (P-23): the
    /// harness distils the call into one minimal matcher (exec: the argv
    /// prefix; edit: that file; read: that directory), journals it as
    /// `RuleGranted` and applies it as a session policy rule. Honoured only
    /// when the run allowed session grants; a `protected_action` ask is
    /// never lowered.
    AllowSession,
    /// No for the call's pattern, for the rest of the session (P-23).
    DenySession,
}

/// Who answers an `Ask` (§5.3): the CLI prompt, or an embedding UI. The
/// approver sees only the [`ApprovalRequest`] (never a token), and answers
/// yes, no, or not at all by `deadline`.
pub trait Approver {
    /// What kind of approver this is (journaled with every answer).
    fn kind(&self) -> ApproverKind;

    /// Show `req` and wait at most until `deadline` for an answer. Anything
    /// but an explicit yes denies the call.
    fn ask(&self, req: &ApprovalRequest, deadline: Instant) -> ApprovalAnswer;
}

/// A recorded answer, re-fed in place of asking (audit, resume catch-up).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordedApproval {
    /// `ApprovalGranted`: who, and the nonce it consumed.
    Granted { kind: ApproverKind, nonce: [u8; 16] },
    /// `ApprovalDenied`.
    Denied { kind: ApproverKind },
    /// `ApprovalExpired`.
    Expired,
    /// `RuleGranted` (P-23): who, and the digest of the matcher's
    /// canonical JSON — the replayed loop rebuilds the matcher from the
    /// call and must reach the same digest or the replay diverges.
    AllowSession {
        kind: ApproverKind,
        matcher: gate_outcome::Digest,
    },
    /// `RuleGranted`, deny list (P-23).
    DenySession {
        kind: ApproverKind,
        matcher: gate_outcome::Digest,
    },
}

/// A 16-byte approval nonce as the journal writes it: 32 lowercase hex
/// characters, the render nonce's grammar (so it is a trusted name).
pub(crate) fn nonce_name(bytes: [u8; 16]) -> Option<Nonce> {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Nonce::new(&hex)
}

/// The bytes of a journaled approval nonce: exactly 32 lowercase hex
/// characters.
pub(crate) fn nonce_bytes(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 || Nonce::new(s).is_none() {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approver_kinds_round_trip_and_nothing_else_parses() {
        for k in [ApproverKind::Terminal, ApproverKind::Embedded] {
            assert_eq!(ApproverKind::parse(k.as_str()), Some(k));
        }
        for bad in ["", "Terminal", "cli", "embedded ", "a@b"] {
            assert_eq!(ApproverKind::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_nonce_round_trips_through_its_journal_name() {
        let b = [
            0x00, 0x01, 0xab, 0xff, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 0xfe,
        ];
        let n = nonce_name(b).unwrap();
        assert_eq!(n.as_str().len(), 32);
        assert_eq!(nonce_bytes(n.as_str()), Some(b));
        for bad in [
            "",
            "0001abff",
            "0001ABFF0708090a0b0c0d0e0f1011fe",
            "0001abff0708090a0b0c0d0e0f1011fe00",
        ] {
            assert_eq!(nonce_bytes(bad), None, "{bad:?}");
        }
    }
}
