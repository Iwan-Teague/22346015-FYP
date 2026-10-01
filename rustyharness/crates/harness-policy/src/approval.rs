//! Approval tokens, the §5.3 slice (design `docs/01-design-v0.1.md` §5.3).
//!
//! An `Ask` from [`crate::Session::decide`] never becomes an
//! [`crate::Authorized`] call by itself: the run driver shows an
//! [`ApprovalRequest`] to the approver (CLI prompt or embedding UI), and a
//! "yes" mints an [`Approval`] through the run's [`ApprovalAuthority`]. The
//! token is the rustyfin confirmation-token pattern: bound to run, attempt,
//! step, capability, argument digest, tier, expiry and nonce, authenticated
//! with an HMAC under a per-run key that exists only in harness memory. A
//! token forged on disk is worthless — the MAC cannot be computed outside
//! the harness process — and tokens never enter the model context (§5.3).
//! [`Session::authorize_approved`](crate::Session::authorize_approved) is
//! the only place an `Ask` plus a token becomes an
//! [`Authorized`](crate::Authorized) call.
//!
//! Pure: no I/O, no clock, no RNG. The caller supplies the run id, the key
//! randomness, the nonce bytes and the current monotonic time (the
//! `harness_core::RunId::new` pattern, §2.8). Expiry is read from a
//! [`std::time::Duration`] handed in, so replay recomputes it (§2.9).
//!
//! Fail-closed (INV-5): a call under `Ask` without a valid, bound,
//! unconsumed approval refuses every time — no token, a token for different
//! arguments, an expired token, a reused token, a token from another run:
//! all refused. Unforgeable and bound (INV-16): every bound field sits
//! under the MAC, and a consumed nonce can never be spent again.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use harness_core::{sha256, Digest, RunId};
use harness_manifest::{CapId, Confirmation};
use serde_json::Value;

use crate::EffectiveClass;

/// How long an approval lives (§5.3, R2 §5: fifteen minutes).
pub const APPROVAL_TTL: Duration = Duration::from_secs(15 * 60);

/// Domain separation for the approval MAC (§5.3): every field is
/// length-prefixed under this tag, so an approval token can never be
/// confused with any other HMAC'd structure in the harness.
const DOMAIN: &[u8] = b"rustyharness.approval.v1";

/// A journal step number (§2.2): the step of the run a call belongs to.
/// Bound into every approval token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StepId(u64);

impl StepId {
    /// Wrap a step number.
    pub const fn new(n: u64) -> Self {
        Self(n)
    }

    /// The number.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for StepId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "step {}", self.0)
    }
}

/// Why a principal id was refused at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PrincipalIdError {
    /// The id is empty.
    #[error("principal id is empty")]
    Empty,
    /// Longer than 128 bytes.
    #[error("principal id is {len} bytes; at most 128 are allowed")]
    TooLong {
        /// How many bytes were supplied.
        len: usize,
    },
    /// A byte outside `[A-Za-z0-9._-]`.
    #[error("principal id contains a byte outside [A-Za-z0-9._-]")]
    BadChar,
    /// Starts with `.` or `-`.
    #[error("principal id starts with {start:?}; a leading '.' or '-' is refused")]
    BadStart {
        /// The offending first character.
        start: char,
    },
}

/// Who approved: the human principal behind the "yes" (a CLI user, an
/// embedding UI session). Recorded in every token and covered by the MAC.
///
/// The grammar is the journal identifier grammar (ASCII `[A-Za-z0-9._-]`,
/// at most 128 bytes, no leading `.` or `-`): approvers are journaled
/// (§5.3), so the id must survive the journal's name rules unchanged.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrincipalId(String);

impl PrincipalId {
    /// Check `s` against the identifier grammar.
    pub fn new(s: &str) -> Result<Self, PrincipalIdError> {
        if s.is_empty() {
            return Err(PrincipalIdError::Empty);
        }
        if s.len() > 128 {
            return Err(PrincipalIdError::TooLong { len: s.len() });
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(PrincipalIdError::BadChar);
        }
        if let Some(start) = s.chars().next() {
            if start == '.' || start == '-' {
                return Err(PrincipalIdError::BadStart { start });
            }
        }
        Ok(Self(s.to_owned()))
    }

    /// The id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How far one approval reaches (§5.3). Recorded in the token and covered
/// by the MAC, so a `once` token cannot be relabelled `run`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApprovalScope {
    /// One call. Every `protected_action` token is single-use (§5.3).
    Once,
    /// "For identical calls in this run": same capability AND same
    /// argument digest only. A `user_confirm` approval may carry it.
    Run,
}

/// What an approval binds (§5.3): the call's identity as the redeemer
/// expects it. Built from a [`crate::Call`] with [`BoundCall::for_call`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundCall {
    /// The attempt the approval was asked for.
    pub attempt: u32,
    /// The step the approval was asked for.
    pub step: StepId,
    /// The capability being approved.
    pub capability: CapId,
    /// SHA-256 of the call's canonical form.
    pub args_sha256: Digest,
    /// The confirmation tier that was asked.
    pub tier: Confirmation,
}

impl BoundCall {
    /// The binding for `call` at `attempt`/`step`, at tier `tier`:
    /// capability and the same canonical argument digest the journal's
    /// call-intent uses (§2.9, H1c review F-7). `None` when the call's
    /// capability string is not even a valid capability id — policy would
    /// have refused such a call before any approval could exist.
    pub fn for_call(
        attempt: u32,
        step: StepId,
        call: &crate::Call,
        tier: Confirmation,
    ) -> Option<Self> {
        let capability = CapId::new(&call.capability).ok()?;
        Some(Self {
            attempt,
            step,
            capability,
            args_sha256: crate::canonical_call_digest(call),
            tier,
        })
    }
}

/// What the approver said "yes" to minting. Untrusted until the authority
/// MACs it; the tier must be at least `user_confirm` (a `none`-tier call
/// never asks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintRequest {
    /// The attempt the approval is for.
    pub attempt: u32,
    /// The step the approval is for.
    pub step: StepId,
    /// The capability being approved.
    pub capability: CapId,
    /// SHA-256 of the call's canonical form.
    pub args_sha256: Digest,
    /// The confirmation tier that was asked.
    pub tier: Confirmation,
    /// How far the approval reaches. `protected_action` forces
    /// [`ApprovalScope::Once`].
    pub scope: ApprovalScope,
    /// Who approved.
    pub approver: PrincipalId,
}

/// Why a mint was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MintRefused {
    /// The tier is below `user_confirm`: nothing there ever asked.
    #[error("approval tier {0:?} is below user_confirm; nothing asked for it")]
    TierBelowFloor(Confirmation),
    /// `protected_action` tokens are single-use (§5.3).
    #[error("a protected_action approval must be scoped once")]
    ProtectedActionMustBeOnce,
    /// The nonce was already consumed by an earlier approval.
    #[error("nonce already consumed by an earlier approval")]
    NonceTaken,
}

/// Why a redemption was refused. Every refusal is fail-closed (INV-5):
/// nothing is minted and nothing runs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalRefused {
    /// The token names a different run than this authority's (INV-16).
    #[error("token names run {found}, not this authority's run {expected}")]
    WrongRun {
        /// The run on the token.
        found: RunId,
        /// This authority's run.
        expected: RunId,
    },
    /// The MAC does not verify: the token was made outside the harness
    /// process, or some field changed after minting (INV-16).
    #[error("approval MAC does not verify (forged or corrupted token)")]
    Forged,
    /// The token's TTL (15 minutes, §5.3) is over.
    #[error("approval expired (TTL is 15 minutes)")]
    Expired,
    /// The token is for another attempt.
    #[error("token is for attempt {found}, this is attempt {expected}")]
    AttemptMismatch {
        /// The attempt on the token.
        found: u32,
        /// The expected attempt.
        expected: u32,
    },
    /// The token is for another step.
    #[error("token is for {found}, this is {expected}")]
    StepMismatch {
        /// The step on the token.
        found: StepId,
        /// The expected step.
        expected: StepId,
    },
    /// The token is for another capability.
    #[error("token is for capability {found}, not {expected}")]
    CapabilityMismatch {
        /// The capability on the token.
        found: CapId,
        /// The expected capability.
        expected: CapId,
    },
    /// The token is for other arguments (different digest).
    #[error("token is for other arguments (digest mismatch)")]
    ArgsMismatch,
    /// The token is for another tier.
    #[error("token is for tier {found:?}, this call asks {expected:?}")]
    TierMismatch {
        /// The tier on the token.
        found: Confirmation,
        /// The expected tier.
        expected: Confirmation,
    },
    /// The nonce was consumed already: single use means single use
    /// (INV-16; consumed nonces are journaled so replay shows).
    #[error("approval nonce already consumed")]
    NonceReused,
}

/// The per-run HMAC key (§5.3): 32 random bytes supplied by the caller at
/// run start and held only in harness memory. Not `Clone`, not `Debug`-able
/// into anything but a redaction: the key never leaves the authority.
#[derive(PartialEq, Eq)]
struct ApprovalKey([u8; 32]);

impl fmt::Debug for ApprovalKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApprovalKey(redacted)")
    }
}

/// The §5.3 approval token. Every field is private and the only mint is
/// [`ApprovalAuthority::mint`]; there is deliberately no `Serialize`/`
/// Deserialize`: tokens never enter the model context, and a token found on
/// disk does not verify under the live run's key.
///
/// # INV-16 (compile-fail): no literal token construction
///
/// ```compile_fail,E0451
/// let forged = harness_policy::approval::Approval {
///     run: harness_core::RunId::new(0, [0; 10]),
///     attempt: 0,
///     step: harness_policy::approval::StepId::new(0),
///     capability: harness_manifest::CapId::new("x.y").unwrap(),
///     args_sha256: harness_core::Digest::from_bytes([0; 32]),
///     tier: harness_manifest::Confirmation::None,
///     expires_at: std::time::Duration::ZERO,
///     nonce: [0; 16],
///     approver: harness_policy::approval::PrincipalId::new("a").unwrap(),
///     scope: harness_policy::approval::ApprovalScope::Once,
///     mac: [0; 32],
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    run: RunId,
    attempt: u32,
    step: StepId,
    capability: CapId,
    args_sha256: Digest,
    tier: Confirmation,
    expires_at: Duration,
    nonce: [u8; 16],
    approver: PrincipalId,
    scope: ApprovalScope,
    mac: [u8; 32],
}

impl Approval {
    /// The run the token belongs to.
    pub fn run(&self) -> &RunId {
        &self.run
    }

    /// The attempt the token was asked for.
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// The step the token was asked for.
    pub fn step(&self) -> StepId {
        self.step
    }

    /// The capability the token approves.
    pub fn capability(&self) -> &CapId {
        &self.capability
    }

    /// SHA-256 of the approved call's canonical form.
    pub fn args_sha256(&self) -> Digest {
        self.args_sha256
    }

    /// The confirmation tier the token was asked at.
    pub fn tier(&self) -> Confirmation {
        self.tier
    }

    /// When the token dies (mint time + [`APPROVAL_TTL`]).
    pub fn expires_at(&self) -> Duration {
        self.expires_at
    }

    /// The single-use nonce, for journaling (§5.3, INV-16).
    pub fn nonce(&self) -> [u8; 16] {
        self.nonce
    }

    /// Who said "yes".
    pub fn approver(&self) -> &PrincipalId {
        &self.approver
    }

    /// How far the token reaches.
    pub fn scope(&self) -> ApprovalScope {
        self.scope
    }

    /// The HMAC over every bound field, for audit display.
    pub fn mac(&self) -> [u8; 32] {
        self.mac
    }
}

/// Proof that a token was redeemed for exactly one binding: what
/// [`Session::authorize_approved`](crate::Session::authorize_approved)
/// consumes, by value, so a single-use approval cannot be spent twice. Not
/// `Clone` (H2b): a copy would be a second proof of one redemption.
#[derive(Debug, PartialEq, Eq)]
pub struct Redeemed {
    run: RunId,
    attempt: u32,
    step: StepId,
    capability: CapId,
    args_sha256: Digest,
    tier: Confirmation,
    scope: ApprovalScope,
    nonce: [u8; 16],
}

impl Redeemed {
    /// The run the redeemed token belongs to.
    pub fn run(&self) -> &RunId {
        &self.run
    }

    /// The attempt the token was redeemed for.
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// The step the token was redeemed for.
    pub fn step(&self) -> StepId {
        self.step
    }

    /// The capability the token binds.
    pub fn capability(&self) -> &CapId {
        &self.capability
    }

    /// SHA-256 of the bound call's canonical form.
    pub fn args_sha256(&self) -> Digest {
        self.args_sha256
    }

    /// The tier the token was redeemed at.
    pub fn tier(&self) -> Confirmation {
        self.tier
    }

    /// How far the redemption reaches.
    pub fn scope(&self) -> ApprovalScope {
        self.scope
    }

    /// The consumed nonce, for journaling (§5.3, INV-16).
    pub fn nonce(&self) -> [u8; 16] {
        self.nonce
    }
}

/// The run's minter and verifier of approval tokens (§5.3). One per run:
/// the key and the consumed-nonce set are per-run state, so a token from
/// another run (or a token after a restart, which mints a fresh key)
/// never verifies.
///
/// Pure: the key comes in as caller-supplied randomness, time comes in per
/// call.
///
/// ```
/// use harness_policy::approval::*;
/// use harness_policy::Call;
/// use harness_manifest::Confirmation;
/// use harness_core::RunId;
/// use serde_json::json;
/// use std::time::Duration;
///
/// let mut authority =
///     ApprovalAuthority::new(RunId::new(0, [1; 10]), [7u8; 32]);
/// let call = Call { capability: "fixture.p".into(), args: json!({"path": "a"}) };
/// let bound =
///     BoundCall::for_call(1, StepId::new(3), &call, Confirmation::UserConfirm)
///         .unwrap();
/// let req = MintRequest {
///     attempt: 1,
///     step: StepId::new(3),
///     capability: bound.capability.clone(),
///     args_sha256: bound.args_sha256,
///     tier: Confirmation::UserConfirm,
///     scope: ApprovalScope::Once,
///     approver: PrincipalId::new("cli").unwrap(),
/// };
/// let token = authority.mint(&req, [9u8; 16], Duration::from_secs(100)).unwrap();
/// assert!(authority
///     .redeem(&token, &bound, Duration::from_secs(200))
///     .is_ok());
/// // Single use means single use (§5.3).
/// assert_eq!(
///     authority.redeem(&token, &bound, Duration::from_secs(300)),
///     Err(ApprovalRefused::NonceReused)
/// );
/// ```
pub struct ApprovalAuthority {
    run: RunId,
    key: ApprovalKey,
    consumed: BTreeMap<[u8; 16], ApprovalScope>,
}

impl fmt::Debug for ApprovalAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalAuthority")
            .field("run", &self.run)
            .field("consumed", &self.consumed.len())
            .finish_non_exhaustive()
    }
}

impl ApprovalAuthority {
    /// The authority for `run`, keyed by 32 caller-supplied random bytes
    /// (OS randomness in the driver, `[0; 32]`-shaped input in tests).
    pub fn new(run: RunId, key_randomness: [u8; 32]) -> Self {
        Self {
            run,
            key: ApprovalKey(key_randomness),
            consumed: BTreeMap::new(),
        }
    }

    /// The run this authority belongs to.
    pub fn run(&self) -> &RunId {
        &self.run
    }

    /// Mint an approval for `req`, at `now`, with caller-supplied nonce
    /// bytes (16 random bytes in the driver). Refuses a tier below
    /// `user_confirm`, a run-scoped `protected_action`, and a nonce an
    /// earlier approval already consumed.
    pub fn mint(
        &mut self,
        req: &MintRequest,
        nonce: [u8; 16],
        now: Duration,
    ) -> Result<Approval, MintRefused> {
        if req.tier < Confirmation::UserConfirm {
            return Err(MintRefused::TierBelowFloor(req.tier));
        }
        if req.tier == Confirmation::ProtectedAction && req.scope == ApprovalScope::Run {
            return Err(MintRefused::ProtectedActionMustBeOnce);
        }
        if self.consumed.contains_key(&nonce) {
            return Err(MintRefused::NonceTaken);
        }
        let expires_at = now.saturating_add(APPROVAL_TTL);
        let mut token = Approval {
            run: self.run.clone(),
            attempt: req.attempt,
            step: req.step,
            capability: req.capability.clone(),
            args_sha256: req.args_sha256,
            tier: req.tier,
            expires_at,
            nonce,
            approver: req.approver.clone(),
            scope: req.scope,
            mac: [0; 32],
        };
        token.mac = mac_over(&self.key.0, &token);
        Ok(token)
    }

    /// Redeem `token` against `expected` at time `now` (§5.3): the run
    /// must match, the MAC must verify, the token must be unexpired, every
    /// bound field must match the expected call, and the nonce must be
    /// unconsumed (for single-use scope). On success the nonce's
    /// consumption is recorded — visible through
    /// [`ApprovalAuthority::consumed_nonces`] so the driver journals it —
    /// and the [`Redeemed`] proof is returned.
    ///
    /// A run-scoped token may be redeemed again, but only for the SAME
    /// binding: same capability and same argument digest (§5.3).
    pub fn redeem(
        &mut self,
        token: &Approval,
        expected: &BoundCall,
        now: Duration,
    ) -> Result<Redeemed, ApprovalRefused> {
        if token.run != self.run {
            return Err(ApprovalRefused::WrongRun {
                found: token.run.clone(),
                expected: self.run.clone(),
            });
        }
        let want = mac_over(&self.key.0, token);
        if !mac_eq(&token.mac, &want) {
            return Err(ApprovalRefused::Forged);
        }
        if now >= token.expires_at {
            return Err(ApprovalRefused::Expired);
        }
        if token.attempt != expected.attempt {
            return Err(ApprovalRefused::AttemptMismatch {
                found: token.attempt,
                expected: expected.attempt,
            });
        }
        if token.step != expected.step {
            return Err(ApprovalRefused::StepMismatch {
                found: token.step,
                expected: expected.step,
            });
        }
        if token.capability != expected.capability {
            return Err(ApprovalRefused::CapabilityMismatch {
                found: token.capability.clone(),
                expected: expected.capability.clone(),
            });
        }
        if token.args_sha256 != expected.args_sha256 {
            return Err(ApprovalRefused::ArgsMismatch);
        }
        if token.tier != expected.tier {
            return Err(ApprovalRefused::TierMismatch {
                found: token.tier,
                expected: expected.tier,
            });
        }
        if let Some(scope) = self.consumed.get(&token.nonce) {
            if *scope == ApprovalScope::Once {
                return Err(ApprovalRefused::NonceReused);
            }
        }
        self.consumed.insert(token.nonce, token.scope);
        Ok(Redeemed {
            run: token.run.clone(),
            attempt: token.attempt,
            step: token.step,
            capability: token.capability.clone(),
            args_sha256: token.args_sha256,
            tier: token.tier,
            scope: token.scope,
            nonce: token.nonce,
        })
    }

    /// Every consumed nonce with its scope, in nonce order, for the
    /// driver to journal (§5.3: consumed nonces are journaled so reuse is
    /// detectable in replay, INV-16).
    pub fn consumed_nonces(&self) -> impl Iterator<Item = ([u8; 16], ApprovalScope)> + '_ {
        self.consumed.iter().map(|(n, s)| (*n, *s))
    }
}

// ---------------------------------------------------------------------------
// What the approver sees (§5.3): capability summary, effective class in
// plain words, rendered escaped arguments, the step.
// ---------------------------------------------------------------------------

/// The §5.3 approval request shown to the approver. Built by the run
/// driver at an `Ask`; rendering is plain words plus escaped JSON, never
/// raw model output.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalRequest {
    attempt: u32,
    step: StepId,
    capability: CapId,
    summary: String,
    class: EffectiveClass,
    args: Value,
    tier: Confirmation,
}

/// How much of the rendered arguments an approval request shows, in
/// characters. Past it the request says how much was left out and the
/// SHA-256 of the whole call (the digest the token binds).
pub const APPROVAL_ARGS_SHOWN: usize = 4000;

impl ApprovalRequest {
    /// The request for one asked call: its capability (with the manifest
    /// summary), its effective class, its arguments, the tier the decision
    /// asked at (an `Ask`'s own tier: a rule may ask above the class's
    /// declared confirmation, as the built-in edits' default does, H2b), at
    /// one step of one attempt.
    pub fn new(
        capability: CapId,
        summary: String,
        class: EffectiveClass,
        args: Value,
        tier: Confirmation,
        attempt: u32,
        step: StepId,
    ) -> Self {
        Self {
            attempt,
            step,
            capability,
            summary,
            class,
            args,
            tier,
        }
    }

    /// The capability being asked about.
    pub fn capability(&self) -> &CapId {
        &self.capability
    }

    /// The step the call belongs to.
    pub fn step(&self) -> StepId {
        self.step
    }

    /// The confirmation tier being asked.
    pub fn tier(&self) -> Confirmation {
        self.tier
    }
}

impl fmt::Display for ApprovalRequest {
    /// Plain words (§5.3): what is being called, its effective class in
    /// words a human can weigh, and the arguments as JSON, escaped for a
    /// terminal (§7.1 display paths: control, bidi and zero-width
    /// characters become `\u{HEX}`, so model-chosen arguments cannot
    /// redraw or reorder what the approver reads) and bounded to
    /// [`APPROVAL_ARGS_SHOWN`] characters.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = &self.class;
        writeln!(f, "approval needed: {} — {}", self.capability, self.summary)?;
        writeln!(
            f,
            "{}, attempt {}: {}",
            self.step,
            self.attempt,
            self.tier.as_str()
        )?;
        writeln!(
            f,
            "class: {} effect, {}, {}, {}, {}",
            c.effect.as_str(),
            sensitivity_words(c.sensitivity),
            blast_words(c.blast_radius),
            egress_words(c.egress),
            content_words(c.content),
        )?;
        let json = serde_json::to_string(&self.args).unwrap_or_else(|_| "?".to_string());
        let total = json.chars().count();
        // §7.1 display paths, through the ONE terminal-safe escaper
        // (harness_core::display, P-04): the first APPROVAL_ARGS_SHOWN
        // characters of the call's JSON, control, bidi and zero-width
        // characters escaped, on one line. The sha256 line below still
        // names what was left out.
        let shown_chars: String = json.chars().take(APPROVAL_ARGS_SHOWN).collect();
        write!(
            f,
            "args: {}",
            harness_core::display::escape_for_terminal(
                &shown_chars,
                harness_core::display::DisplayMode::Line
            )
        )?;
        if total > APPROVAL_ARGS_SHOWN {
            let call = crate::Call {
                capability: self.capability.as_str().to_owned(),
                args: self.args.clone(),
            };
            write!(
                f,
                " … ({} more characters not shown; sha256 of the call {})",
                total - APPROVAL_ARGS_SHOWN,
                crate::canonical_call_digest(&call)
            )?;
        }
        Ok(())
    }
}

fn sensitivity_words(s: harness_manifest::Sensitivity) -> &'static str {
    match s {
        harness_manifest::Sensitivity::Public => "public data",
        harness_manifest::Sensitivity::Operational => "operational, non-personal data",
        harness_manifest::Sensitivity::Personal => "personal data",
        harness_manifest::Sensitivity::Restricted => "restricted (life-data) class",
    }
}

fn blast_words(b: harness_manifest::BlastRadius) -> &'static str {
    match b {
        harness_manifest::BlastRadius::Own => "the provider's own state",
        harness_manifest::BlastRadius::Host => "this host's state",
        harness_manifest::BlastRadius::Shared => "state other people or machines rely on",
    }
}

fn egress_words(e: harness_manifest::Egress) -> &'static str {
    match e {
        harness_manifest::Egress::None => "no network egress",
        harness_manifest::Egress::Lan => "local-network egress",
        harness_manifest::Egress::Internet => "internet egress",
    }
}

fn content_words(c: harness_manifest::Content) -> &'static str {
    match c {
        harness_manifest::Content::Own => "own content",
        harness_manifest::Content::ThirdParty => "can carry third-party text",
    }
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 over the domain-separated canonical binding, on top of the
// ONE digest function (harness_core::sha256, §1.4). Hand-rolled because the
// purity allowlist admits exactly one SHA-2 crate and no HMAC crate: plain
// HMAC (RFC 2104), ipad 0x36 / opad 0x5c, block 64.
// ---------------------------------------------------------------------------

fn tier_byte(t: Confirmation) -> u8 {
    match t {
        Confirmation::None => 0,
        Confirmation::UserConfirm => 1,
        Confirmation::ProtectedAction => 2,
    }
}

fn scope_byte(s: ApprovalScope) -> u8 {
    match s {
        ApprovalScope::Once => 0,
        ApprovalScope::Run => 1,
    }
}

/// Append `b` length-prefixed (u64 LE), so no two field sequences can
/// collide.
fn put(m: &mut Vec<u8>, b: &[u8]) {
    m.extend_from_slice(&u64::try_from(b.len()).unwrap_or(u64::MAX).to_le_bytes());
    m.extend_from_slice(b);
}

/// The canonical MAC input for one approval binding (§5.3): the domain
/// tag, then every bound field, length-prefixed or fixed-width, so
/// changing ANY field (run, attempt, step, capability, argument digest,
/// tier, expiry, nonce, approver, scope) breaks the MAC.
fn mac_over(key: &[u8; 32], t: &Approval) -> [u8; 32] {
    let mut m = Vec::new();
    put(&mut m, DOMAIN);
    put(&mut m, t.run.as_str().as_bytes());
    m.extend_from_slice(&t.attempt.to_le_bytes());
    m.extend_from_slice(&t.step.get().to_le_bytes());
    put(&mut m, t.capability.as_str().as_bytes());
    m.extend_from_slice(t.args_sha256.as_bytes());
    m.push(tier_byte(t.tier));
    m.extend_from_slice(&t.expires_at.as_secs().to_le_bytes());
    m.extend_from_slice(&t.expires_at.subsec_nanos().to_le_bytes());
    m.extend_from_slice(&t.nonce);
    put(&mut m, t.approver.as_str().as_bytes());
    m.push(scope_byte(t.scope));
    hmac_sha256(key, &m)
}

/// Compare two MACs in time independent of where they first differ:
/// every byte is examined, so the comparison leaks nothing about how
/// much of a guessed MAC was right.
fn mac_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// HMAC-SHA256 (RFC 2104/4231) over `message`, built only on
/// `harness_core::sha256`.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let d = sha256(key);
        k.copy_from_slice(d.as_bytes());
    } else {
        for (slot, b) in k.iter_mut().zip(key.iter()) {
            *slot = *b;
        }
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for ((i, o), b) in ipad.iter_mut().zip(opad.iter_mut()).zip(k.iter()) {
        *i ^= *b;
        *o ^= *b;
    }
    let mut inner = Vec::with_capacity(BLOCK + message.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(message);
    let inner_digest = sha256(&inner);
    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(inner_digest.as_bytes());
    let out = sha256(&outer);
    let mut mac = [0u8; 32];
    mac.copy_from_slice(out.as_bytes());
    mac
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run() -> RunId {
        RunId::new(1_000, [3; 10])
    }

    fn authority() -> ApprovalAuthority {
        ApprovalAuthority::new(run(), [0x11; 32])
    }

    fn approver() -> PrincipalId {
        PrincipalId::new("cli-prompt").unwrap()
    }

    fn ask_call() -> crate::Call {
        crate::Call {
            capability: "fixture.p".into(),
            args: json!({"path": "a"}),
        }
    }

    fn bound(tier: Confirmation) -> BoundCall {
        BoundCall::for_call(1, StepId::new(3), &ask_call(), tier).unwrap()
    }

    fn mint_once(a: &mut ApprovalAuthority, nonce: [u8; 16], now: Duration) -> Approval {
        let b = bound(Confirmation::UserConfirm);
        let req = MintRequest {
            attempt: b.attempt,
            step: b.step,
            capability: b.capability.clone(),
            args_sha256: b.args_sha256,
            tier: b.tier,
            scope: ApprovalScope::Once,
            approver: approver(),
        };
        a.mint(&req, nonce, now).unwrap()
    }

    // The MAC primitive itself, against the RFC 4231 test vectors (so the
    // hand-rolled HMAC is not merely self-consistent).
    #[test]
    fn hmac_matches_the_rfc4231_vectors() {
        let key1 = [0x0bu8; 20];
        assert_eq!(
            hex(&hmac_sha256(&key1, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // INV-16: flip one byte of each bound field — run, attempt, step,
    // capability, argument digest, tier, expiry, nonce, approver, scope,
    // mac — and every one is refused.
    #[test]
    fn inv_16_one_flipped_byte_in_any_field_refuses_the_token() {
        let mut a = authority();
        let t = mint_once(&mut a, [0x22; 16], Duration::from_secs(1_000));
        let b = bound(Confirmation::UserConfirm);
        let other_run = RunId::new(9_999, [3; 10]);
        type Flip = Box<dyn Fn(&mut Approval)>;
        let cases: Vec<(&str, Flip)> = vec![
            (
                "run",
                Box::new(move |t: &mut Approval| t.run = other_run.clone()),
            ),
            ("attempt", Box::new(|t: &mut Approval| t.attempt ^= 1)),
            (
                "step",
                Box::new(|t: &mut Approval| t.step = StepId::new(t.step.get() + 1)),
            ),
            (
                "capability",
                Box::new(|t: &mut Approval| {
                    t.capability = CapId::new("fixture.q").unwrap();
                }),
            ),
            (
                "args_sha256",
                Box::new(|t: &mut Approval| {
                    let mut d = *t.args_sha256.as_bytes();
                    d[0] ^= 1;
                    t.args_sha256 = Digest::from_bytes(d);
                }),
            ),
            (
                "tier",
                Box::new(|t: &mut Approval| t.tier = Confirmation::ProtectedAction),
            ),
            (
                "expires_at",
                Box::new(|t: &mut Approval| {
                    t.expires_at += Duration::from_nanos(1);
                }),
            ),
            ("nonce", Box::new(|t: &mut Approval| t.nonce[0] ^= 1)),
            (
                "approver",
                Box::new(|t: &mut Approval| {
                    t.approver = PrincipalId::new("other-approver").unwrap();
                }),
            ),
            (
                "scope",
                Box::new(|t: &mut Approval| t.scope = ApprovalScope::Run),
            ),
            ("mac", Box::new(|t: &mut Approval| t.mac[0] ^= 1)),
        ];
        for (name, flip) in cases {
            let mut forged = t.clone();
            flip(&mut forged);
            let err = a
                .redeem(&forged, &b, Duration::from_secs(1_100))
                .unwrap_err();
            let expected = if name == "run" {
                ApprovalRefused::WrongRun {
                    found: forged.run.clone(),
                    expected: run(),
                }
            } else {
                ApprovalRefused::Forged
            };
            assert_eq!(err, expected, "{name}");
        }
        // The untouched token still redeems: the refusals were the flips.
        assert!(a.redeem(&t, &b, Duration::from_secs(1_100)).is_ok());
    }

    // INV-16: a consumed nonce is dead.
    #[test]
    fn inv_16_replaying_a_consumed_nonce_is_refused() {
        let mut a = authority();
        let t = mint_once(&mut a, [0x33; 16], Duration::from_secs(1_000));
        let b = bound(Confirmation::UserConfirm);
        let redeemed = a.redeem(&t, &b, Duration::from_secs(1_000)).unwrap();
        assert_eq!(redeemed.nonce(), [0x33; 16]);
        assert_eq!(
            a.redeem(&t, &b, Duration::from_secs(1_001)),
            Err(ApprovalRefused::NonceReused)
        );
        // The consumption is visible for the journal (§5.3).
        assert_eq!(
            a.consumed_nonces().collect::<Vec<_>>(),
            vec![([0x33; 16], ApprovalScope::Once)]
        );
        // And a fresh mint cannot reuse the nonce either.
        assert_eq!(
            mint_once_result(&mut a, [0x33; 16]),
            Err(MintRefused::NonceTaken)
        );
    }

    fn mint_once_result(
        a: &mut ApprovalAuthority,
        nonce: [u8; 16],
    ) -> Result<Approval, MintRefused> {
        let b = bound(Confirmation::UserConfirm);
        let req = MintRequest {
            attempt: b.attempt,
            step: b.step,
            capability: b.capability.clone(),
            args_sha256: b.args_sha256,
            tier: b.tier,
            scope: ApprovalScope::Once,
            approver: approver(),
        };
        a.mint(&req, nonce, Duration::from_secs(1_000))
    }

    // INV-16: a token minted under another run's key never verifies —
    // not even under an authority for the same run id with a fresh key.
    #[test]
    fn inv_16_a_token_from_another_run_is_refused() {
        let mut a = authority();
        let t = mint_once(&mut a, [0x44; 16], Duration::from_secs(1_000));
        let b = bound(Confirmation::UserConfirm);
        // Another run, another key.
        let mut other = ApprovalAuthority::new(RunId::new(2_000, [4; 10]), [0x55; 32]);
        assert_eq!(
            other.redeem(&t, &b, Duration::from_secs(1_100)),
            Err(ApprovalRefused::WrongRun {
                found: t.run().clone(),
                expected: other.run().clone(),
            })
        );
        // Same run id, fresh key (a restart): the MAC cannot verify.
        let mut restart = ApprovalAuthority::new(run(), [0x66; 32]);
        assert_eq!(
            restart.redeem(&t, &b, Duration::from_secs(1_100)),
            Err(ApprovalRefused::Forged)
        );
    }

    // §5.3 TTL: alive one nanosecond before the boundary, dead on it.
    #[test]
    fn ttl_expires_exactly_at_fifteen_minutes() {
        let t0 = Duration::from_secs(10_000);
        let mut a = authority();
        let t = mint_once(&mut a, [0x77; 16], t0);
        assert_eq!(t.expires_at(), t0 + APPROVAL_TTL);
        let b = bound(Confirmation::UserConfirm);
        assert!(a
            .redeem(&t, &b, t0 + APPROVAL_TTL - Duration::from_nanos(1))
            .is_ok());
        assert_eq!(
            a.redeem(&t, &b, t0 + APPROVAL_TTL),
            Err(ApprovalRefused::Expired)
        );
    }

    // §5.3: a user_confirm approval may be run-scoped "for identical calls
    // in this run" — same capability and same arg digest ONLY.
    #[test]
    fn run_scope_redeems_identical_calls_only() {
        let mut a = authority();
        let b = bound(Confirmation::UserConfirm);
        let req = MintRequest {
            attempt: b.attempt,
            step: b.step,
            capability: b.capability.clone(),
            args_sha256: b.args_sha256,
            tier: b.tier,
            scope: ApprovalScope::Run,
            approver: approver(),
        };
        let t = a
            .mint(&req, [0x88; 16], Duration::from_secs(1_000))
            .unwrap();
        assert!(a.redeem(&t, &b, Duration::from_secs(1_000)).is_ok());
        // Identical binding: redeems again within the TTL.
        assert!(a.redeem(&t, &b, Duration::from_secs(1_001)).is_ok());
        // Different arguments (or step, or tier): refused.
        let other_call = crate::Call {
            capability: "fixture.p".into(),
            args: json!({"path": "b"}),
        };
        let other =
            BoundCall::for_call(1, StepId::new(3), &other_call, Confirmation::UserConfirm).unwrap();
        assert_eq!(
            a.redeem(&t, &other, Duration::from_secs(1_002)),
            Err(ApprovalRefused::ArgsMismatch)
        );
        let stepped =
            BoundCall::for_call(1, StepId::new(4), &ask_call(), Confirmation::UserConfirm).unwrap();
        assert!(matches!(
            a.redeem(&t, &stepped, Duration::from_secs(1_003)),
            Err(ApprovalRefused::StepMismatch { .. })
        ));
        let tiered = BoundCall::for_call(
            1,
            StepId::new(3),
            &ask_call(),
            Confirmation::ProtectedAction,
        )
        .unwrap();
        assert!(matches!(
            a.redeem(&t, &tiered, Duration::from_secs(1_004)),
            Err(ApprovalRefused::TierMismatch { .. })
        ));
    }

    // §5.3: protected_action is single-use, and nothing below
    // user_confirm ever asked.
    #[test]
    fn mint_refuses_impossible_tiers_and_scopes() {
        let mut a = authority();
        let b = bound(Confirmation::UserConfirm);
        let req = MintRequest {
            attempt: b.attempt,
            step: b.step,
            capability: b.capability.clone(),
            args_sha256: b.args_sha256,
            tier: Confirmation::None,
            scope: ApprovalScope::Once,
            approver: approver(),
        };
        assert_eq!(
            a.mint(&req, [0x99; 16], Duration::from_secs(1_000)),
            Err(MintRefused::TierBelowFloor(Confirmation::None))
        );
        let req = MintRequest {
            attempt: b.attempt,
            step: b.step,
            capability: b.capability.clone(),
            args_sha256: b.args_sha256,
            tier: Confirmation::ProtectedAction,
            scope: ApprovalScope::Run,
            approver: approver(),
        };
        assert_eq!(
            a.mint(&req, [0x9a; 16], Duration::from_secs(1_000)),
            Err(MintRefused::ProtectedActionMustBeOnce)
        );
    }

    // The mismatch taxonomy (everything redeem checks besides MAC/expiry).
    #[test]
    fn redeem_names_the_binding_that_did_not_match() {
        let mut a = authority();
        let t = mint_once(&mut a, [0xab; 16], Duration::from_secs(1_000));
        let wrong_attempt = BoundCall {
            attempt: 2,
            ..bound(Confirmation::UserConfirm)
        };
        assert!(matches!(
            a.redeem(&t, &wrong_attempt, Duration::from_secs(1_000)),
            Err(ApprovalRefused::AttemptMismatch { .. })
        ));
        let wrong_cap = BoundCall {
            capability: CapId::new("fixture.q").unwrap(),
            ..bound(Confirmation::UserConfirm)
        };
        assert!(matches!(
            a.redeem(&t, &wrong_cap, Duration::from_secs(1_000)),
            Err(ApprovalRefused::CapabilityMismatch { .. })
        ));
    }

    // The approver id follows the journal identifier grammar.
    #[test]
    fn principal_ids_follow_the_journal_grammar() {
        assert!(PrincipalId::new("cli").is_ok());
        assert!(PrincipalId::new("user_01.host-a").is_ok());
        for bad in [
            "",
            ".hidden",
            "-rf",
            "has space",
            "ütf",
            "a@b",
            &"x".repeat(129),
        ] {
            assert!(PrincipalId::new(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            PrincipalId::new(&"x".repeat(128)).unwrap().as_str().len(),
            128
        );
    }

    // §5.3: the request renders plain words and escaped arguments.
    #[test]
    fn approval_request_renders_plain_words_and_escaped_args() {
        let cap = m_cap();
        let class = crate::effective_class(&cap, Confirmation::None);
        let req = ApprovalRequest::new(
            cap.id().clone(),
            "reads personal files".into(),
            class,
            json!({"path": "a", "note": "line\nbreak"}),
            Confirmation::UserConfirm,
            1,
            StepId::new(3),
        );
        let shown = req.to_string();
        assert!(shown.contains("fixture.p"), "{shown}");
        assert!(shown.contains("personal data"), "{shown}");
        assert!(shown.contains("user_confirm"), "{shown}");
        // Escaped args: the embedded newline in `note` appears as the
        // two-character escape `\n`, never as a raw control character.
        assert!(shown.contains("\\n"), "{shown}");
        assert_eq!(
            shown.matches('\n').count(),
            3,
            "only the three writeln line breaks"
        );
    }

    // P-04: the args render through the ONE terminal-safe escaper
    // (harness_core::display) instead of the manifest's display_safe.
    // Golden: the request is unchanged (on this input the two escapers
    // agree byte for byte), and nothing raw survives.
    #[test]
    fn approval_request_display_unchanged() {
        let cap = m_cap();
        let class = crate::effective_class(&cap, Confirmation::None);
        let args = json!({
            "path": "notes.txt",
            "note": "line\nbreak",
            "motive": "\u{1b}[31mred\u{202e}pinned.exe\u{200b}"
        });
        let req = ApprovalRequest::new(
            cap.id().clone(),
            "reads personal files".into(),
            class,
            args.clone(),
            Confirmation::UserConfirm,
            1,
            StepId::new(3),
        );
        let shown = req.to_string();
        // Golden, pinned line for line.
        #[rustfmt::skip]
        let expected = r#"approval needed: fixture.p — reads personal files
step 3, attempt 1: user_confirm
class: read effect, personal data, the provider's own state, no network egress, own content
args: {"motive":"\\u001b[31mred\u{202E}pinned.exe\u{200B}","note":"line\\nbreak","path":"notes.txt"}"#;
        assert_eq!(shown, expected);
        // The escapes are the ones the old escaper produced (the journal
        // and JSON spellings still double; the raw bidi and zero-width
        // characters JSON leaves are `\u{HEX}`-escaped).
        let json = serde_json::to_string(&args).unwrap_or_default();
        let taken: String = json.chars().take(APPROVAL_ARGS_SHOWN).collect();
        let args_at = shown.rfind("args: ").unwrap() + "args: ".len();
        assert_eq!(
            &shown[args_at..],
            harness_manifest::display_safe(&taken, APPROVAL_ARGS_SHOWN),
        );
        // Terminal-safe: no raw control, bidi or zero-width character in
        // the args (the three writeln line breaks are the request's own).
        assert!(
            !shown.chars().any(|c| {
                c != '\n'
                    && (c.is_control()
                        || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'))
            }),
            "{shown:?}"
        );
    }

    fn m_cap() -> harness_manifest::Capability {
        let m = serde_json::json!({
            "id": "fixture.p",
            "mcp_name": "p",
            "summary": "fixture capability",
            "effect": "read", "sensitivity": "personal", "blast_radius": "own",
            "egress": "none", "content": "own", "confirmation": "none",
            "input_schema": {"type": "object", "additionalProperties": false, "properties": {}},
            "schema_sha256": "0".repeat(64),
            "description_sha256": "0".repeat(64)
        });
        let doc = serde_json::json!({
            "schema_version": 1, "provider": "fixture", "provider_version": "1",
            "min_harness": "0.0.1",
            "transport": {"kind": "mcp-stdio", "argv": ["/opt/fixture/server"], "env_allow": []},
            "mcp_protocols": ["2025-06-18"],
            "capabilities": [m]
        });
        harness_manifest::Manifest::parse(
            doc.to_string().as_bytes(),
            &harness_manifest::ValidationContext::new(
                harness_manifest::SemVer {
                    major: 0,
                    minor: 0,
                    patch: 1,
                },
                &[],
            )
            .unwrap(),
        )
        .unwrap()
        .capabilities()[0]
            .clone()
    }
}
