//! The ONE gate-layer outcome type for rustyharness.
//!
//! This crate is deliberately std-only and dependency-free on default
//! features: it is the bottom of the crate lattice (design `docs/01-design-v0.1.md`
//! §1.2). Everything here is pure: no I/O, no threads, no clock reads, no
//! global state.
//!
//! Core shapes (UNIFIED gate-outcome v0.3 §2-§6, vocabulary v0.1 §2-§4):
//!
//! - [`GateOutcome`] — `Passed(Witness)` / `Failed` / `Indeterminate { why }`.
//! - [`GateReport`] — gate id + outcome + findings + coverage + scope.
//! - [`verdict`] — total, worst-wins reduction over reports.
//! - [`Check`] / [`run_checked`] — the ONLY mint of a [`Witness`].
//! - [`child`] — the §6 child-run protocol (`ChildRun`, `ExitKind`, `interpret`).
//!
//! Non-negotiable laws implemented here:
//!
//! - INV-4: `Witness` (and therefore `Passed`) cannot be constructed outside
//!   this crate. It is minted only by [`run_checked`] and by the §6 child
//!   protocol in [`child`], and never parsed back from bytes (no
//!   `Deserialize` is implemented for `Witness` or [`GateOutcome`]). A
//!   [`GateReport`] has private fields, and the public [`GateReport::new`]
//!   refuses `Passed`, so a minted witness cannot be moved onto another
//!   report either.
//! - INV-18: zero examined items can never yield `Passed` through
//!   [`run_checked`] or a §6.1 protocol report; it yields `Indeterminate`
//!   with [`IndeterminateKind::NothingChecked`]. (The §6.2 exit-code
//!   convention is the one pass that counts no items: see
//!   [`Witness::checked`].)
//! - A `Failed` report carries at least one `Severity::Blocking` finding;
//!   `Passed` carries none and has `Coverage::Full`. Construction enforces
//!   this, and [`verdict`] re-checks it on every report: an unlawful report
//!   counts as `Indeterminate { UnreadableEvidence }`, never as itself.
//! - `Failed` dominates `Indeterminate` in [`verdict`]: a refutation is
//!   knowledge an `Indeterminate` cannot erase.
//!
//! The crate NEVER hashes. A [`Digest`] is an opaque 32-byte claim handed in
//! by harness code; producing one is `harness_core::sha256`'s
//! responsibility, not this crate's.

#![forbid(unsafe_code)]
// The panic-set lints ratchet production code; unit tests may assert loosely.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

use std::fmt;

/// Identity of the gate that produced a report (vocabulary §2).
///
/// Content-checked at construction (and therefore on the wire too): an id
/// is non-empty and contains no whitespace and no control character. An
/// empty id would let the marker content `"ok "` name it, and a trailing
/// `\r` in an id would let a CRLF marker line match it (design §7.3,
/// "Marker content"); both are refused here rather than special-cased in
/// the marker matcher. The string is otherwise opaque to this crate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "json",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "String", into = "String")
)]
pub struct GateId(String);

impl GateId {
    /// Names a gate. Refuses an empty id and any id containing whitespace
    /// or a control character.
    pub fn new(id: impl Into<String>) -> Result<Self, GateIdError> {
        let id = id.into();
        if id.is_empty() {
            return Err(GateIdError::Empty);
        }
        if let Some((at, _)) = id
            .char_indices()
            .find(|(_, c)| c.is_whitespace() || c.is_control())
        {
            return Err(GateIdError::ForbiddenChar { at });
        }
        Ok(Self(id))
    }

    /// Borrows the gate name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for GateId {
    type Error = GateIdError;

    fn try_from(id: String) -> Result<Self, Self::Error> {
        Self::new(id)
    }
}

impl From<GateId> for String {
    fn from(id: GateId) -> Self {
        id.0
    }
}

/// Why a gate id was refused at construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateIdError {
    /// The id is the empty string.
    Empty,
    /// The id contains whitespace or a control character.
    ForbiddenChar {
        /// Byte offset of the first offending character.
        at: usize,
    },
}

impl fmt::Display for GateIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("gate id is empty"),
            Self::ForbiddenChar { at } => write!(
                f,
                "gate id contains whitespace or a control character at byte {at}"
            ),
        }
    }
}

impl std::error::Error for GateIdError {}

/// Opaque 32-byte content claim.
///
/// This crate never computes a digest: it transports one. `Debug` and
/// `Display` render lowercase hex so journal output stays greppable without
/// ever widening the type back to raw bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "json",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "String", into = "String")
)]
pub struct Digest([u8; 32]);

impl Digest {
    /// Wraps 32 raw bytes. The caller owns the claim that they are a digest
    /// of something.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({self})")
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl From<Digest> for String {
    fn from(d: Digest) -> Self {
        let mut s = String::with_capacity(64);
        for byte in d.0 {
            s.push_str(&format!("{byte:02x}"));
        }
        s
    }
}

impl std::str::FromStr for Digest {
    type Err = DigestParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();
        if bytes.len() != 64 {
            return Err(DigestParseError::BadLength { got: bytes.len() });
        }
        let mut out = [0u8; 32];
        for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
            let (hi, lo) = match pair {
                [hi, lo] => (*hi, *lo),
                // Unreachable: `bytes.len() == 64` was checked above, so
                // chunks_exact(2) always yields full pairs.
                _ => return Err(DigestParseError::BadHex),
            };
            let hi = hex_val(hi).ok_or(DigestParseError::BadHex)?;
            let lo = hex_val(lo).ok_or(DigestParseError::BadHex)?;
            *slot = (hi << 4) | lo;
        }
        Ok(Self(out))
    }
}

/// A hex string was not a 64-char SHA-256 rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestParseError {
    /// Wrong number of characters.
    BadLength {
        /// How many characters were supplied.
        got: usize,
    },
    /// A character was not a hex digit.
    BadHex,
}

impl fmt::Display for DigestParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength { got } => write!(f, "digest hex must be 64 chars, got {got}"),
            Self::BadHex => f.write_str("digest hex contains a non-hex character"),
        }
    }
}

impl std::error::Error for DigestParseError {}

impl TryFrom<String> for Digest {
    type Error = DigestParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Rank of a finding (vocabulary §3): declaration order IS severity order.
///
/// `Blocking` refutes; everything else is advisory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "json", derive(serde::Serialize, serde::Deserialize))]
pub enum Severity {
    /// Informational.
    Info,
    /// Worth noting, harmless.
    Low,
    /// Should be fixed, does not refute.
    Medium,
    /// Serious; still advisory, so it cannot fail a gate alone.
    High,
    /// Refutes. The ONLY severity that can back a `Failed` outcome.
    Blocking,
}

/// Open-ended reason code (UNIFIED §4): a closed taxonomy would force the
/// gate author to lie, so codes are strings under a newtype.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "json", derive(serde::Serialize, serde::Deserialize))]
pub struct FindingCode(pub String);

/// One observation that deviates from expectation (vocabulary §3).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "json",
    derive(serde::Serialize, serde::Deserialize),
    serde(deny_unknown_fields)
)]
pub struct Finding {
    /// How bad this is.
    pub severity: Severity,
    /// Open reason code.
    pub code: FindingCode,
    /// Where the deviation was seen (path, step, rule...).
    pub location: String,
    /// What the gate expected.
    pub expected: String,
    /// What was actually seen. EMPTY IS NOT LEGAL: a check that can only
    /// assert presence produces `Indeterminate`, never a Finding.
    pub observed: String,
}

/// `Finding::new` was handed an empty `observed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindingError;

impl fmt::Display for FindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("finding observed-text must be non-empty (vocabulary §3)")
    }
}

impl std::error::Error for FindingError {}

impl Finding {
    /// Constructs a finding, refusing an empty `observed` (fail-closed).
    pub fn new(
        severity: Severity,
        code: FindingCode,
        location: impl Into<String>,
        expected: impl Into<String>,
        observed: impl Into<String>,
    ) -> Result<Self, FindingError> {
        let observed = observed.into();
        if observed.is_empty() {
            return Err(FindingError);
        }
        Ok(Self {
            severity,
            code,
            location: location.into(),
            expected: expected.into(),
            observed,
        })
    }

    /// Internal constructor for call sites where non-emptiness holds by
    /// construction (literals, formatting that embeds runtime data). The
    /// public path is `Finding::new`, which enforces the law.
    fn literal(
        severity: Severity,
        code: &str,
        location: String,
        expected: &str,
        observed: String,
    ) -> Self {
        Self {
            severity,
            code: FindingCode(code.to_string()),
            location,
            expected: expected.to_string(),
            observed,
        }
    }
}

/// Why part of the checked universe was not examined (vocabulary §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "json", derive(serde::Serialize, serde::Deserialize))]
pub enum UnreadReason {
    /// Evidence could not be parsed.
    ParseFailure,
    /// The input could not be reached at all.
    UnreachableInput,
    /// The gate's own manifest excluded it.
    DeclaredExclusion,
    /// The tool that would have read it is broken.
    ToolDefect,
}

/// A declared, typed gap in coverage (vocabulary §3).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "json",
    derive(serde::Serialize, serde::Deserialize),
    serde(deny_unknown_fields)
)]
pub struct Unread {
    /// Name of the universe that was partially unread (e.g. "workspace files").
    pub universe: String,
    /// Why it was not read.
    pub why: UnreadReason,
    /// Human-readable detail; never empty in practice, not policed here.
    pub detail: String,
}

/// How much of the gate's universe was actually examined (vocabulary §3).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "json",
    derive(serde::Serialize, serde::Deserialize),
    serde(deny_unknown_fields)
)]
pub enum Coverage {
    /// Everything the manifest declared was examined.
    Full,
    /// Part was not, and why. Caps a verdict at `Indeterminate`.
    Partial {
        /// The typed gap.
        unread: Unread,
    },
}

/// One declared exclusion from a gate's scope (UNIFIED §2 `Scope`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "json",
    derive(serde::Serialize, serde::Deserialize),
    serde(deny_unknown_fields)
)]
pub struct Exclusion {
    /// Pattern describing the excluded slice (glob or path prefix).
    pub glob: String,
    /// Why it is excluded.
    pub why: UnreadReason,
    /// Human-readable detail.
    pub detail: String,
}

/// What the gate chose to look at, not look at, and pin against (UNIFIED §2).
///
/// No `Default`: a scope is always an explicit decision.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "json",
    derive(serde::Serialize, serde::Deserialize),
    serde(deny_unknown_fields)
)]
pub struct Scope {
    /// What was examined.
    pub examined: Vec<String>,
    /// What was declaredly excluded.
    pub excluded: Vec<Exclusion>,
    /// Optional pin (commit/tree digest as opaque hex) the gate measured against.
    pub pin: Option<String>,
}

impl Scope {
    /// The empty scope: nothing examined, nothing excluded, nothing pinned.
    /// Explicit, because `Default` is forbidden for scopes.
    pub fn empty() -> Self {
        Self {
            examined: Vec::new(),
            excluded: Vec::new(),
            pin: None,
        }
    }
}

/// Proof that a gate ran and what it read (UNIFIED §5).
///
/// The fields are PRIVATE on purpose (choke point): the only constructors
/// are in this crate, reachable from [`run_checked`] and the [`child`]
/// protocol module — never from user code, never from bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Witness {
    /// How many items were examined. Private: the number is only meaningful
    /// alongside the constructor that vouches for it.
    checked: usize,
    /// Digest over the examined set (set-digest or child capture).
    digest: Digest,
}

impl Witness {
    /// The single mint inside this crate, used by `run_checked` and the §6
    /// child protocol.
    pub(crate) fn from_run_checked(checked: usize, digest: Digest) -> Self {
        Self { checked, digest }
    }

    /// How many items this witness vouches for.
    ///
    /// Always `> 0` for a witness minted by [`run_checked`] or by a §6.1
    /// protocol report. It is `0` for exactly one kind of pass: the §6.2
    /// legacy exit-code convention (exit 0 plus the `ok <gate-id>` marker),
    /// which vouches for the child's captured output ([`Witness::digest`])
    /// and not for an item count. A consumer that needs an item count must
    /// treat `0` as "legacy exit-convention pass".
    pub fn checked(&self) -> usize {
        self.checked
    }

    /// The digest this witness vouches for.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

impl fmt::Debug for Witness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Witness")
            .field("checked", &self.checked)
            .field("digest", &self.digest)
            .finish()
    }
}

impl fmt::Display for Witness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} items, {}", self.checked, self.digest)
    }
}

#[cfg(feature = "json")]
impl serde::Serialize for Witness {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        let mut s = serializer.serialize_struct("Witness", 2)?;
        s.serialize_field("checked", &self.checked)?;
        s.serialize_field("digest", &String::from(self.digest))?;
        s.end()
    }
}

/// Why a run could not produce a verdict (vocabulary §2, exactly five).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "json", derive(serde::Serialize, serde::Deserialize))]
pub enum IndeterminateKind {
    /// Nothing was examined at all (INV-18).
    NothingChecked,
    /// Evidence existed but could not be read or parsed.
    UnreadableEvidence,
    /// The check itself could not run.
    CouldNotRun,
    /// This OS cannot run this gate.
    UnsupportedOs,
    /// The thing to be checked is stale relative to the pin.
    StaleBinary,
}

/// The outcome of one gate (UNIFIED §2, verbatim shape).
///
/// `Failed` carries no payload: refutations are `Severity::Blocking`
/// findings on the [`GateReport`], never data inside the variant.
///
/// INV-4: `Passed` is unconstructible outside this crate — the witness type
/// has private fields and no public constructor, so neither the variant nor
/// a witness value can be forged.
///
/// # INV-4 (compile-fail): no literal Witness construction
///
/// ```compile_fail,E0451
/// let w = gate_outcome::Witness {
///     checked: 3,
///     digest: gate_outcome::Digest::from_bytes([0u8; 32]),
/// };
/// ```
///
/// # INV-4 (compile-fail): no public Witness constructor
///
/// ```compile_fail,E0624
/// let w = gate_outcome::Witness::from_run_checked(
///     3,
///     gate_outcome::Digest::from_bytes([0u8; 32]),
/// );
/// ```
///
/// # INV-4 (compile-fail): a report's outcome cannot be replaced
///
/// A witness minted for one report cannot be transplanted onto another by
/// assignment: the report's fields are private.
///
/// ```compile_fail,E0616
/// fn transplant(mut other: gate_outcome::GateReport, good: &gate_outcome::GateReport) {
///     other.outcome = good.outcome().clone();
/// }
/// ```
#[derive(Clone, PartialEq, Eq)]
pub enum GateOutcome {
    /// The gate ran over real evidence and saw no refutation.
    Passed(Witness),
    /// The gate refuted the claim; see the report's Blocking findings.
    Failed,
    /// The gate could not produce a verdict, and says why.
    Indeterminate {
        /// The typed reason.
        why: IndeterminateKind,
    },
}

impl fmt::Debug for GateOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Passed(w) => f.debug_tuple("Passed").field(w).finish(),
            Self::Failed => f.write_str("Failed"),
            Self::Indeterminate { why } => f.debug_tuple("Indeterminate").field(why).finish(),
        }
    }
}

/// Serialized shape (the §6.1 wire form a parent reads back, see
/// [`child`]): `{"Passed":{"checked":N,"digest":"<hex>"}}`, `"Failed"`, or
/// `{"Indeterminate":{"why":"<kind>"}}`.
#[cfg(feature = "json")]
impl serde::Serialize for GateOutcome {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStructVariant;
        match self {
            Self::Passed(w) => serializer.serialize_newtype_variant("GateOutcome", 0, "Passed", w),
            Self::Failed => serializer.serialize_unit_variant("GateOutcome", 1, "Failed"),
            Self::Indeterminate { why } => {
                let mut v =
                    serializer.serialize_struct_variant("GateOutcome", 2, "Indeterminate", 1)?;
                v.serialize_field("why", why)?;
                v.end()
            }
        }
    }
}

/// Everything one gate says about one run (vocabulary §4 + UNIFIED §2).
///
/// Fields are private: a report is built by [`run_checked`], by
/// [`child::interpret`], or by [`GateReport::new`] (which refuses `Passed`),
/// and read through the getters. No code outside this crate can change a
/// report after construction.
///
/// # Compile-fail: no struct-literal reports
///
/// ```compile_fail,E0451
/// let r = gate_outcome::GateReport {
///     gate: gate_outcome::GateId::new("g").unwrap(),
///     outcome: gate_outcome::GateOutcome::Failed,
///     findings: Vec::new(),
///     coverage: gate_outcome::Coverage::Full,
///     scope: gate_outcome::Scope::empty(),
/// };
/// ```
///
/// # Compile-fail: no pushing findings onto a built report
///
/// ```compile_fail,E0616
/// fn add(r: &mut gate_outcome::GateReport, f: gate_outcome::Finding) {
///     r.findings.push(f);
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct GateReport {
    gate: GateId,
    outcome: GateOutcome,
    findings: Vec<Finding>,
    coverage: Coverage,
    scope: Scope,
}

/// A report was refused because it violates the outcome/finding laws.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateReportError {
    /// `Passed` handed to the public constructor. A passing report is minted
    /// only by [`run_checked`] or [`child::interpret`], so a witness cannot
    /// be moved from the report it was minted for onto another one.
    PassedIsMintedOnly,
    /// `Failed` without a `Severity::Blocking` finding.
    FailedWithoutBlockingFinding,
    /// `Passed` carried a `Severity::Blocking` finding.
    PassedWithBlockingFinding,
    /// `Passed` with [`Coverage::Partial`] (partial coverage caps at
    /// `Indeterminate`).
    PassedWithPartialCoverage,
}

impl fmt::Display for GateReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PassedIsMintedOnly => {
                f.write_str("Passed reports are minted only by run_checked or child::interpret")
            }
            Self::FailedWithoutBlockingFinding => {
                f.write_str("Failed requires at least one Blocking finding")
            }
            Self::PassedWithBlockingFinding => {
                f.write_str("Passed must not carry a Blocking finding")
            }
            Self::PassedWithPartialCoverage => f.write_str("Passed requires Coverage::Full"),
        }
    }
}

impl std::error::Error for GateReportError {}

impl GateReport {
    /// Public constructor for non-passing reports: enforces the report laws,
    /// fail-closed. `Passed` is always refused
    /// ([`GateReportError::PassedIsMintedOnly`]).
    pub fn new(
        gate: GateId,
        outcome: GateOutcome,
        findings: Vec<Finding>,
        coverage: Coverage,
        scope: Scope,
    ) -> Result<Self, GateReportError> {
        if matches!(outcome, GateOutcome::Passed(_)) {
            return Err(GateReportError::PassedIsMintedOnly);
        }
        let report = Self::build(gate, outcome, findings, coverage, scope);
        match report.law_violation() {
            Some(err) => Err(err),
            None => Ok(report),
        }
    }

    /// Internal unvalidated constructor. Callers in this file uphold the
    /// report laws by construction; nothing outside this file may call it,
    /// and [`verdict`] re-checks the laws anyway.
    fn build(
        gate: GateId,
        outcome: GateOutcome,
        findings: Vec<Finding>,
        coverage: Coverage,
        scope: Scope,
    ) -> Self {
        Self {
            gate,
            outcome,
            findings,
            coverage,
            scope,
        }
    }

    /// The first report law this report breaks, if any.
    fn law_violation(&self) -> Option<GateReportError> {
        let has_blocking = has_blocking(&self.findings);
        match &self.outcome {
            GateOutcome::Failed if !has_blocking => {
                Some(GateReportError::FailedWithoutBlockingFinding)
            }
            GateOutcome::Passed(_) if has_blocking => {
                Some(GateReportError::PassedWithBlockingFinding)
            }
            GateOutcome::Passed(_) if !matches!(self.coverage, Coverage::Full) => {
                Some(GateReportError::PassedWithPartialCoverage)
            }
            _ => None,
        }
    }

    /// Which gate produced this.
    pub fn gate(&self) -> &GateId {
        &self.gate
    }

    /// The outcome.
    pub fn outcome(&self) -> &GateOutcome {
        &self.outcome
    }

    /// Findings. May be non-empty on `Passed` (advisory findings). A `Failed`
    /// report carries at least one `Severity::Blocking` finding.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Coverage is REQUIRED: a report without a coverage decision is not a
    /// report (no `Option`, no `Default`).
    pub fn coverage(&self) -> &Coverage {
        &self.coverage
    }

    /// Scope: examined / excluded / pin.
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
}

fn has_blocking(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.severity == Severity::Blocking)
}

/// What a [`Check`] saw when it examined its input (design §1.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Examination {
    /// Digests of the items actually examined, in examination order.
    pub items: Vec<Digest>,
    /// Digest over the examined set as a whole (fold/merkle/canonical
    /// concatenation — the check's choice; this crate never re-derives it).
    pub set_digest: Digest,
    /// Findings observed during examination.
    pub findings: Vec<Finding>,
    /// Coverage the check actually achieved.
    pub coverage: Coverage,
    /// Scope the check operated over.
    pub scope: Scope,
}

/// A pure, side-effect-free gate (design §1.4).
pub trait Check {
    /// The input this check examines.
    type Input;

    /// Which gate this is (named so a report can be attributed without
    /// stringly typing the caller).
    fn gate(&self) -> GateId;

    /// Examine one input and report what was seen. No I/O, no clock, no
    /// globals: everything observed comes back in the `Examination`.
    fn examine(&self, input: &Self::Input) -> Examination;
}

/// The ONLY way harness code mints a `Passed` witness from a `Check`
/// (design §1.4, UNIFIED §5).
///
/// Derives the outcome from the examination: any Blocking finding →
/// `Failed` (a refutation is kept even when nothing else was counted); zero
/// examined items → `Indeterminate::NothingChecked` (INV-18); partial
/// coverage → capped `Indeterminate`; otherwise `Passed` with a witness
/// minted here and nowhere else.
pub fn run_checked<C: Check>(check: &C, input: &C::Input) -> GateReport {
    let exam = check.examine(input);
    let examined = exam.items.len();
    let witness = Witness::from_run_checked(examined, exam.set_digest);
    let outcome = derive_outcome(examined, &exam.findings, &exam.coverage, witness);
    GateReport::build(
        check.gate(),
        outcome,
        exam.findings,
        exam.coverage,
        exam.scope,
    )
}

/// Outcome derivation for `run_checked`.
fn derive_outcome(
    examined: usize,
    findings: &[Finding],
    coverage: &Coverage,
    witness: Witness,
) -> GateOutcome {
    if has_blocking(findings) {
        return GateOutcome::Failed;
    }
    if examined == 0 {
        return GateOutcome::Indeterminate {
            why: IndeterminateKind::NothingChecked,
        };
    }
    if let Coverage::Partial { unread } = coverage {
        return GateOutcome::Indeterminate {
            why: cap_kind(unread.why),
        };
    }
    GateOutcome::Passed(witness)
}

/// How an `UnreadReason` caps a verdict. `DeclaredExclusion` maps to
/// `UnreadableEvidence` rather than `CouldNotRun`: the check did run; what it
/// cannot vouch for is the evidence it deliberately left unread.
fn cap_kind(why: UnreadReason) -> IndeterminateKind {
    match why {
        UnreadReason::ParseFailure | UnreadReason::DeclaredExclusion => {
            IndeterminateKind::UnreadableEvidence
        }
        UnreadReason::UnreachableInput | UnreadReason::ToolDefect => IndeterminateKind::CouldNotRun,
    }
}

/// Total, worst-wins reduction over reports (UNIFIED §3).
///
/// Rank: `Passed` < `Indeterminate` < `Failed`. An empty slice yields
/// `Indeterminate::NothingChecked` (INV-18 / P2). When several reports tie at
/// the worst rank, the FIRST of them wins (documented, deterministic).
///
/// The report laws are re-checked here, not trusted: a report that breaks
/// one (a `Failed` with no Blocking finding, a `Passed` with a Blocking
/// finding or partial coverage) counts as
/// `Indeterminate { UnreadableEvidence }`. Fail closed.
///
/// P1/P3: no slice containing a `Failed` or `Indeterminate` report can ever
/// reduce to `Passed`; monotone in appending worse reports.
pub fn verdict(reports: &[GateReport]) -> GateOutcome {
    let mut best: Option<(u8, GateOutcome)> = None;
    for report in reports {
        let outcome = lawful_outcome(report);
        let rank = outcome_rank(&outcome);
        if best.as_ref().is_none_or(|(r, _)| rank > *r) {
            best = Some((rank, outcome));
        }
    }
    match best {
        None => GateOutcome::Indeterminate {
            why: IndeterminateKind::NothingChecked,
        },
        Some((_, outcome)) => outcome,
    }
}

/// A report's outcome if it obeys the report laws, else
/// `Indeterminate { UnreadableEvidence }`.
fn lawful_outcome(report: &GateReport) -> GateOutcome {
    match report.law_violation() {
        None => report.outcome.clone(),
        Some(_) => GateOutcome::Indeterminate {
            why: IndeterminateKind::UnreadableEvidence,
        },
    }
}

fn outcome_rank(outcome: &GateOutcome) -> u8 {
    match outcome {
        GateOutcome::Passed(_) => 0,
        GateOutcome::Indeterminate { .. } => 1,
        GateOutcome::Failed => 2,
    }
}

/// The §6 child-run protocol (UNIFIED §6, design §7.3).
///
/// A child gate process either (1) emits a `GateReport` as its LAST stdout
/// line of JSON (§6.1, when the gate's manifest declares it speaks the
/// protocol), or (2) falls back to the exit-code convention (§6.2). The
/// parent interprets a completed child run through [`interpret`]; this
/// module is the designated sibling mint of `Witness` alongside
/// `run_checked` (UNIFIED §5).
pub mod child {
    use super::*;

    /// How the child process ended.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ExitKind {
        /// Normal exit with a code.
        Code(i32),
        /// Killed by a signal.
        Signal(i32),
    }

    /// Facts about a completed child run, as observed by the parent.
    ///
    /// Fields are private; the parent records what it SAW (exit kind, last
    /// stdout line, marker file contents, timeout, capture digest) and this
    /// module does the interpreting, so no heuristic can creep into the
    /// parent's loop.
    ///
    /// `speaks_protocol` is manifest knowledge, not a sniffed heuristic: the
    /// parent sets it only when the gate's manifest declares the child speaks
    /// the §6.1 JSON protocol, and then the last stdout line is read as the
    /// report. `false` means the §6.2 exit-code convention governs.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ChildRun {
        gate: GateId,
        exit: ExitKind,
        last_stdout_line: String,
        marker: Option<String>,
        timed_out: bool,
        capture: Digest,
        speaks_protocol: bool,
    }

    impl ChildRun {
        /// Records an observed child run.
        ///
        /// `marker` is the content of the per-check `GATE_OK_FILE` (`None`
        /// when the file was not written). Only the exact content
        /// `ok <gate-id>` (optionally followed by one `\n`) counts.
        pub fn new(
            gate: GateId,
            exit: ExitKind,
            last_stdout_line: String,
            marker: Option<String>,
            timed_out: bool,
            capture: Digest,
            speaks_protocol: bool,
        ) -> Self {
            Self {
                gate,
                exit,
                last_stdout_line,
                marker,
                timed_out,
                capture,
                speaks_protocol,
            }
        }

        /// Which gate this run belonged to.
        pub fn gate(&self) -> &GateId {
            &self.gate
        }

        /// How the child ended.
        pub fn exit(&self) -> ExitKind {
            self.exit
        }

        /// Last line the child wrote to stdout.
        pub fn last_stdout_line(&self) -> &str {
            &self.last_stdout_line
        }

        /// The §6.2 success-marker file content, if the file was written.
        pub fn marker(&self) -> Option<&str> {
            self.marker.as_deref()
        }

        /// Whether the parent killed the child at its wall-clock budget.
        pub fn timed_out(&self) -> bool {
            self.timed_out
        }

        /// Parent-computed digest of the child's captured output.
        pub fn capture(&self) -> &Digest {
            &self.capture
        }

        /// Whether the manifest declared this child a §6.1 protocol speaker.
        pub fn speaks_protocol(&self) -> bool {
            self.speaks_protocol
        }
    }

    /// The §6.1 wire form of a report: exactly the JSON that
    /// `GateReport`'s `Serialize` writes, so one rustyharness can consume
    /// another's report. Unknown fields are refused at every level. It is a
    /// parent-side mirror, never a way to forge a local outcome (INV-4: no
    /// `Deserialize` exists for `GateOutcome`/`Witness`); the parent
    /// re-checks every law before minting anything.
    #[cfg(feature = "json")]
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WireReport {
        gate: GateId,
        outcome: WireOutcome,
        findings: Vec<Finding>,
        coverage: Coverage,
        scope: Scope,
    }

    #[cfg(feature = "json")]
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    enum WireOutcome {
        Passed(WireWitness),
        Failed,
        Indeterminate { why: IndeterminateKind },
    }

    #[cfg(feature = "json")]
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WireWitness {
        checked: usize,
        digest: Digest,
    }

    /// Interprets a completed child run into a [`GateReport`] (UNIFIED §6,
    /// design §7.3).
    ///
    /// Precedence — run-level facts are read BEFORE any report content:
    ///
    /// 1. wall-clock timeout → `CouldNotRun` (UNIFIED §6 item 3);
    /// 2. killed by a signal → `CouldNotRun`;
    /// 3. a manifest-declared §6.1 speaker: its last stdout line is read as
    ///    the report (unparseable or unknown fields → `UnreadableEvidence`),
    ///    its gate id must be the launched gate, its laws are re-checked, and
    ///    its declared outcome must agree with the exit code (`Passed` ⇔ 0,
    ///    `Failed` ⇔ 1, `Indeterminate` ⇔ neither); any contradiction →
    ///    `UnreadableEvidence`;
    /// 4. otherwise the §6.2 exit-code convention.
    pub fn interpret(run: &ChildRun) -> GateReport {
        if run.timed_out {
            return could_not_run(
                run,
                "child exceeded its wall-clock budget and was killed".to_string(),
            );
        }
        if let ExitKind::Signal(sig) = run.exit {
            return could_not_run(run, format!("child killed by signal {sig}"));
        }
        if run.speaks_protocol {
            return interpret_protocol_report(run);
        }
        interpret_exit_convention(run)
    }

    #[cfg(feature = "json")]
    fn interpret_protocol_report(run: &ChildRun) -> GateReport {
        let Ok(wire) = serde_json::from_str::<WireReport>(&run.last_stdout_line) else {
            return unreadable(
                run,
                "child's last stdout line is not a well-formed protocol report",
            );
        };
        // Fail closed on attribution: a child claiming a different gate id
        // than the one the parent launched offers contradictory evidence and
        // is never re-attributed (design §7.3).
        if wire.gate != run.gate {
            return unreadable(
                run,
                "child's declared gate id contradicts the gate the parent launched",
            );
        }
        // Finding law (vocabulary §3): observed text is never empty.
        if wire.findings.iter().any(|f| f.observed.is_empty()) {
            return unreadable(
                run,
                "child's report carries a finding with empty observed text",
            );
        }
        // The child's declared outcome must agree with how it exited.
        let exit_agrees = match (&wire.outcome, run.exit) {
            (WireOutcome::Passed(_), ExitKind::Code(code)) => code == 0,
            (WireOutcome::Failed, ExitKind::Code(code)) => code == 1,
            (WireOutcome::Indeterminate { .. }, ExitKind::Code(code)) => code != 0 && code != 1,
            // Signals were handled before the report was read.
            (_, ExitKind::Signal(_)) => false,
        };
        if !exit_agrees {
            return unreadable(run, "child's exit status contradicts its own report");
        }
        let blocking = has_blocking(&wire.findings);
        let outcome = match wire.outcome {
            WireOutcome::Passed(w) => {
                if blocking || !matches!(wire.coverage, Coverage::Full) {
                    return unreadable(
                        run,
                        "child declared Passed with a Blocking finding or partial coverage",
                    );
                }
                if w.checked == 0 {
                    // INV-18: a pass over nothing is not a pass.
                    GateOutcome::Indeterminate {
                        why: IndeterminateKind::NothingChecked,
                    }
                } else {
                    GateOutcome::Passed(Witness::from_run_checked(w.checked, w.digest))
                }
            }
            WireOutcome::Failed => {
                if !blocking {
                    return unreadable(run, "child declared Failed without a Blocking finding");
                }
                GateOutcome::Failed
            }
            // The child's own non-pass is honoured; the parent never upgrades.
            WireOutcome::Indeterminate { why } => GateOutcome::Indeterminate { why },
        };
        GateReport::build(
            run.gate.clone(),
            outcome,
            wire.findings,
            wire.coverage,
            wire.scope,
        )
    }

    #[cfg(not(feature = "json"))]
    fn interpret_protocol_report(run: &ChildRun) -> GateReport {
        unreadable(
            run,
            "child offered a protocol report this build cannot parse (feature `json` is off)",
        )
    }

    /// Whether marker-file content is exactly `ok <gate-id>` (one trailing
    /// `\n` tolerated, nothing else).
    fn marker_names_gate(marker: &str, gate: &GateId) -> bool {
        let body = marker.strip_suffix('\n').unwrap_or(marker);
        body.strip_prefix("ok ") == Some(gate.as_str())
    }

    fn interpret_exit_convention(run: &ChildRun) -> GateReport {
        match run.exit {
            ExitKind::Code(0) => match run.marker.as_deref() {
                Some(marker) if marker_names_gate(marker, &run.gate) => GateReport::build(
                    run.gate.clone(),
                    // checked = 0: the legacy convention counts no items
                    // (see `Witness::checked`); the capture is what it
                    // vouches for.
                    GateOutcome::Passed(Witness::from_run_checked(0, run.capture)),
                    Vec::new(),
                    Coverage::Full,
                    Scope::empty(),
                ),
                // A marker that does not name THIS gate is contradictory
                // evidence (stale, shared, or another check's file).
                Some(marker) => unreadable(
                    run,
                    &format!(
                        "success marker {marker:?} is not `ok {}` for this gate",
                        run.gate
                    ),
                ),
                // Exit 0 WITHOUT the marker is Indeterminate{NothingChecked},
                // NEVER Passed (UNIFIED §6.2).
                None => GateReport::build(
                    run.gate.clone(),
                    GateOutcome::Indeterminate {
                        why: IndeterminateKind::NothingChecked,
                    },
                    Vec::new(),
                    Coverage::Partial {
                        unread: Unread {
                            universe: "success marker".to_string(),
                            why: UnreadReason::UnreachableInput,
                            detail: format!(
                                "exit 0 without a success marker; last stdout line: {:?}",
                                run.last_stdout_line
                            ),
                        },
                    },
                    Scope::empty(),
                ),
            },
            ExitKind::Code(1) => {
                let finding = Finding::literal(
                    Severity::Blocking,
                    "child-exit-1",
                    run.gate.as_str().to_string(),
                    "exit 0 with success marker",
                    format!("exit 1; last stdout line: {:?}", run.last_stdout_line),
                );
                GateReport::build(
                    run.gate.clone(),
                    GateOutcome::Failed,
                    vec![finding],
                    Coverage::Full,
                    Scope::empty(),
                )
            }
            ExitKind::Code(code) => could_not_run(
                run,
                format!("child exited {code} (usage error or missing interpreter)"),
            ),
            ExitKind::Signal(sig) => could_not_run(run, format!("child killed by signal {sig}")),
        }
    }

    fn could_not_run(run: &ChildRun, detail: String) -> GateReport {
        let ended = match run.exit {
            ExitKind::Code(code) => format!("exit code {code}"),
            ExitKind::Signal(sig) => format!("killed by signal {sig}"),
        };
        let detail = format!(
            "{detail}; child ended: {ended}; last stdout line: {:?}; capture {}",
            run.last_stdout_line, run.capture
        );
        GateReport::build(
            run.gate.clone(),
            GateOutcome::Indeterminate {
                why: IndeterminateKind::CouldNotRun,
            },
            Vec::new(),
            Coverage::Partial {
                unread: Unread {
                    universe: "child run output".to_string(),
                    why: UnreadReason::UnreachableInput,
                    detail,
                },
            },
            Scope::empty(),
        )
    }

    fn unreadable(run: &ChildRun, detail: &str) -> GateReport {
        GateReport::build(
            run.gate.clone(),
            GateOutcome::Indeterminate {
                why: IndeterminateKind::UnreadableEvidence,
            },
            Vec::new(),
            Coverage::Partial {
                unread: Unread {
                    universe: "child stdout".to_string(),
                    why: UnreadReason::ParseFailure,
                    detail: format!(
                        "{detail}; last stdout line: {:?}; capture {}",
                        run.last_stdout_line, run.capture
                    ),
                },
            },
            Scope::empty(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D1: Digest = Digest([1u8; 32]);
    const D2: Digest = Digest([2u8; 32]);
    const D3: Digest = Digest([3u8; 32]);

    /// A lawful gate id for tests (refusal cases call `GateId::new` directly).
    fn gid(id: &str) -> GateId {
        GateId::new(id).expect("test gate id is lawful")
    }

    // Carry-over N-2 (H1a confirming review): an empty id let the marker
    // content "ok " pass. Refused at construction now, and on the wire.
    #[test]
    fn gate_id_refuses_empty_whitespace_and_control() {
        assert_eq!(GateId::new(""), Err(GateIdError::Empty));
        for (bad, at) in [
            (" ", 0),
            ("a b", 1),
            ("g\r", 1),
            ("g\n", 1),
            ("\tg", 0),
            ("g\0", 1),
            ("g\u{85}", 1),
            ("g\u{a0}", 1),
            ("g\u{2028}", 1),
        ] {
            assert_eq!(
                GateId::new(bad),
                Err(GateIdError::ForbiddenChar { at }),
                "id {bad:?} must be refused"
            );
        }
        assert_eq!(gid("cargo-test.unit_1").as_str(), "cargo-test.unit_1");
    }

    #[cfg(feature = "json")]
    #[test]
    fn gate_id_wire_form_refuses_empty() {
        assert!(serde_json::from_str::<GateId>("\"\"").is_err());
        assert!(serde_json::from_str::<GateId>("\"g\\r\"").is_err());
        let g: GateId = serde_json::from_str("\"g\"").expect("lawful id parses");
        assert_eq!(serde_json::to_string(&g).expect("serialises"), "\"g\"");
    }

    fn finding(sev: Severity, code: &str) -> Finding {
        Finding::literal(
            sev,
            code,
            "loc".to_string(),
            "expected",
            "observed".to_string(),
        )
    }

    fn partial() -> Coverage {
        Coverage::Partial {
            unread: Unread {
                universe: "u".into(),
                why: UnreadReason::ToolDefect,
                detail: "d".into(),
            },
        }
    }

    fn indet(why: IndeterminateKind) -> GateOutcome {
        GateOutcome::Indeterminate { why }
    }

    /// A lawful minted pass (crate-internal, as run_checked would build it).
    fn passed_report(gate: &str) -> GateReport {
        GateReport::build(
            gid(gate),
            GateOutcome::Passed(Witness::from_run_checked(2, D1)),
            Vec::new(),
            Coverage::Full,
            Scope::empty(),
        )
    }

    fn failed_report(gate: &str) -> GateReport {
        GateReport::new(
            gid(gate),
            GateOutcome::Failed,
            vec![finding(Severity::Blocking, "b")],
            Coverage::Full,
            Scope::empty(),
        )
        .expect("lawful")
    }

    fn indet_report(gate: &str, why: IndeterminateKind) -> GateReport {
        GateReport::new(
            gid(gate),
            indet(why),
            Vec::new(),
            Coverage::Full,
            Scope::empty(),
        )
        .expect("lawful")
    }

    #[test]
    fn digest_hex_roundtrip() {
        let s = String::from(D1);
        assert_eq!(s.len(), 64);
        let parsed: Digest = s.parse().expect("roundtrip");
        assert_eq!(parsed, D1);
    }

    #[test]
    fn digest_rejects_bad_hex() {
        assert_eq!(
            "zz".parse::<Digest>(),
            Err(DigestParseError::BadLength { got: 2 })
        );
        assert_eq!(
            "gg".repeat(32).parse::<Digest>(),
            Err(DigestParseError::BadHex)
        );
    }

    #[test]
    fn finding_refuses_empty_observed() {
        assert!(Finding::new(Severity::Info, FindingCode("x".into()), "l", "e", "").is_err());
    }

    #[test]
    fn report_new_refuses_passed_so_witnesses_cannot_move() {
        // A witness minted for one report cannot be put on another through
        // the public constructor, whatever the rest of the report says.
        let good = passed_report("good");
        assert_eq!(
            GateReport::new(
                gid("other"),
                good.outcome().clone(),
                Vec::new(),
                Coverage::Full,
                Scope::empty(),
            )
            .err(),
            Some(GateReportError::PassedIsMintedOnly)
        );
    }

    #[test]
    fn report_laws_are_enforced() {
        // Failed needs a Blocking finding.
        assert_eq!(
            GateReport::new(
                gid("g"),
                GateOutcome::Failed,
                vec![finding(Severity::High, "h")],
                Coverage::Full,
                Scope::empty(),
            )
            .err(),
            Some(GateReportError::FailedWithoutBlockingFinding)
        );
        // The Passed laws, as checked on built reports.
        let mut r = passed_report("g");
        r.findings.push(finding(Severity::Blocking, "b"));
        assert_eq!(
            r.law_violation(),
            Some(GateReportError::PassedWithBlockingFinding)
        );
        let mut r = passed_report("g");
        r.coverage = partial();
        assert_eq!(
            r.law_violation(),
            Some(GateReportError::PassedWithPartialCoverage)
        );
        assert_eq!(passed_report("g").law_violation(), None);
    }

    #[test]
    fn verdict_does_not_trust_an_unlawful_report() {
        let unreadable = indet(IndeterminateKind::UnreadableEvidence);
        // Failed with no Blocking finding.
        let mut r = failed_report("f");
        r.findings.clear();
        assert_eq!(verdict(&[r]), unreadable);
        // Passed with a Blocking finding pushed on after minting.
        let mut r = passed_report("p");
        r.findings.push(finding(Severity::Blocking, "b"));
        assert_eq!(verdict(&[r]), unreadable);
        // Passed with partial coverage.
        let mut r = passed_report("p");
        r.coverage = partial();
        assert_eq!(verdict(&[r]), unreadable);
    }

    #[test]
    fn empty_report_slice_is_indeterminate_nothing_checked() {
        assert_eq!(verdict(&[]), indet(IndeterminateKind::NothingChecked));
    }

    #[test]
    fn failed_dominates_indeterminate_and_passed() {
        let passed = passed_report("p");
        let i = indet_report("i", IndeterminateKind::CouldNotRun);
        let failed = failed_report("f");
        assert!(matches!(
            verdict(std::slice::from_ref(&passed)),
            GateOutcome::Passed(_)
        ));
        assert_eq!(verdict(&[passed, i.clone()]), i.outcome);
        assert_eq!(verdict(&[i, failed.clone()]), GateOutcome::Failed);
        assert_eq!(verdict(&[failed]), GateOutcome::Failed);
    }

    #[test]
    fn verdict_first_max_tiebreak_is_deterministic() {
        // Two DIFFERENT outcomes of the same rank: the first one wins, in
        // either order.
        let a = indet_report("a", IndeterminateKind::CouldNotRun);
        let b = indet_report("b", IndeterminateKind::StaleBinary);
        assert_eq!(
            verdict(&[a.clone(), b.clone()]),
            indet(IndeterminateKind::CouldNotRun)
        );
        assert_eq!(verdict(&[b, a]), indet(IndeterminateKind::StaleBinary));
    }

    /// Every report shape the reduction can see: a lawful pass, a lawful
    /// fail, the five Indeterminate kinds, and three unlawful reports.
    fn report_universe() -> Vec<GateReport> {
        let mut v = vec![passed_report("p"), failed_report("f")];
        for why in [
            IndeterminateKind::NothingChecked,
            IndeterminateKind::UnreadableEvidence,
            IndeterminateKind::CouldNotRun,
            IndeterminateKind::UnsupportedOs,
            IndeterminateKind::StaleBinary,
        ] {
            v.push(indet_report("i", why));
        }
        let mut bad = failed_report("bad-failed");
        bad.findings.clear();
        v.push(bad);
        let mut bad = passed_report("bad-passed-blocking");
        bad.findings.push(finding(Severity::Blocking, "b"));
        v.push(bad);
        let mut bad = passed_report("bad-passed-partial");
        bad.coverage = partial();
        v.push(bad);
        v
    }

    /// Independent oracle for `verdict`, written from UNIFIED §3 directly.
    fn oracle(reports: &[GateReport]) -> GateOutcome {
        let effective: Vec<GateOutcome> = reports
            .iter()
            .map(|r| {
                let blocking = r.findings.iter().any(|f| f.severity == Severity::Blocking);
                match &r.outcome {
                    GateOutcome::Failed if !blocking => {
                        indet(IndeterminateKind::UnreadableEvidence)
                    }
                    GateOutcome::Passed(_) if blocking || !matches!(r.coverage, Coverage::Full) => {
                        indet(IndeterminateKind::UnreadableEvidence)
                    }
                    o => o.clone(),
                }
            })
            .collect();
        if effective.contains(&GateOutcome::Failed) {
            return GateOutcome::Failed;
        }
        if let Some(first) = effective
            .iter()
            .find(|o| matches!(o, GateOutcome::Indeterminate { .. }))
        {
            return first.clone();
        }
        match effective.first() {
            Some(pass) => pass.clone(),
            None => indet(IndeterminateKind::NothingChecked),
        }
    }

    #[test]
    fn verdict_is_exhaustively_correct_over_up_to_three_reports() {
        let u = report_universe();
        let n = u.len();
        let mut sets: Vec<Vec<GateReport>> = vec![Vec::new()];
        for a in 0..n {
            sets.push(vec![u[a].clone()]);
            for b in 0..n {
                sets.push(vec![u[a].clone(), u[b].clone()]);
                for c in 0..n {
                    sets.push(vec![u[a].clone(), u[b].clone(), u[c].clone()]);
                }
            }
        }
        assert_eq!(sets.len(), 1 + n + n * n + n * n * n);
        for set in &sets {
            let got = verdict(set);
            assert_eq!(got, oracle(set), "verdict over {set:?}");
            // P1: any non-pass (lawful or not) forbids Passed.
            let all_lawful_passes = set.iter().all(|r| {
                matches!(r.outcome, GateOutcome::Passed(_)) && r.law_violation().is_none()
            });
            if matches!(got, GateOutcome::Passed(_)) {
                assert!(all_lawful_passes && !set.is_empty(), "{set:?}");
            }
            // P3: appending any report never improves the rank.
            for extra in &u {
                let mut longer = set.clone();
                longer.push(extra.clone());
                assert!(
                    outcome_rank(&verdict(&longer)) >= outcome_rank(&got) || set.is_empty(),
                    "appending {extra:?} to {set:?} improved the verdict"
                );
            }
        }
    }

    #[test]
    fn run_checked_empty_examination_never_passes() {
        struct Empty;
        impl Check for Empty {
            type Input = ();
            fn gate(&self) -> GateId {
                gid("empty")
            }
            fn examine(&self, _input: &()) -> Examination {
                Examination {
                    items: Vec::new(),
                    set_digest: D1,
                    findings: Vec::new(),
                    coverage: Coverage::Full,
                    scope: Scope::empty(),
                }
            }
        }
        let report = run_checked(&Empty, &());
        assert_eq!(report.outcome, indet(IndeterminateKind::NothingChecked));
    }

    #[test]
    fn run_checked_blocking_with_nothing_examined_is_still_failed() {
        struct RefutedEarly;
        impl Check for RefutedEarly {
            type Input = ();
            fn gate(&self) -> GateId {
                gid("early")
            }
            fn examine(&self, _input: &()) -> Examination {
                Examination {
                    items: Vec::new(),
                    set_digest: D1,
                    findings: vec![finding(Severity::Blocking, "refuted")],
                    coverage: Coverage::Full,
                    scope: Scope::empty(),
                }
            }
        }
        assert_eq!(run_checked(&RefutedEarly, &()).outcome, GateOutcome::Failed);
    }

    #[test]
    fn run_checked_partial_coverage_caps_at_indeterminate() {
        struct Partial;
        impl Check for Partial {
            type Input = ();
            fn gate(&self) -> GateId {
                gid("partial")
            }
            fn examine(&self, _input: &()) -> Examination {
                Examination {
                    items: vec![D1, D2],
                    set_digest: D3,
                    findings: Vec::new(),
                    coverage: Coverage::Partial {
                        unread: Unread {
                            universe: "files".into(),
                            why: UnreadReason::DeclaredExclusion,
                            detail: "vendor/".into(),
                        },
                    },
                    scope: Scope::empty(),
                }
            }
        }
        let report = run_checked(&Partial, &());
        assert_eq!(report.outcome, indet(IndeterminateKind::UnreadableEvidence));
    }

    #[test]
    fn run_checked_passes_only_over_real_evidence() {
        struct Good;
        impl Check for Good {
            type Input = ();
            fn gate(&self) -> GateId {
                gid("good")
            }
            fn examine(&self, _input: &()) -> Examination {
                Examination {
                    items: vec![D1],
                    set_digest: D2,
                    findings: vec![finding(Severity::Low, "note")],
                    coverage: Coverage::Full,
                    scope: Scope::empty(),
                }
            }
        }
        let report = run_checked(&Good, &());
        let GateOutcome::Passed(w) = report.outcome() else {
            panic!("expected Passed, got {:?}", report.outcome());
        };
        assert_eq!(w.checked(), 1);
        assert_eq!(w.digest(), &D2);
        // Advisory findings survive on a Passed report.
        assert_eq!(report.findings().len(), 1);
    }

    mod child_tests {
        use super::super::child::{interpret, ChildRun, ExitKind};
        use super::*;

        fn legacy(exit: ExitKind, marker: Option<&str>, timed_out: bool) -> ChildRun {
            ChildRun::new(
                gid("c"),
                exit,
                "last line".to_string(),
                marker.map(str::to_string),
                timed_out,
                D1,
                false,
            )
        }

        #[test]
        fn exit0_without_marker_is_never_passed() {
            let report = interpret(&legacy(ExitKind::Code(0), None, false));
            assert_eq!(report.outcome, indet(IndeterminateKind::NothingChecked));
            // It examined nothing, so it cannot claim full coverage.
            assert!(
                matches!(report.coverage, Coverage::Partial { .. }),
                "{:?}",
                report.coverage
            );
        }

        #[test]
        fn exit0_with_exact_marker_passes_via_child_mint() {
            for marker in ["ok c", "ok c\n"] {
                let report = interpret(&legacy(ExitKind::Code(0), Some(marker), false));
                let GateOutcome::Passed(w) = report.outcome() else {
                    panic!(
                        "marker {marker:?}: expected Passed, got {:?}",
                        report.outcome
                    );
                };
                // Legacy pass: vouches for the capture, counts no items.
                assert_eq!(w.checked(), 0);
                assert_eq!(w.digest(), &D1);
            }
        }

        // Carry-over N-5 (H1a confirming review), decided: a CRLF marker is
        // REFUSED. The marker is exactly `ok <gate-id>` with at most one
        // trailing LF (design §7.3, "Marker content"). A Windows child must
        // write LF; `\r\n` is `UnreadableEvidence`, never a pass, and a gate
        // id cannot end in `\r` (N-2), so no id can absorb the CR either.
        #[test]
        fn crlf_marker_is_refused_not_tolerated() {
            for marker in ["ok c\r\n", "ok c\r", "ok c\r\n\r\n"] {
                let report = interpret(&legacy(ExitKind::Code(0), Some(marker), false));
                assert_eq!(
                    report.outcome,
                    indet(IndeterminateKind::UnreadableEvidence),
                    "CRLF marker {marker:?} must be refused"
                );
            }
            // Control: the LF form of the same marker passes.
            let report = interpret(&legacy(ExitKind::Code(0), Some("ok c\n"), false));
            assert!(matches!(report.outcome, GateOutcome::Passed(_)));
        }

        #[test]
        fn marker_must_read_exactly_ok_and_this_gate_id() {
            for marker in [
                "",
                "ok",
                "ok ",
                "ok other",
                "ok c extra",
                "ok cc",
                "ok c\r\n",
                "ok c\n\n",
                " ok c",
                "OK c",
                "1",
            ] {
                let report = interpret(&legacy(ExitKind::Code(0), Some(marker), false));
                assert_eq!(
                    report.outcome,
                    indet(IndeterminateKind::UnreadableEvidence),
                    "marker {marker:?} must not pass"
                );
            }
        }

        #[test]
        fn exit1_is_failed_with_blocking_finding() {
            let report = interpret(&legacy(ExitKind::Code(1), None, false));
            assert_eq!(report.outcome, GateOutcome::Failed);
            assert!(report
                .findings
                .iter()
                .any(|f| f.severity == Severity::Blocking));
        }

        #[test]
        fn timeout_signal_and_usage_are_could_not_run() {
            let could_not_run = indet(IndeterminateKind::CouldNotRun);
            // Timed out with exit 0 AND a valid marker: still not a pass.
            assert_eq!(
                interpret(&legacy(ExitKind::Code(0), Some("ok c"), true)).outcome,
                could_not_run
            );
            assert_eq!(
                interpret(&legacy(ExitKind::Signal(9), Some("ok c"), false)).outcome,
                could_not_run
            );
            for code in [2, 127, -1] {
                assert_eq!(
                    interpret(&legacy(ExitKind::Code(code), None, false)).outcome,
                    could_not_run
                );
            }
        }

        #[test]
        fn could_not_run_records_child_evidence() {
            let run = ChildRun::new(
                gid("c"),
                ExitKind::Signal(15),
                "aborted mid-check".to_string(),
                None,
                true,
                D2,
                false,
            );
            let report = interpret(&run);
            assert_eq!(report.outcome, indet(IndeterminateKind::CouldNotRun));
            let Coverage::Partial { unread } = &report.coverage else {
                panic!("expected Partial coverage, got {:?}", report.coverage);
            };
            assert_eq!(unread.why, UnreadReason::UnreachableInput);
            assert!(unread.detail.contains("wall-clock budget"), "{unread:?}");
            assert!(unread.detail.contains("killed by signal 15"), "{unread:?}");
            assert!(unread.detail.contains("aborted mid-check"), "{unread:?}");
            assert!(unread.detail.contains(&D2.to_string()), "{unread:?}");
        }

        #[cfg(not(feature = "json"))]
        #[test]
        fn protocol_report_without_json_feature_is_unreadable() {
            let run = ChildRun::new(
                gid("c"),
                ExitKind::Code(0),
                "{}".to_string(),
                Some("ok c".to_string()),
                false,
                D1,
                true,
            );
            assert_eq!(
                interpret(&run).outcome,
                indet(IndeterminateKind::UnreadableEvidence)
            );
        }

        #[cfg(feature = "json")]
        mod protocol {
            use super::*;

            /// A child report on the wire, as the crate itself serializes it.
            fn wire(gate: &str, outcome: serde_json::Value, findings: &[Finding]) -> String {
                serde_json::json!({
                    "gate": gate,
                    "outcome": outcome,
                    "findings": findings,
                    "coverage": Coverage::Full,
                    "scope": Scope::empty(),
                })
                .to_string()
            }

            fn passing_wire() -> String {
                wire(
                    "c",
                    serde_json::json!({"Passed": {"checked": 3, "digest": D2.to_string()}}),
                    &[],
                )
            }

            fn speaker(exit: ExitKind, line: String, timed_out: bool) -> ChildRun {
                ChildRun::new(gid("c"), exit, line, None, timed_out, D1, true)
            }

            #[test]
            fn passing_report_with_exit0_passes() {
                let report = interpret(&speaker(ExitKind::Code(0), passing_wire(), false));
                let GateOutcome::Passed(w) = report.outcome() else {
                    panic!("expected Passed, got {:?}", report.outcome);
                };
                assert_eq!(w.checked(), 3);
                assert_eq!(w.digest(), &D2);
            }

            #[test]
            fn timeout_beats_a_passing_report() {
                assert_eq!(
                    interpret(&speaker(ExitKind::Code(0), passing_wire(), true)).outcome,
                    indet(IndeterminateKind::CouldNotRun)
                );
                // Killed at the deadline (timeout + SIGKILL).
                assert_eq!(
                    interpret(&speaker(ExitKind::Signal(9), passing_wire(), true)).outcome,
                    indet(IndeterminateKind::CouldNotRun)
                );
            }

            #[test]
            fn signal_beats_a_passing_report() {
                for sig in [9, 11, 15] {
                    assert_eq!(
                        interpret(&speaker(ExitKind::Signal(sig), passing_wire(), false)).outcome,
                        indet(IndeterminateKind::CouldNotRun),
                        "signal {sig}"
                    );
                }
            }

            #[test]
            fn nonzero_exit_contradicting_a_passing_report_is_unreadable() {
                for code in [1, 2, 3, 5, 127, -1] {
                    assert_eq!(
                        interpret(&speaker(ExitKind::Code(code), passing_wire(), false)).outcome,
                        indet(IndeterminateKind::UnreadableEvidence),
                        "exit {code}"
                    );
                }
            }

            #[test]
            fn declared_outcome_must_agree_with_exit_both_ways() {
                let failed = wire(
                    "c",
                    serde_json::json!("Failed"),
                    &[finding(Severity::Blocking, "child-says")],
                );
                assert_eq!(
                    interpret(&speaker(ExitKind::Code(1), failed.clone(), false)).outcome,
                    GateOutcome::Failed
                );
                for code in [0, 2, 5] {
                    assert_eq!(
                        interpret(&speaker(ExitKind::Code(code), failed.clone(), false)).outcome,
                        indet(IndeterminateKind::UnreadableEvidence),
                        "Failed report with exit {code}"
                    );
                }
                let stale = wire(
                    "c",
                    serde_json::json!({"Indeterminate": {"why": "StaleBinary"}}),
                    &[],
                );
                assert_eq!(
                    interpret(&speaker(ExitKind::Code(5), stale.clone(), false)).outcome,
                    indet(IndeterminateKind::StaleBinary)
                );
                for code in [0, 1] {
                    assert_eq!(
                        interpret(&speaker(ExitKind::Code(code), stale.clone(), false)).outcome,
                        indet(IndeterminateKind::UnreadableEvidence),
                        "Indeterminate report with exit {code}"
                    );
                }
            }

            #[test]
            fn checked_zero_is_nothing_checked() {
                let line = wire(
                    "c",
                    serde_json::json!({"Passed": {"checked": 0, "digest": D2.to_string()}}),
                    &[],
                );
                assert_eq!(
                    interpret(&speaker(ExitKind::Code(0), line, false)).outcome,
                    indet(IndeterminateKind::NothingChecked)
                );
            }

            #[test]
            fn declared_outcomes_that_break_the_laws_are_unreadable() {
                let unreadable = indet(IndeterminateKind::UnreadableEvidence);
                // Failed without a Blocking finding.
                let line = wire("c", serde_json::json!("Failed"), &[]);
                assert_eq!(
                    interpret(&speaker(ExitKind::Code(1), line, false)).outcome,
                    unreadable
                );
                // Passed with a Blocking finding.
                let line = wire(
                    "c",
                    serde_json::json!({"Passed": {"checked": 3, "digest": D2.to_string()}}),
                    &[finding(Severity::Blocking, "b")],
                );
                assert_eq!(
                    interpret(&speaker(ExitKind::Code(0), line, false)).outcome,
                    unreadable
                );
                // Passed with partial coverage.
                let line = serde_json::json!({
                    "gate": "c",
                    "outcome": {"Passed": {"checked": 3, "digest": D2.to_string()}},
                    "findings": [],
                    "coverage": partial(),
                    "scope": Scope::empty(),
                })
                .to_string();
                assert_eq!(
                    interpret(&speaker(ExitKind::Code(0), line, false)).outcome,
                    unreadable
                );
                // A finding with empty observed text.
                let mut empty = finding(Severity::Low, "note");
                empty.observed.clear();
                let line = wire(
                    "c",
                    serde_json::json!({"Passed": {"checked": 3, "digest": D2.to_string()}}),
                    &[empty],
                );
                assert_eq!(
                    interpret(&speaker(ExitKind::Code(0), line, false)).outcome,
                    unreadable
                );
            }

            #[test]
            fn unknown_fields_are_refused_at_every_level() {
                let unreadable = indet(IndeterminateKind::UnreadableEvidence);
                let mut top: serde_json::Value =
                    serde_json::from_str(&passing_wire()).expect("json");
                top["verdict"] = serde_json::json!("Failed");
                let mut in_witness = top.clone();
                in_witness
                    .as_object_mut()
                    .expect("object")
                    .remove("verdict");
                in_witness["outcome"]["Passed"]["note"] = serde_json::json!(1);
                let mut in_scope = in_witness.clone();
                in_scope["outcome"]["Passed"]
                    .as_object_mut()
                    .expect("object")
                    .remove("note");
                in_scope["scope"]["extra"] = serde_json::json!([]);
                let mut in_finding = in_scope.clone();
                in_finding["scope"]
                    .as_object_mut()
                    .expect("object")
                    .remove("extra");
                let mut f = serde_json::to_value(finding(Severity::Low, "n")).expect("json");
                f["why"] = serde_json::json!("x");
                in_finding["findings"] = serde_json::json!([f]);
                for (name, value) in [
                    ("top", top),
                    ("witness", in_witness),
                    ("scope", in_scope),
                    ("finding", in_finding),
                ] {
                    assert_eq!(
                        interpret(&speaker(ExitKind::Code(0), value.to_string(), false)).outcome,
                        unreadable,
                        "unknown field in {name}"
                    );
                }
            }

            #[test]
            fn the_crates_own_report_json_reads_back() {
                // One rustyharness must be able to consume another's report
                // line (design §7.7).
                let failed = failed_report("c");
                let line = serde_json::to_string(&failed).expect("json");
                let back = interpret(&speaker(ExitKind::Code(1), line, false));
                assert_eq!(back.outcome, GateOutcome::Failed);
                assert_eq!(back.findings, failed.findings);

                let stale = indet_report("c", IndeterminateKind::StaleBinary);
                let line = serde_json::to_string(&stale).expect("json");
                assert_eq!(
                    interpret(&speaker(ExitKind::Code(5), line, false)).outcome,
                    indet(IndeterminateKind::StaleBinary)
                );

                let mut pass = passed_report("c");
                pass.findings.push(finding(Severity::Low, "note"));
                let line = serde_json::to_string(&pass).expect("json");
                let back = interpret(&speaker(ExitKind::Code(0), line, false));
                let GateOutcome::Passed(w) = back.outcome() else {
                    panic!("expected Passed, got {:?}", back.outcome);
                };
                assert_eq!((w.checked(), *w.digest()), (2, D1));
            }

            #[test]
            fn declared_gate_id_must_be_the_launched_gate() {
                let line = wire(
                    "other-gate",
                    serde_json::json!({"Passed": {"checked": 3, "digest": D2.to_string()}}),
                    &[],
                );
                assert_eq!(
                    interpret(&speaker(ExitKind::Code(0), line, false)).outcome,
                    indet(IndeterminateKind::UnreadableEvidence)
                );
            }

            #[test]
            fn unparseable_or_undeclared_report() {
                assert_eq!(
                    interpret(&speaker(ExitKind::Code(0), "{not json".to_string(), false)).outcome,
                    indet(IndeterminateKind::UnreadableEvidence)
                );
                // Not declared a speaker: the line is ignored and the exit
                // convention governs (no marker → NothingChecked).
                let run = ChildRun::new(
                    gid("c"),
                    ExitKind::Code(0),
                    passing_wire(),
                    None,
                    false,
                    D1,
                    false,
                );
                assert_eq!(
                    interpret(&run).outcome,
                    indet(IndeterminateKind::NothingChecked)
                );
            }
        }
    }
}
