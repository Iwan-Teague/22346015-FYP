//! Capability manifest v1 (design `docs/01-design-v0.1.md` §4.1-§4.4, §4.8).
//!
//! A manifest is the trust root for a provider's capabilities: policy reads
//! the manifest's closed-set dimensions, never what a server says about
//! itself. This crate is pure (no I/O, no clock, no global state): callers
//! hand in bytes and a [`ValidationContext`], and get back either a
//! [`Manifest`] whose CONTENT was checked, or a typed [`ManifestError`].
//!
//! What parsing refuses (§4.3), each with a test:
//! - duplicate JSON keys at any depth (INV-22, `harness_core::strict_json`);
//! - unknown fields and unknown dimension values (`deny_unknown_fields`);
//! - a schema version outside [`SUPPORTED_SCHEMA_VERSIONS`], naming both;
//!   v0 gets a migration message;
//! - reserved provider names ([`RESERVED_NAMESPACES`] ∪ config additions),
//!   before any per-capability check (INV-1);
//! - ids outside the provider namespace, duplicate ids, an empty capability
//!   list, an `mcp_name` mapped twice (INV-8 for ids);
//! - input schemas outside the §3.3 subset ([`schema`]);
//! - summaries with control, zero-width or bidi characters (refused, never
//!   stripped).
//!
//! Plus content checks the table in §4.1 implies: per-transport fields must
//! be present exactly when meaningful (an `mcp_name` on a built-in tool is
//! refused, not ignored), `min_harness` is enforced, hex pins are exact.
//!
//! Trust tiers, admission and the H1 phase gate live in [`admission`]; the
//! built-in manifest in [`builtin`].

#![forbid(unsafe_code)]
// The panic-set lints ratchet production code; unit tests may assert loosely.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;
use serde_json::Value;

pub mod admission;
pub mod builtin;
pub mod schema;
use harness_core::strict_json;

pub use schema::{ArgsError, InputSchema, SchemaError};

/// Manifest schema versions this harness understands (design §4.1, §4.7).
pub const SUPPORTED_SCHEMA_VERSIONS: &[u32] = &[1];

/// Provider names no loaded manifest may claim (design §4.3, R5 §6.3). The
/// effective set is this constant ∪ `ValidationContext::extra_reserved`;
/// config can add names, never remove one.
pub const RESERVED_NAMESPACES: &[&str] = &["harness", "rustyvault"];

/// The built-in tools' namespace. Only the manifest compiled into this crate
/// ([`builtin::manifest`]) may use it.
pub const BUILTIN_NAMESPACE: &str = "harness";

/// Largest manifest accepted, in bytes (checked before parsing).
pub const MANIFEST_MAX_BYTES: usize = 1 << 20;
/// Length cap for provider names, in bytes.
pub const PROVIDER_MAX: usize = 64;
/// Length cap for capability ids, in bytes.
pub const ID_MAX: usize = 128;
/// Length cap for capability summaries, in bytes.
pub const SUMMARY_MAX: usize = 512;
/// Length cap for `provider_version`, in bytes.
pub const PROVIDER_VERSION_MAX: usize = 32;
/// Cap on how many capabilities one manifest may declare.
pub const CAPABILITIES_MAX: usize = 1024;
/// Length cap for an `mcp_name`, in bytes.
pub const MCP_NAME_MAX: usize = 128;
/// Cap on secret handles per capability.
pub const SECRETS_MAX: usize = 16;

// ---------------------------------------------------------------------------
// Closed-set dimensions (§4.1). Declaration order IS the ordinal: derive(Ord)
// makes `Read < Write < Execute < Irreversible` and so on.
// ---------------------------------------------------------------------------

/// What invoking a capability does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// Reads state.
    Read,
    /// Changes state reversibly.
    Write,
    /// Runs code.
    Execute,
    /// Cannot be undone.
    Irreversible,
}

/// What the result or effect touches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    /// Public data.
    Public,
    /// Operational, non-personal data.
    Operational,
    /// Personal data.
    Personal,
    /// Restricted (life-data) class: refused in v0.1 (INV-27).
    Restricted,
}

/// Whose state an effect can reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlastRadius {
    /// The provider's own state.
    Own,
    /// Machine-wide state.
    Host,
    /// State other people or machines rely on.
    Shared,
}

/// Whether invoking it sends data off-host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Egress {
    /// Nothing leaves the host.
    None,
    /// The local network.
    Lan,
    /// The internet.
    Internet,
}

/// Whether results can carry text authored outside the user's control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Content {
    /// Authored by the user or the provider itself.
    Own,
    /// Can carry third-party text (web, messages, other people's files).
    ThirdParty,
}

/// Confirmation floor (a floor, never a ceiling: max-rule, §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confirmation {
    /// No confirmation.
    None,
    /// The user confirms.
    UserConfirm,
    /// Protected action: asked every time, single-use approval.
    ProtectedAction,
}

// The wire names of the dimensions (the manifest's own spelling), for
// messages and reports. A test round-trips every variant through serde, and
// its variant lists sit behind wildcard-free matches, so a new variant does
// not compile until it is listed there too.

impl Effect {
    /// The manifest wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Effect::Read => "read",
            Effect::Write => "write",
            Effect::Execute => "execute",
            Effect::Irreversible => "irreversible",
        }
    }
}

impl Sensitivity {
    /// The manifest wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Sensitivity::Public => "public",
            Sensitivity::Operational => "operational",
            Sensitivity::Personal => "personal",
            Sensitivity::Restricted => "restricted",
        }
    }
}

impl BlastRadius {
    /// The manifest wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            BlastRadius::Own => "own",
            BlastRadius::Host => "host",
            BlastRadius::Shared => "shared",
        }
    }
}

impl Egress {
    /// The manifest wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Egress::None => "none",
            Egress::Lan => "lan",
            Egress::Internet => "internet",
        }
    }
}

impl Content {
    /// The manifest wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Content::Own => "own",
            Content::ThirdParty => "third_party",
        }
    }
}

impl Confirmation {
    /// The manifest wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Confirmation::None => "none",
            Confirmation::UserConfirm => "user_confirm",
            Confirmation::ProtectedAction => "protected_action",
        }
    }
}

// ---------------------------------------------------------------------------
// Validated names.
// ---------------------------------------------------------------------------

/// A provider namespace, `[a-z0-9_-]{1,64}` (scaffold grammar).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderName(String);

impl ProviderName {
    /// Check `s` against the provider-name grammar.
    pub fn new(s: &str) -> Result<Self, ManifestError> {
        check_name("provider", s, false, PROVIDER_MAX)?;
        Ok(Self(s.to_owned()))
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProviderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A capability id, `<provider>.<verb...>`: ASCII `[a-z0-9._-]`, at most 128
/// bytes, no empty, leading, trailing or doubled dot after the provider.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapId(String);

impl CapId {
    /// Check `s` against the id grammar and split off its provider.
    pub fn new(s: &str) -> Result<Self, ManifestError> {
        check_name("capability id", s, true, ID_MAX)?;
        let bad = || ManifestError::InvalidName {
            field: "capability id",
            value: s.to_owned(),
            max: ID_MAX,
        };
        let (provider, rest) = s.split_once('.').ok_or_else(bad)?;
        check_name("capability id", provider, false, PROVIDER_MAX).map_err(|_| bad())?;
        if rest.is_empty() || rest.starts_with('.') || rest.ends_with('.') || rest.contains("..") {
            return Err(bad());
        }
        Ok(Self(s.to_owned()))
    }

    /// The id.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The namespace part (before the first dot).
    pub fn provider(&self) -> &str {
        self.0.split_once('.').map_or("", |(p, _)| p)
    }
}

impl fmt::Display for CapId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A byte allowed in a manifest name. Dots are the namespace separator, so
/// they are legal only inside capability ids, never in a provider name.
fn is_name_byte(b: u8, allow_dot: bool) -> bool {
    b.is_ascii_lowercase()
        || b.is_ascii_digit()
        || b == b'-'
        || b == b'_'
        || (allow_dot && b == b'.')
}

fn check_name(
    field: &'static str,
    value: &str,
    allow_dot: bool,
    max: usize,
) -> Result<(), ManifestError> {
    if value.is_empty() || !value.bytes().all(|b| is_name_byte(b, allow_dot)) {
        return Err(ManifestError::InvalidName {
            field,
            value: shown(value),
            max,
        });
    }
    if value.len() > max {
        return Err(ManifestError::TooLong {
            field,
            len: value.len(),
            max,
        });
    }
    Ok(())
}

/// Bound untrusted text before it goes into an error message. Every
/// caller formats the result with `{:?}`, which escapes control and bidi
/// characters; text shown with `{}` goes through [`display_safe`].
fn shown(s: &str) -> String {
    s.chars().take(80).collect()
}

/// Untrusted text made safe to show with `{}` (design §7.1: display paths
/// escape control, bidi and ANSI sequences), with the journal's reversible
/// escape: `\` becomes `\\`, and every control character (ESC included,
/// so an ANSI sequence is inert), line or paragraph separator, zero-width or
/// bidi code point becomes `\u{HEX}`. At most `max` characters of `s` are
/// kept (H1f-2 review F-1: a refused manifest could otherwise redraw the
/// terminal, e.g. print a forged "OK" over its own refusal).
fn display_safe(s: &str, max: usize) -> String {
    let mut out = String::new();
    for c in s.chars().take(max) {
        if c == '\\' {
            out.push_str("\\\\");
        } else if c.is_control() || is_invisible_or_bidi(c) || matches!(c, '\u{2028}' | '\u{2029}')
        {
            out.push_str(&format!("\\u{{{:X}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

/// A strict `MAJOR.MINOR.PATCH` (no pre-release or build suffix, no leading
/// zeros). The harness's own version is handed in, never read here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemVer {
    /// Major.
    pub major: u64,
    /// Minor.
    pub minor: u64,
    /// Patch.
    pub patch: u64,
}

impl SemVer {
    /// Parse a strict `MAJOR.MINOR.PATCH`.
    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.split('.');
        let mut next = || -> Option<u64> {
            let p = parts.next()?;
            let ok = !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p == "0" || !p.starts_with('0'));
            if ok {
                p.parse().ok()
            } else {
                None
            }
        };
        let v = SemVer {
            major: next()?,
            minor: next()?,
            patch: next()?,
        };
        if parts.next().is_some() {
            return None;
        }
        Some(v)
    }
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// A 32-byte SHA-256 pin, written as 64 lowercase hex characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Pin([u8; 32]);

impl Sha256Pin {
    /// Parse exactly 64 lowercase hex characters.
    pub fn parse_hex(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() != 64 {
            return None;
        }
        let val = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        let mut out = [0u8; 32];
        for (slot, pair) in out.iter_mut().zip(b.chunks_exact(2)) {
            let (hi, lo) = match pair {
                [hi, lo] => (val(*hi)?, val(*lo)?),
                _ => return None,
            };
            *slot = (hi << 4) | lo;
        }
        Some(Self(out))
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Wire form (serde, deny_unknown_fields everywhere).
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestWire {
    schema_version: u32,
    provider: String,
    provider_version: String,
    min_harness: String,
    transport: TransportWire,
    #[serde(default)]
    mcp_protocols: Vec<String>,
    capabilities: Vec<CapabilityWire>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum TransportWire {
    // A struct variant, not a unit one: serde ignores extra fields on an
    // internally tagged UNIT variant even under deny_unknown_fields (test
    // `unit_transport_variant_still_refuses_unknown_fields`).
    Builtin {},
    McpStdio {
        argv: Vec<String>,
        env_allow: Vec<String>,
    },
    InProcess {
        feature: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityWire {
    id: String,
    #[serde(default)]
    mcp_name: Option<String>,
    summary: String,
    effect: Effect,
    sensitivity: Sensitivity,
    blast_radius: BlastRadius,
    egress: Egress,
    content: Content,
    confirmation: Confirmation,
    input_schema: Value,
    #[serde(default)]
    schema_sha256: Option<String>,
    #[serde(default)]
    description_sha256: Option<String>,
    #[serde(default)]
    secrets: Vec<String>,
    #[serde(default)]
    limits: Option<LimitsWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsWire {
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    max_result_bytes: Option<u64>,
}

// ---------------------------------------------------------------------------
// Validated form.
// ---------------------------------------------------------------------------

/// How the provider is reached (§4.1 `transport`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// In-process built-in tools (`harness.*` only).
    Builtin,
    /// An MCP server spawned confined (H4).
    McpStdio {
        /// argv vector; `argv[0]` is an absolute path.
        argv: Vec<String>,
        /// Environment variable names passed through.
        env_allow: Vec<String>,
    },
    /// A Rust adapter crate behind a cargo feature (H4).
    InProcess {
        /// The cargo feature name.
        feature: String,
    },
}

impl Transport {
    /// Short name for messages.
    pub fn kind(&self) -> &'static str {
        match self {
            Transport::Builtin => "builtin",
            Transport::McpStdio { .. } => "mcp-stdio",
            Transport::InProcess { .. } => "in-process",
        }
    }
}

/// Per-capability limits; they can only tighten harness defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Limits {
    /// Per-call timeout, milliseconds (> 0).
    pub timeout_ms: Option<u64>,
    /// Result cap, bytes (> 0).
    pub max_result_bytes: Option<u64>,
}

impl Limits {
    /// The effective limits: each declared value can only lower the default
    /// (max-rule for limits, §4.1).
    pub fn tighten(&self, default_timeout_ms: u64, default_max_result_bytes: u64) -> (u64, u64) {
        (
            self.timeout_ms
                .map_or(default_timeout_ms, |t| t.min(default_timeout_ms)),
            self.max_result_bytes.map_or(default_max_result_bytes, |b| {
                b.min(default_max_result_bytes)
            }),
        )
    }
}

/// One validated capability. Fields are private and read through getters:
/// other crates can neither build one nor change a copy of one, so every
/// `Capability` holds exactly what a validated [`Manifest`] said.
///
/// # Compile-fail: no field writes, even on a clone (review F-5)
///
/// ```compile_fail,E0616
/// use harness_manifest::{builtin, Effect, SemVer, ValidationContext};
/// let ctx = ValidationContext::new(SemVer { major: 0, minor: 0, patch: 1 }, &[]).unwrap();
/// let m = builtin::manifest(&ctx).unwrap();
/// let mut c = m.capabilities()[0].clone();
/// c.effect = Effect::Irreversible;
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Capability {
    /// `<provider>.<verb...>`.
    id: CapId,
    /// Server tool name (mcp-stdio only; `None` otherwise).
    mcp_name: Option<String>,
    /// Shown to humans in approvals.
    summary: String,
    /// Effect class.
    effect: Effect,
    /// Data sensitivity.
    sensitivity: Sensitivity,
    /// Blast radius.
    blast_radius: BlastRadius,
    /// Egress.
    egress: Egress,
    /// Content provenance.
    content: Content,
    /// Declared confirmation floor.
    confirmation: Confirmation,
    /// Validated input schema.
    input_schema: InputSchema,
    /// Pinned schema hash (non-builtin transports only).
    schema_sha256: Option<Sha256Pin>,
    /// Pinned description hash (non-builtin transports only).
    description_sha256: Option<Sha256Pin>,
    /// Secret handle names.
    secrets: Vec<String>,
    /// Limits (tighten only).
    limits: Limits,
}

impl Capability {
    /// `<provider>.<verb...>`.
    pub fn id(&self) -> &CapId {
        &self.id
    }
    /// Server tool name (mcp-stdio only).
    pub fn mcp_name(&self) -> Option<&str> {
        self.mcp_name.as_deref()
    }
    /// Human-facing summary (validated text).
    pub fn summary(&self) -> &str {
        &self.summary
    }
    /// Effect class.
    pub fn effect(&self) -> Effect {
        self.effect
    }
    /// Data sensitivity.
    pub fn sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
    /// Blast radius.
    pub fn blast_radius(&self) -> BlastRadius {
        self.blast_radius
    }
    /// Egress.
    pub fn egress(&self) -> Egress {
        self.egress
    }
    /// Content provenance.
    pub fn content(&self) -> Content {
        self.content
    }
    /// Declared confirmation floor.
    pub fn confirmation(&self) -> Confirmation {
        self.confirmation
    }
    /// Validated input schema.
    pub fn input_schema(&self) -> &InputSchema {
        &self.input_schema
    }
    /// Pinned schema hash (non-builtin transports only).
    pub fn schema_sha256(&self) -> Option<Sha256Pin> {
        self.schema_sha256
    }
    /// Pinned description hash (non-builtin transports only).
    pub fn description_sha256(&self) -> Option<Sha256Pin> {
        self.description_sha256
    }
    /// Secret handle names.
    pub fn secrets(&self) -> &[String] {
        &self.secrets
    }
    /// Limits (tighten only).
    pub fn limits(&self) -> Limits {
        self.limits
    }
}

/// Where a manifest's bytes came from. Only this crate produces a
/// `Compiled` manifest (the public [`Manifest::parse`] always validates as
/// `External`), so only the built-in manifest can use the reserved
/// `harness` namespace or the `builtin` transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Compiled into the binary ([`builtin::manifest`]).
    Compiled,
    /// Loaded from outside (a provider's `manifest.json`).
    External,
}

/// A manifest whose content was validated. Fields are private: the only
/// constructors are [`Manifest::parse`] and [`builtin::manifest`].
#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    schema_version: u32,
    provider: ProviderName,
    provider_version: String,
    min_harness: SemVer,
    transport: Transport,
    mcp_protocols: Vec<String>,
    capabilities: Vec<Capability>,
    origin: Origin,
}

impl Manifest {
    /// Parse and validate an EXTERNAL manifest (a provider's
    /// `manifest.json`). Reserved namespaces and the `builtin` transport are
    /// refused here whatever the bytes say.
    pub fn parse(bytes: &[u8], ctx: &ValidationContext) -> Result<Self, ManifestError> {
        parse_with_origin(bytes, ctx, Origin::External)
    }

    /// Schema version (always in [`SUPPORTED_SCHEMA_VERSIONS`]).
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }
    /// Provider namespace.
    pub fn provider(&self) -> &ProviderName {
        &self.provider
    }
    /// Provider's own version string (recorded, not interpreted).
    pub fn provider_version(&self) -> &str {
        &self.provider_version
    }
    /// Oldest harness this manifest accepts.
    pub fn min_harness(&self) -> SemVer {
        self.min_harness
    }
    /// Transport.
    pub fn transport(&self) -> &Transport {
        &self.transport
    }
    /// MCP protocol versions (mcp-stdio only).
    pub fn mcp_protocols(&self) -> &[String] {
        &self.mcp_protocols
    }
    /// The capabilities, in manifest order.
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }
    /// Where the bytes came from.
    pub fn origin(&self) -> Origin {
        self.origin
    }
}

/// What validation needs from outside: the running harness's version and
/// the config's additive reserved names.
#[derive(Debug, Clone)]
pub struct ValidationContext {
    harness_version: SemVer,
    reserved: BTreeSet<String>,
}

impl ValidationContext {
    /// `extra_reserved` can only ADD names to [`RESERVED_NAMESPACES`]; there
    /// is no way to remove one (§4.3). Each extra name must itself be a
    /// valid provider name, or the config is refused.
    pub fn new(harness_version: SemVer, extra_reserved: &[String]) -> Result<Self, ManifestError> {
        let mut reserved: BTreeSet<String> = RESERVED_NAMESPACES
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        for extra in extra_reserved {
            ProviderName::new(extra)?;
            reserved.insert(extra.clone());
        }
        Ok(Self {
            harness_version,
            reserved,
        })
    }

    /// Whether `name` is in the effective reserved set.
    pub fn is_reserved(&self, name: &str) -> bool {
        self.reserved.contains(name)
    }

    /// The running harness's version.
    pub fn harness_version(&self) -> SemVer {
        self.harness_version
    }
}

/// Which structural problem serde reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapeKind {
    /// A field the schema does not know.
    UnknownField,
    /// A value outside a closed set (e.g. `effect: "delete"`).
    UnknownValue,
    /// A required field is absent.
    MissingField,
    /// Anything else (wrong JSON type, ...).
    Other,
}

/// Why a manifest was refused. Every variant is a refusal; there is no
/// "accepted with warnings".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    /// Larger than [`MANIFEST_MAX_BYTES`].
    #[error("manifest is {len} bytes; the cap is {max}")]
    TooLarge {
        /// Size.
        len: usize,
        /// Cap.
        max: usize,
    },
    /// Not one well-formed JSON value.
    #[error("manifest is not well-formed JSON: {0}")]
    Json(String),
    /// A JSON object repeats a key (any depth).
    #[error("manifest repeats a JSON key: {0}")]
    DuplicateKey(String),
    /// `schema_version` missing or not a non-negative integer.
    #[error("manifest has no integer schema_version")]
    NoSchemaVersion,
    /// The scaffold format.
    #[error("manifest schema_version 0 is the pre-v1 scaffold format (this harness supports {supported:?}); migrate: rename app to provider and app_version to provider_version, add min_harness, transport and every per-capability dimension (design §4.1)")]
    SchemaV0 {
        /// Versions this harness supports.
        supported: &'static [u32],
    },
    /// A version this harness does not support.
    #[error("manifest schema_version {found} is not supported by this harness (supported: {supported:?})")]
    UnsupportedSchema {
        /// What the manifest says.
        found: u64,
        /// Versions this harness supports.
        supported: &'static [u32],
    },
    /// Structural error: unknown field, unknown enum value, missing field.
    #[error("manifest shape refused ({kind:?}): {detail}")]
    Shape {
        /// Classified kind.
        kind: ShapeKind,
        /// serde's message.
        detail: String,
    },
    /// A reserved namespace.
    #[error("provider name {0:?} is reserved")]
    ReservedProvider(String),
    /// A name outside the grammar.
    #[error("{field} {value:?} is not a valid name: use 1..={max} bytes of ASCII lowercase letters, digits, '-' or '_' (dots only as the id separator)")]
    InvalidName {
        /// Which field.
        field: &'static str,
        /// The offending value (bounded).
        value: String,
        /// Its length cap.
        max: usize,
    },
    /// A field over its length or count cap.
    #[error("{field} is {len}; the cap is {max}")]
    TooLong {
        /// Which field.
        field: &'static str,
        /// Actual length or count.
        len: usize,
        /// Cap.
        max: usize,
    },
    /// Text with a forbidden character (control, zero-width, bidi, or
    /// outside the allowlist). Refused, never stripped.
    #[error("{field} has a forbidden character at byte {at}")]
    ForbiddenChar {
        /// Which field.
        field: &'static str,
        /// Byte offset.
        at: usize,
    },
    /// Empty text where content is required.
    #[error("{0} is empty")]
    EmptyField(&'static str),
    /// No capabilities.
    #[error("manifest for {0} declares no capabilities")]
    NoCapabilities(String),
    /// An id outside the provider's namespace.
    #[error("capability {id} is not under provider namespace {provider}")]
    ForeignNamespace {
        /// Provider.
        provider: String,
        /// Offending id.
        id: String,
    },
    /// Two capabilities share an id.
    #[error("duplicate capability id {0}")]
    DuplicateId(String),
    /// Two capabilities share an `mcp_name`.
    #[error("mcp_name {0:?} is mapped twice")]
    DuplicateMcpName(String),
    /// Not a strict `MAJOR.MINOR.PATCH`.
    #[error("{field} {value:?} is not a strict MAJOR.MINOR.PATCH")]
    BadSemVer {
        /// Which field.
        field: &'static str,
        /// Offending value (bounded).
        value: String,
    },
    /// This harness is older than the manifest's `min_harness`.
    #[error("manifest needs harness >= {need}; this is {have}")]
    HarnessTooOld {
        /// `min_harness`.
        need: SemVer,
        /// Running harness.
        have: SemVer,
    },
    /// Only the compiled-in manifest may use the builtin transport.
    #[error("transport builtin is reserved for the manifest compiled into the harness")]
    BuiltinTransportExternal,
    /// A per-transport field present where it means nothing, or absent where
    /// it is required.
    #[error("{field} is {} for transport {transport}", if *.required { "required" } else { "not allowed" })]
    TransportField {
        /// Which field.
        field: &'static str,
        /// The manifest's transport.
        transport: &'static str,
        /// Whether it was missing (true) or superfluous (false).
        required: bool,
    },
    /// A transport value with bad content.
    #[error("transport {transport}: {detail}")]
    BadTransport {
        /// Transport kind.
        transport: &'static str,
        /// What is wrong.
        detail: String,
    },
    /// An input schema outside the subset.
    #[error("capability {capability}: input_schema refused at {at}: {detail}")]
    Schema {
        /// Capability id.
        capability: String,
        /// Location.
        at: String,
        /// What is wrong.
        detail: String,
    },
    /// A hex pin that is not 64 lowercase hex characters.
    #[error("capability {capability}: {field} is not 64 lowercase hex characters")]
    BadPin {
        /// Capability id.
        capability: String,
        /// Which pin.
        field: &'static str,
    },
    /// An explicit JSON `null`. Manifest v1 has no nullable field: an
    /// optional field is either absent or carries a value.
    #[error("manifest has a null value at {0}")]
    NullValue(String),
    /// Limits that are zero or empty.
    #[error("capability {0}: limits must set at least one value, each > 0")]
    BadLimits(String),
}

fn shape(e: &serde_json::Error) -> ManifestError {
    let raw = e.to_string();
    let kind = if raw.starts_with("unknown field") {
        ShapeKind::UnknownField
    } else if raw.starts_with("unknown variant") {
        ShapeKind::UnknownValue
    } else if raw.starts_with("missing field") {
        ShapeKind::MissingField
    } else {
        ShapeKind::Other
    };
    // serde quotes the offending key or value verbatim.
    ManifestError::Shape {
        kind,
        detail: display_safe(&raw, 512),
    }
}

/// Zero-width and bidi-control code points (design §2.3, §4.3).
fn is_invisible_or_bidi(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}'
        | '\u{180B}'..='\u{180F}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{206F}' | '\u{3164}' | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}'
        | '\u{FFA0}' | '\u{FFF0}'..='\u{FFFB}' | '\u{E0000}'..='\u{E0FFF}')
}

/// Human-facing text (§4.1 `summary`): printable ASCII (space included) plus
/// non-ASCII LETTERS; never control, zero-width or bidi characters. An
/// allowlist, so an unlisted invisible character is refused by default.
fn check_human_text(field: &'static str, s: &str, max: usize) -> Result<(), ManifestError> {
    if s.is_empty() {
        return Err(ManifestError::EmptyField(field));
    }
    if s.len() > max {
        return Err(ManifestError::TooLong {
            field,
            len: s.len(),
            max,
        });
    }
    for (at, c) in s.char_indices() {
        let ok = if c.is_ascii() {
            c == ' ' || c.is_ascii_graphic()
        } else {
            c.is_alphabetic() && !is_invisible_or_bidi(c)
        };
        if !ok {
            return Err(ManifestError::ForbiddenChar { field, at });
        }
    }
    Ok(())
}

pub(crate) fn parse_with_origin(
    bytes: &[u8],
    ctx: &ValidationContext,
    origin: Origin,
) -> Result<Manifest, ManifestError> {
    if bytes.len() > MANIFEST_MAX_BYTES {
        return Err(ManifestError::TooLarge {
            len: bytes.len(),
            max: MANIFEST_MAX_BYTES,
        });
    }
    let value = strict_json::parse(bytes).map_err(|e| {
        let msg = e.to_string();
        if msg.contains(strict_json::DUPLICATE_KEY) {
            ManifestError::DuplicateKey(msg)
        } else {
            ManifestError::Json(msg)
        }
    })?;

    // Version first, so a v0 or v2 manifest gets a version message rather
    // than an "unknown field" one (§4.7: naming both versions).
    let version = value
        .get("schema_version")
        .and_then(Value::as_u64)
        .ok_or(ManifestError::NoSchemaVersion)?;
    if !SUPPORTED_SCHEMA_VERSIONS
        .iter()
        .any(|v| u64::from(*v) == version)
    {
        return Err(if version == 0 {
            ManifestError::SchemaV0 {
                supported: SUPPORTED_SCHEMA_VERSIONS,
            }
        } else {
            ManifestError::UnsupportedSchema {
                found: version,
                supported: SUPPORTED_SCHEMA_VERSIONS,
            }
        });
    }

    // Reserved names BEFORE any per-capability check (§4.3).
    if let Some(p) = value.get("provider").and_then(Value::as_str) {
        if origin == Origin::External && ctx.is_reserved(p) {
            return Err(ManifestError::ReservedProvider(shown(p)));
        }
    }

    // No nullable field exists in v1: an explicit null is refused rather than
    // read as "absent" by `#[serde(default)]` (review F-3). It runs after
    // the version and reserved-name checks so those keep their own messages
    // (H1b confirming review NF-1), and before the typed parse.
    if let Some(at) = find_null(&value, String::new()) {
        return Err(ManifestError::NullValue(at));
    }

    let wire: ManifestWire = serde_json::from_value(value).map_err(|e| shape(&e))?;
    validate(wire, ctx, origin)
}

fn validate(
    w: ManifestWire,
    ctx: &ValidationContext,
    origin: Origin,
) -> Result<Manifest, ManifestError> {
    let provider = ProviderName::new(&w.provider)?;
    match origin {
        Origin::External if ctx.is_reserved(provider.as_str()) => {
            return Err(ManifestError::ReservedProvider(provider.0));
        }
        // The compiled-in manifest is exactly the builtin namespace.
        Origin::Compiled if provider.as_str() != BUILTIN_NAMESPACE => {
            return Err(ManifestError::ReservedProvider(provider.0));
        }
        _ => {}
    }

    if w.provider_version.is_empty() {
        return Err(ManifestError::EmptyField("provider_version"));
    }
    if w.provider_version.len() > PROVIDER_VERSION_MAX {
        return Err(ManifestError::TooLong {
            field: "provider_version",
            len: w.provider_version.len(),
            max: PROVIDER_VERSION_MAX,
        });
    }
    if let Some((at, _)) = w
        .provider_version
        .char_indices()
        .find(|(_, c)| !c.is_ascii_graphic())
    {
        return Err(ManifestError::ForbiddenChar {
            field: "provider_version",
            at,
        });
    }

    let min_harness = SemVer::parse(&w.min_harness).ok_or_else(|| ManifestError::BadSemVer {
        field: "min_harness",
        value: shown(&w.min_harness),
    })?;
    if ctx.harness_version < min_harness {
        return Err(ManifestError::HarnessTooOld {
            need: min_harness,
            have: ctx.harness_version,
        });
    }

    let transport = validate_transport(w.transport, origin)?;
    let kind = transport.kind();
    let is_mcp = matches!(transport, Transport::McpStdio { .. });
    let is_builtin = matches!(transport, Transport::Builtin);

    // mcp_protocols: required (non-empty) for mcp-stdio, refused otherwise.
    if is_mcp && w.mcp_protocols.is_empty() {
        return Err(ManifestError::TransportField {
            field: "mcp_protocols",
            transport: kind,
            required: true,
        });
    }
    if !is_mcp && !w.mcp_protocols.is_empty() {
        return Err(ManifestError::TransportField {
            field: "mcp_protocols",
            transport: kind,
            required: false,
        });
    }
    let mut seen_proto = BTreeSet::new();
    for p in &w.mcp_protocols {
        if !is_date_version(p) || !seen_proto.insert(p.as_str()) {
            return Err(ManifestError::BadTransport {
                transport: kind,
                detail: format!(
                    "mcp_protocols entry {:?} is not a unique YYYY-MM-DD version",
                    shown(p)
                ),
            });
        }
    }

    if w.capabilities.is_empty() {
        return Err(ManifestError::NoCapabilities(provider.0));
    }
    if w.capabilities.len() > CAPABILITIES_MAX {
        return Err(ManifestError::TooLong {
            field: "capabilities",
            len: w.capabilities.len(),
            max: CAPABILITIES_MAX,
        });
    }

    let mut ids = BTreeSet::new();
    let mut mcp_names = BTreeSet::new();
    let mut capabilities = Vec::with_capacity(w.capabilities.len());
    for c in w.capabilities {
        let id = CapId::new(&c.id)?;
        if id.provider() != provider.as_str() {
            return Err(ManifestError::ForeignNamespace {
                provider: provider.0.clone(),
                id: id.0,
            });
        }
        if !ids.insert(id.0.clone()) {
            return Err(ManifestError::DuplicateId(id.0));
        }

        // mcp_name: exactly for mcp-stdio, 1:1.
        match (&c.mcp_name, is_mcp) {
            (None, true) => {
                return Err(ManifestError::TransportField {
                    field: "mcp_name",
                    transport: kind,
                    required: true,
                })
            }
            (Some(_), false) => {
                return Err(ManifestError::TransportField {
                    field: "mcp_name",
                    transport: kind,
                    required: false,
                })
            }
            (Some(n), true) => {
                let ok = !n.is_empty()
                    && n.len() <= MCP_NAME_MAX
                    && n.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
                if !ok {
                    return Err(ManifestError::InvalidName {
                        field: "mcp_name",
                        value: shown(n),
                        max: MCP_NAME_MAX,
                    });
                }
                if !mcp_names.insert(n.clone()) {
                    return Err(ManifestError::DuplicateMcpName(n.clone()));
                }
            }
            (None, false) => {}
        }

        check_human_text("summary", &c.summary, SUMMARY_MAX)?;

        let input_schema = InputSchema::new(c.input_schema).map_err(|e| ManifestError::Schema {
            capability: id.0.clone(),
            at: e.at,
            detail: e.detail,
        })?;

        // Pins: required for every non-builtin transport (checked at connect
        // time, H4), refused on builtin tools (nothing to compare against).
        let pin =
            |field: &'static str, v: &Option<String>| -> Result<Option<Sha256Pin>, ManifestError> {
                match (v, is_builtin) {
                    (None, true) => Ok(None),
                    (Some(_), true) => Err(ManifestError::TransportField {
                        field,
                        transport: kind,
                        required: false,
                    }),
                    (None, false) => Err(ManifestError::TransportField {
                        field,
                        transport: kind,
                        required: true,
                    }),
                    (Some(h), false) => {
                        Sha256Pin::parse_hex(h)
                            .map(Some)
                            .ok_or_else(|| ManifestError::BadPin {
                                capability: id.0.clone(),
                                field,
                            })
                    }
                }
            };
        let schema_sha256 = pin("schema_sha256", &c.schema_sha256)?;
        let description_sha256 = pin("description_sha256", &c.description_sha256)?;

        if c.secrets.len() > SECRETS_MAX {
            return Err(ManifestError::TooLong {
                field: "secrets",
                len: c.secrets.len(),
                max: SECRETS_MAX,
            });
        }
        let mut seen_secret = BTreeSet::new();
        for s in &c.secrets {
            check_name("secret handle", s, false, PROVIDER_MAX)?;
            if !seen_secret.insert(s.as_str()) {
                return Err(ManifestError::InvalidName {
                    field: "secret handle (duplicate)",
                    value: shown(s),
                    max: PROVIDER_MAX,
                });
            }
        }

        let limits = match c.limits {
            None => Limits::default(),
            Some(l) => {
                let bad = l.timeout_ms == Some(0)
                    || l.max_result_bytes == Some(0)
                    || (l.timeout_ms.is_none() && l.max_result_bytes.is_none());
                if bad {
                    return Err(ManifestError::BadLimits(id.0));
                }
                Limits {
                    timeout_ms: l.timeout_ms,
                    max_result_bytes: l.max_result_bytes,
                }
            }
        };

        capabilities.push(Capability {
            id,
            mcp_name: c.mcp_name,
            summary: c.summary,
            effect: c.effect,
            sensitivity: c.sensitivity,
            blast_radius: c.blast_radius,
            egress: c.egress,
            content: c.content,
            confirmation: c.confirmation,
            input_schema,
            schema_sha256,
            description_sha256,
            secrets: c.secrets,
            limits,
        });
    }

    Ok(Manifest {
        schema_version: w.schema_version,
        provider,
        provider_version: w.provider_version,
        min_harness,
        transport,
        mcp_protocols: w.mcp_protocols,
        capabilities,
        origin,
    })
}

fn validate_transport(t: TransportWire, origin: Origin) -> Result<Transport, ManifestError> {
    match (t, origin) {
        (TransportWire::Builtin {}, Origin::Compiled) => Ok(Transport::Builtin),
        (TransportWire::Builtin {}, Origin::External) => {
            Err(ManifestError::BuiltinTransportExternal)
        }
        (_, Origin::Compiled) => Err(ManifestError::BadTransport {
            transport: "builtin",
            detail: "the compiled-in manifest must use transport builtin".into(),
        }),
        (TransportWire::McpStdio { argv, env_allow }, Origin::External) => {
            let bad = |detail: String| ManifestError::BadTransport {
                transport: "mcp-stdio",
                detail,
            };
            let Some(prog) = argv.first() else {
                return Err(bad("argv is empty".into()));
            };
            // Absolute on every OS: `/…` or `X:\…`. A bare name would be
            // resolved against PATH at spawn time, which the manifest's
            // reviewer never saw.
            let pb = prog.as_bytes();
            let absolute = pb.first() == Some(&b'/')
                || (pb.len() > 3
                    && pb.first().is_some_and(u8::is_ascii_alphabetic)
                    && pb.get(1) == Some(&b':')
                    && pb.get(2) == Some(&b'\\'));
            if !absolute {
                return Err(bad("argv[0] must be an absolute path".into()));
            }
            // Review F-8: `//host/share/…` (any mix of `/` and `\`) is UNC on
            // Windows, a spawn over the network; a `..` component makes the
            // reviewed path mean another file.
            let sep = |b: Option<&u8>| matches!(b, Some(b'/') | Some(b'\\'));
            if sep(pb.first()) && sep(pb.get(1)) {
                return Err(bad("argv[0] must not be a UNC path".into()));
            }
            if prog.split(['/', '\\']).any(|c| c == "..") {
                return Err(bad("argv[0] must not contain a '..' component".into()));
            }
            if argv.iter().any(|a| a.chars().any(char::is_control)) {
                return Err(bad("argv contains a control character".into()));
            }
            let mut seen = BTreeSet::new();
            for e in &env_allow {
                let ok = !e.is_empty()
                    && e.len() <= 64
                    && e.bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                    && !e.as_bytes().first().is_some_and(u8::is_ascii_digit);
                if !ok || !seen.insert(e.as_str()) {
                    return Err(bad(format!(
                        "env_allow entry {:?} is not a unique [A-Z_][A-Z0-9_]*",
                        shown(e)
                    )));
                }
            }
            Ok(Transport::McpStdio { argv, env_allow })
        }
        (TransportWire::InProcess { feature }, Origin::External) => {
            check_name("in-process feature", &feature, false, PROVIDER_MAX)?;
            Ok(Transport::InProcess { feature })
        }
    }
}

/// JSON-pointer-like location of the first `null` in `v`, if any.
fn find_null(v: &Value, at: String) -> Option<String> {
    match v {
        Value::Null => Some(if at.is_empty() { "/".into() } else { at }),
        Value::Array(a) => a
            .iter()
            .enumerate()
            .find_map(|(i, e)| find_null(e, format!("{at}/{i}"))),
        Value::Object(o) => o
            .iter()
            .find_map(|(k, e)| find_null(e, format!("{at}/{}", display_safe(k, 80)))),
        _ => None,
    }
}

/// `YYYY-MM-DD`, the MCP protocol-version shape.
fn is_date_version(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b.iter().enumerate().all(|(i, c)| {
            if i == 4 || i == 7 {
                *c == b'-'
            } else {
                c.is_ascii_digit()
            }
        })
}

#[cfg(test)]
mod tests;
