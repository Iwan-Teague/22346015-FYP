//! Manifest pins and MCP protocol negotiation (P-37 design note §6.1, §3.3).
//!
//! What a server says about itself is COMPARED, never trusted and never
//! shown to the model (D5): the manifest's reviewed `description_sha256`
//! and `schema_sha256` pins are checked against the server's `tools/list`
//! claims ([`compare`]). A drift quarantines the capability and, when it is
//! granted, stops the run before the first model call (§7.1); this module
//! is the pure half the audit recomputes.
//!
//! Digests:
//! - [`description_digest`]: SHA-256 of the exact UTF-8 bytes of the
//!   server's `description` string; a tool with no description hashes the
//!   empty string. The text is never inspected — it is hashed byte-exact.
//! - [`schema_digest`]: SHA-256 of the canonical JSON of `inputSchema`:
//!   compact, object keys sorted (`serde_json::Value` without
//!   `preserve_order` is a sorted map), numbers as `serde_json` prints
//!   them. The same parsed form is hashed at admission and at connect.
//!
//! [`negotiate`] picks the MCP protocol version to request (D2): the
//! highest entry this build supports ([`SUPPORTED_MCP_PROTOCOLS`]) that the
//! manifest also declares; none in common refuses the provider at
//! admission.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use harness_core::{sha256, Digest};

use crate::{Capability, Manifest, Sha256Pin, Transport};

/// The MCP protocol versions this build speaks (D2). Adding one is a
/// reviewed code change that adds the fixture's wire tests for it; a
/// version we have not wire-tested is refused, not spoken hopefully.
pub const SUPPORTED_MCP_PROTOCOLS: &[&str] = &["2025-06-18"];

/// Why no protocol version could be chosen: the manifest and this build
/// share none, so there is no dialect both sides were reviewed to speak.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("no MCP protocol version in common: this harness speaks {supported:?}, the manifest declares {declared:?}")]
pub struct NegotiateError {
    /// What this build speaks.
    pub supported: &'static [&'static str],
    /// What the manifest declared, as given.
    pub declared: Vec<String>,
}

/// The highest version in `SUPPORTED_MCP_PROTOCOLS ∩ declared` (D2). The
/// versions are fixed-width `YYYY-MM-DD`, so the highest is the
/// lexicographic maximum; requesting the highest common one keeps a newer
/// server on the newest dialect both sides know.
pub fn negotiate(declared: &[String]) -> Result<&'static str, NegotiateError> {
    let mut best: Option<&'static str> = None;
    for v in SUPPORTED_MCP_PROTOCOLS {
        if declared.iter().any(|d| d == v) {
            best = match best {
                Some(b) if b > v => Some(b),
                _ => Some(v),
            };
        }
    }
    best.ok_or(NegotiateError {
        supported: SUPPORTED_MCP_PROTOCOLS,
        declared: declared.to_vec(),
    })
}

/// SHA-256 of the exact UTF-8 bytes (§6.1). A tool with no `description`
/// hashes the empty string; the caller passes `""` for it.
pub fn description_digest(s: &str) -> Digest {
    sha256(s.as_bytes())
}

/// Canonical JSON: compact, object keys sorted at every depth, numbers as
/// `serde_json` prints them. `Value`'s `Display` is exactly this and cannot
/// fail, so no encoding fault can sneak a fallback past a pin.
fn canonical(v: &Value) -> String {
    v.to_string()
}

/// SHA-256 of the canonical JSON of the presented `inputSchema` (§6.1). The
/// same function runs at admission (over the manifest's reviewed schema)
/// and at connect (over the server's), over the same parsed form.
pub fn schema_digest(v: &Value) -> Digest {
    sha256(canonical(v).as_bytes())
}

/// What the server presented about one tool in `tools/list`. Untrusted data
/// built by the caller from the server's JSON: compared here, never shown
/// to the model — the manifest's reviewed summary and schema are what the
/// model sees (D5).
#[derive(Debug, Clone, PartialEq)]
pub struct PresentedTool {
    /// The server's `name` field.
    pub name: String,
    /// The server's `description`, if it sent one; an absent description
    /// hashes the empty string (§6.1).
    pub description: Option<String>,
    /// The server's `inputSchema`.
    pub input_schema: Value,
}

/// Per-capability pin status. The `as_str` spellings are the journal's
/// (`McpConnected.pins`, P-37 §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinStatus {
    /// Both pins match what the server presented.
    Ok,
    /// The presented description hashes to another pin.
    DescriptionDrift,
    /// The presented schema hashes to another pin.
    SchemaDrift,
    /// The manifest names a tool the server did not present.
    Missing,
}

impl PinStatus {
    /// Short name for journal records and messages.
    pub fn as_str(self) -> &'static str {
        match self {
            PinStatus::Ok => "ok",
            PinStatus::DescriptionDrift => "description",
            PinStatus::SchemaDrift => "schema",
            PinStatus::Missing => "missing",
        }
    }
}

/// The outcome of [`compare`]: every capability's pin status plus how many
/// presented tools the manifest does not name (dropped and counted, §6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinReport {
    statuses: BTreeMap<String, PinStatus>,
    dropped: usize,
}

impl PinReport {
    /// Status per manifest capability id.
    pub fn statuses(&self) -> &BTreeMap<String, PinStatus> {
        &self.statuses
    }

    /// Presented tools the manifest does not name: dropped, counted, never
    /// an error and never surfaced (§6.1).
    pub fn dropped(&self) -> usize {
        self.dropped
    }

    /// Whether every capability pins clean and nothing was dropped.
    pub fn is_clean(&self) -> bool {
        self.dropped == 0 && self.statuses.values().all(|s| *s == PinStatus::Ok)
    }
}

/// Why [`compare`] refused to run at all (the connection is refused, §6.1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompareError {
    /// The server presented one tool name twice: the binding to a
    /// capability would be ambiguous, and "first wins" would let a rug-pull
    /// hide behind the duplicate (§8.5).
    #[error("the server presented tool name {0:?} twice")]
    DuplicatePresentedName(String),
    /// [`compare`] is defined for mcp-stdio manifests only; a builtin or
    /// in-process manifest has no server to compare against.
    #[error("pins::compare needs an mcp-stdio manifest; this one is {0}")]
    NotMcpStdio(&'static str),
}

/// Compare a manifest's pins with what the server presented (§6.1). Every
/// manifest capability gets a [`PinStatus`]; presented tools the manifest
/// does not name are dropped and counted; a name presented twice is an
/// error, refused before anything is compared.
pub fn compare(
    manifest: &Manifest,
    presented: &[PresentedTool],
) -> Result<PinReport, CompareError> {
    if !matches!(manifest.transport(), Transport::McpStdio { .. }) {
        return Err(CompareError::NotMcpStdio(manifest.transport().kind()));
    }

    let mut seen = BTreeSet::new();
    for t in presented {
        if !seen.insert(t.name.as_str()) {
            return Err(CompareError::DuplicatePresentedName(t.name.clone()));
        }
    }
    let by_name: BTreeMap<&str, &PresentedTool> =
        presented.iter().map(|t| (t.name.as_str(), t)).collect();
    let mcp_names: BTreeSet<&str> = manifest
        .capabilities()
        .iter()
        .filter_map(Capability::mcp_name)
        .collect();
    let dropped = presented
        .iter()
        .filter(|t| !mcp_names.contains(t.name.as_str()))
        .count();

    // An absent pin cannot prove a match, so it refuses as drift: the
    // fail-closed reading of "required for non-builtin transports".
    let pins_match = |pin: Option<Sha256Pin>, digest: Digest| {
        pin.is_some_and(|p| p.as_bytes() == digest.as_bytes())
    };

    let mut statuses = BTreeMap::new();
    for c in manifest.capabilities() {
        let Some(name) = c.mcp_name() else {
            // Unconstructable through `Manifest::parse` (an mcp-stdio
            // manifest requires an `mcp_name`); a status is still owed.
            statuses.insert(c.id().to_string(), PinStatus::Missing);
            continue;
        };
        let status = match by_name.get(name) {
            None => PinStatus::Missing,
            Some(t) => {
                // Either drift quarantines the capability, so one status is
                // enough; description is checked first.
                let description = t.description.as_deref().unwrap_or("");
                if !pins_match(c.description_sha256(), description_digest(description)) {
                    PinStatus::DescriptionDrift
                } else if !pins_match(c.schema_sha256(), schema_digest(&t.input_schema)) {
                    PinStatus::SchemaDrift
                } else {
                    PinStatus::Ok
                }
            }
        };
        statuses.insert(c.id().to_string(), status);
    }

    Ok(PinReport { statuses, dropped })
}
