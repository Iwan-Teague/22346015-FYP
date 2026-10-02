//! Pure record encoding and the hash chain (design §7.1). No I/O.
//!
//! A record line is the compact JSON of an object with sorted keys
//! (`serde_json`'s default map is a `BTreeMap`, and this workspace does not
//! enable `preserve_order`):
//!
//! ```text
//! {"attempt":n,"body":{..},"hash":"<hex>","kind":"..","prev":"<hex>","run":"..","seq":N,"step":k,"t_mono_ms":..,"t_wall":".."}
//! ```
//!
//! `hash = sha256(prev_bytes || canonical(line without "hash"))`, and the
//! first record's `prev` is 32 zero bytes. The reader accepts a line only if
//! it is byte-for-byte the canonical encoding of what it parsed, so a
//! duplicated key, reordered keys, extra whitespace or a re-escaped string
//! are all refused, not normalised.

use core::net::IpAddr;
use std::fmt;

use harness_core::{sha256_parts, Digest};
use serde_json::{Map, Value};

/// `prev` of the first record.
pub const GENESIS: Digest = Digest::from_bytes([0u8; 32]);

/// Largest untrusted payload carried inline in a record, in bytes (§7.1).
pub const INLINE_MAX: usize = 4096;

/// Harness-controlled identifier text: 1..=128 bytes of ASCII
/// `[A-Za-z0-9._-]`. No spaces, quotes, backslashes, control characters,
/// `/`, `:` or `@`, so an `Ident` can carry no markup, escape, path or URL.
///
/// **Provenance rule (review F-6).** A trusted field says "the harness
/// vouches for this value". `Ident` is therefore ONLY for values the harness
/// minted itself (run ids, attempt keys, reason codes) or already validated
/// against a closed grammar it owns (capability ids from an admitted
/// manifest, versions, budget dimensions). Anything a model, tool, file or
/// task produced (paths, URLs, arguments, names chosen at run time) goes
/// into an [`crate::UntrustedBlob`], even when it happens to fit this
/// grammar. The grammar keeps paths and URLs out by construction; the
/// typed constructors below keep runtime text out (closed in H1e-1).
///
/// **Typed provenance (H1c review F-6, closed in H1e-1).** There is no
/// public constructor from a runtime `&str`. An `Ident` comes from:
/// - [`Ident::of`]: a `&'static str` (compile-time harness text), or
/// - [`Ident::from_trusted`]: a value implementing the sealed
///   `harness_core::TrustedName` (a `RunId` or a `Nonce`), or
/// - [`Ident::from_capability`]: an admitted manifest's `Capability`.
///
/// The grammar also refuses a leading `.` or `-` (so never `.`, `..`,
/// `.hidden` or `-rf`; H1c confirming review NF-3).
///
/// ```compile_fail,E0624
/// let _ = harness_journal::Ident::new("from-runtime-text");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ident(String);

impl Ident {
    /// Check `s` against the identifier grammar (crate-internal).
    pub(crate) fn new(s: &str) -> Option<Self> {
        let ok = !s.is_empty()
            && s.len() <= 128
            && s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        ok.then(|| Self(s.to_owned()))
    }

    /// Compile-time harness text (a reason code, a key, a version).
    pub fn of(s: &'static str) -> Option<Self> {
        Self::new(s)
    }

    /// Text a trusted type vouches for (typed provenance). `TrustedName`
    /// is sealed in `harness-core` (H1e-1 review NF-C): only `RunId` and
    /// `Nonce` implement it.
    ///
    /// A `CapId` cannot vouch: `CapId::new` accepts any text that fits the
    /// id grammar, model text included (NF-C).
    ///
    /// ```compile_fail,E0277
    /// let id = harness_manifest::CapId::new("fixture.any.text").unwrap();
    /// let _ = harness_journal::Ident::from_trusted(&id);
    /// ```
    pub fn from_trusted<T: harness_core::TrustedName + ?Sized>(t: &T) -> Option<Self> {
        Self::new(t.trusted_name())
    }

    /// A capability's id. A `Capability` exists only as part of a manifest
    /// that parsed and validated (trust-base input; private fields, no
    /// public constructor), so model or tool text cannot reach a trusted
    /// field this way, even when it happens to fit the id grammar
    /// (H1e-1 review NF-C: vouch for resolved capabilities, not for any
    /// grammatical `CapId`).
    pub fn from_capability(c: &harness_manifest::Capability) -> Option<Self> {
        Self::new(c.id().as_str())
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Ident {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Event kinds (design §7.2). A closed set: the reader refuses any other.
///
/// **Session kinds (P-05/P-10, hotspot H-E: reserved once).** Three are
/// defined now with their canonical field lists (the bodies are written by
/// the session loop, P-13); six more names are reserved for later slices,
/// which own their bodies. The reader accepts every name here;
/// `replay::recorded` treats a reserved kind as "not a shape the loop
/// writes" until its owner defines the body. Canonical bodies are JSON
/// objects whose keys are exactly the fields listed (sorted on the wire,
/// like every body):
///
/// - `UserTurn` (fsynced; one per user message, refused ones included):
///   `external_change` (Bool), `shown` (Text `yes` | `withheld` |
///   `over_share`), `text` (UntrustedBlob, `source: {"kind":"user"}`),
///   `turn` (U64, 1-based count of `UserTurn` records), `turn_steps`
///   (U64, the turn's step allowance), `wall_used_ms` (U64),
///   `workspace_files` (U64), `workspace_oversize` (U64),
///   `workspace_tree` (Digest).
/// - `TurnEnded` (fsynced; the turn boundary): `reason` (Text:
///   `answered`, `submitted`, `submitted_checks_failed`, `turn_steps`,
///   `format_errors`, `loop:repeat`, `loop:edit_churn`,
///   `loop:no_progress`, `loop:denied`, `model_unavailable`,
///   `input_refused`), `steps` (U64), `turn` (U64).
/// - `InputEnded` (fsynced; the user's input ended the session):
///   `reason` (Text `eof` | `exit` | `timeout`), `turn` (U64).
///
/// **Web airlock kinds (P-39c, hotspot H-E: defined once, here).** The
/// `Egress` name was reserved with the first wave and is fsynced (§4.5:
/// appended before any bytes are forwarded); the two research-note kinds
/// (§6, §7) are fsynced because a resume reads notes from the journal's
/// evidence, not from a hand-wave. Their canonical bodies
/// ([`check_canonical_body`] enforces exactly these keys and shapes; the
/// writer refuses anything else before a byte is written):
///
/// - `Egress` (fsynced; one per attempted fetch or search, allow or
///   refuse): `decision` (Text `allow` | `refuse:<reason>`, reason in the
///   closed set `non-global-address`, `no-address`, `dns-timeout`,
///   `budget`, `host-not-allowlisted`, `downgrade`), `host` (Text, the
///   lowercase DNS name or IP literal the request targeted, §8),
///   `hop` (U64, 0-based redirect hop), `ip` (null | Text IP address |
///   `delegated` in user-proxy mode), `mode` (Text `direct` |
///   `user-proxy` | `search-endpoint`), `port` (U64 ≤ 65535),
///   `purpose` (Text `fetch` | `search`), `resolved` (list of Text IP
///   addresses, the resolver answer in the order it is re-fed by audit),
///   `url` (UntrustedBlob with `source: {"kind":"model"}` per §4.5, the
///   model-supplied URL in its typed home).
/// - `NoteSaved` (fsynced; §6, one per research note written under
///   `<state_root>/research/notes/`): `bytes` (U64), `note` (Text, the
///   note's 64-hex SHA-256 id), `sources` (U64, count), `turn` (U64).
/// - `NoteImported` (fsynced; §7, a note promoted back into context):
///   `bytes` (UntrustedBlob, the file's bytes in their typed home),
///   `confirm` (Text `typed-id-prefix`, exact — INV-50), `note` (Text,
///   the note's 64-hex id), `path` (UntrustedBlob, the note's path),
///   `sha256` (Text, the payload's digest).
///
/// - Reserved: `ModeChanged` (P-28), `RuleGranted` (P-23), `Restored`
///   (P-22/P-26), `InstructionsLoaded` (P-30), `ForkedFrom` (P-32),
///   `ChildRun` (P-38). No code writes them in this wave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(missing_docs)] // names are the §7.2 table, verbatim
pub enum EventKind {
    RunStarted,
    ContextBuilt,
    ModelRequested,
    ModelReplied,
    ActionParsed,
    FormatError,
    PolicyDecided,
    ApprovalRequested,
    ApprovalGranted,
    ApprovalDenied,
    ApprovalExpired,
    ToolStarted,
    ToolFinished,
    EditApplied,
    Egress,
    Redacted,
    Quarantined,
    SandboxUnavailable,
    LoopDetected,
    BudgetCharged,
    BudgetNotice,
    SubmitRequested,
    PresubmitChecked,
    VerificationStarted,
    VerificationFinished,
    CheckReported,
    ReviewerRefused,
    ReviewReported,
    RunStopped,
    UserTurn,
    TurnEnded,
    InputEnded,
    ModeChanged,
    RuleGranted,
    Restored,
    InstructionsLoaded,
    ForkedFrom,
    ChildRun,
    NoteSaved,
    NoteImported,
}

const KINDS: &[(EventKind, &str)] = &[
    (EventKind::RunStarted, "RunStarted"),
    (EventKind::ContextBuilt, "ContextBuilt"),
    (EventKind::ModelRequested, "ModelRequested"),
    (EventKind::ModelReplied, "ModelReplied"),
    (EventKind::ActionParsed, "ActionParsed"),
    (EventKind::FormatError, "FormatError"),
    (EventKind::PolicyDecided, "PolicyDecided"),
    (EventKind::ApprovalRequested, "ApprovalRequested"),
    (EventKind::ApprovalGranted, "ApprovalGranted"),
    (EventKind::ApprovalDenied, "ApprovalDenied"),
    (EventKind::ApprovalExpired, "ApprovalExpired"),
    (EventKind::ToolStarted, "ToolStarted"),
    (EventKind::ToolFinished, "ToolFinished"),
    (EventKind::EditApplied, "EditApplied"),
    (EventKind::Egress, "Egress"),
    (EventKind::Redacted, "Redacted"),
    (EventKind::Quarantined, "Quarantined"),
    (EventKind::SandboxUnavailable, "SandboxUnavailable"),
    (EventKind::LoopDetected, "LoopDetected"),
    (EventKind::BudgetCharged, "BudgetCharged"),
    (EventKind::BudgetNotice, "BudgetNotice"),
    (EventKind::SubmitRequested, "SubmitRequested"),
    (EventKind::PresubmitChecked, "PresubmitChecked"),
    (EventKind::VerificationStarted, "VerificationStarted"),
    (EventKind::VerificationFinished, "VerificationFinished"),
    (EventKind::CheckReported, "CheckReported"),
    (EventKind::ReviewerRefused, "ReviewerRefused"),
    (EventKind::ReviewReported, "ReviewReported"),
    (EventKind::RunStopped, "RunStopped"),
    (EventKind::UserTurn, "UserTurn"),
    (EventKind::TurnEnded, "TurnEnded"),
    (EventKind::InputEnded, "InputEnded"),
    (EventKind::ModeChanged, "ModeChanged"),
    (EventKind::RuleGranted, "RuleGranted"),
    (EventKind::Restored, "Restored"),
    (EventKind::InstructionsLoaded, "InstructionsLoaded"),
    (EventKind::ForkedFrom, "ForkedFrom"),
    (EventKind::ChildRun, "ChildRun"),
    (EventKind::NoteSaved, "NoteSaved"),
    (EventKind::NoteImported, "NoteImported"),
];

impl EventKind {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        KINDS
            .iter()
            .find(|(k, _)| *k == self)
            .map_or("?", |(_, n)| n)
    }

    /// Parse a wire name; `None` for anything outside the closed set.
    pub fn parse(s: &str) -> Option<Self> {
        KINDS.iter().find(|(_, n)| *n == s).map(|(k, _)| *k)
    }

    /// Kinds the writer fsyncs right after appending (§7.1 "Detection and
    /// durability"): the header, every intent (`ToolStarted`, via
    /// `append_intent`) and result (`ToolFinished`), `Egress` (appended
    /// before forwarding), the verification events and `RunStopped`. The
    /// session kinds (P-05/P-10) are all fsynced: they are inputs or turn
    /// boundaries, and resume keys on them. The web airlock kinds (P-39c)
    /// are fsynced for the same reason: `Egress` is appended before any
    /// bytes are forwarded (§4.5), and the research notes (§6, §7) are
    /// evidence a resume reads back. Decided once, here, so owners never
    /// touch `canon.rs` again.
    pub fn needs_fsync(self) -> bool {
        matches!(
            self,
            EventKind::RunStarted
                | EventKind::ToolStarted
                | EventKind::ToolFinished
                | EventKind::Egress
                | EventKind::VerificationStarted
                | EventKind::CheckReported
                | EventKind::VerificationFinished
                | EventKind::RunStopped
                | EventKind::UserTurn
                | EventKind::TurnEnded
                | EventKind::InputEnded
                | EventKind::ModeChanged
                | EventKind::RuleGranted
                | EventKind::Restored
                | EventKind::InstructionsLoaded
                | EventKind::ForkedFrom
                | EventKind::ChildRun
                | EventKind::NoteSaved
                | EventKind::NoteImported
        )
    }
}

/// The canonical body fields of the web airlock kinds (P-39c, design
/// §4.5, §6, §7), sorted like the wire (every body's keys are sorted on
/// the record line). `None` for kinds whose bodies their owning slices
/// still define: the writer polices only what is defined here, so nothing
/// written before P-39c changes shape.
pub fn canonical_body_keys(kind: EventKind) -> Option<&'static [&'static str]> {
    match kind {
        EventKind::Egress => Some(&[
            "decision", "hop", "host", "ip", "mode", "port", "purpose", "resolved", "url",
        ]),
        EventKind::NoteSaved => Some(&["bytes", "note", "sources", "turn"]),
        EventKind::NoteImported => Some(&["bytes", "confirm", "note", "path", "sha256"]),
        _ => None,
    }
}

/// Refusal reasons an `Egress` record may carry (§4.5). Closed.
const EGRESS_REFUSALS: &[&str] = &[
    "non-global-address",
    "no-address",
    "dns-timeout",
    "budget",
    "host-not-allowlisted",
    "downgrade",
];

/// `allow`, or `refuse:` plus a reason from the closed set.
fn check_egress_decision(s: &str) -> Result<(), &'static str> {
    if s == "allow" {
        return Ok(());
    }
    let refused = s
        .strip_prefix("refuse:")
        .ok_or("Egress: \"decision\" is \"allow\" or \"refuse:<reason>\"")?;
    if EGRESS_REFUSALS.contains(&refused) {
        Ok(())
    } else {
        Err("Egress: unknown \"refuse:\" reason")
    }
}

/// A lowercase DNS name (labels of `[a-z0-9-]`, 1..=63 bytes each, no
/// leading or trailing hyphen, no empty label, ≤ 253 bytes) — or an IP
/// literal (§8's search-endpoint mode addresses the resolver by IP). A
/// shape backstop only: the authoritative host check is the airlock's
/// (P-39a), which the `Egress` record merely evidences.
fn is_egress_host(s: &str) -> bool {
    if s.parse::<IpAddr>().is_ok() {
        return true;
    }
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// A field that must be an IP address in text form.
fn as_ip(s: &str) -> Result<(), &'static str> {
    if s.parse::<IpAddr>().is_ok() {
        Ok(())
    } else {
        Err("expected an IP address")
    }
}

/// A field that must be a digest in text form (64 lowercase hex).
fn as_digest_str(s: &str) -> Result<(), &'static str> {
    if s.parse::<Digest>().is_ok() {
        Ok(())
    } else {
        Err("expected a 64-hex digest")
    }
}

/// An untrusted payload home: a JSON object carrying the reserved
/// `"untrusted": true` marker (the reader's `check_blob` does the deep
/// check against the blob store; this is the body's shape).
fn is_untrusted_home(o: &Map<String, Value>) -> bool {
    o.get(crate::event::UNTRUSTED_KEY) == Some(&Value::Bool(true))
}

/// Check a body against its kind's canonical field list
/// ([`canonical_body_keys`]): exactly those keys, and each value in the
/// shape §4.5/§6/§7 give it. Kinds with no list yet are accepted
/// unchanged. The writer calls this before anything is written and
/// refuses a mismatch the way it refuses any other malformed event (a
/// harness bug, not an I/O failure); the reader does not re-check it, so
/// journals written before this check existed still verify.
pub fn check_canonical_body(
    kind: EventKind,
    body: &Map<String, Value>,
) -> Result<(), &'static str> {
    let keys = match canonical_body_keys(kind) {
        Some(keys) => keys,
        None => return Ok(()),
    };
    if body.len() != keys.len() || keys.iter().any(|k| !body.contains_key(*k)) {
        return Err("body is not exactly the kind's canonical fields");
    }
    match kind {
        EventKind::Egress => {
            check_egress_decision(
                body.get("decision")
                    .and_then(Value::as_str)
                    .ok_or("Egress: \"decision\" must be text")?,
            )?;
            match body.get("host").and_then(Value::as_str) {
                Some(h) if is_egress_host(h) => {}
                _ => return Err("Egress: \"host\" is not a lowercase DNS name or IP literal"),
            }
            // `hop` is a 0-based redirect counter: the airlock's hop budget
            // (P-39a) bounds it, the record only carries it.
            body.get("hop")
                .and_then(Value::as_u64)
                .ok_or("Egress: \"hop\" must be a u64")?;
            match body.get("ip") {
                Some(Value::Null) => {}
                Some(Value::String(s)) if s == "delegated" => {}
                Some(Value::String(s)) => as_ip(s)
                    .map_err(|_| "Egress: \"ip\" is null, an IP address, or \"delegated\"")?,
                _ => return Err("Egress: \"ip\" is null, an IP address, or \"delegated\""),
            }
            match body.get("mode").and_then(Value::as_str) {
                Some("direct" | "user-proxy" | "search-endpoint") => {}
                _ => return Err("Egress: unknown \"mode\""),
            }
            if body
                .get("port")
                .and_then(Value::as_u64)
                .ok_or("Egress: \"port\" must be a u64")?
                > 65535
            {
                return Err("Egress: \"port\" is above 65535");
            }
            match body.get("purpose").and_then(Value::as_str) {
                Some("fetch" | "search") => {}
                _ => return Err("Egress: unknown \"purpose\""),
            }
            match body.get("resolved") {
                Some(Value::Array(addrs)) => {
                    for addr in addrs {
                        as_ip(
                            addr.as_str()
                                .ok_or("Egress: every entry of \"resolved\" must be text")?,
                        )
                        .map_err(|_| "Egress: \"resolved\" holds IP addresses")?;
                    }
                }
                _ => return Err("Egress: \"resolved\" must be a list"),
            }
            // §4.5: the URL came from the model, so its payload home says so.
            let url = body
                .get("url")
                .and_then(Value::as_object)
                .ok_or("Egress: \"url\" must be an untrusted payload home")?;
            let source_is_model = url
                .get("source")
                .and_then(Value::as_object)
                .and_then(|s| s.get("kind"))
                .and_then(Value::as_str)
                == Some("model");
            if !is_untrusted_home(url) || !source_is_model {
                return Err("Egress: \"url\" must be a model-source untrusted payload home");
            }
        }
        EventKind::NoteSaved => {
            body.get("bytes")
                .and_then(Value::as_u64)
                .ok_or("NoteSaved: \"bytes\" must be a u64")?;
            as_digest_str(
                body.get("note")
                    .and_then(Value::as_str)
                    .ok_or("NoteSaved: \"note\" must be text")?,
            )
            .map_err(|_| "NoteSaved: \"note\" must be a 64-hex digest")?;
            body.get("sources")
                .and_then(Value::as_u64)
                .ok_or("NoteSaved: \"sources\" must be a u64")?;
            body.get("turn")
                .and_then(Value::as_u64)
                .ok_or("NoteSaved: \"turn\" must be a u64")?;
        }
        EventKind::NoteImported => {
            // §7: the file's bytes and its path go to their typed homes.
            for key in ["bytes", "path"] {
                let ok = body
                    .get(key)
                    .and_then(Value::as_object)
                    .map(is_untrusted_home)
                    .unwrap_or(false);
                if !ok {
                    return Err("NoteImported: \"bytes\" and \"path\" are untrusted payload homes");
                }
            }
            if body.get("confirm").and_then(Value::as_str) != Some("typed-id-prefix") {
                return Err("NoteImported: \"confirm\" is exactly \"typed-id-prefix\" (INV-50)");
            }
            as_digest_str(
                body.get("note")
                    .and_then(Value::as_str)
                    .ok_or("NoteImported: \"note\" must be text")?,
            )
            .map_err(|_| "NoteImported: \"note\" must be a 64-hex digest")?;
            as_digest_str(
                body.get("sha256")
                    .and_then(Value::as_str)
                    .ok_or("NoteImported: \"sha256\" must be text")?,
            )
            .map_err(|_| "NoteImported: \"sha256\" must be a 64-hex digest")?;
        }
        _ => return Ok(()),
    }
    Ok(())
}

/// Zero-width, bidi-control, invisible-letter and tag code points. Escaped
/// in untrusted text so a journal viewer is not an injection sink.
pub(crate) fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}'
        | '\u{180B}'..='\u{180F}' | '\u{200B}'..='\u{200F}' | '\u{2028}' | '\u{2029}'
        | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{3164}' | '\u{FE00}'..='\u{FE0F}'
        | '\u{FEFF}' | '\u{FFA0}' | '\u{FFF0}'..='\u{FFFB}' | '\u{E0000}'..='\u{E0FFF}')
}

/// Reversible escaping for untrusted text (§7.1): `\` becomes `\\`, and
/// every control character (ESC included, so ANSI sequences are inert),
/// zero-width, bidi or invisible code point becomes `\u{HEX}`. Everything
/// else is kept. [`unescape`] is the exact inverse, so the reader can
/// recompute the payload's SHA-256.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\\' {
            out.push_str("\\\\");
        } else if c.is_control() || is_invisible(c) {
            out.push_str(&format!("\\u{{{:X}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

/// Inverse of [`escape`]; `None` if `s` is not an output of `escape`.
pub fn unescape(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            if c.is_control() || is_invisible(c) {
                return None; // escape() never leaves these raw
            }
            out.push(c);
            continue;
        }
        match it.next()? {
            '\\' => out.push('\\'),
            'u' => {
                if it.next()? != '{' {
                    return None;
                }
                let mut hex = String::new();
                loop {
                    match it.next()? {
                        '}' => break,
                        h if h.is_ascii_hexdigit() && hex.len() < 6 => hex.push(h),
                        _ => return None,
                    }
                }
                let ch = char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?;
                // Canonical: only characters escape() escapes, in its spelling.
                if !(ch.is_control() || is_invisible(ch)) || hex != format!("{:X}", u32::from(ch)) {
                    return None;
                }
                out.push(ch);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// UTC RFC 3339 with milliseconds from Unix milliseconds (civil-from-days,
/// H. Hinnant). Pure, so records are reproducible in tests.
pub fn rfc3339_utc(unix_ms: u64) -> String {
    let secs = unix_ms / 1000;
    let ms = unix_ms % 1000;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // days since 1970-01-01 -> civil date
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(mo <= 2);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.{ms:03}Z")
}

/// The fields of one record, before hashing.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordFields {
    /// Sequence number (0 = header).
    pub seq: u64,
    /// Hash of the previous record ([`GENESIS`] for seq 0).
    pub prev: Digest,
    /// Monotonic milliseconds since the writer opened.
    pub t_mono_ms: u64,
    /// Wall clock, RFC 3339 UTC.
    pub t_wall: String,
    /// Run id.
    pub run: harness_core::RunId,
    /// Attempt number.
    pub attempt: u32,
    /// Loop step.
    pub step: u64,
    /// Kind.
    pub kind: EventKind,
    /// Body object.
    pub body: Map<String, Value>,
}

fn hex(d: &Digest) -> String {
    d.to_string()
}

impl RecordFields {
    fn object_without_hash(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("attempt".into(), Value::from(self.attempt));
        m.insert("body".into(), Value::Object(self.body.clone()));
        m.insert("kind".into(), Value::from(self.kind.as_str()));
        m.insert("prev".into(), Value::from(hex(&self.prev)));
        m.insert("run".into(), Value::from(self.run.as_str()));
        m.insert("seq".into(), Value::from(self.seq));
        m.insert("step".into(), Value::from(self.step));
        m.insert("t_mono_ms".into(), Value::from(self.t_mono_ms));
        m.insert("t_wall".into(), Value::from(self.t_wall.clone()));
        m
    }

    /// Encode: `(line bytes WITHOUT the trailing newline, record hash)`.
    pub fn encode(&self) -> (Vec<u8>, Digest) {
        let mut obj = self.object_without_hash();
        let canonical = Value::Object(obj.clone()).to_string();
        let hash = sha256_parts(&[self.prev.as_bytes(), canonical.as_bytes()]);
        obj.insert("hash".into(), Value::from(hex(&hash)));
        (Value::Object(obj).to_string().into_bytes(), hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // H3a: the new kind and the new stop cause have wire names the reader
    // parses back, and neither collides with an existing one.
    #[test]
    fn the_presubmit_kind_and_stop_cause_have_their_own_wire_names() {
        assert_eq!(EventKind::PresubmitChecked.as_str(), "PresubmitChecked");
        assert_eq!(
            EventKind::parse("PresubmitChecked"),
            Some(EventKind::PresubmitChecked)
        );
        assert!(
            !EventKind::PresubmitChecked.needs_fsync(),
            "the result that follows it is the durable one"
        );
        let names: std::collections::BTreeSet<&str> = KINDS.iter().map(|(_, n)| *n).collect();
        assert_eq!(names.len(), KINDS.len(), "every kind has its own name");
        assert_eq!(
            crate::writer::stop_cause_name(&harness_core::StopCause::SubmittedChecksFailed),
            "submitted_checks_failed"
        );
        assert_ne!(
            crate::writer::stop_cause_name(&harness_core::StopCause::Submitted),
            crate::writer::stop_cause_name(&harness_core::StopCause::SubmittedChecksFailed)
        );
    }

    #[test]
    fn escape_is_reversible_and_neutralises_viewer_sinks() {
        for s in [
            "plain text, ünïcödé",
            "ansi \u{1b}[31mred\u{1b}[0m",
            "bidi \u{202E}evil\u{202C} and \u{2066}iso\u{2069}",
            "zero\u{200B}width \u{FEFF} tag\u{E0041}",
            "back\\slash \\u{41} literal",
            "new\nline\ttab\r\0nul",
            "hangul\u{3164}filler",
        ] {
            let e = escape(s);
            assert!(
                !e.chars().any(|c| c.is_control() || is_invisible(c)),
                "{e:?}"
            );
            assert_eq!(unescape(&e).as_deref(), Some(s), "{s:?}");
        }
    }

    #[test]
    fn unescape_refuses_non_canonical_forms() {
        for bad in [
            "\\x41",
            "\\u{41}",
            "\\u{1b",
            "\\u{1B}x\u{1b}",
            "\\",
            "\\u{00001B}",
            "\\u{1b}",
        ] {
            assert_eq!(unescape(bad), None, "{bad:?}");
        }
        assert_eq!(unescape("\\u{1B}").as_deref(), Some("\u{1b}"));
    }

    #[test]
    fn rfc3339_known_instants() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339_utc(951_782_400_123), "2000-02-29T00:00:00.123Z");
        assert_eq!(rfc3339_utc(1_790_000_000_000), "2026-09-21T14:13:20.000Z");
    }

    #[test]
    fn kinds_round_trip_and_unknown_is_none() {
        for (k, n) in KINDS {
            assert_eq!(k.as_str(), *n);
            assert_eq!(EventKind::parse(n), Some(*k));
        }
        assert_eq!(EventKind::parse("runstarted"), None);
        assert_eq!(EventKind::parse("Shell"), None);
    }

    // P-05/P-10 (hotspot H-E): the six reserved names are in the closed set
    // now, parse back, and collide with nothing; no code writes them yet.
    #[test]
    fn reserved_kinds_parse() {
        for (k, n) in [
            (EventKind::ModeChanged, "ModeChanged"),
            (EventKind::RuleGranted, "RuleGranted"),
            (EventKind::Restored, "Restored"),
            (EventKind::InstructionsLoaded, "InstructionsLoaded"),
            (EventKind::ForkedFrom, "ForkedFrom"),
            (EventKind::ChildRun, "ChildRun"),
        ] {
            assert_eq!(k.as_str(), n);
            assert_eq!(EventKind::parse(n), Some(k));
        }
        let names: std::collections::BTreeSet<&str> = KINDS.iter().map(|(_, n)| *n).collect();
        assert_eq!(names.len(), KINDS.len(), "every kind has its own name");
    }

    // P-05/P-10: the session kinds are inputs or turn boundaries and resume
    // keys on them, so every one of the nine is fsynced.
    #[test]
    fn session_kinds_are_fsynced() {
        for k in [
            EventKind::UserTurn,
            EventKind::TurnEnded,
            EventKind::InputEnded,
            EventKind::ModeChanged,
            EventKind::RuleGranted,
            EventKind::Restored,
            EventKind::InstructionsLoaded,
            EventKind::ForkedFrom,
            EventKind::ChildRun,
        ] {
            assert!(k.needs_fsync(), "{}", k.as_str());
        }
    }

    #[test]
    fn idents_refuse_markup_whitespace_paths_and_urls() {
        for bad in [
            "",
            "a b",
            "a\"b",
            "a\\b",
            "a\nb",
            "é",
            "<x>",
            "src/notes/ignore-previous",
            "https://evil.example/x",
            "sha256:ab",
            "user@host",
            "a+b=c",
            ".",
            "..",
            ".hidden",
            "-rf",
            &"a".repeat(129),
        ] {
            assert!(Ident::new(bad).is_none(), "{bad:?}");
        }
        for ok in ["run-01", "harness.fs.read", "0.0.1", "userns_disabled"] {
            assert!(Ident::new(ok).is_some(), "{ok:?}");
        }
    }

    // P-39c (§4.5): `Egress` is appended before any bytes are forwarded,
    // so it must be durable whether the decision is allow or refuse.
    #[test]
    fn egress_is_fsynced() {
        assert!(EventKind::Egress.needs_fsync());
    }

    fn body(v: serde_json::Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    fn hex_of(what: &[u8]) -> String {
        sha256_parts(&[what]).to_string()
    }

    fn egress_body() -> serde_json::Value {
        serde_json::json!({
            "decision": "allow",
            "host": "example.com",
            "hop": 0,
            "ip": null,
            "mode": "direct",
            "port": 443,
            "purpose": "fetch",
            "resolved": ["93.184.216.34"],
            "url": {
                "untrusted": true,
                "source": {"kind": "model"},
                "sha256": hex_of(b"https://example.com/doc"),
                "len": 22,
                "inline": "https://example.com/doc"
            }
        })
    }

    // P-39c: the web airlock kinds carry exactly the §4.5/§6/§7 fields, in
    // shapes the design gives them; anything else is refused before a byte
    // is written, and kinds without a defined list are untouched.
    #[test]
    fn web_airlock_bodies_are_shape_checked() {
        let keys = canonical_body_keys(EventKind::Egress).unwrap();
        assert_eq!(keys.len(), 9);
        assert!(
            keys.windows(2).all(|w| w[0] < w[1]),
            "sorted, like the wire"
        );
        assert_eq!(canonical_body_keys(EventKind::NoteSaved).unwrap().len(), 4);
        assert_eq!(
            canonical_body_keys(EventKind::NoteImported).unwrap().len(),
            5
        );
        assert_eq!(canonical_body_keys(EventKind::ModelReplied), None);

        assert_eq!(
            check_canonical_body(EventKind::Egress, &body(egress_body())),
            Ok(())
        );
        // Every refusal reason names itself; user-proxy answers "delegated"
        // instead of an address; the search endpoint is addressed by IP.
        for reason in EGRESS_REFUSALS {
            let mut m = egress_body();
            m["decision"] = Value::from(format!("refuse:{reason}"));
            m["ip"] = Value::from("delegated");
            m["mode"] = Value::from("user-proxy");
            assert_eq!(
                check_canonical_body(EventKind::Egress, &body(m)),
                Ok(()),
                "{reason}"
            );
        }
        let mut endpoint = egress_body();
        endpoint["host"] = Value::from("127.0.0.1");
        endpoint["mode"] = Value::from("search-endpoint");
        endpoint["purpose"] = Value::from("search");
        endpoint["resolved"] = Value::Array(vec![]);
        assert_eq!(
            check_canonical_body(EventKind::Egress, &body(endpoint)),
            Ok(())
        );

        let mut extra = egress_body();
        extra["extra"] = Value::from(1);
        assert!(check_canonical_body(EventKind::Egress, &body(extra)).is_err());
        let mut missing = egress_body();
        missing.as_object_mut().unwrap().remove("resolved");
        assert!(check_canonical_body(EventKind::Egress, &body(missing)).is_err());
        let bad: &[(&str, Value)] = &[
            ("decision", "refuse:because".into()),
            ("decision", "ALLOW".into()),
            ("host", "EXAMPLE.com".into()),
            ("host", "under_score.example".into()),
            ("host", "-lead.example".into()),
            ("host", "example.com.".into()),
            ("host", "a..b".into()),
            ("ip", "999.0.0.1".into()),
            ("ip", "delegated ".into()),
            ("ip", true.into()),
            ("mode", "tunnel".into()),
            ("port", 65536.into()),
            ("purpose", "crawl".into()),
        ];
        for (key, v) in bad {
            let mut m = egress_body();
            m[*key] = v.clone();
            assert!(
                check_canonical_body(EventKind::Egress, &body(m)).is_err(),
                "{key} = {v}"
            );
        }
        let mut resolved_text = egress_body();
        resolved_text["resolved"] = Value::from("93.184.216.34");
        assert!(check_canonical_body(EventKind::Egress, &body(resolved_text)).is_err());
        let mut resolved_bad = egress_body();
        resolved_bad["resolved"] = serde_json::json!(["not-an-ip"]);
        assert!(check_canonical_body(EventKind::Egress, &body(resolved_bad)).is_err());
        let mut url_user = egress_body();
        url_user["url"]["source"] = serde_json::json!({"kind": "user"});
        assert!(check_canonical_body(EventKind::Egress, &body(url_user)).is_err());
        let mut url_plain = egress_body();
        url_plain["url"] = Value::from("https://example.com/doc");
        assert!(check_canonical_body(EventKind::Egress, &body(url_plain)).is_err());

        let note = hex_of(b"note-1 body");
        let saved = serde_json::json!({
            "bytes": 2048u64,
            "note": note,
            "sources": 2u64,
            "turn": 4u64,
        });
        assert_eq!(
            check_canonical_body(EventKind::NoteSaved, &body(saved.clone())),
            Ok(())
        );
        let mut note_bad = saved.clone();
        note_bad["note"] = Value::from("not-a-digest");
        assert!(check_canonical_body(EventKind::NoteSaved, &body(note_bad)).is_err());
        let mut saved_extra = saved;
        saved_extra["turn"] = Value::from(-1);
        assert!(check_canonical_body(EventKind::NoteSaved, &body(saved_extra)).is_err());

        let imported = serde_json::json!({
            "bytes": {
                "untrusted": true,
                "source": {"kind": "workspace", "path": "research/notes"},
                "sha256": hex_of(b"note body"),
                "len": 9,
                "inline": "note body"
            },
            "confirm": "typed-id-prefix",
            "note": note,
            "path": {
                "untrusted": true,
                "source": {"kind": "workspace", "path": "research/notes"},
                "sha256": hex_of(b"some-id/note.md"),
                "len": 15,
                "inline": "some-id/note.md"
            },
            "sha256": hex_of(b"note body"),
        });
        assert_eq!(
            check_canonical_body(EventKind::NoteImported, &body(imported.clone())),
            Ok(())
        );
        let mut confirm_bad = imported.clone();
        confirm_bad["confirm"] = Value::from("yes");
        assert!(check_canonical_body(EventKind::NoteImported, &body(confirm_bad)).is_err());
        let mut path_plain = imported;
        path_plain["path"] = Value::from("some-id/note.md");
        assert!(check_canonical_body(EventKind::NoteImported, &body(path_plain)).is_err());

        // Kinds with no defined list are policed by their owners, not here.
        assert_eq!(
            check_canonical_body(
                EventKind::ContextBuilt,
                &body(serde_json::json!({"anything": true}))
            ),
            Ok(())
        );
    }
}
