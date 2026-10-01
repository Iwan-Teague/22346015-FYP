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
/// grammar. The grammar keeps paths and URLs out by construction; the rest
/// of the rule is enforced by review until H1e gives `Ident` typed
/// constructors from `RunId`/`CapId` (design doc, Changes since v0.2).
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
    SubmitRequested,
    VerificationStarted,
    VerificationFinished,
    CheckReported,
    ReviewerRefused,
    ReviewReported,
    RunStopped,
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
    (EventKind::SubmitRequested, "SubmitRequested"),
    (EventKind::VerificationStarted, "VerificationStarted"),
    (EventKind::VerificationFinished, "VerificationFinished"),
    (EventKind::CheckReported, "CheckReported"),
    (EventKind::ReviewerRefused, "ReviewerRefused"),
    (EventKind::ReviewReported, "ReviewReported"),
    (EventKind::RunStopped, "RunStopped"),
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
    /// before forwarding), the verification events and `RunStopped`.
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
        )
    }
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
}
