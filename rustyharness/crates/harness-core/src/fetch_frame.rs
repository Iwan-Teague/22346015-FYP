//! The `rh-fetch/1` frame codec (design note `P-39-web-airlock` §5.2).
//!
//! A frame is how the confined web fetcher reports one hop back to the
//! harness: a magic line, one strict-JSON header line (at most
//! [`MAX_HEADER_BYTES`], duplicate and unknown keys refused), then exactly
//! `body_len` raw body bytes. The header keys are written in sorted order
//! (a `serde_json` map is a `BTreeMap`), and [`parse_frame`] re-derives
//! every field with its own type checks: the fetcher is treated as an
//! untrusted adversary (A4), so nothing on the wire is taken on faith.
//!
//! This module is pure: bytes in, values out. The sandbox caps the
//! fetcher's output at `max_body + 64 KiB`, so an over-writing fetcher is
//! cut mid-frame and shows up here as a short body
//! ([`FrameError::BodyLenMismatch`]).

/// The magic first line of every frame.
pub const MAGIC: &str = "rh-fetch/1";

/// Hard cap on the header line: 16 KiB (design note §5.2).
pub const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Per-hop TLS details. Only ever filled by a later, TLS-enabled fetcher
/// (`net` feature, P-39n); the pure codec carries it opaquely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInfo {
    /// Negotiated protocol version, e.g. `tls1.3`.
    pub version: String,
    /// Negotiated cipher suite name.
    pub suite: String,
    /// SHA-256 of the leaf certificate, hex-encoded.
    pub cert_sha256: String,
}

/// The strict-JSON header block of a frame. Every field is re-validated on
/// parse; `body_len` and `truncated` are required, everything else may be
/// null.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    /// Response status, absent on an error frame.
    pub status: Option<u16>,
    /// Response reason phrase, absent on an error frame.
    pub reason: Option<String>,
    /// Response `Content-Type`, when the origin sent one.
    pub content_type: Option<String>,
    /// Response `Content-Length` as claimed by the origin (may exceed
    /// `body_len` when the body was truncated).
    pub content_length: Option<u64>,
    /// Response `Location` (redirects are reported, never followed).
    pub location: Option<String>,
    /// Number of body bytes that follow the header line. The reader refuses
    /// fewer or more.
    pub body_len: u64,
    /// True when the body was cut at the per-hop cap.
    pub truncated: bool,
    /// TLS details, when the hop was HTTPS (never in the default build).
    pub tls: Option<TlsInfo>,
    /// Typed error kind (`tls_unavailable`, `connect_failed`, `http_parse`,
    /// `encoding_refused`, `too_large_headers`, ...); null on success.
    pub error: Option<String>,
}

/// One reported fetch hop: header plus exactly `header.body_len` body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The strict-JSON header block.
    pub header: FrameHeader,
    /// Raw body bytes, never decompressed (INV-46).
    pub body: Vec<u8>,
}

/// Everything that can make a frame unparseable. Every refusal is typed:
/// a budget that ends in an error is still a budget that ended (INV-48).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// Zero bytes were given.
    Empty,
    /// The first line is not exactly [`MAGIC`].
    BadMagic,
    /// The header line is missing, unterminated, or over
    /// [`MAX_HEADER_BYTES`].
    HeaderTooLarge,
    /// The header line is not strict JSON (duplicate key, trailing bytes,
    /// bad syntax). Carries the underlying reader's message.
    Header(String),
    /// The header parsed but does not match the frame schema (unknown key,
    /// wrong type, missing required field). Carries a description.
    Schema(String),
    /// `body_len` exceeds the caller's cap.
    BodyOverCap {
        /// The cap that was exceeded.
        cap: u64,
    },
    /// The byte count after the header line differs from `body_len`.
    BodyLenMismatch {
        /// The declared body length.
        expected: u64,
        /// The actual number of trailing bytes.
        actual: u64,
    },
}

impl Frame {
    /// An error frame: empty body, no status, and the given error kind.
    pub fn error(kind: &str) -> Frame {
        Frame {
            header: FrameHeader {
                status: None,
                reason: None,
                content_type: None,
                content_length: None,
                location: None,
                body_len: 0,
                truncated: false,
                tls: None,
                error: Some(kind.to_string()),
            },
            body: Vec::new(),
        }
    }
}

/// Serialize one frame: magic line, sorted-key strict-JSON header line, then
/// exactly `header.body_len` raw body bytes.
pub fn encode_frame(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(header_value(&frame.header).to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(&frame.body);
    out
}

/// Parse one frame from `bytes`. Refuses a body shorter or longer than the
/// declared `body_len`, a `body_len` over `max_body`, a header over
/// [`MAX_HEADER_BYTES`], and any header that is not strict JSON in the exact
/// frame schema.
pub fn parse_frame(bytes: &[u8], max_body: u64) -> Result<Frame, FrameError> {
    let Some(after_magic) = bytes.strip_prefix(MAGIC.as_bytes()) else {
        if bytes.is_empty() {
            return Err(FrameError::Empty);
        }
        return Err(FrameError::BadMagic);
    };
    let Some(after_first_line) = after_magic.strip_prefix(b"\n") else {
        return Err(FrameError::BadMagic);
    };
    let Some(header_end) = find(after_first_line, b"\n") else {
        return Err(FrameError::HeaderTooLarge);
    };
    let header_bytes = header_bytes(after_first_line, header_end)?;
    let Some(tail) = after_first_line.get(header_end + 1..) else {
        return Err(FrameError::HeaderTooLarge);
    };

    let value = crate::strict_json::parse(header_bytes)
        .map_err(|err| FrameError::Header(err.to_string()))?;
    let header = parse_header(&value)?;
    if header.body_len > max_body {
        return Err(FrameError::BodyOverCap { cap: max_body });
    }
    let actual = u64::try_from(tail.len()).unwrap_or(u64::MAX);
    if actual != header.body_len {
        return Err(FrameError::BodyLenMismatch {
            expected: header.body_len,
            actual,
        });
    }
    Ok(Frame {
        header,
        body: tail.to_vec(),
    })
}

fn header_bytes(after_first_line: &[u8], header_end: usize) -> Result<&[u8], FrameError> {
    let raw = after_first_line
        .get(..header_end)
        .ok_or(FrameError::HeaderTooLarge)?;
    if raw.len() > MAX_HEADER_BYTES {
        return Err(FrameError::HeaderTooLarge);
    }
    Ok(raw)
}

fn header_value(header: &FrameHeader) -> serde_json::Value {
    // A serde_json map is a BTreeMap, so the keys land on the wire sorted.
    let mut map = serde_json::Map::new();
    map.insert(
        "body_len".to_string(),
        serde_json::Value::from(header.body_len),
    );
    map.insert(
        "content_length".to_string(),
        header
            .content_length
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null),
    );
    map.insert(
        "content_type".to_string(),
        optional_string(&header.content_type),
    );
    map.insert("error".to_string(), optional_string(&header.error));
    map.insert("location".to_string(), optional_string(&header.location));
    map.insert("reason".to_string(), optional_string(&header.reason));
    map.insert(
        "status".to_string(),
        header
            .status
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null),
    );
    map.insert(
        "tls".to_string(),
        match &header.tls {
            None => serde_json::Value::Null,
            Some(tls) => {
                let mut tls_map = serde_json::Map::new();
                tls_map.insert(
                    "cert_sha256".to_string(),
                    serde_json::Value::from(tls.cert_sha256.clone()),
                );
                tls_map.insert(
                    "suite".to_string(),
                    serde_json::Value::from(tls.suite.clone()),
                );
                tls_map.insert(
                    "version".to_string(),
                    serde_json::Value::from(tls.version.clone()),
                );
                serde_json::Value::Object(tls_map)
            }
        },
    );
    map.insert(
        "truncated".to_string(),
        serde_json::Value::from(header.truncated),
    );
    serde_json::Value::Object(map)
}

fn optional_string(value: &Option<String>) -> serde_json::Value {
    match value {
        None => serde_json::Value::Null,
        Some(text) => serde_json::Value::from(text.clone()),
    }
}

fn parse_header(value: &serde_json::Value) -> Result<FrameHeader, FrameError> {
    let map = value
        .as_object()
        .ok_or_else(|| FrameError::Schema("header must be a JSON object".to_string()))?;
    let mut status = None;
    let mut reason = None;
    let mut content_type = None;
    let mut content_length = None;
    let mut location = None;
    let mut truncated = None;
    let mut body_len = None;
    let mut tls = None;
    let mut error = None;
    for (key, value) in map {
        match key.as_str() {
            "status" => status = optional_u16(value, "status")?,
            "reason" => reason = optional_text(value, "reason")?,
            "content_type" => content_type = optional_text(value, "content_type")?,
            "content_length" => content_length = optional_u64(value, "content_length")?,
            "location" => location = optional_text(value, "location")?,
            "body_len" => body_len = Some(required_u64(value, "body_len")?),
            "truncated" => truncated = Some(required_bool(value, "truncated")?),
            "tls" => tls = optional_tls(value)?,
            "error" => error = optional_text(value, "error")?,
            other => return Err(FrameError::Schema(format!("unknown header key {other:?}"))),
        }
    }
    Ok(FrameHeader {
        status,
        reason,
        content_type,
        content_length,
        location,
        truncated: truncated.ok_or_else(|| missing("truncated"))?,
        body_len: body_len.ok_or_else(|| missing("body_len"))?,
        tls,
        error,
    })
}

fn optional_tls(value: &serde_json::Value) -> Result<Option<TlsInfo>, FrameError> {
    let Some(map) = value.as_object() else {
        if value.is_null() {
            return Ok(None);
        }
        return Err(FrameError::Schema(
            "tls must be null or an object".to_string(),
        ));
    };
    let mut version = None;
    let mut suite = None;
    let mut cert_sha256 = None;
    for (key, value) in map {
        match key.as_str() {
            "version" => version = Some(required_text(value, "tls.version")?),
            "suite" => suite = Some(required_text(value, "tls.suite")?),
            "cert_sha256" => cert_sha256 = Some(required_text(value, "tls.cert_sha256")?),
            other => return Err(FrameError::Schema(format!("unknown tls key {other:?}"))),
        }
    }
    Ok(Some(TlsInfo {
        version: version.ok_or_else(|| missing("tls.version"))?,
        suite: suite.ok_or_else(|| missing("tls.suite"))?,
        cert_sha256: cert_sha256.ok_or_else(|| missing("tls.cert_sha256"))?,
    }))
}

fn optional_text(value: &serde_json::Value, name: &str) -> Result<Option<String>, FrameError> {
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(required_text(value, name)?))
}

fn required_text(value: &serde_json::Value, name: &str) -> Result<String, FrameError> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| wrong_type(name))
}

fn optional_u64(value: &serde_json::Value, name: &str) -> Result<Option<u64>, FrameError> {
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(required_u64(value, name)?))
}

fn required_u64(value: &serde_json::Value, name: &str) -> Result<u64, FrameError> {
    value.as_u64().ok_or_else(|| wrong_type(name))
}

fn optional_u16(value: &serde_json::Value, name: &str) -> Result<Option<u16>, FrameError> {
    if value.is_null() {
        return Ok(None);
    }
    let raw = required_u64(value, name)?;
    u16::try_from(raw).map_err(|_| wrong_type(name)).map(Some)
}

fn required_bool(value: &serde_json::Value, name: &str) -> Result<bool, FrameError> {
    value.as_bool().ok_or_else(|| wrong_type(name))
}

fn wrong_type(name: &str) -> FrameError {
    FrameError::Schema(format!("{name} has the wrong JSON type"))
}

fn missing(name: &str) -> FrameError {
    FrameError::Schema(format!("missing header key {name:?}"))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Empty => write!(f, "empty frame"),
            FrameError::BadMagic => write!(f, "bad magic line (expected {MAGIC})"),
            FrameError::HeaderTooLarge => {
                write!(
                    f,
                    "header line missing, unterminated, or over {} bytes",
                    MAX_HEADER_BYTES
                )
            }
            FrameError::Header(why) => write!(f, "header is not strict JSON: {why}"),
            FrameError::Schema(why) => write!(f, "header schema: {why}"),
            FrameError::BodyOverCap { cap } => write!(f, "body_len exceeds cap {cap}"),
            FrameError::BodyLenMismatch { expected, actual } => {
                write!(
                    f,
                    "body_len {expected} but {actual} bytes follow the header"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_frame() -> Frame {
        Frame {
            header: FrameHeader {
                status: Some(200),
                reason: Some("OK".to_string()),
                content_type: Some("text/plain".to_string()),
                content_length: Some(5),
                location: Some("/elsewhere".to_string()),
                body_len: 5,
                truncated: false,
                tls: None,
                error: None,
            },
            body: b"hello".to_vec(),
        }
    }

    #[test]
    fn frame_round_trips() {
        let frame = full_frame();
        let bytes = encode_frame(&frame);
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.starts_with("rh-fetch/1\n"));
        // Keys land on the wire sorted (a serde_json map is a BTreeMap).
        let key_positions = [
            text.find("\"body_len\"").unwrap(),
            text.find("\"content_length\"").unwrap(),
            text.find("\"content_type\"").unwrap(),
            text.find("\"error\"").unwrap(),
            text.find("\"location\"").unwrap(),
            text.find("\"reason\"").unwrap(),
            text.find("\"status\"").unwrap(),
            text.find("\"tls\"").unwrap(),
            text.find("\"truncated\"").unwrap(),
        ];
        let mut sorted = key_positions;
        sorted.sort_unstable();
        assert_eq!(key_positions, sorted);
        assert!(text.ends_with("\nhello"));
        let parsed = parse_frame(&bytes, 1024).unwrap();
        assert_eq!(parsed, frame);
    }

    #[test]
    fn frame_with_short_or_long_body_refused() {
        let bytes = encode_frame(&full_frame());
        let short = &bytes[..bytes.len() - 1];
        assert!(matches!(
            parse_frame(short, 1024),
            Err(FrameError::BodyLenMismatch {
                expected: 5,
                actual: 4
            })
        ));
        let mut long = bytes.clone();
        long.push(b'x');
        assert!(matches!(
            parse_frame(&long, 1024),
            Err(FrameError::BodyLenMismatch {
                expected: 5,
                actual: 6
            })
        ));
    }

    #[test]
    fn frame_duplicate_key_refused() {
        let raw = b"rh-fetch/1\n{\"body_len\":0,\"body_len\":0,\"truncated\":false}\n".to_vec();
        let err = parse_frame(&raw, 1024).unwrap_err();
        assert!(matches!(err, FrameError::Header(_)));
        assert!(err.to_string().contains("duplicate JSON key"));
    }

    #[test]
    fn frame_unknown_key_refused() {
        let raw = b"rh-fetch/1\n{\"body_len\":0,\"truncated\":false,\"bogus\":1}\n".to_vec();
        assert!(matches!(
            parse_frame(&raw, 1024),
            Err(FrameError::Schema(_))
        ));
    }

    #[test]
    fn frame_missing_required_key_refused() {
        let raw = b"rh-fetch/1\n{\"body_len\":0}\n".to_vec();
        assert!(matches!(
            parse_frame(&raw, 1024),
            Err(FrameError::Schema(_))
        ));
    }

    #[test]
    fn frame_body_over_cap_refused() {
        let bytes = encode_frame(&full_frame());
        assert_eq!(
            parse_frame(&bytes, 4),
            Err(FrameError::BodyOverCap { cap: 4 })
        );
    }

    #[test]
    fn frame_empty_and_bad_magic_typed() {
        assert_eq!(parse_frame(b"", 1024), Err(FrameError::Empty));
        assert_eq!(
            parse_frame(b"nope\n{\"body_len\":0,\"truncated\":false}\n", 1024),
            Err(FrameError::BadMagic)
        );
    }

    #[test]
    fn frame_header_too_large_refused() {
        let mut raw = b"rh-fetch/1\n{".to_vec();
        raw.extend(std::iter::repeat_n(b'a', MAX_HEADER_BYTES + 1));
        assert_eq!(parse_frame(&raw, 1024), Err(FrameError::HeaderTooLarge));
        // An unterminated header line is the same refusal.
        let mut unterminated = b"rh-fetch/1\n{".to_vec();
        unterminated.extend(std::iter::repeat_n(b'a', 10));
        assert_eq!(
            parse_frame(&unterminated, 1024),
            Err(FrameError::HeaderTooLarge)
        );
    }

    #[test]
    fn frame_error_frame_round_trips() {
        let frame = Frame::error("http_parse");
        assert_eq!(frame.header.error.as_deref(), Some("http_parse"));
        assert!(frame.body.is_empty());
        let parsed = parse_frame(&encode_frame(&frame), 16).unwrap();
        assert_eq!(parsed, frame);
    }

    #[test]
    fn frame_tls_block_round_trips_and_refuses_unknown_subkeys() {
        let mut frame = full_frame();
        frame.header.tls = Some(TlsInfo {
            version: "tls1.3".to_string(),
            suite: "TLS_AES_128_GCM_SHA256".to_string(),
            cert_sha256: "ab".repeat(32),
        });
        let parsed = parse_frame(&encode_frame(&frame), 1024).unwrap();
        assert_eq!(parsed, frame);
        let raw = b"rh-fetch/1\n{\"body_len\":0,\"truncated\":false,\"tls\":{\"version\":\"t\",\"suite\":\"s\",\"cert_sha256\":\"c\",\"extra\":1}}\n".to_vec();
        assert!(matches!(
            parse_frame(&raw, 1024),
            Err(FrameError::Schema(_))
        ));
    }
}
