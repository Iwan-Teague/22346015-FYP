//! The MCP stdio wire codec (design note §3.1-§3.4): newline framing,
//! strict parsing, classification and the deterministic request encoders.
//!
//! **Framing (§3.1).** One JSON-RPC message per line, UTF-8, `\n`-terminated.
//! A trailing `\r` is refused, not stripped (a server that writes CRLF is
//! not speaking the transport we tested); a `\r` between tokens is ordinary
//! JSON whitespace. [`FRAME_MAX`] bounds one line at 1 MiB: the fault is
//! raised as soon as the buffered line would pass the cap, and the rest of
//! the line is never buffered.
//!
//! **Parsing.** Through the shared strict reader
//! (`harness_core::strict_json::parse_typed`), so duplicate keys are
//! refused at every depth (INV-22); a non-object top level — a JSON-RPC
//! batch array, removed in protocol `2025-06-18`, or a scalar — is refused.
//! Unknown top-level keys are ignored: classification keys on the fields
//! §3.1 names, and anything else is untrusted data this codec never reads.
//!
//! **Classification (§3.1).** A [`Incoming::Response`] names
//! `jsonrpc: "2.0"`, an `id`, and exactly one of `result`/`error`; a
//! [`Incoming::ServerRequest`] an `id` and a `method`; a
//! [`Incoming::Notification`] a `method` and no `id`. An `id` that is
//! `null`, a float, a boolean or a container is refused (§3.2, §3.5);
//! integers are accepted in the i64 range (JSON-RPC 2.0 recommends ids of
//! at most 2^53-1; larger magnitudes are refused). Matching an id against
//! the one outstanding request is the client's job (P-37e); the codec
//! accepts every well-typed id.
//!
//! **Encoding (§3.3, §3.4).** Compact JSON, keys sorted, exactly as
//! serde_json without `preserve_order` writes them, so the request bytes —
//! and the journal digest over them (§11 `mcp_request`) — are a pure
//! function of the encoder's arguments, recomputable at audit (§12). The
//! encoders return the line's bytes without the terminating newline: the
//! newline is transport framing.

use harness_core::strict_json;
use serde_json::{json, Map, Value};

/// The largest one frame (one line, without its newline) may be (§4:
/// `FRAME_MAX`, 1 MiB).
pub const FRAME_MAX: usize = 1024 * 1024;

/// The `clientInfo.name` we send in `initialize` (§3.3).
pub const CLIENT_NAME: &str = "rustyharness";

/// JSON-RPC `method not found`: the only reply a server-initiated request
/// ever gets (§3.5, D3), counted, never served.
pub const METHOD_NOT_FOUND: i64 = -32601;

/// The method that starts the lifecycle (§3.3).
pub const METHOD_INITIALIZE: &str = "initialize";
/// The notification that ends it (§3.3).
pub const METHOD_INITIALIZED: &str = "notifications/initialized";
/// The method that lists the server's tools, at connect and before every
/// call (§3.3, §7.2).
pub const METHOD_TOOLS_LIST: &str = "tools/list";
/// The method that runs one admitted tool (§3.4).
pub const METHOD_TOOLS_CALL: &str = "tools/call";

/// Why a frame was refused. Every variant is a protocol violation (§4):
/// the client kills the server and quarantines the provider's
/// capabilities; none is recoverable in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireFault {
    /// A line would pass [`FRAME_MAX`]; the rest is never buffered (§3.1).
    #[error("a frame passed the 1 MiB line cap")]
    OverCap,
    /// A completed line is not UTF-8 (§3.1).
    #[error("a frame is not UTF-8")]
    InvalidUtf8,
    /// The strict reader refused the line: bad syntax, a duplicate key at
    /// any depth, trailing content, or an empty line (INV-22).
    #[error("a frame is not one strict-JSON value")]
    MalformedJson,
    /// The line is a JSON value but not an object: a batch array (removed
    /// in `2025-06-18`) or a scalar (§3.1).
    #[error("a frame is a batch array or another non-object JSON value")]
    NotAnObject,
    /// The line ends with CR before LF (§3.1: refused, not stripped).
    #[error("a frame ends with CR before LF")]
    TrailingCr,
    /// The stream ended with a partial line still buffered (§4: an early
    /// end kills the server; a clean end is not a fault).
    #[error("the stream ended with a partial frame buffered")]
    EofMidLine,
    /// The line parsed but is not a JSON-RPC 2.0 message of an accepted
    /// shape (§3.1): a wrong or missing `jsonrpc` field, no `method` and no
    /// `id`, a malformed `id`, a `result` and an `error` together, neither
    /// of them, or an `error` object without an integer `code` and a string
    /// `message`.
    #[error("a frame is not a JSON-RPC 2.0 message of an accepted shape")]
    BadMessage,
}

/// The `id` of a message the server sent, echoed back verbatim in the
/// `-32601` reply for a server-initiated request (§3.5): a string or an
/// i64-range integer. `null`, floats (including fractionless ones such as
/// `2.0`, which parse as floats), booleans and containers are refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerId {
    /// An integer id.
    Int(i64),
    /// A string id.
    Str(String),
}

impl PeerId {
    /// The id as a JSON value, for the encoders.
    fn to_value(&self) -> Value {
        match self {
            PeerId::Int(n) => json!(n),
            PeerId::Str(s) => json!(s),
        }
    }
}

/// Read a well-typed `id` value; `None` for anything the harness refuses.
fn peer_id(v: &Value) -> Option<PeerId> {
    match v {
        Value::Number(n) => n.as_i64().map(PeerId::Int),
        Value::String(s) => Some(PeerId::Str(s.clone())),
        _ => None,
    }
}

/// The one of `result`/`error` a response carries (§3.1: exactly one).
#[derive(Debug, Clone, PartialEq)]
pub enum ResponsePayload {
    /// The `result` value as received. Its shape is the renderer's to read
    /// (P-37f), as untrusted data; nothing here is inspected.
    Result(Value),
    /// The `error` object, read strictly: an integer `code`, a string
    /// `message`, an optional `data` of any shape.
    Error {
        /// The JSON-RPC error code (e.g. `-32601`).
        code: i64,
        /// The server's message: untrusted text, bounded by the renderer,
        /// never parsed for anything.
        message: String,
        /// The optional `data` member, untrusted.
        data: Option<Value>,
    },
}

/// One classified inbound message (§3.1).
#[derive(Debug, Clone, PartialEq)]
pub enum Incoming {
    /// A reply to one of our requests (§3.2: the client matches the id
    /// against the one outstanding request).
    Response {
        /// The echoed request id.
        id: PeerId,
        /// The `result`, or the `error` (exactly one was present).
        payload: ResponsePayload,
    },
    /// A request the server initiated — sampling, roots, elicitation,
    /// `ping`, anything (§3.5): every one is answered `-32601` and counted;
    /// past a small cap it is a violation.
    ServerRequest {
        /// The server's id for the request.
        id: PeerId,
        /// The method name as received.
        method: String,
        /// The `params` member, if present, untrusted.
        params: Option<Value>,
    },
    /// A server notification (`notifications/*`, §3.5): dropped and
    /// counted; a `cancelled` naming the outstanding id is the client's to
    /// notice.
    Notification {
        /// The method name as received.
        method: String,
        /// The `params` member, if present, untrusted.
        params: Option<Value>,
    },
}

/// One complete frame: the raw line as received (without its newline) and
/// its classified message. The raw line is what the journal keeps for an
/// MCP response (§11 `mcp_response`), so audit can re-render the
/// observation from exactly what the server sent (§12).
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    /// The line as received, without the newline.
    pub line: String,
    /// The classified message.
    pub message: Incoming,
}

/// Classify one decoded frame (the line's text, without its newline).
pub fn classify(line: &str) -> Result<Incoming, WireFault> {
    let value = strict_json::parse_typed(line.as_bytes()).map_err(|_| WireFault::MalformedJson)?;
    let obj = match value {
        Value::Object(map) => map,
        _ => return Err(WireFault::NotAnObject),
    };
    match obj.get("jsonrpc") {
        Some(Value::String(v)) if v == "2.0" => {}
        _ => return Err(WireFault::BadMessage),
    }
    let method = match obj.get("method") {
        None => None,
        Some(Value::String(m)) => Some(m.clone()),
        Some(_) => return Err(WireFault::BadMessage),
    };
    let id = match obj.get("id") {
        None => None,
        Some(v) => Some(peer_id(v).ok_or(WireFault::BadMessage)?),
    };
    match (method, id) {
        (Some(method), Some(id)) => Ok(Incoming::ServerRequest {
            id,
            method,
            params: obj.get("params").cloned(),
        }),
        (Some(method), None) => Ok(Incoming::Notification {
            method,
            params: obj.get("params").cloned(),
        }),
        (None, Some(id)) => {
            let result = obj.get("result");
            let error = obj.get("error");
            match (result, error) {
                (Some(result), None) => Ok(Incoming::Response {
                    id,
                    payload: ResponsePayload::Result(result.clone()),
                }),
                (None, Some(error)) => Ok(Incoming::Response {
                    id,
                    payload: error_payload(error)?,
                }),
                // Both, or neither, is a violation (§3.1).
                _ => Err(WireFault::BadMessage),
            }
        }
        (None, None) => Err(WireFault::BadMessage),
    }
}

/// Read the `error` object of a response: an integer `code`, a string
/// `message`, an optional `data`; anything else is a violation.
fn error_payload(v: &Value) -> Result<ResponsePayload, WireFault> {
    let obj = match v {
        Value::Object(map) => map,
        _ => return Err(WireFault::BadMessage),
    };
    let code = match obj.get("code") {
        Some(Value::Number(n)) => n.as_i64().ok_or(WireFault::BadMessage)?,
        _ => return Err(WireFault::BadMessage),
    };
    let message = match obj.get("message") {
        Some(Value::String(m)) => m.clone(),
        _ => return Err(WireFault::BadMessage),
    };
    Ok(ResponsePayload::Error {
        code,
        message,
        data: obj.get("data").cloned(),
    })
}

/// The bounded newline-frame reader (§3.1): fed the bytes of the server's
/// stdout as they arrive, in any split, it returns every frame those bytes
/// complete, in order, and buffers only the partial line still being read.
/// Like `harness-model-core`'s `SseReader`, it is fed and never pulls: the
/// transport owns the pipe and the deadlines. A line that would pass
/// [`FRAME_MAX`] faults as soon as one more byte arrives — the rest is
/// never buffered (§3.1) — and after any fault the reader is dead: the
/// client kills the server (§4) and starts no new reader on it.
#[derive(Debug, Default)]
pub struct FrameReader {
    /// The undecoded bytes of the line being read (never longer than
    /// [`FRAME_MAX`]).
    line: Vec<u8>,
}

impl FrameReader {
    /// An empty reader.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed the next bytes (any framing, any split); every frame completed
    /// by them is returned. A fault leaves nothing to retry with: the
    /// violating server is killed, not corrected.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Frame>, WireFault> {
        let mut frames = Vec::new();
        for &b in bytes {
            if b == b'\n' {
                let line = std::mem::take(&mut self.line);
                frames.push(decode_line(&line)?);
            } else {
                if self.line.len() == FRAME_MAX {
                    // One more byte would pass the cap: refuse now, with
                    // the rest of the line unread and unbuffered (§3.1).
                    return Err(WireFault::OverCap);
                }
                self.line.push(b);
            }
        }
        Ok(frames)
    }

    /// The stream ended. A clean end at a frame boundary is fine; a
    /// partial line still buffered is a fault (§4: the server is killed).
    pub fn finish(&mut self) -> Result<(), WireFault> {
        if self.line.is_empty() {
            Ok(())
        } else {
            Err(WireFault::EofMidLine)
        }
    }
}

/// Decode one complete line (its bytes, without the newline): the CR check
/// on the raw bytes, then UTF-8, then the strict parse and classification.
fn decode_line(line: &[u8]) -> Result<Frame, WireFault> {
    if line.last() == Some(&b'\r') {
        return Err(WireFault::TrailingCr);
    }
    let text = std::str::from_utf8(line).map_err(|_| WireFault::InvalidUtf8)?;
    let message = classify(text)?;
    Ok(Frame {
        line: text.to_owned(),
        message,
    })
}

/// The `initialize` request (§3.3): the negotiated protocol version, EMPTY
/// client capabilities (D3: no sampling, no roots, no elicitation), and our
/// name and version. Bytes without the trailing newline.
pub fn encode_initialize(id: u64, protocol_version: &str, client_version: &str) -> Vec<u8> {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": METHOD_INITIALIZE,
        "params": {
            "protocolVersion": protocol_version,
            "capabilities": {},
            "clientInfo": {"name": CLIENT_NAME, "version": client_version},
        },
    })
    .to_string()
    .into_bytes()
}

/// The `notifications/initialized` notification (§3.3): no id, no params.
pub fn encode_initialized() -> Vec<u8> {
    json!({"jsonrpc": "2.0", "method": METHOD_INITIALIZED})
        .to_string()
        .into_bytes()
}

/// A `tools/list` request (§3.3 step 4, §7.2). Cursor pagination rides in
/// a later slice, with the client that drives the pages.
pub fn encode_list(id: u64) -> Vec<u8> {
    json!({"jsonrpc": "2.0", "id": id, "method": METHOD_TOOLS_LIST})
        .to_string()
        .into_bytes()
}

/// A `tools/call` request (§3.4): the server tool name and arguments that
/// were already validated against the manifest's schema (§6.1: the model
/// never sees the server schema, and only args that pass are sent). `args`
/// is an object by type. The bytes are a deterministic function of the
/// three arguments — one encoder, keys sorted — so the journal's request
/// digest (`mcp_request`, §11) is recomputable at audit (§12).
pub fn encode_call(id: u64, name: &str, args: &Map<String, Value>) -> Vec<u8> {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": METHOD_TOOLS_CALL,
        "params": {"name": name, "arguments": args},
    })
    .to_string()
    .into_bytes()
}

/// The one reply a server-initiated request ever gets (§3.5, D3): JSON-RPC
/// `method not found`, echoing the request's id exactly as received.
pub fn encode_method_not_found(id: &PeerId) -> Vec<u8> {
    json!({
        "jsonrpc": "2.0",
        "id": id.to_value(),
        "error": {"code": METHOD_NOT_FOUND, "message": "not supported"},
    })
    .to_string()
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed one line (plus its newline) to a fresh reader; return the
    /// fault, failing the test if the line was accepted.
    fn feed_fault(line: &[u8]) -> WireFault {
        let mut bytes = line.to_vec();
        bytes.push(b'\n');
        let mut r = FrameReader::new();
        let frames = r.feed(&bytes);
        assert!(frames.is_err(), "the reader accepted {line:?}");
        frames.expect_err("checked above")
    }

    /// Feed one line (plus its newline) to a fresh reader; return its one
    /// classified message, failing if the reader did not end clean with
    /// exactly that frame.
    fn one(line: &[u8]) -> Incoming {
        let mut bytes = line.to_vec();
        bytes.push(b'\n');
        let mut r = FrameReader::new();
        let mut frames = r.feed(&bytes).expect("the reader refused a good line");
        assert!(
            r.finish().is_ok(),
            "a fully read stream did not finish clean"
        );
        assert_eq!(frames.len(), 1, "wanted one frame from {line:?}");
        frames.pop().expect("checked above").message
    }

    #[test]
    fn codec_refuses_malformed_json_line() {
        assert_eq!(feed_fault(b"{"), WireFault::MalformedJson);
        assert_eq!(feed_fault(br#"{"jsonrpc":}"#), WireFault::MalformedJson);
        assert_eq!(feed_fault(b"{} {}"), WireFault::MalformedJson);
        // An empty line is not a message either.
        assert_eq!(feed_fault(b""), WireFault::MalformedJson);
    }

    #[test]
    fn codec_refuses_duplicate_keys() {
        assert_eq!(feed_fault(br#"{"a":1,"a":2}"#), WireFault::MalformedJson);
        // At depth, inside a result we would otherwise have classified
        // (INV-22: every depth).
        assert_eq!(
            feed_fault(br#"{"jsonrpc":"2.0","id":1,"result":{"x":1,"x":2}}"#),
            WireFault::MalformedJson
        );
    }

    #[test]
    fn codec_refuses_frame_over_cap_without_buffering_it() {
        // More than FRAME_MAX bytes on one line, fed one byte at a time:
        // the fault must come exactly when the cap passes — one byte into
        // the overflow — long before the line's end or its newline (the
        // rest is never buffered, §3.1).
        let bytes: Vec<u8> = std::iter::repeat_n(b'a', FRAME_MAX + 4096)
            .chain(std::iter::once(b'\n'))
            .collect();
        let mut r = FrameReader::new();
        let mut fault_at = None;
        for (i, b) in bytes.iter().enumerate() {
            if let Err(e) = r.feed(std::slice::from_ref(b)) {
                assert_eq!(e, WireFault::OverCap);
                fault_at = Some(i);
                break;
            }
        }
        assert_eq!(
            fault_at,
            Some(FRAME_MAX),
            "the fault must come exactly at the cap, not at the newline"
        );
        // The same line in one chunk faults the same way, with no frames.
        let mut r = FrameReader::new();
        assert_eq!(r.feed(&bytes), Err(WireFault::OverCap));
        // A line of exactly the cap is read as far as the cap is
        // concerned: it fails as JSON, not as over-cap.
        let exact: Vec<u8> = std::iter::repeat_n(b'a', FRAME_MAX).collect();
        assert_eq!(feed_fault(&exact), WireFault::MalformedJson);
    }

    #[test]
    fn codec_refuses_non_utf8() {
        assert_eq!(feed_fault(b"\xff\xfe\xfd"), WireFault::InvalidUtf8);
        assert_eq!(
            feed_fault(b"{\"jsonrpc\":\"\xff\xfe\"}"),
            WireFault::InvalidUtf8
        );
    }

    #[test]
    fn codec_refuses_trailing_cr() {
        // CRLF is refused, not stripped (§3.1), even when the rest of the
        // line would have classified cleanly.
        assert_eq!(feed_fault(b"{}\r"), WireFault::TrailingCr);
        let mut line = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_vec();
        line.push(b'\r');
        assert_eq!(feed_fault(&line), WireFault::TrailingCr);
        // A CR that is not trailing is ordinary JSON whitespace (RFC 8259).
        assert_eq!(
            one(b"{\"jsonrpc\":\r\"2.0\",\r\"method\":\"notifications/initialized\"}"),
            Incoming::Notification {
                method: "notifications/initialized".to_owned(),
                params: None,
            }
        );
    }

    #[test]
    fn codec_refuses_batch_array() {
        // A batch is refused (removed in 2025-06-18), as is any non-object.
        assert_eq!(
            feed_fault(br#"[{"jsonrpc":"2.0","id":1,"result":{}}]"#),
            WireFault::NotAnObject
        );
        assert_eq!(feed_fault(b"3"), WireFault::NotAnObject);
        assert_eq!(feed_fault(br#""hello""#), WireFault::NotAnObject);
        assert_eq!(feed_fault(b"null"), WireFault::NotAnObject);
    }

    #[test]
    fn codec_classifies_request_notification_response() {
        assert_eq!(
            one(br#"{"jsonrpc":"2.0","id":7,"result":{"tools":[]}}"#),
            Incoming::Response {
                id: PeerId::Int(7),
                payload: ResponsePayload::Result(json!({"tools": []})),
            }
        );
        assert_eq!(
            one(br#"{"jsonrpc":"2.0","id":"abc","error":{"code":-32601,"message":"nope"}}"#),
            Incoming::Response {
                id: PeerId::Str("abc".to_owned()),
                payload: ResponsePayload::Error {
                    code: -32601,
                    message: "nope".to_owned(),
                    data: None,
                },
            }
        );
        assert_eq!(
            one(br#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"m","data":{"k":1}}}"#),
            Incoming::Response {
                id: PeerId::Int(1),
                payload: ResponsePayload::Error {
                    code: -1,
                    message: "m".to_owned(),
                    data: Some(json!({"k": 1})),
                },
            }
        );
        // A server request carries an id and a method (§3.5: answered
        // -32601, counted; never served).
        assert_eq!(
            one(br#"{"jsonrpc":"2.0","id":2,"method":"ping","params":{}}"#),
            Incoming::ServerRequest {
                id: PeerId::Int(2),
                method: "ping".to_owned(),
                params: Some(json!({})),
            }
        );
        // A notification carries a method and no id.
        assert_eq!(
            one(br#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#),
            Incoming::Notification {
                method: "notifications/tools/list_changed".to_owned(),
                params: None,
            }
        );
        // Exactly one of result/error (§3.1): neither, or both, refused.
        assert_eq!(
            feed_fault(br#"{"jsonrpc":"2.0","id":1}"#),
            WireFault::BadMessage
        );
        assert_eq!(
            feed_fault(br#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"m"}}"#),
            WireFault::BadMessage
        );
        // The jsonrpc field must name exactly 2.0 (§3.1).
        assert_eq!(
            feed_fault(br#"{"jsonrpc":"1.0","id":1,"result":{}}"#),
            WireFault::BadMessage
        );
        assert_eq!(
            feed_fault(br#"{"id":1,"result":{}}"#),
            WireFault::BadMessage
        );
        // Neither method nor id at all.
        assert_eq!(feed_fault(br#"{"jsonrpc":"2.0"}"#), WireFault::BadMessage);
        // The error object must be shaped: integer code, string message.
        assert_eq!(
            feed_fault(br#"{"jsonrpc":"2.0","id":1,"error":{"code":"-32601","message":"m"}}"#),
            WireFault::BadMessage
        );
        assert_eq!(
            feed_fault(br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}"#),
            WireFault::BadMessage
        );
        // A method must be a string.
        assert_eq!(
            feed_fault(br#"{"jsonrpc":"2.0","method":7}"#),
            WireFault::BadMessage
        );
    }

    #[test]
    fn codec_refuses_null_or_float_id() {
        // A response's id (§3.2: null is a violation, and so is any
        // non-integer, including a fractionless float such as 2.0, which
        // arrives as a float).
        assert_eq!(
            feed_fault(br#"{"jsonrpc":"2.0","id":null,"result":{}}"#),
            WireFault::BadMessage
        );
        assert_eq!(
            feed_fault(br#"{"jsonrpc":"2.0","id":1.5,"result":{}}"#),
            WireFault::BadMessage
        );
        assert_eq!(
            feed_fault(br#"{"jsonrpc":"2.0","id":2.0,"result":{}}"#),
            WireFault::BadMessage
        );
        assert_eq!(
            feed_fault(br#"{"jsonrpc":"2.0","id":true,"result":{}}"#),
            WireFault::BadMessage
        );
        // A server request's id too (§3.5: null or not a string/integer).
        assert_eq!(
            feed_fault(br#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#),
            WireFault::BadMessage
        );
        assert_eq!(
            feed_fault(br#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#),
            WireFault::BadMessage
        );
    }

    #[test]
    fn encode_call_is_deterministic_and_sorted() {
        // Keys inserted out of order; the encoder writes them sorted, so
        // the bytes depend only on the arguments (§3.4, §11 mcp_request).
        let mut args = Map::new();
        args.insert("z".to_owned(), json!([2, "x"]));
        args.insert("a".to_owned(), json!(1));
        let first = encode_call(3, "echo", &args);
        let again = encode_call(3, "echo", &args);
        assert_eq!(first, again, "the same call encoded twice differed");
        assert_eq!(
            String::from_utf8(first).expect("the encoder wrote UTF-8"),
            r#"{"id":3,"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"a":1,"z":[2,"x"]},"name":"echo"}}"#
        );
    }

    #[test]
    fn encode_initialize_has_empty_capabilities() {
        assert_eq!(
            String::from_utf8(encode_initialize(1, "2025-06-18", "0.0.1"))
                .expect("the encoder wrote UTF-8"),
            r#"{"id":1,"jsonrpc":"2.0","method":"initialize","params":{"capabilities":{},"clientInfo":{"name":"rustyharness","version":"0.0.1"},"protocolVersion":"2025-06-18"}}"#
        );
    }

    #[test]
    fn encode_initialized_list_and_32601_are_exact() {
        assert_eq!(
            String::from_utf8(encode_initialized()).expect("the encoder wrote UTF-8"),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
        );
        assert_eq!(
            String::from_utf8(encode_list(2)).expect("the encoder wrote UTF-8"),
            r#"{"id":2,"jsonrpc":"2.0","method":"tools/list"}"#
        );
        // The -32601 reply echoes the server's id exactly as received:
        // integer or string (§3.5).
        assert_eq!(
            String::from_utf8(encode_method_not_found(&PeerId::Int(11)))
                .expect("the encoder wrote UTF-8"),
            r#"{"error":{"code":-32601,"message":"not supported"},"id":11,"jsonrpc":"2.0"}"#
        );
        assert_eq!(
            String::from_utf8(encode_method_not_found(&PeerId::Str("srv-1".to_owned())))
                .expect("the encoder wrote UTF-8"),
            r#"{"error":{"code":-32601,"message":"not supported"},"id":"srv-1","jsonrpc":"2.0"}"#
        );
    }

    #[test]
    fn reader_yields_every_frame_and_finishes_clean_at_eof() {
        let mut r = FrameReader::new();
        // Two frames and a partial third, split mid-chunk mid-line.
        let mut chunk = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_vec();
        chunk.push(b'\n');
        chunk.extend_from_slice(br#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#);
        chunk.push(b'\n');
        chunk.extend_from_slice(br#"{"jsonrpc":"2.0","method":"notifications/progress""#);
        let frames = r.feed(&chunk).expect("the reader refused good frames");
        assert_eq!(frames.len(), 2, "the partial line must not yield a frame");
        assert_eq!(
            frames[0].line, r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            "the raw line is kept as received, for the journal"
        );
        assert_eq!(
            frames[1].message,
            Incoming::ServerRequest {
                id: PeerId::Int(2),
                method: "ping".to_owned(),
                params: None,
            }
        );
        // A partial line at end of stream is a fault (§4); the newline
        // that completes it first makes it a frame.
        assert_eq!(r.finish(), Err(WireFault::EofMidLine));
        assert_eq!(
            r.feed(b"}\n")
                .expect("the reader refused the line's tail")
                .len(),
            1
        );
        assert_eq!(r.finish(), Ok(()));
        // Feeding nothing changes nothing.
        assert!(r.feed(b"").expect("an empty feed refused").is_empty());
        assert_eq!(r.finish(), Ok(()));
    }
}
