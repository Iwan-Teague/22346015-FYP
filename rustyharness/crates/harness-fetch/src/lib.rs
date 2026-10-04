#![forbid(unsafe_code)]
// The panic-set lints ratchet production code; unit tests may assert loosely.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]
//! The confined web fetcher (design note `P-39-web-airlock` §5, slice P-39d).
//!
//! This crate is the ONLY place web bytes are ever parsed (INV-46): it runs
//! one bounded, hand-written HTTP/1.1 fetch over a tunnel the caller opens,
//! and reports the result as one `rh-fetch/1` frame (the codec lives in
//! `harness_core::fetch_frame`). It never decompresses: any `Content-Encoding`
//! other than `identity` is refused before the body is read, and no
//! decompressor is linked at all (INV-46). Every budget ends in a typed
//! refusal (INV-48). The default build links no TLS: an `https` request is
//! refused with the `tls_unavailable` kind (INV-52). The off-by-default
//! `net` feature adds exactly one thing, the TLS arm of §5.2 of the design
//! note (P-39n): rustls with the ring provider and the compiled-in Mozilla
//! roots, exposed as [`fetch_over_tls`] (see `src/tls.rs`). With `net` on,
//! an `https` hop handshakes over its tunnel first — SNI is the request's
//! host, ALPN offers only `http/1.1`, the system trust store is never read
//! — and the frame carries `tls {version, suite, cert_sha256}`.
//!
//! The library API is deliberately small:
//!
//! - [`read_request`]: strict-JSON request file (read from a PATH, never an
//!   inline payload, INV-23), capped at [`MAX_REQUEST_BYTES`];
//! - [`fetch_over`]: run one fetch over an already-open byte tunnel. It
//!   never returns `Err`: every failure — its own included — becomes an
//!   error frame, so the process can always report and exit 0. Only a
//!   failure to WRITE the frame to stdout leaves the fetcher silent, which
//!   the harness types as `ended: fetcher_failed`.
//!
//! The binary (`rustyharness-fetch`) glues these together: argv[1] names the
//! request file, the tunnel is a TCP connection to `127.0.0.1:<proxy_port>`
//! (the loopback pump), and the frame goes to stdout.
//!
//! This crate is deliberately NOT loop-visible: the fetcher journals
//! nothing (there is no journal kind here). Egress journaling happens
//! harness-side before the pump dials (P-39f, INV-43); this process only
//! ever talks to the loopback port the harness handed it in the request.
//! See the note section 4.x in `docs/slices/P-37c.md` for the same
//! reasoning applied to the MCP wire codec.

use std::io::{Read, Write};

pub use harness_core::fetch_frame::{encode_frame, parse_frame, Frame};
use harness_core::fetch_frame::{FrameHeader, TlsInfo};
use harness_core::strict_json;

#[cfg(feature = "net")]
pub use tls::{fetch_over_tls, fetch_over_tls_with_roots};

#[cfg(feature = "net")]
mod tls;

/// Hard cap on a request's `max_body`: 2 MiB per hop (design note §4.4).
pub const MAX_BODY_CAP: u64 = 2 * 1024 * 1024;

/// Hard cap on a request's `max_header_bytes`: 32 KiB (design note §4.4).
pub const MAX_HEADER_CAP: usize = 32 * 1024;

/// Hard cap on a `Location` value: 4 KiB (design note §4.4).
pub const MAX_LOCATION_BYTES: usize = 4096;

/// Hard cap on the request file itself: 16 KiB (design note §5.1).
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;

/// Hard cap on the wall budget a request may ask for: 60 s (§4.4). The
/// sandbox enforces its own, shorter wall; this is only an upper bound.
pub const MAX_TIMEOUT_MS: u64 = 60_000;

/// `https` with the `net` feature OFF (INV-52: the default build links no
/// TLS, so an https hop is refused before any byte moves). With `net` on
/// the kind can never be emitted — every TLS failure is [`KIND_TLS_FAILED`]
/// instead.
#[cfg(not(feature = "net"))]
const KIND_TLS_UNAVAILABLE: &str = "tls_unavailable";
/// A TLS failure with the `net` feature on (P-39n): the handshake itself,
/// certificate verification (wrong host, expired, untrusted), or the
/// protocol negotiation failed. Opaque to the caller by design: the reason
/// text never quotes server-controlled data. Used only by the `net` arm
/// (`src/tls.rs`).
#[cfg(feature = "net")]
pub const KIND_TLS_FAILED: &str = "tls_failed";
const KIND_CONNECT_FAILED: &str = "connect_failed";
const KIND_HTTP_PARSE: &str = "http_parse";
const KIND_ENCODING_REFUSED: &str = "encoding_refused";
const KIND_TOO_LARGE_HEADERS: &str = "too_large_headers";
const KIND_IO: &str = "io_error";

const MAX_HEADERS: usize = 100;
const MAX_INFORMATIONAL: usize = 5;
const MAX_CHUNK_LINE_BYTES: usize = 1024;
const MAX_TOKEN_BYTES: usize = 1024;
const MAX_HOST_BYTES: usize = 512;
const MAX_TARGET_BYTES: usize = 8 * 1024;
const MAX_ACCEPT_BYTES: usize = 1024;
const MAX_USER_AGENT_BYTES: usize = 256;
const DEFAULT_USER_AGENT: &str = "rustyharness-fetch";
const DEFAULT_ACCEPT: &str = "*/*";

/// Which scheme the hop should use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Plain HTTP through the pump.
    Http,
    /// HTTPS: refused with `tls_unavailable` until `net` lands (P-39n).
    Https,
}

impl Scheme {
    /// Wire name of the scheme.
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

/// How the tunnel to the origin is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Dial `127.0.0.1:proxy_port`, send CONNECT with the bearer token, then
    /// fetch through the tunnel (P-39g's pump).
    Proxy,
    /// The tunnel is already the origin (used by tests and by the pump
    /// itself); fetch directly over it.
    Direct,
}

impl Mode {
    /// Wire name of the mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Proxy => "proxy",
            Mode::Direct => "direct",
        }
    }
}

/// One fetch hop, as written by the harness into the request file
/// (design note §5.1). All of it is re-validated by [`read_request`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Request schema version; only 1 exists.
    pub v: u32,
    /// Loopback pump port to dial (mode `proxy`).
    pub proxy_port: u16,
    /// Bearer token for the pump CONNECT (mode `proxy`).
    pub token: String,
    /// `http` or `https`.
    pub scheme: Scheme,
    /// Origin host (no scheme, no port).
    pub host: String,
    /// Origin port.
    pub port: u16,
    /// Origin path plus query, starting with `/`.
    pub target: String,
    /// `Accept` header value; empty means [`DEFAULT_ACCEPT`].
    pub accept: String,
    /// Per-hop body cap in bytes (at most [`MAX_BODY_CAP`]).
    pub max_body: u64,
    /// Per-hop head cap in bytes (at most [`MAX_HEADER_CAP`]).
    pub max_header_bytes: usize,
    /// Socket read/write budget in ms (at most [`MAX_TIMEOUT_MS`]).
    pub timeout_ms: u64,
    /// `User-Agent` header value; empty means [`DEFAULT_USER_AGENT`].
    pub user_agent: String,
    /// [`Mode::Proxy`] or [`Mode::Direct`].
    pub mode: Mode,
}

/// Everything that can make a request file unusable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    /// The file is over [`MAX_REQUEST_BYTES`].
    TooLarge,
    /// The file is not strict JSON. Carries the reader's message.
    Json(String),
    /// The file parsed but does not match the request schema (unknown key,
    /// wrong type, out of range, missing field). Carries a description.
    Schema(String),
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestError::TooLarge => {
                write!(f, "request file over {} bytes", MAX_REQUEST_BYTES)
            }
            RequestError::Json(why) => write!(f, "request file is not strict JSON: {why}"),
            RequestError::Schema(why) => write!(f, "request schema: {why}"),
        }
    }
}

/// Parse one request file (strict JSON, exact key set, everything bounded).
/// A PATH is read by the caller; this function sees bytes only (INV-23).
pub fn read_request(bytes: &[u8]) -> Result<Request, RequestError> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(RequestError::TooLarge);
    }
    let value = strict_json::parse(bytes).map_err(|err| RequestError::Json(err.to_string()))?;
    let map = value
        .as_object()
        .ok_or_else(|| RequestError::Schema("request must be a JSON object".to_string()))?;

    let mut v = None;
    let mut proxy_port = None;
    let mut token = None;
    let mut scheme = None;
    let mut host = None;
    let mut port = None;
    let mut target = None;
    let mut accept = None;
    let mut max_body = None;
    let mut max_header_bytes = None;
    let mut timeout_ms = None;
    let mut user_agent = None;
    let mut mode = None;

    for (key, value) in map {
        match key.as_str() {
            "v" => v = Some(required_u64(value, "v")?),
            "proxy_port" => proxy_port = Some(required_u64(value, "proxy_port")?),
            "token" => token = Some(required_text(value, "token")?),
            "scheme" => scheme = Some(required_text(value, "scheme")?),
            "host" => host = Some(required_text(value, "host")?),
            "port" => port = Some(required_u64(value, "port")?),
            "target" => target = Some(required_text(value, "target")?),
            "accept" => accept = Some(required_text(value, "accept")?),
            "max_body" => max_body = Some(required_u64(value, "max_body")?),
            "max_header_bytes" => max_header_bytes = Some(required_u64(value, "max_header_bytes")?),
            "timeout_ms" => timeout_ms = Some(required_u64(value, "timeout_ms")?),
            "user_agent" => user_agent = Some(required_text(value, "user_agent")?),
            "mode" => mode = Some(required_text(value, "mode")?),
            other => {
                return Err(RequestError::Schema(format!(
                    "unknown request key {other:?}"
                )))
            }
        }
    }

    let v = v.ok_or_else(|| missing("v"))?;
    if v != 1 {
        return Err(RequestError::Schema(format!("v must be 1, got {v}")));
    }
    let proxy_port = port_field(proxy_port, "proxy_port")?;
    let token = token.ok_or_else(|| missing("token"))?;
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(RequestError::Schema(format!(
            "token must be 1..={MAX_TOKEN_BYTES} bytes"
        )));
    }
    if !token.bytes().all(is_header_safe) {
        return Err(RequestError::Schema(
            "token must be printable ASCII".to_string(),
        ));
    }
    let host = host.ok_or_else(|| missing("host"))?;
    if host.is_empty() || host.len() > MAX_HOST_BYTES {
        return Err(RequestError::Schema(format!(
            "host must be 1..={MAX_HOST_BYTES} bytes"
        )));
    }
    if !host.bytes().all(is_header_safe) {
        return Err(RequestError::Schema(
            "host must be printable ASCII".to_string(),
        ));
    }
    let port = port_field(port, "port")?;
    let target = target.ok_or_else(|| missing("target"))?;
    if !target.starts_with('/') || target.len() > MAX_TARGET_BYTES {
        return Err(RequestError::Schema(format!(
            "target must start with '/' and be at most {MAX_TARGET_BYTES} bytes"
        )));
    }
    if !target.bytes().all(is_header_safe) {
        return Err(RequestError::Schema(
            "target must be printable ASCII".to_string(),
        ));
    }
    let accept = accept.ok_or_else(|| missing("accept"))?;
    if accept.len() > MAX_ACCEPT_BYTES || !accept.bytes().all(is_header_safe) {
        return Err(RequestError::Schema(
            "accept must be printable ASCII".to_string(),
        ));
    }
    let max_body = max_body.ok_or_else(|| missing("max_body"))?;
    if max_body == 0 || max_body > MAX_BODY_CAP {
        return Err(RequestError::Schema(format!(
            "max_body must be 1..={MAX_BODY_CAP}"
        )));
    }
    let max_header_bytes_raw = max_header_bytes.ok_or_else(|| missing("max_header_bytes"))?;
    if max_header_bytes_raw == 0 || max_header_bytes_raw > MAX_HEADER_CAP as u64 {
        return Err(RequestError::Schema(format!(
            "max_header_bytes must be 1..={MAX_HEADER_CAP}"
        )));
    }
    let timeout_ms = timeout_ms.ok_or_else(|| missing("timeout_ms"))?;
    if timeout_ms == 0 || timeout_ms > MAX_TIMEOUT_MS {
        return Err(RequestError::Schema(format!(
            "timeout_ms must be 1..={MAX_TIMEOUT_MS}"
        )));
    }
    let user_agent = user_agent.ok_or_else(|| missing("user_agent"))?;
    if user_agent.len() > MAX_USER_AGENT_BYTES || !user_agent.bytes().all(is_header_safe) {
        return Err(RequestError::Schema(
            "user_agent must be printable ASCII".to_string(),
        ));
    }
    let mode_text = mode.ok_or_else(|| missing("mode"))?;
    let scheme = match scheme.ok_or_else(|| missing("scheme"))?.as_str() {
        "http" => Scheme::Http,
        "https" => Scheme::Https,
        other => {
            return Err(RequestError::Schema(format!(
                "scheme must be http or https, got {other:?}"
            )))
        }
    };
    let mode = match mode_text.as_str() {
        "proxy" => Mode::Proxy,
        "direct" => Mode::Direct,
        other => {
            return Err(RequestError::Schema(format!(
                "mode must be proxy or direct, got {other:?}"
            )))
        }
    };

    Ok(Request {
        v: 1,
        proxy_port,
        token,
        scheme,
        host,
        port,
        target,
        accept,
        max_body,
        max_header_bytes: max_header_bytes_raw as usize,
        timeout_ms,
        user_agent,
        mode,
    })
}

/// Run one fetch over an already-open `tunnel` and report it as a frame.
/// Never returns `Err`: every failure becomes an error frame with a typed
/// `error` kind, so the caller can always write something and exit 0.
pub fn fetch_over<S: Read + Write>(mut tunnel: S, req: &Request) -> Frame {
    match run(&mut tunnel, req) {
        Ok(frame) => frame,
        Err(kind) => Frame::error(&kind),
    }
}

fn run<S: Read + Write>(tunnel: &mut S, req: &Request) -> Result<Frame, String> {
    // INV-52: no TLS in this build. Refused before any byte moves — before
    // the CONNECT too, so the pump never learns of an https hop it cannot
    // serve.
    #[cfg(not(feature = "net"))]
    {
        if req.scheme == Scheme::Https {
            return Err(KIND_TLS_UNAVAILABLE.to_string());
        }
    }

    if req.mode == Mode::Proxy {
        proxy_connect(tunnel, req)?;
    }

    match req.scheme {
        // Plain HTTP: the tunnel already reaches the origin.
        Scheme::Http => http_over(tunnel, req, None),
        // HTTPS (P-39n, `net` only): the TLS handshake rides the tunnel
        // first — through the pump's CONNECT when mode is proxy — then the
        // very same bounded HTTP exchange runs over it.
        #[cfg(feature = "net")]
        Scheme::Https => tls::https_over_web_roots(tunnel, req),
        // INV-52: no TLS in this build; refused before any byte moves. The
        // match needs the arm to be exhaustive.
        #[cfg(not(feature = "net"))]
        Scheme::Https => Err(KIND_TLS_UNAVAILABLE.to_string()),
    }
}

/// The pump's CONNECT (mode `proxy`): one request, the reply's status line
/// checked, the tunnel then carries origin bytes.
fn proxy_connect<S: Read + Write>(tunnel: &mut S, req: &Request) -> Result<(), String> {
    let connect = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Authorization: Bearer {token}\r\n\r\n",
        host = req.host,
        port = req.port,
        token = req.token,
    );
    tunnel
        .write_all(connect.as_bytes())
        .map_err(|_| KIND_CONNECT_FAILED.to_string())?;
    tunnel
        .flush()
        .map_err(|_| KIND_CONNECT_FAILED.to_string())?;
    let reply = read_head(tunnel, req.max_header_bytes)?;
    if reply.status != 200 {
        return Err(KIND_CONNECT_FAILED.to_string());
    }
    Ok(())
}

/// The bounded HTTP/1.1 GET and its reply, over an established tunnel
/// (plain, or TLS-decoded when `tls` is set). This is INV-46's ONLY path
/// web bytes ever take.
fn http_over<S: Read + Write>(
    tunnel: &mut S,
    req: &Request,
    tls: Option<TlsInfo>,
) -> Result<Frame, String> {
    let user_agent = if req.user_agent.is_empty() {
        DEFAULT_USER_AGENT
    } else {
        req.user_agent.as_str()
    };
    let accept = if req.accept.is_empty() {
        DEFAULT_ACCEPT
    } else {
        req.accept.as_str()
    };
    let get = format!(
        "GET {target} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: {agent}\r\nAccept: {accept_value}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        target = req.target,
        host = req.host,
        port = req.port,
        agent = user_agent,
        accept_value = accept,
    );
    tunnel
        .write_all(get.as_bytes())
        .map_err(|_| KIND_IO.to_string())?;
    tunnel.flush().map_err(|_| KIND_IO.to_string())?;

    // Skip informational replies (1xx), at most MAX_INFORMATIONAL of them.
    let mut informational = 0;
    let head = loop {
        let head = read_head(tunnel, req.max_header_bytes)?;
        if (100..200).contains(&head.status) {
            informational += 1;
            if informational > MAX_INFORMATIONAL {
                return Err(KIND_HTTP_PARSE.to_string());
            }
            continue;
        }
        break head;
    };

    let content_type = header_value(&head.headers, "content-type");
    // Redirects are reported, never followed (design note §5.2 step 6).
    let location = match header_value(&head.headers, "location") {
        Some(value) => {
            if value.len() > MAX_LOCATION_BYTES {
                return Err(KIND_TOO_LARGE_HEADERS.to_string());
            }
            Some(value)
        }
        None => None,
    };
    // INV-46: refuse any content coding BEFORE the body is read.
    if let Some(encoding) = header_value(&head.headers, "content-encoding") {
        if !encoding.eq_ignore_ascii_case("identity") {
            return Err(KIND_ENCODING_REFUSED.to_string());
        }
    }

    let content_length = framing(&head.headers)?;
    let mut body = Vec::new();
    let truncated = match content_length {
        Some(length) => read_length_body(tunnel, &mut body, length, req.max_body)?,
        None => {
            if has_transfer_encoding(&head.headers) {
                read_chunked(tunnel, &mut body, req.max_body, req.max_header_bytes)?
            } else {
                read_until_close(tunnel, &mut body, req.max_body)
            }
        }
    };

    Ok(Frame {
        header: FrameHeader {
            status: Some(head.status),
            reason: Some(head.reason),
            content_type,
            content_length,
            location,
            body_len: u64::try_from(body.len()).unwrap_or(u64::MAX),
            truncated,
            tls,
            error: None,
        },
        body,
    })
}

struct Head {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
}

/// Read one head (status line + headers) bounded by `cap` bytes and
/// [`MAX_HEADERS`] lines. Reads one byte at a time so no body byte beyond
/// the head is ever consumed from the tunnel. EOF before the head ends is a
/// parse refusal.
fn read_head<S: Read>(stream: &mut S, cap: usize) -> Result<Head, String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let got = stream
            .read(&mut byte)
            .map_err(|_| KIND_HTTP_PARSE.to_string())?;
        if got == 0 {
            return Err(KIND_HTTP_PARSE.to_string());
        }
        let Some(&b) = byte.first() else {
            return Err(KIND_HTTP_PARSE.to_string());
        };
        buf.push(b);
        if buf.ends_with(b"\r\n\r\n") {
            let end = buf.len() - 4;
            if end > cap {
                return Err(KIND_TOO_LARGE_HEADERS.to_string());
            }
            return parse_head(&buf, end);
        }
        if buf.len() > cap + 4 {
            return Err(KIND_TOO_LARGE_HEADERS.to_string());
        }
    }
}

fn parse_head(buf: &[u8], end: usize) -> Result<Head, String> {
    let head_bytes = buf.get(..end).ok_or_else(|| KIND_HTTP_PARSE.to_string())?;
    let text = std::str::from_utf8(head_bytes).map_err(|_| KIND_HTTP_PARSE.to_string())?;

    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| KIND_HTTP_PARSE.to_string())?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().ok_or_else(|| KIND_HTTP_PARSE.to_string())?;
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        return Err(KIND_HTTP_PARSE.to_string());
    }
    let code = parts.next().ok_or_else(|| KIND_HTTP_PARSE.to_string())?;
    if code.len() != 3 {
        return Err(KIND_HTTP_PARSE.to_string());
    }
    let status: u16 = code.parse().map_err(|_| KIND_HTTP_PARSE.to_string())?;
    if !(100..=599).contains(&status) {
        return Err(KIND_HTTP_PARSE.to_string());
    }
    let reason = parts.next().unwrap_or("").to_string();

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if headers.len() >= MAX_HEADERS {
            return Err(KIND_TOO_LARGE_HEADERS.to_string());
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(KIND_HTTP_PARSE.to_string());
        };
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
    Ok(Head {
        status,
        reason,
        headers,
    })
}

/// Classify the framing headers. Smuggling shapes are refused (design note
/// §943): `Content-Length` together with `Transfer-Encoding`, a
/// `Transfer-Encoding` whose only coding is not `chunked`, duplicate or
/// unparseable `Content-Length` values.
fn framing(headers: &[(String, String)]) -> Result<Option<u64>, String> {
    let length_values: Vec<&str> = header_values(headers, "content-length").collect();
    let mut codings: Vec<&str> = Vec::new();
    for value in header_values(headers, "transfer-encoding") {
        for part in value.split(',') {
            codings.push(part.trim());
        }
    }
    let length = match length_values.as_slice() {
        [] => None,
        [only] => {
            let raw = only
                .parse::<u64>()
                .map_err(|_| KIND_HTTP_PARSE.to_string())?;
            Some(raw)
        }
        _ => return Err(KIND_HTTP_PARSE.to_string()),
    };
    if codings.is_empty() {
        return Ok(length);
    }
    if length.is_some() {
        // Content-Length and Transfer-Encoding together: refuse.
        return Err(KIND_HTTP_PARSE.to_string());
    }
    if codings.len() != 1 || codings.first().copied() != Some("chunked") {
        return Err(KIND_HTTP_PARSE.to_string());
    }
    Ok(None)
}

fn has_transfer_encoding(headers: &[(String, String)]) -> bool {
    header_values(headers, "transfer-encoding").next().is_some()
}

fn read_length_body<S: Read>(
    stream: &mut S,
    out: &mut Vec<u8>,
    length: u64,
    cap: u64,
) -> Result<bool, String> {
    if length > cap {
        // Read up to the cap, then stop and mark truncated; the rest of the
        // connection is abandoned (design note §4.4).
        let room = usize::try_from(cap).unwrap_or(0);
        read_exact_n(stream, out, room)?;
        return Ok(true);
    }
    let want = usize::try_from(length).map_err(|_| KIND_HTTP_PARSE.to_string())?;
    read_exact_n(stream, out, want)?;
    Ok(false)
}

/// Read a chunked body bounded by `cap`. Returns `truncated`.
fn read_chunked<S: Read>(
    stream: &mut S,
    out: &mut Vec<u8>,
    cap: u64,
    header_budget: usize,
) -> Result<bool, String> {
    let mut sum: u64 = 0;
    loop {
        let line = read_line(stream, MAX_CHUNK_LINE_BYTES)?;
        let text = std::str::from_utf8(&line).map_err(|_| KIND_HTTP_PARSE.to_string())?;
        let size_text = text.split(';').next().unwrap_or("").trim();
        // A chunk-size line longer than 16 hex digits is refused (§937):
        // no extensions beyond a short `;ext`, no absurd sizes.
        if size_text.is_empty() || size_text.len() > 16 {
            return Err(KIND_HTTP_PARSE.to_string());
        }
        let size = u64::from_str_radix(size_text, 16).map_err(|_| KIND_HTTP_PARSE.to_string())?;
        if size == 0 {
            read_trailers(stream, header_budget)?;
            return Ok(false);
        }
        sum = sum
            .checked_add(size)
            .ok_or_else(|| KIND_HTTP_PARSE.to_string())?;
        if sum > cap {
            let used = u64::try_from(out.len()).unwrap_or(u64::MAX);
            let room = usize::try_from(cap.saturating_sub(used)).unwrap_or(0);
            read_exact_n(stream, out, room)?;
            return Ok(true);
        }
        let want = usize::try_from(size).map_err(|_| KIND_HTTP_PARSE.to_string())?;
        read_exact_n(stream, out, want)?;
        let terminator = read_line(stream, MAX_CHUNK_LINE_BYTES)?;
        if !terminator.is_empty() {
            return Err(KIND_HTTP_PARSE.to_string());
        }
    }
}

fn read_trailers<S: Read>(stream: &mut S, budget: usize) -> Result<(), String> {
    let mut used = 0usize;
    for _ in 0..MAX_HEADERS {
        let line = read_line(stream, MAX_CHUNK_LINE_BYTES)?;
        used += line.len().saturating_add(2);
        if used > budget {
            return Err(KIND_TOO_LARGE_HEADERS.to_string());
        }
        if line.is_empty() {
            return Ok(());
        }
    }
    Err(KIND_TOO_LARGE_HEADERS.to_string())
}

/// Read until the tunnel closes, bounded by `cap`. Returns whether the cap
/// was hit (and the body therefore truncated).
fn read_until_close<S: Read>(stream: &mut S, out: &mut Vec<u8>, cap: u64) -> bool {
    let mut tmp = [0u8; 8192];
    loop {
        let used = u64::try_from(out.len()).unwrap_or(u64::MAX);
        if used >= cap {
            return true;
        }
        match stream.read(&mut tmp) {
            Ok(0) => return false,
            Ok(got) => {
                let room = usize::try_from(cap - used).unwrap_or(0);
                let keep = got.min(room);
                let take = tmp.get(..keep).unwrap_or(&[]);
                out.extend_from_slice(take);
            }
            Err(_) => return true,
        }
    }
}

fn read_exact_n<S: Read>(stream: &mut S, out: &mut Vec<u8>, want: usize) -> Result<(), String> {
    // `take` bounds the underlying reads so not a single byte past `want`
    // is consumed from the tunnel (the bytes after a length-delimited body
    // still belong to the connection's framing).
    let mut limited = stream.take(want as u64);
    let got = limited
        .read_to_end(out)
        .map_err(|_| KIND_HTTP_PARSE.to_string())?;
    if got != want {
        // The origin promised more bytes than it sent: refuse.
        return Err(KIND_HTTP_PARSE.to_string());
    }
    Ok(())
}

/// Read one CRLF-terminated line (the terminator is stripped), bounded by
/// `cap` bytes. EOF before a newline is a refusal.
fn read_line<S: Read>(stream: &mut S, cap: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let got = stream
            .read(&mut byte)
            .map_err(|_| KIND_HTTP_PARSE.to_string())?;
        if got == 0 {
            return Err(KIND_HTTP_PARSE.to_string());
        }
        let Some(&b) = byte.first() else {
            return Err(KIND_HTTP_PARSE.to_string());
        };
        if b == b'\n' {
            if out.last() == Some(&b'\r') {
                out.pop();
            }
            return Ok(out);
        }
        out.push(b);
        if out.len() > cap {
            return Err(KIND_HTTP_PARSE.to_string());
        }
    }
}

fn header_values<'a>(
    headers: &'a [(String, String)],
    name: &'static str,
) -> impl Iterator<Item = &'a str> {
    headers
        .iter()
        .filter(move |(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

fn header_value(headers: &[(String, String)], name: &'static str) -> Option<String> {
    header_values(headers, name).next().map(str::to_string)
}

fn is_header_safe(byte: u8) -> bool {
    (0x21..=0x7e).contains(&byte)
}

fn required_u64(value: &serde_json::Value, name: &str) -> Result<u64, RequestError> {
    value.as_u64().ok_or_else(|| wrong_type(name))
}

fn required_text(value: &serde_json::Value, name: &str) -> Result<String, RequestError> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| wrong_type(name))
}

fn port_field(raw: Option<u64>, name: &str) -> Result<u16, RequestError> {
    let raw = raw.ok_or_else(|| missing(name))?;
    let port = u16::try_from(raw).map_err(|_| wrong_type(name))?;
    if port == 0 {
        return Err(RequestError::Schema(format!("{name} must be 1..=65535")));
    }
    Ok(port)
}

fn wrong_type(name: &str) -> RequestError {
    RequestError::Schema(format!("{name} has the wrong JSON type"))
}

fn missing(name: &str) -> RequestError {
    RequestError::Schema(format!("missing request key {name:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// An in-memory tunnel: the test pre-loads what the "origin" will send
    /// and can inspect what the fetcher sent afterwards.
    struct TestTunnel {
        server: Vec<u8>,
        pos: usize,
        sent: Rc<RefCell<Vec<u8>>>,
    }

    impl TestTunnel {
        fn new(response: &str) -> Self {
            TestTunnel {
                server: response.as_bytes().to_vec(),
                pos: 0,
                sent: Rc::new(RefCell::new(Vec::new())),
            }
        }
    }

    impl Read for TestTunnel {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let remaining = self.server.len() - self.pos;
            let n = remaining.min(out.len());
            out[..n].copy_from_slice(&self.server[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    impl Write for TestTunnel {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.sent.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn request() -> Request {
        Request {
            v: 1,
            proxy_port: 1,
            token: "tok".to_string(),
            scheme: Scheme::Http,
            host: "example.net".to_string(),
            port: 80,
            target: "/".to_string(),
            accept: "text/plain".to_string(),
            max_body: 1024,
            max_header_bytes: 1024,
            timeout_ms: 1000,
            user_agent: "ua".to_string(),
            mode: Mode::Direct,
        }
    }

    fn kind_of(frame: &Frame) -> Option<&str> {
        frame.header.error.as_deref()
    }

    #[test]
    fn parses_content_length_body() {
        let tunnel = TestTunnel::new(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello",
        );
        let frame = fetch_over(tunnel, &request());
        assert_eq!(kind_of(&frame), None);
        assert_eq!(frame.header.status, Some(200));
        assert_eq!(frame.header.reason.as_deref(), Some("OK"));
        assert_eq!(frame.header.content_type.as_deref(), Some("text/plain"));
        assert_eq!(frame.header.content_length, Some(5));
        assert_eq!(frame.body, b"hello");
        assert!(!frame.header.truncated);
    }

    #[test]
    fn parses_chunked_body_bounded() {
        let tunnel = TestTunnel::new(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        );
        let frame = fetch_over(tunnel, &request());
        assert_eq!(kind_of(&frame), None);
        assert_eq!(frame.header.status, Some(200));
        assert_eq!(frame.header.content_length, None);
        assert_eq!(frame.body, b"hello");
        assert!(!frame.header.truncated);
    }

    #[test]
    fn chunk_size_line_over_16_hex_refused() {
        let tunnel = TestTunnel::new(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFFF\r\n\r\n",
        );
        let frame = fetch_over(tunnel, &request());
        assert_eq!(kind_of(&frame), Some(KIND_HTTP_PARSE));
    }

    #[test]
    fn gzip_content_encoding_refused() {
        let tunnel = TestTunnel::new(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 5\r\n\r\nhello",
        );
        let frame = fetch_over(tunnel, &request());
        assert_eq!(kind_of(&frame), Some(KIND_ENCODING_REFUSED));
        assert!(frame.body.is_empty());
    }

    #[test]
    fn content_length_and_chunked_together_refused() {
        let tunnel = TestTunnel::new(
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        let frame = fetch_over(tunnel, &request());
        assert_eq!(kind_of(&frame), Some(KIND_HTTP_PARSE));
    }

    #[test]
    fn oversize_headers_refused() {
        let response = format!("HTTP/1.1 200 OK\r\nX-Pad: {}\r\n\r\n", "a".repeat(2000));
        let tunnel = TestTunnel::new(&response);
        let frame = fetch_over(tunnel, &request());
        assert_eq!(kind_of(&frame), Some(KIND_TOO_LARGE_HEADERS));
    }

    #[test]
    fn body_over_cap_truncated_and_marked() {
        let mut req = request();
        req.max_body = 5;
        let tunnel = TestTunnel::new("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789");
        let frame = fetch_over(tunnel, &req);
        assert_eq!(kind_of(&frame), None);
        assert_eq!(frame.body, b"01234");
        assert!(frame.header.truncated);
        assert_eq!(frame.header.content_length, Some(10));
    }

    #[test]
    fn chunked_over_cap_truncated_and_marked() {
        let mut req = request();
        req.max_body = 5;
        let tunnel = TestTunnel::new(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n4\r\nefgh\r\n0\r\n\r\n",
        );
        let frame = fetch_over(tunnel, &req);
        assert_eq!(kind_of(&frame), None);
        assert_eq!(frame.body, b"abcde");
        assert!(frame.header.truncated);
    }

    #[test]
    fn until_close_body_parsed() {
        let tunnel = TestTunnel::new("HTTP/1.1 200 OK\r\nX-No-Framing: 1\r\n\r\nstreamed body");
        let frame = fetch_over(tunnel, &request());
        assert_eq!(kind_of(&frame), None);
        assert_eq!(frame.body, b"streamed body");
        assert!(!frame.header.truncated);
    }

    #[test]
    fn redirect_not_followed_location_reported() {
        let tunnel = TestTunnel::new(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: http://example.net/next\r\nContent-Length: 0\r\n\r\n",
        );
        let sent_handle = Rc::clone(&tunnel.sent);
        let frame = fetch_over(tunnel, &request());
        assert_eq!(kind_of(&frame), None);
        assert_eq!(frame.header.status, Some(301));
        assert_eq!(
            frame.header.location.as_deref(),
            Some("http://example.net/next")
        );
        assert!(frame.body.is_empty());
        // Exactly one request went out; nothing was followed.
        let sent = String::from_utf8(sent_handle.borrow().clone()).unwrap();
        assert_eq!(sent.matches("GET ").count(), 1);
        assert!(!sent.contains("/next"));
    }

    #[test]
    fn connect_token_sent_first() {
        let mut req = request();
        req.mode = Mode::Proxy;
        let tunnel = TestTunnel::new(
            "HTTP/1.1 200 Connection established\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        );
        let sent_handle = Rc::clone(&tunnel.sent);
        let frame = fetch_over(tunnel, &req);
        assert_eq!(kind_of(&frame), None);
        assert_eq!(frame.body, b"hi");
        let sent = String::from_utf8(sent_handle.borrow().clone()).unwrap();
        assert!(sent.starts_with("CONNECT example.net:80 HTTP/1.1\r\n"));
        assert!(sent.contains("Host: example.net:80\r\n"));
        assert!(sent.contains("Proxy-Authorization: Bearer tok\r\n"));
        // The CONNECT goes out before the GET.
        assert!(sent.find("CONNECT").unwrap() < sent.find("GET ").unwrap());
    }

    #[test]
    fn connect_non_200_is_connect_failed() {
        let mut req = request();
        req.mode = Mode::Proxy;
        let tunnel = TestTunnel::new("HTTP/1.1 403 Denied\r\n\r\n");
        let frame = fetch_over(tunnel, &req);
        assert_eq!(kind_of(&frame), Some(KIND_CONNECT_FAILED));
    }

    /// INV-52: the default build (no `net`) refuses https before dialing.
    /// The net build's https path is exercised by tests/tls.rs instead.
    #[cfg(not(feature = "net"))]
    #[test]
    fn https_without_net_is_tls_unavailable() {
        let mut req = request();
        req.scheme = Scheme::Https;
        let tunnel = TestTunnel::new("HTTP/1.1 200 OK\r\n\r\n");
        let sent_handle = Rc::clone(&tunnel.sent);
        let frame = fetch_over(tunnel, &req);
        assert_eq!(kind_of(&frame), Some(KIND_TLS_UNAVAILABLE));
        assert!(sent_handle.borrow().is_empty());
    }

    /// P-39n: with `net` on, an https hop over a tunnel that is not TLS is
    /// the opaque `tls_failed` kind — and nothing was sent in the clear.
    #[cfg(feature = "net")]
    #[test]
    fn https_over_a_plaintext_tunnel_is_tls_failed() {
        let mut req = request();
        req.scheme = Scheme::Https;
        let tunnel = TestTunnel::new("HTTP/1.1 200 OK\r\n\r\n");
        let sent_handle = Rc::clone(&tunnel.sent);
        let frame = fetch_over(tunnel, &req);
        assert_eq!(kind_of(&frame), Some(KIND_TLS_FAILED));
        // The client hello may have been written (in vain); whatever moved,
        // no HTTP request did.
        let sent = sent_handle.borrow().clone();
        assert!(!sent.windows(4).any(|w| w == b"GET "));
    }

    #[test]
    fn informational_replies_are_skipped() {
        let tunnel = TestTunnel::new(
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        );
        let frame = fetch_over(tunnel, &request());
        assert_eq!(kind_of(&frame), None);
        assert_eq!(frame.body, b"hi");
    }

    #[test]
    fn garbage_response_is_typed_error_not_panic() {
        let location_too_long = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://example.net/{}\r\nContent-Length: 0\r\n\r\n",
            "a".repeat(5000)
        );
        let cases: Vec<(String, &'static str)> = vec![
            (String::new(), KIND_HTTP_PARSE),
            ("x".to_string(), KIND_HTTP_PARSE),
            ("\r\n\r\n".to_string(), KIND_HTTP_PARSE),
            ("HTTP/1.1 abc OK\r\n\r\n".to_string(), KIND_HTTP_PARSE),
            ("HTTP/9.9 200 OK\r\n\r\n".to_string(), KIND_HTTP_PARSE),
            ("HTTP/1.1 20 OK\r\n\r\n".to_string(), KIND_HTTP_PARSE),
            ("HTTP/1.1 600 OK\r\n\r\n".to_string(), KIND_HTTP_PARSE),
            ("HTTP/1.1 99 OK\r\n\r\n".to_string(), KIND_HTTP_PARSE),
            ("HTTP/1.1".to_string(), KIND_HTTP_PARSE),
            (
                "HTTP/1.1 200 OK\r\nNoColonHere\r\n\r\n".to_string(),
                KIND_HTTP_PARSE,
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n".to_string(),
                KIND_HTTP_PARSE,
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n".to_string(),
                KIND_HTTP_PARSE,
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"
                    .to_string(),
                KIND_HTTP_PARSE,
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
                    .to_string(),
                KIND_HTTP_PARSE,
            ),
            (
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n".to_string(),
                KIND_HTTP_PARSE,
            ),
            (
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\n\r\n".to_string(),
                KIND_HTTP_PARSE,
            ),
            (
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n\r\n".to_string(),
                KIND_HTTP_PARSE,
            ),
            (
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel".to_string(),
                KIND_HTTP_PARSE,
            ),
            (
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX".to_string(),
                KIND_HTTP_PARSE,
            ),
            (
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-T: 1\r\n".to_string(),
                KIND_HTTP_PARSE,
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: 2\r\n\r\nhi"
                    .to_string(),
                KIND_ENCODING_REFUSED,
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhi".to_string(),
                KIND_HTTP_PARSE,
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 4294967296\r\n\r\n".to_string(),
                KIND_HTTP_PARSE,
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n".to_string(),
                KIND_HTTP_PARSE,
            ),
            (location_too_long, KIND_TOO_LARGE_HEADERS),
            (
                "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n"
                    .to_string(),
                KIND_HTTP_PARSE,
            ),
        ];
        assert!(cases.len() >= 20);
        for (response, want) in &cases {
            let tunnel = TestTunnel::new(response);
            let frame = fetch_over(tunnel, &request());
            assert_eq!(
                kind_of(&frame),
                Some(*want),
                "case {response:?} gave the wrong kind"
            );
            assert!(frame.body.is_empty(), "case {response:?} leaked body bytes");
        }
    }

    fn request_json(extra: &str) -> String {
        format!(
            concat!(
                "{{\"v\":1,\"proxy_port\":9,\"token\":\"t\",\"scheme\":\"http\",",
                "\"host\":\"example.net\",\"port\":80,\"target\":\"/\",",
                "\"accept\":\"*/*\",\"max_body\":1024,\"max_header_bytes\":1024,",
                "\"timeout_ms\":1000,\"user_agent\":\"ua\",\"mode\":\"direct\"{extra}}}"
            ),
            extra = extra
        )
    }

    #[test]
    fn request_round_trips_all_fields() {
        let req = read_request(request_json("").as_bytes()).unwrap();
        assert_eq!(req.v, 1);
        assert_eq!(req.proxy_port, 9);
        assert_eq!(req.scheme, Scheme::Http);
        assert_eq!(req.mode, Mode::Direct);
        assert_eq!(req.host, "example.net");
        assert_eq!(req.port, 80);
        assert_eq!(req.max_body, 1024);
        assert_eq!(req.max_header_bytes, 1024);
        assert_eq!(req.timeout_ms, 1000);
    }

    #[test]
    fn request_rejects_unknown_key() {
        assert!(matches!(
            read_request(request_json(",\"bogus\":1").as_bytes()),
            Err(RequestError::Schema(_))
        ));
    }

    #[test]
    fn request_rejects_missing_key() {
        let raw = b"{\"v\":1}".to_vec();
        assert!(matches!(read_request(&raw), Err(RequestError::Schema(_))));
    }
    #[test]
    fn request_rejects_out_of_range_budgets() {
        let over_body = request_json("").replace("\"max_body\":1024", "\"max_body\":99999999999");
        assert!(matches!(
            read_request(over_body.as_bytes()),
            Err(RequestError::Schema(_))
        ));
        let over_timeout = request_json("").replace("\"timeout_ms\":1000", "\"timeout_ms\":999999");
        assert!(matches!(
            read_request(over_timeout.as_bytes()),
            Err(RequestError::Schema(_))
        ));
    }

    #[test]
    fn request_rejects_header_injection() {
        let crlf_token = request_json("").replace("\"token\":\"t\"", "\"token\":\"a\\r\\nb\"");
        assert!(matches!(
            read_request(crlf_token.as_bytes()),
            Err(RequestError::Schema(_))
        ));
        let space_host = request_json("").replace("\"host\":\"example.net\"", "\"host\":\"a b\"");
        assert!(matches!(
            read_request(space_host.as_bytes()),
            Err(RequestError::Schema(_))
        ));
    }

    #[cfg(not(feature = "net"))]
    #[test]
    fn request_accepts_https_and_proxy_but_fetch_refuses_tls() {
        let https = request_json("")
            .replace("\"scheme\":\"http\"", "\"scheme\":\"https\"")
            .replace("\"mode\":\"direct\"", "\"mode\":\"proxy\"");
        let req = read_request(https.as_bytes()).unwrap();
        assert_eq!(req.scheme, Scheme::Https);
        assert_eq!(req.mode, Mode::Proxy);
        let tunnel = TestTunnel::new("");
        let frame = fetch_over(tunnel, &req);
        assert_eq!(kind_of(&frame), Some(KIND_TLS_UNAVAILABLE));
    }
}
