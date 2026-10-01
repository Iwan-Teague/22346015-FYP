//! A minimal HTTP/1.1 client for loopback model servers.
//!
//! **Why hand-rolled.** Design §3.2 asks for a thin client with no hyper and
//! no reqwest, because every popular Rust LLM client pulls in C through TLS.
//! The H1 build talks only to loopback over plain HTTP (§3.2 endpoint
//! rules; TLS is the future `hosted` feature), so a request/response
//! exchange over `std::net::TcpStream` covers it with ZERO new dependencies:
//! one `POST` or `GET` per connection (`Connection: close`), a bounded
//! response head, and a bounded body framed by `Content-Length`, `chunked`,
//! or connection close. `ureq` (default features off) was the alternative;
//! it would add a dependency tree to review for less control over the
//! bounds and timeouts below.
//!
//! **Bounds, all fail-closed:**
//! - connect timeout, per-read idle timeout, and a total deadline checked
//!   before every connect, write and read (each read waits at most
//!   `min(read_timeout, time left)`);
//! - response head ≤ `max_head_bytes`, body ≤ `max_body_bytes` (a server
//!   that streams forever hits the deadline or the size cap);
//! - `Transfer-Encoding` other than exactly `chunked`, both
//!   `Transfer-Encoding` and `Content-Length`, conflicting lengths, a bad
//!   chunk size, or a non-HTTP status line are `Malformed`.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// Limits for one exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpLimits {
    /// Connect timeout.
    pub connect_timeout: Duration,
    /// Longest wait for any single read (idle timeout).
    pub read_timeout: Duration,
    /// Largest response head (status line + headers, and trailers).
    pub max_head_bytes: usize,
    /// Largest response body after de-chunking.
    pub max_body_bytes: usize,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(60),
            max_head_bytes: 32 * 1024,
            max_body_bytes: 8 * 1024 * 1024,
        }
    }
}

/// A received response.
#[derive(Debug)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// `Content-Type`, lowercased, without parameters.
    pub content_type: Option<String>,
    /// `Retry-After` in delta-seconds form (digits only, at most one day).
    /// The HTTP-date form is ignored (treated as absent): honouring it
    /// would need the wall clock, and the backoff applies instead.
    pub retry_after_secs: Option<u64>,
    /// The `Server` header, at most 256 bytes: a CLAIM (§3.5).
    pub server: Option<String>,
    /// The (de-chunked) body.
    pub body: Vec<u8>,
}

/// A parsed response head.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Head {
    status: u16,
    framing: Framing,
    content_type: Option<String>,
    retry_after_secs: Option<u64>,
    server: Option<String>,
}

/// Longest `Server` claim kept.
const SERVER_CLAIM_MAX: usize = 256;
/// Largest `Retry-After` honoured, in seconds.
const RETRY_AFTER_MAX_SECS: u64 = 86_400;

/// Why an exchange failed. Messages are harness-authored; no request or
/// response bytes, and never a header value, are included.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    /// Refused or reset.
    #[error("connection failed ({0})")]
    Connect(String),
    /// The connect timeout elapsed.
    #[error("connect timeout")]
    ConnectTimeout,
    /// A read waited longer than the read timeout.
    #[error("read timeout")]
    ReadTimeout,
    /// The total deadline elapsed.
    #[error("deadline exceeded")]
    Deadline,
    /// The response head or body exceeded its cap.
    #[error("{0} too large")]
    TooLarge(&'static str),
    /// Not a well-formed HTTP/1.x response.
    #[error("malformed HTTP response: {0}")]
    Malformed(&'static str),
    /// Another I/O error.
    #[error("I/O error ({0})")]
    Io(String),
}

fn left(deadline: Instant) -> Result<Duration, HttpError> {
    let now = Instant::now();
    if now >= deadline {
        return Err(HttpError::Deadline);
    }
    Ok(deadline - now)
}

fn io_kind(e: &io::Error) -> String {
    format!("{:?}", e.kind())
}

struct Conn {
    stream: TcpStream,
    buf: Vec<u8>,
    pos: usize,
    read_timeout: Duration,
    deadline: Instant,
    eof: bool,
}

impl Conn {
    /// Read more bytes into the buffer; returns how many (0 = EOF).
    fn fill(&mut self) -> Result<usize, HttpError> {
        let wait = self.read_timeout.min(left(self.deadline)?);
        self.stream
            .set_read_timeout(Some(wait.max(Duration::from_millis(1))))
            .map_err(|e| HttpError::Io(io_kind(&e)))?;
        let mut chunk = [0u8; 16 * 1024];
        match self.stream.read(&mut chunk) {
            Ok(0) => {
                self.eof = true;
                Ok(0)
            }
            Ok(n) => {
                self.buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
                Ok(n)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if Instant::now() >= self.deadline {
                    Err(HttpError::Deadline)
                } else {
                    Err(HttpError::ReadTimeout)
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(1),
            Err(e) => Err(HttpError::Io(io_kind(&e))),
        }
    }

    fn available(&self) -> &[u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }

    /// One CRLF-terminated line (without the CRLF), at most `max` bytes.
    fn line(&mut self, max: usize, what: &'static str) -> Result<Vec<u8>, HttpError> {
        loop {
            if let Some(i) = self.available().windows(2).position(|w| w == b"\r\n") {
                let line = self.available().get(..i).unwrap_or(&[]).to_vec();
                self.pos += i + 2;
                return Ok(line);
            }
            if self.available().len() > max {
                return Err(HttpError::TooLarge(what));
            }
            if self.fill()? == 0 {
                return Err(HttpError::Malformed("connection closed mid-line"));
            }
        }
    }

    /// Exactly `n` bytes.
    fn exact(&mut self, n: usize) -> Result<Vec<u8>, HttpError> {
        while self.available().len() < n {
            if self.fill()? == 0 {
                return Err(HttpError::Malformed("connection closed mid-body"));
            }
        }
        let out = self.available().get(..n).unwrap_or(&[]).to_vec();
        self.pos += n;
        Ok(out)
    }

    fn compact(&mut self) {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }
}

/// Parse a response head (without the final blank line). Pure.
fn parse_head(lines: &[Vec<u8>]) -> Result<Head, HttpError> {
    let m = HttpError::Malformed;
    let (status_line, headers) = lines.split_first().ok_or(m("empty head"))?;
    let sl = std::str::from_utf8(status_line).map_err(|_| m("status line"))?;
    let mut parts = sl.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(m("not HTTP/1.x"));
    }
    let code = parts.next().unwrap_or("");
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(m("status code"));
    }
    let status: u16 = code.parse().map_err(|_| m("status code"))?;
    if !(200..=599).contains(&status) {
        return Err(m("unsupported status class"));
    }
    let mut length: Option<usize> = None;
    let mut chunked = false;
    let mut content_type = None;
    let mut retry_after_secs = None;
    let mut server = None;
    for h in headers {
        let text = std::str::from_utf8(h).map_err(|_| m("header is not UTF-8"))?;
        if text.chars().any(|c| c.is_control() && c != '\t') {
            return Err(m("control character in a header"));
        }
        let (name, value) = text.split_once(':').ok_or(m("header without a colon"))?;
        if name.is_empty() || name.trim() != name {
            return Err(m("header name"));
        }
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "content-length" => {
                // Digits only: `usize::from_str` would accept a leading `+`
                // (H1d review F-7).
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(m("content-length"));
                }
                let n: usize = value.parse().map_err(|_| m("content-length"))?;
                if length.is_some_and(|l| l != n) {
                    return Err(m("conflicting content-length"));
                }
                length = Some(n);
            }
            "transfer-encoding" => {
                if !value.eq_ignore_ascii_case("chunked") || chunked {
                    return Err(m("unsupported transfer-encoding"));
                }
                chunked = true;
            }
            "content-type" => {
                let base = value
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                content_type = Some(base);
            }
            "retry-after" => {
                retry_after_secs = (!value.is_empty()
                    && value.len() <= 6
                    && value.bytes().all(|b| b.is_ascii_digit()))
                .then(|| value.parse::<u64>().ok())
                .flatten()
                .filter(|s| *s <= RETRY_AFTER_MAX_SECS);
            }
            "server" if value.len() <= SERVER_CLAIM_MAX && !value.is_empty() => {
                server = Some(value.to_owned());
            }
            _ => {}
        }
    }
    let framing = match (chunked, length) {
        (true, Some(_)) => return Err(m("both transfer-encoding and content-length")),
        (true, None) => Framing::Chunked,
        (false, Some(n)) => Framing::Length(n),
        (false, None) => Framing::Close,
    };
    Ok(Head {
        status,
        framing,
        content_type,
        retry_after_secs,
        server,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    Length(usize),
    Chunked,
    Close,
}

/// One exchange: connect to `addr`, send the request, read the response.
#[allow(clippy::too_many_arguments)]
pub fn exchange(
    addr: SocketAddr,
    method: &str,
    host_header: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    limits: &HttpLimits,
    deadline: Instant,
) -> Result<HttpResponse, HttpError> {
    let wait = limits.connect_timeout.min(left(deadline)?);
    let stream = TcpStream::connect_timeout(&addr, wait).map_err(|e| {
        if matches!(
            e.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ) {
            if Instant::now() >= deadline {
                HttpError::Deadline
            } else {
                HttpError::ConnectTimeout
            }
        } else {
            HttpError::Connect(io_kind(&e))
        }
    })?;
    let _ = stream.set_nodelay(true);
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\nAccept: text/event-stream, application/json\r\n"
    );
    for (k, v) in headers {
        head.push_str(k);
        head.push_str(": ");
        head.push_str(v);
        head.push_str("\r\n");
    }
    if !body.is_empty() || method == "POST" {
        head.push_str("Content-Type: application/json\r\n");
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    let mut s = stream;
    let wt = limits.read_timeout.min(left(deadline)?);
    s.set_write_timeout(Some(wt.max(Duration::from_millis(1))))
        .map_err(|e| HttpError::Io(io_kind(&e)))?;
    let write = |s: &mut TcpStream, b: &[u8]| {
        s.write_all(b).map_err(|e| {
            if matches!(
                e.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) {
                HttpError::Deadline
            } else {
                HttpError::Connect(io_kind(&e))
            }
        })
    };
    write(&mut s, head.as_bytes())?;
    write(&mut s, body)?;
    let _ = s.flush();

    let mut c = Conn {
        stream: s,
        buf: Vec::new(),
        pos: 0,
        read_timeout: limits.read_timeout,
        deadline,
        eof: false,
    };
    let mut lines = Vec::new();
    let mut head_bytes = 0usize;
    loop {
        let l = c.line(limits.max_head_bytes, "response head")?;
        head_bytes += l.len() + 2;
        if head_bytes > limits.max_head_bytes {
            return Err(HttpError::TooLarge("response head"));
        }
        if l.is_empty() {
            break;
        }
        lines.push(l);
    }
    let Head {
        status,
        framing,
        content_type,
        retry_after_secs,
        server,
    } = parse_head(&lines)?;
    c.compact();
    let body = match framing {
        Framing::Length(n) => {
            if n > limits.max_body_bytes {
                return Err(HttpError::TooLarge("response body"));
            }
            c.exact(n)?
        }
        Framing::Close => {
            while !c.eof {
                if c.available().len() > limits.max_body_bytes {
                    return Err(HttpError::TooLarge("response body"));
                }
                c.fill()?;
            }
            if c.available().len() > limits.max_body_bytes {
                return Err(HttpError::TooLarge("response body"));
            }
            c.available().to_vec()
        }
        Framing::Chunked => {
            let mut out = Vec::new();
            loop {
                let size_line = c.line(64, "chunk size line")?;
                let text = std::str::from_utf8(&size_line)
                    .map_err(|_| HttpError::Malformed("chunk size"))?;
                let hex = text.split(';').next().unwrap_or("").trim();
                if hex.is_empty() || hex.len() > 8 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(HttpError::Malformed("chunk size"));
                }
                let n = usize::from_str_radix(hex, 16)
                    .map_err(|_| HttpError::Malformed("chunk size"))?;
                if n == 0 {
                    // Trailers until the blank line, bounded like the head.
                    let mut trailer = 0usize;
                    loop {
                        let t = c.line(limits.max_head_bytes, "trailers")?;
                        trailer += t.len() + 2;
                        if trailer > limits.max_head_bytes {
                            return Err(HttpError::TooLarge("trailers"));
                        }
                        if t.is_empty() {
                            break;
                        }
                    }
                    break;
                }
                if out.len().saturating_add(n) > limits.max_body_bytes {
                    return Err(HttpError::TooLarge("response body"));
                }
                out.extend_from_slice(&c.exact(n)?);
                if !c.line(2, "chunk terminator")?.is_empty() {
                    return Err(HttpError::Malformed("chunk terminator"));
                }
                c.compact();
            }
            out
        }
    };
    Ok(HttpResponse {
        status,
        content_type,
        retry_after_secs,
        server,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(s: &str) -> Vec<Vec<u8>> {
        s.split("\r\n").map(|l| l.as_bytes().to_vec()).collect()
    }

    #[test]
    fn retry_after_is_delta_seconds_only_and_bounded() {
        let ra = |v: &str| {
            parse_head(&lines(&format!(
                "HTTP/1.1 429 Too Many\r\nContent-Length: 0\r\nRetry-After: {v}"
            )))
            .unwrap()
            .retry_after_secs
        };
        assert_eq!(ra("3"), Some(3));
        assert_eq!(ra("86400"), Some(86_400));
        for ignored in [
            "86401",
            "-1",
            "+3",
            "3.5",
            "Wed, 21 Oct 2015 07:28:00 GMT",
            "9999999",
        ] {
            assert_eq!(ra(ignored), None, "{ignored}");
        }
        let h = parse_head(&lines(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nServer: llama.cpp b1234",
        ))
        .unwrap();
        assert_eq!(h.server.as_deref(), Some("llama.cpp b1234"));
    }

    #[test]
    fn heads_are_parsed_strictly() {
        let h =
            parse_head(&lines("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nTransfer-Encoding: chunked"))
                .unwrap();
        assert_eq!(
            (h.status, h.framing, h.content_type.as_deref()),
            (200, Framing::Chunked, Some("text/event-stream"))
        );
        for bad in [
            "HTTP/2 200 OK",
            "HTTP/1.1 20 OK",
            "HTTP/1.1 100 Continue",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6",
            "HTTP/1.1 200 OK\r\nContent-Length: -1",
            "HTTP/1.1 200 OK\r\nContent-Length: +5",
            "HTTP/1.1 200 OK\r\nContent-Length: 0x5",
            "HTTP/1.1 200 OK\r\nContent-Length: ",
            "HTTP/1.1 200 OK\r\nNoColon",
            "HTTP/1.1 200 OK\r\n Folded: x",
        ] {
            assert!(parse_head(&lines(bad)).is_err(), "{bad:?}");
        }
    }
}
