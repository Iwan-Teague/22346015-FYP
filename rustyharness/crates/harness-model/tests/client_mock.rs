//! The loopback client against a mock HTTP server (design §3.2, §9 H1 key
//! tests: "mock server returning empty / `length` / 429").

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use harness_core::{Source, Untrusted};
use harness_model::client::{ApiKey, ClientConfig, HttpLimits, OpenAiCompatible, RetryPolicy};
use harness_model::profile::{Profile, Protocol};
use harness_model::protocol::{parse_reply, FormatError};
use harness_model::{
    FinishReason, HarnessText, Message, ModelBackend, ModelError, ModelRequest, RenderNonce,
    TaskText, ToolSpec, Unavailable,
};

#[derive(Clone)]
enum Behave {
    /// Send these bytes, then close.
    Respond(Vec<u8>),
    /// Read the request, send nothing, hold the connection.
    Silent,
    /// Send `head`, then `chunk` every `every`, forever.
    Trickle(Vec<u8>, Vec<u8>, Duration),
    /// Send `head`, then `chunk` as fast as possible, forever.
    Flood(Vec<u8>, Vec<u8>),
}

struct Mock {
    port: u16,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
}

fn read_request(s: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..i]).to_ascii_lowercase();
            let len = head
                .lines()
                .find_map(|l| {
                    l.strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if buf.len() >= i + 4 + len {
                return buf;
            }
        }
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return buf,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
}

fn mock(script: Vec<Behave>) -> Mock {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let reqs = requests.clone();
    thread::spawn(move || {
        for b in script {
            let Ok((mut s, _)) = l.accept() else { return };
            reqs.lock().unwrap().push(read_request(&mut s));
            thread::spawn(move || match b {
                Behave::Respond(bytes) => {
                    let _ = s.write_all(&bytes);
                }
                Behave::Silent => thread::sleep(Duration::from_secs(10)),
                Behave::Trickle(head, chunk, every) => {
                    let _ = s.write_all(&head);
                    while s.write_all(&chunk).is_ok() {
                        thread::sleep(every);
                    }
                }
                Behave::Flood(head, chunk) => {
                    let _ = s.write_all(&head);
                    while s.write_all(&chunk).is_ok() {}
                }
            });
        }
    });
    Mock { port, requests }
}

fn http(status: &str, ctype: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn chunked(ctype: &str, body: &str) -> Vec<u8> {
    let mut out =
        format!("HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nTransfer-Encoding: chunked\r\n\r\n");
    for part in body.as_bytes().chunks(7) {
        out.push_str(&format!("{:x}\r\n", part.len()));
        out.push_str(std::str::from_utf8(part).unwrap());
        out.push_str("\r\n");
    }
    out.push_str("0\r\n\r\n");
    out.into_bytes()
}

fn sse(events: &[&str]) -> String {
    events.iter().map(|e| format!("data: {e}\n\n")).collect()
}

fn config() -> ClientConfig {
    ClientConfig {
        limits: HttpLimits {
            connect_timeout: Duration::from_millis(500),
            read_timeout: Duration::from_millis(300),
            max_head_bytes: 8 * 1024,
            max_body_bytes: 64 * 1024,
        },
        retry: RetryPolicy {
            max_retries: 3,
            base_ms: 5,
            cap_ms: 20,
            jitter_seed: 1,
        },
    }
}

fn client(m: &Mock, key: Option<ApiKey>) -> OpenAiCompatible {
    OpenAiCompatible::new(
        &format!("http://127.0.0.1:{}/v1", m.port),
        Profile::conservative_default("local-model"),
        key,
        config(),
    )
    .unwrap()
}

fn tools() -> Vec<ToolSpec> {
    vec![ToolSpec {
        id: "harness.fs.read".into(),
        description: HarnessText::from_static("read"),
        parameters: serde_json::json!({"type":"object","additionalProperties":false,"properties":{}}),
    }]
}

fn req() -> ModelRequest {
    ModelRequest {
        messages: vec![
            Message::System(HarnessText::from_static("rules")),
            Message::Task(TaskText::new("read the readme".into())),
            Message::Observation {
                call: "harness.fs.read".into(),
                body: Untrusted::new("file text".into(), Source::Tool("harness.fs.read".into())),
            },
        ],
        tools: tools(),
        nonce: RenderNonce::new("00112233445566778899aabbccddeeff").unwrap(),
    }
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

const STOP: &str = r#"{"choices":[{"delta":{},"finish_reason":"stop"}]}"#;

fn text_event(t: &str) -> String {
    serde_json::json!({"choices":[{"delta":{"content": t}}]}).to_string()
}

// ---- the happy paths --------------------------------------------------------

#[test]
fn streamed_reply_over_chunked_encoding_with_the_key_only_in_the_header() {
    let body = sse(&[
        &text_event("thinking <action>{\"tool\":\"harness.fs.read\",\"args\":{}}</action>"),
        STOP,
        "[DONE]",
    ]);
    let m = mock(vec![Behave::Respond(chunked("text/event-stream", &body))]);
    let key = ApiKey::new("local-llama", "sk-SECRET-VALUE-123".into()).unwrap();
    let c = client(&m, Some(key));
    let completion = c.complete(&req(), soon()).unwrap();
    assert_eq!(completion.finish, FinishReason::Stop);
    let parsed = parse_reply(&completion, Protocol::Text, &tools()).unwrap();
    assert_eq!(parsed.action.tool, "harness.fs.read");

    let raw = String::from_utf8(m.requests.lock().unwrap()[0].clone()).unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
    assert!(head.contains("\r\nAuthorization: Bearer sk-SECRET-VALUE-123\r\n"));
    assert!(
        !body.contains("SECRET"),
        "the key must never be in the body"
    );
    assert!(body.contains("\"stream\":true"));
    // §5.5: identity and Debug carry the handle, never the value.
    let id = c.identity();
    assert_eq!(id.api_key_handle.as_deref(), Some("local-llama"));
    assert!(!format!("{id:?}").contains("SECRET"));
    assert!(!format!("{c:?}").contains("SECRET"));
}

#[test]
fn plain_json_reply_is_accepted() {
    let body = r#"{"choices":[{"message":{"content":"x","tool_calls":[{"function":{"name":"harness_fs_read","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}"#;
    let m = mock(vec![Behave::Respond(http(
        "200 OK",
        "application/json",
        body,
    ))]);
    let c = client(&m, None).complete(&req(), soon()).unwrap();
    assert_eq!(c.finish, FinishReason::ToolCalls);
    assert_eq!(c.tool_calls.len(), 1);
}

// ---- INV-3 and typed errors --------------------------------------------------------

#[test]
fn inv_3_empty_and_length_are_typed_errors() {
    let m = mock(vec![
        Behave::Respond(chunked("text/event-stream", &sse(&["[DONE]"]))),
        Behave::Respond(http("200 OK", "text/event-stream", "")),
        Behave::Respond(chunked(
            "text/event-stream",
            &sse(&[
                r#"{"choices":[{"delta":{"content":"half"},"finish_reason":"length"}]}"#,
                "[DONE]",
            ]),
        )),
        Behave::Respond(chunked(
            "text/event-stream",
            &sse(&[&text_event("no finish")]),
        )),
    ]);
    let c = client(&m, None);
    assert_eq!(c.complete(&req(), soon()).unwrap_err(), ModelError::Empty);
    assert_eq!(c.complete(&req(), soon()).unwrap_err(), ModelError::Empty);
    assert_eq!(
        c.complete(&req(), soon()).unwrap_err(),
        ModelError::Truncated("finish_reason: length")
    );
    assert_eq!(
        c.complete(&req(), soon()).unwrap_err(),
        ModelError::Truncated("no finish_reason")
    );
    assert_eq!(
        m.requests.lock().unwrap().len(),
        4,
        "none of these was retried"
    );
}

#[test]
fn rate_limits_are_retried_within_the_budget_and_recorded() {
    let too_many = http("429 Too Many Requests", "application/json", "{}");
    let m = mock(vec![Behave::Respond(too_many.clone()); 4]);
    assert_eq!(
        client(&m, None).complete(&req(), soon()).unwrap_err(),
        ModelError::RateLimited {
            statuses: vec![429, 429, 429, 429]
        }
    );
    assert_eq!(
        m.requests.lock().unwrap().len(),
        4,
        "1 attempt + 3 retries, no more"
    );

    let ok = chunked(
        "text/event-stream",
        &sse(&[&text_event("fine"), STOP, "[DONE]"]),
    );
    let m = mock(vec![Behave::Respond(too_many), Behave::Respond(ok)]);
    let c = client(&m, None).complete(&req(), soon()).unwrap();
    assert_eq!(
        c.retried,
        vec![429],
        "the failed attempt is recorded on the result"
    );
}

// H1d review F-7: the whole retry history survives the final failure.
#[test]
fn the_final_failure_keeps_every_retry_status() {
    let m = mock(vec![
        Behave::Respond(http("503 Service Unavailable", "text/plain", "")),
        Behave::Respond(http("500 Internal Server Error", "text/plain", "")),
        Behave::Respond(http("503 Service Unavailable", "text/plain", "")),
        Behave::Respond(http("429 Too Many Requests", "text/plain", "")),
    ]);
    assert_eq!(
        client(&m, None).complete(&req(), soon()).unwrap_err(),
        ModelError::RateLimited {
            statuses: vec![503, 500, 503, 429]
        }
    );
}

#[test]
fn server_errors_are_retried_then_typed() {
    let m = mock(vec![
        Behave::Respond(http(
            "503 Service Unavailable",
            "text/plain",
            "busy"
        ));
        4
    ]);
    assert_eq!(
        client(&m, None).complete(&req(), soon()).unwrap_err(),
        ModelError::Unavailable(Unavailable::Status {
            code: 503,
            statuses: vec![503, 503, 503, 503]
        })
    );
}

#[test]
fn retries_never_run_past_the_deadline() {
    let mut cfg = config();
    // The first backoff is at least 500 ms (half of 1000, plus jitter):
    // longer than the 300 ms left, so the client gives up instead of
    // sleeping past the deadline.
    cfg.retry.base_ms = 1000;
    cfg.retry.cap_ms = 1000;
    let m = mock(vec![
        Behave::Respond(http(
            "429 Too Many Requests",
            "text/plain",
            ""
        ));
        4
    ]);
    let c = OpenAiCompatible::new(
        &format!("http://127.0.0.1:{}/v1", m.port),
        Profile::conservative_default("local-model"),
        None,
        cfg,
    )
    .unwrap();
    let t = Instant::now();
    let e = c
        .complete(&req(), Instant::now() + Duration::from_millis(300))
        .unwrap_err();
    assert!(
        matches!(&e, ModelError::RateLimited { statuses } if statuses == &vec![429]),
        "{e:?}"
    );
    assert!(t.elapsed() < Duration::from_millis(300));
}

#[test]
fn malformed_and_non_retryable_replies_are_unusable_and_not_retried() {
    for bytes in [
        http("200 OK", "application/json", "{bad json"),
        http("200 OK", "application/json", r#"{"choices":[{"message":{"content":"a","content":"b"},"finish_reason":"stop"}]}"#),
        chunked("text/event-stream", &sse(&["{broken", "[DONE]"])),
        http("200 OK", "text/html", "<html>"),
        http("400 Bad Request", "application/json", "{}"),
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n".to_vec(),
        b"NOT HTTP\r\n\r\n".to_vec(),
    ] {
        let m = mock(vec![Behave::Respond(bytes.clone())]);
        let e = client(&m, None).complete(&req(), soon()).unwrap_err();
        assert!(matches!(e, ModelError::Unusable(_)), "{}: {e:?}", String::from_utf8_lossy(&bytes));
        assert_eq!(m.requests.lock().unwrap().len(), 1, "an unusable reply is not retried");
    }
}

// ---- timeouts and bounds ------------------------------------------------------------

#[test]
fn a_silent_server_hits_the_read_timeout() {
    let m = mock(vec![Behave::Silent]);
    let t = Instant::now();
    let e = client(&m, None).complete(&req(), soon()).unwrap_err();
    assert_eq!(e, ModelError::Unavailable(Unavailable::ReadTimeout));
    assert!(t.elapsed() < Duration::from_secs(2));
}

#[test]
fn a_server_that_trickles_forever_hits_the_total_deadline() {
    // Each byte arrives well inside the read timeout, so only the deadline stops it.
    let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n".to_vec();
    let m = mock(vec![Behave::Trickle(
        head,
        b": keep-alive\n\n".to_vec(),
        Duration::from_millis(50),
    )]);
    let t = Instant::now();
    let e = client(&m, None)
        .complete(&req(), Instant::now() + Duration::from_millis(800))
        .unwrap_err();
    assert_eq!(e, ModelError::Unavailable(Unavailable::Deadline));
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
}

#[test]
fn a_server_that_floods_forever_hits_the_size_cap() {
    let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n".to_vec();
    let chunk = format!("data: {}\n\n", text_event(&"x".repeat(1000))).into_bytes();
    let m = mock(vec![Behave::Flood(head, chunk)]);
    let e = client(&m, None).complete(&req(), soon()).unwrap_err();
    assert_eq!(e, ModelError::Unusable("response body too large".into()));
}

#[test]
fn oversized_heads_and_declared_bodies_are_refused() {
    let big_head = format!(
        "HTTP/1.1 200 OK\r\nX-Pad: {}\r\nContent-Length: 0\r\n\r\n",
        "a".repeat(10_000)
    )
    .into_bytes();
    let big_body =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10000000\r\n\r\n"
            .to_vec();
    for (bytes, want) in [
        (big_head, "response head too large"),
        (big_body, "response body too large"),
    ] {
        let m = mock(vec![Behave::Respond(bytes)]);
        assert_eq!(
            client(&m, None).complete(&req(), soon()).unwrap_err(),
            ModelError::Unusable(want.into())
        );
    }
}

#[test]
fn a_spent_deadline_makes_no_connection() {
    let m = mock(vec![]);
    let e = client(&m, None)
        .complete(&req(), Instant::now())
        .unwrap_err();
    assert_eq!(e, ModelError::Unavailable(Unavailable::Deadline));
    assert!(m.requests.lock().unwrap().is_empty());
}

#[test]
fn a_closed_port_is_a_connect_error() {
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    // Windows does not refuse a loopback connect at once: it retransmits the
    // SYN after each RST and reports the refusal only after about 2 s. The
    // connect timeout here outlasts that, so every OS reaches the refusal
    // itself rather than the timeout (both are `Unavailable`; this test pins
    // the refused path).
    let mut cfg = config();
    cfg.limits.connect_timeout = Duration::from_secs(10);
    let c = OpenAiCompatible::new(
        &format!("http://127.0.0.1:{port}/v1"),
        Profile::conservative_default("m"),
        None,
        cfg,
    )
    .unwrap();
    let e = c
        .complete(&req(), Instant::now() + Duration::from_secs(20))
        .unwrap_err();
    assert!(
        matches!(e, ModelError::Unavailable(Unavailable::Connect(_))),
        "{e:?}"
    );
}

// ---- INV-29 through the wire ----------------------------------------------------------

#[test]
fn inv_29_a_reply_smuggling_a_second_action_is_a_format_error() {
    let two = "ok <action>{\"tool\":\"harness.fs.read\",\"args\":{}}</action> and also <action>{\"tool\":\"harness.fs.read\",\"args\":{\"path\":\"/etc/passwd\"}}</action>";
    let body = sse(&[&text_event(two), STOP, "[DONE]"]);
    let m = mock(vec![Behave::Respond(chunked("text/event-stream", &body))]);
    let c = client(&m, None).complete(&req(), soon()).unwrap();
    assert_eq!(
        parse_reply(&c, Protocol::Text, &tools()).unwrap_err(),
        FormatError::SeveralActions
    );
}

// ---- startup check ------------------------------------------------------------------------

#[test]
fn startup_check_needs_the_model_listed() {
    let listed = http(
        "200 OK",
        "application/json",
        r#"{"data":[{"id":"local-model"}]}"#,
    );
    let other = http(
        "200 OK",
        "application/json",
        r#"{"data":[{"id":"something-else"}]}"#,
    );
    let m = mock(vec![Behave::Respond(listed), Behave::Respond(other)]);
    let c = client(&m, None);
    c.startup_check(soon()).unwrap();
    assert!(matches!(
        c.startup_check(soon()),
        Err(ModelError::Unusable(_))
    ));
    let raw = String::from_utf8(m.requests.lock().unwrap()[0].clone()).unwrap();
    assert!(raw.starts_with("GET /v1/models HTTP/1.1\r\n"));
}

// ---- H1e-2b: Retry-After and server-claimed identity ------------------------------

fn with_retry_after(status: &str, secs: &str) -> Vec<u8> {
    format!("HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nRetry-After: {secs}\r\nContent-Length: 0\r\n\r\n")
        .into_bytes()
}

#[test]
fn retry_after_is_honoured_as_a_floor_on_the_backoff() {
    // The configured backoff is 5-20 ms; the server asks for 1 s.
    let ok = chunked(
        "text/event-stream",
        &sse(&[&text_event("fine"), STOP, "[DONE]"]),
    );
    let m = mock(vec![
        Behave::Respond(with_retry_after("429 Too Many Requests", "1")),
        Behave::Respond(ok),
    ]);
    let t = Instant::now();
    let c = client(&m, None).complete(&req(), soon()).unwrap();
    assert_eq!(c.retried, vec![429]);
    assert!(
        t.elapsed() >= Duration::from_secs(1),
        "waited only {:?}",
        t.elapsed()
    );
}

#[test]
fn a_retry_after_past_the_deadline_ends_the_call_without_waiting() {
    let m = mock(vec![Behave::Respond(with_retry_after(
        "503 Service Unavailable",
        "3600",
    ))]);
    let t = Instant::now();
    let e = client(&m, None)
        .complete(&req(), Instant::now() + Duration::from_secs(2))
        .unwrap_err();
    assert_eq!(
        e,
        ModelError::Unavailable(Unavailable::Status {
            code: 503,
            statuses: vec![503]
        })
    );
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    assert_eq!(m.requests.lock().unwrap().len(), 1);
}

#[test]
fn the_startup_check_records_what_the_server_claims() {
    let listed = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: llama.cpp b9999\r\nContent-Length: {}\r\n\r\n{}",
        r#"{"data":[{"id":"local-model"}]}"#.len(),
        r#"{"data":[{"id":"local-model"}]}"#
    )
    .into_bytes();
    let m = mock(vec![Behave::Respond(listed)]);
    let c = client(&m, None);
    assert_eq!(c.identity().claimed, harness_model::ServerClaims::default());
    c.startup_check(soon()).unwrap();
    let claimed = c.identity().claimed;
    assert_eq!(claimed.model_id.as_deref(), Some("local-model"));
    assert_eq!(claimed.server.as_deref(), Some("llama.cpp b9999"));
    assert_eq!(claimed.template_sha256, None);
}
