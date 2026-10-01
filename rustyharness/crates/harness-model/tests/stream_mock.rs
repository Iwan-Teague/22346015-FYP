//! The streaming observer path (P-06) against a mock HTTP server that sends
//! its reply in pieces with delays, so the parts of the reply the observer
//! is told about can be checked while the reply is still arriving. The
//! bounds (deadline, read timeout, size caps) must hold on this path too.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use harness_core::{sha256, Digest};
use harness_model::client::{ClientConfig, HttpLimits, OpenAiCompatible, RetryPolicy};
use harness_model::profile::Profile;
use harness_model::wire::{parse_sse_reply, render_request, request_digest, StreamObserver};
use harness_model::{
    Completion, HarnessText, Message, ModelBackend, ModelError, ModelRequest, TaskText, Unavailable,
};

/// Send `pieces` in order, waiting `every` between pieces, then close.
fn paced(pieces: Vec<Vec<u8>>, every: Duration) -> Server {
    server(vec![boxed(move |s: &mut TcpStream| {
        for p in &pieces {
            let _ = s.write_all(p);
            let _ = s.flush();
            thread::sleep(every);
        }
    })])
}

/// Send `head`, then `chunk` as fast as possible, forever.
fn flood(head: Vec<u8>, chunk: Vec<u8>) -> Server {
    server(vec![boxed(move |s: &mut TcpStream| {
        let _ = s.write_all(&head);
        while s.write_all(&chunk).is_ok() {}
    })])
}

struct Server {
    port: u16,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
}

/// One scripted connection behaviour.
type Behavior = Box<dyn FnOnce(&mut TcpStream) + Send>;

fn boxed(f: impl FnOnce(&mut TcpStream) + Send + 'static) -> Behavior {
    Box::new(f)
}

fn server(script: Vec<Behavior>) -> Server {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let reqs = requests.clone();
    thread::spawn(move || {
        for b in script {
            let Ok((mut s, _)) = l.accept() else { return };
            reqs.lock().unwrap().push(read_request(&mut s));
            thread::spawn(move || b(&mut s));
        }
    });
    Server { port, requests }
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

/// The part of `raw` after its first `sep` (the request body).
fn after<'a>(raw: &'a [u8], sep: &[u8]) -> &'a [u8] {
    &raw[raw.windows(sep.len()).position(|w| w == sep).unwrap() + sep.len()..]
}

impl Server {
    /// The body of the request the client sent, one connection assumed.
    fn sent(&self) -> Vec<u8> {
        after(&self.requests.lock().unwrap()[0], b"\r\n\r\n").to_vec()
    }
}

fn config(read_timeout: Duration) -> ClientConfig {
    ClientConfig {
        limits: HttpLimits {
            connect_timeout: Duration::from_millis(500),
            read_timeout,
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

fn client(port: u16, read_timeout: Duration) -> OpenAiCompatible {
    OpenAiCompatible::new(
        &format!("http://127.0.0.1:{port}/v1"),
        Profile::conservative_default("local-model"),
        None,
        config(read_timeout),
    )
    .unwrap()
}

fn req() -> ModelRequest {
    ModelRequest {
        messages: vec![
            Message::System(HarnessText::from_static("rules")),
            Message::Task(TaskText::new("read the readme".into())),
        ],
        tools: vec![],
    }
}

/// What the observer was told, shared with the test thread.
#[derive(Default)]
struct Seen {
    text: Mutex<Vec<String>>,
    reasoning: Mutex<Vec<String>>,
    names: Mutex<Vec<String>>,
    saw_text: AtomicBool,
}

/// A `StreamObserver` over the shared `Seen` (a local newtype: `Arc` and
/// the trait are both foreign).
struct Recorder(Arc<Seen>);

impl StreamObserver for Recorder {
    fn on_text(&self, text: &str) {
        self.0.text.lock().unwrap().push(text.to_owned());
        self.0.saw_text.store(true, Ordering::SeqCst);
    }
    fn on_reasoning(&self, text: &str) {
        self.0.reasoning.lock().unwrap().push(text.to_owned());
    }
    fn on_tool_call_name(&self, name: &str) {
        self.0.names.lock().unwrap().push(name.to_owned());
    }
}

const SSE_HEAD: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n";

fn sse_body(head: &str, rest: &str) -> Vec<u8> {
    let mut b = head.as_bytes().to_vec();
    b.extend_from_slice(rest.as_bytes());
    b
}

fn event(t: &str) -> String {
    let e = serde_json::json!({"choices":[{"delta":{"content": t}}]}).to_string();
    format!("data: {e}\n\n")
}

fn stop_event() -> String {
    "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n".to_owned()
}

/// P-06: the observer sees the first text while the reply is still being
/// sent, before `complete` returns.
#[test]
fn stream_observer_sees_text_before_reply_completes() {
    let first = sse_body(SSE_HEAD, &event("Hello"));
    let rest = format!("{}{}", event(" world"), stop_event());
    let s = paced(vec![first, rest.into_bytes()], Duration::from_millis(400));
    let seen: Arc<Seen> = Arc::default();
    let c = client(s.port, Duration::from_secs(5)).with_observer(Box::new(Recorder(seen.clone())));

    let done = Arc::new(AtomicBool::new(false));
    let done2 = done.clone();
    let handle = thread::spawn(move || {
        let r = c.complete(&req(), Instant::now() + Duration::from_secs(5));
        done2.store(true, Ordering::SeqCst);
        r
    });
    // Wait until the first chunk has been observed; the mock is still
    // holding the rest of the reply back.
    let started = Instant::now();
    while !seen.saw_text.load(Ordering::SeqCst) {
        assert!(
            !done.load(Ordering::SeqCst),
            "the call finished before the observer saw anything"
        );
        assert!(started.elapsed() < Duration::from_secs(4), "no text seen");
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        !done.load(Ordering::SeqCst),
        "the observer saw text only after complete returned"
    );
    let completion = handle.join().unwrap().unwrap();
    assert_eq!(seen.text.lock().unwrap().as_slice(), ["Hello", " world"]);
    assert!(seen.reasoning.lock().unwrap().is_empty());
    assert_eq!(completion.content.inspect("test"), "Hello world");
}

/// P-06: the streaming client's completion is exactly the one-shot parse of
/// the same bytes (same content, usage, finish reason, byte counts).
#[test]
fn stream_result_equals_nonstream_parse() {
    let events = format!(
        "{}{}{}",
        event("I will read "),
        event("it."),
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":3}}\n\ndata: [DONE]\n\n"
    );
    let s = paced(vec![sse_body(SSE_HEAD, &events)], Duration::ZERO);
    let c = client(s.port, Duration::from_secs(5));
    let completion = c
        .complete(&req(), Instant::now() + Duration::from_secs(5))
        .unwrap();
    // request_bytes is the length of the body the client sent.
    let expected = parse_sse_reply(events.as_bytes(), s.sent().len() as u64, vec![]).unwrap();
    let same = |k: &Completion| format!("{k:?}");
    assert_eq!(same(&completion), same(&expected));
    assert_eq!(completion.request_bytes, s.sent().len() as u64);
    assert_eq!(completion.reply_bytes, expected.reply_bytes);
}

/// P-06: the deadline binds mid-stream, with chunks still arriving inside
/// the read timeout: the client gives up at the deadline, not later.
#[test]
fn stream_deadline_still_enforced_mid_stream() {
    // The first piece arrives at once; the second is 10 s away, far past
    // the deadline but inside the (5 s) read timeout, so only the deadline
    // can stop the call.
    let s = paced(
        vec![sse_body(SSE_HEAD, &event("Hello")), b"late".to_vec()],
        Duration::from_secs(10),
    );
    let t = Instant::now();
    let e = client(s.port, Duration::from_secs(5))
        .complete(&req(), Instant::now() + Duration::from_millis(600))
        .unwrap_err();
    assert_eq!(e, ModelError::Unavailable(Unavailable::Deadline));
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
}

/// P-06: a stream that declares more than the body cap is refused before a
/// byte of it is read.
#[test]
fn stream_oversize_refused() {
    let head =
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 10000000\r\n\r\n";
    let s = paced(vec![head.as_bytes().to_vec()], Duration::ZERO);
    let e = client(s.port, Duration::from_secs(5))
        .complete(&req(), Instant::now() + Duration::from_secs(5))
        .unwrap_err();
    assert_eq!(e, ModelError::Unusable("response body too large".into()));
}

/// P-06: a server that streams event data forever hits the body cap, with
/// an observer attached and fed along the way.
#[test]
fn stream_forever_hits_cap() {
    let s = flood(
        SSE_HEAD.as_bytes().to_vec(),
        event(&"x".repeat(1000)).into_bytes(),
    );
    let seen: Arc<Seen> = Arc::default();
    let c = client(s.port, Duration::from_secs(5)).with_observer(Box::new(Recorder(seen.clone())));
    let e = c
        .complete(&req(), Instant::now() + Duration::from_secs(5))
        .unwrap_err();
    assert_eq!(e, ModelError::Unusable("response body too large".into()));
    assert!(
        !seen.text.lock().unwrap().is_empty(),
        "some deltas were seen"
    );
}

/// P-06: the observer changes nothing on the wire: with and without one,
/// the same request renders to the same bytes, hence the same digest.
#[test]
fn observer_never_affects_request_digest() {
    let events = format!("{}{}", event("ok"), stop_event());
    let a = paced(vec![sse_body(SSE_HEAD, &events)], Duration::ZERO);
    let b = paced(vec![sse_body(SSE_HEAD, &events)], Duration::ZERO);
    let with = client(a.port, Duration::from_secs(5))
        .with_observer(Box::new(Recorder(Arc::default())))
        .complete(&req(), Instant::now() + Duration::from_secs(5))
        .unwrap();
    let without = client(b.port, Duration::from_secs(5))
        .complete(&req(), Instant::now() + Duration::from_secs(5))
        .unwrap();
    // The digest is over the rendered request's canonical JSON bytes; the
    // bytes the two servers received are those bytes, so both their sha256
    // and the recorded request_bytes agree.
    let (da, db) = (sha256(&a.sent()), sha256(&b.sent()));
    let expected: Digest = request_digest(
        &render_request(&req(), &Profile::conservative_default("local-model")).unwrap(),
    );
    assert_eq!(da, db);
    assert_eq!(da, expected);
    assert_eq!(with.request_bytes, without.request_bytes);
    assert_eq!(with.request_bytes, a.sent().len() as u64);
}
