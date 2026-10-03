//! P-37e: the client state machine's hostile-server suite (design note
//! §3.2-§3.5, §4), over in-memory pipes against this crate's fixture
//! `serve` and a few inline scripted servers for the cases the fixture's
//! mode list does not carry (a first-line garbage greeting, a cancellation
//! of the outstanding id, an over-cap `initialize` result, a duplicate
//! response inside one frame chunk).
//!
//! WHY THIS PACKAGE: the purity gate scans every file of `harness-mcp`
//! (`scripts/ci/purity.sh` §2), so the client crate may not name the
//! pipes, the clock or a served session even in its own tests. The pipes
//! and the wall clock live here; the client sees only bytes, deadlines
//! and kills, which is the seam it will be driven through in production.
//!
//! Every test drives a REAL served session on its own worker thread
//! (`serve` blocks on input, exactly like a real server process), so the
//! interleave the client sees is the production shape: writes are flushed
//! per message, reads are chunked per write.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{BufRead, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use harness_mcp::client::{
    CallEnd, Client, Clock, Connected, Fault, Transport, TransportFault, Violation, INIT_MAX,
};
use harness_mcp::wire::WireFault;
use harness_mcp_fixture::{ok_tools, serve, PROTOCOL_VERSION};
use serde_json::{json, Map, Value};

/// Handshake budgets generous enough never to fire on a healthy fixture
/// (§4's production values are 10 s / 5 s / 15 s; the tests are tighter
/// only where the mode IS the delay).
const INIT_BUDGET: Duration = Duration::from_secs(5);
const PAGE_BUDGET: Duration = Duration::from_secs(2);
const LIST_BUDGET: Duration = Duration::from_secs(5);
/// The per-call budget (§4: the run's tool timeout bounds it in
/// production; here the fixture answers immediately or never).
const CALL_BUDGET: Duration = Duration::from_secs(5);

/// The client version the tests connect with (any string; the server
/// never reads it back).
const CLIENT_VERSION: &str = "0.0.1";

/// The fixture's output sink: every write becomes one pipe chunk, the
/// same granularity a flushed line has on a real pipe.
struct ChanWriter {
    tx: SyncSender<Vec<u8>>,
}

impl Write for ChanWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.tx
            .send(buf.to_vec())
            .map(|_| buf.len())
            .map_err(|_| std::io::Error::other("fixture output closed"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The fixture's input source: pipe chunks as they arrive, end of input
/// when every sender is gone (the client killed or dropped the pipe).
struct ChanReader {
    rx: Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl Read for ChanReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let filled = self.fill_buf()?;
        let n = filled.len().min(out.len());
        out[..n].copy_from_slice(&filled[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for ChanReader {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.pos >= self.buf.len() {
            if let Ok(chunk) = self.rx.recv() {
                self.buf = chunk;
                self.pos = 0;
            }
        }
        Ok(&self.buf[self.pos..])
    }

    fn consume(&mut self, amt: usize) {
        self.pos += amt;
    }
}

/// One served connection: the client side of the pipes, the log of the
/// frames the client sent (the `-32601` assertions read it), the kill
/// flag, and the served worker (dropping the pipe detaches it; the `hang`
/// mode never notices end of input and sleeps until the test process
/// ends, which is fine).
struct TestPipe {
    to_server: Option<SyncSender<Vec<u8>>>,
    from_server: Receiver<Vec<u8>>,
    sent: Arc<Mutex<Vec<String>>>,
    killed: Arc<AtomicBool>,
    _server: JoinHandle<()>,
}

impl TestPipe {
    /// Serves `mode` of the fixture on the far side of the pipes.
    fn fixture(mode: &str) -> TestPipe {
        let mode = mode.to_owned();
        Self::served(move |input, output| {
            let _ = serve(&mode, input, output);
        })
    }

    /// Serves an inline script for the cases the fixture's mode list does
    /// not carry. The script gets the server side of the pipes.
    fn scripted(
        script: impl FnOnce(Box<dyn BufRead + Send>, Box<dyn Write + Send>) + Send + 'static,
    ) -> TestPipe {
        Self::served(script)
    }

    fn served(
        serve_fn: impl FnOnce(Box<dyn BufRead + Send>, Box<dyn Write + Send>) + Send + 'static,
    ) -> TestPipe {
        let (to_server, server_in) = sync_channel(64);
        let (server_out, from_server) = sync_channel(256);
        let input: Box<dyn BufRead + Send> = Box::new(ChanReader {
            rx: server_in,
            buf: Vec::new(),
            pos: 0,
        });
        let output: Box<dyn Write + Send> = Box::new(ChanWriter { tx: server_out });
        let _server = thread::spawn(move || serve_fn(input, output));
        TestPipe {
            to_server: Some(to_server),
            from_server,
            sent: Arc::new(Mutex::new(Vec::new())),
            killed: Arc::new(AtomicBool::new(false)),
            _server,
        }
    }

    /// Clones of the observation handles a test asserts on after the pipe
    /// has been moved into a [`Client`].
    fn handles(&self) -> (Arc<AtomicBool>, Arc<Mutex<Vec<String>>>) {
        (self.killed.clone(), self.sent.clone())
    }
}

impl Transport for TestPipe {
    type Deadline = Instant;

    fn send(&mut self, frame: &[u8]) -> Result<(), TransportFault> {
        let tx = match self.to_server.as_ref() {
            Some(tx) => tx,
            None => return Err(TransportFault::Closed),
        };
        self.sent
            .lock()
            .unwrap()
            .push(String::from_utf8_lossy(frame).into_owned());
        let mut line = frame.to_vec();
        line.push(b'\n');
        tx.send(line).map_err(|_| TransportFault::Closed)
    }

    fn recv(&mut self, deadline: Instant) -> Result<Option<Vec<u8>>, TransportFault> {
        let Some(budget) = deadline.checked_duration_since(Instant::now()) else {
            return Err(TransportFault::Deadline);
        };
        match self.from_server.recv_timeout(budget) {
            Ok(chunk) => Ok(Some(chunk)),
            Err(RecvTimeoutError::Timeout) => Err(TransportFault::Deadline),
            Err(RecvTimeoutError::Disconnected) => Ok(None),
        }
    }

    fn kill(&mut self) {
        self.killed.store(true, Ordering::SeqCst);
        // End of input ends the served session (the `hang` mode excepted;
        // it never reads again).
        self.to_server = None;
    }
}

/// The tests' clock: the real wall clock, read in the one place the
/// client's [`Clock`] seam allows.
struct WallClock;

impl Clock for WallClock {
    type Time = Instant;

    fn after(&self, budget: Duration) -> Instant {
        Instant::now() + budget
    }
}

/// The handles a connected test needs: the client over the pipe, the
/// kill flag and the sent-frame log.
type ConnectedPipe = (
    Client<WallClock, TestPipe>,
    Arc<AtomicBool>,
    Arc<Mutex<Vec<String>>>,
);

/// A connected client over `pipe`, plus the kill and sent-log handles.
fn connected(pipe: TestPipe) -> ConnectedPipe {
    let (killed, sent) = pipe.handles();
    let mut client = Client::new(WallClock, pipe);
    let baseline = client
        .connect(
            PROTOCOL_VERSION,
            CLIENT_VERSION,
            INIT_BUDGET,
            PAGE_BUDGET,
            LIST_BUDGET,
        )
        .expect("the fixture answered the handshake");
    assert_eq!(baseline.protocol, PROTOCOL_VERSION);
    assert_eq!(tool_names(&baseline), vec!["echo", "add"]);
    (client, killed, sent)
}

/// The names of a baseline's tools, in presentation order.
fn tool_names(connected: &Connected) -> Vec<String> {
    connected.tools.iter().map(|t| t.name.clone()).collect()
}

/// Call arguments from pairs.
fn args(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

/// The exact `-32601` refusal the client sends for a server request with
/// this id (the encoders' byte shape is pinned by the codec's own tests).
fn refusal_line(id: u64) -> String {
    format!(r#"{{"error":{{"code":-32601,"message":"not supported"}},"id":{id},"jsonrpc":"2.0"}}"#)
}

/// The `tools/list` result the scripted servers answer with: the `ok`
/// mode's two tools, exactly as the fixture presents them.
fn listed_tools() -> Value {
    json!({
        "tools": ok_tools()
            .into_iter()
            .map(|t| json!({"name": t.name, "description": t.description, "inputSchema": t.input_schema}))
            .collect::<Vec<Value>>(),
    })
}

/// The `initialize` result the scripted servers answer with.
fn init_result() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": {"name": "scripted", "version": "0"},
    })
}

/// Reads one request line from the scripted server's input and parses it;
/// `None` at end of input.
fn next_request(input: &mut dyn BufRead) -> Option<Value> {
    let mut line = String::new();
    let read = input.read_line(&mut line).unwrap_or(0);
    if read == 0 {
        return None;
    }
    serde_json::from_str(line.trim_end()).ok()
}

/// Writes one frame line and flushes.
fn reply(out: &mut dyn Write, frame: &Value) {
    let _ = writeln!(out, "{frame}");
    let _ = out.flush();
}

#[test]
fn client_protocol_version_mismatch_refused() {
    // §3.3: the server must name EXACTLY the negotiated version; the
    // spec's renegotiation dance is refused, not spoken.
    let pipe = TestPipe::fixture("version:2024-11-05");
    let (killed, _sent) = pipe.handles();
    let mut client = Client::new(WallClock, pipe);
    let fault = client
        .connect(
            PROTOCOL_VERSION,
            CLIENT_VERSION,
            INIT_BUDGET,
            PAGE_BUDGET,
            LIST_BUDGET,
        )
        .expect_err("a wrong version must be refused");
    assert_eq!(
        fault,
        Fault::Violation(Violation::VersionMismatch {
            got: "2024-11-05".to_owned()
        })
    );
    assert!(killed.load(Ordering::SeqCst), "the server is killed");
}

#[test]
fn client_server_without_tools_capability_refused() {
    // §3.3: `capabilities.tools` must be present; a server that offers
    // nothing we came for is not a server we can use.
    let pipe = TestPipe::fixture("no-tools-capability");
    let (killed, _sent) = pipe.handles();
    let mut client = Client::new(WallClock, pipe);
    let fault = client
        .connect(
            PROTOCOL_VERSION,
            CLIENT_VERSION,
            INIT_BUDGET,
            PAGE_BUDGET,
            LIST_BUDGET,
        )
        .expect_err("a tools-less server must be refused");
    assert_eq!(fault, Fault::Violation(Violation::NoToolsCapability));
    assert!(killed.load(Ordering::SeqCst), "the server is killed");
}

#[test]
fn client_tools_list_pagination_bounded() {
    // The happy walk: `paginate:3` splits two tools over three cursor
    // pages; the client follows the cursor and reassembles the list.
    let pipe = TestPipe::fixture("paginate:3");
    let (mut client, _killed, _sent) = connected(pipe);
    let relisted = client
        .list(PAGE_BUDGET, LIST_BUDGET)
        .expect("the walk serves");
    assert_eq!(
        relisted.iter().map(|t| t.name.clone()).collect::<Vec<_>>(),
        vec!["echo", "add"]
    );
    // The walk asked for three pages, the last carrying the second page's
    // cursor (ids 2, 3, 4 after `initialize` = 1).
    // And the bound: a walk that would need a NINTH page (LIST_PAGES_MAX
    // is 8) is a violation, before the ninth request is even answered.
    let pipe = TestPipe::fixture("paginate:9");
    let (killed, sent) = pipe.handles();
    let mut client = Client::new(WallClock, pipe);
    let fault = client
        .connect(
            PROTOCOL_VERSION,
            CLIENT_VERSION,
            INIT_BUDGET,
            PAGE_BUDGET,
            LIST_BUDGET,
        )
        .expect_err("a walk past the page cap must be refused");
    assert_eq!(fault, Fault::Violation(Violation::ListOverrun));
    assert!(killed.load(Ordering::SeqCst), "the server is killed");
    // Exactly eight page requests went out; the ninth never did.
    let sent = sent.lock().unwrap();
    assert_eq!(
        sent.iter()
            .filter(|line| line.contains(r#""method":"tools/list""#))
            .count(),
        8,
        "the walk stops at LIST_PAGES_MAX requests: {sent:?}"
    );
}

#[test]
fn client_duplicate_tool_name_in_list_refused() {
    // §8: one name listed twice is an ambiguous binding, never
    // "first wins".
    let pipe = TestPipe::fixture("dup-tool-name");
    let (killed, _sent) = pipe.handles();
    let mut client = Client::new(WallClock, pipe);
    let fault = client
        .connect(
            PROTOCOL_VERSION,
            CLIENT_VERSION,
            INIT_BUDGET,
            PAGE_BUDGET,
            LIST_BUDGET,
        )
        .expect_err("a duplicated tool name must be refused");
    assert_eq!(
        fault,
        Fault::Violation(Violation::DuplicateTool("echo".to_owned()))
    );
    assert!(killed.load(Ordering::SeqCst), "the server is killed");
}

#[test]
fn client_slow_loris_hits_absolute_deadline() {
    // §4: the deadline is ABSOLUTE per exchange, never inter-byte. The
    // fixture trickles the initialize result one byte per 100 ms — the
    // full frame would take tens of seconds — and a 400 ms budget must
    // end the exchange while the trickle is still in its first bytes.
    let pipe = TestPipe::fixture("slow-loris");
    let (killed, _sent) = pipe.handles();
    let mut client = Client::new(WallClock, pipe);
    let started = Instant::now();
    let fault = client
        .connect(
            PROTOCOL_VERSION,
            CLIENT_VERSION,
            Duration::from_millis(400),
            PAGE_BUDGET,
            LIST_BUDGET,
        )
        .expect_err("the trickle must hit the deadline");
    let elapsed = started.elapsed();
    assert_eq!(fault, Fault::Timeout, "the breach is a timeout");
    assert!(killed.load(Ordering::SeqCst), "the server is killed");
    // The whole trickle would need the frame's length in 100 ms steps;
    // the deadline fired long before that, which is the absolute-deadline
    // property: reading slower (the trickler's whole plan) buys nothing.
    let full_trickle = Duration::from_millis(
        100 * u64::try_from(
            harness_mcp::wire::encode_initialize(1, PROTOCOL_VERSION, CLIENT_VERSION).len(),
        )
        .expect("the frame length fits"),
    );
    assert!(
        elapsed < full_trickle,
        "the deadline fired at {elapsed:?}, the trickle needs {full_trickle:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(400),
        "not before the budget"
    );
}

#[test]
fn client_timeout_kills_server() {
    // `hang` answers `initialize`, then never answers anything again: the
    // list exchange meets its budget, and the server is killed — after
    // which the client answers every call with the recorded fault (a dead
    // connection is never reused, §4).
    let pipe = TestPipe::fixture("hang");
    let (killed, _sent) = pipe.handles();
    let mut client = Client::new(WallClock, pipe);
    let fault = client
        .connect(
            PROTOCOL_VERSION,
            CLIENT_VERSION,
            INIT_BUDGET,
            Duration::from_millis(300),
            Duration::from_secs(2),
        )
        .expect_err("the hanging list must time out");
    assert_eq!(fault, Fault::Timeout);
    assert!(killed.load(Ordering::SeqCst), "the server is killed");
    assert!(client.is_dead());
    let again = client
        .list(PAGE_BUDGET, LIST_BUDGET)
        .expect_err("dead stays dead");
    assert_eq!(again, Fault::Timeout, "the recorded fault is replayed");
}

#[test]
fn client_response_with_unknown_id_is_violation() {
    // §3.2: `wrong-id` answers everything with id 424242; nobody sent a
    // request with that id.
    let pipe = TestPipe::fixture("wrong-id");
    let (killed, _sent) = pipe.handles();
    let mut client = Client::new(WallClock, pipe);
    let fault = client
        .connect(
            PROTOCOL_VERSION,
            CLIENT_VERSION,
            INIT_BUDGET,
            PAGE_BUDGET,
            LIST_BUDGET,
        )
        .expect_err("an unknown id must be a violation");
    assert_eq!(fault, Fault::Violation(Violation::UnknownId));
    assert!(killed.load(Ordering::SeqCst), "the server is killed");
}

#[test]
fn client_response_with_string_id_for_int_is_violation() {
    // §3.2: `"1"` is not `1`. The codec accepts well-typed ids; the CLIENT
    // refuses the type switch against its integer counter.
    let pipe = TestPipe::fixture("string-id");
    let (killed, _sent) = pipe.handles();
    let mut client = Client::new(WallClock, pipe);
    let fault = client
        .connect(
            PROTOCOL_VERSION,
            CLIENT_VERSION,
            INIT_BUDGET,
            PAGE_BUDGET,
            LIST_BUDGET,
        )
        .expect_err("a string id must be a violation");
    assert_eq!(fault, Fault::Violation(Violation::UnknownId));
    assert!(killed.load(Ordering::SeqCst), "the server is killed");
}

#[test]
fn client_duplicate_response_is_violation() {
    // §3.2: a second response for one request. In the fixture's framing
    // the twin arrives as its own chunk, so the client meets it on the
    // NEXT exchange as a response to an already-answered id — still a
    // violation, still fatal.
    let pipe = TestPipe::fixture("double-response");
    let (killed, _sent) = pipe.handles();
    let mut client = Client::new(WallClock, pipe);
    let fault = client
        .connect(
            PROTOCOL_VERSION,
            CLIENT_VERSION,
            INIT_BUDGET,
            PAGE_BUDGET,
            LIST_BUDGET,
        )
        .expect_err("a doubled response must be a violation");
    assert!(
        matches!(fault, Fault::Violation(_)),
        "any duplicate response is a violation: {fault:?}"
    );
    assert!(killed.load(Ordering::SeqCst), "the server is killed");
    // The same twin inside ONE chunk is caught in place, as a stray
    // second response for the request it answers.
    let pipe = TestPipe::scripted(move |mut input, mut out| {
        while let Some(msg) = next_request(&mut input) {
            if msg.get("method").and_then(Value::as_str) == Some("initialize") {
                let frame = json!({
                    "jsonrpc": "2.0",
                    "id": msg.get("id").cloned().unwrap_or(Value::Null),
                    "result": init_result(),
                })
                .to_string();
                let _ = out.write_all(format!("{frame}\n{frame}\n").as_bytes());
                let _ = out.flush();
            }
        }
    });
    let (killed, _sent) = pipe.handles();
    let mut client = Client::new(WallClock, pipe);
    let fault = client
        .connect(
            PROTOCOL_VERSION,
            CLIENT_VERSION,
            INIT_BUDGET,
            PAGE_BUDGET,
            LIST_BUDGET,
        )
        .expect_err("a same-chunk twin must be a violation");
    assert_eq!(fault, Fault::Violation(Violation::StrayResponse));
    assert!(killed.load(Ordering::SeqCst), "the server is killed");
}

#[test]
fn client_result_and_error_both_is_violation() {
    // §3.1: exactly one of `result`/`error`; the codec refuses the frame
    // and the client treats the shape fault as any violation.
    let pipe = TestPipe::fixture("result-and-error");
    let (killed, _sent) = pipe.handles();
    let mut client = Client::new(WallClock, pipe);
    let fault = client
        .connect(
            PROTOCOL_VERSION,
            CLIENT_VERSION,
            INIT_BUDGET,
            PAGE_BUDGET,
            LIST_BUDGET,
        )
        .expect_err("a both-fields response must be a violation");
    assert_eq!(
        fault,
        Fault::Violation(Violation::Frame(WireFault::BadMessage))
    );
    assert!(killed.load(Ordering::SeqCst), "the server is killed");
}

#[test]
fn client_notification_flood_is_violation() {
    // §3.5: `flood` writes 10 000 notifications before the initialize
    // result. The exchange's noise cap (256 messages) bites long before
    // the response the client is waiting for arrives.
    let pipe = TestPipe::fixture("flood");
    let (killed, _sent) = pipe.handles();
    let mut client = Client::new(WallClock, pipe);
    let fault = client
        .connect(
            PROTOCOL_VERSION,
            CLIENT_VERSION,
            INIT_BUDGET,
            PAGE_BUDGET,
            LIST_BUDGET,
        )
        .expect_err("the flood must be a violation");
    assert_eq!(fault, Fault::Violation(Violation::Noise));
    assert!(killed.load(Ordering::SeqCst), "the server is killed");
}

#[test]
fn client_server_request_sampling_refused_with_32601() {
    // D3: `sampling/createMessage` is never served. The client answers
    // `-32601` with the request's id echoed EXACTLY as received, counts
    // the request under the per-connection cap, and carries on: the
    // handshake still completes and the baseline is read.
    let (mut client, _killed, sent) = connected(TestPipe::fixture("sampling"));
    assert!(
        matches!(
            client.call("echo", &args(&[("text", json!("hi"))]), CALL_BUDGET),
            Ok(CallEnd::Response(_))
        ),
        "a refused sampling request leaves the connection usable"
    );
    let sent = sent.lock().unwrap();
    assert!(
        sent.contains(&refusal_line(1001)),
        "the -32601 refusal echoes the server's id: {sent:?}"
    );
}

#[test]
fn client_server_requests_roots_elicitation_ping_refused() {
    // D3 across the whole family: `roots/list`, `elicitation/create` and
    // `ping` get the same refusal, one each per connection.
    for mode in ["roots", "elicit", "ping"] {
        let (_client, _killed, sent) = connected(TestPipe::fixture(mode));
        let sent = sent.lock().unwrap();
        assert!(
            sent.contains(&refusal_line(1001)),
            "{mode}: the refusal echoes the server's id: {sent:?}"
        );
        assert_eq!(
            sent.iter().filter(|line| line.contains("-32601")).count(),
            1,
            "{mode}: exactly one refusal was sent"
        );
    }
}

#[test]
fn client_server_request_flood_is_violation() {
    // §3.5: past SERVER_REQUESTS_MAX (16) server requests in one run, the
    // server is hostile. `request-flood` blasts 20 pings before the first
    // list answer; the client refuses the first 17 and kills on the 17th.
    let pipe = TestPipe::fixture("request-flood");
    let (killed, sent) = pipe.handles();
    let mut client = Client::new(WallClock, pipe);
    let fault = client
        .connect(
            PROTOCOL_VERSION,
            CLIENT_VERSION,
            INIT_BUDGET,
            PAGE_BUDGET,
            LIST_BUDGET,
        )
        .expect_err("the request flood must be a violation");
    assert_eq!(fault, Fault::Violation(Violation::ServerRequestFlood));
    assert!(killed.load(Ordering::SeqCst), "the server is killed");
    let sent = sent.lock().unwrap();
    assert_eq!(
        sent.iter().filter(|line| line.contains("-32601")).count(),
        17,
        "one refusal per request up to and including the breaching one: {sent:?}"
    );
}

#[test]
fn client_stdout_garbage_before_initialize_is_violation() {
    // §3.1: the server's output carries only MCP messages; a non-JSON
    // line — here BEFORE the initialize response even exists — is a
    // violation the moment it is read.
    let pipe = TestPipe::scripted(move |mut input, mut out| {
        let _ = writeln!(out, "{{not json");
        let _ = out.flush();
        while next_request(&mut input).is_some() {}
    });
    let (killed, _sent) = pipe.handles();
    let mut client = Client::new(WallClock, pipe);
    let fault = client
        .connect(
            PROTOCOL_VERSION,
            CLIENT_VERSION,
            INIT_BUDGET,
            PAGE_BUDGET,
            LIST_BUDGET,
        )
        .expect_err("garbage on the wire must be a violation");
    assert_eq!(
        fault,
        Fault::Violation(Violation::Frame(WireFault::MalformedJson))
    );
    assert!(killed.load(Ordering::SeqCst), "the server is killed");
}

#[test]
fn client_huge_frame_is_violation() {
    // §3.1/§4: `huge-frame` writes one 2 MiB line; the reader faults the
    // moment the buffered line would pass the 1 MiB cap, with the rest of
    // the line never buffered.
    let pipe = TestPipe::fixture("huge-frame");
    let (killed, _sent) = pipe.handles();
    let mut client = Client::new(WallClock, pipe);
    let fault = client
        .connect(
            PROTOCOL_VERSION,
            CLIENT_VERSION,
            INIT_BUDGET,
            PAGE_BUDGET,
            LIST_BUDGET,
        )
        .expect_err("a 2 MiB line must be a violation");
    assert_eq!(
        fault,
        Fault::Violation(Violation::Frame(WireFault::OverCap))
    );
    assert!(killed.load(Ordering::SeqCst), "the server is killed");
}

#[test]
fn client_eof_mid_response_is_crash() {
    // §4: `exit-midcall` writes half a frame, then the session ends. The
    // call in flight is a crash, not a violation — the server ended, it
    // did not misbehave — and the connection is dead either way. The
    // script IS the fixture mode's script, played by a served session
    // that RETURNS after the half frame, as a process that exits would:
    // the fixture binary's `serve` would keep its session open for the
    // next request, which no exiting process ever does.
    let pipe = TestPipe::scripted(move |mut input, mut out| {
        while let Some(msg) = next_request(&mut input) {
            let id = msg.get("id").cloned().unwrap_or(Value::Null);
            match msg.get("method").and_then(Value::as_str) {
                Some("initialize") => {
                    reply(
                        &mut out,
                        &json!({"jsonrpc": "2.0", "id": id, "result": init_result()}),
                    );
                }
                Some("tools/list") => {
                    reply(
                        &mut out,
                        &json!({"jsonrpc": "2.0", "id": id, "result": listed_tools()}),
                    );
                }
                Some("tools/call") => {
                    // Half a frame, WITHOUT the newline, then end of
                    // session: the pipes close behind it.
                    let _ = out.write_all(b"{\"jsonrpc\":");
                    let _ = out.flush();
                    return;
                }
                _ => {}
            }
        }
    });
    let (killed, _sent) = pipe.handles();
    let mut client = Client::new(WallClock, pipe);
    client
        .connect(
            PROTOCOL_VERSION,
            CLIENT_VERSION,
            INIT_BUDGET,
            PAGE_BUDGET,
            LIST_BUDGET,
        )
        .expect("the handshake serves before the exit");
    let fault = client
        .call("echo", &args(&[("text", json!("hi"))]), CALL_BUDGET)
        .expect_err("half a frame then end of output is a crash");
    assert_eq!(fault, Fault::Ended);
    assert!(killed.load(Ordering::SeqCst), "the server is killed");
}

#[test]
fn client_cancelled_for_outstanding_id_ends_call() {
    // §3.5: a `notifications/cancelled` naming OUR outstanding id ends
    // that call — as a cancellation, NOT a violation: the server stays up
    // and the next exchange works.
    let pipe = TestPipe::scripted(move |mut input, mut out| {
        while let Some(msg) = next_request(&mut input) {
            let id = msg.get("id").cloned().unwrap_or(Value::Null);
            match msg.get("method").and_then(Value::as_str) {
                Some("initialize") => {
                    reply(
                        &mut out,
                        &json!({"jsonrpc": "2.0", "id": id, "result": init_result()}),
                    );
                }
                Some("tools/list") => {
                    reply(
                        &mut out,
                        &json!({"jsonrpc": "2.0", "id": id, "result": listed_tools()}),
                    );
                }
                Some("tools/call") => {
                    // The cancellation names the id of the request it
                    // cancels, and NO response is ever sent for it.
                    reply(
                        &mut out,
                        &json!({
                            "jsonrpc": "2.0",
                            "method": "notifications/cancelled",
                            "params": {"requestId": id},
                        }),
                    );
                }
                _ => {}
            }
        }
    });
    let (killed, _sent) = pipe.handles();
    let mut client = Client::new(WallClock, pipe);
    client
        .connect(
            PROTOCOL_VERSION,
            CLIENT_VERSION,
            INIT_BUDGET,
            PAGE_BUDGET,
            LIST_BUDGET,
        )
        .expect("the scripted handshake serves");
    let ended = client
        .call("echo", &args(&[("text", json!("hi"))]), CALL_BUDGET)
        .expect("a cancellation ends the call, not the connection");
    assert_eq!(ended, CallEnd::Cancelled);
    assert!(!client.is_dead(), "the server stays up");
    assert!(!killed.load(Ordering::SeqCst), "nothing was killed");
    // The connection is still usable: the next exchange answers.
    let relisted = client.list(PAGE_BUDGET, LIST_BUDGET).expect("still alive");
    assert_eq!(
        relisted.iter().map(|t| t.name.clone()).collect::<Vec<_>>(),
        vec!["echo", "add"]
    );
}

#[test]
fn client_ok_connect_list_call_round_trip() {
    // The positive control: connect, relist, call, call — ids in order,
    // results on the line the renderer will read, connection alive.
    let (mut client, killed, sent) = connected(TestPipe::fixture("ok"));
    let relisted = client
        .list(PAGE_BUDGET, LIST_BUDGET)
        .expect("relist serves");
    assert_eq!(
        relisted.iter().map(|t| t.name.clone()).collect::<Vec<_>>(),
        vec!["echo", "add"]
    );
    let line = match client
        .call("echo", &args(&[("text", json!("hi"))]), CALL_BUDGET)
        .expect("echo serves")
    {
        CallEnd::Response(line) => line,
        CallEnd::Cancelled => panic!("echo was not cancelled"),
    };
    let frame: Value = serde_json::from_str(&line).expect("the line is json");
    assert_eq!(frame.get("id"), Some(&json!(4)), "the fourth request's id");
    assert_eq!(
        frame["result"]["content"][0]["text"],
        json!("hi"),
        "the raw line is the renderer's input"
    );
    let line = match client
        .call(
            "add",
            &args(&[("a", json!(2)), ("b", json!(3))]),
            CALL_BUDGET,
        )
        .expect("add serves")
    {
        CallEnd::Response(line) => line,
        CallEnd::Cancelled => panic!("add was not cancelled"),
    };
    let frame: Value = serde_json::from_str(&line).expect("the line is json");
    assert_eq!(frame["result"]["content"][0]["text"], json!("5"));
    assert!(!client.is_dead() && !killed.load(Ordering::SeqCst));
    // No refusals were owed: `ok` sends no server requests.
    let sent = sent.lock().unwrap();
    assert!(
        !sent.iter().any(|line| line.contains("-32601")),
        "a well-behaved server gets no refusals: {sent:?}"
    );
}

#[test]
fn client_init_over_cap_is_violation() {
    // §3.3/§4: the initialize result must fit INIT_MAX (64 KiB), stricter
    // than the 1 MiB line cap — a padded but well-formed result is still
    // refused.
    let pipe = TestPipe::scripted(move |mut input, mut out| {
        let pad = "x".repeat(INIT_MAX + 512);
        let result = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name": "scripted", "version": "0"},
            "pad": pad,
        });
        while let Some(msg) = next_request(&mut input) {
            if msg.get("method").and_then(Value::as_str) == Some("initialize") {
                reply(
                    &mut out,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": msg.get("id").cloned().unwrap_or(Value::Null),
                        "result": result.clone(),
                    }),
                );
            }
        }
    });
    let (killed, _sent) = pipe.handles();
    let mut client = Client::new(WallClock, pipe);
    let fault = client
        .connect(
            PROTOCOL_VERSION,
            CLIENT_VERSION,
            INIT_BUDGET,
            PAGE_BUDGET,
            LIST_BUDGET,
        )
        .expect_err("an over-cap initialize must be a violation");
    assert_eq!(fault, Fault::Violation(Violation::InitOverCap));
    assert!(killed.load(Ordering::SeqCst), "the server is killed");
}
