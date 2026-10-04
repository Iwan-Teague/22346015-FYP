//! Hostile-web fixtures (P-39k; P-39-web-airlock §11): the pieces the web
//! airlock's hostile tests share, so the suites in `harness-run` stop
//! duplicating them. Everything binds only loopback, spawns no fetcher
//! binary, and — like the rest of the kit — stays inside the panic-set
//! ratchet: constructors return `Result`s and locks are handled without
//! unwrapping.
//!
//! These are the design note's fixture classes: a scripted HTTP/1.1
//! server ([`FixtureServer`], including the never-ending and dribbling
//! hostile shapes), a name-to-answer resolver ([`FakeResolver`]) that can
//! answer differently on the first and second lookup (rebinding), an
//! egress log that records every decision ([`RecordingLog`]), and a hop
//! runner that runs the fetcher library in process
//! ([`InProcessHopRunner`]). Mapping the allowlisted test hosts onto the
//! fixture's port stays in the test crate: it needs the sandbox's
//! `remap`-gated test connector, which this crate must not enable.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use harness_sandbox::egress::{EgressLog, EgressLogError, EgressRecord, ResolveRefused, Resolver};
use harness_tools::{HopRun, HopRunner, RunnerError};

// ---------------------------------------------------------------------------
// The scripted fixture server.
// ---------------------------------------------------------------------------

/// What the server answers with, connection by connection.
enum Script {
    /// One pre-built HTTP/1.1 byte blob per connection, in order.
    Blobbed(Arc<Mutex<VecDeque<Vec<u8>>>>),
    /// A `Transfer-Encoding: chunked` head followed by chunks forever.
    EndlessChunked,
    /// A partial head, then one byte at a time, slower than any hop wall.
    Slowloris,
}

/// A scripted HTTP/1.1 server on `127.0.0.1:0` (§11's fixture server).
/// Each accepted connection is answered from the script; the accepted
/// connection count lets a test prove a refused hop never dialed.
pub struct FixtureServer {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
}

impl FixtureServer {
    /// A server answering `responses` in order, one per connection; a
    /// connection beyond the script is accepted and immediately closed.
    pub fn scripted(responses: Vec<Vec<u8>>) -> std::io::Result<Self> {
        Self::start(Script::Blobbed(Arc::new(Mutex::new(
            responses.into_iter().collect(),
        ))))
    }

    /// A server that streams a valid chunked head and then chunks of
    /// 4095 bytes forever: the body never ends.
    pub fn endless_chunked() -> std::io::Result<Self> {
        Self::start(Script::EndlessChunked)
    }

    /// A server that writes a partial head and then dribbles one byte
    /// every 50 ms: any sane hop wall times out first.
    pub fn slowloris() -> std::io::Result<Self> {
        Self::start(Script::Slowloris)
    }

    fn start(script: Script) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let addr = listener.local_addr()?;
        let accepts = Arc::new(AtomicUsize::new(0));
        std::thread::Builder::new()
            .name("fixture-server".to_string())
            .spawn({
                let accepts = Arc::clone(&accepts);
                move || serve(listener, accepts, script)
            })?;
        Ok(Self { addr, accepts })
    }

    /// The loopback address to dial.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The port to dial.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// How many connections the server accepted so far.
    pub fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }
}

fn serve(listener: TcpListener, accepts: Arc<AtomicUsize>, script: Script) {
    for conn in listener.incoming() {
        let Ok(mut sock) = conn else { break };
        accepts.fetch_add(1, Ordering::SeqCst);
        match &script {
            Script::Blobbed(queue) => {
                let next = queue.lock().ok().and_then(|mut q| q.pop_front());
                let Some(blob) = next else {
                    continue; // nothing scripted: the close is the answer
                };
                if sock.write_all(&blob).and_then(|_| sock.flush()).is_err() {
                    continue;
                }
                let _ = sock.shutdown(std::net::Shutdown::Write);
                drain(&mut sock);
            }
            Script::EndlessChunked => {
                let head =
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
                if sock.write_all(head).and_then(|_| sock.flush()).is_err() {
                    continue;
                }
                let chunk = endless_chunk();
                loop {
                    // The peer stops reading (and closes) at its body cap;
                    // the failing write is how this loop ends.
                    if sock.write_all(&chunk).and_then(|_| sock.flush()).is_err() {
                        break;
                    }
                }
                drain(&mut sock);
            }
            Script::Slowloris => {
                if sock
                    .write_all(b"HTTP/1.1 200 OK\r\nX-")
                    .and_then(|_| sock.flush())
                    .is_err()
                {
                    continue;
                }
                loop {
                    std::thread::sleep(Duration::from_millis(50));
                    if sock.write_all(b"-").and_then(|_| sock.flush()).is_err() {
                        break;
                    }
                }
                drain(&mut sock);
            }
        }
    }
}

/// One maximal chunk frame: `0FFF` hex size, 4095 bytes, CRLF.
fn endless_chunk() -> Vec<u8> {
    let mut chunk = Vec::with_capacity(4095 + 8);
    chunk.extend_from_slice(b"0FFF\r\n");
    let mut byte = b'A';
    for _ in 0..4095 {
        chunk.push(byte);
        byte = if byte >= b'z' { b'A' } else { byte + 1 };
    }
    chunk.extend_from_slice(b"\r\n");
    chunk
}

/// Read the peer's remaining bytes until it closes or goes quiet, so the
/// fetcher's request bytes never pile up unread.
fn drain(sock: &mut TcpStream) {
    let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
    let mut sink = [0u8; 4096];
    loop {
        match sock.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

// ---------------------------------------------------------------------------
// The fake resolver.
// ---------------------------------------------------------------------------

/// A name→answer resolver (§11's fake resolver): the default answer is
/// returned for every lookup, unless pushed answers are queued — the first
/// lookup takes the first pushed answer, the second the second, and so on,
/// which is how a rebinding attack is scripted.
pub struct FakeResolver {
    answers: Mutex<VecDeque<Vec<IpAddr>>>,
    default: Vec<IpAddr>,
    calls: AtomicUsize,
}

impl FakeResolver {
    /// A resolver answering `default` for every lookup.
    pub fn new(default: Vec<IpAddr>) -> Self {
        Self {
            answers: Mutex::new(VecDeque::new()),
            default,
            calls: AtomicUsize::new(0),
        }
    }

    /// Queue one answer, consumed by the next lookup.
    pub fn push(&self, answer: Vec<IpAddr>) {
        if let Ok(mut q) = self.answers.lock() {
            q.push_back(answer);
        }
    }

    /// How many lookups were made.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Resolver for FakeResolver {
    fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, ResolveRefused> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let queued = self.answers.lock().ok().and_then(|mut q| q.pop_front());
        Ok(queued.unwrap_or_else(|| self.default.clone()))
    }
}

// ---------------------------------------------------------------------------
// The recording egress log.
// ---------------------------------------------------------------------------

/// An [`EgressLog`] that keeps every record it is given (in order), so a
/// test can assert the decisions that were journalled — and, by counting
/// the server's accepts, that a refusal preceded any dial.
#[derive(Default)]
pub struct RecordingLog {
    records: Mutex<Vec<EgressRecord>>,
}

impl RecordingLog {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many records were appended.
    pub fn len(&self) -> usize {
        self.records.lock().map(|v| v.len()).unwrap_or(0)
    }

    /// Whether nothing was appended.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The records so far, in append order.
    pub fn records(&self) -> Vec<EgressRecord> {
        self.records.lock().map(|v| v.clone()).unwrap_or_default()
    }

    /// The decisions so far, in their §4.5 wire text (`allow` or
    /// `refuse:<reason>`).
    pub fn decisions(&self) -> Vec<String> {
        self.records()
            .into_iter()
            .map(|r| r.decision.wire_str())
            .collect()
    }
}

impl EgressLog for RecordingLog {
    fn append(&self, record: &EgressRecord) -> Result<(), EgressLogError> {
        if let Ok(mut v) = self.records.lock() {
            v.push(record.clone());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The in-process hop runner.
// ---------------------------------------------------------------------------

/// Runs the fetcher library in process (§11's in-process hop runner):
/// reads the hop's `req.json`, dials the hop's loopback relay, and runs
/// the same `fetch_over` the real binary runs. No confinement, no spawn —
/// the hostile classes here are in the page and the transport, not the
/// fetcher's own behaviour.
pub struct InProcessHopRunner;

impl HopRunner for InProcessHopRunner {
    fn run(&mut self, run: &HopRun<'_>) -> Result<Vec<u8>, RunnerError> {
        let bytes = std::fs::read(run.req_path)
            .map_err(|e| RunnerError::Io(format!("{}: {e}", run.req_path.display())))?;
        let req =
            harness_fetch::read_request(&bytes).map_err(|e| RunnerError::Io(e.to_string()))?;
        let mut sock = TcpStream::connect(SocketAddr::new(
            IpAddr::from([127, 0, 0, 1]),
            run.proxy_port,
        ))
        .map_err(|e| RunnerError::Io(e.to_string()))?;
        let frame = harness_fetch::fetch_over(&mut sock, &req);
        Ok(harness_fetch::encode_frame(&frame))
    }
}
