//! P-39f airlock tests. All traffic is loopback: the fixture HTTP server,
//! the [`RemapConnector`] (which maps one fixed global address onto the
//! fixture) and the pump itself never leave 127.0.0.1.

use super::*;

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use harness_fetch::{fetch_over, Frame, Mode, Request, Scheme, MAX_BODY_CAP, MAX_HEADER_CAP};

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

/// A loopback HTTP fixture: answers every request with a fixed-length body
/// and counts accepted connections.
struct Fixture {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
}

impl Fixture {
    fn addr(&self) -> SocketAddr {
        self.addr
    }
}

fn spawn_fixture(body_len: usize) -> Fixture {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let count = accepts.clone();
    thread::spawn(move || {
        let body = vec![b'x'; body_len];
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            count.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let mut got: Vec<u8> = Vec::new();
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        got.extend_from_slice(&buf[..n]);
                        if got.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    });
    Fixture { addr, accepts }
}

/// Resolver with scripted per-call answers; counts calls so tests can
/// prove a hop resolves exactly once.
#[derive(Default)]
struct FakeResolver {
    answers: Mutex<VecDeque<Result<Vec<IpAddr>, ResolveRefused>>>,
    calls: AtomicUsize,
}

impl FakeResolver {
    fn push(&self, answer: Result<Vec<IpAddr>, ResolveRefused>) {
        self.answers.lock().unwrap().push_back(answer);
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Resolver for FakeResolver {
    fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, ResolveRefused> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.answers.lock().unwrap().pop_front() {
            Some(answer) => answer,
            None => Ok(vec![RemapConnector::REMAP_FROM_IP]),
        }
    }
}

/// Resolver whose lookups sleep past a tiny deadline.
struct SlowResolver {
    delay: Duration,
    deadline: Duration,
}

impl Resolver for SlowResolver {
    fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, ResolveRefused> {
        let delay = self.delay;
        resolve_bounded(self.deadline, move || -> io::Result<Vec<IpAddr>> {
            thread::sleep(delay);
            Ok(Vec::new())
        })
    }
}

/// Journal that records everything.
#[derive(Default)]
struct RecordingLog {
    records: Mutex<Vec<EgressRecord>>,
}

impl EgressLog for RecordingLog {
    fn append(&self, record: &EgressRecord) -> Result<(), EgressLogError> {
        self.records.lock().unwrap().push(record.clone());
        Ok(())
    }
}

/// Journal that always fails (INV-43 fixture).
struct FailingLog;

impl EgressLog for FailingLog {
    fn append(&self, _record: &EgressRecord) -> Result<(), EgressLogError> {
        Err(EgressLogError("fixture: journal write failed".to_string()))
    }
}

fn hop_request<'a>(mode: EgressMode, token: &'a str, budgets: HopBudgets) -> HopRequest<'a> {
    HopRequest {
        hop: 7,
        url: "http://example.test/".to_string(),
        host: "example.test".to_string(),
        port: 8080,
        mode,
        purpose: EgressPurpose::Fetch,
        token,
        budgets,
    }
}

fn open_fixture_hop<'a, R: Resolver>(
    log: &'a RecordingLog,
    resolver: &'a R,
    fixture: &Fixture,
    mode: EgressMode,
    token: &'a str,
    budgets: HopBudgets,
) -> Result<HopPump, HopRefused> {
    open_hop(
        log,
        resolver,
        RemapConnector::new(fixture.addr()),
        &hop_request(mode, token, budgets),
    )
}

/// Run one `harness-fetch` request through the pump (synchronous).
fn run_fetch(pump_port: u16, token: &str, host: &str, port: u16) -> Frame {
    let sock = TcpStream::connect(("127.0.0.1", pump_port)).unwrap();
    fetch_thread_on(sock, pump_port, token, host, port)
}

/// `fetch_over` on an already-dialled socket (shared by [`run_fetch`] and
/// the threaded variant below).
fn fetch_thread_on(sock: TcpStream, pump_port: u16, token: &str, host: &str, port: u16) -> Frame {
    let req = Request {
        v: 1,
        proxy_port: pump_port,
        token: token.to_string(),
        scheme: Scheme::Http,
        host: host.to_string(),
        port,
        target: "/".to_string(),
        accept: String::new(),
        max_body: MAX_BODY_CAP,
        max_header_bytes: MAX_HEADER_CAP,
        timeout_ms: 15_000,
        user_agent: String::new(),
        mode: Mode::Proxy,
    };
    fetch_over(sock, &req)
}

/// Fetch on a thread; `None` when even the TCP connect to the pump failed
/// (the refused-late case, after the listener is gone).
fn fetch_thread(
    pump_port: u16,
    token: &'static str,
    host: &'static str,
    port: u16,
) -> thread::JoinHandle<Option<Frame>> {
    thread::spawn(move || {
        let sock = TcpStream::connect(("127.0.0.1", pump_port)).ok()?;
        Some(fetch_thread_on(sock, pump_port, token, host, port))
    })
}

/// Raw pump client for byte-cap tests: sends a correct CONNECT and returns
/// the tunnel after the `200`.
fn raw_connect(pump_port: u16, token: &str, host: &str, port: u16) -> TcpStream {
    let mut sock = TcpStream::connect(("127.0.0.1", pump_port)).unwrap();
    let head = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
    );
    sock.write_all(head.as_bytes()).unwrap();
    let mut reply: Vec<u8> = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        let n = sock.read(&mut buf).unwrap();
        assert!(n > 0, "pump closed during handshake");
        reply.extend_from_slice(&buf[..n]);
        if reply.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8(reply).unwrap();
    assert!(text.starts_with("HTTP/1.1 200"), "pump replied: {text}");
    sock
}

// ---------------------------------------------------------------------------
// Required tests.
// ---------------------------------------------------------------------------

#[test]
fn pump_journals_before_connect() {
    let fixture = spawn_fixture(5);
    let log = RecordingLog::default();
    let resolver = FakeResolver::default();

    let pump = open_fixture_hop(
        &log,
        &resolver,
        &fixture,
        EgressMode::UserProxy,
        "t",
        HopBudgets::default(),
    )
    .unwrap();

    // INV-43: the allow record exists before the fetcher runs and before
    // the origin is dialled.
    let records = log.records.lock().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].decision, EgressDecision::Allow);
    assert_eq!(records[0].ip, Some(RemapConnector::REMAP_FROM_IP));
    assert_eq!(records[0].resolved, vec![RemapConnector::REMAP_FROM_IP]);
    assert_eq!(records[0].hop, 7);
    assert_eq!(records[0].url, "http://example.test/");
    assert_eq!(records[0].host, "example.test");
    assert_eq!(records[0].port, 8080);
    assert_eq!(records[0].mode, EgressMode::UserProxy);
    assert_eq!(records[0].purpose, EgressPurpose::Fetch);
    drop(records);
    assert_eq!(fixture.accepts.load(Ordering::SeqCst), 0);

    let frame = run_fetch(pump.port(), "t", "example.test", 8080);
    assert_eq!(frame.header.status, Some(200));
    assert!(frame.header.error.is_none());
    let io = pump.join();
    assert_eq!(io.ended, HopEnded::Relayed);
    assert_eq!(io.chosen, RemapConnector::REMAP_FROM_IP);
    // The pump counts what MOVED: the origin's response head plus body.
    assert!(io.bytes_down >= 5);
    assert!(io.bytes_up > 0);
    assert_eq!(fixture.accepts.load(Ordering::SeqCst), 1);
    assert_eq!(resolver.calls(), 1);
}

#[test]
fn egress_append_failure_refuses_hop() {
    let fixture = spawn_fixture(5);
    let log = FailingLog;
    let resolver = FakeResolver::default();

    let refused = open_hop(
        &log,
        &resolver,
        RemapConnector::new(fixture.addr()),
        &hop_request(EgressMode::UserProxy, "t", HopBudgets::default()),
    )
    .unwrap_err();
    assert!(matches!(refused, HopRefused::Log(_)));
    // ZERO connections reached the fixture: nothing was bound or dialled.
    assert_eq!(fixture.accepts.load(Ordering::SeqCst), 0);
    assert_eq!(resolver.calls(), 1);
}

#[test]
fn egress_to_private_ip_refused_after_dns() {
    let fixture = spawn_fixture(0);
    let log = RecordingLog::default();
    let resolver = FakeResolver::default();
    resolver.push(Ok(vec![IpAddr::from([192, 168, 1, 10])]));

    let refused = open_fixture_hop(
        &log,
        &resolver,
        &fixture,
        EgressMode::UserProxy,
        "t",
        HopBudgets::default(),
    )
    .unwrap_err();
    assert_eq!(
        refused,
        HopRefused::NonGlobalAddress {
            ip: IpAddr::from([192, 168, 1, 10]),
            class: "private",
        }
    );

    let records = log.records.lock().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].decision.wire_str(), "refuse:non-global-address");
    assert_eq!(records[0].resolved, vec![IpAddr::from([192, 168, 1, 10])]);
    assert_eq!(records[0].ip, None);
    drop(records);
    assert_eq!(fixture.accepts.load(Ordering::SeqCst), 0);
}

#[test]
fn mixed_dns_answer_refused() {
    let fixture = spawn_fixture(0);
    let log = RecordingLog::default();
    let resolver = FakeResolver::default();
    // One global address cannot carry a mixed answer: the whole hop is
    // refused, and the journal keeps the FULL answer for audit.
    resolver.push(Ok(vec![
        RemapConnector::REMAP_FROM_IP,
        IpAddr::from([10, 0, 0, 9]),
    ]));

    let refused = open_fixture_hop(
        &log,
        &resolver,
        &fixture,
        EgressMode::UserProxy,
        "t",
        HopBudgets::default(),
    )
    .unwrap_err();
    assert_eq!(
        refused,
        HopRefused::NonGlobalAddress {
            ip: IpAddr::from([10, 0, 0, 9]),
            class: "private",
        }
    );

    let records = log.records.lock().unwrap();
    assert_eq!(records[0].resolved.len(), 2);
    assert_eq!(records[0].ip, None);
    drop(records);
    assert_eq!(fixture.accepts.load(Ordering::SeqCst), 0);
}

#[test]
fn dns_rebinding_fixture_second_answer_never_used() {
    let fixture = spawn_fixture(5);
    let log = RecordingLog::default();
    let resolver = FakeResolver::default();
    resolver.push(Ok(vec![RemapConnector::REMAP_FROM_IP]));
    // The rebinding answer waits in the queue and is never consumed: a hop
    // resolves exactly once, before classification.
    resolver.push(Ok(vec![IpAddr::from([127, 0, 0, 1])]));

    let pump = open_fixture_hop(
        &log,
        &resolver,
        &fixture,
        EgressMode::UserProxy,
        "t",
        HopBudgets::default(),
    )
    .unwrap();
    let frame = run_fetch(pump.port(), "t", "example.test", 8080);
    assert_eq!(frame.header.status, Some(200));
    let io = pump.join();
    assert_eq!(io.ended, HopEnded::Relayed);
    assert_eq!(fixture.accepts.load(Ordering::SeqCst), 1);
    assert_eq!(resolver.calls(), 1);
    let records = log.records.lock().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].resolved, vec![RemapConnector::REMAP_FROM_IP]);
}

#[test]
fn dns_timeout_refuses_hop() {
    let fixture = spawn_fixture(0);
    let log = RecordingLog::default();
    let resolver = SlowResolver {
        delay: Duration::from_millis(300),
        deadline: Duration::from_millis(20),
    };

    let refused = open_fixture_hop(
        &log,
        &resolver,
        &fixture,
        EgressMode::UserProxy,
        "t",
        HopBudgets::default(),
    )
    .unwrap_err();
    assert_eq!(refused, HopRefused::DnsTimeout);

    let records = log.records.lock().unwrap();
    assert_eq!(records[0].decision.wire_str(), "refuse:dns-timeout");
    assert!(records[0].resolved.is_empty());
    assert_eq!(records[0].ip, None);
    drop(records);
    assert_eq!(fixture.accepts.load(Ordering::SeqCst), 0);
}

#[test]
fn wrong_token_refused() {
    let fixture = spawn_fixture(5);
    let log = RecordingLog::default();
    let resolver = FakeResolver::default();

    let pump = open_fixture_hop(
        &log,
        &resolver,
        &fixture,
        EgressMode::UserProxy,
        "right-token",
        HopBudgets::default(),
    )
    .unwrap();
    let frame = run_fetch(pump.port(), "wrong-token", "example.test", 8080);
    assert!(frame.header.error.is_some());
    let io = pump.join();
    assert_eq!(io.ended, HopEnded::Refused);
    // The origin was never dialled.
    assert_eq!(fixture.accepts.load(Ordering::SeqCst), 0);
}

#[test]
fn second_connect_refused() {
    let fixture = spawn_fixture(1024);
    let log = RecordingLog::default();
    let resolver = FakeResolver::default();

    let pump = open_fixture_hop(
        &log,
        &resolver,
        &fixture,
        EgressMode::UserProxy,
        "t",
        HopBudgets::default(),
    )
    .unwrap();
    let port = pump.port();
    let first = fetch_thread(port, "t", "example.test", 8080);
    thread::sleep(Duration::from_millis(100));
    let second = fetch_thread(port, "t", "example.test", 8080);

    let first = first.join().unwrap().expect("first fetch completes");
    assert_eq!(first.header.status, Some(200));
    let second = second.join().unwrap();
    // The second connection is closed in the drain window (or refused once
    // the listener is gone) — never served, never relayed.
    assert!(second.is_none_or(|frame| frame.header.error.is_some()));

    let io = pump.join();
    assert_eq!(io.ended, HopEnded::Relayed);
    assert_eq!(fixture.accepts.load(Ordering::SeqCst), 1);
}

/// The origin closing FIRST (before the fetcher lets go of the tunnel)
/// must not turn a clean hop into `aborted`: the pump never shuts a
/// socket down under the other relay thread — on Darwin that surfaces as
/// ECONNRESET in a sibling's blocked read, which used to audit `relayed`
/// hops as `aborted`. Instead the finished direction flags the sibling,
/// which stops orderly at its next bounded poll.
#[test]
fn origin_eof_before_fetcher_close_still_relays() {
    // Origin: answer one request, then close its half immediately.
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut buf = [0u8; 4096];
        let mut got: Vec<u8> = Vec::new();
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    got.extend_from_slice(&buf[..n]);
                    if got.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let body = "hello";
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(body.as_bytes());
        let _ = stream.shutdown(std::net::Shutdown::Both);
    });

    let log = RecordingLog::default();
    let resolver = FakeResolver::default();
    let pump = open_hop(
        &log,
        &resolver,
        RemapConnector::new(addr),
        &hop_request(EgressMode::UserProxy, "t", HopBudgets::default()),
    )
    .unwrap();

    let mut sock = raw_connect(pump.port(), "t", "example.test", 8080);
    sock.write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .unwrap();
    let mut response = Vec::new();
    sock.read_to_end(&mut response).unwrap();
    assert!(response.ends_with(b"hello"), "{response:?}");
    // The origin is long gone; the fetcher still holds the session for a
    // moment, exactly the window where the old cross-thread shutdown
    // raced the blocked up-relay read.
    thread::sleep(Duration::from_millis(150));
    drop(sock);

    let io = pump.join();
    assert_eq!(io.ended, HopEnded::Relayed);
    assert!(io.bytes_down >= 5);
    assert!(io.bytes_up > 0);
}

#[test]
fn connect_target_mismatch_refused() {
    let fixture = spawn_fixture(5);
    let log = RecordingLog::default();
    let resolver = FakeResolver::default();

    let pump = open_fixture_hop(
        &log,
        &resolver,
        &fixture,
        EgressMode::UserProxy,
        "t",
        HopBudgets::default(),
    )
    .unwrap();
    // The pump expects `CONNECT example.test:8080`; the client asks for
    // somewhere else entirely.
    let frame = run_fetch(pump.port(), "t", "evil.test", 99);
    assert!(frame.header.error.is_some());
    let io = pump.join();
    assert_eq!(io.ended, HopEnded::Refused);
    assert_eq!(fixture.accepts.load(Ordering::SeqCst), 0);
}

#[test]
fn pump_caps_bytes_and_time() {
    // Bytes: a direction stops at the cap, hard, and reports what moved.
    let fixture = spawn_fixture(1024 * 1024);
    let log = RecordingLog::default();
    let resolver = FakeResolver::default();
    const CAP: u64 = 64 * 1024;
    let budgets = HopBudgets::new(Duration::from_secs(10), CAP).unwrap();
    let pump = open_fixture_hop(
        &log,
        &resolver,
        &fixture,
        EgressMode::UserProxy,
        "t",
        budgets,
    )
    .unwrap();
    let mut client = raw_connect(pump.port(), "t", "example.test", 8080);
    // Ask the origin for the big body, then read until the cap ends the
    // hop and the pump closes the tunnel.
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .unwrap();
    let mut got: Vec<u8> = Vec::new();
    let read = client.read_to_end(&mut got).unwrap();
    assert_eq!(read as u64, CAP);
    let io = pump.join();
    assert_eq!(io.ended, HopEnded::Capped);
    assert_eq!(io.bytes_down, CAP);

    // Time: a silent client cannot hold the pump past the wall budget.
    let fixture = spawn_fixture(0);
    let log = RecordingLog::default();
    let resolver = FakeResolver::default();
    let budgets = HopBudgets::new(Duration::from_millis(300), DEFAULT_RELAY_CAP_BYTES).unwrap();
    let pump = open_fixture_hop(
        &log,
        &resolver,
        &fixture,
        EgressMode::UserProxy,
        "t",
        budgets,
    )
    .unwrap();
    let silent = TcpStream::connect(("127.0.0.1", pump.port())).unwrap();
    let io = pump.join();
    assert_eq!(io.ended, HopEnded::Timeout);
    assert!(io.elapsed >= Duration::from_millis(250));
    assert_eq!(io.bytes_up + io.bytes_down, 0);
    assert_eq!(fixture.accepts.load(Ordering::SeqCst), 0);
    drop(silent);
}

#[test]
fn loopback_connector_refuses_non_loopback() {
    let refused = LoopbackConnector
        .connect(SocketAddr::from(([93, 184, 216, 34], 80)))
        .unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::InvalidInput);
    // A loopback address is dialled (nothing listens on that port, but the
    // connector's refusal is only ever about the address class).
    let refused = LoopbackConnector
        .connect(SocketAddr::from(([127, 0, 0, 1], 9)))
        .unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
}

#[test]
#[cfg(not(feature = "net"))]
fn default_build_refuses_direct_mode() {
    let fixture = spawn_fixture(0);
    let log = RecordingLog::default();
    let resolver = FakeResolver::default();

    let refused = open_fixture_hop(
        &log,
        &resolver,
        &fixture,
        EgressMode::Direct,
        "t",
        HopBudgets::default(),
    )
    .unwrap_err();
    assert_eq!(refused, HopRefused::NoDirectEgress);
    // Total silence: nothing resolved, nothing journalled, nothing dialled.
    assert_eq!(resolver.calls(), 0);
    assert!(log.records.lock().unwrap().is_empty());
    assert_eq!(fixture.accepts.load(Ordering::SeqCst), 0);
    assert!(!direct_egress_available());
}

#[test]
fn budgets_refuse_out_of_range() {
    assert!(HopBudgets::new(Duration::ZERO, DEFAULT_RELAY_CAP_BYTES).is_err());
    assert!(HopBudgets::new(
        MAX_HOP_WALL + Duration::from_secs(1),
        DEFAULT_RELAY_CAP_BYTES
    )
    .is_err());
    assert!(HopBudgets::new(DEFAULT_HOP_WALL, 0).is_err());
    assert!(HopBudgets::new(DEFAULT_HOP_WALL, MAX_RELAY_CAP_BYTES + 1).is_err());
    assert!(HopBudgets::new(Duration::from_millis(1), 1).is_ok());
    assert_eq!(HopBudgets::default().wall(), DEFAULT_HOP_WALL);
    assert_eq!(
        HopBudgets::default().relay_cap_bytes(),
        DEFAULT_RELAY_CAP_BYTES
    );
}

#[test]
fn egress_decision_wire_text() {
    assert_eq!(EgressDecision::Allow.wire_str(), "allow");
    assert_eq!(
        EgressDecision::Refuse(RefuseReason::HostNotAllowlisted).wire_str(),
        "refuse:host-not-allowlisted"
    );
    assert_eq!(
        EgressDecision::Refuse(RefuseReason::Downgrade).wire_str(),
        "refuse:downgrade"
    );
    assert_eq!(EgressMode::UserProxy.as_str(), "user-proxy");
    assert_eq!(EgressMode::SearchEndpoint.as_str(), "search-endpoint");
    assert_eq!(EgressPurpose::Search.as_str(), "search");
    assert_eq!(HopEnded::ConnectFailed.as_str(), "connect_failed");
}

// ---------------------------------------------------------------------------
// P-39h: search-endpoint mode.
// ---------------------------------------------------------------------------

#[test]
fn search_hop_journals_allow_and_dials_loopback_without_resolution() {
    let fixture = spawn_fixture(5);
    let log = RecordingLog::default();
    let resolver = FakeResolver::default();
    let port = fixture.addr().port();
    let req = HopRequest {
        hop: 9,
        url: format!("http://127.0.0.1:{port}/search?q=x&format=json"),
        host: "127.0.0.1".to_string(),
        port,
        mode: EgressMode::SearchEndpoint,
        purpose: EgressPurpose::Search,
        token: "t",
        budgets: HopBudgets::default(),
    };
    let pump = open_hop(&log, &resolver, LoopbackConnector, &req).unwrap();

    // INV-43: allowed before any byte; no resolution happened (§8 step 1).
    let records = log.records.lock().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].decision, EgressDecision::Allow);
    assert!(records[0].resolved.is_empty());
    assert_eq!(records[0].ip, Some(IpAddr::from([127, 0, 0, 1])));
    assert_eq!(records[0].purpose, EgressPurpose::Search);
    assert_eq!(records[0].mode, EgressMode::SearchEndpoint);
    drop(records);
    assert_eq!(resolver.calls(), 0, "search endpoints are never resolved");

    let frame = run_fetch(pump.port(), "t", "127.0.0.1", port);
    assert_eq!(frame.header.status, Some(200));
    let io = pump.join();
    assert_eq!(io.ended, HopEnded::Relayed);
    assert_eq!(io.chosen, IpAddr::from([127, 0, 0, 1]));
    assert_eq!(fixture.accepts.load(Ordering::SeqCst), 1);
}

#[test]
fn search_endpoint_non_loopback_host_refused_and_journalled() {
    let fixture = spawn_fixture(0);
    let log = RecordingLog::default();
    let resolver = FakeResolver::default();
    for host in ["10.0.0.5", "example.test", "[::1]x"] {
        let req = HopRequest {
            hop: 9,
            url: format!("http://{host}/search?q=x"),
            host: host.to_string(),
            port: fixture.addr().port(),
            mode: EgressMode::SearchEndpoint,
            purpose: EgressPurpose::Search,
            token: "t",
            budgets: HopBudgets::default(),
        };
        let refused = open_hop(&log, &resolver, LoopbackConnector, &req).unwrap_err();
        assert!(
            matches!(refused, HopRefused::Resolve(_)),
            "host {host}: {refused:?}"
        );
    }
    let records = log.records.lock().unwrap();
    assert_eq!(records.len(), 3);
    for r in records.iter() {
        assert_eq!(r.decision.wire_str(), "refuse:no-address");
        assert!(r.resolved.is_empty());
        assert_eq!(r.ip, None);
    }
    drop(records);
    assert_eq!(resolver.calls(), 0, "never resolved, refused outright");
    assert_eq!(fixture.accepts.load(Ordering::SeqCst), 0);
}
