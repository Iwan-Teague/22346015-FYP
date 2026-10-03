//! P-39g: `harness.web.fetch` through the confined fetcher, over the
//! real seam (a research session authorises, the journal makes the
//! intent durable, then `WebTools` runs the call). The egress side is
//! faked in process — a scripted HTTP fixture stands in for the origin,
//! a remapping connector dials it for the pinned test address, and the
//! hop runner runs the fetcher library in process (design §5.1's
//! dev-dependency carve-out). `fetcher_runs_confined_end_to_end` runs
//! the real binary through the real sandbox on macOS when it can find
//! one.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::Cell;
use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use harness_core::RunId;
use harness_journal::testing::{FaultFile, FaultPlan, MemBlobs};
use harness_journal::{Clock, Event, EventKind, Header, Ident, JournalWriter};
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, SemVer, ValidationContext};
use harness_model_core::endpoint::Endpoint;
use harness_policy::web::Allowlist;
use harness_policy::{
    Call, DenyReason, PolicyDecision, Session, SessionKind, SessionSpec, UserPolicy,
    WebConfirmation, WebGrant,
};
use harness_sandbox::egress::{
    Connector, EgressLog, EgressLogError, EgressMode, EgressRecord, ResolveRefused, Resolver,
};
use harness_sandbox::{
    ConfinedChild, ConfinedSpec, Confinement, Conformed, Refused, SpawnError, Unavailable,
    UnavailableReason,
};
use harness_tools::builtin::code;
use harness_tools::{
    BoxConnector, Egress, FetcherPin, HopRun, HopRunner, InvokeCtx, RunnerError, ToolProvider,
    ToolResult, ToolStatus, WebBudgets, WebSetupError, WebTools,
};
use serde_json::{json, Value};

struct Tick(Cell<u64>);
impl Clock for Tick {
    fn mono_ms(&self) -> u64 {
        self.0.set(self.0.get() + 1);
        self.0.get()
    }
    fn unix_ms(&self) -> u64 {
        0
    }
}

fn scratch(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("web-tools-{name}"));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// The pinned test address: not loopback, not private — the only address
/// a remapping connector may dial (egress tests use it the same way).
fn remap_ip() -> IpAddr {
    IpAddr::from([93, 184, 216, 34])
}

/// Answers every host with the remap address, or the next scripted
/// answer when there is one (the private-IP tests push one).
struct FakeResolver {
    answers: Mutex<VecDeque<Vec<IpAddr>>>,
    calls: AtomicUsize,
}

impl FakeResolver {
    fn new() -> Self {
        Self {
            answers: Mutex::new(VecDeque::new()),
            calls: AtomicUsize::new(0),
        }
    }

    fn push(&self, answer: Vec<IpAddr>) {
        self.answers.lock().unwrap().push_back(answer);
    }
}

impl Resolver for FakeResolver {
    fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, ResolveRefused> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .answers
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| vec![remap_ip()]))
    }
}

/// Dials the fixture for the remap address; refuses anything else.
struct RemapConnector {
    to: SocketAddr,
}

impl Connector for RemapConnector {
    fn connect(&self, addr: SocketAddr) -> std::io::Result<TcpStream> {
        if addr.ip() == remap_ip() {
            TcpStream::connect(self.to)
        } else {
            Err(std::io::Error::other("not the remap address"))
        }
    }
}

/// Every `Egress` decision, kept in order.
struct RecordingLog {
    records: Mutex<Vec<EgressRecord>>,
}

impl RecordingLog {
    fn new() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
        }
    }

    fn len(&self) -> usize {
        self.records.lock().unwrap().len()
    }

    fn decisions(&self) -> Vec<String> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .map(|r| match &r.decision {
                harness_sandbox::egress::EgressDecision::Allow => "allow".to_string(),
                harness_sandbox::egress::EgressDecision::Refuse(reason) => {
                    format!("refuse:{}", reason.as_str())
                }
            })
            .collect()
    }
}

impl EgressLog for RecordingLog {
    fn append(&self, record: &EgressRecord) -> Result<(), EgressLogError> {
        self.records.lock().unwrap().push(record.clone());
        Ok(())
    }
}

/// The hop runner design §5.1 carves out for tests: the fetcher library
/// run in process against the relay.
struct InProcessHopRunner;

impl HopRunner for InProcessHopRunner {
    fn run(&mut self, run: &HopRun<'_>) -> Result<Vec<u8>, RunnerError> {
        let bytes = fs::read(run.req_path).map_err(|e| RunnerError::Io(e.to_string()))?;
        let req =
            harness_fetch::read_request(&bytes).map_err(|e| RunnerError::Io(e.to_string()))?;
        eprintln!(
            "DBG req mode={:?} v={} target={}",
            req.mode, req.v, req.target
        );
        eprintln!("DBG req.json: {}", String::from_utf8_lossy(&bytes));
        let mut sock = TcpStream::connect(("127.0.0.1", run.proxy_port))
            .map_err(|e| RunnerError::Io(e.to_string()))?;
        let frame = harness_fetch::fetch_over(&mut sock, &req);
        eprintln!("DBG frame header: {:?}", frame.header);
        Ok(harness_fetch::encode_frame(&frame))
    }
}

/// A test confinement that never spawns: in-process tests never reach
/// the fetcher binary.
struct NeverSpawn;

impl Confinement for NeverSpawn {
    fn require(&self) -> Result<Conformed, Refused> {
        Err(Refused(Unavailable {
            backend: None,
            reason: UnavailableReason::NoBackendForOs,
        }))
    }

    fn spawn(&self, _spec: &ConfinedSpec, _ev: &Conformed) -> Result<ConfinedChild, SpawnError> {
        Err(SpawnError::Io("tests never spawn".into()))
    }
}

/// A scripted origin: one connection per hop; each connection gets the
/// next blob (a CONNECT 200 followed by the HTTP response, in one
/// write), then is closed.
struct Fixture {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
}

fn fixture(responses: Vec<Vec<u8>>) -> Fixture {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let script = Arc::new(Mutex::new(VecDeque::from(responses)));
    let accepts2 = accepts.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut sock) = conn else { break };
            accepts2.fetch_add(1, Ordering::SeqCst);
            let next = script.lock().unwrap().pop_front();
            let Some(resp) = next else { break };
            let _ = sock.write_all(&resp);
            let _ = sock.flush();
            let _ = sock.shutdown(Shutdown::Write);
            let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
            let mut buf = [0u8; 4096];
            loop {
                match sock.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
    });
    Fixture { addr, accepts }
}

fn accepts(f: &Fixture) -> usize {
    f.accepts.load(Ordering::SeqCst)
}

/// One scripted origin connection: a plain HTTP response. The pump
/// terminates the CONNECT on the loopback side, so the origin sees a
/// bare `GET` and answers with the response and nothing else.
fn response(content_type: Option<&str>, extra: &[&str], body: &[u8]) -> Vec<u8> {
    let mut head = "HTTP/1.1 200 OK\r\n".to_string();
    if let Some(ct) = content_type {
        head.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    for e in extra {
        head.push_str(e);
        head.push_str("\r\n");
    }
    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    head.push_str("Connection: close\r\n\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

fn redirect(location: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

/// The pinned fetcher stand-in: a real file whose digest the provider
/// verifies at construction (in-process tests never execute it).
fn pinned_fetcher(dir: &Path) -> FetcherPin {
    let p = dir.join("fetcher-stand-in");
    fs::write(&p, b"rustyharness-fetch stand-in for in-process tests\n").unwrap();
    FetcherPin {
        path: p,
        sha256: harness_core::sha256(b"rustyharness-fetch stand-in for in-process tests\n"),
    }
}

struct Rig<'a> {
    w: JournalWriter<FaultFile, MemBlobs, Tick>,
    s: Session,
    step: u64,
    t: WebTools<'a>,
    log: Arc<RecordingLog>,
    resolver: Arc<FakeResolver>,
    fixture: Fixture,
}

impl<'a> Rig<'a> {
    fn new(name: &str, responses: Vec<Vec<u8>>, budgets: WebBudgets) -> Self {
        Self::build(
            name,
            responses,
            budgets,
            None::<&fn(u16) -> Endpoint>,
            false,
        )
    }

    /// A research session granted `harness.web.search` too, with the
    /// provider wired to a loopback search endpoint on the fixture's
    /// port (P-39h).
    fn new_search(
        name: &str,
        responses: Vec<Vec<u8>>,
        budgets: WebBudgets,
        endpoint_for: impl Fn(u16) -> Endpoint,
    ) -> Self {
        Self::build(name, responses, budgets, Some(&endpoint_for), true)
    }

    fn build(
        name: &str,
        responses: Vec<Vec<u8>>,
        budgets: WebBudgets,
        search: Option<&impl Fn(u16) -> Endpoint>,
        grants_search: bool,
    ) -> Self {
        let ctx = ValidationContext::new(
            SemVer {
                major: 0,
                minor: 0,
                patch: 1,
            },
            &[],
        )
        .unwrap();
        let reg = Registry::admit(vec![(
            builtin::research_manifest(&ctx).unwrap(),
            Tier::Builtin,
        )])
        .unwrap();
        let mut grants = vec!["harness.web.fetch".to_string()];
        if grants_search {
            grants.push("harness.web.search".to_string());
        }
        let s = Session::plan(
            &SessionSpec {
                grants,
                workspace: None,
                approver_present: false,
                personal_data_granted: false,
                conformed: false,
                exec_programs: Vec::new(),
                read_window: None,
                kind: SessionKind::Research(WebGrant {
                    allowlist: vec![
                        "http://example.test:8080".into(),
                        "http://example.test:8081".into(),
                    ],
                    search: grants_search,
                    confirmed: Some(WebConfirmation::Flag),
                }),
            },
            &reg,
            &UserPolicy::default(),
        )
        .unwrap();
        let w = JournalWriter::start(
            FaultFile::new(FaultPlan::default()),
            MemBlobs::default(),
            Tick(Cell::new(0)),
            RunId::new(1, [0; 10]),
            1,
            Header::new(Ident::of("0.0.1").unwrap()),
        )
        .unwrap();
        let dir = scratch(name);
        let fixture = fixture(responses);
        let search = search.map(|f| f(fixture.addr.port()));
        let log = Arc::new(RecordingLog::new());
        let resolver = Arc::new(FakeResolver::new());
        let t = WebTools::new_with_runner(
            &dir,
            Allowlist::load(&[
                "http://example.test:8080".into(),
                "http://example.test:8081".into(),
            ])
            .unwrap(),
            budgets,
            pinned_fetcher(&dir),
            search,
            Box::new(InProcessHopRunner),
            Egress {
                mode: EgressMode::UserProxy,
                resolver: resolver.clone(),
                connector: BoxConnector::new(Arc::new(RemapConnector { to: fixture.addr })),
            },
        )
        .unwrap();
        Self {
            w,
            s,
            step: 0,
            t,
            log,
            resolver,
            fixture,
        }
    }

    fn call(&mut self, args: Value) -> ToolResult {
        self.call_egress(args, true)
    }

    fn call_egress(&mut self, args: Value, wired: bool) -> ToolResult {
        self.call_cap("harness.web.fetch", args, wired)
    }

    /// A `harness.web.search` call through the same journal seam.
    fn call_search(&mut self, args: Value) -> ToolResult {
        self.call_cap("harness.web.search", args, true)
    }

    fn call_cap(&mut self, cap: &str, args: Value, wired: bool) -> ToolResult {
        self.step += 1;
        let a = self
            .s
            .authorize(Call {
                capability: cap.to_string(),
                args,
            })
            .expect("policy allows the call");
        let j = self
            .w
            .append_intent(self.step, Event::new(EventKind::ToolStarted), a)
            .unwrap();
        let none: Option<&dyn EgressLog> = None;
        let log: Option<&dyn EgressLog> = if wired { Some(self.log.as_ref()) } else { none };
        self.t
            .invoke(
                j,
                &InvokeCtx {
                    step: self.step,
                    deadline: Instant::now() + Duration::from_secs(30),
                    reads: &harness_tools::ReadLog::default(),
                    egress: log,
                },
            )
            .unwrap()
    }
}

fn text(r: &ToolResult) -> String {
    String::from_utf8(r.output.inspect("test").clone()).unwrap()
}

fn err_code(r: &ToolResult) -> u16 {
    match r.status {
        ToolStatus::Error { code } => code,
        other => panic!("expected an error status, got {other:?}: {}", text(r)),
    }
}

fn ok_code(r: &ToolResult) {
    assert_eq!(r.status, ToolStatus::Ok, "{}", text(r));
}

fn research_session(allowlist: &[&str]) -> Session {
    let ctx = ValidationContext::new(
        SemVer {
            major: 0,
            minor: 0,
            patch: 1,
        },
        &[],
    )
    .unwrap();
    let reg = Registry::admit(vec![(
        builtin::research_manifest(&ctx).unwrap(),
        Tier::Builtin,
    )])
    .unwrap();
    Session::plan(
        &SessionSpec {
            grants: vec!["harness.web.fetch".into()],
            workspace: None,
            approver_present: false,
            personal_data_granted: false,
            conformed: false,
            exec_programs: Vec::new(),
            read_window: None,
            kind: SessionKind::Research(WebGrant {
                allowlist: allowlist.iter().map(|s| (*s).to_string()).collect(),
                search: false,
                confirmed: Some(WebConfirmation::Flag),
            }),
        },
        &reg,
        &UserPolicy::default(),
    )
    .unwrap()
}

const PAGE: &str = "<html><title>Example</title><body><h1>Hello</h1><p>body text</p></body></html>";

#[test]
fn fetch_html_extracted_untrusted_web_source() {
    let mut rig = Rig::new(
        "html-ok",
        vec![response(
            Some("text/html; charset=utf-8"),
            &[],
            PAGE.as_bytes(),
        )],
        WebBudgets::default(),
    );
    let r = rig.call(json!({"url": "http://example.test:8080/"}));
    ok_code(&r);
    assert!(
        matches!(r.output.source(), harness_core::Source::Web(url) if url.starts_with("http://example.test:8080")),
        "source is {:?}",
        r.output.source()
    );
    let t = text(&r);
    assert!(
        t.contains("fetched http://example.test:8080/ -> 200 text/html"),
        "{t}"
    );
    assert!(t.contains("sha256:"), "{t}");
    assert!(t.contains(" 1-3/3\n"), "{t}");
    assert!(t.contains("Hello"), "extracted heading: {t}");
    assert!(t.contains("body text"), "{t}");
    let web = r.web.as_ref().unwrap();
    assert_eq!(web.hops.len(), 1);
    assert_eq!(web.hops[0].status, Some(200));
    assert_eq!(web.hops[0].ended, "relayed");
    assert_eq!(web.hops[0].mode, "user-proxy");
    assert_eq!(web.final_url, "http://example.test:8080/");
    assert!(!web.cached);
}

#[test]
fn fetched_text_marked_untrusted() {
    let mut rig = Rig::new(
        "untrusted",
        vec![response(Some("text/plain"), &[], b"plain text body\n")],
        WebBudgets::default(),
    );
    let r = rig.call(json!({"url": "http://example.test:8080/a.txt"}));
    ok_code(&r);
    // `inspect` is the only way in: the bytes are untrusted by type, and
    // every observation carries the audit header before the body.
    let t = text(&r);
    assert!(
        t.starts_with("fetched http://example.test:8080/a.txt -> 200 text/plain 16B sha256:"),
        "{t}"
    );
    assert!(t.ends_with(" 1-1/1\nplain text body\n"), "{t}");
    assert!(!r.web.as_ref().unwrap().cached);
}

#[test]
fn redirect_to_private_ip_refused_per_hop() {
    let mut rig = Rig::new(
        "private-ip",
        vec![redirect("http://example.test:8080/latest")],
        WebBudgets::default(),
    );
    // Hop 1 resolves to the pinned test address and dials the fixture;
    // the redirect hop's answer is the metadata service.
    rig.resolver.push(vec![remap_ip()]);
    rig.resolver.push(vec![IpAddr::from([169, 254, 169, 254])]);
    let r = rig.call(json!({"url": "http://example.test:8080/start"}));
    assert_eq!(err_code(&r), code::WEB_EGRESS);
    assert_eq!(accepts(&rig.fixture), 1, "only hop 1 dialed");
    let decisions = rig.log.decisions();
    assert!(
        decisions.contains(&"refuse:non-global-address".to_string()),
        "{decisions:?}"
    );
}

#[test]
fn redirect_to_unlisted_host_refused() {
    let mut rig = Rig::new(
        "unlisted",
        vec![redirect("http://evil.test:80/")],
        WebBudgets::default(),
    );
    let r = rig.call(json!({"url": "http://example.test:8080/out"}));
    assert_eq!(err_code(&r), code::WEB_URL_REFUSED);
    assert_eq!(accepts(&rig.fixture), 1);
    let decisions = rig.log.decisions();
    assert!(
        decisions.contains(&"refuse:host-not-allowlisted".to_string()),
        "{decisions:?}"
    );
}

#[test]
fn too_many_redirects_refused() {
    let responses: Vec<Vec<u8>> = (1..=6)
        .map(|i| redirect(&format!("http://example.test:8080/r{i}")))
        .collect();
    let mut rig = Rig::new("many-redirects", responses, WebBudgets::default());
    let r = rig.call(json!({"url": "http://example.test:8080/loop"}));
    assert_eq!(err_code(&r), code::WEB_REDIRECT_LIMIT);
    assert_eq!(accepts(&rig.fixture), 6, "1 + 5 redirect hops");
    assert_eq!(rig.log.len(), 6, "one allow per hop");
}

#[test]
fn content_type_pdf_refused() {
    let mut rig = Rig::new(
        "pdf",
        vec![response(Some("application/pdf"), &[], b"%PDF-1.4 fake")],
        WebBudgets::default(),
    );
    let r = rig.call(json!({"url": "http://example.test:8080/doc.pdf"}));
    assert_eq!(err_code(&r), code::WEB_CONTENT_TYPE);
}

#[test]
fn declared_html_binary_body_refused() {
    let mut body = b"<html>ok so far".to_vec();
    body.push(0);
    body.extend_from_slice(b"then binary");
    let mut rig = Rig::new(
        "binary",
        vec![response(Some("text/html"), &[], &body)],
        WebBudgets::default(),
    );
    let r = rig.call(json!({"url": "http://example.test:8080/bin.html"}));
    assert_eq!(err_code(&r), code::WEB_BINARY);
}

#[test]
fn missing_content_type_refused() {
    let mut rig = Rig::new(
        "no-ctype",
        vec![response(None, &[], b"<html>no type</html>")],
        WebBudgets::default(),
    );
    let r = rig.call(json!({"url": "http://example.test:8080/no-type"}));
    assert_eq!(err_code(&r), code::WEB_CONTENT_TYPE);
}

#[test]
fn latin1_decoded_unknown_charset_refused() {
    // iso-8859-1 decodes as windows-1252: 0xE9 is e-acute.
    let mut rig = Rig::new(
        "latin1",
        vec![response(
            Some("text/plain; charset=iso-8859-1"),
            &[],
            b"caf\xe9 menu",
        )],
        WebBudgets::default(),
    );
    let r = rig.call(json!({"url": "http://example.test:8080/cafe.txt"}));
    ok_code(&r);
    assert!(text(&r).contains("café"), "{}", text(&r));
    // An unknown charset is refused, never guessed.
    let mut rig2 = Rig::new(
        "shift-jis",
        vec![response(
            Some("text/plain; charset=shift_jis"),
            &[],
            b"\x93\xfa\x96{",
        )],
        WebBudgets::default(),
    );
    let r = rig2.call(json!({"url": "http://example.test:8080/jp.txt"}));
    assert_eq!(err_code(&r), code::WEB_CHARSET);
}

#[test]
fn giant_response_truncated_marked() {
    let body = vec![b'x'; 10_000];
    let budgets = WebBudgets {
        body_max_bytes: 1024,
        ..WebBudgets::default()
    };
    let mut rig = Rig::new(
        "giant",
        vec![response(Some("text/plain"), &[], &body)],
        budgets,
    );
    let r = rig.call(json!({"url": "http://example.test:8080/big.txt"}));
    ok_code(&r);
    let t = text(&r);
    assert!(t.contains("(truncated)"), "{t}");
    let web = r.web.as_ref().unwrap();
    assert!(web.hops[0].truncated, "hop records the cut");
    assert_eq!(web.hops[0].body_len, 1024);
}

#[test]
fn second_window_served_from_cache_without_egress() {
    let page = "line one\nline two\nline three\nline four\nline five\n";
    let mut rig = Rig::new(
        "cache",
        vec![response(Some("text/plain"), &[], page.as_bytes())],
        WebBudgets::default(),
    );
    let r1 = rig.call(json!({"url": "http://example.test:8080/lines.txt", "start": 1, "lines": 5}));
    ok_code(&r1);
    let records = rig.log.len();
    let dialed = accepts(&rig.fixture);
    let r2 = rig.call(json!({"url": "http://example.test:8080/lines.txt", "start": 2, "lines": 3}));
    ok_code(&r2);
    assert!(r2.web.as_ref().unwrap().cached);
    assert_eq!(rig.log.len(), records, "no egress for a cache hit");
    assert_eq!(
        accepts(&rig.fixture),
        dialed,
        "no connection for a cache hit"
    );
    let t = text(&r2);
    assert!(t.contains("line two"), "{t}");
    assert!(t.contains("line four"), "{t}");
    assert!(!t.contains("line one"), "{t}");
}

#[test]
fn fetch_budget_exhausted_refused() {
    let budgets = WebBudgets {
        fetches: 1,
        ..WebBudgets::default()
    };
    let mut rig = Rig::new(
        "budget",
        vec![
            response(Some("text/plain"), &[], b"first"),
            response(Some("text/plain"), &[], b"second"),
        ],
        budgets,
    );
    let r = rig.call(json!({"url": "http://example.test:8080/one.txt"}));
    ok_code(&r);
    let r = rig.call(json!({"url": "http://example.test:8080/two.txt"}));
    assert_eq!(err_code(&r), code::WEB_BUDGET);
    assert_eq!(accepts(&rig.fixture), 1);
}

#[test]
fn terminal_escapes_in_page_inert() {
    let page = "<html><body><pre>\u{1b}[31mred\u{1b}[0m plain</pre></body></html>";
    let mut rig = Rig::new(
        "escapes",
        vec![response(Some("text/html"), &[], page.as_bytes())],
        WebBudgets::default(),
    );
    let r = rig.call(json!({"url": "http://example.test:8080/esc.html"}));
    ok_code(&r);
    let t = text(&r);
    assert!(!t.contains('\u{1b}'), "raw ESC leaked: {t:?}");
    assert!(t.contains("[31m"), "the sequence survives inert: {t}");
}

#[test]
fn fetch_refused_without_egress_log() {
    let mut rig = Rig::new(
        "no-egress",
        vec![response(Some("text/plain"), &[], b"never fetched")],
        WebBudgets::default(),
    );
    let r = rig.call_egress(json!({"url": "http://example.test:8080/x"}), false);
    assert_eq!(err_code(&r), code::WEB_EGRESS);
    assert_eq!(rig.log.len(), 0, "nothing journaled: no log to journal to");
    assert_eq!(accepts(&rig.fixture), 0, "nothing dialed");
}

#[test]
fn fetch_refused_without_conformed() {
    // INV-46: without a witness covering the airlock cases nothing is
    // fetched. The only mint is `require()`, which enforces the H2 exit
    // cases; today's conformance matrix row does not yet carry the four
    // proxy airlock cases (FT-13p/15p/19/20), so the real witness on this
    // machine is exactly "a witness that does not cover the airlock
    // cases" — and the default (confined) hop runner must refuse it at
    // construction. When the row lands, the positive path is proven by
    // `fetcher_runs_confined_end_to_end`.
    let witness = harness_sandbox::require()
        .unwrap_or_else(|e| panic!("this test needs a conformed sandbox: {e}"));
    let airlocked = witness
        .covers(harness_sandbox::conformance::AIRLOCK_CASES)
        .is_err();
    let dir = scratch("no-conformed");
    let pin = pinned_fetcher(&dir);
    let nc = NeverSpawn;
    let e = WebTools::new(
        &dir,
        Allowlist::load(&["http://example.test:8080".into()]).unwrap(),
        WebBudgets::default(),
        pin,
        None,
        &nc,
        witness,
        Egress {
            mode: EgressMode::UserProxy,
            resolver: Arc::new(FakeResolver::new()),
            connector: BoxConnector::new(Arc::new(RemapConnector {
                to: "127.0.0.1:1".parse().unwrap(),
            })),
        },
    )
    .err()
    .expect("construction with the default confined runner must fail today");
    assert!(
        matches!(e, WebSetupError::NoConformed),
        "expected NoConformed, got {e}"
    );
    assert!(airlocked, "the matrix row gained the airlock cases: this test now needs a covering witness to stay honest");
}

#[test]
fn fetcher_digest_mismatch_refused() {
    let dir = scratch("digest");
    let pin = pinned_fetcher(&dir);
    let wrong = FetcherPin {
        path: pin.path.clone(),
        sha256: harness_core::sha256(b"not the pinned bytes"),
    };
    let e = WebTools::new_with_runner(
        &dir,
        Allowlist::load(&["http://example.test:8080".into()]).unwrap(),
        WebBudgets::default(),
        wrong,
        None,
        Box::new(InProcessHopRunner),
        Egress {
            mode: EgressMode::UserProxy,
            resolver: Arc::new(FakeResolver::new()),
            connector: BoxConnector::new(Arc::new(RemapConnector {
                to: "127.0.0.1:1".parse().unwrap(),
            })),
        },
    )
    .err()
    .expect("construction refuses a digest mismatch");
    assert!(matches!(e, WebSetupError::Digest { .. }), "{e}");
}

#[test]
fn url_not_on_allowlist_refused_before_any_hop() {
    let rig = Rig::new(
        "not-allowlisted",
        vec![response(Some("text/plain"), &[], b"unused")],
        WebBudgets::default(),
    );
    // The allowlist is a policy check: the call is refused at authorize,
    // before the provider, the journal, or any hop.
    let e = rig
        .s
        .authorize(Call {
            capability: "harness.web.fetch".into(),
            args: json!({"url": "http://other.test:8080/"}),
        })
        .expect_err("a host off the allowlist is refused at policy");
    assert!(
        matches!(
            e,
            PolicyDecision::Deny {
                reason: DenyReason::Web(harness_policy::WebCallRefused::HostNotAllowlisted),
                ..
            }
        ),
        "{e:?}"
    );
    assert_eq!(rig.log.len(), 0);
    assert_eq!(accepts(&rig.fixture), 0);
}

#[test]
fn ungranted_capability_refused_at_policy() {
    // A capability outside the session's active set (unknown or never
    // granted) is denied at authorize — no intent is journaled and no
    // provider ever runs (fail closed at the earliest layer).
    let mut rig = Rig::new("unknown-cap", vec![], WebBudgets::default());
    rig.step += 1;
    let e = rig
        .s
        .authorize(Call {
            capability: "harness.fs.read".into(),
            args: json!({"path": "x"}),
        })
        .expect_err("an ungranted capability is refused at policy");
    assert!(
        matches!(
            e,
            PolicyDecision::Deny {
                reason: DenyReason::NotGranted,
                ..
            }
        ),
        "{e:?}"
    );
    assert_eq!(rig.log.len(), 0);
    assert_eq!(accepts(&rig.fixture), 0);
}

#[cfg(target_os = "macos")]
#[test]
fn fetcher_runs_confined_end_to_end() {
    let bin = std::env::var("RH_FETCHER_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/rustyharness-fetch")
        });
    if !bin.is_file() {
        eprintln!(
            "skipping fetcher_runs_confined_end_to_end: no fetcher binary at {}",
            bin.display()
        );
        return;
    }
    let witness = harness_sandbox::require().unwrap();
    if witness
        .covers(harness_sandbox::conformance::AIRLOCK_CASES)
        .is_err()
    {
        // The confined runner refuses at construction until the
        // conformance matrix row carries the proxy airlock cases
        // (FT-13p/15p/19/20). Skipping is honest: fabricating coverage
        // would defeat the check this test exists to exercise.
        eprintln!(
            "skipping fetcher_runs_confined_end_to_end: the sandbox matrix row \
             does not yet cover the airlock proxy cases, so no mintable \
             witness can pass the confined runner's INV-46 check"
        );
        return;
    }
    let dir = scratch("e2e-real");
    let mut digest = harness_core::Sha256Stream::new();
    digest.update(&fs::read(&bin).unwrap());
    let pin = FetcherPin {
        path: bin,
        sha256: digest.finish(),
    };
    let fixture = fixture(vec![response(
        Some("text/plain"),
        &[],
        b"confined end to end",
    )]);
    let log = Arc::new(RecordingLog::new());
    let sys = harness_sandbox::SystemConfinement;
    let mut t = WebTools::new(
        &dir,
        Allowlist::load(&["http://example.test:8080".into()]).unwrap(),
        WebBudgets::default(),
        pin,
        None,
        &sys,
        witness.clone(),
        Egress {
            mode: EgressMode::UserProxy,
            resolver: Arc::new(FakeResolver::new()),
            connector: BoxConnector::new(Arc::new(RemapConnector { to: fixture.addr })),
        },
    )
    .unwrap();
    // The default runner IS the confined one; nothing to swap.
    let s = research_session(&["http://example.test:8080"]);
    let mut w = JournalWriter::start(
        FaultFile::new(FaultPlan::default()),
        MemBlobs::default(),
        Tick(Cell::new(0)),
        RunId::new(1, [0; 10]),
        1,
        Header::new(Ident::of("0.0.1").unwrap()),
    )
    .unwrap();
    let a = s
        .authorize(Call {
            capability: "harness.web.fetch".into(),
            args: json!({"url": "http://example.test:8080/e2e.txt"}),
        })
        .unwrap();
    let j = w
        .append_intent(1, Event::new(EventKind::ToolStarted), a)
        .unwrap();
    let r = t
        .invoke(
            j,
            &InvokeCtx {
                step: 1,
                deadline: Instant::now() + Duration::from_secs(30),
                reads: &harness_tools::ReadLog::default(),
                egress: Some(log.as_ref()),
            },
        )
        .unwrap();
    ok_code(&r);
    assert!(text(&r).contains("confined end to end"), "{}", text(&r));
    assert_eq!(r.web.as_ref().unwrap().hops[0].ended, "relayed");
}

// ---------------------------------------------------------------------------
// P-39h: harness.web.search over the loopback SearXNG endpoint.
// ---------------------------------------------------------------------------

/// A SearXNG-shaped JSON response body.
fn searx(results: Value) -> Vec<u8> {
    let mut doc = results;
    doc.as_object_mut()
        .unwrap()
        .entry("results")
        .or_insert_with(|| json!([]));
    response(
        Some("application/json"),
        &[],
        serde_json::to_vec(&doc).unwrap().as_slice(),
    )
}

fn search_endpoint() -> impl Fn(u16) -> Endpoint {
    |port| Endpoint::parse(&format!("http://127.0.0.1:{port}")).unwrap()
}

#[test]
fn search_results_bounded_sanitised_and_marked_fetchable() {
    // Hostile classes (§11): an ESC sequence and a bidi control in the
    // payload fields, overlong title and snippet.
    let title = format!("{}\u{1b}[31m injected", "x".repeat(130));
    let snippet = format!("{}\u{1b}[2K\u{200B}tail", "y".repeat(310));
    let results = json!({
        "query": "tokio",
        "results": [
            {"url": "not a url at all", "title": "dropped me", "content": "dropped"},
            {"url": "http://example.test:8080/a", "title": title, "content": snippet},
            {"url": "http://example.test:8081/b", "title": "Second", "content": "second snippet"},
            {"url": "http://off.test:80/c", "title": "Third off", "content": "third snippet"},
            {"url": "http://off.test:80/d", "title": "Fourth off", "content": ""},
            {"url": "http://off.test:80/e", "title": "Fifth off"},
            {"url": "http://off.test:80/f", "title": "Sixth — past the cap"}
        ],
        "infobox": {"secret": "RAW_JSON_MARKER"}
    });
    let mut rig = Rig::new_search(
        "search-bounded",
        vec![searx(results)],
        WebBudgets::default(),
        search_endpoint(),
    );
    let r = rig.call_search(json!({"query": "tokio scheduling"}));
    ok_code(&r);
    let t = text(&r);
    assert!(
        t.starts_with("search \"tokio scheduling\": 5 results (1 dropped: bad URL)\n"),
        "{t}"
    );
    assert!(!t.contains('\u{1b}'), "raw ESC leaked: {t:?}");
    assert!(!t.contains('\u{200B}'), "raw zero-width leaked: {t:?}");
    assert!(!t.contains('\u{202E}'), "raw bidi leaked: {t:?}");
    // The unlisted host is shown but marked: a search never widens the
    // allowlist.
    assert!(t.contains("1. [fetchable] example.test:8080/a — "), "{t}");
    assert!(
        t.contains("2. [fetchable] example.test:8081/b — Second"),
        "{t}"
    );
    assert!(
        t.contains("3. [not on allowlist] off.test:80/c — Third off"),
        "{t}"
    );
    assert!(
        t.contains("5. [not on allowlist] off.test:80/e — Fifth off"),
        "{t}"
    );
    // Cut to 120 title / 300 snippet characters, on a char boundary.
    assert!(!t.contains(&"x".repeat(130)), "title not cut: {t:?}");
    assert!(t.contains(&"x".repeat(120)), "{t}");
    assert!(!t.contains(&"y".repeat(310)), "snippet not cut: {t:?}");
    assert!(t.contains(&"y".repeat(300)), "{t}");
    // Result six is past `max_results` (default 5) and is never shown;
    // the dropped one is counted, not rendered.
    assert!(!t.contains("Sixth"), "{t}");
    assert!(!t.contains("dropped me"), "{t}");
    // Raw JSON — including unknown fields — never reaches the context.
    assert!(!t.contains("RAW_JSON_MARKER"), "{t}");
    assert!(!t.contains("infobox"), "{t}");
}

#[test]
fn search_raw_json_never_in_output() {
    let results = json!({
        "results": [
            {"url": "http://example.test:8080/r", "title": "TITLE_MARKER", "content": "SNIP_MARKER",
             "thumbnail": "FIELD_MARKER", "publishedDate": "2026-01-01"}
        ]
    });
    let mut rig = Rig::new_search(
        "search-raw-json",
        vec![searx(results)],
        WebBudgets::default(),
        search_endpoint(),
    );
    let r = rig.call_search(json!({"query": "q"}));
    ok_code(&r);
    let t = text(&r);
    assert!(
        t.contains("TITLE_MARKER") && t.contains("SNIP_MARKER"),
        "{t}"
    );
    assert!(!t.contains("FIELD_MARKER"), "unknown field leaked: {t}");
    assert!(!t.contains("publishedDate"), "{t}");
    assert!(
        !t.contains('{'),
        "no raw JSON syntax in the observation: {t:?}"
    );
    // The URL is rendered through parse_url, not as a raw JSON string.
    assert!(
        t.contains("1. [fetchable] example.test:8080/r — TITLE_MARKER"),
        "{t}"
    );
}

#[test]
fn search_endpoint_must_be_loopback() {
    use harness_model_core::endpoint::EndpointRefused;
    let e = Endpoint::parse("http://10.0.0.5:8888").unwrap_err();
    assert!(matches!(e, EndpointRefused::NotLoopback), "{e:?}");
    let e = Endpoint::parse("http://search.example.test:80").unwrap_err();
    assert!(matches!(e, EndpointRefused::NotLoopback), "{e:?}");
    // https is refused on the same rule as the model endpoint: the
    // loopback trust base is plain http on the user's machine.
    let e = Endpoint::parse("https://127.0.0.1:8888").unwrap_err();
    assert!(matches!(e, EndpointRefused::NeedsHosted), "{e:?}");
    // `localhost` maps to loopback without a DNS lookup.
    let ok = Endpoint::parse("http://localhost:8888/searx").unwrap();
    assert_eq!(ok.port, 8888);
}

#[test]
fn search_query_journaled_in_egress() {
    let mut rig = Rig::new_search(
        "search-journal",
        vec![searx(json!({"results": [
            {"url": "http://example.test:8080/r", "title": "R", "content": "c"}
        ]}))],
        WebBudgets::default(),
        search_endpoint(),
    );
    let r = rig.call_search(json!({"query": "tokio current_thread scheduling"}));
    ok_code(&r);
    let records = rig.log.records.lock().unwrap();
    assert_eq!(records.len(), 1, "one search, one egress record");
    let rec = &records[0];
    // INV-43: the allow decision, journaled with the full request URL —
    // the query is in the journal before any byte moved.
    assert_eq!(rec.decision, harness_sandbox::egress::EgressDecision::Allow);
    assert_eq!(rec.purpose, harness_sandbox::egress::EgressPurpose::Search);
    assert_eq!(rec.mode, EgressMode::SearchEndpoint);
    assert_eq!(rec.host, "127.0.0.1");
    assert_eq!(rec.port, rig.fixture.addr.port());
    assert!(rec.resolved.is_empty(), "search endpoints are not resolved");
    assert_eq!(rec.ip, Some(IpAddr::from([127, 0, 0, 1])));
    let port = rig.fixture.addr.port();
    assert_eq!(
        rec.url,
        format!(
            "http://127.0.0.1:{port}/search?q=tokio%20current_thread%20scheduling&format=json&pageno=1&safesearch=1"
        )
    );
    let hop_no = rec.hop;
    drop(records);
    assert_eq!(accepts(&rig.fixture), 1, "the hop dialed the endpoint");
    // The ToolFinished hop record pairs with the egress entry (P-39j).
    let web = r.web.as_ref().unwrap();
    assert_eq!(web.hops.len(), 1);
    assert_eq!(web.hops[0].hop, hop_no);
    assert_eq!(web.hops[0].mode, "search-endpoint");
    assert_eq!(web.hops[0].ended, "relayed");
    assert_eq!(web.final_url, rec_url_placeholder(port));
}

fn rec_url_placeholder(port: u16) -> String {
    format!(
        "http://127.0.0.1:{port}/search?q=tokio%20current_thread%20scheduling&format=json&pageno=1&safesearch=1"
    )
}

#[test]
fn search_budget_exhausted_refused() {
    let body = json!({"results": [
        {"url": "http://example.test:8080/r", "title": "R"}
    ]});
    let budgets = WebBudgets {
        searches: 1,
        ..WebBudgets::default()
    };
    let mut rig = Rig::new_search(
        "search-budget",
        vec![searx(body.clone()), searx(body)],
        budgets,
        search_endpoint(),
    );
    let r1 = rig.call_search(json!({"query": "first"}));
    ok_code(&r1);
    let r2 = rig.call_search(json!({"query": "second"}));
    assert_eq!(err_code(&r2), code::WEB_BUDGET);
    assert!(
        text(&r2).contains("search budget exhausted"),
        "{}",
        text(&r2)
    );
    assert_eq!(accepts(&rig.fixture), 1, "the refused search opened no hop");
    assert_eq!(rig.log.len(), 1, "only the allowed search journaled egress");
}

#[test]
fn searxng_garbage_json_typed_error() {
    let mut rig = Rig::new_search(
        "search-garbage",
        vec![response(Some("application/json"), &[], b"this is not json")],
        WebBudgets::default(),
        search_endpoint(),
    );
    let r = rig.call_search(json!({"query": "x"}));
    assert_eq!(err_code(&r), code::WEB_SEARCH_PARSE);
    // A non-200 answer is the same typed refusal, not a parse crash.
    let mut rig2 = Rig::new_search(
        "search-502",
        vec![
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ],
        WebBudgets::default(),
        search_endpoint(),
    );
    let r2 = rig2.call_search(json!({"query": "x"}));
    assert_eq!(err_code(&r2), code::WEB_SEARCH_PARSE);
    assert!(text(&r2).contains("502"), "{}", text(&r2));
    // JSON without a results array is refused the same way (raw body, so
    // the test helper cannot add one).
    let mut rig3 = Rig::new_search(
        "search-no-results",
        vec![response(Some("application/json"), &[], br#"{"query":"x"}"#)],
        WebBudgets::default(),
        search_endpoint(),
    );
    let r3 = rig3.call_search(json!({"query": "x"}));
    assert_eq!(err_code(&r3), code::WEB_SEARCH_PARSE);
}

#[test]
fn javascript_url_result_dropped_and_counted() {
    let body = json!({"results": [
        {"url": "javascript:alert(1)", "title": "Evil", "content": "pwn"},
        {"url": "http://example.test:8080/ok", "title": "Fine", "content": "fine"}
    ]});
    let mut rig = Rig::new_search(
        "search-js-url",
        vec![searx(body)],
        WebBudgets::default(),
        search_endpoint(),
    );
    let r = rig.call_search(json!({"query": "evil"}));
    ok_code(&r);
    let t = text(&r);
    assert!(t.contains("1 results (1 dropped: bad URL)"), "{t}");
    assert!(!t.contains("javascript"), "{t}");
    assert!(!t.contains("Evil"), "{t}");
    assert!(
        t.contains("1. [fetchable] example.test:8080/ok — Fine"),
        "{t}"
    );
}
