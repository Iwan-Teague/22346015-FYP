//! P-39o: the research web path in `user-proxy` mode (design §5.5).
//!
//! The pump's target is the user's own loopback forward proxy; the fetcher
//! sends an absolute-form `GET https://host/target` to it in the clear, and
//! the user's proxy does DNS, TLS and the origin IP checks. The harness
//! keeps the allowlist, the budgets and the response handling, and says in
//! the journal (`Egress.ip = delegated`) that it cannot see the address.
//!
//! The "user's proxy" here is a scripted loopback fixture that records the
//! request bytes it receives. The resolver is a trap: it counts every call
//! and answers with a PRIVATE address, so a hop that still resolved and
//! classified would be refused, and a hop that merely resolved would be
//! counted. Nothing here dials a real host.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::Cell;
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
    Call, Session, SessionKind, SessionMode, SessionSpec, UserPolicy, WebConfirmation, WebGrant,
};
use harness_sandbox::egress::{
    EgressDecision, EgressLog, EgressLogError, EgressMode, EgressRecord, HopEnded, HopIo,
    LoopbackConnector, RefuseReason, ResolveRefused, Resolver,
};
use harness_tools::builtin::code;
use harness_tools::web::{RecordedHops, RecordedResolver};
use harness_tools::{
    BoxConnector, Egress, FetcherPin, HopRun, HopRunner, InvokeCtx, RunnerError, ToolProvider,
    ToolResult, ToolStatus, WebBudgets, WebTools,
};
use serde_json::json;

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
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("web-user-proxy-{name}"));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// The trap resolver: counts calls, answers with a private address.
struct TrapResolver {
    calls: AtomicUsize,
}

impl Resolver for TrapResolver {
    fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, ResolveRefused> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![IpAddr::from([10, 0, 0, 9])])
    }
}

struct RecordingLog {
    records: Mutex<Vec<EgressRecord>>,
}

impl RecordingLog {
    fn new() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
        }
    }
    fn records(&self) -> Vec<EgressRecord> {
        self.records.lock().unwrap().clone()
    }
}

impl EgressLog for RecordingLog {
    fn append(&self, record: &EgressRecord) -> Result<(), EgressLogError> {
        self.records.lock().unwrap().push(record.clone());
        Ok(())
    }
}

/// The fetcher library run in process against the pump (the design's
/// dev-dependency carve-out), no debug output.
struct InProcessHopRunner;

impl HopRunner for InProcessHopRunner {
    fn run(&mut self, run: &HopRun<'_>) -> Result<Vec<u8>, RunnerError> {
        let bytes = fs::read(run.req_path).map_err(|e| RunnerError::Io(e.to_string()))?;
        let req =
            harness_fetch::read_request(&bytes).map_err(|e| RunnerError::Io(e.to_string()))?;
        let mut sock = TcpStream::connect(("127.0.0.1", run.proxy_port))
            .map_err(|e| RunnerError::Io(e.to_string()))?;
        let frame = harness_fetch::fetch_over(&mut sock, &req);
        Ok(harness_fetch::encode_frame(&frame))
    }
}

/// The user's proxy: one scripted response per connection; keeps what it
/// was asked, byte for byte.
struct UserProxyFixture {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
}

fn user_proxy(responses: Vec<Vec<u8>>) -> UserProxyFixture {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let script = Arc::new(Mutex::new(std::collections::VecDeque::from(responses)));
    let (a2, r2) = (accepts.clone(), requests.clone());
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut sock) = conn else { break };
            a2.fetch_add(1, Ordering::SeqCst);
            let _ = sock.set_read_timeout(Some(Duration::from_millis(1500)));
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match sock.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&buf[..n]),
                }
            }
            r2.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&head).into_owned());
            let Some(resp) = script.lock().unwrap().pop_front() else {
                break;
            };
            let _ = sock.write_all(&resp);
            let _ = sock.flush();
            let _ = sock.shutdown(Shutdown::Write);
            let _ = sock.set_read_timeout(Some(Duration::from_millis(300)));
            while matches!(sock.read(&mut buf), Ok(n) if n > 0) {}
        }
    });
    UserProxyFixture {
        addr,
        accepts,
        requests,
    }
}

fn response(body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn redirect(location: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn pinned_fetcher(dir: &Path) -> FetcherPin {
    let p = dir.join("fetcher-stand-in");
    let bytes = b"rustyharness-fetch stand-in for in-process tests\n";
    fs::write(&p, bytes).unwrap();
    FetcherPin {
        path: p,
        sha256: harness_core::sha256(bytes),
    }
}

fn registry() -> Registry {
    let ctx = ValidationContext::new(
        SemVer {
            major: 0,
            minor: 0,
            patch: 1,
        },
        &[],
    )
    .unwrap();
    Registry::admit(vec![(
        builtin::research_manifest(&ctx).unwrap(),
        Tier::Builtin,
    )])
    .unwrap()
}

fn session(allowlist: &[&str]) -> Session {
    Session::plan(
        &SessionSpec {
            grants: vec!["harness.web.fetch".to_string()],
            workspace: None,
            approver_present: false,
            personal_data_granted: false,
            conformed: false,
            exec_programs: Vec::new(),
            lan_ports: Vec::new(),
            read_window: None,
            kind: SessionKind::Research(WebGrant {
                allowlist: allowlist.iter().map(|s| (*s).to_owned()).collect(),
                search: false,
                confirmed: Some(WebConfirmation::Flag),
                user_proxy: true,
            }),
            mode: SessionMode::Build,
        },
        &registry(),
        &UserPolicy::default(),
    )
    .unwrap()
}

fn endpoint_of(addr: SocketAddr) -> Endpoint {
    Endpoint::parse(&format!("http://127.0.0.1:{}", addr.port())).unwrap()
}

struct Rig<'a> {
    w: JournalWriter<FaultFile, MemBlobs, Tick>,
    s: Session,
    step: u64,
    t: WebTools<'a>,
    log: Arc<RecordingLog>,
    resolver: Arc<TrapResolver>,
    proxy: UserProxyFixture,
}

impl Rig<'_> {
    /// `session_list` is what POLICY lets through; `tool_list` is what the
    /// provider's own allowlist holds (they differ only in the test that
    /// aims at the provider's own defence).
    fn new(name: &str, responses: Vec<Vec<u8>>, session_list: &[&str], tool_list: &[&str]) -> Self {
        let proxy = user_proxy(responses);
        let dir = scratch(name);
        let resolver = Arc::new(TrapResolver {
            calls: AtomicUsize::new(0),
        });
        let t = WebTools::new_with_runner(
            &dir,
            Allowlist::load(
                &tool_list
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
            WebBudgets::default(),
            pinned_fetcher(&dir),
            None,
            Box::new(InProcessHopRunner),
            Egress {
                // Deliberately the WRONG door and the WRONG connector: the
                // user-proxy switch must override both.
                mode: EgressMode::SearchEndpoint,
                resolver: resolver.clone(),
                connector: BoxConnector::new(Arc::new(NeverDial)),
            },
        )
        .unwrap()
        .with_user_proxy(&endpoint_of(proxy.addr));
        let w = JournalWriter::start(
            FaultFile::new(FaultPlan::default()),
            MemBlobs::default(),
            Tick(Cell::new(0)),
            RunId::new(1, [0; 10]),
            1,
            Header::new(Ident::of("0.0.1").unwrap()),
        )
        .unwrap();
        Self {
            w,
            s: session(session_list),
            step: 0,
            t,
            log: Arc::new(RecordingLog::new()),
            resolver,
            proxy,
        }
    }

    fn call(&mut self, url: &str) -> ToolResult {
        self.step += 1;
        let a = self
            .s
            .authorize(Call {
                capability: "harness.web.fetch".to_string(),
                args: json!({ "url": url }),
            })
            .expect("policy allows the call");
        let j = self
            .w
            .append_intent(self.step, Event::new(EventKind::ToolStarted), a)
            .unwrap();
        self.t
            .invoke(
                j,
                &InvokeCtx {
                    step: self.step,
                    deadline: Instant::now() + Duration::from_secs(30),
                    reads: &harness_tools::ReadLog::default(),
                    egress: Some(self.log.as_ref()),
                    bg_ports: &[],
                },
            )
            .unwrap()
    }

    fn accepts(&self) -> usize {
        self.proxy.accepts.load(Ordering::SeqCst)
    }
}

/// A connector that must never be used: `with_user_proxy` replaces it.
struct NeverDial;

impl harness_sandbox::egress::Connector for NeverDial {
    fn connect(&self, _addr: SocketAddr) -> std::io::Result<TcpStream> {
        Err(std::io::Error::other("the injected connector was used"))
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

const LIST: &[&str] = &["docs.example.org", "other.example.org"];

/// The fetch goes to the user's proxy as an absolute-form https request;
/// the allowlisted https host is fetched with no TLS in the harness.
#[test]
fn user_proxy_fetch_sends_absolute_form_and_records_delegated_egress() {
    let mut rig = Rig::new("shape", vec![response(b"hello from origin")], LIST, LIST);
    let r = rig.call("https://docs.example.org/guide?x=1");
    assert_eq!(r.status, ToolStatus::Ok, "{}", text(&r));
    assert!(text(&r).contains("hello from origin"));

    // The proxy saw exactly one request, in absolute form, https scheme.
    let reqs = rig.proxy.requests.lock().unwrap().clone();
    assert_eq!(reqs.len(), 1, "{reqs:?}");
    assert!(
        reqs[0].starts_with("GET https://docs.example.org/guide?x=1 HTTP/1.1\r\n"),
        "{}",
        reqs[0]
    );
    assert!(
        reqs[0].contains("\r\nHost: docs.example.org\r\n"),
        "{}",
        reqs[0]
    );
    assert!(!reqs[0].contains("CONNECT"), "{}", reqs[0]);

    // The journal side: delegated, never an address; no DNS at all (the
    // trap resolver would have refused the private answer and counted).
    assert_eq!(rig.resolver.calls.load(Ordering::SeqCst), 0);
    let recs = rig.log.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].decision, EgressDecision::Allow);
    assert_eq!(recs[0].mode, EgressMode::UserProxy);
    assert!(recs[0].delegated);
    assert_eq!(recs[0].ip, None);
    assert!(recs[0].resolved.is_empty());
    assert_eq!(recs[0].host, "docs.example.org");
    assert_eq!(recs[0].port, 443);

    // The tool record names the mode and carries no address.
    let web = r.web.as_ref().unwrap();
    assert_eq!(web.hops[0].mode, "user-proxy");
    assert_eq!(web.hops[0].ip, None);
    assert_eq!(web.hops[0].ended, "relayed");
}

/// P-39o `allowlist_still_enforced_in_user_proxy_mode`: delegating the IP
/// checks does not widen WHO may be fetched. Three layers, each aimed
/// separately: policy at authorize, the provider's own check on the first
/// URL, and the per-hop check on a redirect target. In every case the user's
/// proxy is asked for nothing it must not be.
#[test]
fn allowlist_still_enforced_in_user_proxy_mode() {
    // 1. Policy: an off-list host never reaches the provider.
    let rig = Rig::new("al-policy", vec![response(b"unused")], LIST, LIST);
    let e = rig
        .s
        .authorize(Call {
            capability: "harness.web.fetch".into(),
            args: json!({"url": "https://evil.example.net/"}),
        })
        .expect_err("policy refuses an off-list host");
    let _ = e;
    assert_eq!(rig.accepts(), 0);
    assert!(rig.log.records().is_empty());

    // 2. The provider's own check: policy lets the host through (a wider
    // session list), the provider's allowlist does not.
    let mut rig = Rig::new(
        "al-provider",
        vec![response(b"unused")],
        &["docs.example.org", "wider.example.org"],
        &["docs.example.org"],
    );
    let r = rig.call("https://wider.example.org/");
    assert_eq!(err_code(&r), code::WEB_URL_REFUSED, "{}", text(&r));
    assert_eq!(rig.accepts(), 0, "the proxy was never asked");
    assert!(rig.log.records().is_empty(), "no hop, no Egress record");

    // 3. A redirect off the list: the first hop goes to the proxy, the
    // second is refused (and journalled) before any request for it.
    let mut rig = Rig::new(
        "al-redirect",
        vec![redirect("https://evil.example.net/landing"), response(b"x")],
        LIST,
        LIST,
    );
    let r = rig.call("https://docs.example.org/out");
    assert_eq!(err_code(&r), code::WEB_URL_REFUSED, "{}", text(&r));
    assert_eq!(rig.accepts(), 1, "only the first hop reached the proxy");
    let recs = rig.log.records();
    assert_eq!(recs.len(), 2, "{recs:?}");
    assert_eq!(recs[0].decision, EgressDecision::Allow);
    assert!(recs[0].delegated);
    assert_eq!(
        recs[1].decision,
        EgressDecision::Refuse(RefuseReason::HostNotAllowlisted)
    );
}

/// The proxy is dialled through the loopback connector only: whatever
/// connector the caller injected is dropped (here one that fails on use),
/// and the pump target is the configured proxy, not the origin.
#[test]
fn user_proxy_pump_dials_only_the_configured_proxy() {
    let mut rig = Rig::new("dial", vec![response(b"ok")], LIST, LIST);
    let r = rig.call("https://docs.example.org/");
    assert_eq!(r.status, ToolStatus::Ok, "{}", text(&r));
    assert_eq!(rig.accepts(), 1);
}

/// P-39o `user_proxy_session_audits_clean`: the offline audit's replay
/// recomputes a live user-proxy fetch byte for byte — the tool record, the
/// hop digests and the `Egress` record (delegated, no address) — from the
/// re-fed frame and pump outcome alone: no socket is bound, the proxy is
/// not asked again, and nothing is resolved.
#[test]
fn user_proxy_session_audits_clean() {
    let mut rig = Rig::new(
        "audit",
        vec![response(b"audited page body")],
        &["docs.example.org"],
        &["docs.example.org"],
    );
    let r = rig.call("https://docs.example.org/page");
    assert_eq!(r.status, ToolStatus::Ok, "{}", text(&r));
    let live = r.web.clone().unwrap();
    let live_records = rig.log.records();
    assert_eq!(live_records.len(), 1);
    assert!(live_records[0].delegated);
    let hop0 = &live.hops[0];
    let accepts_after_live = rig.accepts();

    let hops = RecordedHops::new();
    hops.push(
        hop0.frame.clone().expect("the live hop carries its frame"),
        HopIo {
            // A delegated hop records no resolver answer; the pump's
            // `chosen` is the proxy.
            resolved: Vec::new(),
            chosen: IpAddr::from([127, 0, 0, 1]),
            bytes_up: hop0.bytes_up,
            bytes_down: hop0.bytes_down,
            elapsed: Duration::from_millis(hop0.elapsed_ms),
            ended: HopEnded::Relayed,
        },
    );
    let replay_dir = scratch("audit-replay");
    let replay_log = Arc::new(RecordingLog::new());
    let recorded_resolver = RecordedResolver::new();
    let mut t = WebTools::new_replaying(
        &replay_dir,
        Allowlist::load(&["docs.example.org".to_owned()]).unwrap(),
        WebBudgets::default(),
        None,
        Arc::new(hops),
        Egress {
            mode: EgressMode::UserProxy,
            // Nothing recorded: a replay that resolved would fail.
            resolver: Arc::new(recorded_resolver),
            connector: BoxConnector::new(Arc::new(LoopbackConnector)),
        },
    )
    .unwrap()
    .with_user_proxy(&endpoint_of(rig.proxy.addr));

    let s = session(&["docs.example.org"]);
    let mut w = JournalWriter::start(
        FaultFile::new(FaultPlan::default()),
        MemBlobs::default(),
        Tick(Cell::new(0)),
        RunId::new(2, [0; 10]),
        1,
        Header::new(Ident::of("0.0.1").unwrap()),
    )
    .unwrap();
    let a = s
        .authorize(Call {
            capability: "harness.web.fetch".to_string(),
            args: json!({"url": "https://docs.example.org/page"}),
        })
        .unwrap();
    let j = w
        .append_intent(1, Event::new(EventKind::ToolStarted), a)
        .unwrap();
    let replay = t
        .invoke(
            j,
            &InvokeCtx {
                step: 1,
                deadline: Instant::now() + Duration::from_secs(30),
                reads: &harness_tools::ReadLog::default(),
                egress: Some(replay_log.as_ref()),
                bg_ports: &[],
            },
        )
        .unwrap();
    assert_eq!(replay.status, ToolStatus::Ok, "{}", text(&replay));
    assert_eq!(
        replay.web.as_ref().unwrap(),
        &live,
        "tool record recomputed"
    );
    assert_eq!(replay_log.records(), live_records, "Egress recomputed");
    assert_eq!(
        rig.accepts(),
        accepts_after_live,
        "the replay bound nothing"
    );
    assert_eq!(rig.resolver.calls.load(Ordering::SeqCst), 0);
}
