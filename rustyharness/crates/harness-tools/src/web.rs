//! The web tools (`harness.web.fetch` P-39g, `harness.web.search` P-39h)
//! through the confined fetcher, per the airlock design (§3-§5 and §8 of
//! `docs/01-design-v0.1.md` and `docs/slices/P-39-web-airlock.md` §11).
//!
//! The provider never touches the network itself. Every hop goes:
//!
//! 1. `open_hop` ([`harness_sandbox::egress`]) — DNS resolved once, the
//!    answer classified, the decision journaled through
//!    [`InvokeCtx::egress`] **before any byte moves** (§4.5, INV-43) — and
//!    a loopback relay bound;
//! 2. the hop's `req.json` written under `<scratch>/web/<step>-<hop>/`;
//! 3. the pinned fetcher binary spawned through [`Confinement`] with
//!    `Network::Proxy { port }` (§5.3): it may talk to nothing but the
//!    relay, and only with the hop's bearer token;
//! 4. the frame parsed ([`harness_core::fetch_frame::parse_frame`]) and
//!    verdict-ed (content type, charset, binary sniff, INV-47);
//! 5. redirects re-checked per hop (P-39a: scheme downgrades and
//!    non-allowlisted hosts refused, at most 5).
//!
//! The fetched text is [`Untrusted`] with [`Source::Web`] and terminal
//! sanitized (P-44); the observation is a bounded line window of it. A
//! fetched page is cached for the provider's lifetime, so a later window
//! on the same URL is served with no egress at all. Budgets (§4.4): at
//! most 20 fetches and 32 MiB down per session, one hop's wall clock per
//! hop, at most 5 redirects per call.
//!
//! Search (§8, P-39h) rides the same one relay per hop: the endpoint is a
//! SearXNG-compatible server the user runs on loopback (parsed with the
//! same rule as the model endpoint, `harness_model_core::endpoint`), the
//! hop is opened in `search-endpoint` mode — no resolution, the pump dials
//! the loopback address directly — and the fetcher asks it for
//! `GET /search?q=…&format=json`. The raw JSON is a blob for audit only;
//! the observation is rebuilt in process from `results[]`, each URL
//! re-checked through `parse_url`, titles and snippets cut and sanitized,
//! each entry marked fetchable or not. A search never widens the
//! allowlist.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use harness_core::display::{sanitize_for_terminal_bounded, DisplayMode};
use harness_core::html::{self, ExtractLimits};
use harness_core::{sha256, Digest, Sha256Stream, Source, Untrusted};
use harness_journal::Journaled;
use harness_manifest::ProviderName;
use harness_model_core::endpoint::{Endpoint, LoopbackHost};
use harness_policy::web::{
    parse_url, query_clean, resolve_location, Allowlist, WebUrl, MAX_URL_BYTES,
};
use harness_policy::{Authorized, Call, WEB_FETCH_ID, WEB_SEARCH_ID};
use harness_sandbox::egress::{
    open_hop, Connector, EgressDecision, EgressLog, EgressMode, EgressPurpose, EgressRecord,
    HopBudgets, HopRefused, HopRequest, LoopbackConnector, RefuseReason, Resolver,
};
use harness_sandbox::{ChildStatus, ConfinedSpec, Confinement, Conformed, Limits, Network};
use serde_json::{json, Value};

use crate::builtin::{code, refused};
use crate::provider::{InvokeCtx, RefusalKind, ToolError, ToolProvider, ToolResult, ToolStatus};

/// Redirects followed per fetch, at most (§4.4).
pub const MAX_REDIRECTS: u32 = 5;

/// Hop attempts per fetch: the first response plus one per redirect.
const MAX_HOPS: usize = 1 + MAX_REDIRECTS as usize;

/// A declared-text body with a NUL in its first [`SNIFF_BYTES`] is binary
/// and refused (§11).
const SNIFF_BYTES: usize = 8 * 1024;

/// The observation a fetch returns, in bytes (§4.4: at most the read
/// window, 12 KiB here).
pub const OBSERVATION_MAX_BYTES: usize = 12 * 1024;

/// Line-window bounds on the observation (§11, the manifest schema).
pub const MAX_LINES: u64 = 400;
/// Lines served when the call does not ask for a window.
pub const DEFAULT_LINES: u64 = 200;

/// The text kept from one page, in bytes (P-44's extract cap).
pub const TEXT_MAX_BYTES: usize = 256 * 1024;

/// The body one fetch keeps, in bytes (§4.4: 2 MiB per hop).
pub const BODY_MAX_BYTES: u64 = 2 * 1024 * 1024;

/// Fetches per provider (session) by default (§4.4).
pub const DEFAULT_FETCHES: u32 = 20;

/// Bytes down per provider (session) by default (§4.4).
pub const DEFAULT_BYTES_DOWN: u64 = 32 * 1024 * 1024;

/// Searches per provider (session) by default (§4.4).
pub const DEFAULT_SEARCHES: u32 = 10;

/// Searches per provider (session), at most (§4.4).
pub const MAX_SEARCHES: u32 = 100;

/// The search endpoint's JSON body, in bytes (§8: 512 KiB).
pub const SEARCH_BODY_MAX_BYTES: u64 = 512 * 1024;

/// Characters kept from one result title (§8).
pub const SEARCH_TITLE_MAX_CHARS: usize = 120;

/// Characters kept from one result snippet (§8).
pub const SEARCH_SNIPPET_MAX_CHARS: usize = 300;

/// Results shown when the call does not ask for a count (§4.4).
pub const DEFAULT_SEARCH_RESULTS: u64 = 5;

/// Results shown per search, at most (§4.4).
pub const MAX_SEARCH_RESULTS: u64 = 10;

/// The content types a response may carry (§11). Anything else — PDFs,
/// images, `application/octet-stream` — is refused, never downloaded into
/// the context.
const ALLOWED_TYPES: [&str; 5] = [
    "text/html",
    "application/xhtml+xml",
    "text/plain",
    "text/markdown",
    "application/json",
];

/// The charsets a response may declare (§11). `iso-8859-1` is decoded as
/// `windows-1252` (its superset in practice); anything else is refused.
const ALLOWED_CHARSETS: [&str; 4] = ["utf-8", "us-ascii", "iso-8859-1", "windows-1252"];

/// Why a [`WebTools`] could not even be built. Nothing ran.
#[derive(Debug, thiserror::Error)]
pub enum WebSetupError {
    /// The scratch directory could not be prepared.
    #[error("scratch dir: {0}")]
    Scratch(String),
    /// The pinned fetcher is missing or unreadable.
    #[error("fetcher: {0}")]
    Fetcher(String),
    /// The fetcher on disk does not match its pinned SHA-256 (INV-46):
    /// build artifact swapped under the pin.
    #[error("fetcher digest mismatch: pinned {expected}, found {actual}")]
    Digest {
        /// The digest the configuration pinned.
        expected: Digest,
        /// The digest the file on disk hashes to.
        actual: Digest,
    },
    /// The hop budgets are out of range.
    #[error("budgets: {0}")]
    Budgets(String),
    /// The sandbox witness does not cover the web airlock cases (INV-46).
    #[error("the sandbox witness does not cover the web airlock cases")]
    NoConformed,
}

/// The pinned fetcher (§5.1): its path and the SHA-256 its bytes must
/// hash to, both from the user's configuration and checked at provider
/// construction.
#[derive(Debug, Clone)]
pub struct FetcherPin {
    /// Where the fetcher binary lives.
    pub path: PathBuf,
    /// The digest its bytes must have.
    pub sha256: Digest,
}

/// Egress plumbing for hops: how hops resolve, and through what they
/// connect. Production wiring is the user proxy; tests inject fakes.
pub struct Egress {
    /// The mode every hop is journaled with.
    pub mode: EgressMode,
    /// Name resolution for hop hosts.
    pub resolver: Arc<dyn Resolver>,
    /// The connector hops dial through.
    pub connector: BoxConnector,
}

/// A shared, owned [`Connector`]: `open_hop` takes its connector by
/// value, and the provider opens many hops over one connector. The inner
/// connector must be `Send + Sync` (its `connect` runs on the relay's
/// thread); the sandbox's own connectors all are.
#[derive(Clone)]
pub struct BoxConnector(Arc<dyn Connector + Send + Sync>);

impl BoxConnector {
    /// Wrap a connector for reuse across hops.
    pub fn new(inner: Arc<dyn Connector + Send + Sync>) -> Self {
        Self(inner)
    }
}

impl Connector for BoxConnector {
    fn connect(&self, addr: std::net::SocketAddr) -> io::Result<std::net::TcpStream> {
        self.0.connect(addr)
    }
}

impl std::fmt::Debug for BoxConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BoxConnector")
    }
}

/// Per-session web budgets (§4.4). One hop's budgets ride along in
/// [`WebBudgets::hop`].
#[derive(Debug, Clone)]
pub struct WebBudgets {
    /// Fetches per session (cache hits do not count).
    pub fetches: u32,
    /// Searches per session (P-39h).
    pub searches: u32,
    /// Bytes down per session, across every hop.
    pub bytes_down: u64,
    /// The body one fetch keeps; the fetcher truncates over this.
    pub body_max_bytes: u64,
    /// Per-hop wall clock and relay byte cap.
    pub hop: HopBudgets,
}

impl Default for WebBudgets {
    fn default() -> Self {
        Self {
            fetches: DEFAULT_FETCHES,
            searches: DEFAULT_SEARCHES,
            bytes_down: DEFAULT_BYTES_DOWN,
            body_max_bytes: BODY_MAX_BYTES,
            hop: HopBudgets::default(),
        }
    }
}

/// One hop of one fetch, as `ToolFinished` reports it (§4.5): what the
/// egress journal's `Egress` entry for this hop pairs with (INV-43; the
/// pairing is P-39j). Measured fields first, derived after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebHop {
    /// The hop index, session-wide, matching its `Egress` entry.
    pub hop: u64,
    /// The URL this hop asked for.
    pub url: String,
    /// The response status, when the fetcher got one.
    pub status: Option<u16>,
    /// The declared content type, verbatim.
    pub content_type: Option<String>,
    /// Bytes of body kept.
    pub body_len: u64,
    /// SHA-256 of the body kept.
    pub body_sha256: Digest,
    /// The fetcher cut the body at the body cap.
    pub truncated: bool,
    /// Bytes sent up the relay (request + CONNECT).
    pub bytes_up: u64,
    /// Bytes read down the relay.
    pub bytes_down: u64,
    /// Wall time of the hop, in milliseconds.
    pub elapsed_ms: u64,
    /// How the relayed connection ended (`HopEnded::as_str`).
    pub ended: &'static str,
    /// The egress mode (`EgressMode::as_str`).
    pub mode: &'static str,
    /// The address the hop connected to.
    pub ip: Option<std::net::IpAddr>,
    /// The `Location` the response named, when it did.
    pub location: Option<String>,
}

/// What one web call produced, beyond its observation (§4.5): the hops it
/// made and the digest of the text it kept. The run journals this with
/// `ToolFinished`; audit pairs it with the `Egress` entries (P-39j).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebRecord {
    /// One entry per hop actually opened, in order.
    pub hops: Vec<WebHop>,
    /// The URL the call ended on (after redirects).
    pub final_url: String,
    /// SHA-256 of the page text the call kept (the extraction, not the
    /// wire body).
    pub text_sha256: Digest,
    /// The observation came from the session cache, with no egress.
    pub cached: bool,
}

/// A page kept for the provider's lifetime, so a later window on the same
/// URL is served with no egress (§4.4).
struct CachedPage {
    text: String,
    text_sha256: Digest,
    status: u16,
    content_type: String,
    body_len: u64,
    body_sha256: Digest,
    body_truncated: bool,
}

/// Session state: the cache and the running budgets.
#[derive(Default)]
struct Session {
    cache: BTreeMap<String, CachedPage>,
    fetches: u32,
    searches: u32,
    bytes_down: u64,
    next_hop: u64,
}

/// The pinned fetcher, run one hop at a time.
///
/// The provider hands the runner a written `req.json`, the relay port and
/// the hop's limits; the runner returns the fetcher's framed response.
/// Production runs the binary through the sandbox
/// ([`ConfinedHopRunner`]); tests run the fetcher in process.
pub trait HopRunner {
    /// Run one hop: `req.json` is at `run.req_path`, the relay listens on
    /// `run.proxy_port`. Returns the frame bytes.
    fn run(&mut self, run: &HopRun<'_>) -> Result<Vec<u8>, RunnerError>;
}

/// One hop handed to a [`HopRunner`].
pub struct HopRun<'a> {
    /// The written request file (`rh-fetch/1` JSON).
    pub req_path: &'a Path,
    /// The hop's scratch directory (the fetcher's working directory).
    pub hop_dir: &'a Path,
    /// The port the egress relay bound for this hop.
    pub proxy_port: u16,
    /// The hop's wall clock.
    pub wall: Duration,
    /// The most stdout the fetcher may keep.
    pub output_bytes: u64,
}

/// Why a hop's fetcher run failed.
#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    /// The sandbox refused the spec or could not start: nothing ran.
    #[error("could not start the fetcher: {0}")]
    Spawn(String),
    /// The fetcher ended without a clean exit.
    #[error("the fetcher ended badly: {0:?}")]
    Status(ChildStatus),
    /// Reading the fetcher's frame failed.
    #[error("reading the fetcher's frame failed: {0}")]
    Io(String),
}

/// Runs the pinned fetcher binary through [`Confinement`] (§5.3): the
/// fetcher may read only its own binary directory and this hop's scratch
/// directory, may write nothing, and may connect only to the hop's loopback
/// relay port. Building it demands a witness that covers the airlock cases
/// (INV-46): this is the path bytes actually move on, so it refuses at the
/// earliest point rather than mid-hop.
pub struct ConfinedHopRunner<'a> {
    confinement: &'a dyn Confinement,
    witness: Conformed,
    fetcher: PathBuf,
    fetcher_dir: PathBuf,
}

impl<'a> ConfinedHopRunner<'a> {
    /// Pin the runner to a confinement, the run's witness and the
    /// (digest-verified) fetcher path. Refuses a witness that does not
    /// cover [`harness_sandbox::conformance::AIRLOCK_CASES`].
    pub fn new(
        confinement: &'a dyn Confinement,
        witness: Conformed,
        fetcher: PathBuf,
    ) -> Result<Self, WebSetupError> {
        witness
            .covers(harness_sandbox::conformance::AIRLOCK_CASES)
            .map_err(|_| WebSetupError::NoConformed)?;
        let io = |e: io::Error| WebSetupError::Fetcher(e.to_string());
        let fetcher_dir = fs::canonicalize(
            fetcher
                .parent()
                .ok_or_else(|| WebSetupError::Fetcher("fetcher path has no parent".into()))?,
        )
        .map_err(io)?;
        Ok(Self {
            confinement,
            witness,
            fetcher,
            fetcher_dir,
        })
    }
}

impl HopRunner for ConfinedHopRunner<'_> {
    fn run(&mut self, run: &HopRun<'_>) -> Result<Vec<u8>, RunnerError> {
        // §5.3: the fetcher reads its binary directory and the hop
        // directory, writes nothing (`file_size: 0` is inexpressible in
        // [`Limits`], so the empty `read_write` list carries the intent),
        // and dials only the hop's loopback relay.
        let spec = ConfinedSpec {
            argv: vec![
                self.fetcher.clone().into_os_string(),
                run.req_path.as_os_str().to_os_string(),
            ],
            cwd: run.hop_dir.to_path_buf(),
            env: Vec::new(),
            read_only: vec![self.fetcher_dir.clone(), run.hop_dir.to_path_buf()],
            read_write: Vec::new(),
            protected: Vec::new(),
            network: Network::Proxy {
                port: run.proxy_port,
            },
            limits: Limits {
                wall: run.wall,
                cpu: Some(run.wall),
                file_size: None,
                memory: Some(256 * 1024 * 1024),
                processes: Some(4),
                output_bytes: run.output_bytes,
            },
        };
        let child = self
            .confinement
            .spawn(&spec, &self.witness)
            .map_err(|e| RunnerError::Spawn(e.to_string()))?;
        let exit = child.wait();
        if exit.status != ChildStatus::Exited(0) {
            return Err(RunnerError::Status(exit.status));
        }
        if exit.stdout_truncated {
            return Err(RunnerError::Io("frame over the output cap".into()));
        }
        Ok(exit.stdout)
    }
}

/// The built-in web tools (§3, §8; P-39g, P-39h): `harness.web.fetch`
/// and `harness.web.search`.
pub struct WebTools<'a> {
    ns: ProviderName,
    web_dir: PathBuf,
    allowlist: Allowlist,
    budgets: WebBudgets,
    search_endpoint: Option<Endpoint>,
    egress: Egress,
    runner: Box<dyn HopRunner + 'a>,
    session: Session,
}

impl<'a> WebTools<'a> {
    /// Build the provider: prepare `<scratch>/web`, verify the fetcher's
    /// digest against its pin, validate the budgets and build the default
    /// confined hop runner — which demands a witness covering the airlock
    /// cases (INV-46, checked at the earliest point of the byte-moving
    /// path). Tests bypass the confined path via
    /// [`WebTools::new_with_runner`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scratch: &Path,
        allowlist: Allowlist,
        budgets: WebBudgets,
        fetcher: FetcherPin,
        search: Option<Endpoint>,
        confinement: &'a dyn Confinement,
        witness: Conformed,
        egress: Egress,
    ) -> Result<Self, WebSetupError> {
        let io = |e: io::Error| WebSetupError::Scratch(e.to_string());
        let web_dir = scratch.join("web");
        make_dir(&web_dir).map_err(io)?;
        let web_dir = fs::canonicalize(&web_dir).map_err(io)?;
        let runner = Box::new(ConfinedHopRunner::new(
            confinement,
            witness,
            fetcher.path.clone(),
        )?);
        Self::assemble(web_dir, allowlist, budgets, fetcher, search, egress, runner)
    }

    /// Build the provider with an explicit hop runner: every check of
    /// [`WebTools::new`] except the witness one, which is the runner's
    /// duty (INV-46 lives where the bytes move). The in-process runner is
    /// a test-only seam; production wiring uses [`WebTools::new`].
    pub fn new_with_runner(
        scratch: &Path,
        allowlist: Allowlist,
        budgets: WebBudgets,
        fetcher: FetcherPin,
        search: Option<Endpoint>,
        runner: Box<dyn HopRunner + 'a>,
        egress: Egress,
    ) -> Result<Self, WebSetupError> {
        let io = |e: io::Error| WebSetupError::Scratch(e.to_string());
        let web_dir = scratch.join("web");
        make_dir(&web_dir).map_err(io)?;
        let web_dir = fs::canonicalize(&web_dir).map_err(io)?;
        Self::assemble(web_dir, allowlist, budgets, fetcher, search, egress, runner)
    }

    /// Shared tail of the constructors: budgets and the fetcher pin are
    /// checked, then the provider is assembled around the given runner.
    fn assemble<'b>(
        web_dir: PathBuf,
        allowlist: Allowlist,
        budgets: WebBudgets,
        fetcher: FetcherPin,
        search: Option<Endpoint>,
        egress: Egress,
        runner: Box<dyn HopRunner + 'b>,
    ) -> Result<WebTools<'b>, WebSetupError> {
        let ns = ProviderName::new(harness_manifest::BUILTIN_NAMESPACE)
            .map_err(|_| WebSetupError::Scratch("namespace".into()))?;
        if budgets.body_max_bytes == 0 || budgets.body_max_bytes > BODY_MAX_BYTES {
            return Err(WebSetupError::Budgets(
                "body cap must be in [1, 2 MiB]".into(),
            ));
        }
        if budgets.searches == 0 || budgets.searches > MAX_SEARCHES {
            return Err(WebSetupError::Budgets(format!(
                "searches must be in [1, {MAX_SEARCHES}]"
            )));
        }
        HopBudgets::new(budgets.hop.wall(), budgets.hop.relay_cap_bytes())
            .map_err(|e| WebSetupError::Budgets(e.to_string()))?;
        let actual =
            file_sha256(&fetcher.path).map_err(|e| WebSetupError::Fetcher(e.to_string()))?;
        if actual != fetcher.sha256 {
            return Err(WebSetupError::Digest {
                expected: fetcher.sha256,
                actual,
            });
        }
        Ok(WebTools {
            ns,
            web_dir,
            allowlist,
            budgets,
            search_endpoint: search,
            egress,
            runner,
            session: Session::default(),
        })
    }

    /// Swap the hop runner (tests run the fetcher in process).
    #[must_use]
    pub fn with_runner(mut self, runner: Box<dyn HopRunner + 'a>) -> Self {
        self.runner = runner;
        self
    }
}

impl ToolProvider for WebTools<'_> {
    fn namespace(&self) -> &ProviderName {
        &self.ns
    }

    fn serves(&self, capability: &str) -> bool {
        capability == WEB_FETCH_ID || capability == WEB_SEARCH_ID
    }

    fn invoke(
        &mut self,
        call: Journaled<Authorized<Call>>,
        ctx: &InvokeCtx<'_>,
    ) -> Result<ToolResult, ToolError> {
        let c = call.call().call();
        let cap = c.capability.as_str();
        if cap != WEB_FETCH_ID && cap != WEB_SEARCH_ID {
            return Ok(refused(cap, RefusalKind::UnknownCapability));
        }
        if Instant::now() >= ctx.deadline {
            return Ok(refused(cap, RefusalKind::DeadlinePassed));
        }
        // No egress log, no web: the run granted none (INV-43). Nothing
        // else may run first — not even the URL parse. Airlock witness
        // coverage is enforced where bytes move, in [`ConfinedHopRunner`].
        let Some(log) = ctx.egress else {
            return Ok(self.fail(
                code::WEB_EGRESS,
                "web egress is not wired into this session",
                raw_url(&c.args),
                Vec::new(),
            ));
        };
        if cap == WEB_SEARCH_ID {
            return self.search(&c.args, log, ctx.deadline);
        }
        let Some(raw) = c.args.get("url").and_then(Value::as_str) else {
            return Ok(self.fail(
                code::BAD_ARGS,
                "url must be a string",
                raw_url(&c.args),
                Vec::new(),
            ));
        };
        if raw.len() > MAX_URL_BYTES {
            return Ok(self.fail(
                code::BAD_ARGS,
                "url is too long",
                raw.to_owned(),
                Vec::new(),
            ));
        }
        let Some(start) = window_start(&c.args) else {
            return Ok(self.fail(
                code::BAD_ARGS,
                "start must be an integer >= 1",
                raw.to_owned(),
                Vec::new(),
            ));
        };
        let Some(lines) = window_lines(&c.args) else {
            return Ok(self.fail(
                code::BAD_ARGS,
                "lines must be an integer in [1, 400]",
                raw.to_owned(),
                Vec::new(),
            ));
        };
        let first = match parse_url(raw) {
            Ok(u) => u,
            Err(e) => {
                return Ok(self.fail(
                    code::WEB_URL_REFUSED,
                    &e.to_string(),
                    raw.to_owned(),
                    Vec::new(),
                ))
            }
        };
        if !self.allowlist.allows(&first) {
            return Ok(self.fail(
                code::WEB_URL_REFUSED,
                "host is not on the session allowlist",
                raw.to_owned(),
                Vec::new(),
            ));
        }
        let key = cache_key(&first);
        if self.session.cache.contains_key(&key) {
            let page = self.session.cache.get(&key);
            if let Some(page) = page {
                let record = WebRecord {
                    hops: Vec::new(),
                    final_url: key.clone(),
                    text_sha256: page.text_sha256,
                    cached: true,
                };
                let header = format!(
                    "fetched {} -> {} {} {}B sha256:{} (cached)",
                    key, page.status, page.content_type, page.body_len, page.body_sha256
                );
                if page.body_truncated {
                    let header = format!("{header} (truncated)");
                    let obs = render(page, &header, start, lines);
                    return Ok(self.done(&key, obs, record));
                }
                let obs = render(page, &header, start, lines);
                return Ok(self.done(&key, obs, record));
            }
        }
        self.session.fetches += 1;
        if self.session.fetches > self.budgets.fetches {
            return Ok(self.fail(
                code::WEB_BUDGET,
                "session fetch budget exhausted",
                raw.to_owned(),
                Vec::new(),
            ));
        }
        self.fetch(log, first, key, start, lines, ctx.deadline)
    }
}

impl WebTools<'_> {
    /// One search (§8, P-39h): the query re-checked against §2.3 (policy
    /// checked it at authorize; this is the only path to egress), the hop
    /// opened in search-endpoint mode — no resolution, loopback only,
    /// journaled like every hop — and the endpoint's JSON rebuilt into a
    /// bounded, sanitized observation. The raw JSON is a blob for audit
    /// (its digest rides the hop record); it never reaches the context.
    #[allow(clippy::too_many_lines)]
    fn search(
        &mut self,
        args: &Value,
        log: &dyn EgressLog,
        deadline: Instant,
    ) -> Result<ToolResult, ToolError> {
        let Some(endpoint) = self.search_endpoint.as_ref() else {
            return Ok(self.fail(
                code::WEB_NO_SEARCH,
                "no search endpoint is configured for this session",
                WEB_SEARCH_ID.to_owned(),
                Vec::new(),
            ));
        };
        let addr_host = match &endpoint.host {
            LoopbackHost::V4 => "127.0.0.1",
            LoopbackHost::V6 => "[::1]",
        };
        let (port, base_path) = (endpoint.port, endpoint.base_path.clone());
        let Some(query) = args.get("query").and_then(Value::as_str) else {
            return Ok(self.fail(
                code::WEB_QUERY,
                "query must be a string",
                WEB_SEARCH_ID.to_owned(),
                Vec::new(),
            ));
        };
        if !query_clean(query) {
            return Ok(self.fail(
                code::WEB_QUERY,
                "query fails the §2.3 bounds (1..=256 chars, no control, zero-width or bidi)",
                query.to_owned(),
                Vec::new(),
            ));
        }
        let shown = match args.get("max_results") {
            None | Some(Value::Null) => DEFAULT_SEARCH_RESULTS,
            Some(v) => match v.as_u64() {
                Some(n) if (1..=MAX_SEARCH_RESULTS).contains(&n) => n,
                _ => {
                    return Ok(self.fail(
                        code::BAD_ARGS,
                        "max_results must be an integer in [1, 10]",
                        query.to_owned(),
                        Vec::new(),
                    ))
                }
            },
        };
        self.session.searches += 1;
        if self.session.searches > self.budgets.searches {
            return Ok(self.fail(
                code::WEB_BUDGET,
                "session search budget exhausted",
                query.to_owned(),
                Vec::new(),
            ));
        }
        let wall = self
            .budgets
            .hop
            .wall()
            .min(deadline.saturating_duration_since(Instant::now()));
        if wall.is_zero() {
            return Ok(self.fail(
                code::WEB_BUDGET,
                "the per-call deadline passed before the search",
                WEB_SEARCH_ID.to_owned(),
                Vec::new(),
            ));
        }
        let Ok(budgets) = HopBudgets::new(wall, SEARCH_BODY_MAX_BYTES + 64 * 1024) else {
            return Ok(self.fail(
                code::WEB_BUDGET,
                "hop budgets out of range",
                WEB_SEARCH_ID.to_owned(),
                Vec::new(),
            ));
        };
        let target = format!(
            "{base}/search?q={}&format=json&pageno=1&safesearch=1",
            percent_encode_query(query),
            base = base_path,
        );
        let request_url = format!("http://{addr_host}:{port}{target}");
        let hop_no = self.session.next_hop;
        self.session.next_hop += 1;
        let token = hop_token(hop_no);
        let hreq = HopRequest {
            hop: hop_no,
            url: request_url.clone(),
            host: addr_host.to_owned(),
            port,
            mode: EgressMode::SearchEndpoint,
            purpose: EgressPurpose::Search,
            token: &token,
            budgets,
        };
        // Journals the decision (allow or refusal) before any byte. The
        // pump dials the loopback endpoint through the dedicated
        // connector; nothing here resolves (§8 steps 1-2).
        let pump = match open_hop(log, self.egress.resolver.as_ref(), LoopbackConnector, &hreq) {
            Ok(p) => p,
            Err(e) => {
                return Ok(self.fail(code::WEB_EGRESS, &egress_msg(&e), request_url, Vec::new()))
            }
        };
        let relay_port = pump.port();
        let hop_dir = self.web_dir.join(format!("hop-{hop_no}"));
        if let Err(e) = make_dir(&hop_dir) {
            return Ok(self.fail(
                code::WEB_FETCHER,
                &format!("hop dir: {e}"),
                request_url,
                Vec::new(),
            ));
        }
        let req_path = hop_dir.join("req.json");
        if let Err(e) = write_search_request(
            &req_path, relay_port, &token, addr_host, port, &target, wall,
        ) {
            return Ok(self.fail(
                code::WEB_FETCHER,
                &format!("request file: {e}"),
                request_url,
                Vec::new(),
            ));
        }
        let run = HopRun {
            req_path: &req_path,
            hop_dir: &hop_dir,
            proxy_port: relay_port,
            wall,
            output_bytes: SEARCH_BODY_MAX_BYTES + 4096,
        };
        let framed = self.runner.run(&run);
        let io = pump.join();
        self.session.bytes_down += io.bytes_down;
        // §5.3: the hop directory holds only the request file and is
        // removed once the hop ends. Best effort: the frame is already
        // in memory and the egress record already journaled.
        let _ = fs::remove_dir_all(&hop_dir);
        let record = |frame: Option<&harness_core::fetch_frame::Frame>| WebHop {
            hop: hop_no,
            url: request_url.clone(),
            status: frame.and_then(|f| f.header.status),
            content_type: frame.and_then(|f| f.header.content_type.clone()),
            body_len: frame.map_or(0, |f| f.header.body_len),
            body_sha256: frame.map_or(sha256(&[]), |f| sha256(&f.body)),
            truncated: frame.is_some_and(|f| f.header.truncated),
            bytes_up: io.bytes_up,
            bytes_down: io.bytes_down,
            elapsed_ms: u64::try_from(io.elapsed.as_millis()).unwrap_or(u64::MAX),
            ended: io.ended.as_str(),
            mode: EgressMode::SearchEndpoint.as_str(),
            ip: Some(io.chosen),
            location: None,
        };
        let frame = match framed {
            Ok(bytes) => {
                match harness_core::fetch_frame::parse_frame(&bytes, SEARCH_BODY_MAX_BYTES) {
                    Ok(f) => f,
                    Err(e) => {
                        let hops = vec![record(None)];
                        return Ok(self.fail(code::WEB_FETCHER, &e.to_string(), request_url, hops));
                    }
                }
            }
            Err(e) => {
                let hops = vec![record(None)];
                return Ok(self.fail(code::WEB_FETCHER, &e.to_string(), request_url, hops));
            }
        };
        let hops = vec![record(Some(&frame))];
        if let Some(kind) = frame.header.error.as_deref() {
            return Ok(self.fail(code::WEB_FETCHER, kind, request_url, hops));
        }
        let status = frame.header.status.unwrap_or(0);
        if status != 200 {
            return Ok(self.fail(
                code::WEB_SEARCH_PARSE,
                &format!("search endpoint returned {status}"),
                request_url,
                hops,
            ));
        }
        let body = serde_json::from_slice::<Value>(&frame.body);
        let doc = match body {
            Ok(d) => d,
            Err(_) => {
                return Ok(self.fail(
                    code::WEB_SEARCH_PARSE,
                    "search endpoint response is not JSON",
                    request_url,
                    hops,
                ))
            }
        };
        let Some(results) = doc.get("results").and_then(Value::as_array) else {
            return Ok(self.fail(
                code::WEB_SEARCH_PARSE,
                "search endpoint response has no results array",
                request_url,
                hops,
            ));
        };
        Ok(self.finish_search(query, shown, results, request_url, hops))
    }

    /// Rebuild the observation from the search JSON (§8 step 4): only
    /// `results[].{url,title,content}` are read; every URL goes through
    /// `parse_url` (bad ones dropped and counted); titles and snippets
    /// are sanitized and cut; each kept entry is marked fetchable or not.
    /// The allowlist is never widened by a search result.
    fn finish_search(
        &self,
        query: &str,
        shown: u64,
        results: &[Value],
        request_url: String,
        hops: Vec<WebHop>,
    ) -> ToolResult {
        let mut kept: Vec<(String, bool, String, Option<String>)> = Vec::new();
        let mut dropped = 0u64;
        for r in results {
            if kept.len() as u64 >= shown {
                break;
            }
            let Some(url) = r.get("url").and_then(Value::as_str) else {
                dropped += 1;
                continue;
            };
            let Ok(parsed) = parse_url(url) else {
                dropped += 1;
                continue;
            };
            let fetchable = self.allowlist.allows(&parsed);
            let title = r
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let snippet = r
                .get("content")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            kept.push((
                format!("{}:{}{}", parsed.host(), parsed.port(), parsed.target()),
                fetchable,
                title,
                snippet,
            ));
        }
        let mut obs = String::new();
        obs.push_str(&format!(
            "search \"{}\": {} results ({} dropped: bad URL)\n",
            sanitize_for_terminal_bounded(query, DisplayMode::Block, MAX_URL_BYTES),
            kept.len(),
            dropped
        ));
        for (i, (where_, fetchable, title, snippet)) in kept.iter().enumerate() {
            let mark = if *fetchable {
                "fetchable"
            } else {
                "not on allowlist"
            };
            let title = sanitize_for_terminal_bounded(
                title,
                DisplayMode::Block,
                4 * SEARCH_TITLE_MAX_CHARS,
            );
            let title = cut_chars(&title, SEARCH_TITLE_MAX_CHARS);
            obs.push_str(&format!("{}. [{mark}] {where_} — {title}\n", i + 1));
            if let Some(snippet) = snippet {
                let snippet = sanitize_for_terminal_bounded(
                    snippet,
                    DisplayMode::Block,
                    4 * SEARCH_SNIPPET_MAX_CHARS,
                );
                let snippet = cut_chars(&snippet, SEARCH_SNIPPET_MAX_CHARS);
                obs.push_str("   ");
                obs.push_str(snippet);
                obs.push('\n');
            }
        }
        let record = WebRecord {
            hops,
            final_url: request_url.clone(),
            text_sha256: sha256(obs.as_bytes()),
            cached: false,
        };
        self.done(&request_url, obs, record)
    }

    /// The fetch loop: at most `MAX_HOPS` hops, each journaled before any
    /// byte moves, redirects re-checked per hop.
    #[allow(clippy::too_many_lines)]
    fn fetch(
        &mut self,
        log: &dyn EgressLog,
        first: WebUrl,
        key: String,
        start: u64,
        lines: u64,
        deadline: Instant,
    ) -> Result<ToolResult, ToolError> {
        let mut current = first;
        let mut hops: Vec<WebHop> = Vec::new();
        let mut redirects = 0u32;
        let frame = loop {
            if hops.len() >= MAX_HOPS {
                return Ok(self.fail(
                    code::WEB_REDIRECT_LIMIT,
                    "too many redirects",
                    current_url(&current),
                    hops,
                ));
            }
            let wall = self
                .budgets
                .hop
                .wall()
                .min(deadline.saturating_duration_since(Instant::now()));
            if wall.is_zero() {
                return Ok(self.fail(
                    code::WEB_BUDGET,
                    "the per-call deadline passed mid-fetch",
                    current_url(&current),
                    hops,
                ));
            }
            let Ok(budgets) = HopBudgets::new(wall, self.budgets.hop.relay_cap_bytes()) else {
                return Ok(self.fail(
                    code::WEB_BUDGET,
                    "hop budgets out of range",
                    current_url(&current),
                    hops,
                ));
            };
            let hop_no = self.session.next_hop;
            self.session.next_hop += 1;
            let token = hop_token(hop_no);
            let hreq = HopRequest {
                hop: hop_no,
                url: current_url(&current),
                host: current.host().to_owned(),
                port: current.port(),
                mode: self.egress.mode,
                purpose: EgressPurpose::Fetch,
                token: &token,
                budgets,
            };
            // Journals the decision (allow or refusal) before any byte.
            let pump = match open_hop(
                log,
                self.egress.resolver.as_ref(),
                self.egress.connector.clone(),
                &hreq,
            ) {
                Ok(p) => p,
                Err(e) => {
                    return Ok(self.fail(
                        code::WEB_EGRESS,
                        &egress_msg(&e),
                        current_url(&current),
                        hops,
                    ))
                }
            };
            let port = pump.port();
            let hop_dir = self.web_dir.join(format!("hop-{hop_no}"));
            if let Err(e) = make_dir(&hop_dir) {
                return Ok(self.fail(
                    code::WEB_FETCHER,
                    &format!("hop dir: {e}"),
                    current_url(&current),
                    hops,
                ));
            }
            let req_path = hop_dir.join("req.json");
            if let Err(e) = write_request(
                &req_path,
                port,
                &token,
                &current,
                self.budgets.body_max_bytes,
                wall,
            ) {
                return Ok(self.fail(
                    code::WEB_FETCHER,
                    &format!("request file: {e}"),
                    current_url(&current),
                    hops,
                ));
            }
            let run = HopRun {
                req_path: &req_path,
                hop_dir: &hop_dir,
                proxy_port: port,
                wall,
                output_bytes: self.budgets.body_max_bytes + 4096,
            };
            let framed = self.runner.run(&run);
            let io = pump.join();
            self.session.bytes_down += io.bytes_down;
            // §5.3: the hop directory holds only the request file and is
            // removed once the hop ends. Best effort: the frame is already
            // in memory and the egress record already journaled.
            let _ = fs::remove_dir_all(&hop_dir);
            let record = |frame: Option<&harness_core::fetch_frame::Frame>| WebHop {
                hop: hop_no,
                url: current_url(&current),
                status: frame.and_then(|f| f.header.status),
                content_type: frame.and_then(|f| f.header.content_type.clone()),
                body_len: frame.map_or(0, |f| f.header.body_len),
                body_sha256: frame.map_or(sha256(&[]), |f| sha256(&f.body)),
                truncated: frame.is_some_and(|f| f.header.truncated),
                bytes_up: io.bytes_up,
                bytes_down: io.bytes_down,
                elapsed_ms: u64::try_from(io.elapsed.as_millis()).unwrap_or(u64::MAX),
                ended: io.ended.as_str(),
                mode: self.egress.mode.as_str(),
                ip: Some(io.chosen),
                location: frame.and_then(|f| f.header.location.clone()),
            };
            let frame = match framed {
                Ok(bytes) => match harness_core::fetch_frame::parse_frame(
                    &bytes,
                    self.budgets.body_max_bytes,
                ) {
                    Ok(f) => f,
                    Err(e) => {
                        hops.push(record(None));
                        return Ok(self.fail(
                            code::WEB_FETCHER,
                            &e.to_string(),
                            current_url(&current),
                            hops,
                        ));
                    }
                },
                Err(e) => {
                    hops.push(record(None));
                    return Ok(self.fail(
                        code::WEB_FETCHER,
                        &e.to_string(),
                        current_url(&current),
                        hops,
                    ));
                }
            };
            if self.session.bytes_down > self.budgets.bytes_down {
                hops.push(record(Some(&frame)));
                return Ok(self.fail(
                    code::WEB_BUDGET,
                    "session download budget exhausted",
                    current_url(&current),
                    hops,
                ));
            }
            if let Some(kind) = frame.header.error.as_deref() {
                hops.push(record(Some(&frame)));
                return Ok(self.fail(code::WEB_FETCHER, kind, current_url(&current), hops));
            }
            let status = frame.header.status.unwrap_or(0);
            let location = frame.header.location.clone();
            hops.push(record(Some(&frame)));
            if !(300..400).contains(&status) {
                break frame;
            }
            let Some(loc) = location else {
                return Ok(self.fail(
                    code::WEB_URL_REFUSED,
                    "redirect without a location",
                    current_url(&current),
                    hops,
                ));
            };
            redirects += 1;
            if redirects > MAX_REDIRECTS {
                return Ok(self.fail(
                    code::WEB_REDIRECT_LIMIT,
                    "too many redirects",
                    current_url(&current),
                    hops,
                ));
            }
            let next = match resolve_location(&current, &loc) {
                Ok(n) => n,
                Err(e) => {
                    let reason = if matches!(e, harness_policy::web::UrlRefused::Downgrade) {
                        RefuseReason::Downgrade
                    } else {
                        RefuseReason::HostNotAllowlisted
                    };
                    if journal_refuse(log, self.session.next_hop, &loc, self.egress.mode, reason)
                        .is_err()
                    {
                        return Ok(self.fail(
                            code::WEB_EGRESS,
                            "egress log failed",
                            current_url(&current),
                            hops,
                        ));
                    }
                    return Ok(self.fail(
                        code::WEB_URL_REFUSED,
                        &e.to_string(),
                        current_url(&current),
                        hops,
                    ));
                }
            };
            if !self.allowlist.allows(&next) {
                if journal_refuse(
                    log,
                    self.session.next_hop,
                    &current_url(&next),
                    self.egress.mode,
                    RefuseReason::HostNotAllowlisted,
                )
                .is_err()
                {
                    return Ok(self.fail(
                        code::WEB_EGRESS,
                        "egress log failed",
                        current_url(&current),
                        hops,
                    ));
                }
                return Ok(self.fail(
                    code::WEB_URL_REFUSED,
                    "redirect host is not on the session allowlist",
                    current_url(&current),
                    hops,
                ));
            }
            current = next;
        };
        self.verdict(frame, key, hops, start, lines)
    }

    /// The content verdict (§11): type allowlist, binary sniff, charset
    /// allowlist; then extraction, window and cache.
    fn verdict(
        &mut self,
        frame: harness_core::fetch_frame::Frame,
        key: String,
        hops: Vec<WebHop>,
        start: u64,
        lines: u64,
    ) -> Result<ToolResult, ToolError> {
        let status = frame.header.status.unwrap_or(0);
        let Some(declared) = frame.header.content_type.clone() else {
            return Ok(self.fail(
                code::WEB_CONTENT_TYPE,
                "response has no content type",
                key,
                hops,
            ));
        };
        let (mime, charset) = parse_content_type(&declared);
        if !ALLOWED_TYPES.contains(&mime.as_str()) {
            return Ok(self.fail(
                code::WEB_CONTENT_TYPE,
                &format!("content type {mime:?} is not allowed"),
                key,
                hops,
            ));
        }
        let sniff = frame.body.get(..SNIFF_BYTES).unwrap_or(&frame.body);
        if sniff.contains(&0) {
            return Ok(self.fail(
                code::WEB_BINARY,
                "declared-text body sniffs binary (NUL)",
                key,
                hops,
            ));
        }
        if !charset.is_empty() && !ALLOWED_CHARSETS.contains(&charset.as_str()) {
            return Ok(self.fail(
                code::WEB_CHARSET,
                &format!("charset {charset:?} is not supported"),
                key,
                hops,
            ));
        }
        let text = if mime.ends_with("html") {
            let ex = html::to_text(&frame.body, &ExtractLimits::default());
            ex.text
        } else {
            let decoded = decode_body(&frame.body, &charset);
            sanitize_for_terminal_bounded(&decoded, DisplayMode::Block, TEXT_MAX_BYTES)
        };
        let text_sha256 = sha256(text.as_bytes());
        let body_sha256 = sha256(&frame.body);
        let page = CachedPage {
            text_sha256,
            text,
            status,
            content_type: mime,
            body_len: frame.header.body_len,
            body_sha256,
            body_truncated: frame.header.truncated,
        };
        let header = format!(
            "fetched {} -> {} {} {}B sha256:{}{}",
            key,
            page.status,
            page.content_type,
            page.body_len,
            page.body_sha256,
            if page.body_truncated {
                " (truncated)"
            } else {
                ""
            },
        );
        let obs = render(&page, &header, start, lines);
        let record = WebRecord {
            hops,
            final_url: key.clone(),
            text_sha256: page.text_sha256,
            cached: false,
        };
        self.session.cache.insert(key.clone(), page);
        Ok(self.done(&key, obs, record))
    }

    /// A finished, successful observation: bounded, digest over the full
    /// text, marked [`Source::Web`] (INV-47).
    fn done(&self, url: &str, obs: String, record: WebRecord) -> ToolResult {
        let digest = sha256(obs.as_bytes());
        let mut text = obs;
        let truncated = text.len() > crate::builtin::RESULT_MAX_BYTES;
        if truncated {
            let mut end = crate::builtin::RESULT_MAX_BYTES;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
        }
        ToolResult {
            status: ToolStatus::Ok,
            output: Untrusted::new(text.into_bytes(), Source::Web(url.to_owned())),
            truncated,
            digest,
            read: None,
            edits: Vec::new(),
            exec: None,
            web: Some(record),
        }
    }

    /// A finished error: the code, the hops made so far, and the output
    /// still marked web.
    fn fail(&self, code: u16, msg: &str, url: String, hops: Vec<WebHop>) -> ToolResult {
        let text = format!("error: {msg}");
        let digest = sha256(text.as_bytes());
        let final_url = hops.last().map_or(url.clone(), |h| h.url.clone());
        ToolResult {
            status: ToolStatus::Error { code },
            output: Untrusted::new(text.into_bytes(), Source::Web(url)),
            truncated: false,
            digest,
            read: None,
            edits: Vec::new(),
            exec: None,
            web: Some(WebRecord {
                hops,
                final_url,
                text_sha256: sha256(&[]),
                cached: false,
            }),
        }
    }
}

/// Render the observation: the header line, then the asked-for line
/// window of the page text, byte-bounded.
fn render(page: &CachedPage, header: &str, start: u64, lines: u64) -> String {
    let total = page.text.lines().count() as u64;
    let mut obs = String::new();
    if start > total {
        obs.push_str(header);
        obs.push_str("\nerror: the window starts past the end of the page\n");
        return obs;
    }
    let last = (start + lines - 1).min(total);
    let body: String = page
        .text
        .lines()
        .skip(start.saturating_sub(1) as usize)
        .take((last - start + 1) as usize)
        .collect::<Vec<_>>()
        .join("\n");
    obs.push_str(header);
    obs.push_str(&format!(" {start}-{last}/{total}\n"));
    obs.push_str(&body);
    obs.push('\n');
    if obs.len() > OBSERVATION_MAX_BYTES {
        let mut end = OBSERVATION_MAX_BYTES;
        while !obs.is_char_boundary(end) {
            end -= 1;
        }
        let cut = obs.len() - end;
        obs.truncate(end);
        obs.push_str(&format!("\n[{cut} bytes cut]\n"));
    }
    obs
}

/// Percent-encode a search query for the endpoint's `q=` parameter
/// (§8): RFC 3986 unreserved characters pass, everything else becomes
/// `%XX` (uppercase hex). The query is already §2.3-clean, so this is
/// about the URL grammar, not about hiding content.
fn percent_encode_query(q: &str) -> String {
    let mut out = String::with_capacity(q.len());
    for b in q.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Cut to at most `max_chars` characters, on a char boundary.
fn cut_chars(s: &str, max_chars: usize) -> &str {
    s.char_indices()
        .nth(max_chars)
        .map_or(s, |(idx, _)| &s[..idx])
}

/// Serialize the search hop's `rh-fetch/1` request file (§8 step 3): the
/// target is the endpoint's `/search` path, JSON asked for by `accept`,
/// the body capped at [`SEARCH_BODY_MAX_BYTES`].
fn write_search_request(
    path: &Path,
    proxy_port: u16,
    token: &str,
    host: &str,
    port: u16,
    target: &str,
    wall: Duration,
) -> io::Result<()> {
    let timeout_ms = wall.as_millis().min(60_000);
    let doc = json!({
        "v": 1,
        "proxy_port": proxy_port,
        "token": token,
        "scheme": "http",
        "host": host,
        "port": port,
        "target": target,
        "accept": "application/json",
        "max_body": SEARCH_BODY_MAX_BYTES,
        "max_header_bytes": 32 * 1024,
        "timeout_ms": timeout_ms,
        "user_agent": "",
        "mode": "proxy",
    });
    let bytes = serde_json::to_vec(&doc).map_err(io::Error::other)?;
    fs::write(path, bytes)
}

/// Serialize the hop's `rh-fetch/1` request file.
fn write_request(
    path: &Path,
    proxy_port: u16,
    token: &str,
    url: &WebUrl,
    body_max_bytes: u64,
    wall: Duration,
) -> io::Result<()> {
    let scheme = match url.scheme() {
        harness_policy::web::Scheme::Http => "http",
        harness_policy::web::Scheme::Https => "https",
    };
    let timeout_ms = wall.as_millis().min(60_000);
    let doc = json!({
        "v": 1,
        "proxy_port": proxy_port,
        "token": token,
        "scheme": scheme,
        "host": url.host(),
        "port": url.port(),
        "target": url.target(),
        "accept": "",
        "max_body": body_max_bytes,
        "max_header_bytes": 32 * 1024,
        "timeout_ms": timeout_ms,
        "user_agent": "",
        "mode": "proxy",
    });
    let bytes = serde_json::to_vec(&doc).map_err(io::Error::other)?;
    fs::write(path, bytes)
}

/// The hop's bearer token: 32 hex chars derived from the hop index. Good
/// enough to fence the loopback relay against other local processes for
/// the hop's lifetime; a run-level secret would be wired by P-39j.
fn hop_token(hop: u64) -> String {
    let d = sha256(format!("rh-hop/{hop}").as_bytes());
    d.to_string().chars().take(32).collect()
}

/// Journal a provider-side egress refusal (a redirect that downgrades or
/// leaves the allowlist): the decision is the record, INV-43.
fn journal_refuse(
    log: &dyn EgressLog,
    hop: u64,
    url: &str,
    mode: EgressMode,
    reason: RefuseReason,
) -> Result<(), ()> {
    log.append(&EgressRecord {
        hop,
        decision: EgressDecision::Refuse(reason),
        url: url.to_owned(),
        host: String::new(),
        port: 0,
        mode,
        purpose: EgressPurpose::Fetch,
        resolved: Vec::new(),
        ip: None,
    })
    .map_err(|_| ())
}

/// The static message for an `open_hop` refusal.
fn egress_msg(e: &HopRefused) -> String {
    match e {
        HopRefused::NoDirectEgress => "direct egress is not available in this build".into(),
        HopRefused::DnsTimeout => "dns timed out".into(),
        HopRefused::Resolve(e) => format!("dns resolution refused: {e}"),
        HopRefused::NoAddress => "host has no address".into(),
        HopRefused::NonGlobalAddress { ip, class } => {
            format!("host resolves to a non-global address ({ip}, {class})")
        }
        HopRefused::Log(e) => format!("egress log failed: {e}"),
        HopRefused::Bind(e) => format!("could not bind the egress relay: {e}"),
        HopRefused::Spawn(e) => format!("could not start the egress relay: {e}"),
    }
}

/// The cache key: scheme, host, port and target — everything that makes
/// the origin fetch.
fn cache_key(url: &WebUrl) -> String {
    format!(
        "{}://{}:{}{}",
        match url.scheme() {
            harness_policy::web::Scheme::Http => "http",
            harness_policy::web::Scheme::Https => "https",
        },
        url.host(),
        url.port(),
        url.target()
    )
}

fn current_url(url: &WebUrl) -> String {
    cache_key(url)
}

/// The raw `url` argument, for results that never got far enough to name
/// a real URL.
fn raw_url(args: &Value) -> String {
    args.get("url")
        .and_then(Value::as_str)
        .unwrap_or("harness.web.fetch")
        .to_owned()
}

fn window_start(args: &Value) -> Option<u64> {
    match args.get("start") {
        None | Some(Value::Null) => Some(1),
        Some(v) => v.as_u64().filter(|s| *s >= 1),
    }
}

fn window_lines(args: &Value) -> Option<u64> {
    match args.get("lines") {
        None | Some(Value::Null) => Some(DEFAULT_LINES),
        Some(v) => v.as_u64().filter(|l| (1..=MAX_LINES).contains(l)),
    }
}

/// Split `text/html; charset=utf-8` into its lowercased type and charset
/// (empty when undeclared).
fn parse_content_type(declared: &str) -> (String, String) {
    let mut parts = declared.split(';');
    let mime = parts.next().unwrap_or("").trim().to_ascii_lowercase();
    let mut charset = String::new();
    for p in parts {
        let p = p.trim();
        if let Some((name, value)) = p.split_once('=') {
            if name.trim().eq_ignore_ascii_case("charset") {
                charset = value.trim().trim_matches('"').trim().to_ascii_lowercase();
            }
        }
    }
    (mime, charset)
}

/// Decode the body under the declared charset. `iso-8859-1` decodes as
/// `windows-1252` (its practical superset, §11); UTF-8 errors become the
/// replacement character — the text is untrusted either way.
fn decode_body(body: &[u8], charset: &str) -> String {
    if charset == "iso-8859-1" || charset == "windows-1252" {
        let mut out = String::with_capacity(body.len());
        for &b in body {
            out.push(match b {
                0x80 => '\u{20AC}',
                0x82 => '\u{201A}',
                0x83 => '\u{0192}',
                0x84 => '\u{201E}',
                0x85 => '\u{2026}',
                0x86 => '\u{2020}',
                0x87 => '\u{2021}',
                0x88 => '\u{02C6}',
                0x89 => '\u{2030}',
                0x8A => '\u{0160}',
                0x8B => '\u{2039}',
                0x8C => '\u{0152}',
                0x8E => '\u{017D}',
                0x91 => '\u{2018}',
                0x92 => '\u{2019}',
                0x93 => '\u{201C}',
                0x94 => '\u{201D}',
                0x95 => '\u{2022}',
                0x96 => '\u{2013}',
                0x97 => '\u{2014}',
                0x98 => '\u{02DC}',
                0x99 => '\u{2122}',
                0x9A => '\u{0161}',
                0x9B => '\u{203A}',
                0x9C => '\u{0153}',
                0x9E => '\u{017E}',
                0x9F => '\u{0178}',
                _ => b as char,
            });
        }
        return out;
    }
    String::from_utf8_lossy(body).into_owned()
}

fn make_dir(p: &Path) -> io::Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(p)?;
    let m = fs::symlink_metadata(p)?;
    if m.file_type().is_symlink() || !m.is_dir() {
        return Err(io::Error::other("not a real directory"));
    }
    Ok(())
}

fn file_sha256(p: &Path) -> io::Result<Digest> {
    let mut f = fs::File::open(p)?;
    let mut h = Sha256Stream::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(buf.get(..n).unwrap_or_default());
    }
    Ok(h.finish())
}
