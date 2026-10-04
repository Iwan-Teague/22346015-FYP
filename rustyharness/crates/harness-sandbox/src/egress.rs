//! The web egress airlock (design note §3, §4; INV-43, INV-44, INV-52).
//!
//! Nothing in the harness dials the network directly except this module's
//! pump, and every hop attempt is journalled BEFORE any byte can be sent:
//!
//! - [`open_hop`] resolves the host once ([`Resolver`]), refuses unless
//!   EVERY resolved address is globally routable ([`harness_policy::web`]
//!   §4.2 classification), appends the `Egress` journal record (allow or
//!   `refuse:<reason>`) and only then binds the one-shot loopback pump and
//!   returns it. A failed journal append refuses the hop and nothing is
//!   bound or dialled (INV-43).
//! - The pump accepts exactly ONE connection, demands
//!   `CONNECT <expected host:port>` with the expected bearer token, dials
//!   the CLASSIFIED address through the [`Connector`] (never re-resolving;
//!   INV-44), and relays both ways under the hop budgets. A second
//!   connection is closed; the pump never dials anything but the classified
//!   address.
//! - Budgets are typed ([`HopBudgets`], INV-48): a hop that exhausts its
//!   wall ends [`HopEnded::Timeout`], a hop that fills its relay cap ends
//!   [`HopEnded::Capped`]; neither can run away.
//! - Without the `net` feature there is no [`DirectConnector`]:
//!   [`open_hop`] refuses `mode: direct` with [`HopRefused::NoDirectEgress`]
//!   and [`direct_egress_available`] reports it (INV-52: the default build
//!   opens no outbound sockets at all; the loopback pump remains, since the
//!   user-proxy and search-endpoint modes need it).

use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use harness_policy::web::{classify_answer, AnswerRefused};

/// DNS deadline (§4.3): a resolver answer later than this is a
/// `refuse:dns-timeout`; the worker thread is abandoned and its answer is
/// never used.
pub const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// TCP connect deadline (§4.4): dialling the classified address takes at
/// most this long; over it the hop ends `connect_failed`.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default per-hop wall budget (§4.4).
pub const DEFAULT_HOP_WALL: Duration = Duration::from_secs(20);

/// Maximum per-hop wall budget (§4.4); larger [`HopBudgets`] are refused.
pub const MAX_HOP_WALL: Duration = Duration::from_secs(60);

/// Default per-direction relay cap (§4.4): the 2 MiB body cap plus slack
/// for the response head the fetch layer reads around it.
pub const DEFAULT_RELAY_CAP_BYTES: u64 = 2 * 1024 * 1024 + 64 * 1024;

/// Maximum per-direction relay cap; larger [`HopBudgets`] are refused.
pub const MAX_RELAY_CAP_BYTES: u64 = 16 * 1024 * 1024;

/// The pump listens here (and nowhere else), on an ephemeral port.
const PUMP_BIND_HOST: &str = "127.0.0.1";

/// How often the accept loop re-polls the non-blocking listener.
const ACCEPT_POLL: Duration = Duration::from_millis(2);

/// How long the pump keeps closing further connections after the session
/// ends, so a queued second connection is refused, not silently deferred.
const DRAIN_WINDOW: Duration = Duration::from_millis(250);

/// One socket-timeout slice: I/O timeouts are set in slices no longer than
/// this so the wall budget is re-checked between operations.
const IO_SLICE: Duration = Duration::from_secs(1);

/// Relay read chunk.
const RELAY_CHUNK: usize = 16 * 1024;

/// CONNECT head read chunk.
const HEAD_CHUNK: usize = 1024;

/// CONNECT head cap: a request head larger than this is refused.
const CONNECT_HEAD_CAP_BYTES: usize = 8 * 1024;

/// Head terminator.
const HEAD_END: &[u8] = b"\r\n\r\n";

/// How long to wait for the down-relay thread to report after the up
/// direction has finished (it always ends by the wall deadline, and stops
/// within one `IO_SLICE` of the sibling direction finishing).
const RELAY_JOIN: Duration = Duration::from_secs(5);

/// The CONNECT handshake replies.
const REPLY_200: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const REPLY_403: &[u8] = b"HTTP/1.1 403 Forbidden\r\n\r\n";
const REPLY_502: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\n\r\n";

// ---------------------------------------------------------------------------
// Journal record (§4.5): the shapes are enforced again by the journal layer
// (`harness-journal` canonical bodies); this is the typed Rust form.
// ---------------------------------------------------------------------------

/// Why a hop was refused (§4.5 closed vocabulary). `host-not-allowlisted`
/// and `downgrade` are refused by the URL/allowlist layer upstream of the
/// airlock (P-39a/P-39b); the airlock journals them through this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefuseReason {
    /// A resolved address was not globally routable (INV-44).
    NonGlobalAddress,
    /// The resolver answer held no address.
    NoAddress,
    /// The resolver did not answer within [`DNS_TIMEOUT`].
    DnsTimeout,
    /// A budget was exhausted before the hop could start.
    Budget,
    /// The URL host was not on the policy allowlist.
    HostNotAllowlisted,
    /// An https URL was downgraded to http.
    Downgrade,
}

impl RefuseReason {
    /// The `refuse:<reason>` wire text of the reason (§4.5).
    pub fn as_str(self) -> &'static str {
        match self {
            RefuseReason::NonGlobalAddress => "non-global-address",
            RefuseReason::NoAddress => "no-address",
            RefuseReason::DnsTimeout => "dns-timeout",
            RefuseReason::Budget => "budget",
            RefuseReason::HostNotAllowlisted => "host-not-allowlisted",
            RefuseReason::Downgrade => "downgrade",
        }
    }
}

/// The decision of one hop attempt (§4.5): `allow` or `refuse:<reason>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressDecision {
    /// The hop was allowed; the pump is starting.
    Allow,
    /// The hop was refused before any byte could be sent.
    Refuse(RefuseReason),
}

impl EgressDecision {
    /// The §4.5 wire text: `allow` or `refuse:<reason>`.
    pub fn wire_str(self) -> String {
        match self {
            EgressDecision::Allow => "allow".to_string(),
            EgressDecision::Refuse(reason) => format!("refuse:{}", reason.as_str()),
        }
    }
}

/// Which door the hop uses (§4.5 closed vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressMode {
    /// Direct socket to the origin; only in builds with the `net` feature.
    Direct,
    /// Through the user's local HTTP proxy.
    UserProxy,
    /// To the harness search endpoint on loopback.
    SearchEndpoint,
}

impl EgressMode {
    /// The §4.5 wire text of the mode.
    pub fn as_str(self) -> &'static str {
        match self {
            EgressMode::Direct => "direct",
            EgressMode::UserProxy => "user-proxy",
            EgressMode::SearchEndpoint => "search-endpoint",
        }
    }
}

/// What the hop is for (§4.5 closed vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressPurpose {
    /// A web fetch hop.
    Fetch,
    /// A search hop.
    Search,
}

impl EgressPurpose {
    /// The §4.5 wire text of the purpose.
    pub fn as_str(self) -> &'static str {
        match self {
            EgressPurpose::Fetch => "fetch",
            EgressPurpose::Search => "search",
        }
    }
}

/// One egress journal record (§4.5). Every hop attempt produces exactly
/// one, appended before anything is bound or dialled (INV-43). `ip` is
/// `None` when the hop was refused before an address was chosen; the
/// `delegated` form is written by the user-proxy mode (P-39o), not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRecord {
    /// Monotonic hop counter.
    pub hop: u64,
    /// Allow/refuse decision.
    pub decision: EgressDecision,
    /// The model-supplied URL (untrusted input; the journal layer types it).
    pub url: String,
    /// The host as requested (lowercase).
    pub host: String,
    /// The port as requested.
    pub port: u16,
    /// Which door.
    pub mode: EgressMode,
    /// What for.
    pub purpose: EgressPurpose,
    /// The full resolver answer, in resolver order (re-fed to audit).
    pub resolved: Vec<IpAddr>,
    /// The classified address the pump may dial, if the hop was allowed.
    pub ip: Option<IpAddr>,
}

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

/// The journal sink refused the record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct EgressLogError(pub String);

/// Why a resolver lookup failed (§4.3).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveRefused {
    /// The lookup outlived its deadline; the worker is abandoned.
    #[error("dns lookup timed out")]
    Timeout,
    /// The lookup failed. Carries the failure description.
    #[error("{0}")]
    Failed(String),
}

/// Why [`open_hop`] refused to start a hop. Every variant leaves the
/// journal in the state INV-43 demands: either the refusal is already
/// journalled (`DnsTimeout`, `Resolve`, `NoAddress`, `NonGlobalAddress`)
/// or nothing about the hop was ever journalled because nothing about it
/// could happen (`NoDirectEgress`, `Log`, `Bind`, `Spawn`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HopRefused {
    /// This build has no direct egress (INV-52); configure user-proxy or
    /// rebuild with `--features net`.
    #[error("this build has no direct egress; build with --features net, or configure user-proxy")]
    NoDirectEgress,
    /// DNS outlived [`DNS_TIMEOUT`]; journalled `refuse:dns-timeout`.
    #[error("dns lookup timed out")]
    DnsTimeout,
    /// The resolver failed; journalled `refuse:no-address`.
    #[error("resolver failed: {0}")]
    Resolve(String),
    /// The resolver answer was empty; journalled `refuse:no-address`.
    #[error("resolver answer is empty")]
    NoAddress,
    /// Some resolved address was not globally routable (INV-44); journalled
    /// `refuse:non-global-address` with the full answer.
    #[error("resolver answer holds {ip} which is {class}")]
    NonGlobalAddress {
        /// The offending address.
        ip: IpAddr,
        /// Its §4.2 class.
        class: &'static str,
    },
    /// The journal sink refused the record (INV-43): nothing is bound and
    /// no connection is attempted.
    #[error("egress journal: {0}")]
    Log(EgressLogError),
    /// The pump could not bind its loopback listener (harness fault, not a
    /// policy refusal; the already-journalled allow is superseded by the
    /// hop error the caller reports).
    #[error("pump bind: {0}")]
    Bind(String),
    /// The pump thread could not start (harness fault).
    #[error("pump spawn: {0}")]
    Spawn(String),
}

/// A [`HopBudgets`] value was out of range (§4.4).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid hop budgets: {0}")]
pub struct BudgetError(pub String);

// ---------------------------------------------------------------------------
// Traits.
// ---------------------------------------------------------------------------

/// The egress journal sink (INV-43). `fsync` happens behind this trait; the
/// airlock refuses the hop when the append fails.
pub trait EgressLog {
    /// Append one record. The hop may proceed only if this returns `Ok`.
    ///
    /// No `Send`/`Sync` bound: the log is used only on the caller's
    /// thread, before anything is bound or spawned (INV-43). A test can
    /// therefore back it with a non-thread-safe journal seam.
    fn append(&self, record: &EgressRecord) -> Result<(), EgressLogError>;
}

/// Name resolution (§4.3). The airlock resolves ONCE per hop and classifies
/// the answer; the pump never resolves.
pub trait Resolver: Send + Sync {
    /// Resolve `host:port` to a list of addresses, in resolver order. The
    /// answer may be empty (the airlock then refuses `no-address`).
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, ResolveRefused>;
}

/// Dial the classified address (INV-44). Implementations are the only code
/// that may open a network connection; the pump dials exactly the address
/// [`open_hop`]'s classification chose, or nothing.
pub trait Connector: Send {
    /// Dial `addr`, or fail. Failures end the hop `connect_failed`.
    fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream>;
}

// ---------------------------------------------------------------------------
// System resolver (§4.3).
// ---------------------------------------------------------------------------

/// Run `query` on a helper thread with a hard deadline (§4.3). On timeout
/// the worker thread is abandoned (it is detached; the OS reclaims it when
/// the lookup finally returns) and its answer is dropped unused — a late
/// answer can never be consumed.
pub(crate) fn resolve_bounded<T, F>(deadline: Duration, query: F) -> Result<T, ResolveRefused>
where
    T: Send + 'static,
    F: FnOnce() -> io::Result<T> + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    let worker = thread::Builder::new()
        .name("egress-resolve".to_string())
        .spawn(move || {
            let _ = tx.send(query());
        });
    let worker = worker.map_err(|e| ResolveRefused::Failed(format!("resolver thread: {e}")))?;
    match rx.recv_timeout(deadline) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(ResolveRefused::Failed(e.to_string())),
        Err(_) => {
            drop(worker);
            Err(ResolveRefused::Timeout)
        }
    }
}

/// The system resolver: `ToSocketAddrs` on a helper thread with a deadline
/// (§4.3). Duplicate addresses are dropped; order is resolver order.
#[derive(Debug, Clone)]
pub struct SystemResolver {
    deadline: Duration,
}

impl Default for SystemResolver {
    fn default() -> Self {
        Self {
            deadline: DNS_TIMEOUT,
        }
    }
}

impl SystemResolver {
    /// A resolver with an explicit deadline (tests use a short one).
    pub fn with_deadline(deadline: Duration) -> Self {
        Self { deadline }
    }
}

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, ResolveRefused> {
        let host = host.to_string();
        let lookup = move || {
            let addrs = (host, port).to_socket_addrs()?;
            let mut ips: Vec<IpAddr> = Vec::new();
            for addr in addrs {
                if !ips.contains(&addr.ip()) {
                    ips.push(addr.ip());
                }
            }
            Ok(ips)
        };
        resolve_bounded(self.deadline, lookup)
    }
}

// ---------------------------------------------------------------------------
// Connectors (INV-44).
// ---------------------------------------------------------------------------

/// Dial only loopback addresses: the user-proxy and search-endpoint doors
/// (§4.4). Always available, in every build.
#[derive(Debug, Clone, Copy)]
pub struct LoopbackConnector;

impl Connector for LoopbackConnector {
    fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        if !addr.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("loopback connector refuses non-loopback {addr}"),
            ));
        }
        TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
    }
}

/// Dial any address the classification allowed: the direct door (§4.4).
/// Only exists in builds with the `net` feature (INV-52).
#[cfg(feature = "net")]
#[derive(Debug, Clone, Copy)]
pub struct DirectConnector;

#[cfg(feature = "net")]
impl Connector for DirectConnector {
    fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
    }
}

/// Test-only connector: remaps ONE fixed global address to a loopback
/// fixture, so airlock tests exercise the full classify-then-dial path with
/// no real network. Gated `#[cfg(any(test, feature = "remap"))]` exactly
/// like `harness-journal`'s fault-injection seam: unit tests always see it;
/// the cargo feature exists only so `purity.sh` can police that no normal
/// dependency edge enables it.
#[cfg(any(test, feature = "remap"))]
#[derive(Debug, Clone, Copy)]
pub struct RemapConnector {
    to: SocketAddr,
}

#[cfg(any(test, feature = "remap"))]
impl RemapConnector {
    /// The global test address this connector remaps (a documentation-range
    /// neighbour kept OUT of every §4.2 special table, so classification
    /// sees a genuine global address).
    pub const REMAP_FROM_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34));

    /// Remap [`Self::REMAP_FROM_IP`] to `to` and refuse every other
    /// address (fail-closed: the fixture connector dials one target).
    pub fn new(to: SocketAddr) -> Self {
        Self { to }
    }
}

#[cfg(any(test, feature = "remap"))]
impl Connector for RemapConnector {
    fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        if addr.ip() != Self::REMAP_FROM_IP {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "remap connector only dials {}, not {addr}",
                    Self::REMAP_FROM_IP
                ),
            ));
        }
        TcpStream::connect_timeout(&self.to, CONNECT_TIMEOUT)
    }
}

// ---------------------------------------------------------------------------
// Budgets and hop request (§4.4, INV-48).
// ---------------------------------------------------------------------------

/// Per-hop budgets (§4.4). Construction validates; a bad budget is refused
/// before any resolution or journalling happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HopBudgets {
    wall: Duration,
    relay_cap_bytes: u64,
}

impl HopBudgets {
    /// Validate a budget pair: wall within `(0, 60 s]`, cap within
    /// `(0, 16 MiB]`.
    pub fn new(wall: Duration, relay_cap_bytes: u64) -> Result<Self, BudgetError> {
        if wall.is_zero() || wall > MAX_HOP_WALL {
            return Err(BudgetError(format!(
                "wall must be within (0, {} s], got {wall:?}",
                MAX_HOP_WALL.as_secs()
            )));
        }
        if relay_cap_bytes == 0 || relay_cap_bytes > MAX_RELAY_CAP_BYTES {
            return Err(BudgetError(format!(
                "relay cap must be within (0, {} bytes], got {relay_cap_bytes}",
                MAX_RELAY_CAP_BYTES
            )));
        }
        Ok(Self {
            wall,
            relay_cap_bytes,
        })
    }

    /// The wall budget.
    pub fn wall(self) -> Duration {
        self.wall
    }

    /// The per-direction relay cap.
    pub fn relay_cap_bytes(self) -> u64 {
        self.relay_cap_bytes
    }
}

impl Default for HopBudgets {
    fn default() -> Self {
        Self {
            wall: DEFAULT_HOP_WALL,
            relay_cap_bytes: DEFAULT_RELAY_CAP_BYTES,
        }
    }
}

/// One hop request (§3 step 4). `token` is the bearer token the pump
/// demands on the CONNECT line; `budgets` bound the whole hop.
#[derive(Debug, Clone)]
pub struct HopRequest<'a> {
    /// Monotonic hop counter for the journal.
    pub hop: u64,
    /// The model-supplied URL, journalled verbatim.
    pub url: String,
    /// The origin host (lowercase DNS name or IP literal).
    pub host: String,
    /// The origin port.
    pub port: u16,
    /// Which door.
    pub mode: EgressMode,
    /// What for.
    pub purpose: EgressPurpose,
    /// The bearer token the pump demands.
    pub token: &'a str,
    /// Wall and relay budgets.
    pub budgets: HopBudgets,
}

/// Whether this build can open direct egress at all (INV-52): true only
/// with the `net` feature. Callers (P-39g) refuse `web.mode = direct` at
/// config load when this is false.
pub fn direct_egress_available() -> bool {
    cfg!(feature = "net")
}

// ---------------------------------------------------------------------------
// open_hop (§3 steps 4–5) and the pump.
// ---------------------------------------------------------------------------

/// Journal one refusal (no chosen address, no `resolved` payload).
fn journal_refuse<L>(log: &L, req: &HopRequest<'_>, reason: RefuseReason) -> Result<(), HopRefused>
where
    L: EgressLog + ?Sized,
{
    journal_refuse_with(log, req, reason, Vec::new())
}

/// Journal one refusal carrying the full resolver answer.
fn journal_refuse_with<L>(
    log: &L,
    req: &HopRequest<'_>,
    reason: RefuseReason,
    resolved: Vec<IpAddr>,
) -> Result<(), HopRefused>
where
    L: EgressLog + ?Sized,
{
    log.append(&EgressRecord {
        hop: req.hop,
        decision: EgressDecision::Refuse(reason),
        url: req.url.clone(),
        host: req.host.clone(),
        port: req.port,
        mode: req.mode,
        purpose: req.purpose,
        resolved,
        ip: None,
    })
    .map_err(HopRefused::Log)
}

/// The decision phase of one hop (§3 steps 1–3): the build-capability
/// check, the search-endpoint loopback waiver (no resolution), or one
/// resolver call with every answer classified (INV-44); then the decision
/// journalled FIRST (INV-43). Everything measured stays out: no socket is
/// bound and no thread is started.
///
/// This is the exact decision logic [`open_hop`] runs — one function, so
/// the offline audit (P-39j, INV-51) recomputes and re-journals precisely
/// what the live run decided, and then re-feeds the pump outcome.
pub struct HopPlan {
    /// The full resolver answer the decision classified (empty for the
    /// search-endpoint waiver).
    pub resolved: Vec<IpAddr>,
    /// The classified address the pump may dial.
    pub chosen: IpAddr,
}

/// Recompute and re-journal one hop's decision, binding nothing (§9,
/// INV-51). Errors carry the same variants [`open_hop`] would return; the
/// refusal, when journalled, is byte-identical to the live one.
pub fn replay_hop<L, R>(log: &L, resolver: &R, req: &HopRequest<'_>) -> Result<HopPlan, HopRefused>
where
    L: EgressLog + ?Sized,
    R: Resolver + ?Sized,
{
    // Build-capability refusal (INV-52): before anything else, before any
    // journalling — the build's silence about the network is total.
    if req.mode == EgressMode::Direct && !direct_egress_available() {
        return Err(HopRefused::NoDirectEgress);
    }

    // Search-endpoint mode (P-39h): the host is a user-configured loopback
    // IP (SearXNG on `127.0.0.1` or `[::1]`), so no resolution happens and
    // the loopback-classification waiver never applies to anything else.
    // The host must already be an address: a name here would mean a DNS
    // lookup this mode does not do, so it is refused (fail closed).
    let (resolved, chosen) = if req.mode == EgressMode::SearchEndpoint {
        match req.host.parse::<std::net::IpAddr>() {
            Ok(ip) if ip.is_loopback() => (Vec::new(), ip),
            _ => {
                journal_refuse(log, req, RefuseReason::NoAddress)?;
                return Err(HopRefused::Resolve(
                    "search endpoint host must be a loopback IP".into(),
                ));
            }
        }
    } else {
        open_hop_resolved(log, resolver, req)?
    };

    // Journal allow BEFORE anything is bound or dialled (INV-43). A failed
    // append refuses the hop outright.
    log.append(&EgressRecord {
        hop: req.hop,
        decision: EgressDecision::Allow,
        url: req.url.clone(),
        host: req.host.clone(),
        port: req.port,
        mode: req.mode,
        purpose: req.purpose,
        resolved: resolved.clone(),
        ip: Some(chosen),
    })
    .map_err(HopRefused::Log)?;
    Ok(HopPlan { resolved, chosen })
}

/// Open one egress hop (§3 steps 4–5): resolve once, classify every
/// address, journal the decision FIRST (INV-43), then bind the one-shot
/// loopback pump and return it while the pump thread runs.
///
/// The caller drives the fetcher against [`HopPump::port`] and then calls
/// [`HopPump::join`] for the hop outcome. The port is known before this
/// returns; whether the fetcher's byte exchange succeeded is known at
/// `join`.
pub fn open_hop<L, R, C>(
    log: &L,
    resolver: &R,
    connector: C,
    req: &HopRequest<'_>,
) -> Result<HopPump, HopRefused>
where
    L: EgressLog + ?Sized,
    R: Resolver + ?Sized,
    C: Connector + Send + 'static,
{
    // The decision (§3 steps 1–3), shared with the audit's replay:
    // build-capability check, resolution and classification, and the
    // journalled allow (INV-43).
    let plan = replay_hop(log, resolver, req)?;
    let (resolved, chosen) = (plan.resolved, plan.chosen);

    // Bind the one-shot pump on loopback and hand it to a thread.
    let listener =
        TcpListener::bind((PUMP_BIND_HOST, 0)).map_err(|e| HopRefused::Bind(e.to_string()))?;
    let port = listener
        .local_addr()
        .map_err(|e| HopRefused::Bind(e.to_string()))?
        .port();
    let connect_addr = SocketAddr::new(chosen, req.port);
    let host_port = format!("{}:{}", req.host, req.port);
    let token = req.token.to_string();
    let budgets = req.budgets;
    let handle = thread::Builder::new()
        .name("egress-pump".to_string())
        .spawn({
            let resolved = resolved.clone();
            move || {
                pump_run(
                    listener,
                    connector,
                    &resolved,
                    connect_addr,
                    host_port,
                    token,
                    budgets,
                )
            }
        })
        .map_err(|e| HopRefused::Spawn(e.to_string()))?;
    Ok(HopPump {
        port,
        resolved,
        chosen,
        handle,
    })
}

/// The resolve-then-classify path for the non-search modes (§4.3): resolve
/// once per hop, classify the WHOLE answer (INV-44), journaling every
/// refusal. The pump never re-resolves.
fn open_hop_resolved<L, R>(
    log: &L,
    resolver: &R,
    req: &HopRequest<'_>,
) -> Result<(Vec<IpAddr>, IpAddr), HopRefused>
where
    L: EgressLog + ?Sized,
    R: Resolver + ?Sized,
{
    let resolved = match resolver.resolve(&req.host, req.port) {
        Ok(addrs) => addrs,
        Err(ResolveRefused::Timeout) => {
            journal_refuse(log, req, RefuseReason::DnsTimeout)?;
            return Err(HopRefused::DnsTimeout);
        }
        Err(ResolveRefused::Failed(why)) => {
            journal_refuse(log, req, RefuseReason::NoAddress)?;
            return Err(HopRefused::Resolve(why));
        }
    };
    let chosen = match classify_answer(&resolved) {
        Ok(ip) => ip,
        Err(AnswerRefused::Empty) => {
            journal_refuse_with(log, req, RefuseReason::NoAddress, resolved)?;
            return Err(HopRefused::NoAddress);
        }
        Err(AnswerRefused::NonGlobal { ip, class }) => {
            journal_refuse_with(log, req, RefuseReason::NonGlobalAddress, resolved)?;
            return Err(HopRefused::NonGlobalAddress { ip, class });
        }
    };
    Ok((resolved, chosen))
}

/// A running pump: the loopback port the fetcher dials, and the future hop
/// outcome. Dropping it detaches the pump thread (the wall budget ends it
/// either way); `join` is the normal path.
#[derive(Debug)]
pub struct HopPump {
    port: u16,
    resolved: Vec<IpAddr>,
    chosen: IpAddr,
    handle: JoinHandle<HopIo>,
}

impl HopPump {
    /// The loopback port the fetcher connects to.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Wait for the pump to end and report the hop outcome.
    pub fn join(self) -> HopIo {
        let Self {
            resolved,
            chosen,
            handle,
            ..
        } = self;
        match handle.join() {
            Ok(io) => io,
            // The pump never panics (no panics in this crate's production
            // code); a vanished thread still reports, fail-closed.
            Err(_) => HopIo {
                resolved,
                chosen,
                bytes_up: 0,
                bytes_down: 0,
                elapsed: Duration::ZERO,
                ended: HopEnded::Aborted,
            },
        }
    }
}

/// How a hop ended (§3 step 7 family; `aborted` covers local transport
/// faults, mirroring the design note's `fetcher_failed` family).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopEnded {
    /// Both directions relayed to EOF under budget.
    Relayed,
    /// The CONNECT handshake failed the pump's checks (wrong token, wrong
    /// target, junk); nothing was dialled.
    Refused,
    /// Dialling the classified address failed.
    ConnectFailed,
    /// The wall budget ran out.
    Timeout,
    /// A direction filled its relay cap.
    Capped,
    /// A local transport fault ended the hop.
    Aborted,
}

impl HopEnded {
    /// The wire text for the hop record.
    pub fn as_str(self) -> &'static str {
        match self {
            HopEnded::Relayed => "relayed",
            HopEnded::Refused => "refused",
            HopEnded::ConnectFailed => "connect_failed",
            HopEnded::Timeout => "timeout",
            HopEnded::Capped => "capped",
            HopEnded::Aborted => "aborted",
        }
    }

    /// The hop outcome a journal names (P-46): the exact inverse of
    /// [`Self::as_str`], so a replay can re-feed what the pump recorded.
    /// `None` for any other text — not a shape the loop writes.
    pub fn from_wire(s: &str) -> Option<Self> {
        Some(match s {
            "relayed" => HopEnded::Relayed,
            "refused" => HopEnded::Refused,
            "connect_failed" => HopEnded::ConnectFailed,
            "timeout" => HopEnded::Timeout,
            "capped" => HopEnded::Capped,
            "aborted" => HopEnded::Aborted,
            _ => return None,
        })
    }
}

/// The outcome of one hop (§3 step 7). Byte counts are what actually moved;
/// `elapsed` is measured from pump start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopIo {
    /// The full resolver answer the hop was classified against.
    pub resolved: Vec<IpAddr>,
    /// The classified address the pump dialled.
    pub chosen: IpAddr,
    /// Bytes moved fetcher → origin.
    pub bytes_up: u64,
    /// Bytes moved origin → fetcher.
    pub bytes_down: u64,
    /// Wall time the pump ran.
    pub elapsed: Duration,
    /// How it ended.
    pub ended: HopEnded,
}

/// The pump body (§3 step 4): accept exactly one connection, check its
/// CONNECT line and token, dial the classified address, relay under
/// budgets, then close everything and drain any queued second connection.
fn pump_run<C: Connector>(
    listener: TcpListener,
    connector: C,
    resolved: &[IpAddr],
    connect_addr: SocketAddr,
    host_port: String,
    token: String,
    budgets: HopBudgets,
) -> HopIo {
    let started = Instant::now();
    let deadline = started + budgets.wall;
    let cap = budgets.relay_cap_bytes();
    let finish = |ended: HopEnded, bytes_up: u64, bytes_down: u64| HopIo {
        resolved: resolved.to_vec(),
        chosen: connect_addr.ip(),
        bytes_up,
        bytes_down,
        elapsed: started.elapsed(),
        ended,
    };

    if listener.set_nonblocking(true).is_err() {
        return finish(HopEnded::Aborted, 0, 0);
    }

    // Accept phase: wait for the ONE session connection.
    let mut session = loop {
        if remaining(deadline).is_none() {
            return finish(HopEnded::Timeout, 0, 0);
        }
        match listener.accept() {
            Ok((sock, _peer)) => break sock,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
            Err(_) => return finish(HopEnded::Aborted, 0, 0),
        }
    };

    // Handshake on the session connection.
    if session.set_nonblocking(false).is_err() {
        return finish(HopEnded::Aborted, 0, 0);
    }
    let _ = session.set_nodelay(true);
    let head = match read_head(&mut session, deadline) {
        Ok(head) => head,
        Err(HeadError::TimedOut) => return finish(HopEnded::Timeout, 0, 0),
        Err(HeadError::Io) => return finish(HopEnded::Aborted, 0, 0),
        Err(HeadError::Malformed) => {
            let _ = write_reply(&mut session, REPLY_403, deadline);
            return finish(HopEnded::Refused, 0, 0);
        }
    };
    if !request_line_ok(&head, &host_port) || !bearer_ok(&head, &token) {
        let _ = write_reply(&mut session, REPLY_403, deadline);
        return finish(HopEnded::Refused, 0, 0);
    }

    // Dial the classified address — and nothing else (INV-44).
    let mut origin = match connector.connect(connect_addr) {
        Ok(origin) => origin,
        Err(_) => {
            let _ = write_reply(&mut session, REPLY_502, deadline);
            return finish(HopEnded::ConnectFailed, 0, 0);
        }
    };
    let _ = origin.set_nodelay(true);
    if write_reply(&mut session, REPLY_200, deadline).is_err() {
        return finish(HopEnded::Aborted, 0, 0);
    }

    // Relay both directions under the cap and the wall budget. No thread
    // ever shuts a socket down under the other one: on Darwin a shutdown
    // under a sibling's blocked read surfaces as ECONNRESET and used to
    // audit clean hops as `aborted`. Each direction instead wakes at
    // least every `IO_SLICE`, sees the sibling-finished flag and then
    // stops orderly — the peer half of the session is already closed, so
    // no further byte is wanted. A genuine transport fault still ends
    // the hop `aborted`.
    let Ok(mut session_down) = session.try_clone() else {
        return finish(HopEnded::Aborted, 0, 0);
    };
    let Ok(mut origin_down) = origin.try_clone() else {
        return finish(HopEnded::Aborted, 0, 0);
    };
    let up_done = Arc::new(AtomicBool::new(false));
    let down_done = Arc::new(AtomicBool::new(false));
    let (down_tx, down_rx) = mpsc::channel();
    let sibling_up = up_done.clone();
    let sibling_down = down_done.clone();
    let down = thread::Builder::new()
        .name("egress-relay-down".to_string())
        .spawn(move || {
            let result = relay(
                &mut origin_down,
                &mut session_down,
                deadline,
                cap,
                &sibling_up,
            );
            sibling_down.store(true, Ordering::Release);
            let _ = down_tx.send(result);
        });
    let Ok(down_handle) = down else {
        return finish(HopEnded::Aborted, 0, 0);
    };

    let (bytes_up, up_end) = relay(&mut session, &mut origin, deadline, cap, &down_done);
    up_done.store(true, Ordering::Release);
    let (bytes_down, down_end) = match down_rx.recv_timeout(RELAY_JOIN) {
        Ok(pair) => pair,
        Err(_) => (0, DirectionEnd::Aborted),
    };
    drop(down_handle);
    // Both directions have ended and no thread is blocked on either
    // socket any more: close both before the drain phase.
    let _ = session.shutdown(Shutdown::Both);
    let _ = origin.shutdown(Shutdown::Both);

    let ended = match (up_end, down_end) {
        (DirectionEnd::Capped, _) | (_, DirectionEnd::Capped) => HopEnded::Capped,
        (DirectionEnd::Aborted, _) | (_, DirectionEnd::Aborted) => HopEnded::Aborted,
        (DirectionEnd::TimedOut, _) | (_, DirectionEnd::TimedOut) => HopEnded::Timeout,
        (DirectionEnd::Eof, DirectionEnd::Eof) => HopEnded::Relayed,
    };
    let io = finish(ended, bytes_up, bytes_down);

    // Drain phase: any connection queued behind the session is closed
    // immediately; after the drain the listener is gone, so later connects
    // are refused at the OS level. Exactly one session, ever.
    let drain_end = Instant::now() + DRAIN_WINDOW;
    while Instant::now() < drain_end {
        match listener.accept() {
            Ok((extra, _peer)) => drop(extra),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
            Err(_) => break,
        }
    }
    drop(listener);
    io
}

/// Time left before `deadline`, or `None` when it has passed.
fn remaining(deadline: Instant) -> Option<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        None
    } else {
        Some(left)
    }
}

/// Why reading a CONNECT head failed.
enum HeadError {
    /// The wall budget ran out mid-head.
    TimedOut,
    /// A local transport fault.
    Io,
    /// EOF, over-cap, non-UTF-8, or pipelined bytes after the terminator.
    Malformed,
}

/// Read the CONNECT head: bounded bytes, until the `CRLF CRLF` terminator,
/// with nothing after it.
fn read_head(stream: &mut TcpStream, deadline: Instant) -> Result<Vec<u8>, HeadError> {
    let mut head: Vec<u8> = Vec::new();
    let mut buf = [0u8; HEAD_CHUNK];
    loop {
        if head.len() >= CONNECT_HEAD_CAP_BYTES {
            return Err(HeadError::Malformed);
        }
        let Some(left) = remaining(deadline) else {
            return Err(HeadError::TimedOut);
        };
        if stream.set_read_timeout(Some(left.min(IO_SLICE))).is_err() {
            return Err(HeadError::Io);
        }
        match stream.read(&mut buf) {
            Ok(0) => return Err(HeadError::Malformed),
            Ok(n) => {
                let Some(chunk) = buf.get(..n) else {
                    return Err(HeadError::Io);
                };
                head.extend_from_slice(chunk);
                if let Some(pos) = head.windows(HEAD_END.len()).position(|w| w == HEAD_END) {
                    if pos + HEAD_END.len() != head.len() {
                        // Pipelined bytes after the CONNECT head: refuse.
                        return Err(HeadError::Malformed);
                    }
                    return Ok(head);
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(HeadError::Io),
        }
    }
}

/// Check the request line is exactly
/// `CONNECT <expected host:port> HTTP/1.1`.
fn request_line_ok(head: &[u8], host_port: &str) -> bool {
    let Ok(text) = std::str::from_utf8(head) else {
        return false;
    };
    let mut lines = text.split("\r\n");
    let Some(request) = lines.next() else {
        return false;
    };
    let mut parts = request.split_whitespace();
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("CONNECT"), Some(target), Some("HTTP/1.1"), None) => target == host_port,
        _ => false,
    }
}

/// Check the head carries exactly one `Proxy-Authorization: Bearer <token>`
/// header and it matches. A duplicated header is refused, not first-wins.
fn bearer_ok(head: &[u8], token: &str) -> bool {
    let Ok(text) = std::str::from_utf8(head) else {
        return false;
    };
    let mut found = false;
    for line in text.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("proxy-authorization") {
            continue;
        }
        if found {
            return false;
        }
        found = true;
        match value.trim().strip_prefix("Bearer ") {
            Some(bearer) => {
                if bearer != token {
                    return false;
                }
            }
            None => return false,
        }
    }
    found
}

/// Write one handshake reply before the wall budget ends.
fn write_reply(stream: &mut TcpStream, reply: &[u8], deadline: Instant) -> io::Result<()> {
    let Some(left) = remaining(deadline) else {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "hop wall budget exhausted",
        ));
    };
    stream.set_write_timeout(Some(left.min(IO_SLICE)))?;
    stream.write_all(reply)
}

/// How one relay direction ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectionEnd {
    /// Peer closed, or the sibling direction finished with the peer half
    /// of the session closed behind it (an orderly stop, not a fault).
    Eof,
    /// The cap stopped the direction.
    Capped,
    /// The wall budget stopped the direction.
    TimedOut,
    /// A local transport fault stopped the direction.
    Aborted,
}

/// Relay one direction (`from` → `to`) under the wall deadline and the
/// per-direction cap, stopping orderly when `sibling_done` is set (the
/// sibling thread finished its direction). Never writes a byte past the
/// cap; returns the count moved and how the direction ended.
fn relay(
    from: &mut TcpStream,
    to: &mut TcpStream,
    deadline: Instant,
    cap: u64,
    sibling_done: &AtomicBool,
) -> (u64, DirectionEnd) {
    let mut buf = [0u8; RELAY_CHUNK];
    let mut count: u64 = 0;
    loop {
        let Some(left) = remaining(deadline) else {
            return (count, DirectionEnd::TimedOut);
        };
        if sibling_done.load(Ordering::Acquire) {
            return (count, DirectionEnd::Eof);
        }
        let slice = left.min(IO_SLICE);
        if from.set_read_timeout(Some(slice)).is_err() {
            return (count, DirectionEnd::Aborted);
        }
        if to.set_write_timeout(Some(slice)).is_err() {
            return (count, DirectionEnd::Aborted);
        }
        match from.read(&mut buf) {
            Ok(0) => return (count, DirectionEnd::Eof),
            Ok(n) => {
                let room = cap - count;
                let take = if (n as u64) <= room { n } else { room as usize };
                let Some(chunk) = buf.get(..take) else {
                    return (count, DirectionEnd::Aborted);
                };
                if to.write_all(chunk).is_err() {
                    return (count, DirectionEnd::Aborted);
                }
                count += take as u64;
                if count >= cap {
                    return (count, DirectionEnd::Capped);
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return (count, DirectionEnd::Aborted),
        }
    }
}

#[cfg(test)]
mod tests;
