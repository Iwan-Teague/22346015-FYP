//! The MCP client state machine (P-37e, design note §3.2-§3.5, §4):
//! `initialize` → `notifications/initialized` → `tools/list`, then
//! `tools/call`, over a [`Transport`] the caller owns — send one frame,
//! receive before an absolute deadline, kill.
//!
//! **The seams.** This module is scanned by the purity gate as a pure
//! source (`scripts/ci/purity.sh` §2), so it names no facility of the I/O
//! or clock kind: bytes and time enter from outside, never reach outward.
//! The caller supplies two impls. A [`Clock`], whose one read anchors a
//! budget at "the current moment plus a [`Duration`]" and hands back an
//! opaque [`Clock::Time`]; the client only orders those handles, never
//! creates them. And a [`Transport`], which owns the server's pipes and
//! honours the deadlines: [`Transport::recv`] returns the next bytes of
//! the server's output before the given [`Clock::Time`] or fails with
//! [`TransportFault::Deadline`]. Because one deadline governs a whole
//! exchange — the client re-arms nothing between reads — a server that
//! trickles one byte at a time meets exactly the deadline a silent one
//! would (§4: absolute, never inter-byte).
//!
//! **Id discipline (§3.2).** Requests use integer ids from a per-connection
//! counter starting at 1 (`initialize` = 1); at most one request is
//! outstanding. A response whose id is not the outstanding one — unknown,
//! already answered, a string `"1"` for `1`, a negative — is a
//! [`Violation::UnknownId`]; a second response for the same id a
//! [`Violation::StrayResponse`]. Every violation kills the connection: the
//! client calls [`Transport::kill`] once, remembers the fault, and
//! replays it for every later call (fail-closed; a violated server is
//! never spoken to again).
//!
//! **Noise and refusals (§3.5, D3).** Every server-initiated request is
//! answered `-32601` (echoing its id exactly as received) and counted
//! against [`SERVER_REQUESTS_MAX`] per connection. Every notification —
//! and every server request, which is also non-response traffic — counts
//! against [`NOISE_MAX`] messages and [`NOISE_BYTES_MAX`] bytes **per
//! exchange**. A `notifications/cancelled` naming the outstanding id ends
//! that call as [`CallEnd::Cancelled`] without killing the connection;
//! anything else is dropped and counted.
//!
//! **Bounds (§4).** [`INIT_MAX`] caps the `initialize` result, and the
//! list walk takes at most [`LIST_PAGES_MAX`] cursor pages of at most
//! [`TOOLS_MAX`] tools with no name twice ([`Violation::ListOverrun`],
//! [`Violation::DuplicateTool`]). The caller's own request is bounded at
//! the frame cap and refused before sending — [`Fault::RequestTooLarge`],
//! which is not a fault of the server and kills nothing. Wall-clock
//! budgets arrive as [`Duration`]s and are anchored through the caller's
//! [`Clock`]; the per-page deadline never passes the whole-list one.

use std::collections::BTreeSet;
use std::time::Duration;

use serde_json::{Map, Value};

use crate::wire::{self, Frame, Incoming, PeerId, ResponsePayload, WireFault};

/// The largest an `initialize` result may be (§4: `INIT_MAX`, 64 KiB).
pub const INIT_MAX: usize = 64 * 1024;
/// The most cursor pages one `tools/list` walk may take (§4).
pub const LIST_PAGES_MAX: usize = 8;
/// The most tools one connection may list (§4: `TOOLS_MAX`).
pub const TOOLS_MAX: usize = 256;
/// The most non-response messages one exchange may carry (§4: `NOISE_MAX`).
pub const NOISE_MAX: u64 = 256;
/// The most non-response bytes one exchange may carry (§4: `NOISE_BYTES_MAX`).
pub const NOISE_BYTES_MAX: u64 = 1024 * 1024;
/// The most server-initiated requests one connection may carry (§4:
/// `SERVER_REQUESTS_MAX`).
pub const SERVER_REQUESTS_MAX: u64 = 16;

/// The one notification that can end a call short of a response (§3.5).
const CANCELLED_METHOD: &str = "notifications/cancelled";
/// Where `notifications/cancelled` names the request it cancels.
const REQUEST_ID_KEY: &str = "requestId";

/// The one clock seam (purity §2: no clock read in this crate). The
/// caller owns the real clock; the client only asks it to anchor a budget
/// and orders the handles it gets back.
pub trait Clock {
    /// An opaque moment: created by [`Clock::after`], compared with its
    /// peers, consumed by the [`Transport`] the handle was minted for.
    type Time: Copy + Ord;

    /// The moment `budget` from now (the trait's one read of the clock).
    fn after(&self, budget: Duration) -> Self::Time;
}

/// The one pipe seam: the client's whole view of the server (design note
/// §2). An implementation owns the pipes and the clock that backs
/// [`Clock::Time`]; the client drives it with bytes and deadlines only.
pub trait Transport {
    /// The deadline vocabulary this pipe speaks (the [`Clock`]'s
    /// [`Clock::Time`]).
    type Deadline: Copy;

    /// Writes one frame — the bytes without the newline, which is this
    /// side's framing — and flushes. A full or broken pipe is
    /// [`TransportFault::Closed`]: the server is gone for good. The write
    /// never blocks indefinitely (§16: at most one request is ever in
    /// flight, and the production relay buffers it).
    fn send(&mut self, frame: &[u8]) -> Result<(), TransportFault>;

    /// The next bytes of the server's output — any framing, any split —
    /// before the absolute `deadline`, or `None` at a clean end of the
    /// stream (the server exited, §4). The deadline covers this whole
    /// exchange: slow bytes meet the same deadline as silence (§4).
    fn recv(&mut self, deadline: Self::Deadline) -> Result<Option<Vec<u8>>, TransportFault>;

    /// Stops the server now. Idempotent; after it the connection is dead.
    fn kill(&mut self);
}

/// Why a pipe operation failed (§4): the deadline passed first, or the
/// pipe is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransportFault {
    /// The absolute deadline passed before the operation completed.
    #[error("the exchange passed its deadline")]
    Deadline,
    /// The pipe broke: the write failed or the other end is gone.
    #[error("the server's pipe is gone")]
    Closed,
}

/// How a server broke the protocol (§3.1-§3.5): each one kills the
/// connection and, downstream, quarantines the provider's capabilities.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Violation {
    /// The wire codec refused a frame ([`WireFault`]): over the line cap,
    /// not UTF-8, malformed, a batch array, a trailing CR, a bad shape.
    #[error("the wire codec refused a frame: {0}")]
    Frame(#[from] WireFault),
    /// A response named an id no outstanding request has (§3.2): unknown,
    /// already answered, or a string where the counter sent an integer.
    #[error("a response named an id no outstanding request has")]
    UnknownId,
    /// A second response for the one outstanding request (§3.2).
    #[error("a second response arrived for one request")]
    StrayResponse,
    /// More server-initiated requests than [`SERVER_REQUESTS_MAX`] (§3.5).
    #[error("the server sent more requests than the per-connection cap")]
    ServerRequestFlood,
    /// More non-response traffic than [`NOISE_MAX`] messages or
    /// [`NOISE_BYTES_MAX`] bytes in one exchange (§3.5).
    #[error("one exchange carried more noise than the caps allow")]
    Noise,
    /// The `initialize` result named another protocol version than the
    /// negotiated one (§3.3: refused, not negotiated again).
    #[error("the server named protocol version {got:?}, not the negotiated one")]
    VersionMismatch {
        /// What the server named, if it named a string at all.
        got: String,
    },
    /// The `initialize` result declared no `capabilities.tools` (§3.3).
    #[error("the server declared no tools capability")]
    NoToolsCapability,
    /// The `initialize` result passed [`INIT_MAX`] (§3.3, §4).
    #[error("the initialize result passed the 64 KiB cap")]
    InitOverCap,
    /// The server listed one tool name twice (§8: ambiguous, never
    /// "first wins").
    #[error("the server listed tool {0:?} twice")]
    DuplicateTool(String),
    /// The list walk passed [`LIST_PAGES_MAX`] pages or [`TOOLS_MAX`]
    /// tools (§4).
    #[error("the tool list passed the page or tool cap")]
    ListOverrun,
    /// A `tools/list` result is not an array of named tool objects, or
    /// its cursor is not a string (§3.3).
    #[error("a tools/list result is not an array of named tool objects")]
    BadListPage,
    /// The `initialize` response is not a successful result (unreachable
    /// through the codec's classification; kept for a total match).
    #[error("the initialize response is not a successful result")]
    BadInitialize,
    /// The request id counter passed the integer id range (never reached
    /// in a run; refused rather than wrapped).
    #[error("the request id counter passed its range")]
    IdSpaceExhausted,
}

/// Why the connection ended (§4): a violation, a deadline, a server that
/// ended or went away, or a handshake step the server cancelled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Fault {
    /// The server broke the protocol: killed, and the provider's
    /// capabilities are quarantined downstream.
    #[error("mcp protocol violation: {0}")]
    Violation(#[from] Violation),
    /// An absolute deadline passed: killed (§4).
    #[error("mcp: the exchange passed its deadline")]
    Timeout,
    /// The server's output ended mid-exchange (an exit or EOF): killed,
    /// and the call in flight renders as crashed (§4).
    #[error("mcp: the server ended mid-exchange")]
    Ended,
    /// The pipe broke under a write: killed (§4).
    #[error("mcp: the server's pipe is gone")]
    Closed,
    /// The server cancelled a connect or list step (§3.5): the step
    /// cannot complete, so the connection is killed as unusable. A
    /// cancelled `tools/call` is different: [`CallEnd::Cancelled`].
    #[error("mcp: the server cancelled a handshake step")]
    Cancelled,
    /// The server answered a handshake request with a JSON-RPC error.
    #[error("mcp: the server refused a handshake request with error {code}")]
    ServerRefused {
        /// The JSON-RPC error code the server sent.
        code: i64,
    },
    /// Our own request passed the frame cap: refused before sending (§4).
    /// Not the server's fault; nothing is killed.
    #[error("mcp: the request exceeds the 1 MiB frame cap")]
    RequestTooLarge,
    /// The caller stopped the connection deliberately (run end, drop).
    #[error("mcp: the connection was stopped")]
    Stopped,
}

/// What one exchange of [`Client::connect`] or [`Client::list`] produced:
/// a classified frame, or a call the server cancelled (§3.5).
enum Step {
    Frame(Frame),
    Cancelled,
}

/// How a call ended ([`Client::call`], §9 step 4). Not a verdict of the
/// run (§1.4, INV-28): the only pass verdict is `gate_outcome::GateOutcome`.
#[derive(Debug, Clone, PartialEq)]
pub enum CallEnd {
    /// The raw response line, exactly as received: the renderer's input
    /// and the journal's `mcp_response` blob (§9 step 5, §11). A JSON-RPC
    /// `error` rides here too — it is a rendered tool error, not a
    /// connection fault (§9 step 5).
    Response(String),
    /// The server sent `notifications/cancelled` naming this request's id
    /// (§3.5): the call ends now, as `MCP_RPC_ERROR` downstream; the
    /// connection stays usable.
    Cancelled,
}

/// One listed tool: its name and the whole entry object as presented
/// (§7.2: the pre-call relist compares whole entries, never two hashes).
#[derive(Debug, Clone, PartialEq)]
pub struct ToolEntry {
    /// The server-side tool name (the manifest's `mcp_name`).
    pub name: String,
    /// The whole entry object as the server presented it, untrusted.
    pub entry: Value,
}

/// What [`Client::connect`] established (§3.3): the negotiated protocol,
/// the untrusted `initialize` result (whose `serverInfo` and
/// `instructions` are journaled as blobs, never shown to a model), and
/// the baseline tool list.
#[derive(Debug, Clone, PartialEq)]
pub struct Connected {
    /// The protocol version both sides named (exactly the negotiated one).
    pub protocol: String,
    /// The `initialize` result as received, untrusted.
    pub init_result: Value,
    /// The baseline list, in presentation order.
    pub tools: Vec<ToolEntry>,
}

/// The per-exchange noise counters (§3.5): messages and bytes of
/// non-response traffic since the exchange began. Pure arithmetic, so the
/// caps are recomputed the same way everywhere.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Noise {
    msgs: u64,
    bytes: u64,
}

impl Noise {
    /// Counts one non-response frame of `len` bytes; over either cap is a
    /// [`Violation::Noise`].
    fn count(&mut self, len: usize) -> Result<(), Violation> {
        self.msgs = match self.msgs.checked_add(1) {
            Some(msgs) => msgs,
            None => return Err(Violation::Noise),
        };
        self.bytes = match self.bytes.checked_add(len as u64) {
            Some(bytes) => bytes,
            None => return Err(Violation::Noise),
        };
        match self.msgs > NOISE_MAX || self.bytes > NOISE_BYTES_MAX {
            true => Err(Violation::Noise),
            false => Ok(()),
        }
    }
}

/// Collects one `tools/list` page into `tools` (§3.3 step 4): every entry
/// must be an object naming itself with a string, no name may appear
/// twice in the whole walk, the walk is capped at [`TOOLS_MAX`] tools,
/// and a cursor must be a string if it is there at all. Returns the next
/// cursor, when the page names one.
fn collect_page(
    result: &Value,
    tools: &mut Vec<ToolEntry>,
    seen: &mut BTreeSet<String>,
) -> Result<Option<String>, Violation> {
    let entries = match result.get("tools").and_then(Value::as_array) {
        Some(entries) => entries,
        None => return Err(Violation::BadListPage),
    };
    for entry in entries {
        let obj = match entry.as_object() {
            Some(obj) => obj,
            None => return Err(Violation::BadListPage),
        };
        let name = match obj.get("name").and_then(Value::as_str) {
            Some(name) => name,
            None => return Err(Violation::BadListPage),
        };
        if tools.len() >= TOOLS_MAX {
            return Err(Violation::ListOverrun);
        }
        if !seen.insert(name.to_owned()) {
            return Err(Violation::DuplicateTool(name.to_owned()));
        }
        tools.push(ToolEntry {
            name: name.to_owned(),
            entry: entry.clone(),
        });
    }
    match result.get("nextCursor") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(next)) => Ok(Some(next.clone())),
        Some(_) => Err(Violation::BadListPage),
    }
}

/// The MCP client over one connection: ids, noise caps, bounds and the
/// kill-on-any-fault rule (§3.2-§3.5, §4). Generic over the caller's
/// [`Clock`] and the [`Transport`] whose deadlines that clock mints.
pub struct Client<C: Clock, T: Transport<Deadline = C::Time>> {
    clock: C,
    transport: T,
    /// The next request id (§3.2: starts at 1, `initialize` first).
    next_id: u64,
    /// The one request that may be answered (§3.2).
    outstanding: Option<u64>,
    /// Server-initiated requests so far, this connection (§3.5).
    server_requests: u64,
    /// Non-response traffic of the exchange in flight (§3.5).
    noise: Noise,
    /// The bounded line reader over the bytes [`Transport::recv`] yields.
    reader: wire::FrameReader,
    /// The fault that ended the connection, replayed forever after (§4).
    dead: Option<Fault>,
    /// The request id of the exchange seen last (P-37h: the provider's
    /// `McpRecord.request_id`, §9 step 6).
    last_id: Option<u64>,
    /// The noise count of the exchange seen last, reset-or-faulted (P-37h:
    /// the provider's `McpRecord.noise`).
    last_noise: u64,
}

impl<C: Clock, T: Transport<Deadline = C::Time>> Client<C, T> {
    /// A live client over `transport`, anchoring budgets with `clock`.
    pub fn new(clock: C, transport: T) -> Self {
        Client {
            clock,
            transport,
            next_id: 1,
            outstanding: None,
            server_requests: 0,
            noise: Noise::default(),
            reader: wire::FrameReader::new(),
            dead: None,
            last_id: None,
            last_noise: 0,
        }
    }

    /// Stops the connection deliberately (a run's stop path, §5.3): the
    /// transport is killed and every later call replays [`Fault::Stopped`].
    pub fn kill(&mut self) {
        self.transport.kill();
        self.dead = Some(Fault::Stopped);
    }

    /// Whether the connection has ended (any fault, or [`Client::kill`]).
    pub fn is_dead(&self) -> bool {
        self.dead.is_some()
    }

    /// The request id of the exchange seen last (P-37h): `None` before the
    /// first request. The provider journals it as `McpRecord.request_id`
    /// (§9 step 6), so the record names the frame the wire carried.
    pub fn last_request_id(&self) -> Option<u64> {
        self.last_id
    }

    /// The noise count of the exchange seen last (P-37h): server-originated
    /// frames between our request and its end, however the exchange ended.
    /// The provider journals it as `McpRecord.noise`.
    pub fn last_exchange_noise(&self) -> u64 {
        self.last_noise
    }

    /// The lifecycle handshake and the baseline list (§3.3): `initialize`
    /// naming exactly the negotiated `protocol` (else
    /// [`Violation::VersionMismatch`]), which must carry
    /// `capabilities.tools` and fit [`INIT_MAX`]; then
    /// `notifications/initialized`; then `tools/list` under the page and
    /// whole-list budgets. Any failure kills the connection.
    pub fn connect(
        &mut self,
        protocol: &str,
        client_version: &str,
        init: Duration,
        page: Duration,
        list: Duration,
    ) -> Result<Connected, Fault> {
        let init_deadline = self.clock.after(init);
        let step = self.request(
            |id| wire::encode_initialize(id, protocol, client_version),
            init_deadline,
        )?;
        let frame = match step {
            Step::Frame(frame) => frame,
            Step::Cancelled => return Err(self.die(Fault::Cancelled)),
        };
        if frame.line.len() > INIT_MAX {
            return Err(self.die(Fault::Violation(Violation::InitOverCap)));
        }
        let result = match &frame.message {
            Incoming::Response {
                payload: ResponsePayload::Result(value),
                ..
            } => value,
            Incoming::Response {
                payload: ResponsePayload::Error { code, .. },
                ..
            } => return Err(self.die(Fault::ServerRefused { code: *code })),
            _ => return Err(self.die(Fault::Violation(Violation::BadInitialize))),
        };
        let got = result
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if got != protocol {
            return Err(self.die(Fault::Violation(Violation::VersionMismatch {
                got: got.to_owned(),
            })));
        }
        if result
            .get("capabilities")
            .and_then(|caps| caps.get("tools"))
            .is_none()
        {
            return Err(self.die(Fault::Violation(Violation::NoToolsCapability)));
        }
        if let Err(fault) = self.transport.send(&wire::encode_initialized()) {
            return Err(self.die(ended(fault)));
        }
        let list_deadline = self.clock.after(list);
        let tools = self.list_bounded(page, list_deadline)?;
        Ok(Connected {
            protocol: protocol.to_owned(),
            init_result: result.clone(),
            tools,
        })
    }

    /// The whole `tools/list` walk (§3.3 step 4, §7.2): cursor pages under
    /// the per-page and whole-list budgets, the tool and page caps, no
    /// name twice. The provider re-lists with this before every call.
    pub fn list(&mut self, page: Duration, total: Duration) -> Result<Vec<ToolEntry>, Fault> {
        let list_deadline = self.clock.after(total);
        self.list_bounded(page, list_deadline)
    }

    /// One `tools/call` (§3.4, §9 step 4): the name and arguments were
    /// validated against the manifest before this sees them. A response
    /// — success or JSON-RPC error — comes back as its raw line for the
    /// renderer; a server cancellation ends the call as
    /// [`CallEnd::Cancelled`]. A deadline kills the connection (§4).
    pub fn call(
        &mut self,
        name: &str,
        args: &Map<String, Value>,
        budget: Duration,
    ) -> Result<CallEnd, Fault> {
        let deadline = self.clock.after(budget);
        match self.request(|id| wire::encode_call(id, name, args), deadline)? {
            Step::Frame(frame) => Ok(CallEnd::Response(frame.line)),
            Step::Cancelled => Ok(CallEnd::Cancelled),
        }
    }

    /// The `tools/list` walk against an already-anchored whole-list
    /// deadline, so [`Client::connect`]'s list phase shares the connect
    /// budget's shape (§4: page 5 s, whole list 15 s, both absolute).
    fn list_bounded(
        &mut self,
        page: Duration,
        list_deadline: C::Time,
    ) -> Result<Vec<ToolEntry>, Fault> {
        let mut tools: Vec<ToolEntry> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0usize;
        loop {
            // A page never waits past the whole-list deadline: the smaller
            // of the two absolute bounds governs this exchange (§4).
            let deadline = self.clock.after(page).min(list_deadline);
            let carried = cursor.clone();
            let step = self.request(|id| wire::encode_list(id, carried.as_deref()), deadline)?;
            let frame = match step {
                Step::Frame(frame) => frame,
                Step::Cancelled => return Err(self.die(Fault::Cancelled)),
            };
            pages += 1;
            let result = match &frame.message {
                Incoming::Response {
                    payload: ResponsePayload::Result(value),
                    ..
                } => value,
                Incoming::Response {
                    payload: ResponsePayload::Error { code, .. },
                    ..
                } => return Err(self.die(Fault::ServerRefused { code: *code })),
                _ => return Err(self.die(Fault::Violation(Violation::BadListPage))),
            };
            let next = collect_page(result, &mut tools, &mut seen)
                .map_err(|violation| self.die(Fault::Violation(violation)))?;
            match next {
                Some(next) if pages < LIST_PAGES_MAX => cursor = Some(next),
                // A page naming a successor after the cap: the walk would
                // need a page beyond LIST_PAGES_MAX (§4).
                Some(_) => return Err(self.die(Fault::Violation(Violation::ListOverrun))),
                None => return Ok(tools),
            }
        }
    }

    /// Mints the next request id, replaying a recorded fault first (§4:
    /// a dead connection is never reused).
    fn mint(&mut self) -> Result<u64, Fault> {
        if let Some(fault) = self.dead.clone() {
            return Err(fault);
        }
        let id = self.next_id;
        match self.next_id.checked_add(1) {
            Some(next) => self.next_id = next,
            None => return Err(self.die(Fault::Violation(Violation::IdSpaceExhausted))),
        }
        self.last_id = Some(id);
        Ok(id)
    }

    /// Sends one encoded request and waits its exchange out (§3.2-§3.5):
    /// the shared loop of `initialize`, `tools/list` and `tools/call`.
    fn request(
        &mut self,
        build: impl FnOnce(u64) -> Vec<u8>,
        deadline: C::Time,
    ) -> Result<Step, Fault> {
        let id = self.mint()?;
        let bytes = build(id);
        self.run(id, &bytes, deadline)
    }

    /// The exchange loop for the request already encoded as `bytes`: send,
    /// then read, classify and file every frame until the one response
    /// that matches `id` — answering and counting server requests,
    /// counting noise, honouring a cancellation — or the first fault,
    /// which kills the connection (§4).
    fn run(&mut self, id: u64, bytes: &[u8], deadline: C::Time) -> Result<Step, Fault> {
        let id_i64 = match i64::try_from(id) {
            Ok(id_i64) => id_i64,
            Err(_) => return Err(self.die(Fault::Violation(Violation::IdSpaceExhausted))),
        };
        // Our own request is bounded like a frame (§4); refusing it is not
        // the server's fault, so nothing is killed.
        if bytes.len() > wire::FRAME_MAX {
            return Err(Fault::RequestTooLarge);
        }
        self.noise = Noise::default();
        self.outstanding = Some(id);
        if let Err(fault) = self.transport.send(bytes) {
            return Err(self.die(ended(fault)));
        }
        // The exchange's state: still open, answered by the matching
        // response, or ended by our own cancellation (§3.5).
        enum Exchange {
            Open,
            Won(Frame),
            Cancelled,
        }
        let mut exchange = Exchange::Open;
        loop {
            let chunk = match self.transport.recv(deadline) {
                Ok(Some(chunk)) => chunk,
                Ok(None) => return Err(self.die(Fault::Ended)),
                Err(fault) => return Err(self.die(ended(fault))),
            };
            let frames = match self.reader.feed(&chunk) {
                Ok(frames) => frames,
                Err(fault) => {
                    return Err(self.die(Fault::Violation(Violation::Frame(fault))));
                }
            };
            for frame in frames {
                match frame.message {
                    Incoming::Response { id: ref peer, .. } => {
                        if *peer != PeerId::Int(id_i64) {
                            return Err(self.die(Fault::Violation(Violation::UnknownId)));
                        }
                        exchange = match exchange {
                            Exchange::Open => Exchange::Won(frame),
                            // A second response for the answered request
                            // (§3.2), in this or a later read.
                            Exchange::Won(_) | Exchange::Cancelled => {
                                return Err(self.die(Fault::Violation(Violation::StrayResponse)));
                            }
                        };
                    }
                    Incoming::ServerRequest { id: peer, .. } => {
                        // D3: never served, always refused, always counted;
                        // over the per-connection cap the server is
                        // hostile (§3.5).
                        if let Err(violation) = self.noise.count(frame.line.len()) {
                            return Err(self.die(Fault::Violation(violation)));
                        }
                        self.server_requests = match self.server_requests.checked_add(1) {
                            Some(count) => count,
                            None => {
                                return Err(
                                    self.die(Fault::Violation(Violation::ServerRequestFlood))
                                );
                            }
                        };
                        let reply = wire::encode_method_not_found(&peer);
                        if let Err(fault) = self.transport.send(&reply) {
                            return Err(self.die(ended(fault)));
                        }
                        if self.server_requests > SERVER_REQUESTS_MAX {
                            return Err(self.die(Fault::Violation(Violation::ServerRequestFlood)));
                        }
                    }
                    Incoming::Notification { method, params } => {
                        if let Err(violation) = self.noise.count(frame.line.len()) {
                            return Err(self.die(Fault::Violation(violation)));
                        }
                        // The one notification that acts (§3.5): a
                        // cancellation of OUR outstanding id ends the
                        // exchange; any other method, or a cancellation
                        // naming some other id, is only counted.
                        if method == CANCELLED_METHOD
                            && params
                                .as_ref()
                                .and_then(|params| params.get(REQUEST_ID_KEY))
                                .and_then(Value::as_u64)
                                == Some(id)
                            && matches!(exchange, Exchange::Open)
                        {
                            exchange = Exchange::Cancelled;
                        }
                    }
                }
            }
            match exchange {
                Exchange::Open => continue,
                Exchange::Won(_) | Exchange::Cancelled => {
                    self.last_noise = self.noise.msgs;
                    self.noise = Noise::default();
                    self.outstanding = None;
                    return Ok(match exchange {
                        Exchange::Won(frame) => Step::Frame(frame),
                        _ => Step::Cancelled,
                    });
                }
            }
        }
    }

    /// Kills the connection and records `fault` as its permanent answer
    /// (§4: a violated, timed-out, ended or stopped server is never
    /// spoken to again).
    fn die(&mut self, fault: Fault) -> Fault {
        // The provider's record cites the noise the dying exchange carried.
        self.last_noise = self.noise.msgs;
        self.transport.kill();
        self.dead = Some(fault.clone());
        fault
    }
}

/// Maps a [`TransportFault`] onto the connection fault it means: the
/// deadline is the caller's budget spent, a broken pipe is the server
/// going away (§4).
fn ended(fault: TransportFault) -> Fault {
    match fault {
        TransportFault::Deadline => Fault::Timeout,
        TransportFault::Closed => Fault::Closed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// One named entry, the shape every real page carries.
    fn entry(name: &str) -> Value {
        serde_json::json!({"name": name, "description": "d"})
    }

    /// A transport whose server side is a script of queued chunks (P-37h:
    /// the id and noise accessors, against a deterministic peer). Pure, so
    /// it may live inside this scanned crate; the hostile wire suites live
    /// in the fixture package.
    struct Scripted {
        chunks: VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
    }
    impl Transport for Scripted {
        type Deadline = u64;
        fn send(&mut self, frame: &[u8]) -> Result<(), TransportFault> {
            self.sent.push(frame.to_vec());
            Ok(())
        }
        fn recv(&mut self, _deadline: u64) -> Result<Option<Vec<u8>>, TransportFault> {
            Ok(self.chunks.pop_front())
        }
        fn kill(&mut self) {}
    }

    /// Counts milliseconds up from zero; deadlines never move backwards.
    struct StepClock;
    impl Clock for StepClock {
        type Time = u64;
        fn after(&self, budget: Duration) -> u64 {
            u64::try_from(budget.as_millis()).unwrap_or(u64::MAX)
        }
    }

    fn response(id: u64, result: Value) -> String {
        serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string()
    }

    #[test]
    fn client_accessors_track_request_ids_and_noise() {
        // initialize (id 1), then one noise notification ahead of the list
        // page (id 2): the record facts a provider cites are the last
        // exchange's.
        let script = Scripted {
            chunks: VecDeque::from(vec![
                format!(
                    "{}\n",
                    response(
                        1,
                        serde_json::json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}})
                    )
                )
                .into_bytes(),
                format!(
                    "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{{}}}}\n{}\n",
                    response(2, serde_json::json!({"tools": [entry("echo")]}))
                )
                .into_bytes(),
            ]),
            sent: Vec::new(),
        };
        let mut client = Client::new(StepClock, script);
        let connected = client
            .connect(
                "2025-06-18",
                "0.0.1",
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(5),
            )
            .expect("scripted connect");
        assert_eq!(connected.tools.len(), 1);
        assert_eq!(client.last_request_id(), Some(2));
        assert_eq!(client.last_exchange_noise(), 1);
        // A fresh exchange resets the count; the id climbs.
        client
            .call("echo", &Map::new(), Duration::from_secs(1))
            .expect_err("the script has no answer for a call");
        assert_eq!(client.last_request_id(), Some(3));
        assert_eq!(client.last_exchange_noise(), 0);
    }

    #[test]
    fn client_collect_page_walks_names_and_cursors() {
        let mut tools = Vec::new();
        let mut seen = BTreeSet::new();
        let page = serde_json::json!({"tools": [entry("echo"), entry("add")]});
        assert_eq!(collect_page(&page, &mut tools, &mut seen), Ok(None));
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "echo");
        assert_eq!(tools[1].entry, entry("add"));
        // A string cursor is carried; an absent or null one ends the walk.
        let paged = serde_json::json!({"tools": [], "nextCursor": "p1"});
        assert_eq!(
            collect_page(&paged, &mut tools, &mut seen),
            Ok(Some("p1".to_owned()))
        );
        let nulled = serde_json::json!({"tools": [], "nextCursor": Value::Null});
        assert_eq!(collect_page(&nulled, &mut tools, &mut seen), Ok(None));
    }

    #[test]
    fn client_collect_page_refuses_bad_shapes() {
        let mut tools = Vec::new();
        let mut seen = BTreeSet::new();
        // No tools array, an unnamed entry, a non-object entry, a
        // non-string cursor: all refused, nothing collected.
        for page in [
            serde_json::json!({}),
            serde_json::json!({"tools": [{"description": "d"}]}),
            serde_json::json!({"tools": ["echo"]}),
            serde_json::json!({"tools": [], "nextCursor": 3}),
        ] {
            let mut fresh = Vec::new();
            assert_eq!(
                collect_page(&page, &mut fresh, &mut seen),
                Err(Violation::BadListPage)
            );
            assert!(fresh.is_empty());
        }
        // A name twice in one page is the ambiguous listing of §8.
        let dup = serde_json::json!({"tools": [entry("echo"), entry("echo")]});
        assert_eq!(
            collect_page(&dup, &mut tools, &mut seen),
            Err(Violation::DuplicateTool("echo".to_owned()))
        );
    }

    #[test]
    fn client_tool_cap_enforced_across_pages() {
        // TOOLS_MAX binds the WHOLE walk, page by page: the cap lands on
        // the entry that would be the TOOLS_MAX+1-th, whatever split the
        // server chose.
        let mut tools = Vec::new();
        let mut seen = BTreeSet::new();
        for page in 0..(TOOLS_MAX / 4) {
            // Rename per page so the names stay unique across the walk.
            let page = serde_json::json!({
                "tools": (0..4).map(|i| entry(&format!("t{}_{}", page, i)))
                    .collect::<Vec<Value>>(),
                "nextCursor": format!("p{page}"),
            });
            collect_page(&page, &mut tools, &mut seen).expect("page under the cap");
        }
        assert_eq!(tools.len(), TOOLS_MAX);
        let one_more = serde_json::json!({"tools": [entry("over")]});
        assert_eq!(
            collect_page(&one_more, &mut tools, &mut seen),
            Err(Violation::ListOverrun)
        );
    }

    #[test]
    fn client_noise_cap_counts_lines_and_bytes() {
        let mut noise = Noise::default();
        for _ in 0..NOISE_MAX {
            assert_eq!(noise.count(8), Ok(()));
        }
        assert_eq!(noise.count(8), Err(Violation::Noise));
        // The byte cap bites on its own: one huge frame over
        // NOISE_BYTES_MAX, well under the message count.
        let mut noise = Noise::default();
        assert_eq!(
            noise.count(NOISE_BYTES_MAX as usize),
            Ok(()),
            "a frame AT the cap still fits"
        );
        assert_eq!(noise.count(1), Err(Violation::Noise));
        // The counters refuse to wrap an absurd length.
        let mut noise = Noise::default();
        assert_eq!(noise.count(usize::MAX), Err(Violation::Noise));
    }
}
