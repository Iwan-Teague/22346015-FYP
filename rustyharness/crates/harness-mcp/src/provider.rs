//! The MCP tool provider (design note §7-§9, P-37h): the adapter that
//! turns an admitted, journaled call into exactly one `tools/call`
//! exchange against the server a [`McpConnector`] dialed.
//!
//! Order of business, fail closed at every step (§8 before §7.2):
//!
//! 1. a provider that is not connected, or whose connection has faulted,
//!    refuses or errors — a dead server is never spoken to again (§4);
//! 2. a quarantined capability is refused (`Quarantined`);
//! 3. a capability this provider was not admitted for is refused
//!    (`UnknownCapability`) before ANY wire traffic: the manifest's
//!    capability id is the only name the loop may send, and the server's
//!    own tool name never leaves this file (§8, D5);
//! 4. the pre-call relist (§7.2): the whole list is digested against the
//!    connect-time baseline; drift quarantines the called capability when
//!    its entry changed or vanished, and merely counts the unlisted tools
//!    that appeared. The drift facts are exposed for the driver to journal
//!    ([`McpProvider::take_drift`], the `McpDrift` record of §7.2);
//! 5. one `tools/call`; the raw response line is rendered by
//!    [`crate::render`], and the output re-attributed to the capability id
//!    that earned the call (the renderer's `Source::Tool("mcp")` is an
//!    internal name, never the model's view).
//!
//! The provider never panics on server misbehavior: every fault of the
//! client maps onto a [`ToolStatus`], per §4.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use harness_core::{sha256, Digest, Source, Untrusted};
use harness_journal::Journaled;
use harness_manifest::ProviderName;
use harness_policy::{Authorized, Call};
use harness_tools::builtin::code;
use harness_tools::{
    InvokeCtx, McpRecord, RefusalKind, ToolError, ToolProvider, ToolResult, ToolStatus,
};

use crate::client::{CallEnd, Client, Clock, Fault, ToolEntry, Transport};
use crate::connect::{ConnectorError, McpConnector};
use crate::{render, wire};

type Args = serde_json::Map<String, serde_json::Value>;

/// The budgets and bounds one provider runs with (§4). The driver owns the
/// step deadline ([`InvokeCtx`]); these are this connection's own budgets.
#[derive(Debug, Clone)]
pub struct McpConfig {
    /// The protocol version to name in `initialize` (already negotiated
    /// against the manifest by the admission slice).
    pub protocol: String,
    /// The client version to name in `initialize`.
    pub client_version: String,
    /// The `initialize` budget.
    pub init: Duration,
    /// The per-`tools/list`-page budget.
    pub page: Duration,
    /// The whole-relist budget.
    pub list: Duration,
    /// The per-`tools/call` budget.
    pub call: Duration,
    /// The rendered-result cap (clamped by the renderer to
    /// [`render::MCP_RESULT_DEFAULT`]).
    pub result_cap: usize,
}

/// What the pre-call relist saw that the baseline did not (§7.2). Tool
/// names are the server's own (`mcp_name`); the driver maps them back
/// through the manifest when it journals `McpDrift`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftInfo {
    /// Admitted tools whose WHOLE entry changed since connect.
    pub changed: Vec<String>,
    /// Admitted tools that vanished from the listing.
    pub removed: Vec<String>,
    /// Tools the listing now carries that the baseline did not (counted,
    /// dropped, never called — §7.2: a new tool is not drift against the
    /// admitted set).
    pub unlisted: u64,
    /// The digest of the listing that showed the drift.
    pub list_sha256: Digest,
}

/// Why a provider could not reach its handshake (§6).
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// The connector could not start the server.
    #[error(transparent)]
    Connector(#[from] ConnectorError),
    /// The handshake or baseline list failed; the connection is dead.
    #[error("the MCP handshake failed: {0}")]
    Handshake(#[from] Fault),
}

/// The MCP adapter over one dialed server (§7). Generic over the connector
/// so the confined connector (P-37l) and the test connector plug in without
/// this file knowing threads, pipes or processes.
pub struct McpProvider<C: McpConnector> {
    connector: C,
    config: McpConfig,
    namespace: ProviderName,
    /// The admitted capability id -> the server tool name it may call
    /// (§8). Nothing outside this map is ever sent.
    admitted: BTreeMap<String, String>,
    /// The connect-time listing, per tool name: the baseline the pre-call
    /// relist is compared against, whole entry by whole entry (§7.2).
    baseline_entries: BTreeMap<String, serde_json::Value>,
    /// The digest of the baseline listing (canonical JSON of the whole
    /// array, in presented order).
    baseline_digest: Digest,
    /// The connection; `None` until [`McpProvider::connect`] succeeds.
    client: Option<Client<C::Clock, C::Transport>>,
    /// Capability ids this provider has quarantined (§7.2); they refuse
    /// with `Quarantined` from then on.
    quarantine: BTreeSet<String>,
    /// The drift the last relist saw, waiting for the driver to journal it.
    drift: Option<DriftInfo>,
}

impl<C: McpConnector> McpProvider<C> {
    /// A provider for `admitted` (capability id -> server tool name). It is
    /// NOT connected yet: dialing needs the call's sandbox witness.
    pub fn new(
        connector: C,
        config: McpConfig,
        namespace: ProviderName,
        admitted: BTreeMap<String, String>,
    ) -> Self {
        McpProvider {
            connector,
            config,
            namespace,
            admitted,
            baseline_entries: BTreeMap::new(),
            baseline_digest: sha256(b""),
            client: None,
            quarantine: BTreeSet::new(),
            drift: None,
        }
    }

    /// Dials the server and runs the lifecycle handshake plus the baseline
    /// list (§3.3, §7.2). Any failure leaves the provider unconnected.
    pub fn connect(&mut self, conformed: &harness_sandbox::Conformed) -> Result<(), ConnectError> {
        let transport = self.connector.dial(conformed)?;
        let mut client = Client::new(self.connector.clock(), transport);
        let connected = client.connect(
            &self.config.protocol,
            &self.config.client_version,
            self.config.init,
            self.config.page,
            self.config.list,
        )?;
        self.baseline_digest = canonical_tools_sha256(&connected.tools);
        self.baseline_entries = connected
            .tools
            .iter()
            .map(|entry| (entry.name.clone(), entry.entry.clone()))
            .collect();
        self.client = Some(client);
        Ok(())
    }

    /// Whether the connection has faulted (§4): every further call refuses
    /// without touching the wire.
    pub fn is_dead(&self) -> bool {
        self.client.as_ref().is_some_and(|client| client.is_dead())
    }

    /// The drift the last relist saw, if any (§7.2). Taken, so the driver
    /// journals `McpDrift` exactly once per drift event.
    pub fn take_drift(&mut self) -> Option<DriftInfo> {
        self.drift.take()
    }

    /// The capability ids quarantined so far (§7.2).
    pub fn quarantined(&self) -> &BTreeSet<String> {
        &self.quarantine
    }

    /// A bare refusal result (static words only, attributed to the
    /// capability that was refused).
    fn refused(capability: &str, reason: RefusalKind, why: &'static str) -> ToolResult {
        let output = Untrusted::new(why.as_bytes().to_vec(), Source::Tool(capability.to_owned()));
        ToolResult {
            status: ToolStatus::Refused { reason },
            digest: sha256(why.as_bytes()),
            output,
            truncated: false,
            read: None,
            edits: Vec::new(),
            exec: None,
            mcp: None,
            web: None,
        }
    }
}

/// Maps a client fault onto its result and closes the connection when §4
/// says so (a free function: it borrows only the client, so the provider's
/// own state stays out of the borrow).
fn fault_result<Ck, T>(
    client: &mut Client<Ck, T>,
    capability: &str,
    mcp_name: &str,
    args: &Args,
    fault: Fault,
    list_sha256: Digest,
) -> ToolResult
where
    Ck: Clock,
    T: Transport<Deadline = Ck::Time>,
{
    let (status, why, dead) = match &fault {
        Fault::Timeout => (
            ToolStatus::Timeout,
            "mcp: the tool passed its deadline",
            true,
        ),
        // Our own request over the frame cap is not the server's fault;
        // the connection stays up (§4).
        Fault::RequestTooLarge => (
            ToolStatus::Error {
                code: code::MCP_RPC_ERROR,
            },
            "mcp: the request exceeds the frame cap",
            false,
        ),
        _ => (
            ToolStatus::Crashed { signal: None },
            "mcp: the server ended the connection",
            true,
        ),
    };
    if dead {
        client.kill();
    }
    // The record cites the exchange even when it never finished: the id
    // the request carried, and whatever noise the dying exchange gathered.
    // `0` as the id means none was ever minted.
    let request_id = client.last_request_id().unwrap_or(0);
    let request_bytes = wire::encode_call(request_id, mcp_name, args);
    let output = Untrusted::new(why.as_bytes().to_vec(), Source::Tool(capability.to_owned()));
    ToolResult {
        status,
        digest: sha256(why.as_bytes()),
        output,
        truncated: false,
        read: None,
        edits: Vec::new(),
        exec: None,
        mcp: Some(McpRecord {
            request_id,
            request_sha256: sha256(&request_bytes),
            response_frame: None,
            list_sha256,
            noise: client.last_exchange_noise(),
        }),
        web: None,
    }
}

impl<C: McpConnector> ToolProvider for McpProvider<C> {
    fn namespace(&self) -> &ProviderName {
        &self.namespace
    }

    fn invoke(
        &mut self,
        call: Journaled<Authorized<Call>>,
        _ctx: &InvokeCtx<'_>,
    ) -> Result<ToolResult, ToolError> {
        // The step deadline is the driver's to enforce (it brackets the
        // whole tool step); this exchange runs on the connection's own
        // budgets. The provider never names a wall clock — the purity gate
        // keeps this crate clock-free.
        let work = call.call().call();
        let capability = work.capability.as_str();
        let mcp_name = match self.admitted.get(capability) {
            Some(mcp_name) => mcp_name.as_str(),
            // §8: not admitted here means no wire traffic at all — the
            // relist is part of the traffic.
            None => {
                return Ok(Self::refused(
                    capability,
                    RefusalKind::UnknownCapability,
                    "mcp: the capability is not admitted for this server",
                ))
            }
        };
        if self.quarantine.contains(capability) {
            return Ok(Self::refused(
                capability,
                RefusalKind::Quarantined,
                "mcp: the capability is quarantined",
            ));
        }
        let client = match self.client.as_mut() {
            // A dead connection replays its fault forever (§4); the
            // capabilities of a dead server are quarantined in every way
            // that matters, so refuse on those words.
            Some(client) if client.is_dead() => {
                return Ok(Self::refused(
                    capability,
                    RefusalKind::Quarantined,
                    "mcp: the server's connection has ended",
                ))
            }
            Some(client) => client,
            None => {
                return Err(ToolError(
                    "mcp provider invoked before connect()".to_owned(),
                ))
            }
        };

        // §7.2: the pre-call relist, whole list against the baseline.
        let listed = match client.list(self.config.page, self.config.list) {
            Ok(listed) => listed,
            Err(fault) => {
                return Ok(fault_result(
                    client,
                    capability,
                    mcp_name,
                    args_of(work).as_ref(),
                    fault,
                    self.baseline_digest,
                ));
            }
        };
        let list_sha256 = canonical_tools_sha256(&listed);
        if list_sha256 != self.baseline_digest {
            let mut changed = Vec::new();
            let mut removed = Vec::new();
            for (name, baseline) in &self.baseline_entries {
                match listed.iter().find(|entry| &entry.name == name) {
                    Some(entry) if &entry.entry != baseline => changed.push(name.clone()),
                    None => removed.push(name.clone()),
                    Some(_) => {}
                }
            }
            let unlisted = listed
                .iter()
                .filter(|entry| !self.baseline_entries.contains_key(&entry.name))
                .count() as u64;
            let called_tool_drifted = changed.iter().any(|name| name == mcp_name)
                || removed.iter().any(|name| name == mcp_name);
            self.drift = Some(DriftInfo {
                changed,
                removed,
                unlisted,
                list_sha256,
            });
            if called_tool_drifted {
                self.quarantine.insert(capability.to_owned());
                return Ok(Self::refused(
                    capability,
                    RefusalKind::Quarantined,
                    "mcp: the tool changed on the server since it was admitted",
                ));
            }
        }

        // §9 step 4: the one call, under the connection's call budget.
        match client.call(mcp_name, args_of(work).as_ref(), self.config.call) {
            Ok(CallEnd::Response(line)) => {
                let request_id = match client.last_request_id() {
                    Some(id) => id,
                    None => {
                        return Err(ToolError(
                            "mcp client answered a call with no request id".to_owned(),
                        ))
                    }
                };
                let request_bytes = wire::encode_call(request_id, mcp_name, args_of(work).as_ref());
                let rendered = render::render(&line, self.config.result_cap);
                // Re-attribute: the renderer speaks for the connection
                // ("mcp"); the model must see the capability the call ran
                // under (§9 step 6, D5).
                let output = Untrusted::new(
                    rendered
                        .output
                        .inspect("re-attribute the server's words to the capability")
                        .clone(),
                    Source::Tool(capability.to_owned()),
                );
                Ok(ToolResult {
                    status: rendered.status,
                    digest: rendered.digest,
                    truncated: rendered.truncated,
                    output,
                    read: None,
                    edits: Vec::new(),
                    exec: None,
                    mcp: Some(McpRecord {
                        request_id,
                        request_sha256: sha256(&request_bytes),
                        response_frame: Some(Untrusted::new(
                            line.into_bytes(),
                            Source::Tool(capability.to_owned()),
                        )),
                        list_sha256,
                        noise: client.last_exchange_noise(),
                    }),
                    web: None,
                })
            }
            Ok(CallEnd::Cancelled) => {
                // §3.5: our request was withdrawn by the server; the call
                // ends as a typed error, connection still up.
                let why = "mcp: the server cancelled the call";
                let request_id = client.last_request_id().unwrap_or(0);
                let request_bytes = wire::encode_call(request_id, mcp_name, args_of(work).as_ref());
                Ok(ToolResult {
                    status: ToolStatus::Error {
                        code: code::MCP_RPC_ERROR,
                    },
                    digest: sha256(why.as_bytes()),
                    output: Untrusted::new(
                        why.as_bytes().to_vec(),
                        Source::Tool(capability.to_owned()),
                    ),
                    truncated: false,
                    read: None,
                    edits: Vec::new(),
                    exec: None,
                    mcp: Some(McpRecord {
                        request_id,
                        request_sha256: sha256(&request_bytes),
                        response_frame: None,
                        list_sha256,
                        noise: client.last_exchange_noise(),
                    }),
                    web: None,
                })
            }
            Err(fault) => Ok(fault_result(
                client,
                capability,
                mcp_name,
                args_of(work).as_ref(),
                fault,
                list_sha256,
            )),
        }
    }
}

/// The call's arguments as the wire wants them; a call whose arguments are
/// not an object carries nothing (the manifest's schema already shaped
/// them, so this is belt-and-braces, not a path to panic).
fn args_of(work: &Call) -> Cow<'_, Args> {
    match work.args.as_object() {
        Some(map) => Cow::Borrowed(map),
        None => Cow::Owned(Args::new()),
    }
}

/// The canonical digest of a listing (§7.2, §9): SHA-256 over the JSON
/// array of the whole entries, in presented order, canonically serialized
/// (`serde_json` writes object keys sorted).
fn canonical_tools_sha256(entries: &[ToolEntry]) -> Digest {
    let array = serde_json::Value::Array(entries.iter().map(|e| e.entry.clone()).collect());
    sha256(array.to_string().as_bytes())
}
