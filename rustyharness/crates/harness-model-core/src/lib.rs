//! The pure half of the model layer (design `docs/01-design-v0.1.md` §3,
//! §2.2 steps 2-4, §2.3): message and completion types, endpoint rules, the
//! wire format, both action protocols, profiles, and the context builder.
//!
//! **A separate pure crate (H1e-1 review NF-A).** These modules used to
//! share a crate with the socket code, so an I/O path was one `crate::`
//! away and only a regex stood in the way. Here there is no I/O module to
//! reach: this crate depends on `harness-core` and serde only, and the
//! purity gate treats it like every other pure crate (dependency allowlist
//! and content scan). The I/O half (the HTTP client, the backends) is
//! `harness-model`, which re-exports everything below.

#![forbid(unsafe_code)]
// The panic-set lints ratchet production code; unit tests may assert loosely.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

use std::borrow::Cow;
use std::fmt;

use harness_core::Untrusted;

pub mod context;
pub mod endpoint;
pub mod profile;
pub mod protocol;
pub mod wire;

/// Harness-authored text: system rules, protocol spec, repair messages,
/// rendered tool definitions. Constructible only from `&'static` templates
/// (and, inside this crate, from renderings of harness data), never from
/// model or tool output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessText(Cow<'static, str>);

impl HarnessText {
    /// A compile-time template.
    pub fn from_static(s: &'static str) -> Self {
        Self(Cow::Borrowed(s))
    }

    pub(crate) fn rendered(s: String) -> Self {
        Self(Cow::Owned(s))
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The task as the user wrote it in the task spec: trusted intent (§2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskText(String);

impl TaskText {
    /// The task spec's task text.
    pub fn new(s: String) -> Self {
        Self(s)
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One message in the context (design §1.3, scaffold review F4).
#[derive(Debug)]
pub enum Message {
    /// Harness rules, protocol spec, tool definitions.
    System(HarnessText),
    /// The task.
    Task(TaskText),
    /// A prior reply of the model.
    Assistant(Untrusted<String>),
    /// A tool result, fed back as data.
    Observation {
        /// The capability id that produced it.
        call: String,
        /// Its output.
        body: Untrusted<String>,
    },
}

/// A tool as offered to the model: its manifest id, a harness-authored
/// description, and its input schema (already validated, §3.3 subset).
#[derive(Debug, Clone, PartialEq)]
pub struct ToolSpec {
    /// Capability id, e.g. `harness.fs.read`.
    pub id: String,
    /// Description shown to the model.
    pub description: HarnessText,
    /// JSON Schema of the arguments.
    pub parameters: serde_json::Value,
}

impl ToolSpec {
    /// The tool definition of an admitted capability (§2.3 block 2): its id,
    /// its manifest summary and its input schema. A [`harness_manifest::Capability`]
    /// exists only inside a validated manifest (private fields), so the
    /// description is reviewed manifest text, never model or tool output.
    pub fn from_capability(c: &harness_manifest::Capability) -> Self {
        Self {
            id: c.id().as_str().to_owned(),
            description: HarnessText::rendered(c.summary().to_owned()),
            parameters: c.input_schema().as_json().clone(),
        }
    }
}

/// The per-turn delimiter nonce (§2.3). It lives in `harness-core` (as
/// [`harness_core::Nonce`]) because it is one of the few values the journal
/// may carry as trusted text (NF-C: `TrustedName` is sealed to core types).
pub use harness_core::Nonce as RenderNonce;

/// One model request.
#[derive(Debug)]
pub struct ModelRequest {
    /// The context, in order.
    pub messages: Vec<Message>,
    /// The active tools.
    pub tools: Vec<ToolSpec>,
    /// This turn's delimiter nonce.
    pub nonce: RenderNonce,
}

/// A tool call as the server returned it (native protocol). Untrusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawToolCall {
    /// The wire function name.
    pub name: String,
    /// The arguments, as the JSON text the server sent.
    pub arguments: String,
}

/// Why generation stopped. Only these two are a usable completion;
/// `length`, an absent reason and anything else are [`ModelError`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishReason {
    /// `stop`.
    Stop,
    /// `tool_calls`.
    ToolCalls,
}

impl FinishReason {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            FinishReason::Stop => "stop",
            FinishReason::ToolCalls => "tool_calls",
        }
    }
}

/// Token usage as the server reported it; `None` in [`Completion::usage`]
/// means it reported nothing and the meter estimates (§2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerUsage {
    /// Prompt tokens.
    pub input: u64,
    /// Completion tokens.
    pub output: u64,
}

/// A usable completion.
#[derive(Debug)]
pub struct Completion {
    /// The reply text (reasoning and, in text mode, the action block).
    pub content: Untrusted<String>,
    /// Native tool calls.
    pub tool_calls: Vec<Untrusted<RawToolCall>>,
    /// Why generation stopped.
    pub finish: FinishReason,
    /// Server-reported usage, if any.
    pub usage: Option<ServerUsage>,
    /// Bytes of the rendered request (for the meter's estimate).
    pub request_bytes: u64,
    /// Bytes of the reply content plus tool calls (for the meter's estimate).
    pub reply_bytes: u64,
    /// HTTP statuses of failed attempts retried before this success (§3.2:
    /// each attempt is recorded).
    pub retried: Vec<u16>,
}

/// Why a transport attempt did not produce a reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unavailable {
    /// Connection refused or reset.
    Connect(String),
    /// The connect timeout elapsed.
    ConnectTimeout,
    /// No byte arrived within the read timeout.
    ReadTimeout,
    /// The call's total deadline elapsed.
    Deadline,
    /// A 5xx status, after the retry budget.
    Status {
        /// The last status.
        code: u16,
        /// Every attempt's status, in order (H1d review F-7: the whole
        /// retry history survives a final failure).
        statuses: Vec<u16>,
    },
}

/// A model call that produced no usable completion (§2.2 step 3). None of
/// these is ever an empty success (INV-3).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelError {
    /// No content and no tool call.
    #[error("the model returned an empty completion")]
    Empty,
    /// `finish_reason` was `length`, or absent at the end of the stream.
    #[error("the completion was truncated ({0})")]
    Truncated(&'static str),
    /// A reply that is not a well-formed completion: malformed JSON,
    /// duplicate keys, an unexpected content type or finish reason, an
    /// oversized response, a non-2xx status that is not retried.
    #[error("unusable completion: {0}")]
    Unusable(String),
    /// The backend could not be reached in time.
    #[error("model backend unavailable: {0:?}")]
    Unavailable(Unavailable),
    /// 429 after the retry budget.
    #[error("rate limited after {} attempts", statuses.len())]
    RateLimited {
        /// Every attempt's status, in order (the last is 429).
        statuses: Vec<u16>,
    },
    /// Replay could not reproduce the recorded exchange (§2.9).
    #[error("replay diverged at model exchange {exchange}: {why}")]
    ReplayDiverged {
        /// 0-based exchange index.
        exchange: usize,
        /// What differed.
        why: &'static str,
    },
}

/// Endpoint class (§3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointClass {
    /// Loopback HTTP.
    Loopback,
    /// Replay of a journal.
    Replay,
    /// Scripted (tests).
    Scripted,
}

/// What the journal header records about the model (§3.5). Server claims
/// (model id, software, template) join when the startup check records them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelIdentity {
    /// Endpoint class.
    pub endpoint: EndpointClass,
    /// Profile id.
    pub profile_id: String,
    /// SHA-256 of the profile bytes (hex), when loaded from a file.
    pub profile_sha256: Option<String>,
    /// Whether the profile carries a `profile check` stamp consistent with
    /// its content (H1d review F-5). A staleness check, not authentication
    /// (H1e-1 review NF-E; see `profile::Stamp`).
    pub profile_validated: bool,
    /// That stamp's digest, recorded with the flag.
    pub profile_stamp_sha256: Option<String>,
    /// The API key's handle name, never its value (§5.5).
    pub api_key_handle: Option<String>,
    /// What the server SAYS it is (§3.5). Claims, not facts: the run
    /// driver records them only as untrusted payloads labelled "claimed".
    pub claimed: ServerClaims,
}

/// Server-claimed identity (§3.5): a server can lie about what it serves,
/// so these are recorded as claims beside what the harness controls.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerClaims {
    /// The model id the server listed for the profile's model.
    pub model_id: Option<String>,
    /// The server's `Server` header (software and version).
    pub server: Option<String>,
    /// The chat-template hash. Not collected in this build: it needs the
    /// llama.cpp `/props` check of spike S-P1.
    pub template_sha256: Option<String>,
}

impl fmt::Display for EndpointClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EndpointClass::Loopback => "loopback",
            EndpointClass::Replay => "replay",
            EndpointClass::Scripted => "scripted",
        })
    }
}
