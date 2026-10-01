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

    /// A policy denial for arguments outside a tool's schema, naming the
    /// argument and the bounds the tool's own schema gives it: "the argument
    /// `lines` must be an integer from 1 to 100". Everything rendered comes
    /// from `spec` (an admitted capability's reviewed schema): `property` is
    /// only looked up among the schema's properties, and the name shown is
    /// the schema's own key, never the call's text. `None` when the schema
    /// has no such property, or gives it no bound, so the caller keeps its
    /// static text (judge finding (c) of the dev-suite review, H2b).
    pub fn argument_bounds(spec: &ToolSpec, property: &str) -> Option<Self> {
        let (name, node) = spec
            .parameters
            .get("properties")?
            .as_object()?
            .iter()
            .find(|(k, _)| k.as_str() == property)?;
        let int = |k: &str| node.get(k).and_then(serde_json::Value::as_i64);
        let bound = match node.get("type").and_then(serde_json::Value::as_str)? {
            "integer" => match (int("minimum"), int("maximum")) {
                (Some(lo), Some(hi)) => format!("an integer from {lo} to {hi}"),
                (Some(lo), None) => format!("an integer of at least {lo}"),
                (None, Some(hi)) => format!("an integer of at most {hi}"),
                (None, None) => return None,
            },
            "string" => format!("a string of at most {} characters", int("maxLength")?),
            _ => return None,
        };
        Some(Self::rendered(format!(
            "Policy denied the call: the argument {name} must be {bound}. The tool's schema lists every argument and its bounds."
        )))
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
///
/// The first four are what the text protocol shows back to the model. The
/// native protocol shows a past action as the model's own tool call and its
/// result as the tool's answer ([`Message::ToolCall`], then
/// [`Message::ToolResult`] or [`Message::ToolNotice`] with the same id), so
/// the model sees its history in the form it is asked to reply in (design
/// row H1h).
///
/// **Each observation carries its own delimiter nonce (design row H1i).**
/// It is drawn when the observation is first rendered and reused every time
/// it is shown again, so a past observation renders to the same bytes in
/// every later request (the server's prompt cache can keep it), while a new
/// one still gets a nonce nothing could predict when its output was made.
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
        /// Its delimiter nonce (drawn at its first render, H1i).
        nonce: RenderNonce,
    },
    /// Native protocol: a past action, shown as the model's own tool call.
    /// It is the harness's rendering of the action it parsed and acted on
    /// (the active tool and the parsed arguments), never the raw reply, so
    /// a reply that was not exactly one well-formed call has no
    /// `ToolCall`.
    ToolCall {
        /// Harness-made id; the next message answers it.
        id: ToolCallId,
        /// The capability id (its wire name is derived when rendering).
        tool: String,
        /// The parsed arguments as canonical JSON text: model-chosen values.
        arguments: Untrusted<String>,
        /// The text of the reply beside the call (its reasoning).
        content: Untrusted<String>,
    },
    /// Native protocol: the tool output answering the [`Message::ToolCall`]
    /// with the same id, fed back as data in the tool role.
    ToolResult {
        /// The id of the call it answers.
        id: ToolCallId,
        /// The capability id that produced it.
        call: String,
        /// Its output.
        body: Untrusted<String>,
        /// Its delimiter nonce (drawn at its first render, H1i).
        nonce: RenderNonce,
    },
    /// Native protocol: the harness's own answer to a [`Message::ToolCall`]
    /// that produced no tool output (a policy denial, a provider failure).
    ToolNotice {
        /// The id of the call it answers.
        id: ToolCallId,
        /// The harness text.
        text: HarnessText,
    },
}

/// The id of a past tool call in the native protocol's history (design row
/// H1h). Harness-made from the loop step, which runs at most one action, so
/// no model or server text ever enters an id (the ids a server puts in its
/// replies are never read), and a replay that rebuilds the same turns
/// rebuilds the same ids and the same context digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ToolCallId(u64);

impl ToolCallId {
    /// The id of the call made at loop step `step`.
    pub fn for_step(step: u64) -> Self {
        Self(step)
    }

    /// The loop step.
    pub fn step(self) -> u64 {
        self.0
    }

    /// The wire form: `call` and the step zero-padded to five digits
    /// (`call00007`). That is nine ASCII letters and digits, a shape strict
    /// servers accept (some chat templates require exactly nine
    /// alphanumerics; UNVERIFIED beyond the servers the harness was run
    /// against), and it stays unique past step 99 999, only longer.
    pub fn wire(self) -> String {
        format!("call{:05}", self.0)
    }
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

/// An observation's delimiter nonce (§2.3; one per observation since H1i).
/// It lives in `harness-core` (as [`harness_core::Nonce`]) because it is
/// one of the few values the journal may carry as trusted text (NF-C:
/// `TrustedName` is sealed to core types).
pub use harness_core::Nonce as RenderNonce;

/// One model request. Its observations carry their own nonces (H1i); the
/// request has none of its own.
#[derive(Debug)]
pub struct ModelRequest {
    /// The context, in order.
    pub messages: Vec<Message>,
    /// The active tools.
    pub tools: Vec<ToolSpec>,
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
    /// What the server reported about its prompt cache and its timings for
    /// this reply (design row H1i), as compact JSON text: the numeric
    /// entries of OpenAI-style `usage.prompt_tokens_details` (such as
    /// `cached_tokens`) and of llama.cpp's `timings` (such as `cache_n`,
    /// `prompt_n`, `prompt_ms`, `predicted_n`, `predicted_ms`), under those
    /// names. Server claims: journaled as untrusted data, for the
    /// prefill/generation split of RQ2, and never used for a decision.
    /// `None` when the server reported neither.
    pub server_stats: Option<Untrusted<String>>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn read_tool() -> ToolSpec {
        ToolSpec {
            id: "harness.fs.read".into(),
            description: HarnessText::from_static("read"),
            parameters: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "path": {"type": "string", "maxLength": 4096},
                    "start": {"type": "integer", "minimum": 1},
                    "lines": {"type": "integer", "minimum": 1, "maximum": 100},
                    "flag": {"type": "boolean"}
                },
                "required": ["path"]
            }),
        }
    }

    // Judge finding (c): a denial names the violated argument's bounds from
    // the tool's own schema; anything the schema does not bound, or does
    // not have, gets no rendering (the caller keeps its static text).
    #[test]
    fn an_argument_denial_names_the_schemas_bounds() {
        let t = read_tool();
        let text = |p: &str| HarnessText::argument_bounds(&t, p).map(|h| h.as_str().to_owned());
        assert_eq!(
            text("lines").unwrap(),
            "Policy denied the call: the argument lines must be an integer from 1 to 100. \
             The tool's schema lists every argument and its bounds."
        );
        assert!(text("start").unwrap().contains("an integer of at least 1"));
        assert!(text("path")
            .unwrap()
            .contains("a string of at most 4096 characters"));
        for none in ["flag", "nosuch", "", "lines/0", "LINES"] {
            assert_eq!(text(none), None, "{none:?}");
        }
    }
}
