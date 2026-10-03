//! The JSON-RPC 2.0 envelope and the ACP message shapes (P-35), built and
//! parsed as `serde_json::Value`s by hand: no derive, no third-party
//! dependencies beyond the workspace's `serde_json`. Version pinned in
//! `docs/slices/P-35-acp-spec-notes.md` (ACP v1, `protocolVersion` 1).

use serde_json::{json, Value};

/// JSON-RPC `parse error`: the line is not JSON at all.
pub(crate) const PARSE_ERROR: i64 = -32700;
/// JSON-RPC `invalid request`: JSON, but not a 2.0 envelope.
pub(crate) const INVALID_REQUEST: i64 = -32600;
/// JSON-RPC `method not found` (also: a method whose capability we do
/// not advertise, such as `session/load`).
pub(crate) const METHOD_NOT_FOUND: i64 = -32601;
/// JSON-RPC `invalid params`.
pub(crate) const INVALID_PARAMS: i64 = -32602;
/// Server error: the session is busy (a second `session/new`).
pub(crate) const BUSY: i64 = -32000;
/// Server error: the session id is unknown.
pub(crate) const NO_SESSION: i64 = -32001;
/// Server error: `initialize` has not been answered yet.
pub(crate) const NOT_INITIALIZED: i64 = -32002;

/// One line from the client, parsed as far as it can be.
pub(crate) enum Line {
    /// A client request (`method` + `id`): wants a response.
    Request {
        /// The id, echoed verbatim in the response.
        id: Value,
        /// The method name.
        method: String,
        /// The params (`Null` when absent).
        params: Value,
    },
    /// A client notification (no `id`): never answered.
    Notification {
        /// The method name.
        method: String,
        /// The params (`Null` when absent).
        params: Value,
    },
    /// A response to one of OUR requests (e.g.
    /// `session/request_permission`).
    Response {
        /// The id we minted (`srv-<n>`).
        id: Value,
        /// The `result` value (`Null` for an error response; the error
        /// text is gone — an error answering a permission is a deny).
        result: Value,
    },
}

/// One read line: parsed (`Ok`), or the parse failure (`Err`) —
/// `Err(None)` is not even JSON (`-32700`, id `null`); `Err(Some(id))`
/// is JSON that fails the envelope check (`-32600`).
pub(crate) fn parse_line(line: &str) -> Result<Line, Option<Value>> {
    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return Err(None),
    };
    let obj = match v.as_object() {
        Some(o) => o,
        None => return Err(Some(Value::Null)),
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(Some(obj.get("id").cloned().unwrap_or(Value::Null)));
    }
    let id = obj.get("id").cloned();
    let method = obj.get("method").and_then(Value::as_str);
    let params = obj.get("params").cloned().unwrap_or(Value::Null);
    match (id, method) {
        (Some(id), Some(m)) => Ok(Line::Request {
            id,
            method: m.to_owned(),
            params,
        }),
        (None, Some(m)) => Ok(Line::Notification {
            method: m.to_owned(),
            params,
        }),
        // A response carries `result` or `error`; either way what the
        // caller needs is the payload (an error result answers a
        // permission as a deny, so `Null` is the fail-closed reading).
        (Some(id), None) if obj.contains_key("result") || obj.contains_key("error") => {
            let result = obj.get("result").cloned().unwrap_or(Value::Null);
            Ok(Line::Response { id, result })
        }
        (id, _) => Err(Some(id.unwrap_or(Value::Null))),
    }
}

/// A response to a client request.
pub(crate) fn response(id: &Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}

/// An error response to a client request (or to a line with no usable
/// id: `id: null`).
pub(crate) fn error(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

/// A server→client request (we mint string ids `srv-<n>`).
pub(crate) fn server_request(id: &str, method: &str, params: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
}

/// A `session/update` notification (every server→client event).
pub(crate) fn update(session_id: &str, one: Value) -> Value {
    json!({"jsonrpc":"2.0","method":"session/update","params":{
        "sessionId": session_id, "update": one
    }})
}

/// `agent_message_chunk`: a piece of the model's spoken reply.
pub(crate) fn agent_message_chunk(text: &str) -> Value {
    json!({"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":text}})
}

/// `tool_call`: a tool call started (status `pending`).
pub(crate) fn tool_call(tool_call_id: &str, name: &str, title: &str, kind: &str) -> Value {
    json!({"sessionUpdate":"tool_call","toolCallId":tool_call_id,"name":name,
           "title":title,"kind":kind,"status":"pending"})
}

/// `tool_call_update`: a tool call finished (`completed` or `failed`),
/// optionally with a text content block.
pub(crate) fn tool_call_update(tool_call_id: &str, status: &str, text: Option<&str>) -> Value {
    let mut v =
        json!({"sessionUpdate":"tool_call_update","toolCallId":tool_call_id,"status":status});
    if let Some(t) = text {
        if let Some(obj) = v.as_object_mut() {
            obj.insert(
                "content".to_owned(),
                json!([{"type":"content","content":{"type":"text","text":t}}]),
            );
        }
    }
    v
}

/// The `initialize` result: version 1, no capabilities advertised
/// (fail closed: everything the client might assume we can do, we say
/// we cannot).
pub(crate) fn initialize_result(version: i64) -> Value {
    json!({
        "protocolVersion": version,
        "agentCapabilities": {
            "loadSession": false,
            "promptCapabilities": {},
            "mcpCapabilities": {}
        },
        "agentInfo": {
            "name": "rustyharness",
            "version": env!("CARGO_PKG_VERSION")
        },
        "authMethods": []
    })
}

/// The prompt's text: `text` blocks joined by newlines; a
/// `resource_link` block becomes one bracketed line (baseline: the
/// block is accepted, only its coordinates are kept); any other block
/// type needs a capability we do not advertise, so the prompt is
/// refused.
pub(crate) fn prompt_text(params: &Value) -> Result<String, String> {
    let blocks = params
        .get("prompt")
        .and_then(Value::as_array)
        .ok_or_else(|| "params.prompt must be an array of content blocks".to_owned())?;
    let mut parts: Vec<String> = Vec::with_capacity(blocks.len());
    for b in blocks {
        match b.get("type").and_then(Value::as_str) {
            Some("text") => {
                let t = b
                    .get("text")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "text block without text".to_owned())?;
                parts.push(t.to_owned());
            }
            Some("resource_link") => {
                let uri = b.get("uri").and_then(Value::as_str).unwrap_or("");
                let name = b.get("name").and_then(Value::as_str).unwrap_or("");
                parts.push(format!("[resource_link {name} {uri}]"));
            }
            _ => {
                return Err(
                    "unsupported content block (only text and resource_link are advertised)"
                        .to_owned(),
                );
            }
        }
    }
    Ok(parts.join("\n"))
}

/// The ACP tool-call `kind` for a harness capability: read tools read,
/// edit tools edit, the runner executes, search/glob/list search,
/// everything else is `other`.
pub(crate) fn tool_kind(capability: &str) -> &'static str {
    if capability.contains("exec") {
        "execute"
    } else if capability.contains("edit") {
        "edit"
    } else if capability.contains("search")
        || capability.contains("glob")
        || capability.contains("list")
    {
        "search"
    } else if capability.contains("read") {
        "read"
    } else {
        "other"
    }
}
