# P-35 spec notes: the Agent Client Protocol wire (pinned)

Pinned version: **ACP v1**, fetched 2026-10-03 from
`https://agentclientprotocol.com` (protocol overview and the
`initialize` / `session/new` / `session/prompt` / `session/cancel` /
`session/update` / `session/request_permission` pages).

`protocolVersion` on the wire is the **integer `1`** (not a string).
This build speaks exactly version 1.

## Envelope

One JSON-RPC 2.0 message per stdio line (newline-delimited; we do not
use `Content-Length` framing — the spec's stdio transport is
newline-delimited JSON).

- Request: `{"jsonrpc":"2.0","id":<num|string>,"method":M,"params":P}`
- Notification: `{"jsonrpc":"2.0","method":M,"params":P}`
- Response: `{"jsonrpc":"2.0","id":…,"result":R}` or
  `{"jsonrpc":"2.0","id":…,"error":{"code":C,"message":S}}`

Error codes we emit: `-32700` parse error (id `null`), `-32600`
invalid request, `-32601` method not found, `-32602` invalid params,
and server errors in `-32000..-32099` (`-32000` busy, `-32001`
unknown session, `-32002` not initialized).

## Handshake

`initialize` request
`{protocolVersion:1, clientCapabilities:{…}, clientInfo:{name,…}}` →
result `{protocolVersion:1, agentCapabilities:{…},
agentInfo:{name,version}, authMethods:[]}`. The client's version is
echoed when it equals ours; otherwise we reply our latest (1) and the
client decides. We advertise **no** capabilities: `loadSession:false`,
empty `promptCapabilities` / `mcpCapabilities` / `sessionCapabilities`,
no auth methods.

## Session

- `session/new {cwd, mcpServers:[]}` → `{sessionId}`. `cwd` MUST be
  absolute and becomes the session's workspace (the spec: it is used
  regardless of where the agent process was spawned). A non-empty
  `mcpServers` is refused (`-32602`): we advertise no MCP.
- `session/prompt {sessionId, prompt: ContentBlock[]}` →
  `{stopReason}`. Content blocks: `{type:"text",text}` and
  `{type:"resource_link",uri,name?}` are baseline; image/audio/resource
  need advertised capabilities we do not have, so a prompt carrying
  them is refused (`-32602`). stopReason values: `end_turn`,
  `max_tokens`, `max_turn_requests`, `refusal`, `cancelled`.
- `session/cancel {sessionId}` is a **notification**, legal any time
  during a turn; the agent stops as soon as it can, MUST answer a
  pending `session/request_permission` with `{"outcome":"cancelled"}`
  (the client sends that answer), and MUST reply to `session/prompt`
  with `stopReason:"cancelled"` — not an error.
- `session/update {sessionId, update:{sessionUpdate:…}}` is an
  agent→client notification. Variants we emit:
  `agent_message_chunk {content:{type:"text",text}}`,
  `tool_call {toolCallId, name, title, kind, status:"pending",
  content?}`, `tool_call_update {toolCallId, status:"completed"|
  "failed", content?}`. `tool_call.kind` is one of `read|edit|delete|
  move|search|execute|think|fetch|switch_mode|other`.
- `session/request_permission` is an agent→client **request**:
  `{sessionId, toolCall:{toolCallId}, options:[{optionId, name,
  kind: allow_once|allow_always|reject_once|reject_always}]}` → result
  `{"outcome":{"outcome":"selected","optionId":…}}` or
  `{"outcome":"cancelled"}`.
- `session/load`, `session/resume`, `session/close` exist in the spec
  behind capabilities we do not advertise; we refuse them
  (`-32601`).

## This build's mappings (details in docs/slices/P-35.md)

- One ACP session ⇔ one `run_session` ⇔ one journal; each prompt is
  one user turn; the prompt's response is written right after that
  turn's `TurnEnded` reaches the sink.
- `stopReason`: turn reasons `answered`/`submitted`/
  `submitted_checks_failed` → `end_turn`; `turn_steps`/
  `format_errors`/`loop:*` → `max_turn_requests`; `input_refused` →
  `refusal`; session stops: `budget`/`context_exhausted` → `max_tokens`,
  `model_unavailable`/`policy_abort`/`sandbox_lost`/
  `journal_unavailable` → `refusal`; a seen `session/cancel` →
  `cancelled` (overrides).
- Tool events: `ToolStarted` → `tool_call` (`toolCallId` `c<seq>`),
  `ToolFinished` → `tool_call_update`.
- Approvals: the ACP client is the approver
  (`ApproverKind::Embedded`); `allow_once`→`Yes`, `allow_always`→
  `AllowSession` (only offered when session grants are on),
  `reject_once`→`No`, `reject_always`→`DenySession` (same gate),
  `cancelled`/error/timeout→`No` (fail closed).
