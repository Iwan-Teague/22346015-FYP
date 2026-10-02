# P-37: MCP stdio client (design note)

Status: design for owner review (roadmap §4.3 P-37, ARCH; owner question Q-13). Docs only. Written
unattended: every open point is decided fail-closed and the reason is written down; the owner-only
ones are in §17 with their defaults. Implemented by the slices of §19 (P-37a to P-37m).

Verified against `912fdd2` (branch `w/P-37`): `crates/harness-manifest/src/{lib.rs,admission.rs,schema.rs}`,
`crates/harness-policy/src/lib.rs` (`Session::plan_with`, `trifecta`, `quarantine`, `decide`),
`crates/harness-tools/src/provider.rs` (`ToolProvider`, `ToolResult`, `ToolStatus`),
`crates/harness-sandbox/src/{lib.rs,spec.rs,confine_spawn.rs}`, `crates/harness-run/src/driver/{plan.rs,step.rs,tools.rs}`,
`crates/harness-run/src/replay.rs`, `crates/harness-run/src/replay/resume.rs`,
`crates/harness-journal/src/{canon.rs,conditions.rs,event.rs}`, `scripts/ci/purity.sh` (§2f, §5), design
`docs/01-design-v0.1.md` (D7, D8, §4.1-§4.6, §4.10, §5.2, §5.4, §6.2, §6.4, §6.5, INV-6/7/8/9/23/29/31, §11),
`docs/slices/P-05-session.md`, `docs/OWNER-DECISIONS.md` (#8).

**Terms.** *Server*: one MCP server process, the `mcp-stdio` transport of one admitted manifest. *Provider*:
the manifest's namespace (`provider` field); one provider = one server process per run. *Capability*: a
manifest entry `provider.verb`, bound 1:1 to a server tool name (`mcp_name`). *Presented*: what the server
says about itself in `initialize` and `tools/list`; compared, never trusted (§4.5 `presented()`).

---

## 0. Decisions at a glance

| # | Decision |
|---|---|
| D1 | A new crate `harness-mcp` holds our own minimal, **synchronous** JSON-RPC 2.0 client for MCP over stdio. Methods sent: `initialize`, `notifications/initialized`, `tools/list`, `tools/call`. Nothing else, ever (§3). No rmcp, no tokio, no new crates.io crate (§13). |
| D2 | Protocol version pinned: the harness's compiled set ∩ the manifest's `mcp_protocols`, highest common one requested; the server must answer **exactly** that version or the connection is refused (§3.3). v1 set: `2025-06-18` only. |
| D3 | Client capabilities are `{}`: no sampling, no roots, no elicitation. Every server-initiated request (sampling, roots, elicitation, ping, anything) gets JSON-RPC error `-32601` and is counted; past a small cap it is a protocol violation (§3.5). Resources, prompts, completions and logging are never called. |
| D4 | The server runs confined through `confine_spawn` in a new **duplex** mode (stdin relayed by the domain stub, stdout streamed). It may read only its admitted read-only roots and, if the admission record says so, the workspace **read-only**; it may write only its own per-run scratch directory; it has **no network** (§5). No server ever gets a workspace write root (this sidesteps Q-16). |
| D5 | What the model sees of a tool is the **manifest's** reviewed `summary` and `input_schema`, never the server's description, title, annotations, `instructions` or server info. Server text reaches the model only as delimited, `Untrusted`, bounded tool-result content (§9). |
| D6 | Manifest v1 is unchanged (no schema bump). Its required `description_sha256`/`schema_sha256` are checked at connect: description = SHA-256 of the exact UTF-8 bytes; schema = SHA-256 of the canonical JSON of `inputSchema` (§6.1). The server's confinement inputs live in the user's **admission record** (trust base), not the manifest (§6.2). |
| D7 | Admission: the `pinned` tier with the `mcp-stdio` transport is admitted (the H1 phase gate lifted for exactly that pair). `signed` stays refused (no ed25519 crate yet), `in-process` stays refused, secret handles stay refused (§6.3). Pinned capabilities ask by default (`user_confirm` floor, §4.4). |
| D8 | Rug-pull: at connect, a pin mismatch quarantines the capability and, if it is granted, the run stops before the first model call (`Indeterminate { CouldNotRun }`). Before **every** MCP call the client re-lists tools; any byte change to an admitted tool's entry since connect quarantines it, the call is refused, the tool is withdrawn from the active set, and both are journaled (§7). |
| D9 | Namespacing: the model calls manifest ids only; server tool names are internal. Duplicate namespaces (INV-8), duplicate `mcp_name`s, and a server listing one tool name twice are all refused (§8). |
| D10 | Per call: schema check and policy decision as for any capability, approval when asked, write-ahead intent, then one `tools/call`. `ToolFinished` carries the request digest, the raw response frame (as an untrusted blob), the pre-call list digest and the noise count. Results are `Untrusted(Source::Tool(id))`, rendered from text blocks only, bounded (§9, §11). |
| D11 | MCP tools count against `max_active_tools` like any grant; the cap is not raised (Q-6 default). Labels are lifted per **process**: an mcp-stdio capability carries the max egress, content and sensitivity over its whole manifest, granted or not (§5.4, §10). |
| D12 | Hard bounds on bytes, frames, time and noise; any violation kills the server and quarantines all its capabilities for the rest of the run; a timed-out call kills it too. No restart in v1 (§4). |
| D13 | Audit replays MCP calls with no server: it re-feeds the raw frames and recomputes the request bytes, the rendered observation, its digest and every quarantine decision. Resume reconnects; a cut call whose effect is `write` or more refuses the resume (§12). |
| D14 | Tests use a fake MCP server written in Rust, a new `publish = false` crate `harness-mcp-fixture` (lib + bin `rh-mcp-fixture`) with scripted hostile modes. No Python, no Node (§14). |

---

## 1. Scope

In: stdio servers only; tools only; one server process per admitted provider used by the run; sequential
calls (one outstanding request per server, ever); macOS (the only `Conformed` backend today).

Out (each refused, not ignored): Streamable HTTP / SSE transports (need TLS; owner #2 says opt-in `net`
feature later), resources, prompts, completions, sampling, roots, elicitation, logging levels, progress,
JSON-RPC batches, server restarts, the `signed` and `in-process` tiers, secret handles, egress for servers,
workspace writes by servers. Linux and Windows: no `Conformed`, so any grant of an mcp-stdio capability is
refused at planning (INV-6, exit 3), exactly like `harness.exec.run` today.

---

## 2. Crates

```
crates/harness-mcp           new: the client (I/O), the provider, the connector seam
  src/wire.rs                pure: frame reader over `Read`, message classification, encoders
  src/render.rs              pure: tools/call response -> observation text, status, digest
  src/client.rs              the state machine over a `Transport` (deadlines, ids, noise caps)
  src/provider.rs            `McpProvider: ToolProvider`; pre-call relist; quarantine decisions
  src/connect.rs             `McpConnector` seam; `ConfinedConnector` (production)
  src/testing.rs             feature `testing` only: `InMemoryConnector` over the fixture lib
crates/harness-mcp-fixture   new, publish = false: the fake server (lib + bin `rh-mcp-fixture`)
```

Edges (downward only, design §1.2): `harness-run → harness-mcp → harness-tools, harness-sandbox,
harness-policy, harness-manifest, harness-journal, harness-core`. `harness-mcp` depends on `serde_json` and
`thiserror` only from crates.io (already on the purity gate's reviewed list), so §5 of `purity.sh` passes
with no list change. `wire.rs` and `render.rs` are declared pure (no `std::fs/net/process/env/path`, no clock):
P-37c adds both files to the purity gate's grep scan of pure sources, because audit recomputes from them.
`harness-mcp-fixture` is not in the shipped binary's tree; its `src/main.rs` is a bin root under
`crates/*/src`, so it needs `#![forbid(unsafe_code)]` and passes §2f (it names no `Command`). Pure helpers
for pins (§6.1) go into `harness-manifest` (`pins.rs`, using `harness_core::sha256`; already allowlisted).

The `testing` feature of `harness-mcp` follows the journal's `fault-injection` precedent: P-37h adds a
purity rule that no normal dependency edge enables `harness-mcp/testing`.

---

## 3. Wire protocol

### 3.1 Framing (MCP stdio)

One JSON-RPC message per line, UTF-8, `\n`-terminated, no embedded newline (a trailing `\r` is refused,
not stripped). The server's stdout carries only MCP messages; stderr is logging. Our reader:

- reads stdout on its own thread into a bounded line buffer; a line longer than `FRAME_MAX` (1 MiB) is a
  violation **as soon as the buffer passes the cap** (the rest is never buffered);
- parses each line with `harness_core::strict_json::parse_typed` (duplicate keys refused at every depth,
  INV-22); invalid UTF-8, a non-object, a JSON array (a batch, removed in `2025-06-18`), or any parse
  fault is a violation;
- classifies: `Response` (`jsonrpc:"2.0"`, `id`, exactly one of `result`/`error`), `ServerRequest`
  (`id` + `method`), `Notification` (`method`, no `id`), anything else a violation.

### 3.2 Ids

Our requests use integer ids from a per-connection counter starting at 1 (`initialize` = 1). At most one
request is outstanding. A response whose id is not the outstanding one (unknown, already answered, a string
`"1"` for `1`, `null`), a second response, or one with both `result` and `error` is a violation. Ids are
recorded (§11), so audit can recompute the exact request bytes.

### 3.3 Lifecycle and version pinning

1. `initialize` with `{"protocolVersion": V, "capabilities": {}, "clientInfo": {"name": "rustyharness",
   "version": <harness version>}}`, where `V` = the highest version in `SUPPORTED_MCP_PROTOCOLS ∩
   manifest.mcp_protocols` (`harness_manifest::negotiate`; none in common refuses the provider at admission,
   design §4.1). `SUPPORTED_MCP_PROTOCOLS = ["2025-06-18"]` in v1; adding a version is a reviewed code
   change that adds the fixture's wire tests for it (later versions such as `2025-11-25`: UNVERIFIED here).
2. The result must name **exactly** `V` (the spec lets a server propose another version; we refuse rather
   than speak a dialect we did not test), must have `capabilities.tools`, and must fit `INIT_MAX`
   (64 KiB). `serverInfo` and `instructions` are journaled as untrusted blobs and never shown to the model
   (an `instructions` string is a prompt-injection channel by design).
3. `notifications/initialized`.
4. `tools/list` (with `cursor` pagination: at most `LIST_PAGES_MAX` = 8 pages and `TOOLS_MAX` = 256 tools,
   each page ≤ `FRAME_MAX`), the baseline for §7.

### 3.4 Methods we send after that

`tools/list` (re-list before each call, §7.2) and `tools/call` with `{"name": <mcp_name>, "arguments":
<the validated args>}`. No `_meta`, no `progressToken`. Request bytes are produced by one deterministic
encoder (`wire::encode_call(id, name, args)`: compact JSON, keys sorted, as `serde_json` without
`preserve_order` writes them), so their digest is recomputable.

### 3.5 Messages the server sends us

| Message | Action |
|---|---|
| any request (`sampling/createMessage`, `roots/list`, `elicitation/create`, `ping`, unknown) | reply `{"jsonrpc":"2.0","id":<its id>,"error":{"code":-32601,"message":"not supported"}}`; count. Over `SERVER_REQUESTS_MAX` (16) per run: violation. A request whose `id` is `null` or not a string/integer: violation. |
| `notifications/tools/list_changed` | count; the pre-call relist (§7.2) already re-reads the list. |
| `notifications/message`, `notifications/progress`, `notifications/cancelled`, anything else | drop, count. A `cancelled` naming our outstanding id ends that call as `Error{MCP_RPC_ERROR}`. |
| more than `NOISE_MAX` (256) messages or `NOISE_BYTES_MAX` (1 MiB) of non-response traffic during one exchange | violation |
| anything on stdout before the `initialize` response other than the above | handled the same way; a non-JSON line is a violation |

We never answer a `ping` with success: liveness is not our concern, and a server that gives up on us simply
ends (its capabilities become unavailable, §4).

---

## 4. Limits and hostile servers

All deadlines are **absolute** per exchange, never inter-byte, so a slow-loris server that trickles bytes
meets the same deadline as a silent one.

| Bound | Value | On breach |
|---|---|---|
| spawn + `initialize` round trip | 10 s | connect fails |
| each `tools/list` page / whole list | 5 s / 15 s | connect fails, or (pre-call) server killed |
| `tools/call` | `min(manifest limits.timeout_ms, run tool timeout (30 s default), remaining wall)` | `ToolStatus::Timeout`; server killed |
| `FRAME_MAX` (one line) | 1 MiB | violation |
| `INIT_MAX` | 64 KiB | violation |
| request size (our own) | 1 MiB (args are already schema-bounded) | call refused before sending |
| rendered observation | `min(manifest limits.max_result_bytes, MCP_RESULT_DEFAULT = 32 KiB)`; cut with `truncated: true` | not a breach |
| stderr kept | last 64 KiB (ring) | rest dropped, counted |
| noise per exchange | 256 messages / 1 MiB | violation |
| server requests per run | 16 | violation |

A **violation**, an EOF on stdout, an exit, or a timeout kills the server (stub sweep, §5.3) and marks the
provider *dead*: every capability of it is quarantined with reason `server_ended`, journaled (`McpStopped`,
`Quarantined` enter per capability), withdrawn from the active set; the call in flight ends `Crashed`
(`Timeout` for a timeout). Why no restart: a restarted server is a new process whose behaviour and state the
journal cannot tie to the old one, a crash-loop would burn the wall budget, and a late response from the old
process cannot be confused with a new one if there is no new one. Owner question O-10 (§17).

---

## 5. Confinement of the server

### 5.1 The `ConfinedSpec` (built by `ConfinedConnector`, P-37l)

| Field | Value |
|---|---|
| `argv` | the manifest's `transport.argv` verbatim (`argv[0]` absolute, no `..`, no UNC: already validated). It travels over the control pipe (INV-23); no payload is ever on it. |
| `cwd` | the server's scratch dir, or the workspace when the admission record grants `workspace: read_only` |
| `env` | built: `HOME` and `TMPDIR` = scratch, `PATH=/usr/bin:/bin`, `LANG=C.UTF-8`, plus exactly the admission record's `env` values for names in the manifest's `env_allow` (a name not in `env_allow` refuses the record; a name in `env_allow` with no value is simply absent). Never inherited from the harness process (OD-2: `harness-run` reads no environment). Loader variables are refused by `spec::validate` already. |
| `read_only` | the admission record's `read_only` roots (the server binary's install dir, its runtime) plus the workspace if `workspace: read_only` |
| `read_write` | `runs/<id>/scratch/mcp/<provider>/` only (created 0700), outside the workspace |
| `protected` | empty |
| `network` | `Network::None`, always in v1 |
| `limits` | `wall` = the run's wall budget + 60 s (the run stops it long before); memory, processes, CPU from the admission record, defaults 1024 MiB / 32 / the wall |

Everything else is denied by the deny-default Seatbelt profile: `$HOME` (except admitted subpaths),
`state_root`, the trust base (admission records, manifests, policy), other runs, the model server's port.

### 5.2 Why no workspace write, and Q-16

The file tools' race (OPEN-QUESTIONS 7, Q-16) exists because a confined process could change the workspace
(e.g. swap a path for a symlink) while the harness does in-process file operations. A server with no
writable root inside the workspace cannot do that, so P-37 needs neither the confined file-op helper nor the
interim (b) "stop unless every process is gone" rule, which a long-lived server could never satisfy. A
read-only workspace grant races nothing. `workspace: read_write` is refused by the admission record parser
until the owner decides Q-16 and the helper exists (O-4).

### 5.3 Lifetime and kill

A server starts only if at least one of its capabilities is granted, after the journal header and before the
first model call; it lives for the run (the whole session in session mode, across user turns) and is stopped
at **every** stop path: submit, any budget, loop stop, `session_ended`, journal failure, replay divergence,
a panic-free early return (the provider's `Drop` stops it too). Stop = relay frame `e` (close the server's
stdin), up to 1 s for it to exit, then close the control pipe so the stub sweeps the sandbox instance and
reports. `McpStopped` records the cleanup (`confirmed` with its kill count, or `unconfirmed`). An unconfirmed
cleanup mid-run stops the run (the same fail-closed rule as a command, §4.8); at the run's end it is
journaled and the outcome stays as it was (`NothingChecked` cannot get worse). Orphans after a harness crash
are swept by P-36's start-time orphan cleanup (scratch marker), which P-37 reuses.

### 5.4 Trifecta interplay

The server has no network in v1, and planning keeps refusing any capability with `egress ≠ none` ("egress
(the allowlist proxy is H4)", `plan_with`), so an MCP server adds no E label today. For when the egress
proxy exists (P-39, owner #1/#2):

- the server process would get `Network::Proxy(allowlist)` from its admission record, never a direct route,
  and never loopback (the proxy refuses loopback and private ranges, design §6.5), so never the model server;
- **process-level label lift** (in force from P-37b, before any egress exists): one process serves every tool
  of its manifest, so data handed to any of them can leave through any of them, and text fetched by any can
  surface in any. For an mcp-stdio capability the policy uses `egress`, `content` and `sensitivity` = the max
  over **all** capabilities of its manifest, granted or not. A server with one egress tool therefore makes
  every granted tool of it an E source, and P ∧ U ∧ E with a private workspace refuses the session (INV-9).
  Such servers are usable only in workspace-less sessions (the airlock) or with a `public` workspace.
- a quarantine or a dead server removes capabilities; removal only shrinks labels, but the trifecta is
  recomputed anyway (design §5.4, INV-9), with a test.

---

## 6. Manifest pins and admission

### 6.1 Pins (manifest v1, unchanged)

`harness_manifest::pins` (pure, P-37a):

- `description_digest(s: &str) = sha256(s.as_bytes())` over the server's `description` string as decoded
  from JSON. A tool with no `description` hashes the empty string. Manifest validation already refuses a
  summary with control, zero-width or bidi characters; the server's description is never shown, so it is
  hashed byte-exact and not inspected.
- `schema_digest(v: &Value) = sha256(canonical(v))`, canonical = compact JSON with object keys sorted
  (`serde_json::to_vec` on a `Value` without `preserve_order`), numbers as `serde_json` prints them. The same
  function runs at admission and at connect, over the same parsed form.
- `compare(manifest, presented) -> PinReport`: per capability `Ok | DescriptionDrift | SchemaDrift |
  Missing`; presented tools with no manifest entry are dropped and counted; a presented name listed twice is
  an error (refuse the connection).

The model never sees the server schema either: arguments are validated against the manifest's
`input_schema` (the stricter, reviewed subset with `additionalProperties: false`), and only args that pass are
sent. The schema pin proves the server still declares what was reviewed.

### 6.2 The admission record (trust base, design §6.4)

`<config dir>/providers/<provider>/` (P-07's config dir, 0700) holds `manifest.json` (the user's copy) and
`admission.json` (strict JSON, 0600):

```json
{"admission_version": 1, "provider": "notes", "tier": "pinned",
 "manifest_sha256": "<hex of manifest.json bytes>",
 "read_only": ["/opt/notes-mcp"], "workspace": "none",
 "env": {"NOTES_DIR": "/opt/notes-mcp/data"},
 "limits": {"memory_mib": 512, "processes": 16}}
```

`workspace` is `none` (default) or `read_only`; `read_write` is refused (O-4). Roots must be absolute,
canonical, existing, not containing `$HOME` as a whole (spec rules of `harness-sandbox::spec`). Written only by
`rustyharness provider add|repin` run by the user outside any run (INV-12; P-37m). An embedder passes
admissions in through the `harness-run` API instead (OD-2: the library reads no config). The run header
records, per provider in use, `{provider, tier, manifest_sha256, admission_sha256}` as a header input
(`mcp_providers`; absent when no MCP grant, so every existing header and digest is unchanged); `replay` and
`resume` must be given the same.

### 6.3 Tiers and the phase gate

`Registry::admit` keeps steps 1-3. Step 4 (the H1 phase gate) changes for exactly one pair: `Tier::Pinned`
with `Transport::McpStdio` admits. Still refused: `Signed` (needs an ed25519 crate through `deny.toml` and the
purity list, O-6), `InProcess` (unconfined provider code), any secret handle (§5.5 boundary not built).
Pinned data rules stand: `sensitivity ≤ operational`, `blast_radius ≤ host`. Policy (P-37b): every pinned
capability gets the derived floor `user_confirm` (design §4.4 "always … confirmation ≥ user_confirm"), so it
asks unless a user allow rule (or a P-23 session grant) covers it; `protected_action` floors are never lowered.

### 6.4 `rustyharness provider` (P-37m)

`provider add <dir>`: parse and validate the manifest, print the plain-language capability table (effective
class per §4.2, sanitised), require a conformed sandbox, start the server confined once, handshake, list,
`compare`; any drift or missing tool refuses and prints the presented hashes (so an author can fix the
manifest); otherwise ask the user (TTY only; no TTY = refuse) and write the two files. `provider repin
<provider>`: the same, but on drift it shows the old and new description text side by side (sanitised, cut at
2 KiB) and, on an explicit yes, rewrites the pins in the user's manifest copy and the record. `provider list`,
`provider remove`. Nothing here runs inside a run.

---

## 7. Connect, pin check, rug-pull quarantine

### 7.1 At connect (after `RunStarted`, before the first `ContextBuilt`)

For each provider in use: connect, journal `McpConnected` (protocol, untrusted server info, the baseline
list as an untrusted blob, its digest, per-capability pin status). Then, for each capability whose status is
not `Ok`: the `Quarantined` standing condition enters (`key` = capability id). If any **granted** capability is
quarantined or missing, or a connect fails, the run stops there, before any model call, with
`Indeterminate { CouldNotRun }` and a message naming the capability and the fix (`rustyharness provider
repin <provider>`). Zero tool invocations happen (INV-7's falsifying test). Why stop instead of running
without it: the task asked for it, and design §4.5 forbids silently dropping a granted capability.

### 7.2 Before every MCP call

The client re-lists (`tools/list`, same bounds). If the list's digest equals the previous one, the call
proceeds. Otherwise it compares each admitted tool's **whole entry** (canonical JSON of the tool object:
name, title, description, inputSchema, outputSchema, annotations, `_meta`, everything) with the connect-time
baseline:

- an admitted tool changed or vanished: that capability is quarantined (`entry_changed` / `removed`);
- tools appeared that the manifest does not name: dropped, counted, nothing quarantined;
- the drift is journaled once (`McpDrift`, with the new list as a blob), the `Quarantined` condition enters;
- if the called capability is quarantined, the call ends `Refused { Quarantined }` with a harness message,
  and the server is **not** called.

Mid-run comparison is stricter than connect (the whole entry, not two hashes) because nothing outside the
run needs to be reproduced: the baseline is the run's own first observation.

Why re-list before every call rather than on `list_changed` only: a server that rug-pulls has no reason to
announce it. One extra local round trip per call is cheap, and it gives the journal a digest of what the
server claimed at the moment of each call. It cannot detect a server that keeps its metadata and changes its
behaviour (named in §18).

### 7.3 Withdrawal

A quarantined capability leaves the active set at the next context build, through the same path the loop
detector's `removed_capabilities()` uses (design §2.6), with a one-line harness notice naming the tool and
"withdrawn: its provider changed or stopped". `Session::quarantine` then re-runs the trifecta (§5.4). A
withdrawn tool that the model still calls is denied by policy (`deny.quarantined`, already in `decide`).
The notice text is new harness text; it only appears in runs that use MCP, so no existing journal's context
digest changes. P-37i adds a golden for it and the H-D owner decides whether it rides the next `rh-context/N`
bump (it is listed for the P-33 consolidation).

---

## 8. Namespacing and duplicates

1. The namespace is the manifest's `provider`; reserved names (`harness`, `rustyvault`, plus config
   additions) are refused (INV-1).
2. Two admitted providers with one namespace: refused (`AdmissionError::Shadowed`, INV-8).
3. Capability ids lie inside their namespace; `mcp_name` is 1:1 per manifest (`DuplicateMcpName`).
4. The model sees and calls `provider.verb` only; `mcp_name` never enters context, approvals or logs shown
   to the model. A model that types a server tool name gets the ordinary unknown-tool format error.
5. A server that lists one name twice: connection refused (ambiguous binding; never "first wins").
6. Two providers may run the same binary; they are separate processes with separate scratch dirs.

---

## 9. One call

1. **Decide.** The parsed action names a manifest id. `Session::decide` validates the args against the
   manifest schema and applies deny → ask → allow → default deny with the pinned floor, the effective class
   (lifted, §5.4), quarantine and P-08 rules. Approvals show the manifest `summary`, the class in plain words,
   the rendered args (escaped): no server text.
2. **Intent.** `append_intent` (fsynced) mints `Journaled<Authorized<Call>>`; `McpProvider::invoke` accepts
   only that type (INV-33, `provider.rs`'s compile-fail doctests apply unchanged).
3. **Pre-call relist** (§7.2).
4. **Exchange.** One `tools/call`, waiting for its response under the deadline, refusing/dropping noise.
5. **Render** (`render.rs`, pure): `result.content` text blocks joined with `\n`; every other block becomes
   one placeholder line (`[image omitted: <mime>, <n> bytes]`, `[audio omitted …]`, `[resource omitted:
   <uri, sanitised, cut at 200 bytes>]`); no text block but `structuredContent` present → its canonical JSON;
   `isError: true` → `ToolStatus::Error { code: MCP_TOOL_ERROR }`; a JSON-RPC `error` → `Error { code:
   MCP_RPC_ERROR }` with its message (untrusted, cut at 1 KiB); then the byte cap (§4). Codes join
   `harness_tools::builtin::code`.
6. **Result.** `ToolResult { output: Untrusted::new(text, Source::Tool(id)), truncated, digest: sha256(text),
   mcp: Some(McpRecord { request_id, request_sha256, response_frame, list_sha256, noise }) }` (a new optional
   field; `None` for every built-in). The context builder delimits it with the run's nonce, strips invisibles
   and withholds a nonce echo, as for every observation; nothing in it is ever parsed for actions (INV-29).
7. **Journal.** `ToolFinished` with the usual fields plus the `mcp_*` fields (§11); the wall time is charged
   after it is durable, as for every tool.

---

## 10. Tool-count cap and small models

`plan()` counts grants against `profile.max_active_tools()` (5-8) and refuses `TooManyTools`. MCP grants are
grants; no change, no exemption, and no wildcard grant (`provider.*` is a policy selector, not a grant). A
CLI message names the MCP grants first when it refuses, since they are the usual surplus. Per-tool context
cost is bounded by the manifest (summary ≤ 512 bytes; schema depth ≤ 4, ≤ 32 properties, enums ≤ 64) and is
reviewed text, so it is also stable across turns (prefix-cache friendly: a server cannot grow the tool block).
Raising the cap for interactive profiles is Q-6 (O-3).

---

## 11. Journal records (P-37g; canonical bodies, keys sorted on the wire)

New kinds, all appended with `append` and **fsynced** (inputs or provider-state changes resume keys on):

**`McpConnected`** (step 0)

| field | type | audit rule |
|---|---|---|
| `provider` | Id | recomputed (from the header input) |
| `protocol` | Text | re-fed; must equal the negotiated version recomputed from the manifest |
| `server_info` | UntrustedBlob (`initialize` result's `serverInfo` + `instructions`, canonical JSON) | re-fed, never rendered |
| `tools` | UntrustedBlob (the baseline list: every page's `tools` array, concatenated, canonical JSON) | re-fed |
| `tools_sha256` | Digest | recomputed from `tools` |
| `pins` | Obj `{<capability id>: "ok" \| "description" \| "schema" \| "missing"}` | recomputed by `pins::compare` |
| `dropped` | U64 (presented tools the manifest does not name) | recomputed |

**`McpDrift`** (step of the call that found it): `provider` (Id), `tools` (UntrustedBlob, the new list),
`tools_sha256` (Digest, recomputed), `quarantined` (Obj id → `entry_changed` | `removed`, recomputed against
the baseline), `added` (U64, recomputed).

**`McpStopped`**: `provider` (Id), `reason` (Text `run_end` | `violation:<kind>` | `timeout` | `exited` |
`eof`), `cleanup` (Text `confirmed` | `unconfirmed`), `kills` (U64), `stderr` (UntrustedBlob, the kept tail),
`stderr_dropped` (U64). Re-fed (it is an observation of the process), except that audit recomputes that
one was written at every stop.

**`ToolFinished`** of an MCP capability gains: `mcp_request_id` (U64), `mcp_request` (Digest of the exact
line written), `mcp_list` (Digest of the pre-call list), `mcp_noise` (U64), and `mcp_response` (UntrustedBlob,
the raw response line) when a response arrived. Absent for every other capability, so no existing record
changes. **Quarantined** keeps its standing-condition body (`condition`, `key`, `affected`).

The reader accepts the new kinds; `replay::recorded` refuses `mcp_*` fields on a non-MCP capability and an MCP
`ToolFinished` without them. Hotspot H-E: P-37g is the only P-37 slice touching `canon.rs`.

---

## 12. Replay, audit, resume

**Audit** (no server is started; `reproduce` mode is not built):

- `McpConnected`: re-feed `protocol`, `server_info`, `tools`; recompute `tools_sha256`, `pins`, `dropped`,
  the quarantine entries and the stop-before-first-call decision.
- Each MCP call: the intent is recomputed as today; then recompute `wire::encode_call(mcp_request_id,
  mcp_name, args)` and compare its digest with `mcp_request` (catches an edited id, name or args); check
  `mcp_request_id` is greater than every earlier one; re-feed `mcp_list` and, when it differs, the matching
  `McpDrift.tools`, and recompute the quarantine decision and refusal; re-feed `mcp_response` and recompute
  `render(…)` → `status`, `output`, `digest`, `truncated`: any difference is a divergence at that step. So a
  tampered observation is caught even at the last step (unlike built-in tool results, whose last result is
  anchor-only, row H1e-2b), because the raw frame and the rendered text are tied by a pure function.
- `McpStopped`: re-fed; its presence after each stop is recomputed.

**Resume** reconnects every provider in use in the new attempt (fresh process, fresh `McpConnected`), with the
header inputs required to match. The new baseline is compared with the old attempt's baseline as in §7.2;
a changed admitted tool is quarantined, and if it is granted the resume stops `CouldNotRun`. Completed calls
are re-fed, never re-sent. A **cut** last step (intent without result) whose capability is an MCP one with
effect `write` or above refuses the resume: its effect may or may not have happened on the server's side,
and nothing in the workspace digest can tell (the server cannot write the workspace). The message says so and
names the capability. A cut `read` call runs again live, decided again by policy, as today.

**Session mode (P-05):** the server lives across turns; `UserTurn` does not reconnect; `audit_session` and
`resume_session` apply the rules above; a session reopened after `session_ended` reconnects like a resume.

---

## 13. Why our own client, not rmcp

Design D7 says rmcp; §11 lists "rmcp starts pulling compiled C, or requires server features §4.6 refuses"
as the reason to switch. The reasons found now are different and sufficient on their own:

1. **One spawn site (INV-23, `purity.sh` §2f, §5).** rmcp's stdio transport spawns the child itself
   (tokio's process API). The harness may start processes only in `capture.rs` and `confine_spawn.rs`, and
   §5 of the gate admits only crates.io crates reviewed to have no process API. tokio has one (feature-gated,
   and features unify across the workspace), so admitting it means reviewing a moving feature set forever.
2. **The harness is synchronous.** `ModelBackend` and `ToolProvider` are sync by decision (H1e); rmcp is
   async-only and would bring a runtime into a process that has none.
3. **Dependency surface.** rmcp brings tokio, futures, a proc-macro crate and a schema crate; the workspace
   today locks ~33 packages and its gate lists each by review.
4. **We use almost none of it.** Four methods, newline framing, no transports but stdio, and we refuse most
   of what rmcp implements (sampling, roots, elicitation, resources, prompts).
5. **Precedent.** `harness-model` is our own HTTP/1.1 client for the same reasons, and it works.

Cost accepted: spec drift is ours to track (mitigated by the exact-version pin, D2, and wire tests per
version), and we must test against real servers (P-21-style manual runs, O-2). Owner decision #8 recommends
the same. This note amends D7 for the implementation; the design doc row is updated at wave consolidation.

---

## 14. The fake server (`harness-mcp-fixture`)

A `publish = false` workspace crate: `src/lib.rs` has `serve(mode, input: impl BufRead, output: impl Write)`
(the server logic, std + `serde_json` only), `src/main.rs` is the bin `rh-mcp-fixture` (`#![forbid(unsafe_code)]`)
that reads `--mode <m>` from argv and serves stdin/stdout. Modes (each a test's hostile server):

`ok` (two tools `echo`, `add`; descriptions and schemas fixed, their pins printed by a test helper),
`drift-description`, `drift-schema` (wrong at connect), `rug-pull-after:<n>` (changes `echo`'s description
after n calls), `vanish-after:<n>`, `list-changed-spam`, `malformed`, `huge-frame` (a 2 MiB line),
`slow-loris` (one byte per 100 ms), `wrong-id`, `string-id`, `double-response`, `result-and-error`,
`flood` (10 000 notifications), `sampling`, `roots`, `elicit`, `ping`, `request-flood`, `batch`,
`version:<v>`, `no-tools-capability`, `dup-tool-name`, `paginate:<pages>`, `instructions-injection`
(an `instructions` string with an action block), `result-injection` (a text block with `<action>…</action>`
and a forged nonce delimiter), `exit-midcall`, `stderr-spam`, `hang`, `confinement-probe` (a tool that tries
to write `$HOME/canary`, write in the workspace, connect to 127.0.0.1:<model port> and 1.1.1.1:443, read a
planted home canary, and reports each result as text).

How tests reach it:
- `harness-mcp` dev-depends on the fixture **lib**; `testing::InMemoryConnector` runs `serve` on a thread over
  in-memory pipes, so client, provider and hostile tests run on every OS.
- Real confined runs need the **binary**, and Cargo exposes `CARGO_BIN_EXE_rh-mcp-fixture` only to the
  fixture crate's own integration tests. So the end-to-end tests (`run` + real sandbox + real process) live in
  `crates/harness-mcp-fixture/tests/` with dev-dependencies on `harness-run`, `harness-mcp`,
  `harness-sandbox`, `harness-manifest`; they are `#[cfg(target_os = "macos")]` and say why they skip elsewhere,
  like `conformance_macos.rs`. Integration tests may spawn (`purity.sh` §2f), but these spawn only through
  `SystemConfinement`.
- Driver tests in `harness-run/tests/mcp.rs` use a real witness from `SystemConfinement.require()` (macOS,
  the `exec.rs` precedent) and the `InMemoryConnector`, which takes `&Conformed` like the real one, so the
  type gate is the same and no process starts.
- INV-31: the e2e manifest lives at `adapters/fixture-mcp/manifest.json` with a namespace (`zzfixture`) that
  no file under `crates/` names; `fixture_provider_integrates_with_zero_core_diff` greps `crates/*/src` for it.

---

## 15. Invariants

Provisional names (numbered at wave consolidation; sibling ARCH notes may claim INV-42+ in parallel).

| Id | Property | Tests (slice) |
|---|---|---|
| INV-6 (H4 part) | no mcp-stdio process without `Conformed`; no unconfined fallback | `mcp_capability_without_conformed_refused_at_planning` (b), `confined_connector_refuses_without_witness` (l), `mcp_grant_refused_on_host_without_backend` (i) |
| INV-7 | drift quarantines until repinned outside the run | `mcp_tool_list_pinned_hash_mismatch_quarantines` (i), `rug_pull_mid_session_quarantines_and_withdraws` (i) |
| INV-8 | namespaces unique, ids in namespace | `mcp_duplicate_namespace_refused` (a) |
| INV-9 | trifecta recomputed on quarantine; process-level lift | `quarantine_recomputes_trifecta_and_never_widens`, `process_label_lift_marks_sibling_capability_third_party` (b) |
| INV-23 | no payload on any argv; server started only by `confine_spawn` | `duplex_payload_never_on_argv` (k), purity §2f unchanged list |
| INV-29 | nothing in an MCP result, description or `instructions` is parsed as an action | `mcp_result_action_block_never_parsed`, `server_instructions_never_reach_context` (i) |
| INV-31 | a new MCP provider integrates with no core diff | `fixture_provider_integrates_with_zero_core_diff` (l) |
| INV-MCP-1 | no server text but rendered `tools/call` content reaches the model or an approval prompt | `tool_block_uses_manifest_summary_not_server_description` (i), `approval_shows_manifest_summary_only` (m) |
| INV-MCP-2 | a server has no workspace write root and no network, and is stopped and swept at every stop | `mcp_server_runs_confined` (l), `server_stopped_on_every_stop_path` (i) |
| INV-MCP-3 | every MCP observation's raw frame is durable before the observation exists, and audit re-renders it | `mcp_call_journaled_and_policy_checked` (i), `audit_detects_tampered_mcp_response_even_at_last_step` (j) |
| INV-MCP-4 | a protocol violation, timeout or exit ends the provider for the run; nothing it sends afterwards is read | `client_timeout_kills_server`, `client_response_with_unknown_id_is_violation` (e) |
| INV-MCP-5 | a cut MCP call with effect ≥ write is never re-sent by resume | `resume_refuses_cut_mcp_write_call` (j) |

Unaffected: INV-1..5, 10 (no secret handles admitted), 11-22, 24-28, 30, 32-41.

---

## 16. Dependence on P-36 (spawn precedent)

P-36 is the first slice to give `confine_spawn.rs` a **long-lived** confined process (start now, read output
while it runs, stop later, sweep, orphan cleanup by scratch marker, a run-level registry that stops every live
process at every stop path). P-37 needs exactly that, plus one thing P-36 does not: the program's **stdin**.

What P-37k adds on top of P-36's handle (in `confine_spawn.rs`, so the pinned hash changes again, by review):
a frame header `rh-stub/2` (the stub keeps accepting `rh-stub/1`, so exec is untouched) after which the
control pipe carries relay frames `d <len>\n<bytes>` (bytes for the program's stdin) and `e\n` (close the
program's stdin); EOF of the control pipe still means stop and sweep. The stub never blocks in a write: it
writes to the program's stdin only when `select` reports it writable, keeps watching the control pipe, and
buffers at most 1 MiB (the harness never has more than one request in flight). The program's stdout is the
stub's stdout, streamed to the harness unchanged. API: `Confinement::spawn_duplex(&ConfinedSpec, &Conformed)
-> Result<ConfinedDuplex, SpawnError>` (a default method that refuses, so `NoConfinement` and test seams need
no change), `ConfinedDuplex { send, close_stdin, take_stdout, stop -> ConfinedExit }`.

| Slice | Before P-36's spawn-pin work lands? |
|---|---|
| P-37a manifest pins + admission gate | **yes** (pure) |
| P-37b policy planning rules | **yes** (pure) |
| P-37c wire codec | **yes** (pure) |
| P-37d fixture crate | **yes** |
| P-37e client state machine + hostile tests | **yes** (in-memory transport) |
| P-37f renderer | **yes** (pure) |
| P-37g journal kinds | **yes** (but serialised with any other `canon.rs` slice) |
| P-37h provider + connector seam + `InMemoryConnector` | **yes** |
| P-37i driver wiring | **yes** (macOS witness + in-memory connector; serialised in the driver chain) |
| P-37j audit and resume | **yes** (same) |
| P-37k duplex spawn in `confine_spawn.rs` + pin | **no**: needs P-36's long-lived handle and pin, and H-G allows one `confine_spawn.rs` slice at a time |
| P-37l `ConfinedConnector`, e2e confined tests, conformance, INV-31 | **no** (needs k) |
| P-37m `rustyharness provider` CLI + task wiring | **no** (add/repin start a real server; needs l) |

If P-36 is delayed, P-37a-j still land and are useful (a full MCP path, audited, tested in memory); only real
servers wait. When P-36 is split into its own slices, replace `P-36` in P-37k's deps with the id of its
spawn-pin slice.

---

## 17. Owner questions (each with the fail-closed default that holds until answered)

| Id | Question | Default | Recommendation |
|---|---|---|---|
| O-1 (Q-13) | Own thin client (this note) or rmcp as design D7 says? | Own client; no rmcp | Own client (§13; owner decision #8 recommends the same) |
| O-2 | Which MCP protocol versions? A version we have not wire-tested is refused. | `2025-06-18` only | Add newer versions one at a time, each with fixture wire tests and one manual run against a real reference server |
| O-3 (Q-6) | MCP tools count against `max_active_tools` (5-8). Raise the cap for interactive profiles? | Count them; cap unchanged; over the cap the run is refused | Allow up to 12 only for a profile whose stamp's smoke eval ran with that many tools (P-21 measures) |
| O-4 (Q-16) | May a server get the workspace? | `none` by default; `read_only` opt-in in the admission record; `read_write` refused | Keep `read_write` refused until the confined file-op helper exists |
| O-5 | Show the server's (pin-verified) description to the model instead of the manifest summary? | No: manifest summary and schema only | No: the summary is the text the user approved; server text is the classic tool-poisoning channel |
| O-6 | The `signed` tier (ed25519 crate through `deny.toml` and the purity list) | Refused; `pinned` only | Later slice, after a crate review; not needed for personal use |
| O-7 (Q-1, Q-2) | Servers with egress capabilities | Refused until the egress proxy exists; then proxy-only with the process-level label lift | As default; usable in airlock sessions only |
| O-8 | Resume after a cut MCP write call | Resume refused; the user starts a new run | Accept |
| O-9 | Remote MCP (Streamable HTTP) | Not built (no TLS in the default build, owner #2) | Behind the opt-in `net` feature, after P-39's fetcher review |
| O-10 | A timeout or violation ends the server for the run (no restart) | No restart | Accept for v1; a later bounded restart (≤ 1, journaled as a new connection with its own baseline) if real servers need it |

---

## 18. What could make this design wrong

- A server keeps its metadata and changes behaviour (returns hostile text, or does a different side effect).
  Pins and re-listing cannot see that; the defences are confinement, `Untrusted` results, per-call policy and
  the trifecta. If behaviour drift matters, the answer is per-call output checks, not more hashing.
- Real servers rely on things refused here: answering `ping`, `roots/list` (filesystem servers ask for
  roots), sampling, or `read_write` workspace access. Then many useful servers do not work until those are
  designed (roots could map to the workspace grant; never sampling).
- Popular servers are Node or Python programs that need wide read-only roots (a whole runtime, `node_modules`,
  a venv) and environment, which makes admission records long and error-prone. A `provider add` that measures
  what the server opened (a Seatbelt trace run) would be the fix.
- The 5-8 tool cap makes MCP impractical next to the built-ins for small models (O-3).
- The pre-call relist costs too much for servers with large lists or slow `tools/list`; then relist only on
  `list_changed` plus every N calls, and accept a weaker journal.
- Server stdout that is not strictly one message per line (pretty-printed JSON, log lines) is common in the
  wild; we refuse it (a violation). If too many servers do this, a tolerant mode would be a separate, named,
  weaker tier, never the default.
- The protocol moves faster than our pin (versions after `2025-06-18` change tool result shapes); the exact
  pin keeps us safe but may leave us unable to talk to current servers.
- If P-36 chooses a long-lived process API whose stop path can block (e.g. a blocking write), the duplex mode
  inherits it; P-37k's `relay_stop_works_when_server_never_reads_stdin` exists to catch that.

---

## 19. Slice cards (to paste into the roadmap)

Card fields as in §4.3 of the roadmap. Machine-readable deps and order: `docs/slices/P-37-slices.json`.

**P-37a Manifest pins, MCP version set, admission gate for pinned mcp-stdio**
- Why: §6.1, §6.3, D2. Pure `harness_manifest::pins` (`description_digest`, `schema_digest` over canonical JSON, `compare(manifest, presented) -> PinReport`), `SUPPORTED_MCP_PROTOCOLS = ["2025-06-18"]` and `negotiate()`, and the phase gate lifted for exactly `Tier::Pinned` + `Transport::McpStdio` (signed, in-process and secret handles still refused).
- Crates: harness-manifest.
- Tests: `schema_digest_is_key_order_independent`, `description_digest_is_exact_bytes`, `pin_report_flags_description_drift`, `pin_report_flags_schema_drift`, `pin_report_missing_tool_is_missing`, `pin_report_drops_unlisted_tools_and_counts`, `pin_report_duplicate_presented_name_refused`, `negotiate_picks_highest_common_version`, `negotiate_none_in_common_refused`, `pinned_mcp_stdio_admits`, `mcp_duplicate_namespace_refused`, `signed_tier_still_refused`, `in_process_still_refused`, `secret_handles_still_refused`, existing manifest tests unchanged.
- Deps: none. Parallel: yes (manifest only). Risk: low-medium (trust root). ARCH: no.

**P-37b Policy planning for MCP capabilities**
- Why: §5.4, §6.3, §9 step 1. The planner's lookup carries the provider's tier and transport and the whole manifest; mcp-stdio capabilities require `conformed` (INV-6); pinned-tier derived floor `user_confirm`; provider-declared `write`/`execute` plan and ask instead of `OutOfScope`; egress still refused; process-level label lift (max egress/content/sensitivity over the manifest); quarantine re-runs the trifecta.
- Crates: harness-policy.
- Tests: `mcp_capability_without_conformed_refused_at_planning`, `pinned_tier_read_capability_asks_by_default`, `pinned_tier_allow_rule_allows_unattended`, `mcp_protected_action_never_allowed_by_rule`, `mcp_write_capability_plans_and_asks`, `mcp_egress_capability_refused_until_proxy`, `process_label_lift_marks_sibling_capability_third_party`, `quarantined_mcp_capability_denied_with_rule_id`, `quarantine_recomputes_trifecta_and_never_widens`, `builtin_decisions_unchanged`.
- Deps: P-37a, P-08. Parallel: yes (policy only; not with another `plan_with` slice). Risk: medium (trust root). ARCH: no.

**P-37c `harness-mcp` crate: pure wire codec**
- Why: §3.1-§3.4. New crate (publish=false), `wire.rs`: bounded newline frame reader over `Read`, strict parse, classification (response / server request / notification / violation), deterministic encoders (`initialize`, `initialized`, `tools/list`, `tools/call`, `-32601` reply). Adds `wire.rs` (and the later `render.rs` path) to the purity gate's pure-file scan.
- Crates: harness-mcp (new), Cargo.lock (H-F), scripts/ci/purity.sh (scan list only, not the pinned hashes).
- Tests: `codec_refuses_malformed_json_line`, `codec_refuses_duplicate_keys`, `codec_refuses_frame_over_cap_without_buffering_it`, `codec_refuses_non_utf8`, `codec_refuses_trailing_cr`, `codec_refuses_batch_array`, `codec_classifies_request_notification_response`, `codec_refuses_null_or_float_id`, `encode_call_is_deterministic_and_sorted`, `encode_initialize_has_empty_capabilities`.
- Deps: none. Parallel: yes (new crate; Cargo.lock regenerate). Risk: low. ARCH: no.

**P-37d `harness-mcp-fixture`: the fake MCP server in Rust**
- Why: §14. New `publish = false` crate, lib `serve(mode, input, output)` + bin `rh-mcp-fixture` (`--mode`), every hostile mode listed in §14, std + `serde_json` only, `#![forbid(unsafe_code)]`.
- Crates: harness-mcp-fixture (new), Cargo.lock (H-F).
- Tests: `fixture_ok_mode_answers_initialize_list_call`, `fixture_every_mode_parses`, `fixture_rug_pull_changes_description_after_n_calls`, `fixture_bin_speaks_newline_json` (spawns `CARGO_BIN_EXE_rh-mcp-fixture` with std in its own integration test), `fixture_pins_helper_matches_ok_mode`.
- Deps: none. Parallel: yes (new crate; Cargo.lock regenerate). Risk: low. ARCH: no.

**P-37e Client state machine and hostile-server suite**
- Why: §3.2-§3.5, §4. `client.rs` over a `Transport` trait (send line, receive line before a deadline, kill): connect (version must match exactly, `tools` capability required, pagination bounds, duplicate names refused), call, relist, `-32601` to every server request, noise caps, id discipline, absolute deadlines, provider death on any violation. Tested over in-memory pipes with the fixture lib.
- Crates: harness-mcp.
- Tests: `client_protocol_version_mismatch_refused`, `client_server_without_tools_capability_refused`, `client_tools_list_pagination_bounded`, `client_duplicate_tool_name_in_list_refused`, `client_slow_loris_hits_absolute_deadline`, `client_timeout_kills_server`, `client_response_with_unknown_id_is_violation`, `client_response_with_string_id_for_int_is_violation`, `client_duplicate_response_is_violation`, `client_result_and_error_both_is_violation`, `client_notification_flood_is_violation`, `client_server_request_sampling_refused_with_32601`, `client_server_requests_roots_elicitation_ping_refused`, `client_server_request_flood_is_violation`, `client_stdout_garbage_before_initialize_is_violation`, `client_huge_frame_is_violation`, `client_eof_mid_response_is_crash`, `client_cancelled_for_outstanding_id_ends_call`.
- Deps: P-37a, P-37c, P-37d. Parallel: yes with P-37f/g. Risk: medium (protocol edge cases). ARCH: no.

**P-37f Result renderer (pure, audit-recomputable)**
- Why: §9 step 5, §12. `render.rs`: raw response line + cap → `(status, text, truncated, digest)`; text blocks only, placeholders for others, `isError` and JSON-RPC errors mapped to new `MCP_TOOL_ERROR`/`MCP_RPC_ERROR` codes, `structuredContent` fallback, byte cap.
- Crates: harness-mcp, harness-tools (two code constants only).
- Tests: `render_text_blocks_joined`, `render_image_block_placeholder_only`, `render_resource_link_placeholder_sanitised_and_cut`, `render_is_error_maps_to_tool_error`, `render_rpc_error_message_bounded`, `render_structured_content_fallback_canonical`, `render_bounded_marks_truncated`, `render_deterministic_digest`, `render_action_block_is_plain_text`.
- Deps: P-37c. Parallel: yes. Risk: low. ARCH: no.

**P-37g Journal kinds and `ToolFinished` MCP fields**
- Why: §11. `McpConnected`, `McpDrift`, `McpStopped` added to the closed kind set with canonical field lists, all fsynced; optional `mcp_request_id`, `mcp_request`, `mcp_list`, `mcp_noise`, `mcp_response` on `ToolFinished`; reader accepts them; old journals read unchanged.
- Crates: harness-journal.
- Tests: `mcp_kinds_round_trip_canonical`, `mcp_kinds_are_fsynced`, `tool_finished_mcp_fields_round_trip`, `mcp_response_blob_tamper_detected`, `unknown_kind_still_refused`, `old_journal_still_reads`.
- Deps: P-10. Parallel: no other slice touching `canon.rs` (H-E). Risk: low-medium. ARCH: no.

**P-37h `McpProvider`, connector seam, in-memory connector**
- Why: §7.2, §9, §14. `McpProvider: ToolProvider` (pre-call relist, entry-digest comparison, quarantine/refusal, call, render, `McpRecord`), `McpConnector` trait taking `&Conformed`, `testing::InMemoryConnector` (feature `testing`, dev-only; purity rule: no normal edge enables it), optional `ToolResult.mcp: Option<McpRecord>`.
- Crates: harness-mcp, harness-tools (`provider.rs` field), scripts/ci/purity.sh (feature rule only).
- Tests: `provider_relist_drift_quarantines_before_call`, `provider_new_unlisted_tool_does_not_quarantine`, `provider_vanished_tool_quarantines`, `provider_timeout_marks_provider_dead`, `provider_result_is_untrusted_tool_source`, `provider_never_sends_mcp_name_it_was_not_admitted_for`, `builtin_results_have_no_mcp_record`, `testing_feature_not_enabled_by_normal_edges` (purity selftest case).
- Deps: P-37b, P-37e, P-37f. Parallel: yes (no driver). Risk: medium. ARCH: no.

**P-37i Driver wiring: connect, journal, drift, stop**
- Why: §6.2 header input, §7, §9, §5.3. `harness-run` takes admissions and an `McpConnector`; header input `mcp_providers`; connect after `RunStarted`; `McpConnected`; connect-time quarantine stops `CouldNotRun` before any model call; MCP `ToolFinished` fields; `McpDrift` + `Quarantined` + withdrawal notice; `McpStopped` at every stop path; MCP grants counted against the tool cap. Tests use a macOS witness and the in-memory connector.
- Crates: harness-run (driver chain, H-B).
- Tests: `mcp_call_journaled_and_policy_checked`, `mcp_tool_list_pinned_hash_mismatch_quarantines`, `rug_pull_mid_session_quarantines_and_withdraws`, `tool_block_uses_manifest_summary_not_server_description`, `server_instructions_never_reach_context`, `mcp_result_action_block_never_parsed`, `server_stopped_on_every_stop_path`, `mcp_tools_count_against_max_active_tools`, `mcp_grant_refused_on_host_without_backend` (every OS), `no_mcp_header_unchanged`, `mcp_session_server_survives_user_turns`.
- Deps: P-37g, P-37h, P-09, P-13. Parallel: no (driver chain). Risk: high (the loop). ARCH: no; reviewer pass required.

**P-37j Audit and resume of MCP runs**
- Why: §12. Audit re-feeds `McpConnected`/`McpDrift`/`McpStopped` and raw frames, recomputes request digests, pin and quarantine decisions and the rendered observation; resume reconnects and compares baselines; a cut MCP call with effect ≥ write refuses the resume.
- Crates: harness-run (replay, H-B).
- Tests: `audit_of_mcp_run_is_clean`, `audit_detects_tampered_mcp_response_even_at_last_step`, `audit_detects_edited_mcp_request_args`, `audit_detects_forged_pin_status`, `audit_detects_decreasing_mcp_request_id`, `resume_mcp_run_reconnects_and_refeeds`, `resume_quarantines_when_baseline_changed`, `resume_refuses_cut_mcp_write_call`, `resume_reruns_cut_mcp_read_call_live`, `audit_session_with_mcp_clean`.
- Deps: P-37i, P-17. Parallel: no (replay chain). Risk: high. ARCH: no; reviewer pass required.

**P-37k Confined duplex spawn (stdin relay) and pin re-review**
- Why: §16. `rh-stub/2` relay mode in the domain stub (select-based, never blocking in a write, ≤ 1 MiB pending), `Confinement::spawn_duplex` (default refuses), `ConfinedDuplex`; `confine_spawn_sha256` updated in `purity.sh` in the same commit, said loudly in the slice note; exec's `rh-stub/1` path byte-for-byte unchanged in behaviour.
- Crates: harness-sandbox, scripts/ci/purity.sh (H-G).
- Tests: `duplex_round_trips_lines`, `duplex_payload_never_on_argv`, `relay_stop_works_when_server_never_reads_stdin`, `duplex_stop_sweeps_domain_confirmed`, `duplex_close_stdin_lets_server_exit`, `stub_v1_exec_behaviour_unchanged` (existing exec and conformance suites), `no_confinement_spawn_duplex_refuses`.
- Deps: P-36, P-41. Parallel: no (`confine_spawn.rs` and its pin). Risk: high (spawn site). ARCH: no.

**P-37l `ConfinedConnector`, end-to-end confined tests, conformance, INV-31**
- Why: §5.1, §14. Builds the server's `ConfinedSpec` from the admission record (scratch-only writes, optional read-only workspace, built env, no network), spawns through `spawn_duplex`; e2e tests in `harness-mcp-fixture/tests/` with the real binary and sandbox (macOS; skipped with reason elsewhere); the zero-core-diff test.
- Crates: harness-mcp, harness-mcp-fixture (tests), adapters/fixture-mcp (data).
- Tests: `confined_connector_refuses_without_witness`, `spec_for_server_has_no_workspace_write`, `spec_env_only_admission_values`, `mcp_server_runs_confined` (fixture `confinement-probe`: home write, workspace write, network to model port and internet, home canary read all refused), `e2e_ok_mode_run_audits_clean`, `e2e_rug_pull_quarantines`, `e2e_hostile_modes_end_provider_not_run`, `e2e_server_killed_at_run_end`, `fixture_provider_integrates_with_zero_core_diff`.
- Deps: P-37k, P-37i, P-37j. Parallel: yes after k (no shared hotspot). Risk: medium-high. ARCH: no.

**P-37m `rustyharness provider` and task wiring**
- Why: §6.2, §6.4. `provider add|repin|list|remove` writing the admission record and manifest copy in the user config dir (TTY confirmation; refuses without one), registry built from built-ins plus admitted providers, admissions and the confined connector passed to `run`/`chat`; approval prompt shows the manifest summary; usage text.
- Crates: harness-cli.
- Tests: `provider_add_refuses_drifted_server_and_prints_presented_hashes`, `provider_add_requires_tty_confirmation`, `provider_add_writes_record_0600_outside_workspace`, `provider_repin_shows_old_and_new_description`, `provider_remove_only_its_own_files`, `admission_read_write_workspace_refused`, `approval_shows_manifest_summary_only`, `run_with_mcp_grant_uses_admitted_provider`, `usage_text_lists_provider_verbs`.
- Deps: P-37l, P-07, P-23. Parallel: small cli hotspot (dispatch line). Risk: medium (trust-base writes). ARCH: no.
