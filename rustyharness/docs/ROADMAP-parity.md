# rustyharness: parity-gap analysis and work roadmap

Repo read: `FYP/repo/.wt-h3a-presubmit` (branch `h3a-presubmit-checks`, HEAD `c03c1dd`, ~59k LOC incl. tests, 11 crates, 686 `#[test]`).
Sources: README, `docs/00-overview.md`, `docs/01-design-v0.1.md` (OD-1..OD-7, §2-§7, §9, §11), `docs/OPEN-QUESTIONS.md`, and the code named below. Competitor facts: vendor docs fetched 2026-10-01 (opencode permissions/tools, Codex CLI, Gemini CLI, Goose) plus prior knowledge for Claude Code, Cline/Roo and Aider; cells marked `~` are less certain.
Plain-language rule from the owner's memory: module codes are not used here; nothing in this file names one.

---

## 1. Inventory: what rustyharness has TODAY (verified in code)

### 1.1 CLI (`crates/harness-cli/src/lib.rs`, 1350 lines, one file; `main.rs` is a thin wrapper)
Verbs (`main_with`, lib.rs ~L225): `version`, `sandbox`, `manifest check <file>`, `run`, `resume`, `replay`, `profile check`. Nothing else: no REPL, no `chat`, no `sessions`, no `gc`, no `events`.
- `run` options: `--task --workspace --state-root --profile --endpoint [--policy] [--gate]`; all required but policy/gate. `resume` adds `--run`. `replay` adds `--run --attempt --anchor`.
- Gate-child contract (design §7.7): last stdout line is a JSON `GateReport`; stdout line before it `chain_head <sha256>`; stderr carries human lines. Exit codes: 0 Passed, 1 Failed, 2 usage, 3 confinement refused, 4 unreadable input, 5 Indeterminate. **No run can end `Passed` today**: no verification (H3 not built); every run ends `Indeterminate{NothingChecked}` (exit 5).
- Inputs are JSON files, strict (`deny_unknown_fields`): task (`task, grants[], workspace_public, exec{programs[{name,path}], read_only[], env{}, limits{}}, budget{steps,wall_secs,exec_secs}, presubmit{commands[][], max_rounds}`), policy (`deny[], ask[], allow[]` of capability ids or `provider.*`; no argument matching), profile (`profile_version:1`, see §1.3). No config file, no env-var config, no defaults for `state_root`/workspace/endpoint.
- Approver: `TerminalApprover` (lib.rs ~L150): prompts on stderr, one `y/yes` = approve this one call; used only when stdin is a TTY; otherwise nobody is asked and every Ask is a Deny. Approver kinds journaled: `terminal`, `embedded` (`harness-run/src/approve.rs`).
- Output formats: human text on stderr + final JSON GateReport. No NDJSON/event stream, no usage/cost footer.

### 1.2 Built-in tools (10; manifest `crates/harness-manifest/src/builtin.rs`, impls `crates/harness-tools/src/{builtin,edit,exec,search,glob,todo}.rs`)
| Tool | Class | Notes |
|---|---|---|
| `harness.fs.read` | read | line window (100 default, profile up to 2000), returns sha256 + total lines, records read hash for stale-read check |
| `harness.fs.search` | read | literal or `regex:true` (pure-Rust `regex`, linear time), include/exclude globs, 0-5 context lines, hit caps (50 shown, 10/file) |
| `harness.fs.glob` | read | `*?[..]{a,b}**`, <=90 results with sizes |
| `harness.fs.list` | read | bounded dir listing |
| `harness.edit.replace` | write | exact unique match (count 1..1000), stale-read refusal, atomic tmp+fsync+rename, post-apply hash verify, near-miss hints, CRLF hint |
| `harness.edit.write` | write | new file (creates dirs) or whole-file overwrite <=400 lines after a read |
| `harness.edit.multi` | write | <=20 exact replacements in one file, all-or-none |
| `harness.exec.run` | execute | argv; `argv[0]` is a program NAME pinned by the task's `exec.programs` to one absolute path; no PATH lookup; no shell unless allowlisted; runs only in a `Conformed` sandbox; stdin null; per-command wall (120 s default, task `exec_secs` up to 1 h); output head+tail cut keeping failure-looking lines |
| `harness.task.todo` | write(public) | checklist, 20ish items, recomputed by replay |
| `harness.task.submit` | sentinel | always granted; ends the run, or (H3a) is turned back by failing pre-submit checks |
NOT built although in the design: `harness.notes.write`, `post_edit` syntax check (§4.9 step 6: `grep post_edit crates/*/src` = 0 hits), content snapshots/undo, protected-path overlays for edits (exec has an empty `protected` vec, `harness-tools/src/exec.rs:885`), egress/proxy, MCP (`harness-mcp` crate does not exist), reviewer run, verification plan.
Dispatch: `ToolProvider` trait (`harness-tools/src/provider.rs:234`), `serves()` splits the shared `harness` namespace by verb; only a `Journaled<Authorized<Call>>` can be invoked (write-ahead by type).

### 1.3 Model layer (`harness-model`, `harness-model-core`)
- `ModelBackend` trait is **synchronous**, `complete(&req, deadline) -> Result<Completion, ModelError>` (`harness-model/src/lib.rs:49`). Backends: `OpenAiCompatible` (own HTTP/1.1 over `std::net`, `client.rs`, `http.rs`), `ReplayBackend`, `ScriptedBackend` (`scripted.rs`, with `text_reply`/`tool_reply` helpers).
- Endpoint: loopback only (`127.0.0.1`, `[::1]`, `localhost`); anything else refused at client build (`endpoint.rs`, INV-24). No TLS, no `hosted` cargo feature exists yet (design §3.2 plans it). API key handle supported (`ApiKey`).
- The request sets `stream:true` (`wire.rs:303`) but the reply is read **whole** then parsed (`parse_sse_reply` on the full body): no incremental streaming, no token-by-token display, no reasoning-channel display.
- Protocols: `native` (OpenAI `tools`, one call per reply, history sent back as assistant `tool_calls` + `role:tool`, H1h) and `text` (`<action>{json}</action>`). Zero or several calls in a reply = format error + repair message; 3 consecutive = stop.
- Profile (`profile.rs`): `context_window, fill_ratio, protocol, tool_choice_required_ok, parallel_tool_calls_false_ok, stream_include_usage_ok, grammar (none/gbnf_lazy/json_schema; unused), max_active_tools (5-8), edit_format, recent_turns K, sampling{temperature,top_p,seed,max_tokens}, read_window, read_timeout_secs, kv_quant_note, stamp`. `profile check` = live smoke eval (>=5 cases) that stamps a profile. `Profile::conservative_default(model)` exists but nothing in the CLI uses it to auto-create a profile.
- Hosted model: only reachable through a separate loopback proxy the user runs; the harness cannot tell and applies no hosted rules.

### 1.4 Run loop, context, budgets (`harness-run/src/driver.rs` 2818 lines, `replay.rs` 1445 lines)
- One task = one run = one journal attempt. A run ends on submit, budget, loop detection, format errors, context exhaustion, journal failure. **There is no concept of a follow-up user message**: the task text is block 3 of the context and fixed. A model reply with zero actions is a format error, so a plain-text answer does not end a turn.
- Budgets (§2.4, `harness-core::Meter`): steps (default 50, task 1-500), tokens (profile-derived), wall (30 min, task 1 s-24 h; approval waits excluded), cost (0 local; hosted price table not built), format errors 3, repair rounds 1, per-call timeouts (model 300 s, tool 30 s, exec 120 s), approval wait 15 min. Notices to the model at 50/80/90% of steps and wall and before the last step.
- Loop detection (`harness-core`): Repeat (3 of last 6), EditChurn (>8 edits one file), NoProgress (10 steps), Denied (3 denials of one capability); keyed by (tool, args digest, workspace tree digest).
- Context (`harness-model-core/src/context.rs`, 2387 lines; format `rh-context/5`): rebuilt every turn, append-mostly between compactions (prefix-cache friendly), blocks: system, tools, task, harness facts, observation index, recent turns. **Compaction is deterministic and pointer-only** (old observations become index lines of step/tool/args/digest/size; no model-written summaries); chunked by `context_window x fill_ratio`; K recent turns kept; per-observation nonce delimiters, nonce-echo withholding, zero-width/bidi stripping; `ContextExhausted` stop if the newest turn cannot fit. No project instruction file, no repo map, no conversation ledger.
- Presubmit checks (H3a, `presubmit.rs`): a task's check commands run in the sandbox when the model submits; failure turns the submission back (`max_rounds` 1-5); recorded `PresubmitChecked`; outcome still `NothingChecked`.
- Resume (`replay.rs::resume`): continues an interrupted run in a new attempt after verifying the chain and that the workspace tree digest equals the last journaled one; completed edits/commands are re-fed, never re-run; a trailing intent is re-decided.
- Audit replay (`replay.rs::audit`): re-drives from recorded model replies, tool results, approval answers and nonces; recomputes every context digest, compaction/withholding decision, policy decision, loop signal and stop; reports first divergence; `--anchor` detects a replaced journal; refuses a journal from another build/format. `reproduce` mode (re-execute tools) is in the design only (`grep reproduce` = 0 hits).

### 1.5 Policy, approvals, trifecta (`harness-policy`, pure)
- `decide()` order: deny, ask, allow, default deny (§5.1). `UserPolicy` = 3 lists of selectors that are **capability ids or `provider.*` only** (`harness-policy/src/lib.rs:179`): no argument/path/argv matching, no persistent or session grants.
- Defaults: read allow; edits ask unless allowed (interim until sandbox+snapshots exist); exec ask; irreversible/shared ask every time; no approver => Ask becomes Deny. Approval tokens: HMAC-bound to run/attempt/step/capability/args digest/tier, single-use, nonce journaled (`approval.rs`). Scope `Run` exists in the type but is never offered (owner kept strict step binding).
- Trifecta (§5.4): workspace = private + untrusted; any egress capability + workspace refuses the session (no override, INV-9). No capability has egress today, so it never fires yet.
- Path policy `harness-policy/src/path.rs` (workspace-relative, symlink-refusing); locality check refuses non-local `state_root` (`locality.rs`); no default deny list for secret files (`.env`, keys).

### 1.6 Sandbox (`harness-sandbox`)
- macOS: deny-default Seatbelt (`seatbelt.rs`, 585 lines), passes conformance suite `tests/conformance_macos.rs` (907 lines) + live self-probe => `Conformed` witness; limits for time, CPU, memory (RLIMIT_AS), file size, output; process-count via in-sandbox watchdog (owner Q 6 provisional). Workspace + per-run scratch are the only writable roots; env is built, not inherited; no network.
- Linux: `linux.rs` is a probe only, never mints a witness (mechanism D29 undecided). Windows: refused (spike S-W1). So **exec works on macOS only today**; on Linux/Windows read/edit work, exec refuses (exit 3).
- Purity gate pins SHA-256 of the only two spawn sites, `capture.rs` and `confine_spawn.rs` (INV-23, `scripts/ci/purity.sh` ~L591-602). Any new long-lived process (background commands, MCP servers) must go through `confine_spawn.rs` and re-pin the hash.

### 1.7 Journal (`harness-journal`)
Hash-chained JSONL per attempt, write-ahead intents (`Journaled<C>`), poison-on-failure, fsync discipline, blobs for untrusted payloads (`blobs/<sha>`), exclusive lock, torn-tail handling, `JournalReader` verifies chain. 29 event kinds (`canon.rs:115-143`): RunStarted, ContextBuilt, ModelRequested/Replied, ActionParsed, FormatError, PolicyDecided, Approval{Requested,Granted,Denied,Expired}, ToolStarted/Finished, EditApplied, Egress, Redacted, Quarantined, SandboxUnavailable, LoopDetected, BudgetCharged/Notice, SubmitRequested, PresubmitChecked, Verification{Started,Finished}, CheckReported, ReviewerRefused, ReviewReported, RunStopped (several reserved for H3/H4). `EditApplied` stores before/after digests only, **not the pre-image bytes**, so nothing can be restored.
Header records: harness version, task/policy/manifest/profile digests, model identity, sandbox row, context format, budgets, exec setup (resolved program paths), approver_present, environment sample.

### 1.8 Tests and gates
`scripts/ci/gates.sh`: fmt, purity (+ selftest with planted violations), `cargo deny` (allowed licences Apache-2.0/MIT/Unicode-3.0/PolyForm-NC; crates.io set = serde stack, sha2 stack, regex trio, libc, thiserror), clippy `-D warnings` (panic/unwrap/index lints), tests (+ compile-fail doctests). Existing test shape: whole runs through `run()` with `ScriptedBackend` (`harness-run/tests/*.rs`), CLI tests with a mock TCP model server (`harness-cli/tests/cli.rs`, 1874 lines, `mock()`/`act()` helpers), live-model exit tests `#[ignore]`d (`harness-cli/tests/exit_h1.rs`, env `RUSTYHARNESS_EXIT_ENDPOINT/MODEL`). Test helpers are duplicated per file (e.g. the `Local` locality probe), no shared kit.
Dependencies: only serde/serde_json/sha2/regex/regex-syntax/thiserror/libc (Cargo.lock: 33 packages). `unsafe_code = "forbid"` workspace-wide (so no raw-mode termios in-tree; see P-18).

### 1.9 What a user cannot do today
Type a task and watch it work; follow up; see streamed text; approve with more than yes/no; allow `cargo test` but ask for `git push`; undo an edit; list or resume "my last session"; get JSON events; use AGENTS.md; run on a hosted model; fetch the web; run a dev server; use MCP/LSP; delegate; plan then build; get a usage/cost line. Also needs three hand-written JSON files, an existing state dir, and an absolute path per program.

---

## 2. Feature matrix

Legend: Y yes, ~ partial/weaker, N no, `?` unsure. Last two columns: rustyharness today, and the slice(s) that close the gap (or `Q-n` if blocked on an owner question in section 6).

| Feature | opencode | Claude Code | Codex CLI | Cline/Roo | Aider | Goose | Gemini CLI | rustyharness today | Closed by |
|---|---|---|---|---|---|---|---|---|---|
| Interactive REPL/TUI | Y TUI+web+server | Y TUI | Y TUI | Y (IDE panel) | Y line REPL | Y CLI+desktop | Y TUI | N batch only | P-18 (line REPL; TUI deferred, see 3.2) |
| Streaming output | Y | Y | Y | Y | Y | Y | Y | N (whole body, then parse) | P-06, P-18 |
| Session persistence/resume | Y | Y (`--continue/--resume`) | Y (`codex resume`) | Y (task history) | ~ (chat history file) | Y | Y | ~ resume of an interrupted run only | P-14, P-17 |
| Session fork / branch | Y | Y | ~ | ~ | N | ~ | ~ | N | P-32 |
| Context compaction | Y auto summary | Y auto-compact + /compact | Y | Y | ~ (history summarise) | Y | Y | Y pointer-only, deterministic | P-33 (ledger) |
| Checkpoints / undo / rewind | Y (git snapshot, /undo,/redo) | Y (rewind) | Y (undo) | Y checkpoints | Y /undo (git commit per edit) | ~ | Y checkpointing | N (digests only, no pre-image) | P-22, P-26 |
| Plan mode vs build mode | Y (plan/build agents) | Y (plan mode, shift-tab) | ~ (read-only mode) | Y Plan/Act | Y architect/ask modes | ~ chat mode | ~ | N | P-28 |
| Permission rules allow/ask/deny with globs | Y (last-match, per-tool, per-agent) | Y (`Tool(pattern)`, modes) | ~ (approval policy + sandbox modes, exec rules) | ~ (auto-approve toggles) | N | ~ (modes) | ~ (trusted folders, per-tool) | ~ ids only | P-08, P-23 |
| Persistent grants ("always allow") | Y | Y | Y | Y | N | Y | Y | N | P-23 (Q-4) |
| Permission modes (accept-edits, bypass...) | Y `--auto` | Y | Y | Y | N | Y | Y | N (policy file only) | P-23 |
| Project instruction file | Y AGENTS.md | Y CLAUDE.md | Y AGENTS.md | Y rules | Y CONVENTIONS.md | Y .goosehints | Y GEMINI.md | N | P-30 (Q-7) |
| Hooks | ~ plugins | Y | ~ | Y | N | ~ | ~ | N | not offered; replaced by P-27 + presubmit (3.2) |
| Custom slash commands / skills | Y | Y | Y | Y | ~ | Y recipes | Y TOML cmds | N | P-30 |
| Subagents / task tool | Y | Y | Y | ~ (Roo orchestrator) | N | Y | ~ | N | P-38 (ARCH) |
| Todo/planning tool | Y | Y | Y | ~ | N | ~ | Y | Y `harness.task.todo` | done |
| read/list/glob/grep | Y | Y | Y (shell-based) | Y | Y (repo map) | Y | Y | Y | done |
| edit/write | Y | Y | Y (apply_patch) | Y | Y (search/replace, udiff) | Y | Y | Y exact-replace, whole write | done |
| multi-edit / apply_patch (multi-file) | Y apply_patch | Y MultiEdit | Y apply_patch | Y | Y | ~ | ~ | ~ multi (one file) | P-25 |
| Delete/move files | via bash | via bash | via apply_patch/bash | Y | via git | via shell | via shell | N | P-25 |
| Bash with background processes | Y | Y | Y | Y | ~ (/run) | Y | Y | ~ sync argv only, no bg, no shell by default | P-11 (shell), P-36 (bg) |
| Web fetch / web search | Y | Y | Y (`--search`) | Y (browser) | ~ /web | Y | Y (search grounding) | N | P-39 (Q-1, Q-2) |
| LSP / diagnostics feedback | Y (experimental) | Y (IDE diag) | N | Y | ~ lint/test after edit | ~ | ~ | N | P-27 (post-edit checks instead of LSP) |
| MCP client | Y | Y | Y | Y | N | Y (core idea) | Y | N | P-37 (ARCH, Q-13) |
| Git integration | Y snapshot | Y | Y | Y | Y (auto commit) | Y | Y | N (exec of `git` possible after P-11) | P-11, P-29; no git spawn in harness |
| Repo map | ~ | ~ (search) | ~ | ~ | Y (tree-sitter map) | ~ | ~ | N | P-24, P-33 |
| Headless JSON / event stream | Y `run --format json` | Y `-p --output-format stream-json` | Y `exec --json` | N | ~ (--message) | Y | Y json + stream-json | ~ final GateReport only | P-15 |
| Cost / token reporting | Y | Y | Y | Y | Y | Y | Y | N (meter has it, not shown) | P-15 |
| Multi-provider / hosted | Y many | Anthropic (+bedrock/vertex) | OpenAI (+oss via ollama) | Y | Y | Y 15+ | Google | N loopback only | P-31 (Q-2, Q-3) |
| Prompt caching | Y | Y | Y | Y | Y | ~ | Y | ~ prefix-stable append-mostly context for server cache | P-31 note |
| Image input | Y | Y | Y `--image` | Y | Y | ~ | Y | N | deferred (3.2) |
| IDE integration (ACP/LSP) | Y ACP | Y (VS Code, JetBrains) | Y | native | ~ | ACP | Y companion | N | P-35 |
| Sandboxing | N (permissions only) | Y optional (seatbelt/bubblewrap) | Y default seatbelt/landlock | N | N | ~ | Y (seatbelt/docker) | Y macOS Seatbelt, fail-closed; Linux no backend | strength; Linux track (3.3) |
| Evals / benchmarks in repo | ~ | ~ | ~ | N | Y (polyglot leaderboard) | ~ | ~ | ~ profile smoke eval, rh-bench (external) | P-19, P-20, P-21, P-34 |
| Tamper-evident journal + audit replay | N | N | N | N | N | N | N | **Y** | strength |
| Evidence-based verdicts / reward-hack defences | N | N | N | N | ~ (runs tests) | N | N | ~ presubmit only, H3 not built | H3 track (3.3) |

---

## 3. Gaps and improvements

### 3.1 Per gap: covered by design? blocked? improvement over the field
Format: **Gap** | design coverage | owner block | IMPROVEMENT (exploits journal, replay, fail-closed confinement, evidence, budgets, profiles, small local models).

1. **Interactive REPL** | not designed beyond "CLI prompt" (§5.3) and "not a chat app at first" (overview §5); no phase | none (owner goal OD-1) | One journal per *session* with user turns as recorded inputs, so a whole conversation is audit-replayable and resumable; the REPL is a thin renderer over the same events, so what the user saw is exactly what the journal says. Line REPL first, no TUI crate (see 3.2).
2. **Streaming** | §3.2 says "with SSE streaming" | none | Display-only observer: the journaled `Completion` is still the complete reply, so replay never depends on chunks; all streamed text passes the control/ANSI/bidi sanitiser (P-04) so a hostile model cannot paint the terminal. Reasoning channel is shown dimmed, never fed back.
3. **Sessions: resume, list, fork** | resume §2.10 (interrupted only) | none | Resume re-verifies the chain and tree digest (fail-closed); fork = a new run hash-linked to (parent run, step, parent chain head), built from the same catch-up machinery as resume: a verifiable branch no other agent has. `sessions` list shows outcome and anchor.
4. **Compaction** | §2.3 pointer-only (stronger than others) | model-written summaries need owner OK (Q-9) | Deterministic **ledger**: never-compacted user messages (bounded), todo, harness-computed files-touched table, observation index; replay recomputes it bit-for-bit. No competitor can audit its compaction. Default stays "no model-written summaries".
5. **Checkpoints / undo / rewind** | §2.8 "snapshots" planned; H2b notes none exist | none | Pre-image blobs stored content-addressed and referenced from `EditApplied`; `/undo`, `/rewind N` restore bytes and **verify the resulting tree digest equals the journaled digest at that step**, journaled as `Restored`; audit recomputes. Also enables the §5.2 default flip to "edits allowed" (sandbox + undo make them reversible).
6. **Plan vs build mode** | not in design | none | Mode = active-tool set + policy; switching is a journaled event and re-runs the trifecta check (§5.4 already requires recompute on active-set change). **Plan-scoped grants**: the user-approved plan lists files; build mode may edit exactly those without prompting and asks for others. Fewer prompts, still fail-closed, plan digest in journal.
7. **Permission rules with globs / modes / persistent grants** | §5.1 selectors by capability only; §5.3 scope `Run` designed but not offered | "always allow" relaxes owner's strict step binding: Q-4 | Pure `harness-policy` matchers on canonical args (path globs for edit/read, argv-prefix for exec), rule id on every decision, recomputed by replay. Session grants are *journaled rule additions*, not reusable tokens (token binding stays strict). Persisting a rule to disk only on an explicit user command, to the trust-base dir. Workspace-resident config may only tighten (add deny/ask), never loosen (Q-8): repo-controlled config is executable config (§7.6).
8. **Project instruction files** | not designed; OD-2 requires embedders can switch off | Q-7 | Loaded as an `Untrusted`-labelled block, hash-pinned: shown to the user first, re-approved when its digest changes (TOFU), digest in header, replay re-feeds. Never feeds policy. Library default off; CLI default on after confirmation.
9. **Hooks / slash commands / skills** | not designed | none | Hooks that run arbitrary commands outside confinement are refused by design (INV-23). Offered instead: post-edit checks and pre-submit checks that run in the sandbox under policy and are journaled (P-27, H3a). Slash commands/skills = prompt templates from the **trust-base** dir only (expanded text becomes a user turn, so repo-supplied templates would be injection into the trusted channel); workspace templates are shown and need approval.
10. **Subagents** | reviewer run (§7.5) is the only nested run | Q-14 (concurrency 1) | Delegate a read-only explorer run: own child journal linked by digest from the parent's `ToolFinished`; parent sees a result that is `Untrusted`; child budgets are carved from the parent's meter (deterministic); sequential only (endpoint concurrency 1). Audit replays parent and child.
11. **apply_patch / multi-file / delete / move** | §4.9 forbids `git apply`/unified diff in v0.1 | none | Own in-process format: exact-match hunks over several files, all-or-none, each file verified by post-apply hash, pre-images stored, per-profile (`edit_format`) so small models keep `replace`. Delete/move are ask-always + undoable.
12. **Bash with background processes, ports** | §4.8 sync only; OD-5(a)(b) required, not designed | OD-5, FT-5 (Q-16) | Background process manager through `confine_spawn`, killed at run end and any stop, output cursor journaled; granted-loopback-port rule never includes the model server's port. ARCH, needs R6 threat update and Seatbelt `network-bind` rule + purity re-pin. Shell: opt-in `sh` on the allowlist stamps `shell_enabled:true` (design §4.8 already allows); sandbox is the control.
13. **Web fetch / search** | egress proxy H4; trifecta forbids workspace + egress (§5.4, OD-1 "known conflict") | Q-1 (Q7), Q-2 (TLS) | Research session with **no workspace grant** (so no P label), egress via allowlist proxy in the harness process, results saved as quarantined untrusted notes; moving them into a coding session is a human-reviewed file copy (an "airlock": human is the declassifier). Egress journaled per request before forwarding (design §6.5).
14. **LSP/diagnostics** | not designed | none | Skip LSP (long-lived confined servers, big surface). Do **verified-edit-by-checks**: task-declared post-edit commands (`cargo check`, formatter, linter) run in the sandbox after each edit; failure rolls the edit back and returns diagnostics. Same value as lint-guarded edits (SWE-agent +3 pp cited in §4.9) and fully journaled.
15. **MCP client** | H4: `harness-mcp` with rmcp, manifest pinning, quarantine | Q-13 (rmcp pulls tokio) | Own thin stdio JSON-RPC client (tools/list, tools/call only; no sampling, no resources) like `harness-model`; server spawned via `confine_spawn`; capability manifest pins description+schema hashes (rug-pull => quarantine); each call policy-checked and journaled. ARCH.
16. **Git integration** | `.git` protected path (§7.6), harness-side git via argv only | none | No git spawn in the harness (INV-23). `git` runs via `exec.run` allowlist with `.git` read-only overlay by default; `git commit/push/reset --hard` classified `protected_action` by argv-prefix rules (ask every time). `/diff` is computed from journal pre-image/after blobs, so it needs no git and is tamper-evident (P-40).
17. **Repo map** | not designed | none | `harness.fs.outline` (regex-based symbol extraction per language, deterministic) plus an optional context block sized from the profile window; replay recomputes the block. No tree-sitter dependency.
18. **Headless JSON / events** | §7.7 report only | none | `events` = a projection of the journal (same bytes the audit trusts), plus live tail; `run --output stream-json` prints the same. A consumer can verify the chain over the stream.
19. **Cost/token reporting** | §2.4 cost budget designed | price table for hosted | Footer + JSON from `BudgetCharged`/`ModelReplied` journal events (so reporting = audited data); includes server-reported cached tokens when present.
20. **Hosted models / multi-provider** | §3.2 `hosted` feature + TLS; Q2 | Q-2, Q-3 | No TLS in-tree. Documented recipe: user's own loopback proxy; profile declares `upstream:"hosted"` (user attestation journaled) so the harness applies hosted disclosure rules (no `personal` sensitivity) and a price-table cost budget. Fail-closed: an undeclared proxy is just a loopback server (harness cannot know; documented residual).
21. **Prompt caching** | append-mostly prefix (H1i) | none | Already the harness's strength for llama.cpp prefix cache; add cached-token display (P-15). Explicit Anthropic-style cache markers = proxy's job.
22. **Image input** | not designed | none | Deferred (3.2).
23. **IDE/ACP** | not designed | none | `rustyharness acp` over stdio only (no listener), permission requests mapped to the `Approver` trait, events from the same session API. P-35.
24. **Small local model support** | profiles, smoke eval, tool cap 5-8 (§3.4) | Q-6 (cap), Q-5 (parallel calls) | Per-model tool-schema minimisation: mode-based active sets (plan mode shows ~5 tools), per-profile edit tool selection, terse tool docs (bundled with P-33's context bump), `profile init` that sizes `max_active_tools`/window from `/v1/models` + smoke eval. The harness can *measure* a model before trusting it: nobody else does.
25. **Evidence-based verdicts** | H3 (verification plan, grading worktree, reviewer, reward-hack defences) | OQ item 10 | Out of scope for this parity roadmap except hooks into it: interactive sessions emit a GateReport (`NothingChecked`) until H3; presubmit checks reusable as the verification plan (owner OQ 10). Listed as parallel track 3.3.
26. **Linux/Windows confinement** | D29 open; S-W1 | D29, OD-7 | Parallel track 3.3. Until then the REPL on Linux is read+edit only (edits are in-process), exec refuses.

### 3.2 Deliberate non-goals / deferrals (with reason)
- **Full-screen TUI (ratatui/crossterm):** needs raw terminal mode = `unsafe` or a libc-heavy crate vs workspace `forbid(unsafe_code)`; adds a large dependency tree to `deny.toml`/purity. Line REPL with ANSI colour via `std` covers the 90% case; revisit with owner after M1.
- **Hooks (arbitrary command per tool call):** conflicts with INV-23/confinement; replaced by sandboxed post-edit/pre-submit checks.
- **LSP client:** replaced by post-edit checks.
- **Image input:** needs multimodal request parts and a VLM profile flag; low value for small local text models. Revisit after M2.
- **tree-sitter repo map:** C dependency, violates purity; regex outline instead.
- **Parallel tool calls in one reply:** owner question OQ 9; default stays one action per reply (Q-5).
- **Shared-state network/LAN model hosts, TLS in-tree:** Q-2.

### 3.3 Parallel tracks not scheduled here (named so the roadmap is honest)
- **S-L:** Linux confinement backend (D29). Largest single blocker for Linux users running commands.
- **H3:** verification plan, pristine grading worktree, protected-path diff audit, reviewer run, `Passed`. (P-29 only adds the `.git` default; H3 owns the rest.)
- **S-W1:** Windows spike.
- **Owner OQ 4/7:** shared confinement crate; confined file-op helper vs interim (b). Interim (b) stops a run if the sandbox cannot confirm every command process is gone: P-36's background processes are incompatible with it, so P-36 first needs OQ 7 decided.

---

## 4. Roadmap

### 4.1 Conventions
- **Size:** each slice 1-3 h for a cheap model with file+shell tools, 1-3 crates, tests named below (`cargo test -p <crate> <name>`). Gates (`sh scripts/ci/gates.sh`) green before merge.
- **No new third-party crates in any slice** unless stated (none are). New *workspace* crates (P-03, P-35) touch `Cargo.lock`.
- **Per-slice notes go in `docs/slices/P-xx.md`** (new file per slice), NOT as new rows in `docs/01-design-v0.1.md` (every existing slice appends there: guaranteed conflict). One consolidation commit per wave folds them into the design doc.
- **Every loop-visible feature** must (a) add a journal record or reuse one, (b) be recomputed or re-fed in `replay.rs::audit`, (c) have a test in which audit of the produced journal reports no divergence (helper from P-03: `assert_audit_clean(run)`), (d) bump `context_format` if the rendered context changes.
- **Hotspots (serialise or isolate):**
  - H-A `crates/harness-cli/src/lib.rs`: split first (P-01); after that each verb is its own module and `dispatch.rs` gets one line per verb.
  - H-B `crates/harness-run/src/driver.rs` (2.8k) and `replay.rs` (1.4k): split first (P-09); then slices that touch the loop are chained, never parallel with each other: P-13 -> P-17 -> P-22 -> P-23 -> P-26/P-27/P-28.
  - H-C built-in tool declaration trio: `harness-manifest/src/builtin.rs` JSON const, `harness-policy/src/lib.rs` id constants + default table, `harness-tools/src/builtin.rs`; split per tool in P-02, so new-tool slices (P-24, P-25) add files, not hunks.
  - H-D context builder `harness-model-core/src/context.rs` (2.4k) + `wire.rs`: each context change bumps `rh-context/N`: chain P-10 (/6) -> P-28 (/7) -> P-30 (/8) -> P-33 (/9). Never parallel.
  - H-E `harness-journal/src/canon.rs` event-kind list and `event.rs`: all new kinds are reserved once in P-10 (UserTurn, TurnEnded, ModeChanged, RuleGranted, Restored, InstructionsLoaded, ForkedFrom, ChildRun). Later slices only use them.
  - H-F `Cargo.lock`: only new workspace crates (P-03, P-35) change it; merge by `cargo update -w` regenerate, never hand-merge.
  - H-G `scripts/ci/purity.sh` pinned spawn-file hashes: only P-36/P-37 touch `confine_spawn.rs`.
  - Docs: `README.md` Status section: edit only at wave consolidation.

### 4.2 Waves overview (4 lanes each; lane = one slice running concurrently)
| Wave | Lane 1 | Lane 2 | Lane 3 | Lane 4 | Exit milestone |
|---|---|---|---|---|---|
| W0 foundations | P-01 cli split | P-02 tool registry | P-03 testkit | P-04 sanitiser | refactors green, behaviour identical |
| W1 | P-05 ARCH session design (docs) | P-06 SSE streaming | P-07 config + defaults + profile init | P-08 policy matchers | design approved by owner for sessions |
| W2 | P-09 split driver/replay | P-10 session events + ctx fmt 6 | P-11 exec presets + shell | P-12 sensitive-path denies | session building blocks |
| W3 | P-13 session loop (driver) | P-14 sessions/bundle/gc | P-15 events + usage | P-16 diff preview | loop supports turns |
| W4 | P-17 audit/resume of sessions | P-18 chat REPL | P-19 hostile suite v1 | P-20 scenario suite | **M1: usable interactive agent** |
| W5 | P-22 pre-image store | P-23 approval UX + session grants | P-24 outline tool | P-25 patch + file ops | undoable, glob-permissioned |
| W6 | P-26 undo/rewind | P-27 post-edit checks | P-28 plan/build modes | P-29 protected paths | **M2: safe daily driver** |
| W7 | P-30 instructions + commands | P-31 hosted via proxy | P-32 fork | P-21 real-model smoke + mini bench | |
| W8 | P-33 ledger + repo map block | P-34 tamper/golden suite | P-35 ACP | (spare: P-40 verified diff review) | **M3: parity-plus** |
| W9 ARCH | P-36 background + ports | P-37 MCP | P-38 subagents | P-39 web airlock | M4 (each needs its design note first) |

(P-21 is numbered with the eval slices but scheduled in W7 so it can use the REPL; P-40 appears in W8 spare lane.)

Parallel-safety in W-by-W detail is on each card ("Parallel:").

### 4.3 Slice cards

Card fields: **Why** | **Crates** | **Tests** (named, `cargo test`) | **Deps** | **Parallel** | **Risk** | **ARCH**.

#### Wave 0 - foundations (pure refactors and test kit; no behaviour change)

**P-01 Split `harness-cli/src/lib.rs` into modules**
- Why: H-A hotspot; every later CLI slice needs its own file. 1350 lines into `args.rs` (options parsing), `inputs.rs` (TaskFile/BudgetFile/PolicyFile/profile readers), `approver.rs` (TerminalApprover, ApproverSource), `report.rs` (emit, Outcome, exit), `cmd_run.rs`, `cmd_replay.rs`, `cmd_profile.rs`, `cmd_manifest.rs`, `dispatch.rs` (`main_with` match). Public API (`Cx`, `main_with`, `ApproverSource`, `TerminalApprover`) unchanged.
- Crates: harness-cli. 
- Tests: all existing `cargo test -p harness-cli` pass unchanged (cli.rs, exit_h1.rs); add `cli_public_api_unchanged` (compile-only use of `Cx`, `main_with`, `ApproverSource`, `TerminalApprover`); `usage_text_unchanged` (golden of USAGE).
- Deps: none. Parallel: yes (cli only). Risk: low. ARCH: no.

**P-02 Built-in tool registry: one module + manifest fragment per tool**
- Why: H-C; makes P-24/P-25 conflict-free. Split `BUILTIN_MANIFEST_JSON` into per-capability JSON fragments (`include_str!` pieces assembled in a fixed order) and the policy id constants/default-class table into per-tool registration entries; dispatch table in `harness-tools` lists `(id, provider ctor)`. Output must be **byte-identical** (manifest sha is in every journal header; a drift would make every old journal "another build").
- Crates: harness-manifest, harness-policy, harness-tools.
- Tests: `builtin_manifest_bytes_unchanged` (compare against a pinned sha256 literal computed before the change), `builtin_registry_lists_ten_tools_in_order`, `policy_default_table_unchanged` (same decisions for all 10 ids x 3 roles), existing `cargo test --workspace`.
- Deps: none. Parallel: yes (touches manifest/policy/tools; not cli/run/model). Risk: low-medium (digest drift). ARCH: no.

**P-03 `harness-testkit` crate (dev-only helper)**
- Why: tests duplicate fixtures; every later slice needs scripted scenarios and clean-audit asserts. New workspace member `crates/harness-testkit` (publish=false, no third-party deps): `Fixture::new()` (temp state_root + workspace), `Local` locality probe, `registry()`, scripted-model builders (`say()`, `act(tool,args)`), `run_scripted(fixture, replies) -> RunReport`, `assert_audit_clean(&RunReport)`, `journal_kinds(&report) -> Vec<EventKind>`, in-process CLI driver `cli(args, stdin_lines) -> (code, stdout, stderr)` over `harness_cli::main_with` with an injected approver. Convert 2 existing test files to it as proof.
- Crates: harness-testkit (new), harness-run tests, harness-cli tests (dev-deps only).
- Tests: `testkit_runs_a_scripted_read_task_and_audits_clean`, `testkit_cli_driver_captures_report_line`, `testkit_fixture_cleans_up`.
- Deps: P-01 not required but the cli driver wraps `main_with` (stable). Parallel: yes, except Cargo.lock (H-F). Risk: low. ARCH: no.

**P-04 Terminal-safe display (`harness_core::display`)**
- Why: REPL/events/streaming print untrusted text (model replies, tool output, file names) to a terminal. A pure `sanitize_for_terminal(&str, mode) -> String`: strips/escapes ESC and all C0/C1 controls except `\n` and `\t`, bidi overrides, zero-width, OSC/CSI sequences; `mode` = `Line` | `Block`; bounded output length with a visible `[N bytes cut]` marker; idempotent. Reuse from the approval request rendering (replace its private escaper, keep output identical).
- Crates: harness-core (pure: no I/O names), harness-policy (swap in the helper).
- Tests: `display_strips_csi_osc_and_c1`, `display_escapes_bidi_and_zero_width`, `display_is_idempotent`, `display_bound_marks_cut`, `approval_request_display_unchanged` (golden), purity gate passes.
- Deps: none. Parallel: yes. Risk: low. ARCH: no.

#### Wave 1

**P-05 ARCH: design note "interactive session model"** (docs only, expensive model, output `docs/slices/P-05-session.md`, then owner review)
- Must decide and specify: (1) one journal attempt holds N user turns (`UserTurn` event, trusted-source text stored as `UntrustedBlob`-style blob with `Source::User`, digest in event); (2) turn end = model reply with no action (native: plain content; text protocol: `<final>` or plain text) or `harness.task.submit`; zero-action reply is NOT a format error in session mode, but is in batch mode (header flag `mode: session|batch` is a header input); (3) per-turn vs per-session budgets (steps per turn, session wall, token total; deterministic carve) ; (4) external edits between turns: at each `UserTurn` re-measure the workspace, journal `tree_digest` + "changed outside the harness" flag; read-hash records invalidated (stale-read forces re-read); resume digest check applies at turn boundaries; (5) context: conversation block order, user messages never compacted (bounded), `rh-context/6`; (6) replay: user turns are recorded inputs re-fed like model replies; (7) approver/UserInput/EventSink traits in `harness-run` (sync); (8) outcome of a session (`NothingChecked` until H3; exit code); (9) loop detector scope per turn; (10) compatibility: `run()` batch API and old journals still audit.
- Tests: n/a (review checklist inside note: every record has a replay rule).
- Deps: none. Parallel: yes (docs). Risk: design. ARCH: **yes** (the one that matters most).

**P-06 Incremental SSE streaming observer**
- Why: parity + feel. `http.rs::exchange` returns the full body; add a chunk callback path so SSE `data:` events are parsed as they arrive, feeding an optional `StreamObserver` (`on_text(&str)`, `on_reasoning(&str)`, `on_tool_call_name(&str)`) set on `OpenAiCompatible::with_observer` (not on the trait, so the loop and replay are untouched). Deadline and size caps still bind per chunk; the returned `Completion` is assembled exactly as today and is what is journaled. Reasoning deltas (`reasoning_content`) surfaced to the observer only.
- Crates: harness-model (`http.rs`, `client.rs`), harness-model-core (`wire.rs`: incremental accumulator shared with `parse_sse_reply`).
- Tests (mock TCP server that sends chunks with delays): `stream_observer_sees_text_before_reply_completes`, `stream_result_equals_nonstream_parse` (same Completion bytes/digests), `stream_deadline_still_enforced_mid_stream`, `stream_oversize_refused`, `stream_forever_hits_cap`, `observer_never_affects_request_digest`; existing `client_mock.rs` unchanged.
- Deps: none. Parallel: yes (harness-model*). Risk: medium (HTTP framing: chunked + SSE split across reads). ARCH: no.

**P-07 CLI defaults, user config, `profile init`**
- Why: today a run needs three JSON files + existing state dir + endpoint. Add: default `state_root` (macOS `~/Library/Application Support/rustyharness`, Linux `$XDG_DATA_HOME` or `~/.local/share/rustyharness`; created 0700; locality-checked as today), `--workspace` default = cwd, user config `<config dir>/config.json` (strict JSON: `endpoint, profile, policy, state_root, approver`), flags override config. **Config is read only from the user config dir, never from the workspace.** `rustyharness profile init --endpoint URL [--out file]`: GET `/v1/models`, pick/prompt the model id, write a profile from `Profile::conservative_default`, run the smoke eval, stamp if it passes. Config opt-out for embedders: library API unchanged (`harness-run` reads no config).
- Crates: harness-cli (new `config.rs`, `cmd_profile.rs` extension), harness-model (smoke reuse).
- Tests: `config_flags_override_file`, `config_in_workspace_is_never_read`, `default_state_root_created_0700`, `default_state_root_refused_if_not_local`, `profile_init_writes_conservative_profile_for_listed_model` (mock server), `profile_init_refuses_unlisted_model`, `profile_init_stamps_only_on_pass`.
- Deps: P-01. Parallel: yes with P-05/06/08 (cli vs model vs policy). Risk: low-medium. ARCH: no.

**P-08 Policy argument matchers**
- Why: `allow cargo test` but `ask git push`; `allow edits under src/**`; deny `.env`. Extend `UserPolicy` selectors: `{capability, match?: {path_glob?, argv_prefix?, argv_not_prefix?}}`. Matching on the canonical args the decision already digests. Order unchanged (deny > ask > allow > default deny; first match within a list; allow never lowers a floor). Move the pure glob matcher from `harness-tools/src/glob.rs` into `harness-core` (pure), re-export from tools. Policy file format v2 is a superset (old files parse identically and yield the identical policy digest). Rule id on every decision includes list+index. Unit tests for load-time examples (Codex-style `match`/`not_match` examples per §4.8: a rule file may carry `examples` that are checked when loaded; failing example = refuse the file).
- Crates: harness-policy, harness-core (glob move), harness-tools (re-export), harness-cli (`inputs.rs` policy parser).
- Tests: `matcher_path_glob_allows_only_under_src`, `matcher_argv_prefix_cargo_test`, `deny_matcher_beats_allow_matcher`, `allow_matcher_cannot_lower_floor` (irreversible stays ask), `old_policy_file_same_digest`, `rule_examples_checked_at_load`, `bad_glob_refused`, `glob_behaviour_unchanged` (moved tests), `audit_recomputes_matcher_decisions` (run through P-03 kit once available, else harness-run test).
- Deps: P-01 (for cli parse; can land policy part first). Parallel: yes except harness-tools/glob move (P-02 also touches harness-tools: coordinate: P-08 moves `glob.rs` only, P-02 does not touch it). Risk: medium (trust root). ARCH: no (spec above is complete).

#### Wave 2

**P-09 Split `driver.rs` and `replay.rs` into submodules (no behaviour change)**
- Why: H-B. Driver: `plan.rs` (prepare/session planning), `header.rs`, `step.rs` (Loop::step phases), `tools.rs` (provider build + dispatch), `approvals.rs`, `stop.rs`, `driver.rs` (run). Replay: `audit.rs`, `resume.rs`, `feed.rs` (re-feed backends), `compare.rs`. Public paths (`harness_run::{run, audit, resume, Run, ...}`) unchanged.
- Crates: harness-run.
- Tests: all existing `cargo test -p harness-run` unchanged; `public_api_paths_unchanged` compile test.
- Deps: none; but must land before P-13/P-17. Parallel: yes with P-10 (journal + model-core), P-11 (cli), P-12 (policy/tools). Risk: medium (large mechanical move; use `git mv`-style splits, no logic edits). ARCH: no.

**P-10 Session events and context format `rh-context/6`**
- Why: unblocks the session loop with all new journal kinds reserved once (H-E): `UserTurn`, `TurnEnded`, `ModeChanged`, `RuleGranted`, `Restored`, `InstructionsLoaded`, `ForkedFrom`, `ChildRun`; canonical field lists in `canon.rs`; journal reader/schema accept them; header gains `mode: batch|session` (absent = batch; digest of old headers unchanged). Context builder: conversation block (user messages verbatim, never compacted, bounded by a profile-relative cap; oldest dropped only with a visible harness notice and counted) per P-05; `context_format` = `rh-context/6` for session mode only, batch stays `/5` (old journals still audit).
- Crates: harness-journal, harness-model-core.
- Tests: `new_event_kinds_round_trip_canonical`, `unknown_kind_still_refused`, `batch_context_digest_unchanged` (golden from `/5`), `session_context_orders_user_turns`, `session_context_user_turn_cap_notice`, `session_context_user_text_cannot_contain_nonce` (withheld), `old_journal_still_reads`.
- Deps: P-05 approved. Parallel: yes with P-09/11/12. Risk: medium. ARCH: no (spec from P-05).

**P-11 Exec presets, PATH pinning and `--shell`**
- Why: today every program needs an absolute path by hand. `--allow-exec cargo,git,rg` (or `exec_programs` in user config) resolves each name via the CLI's own PATH **at startup in the trust base**, canonicalises to an absolute path, records it in the header's exec section (already recorded). Presets (data tables, `rust`, `node`, `python`, `go`) fill `read_only` roots (toolchain dirs found via the resolved binary's parents), env (`CARGO_NET_OFFLINE=true`, `CARGO_TARGET_DIR` into scratch already handled), limits. `--shell` adds `sh` to the allowlist and stamps `shell_enabled:true` (design §4.8). All printed to the user before the run starts ("will allow: cargo -> /path"). Resolved task is written as JSON (feeds P-14).
- Crates: harness-cli (`exec_presets.rs`), harness-tools (only a pub constructor if needed).
- Tests: `allow_exec_resolves_to_absolute_path` (fake PATH dir with a script), `allow_exec_refuses_relative_or_symlink_escape` (path must canonicalise to an existing regular file), `preset_rust_sets_read_only_roots`, `shell_flag_sets_shell_enabled_in_header`, `unknown_preset_refused`, `resolved_exec_matches_task_file_form` (equal `ExecSpec`).
- Deps: P-01, P-07 (config). Parallel: yes (cli modules) with P-09/10/12. Risk: low-medium. ARCH: no.

**P-12 Sensitive-path default denies**
- Why: opencode denies `.env` by default; Claude Code supports deny rules. CLI-supplied default deny list (`.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa*`, `.aws/**`, `.ssh/**`, `.git/config`, `.npmrc`, `.netrc`) applied through P-08 matchers to read/search/glob/list/edit; `search`/`glob`/`list` skip them and say how many were skipped (never silently). Library default = empty (embedders decide, OD-2); CLI default on, `--no-default-denies` off-switch recorded in header.
- Crates: harness-policy (data list const + helper), harness-tools (skip-and-count in search/glob/list), harness-cli.
- Tests: `read_dot_env_denied_by_default_cli`, `search_skips_denied_files_and_counts_them`, `glob_and_list_hide_denied_but_report_count`, `edit_to_denied_path_refused`, `library_run_has_no_default_denies`, `denied_decision_has_rule_id`, `audit_clean_with_denies`.
- Deps: P-08. Parallel: yes (policy/tools files not shared with P-09/10/11 except P-08 done earlier). Risk: low-medium. ARCH: no.

#### Wave 3

**P-13 Session loop in `harness-run`**
- Why: the core of interactivity. New `harness_run::session::run_session(SessionRun)` (batch `run()` unchanged): per P-05, a loop of `UserInput::next(deadline) -> Option<UserMessage>` (sync trait, like `Approver`), journals `UserTurn`, runs model/tool steps until turn end (plain-text answer or submit), journals `TurnEnded`, then waits for the next input; `EventSink::emit(&UiEvent)` called after each journaled record (display only, never an input to decisions). Turn budgets and session budgets from P-05; external-change detection at each turn start; read-hash invalidation. `submit` in session mode ends the turn, not the session. Session ends on `None` input, wall budget, journal failure, context exhaustion.
- Crates: harness-run (driver chain; do not parallel with other loop slices), harness-model-core only for types already added in P-10.
- Tests (scripted model + scripted `UserInput`): `session_two_turns_one_journal`, `plain_answer_ends_turn_in_session_not_in_batch`, `turn_budget_ends_turn_not_session`, `session_wall_budget_stops`, `user_turn_recorded_and_in_context_order`, `external_edit_between_turns_detected_and_stale_read_forces_reread`, `approval_in_turn_two_works`, `event_sink_sees_only_journaled_records`, `no_input_means_session_ends_indeterminate_nothing_checked`, `batch_run_behaviour_unchanged` (existing suite).
- Deps: P-05, P-09, P-10. Parallel: with P-14/15/16 yes (different crates). Risk: high (the loop). ARCH: no (design is P-05) but assign the stronger of the cheap models and require a reviewer pass.

**P-14 `sessions` list/show, run bundle, `gc`**
- Why: parity with resume pickers; OD-5(d). `rustyharness sessions [--state-root]` lists runs (id, start time, first user text 60 chars sanitised, steps, stop cause, outcome, chain head, workspace) by scanning `runs/` with `JournalReader` (read-only, chain-verifying; a broken journal is listed as `UNREADABLE`, not skipped). `sessions show --run id` summary. **Run bundle:** `run`/`chat` copy the resolved task/profile/policy/exec/config into `runs/<id>/inputs/` (0600, digests equal the header's), so `replay --run ID` and `resume --run ID` need no other flags (flags still override and must match digests). `gc --run id | --older-than 30d`: remove `workspace/ grading/ scratch/` only; never journal, blobs, snapshots, inputs; refuses a run that is still locked/active.
- Crates: harness-cli, harness-journal (a small read-only `scan_runs` helper), harness-run only if layout fns needed.
- Tests: `sessions_lists_runs_newest_first`, `sessions_marks_tampered_journal_unreadable`, `sessions_sanitises_task_text`, `bundle_written_with_matching_digests`, `replay_with_only_run_id_uses_bundle`, `bundle_digest_mismatch_refused`, `gc_removes_scratch_keeps_journal`, `gc_refuses_active_run`, `gc_is_idempotent`.
- Deps: P-01, P-04, P-07. Parallel: yes. Risk: low-medium. ARCH: no.

**P-15 `events` projection and usage/cost footer**
- Why: headless JSON stream and token/cost reporting from audited data. `rustyharness events --run ID [--follow] [--format ndjson]`: one JSON object per journal record with `seq, hash, kind, step, body` (untrusted payloads inline <=4 KiB sanitised, else blob ref + digest), schema version header line; `--follow` tails the live journal (poll + torn-tail aware). `run --output stream-json` prints the same live. Usage: footer and `usage` object in the final report-adjacent line (stdout line before `chain_head`, keeping the last-line GateReport contract): steps, model calls, tokens in/out/cached (when server reports), wall, per-tool counts; computed from `BudgetCharged`/`ModelReplied`/`ToolFinished`.
- Crates: harness-cli (`cmd_events.rs`, `usage.rs`), harness-journal (tail reader helper).
- Tests: `events_ndjson_one_line_per_record`, `events_chain_verifiable_from_stream` (consumer recomputes hashes), `events_follow_sees_new_records`, `events_torn_tail_not_emitted`, `events_untrusted_payload_sanitised`, `usage_matches_budget_charged`, `final_stdout_line_still_gatereport`, `stream_json_run_exit_codes_unchanged`.
- Deps: P-01, P-04. Parallel: yes. Risk: low-medium. ARCH: no.

**P-16 Edit diff preview renderer**
- Why: approvals need to show what will change (Claude Code/Cline do). Pure line diff (Myers or simple LCS, bounded) `harness_core::diff::unified(old, new, context=3, max_lines=200) -> String` plus `EditTools::preview(&Call) -> Result<String, PreviewRefused>` for replace/multi/write that applies the edit in memory (no write, no journaling) and renders a diff; sanitised via P-04; deterministic.
- Crates: harness-core (pure diff), harness-tools (preview).
- Tests: `diff_identical_is_empty`, `diff_single_line_change`, `diff_crlf_preserved_marked`, `diff_bounded_marks_cut`, `diff_deterministic`, `preview_replace_matches_applied_result` (apply for real in a tmp copy and compare), `preview_does_not_modify_file`, `preview_refuses_stale_read_like_apply`.
- Deps: P-04. Parallel: yes. Risk: low. ARCH: no.

#### Wave 4 - M1: usable interactive agent

**P-17 Audit replay and resume for sessions**
- Why: no feature ships unreplayable. `audit` handles session journals: re-feeds recorded `UserTurn` texts, recomputes conversation context, turn ends, per-turn budgets, external-change records (re-fed observed digests, recomputed decisions); `resume` of a session continues at a turn boundary or mid-turn (catch-up as today), asks for next user input.
- Crates: harness-run (`audit.rs`, `resume.rs` after P-09).
- Tests: `audit_of_two_turn_session_is_clean`, `audit_detects_edited_user_turn_text`, `audit_detects_dropped_turn`, `resume_session_mid_turn_continues`, `resume_session_at_boundary_waits_for_input`, `resume_refuses_workspace_changed_since_last_record` (unless the next record is an `external-change` turn start), `batch_audit_unchanged`.
- Deps: P-13. Parallel: with P-18 yes (cli vs run). Risk: high. ARCH: no.

**P-18 `rustyharness chat` (line REPL v1)**
- Why: the headline feature. `rustyharness [chat] [--workspace .] [--resume [ID]|--continue]`: prints a banner (workspace, model, confinement witness or "no confinement: read/edit only", granted tools, policy summary, state root), prompt `> `, reads lines; multi-line with `"""`; streams model text through P-06/P-04; shows tool calls as one-line `[tool] harness.fs.read src/lib.rs 1-100 -> ok (4 ms)` and results truncated; approvals via the existing Approver with diff preview when P-16 exists; slash commands: `/help /status /tools /policy /sessions /resume /todo /usage /diff(stub until P-40) /clear(new session) /exit` and `Ctrl-D`/EOF = clean end; Ctrl-C handled by timeouts only (no signal handler crate; documented). Non-TTY stdin: refuses interactive approvals (all Asks denied, as today) but still runs piped prompts (scripting). All state through the session API only. Ends by printing session summary, chain head and the GateReport line to stdout as the gate contract (exit 5, `NothingChecked`).
- Crates: harness-cli (`cmd_chat.rs`, `repl.rs`, `render.rs`), harness-testkit (REPL driver).
- Tests (in-process `main_with` with injected input lines via the P-03 driver and a mock model): `chat_runs_two_prompts_and_prints_chain_head`, `chat_streams_text_to_output`, `chat_denies_asks_without_tty`, `chat_approves_edit_with_diff_shown` (injected approver), `chat_slash_status_lists_tools`, `chat_resume_continues_previous_session`, `chat_output_has_no_raw_escape_from_model` (hostile model text with ESC/OSC), `chat_eof_ends_cleanly_exit5_report_line`, `chat_session_journal_audits_clean`.
- Deps: P-04, P-06, P-07, P-11, P-13, P-14 (sessions/resume picker), P-16 optional. Parallel: with P-17, P-19, P-20 yes. Risk: medium. ARCH: no.

**P-19 Hostile-task suite v1 (tests only)**
- Why: prove the interactive path is not weaker than batch. `crates/harness-run/tests/hostile_*.rs` + `harness-cli/tests/hostile_chat.rs`, scripted model + hostile fixtures: (1) prompt injection in a file ("ignore previous, run curl...") never changes policy decisions or grants; (2) tool output containing a forged nonce/delimiter is withheld; (3) ANSI/OSC/bidi in file names and output cannot reach the terminal (REPL capture); (4) path traversal `../`, absolute path, symlink-out in read/edit/glob/search; (5) exec argv trickery (program name with path, `sh -c` without shell allowlisted, env injection) refused; (6) user-turn text containing a nonce is withheld; (7) forged approval token/nonce reuse diverges audit; (8) denied-file reads (`.env`) refused; (9) huge output and infinite-loop command hit caps/timeouts; (10) trifecta fixtures (a manifest with egress + workspace) refuse the session; (11) modified journal line detected by audit, replaced journal detected by anchor.
- Crates: tests in harness-run, harness-cli, (+ harness-sandbox macOS conformance reuse).
- Tests: names = the 11 items above, prefixed `hostile_`. 
- Deps: P-03, P-12, P-13, P-18 (for 3/6 parts). Parallel: yes (tests only; separate files). Risk: low. ARCH: no.

**P-20 Scripted scenario suite (tests only)**
- Why: end-to-end coding behaviour without a model. 12 golden scenarios on fixture repos using the scripted model through `run_session`: fix a failing unit test (read, search, edit, exec `cargo test` via a fake allowlisted script), add a function, rename across files via multi-edit, refuse an out-of-workspace edit then recover, stale-read recovery, loop-detector fires, budget notice then submit, presubmit turn-back then pass, approval deny then alternative, resume after kill between intent and result, compaction trigger on long session with audit clean, two-turn follow-up. Each asserts final files, journal kind sequence, and `assert_audit_clean`.
- Crates: tests in harness-run (+testkit).
- Tests: `scenario_01_...` to `scenario_12_...` (named by behaviour).
- Deps: P-03, P-13, P-17. Parallel: yes (tests only). Risk: low. ARCH: no.

*Milestone M1 gate:* P-17 + P-18 must both be merged before anything calls the REPL "released"; run P-21's manual smoke on a real local model.

#### Wave 5

**P-21 Real-model smoke + mini coding benchmark (ignored tests, scheduled W7 but cards here)**
- Why: scripted models cannot reveal prompt/format problems. (a) `harness-cli/tests/chat_live.rs` `#[ignore]`: env `RUSTYHARNESS_EXIT_ENDPOINT/MODEL`, drives `chat` over piped stdin through two turns on a fixture repo, asserts the answer, a verified edit, clean audit, anchored replay; both protocols. (b) `scripts/dev/mini-bench.sh` + 10 fixture tasks (`fixtures/bench/*/task.json + repo + expected check command`): runs each with presubmit checks, records pass/fail/steps/tokens/format-errors to a TSV keyed by (harness version, profile sha) so regressions are visible (design R1 §8 #15). Not a gate; run before releases and nightly on a local model.
- Crates: harness-cli tests, scripts, fixtures.
- Tests: `chat_live_native_two_turns`, `chat_live_text_two_turns` (ignored); mini-bench self-test with the scripted backend (`minibench_scripted_all_pass`) runs in gates.
- Deps: P-18 (+P-22 for edit-verify cases later). Parallel: yes. Risk: low. ARCH: no.

**P-22 Pre-image store**
- Why: enables undo, `/diff`, safe auto-accept. Before any edit/write/patch applies, the harness stores the file's prior bytes (or "absent") as a content-addressed blob (cap per file 2 MiB; larger = edit refused with a clear message, fail closed) and `EditApplied` carries `before_blob`/`after_blob` refs (after-blob for `/diff`). Restore primitive `harness_tools::restore::restore_file(path, blob)` with digest verification both ways. Blob store gc unchanged (kept by `gc`).
- Crates: harness-tools (edit engine returns pre/post bytes), harness-journal (blob refs in EditApplied canon), harness-run (driver edit path; chain after P-17).
- Tests: `edit_stores_pre_image_blob`, `new_file_pre_image_is_absent_marker`, `pre_image_over_cap_refuses_edit`, `restore_file_verifies_digest`, `restore_refuses_if_file_changed_since_after_digest`, `audit_clean_with_blobs`, `blob_tamper_detected_by_audit`, existing `edits.rs` unchanged.
- Deps: P-17 (loop chain), P-10. Parallel: with P-24/P-25 yes (tools split by P-02); with P-23 shares driver (different functions: edit result vs approval) - merge carefully. Risk: medium. ARCH: no.

**P-23 Approval UX and session-scoped grants**
- Why: parity with every competitor. Prompt options `[y] once [n] no [a] allow this pattern for the session [d] deny this pattern for the session [?] details`; "this pattern" proposes a minimal matcher (exec: `argv_prefix` first 2 items; edit: that file; read: that dir) shown verbatim; granting journals `RuleGranted{list,matcher digest}` and the loop applies it exactly as a policy rule (decision carries rule id `session.allow.N`); deny/protected_action classes can never be "always" (cannot lower floor); `--accept-edits` flag sets an allow matcher for edits (only once pre-image store works, P-22, else flag refused); `--allow-session-grants` required for `[a]` (Q-4 default off). Diff preview from P-16 shown for edits. Replay re-feeds the answers and recomputes rule application.
- Crates: harness-run (approve.rs, driver approval path), harness-policy (session rule list type, pure), harness-cli (prompt).
- Tests: `session_allow_applies_to_next_matching_call_only`, `session_allow_does_not_match_other_argv`, `session_grant_never_covers_protected_action`, `session_grant_requires_flag`, `granted_rule_recorded_and_audited`, `denied_session_rule_blocks_later_allow_matcher`, `accept_edits_refused_without_pre_image_store`, `prompt_shows_diff_for_edit`, `eof_at_prompt_is_noanswer_deny`.
- Deps: P-08, P-16, P-17, P-18; P-22 for `--accept-edits`. Parallel: share-risk with P-22 on driver.rs (see above). Risk: medium-high (permission semantics; owner Q-4). ARCH: no.

**P-24 `harness.fs.outline` tool (+ outline provider)**
- Why: repo-map-lite. Deterministic regex symbol extraction for Rust, Python, JS/TS, Go, C-family, Markdown headings: `{path|dir, kind?}` returns `line: signature` entries bounded (default 200 lines), over the same confined walk as glob/search, sanitised, denied files skipped.
- Crates: harness-tools (new `outline.rs`), harness-manifest (fragment file from P-02), harness-policy (id + class entry).
- Tests: `outline_rust_fns_structs_impls`, `outline_python_defs_classes`, `outline_ts_exports`, `outline_dir_bounded_and_sorted`, `outline_skips_denied_files`, `outline_binary_file_refused`, `outline_deterministic_digest`, `tool_count_policy_default_read_allow`.
- Deps: P-02, P-12. Parallel: yes. Risk: low. ARCH: no.

**P-25 `harness.edit.patch` + `harness.edit.delete` / `harness.edit.move`**
- Why: apply_patch parity for larger models; file ops. Patch format = own `*** Begin Patch` style (per-file `Update` with exact-context hunks, `Add`, `Delete`) parsed strictly in harness-tools; all files all-or-none, every hunk must match exactly once, per-file verify hash, pre-images from P-22 if present else the tool is refused (fail closed: no undo, no multi-file edit). `delete`/`move`: single path, ask-always class (`protected_action` tier for delete of >50 lines? keep simple: `user_confirm` ask, never allow-listed by `--accept-edits`), pre-image stored. Active only when granted; profile `edit_format: patch` selects it over `replace`.
- Crates: harness-tools, harness-manifest (fragments), harness-policy (ids), harness-model-core (`EditFormat::Patch` in profile; profile digest of existing profiles unchanged).
- Tests: `patch_two_files_all_or_none`, `patch_hunk_mismatch_changes_nothing`, `patch_add_existing_file_refused`, `patch_delete_missing_refused`, `patch_requires_pre_image_store`, `patch_stale_read_refused`, `delete_stores_pre_image_and_asks`, `move_refuses_overwrite`, `profile_edit_format_patch_parses`, `old_profile_digest_unchanged`.
- Deps: P-02, P-22. Parallel: yes with P-24 (separate files; policy id table touched in separate fragment files per P-02) ; shares harness-model-core profile.rs only with nothing else in W5. Risk: medium. ARCH: no.

#### Wave 6 - M2: safe daily driver

**P-26 `/undo`, `/rewind N` with verified restore**
- Why: checkpoints parity with a stronger guarantee. `restore_to_step(session, step)`: replay the journal's edit records backward using pre-image blobs; after restoring, the workspace tree digest must equal the digest journaled at that step (else stop, restore nothing further, report which files differ: fail closed); journals `Restored{to_step, tree_digest, files}`; the model is told by a harness notice; audit recomputes the restore deterministically from blobs. Refuses if the workspace was changed outside the harness since the last record (shows the diff; user may `/rewind --force-keep-external` = restores only harness-edited files whose current digest equals journaled after-digest).
- Crates: harness-run (new `restore.rs`; driver hook), harness-cli (commands).
- Tests: `undo_last_edit_restores_bytes`, `rewind_three_edits_tree_digest_matches`, `rewind_refuses_when_file_changed_outside`, `rewind_force_keep_external_restores_only_owned_files`, `restored_event_audited_clean`, `restored_notice_reaches_context`, `undo_of_deleted_file_recreates_it`, `undo_nothing_to_undo_message`.
- Deps: P-22, P-17, P-18. Parallel: with P-27/28 shares driver (restore is a new module + one hook); sequence P-26 first if conflicts. Risk: medium. ARCH: no.

**P-27 Post-edit verified checks**
- Why: LSP/lint-guarded edits without LSP. Task/config `post_edit: [{match: "**/*.rs", argv: ["cargo","check","-q"]}, {match:"**/*.py", argv:["ruff","check","{path}"]}]`, run in the same sandbox/policy as `exec.run` after each successful edit (pre-submit machinery reused); on failure the edit is rolled back from the pre-image (journaled `Restored`) and the model gets the diagnostics as an observation (or, with `keep_on_failure: true`, the edit stays and diagnostics are appended — default rollback). Time-bounded; per-check allow rule needed in unattended runs, as presubmit.
- Crates: harness-run (new `postedit.rs`, driver hook), harness-cli (task/config section), harness-tools (restore from P-22).
- Tests: `post_edit_failure_rolls_back_edit`, `post_edit_pass_keeps_edit`, `post_edit_diagnostics_shown_to_model_delimited`, `post_edit_timeout_rolls_back`, `post_edit_needs_exec_grant`, `post_edit_policy_denied_refuses_task_file`, `post_edit_replay_and_resume` (re-fed results), `post_edit_header_input_must_match`.
- Deps: P-22, P-26 (restore), P-11. Parallel: driver-chain; run after P-26 or merge carefully. Risk: medium-high. ARCH: no.

**P-28 Plan/build modes and plan-scoped grants**
- Why: the best-liked workflow in the field. `/plan`: active set = read tools + todo + `harness.plan.submit {summary, files[], steps[]}`; no edits/exec; user sees the plan, `/build` approves it: journals `ModeChanged{plan_digest}`, active set widens, trifecta recomputed (design §5.4), edit calls on files named in the approved plan skip the ask (matcher `plan.allow`), others ask. `rh-context/7` adds a mode line and the approved plan block (user-approved text, trusted-intent).
- Crates: harness-run (driver chain), harness-policy (mode active-set + plan matcher), harness-model-core (context fmt /7, chain H-D), harness-cli (commands).
- Tests: `plan_mode_hides_edit_and_exec_tools`, `build_after_plan_allows_listed_files_without_ask`, `edit_outside_plan_asks`, `mode_change_recomputes_trifecta`, `plan_digest_in_journal_and_audit`, `context_fmt7_only_in_session_mode`, `plan_submit_content_untrusted_in_context_until_user_approves`.
- Deps: P-08, P-13, P-17, P-23. Parallel: no (driver + context chains). Risk: medium-high. ARCH: no.

**P-29 Protected paths: `.git` and friends read-only by default**
- Why: reward-hack/safety floor on a real repo. Edit tools refuse protected paths; sandbox exec gets them as read-only overlays (`ConfinedSpec.protected`, today always empty at `harness-tools/src/exec.rs:885`). Default CLI list: `.git/**`, `.rustyharness/**`, CI config globs (`.github/**`) as `ask`-to-edit not deny? Fail-closed default: edit denied for `.git/**`, ask for CI/lockfiles (task-declared protected list supported). Macos conformance cases added (write into `.git` from sandboxed command fails).
- Crates: harness-tools, harness-sandbox (`conformance.rs` + seatbelt profile only if overlay logic lives there), harness-cli.
- Tests: `edit_into_dot_git_refused`, `exec_cannot_write_dot_git` (macOS conformance, skipped elsewhere with reason), `protected_list_in_header`, `read_of_dot_git_allowed`, `task_declared_protected_path_refused`, `lockfile_edit_asks`.
- Deps: P-08, P-11. Parallel: yes (tools/sandbox/cli; touches no driver). Risk: medium (sandbox profile). ARCH: no.

#### Wave 7

**P-30 Project instructions and slash commands/skills**
- Why: AGENTS.md/CLAUDE.md parity. At session start the CLI finds `AGENTS.md` (then `CLAUDE.md`) in the workspace root, shows its digest and size, asks the user to trust it (remembered by digest in the user config dir, not in the workspace); trusted text enters the context as an `Untrusted`-labelled "project notes" block (cap = 8% of window, cut with notice), journaled `InstructionsLoaded{path,digest}` with the bytes as a blob so audit re-feeds. Library default: no instructions. Slash commands: `<config dir>/commands/*.md` (trust base only; `$ARGUMENTS`) expand to a user turn; workspace `.rustyharness/commands` listed but need per-digest approval; skills = same files loadable by the model through read-only `harness.skill.load`? (deferred; commands only here). `rh-context/8`.
- Crates: harness-model-core (context chain), harness-run (header/audit input), harness-cli.
- Tests: `instructions_untrusted_label_and_digest_in_journal`, `changed_instructions_require_reapproval`, `instructions_cannot_alter_policy` (hostile AGENTS.md), `instructions_cap_with_notice`, `library_default_loads_nothing`, `command_template_expands_arguments`, `workspace_command_needs_approval`, `audit_refeeds_instruction_blob`.
- Deps: P-28 (context chain), P-18. Parallel: not with context/driver slices. Risk: medium. ARCH: no. Owner Q-7.

**P-31 Hosted model via loopback proxy: declaration, disclosure rule, cost budget**
- Why: multi-provider parity without TLS in-tree. Profile gains optional `upstream: "hosted"` + `price_table{in_micro_per_ktok,out_micro_per_ktok}` (absent = unchanged digest). When declared: header `endpoint_class: loopback-proxy-hosted`; session planning refuses grants with sensitivity >= personal (Q2 default) and refuses a run with no price table (design §2.4); cost computed from usage into the meter's `Cost` dimension; banner and `/status` say "context is sent to a hosted provider". Docs recipe `docs/hosted-proxy.md` (user runs their own proxy; harness never sees the key beyond the optional `ApiKey` handle).
- Crates: harness-model-core (profile), harness-run (planning check, cost charge), harness-cli (banner).
- Tests: `hosted_profile_refuses_personal_sensitivity`, `hosted_profile_without_price_table_refuses`, `cost_budget_stops_run`, `cost_in_usage_footer`, `local_profile_digest_unchanged`, `hosted_declared_header_recorded_and_audited`.
- Deps: P-15 (usage), P-17. Parallel: touches driver planning (small) - schedule when no loop slice runs. Risk: medium. ARCH: no. Owner Q-2, Q-3.

**P-32 Session fork**
- Why: branch a conversation (opencode/Claude Code parity) with verifiable lineage. `chat --fork RUN@STEP` (or `/fork` in REPL): new run id whose first record `ForkedFrom{parent_run, parent_step, parent_chain_head}`; context and tree reconstructed by the resume catch-up machinery from the parent's records up to STEP (workspace restored to that step via P-26 restore or required to match the digest); parent journal untouched; audit of the child verifies parent prefix hashes against the recorded head.
- Crates: harness-run (replay/resume module reuse), harness-cli.
- Tests: `fork_child_audits_clean_and_links_parent`, `fork_parent_unchanged`, `fork_at_missing_step_refused`, `fork_requires_workspace_digest_match_or_restore`, `fork_parent_tampered_refused`.
- Deps: P-17, P-26. Parallel: no (replay chain). Risk: medium-high. ARCH: no.

#### Wave 8 - M3: parity-plus

**P-33 Deterministic conversation ledger, repo-map block, terse tool docs (`rh-context/9`)**
- Why: long sessions on small windows. Ledger block: user turns (kept), todo state, files-touched table (path, edits, last digest) derived from `EditApplied`, commands-run list (argv, exit) derived from `ToolFinished`, restored/mode events; replaces nothing model-written. Optional repo map: outline of top-N files by recency/edit count within a token share of the window (uses P-24 extractor), recomputed per build, digest-covered. Profile `tool_docs: terse|full` (default full => unchanged digests) shortens tool summaries for small models. No model-written summary (Q-9 default).
- Crates: harness-model-core (context chain), harness-run (inputs), harness-tools (outline fn reuse).
- Tests: `ledger_survives_compaction_and_lists_edits`, `ledger_deterministic_digest`, `repo_map_respects_budget_share`, `repo_map_recomputed_identically_by_audit`, `terse_docs_reduce_tool_block_bytes`, `full_docs_digest_unchanged`, `context_fmt9_only_session_mode`.
- Deps: P-24, P-28/P-30 (context chain), P-22. Parallel: no (context chain). Risk: medium-high. ARCH: no.

**P-34 Journal tamper suite and REPL golden transcripts (eval)**
- Why: prove the evidence story under attack and freeze UX. (a) Property-style mutation test: for a scripted session journal, mutate each line (bit flips, field swaps, line drop/duplicate/reorder, truncation, post-RunStopped bytes, re-chain with valid hashes but altered content) and assert `audit`/reader detects (re-chain only with `--anchor`). (b) Golden transcripts of `chat` output (sanitised, timing stripped) for 8 flows (read-only Q&A, edit with approval, deny, undo, plan->build, resume, hostile output, budget stop).
- Crates: tests in harness-journal, harness-run, harness-cli.
- Tests: `tamper_every_line_flip_detected`, `tamper_rechain_detected_only_with_anchor`, `tamper_truncated_tail_reported`, `golden_chat_*` (8).
- Deps: P-17, P-26, P-28. Parallel: yes (tests only). Risk: low. ARCH: no.

**P-35 ACP server (`rustyharness acp`)**
- Why: IDE integration (Zed etc.). New crate `harness-acp` (no deps beyond workspace serde_json) speaking Agent Client Protocol JSON-RPC over stdio only (no listener): `initialize`, `session/new`, `session/prompt`, `session/update` notifications from `EventSink`, `session/request_permission` mapped to `Approver` (Embedded kind), `session/cancel`. Needs the exact ACP version pinned in a doc after reading the spec (first step of the slice: write `docs/slices/P-35-acp-spec-notes.md`).
- Crates: harness-acp (new), harness-cli (verb), Cargo.lock (H-F).
- Tests: `acp_initialize_handshake`, `acp_prompt_streams_updates`, `acp_permission_request_roundtrip_yes_no`, `acp_cancel_ends_turn`, `acp_session_journal_audits_clean`, `acp_rejects_malformed_json_rpc`, `acp_never_binds_a_socket` (code scan in test).
- Deps: P-13, P-17, P-23. Parallel: yes (new crate + one cli line). Risk: medium (spec drift). ARCH: no.

**P-40 Tamper-evident diff review (`/diff`, `rustyharness review --run ID`)**
- Why: improvement no competitor has. Render the session's total change as a diff computed from journal pre-image/after blobs (not from `git`), verify each blob against its journaled digest and the current workspace against the last after-digest; flag any file that differs from what the harness recorded ("changed outside the harness"); output includes the chain head so the review is bound to an anchor.
- Crates: harness-cli, harness-tools (diff from P-16), harness-journal (reader).
- Tests: `review_diff_matches_workspace_changes`, `review_flags_out_of_band_change`, `review_detects_blob_tamper`, `review_includes_chain_head`, `review_empty_session_message`.
- Deps: P-16, P-22. Parallel: yes (spare lane). Risk: low. ARCH: no.

#### Wave 9 - ARCH slices (each starts with a design note by the reasoning model, reviewed by the owner, then is split into 2-4 cheap-model slices)

**P-36 ARCH: background processes and granted loopback ports (OD-5a, OD-5b)**
- Design note must cover: `harness.exec.start/read/stop` via `confine_spawn.rs` (purity re-pin, INV-23), per-process ids, bounded ring-buffer output with journaled cursor, kill-at-every-stop (cleanup that survives crashes: next start kills orphans by scratch marker), interaction with the interim file-op race (option (b), owner Q-16), Seatbelt `network-bind`/`network-outbound` rules limited to granted `127.0.0.1:port`, never the model server's port, a LAN-visible port as a separate higher-risk ask-every-time grant, Linux/Windows refuse. Conformance cases (FT-ports) written first.
- Crates (expected): harness-sandbox, harness-tools, harness-run, harness-policy.
- Tests (to be refined in the note): `bg_process_killed_on_run_end`, `bg_process_killed_on_stop_by_budget`, `bind_to_model_server_port_refused`, `bind_ungranted_port_refused`, `lan_bind_requires_separate_grant`, `bg_output_cursor_replayable`, conformance `ft_ports_*` (macOS).
- Deps: P-22..P-27, owner Q-16/Q-12. Parallel: no (sandbox + purity pin). Risk: high. ARCH: **yes**.

**P-37 ARCH: MCP stdio client (own thin client)**
- Design note: minimal JSON-RPC 2.0 stdio client (initialize, tools/list, tools/call; refuse sampling, roots, resources, elicitation), server spawned confined (`confine_spawn`), manifest v1 pins description+schema hashes, admission tiers, rug-pull quarantine, per-call policy and journal, output `Untrusted`, tool-count cap interplay (Q-6: MCP tools count against `max_active_tools`), no network for the server unless granted (trifecta applies). Decision: own client instead of rmcp (tokio/heavy; design §11 "what would make this wrong").
- Crates (expected): new `harness-mcp`, harness-manifest, harness-policy, harness-run, harness-sandbox (spawn pin).
- Tests: `mcp_tool_list_pinned_hash_mismatch_quarantines`, `mcp_server_runs_confined`, `mcp_sampling_request_refused`, `mcp_duplicate_namespace_refused`, `mcp_call_journaled_and_policy_checked`, fixture-provider zero-core-diff test (design D8).
- Deps: P-36 spawn precedent, P-23, P-08. Parallel: no. Risk: high. ARCH: **yes**. Owner Q-13.

**P-38 ARCH: subagents (`harness.task.delegate`)**
- Design note: child run via the same driver, read-only tools only (explorer) in v1, budgets carved from the parent meter deterministically, child journal separate and linked (`ChildRun{run_id, chain_head}` in the parent's tool result), result delivered as `Untrusted` bounded text, endpoint concurrency 1 so strictly sequential, approvals inside a child route to the parent's approver and say so, replay of parent re-feeds the child's final result and audits the child separately, depth limit 1.
- Crates (expected): harness-run, harness-tools or run-level provider, harness-manifest, harness-policy.
- Tests: `delegate_child_cannot_edit`, `delegate_budget_carved_from_parent`, `delegate_result_untrusted_and_bounded`, `delegate_child_journal_audits_clean_and_linked`, `delegate_depth_limit`, `delegate_denied_without_grant`.
- Deps: P-33, P-17. Parallel: no (loop). Risk: high. ARCH: **yes**.

**P-39 ARCH: web research airlock (web.fetch/search)**
- Design note: research session type with no workspace grant (so no P label; trifecta passes), egress proxy in the harness process with exact-host allowlist (`*` refused, loopback/private ranges refused after resolution), per-request `Egress` journal event before forwarding, TLS question (Q-2: either a reviewed C-free TLS crate in `deny.toml`, or HTTP-only allowlist, or user-provided loopback fetch proxy tool), results stored as quarantined notes under state dir; import into a coding session is an explicit human action (`/import-research FILE` shows diff, the user types the confirmation) and the imported text is `Untrusted`. Trifecta change itself (owner Q-1) is **not** assumed.
- Crates (expected): harness-sandbox (egress), harness-tools, harness-policy, harness-run, harness-cli.
- Tests: `web_session_refused_with_workspace_grant`, `egress_to_private_ip_refused_after_dns`, `egress_event_precedes_forward`, `fetched_text_marked_untrusted`, `import_requires_user_confirmation`, `research_notes_never_reach_policy`.
- Deps: P-23, P-31 (TLS decision), owner Q-1/Q-2. Parallel: no. Risk: high. ARCH: **yes**.

(The numbering P-21..P-40 is by card order, not wave order; the wave table in 4.2 is authoritative for scheduling.)

---

## 5. Eval plan: proving the harness works end to end

| # | Eval | Where | Gate? | Proves |
|---|---|---|---|---|
| E1 | **Scripted scenario suite** (P-20): 12 coding scenarios, scripted model, real tools, real journal, `assert_audit_clean` on each | `harness-run/tests/scenarios.rs` | yes | loop + tools + approvals + budgets compose; replay holds for every feature |
| E2 | **Hostile-task suite** (P-19): injection, nonce forgery, ANSI/bidi, traversal/symlink, argv tricks, exfil via trifecta fixture, forged approvals, huge output, runaway command, journal tamper | `harness-run/tests/hostile_*.rs`, `harness-cli/tests/hostile_chat.rs`, macOS `conformance_macos.rs` | yes | fail-closed behaviour is not weaker in sessions |
| E3 | **Replay parity everywhere**: every integration test in the repo that produces a journal calls `assert_audit_clean`; CI check script greps that new tests in `tests/` using `run`/`run_session` do (`scripts/ci/audit-parity.sh`, added with P-03) | testkit + script | yes | "any new feature is journaled and replayable" is enforced, not hoped |
| E4 | **Tamper suite** (P-34a): mutate/re-chain/truncate every line of a session journal | `harness-journal/tests`, `harness-run/tests` | yes | evidence claims (chain, anchor, torn tail, post-stop bytes) |
| E5 | **REPL golden transcripts** (P-34b) | `harness-cli/tests/golden/` | yes | UX regressions, escape safety |
| E6 | **Streaming mock-server tests** (P-06): delayed chunks, mid-stream deadline, oversized stream | harness-model tests | yes | streaming cannot weaken deadlines/caps |
| E7 | **Real-model smoke** (P-21a): `chat` over a loopback server, both protocols, two turns, edit, anchored replay | `harness-cli/tests/chat_live.rs` | `#[ignore]`, run before release | prompts/format work with a real model (the thing scripted tests cannot show) |
| E8 | **Mini coding benchmark** (P-21b): 10 fixture repos, presubmit checks as oracle, TSV keyed by (harness version, profile sha); also run per candidate small model to set `max_active_tools`/`tool_docs` empirically (answers Q-6) | `scripts/dev/mini-bench.sh`, `fixtures/bench/` | nightly/manual | regressions in agent quality; model-vs-harness effect size (overview §1) |
| E9 | **Sandbox conformance** extended: `.git` write (P-29), ports (P-36), background kill (P-36) | `harness-sandbox/tests/conformance_macos.rs` | yes on macOS CI | confinement claims for new features |
| E10 | **Gates**: `sh scripts/ci/gates.sh` unchanged semantics; purity selftest extended when a slice adds a new reviewed dependency or spawn file | scripts/ci | yes | no heavy deps; spawn sites reviewed |
| E11 | **Per-slice acceptance**: the card's named tests; reviewer (fresh context, different model where possible) checks the diff against the card before merge | process | yes | cheap-model output is verified |

Suggested definition of done for any slice: card tests green + `sh scripts/ci/gates.sh` + `assert_audit_clean` in at least one test + `docs/slices/P-xx.md` written + no changes outside the card's crates (checked by `git diff --stat`).

---

## 6. Owner questions raised (each with the fail-closed default that holds until answered)

| Id | Question | Default until answered | Blocks |
|---|---|---|---|
| Q-1 | Revisit the trifecta (OPEN-QUESTIONS 1.7 / design Q7) for web research: is the airlock design (research session without workspace, human-reviewed import) acceptable, or is a plan-then-execute/dual-LLM path wanted? | Never combine workspace + egress; no web tools | P-39 |
| Q-2 | TLS: may the build take a reviewed C-free TLS stack (feature `hosted`) for hosted models/web fetch, or must hosted/web stay behind the user's own loopback proxy? May a hosted model see `personal` data (design Q2)? | No TLS in tree; hosted only via user's loopback proxy; no `personal` data to a hosted upstream | P-31 (declaration only), P-39 |
| Q-3 | Does a profile declared `upstream:"hosted"` through a loopback proxy count as a hosted model for the disclosure rules? | Yes: hosted rules apply to anything the user declares hosted | P-31 |
| Q-4 | Session-scoped "always allow this pattern" grants (relaxes the strict one-call approval binding the owner kept; tokens stay single-use, the grant is a journaled rule). Also `--accept-edits` once undo exists? | Prompts offer yes/no only; session grants and `--accept-edits` off (flags refused) | P-23, P-28 |
| Q-5 | Several read-only calls per reply (OPEN-QUESTIONS 9). | One action per reply | not scheduled |
| Q-6 | Active-tool cap 5-8 vs ~10-12 for interactive profiles (OPEN-QUESTIONS 8). | 5-8, interactive profiles set 8, modes shrink the set (P-28) | P-24/P-25 default grants, P-37 |
| Q-7 | Project instruction files (AGENTS.md/CLAUDE.md): loaded at all, and with what trust? | Library: never. CLI: only after the user approves the file's digest; treated Untrusted; never affects policy | P-30 |
| Q-8 | Workspace-resident config (a `.rustyharness` file in the repo): may it exist? | Not read. If later allowed: tighten-only (add deny/ask), never loosen | P-07, P-30 |
| Q-9 | Model-written summaries in long-session compaction. | No; deterministic ledger only (P-33) | P-33 variant |
| Q-10 | What should an interactive session's final report be before H3? | `Indeterminate{NothingChecked}`, exit 5 (unchanged); a user-run `/check` is not a verdict | P-18 wording |
| Q-11 | Shell: confirm that `--shell` (an `sh` on the exec allowlist, sandbox as the control, `shell_enabled:true` in header) is the intended route to "bash". | Off; explicit flag per run | P-11 |
| Q-12 | Ports and background processes (OD-5): design approval, Seatbelt `network-bind`, LAN grant tier. | None granted; exec stays synchronous | P-36 |
| Q-13 | MCP: own thin stdio client (no rmcp/tokio) vs rmcp as the design says (D7). | No MCP; when built, own client | P-37 |
| Q-14 | Subagents with endpoint concurrency 1 (design Q6): sequential only? | No subagents; when built, strictly sequential, depth 1 | P-38 |
| Q-15 | Interactive on Windows (OD-7): read/edit only until S-W1. | Windows: no exec; REPL read/edit with approvals; state_root refused until S-W1 | none |
| Q-16 | The file tools' race in sessions that execute (OPEN-QUESTIONS 7): build the confined file-op helper (needed once commands run in the REPL alongside in-process edits and especially for background processes), or keep interim (b)? | Interim (b): the run stops unless the sandbox confirms every command process is gone | P-36 |
| Q-17 | Linux backend mechanism D29 (namespace-less Landlock+seccomp likely). | exec refuses on Linux | track S-L |
| Q-18 | Does the owner want the process rule "slice notes in `docs/slices/P-xx.md`, folded into the design per wave" instead of appending rows to the design doc per slice? | Slice notes in separate files | all slices |

---

## 7. Suggested first moves
1. Run W0 (P-01..P-04) now: four parallel cheap-model briefs, all refactors/test kit, no owner input needed.
2. Start P-05 (ARCH) in W1 with the reasoning model; get the owner's OK on the session model before W2 starts. Meanwhile P-06/P-07/P-08 proceed.
3. Ask the owner Q-4, Q-7, Q-10, Q-11 early (they shape P-18/P-23/P-30 wording but each has a safe default, so nothing waits on them).
4. Before declaring M1, run P-21a on the local Qwen/GLM profiles used in earlier phases; record in the FYP log.
