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
- Why: scripted models cannot reveal prompt/format problems. (a) `harness-cli/tests/chat_live.rs` `#[ignore]`: env `RUSTYHARNESS_EXIT_ENDPOINT/MODEL`, drives `chat` over piped stdin through two turns on a fixture repo, asserts the answer, a verified edit, clean audit, anchored replay; both protocols. (b) a Rust dev binary `crates/harness-minibench` (workspace member, publish=false, no Python or shell logic; the project is Rust only) + 10 fixture tasks (`fixtures/bench/*/task.json + repo + expected check command`): runs each with presubmit checks, records pass/fail/steps/tokens/format-errors to a TSV keyed by (harness version, profile sha) so regressions are visible (design R1 §8 #15). Not a gate; run before releases and nightly on a local model.
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
| E12 | **Web airlock hostile suite** (P-39k): prompt injection and forged nonces in fetched pages, redirect/DNS attacks (metadata IP, private-via-DNS, rebinding, mixed answers, IPv4-mapped IPv6), budget bombs (giant bodies, endless chunked, slowloris, header floods, gzip bombs), zip-as-HTML, content-type games, request smuggling, terminal escapes, search-snippet injection, lying fetcher frames, offline audit replay with zero sockets | `harness-run/tests/hostile_web.rs` | yes | the web airlock refuses each hostile class with a typed refusal, keeps every egress journaled before it happens, and replays offline identically |

Suggested definition of done for any slice: card tests green + `sh scripts/ci/gates.sh` + `assert_audit_clean` in at least one test + `docs/slices/P-xx.md` written + no changes outside the card's crates (checked by `git diff --stat`).

---

## 6. Owner questions raised (each with the fail-closed default that holds until answered)

| Id | Question | Default until answered | Blocks |
|---|---|---|---|
| Q-1 (APPROVED 2026-10-02: airlock now, dual-LLM later as a research track, never a prompt per fetch) | Revisit the trifecta (OPEN-QUESTIONS 1.7 / design Q7) for web research: is the airlock design (research session without workspace, human-reviewed import) acceptable, or is a plan-then-execute/dual-LLM path wanted? | Never combine workspace + egress; no web tools | P-39 |
| Q-2 (APPROVED 2026-10-02: no TLS in the default build; opt-in `net` feature, out-of-process fetcher, after review) | TLS: may the build take a reviewed C-free TLS stack (feature `hosted`) for hosted models/web fetch, or must hosted/web stay behind the user's own loopback proxy? May a hosted model see `personal` data (design Q2)? | No TLS in tree; hosted only via user's loopback proxy; no `personal` data to a hosted upstream | P-31 (declaration only), P-39 |
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

---

### Added during execution (extras)

**P-41 Seatbelt live-probe robustness**
- Why: under machine load the macOS sandbox startup probes fail spuriously (`LiveProbeFailed ... mem-applied Signaled(5)`, and `live probe sweep ... Unconfirmed("processes of the domain would not die within the sweep deadline (3 s)")`), refusing execution and failing gate runs for no real reason. Fail-closed must stay: a probe that truly fails must still refuse. Make the probes robust, not weaker: (1) the sweep deadline scales (3 s base, retried once with 3x on `Unconfirmed` timeouts, never on a definite negative result such as a process that survived after a *confirmed* kill attempt); (2) a probe that is killed by a signal before it reports is re-run once, and a second identical failure is final; (3) the witness records the attempt count and the deadline used, so an audit can see a retried probe; (4) never retry a probe whose result was an escape (a negative security observation).
- Crates: harness-sandbox only (`confine_spawn.rs` / probe code; mind the pinned SHA of spawn files in scripts/ci/purity.sh: if the pin must be updated, update it in the same commit and say so loudly in the slice note).
- Tests: `probe_retries_unconfirmed_timeout_once`, `probe_retry_never_masks_an_escape` (a fixture where the sandbox is deliberately weakened must still be refused), `probe_second_failure_is_final`, `witness_records_attempts_and_deadline`, plus the existing conformance suite unchanged.
- Deps: none. Parallel: yes (sandbox crate only). Risk: medium (security-relevant: fail-closed). ARCH: no.

**P-43 `rustyharness doctor`**
- Why: parity with `opencode doctor`-style self-diagnosis and a far better first-run experience. New verb `doctor [--endpoint URL] [--state-root DIR]` printing one line per check with PASS/WARN/FAIL and a one-sentence fix: platform and sandbox witness (macOS Seatbelt conformance or "refuses: reason"), state root exists/local/0700, user config readable and strict-valid (P-07 config), endpoint reachable and `/v1/models` listing, a profile exists and its stamp is valid, toolchain programs for the presets found (P-11), terminal is a TTY. Exit code 0 when no FAIL. Output is sanitised (P-04); no network calls except to the given loopback endpoint.
- Crates: harness-cli (new `cmd_doctor.rs`, one dispatch line, usage text).
- Tests: `doctor_all_pass_with_mock_server`, `doctor_fails_without_state_root_and_says_how`, `doctor_warns_on_non_tty`, `doctor_reports_unreachable_endpoint`, `doctor_output_has_no_raw_escapes`, `doctor_exit_code_follows_fail`.
- Deps: P-07, P-11, P-04. Parallel: small cli hotspot (dispatch/args), keep the diff tiny. Risk: low. ARCH: no.

---

### Added from the Odysseus review (2026-10-02)

Odysseus (PewDiePie's self-hosted AI workspace) offers web search/fetch/deep research, persistent memory, skills, MCP, approval gates, model comparison and scheduled tasks. Already planned here: web airlock (P-39), skills and instructions (P-30), MCP client (P-37), approvals (P-23). New cards below. Deliberately not taken: email/calendar/document editor, a web UI/PWA, Docker, and a headless browser (deferred: large attack surface; revisit after the airlock is proven; owner decision).

**P-44 Pure HTML-to-text extractor (readability-lite)**
- Why: the fetch half of web research without a browser. A pure function `harness_core::html::to_text(&[u8], limits) -> Extracted {title, text, links, truncated}`: tolerant tokenizer (no regex crate), drops script/style/nav/aside/footer/form/iframe/svg and comments, keeps headings/paragraphs/lists/code/pre/table cells as plain text with markers, resolves nothing and fetches nothing, bounded input (e.g. 2 MiB) and bounded output with a visible `[N bytes cut]`, output passed through the terminal sanitiser (P-04), links returned as data (never followed). Fuzz-style tests on malformed HTML. Foundation for P-39/P-46; fully offline, so safe to build now.
- Crates: harness-core (pure; no I/O names, no clock).
- Tests: `extracts_title_and_paragraphs`, `drops_script_style_and_comments`, `prompt_injection_text_is_kept_as_plain_text_not_interpreted`, `malformed_unclosed_tags_do_not_panic`, `deeply_nested_input_is_bounded`, `huge_input_is_truncated_with_marker`, `output_has_no_control_or_bidi_characters`, `links_are_data_only`, `deterministic_digest`, purity gate passes.
- Deps: P-04. Parallel: yes. Risk: low. ARCH: no.

**P-46 Deep research mode (`rustyharness research "<question>"`)**
- Why: Odysseus's Deep Research, with evidence. A research session (no workspace grant, so the trifecta rule passes) runs a fixed loop under the P-39 airlock: plan queries, search (SearXNG-compatible endpoint the user runs, or the airlock's fetcher), fetch top-N pages, extract with P-44, then write a cited report. Every query, every fetch (URL, status, content digest) and every cited passage is journaled; the report's citations are checked against the journaled digests (a citation of text that was not fetched is flagged "phantom citation"). Output is stored as a quarantined note under the state dir; importing it into a coding session is a separate explicit user action (P-39 rule).
- Crates: harness-run, harness-tools (provider from P-39), harness-cli.
- Tests: `research_session_has_no_workspace_grant`, `every_fetch_journaled_with_digest`, `phantom_citation_flagged`, `report_quarantined_until_import`, `research_replay_audits_clean`, `budget_stops_research`.
- Deps: P-39 (ARCH note first), P-44, P-18. Risk: medium-high. ARCH: via P-39.

**P-47 Memory provider seam and the rustylife add-on**
- Why: persistent memory without building a second memory system. The owner is building rustylife (an encrypted on-device tree of the user's information, an "Obsidian second brain" with hybrid local search, per-subtree scopes and information-flow labels). The harness must not hold app-specific code (OD-2) and must stay standalone, so: a generic, off-by-default **memory provider seam** (tools `memory.search {query, scope?}`, `memory.read {id}`, `memory.propose {path, text}`), and rustylife is the first provider, shipped as an optional H5 add-on (`adapters/rustylife/` manifest plus a thin provider process that calls the rustylife store/CLI; never a harness core dependency). Rules: (a) the user unlocks the store in the trust base (the key never reaches the harness or the model, secrets boundary, INV-27); (b) each session names a rustylife `Scope` (subtree grant); the provider can only read inside it; (c) rustylife's information-flow labels map to the harness sensitivity labels: anything labelled personal makes the session `personal`, so a hosted model is refused (Q2 default) and the trifecta rule applies (private + untrusted + exfil never combine); (d) retrieved text is `Untrusted` and delimited; (e) writes are proposals only: `memory.propose` journals a pending note the user approves/rejects out of band, never auto-saved; (f) every read is journaled (ids and digests, not content) so a session shows exactly which memories influenced it; (g) default profile for small local models: top-k with a token cap.
- Crates: harness-manifest/policy (a `memory` capability class, label mapping), harness-tools (seam only), adapters/rustylife (new, feature-gated; the only place rustylife is named), harness-cli (`--memory rustylife --memory-scope <node ids>`).
- Tests (design-note refines): `memory_off_by_default`, `memory_read_outside_scope_refused`, `personal_label_blocks_hosted_profile`, `memory_text_untrusted_and_delimited`, `propose_never_writes_without_approval`, `reads_journaled_without_content`, `key_never_in_journal_or_context`, `default_build_has_no_rustylife_dependency` (purity), add-on on/off matrix (INV-32).
- Deps: P-23, P-31 (sensitivity), P-08; needs a rustylife read API contract from the rustylife side (search/get_node/scope) which is the owner's project. Risk: high (privacy). ARCH: **yes** (design note first; owner confirms the rustylife contract).

**P-48 `rustyharness compare` (blind side-by-side runs)**
- Why: Odysseus's model comparison, but with evidence and without grading by the harness (OD-3). Runs the same task (same workspace snapshot, policy, budgets) on 2 to 4 profiles/endpoints one after another (endpoint concurrency 1), each from a fresh scratch copy; writes a comparison report with arms labelled A/B/C in random-but-recorded order, and per arm: steps, tokens, wall, format errors, tool counts, final diff, pre-submit check result (a fact, not a score), chain head. The user picks a winner (recorded in the report); the label to model map is revealed only after. All arms replayable.
- Crates: harness-cli (`cmd_compare.rs`), harness-run (scratch copy helper).
- Tests: `compare_runs_each_arm_in_fresh_copy`, `compare_labels_hide_model_until_reveal`, `compare_report_lists_facts_not_scores`, `compare_each_arm_audits_clean`, `compare_refuses_one_arm`.
- Deps: P-18, P-21, P-22 (diff). Risk: low-medium. ARCH: no.

**P-49 Scheduled unattended runs (`rustyharness schedule`)**
- Why: scheduled agent tasks. `schedule add --name N --task task.json [--daily HH:MM|--every Nh]` writes a user-level launchd plist (macOS) or systemd user timer (Linux) that runs `rustyharness run` with the saved bundle; installing/removing is a config change, so the command prints the exact file and asks the user to confirm (never silent). Unattended means no approver: every Ask is denied (benchmark-mode semantics), a task must carry budgets, and results are `sessions` entries with an `events` stream. `schedule list/remove/run-now`.
- Crates: harness-cli (`cmd_schedule.rs`), no new deps.
- Tests: `schedule_add_prints_plist_and_requires_confirmation`, `schedule_refuses_task_without_budgets`, `schedule_run_denies_every_ask`, `schedule_remove_deletes_only_its_own_file`, `schedule_list_shows_next_run`, `plist_has_no_secrets`.
- Deps: P-14, P-18. Risk: low-medium. ARCH: no.

**Deferred (owner decision):** headless browser tool (JS-rendered pages). Large dependency and attack surface; the airlock plus P-44 covers static pages. Revisit after P-39 ships.

---

### Found by the first real-model run (2026-10-02)

**P-51 Exec presets: read-only roots for the program's dynamic-library dependencies**
- Why: live run of the new build with Qwen3-4B on a failing Rust crate: the model made the right edit (`a - b` to `a + b`), but the pre-submit `cargo test` failed inside the Seatbelt sandbox with a dyld error (missing `libgit2`): homebrew's `cargo` links dylibs from other Cellar directories that the `rust` preset (P-11) did not whitelist (`read-only: /opt/homebrew/Cellar/rust/1.97.0` only). The harness correctly failed closed (`submitted_checks_failed`), but it made a correct agent look wrong and wasted budget. Fix at the source, in the trust base: when `--allow-exec` resolves a program, also resolve its dynamic dependencies and add their directories as read-only roots, shown to the user before the run ("will allow: cargo -> /path; libs: ...") and recorded in the header's exec section. Pure Rust: parse the Mach-O load commands (`LC_LOAD_DYLIB`, `@rpath`/`@loader_path` expansion with the binary's rpaths, one level of transitive deps, depth and count bounded) and the ELF `DT_NEEDED` on Linux; no `otool`/`ldd` subprocess; system paths (`/usr/lib`, `/System`) are already readable; anything that resolves outside an allowed prefix list (home dir, `/opt/homebrew`, `/usr/local`, the toolchain dir) is listed and refused unless the user adds it. `doctor` gains a check that runs `<program> --version` through the confinement witness for every preset program and says exactly which path the sandbox blocked.
- Crates: harness-cli (`exec_presets.rs`, `cmd_doctor.rs`), a new pure module for the object-file parser (harness-core or harness-tools; no I/O in a pure crate: the file read stays in the CLI).
- Tests: `macho_load_commands_parsed_from_fixture_bytes`, `rpath_and_loader_path_expanded`, `transitive_depth_is_bounded`, `deps_outside_allowed_prefixes_listed_and_refused`, `preset_rust_includes_cargo_dylib_roots` (this machine: skipped with reason if cargo is not a Mach-O), `header_records_lib_roots`, `doctor_flags_a_program_that_cannot_run_in_the_sandbox`, `malformed_object_file_is_refused_not_panicked`.
- Deps: P-11, P-43. Risk: medium (parser of untrusted-ish binaries: bounded, no unsafe, fuzz-style tests). ARCH: no.

---

### Added by the manager (2026-10-02, afternoon)

**P-52 Workspace modes: in place, scratch copy, git worktree, with review-and-apply**
- Why: let a user (and a small model) work on a throwaway copy and keep only what they review. `chat`/`run` gain `--workspace-mode in-place|scratch|worktree` (default `in-place`, unchanged). `scratch`: the CLI (trust base, not the model) copies the workspace into `<state-root>/scratch/<session>/` (skips `target/`, `node_modules/`, `.git` internals are copied only if `--scratch-with-git`; refuses over a size cap with a clear message) and records source path, copy manifest digest and per-file digests in the journal header; the model only ever sees the copy. `worktree`: the CLI runs `git worktree add` with fixed argv (no model input in argv) under the state root, only when the workspace is a clean git repo; otherwise refused. `rustyharness apply --session ID [--dry-run]` shows the diff scratch vs original (P-16 renderer), and applies it only after typed confirmation; every original file must still match its recorded digest (else listed as a conflict and skipped, never overwritten); an apply report is written and the chain is unaffected. `/apply` and `/discard` in `chat`.
- Crates: harness-cli (`workspace_mode.rs`, `cmd_apply.rs`), harness-run (header fields only), harness-testkit.
- Tests: `scratch_mode_edits_never_touch_original`, `scratch_copy_skips_target_dir_and_records_manifest`, `scratch_refused_over_size_cap`, `worktree_mode_refused_on_dirty_repo`, `apply_requires_typed_confirmation`, `apply_skips_conflicting_original_and_reports_it`, `apply_dry_run_changes_nothing`, `scratch_session_audits_clean`, `in_place_default_unchanged`.
- Deps: P-14, P-16, P-18. Parallel: yes (cli files only; one dispatch line each). Risk: medium. ARCH: no.

**P-53 Chat robust for small models: terse tool docs per profile, parallel reads opt-in**
- Why: the live runs (P-21) show small local models fumble long tool descriptions and call many tools per turn. Profile fields `tool_docs: "full"|"terse"` (terse = the description is cut to one sentence plus the argument names, from a fixed table in `harness-manifest`, digest-recorded in the header) and `parallel_tool_calls: false` by default (a second call in one assistant turn is rejected with a clear tool error and journaled, unless the profile opts in), and `max_active_tools` honoured in the declarations. No change to the rendered context text (`rh-context` stays at its current version); only the tool declarations in the request change, and the profile stamp covers the new fields.
- Crates: harness-manifest (terse table), harness-model-core (declaration rendering only), harness-cli (profile fields, `profile init` defaults for local small models), harness-run (reject surplus calls).
- Tests: `terse_docs_are_shorter_and_keep_arg_names`, `terse_table_covers_every_builtin_tool`, `second_tool_call_in_a_turn_rejected_when_not_opted_in`, `parallel_calls_allowed_when_profile_opts_in`, `profile_stamp_changes_with_tool_docs`, `max_active_tools_limits_declarations`, `replay_audits_clean_with_terse_docs`.
- Deps: P-21 (the benchmark decides the exact defaults), P-18. Parallel: no (touches the declaration trio, H-C). Risk: medium. ARCH: no.

**P-54 Fuzz-style robustness tests (no new crates): journal reader, HTML extractor, sanitiser, config and policy parsers**
- Why: hardening. A tiny seeded xorshift generator and byte-mutation helpers in `harness-testkit` (deterministic, no `rand`), used to feed mutated/truncated/garbage input to every parser of untrusted bytes and assert: no panic, no hang (iteration and size bounded), and either a clean typed error or a value that round-trips. Seeds are fixed so failures reproduce; the case count is modest in gates (e.g. 2000 per target) and larger under an ignored `RH_FUZZ_CASES` test.
- Crates: harness-testkit (mutator), tests in harness-journal (reader/verifier), harness-core (html, display sanitiser, config), harness-policy (policy file parser), harness-manifest (manifest parser).
- Tests: `fuzz_journal_reader_mutated_valid_log_never_panics`, `fuzz_journal_truncation_at_every_byte_is_typed_error`, `fuzz_html_extractor_never_panics_and_is_bounded`, `fuzz_sanitiser_output_has_no_control_chars`, `fuzz_policy_parser_never_panics`, `fuzz_manifest_parser_never_panics`, `fuzz_config_parser_never_panics`, `mutator_is_deterministic_for_a_seed`.
- Deps: P-03, P-44. Parallel: yes. Risk: low. ARCH: no.

**P-55 Fuzz-style tests for the Mach-O/ELF dependency parser (P-51) and the patch parser (P-25)**
- Why: those parsers read untrusted-ish binary and text input. Same mutator as P-54. Split in two commits so the patch half can follow P-25.
- Crates: the parser crates' tests only.
- Tests: `fuzz_macho_parser_never_panics`, `fuzz_macho_truncation_at_every_byte_is_typed_error`, `fuzz_elf_parser_never_panics`, `fuzz_macho_bounds_hold_on_cyclic_dependency_fixture`, `fuzz_patch_parser_never_panics` (only when P-25 is merged), `fuzz_patch_parser_bounded_on_huge_hunk_counts`.
- Deps: P-51, P-54. Parallel: yes. Risk: low. ARCH: no.

**P-56 ARCH: Linux sandbox backend (Landlock + seccomp) and the Linux conformance suite**
- Design note first (reasoning model): raw-syscall Landlock ruleset + seccomp-bpf filter built in `harness-sandbox` (`unsafe` stays confined there; no new crate if at all possible, else a written reason), mapping from the existing confinement spec to Landlock rights, network deny by default, a witness/probe at startup like Seatbelt (fail closed: if the witness does not pass, exec refuses as today), the conformance suite re-used, and how it is verified when the dev machine is macOS (cross-`cargo check --target x86_64-unknown-linux-gnu`, runtime tests skipped with a stated reason, an explicit "UNVERIFIED on real Linux" status in `docs/STATUS.md` until someone runs the suite on Linux). Split into slices by the note.
- Crates (expected): harness-sandbox.
- Deps: P-41 (probe robustness). Risk: high. ARCH: **yes**.

**P-57 Windows spike S-W1: read/edit only**
- Why: make the workspace build for `x86_64-pc-windows-msvc` (cross `cargo check`) with exec refused ("no confinement on this platform", same fail-closed message as Linux today), read/edit/search/outline tools working, path handling (drive letters, `\\?\`, case-insensitivity, reserved names, UNC paths refused) in the policy path matcher, and `doctor` reporting it. No exec on Windows until a conformance suite passes there.
- Crates: harness-core/policy (path handling), harness-sandbox (cfg stubs), harness-cli.
- Tests: `windows_path_normalisation_cases` (pure, runs everywhere), `unc_and_device_paths_refused`, `reserved_names_refused`, `exec_refuses_without_confinement_on_windows` (cfg), plus a CI-script-free cross check recorded in the slice note.
- Deps: P-11. Parallel: yes (policy path module only). Risk: medium. ARCH: no.

**P-58 Docs: user guide, `--help` completeness, version and changelog**
- Why: definition of done. `docs/USER-GUIDE.md` (install, 5-minute quickstart for a local model and for a hosted one through the loopback proxy, `profile init`, `doctor`, `chat`, `run`, `replay`, `sessions`, `schedule`, policy file format, profiles, workspace modes, the security model in plain words, limits), every verb's `--help` text complete and covered by a test that every dispatch verb has usage text, `CHANGELOG.md`, version bump to 0.2.0 in the workspace manifest. Scheduled late (after the interactive features it documents).
- Crates: harness-cli (usage text and its test), docs.
- Tests: `every_dispatch_verb_has_usage_text`, `help_for_each_verb_exits_zero`, `usage_mentions_every_flag_of_chat_and_run`, `readme_quickstart_commands_exist_as_verbs`.
- Deps: P-23, P-26, P-28, P-31. Parallel: yes. Risk: low. ARCH: no.

**P-59 Minibench: profile files, both protocols, journal audit, regression gate against a recorded baseline**
- Why: P-21b's `harness-minibench` only builds `Profile::conservative_default` from `--model`, so it cannot run the text and native protocols or the recorded profiles (`devkit/glm/profiles`, `devkit/local/profiles`), cannot audit what it produced, and has no regression check. Add: `--profile FILE` (a profile JSON, strict-validated, the TSV's `profile_sha` is that profile's `content_sha256`), `--only NAME[,NAME]` filter, `--keep DIR` (copy every run's journal there) and `--audit` (after each run, `audit_batch`/`audit_session` over the produced journal must report no divergence and an anchored chain head; otherwise the row is marked `audit_fail` and the exit code is non-zero), `--baseline FILE` (a recorded TSV; exit non-zero if a task that passed in the baseline now fails, or steps grew by more than 50% and by at least 3, rows with a different harness version are compared but flagged), `--repeat N` (rows are per attempt; a task passes the gate when it passes in a majority). A recorded results directory `docs/bench/` holds `<date>-<model>-<protocol>.tsv` plus a short `README.md` table. The scripted self-test grows: `minibench_audit_flag_passes_on_scripted_run`, `minibench_baseline_regression_detected`.
- Crates: harness-minibench (+ `harness-testkit` if a helper is needed).
- Tests: `profile_file_sets_profile_sha_in_row`, `invalid_profile_file_refused`, `only_filter_runs_named_fixtures`, `audit_flag_marks_divergence_as_audit_fail` (a doctored journal copy), `baseline_regression_on_newly_failing_task`, `baseline_step_growth_flagged`, `baseline_other_harness_version_flagged_not_failed`, `repeat_majority_rule`, `keep_dir_receives_every_journal`.
- Deps: P-21. Parallel: yes. Risk: low. ARCH: no.

---

### P-39 slices (from the approved web airlock design, `docs/slices/P-39-web-airlock.md` section 11)

Owner approved the airlock and the opt-in `net` feature on 2 Oct. Each card below is a pointer: the spec, schemas, named tests and file lists are in the design note's section 11 row of the same name and in the sections that row cites. Implement exactly that row, with every named test.

**P-39a Pure foundations (url, ipclass, robots, b64, http1, fetchproto, content)**
- Spec: `docs/slices/P-39-web-airlock.md` section 11, row P-39a, plus the sections it cites (read the whole note first: sections 0, 2.1, 4, 5, 7, 9).
- Tests: all the named tests in that row; hostile classes in section 7.
- Rules: pure crates stay pure; default build and root Cargo.lock must contain no TLS crate (purity gate); nothing in this slice opens a network connection outside the dialer; every egress is journaled before it happens.

**P-39b Research policy and manifest (SessionKind, allowlist, hop decisions, web tool manifests)**
- Spec: `docs/slices/P-39-web-airlock.md` section 11, row P-39b, plus the sections it cites (read the whole note first: sections 0, 2.1, 4, 5, 7, 9).
- Tests: all the named tests in that row; hostile classes in section 7.
- Rules: pure crates stay pure; default build and root Cargo.lock must contain no TLS crate (purity gate); nothing in this slice opens a network connection outside the dialer; every egress is journaled before it happens.

**P-39c Journal: Egress and EgressDone, ImportedResearch, Source::Research**
- Spec: `docs/slices/P-39-web-airlock.md` section 11, row P-39c, plus the sections it cites (read the whole note first: sections 0, 2.1, 4, 5, 7, 9).
- Tests: all the named tests in that row; hostile classes in section 7.
- Rules: pure crates stay pure; default build and root Cargo.lock must contain no TLS crate (purity gate); nothing in this slice opens a network connection outside the dialer; every egress is journaled before it happens.

**P-39d Streaming confined stdio primitive (shared with P-37) and conformance cases**
- Spec: `docs/slices/P-39-web-airlock.md` section 11, row P-39d, plus the sections it cites (read the whole note first: sections 0, 2.1, 4, 5, 7, 9).
- Tests: all the named tests in that row; hostile classes in section 7.
- Rules: pure crates stay pure; default build and root Cargo.lock must contain no TLS crate (purity gate); nothing in this slice opens a network connection outside the dialer; every egress is journaled before it happens.

**P-39e Egress dialer (resolve, check, pin, tunnel; feature net, TLS-free)**
- Spec: `docs/slices/P-39-web-airlock.md` section 11, row P-39e, plus the sections it cites (read the whole note first: sections 0, 2.1, 4, 5, 7, 9).
- Tests: all the named tests in that row; hostile classes in section 7.
- Rules: pure crates stay pure; default build and root Cargo.lock must contain no TLS crate (purity gate); nothing in this slice opens a network connection outside the dialer; every egress is journaled before it happens.

**P-39f Fetcher workspace fetch/ and the TLS-free build proof (needs OD-W1/OD-W2)**
- Spec: `docs/slices/P-39-web-airlock.md` section 11, row P-39f, plus the sections it cites (read the whole note first: sections 0, 2.1, 4, 5, 7, 9).
- Tests: all the named tests in that row; hostile classes in section 7.
- Rules: pure crates stay pure; default build and root Cargo.lock must contain no TLS crate (purity gate); nothing in this slice opens a network connection outside the dialer; every egress is journaled before it happens.

**P-39g Web provider (hops, redirects, caps, ScriptedWeb/RecordedWeb/LiveWeb, note saving)**
- Spec: `docs/slices/P-39-web-airlock.md` section 11, row P-39g, plus the sections it cites (read the whole note first: sections 0, 2.1, 4, 5, 7, 9).
- Tests: all the named tests in that row; hostile classes in section 7.
- Rules: pure crates stay pure; default build and root Cargo.lock must contain no TLS crate (purity gate); nothing in this slice opens a network connection outside the dialer; every egress is journaled before it happens.

**P-39h Research session type (header, context, /allow-host rule)**
- Spec: `docs/slices/P-39-web-airlock.md` section 11, row P-39h, plus the sections it cites (read the whole note first: sections 0, 2.1, 4, 5, 7, 9).
- Tests: all the named tests in that row; hostile classes in section 7.
- Rules: pure crates stay pure; default build and root Cargo.lock must contain no TLS crate (purity gate); nothing in this slice opens a network connection outside the dialer; every egress is journaled before it happens.

**P-39i Quarantine store and verified import**
- Spec: `docs/slices/P-39-web-airlock.md` section 11, row P-39i, plus the sections it cites (read the whole note first: sections 0, 2.1, 4, 5, 7, 9).
- Tests: all the named tests in that row; hostile classes in section 7.
- Rules: pure crates stay pure; default build and root Cargo.lock must contain no TLS crate (purity gate); nothing in this slice opens a network connection outside the dialer; every egress is journaled before it happens.

**P-39j CLI: research, hosts, import-research, net status/install-fetcher**
- Spec: `docs/slices/P-39-web-airlock.md` section 11, row P-39j, plus the sections it cites (read the whole note first: sections 0, 2.1, 4, 5, 7, 9).
- Tests: all the named tests in that row; hostile classes in section 7.
- Rules: pure crates stay pure; default build and root Cargo.lock must contain no TLS crate (purity gate); nothing in this slice opens a network connection outside the dialer; every egress is journaled before it happens.

**P-39k Hostile suite and eval row for web research**
- Spec: `docs/slices/P-39-web-airlock.md` section 11, row P-39k, plus the sections it cites (read the whole note first: sections 0, 2.1, 4, 5, 7, 9).
- Tests: all the named tests in that row; hostile classes in section 7.
- Rules: pure crates stay pure; default build and root Cargo.lock must contain no TLS crate (purity gate); nothing in this slice opens a network connection outside the dialer; every egress is journaled before it happens.


---

### Split cards from the P-38 design note

Scheduling note: the roadmap card listed P-33 as a dependency; this design does not touch the context builder
(no `rh-context` bump, no hint text), so P-33 is not needed. The loop-touching slices (P-38d, P-38e, P-38f) are
serial with each other and with every other loop slice (hotspot H-B), so they depend on the end of the W5/W6
driver chain (P-23, P-26, P-27, P-28) as a scheduling dependency, not a technical one.

**P-38a Delegate capability: manifest fragment, policy registration, `plan_child`**
- Why: the tool exists only as declared, labelled and planned data before any loop code (design note §1, §9, §11). Add `builtin/task_delegate.rs` (read / operational / own / none, content `third_party`, schema `{task: string ≤ 2000}`), insert before the sentinel, re-pin the built-in manifest digest; `DELEGATE_ID`, `ToolKind::Delegate` (needs a workspace), `is_builtin_delegate`, `CHILD_ELIGIBLE`, `Active.delegate`; `SessionRefused::DelegateScope` in `plan_with` and `Session::plan_child` with `SessionRefused::ChildScope`.
- Crates: harness-manifest, harness-policy.
- Tests: `delegate_manifest_fragment_has_read_labels`, `builtin_manifest_bytes_unchanged` (new pinned digest), `builtin_registry_lists_delegate_before_submit`, `delegate_denied_without_grant`, `delegate_allowed_by_default_read_rule_when_granted`, `delegate_refused_without_workspace`, `delegate_args_schema_refuses_extra_field_and_long_task`, `delegate_refused_when_child_scope_more_sensitive` (fixture via `plan_with`), `plan_child_refuses_delegate_grant`, `plan_child_refuses_edit_and_exec`, `plan_child_accepts_fs_and_submit`, `user_deny_rule_on_delegate_wins`.
- Deps: P-02, P-24. Parallel: yes (manifest/policy only; not with another slice that adds a built-in tool). Risk: low-medium (manifest digest drift is intended and pinned). ARCH: no.

**P-38b Budget carve and child spend in the meter**
- Why: deterministic carving and absorption are pure and are the budget guarantee (note §5). `Carve`, `carve()`, the constants, `ChildSpend::{measured, recorded}`, `Meter::absorb_child`; purity gate confines `ChildSpend::recorded` to harness-run's driver and replay like `Meter::new_resumed`.
- Crates: harness-core, scripts/ci (purity.sh only).
- Tests: `carve_halves_remaining_and_caps`, `carve_keeps_one_parent_step`, `carve_refuses_below_step_minimum`, `carve_refuses_below_token_minimum`, `carve_wall_never_refuses`, `carve_is_deterministic`, `absorb_child_charges_steps_tokens_wall_and_cost`, `absorb_child_latches_typed_cause`, `absorb_child_marks_estimated_tokens`, `child_spend_measured_reads_the_child_meter`, purity selftest case `child_spend_recorded_outside_driver_refused`.
- Deps: none. Parallel: yes (pure crate). Risk: low. ARCH: no.

**P-38c Approval origin label and `LabelledApprover`**
- Why: an ask inside a helper must reach the parent's approver and say where it comes from (note §8). `Origin`, `ApprovalRequest::with_origin`, origin as the first display line (trusted ids and numbers only), unchanged display without one; `LabelledApprover` in `approve.rs` forwarding kind, deadline and answer.
- Crates: harness-policy (approval.rs), harness-run (approve.rs only).
- Tests: `approval_request_origin_line_first`, `approval_request_without_origin_display_unchanged` (golden), `origin_line_contains_only_ids_and_numbers`, `labelled_approver_forwards_kind_answer_and_deadline`, `labelled_approver_no_answer_is_deny`.
- Deps: P-23 (same files: approval display and approver). Parallel: yes with P-38a/P-38b; not with another slice editing `approval.rs`. Risk: low. ARCH: no.

**P-38d Child run construction: template, brief, child spec, header link**
- Why: the child must be a normal batch run with a fixed prompt and a verifiable link before the loop calls it (note §2, §3). New `harness-run/src/delegate.rs`: `CHILD_TEMPLATE` and its pinned digest, `child_task_text` (strip invisibles, nonce redrawn until absent, nonce seeded as drawn), `child_spec` (eligible grants ∩ parent, cut to the tool cap, submit), `ChildCtx`, `run_child` (plan_child, create_run, header with `mode: child`, `parent`, `child`, inherited facts, `Loop::drive`, commit); `prepare` refusals (delegate without an fs grant, budget under 4096 tokens); `HEADER_INPUT_KEYS` 18 and `header_mismatch` arms; batch/session audit and resume refuse a child journal at `mode`.
- Crates: harness-run.
- Tests: `child_template_digest_pinned`, `child_task_text_delimits_brief_with_nonce`, `child_brief_containing_nonce_gets_new_nonce`, `child_brief_invisibles_stripped`, `child_spec_grants_are_parent_fs_grants_plus_submit`, `child_spec_cut_to_tool_cap_in_priority_order`, `run_child_scripted_submit_returns_note_and_head`, `child_header_records_parent_link_template_and_limits`, `child_inherits_parent_tree_without_walk`, `child_journal_in_its_own_run_dir`, `delegate_without_fs_grant_refused_before_start`, `delegate_with_tiny_profile_refused_before_start`, `batch_audit_refuses_child_journal_by_mode`, `batch_header_unchanged_without_delegate`, `session_header_unchanged_without_delegate`.
- Deps: P-38a, P-38b, P-38c, P-17, P-26, P-27, P-28. Parallel: no (driver plan/header; loop chain H-B). Risk: medium. ARCH: no.

**P-38e Delegate step in the loop: admission, child run, `ChildRun`, report, absorb**
- Why: the feature itself (note §4-§7, §10, §12). The `DELEGATE_ID` branch in `step_inner` beside the todo branch: pure admission (cap, brief size, plan_child, carve) with `DELEGATE_REFUSED`; parent wall paused; `run_child`; `ChildRun` (fsynced) then `ToolFinished` with the framed, capped report or `DELEGATE_NO_REPORT` / `DELEGATE_NOT_STARTED`; child journal failure stops the parent `JournalUnavailable`; `absorb_child` at step 10; `run()` and `run_session()` set `ChildCtx{live: true}`; carve base includes the turn allowance in a session; error codes 25-27 in harness-tools.
- Crates: harness-run, harness-tools (codes only).
- Tests: `delegate_child_cannot_edit`, `delegate_budget_carved_from_parent`, `delegate_child_usage_absorbed_into_parent_meter`, `delegate_parent_wall_excludes_child_approval_wait`, `delegate_result_untrusted_and_bounded`, `delegate_result_huge_is_cut_with_marker`, `delegate_result_with_parent_nonce_withheld`, `delegate_result_action_block_never_parsed`, `delegate_child_loop_returns_no_report_error`, `delegate_refused_when_carve_too_small`, `delegate_cap_per_run`, `delegate_depth_limit`, `delegate_child_journal_failure_stops_parent_unreadable`, `delegate_child_not_started_is_observation`, `delegate_approval_in_child_routed_with_origin`, `delegate_without_approver_child_ask_denied`, `delegate_in_session_turn_goes_on`, `delegate_runs_child_synchronously_one_request_at_a_time`, `child_labels_subset_of_parent`.
- Deps: P-38d. Parallel: no (loop, H-B). Risk: high (the loop; assign the stronger cheap model and a reviewer pass). ARCH: no.

**P-38f Audit and resume with children**
- Why: no feature ships unreplayable (note §14, §10). `recorded()` maps `ChildRun` to `RecordedChild` and refuses it in a child journal; the replayed step recomputes admission and carve, writes `ChildRun` from re-fed and recomputed fields, absorbs `ChildSpend::recorded`; `Audit.children` (`Verify` default) and `AuditReport.children`; per-child audit: head = `ChildRun.chain_head`, header link and fields, child batch audit, stop/result/report/spend cross-checks; missing child = divergence; resume catch-up never starts a child, a trailing delegate intent starts a new one.
- Crates: harness-run (replay/*).
- Tests: `delegate_child_journal_audits_clean_and_linked`, `session_audit_with_delegate_clean`, `audit_recomputes_delegate_refusal`, `audit_detects_forged_carve_limits`, `audit_detects_child_journal_replaced`, `audit_detects_missing_child_journal`, `audit_detects_child_result_swapped`, `audit_detects_child_spend_understated`, `audit_detects_child_linked_to_other_parent`, `audit_detects_child_wall_exceeding_elapsed`, `audit_refuses_child_run_record_in_child_journal`, `audit_children_skip_reports_parent_only`, `resume_refeeds_completed_delegate_without_rerun`, `resume_reruns_interrupted_delegate_with_new_child`, `resume_after_childrun_without_toolfinished_starts_new_child`.
- Deps: P-38e. Parallel: no (replay, H-B). Risk: high. ARCH: no.

**P-38g CLI: replay of children, sessions listing, chat lines**
- Why: users must see and verify helpers (note §7, §8, §14). `replay` prints one line per child audit (id, anchored, divergence) and fails when any child fails; `sessions` hides child runs by default and shows `child of <run>@<step>` with `--all`; `chat` prints `[helper] started (run <id>, <n> steps)` from the delegate's `ToolStarted` and the report line from its `ToolFinished`; approval prompts show the origin line (from P-38c, no new code); usage footer includes `ChildRun.spent`.
- Crates: harness-cli, harness-journal (header field read in `scan_runs`).
- Tests: `cli_replay_audits_children_and_reports_them`, `cli_replay_fails_when_child_tampered`, `sessions_hides_child_runs_by_default`, `sessions_all_shows_child_with_parent_link`, `chat_shows_helper_start_and_report_lines`, `approval_prompt_shows_helper_origin`, `usage_footer_includes_child_spend`.
- Deps: P-38f, P-14, P-15, P-18. Parallel: yes (cli files; one line in each verb). Risk: low-medium. ARCH: no.

**P-38h Hostile delegation suite (tests only)**
- Why: prove delegation weakens nothing (note §15, §17).
- Crates: tests in harness-run (`tests/hostile_delegate.rs`), harness-cli (`tests/hostile_chat.rs`).
- Tests: `hostile_delegate_report_with_action_block_is_data`, `hostile_delegate_report_with_parent_nonce_withheld`, `hostile_delegate_report_with_fake_harness_notice_stays_delimited`, `hostile_delegate_report_ansi_and_bidi_stripped`, `hostile_delegate_brief_injection_cannot_grant_tools`, `hostile_delegate_child_denied_dot_env`, `hostile_delegate_child_tries_delegate`, `hostile_delegate_child_loops_until_carve`, `hostile_delegate_cannot_amplify_budget`, `hostile_delegate_repeat_same_brief_stops_parent`, `hostile_delegate_cap_reached_refused`, `hostile_delegate_child_journal_rechained_detected`, `hostile_delegate_child_spend_understated_detected`, `hostile_delegate_child_swapped_between_two_calls_detected`, `hostile_delegate_approval_token_not_reusable_across_runs`, `hostile_delegate_crash_mid_child_resume_new_child`, `hostile_delegate_report_cannot_paint_terminal`.
- Deps: P-38f, P-19. Parallel: yes (tests only, new files). Risk: low. ARCH: no.

**P-38i Live smoke and docs for delegation**
- Why: scripted tests cannot show whether a small model uses delegation well (note §20, OQ-4). An `#[ignore]`d live test (env `RUSTYHARNESS_EXIT_ENDPOINT/MODEL`, as `exit_h1.rs`): a fixture repo question answered with and without the delegate grant, both anchored and audited with children; record steps, tokens and success in the slice note. README "Try it" gains the grant and its limits; the design doc consolidation row for P-38.
- Crates: harness-cli (tests), docs.
- Tests: `live_delegate_answers_fixture_question_and_audits` (ignored), `live_delegate_vs_inline_usage_recorded` (ignored), `readme_mentions_delegate_grant_limits` (doc test over README text).
- Deps: P-38g, P-21. Parallel: yes. Risk: low. ARCH: no.

---

### Split cards from the P-37 design note

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

---

### Split cards from the P-36 design note

Order: P-36a → P-36b → P-36d → P-36l is the serial sandbox/pin chain. P-36c, P-36e, P-36g, P-36h can run
beside it. P-36f, P-36i, P-36j, P-36k are the tools and loop chain (P-36j and P-36k touch the driver
hotspot H-B: never parallel with another loop slice). P-36m and P-36n close.

**P-36a Ports conformance first: `Network::Loopback`, Seatbelt port rules, live port probe**
- Why: §4.3, §4.4, §12. Measure what SBPL can express before anything uses it. `spec.rs`: `Network::Loopback{bind, connect, lan}`, `Context.reserved_ports`, validation (≥1024, not reserved, lan ⊆ bind, ≤4 binds); `profile.rs`: rules after `(deny network*)` plus the final reserved-port deny, `Network::None` byte-identical; `seatbelt.rs`: `probe_ports` and `PortsWitness`; `conformance.rs`: the `PORTS_CASES` variants, added to the macOS row only if every test passes here (else the slice note records the measurement and ports stay refused). Records whether `localhost` covers `::1` and whether `/private/etc/hosts` must be readable.
- Crates: harness-sandbox (`spec.rs`, `profile.rs`, `seatbelt.rs`, `conformance.rs`, new `tests/conformance_ports_macos.rs`). Not `confine_spawn.rs`.
- Tests: `ft_ports_bind_granted_loopback_port_is_allowed`, `ft_ports_bind_ungranted_port_is_refused`, `ft_ports_bind_wildcard_address_is_refused_without_lan`, `ft_ports_bind_wildcard_address_is_allowed_with_lan_grant`, `ft_ports_connect_to_granted_port_is_allowed`, `ft_ports_connect_to_ungranted_loopback_port_is_refused`, `ft_ports_connect_to_model_server_port_is_refused`, `ft_ports_outbound_routable_unix_and_dns_still_refused`, `ft_ports_udp_bind_refused`, `validate_refuses_port_below_1024_and_reserved`, `validate_refuses_lan_not_subset_of_bind`, `render_puts_port_allows_after_network_deny_and_reserved_deny_last`, `network_none_profile_unchanged_byte_for_byte`, `probe_ports_refuses_when_an_ungranted_bind_succeeds` (injected observation), existing conformance suite unchanged.
- Deps: P-41, P-29. Parallel: no (sandbox chain head; profile/spec are shared with P-36b). Risk: high (security boundary; UNVERIFIED SBPL syntax). ARCH: no.

**P-36b Live confined child: ring buffer, cursors, deadline closer (pin change)**
- Why: §4.2, §5.3. `ConfinedChild::{try_status, read, totals, stop}`, `Confinement::spawn_live(spec, ev, LiveOpts)`, `Ring` (circular buffer, monotonic total, running SHA-256, 4 KiB tail for the report), the pure window fn of §3.2 (backend-neutral module so the Linux backend reuses it), report stripping on reads after exit, the lifetime closer thread. `wait()` byte-identical for exec.run. The stub text is unchanged. Re-pin `confine_spawn_sha256` per §13.
- Crates: harness-sandbox (`confine_spawn.rs`, `lib.rs`, new `ring.rs`, new `tests/conformance_bg_macos.rs`), `scripts/ci/purity.sh`.
- Tests: `ring_cursor_arithmetic_next_and_tail`, `ring_drop_counts_overwritten_bytes`, `ring_stream_sha_covers_every_byte`, `read_strips_trailing_stub_report_after_exit`, `wait_api_unchanged_for_exec_run`, `ft_bg_long_lived_child_is_swept_on_stop`, `ft_bg_setsid_descendant_is_swept_on_stop`, `ft_bg_parent_sigkill_sweeps_the_domain` (re-execs the test binary), `ft_bg_lifetime_closer_stops_child_while_parent_blocks`, `ft_bg_output_flood_keeps_memory_bounded`, `ft_bg_fork_bomb_stopped_by_watchdog_other_children_unaffected`, `bg_soak_ten_minutes` (`#[ignore]`), purity + purity-selftest pass with the new pin.
- Deps: P-36a. Parallel: no (pinned spawn file, H-G). Risk: high. ARCH: no.

**P-36c `rh-fileop/1` codec (pure)**
- Why: §7.3. Request/response framing and error codes as a pure module, so the helper slice only adds the stub and the process. No I/O, no spawn.
- Crates: harness-sandbox (new `fileop/proto.rs`).
- Tests: `fileop_frame_round_trip_every_op`, `fileop_frame_refuses_oversize_item`, `fileop_frame_refuses_bad_count_and_non_decimal_length`, `fileop_response_error_codes_round_trip`, `fileop_path_must_be_workspace_relative_without_dot_components`, `fileop_codec_is_deterministic`.
- Deps: none. Parallel: yes (new file; not a pin slice). Risk: low. ARCH: no.

**P-36d Confined file-op helper: fork-less stub, profile, process (pin change + new pin)**
- Why: §7.1-7.3, owner decision 7. `fileop_stub.rs` (`FILEOP_STUB`, start canary, ops of §7.3 with core `Digest::SHA`, `O_NOFOLLOW`, link+unlink move, directory fsync), `Stub::{Domain, FileOp}` select in `confine_spawn.rs`, `profile::render_fileop` (no fork, exec perl only, workspace rw or ro), `harness_sandbox::fileop::FileOpHelper` (start, request with deadline, restart), `FILEOP_CASES` in the macOS row when green. New pin `fileop_stub_sha256` and re-pin of `confine_spawn_sha256` per §13, with the two new selftest cases.
- Crates: harness-sandbox (`fileop_stub.rs`, `fileop/mod.rs`, `confine_spawn.rs`, `profile.rs`, `conformance.rs`, new `tests/conformance_fileop_macos.rs`), `scripts/ci/purity.sh`, `scripts/ci/purity-selftest.sh`.
- Tests: `fileop_helper_reads_and_writes_inside_workspace`, `fileop_symlink_to_outside_is_refused_by_the_kernel`, `fileop_symlink_swap_race_never_reaches_outside` (2000 iterations against a confined swapper), `fileop_fifo_is_refused_fast`, `fileop_protected_path_write_refused`, `fileop_helper_cannot_fork`, `fileop_hard_link_from_outside_refused`, `fileop_replace_refuses_changed_expect_sha`, `fileop_move_never_overwrites`, `fileop_readonly_profile_refuses_every_write`, `fileop_request_timeout_kills_and_restarts_helper`, `fileop_stub_refuses_to_start_unconfined`, purity selftest `fileop stub changed without re-pin`, `a fork added to the fileop stub`.
- Deps: P-36b, P-36c. Parallel: no (pinned files, H-G). Risk: high. ARCH: no.

**P-36e `FileOps` trait: built-in file tools behind one seam (no behaviour change)**
- Why: §7.4. Move every filesystem access of read/search/glob/list/outline/edit (replace, write, multi, and patch/delete/move from P-25) and `workspace_tree` behind `trait FileOps` with an `InProcess` impl holding today's code; results, digests and errors byte-identical.
- Crates: harness-tools.
- Tests: all existing `cargo test -p harness-tools` unchanged, `file_ops_in_process_results_byte_identical` (golden over a fixture tree: every tool's output digest before = after), `tool_modules_touch_fs_only_through_file_ops` (source scan test: no `std::fs` outside `file_ops/in_process.rs` and the scratch setup).
- Deps: P-22, P-25. Parallel: yes with the sandbox chain (different crate); not with other harness-tools edit slices. Risk: medium (large mechanical move). ARCH: no.

**P-36f Route file tools through the helper in runs that execute**
- Why: §7.4-7.5, INV-42. `Confined(FileOpHelper)` impl of `FileOps`; `workspace_tree` via the `tree` op; planning starts the helper after the witness for any execute-class grant (refuses the run if it cannot start); header `file_ops`; bounded restarts then `SandboxLost`; the helper's `tree` digest must equal the in-process one. Records the measured cost in the slice note.
- Crates: harness-tools (`file_ops/confined.rs`), harness-run (planning, header, stop on helper loss).
- Tests: `run_with_exec_grant_uses_confined_file_ops`, `run_without_exec_grant_stays_in_process`, `header_records_file_ops_mode_and_stub_digest`, `old_header_digest_unchanged_without_file_ops`, `helper_tree_digest_equals_in_process_digest`, `helper_start_failure_refuses_the_run`, `helper_lost_three_times_stops_sandbox_lost`, `hanging_file_op_ends_in_tool_timeout_within_wall`, `edit_through_helper_audits_clean`.
- Deps: P-36d, P-36e, P-13. Parallel: no with other driver slices (planning/header). Risk: medium-high. ARCH: no.

**P-36g Bg tools in manifest and policy; port and LAN grants**
- Why: §3, §6.1, §6.3, §9. Manifest fragments and policy registration for `harness.exec.start/read/stop` with defaults (`ask.exec.default`, `allow.exec.bg-read`, `allow.exec.bg-stop`), the LAN floor rule `ask.exec.lan-bind` (protected_action), the trifecta E label from `lan_ports`, task-file `exec.ports`/`exec.lan_ports` parse and checks, CLI `--allow-port`, `--allow-lan-port`, `--bg-persist`, model port derived from the endpoint, `reserved_ports` in the library API.
- Crates: harness-manifest, harness-policy, harness-cli (`inputs.rs`, `args.rs`).
- Tests: `builtin_manifest_lists_bg_tools`, `policy_default_start_asks_read_and_stop_allow`, `lan_port_start_asks_every_time_protected_action`, `lan_ports_label_egress_for_trifecta`, `lan_ports_allowed_with_public_workspace_and_ask`, `session_grant_never_covers_lan_start`, `port_grant_refuses_model_server_port`, `port_grant_refuses_below_1024_and_duplicates`, `port_grant_library_requires_reserved_ports_with_loopback_endpoint`, `task_file_ports_parse_and_header_digest`, `old_task_file_digest_unchanged`, `bg_grant_without_exec_setup_refused`.
- Deps: P-02, P-08, P-11, P-23. Parallel: yes (manifest/policy/cli; no sandbox, no driver). Risk: medium (trust root). ARCH: no.

**P-36h Journal: `BgStopped`, `OrphanCheck`, the `bg` record**
- Why: §10. Two new kinds in `canon.rs`/`event.rs` (fsynced), canonical bodies; `bg_fields`/`parse_bg` beside `exec_fields`/`parse_exec`; `connect` in the exec record only when non-empty; header `bg`/`ports`/`file_ops` objects absent when unused.
- Crates: harness-journal, harness-run (`driver/tools.rs` record fns only).
- Tests: `bg_stopped_and_orphan_check_kinds_round_trip_canonical`, `unknown_kind_still_refused`, `tool_finished_bg_record_round_trip_every_op`, `exec_record_connect_absent_when_empty_digest_unchanged`, `old_journal_still_reads`.
- Deps: P-10. Parallel: yes (journal + one record module). Risk: low-medium. ARCH: no.

**P-36i `BgTools` provider: start, read, stop**
- Why: §3, §6.2. `harness-tools::bg`: `BgManager` (ids, live map, port holdings, host port check, limits, cursors per stream, `ready` wait, rendering with dropped/skipped markers, `poll()`), the `BgTools` `ToolProvider` serving the three ids through `spawn_live`; exec.run gets `connect` = ports of live ids; refuses unless `file_ops` is the helper.
- Crates: harness-tools (new `bg.rs`, `exec.rs` connect field), harness-sandbox (use only).
- Tests: `bg_start_returns_sequential_ids`, `bg_start_refuses_program_not_on_allowlist`, `bg_start_refuses_ungranted_or_held_port`, `bg_start_refuses_over_max_live_and_max_starts`, `bg_start_refuses_when_port_busy_on_host`, `bg_read_next_and_tail_modes_cursor_arithmetic`, `bg_read_reports_dropped_after_ring_overrun`, `bg_read_wait_returns_on_new_output_or_exit`, `bg_read_without_id_lists_all`, `bg_stop_sweeps_and_returns_final_output`, `bg_read_of_unknown_or_stopped_id_refused`, `bg_ready_port_waits_for_listener`, `exec_run_gets_connect_ports_of_live_bg`, `bg_requires_confined_file_ops`.
- Deps: P-36b, P-36f, P-36g, P-36h. Parallel: no with other harness-tools exec slices. Risk: medium-high. ARCH: no.

**P-36j Driver: kill at every stop, step-boundary poll, planning checks**
- Why: §5.1, §5.2, §9, INV-40/41. Wire `BgTools` into the run and session loops: poll at each step start and before each start decision (journal `BgStopped{exited|lifetime}`), stop-all before `TurnEnded` (turn scope), `InputEnded`, `RunStopped` for every cause, `SandboxLost` cascade, `Drop` backstop on early return, planning refusals (witness sets, port probe, helper, scope), tree measured after the stop-all.
- Crates: harness-run (driver, session; H-B chain).
- Tests: `bg_process_killed_on_run_end`, `bg_process_killed_on_stop_by_budget`, `bg_turn_scoped_killed_at_turn_end`, `bg_session_scoped_survives_turn_and_dies_at_session_end`, `bg_session_scope_refused_without_persist_flag`, `bg_exit_observed_and_journaled_at_step_boundary`, `bg_lifetime_expiry_journaled`, `bg_unconfirmed_stop_stops_run_sandbox_lost_after_stopping_others`, `bg_killed_when_run_returns_early_on_journal_failure`, `bg_refused_when_witness_lacks_bg_or_ports_cases`, `bind_to_model_server_port_refused`, `bind_ungranted_port_refused`, `lan_bind_requires_separate_grant`.
- Deps: P-36i, P-13. Parallel: no (driver hotspot H-B). Risk: high. ARCH: no.

**P-36k Audit and resume of runs with background processes**
- Why: §11, INV-40. Audit re-feeds bg results and `BgStopped`/`OrphanCheck`, recomputes ids, refusals, liveness, cursor arithmetic, `connect`, and the stop-before-end rule; resume runs the orphan check, journals `BgStopped` for ids the kept records leave live, and keeps the mid-turn tree rule.
- Crates: harness-run (`replay/audit.rs`, `replay/resume.rs`, `replay/feed.rs`).
- Tests: `bg_output_cursor_replayable`, `session_with_bg_audits_clean`, `audit_detects_edited_bg_cursor`, `audit_detects_missing_bg_stop_before_run_stopped`, `audit_recomputes_bg_refusals`, `audit_detects_read_reporting_running_after_stop`, `audit_detects_decreasing_stream_total`, `resume_after_crash_with_live_bg_records_stop_and_continues_at_boundary`, `resume_mid_turn_refused_when_bg_changed_tree`.
- Deps: P-36j, P-17. Parallel: no (replay chain). Risk: high. ARCH: no.

**P-36l Orphan markers, lease, next-start check (pin change)**
- Why: §5.4. Markers in `runs/<run>/bg/`; the stub's `lease` frame line with an inherited shared `flock` (re-pin `confine_spawn_sha256` per §13); the lease probe (confined perl by default, std `try_lock` if Q-P36-6 says bump); the next-start scan for `run`/`chat`/`resume`; `OrphanCheck` record; `RunRefused::OrphansSuspected`; `doctor --orphans` report and user-confirmed clear. No pid kill unless Q-P36-3 is answered yes.
- Crates: harness-sandbox (`confine_spawn.rs` stub lease, `seatbelt.rs` lease probe), harness-run (marker write/close, start scan), harness-cli (`cmd_doctor.rs`), `scripts/ci/purity.sh`.
- Tests: `orphan_marker_written_and_closed_on_confirmed_stop`, `lease_inherited_by_setsid_descendant`, `next_start_clear_markers_recorded`, `next_start_with_held_lease_refuses_bg_grant`, `next_start_with_busy_recorded_port_refuses_port_grant`, `orphan_check_journaled_in_new_run`, `task_without_bg_runs_with_orphan_warning`, `doctor_reports_and_clears_orphan_markers_only_on_confirmation`, purity + selftest pass with the new pin.
- Deps: P-36j, P-36d, P-43. Parallel: no (pinned spawn file, H-G). Risk: high. ARCH: no.

**P-36m Chat surface for background processes**
- Why: §6.3, Q-P36-2. Banner lists granted ports (loopback/LAN) and `--bg-persist`; prompt shows the running count; `/bg` lists and `/bg stop N` stops through the session API (a user-initiated stop is not a tool call: it is a `BgStopped{reason: "user"}` record, written between turns and re-fed by the audit as an input); LAN ask text in plain words; bg output shown sanitised (P-04).
- Crates: harness-cli (`repl.rs`, `render.rs`, `cmd_chat.rs`), harness-run (one `BgStopped` reason and its audit re-feed).
- Tests: `chat_banner_lists_granted_ports`, `chat_prompt_shows_running_bg_count`, `chat_slash_bg_lists_and_stops`, `chat_user_bg_stop_journaled_and_audited`, `chat_lan_ask_prompt_says_reachable_from_network`, `chat_bg_output_has_no_raw_escapes`.
- Deps: P-36j, P-36k, P-18. Parallel: yes with P-36l (cli vs sandbox; `cmd_doctor.rs` is P-36l's only cli file). Risk: low-medium. ARCH: no.

**P-36n Hostile suite for background processes and the helper (tests only)**
- Why: §14. The adversarial table end to end through `run`/`run_session` with a scripted model and a mock model server; every test asserts outcome, journal kinds and `assert_audit_clean` where the run commits.
- Crates: tests in harness-run (`tests/hostile_bg.rs`), harness-sandbox (re-exec helper for the SIGKILL case).
- Tests: `hostile_bg_fork_bomb_contained`, `hostile_bg_setsid_escape_swept`, `hostile_bg_member_kills_stub_stops_run_and_marks_orphan`, `hostile_bg_port_squat_ungranted_refused`, `hostile_bg_binds_wildcard_without_lan_refused`, `hostile_bg_connects_model_server_refused`, `hostile_bg_output_flood_bounded`, `hostile_bg_zombie_after_harness_sigkill_none_survive`, `hostile_bg_symlink_swap_vs_edit_never_escapes`, `hostile_bg_edits_read_file_forces_stale_read`, `hostile_bg_writes_dot_git_refused`, `hostile_bg_forged_stub_report_in_output_ignored`, `hostile_bg_nonce_in_output_withheld`, `hostile_bg_lifetime_while_model_blocks`.
- Deps: P-36k, P-36l. Parallel: yes (tests only, new files). Risk: low. ARCH: no.

---

### Split cards from the P-39 design note

Card fields are as in roadmap §4.3. All are wave 9, after this note is approved. Each one can be merged
alone with the gates green. The web code stays unreachable by users until P-39k. The default build
gains no TLS dependency until P-39n, the explicit `net` slice, and even after P-39n the default
feature set has none.

**P-39a Pure egress rules: URL parser, exact allowlist, address classes, redirect resolution**
- Why: §4.1, §4.2. Every later slice decides with these pure functions, and so does the audit.
  `harness-policy/src/web.rs`:
  - `parse_url(&str) -> Result<WebUrl, UrlRefused>`: strict; ASCII/`xn--` hosts; no userinfo;
    IP-literal shorthands refused; fragment dropped; ≤ 4096 bytes.
  - `Allowlist::load(&[String])`: exact `host`, `host:port`, `http://host[:port]`; `*`, wildcards,
    leading or trailing dots, single-label names, `localhost`, `.local`, `.internal`, `.localhost`,
    `.arpa` and non-global IP literals refused; ≤ 64 entries.
  - `classify(core::net::IpAddr) -> AddrClass`: the §4.2 table; IPv4-mapped and NAT64 classified by
    the embedded IPv4; 2002::/16 refused.
  - `classify_answer(&[IpAddr]) -> Result<IpAddr, AnswerRefused>`: any non-global address refuses;
    empty refuses; otherwise the first.
  - `resolve_location(&WebUrl, &str)`: RFC 3986 subset, re-parsed; https→http refused.

  Uses `core::net` only. Confirm the purity grep does not match it.
- Crates: harness-policy.
- Tests: `url_parser_refuses_userinfo_controls_and_shorthand_ipv4`, `url_fragment_dropped_and_target_verbatim`, `allowlist_refuses_star_and_wildcards`, `allowlist_refuses_localhost_single_label_and_private_literals`, `allowlist_matches_exact_scheme_host_port`, `classify_refuses_every_private_range` (table over every row of §4.2), `ipv4_mapped_and_nat64_classified_by_embedded_v4`, `mixed_answer_refused_and_empty_answer_refused`, `redirect_location_resolved_and_rechecked`, `https_to_http_downgrade_refused`, `port_outside_allowlist_refused`; `sh scripts/ci/purity.sh` passes.
- Deps: P-08. Parallel: yes (a new file plus one `mod` line in harness-policy). Risk: medium (security table; review the table against IANA special-purpose registries). ARCH: no.

**P-39b Research manifest and the research session kind in policy (no prompt per fetch)**
- Why: §2.1–§2.3, INV-42, INV-53.
  - harness-manifest: fragments `builtin/web_fetch.rs` and `builtin/web_search.rs`, labelled read /
    operational / own / internet / third_party / `none`, with schemas `{url ≤4096, start?≥1,
    lines? 1..400}` and `{query ≤256, max_results? 1..10}`. `research_manifest_json()` = head + web
    fetch + web search + task todo + task submit + tail (the todo and submit fragments reused byte for
    byte); `research_manifest()`.
  - harness-policy: `SessionKind {Coding, Research(WebGrant{allowlist, search: bool, confirmed})}` on
    `SessionSpec` (`Coding` is the default, so existing callers are unchanged). Plan rules (§2.2 item
    3): a research session has no workspace, no personal data, builtin-tier caps only, and a
    confirmation present; egress is planned only for the two web ids in `Research`; a user ask rule on
    a web id gives `OutOfScope`. A `decide` web branch before step 2: `Allow`
    `allow.web.session-allowlist` / `allow.web.search-endpoint`, or `Deny` `deny.web.*`; **never
    `Ask`**. Registration entries in `builtin.rs`.
- Crates: harness-manifest, harness-policy.
- Tests: `coding_manifest_bytes_unchanged` (the existing pin, untouched), `research_manifest_bytes_pinned`, `coding_registry_has_no_web_capability`, `web_session_refused_with_workspace_grant` (the research manifest plus a workspace gives the `Trifecta` refusal naming workspace/workspace/web), `research_session_refuses_fs_edit_exec_grants`, `research_session_with_personal_capability_refused_by_trifecta` (a test-only lookup through `plan_with`), `research_session_without_confirmation_refused`, `web_decisions_never_ask` (property over URL samples × approver present/absent), `ask_rule_on_web_capability_refuses_session`, `fetch_to_unlisted_host_denied_with_rule_id`, `search_query_bounds_enforced`, `egress_still_out_of_scope_in_coding_sessions`, `policy_default_table_unchanged`.
- Deps: P-39a, P-02. Parallel: yes with P-39c/d/e (no shared files). Risk: medium-high (trust root; the "floor met at session start" rule must be reviewed against INV-25). ARCH: no.

**P-39c Journal: `Egress` body, `NoteSaved` and `NoteImported` kinds, `Source::Web`**
- Why: §4.5, §6, §7.
  - `canon.rs`: the canonical field list for `Egress` (already a reserved name and already fsynced);
    two new kinds `NoteSaved` (`bytes, note, sources, turn`) and `NoteImported` (`bytes, confirm,
    note, path, sha256`), both fsynced, added to `KINDS` and `needs_fsync`. Hotspot H-E: done once
    here.
  - harness-core: `Source::Web(String)` (the URL), with canonical form `{"kind":"web","url":…}`
    escaped like other untrusted text.
  - `layout.rs`: `research_notes_dir(state_root)`.
- Crates: harness-journal, harness-core.
- Tests: `egress_body_round_trips_canonical`, `egress_body_with_extra_key_refused`, `egress_is_fsynced`, `note_kinds_round_trip_and_fsynced`, `unknown_kind_still_refused`, `source_web_escaped_in_journal`, `old_journal_still_reads`.
- Deps: P-10. Parallel: not with any other slice that edits `canon.rs` (P-37/P-38 if they add kinds); otherwise yes. Risk: low-medium. ARCH: no.

**P-39d `harness-fetch`: the HTTP-only fetcher crate and binary, and the frame codec**
- Why: §5.1, §5.2, INV-46, INV-48.
  - harness-core `fetch_frame.rs` (pure): the `rh-fetch/1` codec. Strict JSON header (≤ 16 KiB, via
    `strict_json`); `body_len` must equal the remaining bytes.
  - New workspace member `crates/harness-fetch` (lib plus bin `rustyharness-fetch`; dependencies
    harness-core and serde_json only):
    - `read_request` (strict);
    - `fetch_over<S: Read+Write>` (CONNECT with the token, then its own bounded HTTP/1.1 client:
      Content-Length, chunked, read-to-close, 1xx skip, identity only, smuggling shapes refused,
      redirects reported and never followed);
    - `main` (read `argv[1]`, connect to `127.0.0.1:proxy_port`, run `fetch_over`, write the frame,
      exit 0).

    No `net` feature yet: https requests return `error: tls_unavailable`.
  - Purity gate: an allowlist for harness-fetch's default tree.
- Crates: harness-fetch (new), harness-core, scripts/ci/purity.sh (plus Cargo.lock, H-F).
- Tests: `parses_content_length_body`, `parses_chunked_body_bounded`, `chunk_size_line_over_16_hex_refused`, `gzip_content_encoding_refused`, `content_length_and_chunked_together_refused`, `oversize_headers_refused`, `body_over_cap_truncated_and_marked`, `redirect_not_followed_location_reported`, `connect_token_sent_first`, `https_without_net_is_tls_unavailable`, `frame_round_trips`, `frame_with_short_or_long_body_refused`, `frame_duplicate_key_refused`, `garbage_response_is_typed_error_not_panic` (malformed corpus ≥ 20 cases); the purity gate passes with the new allowlist; the INV-24 TLS denylist still passes.
- Deps: none. Parallel: yes (new crate; Cargo.lock regenerated by `cargo update -w`). Risk: medium (a parser of hostile bytes; bounded, no unsafe). ARCH: no.

**P-39e Seatbelt `Network::Proxy{port}` and the airlock conformance cases**
- Why: §5.3, INV-44, INV-46.
  - `spec.rs`: `Network::Proxy { port: u16 }` (the unused `allowlist_id` goes away); `validate`
    accepts it with port ≠ 0, Seatbelt only.
  - `profile.rs`: `(allow network-outbound (remote ip "localhost:<port>"))` after `(deny network*)`.
    The **first step** is to confirm the SBPL spelling on this host. If none passes, keep refusing
    `Proxy` and report.
  - `conformance.rs`: cases FT-13p, FT-15p, FT-19, FT-20 and `AIRLOCK_CASES`, in
    `tests/conformance_macos.rs`.
  - Does **not** touch `confine_spawn.rs` or `capture.rs`: no purity pin moves.
- Crates: harness-sandbox.
- Tests: `proxy_profile_allows_only_the_granted_loopback_port` (render golden), `proxy_profile_keeps_deny_network_before_the_allow`, `proxy_port_zero_refused`, `proxy_refused_on_backends_without_support`; macOS conformance `ft13_proxy_direct_connect_refused`, `ft15_proxy_no_resolver`, `ft19_other_loopback_port_refused` (a planted listener stands in for the model server), `ft20_proxy_no_listen`, `granted_port_connects` (positive control), `ft17_ft18_hold_under_proxy_profile`.
- Deps: P-41. Parallel: not with P-36 (both edit `profile.rs` network rules); yes with the rest. Risk: high (sandbox profile; UNVERIFIED SBPL). ARCH: no.

**P-39f Harness-side pump, resolver and connectors (`harness-sandbox::egress`)**
- Why: §3 steps 1–4 and 6, §4.3, INV-43, INV-44, INV-48, INV-52.
  - `egress.rs`:
    - `Resolver` trait (`SystemResolver`: `ToSocketAddrs` on a helper thread with a 5 s deadline);
    - `Connector` trait (`DirectConnector`: `TcpStream::connect_timeout`, `#[cfg(feature = "net")]`
      only; `LoopbackConnector` for the search endpoint and user proxy, refuses any non-loopback
      address);
    - `EgressLog` trait (`append(&EgressRecord) -> Result<(), EgressLogError>`);
    - `open_hop(...)`: resolve, `classify_answer` (P-39a), **append `Egress` first** (Err → refuse,
      no connect), bind `127.0.0.1:0`, run the pump thread (exactly one connection; first line must
      be `CONNECT <expected host:port>` with the token, else 403 and close; then connect, `200`, relay
      with byte caps and deadline); return `HopIo{resolved, chosen, bytes_up, bytes_down, elapsed,
      ended}`.
  - Feature `net` on harness-sandbox (no new crates).
  - `gates.sh` gains clippy and tests with `-p harness-sandbox --features net`.
  - Test-only `RemapConnector` behind a dev-only feature, which the purity gate refuses on normal
    edges (the fault-injection pattern).
- Crates: harness-sandbox (+ dev-dep harness-fetch), scripts/ci/gates.sh, scripts/ci/purity.sh.
- Tests: `pump_journals_before_connect`, `egress_append_failure_refuses_hop` (the fixture sees zero connections), `egress_to_private_ip_refused_after_dns`, `mixed_dns_answer_refused`, `dns_rebinding_fixture_second_answer_never_used` (resolver call count 1), `dns_timeout_refuses_hop`, `wrong_token_refused`, `second_connect_refused`, `connect_target_mismatch_refused`, `pump_caps_bytes_and_time`, `loopback_connector_refuses_non_loopback`, `default_build_refuses_direct_mode` (without `net`), `remap_connector_not_on_a_normal_edge` (purity selftest plant).
- Deps: P-39a, P-39c, P-39d. Parallel: yes with P-39e (different files in harness-sandbox: `egress.rs` vs `spec.rs`/`profile.rs`; `lib.rs` gets one `mod` line, merge carefully). Risk: high (network code in the trust base). ARCH: no.

**P-39g `WebTools`: `harness.web.fetch` through the confined fetcher**
- Why: §3, §4.4, INV-45, INV-46, INV-47, INV-48.
  - `harness-tools/src/web.rs`, the `WebTools` provider (namespace `harness`, `serves` the
    `harness.web.*` verbs). Per hop:
    - write `req.json` to `<scratch>/web/<step>-<hop>/`;
    - `open_hop` (P-39f), using the `EgressLog` from `InvokeCtx.egress` (a new optional field in
      `provider.rs`; `None` means web calls are refused);
    - spawn the fetcher via `Confinement::spawn` with the §5.3 spec, using `HopRunner`
      (`ConfinedHopRunner` | test-only `InProcessHopRunner`);
    - `parse_frame`.

    Then the redirect chain (P-39a re-checks, ≤ 5); the content verdict (types `text/html`,
    `application/xhtml+xml`, `text/plain`, `text/markdown`, `application/json`; charsets utf-8,
    us-ascii, iso-8859-1, windows-1252; NUL sniff in the first 8 KiB); P-44 `to_text` or
    `sanitize_for_terminal_bounded`; the session cache keyed by final URL (a later window is served
    with no egress); budgets.
  - The result: an output observation `Untrusted(Source::Web)` with a header line (URL, status, type,
    size, digest, line window), `hops[]` (measured and derived fields), body and text blobs.
  - Fetcher pin: path and SHA-256 are checked at provider construction.
- Crates: harness-tools.
- Tests: `fetch_html_extracted_untrusted_web_source`, `fetched_text_marked_untrusted`, `redirect_to_private_ip_refused_per_hop`, `redirect_to_unlisted_host_refused`, `too_many_redirects_refused`, `content_type_pdf_refused`, `declared_html_binary_body_refused`, `missing_content_type_refused`, `latin1_decoded_unknown_charset_refused`, `giant_response_truncated_marked`, `second_window_served_from_cache_without_egress`, `fetch_budget_exhausted_refused`, `terminal_escapes_in_page_inert`, `fetch_refused_without_egress_log`, `fetch_refused_without_conformed`, `fetcher_digest_mismatch_refused`, `fetcher_runs_confined_end_to_end` (macOS, skipped elsewhere with a reason).
- Deps: P-39b, P-39c, P-39e, P-39f, P-44. Parallel: yes (new file; `provider.rs` gets one field). Risk: medium-high. ARCH: no.

**P-39h `harness.web.search` via the user's loopback SearXNG**
- Why: §8, INV-47.
  - The search endpoint config type (loopback rule reused from `harness-model-core/src/endpoint.rs`).
  - Search through `open_hop` in `search-endpoint` mode (`LoopbackConnector`, no resolution) and the
    fetcher: `GET /search?q=…&format=json&pageno=1&safesearch=1`, body ≤ 512 KiB.
  - Parse in-process: `serde_json::Value`; only `results[].{url,title,content}`; URLs through
    `parse_url`, invalid ones dropped and counted; cuts at 120 and 300 characters; sanitised; each
    marked `[fetchable]` or `[not on allowlist]`.
  - Search budget. The raw JSON is a blob only.
- Crates: harness-tools, harness-model-core (expose the loopback check as a pure fn if it is not
  already public).
- Tests: `search_results_bounded_sanitised_and_marked_fetchable`, `search_raw_json_never_in_output`, `search_endpoint_must_be_loopback`, `search_query_journaled_in_egress`, `search_budget_exhausted_refused`, `searxng_garbage_json_typed_error`, `javascript_url_result_dropped_and_counted`.
- Deps: P-39g. Parallel: yes. Risk: medium. ARCH: no.

**P-39i Research sessions without a workspace in `harness-run` (skeleton, no web yet)**
- Why: §2.1, §2.4, INV-42.
  - `TaskSpec.kind: SessionKind` (`Coding` is the default; nothing else changes).
  - `prepare` and `plan` (`driver/plan.rs:69`, `:253`) take the workspace as optional internally:
    `Prepared.read_tools`, `edit_tools`, `tree` and `facts` become `Option`; with no workspace there
    is no tree walk, the research facts block is used, and `SessionSpec.workspace = None` with
    `kind: Research`.
  - The research registry; header keys `session_kind` and `web` added to `HEADER_INPUT_KEYS` (absent
    for coding).
  - `rh-research/1`: the system template and facts (`harness-model-core/src/context.rs`).
  - `run_research(ResearchRun)` reuses the session loop (P-13); P-05 D4's turn-start re-measure and
    the resume tree check are skipped when there is no workspace.
  - A research session here can be granted only todo and submit. The web capabilities are refused
    until P-39j wires them.
- Crates: harness-run, harness-model-core.
- Tests: `research_session_has_no_workspace_grant`, `research_session_runs_two_turns_and_audits_clean` (scripted model, todo only), `research_header_records_kind_allowlist_and_confirmation`, `coding_header_digest_unchanged`, `batch_and_session_context_digests_unchanged`, `research_context_format_is_rh_research_1`, `research_refused_without_conformed` (the airlock cases are required even before web is wired: fail-closed), `resume_of_research_session_skips_tree_check`.
- Deps: P-39b, P-39e, P-13, P-17. Parallel: no with driver/context-chain slices (P-22, P-23, P-26, P-27, P-28, P-30, P-33, P-38). Risk: high (driver hotspot H-B; mechanical `Option` threading; reviewer pass required). ARCH: no.

**P-39j Wire the web tools into research sessions, and the offline audit**
- Why: §3, §9, INV-43, INV-51.
  - `EgressLog` over the run's `JournalWriter` (`Egress` appended and fsynced through the writer; a
    poisoned writer refuses).
  - `WebTools` built in research sessions with the confinement witness, the fetcher pin, the allowlist
    and the budgets.
  - `ToolFinished` hop bodies.
  - Audit (`replay/feed.rs`, `replay/audit.rs`): `Recorded` gains web inputs (`resolved` lists, frames
    from blobs, byte counts, elapsed, `ended`). `RecordedResolver` and `RecordedHopRunner` re-feed
    them. Decisions, redirects, verdicts, extraction, observations, cache hits, budgets and `Egress`
    records are recomputed and compared.
  - Resume carries the egress counts.
- Crates: harness-run, harness-tools (the `Recorded*` seam types).
- Tests: `egress_event_precedes_forward` (sequence order in a real journal), `research_scripted_fetch_journals_egress_before_tool_finished`, `research_replay_audits_clean_offline`, `tampered_body_blob_diverges`, `tampered_dns_answer_diverges`, `audit_never_opens_a_socket` (panicking resolver and confinement), `poisoned_writer_refuses_fetch` (fault-injected `JournalFile`: zero fixture connections), `resume_refetches_interrupted_hop_and_counts_both`.
- Deps: P-39g, P-39h, P-39i. Parallel: no (driver/replay chain). Risk: high. ARCH: no.

**P-39k CLI: research sessions, the `web` config section, start-of-session confirmation**
- Why: §2.1, §2.3, §5.5, INV-53.
  - `chat --research --allow-host H…` and research task files (`session`, `web`; refused
    combinations exit 2 or 4).
  - User config `web` section: `mode`, `fetcher{path,sha256}`, `search_endpoint`, `user_proxy`,
    `user_proxy_ack`, `budgets`. It is read only from the config dir.
  - Before the first model call: print the allowlist, mode, budgets, search endpoint and fetcher
    digest, and require a typed `yes` on a TTY. Non-TTY needs `--allow-unattended-web`, else exit 4.
  - The banner discloses web mode. `/status` shows budgets used.
  - `doctor` (P-43) checks the fetcher pin and the airlock witness coverage.
- Crates: harness-cli.
- Tests: `chat_research_requires_typed_confirmation`, `chat_research_with_workspace_flag_refused`, `research_task_with_exec_or_workspace_keys_refused`, `unattended_research_needs_flag`, `config_web_section_strict`, `direct_mode_refused_without_net_build`, `banner_discloses_web_mode_and_hosts`, `chat_research_session_audits_clean` (mock model, in-process hop runner), `doctor_reports_fetcher_pin_and_airlock_cases`.
- Deps: P-39j, P-18, P-07, P-43. Parallel: yes (cli only). Risk: medium. ARCH: no.

**P-39l Quarantined notes: build, store, `NoteSaved`, `notes list|show|verify|rebuild`**
- Why: §6, INV-49.
  - Note builder from journal records (deterministic; harness-run `research/note.rs`).
  - Saved at each research turn that ends `answered` or `submitted`, and by `/save-note`.
  - `NoteSaved` first, then the files (0700/0600, atomic, immutable).
  - Audit recomputes the `NoteSaved` id.
  - CLI verb `notes` (`cmd_notes.rs`): `list`, `show` (sanitised), `verify [--anchor]`, `rebuild --run`.
- Crates: harness-run, harness-cli.
- Tests: `note_saved_content_addressed_and_immutable`, `note_labels_untrusted_web`, `note_verify_detects_tamper` (edited `note.json`; a source digest not in the journal; edited journal → chain error), `note_saved_audit_recomputes_id`, `note_missing_file_listed_and_rebuilt`, `notes_show_sanitises_terminal_escapes`, `note_written_only_under_state_root_research`, `research_notes_never_reach_policy` (a note holding policy, task and config JSON; the config/inputs/plan modules never name the notes dir; policy digest unchanged).
- Deps: P-39k, P-14. Parallel: yes with P-39m's CLI part only after this merges (P-39m needs the store). Risk: medium. ARCH: no.

**P-39m `/import-research` and `notes export`: the human-only airlock**
- Why: §7, INV-50.
  - `UserInput` gains `Input::Import(ImportRequest{note, dest, confirmed})` (`harness-run/src/session.rs`).
  - At a turn boundary the loop verifies the note, checks the destination (`workspace_path`, not
    protected (P-29), must not exist), journals `NoteImported` (bytes as a blob), creates the file
    with the edit engine's atomic create, and records its digest in the loop's own tree, so it is not
    an external change.
  - REPL `/import-research <id|path> [dest]`: full sanitised preview, then the typed 8-character id
    prefix; any other answer or EOF cancels.
  - `notes export <id> --out FILE`: TTY only, same dialogue, refuses `state_root` and config paths.
  - Audit re-feeds `NoteImported`.
- Crates: harness-run, harness-cli, harness-tools (expose the create path if it is private).
- Tests: `import_requires_user_confirmation`, `import_wrong_prefix_cancels`, `import_refused_without_tty`, `model_cannot_trigger_import`, `imported_file_read_is_untrusted_workspace_source`, `import_refuses_existing_or_protected_destination`, `import_refuses_note_outside_store_or_unverified`, `import_not_flagged_as_external_change`, `session_with_import_audits_clean`, `export_refuses_state_root_and_config_paths`, `pasting_note_answer_as_message_refused_with_hint`.
- Deps: P-39l, P-18, P-29. Parallel: no with other `session.rs` slices (P-23, P-26, P-28). Risk: medium-high (it is the declassifier). ARCH: no.

**P-39n `net` feature: rustls in the fetcher, direct egress in the build, licence and purity review**
- Why: §5.4, INV-52. **Needs owner question OQ-1 answered before merge.**
  - `harness-fetch/net`: optional `rustls` (no default features; `std`, `tls12`, `ring`; ring
    provider installed explicitly) and `webpki-roots`; `fetch_over_tls` (SNI = host, ALPN
    `http/1.1`, frame `tls{version,suite,cert_sha256}`).
  - Feature forwarding `harness-cli/net` → `harness-tools/net` → `harness-sandbox/net`. harness-cli
    never depends on harness-fetch.
  - `deny.toml`: the licence additions measured with `cargo deny list`, each crate listed with a
    reason under `[bans]`.
  - `purity.sh`: the `harness-fetch --features net` allowlist (the exact reviewed set); `harness-cli
    --all-features` TLS denylist; a selftest plant.
  - `gates.sh`: a `harness-fetch --features net` clippy and test step.
  - README "Try it": the build line.
- Crates: harness-fetch, harness-cli (feature line only), deny.toml, scripts/ci/{purity.sh,purity-selftest.sh,gates.sh} (plus Cargo.lock, H-F).
- Tests: `tls_handshake_against_fixture_with_test_root` (a committed static test CA and leaf PEM; a rustls server under dev-deps), `wrong_host_cert_refused`, `expired_cert_refused`, `sni_is_the_allowlisted_host`, `cli_never_links_tls` (purity), `default_features_have_no_tls_crate` (purity; INV-24 check unchanged), `net_tree_equals_reviewed_set` (purity), `tls_handshake_inside_proxy_sandbox` (macOS positive control).
- Deps: P-39d, P-39f, P-39k. Parallel: yes (fetcher crate plus scripts). Risk: high (supply chain; C in ring). ARCH: no (decided here; owner sign-off is OQ-1).

**P-39o User-proxy mode: the default build's web path, IP checks delegated and disclosed**
- Why: §5.5, decision #2 option A, owner question OQ-4.
  - `mode: user-proxy`: the pump target is the configured loopback proxy (`LoopbackConnector`). The
    fetcher sends an absolute-form `GET https://host/target` (no CONNECT, no TLS in the fetcher).
  - `Egress.ip = "delegated"`. The allowlist, budgets and response handling are unchanged.
  - Config requires `user_proxy_ack: "ip-checks-delegated"`. Banner and header disclose it.
  - Doc recipe `docs/web-user-proxy.md`, naming one proxy that accepts absolute-form https
    (UNVERIFIED per proxy).
- Crates: harness-tools, harness-fetch, harness-cli.
- Tests: `user_proxy_mode_requires_ack`, `user_proxy_must_be_loopback`, `user_proxy_egress_journals_delegated_ip`, `allowlist_still_enforced_in_user_proxy_mode`, `user_proxy_absolute_form_request_shape`, `user_proxy_session_audits_clean`.
- Deps: P-39k. Parallel: yes with P-39l/m/n. Risk: medium. ARCH: no.

**P-39p Adversarial airlock suite (tests only)**
- Why: §11. Proves that the airlock holds under hostile pages, DNS, fetchers and users, end to end
  through the session loop and the REPL, and that the whole hostile session audits offline.
- Crates: tests in harness-run (`tests/hostile_web.rs`), harness-cli (`tests/hostile_research.rs`), harness-testkit (fixture server, fake resolver).
- Tests: `hostile_web_prompt_injection_in_page`, `hostile_web_forged_nonce_in_page`, `hostile_web_redirect_to_metadata_ip`, `hostile_web_redirect_to_private_via_dns`, `hostile_web_dns_rebinding`, `hostile_web_mixed_answer`, `hostile_web_ipv4_mapped_v6`, `hostile_web_giant_response`, `hostile_web_endless_chunked`, `hostile_web_slowloris`, `hostile_web_header_flood`, `hostile_web_gzip_bomb`, `hostile_web_zip_as_html`, `hostile_web_content_type_games`, `hostile_web_smuggling_shapes`, `hostile_web_terminal_escapes`, `hostile_web_search_snippet_injection`, `hostile_web_note_poisoning`, `hostile_web_import_without_typing`, `hostile_web_fetcher_lies`, `hostile_web_audit_offline`.
- Deps: P-39h, P-39m, P-03, P-19. Parallel: yes (tests only, separate files). Risk: low. ARCH: no.

Order and lanes:
- **Lane A** (pure, then policy): P-39a → P-39b.
- **Lane B:** P-39c.
- **Lane C:** P-39d.
- **Lane D:** P-39e.
- Then P-39f (after a, c, d), then P-39g (after b, e, f), then P-39h, then P-39i (after b and e; it can
  run alongside f/g/h, but it is in the driver chain), then P-39j, then P-39k.
- Then P-39l → P-39m, alongside P-39n (owner-gated) and P-39o.
- P-39p last.

The machine-readable copy is `docs/slices/P-39-slices.json`.

### Track S-L (Linux)

The Linux confinement backend (design note `docs/slices/S-L-linux-sandbox.md`, owner decision D29 / Q-17).
Namespace-less Landlock (ABI 1–4+) + seccomp-bpf + no_new_privs + rlimits + subreaper/pgid kill as the
fail-closed default; an unprivileged namespace tier (ports, stronger kill) as a later opt-in. `unsafe`
is confined to a new `harness-sandbox-linux` crate (design §6.7). Runtime tests run in a real Linux VM
over ssh, never `cargo check` alone; the matrix row is committed only from a green run on a real kernel.
Each card is one GLM-flash slice. The machine-readable deps are in the note's `deps_extra.json` object.

#### S-La — crate skeleton and delegation seam
**S-La New `harness-sandbox-linux` crate, `unsafe` ratchet, delegation from `linux.rs`**
- Why: give `unsafe` a home (design §6.7, L-D1/L-D2) and wire `harness_sandbox::linux::Linux::probe()` to delegate to it on `target_os=linux` while every other OS pulls none of it. No behaviour change yet: `probe()` still refuses, but now through the new crate's "primitives present?" check, not an unconditional `NotBuilt`. New crate `#![allow(unsafe_code)]` with a `// SAFETY:`-per-site ratchet; `harness-sandbox` stays `#![forbid(unsafe_code)]`. Add the crate to `scripts/ci/purity.sh` §5 as the single named `unsafe` exception with an `unsafe`-site count, the registry allowlist additions (`landlock`, `rustix` or `nix`, `enumflags2`, `libc`), and the target-gated path dep. No new behaviour reaches `harness-run`.
- Crates: harness-sandbox-linux (new), harness-sandbox (`linux.rs` delegation, `Cargo.toml` target dep), scripts/ci/purity.sh, deny.toml, Cargo.lock (H-F).
- Tests: `linux_crate_builds_on_linux_target` (cfg), `probe_still_refuses_without_primitives`, `unsafe_site_count_matches_ratchet` (purity selftest), `purity_allows_the_named_linux_unsafe_crate_only`, existing `cargo test -p harness-sandbox` unchanged on macOS.
- Deps: ARCH:S-L. Parallel: no (crate head; touches purity/deny/lock). Risk: medium (supply chain, gate changes). ARCH: no.

#### S-Lb — Landlock ruleset from a Validated spec
**S-Lb Landlock ruleset: read/write/exec rights from the spec, ABI-aware, degrade = refuse**
- Why: §1 (fs read/write/protected/exec parity, FT-3/4/9/10/12, hard-link). Map `Validated.{read_only, read_write, protected}` to a `landlock::Ruleset` using `PathFd` handles: read trees + devices + ro roots get `ReadFile|ReadDir`; rw roots add `WriteFile|Truncate|MakeReg|MakeDir|Remove*|Refer`; protected dirs get read-only rights (path specificity beats the rw rule). HARD-require the ABI the grants need (`CompatLevel::HardRequirement`, not best-effort): a kernel below it → `PrimitiveMissing("landlock-abi")`, never a weaker domain (L-D5). Pure rule-building is unit-tested on any OS; applying is linux-only.
- Crates: harness-sandbox-linux (`landlock_rules.rs`).
- Tests: `rules_grant_exactly_the_spec_roots`, `protected_dir_is_read_only_inside_a_writable_root`, `missing_required_abi_refuses_not_degrades`, `ro_root_gets_no_write_right`, `refer_denied_outside_rw_roots` (hard-link).
- Deps: S-La. Parallel: yes (with S-Lc). Risk: high (security boundary). ARCH: no.

#### S-Lc — seccomp denylist
**S-Lc seccomp-bpf denylist: network off by default, escape syscalls refused**
- Why: §1 "what Landlock cannot do" — close the socket/ptrace/io_uring/mount/unshare/kexec/bpf/perf/keyring gaps with one seccomp filter applied last before exec. Build the `BpfProgram` as pure-Rust data (an arch-guarded nr→RET_ERRNO ladder, ~100 lines) behind an internal `SeccompFilter` trait; one `seccomp(2)`/`prctl` apply is the only `unsafe`. `Network::None` denies the whole `socket` family; `clone3` denied outright, `clone` arg-filtered on `CLONE_NEW*`. The filter data builder is unit-tested anywhere; applying is linux-only.
- Crates: harness-sandbox-linux (`seccomp.rs`).
- Tests: `filter_data_denies_the_documented_syscalls`, `filter_data_is_deterministic`, `network_syscalls_denied_at_network_none`, `clone3_denied_and_clone_newns_flag_filtered`, `applied_filter_blocks_socket_in_a_child` (linux, control: unconfined child can `socket`).
- Deps: S-La. Parallel: yes (with S-Lb). Risk: high (security boundary). ARCH: no.

#### S-Ld — supervisor: subreaper, pgid, pidfd, reliable kill
**S-Ld Supervisor: subreaper + process group + pidfd + control pipe; stop and crash both empty the tree**
- Why: §1 process-tree containment / "every command process is gone" (FT-5/8/16/16-setsid). The launcher sets `PR_SET_CHILD_SUBREAPER`, runs the program in its own `setpgid` group, holds a `pidfd` and a control pipe with `PR_SET_PDEATHSIG` so a harness crash makes the kernel signal the helper, which sweeps. Stop = `kill_process_group(SIGKILL)` + reap descendants from the subreaper's child list (a `setsid` escapee is still reaped by the subreaper). Reuse the backend-neutral `ring.rs` for live output and the existing `ConfinedExit`/`DomainCleanup` vocabulary. `close_range` before exec so no harness fd leaks (fd-inherit case). No `ConfinedChild` API change.
- Crates: harness-sandbox-linux (`supervisor.rs`), harness-sandbox (reuse `ring.rs`, `spec.rs`).
- Tests: `stop_kills_the_whole_process_group`, `setsid_double_fork_escapee_is_reaped_by_the_subreaper`, `crash_of_the_parent_sweeps_via_pdeathsig`, `no_stray_fd_crosses_exec`, `ring_output_is_bounded_and_digested` (reuse), `wall_clock_and_rlimit_cpu_both_stop_a_busy_loop`.
- Deps: S-Lb, S-Lc. Parallel: no (joins the two halves). Risk: high. ARCH: no.
#### S-Le — live probe, witness mint, matrix row
**S-Le Live self-probe that applies the sandbox in a child, verifies canaries refused, mints `Conformed`**
- Why: §3.4, INV-6/INV-15. A probe child spawned through the real supervisor path applies Landlock+seccomp+rlimits then attempts the canaries (connect, bind, write-outside, read-home-canary + symlink, env, benign-control, fork/mem bomb, setsid sweep); any canary NOT refused → `LiveProbeFailed`, no witness (final, never retried — load-shaped Io retries only, matching `seatbelt.rs` H2f). Commit the first Linux `MatrixRow` (`linux-landlock-seccomp-nons-v1`, `NetworkMechanism::LinuxLandlockSeccomp`, `KillDomain::LinuxCgroup`-or-subreaper, guards per tier) covering `H2_EXIT_CASES` — but ONLY after S-Lf is green on a real kernel (this card lands the probe + an UNCOMMITTED row behind a feature/test gate; the row is committed in the same PR S-Lf passes). Mint stays crate-private in `linux.rs` (INV-15). Add the `backend` journal object (§3.5), replay-recomputed.
- Crates: harness-sandbox-linux (`probe.rs`), harness-sandbox (`linux.rs` mint, `conformance.rs` row), the journal/header layer (`backend` object), replay audit.
- Tests: `probe_mints_only_when_every_canary_is_refused`, `an_escape_is_final_and_mints_nothing`, `a_load_shaped_io_failure_is_retried`, `witness_names_backend_abi_and_guards`, `backend_object_round_trips_and_replay_recomputes_it`, `require_passes_on_linux_when_the_probe_passes` (linux/VM).
- Deps: S-Ld. Parallel: no. Risk: high. ARCH: no.
#### S-Lf — Linux conformance parity suite
**S-Lf `tests/conformance_linux.rs`: the macOS suite mirrored through the real spawn seam**
- Why: §4. One-for-one with `conformance_macos.rs`, same `Case` ids (FT-1..FT-18 as applicable, D31, nested-sandbox, hard-link), each checked from OUTSIDE with an unconfined control, `--test-threads=1`. This is the suite `rh-dev linux` runs in the VM; its green run on a real kernel is what lets S-Le commit the matrix row. FT-17 handling per L-Q3 (macOS-only on the row, reason recorded) until decided.
- Crates: harness-sandbox (`tests/conformance_linux.rs`, `#![cfg(target_os="linux")]`).
- Tests (named cases): `ft1_tcp_connect_refused`, `ft3_writes_outside_fail`, `ft4_secrets_and_home_unreadable`, `ft5_fork_bomb_bounded`, `ft6_memory_bomb_bounded`, `ft7_disk_fill_capped`, `ft8_busy_loop_killed`, `ft9_protected_paths_read_only`, `ft10_harness_state_unreadable`, `ft11_unix_socket_connect_fails`, `ft12_symlink_escape_refused`, `ft15_no_dns`, `ft16_setsid_escapee_reaped`, `d31_bind_refused`, `nested_sandbox_cannot_loosen`, `hard_link_from_outside_refused`.
- Deps: S-Le, S-Lh. Parallel: no (verified serially in the one VM). Risk: high. ARCH: no.
#### S-Lg — Linux-specific escape cases
**S-Lg Linux escape cases: openat2, /proc mem, fd-inherit, LD_PRELOAD, setuid, memfd-exec, abstract unix, ptrace, fork-bomb-pgroup, /dev/shm+tmpfs**
- Why: §4 Linux-specific table. New `Case` variants added to the Linux row ONLY as each test passes on a real kernel (P-36 §12 discipline). Covers the escapes a path/string sandbox misses.
- Crates: harness-sandbox (`conformance.rs` new `Case` variants + ids; `tests/conformance_linux.rs` additions).
- Tests: `linux_openat2_resolve_flags_cannot_escape_roots`, `linux_proc_self_mem_and_pid_mem_are_not_a_write_channel`, `linux_no_unexpected_fd_is_inherited_into_the_child`, `linux_ld_preload_and_loader_env_are_absent`, `linux_setuid_binary_gains_nothing_under_no_new_privs`, `linux_memfd_create_then_execveat_is_refused`, `linux_abstract_unix_socket_connect_is_refused`, `linux_ptrace_of_a_sibling_is_refused`, `linux_fork_bomb_and_setsid_double_fork_are_all_reaped`, `linux_dev_shm_and_tmpfs_writes_stay_inside_roots`.
- Deps: S-Lf. Parallel: no. Risk: high. ARCH: no.
#### S-Lh — rh-dev linux VM runner
**S-Lh `rh-dev linux`: sync workspace to the Linux VM over ssh, run the suite with a timeout, report pass/fail**
- Why: §5.1. A Rust subcommand on `tools/rh-dev` (no shell logic, memory "rust-only-tooling"): `--boot` via `utmctl`, poll ssh, `rsync` the tree (excl. target/.git), run `cargo test -p harness-sandbox --test conformance_linux -- --nocapture --test-threads=1` (+ unit tests) with a wall-clock timeout that kills the ssh child's group, parse `test result:` lines, exit 0 only if all pass, `--keep-logs`. Acquires `/tmp/rh-linux-vm.lock` for the whole run (one VM, serialised). Unreachable VM → loud non-zero "SKIPPED, not a pass".
- Crates: tools/rh-dev (new `linux.rs` module; reuse its `Command`/output-parse helpers).
- Tests: `rh_dev_linux_parses_cargo_test_result_lines`, `rh_dev_linux_unreachable_vm_is_loud_nonzero`, `rh_dev_linux_acquires_the_vm_lock`, `rh_dev_linux_builds_the_ssh_and_rsync_argv_without_a_shell`.
- Deps: none. Parallel: yes (dev tool only). Risk: medium. ARCH: no.
#### S-Li — conductor optional Linux step
**S-Li Conductor Linux gate step: run `rh-dev linux` after macOS gates, never silently green**
- Why: §5.2–5.3. For slices touching `harness-sandbox-linux`/`conformance_linux`, the conductor runs `rh-dev linux` after the macOS member gates pass; reachable → gates the merge like any other gate; unreachable/busy → loud banner, `linux: skipped` in the worker report, slice marked NOT Linux-verified (row not committed from a skipped run). Thin launcher only; all logic in `rh-dev`.
- Crates: devkit/swarm (verify/conductor integration — a launcher line), docs note of the contract.
- Tests: manual/recorded in the slice note (conductor is throwaway orchestration); assert the banner text and the non-green-on-skip behaviour in `rh-dev linux` itself (covered by S-Lh tests).
- Deps: S-Lh. Parallel: yes. Risk: low. ARCH: no.
#### S-Lj — opt-in namespace tier and loopback ports
**S-Lj Namespace tier: unprivileged userns/netns/pidns + harness forwarder, enabling `Network::Loopback` ports**
- Why: §1 ports row + P-36 §8 point 3. Where `HostFacts.userns_usable()` is true, an opt-in tier: empty netns + a harness-process forwarder (host `127.0.0.1:<p>` ⇄ bind-mounted unix socket ⇄ inside-netns `127.0.0.1:<p>`), PID-namespace init for atomic whole-tree kill (`KillDomain::LinuxPidNamespace`), and `NetworkMechanism::LinuxNetNamespace`. Only this tier lists `PORTS_CASES` on its row (seccomp cannot inspect sockaddr, so the default tier refuses ports). AppArmor-restricted-userns hosts stay on the default tier (ports refused), never refuse outright (L-Q8).
- Crates: harness-sandbox-linux (`namespaces.rs`), harness-sandbox (`conformance.rs` netns row, `tests/conformance_linux.rs` ports cases).
- Tests: `netns_tier_blocks_all_network_until_a_port_is_granted`, `granted_loopback_port_connects_through_the_forwarder`, `model_port_is_never_forwarded`, `pid_namespace_kill_leaves_no_descendant`, `apparmor_restricted_userns_falls_back_to_default_tier_not_refusal`, `default_tier_witness_refuses_loopback_ports` (covers() gate).
- Deps: S-Lf. Parallel: yes (with S-Lk). Risk: high. ARCH: no.
#### S-Lk — cgroup v2 bounds and the confined file-op helper
**S-Lk cgroup v2 `memory.max`/`pids.max` (whole-tree bounds) and the Linux `rustyharness __confine fileop` helper**
- Why: §1 memory/process rows (stronger bars `MemoryGuard::LinuxCgroupMax`, `ProcessGuard::LinuxPidsMax`) where a delegated cgroup subtree exists (`HostFacts.cgroup_v2`); and the Linux file-op helper (P-36 §8 point 4): `rustyharness __confine fileop` in a mount view with only the workspace, the same `rh-fileop/1` codec (`fileop/proto.rs`, already backend-neutral), no perl. Falls back to `RLIMIT_AS`/watchdog when no cgroup subtree is delegated.
- Crates: harness-sandbox-linux (cgroup setup, fileop helper), harness-sandbox (reuse `fileop/proto.rs`, `conformance.rs` FILEOP_CASES on the Linux row).
- Tests: `cgroup_pids_max_is_a_hard_fork_bomb_bound`, `cgroup_memory_max_bounds_the_whole_tree`, `falls_back_to_rlimit_when_no_delegated_subtree`, `fileop_helper_reads_and_writes_inside_workspace`, `fileop_symlink_to_outside_refused_by_the_kernel`, `fileop_helper_cannot_fork`.
- Deps: S-Lf. Parallel: yes (with S-Lj). Risk: high. ARCH: no.
