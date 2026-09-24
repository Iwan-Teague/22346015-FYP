> Research helper for the 24 Sep 2026 decision reviews (agent a89ed6df8cb108818, Opus). Saved verbatim from its final report.

## Coding-agent harness prior art (read 2026-09-24)

All eight questions are answered below. Some older issues and the Codex tool count are marked UNVERIFIED. Things to know before relying on this:
- The WebFetch helper summarises long pages. Three times it gave me invented or misplaced details, which I caught by re-querying:
  - a made-up Stop-hook field `continueConversation`;
  - wrong Gemini tool names;
  - wrong changelog version numbers.

  Every claim marked VERIFIED was re-checked against raw text or a verbatim excerpt.
- Web search ran out partway through (200/200 calls for the session), so the later checks used direct page fetches only.

**1. Claude Code: built-in tools**
- The docs table lists **46 tools**: Agent, Artifact, AskUserQuestion, Bash, CronCreate, CronDelete, CronList, Edit, EndConversation, EnterPlanMode, EnterWorktree, ExitPlanMode, ExitWorktree, Glob, Grep, ListAgents, ListMcpResourcesTool, LSP, Monitor, NotebookEdit, PowerShell, PushNotification, Read, ReadMcpResourceTool, RemoteTrigger, ReportFindings, ScheduleWakeup, SendFeedback, SendMessage, SendUserFile, ShareOnboardingGuide, Skill, SubagentHandback, TaskCreate, TaskGet, TaskList, TaskOutput, TaskStop, TaskUpdate, TodoWrite, ToolSearch, WaitForMcpServers, WebFetch, WebSearch, Workflow, Write. Many depend on platform, model, plan or flags; the docs give no single "default" count. (code.claude.com/docs/en/tools-reference, read 2026-09-24) VERIFIED
- The docs are behind the code. The table still shows TaskOutput as deprecated, but v2.1.277 says "Removed the deprecated TaskOutput tool", so it is effectively **45 tools** in v2.1.282. (raw.githubusercontent.com/anthropics/claude-code/main/CHANGELOG.md, v2.1.282) VERIFIED
- Glob and Grep are not in the default set on macOS, Linux and WSL: "Claude searches with `find` and `grep` through the Bash tool instead". This came in v2.1.117: "the `Glob` and `Grep` tools are replaced by embedded `bfs` and `ugrep`". (tools-reference; CHANGELOG@cc898dc) VERIFIED
- Claude Code also changes tools per model:
  - Task tools and TodoWrite are on "by default only on Claude 3.x models, Opus 4 through 4.7", plus Sonnet 4–4.6 and Haiku 4.5.
  - EndConversation only appears on "Claude Opus 4.8, Claude Sonnet 5, Claude Fable 5, or a later version".
  
  (tools-reference) VERIFIED
- Rename history:
  - v2.0.64: "Unshipped AgentOutputTool and BashOutputTool, in favor of a new unified TaskOutputTool". (CHANGELOG@d213a74) VERIFIED
  - v2.1.83: "Deprecated `TaskOutput` tool in favor of using `Read`". (CHANGELOG@9772e13) VERIFIED
  - v2.1.98: "Added Monitor tool for streaming events from background scripts". (CHANGELOG@9772e13) VERIFIED
  - TaskStop appears by v2.1.30. (CHANGELOG@b374a30) VERIFIED
  - Issue #80566 calls TaskOutput and TaskStop "renamed KillShell/AgentOutput tools". The exact rename version is UNVERIFIED.
  - The Task tool is called Agent by v2.1.71; the rename version is UNVERIFIED.

**2. Claude Code: background processes, turn end, Stop hook**
- Bash `run_in_background: true` returns a task ID. Output goes to a file, and "Claude can retrieve it using the Read tool". Tasks are stopped with TaskStop or `/tasks`; Ctrl+B moves a running command to the background. (tools-reference; code.claude.com/docs/en/interactive-mode) VERIFIED
- When a command hits its timeout, Claude Code "moves it to the background instead of stopping it" (unless it starts with `sleep`). This dates from v2.0.19. (tools-reference; CHANGELOG@d213a74) VERIFIED
- Monitor runs a background command and sends each output line back as an event. Default deadline 5 minutes, maximum 30. (tools-reference) VERIFIED
- Cleanup:
  - "Background tasks are automatically cleaned up when Claude Code exits." On macOS and Linux this also covers processes detached with `setsid` or `timeout`.
  - Tasks are killed if output passes 5 GB.
  - On critical memory pressure after 30 minutes idle, tasks are reaped (v2.1.193+).
  - A foreground subagent's commands stop at its final response.
  
  (interactive-mode) VERIFIED
- In `-p` mode, background shells are "terminated about five seconds after Claude has returned its final result". On SIGTERM it "terminates the process tree of any Bash command that is still running". (code.claude.com/docs/en/headless) VERIFIED
- Orphaned-process issues:
  - #43944 (Apr 5 2026, macOS, closed as not planned): processes get "reparented to PID 1".
  - #81462 (Jul 26 2026, v2.1.220, open): a `cmd &` child survives a foreground Bash call; the issue proposes killing the whole process group.
  - #96625 (opened 2026-09-24, v2.1.278/280, open): orphans left after a crash or force-quit.
  
  VERIFIED. Windows-only issues #77593, #84464, #87813, #90672, #91523 and #92583 are titles from search results only (UNVERIFIED).
- How a turn ends: "Turns continue until Claude produces output with no tool calls". The SDK then emits a `ResultMessage`, with `stop_reason` such as end_turn, max_tokens or refusal. (code.claude.com/docs/en/agent-sdk/agent-loop) VERIFIED
- Stop hook can force continuation:
  - "`PostToolUse` and `Stop` hooks use a top-level `decision: "block"` field". Exit code 2 also blocks, and the reason is fed back to Claude.
  - Safety cap: Claude Code "overrides a Stop hook after it blocks eight times in a row". This is adjustable with `CLAUDE_CODE_STOP_HOOK_BLOCK_CAP`; hooks should check `stop_hook_active` to avoid loops.
  - A prompt-type Stop hook returning `ok:false` keeps Claude working unless it also sets `"impossible": true`.
  
  (code.claude.com/docs/en/hooks-guide, raw text) VERIFIED. The hooks.md reference page was too long to read in full.

**3. Claude Code: Bash rule fragility and sandbox**
- The docs warning: "Bash permission patterns that try to constrain command arguments are fragile." Its examples are options placed before the URL, a different protocol, redirects, and variables. The suggested fixes are denying curl/wget and using `WebFetch(domain:…)`, PreToolUse hooks, and the sandbox network allowlist. (code.claude.com/docs/en/permissions) VERIFIED
- A deny rule "isn't a security boundary around the program". `Bash(curl *)` misses `/usr/bin/curl` and `sh -c 'curl…'`; `Bash(git push *)` misses `git -C . push`. (permissions) VERIFIED
- Compound commands are split on `&&`, `||`, `;`, `|`, `|&`, `&` and newlines, and each part must match. The wrappers timeout, time, nice, nohup, stdbuf and bare xargs are stripped before matching. (permissions) VERIFIED
- The sandbox "lets Claude run most shell commands without stopping to ask permission":
  - It uses Seatbelt on macOS and bubblewrap on Linux/WSL2.
  - `autoAllowBashIfSandboxed` is true by default.
  - Claude can retry a blocked command with `dangerouslyDisableSandbox`, which goes back through the normal permission flow.
  - The docs say it "is not a complete isolation boundary".
  
  (code.claude.com/docs/en/sandboxing) VERIFIED
- The 84% figure is only in Anthropic's engineering blog (2025-10-20), not the current docs: "sandboxing safely reduces permission prompts by 84%" (internal usage). The motivation given is "approval fatigue". (anthropic.com/engineering/claude-code-sandboxing) VERIFIED

**4. OpenAI Codex CLI: tools** (main branch, release 0.156.1 of 2026-09-23)
- The separate legacy shell tools (`shell`, `shell_command`, local shell) are gone from main. `ConfigShellToolType` now has only `UnifiedExec` and `Disabled`, and the old config values `"default"`, `"local"` and `"shell_command"` are accepted as aliases for `UnifiedExec`. (codex-rs/protocol/src/openai_models.rs) VERIFIED. When they were removed is UNVERIFIED.
- The shell tool is `exec_command`: "Runs a command in a PTY, returning output or a session ID". `write_stdin` is added when the `unified_exec` feature is on (stable, on by default). Without it, a one-shot variant keeps the same name `exec_command`, "Runs a command to completion", has no `yield_time_ms`, and defaults to a 10 s timeout. (core/src/tools/spec_plan.rs; handlers/shell_spec.rs; handlers/unified_exec/exec_command.rs; features/src/lib.rs) VERIFIED
- apply_patch is registered only if the model's `apply_patch_tool_type` is set. The only remaining type is `Freeform`; the `apply_patch_freeform` feature is marked Removed. (openai_models.rs; features/src/lib.rs) VERIFIED
- Other tools and their gates (spec_plan.rs) VERIFIED:
  - `update_plan`: behind `config.update_plan_enabled`; its default value is UNVERIFIED.
  - `view_image`: on by default.
  - `web_search`: hosted or standalone depending on the model and search mode.
  - `list_mcp_resources`, `list_mcp_resource_templates`, `read_mcp_resource`: only when MCP servers are configured.
  - Multi-agent tools, on by default: `spawn_agent`, `send_message`, `followup_task`, `wait_agent`, `interrupt_agent`, `list_agents`.
  - Also gated: `request_user_input`, `sleep`, `image_generation`, `tool_search`, `current_time`.
- Code mode:
  - When a model's `tool_mode` is `code_mode_only`, the model sees `exec` and `wait` at top level.
  - `exec` runs JavaScript in a V8 isolate: "All nested tools are available on the global `tools` object".
  - A source test (`code_mode_only_exposes_code_executor_and_hides_nested_tools`) checks that nested tools are hidden from the top level.
  - Both bundled models (`gpt-6-astra`, `gpt-6-sol`) set `"tool_mode": "code_mode_only"`.
  
  (code-mode-protocol/src/lib.rs and description.rs; core/src/tools/spec_plan_tests.rs; models-manager/models.json) VERIFIED
- Default tool count: there is no single fixed number. For the bundled GPT-6 models it is `exec` and `wait`, plus anything that cannot run inside code mode. In direct mode it is roughly 6 core tools, about 6 multi-agent tools, and 3 MCP resource tools when MCP is configured. UNVERIFIED

**5. Codex: tools chosen per model**
- `ModelInfo` is "Model metadata returned by the Codex backend `/models` endpoint". Its tool-related fields are `shell_type`, `apply_patch_tool_type`, `web_search_tool_type`, `experimental_supported_tools`, `supports_search_tool`, `tool_mode`, `multi_agent_version`, `truncation_policy` and `use_responses_lite`. `model_family.rs` no longer exists (404). (openai_models.rs) VERIFIED
- What they control:
  - `shell_type: Disabled` removes `exec_command`.
  - An unset `apply_patch_tool_type` removes apply_patch.
  - `experimental_supported_tools` switches on extra tools per model (for example `"clock"` turns on `current_time`).
  - The model's `tool_mode` overrides feature flags: `model_info.tool_mode.unwrap_or_else(`…).
  
  (spec_plan.rs; core/src/tools/mod.rs) VERIFIED
- `supports_parallel_tool_calls: true` still appears in models.json but not in openai_models.rs, so it looks unused. UNVERIFIED
- Other examples of the same pattern:
  - opencode swaps edit/write for apply_patch when the model ID matches `includes("gpt-") && !…("oss") && !…("gpt-4")`.
  - Claude Code's per-model tools are listed in item 1.
  
  VERIFIED

**6. Codex: long-running processes and approvals**
- Timing and output limits (handlers/shell_spec.rs; unified_exec/mod.rs) VERIFIED:
  - `exec_command` waits 10000 ms by default before returning; "effective range is 250-30000 ms".
  - `write_stdin`: non-empty writes wait 250 ms (cap 30 s); "empty polls wait 5000-300000 ms by default".
  - `chars` "Defaults to empty, which polls without writing."
  - `max_output_tokens` defaults to 10000; the output buffer is capped at 1 MiB.
- Session IDs are random in 1000–100000. At most 64 processes (`MAX_UNIFIED_EXEC_PROCESSES = 64`). When full, it keeps the 8 most recently used (`.take(8)`), evicts the least recently used exited process first, otherwise the least recently used live one, and skips processes currently being written to. (unified_exec/process_manager.rs) VERIFIED
- Processes survive across turns. Interrupting a turn does not kill them: issue #42717 (open, Sep 4 2026) says "the shell process continues running". They are killed at session shutdown (`shutdown_session_runtime` calls `terminate_all_processes`) and by `/stop` (alias `/clean`). `/ps` lists each background terminal with up to three recent output lines. A request to wake Codex when background output arrives (#29865) was closed as not planned. (core/src/session/handlers.rs; learn.chatgpt.com/docs/cli/slash-commands) VERIFIED
- Approvals: rules are Starlark `prefix_rule` entries with allow/prompt/forbidden, and the strictest match wins. "Use rules to control which commands Codex can run outside the sandbox."
  - A `bash -lc` script made of plain words joined by `&&`, `||`, `;` or `|` is split "(using tree-sitter)" into separate commands.
  - Scripts with redirects, substitutions, variables, globs or control flow are treated as one opaque command.
  - The docs example is `git add . && rm -rf /`: the `rm` part blocks auto-approval.
  
  (learn.chatgpt.com/docs/agent-configuration/rules.md, which developers.openai.com/codex/rules redirects to) VERIFIED
- Known bypass: issue #44964 (open, Sep 12 2026) shows a complex `zsh -c` script getting past a managed `rm → forbidden` rule. VERIFIED

**7. opencode** (v1.18.32, 2026-09-21)
- The built-in list in the registry: invalid (internal, described "Do not use"), question, bash, read, glob, grep, edit, write, task, webfetch, todowrite, websearch, skill and apply_patch. Experimental extras are code-mode execute, lsp and plan.
  - websearch only appears for certain providers or with a flag.
  - The docs page lists 13 tools and omits `task`.
  - `list`, `todoread` and `patch` are gone.
  - A typical CLI session with a Claude model gets 11 tools; with GPT models, apply_patch replaces edit and write.
  
  (github.com/anomalyco/opencode packages/opencode/src/tool/registry.ts; opencode.ai/docs/tools) VERIFIED. The per-session count is my own derivation.
- No background support: the bash tool takes only `command`, `workdir` and `timeout` (default 2 minutes), and there is no separate background tool. On timeout it force-kills after 3 s. Issue #50316 (open, Sep 21 2026): "The bash tool never returns for a command that starts a background service." (tool/shell.ts; tool/shell/id.ts) VERIFIED
- End of turn: the loop stops when the last message's finish reason is not `tool-calls` or `unknown` (`!["tool-calls", "unknown"].includes(lastAssistant.finish)`) and there are no tool calls. An `agent.steps` limit adds a MAX_STEPS prompt. (session/prompt.ts) VERIFIED

**8. Gemini CLI** (main branch; v0.62.0-preview.0 of 2026-09-23)
- `run_shell_command` takes `command`, `description`, `dir_path` and `is_background` ("Whether to move the process to the background immediately after starting."). With `&`, "the tool will return immediately and the process will continue to run in the background". The result includes "`Background PIDs`: PIDs of any started background processes." (docs/tools/shell.md) VERIFIED
- How it works in code (packages/core/src/tools/shell.ts; services/shellExecutionService.ts) VERIFIED:
  - PIDs are captured with `trap 'jobs -p > "$_bgpids_file"' EXIT`.
  - With `is_background`, the process is handed to a background service and its output logged to `background-processes/background-{pid}.log`.
  - The model is told "Command is running in background. PID: …".
  - I found no kill-all-on-exit; cleanup at exit is UNVERIFIED.
- Tools: the built-in list has 27 names: glob, write_todos, write_file, google_web_search, web_fetch, replace, run_shell_command, grep_search, read_many_files, read_file, list_directory, activate_skill, ask_user, six tracker_* tools, get_internal_docs, enter_plan_mode, exit_plan_mode, update_topic, complete_task, invoke_agent, read_mcp_resource, list_mcp_resources. The old name `search_file_content` maps to `grep_search`, and `save_memory` is gone. (tools/definitions/base-declarations.ts; tools/tool-names.ts) VERIFIED. Which of these are on by default is UNVERIFIED.

**Could not check**
- Exact versions of the KillShell→TaskStop and Task→Agent renames.
- The Stop section of Claude Code's hooks.md reference (page too long to read).
- For Codex: the default tool count, the `update_plan` default, when the legacy shell tools were removed, and whether `supports_parallel_tool_calls` is used anywhere.
- Gemini CLI's cleanup of background processes at exit, and its default tool set.
- The Windows Claude Code orphan issues, which I did not open.
- Prompt-injection check: nothing tried to redirect me. Claude Code doc pages start with a benign note telling AI readers to fetch llms.txt, which I used as the page index. The opencode `shell.txt` file and Codex `models.json` contain agent prompts, which I treated as data only.
