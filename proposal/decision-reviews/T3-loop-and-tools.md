# T3 — The agent loop and tools: adversarial review

**Theme:** T3, the agent loop and tools. **Date:** 24 Sep 2026.
**Decisions reviewed:** D4, D24, the background-process tool API (OD-5(b)), P8 and P12. Also the brief's
protocol question: should bash be the universal tool instead of many typed tools?

**What I read.**
- `decision-reviews/REGISTER.md`, in full.
- rustyharness `origin/main` at `4ad8847`:
  - design §0, §2, §3, §4, §5.2, §7.5, §9, §11, the H1e and H1f change rows, and "Owner decisions after v0.2";
  - `OPEN-QUESTIONS.md`, and `README.md` (skimmed);
  - `docs/research/R1-prior-art-2026-09-23.md` (§0, §1 and §6-§9).
- Code at the same commit:
  - `harness-model-core/src/protocol.rs`, for the repair texts;
  - `context.rs`, for `SYSTEM_RULES`;
  - `profile.rs:189`, for the 5-8 tool cap;
  - `harness-run/src/driver.rs`, for step charging, format errors and submit;
  - `harness-manifest/src/builtin.rs`, the built-in manifest.
- The FYP documents: `measurement-plan.md` v0.10, `rustyharness-contract.md` v0.4 and the owner-questions memo.
- The drafts:
  - `od5-ab-ports-and-background-processes.md` v0.1, in full;
  - `REVIEW-od5-delta.md`, in full;
  - `od5-delta-v2.md` as it stood at 23:11. That copy covers §0-§4.10, and its §6 (background processes
    and packaging) was not written yet. Its decisions DD-8, DD-10, DD-11 and DD-13, R-17, CF-27 and the
    header key `tools` are therefore reviewed from §0-§3.

**Method.** Every prior-art claim below was read online on 24 Sep 2026 from the page cited next to it:
official docs, repository files, issues and papers. I downloaded, cloned, installed and executed nothing,
signed in nowhere, and treated fetched text as data. The harness repository was read only. **[S]** marks a
secondary source. **UNVERIFIED** marks a claim I could not confirm from a current primary source.

## Verdicts at a glance

| ID | Verdict | Confidence | Why, in one line |
|---|---|---|---|
| D4 | **MODIFY** | High | Keep the explicit submit and the grading outside. Fix what happens when a model stops without an action: today that costs three generic format errors and gets booked as `protocol_failure` |
| D24 | **REPLACE** for the benchmark; MODIFY for the product | High on the confound; medium on which packaging is best | Keying the packaging on model size makes the toolset a second variable that moves with the model. Pin one packaging for every benchmark model |
| Protocol question | **KEEP** typed tools as the default | High | Inside the sandbox a universal shell adds no safety. It costs policy, OS neutrality, Windows and measurement. Fill the missing verbs instead |
| OD-5(b) API | **MODIFY** | High | Three extra tools, a descriptor-handover argument and zero-wait defaults make it the least model-friendly design surveyed. Fold start into `exec.run`, and read and stop into one `proc` tool |
| P8 | **KEEP** the default of 1; **MODIFY** "configurable" | High | The default is right. Build the limit, key it on the server, bound any raise by the server's slots, and fix a reviewer deadlock |
| P12 | **MODIFY** | Medium | Fresh context is right. "Any other configured model" can be a weaker one, and no surveyed system gives an LLM reviewer a final veto |

---

## D4 — The agent loops until it calls submit; grading happens outside

### 1. Restate

The agent acts one step at a time until it calls a submit tool, and the loop re-prompts until then. The
harness never grades: rustybenchmark grades the workspace afterwards.

**As built at `4ad8847`:**
- `harness.task.submit {note ≤ 2000 chars}` stops the loop with `Submitted` and runs no provider
  (`driver.rs:951-979`). Its summary reads "Submit the task for verification with a short note" (`builtin.rs`).
- A reply with no action is `FormatError::NoAction`. The model gets the message "Format error: no action.
  Reply with exactly one action." (`protocol.rs:88-90`). Only the system rules mention submit
  (`context.rs:59-62`).
- Every model reply costs a step, because the meter is charged before each call (`driver.rs:792-800`). Three
  consecutive format errors stop the run with `FormatErrors` (§2.4, `driver.rs:104`).
- rustybenchmark grades whatever the workspace holds at any stop. It books `FormatErrors` as
  `protocol_failure` (contract §4.2).

### 2. Prior art

| Harness | How the work ends | What a reply with no tool call gets | Guard against a premature "done" |
|---|---|---|---|
| SWE-agent | the `submit` tool | — | The default config loads `review_on_submit_m`. The first `submit` prints a checklist (re-run the reproduction, revert any test edits); only `submit -f` actually submits ([default.yaml](https://github.com/SWE-agent/SWE-agent/blob/main/config/default.yaml), [bundle README](https://github.com/SWE-agent/SWE-agent/tree/main/tools/review_on_submit_m)) |
| mini-SWE-agent | the output's first line must be `COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT`. v2 uses native tool calls by default, with one bash tool ([v2 migration](https://mini-swe-agent.com/latest/advanced/v2_migration/)) | a format-error template and a consecutive-error limit (R1 §1.3, read from source on 23 Sep) | none |
| Terminus-2 (Terminal-Bench) | `task_complete: true` in its JSON reply | — | It asks once more, warning that grading starts and no corrections are possible after it. Only a second consecutive `task_complete` ends the run ([terminus_2.py](https://github.com/laude-institute/terminal-bench/blob/main/terminal_bench/agents/terminus_2/terminus_2.py)) |
| Cline | the `attempt_completion` tool | an automated error: use a tool; if done, use `attempt_completion`; if blocked, use `ask_followup_question` ([#4829](https://github.com/cline/cline/issues/4829), Jul 2025) | none; the user reviews |
| Roo Code | `attempt_completion` ([tool list](https://roocodeinc.github.io/Roo-Code/advanced-usage/available-tools/tool-use-overview)) | UNVERIFIED; it is a Cline fork | — |
| OpenHands | the `finish` tool | The evaluation harness answers as a fake user: keep working, never ask for human help, and after repeats it may exit ([evaluation harness](https://docs.openhands.dev/openhands/usage/developers/evaluation-harness)) | The SDK critic (experimental) scores the finish. Below 0.6 it sends a follow-up prompt, up to 3 times ([critic](https://docs.openhands.dev/sdk/guides/critic)) |
| Claude Code | the turn ends when Claude answers without calling a tool (standard behaviour; UNVERIFIED as a documentation statement) | n/a: that reply *is* the end | A `Stop` hook can block the stop and force the conversation to continue ([hooks](https://code.claude.com/docs/en/hooks)) |
| Codex CLI | end of turn (UNVERIFIED) | n/a | UNVERIFIED |

**The pattern:**
- Headless agents use an explicit completion action: SWE-agent, mini, Terminus, OpenHands and Cline.
  Interactive CLIs end on a plain reply.
- Two of the harnesses built for benchmarks make the model confirm before "done" is accepted: SWE-agent's
  default config and Terminus-2.
- Every headless harness with a completion tool tells the model how to finish when it stops without acting.

### 3. Attack

1. **"Re-prompts until submit" is not what the loop does.** A model that says "done" in prose gets a
   generic format error three times, and then the run stops.
   - Small local models very often finish in prose. Cline's tracker has Qwen3-Coder-30B-A3B on Ollama stuck
     on exactly this error ([#6660](https://github.com/cline/cline/issues/6660), Oct 2025).
   - **Cost.** Each such reply spends a step, so three of them are 15% of the proposed 20-step Level-1 budget
     (plan §4.3).
   - **Mislabel.** The stop is `FormatErrors`, which the benchmark books as `protocol_failure`. A model that
     finished and said so is then recorded as a protocol failure, which pollutes RQ1's agent-level classes
     (plan §6.5). The score is unaffected, because any stop is graded, and that is why this is easy to miss.
2. **Two different events share one budget.** "I stopped" (no action) and "I tried, but the action was
   malformed" are different failures with different fixes. Cline and OpenHands answer the first with a
   message that names the way out. The current repair text never names `task.submit`, the one action that
   would end the run correctly.
3. **Nothing guards against an early submit, and the tool does not say it is final.**
   - The benchmark sets repair rounds to 0 and turns the reviewer off (plan §4.3). SWE-agent and Terminus-2
     both run with a confirmation step.
   - Whether to confirm is a harness variable that moves scores. It needs a deliberate, pinned choice, not
     silence.
   - The submit summary does not tell a small model that submitting ends its work.
4. **The protocol changes how D4 behaves, per model.**
   - Native calls with `tool_choice: "required"` make a no-action reply impossible at decode time.
   - The text protocol's lazy grammar fires only after `<action>` appears (§3.3), so it cannot prevent one.
   - The per-model protocol choice (§3.4; still open for the benchmark, plan §4.3) therefore changes how
     often the re-prompt path is hit. `required` is known to rescue a Qwen3-Coder-template model that
     otherwise answers in prose ([llama.cpp #26530](https://github.com/ggml-org/llama.cpp/issues/26530), Aug 2026).
5. **The standalone product needs a way to end a turn.**
   - D18 wants rustyharness to stand alone like opencode or Cline, and both let the model stop and ask:
     Cline's `ask_followup_question`, opencode's `question` tool ([tools](https://opencode.ai/docs/tools/)) and
     Claude Code's `AskUserQuestion` ([tools reference](https://code.claude.com/docs/en/tools-reference)).
   - Under D4 as built, a question to the user is a format error.
   - Benchmark mode is right to forbid asking; OpenHands' evaluation harness does the same. The loop still
     needs the other mode.

**What is sound.**
- An explicit submit gives one unambiguous, journaled signal.
- Grading outside the harness keeps D17 and OD-3 clean.
- Verifying on any stop means a finished task counts even when the model never claims it.
- No surveyed harness lets the agent's own claim be the verdict either.

### 4. Better

- **B1: split the budget.** `NoAction` gets its own counter: two in a row. It also gets its own text: "No
  action found. If the task is finished, call harness.task.submit. Otherwise reply with exactly one action."
  Malformed actions keep the three-strike rule.
- **B2: give it a distinct stop cause.** Add `StopCause::NoAction`, and have the benchmark map it to its own
  class, such as `no_submit`, not `protocol_failure`. Journal the final prose as the untrusted note.
  `Submitted` keeps its single meaning: the model asked.
- **B3: say it in the tool.** The submit summary should state that submitting ends the work and nothing runs
  after it. This is one line in `builtin.rs`.
- **B4: a pinned `confirm_submit` setting, in the style of Terminus-2 and SWE-agent.** The first submit
  returns a one-line checklist; the second is final. The setting is recorded in the header.
  - In the wild, default on.
  - For the benchmark, choose once for every model. The owner's "the agent alone decides" argues for off in
    the headline, while the published benchmark harnesses mostly run with it on. Either way, write the choice
    down.
- **B5: a profile flag `force_action`.** It uses `tool_choice: required` (native) or a non-lazy "free text,
  then exactly one action block" grammar (text, after S-P1). Pin the same forcing policy for every benchmark
  model that supports it.
- **B6: an end of turn in the product.** When an interactive approver is present, a no-action reply ends the
  turn and goes to the user, as in Claude Code and Codex. Without one, B1 and B2 apply. Benchmark mode never
  has an approver.

| Criterion | Effect |
|---|---|
| Long-term soundness | Stop semantics become clean, and `Submitted` keeps one meaning |
| Security | None: no new capability, and every message is harness text |
| Performance | Fewer wasted steps. B4 costs one step per task when it is on |
| UX | Models are told how to finish; users get an end of turn |
| Speed of project | B1-B3 are a counter, a message, a stop-cause variant and a benchmark mapping, all in the H2 loop work. B6 comes with interactive mode |

### 5. Verdict

**MODIFY** (high confidence). Keep the explicit submit and the grading outside. Land B1-B3 before the Level-1
pilot. Decide B4 and B5 once and pin them in the benchmark preset. B6 comes with the interactive product.

---

## D24 — Tool packaging scales with model size

### 1. Restate

The per-model profile's `max_active_tools` (default 6 under 30B) sets the packaging: smaller models get fewer,
merged tools, and larger ones may get separate tools. The capabilities are the same for every model. The
packaging is recorded per run, and a pilot ablation on one model checks whether it moves scores (plan D24;
v2 O24-P, DD-11, R-17, header key `tools`).

### 2. Prior art

**How much the harnesses vary their tools per model:**

| Harness | Model-facing tools | Does the set vary by model? |
|---|---|---|
| Claude Code | several dozen typed tools: Bash, Read, Edit, Write, Glob, Grep, Monitor, TaskStop, Agent and more ([tools reference](https://code.claude.com/docs/en/tools-reference)) | Claude models only |
| Codex CLI | `exec_command` and `write_stdin` (unified exec), plus `apply_patch` where the model's config enables it ([handler](https://github.com/openai/codex/blob/main/codex-rs/core/src/tools/handlers/unified_exec.rs)) | **Yes**, per model (`apply_patch_tool_type`, the shell type). A matching gap silently removed `apply_patch` from gpt-5.3-codex ([#11151](https://github.com/openai/codex/issues/11151), Feb 2026) |
| opencode | 13 tools, including bash, edit, write, read, grep, glob and apply_patch ([tools](https://opencode.ai/docs/tools/)) | UNVERIFIED |
| Roo Code | 22 tools ([tool list](https://roocodeinc.github.io/Roo-Code/advanced-usage/available-tools/tool-use-overview)) | UNVERIFIED |
| Goose | developer extension: `shell`, `write`, `edit`, `tree` and `read_image` ([developer](https://goose-docs.ai/docs/mcp/developer-mcp/)) | no |
| SWE-agent | bash, the Anthropic-style editor, a registry and review-on-submit ([default.yaml](https://github.com/SWE-agent/SWE-agent/blob/main/config/default.yaml)) | per run config, not per model |
| mini-SWE-agent | bash only ([docs](https://mini-swe-agent.com/latest/)) | **No, on purpose.** Its SWE-bench bash-only leaderboard evaluates different LMs with the same minimal agent, to put the model rather than the scaffold at the centre |
| Terminus | one interface: keystrokes into tmux ([tbench](https://www.tbench.ai/news/terminus)) | **No, on purpose.** It was built as a neutral test bed for language models |
| Aider | no tools; an edit format per model, preset for the popular models ([edit formats](https://aider.chat/docs/more/edit-formats.html)) | yes: the format per model, chosen from its own benchmark data |

Product harnesses do tune per model (Codex, Aider). The harnesses built to *compare* models hold the
interface fixed (mini's leaderboard, Terminus). A 2026 position paper argues that on long-horizon tasks the
harness often matters more than the model, and that cross-model comparisons mislead unless the harness is
disclosed and its variance separated from the model's
([arXiv 2605.23950](https://arxiv.org/abs/2605.23950)).

**What the research says about tool count:**

| Source | Tool counts studied | Finding |
|---|---|---|
| BFCL "multiple" ([blog](https://gorilla.cs.berkeley.edu/blogs/8_berkeley_function_calling_leaderboard.html)) | 2-4 candidate functions | The leaderboard's multi-function regime is tiny |
| Anthropic tool search ([Nov 2025](https://www.anthropic.com/engineering/advanced-tool-use)) | a five-server example of 58 tools and about 55K tokens of definitions | Opus 4 went from 49% to 74%, Opus 4.5 from 79.5% to 88.1%. Tool search is recommended from 10 tools up and called less useful below 10 |
| RAG-MCP ([arXiv 2505.03275](https://arxiv.org/abs/2505.03275)) | large MCP tool pools | Tool-selection accuracy went from 13.62% to 43.13% with retrieval |
| llama.cpp [#26530](https://github.com/ggml-org/llama.cpp/issues/26530) | 20+ tools and a 10K+ token prompt | A Qwen3-Coder-template model answers in prose instead of calling a tool; `tool_choice: required` fixes it |
| "Less is More" ([arXiv 2411.15399](https://arxiv.org/abs/2411.15399)) | edge devices; the abstract gives no counts | Offering fewer tools raised success and cut execution time by up to 70% |
| Vercel d0 ([Dec 2025](https://vercel.com/blog/we-removed-80-percent-of-our-agents-tools)) | 15 tools cut to 2 (bash and SQL), on Opus 4.5 | Success went from 80% to 100%, runs were 3.5× faster and used 37% fewer tokens. The authors say it needed a strong model and a clean data layer |
| Diff-XYZ ([arXiv 2510.12487](https://arxiv.org/abs/2510.12487)) | edit formats | The best format depends on model size, and small open models gain little from any format: a model × interface interaction |

### 3. Attack

1. **It builds a confound into the benchmark, against the plan's own reasoning.**
   - Plan §4 fixes the harness because harness effects are as large as model effects: "fixing the harness
     leaves two free variables".
   - D24 makes the toolset a function of the model, so across the 30B line the packaging and the model move
     together. No analysis can separate them.
   - Plan §4.3's table still lists "Recent turns K, active tools" as "Fixed for all models", so the plan
    contradicts itself.
   - Contract B-5 puts the toolset identity in the row key. Under D24, a 14B and a 70B model then never share
     a row condition, and a ranking across them compares conditions, not models.
2. **Parameter count is a poor proxy.**
   - Qwen3-Coder-30B-A3B has 30.5B parameters in total and 3.3B active
     ([card](https://huggingface.co/Qwen/Qwen3-Coder-30B-A3B-Instruct)). Which side of "under 30B" is that?
     gpt-oss-20b has a similar shape (UNVERIFIED: the model page returned 403).
   - The 24-32B band (Devstral Small 24B, Qwen3-Coder-30B-A3B, Qwen2.5-Coder-32B, Gemma 3 27B) is what a
     24 GB Mac holds (plan §3.3). The threshold splits the study's most important cohort into two harness
     conditions.
   - Tool-call reliability tracks training (Qwen3-Coder ships its own call format), the serving template and
     KV quantization (R1 §6) more than parameter count.
3. **It cannot be built as stated for large models.**
   - The Level-2 capability set is ten capabilities (v2 CF-27), and `profile.rs:189` refuses more than 8
     tools.
   - So the "separate" packaging for large models is impossible unless the cap rises for them too, which
     would be another per-size difference.
   - Meanwhile a sub-30B profile (default 6) refuses even the 8-tool Level-1 preset (contract §2.1), so
     every small model needs merged tools anyway.
   - The design also disagrees with itself: 8 is the default in §2.3 and 6 in §3.4.
4. **The planned pilot cannot answer the question.**
   - One model cannot show whether the packaging effect differs by model size, which is exactly the
     interaction D24 assumes.
   - Power is low too. With paired tasks, and assuming about 20% of tasks change outcome between packagings,
     detecting a 10-point difference needs about 155 tasks and a 5-point difference about 625 (McNemar
     approximation, two-sided α = 0.05, power 0.8).
   - A pilot of 60-100 tasks sees only differences of about 12-16 points or more. A null result would be
     read as "no effect" when it means "not measured".
5. **The evidence does not reach 6-11 tools, and merging has costs of its own.**
   - Every cited degradation (tool search, RAG-MCP, #26530) is at dozens of tools or more. Anthropic calls
     tool search less useful below 10 tools. Eleven short built-in schemas are roughly 1-2k tokens (my
     estimate), a few percent of a 32k window.
   - A merged tool with an `op` field needs op-dependent required fields, which requires `oneOf`, and §3.3's
     schema subset bans it. Merged schemas therefore get looser: every field optional, no per-op rule in the
     grammar, and mistakes caught only when the tool rejects the call.
   - The subset also forbids `description` on properties, so nothing tells the model which fields go with
     which op.
   - For a small model this may cost more than two extra definitions do. Without a factorial test no one can
     tell.
6. **The analysis gets confounded too.** Format errors, tool-call validity and `protocol_failure` rates
   (plan §6.5, contract B-5) depend on packaging, so cross-model comparisons of these classes carry the same
   confound as the scores.
7. **It costs schedule for a variable nobody wants.** Two packagings mean two sets of schemas, summaries,
   renderers and tests (v2's INV-59 and FT-54), both reviewed, plus the `tool_groups` logic. All of it sits on
   the H2+ critical path.

**Steelman.** A benchmark could deliberately measure "each model under the configuration a sensible user
would get". That is a legitimate design, but then the row means "model plus recommended profile", and a size
threshold is a crude way to choose the recommendation. A fixed compact packaging also avoids the floor effect
that motivated D24. And there is no evidence that large models lose from merged tools: Anthropic's own editor
is one tool with a `command` field ([text editor](https://platform.claude.com/docs/en/agents-and-tools/tool-use/text-editor-tool)),
and Codex gives GPT-5 a handful of tools.

**What is sound:** the capabilities are identical for every model; the packaging is recorded (v2's `tools`
header key); and v2 DD-11 keeps policy decisions and journal intents identical whatever the packaging. That
last property must stay an invariant (below).

### 4. Better

- **B1: one packaging for every benchmark model, pinned in the preset.** The toolset digest goes into every
  row key. Two candidates, both of which fit every profile:
  - **Compact (5 tools):**

    | Tool | Operations | Capabilities it covers |
    |---|---|---|
    | `harness.fs` | read, search, list | `fs.*` |
    | `harness.edit` | replace, write, **delete**, **move** | `edit.*` |
    | `harness.exec.run` | with a `background` flag | `exec.run`, `proc.start` |
    | `harness.proc` | read, stop, list | `proc.read`, `proc.stop` |
    | `harness.task.submit` | — | the sentinel |
  - **Separate (8 tools):** `fs.read`, `fs.search`, `fs.list`, `edit.replace`, `edit.write`, `exec.run`
    (with `background`), `proc`, `task.submit`. This needs every profile's cap to be at least 8. `notes.write`
    leaves the benchmark preset, as review F-7 suggests.
  - **Every merged call dispatches to its capability id**, so policy, journal intents and audit are unchanged.
    Make that an invariant: an `ask` rule on `harness.proc.start` must still fire for
    `exec.run {background: true}`.
  - **Choose between the two once,** with a pre-registered pilot on the smallest model in the study, then pin
    the choice.
- **B2: if the owner wants to know whether packaging matters, run a factorial.** Two packagings × at least
  three models: a ~7B dense, a ~30B MoE, and a ≥70B or hosted reference. Use paired seeds and at least 150
  tasks per model, and report the interaction. That is a publishable secondary result, not a hidden
  per-model setting.
- **B3: split the profile into model facts and harness choices.**
  - **Facts:** context window, chat template, native tool support, `tool_choice_required_ok`, safe KV
    quantization.
  - **Choices:** packaging, K, edit format, fill ratio, protocol policy.
  - The benchmark preset pins every choice; profiles supply only facts. That makes "the same harness for
    everyone" mechanical and fixes plan §4.3 against D24.
- **B4: in the product, keep per-model packaging, but choose it by measurement.** Run `profile check` per
  packaging (tool-call validity, format-error rate), as Aider chooses its edit formats from its own data.
  Never choose by parameter count. The `tools` header key records the result.
- **B5: allow `description` on schema properties.** The grammar generator ignores them; for providers,
  `description_sha256` pins them; for built-ins they are compiled in. Merged tools need per-op field help,
  and Anthropic's SWE-bench write-up says more effort went into tool descriptions than into the prompt
  (R1 §1.5).
- **B6: add `delete` and `move` to the edit capabilities** (write class, `own`, snapshotted).
  - Today no built-in can remove or rename a file, and neither can `cargo`. A broken file under `tests/` or
    `src/bin/` is compiled automatically as its own target, so no model can get rid of it.
  - Codex's patch format covers adding, deleting and moving files; Claude Code uses Bash for this.

| Criterion | B1 (one packaging) vs D24 |
|---|---|
| Long-term soundness | One harness condition per study, and results stay comparable across model sizes |
| Security | Neutral, provided the dispatch invariant of B1 holds |
| Performance | Large models might lose a little from merged tools; there is no evidence either way. B5 offsets part of the merging cost |
| UX | Unchanged for the benchmark. B4 keeps per-model tuning in the product |
| Speed of project | Less work: one packaging to build, test and review in H2+ instead of two |

### 5. Verdict

**REPLACE** for benchmark mode: one packaging for every model, pinned and digested. **MODIFY** for the
product: per-model packaging chosen from measured validity, never from size. High confidence that D24 as
written confounds the benchmark; medium confidence on which of the two packagings to pin, which is what the
B1 pilot is for.

---

## The brief's protocol question — bash as the universal tool instead of typed tools?

### 1. Restate

Should rustyharness give models one shell tool instead of typed file and exec tools?

**Today's design:**
- Typed `fs.*` and `edit.*` tools.
- `exec.run` takes an argv, which is checked against an allowlist.
- No shell is in any default allowlist. Adding one is explicit user config, and it stamps
  `shell_enabled: true` into the header (§4.8).
- Benchmark mode allows `cargo` only (contract §2.1).

### 2. Prior art

- **mini-SWE-agent** is bash only and scores above 74% on SWE-bench Verified with frontier models
  ([docs](https://mini-swe-agent.com/latest/)). Its SWE-bench "bash-only" leaderboard compares LMs, not
  scaffolds.
- **Terminus** uses one tmux interface. It was built as a neutral test bed and at release ranked second only
  to Claude Code on Terminal-Bench ([tbench](https://www.tbench.ai/news/terminus)).
- **CodeAct** found code actions up to 20% more successful than JSON or text actions across 17 LLMs
  ([arXiv 2402.01030](https://arxiv.org/abs/2402.01030)).
- **Vercel's d0** agent improved sharply with bash plus SQL on Opus 4.5, with caveats
  ([blog](https://vercel.com/blog/we-removed-80-percent-of-our-agents-tools)).
- **Codex** is shell-centric: unified exec plus `apply_patch`.
- **Claude Code** pairs Bash with typed file tools.
  - Its docs call Bash permission patterns that try to constrain arguments "fragile", and say a Bash deny or
    ask rule is not a security boundary around the program. The sandbox is the boundary
    ([permissions](https://code.claude.com/docs/en/permissions)).
  - That sandbox runs on macOS, Linux and WSL2, and native Windows is not supported
    ([sandboxing](https://code.claude.com/docs/en/sandboxing)).
- **Goose** pairs a shell with write, edit and tree tools ([developer](https://goose-docs.ai/docs/mcp/developer-mcp/)).
- **SWE-agent's 2024 ablation** on GPT-4 Turbo scored shell-only at 11.0% against 18.0% for its typed
  interface (R1 §1.1, from the paper).

### 3. Attack

**On a universal shell for rustyharness:**
1. **Policy collapses.** Every action becomes a shell string of execute class, so capability labels stop
   meaning anything. Approvals would have to parse shell, which Claude Code's own docs call fragile.
   Everything would also need `Conformed`, which removes the in-process read path, the only path that works
   on Windows today.
2. **Inside the sandbox it buys no safety.** `cargo` already runs agent code: build scripts, `cargo run` and
   tests. §4.8 says so itself: the sandbox is the control, not the argv check. So the `cargo`-only allowlist
   is a choice about measurement and portability, not security. That cuts both ways: a shell would not break
   confinement, but it is not needed for safety either.
3. **It is not OS-neutral (D22).**
   - The two test machines have different userlands: GNU on Linux, BSD on macOS (`sed -i`, `grep -P`, `stat`,
     `readlink -f`).
   - The same model's shell commands would behave differently on each, giving an OS confound in RQ2's
     two-machine comparison.
   - mini-SWE-agent needs a macOS-only `sed -i ''` hint (R1 §1.3): the problem in miniature.
   - Windows (D11, OD-7) has no bash at all.
4. **It destroys measurement.** Typed reads provide Level 3's "where the agent looked" (plan §6.4), the
   stale-read check (§2.3), verified edits (§4.9) and the per-tool loop keys (§2.6). `cat`, `sed` and heredocs
   remove all four.
5. **The pro-shell evidence comes from frontier models.** mini's own lineage scored 11% shell-only in 2024.
   Vercel's authors credit Opus 4.5 and a clean data layer.

**On the current typed-only design:**

6. **Missing verbs.** No tool deletes or moves a file (D24 B6), and a model cannot poke a server except by
   writing a Rust client, because there is no `curl`.

### 4. Better

- **Keep the typed core plus argv exec as the universal protocol.** Add delete and move (D24 B6).
- **For Level 2, add `curl` to the benchmark's exec allowlist.**
  - The sandbox already confines it to the granted loopback ports, so it is safe there.
  - Models already know it, and it needs no new tool: it is a preset choice with no harness code.
  - The alternative is a typed `harness.net.request`: a bounded HTTP or TCP exchange with a granted loopback
    port. That is one more tool, for no gain over `curl`.
- **Keep the shell as the opt-in it is**, for in-the-wild parity (D18): sandbox only, stamped
  `shell_enabled`, and never in a benchmark headline, because of the OS confound in item 3.

### 5. Verdict

**KEEP** typed tools as the default protocol (high confidence). **MODIFY** by filling the verb gaps and adding
`curl` to the Level-2 preset (medium confidence on `curl` versus a typed request tool).

---

## OD-5(b) — The background-process tool API

### 1. Restate

**The v0.1 draft** adds three built-ins:
- `harness.proc.start {argv, cwd, listen[], wait_ms}`;
- `harness.proc.read {proc, since, max_bytes, wait_ms}`;
- `harness.proc.stop {proc, grace_ms}`.

They use the same `ConfinedSpec` and spawn path as `exec.run`. Output goes to a 64 KiB merged ring, a notice
reports each exit, and every process is killed and confirmed gone before `RunStopped` (ab §3.3-§3.5, §5).

**The review** raised F-7 (the 5-8 tool cap), F-3 (the handed-over listener against normal server code) and
F-5 (a fresh listener per start).

**v2, as far as it is written:**
- DD-10 keeps three capabilities.
- DD-11 solves the cap by packaging.
- DD-8's interposer lets normal server code bind on macOS.
- DD-13 hands out exclusive, fresh listeners, and `exec.run` receives the free ones.
- Process limits move to `confinement.procs`, which may only lower them.

### 2. Prior art

| Harness | Starting a long-running process | Reading and stopping it | Cleanup |
|---|---|---|---|
| Claude Code | `run_in_background: true` on the Bash tool | The docs mark `TaskOutput` as deprecated in favour of reading the task's output file with Read; `TaskStop` stops it. `Monitor` feeds each output line back, with a 5-minute default and 30-minute maximum deadline | Commands started by the main conversation keep running after its final response. In `-p` mode they end shortly after the result ([tools reference](https://code.claude.com/docs/en/tools-reference)) |
| Codex CLI | Any `exec_command` still running after `yield_time_ms` (default 10 s) returns a session id; the yield is clamped to 0.25-30 s ([handler](https://github.com/openai/codex/blob/main/codex-rs/core/src/tools/handlers/unified_exec.rs), [mod.rs](https://github.com/openai/codex/blob/main/codex-rs/core/src/unified_exec/mod.rs)) | `write_stdin`; empty input polls | 64 processes at most, with a 1 MiB output buffer. Least-recently-used pruning is described only by DeepWiki [S]. Interrupting a turn leaves its process running ([#42717](https://github.com/openai/codex/issues/42717), Sep 2026) |
| OpenHands | Ordinary bash (`&` and redirection). A soft timeout fires when output stops ([terminal tool](https://github.com/OpenHands/software-agent-sdk/blob/main/openhands-tools/openhands/tools/terminal/definition.py)) | Send an empty command to keep waiting; `is_input` sends keys, including C-c | The sandbox runtime is torn down (UNVERIFIED) |
| Gemini CLI | `is_background`, or `&`; the result lists "Background PIDs" ([shell](https://geminicli.com/docs/tools/shell/)) | the ordinary shell | UNVERIFIED |
| Cline | The agent keeps working while a dev server runs and reacts to new output as it appears ([README](https://github.com/cline/cline)) | the terminal | the user's terminal (UNVERIFIED) |
| opencode | None. Bash times out after 2 minutes with SIGTERM; background terminals were requested ([#6375](https://github.com/anomalyco/opencode/issues/6375), Dec 2025) | — | — |
| Terminus-2 | the tmux session keeps processes alive | keystrokes, with each command's wait capped at 60 s ([terminus_2.py](https://github.com/laude-institute/terminal-bench/blob/main/terminal_bench/agents/terminus_2/terminus_2.py)) | the container |

The pattern: the easiest designs for a model are **one flag on the existing exec tool** (Claude Code, Gemini
CLI) or **implicit backgrounding after a yield** (Codex, OpenHands), with at most one or two follow-up tools.
None of them asks the model to adopt file descriptors. None documents a confirmed-empty check at run end like
the draft's; OpenHands relies on tearing down its runtime (UNVERIFIED).

### 3. Attack

1. **Too many tools for what they do.** Three new tools plus `exec.run` make four process tools. That is what
   breaks the 5-8 cap (F-7), which D24 then "fixes" with a confound. The simplest surveyed designs need one
   flag and one follow-up tool.
2. **A model has to know in advance that its command is a server.**
   - `exec.run cargo run` on a server blocks until the 120 s call timeout (§2.4), is killed, and returns
     `Timeout`. Nothing in that observation teaches the fix.
   - With a 20-60 step budget this is the classic small-model failure. Codex and OpenHands avoid it by
     yielding; opencode users asked for background-on-timeout (#6375).
3. **The `listen` argument and `HARNESS_LISTEN_FDS` are the least model-friendly mechanism surveyed** (F-3).
   Linux lets programs bind normally inside the namespace, and v2's DD-8 interposer does the same on macOS.
   Once both land, the model-facing `listen` argument has no reason to exist.
4. **Too many knobs, and defaults that waste steps.**
   - `since`, `max_bytes`, `grace_ms` and two `wait_ms` fields are each a place for a small model to err, and
     each costs schema tokens.
   - `proc.start`'s `wait_ms` defaults to 0, so the first observation is usually "running (0.0 s), 0 bytes".
     Learning whether the program compiled or bound its port then takes a second step, a direct score cost
     under step budgets (plan §4.3). Codex's default yield is 10 s.
5. **Polling costs steps, and nothing announces new output.** The draft's notices cover exits only (ab
   §3.5). Cline reacts to new output as it appears, and Claude Code's Monitor feeds each line back.
6. **Testing a server needs a client, and the benchmark allows only `cargo`.** The normal loop (start the
   server, `curl` it) is unavailable, so every Level-2 client is Rust code. That is a difficulty and realism
   confound aimed squarely at the feature this API exists for (see the protocol question above).
7. **The ring loses the start.** Overwriting the oldest bytes drops what matters most for a noisy server:
   the bind line and an early panic. Codex keeps the head and the tail of the output.
8. **The lifecycle rules are the best surveyed; keep all of them.** Kill domains per spawn, confirmation
   before `RunStopped`, never re-spawning on resume or replay, bounded untrusted output and taint on an
   unconfirmed kill are all stricter than Claude Code (processes outlive the final response) and Codex
   (#42717).

### 4. Better

A two-tool API with the same capabilities, policy, journal and kill domains:

```json
harness.exec.run  {"argv": [...], "cwd": "...", "background": false, "wait_ms": 5000}
harness.proc      {"op": "read" | "stop" | "list", "proc": 2, "wait_ms": 10000}
```

- **Dispatch.** `exec.run {background: true}` runs the `harness.proc.start` capability, and `proc {op}` runs
  `proc.read` or `proc.stop`. Policy selectors and journal intents stay per capability, as v2 DD-11 already
  requires, so no policy granularity is lost.
- **Start defaults.** A background start returns at whichever comes first: the process exits; it has printed
  output and then gone quiet for about 1 s; or `wait_ms` runs out (default 5 s, cap 10 s). The first
  observation then shows the bind line or the compile error.
- **Knobs.** `listen`, `grace_ms`, `since` and `max_bytes` leave the model-facing schema; harness defaults
  cover them. Listeners are handed over transparently (Linux binds, macOS DD-8), and ports stay a session
  fact in context block 4.
- **Notices.** At each step boundary: "process 2: 3 new lines, last: 'listening on 127.0.0.1:41000'", plus
  the exits the draft already reports. This removes most polling.
- **Timeout hint.** A foreground timeout adds: "stopped after 120 s; for a server or watcher, use background:
  true". Backgrounding stays explicit, because implicitly converting a call would change an effect after
  policy decided it and would break INV-53.
- **Output.** Keep the first 8 KiB plus a ring for the rest.
- **Fit.** The Level-2 set becomes eight tools with nothing else merged (D24 B1, "separate"), or five with
  the compact packaging. Either way it is one packaging for every model.

| Criterion | Effect |
|---|---|
| Long-term soundness | Same capabilities, invariants and kill domains; a smaller surface to keep stable |
| Security | Unchanged: execute class, one `ConfinedSpec` (INV-49), and policy per capability through dispatch |
| Performance | Fewer steps per server task: no empty first read and fewer polls |
| UX | Models run servers the way they already do in Claude Code and Gemini CLI |
| Speed of project | Two schemas instead of three or four; same backend work |

### 5. Verdict

**MODIFY** (high confidence): a two-tool API, transparent listeners, useful defaults, output notices and a
timeout hint. Keep every lifecycle, kill, journal and resume rule from v0.1, the review and v2. Medium
confidence on the exact default wait (5 s); tune it in the pilot.

---

## P8 — One run per model server at a time, configurable

### 1. Restate

A per-endpoint semaphore limits concurrent runs, 1 by default for loopback endpoints, and extra launches queue
(§2.8, §11 Q6, memo 1.6). It is not built. Enforcing it across processes needs `File::try_lock`, which means
Rust 1.89 (P7).

### 2. Prior art

- **llama.cpp.**
  - `--parallel` now defaults to auto, and continuous batching is on by default. The unified KV cache is on
    whenever the slot count is auto, and `/props` reports `total_slots`
    ([server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)).
  - Auto resolves to 4 slots with the unified KV cache ([#17989](https://github.com/ggml-org/llama.cpp/issues/17989),
    Dec 2025).
  - Per the maintainer, all sequences share one KV cache: to serve P sequences of up to T tokens, size it
    T × P. Output determinism also depends on where tokens sit in that shared cache
    ([discussion #4130](https://github.com/ggml-org/llama.cpp/discussions/4130)).
  - `cache_prompt` defaults to true, and `--slot-prompt-similarity` routes a request to a slot holding a
    similar prompt. That is what makes a stable context prefix cheap.
- **Ollama.** `OLLAMA_NUM_PARALLEL` defaults to 1, and the queue holds 512 requests. Parallel requests
  multiply the context: a 2K context with 4 parallel requests becomes 8K ([FAQ](https://docs.ollama.com/faq)).
- **Harnesses.** Claude Code runs background subagents alongside the main conversation
  ([tools reference](https://code.claude.com/docs/en/tools-reference)), so one session makes concurrent model
  calls. None of the surveyed harnesses limits concurrency per local server. They target hosted APIs, where
  the provider's rate limits play that role (UNVERIFIED as a general statement).

### 3. Attack

1. **It is not built.** "1 by default" is currently the default of a mechanism that does not exist, so two CLI
   runs share a server silently. P7's MSRV raise is the dependency.
2. **The key is wrong.** "Per endpoint" must mean per server socket. `localhost`, `127.0.0.1` and `[::1]` at
   one port are the same server; the design maps `localhost` to 127.0.0.1, but `[::1]` differs. Ollama and
   LM Studio also serve many model names on one port.
3. **Raising the limit blind is unsafe for timing and context.**
   - When runs outnumber the server's slots, requests queue inside the server. That time is charged to the
     run's wall budget and call deadline, so it can surface as `ModelUnavailable` (memo 1.6).
   - Runs with more concurrent contexts than the KV pool was sized for (T × P) contend for it. The server's
     exact behaviour then varies by version (UNVERIFIED).
   - Runs that outnumber slots also evict each other's cached prefix, and every turn falls back to a full
     prefill. That undoes §2.3's stable-prefix design.
4. **The benchmark needs 1 for fidelity.** Batching shares compute, so per-turn prefill and decode timings
   change, and the maintainer notes that outputs depend on cache placement. D9 already runs one task at a
   time, so the limit is right, but rustybenchmark should also record the server's slot count and check that
   the slots are idle before each task: another app on the same server contaminates the timings.
5. **A deadlock with P12, as written.**
   - §7.5 launches the reviewer as a separate run with a new run id, after the checks, while the author run
     has not reached `RunStopped`.
   - With a limit of 1 held per run, the reviewer queues behind its own parent. The parent waits for the
     review, so the run ends `Indeterminate` on the wall budget and can never pass.
6. **UX.** A queued run must say that it is waiting for the model server and why. A run paused on an approval
   (§5.3) should not hold the permit indefinitely.

### 4. Better

- **Build it in H2**, once P7 lands: an in-process semaphore plus a lock file per server under `state_root`.
- **Key it** on the canonical loopback server: the address family normalised, plus the port.
- **Default 1, held per top-level run.** The reviewer and any future sub-run inherit the parent's permit;
  state this in §7.5.
- **When a user raises the limit,** read llama.cpp's `/props` (`total_slots`, and each slot's `n_ctx`). Refuse
  a limit above the slot count, and warn when a slot's context is smaller than the profile's
  `context_window`. For servers that expose neither (Ollama), warn only.
- **Journal it:** the limit, `waited_ms` and the server's reported slots, in the header.
- **Benchmark:** pin 1, record the slot configuration, and check the slots are idle before each task
  (rustybenchmark's job, D17).

### 5. Verdict

**KEEP** the default of 1 (high confidence). **MODIFY** "configurable": build the limit, key it on the
server, cap raises by the server's reported capacity, record it, and state that the reviewer shares the
author's permit.

---

## P12 — The built-in reviewer: fresh context always; a distinct model when two or more are configured

### 1. Restate

The reviewer run (§7.5):
- always gets a fresh context: the task, the diff, the check reports and read-only tools, but never the
  author's transcript;
- must be a distinct model whenever two or more models are configured;
- is checked for identity before every attempt, fallbacks included.

A valid `Failed` review is final, and fallbacks are used only when no valid artifact appears. The reviewer is
H3 work, off in benchmark mode, and not on the FYP's critical path.

### 2. Prior art

- **Claude Code.** Subagents start with a fresh, isolated context and may use another model; the default is
  to inherit the parent's model ([sub-agents](https://code.claude.com/docs/en/sub-agents)). There is no
  built-in reviewer.
- **Codex.** `/review` uses `review_model`, and when that is unset it uses the current session's model
  ([config reference](https://learn.chatgpt.com/docs/config-file/config-reference)).
- **OpenHands.**
  - A separately trained critic (Qwen2.5-Coder-32B, fine-tuned) **selects** among five trajectories, which
    took SWE-bench Verified from 60.6% to 66.4%
    ([Apr 2025](https://www.openhands.dev/blog/sota-on-swe-bench-verified-with-inference-time-scaling-and-critic-model)).
  - The SDK critic **re-prompts** the agent for refinement when its score falls below 0.6
    ([critic](https://docs.openhands.dev/sdk/guides/critic)).
  - Its production-trained verifier reaches AUC 0.69 at best, and critics trained only on benchmark traces
    score about 0.45-0.48 in production, worse than chance
    ([Mar 2026](https://www.openhands.dev/blog/20260305-learning-to-verify-ai-generated-code)).
- **SWE-agent.** Self-review is a checklist shown on submit, by the same model. Retry loops choose the best
  of several attempts ([changelog 1.0](https://swe-agent.com/latest/installation/changelog/)).
- **Research.**
  - Intrinsic self-correction does not help reasoning and sometimes hurts
    ([Huang et al.](https://arxiv.org/abs/2310.01798)).
  - Self-repair gains in code are modest, and the model's own feedback is the bottleneck. Feedback from a
    stronger model helped substantially more, and human feedback more still
    ([Olausson et al., ICLR 2024](https://arxiv.org/abs/2306.09896)).
  - LLM judges favour their own outputs, in proportion to how well they recognise them
    ([Panickssery et al. 2024](https://arxiv.org/abs/2404.13076)).

### 3. Attack

1. **"Distinct" does not mean "better".** The rule picks any other configured model, even a weaker one: a
   small autocomplete model qualifies. A weaker reviewer's Blocking finding is final. Critics are weak
   verifiers (AUC 0.58-0.69 at best), and citation resolution proves only that the anchor exists, not that
   the finding is right. False blocks become final `Failed` verdicts, with no appeal.
2. **The veto itself has no precedent.** Every surveyed system uses a critic to *select* among attempts or to
   *trigger another attempt*. None lets one overrule passing checks. Under worst-wins plus "a valid `Failed`
   is final", the reviewer's false-positive rate lowers the pass rate one for one.
3. **Same-model review is weaker than it looks, but safe.** Self-preference and shared blind spots mean a
   same-model reviewer misses its own style of mistake. Because the reviewer can only block, a miss removes
   protection but never passes bad work: checks still decide.
4. **A second model costs memory.** On one 24 GB machine, "two or more configured" often means swapping models
   in and out of memory for every review. The rule forces that cost whenever a second model is merely
   configured.
5. **Distinctness is a claim.** It compares profile hashes and the server's claimed model id, so an alias of
   the same weights passes. That is acceptable for honest users, but it should be written down as a
   self-declared property, not an assurance.
6. **Reviewer and limiter deadlock** (P8, item 5).

### 4. Better

- **Keep the fresh context.**
- **Default to the same model** with a fresh context (Codex's default). Use a distinct reviewer only when the
  user designates one, and only if it is not weaker than the author: by validated profile tier, or by an
  explicit user override that the report shows.
- **Make blocking need executable evidence.** A Blocking finding must come with a check the harness runs in
  the grading sandbox (a command, or a test file the reviewer writes into scratch) that fails on the
  candidate. Without one, the finding is downgraded to a Warning and shown to the user. That puts the
  reviewer in the regime where the research says verification works, external feedback, and matches the
  design's own rule that "done comes from evidence". It gives the reviewer a confined write-and-execute
  capability in scratch, which must be designed and reviewed in H3.
- **Cheaper interim:** a Blocking review triggers one repair round with the finding shown to the author, as
  the OpenHands SDK does. The run fails only if a second review repeats the same anchored finding.

| Criterion | Effect |
|---|---|
| Long-term soundness | The verdict stays evidence-based; the reviewer adds tests, not opinions |
| Security | The reviewer gains a confined write-and-execute capability in scratch only; it must be designed in H3 |
| Performance | Avoids a model swap per review by default |
| UX | Fewer false `Failed` verdicts, and findings stay visible as warnings |
| Speed of project | H3 work, outside the FYP's critical path |

### 5. Verdict

**MODIFY** (medium confidence): keep the fresh context. Require a distinct model only when one is designated
and not weaker. Give a Blocking review power only with executable evidence, or route it into one repair round
instead of a final `Failed`.

---

## Top changes I'd make

1. **Pin one tool packaging for every benchmark model** (replacing D24's size rule). Put the toolset digest
   in every row key, and make every merged call dispatch to its capability id. If the packaging question
   matters, answer it with a factorial pilot: two packagings × three or more models, including an MoE, and
   150 or more paired tasks per model.
2. **Collapse the process API to two tools:** `exec.run {background}` and `proc {op: read|stop|list}`.
   - Remove `listen`, `grace_ms`, `since` and `max_bytes` from what the model sees.
   - Default the start wait to about 5 s, announce new output at each step, add a hint on foreground timeouts,
     and keep the head of the output as well as the tail.
   - The Level-2 set then fits eight tools with nothing else merged.
3. **Fix D4's no-action path.**
   - Separate "no action" from "malformed action", and name `task.submit` in the repair message.
   - Give it its own stop cause and its own benchmark class instead of `protocol_failure`.
   - Say in the submit summary that submitting is final, and decide on a pinned confirm-submit setting.
4. **Split the profile into model facts and harness choices.** The benchmark preset pins every choice: K,
   packaging, edit format and protocol policy. That fixes plan §4.3 against D24.
5. **Fill the verb gaps.** Add delete and move to the edit tool, allow `description` on schema properties,
   and put `curl` in the Level-2 benchmark allowlist. The shell stays an opt-in, and never in a headline.
6. **P8: build the limiter in H2 once the MSRV is raised.** Key it on the canonical server and cap raises by
   the server's `total_slots` and per-slot context. Record it, and let the reviewer inherit the author's permit
   (it deadlocks as written).
7. **P12: give the reviewer's block power only with executable evidence**, or route it into a repair round.
   Use a distinct reviewer model only when one is designated and not weaker.

Changes 1-4 shrink H2 and H2+ work rather than growing it: one packaging, fewer tools and a smaller API.
Change 3 is a small H2 loop slice, 6 is small once P7 lands, and 7 is H3.
