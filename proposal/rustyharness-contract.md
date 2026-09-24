# rustybenchmark ↔ rustyharness: the integration contract

Draft v0.4 · 24 Sep 2026 · Not yet reviewed. Checked against rustyharness `6ba3437` (H1 built): see
[rustyharness-alignment-2026-09-24.md](rustyharness-alignment-2026-09-24.md). Companion to [measurement-plan.md](measurement-plan.md) §4.
Grounded in rustyharness design v0.1 (reviewed SOUND, 23 Sep; its sections are cited as "RH §n") and
rustybenchmark at `215f573`.

rustyharness is a full coding agent on its own; rustybenchmark runs it in a locked-down **benchmark
mode**, which is a configuration, not code (v0.4). Grading and measuring stay in rustybenchmark.

## 0. The rules (Decided)

1. **rustyharness stands on its own two feet.** In the wild it is a full coding agent, like opencode or
   Cline: it can fetch crates and docs online, open ports on the device, run commands, all with the
   user's permission.
2. **Suite integration comes as add-ons**, off unless enabled (RH ADR-0002; design decision D16). A
   standalone build contains none of them.
3. **Benchmark mode is a configuration, not code.** rustybenchmark embeds the harness and hands it its
   own locked-down configuration: only the local crates, only the benchmark's ports, no internet, a fixed
   toolset, fixed settings. rustyharness's embedding API already takes all of it (§2), so no
   benchmark-specific code is needed in the harness.
4. **Benchmark mode locks down; it never grades or measures.** Everything used for grading or measuring
   lives in rustybenchmark.
5. **Dependencies run one way:** rustybenchmark → rustyharness. rustyharness's code never depends on
   rustybenchmark.

Where a proposed change belongs:

- A user with no interest in benchmarks would want it → **rustyharness**.
- Only the benchmark needs it, and it controls the environment → **the benchmark's configuration**
  (policy, profile, task spec). If that can't express it, it becomes a generic harness feature.
- It grades or measures → **rustybenchmark**.

## 1. In the wild vs benchmark mode

| | In the wild (standalone) | Benchmark mode |
|---|---|---|
| Internet | With permission, through the allowlist proxy (RH D13): crates.io, docs.rs, … | None |
| Crates | Live from crates.io, with permission | Only the local set (top 500 at a pinned date); common ones pre-built |
| Ports | Opened with permission. Loopback first; a port visible on the network asks separately | The fixed loopback range, pre-granted; nothing else |
| Commands | The `exec.run` allowlist; a shell if the user enables it (RH §4.8) | `cargo` only, plus the built-in file tools |
| Tool providers (MCP, suite apps) | Admitted by the user | None |
| Model endpoint | Loopback; LAN or hosted only by explicit opt-in (RH §3.2) | Loopback only: the same device |
| User config and rules files | Honoured | Ignored: the benchmark preset wins |
| Approvals | Asked interactively | No one to ask: anything that would ask is denied |
| Reviewer, repair rounds | On by default | Off; 0 |
| Budgets, protocol, context size | User or profile defaults | The benchmark preset (measurement-plan §4.3) |
| Model transport | rustyharness's own client | rustybenchmark's instrumented `ModelBackend` (§5) |
| Checks | The user's | Visible checks only; rustybenchmark grades separately (§4) |
| Journal header | As normal | Plus: benchmark mode, the preset's digest, the harness version |

## 2. Benchmark mode: a configuration, not code

Checked against rustyharness `6ba3437` (H1 built): its embedding API already provides every piece.
`harness_run::run` takes the policy, the provider registry, the model profile and the model backend from
its caller, and `harness-run` reads no configuration of its own.

| ID | Requirement | How rustyharness already provides it |
|---|---|---|
| BM-1 | **Switch** | The embedding API itself: rustybenchmark passes its own policy, a provider registry that holds only the compiled-in built-in manifest (no app-specific providers), its profile and its instrumented backend. The registry can't be empty: `run` always grants `harness.task.submit`, and planning resolves every grant against the registry. No cargo feature, which also fits rustyharness's rule that `addon-*` features are only for in-process needs (RH §8) |
| BM-2 | **Preset** | The benchmark's policy, profile, task spec and run config: versioned files on the benchmark's side |
| BM-3 | **Precedence over the user's setup** | Inherent: the library never reads the user's config, and the CLI only takes `--policy` explicitly. rustyharness reads no project instruction files today; if it ever does, embedders must be able to switch that off |
| BM-4 | **Lockdown:** the right-hand column of §1 | Deny-first policy (RH §5.1), per-task grants, a registry with only the built-in manifest, no network by default (RH §6.5), the exec allowlist (H2). The local crate set needs gap G3 (alignment review) |
| BM-5 | **Non-interactive** | Designed: "no approver present ⇒ every Ask becomes Deny" (RH §5.3) |
| BM-6 | **Fail closed** | The harness's own rule: no conformed sandbox, no execution (RH §6.1); plus the benchmark's handshake (§8) |
| BM-7 | **Record** | The journal header carries the harness version, the config, policy and manifest SHA-256s, and the profile hash (RH §7.1) |

The harness process itself stays outside the sandbox: its trust base must be out of the agent's reach
(RH §6.4), and it holds the model connection. Benchmark mode applies the lockdown to the sandbox the
agent's commands run in.

### 2.1 What the preset looks like (illustrative)

Benchmark mode is the same harness code with one sealed configuration. Values below are the plan's
examples (measurement-plan §4.3), not final:

```toml
# rustybenchmark preset: sealed, so nothing outside this file can loosen it
preset_version = 1
sealed = true                  # user/global config and rules files are ignored
approvals = "deny"             # nobody is watching: anything that would ask is refused

[tools]
allow = ["fs.read", "fs.search", "fs.list", "edit.replace", "edit.write",
         "exec.run", "notes.write", "task.submit"]
exec_allowlist = ["cargo"]
shell = false
providers = []                 # no MCP servers, no suite apps

[network]
internet = false
loopback_ports = "from-task"   # the slot's fixed range, Levels 2-3 only
model_endpoint = "loopback"

[crates]
source = "local-set"           # top-500 snapshot; pre-built cache mounted read-only

[budgets]
steps = { level1 = 20, level2 = 60, level3 = 60 }
wall_clock = "safety-cap"      # never decides the score
repair_rounds = 0
reviewer = false

[model]
protocol = "per-model"         # open decision: or "text" for every model
context_tokens = 32768
recent_turns = 5
```

**Fixed per study vs per task.** The preset is the same for every model and every task in a study, and
its digest is on every row. The task spec changes per task: prompt, workspace, ports (Levels 2–3), crate
policy (Level 1 std only) and visible checks.

**Beyond the config, only two things differ from a normal run:** the benchmark plugs in its own model
transport so it can time calls (§5), and it supplies the tasks and grades them outside the harness (§4).

**A limitation to state in the FYP report:** benchmark numbers describe rustyharness locked down, with no
internet, no documentation lookups and only the local crates. In the wild the same model may do better
(it can read the docs) or worse (it can wander off).

## 3. Who owns what

| Concern | Owner | Why |
|---|---|---|
| Agent loop: context, action parsing, tools, budgets, loop detection, `task.submit` | Core rustyharness | It is the harness |
| Sandbox for the agent's own commands | Core rustyharness | Any agent needs to run code safely |
| Ports, background processes, extra paths and environment for the agent | Core rustyharness, as generic grants (§6) | Better code: the agent can run and test what it builds |
| The benchmark lockdown | rustybenchmark's configuration of the harness (§2) | Controls the environment |
| Tasks: seeds, prompts, starter workspaces, hidden tests, reference solutions | rustybenchmark | Benchmark content |
| Grading: grader, oracle, hidden tests, grading sandbox, scores | rustybenchmark | Grading |
| Timing and engine telemetry | rustybenchmark, through the harness's `ModelBackend` seam (§5) | Measuring |
| The preset's values, labels, run index | rustybenchmark | Measuring |
| Journal analysis: trajectories, format errors, tool-call validity, crate events, re-grading earlier states | rustybenchmark, reading the harness's journal | Measuring |
| Hardware and environment capture, statistics, results | rustybenchmark | Measuring |
| Integration tests | rustybenchmark's CI | Core rustyharness must not depend on the benchmark |

## 4. One task, end to end

1. **rustybenchmark writes a task spec and passes the preset** (RH §2.1 fields): the prompt; the starter
   workspace; grants (built-in tools, `cargo` on the exec allowlist, loopback ports for Levels 2–3, the
   read-only crate set and build cache); the model profile; visible checks only (§4.1). Hidden tests are
   never in it.
2. **rustyharness, in benchmark mode, runs the agent** through the benchmark's instrumented model
   transport (§5), until `task.submit` or a stop cause. It runs the spec's visible checks, writes its run
   report and journal, and kills everything it started.
3. **rustybenchmark grades on its own.** It takes the deliverable (the base revision plus the harness's
   final diff, stored as a blob, RH §7.2), materialises it in its own grading slot with a fresh clone of
   the build template, adds the hidden tests, and runs its grader in its own sandbox. It first restores
   `.cargo/config.toml` and `rust-toolchain.toml` from the starter workspace, or removes them, so the
   agent can't steer the grading build (measurement-plan §6.1).
4. **rustybenchmark analyses the journal:** trajectories, format errors, tool-call validity, crate events
   (`Cargo.toml` edits and cargo output), and re-grades earlier workspace states (§4.3).
5. **rustybenchmark prunes** the finished run through the harness's generic prune (H-5), keeping the
   journal and snapshots.

### 4.1 The harness's own checks

rustyharness decides "done" from checks, and gives `Indeterminate { NothingChecked }` when a task has
none (RH §2.5). So benchmark task specs carry the checks any user would give: a build, plus the task's
visible tests through the built-in `cargo test` adapter (RH §7.3). The harness's verdict is recorded as a
secondary signal. **It is never the score.**

**Schedule win:** the benchmark's scores don't depend on rustyharness's verification phase (H3). The
benchmark needs H1 (the loop, built) and H2 (confined tools), plus the generic grants of §6. H3 only adds
the harness's own verdict.

### 4.2 Mapping harness stop causes to benchmark results

| rustyharness stop cause | Benchmark result |
|---|---|
| `Submitted` | Graded |
| `Budget(_)`, `Loop(_)`, `FormatErrors`, `ContextExhausted` | Still graded: the deliverable is whatever the workspace holds. The stop cause is kept as a failure class (`budget_exhausted`, `stuck_loop`, `protocol_failure`) |
| `ModelUnavailable`, `SandboxLost`, `Cancelled`, `JournalUnavailable` | Infrastructure failure: never scored as a model failure; the task is retried or resumed |
| A denial logged under BM-5 | Recorded; the agent sees the denial as an observation and carries on, as in any locked-down environment |

### 4.3 Re-grading earlier states (first try, score by turn)

rustyharness keeps a workspace snapshot after every edit for its own resume (RH §2.8, §2.10). The
benchmark reads them through the harness's public journal reader and re-grades them with its own grader.
To verify during H1–H2: snapshot contents, not only their digests, can be retrieved. If they can't, the
benchmark rebuilds each state from the journal's edit events and blobs.

## 5. Timing without touching the harness: the `ModelBackend` seam

rustyharness's model layer is one trait, `ModelBackend`, with implementations `OpenAiCompatible`,
`Replay` and `Scripted` (RH §3.1). The benchmark supplies its own implementation:

- **Same bytes on the wire.** It builds requests and parses replies with the harness's pure
  `harness-model-core` crate (wire format, both action protocols, profiles), so the engine sees exactly
  what rustyharness's own client would send. Only the transport differs: it streams and timestamps every
  delta. A benchmark test checks, byte for byte, that its request bodies match rustyharness's client.
- **It keeps the harness client's guarantees:** loopback only, typed errors on `length` or empty replies,
  the same retry budget (RH §3.2).
- **Timing lives here,** per call: prefill, reasoning and answer time; prompt tokens processed vs cached;
  each number tagged `server`, `client`, `estimated` or `unavailable`. The engine probe runs here too, at
  start: reasoning channel, whether the server reports timings and cached tokens, context size.
- **Correlated with the journal:** each call is logged against the harness's request digest
  (`ModelRequested`, RH §7.2).
- **One engine layer:** it also replaces rustybenchmark's `bench-model` for single-shot runs.

**Engine differences to confirm in a spike:** reasoning arrives in a separate field (e.g.
`reasoning_content`) on some engines and inline `<think>` tags on others; llama.cpp returns a `timings`
object while Ollama reports durations on its native API; Ollama's small default context (docs/04) is
exactly what the probe must catch; model identity comes from llama.cpp `/props`, Ollama `/api/show` or
`/v1/models`, always stored as a claim.

**The engine is a variable too.** Engines differ in speed, and slightly in output, so the same
data-sparsity argument that fixed the harness applies. Record engine and version on every row. For the
FYP, use one primary engine (llama.cpp, which runs on Metal, CUDA and Vulkan), and compare engines only
if time allows.

**Fallback, if keeping two transports in step proves fragile:** a stream-observer callback on the
harness's own client, which any app showing live output could use. It doesn't make the agent's code
better, so under §0 it needs Iwan's explicit OK.

## 6. Generic features core rustyharness gains

| ID | Feature | In the wild | In benchmark mode | In RH v0.1 today |
|---|---|---|---|---|
| H-1 | **Ports grant:** bind and connect on listed ports, never the model server's | Opened with the user's permission | The fixed loopback range, pre-granted | No: the sandbox denies all network, and the egress proxy refuses loopback (RH §6.5) |
| H-2 | **Background processes:** spawn, read output, stop; all killed at run end | A developer's normal workflow | The agent runs its server and hits it with its own client | No |
| H-3 | **Extra paths and environment in the sandbox:** read-only mounts, a writable build directory outside the workspace, env and cargo config | The user's own cargo setup and caches | The local crate set and pre-built cache, read-only | Exec allowlist designed (H2); mounts and env are not |
| H-4 | **A stable embedding surface:** `harness-run`, `ModelBackend`, the public journal reader, the `__confine` dispatch on Linux | Any app can embed the harness | The benchmark app embeds it | Designed (RH §1.2, §3.1) |
| H-5 | **Prune:** delete a finished run's workspace and scratch, keep its journal and snapshots | Disks don't fill up | The reset between tasks | No |

The harness's own roadmap supplies the rest of in-the-wild parity with opencode and Cline: internet
through the allowlist proxy and MCP providers (phase H4), an opt-in shell (RH §4.8), hosted models by
opt-in (RH §3.2). Benchmark mode switches all of them off.

## 7. What rustybenchmark builds (no harness change)

| ID | Piece |
|---|---|
| B-1 | The grader and its grading sandbox on macOS, Linux and Windows (`bench-sandbox` is macOS-only today; see §9) |
| B-2 | The instrumented model transport (§5), replacing `bench-model` |
| B-3 | The task-spec writer and the benchmark preset: profile values, grants, visible checks |
| B-4 | The run index: task id, family, generator version, seed, epoch ↔ harness run id |
| B-5 | Journal analysis: trajectories, format errors, tool-call validity, the toolset identity docs/15 §3.4 puts in the row key, crate events |
| B-6 | Re-grading earlier states (§4.3) |
| B-7 | The local crate set, the pre-built build template, the crates.io name and version list (measurement-plan §5.2, §6.6) |
| B-8 | Integration tests (§8) and `rustybench doctor` |

## 8. Keeping it frictionless

1. **One-way dependency.** The embedding surface (H-4) and the preset format (BM-2) are versioned; a
   breaking change is a harness major version.
2. **Integration tests in rustybenchmark's CI.** Three to five fixture tasks (one per level, plus a
   client–server one) run end to end on the harness's `Scripted` backend, with no LLM: spec → loop →
   submit → deliverable → grade → score. They run on every harness bump.
3. **Benchmark-mode tests.** In the same suite: a planted user config and rules file are ignored; a tool
   that would ask for approval is denied; network beyond the preset's ports is blocked; the run refuses
   to start when a control can't be enforced.
4. **Golden journals.** One real run per fixture, replayed with the harness's `Replay` backend (RH §2.9),
   catches drift in context building or telemetry.
5. **Wire-identity test** for the transport (§5).
6. **A handshake before any model call.** The benchmark checks the harness version and that the grants
   its configuration needs are available on this OS. Otherwise it refuses to start.
7. **`rustybench doctor`.** One command checks the engine, the harness, both sandboxes, the toolchain,
   the crate set and the ports, and answers green or red with the fix for each red.
8. **Governance.** Harness changes go through rustyharness's own review; the benchmark adapts to the
   harness, never the other way round.

## 9. The cost of two sandboxes

With grading outside the harness there are two sandboxes, each needed on three OSes: the harness's (for
the agent's commands) and the benchmark's (for grading). Windows is the risky one in both.

- **Two independent sandboxes:** the simplest reading of the rules, but double the work.
- **A standalone confinement crate that both depend on (recommended):** neither project depends on the
  other, and the Windows work happens once. `gate-outcome` already sets this precedent for outcomes
  (RH §1.4).

rustyharness's design proposed sharing `harness-sandbox` with the benchmark (RH §6.3; its open
question 5). Under the rules in §0, sharing goes through a standalone crate instead.

## 10. Open questions

1. Embed `harness-run` (recommended), or run the CLI as a child process?
2. Two sandboxes, or one standalone confinement crate used by both (§9)?
3. ~~Benchmark-mode mechanisms: generic features or an add-on?~~ Answered 24 Sep: rustyharness's
   embedding API already provides them, so there is no add-on (§2).
4. Transport: a benchmark-owned `ModelBackend` (recommended), or a generic stream-observer hook in the
   harness's client (§5)?
5. One primary engine for the FYP (llama.cpp), with an engine comparison only if time allows?
6. Remote model hosts (rustyharness's open question 10): out of FYP scope?

## Version history

- **v0.1:** first contract; grading ran inside rustyharness as a hidden check.
- **v0.2:** rustyharness stays standalone; grading, timing and measuring move to rustybenchmark.
- **v0.3:** rustyharness is a full coding agent on its own; rustybenchmark switches on a locked-down
  benchmark mode (a suite add-on). Grading and measuring stay in rustybenchmark.
- **v0.4:** checked against rustyharness `6ba3437`. Benchmark mode is a configuration, not code: the
  embedding API already provides every piece, so the add-on and its cargo feature are dropped.
