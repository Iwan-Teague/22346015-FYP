# Measurement plan: how Rustybenchmark will test local models

Draft v0.10 · 24 Sep 2026 · Iwan's decisions from the 24 Sep chat + Claude's recommendations. Not yet
discussed with my supervisor. Version history at the end.

**Labels:** **Decided** = Iwan's call · **Proposed** = recommendation, needs Iwan's OK · **Open** = undecided.
Code facts were checked against rustybenchmark `215f573` (branch `agent/collatz-zero-start`) on 24 Sep.
`docs/NN` means the rustybenchmark design doc with that number.

> **This is bigger than what my supervisor has seen.** The one-pager describes one answer per task, compiled and
> tested in a sandbox, plus one retry with compiler feedback (RQ5). This plan adds an agent loop with
> tools, a sandboxed task environment, and three levels of task. Tell my supervisor, and update the proposal-form
> description, before the form goes out. The full range described here is roadmap-scale (the roadmap
> plans 12–30 months for the task corpus alone), so the FYP needs a cut (§11).

## 0. Decisions so far (Iwan, 24 Sep 2026)

Every decision made so far, in one place. The sections listed hold the detail; the harness contract is
[rustyharness-contract.md](rustyharness-contract.md).

| # | Decision | Where |
|---|---|---|
| D1 | Three levels of task: Level 1 small logic tasks; Level 2 practical builds (servers, CLI tools, data, dashboards, …); Level 3 changes to existing code | §2 |
| D2 | Keep a big set of Level 1 "one-shot logic" families as the gauge of Rust skill | §2.1 |
| D3 | Wide range inside every family. The seed generates everything (prompt, tests, grading tools, categories); no exact answer can be learned by heart | §2.4, §7 |
| D4 | The agent works in a loop over many iterations and calls a submit function when it's done. Grading starts then; until then the loop keeps re-prompting. **Review (T3, T6): core confirmed; both propose additions for a model that never submits. Back to Iwan** | §4 |
| D5 | The agent has the Rust toolchain on every level | §5.1 |
| D6 | The model chooses its crates. Anything in the local set is usable, common crates are pre-built, and nothing is downloaded during a benchmark run | §5.2 |
| D7 | A crates category for Levels 2–3: invented crates, old versions, and so on | §6.6 |
| D8 | The software builds the sandbox itself: toolchain, local crates, a few local ports, no internet | §3 |
| D9 | One sandbox, one task at a time: run, grade, reset, next | §3.1 |
| D10 | No VMs and no external container runtimes (Docker, Podman): native OS sandboxing for each OS. **Confirmed by review T1 (KEEP), 24 Sep.** | §3.3 |
| D11 | Rustybenchmark is a downloadable app for Windows, Linux and macOS, with a sandbox tailored to each | §3.3 |
| D12 | Everything on one device: the model behind a local API on a local port, and the harness and the code on the same device. **Confirmed by review T2 (KEEP), 24 Sep.** Proposed addition, not yet accepted: a startup check that warns when the model server accepts requests from any web page (llama.cpp's default) | §3.5 |
| D13 | Prefill, reasoning and output speed are recorded | §8 |
| D14 | Toolchain time is left out of the headline: the score is the code produced plus model time. A remote inference host is credited as the hardware ("done on a DGX Spark"). **Review T6: MODIFY (pre-register the formula; also report wall-clock, cost and the prefill share). Back to Iwan** | §3.5, §8 |
| D15 | OS, hardware and model are captured automatically | §9 |
| D16 | rustyharness is enforced and pinned for every agent-mode run. **Reviews: T6 KEEP (epoch as a hash tuple); T5 MODIFY (pin a tag and commit; a new release stays in the epoch only if it replays the golden journals cleanly; write the ADR that supersedes rustybenchmark ADR-0010's minimal multi-agent board). Back to Iwan** | §4 |
| D17 | Anything used for grading or measuring lives in rustybenchmark, never in rustyharness. **Confirmed by reviews T5 and T6 (KEEP), 24 Sep.** T5's proposed rewording, not yet accepted: "the harness never scores or computes an app's metrics; it records generic facts with their method", plus a promise that journals stay readable across versions | §4, contract §0 |
| D18 | rustyharness stands on its own as a full coding agent, like opencode or Cline. Suite integration comes as add-ons, and rustybenchmark switches on a locked-down benchmark mode. **Reviews: T6 KEEP; T5 MODIFY (split a frozen study line from a "wild" line on `development`; replace "like opencode or Cline" with a parity checklist; make "reads no user config" a gate rule). Back to Iwan** | §4, contract §1–§2 |
| D19 | Level 2 domain order: decided later | §2.2 |
| D20 | The second test machine is the GPU PC with an RTX 3070, running Linux | §3.3 |
| D21 | macOS cleanup: build the corrected cleanup sweep in H2. If it slips past about 1 November, fall back to a written, dated acceptance of process-group kill for `exec.run` only. **Confirmed by review T1 (KEEP), 24 Sep.** Proposed hardening, not yet accepted: a planted `setsid` escape in the live self-probe as an H2 exit gate; taint marking lands before the fallback is ever used. T2 suggests spiking a dedicated agent user on macOS, which could replace the sweep | §11 |
| D22 | Every test, Level 2 network tasks included, must run on both Linux and macOS, for anyone who downloads the app. Linux is built first; Windows is the goal, but not now. **Confirmed by review T1 (KEEP), 24 Sep.** | §3.3 |
| D23 | The model's context size is logged on every run: native, configured and used | §9 |
| D24 | Tool packaging scales with model size through rustyharness's per-model profile: smaller models get fewer, merged tools, larger ones may get them separately. Every model gets the same capabilities; only the packaging differs, and it is recorded per run. A pilot on one model checks whether packaging changes scores. **Reviews T3 and T6 both say: for benchmark runs, one fixed packaging for every model; size-scaling becomes a product setting and a separate multi-model ablation. Back to Iwan** | §4.3 |
| D25 | Level 1 tasks are std only: Rust's standard library, no crates | §5.3 |

rustyharness decisions made on 24 Sep. All went to adversarial review, with a prior-art check against other harnesses. Each row carries its review state; the details are in `decision-reviews/SYNTHESIS.md`:

| # | Decision | Where |
|---|---|---|
| D26 | Online coding on private repos: the trifecta rule stays, and a safe path (e.g. a quarantined reader model) is built in H4 alongside the internet proxy. **Review T2: MODIFY (the H4 safe path removes internet access instead: harness-fetched crates, offline docs, separate research sessions; no dual-LLM planner for 7–30B models). Back to Iwan** | contract §1 |
| D27 | One shared sandbox library for rustyharness and rustybenchmark's grading. It is staged inside rustyharness during H2, then moved to its own repo before the benchmark uses it. **Confirmed by review T1 (KEEP), 24 Sep.** It depends on D29 converging on one Linux backend | contract §9 |
| D28 | Build order: app-supplied folders and settings, `gc` and the macOS sweep go in H2. Ports and background processes go in H2+, and are designed and reviewed during H2 | §4.2 |
| D29 | Linux: one private network namespace per run, not per command, in H2. **Challenged by spike S-L1: stock Ubuntu 24.04 blocks unprivileged user namespaces. Review T1: MODIFY (default Linux backend = the accepted S-L1 trio: Landlock, seccomp, systemd scope, cgroup tree-kill; per-run network namespace becomes a probed opt-in tier). Back to Iwan** | §3.3 |
| D30 | A granted localhost port counts as internet (E) for the trifecta rule. **Review T2: MODIFY (one approval per session instead of a hard refusal). Back to Iwan** | §3.5 |
| D31 | Ports visible on the network: not in v1. They are designed now as a separate, high-risk opt-in. **Confirmed by review T2 (KEEP), 24 Sep.** Proposed addition, not yet accepted: no sandbox layer ever grants a bind on a shared network stack | §3.3 |
| D32 | macOS network tasks: a transparent socket swap first. If it fails, a pf firewall guard (admin once). **Review T2: MODIFY. Measured on this Mac: `sandbox-exec` and the bash `cargo` shim strip the interposer; `listen()` is refused unless it is interposed too; the swap drops the socket flags; pf can't be checked without root. Back to Iwan** | §12 item 18 |
| D33 | Linux kernels older than 6.7: any port is allowed inside the per-run private network. **Challenged by spike S-L1; T2 says refuse port grants on Linux without a network namespace. Review T1: MODIFY (a per-run capability matrix with fail-closed ports). T1 and T2 disagree on ports without a namespace. Back to Iwan** | §3.3 |

## 1. The shape

```
 ┌─► reset slot ─► load task: seed ─► spec ─► workspace + prompt
 │                     │   (slot: toolchain, local crates, fixed ports, no internet)
 │     ┌───────────────▼───────────────────────────────┐
 │     │ agent loop: model ⇄ harness actions           │
 │     │ watchdog: re-prompts, budgets, loops, stalls  │
 │     └───────────────┬───────────────────────────────┘
 │                     │ submit
 │                     ▼
 │  kill processes ─► keep source only (hashed) ─► add hidden tests ─► rebuild ─► grade
 │                     │
 │                     ▼
 │  journal: scores · failure classes · timings · environment · transcript · snapshots
 │                     │
 └─────────────────────┘ next task
```

"Agent" in this document = a local model driven by rustyharness (§4). Every result reads "model X under
rustyharness vN". The harness is fixed for the whole study, so the one-pager's principle (my own minimal
harness, not an agent tool like opencode) still holds.

## 2. Three levels of task (Decided)

| | Level 1: Units | Level 2: Builds | Level 3: Changes |
|---|---|---|---|
| Task | Small logic task: one function or type ("one-shot logic") | Make a working program from a spec: a server on a given port that does Y, a CLI tool, a data pipeline, a dataset, a dashboard… | Change an existing codebase: add a feature, fix a reported bug, change behaviour across modules, without breaking what works |
| Size | One file (`src/lib.rs`) | Small project, several files | Existing code, ~1–5k lines, bigger than the context window |
| Iterations | Yes (toolchain), small budget; first try also scored (§6.2) | Many; agent calls `submit` when done | Many; agent calls `submit` |
| Crates | std only by default (§5.3) | Model's choice from the local set; common ones pre-built (§5.2) | The codebase's own crates pre-built; model may add from the local set |
| Ports | None | The slot's fixed range (§3.3) | If the codebase needs them |
| Graded by | Existing oracle | A contract + conformance tests (§6.3) | Hidden tests for the change + full regression suite + where the agent looked and edited (§6.4) |
| Volume | Hundreds of families × many seeds | Dozens of families, few seeds each | Dozens of tasks |
| Statistics | Rankable (core categories at `deep`) | Directional (probe class) unless a pilot shows otherwise | Directional |
| Main RQs | RQ1, RQ2, RQ3 | RQ1 (do failures change as tasks grow?), RQ5 (does iterating help?) | RQ1 + my supervisor's comprehension and feature-location themes |

"Level" is used to avoid a clash with the repo's suite tiers (`smoke` / `standard` / `deep`).

### 2.1 Level 1: Units

The existing families: 108 today, 272 planned, 11 categories. Toolchain on, std only, small turn budget.
Snapshot grading keeps a genuine first-try number (§6.2).

**Optional add-on (Proposed):** a comprehension family set with exact answers: "what does this program
print?", "which line fails to borrow-check?". It separates *reading* Rust from *writing* Rust, is cheap
to grade, and fits my supervisor's comprehension theme.

### 2.2 Level 2: Builds

Range comes from a catalogue of domains, each with several families:

| Domain | Example families | Contract the program must honour |
|---|---|---|
| Network services | Line-protocol key–value store, chat relay, pub/sub broker, rate-limited proxy | TCP on an assigned port; protocol from the spec |
| Web APIs | CRUD JSON API over seeded resources, URL shortener, job-status service | HTTP routes, JSON shapes, status codes |
| CLI tools | Log analyser, CSV → JSON converter, config validator, duplicate-file finder | Arguments, stdin/stdout format, exit codes |
| Data | Clean a seeded messy CSV, aggregation report, generate a dataset meeting constraints | Output files: paths + schema |
| Dashboards | Metrics dashboard over a seeded dataset, service status page | HTTP page on an assigned port; values in server-rendered HTML marked with `data-testid`; chart data at `/api/…` |
| Concurrency | Job queue with workers, TTL cache, event scheduler | Library API or CLI, checked by invariants under load |
| Languages | Expression evaluator, config-format parser, binary-protocol decoder | Input → output |

**Range is bounded by the contract, not by the idea.** Anything gradeable through the same kind of
contract can share one conformance runner (§6.3), so adding breadth is mostly adding generators.

### 2.3 Level 3: Changes (Decided)

Why changing existing code is the right third level:

1. **It is the real amalgamation:** Level 1 precision inside Level 2-sized code.
2. **It is most real work.** Real Rust fix patches average 9.8 files and 139.9 lines (docs/04).
3. **It forces navigation.** Code bigger than the context window makes the agent search and read
   selectively. docs/04 says true repo navigation needs tools and deferred it to the agentic track as
   `repo-navigation`; the harness makes it measurable.
4. **It lands on my supervisor's research:** software comprehension, feature location, architecture recovery. The
   generator knows where each feature and each injected bug lives, so "did the agent find the right
   place?" is measurable without human judging (§6.4).

Codebases come from seeds too. The cheapest source is Level 2 reference projects (a working seeded
server, CLI tool or dashboard), plus a seeded change request or injected bug. Task kinds:

- Add a feature
- Fix a reported bug (symptom given; cause injected by the seed)
- Change a behaviour that spans modules
- Answer a location question ("which function decides X?"), graded exactly

**Alternatives considered:**

- **Multi-stage builds:** build v1 → extend → extend, each stage graded with earlier stages as regression
  tests. Measures how errors compound. Could be a Level 3 variant ("evolve your own code").
- **Test writing:** the agent writes tests for given code, graded by mutation score. Already planned as
  the `test-authoring` probe category.

### 2.4 Range within a family

A family = one kind of program + a feature space. The seed picks features, then randomises the surface
(names, values, messages). Example, a web API family:

- Resources: 1–3, with seeded names and fields
- Endpoints: a subset of list / get / create / update / delete / search
- Validation: required fields, ranges, formats
- Pagination: none / offset / cursor
- Error format: a seeded JSON shape
- Auth: none / API-key header
- Storage: memory / file / SQLite

That gives thousands of distinct specs from one family, all graded by the same runner. Each instance
records its difficulty features (§7.4).

## 3. Task environment: one sandbox, reset between tasks (Decided)

### 3.1 The cycle

One sandbox slot, one task at a time:

1. **Reset the slot.** Also done when a run starts, so anything a crash left behind is cleaned first.
2. Load the task's workspace (skeleton, data files, or an existing codebase) and write the prompt.
3. The agent works until `submit` or the budget runs out.
4. **Kill every process** in the slot's process group; check the slot's ports are free.
5. **Keep only the source files** (the hashed snapshot); wipe build output and the task's cargo home.
6. Copy the hidden tests in, rebuild from source, grade.
7. Write the result and its evidence (transcript, source snapshots) to the journal.
8. Back to step 1 for the next task.

rustyharness covers steps 2–4 (materialise the workspace, run the agent, kill what it started). Steps
5–7 are rustybenchmark's alone: it grades the deliverable in its own grading slot and sandbox (§4.2).
The reset uses the harness's generic prune (contract H-5).

Why (Decided):

- **Fixed disk footprint.** Measured: today's grader keeps one workspace per unit (`runs/ws/<unit>`)
  and never deletes it. The 26 smoke-run units left 74 MB (~2.8 MB each), so a `deep` run would leave
  ~3.5 GB. Level 2 projects that build tokio or axum can reach hundreds of MB to GBs each.
- **Crashes still produce results.** Each result reaches the journal before the reset, so a crash loses
  at most the task in progress. Resume already exists: `run-suite` skips units the journal already has.
- **Simpler ports.** Tasks never overlap, so a small fixed range is enough (§3.3).
- **Cleaner timing.** Nothing else competes with the task for CPU, memory or GPU.

Why steps 4–5 (clean before grading) matter, even with one slot:

- The agent's own server may still hold the port. The grader's freshly built server then can't bind and
  fails wrongly, or the grader talks to the old process, including a canned-answer server left running
  on purpose.
- `target/` may not match the final source (the agent edited after its last build).
- Extracted crate sources in the cargo home could have been edited, changing the grading build.

Trade-offs:

- Grading no longer overlaps the next task's generation, so total wall time grows. Worth it for clean
  timing.
- One slot = one run at a time per machine. Each machine runs its own harness and sandbox (§3.3).

What survives resets: the toolchain, the local crate set and the pre-built build template (all
shared, read-only) and the journal. Evidence stays
small: transcripts and source snapshots are KB per task, enough to audit, re-grade and do the trajectory
analysis (§6.5). Build output is never kept.

### 3.2 What's inside the slot

| Part | Rule |
|---|---|
| Workspace | Loaded from the task spec each task. The only writable place |
| Cargo home | Fresh for every attempt, created by rustyharness from typed fields (OD-5(c) draft: an embedder can't supply its own). Nothing needs unpacking into it, because the crate set is a directory source (§5.2) |
| Toolchain | Pinned `cargo`/`rustc` 1.98.0 (the repo's pin), shared, read-only |
| Crates | The local set only (§5.2): commonly chosen crates pre-built, the rest compile on demand; shared, read-only; per-level policy (§5.3) |
| Pre-built crates (Decided) | Commonly chosen crates are compiled at setup into a read-only build template. Measured on this Mac (OD-5 review, M-12, 24 Sep): cargo's fingerprints survive a new cargo home only when the crate set is a directory source at a fixed canonical path. A local registry unpacks crates into the cargo home and rebuilds them. Reset clones it into the slot (copy-on-write where the filesystem allows, e.g. APFS). If the agent picks a pre-built crate with the same version and features, its build reuses it; anything else compiles on demand. The grader rebuilds on a fresh clone of the same template, never on the agent's build output |
| Network | No internet. Loopback only, on the slot's fixed port range (§3.3) |
| Processes | One process group, killed at `submit` or abort. Background processes only if rustyharness gains a spawn/stop tool (contract H-2) |
| Limits | Wall clock per command and per task (harness-owned), CPU time. Memory and disk watched by the watchdog, because macOS enforces memory rlimits unreliably |
| Hidden from the agent | Reads of `$HOME` outside the slot, toolchain and cargo home are denied (built, AQ-200): no benchmark source, reference solutions, seeds, journal or other runs. Hidden tests and grader tools (HTTP/TCP clients, HTML parser, schema checks) live only in rustybenchmark; rustyharness never sees them |

A one-time setup step downloads the toolchain and builds the local crate set with internet access. Every run
after that is offline.

### 3.3 Native sandbox on every OS (Decided: no VMs)

Realism rule: the benchmark runs the way a real user runs a local model, natively on their own OS.
Rustybenchmark ships as a downloadable app with Windows, Linux and macOS versions, each with a sandbox
tailored to its OS (Decided). A Linux VM or container would reserve RAM the model needs (on 24 GB of
unified memory that decides which models fit), and no Windows user runs their coding agent that way.
So each test machine is a complete install: model server, harness and sandbox on one device (§3.5).
For RQ2's two-machine comparison, the second test machine (the GPU PC) is its own complete install,
so it needs a native sandbox for its OS.

| OS | Mechanism | Private localhost? | Status |
|---|---|---|---|
| macOS | seatbelt (`sandbox-exec`) | No: allow only the slot's ports | Built, except ports |
| Linux | Network namespace + bubblewrap/landlock | Yes | Roadmap P1; well-trodden |
| Windows | AppContainer + job objects | No | Roadmap P1, flagged as the risky part (gate G1): toolchain ACLs, and AppContainer restricts loopback by default, which Level 2 needs |

- **One slot makes ports simple:** a small fixed range (e.g. 3 ports), picked at setup, never including
  the model server's port, checked free before each task. Tasks say "listen on the port given in
  `--port`" rather than hard-coding a number. Where localhost isn't private (macOS, Windows), the sandbox
  allows only those ports and the free-port check catches leftovers.
- **The OS of the second test machine (the GPU PC) decides which sandbox the FYP builds next:** Linux is
  moderate; Windows is the risky item on the roadmap. Open (§12).
- **Native per OS means contracts must be OS-neutral** (§6.3), or Windows scores would differ for
  reasons that have nothing to do with the model.
- Describe the environment declaratively in the task spec, so each OS backend implements the same
  environment and tasks never change per OS.

### 3.4 What exists already

`bench-sandbox` (macOS seatbelt): all network denied; writes confined to the workspace, cargo caches and
temp dirs; `$HOME` reads denied; wall-clock kill of the whole process group; `RLIMIT_CPU` backstop.
It fails closed on Linux and Windows unless the operator passes `--allow-unsandboxed`. The grader wipes a
unit's workspace before reuse but not after, hence the build-up measured above. `run-suite` resumes from
the journal. Missing: the reset cycle, the slot's port range, background processes, the pre-built
template, local-crate-set paths, memory and disk watching, and any Linux or Windows sandbox.
rustyharness's `harness-sandbox` covers the agent's commands; grading stays in rustybenchmark's own
sandbox (Decided). Code is shared between them only through a standalone confinement crate (contract
§9).

### 3.5 One device, local API (Decided) · topology kept as an audit field

**Decided:** the model runs behind a local OpenAI-compatible API (llama.cpp, Ollama, LM Studio, vLLM)
on a local port. Rustybenchmark calls that API through rustyharness (§4), and writes, builds and tests
the agent's code on the same device. rustyharness's client connects to loopback only by default, and
refuses plain HTTP to any other address because prompts would cross the LAN in cleartext (its design
§3.2). The design docs define three attach modes (docs/15 §9.1):

| Attach mode | Meaning | Evidence |
|---|---|---|
| Managed | The app launches the model server itself | Strongest: proves same device, and server settings (GPU layers, KV-cache type, threads, flash-attention) become host-verified |
| Colocated | The user's own server, on this device | Proven by finding the process that owns the API port |
| Remote | Another device serves the model (e.g. a DGX Spark serving a laptop) | Declared: the app can't see what's behind the URL. Needs TLS or rustyharness's planned LAN add-on |

**Decided: toolchain time is left out of the headline numbers** (§8). Headline throughput counts model
time only, so where cargo runs matters much less:

- **Capability and model-time throughput are comparable across topologies.** A remote run is logged as
  done on the inference host ("done on a DGX Spark"), because that is where the model time is spent. The
  harness host only runs the harness, the sandbox and cargo, whose time is recorded but not scored.
- **Topology stays as an audit field**, detected rather than asked: `same-device` when managed, or when
  the process listening on the API port is a local model server; `remote` when nothing local owns the
  port, or its owner is a tunnel (e.g. `ssh`). A port owned by a VM or container runtime is recorded as
  same-device, virtualised. rustyharness also records the endpoint class (loopback, LAN add-on, hosted)
  in every journal header.
- **What remote still changes:** the network hop sits inside client-side timings (use server-reported
  timings, §8); the inference host's hardware has to come from the app run in probe mode on that
  device, or it is user-declared and marked unverified; and a URL can't prove what's behind it (it
  could even be a cloud API), so remote rows sit in a lower evidence tier. That matters for a public
  leaderboard later, not for the FYP.
- **FYP study:** every run same-device, which is also rustyharness's default. Remote is future work,
  through TLS or the LAN add-on.

## 4. The harness: rustyharness, enforced and pinned (Decided)

Every agent-mode run goes through **rustyharness** (`rustyharness`),
Iwan's standalone agent harness. Why enforce one harness: harness effects are the same order of size as
model effects (docs/15 §3.4: turning tools on moved the same model by 10.7 points on SWE-bench), and with
hardware, model *and* harness all open, no single combination would ever collect enough data. Fixing the
harness leaves two free variables: the model (with its quant and settings) and the hardware.

**How it is enforced:** the app ships rustyharness built in, as a pinned dependency; there is no "bring
your own harness" mode. Every row records the rustyharness version and the benchmark profile's digest
(§4.3), and a new harness version starts a new epoch whose results are not pooled with the old ones.
rustyharness's own design already plans this: "one pinned, versioned harness" for the benchmark (its
overview, use U3; phase H5).

**In the wild vs benchmark mode (Decided):** on its own, rustyharness is a full coding agent like
opencode or Cline: internet, live crates and ports on the device, all with the user's permission. Suite
integration comes as add-ons, off by default. rustybenchmark runs it in benchmark mode, a locked-down
configuration that its embedding API already accepts (no add-on code; verified against `6ba3437`), so the
agent works in the benchmark's environment: only the local crates, only the benchmark's ports, no
internet, a fixed toolset and settings, no user config or rules files, and no approval prompts. Benchmark
mode never grades or measures (contract §1–§2).

**State (checked 24 Sep at `origin/main` `6ba3437`):** started 23 Sep 2026, all in the FYP period.
Design reviewed SOUND. Phase H1 (the read-only agent) is built, with CI green on macOS, Linux and Windows;
H2 (execution) is next, so nothing executes tools yet. Alignment with this plan:
[rustyharness-alignment-2026-09-24.md](rustyharness-alignment-2026-09-24.md).

### 4.1 What the plan needs, and where rustyharness has it

| Plan needs | rustyharness (design v0.1) | Phase |
|---|---|---|
| Agent says "done" | `harness.task.submit`: a request for verification, never a verdict (D5) | H1 |
| One action per turn | A text `<action>{…}</action>` block, or native tool calls, chosen per model profile; unknown models default to text (§3.3–3.4) | H1 |
| Watchdog | 3 consecutive format errors stop the run; loop detection (repeats, edit churn, no progress, denial hammering); typed stop causes (§2.2, §2.5–2.6) | H1 |
| Context | Rebuilt every turn with a stable prefix; old observations collapse to pointers, never summaries; last K turns verbatim (§2.3) | H1 |
| Budgets | Steps, tokens, wall-clock, format errors, repair rounds; verification has its own budget (§2.4) | H1 |
| Tools | `fs.read/search/list`, `edit.replace/write`, `exec.run` (argv against an allowlist; no shell by default), `notes.write`, `task.submit` (§4.8) | H1–H2 |
| Sandbox | `harness-sandbox`: Linux namespaces + Landlock + seccomp, macOS seatbelt, Windows AppContainer; fails closed until a conformance suite passes (§6) | H2 |
| Grading | Not the harness's job: rustybenchmark grades the deliverable itself (§4.2). The harness only runs the visible checks any user would give it (build, visible tests) | H3, not needed for scores |
| Evidence | Hash-chained, write-ahead journal; snapshots after each write; replay and resume (§2.8–2.10, §7) | H1–H3 |

**Rules (Decided):** rustyharness knows nothing about benchmarks; benchmark mode is purely the
benchmark's configuration of it, and it locks the environment down without grading or measuring. Anything used for grading
or measuring lives in rustybenchmark. A core harness change is justified only if it makes any agent's
work better. Full contract: [rustyharness-contract.md](rustyharness-contract.md).

### 4.2 What rustyharness gains, and what stays in rustybenchmark

**Core rustyharness gains only generic features that make any agent's work better** (contract §6):
ports for the agent's own servers (H-1), background processes (H-2), extra read-only paths and
environment for offline crates and a warm build cache (H-3), a stable embedding surface (H-4), and a
prune for finished runs (H-5). **Benchmark mode needs no harness code:** the embedding API already takes the benchmark's
policy, provider registry, profile and backend, and denies anything that would ask when no approver is
present (contract §2).

**rustybenchmark keeps everything else** (contract §7): the grader and its own grading sandbox on all
three OSes; an instrumented model transport plugged in through the harness's `ModelBackend` trait
(timing and engine probe, §8); the benchmark profile values written into each task spec (§4.3); the run
index; journal analysis; re-grading earlier workspace states; the crate set and build template;
integration tests.

**Schedule:** the benchmark's scores don't depend on rustyharness's verification phase (H3). The critical
path is H2 (confined tools) + H-1 to H-3; H1 (the loop) is built. rustyharness's phases are strictly ordered and
its benchmark entry is currently last (H5), so H-1 to H-3 need scheduling early.

### 4.3 The benchmark profile (Proposed)

The rustyharness settings the benchmark pins, identical for every model (defaults from its design §2.4):

| Setting | rustyharness default | Benchmark (Proposed) | Why |
|---|---|---|---|
| Steps | 50 | e.g. 20 for Level 1, 60 for Levels 2–3 | Pilot decides |
| Tokens | Profile-derived | A fixed cap per level | Hardware-neutral |
| Wall-clock | 30 min, a hard stop | A generous safety cap only, recorded as `timeout_wall` | A slow machine must not get fewer turns, or capability becomes a hardware measure (reverses docs/04's time-boxing → ADR) |
| Repair rounds | 1 (visible diagnostics; hidden checks only say "failed") | 0 for the headline score; a repair round only as a separate RQ5 measure | The agent alone decides when it's done |
| Reviewer run | Built in (§7.5) | Off: the hidden checks are the judge | A reviewer adds model time and bounces work |
| Protocol | Per model: native if its smoke test passes, else text | Open: keep the per-model choice and record it, or force text for all | What a user would get vs one protocol for everyone |
| Recent turns K, active tools | From the model profile; 5–8 tools | Fixed for all models | Same harness for everyone |
| Context size | From the model profile | One size for the study (e.g. 32k), never beyond the model's native window (docs/06) | Comparability |

## 5. Toolchain and crates

### 5.1 Toolchain (Decided: every task gets it)

Realistic: anyone asking an agent for Rust gives it a compiler. Consequences:

- Level 1 tasks are no longer single-shot. The single-shot number is kept anyway through snapshot
  grading (§6.2).
- **clippy gives answers away** in constraint-dominant categories. In `idiom-refactor`, clippy's
  `help: try:` line *is* the solution (docs/03 strips it from repair feedback for exactly this reason).
  Same question for miri in `unsafe-core`. **Open:** leave them out of the agent's toolbox for those
  categories, allow lint names only, or allow them and report it.

### 5.2 Crates (Decided: the model chooses; anything in the local set is usable)

A real user asks an agent to work inside a Rust workspace they already have, on a machine where cargo
has already fetched and built crates they use. The benchmark does the same, without steering the model:

- **The model chooses its crates.** Starter workspaces don't declare any. Whatever the agent adds is
  allowed if it is in the local set, and nothing else is: no live downloads.
- **Local set (Proposed: top 500):** a snapshot of the top 500 crates by crates.io downloads on a fixed
  date, plus their dependencies. They are served through cargo's source replacement as a **directory
  source** (the `cargo vendor` layout) at a fixed canonical path, because only that layout keeps the
  pre-built cache valid (§3.2). Local only, because live downloads would break:
  1. **Determinism.** crates.io changes daily; the same seed on two dates resolves different versions.
  2. **Integrity.** Internet during agent work lets an agent fetch solutions (the Terminal-Bench
     misconduct case, docs/08).
  3. **Comparability** across machines and dates.
- **Pre-built for speed only.** Commonly chosen crates are compiled into the build template (§3.2), so
  picking them is fast, as on a machine that has built them before. Pre-building never changes what is
  allowed. Pick the pre-built list from pilot data on what models actually choose.
- **Crate choice becomes data:** the crates category (§6.6).
- **Crate choice costs toolchain time.** A crate outside the pre-built list compiles from scratch, as it
  would for a real user. That time is recorded (cold vs pre-built builds marked) but left out of the
  headline throughput (§8), and capability is unaffected because budgets are in steps and tokens (§4.3).
- **Old versions (Open).** Models trained on older APIs will ask for older majors (e.g. older axum).
  Include previous majors of the top crates, or record `version_unavailable`.
- Local-set and template snapshot ids recorded in every run. Check early that `cargo add` works against
  the local set.

### 5.3 Crate policy per level (Decided for Level 1: D25)

Crates trivialise Level 1: the `lru_cache` family is solved by `cargo add lru` and a thin wrapper. So
Level 1 stays **std only** (no local set, or specific crates forbidden through the existing
`forbidden_paths` constraint). Levels 2 and 3: the model chooses from the local set (§5.2). A Level 3
codebase arrives with its own crates already declared and pre-built, like a real project. The policy
lives in the task spec (§7.2).

## 6. Grading

### 6.1 What can be deterministic

- **The agent can't be.** Sampling aside, even temperature 0 isn't reproducible across hardware: at
  99.873% per-token agreement, ~40% of 400-token generations differ somewhere (docs/08). Handle it with
  seeds × repeats and confidence intervals (RQ3).
- **The deliverable can.** It is the workspace snapshot at `submit`, hashed.
- **The verdict can.** Same snapshot + same seed → same verdict: clean offline rebuild in the cleaned
  slot (§3.1) with the pinned toolchain, build template and local crate set, seeded test inputs, a reference implementation
  generated from the same seed.
- **The agent can't steer the grader's build.** Cargo reads a `.cargo/config.toml` in the workspace
  before any other config, and honours a `rust-toolchain.toml`. So a workspace file could change how the
  grader builds (flags, runners, toolchain). Before building, the grader restores both from the starter
  workspace, or removes them. Found by rustyharness's OD-5(c) design draft, 24 Sep.
- **Where network tests could wobble:** the harness owns the ports; timeouts are generous and scaled
  from the machine's calibration (docs/05); concurrency checks test invariants that hold under any
  interleaving (e.g. no lost updates), not one particular ordering; every Level 2–3 task is graded 3×,
  and disagreement gives the verdict `flaky`. Races are real bugs, so `flaky` is a reportable failure
  mode, not noise.
- The full transcript, every action and every workspace diff are kept, so any run can be audited and
  re-graded later.

### 6.2 Level 1

Existing oracle, unchanged: apply → compile → behaviour (hidden unit tests, properties, differential
against the reference on seeded inputs) → constraints (allocation, `unsafe` cap, forbidden paths,
clippy; miri for `unsafe-core`). The final score grades the submission.

**Snapshot grading (Proposed):** after the run, also grade the workspace as it stood at each compile
attempt. This gives `first_try_score` (close to single-shot capability, though not identical: the model
has seen the workspace and the protocol) and a score-by-turn curve. One run then yields raw capability,
capability with a compiler, and the gap between them: RQ5 without a separate experiment.

### 6.3 Level 2: grade through a contract

Every Level 2 spec pins a contract: CLI arguments and output format, HTTP routes and JSON shapes, a TCP
protocol, output file paths and schemas, `data-testid` markers in HTML. **The grader never judges looks;
it checks behaviour through the contract.** Without a pinned contract there is nothing to test against.

- **One conformance runner, many families.** Each seed produces its test script as data: start the
  program with arguments → wait for `READY` → send a request → expect a reply; run a CLI with input →
  expect output and exit code; read an output file → check schema and values. A new family = spec
  generator + reference + script generator; the runner is shared.
- **Reference = one generic implementation that reads the spec** (e.g. a reference server that
  interprets the seeded protocol), so every seed is correct by construction. Same gates as Level 1
  (ADR-0003): reference scores 1.0, skeleton fails, degenerate answers fail.
- **Network services:** four-way matrix. Agent server ↔ reference client (scripted session, exact
  replies); reference server ↔ agent client; agent ↔ agent; robustness (malformed and oversized input,
  abrupt disconnects, N concurrent clients with no lost updates, clean shutdown).
- **Dashboards:** values must appear in the **server-rendered** HTML, marked with `data-testid`, and
  chart data at a JSON endpoint. That keeps grading browser-free and deterministic. Looks are not
  scored; screenshots may be kept for qualitative discussion only. Grading JavaScript-rendered pages
  would need a headless browser (Open; probably out of scope).
- **Data tasks:** deterministic transforms are checked row for row against the reference output.
  Generated datasets are checked by properties: schema, row count, uniqueness, ranges, referential
  integrity, distribution within tolerance.
- **CLI tools:** seeded inputs → exact output and exit codes, plus differential checks against the
  reference on generated inputs (the Level 1 differential oracle, at program scale).
- **OS-neutral contracts** (every OS runs natively, §3.3): shutdown through a protocol message or a
  closed stdin, not signals (Windows has no SIGTERM); line endings normalised; no hard-coded paths or
  path separators.
- Score = fraction of checks passed per group, plus a full-pass flag.

### 6.4 Level 3

- Hidden tests for the requested change.
- The full original test suite as regression tests: breaking old behaviour counts against the change.
- **Feature-location accuracy:** the files and functions the agent read and edited, compared with where
  the generator placed the feature or bug.
- Diff size and files touched, compared with the reference change.

### 6.5 Failure classes (RQ1)

**Built:** borrowck, trait, type, lifetime, async-send, syntax, resolve, idiom, logic, constraint,
other. Classified from error code + message patterns (codes alone are blind or ambiguous for about a
third of cases, docs/03). Borrow counts are a lower bound, because type errors stop rustc before the
borrow checker runs.

**Proposed additions:**

- Split `logic` into panic / wrong output / timeout.
- Agent level: `protocol_failure`, `stuck_loop`, `budget_exhausted`, `never_compiled`. rustyharness's
  stop causes map onto these (§4.1).
- Crate mistakes and choices: the crates category (§6.6).
- Level 2: `interface_mismatch`, `protocol_violation`, `hang`, `concurrency`, `flaky`.
- Level 3: `regression` (broke existing behaviour), `wrong_location` (edited somewhere other than where
  the feature or bug lives).
- **Trajectory view:** every compile error hit along the way, not just the final one. Which errors
  models fix, which they never fix, and how many turns fixing takes. This fits my supervisor's
  AI-generated-code theme.

### 6.6 Crates category (Decided for Levels 2–3)

Measured on every Level 2–3 task, since those are the tasks where the model picks crates. Reported per
model as its own category, separate from the build score so one mistake isn't counted twice
(Proposed).

| Measure | How it is detected |
|---|---|
| Invented crate | A requested name that doesn't exist on crates.io at the snapshot date |
| Real crate, not in the local set | Exists on crates.io but outside the local top 500. An availability limit, **not** a model error; reported separately |
| Invented version | A version requirement that no release ever satisfied |
| Outdated version | A requirement older than the local set's release (e.g. an old axum major). Recorded from `Cargo.toml` whether or not the local set can serve it (§5.2; open decision 8) |
| Invented or outdated API | Compile errors that point into a real crate's namespace (unresolved import, missing method or type) |
| Missing feature flag | Using an item behind a crate feature that wasn't enabled, matched from the compiler's message |
| Crate choices | Which crates each model reaches for, and how popular they are |

Telling "invented" apart from "not in the local set" needs the **full crates.io name and version list**
(metadata only, small) from the same snapshot date as the local set. Without it, the local set's
boundary would be counted as hallucination.

**Sharpest test (Proposed):** Level 3 codebases pinned to a recent crate major. A model that writes the
older API fails in a way the classifier can name. This overlaps docs/04's planned `api-evolution`
category and feeds RQ6 (knowledge cut-off).

## 7. One seed → the whole task

### 7.1 Already built for Level 1

`Generator::generate(seed)` is pure in the seed and returns: prompt, workspace files, hidden oracle
files, category, constraint settings (`unsafe` cap, forbidden paths, clippy on/off + allow-list) and
oracle weights. Each family also provides `reference_code(seed)` (must score 1.0), `skeleton_code(seed)`
(must fail) and degenerate answers (must fail). Every instance carries a canary string for leak
detection. Seeds are `blake3(epoch ‖ task_id ‖ index)`, so each epoch gets fresh seeds.

### 7.2 What the task spec needs to add (Proposed)

- Level, and environment needs: ports, crate policy, starter workspace, network profile (§3, §5.2–5.3)
- Agent toolbox: which commands; clippy/miri or not (§5.1)
- Budgets: steps, tokens, wall-clock safety cap (§4.3)
- Contract + conformance test script (Level 2), or change request + regression suite + ground-truth
  location (Level 3)
- Skill tags (subcategories, for RQ1) and difficulty features (§7.4)
- Whole-workspace answers (today the answer is one file, `answer_path`)

Task identity = (family, generator version, seed). Freeze generator versions for the study. The 24 Sep
collatz fix changed one seed's task in 200k, which already shows why.

### 7.3 Memorisation: exact answers vs templates

Goal (Decided): no exact answer can be learned off by heart.

- **Exact answers: already safe.** Seeds change names, constants and worked examples, and differential
  tests on seeded inputs fail a memorised answer.
- **Templates: not safe at Level 1.** Measured 23–24 Sep: median **10** distinct problem structures per
  family (1,262 across 108; 8,917 distinct reference solutions). A model trained on leaked instances
  could learn a family's handful of solution shapes. Mitigations: widen structure by composing spec
  features; keep a private held-out family set; canary strings; RQ6 measures the gap directly.
- **Levels 2–3 compose far more structure** (§2.4): thousands of distinct specs per family, with names,
  values and messages randomised on top. Level 3 adds seeded change requests and injected bugs on top of
  seeded codebases.

### 7.4 Variation must not mean random difficulty

More variation makes scores noisier if difficulty varies with it. When seed A is much harder than seed B,
the benchmark partly measures luck (RQ3). So keep variation free on the surface and controlled in
difficulty: every instance records difficulty features (e.g. number of endpoints, concurrency, framing),
tiers bucket them, and roadmap P3.5 measures whether seeds within a family are interchangeable (ICC: 20
families × 16 seeds × 3 models ≈ 24 h of compute) before suite sizes are fixed.

**Breadth vs depth.** More families means fewer seeds per family for the same compute. Per-family results
at Levels 2–3 will be noisy; report by level and domain, and use a pilot to decide how many tasks it takes
to tell two models apart (RQ3).

## 8. Timing: prefill, reasoning, output (Decided)

**Decided: headline throughput is model time only.** It excludes all toolchain time (`cargo` build,
test and run), so where the agent's commands run matters much less (§3.5). Toolchain time is still
recorded, just not scored.

**Headline throughput = correct tasks per hour of model time**, not raw tokens per second. At the same
tok/s, a model that reasons for 5,000 tokens per task solves fewer tasks per hour than one that answers
in 500. RQ2's "where does the time go" is exactly this split: prefill, reasoning and answer.

**Today:** one blocking request per call, recording total wall time and token counts only. The split was
deferred because 3 of 4 backends don't report it over the OpenAI API (REVIEW-5 R5-S6). In agent mode
the benchmark plugs its own instrumented transport into rustyharness's `ModelBackend` trait (contract
§5), and that transport records, per turn:

| Phase | Measured as |
|---|---|
| Queue + prefill | Time to the first non-empty delta |
| Reasoning | First → last reasoning delta (a separate field such as `reasoning_content`, or `<think>` tags; varies by backend) |
| Answer | First → last content delta |
| Speeds | Tokens ÷ phase time; totals from the final usage block |
| Toolchain (not in headline) | `cargo` build/test/run time per action; cold vs pre-built dependency builds marked (§5.2) |
| Harness (not in headline) | Everything else |

Prefer server-native timings where the backend gives them (llama.cpp `timings`, Ollama's native API
durations): they exclude the network hop, which matters for remote runs.

**Catches:**

- Agent loops reuse the KV cache, and rustyharness keeps a stable context prefix on purpose, so each
  turn's prefill processes only the new tokens. Record processed vs cached prompt tokens per turn, or
  prefill speeds can't be compared across turns, machines or backends.
- Leaving toolchain time out doesn't remove every same-device effect. Builds don't overlap generation
  (one action at a time), but a big build can push the model's memory into swap or heat a laptop, and
  that shows up in *model* time. It is what a real user gets, so keep it, but record swap and thermal
  state and flag affected runs.

## 9. Environment capture (Decided: automatic)

**Today:** nothing in code. Designed in docs/06 (backend metadata) and docs/15 §4 (model profile +
`env.json`).

Per run, `env.json` records:

- **Machine:** OS + version, CPU, cores, RAM, GPU(s) + VRAM + driver, battery or mains, and memory
  pressure / swap during the run (model and rustc share the same machine's RAM).
- **Backend:** name + version, model name, quant, GPU layers, batch, flash-attention, KV-cache type
  (pinned to f16 for ranked rows, docs/06), threads, rope settings.
- **Context size (Decided, D23):** logged on every run, in three parts:
  - **Native:** the model's trained maximum, from the model's metadata (e.g. GGUF `context_length`).
  - **Configured:** what the server actually allows. llama.cpp `/props` (`n_ctx`), Ollama `num_ctx`,
    vLLM `max_model_len`. The probe refuses a run whose configured context is below the study's size
    (Ollama's small default is the known trap).
  - **Used:** the harness profile's `context_window` and fill ratio, plus per turn the prompt tokens
    sent, the share of the window they fill, and every truncation.

  All three are stored as the server's claim where the harness can't verify them.
- **Model identity:** `/v1/models`; llama.cpp `/props`; Ollama `/api/show` (family, size, quant,
  digest); weights-file hash when the harness can read the file.
- **Run:** rustyharness version and benchmark-profile digest, the protocol actually used, generator
  versions, toolchain, local-crate-set and build-template snapshot ids, sampling settings.

In the default same-device setup the app collects all of this itself. It also records the attach mode
and topology (§3.5); for remote runs, both machines' hardware, with their roles. rustyharness adds its
model identity to every journal header: endpoint class, profile hash, and the server's claimed model and
template, stored as claims (its design §3.5).

## 10. Built vs to build (24 Sep)

| Piece | Status |
|---|---|
| Level 1 generators: 108 families with reference / skeleton / degenerate gates | Built |
| Oracle (compile, behaviour, constraints, clippy, miri), failure classes, statistics | Built |
| Sandbox: macOS seatbelt, no network, confined writes, `$HOME` read-deny, process-group kill | Built |
| Model client (rustybenchmark, single-shot) | Built: blocking, total time only. To be replaced by the instrumented transport (contract §5), which also serves agent mode through rustyharness's `ModelBackend` trait |
| Repair mode (one retry) | Designed (docs/03), not built. rustyharness's repair round covers it (§4.3) |
| Resume after a crash | Built (`run-suite`, from the journal) |
| Sandbox slot: reset cycle (§3.1), fixed port range, background processes, local-crate-set paths, memory/disk watch | To build (today: one workspace per unit, never deleted) |
| rustyharness H1: loop, both protocols, budgets, loop detection, model client, replay | Built (`6ba3437`, CI green on three OSes) |
| rustyharness H2: confined tool execution (sandbox backends, conformance suite, `exec.run`, edits) | Designed |
| rustyharness H3: verification in a pristine grading worktree, hidden checks, run report | Designed; not needed for benchmark scores |
| rustyharness generic features: loopback ports, background processes, extra paths and environment, prune (contract H-1 to H-5) | To design and build |
| Timing split | To build, in rustybenchmark's instrumented transport (contract §5) |
| Benchmark mode (contract BM-1 to BM-7) | Nothing to build in rustyharness: its embedding API already provides it (contract §2) |
| Crates category: crates.io name/version list, classifier (§6.6) | To build |
| Environment capture | Designed, not built |
| Topology detection (API port → owning process); probe mode for remote inference hosts | To build (attach modes designed, docs/15 §9.1) |
| Local crate set (source replacement) and pre-built build template (cloned per task) | To build |
| Whole-workspace answers, snapshot grading (first try, score by turn) | To build |
| Conformance runner (test scripts as data) + grader tools (HTTP/TCP clients, HTML parser, schema checks) | To build |
| Level 2 families per domain (spec generator, generic reference, script generator) | To build |
| Level 3 generator: codebase + change request or injected bug + ground-truth location | To build |
| Level 1 comprehension families (optional) | To build |
| Native sandboxes for the second test machine's OS: rustyharness's (agent commands) and rustybenchmark's (grading), or one standalone crate for both (contract §9). Linux: network namespace + bubblewrap/landlock; Windows: AppContainer + job objects | To build. Required: every machine runs everything itself (§3.3) |

## 11. Cost and phasing (Proposed; depends on my supervisor's view of scope)

**Agent mode multiplies cost.** A `deep` Level 1 run is ~44.5 h per model per machine at 20 tok/s with
one answer per task. Several turns per task could multiply that 2–5×, i.e. roughly 4–9 days per model per
machine. A Level 2–3 task could take 10–60 min at 20 tok/s. Run a pilot (e.g. 20 Level 1 families × a
few seeds, 3–5 Level 2 tasks, 2 models) before fixing suite sizes, models and machines.

**Schedule risk:** agent-mode results depend on rustyharness reaching H2 (confined tools) plus its
generic grants H-1 to H-3 (§4.2); H3 isn't needed for scores. If that isn't ready by mid-November, the
interim report uses Level 1 single-shot results from the existing pipeline, and agent mode moves to
Jan–Mar.

**macOS risk (OD-5 review F-1, F-2).** On macOS a process can escape the harness's kill with `setsid()`,
so H2 there also needs a cleanup sweep. The review measured one that works (about 26 ms per pass). If it
slips past about 1 November, the recommended fallback is a dated, written acceptance of process-group kill
for `exec.run` only, which is enough for Level 1.

| When | Deliver |
|---|---|
| By the interim report (23 Dec) | rustyharness H2 plus its generic grants (§4.2), scheduled early (H1 is built); rustybenchmark's grader, instrumented transport and journal analysis. Sandbox slot (reset cycle, ports, local crate set, pre-built template) on macOS and on the second test machine's OS; environment capture. Level 1 in agent mode: first real results on 2 machines (RQ1–RQ3). Conformance runner + first 2–3 Level 2 families as a pilot |
| Jan–Feb | Level 2 across ~4 domains (which ones: decided later) and their results |
| Feb–Mar | Level 3, built from Level 2 reference projects |
| Mar–Apr | Analysis and writing (product due 20 Apr, report 26 Apr) |
| If time allows | More domains, RQ4–RQ6, one small remote-topology comparison (§3.5) |
| Cut line | If behind in January: Level 3 becomes a small case study; Level 2 drops to 2–3 domains |

## 12. Open decisions

Everything already decided is in §0 (D1–D25) and is not repeated here.

1. ~~OS of the second test machine~~ Answered 24 Sep: Linux (D20).
2. **rustyharness schedule** (§4.2): schedule H1–H2 and the generic grants H-1 to H-3 early? Fallback if
   they aren't ready by mid-November: Level 1 single-shot for the interim report (§11).
3. Background processes (contract H-2): build them, or let agents test client and server inside one
   `cargo test`?
4. Benchmark profile (§4.3): wall-clock as a safety cap only; repair rounds 0; reviewer off; protocol per
   model (recorded) or text for all?
5. ~~Level 1 stays std only?~~ Answered 24 Sep: yes (D25).
6. Which crates to pre-build (speed only): pick from pilot data on what models choose (§5.2).
7. Size of the local set: top 500 by downloads plus their dependencies (§5.2)?
8. Local-set contents: latest versions only, or previous majors too?
9. Crates category (§6.6): report it separately from the build score?
10. Dashboards graded through server-rendered values only, with no headless browser (§6.3)?
11. clippy / miri in the agent's toolbox for `idiom-refactor`, other constraint-dominant categories, and
    `unsafe-core` (§5.1)?
12. Context size for the study (§4.3).
13. Suite sizes per level, given the cost (§11): is `deep` still feasible for 4–5 models × 2 machines?
14. Level 1 comprehension families (§2.1): in or out?
15. Two sandboxes (the agent's in rustyharness, grading's in rustybenchmark), or one standalone
    confinement crate that both use (contract §9)?
16. Model transport: a benchmark-owned `ModelBackend` (recommended), or a generic stream-observer hook in
    rustyharness's client (contract §5)?
17. ~~Benchmark-mode mechanisms: generic features or an add-on?~~ Answered 24 Sep: rustyharness's
    embedding API already provides them, so there is no add-on (contract §2).
18. **How Level 2 network tasks work on macOS** (OD-5 review F-3). Decided: they must run there (D22);
    how is open. Under Seatbelt, the harness can keep a server on localhost only by opening the port itself
    and handing over the socket. A normal `bind("127.0.0.1:port")` server, or a `cargo test` that binds a
    port, then fails. Candidates, still to be tested:
    - (a) **Transparent handover:** a small harness library catches the program's own `bind()` on a
      granted port and swaps in the socket the harness already opened. Models write normal code. Needs a
      spike (macOS `DYLD_INSERT_LIBRARIES` interposition).
    - (b) **Packet-filter guard:** allow a normal bind, and a firewall rule blocks the granted ports from
      the network. Models write normal code, but it needs admin once at install.
    - (c) **Explicit handover contract:** every model serves on a handed-over listener. An unusual
      convention, and an RQ1 confound.
    - (d) **Binds visible on the network,** allowed and recorded per run. The weakest isolation.

    Linux has no such problem: inside the sandbox's private network namespace, normal binds work.
19. ~~Tool budget for Level 2~~ Answered 24 Sep: packaging scales with model size, and every model gets
    the same capabilities (D24).

## Version history

- **v0.1:** two task tracks, agent harness, crate mirror, grading, timing, environment capture.
- **v0.2:** task environment (sandbox); three levels of task.
- **v0.3:** one sandbox slot, reset between tasks.
- **v0.4:** native sandbox on every OS, no VMs; Level 3 official; crates ready-built.
- **v0.5:** one device with a local model API; topology recorded.
- **v0.6:** the model chooses its crates from the local set; nothing is pre-declared.
- **v0.10:** checked against rustyharness `6ba3437` (H1 built); benchmark mode needs no harness code;
  the GPU PC's OS is now urgent.
- **v0.9:** decision log (§0); rustyharness is a full coding agent on its own, and rustybenchmark
  switches on a locked-down benchmark mode (contract v0.3).
- **v0.8:** rustyharness stays fully standalone; grading, timing and measurement live in rustybenchmark
  (contract v0.2).
- **v0.7:** rustyharness enforced and pinned (§4 rewritten against its design v0.1); headline throughput
  excludes toolchain time; crates category (§6.6).
