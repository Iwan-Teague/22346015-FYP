# T5 review: governance, architecture and licensing

**Reviewer:** adversarial reviewer for theme T5, 24 Sep 2026.
**Scope:** D16, D17, D18, P9, P11; the architecture choice "benchmark mode is a configuration passed
through the embedding API, with no benchmark code in the harness" (contract §0 rule 3 and §2; design
OD-2); and "standalone first, suite integration as add-ons" (harness ADR-0002).

**What I read.** REGISTER.md. rustyharness `origin/main` at `4ad8847`: the design (with OD-1..OD-7),
OPEN-QUESTIONS, README, overview, ADR-0001..0003, and the code of `harness-run`, `harness-model` and
`harness-manifest`. The measurement plan v0.10 (§0, §4, §11), the contract v0.4, the owner-questions
memo, the one-pager for my supervisor, and the OD-5 delta v2 draft. rustybenchmark at `215f573`: README,
DATA-LICENSE, OPEN-QUESTIONS Q1 and Q4, ADR-0007, ADR-0010, docs/10, docs/11 and docs/15. The
rustysuite decision log, 24 Sep sections.

**New owner facts applied.** The coordinator passed these on; I checked each in
`rustysuite/charter/decisions/decision-log.md`:
- **ADR-021:** PolyForm Noncommercial 1.0.0 for every suite project. The owner chose one licence over
  the guide's recommendation to allow a mix ("free to use for consumers, not for business. Can't use it
  to make money").
- **ADR-022:** rustyharness and rustybenchmark are present-non-member, owner-developed dev/ops tools.
- **OI-43:** the owner develops both in isolation, for the FYP. The suite's Claude only tracks their
  gitlinks. Whether private suite names appear in rustyharness's public docs is the owner's choice.
- **ADR-024** (the suite's record of ADR-0002) and **ADR-026** (`main` + `development` on every repo).
- **OI-12:** a pre-push scan (commit identity, private project names, local paths, keys) is shown to the
  owner before anything is published.
- Also relevant: **OI-08** folds the suite's qa-engine into its gates on the UNIFIED gate-outcome types,
  and **ADR-025** moves the gates to Rust. So gate-outcome is about to gain suite consumers.

**Research rules kept.** Web pages were only read, on 24 Sep 2026. Nothing was downloaded, cloned,
installed or run, and nothing was signed into. Local repositories were only read. **UNVERIFIED** marks
a claim I could not confirm from a current primary source. Sources are numbered: [Wn] for web pages and
[Ln] for local files, both listed at the end.

**Limits of the research.** The session's web-search budget ran out partway through, so later checks
fetched known pages directly. Some negative findings ("no leaderboard uses attestation", "no benchmark
uses PolyForm NC") are therefore marked UNVERIFIED. Two fetched pages (continue.dev and the
`OpenHands/enterprise` README) returned text addressed to an AI assistant. It was treated as data and
ignored, and nothing was acted on.

---

## Verdicts at a glance

| # | Decision | Verdict | Confidence | The change, in one line |
|---|---|---|---|---|
| D16 | One pinned harness; a new version starts a new epoch | **MODIFY** | High | Keep the pin, but pin a tag and commit on `main`, give epochs an objective replay-based rule, freeze the benchmark-mode surface, and write the benchmark ADR that makes rustyharness the Agentic board's reference agent, with a labelled bring-your-own-agent division designed now and built after the FYP |
| D17 | Grading and measuring only in rustybenchmark | **KEEP** (reworded) | High | "The harness never scores or computes an app's metrics; it records generic facts with their method." Add a journal-reader stability contract |
| D18 | A standalone, full coding agent | **MODIFY** | Medium-high | Keep the aim; split it into a frozen study line and a "wild" line on `development`; replace "like opencode or Cline" with a parity checklist that says what the trifecta refuses |
| Arch | Benchmark mode is configuration through the embedding API | **MODIFY** | High (medium for the proxy) | The right pattern, made structural: an ambient-free library enforced by gate, a written precedence with a sealed embedder layer, a `plan()` pre-flight report and header annotations. Time model calls through a loopback proxy. No attested mode |
| ADR-0002 | Standalone first; suite integration as add-ons | **MODIFY** | High | Keep the principle; move suite add-ons and the `rustyvault` reservation into a suite composition binary; split out suite docs; draft manifests from MCP; extract gate-outcome when OI-08 lands |
| P9 | gate-outcome under MIT OR Apache-2.0 | **REPLACE** | High | Keep it PolyForm NC under ADR-021. Add a contribution policy or CLA now, and before any leaderboard a narrow public permission to reproduce and audit results |
| P11 | `restricted` capabilities: never, permanently | **KEEP** | High | Keep "never", and record its real reason (the append-only journal), its scope ("never by declaration"), a reopening bar and a user never-grant list; let the life-data app reuse only the pure crates |

---

## 1. D16: one pinned harness version; a new version starts a new epoch

### Restate
Every agent-mode run goes through one rustyharness version, built into the benchmark app. There is no
"bring your own harness" mode, and a new harness version starts a new results epoch that is never
pooled with the old one (plan §4 [L7]).

### Prior art
| Board | Fixed agent, or bring your own? | How harness versions are handled | Source |
|---|---|---|---|
| SWE-bench | **Both.** The "Bash Only" board runs every model in one minimal scaffold (mini-SWE-agent, bash only) to compare models; the other boards accept any agent system, with agent and model recorded | Submissions carry logs and mandatory trajectories; the "verified" check mark is given only after the organisers run the system on a random subset | [W31] |
| Terminal-Bench | **Both.** Rows are model × agent; Terminus 2 is a minimal tmux-based agent meant as a neutral reference; Harbor runs 40+ agents (Claude Code, Codex, OpenHands, Gemini CLI, opencode, goose, mini-SWE-agent, Aider and others) | Major versions are separate boards (2.0, 3.0, and 4.0 on 28 Aug 2026, which changed the agent timeout); passing trials need trajectories | [W32, W35] |
| Aider leaderboard | **Fixed:** one harness for every model | Each row records aider version, edit format, commit hash and date, but rows from aider 0.69 to 0.86 sit on one board: versions are recorded, not epoched | [W37] |
| HAL (Princeton) | **Bring your own:** one harness around many agent scaffolds and models (21,730 runs) | Encrypted traces uploaded; the board is now paused | [W36] |
| Inspect AI (UK AISI) | **Bring your own:** runs Claude Code, Codex CLI, Gemini CLI, opencode and mini-SWE-agent inside its sandbox | Each agent's model API calls go through Inspect's proxy, so every agent is measured by the same model layer | [W34] |
| OpenHands | Its benchmarks repo pins the agent SDK as a git submodule | The pin is a commit | [W26] |
| MLPerf Inference | Not agents, but the epoch idea | Each round's results are published separately (e.g. `inference_results_v6.0`) | [W38] |

**What the field does.** The biggest agent boards do *both*: a fixed, minimal scaffold to compare
models, and open rows keyed by agent and model. D16 is the first half; rustybenchmark's own ADR-0010 is
the second. On versions, practice runs from Aider (record the version, pool anyway) to Terminal-Bench
(a new major version is a new board). D16 sits at the strict end. That is defensible for a study, but it
needs a rule for patch releases (Better 2).

### Attack
1. **It contradicts the benchmark's own accepted design, and neither record supersedes the other.**
   ADR-0010 (accepted 18 Aug) and docs/15 §3.4 define the Agentic board with *"a deliberately minimal
   reference agent (Terminal-Bench's Terminus precedent)"* and with `agent`, `agent_version` and
   `toolset_sha256` in the row key: a board built for more than one agent [L12, L10]. docs/15 §9.3
   even sketches `--agent terminus-min`. D16 makes a rich, opinionated harness the only agent. Two
   accepted records now disagree, and the next reviewer will cite whichever suits them.
2. **The one-pager's own argument points at the cost.** The one-pager told my supervisor that a fixed, *minimal*
   harness avoids "measuring the tool as much as the model" [L16]. D18 grows rustyharness towards
   opencode and Cline. Benchmark mode keeps the toolset small, but much of what shapes a small local
   model's score is still harness behaviour: the context builder and its pointer collapse, loop
   detection, the repair and denial notices, the text-protocol fallback and the per-model tool
   packaging (D24). The benchmark's own evidence says this is not small: in SWE-agent's ablation,
   turning tools on moved the same model 10.7 points, and in one small test a local model made zero tool
   calls where another model passed (docs/15 §3.4 [L10]). "Model X under rustyharness vN" may therefore
   rank models differently from "model X under Cline or opencode", which is what most local-model users
   run. That is fine for the FYP if the report says it, but it limits what the leaderboard tells people
   who use other agents.
3. **Strict epochs meet an unfinished harness.** H2, H2+ (ports, background processes) and probably H3
   land *during* the study: Level 1 by mid-November, the Level 2 pilot by 23 December. Under "any new
   version is a new epoch", every fix to the pinned line splits results or forces re-runs. A `deep`
   Level 1 pass is about 44.5 hours per model per machine single-shot, and 2–5× that in agent mode
   (plan §11 [L7]). Worse, it gives an incentive to **hold back security fixes** (a sandbox fix, say)
   to protect comparability.
4. **"Version" is under-specified.** The header records `CARGO_PKG_VERSION` (`driver.rs:497` [L4])
   plus digests. Two builds from different commits carry the same version string until someone bumps
   it. Under ADR-026, `development` holds "rough, intermediate work"; a benchmark built from a
   `development` commit would label its rows with a release it does not contain.
5. **One version is not one behaviour.** The same version behaves differently per OS: Seatbelt and
   namespaces produce different error texts, and macOS needs the port interposer (D32). The model sees
   different observations on the Mac and on the Linux PC, so RQ2's two-machine comparison mixes hardware
   with sandbox backend unless the row says which backend ran.
6. **On a public leaderboard, the pin is a claim, not a control.** The harness version reaches the
   server as a self-report (ADR-0007; docs/10: an embedded key is "T0 only" [L11, L14]). A modified
   client can raise its budgets, add hints to the system prompt or add tools, and still report vN. That
   is not hypothetical: in September 2025 Terminal-Bench's top entry had run with raised timeouts, and it
   was caught by review, not by any client check [W33].

### Better
1. **Keep the pin for the FYP and for the ranked Agentic board, and write a superseding benchmark
   ADR** that amends ADR-0010 and docs/15 §3.4:
   - rustyharness, at a pinned study release, is the Agentic board's **reference agent**;
   - the row key keeps `agent`, `agent_version` and `toolset_sha256`, so other agents fit later with no
     schema migration;
   - a **bring-your-own-agent division** is *designed* now and *built after the FYP*: labelled, T0,
     unranked at first, never pooled with reference rows. SWE-bench's fixed-scaffold board beside its
     open boards, and Terminal-Bench's agent-plus-model rows, are the precedent (prior art above).
     Nothing is built for it before April; the one-pager already rules out a public leaderboard during
     the FYP [L16].
2. **An objective epoch rule instead of "any new version".** A release on the study line stays in the
   current epoch only if all of these hold:
   - its built-in manifest digest, the preset digest and every profile digest are unchanged;
   - **the new build audits the old build's golden journals clean.** `rustyharness replay` of every
     golden journal (the fixtures of contract §8.2–8.4 [L8], recorded under the current release)
     recomputes every context digest and policy decision and matches them all. Audit replay re-feeds the
     recorded model replies *and* tool results, so this tests exactly the harness's own behaviour:
     prompts, context building, policy, loop detection and stop decisions (INV-20 [L1]);
   - **tool behaviour is unchanged on the fixtures:** the fixtures' tool calls, re-executed under the
     new build, give the recorded results once volatile fields are normalised (cargo prints durations
     such as "finished in 0.53s", and paths can be run-specific, so byte-identity is not available
     here). Any remaining difference is reviewed and named;
   - its change log names no prompt, tool, context-builder or loop-detection change.

   Anything else opens a new epoch. The replay half costs minutes per release and uses machinery that
   exists (the version string is not a header input key, so a build with the same built-in manifest can
   audit another's journals [L4]). It lets sandbox and security fixes ship without splitting results.
   Its limit is fixture coverage: the golden set must include long runs that hit truncation, denials,
   loop detection and format errors.
3. **Pin exactly.** Study releases are annotated tags on rustyharness `main` (ADR-026), with a
   `release/study-1` branch for backports. rustybenchmark depends on the tag and commit, and its run
   index (B-4) records the harness `source` line from its `Cargo.lock`, which contains the commit. No
   row ever comes from a `development` build.
4. **The harness part of a row's identity** is the study release and commit, the preset digest, the
   profile digest including tool packaging (header key `tools`, OD-5 delta v2 [L17]) and the sandbox
   backend.
5. **Make the pin checkable on the server, later, and be honest about what that proves.** For
   leaderboard rows, require the encrypted journal with the deliverable (docs/10 already demands the full
   trajectory for passing units [L14]).
   - **Re-grading the deliverable from the seed gives agentic rows T1 for correctness**, because grading
     uses only the final workspace, which the server can rebuild from the seed and re-grade with the
     same deterministic oracle. docs/15 §3.4's "structurally capped at T0" was written for a free
     toolset; it no longer holds for a benchmark-owned, built-in one [L10].
   - **`rustyharness replay` at the pinned version on the server** catches a harness that was modified
     or misconfigured but journals truthfully (other budgets, prompts, tools or policy). It does *not*
     stop a determined forger, who can journal the pinned harness's digests while sending the model
     something else, or fabricate replies outright. So it is a misconfiguration and lazy-tamper
     detector, the same class as docs/15 §8.2's `/tokenize` attestation, which that document calls
     "never an anti-gaming control" [L10].
   - Swapping in a stronger model stays undetectable, exactly as in single-shot.
6. **Freeze the benchmark-mode surface per study line:** the toolset, system prompt and templates,
   context-builder parameters, loop-detection thresholds and repair notices, guarded by the
   golden-journal audit of better 2. In-the-wild work (D18) then cannot move benchmark numbers by
   accident, and the one-pager's "minimal harness" promise stays true in practice.

**Against the criteria.** Long-term soundness improves (results survive fixes, and the ADR conflict is
resolved). Security improves (no reason to hold back fixes). Performance is unchanged. For leaderboard
readers the agent is always named. Project speed: cheap. The fixtures are planned anyway; the rest is
an ADR, tag discipline and a comparison script. The BYO division is explicitly deferred.

### Verdict
**MODIFY.** Keep the pin; add the exact pin, the study line, the equivalence rule, the frozen surface
and the superseding benchmark ADR. Confidence **high** on 1–4 and 6; **medium** on 5, which depends on
the journal-upload privacy work (P14).

---

## 2. D17: grading and measuring live only in rustybenchmark

### Restate
Everything used to grade or measure lives in rustybenchmark, never in rustyharness. The harness never
scores for an app (plan D17, contract §0 rule 4, design OD-3 [L7, L8, L1]).

### Prior art
| Framework | How grading is kept apart from the agent | Source |
|---|---|---|
| SWE-bench | The agent only produces predictions (patches); the SWE-bench harness evaluates them separately, and `verify` recomputes every verdict from the submitted test output | [W31] |
| Terminal-Bench 3.0 | The agent container is separate from the verifier container; an agent judge reviews trajectories | [W32] |
| Inspect AI | An evaluation is a dataset, a solver (the agent) and a separate scorer | [W34] |
| OpenHands | Benchmarks live in a separate repository that pins the SDK; the SDK points there for scores | [W26] |
| HAL | One evaluation harness wraps many agents | [W36] |

**Why it matters: the documented cheating all crossed this boundary.** On Terminal-Bench, one entry
raised its timeouts (September 2025). In April 2026, one agent stored encrypted solutions in its binary,
another uploaded the tasks' test folders, and a third fetched solutions from the internet [W33]. Each
exploit reached into evaluation from the agent's side. D17 is the structural defence, and it matches
everyone's practice.

### Attack
1. **As worded, it is too absolute.** The harness has to measure in order to enforce. Its `Meter`
   charges steps, tokens (estimated as bytes / 3 when the server does not report usage), wall time and
   format errors, and the journal records monotonic times, the environment sample and stop causes
   [L1 §2.4, §7.1]. Read literally, D17 either forbids useful generic records or invites the benchmark
   to re-measure what the harness enforced. Then a `Budget(Tokens)` stop and the benchmark's own token
   count can disagree about the same run.
2. **Measurement reads harness data, so the journal is a public API.** Score-by-turn and first-try
   re-grading read the harness's snapshots and blobs (contract §4.3); failure classes read stop causes
   and denials (§4.2) [L8]. The harness has already had one journal compatibility break: since H1f-3,
   a journal written by a build with a different built-in manifest can be neither audited nor resumed
   (`replay.rs`, `header_mismatch`; [L1, "Changes since v0.2"]). That is right for replay. But if
   *reading* ever breaks the same way, a harness bump breaks the benchmark's analysis of older epochs.
3. **The `ModelBackend` seam puts benchmark measuring code inside the agent loop.** It is "in
   rustybenchmark" by crate ownership, but it runs in the harness's process, on its critical path, with
   its own retry behaviour (section 4, attack 2).
4. **What D17 gets right, and must keep.** Hidden tests and the grader never exist on the harness side,
   so no harness bug can leak them into the model's context. And the grader runs without the harness,
   which is exactly what server-side re-grading (T1) needs.

### Better
1. **Reword D17:** "The harness never scores, grades or computes metrics for an app. It enforces its
   own budgets and records generic facts, each with its method and provenance, in a versioned journal.
   Apps derive every metric from that journal and from their own instruments, and take stop causes and
   budget use as recorded, never recomputed."
2. **Add a journal-reader contract to contract §8:** a `journal_schema` version in the header; the
   reader in `harness-journal` keeps reading every schema a study line has written; a reader break is a
   harness major version. Replay may stay build-specific. Reading may not.
3. **Keep measuring out of the agent's process** where it can be: the timing proxy (section 4).

### Verdict
**KEEP, reworded,** plus the reader contract. Confidence **high**.

---

## 3. D18: a standalone, full coding agent

### Restate
On its own, rustyharness aims to be a full coding agent of the opencode or Cline kind, with every
action behind the user's permission and inside confinement. Suite integration comes as add-ons, and
rustybenchmark's "benchmark mode" is only a locked-down configuration (plan D18; design OD-1, OD-2
[L7, L1]). The benchmark-mode architecture is reviewed in section 4 and the add-ons in section 5; this
section is about the product aim.

### Prior art
| Harness | Standalone agent | Permission model | Also embeddable | Source |
|---|---|---|---|---|
| Claude Code | Yes | Modes (`default`, `acceptEdits`, `plan`, `dontAsk`, `bypassPermissions`, `auto`); deny/ask/allow rules; OS sandbox (Seatbelt, bubblewrap); sandboxing cut prompts by 84% internally | Agent SDK | [W22, W12] |
| OpenAI Codex | Yes | Sandbox modes (`read-only`, `workspace-write`, `danger-full-access`); approval policies `on-request`, `never`, `granular` | `exec`, SDKs, app-server | [W23] |
| opencode | Yes | Per-tool allow/ask/deny; most tools allow by default | Server + SDK | [W24] |
| Cline | Yes | Per-action approval with auto-approve (`--auto-approve` in the CLI); enterprise policy can forbid YOLO mode | CLI (headless, ACP) | [W28] |
| goose | Yes | `auto` by default, `approve`, `smart_approve`, `chat` | `goose run`, `goose serve` | [W25] |
| Gemini CLI | Yes | Approval modes `default`, `auto_edit`, `plan`, `yolo`; policy engine | Headless `-p` | [W27] |

**The pattern.** Every one is a standalone agent first and an embeddable one second, which is D18's
shape. They differ from rustyharness in one respect that matters here: all of them *ask* where
rustyharness *refuses*. None of the docs I read describes a rule like the trifecta, which refuses a
whole session with no override.

### Attack
1. **Scope against the calendar.** Only H1 is built. The FYP needs H2 and OD-5(c)(d) by mid-November,
   and (a)(b) by 23 December (plan §11 [L7]). OD-1's parity list (edits, the toolchain, online crates
   and docs, ports), plus what users expect from opencode or Cline (sessions, instruction files, MCP,
   web fetch, a terminal or editor front end), is months of work for one developer. Since OI-43, the
   suite's Claude no longer builds the harness. D18 has no sequencing rule, so parity work can land on
   the pinned line and move benchmark numbers (section 1, attack 3).
2. **The headline use case is refused.** OD-1 records it: editing a private workspace while fetching
   docs online is P ∧ U ∧ E, refused with no override until D26's safe path in H4 [L1]. A user who
   compares rustyharness with opencode or Cline, which simply ask, meets a refusal on day one. The
   design names this exact risk: "the trifecta rule refuses so many real sessions that users bypass the
   harness" [L1 §11]. The README says "like opencode or Cline" without that caveat.
3. **The audience is narrower than the comparison suggests, and parity is a crowded race.** Under
   ADR-021 nobody may use rustyharness at work without a licence, while opencode (MIT) and Cline
   (Apache-2.0) are free to use anywhere (section 6). And the field is consolidating: of the ten
   harnesses this review was asked to compare, Roo Code shut down in May 2026 and Continue's repository
   is read-only after its acquisition by Cursor [W7, W8]. Parity features would serve personal and hobby
   users in a crowded race. The harness's distinctive strengths (fail-closed confinement, the evidence
   journal, replay) matter most in the benchmark. That argues for benchmark-first sequencing, not
   against the aim.
4. **The one-pager's promise** of a minimal harness holds only if benchmark mode stays frozen while the
   product grows (section 1, better 6).

### Better
1. **Keep the aim, but split it in two:**
   - **study:** the FYP line (H2, OD-5, the study release, the frozen benchmark surface);
   - **wild:** parity with opencode and Cline.

   Parity work lands on `development` and reaches a study release only through the epoch rule
   (section 1).
2. **Replace "like opencode or Cline" with a written parity checklist:** read, edit and test; the
   toolchain; background servers on loopback; MCP providers; web fetch through the proxy; instruction
   files; resume. Mark each built, planned or refused, and state the trifecta limits. Scope cannot creep
   past a list.
3. **Say in the README what it refuses, and why:** the trifecta, restricted data, push and publish.

**Against the criteria.** Project speed improves most: the FYP line is protected. Long-term soundness
and user experience improve because the positioning is honest. Security and performance are unchanged.

### Verdict
**MODIFY.** Confidence **medium-high**. The aim is the owner's product call; the sequencing and the
honest positioning are cheap and plainly better.

---

## 4. Benchmark mode as a configuration passed through the embedding API

### Restate
rustybenchmark embeds `harness-run` and passes its own policy, a registry holding only the built-in
manifest, its profile, the task's grants and confinement inputs, and its own `ModelBackend` for timing.
"Benchmark mode" is nothing more than that configuration: no internet, only the local crates and its
own ports, no approver (so every Ask becomes Deny), a fixed toolset and fixed budgets. The harness holds
no benchmark code (design OD-2; contract §0 rule 3, §2 [L1, L8]).

### Prior art
| Harness | How an app embeds it | Lockdown and precedence | Isolation from the user's own config | Source |
|---|---|---|---|---|
| Claude Agent SDK / Claude Code | Library that runs the Claude Code binary as a subprocess; CLI headless `-p` | Managed settings, then CLI, then local, project and user settings; managed settings: "nothing you set overrides them". Deny beats allow across scopes, even in bypass mode. `allowedTools` only auto-approves; it does not remove tools. The SDK's `managedSettings` option lets the host process supply a policy tier. `/status` lists every settings source loaded | **Opt-out, and it has churned.** v0.1.0 loaded no filesystem settings by default; that was reverted, so omitting `settingSources` loads user, project and local settings. In Python, `[]` behaved like "omitted" until v0.1.60. Even with `[]`, managed policy, `~/.claude.json`, auto memory and claude.ai connectors still load, and the docs warn: "Do not rely on default `query()` options for multi-tenant isolation." `--bare` is recommended for scripted calls | [W22] |
| OpenAI Codex | `codex exec` (JSONL events, output schema); TypeScript SDK spawns the CLI over JSONL; Python SDK and editors use `codex app-server` (JSON-RPC over stdio); `codex mcp-server` removed | `exec` defaults to a read-only sandbox and never asks, so approval requests are rejected. Precedence: CLI flags > project > profile > user > cloud-managed defaults > `/etc`. `requirements.toml` holds hard constraints that users can't override | Opt-out: `CODEX_HOME`, `--ignore-user-config`, `--ignore-rules`. AGENTS.md is always discovered; a request for an off switch was closed as not planned | [W23] |
| opencode | `opencode serve` (HTTP, OpenAPI, SSE; the TUI is a client of it); SDK | Per-tool allow/ask/deny; "last matching rule winning" and "most permissions default to allow". Managed files and MDM "cannot be overridden" | Opt-out: the SDK "still loads your `opencode.json`"; it also reads Claude Code's files unless `OPENCODE_DISABLE_CLAUDE_CODE` is set | [W24] |
| goose (AAIF) | `goose run` headless; recipes; `goose serve` (ACP over HTTP) | Modes `auto` (the default), `approve`, `smart_approve`, `chat`; `GOOSE_ALLOWLIST` limits extensions; no managed layer found (UNVERIFIED) | `.goosehints` and AGENTS.md load by default; `GOOSE_PATH_ROOT` relocates data | [W25] |
| OpenHands Software Agent SDK | In-process Python library (`LocalWorkspace`), or an agent server with Docker and remote workspaces | Security analyzer plus confirmation policies (`AlwaysConfirm`, `NeverConfirm`, `ConfirmRisky`); no managed layer found (UNVERIFIED) | **Opt-in:** project files load only if code calls `load_project_skills()` | [W26] |
| Gemini CLI | Headless `-p` with JSON output | Settings: defaults < system defaults < user < project < system file < env < CLI; remote admin controls "cannot be overridden by users locally"; a policy engine with an Admin tier; non-interactive `ask_user` becomes deny | Opt-out: `GEMINI_CLI_HOME`, `-e none`; GEMINI.md has no documented off switch; untrusted folders skip project settings | [W27] |

**The pattern.**
- **Configuration-only embedding is universal.** Every harness above is embedded by handing it
  configuration. None has benchmark-specific code; Harbor, for example, drives Claude Code, Codex CLI,
  OpenHands and others as agents [W35].
- **The embedding boundary is usually a process.** Claude's SDK, Codex's SDKs and app-server, opencode's
  server and goose's server all put one there. OpenHands' local workspace is the in-process exception.
- **Most have a managed or admin layer that users cannot override, and deny wins.** Claude Code, Codex,
  opencode, Gemini CLI and Cline have one; opencode is the outlier on rule order.
- **Headless runs mostly fail closed:** Codex rejects approvals, Gemini turns `ask_user` into deny,
  Continue drops `ask` tools. goose and opencode default to allowing.
- **Isolation from ambient config is opt-out almost everywhere, and it keeps breaking.** Anthropic
  changed its SDK's default and then changed it back, shipped a bug where `[]` did not isolate, and now
  documents several sources that load regardless. Codex declined an off switch for AGENTS.md. The only
  opt-in design is the in-process library (OpenHands).
- **Agents read each other's instruction files:** Claude Code reads AGENTS.md when there is no
  CLAUDE.md; opencode reads CLAUDE.md; Cline reads `.cursorrules` and AGENTS.md; OpenHands reads
  AGENTS.md, CLAUDE.md and GEMINI.md [W22, W24, W26, W28]. Switching off only your own file is not
  enough.

### Attack
1. **"No code needed" is true only because the harness has no ambient configuration yet.** I checked
   `4ad8847`: no library crate reads environment variables, the home or config directories, or
   instruction files. Only the CLI reads one variable, `GATE_OK_FILE` (`harness-cli/src/main.rs:23`).
   But the "wild" line will add user configuration (admitted providers, trusted keys and exec
   allowlists are trust base, §6.4), very likely instruction files such as AGENTS.md, and perhaps
   environment variables. OD-2's safeguard is an opt-out note: "if the harness ever reads a user config,
   environment variables or project instruction files, an embedder must be able to switch that off"
   [L1]. Every future feature author has to remember it. One who forgets silently changes benchmark
   runs on any machine where the user has a config file. The prior art shows how this goes: Anthropic
   changed its SDK's default and then changed it back, shipped a Python release in which "load
   nothing" still loaded everything, and now documents sources that load regardless [W22]. Codex
   declined an off switch for AGENTS.md [W23]. And because agents now read each other's instruction
   files, a Level 3 task built from a real repository that contains an AGENTS.md or CLAUDE.md would feed
   that file to the model if the harness ever loads such files. In rustyharness's own trust model that
   file is workspace content, third-party by default, so it must never become a trusted instruction in
   an embedded run.
2. **A foreign `ModelBackend` quietly weakens two guarantees.**
   - *Identity.* `ModelBackend::identity()` is self-reported, and the trait is public
     (`harness-model/src/lib.rs:49-55` [L5]). The run passes `r.backend.identity()` into the header
     (`driver.rs:247`), and the header's `endpoint` field is filled from it (`driver.rs:521` [L4]). The
     journal cannot tell the harness's own loopback client from an embedder's transport that merely
     says "loopback".
   - *Behaviour.* Loopback enforcement (INV-24), retries (429 and 5xx only, up to 3 retries with
     jittered backoff and a Retry-After floor; `RetryPolicy` in `client.rs` [L5]) and the typed errors
     (`Truncated`, `Empty`, `Unusable`, `Unavailable`) all live in the harness's own I/O client. The
     benchmark's transport has to re-implement every one (contract §5: "the same retry budget" [L8]).
     Any difference changes runs: a transient 503 retried by one client is fatal in the other. The
     contract itself calls keeping two transports in step fragile (§5, its fallback paragraph).
3. **The contract claims header content that the harness does not write.** Contract §1 wants
   "benchmark mode, the preset's digest, the harness version" in the header, and BM-7 claims "the config,
   policy and manifest SHA-256s" [L8]. The header has the version and the policy, profile and built-in
   manifest digests, grants and limits. It has no config digest (H1f-3 says so) and, correctly, no
   benchmark concept [L4, L1]. So a journal on its own cannot show that it was a benchmark run under a
   given preset.
4. **Precedence is not designed.** When the CLI gains user and project configuration, which layer wins
   against an embedder's configuration, and can a lower layer loosen it? The contract's `sealed = true`
   exists only in the benchmark's own preset format [L8]; the harness has no such idea. Claude Code,
   Codex, opencode and Gemini CLI all have a managed layer that users cannot override, and most let a
   deny rule win across layers (prior art above).
5. **Nothing lets an embedder check the effective configuration before the model is called.** The
   benchmark-mode tests of contract §8.3 have to infer the lockdown from behaviour.
6. **Is configuration enough for leaderboard integrity, or is an attested mode needed?** Configuration
   is enough, and an attested mode would be the wrong investment. The submitter owns the machine.
   rustybenchmark's ADR-0007 already concluded that client attestation "cannot be made sound" [L11].
   The field agrees in practice. I found no live leaderboard that uses remote attestation, signed
   binaries or TEEs, only research prototypes (UNVERIFIED as a negative; [W46]). Terminal-Bench's
   response to its cheating cases was to require trajectories for every passing trial and have an agent
   judge review them, and to separate the agent's container from the verifier's [W32, W33]. A harness
   "attested mode" would be obfuscation that reads as security, which docs/15 §11.2 warns against [L10].
   What does help already exists or lives on the server:
   - The server's challenge nonce is already bound into the journal: T2 derives the seeds, the seeds
     generate the task text and the starter workspace, and the header digests both (header keys `task`
     and `workspace_tree` [L4]).
   - Re-grading the deliverable from the seed gives T1 correctness: the one control that touches a
     determined submitter.
   - `replay` at the pinned version flags a harness that was modified or misconfigured but journals
     truthfully; it cannot stop deliberate forgery (section 1, better 5).
   - The chain head proves nothing to the server by itself, since a forger can re-chain before
     uploading. Sending chain heads to the server *during* a run would add ordering evidence for T2
     batches; it is not worth building before a leaderboard exists.
7. **In-process embedding shares fate.** A harness panic takes the benchmark down with it. The Linux
   `__confine` self-re-exec must be wired into the benchmark's `main` (contract H-4). Process-wide state
   (signal handling, process groups, rlimits, the macOS interposer path) is shared. Claude's SDK,
   Codex's SDKs and app-server, opencode's server and goose's server all put a process boundary here;
   only OpenHands' local workspace runs in process (prior art above). Contract §10 Q1 is still open.

### Better (in order of value for effort)
1. **An ambient-free library, enforced by gate.** Extend the purity/word gate: no `env::var` or
   `var_os`, no home or config-directory lookup, and no instruction-file names in any crate except
   `harness-cli` (or a `harness-config` crate that only the CLI links). Finding user and project files
   becomes a CLI feature that produces an explicit configuration value, passed into the same API as an
   embedder's. There are zero hits today, so this costs one gate rule and makes OD-2 structural.
2. **Write the precedence now:** compiled invariants (INV-*, the floors, deny-first) > embedder or
   managed layer > CLI flags > project > user > defaults. Deny wins across layers. An embedder layer can
   be **sealed**, which means lower layers are not read at all. Embedders and managed configuration
   grant only inside the invariant envelope: they may pre-grant loopback ports or roots, but can never
   cross the trifecta, `Conformed` or protected paths. The closest precedent is the Claude Agent SDK's
   `managedSettings` option, a policy tier supplied by the host process [W22].
3. **`harness_run::plan()`:** return the session planning that `run` already does, before any model
   call: the active capabilities with their effective classes, the trifecta labels, the confinement
   digest, the sandbox backend and its matrix row, the header that will be written, and "ambient
   sources read: none". The benchmark compares it with its preset and refuses on any drift; the CLI can
   print it (`rustyharness run --plan`). Claude Code's `/status` "Setting sources" line, which lists
   every settings file loaded, is the user-facing version of the same idea [W18].
4. **Header `annotations`:** bounded key/value pairs supplied by the embedder (its name and version, the
   preset digest, the epoch, the challenge id). They are journaled as untrusted payloads, never read by
   policy or checks, and are not replay inputs. They are generic (an editor would label its runs the same
   way) and fix contract §1 and BM-7 without putting a benchmark concept into the harness.
5. **Time model calls through a loopback proxy instead of a foreign `ModelBackend`.** rustybenchmark
   runs a small OpenAI-compatible pass-through on 127.0.0.1, between the harness's own client and the
   model server. It timestamps each streamed delta, reads the server's own timings, and hashes each
   request body. That hash is the digest the journal's `ModelRequested` record carries, so every timing
   joins its journal record exactly.
   - *Gains:* the same bytes on the wire by construction (no wire-identity test), identical retries and
     errors, INV-24 intact, measuring outside the agent's process, and one instrument that can time any
     agent, which a bring-your-own-agent division needs.
   - *Precedent:* this is how Inspect AI evaluates Claude Code, Codex CLI, Gemini CLI and opencode: a
     proxy in the sandbox receives each agent's model API calls, relays them to Inspect's model layer
     and logs the transcript [W34].
   - *Costs:* one loopback hop (sub-millisecond against seconds of generation; plan §8 prefers server
     timings anyway). The proxy must forward chunks unbuffered and pass the `Server` header and
     `/models` through unchanged. A spike should confirm that prefill timing matches an in-process
     transport.
   - *Model port:* the harness then knows only the proxy's port. So OD-5(a) should refuse to grant any
     port that has a listener at grant time (the plan's free-port check does the same), which also
     covers the real server's port.
   - Keep `ModelBackend` as the seam for replay and scripted tests.
   - **If the owner keeps the in-process backend:** the header must record `backend_origin`, which is
     `harness-client` only when the harness's own constructor built it (a private token) and
     `embedder:<name>@<version>` otherwise, with the endpoint class "embedder-declared".
6. **No attested mode.** State in the contract that leaderboard integrity is server-side (ADR-0007), and
   list what the harness contributes and what each proves: the `task` and `workspace_tree` digests bind
   a journal to its challenge; `replay` catches truthful-but-modified harnesses; neither stops forgery,
   which only deliverable re-grading (T1) and published-data analysis address.
7. **Contract §10 Q1: embed in process for the FYP** (fastest), and keep the child-process path tested in
   rustybenchmark's CI. `rustyharness run` already speaks the child protocol (§7.7), the proxy makes both
   paths timeable, and the child path is what a bring-your-own-agent adapter would use.

**Against the criteria.** Security: 1, 2 and 5 remove silent failure modes. Long-term soundness: the
precedence and the gate stop drift as the "wild" line grows. Performance: neutral (one loopback hop).
User experience: `--plan` shows users what the agent may do. Project speed: 1, 3 and 4 are small; 2 is a
design paragraph; 5 is a spike plus a small proxy, and it removes the wire-identity test and a second
transport to maintain.

### Verdict
**MODIFY.** Configuration-only is the right pattern and matches every major harness, but it has to be
structural, explicit, checkable and labelled. Confidence **high** for 1–4, 6 and 7; **medium** for 5
(spike first; if prefill timing differs, fall back to the origin-stamped backend).

---

## 5. ADR-0002: standalone first, suite integration as add-ons

### Restate
rustyharness is a general harness that works with nothing else from rustysuite installed. Suite
capabilities ship with it as optional add-ons, off unless enabled (cargo features and/or adapters loaded
at runtime). The harness's own security defaults apply to every user; shared types live in standalone
crates; open standards (MCP) come first [L2]. The suite records the same decision as ADR-024 [L15].

### Prior art
| Harness | How integrations stay out of the core | Source |
|---|---|---|
| Claude Code | Plugins are folders with a manifest bundling skills, agents, hooks, MCP and LSP servers, distributed through marketplaces; managed settings can force plugins on or off | [W29] |
| Gemini CLI | Extensions bundle prompts, MCP servers, commands, hooks, sub-agents and skills; installed from a GitHub URL; public gallery | [W29] |
| goose | Every extension is an MCP server (stdio, HTTP or built-in); "70+ extensions via the Model Context Protocol" | [W29] |
| opencode | JS/TS plugins with event hooks that can add or override tools, loaded from local folders or npm; MCP servers | [W29] |
| OpenAI Codex | Plugins bundle skills, MCP servers and hooks, distributed through marketplaces | [W29] |
| Front ends | ACP (JSON-RPC over stdio, modelled on LSP) is spoken by Gemini CLI, goose, opencode, Cline, OpenHands and others; Claude and Codex through adapters | [W30] |
| Stewardship | MCP, goose and AGENTS.md sit in the Linux Foundation's Agentic AI Foundation (founded 9 Dec 2025) | [W16] |

**The pattern.** Integrations live *outside* the core and arrive as separately distributed bundles
(plugins, extensions, MCP servers), never as feature flags in the core repository. MCP is the common
tool wire, and trust comes from the user's or admin's configuration, not the server. What nobody else
has is a harness-specific manifest as the trust root. That is rustyharness's stricter design, and it is
why onboarding needs automating (attack 4).

### Attack
1. **"Ships with the harness" keeps suite code in the harness repository.** Design §8 plans `addon-*`
   cargo features for a mesh model transport and a secret-custody client [L1]. After OI-43, the suite's
   Claude does not develop the harness, so suite features in this repository either wait for the
   owner's isolated stream or break the isolation. Every add-on change is also a harness release, which
   is noise against D16's epochs.
2. **The core already names a suite app.** `RESERVED_NAMESPACES = ["harness", "rustyvault"]`
   (`harness-manifest/src/lib.rs:55` [L6]) puts the suite's secret-custody service into the standalone
   core. That goes against the design's own rule that "the core knows effect classes, never apps"
   [L18 §4], and it publishes a private suite name in public code. OI-43 leaves naming to the owner, and
   OI-12's scan will flag it.
3. **The public docs are suite-heavy.** At `4ad8847` the docs mention rustysuite 26 times, rustyvault
   13, rustyfin 10, "the personal-data app" 11 and suitectl 6, and the overview's use cases U1–U5 are
   all suite uses [L18]. A standalone user reads about a suite they cannot get, and the owner may not
   want those names public.
4. **Bringing an existing MCP server means hand-writing a manifest.** The manifest is the trust root,
   and it is the right security call: the MCP spec itself calls tool annotations untrusted [L1 §4.6].
   But other harnesses admit an MCP server with one config entry and per-tool prompts (prior art
   above). Until manifests are drafted automatically, ADR-0002's "so standalone users can bring
   existing tools" is only half true.
5. **Housekeeping.** ADR-0002 item 4's revisit has happened (suite ADR-022: present-non-member dev/ops
   tool), but ADR-0002 does not say so. And gate-outcome is about to gain suite consumers (OI-08,
   ADR-025) while it is still a workspace member of an owner-isolated repository.

### Better
1. **Suite add-ons live in the suite.** They become crates that implement the harness's public traits
   (`ModelBackend` for the mesh transport, `SecretStore` for custody; providers stay manifests plus MCP
   servers shipped with each app, as §4.10 already says), composed into a suite-built binary on top of
   `harness_cli::main_with` (the CLI is already a library). The harness repository then holds no suite
   code and no `addon-*` features, and INV-32 holds by construction. The cost is that the extension
   traits become stable public API, which contract H-4 needs anyway.
2. **Reserve only `harness` in the core.** The suite binary compiles `rustyvault` into the additive
   reserved list. R5 §6.3's worry was configuration that could *remove* a name; a list compiled into the
   suite binary is code, not configuration.
3. **Move suite material out of the core docs** (the detail of U1–U5 and §8's suite column) into the
   suite repository or one marked appendix, and run the OI-12 scan before publishing. This is the
   owner's call under OI-43.
4. **`rustyharness provider add --from-mcp <argv>`:** start the server confined, read its `tools/list`,
   draft a manifest at the most restrictive labels with the hashes pinned, and show the plain-language
   table. The user may lower a label only with an explicit acknowledgement, and only within §4.4's
   limits for the pinned tier. The trust root stays; the paperwork goes.
5. **Mark ADR-0002 item 4 as answered by ADR-022, and extract gate-outcome to its own repository when
   the first suite consumer lands (OI-08)**, not "before H3 exits".

**Against the criteria.** Long-term soundness and security improve (a smaller core, no suite names in
it, no feature flags to switch on by mistake). User experience improves for MCP users. Project speed:
items 2, 3 and 5 are small; items 1 and 4 belong to H4/H5 and cost nothing before then.

### Verdict
**MODIFY:** keep the principle, change the packaging. Confidence **high**.

---

## 6. P9: the licence of gate-outcome, and the licence split as a whole

### Restate
gate-outcome, the shared outcome-type crate, would be MIT OR Apache-2.0 as a recorded exception to
ADR-0003, while rustyharness (and rustybenchmark's code) stay PolyForm Noncommercial 1.0.0 (memo 1.1
[L9]).

### Prior art
**Harness licences (checked 24 Sep 2026).**

| Harness | Licence | Outside contributions | Commercial part | Source |
|---|---|---|---|---|
| opencode (now `anomalyco/opencode`) | MIT | No CLA | "OpenCode Enterprise" sold separately | [W1] |
| Cline | Apache-2.0 | No CLA; contributions under Apache-2.0 | Paid Enterprise tier | [W2] |
| OpenAI Codex CLI | Apache-2.0 | **Accepts no outside code contributions or pull requests** (a CLA file remains) | None in the repo | [W3] |
| Aider | Apache-2.0 | Individual CLA required | None | [W4] |
| goose (moved to the AAIF, `aaif-goose/goose`, April 2026) | Apache-2.0 | No CLA | None | [W5] |
| OpenHands and its Software Agent SDK | MIT | — | **Enterprise code in separate repos under PolyForm Free Trial 1.0.0; no outside contributions there** | [W6] |
| Continue | Apache-2.0 | CLA required | Acquired by Cursor; repo read-only (date UNVERIFIED) | [W7] |
| Roo Code | Apache-2.0 | UNVERIFIED | Shut down 15 May 2026; repo archived | [W8] |
| Gemini CLI | Apache-2.0 | Google CLA required | None in the repo | [W9] |
| Claude Code | Proprietary ("All rights reserved"; Commercial Terms) | — | The whole product | [W10] |
| Claude Agent SDK | Python: MIT wrapper that bundles the proprietary CLI; TypeScript: proprietary | — | — | [W11] |
| Anthropic `sandbox-runtime` | Apache-2.0: an open sandbox layer under a proprietary product | — | — | [W12] |
| mini-SWE-agent; Harbor with Terminus-2 | MIT; Apache-2.0 | — | — | [W13] |

**Benchmark licences.** SWE-bench code is MIT (its datasets and results state no licence);
Terminal-Bench and Harbor are Apache-2.0, tasks included; HELM and EvalPlus are Apache-2.0;
LiveCodeBench is MIT; MLPerf Inference code *and* results are Apache-2.0, with an MLCommons CLA and
messaging rules for results [W14]. Noncommercial terms do occur in evaluation, but on data, or from
large labs: AlpacaEval's data and Meta's MLGym agent framework are CC BY-NC 4.0 [W15]. I found no
benchmark or eval harness under PolyForm NC (UNVERIFIED: the search budget ran out). rustybenchmark's
explicit CC BY 4.0 licence for results is *better* than much of the field, where results carry no
licence at all.

**What the pattern says.** Among the harnesses the owner compares rustyharness with, everything except
Claude Code is permissive. The vendors that sell something keep the core permissive and put the paid
part elsewhere (OpenHands under a PolyForm licence, opencode and Cline as enterprise tiers); even
Anthropic, whose agent is proprietary, released its sandbox layer as Apache-2.0. rustyharness is the
reverse: everything noncommercial. On contributions, both mainstream answers exist: a CLA (Aider,
Continue, Gemini CLI) or no outside code at all (Codex; OpenHands enterprise).

**PolyForm, source-available alternatives and copyright.**

- **What PolyForm NC permits.** It has two safe harbours: personal use for research, study and hobby
  projects with no anticipated commercial application; and use by charities, educational institutions,
  public research organisations and government bodies "regardless of the source of funding". Research
  done *for a company* falls outside both safe harbours on my reading, and the licence deliberately does
  not define "noncommercial" [W39].
- **Extra grants are allowed.** The "No Other Rights" clause does not stop the licensor granting other
  licences to anyone. PolyForm asks that an edited text drop the PolyForm name, so an exception should be
  a separate grant, not an edit. PolyForm's own Countdown grant is an example of such an add-on grant
  [W39].
- **Not open source, with packaging consequences.** OSD clause 6 and Debian's DFSG 6 forbid
  restricting use in a business, so NC work goes to Debian's non-free area. Homebrew core accepts only
  DFSG-compatible licences, though a personal tap is fine. crates.io accepts the SPDX id
  `PolyForm-Noncommercial-1.0.0` [W40].
- **Adoption signals.** Umbrel's move to PolyForm NC drew public criticism of its "open source" claim.
  After EPPlus moved from LGPL to PolyForm NC, a downstream project (nopCommerce) opened an issue to
  replace it [W41].
- **Alternatives that block competitors rather than all businesses** [W42]:
  - FSL (Sentry): any use except a competing product; each release becomes Apache-2.0 or MIT after two
    years. Fair Source lists 13 companies using this family;
  - PolyForm Shield: no competing products;
  - PolyForm Small Business: free under 100 people and USD 1M revenue;
  - BSL 1.1.
- **Contributions.** Under GitHub's terms, a contribution arrives under the repository's licence. So
  without a CLA, the author holds only noncommercial rights in other people's code. NextUI's move to
  PolyForm NC needed every contributor's consent or a rewrite. Elastic and Grafana require CLAs that keep
  relicensing possible. GitLab replaced its CLA with a DCO in 2017, saying CLAs deterred contributors
  [W43].
- **Copyright in AI-assisted code (not legal advice).**
  - The US Copyright Office (January 2025): AI output is protected only where a human determined enough
    of its expressive elements; prompts alone are not enough, but human selection, arrangement and
    modification can be protected.
  - Ireland's Copyright and Related Rights Act 2000 (s.21(f)) and the UK's CDPA (s.9(3)): the author of
    a computer-generated work is the person who made the arrangements for it [W44].
- **University of Limerick IP policy (v3.0, effective 16 June 2026).** UL owns IP created in "UL
  Research", which is triggered by using UL-owned IP, UL research facilities or equipment, UL-administered
  funding, or sponsored research. IP that undergraduates create solely as part of their education is
  excluded [W45].

### Attack on P9
1. **Its reason has gone.** Memo 1.1 recommended the exception because the suite would not link
   PolyForm NC crates into anything it publishes [L9; L1 §11 Q1]. On the same day, ADR-021 made PolyForm
   NC the licence of every suite project, and the owner chose one licence over the guide's
   recommendation to allow a mix [L15]. Every consumer of gate-outcome (rustyharness, rustybenchmark,
   and the suite's Rust gates under OI-08 and ADR-025) is now PolyForm NC, from the same licensor.
2. **The only people left who would benefit are the ones ADR-021 excludes.** A permissive
   gate-outcome helps third parties, businesses included. That is precisely the exception ADR-021
   ("Can't use it to make money") rules out.
3. **Interoperability does not need a permissive crate.** A third party that wants to speak the child
   protocol or emit a `GateReport` needs the *format*, not this code. If that matters, publish the
   format (the child protocol and the report JSON) as a specification under CC BY 4.0, the way
   rustybenchmark already licenses its data dictionary [L13].
4. **A one-crate exception inside a PolyForm workspace is a maintenance trap** until the crate is
   extracted: every crate today inherits `license.workspace = true`, which is PolyForm NC, gate-outcome
   included (checked at `4ad8847`).

### Attack on the split as a whole: should everything be permissive?
5. **Owner intent rules out "everything permissive".** ADR-021 is explicit, and rustybenchmark's
   OPEN-QUESTIONS Q1 records that the cost to commercial evaluation was accepted "deliberately" [L15,
   L13]. The question is not whether to be permissive, but which residual problems NC leaves. There are
   three.
6. **Residual 1: reproducing a leaderboard row.** Q1 argues that re-deriving the leaderboard from the
   CC BY dump is not a licensed use of the software, and that is right for re-aggregating published
   data. But *reproducing* a row (running the benchmark on the same model and hardware, or ADR-0007's T3
   audit) needs the PolyForm NC benchmark and, in agent mode, the PolyForm NC harness. So a commercial
   auditor, such as a GPU vendor challenging a throughput row, needs a licence first. DATA-LICENSE
   names exactly these parties as the ones with the motive to audit [L13]. ADR-0007 and docs/11 also
   promise to "open-source the aggregation code" [L11, L14]; under ADR-021 that code is source-available,
   not open source, so the wording is now wrong. Nearly every well-known agent benchmark's code is
   permissive (Meta's MLGym, CC BY-NC, is the exception I found; prior art above), so outsiders will
   expect to be able to reproduce.
7. **Residual 2: the first outside contribution breaks the commercial-licence route.** There is no
   CONTRIBUTING.md and no CLA (checked [L3]). A contribution arrives under the repository's licence, so
   a contributor grants only PolyForm NC rights. The owner could then not put that code into the separate
   commercial licences that ADR-0003 offers, and relicensing later would need every contributor's consent
   or a rewrite, as NextUI found [W43]. It is free to fix now and impossible to fix afterwards. It
   applies to every repository under ADR-021.
8. **Residual 3: the licence is a weaker control than it looks.** Every commit carries a Claude
   co-author trailer (41 trailers across 38 commits, checked [L3]). The US Copyright Office protects AI
   output only where a human determined its expressive elements, while Irish and UK law name the person
   who made the arrangements as the author of a computer-generated work [W44]. So the owner's position is
   stronger at home than in the US. This is not legal advice, but the practical point stands: against a
   determined business the licence is a statement of terms whose strength varies by jurisdiction, not a
   technical control. Keep the design documents and reviews; they record the human authorship of the
   design.
9. **What stays in the owner's favour.** Starting noncommercial and relaxing later is the low-regret
   order. The owner is the sole author (38 of 38 commits), so relaxing takes one decision, while a
   permissive release can never be withdrawn (ADR-021 says so itself [L15]). For the FYP, PolyForm NC is
   no obstacle: personal research and use by educational institutions are permitted purposes, so the
   supervisor and examiners are covered [W39].
10. **One precondition to check: who owns the FYP code.** UL's IP policy leaves undergraduates' purely
    educational work with the student, but UL owns IP from "UL Research", which is triggered by UL-owned
    research equipment, facilities, funding or IP [W45]. If any of that is used (for example, if the
    second test machine or a GPU server is UL's), the licence may not be the owner's to grant. A
    one-line confirmation with the supervisor settles it.

### Better
1. **P9: replace the recommendation with the default.** gate-outcome stays PolyForm-Noncommercial-1.0.0
   under ADR-021. Close design §11 Q1 and memo 1.1 citing ADR-021, and remove the now-stale sentence that
   the suite does not link PolyForm NC crates.
2. **A contribution policy in every repository, before the OI-12 pushes make them public.** Either
   "issues welcome, code contributions not accepted" (what OpenAI Codex now does [W3]) or a CLA that
   lets the owner relicense contributions, commercial licences included (as Aider, Continue and Gemini
   CLI require CLAs [W4, W7, W9]).
3. **Before any public leaderboard (not needed for the FYP), grant one narrow public permission** for
   rustybenchmark and the rustyharness release it pins: anyone may run unmodified releases, for any
   purpose, solely to reproduce, verify or audit published Rustybenchmark results, and may publish what
   they find. It gives no right to modify, embed, resell or host. PolyForm's "No Other Rights" clause
   leaves the licensor free to grant other licences to anyone. Make it a separate grant file beside the
   unedited licence, as PolyForm's own add-on grants are [W39]. Whether to add "evaluate a model and
   submit it to the leaderboard" is the owner's commercial lever; I would leave it out and offer a
   licence on request.
4. **Fix the wording** "open-source the aggregation code" to "publish the aggregation code
   (source-available)" in ADR-0007 and docs/11.
5. **Set a dated revisit trigger:** the first commercial-licence request or the leaderboard's launch,
   whichever comes first. If the owner's concern has by then become "no competitor sells it" rather than
   "no business uses it", FSL or PolyForm Shield fit better [W42].
6. **Confirm FYP ownership with the supervisor** (attack 10) before the OI-12 pushes publish anything.

**Against the criteria.** Long-term soundness: 2 is the one item that cannot be fixed later. Leaderboard
credibility: 3 and 4. Project speed: all are small text changes; none touches the FYP's critical path.

### Verdict
**P9: REPLACE** the MIT/Apache exception with the default (PolyForm NC, per ADR-021). Confidence
**high**. **The split as a whole: KEEP noncommercial,** with better 2, 4 and 6 (confidence **high**)
and better 3 (confidence **medium**: the owner's commercial call).

---

## 7. P11: `restricted` capabilities never, permanently

### Restate
The harness may never hold `restricted` (life-data) capabilities. INV-27's refusal becomes permanent,
and reopening it needs a superseding ADR (memo 1.3, option A [L9]).

### Prior art
No harness I checked has a data class that can never be granted. They keep sensitive data out with path
rules, and Cursor says plainly that its rules are advisory:

| Harness | Mechanism | Strength | Source |
|---|---|---|---|
| Claude Code | `permissions.deny` rules such as `Read(./.env)`; managed settings that "nothing you set overrides"; `allowManagedPermissionRulesOnly` | Enforced by the harness for its own tools; the sandbox adds OS-level limits | [W18] |
| Cursor | `.cursorignore` | Advisory: its docs say the terminal and MCP tools the agent uses "cannot block access" to ignored code | [W19] |
| Gemini CLI | `.geminiignore` | Honoured by the tools that respect it | [W20] |
| Aider | `.aiderignore` in the git root | Keeps files out of aider's view | [W21] |
| OpenHands SDK | A security analyzer rates each action LOW, MEDIUM or HIGH, and a confirmation policy (`ConfirmRisky`) pauses risky ones | Per-action judgement, not a data class | [W26] |

**What this says.** rustyharness's class-level refusal (INV-27) is stricter than anything in the
field, which fits a suite that runs life data in a separate, confined runtime. The field's weak spot is
the same as P11's: an ignore rule or a label stops only what it names, and tools that run programs can
reach around path rules unless the sandbox enforces them. So a data-side guard is worth having only if
it is enforced before anything is mounted. The OD-5 delta v2's `Run.never_grant` does that, but only
for declared extra roots (its rule H3); it does not check the workspace itself [L17].

### Attack
1. **"Never" covers what is declared, not the data.** INV-27 refuses capabilities *declared*
   `restricted`. Labels come from the provider (the signed tier "may declare any dimension values"
   [L1 §4.4]), and a workspace or an OD-5(c) read-only root can point at a folder of life data with no
   label at all. The harness cannot classify data. The honest guarantee is "never by declaration".
2. **The real reason is not written down, so "permanently" rests on rhetoric.** The strongest reason is
   architectural. The journal is append-only and hash-chained, keeps every payload as blobs, and is kept
   by default (P14); snapshots keep workspace contents [L1 §7.1]. Restricted data in a session would be
   stored indefinitely and could not be deleted without breaking the chain. That is incompatible with any
   erasure duty (GDPR Article 17, for example, when an app acts as a controller [W17]) and with a user
   who just wants a diary entry gone. That makes "never" the right answer for *this* design, not a
   preference.
3. **It orphans the overview's use case U5.** The overview still lists "the personal-data app's
   ask-model features — each app uses the harness instead of building its own loop" [L18 §2]. Under P11
   the life-data app builds its own loop: two loops, which is the drift that design §1.4 exists to
   prevent.

### Better
1. **Keep "never" for the rustyharness product:** the binary, the action domain and the journal.
2. **Record the reason and a reopening bar in the ADR:** reopening needs crypto-shreddable journal
   payloads (per-run keys that can be destroyed), a threat model for restricted data, and a new
   trust-domain decision (ADR-0002 item 3, ADR-024). It is not a policy switch.
3. **Record the scope ("never by declaration") and add a data-side guard:** a user-level never-grant list
   in the CLI, fed into the OD-5 delta v2's `Run.never_grant` [L17] and pre-filled with known life-data
   stores; extend that check from declared roots to the workspace itself; and add a README and
   SECURITY.md warning not to point the harness at such data.
4. **Let the life-data app's own confined router reuse the pure crates** (`harness-core`,
   `harness-model-core`, `harness-policy`: no I/O, no exec, no journal), inside its own trust domain and
   its own review. ADR-021 removed the licence obstacle. Fix overview U5 to match.

**Against the criteria.** Security and long-term soundness improve (the refusal is principled, and the
data-side gap is named and partly guarded). Project speed: text changes plus one CLI list, none on the
FYP path.

### Verdict
**KEEP "never"**, and tighten the record as above. Confidence **high** for keeping it; **medium** for
item 4 (the suite's call).

---

## Top changes I'd make

In order: first the ones that cannot be fixed later or protect the FYP path, then the ones that shape
the leaderboard, then tidying.

1. **P9 → keep gate-outcome PolyForm NC (ADR-021), and add a contribution policy or CLA to every
   repository before the OI-12 pushes make them public.** A contribution accepted without one cannot be
   relicensed later. In the same pass, confirm with the supervisor that the FYP uses no UL research
   equipment, facilities or funding, so the code is the owner's to license (section 6).
2. **Make benchmark mode structural, not a promise:** an ambient-free library enforced by gate, a written
   precedence with a sealed embedder layer, a `plan()` pre-flight report, and header `annotations`
   (section 4, better 1–4). All small; all stop silent drift as the "wild" line grows.
3. **Pin the study exactly and give epochs an objective rule:** a tag and commit on `main`, a
   `release/study-1` backport branch, the golden-journal audit as the epoch test, and a frozen
   benchmark-mode surface (section 1, better 2–4 and 6). This keeps the one-pager's "minimal harness"
   promise and lets security fixes ship mid-study.
4. **Time model calls through a loopback proxy and keep the harness's own client** (spike first), or,
   failing that, stamp the backend's origin in the header (section 4, better 5).
5. **Write the superseding benchmark ADR:** rustyharness is the Agentic board's reference agent; a
   labelled, T0 bring-your-own-agent division is designed now and built after the FYP; agentic rows
   reach T1 for correctness by re-grading the deliverable, with server-side `replay` only as a
   misconfiguration check (section 1, better 1 and 5).
6. **Before any public leaderboard:** a narrow public permission to reproduce and audit results, and
   "source-available" instead of "open-source" in ADR-0007 and docs/11 (section 6, better 3–4).
7. **Repackage the add-ons (ADR-0002):** suite add-ons and the `rustyvault` reservation move to a suite
   composition binary; suite material leaves the core docs (owner's call under OI-43); manifests are
   drafted from MCP `tools/list`; gate-outcome is extracted when OI-08 lands (section 5).
8. **Tighten P11's record:** the append-only-journal reason, "never by declaration", a reopening bar, a
   user never-grant list, pure-crate reuse, and a corrected overview U5 (section 7).
9. **Reword D17, add a journal-reader contract, split D18 into study and wild lines, and replace "like
   opencode or Cline" with a parity checklist that states what the trifecta refuses** (sections 2–3).

---

## Sources

### Web sources (read on 24 Sep 2026)

- [W1] opencode: https://github.com/anomalyco/opencode/blob/dev/LICENSE · https://github.com/anomalyco/opencode/blob/dev/CONTRIBUTING.md · https://opencode.ai/enterprise
- [W2] Cline: https://github.com/cline/cline/blob/main/LICENSE · https://github.com/cline/cline/blob/main/CONTRIBUTING.md · https://cline.bot/pricing
- [W3] OpenAI Codex licence and contributions: https://github.com/openai/codex/blob/main/LICENSE · https://github.com/openai/codex/blob/main/docs/contributing.md
- [W4] Aider: https://github.com/Aider-AI/aider/blob/main/LICENSE.txt · https://github.com/Aider-AI/aider/blob/main/CONTRIBUTING.md
- [W5] goose: https://github.com/aaif-goose/goose/blob/main/LICENSE · https://goose-docs.ai/blog/2026/04/07/goose-moves-to-aaif/
- [W6] OpenHands: https://github.com/OpenHands/OpenHands/blob/main/LICENSE · https://github.com/OpenHands/software-agent-sdk/blob/main/LICENSE · https://github.com/OpenHands/enterprise · https://github.com/OpenHands/OpenHands-Cloud/blob/main/LICENSE
- [W7] Continue: https://github.com/continuedev/continue/blob/main/LICENSE · https://raw.githubusercontent.com/continuedev/continue/main/CONTRIBUTING.md · https://continue.dev/
- [W8] Roo Code: https://github.com/RooCodeInc/Roo-Code · https://docs.roocode.com/sunset
- [W9] Gemini CLI licence and CLA: https://github.com/google-gemini/gemini-cli/blob/main/LICENSE · https://github.com/google-gemini/gemini-cli/blob/main/CONTRIBUTING.md
- [W10] Claude Code licence: https://github.com/anthropics/claude-code/blob/main/LICENSE.md
- [W11] Claude Agent SDK licences: https://github.com/anthropics/claude-agent-sdk-python/blob/main/LICENSE · https://pypi.org/project/claude-agent-sdk/ · https://github.com/anthropics/claude-agent-sdk-typescript/blob/main/LICENSE.md
- [W12] Anthropic sandbox: https://github.com/anthropic-experimental/sandbox-runtime · https://www.anthropic.com/engineering/claude-code-sandboxing
- [W13] mini-SWE-agent and Harbor licences: https://github.com/SWE-agent/mini-swe-agent/blob/main/LICENSE.md · https://github.com/harbor-framework/harbor/blob/main/LICENSE
- [W14] Benchmark licences: https://github.com/SWE-bench/SWE-bench/blob/main/LICENSE · https://github.com/harbor-framework/terminal-bench-2 · https://github.com/stanford-crfm/helm/blob/main/LICENSE · https://github.com/LiveCodeBench/LiveCodeBench/blob/main/LICENSE · https://github.com/evalplus/evalplus/blob/master/LICENSE · https://github.com/mlcommons/inference/blob/master/LICENSE.md · https://raw.githubusercontent.com/mlcommons/policies/master/MLPerf_Results_Messaging_Guidelines.adoc
- [W15] Noncommercial evaluation assets: https://raw.githubusercontent.com/tatsu-lab/alpaca_eval/main/README.md · https://github.com/facebookresearch/MLGym/blob/main/LICENSE
- [W16] Agentic AI Foundation: https://www.linuxfoundation.org/press/linux-foundation-announces-the-formation-of-the-agentic-ai-foundation · https://aaif.io/projects/
- [W17] GDPR Article 17: https://gdpr-info.eu/art-17-gdpr/
- [W18] Claude Code settings and permissions: https://code.claude.com/docs/en/settings · https://code.claude.com/docs/en/permissions
- [W19] Cursor ignore files: https://cursor.com/docs/context/ignore-files
- [W20] Gemini CLI ignore file: https://geminicli.com/docs/cli/gemini-ignore/
- [W21] Aider options (`.aiderignore`): https://aider.chat/docs/config/options.html
- [W22] Claude Agent SDK: https://code.claude.com/docs/en/agent-sdk/overview · https://code.claude.com/docs/en/agent-sdk/claude-code-features · https://code.claude.com/docs/en/agent-sdk/migration-guide · https://github.com/anthropics/claude-agent-sdk-python/releases/tag/v0.1.60 · https://code.claude.com/docs/en/agent-sdk/permissions · https://code.claude.com/docs/en/headless · https://code.claude.com/docs/en/managed-settings
- [W23] OpenAI Codex embedding and config: https://learn.chatgpt.com/docs/non-interactive-mode · https://github.com/openai/codex/blob/main/codex-rs/exec/src/lib.rs · https://github.com/openai/codex/tree/main/sdk/typescript · https://learn.chatgpt.com/docs/app-server · https://learn.chatgpt.com/docs/mcp-server · https://learn.chatgpt.com/docs/config-file/config-basic · https://learn.chatgpt.com/docs/enterprise/managed-configuration · https://learn.chatgpt.com/docs/agent-configuration/agents-md · https://github.com/openai/codex/issues/5983
- [W24] opencode embedding and config: https://opencode.ai/docs/server · https://opencode.ai/docs/sdk · https://opencode.ai/docs/permissions · https://opencode.ai/docs/config · https://opencode.ai/docs/rules
- [W25] goose: https://github.com/aaif-goose/goose/blob/main/documentation/docs/guides/running-tasks.md · https://github.com/aaif-goose/goose/blob/main/documentation/docs/guides/managing-tools/goose-permissions.md · https://github.com/aaif-goose/goose/blob/main/documentation/docs/guides/allowlist.md · https://github.com/aaif-goose/goose/blob/main/documentation/docs/guides/environment-variables.md · https://github.com/aaif-goose/goose/blob/main/documentation/docs/guides/remote-goose-server.md
- [W26] OpenHands SDK and benchmarks: https://docs.openhands.dev/sdk/arch/overview · https://docs.openhands.dev/sdk/arch/security · https://docs.openhands.dev/sdk/guides/skill.md · https://github.com/OpenHands/benchmarks
- [W27] Gemini CLI configuration: https://geminicli.com/docs/reference/configuration · https://geminicli.com/docs/admin/enterprise-controls.md · https://geminicli.com/docs/reference/policy-engine · https://geminicli.com/docs/cli/headless · https://geminicli.com/docs/cli/trusted-folders
- [W28] Cline: https://docs.cline.bot/usage/cli-overview.md · https://docs.cline.bot/customization/cline-rules.md · https://docs.cline.bot/enterprise-solutions/configuration/remote-configuration/overview.md
- [W29] Plugins and extensions: https://code.claude.com/docs/en/plugins · https://geminicli.com/docs/extensions · https://opencode.ai/docs/plugins · https://learn.chatgpt.com/docs/plugins · https://github.com/aaif-goose/goose
- [W30] Agent Client Protocol: https://agentclientprotocol.com/overview/introduction · https://agentclientprotocol.com/overview/agents
- [W31] SWE-bench boards and submissions: https://www.swebench.com/ · https://mini-swe-agent.com/latest/ · https://github.com/SWE-bench/experiments · https://raw.githubusercontent.com/SWE-bench/experiments/main/checklist.md
- [W32] Terminal-Bench: https://www.tbench.ai/leaderboard · https://www.tbench.ai/news · https://www.tbench.ai/news/terminal-bench-3-0 · https://www.tbench.ai/news/terminal-bench-4-0 · https://arxiv.org/abs/2601.11868
- [W33] Terminal-Bench integrity: https://www.tbench.ai/news/leaderboard-integrity-and-timeouts · https://www.tbench.ai/news/leaderboard-integrity-update
- [W34] Inspect AI: https://inspect.aisi.org.uk/ · https://inspect.aisi.org.uk/agent-bridge.html · https://meridianlabs-ai.github.io/inspect_swe/
- [W35] Harbor agents and leaderboards: https://docs.harborframework.com/core-concepts/agents/pre-integrated-agents.md · https://docs.harborframework.com/core-concepts/harbor-hub/leaderboards.md
- [W36] HAL: https://arxiv.org/abs/2510.11977 · https://hal.cs.princeton.edu/ · https://github.com/princeton-pli/hal-harness
- [W37] Aider leaderboard: https://aider.chat/docs/leaderboards/ · https://github.com/Aider-AI/aider/blob/main/aider/website/_data/polyglot_leaderboard.yml
- [W38] MLPerf per-round results: https://api.github.com/repos/mlcommons/inference_results_v6.0
- [W39] PolyForm: https://polyformproject.org/licenses/noncommercial/1.0.0 · https://github.com/polyformproject/polyform-licenses · https://polyformproject.org/licenses/countdown/1.0.0 · https://writing.kemitchell.com/2021/06/20/License-Round-Up
- [W40] Open source definitions and packaging: https://opensource.org/osd · https://www.debian.org/social_contract#guidelines · https://docs.brew.sh/Licence-Guidelines · https://spdx.org/licenses/PolyForm-Noncommercial-1.0.0.html · https://doc.rust-lang.org/cargo/reference/manifest.html
- [W41] PolyForm NC adoption: https://github.com/getumbrel/umbrel/pull/908 · https://news.ycombinator.com/item?id=31658939 · https://www.epplussoftware.com/en/Home/LgplToPolyform · https://github.com/nopSolutions/nopCommerce/issues/5066
- [W42] Source-available alternatives: https://fsl.software/ · https://fair.io/about/ · https://fair.io/companies/ · https://polyformproject.org/licenses/shield/1.0.0 · https://polyformproject.org/licenses/small-business/1.0.0 · https://mariadb.com/bsl11/
- [W43] Contributions and CLAs: https://docs.github.com/en/site-policy/github-terms/github-terms-of-service · https://github.com/LoveRetro/NextUI/issues/765 · https://www.elastic.co/contributor-agreement · https://github.com/grafana/grafana/blob/main/CONTRIBUTING.md · https://about.gitlab.com/blog/2017/11/01/gitlab-switches-to-dco-license/
- [W44] Copyright and AI-assisted works: https://www.copyright.gov/newsnet/2025/1060.html · https://www.copyright.gov/ai/Copyright-and-Artificial-Intelligence-Part-2-Copyrightability-Report.pdf · https://data.oireachtas.ie/ie/oireachtas/act/2000/28/eng/enacted/a2800.pdf · https://www.legislation.gov.uk/ukpga/1988/48/section/9
- [W45] University of Limerick IP policy v3.0: https://www.ul.ie/media/res001intellectual-property-policy/download?inline · https://www.ul.ie/policy-hub/policies/research
- [W46] Attestation for evaluations (research only): https://arxiv.org/abs/2506.23706 · https://arxiv.org/abs/2402.02675

### Local sources (read only)

- [L1] rustyharness `origin/main` @ `4ad8847`: `docs/01-design-v0.1.md` (design v0.2, "Changes since v0.2", "Owner decisions after v0.2" OD-1..OD-7, §0–§11).
- [L2] rustyharness @ `4ad8847`: `docs/adr/0002-standalone-first.md` and `docs/adr/0003-licence.md`.
- [L3] rustyharness @ `4ad8847`: `README.md`, `docs/OPEN-QUESTIONS.md`, `LICENSE.md`, crate `Cargo.toml` licence fields; `git log` (38 commits, all by the owner, 41 `Co-Authored-By: Claude` trailers); no CONTRIBUTING file.
- [L4] rustyharness @ `4ad8847`: `crates/harness-run/src/driver.rs` (`Run` 115-139; `identity: &r.backend.identity()` 247; `HEADER_INPUT_KEYS` 476-486; header 496-610, `version` from `CARGO_PKG_VERSION` 497, `endpoint` 521).
- [L5] rustyharness @ `4ad8847`: `crates/harness-model/src/lib.rs:49-55` (`pub trait ModelBackend`), `scripted.rs`, `client.rs` (`RetryPolicy`, `max_retries: 3`); `crates/harness-model-core/src/lib.rs` (`ModelIdentity`, `EndpointClass`).
- [L6] rustyharness @ `4ad8847`: `crates/harness-manifest/src/lib.rs:55` (`RESERVED_NAMESPACES`); `crates/harness-cli/src/main.rs:23` (the one ambient read, `GATE_OK_FILE`).
- [L7] `FYP/proposal/measurement-plan.md` v0.10 (§0 D1–D33, §4, §11).
- [L8] `FYP/proposal/rustyharness-contract.md` v0.4.
- [L9] `FYP/proposal/rustyharness-owner-questions-memo.md` (items 1.1, 1.3).
- [L10] rustybenchmark @ `215f573`: `docs/15-profiles-and-divisions.md` (§3.4 lines 141-150, §9.3 line 554, §11.2 line 657).
- [L11] rustybenchmark @ `215f573`: `docs/adr/0007-trust-tiers-over-client-attestation.md` (line 58).
- [L12] rustybenchmark @ `215f573`: `docs/adr/0010-pinned-tuned-open-divisions.md` (line 32).
- [L13] rustybenchmark @ `215f573`: `README.md` (Licence, lines 85-108), `DATA-LICENSE.md`, `docs/OPEN-QUESTIONS.md` (Q1, Q4).
- [L14] rustybenchmark @ `215f573`: `docs/10-integrity.md` (anti-gaming controls), `docs/11-submission-and-privacy.md` (line 86).
- [L15] rustysuite `charter/decisions/decision-log.md`, 24 Sep 2026 sections (ADR-021, ADR-022, ADR-024, ADR-025, ADR-026, OI-08, OI-12, OI-43).
- [L16] `FYP/proposal/one-pager-for-jim.md` (lines 46-48, 82).
- [L17] `FYP/proposal/rustyharness-drafts/od5-delta-v2.md` (draft, 24 Sep: §3.1 `Run.never_grant`; §4.2 host rule H3, which checks `never_grant` against declared roots only; header keys `confinement` and `tools`; A-6).
- [L18] rustyharness @ `4ad8847`: `docs/00-overview.md` (§2 U3, U5; §4).
