# 00 — rustyharness overview (DRAFT v0.0)

**Status:** DRAFT v0.0, 2026-09-23 — written at project start, BEFORE the research
pipeline (docs/research/) reports. Unreviewed. It frames the questions the design
must answer; it does not answer them. It will be superseded by the v0.1 design,
which goes through the suite's two-eyes cycle (design → adversarial review →
rework → confirming review → SOUND).

**Since then:** the design is [01-design-v0.1.md](01-design-v0.1.md) (v0.2, reviewed
SOUND), and H1 is built. This overview is kept as the project's original framing;
where the two differ, the design governs.

## 1. What it is

rustyharness is a standalone **agent harness**, built alongside rustysuite: the
runtime that drives a language model through a loop of reasoning and tool calls to do real work, inside
confinement, with every result backed by evidence.

The model is a swappable part. The harness owns everything around it — the
instructions, the tools offered, the permissions, the sandbox, the budget, the
checks that decide whether the work is done — and those are what make an agent
reliable or not. (rustybenchmark's divisions doc records the evidence that
harness effects are the same order of size as model effects:
`projects/rustybenchmark/docs/15-profiles-and-divisions.md` §3.4.)

Name and placement: [ADR-0001](adr/0001-name-and-placement.md).

**Standalone first** ([ADR-0002](adr/0002-standalone-first.md), owner-decided): anyone can use rustyharness with their own agent and model and nothing else from rustysuite. Everything rustysuite-specific in this document (§2's suite uses, suite app adapters, suitectl, gates, the mesh) is an optional add-on, off unless enabled. The security defaults in §3 apply to every user.

**The goal in the wild** (owner, 2026-09-24; design OD-1): on its own, rustyharness aims to do what a general coding agent such as opencode or Cline does: read and edit code, run the toolchain, fetch crates and documentation online, open ports on the device. Every action needs the user's permission and runs inside confinement. Apps that embed it narrow it through their own configuration; the harness holds no app-specific code (design OD-2).

## 2. Where it is used in the suite (candidates — to be confirmed by research)

These are the suite's uses. The first user is anyone with an agent and a model, using none of them.

| # | Use | What the agent does | Seed material |
|---|---|---|---|
| U1 | **Suite development** | Takes a task (an action-queue row, a review finding), works in an isolated worktree, runs the member's gates through `suitectl`, delivers a patch with evidence | `charter/design/component-d-agent-harness-DRAFT.md`, `suite-dev-engine-plan-v1.md` §6 (component D), `suite-engine-v2-rust.md` |
| U2 | **Design and review fleet** | Authors designs and — as a *separate, independent* agent — reviews them. Replaces today's opencode + bash supervisor fleet | the fleet's own failure history (docs/research, lane ah02) |
| U3 | **rustybenchmark Agentic board** | Enters as one pinned, versioned harness so the benchmark measures which model works best in the suite's own harness on each machine. The benchmark embeds `harness-run` with its own locked-down configuration (policy, a provider registry that holds only the compiled-in built-in manifest and no app-specific providers, its profile, optionally its own `ModelBackend`), and grades and measures outside the harness. No benchmark code lives in the harness (owner, 2026-09-24; design OD-2, OD-3) | `projects/rustybenchmark/docs/15-profiles-and-divisions.md` §3.4 |
| U4 | **Operating the suite** | A local admin assistant: check a rustynet node, read a rustydns zone, verify backups — through each app's declared capabilities | owner direction (local admin-assistant model) |
| U5 | **Assistants inside apps** | rustyfin's grounded AI assistant; the personal-data app's ask-model features — each app uses the harness instead of building its own loop | `projects/rustyfin/docs/plans/2026-03-15-ai-grounded-tools-architecture.md`, suite design notes |

Constraint on U5: the personal-data app currently makes ask-model un-grantable by type
(suite AQ-101). The harness must respect an app's refusal, not route around it.

## 3. What it must be capable of (first cut)

1. **A tool loop** with hard budgets (steps, wall-clock, tokens) and explicit stop conditions.
2. **Model backends** behind one trait: local OpenAI-compatible servers first; hosted models only by explicit opt-in (local-first privacy posture).
3. **Capabilities, not raw access.** The agent never gets a shell or a filesystem by default; it gets capabilities that apps declare (§4), each with an effect class that drives policy.
4. **Policy and approval.** Reads can be automatic; writes are scoped; execution is confined; anything irreversible (delete, push, publish, send) needs a human yes, every time.
5. **Confinement that fails closed.** No sandbox, no execution (`crates/harness-sandbox`). Must work on macOS, Linux and Windows.
6. **Tool output is data.** File contents, test logs, web pages and model output are `Untrusted` (`crates/harness-core`); instructions found in them are never followed.
7. **Evidence, not claims.** "Done" is decided by checks the harness runs (tests, and in the suite the members' gates), expressed in one outcome type shared with rustysuite (ADR-0002: a standalone crate, not a suite dependency) and recorded in an append-only journal — never by the agent saying so.
8. **Two pairs of eyes built in.** A reviewer agent that did not author the work, with its own context, whose verdict is extracted from its artifact.
9. **Isolation per run.** Separate state, worktree and scratch space per run, so concurrent runs cannot corrupt each other.
10. **Secrets stay out of the model's context.** Key material reaches tools, never the prompt. Standalone, through the harness's own secret handling; with the suite add-on, through rustyvault's consumer seam (`charter/design/vault-consumer-seam-rust-v0.1.md`).
11. **Resumable and replayable** from the journal.

Added by the owner on 2026-09-24 (design OD-5; required, not yet designed):

12. **Ports with permission.** An agent can run and test a server it builds: granted loopback ports, never the model server's; a port visible on the network is a separate, higher-risk grant.
13. **Background processes.** Start, read output, stop; all killed when the run ends.
14. **Embedder-supplied confinement inputs.** Extra read-only roots (e.g. a local crate registry, a pre-built build cache), a writable build directory outside the workspace, and environment and cargo configuration.
15. **Cleanup that keeps the evidence.** `gc` removes a finished run's workspace, grading and scratch directories and keeps its journal and snapshots.

## 4. Modularity: how future apps slot in without a redesign

The working idea (now manifest v1 in `crates/harness-manifest`; design §4):

- **Each tool provider ships a versioned capability manifest** — rustysuite apps are the first providers, not the only ones; each ships its manifest with itself (`adapters/` holds fixtures only, design §4.10): capability ids namespaced under the app (`rustydns.zone.read`), a human summary, and an **effect class** (`read`, `write`, `execute`, `irreversible`).
- **The core knows effect classes, never apps.** Policy, approval and confinement are written against effect classes, so adding an app adds a manifest and an adapter — no core change.
- **Unknown means refused.** Unknown fields, future schema versions, foreign namespaces and empty manifests are rejected, not skipped.
- **Versioned schema** with explicit negotiation, so old apps keep working when the schema grows.

Open: the wire protocol. Options: a suite-native protocol, MCP (Model Context Protocol, the de-facto standard, with known security criticisms), or native with an MCP bridge. To be settled by research.

## 5. Non-goals (first cut)

- Not a model and not a model server. It drives models; it does not train or host them.
- No hosted model by default.
- No irreversible action without a human yes.
- Not a chat app at first; a user-facing assistant can be built on top later.
- No grading or measuring for an embedding app: an app such as rustybenchmark does that itself (owner, 2026-09-24; design OD-3).

## 6. Open questions

See [OPEN-QUESTIONS.md](OPEN-QUESTIONS.md).
