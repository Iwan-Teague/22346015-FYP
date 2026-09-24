# rustyharness alignment check (24 Sep 2026)

**Checked:** rustyharness `origin/main` at `6ba3437` ("H1f: finish H1", 17 commits after `ee4dfef`),
against this session's decisions ([measurement-plan.md](measurement-plan.md) §0, D1–D19) and the
[contract](rustyharness-contract.md). Read-only: fetched, not merged. The local `main` checkout is still at
`ee4dfef`. Design sections are cited as "RH §n"; open questions as "RH OQ".

**Follow-up (24 Sep):** the doc changes are in
[rustyharness#2](https://github.com/Iwan-Teague/rustyharness/pull/2) (branch `docs/benchmark-alignment`,
open, not merged). They are recorded there as owner decisions OD-1 to OD-7 in a new "Owner decisions after
v0.2" section of the design. G1–G4 are recorded as required (OD-5) but still need rustyharness's own design
and review.

## Verdict

**No conflict with any decision.** Most decisions sit on the benchmark's side and don't touch the
harness. The harness already provides benchmark mode through its embedding API, so it needs no
benchmark-specific code. What's missing: four generic features (G1–G4) and a goal that isn't written
down (G5). Two doc statements disagree with our decisions (M1–M2), and one item on our side is corrected
(M3).

## Aligned

| Decision | rustyharness today |
|---|---|
| D18: standalone; suite add-ons off by default | ADR-0002; README ("optional add-ons (H5), off unless enabled") |
| D16: one pinned harness for the benchmark | Overview U3: "one pinned, versioned harness" |
| D12: one device, local API | The client connects to loopback only and refuses plain HTTP anywhere else; remote hosts are a mesh add-on (RH §3.2; RH OQ answered 10) |
| D10, D11: a native sandbox per OS, no VMs | Seatbelt, namespaces + Landlock + seccomp, AppContainer (RH §6.3; RH OQ answered 12). CI green on all three OSes (H1f-1) |
| D4: submit, then grading; the loop keeps going until then | `task.submit` sentinel, budgets, loop detection, typed stop causes (RH §2) |
| D13, D14: timing done by the benchmark | `harness_run::run` takes `backend: &dyn ModelBackend`, so the benchmark's instrumented transport plugs in today |
| D17: grading and measuring outside the harness | The harness never scores; its checks are generic (H3); "no run can pass yet" |
| Benchmark mode (contract §2) | Already possible with no harness code. The embedding API takes policy, provider registry, profile and backend from the caller, and `harness-run` reads no ambient config (checked: no environment-variable or config-directory reads). "No approver present ⇒ every Ask becomes Deny" (RH §5.3). The journal header records the harness version, config, policy and manifest SHA-256s, and the profile hash (RH §7.1) |
| D15: environment captured automatically | The new environment sample in the journal header (H1f-3: CPUs, load, memory total and available, …) complements the benchmark's own capture, and helps flag runs slowed by swapping (D14) |

## Gaps: generic features the harness still needs

All of these are useful to any user, which is what D18 asks of a harness change.

| ID | Gap | Where it shows | Needed for |
|---|---|---|---|
| G1 | **No way to open a port.** `ConfinedSpec.network` is `None` or `Proxy(allowlist)`, and the egress proxy refuses loopback and private destinations | RH §6.2, §6.5 | Level 2; "open ports with permission" in the wild. Proposed: a loopback-ports grant (Linux: the namespace's own loopback; macOS: seatbelt port rules; Windows: AppContainer loopback), never the model server's port; ports visible on the network as a separate, higher-risk permission |
| G2 | **No background processes.** No spawn/stop tool; `exec.run` is synchronous with a timeout | RH §4.8 | An agent running its own server and hitting it with its own client (or accept the one-`cargo test` workaround) |
| G3 | **Embedders can't add sandbox paths or environment.** `ConfinedSpec` already has read-only roots, read-write roots and env, but `TaskSpec` and `Run` expose none of them, and env is harness-built | RH §6.2, §5.5; `harness-run` `TaskSpec` | The local crate set, the pre-built cache, a writable build directory, cargo config |
| G4 | **No cleanup.** Retention is listed as not covered ("default keep; explicit `rustyharness gc`") | RH §11 | The one-slot cycle (D9). Proposed: `gc` keeps journal and snapshots, deletes workspace, grading and scratch, and is callable from the embedding API |
| G5 | **The in-the-wild goal isn't written down.** The docs frame rustyharness as a reliable harness for suite uses U1–U5 and anyone with a model, but never say "a full coding agent like opencode or Cline" | Overview §1, §3 | D18. The roadmap covers most of it (egress proxy and MCP in H4, opt-in shell, edits in H2); G1 and G2 are the missing pieces |

## Statements that disagree with our decisions

- **M1: sharing the sandbox.** RH OQ answered item 5 and RH §6.3 propose `harness-sandbox` and the
  conformance corpus as crates rustybenchmark depends on. Our contract §9: grading belongs to
  rustybenchmark, and code is shared only through a standalone confinement crate outside both projects
  (still our open decision 15). Suggest rewording item 5 to "shared only through a standalone crate", or
  reopening it until decision 15 is made.
- **M2: overview U3** says the benchmark measures models "in the suite's own harness", but not how. One
  sentence would stop a future harness change from pulling grading in: the benchmark embeds the harness
  with its own locked-down policy, a provider registry holding only the built-in manifest, and its own instrumented backend, and
  grades and measures outside it. Related: the suite's R5 integration map drafts capabilities for an
  agent to *start* benchmark runs (`rustybenchmark.run.start`), the opposite direction. Harmless, but
  decide whether it's wanted.
- **M3 (our side, fixed):** the contract proposed an `addon-rustybenchmark` cargo feature (BM-1). The
  harness keeps `addon-*` features for in-process needs only (RH §8), and the API finding above makes the
  feature unnecessary. Dropped in contract v0.4.

## Risks for the FYP

- **R1: Windows.** Every Windows `state_root` is refused until spike S-W1 (RH OQ owner question 1.4).
  If the GPU PC runs Windows, agent-mode runs can't happen on it yet. That makes plan open decision 1
  (the GPU PC's OS) urgent.
- **R2: nothing executes yet.** "No sandbox, no execution" until H2. Agent-mode results need H2 plus
  G1–G3.
- **R3: no per-endpoint concurrency limit yet** (RH OQ owner question 1.6). The benchmark's one-slot
  cycle (D9) already runs one task at a time, so this doesn't bite.

## Proposed changes to rustyharness

The "Docs" rows are done in PR #2. The "Design change" rows are recorded there as required (OD-5), and still
go through rustyharness's own design review.

| Where | Change | Kind |
|---|---|---|
| Overview §1, §3 | State the in-the-wild goal (G5) | Docs |
| Overview §2, U3 | How the benchmark embeds the harness (M2) | Docs |
| RH OQ answered item 5; RH §6.3 | Share only through a standalone crate (M1) | Docs, owner decision |
| RH §6.2, §6.5 | Loopback-ports grant (G1) | Design change → review |
| RH §4.8 | Background-process tools (G2) | Design change → review |
| RH §6.2; `harness-run` `TaskSpec` / `Run` | Embedder-supplied paths and environment (G3) | Design change → review |
| RH §11 | Define `gc` (G4) | Design change → review |
