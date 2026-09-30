# Decision memo: rustyharness owner questions

Prepared 2026-09-24 for Iwan Teague (owner). Recommendations only: nothing here is decided until you
tick the block at the end.

**Sources.** rustyharness docs at `a4b9208` (design v0.2 with OD-1 to OD-7, OPEN-QUESTIONS, overview,
README); the FYP measurement plan v0.10 and harness contract v0.4. **Citations.** §n is the design
(`docs/01-design-v0.1.md`); "plan §n" and "contract §n" are the FYP documents; D1–D19 are plan §0;
OD-n are the design's "Owner decisions after v0.2"; "Still open n" is OPEN-QUESTIONS.

## Why now

- §9's H0 exit needs §11's questions "answered or defaults accepted in writing", and none is recorded
  (Still open 1). Phases are strictly ordered (§9): this record, then H1's phase-exit review (Still
  open 3; not an owner question, not covered here), then H2, the FYP's critical path (plan §4.2).
- The FYP needs first agent-mode results by 23 Dec 2026. Plan §11 falls back to Level 1 single-shot
  results if H2 and OD-5 (a)–(c) are not ready by mid-November.
- Seven of the eleven questions do not touch the FYP; answering them takes minutes and closes H0.
  Three do: Still open 5 (OD-5), Still open 4 (shared confinement) and 1.4 (Windows, if the GPU PC
  runs Windows). 1.8 is a contingency.

## At a glance

| # | Question | Recommendation | FYP timeline |
|---|---|---|---|
| 1.1 | `gate-outcome` licence | Recorded exception: MIT OR Apache-2.0 | No |
| 1.2 | Hosted model sees `personal` data | Accept the default: no | No |
| 1.3 | `restricted` capabilities | Never: make the default permanent | No |
| 1.4 | Windows in v1 | Accept the default; do the Windows work first in H2 | Yes, if the GPU PC runs Windows |
| 1.5 | Reviewer independence | Accept the default | No |
| 1.6 | Concurrency per endpoint | Accept the default: 1 | No |
| 1.7 | Trifecta-breaking architecture | Keep "never combine"; revisit in H4's design, not after H4 | No |
| 1.8 | macOS without `sandbox-exec` | Accept the default | Contingency only |
| 2 | Replay checks locality | Yes | No |
| 4 | Shared confinement code | One standalone crate, staged like `gate-outcome` | Yes |
| 5 | OD-5 placement and order | (c), (d) in H2; (a), (b) in a new phase before H3 | Yes, most |

## 1.1 `gate-outcome` licence

- **Question.** Does ADR-0003 (PolyForm Noncommercial) cover `gate-outcome`, or is it a recorded exception?
- **Default.** PolyForm Noncommercial 1.0.0, like this repository (§11 Q1).
- **Affects.** §1.4 (one outcome type, "one crate, one source, two consumers"; own repository before
  H3 exits), §9 H3, INV-28, ADR-0003. The suite links no PolyForm Noncommercial crate into anything it
  publishes (§11 Q1), so under the default its published consumers cannot use the shared type: the
  drift §1.4 exists to stop.
- **Options.** (A) Recorded exception: `gate-outcome` alone under MIT OR Apache-2.0; rustyharness stays
  PolyForm. (B) Accept the default.
- **Recommend A.** The crate's only value is being shared, and it has no product value alone (§11 Q1),
  so ADR-0003's reason protects little here while the default undercuts §1.4. A permissive licence
  relaxes nothing in rustyharness itself. B costs nothing until the move if you would rather wait.
- **FYP.** No. rustybenchmark is PolyForm Noncommercial too (ADR-0003) and reads the harness's report
  only as a secondary signal (contract §4.1). The answer is due before H3 exits.

## 1.2 Hosted models and `personal` data

- **Question.** May a hosted model ever see `personal`-sensitivity data?
- **Default.** No: hosted profiles only for sessions whose maximum sensitivity is ≤ `operational`;
  `restricted` never, whatever the answer (§5.4, §11 Q2).
- **Affects.** §5.4 (hosted as a disclosure rule, with a per-sensitivity config opt-in), §3.2 (the
  `hosted` feature, per-run opt-in, no fallback across privacy classes), §5.2, INV-24; overview U5.
- **Options.** (A) Accept the default for v1; the §5.4 opt-in stays designed but unbuilt until an app
  needs it. (B) Yes, by explicit per-sensitivity opt-in in user config, per run. (C) No, permanently.
- **Recommend A.** Nothing needs it: no §9 phase builds `hosted`, and the default build refuses
  non-loopback endpoints (INV-24). "No" fails closed, and B can come later without a redesign.
- **FYP.** No. Every FYP run is loopback on one device (D12), with generated tasks and no personal data.

## 1.3 `restricted` capabilities

- **Question.** May the harness ever hold `restricted` (life-data) capabilities?
- **Default.** Refused at session start (INV-27; §5.2 "deny").
- **Affects.** §4.1 (`sensitivity`), §5.2, §5.4, §11 non-goals, INV-26, INV-27; ADR-0002 item 3.
- **Options.** (A) Never: the refusal is permanent, and reopening it needs a superseding ADR.
  (B) Accept the default for v1 and revisit later.
- **Recommend A.** ADR-0002 item 3 already points this way and INV-27 already enforces it; a permanent
  answer stops the question returning at every phase.
- **FYP.** No.

## 1.4 Windows in v1

- **Question.** Does v1 ship Windows execution if S-W1 passes, or is it declared v2 now?
- **Default.** Windows is read-only unless S-W1 passes; from H3 a Windows session with checks is never
  `Passed`, and the CLI says so at start (§11 Q4). Today it is stricter: every Windows `state_root` is
  refused because the volume query needs S-W1's FFI crate, so no Windows run starts (design rows
  H1e-2c, H1f-1). Owner intent: Windows execution is wanted, and the S-W1 gate stands (OD-7).
- **Affects.** §6.3 (AppContainer + Job Object; S-W1 with the restricted-token fallback; S-W2
  loopback), §2.8 (Windows locality), §6.7 (`harness-sandbox-windows`, the one `unsafe` crate), §9 H2
  exit ("Windows either green or `Unavailable`"), INV-35, OD-5 (a).
- **Options.** (A) Accept the default, keep the S-W1 gate, and put the Windows work first in H2: land
  the §2.8 volume query early (read-only Windows runs then work), then run S-W1 alongside the Linux and
  macOS backends. (B) Accept the default with no scheduling change. (C) Declare Windows execution v2
  (contradicts OD-7 and D11).
- **Recommend A.** Fail-closed stays intact, and only A serves OD-7 without making Linux and macOS wait
  on Windows. The volume query is three Win32 calls (§2.8) that execution needs anyway. S-W1 is the
  likeliest to run long (Codex judged AppContainer insufficient for developer workflows, §6.3): start
  it first.
- **FYP.** Yes, if the GPU PC runs Windows (plan open decision 1): Level 1 agent mode there needs the
  volume query, S-W1 and a green §6.6 suite by mid-November, and Level 2 also needs S-W2 for loopback
  ports. If it runs Linux, 1.4 leaves the FYP path. Settle the GPU PC's OS first.

## 1.5 Reviewer independence bar

- **Question.** How independent must the built-in reviewer be?
- **Default.** Fresh context and a distinct run always; a distinct model (profile, endpoint, claimed
  model id, weights digest) when two or more are configured (§7.5, §11 Q5).
- **Affects.** §7.5 (identity checked before every attempt; the fallback chain), INV-19, D15, §9 H3.
- **Options.** (A) Accept the default. (B) Always a distinct model: a single-model user's reviewer
  slot is then always refused, so their reviewed tasks never pass unless review is off (§7.5).
- **Recommend A.** Local machines are memory-bound (the reason OD-6 rules out VMs and external container
  runtimes; plan §3.3: 24 GB decides which models fit), so many users serve one model at a time and B
  would make `Passed` unreachable for them. A still forces a distinct model whenever one is configured.
- **FYP.** No. The reviewer is H3, and off in the benchmark profile (plan §4.3, contract §1).

## 1.6 Concurrency per model endpoint

- **Question.** How many runs may share one model endpoint at once?
- **Default.** 1 for loopback, user-configurable (§2.8, §11 Q6); not enforced: the semaphore is not built.
- **Affects.** §2.8 (launches queue, never storm the server), §2.4 (a queued model call spends wall
  budget), §3.2 (timeouts become `Unavailable`).
- **Options.** (A) Accept the default; enforcement stays a tracked gap (a cross-process guard needs
  `File::try_lock`, Rust 1.89, design row H1c). (B) Use the server's own parallel slots (needs spike
  S-P1's props check). (C) No harness limit.
- **Recommend A.** Parallel slots on a local server share its context and compute. 1 is the safe
  default, and a user who knows their server can raise it.
- **FYP.** No. The benchmark runs one task at a time per machine (D9), with the reviewer off.

## 1.7 When to build a trifecta-breaking architecture

- **Question.** When to invest in plan-then-execute or dual-LLM designs that could admit some
  P ∧ U ∧ E sessions?
- **Default.** Never combine, no override (INV-9); revisit after H4 (§5.4, §11 Q7).
- **Affects.** §5.4 (a workspace is P and U by default), INV-9, §6.5 (egress proxy, H4), §11 "What
  would make this design wrong", OD-1.
- **Why it matters.** OD-1's goal, editing code while fetching crates and docs online, is P ∧ U ∧ E for
  a default workspace, so it is refused unless the workspace is declared `public` or the research runs
  in a separate session (§5.4). That collision arrives with H4's proxy, so "after H4" is too late.
- **Options.** (A) Keep "never combine" and no override; revisit in H4's design delta, before the proxy
  is built, with OD-1's online coding session as the test case. (B) Accept the default as written.
  (C) Commit now to a plan-then-execute path in H4 or H5.
- **Recommend A.** The invariant stays; only the timing of the analysis moves, so H4 does not ship a
  proxy that no default coding session can use.
- **FYP.** No. Benchmark mode's registry holds only the built-in manifest, and no built-in has egress
  (§4.8), so E stays false, provided OD-5 (a) labels loopback ports egress `none` (§4.1: egress means
  data leaves the host). Generated workspaces can also be declared `public`.

## 1.8 macOS if `sandbox-exec` disappears

- **Question.** What does macOS execution do if Apple removes `/usr/bin/sandbox-exec`?
- **Default.** `probe()` fails and macOS execution refuses until an exit path lands (§6.3 S-M1, §11 Q8).
- **Affects.** §6.3 (Seatbelt backend), §6.1 (`Conformed`), §6.7 (a second `unsafe` crate would follow
  the Windows rules).
- **Options.** (A) Accept the default; choose the replacement if it happens, judged by the §6.6 suite
  (§6.3: "a spike that fails swaps the primitive, never the bar"). (B) Pre-commit to `sandbox_init` FFI
  in an audited `unsafe` crate. (C) Pre-commit to App Sandbox with code signing.
- **Recommend A.** Waiting loses nothing: the conformance bar decides any replacement, and B or C now
  adds `unsafe` code or a signing dependency for a hypothetical.
- **FYP.** Contingency only: the Mac is a test machine and the benchmark's grading sandbox uses
  `sandbox-exec` too (plan §3.3). Hold the Mac's macOS version fixed for the study (plan §9).

## 2 Should audit replay check `state_root` locality?

- **Question.** Should `rustyharness replay` refuse a non-local `state_root`, as `run` and `resume` do?
- **Default.** None recorded. Today it does not check: `harness_run::Audit` takes no locality probe
  (`Run` and `Resume` do) and writes `runs/<run-id>/replay-<k>/` unchecked, so on Windows it writes
  where `run` refuses (design row H1f-1). The fail-closed choice is to check.
- **Affects.** §2.8, §2.9, INV-35 ("`state_root` is used only on a filesystem positively identified as
  local"), §7.7 (a refusal is exit 5, `CouldNotRun`).
- **Options.** (A) Check: `Audit` takes the caller's probe like `Run`, so `replay` refuses a non-local
  `state_root`, and on Windows until S-W1. (B) Do not check: replay output is disposable; INV-35 records
  the exception. (C) Replay writes nothing under `state_root` (a change to row H1e-2b).
- **Recommend A.** One rule for every verb that writes under `state_root` keeps INV-35 true as written.
  The probe exists (row H1e-2c), and losing Windows replay costs nothing today: no Windows run can
  produce a journal before S-W1. It fits the H1 phase-exit fixes (Still open 3).
- **FYP.** No. Replays run on the machines that made the runs, and an embedder passes its own probe,
  as it does for `run`.

## 4 Sharing confinement code with rustybenchmark

- **Question.** Share confinement code through a standalone crate outside both projects, or keep two
  implementations?
- **Default.** None recorded (reopened 2026-09-24); doing nothing means two implementations. Fixed
  either way: the grading sandbox stays rustybenchmark's, and the harness never depends on it (OD-4).
- **Affects.** §6.3 (backends; its "shared with rustybenchmark" note), §6.6 (FT-1..FT-8 already
  generalise the benchmark's escape set "so both sandboxes can share one corpus"), §6.7, §1.4 (the
  `gate-outcome` precedent); contract §9; plan open decision 15.
- **Options.** (A) One standalone crate (per-OS backends, `ConfinedSpec`, the conformance corpus) with
  no harness or benchmark imports: a workspace member here during H2, like `gate-outcome` (§1.4), moved
  to its own repository before the benchmark's grading sandbox uses it. (B) Two implementations: no
  coupling, and the benchmark may use tools the harness refuses (bubblewrap is external C, §6.3), but
  everything is built twice, on three OSes.
- **Recommend A.** Windows AppContainer is the risky part of both sandboxes (contract §9); A does it
  once. The grader needs the same primitives as OD-5 (a)–(c) for Level 2 (it runs the agent's server
  on the slot's ports, plan §6.3), and it gains the §6.6 bar. The cost is one extraction, SemVer and
  CI on three OSes; both consumers are PolyForm, so 1.1's licence question does not recur.
- **FYP.** Yes. The GPU PC needs both sandboxes on its OS for the interim results (plan §3.3, §10):
  A builds that OS's backend once, B twice.

## 5 Designing the OD-5 capabilities: phase and order

- **Question.** Where do OD-5's four required capabilities go in §9's phases, and in what order?
- **Default.** None: OD-5 leaves placement open and notes that rustybenchmark needs (a)–(c) "with, or
  soon after, H2". Until built, none exists. Each needs a design delta, an R6 threat-model update where
  it touches the network, and the two-eyes review.
- **Affects.** §6.2 (`ConfinedSpec`), §6.5 (network is `None` or `Proxy`; the proxy refuses loopback),
  §4.8 (`exec.run` is synchronous), §2.8 (run layout), §6.4 (trust base), §5.5 and INV-10 (built
  environment), §5.4 (labels), §9 (H2 is "network = none only"), §11 (`gc`).

| | Network (R6)? | FYP need | Design points to settle |
|---|---|---|---|
| (c) embedder inputs | No | Level 1: plan §3.2's slot (read-only toolchain, crate set and build template; per-task cargo home; build output outside the source snapshot) | Roots never overlap `state_root`, config or other runs (§6.4); env and cargo config are trust base, read-only to the agent (cargo config can name programs to run); INV-10 still holds; the §6.6 suite gains cases for the new roots |
| (d) `gc` | No | The reset cycle (D9) without the benchmark deleting inside `state_root` | Refuse a run with no durable `RunStopped` (resume needs its workspace); keep journal, blobs and snapshots; confirm that snapshots or blobs hold file contents, which resume (§2.10) and re-grading (contract §4.3) need |
| (a) loopback ports | Yes | Level 2 network families (servers, web APIs, dashboards) | Linux: the sandbox netns's own loopback. macOS and Windows share host loopback: bind and connect only on granted ports, never the model server's; Windows after S-W2. Label egress `none` (see 1.7). Network-visible ports stay a separate grant |
| (b) background processes | No; pairs with (a) | Only if agents run their own server and client (plan open decision 3) | Start, read, stop; killed at any stop (submit included) and at run end (FT-16); what kills them if the harness dies (macOS has no PID namespace or Job Object); resume never restarts one |

- **Options.** (A) (c) and (d) as H2 slices; (a) and (b) in a new phase between H2 and H3 (working name
  H2+); network-visible ports with H4's proxy. (B) All four in H2, so H2's exit waits for the network
  work. (C) (c) and (d) in H2; (a) and (b) with H4, after H3.
- **Recommend A, in the order (c) → (d) → (a) → (b), then network-visible ports, with (a)'s design
  delta and R6 update written and reviewed during H2.** (c) is the only one Level 1 needs, has no
  network, and exposes `ConfinedSpec` fields H2 builds anyway. (d) is small but needs H2's workspace
  materialisation; it can slip to H2+ if H2 runs late. (a) is the first network change after "network =
  none", so it earns its own review; drafting it during H2 lets H2+ start the day H2 exits. (b) may not
  be needed by the FYP. B puts Level 1 behind network work; C puts Level 2 behind H3, which the
  benchmark does not need (contract §4.1).
- **FYP.** Yes, the most of any question. (c) in H2 decides whether H2 alone gives Level 1 agent mode
  by mid-November; H2+'s timing decides the Level 2 pilot due by 23 Dec (plan §11). If ports slip,
  port-free pilot domains (CLI tools, data, languages; D19 is still open) keep the pilot alive.

## How to answer

Tick one box per item (`[x]`); the first option in each list is this memo's recommendation. Write in
any answer that is not listed, fill in the date, and paste the block into `docs/OPEN-QUESTIONS.md` as
a new section after "Still open", then mark Still open items 1, 2, 4 and 5 as answered there.

## Ready-to-paste block

```markdown
## Owner answers (2026-09-__)

**(owner)** Answers to Still open items 1 (the design's §11 owner questions), 2, 4 and 5. For item 1
this is the written record §9's H0 exit asks for. One box is ticked per question.

- **1.1 `gate-outcome` licence** (§11 Q1, §1.4, ADR-0003)
  - [ ] A recorded exception to ADR-0003: `gate-outcome` alone is licensed MIT OR Apache-2.0;
        rustyharness stays PolyForm Noncommercial 1.0.0.
  - [ ] Default accepted: ADR-0003 covers it (PolyForm Noncommercial 1.0.0).
- **1.2 Hosted models and `personal` data** (§11 Q2, §5.4)
  - [ ] Default accepted for v1: no. The §5.4 per-sensitivity opt-in stays unbuilt until an app
        needs it.
  - [ ] Yes, by explicit per-sensitivity opt-in in user config, per run.
  - [ ] No, permanently: the opt-in is removed from §5.4.
- **1.3 `restricted` capabilities** (§11 Q3, INV-27)
  - [ ] Never: the refusal is permanent (ADR-0002 item 3); reopening it needs a superseding ADR.
  - [ ] Default accepted for v1: refused at session start.
- **1.4 Windows in v1** (§11 Q4, §6.3; design OD-7)
  - [ ] Default accepted and the S-W1 gate kept. The Windows work goes first in H2: the §2.8 volume
        query lands early (read-only Windows runs), then S-W1 runs alongside the Linux and macOS
        backends.
  - [ ] Default accepted, with no scheduling change.
  - [ ] Windows execution is v2.
- **1.5 Reviewer independence** (§11 Q5, §7.5)
  - [ ] Default accepted: fresh context and a distinct run always; a distinct model when two or more
        are configured.
  - [ ] A distinct model always.
- **1.6 Concurrency per model endpoint** (§11 Q6, §2.8)
  - [ ] Default accepted: 1 for loopback, user-configurable. Enforcement stays a tracked gap.
  - [ ] The server's own parallel slots (after spike S-P1).
  - [ ] No harness limit.
- **1.7 Trifecta-breaking architecture** (§11 Q7, §5.4)
  - [ ] Never combine, no override. Revisited in H4's design delta, before the egress proxy is built,
        with design OD-1's online coding session as the test case.
  - [ ] Default accepted: never combine; revisit after H4.
  - [ ] A plan-then-execute path is built in H4 or H5.
- **1.8 macOS without `sandbox-exec`** (§11 Q8, §6.3)
  - [ ] Default accepted: macOS execution refuses until a replacement passes §6.6; the replacement is
        chosen if it happens.
  - [ ] Pre-commit to `sandbox_init` FFI in an audited `unsafe` crate (§6.7).
  - [ ] Pre-commit to App Sandbox with code signing.
- **2 Audit replay and `state_root` locality** (INV-35; design row H1f-1)
  - [ ] Replay checks locality with the same probe as `run` and `resume`, so it refuses on Windows
        until S-W1.
  - [ ] Replay does not check; INV-35 records the exception.
  - [ ] Replay writes nothing under `state_root`.
- **4 Sharing confinement code with rustybenchmark** (design OD-4, §6.3)
  - [ ] One standalone crate (per-OS backends, `ConfinedSpec`, the conformance corpus) with no harness
        or benchmark imports: a workspace member here during H2, moved to its own repository before
        rustybenchmark's grading sandbox uses it.
  - [ ] Two independent implementations.
- **5 The OD-5 capabilities** (design OD-5)
  - Phase:
    - [ ] (c) embedder inputs and (d) `gc` in H2; (a) loopback ports and (b) background processes in
          a new phase between H2 and H3; network-visible ports with H4's proxy.
    - [ ] All four in H2.
    - [ ] (c) and (d) in H2; (a) and (b) with H4, after H3.
  - Order:
    - [ ] (c) → (d) → (a) → (b) → network-visible ports; (a)'s design delta and R6 update are written
          and reviewed during H2.
    - [ ] The same order, with each design delta written only when its phase starts.
- [ ] **H0 exit (§9):** every §11 question above is answered or its default accepted.
      Iwan Teague, 2026-09-__
```
