# Review synthesis: what the adversarial reviewers concluded

**Status:** complete, 24 Sep 2026, 23:39. All six reviews are in. Kept by Claude. It is filled in as each themed report lands.

**Rule from Iwan (24 Sep):** "if the adversarial/scrutinisers agree, log the answers too."
- **KEEP:** Iwan's answer is confirmed, and it gets logged as final in the plan and, later, in rustyharness's docs.
- **MODIFY or REPLACE:** it goes back to Iwan before anything is logged.
- **Pending P-items:** a reviewer agreeing with Claude's recommendation does not make it Iwan's answer. Those are listed for a quick yes or no.

| Theme | Report | Reviewer | State |
|---|---|---|---|
| T1 confinement | `T1-confinement.md` | GLM-5.3-flash (Opus stopped at the usage limit) | **Done** |
| T2 network and online safety | `T2-network-online.md` | Opus | **Done** |
| T3 agent loop and tools | `T3-loop-and-tools.md` | Opus | **Done** |
| T4 builds, caches, state | `T4-builds-caches-state.md` | Opus | **Done** |
| T5 governance and architecture | `T5-governance-architecture.md` | Opus | **Done** |
| T6 benchmark method | `T6-benchmark-method.md` | GLM-5.3-flash (Opus stopped at the usage limit) | **Done** |

## Verdicts by theme

### T3: agent loop and tools

| Item | Verdict | What changes | Next step |
|---|---|---|---|
| D4: loop until `task.submit`; grading outside | **MODIFY** (high) | The core stands: explicit submit, grading outside. Add fixes: separate "no action" from "malformed action"; give no-submit its own stop cause and benchmark class; tell the model that submitting is final; decide on a pinned confirm-submit setting | Core confirmed. The fixes are additions; ask Iwan to accept them |
| D24: tool packaging scales with model size | **REPLACE** for benchmark mode (high); **MODIFY** for the product | Benchmark: one packaging for every model, pinned and digested into each result row, because a size-based rule mixes up model skill with packaging. If packaging matters, test it with a factorial pilot (2 packagings × 3+ models, ≥150 paired tasks each). Product: choose per-model packaging from measured validity, never from size | **Back to Iwan:** it overturns his answer |
| Protocol: typed tools vs bash as the universal tool | **KEEP** typed tools (high); **MODIFY** | Fill the verb gaps (delete and move in the edit tool); allow `curl` in the Level-2 preset | Design detail; no owner decision needed |
| OD-5(b): background-process API | **MODIFY** (high) | Two tools: `exec.run {background}` and `proc {read, stop, list}`. Hide `listen`, `grace_ms`, `since` and `max_bytes` from the model; default start wait about 5 s | Feeds the OD-5 v2 rework |
| P8: one run per model server | **KEEP** default of 1 (high); **MODIFY** | Build the limiter in H2 once MSRV rises; key it on the canonical server; cap raises by the server's reported slots; record it; the reviewer inherits the author's permit (as written it deadlocks) | Recommendation confirmed; Iwan yes/no |
| P12: reviewer independence | **MODIFY** (medium) | Keep fresh context. Require a distinct model only when one is designated and isn't weaker. Let a review block only with executable evidence, or route the block into one repair round | Changed recommendation; Iwan yes/no |

**T3's own summary:** changes 1–4 shrink the H2 and H2+ work rather than growing it: one packaging, fewer tools, a smaller API.

### T6: benchmark method (GLM-5.3-flash; citations not yet spot-checked)

| Item | Verdict | What changes | Next step |
|---|---|---|---|
| D4: submit sentinel; grading outside | **MODIFY** (high) | Keep submit and external grading. Publish an exit-status breakdown (submitted, budget, loop) next to every headline, as mini-SWE-agent does. Grade one pilot subset with no submit sentinel, to measure what the protocol costs small models. Score a miri timeout 0 with a named flag (closes AQ-218) | Core confirmed by T3 and T6. The additions go to Iwan |
| D14: headline = correct tasks per model-hour; toolchain time excluded | **MODIFY** (medium-high) | Keep the exclusion. Pre-register the formula. Also publish wall-clock per task (toolchain included), cost and tokens per second, and the prefill share of model time, with a decode-only variant when prefill dominates. Apply OI-33's baseline band to benchmark runs, and flag or redo thermally compromised runs | Back to Iwan (reporting additions) |
| D16: one pinned harness version = one results epoch | **KEEP** (high), with an addition | Define the epoch as a hash tuple: harness version, profile digest, toolset hash, task-set hash, engine and build ID, calibration band. Publish it as a manifest with the results, and declare docs-only changes epoch-preserving | T5 says MODIFY: **back to Iwan** |
| D17: grading and measuring only in rustybenchmark | **KEEP** (high) | — | T5 also KEEP: **logged as confirmed** |
| D18: standalone harness; benchmark mode is a configuration | **KEEP** (high) | — | T5 says MODIFY: **back to Iwan** |
| D24: packaging scales with model size | **MODIFY** (medium-high) | Flip the arms. Fixed packaging for every model becomes the headline; size-scaled packaging becomes a secondary ablation on 2–3 models across size bands, with columns for format-error rate and tool-call parse rate (Aider's "well formed %" precedent). Settle protocol per model vs text for all the same way, in one pre-registered document | **Agrees with T3:** back to Iwan |

**T6's other suggestions:**
- Run a bash-only reference harness (mini-SWE-agent style) on a subset once per epoch, to measure how much of the headline depends on the harness.
- Golden grader tests: the same final state must get the same grade whoever produced it.
- Byte-equality tests: requests must be identical with instrumentation on and off.
- A property test that the embedding API can't loosen limits (P15).

### T4: builds, caches, run state (Opus; 87 cited sources, 3 local measurements)

| Item | Verdict | What changes | Next step |
|---|---|---|---|
| P1: no app-supplied cargo folder or config | **KEEP** (high) | Record the real reasons: an open-ended key surface, and a shared cargo home is a cross-run channel. Add an invariant that §6.3's "temp" write grant means scratch only, so an agent can't plant an ancestor `.cargo/config.toml` (AQ-215) | Recommendation confirmed; Iwan yes/no |
| P2: refuse RUSTFLAGS, wrappers, sccache; build a harness-owned cache | **MODIFY** (medium-high) | Keep refusing ambient flags and wrappers, and add a closed `-C` grammar. Replace the harness-owned cache with trusted read-only **seeds**, cloned copy-on-write per attempt; a deps-only seed builder comes later | Changed recommendation; Iwan yes/no |
| P3: resume allowed if extra writable folders are "cache" (wiped) | **REPLACE** (high) | Wiping deletes outside the harness's own folders, races macOS survivors, and trusts a folder the agent may have replaced. Use a fresh seed clone per attempt instead, and the benchmark retries rather than resuming | Changed recommendation; Iwan yes/no |
| P4: harness checks may use only app-supplied read-only caches | **KEEP** (high) | It must mean a seed cloned per check, since cargo can't build in a read-only target folder (measured). Enforce "never written" across runs with read-only mounts, not Landlock alone | Recommendation confirmed; Iwan yes/no |
| P13: replay checks `state_root` locality | **MODIFY** | Yes for now. Then audit writes outside `state_root`, and make only verbs that write or delete check locality | Changed recommendation; Iwan yes/no |
| P14: keep run journals | **MODIFY** | Keep them, but add purge tiers with tombstones to gc now. Write the sharing and redaction policy before the first journal leaves the machine | Changed recommendation; Iwan yes/no |
| gc (OD-5(d)) | **MODIFY** (high) | "Finished" trusts `RunStopped` for process liveness, which is unsafe on macOS and on Linux without PID namespaces. gc must confirm the kill domain is empty at gc time, and skip attempts with no header. gc of finished runs can then ship without P7 | Feeds the OD-5 v2 rework |
| Benchmark reset cycle | **MODIFY** (high) | Retry instead of resuming. Agent-caused "infra" stops (`SandboxLost`, `JournalUnavailable`, `ModelUnavailable`) score 0 with a flag. Add a slot lock, and use the harness sweep instead of a process-group kill | Plan §3 change; Iwan yes/no |

**T4's measurements (macOS):**
- Cloned target folders at new paths stay Fresh, so cargo doesn't rebuild them.
- Editing cargo's stored warnings in a target folder changes what the next build prints, so a shared cache is an injection channel.
- An APFS clone of a 2.6 GB target folder takes 1.8 s.

### T2: network and online safety (Opus; primary sources plus 12 local probes on the MacBook)

| Item | Verdict | What changes | Next step |
|---|---|---|---|
| D12: one device, model on loopback | **KEEP** (high) | Proposed addition: a startup probe that warns when the model server accepts requests from any web page (llama.cpp reflects any Origin by default), with that residual named. A TLS remote-server class can wait until after the FYP | **Logged as confirmed** (plan §0, answers log) |
| D26: trifecta rule; H4 safe path (quarantined reader or dual-LLM) | **MODIFY** (medium-high) | Keep the rule. Make H4's safe path remove egress instead of filtering untrusted content: harness-mediated, typed, cached crate fetches; offline rustdoc built from those sources; separate research sessions; a structured extractor later. Don't build CaMeL or dual-LLM planning for 7–30B models. Stop "declare the workspace public" being the only way to get crates online | **Back to Iwan** |
| D30: a granted loopback port counts as egress | **MODIFY** (medium) | On a shared loopback, a port grant in a private session needs one approval per session, not a hard refusal. Otherwise users declare workspaces public, which drops protection for everything | **Back to Iwan** |
| D31: no LAN-visible ports in v1 | **KEEP** (high) | Proposed addition: no confinement layer ever grants a bind on a shared network stack, because neither Seatbelt nor Landlock can limit a bind to 127.0.0.1 | **Logged as confirmed** |
| D32: macOS socket swap by DYLD interposer; pf fallback | **MODIFY** (medium) | Fails as specified (measured below). The interposer needs: a trampoline to survive SIP; interposing `listen`; restoring descriptor flags; IPv6 and port 0; resolving shims; an audited unsafe crate. Drop the pf port-range fallback, which the harness can't even check without root. Ship an explicit `LISTEN_FDS` handover instead, and spike an optional dedicated-agent-user pf mode, which would also fix D21 and OI-38's residuals | **Back to Iwan** |
| P10: hosted models may not see personal data (v1) | **KEEP** (high) | After the FYP, add a `workspace.sensitivity` declaration, and block common secret files for hosted models | Recommendation confirmed; Iwan yes/no |

**T2's measurements that change D32 (macOS 26.5.1, this MacBook):**
- **The interposer gets stripped.** `~/.cargo/bin/cargo` and `rustc` are `#!/bin/bash` shims. `DYLD_INSERT_LIBRARIES` is purged through `/bin/bash`, `/usr/bin/env`, `/usr/bin/sandbox-exec` and the bash cargo shim, and the server's bind then fails.
  - Passing the variable as an argument after the protected hop works (`sandbox-exec … /usr/bin/env DYLD_INSERT_LIBRARIES=… prog`).
  - Through the real cargo binaries, the interposer loads in the target and the swap works.
- **Under Seatbelt with bind and inbound denied,** a bind-only swap fails, because the program's own `listen()` gets EPERM. Swapping and also swallowing `listen()` works.
- **The swap loses the socket flags.** After the `dup2` swap, nonblocking and close-on-exec are lost (true/true before, false/false after).
- **Cost:** about 2.4 ms per process.
- **pf:** an unprivileged harness can't see pf's state (`/dev/pf` is root-only). pf.conf does support a `user` match.

**T2's other top changes:**
- **Ports follow the measured loopback kind.** On Linux without a network namespace (stock Ubuntu 24.04), refuse port grants: Landlock rules name only a port, so a grant would mean binds visible on the LAN and internet egress on that port.
- **One install-time privilege policy for both OSes,** using small argv-only root helpers and no sudoers: an AppArmor user-namespace profile on Ubuntu 24.04 or later, and an agent user plus a pf anchor on macOS.
- **Record `network.mechanism` in every journal header,** so benchmark rows can be split by mechanism.

### T5: governance and architecture (Opus; 46 web and 18 local sources)

| Item | Verdict | What changes | Next step |
|---|---|---|---|
| D16: one pinned harness; a new version starts a new epoch | **MODIFY** (high) | Pin a tag and a commit on `main`. A new release stays in the same epoch only if it replays the old golden journals cleanly. Freeze the benchmark-mode surface. D16 contradicts rustybenchmark's ADR-0010 (accepted 18 Aug: a deliberately minimal reference agent, Terminus-style, and a board with several agents), so write an ADR that supersedes it: rustyharness as the reference agent, with a labelled bring-your-own-agent lane | **Back to Iwan** (T6 said KEEP) |
| D17: grading and measuring only in rustybenchmark | **KEEP**, reworded (high) | "The harness never scores or computes an app's metrics; it records generic facts with their method." Add a promise that the journal stays readable across versions | **Logged as confirmed** (T5 and T6) |
| D18: standalone full coding agent | **MODIFY** (medium-high) | Keep the aim. Split it into a frozen study line and a "wild" line on `development`. Replace "like opencode or Cline" with a parity checklist that says what the trifecta rule refuses | **Back to Iwan** (T6 said KEEP) |
| Benchmark mode as configuration | **MODIFY** (high; medium for the proxy) | Make it structural: a library that reads no ambient config, enforced by a gate; a written precedence with a sealed embedder layer; a `plan()` pre-flight report; annotations in the journal header. Time model calls through a loopback proxy in front of the harness's own client, as Inspect AI does for third-party agents, instead of a second client in rustybenchmark (spike first) | Changes contract §5 (transport); Iwan yes/no |
| Attested mode | **No** | It can't be made sound on the submitter's machine, and no live leaderboard uses one. Re-grade the deliverable on the server instead | Noted |
| ADR-0002: standalone first | **MODIFY** (high) | Move the suite add-ons and the `rustyvault` name, which is hard-coded in the core, into a suite-built binary. Split out the suite docs | rustyharness design change |
| P9: MIT/Apache for `gate-outcome` | **REPLACE** (high) | Keep PolyForm NC under ADR-021. Add a contribution policy or CLA to every repo now, because the first outside PR would otherwise block commercial licensing for good. Before any leaderboard, publish a narrow permission to reproduce and audit results | Changed recommendation; Iwan yes/no |
| P11: `restricted` capabilities never | **KEEP** (high) | Record the real reason (the append-only journal can't delete data), its scope ("never by declaration"), a bar for reopening it, and a user never-grant list | Recommendation confirmed; Iwan yes/no |

**New questions for Iwan from T5:**
- **Who owns the FYP code?** UL's IP policy v3.0 leaves purely educational undergraduate work with the student. UL owns IP from "UL Research", which is triggered by UL equipment, facilities or funding. Confirm with my supervisor in one line; the answer decides whether the licence is Iwan's to grant.
- **One-pager vs D16/D18.** The one-pager told my supervisor that a fixed, *minimal* harness avoids "measuring the tool as much as the model". D16 and D18 make a rich harness the only agent. The proposal form has to take one position.

### T1: confinement platform (GLM-5.3-flash; citations not yet spot-checked; charter facts verified by Claude)

| Item | Verdict | What changes | Next step |
|---|---|---|---|
| D10: no VMs or container runtimes | **KEEP** (high) | — | **Logged as confirmed** |
| D21: macOS `sandbox_check` sweep in H2; dated fallback | **KEEP** (high) | Harden it: a planted `setsid` escape in the live self-probe and negative-control tests as H2 exit gates; taint marking lands before the fallback is ever used. (T2 separately suggests spiking a dedicated agent user, which could replace the sweep) | **Logged as confirmed** |
| D22: every test on Linux and macOS | **KEEP** (high) | — | **Logged as confirmed** |
| D27: one shared confinement library | **KEEP** (medium-high) | Extract it Linux-backend-first with a version pin; write D27 into the design to close OD-4 / open question 4. It depends on D29 converging | **Logged as confirmed** |
| D29: one private network namespace per run | **MODIFY** (high on direction) | Default Linux backend = the accepted S-L1 trio (Landlock ABI 4, seccomp, systemd user scope, cgroup tree-kill), the same as the benchmark's grading sandbox. Stock Ubuntu then needs no admin step. The per-run namespace becomes an opt-in tier, probed at runtime and recorded | **Back to Iwan** |
| D33: kernels < 6.7 allow any port in the private namespace | **MODIFY** (high) | Replace it with a per-run capability matrix (namespace? Landlock ABI? systemd scope?) giving ports none / granted-only / any-in-private-namespace, failing closed with a precise reason | **Back to Iwan** |
| P5: build the `sandbox_init` FFI now | **KEEP** (high) | Order inside one audited macOS crate: the sweep first, then `sandbox_init` after S-M2; `sandbox-exec` stays as a CI canary; an init failure means Unavailable, never an unsandboxed fallback | Recommendation confirmed; Iwan yes/no |
| P6: Windows S-W1 spike in H2 | **MODIFY** (medium) | A three-way spike: AppContainer vs restricted token + ACLs vs dedicated user + WFP (Codex and sandbox-runtime precedents). Rename the benchmark's S-W1 item so the two gates stop sharing a name | Changed recommendation; Iwan yes/no |
| P7: raise MSRV to 1.89 for file locks | **KEEP** (high) | — | Recommendation confirmed; Iwan yes/no |
| P15: Windows ports off; embedders only lower limits | **KEEP** (high) | Add a "config cannot raise limits" test case, and a policy digest in the journal header | Recommendation confirmed; Iwan yes/no |

T1 also evaluated the brief's two ideas:
- **seccomp user notification:** a Linux version of the socket swap (the kernel supports it from 5.9/5.14). "Record, don't build."
- **An AppArmor profile at install that allows user namespaces:** precedented, and should become the switch for the namespace tier.

**T1 and T2 disagree.** Both agree that without a network namespace the sandbox can't keep a bind on loopback.
- **T1:** allow ports that Landlock grants on the no-namespace default.
- **T2:** refuse port grants there, because Landlock rules name only a port. A granted port could then be bound on every interface (breaking confirmed D31), and connect to that port number on any host.

T2's position is the one consistent with D31.

## Decision list for Iwan (all six reviews in, 24 Sep 23:39)

### Logged as confirmed (a reviewer kept Iwan's answer)

D10, D12, D17, D21, D22, D27, D31. These are recorded in plan §0 and the answers log. Reviewers' small proposed additions are noted there but not yet accepted.

### Iwan's answers the reviewers changed: his call

1. **D24, tool packaging** (T3 and T6 agree). For benchmark runs, one fixed packaging for every model. Scaling by model size stays a product setting, tested as a separate multi-model ablation.
2. **D29 and D33, Linux isolation** (T1, T2, spike S-L1). Stock Ubuntu 24.04 blocks the namespaces D29 needs. The default becomes the no-namespace sandbox the benchmark already uses, with the namespace as an opt-in tier and a per-run capability matrix. **Sub-question:** how do Level-2 network tasks get ports on stock Ubuntu?
   - (a) A one-time admin step at install: an AppArmor profile that enables the namespace tier.
   - (b) Build a seccomp-notify socket swap: no admin step, more work.
   - (c) Refuse port tasks there, which clashes with D22.
3. **D32, macOS network tasks** (T2, measured). The interposer as specified fails on this Mac. Either rebuild it (trampoline, `listen`, flags, IPv6 and port 0, shim resolution), or use an explicit `LISTEN_FDS` handover plus a spike of a dedicated agent user under pf. Drop the pf port-range fallback.
4. **D26, safe path for private repos plus online** (T2). Remove internet access rather than filter it: harness-fetched crates, offline docs, separate research sessions. No dual-LLM planner for 7–30B models.
5. **D30, loopback ports and the trifecta rule** (T2). One approval per session instead of a hard refusal.
6. **D16, the pinned harness** (T5; T6 kept it). Pin a tag and commit. A release stays in the epoch only if it replays the golden journals cleanly. Write an ADR that supersedes rustybenchmark's ADR-0010.
7. **D18, standalone harness** (T5; T6 kept it). Split a frozen study line from a "wild" line, and make "reads no user config" a gate rule.
8. **D4, submit and grade outside** (T3 and T6 keep the core). Add no-submit handling: its own stop cause, a message naming `task.submit`, an exit-status breakdown and a no-submit control subset. A miri timeout scores 0 (AQ-218).
9. **D14, headline metric** (T6). Keep toolchain time out. Pre-register the formula, and also report wall-clock time, cost and prefill share.

### FYP-level questions raised by the reviews

- **Proposal wording.** The one-pager's "fixed, minimal harness" vs D16/D18's rich harness: the proposal form must pick one (T5).
- **IP.** Confirm with my supervisor that UL doesn't own the FYP code (UL IP policy v3.0; T5).

### Claude's pending recommendations: Iwan yes or no

- **Reviewer kept the recommendation:** P1, P4, P5, P7, P8, P10, P11, P15.
- **Reviewer changed it:**
  - P2: seeds, not a harness cache.
  - P3: REPLACE; a fresh seed clone per attempt, and the benchmark retries rather than resuming.
  - P6: a three-way Windows spike.
  - P9: REPLACE; stay PolyForm NC and add a CLA.
  - P12: a distinct reviewer model only when one is designated and isn't weaker.
  - P13: replay checks locality now; later only writing verbs check it.
  - P14: keep journals, plus purge tiers and a sharing policy.
  - T5's transport proposal: time model calls through a loopback proxy instead of a second client.

### Design changes with no owner decision (they feed the OD-5 v2 rework)

- The two-tool background-process API (T3).
- gc confirms the kill domain is empty (T4).
- The reset cycle retries instead of resuming (T4).
- Typed tools plus the missing verbs, and `curl` in the Level-2 preset (T3).
- Benchmark mode made structural (T5).
- Move the suite add-ons out of the harness core (T5).

## Where reviewers agree

- **D24:** T3 (Opus) and T6 (GLM) independently say the benchmark headline must use one fixed tool packaging for every model. Size-based packaging stays a product feature and a measured ablation. This overturns Iwan's answer for benchmark runs, so it goes back to him.
- **D4:** both keep the explicit submit and external grading, and both add handling for a model that never submits (T3: its own stop cause and message; T6: an exit-status breakdown and a no-submit control).

## Research notes (saved in `research/`)

`harness-tools-claude-code-codex-opencode-gemini.md` covers tool sets, background processes and turn endings in four harnesses. Points that bear on the decisions:
- **D24 / T3.** Products do vary tools per model. Codex picks its tool mode per model from `/models` metadata. opencode swaps edit/write for `apply_patch` on GPT models. Claude Code gates tools by model. That supports T3's split: vary packaging in the product, pin it in the benchmark.
- **OD-5(b) / T3.** Background processes:
  - Codex uses `exec_command` with a PTY session ID plus `write_stdin`, a 10 s default yield and at most 64 processes.
  - Claude Code uses `run_in_background`, reads output from a file, and has TaskStop and Monitor.
  - Gemini CLI has `is_background` and reports background PIDs.
  - opencode has no background support (open issue #50316).
  
  That fits T3's two-tool API.
- **D21 / T1.** Claude Code's docs say background tasks are cleaned up at exit, and "on macOS and Linux this also covers processes detached with `setsid` or `timeout`". The mechanism wasn't examined; worth checking against D21's sweep. Its open issues #81462 and #96625 show orphans still happen.
- **D4 / T3.** Turn endings:
  - Claude Code ends a turn when the model replies with no tool call. A Stop hook can force it to continue, capped at 8 blocks in a row.
  - opencode stops on a finish reason other than tool-calls.
  
  None of them needs an explicit submit, which is a benchmark-specific choice (T6 weighs this).

`macos-interposition-pf-network-extension.md` covers SIP and DYLD, shims, interposition, socket activation, pf, Network Extension filters and Seatbelt network rules. It bears mainly on D32 and D21:
- **DYLD stripping.** dyld's own source (`pruneEnvVars`) strips `DYLD_*` for everything below a SIP-protected process: `/bin/sh`, bash, zsh, `/usr/bin/env`, `sandbox-exec`. That agrees with T2's measurement.
  - Handing the variable over as an argument (`env DYLD_…=… prog`) is the known workaround.
  - An arm64-only dylib inserted into an arm64e process is fatal, and if the inserted library fails to load, the launch fails.
- **Framework calls may bypass an interposer (inference).** The shared-cache builder keeps stubs only for functions that tools interpose (`accept`, `recv*`, `send*`); `bind`, `listen` and `socket` weren't found in that list. So bind calls made inside Apple frameworks (Network.framework) may slip past an interposer.
- **`~/.cargo/bin/cargo` on this Mac.** It's a bash shim (`#!/bin/bash` + `exec -a cargo …/rustup`, 87 bytes, created 24 Sep 05:13), not Homebrew's default symlink. Whatever created it today changes how the environment reaches cargo. Worth knowing before any macOS benchmark run.
- **Socket activation (`LISTEN_FDS`) needs code changes in the server.** axum's auto-reload example uses `listenfd` with a fallback to `bind`. So T2's explicit handover works only for servers written to accept it; that's fine for generated tasks if the prompt says so.
- **pf.** Every rule change needs root (`/dev/pf` is 0600). Any root process can switch pf off for everyone. Rules have been silently ignored after macOS updates (14.6–15.1). "Admin once at install" would need a LaunchDaemon plus liveness monitoring. That supports T2's advice to drop the pf port-range fallback.
- **Seatbelt.** Codex and Anthropic's sandbox-runtime both still call `/usr/bin/sandbox-exec`, and both use `*:*` for local-bind rules.
  - sandbox-runtime PR #530 implies a `localhost:N` bind rule is narrower than `*:N`. That conflicts with our own measurement that Seatbelt port rules can't keep a bind on loopback. The PR shows no test, so our measurement stands; a re-test would settle it.
  - sandbox_init(3) now says the named `kSBXProfile*` profiles kill the process when built against the macOS 27 SDK; custom profile strings aren't mentioned (P5 context).
