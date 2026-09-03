> **Author:** glm-5.3-flash via opencode (read-only agent), 28 Sep 2026 11:31. Draft — claims not yet verified by Claude/Iwan.



# Decision brief — D29–D33 (+ D4, D14, D16, D18, D24, D26)

**For:** Iwan · **From:** review synthesis, 24 Sep 2026
**Context:** 6 adversarial reviews returned 10 of 17 decisions (owner-answers-log.md:171). D29–D33 block the OD-5 v2 rewrite, which stops after §4.10 (od5-delta-v2.md ends line 469; §5, §6, §13 unwritten — owner-answers-log.md:106). Deadlines: proposal form to my supervisor Fri 2 Oct (owner-answers-log.md:75); Level-1 results mid-Nov, Level-2 pilot 23 Dec (REGISTER.md:12-13).

---

## Priority: D29 — Linux network isolation

**1. Question.** How do Linux runs get network isolation in H2?

**2. Current proposal.** One private network namespace per run, default (REGISTER.md:59; measurement-plan §0 line 56; od5-delta-v2.md:77 DD-7).

**3. Objection (T1, MODIFY, high).** The S-L1 spike measured your actual Linux box (Ubuntu 24.04.4, kernel 6.8.0-139): stock Ubuntu 24.04 blocks unprivileged user namespaces host-wide via AppArmor — `clone3(CLONE_NEWUSER)` fails EINVAL, bwrap non-functional (T1-confinement.md:7, 73). So D29 refuses on the canonical distro unless an admin installs an AppArmor profile (Codex ships exactly this profile; bundled in Ubuntu 25.04, manual copy on 24.04 — T1:73). Meanwhile the namespace-less trio from AQ-208 (Landlock ABI 4 files+TCP, seccomp denying `socket()`/`clone(CLONE_NEW*)`, systemd user scope, cgroup tree-kill) is accepted, reviewed SOUND, implemented, green at r1435, works unprivileged (T1:73). A netns supervisor duplicates work D27 exists to prevent (T1:75). Separately, T2 shows that without a netns a Landlock port grant = LAN-visible bind + internet egress on that port (T2-network-online.md:47-50) — see D31/D33 interaction. T1 and T2 disagree on ports without netns; SYNTHESIS backs T2 (SYNTHESIS.md:130-134).

**4. Options.**
- **(a) Keep D29 + one-time admin AppArmor userns profile.** Codex precedent; cost: zero-setup UX gone, every Linux machine needs admin action.
- **(b) T1's MODIFY:** default = the S-L1 trio (same backend as the benchmark grading sandbox); per-run netns becomes an **opt-in tier**, probed at runtime and recorded in the journal header's host facts; the AppArmor profile becomes the opt-in switch, not load-bearing (T1:75, 155).
- **(c) Netns-only, refuse on stock Ubuntu.** Cleanest model, but kills D22 two-OS testing on the default distro.

**5. Recommendation. (b).** It works unprivileged on stock Ubuntu today, converges harness and benchmark on one Linux backend (which D27, already confirmed, hinges on — T1:63), and keeps netns as a recorded capability rather than a requirement. T1 verdict: MODIFY, high on direction, medium on timing (T1:77).

**6. Unblocks.** OD-5 v2 DD-7 rewrite + §5.5 + §13 phases; Linux backend of the shared confinement library; H2.

---

## Priority: D33 — ports where Landlock network rules are missing

**1. Question.** What ports are allowed on kernels without Landlock network rules (ABI 4, kernel 6.7+)?

**2. Current proposal.** Allow any port inside the per-run private namespace (REGISTER.md:63; plan line 60; v2 O24-8, od5-delta-v2.md:62).

**3. Objection (T1, MODIFY, high).** Coherent **only** under D29-as-written. Without a netns, "any port" means binding the model server's port on the host (T1:87). The rule is anchored to the wrong thing — kernel version — instead of the capability actually present. Debian 12 (kernel 6.1) is the plausible second distro; whether it backports Landlock TCP is **unverified** (T1:87). Review F-11 agrees: inside a private netns, Landlock port rules buy parity with macOS, not safety, and cost availability (port-0 tests break; no-ABI-4 hosts lose ports entirely — REVIEW-od5-delta.md:282-292).

**4. Options.**
- **(a) Keep as written.** Only works if D29 stays netns-default; dies on Debian 12 and on any no-netns host.
- **(b) T1's fix:** per-run **capability matrix** {netns? Landlock ABI? systemd scope?} → ports: none / granted-only / any-in-private-netns; fail closed with a precise reason; record Landlock errata as a host fact (T1:89, 162).
- **(c) Namespace-only default with Landlock as opt-in parity setting** (REVIEW-od5-delta.md:292) — folds into (b) as its default row.

**5. Recommendation. (b).** Fail-closed, honest about what each host can do, and it's the only option that survives both D29 outcomes. Pairs with (c)'s default: inside a netns, namespace-only is enough.

**6. Unblocks.** OD-5 v2 §5.5 rewrite; scoping of D30 and D32.

---

## Priority: D30 — does a granted loopback port count as trifecta E?

**1. Question.** Does a granted loopback port count as egress for the trifecta rule (private ∧ untrusted ∧ egress refused)?

**2. Current proposal.** Yes, per DNS-rebinding reasoning (REGISTER.md:60; plan line 57); v2 applies it on **every** OS including private netns (O24-5, od5-delta-v2.md:59; DD-6 line 76).

**3. Objection (T2, MODIFY, medium).** On shared loopback (macOS, Linux without netns) the rule hard-refuses every private-repo dev-server session; the only escape is declaring the workspace public, which drops P for *everything* — users will game the rule (T2:201). The rebinding route needs 4 conditions (T2:202-207); stronger unlabelled routes exist: previewing in browser/IDE, the model server itself holding context with llama.cpp reflecting any Origin (T2:208-211). No surveyed harness counts a listening port as egress (T2:186-190); real incidents are about *unauthenticated* listeners: Vite CVE-2025-24010, webpack-dev-server CVE-2025-30360, Ollama CVE-2024-28224, MCP Origin MUST (T2:191-196).

**4. Options.**
- **(a) Keep hard refusal.** Consistent only if the browser/preview route is also counted — which is unusable.
- **(b) T2's fix:** keep the label as `host-exposure`, computed from the *measured* loopback kind (shared vs private). In P∧U sessions, one per-session human approval naming what is exposed; no approver = deny. Benchmark workspaces are declared public, so grading is unaffected. On Linux without netns, still refuse outright (ties to D31) (T2:214-222).
- **(c) Narrow exemption** only for ports with a Host-header check recorded as fact. Cheapest, but no invariant behind it.

**5. Recommendation. (b).** Preserves the rule's strength (Meta Rule-of-Two precedent, T2:108), fixes the gaming pressure, and keeps macOS Level-2 dev-server tasks possible. Review F-9 supports the threat model: the user's browser is a local client an attacker can drive (REVIEW-od5-delta.md:252).

**6. Unblocks.** OD-5 v2 §5.9 / INV-54; rustybenchmark `workspace_public` declarations (v2 line 432 already requires them); Level-2 dev-server tasks on macOS.

---

## Priority: D31 — no LAN-visible ports (CONFIRMED, one addition to approve)

**1. Question.** (Already confirmed by T2, KEEP, high — SYNTHESIS.md:76.) Remaining: approve T2's proposed addition.

**2. Addition.** Make it an invariant that **no confinement layer ever grants a bind on a shared network stack** — neither Seatbelt nor Landlock can scope a bind to 127.0.0.1 (T2:240, 245, 251). Add one FT row per backend refusing 0.0.0.0/[::]/LAN binds. Later, when a grant is genuinely needed: harness-side forwarder with interface selector + source allowlist + Ingress records (T2:252-258).

**3. Options.** (a) accept the addition as scoped; (b) accept invariant now, defer FT rows to the H2 matrix amendment (F-16 warns FT rows added after H2 reopen the matrix — REVIEW-od5-delta.md:329-335); (c) reject.

**4. Recommendation. (a).** One row per backend now is cheap and avoids F-16's reopen-the-matrix problem.

**5. Unblocks.** OD-5 v2 DD-17 (v2 line 87); makes D30's "refuse without netns" branch principled.

---

## Priority: D32 — macOS port binding for Level-2 network tasks

**1. Question.** How do macOS Level-2 network tasks bind ports?

**2. Current proposal.** Transparent `DYLD_INSERT_LIBRARIES` interposer swaps a harness-pre-bound 127.0.0.1 listener into `bind()`; fallback pf anchor blocking granted ports on non-loopback, admin once (REGISTER.md:62; plan line 59; v2 DD-8, od5-delta-v2.md:78).

**3. Objection (T2, MODIFY, medium) — measured on your Mac (macOS 26.5.1).** The interposer as drafted breaks in real conditions: DYLD vars are purged through `/bin/bash`, `/usr/bin/env`, sandbox-exec, and your `~/.cargo/bin/cargo` bash shim, so the server's bind fails (T2:26, 28); under Seatbelt, bind-only swap fails because the program's own `listen()` gets EPERM — needs swap + swallowed listen (T2:31); the dup2 swap loses `O_NONBLOCK` and `FD_CLOEXEC` (true/true → false/false) — tokio/mio hang risk, fd leak into children (T2:32); ~2.4 ms/process overhead (T2:33). The pf fallback is worse: `/dev/pf` is root-only, so an unprivileged harness cannot even verify the guard (T2:34); pf needs a root LaunchDaemon forever, any root process can `pfctl -d`, VPN coexistence **unverified** (T2:303-307). Full re-spec list (SIP trampoline, interposing bind+listen+getsockname+setsockopt+close, flag restore, IPv6/port-0 mapping, shim resolution, universal dylib, own audited unsafe crate): T2:311-317.

**4. Options.**
- **(a) Rebuild the interposer as measured** (T2's re-spec): ~1 week with tests; best UX; Seatbelt stays the boundary; fail-closed.
- **(b) Explicit `LISTEN_FDS` handover** (listenfd/systemfd-compatible, `LISTEN_PID` unset): soundest and cheapest, but the model must use it — an RQ1 confound (also review F-3's option ii, REVIEW-od5-delta.md:158); servers must be written for it (axum listenfd precedent; generated tasks fine if the prompt says so) (T2:320).
- **(c) Optional dedicated-agent-user + pf uid-rules mode**, spiked on a disposable Mac first (inbound user match on macOS 26 **unverified**; Mullvad precedent; also fixes the D21 setsid gap and OI-38 residuals; needs the P8 root helper, no sudoers) (T2:321-326).

**5. Recommendation.** T2's verdict: **(a) as primary re-specified + (b) replacing the pf fallback + spike (c)** (T2:334-337). Drop pf entirely as a v1 component — it cannot be verified unprivileged.

**6. Unblocks.** OD-5 v2 §5.4 rewrite; macOS Level-2 network tasks; D22 two-OS testing.

---

## D24 — tool packaging scales with model size

**1. Question.** Should smaller models see fewer merged tools?
**2. Proposal.** Per-model profile `max_active_tools` (default 6 under 30B), same capabilities, packaging recorded, one-model pilot ablation (REGISTER.md:55; plan line 46; v2 DD-11 line 81).
**3. Objection.** T3 REPLACE (benchmark) + MODIFY (product), high; T6 agrees independently (SYNTHESIS.md:144, 186). Size-scaling makes the toolset a variable that moves with the model — an unanalyzable confound by plan §4's own logic (contract B-5 row-key means 14B vs 70B never share a condition, T3:207-215). The 30B threshold splits the 24–32B MoE cohort (Qwen3-Coder-30B-A3B = 30.5B total / 3.3B active, T3:216-224). It can't be built as stated: Level-2 has 10 capabilities vs the 8-tool cap (T3:225-232). The one-model pilot is underpowered (~155 tasks for a 10-pt McNemar, T3:233-240). Tool-count harm evidence is at dozens of tools, not 6–11 (T3:241-251); mini-SWE-agent/Terminus fix the interface to compare models (T3:172-191).
**4. Options.** (a) keep D24; (b) **benchmark = one fixed packaging for every model** (compact 5-tool chosen by a pre-registered pilot on the smallest model; toolset digest in the row key; merged calls dispatch to capability ids so policy/journal unchanged) — product keeps per-model packaging chosen by measured validity, never size; if the question matters, answer it later with a factorial 2×3+ models, ≥150 paired tasks (T3:270-304; T6:142); (c) T6 variant: fixed headline arm + size-scaled secondary ablation arm, 2–3 models, with format-error/parse-rate columns (T6:142).
**5. Recommendation. (b)**, with (c) only if you want the ablation data and can afford the arm. Two independent reviewers converged; (a) is not defensible for the benchmark.
**6. Unblocks.** OD-5 v2 DD-11/§6.2/INV-59/FT-54; T3's two-tool process API (F-7, the §6 design — SYNTHESIS.md:177-182); H2+ toolset work.

---

## D4 — loop ends at task.submit; grading outside

**1. Question.** How does the agent run end?
**2. Proposal.** Loop until a submit tool call, re-prompt until then; grading outside the harness (REGISTER.md:47; plan line 26).
**3. Objection.** T3 MODIFY high + T6 MODIFY high, core KEEP by both (SYNTHESIS.md:154, 187). As built, a model that finishes in prose gets 3× generic FormatError (never naming `task.submit`), stops, and is booked `protocol_failure` — 15% of the proposed 20-step budget; small models do this often (Cline #6660, Qwen3-Coder-30B) (T3:83-97).
**4. Options.** (a) keep exactly as-is; (b) T3's B1–B6: separate NoAction counter (2) + message naming `harness.task.submit`; `StopCause::NoAction` → own class `no_submit`, not `protocol_failure`; submit summary says submitting is final; pinned `confirm_submit` setting (Terminus-2/SWE-agent style, pick once for the benchmark); `force_action` profile flag; end-of-turn only in product mode (T3:124-153); (c) b + T6's additions: publish exit-status breakdown next to every headline; one no-submit control arm on a pilot subset; miri timeout scored 0 with a named flag (closes AQ-218, the only gameable grader discretion) (T6:23-31).
**5. Recommendation. (c).** Core stays yours; the additions turn a silent confound into measurable failure classes.
**6. Unblocks.** H2 loop work; RQ1 failure classes; Level-1 pilot.

---

## D14 — headline: correct tasks per model-hour

**1. Question.** Is toolchain time excluded from the headline metric?
**2. Proposal.** Yes; remote host credited (plan line 36).
**3. Objection (T6, MODIFY medium-high).** Keep the exclusion, but pre-register the formula; co-report wall-clock per task (toolchain incl.), cost/tok/s, prefill share (+ decode-only variant when prefill >~40%); extend the OI-33 calibration band to benchmark runs and flag/redo thermally compromised runs. Prefill/decode stay separate because caching makes "an hour" engine-dependent (T6:47-52).
**4. Options.** (a) keep as-is; (b) accept T6's reporting package; (c) drop the exclusion (changes the headline — against your intent).
**5. Recommendation. (b).**
**6. Unblocks.** Plan §8 reporting design; sweep comparability.

---

## D16 — one pinned harness version = one results epoch

**1. Question.** Does one pinned version define one results epoch?
**2. Proposal.** Yes; new version = new epoch (REGISTER.md:50; plan line 38).
**3. Objection.** T6 KEEP high: epoch = hash tuple (harness version, profile digest, toolset hash, task-set hash, engine+build ID, calibration band), published manifest, docs-only = epoch-preserving (T6:72-74). T5 MODIFY high: pin an annotated tag + commit on main, never a development build; a release stays in epoch only if it **replays old golden journals clean**; freeze the benchmark-mode surface; write an ADR superseding rustybenchmark ADR-0010 — rustyharness becomes the reference agent with a labelled bring-your-own-agent lane designed now, built after FYP (T5:80-127, 179). Without an objective rule, strict epochs mid-study force multi-day re-runs (deep L1 ≈44.5 h/model/machine, ×2–5 in agent mode) and incentivise withholding security fixes (T5:98-103).
**4. Options.** (a) keep simple rule; (b) T6 hash-tuple epoch; (c) b + T5's replay gate and ADR.
**5. Recommendation. (c).** The replay gate is the objective rule that prevents both re-run blowups and hidden-fix pressure; the ADR is needed before the study starts regardless.
**6. Unblocks.** rustybenchmark ADR; study release discipline; plan §4.

---

## D18 — standalone full coding agent; benchmark mode = configuration

**1. Question.** Is rustyharness a standalone agent with benchmark mode as a locked-down config?
**2. Proposal.** Yes, "like opencode or Cline"; embedding API (REGISTER.md:52; plan line 40).
**3. Objection.** T6 KEEP high with tests (wire-byte equality, config-digest golden files, embedder-cannot-raise-limits property test — T6:118-120). T5 MODIFY medium-high: keep the aim, but split a frozen study line from a "wild" development line (ADR-026); replace "like opencode or Cline" with a written parity checklist marking built/planned/refused, including trifecta limits (the headline use case P∧U∧E is refused until H4); make "reads no ambient config" a gate rule (T5:266-307, 417-421). T5 also flags a conflict: the one-pager told my supervisor "fixed, minimal harness" while D16/D18 make a rich harness the only agent — **the proposal form must pick one** (SYNTHESIS.md:108-109). Benchmark-mode internals: structural precedence with a sealed embedder layer, `plan()` pre-flight, header annotations; time model calls via loopback proxy (Inspect AI style) instead of a second ModelBackend — spike first (T5:438-466).
**4. Options.** (a) keep as written; (b) accept T6 tests only; (c) b + T5's ADR-026 split and parity checklist.
**5. Recommendation. (c).** Cheapest honesty: same aim, written scope. Also forces the proposal-form wording decision before 2 Oct.
**6. Unblocks.** Proposal form; benchmark-mode contract §5; D16 epoch rule.

---

## D26 — trifecta rule; H4 safe path

**1. Question.** Does the trifecta (private ∧ untrusted ∧ egress refused) stay, and what is H4's safe path?
**2. Proposal.** Keep trifecta; H4 safe path = quarantined reader or dual-LLM alongside an egress proxy (REGISTER.md:56; plan line 53).
**3. Objection (T2, MODIFY medium-high).** Dual-LLM/CaMeL is unrealistic for 7–30B models (CaMeL is frontier-only, 2.8× tokens, −7pt utility; the only open-weight AgentDojo row is 34% utility undefended; **unverified** at 7–30B) (T2:142-147); no shipped harness runs it for coding (T2:139).
**4. Options.** (a) keep dual-LLM path; (b) T2's **E-elimination**: harness-mediated typed crate fetches (`cargo fetch --locked` outside the sandbox, registry-only lockfile, checksum-verified, cached, journaled — sandboxed code never gets a socket); offline rustdoc from fetched sources; open-web research in separate sessions; optional grammar-enforced extractor later; human-approved fetches as an explicit Rule-of-Two exception with restricted URL grammar; stop `workspace public` being the only way to get crates (T2:153-173); (c) defer H4 entirely.
**5. Recommendation. (b).** Keep the trifecta + INV-9 unchanged; only the safe path changes. Also relieves D30's gaming pressure.
**6. Unblocks.** H4 design; OD-1 online coding.

---

## Cross-cutting items feeding the OD-5 rewrite (no decision needed, for awareness)

- **F-2 (HIGH):** the v2 draft currently refuses **all** macOS `exec.run` in H2; fix is the corrected process sweep (F-1's 3-part test, 26 ms) as a named H2 deliverable with the confirmed D21 dated fallback (REVIEW-od5-delta.md:109, 135).
- **F-3 (HIGH):** inherit-only ports don't fit the Level-2 contract ("listen on the port given in --port"); interacts directly with D32 options (REVIEW-od5-delta.md:158).
- **F-25 (INFO):** your Ubuntu 24.04 GPU PC needs the one-time AppArmor profile regardless of D29 outcome (REVIEW-od5-delta.md:387-390). F-15's Linux supervisor mechanics: body not read; **unverified** beyond its title.
- Record `network.mechanism` in every journal header; one install-time privilege policy across both OSes (T2:328, 382).
- Housekeeping: the FYP folder is a single copy, no git, no backup (owner-answers-log.md:153) — proposed fix at owner-answers-log.md:160-165.

---

## Tick-box answers

**D29** — [ ] (a) netns + required AppArmor profile · [x→ ] (b) trio default, netns opt-in tier *(recommended)* · [ ] (c) netns-only
**D33** — [ ] (a) keep any-port rule · [x→ ] (b) capability matrix, fail-closed *(recommended)*
**D30** — [ ] (a) hard refusal · [x→ ] (b) host-exposure label + per-session approval *(recommended)* · [ ] (c) Host-check exemption
**D31 addition** — [x→ ] yes, invariant + FT rows now *(recommended)* · [ ] invariant only · [ ] no
**D32** — [x→ ] (a) re-specified interposer + (b) LISTEN_FDS fallback + spike (c) *(recommended)* · [ ] (a) only · [ ] (b) only
**D24** — [ ] (a) keep size-scaled · [x→ ] (b) one fixed benchmark packaging *(recommended)* · [ ] (c) + secondary ablation arm
**D4** — [ ] (a) keep as-is · [ ] (b) T3 B1–B6 · [x→ ] (c) b + T6 reporting/AQ-218 *(recommended)*
**D14** — [x→ ] (b) T6 reporting package *(recommended)* · [ ] (a) keep as-is
**D16** — [ ] (a) simple rule · [ ] (b) hash-tuple epoch · [x→ ] (c) + replay gate + ADR *(recommended)*
**D18** — [x→ ] (c) T6 tests + T5 ADR-026/parity checklist *(recommended)* · [ ] (a)/(b)
**D26** — [x→ ] (b) E-elimination safe path, trifecta unchanged *(recommended)* · [ ] (a) dual-LLM · [ ] (c) defer

Two extra items needing a word with **my supervisor before 2 Oct**: proposal wording (minimal vs rich harness — SYNTHESIS.md:108-109) and UL IP ownership (SYNTHESIS.md:157-160).
