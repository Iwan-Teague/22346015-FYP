# Open questions

Owner decisions are marked **(owner)**. The design
([01-design-v0.1.md](01-design-v0.1.md), v0.2, reviewed SOUND) answers most of the
questions the project started with; each is kept here with where it was answered,
so the history stays readable. What is still open is listed first.

## Still open

1. **(owner) The design's owner questions** (§11), each with the fail-closed default
   that holds until answered. §9's H0 exit asks for these to be answered or their
   defaults accepted in writing; no written acceptance is recorded in this
   repository yet.
   1. `gate-outcome`'s licence: does ADR-0003 cover it, or is it a recorded
      exception? *Default:* PolyForm Noncommercial.
   2. May a hosted model ever see `personal` data? *Default:* no.
   3. May the harness ever hold `restricted` capabilities? *Default:* refused (INV-27).
   4. Windows in v1? *Default:* read-only unless spike S-W1 passes; today every
      Windows `state_root` is refused until S-W1 (design row H1f-1). *Owner intent
      (2026-09-24):* Windows execution is wanted, because rustybenchmark will ship a
      Windows app; the S-W1 gate stands (design OD-7).
   5. Reviewer independence bar? *Default:* fresh context and distinct run always; a
      distinct model when two or more are configured.
   6. Concurrency per model endpoint? *Default:* 1 for loopback (not enforced in
      H1: §2.8's per-endpoint semaphore is not built, so nothing stops two runs
      sharing a server).
   7. When to invest in a trifecta-breaking architecture? *Default:* never combine;
      revisit after H4.
   8. macOS if `sandbox-exec` disappears? *Default:* macOS execution refuses.
2. **(owner) Should audit replay check `state_root` locality?** `rustyharness replay`
   writes `runs/<run-id>/replay-<k>/` under `state_root` without the locality check
   `run` applies (INV-35), so on Windows it writes where `run` refuses. Checking would
   make replay refuse on Windows until S-W1 too (design row H1f-1).
3. **The H1 phase exit** (§9): the phase-exit review found H1 NEEDS-FIXES and
   decided its two items: H1 exits with INV-14's hanging-tool test named (it is an
   H2 key test), and `replay`'s message now says that replies, tool results and
   samples are re-fed. Slice H1g made its code and doc fixes (design rows H1g and
   H1g-2), and the findings the review let H1 carry into H2 are named, with where
   each closes, in design row H1g-3.
   The H1 exit test was re-run on a local model server, both protocols, and
   passed (review F-10; design row H1g-4). Still to do before H2: item 1 above
   (F-11).
4. **(owner) Sharing confinement code with rustybenchmark** (reopened 2026-09-24;
   was answered item 5). The owner's position: the benchmark's grading sandbox stays
   its own, and the harness never depends on the benchmark. Open: share confinement
   code through a standalone crate outside both projects (as `gate-outcome` is for
   outcomes), or keep two implementations? (Design OD-4.)
5. **Design the capabilities the owner required on 2026-09-24** (design OD-5): ports
   with permission, background processes, embedder-supplied confinement inputs, and
   `gc`. Each needs a design delta, an R6 threat-model update where it touches the
   network, the two-eyes review, and a phase. rustybenchmark needs the first three
   with, or soon after, H2.
6. **(owner) The macOS process-count bar (FT-5)** (H2c, recorded in H2d). macOS has no
   per-sandbox process limit without privilege (`RLIMIT_NPROC` is per user), so the
   Seatbelt backend meets FT-5 with the in-sandbox member-count watchdog, a named
   weaker bar; `require()` passes and commands run with it **provisionally**. Accept it,
   or refuse execution on macOS until a dedicated agent uid exists (the H2c report,
   §8; dropping `Case::Ft5` from the row is the one-line switch). FT-6 (memory,
   `RLIMIT_AS`) is met at the strong bar either way.
7. **(owner) The file tools' race in sessions that execute** (H2d). The design puts
   the built-in file tools behind a confined file-op helper when a session holds an
   execute grant (§4.8); H2d ships the named interim instead (option (b): the run stops
   unless the sandbox confirms every process a command started is gone). Building the
   helper (option (a)) is the design-conformant follow-up; when is yours to decide.
8. **(owner) The active-tool cap** (H2e). §3.4 caps a session at 5-8 active tools
   (R1 §1.7: fewer tools help small models; profiles refuse `max_active_tools`
   outside 5-8, and the dev profiles set 6, the submit sentinel included). The
   built-in set is ten tools since H2e (four read, three edit, the runner, the
   checklist, the sentinel), so a task picks: a coding task with search, glob,
   edits, the runner and the checklist needs 8. *Default:* the 5-8 range stands
   and tasks choose their grants; raising it (Claude Code offers about 15 tools,
   opencode about 12) is a profile-range change for the owner to decide, ideally
   after measuring a small model with 8 against 10 (design rows H2e).
9. **(owner) Several read-only tool calls in one reply** (H2e). §2.2 runs one action
   per reply, and a reply with several calls is a format error that costs a step and
   a repair. Z.ai ignores `parallel_tool_calls: false` (H1h, finding F2), and in the
   H2e dev runs at `6720a60` GLM-5.3-flash's native replies held two calls in 6 of 13
   runs; Qwen3-4B (text) sent two replacements in one reply on e2. Claude Code and
   opencode run a turn's calls in order. *Default:* one action per reply stands. The
   narrow change would run up to N calls whose labels are read-only, each
   policy-checked and journaled as its own record in reply order, and keep the
   one-action rule for anything that writes or executes. It changes §2.2 and the
   loop's step accounting, so it is the owner's call.
10. **(owner) Pre-submit checks: the defaults and what they stand for** (H3a, design
    rows H3a). Four choices were made to build the slice and are the owner's to
    confirm: (a) **a check round costs no step**, and is bounded by the wall budget and
    `max_rounds` (1 to 5, default 2); (b) **the first failing command ends the round**,
    so the model sees one failure per submission; (c) **each check goes through the
    policy as a `harness.exec.run` call**, so an interactive run's approver is asked once
    per check per submission unless the policy allows the runner, and an unattended task
    needs the allow rule or the run does not start; a declined or unanswered check is
    recorded `not_run` and the submission is accepted; (d) **a task's checks are
    evidence for the model, not for the harness**: the outcome stays
    `Indeterminate { NothingChecked }` and a check can be passed by editing the tests it
    runs. Whether H3's verification should reuse a task's checks as its plan, and
    whether a submission accepted with a failing check should ever be a `Failed`
    outcome, belongs with H3 (§7.3, §7.6).

## Answered by the design

1. **Wire protocol for app capabilities** — MCP on the wire (rmcp, stdio), with a
   capability manifest v1 as the trust root; server self-description is ignored for
   policy (D7, §4, §4.6).
2. **Tool calling with small local models** — both native tool calls and a text
   protocol, chosen per model profile (D6, §3.3); grammar-constrained decoding waits
   on spike S-P1 and safety never depends on it. The native protocol sends past
   actions back as tool-call and tool messages, never as text (design row H1h).
3. **Edit format** — exact search/replace (unique match) or whole-file write, applied
   in process with a stale-read check and post-apply verification; never `git apply`
   (D9, §4.9; H2).
4. **Reuse vs write** — the model client is the harness's own (a small HTTP/1.1
   client over `std::net`, no TLS in the default build; §3.2, design row H1d); MCP
   uses rmcp (§4.5, H4).
5. ~~**Shared crates with rustybenchmark**~~ — reopened 2026-09-24: see Still open
   item 4. (The v0.2 answer proposed the sandbox backends and the conformance corpus
   as the shared crates, §6.3.)
6. **Hosted models** — off in the default build (feature `hosted`), opt-in per run
   (§3.2); a hosted profile only for sessions whose maximum sensitivity is at most
   `operational`, `restricted` never (§5.4); a loopback profile never falls back to
   a hosted one (§3.2). The remaining owner question is item 1.2 above.
7. ~~**Membership (owner)**~~ — decided 2026-09-23: present-non-member dev/ops tool
   until the design is SOUND (ADR-0002).
8. ~~**Licence (owner)**~~ — decided 2026-09-23: PolyForm Noncommercial 1.0.0,
   source-available (ADR-0003).
9. **Where the admin assistant ends** — irreversible or shared-scope operations are
   never automatic; the default policy table says what is (§5.2).
10. **Remote model hosts over rustynet** — a suite add-on (a mesh model transport),
    not core (§8).
11. ~~**rustyharness vs the charter's "rustyai" (owner)**~~ — decided 2026-09-23:
    separate, standalone-first (ADR-0002).
12. **Confinement mode (owner, suite OI-24)** — the harness's half is answered:
    per-OS backends gated by a conformance token, namespaces + Landlock + seccomp
    on Linux, deny-default Seatbelt on macOS, AppContainer + Job Object on Windows
    (D12, §6). A separate OS account per agent is the suite's confinement decision
    (§8), still the suite owner's (OI-24). *Owner (2026-09-24):* no VMs and no external
    container runtimes (Docker, Podman), because a VM reserves memory the local model
    needs. The native backends above stay, container-like or not (design OD-6).
13. **Local-only vs cloud models** — local first: loopback by default, hosted only by
    feature and per-run opt-in (§3.2, §5.4).
14. **Reuse rustyfin's assistant tool contract** — its confirmation-token pattern is
    lifted clean-room, with no code dependency (§5.3).
15. **How suite add-ons are packaged** — runtime-loaded providers (manifest + MCP
    server), plus a few `addon-*` cargo features for what must be in process (§8).
16. **The shared gate-outcome type** — one standalone crate both consume, moving to
    its own repository before H3 exits (§1.4); its licence is item 1.1 above.
17. **Scaffold review design notes** — F4 (`Message` trust marking, done in H1d),
    F5 (`Containment::Available` needs a `Conformed` token, H2, §6.1), F10 (split CLI
    exit codes and the child-report protocol, done in H1e-2b, §7.7), F11 (journal
    untrusted payloads and type-level append-only, done in H1c), F13 (duplicate JSON
    keys refused, done in H1b).
