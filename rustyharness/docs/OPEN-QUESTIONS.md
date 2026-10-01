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
3. **The H1 phase-exit review** (§9): each H1 slice has its own recorded review
   (the H1a-H1e commits, and the H1f rows of the design); the phase as a whole has
   not been reviewed. Two items for it: INV-14's falsifying test ("hanging tool →
   `Budget(Wall)` within budget + kill grace") has no H1 counterpart, because
   in-process read tools are not interruptible (a named §11 residual that H2's
   killable helper closes), so the review decides whether H1 exits with it named;
   and `replay`'s "every record recomputed and matched" message, which should say
   that replies, tool results and samples are re-fed.
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

## Answered by the design

1. **Wire protocol for app capabilities** — MCP on the wire (rmcp, stdio), with a
   capability manifest v1 as the trust root; server self-description is ignored for
   policy (D7, §4, §4.6).
2. **Tool calling with small local models** — both native tool calls and a text
   protocol, chosen per model profile (D6, §3.3); grammar-constrained decoding waits
   on spike S-P1 and safety never depends on it.
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
