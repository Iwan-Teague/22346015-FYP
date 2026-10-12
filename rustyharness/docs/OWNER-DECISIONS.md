# Owner decisions: options, trade-offs, recommendation

**Approved by the owner, 2026-10-02:** #1 (airlock now, dual-LLM as a later research track, never a prompt per fetch) and #2 (no TLS in the default build; an opt-in `net` feature with an out-of-process fetcher after review). Rows are marked APPROVED below.

Written 2026-10-02 while the swarm built the roadmap (`ROADMAP-parity.md`). Every item holds a **fail-closed default** until answered, so nothing is blocked on you; answering just lets the work go further. "Rec" is the recommendation for the long term, weighing strength, security and performance, and not shying from extra work.

Legend: security (S), performance/UX (P), work (W).

## A. Security model (the ones that matter most)

| # | Decision | Options | Pros / cons | Rec |
|---|---|---|---|---|
| 1 | **APPROVED 2026-10-02.** **Web access vs workspace** (Q-1; trifecta) | **A.** Airlock: research sessions have no workspace; results are quarantined notes, imported by an explicit human action. **B.** Plan-then-execute / dual-LLM: an untrusted reader model never sees tools, a privileged planner never sees web text. **C.** Allow both with a prompt per fetch. | A: simple, provable, ships soon (S+++, P+, W low). B: the strongest known defence, FYP-worthy, but a big design and slower (S++++, P-, W high). C: weakest, approval fatigue (S-). | **A now (P-39), B as a research track after M2.** Never C. |
| 2 | **APPROVED 2026-10-02.** **TLS and hosted models** (Q-2) | **A.** No TLS in tree; hosted model/web only through the user's own loopback proxy. **B.** Opt-in cargo feature `net` with a reviewed TLS stack, fetcher in its own confined process. **C.** TLS always in. | A: smallest attack surface, matches today (S+++, W none) but web fetch needs a user-run proxy (P-). B: first-class web and hosted models; adds crypto deps (rustls needs ring/aws-lc, which have C/asm) to audit (S++, W med). C: bigger default surface (S-). | **A for the default build; B as a feature-gated, out-of-process fetcher** once P-39's design is reviewed. |
| 3 | **May a hosted model see `personal` data?** (Q-2b/Q-3) | No / Yes with disclosure / Yes only per-item approved | No: safest, matches rustylife's label gate (S+++). Yes: convenient, leaks private data. | **No.** Labels from rustylife make the session `personal`, hosted models are refused. Revisit only with a per-item declassify prompt. |
| 4 | **Session-scoped "always allow" and `--accept-edits`** (Q-4) | **A.** Yes/no per call only. **B.** Allow journaled pattern grants (matcher-bound, never lower a protected floor, flag-gated). **C.** Free-form "always". | A: strictest, painful for real work (P-). B: Claude Code/opencode parity, still evidence-backed (S++, P++). C: unsafe. | **B**, with `--allow-session-grants` required and `--accept-edits` only once undo (P-22/P-26) exists. |
| 5 | **Shell** (Q-11) | No shell / `--shell` flag (an `sh` on the allowlist; sandbox is the control) / default on | Flag keeps the allowlist model and sandbox as the control; default-on loses the point. | **Flag, per run, recorded in the header.** |
| 6 | **Project instruction files** (Q-7/Q-8) | Never / load after digest approval, Untrusted / auto-load | Digest approval gives parity with AGENTS.md while a hostile repo can't self-trust. | **Digest-approved, Untrusted, never affects policy.** Workspace-resident config only tightens, never loosens. |
| 7 | **Background processes and ports** (Q-12/Q-16, OD-5) | None / design approval then build / interim "stop the run if a process survives" | Needed for dev servers and for rustybenchmark's ports; the highest-risk sandbox work. The interim rule (stop run) hurts the REPL. | **Approve the design note and build the confined file-op helper** (it also closes the file-tool race). Loopback ports only; LAN is a separate ask-every-time grant. W high, worth it. |
| 8 | **MCP** (Q-13) | Own thin stdio client / rmcp (tokio) | Own client: small audited surface, no async runtime (S++), more maintenance and spec drift. rmcp: faster to build, heavy deps (S-). | **Own client**, wire-tested against reference servers; quarantine on description change; MCP tools count against the tool cap. |
| 9 | **Subagents** (Q-14) | None / sequential, depth 1 / parallel | Sequential keeps endpoint concurrency 1 and a clean journal; parallel needs multiple endpoints. | **Sequential, depth 1, read-only first.** |
| 10 | **Compaction** (Q-9) | Deterministic ledger only / optional model-written summary | Ledger is replay-recomputable and injection-proof; summaries help very long sessions but persist injected text. | **Ledger default; later an opt-in `--compaction summary`, summary stored as Untrusted and re-fed in replay.** |

## B. Platforms and sandbox

| # | Decision | Options | Pros / cons | Rec |
|---|---|---|---|---|
| 11 | **Linux backend** (Q-17) | Exec refuses on Linux (today) / Landlock + seccomp + conformance suite / namespaces | Today: macOS-only agent. Landlock+seccomp works unprivileged and fits "no VMs, no containers" (OD-6); needs the full conformance suite (W high, S+++). | **Build it** (after M2); needed for CI, servers, and rustybenchmark. |
| 12 | **Windows** (Q-15/OD-7) | Read/edit only until spike S-W1 / commit to AppContainer + Job Object | Rustybenchmark wants a Windows app. The spike is cheap and tells us if it is possible. | **Schedule the S-W1 spike after M2; stay read/edit until it passes.** |
| 13 | **macOS process-count bar FT-5** (item 6) | Accept the in-sandbox watchdog (named weaker bar) / refuse exec until a dedicated agent uid exists | Watchdog works today and is disclosed; a dedicated uid needs privileged setup. | **Accept the watchdog now, add the dedicated-uid option later.** |
| 14 | **If macOS drops `sandbox-exec`** | Refuse exec / port to another mechanism | Refuse is the safe default. | **Refuse; track Apple's replacement.** |
| 15 | **Sharing confinement with rustybenchmark** (OD-4) | Two implementations / one standalone crate (like `gate-outcome`) | One audited implementation, bugs fixed once vs coordination and version coupling. | **Standalone crate outside both projects, adopted by the benchmark when stable;** until then keep both. |
| 16 | **Workspace modes** (new) | In place / scratch copy / git worktree | In place: simple. Copy: safest, reviewable diff. Worktree: light for real repos. | **Offer all three;** default in place for the REPL, copy for unattended runs. |

## C. Product behaviour and UX

| # | Decision | Options | Pros / cons | Rec |
|---|---|---|---|---|
| 17 | **Several read-only calls per reply** (Q-5) | One action / allow N reads | Fewer round trips (P+), small models handle it badly, ordering must stay deterministic. | **Per-profile opt-in `parallel_reads`, default off.** |
| 18 | **Tool cap** (Q-6) | 5-8 / 10-12 | More tools mean more context cost on small windows (Odysseus found the same problem). | **Per-profile cap (8 for interactive); modes shrink the set;** measure with P-21. |
| 19 | **Interactive final report before H3** (Q-10) | `NothingChecked` exit 5 / invent a verdict | A user-run `/check` is not a verdict. | **Keep `NothingChecked`.** |
| 20 | **Plain text ends a turn; no `required` tool choice in sessions** (P-05 O-1/O-2) | As designed / `<final>` tag / forced tools | Risk: small models answer when they should act. | **Accept; P-21 measures it;** add a per-profile `tool_choice_required` for models that obey it. |
| 21 | **Reopen ended sessions** (O-4) | Only after EOF/exit/timeout / never | Convenience at no safety cost (released outcome stays `NothingChecked`). | **Accept as designed.** |
| 22 | **User text is trusted intent** (O-9), **re-chain-only metrics** (O-10) | Accept | Documented residuals; the printed chain head is the defence. | **Accept.** |
| 23 | **Slice notes in `docs/slices/`** (Q-18) | Yes / append to the design doc | Avoids conflicts; folded per wave. | **Yes.** |

## D. Project and publication

| # | Decision | Options | Rec |
|---|---|---|---|
| 24 | **`gate-outcome` licence** (open Q 1.1) | PolyForm Noncommercial (default) / permissive | **Permissive for `gate-outcome` only** if you want others to embed outcome types; otherwise keep default. Your call. |
| 25 | **Restricted capabilities, reviewer independence, endpoint concurrency** (open Q 1.3/1.5/1.6) | Defaults: refuse restricted, fresh context + distinct run, concurrency 1 | **Accept all three defaults.** |
| 26 | **rustylife memory contract** (P-47) | You define search / get-node / scope read API | **You own this;** the harness side is designed around it. |
| 27 | **Headless browser** | Defer / build | **Defer** until the airlock is proven. |
| 28 | **Pushing / publishing** (your standing rule) | Local only / private GitHub repo / public scrubbed copy | **Local only until you say.** When ready: private repo for `rustyharness` first; public copy only after a scrub review. |
| 29 | **AI-use declaration** | The supervisor approved AI use on the harness; benchmark needs a requirements spec first; log each use | Keep the swarm's logs (`devkit/swarm/logs`) and commit history as the evidence for §15.3 of the guidelines. |

## E. Web airlock details (new, from `docs/slices/P-39-web-airlock.md` §13)

The airlock design is written (11 slices, P-39a..k). It adds 13 smaller decisions OD-W1..W13, each with a fail-closed default; only two affect whether the fetcher can be built at all:

| # | Decision | Rec |
|---|---|---|
| OD-W1 | Fetcher crypto provider: `ring` (C + asm, most audited) / `aws-lc-rs` (C, larger) / `rustls-rustcrypto` (pure Rust, young) | **`ring`**, confined to the out-of-process fetcher workspace `fetch/`, never in the default build. Until answered the fetcher is written and reviewed but not built in CI. |
| OD-W2 | `fetch/deny.toml` may allow the ISC and CDLA-Permissive-2.0 licences (ring, webpki-roots); the root list stays unchanged | **Yes, in `fetch/deny.toml` only.** |
| OD-W3..W13 | root store (compiled `webpki-roots`), search-returned hosts, LAN search endpoint, web tools in a `public` coding workspace, robots override, non-interactive import, plain http, any-vs-chosen resolved address, typed grant meets the egress floor, fallback loopback socket, Linux/Windows | **All defaults stand** (strictest choice each; see the note). |
