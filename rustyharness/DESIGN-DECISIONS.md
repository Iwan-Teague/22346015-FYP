# Harness design decisions, 2 Oct 2026

Having worked through every option and deep-dived them with a GLM-5.3 agent — it
gathered the research, laid out the trade-offs and argued the other side — these are the
choices I settled on for rustyharness. Written up 12 Oct 2026 from my working notes made
while the roadmap (`ROADMAP-parity.md`) was being built.

Every item holds a **fail-closed default** until I decide it, so nothing is blocked;
deciding just lets the work go further. "Rec" is the recommendation for the long term,
weighing strength, security and performance, and not shying from extra work.
Legend: security (S), performance/UX (P), work (W).

## A. Security model

| # | Decision | Options | My call |
|---|---|---|---|
| 1 | **Web access vs workspace** (trifecta) | **A.** Airlock: research sessions have no workspace; results are quarantined notes, imported by an explicit human action. **B.** Plan-then-execute / dual-LLM: an untrusted reader model never sees tools, a privileged planner never sees web text. **C.** Allow both with a prompt per fetch. | I chose **A now, B as a later research track. Never C.** A is simple, provable and ships soon (S+++, P+, W low); B is the strongest known defence and FYP-worthy, but a big design and slower (S++++, P-, W high); C is the weakest — approval fatigue (S-) |
| 2 | **TLS and hosted models** | **A.** No TLS in tree; hosted model/web only through the user's own loopback proxy. **B.** Opt-in cargo feature `net` with a reviewed TLS stack, fetcher in its own confined process. **C.** TLS always in. | **A for the default build; B as a feature-gated, out-of-process fetcher** once the web-airlock design is reviewed. A keeps the smallest attack surface (S+++, W none) but web fetch needs a user-run proxy (P-); B gives first-class web and hosted models at the cost of crypto deps to audit (S++, W med); C grows the default surface (S-) |
| 3 | **May a hosted model see `personal` data?** | No / Yes with disclosure / Yes only per-item approved | **No.** Labels make the session `personal`, hosted models are refused. I'll revisit only with a per-item declassify prompt. No is safest and matches the label gate (S+++); yes leaks private data |
| 4 | **Session-scoped "always allow" and `--accept-edits`** | **A.** Yes/no per call only. **B.** Allow journaled pattern grants (matcher-bound, never lower a protected floor, flag-gated). **C.** Free-form "always". | **B**, with `--allow-session-grants` required and `--accept-edits` only once undo exists. A is strictest but painful for real work (P-); B gives parity with existing tools while staying evidence-backed (S++/P++); C is unsafe |
| 5 | **Shell** | No shell / `--shell` flag (an `sh` on the allowlist; sandbox is the control) / default on | **Flag, per run, recorded in the header.** The flag keeps the allowlist model and the sandbox as the control; default-on loses the point |
| 6 | **Project instruction files** | Never / load after digest approval, Untrusted / auto-load | **Digest-approved, Untrusted, never affects policy.** Workspace-resident config only tightens, never loosens — a hostile repo can't self-trust |
| 7 | **Background processes and ports** | None / design approval then build / interim "stop the run if a process survives" | **Approve the design and build the confined file-op helper** (it also closes the file-tool race). Loopback ports only; LAN is a separate ask-every-time grant. Needed for dev servers and the benchmark's ports — the highest-risk sandbox work, worth the effort |
| 8 | **MCP** | Own thin stdio client / rmcp (tokio) | **Own client**, wire-tested against reference servers; quarantine on description change; MCP tools count against the tool cap. Own client: small audited surface, no async runtime (S++), but more maintenance; rmcp: faster to build, heavy deps (S-) |
| 9 | **Subagents** | None / sequential, depth 1 / parallel | **Sequential, depth 1, read-only first.** Sequential keeps endpoint concurrency 1 and a clean journal; parallel needs multiple endpoints |
| 10 | **Compaction** | Deterministic ledger only / optional model-written summary | **Ledger default; later an opt-in summary mode**, summary stored as Untrusted and re-fed in replay. The ledger is replay-recomputable and injection-proof; summaries help very long sessions but persist injected text |

## B. Platforms and sandbox

| # | Decision | Options | My call |
|---|---|---|---|
| 11 | **Linux backend** | Exec refuses on Linux / Landlock + seccomp + conformance suite / namespaces | **Build Landlock + seccomp** (after M2); needed for CI, servers, and the benchmark. It works unprivileged and fits "no VMs, no containers"; needs the full conformance suite (W high, S+++) |
| 12 | **Windows** | Read/edit only until a spike / commit to AppContainer + Job Object | **Schedule the spike after M2; stay read/edit until it passes.** The spike is cheap and tells us if it is possible |
| 13 | **macOS process-count bar** | Accept the in-sandbox watchdog (named weaker bar) / refuse exec until a dedicated agent uid exists | **Accept the watchdog now, add the dedicated-uid option later.** The watchdog works today and is disclosed; a dedicated uid needs privileged setup |
| 14 | **If macOS drops `sandbox-exec`** | Refuse exec / port to another mechanism | **Refuse; track Apple's replacement.** Refuse is the safe default |
| 15 | **Sharing confinement with the benchmark** | Two implementations / one standalone crate | **Standalone crate outside both projects, adopted by the benchmark when stable;** until then keep both. One audited implementation, bugs fixed once |
| 16 | **Workspace modes** | In place / scratch copy / git worktree | **Offer all three;** default in place for the REPL, copy for unattended runs |

## C. Product behaviour and UX

| # | Decision | Options | My call |
|---|---|---|---|
| 17 | **Several read-only calls per reply** | One action / allow N reads | **Per-profile opt-in, default off.** Fewer round trips (P+), but small models handle it badly and ordering must stay deterministic |
| 18 | **Tool cap** | 5-8 / 10-12 | **Per-profile cap (8 for interactive); modes shrink the set;** measure with the ablation. More tools mean more context cost on small windows |
| 19 | **Interactive final report** | `NothingChecked` exit 5 / invent a verdict | **Keep `NothingChecked`.** A user-run `/check` is not a verdict |
| 20 | **Plain text ends a turn; no `required` tool choice** | As designed / `<final>` tag / forced tools | **Accept; measure it;** add a per-profile `tool_choice_required` for models that obey it. Risk: small models answer when they should act |
| 21 | **Reopen ended sessions** | Only after EOF/exit/timeout / never | **Accept.** Convenience at no safety cost (a released outcome stays `NothingChecked`) |
| 22 | **User text is trusted intent; re-chain-only metrics** | Accept | **Accept.** Documented residuals; the printed chain head is the defence |
| 23 | **Slice notes** | Own files / append to the design doc | **Own files** (`docs/slices/`), folded per wave — avoids conflicts |

## D. Memory and scope boundaries

| # | Decision | My call |
|---|---|---|
| 24 | **Memory search contract** | The harness side is designed around a defined search/scope-read API; the memory store owns it |
| 25 | **Headless browser** | **Defer** until the airlock is proven |
| 26 | **Restricted capabilities, reviewer independence, endpoint concurrency** | **Defaults stand:** refuse restricted, fresh context + distinct run, concurrency 1 |

## E. Web airlock details

The airlock design (11 slices) adds thirteen smaller decisions, each with a
fail-closed default; only two affect whether the fetcher can be built at all:

| # | Decision | My call |
|---|---|---|
| W1 | Fetcher crypto provider: `ring` (C + asm, most audited) / `aws-lc-rs` (C, larger) / pure-Rust rustls | **`ring`**, confined to the out-of-process fetcher workspace `fetch/`, never in the default build. Until answered the fetcher is written and reviewed but not built in CI |
| W2 | Fetcher licence allowlist may add ISC and CDLA-Permissive-2.0 (ring, webpki-roots); the root list stays unchanged | **Yes, in the fetcher's `deny.toml` only** |
| W3–W13 | root store (compiled `webpki-roots`), search-returned hosts, LAN search endpoint, web tools in a `public` coding workspace, robots override, non-interactive import, plain http, any-vs-chosen resolved address, typed grant meets the egress floor, fallback loopback socket, Linux/Windows | **All defaults stand** (strictest choice each) |
