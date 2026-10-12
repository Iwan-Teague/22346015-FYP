# ADR-0010 — Pinned / Tuned / Open divisions; pin the request, gate the readable, key the coarse, condition the backend

**Status:** Accepted · 2026-08-18 · **Amends [ADR-0005](0005-execution-classes-not-gpu-only.md)**

## Context

The harness talks to any OpenAI-compatible endpoint. Three positions were on the table: (a) accept whatever server the user has and take a base URL; (b) standardise the environment so rows are comparable; (c) some principled split.

(a) admits an uncontrolled band into the sort key of a leaderboard that targets ±10.7% per-category precision. (b) is likely unachievable for exactly the backends named — Bench360, the closest published methodological neighbour, **excluded llama.cpp and Ollama** from its controlled cross-engine comparison on the grounds that their formats and hardware-specific optimisations "hinder controlled comparison". (c) needed a rule, not a taste.

Four measurement results decided it:

1. **The request body is free to pin and expensive to leave free.** Omitting `temperature` gives the *server's* default (llama.cpp: 0.8 plus a nine-stage sampler chain; vLLM: the model author's `generation_config.json`), producing 5 distinct outputs in 12 draws with 2 not valid Rust. The system prompt, output protocol and `tools` presence behave the same way. None of it requires a server change.
2. **The largest confound is invisible over the API.** Re-derived from Aider's raw `quant.yml` (n = 133): the context misconfiguration is 19.5pp at *z* = 3.27, *p* = 0.001, and is the **only** significant contrast in the file. It is probeable on every backend by binary-searching prompt length.
3. **Byte-identity is the wrong criterion for "does this knob move capability".** Per-token agreement compounds as a^L, and Rust solutions run 400–1500 tokens. At the tightest knob measured (flash attention, 99.873%), 40% of 500-token generations already differ. Only *oracle-verdict* stability is meaningful, and measuring it is the same instrument as ρ.
4. **The evidence used to free the backend does not exist.** The 4.5pp provider spread is *p* = 0.42, and the observed 12-configuration range is too tight to be independent (**P(range ≤ 4.5pp) = 0.0003** under a null of 12 independent draws at p = 0.70, n = 133). The published marginals cannot yield a paired bound in either direction.

## Options

1. **Free the backend** on the 4.5pp figure. Rejected: the figure is not evidence.
2. **Pin the backend** for ranked rows. Rejected: excludes vLLM and Ollama users, privileges one project, and the measurement that would justify it is under-powered by ~3.5× at any Phase 3.5 budget.
3. **Put the backend in the row key.** Rejected in its natural form: `backend_version` is fatal (**62 `ggml-org/llama.cpp` releases in 7 days, ≥200 in 30**, measured), and keying backend family alone still forecloses a question that is answerable over time.
4. **Condition the comparison, measure δ as a community instrument.** Accepted.

## Decision

**Pin the request body. Gate the readable-but-silent. Key the coarse and discrete. Free the rest. Condition what the evidence cannot yet settle.**

- **Pinned** division is the default and the only ranked one; the unqualified phrase "Rustybenchmark score" means Pinned (MLPerf naming rule).
- **Tuned** frees the serving configuration and may not be published without its Pinned twin (SPEC CPU2017 Rule 4.1.5); it reports `tuning_gain` and `verdict_agreement` on the timing subsample, not the full suite.
- **Open** accepts any base URL at T0, unranked, and absorbs every gate failure so that no gate is a bounce. SPEC Rule 4.6 (`INVALID`) is explicitly **not** adopted: SPEC has a submission committee; this project has 1 FTE.
- **Agentic** stays a separate board with `agent`, `agent_version` and `toolset_sha256` in the row key, benchmark-owned tools, and a structural T0 cap.
- **Backend family is conditioned, not keyed and not free:** default ranked view is within-backend, cross-backend comparisons are shown, marked, and ±δ-widened, and δ is estimated by pooling within-machine `rustybench ab --factor backend` contrasts across submitters. The release criterion is numeric and stated in [15](../15-profiles-and-divisions.md) §10.3.
- **`backend_version` is recorded and displayed but never in the row key.**
- **The core instrument is `rustybench ab`** — paired oracle-verdict flips over a fixed seed subset with exactly one factor varied. It serves ρ, the quant ladder, exec class, backend, and the free-bucket audit with one implementation.

## Consequences

**Good**

- Zero server changes are required to run in the ranked division on llama.cpp, vLLM and LM Studio; one relaunch (`--parallel 1`, or context) on the others. Participation cost is near the floor.
- The 19.5-point silent context loss becomes a `doctor` message and a copy-paste.
- The throughput half of the two-number thesis survives intact: threads (3.75×), batch/ubatch, flash attention, speculative decoding and all hardware stay free, so a tuned machine is still measurably tuned.
- [Q27](../OPEN-QUESTIONS.md) is retired and [Q5](../OPEN-QUESTIONS.md) answered.
- The unresolvable question becomes a published, improving measurement instead of an assertion — the leaderboard corpus is the instrument.

**Bad**

- Temperature 0 plus a mandatory system prompt runs Qwen3 and DeepSeek-R1 against their authors' explicit instructions, at a citable ~0–2 point cost. Tuned measures the handicap rather than hiding it.
- Keying `exec_class` splits the 8–16 GB partial-offload band, and the *direction* of the offload effect is unmeasured — this may be needless fragmentation.
- Nine new recorded fields against a project whose documented failure mode is documentation drift. Mitigated structurally: they live in one hashed `model-profile.toml` that is a row-key component, so drift produces a different key rather than a wrong comparison.
- Pinning is unenforceable — nothing exposes `ngl`, KV type, flash attention, batch or threads, and a 30-line server with zero weights replays `/props` byte-identically. The pinned set buys honest comparability from the honest majority and nothing else; T1 replay remains the only control that touches a determined submitter.

**Amends ADR-0005.** ADR-0005 states *"`capability_score` compares across all classes, because correctness does not care where the layers ran."* [06](../06-execution-classes.md) has already withdrawn that on measurement (7/7 byte-different at `-ngl 0` vs `-ngl 99`, one oracle-verdict flip). ADR-0005 is amended, not rewritten. ADR-0005 additionally states that `exec_class` is *"derived from the backend's reported layer split, never self-declared"*; that is false for llama.cpp (no HTTP endpoint exposes `ngl`) and, combined with "`Unknown` is not leaderboard-eligible", bans the project's flagship backend by accident. Superseded by the three-source rule (`observed` / `host` / `declared`) in [15](../15-profiles-and-divisions.md) §2.4.

**Provisional under [Q22](../OPEN-QUESTIONS.md).** The divisions, the gates and the pinned request body ship now. The **comparability rules** (§10.1–10.3) are versioned with the epoch and are not frozen until ρ is measured: at ρ ≥ 0.5 family-level pairing becomes viable, fresh per-submitter seeds become possible, and the fragmentation cost of any row key largely evaporates — which would change this decision.
