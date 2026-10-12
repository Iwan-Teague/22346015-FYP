# 15 — Model profiles and divisions

> Settles: what the harness pins, what it gates, what it keys, what it leaves free, and which rows may be compared with which. Supersedes the "Backend metadata to capture" block in [06](06-execution-classes.md) and amends [ADR-0005](adr/0005-execution-classes-not-gpu-only.md). Decision recorded in [ADR-0010](adr/0010-pinned-tuned-open-divisions.md).

---

## 1. The decision

**Pin the request body, gate the readable, key the coarse, free the rest — and where the evidence is void, condition the comparison instead of banning the configuration.** The harness never launches, configures, or dictates flags to a model server unless the user asks it to; the entire pinned set is the HTTP request body the harness itself writes (full sampler chain, harness-authored system prompt, output protocol, `n=1`, `cache_prompt:false`, `tools` key absent), which costs zero server changes and works on any base URL. Server-set knobs that move capability and fail *silently* — effective context, serving concurrency, rope scaling, KV cache dtype — are **preflight gates** with the exact fix printed, because their failure mode is a score, not an error. Server-set knobs that move capability but are low-cardinality and discrete — weights identity, quant class, execution class, template fingerprint, reasoning mode — go in the **row key**, following Terminal-Bench's `(Agent, Model, Effort)` precedent. Everything measured to move throughput without moving the *verdict* — threads (3.75×), batch/ubatch, flash attention, speculative decoding, mmap, hardware — stays **free**, which is what keeps the throughput half of the two-number thesis alive. One knob resists all four buckets: **backend**. The 4.5pp figure all three proposals used to justify freeing it does not exist as evidence (§2, re-derived: *p* = 0.42), and the experiment that would settle it is under-powered by ~3.5× at any Phase 3.5 budget — so backend is neither pinned nor free but **conditioned**: recorded, in the comparison scope but not the identity, with the default ranked view within-backend, and with a pooled community A/B measurement (`rustybench ab`) that tightens the cross-backend rule automatically as submissions accumulate. Three divisions carry this: **Pinned** (the default; the unqualified phrase "Rustybenchmark score" means this), **Tuned** (submitter's serving config, publishable only alongside its Pinned twin, SPEC Rule 4.1.5), and **Open** (any base URL, T0, unranked, never a bounce). Agentic stays a separate board with the agent in the row key.

---

## 2. The pin/free split

### 2.1 The rule that generates the table

A knob is **PINNED** iff it moves capability **and** the client can set it in a standard request body at zero server cost.
**(moves capability) ∧ ¬(client-settable)** → **GATE** if its failure is silent and it is readable or probeable; **KEY** if it is discrete and low-cardinality; **CONDITION** if its magnitude is unmeasured and pinning it would exclude the target audience.
**¬(moves capability) ∧ (client-settable)** → pinning is pure friction. **FREE**, recorded where free to record.
**Neither** → **FREE**.

Two corrections to how "moves capability" is measured, both of which change the answer:

**(a) Byte-identity is the wrong criterion and every proposal used it.** Per-token top-1 agreement compounds: P(identical generation) = a^L. Rust solutions run 400–1500 tokens.

| Knob | measured top-1 agreement `a` | P(identical @ L=400) | P(identical @ L=1000) |
|---|---|---|---|
| flash attention off vs on | 0.99873 | **0.602** | 0.281 |
| KV `q8_0` vs `f16` | 0.99608 | **0.208** | 0.020 |
| `-ngl 18` vs `-ngl 99` | 0.97814 | 1.4×10⁻⁴ | 2.5×10⁻¹⁰ |
| `-ngl 0` vs `-ngl 99` | 0.94353 | 8.0×10⁻¹¹ | ~0 |
| YaRN ×4 | 0.91951 | 2.7×10⁻¹⁵ | ~0 |

Per-token agreement of **99.990%** is required for 95% byte-identity at L=500. Nothing measured comes close. So *no* knob is output-neutral at generation length, the free bucket cannot be justified by output identity, and [08](08-run-protocol.md)'s "flag any case where identical `(model, seed, sampling)` produced different output" is a near-useless control on its own terms. This also **reconciles the two measurement tracks that appeared to disagree**: KV `q8_0` at 99.608% predicts 5.55 of 7 prompts differing at L=400; the generation track measured 4/7. Same finding, not a contradiction — and it means the KLD track's summary "`q8_0` is free" was wrong, so [06](06-execution-classes.md)'s pin of `kv_cache_type = f16` is correct and stays. (Flash attention is the residual tension: 99.873% predicts 2.8 of 7 differing, and 0/7 was observed; *p* = 0.029. Flagged in §2.3, not resolved.)

**The only criterion that matters is verdict stability**, measured as paired oracle-verdict flips over a fixed seed set with one factor varied. That is the same instrument as ρ ([Q22](OPEN-QUESTIONS.md)), the same instrument as the quant ladder ([Q5](OPEN-QUESTIONS.md)), and the same instrument as the backend contrast. Building it once retires four workstreams — see §12.

**(b) The provider-spread evidence is void.** Re-derived today from the raw `quant.yml` (14 configurations, one set of Qwen2.5-Coder-32B weights, `test_cases: 133`), two-proportion *z*:

| Contrast | Δ | z | p |
|---|---|---|---|
| context 8k vs 2k | **19.5pp** | **3.27** | **0.001** |
| fp16 vs q2_K | 9.7pp | 1.68 | 0.094 |
| fp16 vs q4_K_M | 4.5pp | 0.79 | 0.427 |
| **provider/precision spread (72.2 vs 67.7)** | **4.5pp** | **0.80** | **0.423** |

Only the context effect survives. Worse, the observed 12-configuration range is *too tight to be independent*: simulating 12 configurations at a common true rate 0.70, n = 133, gives mean range **12.9pp** and **P(range ≤ 4.5pp) = 0.0003**. The rows are heavily paired (same 133 tasks) and the published marginals cannot yield a paired interval in either direction. **The 4.5pp number is neither an effect nor a bound.** Any design that frees the backend on it is asserting, not measuring.

### 2.2 The split

Evidence column cites the dossier measurement or the re-derivation above. "Moves capability" is judged on verdict, not bytes.

| Knob | Disposition | Evidence |
|---|---|---|
| Full sampler chain (`temperature`, `top_p`, `top_k`, `min_p`, `typ_p`, penalties, `xtc`, `dry`, `mirostat`), sent explicitly every request | **PIN** | Omission gives the *server's* default, not a neutral one: llama.cpp `/props` reports temp 0.8 / top_k 40 / top_p 0.95 / min_p 0.05 and a **nine-stage** chain; vLLM instead applies the model author's `generation_config.json`. 12 draws on a Rust fn-signature prompt with no `temperature` sent → 5 distinct outputs, **2 of which were not valid Rust**; `temperature=0` → 12/12 identical. [12](12-schemas.md) currently records 4 of 9 active samplers. |
| System prompt (harness-authored, verbatim, hashed) | **PIN** | "No system prompt" is not neutral, it is per-vendor: Qwen2.5-3B's template injects *"You are Qwen, created by Alibaba Cloud…"* (30 vs 15 `prompt_tokens`; omitting **costs** 15 tokens of hidden instruction), Ornith-9B is the opposite sign (11 vs 17). Not a throughput knob: format-strict system prompt cut mean completion 353.7 → 60.7 tokens (5.8×), prose contamination 6/6 → 0/6, **cap-hits 4/6 → 0/6** at `max_tokens=400` — four scored failures recovered by a string. |
| Output protocol: whole-file / single fenced block, never a strict diff | **PIN** | Aider polyglot, same Qwen2.5-Coder-32B weights, same tasks, format only: diff **8.0%** pass / 71.6% well-formed / 148 malformed; whole **16.4%** / 99.6% / 1. A **2.05×** score difference from the response protocol. 59 of 69 leaderboard rows sit below 100% well-formed. Direction is task-shape-dependent (2023 refactoring had diff beating whole 20%→61%), which is exactly why it cannot be free. |
| `tools` key **absent** from the body | **PIN** | Already landed in [08](08-run-protocol.md). 3/3 non-trivial Rust tasks flipped from ```rust blocks to `finish_reason: tool_calls` with **0 chars of content**; 16 irrelevant tools did the same; `tool_choice:"none"` is not a control (`prompt_tokens` identical at 323, raw `<tool_call>` blob in content) because the template branches on `{%- if tools %}`. |
| `n = 1` | **PIN** | Required for determinism; vLLM additionally suppresses `prompt_tokens_details` and per-request metrics when n>1. |
| `cache_prompt: false`, verified via `usage.prompt_tokens_details.cached_tokens == 0` | **PIN** | Sent unconditionally (unknown fields ignored). llama.cpp, 1124-token prompt: cold 762.2 ms → warm 20.4 ms (**37.4×**) → warm with `cache_prompt:false` 751.5 ms (within 1.4% of cold). Not only timing: vLLM #40896 (Qwen3-8B, H100, temp 0) reports the cache-miss request returning a *different completion* from all cache-hit repeats, diverging at token 0, and MI355X shows it while MI325X does not. Retires [Q27](OPEN-QUESTIONS.md). |
| `max_tokens` ≥ 32768 for reasoning-detected rows | **PIN** | [02](02-task-format.md) sets 16000. Ornith-9B, same task and seed at temp 0: `max_tokens` 100 / 200 / 400 → `finish_reason: length` with **0 characters of content** every time; 600 → `stop`, 579 completion tokens, **113 chars of correct code** (`v.split_at_mut(k)`). ~94% of emitted tokens were reasoning. Qwen3's own card specifies 32,768 for most queries and 38,912 for benchmarking complex programming; 16000 is 41% of that. |
| Endpoint = `/v1/chat/completions` | **PIN** | `/v1/completions` applies no template at all (verified: a hand-written ChatML string tokenised to 10 tokens with no wrapping). Self-rendering produces double-BOS on Llama-3/Gemma and loses tool rendering. |
| **Effective context** | **GATE**, per category | The only significant effect in `quant.yml` (19.5pp, *p* = 0.001), and invisible over the API on every backend: llama.cpp returns `HTTP 400 {"type":"exceed_context_size_error","n_ctx":4096}`; Ollama truncates silently. Probe by binary-searching prompt length until the server errors **or** `usage.prompt_tokens` stops tracking the input — no vendor extension, works on silent-truncating backends. See §2.4 for the per-category correction. |
| Serving concurrency = 1 | **GATE** | Already landed in [08](08-run-protocol.md). llama.cpp reports `total_slots: 4` with no `-np` flag; 8 slots on an identical prompt → 5–8 unique completions; vLLM at temp 0 → 80 distinct completions in 1000 runs, first divergence at token 103. |
| Rope / YaRN scaling = none | **GATE** | Already landed in [06](06-execution-classes.md). YaRN ×4 measured over **512-token windows** (so no prompt is long): +1.93% PPL, 91.95% top-1; linear ×2: **+211% PPL**, 58.5% top-1. Control: `-c` alone across 2048/8192/32768 within native context gave **bit-identical** greedy completions — configured context is free, rope is not. Qwen's own cards: add `rope_scaling` "only when processing long contexts is required". |
| `kv_cache_type = f16` | **GATE** | Already landed in [06](06-execution-classes.md); §2.1(a) confirms it rather than weakening it. `q4_0` additionally costs +72.6% PPL on a narrow-KV model (16/2 heads, 256 KV dims/layer) vs +0.27% on a wide-KV one — a 270× architecture-dependent spread, so no global rule is defensible. |
| Weights identity + quant class {≥Q4_K, ≤Q3} | **KEY** | The Aider quant deltas are individually non-significant at n=133 (§2.1b); the signal is the *monotone ladder* in the GGUF k-quant data — Llama-3.1-8B GSM8K FP16 77.63 / Q4_K_S 77.33 / **Q3_K_S 68.31**, PPL 7.32 / 7.62 / 8.96. Cliff is below Q4, not between Q4 and Q8. Code-specific AWQ-4bit costs up to −6pp on DeepSeek-Coder 6.7B/33B. |
| `exec_class` | **KEY** | Already landed in [06](06-execution-classes.md): 7/7 byte-different at `-ngl 0` vs `-ngl 99`, one oracle-verdict flip (GPU compiled, CPU returned `&[u8]` as `&[u32]`). §2.1(a) shows divergence is *certain* at Rust generation lengths (1.4×10⁻⁴ at `-ngl 18`). |
| Template fingerprint | **KEY** | "Same model name" ≠ same template: `bartowski/google_gemma-4-26B-A4B-it-GGUF` through the HF→Ollama registry receives a **159-byte** template layer versus the full GGUF template; LM Studio lets the user hand-edit the template in the GUI between two runs on the same machine. |
| Reasoning mode | **KEY** | Set by the *weights' template*, not by any request parameter: Ornith-9B's template terminates the rendered prompt with `<|im_start|>assistant\n<think>\n`. Cannot be a declared flag; must be detected. |
| Suite version, prompt-pack hash, sampling-profile id, division | **KEY** | Prompt style alone moved Mistral-7B on ARC-Challenge 50.1% → 72.4% *within one harness*, with ranking flips. A prompt-pack change is a benchmark-version bump, not a patch. |
| **Backend family** | **CONDITION** | Evidence void (§2.1b). Not pinned (would exclude vLLM/Ollama users and privilege one project); not free (would admit an unmeasured between-submitter bias into the sort key). Recorded, in the comparison scope, default ranked view within-backend. Measurement and release criterion in §10.3. |
| **Backend version / build** | **FREE**, recorded, **never in the row key** | Measured today via `gh api`: **62 `ggml-org/llama.cpp` releases in the last 7 days, ≥200 in 30 days** (API page cap). A build number in the row key makes essentially every submitter a singleton cell. Read it from the standard `system_fingerprint` field where present (llama.cpp: `b10470-34af94cd9`; Ollama hardcodes `"fp_ollama"`). |
| Threads | **FREE** | Largest single free knob: CPU-only tg128 t1=11.02 → t8=41.34 tok/s (**3.75×**), t10 regresses 24.7% below t8, and `llama-bench`'s own default t=4 is 37% below optimum. 0/7 output change. This is the owner's "a generic environment flatters nobody", quantified. |
| Prefill chunk size (`-b` / `-ub`) | **FREE** | 0/7 across ubatch 64–512 and batch 64–2048, bit-identical under 4-slot concurrency. **Naming trap to fix in the docs:** "prefill chunk size" is free, "serving concurrency" is gated, and both are called batch size. |
| mmap / mlock, NUMA, `sccache`, target-dir layout | **FREE** | mmap measured at +1.2% (16.6 → 16.8 tok/s). Ignorable. |
| Configured `n_ctx` within the model's native window | **FREE** | Bit-identical greedy completions across 2048/8192/32768. Changes KV memory only. Distinct from both the context *gate* and rope scaling. |
| Hardware, power state, thermal envelope | **FREE**, unverifiable | Already correctly tiered by [10](10-integrity.md). |

### 2.3 Weak evidence — fail-safe defaults

Every row here has evidence too thin to carry a design decision. Each gets the default that is wrong in the *safe* direction, and none gates a run.

| Knob / claim | Why the evidence is weak | Fail-safe default |
|---|---|---|
| **Flash attention is output-neutral** | 0/7 measured, but its own 99.873% top-1 predicts 2.8 of 7 differing at L=400 (*p* = 0.029). Metal only; CUDA flash attention is a different kernel with a different reduction order. Rule of three: 0/7 gives a 95% upper bound of **34.8%** on the true divergence rate. | **FREE** (throughput cost of pinning is only +3.2% at depth 0), recorded because llama.cpp requires it to quantise the V cache. Add to the standing `ab` probe (§9.3), do not write "output-neutral" as fact. |
| **Speculative decoding is lossless** | Distribution-preserving by construction and χ² = 162.5, *p* = 0.976 over ~9200 tokens — but never verified on this project's hardware, and llama.cpp ships lossy variants (`--spec-type draft-mtp`) whose equivalence is not established. Verification also decodes K positions in one batch, inheriting any batch non-invariance. Throughput effect can be **negative** (0.33–0.52× on quantised Metal). | **OFF for Pinned rows** unless the submitter passes the one-unit byte-identity check against a spec-off replay. Always recorded (`draft_model`, `draft_n_max`, variant). Invisible in llama.cpp `timings`; detectable only via `/slots.speculative` and `/metrics spec_decode_*`. |
| **KV-quant risk predicted from KV dims/layer** | Two data points that happen to land where the llama.cpp #21385 mechanism predicts. Encouraging, not established. | Advisory warning on the row. **Never a gate.** `f16` is pinned regardless of geometry. |
| **Behavioural (logprob) weights fingerprint** | Measured negative: same weights at `-ngl 99` vs `-ngl 0` gave top-5 set-equality **6/8** and max |Δlogprob| **0.853** — 43× the 0.020 that KV quantisation produces — while genuinely *different* weights at the same exec class gave 4/8. Signal and noise are the same order at n = 8. Untested on the case that matters (two quants of the same weights). | Ship the field with `status = "not_yet_a_gate"`. Publish the operating characteristic it would need (§12.2). Never a badge. |
| **llama.cpp Metal is batch-invariant** | 0/7 across ubatch and 4-slot concurrency, contradicted by a report of batch-dependent logit shifts up to ~0.1 on quantised Metal under multi-position speculative verification. Different regimes; both can be true. | Record `batch_invariance` as a **per-backend, per-regime probed field**. Never assert it in prose. |
| **Prefill tok/s discriminates exec class** | 4.4× prefill vs 1.5× decode, but measured under two contending servers; single model, single arm64 host. | Not a plausibility gate. R5-S5 killed six checks for exactly this shape. |
| **Co-tenancy detection** | Real effect (26.6× pp512 swing, and within-invocation stddev did not detect it — a contended run self-reported `tg128 57.97 ± 0.05`). But the broad form fires on ~100% of the target audience: this machine currently has 30 Chrome, 27 VS Code, 4 Safari, 3 Electron processes plus `WindowServer`, every one a GPU client on the unified-memory hardware [06](06-execution-classes.md) exists to serve. | **Narrow form only**: another inference server process, or another process with the weights file mapped. Flags **throughput** unscorable; never touches `capability_score`; never invalidates a run. FP rate must be measured on real machines before it becomes a hard flag. |
| **Ollama defaults to 2k context** | Stale. `envconfig/config.go`: `ContextLength = Uint("OLLAMA_CONTEXT_LENGTH", 0)`, doc string *"default: 4k/32k/256k based on VRAM"*. The 19.5pp measurement dates from Nov 2024. | Cite the **failure mode** (silent truncation, invisible over the API) as the durable finding. Never quote "2k" as current fact. The probe measures the actual value anyway. |
| **GitHub Copilot 40→13 tools = +2–5pp** | Vendor-reported, aggregate range only, no per-benchmark baselines, not independently replicated. The Microsoft Research MCP survey it is usually bundled with explicitly did **not** measure task success against varying MCP configurations. | Cite as a range with attribution. Do not build a capability claim on it. |
| **Harness variance = 7.80× model variance** | Single 2026 arXiv preprint, unverified as peer-reviewed, referencing models that cannot be independently confirmed. Corroborated in *direction* by an independent five-harness replication and the live Terminal-Bench board. | Attribute to the preprint. Use the direction, not the coefficient. |

### 2.4 Two gates that are wrong as specified and must be fixed before shipping

**The context gate refuses the design's own flagship suite.** [04](04-categories.md) sizes `cross-module` at ≤5k LoC, and measures **10.4–12.3 tokens/LoC on 3,000 real `.rs` files ⇒ 52k–62k tokens of source alone — "beyond a 32k context"**. Add a 32k completion budget and the requirement is ~90k. A single suite-level context gate therefore marks `deep` invalid for the entire 8–24 GB band the project targets. **Resolution, which is also [Q12](OPEN-QUESTIONS.md)'s stated leaning:** the gate is **per category**. Each category declares `min_effective_ctx`. A category whose requirement exceeds the probed value emits `skipped_context` (a flag [12](12-schemas.md) already defines), is **excluded from that category's denominator and reported as absent, not zero**, and the row publishes `categories_scored`. Rows with different `categories_scored` are not comparable on `capability_score` — which is the rule [00](00-overview.md) and [04](04-categories.md) already carry for `perf-optimization` and `capability_score_core5`. The gate refuses a *run* only when a **core** category is unattemptable.

**`exec_class` cannot be derived as [06](06-execution-classes.md) says it is, and the current text bans llama.cpp by accident.** [06](06-execution-classes.md) states offload is *"derived from the backend's reported layer split, not self-declared. For llama.cpp: `ngl` vs total layers"*, and that `Unknown` is not leaderboard-eligible. Measured: a `llama-server` launched with `-ngl 99 -fa on -ctk q8_0 -ctv q8_0 -ub 256 -b 1024 -t 6` exposes **none** of it — grepping the full `/props` body for `flash|cache_type|type_k|n_batch|n_ubatch|n_threads|n_gpu_layers|ngl|rope|yarn|offload` returns **zero hits**; `/slots` returns `{id, n_ctx, speculative, is_processing}`; `/metrics` is 501 without `--metrics`. Taken literally, every llama.cpp row is `Unknown` and therefore ineligible. **Resolution:** `exec_class` has three sources, ranked — `observed` (Ollama `/api/ps`, `size` vs `size_vram`, the only backend reporting offload over HTTP), `host` (harness colocated with the server: launch args, accelerator memory attribution — available in managed mode, §9.1), `declared` (everything else). `Unknown` means *no source at all*, not *not machine-readable*, and a `declared` exec class is leaderboard-eligible at the self-reported tier.

---

## 3. The divisions

Names avoid two live collisions: `standard` is a **suite** ([07](07-statistics.md)) and *reference* is a **generated artifact** ([ADR-0003](adr/0003-per-seed-generated-references.md)). Hence Pinned / Tuned / Open.

**MLPerf's naming rule, adopted verbatim:** the unqualified phrase "Rustybenchmark score" means **Pinned**. Any other division carries a qualifier that cannot be dropped from a screenshot.

### 3.1 Pinned — the default, and the only ranked division

- **Pins:** the entire request body of §2.2 (sampler chain, system prompt, output protocol, `tools` absent, `n=1`, `cache_prompt:false`, `max_tokens`, chat-completions endpoint).
- **Gates:** per-category effective context, concurrency = 1, rope = none, KV = `f16`, template establishable.
- **Keys:** weights identity + quant class, `exec_class`, template fingerprint, reasoning mode, `suite_version`, `prompt_pack_hash`, `sampling_profile_id`, `categories_scored`.
- **Conditions:** backend family (§10.3).
- **Frees:** backend version, threads, batch/ubatch, flash attention, mmap/NUMA/sccache, configured `n_ctx` within native, all hardware.
- **Measures:** `capability_score` + per-category vector + CIs, `throughput_score`, `first_try_score`, `apply_rate`, `well_formed_rate`, `budget_exhausted_rate`, `cache_hit_ratio`, `harness_overhead_ratio`.
- **Comparable to:** any other Pinned row with an identical row key. Cross-backend comparison is available but marked and interval-widened (§10.3). Throughput additionally requires matching `exec_class` **and** memory architecture — `offload_ratio = 0.75` is 73% of peak on Apple unified memory and ~13% on a discrete PCIe card (RTX 5060 Ti, 48-layer model: `ngl 40` = 12.5 tok/s vs `ngl 48` = 43.18 tok/s; the last 8 layers alone are worth 3.45×). `offload_ratio` is not a comparable scalar across memory architectures and is **not** in the row key (continuous keys never match).

### 3.2 Tuned — SPEC "peak", Lambda "Optimized"

- **Pins:** the harness-owned layer only (prompt pack, output protocol, oracle, suite, seed set, `tools` absent), plus the per-category context gate, plus **same machine, same weights file, same session, A/B/A interleaved**.
- **Frees:** sampling (typically the model author's published values), system prompt, prefix caching, rope, `q4_0` KV, concurrency, speculative decoding of any variant.
- **Why it exists:** full standardisation is explicitly counter-recommended by two of the most likely subjects. Qwen3's card: *"DO NOT use greedy decoding, as it can lead to performance degradation and endless repetitions"*; DeepSeek-R1's README: *"avoid adding a system prompt"*, temperature 0.5–0.7. Pinned runs both against their authors' instructions. Tuned measures the size of that handicap instead of hiding it.
- **Measures:** `tuning_gain` = `throughput_tuned / throughput_pinned`; `verdict_agreement` = fraction of paired units reaching the same oracle verdict as the Pinned pass (**not** byte agreement — §2.1a); `capability_delta` with a paired CI.
- **Cost control:** the Tuned pass runs over the existing 10% timing subsample plus the `ab` seed subset, **not** the full suite. A `deep` run is already 44.5 h; doubling it is not viable.
- **SPEC Rule 4.1.5, verbatim:** a Tuned row may not be published without its Pinned twin. Rendered as one row with two numbers and a delta, never as a standalone entry.
- **Comparable to:** its own Pinned twin, as a delta. `tuning_gain` is comparable across machines **as a ratio only**, with the caveat in §11.4.
- **Volume expectation:** small. MLPerf v5.1 ran 108 Closed system configurations vs 28 Open (3.9:1), 29 vs 8 submitting organisations. A free lane is an overflow valve, not a growth engine.

### 3.3 Open — the anti-bounce lane

- **Pins:** the harness-owned layer, and the context gate (a truncated prompt is a *different task*, not a harder one).
- **Frees:** everything, including everything Pinned gates. Any backend, KoboldCpp, LocalAI, a hosted API behind a base URL, LM Studio with a hand-edited GUI template.
- **Measures:** the same scores at **T0**, greyed, unranked, excluded from every aggregate and from all paired statistics.
- **Comparable to:** nothing by default. Two Open rows compare only when every key field matches, and the UI computes that mechanically and names the differing field rather than asserting comparability.
- **Its actual product:** the ecosystem census — which backends, quants, contexts and templates people really run — published with the self-selection caveat attached. This is the reason [06](06-execution-classes.md)'s "one field now, no schema migration later" instinct is right.
- **Why P1's SPEC Rule 4.6 (`INVALID`) is rejected:** SPEC can mark a submission invalid because it has paying members and a submission committee. A 1-FTE hobbyist leaderboard converts every gate into a bounce. Open absorbs every gate failure, so gates cost *participation* (self-limiting, unmeasurable in advance) rather than *alarm budget* (measured by R5-S5 at 50–98% false-positive against 1 FTE).

### 3.4 Agentic — separate board

- **Pins:** the toolset is **benchmark-owned** (τ-bench pattern: fixed local tools shipped with the benchmark, graded on resulting **state** rather than call syntax — which composes with this project's property-based oracle); a deliberately minimal reference agent (Terminal-Bench's Terminus precedent, an LLM plus a shell); timeouts; repo state; patch extraction. **Local stdio tools only** (§8.4).
- **Row key includes `agent`, `agent_version`, `toolset_sha256`, `tool_count`, `tool_schema_tokens`,** under the same mismatch-is-fatal rule [12](12-schemas.md) applies to `model`/`quant`/`backend_version`.
- **Measures:** model **and** scaffold, jointly and inseparably, plus a mandatory `tool_call_validity_rate` — without it the Rust number is uninterpretable for this population (seven local models on a trivial Rust edit task: 4/7 passed, `qwen2.5-coder:14b` made **zero** tool calls and emitted the tool-call JSON as plain text, while `qwen3:8b` passed; n=1 task, weak, but it agrees with the direct measurement in §8.1).
- **Structurally capped at T0.** The server can re-materialise the seed but not the toolset, so T1 replay is impossible for any tool-touching unit. Tool-enabled results must not be compared across epochs: a 3-month study of live MCP servers found **20.7% of remote servers went dark** and **54.6% of tools modified (32.5%) or deprecated (22.1%)**.
- **Comparable to:** other Agentic rows sharing the full agent-inclusive key. Never merged with Pinned. SWE-agent's ACI ablation put the tools-on/tools-off gap at **+10.7pp on the same model** — roughly a model generation.
- **Counter-evidence that argues for keeping it minimal:** mini-SWE-agent is ~100 lines, bash-only, does not use the tool-calling interface at all, and scores >74% on SWE-bench Verified. The rich-ACI advantage is a function of model weakness and is shrinking.

---

## 4. The model profile — concrete TOML

Two files, deliberately different formats for different epistemic status. **`model-profile.toml`** is what a human declares or `rustybench doctor` writes for them — TOML because it is hand-editable and matches `Cargo.toml`, and because *everything a human types is at the lowest trust tier by construction*. The harness's own observations go into `env.json` inside the run bundle, alongside the existing [12](12-schemas.md) schemas. `profile_hash` = blake3 over the canonicalised TOML and is a row-key component.

```toml
schema      = 1
profile_id  = "blake3:9f2c…"
division    = "pinned"                 # pinned | tuned | open | agentic
captured_at = "2026-08-18T11:04:22Z"
doctor      = "rustybench 0.1.0"

# ─── endpoint ───────────────────────────────────────────────────────────────
[endpoint]
base_url_hash    = "blake3:…"          # never the URL: it may carry a hostname
attach_mode      = "attached-colocated" # managed | attached-colocated | attached-remote
backend          = "llama.cpp"          # probed
backend_version  = "b10470-34af94cd9"   # probed: standard `system_fingerprint`
version_source   = "system_fingerprint" # system_fingerprint | props | tgi_info | declared
introspection    = "full"               # full | partial | none
endpoints_seen   = ["/props", "/v1/models", "/tokenize", "/apply-template"]
tier             = "probed"

# ─── context: the one hard gate ─────────────────────────────────────────────
[context]
reported_ctx     = 32768
effective_ctx    = 32768                # binary-search probe — the authoritative value
ctx_source       = "probed"             # probed | props | api_ps | max_model_len | v0_models
overflow_mode    = "loud_fail"          # loud_fail | silent_truncate
categories_ok    = ["borrow-lifetimes","traits-generics","unsafe-core","async-concurrency","idiom-refactor"]
categories_skipped = ["cross-module"]   # emits `skipped_context`, excluded from denominator
tier             = "probed"

# ─── template: keyed, fingerprinted, never re-implemented ───────────────────
[template]
sha256                 = "55b2f4a26ac9…"   # exact Jinja, where exposed
source                 = "props"            # props | api_show | probe_only
probe_vector           = [30, 15, 42]       # usage.prompt_tokens for P1/P2/P3 — universal
injects_default_system = true               # derived: P1 > P2 inversion
bos_token              = "<|endoftext|>"
add_bos_token          = false
jinja_engine           = true               # llama.cpp --jinja default FLIPPED to enabled
tier                   = "probed"

[template.caps]                             # llama.cpp chat_template_caps; Ollama capabilities[]
supports_tools             = true
supports_tool_calls        = true
supports_reasoning_effort  = true
supports_preserve_reasoning = true

[reasoning]
mode                  = "off"               # always_on | off | request_controlled | unknown
detected_via          = "apply_template_tail"
content_separated     = true                # false ⇒ <think> arrives inline in content
budget_tokens_applied = 32768
tier                  = "probed"

# ─── weights: a ladder, never a badge (see §6) ──────────────────────────────
[weights]
declared_name   = "qwen3-coder-30b-a3b"
declared_quant  = "Q4_K_M"
quant_class     = "q4k-plus"                # q4k-plus | sub-q4 | fp16-plus | undeclared
identity_tier   = "W3"                      # W0 | W1 | W2 | W3 | W3+W4
file_hash       = "blake3:…"                # W3: harness hashed the file it was pointed at
gguf_uuid       = "c0a8d335-3f52-54d4-…"    # llama-gguf-hash --uuid (metadata-stable)
registry_digest = ""                        # W2: Ollama library / TGI model_sha, where applicable
path_basename_hash = "blake3:…"             # NEVER the path, NEVER the basename in clear
hash_scope      = "file_on_disk_not_proof_of_load"   # literal string, always emitted
tier            = "self_reported"           # ALWAYS. No exceptions.

[weights.geometry]                          # probed; survives --alias spoofing
n_params        = 30532000000
n_vocab         = 151936
n_embd          = 2048
n_ctx_train     = 262144
ftype           = "Q4_K - Medium"
head_count      = 16
head_count_kv   = 2
key_length      = 128
value_length    = 128
kv_dims_per_layer = 256                     # derived; advisory only (§2.3)
consistent_with_declared_name = true

[weights.behavioural_fp]
spec      = "rb-fp/0"
probes    = 8
statistic = "top5_token_id_set + rank_order"
value     = "sha256:10a6fdb51696cd96…"
status    = "not_yet_a_gate"                # measured negative — §2.3, §12.2

# ─── request contract: authored by the harness ──────────────────────────────
[request]
sampling_profile_id = "greedy-v1"
sampling_hash       = "blake3:…"
system_prompt_id    = "rb-sys/1"
system_prompt_sha256 = "blake3:…"
prompt_pack_id      = "rb-prompt/2026.08.1"
prompt_pack_sha256  = "blake3:…"
output_protocol     = "whole_file"
endpoint_path       = "/v1/chat/completions"
tools_offered       = false
tools_attested      = true                  # prompt-token prediction matched
tools_attestation_delta = 0                 # predicted 38, observed 38
n                   = 1
cache_prompt_sent   = false
max_tokens          = 32768
sampler_pin_level   = "full"                # full | core_only (server 4xx'd the extensions)
tier                = "harness_authored"

[request.sampling]
temperature = 0.0
top_p = 1.0
top_k = 0
min_p = 0.0
typ_p = 1.0
repeat_penalty = 1.0
repeat_last_n = 0
presence_penalty = 0.0
frequency_penalty = 0.0
dry_multiplier = 0.0
xtc_probability = 0.0
mirostat = 0
seed = 42

[server_defaults]                            # what WOULD have applied — probed, for the reader
temperature = 0.8
top_k = 40
top_p = 0.95
min_p = 0.05
sampler_chain = ["penalties","dry","top_n_sigma","top_k","typ_p","top_p","min_p","xtc","temperature"]

# ─── declared: no observation path on any backend. Hardware trust tier. ─────
[serving]
exec_class        = "GpuFull"
exec_class_source = "host"                  # observed | host | declared   (§2.4)
offload_ratio     = 1.0
memory_arch       = "unified"               # unified | discrete  — offload_ratio is meaningless without it
kv_cache_type_k   = "f16"
kv_cache_type_v   = "f16"
flash_attn        = true
rope_scaling      = "none"
threads           = 8
batch             = 2048
ubatch            = 512
concurrency       = 1                       # probed via /slots where available
tier              = "self_reported"

[serving.speculative]
enabled     = false
draft_model = ""
variant     = ""                            # exact_verification | draft_mtp | other
byte_identity_checked = false

# ─── probes: recorded facts, not assumptions ────────────────────────────────
[probes]
determinism_sequential = "5/5 identical"
determinism_concurrent = "4/4 identical"
batch_invariance       = "probed_true_regime_A"   # per-backend, per-regime (§2.3)
cache_field_available  = true                     # false on Ollama's OpenAI surface
cache_prompt_honoured  = true
cold_prefill_ms        = 762.2
warm_prefill_ms        = 20.4
timings_available      = true
cotenancy_inference_servers = 0                   # narrow form only (§2.3)
```

---

## 5. What can be captured, ruthlessly bucketed

The client owns the machine. That single fact collapses most of what the proposals called "verifiable".

### 5.1 VERIFIABLE — the server re-derives it without trusting the submitter

This is a **short list**, and it is short on purpose. Only [10](10-integrity.md)'s T1 replay path qualifies: the server re-materialises the instance from the seed and re-runs the oracle over the *submitted output*.

- **L0–L3 oracle verdicts** for every submitted unit. (L4 cannot be replayed — criterion timings are hardware-dependent and cargo-mutants is not deterministic; L4 stays T0 even inside a T2 row, per [10](10-integrity.md).)
- **Suite hash, plan hash, generator commit, seed-set membership, unit count, epoch and challenge nonce** — the server recomputes these from the seed and the commit, so a mismatch is arithmetic, not testimony.
- **Cross-row consistency**, which is the one genuinely *external* anchor this design has: two rows claiming the same weights must agree on the geometry block and the template fingerprint, or one is misdeclared. The anchor is the **published corpus itself** — precisely what R5-S5 found the killed plausibility checks lacked.

Nothing else is in this bucket. In particular, `tools_offered` is **not**: the harness authors the `tools` array, which makes it non-spoofable **by the model server** and defeated by a patched client — exactly [10](10-integrity.md)'s stated T0 assumption. It is strong evidence against accidental leakage and no evidence at all against a determined submitter.

### 5.2 SELF-REPORTED — sub-tiered by the cost of the lie

Everything read from the endpoint, and everything the harness asserts about its own request. All of it is spoofable; they differ only in effort. A **30-line Python HTTP server holding zero bytes of weights** replayed llama.cpp's `/props` byte-identically — the full 2506-character chat template, `build_info`, `model_path`, `ftype` — plus a fabricated `/v1/models.meta` block and fabricated timings claiming 516 tok/s prefill. Only logprobs could not be produced.

| Sub-tier | Cost of the lie | Fields |
|---|---|---|
| **S1 — caught by internal consistency** | edit a CLI flag | `--alias` spoofing: setting `--alias "Llama-3.3-70B-Instruct-Q8_0"` on a Qwen2.5-3B-Q4_K_M server changed the `id` but `meta` still reported `n_params = 3085938688` (not 70B), `ftype = "Q4_K - Medium"`, `n_vocab = 151936` (Llama-3.3 is 128256). Catches every attacker using only supported flags. |
| **S2 — requires patching the harness** | recompile the client | `sampling_hash`, `system_prompt_hash`, `prompt_pack_hash`, `tools_offered`, `tools_attested`, `n`, `cache_prompt_sent`, `probe_vector`, determinism/cache/co-tenancy probe results, `file_hash` |
| **S3 — requires patching or impersonating the server** | 30 lines of Python | `backend`, `backend_version`, `effective_ctx`, `overflow_mode`, `template.sha256`, `caps`, `cached_tokens`, `timings`, `total_slots`, `weights.geometry`, `quantization_level`, `max_model_len`, Ollama `size_vram` |
| **S4 — free text, no anchor** | type a string | `declared_name`, `declared_quant`, all `[serving]` fields, all hardware, `memory_arch` |

The whole of §5.2 receives the **same leaderboard treatment [10](10-integrity.md) already gives hardware claims**. The design's existing position — *hardware is unverifiable, so it is labelled differently* — extends verbatim to model identity, and saying so is the single most important honesty move in this document.

### 5.3 UNOBSERVABLE — no path on any backend, at any tier

- `n_gpu_layers` / offload ratio (**except** Ollama `/api/ps` `size` vs `size_vram`), `kv_cache_type`, `flash_attn`, `threads`, `batch`, `ubatch`, NUMA policy, rope settings. Verified by exhaustive grep of `/props`, `/slots` and `/metrics` (§2.4).
- **Which weights the process actually has in memory.** Hashing a file proves a file with that hash exists on disk (measured cost: `sha256` of a 1.93 GB GGUF = 3.6 s; `llama-gguf-hash --uuid --no-layer` = 2.1 s; ~31 s extrapolated for 16.7 GB, against a run measured in tens of hours). It raises the cost of fraud from *edit a string* to *patch the binary*, and nothing more.
- **A wrapping agent's MCP toolset.** MCP `tools/list` / `tools/call` are JSON-RPC between the MCP host and the MCP server; the traffic never touches the inference API. Only the aggregate prompt-token footprint is observable.
- **Whether the base URL proxies to a hosted frontier model.** Nothing in this design detects it. The two checks that might have — throughput plausibility and error-code fingerprinting — were killed by R5-S5 for firing on 50–98% of honest runs. This belongs on the public methodology page as a stated limit, not discovered later.
- Speculative decoding on any backend but llama.cpp; batch size, thread count and NUMA on all four.

### 5.4 New per-unit fields this forces into `journal.jsonl`

- `finish_reason` — absent today, and without it budget exhaustion is indistinguishable from incapacity (§2.2).
- `budget_exhausted` boolean, and a published `budget_exhausted_rate` **column**. **The denominator does not move.** [02](02-task-format.md)'s "overrun is a scored failure" stands: score it 0. Excluding these units is a denominator attack on a field the submitter's own server emits — base rate 40%, exclude the hardest 15% (which would have scored ~5%), and `0.85x + 0.15(0.05) = 0.40` gives **x = 46.2%, +6.2 points**, larger than the gap the design exists to detect, at zero cost and with a sympathetic cover story. A run whose `budget_exhausted_rate` exceeds a published threshold is **tainted**, not adjusted.
- `cached_tokens` / `cache_hit_ratio` per unit; non-zero invalidates that unit's *timing*, never its verdict.
- `reasoning_content_present`, `reasoning_chars`. There is no `completion_tokens_details.reasoning_tokens` on llama.cpp. **Live correctness bug:** under `--reasoning-format none` the `<think>…</think>` block arrives **inline in `content`**, where a naive fenced-code extractor will pick up code the model wrote while thinking and then discarded. The L1 apply layer must strip it.
- `apply_ok` / `well_formed` promoted from weight-0.0 gates to **published columns**. [03](03-oracle.md) gives apply weight 0.0; for local models it is a substantial fraction of the measured difference — Qwen3-32B lost **16.4% of cases to format alone** on a diff protocol.
- `timings` opportunistically (llama.cpp returns `{prompt_n, prompt_ms, predicted_n, predicted_ms, cache_n}` on the standard endpoint and it survives `--no-perf`).

---

## 6. Weights identity

**Requirement (i) — "which weights are actually loaded" — is not answerable, at any tier, on any backend.** It belongs in exactly the same sentence as "hardware claims are unverifiable". What the leaderboard gets instead is a ladder, and every rung states what defeats it.

| Tier | Evidence | Proves | Defeated by |
|---|---|---|---|
| **W0** | declared name + quant | nothing | anything |
| **W1** | geometry block — llama.cpp `/v1/models.meta`; Ollama `/api/show.model_info`; LM Studio `arch`+`quantization`; **vLLM: nothing** | the declared name is arithmetically consistent with what is loaded | a patched binary. **Not** defeated by `--alias` (§5.2 S1). Free, so mandatory. |
| **W2** | registry cross-check — Ollama digest against `registry.ollama.ai` (live-verified: `sha256:5ee4f07cdb9b…`, size 1929903008, with the **template as a separately content-addressed blob**, so the template is independently pinnable); TGI `/info.model_sha` = an HF commit | the declared identity names a real public artifact of the right size | a server lying about its own digest. Partial coverage: `ollama create` and local GGUF imports have locally-computed digests with no public counterpart. **The manifest byte-canonicalisation for the comparison is unspecified and must be nailed down before shipping.** |
| **W3** | local file hash + `llama-gguf-hash --uuid` | a file with that hash exists on this disk | it does **not** prove the server loaded it. Raises fraud cost from *edit a string* to *patch the binary*. |
| **W4** | behavioural top-k logprob probe | the endpoint runs *something* behaving like the claimed weights — the only signal the 30-line fake server could not produce | **currently defeated by the nuisance factor the design cannot pin.** See below. |

**W4 is measured non-viable as currently specified.** Same weights at `-ngl 99` vs `-ngl 0` gave top-5 set-equality **6/8** and max |Δlogprob| **0.853** — 43× the 0.020 that KV quantisation produces — while *different weights* at the same exec class gave **4/8**. Signal (4/8) and noise (2/8) are the same order at n = 8. The dossier's recommendation to fingerprint on rank order was validated against KV quantisation and falsified against offload. Ship the field with `status = "not_yet_a_gate"`; §12.2 states the operating characteristic that would reopen it.

**What the composite cannot do, measured.** Two same-architecture, same-quant fine-tunes on this machine (`Ornith-1.0-35B-UD-Q3_K_M` vs `ornith-1.0-35b-heretic-Q3_K_M`, **733 tensors each**) are byte-identical across every architectural field: `qwen35moe`, block_count 40, embedding_length 2048, context_length 262144, file_type 12, vocab 248320, head_count 16, head_count_kv 2, key_length = value_length = 256. Only free-text `general.*` keys differ, all editable with `gguf-py` without touching a weight. **W1 separates model families; it does not separate fine-tunes.**

**What a liar can do, priced.** Rename the file: caught by W1. `--alias`: caught by W1. Edit `general.*` GGUF metadata: not caught, costs seconds. Run a 30-line fake server with no weights: not caught by anything except W4, which does not work yet — but every *oracle verdict* it claims is caught by T1 replay, so the fake server can lie about its identity and cannot lie about its score. Proxy the base URL to a hosted frontier model: **not caught at all** (§5.3). This asymmetry is the design's actual security posture and should be stated: **you can lie about what ran; you cannot lie about whether the code compiled.**

**Recommendation:** build W0–W3 now, mandate W1 (free), offer W3 wherever the harness can see the file, gate W4 behind §12.2, and ship **no "verified weights" badge in any case**. `weights.identity_tier` is displayed and doubles as a voluntary participation ladder — the same mechanic as MLPerf's Available/Preview/RDI.

**Privacy, mandatory, at capture time.** `/props.model_path` and `/v1/models.id` return an absolute filesystem path containing the account name (measured: `/Users/<user>/Desktop/models/Qwen2.5-3B-Instruct-Q4_K_M.gguf`); Ollama's `modelfile` carries the same; the chat template itself can contain identifying strings. R5-S6 already found the T1 bundle contradicting the consent screen on exactly this, and R5's `redaction-is-a-denylist` finding applies to every field added here. **Publish `blake3(basename)` plus the geometry tuple; never the path, never the basename in clear; strip at capture time so it never reaches an uploadable artifact.** A field-by-field redaction list for the new fields is a shipping blocker, tracked in §12.

---

## 7. Chat template handling

**The harness owns the template layer, and "own" means pin-and-fingerprint, never re-implement.**

**Why not re-implement.** `/v1/completions` applies no template at all — verified: a hand-written ChatML string returned `prompt_tokens = 10` with the special tokens tokenised as special and no wrapping added; llama.cpp's own README confirms `/completion` and `/v1/completions` "do not apply chat templates". Rendering client-side therefore requires the harness to own BOS handling, which is model-metadata-dependent and a documented source of silent corruption: Llama-3-family models both add BOS *and* carry `<|begin_of_text|>` inside the template, producing *"the final prompt starts with 2 BOS tokens"*, and Gemma emits *"Detected duplicate leading `<bos>` in prompt, this will likely reduce response quality"* — both to stderr, which the harness cannot see over HTTP. Client rendering also loses tool rendering entirely, which the agentic track needs. **Decision: `/v1/chat/completions` only; the server owns rendering; the harness fingerprints.**

**Why the template must be keyed rather than ignored.** It silently injects a system prompt (30 vs 15 `prompt_tokens` on Qwen2.5-3B, opposite sign on Ornith-9B). It switches reasoning on with no request parameter (Ornith-9B's template ends the prompt with `<|im_start|>assistant\n<think>\n`). It varies by *packaging*, not weights: the same nominal GGUF served through the HF→Ollama registry receives a **159-byte** template handling only basic turns versus the full GGUF template that must handle BOS, tools, thinking, tool calls and image tags. It is **user-mutable and invisible** on LM Studio, where the prompt template is editable in the GUI and GUI presets do not auto-apply to API calls. And llama.cpp's `--jinja` default **flipped to enabled**, so two submitters on different builds get different rendered prompts from the same GGUF with no visible config difference.

**The three-source fingerprint, in priority order:**

1. **Exact** — llama.cpp `GET /props.chat_template` (available with no flags; measured 2506 chars, `sha256 55b2f4a26ac9…`), Ollama `POST /api/show.template`. Record `template_sha256` and `template_source = "props" | "api_show"`.
2. **Universal probe vector** — three requests at `max_tokens = 1`: `P1=[user]`, `P2=[system,user]`, `P3=[user,assistant,user]`, recording `usage.prompt_tokens`. Measured: Qwen2.5-3B = **(30, 15, 42)**, Ornith-9B = **(11, 17, 23)** — fully distinct, no vendor API, works on all four backends. A `P1 > P2` inversion is the signature of an injected default system prompt.
3. **Fail** — no establishment ⇒ the row lands in **Open**, not `INVALID` (§3.3).

**The probe vector is a difference-detector, not an identity.** Validated on 2 models and 1 backend; collision rate unmeasured. It proves two rows are *not* comparable; it does not prove they are. Where an exact hash exists, prefer it and record which the reader is looking at.

**The evidence gap that must be stated rather than papered over.** There is **no published measurement of chat-template mismatch on a coding benchmark.** Every strong template number is instruction-following (IFEval +39% for Zephyr-7b-beta) or qualitative. The coding numbers isolate edit format (2.2–4.5pp), thinking mode (4.9pp) and serving stack (6.2pp) — not template *correctness*. This is the single largest evidence gap behind the fingerprint recommendation and it is cheaply closable in-house: §12.3.

**Corollary for the system prompt.** Because the template may inject one, the harness must send an explicit system message on every request — otherwise it is silently benchmarking each vendor's marketing copy. And because a format-strict system prompt cut output 5.8× and eliminated 4 of 6 truncations, the pinned prompt is capability-affecting and must be **validated against all five oracle layers**, not just against extractability (§12.5).

---

## 8. MCP and tools

### 8.1 Three layers, three capture stories — do not merge them into one field

| Layer | Controlled by | Capturable | Verifiable | Policy |
|---|---|---|---|---|
| **(i) harness-offered `tools` array** | the harness | **losslessly, by construction** | against the *server* only (§5.1) | Pinned/Tuned/Open: **key absent**. Agentic: **benchmark-owned**, hashed. |
| **(ii) serving-stack tools** — LM Studio `mcp.json` / `integrations`, vLLM `--tool-call-parser`, Ollama web_search | the server operator | only where the backend introspects (llama.cpp `chat_template_caps`, Ollama `/api/show.capabilities`) | no | record `serving_stack_introspection = full \| partial \| none`; do not pretend it is cross-backend comparable |
| **(iii) wrapping-agent tools** | invisible | **no** (§5.3) | no | any `mcp_servers` field is a **self-report with a capture timestamp** — `tools/list` carries `ttlMs` (300000 in the spec example) and servers emit `notifications/tools/list_changed` mid-session, so a snapshot goes stale within one run |

**Requirement (ii) is the easy one and requirement (i) is the hard one, and they must carry different badges.** The harness serialises the tool array, so it can hash exactly what it sent; nothing on any backend reports which weights are loaded. Presenting them together as one "environment" block would be the most misleading thing this design could do.

### 8.2 Main benchmark — already landed, plus attestation

[08](08-run-protocol.md) already omits the `tools` key and records `tools_offered: false` as an attested field. This document adds the attestation mechanism: render via `/apply-template`, count via `/tokenize`, predict `usage.prompt_tokens`, compare. Measured: predicted 38, observed 38, delta 0; routed through a 20-line proxy that appended one tool and prepended a system message, observed 169 — **delta +131, detected**. Three caveats that must ship with it: it is forgeable (a hostile proxy lies on `/tokenize` too), so it is a middlebox/misconfiguration detector at S2, never an anti-gaming control; `/tokenize` exists on llama.cpp and vLLM but **not** Ollama or LM Studio, so `tools_attested: false` is a real state; and it is **untested under `stream: true`**, which the harness will almost certainly use (§12.6).

Tool schemas are also pure prompt tax and scale linearly — measured `prompt_tokens` by tool count: 0→38, 1→203, 2→291, 4→467, 8→819, 16→1535, 32→2975. First tool ~165 tokens (including a ~77-token `# Tools` preamble), each additional ~88. **At 32 tools the schemas alone consumed 73% of a 4096-token context**, competing directly with the 19.5pp context effect. Any tools-enabled track needs its own context floor with the tool budget subtracted.

### 8.3 Why MCP does not belong in the main benchmark at all

The largest measured Rust tool effect is **compiler-in-the-loop**: RustAssistant iterating an LLM against rustc reaches ~74% (2023 models) to 93% (2024 models) on real compilation errors, where `cargo fix` fixes under 10%. **`repair` mode already is that**, delivered with zero tool-calling machinery — and it is [08](08-run-protocol.md)'s default. Exposing `cargo_check` as a callable tool buys marginal capability over that while importing every confound in §8.4, and the direct measurement shows `cargo_check` is *precisely* the tool a 3B model reaches for **instead of writing code**.

The second-highest-leverage Rust tool is docs lookup — RustEvo² measured a **23.6pp knowledge-cutoff gap** (56.1% before-cutoff vs 32.5% after, across 588 API changes) with RAG recovering 13.5% — and it needs network, which the sandbox denies. **Corollary the main benchmark must absorb anyway:** pre-vendored `.crate` files with `--offline --locked` is *already* a tool-policy decision that suppresses most of this axis, and the vendored version set is a **hidden treatment**. Pin and publish it in `plan.json` alongside `suite_hash`, or a routine suite refresh silently moves every score.

Do **not** design around an LSP benefit. The often-cited 19–25% compilation-rate figure is Monitor-Guided Decoding on **Java**, and it is logit-level constrained decoding that no OpenAI-compatible endpoint exposes. Several rust-analyzer MCP servers exist with zero published evaluation. That is a genuine research gap and a better use of the agentic track than chasing MCP breadth.

### 8.4 Agentic track policy, and the sandbox correction

- **Harness owns the tool list.** Record the exact list, not a count and not a server name: MCP-Universe cut Claude-4.0-Sonnet's Location Navigation success **22.22% → 11.11%** by expanding to 7 servers / 94 tools. More tools is not more capability.
- **User-supplied MCP: Open-division only, never ranked, never replayed, descriptions captured verbatim and published** (which means they cannot also be private). Reproducibility is impossible in principle (§3.4), and tool descriptions are an unsanitised attacker-controlled channel — MCPTox measured a mean **36.5% tool-poisoning attack success rate** across 45 live servers × 20 LLMs (max 72.8%) against a harness that then **compiles and runs the model's Rust**.
- **Admission gate:** `chat_template_caps.supports_tools` / Ollama `capabilities`. A server whose template cannot render tools fails every tool-using task silently, and that is currently indistinguishable from model incapability. Also record whether the backend used a native or **generic** tool format — llama.cpp logs `Chat format: Generic` for unrecognised templates and its docs note generic support "may consume more tokens". Both local templates prepend the `# Tools` section **to the system message**, so declaring tools *rewrites the pinned system prompt*; the tools-declared probe vector must be captured separately.

**Correction to the sandbox claim, which all three proposals stated as a mechanism fact and which is false.** The original `curl 127.0.0.1:8080 → exit 7` measurement was taken after the local server had crashed; exit 7 is "could not connect", identical to nothing listening. Re-run against a live listener:

```
baseline, no sandbox                                          → 200
(version 1)(allow default)(deny network*)                     → 000, exit 7    ← deny works
(deny network-outbound)(allow network-outbound (remote ip "localhost:*")) → 200 ← loopback restorable
```

So "network-backed tools are categorically incompatible with the sandbox" is **wrong**: loopback-permitting/external-denying is one line of seatbelt, and a Linux network namespace with `lo` up gives the same for free. It is a **threat-model choice** (a local proxy can egress), not a mechanism. The correct statement for [08](08-run-protocol.md) §Network policy: *external network is denied by policy and enforced by the OS; loopback is deniable by default and selectively restorable; a loopback allowance admits a local-proxy egress path and is therefore not granted for grading, only for the model call.*

**And the boundary bug is on the main path, not the agentic one.** [08](08-run-protocol.md)'s per-unit sequence is:

```
3. enter sandbox
4. render prompt, send to backend, capture response
5. exit sandbox
```

Step 4 is a loopback HTTP call inside a region that denies loopback. This is broken today for `single-shot` and `repair`, not conditionally in a track that does not exist. **Fix:** the model call moves outside the sandboxed region (steps become: render → call → enter sandbox → grade → exit), or the generation region uses the loopback-restoring profile above while the *grading* region keeps `deny network*` unchanged. The second preserves `reason = "network_attempt"` where it matters — grading is where model-generated code runs.

---

## 9. Onboarding — the actual commands

### 9.1 Three attach modes, decreasing evidence

`rustybench` never manages a server the user did not ask it to manage. But **managed mode is offered and recommended**, because it is the *only* route that promotes `ngl`, `kv_cache_type`, `threads`, `flash_attn` and `rope` from S4 (§5.2) to host-verified — that is the entire unobservable bucket, recovered for the cost of one flag. The three modes are `managed`, `attached-colocated` (user's server, harness can read the weights file), `attached-remote` (base URL only). The mode is a **published column**.

### 9.2 `rustybench doctor` — the most important command in the product

Every failure mode in this document is **silent**: Ollama truncates rather than erroring, llama.cpp applies temperature 0.8 and four slots by default, `tool_choice:"none"` still renders schemas, a reasoning template returns empty content under a low budget. `doctor` is read-only, mutates nothing, and takes ~90 s.

```
rustybench doctor --endpoint http://localhost:8080/v1 [--weights ~/models/x.gguf]
```

Probe order — each cheap, each turning an assumption into a recorded fact:

| # | Probe | Mechanism | Gates |
|---|---|---|---|
| 1 | introspection sweep | `/v1/models`, `/props`; `/api/tags`+`/api/show`+`/api/ps`; `/api/v0/models`; `/info` | `introspection` level, row tier |
| 2 | **context, per category** | binary-search prompt length until 4xx **or** `usage.prompt_tokens` stops tracking input | category admission (§2.4) |
| 3 | template | 3-probe vector + exact sha where exposed | ranking eligibility |
| 4 | sampler assertion | send all 13 fields; 4xx ⇒ `sampler_pin_level = core_only`; also record server defaults | row annotation |
| 5 | concurrency | `/slots.total_slots`, else 4 concurrent identical requests | gate |
| 6 | determinism | same request ×5 sequential, ×4 concurrent | records `batch_invariance` regime |
| 7 | cache | identical prompt twice; then `cache_prompt:false`; record `cached_tokens` availability | throughput scoring |
| 8 | reasoning | `/apply-template` tail, or non-empty `reasoning_content` | `max_tokens` selection |
| 9 | weights | geometry block; `llama-gguf-hash --uuid` if readable | `identity_tier` |
| 10 | tools attestation | predicted vs observed `prompt_tokens` | `tools_attested` |
| 11 | co-tenancy (narrow) | other inference servers / processes mapping the weights | throughput only |

Output, common case:

```
  mode         attached-colocated          introspection: full
  backend      llama.cpp b10470-34af94cd9  (version recorded, NOT in row key)
  weights      qwen3-coder-30b-a3b Q4_K_M  identity: W3 (file hashed)  geometry: consistent
  context      32768 effective (probed)    overflow: loud_fail
               categories ok: 5 core       skipped: cross-module (needs ~90k)  → skipped_context
  template     sha256 55b2f4a2…  probe (30,15,42)   hidden system prompt: no
  reasoning    off                         max_tokens 32768
  determinism  5/5 sequential · 4/4 concurrent      cache: defeatable, verified
  co-tenancy   none

  Division: PINNED.  Estimated 44.5 h for `deep` (5 of 6 categories).
```

Output when a gate fires — the only time the harness asks for anything:

```
  context      4096 effective (probed)   overflow: SILENT_TRUNCATE      GATE

  Every category needs more than this. Your server truncates above 4096 with no error:
  prompts would be cut and the model scored on a task it never saw. The measured cost of
  exactly this misconfiguration on identical weights is 19.5 points (Aider, n=133, p=0.001).

    Ollama:     OLLAMA_CONTEXT_LENGTH=32768 ollama serve
    llama.cpp:  llama-server -m <model> -c 32768 --parallel 1
    vLLM:       --max-model-len 32768

  Re-run `rustybench doctor` after restarting — or submit to OPEN right now:
    rustybench run --suite standard --division open --endpoint http://localhost:8080/v1
```

Converting a 19.5-point silent loss into a copy-paste is worth more than any statistical control in this design.

### 9.3 Run commands, per division

```bash
# PINNED — managed: highest evidence, harness writes the launch line and knows it
rustybench run --suite deep --division pinned \
  --serve ~/models/qwen3-coder-30b-a3b-Q4_K_M.gguf --epoch 2026-08

# PINNED — attached, colocated: the normal local-LLM case
rustybench run --suite deep --division pinned \
  --endpoint http://localhost:8080/v1 \
  --weights ~/models/qwen3-coder-30b-a3b-Q4_K_M.gguf --epoch 2026-08

# PINNED — attached, remote: base URL only; eligible, weights_evidence = W0/W1
rustybench run --suite deep --division pinned --endpoint http://192.168.1.40:8000/v1

# TUNED — requires a completed Pinned pass in the same session; A/B/A interleaved,
#         runs the timing subsample + the ab seed set, not the full suite
rustybench run --suite deep --division tuned --serve <gguf> \
  --tuned-args "-fa on -t 8 -ctk q8_0 --draft-model <gguf> --parallel 4"

# OPEN — always accepted, T0, unranked. Never a bounce.
rustybench run --suite standard --division open --endpoint <url>

# AGENTIC — separate board; agent and toolset are row-key components
rustybench run --suite agentic --division agentic --agent terminus-min --endpoint <url>
```

Two supporting commands:

```bash
# The instrument this whole document rests on: paired oracle-verdict flips over a fixed
# seed subset with exactly ONE factor varied. Reports flip rate + signed delta + paired CI.
rustybench ab --factor backend   --alt-endpoint http://localhost:11434/v1 --seeds ab-2026-08
rustybench ab --factor exec-class --alt-args "-ngl 0"
rustybench ab --factor quant     --alt-weights <gguf>
rustybench ab --factor spec-decode --alt-args "--draft-model <gguf>"   # one-unit byte check

# Local KL/top-1 audit against a saved baseline. Measured cost: 22 s + 2.9 GB for a
# 20,480-token baseline; 30–90 s per GPU variant; the full 9-config sweep across two
# models ran in under 40 minutes. Gate on TOP-1 AGREEMENT, not perplexity — PPL ratio
# stayed under 1.005 for configurations that flipped 5–6% of tokens.
rustybench config-audit --weights <gguf> --knobs kv,ngl,rope,fa,threads
```

`rustybench ab --factor backend` is the community instrument in §10.3. **Design detail that must not be missed:** the same GGUF under llama.cpp and under Ollama may carry *different templates* (Ollama's registry ships the template as a separate content-addressed blob), so the backend A/B must build the Ollama side with `ollama create` from the same GGUF and **assert template-sha equality**, or δ confounds backend with template.

### 9.4 Friction, per backend, worst case

| Backend | Changes required to run | Optional upgrade |
|---|---|---|
| llama.cpp | `--parallel 1` (default is now 4) | none — everything readable by default |
| LM Studio | none | none; `/v1` may lack the `stats` object (§12.6) |
| vLLM | none | `--enable-per-request-metrics --enable-prompt-tokens-details` upgrades the throughput tier. Without them, differencing the `/metrics` histogram `_sum`/`_count` around each serialised request recovers exact per-request prefill/decode plus `prefix_cache_hits_total` — valid only at concurrency 1, which is gated anyway. **Assert `vllm:num_requests_running == 0` before and after each unit.** |
| Ollama | context, more often than others (silent truncation) | none available: its OpenAI `Usage` struct has three fields and no `cached_tokens`; `Model` has four and no digest; `system_fingerprint` is the constant `"fp_ollama"`. **Native probe (`/api/tags`, `/api/ps`, `/api/show`) is mandatory, so "just take a base URL" is already dead as a contract** — this should be stated as a design property rather than discovered in triage. |
| KoboldCpp / LocalAI | none | none. `introspection: none`, Open only. Probe `/api/extra/true_max_context_length` specifically — the horde-facing value KoboldCpp otherwise reports is deliberately not the real one. |

Offline path is preserved: `doctor`, `run` and `ab` require no network and are capped at T0/T1 exactly as [10](10-integrity.md) already specifies.

---

## 10. The leaderboard row and the comparability rules

### 10.1 Row key — deliberately coarse, discrete, and small

```
suite_version · prompt_pack_hash · sampling_profile_id · division
  · weights_id(name + quant_class) · template_fingerprint · reasoning_mode
  · exec_class · categories_scored
```

**Deliberately excluded:** `backend_version` (62 releases in 7 days ⇒ singleton cells), `offload_ratio` (continuous ⇒ never matches; 0.74 and 0.75 would be different experiments), any hardware field, `profile_hash` in full (it changes on a probe re-run).

**Comparison scope** is a separate, wider predicate: two rows may be *compared* when their keys match, and the comparison is *conditioned* on `backend_family` and, for throughput, on `memory_arch`.

The distinction matters because the critique's framing needs one correction: putting a field in the key does not destroy the *item* pairing — every model in an epoch runs the identical core seed set ([ADR-0009](adr/0009-paired-core-and-fresh-probe-seeds.md)), so McNemar pairing over items is intact regardless. What a high-cardinality key destroys is **comparability density**, which is HELM's measured contribution (core-scenario coverage raised from 17.9% to 96.0%): a sparse matrix of beautifully-annotated incomparable rows has near-zero information value however honest each row is.

### 10.2 Displayed columns, grouped by the §5 buckets

| Bucket | Columns |
|---|---|
| **Verifiable** (T1 replay re-derives) | `capability_score` + CI, per-category vector + per-category CIs, rustc error-code histogram, `compile_rate`, `apply_rate`, `well_formed_rate`, `first_try_score`, `categories_scored`, `suite_version`, `generator_commit`, trust tier |
| **Self-reported S1–S3** (endpoint-read; honest-misconfiguration detection only) | backend + version, `effective_ctx` + source + `overflow_mode`, template fingerprint + source, `reasoning_mode`, `cache_hit_ratio`, `weights.identity_tier`, `concurrency`, `attach_mode`, `introspection` |
| **Self-reported S4** (same badge as hardware) | `exec_class` + source, `offload_ratio`, `memory_arch`, `kv_cache_type`, `flash_attn`, `threads`, `batch`/`ubatch`, `rope`, speculative config, GPU/CPU class, power |
| **Integrity** | trust tier T0–T3, completeness, taint flags, `budget_exhausted_rate`, `nondeterministic_repeat` count, and a **Hacks/Flags column** — Terminal-Bench's precedent for surfacing integrity findings *on the row* rather than suppressing them |

Two columns the current design lacks and needs: `apply_rate` / `well_formed_rate` (§5.4) and `budget_exhausted_rate` (§5.4).

Aggregation must be fixed and documented: **`capability_score` macro-averages across categories with equal weight**, per [07](07-statistics.md)'s corrected estimator. R5-S7 already found three documents giving three different per-category CIs, and micro-vs-macro on MMLU's 57 subjects is documented to move results by several percentage points.

### 10.3 The backend rule — conditioned, with a stated release criterion

The evidence for freeing the backend is void (§2.1b); the evidence for pinning it is equally absent, and pinning would exclude vLLM and Ollama users while privileging one project. So:

- **Default ranked view compares within `backend_family`.** llama.cpp, Ollama and LM Studio all descend from llama.cpp, so this is a low-cardinality, heavily-concentrated split and the density cost is small.
- **Cross-backend comparisons are shown, marked `cross-backend`, and carry an added ±δ band** rather than being suppressed.
- **δ is measured by `rustybench ab --factor backend`** — same machine, same weights file, same seed set, sampling pinned, concurrency 1, cache off, template-sha equality asserted — and estimated by **pooling within-machine paired contrasts across submitters with machine fixed effects**. Each submitter's contribution is a `standard`-suite A/B (416 scored units).

**The power arithmetic that all three proposals skipped.** For a paired (McNemar) contrast, 95% half-width ≈ 1.96·√(d/n) where *d* is the discordant-pair rate:

| n (paired units) | d = 0.05 | d = 0.10 | d = 0.20 |
|---|---|---|---|
| 416 (`standard`) | ±2.16pp | ±3.05pp | ±4.32pp |
| 1088 (`deep`) | ±1.33pp | **±1.88pp** | ±2.66pp |
| 4000 | ±0.69pp | ±0.98pp | ±1.39pp |

Clustering makes this worse (effective N 573 at `deep` ⇒ ±2.59pp at d = 0.10). **One `deep` A/B pair cannot free the backend.** Reaching ±1.0pp at d = 0.10 needs ~3,842 paired units — about 3.5 `deep` passes per arm, ~160 h per arm. That is not a Phase 3.5 experiment; it is a **community measurement**, and ten submitters running a `standard` A/B (4,160 units) reach ±0.96pp. The leaderboard corpus therefore *is* the instrument, at zero marginal cost, provided backend is recorded and the core seed set is shared.

**Release criterion, stated now so it cannot be argued later:**

| Pooled |δ| 95% upper bound | Rule |
|---|---|---|
| ≤ 1.0pp | backend leaves the comparison scope entirely; cross-backend rows rank together, recorded only |
| 1.0 – 3.0pp | current rule stands: within-backend default, cross-backend marked and ±δ-widened |
| > 3.0pp | backend enters the **row key** permanently, and the Pinned division names a single backend family for the ranked table |

Thresholds are derived from the false-positive simulation (a fixed offset *b* inflates type-I error against two identical models: at ρ = 0.25, *b* = 2.0pp gives ~9% FPR and *b* = 4.5pp gives ~27%, against ~31% power at a true 5pp gap). They must be recomputed once ρ ([Q22](OPEN-QUESTIONS.md)) is known, because the FPR inflation depends on ρ.

### 10.4 Sequencing

**The pin/free decision is downstream of ρ and this document says so.** If ρ ≥ 0.5, seed-level pairing buys under 7pp over family-level pairing, fresh per-submitter seeds become viable, and the fragmentation cost of any row key largely evaporates — which changes the answer here. **Nothing in §10.1–10.3 is frozen until [Q22](OPEN-QUESTIONS.md) returns.** The divisions, the gates and the pinned request body are not contingent on ρ and ship immediately; the *comparability rules* are provisional and versioned with the epoch.

---

## 11. Honest costs, and what this gives up

**11.1 The Pinned division handicaps the models it most wants to measure.** Qwen3's card forbids greedy decoding; DeepSeek-R1's forbids a system prompt. Pinned does both. The Codex temperature sweep found 0.2 optimal for pass@1 (0.8 for pass@100), so temperature 0 is a real, citable **~0–2 point handicap accepted for reproducibility and cheap server-side replay, not because it maximises score** — and the docs must say so before a reviewer finds it. There is no gentle gradient to exploit: 5 seeds at temp 0.0 gave 1 unique output; temp 0.1, 0.2, 0.4 and 0.8 all gave 5/5 distinct. Mitigation: add a temp-0.2 single-sample arm to the existing `--pass-k 5 --temp 0.8` variance probe so the handicap is measured rather than assumed.

**11.2 Pinning is unenforceable, and no amount of it buys anti-gaming.** Nothing exposes `ngl`, KV type, flash attention, batch or threads (§2.4), and a 30-line server with zero weights replays `/props` byte-identically. The pinned set is a request to the honest majority; **T1 replay is the only control that touches the dishonest minority.** Conflating them would repeat exactly the R5-S5 failure — a control that reads as security and is not.

**11.3 Keying `exec_class` fragments the audience [06](06-execution-classes.md) exists to serve, and the direction of the effect is unknown.** 7/7 byte-different and one verdict flip prove `GpuFull` and `CpuOnly` are different samples; they do **not** prove `CpuOnly` is worse. It could be symmetric noise. This design fails safe by refusing to merge them, which needlessly splits the 8–16 GB partial-offload band if the divergence turns out symmetric. That is a measurable, unmeasured cost (§12.4).

**11.4 `tuning_gain` has a submitter-controlled denominator.** Nothing pins the *free-bucket* settings of the Pinned pass, and threads alone spans 3.75×. A submitter can hobble their own baseline and publish a 3× gain. A/B/A interleaving on the same machine and session controls for the machine, not for this. Mitigation: publish `tuning_gain` with the Pinned pass's free-bucket settings displayed beside it, and never present it as a hardware figure of merit.

**11.5 Nine new fields against a project whose documented failure mode is documentation drift.** R5-S7 found six documents quoting stale suite figures, three giving three different per-category CIs, and [ADR-0009](adr/0009-paired-core-and-fresh-probe-seeds.md) still containing a superseded formula. **Structural mitigation, not a promise to be careful:** every new field lives in one `model-profile.toml` whose hash is a row-key component, so a drifted field mechanically produces a different row key rather than a silently wrong comparison.

**11.6 `doctor` costs ~90 s and ~20 requests before any scoring.** Trivial against a 44.5 h run; not trivial for the first impression, which is when a user decides whether to bother. Mitigation: print findings incrementally, and end the common case with "Nothing to change."

**11.7 This design does not attempt option (b), and says why out loud.** Bench360 — the closest methodological neighbour that exists — **deliberately excluded llama.cpp and Ollama** from its controlled cross-engine comparison because their formats and hardware-specific optimisations "hinder controlled comparison", and scoped its engine-level questions to throughput and energy only, never quality. A published paper judged full standardisation unachievable for exactly the backends this project names. Bench360's own rule (pin decoding, then engine affects only system metrics) is the split proposed here, arrived at independently.

**11.8 What this does not touch.** Precomputation (R5-S2), seed secrecy, ρ (Q22), the shape-count ceiling (R5-S3), the mining pipeline (R5-S4), authentication (Q23). It is orthogonal to all of them. It **does** retire [Q27](OPEN-QUESTIONS.md) outright (§2.2, `cache_prompt:false` + `cached_tokens` verification + `/metrics` differencing on vLLM, with MLPerf's principled line: within-request KV cache is legitimate because it is part of what the model *is*; cross-request prefix reuse is not, because it is a property of request history) and answers [Q5](OPEN-QUESTIONS.md) (quantisation is a two-class row-key field, not a pinned value and not merged).

### 11.9 Edits this document forces elsewhere

| Document | Edit |
|---|---|
| [ADR-0005](adr/0005-execution-classes-not-gpu-only.md) | **Stale.** Still says *"`capability_score` compares across all classes, because correctness does not care where the layers ran"*, which [06](06-execution-classes.md) has already withdrawn. Amend with a reversal note; do not edit history. |
| [06](06-execution-classes.md) | *"Derived from the backend's reported layer split, not self-declared. For llama.cpp: `ngl` vs total layers"* is **false** and, combined with *"`Unknown` is not leaderboard-eligible"*, bans llama.cpp by accident. Replace with the three-source rule in §2.4. |
| [06](06-execution-classes.md) | "Backend metadata to capture" block replaced by §2.2 + §4; `backend_version` moved out of the row key. |
| [08](08-run-protocol.md) | Per-unit steps 3–5 put the model call inside a loopback-denying sandbox on the **main** path. Restructure per §8.4. |
| [08](08-run-protocol.md) | Network policy: replace "categorically incompatible" with the measured loopback-restorable profile and the local-proxy residual. |
| [08](08-run-protocol.md) | Sampling record `{temp, top_p, top_k, seed, …}` covers 4 of 9 active samplers; extend to the full chain (§4). |
| [08](08-run-protocol.md) | "Flag any nondeterministic repeat" is near-useless as stated (§2.1a). Scope it to *verdict* changes, not byte changes. |
| [02](02-task-format.md) | `budget_tokens = 16000` → 32768 for reasoning-detected rows. Keep "overrun is a scored failure"; add `finish_reason` capture and the `budget_exhausted_rate` column (§5.4). |
| [03](03-oracle.md) | L1 apply layer must strip `<think>…</think>` when `reasoning_format = none`; `apply_rate` promoted from a weight-0.0 gate to a published column. |
| [04](04-categories.md) | Context gate is per-category; `min_effective_ctx` declared per category; `skipped_context` semantics tied to the denominator rule (§2.4). Closes the leaning in [Q12](OPEN-QUESTIONS.md). |
| [12](12-schemas.md) | New per-unit fields (§5.4); `identity` block gains `division`, `profile_hash`, `template_fingerprint`, `tools_offered`, `categories_scored`. |
| [11](11-submission-and-privacy.md) | Redaction list must enumerate `model_path`, Ollama `modelfile`, the chat-template body, and `base_url`. |

---

## 12. Open questions, each with the measurement that closes it

**12.1 — What is the cross-backend offset δ for *this* configuration?** *(highest value; the central claim of §3.1 rests on it)*
Nobody has published the spread for: same weights, same prompt, executable oracle, sampling pinned, backend free. The Aider 4.5pp proxy is void (§2.1b) and used a different scaffold and oracle. **Measurement:** `rustybench ab --factor backend` on one machine, same GGUF, template-sha asserted equal, `standard` suite both arms; then pool across submitters with machine fixed effects. **Closes when** the pooled 95% upper bound on |δ| crosses one of the §10.3 thresholds. **Note the power result:** one `deep` pair gives ±1.9pp (d = 0.10), which is *not* enough to free the backend — this is a multi-submitter measurement by construction, and that is a feature, because it makes the leaderboard its own instrument.

**12.2 — Does a logprob fingerprint separate two *quantisations* of the same weights?** *(gates W4)*
Untested; the only case that matters. Distinguishing different *models* is trivial. Adjacent measurement is discouraging: KV quantisation shifts logprobs by ≤0.020 while leaving rank order invariant, and offload shifts them by **0.853** with signal 4/8 vs noise 2/8 at n = 8. **Measurement:** one fp16 GGUF + local `llama-quantize` to Q4_K_M/Q8_0; ≥20 model pairs; report probe count, decision rule, and measured FP/FN rates; select probes for low cross-exec-class variance (positions where the rank-1 margin exceeds ~2 nats). **Closes when** FP ≤ 1% at FN ≤ 10% over ≥20 pairs. Until then W4 ships as `not_yet_a_gate`.

**12.3 — What does a *wrong template* cost on a coding benchmark?** *(the biggest evidence gap behind §7)*
Every strong template number is instruction-following. **Measurement, in-house, cheap:** the same GGUF twice under llama.cpp with `--jinja` versus `--chat-template chatml`, ~50 Rust tasks, report the paired verdict-flip rate and signed delta. This experiment does not exist publicly.

**12.4 — Is execution-class divergence symmetric noise or a systematic penalty?** *(decides whether Hybrid/CpuOnly can ever be ranked, §11.3)*
94–98% top-1 agreement guarantees different text; it says nothing about worse. **Measurement:** `rustybench ab --factor exec-class` — the same instrument as ρ, run over `exec_class` instead of over models, so it composes with [Q22](OPEN-QUESTIONS.md) for one extra pass.

**12.5 — Does the pinned system prompt distort the oracle's other four layers?** *(blocks freezing `rb-sys/1`)*
A format-strict prompt cut output 5.8×. If it also suppresses doc comments or error handling it depresses the L2 constraint layer (weight 0.2) and the L3 quality layer (weight 0.1) while inflating L1. **Measurement:** run the candidate prompt against all five layers on a ≥100-unit subset and compare the per-layer score vector to a neutral prompt. Validated today only for extractability.

**12.6 — Is `usage` reliably populated under `stream: true`?** *(gates three mechanisms at once)*
The harness will stream. Several backends omit or approximate `usage` in that mode, which would break the tools attestation, the cache assertion and the context probe simultaneously. **Measurement:** 30 minutes per backend.

**12.7 — Per-backend surface confirmation.** Every llama.cpp finding is measured on b10470 / Apple M5 / macOS 26.5; every vLLM, Ollama, LM Studio, TGI, KoboldCpp and LocalAI claim is read from source or docs. Specifically unresolved and load-bearing: whether Ollama's `/api/ps.context_length` reports the *loaded instance* or the model maximum (reading the maximum would silently defeat the context gate on the backend where it matters most); `size_vram` semantics under partial offload; whether vLLM's flag-gating behaves at runtime as `main` reads; whether LM Studio's `/v1` carries the `stats` object or only `/api/v0` (this single fact decides whether LM Studio needs a backend-specific code path); the byte-canonicalisation for comparing an `registry.ollama.ai` manifest to a reported digest (gates W2). **Measurement:** ~30 minutes per backend on a Linux/GPU host.

**12.8 — Speculative decoding output-preservation on this project's hardware.** Largest unverified free-bucket knob (1.5–3×, and can be *negative*: 0.33–0.52× on quantised Metal). **Measurement:** one hour — same prompt, temp 0, with and without a draft model, compare hashes; separately assess `--spec-type draft-mtp`. Default stays OFF for Pinned until then.

**12.9 — The GGUF k-quant × code-generation cell is empty in the literature.** Every published quant-vs-coding result uses GPTQ/AWQ/bitsandbytes; every published GGUF k-quant ladder measures GSM8K/MMLU and explicitly no HumanEval/MBPP. This project's audience runs Q4_K_M GGUF. **Measurement:** one fp16 GGUF + local `llama-quantize`, `rustybench ab --factor quant` across Q4_K_M/Q5_K_M/Q6_K/Q8_0/fp16. It is simultaneously a ρ estimate (the per-item flip rate between two quants of the same model *is* ρ for a minimally-different model pair; published MMLU flip rates run 3.3–13.6% against near-zero accuracy change) and a real publishable contribution.

**12.10 — Co-tenancy false-positive rate on real machines.** The effect is real (26.6×) and the broad detector is unusable (§2.3). **Measurement:** log narrow-form detections (with consent) across the first 100 submissions; promote to a hard flag only if FP < 5%.

**12.11 — Do pre-vendored crates neutralise API-recency effects, or freeze a hidden treatment?** RustEvo² measured a 23.6pp before/after-cutoff gap. **Measurement:** run the same suite against two vendor sets a year apart. Regardless of outcome, pin and publish the vendored set in `plan.json` alongside `suite_hash`.

**12.12 — Participation cost of the gates.** No evidence exists either way. MLPerf's 3.9:1 Closed:Open ratio is about corporate submitters and says nothing about a hobbyist with a tuned llama.cpp build. This is a product question, not a measurement question. **Instrument it:** log `doctor` outcomes with consent, learn which gate loses the most users, and be prepared to demote a gate to a row-key field if it costs more participation than the confound it removes.

**12.13 — `macOS sandbox-exec` deprecation status.** The whole `deny network*` control on macOS rests on it. It works today on 26.5.1 (§8.4). Unchecked against Apple's deprecation notices.

**12.14 — Field-by-field redaction list for the new fields.** R5-S6 already found the T1 bundle contradicting the consent screen, and R5's `redaction-is-a-denylist` finding applies to everything added here. **Shipping blocker**, not an open question: enumerate before the first submission, not after.

---
