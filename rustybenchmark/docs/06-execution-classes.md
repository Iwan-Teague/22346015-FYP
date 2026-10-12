# 06 — Execution classes and memory accounting

## The problem with "GPU only"

A strict GPU-only rule sounds like it simplifies memory measurement. It does not, and it excludes the machines this project exists to serve.

**Partial offload is the normal consumer configuration.** An 8 GB laptop GPU running a 19 GB Q4 model puts some layers on the GPU and the rest on the CPU. That is not "CPU inference" — it is the majority setup in the 8–16 GB band. A GPU-only rule either excludes those machines entirely or forces them onto models small enough for full offload, which quietly biases the whole leaderboard toward tiny models.

**MoE changed the CPU maths.** Qwen3-Coder-30B-A3B is 30B total with ~3.3B active parameters. Sparse-active models are far more viable on CPU than dense models of the same nominal size, so "CPU inference is pointless" is materially less true than it was.

**Support cost is near zero.** The harness speaks OpenAI-compatible HTTP; it does not know or care where the layers live. The only work is *reporting*, and llama.cpp already exposes the offload split.

Decision recorded in [ADR-0005](adr/0005-execution-classes-not-gpu-only.md): **classify, do not ban.**

## Classes

```rust
pub enum ExecClass {
    /// 100% of layers offloaded, KV cache on accelerator.
    GpuFull,
    /// Partial offload. offload_ratio in (0.0, 1.0).
    Hybrid,
    /// Zero layers offloaded.
    CpuOnly,
}
```

**Three sources, ranked** — the earlier rule said "derived from the backend's reported layer split…
For llama.cpp: `ngl` vs total layers", which is **false and bans llama.cpp by accident**. Measured: a
`llama-server` launched with `-ngl 99 -fa on -ctk q8_0 -ctv q8_0 -ub 256 -b 1024 -t 6` exposes none of
it — grepping the full `/props` body for `flash|cache_type|type_k|n_batch|n_ubatch|n_threads|n_gpu_layers|ngl|rope|yarn|offload`
returns **zero hits**; `/slots` returns only `{id, n_ctx, speculative, is_processing}`; `/metrics` is
501 without `--metrics`. Taken literally, every llama.cpp row was `Unknown` and therefore ineligible.

| Source | How | Backends |
|---|---|---|
| `observed` | Read over HTTP | **Ollama only** — `/api/ps` gives `size` vs `size_vram` (offload ratio directly) and `context_length` |
| `host` | Harness colocated with the server: launch args, accelerator memory attribution | Managed mode |
| `declared` | Submitter states it | Everything else |

`Unknown` now means **no source at all**, not "not machine-readable". A `declared` exec class is
leaderboard-eligible at the self-reported tier, alongside hardware.

## Memory accounting

Two numbers plus a ratio, replacing the single "VRAM" field. This is cleaner even for pure-GPU runs, because Apple unified memory does not fit a VRAM-shaped field at all.

```rust
pub struct MemProfile {
    pub peak_accel_mem_mb: u64,   // VRAM, or unified-memory attribution on Apple
    pub peak_host_rss_mb:  u64,   // system RAM
    pub offload_ratio:     f32,   // ngl_layers / total_layers, 0.0 ..= 1.0
    pub kv_cache_location: KvLoc, // Accel | Host | Split
    pub mem_bandwidth_class: BwClass, // derived from calibrated tg128
}
```

`mem_bandwidth_class` is the real predictor of generation speed regardless of where the memory physically lives, which is why it is derived and recorded rather than inferred by readers from the GPU model name.

## Leaderboard policy

- **`GpuFull` is the default view.** Cleanest, most comparable, the primary table.
- **`Hybrid` and `CpuOnly` are collected, tagged, and shown behind a toggle.** Never merged into the same ranking.
- **Timing-derived metrics are comparable only within a class.** `throughput_score`, `time_to_first_pass`, `efficiency_score` — all class-scoped.
- **`capability_score` is NOT comparable across execution classes.** This document previously
  asserted the opposite — *"correctness does not care where the layers ran"* — and that is
  **empirically false**, measured directly:

  | Measurement | Result |
  |---|---|
  | Greedy output at `-ngl 0` vs `-ngl 99`, 7 Rust prompts, temp 0, fixed seed | **7/7 byte-different** |
  | Top-1 token agreement vs full offload | `-ngl 18`: 97.8% · `-ngl 0`: **94.4%** |
  | Oracle-verdict flip | On an unsafe-transmute task the GPU answer compiled; the CPU answer returned a `&[u8]` slice as `&[u32]` — **a type error** |

  At a 2–6% per-token flip probability, any generation beyond ~30 tokens diverges with near
  certainty, and Rust solutions run 400–1500 tokens. Two submitters with the same model, quant, seed
  and sampling **will not produce the same code** if one has 24 GB and the other 12 GB. This is a
  pass/fail difference, not a stylistic one.

  **Therefore `exec_class` is part of the row identity, exactly like quantisation** — not a hardware
  tag attached to an otherwise-comparable score. Cross-class comparison of `capability_score` is
  withdrawn; rows carry their class and are compared within it. (`perf-optimization` remains
  additionally gated to `GpuFull`, so the denominator rule in [04](04-categories.md) still applies on
  top of this.)

That last point is worth stating on the leaderboard itself: a `CpuOnly` row with the same `capability_score` as a `GpuFull` row is making the same claim about the model and a very different claim about the machine.

## Implementation order

Build `GpuFull` end to end first. `Hybrid` and `CpuOnly` fall out for free the moment `offload_ratio` is being recorded — which should happen from day one whether or not those submissions are accepted. One field now, no schema migration later.

## Where CPU genuinely hurts

`perf-optimization` (category 7). Criterion ratios against a reference implementation are noisy on a thermally unstable, contended CPU. That category is gated:

- execution class `GpuFull` only
- AC power required
- stability precheck: repeated timing of the reference must vary <5% across repetitions

Failing the precheck skips the category and marks the run `perf_unavailable`. It does not score the model badly for the user's thermal situation.

## Backend metadata to capture

Recorded for every run; displayed on the leaderboard because these are the knobs that make results incomparable if hidden.

```
backend           llama.cpp | ollama | vllm | lmstudio | other
backend_version   e.g. b7412
model_name        canonical
quant             Q4_K_M | Q5_K_M | Q8_0 | fp16 | awq | gptq | ...
ctx               context window actually configured
ngl               layers offloaded
batch / ubatch
flash_attn        on | off
kv_cache_type     f16 | q8_0 | q4_0   <- PINNED to f16 for a ranked row, not merely recorded
threads
rope / yarn settings if non-default
```

Quantisation especially: comparing a Q4_K_M row to a Q8_0 row of the "same model" as though they were the same thing is one of the most common errors in local-model discourse, and the leaderboard should make it impossible to do by accident.

**`kv_cache_type` is promoted from recorded to pinned.** Measured: `-ctk q8_0 -ctv q8_0` versus `f16`
gave byte-different greedy output on **4 of 7** prompts, with divergence appearing as early as the
first line of generated code. It is a capability knob wearing a memory-optimisation label, and a
ranked row must pin it to `f16`.

**`flash_attn` stays free.** Measured output-preserving to within noise — 99.87% top-1 agreement,
perplexity ratio 1.00013, an order of magnitude tighter than any other knob tested. Record it only
because llama.cpp requires it to quantise the V cache, so turning it off silently forces V back to
`f16` and changes the memory accounting above.

**Rope/YaRN scaling is capability-affecting and must be pinned.** Configuring a context *beyond* the
model's native window costs real quality even on short prompts: YaRN at 4× gave +1.93% perplexity and
**91.95%** top-1 agreement, and *linear* rope scaling at 2× was catastrophic — +211% perplexity,
**58.5%** top-1 agreement. By contrast, changing `-c` **within** the native context produced
**bit-identical** greedy completions, so configured context size alone is genuinely free. Two
different rules that the old "(rope / yarn settings if non-default)" parenthetical collapsed into one.
