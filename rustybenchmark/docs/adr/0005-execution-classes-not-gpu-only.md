# ADR-0005 — Classify execution mode; do not restrict to GPU

**Status:** Accepted · 2026-08-17

## Context

A GPU-only restriction is attractive: VRAM is a clean, single number, and it removes a whole axis of variability from the leaderboard.

Three facts argue against it.

1. **Partial offload is the normal consumer configuration.** An 8 GB laptop GPU running a 19 GB Q4 model splits layers between GPU and CPU. That is not "CPU inference" — it is the majority setup in the 8–16 GB band this project explicitly targets. A GPU-only rule either excludes those machines or forces them onto models small enough for full offload, which biases the leaderboard toward small models.
2. **MoE changed the CPU maths.** Qwen3-Coder-30B-A3B is 30B total with ~3.3B active. Sparse-active models are far more viable on CPU than dense models of the same nominal size.
3. **Support cost is near zero.** The harness speaks OpenAI-compatible HTTP and does not know where layers live. The only work is reporting, and llama.cpp already exposes the split.

Also: VRAM alone was already the wrong field. Apple unified memory does not fit it.

## Options

1. **GPU-only, full offload required.** Clean, excludes much of the target audience.
2. **Accept everything, one leaderboard.** Meaningless timing comparisons.
3. **Accept everything, classify it, scope the timing metrics.**

## Decision

**Option 3.**

```rust
enum ExecClass { GpuFull, Hybrid, CpuOnly }
```

Derived from the backend's reported layer split, never self-declared. Memory reported as three fields rather than one: `peak_accel_mem_mb`, `peak_host_rss_mb`, `offload_ratio`, plus `kv_cache_location` and a derived `mem_bandwidth_class`.

Leaderboard policy: `GpuFull` is the default view; `Hybrid` and `CpuOnly` are tagged and shown behind a toggle. **Timing metrics compare only within a class. `capability_score` compares across all classes**, because correctness does not care where the layers ran.

## Consequences

**Good**

- The 8 GB laptop case — explicitly a target, and demonstrably capable of a full 225-problem Aider Polyglot run offline — is representable.
- The memory model is cleaner than VRAM-only even for pure GPU runs, and works for Apple unified memory.
- `mem_bandwidth_class`, derived from calibrated `tg128`, is the actual predictor of generation speed regardless of where memory physically lives.
- Zero additional harness complexity; one extra field.

**Bad**

- Three leaderboard views instead of one. Mitigated by making `GpuFull` the default and the others explicit toggles.
- `perf-optimization` (category 7) genuinely cannot be measured reliably on a thermally unstable, contended CPU. That category is gated to `GpuFull` on AC power with a <5% timing-stability precheck; failing the precheck marks the run `perf_unavailable` rather than scoring the model badly for the user's thermal situation.

## Implementation note

Build `GpuFull` end to end first. `Hybrid` and `CpuOnly` fall out for free the moment `offload_ratio` is recorded — which should happen from day one whether or not those submissions are accepted. One field now avoids a schema migration later.


---

> **Amended 2026-08-18.** This ADR's consequence *"`capability_score` is comparable across all
> classes. Correctness does not care where the layers ran"* has been **withdrawn as empirically
> false**. Measured: 7/7 Rust prompts byte-different at `-ngl 0` vs `-ngl 99` under greedy decoding
> with a fixed seed, top-1 token agreement 94.4% at `-ngl 0`, and one oracle-verdict flip (the GPU
> answer compiled; the CPU answer returned a `&[u8]` slice as `&[u32]`). `exec_class` is part of the
> row identity, like quantisation. The decision to *classify rather than ban* still stands and is
> unaffected. See [15-profiles-and-divisions.md](../15-profiles-and-divisions.md) and
> [ADR-0010](0010-pinned-tuned-open-divisions.md).
