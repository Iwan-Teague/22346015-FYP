# 05 — Hardware profiling and calibration

Two phases run before any task. Both are mandatory; a run without them is not scorable.

## Phase A — Static inventory

```rust
pub struct HwProfile {
    pub schema:  u32,
    pub cpu:     CpuInfo,      // model, physical/logical cores, base+boost MHz, arch,
                               // features (avx2/avx512/neon/sve)
    pub ram:     RamInfo,      // total, available, type + channels where obtainable
    pub gpus:    Vec<GpuInfo>, // vendor, model, mem_total, mem_free, driver version,
                               // compute units, cuda_cc / rocm_arch / metal_family
    pub os:      OsInfo,       // kernel, version, build
    pub storage: DiskInfo,     // nvme | sata | spinning | unknown, free space on scratch
    pub power:   PowerHint,    // ac | battery, chassis: laptop | desktop | server | unknown
    pub unified_memory: bool,  // Apple Silicon and similar
}
```

### Crates

| Need | Crate | Notes |
|---|---|---|
| CPU, RAM, OS, disk | `sysinfo` | now also exposes GPU info on Linux, macOS, and Windows |
| NVIDIA detail | `nvml-wrapper` | safe wrapper over NVML; `device.memory_info()` for used/total |
| Cross-vendor VRAM | `gpu-probe` | no vendor SDKs required beyond the driver; uses nvml-wrapper for NVIDIA |
| Universal fallback | `wgpu` adapter enumeration | covers Apple Metal, Intel Arc, AMD where nothing else does |

Strategy: try vendor-specific first (most detail), fall back to `gpu-probe`, fall back to `wgpu` adapter info, fall back to `unknown` with a warning. Record which path produced each field — a leaderboard row derived from `wgpu` fallback deserves a different confidence marker than one from NVML.

## Phase B — Inference calibration

Adopt the llama-bench protocol so numbers are comparable to the wider ecosystem.

```
warm-up:     60 s sustained load, results discarded
measure:     pp512   prompt processing, 512 tokens   -> compute-bound throughput
             tg128   token generation, 128 tokens    -> memory-bandwidth-bound latency
             repetitions = 10, report median + p5 + p95
also record: peak accelerator memory, peak host RSS,
             clock at start vs end, wall-clock drift across repetitions
```

`pp512` measures a single forward pass over a 512-token prompt, reported as `(B × 512) / median_time` — big GEMMs and SDPA, compute-bound. `tg128` measures generating 128 tokens one at a time from a KV cache warmed by a short prefill, reported as `(B × 128) / median_time` of the decode loop only — frequent small matmuls and KV traffic, memory-bound. They fail differently and must be reported separately.

### The sustained phase — our addition

Standard tooling stops at the short burst. That hides the fact that matters most for a 44.5-hour benchmark run.

```
sustained:   10 minutes of bench-shaped load
             (2k-token prompts, 1k-token generations, back to back)
record:      tok/s at minute 1 vs minute 10
             clock throttle delta
             any thermal event flags the OS exposes
```

Thermal throttling alone swings llama.cpp results **12–18%** between cold and stabilised runs. Laptops fall off a cliff over ten minutes; desktops mostly do not. That delta is a genuine hardware fact almost nobody publishes, and it is one of the more useful things this project can contribute.

**Warm-up is not optional.** A calibration without it is not comparable to anything.

### Calibration is per-segment, and tiered

A run that spans multiple sessions (see [09-resume-and-checkpointing.md](09-resume-and-checkpointing.md)) recalibrates at the start of every segment. Thermal and power state do not persist across a lid close. Timing metrics aggregate across segments with segment tags, and the run reports inter-segment calibration variance.

But full calibration is ~15 minutes. In the ninety-minute evening slices this project explicitly sells, that is **17% overhead** — roughly 6.5 hours of pure measurement across a 44.5-hour suite. So calibration is tiered:

| Segment | Calibration | Cost |
|---|---|---|
| 0 | **Full** — warm-up + 10 reps + sustained phase | ~15 min |
| 1..n | **Abbreviated** — warm-up + 5 reps, no sustained phase | ~3 min |
| any | **Escalate to full** if abbreviated deviates >10% from segment 0 | ~15 min |

Overhead drops to ~3% while preserving the guarantee: a machine whose behaviour has genuinely changed triggers the full measurement automatically.

If calibrated `tg128` varies more than **±10%** across segments, the run's **throughput metrics are flagged unstable**. Correctness metrics are unaffected — they do not depend on speed.

## Derived metrics

```
capability_score     = weighted mean task score across categories   (model property)
throughput_score     = tasks_passed / wall_clock_hour               (machine property)
efficiency_score     = tasks_passed / kWh                           (where telemetry exists)
vram_efficiency      = capability_score / peak_accel_gb
time_to_first_pass   = median seconds from prompt to a passing solution
harness_overhead_ratio = (build_ms + grade_ms) / (prefill_ms + gen_ms + build_ms + grade_ms)
```

`capability_score` is comparable across machines and execution classes **only when both rows scored the same category set**; `capability_score_core5` always is, because those five categories are never machine-gated. `throughput_score`, `time_to_first_pass`, and `efficiency_score` are **only comparable within an execution class** — see [06-execution-classes.md](06-execution-classes.md).

`harness_overhead_ratio` is a harness-health metric: it covers **every millisecond that is not the
model**. The old `build_overhead_ratio` omitted `prefill_ms` from the denominator and `grade_ms` from
the numerator, which made it blindest at `deep` — the one tier where L4 (cargo-mutants + criterion)
adds ~40 s of pure grading per unit. It was defined so that the tier where it matters most was the
tier it could not see ([REVIEW-5.md](REVIEW-5.md) `build-overhead-ratio-blind`).

Threshold re-derived against the deep-tier cost model rather than carried over: at 20 tok/s a healthy
`deep` unit is 64 s model / 64 s harness, so the ratio is **~0.50 by design**, rising to ~0.75 at
60 tok/s. A single 0.3 gate would fire on every healthy deep run. Publish `l4_share_of_grade`
alongside it so a caching regression is distinguishable from mandatory mutation testing.

## Hardware classes

Auto-assigned so leaderboard rows are comparable without the user choosing anything.

```
cpu-only
igpu
vram-8      vram-12     vram-16     vram-24     vram-32     vram-48     vram-80+
unified-16  unified-32  unified-64  unified-128            (Apple Silicon and similar)
multi-gpu-<n>x<class>
```

Buckets, not exact models, both for comparability and because an exact GPU model plus driver plus core count plus serial is an identifying fingerprint. See [11-submission-and-privacy.md](11-submission-and-privacy.md).

## Power telemetry

Best-effort, never required.

| Platform | Source |
|---|---|
| NVIDIA | NVML power draw sampling |
| Apple Silicon | `powermetrics` (requires elevated privileges — ask, do not demand) |
| Linux | RAPL where readable |
| Windows / AMD / Intel Arc | frequently unavailable |

If unavailable, `efficiency_score` is `null`. Never estimate it from TDP — a made-up number on a leaderboard is worse than a missing one.

## Pre-run gates

The harness refuses to start, or warns loudly, when:

| Condition | Action |
|---|---|
| Calibrated `tg128` below the suite's floor (suite would exceed 72 h) | refuse, suggest a smaller suite |
| Free scratch space below the suite's estimate ×1.5 | refuse |
| On battery power | warn; refuse for `perf-optimization` |
| Cold/warm calibration delta >15% | warn; mark throughput metrics unstable |
| Model context window smaller than the largest family's prompt | refuse that family, record as `skipped_context` |
| Network reachable from inside the sandbox | refuse — the sandbox is broken |
| **Serving concurrency > 1** (`/slots` reports `total_slots` > 1, or `-np` unset on llama.cpp) | **refuse.** The default is now 4 slots, and concurrent decoding yields 5–8 distinct completions for one prompt. Non-negotiable for a ranked row |
| **Effective context unknown or below the suite's largest prompt** | **refuse.** See the context probe below |
| Backend batch-invariance unverified (vLLM without batch-invariant kernels) | warn; ineligible for ranking |
| `tools` key present in the request path | refuse — the control condition requires its absence |

### The context probe — the highest-impact hidden variable

Context length is the **single largest measured effect in the whole design space**: same weights, same
backend, Aider measured **71.4% at 8k context versus 51.9% at 2k — a 19.5 point swing**, with
well-formed-response rate collapsing from 90.2% to 46.2%. That is larger than the quantisation effect,
larger than the edit-format effect, and larger than every backend and precision effect combined.

It is also **invisible over the OpenAI-compatible API**, and backends fail differently:

- **llama.cpp fails loudly** — HTTP 400 with the exact window in the body:
  `{"type":"exceed_context_size_error","n_prompt_tokens":5583,"n_ctx":4096}` (measured).
- **Ollama truncates silently**, discarding the oldest messages with no error.

A silently truncated prompt is scored as a model failure caused by configuration — noise attributed to
the wrong cause, in the direction that makes weak configurations look like weak models.

So preflight **binary-searches the effective context**: send prompts of increasing length until the
server either errors or stops tracking the input (detectable because `usage.prompt_tokens` ceases to
match what was sent). Costs a handful of requests, needs no vendor extension, and works on the silent
backends too. The result is recorded, and it also classifies the backend as loud-fail or silent-truncate.
