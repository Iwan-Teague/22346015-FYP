# 00 — Overview

## Thesis

Two questions have no good joint answer today:

1. **"Which local model is actually good at Rust, and good at *which parts* of Rust?"**
2. **"What will that model do on *my* hardware?"**

Existing coding benchmarks answer a degraded version of (1) — usually Python, usually a single scalar, usually contaminated. Existing hardware benchmarks answer a degraded version of (2) — tokens per second, disconnected from whether the tokens were any good.

Rustybenchmark answers both, in one run, and keeps them clearly separated because they have very different epistemic status: correctness is independently verifiable, throughput is not.

## Goals

- **Rust-native.** Grade on the signals Rust uniquely provides: rustc diagnostic codes, clippy, `unsafe` counts, miri, trait/lifetime semantics. Not just pass/fail.
- **Contamination-resistant by construction.** Tasks are generators. A model cannot memorise an instance it has never seen. Seeds rotate per epoch.
- **Runs on consumer hardware.** Target band is 8–24 GB VRAM, laptops included. The smallest suite finishes inside an hour.
- **Category-resolved.** Eleven Rust skill areas, scored independently, with honest confidence intervals on each — and an explicit split between the five that are precise enough to rank and the six that are directional only.
- **Hardware-aware.** Every run profiles and calibrates the host so results are comparable and so machine capability is itself a published output.
- **Verifiable.** Correctness claims are re-checkable server-side. Everything that cannot be verified says so on the leaderboard.
- **Resumable.** A 44.5-hour suite must survive being run in ninety-minute evening slices.

## Non-goals

- **Not a frontier-model leaderboard.** Hosted API models may be run for reference points, but the design centre is local inference.
- **Not an agent-framework benchmark.** The default interaction mode is single-shot plus one repair turn. Full agentic loops confound the model with the scaffolding and multiply cost. Agentic mode exists but is a separate reported track.
- **Not a training set.** Solved instances are never published. Model output is retained privately for verification only, then deleted.
- **Not a general-purpose eval framework.** Rust only. The narrowness is the point — it is what lets the oracle be sharp.

## The two headline numbers

```
capability_score    = weighted mean task score across the suite
                      (what the model can do, time-unbounded)

throughput_score    = tasks passed per wall-clock hour
                      (what this machine + model actually delivers)
```

Plus derived:

```
efficiency_score    = tasks passed per kWh              (where power telemetry exists)
vram_efficiency     = capability_score / peak_accel_gb
time_to_first_pass  = median seconds to a passing solution
```

`capability_score` compares models, and is comparable across machines **only when the category sets match** — `perf-optimization` is machine-gated, so `capability_score_core5` is the cross-machine key ([04](04-categories.md)). `throughput_score` compares machines and is only comparable within an execution class. Never merge them.

## Design principles

1. **Report vectors, not scalars.** The composite score exists for sorting. The interesting output is the per-category breakdown and the rustc error-code histogram.
2. **Separate the verifiable from the unverifiable.** Correctness is deterministic and re-checkable. Hardware timing is neither. Label accordingly, always.
3. **Breadth over depth.** Statistical power comes from more task families, not more repeats of the same family. See [07-statistics.md](07-statistics.md).
4. **Cheap to run, expensive to fake.** The harness should be trivial to run honestly and require sustained effort to fake convincingly.
5. **Publish the raw corpus.** Independent re-derivation of the leaderboard is the strongest integrity mechanism available.
6. **Fail loudly, never silently degrade.** A run that cannot maintain its invariants aborts or is marked tainted. It does not quietly produce a worse number.

## Naming

- Project: **Rustybenchmark**
- Binary / CLI: `rustybench`
- Crate prefix: `bench-*` (workspace-internal), published crates as `rustybench-*`
