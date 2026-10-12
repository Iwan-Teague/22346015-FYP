# ADR-0008 — Core and probe categories

**Status:** Accepted · 2026-08-17 · Arising from [REVIEW.md](../REVIEW.md) S3

## Context

Per-category precision has a ceiling that seeds cannot raise. As seeds per family → ∞:

```
lim (m × F) / (1 + (m−1) × ICC)  =  F / ICC
m→∞
```

Effective N per category is bounded by **family count alone**.

At the originally planned 20 families per category:

| ICC | Ceiling eff. N | Best achievable ±CI |
|---|---|---|
| 0.2 | 100 | ±9.8% |
| 0.3 | 66.7 | **±12.0%** |
| 0.5 | 40 | **±15.5%** |
| 0.7 | 28.6 | ±18.3% |

The radar chart is the product's most distinctive feature. At 20 families it would have carried ±12–16% error bars at *any* suite size, forever. "This model is better at traits than at lifetimes" would never have been supportable. **The headline feature was statistically unbuildable as specified**, and nobody had noticed because the ceiling had not been derived.

## Options

1. **10 categories × 20 families = 200.** Status quo. All category scores ±12–16%. Honest only if we stop presenting them as rankable — which guts the radar chart.
2. **10 categories × 45 families = 450.** All categories ±8%. Roughly 2.25× the corpus cost, pushing the project from ~1–3 years to ~3–7.
3. **5 categories × 40 families = 200.** Same cost as option 1, ±8.5% each, but halves the resolution axes and loses the categories that make the benchmark interesting.
4. **Two classes: core at 40 families, probe at 12.**

## Decision

**Option 4.**

- **Core — 40 families, rankable.** `borrow-lifetimes`, `traits-generics`, `error-handling`, `idiom-refactor`, `unsafe-core`. Ceiling ±8.5% at ICC 0.3; ±10.7% at the `deep` suite's 4 seeds.
- **Probe — 12 families, directional only, never ranked.** `async-concurrency`, `perf-optimization`, `api-evolution`, `test-authoring`, `cross-module`, `ffi-boundary`. ±19.6% at `deep`.

Corpus: 272 families, up from 200.

Both classes contribute to `capability_score`. Only core categories may be compared against each other or across models. The UI does not offer sorting on probe scores — an error bar that cannot support an ordering should not be presented as though it could.

### Which categories became probes, and why

Selection was by **oracle tractability**, not by importance:

| Category | Reason |
|---|---|
| `async-concurrency` | Differential oracle not well-defined under nondeterministic scheduling — see [REVIEW.md](../REVIEW.md) S10, still open |
| `perf-optimization` | Hardware-gated; unmeasurable on thermally unstable or `CpuOnly` machines |
| `test-authoring` | L4-dominant, therefore not replay-verifiable |
| `cross-module` | Mined; small-commit yield unproven; slowest tier |
| `api-evolution` | Mined; supply bounded by the Rust release calendar |
| `ffi-boundary` | Miri cannot execute foreign calls, so it needs a different oracle entirely (a real C shim) |

The last row is also a category split: the original `unsafe-ffi` demanded miri on code miri definitionally cannot run. `unsafe-core` (raw pointers, transmute, aliasing, `Send`/`Sync`) is miri-checkable and became core; `ffi-boundary` became a probe.

## Consequences

**Good**

- The radar chart becomes defensible for the five categories that most distinguish Rust from every other language.
- Corpus grows only 36% (200 → 272) rather than 125%.
- Probe categories still contribute to the composite and still surface directional signal — a model scoring 5% on `async-concurrency` is informative even at ±19.6%.
- Forces an explicit statement of which category scores are claims and which are indications. That honesty is itself a differentiator.

**Bad**

- Two classes of category is a concept users must learn. Mitigated by making it visible in the UI (probe scores rendered with visible error bars and no sort affordance) rather than buried in documentation.
- The five core categories are all synthetic. Realism in the composite now rests entirely on probe categories, which are the noisier half. The `synth`/`wild` correlation from [ADR-0002](0002-hand-written-and-mined-suites.md) becomes correspondingly more important as validity evidence.
- If **G2** measures ICC > 0.5, even 40 families floors near ±12% and core categories need to grow to ~60, or drop to four. That pivot is written into the roadmap gate rather than left to be discovered.

## Related

This ADR is also what killed the `full` suite. Once the ceiling is understood, 4 → 16 seeds buys about 1.5 percentage points of per-category precision for 4× the wall clock. The compute belongs in families.
