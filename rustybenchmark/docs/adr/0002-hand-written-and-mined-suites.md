# ADR-0002 — Both hand-written and mined suites, reported separately

**Status:** Accepted · 2026-08-17

## Context

Two ways to obtain tasks, with opposite strengths.

| | Hand-written (`synth`) | Mined (`wild`) |
|---|---|---|
| Difficulty control | precise | none |
| Oracle correctness | guaranteed by construction | inherited from repo tests, imperfect |
| Contamination resistance | high, fresh seeds forever | decays; needs post-cutoff harvesting |
| Construct validity | measures the skill you named | measures real work |
| Authoring cost | very high, per family | moderate, per pipeline |

The initial recommendation was hand-written for categories 1–7 and mined for 8 and 10, chosen on cost. Cost is no longer the deciding constraint — the stated priority is the most accurate data.

## Options

1. **Hand-written only.** Risks measuring the author's taste in puzzles. No external validity evidence.
2. **Mined only.** Cannot isolate categories — a failure could be lifetimes or repo navigation and you never know which.
3. **Both, blended into one score.** Worst of both: an uninterpretable number whose composition nobody can reason about.
4. **Both, reported separately, with the correlation between them published.**

## Decision

**Option 4.** Hand-write categories 1–9 (~165 families). Mine categories 8 and 10 (~35 families). Report `synth` and `wild` as separate suites; never blend them into a single figure.

## Consequences

**Good**

- The correlation between `synth` and `wild` scores becomes **validity evidence for the benchmark itself**. If `synth` `borrow-lifetimes` performance predicts `wild` performance, the synthetic categories demonstrably mean something. That is a stronger claim than any comparable benchmark currently makes.
- Category attribution stays exact where it matters, and realism is still represented.
- A model that games the synthetic suite is visible as an outlier against `wild`.

**Bad**

- Two pipelines to build and maintain.
- Mined oracle quality is inherited, not guaranteed. `wild` results carry a caveat that `synth` results do not.
- Publishing two numbers invites "which is the real one?" — answered by making `capability_score` explicitly the synthetic-suite number and `wild` an explicitly-labelled realism check.

## Related

Category 10 (`cross-module`) is mined *and* in the headline composite — see [ADR-0004](0004-cross-module-in-headline.md). The composite is therefore not purely synthetic. This tension is deliberate: excluding real repo work entirely would be a larger validity error than including a mined category with a caveat.


> **Superseded in part.** The family counts here (~165 hand-written, ~35 mined) predate the core/probe split in [ADR-0008](0008-core-and-probe-categories.md). Current corpus: **272 families — 248 synthetic, 24 mined**. This ADR's promise of a published synthetic-suite number went undelivered until round 5; `capability_score_synth` now exists ([REVIEW-5.md](../REVIEW-5.md) W4). Both of this ADR's validity claims failed under simulation in round 5 — see **Q25**.
