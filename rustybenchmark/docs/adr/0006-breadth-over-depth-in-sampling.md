# ADR-0006 — More families beats more seeds per family

**Status:** Accepted · 2026-08-17

## Context

Given a fixed compute budget, spend it on more task families or on more seeds per family? The intuition "run each test several times and average" points toward depth. The arithmetic points the other way.

Seeds within a family are not independent observations. A model that cannot reason about lifetime elision fails every seed of `borrowck/elide-nested` together. That is intra-class correlation, and it shrinks effective sample size:

```
design_effect = 1 + (seeds_per_family − 1) × ICC
effective_N   = total_instances / design_effect
```

At a plausible ICC of 0.3:

| Seeds/family | Effective items per family |
|---|---|
| 1 | 1.00 |
| 2 | 1.54 |
| 4 | 2.11 |
| 8 | 2.58 |
| 16 | 2.91 |

Sixteen seeds of one family buys roughly **2.9 independent items**.

## Decision

**Prioritise family count.** Target 272 families — 5 core categories at 40, 6 probe categories at 12 ([ADR-0008](0008-core-and-probe-categories.md)) — with 1–4 seeds each depending on suite tier.

Concretely, for the same 600 instances:

> 200 families × 3 seeds ≈ **400 effective**
> 50 families × 12 seeds ≈ **155 effective**

Same compute, **2.6× the statistical power**.

Supporting decisions:

- **Paired design.** All models in an epoch run the identical seed set; comparison uses McNemar on discordant pairs. Typically 2–4× further power gain for one line of policy.
- **Greedy primary, sampled probe.** `temp = 0.0`, one sample per instance for the primary score; a 10% subsample × 5 samples at `temp = 0.8` for the variance estimate. Greedy repeats mostly re-measure backend nondeterminism, which is worth detecting but not worth 5× the budget.
- **Cluster-bootstrap CIs at the family level.** Naive per-instance bootstrap understates the CI by roughly 40% at ICC = 0.3.
- **`deep` is the minimum tier for a ranked leaderboard row.** At `standard`, per-core-category CIs are **±12.5%** and per-probe-category **±22.8%** — too wide for any category-level claim. (An earlier "around ±17 points" here was a third value for the same quantity; see [REVIEW-5.md](../REVIEW-5.md) `standard-row-ci`.)

## Consequences

**Good**

- Substantially more power per compute-hour.
- Forces investment where it belongs: the corpus.
- The `deep`-minimum rule prevents the leaderboard filling with underpowered rows that look authoritative.

**Bad**

- Reinforces that authoring ~272 families is the project. There is no shortcut.
- Users running `smoke` or `standard` get a number they cannot rank with. Handled by displaying those rows greyed and explicitly marked *insufficient precision for ranking*, rather than rejecting them.
- ICC = 0.3 is an assumption. `rustybench calibrate-suite` measures it empirically once submissions exist; seeds-per-family is then retuned from data rather than from this estimate.

## Follow-on

The schema reserves per-family IRT fields (`difficulty`, `discrimination`, `guessing`) from v1 even though nothing writes them. Families where every model scores 0% or 100% carry no information; adaptive allocation reaching the same precision with fewer items is the natural v2 optimisation, and it needs somewhere to store its parameters.
