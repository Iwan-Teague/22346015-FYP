# 07 — Statistics: suite sizing, power, and confidence

This document decides how many task families exist, how many seeds each gets, how many times a model is sampled, and what confidence can honestly be claimed. Every one of those is the same question: how to spend a fixed compute budget for the tightest unbiased estimate.

## The pass predicate

`task_score` is continuous on [0, 1] — the right signal for the **capability** headline, but the wrong
*type* for the six consumers that need a yes/no: `throughput_score` ("tasks passed per hour"),
`time_to_first_pass`, McNemar model comparison, the sign-test precomputation detector, the probe
discordance calibration, and `budget_exhausted_rate`.

**Pass is defined structurally, not as a threshold on `task_score`** (Q28, pre-registered). A task is
*solved* iff, in order:

1. it **applied** (L0 — the answer was extractable), and
2. it **compiled** (L1), and
3. it is **behaviourally correct** — the L2 behaviour score is exactly `1.0` (every unit, property and
   differential check passed), and
4. it **respects the hard L3 constraints** it declared — no disallowed `unsafe`, no forbidden path,
   allocation budget met. A constraint the family did not declare (`None`) is not a barrier; only an
   explicit failure fails the task. Quality checks (clippy, fmt, and L4) are **not** part of pass.

Two properties make this the right definition rather than a tuned cutoff:

- **Weight-independent.** It never reads the composite weights, so re-tuning a category's
  behavior/constraint split cannot move pass rates. A threshold `task_score ≥ τ` does not have this
  property — REVIEW-6 measured a swept τ producing **23.3% type-I error** and moving effect sizes by a
  median 7 points. Structural pass removes the free parameter entirely.
- **It enforces the category thesis.** A clone-everything answer in `borrow-lifetimes` passes every
  behaviour test but fails the allocation constraint, so it does **not** pass — exactly what the
  constraint-dominant weighting intends, now as a hard fact rather than a weighted average.

Implemented as `OracleVector::passed()` in `bench-core`. The continuous `capability_score` stays the
published headline and the basis for every confidence interval; `passed` feeds only the binary metrics
above. A task with no behaviour oracle cannot pass — nothing confirmed it correct.

## Variance sources

Three, and they are not equal:

1. **Item variance** — which task families are in the suite. **Dominant.**
2. **Instance variance** — which seed within a family. Moderate, and *correlated within family*.
3. **Sampling variance** — temperature and backend nondeterminism. Small at temperature 0.

## The clustering result that drives everything

Seeds within a family are **not independent observations**. A model that cannot reason about lifetime elision fails seeds 1–16 of `borrowck/elide-nested` together. That is intra-class correlation (ICC), and it shrinks effective sample size:

```
design_effect = 1 + (seeds_per_family − 1) × ICC
effective_N   = total_instances / design_effect
```

For seeded variants of one family, ICC is plausibly **0.3–0.5**. At ICC = 0.3:

| Seeds/family | design effect | Effective items per family |
|---|---|---|
| 1 | 1.0 | 1.00 |
| 2 | 1.3 | 1.54 |
| 4 | 1.9 | 2.11 |
| 8 | 3.1 | 2.58 |
| 16 | 5.5 | 2.91 |

**Sixteen seeds of one family buys roughly 2.9 independent items. Four buys 2.1.** Diminishing returns arrive fast.

Therefore: **breadth beats depth, decisively.**

> 200 families × 3 seeds = 600 instances ≈ 400 effective
> 50 families × 12 seeds = 600 instances ≈ 155 effective

Same compute, **2.6× the statistical power**. This is the single most consequential number in the design, and it is why the family count (272) matters far more than the seed count.

It also answers "surely we need an average?" — yes, but the average that carries information is *across families*, not across repeats of the same family. Repeats mostly re-measure something already known.

## Precision achieved

95% CI half-width at p = 0.5 (worst case), on **effective** N:

| Effective N | ±CI |
|---|---|
| 25 | ±19.6% |
| 50 | ±13.9% |
| 100 | ±9.8% |
| 200 | ±6.9% |
| 400 | ±4.9% |
| 800 | ±3.5% |

To separate two models **10 points apart** (unpaired, 80% power, α = 0.05): ~385 effective items per arm.
To separate them at **5 points**: ~1,530 effective items per arm.

That second number is why pairing matters.

> **Note on the formula.** `task_score` is continuous on [0, 1], not binary, so the binomial
> expression is not exactly right. It is a *conservative upper bound*: the variance of any
> variable bounded on [0, 1] is at most 0.25, so these CIs are never too narrow. The reported
> CI is always the cluster bootstrap, not this formula; the table exists for sizing decisions.

## Clustering is two-level: shape → family → seed

The model above is one-level (family → seed) and **understates variance whenever families cluster
into a smaller number of task shapes**, which round 4 established they do: `unsafe-core`'s 40 families
span only ~16 miri-checkable shapes, and `idiom-refactor`'s usable transform catalogue measured at
5 of 35 candidates and ~3 distinct lessons ([REVIEW-5.md](REVIEW-5.md) R5-S3).

Two consequences, both load-bearing:

1. **The precision ceiling is governed by SHAPE count, not family count.** Buying more families
   inside an exhausted shape space buys almost nothing. Below roughly 13 shapes, the ±10.7% target is
   unreachable at *any* family budget, so **no core category currently reaches the figure
   [ADR-0008](adr/0008-core-and-probe-categories.md) claims**. The budgets in that ADR are marked
   provisional pending a shape-count audit per category (**Q24**).
2. **The specified family-level cluster bootstrap under-covers**, and the within-family ICC that
   Phase 3.5 was designed to measure is **invariant to the defect** — it cannot detect shape
   clustering at all. Gate G2 as written measures the wrong quantity.

So: the bootstrap resamples **shapes**, carrying their families and seeds; `report.json` records
`shapes`, `icc_within_family` and `icc_within_shape` per category; and Phase 3.5 must estimate the
shape component, not only the family one.

`idiom-refactor` is a special case: its clustering is **crossed, not nested** — a transform appears
across many families rather than partitioning them — so **no nested bootstrap is valid for it**. It
needs a different estimator or a different category design, and that is unresolved (**Q24**).

## The ceiling that seeds cannot raise

As seeds per family → ∞, the design effect grows linearly, so effective N per category converges:

```
lim (m × F) / (1 + (m−1) × ICC)  =  F / ICC
m→∞
```

**Per-category precision is bounded by family count alone.** No amount of seeding escapes it.

| Families per category | ICC 0.2 | ICC 0.3 | ICC 0.5 | ICC 0.7 |
|---|---|---|---|---|
| 12 | ±12.7% | ±15.5% | ±20.0% | ±23.7% |
| 20 | ±9.8% | **±12.0%** | **±15.5%** | ±18.3% |
| 30 | ±8.0% | ±9.8% | ±12.7% | ±15.0% |
| 40 | ±6.9% | **±8.5%** | ±11.0% | ±13.0% |
| 45 | ±6.5% | ±8.0% | ±10.3% | ±12.2% |

This is the finding that reshaped the category design. At the originally planned 20 families per
category, the radar chart — the product's most distinctive feature — would carry ±12–16% error bars
at *any* suite size, forever. "Better at traits than at lifetimes" would never be supportable.

Resolution: categories split into **core** (40 families, rankable) and **probe** (12 families,
explicitly directional-only). See [04-categories.md](04-categories.md) and
[ADR-0008](adr/0008-core-and-probe-categories.md).

## Paired design — free 2–4× power

**Every model in an epoch runs the identical scored seed set.** Comparison then uses McNemar on discordant pairs rather than two independent proportions. Models fail on correlated items, so pairing cancels most of the item variance — typically a 2–4× reduction in the N required for the same power.

This requirement collides head-on with the anti-precomputation design, which wants seeds that did not exist before the run was requested. A single derivation cannot serve both. Resolved by splitting each epoch into a **paired core** (~85%, fixed per epoch, scored) and a **fresh probe** (~15%, per-batch nonce, never scored, used only as a precomputation detector) — see [ADR-0009](adr/0009-paired-core-and-fresh-probe-seeds.md).

All precision figures in this document are computed on the **core** set only. Probe units are **additional**, not carved out of the scored count — so a `deep` run executes 1088 scored core units *plus* ~163 probe units, and its wall clock is ~15% above the scored-only figure. The suite table below states both.

## Suite sizing

### Timing model

Per-instance cost, on a 20 tok/s local model:

```
prefill        ~10 s     (2k-token prompt at ~200 tok/s)
generate       ~30 s     (600 completion tokens)
build + grade  ~12 s     (warm cargo cache, L0-L3)
               ------
single-shot     ~55 s
repair mode     ~88 s    (2 attempts on the ~60% that fail attempt 1)
+ L4 quality   ~128 s    (cargo-mutants + criterion)
```

`repair` is the **default** interaction mode and L4 is **mandatory at `deep`**, so both must be in
the estimate. The earlier draft costed only the 55 s single-shot path and understated every suite
by 2–3×.

### Suites

Corpus: **272 families** — 5 core × 40, 6 probe × 12. See [04-categories.md](04-categories.md).

| Suite | Families | Seeds | Scored units | + probe | Mode | Eff. N | ±CI overall | ±CI core cat | ±CI probe cat | @20 tok/s | @60 tok/s |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `smoke` | 60 | 1 | 60 | — | single-shot | 60 | ±12.7% | n/a | n/a | ~55 min | ~25 min |
| `standard` | **208** | 2 | **416** | +62 | repair | ~320 | **±6.5%** | ±12.5% | ±22.8% | **~11.7 h** | **~6.0 h** |
| `deep` | 272 | 4 | 1088 | +163 | repair + L4 | ~573 | ±4.9% | **±10.7%** | ±19.5% | ~44.5 h | **~29.7 h** |

All figures at ICC = 0.3. Precision columns are computed on scored units only; wall-clock columns
include the probe. `smoke` carries no probe — it is not submittable for ranking, so precomputation
detection is moot. See the sensitivity grid below.

Three columns were corrected after round 5 ([REVIEW-5.md](REVIEW-5.md)); the reasoning is worth
keeping visible because two of the errors were of the same class as R1-S1.

**The `standard` row no longer claims the full corpus.** [04](04-categories.md) marks expensive
families (miri, criterion, multi-file) as `tier = deep`, "admitted only above the `standard` suite" —
and miri is *mandatory* for `unsafe-core`. So 64 families (all 40 of `unsafe-core`, plus 12
`perf-optimization` and 12 `cross-module`) are deep-tier, and `standard` runs **208 families across
8 categories**, not 272 across 11. The old row sized `standard` as the whole corpus and then quoted a
`±CI core cat` figure for a category that, by 04's own tier rule, had no families in that suite.

This is why the denominator rule in [04](04-categories.md) matters: **`standard` and `deep` do not
compute `capability_score` over the same category set**, so their headline numbers are not directly
comparable and each must publish `categories_scored`. `capability_score_core5` is undefined at
`standard` (only four core categories run), which is a further reason `deep` is the minimum ranked
tier.

**`±CI overall` uses the right estimator now.** `capability_score` is defined as an *equal-weight mean
of eleven category means* ([04](04-categories.md)), not a pooled mean of 1088 units. Under equal
weighting each 48-unit probe category carries the same 1/11 weight as each 160-unit core category, so
the variance is dominated by the six small strata:

```
Var = (1/121) · Σ_c Var_c          Var_c = 0.25 / eff_N_c
deep:      ±4.9%   (equal-weight effective N 408, not the pooled 573)
standard:  ±5.7%   (equal-weight effective N 298)
lite (10 categories): ±5.0% deep, ±5.8% standard
```

The pooled effective N is still published in the `Eff. N` column because it is the right number for
*unit-level* questions; it is the wrong number for the headline score, and the two are now labelled.

**`±CI core cat` / `±CI probe cat` on the `standard` row** previously used the `deep` suite's design
effect (1.90, for 4 seeds) inside a 2-seed row. At the correct DE = 1.30 they are ±12.5% and ±22.8%.

**`@60 tok/s` on the `deep` row** treated the whole per-unit cost as token-bound. It is not:

```
per-unit @20 tok/s = 64 s token-bound + 64 s fixed (build+grade ×2 attempts, L4 once) = 128 s
per-unit @60 tok/s = 21 s token-bound + 64 s fixed                                    =  85 s
```

So `deep` is ~29.7 h at 60 tok/s, not 20.2 h. **The L4 share of per-unit cost rises from 31% at
20 tok/s to 47% at 60 tok/s** — on fast hardware `deep` is progressively grading-bound rather than
inference-bound, which is a result worth publishing and which a single throughput multiplier hid.

### ICC sensitivity

ICC is an **assumption, not a measurement** (see [REVIEW.md](REVIEW.md) S2). Overall effective N and
±CI for `deep` (272 × 4 = 1088 instances) across plausible values:

| ICC | Design effect | Eff. N (pooled) | ±CI overall (pooled — see above) | ±CI core cat |
|---|---|---|---|---|
| 0.2 | 1.6 | 680 | ±3.8% | ±9.8% |
| 0.3 | 1.9 | 573 | ±4.1% | ±10.7% |
| 0.5 | 2.5 | 435 | ±4.7% | ±12.3% |
| 0.7 | 3.1 | 351 | ±5.2% | ±13.7% |

Suite sizing is **provisional until Phase 3.5 measures the real ICC**. That experiment is a hard
gate before corpus scale-up.

**ICC is estimated and published per category, not pooled.** Round 4 found that `unsafe-core`'s
40 families must spread across only ~16 miri-checkable task shapes, so families within a shape are
correlated and the category's effective ICC exceeds the corpus-wide 0.3. Its honest CI is nearer
±12.3% than the ±10.7% a pooled value implies. Any category whose families cluster into few shapes
has the same problem, so the estimate belongs per category. See [REVIEW-4.md](REVIEW-4.md) R4-S5.

### There is no `full` suite

An earlier draft specified `full` at 16 seeds. It was deleted. Going 4 → 16 seeds improves
per-core-category CI from ±10.7% to roughly ±9% for **4× the wall clock** — **178 hours** at
20 tok/s. (An earlier draft said "over 110 hours" in the same sentence as "4×"; 4 × 44.5 = 178.) The S3 ceiling means the money is in families, never in seeds.

If someone wants more precision than `deep`, the answer is more families, not more seeds.

### Leaderboard policy

- **`deep` is the minimum tier for a ranked row.** `standard` and `smoke` are accepted, displayed
  greyed, marked *insufficient precision for ranking*.
- **Core category scores are rankable at `deep`** (±10.7%). Two models must differ by roughly
  15 points before a core-category difference is claimable, and the claim uses the paired
  bootstrap, not overlapping CIs.
- **Probe category scores are never ranked.** They are displayed as directional indicators with
  their CIs shown, and the UI does not offer sorting on them. A ±19.6% error bar cannot support
  an ordering and should not be presented as if it could.

## Sampling protocol

```
primary        temp = 0.0, 1 sample per instance, all families × N seeds
               -> capability_score, category scores, clustered-bootstrap CIs

variance probe 10% instance subsample × 5 samples @ temp = 0.8
               -> pass@5, self-consistency rate, sampling-variance estimate
               cost: +5% of total runtime

determinism    20 instances × 3 identical greedy calls
probe          -> detects backend nondeterminism; reported as a hardware/backend fact
```

Greedy repeats are near-worthless for capability estimation — that budget belongs to more families. Sampled repeats on a subsample give the variance estimate needed to put honest error bars on everything else.

Backend nondeterminism is real: llama.cpp greedy output can vary with batch size and backend. Any case where identical `(model, seed, sampling)` produced different output is recorded and published as a backend fact, not silently averaged away.

## Confidence intervals and tests (the estimation spec)

**The published CI is always the cluster bootstrap. The design-effect formula and the ICC estimate are
for sizing and diagnostics only — never for a published interval (Q29).** This one rule removes the
worst failure mode: a badly-estimated (even negative) ICC cannot narrow a bootstrap CI, because the
bootstrap never reads it.

### The bootstrap unit: the coarsest cluster

Resample at the **top** cluster level, carrying everything nested beneath it, then recompute:

```
repeat 10_000 times:
    resample <top-level clusters> with replacement
    carry all families and seeds of each along
    recompute the statistic
report 2.5th and 97.5th percentiles
```

The top level is **shapes** once shapes are labelled ("Clustering is two-level" above; needs the
shape-count audit, **Q24**) — families cluster into a smaller number of shapes, and a family-level
resample misses that correlation. **Until shapes are labelled the bootstrap resamples families, and
every CI so produced is flagged as a lower bound on width** (it under-covers by the shape clustering it
cannot see). Never resample instances (seeds) independently — that understates the CI by ~40% at
ICC 0.3, which is confident nonsense. The same rule applies to category scores (resample the clusters
within the category) and to paired comparisons (resample clusters, recompute the paired difference).

`idiom-refactor` clusters **crossed, not nested** (a transform spans families), so no nested bootstrap
is valid for it; it is **directional-only, never ranked**, until Q24 gives it an estimator.

### Few clusters: wild cluster bootstrap

The naive percentile cluster bootstrap **under-covers when clusters are few** — simulated 92% at a core
category and 84% at `idiom-refactor`, against a nominal 95%. Use the **studentised (percentile-t) wild
cluster bootstrap** (Cameron–Gelbach–Miller): Rademacher sign-flips on the per-family residual sums, with
each replicate carrying its own cluster-robust SE so the interval inverts bootstrap t-quantiles rather
than raw percentiles — the t-pivot is what cancels the small-sample SE noise and restores coverage.
Implemented in `bench-stats` and **validated by simulation**: measured **0.95 coverage at 12 clusters**,
versus 0.90 for the un-studentised percentile form. It holds down to ~12–15 clusters; below that it
degenerates (at 2 clusters the sign flips that carry the signal also zero the bootstrap SE), which is why
any category below a cluster-count floor (fixed at the shape audit) is **directional-only, not ranked** —
the honest home for `idiom-refactor` and any few-shape category.

### ICC: estimated, clamped, diagnostic-only

ICC is estimated by variance components (ANOVA / REML), **clamped to [0, 1]**, and the design effect is
`max(1, 1 + (m−1)·ICĈ)` — you can never claim more precision than an independent sample from clustered
data. Because per-category family counts are small, each category's ICC is **shrunk toward the pooled
estimate** (empirical Bayes) rather than trusted raw. It is published per category as
`icc_within_family` / `icc_within_shape` and used for *sizing*; it is not an input to any published CI.

### The precomputation detector: sign test, pick-one collapse

The fresh-probe seed is compared against the paired core to detect precomputation. A `deep` run has 4
core seeds per family and 1 probe seed, so the family's core outcome (`passed`, above) must collapse to
one bit to pair with the probe. **The collapse is pick-one: a single designated core seed (index 0).**
It is the only rule that preserves the null — proven `E[b]−E[c] = E[P(B=1|p)] − E[p]`, with simulated
honest-run false-accusation rates of 100% (`any`), 53.7% (`majority`), **4.2% (`pick-one`, ≈ nominal)**.
The other three core seeds serve capability, not the detector; "wasting" them here is the price of a
valid test.

### Multiple comparisons: family-wise control

The radar chart shows 11 category scores at once; uncorrected, its family-wise error is 94–99%.
**Control the family-wise error rate, pre-registered (Q29.4):**

- **Radar CIs are simultaneous** — each category interval is computed at level 1 − 0.05/11 ≈ 99.5%
  (Bonferroni), so *joint* coverage across all 11 is 95%. The chart states that its bands are
  simultaneous.
- **Model-vs-model category comparisons use Holm** across the categories compared — uniformly more
  powerful than plain Bonferroni while still controlling FWER.

FDR (Benjamini–Hochberg) was considered and rejected: on a public leaderboard a controlled fraction of
false "category X beats Y" claims is worse than wider bars.

## Measure the real ICC, then adapt

Ship `rustybench calibrate-suite`. Once a few hundred submissions exist:

1. **Compute per-family ICC empirically** and retune seeds-per-family instead of guessing 0.3.
2. **Adaptive allocation.** Families where every model scores 0% or 100% carry no information — they are wasted compute. Families near a 50% pass rate carry the most. Item-response-theory and adaptive-testing approaches reach the same precision with substantially fewer items.

Adaptive allocation is a version-2 feature, but the schema must have a home for per-family difficulty and discrimination parameters **from day one**. See [12-schemas.md](12-schemas.md).

## Reporting rules

- Every published score carries a CI. A score without one is not published.
- Every published score states its suite tier and effective N.
- Category comparisons within a model use the paired bootstrap, not overlapping-CI eyeballing.
- Model comparisons use McNemar on the shared seed set (the `passed` bit), and state the discordant-pair count.
- Any figure showing many scores at once (the radar) uses **simultaneous** CIs; any multi-category test controls FWER (Bonferroni/Holm). The correction is pre-registered, never chosen post-hoc.
- Any metric flagged unstable (see [05-hardware-and-calibration.md](05-hardware-and-calibration.md)) is displayed struck through, not omitted.
