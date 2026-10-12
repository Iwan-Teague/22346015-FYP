# Adversarial review — round 4

**Date:** 2026-08-17 · **Scope:** the three questions round 3 deferred (Q16–Q18), plus the mechanical schema cross-check the round-3 process note demanded.

Round 4 found the most serious defect of any round so far, and separately came within one simulation of recommending a change that would have gutted the benchmark's statistical power. Both are recorded.

---

## R4-S1 — The precomputation detector is defeated by suppression · **PATCHED**

**Severity: severe.** Round 3 improved the detector's sensitivity against a *naive* adversary and explicitly deferred the adaptive case. The adaptive case breaks it.

**The strategy.** Precompute answers for a fraction of core families. That creates one-directional discordance (core passes, fresh probe fails), which is what the sign test detects. To hide it, deliberately fail some core units you could have passed, manufacturing discordance in the opposite direction until the test rebalances.

**Simulated** — 272 families, 4 seeds, 163 probed, base pass rate 40%, ICC ≈ 0.3, 300 trials per cell:

| Precomputed | No suppression | | Blind suppression | | Informed suppression | |
|---|---|---|---|---|---|---|
| | net score | detected | net score | detected | net score | detected |
| 5% | +2.9p | 12% | +0.2p | **0%** | +2.3p | **0%** |
| 10% | +6.0p | 31% | +2.4p | **0%** | +5.1p | **0%** |
| 20% | +11.9p | 78% | +7.5p | **0%** | +10.2p | **0%** |
| 35% | +21.0p | 100% | +17.1p | **0%** | +18.7p | 19% |

**A cheater keeps 10 of 12 points and becomes completely invisible.** At 35% precomputation — nearly 19 points of inflation — detection is 19%.

**Two defences were tested and both failed:**

- **Family-aggregate pairing** (compare all 4 core seeds against the probe rather than one designated seed, so suppression costs 4 units instead of 1): 20% precomputation still nets +10.4p at 0% detection.
- **Probe/core indistinguishability** (deliver a shuffled unlabelled seed list so suppression cannot be targeted): 20% still nets +9.0p at 0% detection.

**Why no test statistic can fix this.** The arithmetic is structural:

```
the cheat pays off across    1088 core units
the detector observes         163 family-level pairs
gain : hiding-cost ratio  =   6.7x
```

Hiding is roughly seven times cheaper than the gain, because the score is earned over the whole core while the detector only ever sees the probed subset. Improving the test statistic changes the constant, not the ratio.

**Resolution — the probe is demoted, and secrecy becomes the primary control.** See R4-S2. The probe is retained as a screening test against *unsophisticated* precomputation and is documented with its measured failure mode, rather than presented as the control it is not. [ADR-0009](adr/0009-paired-core-and-fresh-probe-seeds.md) and [10-integrity.md](10-integrity.md) are corrected.

**Also found:** [10-integrity.md](10-integrity.md) still specified `precompute_signal = core_score − probe_score` — the mean comparison that [R3-S3](REVIEW-3.md) replaced with the sign test. Round 3 patched the ADR and not the integrity document, which is the one the server implements from. Exactly the drift the round-3 process note warned about, one round later.

---

## R4-S2 — Published seeds make precomputation trivially available · **PATCHED**

**Severity: severe.** Three separately reasonable decisions combine into an open door.

1. [02-task-format.md](02-task-format.md) states: *"Generators are public. Seeds used in a run are public."*
2. Pairing requires that **every submitter in an epoch runs the identical core seed set** ([07-statistics.md](07-statistics.md)).
3. R4-S1 shows the detector cannot catch a submitter who precomputes and suppresses.

So the second submitter in an epoch reads the first submitter's published seeds, precomputes offline with unlimited time and a stronger model, suppresses to flatten the discordance signal, and posts an inflated score that T1 replay confirms as genuine — because the answers really are correct.

The probe existed to close exactly this hole and cannot.

**Resolution — seed secrecy with delayed publication.**

- Core seeds for an epoch are **not published while the epoch is open**.
- The public dump for epoch *N* is released when epoch *N* closes, at the start of epoch *N+1*.
- Independent re-derivation and audit remain fully possible, delayed by one epoch.
- Seeds are never reused across epochs, so a published set has no forward value.

This preserves the integrity argument that matters — anyone can re-derive the leaderboard from published data — while removing the window in which that same data is an attack tool. The cost is one epoch of delay on public scrutiny, which is a far smaller price than an undetectable inflation channel.

**Residual threat, stated rather than hidden:** a submitter who has already run holds the seeds and can leak them to a confederate within the same epoch. Against that, the remaining defences are the (weak) probe, canary cross-screening, and T3 audit. This is a real limitation and belongs on the leaderboard's methodology page.

---

## R4-S3 — Near-miss: family-level pairing is not a viable simplification · **RECORDED, NOT ADOPTED**

Worth recording because the first analysis said the opposite and it would have been a large, wrong change.

R4-S1 makes the entire probe apparatus look like poor value. It exists only because pairing is defined at **seed** level, which forces seed reuse across submitters. If pairing worked at **family** level — every submitter runs the same 272 families with *fresh* seeds — then precomputation would be impossible by construction, and the probe, the batch nonces, the two-level plan from [R3-S1](REVIEW-3.md), and Q13/Q16 could all be deleted.

**The first simulation supported this.** Modelling outcomes as Bernoulli draws from a family-level difficulty distribution, family-pairing lost essentially nothing:

| True gap | Seed-paired | Family-paired | Lost |
|---|---|---|---|
| 3p | 34% | 38% | −4pp |
| 5p | 79% | 79% | 0pp |

**That model was wrong.** It injected stochastic noise that *neither* pairing cancels, diluting the difference. At `temp = 0` with greedy decoding, an outcome is near-deterministic given the instance — so within-family variance is mostly **instance-specific difficulty**, which seed-pairing cancels and family-pairing does not. With ICC = 0.3, that is **70% of the difficulty variance**.

Re-simulated with a deterministic threshold model:

| True gap | Seed-paired | Family-paired | Lost |
|---|---|---|---|
| 0.05 | 100% | 18% | **82pp** |
| 0.10 | 100% | 59% | **41pp** |
| 0.15 | 100% | 86% | 14pp |

And it cannot be bought back with corpus size — family-pairing at 480 families reaches 75% where seed-pairing at 272 reaches 100%.

**Seed-level pairing stays.** The probe apparatus stays with it, demoted per R4-S1 and backstopped by secrecy per R4-S2.

**Process lesson:** the first model's noise term was doing the work, and the result looked clean enough to act on. Simulating a second model with different assumptions is what caught it. Two models, not one, whenever a simulation is about to justify deleting a subsystem.

---

## R4-S4 — Surface distance is a fragile proxy for compositional families · **PATCHED**

Round 3 hypothesised that `min_instance_distance` on prompt+skeleton would **invert** for compositional families — passing cosmetic reskins and failing genuinely different tasks.

**Tested. The inversion did not reproduce.** Three instances: same transform set on different code, and different transforms on the same code.

| Comparison | Surface distance | Gate @0.25 | Correct verdict |
|---|---|---|---|
| Same transforms, different code | 0.146 | FAIL | FAIL ✓ |
| Different transforms, same code | 0.331 | PASS | PASS ✓ |

The gate got both right. But look at the margins — 0.146 and 0.331 sit either side of a 0.25 threshold by less than 0.1. Surface distance is a **proxy that happens to correlate when reskins are shallow**; a more aggressive reskin would push a same-lesson instance over the line.

The direct measure is unambiguous:

| Comparison | Transform-set Jaccard |
|---|---|
| Same transforms, different code | **0.00** → correctly fails |
| Different transforms, same code | **1.00** → correctly passes |

**Resolution:** compositional families gate on **transform-set Jaccard distance** as primary, with surface distance retained as a secondary check. Same shape as the [R3-S2](REVIEW-3.md) prompt-vs-reference correction: measure the thing that defines task identity, not a correlate of it.

---

## R4-S5 — `unsafe-core` fits 40 families, but barely, and it raises the category's ICC · **PATCHED**

Miri's confirmed limitations: it cannot interpret foreign code, cannot execute inline assembly, has inherent limits on weak-memory behaviours, and under per-process parallel execution stops detecting cross-test data races. Slowdown is roughly **60×** — a 5-second suite becomes 5 minutes — which independently validates the 30–120 s/unit miri figure used in [R3-S6](REVIEW-3.md).

Miri-checkable task shapes, enumerated: raw-pointer provenance (Stacked/Tree Borrows), `transmute`, `MaybeUninit` and uninitialised reads, `&mut` aliasing violations, use-after-free in custom containers, custom global allocators, self-referential types and `Pin`, union field access, drop order / `ManuallyDrop` / leak checking, references into packed structs, `from_utf8_unchecked` invariants, `NonNull` and niche violations, threads with data-race detection, atomics and ordering (partial), alignment violations, integer-to-pointer casts and strict provenance.

**About 16 distinct shapes.** At 2–3 families per shape that is 32–48 — so 40 is feasible, but it is near the ceiling rather than comfortably inside it.

**The consequence nobody had traced:** if 40 families cluster into ~16 shapes, families *within a shape* are correlated. The category's effective ICC is therefore **higher than the 0.3 assumed corpus-wide**, and its true per-category CI is worse than the ±10.7% claimed in [07-statistics.md](07-statistics.md). At an effective ICC of 0.5 for this category the honest figure is nearer ±12.3%.

**Resolution:** ICC is estimated and published **per category**, not once for the corpus. Phase 3.5 already measures it; the change is to report and use it per category rather than pooling. `unsafe-core` is flagged as the category most at risk of shape-clustering, and its family authoring should deliberately spread across shapes rather than deepening the easy ones.

---

## R4-S6 — Schema drift confirmed mechanically · **PATCHED**

The round-3 process note predicted this. A mechanical diff of identifiers used in prose against [12-schemas.md](12-schemas.md) found **12 genuine schema fields specified in other documents and absent from the schema**:

`diagnostic_completeness`, `classified_rate`, `compile_rate`, `first_failing_input`, `failure_class` extensions, `exit_reason`, `build_overhead_ratio`, `min_reference_distance`, `forbidden_calls`, `max_ratio`, `model_name`, `challenge_nonce`

Most were introduced by rounds 2 and 3 — `diagnostic_completeness` and `classified_rate` are load-bearing outputs of the R2-S2 diagnostic redesign and never reached the schema at all.

**Resolution:** all twelve added. The rule from the round-3 process note is now explicit in [13-architecture.md](13-architecture.md): **any change introducing a field or unit kind patches [12-schemas.md](12-schemas.md) in the same commit.** A mechanical drift check runs in CI.

---

## What survived round 4

- **Seed-level pairing** — attacked directly by R4-S3 and vindicated by it.
- **T1 replay** — untouched. Note that it is *orthogonal* to R4-S1: replay confirms answers are genuinely correct, which is exactly why it cannot detect precomputation. The two controls cover different threats and neither substitutes for the other.
- **Work-unit idempotence** — fourth round of attack, still sound.
- **The two-level plan** ([R3-S1](REVIEW-3.md)) — survives, and is now additionally justified because probe units remain in the design.

---

## Round 5 scope

1. **Quantify the residual leak threat under R4-S2.** A confederate inside an open epoch defeats secrecy. Is per-submitter seed *salting* possible while preserving enough pairing — for instance, pairing only across submitters who share a salt cohort?
2. **The suppression attack applies to any benchmark with a fresh-subset detector.** Check whether it also defeats the canary cross-screen and the plausibility checks in [10-integrity.md](10-integrity.md), which were never modelled adversarially.
3. **Per-category ICC** (R4-S5) may invalidate the core/probe family budgets in [ADR-0008](adr/0008-core-and-probe-categories.md), which assumed a single corpus-wide value.
4. **Nothing in four rounds has attacked the `wild` suite's mining pipeline**, `bench-model`'s token accounting, or the consent/redaction flow.
