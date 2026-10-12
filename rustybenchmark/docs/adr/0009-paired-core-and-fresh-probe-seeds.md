# ADR-0009 — Paired core and fresh probe seed sets

**Status:** Accepted · 2026-08-17 · Arising from [REVIEW-2.md](../REVIEW-2.md) R2-S1

## Context

Two corrected documents specified incompatible seed derivation, and the conflict was invisible until they were read against each other.

**[07-statistics.md](../07-statistics.md)** requires every model in an epoch to run the **identical seed set**. Paired comparison via McNemar on discordant pairs is where the 2–4× power gain comes from. Without pairing, separating two models 5 points apart needs ~1,530 effective items per arm — beyond any suite we will ship.

**[10-integrity.md](../10-integrity.md)** derives seeds from a **per-batch, per-run challenge nonce**, specifically so the seeds did not exist before the run was requested and precomputed solutions cannot apply.

Both cannot hold:

- Per-run nonce ⇒ every submitter gets different seeds ⇒ **no pairing** ⇒ the statistical design collapses.
- Per-epoch shared nonce ⇒ public the moment the first submitter receives it ⇒ **precomputation returns**.

## Options

1. **Pairing wins; drop T2.** Seeds fixed per epoch, published. Precomputation possible all epoch. Rotation is the only defence.
2. **Freshness wins; drop pairing.** Per-run nonces, no cross-model comparison, ~4× larger suites needed for the same discriminating power. Unaffordable.
3. **Alternate by epoch.** Some epochs paired, some fresh. Halves the data for both purposes.
4. **Split the seed set within every epoch.**

## Decision

**Option 4.** Every epoch issues two disjoint sets of units.

| Set | Share | Derivation | Role |
|---|---|---|---|
| **Paired core** | ~85% | `blake3(epoch_seed \|\| task_id \|\| i)` — fixed per epoch, identical for every submitter | **Scored.** Cross-model comparison, McNemar pairing, all published figures |
| **Fresh probe** | ~15% | `blake3(batch_nonce \|\| task_id \|\| i)` — per batch, per run | **Never scored.** Precomputation detector |

The reported score comes from the paired core. The probe is a **detector**.

**The detector is a sign test on family-paired discordance, not a comparison of scores.** Probe seeds
are drawn on families *already present in core*, so each probe unit pairs with that family's core
result. Count families where core passed and probe failed against the reverse: honest execution is
symmetric, precomputation is one-directional.

Round 3 measured both designs at the same 15% probe share (163 families):

| Detector | Detectable inflation (80% power, α=0.05) |
|---|---|
| Compare core and probe means (originally specified) | 12.4 pts |
| **Sign test on family-paired discordance** | **~5.2 pts** |

2.4× more sensitive at identical cost, and robust to the baseline discordance rate (3.7 pts at 10%
baseline, 6.3 pts at 50%). A cheater precomputing 10% of core gains ~6 points — missed by the
mean comparison, caught by the sign test.

```
precompute_signal = sign_test(family-paired core-vs-probe discordance)   # R3-S3; NOT a mean comparison
```

Both sets draw from the same families with the same seed-space, so under honest execution the two scores should agree within sampling error. The gap is the signal.

## Consequences

**Good**

- **Pairing is exact.** The full 2–4× power gain is preserved, and it is the reason the suites are affordable at all.
- **Precomputation becomes detectable rather than merely bounded.** Strictly stronger than the original T2: a cheater must now solve the probe honestly *and* match their own inflated core score, which is self-defeating.
- The detector needs no trust in the client and no server-side replay — it is a comparison of two numbers the submitter provides.
- Composes cleanly with batching and with resumable segments: core units need no network, probe units need a batch nonce.

**Bad**

- Epoch seeds are effectively public within the epoch. A determined attacker can precompute the core set for the current epoch — and will be caught by the probe only if they do not also solve the probe. Epoch rotation remains necessary; this does not replace it.
- The probe costs ~15% of every run and produces no score.
- **The probe does not survive an adaptive adversary.** Round 4 simulated precomputation combined
  with deliberate suppression of core units: at 20% precomputation the cheater retains **+9 to +10
  points at 0% detection**. Family-aggregate pairing and probe/core indistinguishability were both
  tested and both failed. The ratio is structural — the cheat pays off across 1088 scored units
  while the detector observes 163 family-level pairs, so hiding is ~6.7× cheaper than the gain.
  **The probe is demoted to a screening test; seed secrecy is the primary control.** See
  [REVIEW-4.md](../REVIEW-4.md) R4-S1 and R4-S2.
- **The detector has an irreducible sensitivity floor, and it must be published.** Even at 50% probe
  share the mean comparison bottoms out near 8 points and the sign test near 4. **Inflation below
  roughly 4–5 points is undetectable at any probe size we can afford.** The probe is a screening test
  with a stated floor, not a proof of honesty, and the leaderboard must say so rather than implying
  the badge carries more assurance than it does.

## Related

This supersedes the seed derivation in [10-integrity.md](../10-integrity.md) T2 and the "seeds are fixed per epoch" statement in [07-statistics.md](../07-statistics.md). Both documents now reference this ADR rather than specifying derivation themselves.
