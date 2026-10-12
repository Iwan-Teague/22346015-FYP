# Adversarial review — round 3

**Date:** 2026-08-17 · **Scope:** the four items deferred by [REVIEW-2.md](REVIEW-2.md), plus a fresh cross-document pass · **Method:** where a question was computable or testable, it was computed or tested rather than argued.

Round 2's most severe finding came from reading two *separately correct* documents together. Round 3 repeated that pass and found the same class of defect again — see R3-S1.

Three of the four deferred items are now settled empirically. Two of those settled **against** the design.

---

## R3-S1 — The frozen plan cannot contain probe units · **PATCHED**

**Severity: architectural.** Introduced by round 2's own fix, and invisible until [09](09-resume-and-checkpointing.md) and [ADR-0009](adr/0009-paired-core-and-fresh-probe-seeds.md) are read together.

[ADR-0009](adr/0009-paired-core-and-fresh-probe-seeds.md) derives probe seeds from `blake3(batch_nonce || task_id || i)`, where `batch_nonce` is issued **during execution**, per batch, with an expiry measured in hours.

[09-resume-and-checkpointing.md](09-resume-and-checkpointing.md) requires the plan — every unit, with its concrete seed — to be **computed and hashed before the first unit runs**, and never re-derived.

Both cannot hold. Four concrete failures:

1. `plan.units[].seed` is undefined for probe units at freeze time.
2. `unit_id = blake3(run_id || task_id || seed || attempt)` therefore cannot be computed for them either.
3. If probe seeds are filled in progressively, `plan_hash` changes on every batch — and `plan_hash` is the first resume validity gate, so **every resume would fail**.
4. Worst: batch nonces **expire**. A segment that ends mid-batch and resumes three evenings later holds probe units whose nonce is dead. The evening-slices story and the precomputation detector are in direct conflict.

**Resolution — a two-level plan, exploiting an asymmetry round 2 created.**

```json
{
  "plan_hash": "blake3:...",        // covers core units + probe SLOT STRUCTURE only
  "core":  [ { "index": 0, "unit_id": "...", "task_id": "...", "seed": 8412739123 } ],
  "probe": [ { "index": 0, "task_id": "...", "batch": 0, "seed": null } ]
}
```

- **Core units** are fully specified and frozen. Epoch-derived seeds are known at freeze time. `plan_hash` covers them completely.
- **Probe slots** carry `task_id` and position but no seed. `plan_hash` covers the slot *structure*, not the seeds.
- On resume, unfinished probe slots in an expired batch are **re-issued a fresh nonce and fresh seeds**.

Point three is what makes this sound, and it is worth stating explicitly: **probe units are re-drawable precisely because they are never scored.** Core units are not re-drawable because they are paired across submitters. The scoring/detection split that round 2 introduced to fix R2-S1 is exactly what makes the resume problem solvable here. The journal records which `batch_nonce` produced each probe unit, so the server can still verify derivation.

---

## R3-S2 — `cargo clippy --fix` solves de-idiomatized tasks outright · **PATCHED**

**Severity: severe.** `idiom-refactor` is a **core, rankable** category with constraint weight 0.60.

Round 2 introduced the compositional archetype: synthesise idiomatic code, apply `de_idiomatize()` inverse transforms, hand the mangled version to the model. Round 3 tested whether the resulting task is actually hard.

**Test.** Three representative transforms — iterator chain → index loop, `Option::map` → `match`, `?` → `match` — hand-written in both forms, with equivalence tests across empty, negative, boundary, and repeated inputs.

**Result 1: the transforms are behaviour-preserving.** All equivalence tests pass. The archetype's invertibility assumption holds.

**Result 2: clippy prints the answer.**

```
src/lib.rs:21:5: warning: unneeded `return` statement
src/lib.rs:16:14: warning: the loop variable `i` is only used to index `v`
src/lib.rs:24:5: warning: manual implementation of `Option::map`: help: try: `m.get(k).map(|x| *x)`
```

The third is not a hint. It is the complete solution, emitted by a tool that ships with the toolchain.

**Result 3: `cargo clippy --fix` solves the task unaided.** Run on the de-idiomatized source with no model involved:

```diff
-    return out;
+    out
-    match m.get(k) { Some(x) => Some(*x), None => None }
+    m.get(k).map(|x| *x)
```

**Two of three transforms auto-solved, equivalence tests still passing.** Only the index-loop→iterator transform survived, because that lint's suggestion is not machine-applicable.

**Why this is severe, in four ways:**

1. A substantial fraction of a core category may be solvable by **one command with zero understanding**.
2. The grading oracle for the category is clippy-dominant. **The oracle and the answer key are the same tool** — we would grade "did you satisfy clippy" using clippy, on code clippy already offered to fix.
3. In `repair` mode the harness feeds L3 constraint violations back to the model *with file:line*. If clippy's `help: try:` text rides along, **attempt 2 receives the literal answer**.
4. In agentic mode the model can simply run the tool.

**Resolution — three changes:**

- **New family-validation gate (#11): `cargo clippy --fix` must not solve the instance.** Run it on every generated instance in CI; if the auto-fixed result converges toward the reference, reject the instance. Mechanical, cheap, and exactly targeted.
- **The transform catalogue excludes inverses that are machine-applicable clippy suggestions.** Clippy's own `Applicability` level is the discriminator, so this is a lookup, not a judgement call.
- **Repair feedback strips suggestion text** for constraint-dominant categories. Lint *name* and location are fed back; `help: try: <code>` is not.

The surviving transform class — those whose inverse clippy can detect but not mechanically apply — is the legitimate task space. It is smaller than round 2 assumed, and family authoring for this category is correspondingly harder.

---

## R3-S3 — The probe detector is 2.4× weaker than it needs to be · **PATCHED**

**Severity: moderate.** Round 2 specified the detector as *"if a submission's probe score is materially below its core score"* — a comparison of means — and guessed 15% of units. Round 1's own lesson was that guessed sample sizes need the effective-N arithmetic applied. It was not applied.

Applying it. Core: 1088 units, ICC 0.3, effective N 573. Probe at 1 seed per family has no clustering penalty, so effective N equals unit count.

**Detector A — compare means (as specified):**

| Probe share | Units | Detectable inflation (80% power, α=0.05) |
|---|---|---|
| 5% | 54 | 19.9 pts |
| 10% | 109 | 14.6 pts |
| **15%** | **163** | **12.4 pts** |
| 30% | 326 | 9.7 pts |
| 50% | 544 | 8.4 pts |

**Detector B — sign test on family-paired discordance.** Draw probe seeds on families *already in core*, then count families where core passed and probe failed versus the reverse. Under honest execution the discordance is symmetric; precomputation makes it one-directional.

At the same 15% (163 paired families), the sign test detects **~5.2 points** of inflation — **2.4× more sensitive** — and is robust to the honest discordance rate (3.7 pts at 10% baseline discordance, 6.3 pts at 50%).

**What a cheater actually gains,** from a 40% baseline:

| Precomputed share of core | Inflation | Detector A (12.4) | Detector B (5.2) |
|---|---|---|---|
| 10% | +6 pts | missed | **caught** |
| 25% | +15 pts | caught | caught |
| 50% | +30 pts | caught | caught |

**Resolution:** the detector is a **sign test on family-paired discordance**, not a comparison of means, and probe seeds are drawn on families already present in core so the pairing exists. Probe share stays 15%.

**The floor is real and must be published.** Even at 50% probe, mean-comparison bottoms out near 8 points; the sign test bottoms out near 4. **Inflation below roughly 4–5 points is undetectable by any probe size we can afford.** The probe is a screening test with a stated sensitivity floor, not a proof of honesty, and the leaderboard should say so rather than implying the badge means more than it does.

---

## R3-S4 — `error-handling` is gradeable only if it stops testing error design · **PATCHED**

**Severity: moderate.** Round 2 hypothesised this category as "hybrid" and left it unvalidated.

**The archetype question resolves cleanly, and favourably.** Families within the category split by shape:

| Shape | Archetype |
|---|---|
| Wire N fallible calls through `?` with a custom error enum and `From` impls | parametric |
| Design an error type given a set of failure modes | parametric |
| Convert a manual `match` chain into `?` | compositional |
| Add a `source` chain / context | parametric |

Archetype is a property of the **family**, not the category. No third archetype is needed, and Phase 3 scope is unchanged.

**But the oracle has a problem round 2 did not anticipate.** Error-handling references are non-unique in a way that reaches *observable behaviour*: many valid error designs differ in variant naming and structure while being equally correct. A differential oracle comparing candidate against reference error output fails on any valid alternative design — the model is penalised for choosing different, correct names.

R2-S7 disabled `size_ratio` for compositional categories on non-uniqueness grounds. This is the same defect one layer deeper: it reaches L2, which carries the weight.

**Resolution:** error-handling families **pin the public error type in the skeleton**. The enum is given; the model implements the plumbing. The differential then compares *which variant* is returned, not how it is spelled.

**The honest consequence:** the category tests error **plumbing**, not error **design**. Choosing a good error taxonomy — arguably the most interesting judgement in Rust error handling — is not gradeable by this oracle and is out of scope. That should be stated in the category definition rather than quietly assumed, and a rename to `error-plumbing` is worth considering for accuracy.

---

## R3-S5 — Gate G5 is unsatisfiable as written · **PATCHED**

**Severity: moderate.** [14-roadmap.md](14-roadmap.md) G5 requires `smoke` to complete in under 90 minutes on 8 GB VRAM. It names hardware but not a model, and the two are not independent.

`smoke` is 60 units single-shot at ~55 s = ~55 min **at 20 tok/s**. But 20 tok/s assumes a model that fits. An 8 GB card running the reference 30B-A3B at Q4 (~19 GB) offloads most layers to host and lands nearer 5–8 tok/s → **2.3 to 3.7 hours**. The gate fails.

With a ~7B Q4 (~4.5 GB, fits fully) at 40+ tok/s, `smoke` finishes in ~30 minutes and the gate passes comfortably.

**Resolution:** every hardware target in the documents states its model. G5 becomes: *`smoke` completes in under 90 minutes on 8 GB VRAM **with a 7B-class Q4 model at `GpuFull`***. The same coupling applies to the pre-run gates in [05](05-hardware-and-calibration.md), which currently reason about `tg128` floors without reference to what is loaded.

---

## R3-S6 — Server-side replay is cheap; verify everything · **RESOLVED, favourably**

Q6 and Q15 assumed replay might need sampling to be affordable. Measured, it does not.

**Measurement.** Warm incremental `cargo build` + `cargo test` + `cargo clippy` cycle, edit-then-rebuild, on Apple Silicon:

| Crate | Time per cycle |
|---|---|
| ~15 lines, 2 tests | 0.68 s |
| ~365 lines, 60 tests | 0.65 s |

It barely scales with crate size — incremental compilation dominates, and the marginal cost of the code under test is close to noise.

**Extrapolated to one `deep` submission** (1088 units; 160 of them `unsafe-core` requiring miri), at a conservative 3 s per non-miri unit to absorb proptest and differential input generation:

| miri cost/unit | CPU-hours per submission | 16-core box, wall | 1000 submissions/month |
|---|---|---|---|
| 30 s | 2.11 | 7.9 min | 2,107 CPU-h |
| 60 s | 3.44 | 12.9 min | 3,440 CPU-h |
| 120 s | 6.11 | 22.9 min | 6,107 CPU-h |

**Conclusion: verify every unit of every submission.** No sampling, no asynchronous badge upgrade, no submitter-funded verification. At a few CPU-hours per submission this is a small cloud bill, not an architectural constraint. **Q6 and Q15 close.**

*Measurement conditions: Apple Silicon, `rustc` 1.97.0, no external dependencies, no proptest in the loop. The 3 s figure carries roughly 4× headroom over what was measured. It should be re-measured against a real family once one exists, but the conclusion has too much margin to be at risk.*

---

## Lower-severity findings

| # | Finding | Resolution |
|---|---|---|
| M3-1 | Probe units absent from every schema in [12](12-schemas.md) — no `set: core\|probe` field, no `batch_nonce` on journal lines | Added; without it the server cannot verify probe seed derivation |
| M3-2 | `de_idiomatize` output readability was raised as a round-3 question; the tested output reads as ordinary novice Rust, not machine-mangled | No action. The transforms that *do* look mangled are largely the machine-applicable ones now excluded by R3-S2 |
| M3-3 | Repair feedback content is specified in [03](03-oracle.md) but not constrained per category | Now constrained — see R3-S2 |
| M3-4 | The sign-test detector needs a baseline discordance estimate to be calibrated, which only exists after real runs | Phase 3.5 already collects the data; add discordance estimation to that experiment's outputs |

---

## What survived round 3

- **Two-archetype generation** ([R2-S6](REVIEW-2.md)). R3-S4 tested the hardest hypothesised case and found no third archetype needed.
- **`de_idiomatize` invertibility.** Empirically confirmed behaviour-preserving across three transform classes.
- **The paired-core / fresh-probe split** ([ADR-0009](adr/0009-paired-core-and-fresh-probe-seeds.md)). Attacked twice — its resume interaction (R3-S1) and its power (R3-S3). Both were fixable within the design; the split itself held, and in R3-S1 it turned out to be what made the fix possible.
- **Work-unit idempotence.** Third round of attack, still sound.

---

## Round 4 scope

1. **The sign-test detector against an adaptive adversary** — one who precomputes only families they predict will be probed, or who deliberately fails core units to flatten the discordance signal.
2. **Whether `min_instance_distance` on prompt+skeleton is measurable** for compositional families, where the skeleton is a transform of the reference rather than an ablation of it.
3. **The `unsafe-core` oracle under miri**, specifically whether miri's own limitations (no `extern` calls, restricted `libc`) leave enough task space for 40 families.
4. **Cross-check the schemas against every document** — R3-S1 and M3-1 were both schema gaps introduced by prose changes, which suggests the schemas are drifting behind the design.
