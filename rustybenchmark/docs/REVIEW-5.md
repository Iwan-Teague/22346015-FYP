# Adversarial review — round 5

**Date:** 2026-08-18 · **Method:** six attack surfaces run in parallel, each finding independently
re-derived by a separate adversarial verifier instructed to refute it and to rebuild any simulation
from scratch · **Result:** 62 findings raised, **58 survived** verification — 21 severe, 30 moderate,
7 minor.

Three things about this round differ from the previous four.

**It is larger than one patching pass can absorb.** Rounds 1–4 produced 6–16 findings each and were
fully resolved in the same sitting. 58 is not. This document records all of them; the accompanying
commit fixes the cheap and the urgent, and the remainder are filed as open questions with owners.
The gap between "found" and "fixed" is now itself a project risk and is stated as one below.

**Two surfaces had never been attacked and both came back almost entirely broken.** `mining` returned
11 findings and all 11 survived; `plumbing` 11 of 11. A 100% survival rate on first contact means
those areas had received no adversarial attention at all, not that the verifiers were lenient — the
surfaces that *had* been attacked before (`seed-salting` 7/9, `per-category-icc` 5/7) show the
verifiers rejecting findings normally.

**For the third consecutive round, the previous round's fix created the next round's hole.** R3-S1's
probe re-drawability enables R5's `probe-reroll`. R4-S2's seed secrecy is void for the reason in
R5-S2. This is now a pattern rather than a coincidence, and it is addressed in the round 6 scope.

---

## R5-S1 — R4-S3 is wrong, and the decision that rests on it is now open · **PIVOTAL**

**This is the most consequential finding of the five rounds so far**, because roughly half of round
5's severe findings descend from the decision it invalidates.

[R4-S3](REVIEW-4.md) is the sole evaluation of family-level pairing anywhere in the corpus. It
concluded that seed-level pairing beats family-level pairing by up to 82 percentage points, and that
the gap "cannot be bought back with corpus size". Everything downstream descends from that: seed-level
pairing forces a **shared** seed set, a shared seed set forces **secrecy**, and secrecy produces Q19,
the delayed dump, the disabled `rustybench verify`, the epoch-boundary hazard, and — as R5-S2 shows —
a hole that voids the whole arrangement.

An attacking agent reported the figures do not reproduce. Its verifier rebuilt the simulation
independently and agreed. **I then reproduced my own round 4 numbers exactly** (16.8% / 55.4% / 88.3%
against the published 18% / 59% / 86%), which means the arithmetic was never the problem.

The problem is a modelling assumption I never made explicit. Round 4's model implicitly set
**ρ = 0**, where ρ is the share of instance difficulty that is *model-specific* — the model × instance
interaction. At ρ = 0 a given instance is exactly as hard for model A as for model B, so seed-level
pairing cancels instance difficulty **perfectly** and the comparison becomes almost noiseless.

Measured sensitivity, at a 5-point true gap, 272 families × 4 seeds, ICC 0.3, family-level aggregation:

| ρ (model-specific share of instance difficulty) | Seed-paired | Family-paired | Gap |
|---|---|---|---|
| **0.00** — *round 4's implicit assumption* | 100.0% | 16.0% | **84.0pp** |
| 0.10 | 46.7% | 18.3% | 28.4pp |
| 0.25 | 33.9% | 18.3% | 15.5pp |
| 0.50 | 24.3% | 17.5% | **6.8pp** |
| 0.75 | 18.7% | 17.9% | 0.7pp |
| 1.00 | 17.7% | 19.5% | −1.9pp |

**ρ = 0 is physically implausible.** Different models demonstrably fail on different specific
instances within the same family — one trips on a lifetime pattern, another on a trait bound. ρ is
certainly greater than zero, and note that even ρ = 0.1 collapses seed-pairing's own power from 100%
to 47%, so round 4's headline "seed-paired 100%" holds only in the degenerate case.

**ρ has never been measured.** It is directly measurable, cheaply, in Phase 3.5: run two models over
the same seed set and decompose instance-level variance into shared and model-specific components.

**Why this matters more than any single defect below.** If ρ ≥ 0.5, seed-level pairing buys under
7 percentage points, family-level pairing becomes viable, every submitter can be issued **fresh**
seeds, and precomputation becomes impossible by construction. That would dissolve, at a stroke:
R5-S2, R5-S3, R5-S4, R5-S5, `probe-reroll`, `verify-cmd-leak`, `canary-blind-to-leak`,
`uncommitted-epoch-seed`, and open questions Q13, Q16 and Q19 — **nine of the twenty-one severe
findings and three open questions, on one measurement.**

**Resolution.** Measuring ρ is promoted to a **blocking gate in Phase 3.5, ahead of any secrecy
implementation work.** No further engineering on the probe, batch nonces, or seed secrecy until the
number exists. Round 4's process lesson was "two models, not one"; the sharper version is: *when a
simulation justifies a large architectural commitment, name the parameter the conclusion is most
sensitive to and measure it before building on it.*

---

## R5-S2 — Seed secrecy is void: every submitter is handed the epoch master key at t = 0 · **PATCHED**

Round 4 framed the residual threat as *"a submitter who has already run holds the seeds and can leak
them to a confederate"*. **No confederate is needed, and no leak.**

The plan is frozen before execution ([09](09-resume-and-checkpointing.md)), so `plan.json` contains
all 1088 core `(task_id, seed)` pairs **plus `epoch_seed` itself** at step 4 of the 8-step lifecycle
in [08](08-run-protocol.md) — before calibration, before a single unit runs. Generators are public and
generation is deterministic. The oracle ships in the public `tasks/` tree. So the holder of the seeds
and the beneficiary of precomputing them are the same party.

The verifier's sharpening is stronger than the original finding: because core seeds derive as
`blake3(epoch_seed || task_id || i)` and `epoch_seed` sits in `plan.json`, **a completed 60-unit
`smoke` run — 55 minutes, no interruption, nothing anomalous — yields every `deep` seed at every
index for the whole epoch.**

Three compounding defects:

1. **No clock.** The resume validity gates check `plan_hash`, `suite_hash`, `generator_commit`,
   `harness_version`, model config, `exec_class` and hardware fingerprint — **not elapsed time**.
   `completed_at` is client-supplied. Multi-week evening slices are an advertised feature.
2. **No identity.** The server surface in [11](11-submission-and-privacy.md) has no authentication and
   no accounts; the only identifier is a client-minted `machine_uuid`. The "secret" `epoch_seed` is
   served by an unauthenticated endpoint to anyone who asks. Q19's proposed salting remedy
   presupposes a submitter identity to salt against; there is none.
3. **Round 4's own fix was incomplete.** [09](09-resume-and-checkpointing.md) still annotated
   `epoch_seed` as `// public, shared by all submitters`, and [12](12-schemas.md) carried it with no
   secrecy annotation — the two documents an implementer works from. Exactly the drift class R4-S6
   identified, one round later.

**Consequence:** [10](10-integrity.md)'s claim *"Precomputation exposure is bounded to one batch"* is
false for the 85% of units that are scored. Batch nonces gate only the unscored probe.

**Patched now:** the false bound is deleted, `epoch_seed` is no longer annotated public, and the
absence of authentication is stated as a blocking prerequisite. **Not patched:** the architecture. The
real fix is either R5-S1's fresh-seeds route, or never shipping seeds to the client at all — the
server issues rendered instances per batch (~8.5 MB per run, and the server already generates every
instance for T1 replay). That decision waits on ρ.

---

## R5-S3 — The precision ceiling is set by shape count, not family count · **PATCHED**

R4-S5 found that `unsafe-core`'s 40 families span only ~16 miri-checkable shapes and concluded the
category's ICC exceeds the pooled 0.3. Round 5 shows the consequence is structural and worse.

Clustering is **two-level** — shape → family → seed — and the design's statistics are one-level. The
ceiling derived in [ADR-0008](adr/0008-core-and-probe-categories.md) is `F / ICC`; the true ceiling is
governed by **shape** count. **No core category reaches the claimed ±10.7%**, and below roughly 13
shapes the target is unreachable at *any* family budget — buying more families inside an exhausted
shape space buys nothing.

Two further consequences:

- **The specified family-level cluster bootstrap under-covers** once families cluster into shapes, and
  the within-family ICC that Phase 3.5 measures **cannot detect this** — it is invariant to the
  defect. So gate G2 as written measures the wrong quantity.
- `idiom-refactor` is worse than `unsafe-core`: its usable transform catalogue measured at **5 of 35
  candidates** and ~3 distinct lessons, and its clustering is **crossed, not nested**, so no nested
  bootstrap is valid for it at all.

**Patched:** the shape level is now first-class in the statistics doc, G2 is corrected to measure the
shape component, and ADR-0008's budgets are marked provisional pending shape-count audits per category.

---

## R5-S4 — The mining pipeline does not work · **FILED, blocks Phase 7**

Eleven findings, all surviving. The `wild` suite as specified cannot be built.

- **Yield collapse.** Two independently-shaped models agree the suite cannot be mined at the stated
  repo size. Compounding this, the size cap is **2k LoC in three documents and 5k in two others**, and
  the yield answer flips on that value while the context-limit answer flips the other way.
- **The oracle is inside the model's workspace.** For **62–69% of qualifying crates**, Rust's
  convention of `#[cfg(test)] mod tests` in the same file means the mined oracle lives in a file the
  model is asked to edit. This defeats the oracle-isolation control that [03](03-oracle.md) calls
  non-negotiable, in the category where it matters most.
- **Both of ADR-0002's validity claims fail under simulation** — including the synth/wild correlation
  that round 1 called the design's strongest methodological claim.
- **The escape hatch does not exist.** ADR-0002's answer to the weak-oracle problem is to publish a
  purely-synthetic score. No such number is published: neither `capability_score` nor
  `capability_score_lite` excludes both mined categories.
- **`api-evolution` has the wrong sign.** It is simultaneously the memorisation *detector* and a
  positive-weight component of the headline score, and it violates the item-invariance the paired
  design assumes.

Plus: mined families cannot satisfy the ≥1000-seed validation gate; perturbations are α-invariant;
no provenance or licence field exists anywhere (which is also **Q21**, opened today when the repo was
licensed); and `cross-module`'s wall-clock cap makes `capability_score` a function of the machine —
directly contradicting the project's two-number thesis.

---

## R5-S5 — The plausibility checks cannot work · **PATCHED (documented), FILED (redesign)**

Q20 asked whether they survive an adversary. They do not survive a *definition*.

- **The suite is invariant under uniform time rescaling.** It checks the self-consistency of a tuple
  the client wholly controls, with **no external anchor**. Multiply every timestamp by a constant and
  every check still passes.
- **Error-code fingerprinting is under exclusive, deterministic, zero-cost adversary control.** rustc
  phase ordering — which R2-S3 identified as a measurement bias — is the attack primitive.
- **The thermal check contradicts two of the design's own thresholds** and would flag **33–64% of
  honest laptop runs**: the audience the project exists to serve.
- **Five of the six checks are prose with no threshold, no test statistic and no reference data.** They
  cannot be implemented or evaluated as written, so Q20 cannot be closed either way.
- **No alarm budget.** Between **50% and 98% of honest submissions** raise at least one flag, against
  a 1 FTE project and a flag precision near zero.

I am marking these **documented as non-functional** rather than fixed. A check that fires on most
honest users and none of the adversarial ones is worse than no check, because it consumes the one
maintainer's attention and lends false assurance to the badge.

---

## R5-S6 — Measurement plumbing invalidates published metrics · **PATCHED (documented)**

- **Prompt-prefix caching is on by default in the named backends, is unrecorded, and inflates
  `throughput_score` by 8–139%.** Different backends cache differently, so cross-backend comparison is
  invalid as specified.
- **`prefill_ms`/`gen_ms` cannot be obtained over the OpenAI-compatible surface for three of the four
  named backends**, which silently disables the only decode-side plausibility check.
- **Publishing raw calibration numbers defeats hardware bucketing entirely.** The privacy claim in
  [11](11-submission-and-privacy.md) and the integrity plausibility argument in [10](10-integrity.md)
  cannot both be true: the same numbers are either a fingerprint or a control.
- **`machine_uuid` plus per-unit `completed_at`** in the public dump yields a cross-epoch, linkable
  timeline of when the user is at their computer.
- **The T1 artifact bundle carries absolute filesystem paths and the account name**, contradicting the
  consent screen.
- **The three "separate" consents are not separable** — consent two is a precondition for any ranked
  row.
- **The public dump cannot detect any of the three Terminal-Bench misconduct classes it is justified
  by**, which is the entire stated basis for publishing it.
- `time_to_first_pass` has **four defensible readings in repair mode differing by 2.8×**, and the
  natural one makes it a capability metric wearing a machine-metric label.

---

## R5-S7 — Documentation drift is now systemic · **PATCHED**

The mechanical drift check introduced after R4-S6 was necessary but not sufficient. Fifteen
cross-document findings, all surviving. Representative:

- [02](02-task-format.md) and [08](08-run-protocol.md) still carry the **pre-ADR-0009 seed derivation**,
  and 02 restates R2-S1's contradiction verbatim in two adjacent bullets.
- [ADR-0009](adr/0009-paired-core-and-fresh-probe-seeds.md) — the document declaring itself
  authoritative on seed derivation and detection — **still contains the mean-comparison formula R3-S3
  replaced and R4-S1 explicitly flagged as dangerous.**
- [11](11-submission-and-privacy.md) still uploads per-unit seeds and batch nonces to the public
  leaderboard immediately. R4-S2's fix was applied to the dump section **47 lines below** the upload
  list it missed.
- `min_transform_jaccard` (R4-S4's primary anti-twin gate) is in the manifest and the schema but
  **absent from the CI gate list that actually enforces gates**.
- Six documents still quote `deep` as ~39 h / 1200 units after round 4 established 44.5 h / 1088+163.
- Three documents give three different values for the `standard` suite's per-category CI.
- `capability_score` is declared machine-independent in three documents while two others let a machine
  drop a whole category — a 2–4 point machine-dependent shift on the leaderboard's **sort key**.
- Phase 3.5, the hard gate on which all sizing depends, **requires 20 families but only 3 exist at that
  point in the critical path**, and R4-S5's per-category ICC requirement makes the gate circular.

---

## Full inventory

All 58 surviving findings. Severe first, then by surface.

| Finding | Severity | Surface | Title |
|---|---|---|---|
| `probe-reroll` | severe ↓ | cross-doc | Probe slots are freely re-drawable by an adversary-controlled client, which defeats the precomputation detector at zero score cost — strictly cheaper than R4-S1's suppression attack |
| `epoch-seed-in-plan` | severe | cross-doc | R4-S2's seed secrecy is contradicted by the frozen plan: `epoch_seed` — the master key to every core seed in the epoch — is written to the submitter's disk at run start and annotated "public" |
| `leaderboard-publishes-seeds` | severe ↓ | cross-doc | 11-submission-and-privacy.md still uploads per-unit seeds and batch nonces to the public leaderboard immediately — R4-S2's fix was applied to the dump section of the same file but not to the upload list 47 lines above it |
| `p35-family-supply` | severe | cross-doc | Phase 3.5 — the hard gate on which all suite sizing depends — requires 20 families but only 3 exist at that point in the critical path, and R4-S5's per-category ICC requirement makes the gate circular |
| `W1-yield-collapse` | severe ↓ | mining | Two independently-shaped yield models agree: the wild suite cannot be mined at the stated repo size |
| `W2-perturbation-alpha-invariant` | severe ↓ | mining | Mined perturbations are alpha-invariant, and the anti-twin gate's verdict on the whole wild suite depends on an unspecified metric |
| `W3-oracle-inside-model-workspace` | severe | mining | For 62–69% of qualifying crates the mined oracle lives inside a file the model is asked to edit |
| `W4-no-purely-synthetic-number` | severe ↓ | mining | ADR-0002's answer to the weak-oracle problem does not exist: no purely-synthetic score is published, and neither headline number excludes both mined categories |
| `W6-validity-claims-fail` | severe | mining | Both of ADR-0002's validity claims fail under simulation — including the one round 1 called the design's strongest methodological claim |
| `two-level-bootstrap-undercovers` | severe | per-category-icc | The specified family-level cluster bootstrap under-covers badly once families cluster into shapes — and the within-family ICC cannot detect it |
| `shape-ceiling-invalidates-adr-0008` | severe ↓ | per-category-icc | The precision ceiling is set by SHAPE count, not family count — no core category reaches the claimed +/-10.7%, and below ~13 shapes it is unreachable at any family budget |
| `rescale-invariance` | severe | plausibility | The entire plausibility suite is invariant under uniform time rescaling — it checks self-consistency of a tuple the client wholly controls, and has no external anchor |
| `fingerprint-adversary-control` | severe | plausibility | Error-code fingerprinting is under exclusive, deterministic, zero-cost adversary control — rustc phase ordering is the attack primitive, not just a measurement bias |
| `thermal-selfcontradiction` | severe ↓ | plausibility | The thermal-signature check contradicts two of the design's own thresholds, and penalises 33-64% of honest laptop runs — the audience the project exists to serve |
| `prefix-cache-throughput` | severe | plumbing | Backend prompt-prefix caching is on by default, unrecorded, and inflates throughput_score by 8-139% |
| `calibration-defeats-bucketing` | severe ↓ | plumbing | Publishing raw calibration numbers defeats hardware bucketing entirely; the privacy claim and the integrity plausibility argument cannot both be true |
| `dump-cannot-support-audit-claim` | severe ↓ | plumbing | The public dump cannot detect any of the three Terminal-Bench misconduct classes it is justified by |
| `self-confederate` | severe | seed-salting | No confederate is needed: the frozen plan hands every submitter the whole epoch core seed set at t=0, and nothing bounds the clock |
| `no-identity-no-secrecy` | severe ↓ | seed-salting | There is no authentication anywhere in the protocol, so the 'secret' epoch_seed is served to anyone who asks -- and 09 still documents it as public |
| `epoch-boundary-resume` | severe | seed-salting | A deep run cannot fit inside a monthly epoch under the harness's own usage story, and the epoch-close dump publishes the seeds of units not yet run |
| `r4s3-unreproducible` | severe | seed-salting | REVIEW-4 R4-S3's family-pairing power figures do not reproduce; the number that keeps seed-level pairing -- and therefore creates the entire secrecy problem -- appears to use one instance per family |
| `stale-seed-derivation` | moderate | cross-doc | 02-task-format.md and 08-run-protocol.md still specify the pre-ADR-0009 seed derivation, and 02 restates R2-S1's contradiction verbatim in two adjacent bullets |
| `adr9-stale-formula` | moderate | cross-doc | ADR-0009 — the document that declares itself authoritative on seed derivation and detection — still contains the mean-comparison formula that R3-S3 replaced and R4-S1 explicitly flagged as dangerous |
| `standard-row-ci` | moderate | cross-doc | The `standard` suite row computes its per-category CIs with the `deep` suite's design effect, and three documents give three different values for the same quantity |
| `deep-60tps-timing` | moderate | cross-doc | The `deep` suite's @60 tok/s runtime is understated by 41% because the L4 quality layer — cargo-mutants and criterion — was scaled as if it were token-bound |
| `tier-vs-standard-suite` | moderate | cross-doc | 04's family-tier rule excludes at least 64 families — including all 40 of the core `unsafe-core` category — from the `standard` suite, which 07's suite table sizes as running the full 272-family corpus |
| `capability-score-denominator` | moderate | cross-doc | `capability_score` is defined as a fixed 11-category mean and declared machine-independent in three documents, while two others let a machine drop a whole category — a 2–4 point machine-dependent shift on the leaderboard's sort key |
| `jaccard-not-gated` | moderate | cross-doc | `min_transform_jaccard` — R4-S4's primary anti-twin gate for compositional families — is declared in the manifest and the schema but is absent from the CI validation gate list that actually enforces gates |
| `mining-loc-constraint` | moderate | cross-doc | R2-S5's mining fix reached ADR-0004 and roadmap gate G4 but not 04-categories.md or OPEN-QUESTIONS, which still carry the ≤2k LoC filter that R2-S5 proved self-contradictory |
| `W5-api-evolution-wrong-sign` | moderate | mining | `api-evolution` is the memorisation detector and a positive-weight component of the headline at the same time, and it violates the item-invariance the paired design assumes |
| `W7-size-cap-contradiction` | moderate | mining | The mined repo-size cap is 2k LoC in three documents and 5k in two others, and the yield answer flips on it while the context answer flips the other way |
| `W8-timebox-makes-capability-hardware-dependent` | moderate | mining | `cross-module`'s wall-clock cap makes `capability_score` a function of the machine, contradicting the project's own two-number thesis |
| `W9-mined-families-cannot-pass-validation` | moderate ↓ | mining | The ≥1000-seed family-validation gate list is structurally unsatisfiable for mined families, and there is no seed-rejection path after plan freeze |
| `W10-provenance-and-rederivation-dilemma` | moderate | mining | Mined instances carry no provenance or licence field anywhere, and the "independent re-derivation" control cannot cover the wild suite either way |
| `p35-cannot-measure-the-parameter` | moderate | per-category-icc | Phase 3.5 / gate G2 measures a quantity that is invariant to the defect, and cannot estimate the shape component at all |
| `overall-ci-wrong-estimator` | moderate | per-category-icc | The published overall +/-4.1% is computed for a pooled-unit mean, but `capability_score` is defined as an equal-weight mean of category means |
| `idiom-catalogue-measured` | moderate | per-category-icc | `idiom-refactor`'s usable transform catalogue measured at 5 of 35 candidates and ~3 distinct lessons — and its clustering is crossed, not nested, so no nested bootstrap is valid for it |
| `throughput-band-undefined` | moderate | plausibility | Throughput consistency has no stated band, and no constant band can be both honest and useful — context-length decay alone spans 2.6x on the design's reference model |
| `memory-physics-hybrid-hole` | moderate | plausibility | Memory physics is undefined for Hybrid and CpuOnly — the design's own stated majority configuration — and the design's own worked example fails the check by 2.3 GB |
| `canary-empty-and-colliding` | moderate | plausibility | Canary cross-screening has an almost empty true-positive surface, is definitionally blind across submitters, and its 32-bit identifier collides with p=0.48 within five years |
| `alarm-budget` | moderate | plausibility | No alarm budget: 50-98% of honest submissions raise at least one flag, against a 1 FTE project and a flag precision near zero |
| `stale-seed-derivation-02` | moderate | plausibility | 02-task-format.md still carries the pre-R2-S1 seed derivation and restates the contradiction that round 2 declared patched |
| `prefill-gen-unavailable-cross-backend` | moderate | plumbing | prefill_ms/gen_ms cannot be obtained over the OpenAI-compatible surface for three of the four named backends, silently disabling the only decode-side plausibility check |
| `ttfp-undefined-in-repair` | moderate | plumbing | time_to_first_pass has four defensible readings in repair mode that differ by 2.8x, and the natural one makes it a capability metric wearing a machine-metric label |
| `accel-mem-attribution` | moderate | plumbing | peak_accel_mem_mb is device-wide, making the memory-physics plausibility band unsatisfiable, and vram_efficiency is published cross-class while being undefined on unified memory |
| `t1-bundle-leaks-username` | moderate | plumbing | The T1 artifact bundle carries absolute filesystem paths and the user's account name, contradicting the promise on the consent screen |
| `consent-two-is-mandatory` | moderate ↓ | plumbing | The second consent is a precondition for any ranked row, so the 'three separate consents' are not separable |
| `uuid-plus-timestamps-timeline` | moderate ↓ | plumbing | machine_uuid plus per-unit completed_at in the public dump yields a cross-epoch, linkable activity timeline of when the user is at their computer |
| `verify-cmd-leak` | moderate | seed-salting | `rustybench verify <submission.json>` is a documented full-seed-leak channel, and secrecy silently disables the control the integrity design calls strongest |
| `canary-blind-to-leak` | moderate | seed-salting | Canary cross-screening cannot detect a seed leak, because the canary is a deterministic function of the seed |
| `uncommitted-epoch-seed` | moderate | seed-salting | epoch_seed is never committed to, and secrecy converts operator seed-grinding from a theoretical worry into an unobservable private window |
| `stale-deep-suite-numbers` | minor | cross-doc | Six documents still quote the deep suite as ~39 hours and 1200 units after round 4 established 44.5 h and 1088+163 |
| `report-json-stale` | minor | cross-doc | 12-schemas.md's `report.json` example carries round 1's refuted effective-N figure, two conflicting ICC fields, and failure classes absent from the oracle's own enum |
| `glossary-and-count-drift` | minor | cross-doc | GLOSSARY.md, ADR-0001, ADR-0002 and 04's corpus split still carry pre-split counts, and 04 contradicts its own category table on the synthetic/mined ratio |
| `W11-corpus-split-arithmetic` | minor | mining | The published synth/mined corpus split is wrong by 12 families, and two ADRs still carry pre-split numbers |
| `checks-not-specified` | minor | plausibility | Five of the six checks are prose with no threshold, no test statistic and no reference data source — they cannot be implemented or evaluated, so Q20 cannot be closed as written |
| `build-overhead-ratio-blind` | minor | plumbing | build_overhead_ratio omits prefill_ms and grade_ms, so it reads 0.12 'healthy' while 54% of a deep-tier unit's wall clock is not model time |
| `redaction-is-a-denylist` | minor | plumbing | Redaction is specified as a denylist, and R4-S6 already proved that schema fields are added by prose changes without reaching the schema |

Severity marks: ↑ raised by the verifier, ↓ lowered. `probe-reroll` was lowered from severe on the
grounds that the design already concedes the probe is broken — it is listed severe here because it is
strictly cheaper for an attacker than R4-S1's suppression attack, retaining **full** inflation at
**0% detection across 600 trials under two generative models**, where suppression gave back ~2 of 21
points and still leaked 19% detection.

---

## Follow-up pass — what has since been fixed

Round 5's own warning was that 58 findings exceed what one sitting can absorb. A second pass has
closed the arithmetic and drift classes. Fixed since the review was written:

| Finding | What changed |
|---|---|
| `overall-ci-wrong-estimator` | Overall CI recomputed as a **stratified equal-weight category mean** — `Var = (1/121)·Σ Var_c`. `deep` ±4.1% → **±4.9%**, `standard` ±4.8% → **±5.7%**. Pooled and equal-weight effective N are now both published and labelled |
| `standard-row-ci` | The `standard` row used the `deep` design effect inside a 2-seed row. Corrected to DE 1.30: **±12.5%** core, **±22.8%** probe. ADR-0006's third value for the same quantity corrected |
| `deep-60tps-timing` | Decomposed into token-bound (64 s) and fixed (64 s: build+grade ×2, L4 once). `deep` @60 tok/s **20.2 h → 29.7 h**. Also publishes that L4 rises from **31% to 47%** of per-unit cost as hardware gets faster — `deep` is grading-bound on fast machines |
| `tier-vs-standard-suite` | 04's tier rule makes 64 families deep-only (all of `unsafe-core`, plus `perf-optimization` and `cross-module`). `standard` now correctly runs **208 families across 8 categories**, ~11.7 h, ±6.5% |
| `capability-score-denominator` | Denominator is now part of the score's identity: `categories_scored` is published, and **`capability_score_core5`** is the cross-machine key. Three documents that called the score machine-independent are qualified |
| `W4-no-purely-synthetic-number` | **`capability_score_synth`** now exists — the figure ADR-0002 promised and the design never delivered |
| `two-level-bootstrap-undercovers`, `shape-ceiling-invalidates-adr-0008`, `p35-cannot-measure-the-parameter` | Shape → family → seed clustering is now first-class in [07](07-statistics.md); the bootstrap resamples shapes; ADR-0008's budgets marked provisional; G2 corrected to measure the shape component. `idiom-refactor`'s crossed clustering flagged as needing a different estimator |
| `p35-family-supply` | Circular gate broken — author **one core category to its full 40 families first**, then measure ICC, ρ and the shape component on it |
| `W7-size-cap-contradiction` | Standardised on **≤5k LoC** workspace member crates, with the consequence stated: at a measured 10.4–12.3 tokens/LoC that is **52k–62k tokens of source**, so R2-S4's construct-validity argument needs re-deriving and the flat 2k-token timing model is an order of magnitude out |
| `W11-corpus-split-arithmetic`, `glossary-and-count-drift` | Corpus split corrected to **248 synthetic / 24 mined**; GLOSSARY updated to eleven categories and 272 families, with `Core`/`Probe`/`Shape` entries added; ADR-0001/0002/0004 marked superseded-in-part; ADR-0007's async-verification lean replaced with R3-S6's measured conclusion |
| `report-json-stale` | `effective_n` 632 (round 1's refuted figure) → 573 pooled / 408 equal-weight; core-category `n` 150 → 160; duplicate `icc_estimates` removed; `logic` and `constraint` added to the `failure_class` enum and `timeout` moved to `flags` |
| `build-overhead-ratio-blind` | Redefined as **`harness_overhead_ratio`** covering every millisecond that is not the model, with the threshold re-derived (~0.50 at 20 tok/s, ~0.75 at 60) instead of carrying over a flat 0.3 that would fire on every healthy `deep` run |
| `stale-seed-derivation` | 02's single-nonce formula replaced with ADR-0009's two-set derivation, and the two contradictory bullets deleted |

**Still open**, tracked as Q22–Q27 and requiring measurement or a decision rather than an edit:
R5-S1 (ρ), R5-S2 (secrecy architecture), R5-S4 (the mining pipeline's fate), R5-S5 (the plausibility
checks), and the plumbing findings that need backend behaviour confirmed.

---

## What survived round 5

- **T1 replay.** Attacked from three surfaces; unbroken. It remains orthogonal to precomputation —
  replay confirms answers are genuinely correct, which is precisely why it cannot detect an attacker
  whose answers *are* correct.
- **Work-unit idempotence.** Fifth round of attack, still sound.
- **The oracle's five-layer structure and per-category weights.** Not successfully attacked.
- **Solution-first generation** for parametric families. The compositional variant did not fare as
  well — see R5-S3 on `idiom-refactor`.

---

## The finding about the findings

Five rounds have produced 6, 16, 15, 6 and 58 findings. The jump is not because the design got worse;
it is because rounds 1–4 concentrated on the parts that had already been written carefully, and round
5 was the first to attack the mining pipeline, the measurement plumbing, and the consent flow at all.
**Every surface examined for the first time has come back substantially broken.** The reasonable prior
is that surfaces still unexamined — the agentic track, the leaderboard aggregation code, epoch
rotation mechanics, the family-authoring contributor workflow — are in the same condition.

Two structural responses, both more valuable than fixing any individual item:

1. **Stop reviewing and start building.** The design has now been reviewed far past the point where
   review is the binding constraint. Phase 0–3 exist to produce a working spine and one exemplary
   family; almost every remaining uncertainty (ρ, ICC, shape counts, mining yield, transform catalogue
   size, backend timing availability) is a **measurement**, and measurements need code, not more
   documents. Round 6 should follow the first real implementation, not precede it.
2. **The fix-creates-the-next-hole pattern needs a process answer.** Three consecutive rounds found a
   defect created by the previous round's fix. Each was a *local* fix to a *global* invariant. Before
   any further patch, the invariant it touches should be named and checked corpus-wide — which is what
   the schema drift check does for fields, and what nothing currently does for mechanisms.

---

## Round 6 scope

1. **Measure ρ** (R5-S1). Blocking. Everything about secrecy waits on it.
2. **Audit shape counts per category** (R5-S3), and re-derive ADR-0008's budgets from shapes.
3. **Decide the mining pipeline's fate** (R5-S4). The honest options are: drop the `wild` suite,
   or restrict it to permissively-licensed sources with the oracle extracted to a separate file.
4. **Redesign or delete the plausibility checks** (R5-S5). As specified they are net-negative.
5. **Never attacked:** the agentic track, leaderboard aggregation, epoch rotation, the contributor
   workflow, and `bench-stats`' own correctness.
6. **Round 5's own fixes** — per the pattern above, assume at least one created a new hole.
