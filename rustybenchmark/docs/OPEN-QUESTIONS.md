# Open questions

Unresolved as of 2026-08-17. Each needs a decision before the phase that depends on it.

---

## Q1 — License · **DECIDED (harness), OPEN (mined corpus)**

**Blocks:** first public commit.

Generators must be public for the benchmark to be credible, and the raw corpus must be publishable. Candidates: Apache-2.0, MIT/Apache dual (Rust ecosystem norm), or a permissive code license with the task corpus under CC-BY.

Consideration: do we want to discourage the corpus being used as *training data*? A license cannot really prevent it, and a restrictive license would undercut the "publish everything" integrity argument. Probably dual MIT/Apache-2.0 with a stated norm rather than a legal restriction.


**Decided 2026-08-18: [PolyForm Noncommercial License 1.0.0](../LICENSE.md)** for the harness and the
synthetic task corpus. Noncommercial use is free; commercial use requires a separate licence.

This overrides the reasoning above, which leaned toward permissive dual MIT/Apache. The concern
recorded there still stands and is answered rather than dismissed: a restrictive licence must not
undercut the publish-everything integrity argument. It does not, because **re-deriving the
leaderboard from the published dump is not a licensed use of the software** — reading published data
and publishing analysis of it are unrestricted. What the licence does cost is internal commercial
evaluation, which is a real segment of the likely audience. That trade was made deliberately.

**Still open: the mined `wild` corpus.** Task families mined from third-party repositories carry
those repositories' own licences (MIT, Apache-2.0, GPL, and others). Those cannot be relicensed as
noncommercial, and GPL-derived material may not be redistributable alongside a noncommercial harness
at all. Needs resolving before Phase 7, and possibly before any mined family is published:

- per-source attribution and licence tracking in the family manifest
- an allowlist of source licences compatible with redistribution
- possibly distributing mined families as *fetch recipes* (repo + commit + patch) rather than as
  copied source, which sidesteps redistribution entirely

Tracked separately as **Q21**.

---

## Q2 — Mining pipeline design for the `wild` suite

**Blocks:** Phase 7. **Not** Phase 5.

Rust-SWE-bench's pipeline is the model: >1k-star repos, PRs linked to issues and touching tests, Docker + cargo snapshot per PR, execution-based fail-to-pass validation, then human review. Their yield was 500 tasks from ~80k scraped PRs — roughly 0.6%.

Open: can we get a usable yield restricted to *small* commits (3–10 files, **≤5k LoC** workspace member crates — see W7 in [REVIEW-5.md](REVIEW-5.md))? Round 5 found two independently-shaped yield models agreeing that it collapses at the stated size. Superseded in practice by **Q25**, which asks whether the `wild` suite survives at all.

---

## Q3 — How much does `Spec` need to carry per category? · **PARTLY RESOLVED (2 families measured)**

**Blocks:** Phase 3.

`borrow-lifetimes` has an obvious structural parameterisation. `error-handling` and `idiom-refactor` are less obvious — what is the structural axis that a seed varies? Risk: some categories reduce to cosmetic variation and fail the `min_instance_distance` gate.

Mitigation to test in Phase 3: author one family in a *hard* category (suggest `idiom-refactor`) alongside the exemplar, specifically to find out whether the pattern generalises or whether some categories need a different generation strategy.

**Measured 2026-08-19 — two families of deliberately different shape ([BUILD-LOG](BUILD-LOG.md)).**
Answer: **seeding generalises in correctness but not automatically in variance.**

`borrow-lifetimes` (in-place mutation) and `error-handling` (parse → validate → `Result` with `?`)
both pass all five construction gates on every seed, including the load-bearing
reference-passes-its-own-oracle self-consistency check. So solution-first generation (ADR-0003) is not
specific to the tidy exemplar; a genuinely different-shape category produces correct-by-construction
instances too. That half of Q3 is settled.

The anti-twin measurement splits them:

| family | median prompt+skeleton distance | near-twins (<0.25) |
|---|---|---|
| `borrow-lifetimes` | 0.433 | 7/45 |
| `error-handling` | **0.263** | **18/45** |

`error-handling` instances are markedly more similar — median barely above the near-twin floor. The
cause is structural, not a generator defect: the shared boilerplate (the pinned error enum, the
parse-propagate skeleton, the forbidden-API constraint list — see [04](04-categories.md) "tests
plumbing, not error design") dominates the prompt, so the seed-varied fraction of what the model sees
is small. A family whose fixed scaffolding is large relative to its variable surface lands near-twin
*even when all four variance axes are exercised*.

**Consequence for the 272-family plan:** variance must be designed for per family, not assumed from
seeding. The `validate-family` gate already detects the problem in CI; which prevention lever the
corpus adopts (a per-category floor vs. a mandate to enlarge the variable surface) is the remaining
open part, tracked as **Q30**. The operative measure there turned out to be not the near-twin *count*
but the *distinct-at-floor capacity* (window-op 8; error-handling was 3, since widened to ~326) —
pairwise-mutual distance is a far stronger constraint than the median, and it is the real ceiling.

---

## Q4 — Agentic track: in or out?

**Blocks:** nothing near-term; affects Phase 8.

Single-shot and repair measure the model. Agentic measures model + scaffolding, which is what people actually use but is much harder to attribute and multiplies cost. Current position: separate track, separate leaderboard, not in the headline number. Revisit once the core is stable.

---

## Q5 — Which quantisations to canonicalise?

**Blocks:** leaderboard presentation, Phase 6.

If every quant of every model is its own row, the table is unreadable. If they are merged, the numbers are wrong. Options: canonical quant per model (Q4_K_M as the default row, others behind a toggle), or full matrix with aggressive filtering. Leaning toward the former with the latter available.

---

## Q6 — Server hosting and cost · **CLOSED**

**Blocks:** Phase 6.

T1 replay means the server re-runs the oracle for every submitted unit. At 1200 units per `deep` run, that is real CPU. Options: verify a random sample (say 20%) rather than everything, verify everything but queue it asynchronously, or require submitters to fund verification for large suites. Sampling weakens the guarantee; queuing does not. Leaning toward: verify everything, asynchronously, with the tier badge upgrading from T0 to T1 when verification completes.


**Closed 2026-08-17 by measurement** ([REVIEW-3.md](REVIEW-3.md) R3-S6). See Q15.

---

## Q7 — Windows sandbox parity

**Blocks:** Phase 1.

Network denial and memory limits via job objects and WFP are less well-trodden than netns and seatbelt. If parity is not achievable, the options are: Windows runs at a lower trust tier, Windows requires WSL2, or Windows is unsupported at launch. Needs a spike early — it affects a large fraction of the consumer audience.

---

## Q8 — Power telemetry on Apple Silicon

**Blocks:** `efficiency_score` on a major platform.

`powermetrics` requires elevated privileges. Asking users to run the harness with sudo is unacceptable. Options: prompt once for a helper installation, skip `efficiency_score` on macOS, or find a non-privileged source. Default for now: skip and report `null` rather than estimate.

---

## Q9 — Do we run hosted frontier models as reference points?

**Blocks:** Phase 5 report framing.

Arguments for: gives readers an anchor, makes the local-model numbers interpretable. Against: costs money, invites "why is your leaderboard not about frontier models", and their sampling/config is not controllable. Leaning toward: yes, a small number, clearly marked as reference anchors and excluded from the main ranking.

---

## Q11 — What is the async oracle? · **CLOSED**

**Blocks:** authoring `async-concurrency` (Phase 7). Raised by [REVIEW.md](REVIEW.md) S10.

The differential oracle compares candidate and reference outputs on generated inputs. Under nondeterministic scheduling there is no stable output to compare, so the specification as written either produces spurious failures from scheduling variance or degenerates into a compile check.

Working hypothesis: grade on **linearizability properties under loom's exhaustive scheduling** where the state space is small enough, and on `Send`/`Sync`/cancellation-safety **constraints** otherwise — i.e. treat the category as constraint-dominant like `borrow-lifetimes`. Loom's state-space explosion is the binding constraint on how large a task can be.

**Closed 2026-08-25** by shrinking the async surface until the oracle question disappears: [`poll-future`](../crates/bench-gen/src/poll_future.rs) (family #74, category `future-machinery`) grades **single-future poll state machines under a provided deterministic executor**. The skeleton ships a std-only `block_on` (`Waker::noop`, spin-on-`Pending`), so poll order is fixed by construction — outputs are deterministic and the differential comparison is sound without loom. The model's skill is writing `Future::poll` implementations (pending counts, delivered-on-poll-N contracts), not orchestrating concurrency. True multi-task concurrency stays unauthored; if it ever is, the loom/linearizability hypothesis above remains the recorded path.

---

## Q12 — Context limits for `cross-module` · **CLOSED**

**Blocks:** Phase 7. Raised by [REVIEW.md](REVIEW.md) S13.

A 3–10 file, **≤5k LoC** crate plus instructions plus repair diagnostics is **52k–62k tokens of source alone** at a measured 10.4–12.3 tokens/LoC, which exceeds a 32k context outright. Small-context models would be scored on a category they were structurally prevented from attempting, conflating context window with capability.

Options: declare a minimum context per suite and refuse below it; provide a retrieval interface so the model requests files; score `skipped_context` as a separate outcome rather than as failure. Leaning toward the first plus the third — refusing is honest, and a retrieval interface turns the category into an agentic benchmark, which is a different measurement.

**Closed 2026-08-18** by [15-profiles-and-divisions.md](15-profiles-and-divisions.md) §2.4. The gate is
**per category**: each declares `min_effective_ctx`; a category over budget emits `skipped_context`, is
excluded from its own denominator and reported **absent rather than zero**, and the row publishes
`categories_scored`. A run is refused only when a *core* category is unattemptable — the leaning this
question recorded, now with the arithmetic behind it (`cross-module` needs ~90k; Ollama defaults to 4k
on the target hardware band, so a suite-level gate would have invalidated `deep` for the entire
audience).

Preflight probes effective context by binary-searching prompt length until the server errors or
`usage.prompt_tokens` stops tracking the input — which works on silently-truncating backends too.

---

## Q10 — Epoch length

**Blocks:** Phase 6.

Monthly is the working assumption. Shorter epochs mean fresher seeds but fewer models per epoch, which weakens paired comparison. Longer epochs mean better pairing but more precomputation exposure. Needs a decision informed by actual submission volume, so: start monthly, revisit with data.

---

## Q13 — Probe-subset detector power · **CLOSED**

**Blocks:** Phase 6. Raised by [REVIEW-2.md](REVIEW-2.md) R2-S1 / [ADR-0009](adr/0009-paired-core-and-fresh-probe-seeds.md).

The fresh-probe subset (~15% of units) detects precomputation by comparing probe score to core score. But 15% of a `deep` run is ~163 units, clustered by family — so its effective N is well under 100, and the same design-effect arithmetic that governs scoring applies to the detector.

Unvalidated: can a gap of the size a cheater would produce be distinguished from ordinary sampling noise at useful confidence? The 15% figure is provisional and should be derived from a power calculation on the detector, not chosen for looking reasonable.


**Closed 2026-08-17 by calculation** ([REVIEW-3.md](REVIEW-3.md) R3-S3). The power arithmetic was
done. At 15% probe the originally specified score-comparison detects only **12.4 points** of
inflation; a **sign test on family-paired discordance** detects **~5.2 points** at identical cost.
The detector is now the sign test, and probe seeds are drawn on families already present in core so
the pairing exists. 15% stands.

**Residual, published rather than hidden:** inflation below roughly **4–5 points** is undetectable at
any probe share we can afford. The probe is a screening test with a stated floor.

---

## Q14 — Are `de_idiomatize` transforms invertible in practice? · **CLOSED, badly**

**Blocks:** authoring `idiom-refactor` (Phase 5). Raised by [REVIEW-2.md](REVIEW-2.md) R2-S6.

Each clippy lint has a conceptual inverse, but applying several mechanically may produce code that reads as obviously machine-mangled rather than as plausible human-written non-idiomatic Rust. A prompt that looks generated is a prompt models will treat differently — and possibly one they pattern-match to "this is a benchmark" rather than reasoning about.

Needs a Phase 3 spike alongside the exemplar family: generate 20 instances, have a Rust developer judge whether they read as plausible real code.


**Closed 2026-08-17 by test** ([REVIEW-3.md](REVIEW-3.md) R3-S2). Two answers.

**Invertibility: yes.** Three transform classes (iterator→index loop, `Option::map`→`match`,
`?`→`match`) round-trip with identical behaviour across empty, negative, boundary, and repeated
inputs. The output reads as ordinary novice Rust, not machine-mangled.

**But the task is not hard.** `cargo clippy --fix` solved **2 of the 3** unaided, with equivalence
tests still passing — clippy's `help: try:` text on machine-applicable lints *is* the answer. This
compromised a core, rankable category. Three fixes landed: a new family-validation gate (`clippy
--fix` must not solve the instance), exclusion of machine-applicable inverses from the transform
catalogue, and stripping suggestion text from repair feedback.

The legitimate task space is the transform classes clippy can *detect but not mechanically apply*.
It is smaller than assumed, and authoring for this category is correspondingly harder.

---

## Q15 — Server-side replay cost under the corrected timing model · **CLOSED**

**Blocks:** Phase 6. Supersedes part of Q6.

Q6 was written before the round-1 timing correction. A `deep` run is 1088 scored units, and T1 replay re-runs L0–L3 for every one. At corrected build-and-grade costs this is materially more server CPU than Q6 assumed. Re-derive before committing to "verify everything asynchronously".


**Closed 2026-08-17 by measurement** ([REVIEW-3.md](REVIEW-3.md) R3-S6). A warm `cargo build` +
`test` + `clippy` cycle measures **0.65–0.68 s** and barely scales with crate size (0.68 s at 15
lines / 2 tests; 0.65 s at 365 lines / 60 tests) — incremental compilation dominates. At a
conservative 3 s per non-miri unit, one `deep` submission costs **2.1–6.1 CPU-hours** depending on
miri cost, or under 23 minutes wall on a 16-core box.

**Decision: verify every unit of every submission.** No sampling, no asynchronous badge upgrade, no
submitter-funded verification. A small cloud bill, not an architectural constraint.

---

## Q16 — Does the sign-test detector survive an adaptive adversary? · **CLOSED — it does not**

**Blocks:** Phase 6. Raised by [REVIEW-3.md](REVIEW-3.md) round 4 scope.

R3-S3 computed the detector's power against a *naive* cheater who precomputes a random subset. An adaptive one has options: precompute only families they predict will be probed, or deliberately fail some core units to flatten the discordance signal and stay under the threshold.

The second is the interesting one, because it is self-limiting — suppressing core passes to hide inflation gives back the points the inflation bought. Needs the arithmetic done properly: is there a strategy that nets a gain while staying below the ~5-point detection floor?


**Closed 2026-08-17 by simulation** ([REVIEW-4.md](REVIEW-4.md) R4-S1). **No.** An adversary who
precomputes *and* deliberately fails core units to rebalance the discordance keeps **+9 to +10 points
of inflation at 0% detection** (20% precomputation, 300 trials). Family-aggregate pairing and
probe/core indistinguishability were both tested; both failed.

The ratio is structural: the cheat pays off across 1088 scored units while the detector observes 163
family-level pairs, so hiding is ~6.7× cheaper than the gain. No test statistic fixes that.

**Consequence:** the probe is demoted to a screening test and **seed secrecy becomes the primary
control** — core seeds are not published until their epoch closes. The self-cancelling intuition that
suppression must cost what it gains is wrong, and was only caught by simulating rather than trusting
the algebra.

---

## Q17 — Is `min_instance_distance` measurable for compositional families? · **CLOSED**

**Blocks:** authoring `idiom-refactor` (Phase 5). Raised by [REVIEW-3.md](REVIEW-3.md) round 4 scope.

For parametric families the skeleton is an *ablation* of the reference, so prompt-to-prompt tree-edit distance is well defined. For compositional families the skeleton is a *transform* of the reference, and two instances applying the same three transforms to different code may be structurally near-identical by tree-edit distance while being genuinely different tasks — or the reverse.

The gate may be measuring the wrong thing for half the corpus. Needs validation against real generated instances before the gate is trusted for compositional families.


**Closed 2026-08-17 by test** ([REVIEW-4.md](REVIEW-4.md) R4-S4). The hypothesised *inversion* did
not reproduce — surface distance returned the correct verdict on both probes. But the margins were
0.146 and 0.331 either side of a 0.25 threshold, where transform-set Jaccard gives an unambiguous
0.00 and 1.00. Surface distance is a correlate that holds only while reskins are shallow.

**Resolution:** compositional families gate on `min_transform_jaccard` as primary, surface distance
secondary.

---

## Q18 — Does miri leave enough task space for 40 `unsafe-core` families? · **CLOSED — barely**

**Blocks:** Phase 7. Raised by [REVIEW-3.md](REVIEW-3.md) round 4 scope.

R3 split `unsafe-ffi` because miri cannot execute foreign calls, moving FFI to a probe category and keeping `unsafe-core` as a core category with miri mandatory. But miri has further limitations — restricted `libc`, no real syscalls, some `std` internals unsupported — and `unsafe-core` needs **40 families**, the full core budget.

If miri-checkable unsafe Rust does not span 40 genuinely distinct family shapes, the category either shrinks below core size or admits families miri cannot check, which defeats the split. Needs a feasibility survey before P7.


**Closed 2026-08-17 by survey** ([REVIEW-4.md](REVIEW-4.md) R4-S5). About **16 distinct
miri-checkable shapes** exist (provenance, transmute, `MaybeUninit`, `&mut` aliasing, use-after-free,
custom allocators, `Pin`, unions, drop order, packed refs, `from_utf8_unchecked`, `NonNull`, threads
and data races, atomics (partial), alignment, int-to-ptr provenance). At 2–3 families per shape that
is 32–48 — so 40 fits, but near the ceiling.

**The consequence that matters:** 40 families across ~16 shapes means families cluster, so the
category's effective **ICC exceeds the corpus-wide 0.3** and its honest CI is nearer ±12.3% than the
±10.7% claimed. ICC is now estimated and published **per category**, not pooled. Miri's ~60×
slowdown independently validates the 30–120 s/unit figure used in [R3-S6](REVIEW-3.md).

---

## Process note — schema drift

Both R3-S1 and M3-1 were schema gaps created by prose changes in other documents: probe units were specified in [ADR-0009](adr/0009-paired-core-and-fresh-probe-seeds.md) and [10-integrity.md](10-integrity.md) without ever reaching [12-schemas.md](12-schemas.md), and the resulting contradiction with the frozen plan went unnoticed for a full review round.

**The schemas are drifting behind the design.** Round 4 should cross-check [12-schemas.md](12-schemas.md) against every other document, and thereafter any change introducing a new field or unit kind must patch the schema in the same commit.

---

## Q19 — Can seed secrecy survive a confederate inside an open epoch?

**Blocks:** Phase 6. Raised by [REVIEW-4.md](REVIEW-4.md) R4-S2.

Seed secrecy is now the primary precomputation control, but a submitter who has already run holds the epoch's core seeds and can pass them to a confederate before the epoch closes.

Open: is per-submitter seed **salting** possible while preserving enough pairing — for example, pairing only across submitters who share a salt cohort, accepting a smaller effective comparison set in exchange for removing the leak channel? Needs the power arithmetic doing on cohort sizes.

---

## Q20 — Do the plausibility checks survive the same suppression attack?

**Blocks:** Phase 6. Raised by [REVIEW-4.md](REVIEW-4.md) round 5 scope.

R4-S1 showed a fresh-subset detector is defeated by an adversary willing to throw units. The plausibility checks in [10-integrity.md](10-integrity.md) — throughput consistency, memory physics, thermal signature, error-code fingerprint, canary cross-screening — have **never been modelled adversarially at all**. They were designed against carelessness, not against someone optimising against them.

---

## Q21 — Licence compatibility for the mined `wild` corpus

**Blocks:** publishing any mined family (Phase 7, possibly earlier).

The harness is PolyForm Noncommercial 1.0.0 (Q1). Mined task families derive from third-party repositories under their own licences and cannot be relicensed. GPL-derived material in particular may not be redistributable alongside a noncommercial harness.

Options: an allowlist of permissively licensed sources only; per-family attribution and licence metadata; or distributing mined families as **fetch recipes** (repo URL + commit SHA + patch) so no third-party source is redistributed at all. The last is the cleanest and also reduces the corpus size, at the cost of requiring network access at family-materialisation time — which conflicts with the offline sandbox guarantee in [08-run-protocol.md](08-run-protocol.md) unless fetching happens during preflight.

---

## Q22 — Measure ρ, the model × instance interaction · **BLOCKING**

**Blocks:** every secrecy decision, and Q13/Q16/Q19 are all contingent on it. Raised by [REVIEW-5.md](REVIEW-5.md) R5-S1.

ρ is the share of instance difficulty that is **model-specific** — whether a given instance is equally hard for two different models, or differentially hard. Round 4's R4-S3 implicitly assumed **ρ = 0** and concluded seed-level pairing beats family-level pairing by 82 percentage points. At ρ = 0.5 the gap is **6.8pp**; at ρ = 0.75 it is **0.7pp**. ρ = 0 is physically implausible, and even ρ = 0.1 collapses seed-pairing's own power from 100% to 47%.

**Measurement:** run two models over the same seed set in Phase 3.5 and decompose instance-level variance into shared and model-specific components. Cheap — the runs are already planned.

**Why it is the highest-value question in the corpus:** if ρ ≥ 0.5, family-level pairing is viable, every submitter gets fresh seeds, precomputation becomes impossible by construction, and nine of round 5's twenty-one severe findings plus Q13, Q16 and Q19 dissolve at once.

**No further engineering on the probe, batch nonces, or seed secrecy until this number exists.**

---

## Q23 — Authentication and submitter identity · **BLOCKING secrecy**

**Blocks:** Phase 6. Raised by [REVIEW-5.md](REVIEW-5.md) R5-S2.

The server surface has no authentication, no accounts, and no submitter identity; the only identifier is a client-minted `machine_uuid`. Consequences: the "secret" `epoch_seed` is served by an unauthenticated endpoint to anyone who asks; rate limits bind to a value the client mints; and Q19's salting remedy has nothing to salt against.

Contingent on Q22 — if fresh per-submitter seeds become viable, the requirement weakens considerably but does not vanish (rate limiting and T3 audit still want identity).

---

## Q24 — Shape-count audit, and re-derive ADR-0008 from shapes

**Blocks:** corpus scale-up. Raised by [REVIEW-5.md](REVIEW-5.md) R5-S3.

Clustering is two-level (shape → family → seed); the statistics are one-level. The precision ceiling is governed by **shape** count, not family count, so **no core category reaches the claimed ±10.7%**, and below ~13 shapes the target is unreachable at any family budget.

Needed: an enumerated shape audit per category; a two-level bootstrap; a corrected gate G2 that measures the shape component (the current within-family ICC is invariant to the defect); and re-derived family budgets. Note `idiom-refactor`'s clustering is **crossed, not nested**, so no nested bootstrap is valid for it — it may need a different estimator or a different category design.

---

## Q25 — Does the `wild` mined suite survive at all?

**Blocks:** Phase 7. Raised by [REVIEW-5.md](REVIEW-5.md) R5-S4, and interacts with Q21.

Eleven findings, all surviving verification. Yield collapses at the stated repo size; the size cap is inconsistent across five documents and the answer flips on it; **for 62–69% of qualifying crates the mined oracle lives inside a file the model is asked to edit**, defeating oracle isolation; both of ADR-0002's validity claims fail under simulation; and the purely-synthetic escape-hatch score ADR-0002 promises is not actually published anywhere.

Honest options: drop the `wild` suite; or restrict to permissively-licensed sources with the oracle mechanically extracted to a separate file, and accept a much smaller family count. Deciding to drop it would also close Q21.

---

## Q26 — Redesign or delete the plausibility checks

**Blocks:** Phase 6. Supersedes Q20, which is now answered: they do not survive.

The suite is **invariant under uniform time rescaling** and has no external anchor. Error-code fingerprinting is under deterministic, zero-cost adversary control. The thermal check contradicts two of the design's own thresholds and would flag **33–64% of honest laptop runs**. Five of six checks have no threshold, no test statistic and no reference data. **50–98% of honest submissions raise at least one flag**, at a flag precision near zero, against a 1 FTE project.

A check that fires on most honest users and none of the adversarial ones is worse than no check. Either give each one an external anchor and a stated threshold with a measured false-positive rate, or delete it and say the hardware numbers are unverified.

---

## Q27 — Prompt-prefix caching and cross-backend timing comparability

**Blocks:** any published throughput number. Raised by [REVIEW-5.md](REVIEW-5.md) R5-S6.

Prefix caching is on by default in the named backends, is unrecorded, and inflates `throughput_score` by **8–139%**. Backends cache differently, so cross-backend comparison is invalid as specified. Separately, `prefill_ms`/`gen_ms` cannot be obtained over the OpenAI-compatible surface for three of the four named backends, which silently disables the only decode-side plausibility check.

Options: require cache-disabling flags where the backend supports them and record the setting; or abandon cross-backend throughput comparison and scope `throughput_score` to within-backend only.

---

## Q28 — Define the pass predicate on `task_score` · **DECIDED (structural pass)**

**Blocks:** `bench-stats`, and three published metrics. Raised by [REVIEW-6.md](REVIEW-6.md).

`task_score` is continuous on [0,1] — a weighted mean of five oracle layers. **No pass/fail predicate is defined anywhere in 26 documents.** Simulated at the documented default weights: 97,838 distinct values, P(score = 0) = 47.5% (the L0/L1 gate), **P(score = 1.0) = 0.0%**.

Six consumers each currently assume their own implicit threshold: `throughput_score` ("tasks passed per hour" — uncomputable as written), `time_to_first_pass`, McNemar model comparison, the sign-test detector, the probe discordance calibration, and `budget_exhausted_rate`.

Defining it once will silently change all six. An analyst sweeping plausible cuts gets **23.3% type-I error** and can move the reported effect size by a median 7 points, so the cut must be pre-registered, not chosen.

**Decided 2026-08-20: a structural pass predicate, not a threshold on `task_score`.** A task passes iff it
**applied ∧ compiled ∧ behaviour == 1.0 ∧ (unsafe_ok ∧ paths_ok ∧ alloc_ok)** — where an L3 constraint the
family did not declare (`None`) is not a barrier, and quality (clippy/fmt, L4) is excluded. This is binary,
**weight-independent** (re-tuning composite weights cannot move pass rates, which kills the swept-cut type-I
inflation), and pre-registered by construction because it is a definition of "correct", not a tuned number.
A clone-everything answer fails `borrow-lifetimes` by the constraint clause — the category thesis enforced
as a hard fact. The continuous `capability_score` stays the headline; `passed` feeds only the six binary
consumers. Implemented as `OracleVector::passed()` in `bench-core`; specified in
[07-statistics.md](07-statistics.md#the-pass-predicate).

---

## Q29 — The statistical machinery is undefined, not mis-tuned · **DECIDED**

**Blocks:** `bench-stats` (roadmap P4). Raised by [REVIEW-6.md](REVIEW-6.md).

Four things `bench-stats` is specified to compute have no specification:

1. **The core-seed collapse rule** for the sign test. `deep` runs 4 core seeds per family against 1 probe seed. The null holds **only** if the collapsed bit is marginally distributed as a single seed — proven closed-form, `E[b]−E[c] = E[P(B=1|p)] − E[p]`. Every deterministic k>1 rule breaks it: measured honest-run false-accusation rates of **100%** (`any`), 53.7% (`majority`), 4.2% (pick-one).
2. **The ICC estimator.** Unspecified, and the natural one returns negative values often enough to publish CIs *tighter than an independent sample*.
3. **The bootstrap unit.** [07](07-statistics.md) declares clustering two-level and makes the bootstrap resample shapes, but the CI-computation section 180 lines later still specifies family-level resampling, and the design-effect formula was never updated — so every published effective N assumes the one-level model the same document rejects.
4. **Multiplicity.** No correction anywhere, against 11 category scores plus model-vs-model comparisons. Family-wise error rate on the radar chart alone: **94–99%**.

Additionally the percentile cluster bootstrap **under-covers at every per-category cluster count** — 92% at a core category, 84% at `idiom-refactor` — against a nominal 95%.

---

## Q30 — Anti-twin variance is per-family, not global

**Blocks:** Phase 3 corpus authoring — the `min_instance_distance` each family must clear. Raised by
the two-family measurement in **Q3** / [BUILD-LOG](BUILD-LOG.md).

Inter-instance distance depends heavily on how much fixed scaffolding a family carries. `error-handling`
sits at median 0.263 with 18/45 near-twin pairs against `borrow-lifetimes`' 0.433 / 7-of-45, purely
because a pinned error enum plus a parse-propagate skeleton is most of what the model sees. A single
global `min_instance_distance = 0.25` therefore means very different things across categories:
comfortable headroom for a low-scaffold family, a knife-edge for a high-scaffold one.

Undecided — which lever, or both:

1. **Per-category floor.** Set `min_instance_distance` per category — higher where scaffolding is
   naturally small, lower (with written justification) where the fixed public interface is
   intentionally large. Risk: a low floor licenses genuinely memorisable families.
2. **Force variable surface.** Keep one global floor and require scaffolding-heavy families to enlarge
   their seed-varied surface — more combine ops, more validation rules, deeper composition — until they
   clear it. Risk: inflates authoring cost for exactly the categories already hard to parameterise
   (`error-handling`, `idiom-refactor`).

Second-order problem the measurement also exposed: within a single epoch's *N* paired-core seeds,
nothing currently *guarantees* *N* structurally distinct draws. A finite variant space can collide,
producing near-twins inside one run regardless of the family's average distance. A distance-aware epoch
sampler — reject a candidate seed too close to an already-chosen sibling — fixes that independently of
the floor decision.

**That sampler is now built** (`bench_gen::epoch`, [BUILD-LOG](BUILD-LOG.md) 2026-08-20), and running
it turned the soft near-twin-pair count into a hard ceiling. Its **distinct-at-floor capacity** — the
most pairwise-≥0.25 instances a family can actually serve — is:

| family | median distance | near-twin pairs | **distinct-at-floor capacity** |
|---|---|---|---|
| `borrow-lifetimes` (window-op) | 0.433 | 7/45 | **8** |
| `error-handling` | 0.263 | 18/45 | **3** |

Pairwise-mutual distance is a far stronger constraint than the median, so capacity is *much* lower than
either headline number implies: a family whose median looks healthy can seat only a handful of
genuinely distinct tasks. This reframes the decision above — capacity is a hard ceiling on how many
memorisation-resistant epochs a family can sustain before it must repeat an instance. `window-op`'s 8 is
workable but tight; `error-handling`'s 3 is unusable, so **lever 2 was applied to it** (below). Every
family authored in Phase 3 must report a capacity comfortably above the intended per-epoch seed count,
or be enlarged until it does.

**Lever 2, applied and measured ([BUILD-LOG](BUILD-LOG.md) 2026-08-20).** `error-handling`'s variable
surface was widened — combine operations 3 → 5, validation rules 3 → 6 (12 rule-instances counting
bounds), and the worked examples in the prompt/skeleton are now seed-varied. Result:

| `error-handling` | median | near-twin pairs | distinct-at-floor capacity |
|---|---|---|---|
| before | 0.263 | 18/45 | 3 |
| after | **0.438** | **0/28** | **~326** |

All five construction gates still pass (reference still scores 1.000 — the enlargement kept it
correct-by-construction). One honest caveat: the ~326 is *view*-capacity, and part of the lift is the
seed-varied example text, which the shingle metric rewards. That variation legitimately freshens each
prompt against exact-text memorisation, but it is not skill diversity — the genuine distinct-*logic*
surface is the 5 × 12 = 60 combine/rule combinations. Both numbers (60 skills, ~326 views) sit
comfortably above any per-epoch seed count, which is the bar; the lift is real, not purely metric-gaming,
since same-logic pairs are still often rejected (acceptance ran ~22%, not ~100%).

This is one worked instance of lever 2, not a decision that lever 2 is the standard. The global choice —
per-category floor vs. mandated surface width — is still open. Decide before authoring beyond the
exemplar families. The gate now both *detects* the problem in CI and *prevents* it at serve time
(`validate-family` reports median/near-twins **and** the epoch sampler's capacity; the sampler refuses
to serve a twin, returning `Exhausted` instead).

> **Correction (same day).** The ~326 above is *view*-capacity and it is largely illusory — see
> **Q31**. Measuring capacity on the **reference** (the solution) instead of the prompt gives
> `error-handling` a capacity of **7**, not 326: the seed-varied examples freshen the prompt without
> changing the answer. The honest reading is that widening the surface bought *contamination-resistance*
> (fresh prompts) but very little *solution diversity*. The lever-2 story stands as far as it goes;
> what it does **not** do is make `error-handling` a high-diversity family. Treat the capacity numbers
> in the table above as view-capacity throughout.

---

## Q31 — The text-distance anti-twin metric is unreliable; task identity is structural · **DECIDED (two gates)**

**Blocks:** the `min_instance_distance` gate design, and every family's reported capacity. Found
2026-08-20 while widening `window-op` ([BUILD-LOG](BUILD-LOG.md)).

`min_instance_distance` is measured as token-shingle distance on the **prompt + skeleton** — what the
model sees. Widening the two exemplar families exposed that this measure is unreliable in *both*
directions, so a family can pass it while being memorisation-vulnerable, or fail it while being fine:

- **It over-counts (gameable up).** Seed-varying the worked examples makes every prompt textually
  distinct without changing the task. `window-op` then saturates: **100 % of raw-index seeds are
  accepted**, view near-twins `0/28`, view-capacity effectively unbounded — purely from random example
  arrays. A lazy family author could pass the gate with *zero* structural variety just by randomising
  example numbers.
- **It under-counts (deflated down) on the reference.** Measured on the solution instead, two references
  that differ only in a constant (`n <= 10` vs `n <= 50`) or one expression read as near-twins even
  when the underlying skill differs, because 80–90 % of the text is shared plumbing.

Measured both ways at the 0.25 floor:

| family | view near-twins | view-capacity | **reference near-twins** | **reference-capacity** |
|---|---|---|---|---|
| `window-op` | 0/28 | saturated (≈∞) | 1/28 | **22** |
| `error-handling` | 0/28 | ~250–326 | **12/28** | **7** |

The reference-capacity is the honest *anti-memorisation-of-solution* number, and it is brutal:
`error-handling` serves only **7** genuinely-distinct solutions. Neither text measure is the true
diversity, which is the **structural spec count** — the `(combine, rule, …)` tuple the generator draws
from (≈60 for `error-handling`, though many collapse under any text metric). The generator *knows* the
spec; the text distance is a lossy proxy for it.

Options:

1. **Measure anti-twin distance on the reference (solution), not the prompt.** Directly targets
   memorisation-of-solution and is not gameable by example noise. Cost: deflated by boilerplate, so it
   under-counts and would reject families that are actually fine — needs a lower, per-family floor, which
   loops back into Q30.
2. **Measure on the structural spec directly** (a canonical serialisation of the `(combine, rule, op,
   stride, …)` tuple, Jaccard over its parts — the generalisation of R4-S4's transform-set metric to all
   parametric families). This *is* task identity, is neither inflatable nor deflatable by text, and makes
   "distinct-at-floor capacity" mean exactly "number of distinct task specs." Cost: each family must
   expose its spec to the gate (a small trait method), and the metric no longer sees the model's actual
   view, so **keep the view metric too**, for a different purpose (contamination-resistance: has the
   model seen this exact prompt).
3. **Two gates, two purposes.** View-distance guards *verbatim-recall* (fresh prompts each epoch);
   spec-distance guards *solution-diversity* (enough genuinely different tasks). A family must clear
   both. This is probably the right end state.

Until resolved, `validate-family` reports **both** view- and reference-distance and both capacities so
the gap is visible, and the epoch sampler still serves on view-distance (which, post-finding, means it
rarely rejects anything — its guarantee is real but currently near-vacuous for these two families).
The capacity regression tests are pinned on **reference**-capacity, the honest number.

**Decided 2026-08-20: option 3 — two gates, two purposes.**

- **Spec-distance = task diversity.** Each generator now exposes `spec_signature(seed)` — the structural
  choices that define the *skill*. `spec_diversity(gen, n)` counts distinct signatures; that count is the
  authoritative, ungameable diversity number a family is authored against. `validate-family` reports it.
- **View-distance = contamination-resistance.** Kept as-is: it guards against serving a prompt the model
  may have seen verbatim, which is a real and separate purpose. The epoch sampler continues to serve on
  it so within-epoch prompts stay fresh.
- Reference-distance stays reported as a diagnostic (it is what first exposed the gap) but is not a gate.

**Granularity decision (the sub-question):** the spec-signature includes the operation kind, the rule
*type*, and the stride pattern, but **excludes numeric constants** — `AtMost(10)` and `AtMost(50)` are
the *same skill* with a different constant, so they share a signature. Constants still vary the prompt,
so they still count toward contamination-resistance under the view gate; they just do not inflate the
diversity count. Measured under this rule: `window-op` = **12** distinct skills (6 ops × 2 strides),
`error-handling` = **30** (5 combines × 6 rule-types). Both clear any per-epoch seed count, both pinned
as regression tests.

**Still open, downstream — but now with a provisional floor.** The per-family *floor* — the minimum
spec-diversity a family must clear to ship — is not yet *finally* fixed; it depends on the per-epoch seed
count chosen in Phase 4, and it folds back into
[Q30](#q30--anti-twin-variance-is-per-family-not-global). A **provisional floor of 8** (docs/17's
"comfortably above 8") is now enforced generically in CI as `bench_gen::MIN_SPEC_DIVERSITY`, asserted over
every family in `FAMILY_IDS` ([BUILD-LOG](BUILD-LOG.md) 2026-08-21) — so a too-narrow family fails
`cargo test` today, and the constant is the single place to raise once Phase 4 sets the real value. Every
family currently ships at ≥ 12.

**Spec-collision rejection — built ([BUILD-LOG](BUILD-LOG.md) 2026-08-20).** `bench_gen::epoch` now has
`plan_epoch_distinct_skills`, which serves `n` seeds covering `n` *distinct* skills (rejects a candidate
whose spec-signature is already served, and still enforces view-distance for freshness). It `Exhausted`s
if the family has fewer than `n` distinct skills — the loud signal that a family is too narrow for the
requested per-epoch count. `validate-family` demonstrates it, and a test cross-checks that window-op
serves exactly its 12 skills and no more. `EpochPlan` carries the served `specs` and a `distinct_skills()`
count.

> **New tension this exposes, for Phase 4/P3.5 to resolve.** "One seed per skill per epoch" maximises
> coverage, but the ICC / repeated-measures design (docs/07) may want *several* seeds of the **same**
> skill within a run to estimate within-skill score variance. These are different serving policies for
> different purposes. Likely resolution: an epoch serves distinct skills (coverage), and a *separate*
> repeated-measures pass samples same-skill seeds for variance — but that is a Phase-4 decision, not
> settled here. Until then `plan_epoch_distinct_skills` exists alongside the view-only `plan_epoch_from`.
> The run protocol now exists (`run-suite`, [BUILD-LOG](BUILD-LOG.md) 2026-08-20) but serves on
> `plan_run`'s seed-derived core/probe sets, not yet on either distinct-skills sampler — wiring the
> coverage-vs-variance policy into it is the open Phase-4 decision above.

---

## Q32 — What the offline submission pipeline could not decide · **OPEN (needs owner decisions)**

**Blocks:** any upload. Raised while building `bench-submit` ([BUILD-LOG](BUILD-LOG.md) 2026-10-05).
`rustybench export` / `verify-bundle` / `consent` now exist and are tested; everything below is what
they deliberately do *not* do, and the decision each needs. Nothing here is a bug; each is a place
where the docs are contradictory, blocked by Q22 / Q23, or needs a choice only the
project owner can make.

1. **The upload endpoint, and whether there is one.** The bundle is a file; nothing sends it. Where it
   goes (a hosted service, a Git PR to a results repo, an email) decides authentication, rate limiting
   and deletion. Blocked on Q23.
2. **Consent wording and licence grant.** `consent.rs` ships *draft* text that names "Creative Commons
   Attribution 4.0 International (CC BY 4.0)" in full and grants a "perpetual, worldwide, non-exclusive
   licence" to publish and to license onward, per docs/11. Whether that text is legally sufficient (UK
   sui-generis database rights, DATA-LICENSE.md) is the owner's call, ideally with advice. Changing one
   character changes `terms_hash`, which voids every stored consent by design.
3. **The three consents are not separable** (REVIEW-5 `consent-two-is-mandatory`): consent 2 (encrypted
   replay artifacts) is a precondition for any ranked row, so offering it as an independent opt-in is
   misleading. Only consent 1 is implemented; 2 and 3 are refused with an explanation. Decide whether
   the consent screen should say "ranked rows require consent 2".
4. **Encrypted replay artifacts need a server key and a cipher.** No encryption crate is in the
   workspace graph, and choosing one (age / X25519+ChaCha20-Poly1305 / HPKE) is a dependency and a
   key-management decision. The bundle therefore carries *no* model output at all.
5. **Signing.** docs/11 says ed25519 over canonical CBOR. Not built: no CBOR crate, no ed25519 crate, and
   an embedded key proves nothing (docs/10, T0 only). The bundle uses canonical JSON
   (`rb-canon-json-v1`) and a `content_hash`; the hash detects accidents and casual edits, not an
   adversary (who recomputes it — `tests/verify.rs` does exactly that). Decide: add the two crates, or
   accept T0 = unsigned, or defer to a server-issued submitter token (Q23).
6. **Seeds.** The bundle drops them: a generated `task_id` is `family/{seed:016x}`, so docs/11's
   "always upload `task_id`" contradicts its own "seeds withheld until the epoch closes". A server doing
   T1 replay needs the seeds, so either it re-derives them (it can only if the seed derivation is not
   public — blocked on Q22/R5-S2: the epoch label is a public string today, so *anyone* can derive every
   local-epoch seed) or they travel in the encrypted artifact channel (point 4). `unit_id` is kept as an
   opaque join key.
7. **Raw calibration numbers** (pp512 / tg128 / sustained) are not in the bundle. R5-S6: published raw
   they defeat hardware bucketing; withheld they leave the plausibility checks (themselves R5-S5
   "non-functional") with nothing. There is also no calibration producer yet (docs/05 Phase B). Choose
   fingerprint-vs-control before adding them.
8. **`machine_uuid` and `completed_at`** are omitted (R5-S6: together a linkable activity timeline).
   `segment` / `segment_position` are kept because the throughput warm-up exclusion needs them; they
   reveal how many sessions a run took. Decide whether that is acceptable, or coarsen them.
9. **The row key is not produced by the harness yet** (R6-S4). There is no `state.json`, `plan.json` or
   `profile_hash` writer, so `division`, `template_fingerprint`, `reasoning_mode`, `prompt_pack_hash`,
   `sampling_profile_id`, `weights_id`, `exec_class` and the model's `quant` / `backend` / `ctx` come from
   an optional hand-supplied `--identity` file; absent ones are listed in `body.unrecorded`, not guessed.
   `submitter_config` (R6-S13: `budget_tokens` is 32768 / conditional / 16000 across three documents) is
   not in the bundle until the docs agree.
10. **Model identity.** `model.name` is whatever the user typed (`--model-name`); a path is reduced to its
    basename. Ranking needs a canonical identity (a hash of the weights file, or a registry id), which the
    harness does not compute.
11. **Completeness.** docs/12's `report.completeness` needs the planned unit count; with no `plan.json`
    the bundle cannot say how much of the plan ran. `report` carries `n_core` / `n_probe` only.
12. **`verify-bundle` is not T1.** It proves the bundle is clean, canonical, internally coherent and that
    the aggregates follow from the units. It cannot prove the scores are true (that is replay over model
    output, server-side) and assigns no trust tier. Whether a passing verify should unlock anything is a
    policy question.
13. **Local-identity detection is best-effort.** The scrubber knows this machine's login name, home path
    and hostnames from the environment and `hostname` / `scutil`; a shared account or a renamed machine
    can slip past the literal check (the pattern layer and the strict field grammars still apply).
    A login that equals a schema word (`core`, `unit`) makes the fail-closed scan refuse every export.
14. **Where consent is stored.** `runs/consent.json` follows the repo's `runs/` convention, but consent
    is per person, not per run directory. A per-user path (`~/.config/rustybench/`) is arguably right and
    is a one-line change.

---

## Q33 — L4 quality: what survives the reviews, and what is left to decide · **OPEN**

**Blocks:** wiring any L4 figure into a score. Raised while building the mutation runner
([BUILD-LOG](BUILD-LOG.md) 2026-10-06). Built: a deterministic mutator and a sandboxed
survival check (`bench_oracle::mutation`) and a token `size_ratio` (`bench_oracle::quality`). Not wired
into `OracleVector`, the composite or the pass predicate ([Q28](#q28--define-the-pass-predicate-on-task_score--decided-structural-pass)
keeps quality out of pass), and no `test-authoring` family exists yet to supply model-authored tests.

1. **Perf (criterion) is not built.** docs/03 gates it to execution class `GpuFull` — a CPU
   micro-benchmark gated on GPU offload, which only makes sense as a proxy for "the machine is quiet"
   and then collides with R6-S5 (`exec_class` is a free-text, submitter-chosen string). It also needs a
   <5% repeat-variance precheck, hardware-dependent timings (docs/03: not replay-verifiable) and no
   deterministic proxy is defined (instruction counts need `perf`/valgrind, not installed). Allocation is
   already measured exactly in L3. Decide whether perf is dropped, kept as a T0 hardware-gated figure, or
   replaced by a deterministic proxy.
2. **Mutation has two readings; one survives.** *"Did the model's tests kill the reference's mutants?"*
   (`test-authoring`) is well defined and built. *"For other categories it measures whether the solution
   is meaningfully specified"* scores the **oracle's** weakness (surviving mutants of the model's solution
   are tests the hidden suite lacks), not the model, so rewarding or penalising a model for it is a
   category error. Not built; decide whether to delete that sentence from docs/03.
3. **Equivalent mutants (policy chosen here, needs a ruling).** A mutant the *reference* (hidden) tests
   cannot kill is excluded from the denominator and reported (`unkillable_by_reference`), so a perfect
   test suite scores 1.0 and the score depends on the oracle's strength, not on undecidable equivalence.
   Consequences to accept or change: a weak reference suite shrinks the denominator; with few killable
   mutants the score is noisy (no minimum is enforced; `None` when zero are killable).
4. **Ratio-to-score formulas are undefined.** docs/03 gives weights (mutation 0.5, perf 0.3, size 0.2) and
   `max_ratio` caps but no formula from `size_ratio` / perf ratio / kill fraction to a `[0,1]` score.
   Per-category weights (`test-authoring` quality 0.70) are unusable until these exist.
5. **Determinism vs docs/03's "cargo-mutants is not deterministic".** The in-repo mutator is
   deterministic (fixed operator table, source order, stride sampling) and its verdicts are exact given
   deterministic tests, so mutation score *could* be replay-verified, which would soften "L4 is T0". Not
   claimed: tier policy is unchanged. The operator set is a cargo-mutants-like subset chosen here
   (arithmetic, comparison, logic, compound assignment, `!`, bool literals, primitive/unit function
   bodies; no literal mutation, no `Option`/`Result` returns).
6. **Latent bug found on the way (oracle, not L4) — FIXED 2026-10-06:** `bench_oracle::grade` inherited
   `CARGO_TARGET_DIR` from the environment (now pinned to `<workspace>/target`, see BUILD-LOG; the text below
   describes the bug as found). A user with it set globally makes every graded workspace of the same package
   name share one target directory; the mutation runner showed the symptom (a stale mutant's artifacts
   standing in for the next one: survivors that should have been killed). The mutation runner pins
   `CARGO_TARGET_DIR` inside the workspace; `grade` does not (the stats docs mention a shared `target/`,
   so sharing may be intended). Decide whether `grade` should pin it, and whether a shared target dir
   outside the workspace is also something the seatbelt policy should permit.

---

## Q34 — `plan.json` / `state.json` / segment `meta.json`: the formats are not actually pinned · **OPEN**

**Blocks:** the remaining docs/09 resume gates (`plan_hash`, `suite_hash`, `generator_commit`, `ctx`,
`ngl`, sampling, `exec_class`, backend / quant). Raised on reading docs/09 and docs/12 to implement the
writers ([BUILD-LOG](BUILD-LOG.md) 2026-10-06); **nothing was built**, because an implementation would
have to invent each of these:

1. **`plan.json` carries `epoch_seed`, which R5-S2 says must not be on the submitter's disk** (it is the
   master key to every core seed in the epoch). The harness today has no `epoch_seed` at all: core seeds are
   `blake3(epoch_label || task_id || index)` from a *public* label. A plan writer has to either write the
   secret (contradicting R5-S2), write the public label (honest, but then `plan.json` is not the secret
   docs/09 describes), or omit it (then `plan_hash` covers only derived seeds). Blocked on Q22 / Q23.
2. **Probe slots need the batch/nonce protocol** (`batch`, `seed: null`, re-issue on expiry), which is
   BLOCKED (Q22 / R5-S2). The current runner draws probe seeds from the same label-derived function.
3. **`suite_hash` and `generator_commit` have no definition or producer.** What is hashed (family ids? each
   family's source? generated instances?) is unspecified, and no build step records a git commit, so
   `generator_commit` has no source. Both gates would compare values nothing can yet produce.
4. **`state.json.identity` fields the harness does not know.** `quant`, `backend`, `backend_version`, `ctx`,
   `ngl`, sampling beyond what `SamplingConfig` sends, `exec_class` (+ `exec_class_source`), `profile_hash`,
   `template_fingerprint`, `reasoning_format`, `tools_offered` all come from the profile/probe work
   (docs/15 §10, not built) or from the user. `run-suite` takes only a URL and a model name. They could be
   supplied by hand (as `rustybench export --identity` does) but then a gate would compare two strings the
   submitter typed.
5. **docs/09 and docs/12 disagree on the on-disk root and layout** (docs/09: `~/.local/share/rustybenchmark/
   runs/<run_id>/` with `state.json`, `plan.json`, `hw.json`, `segments/`, `artifacts/`; the code writes a
   single `--out` journal path and `--scratch`), and there is no `run_id` anywhere in the code
   (`rustybench export` derives one from the units).
6. **`segments/<n>/meta.json`** is pinned (docs/09), but `started_at` / `ended_at` are wall-clock times, and
   the crash-safety work established that no resume decision may depend on a wall clock; they would be
   informational only. Writing them is cheap once 1-5 are decided; it was not done alone because a meta
   file without the plan/state it describes would be the "mutable state with no frozen plan" that docs/09
   exists to prevent.

What the journal-side gates (model name, hardware class, harness version) can already check is built; the
rest should wait for a decision on 1-5, in particular whether the first resume-capable release writes a
public-label `plan.json` and leaves `epoch_seed` out.

**Scheduling controls (added 2026-10-06).** `--max-duration`, `--until`, `--max-units` and
`--pause-on-battery` are built; the readings chosen where docs/09 is silent are recorded here so they can
be overruled:

7. **`--idle-only` is not built.** docs/09 gives one line ("only execute while the machine is otherwise
   idle") and defines neither *idle* (load average? input idle time? no other `cargo`/inference process?
   what threshold, over what window?) nor the behaviour when the machine is busy: wait and resume when it
   goes idle, or end the segment (docs/09's "All of these end the segment with a clean `exit_reason`"
   says end; the flag's wording says wait). Either reading needs a probe and a threshold that do not exist.
8. **`exit_reason` has no value for `--max-units`** (the enum is `max_duration | until_time | sigint |
   battery | thermal | crash | complete | aborted`). The runner prints `max_units`; docs/09 and docs/12
   should add it (and decide what a `SIGTERM` stop is called: today it prints under `sigint`'s clean path).
9. **`--max-units N` is per session** (N more units this run), not N in total: the docs' example is an
   evening slice (`--max-units 500`). Overruled easily if "total" was meant.
10. **`--max-duration` is execution time of this session**, from the start of the run loop, measured on
    the monotonic clock; time asleep with the lid closed does not count (macOS's monotonic clock stops
    in sleep). **`--until HH:MM` follows the wall clock** (local time, next occurrence; exactly-now means
    tomorrow), fixed as an absolute deadline at session start, so it still fires after a night's sleep.
    A wall-clock jump backwards delays it; a DST change shifts it by the offset. Needs the local time
    of day, taken from `date` (std has no local time and the repo forbids `unsafe`/new crates for it);
    if `date` fails, the run refuses to start rather than ignore the limit.
11. **`--pause-on-battery` also refuses to *start* on battery**, which is one reading of "if AC power is
    lost"; the other is "only react to a change". Unknown power state (no battery, no `pmset`) never stops
    a run. Linux has no probe yet (`pmset` only), so on Linux the flag is silently inert: it should say so.
