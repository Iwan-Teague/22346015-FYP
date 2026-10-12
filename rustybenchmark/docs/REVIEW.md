# Adversarial review — round 1

**Date:** 2026-08-17 · **Scope:** all design documents as of commit `1026c7b` · **Reviewer stance:** assume the design is wrong and find where.

Findings are ranked by damage. Each states the defect, the concrete failure, and the resolution. Findings that changed a document are marked **PATCHED**; findings that remain open are tracked in [OPEN-QUESTIONS.md](OPEN-QUESTIONS.md).

---

## S1 — The published statistics tables were arithmetically wrong · **PATCHED**

**Defect.** [07-statistics.md](07-statistics.md) gave effective-N and CI figures that do not follow from its own design-effect formula.

| Suite | Published eff. N | Correct (ICC 0.3) | Published ±CI | Correct |
|---|---|---|---|---|
| `deep` (200×6) | 632 | **480** | ±3.9% | **±4.5%** |
| `full` (200×16) | 872 | **582** | ±3.3% | **±4.1%** |
| `deep` per-category | — | **48** | ±12% | **±14.1%** |
| `full` per-category | — | **58** | ±10% | **±12.8%** |

`smoke` and `standard` were correct.

**Failure.** Every precision claim in the roadmap and the leaderboard-eligibility rule was derived from inflated numbers. We would have published category rankings the data cannot support.

**Resolution.** Tables recomputed and replaced, now presented as an **ICC sensitivity grid** rather than single figures, because ICC is an assumption (see S2).

---

## S2 — ICC is a guessed parameter that the entire design rests on · **PATCHED (roadmap)**

**Defect.** ICC = 0.3–0.5 was asserted with no empirical basis. Suite sizing, the breadth-over-depth decision ([ADR-0006](adr/0006-breadth-over-depth-in-sampling.md)), and every CI follow from it. Nothing in the roadmap measured it before the corpus was sized.

**Failure.** At ICC 0.7 — entirely plausible for seeded variants of one family — 16 seeds buys 1.39 effective items per family, and the whole seeding strategy is close to worthless. At ICC 0.1 the breadth-over-depth conclusion weakens considerably. We were about to commit ~400 person-days of corpus authoring to an unmeasured constant.

**Resolution.** New **Phase 3.5: ICC measurement experiment**, a hard gate before corpus scale-up. 20 families × 16 seeds × 3 models ≈ 960 units ≈ 24 h. Cheap relative to what it de-risks. Suite sizing is provisional until it runs.

---

## S3 — Per-category precision has a ceiling that seeds cannot raise · **PATCHED**

**Defect.** Not an error, but a consequence nobody had traced. As seeds → ∞, effective N per category → `families_per_category / ICC`. It is bounded by family count alone.

At 20 families/category:

| ICC | Ceiling eff. N | Best achievable ±CI |
|---|---|---|
| 0.2 | 100 | ±9.8% |
| 0.3 | 66.7 | **±12.0%** |
| 0.5 | 40 | **±15.5%** |
| 0.7 | 28.6 | ±18.3% |

**Failure.** The radar chart — the product's most distinctive feature — would carry ±12–16% error bars at *any* suite size. "This model is better at traits than at lifetimes" would be unsupportable no matter how long anyone ran the benchmark. The headline feature was statistically unbuildable as specified.

**Resolution.** Categories split into **core** (40 families, rankable, ±8.5% ceiling at ICC 0.3) and **probe** (12 families, explicitly directional-only, never ranked). Total corpus grows 200 → 260 families. See [04-categories.md](04-categories.md) and [ADR-0008](adr/0008-core-and-probe-categories.md).

---

## S4 — The `full` suite is not worth running · **PATCHED**

**Defect.** Follows from S3. Going 6 → 16 seeds improves per-category CI from ±14.1% to ±12.8% for **2.7× the wall-clock**.

**Failure.** We would have advertised a 49-hour flagship tier (itself understated, see S5) that buys 1.3 percentage points.

**Resolution.** **`full` is deleted.** `deep` at 4 seeds is the ranked tier. Compute freed goes to families, where it is not subject to the S3 ceiling.

---

## S5 — Time estimates were understated by 2–3× · **PATCHED**

**Defect.** All timings assumed 55 s/instance single-shot. But the default interaction mode is `repair` (2 attempts), and `deep` mandates the L4 quality layer (cargo-mutants, criterion) — neither was costed.

Corrected, at ~40% first-try pass:

| | Published | Actual @20 tok/s |
|---|---|---|
| `standard` | 6.1 h | **14.2 h** |
| `deep` (old 200×6) | 18.3 h | **42.7 h** |
| `full` (deleted) | 49 h | **113.8 h** |

**Failure.** A user told "about 18 hours" would have hit 43. On a benchmark whose core promise is resumability and honest hardware reporting, lying about its own runtime is a credibility failure.

**Resolution.** Timings recomputed with repair and L4 included, published as a range across first-try pass rates. New `deep` (260 × 4) is **37 h @20 tok/s / 17 h @60 tok/s**.

---

## S6 — Oracle weights are wrong for the flagship category · **PATCHED**

**Defect.** Global weights are `behavior 0.7 / constraint 0.2 / quality 0.1`. For `borrow-lifetimes`, a solution that clones everything is **semantically correct** — it passes every behavioural property. The entire signal lives in L3 constraints, weighted 0.2.

**Failure.** Category 1, the most Rust-distinctive category and the project's stated niche, would have graded almost entirely on a layer carrying a fifth of the weight. Models that solve lifetime problems by cloning would score near-identically to models that solve them properly.

**Resolution.** Weights become **per-category**, declared in the category definition and overridable per family. `borrow-lifetimes` and `idiom-refactor` invert to constraint-dominant (`behavior 0.35 / constraint 0.55 / quality 0.10`).

---

## S7 — Forbidden-call AST checking cannot work as specified · **PATCHED**

**Defect.** `forbidden_calls = ["clone", "to_vec"]` attempts to enumerate every way to copy data. It cannot: `to_owned()`, `Vec::from(&s[..])`, `iter().copied().collect()`, `Box::new(x.as_ref().clone())`, `extend_from_slice`, and arbitrarily many more.

**Failure.** A model that avoids the listed names but allocates freely scores as though it satisfied the constraint. The check produces false confidence, which is worse than no check.

**Resolution.** Replace name-blacklisting with **runtime allocation instrumentation** — a counting `#[global_allocator]` in the grading harness asserting an allocation budget derived from the reference implementation. Measures the actual property (does this allocate?) rather than a proxy for it. Name-based checks are retained only where the constraint genuinely *is* about a specific API.

---

## S8 — `min_instance_distance` measures the wrong artifact · **PATCHED**

**Defect.** The anti-twin gate measures tree-edit distance between **reference implementations**. The model never sees the reference. It sees the prompt and skeleton.

**Failure.** Two instances with structurally distant references but near-identical prompts pass the gate while being, from the model's perspective, the same question. The primary memorisation defence had a hole in exactly the place it was pointed at.

**Resolution.** Gate now measures distance across **prompt + skeleton**, with reference distance retained as a secondary check.

---

## S9 — Category 4 mandates miri on code miri cannot run · **PATCHED**

**Defect.** `unsafe-ffi` requires miri. Miri cannot execute foreign function calls — the defining feature of FFI.

**Failure.** Either the category has no real FFI content (and is misnamed), or its mandatory oracle fails on most of its own tasks.

**Resolution.** Category split by oracle feasibility: `unsafe-core` (raw pointers, transmute, `Send`/`Sync`, aliasing — miri-checkable, becomes a core category) and `ffi-boundary` (`repr(C)`, C interop — graded by a real C shim linked at test time, no miri; becomes a probe category).

---

## S10 — Category 5's differential oracle is not well-defined · **OPEN**

**Defect.** `async-concurrency` specifies a differential oracle comparing candidate and reference outputs on generated inputs. Under nondeterministic scheduling there is no stable output to compare; loom is waved at as "where feasible".

**Failure.** Either spurious failures from scheduling variance, or an oracle so weak it only catches compile errors.

**Status.** Open. Tracked as **Q11**. Working hypothesis: grade async on *linearizability properties* under loom's exhaustive scheduling for small state spaces, and on `Send`/`Sync`/cancellation-safety constraints (L3) otherwise — i.e. treat it as constraint-dominant like `borrow-lifetimes`. Needs a Phase 3 spike before the category is authored.

---

## S11 — L4 quality scores cannot be replay-verified · **PATCHED**

**Defect.** [10-integrity.md](10-integrity.md) claims T1 replay verifies correctness exactly because the oracle is deterministic. L4 contains criterion timings and cargo-mutants runs — neither is deterministic, and criterion is hardware-dependent by design.

**Failure.** The server re-grades, gets different L4 numbers, and either rejects honest submissions or silently tolerates mismatches — which reopens the fabrication hole T1 exists to close.

**Resolution.** T1 replay verifies **L0–L3 exactly** and treats **L4 as unverifiable**, subject to plausibility bounds only. L4 contributions are labelled at T0 confidence on the leaderboard even inside a T2 row. Documented as a tier caveat rather than hidden.

---

## S12 — T2 is oversold · **PATCHED**

**Defect.** T2 batched challenge prevents *precomputation*. It does not prevent a submitter from receiving a batch and solving it with a stronger model, a human, or a hosted API within the window.

**Failure.** A row badged T2 implies more assurance than it delivers.

**Resolution.** Wording corrected throughout: T2 proves the answers were **not prepared in advance**, not that the declared model produced them. Model attribution rests on error-code fingerprinting and throughput plausibility — both probabilistic, both stated as such.

---

## S13 — Context limits are unhandled for category 10 · **OPEN**

**Defect.** A 3–10 file, ≤2k LoC repo plus instructions plus repair diagnostics can exceed a 32k context. `skipped_context` exists as a flag; no strategy exists.

**Failure.** Small-context models get scored on a category they were structurally prevented from attempting, which conflates context window with capability.

**Status.** Open. Tracked as **Q12**. Options: declare a minimum context per suite and refuse below it; provide a retrieval interface; score `skipped_context` separately rather than as failure. Leaning toward the first plus the third.

---

## S14 — The roadmap has no critical path, no team assumption, and no kill criteria · **PATCHED**

**Defect.** [14-roadmap.md](14-roadmap.md) listed phases with week ranges but never stated how many people those weeks assume, which phases block which, or what result would justify stopping.

**Failure.** "Weeks 5–8" is unfalsifiable planning. And with no go/no-go gates, a bad ICC result or a 5-days-per-family authoring rate would be absorbed as slippage rather than triggering a decision.

**Resolution.** Roadmap rewritten with an explicit **1 FTE** assumption, a critical path, parallelisable tracks marked, and **five kill/pivot gates** with numeric thresholds.

---

## S15 — Corpus cost implies a multi-year solo project; docs did not say so · **PATCHED**

**Defect.** 260 families × 1–3 days = 260–780 person-days ≈ **1–3 years solo**. The roadmap implied months 6–18.

**Failure.** Planning against a schedule off by a factor of two or more.

**Resolution.** Stated plainly in the roadmap. Mitigation: the design is unusually well suited to **external contribution** — a family is a self-contained PR with nine mechanical CI gates, so quality control does not require the maintainer to review the maths. Contributor-friendliness is promoted from an afterthought to a Phase 3 design requirement.

---

## Lower-severity findings

| # | Finding | Resolution |
|---|---|---|
| M1 | Binomial CI applied to continuous `task_score` ∈ [0,1] | Valid as a conservative upper bound (variance of a bounded variable ≤ 0.25); now stated explicitly. Cluster bootstrap remains the reported CI |
| M2 | `--force-heterogeneous` taint is user-editable in `state.json` | True for T0; irrelevant for T1+ where the server holds the manifest. Documented, not fixed |
| M3 | Canary echoed by the model into its own output could self-flag | Already handled — only *cross-instance* canaries flag. Test added to the spec |
| M4 | Phase 5's "3 categories × 20 families" cannot support category claims (±17–20%) | Phase 5 restated as making an **overall** claim; category claims deferred to Phase 7 |
| M5 | Q3's "hard category" spike appears in OPEN-QUESTIONS but not the roadmap | Now Phase 3 exit criterion |
| M6 | No stated minimum viable hardware | Added to roadmap gates: the `smoke` suite must complete in <90 min on 8 GB VRAM |

---

## What survived unchanged

Worth recording, so a later reader knows these were attacked and held:

- **Solution-first generation** ([ADR-0003](adr/0003-per-seed-generated-references.md)). The wrong-reference risk is real and the independently-written-second-implementation gate is a genuine mitigation. No better approach found.
- **Work-unit idempotence as the basis for resume** ([09](09-resume-and-checkpointing.md)). Attacked for hidden state; none found. Journal-replay recovery is sound.
- **The verifiable/unverifiable split** ([ADR-0007](adr/0007-trust-tiers-over-client-attestation.md)). Held up, with S11 and S12 sharpening its boundaries rather than moving them.
- **Execution classes over GPU-only** ([ADR-0005](adr/0005-execution-classes-not-gpu-only.md)). The partial-offload argument is decisive.
- **Separate `synth` and `wild` suites** ([ADR-0002](adr/0002-hand-written-and-mined-suites.md)). The cross-suite correlation as validity evidence remains the strongest methodological claim in the design.
- **Oracle isolation via separate workspaces** ([03](03-oracle.md)). Attacked for timing windows; the pre-turn content-hash assertion closes them.

---

## Round 2 scope

Not yet attacked, and due before Phase 3 exits:

1. The `Spec` abstraction against a genuinely awkward category (`idiom-refactor`, `error-handling`) — does structural seeding generalise, or do some categories collapse to cosmetic variation?
2. The sandbox, adversarially, on Windows specifically.
3. The mining pipeline's yield assumptions for *small* commits.
4. Failure-class derivation: does the rustc-error-code → category mapping actually hold on real model output, or do most failures land in `other`?
