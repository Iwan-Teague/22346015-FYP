# Glossary

Terms used precisely throughout these documents. Where a word has a loose everyday meaning and a precise meaning here, the precise one wins.

**Ablation** — removing from the reference implementation exactly the part the model must supply, producing the skeleton. Validated by checking that the skeleton fails the oracle.

**Batch** — a group of work units covered by one challenge nonce. Bounds precomputation exposure for T2 runs. Orthogonal to segments.

**Canary** — a unique low-frequency string embedded in each instance's prompt. Its later appearance in a public corpus, or in a *different* instance's submitted output, is direct evidence of leakage.

**Capability score** — weighted mean task score across categories. A property of the model. Comparable across machines and execution classes.

**Category** — one of **eleven** Rust skill areas, scored independently, split into five **core** (40 families, rankable) and six **probe** (12 families, directional only). See [04-categories.md](04-categories.md).

**Design effect** — `1 + (seeds_per_family − 1) × ICC`. The factor by which clustering inflates variance, and therefore the divisor turning raw instance count into effective N.

**Differential oracle** — running the candidate and the reference implementation on the same generated inputs and comparing outputs.

**Effective N** — `total_instances / design_effect`. The number that goes into confidence-interval arithmetic. Always smaller than the instance count.

**Epoch** — a time-boxed period (monthly) with a fixed seed set shared by all models submitted during it. Enables paired comparison.

**Execution class** — `GpuFull` (100% offload), `Hybrid` (partial), or `CpuOnly`. Derived from the backend's reported layer split, never self-declared.

**Family** — a task generator: a named function from seed to instance. The unit that matters for statistical power. **272 planned** — 248 synthetic, 24 mined.

**Frozen** — a task kind with no generation. Development and smoke use only; refused by scored suites.

**ICC (intra-class correlation)** — how correlated outcomes are among seeds of the same family. Estimated at 0.3–0.5 and **published per category, not pooled** (R4-S5): categories whose families cluster into few distinct *shapes* carry a higher effective ICC than the corpus-wide figure.

**Core category** — one of the five categories budgeted at 40 families and precise enough to rank.

**Probe category** — one of the six budgeted at 12 families. Contributes to the composite; its own score is directional and is never sorted on.

**Shape** — a distinct task archetype within a category. Families cluster into shapes, which makes clustering two-level (shape → family → seed) and sets the real precision ceiling (R5-S3).

**Instance** — one concrete problem produced by a family from one seed: prompt, files, hidden oracle, facts, canary.

**Journal** — the append-only, fsync'd `journal.jsonl` recording one line per completed work unit. The source of truth for a run.

**Mined** — a task kind drawing from a corpus of real fail-to-pass commits with seeded perturbations. Used for the `wild` suite. Cannot guarantee oracle correctness by construction, so reported separately.

**Oracle** — the five-layer grader: apply, compile, behavior, constraint, quality. Produces a vector, not a bit.

**Plan** — the frozen, ordered, hashed list of work units, computed once before the first unit runs and never re-derived.

**Property oracle** — invariants derived from the `Spec` (not from the reference code) and checked with seeded proptest.

**Segment** — one continuous execution session of a run. Each has its own calibration. A run may have many.

**Solution-first generation** — generating the reference implementation from the seed first, then deriving the problem, properties, and skeleton from it. Makes the oracle correct by construction.

**Spec** — the seed-sampled structural parameters of an instance: lifetimes, bounds, sizes, chosen API route, identifier pool. Everything else is derived from it.

**Suite** — a named collection of families and seeds-per-family: `smoke`, `standard`, `deep`. Also, separately, `synth` vs `wild` as corpus designations.

**Tainted** — a run whose identity invariants were violated and which proceeded under `--force-heterogeneous`. Permanently ineligible for ranking. Cannot be un-tainted.

**Throughput score** — work units passed per wall-clock hour. A property of the machine. Comparable only within an execution class.

**Trust tier** — T0 self-reported, T1 replayed, T2 challenged, T3 audited. Labels how much of a submission has been independently verified.

**Unstable** — a run whose per-segment calibration varied more than ±10%. Its throughput metrics are struck through; its correctness metrics are unaffected.

**Work unit** — the atom of execution and checkpointing: one `(task, seed, attempt policy)` triple. Independent and idempotent.
