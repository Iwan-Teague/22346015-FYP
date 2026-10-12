# Architecture Decision Records

One file per decision that was genuinely contested, including the ones that were made and then reversed during the exploratory phase.

Format: context, options, decision, consequences. Reversals keep the original reasoning visible rather than editing history — the reason a decision was reversed is usually more informative than the decision itself.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-generated-tasks-not-static-corpus.md) | Tasks are seeded generators, not a static corpus | Accepted |
| [0002](0002-hand-written-and-mined-suites.md) | Both hand-written and mined suites, reported separately | Accepted |
| [0003](0003-per-seed-generated-references.md) | References generated per seed via solution-first construction | Accepted, **reverses an earlier position** |
| [0004](0004-cross-module-in-headline.md) | `cross-module` is in the headline number | Accepted, **reverses an earlier position** |
| [0005](0005-execution-classes-not-gpu-only.md) | Classify execution mode, do not restrict to GPU | Accepted |
| [0006](0006-breadth-over-depth-in-sampling.md) | More families beats more seeds per family | Accepted |
| [0007](0007-trust-tiers-over-client-attestation.md) | Server-side replay over client attestation | Accepted |
| [0008](0008-core-and-probe-categories.md) | Core (40 families, rankable) vs probe (12, directional) categories | Accepted, from [REVIEW.md](../REVIEW.md) S3 |
| [0009](0009-paired-core-and-fresh-probe-seeds.md) | Split epoch seeds into a paired core (scored) and a fresh probe (detector) | Accepted, from [REVIEW-2.md](../REVIEW-2.md) R2-S1 |
| [0010](0010-pinned-tuned-open-divisions.md) | Pinned / Tuned / Open divisions; pin the request, gate the readable, key the coarse, condition the backend | Accepted |
