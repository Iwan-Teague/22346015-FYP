# ADR-0001 — Tasks are seeded generators, not a static corpus

**Status:** Accepted · 2026-08-17

## Context

Every static coding benchmark decays. Models memorise them, and the decay is measurable rather than theoretical:

- RustEvo² measured **56.1%** on before-cutoff APIs versus **32.5%** on after-cutoff APIs — a 24-point gap attributable to training-data recency alone.
- DynaCode showed Llama-3-8B-Instruct dropping significantly from MBPP/MBPP+ to a dynamically generated equivalent.
- MultiPL-E and HumanEval derivatives are now effectively uninformative as discriminators.

## Options

1. **Static curated corpus.** Cheapest. Decays from the day it is published.
2. **Harvest fresh problems** (LiveCodeBench, LiveBench, SWE-ReBench model). Genuinely contamination-free, but supply-limited, cannot isolate specific skills, and requires continuous operational effort forever.
3. **Generate from seeds.** Unbounded freshness, exact category attribution, high authoring cost.

## Decision

**Option 3.** Task families are functions from a seed to a fresh instance. Generators are published; seeds are published per run; solved instances are never published. Seeds derive from a server-issued nonce so they cannot be precomputed.

## Consequences

**Good**

- Freshness is unbounded and free after authoring. No harvesting treadmill.
- Category attribution is exact — we know what each instance tests because we constructed it.
- Difficulty is a parameter, not an accident of what happened to be on GitHub.
- Server can re-derive any instance from its seed, which is what makes T1 replay verification possible at all ([ADR-0007](0007-trust-tiers-over-client-attestation.md)).

**Bad**

- Authoring cost is the entire project. **~248 hand-written generators** (5 core × 40 + 4 synthetic probe categories × 12).
- A buggy generator silently corrupts every score derived from it. Mitigated by the nine-gate CI validation in [02-task-format.md](../02-task-format.md), especially the independently-written second reference.
- Synthetic tasks risk measuring the author's taste in puzzles rather than real Rust work. Mitigated by [ADR-0002](0002-hand-written-and-mined-suites.md).
- A generator that only permutes identifiers is memorisable and worthless. Mitigated by the `min_instance_distance` tree-edit-distance gate.

## Notes

The canary mechanism exists because of this ADR: if generation is our contamination defence, we need direct evidence of whether it is holding. A canary appearing in a public corpus is that evidence.
