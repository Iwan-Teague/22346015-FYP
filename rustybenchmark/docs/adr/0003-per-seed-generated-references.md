# ADR-0003 — References generated per seed, via solution-first construction

**Status:** Accepted · 2026-08-17 · **Reverses an earlier position**

## Context

Every instance needs a ground-truth reference implementation for the differential oracle. Two ways to get one.

**Earlier position (rejected):** one hand-written, parameterised reference per family, covering the whole seed space. Chosen on cost, with the explicit caveat that `variance.structural` would have to be *bounded by what the reference can absorb*.

That caveat is the problem. It caps how structurally different two instances of a family can be — and structural variation is precisely the property that makes a family memorisation-resistant ([ADR-0001](0001-generated-tasks-not-static-corpus.md)). The cost saving was purchased directly out of the benchmark's core value proposition.

## Options

1. **One parameterised reference per family.** Cheap. Caps structural variance. Reference can silently drift out of sync with the generator.
2. **Reference generated per seed, written problem-first.** Requires synthesising a correct solution to a problem you already wrote — hard, and correctness is not guaranteed.
3. **Reference generated per seed, solution-first.** Generate the solution from the `Spec`, then derive the problem, properties, and skeleton from it.

## Decision

**Option 3 — solution-first generation.**

```rust
let spec      = Spec::sample(seed);
let reference = synthesize_reference(&spec);   // correct by construction
let props     = derive_properties(&spec);      // from the Spec, not the code
let skeleton  = ablate(&reference, &spec);
let prompt    = render_prompt(&spec, &skeleton);
```

## Consequences

**Good**

- The reference is **correct by construction** — built from the same `Spec` that generates the properties. There is no hand-written answer that can drift.
- **Solvability is guaranteed**: the reference is by definition a passing solution.
- Structural variance is no longer capped by a human-maintained artifact. This is the whole point.
- Difficulty becomes a direct `Spec` parameter.

**Bad**

- Writing `synthesize_reference` is harder than writing one reference implementation. It is a program that writes programs.
- A bug in `synthesize_reference` produces a *wrong ground truth*, which is the worst possible failure — it silently corrupts every score from that family, in a direction nobody would notice.

## Mitigation for the bad case

The wrong-reference risk is real and is handled by a specific CI gate, not by care:

> The generated reference must pass a **second, independently written implementation** via differential fuzz, over ≥1000 seeds.

Two independently authored implementations agreeing on 2000 generated inputs across 1000 instances is strong evidence. This is the single most important item in the family validation suite, and no family ships without it.

Additionally: derive properties from the `Spec`, never from the reference code. Properties derived from the code would be tautological and would agree with a wrong reference.
