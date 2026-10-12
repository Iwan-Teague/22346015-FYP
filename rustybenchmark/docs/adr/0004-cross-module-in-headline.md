# ADR-0004 — `cross-module` is in the headline number

**Status:** Accepted · 2026-08-17 · **Reverses an earlier position**

## Context

**Earlier position (rejected):** treat `cross-module` as `deep`-tier, opt-in, outside the headline composite. Rationale was cost — a 3–10 file task with a 30B model at ~20 tok/s takes minutes, and consumer hardware is the target.

The rejection reason is validity. Real Rust fix patches average **9.8 files, 9.9 hunks, and 139.9 lines**. Python SWE-bench Verified averages **1.25 files, 2.46 hunks, 14.32 lines**. Rust work is structurally larger than Python work, and a Rust benchmark composed only of single-file puzzles is measuring something meaningfully different from Rust.

Further: Rust-SWE-bench attributes **43.7% of agent failures to repo-wide structure comprehension** — a failure mode that single-file tasks cannot observe at all. Excluding the category does not merely omit a data point; it hides the largest single source of real-world failure.

## Options

1. **Exclude entirely.** Cheapest, largest validity error.
2. **Opt-in extra, outside the composite.** Cheap, but the headline number then silently over-represents toy tasks, and most users would never enable it.
3. **In the composite, with cost managed rather than avoided.**

## Decision

**Option 3.** `cross-module` carries equal category weight in `capability_score`.

Cost is managed by:

- **Fewer families (15 vs 20–25), equal category weight.** Depth traded, not the category.
- **Bounded scope**: 3–10 files, ≤5k LoC, pre-vendored dependencies, prebuilt dependency workspace. Mining targets small fail-to-pass commits in **workspace member crates**, not whole repositories.
- **A second published figure**: `capability_score_synth` excludes this category (and `api-evolution`, the other mined one). A slow machine can run the synthetic set and still appear on the leaderboard.
- **Time-boxed, not turn-boxed**: wall-clock cap per task, with timeout recorded separately from genuine failure. On this benchmark that distinction is a *hardware* fact, and surfacing it is the point of the project.

## Consequences

**Good**

- The headline number reflects Rust work rather than Rust puzzles.
- The 43.7% repo-comprehension failure mode becomes measurable.
- `capability_score` vs `capability_score_synth` is itself informative: a model that scores well on the synthetic set and poorly on the full set is good at Rust semantics and bad at codebases, which is a real and useful distinction.

**Bad**

- The composite is no longer purely synthetic — category 10 is mined, so it inherits the oracle-quality caveat from [ADR-0002](0002-hand-written-and-mined-suites.md).
- Longer minimum run times on weak hardware, partly offset by the lite score.
- Mining yield for *small* commits is unproven — see [OPEN-QUESTIONS Q2](../OPEN-QUESTIONS.md). If yield collapses, the family budget needs revisiting, though the decision to include the category does not.


> **Superseded in part.** The "fewer families (15 vs 20–25)" framing predates the core/probe split in [ADR-0008](0008-core-and-probe-categories.md), which fixed every probe category at 12. Round 5 also found that for 62–69% of qualifying crates the mined oracle sits inside a file the model is asked to edit, which defeats oracle isolation — see **Q25**.
