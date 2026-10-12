# 04 — Categories

Eleven categories in two classes. Each scored independently, each with its own confidence interval, rendered as a radar chart on the leaderboard.

The category count is a taxonomy. The number that decides whether a category score means anything is **families per category** — and per-category precision is *bounded by family count alone*, no matter how many seeds are run ([07-statistics.md](07-statistics.md), the S3 ceiling). At 20 families a category carries ±12–16% forever. At 40 it reaches ±8.5%.

Hence two classes:

- **Core** — 40 families. Rankable at `deep` (±10.7%). Five of them.
- **Probe** — 12 families. **Directional indicators only, never ranked** (±19.6%). Six of them.

Both contribute to `capability_score`. Only core categories may be compared against each other or across models. Decision recorded in [ADR-0008](adr/0008-core-and-probe-categories.md).

## Core categories (40 families each)

| # | Category | Skill probed | Oracle emphasis | Suite |
|---|---|---|---|---|
| 1 | `borrow-lifetimes` | aliasing, NLL, lifetime elision, avoiding self-reference, `split_at_mut`-shaped problems | **constraint-dominant** — allocation instrumentation + L1 error codes E04xx/E05xx | synth |
| 2 | `traits-generics` | trait impls, coherence, GATs, blanket impls, associated types, where-clauses | L1 + L3 signature match | synth |
| 3 | `error-handling` | `?`, custom `From`, `thiserror`/`anyhow`, exhaustive matching — **plumbing, not taxonomy design** (see below) | L2 behavior + L3, with the public error type pinned in the skeleton | synth |
| 4 | `idiom-refactor` | imperative → iterator, `Option`/`Result` combinators, clippy-clean rewrites | **constraint-dominant** | synth |
| 5 | `unsafe-core` | raw pointers, transmute, aliasing rules, `Send`/`Sync` impls, safe wrappers over unsafe cores | **miri mandatory**; UB = hard behavior failure | synth |

**200 families.** All synthetic, all solution-first, all with tractable oracles.

## Probe categories (12 families each)

| # | Category | Skill probed | Oracle emphasis | Suite | Why probe, not core |
|---|---|---|---|---|---|
| 6 | `async-concurrency` | `Send`/`Sync` bounds, tokio, channels, cancellation, deadlock avoidance | loom linearizability where state space permits; otherwise constraint-dominant | synth | Oracle unresolved — see [REVIEW.md](REVIEW.md) S10 |
| 7 | `perf-optimization` | allocation removal, `&str` vs `String`, iterator fusion, SIMD-friendly loops | L4 criterion ratio primary | synth | Hardware-gated; unmeasurable on many machines |
| 8 | `api-evolution` | post-cutoff std stabilisations, crate API migration, deprecation handling | L1 + L2; freshness-rotated | wild | Mined; supply-limited by the release calendar |
| 9 | `test-authoring` | writing tests for a given implementation | **L4 mutation score primary** | synth | L4-dependent, so not replay-verifiable |
| 10 | `cross-module` | coordinating one change across several files and modules | full stack; slowest tier | wild | Mined; yield unproven. **Does not test repo navigation** — see below |
| 11 | `ffi-boundary` | `repr(C)`, C interop, ABI correctness, ownership across the boundary | real C shim linked at test time; **no miri** | synth | Miri cannot execute foreign calls |

**72 families.** Split from the original category 4: miri can check `unsafe-core` but cannot execute FFI, which is what `ffi-boundary` is definitionally about.

**Corpus total: 272 families — 248 synthetic, 24 mined.** (5 core × 40 = 200 synthetic, plus 4
synthetic probe categories × 12 = 48; the two mined probe categories are `api-evolution` and
`cross-module`, 12 each. An earlier "~236 / ~36" split survived four review rounds because the
total was right — [REVIEW-5.md](REVIEW-5.md) W11.)

## Why these eleven

Categories 1, 2, 4, 5 cover the semantics that Rust-SWE-bench attributes **32.6%** of agent failures to and that no general-purpose coding benchmark can see. Category 10 covers the **43.7%** attributed to repo-wide structure comprehension. Category 8 is the contamination probe — RustEvo² measured a **56.1% → 32.5%** before/after-cutoff cliff on exactly this axis, which makes it a direct, quantified memorisation detector.

Categories 3, 6, 7, 9 cover the parts of daily Rust work that determine whether a model is *pleasant* to use rather than merely correct.

## What `cross-module` does and does not measure

It was originally named `multi-file-repo` and claimed to test repo navigation. It cannot, and the rename records that.

The category is squeezed between two constraints introduced in different documents and never reconciled ([REVIEW-2.md](REVIEW-2.md) R2-S4):

- **Context limits push size down.** At 32k context, a task must be small enough to fit alongside instructions and repair diagnostics.
- **Construct validity pushes size up.** Rust-SWE-bench's repos averaged 993 files and 128k LoC, and repo-wide comprehension is 43.7% of agent failures *precisely because the repo does not fit in the model's head*.

At the size that fits in context, **the entire repository is in the prompt**. There is nothing to navigate. What remains is long-context reasoning over several files — a real capability, but not the one the old name claimed.

So: `cross-module` tests **coordinating one change across several files and modules**. That is genuine and worth measuring, and it is what the category now claims.

True repo navigation requires a model that can request files it has not been shown — i.e. tools — which makes it an agentic measurement. It moves to the agentic track as `repo-navigation` rather than being half-done here.

## Category 10 is in the headline number

Earlier draft treated `cross-module` as an opt-in extra. That was wrong, and the reversal is recorded in [ADR-0004](adr/0004-cross-module-in-headline.md).

Real Rust fix patches average **9.8 files and 139.9 lines** (Python SWE-bench Verified: 1.25 files / 14.3 lines). A Rust benchmark composed only of single-file puzzles measures something meaningfully different from Rust work. Excluding the category would bias the entire benchmark toward toy tasks.

Cost is managed rather than avoided:

- **Probe class (12 families), equal category weight.** Its own score is directional only, but it still contributes to the composite.
- **Bounded scope.** 3–10 files, **≤5k LoC**, pre-vendored dependencies, prebuilt dependency
  workspace. Mining targets small fail-to-pass commits in **workspace member crates**, not whole
  repositories — matching [ADR-0004](adr/0004-cross-module-in-headline.md) and roadmap gate G4.
  The ≤2k figure here was R2-S5's superseded value and is corrected
  ([REVIEW-5.md](REVIEW-5.md) W7).

  **The cap is load-bearing on both sides and 5k is not free.** Measured on 3,000 real `.rs` files,
  non-blank Rust runs ~39.5 chars/line ≈ 10.4–12.3 tokens per LoC, so 5k LoC is **52k–62k tokens of
  source alone** — beyond a 32k context, and an order of magnitude above the flat "2k-token prompt"
  the timing model in [07](07-statistics.md) prices every unit at. R2-S4's construct-validity
  argument (that at ≤2k LoC the whole repo fits in the prompt, so the category tests coordination
  rather than navigation) assumed the smaller cap and **needs re-deriving at 5k**. Tracked in
  **Q12** and **Q25**.
- **Separate reporting axis.** `capability_score`, `capability_score_synth` (nine synthetic categories) and `capability_score_core5` are published side by side. A slow machine can run lite and still appear, with the omission explicit rather than silently biasing the table.
- **Time-boxed, not turn-boxed.** Wall-clock cap per task; timeout vs genuine failure is recorded separately, because on this benchmark the distinction is a *hardware* fact and separating it is the point.

## The context gate is per category

Each category declares `min_effective_ctx`. A single suite-level gate would mark `deep` **invalid for
the entire 8–24 GB band the project targets**: `cross-module` at ≤5k LoC is 52k–62k tokens of source
alone, plus a 32k completion budget, so the requirement is ~90k — while Ollama's default on that
hardware band is 4k.

A category whose requirement exceeds the probed effective context emits `skipped_context`, is
**excluded from that category's denominator and reported as absent rather than zero**, and the row
publishes `categories_scored`. A *run* is refused only when a **core** category is unattemptable.

This closes the leaning recorded in **Q12** and composes with the denominator rule above: rows with
different `categories_scored` are not comparable on `capability_score`, which is already the rule for
`perf-optimization`.

## Tiers within a category

Each family carries `tier = smoke | standard | deep`:

- `smoke` — fast, low-variance families used for the sub-hour suite. Present in every category so the smoke run still produces a shape, even though it produces no defensible category CIs.
- `standard` — the working set.
- `deep` — expensive families (miri, criterion, multi-file) admitted only above the `standard` suite.

## Subcategories

Recorded per family for drill-down, not scored independently at launch. Examples:

- `borrow-lifetimes`: `aliasing`, `elision`, `variance`, `self-reference`, `reborrow`
- `traits-generics`: `coherence`, `gat`, `blanket`, `assoc-type`, `object-safety`
- `unsafe-core`: `raw-ptr`, `transmute`, `aliasing`, `send-sync-impl`, `drop-order`
- `ffi-boundary`: `repr-c`, `abi`, `ownership-transfer`, `callback`, `string-marshalling`
- `async-concurrency`: `send-bounds`, `cancellation`, `channels`, `shared-state`, `executor`

Once there are enough submissions, subcategory scores become the mechanism for retuning difficulty and spotting families that carry no information (everyone at 0% or 100%).

## Weighting

Default composite: **equal weight per category.** Not per family — otherwise a 40-family category would silently outweigh a 12-family one.

```
capability_score       = mean over the categories ACTUALLY EXECUTED (see denominator rule below)
capability_score_synth = mean over the 9 synthetic categories        <- ADR-0002's promised number
capability_score_core5 = mean over the 5 core categories             <- always-comparable baseline
```

Probe categories are noisier individually but contribute acceptably to an 11-way mean. Alternative weightings (usage-frequency, difficulty) are published as secondary columns once there is data to justify them, never as the default.

**`capability_score_synth` exists because ADR-0002 promised it and the design never delivered it.**
ADR-0002 resolves "which number is real?" by making the headline explicitly the synthetic-suite
figure with `wild` beside it as a labelled realism check. But the composite spans all eleven
categories, two of which are mined, and the old `_lite` excluded only `cross-module` — so
`api-evolution` sat inside every published figure, with no decision record, carrying the weaker
inherited oracle (30–32% of unit-test-passing solutions only partially correct, 18–23% outright
wrong). See [REVIEW-5.md](REVIEW-5.md) W4.

**The denominator is part of the score's identity.** `perf-optimization` is skipped on non-`GpuFull`
machines, on battery, or when the timing precheck fails (`perf_unavailable`); families can be skipped
for context (`skipped_context`). A mean over eleven categories where one is empty is a different
statistic. So:

- every published `capability_score` carries `categories_scored: [...]`, and the leaderboard renders
  a missing category the way it renders `completeness < 1.0`;
- **`capability_score_core5` is the cross-machine comparison key**, because those five categories are
  never machine-gated and therefore always share a denominator.

This corrects three documents that called `capability_score` comparable across machines without
qualification — see [REVIEW-5.md](REVIEW-5.md) `capability-score-denominator`.

## `error-handling` tests plumbing, not error design

Error-handling references are non-unique in a way that reaches *observable behaviour*: many valid
error designs differ in variant naming and structure while being equally correct. A differential
oracle comparing candidate against reference error output would penalise a model for choosing
different, correct names.

So these families **pin the public error type in the skeleton**. The enum is given; the model
implements the plumbing. The differential then compares *which variant* is returned, not how it is
spelled.

The honest consequence: choosing a good error taxonomy — arguably the most interesting judgement in
Rust error handling — **is not gradeable by this oracle and is out of scope**. A rename to
`error-plumbing` is worth considering for accuracy. See [REVIEW-3.md](REVIEW-3.md) R3-S4.

Pinning the enum has a measured side effect on **variance**. Because the given enum and the fixed
plumbing shape are most of what the model sees, the *first* version of this family sat close together —
median inter-instance distance 0.263 with a **distinct-at-floor capacity of only 3** (against
`borrow-lifetimes`' 8), below any usable per-epoch seed count (measured on the Phase-3 exemplar
families, [BUILD-LOG](BUILD-LOG.md)).

Widening the variable surface (Q30 lever 2) — combine operations 3 → 5, validation rules 3 → 6, and
seed-varied worked examples — raised the *view*-distance to median **0.438** with **0 near-twin
prompts**. But that lift is mostly illusory: measured on the **solution** rather than the prompt, this
family's distinct-at-floor capacity is only **7**, with **12/28** reference near-twins — the pinned-enum
plumbing dominates every solution. The seed-varied examples freshen the prompt (contamination-resistance)
but do not add solution diversity. This is exactly why the family "tests plumbing, not error design", and
it is the concrete evidence behind [Q31](OPEN-QUESTIONS.md). Under Q31's decided measure — distinct
structural specs (constants excluded) — `error-handling`'s authoritative diversity is **30 skills**
(5 combines × 6 rule-types), comfortably above a per-epoch seed count even though its *solution* text is
highly repetitive. See also [Q3](OPEN-QUESTIONS.md) / [Q30](OPEN-QUESTIONS.md).

## Per-category oracle weights

The global default (`behavior 0.70 / constraint 0.20 / quality 0.10`) is **wrong for several categories** and is overridable per category and per family.

The clearest case is `borrow-lifetimes`. A solution that clones everything is *semantically correct* — it passes every behavioural property. The entire signal is in L3. Grading that category on the global weights would score a clone-everything model almost identically to one that actually understands borrows, in the project's own flagship category.

| Category | behavior | constraint | quality | Rationale |
|---|---|---|---|---|
| `borrow-lifetimes` | 0.35 | **0.55** | 0.10 | Cloning is behaviourally correct; constraints carry the signal |
| `idiom-refactor` | 0.30 | **0.60** | 0.10 | The task *is* the constraint |
| `perf-optimization` | 0.30 | 0.10 | **0.60** | Criterion ratio is the point |
| `test-authoring` | 0.20 | 0.10 | **0.70** | Mutation score is the point |
| `unsafe-core` | **0.70** | 0.30 | 0.00 | UB under miri is a behavior failure, not a style deduction |
| all others | 0.70 | 0.20 | 0.10 | Default |

Weights are declared in the category definition, overridable in `task.toml`, and **published on the leaderboard** — a hidden weighting is as much an attack surface as a hidden timeout.
