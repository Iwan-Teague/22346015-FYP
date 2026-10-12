# 02 — Task format

A task is not a file. A task is a **family**: a generator function from a seed to a fresh problem instance, its reference implementation, and its oracle.

## Directory layout

```
tasks/borrowck/split-mut-window/
├── task.toml            # manifest                          (public)
├── gen.rs               # seed -> Instance                  (public)
├── template/            # skeleton fragments                (public)
│   ├── Cargo.toml.hbs
│   └── src/lib.rs.hbs
└── oracle/                                                  (NEVER shown to the model)
    ├── synth.rs         # reference synthesis from Spec
    ├── props.rs         # property derivation from Spec
    ├── tests.rs         # hidden example tests
    └── constraints.toml # static / lint gates
```

Generators are public. **A solved instance is never published.**

**Seeds are secret while their epoch is open.** They are published when the epoch closes, with the
epoch's raw dump. Publishing them live would hand the second submitter in an epoch everything needed
to precompute the shared core seed set — and [R4-S1](REVIEW-4.md) shows the probe detector cannot
catch a submitter who precomputes and suppresses. Independent re-derivation stays fully possible,
delayed by one epoch. See [REVIEW-4.md](REVIEW-4.md) R4-S2.

## Manifest — `task.toml`

```toml
schema        = 1
id            = "borrowck/split-mut-window"
title         = "Sliding-window mutation without cloning"
category      = "borrow-lifetimes"
subcategory   = "aliasing"
difficulty    = 3                 # 1-5, author-declared; recalibrated from live data
authored      = "2026-08-17"
rust_min      = "1.85"
edition       = "2024"
suite         = "synth"           # synth | wild

[generation]
kind       = "seeded"             # seeded | mined | frozen
entry      = "split_mut_window"   # fn in gen.rs
seed_space = "u64"

# What a seed is actually allowed to change. All four should be true for a
# memorisation-resistant family; a renamer-only generator is worthless.
variance = { structural = true, naming = true, numeric = true, api_surface = true }

# Anti-twin floor: minimum normalised tree-edit distance between any two instances
# of this family, measured on PROMPT + SKELETON -- what the model actually sees.
# Reference-implementation distance is checked as a secondary signal only: two
# instances can have distant references and near-identical prompts, which is the
# same question from the model's point of view. Enforced in CI.
min_instance_distance     = 0.25   # prompt + skeleton (primary, PARAMETRIC families)
min_reference_distance    = 0.20   # reference impl    (secondary)
min_transform_jaccard     = 0.50   # transform-set     (primary, COMPOSITIONAL families)

# For a compositional family, task identity IS the transform set, not the surface. Round 4
# measured surface distance landing at 0.146 / 0.331 either side of a 0.25 threshold on cases
# where transform-set Jaccard gives an unambiguous 0.00 / 1.00. Surface distance is a correlate
# that holds only while reskins are shallow. See REVIEW-4.md R4-S4.

[interaction]
mode          = "repair"          # single-shot | repair | agentic
max_attempts  = 2                 # attempt 2 receives compiler + test output only
context       = "files"           # files | diff | agent-tools
budget_tokens = 32768             # completion cap; overrun is a scored failure.
                                  # 16000 starved reasoning models outright: measured, one model
                                  # returned finish_reason=length with ZERO characters of content at
                                  # 100/200/400 tokens, and only at 600 did it emit 113 chars of
                                  # correct code after 579 tokens -- ~94% of output was reasoning.
                                  # Qwen3's own card specifies 32768, and 38912 for complex code.
wall_timeout_s = 900

[deps]
offline  = true
vendored = ["itertools@0.14"]     # pre-vendored; no network at eval time

[oracle]
layers  = ["apply", "compile", "behavior", "constraint", "quality"]
weights = { behavior = 0.7, constraint = 0.2, quality = 0.1 }
# apply and compile carry weight 0.0 — they are gates, not score components.
```

## Generator contract

```rust
/// A materialised problem, ready to hand to a model.
pub struct Instance {
    /// Rendered task statement shown to the model.
    pub prompt: String,
    /// Files placed in the model's workspace.
    pub files: BTreeMap<PathBuf, String>,
    /// Oracle files. Injected into a *separate* grading workspace, after the
    /// model's turn has completed. Never present on disk during generation.
    pub hidden: BTreeMap<PathBuf, String>,
    /// Structured parameters the oracle needs (sizes, invariants, expected complexity).
    pub facts: serde_json::Value,
    /// Unique low-frequency string embedded in the prompt. If it later appears in
    /// a public corpus or in another instance's submitted output, this instance leaked.
    pub canary: String,
}

pub trait Generator {
    fn generate(&self, seed: u64) -> Instance;

    /// Self-check. Run in CI across >= 1000 seeds. See "Generator validation".
    fn validate(&self, seed: u64) -> Result<(), GenError>;
}
```

## Two generator archetypes

Solution-first is the principle. It has **two shapes**, and a family declares which one it uses.

| Archetype | `Spec` varies | Pipeline | Categories |
|---|---|---|---|
| **Parametric** | a structured space — lifetime count, bound shape, nesting depth, sizes, API route | synthesise reference → **ablate** → prompt | `borrow-lifetimes`, `traits-generics`, `unsafe-core` |
| **Compositional** | selection from an authored catalogue of invertible transforms | synthesise reference → **inverse-transform** → prompt | `idiom-refactor`, `error-handling` (hybrid) |

The distinction is not cosmetic. Ablation removes the answer and asks for it back — but in
`idiom-refactor` the model is *given* working code and asked to improve it, so there is nothing to
remove. The pipeline inverts:

```rust
let spec       = Spec::sample(seed);                    // anti-patterns, types, domain, nesting
let reference  = synthesize_idiomatic(&spec);           // the GOOD version
let prompt_src = de_idiomatize(&reference, &spec);      // apply inverse transforms
```

`de_idiomatize` is mechanical: each clippy lint has an invertible form. `iter().map().collect()`
→ index loop; `?` → match with early return; `unwrap_or_default()` → explicit match. **The
anti-pattern catalogue is a set of invertible `syn` transforms**, and the seed selects which subset
to apply and where. Combinatorics are adequate — 15 catalogue entries choose 3 gives 455
combinations before type, domain, and placement variation.

### Threat models differ by archetype

Compositional catalogues are finite and enumerable. A model that memorises 15 anti-pattern → idiom
mappings solves every instance — **and that is fine, because knowing the idiom catalogue *is* being
good at idiomatic Rust.**

Contamination resistance is not uniformly valuable across categories. For `borrow-lifetimes`,
memorising instances is cheating. For `idiom-refactor`, the generator's job is to test **application
in novel composition and context**, not recall. `min_instance_distance` still applies — instances
must differ in composition and setting — but over-engineering recall defences for a compositional
category would be defending the wrong thing.

## Solution-first generation (parametric)

**Do not write a problem and then a solution. Generate the solution from the seed, then derive the problem from it.**

```rust
fn generate(seed: u64) -> Instance {
    let spec      = Spec::sample(seed);            // structural params: lifetimes, bounds,
                                                   // sizes, which std API is the natural route
    let reference = synthesize_reference(&spec);   // ground truth — correct by construction
    let props     = derive_properties(&spec);      // invariants read off the Spec, not the code
    let skeleton  = ablate(&reference, &spec);     // remove exactly what the model must supply
    let prompt    = render_prompt(&spec, &skeleton);

    Instance {
        prompt,
        files:  skeleton,
        hidden: bundle(reference, props, spec.constraints()),
        facts:  spec.into(),
        canary: mint_canary(seed),
    }
}
```

Why this shape:

- **The reference is correct by construction.** It is built from the same `Spec` that generates the properties. There is no hand-written answer that can drift out of sync with the question.
- **Solvability is guaranteed.** The reference is, by definition, a solution that passes.
- **Difficulty is a knob.** `Spec::sample` reads difficulty parameters directly.
- **Seeds can vary structurally** without a human maintaining a matching reference for every shape. This is what lifts the cap on how memorisation-resistant a family can be. See [ADR-0003](adr/0003-per-seed-generated-references.md).

### What `Spec` should carry

At minimum, per family:

```rust
struct Spec {
    difficulty:   u8,
    // structural
    lifetimes:    u8,          // count and nesting of borrows involved
    generic_args: u8,
    trait_bounds: Vec<BoundShape>,
    nesting:      u8,
    // numeric
    sizes:        Vec<usize>,  // array lengths, window widths, thresholds
    // api surface — which std route is the natural solution this time
    api_route:    ApiRoute,    // e.g. ChunksExactMut | SplitAtMut | IterMutZip
    // naming
    idents:       IdentPool,   // domain-flavoured identifier set drawn from seed
}
```

Vary all four axes. A generator that only permutes identifiers is memorisable after a handful of instances and must fail CI via `min_instance_distance`.

### Varying the four axes is necessary, not sufficient

Two families built and measured in Phase 3 ([BUILD-LOG](BUILD-LOG.md), [Q3](OPEN-QUESTIONS.md)) show
that exercising all four axes does not by itself buy distance. `error-handling` varies structure,
naming, numerics and API surface and still lands at median prompt+skeleton distance **0.263 with 18/45
near-twin pairs**, versus `borrow-lifetimes`' **0.433 / 7-of-45**. The difference is scaffolding: when
the fixed part of a family — a pinned error enum, a parse-propagate skeleton, a forbidden-API list — is
large relative to the seed-varied part, the instances the model *sees* are close even though the four
axes all move underneath.

So variance is a property to **measure per family**, not one that seeding guarantees, and two things
follow. First, `validate-family` reports each family's min/median distance and near-twin count, and a
family that clears `min_instance_distance` *on average* can still contain near-twin pairs — the mean is
not the gate. Second, whether the fix is a per-category floor or a mandate to enlarge the variable
surface is open ([Q30](OPEN-QUESTIONS.md)); until it is decided, a scaffolding-heavy family must be
inspected on its near-twin count, not waved through on its median.

The sharper measure is **distinct-at-floor capacity**: the most instances a family can serve that are
all pairwise `≥ min_instance_distance`. The `bench_gen::epoch` sampler computes it by greedily rejecting
any candidate seed too close to an already-accepted sibling, and it is much smaller than the median
suggests — `window-op` seats **8**. That capacity is the real ceiling on how many memorisation-resistant
epochs a family can sustain before it must repeat an instance, so it, not the median, is the number
every Phase-3 family is authored against. The sampler also *serves* the epoch: it never emits a
near-twin, returning `Exhausted` if a family cannot supply the requested count — which is the point at
which that family must be enlarged.

`error-handling` is the worked example — and a cautionary one. Widening its variable surface lifted its
*view*-capacity from 3 to hundreds, but measuring on the **solution** instead of the prompt shows a true
capacity of only **7**: the seed-varied examples freshen the prompt without changing the answer. So
distance-on-view is gameable and distance-on-reference is deflated by shared boilerplate; **neither text
metric is task diversity**, which is the structural spec count. This is [Q31](OPEN-QUESTIONS.md),
**decided as two gates**: a generator's `spec_signature(seed)` names the structural choices that define
the skill (constants excluded), and `spec_diversity` counts distinct signatures — the authoritative,
ungameable diversity number a family is authored against (`window-op` 12 skills, `error-handling` 30).
View-distance is kept as a *separate* gate for contamination-resistance (has the model seen this exact
prompt), and `validate-family` reports spec-diversity, both distances, and both capacities. The lesson
for authoring: design the variable surface for genuine *skill* diversity, and never trust a healthy
view-distance line on its own.

## Generator validation (CI, ≥1000 seeds per family)

Every one of these is a hard gate. A family that fails any of them does not ship.

| Check | Why |
|---|---|
| Reference passes its own oracle | Self-consistency |
| Reference passes a **second, independently written** implementation via differential fuzz | Catches a wrong generator — the failure mode that silently corrupts every score |
| Skeleton **fails** the oracle | Ablation actually removed the answer |
| `todo!()`, `unimplemented!()`, empty body all fail | No trivial pass |
| Returning the skeleton unchanged fails | No copy-through pass |
| Pairwise prompt+skeleton distance ≥ `min_instance_distance` | Instances are not renamed twins *from the model's point of view* |
| Pairwise reference distance ≥ `min_reference_distance` | Secondary structural check |
| **Pairwise transform-set Jaccard ≥ `min_transform_jaccard`** (compositional families) | R4-S4's primary anti-twin gate. It was declared in the manifest and the schema but never added to this list, so nothing enforced it — [REVIEW-5.md](REVIEW-5.md) R5-S7 |
| Reference compiles clean under the family's own `constraints.toml` | The constraints are satisfiable |
| Generation is deterministic: same seed → byte-identical instance | Resume and replay depend on this |
| Prompt contains exactly one canary, and no oracle content | No leakage into the model's view |
| **`cargo clippy --fix` does not solve the instance** | Round 3 measured `clippy --fix` auto-solving **2 of 3** sample de-idiomatization transforms unaided, with equivalence tests still passing. Run it on every generated instance; if the auto-fixed result converges toward the reference, reject. See [REVIEW-3.md](REVIEW-3.md) R3-S2 |

`rustybench validate-family <id> --seeds 1000` runs all of the above.

## Seed derivation

Seeds are never author-chosen for scored runs.

**There are two derivations, not one**, because a single formula cannot serve both pairing and
freshness. [ADR-0009](adr/0009-paired-core-and-fresh-probe-seeds.md) is authoritative:

```
scored core  (~85%)  seed = blake3(epoch_seed  || task_id || i)[..8]   fixed per epoch, frozen in the plan
fresh probe  (~15%)  seed = blake3(batch_nonce || task_id || i)[..8]   per batch, slot-shaped, never scored
```

- The **core** set is identical for every submitter in an epoch, which is what makes paired comparison
  — and therefore the affordable suite sizes in [07-statistics.md](07-statistics.md) — possible.
- The **probe** set uses a per-batch nonce that did not exist before the request. It is a detector,
  not a score.
- Local/offline runs derive both locally and are trust tier T0.

> This section previously carried a single-nonce formula and asserted, in consecutive bullets, both
> that seeds "did not exist before the run was requested" and that "a fixed per-epoch seed set is used
> for all models". Those cannot both hold — that is exactly the contradiction ADR-0009 was written to
> resolve, restated verbatim in the document that was supposed to have been fixed
> ([REVIEW-5.md](REVIEW-5.md) `stale-seed-derivation`).
>
> Note also that neither derivation currently delivers what it claims: see
> [REVIEW-5.md](REVIEW-5.md) R5-S2 — `epoch_seed` is written to the submitter's disk before the first
> unit runs, so core seeds are not secret from the party holding them.

## `kind = "mined"`

For the `wild` suite (categories `cross-module` and `api-evolution`). Instead of synthesising, the generator draws from a pre-built corpus of real fail-to-pass commits, then applies seeded perturbations (identifier renaming, unrelated-hunk injection, dependency version shifts) so that instances are not byte-identical to upstream history.

Mined families cannot guarantee oracle correctness by construction — they inherit it from the upstream repository's own tests. They are therefore reported as a **separate suite**, never blended into the synthetic score. See [ADR-0002](adr/0002-hand-written-and-mined-suites.md).

## `kind = "frozen"`

A fixed instance with no generation. Used only for harness development and smoke tests. **Never eligible for a scored suite** — the harness refuses to include `frozen` families in `standard` or above.
