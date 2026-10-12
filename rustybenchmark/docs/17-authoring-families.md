# 17 — Authoring a family

This is the practical guide to adding a generator family. It exists because family authoring is the
project's long pole — 272 families at 1–3 days each ([14-roadmap.md](14-roadmap.md)) — so the pattern the
families share is written down once, here, rather than re-derived each time. Gate **G3** is "a new
contributor authors a validated family in ≤ 2 days"; this guide is what makes that plausible.

## Reference families — copy the closest one

Eleven families exist. They fall into a few **archetypes**; pick the one whose *shape* matches the skill
you want to probe and copy it.

| Archetype | Copy | What it looks like |
|---|---|---|
| Seed-selected pipeline over a slice → `Vec`/scalar (the workhorse) | [`seq_transform.rs`](../crates/bench-gen/src/seq_transform.rs), [`bit_manipulation.rs`](../crates/bench-gen/src/bit_manipulation.rs) | filter → map → terminal / mask → transform. A free `fn f(...) -> ...`; no pinned types. |
| In-place mutation with an **allocation** (L3) constraint — constraint-dominant | [`window_op.rs`](../crates/bench-gen/src/window_op.rs), [`dual_region.rs`](../crates/bench-gen/src/dual_region.rs) | `&mut [i64]`; a clone-everything answer is behaviourally correct but caught by `alloc.rs`. `window-op` is a single windowed pass; `dual-region` is a `split_at_mut` two-region pass. |
| **Pinned interface** — a type is given, the model fills in against it | [`error_handling.rs`](../crates/bench-gen/src/error_handling.rs) (pinned enum + `?`), [`traits_generics.rs`](../crates/bench-gen/src/traits_generics.rs) (implement a trait), [`generic_select.rs`](../crates/bench-gen/src/generic_select.rs) (write a generic fn over a pinned trait) | The skeleton carries the enum/trait/driver; the model returns the complete `lib.rs` keeping it. |
| Provided enum + exhaustive `match` | [`stack_machine.rs`](../crates/bench-gen/src/stack_machine.rs) | a `Vec<i64>` stack driven by a match over provided ops. |
| **Signature-forced** skill | [`unsafe_core.rs`](../crates/bench-gen/src/unsafe_core.rs) (`*const i64` → `unsafe` is unavoidable) | the function signature makes the skill mandatory, not merely permitted. |

The rest of this document is *why* each part is shaped the way it is.

## The contract

A family implements `bench_gen::Generator`. Everything is a pure function of the `seed` — same seed →
byte-identical instance — because resume and replay depend on it ([09-resume-and-checkpointing.md](09-resume-and-checkpointing.md)).
Never touch the OS RNG; use `bench_gen::Rng` (SplitMix64) seeded from the task seed.

```
fn id(&self) -> &str                       // family id, e.g. "stack-machine"
fn category(&self) -> &str                 // the skill category this family probes
fn generate(&self, seed) -> GeneratedTask  // the model's view + hidden oracle + grading config
fn reference_code(&self, seed) -> String   // the correct solution; must score 1.000
fn skeleton_code(&self, seed) -> String    // the ablated body (todo!()); must fail
fn trivial_baselines(&self, seed) -> Vec<(label, code)>  // right shape, wrong content; each must fail
fn spec_signature(&self, seed) -> Vec<String>            // the structural identity (Q31)
```

Register the new id in `bench_gen::FAMILY_IDS` **and** the `family()` match **and** the `spec_diversity`
pin test in `lib.rs`, all in the same commit (a drift-guard test fails otherwise).

## The recipe (solution-first)

The order matters — it is what makes the oracle correct by construction (ADR-0003). Do **not** write a
prompt and then a checker; derive both from a `Spec`.

1. **`Spec` + `sample(seed)`.** Draw the *structural* choices from the seed: which operation, which rule,
   which stride — the things that define the skill. This is the family's variable surface. Two axes of
   4–6 each (giving ~12–48 distinct specs) is the sweet spot.
2. **`eval` — the native reference.** Write the answer as ordinary Rust that computes the correct result
   for a `Spec` and an input. This is the source of truth.
3. **`reference_src` — the emitted reference.** Render `eval`'s logic as a source string. It must be a
   *mirror* of `eval`: the same arithmetic, the same edge-case handling. This is the pair you must keep
   in lockstep — the differential gate below is what catches you when you don't. (The two need only be
   *semantically* identical, not textually: `dual-region`'s native `eval` uses `enumerate` to satisfy
   clippy while its emitted reference uses a plain index loop. The differential proves they agree.)
4. **`skeleton_src`.** The reference with the body replaced by `todo!()`, plus the worked examples as a
   doc comment. Keep any provided types (enums, traits, signatures) that the model must not re-invent.
5. **`prompt`.** Describe the task from the `Spec`. State edge cases explicitly (empty input, underflow).
   End with the canary (`mint_canary(family, seed)`), which must appear verbatim in the prompt.
6. **Oracle tests** (hidden): a `behavior` test from the worked examples, and a `differential` test that
   fuzzes ~3000 random inputs comparing the model against an inlined copy of the reference. Add an
   `alloc` test only if the category's signal is allocation (see `window-op` / `dual-region`).

## Worked examples: seed-vary them, and include one guaranteed-non-trivial case

Examples appear in both the prompt and the skeleton doc, so they are the family's largest per-instance
text. Seed-vary them (fresh numbers each instance) — it is good for contamination-resistance and it lifts
view-distance. **But** always include one *canonical* case constructed to be non-trivial under every
`Spec`, because the trivial baselines only fail if the canonical case is genuinely changed by the
operation. Compute every example with `eval`, never by hand.

## Trivial baselines: pick ones caught on *every* seed

The baseline gate (`baselines_caught`) requires each degenerate answer to fail on **every** seed. The trap:
a *shaped* baseline (return the input unchanged, return the sum, return the length) usually coincides with
exactly one real spec, and then it passes on that seed and the gate fails. Two reliable strategies:

- **Vec/collection output** → `identity` (return the input) and `empty` (return `[]`) are caught as long as
  the canonical case is changed *and* left non-empty by every spec (`seq_transform`, `str_transform`,
  `window_op`).
- **Scalar / `Option` output** → shaped baselines coincide, so use **two spec-independent constants** and
  choose a canonical input whose answer is provably never either constant. `trait_impl`/`raw_ptr` use
  `const-zero` + `const-one` with a canonical proven ∉ {0, 1}; `generic_select` uses `const-none` +
  `const-zero` with a canonical proven `Some(v), v ≠ 0`. Always pin this with a unit test that loops every
  `(axis…)` combination over the canonical input and asserts the answer avoids the baseline values.

## Forcing the skill through the signature

The oracle grades behaviour; it cannot see *how* the model got the answer unless the shape forces it. Two
families make the target skill unavoidable rather than merely encouraged:

- `raw_ptr` takes `ptr: *const i64` — there is no safe way to dereference it, so a scoring answer *must*
  contain `unsafe`. (Its honest limit: without miri, behaviour + differential catch wrong answers and
  gross out-of-bounds but not subtle unsoundness. Recorded loudly; miri is roadmap P7.)
- `trait_impl` pins the trait's associated type and method signatures; get them wrong and the generic
  driver's bound is unsatisfiable, so the hidden tests fail to build and the answer scores 0.0 — which is
  exactly the "L1 + signature match" oracle emphasis docs/04 assigns `traits-generics`.

## The two numbers that are *not* the same thing (Q31)

Do not confuse these, or you will ship a family that looks diverse and isn't:

- **View-distance / contamination.** Whether two instances' *prompts* differ. Seed-varied examples make
  this easy — too easy: it saturates and is **gameable**. It guards only "has the model seen this exact
  prompt", nothing more. `validate-family` reports it; the epoch sampler serves on it for freshness.
- **`spec_signature` / diversity.** The count of distinct signatures (`bench_gen::spec_diversity`) is the
  **authoritative, ungameable** task-diversity number, and the one a family is authored against. Include
  the structural choices; **exclude** numeric constants and the function name (`AtMost(10)` and
  `AtMost(50)` are the *same skill*). Your family's spec-diversity must comfortably exceed the per-epoch
  seed count.

**Reference-distance is a diagnostic, not a gate — and it is systematically deflated by fixed scaffolding.**
Measured across the families: `bit-ops` and `str-transform` (short bodies whose text changes with the op)
have reference-capacity 45–56, while every **pinned-interface** family is far lower — `error-handling` 7,
`stack-machine` 2, `trait-impl` 1, `generic-select` 4, `dual-region` 6 — because the enum/trait/loop
scaffolding is most of the solution text and only a few lines vary. That is expected and fine: it is a
property of the text proxy, not of the family's diversity. Author against `spec_diversity`; report the rest.

## Validate before you commit

```bash
rustybench validate-family --family <id> --seeds 8
```

Every seed must print `OK`, and the report must show a spec-diversity above your intended per-epoch
count. The gates, and why each exists:

| Gate | Catches |
|---|---|
| `reference = 1.000` | The reference passes its own oracle — the load-bearing self-consistency check |
| `skeleton_behavior < 0.5` | Ablation actually removed the answer |
| `baselines_caught` | Each degenerate answer (const / echo / unwrap) fails — the oracle is not too weak |
| `determinism` | Same seed → identical instance (resume/replay depend on it) |
| `canary` | The prompt carries its leak-detection canary, and no oracle content leaks in |
| differential (inside grading) | The emitted reference matches the native `eval` on 3000 random inputs — this is what keeps step 2 and step 3 honest |

If the reference does not score 1.000, the emitted source and native `eval` have drifted, or a test
target does not build against the reference — fix the mirror, do not weaken the test.

## Pitfalls the families have already hit

- **Emitted-source landmines.** `i64::MIN` has no negative-literal form; `window-op` omits `Min`/`Max`
  for this reason. Prefer identities and constants that render as plain literals.
- **Overflow in the differential.** Debug builds panic on overflow, which fails the differential
  spuriously. Bound the fuzzer's values and program length so no legal input overflows. Bitwise families
  (`bit-ops`) are exempt — their ops wrap by definition — which is a reason to like them.
- **Empty test targets.** Leave `alloc_test` (etc.) as `""` to opt a layer out; the CLI maps empty → not
  configured. A configured target that produces no test summary scores **0.0**, not "absent".
- **Low genuine diversity hiding behind fresh prompts.** If `spec_diversity` is small, widen the
  structural surface (more operations / rules), not the example noise. See Q30/Q31.
- **Clippy runs on your generator, `-D warnings`.** The emitted *strings* are graded without `-D warnings`,
  but your `sample`/`eval`/fragment code is not: `enum_variant_names` (don't prefix every variant with
  `Keep`), `needless_range_loop` (use `enumerate`), and `unnecessary_literal_unwrap` have all fired on
  first cuts this month. Run `cargo clippy --workspace --all-targets -- -D warnings` before committing.
