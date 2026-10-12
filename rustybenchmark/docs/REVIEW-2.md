# Adversarial review — round 2

**Date:** 2026-08-17 · **Scope:** the four targets deferred from [REVIEW.md](REVIEW.md), plus a fresh pass for cross-document contradictions · **Method:** empirical where possible — findings R2-S2, R2-S3 and R2-S7 are measured against rustc 1.97.0, not reasoned.

Round 1 found that its own stated scope was too narrow. So this round also re-read the corrected documents against each other, which is where the most severe finding came from.

---

## R2-S1 — Paired design and challenge nonces are mutually contradictory · **PATCHED**

**Severity: architectural.** Two corrected documents now specify incompatible things.

[07-statistics.md](07-statistics.md) requires that **every model in an epoch runs the identical seed set**, because McNemar on discordant pairs is where the claimed 2–4× power gain comes from. Without it, separating two models 5 points apart needs ~1,530 effective items per arm — far beyond any suite we will ship.

[10-integrity.md](10-integrity.md) derives seeds as `blake3(challenge_nonce || epoch || task_id || i)` where the nonce is issued **per batch, per run**, precisely so it did not exist before the request.

**Both cannot hold.** If the nonce is per-run, two submitters get different seeds and the runs are not paired. If the nonce is per-epoch and shared, it is public the moment the first submitter receives it, and precomputation is back.

This is the load-bearing statistical claim and the load-bearing integrity claim contradicting each other. Neither document was wrong in isolation; the conflict only appears when they are read together, which is exactly what round 1 did not do.

**Resolution — split the seed set.** Each epoch issues two disjoint sets:

| Set | Share | Seed derivation | Purpose |
|---|---|---|---|
| **Paired core** | ~85% of units | `blake3(epoch_seed \|\| task_id \|\| i)`, fixed per epoch, identical for all submitters | Scoring and cross-model comparison. Pairing works |
| **Fresh probe** | ~15% of units | `blake3(batch_nonce \|\| task_id \|\| i)`, per batch, per run | Precomputation detection. Never scored |

The reported score comes from the paired core. The probe is a **detector**: if a submission's probe score is materially below its core score, the core result was likely prepared in advance. The gap is the signal, and it is available per submission without needing to trust anything.

This is strictly better than either original design. Pairing is exact; precomputation is detectable rather than merely bounded; and a cheater must now solve the probe honestly *and* match their own inflated core score, which is self-defeating.

Recorded as [ADR-0009](adr/0009-paired-core-and-fresh-probe-seeds.md).

---

## R2-S2 — `failure_class` from rustc codes is blind or ambiguous for a third of real failures · **PATCHED**

**Measured**, not assumed. 33 realistic failure cases — the kinds of mistake a model actually makes — compiled with rustc 1.97.0, error codes extracted from `--error-format=json`.

### Results

| Outcome | Count | Share |
|---|---|---|
| **No error code at all** (`code: None`) | 6 | **18%** |
| **E0277** (spans four different categories) | 5 | **15%** |
| Category-specific, informative code | 22 | 67% |

### The codeless cases

```
ac_future_not_send      NONE    "future cannot be sent between threads safely"
ac_mutex_across_await   NONE    RefCell guard held across await
x_closure_lifetime      NONE
x_send_sync_struct      NONE    Cell<i32> in a struct passed to a Send bound
idiom_clippy_only       NONE    compiles cleanly; clippy-only
idiom_clippy_only2      NONE    compiles cleanly; clippy-only
```

The first two matter most. **"future cannot be sent between threads safely" — the single most characteristic async failure in Rust — carries no error code.** Verified directly:

```
error: future cannot be sent between threads safely
  = help: within `impl Future<Output = ()>`, the trait `Send` is not implemented for `Rc<i32>`
```
```
JSON: level=error, code=None
```

Every such failure would have landed in `other`. The `async-concurrency` category's diagnostic signal was zero.

### The ambiguous code

E0277 appeared in **four different categories**: error-handling (`?` without a `From` impl), traits-generics (associated-type mismatch), unsafe-core (`Rc` passed to a `Send` bound), and a generic unsized-argument error. It is the most common code in the sample and carries essentially no category information.

### The blind category

`idiom-refactor` produces **zero rustc errors by construction** — non-idiomatic code compiles. Clippy catches all of it:

```
idiom_clippy_only   rustc: clean   clippy: "writing `&Vec` instead of `&[_]`"
                                           "the loop variable `i` is only used to index `v`"
idiom_clippy_only2  rustc: clean   clippy: "match can be simplified with `.unwrap_or_default()`"
```

A core category was entirely invisible to the diagnostic histogram.

### What does work

`borrow-lifetimes` is genuinely well served — E0499, E0502, E0515, E0597, E0382, E0106 are all distinct and specific. `traits-generics` likewise — E0117, E0119, E0038, E0599, E0107. The mechanism works for the two categories it was designed against and fails elsewhere, which is the classic shape of a feature validated only on its motivating example.

**Resolution.** `failure_class` derives from a **tuple**, not a code:

```
failure_class = classify(error_code, message_pattern, clippy_lints, category)
```

- Codeless errors classified by message regex against a curated pattern table (`"future cannot be sent"` → `async-send`, etc.)
- `idiom-refactor` classified from **clippy lint names**, which are stable identifiers and better than error codes would have been
- E0277 disambiguated by its `help` text, which names the actual unsatisfied trait
- **Publish `classified_rate` per category.** If a category's failures are 40% `other`, that is a fact about our instrumentation and it belongs on the leaderboard, not hidden.

---

## R2-S3 — rustc phase ordering biases the histogram against the flagship category · **PATCHED**

**Measured.** A realistic multi-bug function — the kind of thing a model actually emits — containing both a type error and two borrow errors:

```rust
let c = m.entry(w).or_insert(0);              // borrow issue
let longest = words.iter().max_by_key(...);   // type issue
m.insert(longest, m.len());                   // borrow issue
```

Compiles to:

```
E0308  mismatched types
E0308  mismatched types
total errors: 2
```

**The borrow errors never surface.** Type checking aborts before borrowck runs, so they are never reached.

**Failure.** The diagnostic histogram systematically **undercounts borrow failures**, in the exact category the project names as its niche. A model that is bad at both types and borrows registers as bad at types only. The `32.6% of failures are type/trait/borrow semantics` framing that motivated the whole project would be measured with a known bias and no acknowledgement of it.

**Resolution.** There is no way to make borrowck run on code that does not type-check — this is a property of the compiler, not our harness. So:

- Record `diagnostic_completeness ∈ {full, typeck_only}` per unit — whether borrowck was reached at all.
- Treat borrow-failure counts as a **lower bound**, stated as such wherever the histogram is published.
- In `borrow-lifetimes` specifically, the skeleton should be type-complete so that the model's edit is unlikely to introduce type errors that mask the borrow signal. That is a **generator design constraint**, and it belongs in the family authoring guide.

---

## R2-S4 — `cross-module` cannot test what it claims · **PATCHED**

**Severity: construct validity.**

The category is squeezed between two constraints that were introduced in different documents and never reconciled:

- **Q12 / context limits** push repo size *down*: at 32k context, a task must be ≤2k LoC to fit alongside instructions and repair diagnostics.
- **Construct validity** pushes repo size *up*: Rust-SWE-bench's repos averaged **993 files / 128k LoC**, and repo-wide comprehension is 43.7% of agent failures *because* the repo does not fit in the head.

At ≤2k LoC **the entire repository fits in the prompt**. There is nothing to navigate. The category measures long-context reasoning, which is a real capability but not the one on the label.

**Resolution.** Rename to **`cross-module`** and rescope the claim: it tests coordinating a change across several files and modules, which is genuine and worth measuring. It does **not** test repo navigation, and the docs now say so.

True repo-navigation testing requires a model that can request files it has not been shown — i.e. tools — which makes it an agentic measurement. It is therefore moved to the agentic track (P8) as `repo-navigation`, where it belongs, rather than being half-done in the core suite.

---

## R2-S5 — The mining pool constraints are self-contradictory · **PATCHED**

The spec asks for repos **>1k stars** *and* **≤2k LoC**. Rust-SWE-bench's >1k-star pool averaged **993 files and 128k LoC**. These two filters are nearly disjoint: popular Rust repositories are large, and 2k-LoC repositories are rarely popular.

Yield arithmetic is already unforgiving before the contradiction — Rust-SWE-bench got 500 tasks from ~80k scraped PRs, **0.63%**, with no size constraint at all.

**Resolution.**

- **Mine workspace member crates, not whole repositories.** A large, popular repo often contains individually small crates. This preserves code quality and issue-linkage while getting the size down — and it is how the constraint should have been expressed in the first place.
- **Drop the star threshold to ~200.** Widens the pool substantially at modest quality cost, since the fail-to-pass validation gate does the real filtering.
- **Relax to ≤5k LoC**, consistent with the `cross-module` rescope.
- **G4's threshold is re-derived from the new pool** rather than carried over.

---

## R2-S6 — Two generator archetypes are needed; only one is specified · **PATCHED**

Round 1 deferred "does `Spec` generalise to an awkward category". Worked through for `idiom-refactor`. It generalises — but **not by the specified mechanism**.

The documented pipeline is `Spec → synthesize_reference → ablate → prompt`. Ablation removes the answer and asks for it back. For `idiom-refactor` there is nothing to remove: the model is *given* working code and asked to improve it.

The correct inversion:

```rust
let spec      = Spec::sample(seed);            // selects anti-patterns, types, domain, nesting
let reference = synthesize_idiomatic(&spec);   // the GOOD version
let prompt_src = de_idiomatize(&reference, &spec);  // apply inverse transforms
```

`de_idiomatize` is mechanical: each clippy lint has an invertible form. `iter().map().collect()` → index loop. `?` → match with early return. `unwrap_or_default()` → explicit match. These are writable as `syn` transforms, and **the anti-pattern catalogue is a set of invertible transforms** with the seed selecting which subset to apply and where.

So there are two archetypes, and `bench-gen` currently specifies only the first:

| Archetype | Spec varies | Generation | Categories |
|---|---|---|---|
| **Parametric** | a structured space (lifetime count, bound shape, nesting, sizes) | synthesise → **ablate** | `borrow-lifetimes`, `traits-generics`, `unsafe-core` |
| **Compositional** | selection from an authored catalogue | synthesise → **inverse-transform** | `idiom-refactor`, `error-handling` (hybrid) |

Combinatorics are adequate: ~15 catalogue entries choose 3 gives 455 combinations before type, domain, and placement variation.

**This is a framework change, not a per-family one, and it is unbudgeted in Phase 3.** Added to the roadmap.

### A threat-model asymmetry worth stating

Compositional catalogues are finite and enumerable. A model that memorises 15 anti-pattern → idiom mappings solves every instance.

**That is fine, and it is the point.** Knowing the idiom catalogue *is* being good at idiomatic Rust. Contamination resistance is not uniformly valuable across categories: for `borrow-lifetimes`, memorising instances is cheating; for `idiom-refactor`, the generator's job is to test **application in novel composition and context**, not recall. The `min_instance_distance` gate still applies — instances must differ in composition and setting — but the underlying goal differs, and pretending otherwise would lead to over-engineering the wrong defence.

---

## R2-S7 — Compositional categories break two oracle layers · **PATCHED**

There is no unique idiomatic solution. Consequences:

- **`size_ratio` is unsound** for compositional categories. A different-but-equally-idiomatic answer is penalised for not matching one arbitrary reference. **Disabled** for `idiom-refactor` and `error-handling`.
- **Differential comparison remains valid** — it checks behaviour, and behaviour *is* unique.
- **Clippy remains valid** — it is objective and does not privilege one form.

This reinforces the per-category weight decision from round 1: for compositional categories the constraint layer is not merely dominant, it is close to the whole oracle.

---

## R2-S8 — Windows: job object + WFP is the wrong primitive · **PATCHED**

[08-run-protocol.md](08-run-protocol.md) specified "WFP rule / job object" for network denial. Direct WFP filtering at the level needed for reliable isolation is **kernel-mode** — a signed driver, which is out of the question for a tool people install to benchmark their laptop.

**The correct primitive is AppContainer.** Capability-based and OS-enforced: a process launched into an AppContainer without the `networkClient` capability has its traffic dropped by WFP automatically, with no driver of our own. This is the same combination used by current agent sandboxes — token privilege stripping, a job object capping the process tree, and WFP-enforced network denial.

Corrected division of labour on Windows:

| Control | Primitive |
|---|---|
| Network denial | **AppContainer** without network capabilities |
| Filesystem scope | AppContainer SID + explicit ACLs on the workspace |
| Memory / CPU / process caps | Job object |
| Privilege reduction | Restricted token |

**Residual risk, and the real content of gate G1:** rustc and cargo must actually *function* inside an AppContainer. That requires granting the AppContainer SID access to the workspace, `CARGO_HOME`, and the rustup toolchain directory, and some toolchains break in unexpected ways under capability-based ACLs. This is unproven and remains the spike — but it is a tractable ACL problem rather than the driver-signing dead end the previous specification implied.

---

## R2-S9 — Per-segment recalibration breaks the evening-slices story · **PATCHED**

Full calibration is 60 s warm-up + 10 repetitions of pp512/tg128 + a 10-minute sustained phase ≈ **15 minutes**.

[09-resume-and-checkpointing.md](09-resume-and-checkpointing.md) sells "ninety-minute evening slices". Fifteen minutes of every ninety is **17% overhead**, spent measuring rather than benchmarking. Over a 39-hour suite in 90-minute slices that is roughly 6.5 hours of pure calibration.

**Resolution — tiered recalibration.**

| Segment | Calibration | Cost |
|---|---|---|
| 0 | Full: warm-up + 10 reps + sustained | ~15 min |
| 1..n | Abbreviated: warm-up + 5 reps, **no sustained phase** | ~3 min |
| any | Escalate to full **only if** abbreviated deviates >10% from segment 0 | ~15 min |

Overhead drops to ~3%. The stability guarantee is preserved: a machine whose behaviour has genuinely changed triggers the full measurement automatically.

---

## R2-S10 — Allocation instrumentation cannot attribute allocations as specified · **PATCHED**

Round 1 replaced forbidden-call blacklisting with a counting `#[global_allocator]`. Correct direction, unimplementable as written: **a global allocator is process-global**, and proptest's own machinery, the test harness, and the assertion framework all allocate. There is no way to attribute a given allocation to "the candidate function".

**Resolution — differential allocation measurement.** Run the *identical* harness twice, once against the reference and once against the candidate, and compare:

```
allocs_candidate − allocs_reference  ≤  budget
```

Harness overhead is present in both terms and cancels. No attribution is required, and the budget is naturally expressed relative to the reference — which is how the constraint was already written (`max_allocs = "reference"`).

Requires the harness to be deterministic in its own allocation behaviour: same proptest seed, same case count, same ordering. All already guaranteed.

---

## Lower-severity findings

| # | Finding | Resolution |
|---|---|---|
| M7 | Even "clean" codes are not perfectly category-pure — E0597 appeared in both a borrow case and an `impl Trait` lifetime-capture case | Accepted. Classification is (code, message, category); the category context disambiguates |
| M8 | `capability_score_lite` definition drifted across documents after the category split | Redefined once, in [04-categories.md](04-categories.md), and referenced elsewhere |
| M9 | `clippy-driver` is now load-bearing for a core category's oracle, adding a toolchain component to the sandbox | Documented as a hard dependency; preflight must verify it |
| M10 | `tg_missing_bound` produced E0369 (binary operation) rather than the expected E0277 | Confirms the pattern table must be built from measurement, not from expectation. Feeds the Phase 2 work |

---

## What survived round 2

- **Solution-first generation** held again, and gained a second archetype rather than being replaced.
- **The core/probe category split** ([ADR-0008](adr/0008-core-and-probe-categories.md)) held, and R2-S4 vindicates it — `cross-module` was already a probe category, so the rescope costs nothing in the headline number.
- **Work-unit idempotence and journal replay** attacked a third time, including against the new tiered calibration. Still sound: calibration is per-segment metadata, not per-unit state.
- **The verifiable/unverifiable split** held. R2-S1's fix strengthens it — the probe subset makes precomputation *detectable* rather than merely bounded.

## Round 3 scope

1. **The `Spec` for `error-handling`** — hypothesised hybrid, unvalidated. If it is neither cleanly parametric nor cleanly compositional, a third archetype may be needed and that changes Phase 3 scope again.
2. **Whether `de_idiomatize` transforms are actually invertible in practice** without producing code that reads as obviously machine-mangled. A prompt that looks generated is a prompt models will treat differently.
3. **The probe-subset detector's statistical power** — 15% of units may be too few to detect precomputation at a useful confidence. Needs the same effective-N arithmetic applied to it that round 1 applied to scoring.
4. **Server-side replay cost** under the corrected timing model, which is materially higher than when Q6 was written.
