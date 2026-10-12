# 03 — The oracle

Grading produces a **vector**, not a bit. Layers run in order; a failed gate short-circuits later layers but is always recorded.

```
L0 apply      gate
L1 compile    gate            + rustc diagnostic codes  <- richest Rust-specific signal
L2 behavior   weight 0.7      unit + property + differential
L3 constraint weight 0.2      clippy, unsafe, forbidden APIs, signature, miri
L4 quality    weight 0.1      mutation score, perf ratio, size ratio
```

```
task_score = (apply_ok && compile_ok)
           ? w_b*behavior + w_c*constraint + w_q*quality
           : 0.0
```

**Weights are per-category, not global.** The defaults above (0.7 / 0.2 / 0.1) are wrong for
several categories. In `borrow-lifetimes`, a solution that clones everything is *semantically
correct* — it passes every behavioural property, and the entire signal lives in L3. Grading the
project's flagship category on behaviour-dominant weights would score a clone-everything model
almost identically to one that understands borrows. See the weight table in
[04-categories.md](04-categories.md); weights are declared per category, overridable per family,
and published on the leaderboard.

The composite exists for sorting. **Always report the vector.** `compile_rate` alone is a headline-worthy number, and the error-code histogram is the diagnostic that tells a user *which part of Rust* a model is weak at.

---

## L0 — Apply (gate)

The model's response is materialised into the workspace.

- Patch applies cleanly, or whole-file replacement is well-formed.
- No writes outside the workspace root.
- No new files outside declared-writable paths.
- No modification of `Cargo.toml` dependency section unless the family permits it.

**Emits:** `apply_ok: bool`, `apply_error: Option<String>`

**L0 strips reasoning tags** (`<think>…</think>` and equivalents) before extraction when the row's
`reasoning_format` is `none`. Reasoning mode is set by the *weights' chat template*, not by any
request parameter — one measured template terminates the rendered prompt with
`<|im_start|>assistant\n<think>\n`, so it cannot be declared away and must be detected.

`apply_rate` is promoted from a weight-0.0 gate to a **published column**. A model that solves the
problem but cannot emit an extractable answer is a distinct and interesting failure, and the output
protocol moves it enormously: on identical Qwen2.5-Coder-32B weights and identical tasks, strict-diff
format scored **8.0%** with 71.6% well-formed responses, whole-file **16.4%** with 99.6% — a **2.05×
score difference from the response protocol alone**.

Response-format failures land here. Track them: a model that can solve the problem but cannot emit a valid diff is a real and separately interesting result. Aider's benchmark demonstrates that strict diff-edit format is itself a discriminator.

## L1 — Compile (gate)

```
cargo build --offline --locked --message-format=json
```

Capture **every** diagnostic, not just success/failure.

**Emits:**
- `compile_ok: bool`
- `error_codes: Vec<String>` — e.g. `["E0499", "E0597"]`
- `warn_count: u32`
- `build_ms: u64`
- `failure_class` (derived): `borrowck | trait | type | lifetime | async-send | syntax | resolve | idiom | logic | constraint | other`

  `logic` (compiled, failed L2) and `constraint` (compiled, passed L2, failed L3) were used in the
  schema's own examples without existing in this enum — [REVIEW-5.md](REVIEW-5.md) `report-json-stale`.
  `timeout` is **not** a failure class; it lives in `flags`, where the schema already puts it. The
  R4-S6 drift check is extended to compare enum *members* against values used in schema examples, not
  only field names against prose.
- `diagnostic_completeness`: `full | typeck_only`
- `classified_rate` (aggregate, per category)

### `failure_class` is derived from a tuple, not from the code

The obvious design — a lookup table from rustc error code to class — was **measured against rustc 1.97 on 33 realistic failure cases and found to be blind or ambiguous for a third of them** ([REVIEW-2.md](REVIEW-2.md) R2-S2):

- **18% of cases produce no error code at all.** Including *both* async cases: `future cannot be sent between threads safely` — the single most characteristic async failure in Rust — carries `code: None`. The entire `async-concurrency` category would have had zero diagnostic signal.
- **15% produce E0277**, which appeared across four different categories (error-handling, traits, unsafe, generic unsized). It carries essentially no category information.
- **`idiom-refactor` produces zero rustc errors by construction** — non-idiomatic code compiles. Clippy catches all of it.

So classification takes the whole diagnostic, plus context:

```
failure_class = classify(error_code, message_pattern, clippy_lints, category)
```

- Codeless errors are matched by **message regex** against a curated pattern table
  (`"future cannot be sent"` → `async-send`, and so on).
- `idiom-refactor` classifies from **clippy lint names**, which are stable identifiers and
  a better signal than error codes would have been.
- E0277 is disambiguated by its `help` text, which names the actual unsatisfied trait.
- The pattern table is **built from measurement, not expectation** — one probe case predicted to
  yield E0277 in fact yielded E0369.

**`classified_rate` is published per category.** If a category's failures are 40% `other`, that is a fact about our instrumentation, and it belongs on the leaderboard rather than hidden behind a confident-looking histogram.

### Borrow failures are a lower bound

Type checking aborts before borrowck runs. Measured on a realistic multi-bug function containing one type error and two borrow errors, rustc emitted **two E0308s and nothing else** — the borrow errors were never reached.

The histogram therefore **systematically undercounts borrow failures**, in precisely the category this project names as its niche. There is no harness-side fix; it is a property of the compiler. So:

- `diagnostic_completeness` records whether borrowck was reached at all.
- Borrow-failure counts are published **as a lower bound**, stated as such.
- **Generator constraint:** in `borrow-lifetimes`, the skeleton should be type-complete, so a model's edit is unlikely to introduce type errors that mask the borrow signal. This belongs in the family authoring guide.

Rust-SWE-bench attributes **32.6%** of agent failures to type/trait/borrow semantics. We make that visible per model and per category — with the measurement's own blind spots stated alongside it.

## L2 — Behavior (weight 0.7)

Three sub-oracles, all reproducible from the instance seed.

```toml
[behavior.unit]
weight = 0.3
# hidden example tests, seed-parameterised

[behavior.property]
weight = 0.5
runner        = "proptest"
cases         = 512
proptest_seed = "derive:instance"    # blake3(instance_seed || "prop")
properties    = ["order_preserved", "no_element_lost", "idempotent_on_empty"]

[behavior.differential]
weight  = 0.2
inputs  = 2000
compare = "eq"        # eq | approx(1e-9) | set_eq | order_insensitive
# candidate vs oracle/reference.rs on seeded generated inputs
```

Property and differential carry 70% of the behavior weight deliberately. Published evidence: property-based evaluation of StarCoder and CodeLlama on MBPP/HumanEval found **30–32% of solutions only partially satisfy correctness properties and 18–23% fail outright** — all of which example tests scored as passes. Example-only grading would bias our numbers upward in exactly the same way as everyone else's.

**Emits:** `behavior_score: f32` (0.0–1.0), per-sub-oracle breakdown, and `first_failing_input` — the proptest-shrunk minimal counterexample. Publish that last one; it is the single most useful artifact for a human reading a failure.

Property definitions live in `oracle/props.rs` and are **derived from the `Spec`**, not written against the reference implementation. Deriving them from the code would make them tautological.

## L3 — Constraint (weight 0.2)

Rust-specific static gates. Each is binary; the layer score is their weighted mean.

```toml
[constraint]
clippy          = { level = "deny", allow = ["clippy::needless_range_loop"] }
fmt             = true
unsafe_blocks   = { max = 0 }
forbidden_calls = ["clone", "to_vec", "Rc::new", "RefCell"]
required_traits = ["Iterator"]
miri            = { enabled = false }          # true for the unsafe-core category
no_std          = false
public_api      = "must_match_signature"       # exported signatures unchanged
alloc_free      = false                        # optional: no heap allocation in hot path
```

**All checks are AST-based via `syn`, never textual.** Grepping for `clone` is defeated by `<[T]>::to_vec` and false-positives on comments and string literals. The forbidden-call checker resolves method calls against the type where it can and falls back to path matching where it cannot; it records which mode it used so borderline results are auditable.

### Allocation is measured, not blacklisted

`forbidden_calls` cannot express "do not copy the data". Enumerating the ways to copy is hopeless:
`clone`, `to_vec`, `to_owned`, `Vec::from(&s[..])`, `iter().copied().collect()`,
`extend_from_slice`, `Box::new(x.as_ref().clone())`, and arbitrarily many more. A model that avoids
the listed names while allocating freely would score as though it satisfied the constraint —
false confidence, which is worse than no check.

So the real constraint is enforced at runtime:

```toml
[constraint.allocation]
enabled       = true
max_allocs    = "reference"      # reference | <integer> | reference*<factor>
max_bytes     = "reference*1.25"
```

The grading harness installs a counting `#[global_allocator]` and asserts an allocation budget
derived from the reference implementation's own measured behaviour. This measures the actual
property rather than a proxy for it, and it cannot be evaded by choosing a different API.

**Measurement is differential, because a global allocator is process-global.** proptest's own
machinery, the test harness, and the assertion framework all allocate, and there is no way to
attribute a given allocation to "the candidate function". So the identical harness is run twice —
once against the reference, once against the candidate — and the difference is what is bounded:

```
allocs_candidate − allocs_reference  ≤  budget
```

Harness overhead appears in both terms and cancels. No attribution is needed, and the budget is
naturally expressed relative to the reference, which is how the constraint was already written.
This requires the harness to be deterministic in its own allocation behaviour — same proptest seed,
same case count, same ordering — all of which the design already guarantees.

`forbidden_calls` is retained only where the constraint genuinely *is* about a specific API —
"solve this without `RefCell`", "no `unsafe`" — not as an allocation proxy.

**Emits:** `constraint_score: f32`, `violations: Vec<String>` with file:line — e.g. `"forbidden: clone @ src/lib.rs:41"`.

`miri` is mandatory for the `unsafe-core` category and off elsewhere (it is slow). When on, a miri UB report is a hard behavior failure, not a constraint deduction — undefined behaviour is not a style issue.

**Miri cannot run FFI.** It does not execute foreign function calls, which is the defining feature of the code `ffi-boundary` tests. That contradiction is why the original `unsafe-ffi` category was split: `unsafe-core` (raw pointers, transmute, aliasing, `Send`/`Sync`) is miri-checkable and became a core category; `ffi-boundary` (`repr(C)`, C interop, ABI correctness) is graded against a **real C shim linked at test time**, with no miri, and became a probe category.

## L4 — Quality (weight 0.1)

```toml
[quality]
mutation = { tool = "cargo-mutants", timeout_s = 120, weight = 0.5 }
perf     = { tool = "criterion", baseline = "oracle/reference.rs", max_ratio = 2.0, weight = 0.3 }
size     = { max_ratio_vs_reference = 3.0, weight = 0.2 }
```

- **Mutation score** is the primary oracle for the `test-authoring` category: did the model's *tests* kill the mutants? For other categories it measures whether the solution is meaningfully specified rather than accidentally passing.
- **Perf ratio** is the primary oracle for `perf-optimization`. Criterion against the reference implementation, ratio capped at `max_ratio`.
- **Size ratio** penalises LoC bloat relative to the reference.

L4 is expensive. **Off by default**; enabled with `--quality`. Required for `deep`, optional for `standard`, unavailable in `smoke`. It adds roughly 40 s per instance, which is why it appears explicitly in the timing model in [07-statistics.md](07-statistics.md).

### L4 is not replay-verifiable

Criterion timings are hardware-dependent by design and cargo-mutants is not deterministic. A server
re-grading a submission will not reproduce L4 numbers, and pretending otherwise would either reject
honest submissions or force the verifier to tolerate mismatches — which reopens the fabrication hole
that T1 replay exists to close.

Therefore: **T1 replay verifies L0–L3 exactly and treats L4 as unverifiable**, subject to
plausibility bounds only. L4's contribution to a score is labelled at T0 confidence even inside a
T2 row. This is a stated tier caveat, not a hidden one. See [10-integrity.md](10-integrity.md).

### Perf measurement caveat

Criterion ratios are noisy on thermally unstable or contended hardware. The `perf-optimization` category is therefore gated to:

- execution class `GpuFull`
- AC power (not battery)
- a stability precheck: repeated timing of the reference must vary by <5% across repetitions

If the precheck fails, perf tasks are skipped and the run is marked `perf_unavailable` rather than scored badly. See [06-execution-classes.md](06-execution-classes.md).

---

## Oracle isolation — non-negotiable

The single highest-value integrity control in the whole system.

1. The model's workspace and the grading workspace are **separate directories**.
2. `oracle/` content is materialised into the grading workspace **only after** the model's turn has completed and its response has been captured.
3. Before handing the workspace to the model, the harness asserts that no file in it hashes to any oracle file's content hash.
4. The sandbox denies network access for the entire turn, enforced by the OS, not by policy.

Terminal-Bench's three documented misconduct cases were: **shipping the test folder in the agent setup**, **modifying timeouts**, and **fetching solutions from the internet**. Controls 2, 4, and harness-owned timeouts respectively address each.

## Repair mode

When `interaction.mode = "repair"`, attempt 2 receives:

- the exact rustc diagnostics from L1 (rendered, not JSON)
- the names of failing tests and the shrunk counterexample from L2, **without the property source**
- constraint violations from L3 with file:line — **lint name and location only**

**Suggestion text is stripped for constraint-dominant categories.** Clippy emits machine-applicable
fixes: `manual implementation of Option::map: help: try: m.get(k).map(|x| *x)` is not a hint, it is
the complete answer. Feeding that back would make attempt 2 a copy operation and would turn
`idiom-refactor` into a test of transcription. The lint *name* (`clippy::map_clone`) and the location
are fed back; the `help: try: <code>` payload is not. See [REVIEW-3.md](REVIEW-3.md) R3-S2.

It does **not** receive: the reference implementation, hidden test source, property source, or expected outputs. Both attempts are scored and both are recorded; the reported task score is attempt 2's. Attempt-1 score is retained as `first_try_score`, which is a separately interesting metric.
