# Build log

A running record of what has actually been built, verified, and decided —
distinct from the design docs (which specify the target) and the review rounds
(which attack it). One entry per meaningful increment. Newest first.

The roadmap phases referenced here are in [14-roadmap.md](14-roadmap.md).

---

## 2026-10-05 · `parse-traits` — a seventh `error-handling` family: `FromStr` / `TryFrom` and validation order

**What.** Family #127 `parse-traits` (category `error-handling`, core). A pinned error enum
`ParseError { Empty, BadChar(char), TooLong(usize), OutOfRange(i64) }` and one of three pinned newtypes: `Slug(String)`
(lowercase letters, digits, `-`, at most `MAX_LEN` bytes), `Percent(u8)` (`"NN%"`), `Code { letter, num }` (`"A1234"`). The model
implements `FromStr` (`"abc".parse::<Slug>()`), `TryFrom<i64>` (`Slug::try_from(5)` and `5i64.try_into()`), or both. What is graded is
the **variant and payload** for an input that is wrong in more than one way, which the prompt states as a rule:
`CharsFirst` (badly formed beats too long) or `LengthFirst` (too long beats badly formed). The hand-built inputs include a
string that is both, for every type, and a unit test proves each type has an input on which the two orders disagree.

**Surface.** 3 types × (`FromStr` ×2 orders, `Both` ×2 orders, `TryFrom` ×1; the order is meaningless without `FromStr`, so it is
not part of that skill) = **15 distinct skills**; `MAX_LEN` is cosmetic. `unwrap` and `expect` are forbidden paths.

**Measured end to end** (mock endpoint, seed 2 = `Code`, `FromStr`, `CharsFirst`):

| answer | score | notes |
|---|---|---|
| reference | 1.000 | |
| the `LengthFirst` reference submitted for a `CharsFirst` task | 0.471 | builds; 8 of 15 behaviour tests pass, differential fails |
| `always-err` / `lenient` baselines | 0.284 / 0.222 | |

**Gates.** `validate-family --cover`: **41 seeds (all 15 skills) OK**, `reference=1.000`, `baselines_caught=true`
(`always-err`, `lenient`). Clippy flagged three `then(|| ..)` calls in the generator (now `then_some`). 6 module tests.

---

## 2026-10-05 · `bag-traits` — a seventh `traits-generics` family: the collection traits and the `IntoIter` type

**What.** Family #126 `bag-traits` (category `traits-generics`, core). A pinned `Bag<T>` owns a `Vec<T>`; the model
implements three of five std collection traits: `IntoIterator` for `Bag<T>`, for `&'a Bag<T>` and for `&'a mut Bag<T>`
(three `Item` types, three iterator types, two with a lifetime), `FromIterator<T>`, and `Extend<T>`. On stable Rust
`type IntoIter = impl Iterator` is unavailable, so the adapter type has to be **spelled out**
(`std::slice::Iter<'a, T>`, `std::iter::Rev<std::vec::IntoIter<T>>`, `std::iter::StepBy<std::slice::IterMut<'a, T>>`).

**Surface.** C(5,3) = 10 form sets × 3 iteration orders (forward, reverse, every other element) = **30 distinct skills**.
The tests use `i64` and `String`, call each form the way users do (`for x in &bag`, `for x in &mut bag`,
`collect::<Bag<_>>()`, `extend(..)`), and check `Bag` stays usable after a by-reference iteration.

**A test-visibility bug the gate caught, then a unit test for the class.** The first `wrong-order` baseline scored
**1.000** on seed 56 (a spec whose only iterator form is `&mut`): `for x in &mut bag { *x += 1 }` gives the same result in
forward and reverse order, so the order was unobservable and the baseline was not caught. The `&mut` test now adds the
visit *rank* (`k += 1; *x += k`), which differs between orders, and `wrong_order_is_observable_under_every_form_set`
proves, for all 30 skills, that the canonical observations differ between a spec's order and the baseline's.

**Measured end to end** (mock endpoint, seed 3 = `&`, `&mut`, `Extend`, forward): reference 1.000; the reference minus
the `&Bag` impl 0.222 (the hidden targets do not build); `empty` and `wrong-order` baselines 0.222.

**Gates.** `validate-family --cover`: **117 seeds (all 30 skills) OK**, `reference=1.000`, `baselines_caught=true`
(`empty`, `wrong-order`). 7 module tests.

---

## 2026-10-05 · `own-tokens` — a seventh `borrow-lifetimes` family: avoid the self-referential struct

**What.** Family #125 `own-tokens` (category `borrow-lifetimes`, core, constraint-dominant). `Tokens::new(text: &str)
-> Tokens` tokenizes a text and the queries return `&str` slices of it. docs/04 lists "avoiding self-reference" under
this category, and this is the shape it takes: keeping `Vec<&str>` next to the `String` they point into cannot be
written; the next-most-tempting design, `Tokens<'a>` borrowing the caller's text, **compiles** and is wrong for this
API because the hidden tests drop the source `String` first and keep using the `Tokens`. The working design owns a
`String` plus `Vec<(usize, usize)>` byte spans and slices on demand. `leak` is a forbidden path.

**Surface.** 4 tokenizers (non-whitespace runs; trimmed comma segments, empties skipped; non-empty lines with `\r`
stripped; fixed-width byte chunks) × C(5,3) query sets (`word`, `longest`, `find`, `span`, `rest_from`) = **40 distinct
skills**; the chunk width is cosmetic. The queries pin edge behaviour a hurried answer gets wrong: `longest` ties go to
the earliest, `span` is a byte range in the *original* text, `rest_from` past the end is `""`.

**Measured end to end** (mock endpoint, seed 0 = whitespace, `longest` + `span` + `rest_from`):

| answer | score | notes |
|---|---|---|
| reference (owns `String` + spans) | 1.000 | |
| `Tokens<'a>` borrowing the text | 0.611 | builds; every hidden target fails to build (source dropped) |
| `Box::leak` the text to `'static` | 0.694 | behaviour 1.0; forbidden-path constraint fails |
| `empty` / `whole-text` baselines | 0.611 / 0.669 | |

**Gates.** `validate-family --cover`: **205 seeds (all 40 skills) OK**, `reference=1.000`, `baselines_caught=true`
(`empty`, `whole-text`). Clippy found two no-op `.replace(..)` calls in my first baseline text before commit. 7 module tests.

---

## 2026-10-05 · `idiom-shape` — a seventh `idiom-refactor` family: lints whose fix changes the API

**What.** Family #124 `idiom-shape` (category `idiom-refactor`, core, clippy-dominant) on three lints that
`cargo clippy --fix` leaves alone (re-measured here, as in the earlier idiom entries) **and whose idiomatic fix needs
a new type**, so the prompt pins every new name, field and message exactly and the hidden tests call the new API:
- `result_unit_err`: `parse_level -> Result<u8, ()>` becomes `Result<u8, LevelError>`; style A a tuple struct carrying
  the untrimmed input, style B an enum (`Empty` / `NotNumber` / `OutOfRange`); `Display` text pinned; `Error` required
  (the tests also convert it into `Box<dyn Error>`).
- `large_enum_variant`: `Packet` with a 512-byte array (A) or a 416-byte `Frame` (B) inline must box it. The test
  asserts `size_of::<Packet>() <= 64`, so only an actual `Box` passes.
- `too_many_arguments`: `score(w, h, d, t, a, b, c, e)` becomes `score(Params)` (A, one struct) or `score(Dims, Coef)`
  (B, two). Same formula.

**Surface.** The 7 non-empty defect subsets × 2 styles per present defect = 3·2 + 3·4 + 8 = **26 distinct skills**;
bounds, the weight's byte count and the four coefficients are cosmetic. Unchanged code and `#![allow(..)]` both fail to
build against the new API; `allow` is a forbidden path.

**A generator bug the gate caught.** 18 of the first 38 seeds scored the *reference* 0.667: with a coefficient of 1 the
emitted `w * h * 1` trips `clippy::identity_op`, so the answer the family called correct was not clippy-clean. Coefficients
are now drawn from 2..=5. (This is the clippy-graded analogue of "the reference must score 1.000": any emitted constant
that clippy can simplify is a trap.)

**Gates.** `validate-family --cover`: **188 seeds (all 26 skills) OK**, `reference=1.000`, `baselines_caught=true`
(`unchanged`, `allow-attrs`), `clippy_fix_safe=true` on all 188 (2 to 4 lints survive `--fix`, matching the number of defects).
Measured end to end (seed 8 = enum error + array packet + one-struct params): reference 1.000; leaving the array unboxed
0.333; `unchanged` / `allow` 0.333. 6 module tests.

---

## 2026-10-05 · HEAD re-gated after the post-sweep changes: 30 families, 854 seeds, 0 failures

After the full registry sweep (118 families) the following changed: the per-thread allocation counter (7 families, re-gated in that sweep's pass 2), the deny-level clippy oracle fix (the 6 clippy-graded families, re-gated in full: 335/335), `E0038` classification (no gate effect), five new families, and the prompt-freshness changes above, which alter the worked examples that also feed the hidden behaviour tests of **30 families** (the 13 + 11 + 2 example-count bumps, `dyn-shapes`' now-seeded examples, and the recent families whose example ranges were widened).

This pass ran `validate-family --cover` on exactly those 30 families, which include the five newest (`idiom-ptr`, `idiom-traits`, `borrow-disjoint`, `dyn-safety`, `config-load`), under the shared cargo lock in foreground chunks: **854 seeds, every one OK, 0 failures** (19 each for the 24 data-structure/sequence families, `idiom-traits` 45, `idiom-api` 27, `dyn-safety` 78, `idiom-ptr` 69, `config-load` 103, `borrow-disjoint` 76). Together with the sweep (3,543 seeds over 118 families) and the clippy re-gate (335), every family in the registry has passed the gate on its current code. Not re-run: the remaining ~88 families whose generator and oracle path are byte-identical since the sweep.

---

## 2026-10-05 · Prompt-diversity diagnostics across all 123 families (`rustybench diagnose`), and 30 cheap fixes

**Why.** The registry sweep recorded pass/fail only. `validate-family` already prints the anti-twin and capacity
diagnostics, but only for the seeds of that run, and each family's run is graded (minutes). `rustybench diagnose
[--family F] [--seeds N]` computes the same numbers with **no model and no grading** and prints one TSV row per
family: skills, view min/median distance, near-twin pair %, view capacity (accepted/asked, `!` when the planner
exhausted its candidates), reference median distance, reference near-twin %, reference capacity. All 123 families at
32 seeds take about 8 minutes; the rows below match `validate-family`'s own figures on the families I cross-checked
(`idiom-api`: 14.0% near-twin, 9/27 capacity, both ways).

**How to read it.** "Near-twin" is a pair of seeds whose prompt+skeleton shingle distance is under the floor. A family
with *s* skills has about 100/*s* % near-twin pairs for free, because two seeds with the same skill differ only in
examples (10 skills: ~10%). The informative number is the **excess** over that floor. View distance is gameable and is
not the diversity measure (Q31; `spec_diversity` is), so this table is about **prompt freshness**, not skill coverage.
Reference-solution near-twin % is high wherever the solution is a large fixed body (15 families at 100%: the
data-structure families, `trait-impl`, `topk-stream`, ...): the documented deflation, left alone.

**Ranked, before the fixes** (excess over the structural floor, worst first; 32 seeds). 41 families had an exhausted
view-capacity plan and 26 could serve fewer than half of 32 mutually distinct prompts.

| family | skills | near-twin | excess (pts) | view capacity |
|---|---|---|---|---|
| union-find | 10 | 74.6% | +64.6 | 2/32 |
| segment-tree | 10 | 72.0% | +62.0 | 2/32 |
| slot-pool | 10 | 70.8% | +60.8 | 3/32 |
| rank-select | 10 | 70.6% | +60.6 | 2/32 |
| two-stack-queue | 10 | 67.7% | +57.7 | 3/32 |
| count-min-sketch | 10 | 59.7% | +49.7 | 5/32 |
| monotonic-window | 10 | 51.4% | +41.4 | 5/32 |
| base64-codec | 10 | 48.8% | +38.8 | 5/32 |
| idiom-traits | 19 | 31.2% | +25.9 | 5/32 |
| trie | 10 | 33.1% | +23.1 | 9/32 |
| prefix-sum-fenwick | 10 | 29.8% | +19.8 | 10/32 |
| histogram-bucket | 10 | 29.4% | +19.4 | 9/32 |
| dyn-shapes | 10 | 25.0% | +15.0 | 6/32 |
| config-load | 24 | 19.2% | +15.0 | 9/32 |
| poll-future | 10 | 24.0% | +14.0 | 10/32 |
| idiom-ptr | 20 | 17.1% | +12.1 | 15/32 |

(`idiom-api`, `blanket-impl`, `dyn-safety`, `skip-list`, `bloom-filter`, `ring-buffer`, `lru-cache`, `token-bucket`,
`gray-code-counter`, `topk-stream`, `moving-average` were the next tier.)

**Two causes, both cheap.**
1. **Too few seeded example lines.** The data-structure and several newer families put 3 seed-varied example lines
   under 4 fixed ones, in a prompt that is otherwise ~1.5 KB of shared API text. Raising that to 8 (13 families: the 11
   above plus `fenwick`, `poll_future`, `bloom_filter`, `gray_code`, `lru_cache`, `moving_window`, `token_bucket`,
   `topk_stream`, `iter_machine`, `ring_buffer`, `median_maintenance`, `binary_heap`) and, for `slot-pool` and
   `rank-select` whose example is a single number, to 16 over a range of 600 instead of 40, took 11 of the worst 12 to
   a full 32/32 view capacity. In my own recent families I widened value ranges and the number of shown cases
   (`idiom-traits`, `idiom-api`, `idiom-ptr`, `dyn-safety`) and gave `config-load` seeded *passing* values.
2. **A real bug in `dyn-shapes`.** Its prompt, skeleton and behaviour tests all used `worked_examples(7)`, a constant, so
   every instance with the same two operations was byte-identical in its examples. The examples now take the instance
   seed (`Spec.ex_seed`); near-twin 25.0% -> 0.2%.

**After.** Exhausted view-capacity plans 41 -> **15**, families under half capacity 26 -> **0**. Worst remaining
(capacity of 32): `iter-machine` 18, `angles`, `brackets`, `columns`, `perf-refactor`, `streaks`, `tennis` 20,
`scrabble` 21, `morse` 22, `chess` 24, `blanket-impl`, `ordinal`, `raii-guard` 30, `golf`, `letter-grade` 31.
`iter-machine` is inherent: its examples are the first *n* terms of fixed sequences, with nothing to vary.

**Caveat, stated plainly.** This raises prompt freshness (contamination resistance on the *view*), not skill
diversity: `spec_diversity` is unchanged for every family. The changed example generators feed the hidden behaviour
tests too, so every changed family was re-gated afterwards (next entry).

---

## 2026-10-05 · `config-load` — a sixth `error-handling` family: `Option` to `Result` plumbing and error precedence

**What.** Family #123 `config-load` (category `error-handling`, core). A pinned `Config` (key/value strings,
`get` returns the first entry with that key), `ConfigError { Missing, Invalid, Rejected }` and a three-integer
`Settings` are given. The model implements `load`: per field, look the key up (absent: the default, or `Missing` for a
required field), parse the trimmed text (`Invalid` carrying the *original* text), check the rule (`Rejected` carrying the
value); fields are processed in order and the **first** error wins. The other error-handling families produce, propagate
and *are* errors, fold a stream under a policy, or validate; this is the everyday `ok_or_else` / `map_err` / `?` chain
where the error *values* and their *precedence* are the answer.

**Surface.** 8 default patterns (which of the three fields have a default) × 3 rotations of the rules
{range, positive, even} = **24 distinct skills**; key names (4 sets) and range bounds are cosmetic. A default is trusted
and unchecked. The test list reaches every error kind under every pattern (unit-tested: `Missing` reachable iff some
field is required) and includes precedence cases, a padded value, and a duplicate key (first wins).

**Measured end to end** (mock endpoint, seed 0 = field 2 defaulted, rotation 1):

| answer | score | notes |
|---|---|---|
| reference | 1.000 | |
| fields evaluated in reverse order (wrong precedence) | 0.617 | builds; 11 of 13 behaviour tests pass, differential fails |
| `lenient` baseline (`unwrap_or`, no rule, never errors) | 0.330 | |
| `zero` baseline | 0.222 | |

The reversed-order row is the realistic one: it type-checks, passes everything that does not involve two simultaneous
errors, and is caught only by the precedence cases and the differential.

**Gates.** `validate-family --cover`: **103 seeds (all 24 skills) OK**, `reference=1.000`, `baselines_caught=true`
(`zero`, `lenient`). `unwrap`/`expect` are forbidden paths. 5 module tests. (Seeds take ~14 s here: 13 hidden cases plus a
3,000-config differential.)

---

## 2026-10-05 · `dyn-safety` — a sixth `traits-generics` family: object safety via `where Self: Sized`

**What.** Family #122 `dyn-safety` (category `traits-generics`, core). A pinned `trait Stage` has two ordinary methods
and one to three that make it unusable as `dyn Stage`: a **generic method** (`map_all<F: Fn(..)>`), a method that
**returns `Self` by value** (`rescaled(self, ..) -> Self`) and a **static constructor** (`default_stage() -> Self`). The
given code declares `run_pipeline(stages: &[Box<dyn Stage>], x)` against it, so it does not compile (E0038) until the
trait is fixed. The fix is `where Self: Sized` on each offender: the method stays callable on concrete types and leaves
the vtable. The model then implements `run_pipeline`.

**Surface.** 7 non-empty breaker subsets × 4 pipelines (fold, fold from the back, sum of independent applications, max
of independent applications) = **28 distinct skills**. The hidden tests call *every* breaker on concrete types (so
deleting one fails to build) and run the pipeline through `Vec<Box<dyn Stage>>`.

**Measured end to end** (mock endpoint, seed 4 = generic + static ctor, `max_each`):

| answer | score | notes |
|---|---|---|
| reference (`where Self: Sized` on both) | 1.000 | |
| `trait Stage: Sized` | 0.000 | does not compile (E0038) |
| `where Self: Sized` on one of the two only | 0.000 | still E0038 |
| breakers deleted (object-safe, but the tests call them) | 0.533 | builds; behaviour target fails to build, differential passes |
| `empty` baseline | 0.339 | |

**A classifier gap found on the way.** Both zero-scoring rows came back `failure=Other`: `E0038` was in no failure
bucket. It is now in the `Trait` bucket (unit test `object_safety_violation_is_a_trait_failure`), so the trait-system
failure rate counts it.

**Gates.** `validate-family --cover`: **78 seeds (all 28 skills) OK**, `reference=1.000`, `baselines_caught=true`
(`empty`, `deleted-breakers`). 7 module tests, including one asserting the tests call every breaker the given trait
declares.

---

## 2026-10-05 · `borrow-disjoint` — a sixth `borrow-lifetimes` family: the helper-method aliasing trap

**What.** Family #121 `borrow-disjoint` (category `borrow-lifetimes`, core, constraint-dominant). A pinned
`Machine` owns `cells: Vec<i64>` and `log: Vec<String>` and provides a helper `note(&mut self, msg)`. The model
implements `run(&mut self)`: rewrite each cell in place and log some changes. The natural first attempt,
`for (i, c) in self.cells.iter_mut().enumerate() { ...; self.note(..) }`, is the classic aliasing error: a `&mut self`
*method* borrows all of `self`, field access borrows only the field. Copying `cells` first (`clone`, `to_vec`,
`to_owned`) is a forbidden path.

**Surface.** 4 ops (add `k`, double, negate, clamp to a max) × 3 log conditions (cell changed, new value even, new
value above a threshold) × 2 directions (front-to-back, or back-to-front, which reverses the log order but keeps the
front index) = **24 distinct skills**; `k`, the max and the threshold are constants of the same skill and excluded from
`spec_signature`.

**Measured end to end** (mock endpoint, seed 29 = negate / new-even / forward):

| answer | score | notes |
|---|---|---|
| reference (index loop + `self.note`) | 1.000 | |
| `iter_mut().enumerate()` + `self.note(..)` | **0.000** | E0499; `failure=Borrowck` |
| `iter_mut()` + `self.log.push(..)` (disjoint fields) | 1.000 | also correct |
| `clone()` the cells first | 0.694 | behaviour 1.0; forbidden-path constraint fails |
| `noop` / `no-log` baselines | 0.669 / 0.728 | |

The first row is the point: the aliasing mistake is a *compile* error against the answer itself, so unlike the
hidden-test-build families it is classified `Borrowck` and scores zero, while the equally valid disjoint-field
version is accepted.

**A generator bug the gate caught.** Seven of 76 seeds scored the *reference* 0.767 (`behavior:no_summary`): when an
example's log was empty, the test's `vec![].into_iter().map(String::from).collect()` had no element type, so the
behaviour target did not build. The expected log is now a typed `Vec<&str>`. (The canonical cells and the threshold
range were also constrained so that every op x condition logs at least one entry: `NewAbove(t)` draws `t` from
`0..=1`, since a clamp or a negation can never exceed a larger threshold on the canonical cells; a unit test loops
every parameter choice.)

**Gates.** `validate-family --cover`: **76 seeds (all 24 skills) OK**, `reference=1.000`,
`baselines_caught=true` (`noop`, `no-log`). 6 module tests.

---

## 2026-10-05 · Oracle fix: deny-level clippy lints were invisible; and `idiom-traits`

**The oracle bug (found by `idiom-traits`).** `bench_oracle::parse_clippy_lints` kept only diagnostics at level
`warning`. Clippy reports its **deny-by-default** lints (the whole `correctness` group, and e.g.
`inherent_to_string_shadow_display`) at level `error`, so an answer carrying one looked clippy-clean. Measured on the
new family: the reference *plus the inherent `to_string` kept beside the `Display` impl* scored **1.000**; after the
fix it scores **0.667** (`failure=Idiom`, constraint 0.5). The parser now counts `clippy::*` codes at `warning` or
`error` level; rustc errors (`E0308`, which carry no `clippy::` code) and notes are still ignored. New oracle unit test
`deny_level_clippy_lints_count_but_rustc_errors_do_not`. It affects every clippy-graded family: the six
(`idiom-loop`, `-counter`, `-copy`, `-api`, `-ptr`, `-traits`) were re-gated in full afterwards: **335/335 seeds OK**
(58, 41, 95, 27, 69, 45), so none of their references or baselines had been leaning on the blind spot.

**What the family is.** Family #120 `idiom-traits` (category `idiom-refactor`, core, clippy-dominant) on two lints
`clippy --fix` leaves alone (measured): `inherent_to_string` (an inherent `to_string` that should be `Display`) and
`non_canonical_partial_ord_impl` (a custom `Ord::cmp` whose `partial_cmp` does not forward to it). The Ord defect is
a latent bug as well as a lint: the given `partial_cmp` compares `major` only, so `a < b` disagrees with `a.cmp(&b)`.
The prompt states that `cmp` is the truth, and the hidden tests check `<`, `>`, `<=`, `partial_cmp`, `max`, and
`sort` against `sort_by(partial_cmp)`. In the same scratch run `from_over_into` *was* auto-fixed (so it is not used)
and `too_many_arguments`, `large_enum_variant`, `result_unit_err` survive but change the API in ways a prompt cannot
pin, so they are left for a later family.

**Surface.** (`to_string` only) 3 formats + (`Ord` only) 4 orderings + (both) 12 = **19 distinct skills**. Orderings:
lexicographic, major-descending, minor-first, by sum. `allow` is a forbidden path.

**Measured end to end** (mock endpoint, seed 0 = `deg` format + `major_desc` ordering, both defects):

| answer | score | notes |
|---|---|---|
| reference | 1.000 | |
| `Display` added, inherent `to_string` kept | 0.667 | before the oracle fix: 1.000 |
| `Display` fixed, `partial_cmp` left comparing `major` only | 0.413 | builds; differential fails; constraint 0.5 |
| `unchanged` / `#![allow(..)]` | 0.333 / 0.333 | |

**Gates.** `validate-family --cover` (45 seeds; run 60, all 19 skills): all OK, `reference=1.000`,
`baselines_caught=true` (`unchanged`, `allow-attrs`), `clippy_fix_safe=true` ×60. The canonical pairs are
unit-tested to expose the major-only `partial_cmp` under every ordering. 7 module tests.

---

## 2026-10-05 · `idiom-ptr` — a fifth `idiom-refactor` family: `&Vec` / `&String` / `&PathBuf` parameters

**What.** Family #119 `idiom-ptr` (category `idiom-refactor`, core, clippy-dominant 0.30 / 0.60 / 0.10) on
**`clippy::ptr_arg`**: working functions whose parameters are owned containers behind a reference (`&Vec<i64>`,
`&String`, `&PathBuf`, `&mut Vec<i64>`) must take the borrowed forms (`&[i64]`, `&str`, `&Path`, `&mut [i64]`),
behaviour unchanged. Loops (`idiom-loop`, `-counter`, `-copy`) and an API (`idiom-api`) were covered; this is
signatures.

**Q14, measured.** Same scratch-crate method: `cargo clippy --fix` left **all four** `ptr_arg` forms unchanged, and
did not flag a `&mut Vec<i64>` whose body calls `push`, which became the family's decoy.

**Three closed doors.**
- The hidden tests (behaviour **and** differential) call the functions with array references, sub-slices
  (`&v[1..]`), `&str` literals and `Path::new(..)`: none coerce to `&Vec` / `&String` / `&PathBuf`, so a signature
  left alone does not build.
- `#[allow(clippy::ptr_arg)]` is a forbidden path (the AST check sees attribute paths).
- `grow(&mut Vec<i64>)` *needs* the `Vec` (it pushes); "fixing" it to `&mut [i64]` fails to compile.

**A near-miss caught by grading the unchanged code.** My first differential passed `&a` (a `&Vec`) to the functions,
which compiles against the *un*changed signatures, so the unchanged baseline got partial behaviour credit
(`skeleton=0.467`, `behavior 0.400`). The differential now passes `&a[..]`, `s.as_str()`, `&mut x[..]`: the skeleton
scores 0.333 with behaviour 0.000. The full 69-seed gate was re-run after the change.

**Surface.** C(6,3) = **20 distinct skills** (which three of: `&Vec` read, `&String` read, `&mut Vec` in place,
`&String` returning `&str`, `&PathBuf`, two `&Vec`s). Each function also has a seeded variant (`sum_all` /
`max_or_zero`, `first_word` / `last_word`, `has_ext` / `stem_of`, ...) and `add_to_all` a shift constant: these change
the examples and function names only and are excluded from `spec_signature` (Q31).

**Measured end to end** (mock endpoint, seed 0 = `max_or_zero` + `add_to_all` + `matches` + the decoy):

| answer | score | notes |
|---|---|---|
| reference | 1.000 | |
| decoy "fixed" to `&mut [i64]` | 0.000 | does not compile (`failure=Trait`) |
| one signature left as `&Vec` | 0.333 | tests do not build; constraint 0.5 |
| `unchanged` / `#![allow(clippy::ptr_arg)]` | 0.333 / 0.333 | `allow` is a measured violation |

**Gates.** `validate-family --cover`: all **69 seeds (all 20 skills)** OK, `reference=1.000`,
`baselines_caught=true` (`unchanged`, `allow-attrs`), `clippy_fix_safe=true` on all 69. 7 module tests.

---

## 2026-10-06 · scheduling controls: `--max-duration`, `--until`, `--max-units`, `--pause-on-battery`

**What.** Four of docs/09's scheduling controls (`bench-cli/src/schedule.rs`, flattened into `RunSuite` as
one `ScheduleArgs`). Each is **polled at a unit boundary** by the run loop, after the signal check, through
the same clean-stop path as a first `SIGINT`: the unit in flight always finishes and is journalled, the
segment closes (`stopped: <reason> after N unit(s) this session; segment S closed cleanly`), the lock is
released, exit 0. A limit can overshoot by one unit; nothing here interrupts anything, so none can leave a
torn line or a lock. `--idle-only` was **not** built (Q34 #7: no definition of idle, and wait-vs-end is
contradicted inside docs/09); `--pause-on-thermal` has no probe; `--resume-daily` is v2.

**Deterministic tests, no real waiting.** The decision logic takes an `Env` (elapsed, wall clock, local time
of day, power source), tested with a fake (10 unit tests: duration/`HH:MM` parsing incl. rejects,
`secs_until` edge cases, deadline fixed at start, follows the wall clock and not elapsed time, unreadable
clock is an error, unknown battery never stops, deterministic reason when several apply). The real binary
is driven end to end through `RUSTBENCH_SCHEDULE_FAKE=<json file>`, re-read at every poll, which a test
rewrites mid-run (`elapsed_s`, `now_unix`, `local_hms`, `battery`); absent fields use the real probes. It is
a test hook in the production binary, inert unless that variable is set.

**Proved end to end** (7 new `resume.rs` tests, real binary + mock endpoint; all red first with
`error: unexpected argument '--max-units' found`, and the slow one timing out):
- `--max-units 4`: exactly 4 units, then 4 *more* next session (8), no repair reported, finishing without
  the flag completes the plan exactly once with no duplicate; `--max-units 0` stops before the first unit;
- `--max-duration` crossed **while a ~2 s unit is in flight**: that unit finishes and is journalled (exactly
  2 units, exit took > 0.9 s after the flip), no third starts, journal clean, no lock;
- `--until`: deadline fixed from a fake `23:59:50` clock, still running 3+ units before it, stops at the next
  boundary after the wall clock passes it; `07:30:00` with `--until 07:30` does **not** stop at once; an
  unreadable local time refuses before the journal or lock exist;
- `--pause-on-battery`: AC lost mid-run checkpoints cleanly; the next session on battery runs zero units;
  ignored without the flag; an unknown power state never stops a run;
- bad values (`soon`, `25:00`, `-3`) are refused before anything is touched; `--dry-run` ignores the schedule;
- a signal during a scheduled run still uses the same path (`stopped by SIGINT`, exit 0, no lock).

**Not verified:** the real `pmset` battery probe was not exercised against a real battery transition (the
tests use the hook); `date` as the local-time source on non-macOS; `--until` across a real DST change or a
real sleep/wake. `exit_reason` for `max_units` is not in docs/09's enum (Q34 #8).

---

## 2026-10-06 · merge of A's tip, the writers' open question (Q34), two-stage SIGINT/SIGTERM, directory fsync

**Merge** (`6c82a3b`, A's `05e9655`). Conflicts only in `bench-cli/src/main.rs` and BUILD-LOG. Both sides'
`RunSuite` flags kept (`--ignore-gates`, `--require-ac`, `--min-free-disk-gib` and `--force-heterogeneous`).
Order in the arm: **A's environment gates first** (cheap, read-only; a refused run takes no lock and
touches no journal), **then the journal side** (lock, repair, resume identity gate, taint). A new test
runs the two together: an impossible disk gate refuses before the lock (a pre-existing stale lock is
untouched); `--ignore-gates --require-ac` reaches the journal side, which takes over the stale lock,
reports it, and refuses a changed model name, releasing the lock; adding `--force-heterogeneous` succeeds,
taints and loses no unit; `--dry-run` is never blocked and never disturbs the lock. Full workspace after
the merge: 1663 passed, 0 failed.

**Q34 — the plan/state/meta writers were not built, and why.** docs/09 and docs/12 show example JSON, but
the formats are not pinned in the sense an implementation needs: `plan.json` carries `epoch_seed`, which
R5-S2 says must not be on the submitter's disk (and the harness has none: seeds derive from a public
label); probe slots need the blocked batch/nonce protocol; `suite_hash` and `generator_commit` have no
definition or producer; most `state.json.identity` fields (quant, backend, ctx, ngl, exec_class, profile
and template hashes) have no source in `run-suite`; docs/09's on-disk root and the code's `--out` journal
disagree and there is no `run_id`. Recorded as **Q34** with each item; nothing invented.

**Built instead (docs/09 "Interruption handling"), tests red first** (4 of 4 new tests failed before: the
process died on the signal with no exit code, leaving a stale lock):
- first `SIGINT`: finish the unit, write its line, close the segment, **exit 0**, lock released (a clean
  stop is not a crash: the next resume prints no repair);
- second `SIGINT`: **exit 130 within 1.5 s** even mid-unit; the unit in flight is discarded and re-runs;
  the journal has no torn line (an abort lands between journal writes), the stale lock is reported next run;
- `SIGTERM`: as the first `SIGINT` if the unit ends inside the grace window (`RUSTBENCH_TERM_GRACE_SECS`,
  default 10), otherwise **exit 143** at the deadline.
`bench_sandbox::signals`: the handler only bumps an atomic; a watchdog thread (safe Rust) turns counts into
an abort; the run loop polls `requested()` at each unit boundary, the only place a stop loses nothing.
Children already lead their own process group, so a terminal Ctrl-C does not kill an in-flight `cargo`
grade and get it recorded as a model failure.
**This adds one `unsafe` call** (the `signal(2)` registration, with a SAFETY comment, `#[allow(unsafe_code)]`
scoped to it), the same kind of exception `bench-sandbox` already makes for `setrlimit` and `kill`;
no new dependency (libc was already there). Flagged for a decision below the line, not slipped in.

**Directory `fsync`** after creating the journal or lock file and after the atomic rename in
`repair_in_place` (`journal::sync_dir`). What is verified: it runs, errors on a missing directory, and the
suite still passes. What is **not**: that it changes what survives a power cut, which needs a crash
injector or a real power loss; that claim rests on POSIX semantics, not on a test.

**Still open from docs/09:** `--max-duration` / `--until` / `--max-units` / `--pause-on-battery` /
`--idle-only`, segment `meta.json` and per-segment calibration files (Q34 #6), orphan-artifact cleanup
(no artifacts directory exists), and every gate that needs the state/plan files.

---

## 2026-10-06 · `grade()` no longer inherits `CARGO_TARGET_DIR` (Q33 #6 closed)

**The bug** (found while testing the mutation runner, reproduced first): `bench_oracle::grade` ran every
cargo command with the harness's own environment, so a global `CARGO_TARGET_DIR` (very common) made
graded workspaces build into one shared directory: unrelated units share artifacts, and the build lands
outside the only directory the sandbox lets a build write to (it only worked because the temp dir is
also allowed). `tests/target_dir.rs` sets the variable and grades a tiny crate: before the fix it failed
("the build must land in the grading workspace"); now `<workspace>/target/debug` exists and the foreign
directory is never created.

**The change** is one line in `run_cargo`, the oracle's single cargo seam (compile, test, clippy, miri all
go through it): pass `CARGO_TARGET_DIR=<policy.workspace>/target`. With the variable unset this is
cargo's own default, so an ordinary environment is unchanged.

**Does anything rely on a shared target? No, shown rather than assumed.** Nothing in the repository sets
or reads `CARGO_TARGET_DIR` (`grep` over `bench-oracle`, `bench-sandbox`, `bench-cli`), and the whole
workspace test suite was run *with* a shared `CARGO_TARGET_DIR` set in the environment (the shared-Mac
wrapper sets one) and passes with the pin in place: every `grade()` caller (`run`, `run-suite`,
`validate-family`, the oracle's own tests) builds per workspace. The `bench-stats` comment about a "shared
`target/`" and cold-cache lead units describes cargo's per-workspace cache across units of one run, which
is untouched. Cost: none for an ordinary environment; a user who set the variable for speed now pays the
per-unit compile that everyone else already pays (and gets correct, isolated builds).

---

## 2026-10-06 · docs/09 crash safety for real: torn lines, glued units, duplicates, a run lock, resume gates

**What.** `run-suite` was checked against docs/09 by running the real binary under a real `SIGKILL`
(mock endpoint, no model). It did **not** meet it. Six of nine crash-safety tests written first failed on
the pre-fix tree (same test file, run against commit `9eaf4a5`); all nine, plus a tenth for the new
`journal` command, pass now.

**Bugs found, each reproduced before it was fixed:**
1. **A torn final line made resume impossible.** `read_done_keys` and `next_segment` parsed every journal
   line with `?`, so one half-written line (what a kill mid-append leaves) turned every later
   `run-suite`, and `status`, into `error: EOF while parsing a value at line 1 column 439`. docs/09
   promises the torn line is discarded and that unit re-runs. Pre-fix output captured verbatim.
2. **The next append fused with the fragment and lost a *completed* unit.** `writeln!` onto a file that
   does not end in a newline glues the new unit to the fragment; `JSON` parse then fails for both. A
   unit the harness had finished and moved past was unrecoverable. Reproduced (`append_after_a_kill…`
   fails pre-fix: "unit recovered from behind a torn fragment" is exactly the salvage that is now needed
   only for journals written by the old binary).
3. **No `fsync`, and the line was written in two `write` calls.** A journal line the harness had "moved
   past" was not necessarily on disk. Now one `write_all` of `line + "\n"` then `sync_data`.
4. **No lock at all.** Two `run-suite` processes interleave into one journal and run each unit twice.
   Pre-fix: the second run happily proceeded (`a_live_lock…` fails).
5. **Duplicated lines were counted twice** by `stats`, `report`, `compare`, `detect` and `status`
   (pre-fix, 12 duplicated lines made `stats` print "over 128 units" and "127 executed units" for a 116-unit epoch).
6. **No resume validity gate.** docs/09 requires `model_name`, hardware class and `harness_version` to
   match or the run is refused (`--force-heterogeneous` taints it permanently). None existed: continuing an
   epoch on another machine or under another model name silently mixed two experiments.

**Fixes, in two layers.** `bench_core::journal::scan` (pure, 13 tests) decides which lines are units:
every parseable unit is kept in file order; a torn final line is discarded; a unit glued behind a fragment
is **salvaged**; corrupt lines are quarantined; a repeated `unit_id` keeps the **first** copy and reports
whether the copies differed; ordering and timestamps are never consulted. `bench-cli/src/journal.rs` does
the I/O: crash-safe `append_line` (fresh line if a fragment is present, one write, `fsync`),
`repair_in_place` (appends every removed line **verbatim** to `<journal>.quarantine` first, then replaces
the journal atomically: temp file, fsync, rename; a clean journal is not touched, mtime included),
read-only tolerant loading for the read-side commands (they never modify a file another process may be
appending to), and `Lock`. The lock is `<journal>.lock` holding a pid, `create_new`; a dead holder
(`kill -0`) is a **stale lock, taken over and reported**; a live one refuses (a lock with unreadable
contents is held while under 10 s old, stale after); `Drop` removes it only if it is still ours; a refusal
touches nothing. The gates compare model name, hardware class and harness version against what the
journal already recorded **for that epoch** (a new epoch starts clean; a field older lines never recorded
cannot mismatch); `--force-heterogeneous` proceeds and appends the reasons to `<journal>.tainted`, which
`status`, `stats` and `report` then print forever (docs/09: "no way to un-taint"). `JournalLine` gains a
`harness` field. `rustybench journal [--repair]` reports what recovery would do and does it on request.
Everything repaired is printed by `run-suite` (`repaired: ...`), without echoing line contents.

**Proved end to end** (`crates/bench-cli/tests/resume.rs`, real binary, SIGKILL, mock endpoint):
- kill at >= 5 units, lock left behind, resume: `repaired: removed stale lock left by pid <child>`, the whole
  plan completes **exactly once**, every pre-kill unit still present, journal clean, new segment is 1;
- torn tail discarded and reported, its bytes kept in `.quarantine`, only that unit re-runs;
- unit glued behind a fragment (the pre-fix on-disk shape) salvaged, the genuinely lost one re-runs;
- 12 duplicated + reordered lines: `stats` output byte-identical to the clean journal's, file untouched by
  the read, resume reports 12 identical-duplicate repairs and `0 to run`;
- every line stamped with a `completed_at` that runs *backwards* and ends before 1970: no repairs, same
  statistics (nothing consults a clock);
- a live lock refuses, changes nothing and does not steal the lock; `--dry-run` ignores it;
- model name, hardware class and harness version each refused, then forced and tainted, taint visible in
  `status` and `stats`, no unit dropped or duplicated.
Plus bench-submit: export tolerates a torn tail and identical duplicates (with a note) and **refuses**
anything that could hide a missing or ambiguous unit (mid-file corruption, differing duplicates).

**Not done, and the clock.** "Clock jumping backwards" is covered by construction and by the test above:
the harness uses `Instant` for timings and has no wall-clock decision to jump. There is still no
`plan.json`/`state.json`/segment `meta.json`, no `SIGINT` two-stage handling, no `--max-duration`, no
orphan-artifact cleanup, and `fsync` of the *directory* after the atomic rename is not done (the journal
file itself is fsynced). A stale lock whose pid was reused by an unrelated live process is reported as held
(the message says to delete it). The gates see `harness` as the crate version: a rebuild at the same
version is invisible. Windows has no `kill -0` and treats every lock as held.

---

## 2026-10-06 · L4 quality, the part that survives the reviews: a deterministic mutator and `size_ratio`

**Read first.** docs/03 §L4 lists mutation (cargo-mutants), perf (criterion) and size. What the reviews
leave standing: REVIEW.md S11 / docs/03 — L4 is not replay-verifiable, T0 confidence only; Q28 — quality
is **not** part of the pass predicate; REVIEW-6 R6-S5 — the `GpuFull` gate on perf rests on a free-text,
submitter-chosen `exec_class`; docs/04 — only `test-authoring` (and `perf-optimization`) have L4 as their
primary oracle, and no `test-authoring` family exists in the repo. **Judgement:** L4 is not blocked
outright, but only one part is both well defined and buildable offline: mutation read as *"did the
model's tests kill the reference's mutants?"*, plus the exact `size_ratio` measurement. Perf, the other
mutation reading, and every ratio-to-score formula are recorded as open in **Q33**, not built.
`cargo-mutants` is not installed, so the mutator is in-repo.

**Built** (`crates/bench-oracle/src/mutation.rs`, `quality.rs`; no `bench-core` change; one new direct
dependency edge, `proc-macro2` with `span-locations`, already in the graph via `syn`):
- `mutation::enumerate(source)`: syn-based, deterministic, source-ordered, stable ids. Operators: `+ - * /`,
  `< <= > >= == !=`, `&& ||`, `+= -= *=`, `!` removal, bool literals, and whole-body replacement for
  unit / `bool` / integer functions. Skips `#[test]`, `#[cfg(test)]`, `main`, `const fn`, trivial
  bodies. `apply` splices by byte range (multi-byte source tested), `select` is a deterministic even
  spread, never random. `Mutant::describe` names the operator and function, not source text.
- `mutation::run_mutants` / `mutation_score`: for each mutant, compile the test target (`cargo test
  --no-run`, wall limit) then **run the built test binary directly** under the run wall-clock, so the
  limit measures the tests, not cargo start-up. Verdicts: `Killed`, `Timeout` (counted as killed, the
  cargo-mutants rule), `Survived`, `Unviable` (does not compile; excluded). The original is restored on
  every exit (drop guard).
- **Equivalent mutants are not mis-scored.** `mutation_score(reference_target, model_target)` takes the
  mutants the *hidden reference tests* kill as the denominator and counts how many the model's tests also
  kill; mutants the reference cannot kill are reported as `unkillable_by_reference`, not held against
  the model. Tests that fail on the unmutated reference are rejected (`BaselineFails`), since they would
  "kill" everything. `score` is `None` when nothing is killable.
- `quality::size_ratio`: token count of the solution over the reference (comments and whitespace are not
  tokens; delimiters count). Measurement only; docs/03 gives no ratio-to-score formula.

**Proved against real `cargo` under `bench-sandbox` (not a mock):**
- one mutant of each kind, run through the reference tests: `add: + -> -` Killed; `min2: < -> <=`
  (equivalent) **Survived**; `min2: < -> >` Killed; `count_to: += -> -=` (infinite loop) **Timeout** by the
  wall clock; `String + &str` mutated to `-` **Unviable**; original restored.
- a thorough model suite scores **1.0** with the equivalent mutant excluded (12 of 12 killable, 1 equivalent excluded; it would score 0.92 (12 of 13) if the
  equivalent mutant were in the denominator); a weak suite (asserts only zeros) scores **0.42** (5 of 12 killable mutants) and its
  survivor list names `add: + -> -`, `add: + -> *`, `add` body -> 0, `min2: < -> >`, `count_to: < -> >`,
  `count_to: += -> -=`, `count_to` body -> 0; both suites
  see the same killable set (the denominator depends on the reference, not the model); failing model tests
  are rejected; an unparseable reference is refused.
- **containment held through the runner:** a test binary run by the mutation runner that tries a local
  TCP connect and a write outside the workspace recorded `net=false fs=false`, and the escape file does
  not exist (macOS seatbelt).
- 3 consecutive runs of the five scoring/verdict tests: 5/5 each (38-51 s on a busy machine), then the
  containment test and a final full run: 6/6 (56 s); 7 mutator unit tests and 3 `size_ratio` tests pass;
  the 38 pre-existing `bench-oracle` unit tests are unaffected.

**Found by running it:** the first scoring runs gave survivors that should have been killed, differing
between runs. Cause: the harness's inherited `CARGO_TARGET_DIR` made two workspaces with the same package
name share artifacts. The runner now pins the target dir inside the workspace (also the only place the
sandbox lets a build write) and builds non-incrementally. The same inheritance exists in
`bench_oracle::grade`, which this change deliberately does not touch (Q33 #6).

**Not verified:** Linux or any platform without seatbelt (`bench-sandbox` runs unconfined there and says
so); behaviour on large reference crates (cost is a compile per mutant per target; `max_mutants = 40`
by default is a guess, not a measured budget); that docs/03's "~40 s per instance" holds for this runner;
any real model-authored test suite (none exists to try). Nothing here changes any score.

---

## 2026-10-06 · `bench-hw` Phase B — `calibrate` (pp / tg / sustained) through `bench-model`

**What.** `crates/bench-hw/src/calibrate.rs` (new file; `lib.rs` gains one `pub mod` line and a doc line;
`bench-hw` now depends on `bench-model`, which does not depend on `bench-hw`, so no cycle) and
`rustybench calibrate --model URL [--tier full|abbreviated] [--warmup-secs N] [--reps N]
[--sustained-secs N] [--out calib.json]` (`crates/bench-cli/src/calibrate_cmd.rs`; `main.rs` gets one
`mod`, one enum variant, one match arm). Tiers follow docs/05: **full** = 60 s warm-up + 10 reps +
sustained phase; **abbreviated** = warm-up + 5 reps, no sustained phase. Output is docs/12's
`calib.json` shape plus provenance.

**Deviations the OpenAI surface forces, each recorded in the output rather than hidden:**
- *No tokenizer.* A 512-token prompt cannot be built blind, so a probe is sent, the server's own
  `usage.prompt_tokens` is read and the word count rescaled until the *reported* size is within 3% of the
  target (up to 4 probes). The size actually measured is `pp_tokens_actual` (it includes the chat
  template). An endpoint that reports no prompt size cannot be sized: `pp` is then null with a warning,
  not a guess; `tg` still works from arrival gaps.
- *`pp` = evaluated prompt tokens / prefill seconds*, from the server `timings` when sent, else client
  time-to-first-token at `max_tokens = 1` (includes network and one decode step, so it can only
  under-read; stated in a warning when it is the source). Each request has a unique prompt prefix, and a
  rep that reports cached tokens is discarded, so a prefix cache cannot fake prefill.
- *`tg` = decode rate excluding prefill*, `ignore_eos` requested; the achieved length is recorded
  (`tg_tokens_actual`) and a server that stops early or ignores `ignore_eos` raises a warning. A
  non-streaming client is refused (`NotStreaming`): wall time includes prefill and is not a decode rate.
- *Not measured, null with the reason:* peak accelerator memory, peak host RSS, clocks, thermal events.
- *Sustained:* early window vs late window decode rate (window = phase/4, at most 60 s; if a window
  caught no request the first/last request stands in), `delta_pct`; a delta beyond 15% marks throughput
  unstable (docs/05 gate). A context too small for the 2k+1k sustained shape skips that phase with a
  warning instead of failing the calibration.
- *Tier logic as pure functions:* `needs_escalation` (abbreviated vs segment 0, >10% on tg or pp, or a
  figure that vanished) and `tg_unstable_across_segments` (>10% about the mean of medians).

**Tests.** 9 pure-statistics unit tests (percentiles, drift, windows, escalation boundary at exactly
10%, serialisation with nulls) and 16 integration tests against the mock endpoint: rates recovered from
server timings; prompt resized under a 150-token template; distinct prefixes and pinned request shape;
stream fallback; no-usage endpoint; `ignore_eos` ignored; prefix-cache hits discarded; warm-up sent and
discarded; steady sustained phase (delta 0); **throttling mock detected** (delta in -60..-35%, throughput
flagged unstable); small context; refusal of a non-streaming client; failing endpoint; escalation from real
runs; progress lines. 20 consecutive runs, and 24 runs of calibration plus the `bench-model` module under
6-way CPU contention: 0 failures.

**Real binary against the mock** (`cargo run -p bench-model --features mock --example mock_server`, then
`rustybench calibrate`): `pp 50000.0`, `tg 2000.0` tok/s (the mock's configured rates, via its
`timings`), prompt reported as 511 tokens for a target of 512, 8 sustained requests, delta +0.0%,
`calib.json` written; against a dead port: `gave up after 4 attempt(s)`, exit 1.

**Verified against the mock only.** All of it. In particular *not* verified on a real endpoint: that
llama.cpp's `timings` agree with client arrival times; that `ignore_eos` is honoured through
`/v1/chat/completions` on each backend (and that vLLM/Ollama/LM Studio accept it); that a prefix cache is
really defeated by a changed prefix on each backend; that the first byte of a streamed reply really
arrives after prefill (if a backend sends headers early, client time-to-first-token is still measured at
the first *content* delta, which is correct, but a stall timeout would count prefill); how a real machine
behaves for the 10-minute sustained phase. No real model was loaded for any of this (shared Mac). The
first real run is the experiment that turns "protocol and estimators work" into "numbers are right".

---

## 2026-10-06 · `bench-model` hardening — realistic endpoint behaviour, an in-repo mock server, honest timing

**What.** `bench-model` now handles the failure modes docs/15 §2 and §10 measured on real backends, and
says what each timing number *is*. New: `wire.rs` (tolerant parsing, pure), `mock.rs` (a std-only HTTP
server, `feature = "mock"` for other crates), `mock_tests.rs` (28 client tests). `complete()` keeps its
signature and default behaviour (non-streaming, same journal `gen_ms`); everything new is opt-in via
`ClientConfig` / `ModelClient::chat(ChatSpec)`. No new dependencies (the mock is `std::net`).

**Parsing.** `content: null` (tool-call / reasoning-only replies), `usage` absent, `{}` or `null` (reported
as `usage_reported = false`, never as a zero measurement), `reasoning_content` *or* `reasoning`, content as
an array of text parts, `prompt_tokens_details.cached_tokens`, llama.cpp's `timings` block (garbage
rejected), an empty `choices` on a trailing usage chunk (normal) versus in a non-stream reply (`NoChoices`),
`{"error": ...}` with a 200 or mid-stream (`Api`), llama.cpp's loud `exceed_context_size_error`
(`ContextExceeded{n_prompt_tokens, n_ctx}`, never retried), a server that ignores `stream: true`, and
`<think>` inside `content` (flagged `reasoning_inline`; the apply layer still has to strip it).
`finish_reason = "length"` is surfaced as `Completion::truncated()`; with a reasoning model the visible
text is then often empty and is reported as such, not as an error.

**Retries** (`RetryPolicy`: 4 attempts, 500 ms base doubling to a 30 s cap, `Retry-After` honoured and
capped at 60 s; no jitter, one client talks to one local server). Retried: 408/429/500/502/503/504,
refused or reset connections, truncated bodies, interrupted streams. **Not** retried: other 4xx, a context
overflow, a malformed or error-object body, empty choices, and a *request-deadline timeout* (a re-send waits
the same deadline again; this one was wrong on the first run — see below). Attempts and total wait are on
the `Completion` (`attempts`, `retry_wait_ms`); exhaustion is `GaveUp{attempts, last}`; a stream that dies
carries its partial text in `StreamInterrupted`. A stream that ends cleanly with neither `finish_reason`
nor `[DONE]` is truncation, not success; a `finish_reason` without `[DONE]` is accepted.

**Timing, explicit about its source** (`Timing.source`):

| source | when | prefill | decode rate | token count |
|---|---|---|---|---|
| `server_timings` | endpoint sent `timings` (llama.cpp) | server `prompt_ms`, rate over *evaluated* tokens | `predicted_n / predicted_ms` | server |
| `client_stream` | streamed, no `timings` | client time-to-first-token (includes network, queueing and one decode step) | `(n-1)` arrivals over first-to-last gap | `usage` if sent, else delta count, labelled `stream_chunks` |
| `client_wall` | not streamed, no `timings` | none | **none** — a rate that includes prefill is not a decode rate | `usage` |

`end_to_end_tok_per_s` (tokens over total wall time) is always reported separately and is not decode speed.
`cached_tokens` (usage or `cache_n`) is recorded because a non-zero value invalidates a unit's *timing*,
never its verdict. `cache_prompt: false` is now sent (docs/15 PIN; unknown fields are ignored by the
targeted servers); `stream_options.include_usage` is sent when streaming; `ignore_eos` only when a caller
asks (calibration).

**Found by running it, not by reading:** (1) a truncated JSON body surfaces in reqwest as a *decode*
error, not a body error, so it was not retried; (2) a deadline timeout during `send()` is classified as a
*request* error, so the first retry predicate retried it up to the cap (four full deadlines); (3) the blocking
reqwest client has **no per-read timeout**, so `stall_timeout` is implemented with a reader thread and a
per-line `recv_timeout`, and a thread blocked in `read` is abandoned (not interrupted) when it fires.
`stall_timeout` defaults to `None` for the reason in the doc comment: a 50k-token prefill at 200 tok/s is
over four minutes before the first byte.

**Verified against the mock only** (`mock.rs`, written from docs/15's account of the backends): every row
above. 30 consecutive runs of the whole module on a busy shared Mac: 0 failures. **Not verified against a
real llama.cpp / vLLM / Ollama / LM Studio**: that their wire shapes match the mock's (the mock embodies
this author's reading of docs/15), that real `timings` and `usage` agree with client-observed arrival,
that `ignore_eos` and `cache_prompt` are honoured, how each behaves on a reset, and the 429/`Retry-After`
behaviour of any of them. The timing-estimator assertions use wide tolerances (500-1600 tok/s around a true
1000) because sleeps on this machine are coarse; exact assertions are only made where the mock *reports*
the number (server timings).

---

## 2026-10-05 · `bench-submit` (3/3) — `rustybench export` / `consent`: the consent gate and `--dry-run`

**What.** Three subcommands wired into `bench-cli` with a deliberately small `main.rs` change (three enum
variants, three match arms; the argument structs live in `bench_submit::cli`, so a merge touches almost
nothing):

```
rustybench export --journal J --hw H [--identity I] [--run-id ID] --out FILE
                  [--consent public-scores [--remember-consent]] [--consent-file F] [--no-submit] [--force]
rustybench export ... --dry-run          # stdout = the exact bytes; stderr = size, hash, redaction counts
rustybench verify-bundle FILE [--no-rederive]
rustybench consent show | grant [--yes] | revoke [--file F]
```

**The gate (docs/11), as built.** A real export is refused unless consent comes from the current
invocation (`--consent public-scores`) or a stored record **for the current terms** (the record carries
`terms_version` and `terms_hash`; changing the text voids every stored consent). `--no-submit` and
`RUSTBENCH_SUBMIT=0` beat any consent. A refusal happens *before* the inputs are read and records
nothing; `--remember-consent` writes the record only after the bundle file exists. `replay-artifacts` and
`audit-contact` are refused with the reason, not silently ignored. `--dry-run` needs no consent (that is
how a user decides), writes **no file at all** (tested: directory listing identical before and after, even
with `--out`, `--consent` and `--remember-consent` given), and prints to stdout the same bytes a real
export writes — checked by comparing the dry-run output with the written file, and by running the real
binary three times in separate processes (identical SHA each time). `export` never overwrites without
`--force`. Nothing is ever sent; there is no network path in the crate.

**End to end with the real binary** (journal with a home path, an IP and the machine's real hostname in
`base_url`/violations/model path; real `rustybench hw --json`): no consent -> rc 1; `RUSTBENCH_SUBMIT=0`
-> rc 1; with consent -> a 5.8 KiB bundle, 0 occurrences of the login name, the hostname or the IP,
`model.name` reduced from `/Users/<me>/models/qwen.gguf` to `qwen.gguf`, `verify-bundle` 11/11 ok. Editing
one `gen_ms` by `sed` -> `content-hash`, `rederived-stats` and `run-id` all FAIL.

**Found while running it for real:** a home-path prefix replaced by the literal pass left the token
`<path>/x/lib.rs:3:1`, which the token pass then wrapped as `<<path>`. Safe but ugly; fixed (a token
beginning with a placeholder keeps its `<`) and pinned by a test.

**Consent text is draft wording** (`TERMS_VERSION = 2026-10-05-draft`). It names "Creative Commons
Attribution 4.0 International (CC BY 4.0)" in full on its own line, not as a link, and a test asserts it
(docs/11). Whether it is legally sufficient is the owner's decision (OPEN-QUESTIONS Q32 #2).

---

## 2026-10-05 · `bench-submit` (2/3) — `verify-bundle`: what can be re-checked with no server

**What.** `bench_submit::verify::verify_bytes` (CLI: `rustybench verify-bundle FILE [--no-rederive]`, exits
non-zero on any failed check). The offline slice of the docs/10 "server re-derives" column — and
explicitly **not T1**: it assigns no trust tier and cannot say a score is *true*.

**Eleven checks, each reported by name:** `parse` (typed, `deny_unknown_fields`) · `schema` (unknown majors
rejected) · `canonical-form` (re-serialising the parsed bundle must reproduce the file byte for byte, which
is what stops a field outside the schema riding along) · `content-hash` · `grammar` (every identifier-shaped
field re-validated) · `leak-scan` (the exporter's scan again, plus *this* verifier's login/home/hostname) ·
`consent` (granted, the unavailable consents false, `terms_hash` matches the terms version) · `structure`
(unique ids, canonical order, counts, `categories_scored`, one hardware class, `withheld` / `unrecorded`
lists agree) · `oracle-consistency` · `rederived-stats` · `run-id`.

**`oracle-consistency` uses only `bench-core`'s own rules**, so there is nothing new to keep in sync: score
gating (no compile => score 0 and no behaviour/constraint scores), `behavior.score` and `constraint.score`
recomputed with `BehaviorScore::recompute` / `ConstraintScore::recompute`, `diagnostic_completeness`
against `bench_core::diagnostic_completeness(codes)`, and `failure_class` against `classify_error_codes`
(compile failure; a codeless `async-send` is allowed, it is classified from the message) or
`classify_graded` (compiled). **`rederived-stats`** rebuilds `bench-stats` records from the units and
compares *every* number in `report` (tolerance 1e-9 relative, so a verifier on another libm does not
false-alarm on a bootstrap quantile); the resample count is read from the bundle but capped at 100,000 so a
hostile file cannot buy CPU. A derived `rb-...` run id is also recomputed from the units, so it binds them.

**Measured against forgery** (`tests/verify.rs`, a file-only attacker who also recomputes `content_hash`):

| edit | caught by |
|---|---|
| flip any byte of the body | `content-hash` |
| raise one unit's score, hash fixed | `oracle-consistency` + `rederived-stats` |
| make a failed unit a *coherent* pass, hash fixed | `rederived-stats` + `run-id` (aggregates and derived id no longer follow) |
| edit the headline `capability_score`, hash fixed | `rederived-stats` |
| extra field / pretty-printed / reordered units / duplicate id / mixed hardware / false `unrecorded` | `parse` / `canonical-form` / `structure` |
| plant a path, IP, MAC or the verifier's username, hash fixed | `leak-scan` |
| truncation at 6 offsets, junk bytes, `bootstrap_iters = u64::MAX` | clean failure, no panic |

**The honest limit.** An attacker who edits the *journal* and runs the builder produces a bundle that
passes every check — the pipeline is self-consistent by construction. Only replay (re-running the oracle on
the model output, server side) can tell that apart, which is exactly docs/10's point and why T1 is the
"single highest-leverage control". Said in the command's last line and in docs/10.

---

## 2026-10-05 · `bench-submit` (1/3) — the upload bundle: redaction, canonical form, consent text

**What.** New crate `bench-submit`, the *offline* half of roadmap P6 (docs/11, docs/12): journal +
`hw.json` -> a redacted, schema-validated, canonically serialised, content-hashed **upload bundle**.
No network, no signing, no encryption (see "Not built" below). `rustybench export` / `verify-bundle`
follow in the next two entries; this one is the library.

**Shape.** `{schema, canon, content_hash, body}`. `body` = run id, epoch, `identity` (the docs/15 §10.1
row key as far as recorded, every field present, `null` = not recorded), `model`, `hw_public`, `units`,
`report`, `consents`, `withheld`, `unrecorded`. Serialised as **`rb-canon-json-v1`** (sorted keys, no
whitespace, serde_json numbers) — a stand-in for the canonical CBOR docs/11 names, because no CBOR crate
or signing key exists. `content_hash` = `blake3:` over a domain separator + the canonical bytes of
`body`. No new dependencies (blake3, serde, serde_json, clap already in the graph).

**Four design decisions, each a correction forced by something the docs say or got wrong:**

1. **The seed is in the task id.** Generated ids are `family/{seed:016x}`. docs/11 lists `task_id` as an
   always-uploaded field *and* says seeds are withheld until the epoch closes (R5-S7). Both cannot hold.
   The bundle carries `family` + `index` + `kind` + the opaque `unit_id` (blake3 over task id + seed +
   index) and never the suffix; a test searches the bytes for the seed.
2. **Allow-list, not deny-list** (REVIEW-5 `redaction-is-a-denylist`). A journal line is parsed into a
   struct that names the fields taken; `seed`, `model.base_url`, `canary`, any unknown field are never
   read. Identifier-shaped fields (`family`, `category`, `epoch`, `sandbox`, ...) must match a strict
   token grammar or the export is **refused** (the error names the field and line, never the value).
3. **Only genuinely free text is scrubbed**: constraint `violations`, `flags`, `error_codes` (grammar-
   checked: `E\d{4}` or a lint path, anything else is scrubbed or becomes `unrecognised`) and the
   user-typed model name (a path keeps only its basename). The scrubber recognises paths (unix, drive,
   UNC, `~`, `$VAR`, `%VAR%`), URLs, emails, IPv4/IPv6 (also glued to ports and `:line:col`), MAC,
   UUID, long hex, serials, `NAME=value` env assignments, `user=` / `host:` style keys, hostname
   heuristics, plus this machine's literal username / home / hostname. It over-redacts on purpose.
4. **Fail closed.** After construction the whole body is scanned again (values, and `report` map keys);
   any hit aborts the export, reporting the JSON pointer and the kind only.

**Proof.** `tests/redaction.rs`: 37 adversarial fragments (home paths, `.cargo` registry paths, Windows
and UNC paths, IPv4/IPv6/MAC, MacBook-style hostnames, serials, UUIDs, env assignments, emails, URLs with
credentials, a zero-width-split username, ...) are planted in every nested text field *and* in fields the
allow-list never reads *and* in the raw hardware profile; the bundle must either be refused or contain
none of the independently written needles. A randomised property test (default 5 x 300 journals,
`RB_PROP_SEEDS=N` widens it; 60 x 300 = 18,000 passed) found and closed six scrubber gaps while being
written: error-code/flag grammars that also matched IPs and MACs, IP+port+`:line:col`, glued IPv6, a
`family` of `file:`, env names with a glued prefix, and a panic on a multi-byte char boundary.
`tests/bundle.rs`: schema round-trip (byte-for-byte fixed point), determinism (same bytes across repeats,
shuffled journal lines, reversed key order), hash sensitivity, refusal cases (mixed epochs / models /
hardware, duplicate ids, unknown schema major, non-finite scores), identity-file extraction.

**Known limits (stated, not hidden).** An identifier-shaped field that *looks like* a legitimate token
(`ac02xg0fdh7jyz` as a family) cannot be told from one: those fields come from the harness, not from
user text. A keyword-dependent secret with letters glued onto the keyword (`aserial: Xz`) is not
recognised. Non-ASCII case variants of a username are not folded. A user whose login equals a schema
word (`core`, `unit`) makes the fail-closed scan refuse every export; that is annoying, not unsafe.

**Not built, and why** (all recorded in OPEN-QUESTIONS Q32): ed25519 signing (needs a crate + key
policy; an embedded key is T0-only anyway), encrypted replay artifacts (needs a server key),
challenge/batch nonces and seed secrecy (BLOCKED, R5-S2/Q22/Q23), raw calibration numbers in the bundle
(R5-S6: either a fingerprint or a control, not both), `machine_uuid` and per-unit `completed_at`
(R5-S6: together a linkable activity timeline).

---

## 2026-10-05 · The registry sweep: all 118 families gated at HEAD, one real bug (flaky allocation probes), idiom-copy fully gated

**What ran.** `validate-family --cover` over every registered family, via the recipe in the entry below it,
as a sequence of foreground chunks (`--from`, 4-seed steps under a state file, one cargo job at a time under the
shared lock, `nice -n 10`). 3,543 seeds in total: every one of the 118 families run for as many seeds as it takes to
exercise **every one of its skills**. Pass 1 ran 116 families in ~45 chunks of ~9 minutes. Pass 2 re-ran the
7 families whose allocation probe changed (below) plus `iter-borrow`'s unfinished tail and `unit-generic`.
**Result: 3,543 / 3,543 seeds OK, 118 / 118 families pass, after one fix.** Per-family seeds run (all passed;
the first sweep's 3,321 plus the 222 seeds of the two families it had not reached):

> `window-op` 22; `error-handling` 75; `err-chain` 49; `stack-machine` 136; `expr-tree` 40; 
> `seq-transform` 284; `grid-reduce` 31; `trait-impl` 65; `bit-ops` 99; `bitset` 19; `raw-ptr` 65; 
> `raw-ptr-mut` 58; `rle` 19; `str-transform` 79; `dual-region` 40; `generic-select` 58; 
> `checked-eval` 41; `idiom-loop` 58; `idiom-counter` 41; `interval-map` 19; `matrix` 19; 
> `value-tree` 19; `fsm` 19; `poly` 19; `digits` 19; `parity` 19; `minmax` 19; `sorted` 19; `gcd` 19; 
> `collatz` 19; `primes` 19; `base-convert` 19; `fib` 19; `digitroot` 19; `hamming` 19; `modpow` 19; 
> `luhn` 19; `roman` 19; `vector-geometry` 19; `rational` 19; `datecalc` 19; `text-stats` 19; 
> `bisect` 19; `clock` 19; `coins` 19; `triangle` 19; `complex-plane` 19; `temp-scale` 19; 
> `letter-grade` 19; `duration` 19; `ordinal` 19; `angles` 19; `rectangle` 19; `pitch` 19; `caesar` 
> 19; `hex-color` 19; `brackets` 19; `morse` 19; `perms` 19; `scrabble` 19; `columns` 19; 
> `playing-card` 19; `dice` 19; `text-wrap` 19; `golf` 19; `tennis` 19; `chess` 19; `triangular` 19; 
> `parking` 19; `streaks` 19; `timezone` 19; `borrow-fix` 19; `generic-bounds` 19; `pointer-slice` 
> 19; `poll-future` 19; `perf-refactor` 19; `ref-cell` 19; `iter-machine` 19; `convert-trait` 19; 
> `raii-guard` 19; `deref-wrap` 19; `dyn-shapes` 19; `enum-match` 19; `closure-pipe` 19; `cow-str` 
> 19; `atomics-order` 19; `varint-wire` 19; `ring-buffer` 19; `binary-heap` 19; `bloom-filter` 19; 
> `lru-cache` 19; `trie` 19; `token-bucket` 19; `base64-codec` 19; `moving-average` 19; 
> `histogram-bucket` 19; `gray-code-counter` 19; `union-find` 19; `monotonic-window` 19; 
> `topk-stream` 19; `median-maintenance` 19; `count-min-sketch` 19; `prefix-sum-fenwick` 19; 
> `slot-pool` 19; `skip-list` 19; `rank-select` 19; `two-stack-queue` 19; `segment-tree` 19; 
> `lifetime-split` 58; `ops-overload` 58; `idiom-copy` 95; `error-source` 23; `lifetime-view` 33; 
> `blanket-impl` 34; `result-collect` 23; `idiom-api` 27; 
> `iter-borrow` 182; `unit-generic` 40.

**The one real failure, and its cause.** `iter-borrow` seeds 110 and 122 scored the *reference* **0.796**
(`expected 1.0`) in the sweep, though the same seeds had passed in the earlier 182-seed run. The cause was not the
family but the **allocation probe**, in all seven families that have one. The probe counts allocations around a hot
path with a process-wide `#[global_allocator]` counter, and the libtest main thread allocates while a test body runs;
under load that noise lands inside the measured window. A probe whose limit is exactly what the reference uses (0, or
exactly one `Box` per call, as in `iter-borrow`'s boxed variant: 150 allowed, 150 used) then fails intermittently.
Reproducing it in isolation (200 runs of the reference's alloc test on an idle machine) gave 0 failures, which is why
it needed a busy host to show.

**The fix.** `bench_gen::thread_local_counter` rewrites a probe's source so the counter is per thread (a
const-initialised thread-local `Cell`, no destructor, so reading it inside the allocator cannot recurse), keeping the
`fetch_add` / `load` / `store` surface so no limit and no family logic changed. It is applied at the seven call
sites (`window-op`, `dual-region`, `borrow-fix`, `perf-refactor`, `lifetime-split`, `lifetime-view`,
`iter-borrow`), and a registry test (`every_allocation_probe_counts_per_thread`) fails any future probe that
reintroduces a process-wide `AtomicUsize` counter. All seven were re-gated in full under the new probe: 0 failures.
This matters beyond the sweep: a flaky probe would have wrongly failed a *model's* correct answer on the
allocation constraint, in the constraint-dominant categories where that constraint is most of the score.

**`idiom-copy` finished.** Earlier the gate had covered 23 of 27 skills. The four first reached by seeds 46, 53, 67
and 94 were run through the gate itself (not just the mock endpoint): all `OK`, `reference=1.000`, skeleton 0.333,
`baselines_caught=true`, `clippy_fix_safe=true (1 lint survives --fix)`. All 27 skills are now gated.

**Caveats.** `--cover` exercises every *skill* (distinct structural spec), not every seed or every cosmetic variant;
the gate's anti-twin and capacity diagnostics were not collected across the sweep (they need the full seed range in
one run), only pass/fail per seed. The sweep ran on a Mac shared with other agents, so wall-clock figures
(~7-20 s/seed) are load-dependent. `raw-ptr` and `raw-ptr-mut` (category `unsafe-core`) were gated without miri, which is not installed on this host, so their miri stage was skipped (`miri:unavailable`); that layer remains unexercised here. The Q28 floor question is untouched.

---

## 2026-10-05 · Class-scoped throughput in `stats`/`report`/`status`, and the first pre-run gates

**Class-scoped throughput (follow-up to the `hw_class` journal field).**
`bench_stats::throughput_by_class(records)` folds each hardware class on its own (the key is `hw_class`,
`unrecorded` for old lines), and `StatReport.throughput_by_class` carries the map (also in `report --format
json`). `stats` and `report` print a "throughput by hardware class (comparable within a class only)" block
whenever the journal spans more than one class, beneath the existing mixed-hardware warning; the pooled figure
is kept, now clearly labelled by that warning. `status` paces its ETA from `current_host_records`: the records
sharing the class of the *most recent* journal line, so a journal merged from two machines does not yield a
pace that neither machine has.
- *Why per class and not a filter flag:* nothing about a journal says which machine the reader is; showing
  every class side by side is the honest default.
- *Warm-up exclusion never crosses classes* (tested): class A's cold first unit is dropped, while class B,
  whose only timed unit is a cold one, keeps it rather than being emptied (the existing keep-if-all-cold rule,
  now applied per group).
- Verified without a second machine's journal, as asked: 4 new `bench-stats` tests on synthetic journals (a
  10 s/unit machine and a 1 s/unit machine give 360 and 3600 units/hour, the pooled blend sits strictly between;
  untimed classes are absent; `unrecorded` is a class; per-class warm-up; most-recent-host selection) and one
  `bench-cli` test on the rendered text and markdown. End to end, a 3-line journal (`unified-32`, a copy relabelled
  `cpu-only` with 9 s generation, and an unlabelled line) printed 2192, 339 and 344 units/hour against a pooled 475.

**Pre-run gates (`bench-hw::gates`, `rustybench hw --gates`, `run-suite`).** Pure checks on the host
inventory, no endpoint needed (docs/05; the inference-side gates, `tg128` stability and thermal throttling, still
need one):

| gate | severity | fires when |
|---|---|---|
| `scratch-disk` | **block** | free space on the scratch volume is below `--min-free-disk-gib` (default 5); unreadable is a warning, never a block |
| `ac-power` | warn (**block** with `--require-ac`) | on battery; a laptop whose power source cannot be read is only ever a warning |
| `low-power-mode` | warn | macOS Low Power Mode on (new probe: `pmset -g`, `lowpowermode`) |
| `ram-available` | warn | under 1 GiB reclaimable |
| `inventory-complete` | warn | a probe failed or core count / RAM are zero: the hardware class may be wrong |

Warnings are printed and never stop a run (they make *throughput* less trustworthy, not the verdicts). A block
refuses `run-suite` before any model call unless `--ignore-gates`; `--dry-run` only plans and never blocks.
`hw --gates` prints every result and exits non-zero on a block. Checked on this host: all five pass; with
`--min-free-disk-gib 100000` `run-suite` printed the block and exited with "pre-run gate(s) failed:
scratch-disk", `--dry-run` planned anyway (585 units), and `--ignore-gates` ran. 9 gate unit tests cover the
threshold edge (exactly 5 GiB passes, one byte less blocks), battery with and without `--require-ac`,
unknown-power laptop vs desktop, and inventory gaps.

**Running the full registry sweep in chunks (not run here; the shared Mac is too busy).** Nothing has run
`validate-family` over all 118 families at HEAD in one go. `rustybench families` lists them with the number of
seeds `validate-family --cover` needs to exercise every skill of each; summed, that is **3,543 seeds** (the
heaviest: `seq-transform` 284, `iter-borrow` 182, `stack-machine` 136, `bit-ops` 99, `idiom-copy` 95), at roughly
5-20 s per seed depending on host load, i.e. several hours. To run it in pieces, one cargo job at a time:

```bash
export CARGO_TARGET_DIR=/some/dir CARGO_INCREMENTAL=0
cargo build -p bench-cli
for i in 1 2 3 4 5 6 7 8; do            # one chunk per sitting; chunks are dealt round-robin so they cost about the same
  for f in $(target/debug/rustybench families --chunk $i/8 --ids); do
    target/debug/rustybench validate-family --family $f --cover --scratch /tmp/rb-validate-$f > /tmp/rb-v-$f.log 2>&1
    tail -1 /tmp/rb-v-$f.log | grep -q "all gates passed" || echo "FAIL $f"
  done
done
```
`--cover` makes each family run exactly as many seeds as it takes to exercise all of its skills, so a green log
means every skill was gated, not just seeds 0..7. `--from N` resumes a long family at seed N (the range is
`N..cover-count`), which matters on a shared machine: **run each chunk as a foreground job.** Backgrounded
`validate-family` runs made almost no progress while no tool call was active (iter-borrow: 4 seeds in 25 minutes,
then ~7 s/seed in the foreground), so a long sweep should be a sequence of foreground commands of under ~10
minutes each, resumed with `--from`.

**Not done / decisions.** The hidden-build-failure floor (Q28) is untouched. `status` still reads the whole
journal for progress; only the pace is class-scoped. Gate thresholds are modest defaults and will want tuning
against real users' machines.

---

## 2026-10-05 · `iter-borrow` — a fifth `borrow-lifetimes` family: the iterator that captures `&self`

**What.** Family #117 `iter-borrow` (category `borrow-lifetimes`, core, constraint-dominant). A pinned `Series`
owns a `Vec<i64>`; the model implements three of six iterator-returning methods (`positives`, `doubled`,
`every_other`, `pair_sums`, `running_max`, `big_refs`). The given signatures are the natural ones,
`-> impl Iterator<Item = i64>` or `-> Box<dyn Iterator<Item = i64>>`, and a body that borrows `self` does not
type-check against them: edition-2021 `impl Trait` does not capture the `&self` lifetime (E0700), and a boxed trait
object defaults to `'static`. Both need `+ '_`. It is a common stumbling block, and the way out most models reach for
first, `collect()` into a `Vec` and return `vec.into_iter()`, owns its data and needs no lifetime at all.

**The escape is closed by measurement, not by rule.** The hidden alloc probe takes the first element of each iterator
over 256 elements, 50 times: a lazy `impl` allocates nothing, a lazy `Box<dyn>` allocates at most its one `Box` per call,
an eager collect allocates a `Vec` per call. Measured end to end (mock endpoint, seed 1 = `positives`/`doubled`/`big_refs`,
boxed):

| answer | score | notes |
|---|---|---|
| reference (`+ '_`) | 1.000 | |
| same, every `+ '_` removed | 0.000 | does not compile |
| `positives` and `doubled` collected eagerly into a `Vec` | 0.796 | behaviour 1.0; alloc constraint fails (`Constraint`) |
| `empty` baseline | 0.611 | |

**A decoy that turned out to be a constraint.** I first intended `big_refs` (item `&i64`, which already names the
borrow) as a method that needs *no* change. True for `impl Iterator<Item = &i64>`, false for the boxed form:
`Box<dyn Iterator<Item = &i64>>` is ill-formed on its own (the object bound defaults to `'static` while the item
borrows), so even a stub body fails to compile. The given signature for that one case therefore already carries
`+ '_`, a unit test pins exactly which given signatures do, and it remains a decoy for the other two methods.

**A second correction found by compiling the skeleton.** The first skeleton used `todo!()` bodies and 11 of the first 151
seeds scored `skeleton=0.000`, i.e. the *given* code did not build: `-> impl Iterator<..> { todo!() }` does not type-check
(the diverging expression falls back to `()`). The given bodies are now explicit empty-iterator stubs, and the skeleton
builds on every seed (it scores 0.407-0.611, behaviour 0.000). `lifetime-view` did not have the problem (a concrete
return type).

**Surface.** C(6,3) = 20 method sets × 2 return kinds = **40 distinct skills**. Type name cosmetic.

**Gates.** `validate-family --cover`: all **182 seeds (every one of the 40 skills)** OK, `reference=1.000`,
`baselines_caught=true` (`eager-collect`, `empty`). The run was done in pieces (seeds 0-34, then 35-110, 111-180,
181), logs concatenated; see the chunking note below for why. 7 module tests.

---

## 2026-10-05 · `unit-generic` — a fifth `traits-generics` family: associated consts through type parameters

**What.** Family #118 `unit-generic` (category `traits-generics`, core). A pinned `trait Unit { const FACTOR: i64;
const SUFFIX: &'static str; }` and three unit structs are given. The model writes the three `impl Unit` blocks from a
table in the prompt, then **one generic function** that reads the consts through its type parameters:
`convert::<Km, M>(3)` with no value of the type in sight, or, in the by-value style, `convert(Km, M, 3)` with unit
structs as marker values. The other traits-generics families implement an associated *type*, a method-bound generic,
std operator traits and a blanket impl; this is the const corner.

**Surface.** 6 functions (`convert`, `label`, `larger`, `total`, `leftover`, `fits`) × 2 call styles = **12 distinct
skills**; unit names, suffixes, factors (three distinct, ascending, drawn from 13 values) and four name sets are cosmetic.
`larger` on the same unit twice returns the first's suffix, so ties are pinned by a test. The differential compares
every ordered pair of the three units, including a unit with itself, against an inlined reference module.

**Measured end to end** (mock endpoint, seed 0 = `convert`, by value):

| answer | score | notes |
|---|---|---|
| reference | 1.000 | |
| `v * B::FACTOR / A::FACTOR` (direction swapped) | 0.409 | builds; the pair tests fail |
| `all-ones` baseline (every `FACTOR = 1`, suffix `""`) | 0.409 | |
| `ignore-types` baseline | 0.222 | |

The two 0.409 rows tie by construction: with a swapped formula the direction-symmetric pairs (a unit with itself) pass
and the rest fail, which is what the all-ones table does too.

**A prompt bug caught by reading it.** The `label` description said `e.g. "7cm"` while the table's units are `Pinch`,
`Spoon`, `Cup`: an example in a unit the model has not been given. It now describes the format abstractly.

**Gates.** `validate-family --cover` (40 seeds, all 12 skills): all OK, `reference=1.000`, skeleton 0.222,
`baselines_caught=true` (`all-ones`, `ignore-types`). 8 module tests, including one that loops every function ×
four factor tables asserting some canonical call distinguishes the answer from each baseline.

---

## 2026-10-05 · `idiom-api` — a fourth `idiom-refactor` family: fix the API, not a loop

**What.** Family #116 `idiom-api` (category `idiom-refactor`, core, clippy-dominant 0.30 / 0.60 / 0.10). A
small `Bag` type has an un-idiomatic public surface; the model makes it idiomatic and clippy-clean with
behaviour preserved. The three loop families (`idiom-loop`, `idiom-counter`, `idiom-copy`) rewrite a loop;
this rewrites an API: add the missing `is_empty()` (`clippy::len_without_is_empty`) and/or turn an inherent
method named `add` / `sub` / `mul` / `neg` / `next` into the std trait impl (`clippy::should_implement_trait`;
`mul` is `Mul<usize>`).

**Q14, measured.** The same scratch-crate method as `idiom-copy`: `should_implement_trait` (all of
`add`/`neg`/`next`, and by name the rest) and `len_without_is_empty` survive `cargo clippy --fix`;
**`new_without_default` does not** (it inserted the `Default` impl), so that lint is absent and the given code
already carries `Default`. `validate-family` re-confirms per seed: 27/27 `clippy_fix_safe=true`.

**Surface.** (is_empty only) + 5 operator methods + 5 (operator and missing is_empty) = **11 distinct skills**
(at least one defect always present).

**The `#[allow]` cheat, found by running it.** The hidden tests call `is_empty()` and use the operators, so an
answer that silences the lint instead of fixing the API does not build. But it still scored **0.667**: the
build failure costs behaviour, and a clippy-clean constraint layer is worth 0.60 in this category's weights.
Adding `allow` to `forbidden_paths` (the AST path check does see attribute paths) drops the same answer to
**0.333** (constraint 0.5: a measured violation). Recorded rather than left implicit: for a clippy-dominant
category the "does not build against the hidden tests" outcome is worth a lot, which is the Q28
pass-predicate/weights question again and is **not** patched here.

**Measured end to end** (mock endpoint, seed 4 = missing `is_empty` + `add`):

| answer | score | notes |
|---|---|---|
| reference | 1.000 | |
| reference + the inherent `add` kept alongside the trait impl | 0.333 | behaviour 1.0; clippy still flags it (`Idiom`) |
| `unchanged` | 0.000 | tests do not build; two lints |
| `#![allow(..)]` cheat | 0.333 | after `allow` became a forbidden path (0.667 before) |

The keep-both row matters: implementing the trait is not enough, the inherent method has to go, and the
family distinguishes that from a correct answer purely through the clippy layer.

**Gates.** `validate-family --cover` (27 seeds, all 11 skills): all OK, `reference=1.000`,
`baselines_caught=true` (`unchanged`, `allow-attrs`), `clippy_fix_safe=true` ×27. View capacity is 9 ("exhausted
at 2700 candidates") because the given `Bag` code is most of the prompt; spec-diversity 11 clears the floor of 8
but is below a 27-seed epoch, so an epoch should not ask this family for more than ~11 distinct-skill units.

---

## 2026-10-05 · `result-collect` — a fifth `error-handling` family: what does a failure mean for the whole result?

**What.** Family #115 `result-collect` (category `error-handling`, core). A pinned `ItemError { Bad, Rule }` and
`parse_item` are given. The model adds a per-value rule check (failing with `Rule(v)`), then folds the
per-item `Result`s under one of four policies: `FailFast` (`Result<Vec<i64>, E>`, first error wins),
`Partition` (`(Vec<i64>, Vec<E>)`), `AllOrNothing` (`Result<i64, Vec<E>>`: the sum, or *all* the errors) and
`FirstOk` (`Result<i64, E>`: first success, else the *last* error; empty input is `Err(Bad(""))`).
The earlier families are about producing, propagating and being an error; this is the plumbing in between.

**Surface.** 4 policies × 3 rules (`Positive`, `Even`, `AtMost(b)`) = **12 distinct skills**; the bound and
function name are cosmetic and excluded from `spec_signature`. `unwrap` and `expect` are forbidden paths,
matching the prompt. The pinned items are imported into the differential, so it compares pure behaviour.

**A design constraint the unit tests enforce.** The canonical token list is built per rule so the *first
parseable value breaks the rule*: otherwise a rule-ignoring answer and the correct `FirstOk` agree on the
first success and the `skip-bad` baseline would pass. The first version of the native baseline mirror also
failed to drop errors, which the same unit test caught (`FailFast/Positive: skip-bad` equal to the correct
outcome) before the toolchain ran.

**Measured end to end** (mock endpoint, seed 2 = `AllOrNothing`/`Positive`):

| answer | score | notes |
|---|---|---|
| reference | 1.000 | |
| `collect::<Result<Vec<_>,_>>` then `Err(vec![first])` (short-circuits) | 0.456 | builds; passes the all-OK examples, fails every multi-error case |
| `skip-bad` baseline | 0.456 | |
| `empty` baseline | 0.339 | |

The short-circuit row is the realistic mistake: it type-checks and gets partial behaviour credit, so the family
can tell it from both a compile failure and a correct answer.

**Gates.** `validate-family --cover` (23 seeds, all 12 skills): all OK, `reference=1.000`,
`baselines_caught=true` (`empty`, `skip-bad`). 8 module tests.

---

## 2026-10-05 · `blanket-impl` — a fourth `traits-generics` family: a blanket impl, and `?Sized`

**What.** Family #114 `blanket-impl` (category `traits-generics`, core). The traits `Shape` (required
`area`, `sides`) and `Describe` (`describe`) and two shapes are pinned; the model writes
`impl<T: Shape> Describe for T`. `trait-impl` implements a trait for one provided type, `generic-select`
writes a generic function, `ops-overload` implements std traits; this is coherence-level generics.

**Two traps, each checked.**
- *Per-type impls compile and are not enough.* The hidden tests define a third shape (`Poly`) and call
  `describe()` on it. Measured (seed 0): `impl Describe for Sq` + `impl Describe for Rect` builds, then the
  test target fails to build, 0.222 with `behavior:no_summary`.
- *`?Sized`.* In the `Unsized` variant the tests call `describe()` through `Box<dyn Shape>` and `&dyn Shape`;
  `impl<T: Shape>` has an implicit `T: Sized`. Measured: the reference with `+ ?Sized` removed scores
  0.222 (no_summary) where the reference scores 1.000.

**Surface.** 5 render styles (`"4:9"`, a verbose sentence, a parity branch, an integer division, a repeated
`*`) × 2 reaches (`Sized`, `Unsized`) = **10 distinct skills**. Trait/type names are cosmetic (three name
sets) and excluded from `spec_signature`. The differential implements *both* crates' `Shape` for one
test-local type (`Poly`) and compares the two `describe`s over 3000 random (area, sides) pairs, additionally
through `&dyn` for `Unsized`; sides are drawn from 1..=8 so the division style never divides by zero (unit-tested).

**Gates.** `validate-family --cover` (34 seeds, all 10 skills): all OK, `reference=1.000`, skeleton 0.222,
`baselines_caught=true` (`per-type`, `const-empty`). The view-capacity diagnostic reads 30 ("exhausted at 3400
candidates") and 21/561 near-twin prompts: with 10 skills and a mostly-pinned prompt the example text varies
less than in the larger families. Not a gate failure and left as is; widening the surface (more render styles)
is the lever, not more example noise (docs/17).

---

## 2026-10-05 · `lifetime-view` — a fourth `borrow-lifetimes` family: the elided signature that compiles; plus `validate-family --cover` and `emit`

**What.** Family #113 `lifetime-view` (category `borrow-lifetimes`, core, constraint-dominant). A pinned
`View<'a>` wraps a borrowed `&'a [i64]`; the model implements three of five slicing methods (`head`,
`tail`, `init`, `last_n`, `inner`, chosen by seed). The skeleton shows `-> View<'_>` with `todo!()` bodies.
That **compiles**, and is wrong: `'_` is the lifetime of the `&self` borrow, not of the data, so the child
cannot outlive its parent view. The hidden tests drop the parent first (E0597 for the elided answer). The
sibling `lifetime-split` is the version where the elided signature does *not* compile (E0106); this is the
quieter, more common mistake where it builds. Correct is `View<'a>`.

**Surface.** C(5,3) = 10 method sets × 2 miss policies (`Plain` clamps and never panics; `Optional` returns
`None` out of range) = **20 distinct skills**. Type name cosmetic, excluded from `spec_signature`. The
scoped-parent check is in all three hidden targets (behaviour, differential, alloc; inline in the measured
test for alloc, for the parallel-allocation reason recorded under `lifetime-split`); `leak` is a forbidden path.

**Measured end to end** (mock endpoint, seed 0 = `head`/`last_n`/`inner`, `Optional`):

| answer | score | notes |
|---|---|---|
| reference (`View<'a>`) | 1.000 | |
| same, but `Option<View<'_>>` | 0.407 | builds; all three hidden targets fail to build (`no_summary`) |
| `Box::leak` copy of the slice | 0.593 | behaviour 1.0; alloc + forbidden-`leak` constraints fail |
| `echo-whole` baseline | 0.407 | fails on assertions |

The 0.407 floor is the existing non-zero constraint credit for a non-building hidden target; the Q28
question is recorded below, not patched here.

**Gates.** `validate-family --cover` (33 seeds, every one of the 20 skills): all OK, `reference=1.000`,
skeleton 0.407 (behaviour 0.000), `baselines_caught=true` (`echo-whole`, `empty`). 7 module tests.

**Tooling added with it.**
- `bench_gen::seeds_to_cover(gen, cap)` and `validate-family --cover`: run exactly the first N seeds that
  realise every distinct skill the family can produce, instead of guessing `--seeds`. Unit-tested for
  coverage and minimality. (Earlier this session `idiom-copy` needed a hand-run coverage search, and its
  gate run reached only 23 of 27 skills.)
- `rustybench emit --family F --seed N --dir D`: writes the prompt, reference, skeleton, each baseline and the
  hidden tests for one seed, with its skill line, for hand inspection or for grading a hand-written wrong
  answer through a mock endpoint (how the table above was produced).

**Open decision, unchanged (Q28).** A hidden-test build failure still earns 0.22-0.41 through the constraint
layer on every family. Whether behaviour should be a floor is the pass-predicate/weights question; nothing here
touches it.

---

## 2026-10-05 · `idiom-copy` — a third `idiom-refactor` family on the one lint that survives `clippy --fix`

**What.** Family #111 `idiom-copy` (category `idiom-refactor`, core, clippy-dominant 0.30 / 0.60 / 0.10).
The model is given a working function that copies a run of elements with an index loop and must
rewrite it as the slice operation it is (`copy_from_slice` / `clone_from_slice`), clippy-clean, with
behaviour preserved. The lint is `clippy::manual_memcpy`.

**Why this lint (Q14, measured, not assumed).** An `idiom-refactor` family is only meaningful if
`cargo clippy --fix` cannot solve it. A scratch crate against the installed clippy (1.97) applied
`--fix` to eleven candidate manual-idiom lints. `manual_find`, `manual_map`, `manual_unwrap_or`,
`question_mark`, `manual_swap`, `manual_div_ceil`, `manual_abs_diff`, `implicit_saturating_sub`,
`manual_is_multiple_of`, `filter_next` and the pop-in-a-loop pattern were all rewritten mechanically
(each would be rejected as a family, like `manual_flatten` before them). **`manual_memcpy` alone survived
unchanged**, in every loop shape used: offsets on either side, a counted range, a windowed range, and
`i64` / `String` / `u8` elements. Four lints I expected to fire (`manual_clamp`, `manual_range_contains`,
`manual_retain`, `manual_slice_fill`) did not fire at all on the installed version, so they were not
candidates either. `validate-family` re-checks this per seed (`clippy_fix_safe=true (1 lint survives --fix)`).

**Surface.** 3 shapes (`Same`, `ShiftDst`, `ShiftSrc`) × 3 extents (whole `src`, counted `0..n`, windowed
`start..start+n`) × 3 element types = **27 distinct skills**. The shift distance, parameter names and
function name are cosmetic and excluded from `spec_signature` (Q31). A `zip`-based rewrite is also
clippy-clean and accepted.

**Details worth recording.**
- `&src[..src.len()]` trips `clippy::redundant_slicing`, so a whole-`src` copy must emit `copy_from_slice(src)`;
  the first draft of the reference emitted the redundant slice and would have scored below 1.0 against itself.
- The first canonical source had seven elements, too few for `start + shift + n` at the largest shift; a
  unit test that runs `eval` (which panics out of range) over the canonical and 400 seeds' cases caught it.
- The generator's own `eval` uses the idiomatic slice copy (so our crate stays clippy-clean); the hidden
  differential uses an explicit element loop, an independent rendering; a unit test cross-checks the two over
  every (shape, extent, elem, shift) combination.

**Gates.** `validate-family`: every seed `reference=1.000`, skeleton `0.333` (behaviour 1.000: the loop is correct,
only clippy flags it), `baselines_caught=true` (`unchanged`, `noop`), `clippy_fix_safe=true`. Coverage of all 27 combinations took two steps. The gate ran on seeds 0-40 (23 distinct skills, every seed OK, `clippy_fix_safe=true`); the four combinations first reached by seeds 46, 53, 67 and 94 were then graded end to end through a mock endpoint instead (the full 95-seed gate run was abandoned: it slowed to ~100 s/seed under host load): reference 1.000 and the unchanged loop 0.333 (`behavior=1.0`, `constraint=0.0`, `failure=Idiom`) on each. So the Q14 `--fix` gate itself was exercised on 23 of 27 skills, and the same lint fires on the other four.
## 2026-10-05 · `error-source` — a fourth `error-handling` family: being an error, not producing one

**What.** Family #112 `error-source` (category `error-handling`, core). The pinned `AppError` enum is given;
the model writes `impl Display` (each variant rendered in a prescribed style) and `impl std::error::Error`
with a correct `source()`. The existing three families are about producing errors (validation over a
pinned enum, checked arithmetic, `?` across error types).

**Where models slip.** The wrapper variant holds its cause three ways, each with its own `source()`
spelling: concrete (`Io(IoFail)` -> `Some(e)`), boxed (`Io(Box<dyn Error>)` -> `Some(e.as_ref())`), and
chained (`Context(String, Box<AppError>)` -> recurse down an arbitrarily deep chain). A wrapper's `Display`
must show only its own message; the cause is reached through `source()`, so the expected chain is exactly
the sequence of `Display`s down `source()`. 4 styles (Plain / Bracket / Colon / Upper, the last also needing
`to_uppercase`) × 3 payloads = **12 distinct skills**.

**Mirror.** One template table (format string + argument expressions) drives both the native renderer and
the emitted `write!` arms, so they cannot drift; the differential builds the same random error tree against
the model and an inlined `mod reference`, and compares the whole chain.

**Measured end to end** (mock endpoint; seed 0 = Plain/Boxed, seed 5 = Plain/Chained):

| answer | score | notes |
|---|---|---|
| reference | 1.000 | |
| boxed cause returned as `Some(e)` instead of `Some(e.as_ref())` | **0.000** | does not compile, `failure=Trait` |
| correct `Display`, no `source()` (boxed) | 0.356 | builds, chain assertions fail |
| chained `source()` returns `None` | 0.489 | builds; leaf cases still pass |
| `Display` writes nothing | 0.222 | builds, fails |

The `Some(e)` slip is the interesting row: it is a type error the compiler reports against the answer
itself, so it is classified `Trait` rather than falling into the `logic` bucket the hidden-test build
failures of `lifetime-split` get.

**A gate finding.** The first cut passed every `validate-family` gate but reported a view capacity of 6
("exhausted at 1200 candidates") and 36/66 near-twin prompts: example strings came from tiny palettes. They
are now generated words, which lifts view capacity to 12+ and near-twin pairs to 0/66 with no change to the
12 structural skills. Reference-distance stays low (median 0.209): that is the documented property of
pinned-interface families (docs/17), where the fixed enum is most of the solution text.

**Gates.** `validate-family --seeds 12`: all 12 OK covering all 12 skills, `reference=1.000`, skeleton 0.222,
`baselines_caught=true` (`empty-display`, `no-source`). 9 module tests, including one asserting the canonical
wrapper has a chain of at least two non-empty messages under every style × payload (what both baselines need).

**Limits.** Only `Display` + `source()` are graded; `Error::description` is deprecated and `provide` is
unstable, so neither appears. Backtrace capture and `anyhow`-style context are out of scope.

---

## 2026-10-05 · `ops-overload` — a third `traits-generics` family: `std::ops` and `std::iter` impls

**What.** Family #110 `ops-overload` (category `traits-generics`, core). The value type (and for
residue/saturating algebras its `new`/`val`) is pinned in the skeleton; the model writes the
operator-trait impls. `trait-impl` implements a user trait with an associated type and
`generic-select` writes a generic function over one; this is the other large share of everyday trait
work, the std operator and fold traits, including the by-reference impls that are easy to omit.

**Surface.** 4 algebras (component-wise `Pair`; `Cplx` where `*` is complex multiplication; `Mod`
arithmetic mod a seed-chosen prime; `Sat` saturating into ±100) × 4 trait sets (`Core`: Add, Mul, Neg;
`ByRef`: Add and Mul for `T` *and* `&T`; `Assign`: Add, Mul, AddAssign, MulAssign; `Fold`: Add, Mul,
Sum, Product) = **16 distinct skills**. Type name and modulus are cosmetic and excluded from
`spec_signature` (Q31). Hidden drivers use the operators directly (`&a + &b`, `x += y`,
`iter.sum::<T>()`), so a missing impl fails to build and behaviour scores 0.

**Mirror, by construction.** The native algebra (`add`/`mul`/`neg` on a normalised pair) and the
emitted impl bodies are written side by side; the differential pastes the reference into
`mod reference { .. }` of the test file so both `T`s coexist and compares 3000 random operand sets
through a key function. No allocation target (`alloc_test` empty), weights are the category default
(0.70 / 0.20 / 0.10).

**Gates.** `validate-family --seeds 16`: all 16 seeds OK covering all 16 skills, `reference=1.000`,
skeleton 0.222 (behaviour 0.000), `baselines_caught=true` (`echo-lhs`, `all-zero`). Re-run at 4 seeds
after a final refactor: pass. 9 module tests, including one that loops every algebra × trait set ×
modulus asserting each checked result avoids both baselines' values.

**What the unit test caught before the toolchain did.** The first `Mod` canonical triple used
`c = 1`, making `c * c == c` — an echo of the left operand on the `ByRef` set. The test compares each
check against *its own* left operand (`c` for `c*c`, `a` elsewhere); a first version compared all
against `a`, which would have missed the `Cplx` coincidence `(2+i)² = 3+4i = a`.

**Measured end to end** (mock endpoint, seed 3 = `Cplx` / `ByRef`): reference 1.000; reference minus the
two `&T` impls 0.222 with `behavior:no_summary, differential:no_summary` (the driver does not build);
complex `*` replaced by component-wise 0.222 (builds, tests fail). The baselines were checked to
*compile* and fail on assertions, not on a build error: seeds 0, 1, 3, 13 (all four trait sets), both
baselines, `unit=0.0 diff=0.0`, no `no_summary` flag. The 0.222 floor is the same non-zero constraint
credit noted in the `lifetime-split` entry.

**Limits.** `Sum<&T>` (iterating references) is not required or tested; `Fold` uses owned items only.
Operator traits with a non-`T` right-hand side (`Mul<i64> for T`) are a natural follow-up family.

---

## 2026-10-05 · `hw_class` in the journal, and `stats`/`report` say which hardware throughput covers

**What.** Every journal line now carries `hw_class` (the `bench-hw` bucket, e.g. `unified-32`), probed
once per process and cached. `bench-stats` reads it (`Record.hw_class`, default `None`, so old journals
still load) and `StatReport` gains `hw_classes` (units per class, `unrecorded` for old lines) plus
`hardware_note()`. `stats`, `report` (md and json) print it.

**Why.** docs/06: `throughput_score`, `time_to_first_pass` and `efficiency_score` are only comparable
within a hardware class, but nothing stopped `stats` folding two machines' journals into one
"units/hour". Now a single-class journal says `hardware: unified-32 (all N units)`, and a mixed one prints
`WARNING: hardware: this journal mixes ... Throughput aggregates machines that are not comparable
(docs/06); capability_score is unaffected.` Capability is deliberately not blocked: it does not depend on
where the model ran (class-level capability comparability is a separate question, docs/06's exec-class
finding, not hardware).

**Details.** Probe units count toward hardware (they cost wall time) but never toward scored figures.
Recorded-plus-unrecorded also warns, since an appended pre-`hw_class` journal may be a different machine.
The field is omitted, not null, when the probe cannot run. `docs/12` documents `hw_class` and records how
the implemented `hw.json` differs from the sketch (bytes not MB, one provenance map, local-only profile
vs public bucket).

**Verified.** 6 new `bench-stats` tests (old line parses as unrecorded; single class; unrecorded-only;
mixed warns; recorded+unrecorded warns; probe units counted for hardware but not capability) and a
`bench-cli` round-trip (CLI-written line, `None` omitted, read back by `load_journal`). End to end with
a mock endpoint: `run` wrote `"hw_class":"unified-32"`; `stats`/`report` printed the hardware line; appending
a pre-`hw_class` journal flipped it to the mixed warning.

**Not done.** `run-suite` ETA still pools all units in the journal. Class-scoped throughput (one figure per
class rather than a warning) is the obvious follow-up once there are journals from two machines to test with.

---

## 2026-10-05 · `lifetime-split` — a third `borrow-lifetimes` family: which argument does the result borrow from?

**What.** Family #109 `lifetime-split` (category `borrow-lifetimes`, core). The model gets
`pub fn f(text: &str, sep: &str) -> &str` (or `Option<&str>`) with the lifetimes **elided**, which
does not compile (E0106), and must write the annotations. `window-op` and `dual-region` test
aliasing; this is the other half of docs/04's row, lifetime elision and explicit lifetimes.

**The trap, and why it is the point.** The textbook `longest<'a>(x: &'a str, y: &'a str)` fix
compiles but is wrong here: the hidden test drops the separator `String` while the result is still
in use, which only compiles when the result is tied to the *source* argument alone (E0597
otherwise). The test target then fails to build, exactly the `trait-impl` mechanism ("signature
wrong ⇒ unsatisfiable driver").

**Surface.** 6 cuts (BeforeFirst / AfterFirst / BeforeLast / AfterLast / StripPrefix /
StripSuffix) × 2 return shapes (`&str` with a documented miss default, or `Option<&str>`) × 2
source positions (source is the first or the second parameter) = **24 distinct skills**. Function
name, parameter names and the separator are cosmetic and excluded from `spec_signature` (Q31).

**Two things found by running it, not by review.**
1. *The first cut under-penalised the central skill.* With the scoped-separator test only in the
   behaviour target, a both-`'a` answer scored **0.767**: behaviour unit 0 but differential 1.0 and
   constraint 1.0. The lifetime check is now in **every** hidden target. Re-measured end to end
   against a mock endpoint on seed 0 (`carve(text, sep) -> Option<&str>`):

   | answer | score | notes |
   |---|---|---|
   | reference (`<'a>` on `text` only) | **1.000** | |
   | both args `'a` (the textbook shape) | 0.407 | all three test targets fail to build |
   | `text: &'static str` | 0.407 | same |
   | `Box::leak` to a `&'static str` | 0.593 | behaviour 1.0, but alloc + forbidden-`leak` constraints fail |

   0.407 is not "near zero" because a non-building hidden target costs behaviour but the
   constraint layer still credits `unsafe`/forbidden-path checks that did not run into a failure
   (2 of 3 constraint checks pass). That is the existing harness behaviour for every family, the
   same effect as the 0.689 row in the 2026-08 allocation entry, not specific to this one. It is
   recorded rather than patched here because it belongs to the pass-predicate/weights decision (Q28).
2. *A parallel-test hazard in the alloc target.* Adding the scoped test as a second `#[test]` in
   `alloc.rs` made the **reference** score 0.796: tests run on parallel threads and the scoped
   test's `String::from` was counted against the measured loop. In `alloc.rs` the block now runs
   first *inside* the measured test, before the counter is read.

**Gates.** `validate-family --seeds 8` and `--seeds 32`: every seed OK, `reference=1.000`,
`skeleton=0.000`, `baselines_caught=true` (`const-empty`/`const-none` + `echo-source`),
spec-diversity 24. 12 unit tests in the module, including one that loops every op × return-shape × separator combination
asserting the constructed canonical case defeats both baselines, and one that asserts the scoped
test is present in all three hidden targets and both argument orders occur. `leak` is a forbidden
path and the alloc probe closes `Box::leak` independently.

**Limits.** Failure class for a lifetime error inside a *hidden test* build is `logic`, not
`borrowck`: the diagnostic classifier only sees the answer's own compile (the
`diagnostic_completeness` caveat already recorded). Near-twin pairs at 32 seeds (3/496) are
same-spec pairs, expected for a 24-spec family.

---

## 2026-10-05 · `bench-hw` — the static host inventory and its public bucket (P1 hw, Phase A)

**What.** New crate `bench-hw` plus `rustybench hw [--json | --public] [--scratch DIR]`. It
builds the docs/05 Phase A `HwProfile` (CPU model/vendor/arch/cores/perf-efficiency split/features,
RAM total + available, GPUs, OS, storage kind + scratch free space, power source + chassis,
`unified_memory`) from OS tools, and derives the docs/11 **public view** (`HwPublic`): `hw_class`,
vendor, generation, `cpu_class`, chassis, power source. Calibration (Phase B, pp512/tg128/sustained)
is *not* built; it needs a live endpoint.

**Design.**
- **No new dependencies, no `unsafe`.** Probes are plain tools (`sysctl`, `vm_stat`, `pmset`,
  `diskutil`, `system_profiler -json`, `df -Pk`; Linux: `/proc/cpuinfo`, `/proc/meminfo`,
  `nvidia-smi`, `/etc/os-release`, `/sys/class/power_supply`). Each is parsed by a pure function
  in `parse.rs`; orchestration goes through a `Probe` trait so `inventory()` is tested against
  canned machines. `SystemProbe` gives every command a 10 s hard timeout and drains stdout on a
  thread, so a wedged `system_profiler` cannot hang a run before it starts.
- **Provenance per field.** `HwProfile.provenance` maps field → probe; a field with no entry was
  defaulted, not determined (docs/05: a fallback row deserves a different confidence marker). A
  failed probe never aborts: it records a warning and leaves a neutral value.
- **`hw_class` ladder** (docs/05): `unified-{16,32,64,128,128+}` by total RAM, rounded *up* (a
  24 GB Mac is `unified-32`; an 8 GB Mac is `unified-16`); `vram-{8,12,16,24,32,48,80+}` by the
  card's reported size, rounded up, using real reported sizes (RTX 4090's 24564 MiB is
  `vram-24`, a 10 GB 3080 is `vram-12`); `multi-gpu-<n>x<class>` keyed on the *smallest* card;
  `igpu`; `cpu-only`. Unified memory wins over any GPU figure because an Apple GPU has no VRAM.
- **Privacy is a tested property.** A test serialises `HwPublic` and asserts no exact model, core
  count, RAM size, or OS build appears in it (docs/11: exact GPU + driver + cores + RAM is a
  fingerprint). `rustybench hw --public` prints only that view; `--json` is the local detail.
- **Unknowns stay unknown.** Generation is recognised only from a small table (`m<N>`/`a<N>`,
  RTX 20-50, RX 6-9) and is `None` otherwise, never guessed. Linux AMD/Intel GPUs are not probed
  yet, so a Linux host without `nvidia-smi` gets an explicit warning that `cpu-only` may be wrong
  rather than a silent wrong class.

**Verified.** On this host (Apple M5, 24 GB, macOS 26.5.1): `hw_class unified-32`, 10 cores
(4P + 6E), `neon`, Apple GPU 10 cores sharing system memory, Nvme storage, AC/Laptop, `m5`.
`cargo test -p bench-hw -p bench-cli`: 31 + 20 pass; clippy `-D warnings` and rustfmt clean.

**Not verified.** The Linux path is parser-tested against fixtures only; no Linux or NVIDIA host
was available. Windows has no probes (reports an "unsupported OS" warning and `cpu-only`).
Chassis for newer generic `MacNN,M` model ids is inferred from battery presence.

**Next for P1 hw.** Wire `HwPublic` into the journal/submission manifest (docs/12), then Phase B
calibration against an endpoint, then the pre-run gates (AC power, free disk) which can now read
this profile.

---

## 2026-08-27 · L3 miri — the `unsafe-core` interpreter check

**What.** The oracle now runs the behaviour and differential targets under
`cargo +nightly miri test` and treats an interpreter UB report as a **hard
behaviour failure** — `behavior.unit` and `behavior.differential` are zeroed and
the vector carries `miri:ub`. Per docs/03 §L3 and docs/04 category 5, undefined
behaviour is not a style issue, so it does not become a constraint deduction.

**Where.** `GradeSpec::check_miri` plus the stage in `bench_oracle::grade`;
`MiriVerdict` / `parse_miri_verdict` classify captured output. UB markers are
`Undefined Behavior`, `error[E0080]` (const-eval abort), and
`error: unsupported operation` (miri stops, so the run proves nothing).

**Turned on by category, not by family.** The mandate is a property of
`unsafe-core`, so `bench-cli` derives `check_miri` from `task.category` against
one `MIRI_CATEGORY` const rather than adding a knob to ~110 family files. A
bench-cli test asserts some registered family still declares that category — a
rename in `bench-gen` would otherwise silently disable a mandatory layer with
nothing failing. `ffi-boundary` stays excluded by construction: miri cannot
execute foreign calls.

**Absence is recorded, never silent.** `miri_available` probes
`cargo +nightly miri --version` through the same containment policy as every
other cargo call, so a probe cannot download a toolchain. With no nightly+miri
on the host the stage is skipped with `miri:unavailable`; `miri:no_targets`,
`miri:no_summary`, and `timeout:miri` cover the other gaps. That is the state on
this dev host — PATH `cargo` is Homebrew's, not the rustup shim, so the flag
path is what actually fires here and the layer has **not** been exercised
end-to-end against real UB yet.

**A leak is not UB.** Miri's leak report is a resource finding, not an
undefined-behaviour finding, so it yields `Clean`; the failing test summary
already costs the answer through the ordinary L2 path.

**Clean requires a summary.** No UB marker *and* no test summary means the
target did not build under miri — `Unknown`, flagged, not credited. An earlier
draft of this stage returned `Unknown` for every clean run too, which would have
stamped `miri:no_summary` on every passing `unsafe-core` unit; four unit tests
now pin the three verdicts and the leak case.

---

## 2026-08-25 · Skill-area families 7–14 — iterators, conversion traits, drop guards, deref coercion, trait objects, exhaustive matching, higher-order functions, and clone-on-write

**What.** Continued the skill-area pivot past its first five families with
eight more, each pinning a distinct Rust discipline behind a structural
catch:

- `iter-machine` (custom-iterators): the model writes only
  `impl Iterator::next()` state machines under a provided `take(n)`
  driver; an off-by-one baseline starts each machine at index 1.
  Registration exposed a real crash class — an empty `answer_path` made
  the oracle open the workspace root (`EISDIR`) — now pinned by registry
  drift guards that also check task-id prefix, canary derivation, and
  hidden-test keys, all kill-verified by planting faults.
- `convert-trait` (convert-traits): model fills
  `impl TryFrom<&str>` bodies over provided newtypes and error enums;
  naive impls that unwrap die on invalid examples, always-error impls die
  on valid ones. The probe caught a real reference bug pre-commit (Port's
  u16-parse-first misclassified "65536" as `NotNumeric` instead of
  `OutOfRange`), fixed by range-checking on a widened u32 before the
  narrowing cast and pinned structurally.
- `raii-guard` (drop-semantics): a provided guard appends to an audit log
  on drop; ops sequence scopes so answers depend on drop timing. A naive
  baseline reads the log while its guards still live. Assembly surfaced a
  new bug class — tail-expression temporaries are lifetime-extended inside
  call chains, so bare `log.borrow().len() as i64` kept the borrow alive
  into fn-end drops; all tail reads now bind locals first. A
  survivor-mutation ([0] vs `last()` indistinguishable on fresh logs) was
  killed by adding a reused-log pin.
- `deref-wrap` (smart-pointers): the model writes only tiny `Deref` /
  `DerefMut` impl bodies over provided wrapper types; complete drivers do
  everything through coercion. A sees-nothing baseline returns
  `&self.0[..0]`, breaking every slice op but unfakeable for `DerefMut`.
  Validation caught a pair-dependent compile bug (~40% of seeds): `&`
  binds looser than `.to_vec()` in interpolated literals, fixed by
  parenthesizing the interpolation.
- `dyn-shapes` (trait-objects): stubbed impl blocks behind one vtable;
  zero-value impls compile but fail every scalar answer while real tags
  keep `count_tag` honest. Boxed shelves avoid binding-shape bugs; probe
  runs covered two seed pairs after the poll-future/deref-wrap lesson that
  single-seed probes miss pair-dependent emitted-code bugs.
- `enum-match` (pattern-matching): exhaustive matching over a provided
  `Msg` enum where `weighted_balance`'s opposite-direction arms defeat
  payload-blind wildcards; differential needed parallel task/local wires
  because element types differ across the paste boundary.
- `closure-pipe` (higher-order-functions): behavior tests drive every op
  with identity AND shifting closures, so solutions ignoring the closure
  parameter agree with one phase and fail the other. Canonical anchors
  required redesign: a strictly increasing transform leaves positive-count
  and first-negative invariants unchanged, so divergence is demanded only
  from value ops.
- `cow-str` (clone-on-write): every op returns `Cow<'_, str>`;
  ownership verdicts are pinned per example via `matches!` literals
  (`is_borrowed`/`is_owned` remain nightly-only). Always-owned cheats pass
  values but fail Borrowed pins; the always-owned `reverse_view` convicts
  never-cloners since reversed text cannot be a slice of its input.

**Verified.** Each family followed the full treatment: scaffolded ops,
differential fuzz against a pasted renamed reference, mutation kills on
native semantics plus catch-mechanism pins, single-seed dump probes with
reference swaps green end-to-end, and validate-family at 200 seeds passing
all gates. Registry guards grew to enforce unique canonical/examples seed
constants and per-family `answer_path`/id-prefix/canary/hidden-key shape.

Corpus after these families: 84 registered families across 65 categories,
all validated at 200 seeds.

---

## 2026-08-25 · `ref-cell` — interior mutability as the sixth skill-area family

**What.** Extends the skill-area pivot with the one Rust discipline it had
not covered: `RefCell` borrow-flag semantics. Tasks hand a
`&RefCell<Vec<u64>>` and ask for read-phase/write-phase sequencing
(`append_and_total`, `pop_and_return`, `set_first`, plus pure-read
`sum_of_squares` / `count_of`). The reference keeps borrows tightly scoped
to their phase; the naive baseline holds a shared borrow across a
conflicting `borrow_mut()`, so the borrow flag panics deterministically on
every call — a structural catch riding ordinary behavior-test failures,
zero oracle changes, single-threaded so the differential stays sound.

**Verified.** A spike proved both directions before authoring (correct
phased borrows compute cleanly; a held borrow across `borrow_mut()` panics
and is caught by standard test machinery). An exploit pass hand-wrote a
genuine overlapping-borrow implementation against a dumped task: all
behavior examples fail with `BorrowMutError` through the real grading path.
Three native mutations were killed by independent hand pins. Validation at
200 seeds passed all gates with the best anti-twin separation of any
skill-area family (min 0.241, near-twins 2/19900).

Corpus after this family: 76 registered families across 57 categories, all
validated at 200 seeds.

---

## 2026-08-25 · The skill-area pivot — borrow, traits/generics, unsafe-pointer, async, and allocation discipline as generated families

**What.** A review round flagged mission drift: the corpus had grown past
seventy families but nearly all were arithmetic trivia, while
borrow-checker/traits/unsafe coverage sat at ≤2 families each and async/perf
at zero. The pivot shipped five skill-area families, each with a *structural*
catch mechanism rather than another numeric oracle:

- `borrow-fix` (borrow-checking): answers must be slices of the inputs
  themselves — `&str` returns force lifetime reasoning. A hidden
  `tests/alloc.rs` counting `#[global_allocator]` fails any hot path that
  allocates; `alloc_test` rides the standard L3 slot, the first family ever
  to set it. The clone-everything baseline passes behavior and fails only
  the probe.
- `generic-bounds` (traits-generics): the model writes its own generic
  functions over std bounds; hidden behavior tests instantiate on both
  `[i64]` and `[&str]`, so a hard-coded-i64 baseline fails **compilation**
  on the second type.
- `pointer-slice` (the third unsafe-core sibling): reconstruct a slice once
  via `std::slice::from_raw_parts` at the boundary, then work in safe
  iterators — distinct from raw-ptr's per-index deref loops and raw-ptr-mut's
  in-place stores.
- `poll-future` (future-machinery, first async family): tasks ship a
  provided std-only deterministic executor (spin-on-Pending `block_on`,
  `Waker::noop`); the model implements `Future::poll` state machines over
  delay futures. Fixed poll order makes outputs deterministic, which
  resolves Q11's oracle blocker for this shape — the spike the roadmap
  demanded before authoring an async category.
- `perf-refactor` (allocation-discipline): idiom-loop rewrite framing with
  the counting allocator as the signal. Skeletons contain complete,
  behaviorally-correct HashSet / sort-copy / prefix-vector textbook
  implementations; the rewrite must preserve byte-identical answers without
  touching the heap.

**Verified.** Each family: scaffold → generator → registry wiring → mutation
kill on its subtle-state ops → validate-family at 200 seeds with all gates
passed. The perf-refactor skeleton scores fractional by design (behavior
credit, zero allocation credit). An adversarial pass hardened both
allocation probes against a memoizer cheat (a second, differently-shaped
input is exercised after the counter reset). Seed-constant drift guards now
enforce `CANONICAL_SEED`/`EXAMPLES_SEED` uniqueness repo-wide.

Corpus after the pivot: 75 registered families across 56 categories, all
validated at 200 seeds.

---

## 2026-08-21 · docs/12 schema reconciliation — the journal line, matched to what the code emits

The schemas were drifting behind the code again — the exact recurring defect the docs call out a process
note against ([OPEN-QUESTIONS.md](OPEN-QUESTIONS.md), "schema drift"). docs/12's `journal.jsonl` block is
the *design target*; what `run` / `run-suite` actually write had diverged in three ways and grown several
fields the doc never mentioned. Rather than silently rewrite the target (some divergences are genuine
naming decisions to resolve, not typos), added a precise **"Current emission (implemented subset)"**
subsection that documents the real line — `bench-cli`'s `JournalLine` embedding `bench-core`'s
`OracleVector` — and lists every divergence:

- **`kind` vs `set`**: the code emits `"kind"` for the core/probe label (and `bench-stats` reads it, and
  journals exist with it), while the target says `set`. Flagged as a breaking rename to reconcile, not
  quietly picked.
- **`oracle.constraint`** is the real `ConstraintScore` (`alloc_ok`/`clippy_clean`/`fmt_ok`/`unsafe_blocks`/
  `unsafe_ok`/`paths_ok`/`violations`/`score`), not the target's older `{clippy, fmt, unsafe_blocks,
  forbidden, score}` sketch.
- `model` is a nested object with `base_url`; `sandbox` and `epoch` are emitted; `failure_class` is present
  both top-level and inside `oracle`; the stage-scoped timeout/`no_summary` flags are documented.
- **Not emitted yet** (target fields awaiting their phase): `run_id`, `subcategory`, `batch_nonce`, `canary`,
  `attempt`, `completed_at`, `compile_rate_contrib`, `first_try_score`, `classified`, `cached_tokens`,
  `oracle.quality` (L4), and the richer `cost` timings.

And a **guard against the next drift**: a `bench-stats` round-trip test (`parses_current_emission_journal_line`)
pins that the documented line deserialises into `Record`, so a reader change that breaks it fails CI. Docs +
one test, no grading run; `bench-stats` 27 tests, clippy `-D warnings` / `cargo fmt --check` clean.
(Chosen as a collision-free chunk while other agents author families in `bench-gen` and add the miri stage
in a worktree — this touches only docs/12 and `bench-stats`.)

---

## 2026-08-21 · Fifteenth family: `idiom-counter` — the second idiom-refactor family, a different lint

`idiom-refactor` had exactly one family (`idiom-loop`, built around
`clippy::needless_range_loop`). This adds a second, built on a different
detectable non-idiom: the **explicit running counter** —
`let mut i = 0; for &x in xs { … i += 1; }` — which trips
`clippy::explicit_counter_loop`.

Same de-idiomatisation contract as `idiom-loop`: the skeleton is *behaviourally
complete* and only clippy distinguishes it; weights are docs/04's
behavior .30 / constraint .60 / quality .10 (`check_clippy=true`,
`max_unsafe=None`).

Two axes × = **12 distinct specs**: how index contributes (**weight**: linear
`i+1` / reverse `n-i` / parity `±1`) and what each element becomes before
weighting (**map**: identity / double / square / negate). The idiomatic answers:
`.enumerate()` for linear, `.rev().enumerate()` for reverse (the reversed
position *is* the weight — no length arithmetic), an `if i % 2` inside the
closure for parity.

**Q14 verified twice over.** Before authoring, both directions were measured in
a scratch crate:

- all three de-idiom shapes fire `explicit_counter_loop`, whose suggestion is
  MaybeIncorrect — after `cargo clippy --fix` every `i += 1;` survives (and the
  automated gate confirms per-seed below);
- all 12 emitted references are clippy-clean under `-D warnings` (dumped and
  linted verbatim), so the reference scores 1.000 while the unchanged counter
  loop scores ~0.33.

Baselines unchanged from `idiom-loop`: the load-bearing `unchanged` (correct,
unidiomatic) plus `const-zero`; the pinned canonical `[3,1,4,2]` is non-zero
under all 12 spec combinations.

```
validate-family idiom-counter: 8 seed(s)
  seed   0: OK   determinism=true reference=1.000 skeleton=0.333
                 (behavior 1.000) baselines_caught=true canary=true
                 clippy_fix_safe=true (1 lint(s) survive --fix)
  seed   1..7: same OK shape; seeds 2 and 6 report 2 surviving lints  [×8]
  anti-twin  view (prompt+skeleton): min=0.286 median=0.399 near-twin pairs (<0.25)=0/28
  anti-twin  reference (solution) : min=0.120 median=0.833 near-twin pairs (<0.25)=2/28
  capacity   view=8+ (asked 8, rejected 0)  reference=15
  spec-diversity: 12 distinct skills (the authoritative task-diversity measure — Q31)
  distinct-skills epoch: served 8 seed(s) covering 8 distinct skills
all gates passed
```

Honest caveats:

- Skeleton composite 0.333 with behavior 1.000 is the family working as
  designed — the model's starting code is correct, and only the clippy layer
  separates it from full credit.
- Reference anti-twin min=0.120 (two near-twin pairs of 28): with one shared
  signature and three weight strategies, two seeds' references can be close;
  view-distance stays clean and spec-diversity (12) is the gated measure.
- Like `idiom-loop`, there is no unsafe layer here by design.

186 workspace tests (+8); clippy `-D warnings` and `cargo fmt --check` clean.

---

## 2026-08-21 · `diagnostic_completeness` — borrow failures published as the lower bound they are

The last docs/03 §L1 field (commit `21d0761`; this entry backfilled after the concurrent family commits
cleared the shared BUILD-LOG). Type checking aborts before borrow checking, so a solution with a
type/trait/resolve/syntax error never reaches borrowck and any borrow bug it *also* has is masked (docs/03
measured it: one type error + two borrow errors → rustc emitted two E0308s and nothing else). The error
histogram therefore undercounts borrow failures — in exactly this project's niche — so the honest fix is to
*record* when borrowck wasn't reached.

- **`bench-core`**: `DiagnosticCompleteness { Full, TypeckOnly }` (serde `snake_case` → `full`/`typeck_only`)
  + `diagnostic_completeness(codes)` reusing `classify_error_codes`' phase order (a borrow/lifetime error ⇒
  borrowck ran, `Full`; an earlier-phase error with none ⇒ `TypeckOnly`). Added as an `OracleVector` field
  (`#[serde(default)]` = `Full`, so older journals parse unchanged).
- **`bench-oracle`** `grade()`: classified from the codes on a compile failure, `Full` on a success.
- **`bench-stats`/`report`**: `DiagnosticsReport.typeck_only` counts masked-borrowck core failures; the md
  report prints *"borrowck masked: N failure(s) …"* when N > 0.

Verified end-to-end on a synthetic journal (a `type`/E0308 failure + a clean unit): `typeck_only = 1`, the
masked line renders, the serde value round-trips. Pure logic + fast unit tests, no grading run. clippy
`-D warnings` and `cargo fmt --check` clean.

---

## 2026-08-21 · Fourteenth family: `raw-ptr-mut` — unsafe *writes*, the second unsafe-core family (P7)

The corpus had exactly one unsafe-core family (`raw-ptr`, reads through
`*const i64`). This adds the write half of the unsafe story: **in-place mutation
through a raw mutable pointer** —

```rust
pub fn {name}(ptr: *mut i64, len: usize) -> usize  // returns the number of elements written
```

The model must derive addresses with `ptr.add(i)`, dereference-**assign** under
`unsafe`, and return how many slots it touched — a genuinely different skill from
read-only traversal (aliasing discipline: never read a slot you are about to
overwrite, and the count is part of the contract, not an afterthought).

Two structural axes × four transforms = **16 distinct specs**: which positions are
written (`all` / even indices / odd indices / first half — via start/stride/bound,
same shape as `raw-ptr`) and what is stored (`x*2` / `-x` / `x*x` / `x+1`). The
native `eval` mutates a `&mut [i64]` slice and is the source of truth; the reference
mirrors it through `unsafe`; the differential oracle fuzzes 3000 inputs and compares
**both** the returned count *and* the whole mutated buffer against the safe mirror.

Baselines are two constant-ish cheats: `no_op` (write nothing, return 0) and
`fill_zero` (zero everything, return `len`) — both caught on every seed because the
pinned canonical case `[3,1,4,2]` selects ≥2 positions and every expected output
element is non-zero (pinned across all 16 spec combinations).

Honest caveats:

- **Miri stays deferred**, as for `raw-ptr`: docs/04 weights the category
  behaviour .70 / constraint .30 / quality .00 and renormalises quality away until
  miri lands; correctness of pointer arithmetic here is checked by the differential
  mirror plus the grader's existing checks, not by an interpreter.
- Reference-distance is expected to sit near `raw-ptr`'s low band (pinned-pointer
  interface ≈ fixed scaffold), so view/reference capacity is reported but not gated.
- Like all unsafe-core families there is no clippy constraint layer
  (`check_clippy=false`, `max_unsafe=None`).

```
validate-family raw-ptr-mut: 8 seed(s)
  seed   0..7: OK   determinism=true reference=1.000 skeleton=0.000
                     (behavior 0.000) baselines_caught=true canary=true   [×8]
  anti-twin  view (prompt+skeleton): min=0.313 median=0.435 near-twin pairs (<0.25)=0/28
  anti-twin  reference (solution) : min=0.000 median=0.368 near-twin pairs (<0.25)=6/28
  capacity   view=8+ (asked 8, rejected 0)  reference=10
  spec-diversity: 16 distinct skills (the authoritative task-diversity measure — Q31)
  distinct-skills epoch: served 8 seed(s) covering 8 distinct skills
all gates passed
```

178 workspace tests (+6); clippy `-D warnings` and `cargo fmt --check` clean.

---

## 2026-08-21 · `rustybench report` — the journal → deliverable command (P5)

Built the `report` command docs/08 lists (`report [--format md|json]`), the shape of P5's output: fold a
journal into a formatted deliverable rather than the terse `stats` line.

- **`bench_stats::diagnostics(records)`** (new, pure, core-only per ADR-0009): apply-rate, compile-rate
  (compiled ÷ *applied*), and the **failure-class** and **rustc-error-code histograms** — the signal
  docs/03 calls out as this benchmark's differentiator ("*which part of Rust* a model is weak at"), which
  no general-purpose benchmark produces. `FailureClass::as_str()` added to `bench-core` for the kebab
  histogram keys, and `StatReport`/`CategoryReport`/`ThroughputReport`/`DiagnosticsReport` gained
  `Serialize` for the JSON format.
- **CLI**: `report` renders **md** (headline capability + CI + throughput + pass-rate; per-category table
  with CIs, ICC and the directional-only flag; the diagnostics block; and the honest bootstrap/borrowck-
  lower-bound caveats) or **json** (`{stats, diagnostics}` with the histograms as arrays, radar-ready).
  `html` is accepted-but-declined with a clear message (deferred).

Verified on the real smoke journal (`runs/clean.jsonl`, Qwen2.5-3B): capability 0.336, throughput 53.5
tok/s / 945 units-h / 157 passes-h, and — the new part — **apply 1.000, compile 0.375**, failure classes
`none×5, logic×1, other×1, trait×1`, top codes `E0277×1, E0507×1`. That compile-rate and histogram are
exactly the per-model diagnostic the project exists to publish.

Pure code + fast unit tests (a `diagnostics` aggregate test on synthetic records; `FailureClass::as_str`),
no grading run. 172 workspace tests (+2); clippy `-D warnings` and `cargo fmt --check` clean.

---

## 2026-08-21 · Richer `failure_class` — the diagnostic classifier reaches its dormant classes

docs/03 §L1 specifies `failure_class = classify(error_code, message_pattern, clippy_lints, category)`, but
the code only did an error-*code* lookup. Two enum variants were therefore **unreachable**: `AsyncSend`
(Rust's most characteristic async failure, `future cannot be sent between threads safely`, carries
`code: None` — 18% of realistic failures are codeless, docs/03) and `Idiom` (non-idiomatic code compiles
and passes behaviour, so it produces no code — only clippy sees it). Fixed, in pure `bench-core` logic with
fast unit tests (no grading pipeline):

- **`parse_diagnostics`** (bench-oracle) now also captures the rendered **error-level messages**, not just
  codes and the warning count.
- **`classify_compile_error(codes, messages)`** consults a message-pattern table *before* the code table:
  `… cannot be sent/shared between threads safely` → `AsyncSend`, which also disambiguates the notorious
  `E0277` (it spans four categories) — a Send/Sync bound is upgraded to `AsyncSend`, everything else falls
  through to `Trait` via the existing code table. No pattern match ⇒ identical to the old code-only path.
- **`classify_graded(behavior, clippy_clean, constraint)`** classifies a *compiled* unit: behaviour miss →
  `Logic`; else a clippy violation → `Idiom` (the idiom-refactor signal, ahead of a generic `Constraint`);
  else another constraint miss → `Constraint`; else `None`. Extracted into `bench-core` so it is pure and
  unit-tested rather than inline in the grader.

`bench-oracle::grade` calls both. **No regression**: the twelve non-clippy families never set `clippy_clean`
(→ `None`, so `classify_graded` matches the old Logic/Constraint/None), and no current family emits async
messages (→ code-table fallback unchanged). The immediate win is `idiom-loop`: a behaviourally-correct but
non-idiomatic answer now classifies as **`Idiom`** instead of a generic `Constraint`. `AsyncSend` has no
producing family yet (`async-concurrency` awaits its oracle, Q11) but the classifier is ready and tested,
so it lights up the moment async families arrive.

5 new/updated tests (codeless-async → AsyncSend; E0277 split; code fallback; the graded ordering; messages
captured by `parse_diagnostics`). 170 workspace tests (+4); clippy `-D warnings` and `cargo fmt --check`
clean. Deferred, noted: `diagnostic_completeness` (`full` | `typeck_only`, so borrow failures are published
as the lower bound they are — docs/03) is a natural next field.

---

## 2026-08-21 · The Q14 gate, automated — `clippy --fix` must not solve the instance

Promoted the previous entry's manually-measured Q14 property into a real `validate-family` gate, so it can
never silently regress if `idiom-refactor`'s transform catalogue changes. Q14 requires that a family whose
signal is clippy not be *trivially auto-solvable* by `cargo clippy --fix` — otherwise it measures
transcription, not reasoning.

- `bench-oracle` gains `clippy_fix_remaining_lints(files, allow, limits, ws)`: it materialises the
  model-visible skeleton into a fresh sandboxed workspace, runs `cargo clippy --fix --allow-dirty
  --allow-no-vcs --lib` on it (applying every machine-applicable fix), then re-lints and returns the
  clippy lints that **remain**. Empty ⇒ `--fix` produced clean code ⇒ trivially auto-solvable.
- `validate-family` runs it for clippy-graded families (`check_clippy`) and folds the result into the
  per-seed verdict: the seed fails unless lints survive `--fix`.

Live on `idiom-loop`:

```
seed 0: OK … clippy_fix_safe=true (1 lint(s) survive --fix)
```

Every seed keeps its `needless_range_loop` after `clippy --fix` (the suggestion is not machine-applicable),
so the model must genuinely reason about the iterator rewrite — now proven automatically each run rather
than by a one-off manual spike. A family that accidentally chose a *machine-applicable* lint would fail this
gate loudly (`clippy_fix_safe=false`). The check is a no-op for the twelve non-clippy families. The helper
is exercised end-to-end by `validate-family` (like `grade()` itself, it needs the sandboxed toolchain, so
it has no pure unit test). 166 workspace tests; clippy `-D warnings` and `cargo fmt --check` clean.

---

## 2026-08-21 · Thirteenth family: `idiom-loop` (`idiom-refactor`) — the fifth core category, and the first compositional one

The last uncovered docs/04 core category, and the only **compositional** family: instead of ablating a
reference to `todo!()`, it **de-idiomatises** it. The model is given a working but non-idiomatic function
— an explicit `for i in 0..xs.len()` index loop — and must rewrite it in idiomatic, clippy-clean iterator
style, preserving behaviour. So the ablation is *quality, not correctness*: the given code is
behaviourally correct, and **only clippy distinguishes it** (docs/03: "non-idiomatic code compiles; clippy
catches all of it"). This is the family the previous increment's L3 clippy oracle was built for.

Seed-selected on **filter** (All / Positive / Even / Nonzero) × **map** (Identity / Double / Square /
Negate) — the loop body — folding to a sum, so the idiomatic form is a
`xs.iter().copied()[.filter(…)][.map(…)].sum()` chain. 4 × 4 = **16 distinct skills**. docs/04 weights it
constraint-dominant (behavior 0.30 / **constraint 0.60** / quality 0.10): the constraint *is* clippy, and
`max_unsafe: None` keeps the L3 layer purely clippy.

`validate-family --seeds 8`, all gates green — and the middle column tells the whole story:

```
reference=1.000  skeleton=0.333 (behavior 1.000)  baselines_caught=true  canary=true
view       min=0.274 median=0.383 near-twins 0/28
reference  min=0.222 median=0.545 near-twins 1/28   capacity=38
spec-diversity: 16 distinct skills
```

`skeleton=0.333 (behavior 1.000)` is the point: the de-idiomatised loop is *behaviourally perfect* and is
caught purely by clippy dropping the constraint layer to 0 → composite `(0.30·1 + 0.60·0)/0.90 = 0.333`.
The idiomatic reference is clippy-clean → 1.000. This needed the **validate-family gates generalised** from
behaviour to composite: a degenerate answer is "caught" iff it does not achieve a full pass (composite <
1.0), which now covers the `unchanged` (copy-paste) baseline — behaviourally correct, not idiomatic — as
well as the todo!()-ablated skeletons of every other family (composite ~0, unchanged in practice).

**Q14 (the `clippy --fix` trap) — verified, not assumed.** `idiom-refactor` is only meaningful if it is not
trivially auto-solvable. Measured directly: `cargo clippy --fix` leaves `needless_range_loop` **unchanged**
(its suggestion is not machine-applicable), so the index loop survives `--fix` and the model must actually
reason about the rewrite. And all 16 idiomatic references were checked clippy-clean before authoring, so the
reference reliably scores 1.000. (An *automated* clippy-`--fix` gate in `validate-family` is a sensible
follow-up hardening; today the property is verified by measurement and holds by construction of the
transform.)

Honest consequence, recorded: for `idiom-refactor` the binary `passed()` (Q28) treats the unchanged loop as
a *pass* (it excludes clippy as "quality"), so this category's signal lives in the continuous
`capability_score` (via the 0.60 constraint weight), not in the pass rate. That is a property of Q28's
scope, not a bug — and it is why the family is authored constraint-dominant.

**All five docs/04 core categories are now covered** (`borrow-lifetimes`, `traits-generics`,
`error-handling`, `unsafe-core`, `idiom-refactor`). Registered in `FAMILY_IDS` and the `spec_diversity` pin
in the same commit. 166 workspace tests (+7); clippy `-D warnings` and `cargo fmt --check` clean.

---

## 2026-08-21 · The clippy constraint oracle (L3) — the idiomaticity signal

Built the grading layer `idiom-refactor` needs. docs/03 puts clippy in **L3 constraint** (not L4): non-
idiomatic code compiles and is behaviourally correct, so clippy is the *only* thing that distinguishes it
(docs/03 line 84, "Clippy catches all of it"). The `ConstraintScore.clippy_clean` field already existed but
was never populated; now it is.

- `bench-oracle` `grade()` gains a clippy stage (`GradeSpec.check_clippy` / `clippy_allow`): after L1
  compiles, it runs `cargo clippy --lib --offline --message-format=json` (with `-A <lint>` for any allowed
  lints) on the answer's library only — so the hidden test targets never contribute lints — and parses the
  JSON for `clippy::*` **warning** codes. `parse_clippy_lints` counts only `clippy::` codes, so ordinary
  rustc warnings (unused vars) don't touch idiomaticity; empty ⇒ `clippy_clean = true`, else the lint names
  land in `violations`. It feeds `ConstraintScore` (already averaged into the L3 layer score, weighted by
  the per-category `constraint` weight), and — per Q28 — **not** `passed()`, since clippy is quality, not
  correctness.
- `GeneratedTask.max_unsafe` became `Option<u32>` so a family can opt the unsafe check *out* entirely
  (`None`), keeping the constraint layer clippy-only where `unsafe` is irrelevant (`idiom-refactor`) — and
  this also removes the spurious constraint credit `raw-ptr` used to get from its `u32::MAX` limit (now
  `None`: it grades on behaviour alone, no phantom 1.0 constraint term). All 12 families updated
  mechanically (`Some(0)` / `None`); every existing family's grading is unchanged (none sets `check_clippy`).

Part 1 of two. The clippy stage is dormant until a family enables it — the next entry (`idiom-refactor`)
is its first user and its end-to-end test. Direct coverage here: a `parse_clippy_lints` unit test (clippy
warnings kept, rustc warnings dropped, deduped). 159 workspace tests (+1); clippy `-D warnings` and
`cargo fmt --check` clean.

---

## 2026-08-21 · Generic construction-invariant drift-guard over the whole registry

With twelve families and more coming, added a single `cargo test` that loops over `FAMILY_IDS` and asserts
the **pure** construction invariants for every family — the ones that need no toolchain, so they run in
milliseconds rather than in the slow `validate-family` compile path:

- **determinism** — `generate(seed)` is byte-identical on a re-run (prompt, files, hidden);
- **canary** — the prompt carries its `mint_canary` string;
- **non-empty category** and **non-empty `spec_signature`** per seed, and the instance's `category`
  matches the family's;
- **spec-diversity ≥ 8** — docs/17's "comfortably above a per-epoch seed count of 8", now the public
  `bench_gen::MIN_SPEC_DIVERSITY` floor enforced generically (provisional, like
  `bench_stats::CLUSTER_FLOOR`; the real value is fixed once Phase 4 sets the per-epoch count). Every
  current family clears it with headroom (smallest is 12). This turns Q30/Q31's open "per-family floor"
  downstream note from *unspecified* into *provisionally enforced* — recorded there.

Until now these lived only in each family's own hand-written tests and in the manual CLI gate, so a new
family that simply *forgot* to add a canary or determinism test would pass CI. Now the registry itself is
the checklist: a family that skips any invariant fails `cargo test` the moment it lands in `FAMILY_IDS`.
The compile/differential gates (reference = 1.000, skeleton fails, baselines caught) stay in
`validate-family` — they need the sandboxed toolchain and are too slow for every `cargo test`. Also
refreshed the stale crate-level module doc (it still described "this first P3 increment ... one parametric
family"). 158 workspace tests (+1); clippy `-D warnings` and `cargo fmt --check` clean.

---

## 2026-08-21 · README refreshed + corpus snapshot

Refreshed the README status block, which had drifted to "three families / 71 tests" and listed
`bench-stats` and resume as "still to come" though both have landed. It now states twelve families across
nine categories, 157 tests, the full crate list (with `bench-stats`, previously omitted), the run/run-suite/
stats/status CLI surface, and an honest "still to come" (hardware, the full corpus, `idiom-refactor`'s
compositional archetype, `unsafe-core`'s miri layer, the mined `wild` suite).

The corpus after this session's authoring pass — the run-suite epoch planner serves all twelve
(`--dry-run` confirmed):

| family | category | spec-diversity | ref-capacity | notes |
|---|---|---|---|---|
| window-op | borrow-lifetimes | 12 | 22 | in-place windows; alloc constraint |
| dual-region | borrow-lifetimes | 12 | 6 | `split_at_mut` pairs; alloc constraint |
| error-handling | error-handling | 30 | 7 | parse → validate → `Result` + `?` |
| checked-eval | error-handling | 12 | 10 | checked arithmetic; overflow/guard errors |
| trait-impl | traits-generics | 20 | 1 | implement a trait + associated type |
| generic-select | traits-generics | 16 | 4 | write a generic fn over a trait bound |
| raw-ptr | unsafe-core | 20 | 18 | forced `unsafe` raw-pointer reads (miri deferred) |
| bit-ops | bit-manipulation | 20 | 45 | mask → rotate/reverse/swap |
| str-transform | string-processing | 24 | 56 | filter → case-map → order |
| stack-machine | pattern-matching | 40 | 2 | exhaustive `match` over an enum |
| seq-transform | iterators | 48 | 43 | filter → map → terminal |
| grid-reduce | data-structures | 12 | 31 | 2-D grid reduction |

Every spec-diversity clears any plausible per-epoch seed count (the authoritative Q31 gate). The
ref-capacity column is the honest text proxy, deflated by fixed scaffolding — the pinned-interface families
(`trait-impl` 1, `stack-machine` 2, `generic-select` 4, `dual-region` 6, `error-handling` 7) sit low, the
short-body families (`str-transform` 56, `bit-ops` 45, `seq-transform` 43) high — which is exactly why the
gate is spec-diversity, not reference-distance (docs/17). **4 of 5 docs/04 core categories covered**
(`borrow-lifetimes`, `error-handling`, `traits-generics` at 2 families each; `unsafe-core` at 1); only
`idiom-refactor` is unstarted, pending the compositional/inverse-transform archetype (a framework addition,
not a per-family one — roadmap P3 R2-S6). Docs only; 157 tests, clippy/fmt clean.

---

## 2026-08-21 · Twelfth family: `checked-eval` — a *second* `error-handling` family

Brings the third core category to two families. `error-handling` (#1) is parse-then-validate over
`&[&str]` with plain arithmetic; `checked-eval` tests the sub-skill #1 doesn't — **checked arithmetic and
overflow propagation**. The model implements `fn f(xs: &[i64]) -> Result<i64, MathError>`, folding with a
seed-selected checked reduction and short-circuiting on the first error: a **guard** failure
(`MathError::OutOfRange(x)`) or an **overflow** (`MathError::Overflow`). This is the "don't panic on
overflow, propagate via `checked_*` + `.ok_or(…)?`" skill.

Seed-selected on **fold** (Sum / Product / SumSquares, all `checked_*`) × **guard** (Positive / NonZero /
AtMost(b) / InRange(lo,hi)) = **12 distinct skills**; guard bounds are per-skill constants excluded from
`spec_signature`. The `MathError` enum is pinned in the skeleton (docs/04: error-handling pins the public
error type). Correct-by-construction (ADR-0003): native `eval` and the emitted reference are mirrored
(errors compared as tag strings, as in #1).

**The differential earns its keep here.** It fuzzes values in ±3e9 — wide enough that `Product`/
`SumSquares` overflow — so a model that reaches for plain `*` instead of `checked_mul` *panics* in the
debug build, produces no test summary, and scores 0. The reference is `checked_*` throughout, so it never
panics. `validate-family --seeds 8`, all gates green:

```
reference=1.000  skeleton_behavior=0.000  baselines_caught=true  canary=true  determinism=true
view       min=0.201 median=0.397 near-twins 1/28
reference  min=0.130 median=0.453 near-twins 2/28   capacity=10
spec-diversity: 12 distinct skills
```

Baselines: `const-ok` (`Ok(0)`) is caught by the canonical `[2,3,4]` (valid under every guard → `Ok(v≠0)`);
`no-guard` (folds correctly but omits the precondition) is caught by a constructed guard-failure example.
A test pins both invariants across every (fold, guard) combo. reference-capacity **10** — healthier than
the purely-pinned families because the checked-fold body varies more than a bare plumbing shape.

`error-handling` now has **2 of 40**. Three of the four covered core categories (`borrow-lifetimes`,
`traits-generics`, `error-handling`) sit at 2 families each; only `unsafe-core` (miri-gated) is still at 1,
and `idiom-refactor` (compositional archetype) remains unstarted. Second clippy `enum_variant_names` catch
of the session (the `Checked` prefix — exactly the pitfall just added to doc 17), renamed to Sum/Product/
SumSquares. 157 workspace tests (+6); clippy `-D warnings` and `cargo fmt --check` clean.

---

## 2026-08-21 · Refreshed the authoring guide (doc 17) with the families and lessons

The roadmap calls authoring ergonomics "the highest-leverage work in the project" (an hour spent here pays
back ~270 times). [Doc 17](17-authoring-families.md) had drifted badly — it still opened with "Three
reference families" and named only `window_op`/`error_handling`/`stack_machine`, when there are now
**eleven**. Rewrote it around what the last week actually taught:

- **Archetype table.** The eleven families grouped into five shapes (seed-selected pipeline; in-place +
  alloc constraint; pinned interface; provided-enum match; signature-forced) with the canonical family to
  copy for each — so a contributor picks the nearest template by *shape*, not by reading all eleven.
- **A new "trivial baselines" section** capturing the trap I hit in four families this session: a *shaped*
  baseline (return the sum / the length / the first element) coincides with exactly one real spec and then
  passes on that seed. The fix — Vec output uses `identity`/`empty`; scalar/`Option` output uses two
  spec-independent constants with a canonical proven to avoid them, pinned by a test — is now written down.
- **"Forcing the skill through the signature"** — `raw_ptr` (unsafe unavoidable) and `trait_impl`
  (associated-type/signature match), with the honest miri caveat.
- **The reference-capacity reality**, measured across all families: pinned-interface families sit at 1–7
  (scaffolding dominates the solution text) while short-body families reach 45–56, so reference-distance is
  a diagnostic and `spec_diversity` is the gate — with the actual numbers in the doc.
- **A pitfall for clippy on generator code** (`enum_variant_names`, `needless_range_loop`,
  `unnecessary_literal_unwrap` all fired on first cuts), plus the register-in-three-places drift-guard.

Docs only — `bench-invariants` parses docs 04/07/09, not 17, so no table-arithmetic test is affected; the
workspace stays at 151 tests, clippy/fmt clean. This is the G3 lever kept current while the lessons are
fresh, rather than re-derived by the next author.

---

## 2026-08-21 · Eleventh family: `generic-select` — a *second* `traits-generics` family

Deepening the second core category. `traits-generics` had only `trait-impl` (which pins a trait + driver
and asks the model to *implement* the trait); this exercises the **sibling skill** — the model instead
**writes a generic function bounded by** a pinned trait: `fn f<T: Ranked>(items: &[T]) -> Option<i64>`.
Writing the `<T: Ranked>` bound and the generic body is the skill `trait-impl` does not test. It is also
**selection-shaped, not a fold**, so it reads differently from the reduce/pipeline families.

Seed-selected on **select** (Max / Min / First / Last — which item's `rank()`) × **project** (Identity /
Abs / Double / Square — how the chosen rank is transformed) = **16 distinct skills**; `None` iff empty.
Correct-by-construction (ADR-0003): native `eval` and the emitted reference are mirrored, and the
differential builds `Vec<R>` for a hidden `R: Ranked` and fuzzes 3000 slices against a free reference over
the raw ranks; ranks bounded so `Square` can't overflow. `validate-family --seeds 8`, all gates green:

```
reference=1.000  skeleton_behavior=0.000  baselines_caught=true  canary=true  determinism=true
view       min=0.393 median=0.489 near-twins 0/28
reference  min=0.154 median=0.326 near-twins 9/28   capacity=4
spec-diversity: 16 distinct skills
```

Both trivial baselines are constants — `const-none` (always `None`) and `const-zero` (always `Some(0)`) —
caught on every seed because the canonical ranks `[3, 7, 2, 5]` yield `Some(v)` with `v` neither `None` nor
`0` under all 16 combos (pinned test). Same honest pinned-interface caveat as `trait-impl`: reference-
capacity is **4** (the trait + generic-fn scaffolding dominates the short body), while spec-diversity (16,
the authoritative gate) and view-distance (0 near-twins) both clear the bar.

`traits-generics` now has **2 of its 40** families, testing its two complementary halves (implement a
trait; consume one generically). Two core categories now sit at 2 families each (`borrow-lifetimes`,
`traits-generics`). 151 workspace tests (+6); clippy `-D warnings` and `cargo fmt --check` clean.

---

## 2026-08-21 · Tenth family: `dual-region` — a *second* `borrow-lifetimes` family

With the tractable categories covered, the next corpus goal is deepening the core categories toward their
40-family target (docs/04). `borrow-lifetimes` — the project's flagship core category — had only
`window-op`, so this is its second family, deliberately a **different borrow shape**: a
`split_at_mut`-shaped problem, which docs/04 names explicitly and `window-op` (single-pass window
mutation) does not exercise.

The model implements `fn f(v: &mut [i64]) -> usize`: split `v` at its midpoint into two disjoint halves
and, for each of the `len/2` pairs, apply a seed-selected pairwise op **in place**, returning the count of
pairs transformed. Rewriting a pair `(x, y)` from *both* values at once (e.g. `SumDiff → (x+y, x-y)`) is
the canonical case for `split_at_mut` — you need a `&mut` into both halves simultaneously. Seed-selected on
**op** (Swap / SumDiff / SortPair / AddBoth / DiffBoth / MaxBoth) × **pairing** (Aligned `b[i]` / Mirror
`b[len-1-i]`) = **12 distinct skills**.

It reuses `window-op`'s two load-bearing pieces: the **constraint-dominant weights** (behavior 0.35 /
constraint 0.55) and the **allocation instrumentation** (`alloc.rs` counting `#[global_allocator]`), so a
clone-everything answer — behaviourally correct — is caught by the alloc constraint, which is the whole
borrow-lifetimes signal. Correct-by-construction (ADR-0003): native `eval` and the emitted reference are
mirrored (the differential compares *both* the mutated array and the count over 3000 slices); values
bounded so `SumDiff`/`DiffBoth` can't overflow. `validate-family --seeds 8`, all gates green:

```
reference=1.000  skeleton_behavior=0.000  baselines_caught=true  canary=true  determinism=true
view       min=0.408 median=0.511 near-twins 0/28
reference  min=0.120 median=0.296 near-twins 6/28   capacity=6
spec-diversity: 12 distinct skills
```

The two trivial baselines are `const-zero` (returns 0, no work) and `identity` (returns the correct count
`len/2` but does no work — "counts but doesn't transform"); both are caught because the canonical
`[6, 4, 3, 1]` — first half all greater than second half — is changed with a non-zero count by every one of
the 12 (op, pairing) combos (pinned as a test). Honest note: reference-capacity is **6**, on the low side —
the fixed `split_at_mut` loop scaffolding dominates the short solution text, the same pinned-scaffolding
phenomenon as `stack-machine` (2) and `trait-impl` (1). spec-diversity (12, the authoritative Q31 gate) is
what the family is authored against, and it clears the bar; the view distance (0 near-twins) keeps prompts
fresh. One clippy fix along the way: the native `eval`'s index loop tripped `needless_range_loop`, rewritten
with `enumerate` (the emitted reference keeps the readable index loop — it is a string, graded without
`-D warnings`). `borrow-lifetimes` now has **2 of its 40** families. 145 workspace tests (+8); clippy
`-D warnings` and `cargo fmt --check` clean.

---

## 2026-08-20 · `status` — the resume readout (progress · ETA · segment history) (P4)

The docs/08 CLI lists `rustybench status … # progress, ETA, segment history`; built it, and it doubles as
the real resume readout the run protocol needs. `rustybench status --journal <j> [--epoch <e>]
[--seeds-core N] [--seeds-probe M]` reads a journal and, for the chosen epoch (the most recent one if
omitted), reports:

- **progress** — `done / planned (%)`, computed on the *same* plan/resume path `run-suite` uses
  (`plan_run` + `read_done_keys` + `remaining`), so the number is exactly what a resume would face, not a
  re-derivation that could drift;
- **ETA** — `remaining × steady-state s/unit`, where the pace comes from `bench_stats::throughput`, i.e.
  with the cache-warmth exclusion applied — so a resumed run's cold lead unit doesn't inflate the estimate;
- **segment history** — units and mean s/unit per run session (`seg 0`, `seg 1`, … or `seg —` for
  pre-segment journals);
- **next up** — the first few units `run-suite` would actually execute next (the resume readout proper).

Live on the smoke journal (`runs/clean.jsonl`, a pre-segment 4-family run) reprojected onto today's 9
families at the default 4 core / 1 probe:

```
status: epoch clean-2026-08
  plan      45 units (36 core + 9 probe over 9 families)
  done      12/45  (27%)
  pace      3.8 s/unit (steady-state over 12 timed unit(s))
  ETA       ~2.1m for the remaining 33
  segments:
    seg —: 12 unit(s), mean 3.8 s/unit
  next up (5 of 33): window-op core idx=2 …
```

And on a synthetic two-segment journal the ETA tracks the *steady-state* pace (1.0 s/unit) rather than the
warmup-inflated segment mean (34 s/unit) — the whole point of recording `segment_position`. Honest scope
note: docs/08 keys `status` on a `run_id`, but there is no persisted run-state store yet, so it is keyed on
`--journal`/`--epoch` like every other command here; the readout is identical in substance. A `fmt_duration`
unit test pins the s/m/h humanisation. 139 workspace tests (+1); clippy `-D warnings` and
`cargo fmt --check` clean. That closes the run-protocol-depth items from the overnight brief
(`segment_position`, cache-warmth exclusion, `status`, resume readout).

---

## 2026-08-20 · Run protocol depth — `segment_position` + the cache-warmth throughput exclusion (P4)

Closed the docs/08 refinement flagged as future work in the throughput entry below: *"Exclude the first
N units of each segment from timing aggregates (cache warmth); record `segment_position` on every unit so
this is auditable rather than magic."*

- **Segments recorded.** A *segment* is one `run-suite` session over an epoch (docs/09); a resume starts a
  new one, and its lead units compile against cold caches. `run-suite` now stamps every journalled unit
  with `segment` (one past the highest already recorded for the epoch — computed by `next_segment`) and
  `segment_position` (0-based within the session). The single-unit `run` writes neither (`None` — no
  segment structure), and both fields `skip_serializing_if` empty so a `run` line is byte-unchanged.
- **Cache-warmth exclusion.** `bench_stats::throughput` now drops the first `SEGMENT_WARMUP_UNITS` (= 1,
  a named, tunable constant) of each segment from the timing aggregate: a unit is warmup iff its
  `segment_position` is below the threshold. Units with no position (single `run`, older journals) are
  never excluded, and if the exclusion would empty the timed set (a one-unit segment) it falls back to
  using all — a warm-biased number beats none. It touches **timing only**; capability/pass scoring still
  uses every unit. The report carries `warmup_excluded` and `stats` prints it, so the exclusion is
  auditable rather than magic.

Verified three ways. Backward-compat: `stats` on the pre-segment `runs/clean.jsonl` is unchanged
(12 units, 53.5 tok/s, 945 units/h — no positions, nothing excluded). A synthetic segment with one cold
lead unit (1 tok/s) followed by two warm ones (100 tok/s) reports **"2 executed units … 1 segment-warmup
unit excluded", decode 100.0 tok/s** — the cold unit no longer drags the steady-state number down. A unit
test pins both the exclusion and the one-unit-segment fallback.

Honest note: as the throughput entry below already measured, cache warmth is a *smaller* effect than the
compile-success split (a compiling/passing unit runs the 3000-iter differential ≈1 s; a compile-fail
short-circuits ≈0.1 s). So this exclusion matters most for cross-segment/resumed runs; within one warm
session it moves the number little. It is the right, auditable mechanism regardless. 138 workspace tests
(+1); clippy `-D warnings` and `cargo fmt --check` clean. Still future work: `status`/`resume` readouts
(next).

---

## 2026-08-20 · Ninth family: `str-transform` (category `string-processing`)

More corpus breadth (P7): a text-processing shape. The model implements `fn f(s: &str) -> String` as a
seed-selected three-stage pipeline — **filter** (Alpha / Alnum / NonSpace / All) → **case-map** (Upper /
Lower / SwapCase) → **order** (InOrder / Reversed) = 4 × 3 × 2 = **24 distinct skills**, the widest surface
of the families authored tonight. Everything is ASCII-only by construction (the maps are the `to_ascii_*`
family, the fuzzer draws printable-ASCII bytes 0x20..0x7e), so there are no UTF-8 char-boundary hazards —
the string analogue of the arithmetic families bounding their inputs against overflow.

Solution-first / correct-by-construction (ADR-0003): native `eval` and the emitted reference are mirrored
(`s.chars().filter(…).map(…).collect()`, optional `.rev()`); the differential fuzzes 3000 random ASCII
strings. The two trivial baselines (`identity`, `empty`) are caught on every seed because every case-map is
a genuine transform (never identity) and the canonical example `"Hello, World!"` carries both cases plus
punctuation and a space, so all 24 combinations change it and leave it non-empty (pinned as a test).

Like `bit-ops`, this is a textually-healthy family — the short pipeline body changes visibly with the op,
so all three anti-memorisation numbers agree:

```
view       min=0.257 median=0.446 near-twins 0/28
reference  min=0.273 median=0.536 near-twins 0/28   capacity=56
spec-diversity: 24 distinct skills
```

Registered in `FAMILY_IDS` and the `spec_diversity` pin (== 24) in the same commit. **The corpus now spans
9 families across 9 categories** (`borrow-lifetimes`, `error-handling`, `pattern-matching`, `iterators`,
`data-structures`, `traits-generics`, `bit-manipulation`, `unsafe-core`, `string-processing`) — 4 of
docs/04's 5 core categories, only `idiom-refactor` (the compositional/inverse-transform archetype) still
uncovered. 137 workspace tests (+6); `validate-family --seeds 8` all gates green; clippy `-D warnings` and
`cargo fmt --check` clean.

(Clippy caught an `enum_variant_names` on the first cut — every `Filter` variant was prefixed `Keep`;
renamed to `Alpha`/`Alnum`/`NonSpace`/`All`. The gate earning its keep on generator code, not just on
graded answers.)

---

## 2026-08-20 · Eighth family: `raw-ptr` (category `unsafe-core`) — with an honest miri caveat

`unsafe-core` is docs/04 core #5, and this covers it — bringing core coverage to **4 of 5**
(`borrow-lifetimes`, `error-handling`, `traits-generics`, `unsafe-core`; only `idiom-refactor`, which
needs the compositional/inverse-transform archetype, remains). The model implements
`fn f(ptr: *const i64, len: usize) -> i64`, and **`unsafe` is forced by the signature** — there is no
safe way to dereference a `*const i64`, so a scoring answer must contain `unsafe { *ptr.add(i) }` (or
`from_raw_parts`). That is the genuine article, not unsafe-as-decoration.

Seed-selected on two axes — **access pattern** (Forward / EveryOther / OddIndices / FirstHalf, each a
different pointer-arithmetic walk) × **reduce** (Sum / Product / SumOfSquares / SumOfAbs / SumOfPositives)
= **20 distinct skills**. Solution-first and correct-by-construction (ADR-0003) via *three* mirrors of one
index-walk: the native `eval`, the emitted **unsafe** reference (reads through the pointer), and the
differential's **safe** reference (indexes a slice). The differential passes `xs.as_ptr()` / `xs.len()`
into the model's `f` and compares against the safe reference over 3000 bounded slices; the access-pattern
axis is what makes the patterns behaviourally distinct (each selects a different index *subset*, not just
a different order, so the reductions genuinely differ). `validate-family --seeds 8`, all gates green:

```
reference=1.000  skeleton_behavior=0.000  baselines_caught=true  canary=true  determinism=true
view       min=0.288 median=0.406 near-twins 0/28
reference  min=0.176 median=0.429 near-twins 1/28   capacity=18
spec-diversity: 20 distinct skills
```

Both trivial baselines are constants (`const-zero`, `const-one`) — same reasoning as `trait-impl`: any
*shaped* degenerate (first-element, length) coincides with one real spec on the canonical input `[3,1,4,2]`,
whose answer is provably never 0 or 1 under all 20 combos (pinned as a test, which also checks every
pattern selects ≥ 2 elements).

**The honest caveat, stated loudly rather than buried.** docs/04 makes **miri mandatory** for this
category — "UB = hard behavior failure" — and the miri layer does not exist yet (roadmap P7). Behaviour +
the differential catch *wrong* answers and gross out-of-bounds (a value mismatch, or a crash the sandbox
records), but **not** subtle unsoundness that still returns the right values on the fuzzed inputs (a
provenance violation, say). So today this family grades on behaviour + differential only. It is
correct-by-construction and passes every construction gate now; when miri lands it slots into the empty
constraint slot (the family already carries docs/04's behaviour 0.70 / constraint 0.30 weights). Authoring
the family ahead of its full oracle is the deliberate call — the generator is the long pole, and a
gate-valid `unsafe-core` family in hand is worth more than a placeholder, provided the gap is on the
record. It is.

Registered in `FAMILY_IDS` and the `spec_diversity` pin (== 20) in the same commit. 131 workspace tests
(+6); clippy `-D warnings` and `cargo fmt --check` clean.

---

## 2026-08-20 · Seventh family: `bit-ops` (category `bit-manipulation`)

More corpus breadth (roadmap P7), and a deliberately *low-level* shape — no arithmetic fold anywhere. The
model implements `fn f(x: u32) -> u32` as a seed-selected two-stage bit pipeline: a **mask** (Identity /
KeepLow(n) / KeepHigh(n) / ClearLow(n) / SetLow(n)) then a **transform** (RotateLeft(k) / RotateRight(k) /
ReverseBits / SwapBytes). 5 × 4 = **20 distinct skills**; the width `n` (∈ {8,16,24}) and rotate amount `k`
(∈ 1..=31) are constant parameters of the same skill (Q31), excluded from `spec_signature` along with the
function name.

Solution-first / correct-by-construction (ADR-0003): native `eval` and the emitted reference use the same
`u32` methods (`rotate_left`, `reverse_bits`, `swap_bytes`, mask arithmetic); the differential fuzzes 3000
random `u32`. No overflow is reachable — every shift amount is < 32 and the bit ops wrap by definition,
which is the clean answer to the differential-overflow pitfall (docs/17) that the arithmetic families have
to bound their inputs against.

The trivial baselines are `identity` (returns `x`) and `const-zero` (returns `0`). They are caught on
*every* seed by a structural argument, pinned as a test: every transform is a **bijection that fixes zero**,
and no mask can zero the canonical input `0x9ABCDEF1` (it has a set bit in both the lowest and highest
positions), so the canonical result is provably never `0` and never equal to `x`.

**This family is textually healthy where the pinned-interface families are not** — a useful contrast with
yesterday's `trait-impl`/`stack-machine` entries. Because the solution is a short two-line function whose
*text* genuinely changes with the op (`rotate_left(7)` vs `swap_bytes()` share almost nothing), both text
proxies are high, not just the spec count:

```
view       min=0.392 median=0.500 near-twins 0/28
reference  min=0.400 median=0.750 near-twins 0/28   capacity=45
spec-diversity: 20 distinct skills
```

So the anti-memorisation numbers agree with each other here (view, reference *and* spec all comfortably
clear the floor), which they do **not** for a family whose fixed scaffolding dominates the text. Registered
in `FAMILY_IDS` and the `spec_diversity` pin (== 20) in the same commit. 125 workspace tests (+6);
`validate-family --seeds 8` all gates green; clippy `-D warnings` and `cargo fmt --check` clean.

---

## 2026-08-20 · Sixth family: `trait-impl` (category `traits-generics`) — first uncovered core category

Growing the corpus (roadmap P7, the long pole). The five existing families cover `borrow-lifetimes`,
`error-handling`, `pattern-matching`, `iterators`, `data-structures`; of [docs/04](04-categories.md)'s
five **core** categories, only `borrow-lifetimes` (window-op) and `error-handling` were covered. This
adds **`traits-generics`** — core #2, the clearest uncovered gap.

The distinctive skill is deliberately *not* another fold-shaped problem: the model implements a **trait
with an associated type** for a provided unit struct, consumed by a **generic driver with a where-bound**.
The interface is pinned in the skeleton (like `error-handling` pins its enum): the trait `Aggregate {
type Item; fn keep(&self, &Self::Item)->bool; fn identity(&self)->i64; fn combine(&self, i64,
Self::Item)->i64; }`, the driver `fn drive<A: Aggregate<Item = i64>>(agg: &A, xs: &[i64]) -> i64`, and
the struct are all given; the model writes only the `impl … { type Item = i64; … }` block. Getting the
associated type or a method signature wrong makes the driver's `A: Aggregate<Item = i64>` bound
unsatisfiable, so the hidden tests fail to build and the answer scores **0.0** — which is exactly the
"L1 + signature match" oracle emphasis docs/04 assigns this category, enforced structurally rather than
by a bespoke check.

Seed-selected on two axes — **keep** (Positive / Even / NonNegative / Odd) × **reduce** (Sum / Product /
Count / SumOfSquares / SumOfAbs) = **20 distinct skills**. Solution-first and correct-by-construction
(ADR-0003): native `eval`, the emitted `impl`, and the differential's free reference are mirrored; the
differential fuzzes 3000 random slices (values ∈ -9..=9, len 0..12, so no debug overflow — the tightest
case is `Product` over eleven `9`s ≈ 3.1e10). `validate-family --seeds 8`, all five gates green on every
seed:

```
reference=1.000  skeleton_behavior=0.000  baselines_caught=true  canary=true  determinism=true
spec-diversity: 20 distinct skills
distinct-skills epoch: served 8 seed(s) covering 8 distinct skills
```

**The trivial baselines are both constants — and that is deliberate, not lazy.** `const-zero` (returns 0)
and `const-one` (`identity`→1, keep→false → returns 1). Any *shaped* degenerate (sum-everything, length)
coincides with exactly one real spec and would pass on that seed, so a fixed shaped baseline can't be
universally wrong. The two constants are: the canonical worked example is the fixed input `[2, 3, 4, 5]`,
whose answer is provably never 0 or 1 under any of the 20 combos (a pinned test asserts it, and that every
keep predicate keeps ≥ 2 of its elements), so both baselines fail on every seed.

**Honest caveat, same phenomenon as `stack-machine`.** The pinned interface dominates the text, so the
*text* proxies are low: view-distance median 0.299 with 6/28 near-twin pairs, and reference-capacity **1**
(the trait+driver+impl boilerplate is ~90% of every solution; only three short method bodies vary). That
is the Q31 story again — text distance is deflated by shared scaffolding and is *not* the diversity
measure. The authoritative, ungameable number is spec-diversity = **20**, comfortably above any per-epoch
seed count, and the distinct-skills sampler serves them. Left the low text numbers reported honestly
rather than seed-varying the prompt harder to inflate a proxy (Q31 warns that lift is illusory).

Registered in `bench_gen::FAMILY_IDS` and the `spec_diversity` pin (== 20) in the same commit. 119
workspace tests (+11); clippy `-D warnings` and `cargo fmt --check` clean.

---

## 2026-08-20 · Throughput in `stats` — the second headline number

The project's thesis is two numbers (capability + throughput), but `stats` reported only capability. Folded
throughput in, computed from the journal's `cost` fields.

- `bench_stats::Record` gained a `cost` sub-struct (prompt/completion tokens, `gen_ms`, `grade_ms`), serde-
  defaulted so older journals and synthetic records parse with zero timing.
- `throughput(records) -> Option<ThroughputReport>`: aggregate decode tok/s (completion tokens ÷ generate
  seconds — GPU-bound, so the model/hardware number), per-unit wall (gen + grade), grade share,
  **units/hour**, and **passes/hour** (docs/07's `throughput_score`, counting only scored *core* passes).
  Measured over *every executed unit* (core + probe both cost wall time), so it is computed before the
  core-only filter; `None` when no unit carried timing.
- `stats` now prints both headline numbers; wired into `StatReport.throughput`.

On the clean live run (`runs/clean.jsonl`, Qwen2.5-3B on Metal, VM already gone): **decode 53.5 tok/s,
3.8 s/unit (3.3 gen + 0.5 grade), grade 12% of wall, 945 units/hour, 157 passes/hour.** Matches the
hand-computed numbers exactly.

Test pins the arithmetic on a crafted cost-bearing journal (3 units → 50 tok/s, 1440 units/hr,
480 passes/hr) and that synthetic records yield `None`. Workspace 108; clippy/fmt clean.

Note recorded from the live data: grade time is dominated by whether tests *ran* (a compiling/passing
answer executes the 3000-iter differential ≈1 s; a compile-fail short-circuits ≈0.1 s), not primarily by
cache warmth — so the docs/08 "exclude first-N for cache warmth" refinement (needs `segment_position`) is
a smaller effect than the compile-success split, and is still future work.

---

## 2026-08-20 · Live smoke run (Qwen2.5-3B on Metal) — whole loop end-to-end, and it caught a bug

Ran the full pipeline against a real model for the first time: `llama-server` serving
`Qwen2.5-3B-Instruct-Q4_K_M` on Metal, a 12-unit epoch (`run-suite`, 4 families × 2 core + 1 probe),
then `stats` and `detect`. Resource note: a UTM/QEMU VM was at ~78% CPU, so this is a *capability/plumbing*
smoke — the 3B runs on the free GPU, but grading is CPU-bound and would contend, so throughput is not
reported as meaningful.

Everything ran end-to-end: the model answered every unit, each was graded in the sandbox, journalled with
epoch + core/probe labels, aggregated, and run through the detector. The 3B's honest capability profile:
`iterators` **1.000 / pass 1.0** (both core seeds — it writes concise correct functional code),
`borrow-lifetimes` 0.344, `error-handling` 0.222, `pattern-matching` 0.000; capability **0.392**,
pass-rate 0.25. Detector: not flagged (p=0.5), as expected for an honest run.

**The smoke caught a real correctness bug** — exactly what it is for. `stats` was scoring **12 units
including the fresh probe**, when ADR-0009 says the probe is *never* scored. `iterators` read 0.803 /
pass 0.667 (probe dragging it down) instead of the true core-only 1.000 / 1.000. Fixed: `report_with`
and `compare_models_with` now filter to `kind == "core"` — the one place that rule is enforced for
capability, pass-rate, CIs and ICC. The detector was already correct (it pairs only index-0 core+probe).
Re-ran: 8 scored units, `iterators` 1.000/1.0, capability 0.392. Pinned with a test
(`report_scores_core_only_never_probe`). Workspace 107; clippy/fmt clean. (Smoke journals live under the
git-ignored `runs/`.)

---

## 2026-08-20 · Closed the detector loop — `run-suite` → journal → `detect` verdict

The sign test was a pure statistic with no journal reader; wired it to real journal data, so the
precomputation detector now runs the full loop the run protocol emits.

- `bench_stats::Record` gained `kind` / `index` / `epoch` (serde-defaulted for older journals) so core
  and probe units can be told apart.
- `bench_stats::detect(records, α)`: per epoch, take each family's **pick-one** core bit (the index-0
  core unit — the only collapse preserving the null, Q29.1) and pair it with that family's index-0 fresh
  probe; run the one-sided `sign_test`; return a `DetectorReport` per epoch (families paired, core/probe
  wins, p, flagged). Non-index-0 core units are ignored (pick-one), epochs reported separately.
- CLI `rustybench detect --journal <j>`.

Demonstrated end-to-end on synthesised core+probe journals: a cheater (core passes / probe fails on all 8
families) is **FLAGGED** at p=0.0039 < 0.01 (core-wins 8/0); an honest run (core = probe) is clean at
p=1.0. On real data, `run-suite --seeds-probe N` emits the probe units and `detect` reads them — the
whole ADR-0009 precomputation defence now closes.

3 new tests (flag/clear, pick-one + epoch grouping, empty-when-no-probe); workspace 106; clippy/fmt
clean. The detector fires on real data as soon as a `run-suite` epoch executes against a model.

---

## 2026-08-20 · Run protocol — epoch orchestration with paired-core / fresh-probe + resume (P4)

First increment of the run protocol (docs/08, ADR-0009): serve a whole epoch across all families instead
of one task at a time, resumably.

- **Plan** (`bench_gen::epoch::plan_run`, pure/testable): per family, `n_core` paired-core seeds
  `blake3(epoch ‖ family ‖ i)` (identical for every submitter, scored) + `n_probe` fresh-probe seeds
  `blake3(probe_nonce(epoch) ‖ family ‖ i)` (the detector set, disjoint seed space). `RunUnit` carries the
  family, `UnitKind` (Core/Probe), index and derived seed, and a `key()` for dedup.
- **Resume** (`epoch::remaining` + `read_done_keys`): because units are idempotent (seed determines
  instance and grade), resuming is just "skip units whose `family|kind|index` key is already journaled for
  this epoch". Verified: seeding a journal with two done units drops them from the plan, and a different
  epoch label rotates all core seeds and shares nothing.
- **CLI** `rustybench run-suite --model … --epoch … [--seeds-core N] [--seeds-probe M] [--dry-run]`:
  plans, resume-filters, then runs each remaining unit through the single-unit grade path (extracted as
  `grade_and_line`, now shared with `run`). Journal lines gained `epoch` and `kind`. `--dry-run` prints
  the resume-filtered plan with no model calls — how this increment is demonstrated end-to-end without a
  server.
- `bench_gen::FAMILY_IDS` enumerates the registry (with a drift-guard test that every id resolves), so the
  suite serves all four families.

Demonstrated: a 12-unit epoch (4 families × (2 core + 1 probe)) plans deterministically; resume skips the
two pre-recorded units; epoch `2026-09` rotates every core seed. The only unexercised step is the live
model call, which reuses the same `grade_and_line` path `run` already exercises. 5 new tests (run-plan +
family-id drift); workspace 103; clippy/fmt clean.

Not yet: the variance/determinism probes and calibration segments of docs/08, `status`/`resume`
subcommands, and wiring the fresh-probe journal into the sign-test detector (needs this on real data).

---

## 2026-08-20 · `bench-stats` — ICC estimation (Q29.2) + CI clamping

Added the last piece of the Q29 estimation spec: intra-class correlation.

- **Estimator**: one-way random-effects ICC(1) from unbalanced ANOVA components
  (`icc_components` + `icc_from`), **clamped to [0,1]**. Returns `None` when not estimable — fewer than
  two families, or one seed per family (no within-family df to separate the two variance components).
- **Pooled + shrink**: a pooled ICC is formed by summing components across categories (families compared
  within their own category, so category effects cancel); each category's raw ICC is then
  **empirical-Bayes-shrunk** toward it by between-family df (`w = df_b/(df_b+τ)`, τ provisional). The
  shrink target falls back to the canonical `bench_invariants::ICC` (0.3) when nothing is estimable —
  single source of truth for the design assumption.
- **Diagnostic only**: `icc` and its derived `design_effect = 1+(m−1)·ICC` (floored at 1) are reported
  per category and pooled, but are **never** inputs to a CI — a bad or negative ICC cannot narrow a
  published interval, which was the Q29.2 failure mode. `validate` this via the code path: CIs come from
  the bootstrap, ICC sits beside them.
- **CI clamping**: scores/means/pass-rates live in [0,1] and the pass-rate difference in [-1,1], so a
  studentised percentile-t interval that overshoots the boundary (which it can near a boundary or with
  very few clusters) is reported as its intersection with the feasible set. A 2-family category now shows
  `[0.000, 1.000]` (maximally uncertain, and flagged directional-only) rather than a nonsensical
  `[-0.507, 1.520]`.

`stats` now prints per-category `icc`/`de` and a pooled-ICC line. Tests cover pure-between (ICC=1),
pure-within (ICC=0), and not-estimable (one seed per family → None). 19 crate tests (+4); workspace 98;
clippy/fmt clean. The stats layer's remaining gaps are both Q24-gated: shape-level resampling and
`icc_within_shape`.

---

## 2026-08-20 · `bench-stats` — paired McNemar + precomputation sign test

Added the two paired detectors from the Q29 decisions, plus the exact binomial-tail engine both need.

- **McNemar** (`mcnemar`) on the shared `passed` bits: discordant counts (A-only / B-only), the exact
  two-sided binomial p-value on the discordant split (continuity-corrected χ² reported alongside), and a
  normal-approx fallback above 1024 discordant pairs where `0.5^n` underflows.
- **`compare_models`**: aligns two models' journals by `task_id` (the paired design), runs McNemar, and
  adds a **paired, family-clustered studentised wild-bootstrap CI** on the pass-rate difference — the
  clustered interval doc 07 requires beside the discordant count. Wired as `rustybench compare
  --journal-a --journal-b`.
- **Sign test** (`sign_test`) for precomputation (Q29.1): one-sided upper-tail binomial on the
  `pick-one` core-vs-probe discordant split, flagging when the predictable core beats the fresh probe.
  Default detector α = 0.01 (an accusation wants a low false-positive rate). It is a pure statistic for
  now — it begins running on real data once the epoch protocol emits labelled fresh-probe units
  (ADR-0009).
- Exact-tail helper `binom_cdf_le_half` (stable pmf recursion, normal approx above 1024) with an
  A&S erf; unit-tested against known binomial CDF values.

Demonstrated end-to-end: `compare` over a 6-unit paired pair of journals prints discordant counts, the
exact p, and the Δ pass-rate with its paired CI (correctly *not* significant on 6 units — the tests
prove the significant path on larger synthetic data). 15 crate tests (+5); workspace 94; clippy/fmt
clean.

---

## 2026-08-20 · `bench-stats` — studentised the wild cluster bootstrap (coverage 0.90 → 0.95)

Upgraded the wild cluster bootstrap to the **studentised (percentile-t)** form. Each replicate now
computes not just the sign-flipped mean shift `Δ` but its *own* cluster-robust SE from the flipped
residuals (`e*_g = w_g e_g − n_g Δ`), forming a bootstrap t-pivot `t* = Δ / SE*`; the CI inverts those
t-quantiles: `[μ − SE·q_{1−α/2}, μ − SE·q_{α/2}]`. The t-pivot cancels the small-sample noise in the SE
estimate, which is what the raw percentile form couldn't do.

Re-measured the coverage simulation: **0.953 at G = 12**, essentially nominal 0.95, up from the raw
percentile's 0.90. Tightened the regression bound to ≥ 0.90 to lock the improvement in.

Recorded the honest limit: studentising **degenerates at 2 clusters** — the sign flips that carry the
signal also zero the bootstrap SE — so it is well-defined only above ~12 clusters. That is exactly why
sub-floor categories stay `directional_only`; the between-family-variance test now uses 6 families so it
is well-defined. Removed the now-unused raw `percentile_ci`. `bench-stats` 10 tests; workspace 89;
clippy/fmt clean. doc 07's few-clusters section updated to the studentised method.

---

## 2026-08-20 · `bench-stats` — wild cluster bootstrap (Q29.5)

Replaced the interim resample-families percentile bootstrap with the **wild cluster bootstrap**
(Cameron–Gelbach–Miller), the method the Q29.5 decision named for few-cluster coverage. It precomputes
each family's residual sum `e_g = Σ(y_i − μ)` and, per replicate, flips each `e_g` by an i.i.d.
Rademacher sign: `μ* = μ + (Σ_g w_g e_g)/N`. The replicate distribution carries the cluster-robust
variance, so it holds coverage where resampling few clusters under-covers — and it never manufactures
spread the residuals don't contain (a homogeneous category still gets a zero-width interval).

Validated by simulation, as Q29.5 requires: a new test generates clustered data with a mean-zero
population (cluster effects + within-cluster noise) and checks the 95% wild CI covers 0. **Measured
coverage 0.90 at G = 12 clusters**, up from the naive percentile's 0.84–0.92 under-coverage and close to
nominal 0.95. (Studentising the replicates would tighten it further toward 0.95 — a noted future
refinement.) Also added a test that the wild CI picks up between-family variance (a category split
1.0/0.0 gets a wide interval bracketing 0.5, not a collapsed one).

`bench-stats` now 10 tests; workspace 89; clippy/fmt clean. The `directional_only` flag and simultaneous
per-category α are unchanged — the wild bootstrap improves the interval, it does not change which
categories are rankable.

---

## 2026-08-20 · `bench-stats` — journal → capability, pass-rate, cluster-bootstrap CIs (P4)

With Q28/Q29 decided, built the crate they unblocked. `bench-stats` reads a JSONL journal and computes,
exactly per [07-statistics.md](07-statistics.md):

- **`capability_score`** = equal-weight mean of the per-category means (docs/04), not a pooled mean — a
  small probe category counts the same as a large core one.
- **pass-rate** from the structural `OracleVector::passed()` (Q28), never a threshold on the score.
- **CIs from the cluster bootstrap** (Q29): stratified family resampling (10k), the coarsest cluster
  available until shapes are labelled (Q24), flagged as a lower bound on width. Categories below a
  provisional family floor are marked **directional-only** (the honest home for the few-cluster
  under-coverage). Per-category CIs are **simultaneous** — Bonferroni `1 − α/K` (Q29.4). Deterministic
  RNG so the same journal yields the same CI.

Wired as `rustybench stats --journal <path>`. End-to-end on a synthetic 6-unit / 2-category journal:

```
capability_score = 0.610  [0.300, 0.765]  (95% overall CI, cluster bootstrap)
pass_rate        = 0.333  over 6 units in 2 categories
  borrow-lifetimes   score=0.507 [0.000, 0.760]  pass=0.333  fams=2 units=3  <-- directional-only
  error-handling     score=0.713 [0.600, 0.770]  pass=0.333  fams=2 units=3  <-- directional-only
```

The pass predicate visibly discriminates on real-shaped data: a behaviour-1.0 unit that failed the
allocation constraint, and one that used `unsafe` over budget, both correctly count as **not passed** —
the clone-everything case caught structurally, not by weighting. 8 crate tests; workspace 87; clippy/fmt
clean.

Not yet: the wild cluster bootstrap, shape-level resampling (Q24), ICC estimation, and the paired
McNemar / sign-test detectors — this increment is the load-bearing path those extend.

---

## 2026-08-20 · Q28 + Q29 decided — the pass predicate and the estimation spec

Worked through the two blocking statistical questions with the user and wrote the decisions into code and
[07-statistics.md](07-statistics.md).

**Q28 — the pass predicate is structural, not a threshold.** A task passes iff
`applied ∧ compiled ∧ behaviour == 1.0 ∧ (unsafe_ok ∧ paths_ok ∧ alloc_ok)`, where a constraint the family
did not declare is not a barrier and quality (clippy/fmt, L4) is excluded. Binary, weight-independent
(re-tuning composite weights cannot move pass rates — kills REVIEW-6's swept-cut 23.3% type-I), and
pre-registered because it defines "correct" rather than tuning a cutoff. A clone-everything answer fails
`borrow-lifetimes` by the alloc clause. Implemented as `OracleVector::passed()` in `bench-core` (+2 tests);
the continuous `capability_score` stays the headline, `passed` feeds only the six binary consumers.

**Q29 — the estimation spec, resolved around one reframe:** the published CI is *always* the cluster
bootstrap; the design-effect formula and ICC are sizing/diagnostic only (so a bad/negative ICC can't
narrow a published interval). Decisions written into doc 07:

- **Bootstrap unit = coarsest cluster** — shapes once labelled (needs Q24), family-level and flagged as
  under-covering until then; `idiom-refactor` is crossed → directional-only.
- **Few clusters → wild cluster bootstrap** (Cameron–Gelbach–Miller), coverage validated by simulation;
  categories below a cluster floor are directional-only (fixes the 92%/84% under-coverage).
- **ICC** — variance-components, clamped to [0,1], `design_effect = max(1, …)`, empirical-Bayes shrink
  toward pooled; diagnostic/sizing only.
- **Precomputation sign test → pick-one collapse** (core seed index 0): the only rule preserving the null
  (`any` 100% / `majority` 54% / `pick-one` 4.2% false-accusation).
- **Multiplicity → FWER**: simultaneous radar CIs at 1−0.05/11, Holm for pairwise model comparisons; FDR
  considered and rejected for a public leaderboard.

Both marked DECIDED in OPEN-QUESTIONS. Residual dependencies noted: the shape-level bootstrap and the
per-category cluster floor need the Q24 shape audit; the real ICC needs Phase 3.5. `bench-core` 14 tests.

---

## 2026-08-20 · Fourth family: `seq-transform` (category `iterators`)

A fourth family, authored against [17-authoring-families.md](17-authoring-families.md) with `stack-machine` as the
closest template: the model implements `transform(xs: &[i64]) -> Vec<i64>`, applying a **seed-selected
three-stage pipeline** — Filter (Positive / Even / AboveThreshold(t) / NonZero) → Map (Double / Negate /
Square / AddK(k)) → Terminal (Collect / RunningSum / DedupConsecutive). Native `eval` and the emitted
reference are mirrored one-to-one; the differential fuzzes 3000 random slices (values ∈ -9..=9, length
0..12, so no debug-build overflow); a fixed canonical case `[2, 5, 8]` is changed and rendered non-empty
by **every** combination — including every threshold `t` and constant `k` — so both trivial baselines
(`identity`, `empty`) fail on every seed. The structural surface is 4 × 4 × 3 = **48 distinct skills**,
the widest of the four families; `t`, `k` and the function name are excluded from `spec_signature` (Q31).

```
view       min=0.392 median=0.591 near-twins 0/28
reference  min=0.286 median=0.545 near-twins 0/28   capacity=43
spec-diversity: 48 distinct skills
distinct-skills epoch: served 8 covering 8 distinct skills
```

`cargo test -p bench-gen` — 40 passed (incl. `spec_diversity == 48`); `validate-family --seeds 8` — all
gates green; clippy `-D warnings` and `cargo fmt --check` clean.

---

## 2026-08-20 · Authoring guide (doc 17) + README refresh

With three families now sharing a stable pattern, distilled it into [17-authoring-families.md](17-authoring-families.md):
the `Generator` contract, the solution-first recipe (Spec → native `eval` → mirrored emitted reference →
skeleton → prompt → oracle), the worked-example rule (seed-vary + one guaranteed-non-trivial case), the
view-vs-spec-diversity distinction (Q31), the `validate-family` gate table, and the pitfalls the three
families already hit (`i64::MIN` literals, differential overflow, empty test targets). This is the G3
lever — a contributor copies the nearest of the three references and adapts it. Refreshed the README
status (it still described P0 / 14 tests) to the current 7 crates, 71 tests, three families, macOS
sandbox, and added doc 17 to the read-order table. Docs only.

---

## 2026-08-20 · Third family: `stack-machine` (category `pattern-matching`)

A third family in a new category, to keep testing whether solution-first generation generalises and to
cover a genuinely different Rust skill: an **exhaustive `match` over a provided enum** driving a
`Vec<i64>` stack. The model implements `run(program: &[Op]) -> Vec<i64>`; the `Combine` / `Map` /
`Reorder` operations have seed-selected semantics described in the prompt (5 × 4 × 2). Native `eval` and
the emitted reference are mirrored; the differential fuzzes 3000 random programs; the two baselines
(`const-empty`, `echo-pushes`) are both caught.

`validate-family --seeds 8` — all five construction gates green on every seed (reference 1.000, skeleton
fails, baselines caught, canary, determinism). Numbers:

```
view       min=0.349 median=0.453 near-twins 0/28
reference  min=0.000 median=0.207 near-twins 16/28   capacity=2
spec-diversity: 40 distinct skills
distinct-skills epoch: served 8 covering 8 distinct skills
```

**A recorded surprise that further validates Q31.** I built this family expecting *more* solution
diversity than `error-handling` (whose reference-capacity was 7). On the authoritative measure it has it
— **spec-diversity 40, the highest of the three**. But its *reference*-capacity came out **2**, *lower*
than error-handling's 7, because the fixed `match`/loop scaffolding dominates the solution text even more
than the parse-plumbing did. So the family with the *most* skills has the *lowest* reference-distance
proxy — a third, independent confirmation that reference-distance is a poor diversity measure and that
spec-diversity (the decided gate, Q31) is the right one. Left the honest number in the module doc rather
than tuning the family to make a misleading proxy look better.

Three families now span three categories (borrow-lifetimes, error-handling, pattern-matching) and three
distinct task shapes; solution-first generation holds for all three. 71 workspace tests; clippy/fmt
clean.

---

## 2026-08-20 · Epoch sampler serves distinct *skills* (Q31 follow-on)

The Q31 decision left one piece unbuilt: the epoch sampler served on view-distance, which post-finding is
near-vacuous, so within an epoch it did not guarantee distinct *skills* — it could spend several of its
`n` slots on the same skill with different constants. Built `plan_epoch_distinct_skills`: it rejects a
candidate whose `spec_signature` is already served (the point — cover different skills), and still
enforces view-distance for prompt freshness (contamination). It `Exhausted`s once the family's distinct
skills run out.

- `EpochPlan` now carries the served `specs` and a `distinct_skills()` count.
- A test cross-checks the serve-path against `spec_diversity`: asking window-op for 13 distinct skills
  exhausts at exactly **12**, its diversity. Plus determinism and unique-specs tests.
- `validate-family` demonstrates it: "distinct-skills epoch: served 6 seed(s) covering 6 distinct skills".

This surfaced a **new tension for Phase 4 / P3.5**, recorded under Q31: "one seed per skill per epoch"
maximises coverage, but the ICC / repeated-measures design may want *several* seeds of the same skill to
estimate within-skill variance. Different serving policies for different purposes; likely an epoch covers
distinct skills while a separate repeated-measures pass samples same-skill seeds. Not settled here — and
neither planner is wired into a run protocol yet, because there is no run protocol yet. 66 workspace
tests; clippy/fmt clean.

---

## 2026-08-20 · Q31 decided — spec-diversity as the authoritative task-diversity measure

Acting on the Q31 finding (previous entry), and on the "two gates" decision: added a
`spec_signature(seed)` method to the `Generator` trait — the structural choices that define the *skill*,
with numeric constants and identifiers excluded — plus `spec_diversity(gen, n)` counting distinct
signatures. That count is now the authoritative, ungameable diversity number, reported by
`validate-family` and pinned as a regression test.

Granularity: `AtMost(10)` and `AtMost(50)` share a signature (same skill, different constant); constants
still vary the prompt so they still count under the view (contamination) gate, they just don't inflate
diversity. Measured and pinned:

- `window-op`: **12** distinct skills (6 in-place ops × 2 strides)
- `error-handling`: **30** distinct skills (5 combines × 6 rule-types)

Both clear any plausible per-epoch seed count, and — unlike the text proxies — these numbers can be
neither inflated by example noise nor deflated by shared boilerplate. `validate-family` now prints, per
family: view-distance, reference-distance, view/reference capacity, and spec-diversity — the full honest
picture in one place. Q31 marked decided; the per-family diversity *floor* stays open (it depends on the
Phase-4 per-epoch seed count) and folds back into Q30. 63 workspace tests; clippy/fmt clean.

---

## 2026-08-20 · Widened `window-op` — and it exposed that the anti-twin metric is unreliable (Q31)

Set out to raise `window-op`'s tight capacity (8) with the same lever that "fixed" `error-handling`:
two new in-place ops (`Negate`, `AddConst(k)` — chosen because they change every generic window, so the
`identity` baseline stays caught; `Min`/`Max` avoided for the `i64::MIN` literal landmine) plus
seed-varied worked examples. All construction gates stayed green.

**Then measuring capacity two ways broke the earlier story.** The epoch sampler measures distance on the
prompt+skeleton — what the model sees. Seed-varying the examples makes every prompt textually distinct
*without changing the task*, so `window-op` saturated: 100 % of raw-index seeds accepted, view-capacity
effectively unbounded. Measuring on the **reference** (the solution) instead told the truth:

| family | view near-twins | view-capacity | reference near-twins | reference-capacity |
|---|---|---|---|---|
| window-op | 0/28 | saturated | 1/28 | **22** |
| error-handling | 0/28 | ~250–326 | **12/28** | **7** |

So `error-handling`'s "3 → 326" win from the previous entry was mostly illusory — its genuine
solution-diversity is **7**. View-distance over-counts (gameable by example noise); reference-distance
under-counts (deflated by shared boilerplate). Neither is task diversity, which is the structural spec
count. Written up as **[Q31](OPEN-QUESTIONS.md)** (BLOCKING) with three options; the honest correction is
recorded against Q30 and doc 04 too, rather than quietly overwriting the earlier numbers.

Changes made in response, all honest-by-construction:
- `validate-family` now prints **both** view- and reference-distance lines and **both** capacities, so
  the gap is visible in CI. Live: window-op `reference min=0.146 cap=22`; error-handling
  `reference min=0.094 near-twins 12/28 cap=7`.
- `bench_gen::epoch` gained `greedy_distinct_count` and `reference_capacity` (public, documented with the
  over/under-count caveats).
- Capacity regression tests re-pinned to **reference**-capacity: `window_op_reference_capacity_is_healthy`
  (≥18) and `error_handling_reference_capacity_is_low_by_design` (5..=12, a documented limitation, not a
  bug). New `view_distance_saturates_but_reference_distance_does_not` pins the Q31 finding itself.

`window-op` keeps the two new ops (genuine solution diversity, reference-capacity 22) and the seed-varied
examples (contamination-resistance). 62 workspace tests; clippy/fmt clean. The epoch sampler still serves
on view-distance — post-finding that means it rarely rejects, so which basis it should serve on is part
of the Q31 decision.

---

## 2026-08-20 · Widened `error-handling` (Q30 lever 2): capacity 3 → ~326

The sampler flagged `error-handling`'s distinct-at-floor capacity as **3** — unusable, below any
per-epoch seed count. Acted on it directly (Q30 lever 2: enlarge the variable surface):

- **Combine operations 3 → 5**: added `Count` (`acc + 1`) and `SumSquares` (`acc + n*n`). `Min`/`Max`
  were deliberately *not* added — their `i64::MIN` identity has no safe negative-literal form, and the
  emitted reference/tests print literals.
- **Validation rules 3 → 6**: added `AtLeast(b)`, `InRange(lo,hi)`, `Even`. Counting bound choices that
  is 12 distinct rule-instances, so 5 × 12 = 60 combine/rule logics (up from ~9).
- **Seed-varied worked examples**: the examples in the prompt and skeleton are now generated per seed
  (two varied numeric cases + a constructed rule-failure + a parse-failure + empty), where before they
  were four fixed lists. This also fixes a real gap — the old examples never illustrated a *rule*
  failure. Native `eval` and the emitted source stay mirrored, so the reference-passes and differential
  gates still hold.

Verified end to end — `validate-family --family error-handling --seeds 8`, all gates green:

```
reference=1.000  skeleton_behavior=0.000  baselines_caught=true  canary=true  determinism=true
anti-twin (prompt+skeleton): min=0.287 median=0.438 near-twin pairs (<0.25)=0/28
epoch sampler: served 8 pairwise-distant seed(s) (rejected 0 collision(s), min=0.287)
```

| `error-handling` | median | near-twins | distinct-at-floor capacity |
|---|---|---|---|
| before | 0.263 | 18/45 | 3 |
| after | **0.438** | **0/28** | **~326** |

**Honest caveat.** ~326 is *view*-capacity, and part of the lift is example-text variation that the
shingle metric rewards. That legitimately freshens prompts against exact-text recall but is not skill
diversity; the genuine distinct-logic surface is the 60 combine/rule combinations. Both clear any
per-epoch seed count, and acceptance ran ~22% (not ~100%), so it is not pure metric-gaming. The capacity
regression test was re-pinned to a stable lower bound (`error_handling_capacity_clears_a_per_epoch_count`,
seats 50) rather than the RNG-sensitive exact figure; `window_op_capacity_at_floor_is_8` stays exact
(window-op is a true structural ceiling). 61 workspace tests; clippy/fmt clean.

---

## 2026-08-20 · Distance-aware epoch sampler (Q30) — and it measured a hard capacity ceiling

Built `bench_gen::epoch`, the Q30 second-order fix: a run must not *serve* two near-twins even when a
family's average distance is healthy. `plan_epoch` draws candidate seeds in order and rejects any whose
model-view is closer than the floor to an already-accepted sibling, so the seeds it serves are
pairwise-distant by construction. It is deterministic in `(family, epoch, n, threshold)` — replay-safe —
and measures distance on the exact `view_of` string the CI gate uses, so a plan that clears the floor
here clears the gate. If a family cannot supply the requested count it returns `Exhausted` rather than
serving a twin. `MIN_INSTANCE_DISTANCE = 0.25` is now a named constant both the sampler and
`validate-family`'s near-twin gate read, so they cannot drift.

**Running it turned the soft near-twin count into a hard ceiling — the finding.** The sampler's
*distinct-at-floor capacity* (most pairwise-≥0.25 instances a family can seat) is far below what the
median implies, because pairwise-mutual distance is a much stronger constraint than average distance:

| family | median | near-twin pairs | **distinct-at-floor capacity** |
|---|---|---|---|
| window-op | 0.433 | 7/45 | **8** |
| error-handling | 0.263 | 18/45 | **3** |

`error-handling`'s capacity of **3** is below any usable per-epoch seed count: as designed it cannot
outlast repeated epochs without repeating an instance, so Q30's "enlarge the variable surface" lever is
effectively forced for it. `window-op`'s 8 is workable but tight. Both capacities are pinned as
regression tests (`window_op_capacity_at_floor_is_8`, `error_handling_capacity_at_floor_is_3`) so a
family change that moves them fails loudly rather than silently degrading anti-memorisation.

`validate-family` now closes the loop in one output: it reports median/near-twins (detection) **and**
the sampler's capacity (prevention). Live:

```
window-op:       near-twin pairs (<0.25)=7/45   · epoch sampler: capacity 8 … enlarge the variable surface (Q30)
error-handling:  near-twin pairs (<0.25)=18/45  · epoch sampler: capacity 3 … enlarge the variable surface (Q30)
```

Docs updated: Q3/Q30 (capacity table + the "capacity is the real ceiling" reframing),
[02-task-format.md](02-task-format.md) (distinct-at-floor capacity as the measure families are authored
against), [04-categories.md](04-categories.md) (`error-handling` capacity 3 → must be enlarged before it
ships). 7 new tests; workspace 59 tests; clippy/fmt clean.

---

## 2026-08-20 · Folded the Q3 variance finding into the design docs

The second-family measurement (below) produced a design-level conclusion that lived only in this build
log. Promoted it into the durable specs so the 272-family plan carries it:

- **[Q3](OPEN-QUESTIONS.md)** marked *partly resolved*. Records the settled half — solution-first
  seeding generalises in **correctness** across two different-shape families (both pass all five
  construction gates on every seed) — and the unsettled half: it does **not** generalise automatically
  in **variance**. Carries the distance table (`borrow-lifetimes` 0.433 / 7-of-45 vs `error-handling`
  0.263 / 18-of-45).
- **[Q30](OPEN-QUESTIONS.md)** opened for the mechanism the finding leaves undecided: anti-twin
  variance is per-family, not global, so a single `min_instance_distance` means different things across
  categories. Two prevention levers stated (per-category floor vs. forced variable surface), plus the
  second-order epoch-seed-collision problem and its fix (a distance-aware epoch sampler).
- **[02-task-format.md](02-task-format.md)** gained "Varying the four axes is necessary, not
  sufficient" — the rule that variance is measured per family, and that clearing the floor *on average*
  does not clear it *pairwise*.
- **[04-categories.md](04-categories.md)** notes that pinning the error enum makes `error-handling`
  correct-by-construction but naturally low-variance, cross-linking Q3/Q30.

No code changed; `bench-invariants` still green (the edits are prose, not stats-table cells).

---

## 2026-08-19 · P3 — second family (`error-handling`): seeding generalises, and two oracle bugs it caught

**The question this answers.** The docs' biggest open risk (Q3, R2-S6): does
solution-first seeding generalise beyond `window-op`'s in-place-mutation shape,
or collapse to cosmetic variation? A second family in a genuinely different
shape settles it.

**`error-handling`** (category `error-handling`): parse `&[&str]` into `i64`,
validate each against a seed-selected rule (non-negative / at-most-N / non-zero),
combine with a seed-selected operation (sum / product / sum-of-abs), returning
`Result<i64, ParseError>` with `?` propagation. Different machinery entirely —
error paths, a custom enum the model must keep, string parsing. Its constraint is
error-handling-specific: **no `.unwrap()` / `.expect()`** (propagate, don't
panic), which needed the AST forbidden-path check extended to match *method
calls*, not just type paths.

**Verdict: seeding generalises.** All five construction gates pass across every
seed — reference 1.000, skeleton fails, both trivial baselines caught (including
the `.unwrap()` one, proving the extended AST check), canary present, determinism.
The reference-passes-its-own-oracle gate confirms the generator is self-consistent
for this shape too.

**But the anti-twin numbers are a real, quantified caveat:**

| family | min | median | near-twins |
|---|---|---|---|
| window-op | 0.122 | 0.433 | 7/45 |
| **error-handling** | **0.042** | **0.263** | **18/45** |

Error-handling instances are markedly *more similar* — median 0.263 vs 0.433,
barely above the near-twin threshold. The cause is structural: the shared
boilerplate (the `ParseError` enum, the parse-propagate skeleton, the constraint
list) dominates the prompt, so the seed-varied part (op + rule) is a small
fraction of what the model sees. **Solution-first seeding generalises in
correctness but not automatically in variance** — a family with heavy fixed
scaffolding needs a larger variable surface, or a per-category anti-twin
threshold. That is a concrete design conclusion for the 272-family plan, and it
is the honest answer to Q3: *yes, but variance must be designed for, not
assumed.*

**Two oracle bugs, both found by running the second family — not by review.**

1. **Score inflation on non-conforming answers.** The live 3B rewrote the
   provided enum as *private* and dropped `#[derive(PartialEq)]`. The lib still
   compiled (a private enum is legal), so L1 passed — but the behaviour and
   differential test targets could not build against it (`E0603`, `E0369`), so
   they produced no summary, which the oracle recorded as `None`. The composite
   then renormalised over the *remaining* layers and scored the broken answer
   **1.000**. Fixed: a configured test that yields no summary is a **failure
   (0.0)**, never absent, and flags `behavior:no_summary` / `differential:no_summary`.
   The same answer now scores **0.222** — behaviour 0, with only the style
   constraint contributing. (That 0.222 for a non-functional-but-tidy answer
   reinforces the Q28 "should behaviour be a hard floor" question already on
   file; it is the documented weighting, not a new bug.)
2. **Empty test target treated as configured.** A family opts out of the alloc
   layer by leaving its target blank; the CLI wrapped `""` as `Some("")`, so the
   oracle ran `cargo test --test ""`, failed, and (after fix 1) scored it a
   constraint failure — which broke `error-handling` validation. Fixed: empty
   target → `None`.

Window-op could not have surfaced either: its answers conform to a fixed
signature with no enum, so the interface-mismatch path was never exercised. This
is precisely why a second family of a *different shape* was the right next step.

52 tests across seven crates; clippy clean under `-D warnings`; fmt clean.

---

## 2026-08-19 · P3 — anti-twin distance + trivial-baseline gates

**What.** The gate that actually tests the project's central claim — that
generated instances resist memorisation — plus two more construction gates, and
a strengthened `window-op`.

`window-op` gained a fourth operation (RotateRight(k)) and a **stride** modifier
(every window / every other window), taking the distinct-logic space from 3 to
~16, so a seed now varies genuinely different logic. The reference-passes gate
confirms every one of these still grades to 1.0 — a buggy new variant would have
been caught there.

`validate-family` now runs **five gates** per seed and reports the anti-twin
distance:

```
seed 0..9: OK  determinism=true reference=1.000 skeleton_behavior=0.000 baselines_caught=true canary=true
anti-twin (prompt+skeleton): min=0.122 median=0.433 near-twin pairs (<0.25)=7/45
```

- **Trivial-baseline gate** — `const-zero` and `identity` (right signature, wrong
  body) must each fail. They do: the oracle is not fooled by a right-shaped
  answer. This is the check that a family's oracle is not trivially beatable.
- **Canary gate** — the prompt carries its per-instance canary.
- **Anti-twin distance** (normalised token-shingle Jaccard over prompt+skeleton,
  the R4-S4 metric): reported, not hard-gated, because a finite task space
  eventually collides by pigeonhole. The useful signals are the *minimum*
  distance and the near-twin count.

**The measurement earns its keep immediately.** Median 0.433 says most seed-pairs
are genuinely different tasks — the anti-memorisation property holding. But
**7 of 45 pairs are near-twins** (min 0.122): two seeds landing on the same
(operation, stride) produce prompts differing only in the function name. That is
a real, quantified limitation of a ~16-variant family, and it drives a design
conclusion the docs should absorb: **an epoch's N seeds within a family should be
chosen (or the structural axis derived from the seed index) to guarantee N
distinct variants**, rather than trusting independent hashing not to collide.
The gate turned "does generation resist memorisation?" from an assertion into a
number.

47 tests across seven crates; clippy clean under `-D warnings`; fmt clean.

---

## 2026-08-19 · P3 (first increment) — bench-gen: seeded solution-first generation

**What.** The pivotal phase begins: tasks stop being frozen files and become
**seeded generators**. A family is a function from a seed to a fresh instance,
its reference, its oracle, and the skeleton — all built from the same seed,
solution-first, so the oracle is correct by construction (ADR-0003).

`bench-gen` provides seed derivation (blake3), canary minting, a SplitMix64 PRNG
(pure in the seed), the `Generator` trait, and one real family: **`window-op`**
(category `borrow-lifetimes`). Crucially the *operation itself* is seed-selected
— Reverse / RotateLeft(k) / SwapEnds — so a seed changes the logic a model must
write, not just identifiers. From the sampled op the generator derives the
reference source, the worked example outputs (computed natively so they are
correct), the differential oracle (embedded reference + generated inputs), the
alloc test, and the ablated `todo!()` skeleton.

**`rustybench validate-family` runs the construction gates** (ADR-0003), over
every seed and with no model:

```
seed   0..7: OK  determinism=true  reference=1.000  skeleton_behavior=0.000
all gates passed
```

- **Determinism** — same seed → byte-identical instance.
- **Reference passes its own oracle (1.000)** — the synthesised reference,
  graded through the *full* pipeline (compile · behaviour · differential ·
  alloc · unsafe), scores perfect. This is the load-bearing self-consistency
  check: reference, example outputs and differential all agree, so a buggy
  generator is caught here, not in the field.
- **Skeleton fails (behaviour 0.0)** — the ablation genuinely removed the answer.

**Full loop against the live 3B, on tasks it has never seen.** `rustybench run
--family window-op --seed N` generates → prompts the model → grades under the
sandbox. Two seeds, genuinely different operations:

```
seed 3  op=reverse       fn=rework_segments  score 0.751  unit 0.6  diff 0.0  logic
seed 5  op=rotate_left(3) fn=map_frames       score 0.751  unit 0.6  diff 0.0  logic
```

Different operations and names — the anti-memorisation property. The 3B wrote a
windowed reverse whose `(w..v.len()).step_by(w)` loop **misses the last full
window** — a real off-by-one, caught partially by the unit tests (3/5) and fully
by the differential oracle (which is exactly why the differential oracle exists).
The identical 0.751 is coincidental.

**Scope of this increment:** one parametric family, three construction gates. Not
yet: the compositional archetype, the anti-twin distance gate, the remaining
`validate-family` checks (trivial-baselines-fail, prompt has one canary), and the
seed→instance server issuance the integrity model needs. 43 tests across seven
crates; clippy clean under `-D warnings`; fmt clean.

---

## 2026-08-19 · bench-invariants — the doc-arithmetic CI gate (round 6's ask)

**What.** Round 6 asked for "one script that recomputes every published table
from its stated formulae and fails CI on a hand-edited cell", because the same
defect class recurred across three rounds: R1-S1 (statistics tables
arithmetically wrong), round 5's arithmetic block, and R6-S1/R6-S7 (`standard`
published two different CIs for one quantity). This is that gate.

`bench-invariants` holds the canonical parameters (corpus 5×40 + 6×12, ICC 0.3,
per-suite seeds, the timing split) and the formulae (`design_effect`, `ci_pct`,
the stratified `overall_ci`, `F/ICC` ceiling) in **one place**. Four tests parse
the actual markdown tables in `07-statistics.md` and `04-categories.md` and
assert every cell follows from the math: suite families/seeds/units, pooled
eff N, overall CI, per-category CIs, and wall-clock hours (unit-aware — smoke is
in minutes); the 272 = 248 + 24 corpus split; the 44.5-hour headline (with a
guard that a stale "39 hour" cannot reappear); and the precision ceiling.

**Proven both directions.** Passes clean on the current docs. Then I corrupted
`deep`'s overall CI to **±4.1%** — which is *exactly* the stale pre-R6 value —
and the gate failed with `deep overall CI: doc says 4.1, formula gives 4.8542`.
It catches the precise drift round 6 found, and it runs under the normal
`cargo test`, so a hand-edited cell now breaks CI.

The canonical model is now the source of truth: when Phase 3.5 measures ICC, it
changes in `bench-invariants` and every doc table must move with it or the build
fails. 36 tests across six crates; clippy clean under `-D warnings`; fmt clean.

---

## 2026-08-19 · P2 — L3 `syn` AST checks: unsafe counting + forbidden paths

**What.** The structural L3 constraints, done on the parsed tree via `syn`, never
by grepping text (docs/03). A new `bench-oracle::ast` module — also the parsing
machinery P3 generation reuses — exposes `count_unsafe` (every `unsafe {}` block
and `unsafe fn`, free or impl method) and `find_forbidden_paths` (any path
segment matching `RefCell`, `transmute`, … regardless of import style). Tasks
declare `[constraint] max_unsafe` and `forbidden_paths`; `ConstraintScore` gains
`unsafe_ok` / `paths_ok` and the raw `unsafe_blocks` count.

**Demonstrated.** `split-mut-window` now sets `max_unsafe = 0` — solving a
borrow-checker task with raw-pointer `unsafe` sidesteps the very skill it probes.
An `unsafeptr` answer (correct, zero-alloc, but `unsafe { std::ptr::swap(...) }`):

```
unsafe_blocks: 1, unsafe_ok: false, violations: ["unsafe: 1 usage(s), limit 0"]
score 0.694  failure=Constraint
```

Behaviour is perfect (1.0) and it does not allocate — the unsafe is invisible to
L1/L2/L3-alloc. Only the AST check sees it. You cannot hide `unsafe` from the
parse tree.

**A calibration finding, logged not smoothed over.** Adding the unsafe check
*raised* the clone-everything score from **0.389 to 0.694**. Both `clone`
(allocates, no unsafe) and `unsafeptr` (no alloc, uses unsafe) now score 0.694 —
each violates exactly one of the two constraint checks, and the layer is their
**mean** (docs/03). So mean-aggregation gives a cheating solution half credit for
the constraint it happened *not* to violate, which **partially undoes the
constraint-dominant weighting the S6 fix relied on** — the more constraint
checks a task has, the more a single-constraint violation is diluted. This is a
real design question: for a category where every constraint expresses the same
"respect the borrow checker" intent, the layer arguably wants **min** (worst
violation) or per-check weights, not mean. Filed for P2-proper alongside the
pass-predicate decision (Q28); it is the same class of question — how strict the
aggregation should be. The machinery is correct; the aggregation policy is the
open call.

32 tests across five crates; clippy clean under `-D warnings`; fmt clean.

---

## 2026-08-19 · P1 — bench-sandbox: wall-clock timeout + rlimits

**What.** Finishes the sandbox's resource controls. Model code that spins,
hangs, or fork-bombs is now stopped by a **harness-owned wall-clock timeout**,
with `RLIMIT_CPU` as a far backstop. Every cargo stage runs under it.

**Mechanism (Unix).** The child leads its own process group (`process_group(0)`),
so on the deadline the whole tree — cargo → rustc → the test binary — is killed
with `kill(-pgid, SIGKILL)`, not just the direct child. `setrlimit` runs in a
`pre_exec` hook and inherits to every descendant. Stdio is captured to temp files
so a full pipe can't deadlock the manual wait loop. `--wall-timeout-secs` makes
the deadline harness-owned and suite-tunable (docs/08: never submitter-set).

**Demonstrated.** An `infiniteloop` answer (`loop {}`) compiles, then every test
stage hangs; at `--wall-timeout-secs 5` all three are killed and recorded:

```
score 0.000  failure=Logic
flags: timeout:test, timeout:differential, timeout:alloc
```

The journal carries the `flags` (docs/12, R6-S8: a timeout is a *flag*, not a
failure class). Normal cases are unaffected — pass 1.000, subtlebug 0.844.

**A real bug, found by running it — not by review.** The first cut tied
`RLIMIT_CPU` to the wall value. The behaviour stage runs **five tests on five
threads**, so it accumulated CPU 5× faster than wall time and was killed by
`SIGXCPU` at ~1s — *before* the wall clock — so that kill was **not** recorded as
a timeout (its flag was silently missing while differential/alloc, single-test,
raced to the deadline and were flagged). The fix decouples the CPU limit to a
generous backstop (`wall × 30`) so the **wall clock is always the primary
control** for any realistic thread count. A single flat `RLIMIT_CPU == wall`
would have shipped a sandbox that under-reports timeouts on exactly the
multi-test stages that matter. Escape tests (`wall_timeout_kills_runaway`,
`normal_command_does_not_time_out`) now cover it in CI.

**Still deferred:** `RLIMIT_AS` is opt-in (macOS enforces it unreliably); Linux
netns and Windows job objects remain the cross-platform gap.

---

## 2026-08-19 · P1 (partial) — bench-sandbox: containing model-authored code

**What.** Until now the oracle ran arbitrary model-authored Rust under plain
`std::process::Command` — no containment. `bench-sandbox` closes that. Every
`cargo` invocation the oracle makes (compile, since proc macros run at *build*
time, and every test binary) now routes through one `run` seam.

**macOS (implemented, tested here).** A seatbelt profile via `sandbox-exec`:
permit by default, then subtract the two things that matter —

- **network denied** (`deny network*`): the documented Terminal-Bench "agent
  fetched solutions online" threat; and
- **writes confined** (`deny file-write*` + allow only the workspace, cargo
  caches, and temp): model code cannot write or delete outside the grading
  workspace — no `rm -rf ~`.

Reads stay broad because the toolchain needs them and reads are not the threat.
The profile was found empirically: a clean `cargo build`/`test` of the frozen
task runs fine under it.

**The escape tests are the proof, and they run in CI.** From inside the sandbox:

| probe | sandboxed result |
|---|---|
| `TcpStream` connect to 1.1.1.1:80 | **blocked** (`Operation not permitted`) — reaches it unsandboxed |
| write to `~/rb-escape-probe.txt` | **blocked** |
| write inside the workspace | allowed (grading must still work) |

**Grading is identical under containment** — pass 1.000, subtlebug 0.844, clone
0.389, byte-for-byte the same as before the sandbox. The containment contains
without perturbing the measurement.

**Recorded for integrity.** The journal now carries `sandbox: "seatbelt"` (or
`"unsupported"`), and the CLI prints `[sandbox: seatbelt]`. A leaderboard must
know whether model code was contained (docs/10).

**Linux / Windows: honestly not yet.** `available()` returns `Unsupported` and
`run` executes uncontained with a loud warning and an `unsupported` journal flag.
The netns (Linux) and job-object (Windows) paths are the remaining P1 work; the
crate never pretends to contain what it cannot. Also deferred: rlimits
(address-space / CPU-time / pid caps) and the harness-owned wall-clock timeout.

---

## 2026-08-19 · P2 (partial) — L2 differential sub-oracle

**What.** The other half of the P2 exit criterion: *"a deliberately-wrong-but-
tests-passing solution is caught by the property oracle."* The hidden oracle
ships a differential target (`tests/differential.rs`) carrying a known-correct
reference and a seeded LCG generator; it compares the candidate against the
reference over 3000 inputs including widths ≥ 3 that the example tests never
exercise. `behavior.score` now combines unit + differential with the docs/03
weights (unit 0.3 / property 0.5 / differential 0.2, renormalised over those
present). No external crate — the LCG keeps grading deterministic and offline;
`proptest` is the P2-proper upgrade once dep-vendoring is set up.

**The headline, measured end to end:**

| response | unit | differential | behavior | constraint | score | failure_class |
|---|---|---|---|---|---|---|
| correct | 1.0 | 1.0 | 1.0 | ok | **1.000** | none |
| **subtlebug** (swaps only window ends) | **1.0** | **0.0** | 0.6 | ok | **0.844** | **logic** |
| clone-everything | 1.0 | 1.0 | 1.0 | fail | 0.389 | constraint |
| logic-fail (whole-slice reverse) | 0.2 | 0.0 | 0.12 | ok | 0.658 | logic |

The `subtlebug` row is the point. It passes **all five example tests** — a
`unit` of **1.0**, a perfect score under any unit-only oracle — but it only
swaps the first two elements of each window, so it is wrong for every width ≥ 3,
which no example covers. The differential oracle catches it (`differential` 0.0),
dropping behaviour to 0.6 and the composite to 0.844, and flipping
`failure_class` from `none` to `logic`. **Without the differential oracle this
wrong solution would score a perfect 1.000.** That is the 30–32%-overstatement
finding (docs/01) fixed with real toolchain execution.

**Deferred within L2:** the property sub-oracle (metamorphic invariants) and
`proptest` shrinking of the first failing input. `differential` alone already
delivers the exit criterion.

---

## 2026-08-19 · First real model — llama-server + Qwen2.5-3B-Instruct-Q4_K_M

**What.** The first non-mock run: `rustybench run` against a live `llama-server`
(build 10470) serving Qwen2.5-3B-Instruct-Q4_K_M on the M5's Metal GPU, full
offload, concurrency pinned to 1. The HTTP path, token accounting, and the whole
oracle stack exercised against a real model.

**Result — the thesis on a real model.** Score **0.922**, `failure_class` Logic.
The model wrote a genuinely good answer: in-place `slice.reverse()`, **no
allocation** (L3 constraint 1.0), four of five behaviour tests pass. It fails one
— and the failure is a real, subtle Rust bug:

```rust
for i in (0..v.len() - w + 1).step_by(w) { ... }
//            ^^^^^^^^^^^^^^ usize underflow when v.len() < w
```

On the empty slice with `w = 3`, `0usize - 3` panics. The oracle located it
exactly: behaviour 0.8, failing input = `empty_slice`. That is the entire value
proposition demonstrated end to end — not a pass/fail bit, but "compiles,
memory-clean, one usize-underflow edge case." No general-purpose benchmark
produces that shape of result.

**Numbers:** prompt 290 tok, completion 285 tok, gen 5137 ms, grade 1775 ms.

**Throughput is NOT representative and is labelled so.** The ~55 tok/s here was
measured with 15 Chrome + 8 Safari + VS Code + Electron all compositing through
the same GPU and sharing unified-memory bandwidth, Bitdefender hooking every
cargo file write (inflating `grade_ms`), and this agent working alongside.
Correctness is robust to all of it — the oracle is deterministic — which is the
verifiable/unverifiable split (docs/10) confirmed in practice: the score is
trustworthy from a busy machine; the tok/s is not. Calibration-quality
throughput needs a quiesced host (a P1 concern), not a smoke test.

**Host:** Apple M5, 24 GB unified, macOS 26.5.1, AC power, ~81% memory free.

---

## 2026-08-19 · P2 (partial) — L3 constraint layer: allocation instrumentation

**What.** The first L3 constraint check, and per-category oracle weights, wired
through `bench-core` → `bench-oracle` → `bench-cli`.

**The mechanism.** Allocation is *measured*, not name-blacklisted. Round 5
established that `forbidden_calls = ["clone", "to_vec"]` cannot work — there are
unboundedly many ways to copy data. Instead the hidden oracle ships a test
target (`tests/alloc.rs`) carrying a counting `#[global_allocator]`; it snapshots
the allocation count, calls the function under test, and asserts zero
allocations in the hot path. A clone-everything solution allocates and fails it.
Because each integration test is its own binary, the allocator in `alloc.rs`
governs only that target and does not perturb the behaviour tests.

**Per-category weights.** `composite_score` now renormalises over whichever
layers produced a score, so `borrow-lifetimes` can be constraint-dominant
(behavior 0.35 / constraint 0.55) per docs/04. That is the fix for REVIEW.md S6:
under the old behaviour-dominant default a clone-everything solution scored
near-identically to a proper one.

**Verified** on the frozen borrow task, four model responses, weights
behavior 0.35 / constraint 0.55 (measured end to end against a mock):

| response | apply | compile | behavior | constraint(alloc) | score | failure_class |
|---|---|---|---|---|---|---|
| correct (`chunks_exact_mut`) | ✓ | ✓ | 1.0 | ok | **1.000** | none |
| clone-everything (`to_vec` + copy back) | ✓ | ✓ | 1.0 | **fail** | **0.389** | constraint |
| second mutable borrow | ✓ | ✗ (E0499) | — | — | **0.000** | borrowck |
| whole-slice reverse | ✓ | ✓ | 0.2 | ok | **0.689** | logic |

The clone-everything row is the point: behaviourally correct, all five
correctness tests pass, but the allocation it performs is now visible in the
score. Under the behaviour-dominant default weights the same answer scores
**0.778**; constraint-dominant weighting roughly halves it to **0.389**. That is
the REVIEW.md S6 fix, demonstrated with real toolchain execution.

**Observed tension, logged rather than hidden.** The logically-wrong
whole-slice-reverse (0.689) now *outscores* the behaviourally-correct
clone-everything (0.389). That is a genuine consequence of constraint-dominant
weighting: whole-slice-reverse manipulates in place (0 alloc → full 0.55
constraint credit) while clone-everything sidesteps the borrow skill entirely
(0 constraint credit) despite passing correctness. Whether "wrong but in-place"
should beat "right but allocating" on a *borrow-checker* skill probe is a real
design question, not a bug in the machinery — the composite is doing exactly
what the weights say. It bears on the pass-predicate decision (Q28) and on
whether behaviour should be a floor rather than a weighted term. Flagged for
P2-proper; the roadmap's "near zero" for clone-everything is reached more fully
once that is settled and/or L4 quality is present.

**Deferred within L3:** clippy, fmt, and `syn`-based unsafe/forbidden-path
checks. Allocation was done first because it is the flagship and hits the
exit criterion; the others are cheap follow-ups.

---

## 2026-08-19 · P0 — the spine

**What.** `rustybench run` end to end: load a frozen task → call an
OpenAI-compatible model → grade with the real `cargo`/`rustc` toolchain →
append a scored JSONL journal line.

**Crates.** `bench-core` (pure types + scoring + rustc-code→`FailureClass`),
`bench-model` (blocking `/v1/chat/completions`), `bench-oracle` (L0 apply, L1
compile with diagnostic capture, L2 unit), `bench-cli` (the `run` binary). Plus
one hand-written frozen borrow-checker task with five hidden tests.

**Verified** against a mock model: correct → 1.000/none, second-mutable-borrow →
0.000/borrowck (from a real `E0499`), whole-slice-reverse → 0.200/logic.

**Two bugs found by running it, not by review:**
- A materialised task crate was adopted by the outer cargo workspace. Fixed with
  a standalone `[workspace]` table in the task `Cargo.toml` — also how generated
  tasks will ship.
- The test-summary parser read the last `test result:` line (empty doc tests)
  instead of summing lib + integration + doc sections.

14 unit tests, clippy clean under `-D warnings`, rustfmt clean.

**Not yet, by design:** generation, seeding, the sandbox, resume, submission,
and the blocking measurements the reviews flagged (ρ / Q22, the pass predicate /
Q28, the statistical machinery / Q29).
