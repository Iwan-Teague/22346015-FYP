# 14 — Roadmap

## Assumptions this plan is built on

State them, because a plan whose assumptions are hidden cannot be falsified.

- **1 FTE.** All durations below are one full-time person. Two people roughly halves the framework phases and does very little to the corpus phase, which parallelises across contributors rather than across teammates.
- **Family authoring: 1–3 days each, once the framework exists.** This is the largest and least-validated number in the plan. Gate G3 tests it.
- **ICC ≈ 0.3.** Unmeasured. Gate G2 tests it. Suite sizing is provisional until then.
- **Corpus: 272 families.** 5 core × 40, 6 probe × 12.

## The honest cost statement

272 families × 1–3 days = **272–816 person-days**. At 1 FTE that is **1 to 3 years** for the corpus alone, on top of ~4–5 months of framework.

The earlier draft implied "months 6–18". That was wrong by a factor of two or more, and pretending otherwise would mean planning against a schedule that cannot be met.

Two consequences follow, and they shape everything below:

1. **Over-invest in the framework and in `bench-tasks` ergonomics.** Generators 2 through 272 are only tractable if generator 1 established a good pattern and good helpers. An hour spent making family authoring pleasant pays back ~270 times. This is the highest-leverage work in the project.
2. **Design for external contribution from Phase 3, not as an afterthought.** A family is a self-contained PR validated by nine mechanical CI gates — the maintainer does not have to review anyone's statistics or re-derive their oracle. That property is unusual and it is the only realistic path to 272 families. Treat contributor experience as a Phase 3 exit criterion.

---

## Critical path

```
P0 spine ──► P2 oracle depth ──► P3 generation ──► G3 ──► P3.5 ICC ──► G2 ──► P5 first data ──► P7 corpus
                                      │                                          │
P1 sandbox+hw ────────────────────────┘                          P4 resumability ┘
                                                                        │
                                                       P6 attestation ──┘
```

**On the critical path:** P0 → P2 → P3 → P3.5 → P5 → P7.
**Parallelisable:** P1 (independent of task content), P4 (independent of corpus), P6 (independent of everything until P5 ends).

The corpus (P7) is the long pole and cannot start until the generation pattern is proven (G3) and the sizing is confirmed (G2). Everything before those two gates exists to de-risk them.

---

## Phases

### P0 — Spine · 3 weeks · *critical path*

One `frozen` task, no generation. Prove the loop end to end.

- `bench-core` types
- `bench-model` OpenAI-compatible client against a local llama.cpp
- `bench-oracle` L0 + L1 + L2-unit only
- `bench-cli run` writing JSONL

**Exit:** `rustybench run` against a real local model produces a scored journal line.

### P1 — Containment and hardware · 3 weeks · *parallel*

- `bench-sandbox` on all three platforms, with the escape-attempt suite
- `bench-hw` inventory, calibration, sustained phase, pre-run gates
- `ExecClass` and `MemProfile` recorded from the first run onward

**Exit:** escape tests fail correctly on macOS, Linux, and Windows; calibration reproducible within ±5% across repeat runs on one machine.

**Risk:** Windows parity (netns/seatbelt are well-trodden; job objects + WFP are not). Spike this in week 1, not week 3 — see **G1**.

### P2 — Oracle depth · 3 weeks · *critical path*

- L3 constraint layer, `syn`-based AST checks
- **Allocation instrumentation** — counting `#[global_allocator]` with a reference-derived budget
- L2 property + differential sub-oracles, seeded proptest
- Per-category weight support
- `failure_class` derivation from rustc error codes

**Exit:** a deliberately-wrong-but-tests-passing solution is caught by the property oracle, **and** a clone-everything solution to a `borrow-lifetimes` task scores near zero.

### P3 — Generation · 6 weeks · *critical path, pivotal*

Get this right and the rest is repetition.

- `bench-gen`: seed derivation, canary minting, prompt+skeleton distance
- **Both generator archetypes** — parametric (synthesise → ablate) *and* compositional
  (synthesise → inverse-transform), plus the invertible `syn` transform catalogue that
  `de_idiomatize` needs. This was unbudgeted before [REVIEW-2.md](REVIEW-2.md) R2-S6 and is a
  framework change, not a per-family one
- **One exemplary family** — `borrowck/split-mut-window` — to full quality
- `validate-family` with all ten CI gates
- **A second family in a deliberately awkward category** (`idiom-refactor` or `error-handling`), specifically to find out whether structural seeding generalises or collapses to cosmetic variation
- Contributor documentation and a `cargo generate` family template

**Exit / Gate G3:** a third family, authored by someone following the exemplar and the docs, lands in **under two days** and passes 1000-seed validation.

### P3.5 — ICC measurement · 2 weeks · *critical path, hard gate*

The experiment that the earlier draft omitted entirely, and on which all suite sizing depends.

- 20 families × 16 seeds × 3 models ≈ 960 units ≈ 24 h of compute

> **Scheduling defect, corrected.** As previously sequenced this phase needed 20 families while only
> 3 existed at that point on the critical path, and it was circular besides: P5's sizing depends on
> P3.5's ICC, while P3.5 needs families that P5 authors ([REVIEW-5.md](REVIEW-5.md)
> `p35-family-supply`). Broken by **authoring one core category to its full 40 families first**, then
> measuring on it. That yields both the within-family ICC *and* enough families to estimate the shape
> component (R5-S3), which a 20-family sample spread across categories could not. P5's remaining
> categories are sized from the measured value; the first category's own sizing is provisional and
> is re-checked once the number exists.
- Compute per-family and pooled ICC
- **Estimate baseline core-vs-probe discordance per family**, which the sign-test detector needs in
  order to be calibrated (see [REVIEW-3.md](REVIEW-3.md) R3-S3). Same runs, no extra compute
- **Measure ρ, the model × instance interaction** (**Q22**) — the same two-model runs give it for
  free, and it is the highest-value number in the corpus: it decides whether seed-level pairing is
  worth the entire secrecy architecture ([REVIEW-5.md](REVIEW-5.md) R5-S1)
- **Estimate the shape component of ICC**, not only the within-family component — the latter is
  invariant to the shape-clustering defect (R5-S3)
- Recompute suite sizing, family budgets, and every published CI from the measured value

**Exit / Gate G2:** measured ICC in hand; `deep` suite definition finalised.

### P4 — Runs that survive reality · 4 weeks · *parallel*

- `bench-run`: plan freezing, journal, segments, resume, validity gates
- Crash-injection suite
- Scheduling controls
- `status` with partial scores and ETA
- `bench-stats`: cluster bootstrap, ICC estimation, McNemar, effective N

**Exit:** a run killed at every stage boundary resumes to bit-identical final results, **and** a
reader who has never seen these documents can state, from the report alone, one thing the run proves
and one thing it does not.

### P5 — First real data · 8 weeks · *critical path*

**Three core categories × 40 families = 120 families.** Suggested: `borrow-lifetimes`, `traits-generics`, `error-handling` — most Rust-distinctive, all synthesisable, no miri or criterion dependency.

Run across several models and several machines. Publish the analysis.

**What P5 can and cannot claim.** At 120 families and 4 seeds, the *overall* score carries roughly ±6% — a defensible headline. Individual *core category* scores carry roughly ±10.7%, enough to say "weak at lifetimes" but not to rank two adjacent categories. Say exactly that in the writeup. The earlier draft claimed defensible category numbers from 3 × 20 families, which would have been ±17–20%. It could not have supported them.

**Exit:** a written report with real numbers and honest error bars.

### P6 — Attestation and submission · 6 weeks · *parallel*

- `bench-attest`: manifest, canonical CBOR, signing, redaction, canary screening
- Challenge/batch protocol client
- Three-way consent flow
- Server: `/submit`, `/dump`, minimal leaderboard
- T1 replay verification (L0–L3 only)

**Status 2026-10-05 (offline slice done as `bench-submit`, not `bench-attest`).** Built: redaction,
the consent flow for consent 1, canonical serialisation with a content hash, `export`, `verify-bundle`
([BUILD-LOG](BUILD-LOG.md)). Not built, with the reason: signing and canary screening (need decisions,
Q32 #5), the challenge/batch client and anything seed-secrecy-dependent (BLOCKED, R5-S2 / Q22 / Q23),
consents 2 and 3 (need a server key and an identity channel), the server and T1 replay. The crate is
named for what it does, the offline *submit* half; `bench-attest` can still be split out when signing
lands, per [13-architecture.md](13-architecture.md).

**Exit:** an independent third party downloads the dump and re-derives the leaderboard exactly.

### P7 — Corpus · 12–30 months · *the long pole*

- Remaining core categories (2 × 40 = 80 families)
- All probe categories (6 × 12 = 72 families)
- Mining pipeline for `cross-module` and `api-evolution`
- Async oracle resolved (see **Q11** — closed by the deterministic-executor spike; `poll-future` shipped as family #74)
- L4 quality layer where categories need it
- Epoch rotation in production

### P8 — Maturity · ongoing

- `calibrate-suite`: empirical per-family ICC and IRT parameters
- Adaptive item allocation
- T3 audit process and remedies document
- Agentic track as a separate leaderboard

---

## Captured ideas — not yet scheduled

Recorded so they are not lost. No phase, no estimate, no commitment yet.

### Built-in local-model harness

Today, pointing the benchmark at a local model means standing up a server by hand, wiring an
OpenAI-compatible base URL into whatever client is being used, and remembering to shut it down
afterwards so the weights stop occupying unified memory. That is fine once and tedious every time
after.

The idea is to make the harness a first-class part of RustyBench rather than a pile of shell
scripts beside it. Two halves, useful independently:

- **Agent harness** — start, stop, and health-check a local model server from within the tool,
  exposing it as an endpoint an agent can drive. Model lifecycle becomes part of the run rather
  than a manual precondition. Lands close to the P8 agentic track and should be designed with it.
- **Benchmarker** — point the harness at a local endpoint and get the standard suite plus the
  throughput and memory numbers that [05-hardware-and-calibration.md](05-hardware-and-calibration.md)
  already needs. Directly serves **G5**, which is stated in terms of tok/s and VRAM for a named
  model on named hardware — numbers currently gathered by hand.

Prior art on this machine: `~/Desktop/models/qwen3.sh` (start/stop/status/logs over
`mlx_lm.server`) and the opencode `local-qwen` provider entry are a working manual version of
exactly this loop, and are worth reading before designing the real one.

Open question: whether the harness owns the model process or merely attaches to one already
running. Owning it makes runs reproducible and self-contained; attaching avoids reloading 16 GB of
weights between suites. Probably both, with attach as the default.

---

## Kill and pivot gates

Numeric thresholds, decided in advance, so a bad result triggers a decision rather than being absorbed as slippage.

| Gate | When | Threshold | If it fails |
|---|---|---|---|
| **G1** Windows sandbox | P1 week 1 | **rustc and cargo function inside an AppContainer** with network capabilities withheld, and the escape tests fail correctly | Windows runs at reduced trust tier, or requires WSL2, or is unsupported at launch. Decide then, not later — it affects a large share of the consumer audience. Note the real risk is ACLs, not isolation: AppContainer denies network without a kernel driver, but the AppContainer SID must be granted access to the workspace, `CARGO_HOME`, and the rustup toolchain, and toolchains can break under capability-based ACLs |
| **G2** ICC | End of P3.5 | ICC ≤ 0.5 | At ICC > 0.5, seeds are worth little and per-core-category CI floors near ±12%. **Pivot:** raise core categories to 60 families and cut to 4 core categories, or accept that only the overall score is rankable |
| **G3** Authoring rate | End of P3 | A new contributor authors a validated family in ≤ 2 days | At > 3 days/family the corpus is a 3-year project. **Pivot:** cut to 3 core categories, or invest another 4 weeks purely in generation tooling before proceeding |
| **G4** Mining yield | Before P7 mining work | ≥ 12 usable families per mined category, drawn from **workspace member crates** at ≥200 stars and ≤5k LoC | The original filter (>1k stars **and** ≤2k LoC) was self-contradictory — Rust-SWE-bench's >1k-star pool averaged 993 files and 128k LoC, so the two constraints were nearly disjoint. Mining crates rather than repos is the fix. Yield is still unforgiving: 0.6% from ~80k PRs with no size constraint at all. **Pivot:** drop `cross-module` to hand-written multi-file synthesis, losing realism but keeping the category |
| **G5** Minimum viable hardware | End of P4 | `smoke` completes in < 90 min on 8 GB VRAM **with a 7B-class Q4 model at `GpuFull`** | The consumer-hardware promise is unmet. Shrink `smoke`, or raise the stated minimum and say so plainly. The model must be named: at 8 GB the reference 30B-A3B offloads heavily and lands at 5–8 tok/s, putting `smoke` at 2.3–3.7 h. A 7B Q4 fits fully and finishes in ~30 min. See [REVIEW-3.md](REVIEW-3.md) R3-S5 |

---

## What ships first, publicly

**Not a leaderboard. A report.** P5's output: three core categories, several models, several machines, real confidence intervals, published methodology, published generators, published raw data.

A leaderboard launched before the corpus supports category-level claims would be making claims the statistics cannot back, and would be very hard to walk back. The report establishes the method; the leaderboard follows when the corpus justifies it.

## Sequencing rules

1. **Schema decisions before code.** Submission manifest, `ExecClass`, `MemProfile`, per-category weights, and the IRT placeholder fields are cheap now and expensive later. See [12-schemas.md](12-schemas.md).
2. **Sandbox before corpus.** A corpus built against a leaky sandbox has to be revalidated.
3. **ICC before corpus.** Sizing 272 families against an unmeasured constant is the largest avoidable risk in the plan.
4. **Resume before long suites.** Do not discover resume bugs in someone's 40-hour run.
5. **Local runner before server.** The server is small and additive; the runner is the product.
6. **Report before leaderboard.** Method credibility first.
