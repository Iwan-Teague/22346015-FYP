# Rustybenchmark

A benchmark harness for measuring what **local LLMs can actually do in Rust**, and what **your specific machine** can deliver while doing it.

Two numbers that do not currently exist side by side anywhere:

- **Capability** — what a model can solve, time-unbounded, broken down by Rust skill area (borrow checker, traits, unsafe, async, idiom, perf, …).
- **Throughput** — what a given machine + model + quantisation combination actually delivers per hour, per GB of VRAM, per watt-hour.

Every run profiles the host, calibrates inference on it, runs a seeded, contamination-resistant task suite in a sandbox, grades with a layered oracle, and (opt-in) submits redacted results to a public leaderboard.

Written in Rust. Runs on consumer hardware. Talks to any OpenAI-compatible endpoint (llama.cpp, Ollama, vLLM, LM Studio).

---

## Status

**Building — the generation + grading + aggregation half works end to end (macOS).** The design phase (17 docs, 10 ADRs, 6 adversarial review rounds) is under `docs/`. Code follows the roadmap in [docs/14-roadmap.md](docs/14-roadmap.md); phases P0 (spine), P1 (sandbox), P2 (oracle depth), P3 (generation) and much of P4 (runs, resume, stats) have landed.

**What runs today.** `rustybench run` sends a task — a hand-frozen file or a **seed-generated** one — to any OpenAI-compatible endpoint, grades the response with the real `cargo`/`rustc` toolchain inside a sandbox, and writes a scored JSONL journal line. `run-suite` serves a whole resumable epoch (paired-core + fresh-probe seeds); `stats` folds a journal into capability, pass-rate and cluster-bootstrap CIs; `status` gives progress/ETA. Tasks are generated *solution-first* so the oracle is correct by construction; **127 families across 99 skill areas** (all five core categories covered) now generate memorisation-measured, correct-by-construction tasks.

```
crates/
  bench-core        types, scoring, rustc-code → FailureClass       (pure, no I/O)
  bench-gen         seed → task (127 families) · anti-twin + spec-diversity · epoch sampler
  bench-oracle      L0 apply · L1 compile · L2 behavior/differential · L3 syn AST + clippy
  bench-sandbox     macOS seatbelt: no network, confined writes, wall-clock kill
  bench-model       OpenAI-compatible /v1/chat/completions client
  bench-stats       journal → capability · pass-rate · wild cluster bootstrap · McNemar · ICC · throughput
  bench-hw          host inventory (CPU/RAM/GPU/OS/storage/power) + privacy-bucketed hw_class
  bench-cli         run · run-suite · validate-family · stats · compare · detect · status · hw
  bench-invariants  CI gate: recomputes every published statistic
```

Build and try it:

```bash
cargo test                                                                    # ~1,500 tests across the crates
cargo run -p bench-cli -- validate-family --family idiom-loop --seeds 8        # prove a family's generator is sound
cargo run -p bench-cli -- validate-family --family lifetime-split --cover    # run exactly enough seeds to exercise every skill
cargo run -p bench-cli -- families --chunk 1/8 --ids                           # the registry in pieces, for a full sweep
cargo run -p bench-cli -- emit --family idiom-api --seed 3 --dir /tmp/x        # dump one seed: prompt, reference, baselines, hidden tests
cargo run -p bench-cli -- hw --gates                                           # host inventory + pre-run gates (disk, power, memory)
cargo run -p bench-cli -- run --family error-handling --seed 42 --model http://localhost:8080
```

**OS:** grading runs sandboxed on **macOS** (seatbelt). Linux/Windows containment is not built yet (roadmap gate G1).

Landed since P3: the statistics layer (`bench-stats` — capability, pass-rate, studentised wild cluster-bootstrap CIs, McNemar, the precomputation sign test, ICC, throughput), the run protocol (epoch orchestration, resume, `status`, `segment_position` + cache-warmth exclusion), and the Q28/Q29 decisions behind them (the structural pass predicate; the estimation spec). Still to come, per the roadmap: hardware calibration and upload (P1 hw Phase B / P6; the static inventory, `rustybench hw`, has landed); the full 272-family corpus (P7), of which **127** exist — all 5 core categories are covered, but each is far below its 40-family budget; L4 quality (mutation/perf); and the mined `wild` suite.

## Read order

| # | Document | What it settles |
|---|---|---|
| — | [docs/00-overview.md](docs/00-overview.md) | Goals, non-goals, the two-number thesis |
| — | [docs/01-prior-art.md](docs/01-prior-art.md) | What already exists, with figures, and the gap we fill |
| 1 | [docs/02-task-format.md](docs/02-task-format.md) | What a task *is* — manifest, generator contract, solution-first generation |
| 2 | [docs/03-oracle.md](docs/03-oracle.md) | How a solution is graded — the five layers |
| 3 | [docs/04-categories.md](docs/04-categories.md) | The eleven Rust skill categories, core vs probe, and their family budgets |
| 4 | [docs/05-hardware-and-calibration.md](docs/05-hardware-and-calibration.md) | Host inventory, inference calibration, derived metrics |
| 5 | [docs/06-execution-classes.md](docs/06-execution-classes.md) | GPU / hybrid / CPU classification and memory accounting |
| 6 | [docs/07-statistics.md](docs/07-statistics.md) | Suite sizing, ICC, power analysis, confidence intervals |
| 7 | [docs/08-run-protocol.md](docs/08-run-protocol.md) | The run lifecycle and the sandbox |
| 8 | [docs/09-resume-and-checkpointing.md](docs/09-resume-and-checkpointing.md) | Multi-session runs, segments, crash safety |
| 9 | [docs/10-integrity.md](docs/10-integrity.md) | Trust tiers, challenge/replay, anti-gaming |
| 10 | [docs/11-submission-and-privacy.md](docs/11-submission-and-privacy.md) | What is uploaded, what is redacted, consent |
| 11 | [docs/12-schemas.md](docs/12-schemas.md) | Every on-disk and on-wire schema in one place |
| 12 | [docs/13-architecture.md](docs/13-architecture.md) | Crate layout and dependency direction |
| 13 | [docs/14-roadmap.md](docs/14-roadmap.md) | Build order and the minimum shippable product |
| 14 | [docs/15-profiles-and-divisions.md](docs/15-profiles-and-divisions.md) | What the harness pins, gates, keys and frees; the Pinned / Tuned / Open divisions; weights identity; MCP |
| 15 | [docs/16-value-and-data.md](docs/16-value-and-data.md) | What the individual runner gets, data sufficiency, the dataset licence, and what is explicitly out of scope |
| 16 | [docs/17-authoring-families.md](docs/17-authoring-families.md) | How to add a generator family: the contract, the solution-first recipe, and the validation gates |

Supporting:

- **[docs/REVIEW.md](docs/REVIEW.md)** — adversarial review round 1. Read this alongside the docs it corrects; several published figures were wrong and the category design changed as a result
- **[docs/REVIEW-2.md](docs/REVIEW-2.md)** — adversarial review round 2, empirical against rustc 1.97. Found a direct contradiction between the statistical and integrity designs, and measured the diagnostic instrumentation to be blind for a third of realistic failures
- **[docs/REVIEW-3.md](docs/REVIEW-3.md)** — adversarial review round 3. Settled four deferred questions empirically; two settled against the design. `cargo clippy --fix` solves part of a core category, and the frozen plan could not hold probe units
- **[docs/REVIEW-4.md](docs/REVIEW-4.md)** — adversarial review round 4. The precomputation detector is defeated by an adversary willing to fail units deliberately; seed secrecy replaces it as the primary control. Also records a near-miss simplification that two simulations disagreed about
- **[docs/REVIEW-6.md](docs/REVIEW-6.md)** — adversarial review round 6. 72 findings, 23 verified. The statistical machinery cannot be built as specified: `task_score` is continuous, McNemar is a binary test, and no pass predicate exists anywhere — so `throughput_score` is uncomputable. **Unevenly verified; read its first section before acting on it**
- **[docs/REVIEW-5.md](docs/REVIEW-5.md)** — adversarial review round 5. 58 findings, 21 severe. Invalidates round 4's pairing result and with it the entire secrecy architecture; the mining pipeline and the plausibility checks do not work as specified. **Read R5-S1 first**
- [docs/GLOSSARY.md](docs/GLOSSARY.md) — terms used precisely throughout
- [docs/OPEN-QUESTIONS.md](docs/OPEN-QUESTIONS.md) — unresolved decisions, with the phase each blocks
- [docs/adr/](docs/adr/) — architecture decision records, including reversals

## The one-paragraph version

Static coding benchmarks rot: models memorise them. Rustybenchmark ships **generators**, not answers. Each task family is a function from a seed to a fresh problem instance, its reference implementation, and its property-based oracle — all constructed from the same seed, so the oracle is correct by construction and the instance has never been seen. Grading is deterministic given the seed, which means the server can independently re-verify any submitted correctness claim. Hardware claims cannot be verified, so they are reported separately and at a lower trust level. Runs checkpoint continuously and resume across sessions, because the largest suite takes around 44.5 hours on consumer hardware.

## License

**Two licences, deliberately.** The harness is noncommercial; the *data it produces* is not, because
independent re-derivation is the project's strongest integrity control and most of the parties with
the motive to audit a row are commercial.

- **Published results corpus → [CC BY 4.0](DATA-LICENSE.md).** Anyone may download the dump,
  recompute the leaderboard, and build on the data, commercially or not.
- **Harness and synthetic task corpus → [PolyForm Noncommercial License 1.0.0](LICENSE.md)** — free for any noncommercial purpose, including
personal, research, educational, and charitable use. Commercial use requires a separate licence;
open an issue.

Two things this deliberately does **not** restrict, because the benchmark's credibility depends on
them:

- **Reading, auditing, and re-deriving results.** Anyone may download the published corpus and
  recompute the leaderboard. That is the strongest integrity control the project has
  ([docs/10-integrity.md](docs/10-integrity.md)) and no licence term is allowed to weaken it.
- **Publishing findings.** Independent analysis of published data is not a licensed use of the
  software and is not restricted.

**The `wild` mined corpus is not covered by this licence.** Those task families derive from
third-party repositories under their own licences, which cannot be relicensed. They will carry
per-source attribution and terms, tracked in [docs/OPEN-QUESTIONS.md](docs/OPEN-QUESTIONS.md) Q1.
