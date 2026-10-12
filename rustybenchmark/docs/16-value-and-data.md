# 16 — Value and Data

*Consolidated recommendation. Synthesised from five analysis tracks plus an adversarial critique; claims below are grep-verified against the repo at commit state 2026-08-19 unless marked as inference.*

---

## 1. What the individual runner gets today — the honest answer

**They get `report.json` and a CLI verb.** The complete specification of the human-facing deliverable across 5,866 lines is:

- `rustybench report <run_id> [--format md|json|html]` — [08:194](08-run-protocol.md)
- `bench-report — aggregation and rendering. Terminal tables, JSON, HTML with radar charts.` — [13:52](13-architecture.md)

Two fragments, eleven words of content. By contrast [15](15-profiles-and-divisions.md) spends 726 lines on the leaderboard, with §10.1 pinning the row key exactly and §10.2 listing ~35 displayed columns grouped into four epistemic buckets, and [11](11-submission-and-privacy.md) adds seven presentation rules for the public table. **That asymmetry is the answer to the owner's third question.**

Worse than the asymmetry: **`bench-report` appears in [13](13-architecture.md)'s crate layout and in none of P0–P8.** Verified — the only `report` hits in [14](14-roadmap.md) are lines 135/181/183, all referring to the P5 *written analysis* (a human-authored document), not to the CLI. Nothing schedules the artefact the runner receives and no exit criterion covers it. `doctor`, `ab` and `config-audit` share the same fate: they are load-bearing in [15](15-profiles-and-divisions.md) §9.2/§9.3 and in [ADR-0010](adr/0010-pinned-tuned-open-divisions.md):35,42, and they appear in neither [08](08-run-protocol.md)'s CLI surface (which lists `profile, calibrate, run, status, resume, abandon, report, submit, validate-family, calibrate-suite, verify`) nor any roadmap phase.

**Value per hour, stated plainly.** `deep` is 44.5 h @20 tok/s, 29.7 h @60 ([07](07-statistics.md) suite table). In the 90-minute evening slices [00](00-overview.md) and [09](09-resume-and-checkpointing.md) explicitly sell, that is ~30 consecutive evenings — 4–6 weeks with normal life. On the 8 GB band G5 targets (5–8 tok/s for the reference 30B-A3B, [14](14-roadmap.md) G5), it is 40+ evenings. The ladder offers nothing in between: `smoke` 55 min at ±12.7% overall and no category resolution; `standard` 11.7 h, greyed as *insufficient precision for ranking* and with `capability_score_core5` undefined because only four core categories run; `deep` 44.5 h as the minimum ranked tier.

**What is genuinely good and already built** (do not rebuild, do promote): `doctor` — 90 s, read-only, 11 probes, converts a measured 19.5-point silent context loss into a copy-paste line ([15](15-profiles-and-divisions.md) §9.2). `ab --factor {backend,exec-class,quant,spec-decode}` — paired single-factor oracle-verdict flips; `config-audit` — measured at 22 s + 2.9 GB baseline, 30–90 s per variant, full 9-config sweep across two models under 40 min. `status` with a partial score and an honestly widened CI ([09](09-resume-and-checkpointing.md):184–196). Partial-run reporting with an explicit `completeness` field. `profile` and `calibrate` as standalone commands ([08](08-run-protocol.md):189–190) — this is already a 15-minute product and is nowhere marketed as one. The sustained 10-minute thermal-decay block in `calib.json` is a real contribution almost nobody publishes.

**So the suspicion in the brief is correct, with one correction.** The individual gets a great *setup* experience and essentially no *result* experience. The gap is not that the design is greedy — it is that the payoff artefact was never specified, so it was never scheduled, so it will ship last or not at all.

**One correction to the framing.** Two tracks proposed a dump-reading advisor as the fix. Check the roadmap: the public dump ships at **P6** (6 weeks, parallel, after P5's 8 weeks, after ~4–5 months of framework) and is populated at **P7 — 12 to 30 months**. Every dump-consuming proposal pays in roughly two years. The report pays at P5. Fix the near thing first.

---

## 2. The single highest-value unclaimed feature

**Write `docs/16` — the run report — as a first-class product spec, at the level of detail [15](15-profiles-and-divisions.md) gives the leaderboard row.**

Argued entirely from data already collected. Per unit, `journal.jsonl` already carries: the full oracle vector (L0 `apply_ok`; L1 `compile_ok` + `error_codes[]` + `warn_count` + `diagnostic_completeness`; L2 `behavior{unit,property,differential}`; L3 `constraint{clippy,fmt,unsafe_blocks,forbidden}`; L4 `quality{mutation,perf_ratio,size_ratio}`), `score`, `first_try_score`, `failure_class`, `classified`, `finish_reason`, `cached_tokens`, `apply_ok`, `flags[]`, and the eight-field `cost` block. `report.json` carries `capability_score` with CI and both effective-N figures, per-category values with CIs and `shapes`/`icc_*`, `error_histogram`, `compile_rate`, `classified_rate`, `harness_overhead_ratio`, `l4_share_of_grade`, `failure_classes`. `artifacts/<unit_id>/{prompt.md,response.txt,diagnostics.json}` is already retained locally ([09](09-resume-and-checkpointing.md):29–31). **Zero new collection. The entire input set exists.**

What the report must do that nothing currently does:

1. **Open with a verdict paragraph, not a table.** Which categories this model is safe to trust on this box and which it is not, at this suite tier, with the honest "and which comparisons this run cannot support".
2. **Name the failure mode in English.** `E0499: 41` is data; "it cannot hold two mutable borrows apart" is an answer. `E0277` = it does not reach for the right trait bound. `failure_class: constraint` in `borrow-lifetimes` = it cloned its way out.
3. **Surface `first_failing_input`.** [03](03-oracle.md):139 calls the proptest-shrunk minimal counterexample *"the single most useful artifact for a human reading a failure"* and it appears in no schema. Show it, plus the reference implementation, for FAILED units, **locally only** (see §4). This does not conflict with the [00](00-overview.md) non-goal: *publishing* is the constraint; showing a user their own failures on their own machine is not publishing, and `response.txt` already establishes retain-locally-never-upload as the pattern.
4. **Render statistics so they cannot be misread.** [REVIEW.md](REVIEW.md):51 established the radar chart would carry ±12–16% error bars at *any* suite size, and R5-S3/Q24 made it worse — no core category currently reaches the claimed ±10.7%. A chart whose visual grammar invites area comparison, sitting beside a printed CI that forbids it, is not a countermeasure. **Replace the radar with a sorted dot plot with CI bars, and render CI-overlapping categories as explicitly tied.** This is the same principle [11](11-submission-and-privacy.md) already applies to quantisation — *"the presentation should make it impossible to do by accident"* — extended to the statistics. Fold this into `docs/16`; it is not a standalone item.
5. **`rustybench compare <run_a> <run_b> [--paired]`.** Every model in an epoch runs the identical core seed set ([ADR-0009](adr/0009-paired-core-and-fresh-probe-seeds.md)), so this is a McNemar contrast over discordant pairs — statistically the strongest comparison in the system, and `bench-stats` already implements McNemar ([13](13-architecture.md):20). It is nearly free and it is the only home for the experiment a user can actually afford: *I changed one thing*.
6. **Add a P5 exit criterion:** a reader who has never seen the docs can state one thing the run proves and one thing it does not.

**Why this over the advisor.** [14](14-roadmap.md) sequencing rule 5 is the project's own: *"Local runner before server. The server is small and additive; the runner is the product."* Nobody runs → no dataset → the public-benefit half never happens. `docs/16` is upstream of every dump-consuming feature in this document.

**On `rustybench advise` specifically — the proposal is demoted, and the reason matters.** Its load-bearing premise was "the row key carries no hardware field, so capability transfers across machines." [06](06-execution-classes.md):65 says the opposite, in bold, as a recorded reversal: *"`capability_score` is NOT comparable across execution classes… This document previously asserted the opposite… and that is empirically false"* — 7/7 byte-different at `-ngl 0` vs `-ngl 99`, 94.4% top-1 agreement, one oracle-verdict flip on an unsafe-transmute task, `exec_class` therefore part of row identity. So `advise` can rank capability only *within the asker's own exec_class* — and the 8–16 GB partial-offload band it exists to serve lands in `Hybrid`, where [15](15-profiles-and-divisions.md) §11.3/§12.4 records the direction of the effect as unknown and unmeasured. Separately, `throughput_score` is `tasks_passed / wall_clock_hour` — a *joint* model×machine quantity, not a hardware property — so predicting it from calibration still imports a pass rate from a row [06](06-execution-classes.md) forbids importing. **`ab --factor exec-class` (Q22/§12.4) is a prerequisite for `advise`, not an alternative to it.** Verdict in §7.

---

## 3. Data sufficiency

**Verdict: configuration capture is well above field norm. Outcome capture is a vector, which is the design's best decision. The gap is not collection, it is (a) a handful of unretrofittable keys and (b) consumption.**

Inventory: ~51 leaf fields per unit in `journal.jsonl`, ~22 per segment across `calib.json`/`meta.json`, four per-run objects (`plan.json`, `state.json`, `hw.json` ~30 fields each carrying a `source`, `report.json` ~30), plus a manifest adding `machine_uuid`, `epoch`, `submitter_config` (signed, displayed), `hw_public` (9 bucketed), `consents` (3).

### 3a. What is collected and what it supports

| Collected | Supports today |
|---|---|
| Oracle vector L0–L4 per unit, `score`, `first_try_score` | Per-category capability with CIs; repair-gap as a model property |
| `error_codes[]`, `failure_class`, `classified`, `diagnostic_completeness` | `error_histogram`, failure taxonomy, honest reporting of when borrowck was never reached |
| `cost{prompt,completion,prefill_ms,gen_ms,build_ms,grade_ms,peak_accel_mem_mb,peak_host_rss_mb}` | `throughput_score`, `harness_overhead_ratio`, `l4_share_of_grade`, token-efficiency per solved task, prompt-length effects (~2k synth vs 52–62k cross-module) |
| `cached_tokens`, `finish_reason`, `flags[]` | Prefix-cache contamination invalidates timing but never verdict; timeout/overflow/format failures separated from model failure |
| `segment`, `segment_position` + per-segment `calib.json` | Cache-warmth exclusion; thermal decay over 10 min; per-segment throttle events — a genuine contribution nobody publishes |
| `exec_class` + source, `offload_ratio`, `kv_cache_location`, `effective_ctx` (probed), `template_sha256` + source, `reasoning_format`, `tools_offered` | The configuration-confound layer, at a level no comparable harness reaches |
| `hw_public` buckets, `submitter_config` (signed), trust tier, `completeness`, `categories_scored` | Comparability, taint visibility, denominator honesty |
| Seeds published at epoch close + public generators | Item-level response matrix ⇒ IRT, difficulty calibration, dead-family detection — all recoverable post-hoc |

### 3b. Missing fields worth adding

Cost column is engineering effort. "New collection" = requires measuring something not currently measured.

| # | Field | Unblocks | Cost | New collection? | Verdict |
|---|---|---|---|---|---|
| 1 | `shape_id` per unit (in `task.toml` + journal + dump) | **Any third party recomputing a published CI.** [07](07-statistics.md):84 makes the bootstrap resample *shapes*; no schema anywhere carries a shape key; `report.json` publishes only a per-category `shapes` count. Today an auditor recomputes point estimates and gets intervals ~40% too narrow (07's own naive-bootstrap figure at ICC 0.3) — worse than not trying | Small; rides on Q24 which is already blocking | No | **DO NOW** |
| 2 | `attempts: [{attempt, oracle{…}, cost{…}, finish_reason, flags}]` replacing the flat block | *Which rustc error classes does compiler feedback actually fix* — the most citable result the project could produce, and one only this design can produce because [03](03-oracle.md) pins the feedback content and varies only the model. Also: marginal token/second cost of repair; repair regressions | Small — **serialisation only**, both attempts are already graded in memory. Journal grows ~1.7× | No | **DO NOW** |
| 3 | `family_version` in `task.toml` + journal | Prevents a family whose generator changed being silently pooled with its old self across epochs. **Strictly unretrofittable** — accumulated rows cannot be re-labelled | Trivial | No | **DO NOW** |
| 4 | `rustc {version, channel, commit_hash}` per run | `error_histogram` is keyed on rustc diagnostic codes with **no rustc version recorded**. Any multi-epoch histogram trend is uninterpretable by construction | Trivial | No | **DO NOW** |
| 5 | `vendor_set_hash` in `plan.json` | [15](15-profiles-and-divisions.md) §12.11 already asks for this in prose — *"or a routine suite refresh silently moves every score"* — and the schema does not carry it. Also the only route to "does the Rust ecosystem get easier for models as crates stabilise", which nobody else can ask | Trivial | No | **DO NOW** |
| 6 | `behavior.first_failing_input` (length-capped) + `behavior.property_results: [{name, passed}]` | §2 item 3. Also recovers *which* property failed — "satisfies ordering, violates idempotence" is the finding property-based evaluation exists to produce, and three booleans currently collapse to one float | Near zero — proptest already returns both | No | **DO NOW** (local surface; publish `property_results` only) |
| 7 | `constraint.clippy_lints: []` and `violations: [{rule, file, line}]` | `idiom-refactor` is a **core** category that [03](03-oracle.md) says *"produces zero rustc errors by construction — clippy catches all of it"*, so it contributes nothing to the published histogram and its only diagnostic signal is unrecorded. [03](03-oracle.md)'s own `violations: Vec<String>` emission has no home in any schema | Small — already computed | No | **DO NOW** |
| 8 | `cost.energy_j`; `calib.avg_power_w`, `idle_power_w`, `power_telemetry_source` | `efficiency_score` is a README headline and is **structurally uncomputable** — zero occurrences of energy/kwh/watt/joule as a schema field; `report.json` carries `"efficiency_score": null`; [05](05-hardware-and-calibration.md):124–130 lists the telemetry sources and no field to write them into. Unblocks perf-per-watt across quant, and the CPU-vs-GPU efficiency crossover — a number that does not exist publicly and that only a harness measuring correctness and hardware in one run can produce | Small (~200 LoC NVML/RAPL + sampling thread); adds one 60 s idle baseline per segment (~1% of a 90-min slice) | **Yes** — works with no user action on Linux/NVIDIA | **DO LATER (P1)** |
| 9 | `ttft_ms`, `total_request_ms`, decode p50/p95, `timing_source = server_timings\|client_stream` | Zero occurrences of TTFT repo-wide. `prefill_ms`/`gen_ms` are unobtainable on **three of four** named backends (Q27, R5 `prefill-gen-unavailable-cross-backend`), so `throughput_score`, `harness_overhead_ratio` and `time_to_first_pass` degrade *correlated with the variable under study*. TTFT is the one latency number the whole local ecosystem quotes, and a TTFT-vs-prompt-length curve for consumer hardware does not exist publicly | Moderate — switch the model client to streaming. Also yields budget-exhaustion detection and partial-response capture, both of which [15](15-profiles-and-divisions.md) §5.4 wants | **Yes** — no new dependency, works identically on all four backends | **DO LATER (P1)** |
| 10 | `weights.gguf_kv_digest` (blake3 over sorted non-`general.*` KV) + `weights.file_blake3` **conditional on matching a known public build** | Distinguishes *builds* of the same nominal quant. [15](15-profiles-and-divisions.md) measured two same-arch same-quant fine-tunes as byte-identical across every architectural field (733 tensors, identical block_count/embedding_length/vocab/heads), differing only in free-text `general.*` keys editable in seconds. Two rows labelled identically can be different artifacts, and the leaderboard would pool them | Small — `doctor` probe 9 already computes `llama-gguf-hash --uuid` (2.1 s / 1.93 GB ⇒ ~31 s / 16.7 GB); just persist it | No | **DO LATER**, with the privacy condition in §4 |
| 11 | `machine_pseudonym = blake3(machine_uuid ‖ epoch_salt)`; opt-in stable `lineage_id`; publish `completed_at` at segment granularity | [15](15-profiles-and-divisions.md) §10.3's own backend release criterion says δ *"is estimated by pooling within-machine paired contrasts across submitters with machine fixed effects"* — and the public dump carries **no machine grouping key**. The criterion is uncomputable as specified. Also the only route to any within-machine, across-time contrast (driver update, backend bump, re-quant) | Small in code; a consent line in policy | No | **DECIDE NOW, ship at P6** |
| 12 | `plan.variance[]` (epoch-fixed subsample) + `sample_index` + per-line `sampling` block + `report.pass_at_5`, `self_consistency_rate` | [07](07-statistics.md) budgets a *"10% instance subsample × 5 samples @ temp 0.8 → pass@5"* at **+5% of runtime** — ~2.2 h of a `deep` run — and there is no schema, no plan entry, no report field, and no leaderboard column for any of it. Unpaired across models because the subsample is not in the frozen plan, discarding 07's own 2–4× pairing argument | Small — the compute is already budgeted and already being spent | No | **DO NOW — or delete the probe and give the 5% back to families**, which [ADR-0006](adr/0006-breadth-over-depth-in-sampling.md) says is the better spend |
| 13 | `hw_public.gen_year` (bucketed, derived server-side from `vendor`+`gen`) | Hardware price/performance curves over time — the popular half of the longitudinal story | Trivial; the MSRP table is public data held server-side, never collected from users | No | **DO LATER** |
| 14 | `irt` block attached to an explicit `families.jsonl` keyed `(task_id, family_version)`; emit author-declared `difficulty` to the journal | [12](12-schemas.md) reserves `irt: {difficulty, discrimination, guessing}` under a bare "Reserved for v2" heading attached to no parent object. Also enables the cheap check *does author intuition predict empirical difficulty* before the authoring guide scales to 272 families | Trivial | No | **DO LATER (P8)** |

### 3c. Two consumers that need no new fields at all

- **`capability_score_fresh` from the probe.** [ADR-0009](adr/0009-paired-core-and-fresh-probe-seeds.md) states verbatim: *"The probe costs ~15% of every run and produces no score"* — 163 of 1251 units, ~6.7 h of a `deep` run. Probe units are the only instances in the design that provably did not exist before the run was requested: the cleanest uncontaminated capability sample available, currently discarded. Score them into a separate published aggregate (unpaired, wider CI, explicitly not rankable) and publish the family-matched core−probe delta as a per-run contamination indicator. Zero new compute, zero new collection. **Blocked behind Q22** — [OPEN-QUESTIONS](OPEN-QUESTIONS.md) Q22 says *"No further engineering on the probe, batch nonces, or seed secrecy until this number exists."* Respect that; queue it behind ρ.
- **`replication_rate`.** Core seeds are identical for every submitter in an epoch, so two independent runs of the same row key yield a direct empirical answer to *if I run this again on different hardware, how much does the number move* — folding in backend nondeterminism, thermal state, template drift and cache effects, which the published CIs (item-sampling error only) do not. Server-side aggregation, zero client change. **The decision is now-or-never**: [11](11-submission-and-privacy.md) says duplicate `run_id` is idempotent but says nothing about duplicate *row keys*, and a leaderboard that dedupes to one row per model destroys the sample as it arrives.

---

## 4. Fields to remove, or not collect

Over-collection is genuinely not this project's problem. The privacy design is the strongest part of the repo — three opt-in consents on materially different risk lines, bucketed hardware, a locally-minted random UUID explicitly not hardware-derived, an enumerated never-upload list with the leak mechanism named for each entry, and `rustybench forget`. Four small items and four refusals:

**Drop or justify:**

| Field | Status |
|---|---|
| `cost.peak_host_rss_mb` (per unit) | **Drop.** Already recorded per segment in `calib.json`, and near-constant across units since the model process is resident — 1,088 near-identical values per `deep` run. Keep per-unit `peak_accel_mem_mb`, noting R5's `accel-mem-attribution` finding that it is device-wide |
| `oracle.warn_count` | **Name a consumer or drop.** Absent from `report.json`, from [15](15-profiles-and-divisions.md) §10.2's columns, and from every analysis in the docs. Warnings-per-compiling-solution is a plausible model property; if that is the intent, add the aggregate |
| `quality.size_ratio` | **Drop or scope.** Weighted 0.2 inside L4 and never aggregated or displayed. R2-S7 already disabled it for compositional categories on non-uniqueness grounds and R3 found the same defect one layer deeper. A field that is unsound for two core categories and unread for the rest is not earning its weight |
| `machine_uuid` + per-unit `completed_at` in the dump | **The one real exposure** (R5 `uuid-plus-timestamps-timeline`): a cross-epoch linkable activity timeline of when the user is at their computer. **Do not patch this silently** — the obvious fix (delete the identifier) also deletes the within-machine grouping [15](15-profiles-and-divisions.md) §10.3's release criterion depends on. Resolve it as §3b item 11: rotating pseudonym + opt-in lineage + segment-granularity timestamps. Decide it as a value trade, not as a privacy patch |

**Do not collect / do not publish:**

- **Rustc diagnostic message text, even normalised.** [15](15-profiles-and-divisions.md) §12.14 is already marked *"Shipping blocker, not an open question: enumerate before the first submission"*, on top of R5's `redaction-is-a-denylist`. Rustc messages echo model-authored identifiers, and a normalisation ruleset is a permanent maintenance burden that drifts with every rustc release. `clippy_lints[]` (stable identifiers, no user content) yes; message templates no — revisit only after §12.14 converts redaction from a denylist to an allowlist.
- **Model output, failing or passing.** One track proposed a fourth consent to publish *failing* outputs for model authors. Reject. Post-epoch, seeds and generators are both public, so the instance is reconstructible; a published failure corpus is therefore a labelled `(instance, wrong answer, rustc diagnostic)` set — the highest-value RL/SFT signal for exactly the capability being measured, against a shape space R5-S3 measured as small (`unsafe-core` ~16 shapes, `idiom-refactor` ~3 distinct lessons). Keep failure artefacts local, per §2.
- **`weights.file_blake3` of a user-rolled quant.** A hash of a *public* GGUF is near-zero surface. A hash of a locally produced quant is **unique to that user and stable across epochs** — a hardware-independent lifetime identifier, precisely what [11](11-submission-and-privacy.md)'s random-UUID rule exists to prevent. Publish the file hash only when it matches a known public build; otherwise publish the KV digest alone.
- **Per-segment `idle_power_w` as a published time series.** Publish the per-run energy aggregate; a timestamped idle-draw series leaks ambient and other-load patterns. Keep the series local.

---

## 5. Dataset licence

**Recommendation: CC BY 4.0 for the published results corpus, in its own `DATA-LICENSE.md`, stated explicitly as not covering the harness. Apache-2.0 for the aggregator, verifier, dump reader, schema definitions and data dictionary. PolyForm Noncommercial 1.0.0 may stay on the harness and the synthetic task corpus.**

**The gap.** [LICENSE.md](../LICENSE.md) covers "the software". Q1 is DECIDED for *"the harness and the synthetic task corpus"*. Q21 covers only the mined `wild` sources. **The results corpus is named in neither** — so its default is all rights reserved, while [README.md](../README.md):65–69 asserts anyone may *"download the published corpus and recompute the leaderboard"* and calls that the strongest integrity control the project has.

**The hard deadline.** Consent #1 ([11](11-submission-and-privacy.md)) reads *"Publish redacted scores and hardware class to the public leaderboard."* That is consent to publish, **not a licence to sublicense onward** — and CC BY obliges the project to grant downstream rights it would not hold. The fix is retroactively impossible by construction: Q23 records no accounts, and [11](11-submission-and-privacy.md):68 deliberately makes `machine_uuid` a random locally-minted value linked to no contactable identity. There is nobody to go back and ask. **This must land before the first accepted submission (P6), not before launch.**

Concretely:
1. Append to consent #1: *"You grant the project a perpetual, worldwide, non-exclusive licence to publish these redacted results and to license them onward under CC BY 4.0."* Show the licence **name** on the consent screen, not a link.
2. Add `terms_version` and `terms_hash` to the signed `consents` block, so which grant a row was collected under is a recorded fact and a future terms change is a visible schema event.
3. Add a harness test asserting the consent text contains the licence name.
4. State the licence in `DATA-LICENSE.md`, in the README, in `MANIFEST.json` of every dump, and in the `license` field of every mirror release.

**Why CC BY 4.0 specifically, over the alternatives:**

- **4.0 is the first CC version that expressly licenses *sui generis database rights*** — the only right that plausibly attaches to a table of measured facts under UK/EU law, and the owner is UK-based. A US-style copyright licence or a bespoke term leaves the database right unlicensed and the question open.
- **Not NC.** The parties with both motive and budget to audit a competitor's row — Nvidia, AMD, Apple, Ollama, LM Studio, vLLM, quant publishers — are all commercial. NC makes the project's strongest stated integrity control legally available only to hobbyists.
- **Not SA.** Viral onto any downstream aggregator merging these rows into a wider table, which is exactly the reuse that makes the dataset matter.

**The interaction with PolyForm NC on the code, stated plainly.** Q1 records the trade it made: *"What the licence does cost is internal commercial evaluation, which is a real segment of the likely audience. That trade was made deliberately."* There is a second cost Q1 did not record. **No hardware vendor, quant publisher or inference-engine company can legally run the harness to benchmark their own product.** So the published corpus will systematically lack rows for newly released GPUs and new backend versions — precisely the rows users most want, and precisely the rows that would drive adoption. **That is a coverage hole in the *data* created by the *code* licence.**

Two mitigations, in order of preference:
- **Split the licence by directory, not by project.** Aggregator, T1 verifier, dump reader, schema definitions and data dictionary under **Apache-2.0** (the patent grant matters for anything a company runs internally), with a `LICENSE` in those subtrees and a README note that re-derivation tooling is permissive by design. This makes README:65–69 true rather than true-only-if-you-write-your-own-aggregator.
- **Add a standing carve-out to the NC terms:** *"running the harness for the sole purpose of producing a submission published to the public leaderboard is a permitted purpose."* This reopens vendor-run rows without giving away private internal evaluation — the segment Q1 says the decision was actually protecting. Cheapest before the first external contributor PR, since contributions inherit whatever is in place.

**Comparables, checked directly (2026-08-19, HF dataset API):**

| Dataset | Licence | Downloads |
|---|---|---|
| `lmarena-ai/leaderboard-dataset` | `cc-by-4.0` | 38,816 |
| `open-llm-leaderboard/contents` | **none in card metadata** | 17,370 |

The negative example is the instructive one: the largest LLM leaderboard's results table is legally unusable by anyone who reads carefully. Others: LMSYS split theirs (prompts CC-BY-4.0 / model outputs CC-BY-NC-4.0); Papers with Code was CC BY-SA 4.0 (and survives only because the community mirrored it after Meta sunset it in July 2025); BigCodeBench Apache-2.0; HumanEval MIT; MLCommons publishes MLPerf results under Apache-2.0 plus explicit results-messaging rules. The Data Provenance Initiative's audit of 1,800+ datasets measured licence omission above 70% on GitHub and Hugging Face — the default failure is not a wrong licence, it is no licence.

---

## 6. Making the dataset genuinely reusable

The dump is currently designed as an **integrity artifact**, not as a **dataset**: nine lines in [11](11-submission-and-privacy.md), format defined by subtraction (*"Same schema as the local journal minus redacted fields"*), distribution by one endpoint (`GET /dump/<epoch>.jsonl`), and a manifest table named in four words with no schema. Zero occurrences repo-wide of DOI, Zenodo, datasheet, data dictionary, citation, CITATION.cff, Croissant, or "researcher". The word "dataset" appears once, in a subordinate clause.

**Decide the following now, on paper; implement at P6.**

**Format.** Split the endpoint: `dump/<epoch>/units.jsonl`, `dump/<epoch>/runs.jsonl` (the manifest table, joined on `run_id`), `dump/<epoch>/families.jsonl` (family → shape map, `family_version`, IRT parameters), `dump/<epoch>/MANIFEST.json` (per-file sha256, row counts, epoch open/close, `generator_commit`, `suite_hash`, `dump_schema`). Publish a Parquet/DuckDB-friendly mirror alongside JSONL so a third party analyses without writing a parser.

**Dictionary.** A per-column table: name, type, units, nullability, provenance (measured / declared / derived), redaction status, and which epochs it exists in. Redaction defined by *enumeration*, never by subtraction — R5-S7 already found the upload list and the dump section drifting apart, and defining one by reference to the other guarantees it recurs.

**Versioning.** A `dump_schema` integer **distinct** from the harness `schema`, with a stated compatibility policy, a changelog, and a deprecation window. Separately, define `suite_version` — it is a row-key field in three places in [15](15-profiles-and-divisions.md) and is defined nowhere. Three levels with an explicit comparability verdict each: **MAJOR** (category set / oracle weights / estimator changes) — no cross-version comparison, archive the old board rather than migrating; **MINOR** (families added inside existing categories) — comparable subject to the macro-average denominator rule, with the caveat displayed; **PATCH** (generator or oracle bugfix) — no re-run, re-derive from the dump. This must land before P5 publishes, because P5's numbers become the first thing anyone compares against.

**Citation and permanence.** Per epoch close: push to **Zenodo** (concept DOI + version DOI) and **Hugging Face Datasets**, with the project server as canonical origin. Add `CITATION.cff` covering software and dataset separately, and a "How to cite" block naming the concept DOI. Write `docs/DATASHEET.md` against Gebru's seven sections — motivation, composition, collection, preprocessing, uses, distribution, maintenance — which map almost exactly onto content already in [04](04-categories.md), [05](05-hardware-and-calibration.md), [07](07-statistics.md), [10](10-integrity.md), [11](11-submission-and-privacy.md); it is mostly transcription, and its known-limitations section, after six adversarial rounds, is a credibility asset rather than a liability. **The mirror is also the succession plan**: Papers with Code's data survives only because it was mirrored before Meta shut it down.

**Discoverability.** HF auto-emits Croissant metadata, which is the route into Google Dataset Search across ~700,000 datasets — close to free discoverability the project is currently declining. Name three audiences explicitly in [00](00-overview.md) and give each one artifact: the individual choosing a model (an interactive filter, not the ranked board); the vendor or quant publisher (a stable per-hardware-class slice with a documented join key); the eval researcher (the DOI'd, datasheeted dump). One short release note per epoch: row count, models added, hardware classes added, schema changes.

**Auditability of the dump itself.** Two defects worth fixing in the same pass. (a) The ed25519 signature covers the *unredacted* manifest, so redaction necessarily invalidates it over the published form — nothing lets a third party verify that a published row is the row a submitter signed. Have the client sign a **canonical, redaction-stable public projection** separately, so each JSONL line carries its own signature and public key. (b) The dump is served by the party being audited, with no external evidence of append-onlyness. Publish a per-epoch **Merkle root** over `run_id`-sorted rows, signed with the project key and including the previous epoch's root; the Zenodo deposit is the third-party timestamp.

**`rustybench rederive <dump>`.** Recomputes every published leaderboard column from the dump alone and asserts equality against the live board; run it as CI on every closed epoch. This converts *"the numbers can be independently re-derived"* from an assertion into a passing test. It is also P6's stated exit criterion (*"an independent third party downloads the dump and re-derives the leaderboard exactly"*) — currently with no tool to do it and, without `shape_id`, no way to reproduce a single confidence interval.

**A reference analysis notebook, published with the first dump.** A dump with no demonstrated analysis is a dump nobody analyses, and the project's own integrity argument rests on outsiders working the data — all three Terminal-Bench misconduct cases were surfaced by community analysis. Five canned questions: failure_class × category × model; families with near-zero pass rate across all models (which also feeds corpus QA); error codes where one model is an outlier; `first_try_score` vs final score by category ([08](08-run-protocol.md) already calls this *"a genuinely interesting model property"* and never uses it); quant-ladder effects on failure distribution ([15](15-profiles-and-divisions.md) §12.9: *"the GGUF k-quant × code-generation cell is empty in the literature"*). Link it from the README as *what the data is for*.

---

## 7. Missing areas — ranked, with verdicts

### DO NOW

| # | Area | Why now |
|---|---|---|
| 1 | **`docs/16` — the run report spec**, absorbing the rendering rules (dot plot, CI-overlap-as-tie), local `first_failing_input` surfacing, and `rustybench compare` | §2. Upstream of everything. ~2–3 days to spec, 1–2 weeks to build, zero new collection |
| 2 | **The unretrofittable schema bundle** — `shape_id`, per-attempt block, `family_version`, `rustc`, `vendor_set_hash`, `first_failing_input`, `property_results`, `clippy_lints` | [14](14-roadmap.md) sequencing rule 1: *"Schema decisions before code… cheap now and expensive later."* ~1 day against a full-corpus re-run later |
| 3 | **Results-corpus licence + consent grant + `terms_version`/`terms_hash`** | §5. The only item with a hard, unrecoverable deadline |
| 4 | **Add `doctor`, `ab`, `config-audit` and `report` to [08](08-run-protocol.md)'s CLI surface and to roadmap phases** | One row in the "Edits this document forces elsewhere" table [15](15-profiles-and-divisions.md) §11.9 already maintains. Pure documentation hygiene; it is how good features quietly fail to ship |
| 5 | **Ship `doctor` standalone as public v0.1**, with `--fix` and `--json` | It needs only P0's model client plus HTTP probing — no oracle, no corpus, no sandbox. LocalScore bootstrapped its database by shipping a minutes-long tool before it had one. This is the project's only adoption hook that works before any benchmark exists |
| 6 | **Value-per-hour table in the README, and an honest pre-run session estimate** | `doctor` already prints *"Estimated 44.5 h for `deep`"*; add *"≈ 30 evening sessions at your `--max-duration`"* and the ladder: 15 min → your machine's calibration and throttle curve; 90 min → `doctor` plus one `ab` factor; 11.7 h → eight categories directional; 44.5 h → a ranked row. Free, and it reframes `ab` as the 1-hour product |
| 7 | **Errata policy for published epochs** | Retraction runs in exactly one direction today (T3 failure retracts the *submitter's* material). There is no mechanism for the *project* being wrong — and the repo's own record says that is the expected case: [10](10-integrity.md):97 carries a struck-through claim marked *"This claim is false and is retracted"*, and R5 produced 58 findings, 21 severe, invalidating R4's pairing result. Every one of those corrections was free because it happened pre-publication. **A silently re-issued dump is strictly worse than a wrong dump — it destroys the audit trail the whole trust argument rests on.** Epoch dumps immutable; corrections as a sibling `corrections-<epoch>.jsonl` with `supersedes`, reason code and date; a visible marker on corrected rows, same philosophy as tainted rows struck through rather than hidden. ~1 day of policy plus one schema field, and impossible to retrofit once third parties have cached a dump |
| 8 | **A one-page GOVERNANCE.md** | Zero occurrences of governance, dispute, arbitration, appeal, succession, or CONTRIBUTING. Two live exposures, not hypotheticals. (a) T3 says audit selection is *"one selected by the review committee"* and a failed audit *"retracts published material"* — while [15](15-profiles-and-divisions.md):139 states the project **has no committee** (*"a 1-FTE hobbyist leaderboard converts every gate into a bounce"*). A process with reputational consequences has no owner. (b) [15](15-profiles-and-divisions.md) §10.2 adopts a **Hacks/Flags column** — publishing an integrity finding against a named submission, with no defined appeal path. Cover: decision rights (benevolent dictator is a fine answer, but state it); family acceptance beyond the mechanical gates; a dispute path (submitter may respond, response published alongside, findings dated and correctable); retraction with a named decider; what happens to the corpus, the signing keys and the domain if the project stops. ~1 day. Must predate the first dispute to be credible |

### DO LATER

| # | Area | Verdict and gate |
|---|---|---|
| 9 | Energy + TTFT collection (§3b 8, 9) | **P1**, so P5's first report can carry them. `efficiency_score` is a README headline promise with no data path |
| 10 | `rustybench dump pull\|query` + `rederive` + the reference notebook | **P6.** One dump reader unlocks every corpus-facing feature at once |
| 11 | **Frozen anchor set for cross-epoch equating** | **Decide at P5, implement at P6.** See §8. Must be chosen before the first epoch closes — an anchor set retrofitted after two epochs cannot recover the history |
| 12 | `machine_pseudonym` + opt-in `lineage_id` + timestamp coarsening | **Decide now with the consent text (§3 item 3), ship at P6** |
| 13 | Coverage matrix / "most wanted configurations" board + a duplicate-run preflight | **P6.** Cheap (a coverage query plus one view) and the strongest non-monetary incentive available: it converts an anonymous 44-hour donation into a named contribution with visible scarcity. **Note the interaction nobody flagged:** a mid-epoch "17 rows already exist for this configuration" endpoint discloses in-epoch submission state, which the epoch embargo exists to withhold. Coverage counts are not seeds, so this is not fatal, but it needs an explicit answer in [10](10-integrity.md), not a flag |
| 14 | `replication_rate` and the leaderboard dedupe policy | **Decide before the board ships** or the sample is destroyed as it arrives (§3c). Implementation is server-side aggregation, zero client change |
| 15 | Zenodo + HF mirror, DOI, datasheet, CITATION.cff, Croissant, release notes | **P6**, format decided now (§6). Also the succession plan |
| 16 | `rustybench advise` | **P7+, gated on `ab --factor exec-class` ([15](15-profiles-and-divisions.md) §12.4).** Until that measurement exists, `advise` can only rank capability within the asker's own `exec_class` — and the 8–16 GB `Hybrid` band it exists to serve is exactly where the effect is unmeasured. Ship the honest subset first (fits-in-memory + predicted tok/s from local calibration + capability *where a row exists in your class*), and say plainly which of the three is which |
| 17 | `ab --factor context` and `--factor template` | **P5/P6.** [05](05-hardware-and-calibration.md) calls context *the single largest measured effect in the whole design space* (19.5 points) and the design **imports someone else's Python-adjacent number and never produces its own**. [06](06-execution-classes.md) already establishes that changing `-c` within native context gives bit-identical greedy completions, so it is a clean single-factor experiment. [15](15-profiles-and-divisions.md) §12.3 already calls template the biggest evidence gap |
| 18 | Prior-art additions | **Fold into the P5 report write-up.** Two matter: Stanford's *Intelligence per Watt* (arXiv 2511.07885 — 20+ local LMs × 8 accelerators × 1M queries, decomposing a 5.3× 2023–2025 efficiency gain into 3.1× model and 1.7× accelerator) is the closest published neighbour to the hardware half of the thesis and shipped first; and Epoch AI's Capabilities Index is the off-the-shelf method for §8's equating problem. A reviewer who knows the neighbour and does not see it cited discounts everything else |

### EXPLICITLY OUT OF SCOPE — and where to write it down

| Area | Verdict | Write it in |
|---|---|---|
| **Publishing model outputs, failing or passing** | OUT. §4. Strengthen the existing sentence rather than adding a consent | [00](00-overview.md) non-goals |
| **A blind holdout category** | OUT. It breaks the independent re-derivation property [11](11-submission-and-privacy.md) calls *"the strongest integrity mechanism available"* and the LICENSE is written to protect | A new ADR, so the rejection is recorded rather than left as an unconsidered option |
| **Fixed-forever "sentinel" seeds** | OUT. Superseded by §8's construction (frozen *families*, fresh seeds), which achieves the same equating property, preserves contamination resistance completely, and needs no [ADR-0009](adr/0009-paired-core-and-fresh-probe-seeds.md) exception | Same ADR as the anchor set |
| **Publishing rustc message text** | OUT until [15](15-profiles-and-divisions.md) §12.14 converts redaction from a denylist to an allowlist | [11](11-submission-and-privacy.md) redaction rules |
| **A hardware-only leaderboard fed by `smoke`** | OUT. Two independent reasons: `throughput_score` is `tasks_passed/hour`, a joint model×machine quantity — there is no hardware-only number to board; and it would compete directly with LocalScore, which is purpose-built, free, runs in minutes, publishes TTFT, and already has the public DB. A 55-minute Rust suite producing a worse LocalScore is not a differentiator | [06](06-execution-classes.md) leaderboard policy |
| **A human baseline** | OUT. Needs the anchor set first, needs recruiting 3–5 Rust developers, and produces a band uninterpretable against ±10.7% per-category CIs that Q24 says no core category currently reaches | [00](00-overview.md) non-goals |
| **A funded, project-owned reference rig** | OUT. A hardware purchase and an ops commitment for a project with no funding line in any document | [14](14-roadmap.md) assumptions |
| **`rustybench ci` + a GitHub Action** | OUT for v1. The audience (fine-tuners gating a LoRA) is small and `ab --factor` already *is* a paired regression test. Keep only the free part: document exit codes and a stable JSON contract as a supported interface | [14](14-roadmap.md) |
| **`run --budget 3h` (information-gain item selection)** | OUT for v1. Depends on IRT parameters that only exist at P8, and the crude fallback needs the dump. Ship the value-per-hour table (DO NOW #6) instead — it delivers most of the honesty at none of the cost | [07](07-statistics.md) |
| **A lower ranked tier for hardware where `deep` is infeasible** | OUT until **G2 (ICC) is measured**. Sizing policy cannot be revised against an unmeasured constant, and the change touches [07](07-statistics.md)'s leaderboard policy and [04](04-categories.md)'s denominator rule. Premature by two gates. Revisit as an ADR after G2 | [07](07-statistics.md) |
| **Hosted-model reference anchors** | Not out of scope — **it is Q9**, already open, already scoped to "Phase 5 report framing", already carrying a stated lean. Close Q9; do not open a parallel design | [OPEN-QUESTIONS](OPEN-QUESTIONS.md) Q9 |

---

## 8. Longitudinal value, and what must be held fixed

Zero occurrences repo-wide of longitudinal, trend, time-series, equating, or anchor-set. There is no design for comparing epoch N to epoch N+12.

**Seed rotation is not the problem.** Seeds within a family are exchangeable draws from the same generator, so a family-level score *is* comparable across epochs. Three other things break the series:

1. **The corpus grows.** 120 families at P5 → 272 at P7 over 12–30 months. `capability_score` is an equal-weight mean over category means, and each category mean is over whatever families exist that month. Growing `borrow-lifetimes` from 24 to 40 families changes the **estimand**, not just the variance. [07](07-statistics.md) already caught this failure mode once across *tiers* — *"`standard` and `deep` do not compute `capability_score` over the same category set, so their headline numbers are not directly comparable"* — and did not generalise it across *time*.
2. **`generator_commit` and `suite_hash` are row-key components**, so any generator edit silently moves family difficulty, and with no `family_version` the edited family is pooled with its old self.
3. **No `rustc_version`, no `vendor_set_hash`.** The entire L1 oracle is rustc diagnostics and `error_histogram` is keyed on rustc error codes. E0499 counts in 2026-08 and 2027-08 are not the same measurement.

**The construction: a frozen anchor set.** Classical common-item nonequivalent-groups equating; Epoch AI's Capabilities Index uses exactly this (IRT plus anchor-fixing) because most benchmarks saturate too fast to study long-run trends.

- **30–40 families, stratified across categories.** Equating guidance is 10–20 common items minimum, more when content coverage matters; 11 categories forces the upper end. Draw them from P5's 120.
- **Held fixed for a stated 12-month horizon:** the anchor families' `task.toml` and generator code, `generator_commit`, the vendored crate set (`vendor_set_hash`), the rustc channel, the prompt pack, the sampling profile, per-category oracle weights, and the category definitions.
- **Fresh seeds every epoch.** This preserves contamination resistance completely, at zero cost to equating — which is why it strictly dominates a fixed-seed sentinel set and needs no [ADR-0009](adr/0009-paired-core-and-fresh-probe-seeds.md) exception.
- **Publish `capability_score_anchor` beside `capability_score`,** required on every ranked row. Trend lines are drawn on the anchor score; the growing corpus improves precision without moving the origin.
- **Non-anchor families link to the anchor scale via shared submitters,** so corpus growth is absorbed rather than confounding.
- **Version resets are announced as a break in the series,** never as a silent migration.

**Also required for any within-machine time contrast:** the `machine_pseudonym` from §3b item 11. `backend_version` is deliberately excluded from the row key (*"62 releases in 7 days ⇒ singleton cells"*) — correct for ranking, and it makes the longitudinal path the only remaining home for the ecosystem's most frequent change. This is the same field [15](15-profiles-and-divisions.md) §10.3's own backend release criterion depends on, so it pays twice.

**Honest contingencies.** The anchor set cannot be sized before **Q24** (shape audit) tells us how many distinct shapes each category actually has, and its precision cannot be stated before **G2** (ICC). Both are already blocking gates. The anchor set is therefore a P5 decision, not a P0 one — but the *fields* it needs (`family_version`, `rustc`, `vendor_set_hash`, `shape_id`) are P0, because they cannot be retrofitted.

**A claim to demote explicitly.** *"Which Rust skills improve fastest"* is the most tempting longitudinal headline and the least supportable: core-category CI is ±10.7% at best, Q24 says no core category reaches it, so a year-over-year per-category delta below ~15 points is unclaimable at any corpus size without equating **plus** a paired cross-epoch estimator. Write it down as a 24-month goal contingent on the anchor set, not as a P5 result.

---

## 9. Minimum viable dataset

No document sizes precision **across** runs. [07](07-statistics.md) does it beautifully within one run. These numbers are derived from figures already in the docs; put them in [07](07-statistics.md) as a new section.

| Claim | Requirement | Cost | Status |
|---|---|---|---|
| **Model A beats model B on Rust** (one machine, one epoch, one exec_class) | 2 models × 1 `deep` each, shared core seed set, McNemar on discordant pairs | ~89 GPU-h | **Supportable at P5.** This is the design's strongest and least-advertised property and it needs essentially no corpus. Say so in the README. Caveat honestly: per-core-category ±10.7% is the *design target*, and Q24 says no category currently reaches it |
| **Cross-backend offset δ, to the ≤1.0pp threshold that frees the backend** | ~3,842 paired units. [15](15-profiles-and-divisions.md) §10.3's own arithmetic: one `deep` pair gives ±1.9pp (±2.59pp after clustering); **ten submitters running a `standard` A/B (4,160 units) reach ±0.96pp** | ~330 volunteer GPU-h | Multi-submitter by construction — *"that is a feature, because it makes the leaderboard its own instrument."* Requires the machine grouping key (§3b 11) |
| **A hardware/throughput cell median at ±10%** | `hw_class × exec_class × model × quant`; tg128 is flagged unstable beyond ±10% ([05](05-hardware-and-calibration.md)), so at ~10% within-cell CV, n≈4 machines for ±10%, n≈16 for ±5% | — | — |
| **A usefully populated hardware board** | 8 hw_classes × 3 exec_classes × 5 popular models × 2 quant classes = **240 cells**; ~960 runs at n=4 | **~43,000 GPU-h at `deep`** | **Unreachable.** This is the number that settles §7 item 16: the throughput half of any advice must come from *predicting* from local calibration, never from waiting for cells to fill |
| **Longitudinal slope, 10 points/year at 80% power** | ~12 epochs at ≥3 runs/epoch of the same model on the anchor set at ±4.9% | — | Practically: one reference model run repeatedly on continuously-owned hardware for 12 months. Since §7 rules out a funded rig, this depends on a repeat volunteer — which is itself an argument for `docs/16` |
| **Contamination cliff** | ≥6 models, 3 either side of a training cutoff, on ≥2 closed epochs; requires `model.release_date` | Low | Needs one schema field and a decision to retain closed epochs' seed sets deliberately |

**The calibration that should anchor expectations:** MLPerf Training v6.0 — fully corporate-funded, with a submission committee and paying members — drew **95 system submissions from 24 organisations**. Treat ~95 `deep`-equivalents per epoch as an optimistic *ceiling* for a hobbyist project, not a floor.

**Add a participation gate to [14](14-roadmap.md)'s kill-gate table**, in the same style as G1–G5: *G6 — if epoch 1 draws fewer than N submissions across fewer than M hardware classes, the leaderboard is deferred and the project stays a report.* [14](14-roadmap.md) already sets numeric thresholds in advance for everything else *"so a bad result triggers a decision rather than being absorbed as slippage"* — participation is the one variable with no gate, and it is the one the whole public-benefit half depends on.

---

## 10. The three things to do first, and what to refuse

### First

**1. Write `docs/16` — the run report — and put `bench-report` in a roadmap phase.**
The complete current spec of what a person receives after 44.5 hours is one CLI line and eleven words, while the leaderboard row gets 726 lines. Every input already exists in `journal.jsonl` and `report.json`; zero new collection. Verdict paragraph before table; plain-language failure mode; local `first_failing_input` and reference implementation for failed units; dot plot with CI bars instead of the radar; CI-overlapping categories rendered as tied; `rustybench compare` for the one experiment a user can afford. P5 exit criterion: a naive reader can state one thing the run proves and one thing it does not. *~2–3 days to spec, 1–2 weeks to build.*

**2. Close the unretrofittable schema gaps — one day of work.**
`shape_id`, per-attempt `attempts[]`, `family_version`, `rustc{version,channel,commit}`, `vendor_set_hash`, `first_failing_input`, `property_results[]`, `clippy_lints[]`. Plus the `plan.variance[]` decision (schema it or delete the probe and reclaim 5% of every run).
`shape_id` is the sharpest: [07](07-statistics.md):84 makes the bootstrap resample **shapes**, no schema carries a shape key, so a third party with the dump and the open-sourced aggregator can recompute point estimates but **not one published confidence interval** — they get intervals ~40% too narrow. That falsifies the re-derivation claim [11](11-submission-and-privacy.md) calls the strongest integrity mechanism available, and it is P6's own stated exit criterion. It also rides on Q24, which is already blocking: one field, two purposes.
Per-attempt is a **serialisation** decision over data already in memory ([03](03-oracle.md) grades both attempts; the journal writes one line), and it unlocks the most citable result available — *which rustc error classes does compiler feedback actually fix* — which only this design can answer, because [03](03-oracle.md) pins the feedback content and varies only the model. Roughly a third of a `deep` run's wall clock is the repair turn and its return is currently unrecoverable from the corpus.
*Sequencing rule 1, with the reserved IRT block as the precedent the project already accepted.*

**3. Settle the results-corpus licence and the consent grant.**
`DATA-LICENSE.md` → CC BY 4.0, stated as not covering the harness. One sentence appended to consent #1 conveying the onward-licence grant. `terms_version` + `terms_hash` in the signed `consents` block. A harness test asserting the consent text names the licence. Apache-2.0 on the aggregator/verifier/dump-reader/schema subtree. Consider the PolyForm carve-out for leaderboard-submission runs.
*An afternoon. The only item with a hard, unrecoverable deadline — Q23 records no accounts and `machine_uuid` links to no contactable identity, so there is nobody to go back and ask.*

**Too cheap to rank, just do it alongside:** add `doctor`, `ab`, `config-audit` and `report` to [08](08-run-protocol.md)'s CLI surface and to roadmap phases — one row in the table [15](15-profiles-and-divisions.md) §11.9 already maintains — and ship `doctor` standalone as public v0.1.

### Refuse

- **`advise` before `ab --factor exec-class` is measured.** [06](06-execution-classes.md):65 is a recorded reversal with measurements behind it. Building an advisor on the premise it withdrew reintroduces the error the project already corrected.
- **A hardware-only leaderboard.** `throughput_score` is joint, and it would be a worse LocalScore.
- **Publishing model outputs, failing or passing.** Post-epoch the instance is reconstructible; a failure corpus is a labelled training set for exactly the measured capability.
- **A blind holdout category, and fixed-forever sentinel seeds.** The first breaks re-derivability; the second is strictly dominated by the anchor set.
- **Publishing rustc message text** before [15](15-profiles-and-divisions.md) §12.14 lands.
- **A human baseline, a funded reference rig, a CI action, a `--budget` run mode, and a lower ranked tier before G2.** Each is defensible in isolation and none survives a 1-FTE / 272-family / 1-to-3-year budget. Write each into a non-goals or assumptions section so the refusal is a recorded decision rather than a recurring conversation.
- **Any new engineering on the probe, batch nonces, or seed secrecy** — including `capability_score_fresh` — until **Q22 (ρ)** exists. [OPEN-QUESTIONS](OPEN-QUESTIONS.md) already says this; the point here is that §3c's free probe-scoring value does not license an exception.

---

## 11. Open questions, and what closes each

| # | Question | What closes it |
|---|---|---|
| 1 | Does `capability_score` transfer across machines *within* an `exec_class`? | **`rustybench ab --factor exec-class`** ([15](15-profiles-and-divisions.md) §12.4), composed with Q22 for one extra pass. Closes when the paired flip rate and signed delta across `GpuFull`/`Hybrid` are bounded. **Gates `advise`, the coverage matrix's usefulness, and the whole "everyone else benefits" claim for the 8–16 GB band** |
| 2 | How many distinct shapes does each core category actually have? | **Q24**, already blocking. Also fixes the `shape_id` taxonomy and sizes the anchor set. Until it lands, no core category's ±10.7% claim is standing |
| 3 | ρ — the model × instance interaction | **Q22**, already blocking, measured free in P3.5 from runs already planned. Decides whether family-level pairing works, and whether nine of R5's severe findings dissolve |
| 4 | ICC | **G2**, end of P3.5. Blocks every tier and sizing policy change, including §7's rejected lower ranked tier |
| 5 | Does a 44.5-hour run fit inside a monthly epoch? | Compute evenings-to-completion per hardware class from [07](07-statistics.md)'s cost model and the user's own calibration, and publish it. Then decide one of: lengthen epochs; accept cross-epoch runs for the throughput half; or add a rule that a run started inside an epoch stays valid for it. Make `status` show remaining epoch time beside remaining run time. **The user most valuable to this project — a laptop owner in an underrepresented band, running honestly in evening slices — is the one most exposed to spending 40 evenings and getting a tainted or expired result** ([09](09-resume-and-checkpointing.md) makes an `identity` mismatch on resume fatal unless `--force-heterogeneous`, which taints irreversibly). Closes Q10 with an actual number |
| 6 | Are duplicate row keys shown, aggregated, or collapsed? | A leaderboard presentation decision, **before the board ships**. Collapsing destroys the `replication_rate` sample as it arrives, and that statistic is the cheapest credibility asset the project has: zero compute, zero client change |
| 7 | Does the 5%-of-runtime variance probe get a schema, or get deleted? | A one-line decision in [07](07-statistics.md). Either add `plan.variance[]` + `sample_index` + `pass_at_5`, or reclaim ~2.2 h per `deep` run for families — which [ADR-0006](adr/0006-breadth-over-depth-in-sampling.md) says is the better spend anyway. **The current state — spending the compute and having nowhere to put the output — is the only unacceptable one** |
| 8 | Can aggregates publish live while seeds stay embargoed to epoch close? | The precomputation threat in [11](11-submission-and-privacy.md) is specifically about *seeds*, not aggregates. If yes, a submitter's contribution becomes visible in days rather than up to a month, and the coverage board works mid-epoch. Needs a real answer in [10](10-integrity.md), not a flag |
| 9 | Machine pseudonym vs timestamp coarsening | Decide **as one value/privacy trade**, alongside the consent text. The obvious privacy patch alone deletes the instrument [15](15-profiles-and-divisions.md) §10.3's release criterion depends on |
| 10 | PolyForm carve-out for leaderboard-submission runs | A licence decision, not engineering. Closes when the trade is stated: reopening vendor-run rows for new hardware, versus the private-internal-evaluation segment Q1 says the NC decision was protecting |
| 11 | macOS power telemetry | **Q8, narrowed**: not "can we measure power" but "is a one-time privileged helper install acceptable". On Linux/NVIDIA the answer is already yes and needs no user action — ship there first and let macOS follow |
| 12 | Who plays the T3 "review committee"? | Either name the role or downgrade T3 to *deferred until a second maintainer exists* — which [10](10-integrity.md):139 already half-says (*"Worth building only once there are reputations on the line"*). Closes with the GOVERNANCE.md one-pager |

---

**Sources cited beyond the repo:** HF dataset API for `lmarena-ai/leaderboard-dataset` (cc-by-4.0, 38,816 downloads) and `open-llm-leaderboard/contents` (no card licence, 17,370 downloads), both queried 2026-08-19 · [localscore.ai/about](https://www.localscore.ai/about) · [builders.mozilla.org/announcing-localscore](https://builders.mozilla.org/announcing-localscore/) · [phoronix-test-suite.com](https://phoronix-test-suite.com/?k=features) · [github.com/ggml-org/llama.cpp/discussions/4167](https://github.com/ggml-org/llama.cpp/discussions/4167) · [apxml.com/tools/vram-calculator](https://apxml.com/tools/vram-calculator) · [sitepoint.com q4-vs-q6-vs-q8](https://www.sitepoint.com/q4-vs-q6-vs-q8-quantization-local-llms/) · [insiderllm.com/blog/llm-benchmarks-lie-local-ai](https://insiderllm.com/blog/llm-benchmarks-lie-local-ai/) · Stanford *Intelligence per Watt*, arXiv 2511.07885 · Gebru et al., *Datasheets for Datasets*, CACM 2021 · Data Provenance Initiative, *Nature Machine Intelligence* 2024 · MLPerf Training v6.0 results and MLCommons results-messaging guidelines · Epoch AI Capabilities Index.
