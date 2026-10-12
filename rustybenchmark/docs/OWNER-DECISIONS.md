# Owner decisions — digest (2026-10-06)

Every open decision that blocks or shapes work, drawn from [OPEN-QUESTIONS.md](OPEN-QUESTIONS.md) (Q-numbers
below) and the BUILD-LOG entries of both agents. Nothing here is a new question: each cites where it is
recorded. "Effort" is rough engineering time *after* the decision, assuming one person.

## Answer these five first

| # | Decision (one sentence) | My recommendation, and why | Unblocks | Effort |
|---|---|---|---|---|
| 1 | **Q22:** Run the two-model ρ measurement now (how much instance difficulty is model-specific)? | **Yes.** It is cheap (the Phase 3.5 runs are already planned), and Q22 itself says no probe/nonce/secrecy engineering until the number exists; ρ ≥ 0.5 would dissolve Q13/Q16/Q19 and 9 of round 5's 21 severe findings. | Every secrecy decision (Q19, Q23, Q34 #1-2) | 1-2 days of quiet-machine time + 1 day analysis |
| 2 | **Q32 #1 / Q23:** Is there a submission server, or is v0 a file (the bundle) sent by PR/issue to a results repo? | **File-based T0 for v0.** No identity problem (Q23), no server (docs/11 says "do not build until the local runner is good"), and `verify-bundle` already lets CI check a bundle with no trust in the submitter. | Any public leaderboard | 2-3 days (CI check around `rustybench verify-bundle`, results-repo layout) |
| 3 | **Q32 #2-3:** Approve the draft consent text and CC BY 4.0 grant (`crates/bench-submit/src/consent.rs`), and say whether consents 1/2 are really separable (REVIEW-5 `consent-two-is-mandatory`)? | **Approve after one external legal read** (UK database rights, [DATA-LICENSE.md](../DATA-LICENSE.md)); DATA-LICENSE.md says the grant must exist *before the first accepted submission* because there is nobody to ask later. For v0 (T0 only, no replay artifacts) show consent 1 only and say ranked rows will need consent 2. | First accepted submission | ~1 h of yours + the legal read; 1 day to apply wording |
| 4 | **Q26:** Delete the plausibility checks (R5-S5) and say hardware numbers are unverified, or give each an external anchor? | **Delete, and say so.** They are invariant to time rescaling and would flag 33-64% of honest laptop runs (Q26); [10-integrity.md](10-integrity.md) already says throughput is never verifiable. Nothing was built on them, so it costs only doc edits. | Phase 6 scope; stops anyone building dead checks | 0.5 day of doc edits |
| 5 | **Q34 #1-5:** What is a v0 `plan.json`/`state.json`: public-label plan (no `epoch_seed`), `suite_hash` = hash of what, `generator_commit` from where? | **v0 writes a plan with the public epoch label and derived seeds (no secret), `suite_hash` over the ordered family ids, `generator_commit` from a build-time git hash.** It is honest about today's seed derivation (`derive_seed(epoch_label, ...)`, public) and unlocks the remaining docs/09 resume gates; the secret-seed design waits on #1. | `plan_hash`/`suite_hash`/`generator_commit`/ctx/ngl/sampling/exec_class gates; the `unrecorded` list in every bundle | 2-3 days with red tests |

## A. Blocks building now

| Decision | Options → recommendation | Blocks | Effort |
|---|---|---|---|
| **Q33 #4:** formulas from L4 ratios to `[0,1]` scores ([03-oracle.md](03-oracle.md) §L4 gives weights but no formula) | Define (a) kill fraction as-is, (b) size ratio ≤ 1 → 1, ≥ `max_ratio` → 0 linear, (c) perf: see next. → **(a)+(b) only.** Both are exact and re-derivable. | Wiring any L4 figure into a score; `test-authoring` weights (docs/04: quality 0.70) | 0.5 day |
| **Q33 #1:** perf (criterion) — drop, keep as a hardware-gated T0 figure, or a deterministic proxy | → **Drop for now.** Gated on `GpuFull` (a CPU benchmark on GPU class; collides with R6-S5's free-text `exec_class`), needs a <5% variance precheck, no deterministic proxy exists; allocation is already exact in L3. | `perf-optimization` category | 0.5 day to delete; days to do properly |
| **Q33 #2-3:** delete docs/03's "other categories" mutation sentence; accept "denominator = mutants the hidden tests kill" | → **Delete the sentence; accept the denominator** (it scores the model, not the oracle; a perfect suite scores 1.0). Add a minimum-killable floor when wiring. | Wiring mutation into `test-authoring` (no such family exists yet) | 0.5 day |
| **Q32 #4-5:** add an ed25519 crate and an encryption crate, or stay unsigned/no replay artifacts | → **Neither yet.** An embedded key proves nothing (docs/10 T0); encryption needs a server key that does not exist (#2). Add both together when a server exists. | T1 replay; signed manifests | 1-2 days incl. key policy |
| **Q32 #6:** how a replaying server gets seeds when the bundle omits them (task ids embed the seed) | Derive server-side (needs non-public seeds: Q22) or ship in the encrypted channel (needs #4). → **Wait for #1.** | T1 replay verification | depends on #1 |
| **Q28 follow-up:** should behaviour be a *floor* rather than a weighted term? | Evidence: BUILD-LOG 2026-08-19 (a logically wrong in-place answer, 0.689, outscored a correct allocating one, 0.389) and the `idiom-api` `allow` cheat (0.333). → **Keep structural pass as is (decided); revisit weights after real runs.** | Nothing now | — |
| **Q24:** shape-count audit before scaling the corpus | → **Do per category before authoring more** (two-level bootstrap is not built; `idiom-refactor` is crossed, not nested). | Corpus scale-up | 3-5 days |

## B. Blocks shipping

| Decision | Options → recommendation | Blocks | Effort |
|---|---|---|---|
| **Q23:** submitter identity/auth | None (T0 file submissions) / accounts / signed tokens. → **None for v0** (#2); revisit with a server. | Rate limits, deletion (`forget`), T3 contact | days-weeks later |
| **Q32 #7:** raw calibration numbers in a bundle | Omit / bucket / publish. → **Bucket coarsely, or omit until the plausibility decision (#4) is made**: R5-S6 says raw numbers defeat hardware bucketing. | Throughput on the leaderboard | 0.5 day |
| **Q32 #8:** keep `segment`/`segment_position` (reveal session count) and omit `machine_uuid`/timestamps | → **Keep segments (needed for the warm-up exclusion), keep omitting the rest.** | Privacy sign-off | 0 |
| **Q32 #10:** canonical model identity (today a free-text `--model-name`) | Hash of the weights file / registry id. → **Hash of the GGUF when local; record both.** | Ranking joins | 1 day |
| **Q21 / Q25:** is the mined `wild` suite worth keeping (62-69% of qualifying crates have the oracle in the edited file; licences) | Drop / permissive-only + extracted oracle / fetch recipes. → **Drop.** It also closes Q21 and removes the long pole in P7. | Phase 7 plan | 0.5 day to record |
| **Q1 (mined corpus):** licence for mined families | Closed if Q25 → drop. | Publishing mined families | — |

## C. Can wait

- **Q34 #7-11 (scheduling readings):** `--idle-only` undefined; `exit_reason` has no `max_units`; `--max-units` per session; `--max-duration` monotonic, `--until` wall clock via `date`; `--pause-on-battery` also refuses to start. → accept as built, define "idle" only if someone asks. (OPEN-QUESTIONS Q34.)
- **Q32 #14:** consent file at `runs/consent.json` vs a per-user path → per-user later; one-line change.
- **Q33 #5:** claim that the mutator makes mutation replayable (T0 → T1)? → do not claim until a real `test-authoring` family exists.
- **Q10** epoch length: monthly working assumption; revisit with submission data. **Q5** quantisation: [15-profiles-and-divisions.md](15-profiles-and-divisions.md) §11.8 already answers it (two-class row-key field); close the entry. **Q30** anti-twin floor: provisional floor of 8 is enforced in CI; tune with real data.
- **Windows/Linux:** Windows sandbox parity is Q7, `bench-sandbox` reports `Unsupported` off macOS, no Linux battery probe, signal/lock logic Unix-only. Fine until a non-Mac user exists.

## Branch state (nothing is pushed)

Both branches are local only: `git branch -r --contains` finds neither on any remote; the worktrees share one
object store and the repo's `core.bare`/`core.worktree` config is still the broken pair (not edited).

- **A — `bench/agent-2026-10-05`** (tip `b16a93d` at last look): generator families (118 + `idiom-ptr`), per-thread allocation probes, `validate-family --cover/--from`, `emit`, class-scoped throughput, pre-run gates (`--ignore-gates`, `--require-ac`, `--min-free-disk-gib`), the registry sweep (3,543 seeds, one real bug fixed).
- **B — `bench/agent-b-2026-10-05`** (tip `beae49d`): everything in A up to `5237ed0` plus `bench-submit` (export/verify/consent), `bench-model` hardening + mock server, `calibrate`, L4 mutator + `size_ratio`, docs/09 crash safety (journal recovery, lock, resume gates, SIGINT/SIGTERM, scheduling controls), `grade()` target-dir pin, and Q32-Q34.
- **Merge order:** (1) merge A's newest commits into B once more (`5237ed0` → `b16a93d`+; they touch only `bench-gen`, `README.md`, `docs/BUILD-LOG.md`, so expect only BUILD-LOG, possibly README); (2) then take B into the integration branch (fast-forward of A's history plus B). Re-run `cargo test --workspace`, `clippy -D warnings`, `fmt --check`, `cargo deny check bans sources`, and `crates/bench-cli/tests/resume.rs`.
- **Known conflict points:** `docs/BUILD-LOG.md` (both prepend; keep both), `crates/bench-cli/src/main.rs` (the `RunSuite` args and arm: A's gate flags next to B's `--force-heterogeneous` and scheduling flags; resolved once already, order = A's environment gates, then B's lock/repair/identity gate), `docs/OPEN-QUESTIONS.md` (both append: B uses Q32-Q34; renumber if A adds one), `crates/bench-hw/src/lib.rs` and `crates/bench-oracle/src/lib.rs` (B adds `pub mod` lines; A's `bench-oracle` allocation edits are in `bench-gen`, not here).
- **Rule exceptions to surface:** one scoped `unsafe` (`signal(2)` in `bench-sandbox`, same kind as its `setrlimit`/`kill`); `bench-hw` now depends on `bench-model`; `bench-oracle` gained `proc-macro2` (feature `span-locations`, already in the lockfile).
