# 10 — Integrity

## The honest starting point

**Client-side attestation cannot be made sound.** The attacker owns the machine. Hash the binary, embed a signing key, sign the payload — they patch the binary, or extract the key with a debugger and sign whatever they like. Every "only submittable through the program" scheme is obfuscation, not security.

Build it anyway as a speed bump against casual tampering. Design assuming it will be broken.

This is not theoretical. Terminal-Bench found real leaderboard misconduct: one submission **stored encrypted solutions inside the agent binary** and modified timeouts; another **shipped the task test folder** in the agent setup; a third had the agent **fetch solutions from the internet**. All three passed submission until humans looked, and all three were surfaced by independent community analysis of published data.

## The asymmetry we have and most benchmarks do not

Split claims by verifiability:

| Claim | Verifiable? | Mechanism |
|---|---|---|
| "The model produced this code" | **No** | Unfalsifiable in principle |
| **"This code scores 0.83 on task X seed Y"** | **Yes, exactly** | Oracle is deterministic → server re-grades |
| **"These are the tasks I was given"** | **Yes** | Server issues the seeds |
| "This ran on an RTX 4090 at 41 tok/s" | **No** | Plausibility-checkable only |

That split is the whole design. **Correctness is fully verifiable server-side**, because the oracle is deterministic and instances are server-seeded. **Hardware throughput is never verifiable.** Publish them as two different things, with two different confidence labels. Never blend them into one trust-me number.

## Trust tiers

Every leaderboard row is labelled with its tier.

### T0 — Self-reported

Client computes scores, signs with an embedded key, uploads. Verifies nothing. Grey badge. Useful for volume ("I tried this on my laptop"); never headline. This is what offline/local runs get.

### T1 — Replayed

Client uploads the model's raw output artifacts alongside the scores. The server re-materialises each
instance from its seed, **runs the identical oracle over the submitted output** in its own sandbox,
and compares scores. Any mismatch → rejected and flagged.

> **Replay never regenerates the model output, and cannot.** Greedy generation is not reproducible
> across execution classes: the same model, quant, seed and sampling gave **7/7 byte-different**
> completions at `-ngl 0` versus `-ngl 99`, and KV-cache quantisation changed output on 4/7. A grader
> on different hardware would fail to reproduce honest submissions. Replay verifies *"this output
> scores what you claimed"*, never *"this output is what the model would emit"*. The natural reading
> of the old wording was the second, and it is unimplementable.

**This eliminates fabrication of L0–L3 scores entirely.** It costs the server CPU and nothing else. It is the single highest-leverage control in the system.

**Boundary: L4 cannot be replayed.** Criterion timings are hardware-dependent by design and cargo-mutants is not deterministic, so the server cannot reproduce L4 numbers. Replay therefore verifies **L0–L3 exactly** and subjects **L4 to plausibility bounds only**. L4's contribution to any score is labelled at T0 confidence even inside a T2 row. Categories whose oracle is L4-dominant — `perf-optimization`, `test-authoring` — are consequently the least verifiable in the suite, which is one reason both are probe rather than core categories.

### T2 — Challenged

Every epoch issues **two disjoint seed sets**, because a single derivation cannot serve both pairing and freshness — see [ADR-0009](adr/0009-paired-core-and-fresh-probe-seeds.md).

```
paired core  (~85%, scored)      seed = blake3(epoch_seed  || task_id || i)[..8]
fresh probe  (~15%, never scored) seed = blake3(batch_nonce || task_id || i)[..8]
```

The **core** is identical for every submitter in the epoch, which is what makes McNemar pairing — and therefore the affordable suite sizes in [07-statistics.md](07-statistics.md) — possible at all.

The **probe** uses a per-batch nonce that did not exist before the request, so precomputed or binary-embedded solutions cannot apply to it. It is a **detector**, not a score:

```
precompute_signal = sign_test(family-paired core-vs-probe discordance)
```

Under honest execution the discordance is symmetric. Precomputation makes it one-directional.

**The probe is a screening test, not a control, and its failure mode is measured.** An adversary who
precomputes *and then deliberately fails core units they could have passed* rebalances the
discordance and becomes invisible: at 20% precomputation, simulation shows **+9 to +10 points of
inflation retained at 0% detection**. Neither family-aggregate pairing nor probe/core
indistinguishability fixes it. The reason is structural — the cheat pays off across 1088 core units
while the detector observes 163 family-level pairs, so hiding is ~6.7× cheaper than the gain, and no
choice of test statistic changes that ratio.

**The primary control against precomputation is therefore seed secrecy** (see below), not the probe.
The probe catches unsophisticated precomputation and nothing more. See [REVIEW-4.md](REVIEW-4.md)
R4-S1.

Combined with T1 replay this gives: *the answers are right* (replay), and *they were not prepared in advance* (probe gap).

**T2 + T1 is the default requirement for a ranked leaderboard row.**

**What T2 does not prove.** It bounds *precomputation*, nothing more. A submitter can receive a batch and solve it with a stronger model, a hosted API, or a human within the window. Model attribution rests entirely on the probabilistic plausibility checks below — error-code fingerprinting and throughput consistency — and those raise the cost of lying without ever proving authorship. A T2 badge should be read as "these tasks were fresh", not as "this model produced these answers".

#### Batched issuance (required for long runs)

A `deep` suite takes ~44.5 hours; it cannot sit inside a short anti-precomputation window. So the nonce is issued per batch, not per run:

```
client: POST /challenge/batch { run_id, batch_index }
server: { batch_nonce, unit_range, expires_at }   # window measured in hours
client: executes the batch, submits results
client: may not request batch k+1 before submitting batch k
```

~~Precomputation exposure is bounded to one batch.~~ **This claim is false and is retracted.** Batch
nonces derive **probe** seeds only ([ADR-0009](adr/0009-paired-core-and-fresh-probe-seeds.md)); the
85% of units that are *scored* derive from `epoch_seed`, which is written into `plan.json` before the
first unit runs. **Core precomputation exposure is unbounded** — see [REVIEW-5.md](REVIEW-5.md) R5-S2.
A completed 60-unit `smoke` run yields every `deep` seed for the epoch.

Batches compose freely with execution segments — see [09-resume-and-checkpointing.md](09-resume-and-checkpointing.md).

Trade-off: T2 requires network access *between* batches. The sandbox still denies network *during* every unit. Fully offline runs are possible but are capped at T0/T1.

### Seed secrecy — the primary precomputation control

> **BLOCKED — this control does not currently work.** It presumes the seed set can be kept from an
> attacker. It cannot: `plan.json` contains `epoch_seed` and all 1088 core seeds before the first
> unit executes, the server surface has **no authentication and no submitter identity**, and no gate
> anywhere bounds elapsed time between planning and submission. Secrecy protects the seed set from
> third parties and provides **zero** protection against the party holding it, which is every
> submitter. See [REVIEW-5.md](REVIEW-5.md) R5-S2.
>
> Prerequisites before this section describes reality: (a) authenticated submitters, (b) either
> fresh per-submitter seeds — viable if [R5-S1](REVIEW-5.md)'s ρ measurement permits family-level
> pairing — or server-issued rendered instances with seeds never leaving the server, and (c) a
> monotone-progress rule with published `plan_frozen_at` → `submitted_at` elapsed on every row.

Pairing requires every submitter in an epoch to run the **identical core seed set**. That set is
therefore the single most valuable thing an attacker can obtain, and R4-S1 establishes that the
probe cannot protect it.

- Core seeds are **not published while the epoch is open**.
- The public dump for epoch *N* is released when epoch *N* closes, at the start of epoch *N+1*.
- Seeds are never reused across epochs, so a published set has no forward value.
- Independent re-derivation of the leaderboard remains fully possible, delayed by one epoch.

**Residual threat, stated plainly:** a submitter who has already run holds the seeds and can leak
them to a confederate inside the same epoch. Against that the remaining defences are the probe
(weak), canary cross-screening, and T3 audit. This limitation belongs on the public methodology page,
not buried here.

### T3 — Audited

MLPerf's model. Per epoch, audit two submissions — one selected at random, one selected by the review committee. Examine logs, configuration, and any custom code; reproduce on reference hardware; results valid if within **5%** of submitted numbers; **90-day** audit window; a failed audit retracts published material.

Gold badge. Worth building only once there are reputations on the line. It is a policy document plus a small amount of tooling, not a large engineering effort.

## Plausibility checks — the hardware half

Hardware claims cannot be verified, but they are strongly coupled, which makes lying detectable.

| Check | Detects |
|---|---|
| **Throughput consistency** — per-unit `completion_tokens / gen_ms` must match calibrated `tg128` within a band | Fabricated timings, or a calibration run on different hardware |
| **Memory physics** — `peak_accel_mem_mb` must fit the claimed device and be consistent with `model_size × quant + kv_cache(ctx)` | Misreported model, quant, or device |
| **Thermal signature** — laptops throttle 12–18% cold→stabilised | A "laptop" with perfectly flat 10-minute sustained throughput |
| **Error-code fingerprint** — each model family has a characteristic rustc-diagnostic distribution | Output not actually produced by the declared model |
| **Segment coherence** — calibration across segments, `harness_overhead_ratio` drift | A run stitched together from different machines |
| **Canary leakage** — screen submitted output for canaries belonging to *other* instances | An agent that scraped or was fed a solution corpus |

None is proof. All are cheap. Together they make a consistent fake require sustained effort, and every one of them produces a flag that a human reviewer can act on.

## Anti-gaming controls in the harness

Each maps to a documented real-world failure mode.

| Control | Enforcement | Addresses |
|---|---|---|
| **No network during generation or grading** | OS-level (netns / seatbelt / job object), not policy. Attempted connection = hard fail | Terminal-Bench case 3 (agent fetched solutions) |
| **Oracle never in the model's filesystem view** | Separate grading workspace; oracle injected after the turn; pre-turn content-hash assertion | Terminal-Bench case 2 (test folder shipped in agent setup) |
| **Timeouts and limits are harness-owned** | Read from the suite definition; every submitter-settable knob is in the signed manifest and displayed | Terminal-Bench case 1 (modified timeouts) |
| **Full trajectory required for passing units** | Prompt, response, and tool calls stored for every passing unit; T1 rejects passing units without them | Makes audit possible at all |
| **Canary per instance** | Minted at generation, embedded in the prompt, screened at submission and against public corpora | Leakage detection, contamination monitoring |
| **Frozen tasks excluded from scored suites** | Harness refuses `kind = "frozen"` in `standard` and above | Prevents a static, memorisable core |
| **Published raw corpus** | Everything except redacted personal data | Independent re-derivation — the strongest control available |

That last row deserves emphasis: all three Terminal-Bench cases were caught by community analysis of published results, not by the platform's own checks. Publishing the corpus is not a nice-to-have.

## Reconciling replay with leakage

T1 replay requires the model's output. Publishing that output could leak solved instances back into training corpora — poisoning our own benchmark.

Resolution:

- Output artifacts are uploaded **encrypted to a server key**, retained privately, **never published**, never included in the public dump.
- Retention window matches the audit period (90 days), then deleted.
- The public dump contains scores, error codes, timings, and hardware class — no source.
- The consent screen states this **separately** from the statistics consent, because it is a materially different thing to agree to.

See [11-submission-and-privacy.md](11-submission-and-privacy.md).

## What to build, and when

**Before first ship** (expensive to retrofit):

- Canonical manifest format and serialization (`bench-attest/manifest.rs`)
- Seed-from-nonce derivation
- Challenge/batch protocol shape, even if the server initially always returns `local`
- Canary minting and embedding
- Trajectory capture for passing units

**Shortly after** (server-side, additive):

- T1 replay verification
- Plausibility check suite
- Canary cross-screening

**Later** (policy, not code):

- T3 audit process and remedies document


> **Built so far (2026-10-05):** `rustybench verify-bundle` is the offline slice of the "server re-derives"
> column — canonical form and hash, leak scan, oracle-vector coherence (score gating, sub-score
> recomputation, failure class and borrowck completeness against the error codes, via `bench-core`'s own
> rules) and a full `bench-stats` re-derivation of every reported figure from the units. It is
> **self-consistency, not T1**: replay needs the model output (private, encrypted, not in the bundle) and
> assigns no trust tier. A file-only forger who recomputes the hash is caught by the re-derivation or the
> coherence rules unless they forge a *coherent* unit table *and* its aggregates, which is exactly what
> only replay can detect.

## Components

```
bench-attest/
  challenge.rs   # request nonce, derive seeds, enforce batch ordering and expiry
  manifest.rs    # canonical payload: run_id, challenge, suite_hash, generator_commit,
                 # harness_version, binary_hash, submitter-settable config, hw, calib, results
  sign.rs        # ed25519 over canonical CBOR; embedded key = T0 only, no illusions
  redact.rs      # bucket hardware, strip paths / hostnames / usernames / serials
  canary.rs      # mint, embed, screen
```

Server side:

```
verify/replay.rs      # re-materialise seed, re-run oracle, diff against submitted scores
verify/plausible.rs   # throughput / memory / thermal / histogram checks
verify/canary.rs      # cross-instance and cross-corpus canary screening
verify/audit.rs       # T3 workflow support
```
