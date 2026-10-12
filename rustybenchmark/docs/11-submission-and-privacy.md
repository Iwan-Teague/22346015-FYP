# 11 — Submission and privacy

Auto-upload is the right product idea. It is also an outward-facing action carrying a machine fingerprint, so the guardrails go in from day one rather than being retrofitted.

> **Status, 2026-10-05.** The offline half of this document is built as `crates/bench-submit`:
> `rustybench export` (consent gate, `--dry-run`), `verify-bundle`, `consent show|grant|revoke`; schema in
> [12-schemas.md](12-schemas.md#current-emission-the-upload-bundle-rustybench-export). Consent 1 only.
> Where this document was contradicted by the code or the reviews, the build followed the stricter reading:
>
> - **`task_id` is not uploaded** — generated ids embed the seed (`family/{seed:016x}`), so the "Always"
>   list below leaked exactly what the same list says is withheld (R5-S7 fixed the sibling lines, not this
>   one). The bundle carries `family` + `index` + an opaque `unit_id`.
> - **Raw calibration numbers are not uploaded** (R5-S6: fingerprint or control, not both).
> - **No `machine_uuid` and no per-unit timestamps** (R5-S6: a linkable activity timeline).
> - **Not built:** signing, encrypted replay artifacts (consent 2), audit contact (consent 3), the server,
>   `forget`. Each needs a decision recorded in OPEN-QUESTIONS Q32.

## Consent

- **Opt-in, never opt-out.** On first run the harness prints the exact JSON that would be sent and asks. The choice is stored.
- **Three separate consents**, because they are materially different things to agree to:
  1. Publish redacted scores and hardware class to the public leaderboard, **and grant the project a
     perpetual, worldwide, non-exclusive licence to publish these redacted results and to license
     them onward under Creative Commons Attribution 4.0 International (CC BY 4.0)**.

     Consent to *publish* is not by itself a licence to *sublicense*, and CC BY obliges the project
     to grant downstream rights it must therefore hold. The licence is named in full on the consent
     screen — not linked — and a harness test asserts the consent text contains that name. See
     [DATA-LICENSE.md](../DATA-LICENSE.md).
  2. Upload encrypted model output for T1 replay verification (private, 90-day retention, never published).
  3. Contact for T3 audit follow-up (optional, requires an identifier).
- `--no-submit` and `RUSTBENCH_SUBMIT=0` always win, regardless of stored consent.
- `rustybench submit <run_id>` is an explicit command. Submission is never a silent side effect of `run`.
- Consent is revocable: `rustybench forget <run_id>` requests deletion; the harness prints what it can and cannot guarantee.

## What is uploaded

### Always (public leaderboard)

```
run_id, epoch, suite, completeness, tier          (nonces withheld until epoch close)
suite_hash, generator_commit, harness_version
model: name, quant, backend, backend_version, ctx, ngl, sampling config
exec_class, offload_ratio, kv_cache_location
hw_class (bucketed), cpu_class, mem_bandwidth_class, unified_memory, chassis, power_source
calibration: pp512, tg128, sustained delta, per-segment values
per-unit: task_id, oracle vector, error_codes, failure_class, timings, token counts
          (seed and batch_nonce are WITHHELD until the epoch closes -- R5-S7 found the R4-S2
           fix applied to the dump section below but not to this upload list)
aggregates: capability_score, category scores, CIs, effective N
segments: count, exit reasons, stability flags
```

### Conditionally, encrypted, private (T1 replay only)

```
per-unit: prompt, model response, applied diff, diagnostics
```

Encrypted to a server public key. Never published. Never in the public dump. Deleted after the 90-day audit window.

### Never uploaded

- Absolute filesystem paths, hostnames, usernames
- **`model_path`** (llama.cpp `/props` returns it, and it commonly contains the username)
- **Ollama `modelfile`** (contains absolute paths and any user-authored system prompt)
- **The chat-template body** (only its fingerprint is published, never the text — templates can be
  hand-edited in some GUIs and may contain user content)
- **`base_url`** (may encode an internal hostname or port topology)
- Device serial numbers, MAC addresses, UUIDs derived from hardware
- Exact GPU model + driver + core count as a *joint* tuple (see below)
- Anything from outside the run directory
- Environment variables

## Redaction rules

**A precise hardware profile is a fingerprint.** Exact GPU model, driver build, core count, RAM size, and OS build together identify a machine with high probability. So the public record carries **buckets**:

| Raw | Published |
|---|---|
| `NVIDIA GeForce RTX 4090, driver 560.35.03, 16384 CUDA cores, s/n ...` | `hw_class: vram-24`, `vendor: nvidia`, `gen: ada` |
| `Apple M3 Max, 128 GB unified` | `hw_class: unified-128`, `vendor: apple`, `gen: m3` |
| `AMD Ryzen 9 7950X, 32 threads @ 5.7 GHz` | `cpu_class: desktop-16c`, `vendor: amd`, `isa: avx512` |
| `Darwin 25.5.0 build 25F74` | `os: macos-25` |

Driver versions are published as major only, and only where they materially affect performance.

**Machine identity is a locally generated random UUID**, stored once, never derived from hardware. It exists so a user can group and manage their own submissions. It is not a hardware fingerprint and cannot be reconstructed from one.

## Signing and rate limiting

- ed25519 over canonical CBOR of the manifest.
- Embedded key ⇒ T0 only. No pretence that it proves anything beyond "produced by an unmodified-looking binary".
- Server rate-limits per machine UUID and per source, with generous limits — the aim is to stop flooding, not to gate legitimate re-runs.
- Duplicate `run_id` submissions are idempotent, not additive.

## The public dump

**Publish the entire submission corpus** (redacted, no model output) as a downloadable dataset, with the leaderboard's aggregation code open-sourced alongside it.

**Timing matters: the dump for an epoch is released only when that epoch closes.** Core seeds are
identical for every submitter in an epoch, so publishing them live would hand the second submitter
everything needed to precompute — and the probe detector cannot catch a submitter who precomputes
and suppresses ([REVIEW-4.md](REVIEW-4.md) R4-S1). Delayed publication preserves independent
re-derivation while removing the window in which the dump is an attack tool.

Rationale: this is the strongest integrity mechanism available. All three documented Terminal-Bench misconduct cases were found by independent community analysis of published data, not by platform checks. A leaderboard whose numbers cannot be independently re-derived is asking to be trusted; one whose numbers can be is worth trusting.

Format: JSONL, one line per unit, plus a manifest table. Same schema as the local journal minus redacted fields — see [12-schemas.md](12-schemas.md).

## Server

Deliberately small. Do not build this until the local runner is good.

```
POST /challenge/batch      issue batch nonce + unit range
POST /submit               accept manifest (+ encrypted artifacts)
GET  /leaderboard          aggregated view, filterable by exec_class / hw_class / tier
GET  /dump/<epoch>.jsonl   public raw corpus -- released only after <epoch> CLOSES
GET  /epoch/current        active epoch, suite hash, generator commit
```

Append-only store, dedupe on `run_id`, aggregation computed as a materialised view. Rust + axum + Postgres is ample.

## Leaderboard presentation rules

These are integrity controls as much as UX:

- Every row shows its **trust tier** badge (T0 grey / T1 / T2 / T3 gold).
- Every row shows its **suite tier**; below `deep` the row is greyed and marked *insufficient precision for ranking*.
- Every score shows a **confidence interval**.
- **Execution class** is a hard filter, not a column to be scanned past — timing metrics are never compared across classes.
- **Quantisation is displayed at equal prominence to the model name.** Comparing a Q4_K_M row to a Q8_0 row of the "same model" is one of the most common errors in local-model discourse; the presentation should make it impossible to do by accident.
- **Tainted** and **unstable** runs are shown struck through, not hidden. Hiding them invites the suspicion that the leaderboard is curated.
- `completeness < 1.0` is displayed on every partial run.

## Threats this does not address

Stated plainly so nobody assumes otherwise:

- A determined attacker with a patched binary can produce a T0 submission containing anything. T1 replay is the answer, not signing.
- A user can run on hardware A and claim hardware B. Plausibility checks make it awkward, not impossible.
- Nothing here proves the declared model produced the output. Error-code fingerprinting raises the cost; it is not proof.
- T2 bounds precomputation to one batch; it does not prevent a well-resourced attacker from solving a batch faster than the window with a *better* model than the one they declared.

The design response to all four is the same: publish everything, make re-derivation easy, and let the community audit. That worked for Terminal-Bench when their internal checks did not.
