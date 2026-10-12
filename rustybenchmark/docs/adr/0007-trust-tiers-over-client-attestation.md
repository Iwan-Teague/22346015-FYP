# ADR-0007 — Server-side replay over client attestation

**Status:** Accepted · 2026-08-17

## Context

The natural first instinct for leaderboard integrity is client attestation: hash the binary, embed a signing key, accept submissions only from the unmodified program.

**This cannot be made sound.** The attacker owns the machine. They patch the binary, or extract the embedded key with a debugger and sign whatever they like. Every "only submittable through the program" scheme is obfuscation.

The failure mode is not hypothetical. Terminal-Bench found three real cases: **encrypted solutions stored inside an agent binary** with modified timeouts; **the task test folder shipped in an agent setup**; and **an agent fetching solutions from the internet**. All three passed submission. All three were caught by independent community analysis of published data, not by platform checks.

## The asymmetry we have

Claims split cleanly by verifiability:

| Claim | Verifiable? |
|---|---|
| "The model produced this code" | No — unfalsifiable in principle |
| **"This code scores 0.83 on task X seed Y"** | **Yes, exactly** — the oracle is deterministic |
| **"These are the tasks I was given"** | **Yes** — the server issues the seeds |
| "This ran on an RTX 4090 at 41 tok/s" | No — plausibility-checkable only |

Because instances are server-seeded and the oracle is deterministic, **correctness is fully re-verifiable server-side**. That is a stronger position than most benchmarks have, and it should carry the integrity model rather than cryptography on the client.

## Decision

**Four trust tiers, with server-side replay as the load-bearing control.**

- **T0 — Self-reported.** Signed with an embedded key. Verifies nothing. Grey badge, never headline. What offline runs get.
- **T1 — Replayed.** Client uploads model output; server re-materialises each instance from its seed, re-runs the identical oracle, and compares. **Eliminates score fabrication entirely.** Costs server CPU and nothing else.
- **T2 — Challenged.** Server-issued nonce determines the seeds, so precomputed or binary-embedded solutions cannot apply. Issued **per batch**, not per run, so long multi-session runs stay inside short anti-precomputation windows.
- **T3 — Audited.** MLPerf's model: two submissions per epoch (one random, one committee-chosen), reproduced on reference hardware within a **5% tolerance**, **90-day** window, failed audits retract published material.

**T2 + T1 is the requirement for a ranked row.**

Client-side signing is still implemented — as a speed bump against casual tampering, with no illusions about what it proves.

Hardware claims, which cannot be verified at all, are handled by coupled plausibility checks (throughput vs calibration, memory physics, thermal signature, error-code fingerprint, segment coherence, canary leakage) and are labelled at a lower confidence than correctness claims on every leaderboard row.

## Consequences

**Good**

- The most damaging attack — fabricated scores — is fully closed by T1, using only the determinism the design already has.
- T2 closes precomputation without requiring trust in the client.
- Tier badges make the trust model legible rather than implicit.
- Batched challenge issuance composes cleanly with resumable multi-session runs.

**Bad**

- T1 requires uploading model output, which could leak solved instances into training corpora. Resolved by encrypting to a server key, retaining privately for the 90-day audit window, never publishing, and consenting to it **separately** from the statistics consent.
- T2 requires network access between batches, so fully offline runs are capped at T0/T1.
- Server-side replay costs real CPU at scale — see [OPEN-QUESTIONS Q6](../OPEN-QUESTIONS.md). **Resolved by measurement (R3-S6):** verify **every unit of every submission**, synchronously. A warm build+test+clippy cycle measures 0.65–0.68 s, giving 2.1–6.1 CPU-hours per `deep` submission — under 23 minutes wall on a 16-core box. No sampling, no asynchronous badge upgrade. Q6 and Q15 are closed.

## The control that actually caught things

Worth stating plainly, because it is easy to under-fund: **publish the entire raw corpus** and open-source the aggregation code. All three Terminal-Bench cases were found by outsiders reading published data. A leaderboard whose numbers cannot be independently re-derived is asking to be trusted; one whose numbers can be is worth trusting.
