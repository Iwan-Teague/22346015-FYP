# 09 — Resume and checkpointing

The `deep` suite takes ~44.5 hours at 20 tok/s. Nobody has 39 uninterrupted hours. A run must survive being executed in ninety-minute evening slices across two weeks, and must survive crashes, kernel panics, and lid closes without corrupting its own results.

## The property that makes this easy

Work units are **independent and idempotent** (see [08-run-protocol.md](08-run-protocol.md)). Generation is deterministic from the seed; grading is deterministic from the instance. So:

- A completed unit never needs to be re-run.
- An interrupted unit can simply be re-run from scratch — there is no partial state to reconcile.
- Aggregation is a pure fold over completed units, computable at any moment.

Everything below follows from those three facts.

> **Status, 2026-10-06.** Built and tested end to end (real `SIGKILL`, mock endpoint): torn-tail discard,
> salvage of a unit glued behind a fragment, quarantine instead of deletion, duplicate collapse (first
> wins), `fsync`'d single-write appends, a `<journal>.lock` with stale-lock takeover, the resume validity
> gates for model name / hardware class / harness version with `--force-heterogeneous` and a permanent
> `<journal>.tainted`, and `rustybench journal [--repair]`. Also built: two-stage `SIGINT`/`SIGTERM`, directory `fsync`, and the scheduling controls `--max-duration`, `--until`, `--max-units`, `--pause-on-battery`. **Not built:** `--idle-only` (undefined, Q34), `--pause-on-thermal`, `plan.json`, `state.json`,
> segment `meta.json`/calibration files (so `plan_hash`, `suite_hash`, `generator_commit`, `ctx`, `ngl`,
> sampling and `exec_class` gates cannot yet be checked: the formats are not pinned, see Q34), the
> scheduling controls, orphan-artifact cleanup. See
> [BUILD-LOG](BUILD-LOG.md) 2026-10-06.

## On-disk layout

```
~/.local/share/rustybenchmark/runs/<run_id>/
├── state.json              # mutable run state, atomically replaced
├── plan.json               # frozen work-unit list; hashed
├── journal.jsonl           # append-only, fsync'd, one line per completed unit
├── hw.json                 # static inventory (segment 0)
├── segments/
│   ├── 000/
│   │   ├── calib.json      # calibration for this segment
│   │   └── meta.json       # start/end time, units completed, exit reason
│   ├── 001/
│   └── ...
├── artifacts/<unit_id>/
│   ├── prompt.md
│   ├── response.txt        # retained locally; uploaded only for T1+ (encrypted)
│   └── diagnostics.json
└── workspaces/             # ephemeral; wiped between units and on resume
```

macOS uses `~/Library/Application Support/Rustybenchmark/runs/`; Windows uses `%LOCALAPPDATA%\Rustybenchmark\runs\`. Resolved via `directories` crate.

## The plan is frozen at run start

```json
{
  "run_id": "01K3F...",
  "plan_hash": "blake3:...",          // covers core units + probe SLOT STRUCTURE
  "suite": "deep",
  "epoch": "2026-08",
  "epoch_seed": "...",                // SECRET until the epoch closes. Shared across submitters
                                      // for pairing, but see REVIEW-5.md R5-S2: writing it here hands
                                      // every submitter the master key to all 1088 core seeds at t=0.
  "core": [
    { "index": 0, "unit_id": "...", "task_id": "borrowck/split-mut-window", "seed": 8412739123 },
    { "index": 1, "unit_id": "...", "task_id": "traits/blanket-coherence",  "seed": 1177340022 }
  ],
  "probe": [
    { "index": 0, "task_id": "borrowck/split-mut-window", "batch": 0, "seed": null }
  ]
}
```

### Why probe units are slots, not units

Probe seeds derive from a `batch_nonce` issued **during** execution, per batch, expiring in hours
([ADR-0009](adr/0009-paired-core-and-fresh-probe-seeds.md)). They cannot be known at freeze time, so
listing them as ordinary units breaks the plan in four places: the seed is undefined, `unit_id` is
therefore uncomputable, a progressively-filled `plan_hash` changes every batch and fails the first
resume gate, and a nonce that expires mid-segment leaves the run unable to finish.

So the plan carries **core units** (fully specified, epoch-derived, frozen) and **probe slots**
(`task_id` and position only). `plan_hash` covers the core units completely and the probe slot
*structure* — never probe seeds.

**On resume, unfinished probe slots in an expired batch are re-issued a fresh nonce and fresh seeds.**
That is sound for one specific reason worth stating plainly: **probe units are re-drawable because
they are never scored.** Core units are not re-drawable, because they are paired across submitters
and re-drawing would break the pairing. The scoring/detection split introduced to resolve
[R2-S1](REVIEW-2.md) is exactly what makes this resume problem solvable. See
[REVIEW-3.md](REVIEW-3.md) R3-S1.

The journal records which `batch_nonce` produced each probe unit, so the server can still verify
derivation.

Frozen means: the entire ordered work list is computed and written **before the first unit runs**. Resume never re-derives it. If the plan could change between sessions, resume would silently produce a run that is a mixture of two different suites.

Ordering is **deterministic but interleaved** — categories are round-robined rather than run in blocks, so a partially completed run still has balanced category coverage and can produce a meaningful (wider-CI) partial report.

## The journal is the source of truth

One line per completed unit, appended and fsync'd before the harness moves on:

```json
{"unit_id":"...","index":417,"segment":3,"segment_position":22,
 "completed_at":"2026-08-19T21:14:03Z","oracle":{...},"cost":{...},"failure_class":"borrowck"}
```

Resume = read `journal.jsonl`, build the set of completed `unit_id`s, skip them in `plan.json`, continue.

Crash safety:

- Append + `fsync` per line. A torn final line is detected by JSON parse failure and discarded; that unit simply re-runs.
- `state.json` is written to a temp file and `rename`d (atomic on all three platforms).
- Artifacts are written before the journal line. A journal line therefore always implies complete artifacts; artifacts without a journal line are orphans and are cleaned up on resume.
- `workspaces/` is wiped unconditionally at the start of every segment.

## Segments

A **segment** is one continuous execution session. Each has its own calibration.

```json
{
  "segment": 3,
  "started_at": "2026-08-19T19:40:11Z",
  "ended_at":   "2026-08-19T22:02:55Z",
  "exit_reason": "max_duration",
  "units_completed": 88,
  "calib_ref": "segments/003/calib.json"
}
```

`exit_reason` ∈ `max_duration | until_time | sigint | battery | thermal | crash | complete | aborted`.

**Why recalibrate per segment:** thermal and power state do not persist across a lid close. A run that starts cold each evening has different throughput characteristics per session, and pretending otherwise would silently corrupt every timing metric.

### Consequences for metrics

This is the important, non-obvious part:

| Metric family | Resumes cleanly? |
|---|---|
| **Correctness** — `capability_score`, category scores, error histograms, CIs | **Yes, perfectly.** Independent of when or how fast a unit ran. |
| **Throughput** — `throughput_score`, `time_to_first_pass`, `efficiency_score` | **No.** Aggregated per segment, then combined with an explicit stability check. |

Rule: if calibrated `tg128` varies more than **±10%** across segments, the run's throughput metrics are flagged `unstable` and displayed struck through on the leaderboard. Correctness metrics are unaffected and carry no flag.

Same split as the integrity model in [10-integrity.md](10-integrity.md): the deterministic half survives everything; the physical half is fragile and must say so.

## Resume validity gates

On `rustybench resume <run_id>`, the following must match what `state.json` recorded. Any mismatch is a **hard failure** by default.

| Field | Why it must match |
|---|---|
| `plan_hash` | A different plan is a different run |
| `suite_hash` | Task definitions changed → results not comparable |
| `generator_commit` | Generator changed → instances differ for the same seed |
| `harness_version` | Grading logic may have changed |
| `model_name`, `quant`, `backend`, `backend_version` | A different model mid-run invalidates everything |
| `ctx`, `ngl`, sampling config | Changes capability |
| `exec_class` | Plugging in an eGPU mid-run changes the machine |
| `hw fingerprint` (bucketed) | Different machine entirely |

Escape hatch: `--force-heterogeneous` proceeds anyway, records the divergence in `state.json`, and permanently marks the run **tainted**. Tainted runs are never leaderboard-eligible and say so in every report they generate. There is no way to un-taint a run.

Soft-warn (recorded, not fatal): OS minor version, driver version, free RAM, ambient conditions.

## Interruption handling

| Signal | Behaviour |
|---|---|
| `SIGINT` (first) | Finish the current unit, write journal, close segment cleanly, exit 0 |
| `SIGINT` (second) | Abort immediately; current unit is discarded and re-runs on resume |
| `SIGTERM` | Same as first `SIGINT`, with a shorter grace window |
| Power loss / panic | Journal replay handles it; at most one unit is lost |

The first-`SIGINT` behaviour matters: a user pressing Ctrl-C should not lose the 40 seconds of work in flight, and should not be left wondering whether the run is corrupt.

## Scheduling controls

Designed for "run it overnight, every night, for a week".

```
--max-duration 4h            stop cleanly after 4 hours of execution
--until 07:30                stop cleanly at a wall-clock time
--max-units 500              stop after N units
--pause-on-battery           checkpoint and exit if AC power is lost
--pause-on-thermal           checkpoint and exit if sustained throttling is detected
--idle-only                  only execute while the machine is otherwise idle
--resume-daily 22:00         (v2) register a scheduled resume
```

All of these end the segment with a clean `exit_reason`, not a crash.

## Progress and ETA

```
rustybench status 01K3F...

  run      01K3F...           suite deep       epoch 2026-08
  model    qwen3-coder-30b-a3b Q4_K_M          exec GpuFull
  progress 743 / 1200 units   61.9%
  segments 4  (last: 2026-08-19 22:02, exit max_duration)
  elapsed  9h 51m execution   over 4 sessions / 3 days
  eta      ~6h 04m remaining  at current segment rate (41.2 tok/s)
  partial  capability 0.412 [0.361, 0.465]   <- widened CI, 743 units
  stability tg128 across segments: 41.2 / 40.8 / 38.1 / 41.2  -> +/- 4.0%  OK
```

The partial score is computed and shown at every status check. Its CI is honest about the reduced N, and the report is clearly marked partial. Being able to see a converging estimate mid-run is a large part of what makes a 44.5-hour benchmark bearable to run.

## Interaction with challenge windows

A T2 challenged run cannot fit a 44.5-hour execution inside a six-hour anti-precomputation window. Resolved by **batched challenge issuance** rather than one long window:

- The client requests seed batch *k* (e.g. 50 units).
- The server returns `{batch_nonce, expires_at}` with a short window (hours).
- The client must submit batch *k*'s results before, or alongside, requesting batch *k+1*.
- Precomputation exposure is bounded to a single batch, not the whole run.

This composes cleanly with segments: a segment may span several batches, and a batch may span several segments. The only constraint is ordering. Full detail in [10-integrity.md](10-integrity.md).

## Partial-run reporting

A run that is abandoned part-way is still useful, and the harness says exactly how useful:

- `capability_score` with a CI computed on the units actually completed
- explicit `completeness` field: units completed / units planned
- per-category completeness, since round-robin ordering keeps this balanced
- **not leaderboard-eligible** below the suite's declared completion threshold (100% for ranked rows)

An incomplete run is never silently reported as complete. `completeness < 1.0` appears in every rendering of the result.
