# 08 — Run protocol and sandbox

## Lifecycle

```
rustybench run --suite deep --model http://localhost:8080/v1 --epoch 2026-08
```

1. **Preflight** — verify toolchain, scratch space, backend reachability, sandbox integrity. See gates in [05-hardware-and-calibration.md](05-hardware-and-calibration.md).
2. **Profile** — static hardware inventory → `hw.json`.
3. **Challenge** — request `{challenge_nonce, epoch, expires_at}` from the server (or `local` for offline T0 runs).
4. **Plan** — expand the suite into an ordered, frozen list of work units → `plan.json`, hashed.
5. **Calibrate** — warm-up, `pp512`, `tg128`, sustained phase → `segments/000/calib.json`.
6. **Execute** — for each work unit: materialise → prompt → model → attempt 1 → grade → (repair) → attempt 2 → grade → append to journal.
7. **Aggregate** — fold the journal into scores with clustered-bootstrap CIs.
8. **Submit** — optional, consented, redacted. See [11-submission-and-privacy.md](11-submission-and-privacy.md).

Steps 5–6 repeat per segment when a run spans multiple sessions — see [09-resume-and-checkpointing.md](09-resume-and-checkpointing.md).

## Work unit

The atom of execution and of checkpointing.

```rust
pub struct WorkUnit {
    pub unit_id:  UnitId,     // blake3(run_id || task_id || seed || attempt_policy)
    pub task_id:  TaskId,
    pub seed:     u64,
    pub index:    u32,        // position in the plan; fixed
}
```

Work units are **independent and idempotent**. Re-running one produces the same instance (generation is deterministic from the seed) and the same grade (the oracle is deterministic). This property is what makes resume, replay verification, and crash recovery all trivially correct.

## Per-unit sequence

```
1. materialise model workspace       (skeleton + Cargo.toml + vendored deps symlink)
2. assert no oracle content present  (content-hash check)
3. render prompt, send to backend, capture response + token counts + timings
                                     (HARNESS process, NOT sandboxed -- see below)
4. materialise grading workspace     (fresh dir; skeleton + model response + oracle/)
5. run L0..L4 inside the sandbox     (each stage with its own timeout)
6. write artifacts, append journal line, fsync
7. wipe workspaces
```

Steps 1–2 and 4 being separate directories is the core oracle-isolation control. See [03-oracle.md](03-oracle.md).

> **Corrected.** An earlier version wrapped the model call in `enter sandbox` / `exit sandbox` while
> the network policy denied all network. The model server listens on loopback, so **the design as
> written could not make a single model call.** The error came from conflating two different
> containment jobs.
>
> The sandbox exists to contain **untrusted code the model wrote**, which only ever executes during
> grading. Generation executes nothing — the harness makes an HTTP request from its own process and
> receives text. Sandboxing that step protects against nothing and breaks the only thing it touches.

## Sandbox

A full VM is the wrong tool for consumer hardware — heavy, slow to start, and hostile to the "just run this on your laptop" goal. Wasm is also wrong: wasmtime's isolation is excellent, but anything touching `std::fs`, threads, or tokio breaks, which removes half the categories.

**Chosen: OS-level containment around the cargo invocation.**

| Control | Linux | macOS | Windows |
|---|---|---|---|
| Network deny | network namespace, no veth | `sandbox-exec` seatbelt profile | **AppContainer** without network capabilities |
| Filesystem scope | mount namespace, bind-mount workspace only | seatbelt path allowlist | AppContainer SID + explicit workspace ACLs |
| Memory cap | `RLIMIT_AS` + cgroup v2 | `RLIMIT_AS` | job object memory limit |
| CPU time cap | `RLIMIT_CPU` | `RLIMIT_CPU` | job object |
| Wall-clock cap | harness supervisor | harness supervisor | harness supervisor |
| Process cap | `RLIMIT_NPROC` / cgroup pids | `RLIMIT_NPROC` | job object active-process limit |

Firecracker remains an option for a future hosted verification tier, where a ~50k-line Rust VMM with a deliberately small device model is the right trade. Not for the local runner.

### Network policy

**Zero network access during grading** — the only phase in which model-authored code runs — enforced
by the OS rather than by policy. `cargo` runs `--offline` with pre-vendored dependencies. Any attempted
connection is logged and fails the unit with `reason = "network_attempt"`.

This directly addresses one of the three documented Terminal-Bench misconduct cases (an agent fetching
solutions from the internet).

**Loopback-permitting profiles are achievable, and that matters for the agentic track.** Measured on
macOS seatbelt against a live listener:

```
baseline, no sandbox                                          -> HTTP 200
(allow default)(deny network*)                                -> exit 7   <- deny works
(deny network-outbound)(allow ... (remote ip "localhost:*"))  -> HTTP 200 <- loopback restorable
```

On Linux a network namespace with `lo` up gives the same. So "network-backed tools are categorically
incompatible with the sandbox" is **a threat-model choice, not a mechanism fact** — the residual risk
is that a local proxy on loopback can egress. The main benchmark does not need this (it offers no
tools), but the agentic track's design must not be built on the false premise.

### Timeouts are harness-owned

Every timeout — per-attempt generation, per-stage build, per-stage test, per-unit wall clock — comes from the suite definition, not from anything the submitter can set. Any submitter-settable knob that does exist goes into the signed manifest and is displayed on the leaderboard.

Modifying timeouts was another of the three documented Terminal-Bench cases.

## Cargo cost control

Cold builds dominate wall-clock and would make the benchmark measure the user's disk rather than the model.

- **Shared `CARGO_HOME`** across the whole run, persisted between segments.
- **Pre-vendored `.crate` files** shipped with the suite; `--offline --locked` always.
- **Prebuilt dependency workspace** per suite: dependencies compiled once during preflight, `target/` reused by every unit via a shared target directory.
- **`sccache`** where available.
- Record `build_ms` and `grade_ms` separately from `prefill_ms`/`gen_ms` in every journal line, and publish `harness_overhead_ratio = (build_ms + grade_ms) / (prefill_ms + gen_ms + build_ms + grade_ms)`. A healthy `deep` unit sits near **0.50** at 20 tok/s and ~0.75 at 60 tok/s, because L4 grading is fixed cost — the old flat 0.3 gate would have fired on every healthy deep run ([REVIEW-5.md](REVIEW-5.md)).
- **Exclude the first N units of each segment from timing aggregates** (cache warmth); record `segment_position` on every unit so this is auditable rather than magic.

## Determinism controls

Grading is fully reproducible: seed → instance → proptest seed → verdict. Generation is not — but the
reason is **not** the one this document previously gave.

**Corrected:** *"greedy decoding in llama.cpp still varies with batch size"* is false as stated.
Measured on llama.cpp b10470 (Metal, Qwen2.5-3B, temp 0, seed 42): prefill chunk size `-b`/`-ub`
across 64/128/256/512/2048 produced **bit-identical** output on 7/7 prompts, as did `cache_prompt`
true vs false and ten sequential identical requests.

**The real hazard is serving concurrency, and llama.cpp now defaults to 4 slots.** With 8 slots and
an identical prompt to each, llama.cpp yields 5–8 unique completions; a single slot is always
identical. A freshly launched `llama-server` with no `-np` flag reports `total_slots: 4`.

> **The harness MUST pin concurrency to 1** (`--parallel 1` / `-np 1`) **and verify it via `/slots`
> during preflight.** A harness that issues concurrent requests silently enters the non-deterministic
> regime and destroys replay verification. This is a preflight gate, not a recommendation.

**vLLM is measurably not batch-invariant at temperature 0** with default kernels: 1000 completions of
one prompt produced **80 distinct results**, first divergence at token 103. Batch-invariant kernels
make all 1000 identical at ~1.6× the latency. So the "flag any nondeterministic repeat" rule below
would fire on essentially every vLLM run and burn the alarm budget [REVIEW-5.md](REVIEW-5.md) R5-S5
already identified. Batch-invariance is therefore a **per-backend property recorded as a field**, and
a ranked vLLM row requires batch-invariant kernels.

Therefore:

- Record and **send explicitly** the complete sampler chain, not a subset:
  `{temperature, top_p, top_k, min_p, typ_p, repeat_penalty, presence_penalty, frequency_penalty,
  xtc_probability, xtc_threshold, dry_multiplier, mirostat, seed}` plus
  `{backend, backend_version, quant, ngl, ctx, batch, flash_attn, kv_cache_type}`.

  Omitting a sampler yields the **server's** default, not a neutral one: llama.cpp `/props` reports
  temp 0.8 / top_k 40 / top_p 0.95 / min_p 0.05 and a **nine-stage** chain, while vLLM instead applies
  the model author's `generation_config.json`. Measured: 12 draws on a Rust prompt with no
  `temperature` sent gave **5 distinct outputs, 2 of them not valid Rust**; `temperature=0` gave
  12/12 identical. The old record covered 4 of 9 active samplers.
- Default primary run: `temp = 0.0`, single sample.
- `--pass-k 5 --temp 0.8` for the variance probe on a 10% subsample.
- Flag and publish any case where identical `(model, seed, sampling)` produced a different **oracle
  verdict**. Byte-difference is the wrong criterion and would fire almost always: per-token top-1
  agreement compounds as `a^L`, and Rust solutions run 400–1500 tokens. Even flash attention's
  measured 99.873% agreement predicts ~40% of 400-token generations differing somewhere. **95%
  byte-identity at L=500 needs 99.990% per-token agreement, which nothing measured comes close to.**
  Verdict stability is the only criterion that survives generation length.

## Interaction modes

| Mode | Turns | Notes |
|---|---|---|
| `single-shot` | 1 | Cheapest; cleanest measurement of raw capability |
| `repair` | 2 | Attempt 2 sees diagnostics only, never oracle source. **Default.** |
| `agentic` | n | Model drives tools (read/write/run). Separate reported track — the scaffolding confounds the model measurement, and cost multiplies |

**The `tools` key is omitted from the request body entirely.** Not sent empty, not sent with
`tool_choice: "none"`. Measured: merely *offering* three plausible coding tools flipped 3/3 non-trivial
Rust tasks from a fenced code block to a `finish_reason: tool_calls` response with **empty content** —
which the oracle scores as zero. Sixteen wholly irrelevant tools did the same. And `tool_choice: "none"`
is **not** a control condition: the schemas are still rendered into the prompt (`prompt_tokens`
identical at 323), and the model emits an unparseable raw `<tool_call>` blob in the content field. The
server's own chat template branches on `{%- if tools %}`, i.e. on *presence*, not on `tool_choice`.

`tools_offered: false` is recorded as an attested field in the run identity, because a run where tools
leaked in is not comparable to one where they did not, and the failure mode is silent.

`repair` is default because it mirrors real use and because Aider's benchmark established the protocol (two attempts, test output fed back) — comparability is worth something.

Both attempts are scored. `first_try_score` is retained alongside the final score; the gap between them is a genuinely interesting model property.

## CLI surface

```
rustybench doctor                        # ~90 s config audit: probes effective context, concurrency,
                                         #   rope, KV dtype, sampler defaults, tools leakage.
                                         #   Prints the exact fix for each. Run this FIRST.
rustybench ab --factor <f>               # controlled A/B on one factor (backend, exec-class, quant,
                                         #   spec-decode) on the user's own machine
rustybench config-audit                  # sweep the user's own serving configs, ranked
rustybench compare <run_a> <run_b> [--paired]   # McNemar contrast over the shared core seed set
rustybench profile                       # hardware inventory only
rustybench calibrate                     # calibration only
rustybench run --suite <s> --model <url> [--epoch <e>] [--quality] [--max-duration 4h]
rustybench status [<run_id>]             # progress, ETA, segment history
rustybench resume <run_id>               # continue a paused or crashed run
rustybench abandon <run_id>              # mark dead, keep journal
rustybench report <run_id> [--format md|json|html]
rustybench submit <run_id>               # explicit; never automatic on first use
rustybench validate-family <id> --seeds 1000
rustybench calibrate-suite               # ICC / difficulty analysis over a result corpus
rustybench verify <submission.json>      # local replay of someone else's submission
```
