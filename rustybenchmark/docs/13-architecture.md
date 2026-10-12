# 13 — Architecture

Cargo workspace. Dependency direction is strictly downward in the list — no cycles, and `bench-core` depends on nothing else in the workspace.

```
rustybenchmark/
├── Cargo.toml                # workspace
├── crates/
│   ├── bench-core/           # Instance, Generator trait, Spec, manifest schema, scoring math
│   ├── bench-gen/            # generator runtime, seed derivation (blake3), canary minting,
│   │                         #   ablation helpers, tree-edit-distance checks
│   ├── bench-tasks/          # the corpus: one module per family + template + oracle
│   ├── bench-sandbox/        # workspace materialisation, rlimits, netns/seatbelt/job object,
│   │                         #   timeouts, process supervision
│   ├── bench-oracle/         # L0..L4 graders; syn AST checks, cargo JSON parsing,
│   │                         #   proptest driver, miri/mutants/criterion wrappers
│   ├── bench-hw/             # sysinfo/nvml/gpu-probe/wgpu inventory + calibration harness
│   ├── bench-model/          # OpenAI-compatible client, retry, token accounting, backend probes
│   ├── bench-run/            # plan, journal, segments, resume, scheduling, supervision
│   ├── bench-stats/          # cluster bootstrap, ICC, McNemar, effective N, CI rendering
│   ├── bench-attest/         # challenge, manifest, canonical CBOR, signing, redaction
│   ├── bench-report/         # JSONL aggregation, terminal tables, HTML/radar export
│   └── bench-cli/            # `rustybench` binary
└── server/                   # separate workspace; axum + postgres; built last
    ├── api/
    ├── verify/               # replay, plausibility, canary screening
    └── leaderboard/
```

## Crate responsibilities

**`bench-core`** — the vocabulary. `Instance`, `Generator`, `Spec` primitives, `TaskManifest`, `OracleVector`, `WorkUnit`, `UnitId`, scoring arithmetic. No I/O, no async, no process spawning. Everything else depends on this; it depends on nothing.

**`bench-gen`** — turns a seed into an `Instance`. Owns blake3 seed derivation, canary minting, the ablation utilities, and the structural-distance measurement used by family validation. Hosts the `validate-family` logic.

**`bench-tasks`** — the corpus. One module per family. This crate is where ~90% of the eventual line count lives, and its ergonomics determine whether 200 families is achievable. Over-invest in the helper API here.

**`bench-sandbox`** — the only crate allowed to spawn processes or touch the filesystem outside the run directory. Platform-conditional. Exposes one safe API: "run this command, in this workspace, with these limits, with no network".

**`bench-oracle`** — L0 through L4. Depends on `bench-sandbox` for execution. Parses `cargo --message-format=json`, maps error codes to `failure_class`, drives proptest, wraps miri / cargo-mutants / criterion.

**`bench-hw`** — inventory and calibration. Layered probes with recorded provenance per field. Also owns the pre-run gates and the per-segment stability comparison.

**`bench-model`** — HTTP client for OpenAI-compatible endpoints. Backend probing (layer split, context, quantisation) where the backend exposes it. Token accounting and timing separation (prefill vs decode).

**`bench-run`** — the orchestrator. Plan freezing, journal append/replay, segment lifecycle, resume validity gates, scheduling controls, signal handling. This is where the correctness of the whole system concentrates; it should be the most heavily tested crate.

**`bench-stats`** — cluster bootstrap, ICC estimation, McNemar, effective-N computation, CI formatting. Pure functions over the journal; easy to property-test against known distributions.

**`bench-attest`** — challenge protocol client, canonical manifest serialization, ed25519 signing, redaction. Deliberately separate from `bench-report` so that "what we compute" and "what we disclose" cannot drift into each other.

**`bench-report`** — aggregation and rendering. Terminal tables, JSON, HTML with radar charts.

**`bench-cli`** — argument parsing and wiring only. No logic.

## Key external dependencies

| Purpose | Crate |
|---|---|
| Hashing | `blake3` |
| IDs | `ulid` |
| Serialization | `serde`, `serde_json`, `ciborium` (canonical CBOR) |
| Manifests | `toml` |
| Templates | `handlebars` or `minijinja` |
| Rust AST analysis | `syn`, `proc-macro2` |
| Property testing | `proptest` |
| HTTP | `reqwest`, `tokio` |
| Hardware | `sysinfo`, `nvml-wrapper`, `gpu-probe`, `wgpu` |
| Paths | `directories` |
| Signing | `ed25519-dalek` |
| CLI | `clap` |
| Errors | `thiserror`, `anyhow` (binaries only) |
| Tracing | `tracing`, `tracing-subscriber` |

External tools invoked, not linked: `cargo`, `rustc`, `clippy`, `rustfmt`, `miri`, `cargo-mutants`, `criterion` (as a dependency of generated benches), `sccache`.

## Invariants worth enforcing in code

These are the ones that, if violated, silently corrupt results rather than crashing:

1. **`bench-core` has no I/O.** Enforced by not adding the dependencies.
2. **Only `bench-sandbox` spawns processes.** Enforce with a lint or a CI grep for `std::process` outside that crate.
3. **The oracle path never appears in a model workspace.** Runtime assertion before every model turn, not just a test.
4. **The journal is append-only.** No code path rewrites a journal line. Corrections are new lines with a supersedes field, if ever needed.
5. **Generation is pure in the seed.** Property test: same seed ⇒ byte-identical `Instance`, across 1000 seeds, in CI.
6. **The plan is immutable after freezing.** `plan.json` is written once and opened read-only thereafter.
7. **Any change introducing a field or unit kind patches [12-schemas.md](12-schemas.md) in the same
   commit.** Rounds 2 and 3 introduced twelve fields that never reached the schema, and one of the
   resulting gaps ([R3-S1](REVIEW-3.md)) was an architectural contradiction that survived a full
   review round. A mechanical drift check — identifiers used in prose versus present in the schema —
   runs in CI.

## Testing strategy

| Layer | Approach |
|---|---|
| `bench-core` scoring | Unit tests over hand-computed vectors |
| `bench-gen` | Property tests: determinism, distance floor, ablation effectiveness |
| `bench-tasks` | `validate-family` over ≥1000 seeds per family, in CI, per family |
| `bench-sandbox` | Integration tests that *attempt* to escape: network, path traversal, fork bomb, memory bomb. Each must fail correctly on each platform |
| `bench-oracle` | Golden tests against fixture crates with known verdicts |
| `bench-stats` | Property tests against synthetic data with known ICC and known effect sizes |
| `bench-run` | Crash-injection: kill at every stage boundary, verify resume produces identical final results |
| End-to-end | A `frozen` smoke family plus a stub model server that replays fixed responses |

The crash-injection suite for `bench-run` is the one that earns its keep. Resume correctness is not something to discover in the field after somebody's 40-hour run.
