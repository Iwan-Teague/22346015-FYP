# rustyharness

A standalone **agent harness**: the runtime that drives a language model through
tools to do real work, with confinement that fails closed and results decided by
evidence, never by the agent's own say-so. Bring your own agent and model; nothing
else is required.

Built alongside [rustysuite](https://github.com/Iwan-Teague), whose capabilities —
developing and reviewing its code, operating its apps, assistants inside them —
will ship as optional add-ons (H5), off unless enabled ([ADR-0002](docs/adr/0002-standalone-first.md)).

The model is a swappable part. The harness is what makes an agent reliable.

**Aim** (owner, 2026-09-24): on its own, a full coding agent like opencode or Cline,
with every action behind the user's permission and inside confinement. Apps that
embed it, such as rustybenchmark, pass their own locked-down configuration and do
their own grading and measuring; the harness holds no app-specific code. Much of
this is not built yet: see Status below, and the owner decisions in
[the design](docs/01-design-v0.1.md#owner-decisions-after-v02-2026-09-24).

## Status

**H1, the read-only agent, is built** (design
[§9](docs/01-design-v0.1.md#9-phasing)); its phase-exit review's fixes are in
(slice H1g), the exit test passed again on a local model with both protocols,
slice H1h makes the native protocol send past actions back as the model's own
tool calls (a model copied the old text form), and the owner's sign-off on the
design's open questions remains before H2. H2 is being built on an integration
branch: edits (H2b), the macOS sandbox (H2a, H2c) and commands in it (H2d).
What works today:

- **A read-only agent loop** against a model served on loopback
  (`http://127.0.0.1`, `[::1]` or `localhost`; OpenAI-compatible, e.g. llama.cpp),
  with native tool calls or a text action protocol, hard budgets, loop detection,
  and three read tools confined to a workspace (`harness.fs.read`, `.search`,
  `.list`).
- **Evidence, not claims.** Every run that starts writes a hash-chained,
  write-ahead journal. `replay` re-drives a run from its recorded model replies
  and tool results, recomputes every context digest and policy decision, and
  names the first divergence; only `--anchor` (the chain head `run` printed)
  detects a replaced or consistently re-chained journal (design §7.1 and the
  H1e-2b, H1f-3 and H1g rows). A journal written by another harness build is
  refused by name (rows H1f-3, H1h). `resume` continues an interrupted run in a new attempt.
- **Edits, with a person's permission (H2b, in progress on a branch).** Two
  edit tools, `harness.edit.replace` (an exact, unique text) and
  `harness.edit.write` (a new file, or a whole file of at most 400 lines),
  anchored on the run's reads, applied atomically and verified, and journaled
  with their before and after digests. The workspace is edited in place with no
  sandbox or snapshot yet, so an edit asks: the terminal prompts when stdin is
  a terminal, and with nobody to ask it is denied, unless the `--policy` file
  lists the edit tools under `allow` (how an unattended run edits). `resume`
  never applies a completed edit again (design rows H2b).
- **No run can pass yet.** Checks arrive in H3, so no run ends `Passed`,
  whatever the agent says: a run that starts ends `Indeterminate { NothingChecked }`
  (`UnreadableEvidence` if its journal fails or a resume's catch-up diverges),
  exit 5; a refused run is `CouldNotRun`.
- **Commands, in a sandbox, on macOS (H2d, on the integration branch).**
  `harness.exec.run` runs one program the task file allows: `argv` is a list
  whose first item is a program's NAME from the task's `exec` section, which
  pins it to one absolute path (no `PATH` lookup, no shell unless the task
  allowlists one). It runs in the Seatbelt sandbox that passed the conformance
  suite on this host (deny-default, no network, the workspace and a per-run
  scratch directory as its only writable roots, a built environment, and
  time, CPU, memory, process-count and output limits), and the harness
  re-measures the workspace after it. A command asks like an edit unless the
  `--policy` file allows the runner. Where no backend passes (Linux and Windows
  today), a task that executes is refused before anything starts (exit 3);
  `rustyharness sandbox` shows the witness or the reason (design rows H2d).
- **Local disks only.** `run` and `resume` refuse a `state_root` that is not on
  a filesystem positively identified as local; on Windows every one is refused
  until spike S-W1, so runs work on Linux and macOS. `replay` does not check yet
  (an owner question, [OPEN-QUESTIONS](docs/OPEN-QUESTIONS.md) item 2).

Invariants that hold throughout: tool and model output is `Untrusted` data;
capability manifests are versioned, strictly parsed and refused when unknown;
there is exactly one outcome type (`gate-outcome`).

## Layout

```
crates/
  gate-outcome        the one outcome type: GateOutcome, reports, verdict()  (pure, std-only)
  harness-core        Untrusted<T>, the meter, loop detection, SHA-256, strict JSON (pure)
  harness-manifest    capability manifest v1: schema, validation, admission  (pure)
  harness-policy      effective classes, decisions, the trifecta, locality   (pure)
  harness-model-core  messages, action protocols, profiles, context builder  (pure)
  harness-model       the loopback HTTP client, replay and scripted backends
  harness-tools       the ToolProvider seam, the built-in read and edit tools, the command runner
  harness-journal     the append-only, hash-chained run journal
  harness-sandbox     fail-closed confinement (Seatbelt on macOS); locality and environment probes
  harness-run         the run driver: loop, audit replay, resume
  harness-cli         the `rustyharness` binary
adapters/             fixtures only: an example v1 manifest (providers ship their own)
docs/                 overview, design, ADRs, open questions, research
scripts/ci/gates.sh   the member gate entrypoint (fmt, purity, deny, clippy, test)
```

## Try it

```bash
cargo test --workspace
cargo run -p harness-cli -- manifest check adapters/example/manifest.json
cargo run -p harness-cli -- sandbox            # macOS: the witness; elsewhere: why it refuses
```

A run needs the binary (`cargo build --release -p harness-cli` puts it at
`target/release/rustyharness`; the commands below assume it is on your `PATH`),
a task, a model profile (`model` is the id the server lists), an existing state
directory outside the workspace, and a model server on loopback:

```json
{"task": "What is the codename in notes.txt?", "grants": ["harness.fs.read", "harness.fs.list"]}
```

```json
{"profile_version": 1, "id": "my-model", "model": "my-model",
 "context_window": 32768, "fill_ratio": 0.6, "protocol": "text",
 "tool_choice_required_ok": false, "grammar": "none", "max_active_tools": 6,
 "edit_format": "replace", "recent_turns": 5,
 "sampling": {"temperature": 0.2, "top_p": 0.95, "seed": 7, "max_tokens": 2048}}
```

```bash
mkdir -p state
rustyharness run --task task.json --profile profile.json \
  --workspace <dir> --state-root state \
  --endpoint http://127.0.0.1:8080/v1
rustyharness replay --run <run id> --task task.json --profile profile.json \
  --state-root state --anchor <chain head>
```

A task that runs commands names each program it allows, by name and by its
real path, and what the programs need (read-only roots, variables, limits:
per process 2048 MiB of address space, 600 s of CPU and 1024 MiB files, 128
processes and 1024 KiB of each output stream by default). Each command's
build output and caches go to the run's scratch directory
(`CARGO_TARGET_DIR`, `CARGO_HOME`), outside the workspace:

```json
{"task": "Make cargo test pass.",
 "grants": ["harness.fs.read", "harness.fs.list", "harness.edit.replace", "harness.exec.run"],
 "exec": {"programs": [{"name": "cargo", "path": "/Users/me/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin/cargo"}],
          "read_only": ["/Users/me/.rustup/toolchains/1.88.0-aarch64-apple-darwin",
                        "/Library/Developer/CommandLineTools", "/private/etc/ssl"],
          "env": {"DEVELOPER_DIR": "/Library/Developer/CommandLineTools", "CARGO_NET_OFFLINE": "true"},
          "limits": {"memory_mib": 2048, "processes": 128}}}
```

`run` prints the run id on stderr (`run <id> attempt 1: stopped …`) and, on
stdout, `chain_head <hex>`: keep the hex, it is the anchor. `rustyharness` with no
arguments prints every verb. The last stdout line of `run`, `resume` and `replay`
is a JSON `GateReport` and the exit code agrees with it (design §7.7).
`rustyharness profile check` scores a model on a smoke eval and prints a stamp
for its profile when the model passes (exit 0); a model that does not pass exits
1 with no stamp, a failed server check 5, an unreadable profile or a refused
endpoint 4.

## Read order

1. [docs/00-overview.md](docs/00-overview.md) — what it is, where it is used, what it must do, how apps slot in
2. [docs/01-design-v0.1.md](docs/01-design-v0.1.md) — the design (v0.2, reviewed SOUND); "Changes since v0.2" records every H1 slice
3. [ADR-0001 name and placement](docs/adr/0001-name-and-placement.md), [ADR-0002 standalone first](docs/adr/0002-standalone-first.md), [ADR-0003 licence](docs/adr/0003-licence.md)
4. [docs/OPEN-QUESTIONS.md](docs/OPEN-QUESTIONS.md)
5. [docs/research/README.md](docs/research/README.md) — the research pipeline that fed the design

Portable by design: CI runs `scripts/ci/gates.sh` on Linux and macOS; Windows
runs its cargo steps except the error-code doctests (whose result does not depend
on the target), and the purity gate checks Windows dependencies from Linux.

## Licence

**Source-available, noncommercial.** rustyharness is licensed under the
[PolyForm Noncommercial License 1.0.0](LICENSE.md): free to use, modify and share for
any noncommercial purpose — personal, hobby, research, education, charities, public
bodies. **Commercial use requires a separate licence from the author**; ask through
the GitHub profile that owns this repository. See
[ADR-0003](docs/adr/0003-licence.md) for why this is not an OSI open-source licence.
