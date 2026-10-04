# rustyharness user guide

This guide is for the person at the terminal. It covers installing and
running the `rustyharness` binary: a first run against a local model, a
hosted model through your own loopback proxy, every verb, the policy and
profile file formats, workspace modes, the security model in plain words,
and the limits. For the design, see [01-design-v0.1.md](01-design-v0.1.md);
for what is and is not built, see the README's Status section.

Everything here is as of version 0.2.0.

## Install

You need Rust (1.85 or newer) and this repository:

```bash
cargo build --release -p harness-cli
```

The binary is at `target/release/rustyharness`. Put it on your `PATH`, or
call it through `cargo run -p harness-cli --` (the examples below assume
it is on your `PATH`). Check it:

```bash
rustyharness version
rustyharness sandbox            # macOS: the confinement witness; elsewhere: why it refuses
rustyharness --help             # every verb
rustyharness doctor             # your installation, one PASS/WARN/FAIL line per check
```

`rustyharness sandbox` matters before your first run that executes
commands: the harness refuses to run anything (exit 3) on a host where no
confinement backend passes, and macOS is the platform whose backend is
built today.

## Five minutes: a local model

You need a model server speaking the OpenAI-compatible API on loopback
(`127.0.0.1`, `[::1]` or `localhost` — anything else is refused). llama.cpp's
`llama-server` is the usual choice:

```bash
llama-server -m your-model.gguf --port 8080
```

Three small files, all strict JSON (unknown keys are refused):

`task.json` — what the model should do, and which capabilities it gets:

```json
{"task": "What is the codename in notes.txt?", "grants": ["harness.fs.read", "harness.fs.list"]}
```

`profile.json` — which model, how to talk to it. The easy way is to let
the harness write one (`profile init`, next section); the hand-written
form:

```json
{"profile_version": 1, "id": "my-model", "model": "my-model",
 "context_window": 32768, "fill_ratio": 0.6, "protocol": "text",
 "tool_choice_required_ok": false, "grammar": "none", "max_active_tools": 6,
 "edit_format": "replace", "recent_turns": 5,
 "sampling": {"temperature": 0.2, "top_p": 0.95, "seed": 7, "max_tokens": 2048}}
```

`protocol` is `text` (the model writes `<action>{json}</action>`) or
`native` (OpenAI tool calls). `model` is the id the server lists. A state
directory that already exists, outside the workspace:

```bash
mkdir -p state
rustyharness run --task task.json --profile profile.json \
  --workspace . --state-root state \
  --endpoint http://127.0.0.1:8080/v1
```

On stderr you get the run id and the model's and tools' activity; on
stdout, `chain_head <hex>` and then one JSON line, the run's `GateReport`.
Keep the `chain_head` hex: it is the anchor that proves the journal was
not replaced. To re-derive the whole run from its journal:

```bash
rustyharness replay --run <run id> --task task.json --profile profile.json \
  --state-root state --anchor <chain head>
```

(With the defaults from a config file, see "Defaults and config" below,
`replay --run <id>` alone is enough — the run records its own inputs.)

Exit codes: 0 passed, 1 failed, 2 usage, 3 confinement refused, 4
unreadable input, 5 indeterminate. **No run passes yet** (checks arrive in
H3): a run that starts ends `Indeterminate { NothingChecked }`, exit 5.

## Five minutes: a hosted model through a loopback proxy

The harness talks to loopback only, and that is deliberate: the context —
your task, your files' contents — goes to exactly the endpoint you chose.
To use a hosted provider, run your own small proxy on `127.0.0.1` that
forwards to it and holds the provider key. Anything speaking
`/v1/chat/completions` and `/v1/models` on loopback works; no harness code
is involved.

A hosted profile says so, and carries its price table (micro-USD per
kilo-token):

```json
{"profile_version": 1, "id": "hosted-m", "model": "m",
 "context_window": 32768, "fill_ratio": 0.6, "protocol": "text",
 "tool_choice_required_ok": false, "grammar": "none", "max_active_tools": 6,
 "edit_format": "replace", "recent_turns": 5,
 "sampling": {"temperature": 0.2, "top_p": 0.95, "max_tokens": 2048},
 "upstream": "hosted",
 "price_table": {"in_micro_per_ktok": 3000, "out_micro_per_ktok": 15000}}
```

Declared hosted, the harness prints a disclosure in `chat`/ACP, records
`endpoint_class: loopback-proxy-hosted` in the journal, refuses any
capability marked at personal sensitivity or above, and requires a cost
budget in the task (`"budget": {"cost_micros": 100000}`) which it charges
at the price table. Undeclared, a profile is just a local loopback model
as far as the harness can tell — the declaration is on you. Full recipe:
[hosted-proxy.md](hosted-proxy.md).

Then run exactly as before, with `--endpoint http://127.0.0.1:<proxy port>/v1`.

## profile init, profile check

`profile init` asks the server what it serves and writes a conservative
profile:

```bash
rustyharness profile init --endpoint http://127.0.0.1:8080/v1
rustyharness profile init --endpoint http://127.0.0.1:8080/v1 --out my-model.json
```

From a terminal it lists the models and you pick one by number or id;
with exactly one model listed (or stdin not a terminal) it takes that
one. The written profile is 0600.

`profile check` runs a live smoke eval (several cases) against the
endpoint and prints a stamp to add to the profile when the model passes —
the stamp records that this model, at that endpoint, handled the
protocols:

```bash
rustyharness profile check --profile my-model.json --endpoint http://127.0.0.1:8080/v1
```

Exit 0 with a stamp, 1 when the model does not pass, 4 for an unreadable
profile or refused endpoint, 5 when the harness cannot check.

## doctor

```bash
rustyharness doctor [--endpoint <url>] [--state-root <dir>]
```

One PASS/WARN/FAIL line per check — confinement, state root (exists,
local disk), config file, endpoint (reachable, lists models), profile,
exec presets (the programs `--allow-exec` would pin), terminal (is
somebody there to answer asks) — and a suggested fix. Exit 0 when
nothing FAILED. Start here when anything feels wrong.

## run, resume, replay

`run` is the headless verb: one task, one journal, the exit-code table
above. `resume --run <run-id>` continues an interrupted run in a new
attempt: it verifies the journal chain and that the workspace still
digests to the last recorded state, re-feeds completed edits and commands
(never re-runs them), and re-decides a trailing intent. `replay --run
<run-id>` re-drives the run from its recorded model replies, tool
results, approval answers and nonces — recomputing every context digest,
policy decision, loop signal and stop — and names the first divergence;
`--anchor <sha256>` additionally detects a replaced or re-chained journal.

Every run copies its resolved task, profile and policy into
`runs/<id>/inputs/` (0600), so `replay --run <id>` and `resume --run <id>`
need no other flags. Flags still override, and must digest to what the
run recorded — a replay with a different task file is refused, not
silently re-derived. The gate children (`run`, `resume`, `replay`, and
also `chat`, `schedule run-now`) always print a report line as the last
stdout line, whatever happened.

`events --run <run-id> [--follow]` projects an attempt's journal as
newline-delimited JSON; `run --output stream-json` prints the same stream
live, plus a `usage {...}` footer (steps, model calls, tokens, wall time,
tool counts, and the cost at a hosted profile's price table).

`review --run <run-id> --workspace <dir>` and `compare` (2–4 profiles on
the same task, facts only, `compare reveal --winner` to open the
label→model map) are for looking at runs after the fact.

## chat

`chat` is the interactive line REPL, a gate child like `run`:

```bash
rustyharness chat --task task.json --profile profile.json [--endpoint <url>]
```

It takes the run options that make sense for a session (`--workspace`,
`--state-root`, `--policy`, `--gate`, `--allow-exec`, `--preset`,
`--shell`, `--no-default-denies`, `--workspace-mode`, `--scratch-with-git`,
`--allow-session-grants`, `--accept-edits`), plus:

- `--resume [<run-id>]` — continue a session; no id gives you a picker;
- `--continue` — the most recent session;
- `--fork RUN@STEP` — branch a finished session from one of its steps.

The task text is the first message; each further line you type is a
follow-up user message. Slash commands (`/help` lists them):
`/status`, `/tools`, `/policy`, `/sessions`, `/resume <id>`,
`/fork RUN@STEP`, `/todo`, `/usage`, `/diff`, `/undo`, `/rewind [N]
[--force-keep-external]`, `/plan` and `/build` (plan mode keeps the
session read-only), `/clear`, `/exit`, and — in a scratch session —
`/apply` to copy the session's edits onto the original workspace after a
diff. Approvals are asked at the terminal (`approve this one call?
[y/N]`); `y`/`yes` covers that one call only.

## sessions, gc, apply

```bash
rustyharness sessions [--state-root <dir>] [--run <run-id>]
rustyharness gc --run <run-id> | --older-than <N>d [--state-root <dir>]
rustyharness apply --session <run-id> [--state-root <dir>] [--dry-run]
```

`sessions` lists the sessions on a state root. `gc` removes only a
finished run's `workspace/`, `grading/` and `scratch/` — never its
journal, blobs or inputs, so replay and audit stay possible. `apply` is
the after-the-fact form of `/apply`: it copies an ended scratch session's
edits back onto the original workspace, only after showing the diff and
reading a typed `apply`, and only onto an original that still digests to
what the copy was made from — anything else is reported as a conflict and
skipped, never overwritten.

## schedule

`schedule` installs a timed, unattended run as a user-level launchd plist
(macOS) or systemd user service + timer (Linux):

```bash
rustyharness schedule add --name nightly --task task.json --daily 03:00
rustyharness schedule add --name sweep   --task task.json --every 6h
rustyharness schedule list
rustyharness schedule run-now --name nightly
rustyharness schedule remove --name nightly
```

`add` stores the validated task, profile and policy byte-for-byte in
`<state-root>/schedules/<name>/` (0600) and — only after you type `y` on
the same input it reads lines from — writes the OS unit. The task file
must carry an explicit budget (`steps` or `wall_secs`), and
`--allow-exec`/`--preset`/`--shell` are refused: a timed run executes
only what the task file pins, and every ask is denied, even at a
terminal. `run-now` re-checks every recorded digest and runs exactly as
the timer would. Nothing is loaded into launchd or systemd for you; the
command tells you what it wrote.

## The policy file format

A policy is three lists of selectors; the first matching list decides,
and anything unmatched is **denied**:

```json
{"deny":    ["harness.fs.read"],
 "ask":     ["harness.edit.replace"],
 "allow":   ["harness.fs.list", "provider.acme.*"]}
```

A selector is one capability id (`harness.fs.read`) or a whole provider
(`provider.acme.*`). Deny cannot be overridden. What is not in the file
has defaults: reads are allowed, edits ask, commands (`harness.exec.run`)
ask, irreversible or shared things ask every time, a model-served MCP
capability asks — and an ask with nobody to answer (no terminal, or
`"approver": "none"` in the config) is a denial. The sentinel
`harness.task.submit` and the checklist tool are allowed by their own
named rules regardless. Session grants (`--allow-session-grants` and the
chat `/status` flow) let an answered ask be kept for the rest of the
session, bounded by the run's journal; a LAN-port command is never
covered. `--accept-edits` overlays an allow rule for the edit tools;
`--no-default-denies` turns off the built-in overlay that denies the
usual secret files (`.env`, `*.pem`, `id_rsa*`, `.ssh/**`, ...) to reads
and edits. Replay and resume must be given the same overlay flags the
run had.

## Profiles

A profile (see the examples above) says: which model (`model`), how to
talk to it (`protocol`, `sampling`, `stream_include_usage_ok`,
`tool_choice_required_ok`, `parallel_tool_calls` — native only),
how much context it has (`context_window`, `fill_ratio`), how much of it
to keep recent (`recent_turns`), how many tools may be active at once
(`max_active_tools`, 5–8), how tool documentation is rendered
(`tool_docs`: `full` or `terse` for small models), the read window
(`max_read_lines`, up to 2000), and — for a hosted model — `upstream`
and `price_table`. `profile init` writes a conservative one; `profile
check` stamps it after a live smoke eval. Fields are strictly parsed:
unknown keys are refused, out-of-range values are refused.

## Workspace modes

`--workspace-mode` (run, chat; replay and resume keep the mode they find):

- `in-place` (default): the harness works on the directory you named.
- `scratch`: the run works on a copy under the state root; nothing in
  your original tree changes until you apply. `--scratch-with-git` copies
  `.git` too, so diffs and `git` commands inside the session see history.
- `worktree`: refused in this build (it would run `git worktree add`, and
  this build has exactly one spawn module, the sandbox's).

A scratch session's edits reach your tree only through `/apply` (live) or
`apply --session <run-id>` (after it ends), with a diff and a typed
confirmation.

## Defaults and config

`<config dir>/config.json` (optional, strict JSON, flags always win)
sets defaults: `endpoint`, `profile`, `policy`, `state_root`,
`approver` (`"terminal"` or `"none"`), and `exec_programs` (the
`--allow-exec` names). The config dir is
`$RUSTYHARNESS_CONFIG_HOME`, else `~/Library/Application
Support/rustyharness` on macOS, else `$XDG_CONFIG_HOME/rustyharness` or
`~/.config/rustyharness`. Without a configured `state_root`, the default
is the per-user data directory's `rustyharness/`, created 0700. A
`--workspace` default is the current directory. The config is read only
from the user's config directory, never from the workspace.

## The security model in plain words

- **The model is untrusted.** Everything it says is data, never
  instruction: its output is parsed as tool calls or withheld as a format
  error, and no model text is ever executed or shown as harness fact.
- **Nothing happens without a grant.** The task file lists the
  capabilities the model may use at all; the policy then denies, asks or
  allows each call; an ask with nobody to answer is a denial. The person
  at the terminal approves one call at a time.
- **Confinement, or nothing.** Commands run only inside a confinement
  backend that passed this host's conformance suite (macOS Seatbelt
  today): deny-default, no network, the workspace and a per-run scratch
  as the only writable roots, built environment, time/CPU/memory/output
  limits. Where no backend passes, a task that executes is refused
  before anything starts. `argv[0]` is a program name pinned by the task
  file to one absolute path; no `PATH` lookup, no shell unless you asked
  for one.
- **Local disks only.** The state root must be on a positively
  identified local filesystem; the endpoint must be loopback.
- **The record is the evidence.** Every run writes a hash-chained,
  write-ahead journal (tool and model output go into it as untrusted
  blobs). `replay` recomputes the whole run and names the first
  divergence; `--anchor` catches a replaced journal. A journal from
  another harness build is refused by name.
- **Hosted is a declaration, not a detection.** `upstream: "hosted"`
  turns on disclosure, a personal-data refusal and a cost budget. The
  harness cannot detect a proxy; what you declare is what you get.

## Limits

- Budgets per run: steps (default 50, task 1–500), wall time (default
  30 min, task 1 s–24 h; approval waits excluded), tokens (profile
  derived; chat and ACP sessions get 1 M), cost (hosted price table ×
  reported tokens; a priced hosted run needs an explicit
  `budget.cost_micros`), 3 consecutive format errors with 1 repair round.
  The model is told at 50/80/90% of steps and wall and before the last
  step.
- Commands: 120 s each by default (task `exec_secs` up to 1 h), 2048 MiB
  address space, 600 s CPU, 1024 MiB per file, 128 processes, 1024 KiB
  per output stream, by default — a task's `exec.limits` may set its own.
  At most 8 loopback ports per run (`--allow-port`), each 1024 or above,
  LAN ports a subset, and the model endpoint's own port is refused as a
  grant.
- Tools: read window 100 lines (profile up to 2000); search shows 50
  hits, 10 per file, counts the rest; glob up to 90 results; whole-file
  writes up to 400 lines; multi-edits up to 20 replacements in one file;
  checklists around 20 items. At most `max_active_tools` (5–8)
  declarations at once.
- Context: rebuilt every turn, determinism preserved by pointer-only
  compaction (old observations become index lines, never model-written
  summaries); a turn that cannot fit stops the run
  (`ContextExhausted`), it is never silently truncated.
- Approvals: one call per `y`; unanswered asks are denied after the
  deadline (15 min for a run's asks; a chat's ask waits for your line or
  the model's step deadline).
- Schedules: macOS launchd and Linux systemd user units only, installed
  by the OS's own loader, never by the harness; nothing runs while your
  machine is off.
