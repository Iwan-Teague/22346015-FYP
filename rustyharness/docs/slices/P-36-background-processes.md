# P-36: background processes, granted loopback ports, and the confined file-op helper (design note)

Status: design for owner review (roadmap §4.3 P-36, ARCH; OD-5 a/b; owner decision 7 of
`docs/OWNER-DECISIONS.md`). Docs only. Written unattended: every open point below is decided
fail-closed and the reason is written next to it; the points only the owner can settle are in §16.
Verified against branch `w/P-36` at `912fdd2`: `crates/harness-sandbox/src/{confine_spawn.rs,
seatbelt.rs,profile.rs,spec.rs,conformance.rs,lib.rs}`, `crates/harness-sandbox/tests/conformance_macos.rs`,
`crates/harness-tools/src/{exec.rs,edit.rs,builtin.rs,provider.rs}`, `crates/harness-policy/src/builtin.rs`,
`crates/harness-run/src/{session.rs,presubmit.rs,driver/*}`, `scripts/ci/{purity.sh,purity-selftest.sh}`,
design `§4.8, §5.2-5.4, §6.1-6.6`, rows H2a/H2c/H2d/H2f, P-05, P-11, P-29, P-41.

**Terms.** *Bg process*: a program the model started with `harness.exec.start` that runs while the loop
goes on. *Instance*: one `sandbox-exec` invocation; the kernel lets its members signal only each other
(`(allow signal (target same-sandbox))`, `profile.rs:97`). *Domain stub*: the perl `STUB` of
`confine_spawn.rs` that forks the program, waits, and sweeps the instance. *Control pipe*: the stub's
stdin; the harness closing it (or the kernel closing it when the harness dies) means "stop and sweep".
*Helper*: the confined file-op helper of §7. *Model port*: the TCP port of the loopback model endpoint.

---

## 0. Decisions at a glance

| # | Decision |
|---|---|
| D1 | Three new tools: `harness.exec.start`, `harness.exec.read` (no `id` = list), `harness.exec.stop`. `list` is folded into `read` to cost one tool slot less (Q-6 cap 5-8). |
| D2 | **One sandbox instance per bg process**, started through the existing confined spawn (`Backend::spawn`, same profile renderer, same domain stub, same three programs). Stopping = closing its control pipe, so the stub sweeps exactly that instance. No new spawn site, no new program. |
| D3 | A live child API on `ConfinedChild` (`try_status`, `read`, `stop`), a ring buffer of 1 MiB per stream with a monotonic byte cursor, a running SHA-256 of the whole stream, and a deadline closer thread that closes the control pipe at the process's lifetime even while the loop is blocked in a model call. `wait()` (exec.run) is unchanged. |
| D4 | **Kill at every stop**: every exit path of a run, a turn (turn-scoped processes) and a session journals `BgStopped` for every live id before `TurnEnded`/`RunStopped`; `Drop` is the backstop. Harness crash: the kernel closes the control pipes and every stub sweeps (no code needed, a conformance case proves it). Orphans exist only if a member kills its stub (the named H2a R-1 gap); they are detected at the next start by a marker in `state_root` plus a lease file, and bg/ports are then refused until cleared (§5.4). |
| D5 | Ports: the task grants loopback ports (`exec.ports`); a start names a subset; Seatbelt rules `network-bind`/`network-inbound` on `localhost:<port>` for the owner instance and `network-outbound` to the live granted ports for the run's other confined calls, rendered **after** `(deny network*)`. Ports below 1024 and the model port are refused at load, at validation and at render (three layers). A live port probe on this host must pass before any port is granted. |
| D6 | A LAN-visible bind is a separate task grant (`exec.lan_ports`) that **adds the E label to the trifecta**, so with a private workspace the session is refused (INV-9, no override); with `workspace_public: true` each start that names a LAN port is asked every time at the `protected_action` tier, never covered by a session grant or allow rule. |
| D7 | The **confined file-op helper**: a second, fork-less perl stub (`FILEOP_STUB`, own pinned file) run in its own instance whose profile grants only the workspace (read-write, or read-only when no edit tool is granted). In every run that holds an execute-class grant, all built-in file tools and the workspace walk do their filesystem access through it. The kernel checks each access at the moment it happens, which closes the check-then-use race; option (b) stays for sync `exec.run` as an extra stop. |
| D8 | Linux and Windows refuse bg, ports and the helper exactly as they refuse exec today (no witness). The backend-neutral contract the Linux slice (S-L) must meet is written in §8. |
| D9 | Journal: two new kinds `BgStopped`, `OrphanCheck`; a `bg` object in `ToolFinished` (like `exec`); `connect` in the exec record only when non-empty (old digests unchanged); header gains `bg`, `ports` and `file_ops`. Context format unchanged (`rh-context/5` batch, `/6` session): bg facts reach the model only through tool results. |
| D10 | Audit re-feeds every bg result and harness measurement and recomputes ids, refusals, cursor arithmetic, the state machine, and the "every live id stopped before the run or turn ends" rule (INV-40). |
| D11 | Pin discipline: three serial slices change pinned files (`confine_spawn.rs` in P-36b and P-36l; the new `fileop_stub.rs` pin in P-36d); procedure in §13. |

---

## 1. Scope and non-goals

In scope: background processes for dev servers, watchers and long tests; loopback ports so the user's
browser (or a confined test command) can reach them; the confined file-op helper (owner decision 7);
the conformance cases first; policy, journal, replay, adversarial tests; the slice split.

Not here (named, each with its fail-closed state):
- **stdin to a bg process** (interactive programs, REPLs): stdin stays `/dev/null`. The stdin relay the
  MCP client needs (P-37) is a stub change on top of P-36b's live API, owned by P-37.
- **Ephemeral loopback ports for sync `exec.run`** (test suites that bind `127.0.0.1:0`): D31 stays (no
  bind at all). Follow-up after P-36a's measurements (Q-P36-4).
- **Hosted-network egress** from bg processes: `network = none` except the granted loopback ports.
- **Model-visible notices about bg state** (a context block listing running processes): needs a context
  format bump (H-D chain); the model uses `exec.read` without an id instead.
- **CPU accounting** of bg processes against a budget: there is no CPU dimension in the meter; each
  instance has an RLIMIT_CPU equal to its lifetime and the process cap; named residual.

---

## 2. Threats (R6 delta)

| Threat | New because | Control | Test |
|---|---|---|---|
| A process outlives the run and keeps writing the workspace | processes now live across steps | kill at every stop (§5), stub sweep on pipe close, `Drop` backstop, INV-40 audited | `bg_process_killed_on_run_end`, `ft_bg_parent_sigkill_sweeps_the_domain` |
| A bg process races the harness's in-process file tools (symlink swap between check and open) | option (b) no longer holds: by design a process is alive between calls | all file access in the kernel-confined helper (§7) | `fileop_symlink_swap_race_never_reaches_outside`, `hostile_bg_symlink_swap_vs_edit_never_escapes` |
| A bg process reaches the model server (prompt injection into the model's own channel, reading other users' context) | first time any confined process gets network | model port refused at three layers + live port probe | `ft_ports_connect_to_model_server_port_is_refused`, `bind_to_model_server_port_refused` |
| Port squatting: binding a port a local service normally uses so local clients send it data | first listener | only user-granted ports; <1024 refused; the harness checks the port is free before start | `hostile_bg_port_squat_ungranted_refused`, `bg_start_refuses_when_port_busy_on_host` |
| LAN exposure: other machines read workspace data through the listener | LAN bind | egress label for the trifecta; ask every start; protected tier | `lan_ports_label_egress_for_trifecta`, `lan_bind_requires_separate_grant` |
| Output flood exhausts harness memory or the context | long-lived streams | ring buffer bounded per stream; reads capped at 16 KiB; drops counted | `ft_bg_output_flood_keeps_memory_bounded` |
| Fork bomb in a bg process | long-lived | per-instance member-count watchdog (FT-5 bar), process cap | `hostile_bg_fork_bomb_contained` |
| A member kills its stub, then `setsid`s away (orphan) | window is now minutes, not one call | Unconfirmed → group kill → `SandboxLost`; marker + lease → next start refuses bg | `hostile_bg_member_kills_stub_stops_run_and_marks_orphan` |
| A forged stub report in the program's own output | reads of live stderr | the report is trusted only as the final bytes with stub exit 0 (unchanged); reads strip only a trailing well-formed report after the stub exited | `hostile_bg_forged_stub_report_in_output_ignored` |
| A hanging file operation (FIFO or odd mount) holds the run past its wall | known residual (§11 "in-process reads are not interruptible") | the helper is killable; per-request deadline; FIFOs denied by profile | `hanging_file_op_ends_in_tool_timeout_within_wall` |

---

## 3. The tools

All three exist only when the task grants them and holds the exec setup (`exec.programs`); a grant of
any of them without `harness.exec.run`'s setup refuses the task (exit 4), as the exec flags do today.

### 3.1 `harness.exec.start`
Args (strict schema, `deny_unknown_fields`):
`{argv: [string], cwd?: string, ports?: [u16] (<=4), scope?: "turn"|"session" (default "turn"),
lifetime_secs?: u32 (1..=BG_LIFETIME_MAX, default 1800), ready?: {port: u16} | {text: string (<=256 B)},
ready_secs?: u32 (<=60, default 10)}`.

Behaviour, in order (each refusal is a deterministic, recomputed tool error; nothing starts):
1. `argv[0]` resolved by NAME against the pinned allowlist (INV-13, as exec.run); `cwd` by the
   workspace rule.
2. Limits: live bg count `< BG_MAX_LIVE` (4); starts this run `< BG_MAX_STARTS` (16). "Live" is computed
   from journaled state only (started minus `BgStopped`), so it is recomputable (§11).
3. Ports: each in the task grant (`exec.ports` or `exec.lan_ports`), not held by another live id; a
   `lan_ports` member makes this call a `protected_action` ask (§9).
4. `scope: "session"` only when the header says `bg.persist: true` (`--bg-persist`), else refused.
5. Witness: `covers(BG_CASES)`, and `covers(PORTS_CASES)` plus the run's port probe digest when `ports`
   is non-empty (planning already refused the task otherwise, §9; this is defence in depth).
6. Host check: for each port, the harness binds `127.0.0.1:<port>` itself and releases it at once; a
   bind failure means another program holds the port: refused `port_busy` (measurement, journaled in the
   result). The race between this check and the child's bind is harmless: the child's bind then fails.
7. Spawn through `Confinement::spawn_live` (P-36b) with the exec.run `ConfinedSpec` plus
   `network: Network::Loopback { bind: ports, connect: [], lan: <named ports are lan> }`, limits
   `{wall: lifetime, cpu: lifetime, memory, processes, file_size}` from `ExecLimits`, output ring
   `BG_RING_BYTES` (1 MiB) per stream.
8. `ready`: wait at most `ready_secs` for a TCP connect from the harness to `127.0.0.1:<port>` to succeed
   (connect, then close; nothing is read), or for `text` to appear in either stream. Result says `met`
   or `not met` with the waited time; not met is not an error (the process keeps running).

Result text: `started background process 2 (program cargo, ports 5173 loopback, stops at the end of this
turn or after 1800 s)` + the first output since start (tail mode, §3.2 cap). The record is §10.2.

### 3.2 `harness.exec.read`
Args: `{id?: u32, mode?: "next"|"tail" (default "tail"), since_out?: u64, since_err?: u64,
max_bytes?: u32 (<=16384, default 16384), wait_secs?: u32 (<=30, default 0)}`.

- No `id`: list every id of the run with `state` (`running`, `exited`, `stopped`, `lost`), program name,
  ports, scope, start step, and bytes not yet delivered. Recomputable from records (§11).
- With `id`: `since_*` default to the cursor delivered so far for that stream. With `wait_secs`, block
  until new bytes arrive or the process ends (charged as tool time).
- Cursor arithmetic per stream (pure fn `harness_tools::bg::window`, unit-tested):
  `total` = bytes the program has written so far; `ring_start = total - min(total, BG_RING_BYTES)`;
  `from0 = max(since, ring_start)`, `dropped = from0 - since` (bytes lost to the ring before the model
  asked); in `next` mode `from = from0`, `to = min(total, from + cap)`, `skipped = 0`; in `tail` mode
  `to = total`, `from = max(from0, total - cap)`, `skipped = from - from0`. `to` is moved back to a UTF-8
  character boundary (at most 3 bytes) so the cursor equals the bytes shown. The delivered cursor
  becomes `to`. The cap is split stdout 3/4, stderr 1/4, an unused share flowing to the other stream.
- Rendering: two labelled sections, each `[N bytes dropped]`/`[N bytes skipped]` markers when non-zero,
  then the bytes (lossy UTF-8; the context's sanitiser and nonce withholding apply as for every
  `Untrusted` tool output).
- After the stub has exited, a stderr chunk that ends in a well-formed stub report (`parse_report`) is cut
  before it and the cursor does not pass it: the model never sees the harness's own report line.

### 3.3 `harness.exec.stop`
Args: `{id: u32}`. Closes the control pipe; the stub stops the program and sweeps; the call waits the
sweep grace (sweep deadline + 2 s, P-41). Result: end (`exited(c)`, `signaled(n)`, `stopped`,
`process_limit`, `exec_failed`, `unknown`), cleanup (`confirmed(kills)` / `unconfirmed`), and the
output not yet delivered (tail mode, capped). Then, exactly like exec.run (H2d), the workspace is walked
(through the helper) and the tree digest journaled. Stopping a stopped or exited id is a deterministic
refusal with the recorded end repeated. `cleanup: unconfirmed` → every other bg is stopped, then the run
stops `SandboxLost` (§5.1).

### 3.4 Constants (data, in `harness-tools::bg`, documented in the header's `bg` object)

`BG_MAX_LIVE = 4`, `BG_MAX_STARTS = 16`, `BG_LIFETIME_DEFAULT = 1800 s`, `BG_LIFETIME_MAX = 4 h`
(and never past the run's wall budget remaining at the start), `BG_RING_BYTES = 1 MiB` per stream,
`BG_READ_MAX = 16 KiB`, `BG_READY_MAX = 60 s`, `BG_READ_WAIT_MAX = 30 s`, `PORTS_PER_START = 4`,
`PORTS_PER_TASK = 8`, `PORT_MIN = 1024`.

---

## 4. The process model on macOS

### 4.1 Why one instance per process (and not one supervisor instance per run)
A shared instance would make "stop process 2" a process-group kill inside the instance, and a
`setsid`'d descendant leaves its group while staying in the instance: stop would not be complete. With
one instance per process, stop is the stub's sweep of the whole instance, which the conformance suite
already proves complete for `setsid` and double-fork (FT-16, FT-16-setsid). The cost is one perl stub
(~3 MB, ~10 ms) per bg process, bounded by `BG_MAX_LIVE`.

### 4.2 Live child API (P-36b, `confine_spawn.rs` + `lib.rs`)
```rust
impl ConfinedChild {
    pub fn wait(self) -> ConfinedExit;                       // unchanged (exec.run, probes)
    pub fn try_status(&mut self) -> Option<ConfinedExit>;    // Some once the stub has exited and been collected
    pub fn read(&self, s: Stream, since: u64, cap: usize, mode: Mode) -> Chunk;  // §3.2 arithmetic over the ring
    pub fn totals(&self) -> StreamTotals;                    // total bytes + running sha256 per stream
    pub fn stop(self) -> ConfinedExit;                       // close the control pipe, wait sweep grace, collect
}
pub trait Confinement { /* existing */ fn spawn_live(&self, spec: &ConfinedSpec, ev: &Conformed, live: LiveOpts) -> Result<ConfinedChild, SpawnError>; }
pub struct LiveOpts { pub ring_bytes: u64, pub lifetime: Duration }
```
- The `Cap {head, total, tail}` reader becomes `Ring {buf (circular, cap ring_bytes), total, sha: Sha256Stream,
  tail (4 KiB, for the report)}`; `wait()` keeps reading `head` semantics through the same struct (head =
  first `output_bytes`), so exec.run's `ConfinedExit` is byte-identical (test `wait_api_unchanged_for_exec_run`).
- **Deadline closer:** `stdin` moves into `Arc<Mutex<Option<ChildStdin>>>`; a thread sleeps until
  `started + lifetime` and drops it. The stub sees the pipe readable and sweeps in real time, even while
  the loop waits up to 300 s for the model. `stop()` drops it early. The record of a lifetime stop is
  written at the next step boundary (§5.2).
- No change to the stub text for this slice: the stub already treats "control pipe readable or closed"
  as stop, and sweeps on the harness's death (per-pass `ESRCH` acceptance, `confine_spawn.rs:73`).
  The pin still changes (the Rust side of the file changes).

### 4.3 Profile and spec (`spec.rs`, `profile.rs`; not pinned)
```rust
pub enum Network {
    None,
    Proxy { allowlist_id: String },                 // H4, still refused
    Loopback { bind: Vec<u16>, connect: Vec<u16>, lan: Vec<u16> },  // lan ⊆ bind
}
pub struct Context<'a> { /* existing */ pub reserved_ports: &'a [u16] }  // must hold the model port
```
`validate` refuses: a port `< 1024`; a port in `reserved_ports`; duplicates; `lan` not a subset of `bind`;
more than `PORTS_PER_START` binds; `connect` containing a reserved port; `Loopback` when the backend's
witness lacks `PORTS_CASES` (new `SpecError::Unsupported("loopback ports (not conformed on this host)")`).

`render` appends after `(deny network*)` (later rules win, measured E6; the order is golden-tested):
```
(allow network-bind network-inbound (local tcp "localhost:5173"))     ; per bind port not in lan
(allow network-bind network-inbound (local tcp "*:8000"))             ; per lan port only
(allow network-outbound (remote tcp "localhost:5173"))                ; per connect port
```
and then, for every reserved port (the model port at least), a final
`(deny network* (remote tcp "localhost:<m>") (local tcp "*:<m>"))` so that even a renderer bug that let a
reserved port into a list is overridden by a later deny. SBPL's network filters accept only `*` or
`localhost` as the host part; whether `localhost:<p>` covers `::1` and whether it refuses a bind to
`0.0.0.0:<p>` is **UNVERIFIED** and is exactly what P-36a measures first. If a measurement shows the
loopback-only rule cannot be expressed (for example `localhost:<p>` also admits a wildcard bind), P-36a
leaves `PORTS_CASES` out of the matrix row and ports stay refused on macOS (fail closed); the slice note
records the measurement.

`Network::None` renders byte-identically to today (golden), so the live probe digest and every exec
profile are unchanged.

`/private/etc/hosts` is not readable in the profile today, so a program that resolves the name
`localhost` may fail; P-36a measures it and, if needed, adds `(allow file-read* (literal
"/private/etc/hosts"))` to `Loopback` profiles only. The recommended bind address in tool docs is
`127.0.0.1`.

### 4.4 Live port probe (P-36a, `seatbelt.rs`)
`Seatbelt::probe_ports(&Conformed, bind: &[u16], reserved: &[u16]) -> Result<PortsWitness, Unavailable>`,
run at planning when the task grants ports: one confined perl script (fixed text in `seatbelt.rs`, like
`PROBE_SCRIPT`) that must: bind and listen on one granted port (ok), bind an ungranted port (refused),
bind `0.0.0.0:<granted non-lan port>` (refused), connect to a harness-held listener on a reserved port
(refused, and the listener must see no connection), connect to a routable address (refused). The
observations digest is `PortsWitness.digest`, journaled in the header's `ports` object. A failure is
`Unavailable{LiveProbeFailed}`: the run is refused (exit 3) because its task asked for ports. The
existing H2 probe is not touched.

---

## 5. Kill at every stop

### 5.1 Every stop point

| Stop point | Who stops | What is journaled (before the boundary record) |
|---|---|---|
| `harness.exec.stop` | the tool | its `ToolFinished` with `bg.op = stop` |
| program exits by itself (stub sweeps at once) | observed at the next step boundary poll | `BgStopped{reason: "exited"}` |
| lifetime reached | deadline closer thread (real time) | `BgStopped{reason: "lifetime"}` at the next boundary |
| turn end, `scope: "turn"` (session) | session loop, before `TurnEnded` | `BgStopped{reason: "turn_end"}` |
| session end (`InputEnded`, `/exit`, EOF) | session loop | `BgStopped{reason: "session_end"}` |
| run end: submit accepted (batch), any `Budget(_)`, `ContextExhausted`, loop stop, `PolicyAbort` | driver, before `RunStopped` | `BgStopped{reason: "run_end"/"budget"}` |
| `SandboxLost` from any confined call | driver: stop every other live id, then stop | `BgStopped{reason: "sandbox_lost"}` |
| journal failure / poisoned writer | `BgManager::drop` (no journal possible) | nothing (the attempt is uncommitted; resume reaps, §11.3) |
| harness panics, is killed, the machine sleeps | the kernel closes the control pipes; each stub sweeps | next start: `OrphanCheck` (§5.4) |

Rule (INV-40): for every id whose start succeeded, the journal holds a stop record (`exec.stop` or
`BgStopped`) before `TurnEnded` (turn scope), `InputEnded`, and `RunStopped`. The audit checks it (§11).

Order at a run's end: poll all children; journal `BgStopped{exited}` for those already gone; close every
remaining control pipe **together** (so N processes stop in one grace, not N); collect; journal each
`BgStopped`; measure the tree once (through the helper); then `RunStopped`. Any `unconfirmed` cleanup sets
the stop cause to `SandboxLost` if the cause was not already a harder one (journal failure).

### 5.2 Step-boundary poll
At the start of every step (before `ContextBuilt`) and before every policy decision of `exec.start`, the
driver calls `BgManager::poll()`: every child with `try_status() == Some(_)` gets a `BgStopped` record
(reason `exited`, or `lifetime` when the closer fired). So every state the harness acts on is in the
journal before the act, and the audit can recompute "live" counts and refusals without timing.

### 5.3 Crash: the kernel does the kill
When the harness process dies for any reason, the kernel closes its end of every control pipe. Each stub
sees the pipe readable, ends its wait loop with `end=stop`, and sweeps its instance; its per-pass check
accepts `ESRCH` (the harness is gone) by design (`confine_spawn.rs:70-76`). This is the guaranteed half
of crash recovery and it needs no new code: P-36b adds the conformance case
`ft_bg_parent_sigkill_sweeps_the_domain` (a test re-execs its own binary as the "harness", starts a bg
sleeper that writes its pid to the workspace, is SIGKILLed, and the parent test asserts the sleeper and a
`setsid` grandchild are gone within the sweep grace).

### 5.4 Orphans: marker, lease, next-start check (P-36l)
The only way a process outlives both the stop and the crash path is the H2a R-1 gap: a member kills its
stub first (members share its signal right), then leaves the process group with `setsid`. Such a process
is still confined (same profile, no way out of the instance), but nothing sweeps it.

- **Marker** (trust base): `state_root/runs/<run>/bg/<id>.json` (0600, fsynced), written right after a
  successful spawn: `{run, attempt, id, stub_pid, started_unix_ms, ports, lease}`; rewritten with
  `"state": "swept"` after a confirmed stop. Markers are operational state, not evidence; the journal is
  the evidence.
- **Lease** (P-36l stub change): a frame line `lease <len>\n<path>` after `env`; the stub opens the path
  read-only, takes `flock(LOCK_SH)`, and clears close-on-exec on that descriptor (`fcntl($L,2,0)`), so the
  program and every descendant inherit the lock. The lease file lives in its own directory
  `<private_root>/rh-lease-<random>/lease`, granted to the instance as a read-only root (validation
  allows it: it is not the per-call private directory). A process cannot release a lock held by another
  description; it can only close its own copy, which makes a hostile orphan look gone (lies only toward
  "gone"; named residual).
- **Next start** (`run`, `chat`, `resume`, `doctor`): scan markers not `swept` of runs whose journal
  lock is free. For each: lease probe (exclusive non-blocking lock attempt: free = no holder) and port
  probe (the harness binds each recorded port and releases it). All free → mark `gone`, journal
  `OrphanCheck{markers, clear}` in the new run. Anything held → `OrphanCheck{suspect: [...]}`; a task
  that grants bg or ports is refused (exit 3, `RunRefused::OrphansSuspected`, message names the
  marker, lease path and ports); other tasks run with a warning. `rustyharness doctor --orphans` shows
  them and, after the user confirms they checked, clears the markers (a trust-base change by the user,
  outside any run).
- **Killing them** needs to identify the holder's pid safely. Killing a recorded pid or process group
  after the stub is gone could hit an unrelated process that reused the number, so the default does not
  do it. The identification route (`/usr/sbin/lsof -t -- <lease>` as a fourth program in the confined
  spawn, then `/bin/kill -KILL <pid>` and a re-check) is owner question Q-P36-3. Until it is answered,
  the next start detects and refuses, and it does not kill by pid.
- Lease probe implementation: `std::fs::File::try_lock` needs Rust 1.89 and the workspace MSRV is 1.85
  (Q-P36-6). Default: no MSRV bump; the probe is a fixed confined perl script (`LEASE_PROBE` in
  `seatbelt.rs`, granted the lease directory read-only) that tries `flock(LOCK_EX|LOCK_NB)` and prints
  `free` or `held`.

---

## 6. Ports

### 6.1 Grants (task file `exec` section, CLI flags, header)
```json
"exec": { "programs": [...], "ports": [5173, 8000], "lan_ports": [8000] }
```
- `ports` (loopback) and `lan_ports` (a subset of `ports`) are task inputs: the user grants them by
  writing the task or with `--allow-port P` / `--allow-lan-port P` (P-36g). `PORTS_PER_TASK = 8`.
- Refused at load (exit 4): `< 1024`; duplicates; `lan_ports ⊄ ports`; **the model port** (the CLI
  derives it from `--endpoint`/config; a library caller passes `reserved_ports` and harness-run refuses a
  port grant with a `Loopback` endpoint and an empty `reserved_ports`: `RunRefused::ModelPortUnknown`).
- Header `ports: {loopback: [..], lan: [..], reserved: [..], probe_digest}`; absent when no port is
  granted (old header digests unchanged).
- Never the model port, at four layers: the load check, planning (`reserved_ports` ∩ grants = ∅), spec
  validation, and the final deny rule in the rendered profile (§4.3).

### 6.2 Who may connect to a granted port
- The bg process holding it: bind and accept.
- The user's own programs (browser, curl): always; this is the point of the grant, and the approval text
  says so in plain words ("programs on this computer can connect to 127.0.0.1:5173").
- The run's other confined calls (`exec.run`, presubmit checks, other bg processes): outbound to the
  ports **currently held by live bg ids of this run** (`Network::Loopback{connect}`), computed from
  journaled state at the call and recorded in the exec record's `connect` field (audit compares).
- Nothing else: no outbound to other loopback ports, never to the model port, no unix sockets (FT-11
  unchanged), no DNS (FT-15 unchanged), no routable addresses (FT-1 unchanged).

### 6.3 LAN-visible bind (owner decision 7: a separate ask-every-time grant)
A listener on `0.0.0.0` lets other machines connect and read whatever the process serves, which can be
workspace data: it is egress. So:
- Planning folds `lan_ports` non-empty into the trifecta as an **E label** named `exec.lan_ports`. With
  the default private, untrusted workspace (P ∧ U), P ∧ U ∧ E refuses the session (INV-9, no override).
  So a LAN grant is usable only with `workspace_public: true`. This is decided fail-closed; changing it
  would weaken INV-9 and is owner question Q-P36-1.
- When allowed, every `exec.start` that names a LAN port is decided `Ask(protected_action)` by a built-in
  floor rule `ask.exec.lan-bind`: asked every time, never a session grant (P-23 floor), never lowered by a
  user allow rule, a Deny when no approver is present. The ask text: "will listen on port 8000 on ALL
  network interfaces: other computers on your network can connect to it".
- A LAN grant is the label E; the manifest capability `harness.exec.start` stays `egress: none`, because
  the egress depends on a task input, not on the capability. This is the one place planning derives a
  trifecta label from a task input, and it is written in the trifecta refusal as `exec.lan_ports`.

### 6.4 Squatting
- Only user-granted ports, never below 1024 (since macOS 10.14 any user may bind below 1024; the floor is
  ours, not the kernel's).
- The harness checks the port is free on the host before each start (§3.1 step 6) and refuses
  `port_busy`, so the agent never races a running local service for its port.
- Within a run a port belongs to one live id at a time.
- A granted port whose usual owner (say a local database) is down can still be bound: the user granted
  it. The approval and the banner show the port list; a short warning list of well-known local-service
  ports (5432, 3306, 6379, 27017, 11434, 9200) makes the CLI print "this port is commonly used by …"
  when it is granted (advisory only).

---

## 7. The confined file-op helper

### 7.1 What it is
A small perl program, `FILEOP_STUB` (a `const &str` in `crates/harness-sandbox/src/fileop_stub.rs`,
pinned by SHA-256 like `confine_spawn.rs`), run as `/usr/bin/perl -e FILEOP_STUB` through the same
confined spawn (the spawn takes a closed enum `Stub::{Domain, FileOp}`; no free text can be run), in its
own Seatbelt instance whose profile (`profile::render_fileop`) is:
`(deny default)`, `process-exec` of `/usr/bin/perl` only, **no `process-fork`**, system reads as today,
the workspace root read-write (read-only when the task grants no edit tool), the protected overlays as
write-denied, FIFOs denied, `(deny network*)`. Its cwd is the workspace root, so requests carry
workspace-relative paths. It forks nothing, so its instance holds exactly one process, and stopping it is
closing its stdin.

It starts with the same start canary as the domain stub (signal 0 to its parent must fail with `EPERM`),
then reads `rh-fileop/1` frames from stdin and answers on stdout, one request at a time.

### 7.2 Why it closes the race
Today the harness checks each path component with `symlink_metadata` and then opens (H1e-2, H2b/H2f
residual): between the two, a process could swap a component for a symlink to `~/.ssh` and the
unconfined harness would follow it. In the helper, every `open`, `rename`, `link`, `unlink` and `mkdir`
is checked by the kernel at the moment of the call against a profile that contains only the workspace.
A swap that wins the race can only redirect the access to another place inside the workspace (which the
call could reach anyway) and never outside it; protected paths stay write-denied whatever the path
resolves to; a FIFO swapped in fails at once instead of hanging; a hard link from outside cannot be made
(the `HardLink` case). The helper keeps the in-script symlink refusal (lstat per component, `O_NOFOLLOW`
on the last one) so the user-visible rule "symlinks are never followed" holds as before; that check is
semantics, the kernel view is the control. And because the helper is a separate killable process with a
per-request deadline, a blocked filesystem call ends in a tool timeout within the wall budget (INV-14's
hanging-tool test, the §11 residual "in-process reads are not interruptible").

### 7.3 Protocol `rh-fileop/1` (P-36c, pure codec `harness-sandbox/src/fileop/proto.rs`)
Same item framing as the stub frame (`<len>\n<bytes>`, decimal length ≤ 8 digits): request
`<op>\n<n>\n` then n items; response `ok <n>\n` + items, or `err <code>\n`. Codes: `noent`, `symlink`,
`notdir`, `isdir`, `exists`, `toobig`, `changed` (expected digest differs), `denied` (the kernel refused:
outside the view or protected), `nlink` (hard-linked file), `io`, `badreq`. Paths are
`WorkspacePath` strings (already lexically checked); the helper re-splits on `/` and refuses empty, `.`
and `..` components (defence in depth). Bounds: one request ≤ 8 MiB, one response ≤ 8 MiB + 64 B.

| Op | Args | Returns | Used by |
|---|---|---|---|
| `lstat` | path | type, size, mode, nlink | all |
| `read` | path, max | up to max+1 bytes (the +1 detects over-cap, as F-2) | fs.read, search, outline, edit planning |
| `list` | path, max_entries, depth | entries (name, type, size) without following | fs.list, glob |
| `tree` | max_entries, timeout_ms | the exact listing `workspace_tree` builds (paths, types, sizes, file sha256) | post-command and turn-start measurement |
| `create` | path, bytes, mode, max_new_dirs | made dirs | edit.write (new), patch Add, move target dirs |
| `replace` | path, bytes, expect_sha | after_sha | edit.replace/multi/write-overwrite, patch Update |
| `unlink` | path, expect_sha | — | edit.delete, patch Delete |
| `move` | from, to, expect_sha, max_new_dirs | made dirs | edit.move |
| `rmdir` | path | — | rollback of made dirs |
| `ping` | outside_probe_path | `denied` expected | start check of the view |

`replace` inside the helper: walk components (lstat, refuse symlink), open the target `O_RDONLY|O_NOFOLLOW`,
refuse `nlink > 1`, hash (core `Digest::SHA`), compare with `expect_sha` (`changed` → the harness's
`StaleRead::Changed`), create `.rh-edit-<n>.tmp` with `O_CREAT|O_EXCL|O_NOFOLLOW` in the same directory,
write, `fchmod` to the old mode, fsync, rename over the target, fsync the directory (closes the H2b
"fsync of the directory" item), re-open and hash, return `after_sha`. The harness verifies `after_sha` =
the expected splice and ≠ before, exactly as §4.9 step 4.

`move` = `link(from, to)` (fails with `exists` if `to` exists: atomic no-overwrite without
`renameatx_np`) then `unlink(from)` then fsync both directories; regular files only, directories refused
in v1.

### 7.4 How each tool uses it (P-36e trait, P-36f routing)
P-36e introduces `trait FileOps` in `harness-tools` (the ops above as methods) with `InProcess` (today's
code, moved, byte-identical results) and P-36f adds `Confined(FileOpHelper)`. Every built-in file tool
and `workspace_tree` take `&mut dyn FileOps`; search/glob/outline keep their matching in process over
bytes and listings the helper returns.
- **replace / multi / write-overwrite**: `read` → stale-read check (unchanged `ReadLog`) → in-process
  match/splice → `replace(expect_sha = before)`. The stale check now also happens inside the helper,
  at the last moment before the rename.
- **write-create**: `create` (O_EXCL; ≤ 8 new dirs, H2f rules; made dirs removed with `rmdir` on failure).
- **patch (P-25)**: plan in process; apply as `replace`/`create`/`unlink` per file with `expect_sha`,
  every file's expectation checked first by `lstat`+`read`; if a later file fails, the earlier ones are
  restored from their pre-images (P-22 blobs) through `replace(expect_sha = after)`; if a restore fails
  the run stops `PolicyAbort` after measuring the tree (fail closed: the workspace is then in a state the
  journal states).
- **delete (P-25)**: pre-image stored (P-22), then `unlink(expect_sha)`.
- **move (P-25)**: pre-image stored, then `move(expect_sha)`.
- **read / search / glob / list / outline**: `lstat`/`read`/`list`; the P-12 deny list and the walk
  bounds are applied in process before any request.

### 7.5 When the helper is used, and fallbacks
- **Any run whose task grants an execute-class capability** (`exec.run`, `exec.start`, presubmit
  commands): the helper, from planning to run end (design §4.8, decision 7). Header `file_ops:
  {"mode": "confined-helper", "stub": <sha256 of FILEOP_STUB>}`.
- **Runs without one** (and every run on Linux/Windows today): in process, as now; nothing in such a run
  can create a symlink (H1 position, residuals unchanged). Header `file_ops: {"mode": "in-process"}`
  (absent in old headers = in-process, so old digests are unchanged).
- Helper fails to start at planning → the run is refused (exit 3) like a failed confinement; never a
  silent in-process fallback for a run that executes.
- Helper dies or times out mid-run → that call ends `Timeout` or `Error{HELPER_LOST}`, the helper is
  restarted at the next file call; at most 2 restarts per attempt, the third loss stops the run
  `SandboxLost`. A restart is visible in the journal through the error result; no new kind.
- **Option (b) stays** for sync `exec.run`: an unconfirmed cleanup still stops the run. It no longer
  guards the file tools (the helper does) but it still means "a process we cannot account for", which is
  worth a stop. Bg processes require the helper: `exec.start` is refused at planning unless
  `file_ops = confined-helper`.

Cost: one request round trip is ~20-60 µs (two pipe writes); a 20 000-entry search reads ≤ 20 000 files
(≈ 1-2 s worst case on top of the reads). The `tree` op hashes inside the helper (one round trip). P-36f
measures and records both in its note.

---

## 8. Linux and Windows

Today neither has a witness, so `exec.run` refuses and so do `exec.start`, ports and the helper; nothing
changes there. Planning checks `witness.covers(BG_CASES)` / `covers(PORTS_CASES)` / `covers(FILEOP_CASES)`
explicitly, so a future backend whose row lacks a set refuses that feature while plain exec works.

**Contract for the Linux backend (S-L, design §6.3 `LinuxNs`)**, so it can adopt P-36 without design work:
1. `spawn_live` and the `ConfinedChild` live API with the same ring and cursor semantics (the ring code is
   backend-neutral and moves to `spec.rs`-level helpers in P-36b for this reason).
2. Kill domain: stop = kill the PID namespace's init; crash = the namespace init holds the control pipe
   like the stub (EOF → exit → the kernel kills the namespace); no R-1 gap (members cannot outlive the
   namespace), so `OrphanCheck` is always clear on Linux.
3. `Network::Loopback`: the netns is empty, so the user's browser cannot reach `127.0.0.1:<p>` inside it.
   The backend runs a forwarder in the harness process: host `127.0.0.1:<p>` (or `0.0.0.0:<p>` for a
   LAN port) ⇄ a unix socket bind-mounted into the sandbox ⇄ `127.0.0.1:<p>` inside the netns (the same
   shape design §6.5 gives the egress proxy). `connect` ports are forwarded the other way. The model
   port is never forwarded.
4. File-op helper: `rustyharness __confine fileop` (the helper re-exec of §6.3) in a mount view with only
   the workspace; the same `rh-fileop/1` protocol, so `Confined(FileOpHelper)` is unchanged. No perl.
5. The conformance cases of §12 are data with the same ids; the Linux row must list them before Linux
   gets the feature.

Windows: refused until S-W1 (exec) and S-W2 (loopback exemption) pass.

---

## 9. Policy, manifest, approvals

| Id | Effect / sensitivity / blast / egress / content | Default decision (rule id) |
|---|---|---|
| `harness.exec.start` | execute / operational / own / none / third_party | ask, unless a user allow rule matches (`ask.exec.default`, like exec.run); with a LAN port: `ask.exec.lan-bind` at `protected_action`, a floor |
| `harness.exec.read` | read / operational / own / none / third_party | allow (`allow.exec.bg-read`) |
| `harness.exec.stop` | write / operational / own / none / own | allow (`allow.exec.bg-stop`): stopping our own process only reduces what runs |

- Registration: manifest fragments `exec_start.rs`, `exec_read.rs`, `exec_stop.rs` (P-02 layout), policy
  registration entries with label predicates (`is_builtin_exec_start` etc., like `is_builtin_exec`). The
  built-in manifest digest changes (journals from before P-36g are refused by name as "another build",
  as with every manifest change).
- P-08 matchers apply: `argv_prefix` on `exec.start` allows `npm run dev` without asking while `npm
  publish` still asks.
- Planning refusals (typed, exit 4 or 3): bg tools granted without an exec setup; `scope: session` not
  enabled is a call-time refusal, not planning; ports granted without `exec.start`; `lan_ports` with a
  private workspace (trifecta, §6.3); ports when the port probe fails (exit 3); bg when the witness lacks
  `BG_CASES` (exit 3) or the helper cannot start (exit 3); `OrphansSuspected` (exit 3).
- Approval display (P-16/P-23 renderer): program, argv (escaped), cwd, ports with their reach in plain
  words, scope and lifetime.
- Tool cap: the three tools count against `max_active_tools` (Q-6). A dev-server profile (read, edit,
  exec.run, start, read, stop, submit = 7) fits 8.

---

## 10. Journal

### 10.1 New kinds (P-36h; H-E is otherwise closed after P-10, so these two are added here, once)
Both appended and fsynced (`needs_fsync`: they are measurements the audit re-feeds).

**`BgStopped`** — `{id: U64, reason: Text (exited|lifetime|turn_end|session_end|run_end|budget|sandbox_lost|user),
end: Obj (as exec_fields' end), cleanup: Text|Obj (confirmed{kills}|unconfirmed), out_total: U64,
err_total: U64, out_sha: Digest, err_sha: Digest}` — the two digests cover **every byte the stream ever
carried**, including bytes the ring dropped and bytes never read, so the journal commits to the whole
output without storing it.

**`OrphanCheck`** — `{markers: U64, clear: U64, suspect: [Obj {run, id, lease: held|free|unknown,
ports_busy: [U64]}], action: Text (none|refused)}`; written after `RunStarted` and before the first step,
only when markers were found.

### 10.2 `bg` object in `ToolFinished` (P-36h emit/parse, like `exec_fields`/`parse_exec`)
- start: `{op: "start", id, state: "running"|"exec_failed", ports: [..], lan: [..], scope, lifetime_s,
  ready?: {kind: "port"|"text", met: Bool, waited_ms}}`
- read (one id): `{op: "read", id, mode, state, out: W, err: W, end?, cleanup?}` with
  `W = {since, from, to, dropped, skipped, total, sha}` (`sha` = SHA-256 of the raw bytes delivered)
- read (list): `{op: "list", items: [{id, state, ports, pending_out, pending_err}]}`
- stop: `{op: "stop", id, end, cleanup, out: W, err: W, out_total, err_total, out_sha, err_sha}` plus the
  existing `workspace` tree measurement (as exec.run).
The model-visible text is the tool result as today (`UntrustedBlob`, inline ≤ 4 KiB else `blobs/<sha>`),
so the journal holds exactly the bytes the model saw.

### 10.3 Other fields
- `exec` record of `exec.run`/presubmit: `connect: [U64]` only when non-empty.
- Header (inputs): `bg: {persist, max_live, max_starts, lifetime_max_s, ring_bytes}` when any bg tool is
  granted; `ports` (§6.1); `file_ops` (§7.5); all absent when unused, so old header digests are unchanged.

---

## 11. Replay, audit, resume

### 11.1 Audit re-feeds (measurements)
Every `ToolFinished` of a bg tool (its result blob and `bg` object), every `BgStopped`, `OrphanCheck`,
`exec.connect`, the header's probe digest. These come from the world (process timing, output bytes) and
cannot be recomputed; they are bound by the chain.

### 11.2 Audit recomputes (divergence if different)
- Ids: start N that succeeded gets id = count of earlier successful starts in the run + 1 (attempts
  continue the count; ids are never reused).
- Every call-time refusal of §3.1 steps 1-5 and §3.3 (unknown, stopped, exited ids; ports not granted or
  held; limits; scope), from journaled state only.
- Liveness state machine per id: `running` after a successful start; `exited`/`stopped` only after a stop
  record; no read result may report `running` for an id with an earlier stop record; a stop record for an
  id must be its last.
- Cursor arithmetic: for each read/stop window, `since` = the request or the last delivered `to` for
  that stream; `from`, `dropped`, `skipped`, `to` satisfy §3.2 given `total` and `BG_RING_BYTES` from the
  header; `total` never decreases per stream across records; `to ≤ total`; a `BgStopped`'s totals ≥ every
  earlier window's `total`.
- `exec.connect` = the ports held by live ids at that call.
- **INV-40**: every started id is stopped before `TurnEnded` (turn scope), `InputEnded` and
  `RunStopped`; a journal missing one diverges. (An uncommitted journal, which has no `RunStopped`, is
  compared as a prefix, as today.)
- Context digests (as today): the read results enter the context as untrusted observations; nonce
  withholding is recomputed.
Named limit: two reads of overlapping ranges of one stream are not cross-checked byte for byte (each
carries its own `sha`; checking overlaps would need the raw bytes; the stream digest at stop covers the
whole stream).

### 11.3 Resume (P-17 extension)
A resumed attempt's earlier bg processes are gone (their stubs swept when the old harness died, or the
journal's own stop records say so). At resume:
1. Run the orphan check (§5.4); suspects refuse a resume of a task that grants bg (exit 3).
2. For every id the kept records leave live, journal `BgStopped{reason: "run_end", end: unknown,
   cleanup: from the orphan check}` in the new attempt before anything else, so INV-40 holds.
3. Mid-turn resume keeps P-05/P-17's rule: the workspace tree must equal the last stated one, else the
   resume is refused (fail closed; a bg process probably changed it). At a turn boundary the next
   `UserTurn` measures and flags the change as P-05 D4 does.

---

## 12. Conformance cases, written first

New `Case` variants (ids in the journal/witness as listed), grouped into three sets checked by planning.
The existing `H2_EXIT_CASES` and `require()` are unchanged, so plain exec is unaffected by any of them.

| Set | Case id | Test (macOS) | Slice |
|---|---|---|---|
| `PORTS_CASES` | `ports-bind-granted` | `ft_ports_bind_granted_loopback_port_is_allowed` | P-36a |
| | `ports-bind-ungranted` | `ft_ports_bind_ungranted_port_is_refused` | P-36a |
| | `ports-wildcard-no-lan` | `ft_ports_bind_wildcard_address_is_refused_without_lan` | P-36a |
| | `ports-wildcard-lan` | `ft_ports_bind_wildcard_address_is_allowed_with_lan_grant` | P-36a |
| | `ports-connect-granted` | `ft_ports_connect_to_granted_port_is_allowed` | P-36a |
| | `ports-connect-ungranted` | `ft_ports_connect_to_ungranted_loopback_port_is_refused` | P-36a |
| | `ports-model-server` | `ft_ports_connect_to_model_server_port_is_refused` | P-36a |
| | `ports-keep-ft1-ft11-ft15` | `ft_ports_outbound_routable_unix_and_dns_still_refused` | P-36a |
| | `ports-udp` | `ft_ports_udp_bind_refused` | P-36a |
| `BG_CASES` | `bg-stop-sweep` | `ft_bg_long_lived_child_is_swept_on_stop`, `ft_bg_setsid_descendant_is_swept_on_stop` | P-36b |
| | `bg-parent-death` | `ft_bg_parent_sigkill_sweeps_the_domain` | P-36b |
| | `bg-lifetime` | `ft_bg_lifetime_closer_stops_child_while_parent_blocks` | P-36b |
| | `bg-output-bounded` | `ft_bg_output_flood_keeps_memory_bounded` | P-36b |
| `FILEOP_CASES` | `fileop-kernel-view` | `fileop_symlink_to_outside_is_refused_by_the_kernel`, `fileop_symlink_swap_race_never_reaches_outside` | P-36d |
| | `fileop-no-fork` | `fileop_helper_cannot_fork` | P-36d |
| | `fileop-fifo` | `fileop_fifo_is_refused_fast` | P-36d |
| | `fileop-protected` | `fileop_protected_path_write_refused` | P-36d |
| | `fileop-hard-link` | `fileop_hard_link_from_outside_refused` | P-36d |

Each test follows the existing file's rule: check from outside (listener saw nothing, file absent, pid
gone) and run an unconfined control showing the hostile action works when nothing stops it. A set is
added to the macOS matrix row (and the row's evidence string updated) only in the slice whose tests
pass on this host; until then planning refuses that feature. New test files
(`tests/conformance_ports_macos.rs`, `tests/conformance_bg_macos.rs`, `tests/conformance_fileop_macos.rs`)
so the existing 907-line suite is not edited.

---

## 13. Purity pin re-pin procedure

Pinned files touched: `crates/harness-sandbox/src/confine_spawn.rs` (P-36b: live child, ring, closer
thread, `spawn_live`, `Stub` enum select in P-36d; P-36l: lease frame line + stub `flock`), and the new
`crates/harness-sandbox/src/fileop_stub.rs` (P-36d). The slices that touch them are **serial**
(P-36b → P-36d → P-36l) and no other slice (P-37 included) may touch them while one is open (H-G).

Per pin-changing slice:
1. Make the change; keep the stub free of double quotes (`the_stub_has_no_double_quote_...` test) and keep
   the three program literals (`/usr/bin/sandbox-exec`, `/usr/bin/perl`, `/bin/kill`); a fourth program
   only with Q-P36-3 answered, in its own commit with a selftest case for it.
2. Keep the selftest anchors byte-identical: `Command::new("/bin/kill")`,
   `if($pp<=1 || kill(0,$pp) || ($!+0)!=1)`, `if($hit || ($en!=1 && $en!=3))`. If a change must move one,
   update `confine_case` in `scripts/ci/purity-selftest.sh` in the same commit and show the plant still
   refuses.
3. `shasum -a 256 crates/harness-sandbox/src/confine_spawn.rs`; replace `confine_spawn_sha256=` in
   `scripts/ci/purity.sh` and add one comment line above it: slice id, date, one sentence of what changed
   (as P-41 did).
4. P-36d adds a pin block for `fileop_stub.rs` right after the confine pin (same shape:
   `fileop_stub_sha256=`), adds the file to the `for must in ...` list so the scan cannot miss it, adds a
   rule that its code names no `Command`/`CommandExt`/`raw_arg` and holds no absolute-path literal at all
   (it spawns nothing), and adds selftest cases: "fileop stub changed without re-pin" and
   "a `fork` added to the fileop stub" (the pin catches both).
5. Run `sh scripts/ci/purity.sh` and `sh scripts/ci/purity-selftest.sh` (all cases), then the full
   `sh scripts/ci/gates.sh`.
6. The slice note states the old and new SHA-256, a line-by-line summary of the stub diff, and the
   conformance results on this host. Merge needs a fresh-context reviewer who reads the stub diff in full
   (E11), loudly flagged as a pin change in the merge request.

---

## 14. Adversarial tests (P-36n, end to end through `run`/`run_session` with a scripted model, macOS)

| Test | Attack | Must observe |
|---|---|---|
| `hostile_bg_fork_bomb_contained` | bg forks without end (self-capped at 200) | `BgStopped{exited}` with `process_limit`; other bg ids still running; harness responsive |
| `hostile_bg_setsid_escape_swept` | bg double-forks, `setsid`, ignores TERM | after `exec.stop` the grandchild pid (written to the workspace) is gone, cleanup confirmed |
| `hostile_bg_member_kills_stub_stops_run_and_marks_orphan` | a member SIGKILLs the stub then `setsid`s | run stops `SandboxLost` after stopping the others; marker not swept; next start journals `OrphanCheck{suspect}` and refuses a bg task |
| `hostile_bg_port_squat_ungranted_refused` | bg binds an ungranted port, then a granted one twice | bind refused by the kernel; second start naming a held port refused by the harness |
| `hostile_bg_binds_wildcard_without_lan_refused` | bind `0.0.0.0:<granted>` | refused |
| `hostile_bg_connects_model_server_refused` | connect to the mock model server's port | refused; mock server saw no connection |
| `hostile_bg_output_flood_bounded` | `yes` for 30 s | harness RSS growth < 4 MiB; read shows `dropped`; stream digest at stop covers all bytes |
| `hostile_bg_zombie_after_harness_sigkill_none_survive` | the harness (a re-exec'd test binary) is SIGKILLed with 3 bg processes | all their pids gone within grace; next start's `OrphanCheck` clear |
| `hostile_bg_symlink_swap_vs_edit_never_escapes` | bg loops swapping the edit target's directory for a symlink to an outside canary | edits never write outside; reads never return canary bytes; edits either apply to the real file or fail `symlink`/`changed`/`denied` |
| `hostile_bg_edits_read_file_forces_stale_read` | bg rewrites a file the model read | the next edit is `StaleRead::Changed` |
| `hostile_bg_writes_dot_git_refused` | bg writes `.git/config` | refused; bytes unchanged |
| `hostile_bg_forged_stub_report_in_output_ignored` | bg prints `rh-stub/1 confirmed ...` lines | cleanup still decided by the real report; reads show the forged lines as output |
| `hostile_bg_nonce_in_output_withheld` | bg prints the current observation nonce | the observation is withheld as for exec output |
| `hostile_bg_lifetime_while_model_blocks` | scripted model sleeps 20 s while a bg with lifetime 5 s runs | the process is gone at ~5 s (closer thread), `BgStopped{lifetime}` at the next boundary |

---

## 15. Invariants

| Id | Statement | Falsifying test |
|---|---|---|
| INV-40 | Every started bg process is stopped, its instance swept, and the stop journaled before the turn (turn scope), the session and the run end; audit enforces it | `bg_process_killed_on_run_end`, `bg_process_killed_on_stop_by_budget`, `audit_detects_missing_bg_stop_before_run_stopped` |
| INV-41 | No confined process can connect to or bind the model port | `ft_ports_connect_to_model_server_port_is_refused`, `bind_to_model_server_port_refused`, `hostile_bg_connects_model_server_refused` |
| INV-42 | In a run with an execute-class grant, every built-in file operation happens inside the kernel-confined helper | `run_with_exec_grant_uses_confined_file_ops`, `fileop_symlink_swap_race_never_reaches_outside` |
| INV-43 | A LAN-visible listener is never granted with a private workspace, and every LAN start is asked | `lan_ports_label_egress_for_trifecta`, `lan_bind_requires_separate_grant` |

---

## 16. Owner questions (each with the fail-closed default that holds until answered)

| Id | Question | Default until answered | Recommendation |
|---|---|---|---|
| Q-P36-1 | A LAN-visible port is egress. With a private workspace the trifecta refuses it (INV-9 has no override). Allow an ask-every-time LAN grant as a trifecta exception? | No exception: LAN ports only with `workspace_public: true`, asked every start | **Keep the default.** Decision 7's "ask every time" holds inside the trifecta; an exception would be the first override of INV-9. Revisit with the dual-LLM track. |
| Q-P36-2 | May bg processes keep running between user turns (dev server while the user looks at the browser)? | Off: turn-scoped only; `--bg-persist` refused | **Turn on `--bg-persist` for `chat` after P-36m** (the prompt shows running processes), still killed at session end and at the lifetime cap; keep it off for unattended runs (P-49). |
| Q-P36-3 | Kill orphans at the next start by identifying lease holders with `/usr/sbin/lsof -t -- <lease>` (a fourth program in the confined spawn, argv = fixed flags + a harness-made path) and `/bin/kill`? | No pid kill: detect, refuse bg/ports, tell the user | **Admit lsof** after the pin review (small, exact identification, narrow pid-reuse window like the existing post-reap group kill); long term the `sandbox_check` sweep (spike S-M2) closes R-1 itself. |
| Q-P36-4 | Ephemeral loopback ports for sync `exec.run` (tests that bind `127.0.0.1:0`), using `localhost:*` plus later denies for reserved ports | D31 stays: no bind | **Yes, as a follow-up slice** once P-36a shows later denies override `localhost:*` reliably; real projects' test suites need it (P-51 found the same class of real-run failure). |
| Q-P36-5 | The helper for every run with an execute grant (design §4.8), or only for runs with bg tools (cheaper searches)? | Every run with an execute grant | **Every run** (design-conformant, closes the §11 hanging-read residual too); measured cost in P-36f decides only if it is unacceptable. |
| Q-P36-6 | Raise the workspace MSRV from 1.85 to 1.89 so the lease probe can use `std::fs::File::try_lock`? | No bump; confined perl lease probe | **Bump** (simpler, no extra spawn); the toolchain in use is 1.97. |
| Q-P36-7 | Limits: 4 live, 16 starts per run, 30 min default lifetime, 4 h max, 1 MiB ring per stream, 16 KiB per read | As listed | Accept; tune after P-21 runs a real dev-server task. |

---

## 17. What could make this design wrong

- SBPL cannot express "loopback port P only" (P-36a): then macOS ports stay refused until another
  mechanism (for example a harness-side forwarder from a unix socket, as on Linux) is designed; bg
  processes without ports still work.
- `sandbox-exec` fails to keep Seatbelt's checks at syscall time for paths reached through a symlink
  swapped mid-call (the helper's whole argument): `fileop_symlink_swap_race_never_reaches_outside` is the
  test; if it ever returns canary bytes, the helper is not a control and the runs with bg must stop on
  option (b) again (bg refused).
- Apple removes `sandbox-exec` or perl: exec, bg and the helper all refuse (Q8 position unchanged).
- Long-lived stubs reveal a stub weakness that one-call stubs hid (for example pid wrap during a 4 h
  sweep window): the per-pass canary and the 1-30 s sweep bound remain; P-36b's tests run a 10 min soak
  under `#[ignore]`.

---

## Slice cards (to paste into the roadmap)

Order: P-36a → P-36b → P-36d → P-36l is the serial sandbox/pin chain. P-36c, P-36e, P-36g, P-36h can run
beside it. P-36f, P-36i, P-36j, P-36k are the tools and loop chain (P-36j and P-36k touch the driver
hotspot H-B: never parallel with another loop slice). P-36m and P-36n close.

**P-36a Ports conformance first: `Network::Loopback`, Seatbelt port rules, live port probe**
- Why: §4.3, §4.4, §12. Measure what SBPL can express before anything uses it. `spec.rs`: `Network::Loopback{bind, connect, lan}`, `Context.reserved_ports`, validation (≥1024, not reserved, lan ⊆ bind, ≤4 binds); `profile.rs`: rules after `(deny network*)` plus the final reserved-port deny, `Network::None` byte-identical; `seatbelt.rs`: `probe_ports` and `PortsWitness`; `conformance.rs`: the `PORTS_CASES` variants, added to the macOS row only if every test passes here (else the slice note records the measurement and ports stay refused). Records whether `localhost` covers `::1` and whether `/private/etc/hosts` must be readable.
- Crates: harness-sandbox (`spec.rs`, `profile.rs`, `seatbelt.rs`, `conformance.rs`, new `tests/conformance_ports_macos.rs`). Not `confine_spawn.rs`.
- Tests: `ft_ports_bind_granted_loopback_port_is_allowed`, `ft_ports_bind_ungranted_port_is_refused`, `ft_ports_bind_wildcard_address_is_refused_without_lan`, `ft_ports_bind_wildcard_address_is_allowed_with_lan_grant`, `ft_ports_connect_to_granted_port_is_allowed`, `ft_ports_connect_to_ungranted_loopback_port_is_refused`, `ft_ports_connect_to_model_server_port_is_refused`, `ft_ports_outbound_routable_unix_and_dns_still_refused`, `ft_ports_udp_bind_refused`, `validate_refuses_port_below_1024_and_reserved`, `validate_refuses_lan_not_subset_of_bind`, `render_puts_port_allows_after_network_deny_and_reserved_deny_last`, `network_none_profile_unchanged_byte_for_byte`, `probe_ports_refuses_when_an_ungranted_bind_succeeds` (injected observation), existing conformance suite unchanged.
- Deps: P-41, P-29. Parallel: no (sandbox chain head; profile/spec are shared with P-36b). Risk: high (security boundary; UNVERIFIED SBPL syntax). ARCH: no.

**P-36b Live confined child: ring buffer, cursors, deadline closer (pin change)**
- Why: §4.2, §5.3. `ConfinedChild::{try_status, read, totals, stop}`, `Confinement::spawn_live(spec, ev, LiveOpts)`, `Ring` (circular buffer, monotonic total, running SHA-256, 4 KiB tail for the report), the pure window fn of §3.2 (backend-neutral module so the Linux backend reuses it), report stripping on reads after exit, the lifetime closer thread. `wait()` byte-identical for exec.run. The stub text is unchanged. Re-pin `confine_spawn_sha256` per §13.
- Crates: harness-sandbox (`confine_spawn.rs`, `lib.rs`, new `ring.rs`, new `tests/conformance_bg_macos.rs`), `scripts/ci/purity.sh`.
- Tests: `ring_cursor_arithmetic_next_and_tail`, `ring_drop_counts_overwritten_bytes`, `ring_stream_sha_covers_every_byte`, `read_strips_trailing_stub_report_after_exit`, `wait_api_unchanged_for_exec_run`, `ft_bg_long_lived_child_is_swept_on_stop`, `ft_bg_setsid_descendant_is_swept_on_stop`, `ft_bg_parent_sigkill_sweeps_the_domain` (re-execs the test binary), `ft_bg_lifetime_closer_stops_child_while_parent_blocks`, `ft_bg_output_flood_keeps_memory_bounded`, `ft_bg_fork_bomb_stopped_by_watchdog_other_children_unaffected`, `bg_soak_ten_minutes` (`#[ignore]`), purity + purity-selftest pass with the new pin.
- Deps: P-36a. Parallel: no (pinned spawn file, H-G). Risk: high. ARCH: no.

**P-36c `rh-fileop/1` codec (pure)**
- Why: §7.3. Request/response framing and error codes as a pure module, so the helper slice only adds the stub and the process. No I/O, no spawn.
- Crates: harness-sandbox (new `fileop/proto.rs`).
- Tests: `fileop_frame_round_trip_every_op`, `fileop_frame_refuses_oversize_item`, `fileop_frame_refuses_bad_count_and_non_decimal_length`, `fileop_response_error_codes_round_trip`, `fileop_path_must_be_workspace_relative_without_dot_components`, `fileop_codec_is_deterministic`.
- Deps: none. Parallel: yes (new file; not a pin slice). Risk: low. ARCH: no.

**P-36d Confined file-op helper: fork-less stub, profile, process (pin change + new pin)**
- Why: §7.1-7.3, owner decision 7. `fileop_stub.rs` (`FILEOP_STUB`, start canary, ops of §7.3 with core `Digest::SHA`, `O_NOFOLLOW`, link+unlink move, directory fsync), `Stub::{Domain, FileOp}` select in `confine_spawn.rs`, `profile::render_fileop` (no fork, exec perl only, workspace rw or ro), `harness_sandbox::fileop::FileOpHelper` (start, request with deadline, restart), `FILEOP_CASES` in the macOS row when green. New pin `fileop_stub_sha256` and re-pin of `confine_spawn_sha256` per §13, with the two new selftest cases.
- Crates: harness-sandbox (`fileop_stub.rs`, `fileop/mod.rs`, `confine_spawn.rs`, `profile.rs`, `conformance.rs`, new `tests/conformance_fileop_macos.rs`), `scripts/ci/purity.sh`, `scripts/ci/purity-selftest.sh`.
- Tests: `fileop_helper_reads_and_writes_inside_workspace`, `fileop_symlink_to_outside_is_refused_by_the_kernel`, `fileop_symlink_swap_race_never_reaches_outside` (2000 iterations against a confined swapper), `fileop_fifo_is_refused_fast`, `fileop_protected_path_write_refused`, `fileop_helper_cannot_fork`, `fileop_hard_link_from_outside_refused`, `fileop_replace_refuses_changed_expect_sha`, `fileop_move_never_overwrites`, `fileop_readonly_profile_refuses_every_write`, `fileop_request_timeout_kills_and_restarts_helper`, `fileop_stub_refuses_to_start_unconfined`, purity selftest `fileop stub changed without re-pin`, `a fork added to the fileop stub`.
- Deps: P-36b, P-36c. Parallel: no (pinned files, H-G). Risk: high. ARCH: no.

**P-36e `FileOps` trait: built-in file tools behind one seam (no behaviour change)**
- Why: §7.4. Move every filesystem access of read/search/glob/list/outline/edit (replace, write, multi, and patch/delete/move from P-25) and `workspace_tree` behind `trait FileOps` with an `InProcess` impl holding today's code; results, digests and errors byte-identical.
- Crates: harness-tools.
- Tests: all existing `cargo test -p harness-tools` unchanged, `file_ops_in_process_results_byte_identical` (golden over a fixture tree: every tool's output digest before = after), `tool_modules_touch_fs_only_through_file_ops` (source scan test: no `std::fs` outside `file_ops/in_process.rs` and the scratch setup).
- Deps: P-22, P-25. Parallel: yes with the sandbox chain (different crate); not with other harness-tools edit slices. Risk: medium (large mechanical move). ARCH: no.

**P-36f Route file tools through the helper in runs that execute**
- Why: §7.4-7.5, INV-42. `Confined(FileOpHelper)` impl of `FileOps`; `workspace_tree` via the `tree` op; planning starts the helper after the witness for any execute-class grant (refuses the run if it cannot start); header `file_ops`; bounded restarts then `SandboxLost`; the helper's `tree` digest must equal the in-process one. Records the measured cost in the slice note.
- Crates: harness-tools (`file_ops/confined.rs`), harness-run (planning, header, stop on helper loss).
- Tests: `run_with_exec_grant_uses_confined_file_ops`, `run_without_exec_grant_stays_in_process`, `header_records_file_ops_mode_and_stub_digest`, `old_header_digest_unchanged_without_file_ops`, `helper_tree_digest_equals_in_process_digest`, `helper_start_failure_refuses_the_run`, `helper_lost_three_times_stops_sandbox_lost`, `hanging_file_op_ends_in_tool_timeout_within_wall`, `edit_through_helper_audits_clean`.
- Deps: P-36d, P-36e, P-13. Parallel: no with other driver slices (planning/header). Risk: medium-high. ARCH: no.

**P-36g Bg tools in manifest and policy; port and LAN grants**
- Why: §3, §6.1, §6.3, §9. Manifest fragments and policy registration for `harness.exec.start/read/stop` with defaults (`ask.exec.default`, `allow.exec.bg-read`, `allow.exec.bg-stop`), the LAN floor rule `ask.exec.lan-bind` (protected_action), the trifecta E label from `lan_ports`, task-file `exec.ports`/`exec.lan_ports` parse and checks, CLI `--allow-port`, `--allow-lan-port`, `--bg-persist`, model port derived from the endpoint, `reserved_ports` in the library API.
- Crates: harness-manifest, harness-policy, harness-cli (`inputs.rs`, `args.rs`).
- Tests: `builtin_manifest_lists_bg_tools`, `policy_default_start_asks_read_and_stop_allow`, `lan_port_start_asks_every_time_protected_action`, `lan_ports_label_egress_for_trifecta`, `lan_ports_allowed_with_public_workspace_and_ask`, `session_grant_never_covers_lan_start`, `port_grant_refuses_model_server_port`, `port_grant_refuses_below_1024_and_duplicates`, `port_grant_library_requires_reserved_ports_with_loopback_endpoint`, `task_file_ports_parse_and_header_digest`, `old_task_file_digest_unchanged`, `bg_grant_without_exec_setup_refused`.
- Deps: P-02, P-08, P-11, P-23. Parallel: yes (manifest/policy/cli; no sandbox, no driver). Risk: medium (trust root). ARCH: no.

**P-36h Journal: `BgStopped`, `OrphanCheck`, the `bg` record**
- Why: §10. Two new kinds in `canon.rs`/`event.rs` (fsynced), canonical bodies; `bg_fields`/`parse_bg` beside `exec_fields`/`parse_exec`; `connect` in the exec record only when non-empty; header `bg`/`ports`/`file_ops` objects absent when unused.
- Crates: harness-journal, harness-run (`driver/tools.rs` record fns only).
- Tests: `bg_stopped_and_orphan_check_kinds_round_trip_canonical`, `unknown_kind_still_refused`, `tool_finished_bg_record_round_trip_every_op`, `exec_record_connect_absent_when_empty_digest_unchanged`, `old_journal_still_reads`.
- Deps: P-10. Parallel: yes (journal + one record module). Risk: low-medium. ARCH: no.

**P-36i `BgTools` provider: start, read, stop**
- Why: §3, §6.2. `harness-tools::bg`: `BgManager` (ids, live map, port holdings, host port check, limits, cursors per stream, `ready` wait, rendering with dropped/skipped markers, `poll()`), the `BgTools` `ToolProvider` serving the three ids through `spawn_live`; exec.run gets `connect` = ports of live ids; refuses unless `file_ops` is the helper.
- Crates: harness-tools (new `bg.rs`, `exec.rs` connect field), harness-sandbox (use only).
- Tests: `bg_start_returns_sequential_ids`, `bg_start_refuses_program_not_on_allowlist`, `bg_start_refuses_ungranted_or_held_port`, `bg_start_refuses_over_max_live_and_max_starts`, `bg_start_refuses_when_port_busy_on_host`, `bg_read_next_and_tail_modes_cursor_arithmetic`, `bg_read_reports_dropped_after_ring_overrun`, `bg_read_wait_returns_on_new_output_or_exit`, `bg_read_without_id_lists_all`, `bg_stop_sweeps_and_returns_final_output`, `bg_read_of_unknown_or_stopped_id_refused`, `bg_ready_port_waits_for_listener`, `exec_run_gets_connect_ports_of_live_bg`, `bg_requires_confined_file_ops`.
- Deps: P-36b, P-36f, P-36g, P-36h. Parallel: no with other harness-tools exec slices. Risk: medium-high. ARCH: no.

**P-36j Driver: kill at every stop, step-boundary poll, planning checks**
- Why: §5.1, §5.2, §9, INV-40/41. Wire `BgTools` into the run and session loops: poll at each step start and before each start decision (journal `BgStopped{exited|lifetime}`), stop-all before `TurnEnded` (turn scope), `InputEnded`, `RunStopped` for every cause, `SandboxLost` cascade, `Drop` backstop on early return, planning refusals (witness sets, port probe, helper, scope), tree measured after the stop-all.
- Crates: harness-run (driver, session; H-B chain).
- Tests: `bg_process_killed_on_run_end`, `bg_process_killed_on_stop_by_budget`, `bg_turn_scoped_killed_at_turn_end`, `bg_session_scoped_survives_turn_and_dies_at_session_end`, `bg_session_scope_refused_without_persist_flag`, `bg_exit_observed_and_journaled_at_step_boundary`, `bg_lifetime_expiry_journaled`, `bg_unconfirmed_stop_stops_run_sandbox_lost_after_stopping_others`, `bg_killed_when_run_returns_early_on_journal_failure`, `bg_refused_when_witness_lacks_bg_or_ports_cases`, `bind_to_model_server_port_refused`, `bind_ungranted_port_refused`, `lan_bind_requires_separate_grant`.
- Deps: P-36i, P-13. Parallel: no (driver hotspot H-B). Risk: high. ARCH: no.

**P-36k Audit and resume of runs with background processes**
- Why: §11, INV-40. Audit re-feeds bg results and `BgStopped`/`OrphanCheck`, recomputes ids, refusals, liveness, cursor arithmetic, `connect`, and the stop-before-end rule; resume runs the orphan check, journals `BgStopped` for ids the kept records leave live, and keeps the mid-turn tree rule.
- Crates: harness-run (`replay/audit.rs`, `replay/resume.rs`, `replay/feed.rs`).
- Tests: `bg_output_cursor_replayable`, `session_with_bg_audits_clean`, `audit_detects_edited_bg_cursor`, `audit_detects_missing_bg_stop_before_run_stopped`, `audit_recomputes_bg_refusals`, `audit_detects_read_reporting_running_after_stop`, `audit_detects_decreasing_stream_total`, `resume_after_crash_with_live_bg_records_stop_and_continues_at_boundary`, `resume_mid_turn_refused_when_bg_changed_tree`.
- Deps: P-36j, P-17. Parallel: no (replay chain). Risk: high. ARCH: no.

**P-36l Orphan markers, lease, next-start check (pin change)**
- Why: §5.4. Markers in `runs/<run>/bg/`; the stub's `lease` frame line with an inherited shared `flock` (re-pin `confine_spawn_sha256` per §13); the lease probe (confined perl by default, std `try_lock` if Q-P36-6 says bump); the next-start scan for `run`/`chat`/`resume`; `OrphanCheck` record; `RunRefused::OrphansSuspected`; `doctor --orphans` report and user-confirmed clear. No pid kill unless Q-P36-3 is answered yes.
- Crates: harness-sandbox (`confine_spawn.rs` stub lease, `seatbelt.rs` lease probe), harness-run (marker write/close, start scan), harness-cli (`cmd_doctor.rs`), `scripts/ci/purity.sh`.
- Tests: `orphan_marker_written_and_closed_on_confirmed_stop`, `lease_inherited_by_setsid_descendant`, `next_start_clear_markers_recorded`, `next_start_with_held_lease_refuses_bg_grant`, `next_start_with_busy_recorded_port_refuses_port_grant`, `orphan_check_journaled_in_new_run`, `task_without_bg_runs_with_orphan_warning`, `doctor_reports_and_clears_orphan_markers_only_on_confirmation`, purity + selftest pass with the new pin.
- Deps: P-36j, P-36d, P-43. Parallel: no (pinned spawn file, H-G). Risk: high. ARCH: no.

**P-36m Chat surface for background processes**
- Why: §6.3, Q-P36-2. Banner lists granted ports (loopback/LAN) and `--bg-persist`; prompt shows the running count; `/bg` lists and `/bg stop N` stops through the session API (a user-initiated stop is not a tool call: it is a `BgStopped{reason: "user"}` record, written between turns and re-fed by the audit as an input); LAN ask text in plain words; bg output shown sanitised (P-04).
- Crates: harness-cli (`repl.rs`, `render.rs`, `cmd_chat.rs`), harness-run (one `BgStopped` reason and its audit re-feed).
- Tests: `chat_banner_lists_granted_ports`, `chat_prompt_shows_running_bg_count`, `chat_slash_bg_lists_and_stops`, `chat_user_bg_stop_journaled_and_audited`, `chat_lan_ask_prompt_says_reachable_from_network`, `chat_bg_output_has_no_raw_escapes`.
- Deps: P-36j, P-36k, P-18. Parallel: yes with P-36l (cli vs sandbox; `cmd_doctor.rs` is P-36l's only cli file). Risk: low-medium. ARCH: no.

**P-36n Hostile suite for background processes and the helper (tests only)**
- Why: §14. The adversarial table end to end through `run`/`run_session` with a scripted model and a mock model server; every test asserts outcome, journal kinds and `assert_audit_clean` where the run commits.
- Crates: tests in harness-run (`tests/hostile_bg.rs`), harness-sandbox (re-exec helper for the SIGKILL case).
- Tests: `hostile_bg_fork_bomb_contained`, `hostile_bg_setsid_escape_swept`, `hostile_bg_member_kills_stub_stops_run_and_marks_orphan`, `hostile_bg_port_squat_ungranted_refused`, `hostile_bg_binds_wildcard_without_lan_refused`, `hostile_bg_connects_model_server_refused`, `hostile_bg_output_flood_bounded`, `hostile_bg_zombie_after_harness_sigkill_none_survive`, `hostile_bg_symlink_swap_vs_edit_never_escapes`, `hostile_bg_edits_read_file_forces_stale_read`, `hostile_bg_writes_dot_git_refused`, `hostile_bg_forged_stub_report_in_output_ignored`, `hostile_bg_nonce_in_output_withheld`, `hostile_bg_lifetime_while_model_blocks`.
- Deps: P-36k, P-36l. Parallel: yes (tests only, new files). Risk: low. ARCH: no.
