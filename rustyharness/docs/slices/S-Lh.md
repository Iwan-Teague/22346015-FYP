# S-Lh — `rh-dev linux`: run the Linux conformance suite in the UTM VM

Implements design note `docs/slices/S-L-linux-sandbox.md` §5.1/§5.3 (slice card
S-L-h): a Rust dev verb that syncs the workspace to the Linux UTM VM, runs the
suite under a wall-clock timeout that kills the whole process group, parses
cargo's `test result:` lines, and exits 0 **only** if every selected suite ran
and passed. An unreachable VM or a busy lock is a loud non-zero skip that is
never a pass.

Crates touched: a NEW standalone crate `tools/rh-dev` (no dependencies, std
only). Nothing else in the repo changes.

## What landed

- **`tools/rh-dev`, a standalone nested workspace.** The design note assumed
  `tools/rh-dev` already existed; it did not — this slice created it. It is
  deliberately NOT a member of the root workspace (its own empty `[workspace]`
  table): `scripts/ci/purity.sh` §5 (INV-23) classifies every package in
  `cargo tree --workspace` and refuses any workspace package outside
  `crates/<name>`, and §2f refuses the words `Command`/`CommandExt`/`raw_arg`
  anywhere under `crates/*/src` outside the two pinned spawn modules. A dev
  tool whose whole job is driving `ssh`/`rsync`/`utmctl` cannot live under
  either constraint, so it lives outside with its own gates (fmt, clippy
  `-D warnings`, `cargo test --locked`) and its own `Cargo.lock`, and the root
  workspace, root `Cargo.lock` and every root gate are untouched (verified:
  `cargo tree --workspace` at the root does not list `rh-dev`).
- **`linux` verb** (`src/linux.rs`): options + argv builders + the run.
  - Lock first: a filesystem lock — `create_dir` on
    `/tmp/rh-linux-vm.lock` (`--lock-path` in tests) — held by a guard for the
    whole run (boot + sync + suite) and released on drop, so every exit path
    releases it. Busy → `SKIPPED` (exit 3, "not a pass"); lock I/O error →
    exit 4.
  - `--boot` runs `utmctl start <vm>` (argv array), then the reachability
    poll `ssh -o BatchMode=yes -o ConnectTimeout=5 <target> -- true` every
    `--poll-every` (2 s) until `--ssh-wait` (300 s). Unreachable → loud
    `SKIPPED — the Linux conformance did NOT run; this is not a pass`, exit 3.
  - Sync: `rsync -a --delete --exclude target/ --exclude .git/ -e ssh
    <repo>/ <target>:rh-work/` (argv array). A FNV-1a digest of the synced
    tree (relative paths + bytes, symlinks as links, `target/`/`.git/` pruned
    to match rsync) labels the run. Failure → exit 4.
  - Suite: over `ssh -tt`, `cd rh-work && timeout <remaining> cargo test …`
    where `<remaining>` is what is left of the single `--timeout` (1800 s)
    budget shared by boot-sync-suite. The `timeout(1)` wrapper is the
    guest-side belt; the host-side suspenders kill the **ssh child's process
    group** (`CommandExt::process_group(0)` + `/bin/kill -9 -<pid>`) at the
    deadline, so a hung test cannot wedge the tool. Suites: the
    `conformance_linux` integration test (serialised, `--nocapture
    --test-threads=1`) then `cargo test -p harness-sandbox` as the control.
    (`harness-sandbox-linux` unit tests join when S-Lb lands the crate — an
    absent package would make cargo fail loudly, so it is not wired yet.)
  - Verdict: parse each suite's `test result:` lines (`parse.rs`; verdict
    token must be exactly `ok` or `FAILED`, prose and unknown verdicts never
    count), print the per-suite table and totals, exit 0 only if at least one
    suite ran, all were `ok`, and zero tests failed. No tally at all (e.g. the
    suite did not run) is a FAIL, never a silent pass. Exit codes: 0 pass,
    1 tests failed, 2 usage, 3 skipped, 4 could not run.
  - `--keep-logs DIR`: the full transcript (every command + output + verdict)
    is copied to `<DIR>/<vm>-<unix-secs>.log` on **every** exit path, success
    or failure; failure to keep logs is reported, never fatal.
- **Shared helpers**: `proc.rs` — bounded argv runs (`run_bounded`) with the
  process-group kill and a 64 MiB output cap; `parse.rs` — cargo output
  parsing (`cargo_test_results`, `summarize`). No shell is ever spawned: every
  external program (`ssh`, `rsync`, `utmctl`, `/bin/kill`) is an argv array
  through `std::process::Command` (memory "rust-only-tooling").
- **Thin binary** (`src/main.rs`): argv dispatch, usage → exit 2 with the
  verb's usage text on stderr.

## Tests

`cargo test` in `tools/rh-dev` (11 tests), including the four named for the
slice:

- `rh_dev_linux_parses_cargo_test_result_lines` — the `test result:` grammar
  (incl. the indented/prefixed forms cargo actually prints), plus prose and
  unknown-verdict refusals and the empty-log-is-not-a-pass rule.
- `rh_dev_linux_unreachable_vm_is_loud_nonzero` — with `ssh` stubbed to
  `/usr/bin/false`, the run exits `SKIPPED`, stderr says `SKIPPED … not a
  pass`, stdout never says `PASS`, and the lock is released.
- `rh_dev_linux_acquires_the_vm_lock` — take it, a second taker is `Busy`,
  drop releases it.
- `rh_dev_linux_builds_the_ssh_and_rsync_argv_without_a_shell` — the exact
  argv arrays for probe/boot/rsync/suite, and no `sh`/`bash`/`-c` word
  anywhere.

Extras: usage parsing (`--ssh` required, unknown flag, zero timeouts refused),
a failed rsync is loud non-zero, `--keep-logs` writes the transcript on a skip,
and a busy lock skips before anything runs.

## Verification

Run inside `tools/rh-dev` (it is its own workspace):

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

All green. Root workspace unaffected (see above).

## Known limits / follow-ups

- A real `rh-dev linux` run today fails loudly at the first suite:
  `harness-sandbox --test conformance_linux` does not exist until S-Lf (and
  the crate has no Linux backend until S-Lb–S-Le). By design the tool must
  never report a silent pass on an absent suite.
- The VM lock is a `mkdir` lock, not `flock`: a crashed run leaves the
  directory, and the error message says exactly that (remove it only if no run
  is live). Matches design §5.3's `mkdir /tmp/rh-linux-vm.lock` pattern.
- `rh-dev` is outside the root gates by construction; its own gates are the
  three commands above, and `scripts/ci/gates.sh` (cargo-deny) was NOT run
  for this slice (needs network; no new dependencies were added — std only).
