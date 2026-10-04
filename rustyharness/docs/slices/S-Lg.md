# S-Lg — Linux escape-surface conformance cases

Track: S-L · Deps: S-Lf (merged) · Status: **code complete, NOT Linux-verified**
(see "Linux verification" below).

## What this slice does

Adds the ten Linux escape-surface cases to the conformance corpus and, for
each, a real test through the spawn seam in `tests/conformance_linux.rs`.
Per the card and P-36 §12, **no row gains the new cases yet**: they enter a
row only after this suite passes green on a real Linux kernel.

## Corpus (`crates/harness-sandbox/src/conformance.rs`)

- Ten new `Case` variants with stable ids:
  `linux-openat2`, `linux-proc-self-mem`, `linux-fd-inherit`,
  `linux-ld-preload`, `linux-setuid`, `linux-memfd-exec`,
  `linux-abstract-unix`, `linux-ptrace-sibling`,
  `linux-fork-bomb-pgroup`, `linux-dev-shm-tmpfs`.
- `LINUX_ESCAPE_CASES: &[Case]` — the set, in card order.
- New unit test `the_linux_escape_cases_have_stable_ids_and_are_not_yet_on_any_row`:
  pins every id string and asserts none of the ten is on the macOS row,
  the gated Linux probe row, `H2_EXIT_CASES`, `AIRLOCK_CASES`, or
  `PORTS_CASES` (fail-closed until a real-kernel pass commits them).

## Tests (`crates/harness-sandbox/tests/conformance_linux.rs`)

All ten follow the suite rule: refused arm confined, unconfined control
proving the same action works when nothing stops it, outside checks, and a
`DomainCleanup::Confirmed` assertion where a live child is involved.

1. `linux_openat2_resolve_flags_cannot_escape_roots` — raw `openat2`
   (syscall 437) with `RESOLVE_BENEATH` (0x8) and with no flags: the
   workspace file opens, the outside file, `..`, and the
   workspace-symlink arms are refused (Landlock handles them; the
   `RESOLVE_BENEATH` outside arm may be an EINVAL/EXDEV-class refusal —
   the script collapses any failure to `refused`, so the assertion is
   errno-agnostic). Control: cwd = workspace, all six arms open.
2. `linux_proc_self_mem_and_pid_mem_are_not_a_write_channel` — a confined
   program cannot open `/proc/self/mem` nor `/proc/<forked-child>/mem`
   read-write (/proc is not in the read set; ptrace access is
   seccomp-denied). Control: a parent reads its own forked child's mem and
   its own.
3. `linux_no_unexpected_fd_is_inherited_into_the_child` —
   `/proc/<pid>/fd`, read from the test process while a confined sleeper
   holds a bait file open, is exactly `{0,1,2}` and no target names the
   bait. Control: the same listing method on an unconfined child shows the
   bait (>3 fds).
4. `linux_ld_preload_and_loader_env_are_absent` — (a) an `LD_PRELOAD`
   spec env entry is refused with the INV-10 message; (b) `LD_PRELOAD` +
   `LD_LIBRARY_PATH` planted in the harness's own environment (restored
   after) do not reach the child's built env. Control: unconfined, the
   planted variable is visible.
5. `linux_setuid_binary_gains_nothing_under_no_new_privs` — (a)
   `NoNewPrivs: 1` read from `/proc/<pid>/status` of a live confined
   child vs `0` for an unconfined sibling; (b) a 4755 copy of
   `/usr/bin/id` in a `read_only` root (which carries `EXECUTE`)
   execs but prints no `euid=`. Control: unconfined the copy grants
   `euid=0` — if the host mount is nosuid the control says so and fails.
6. `linux_memfd_create_then_execveat_is_refused` — memfd_create (319/279
   by `$Config{archname}`) succeeds, `/bin/echo` is copied in via
   `>&=` dup, then `execveat(fd, "", 0, 0, AT_EMPTY_PATH=0x1000)`
   (322/281) is refused (seccomp arg-deny; also no Landlock execute right
   on an anonymous file). Control: the same program replaces itself with
   echo and prints a bare newline.
7. `linux_abstract_unix_socket_connect_is_refused` — the test holds an
   abstract `UnixListener` (`SocketAddr::from_abstract_name`); the
   control connects with a hand-packed exact-length abstract sockaddr
   (perl's `pack_sockaddr_un` pads to 108 bytes, which would name a
   different address); the confined program is refused at
   `socket(AF_UNIX)` and the listener stays silent.
8. `linux_ptrace_of_a_sibling_is_refused` — `ptrace(PTRACE_ATTACH`=16`)
   of a forked child succeeds unconfined (control) and is
   seccomp-refused confined; `/proc/<confined-sibling>/mem` likewise. The
   confined sibling (a controlled sleeper) is asserted alive afterwards.
9. `linux_fork_bomb_and_setsid_double_fork_are_all_reaped` — the bomb
   (fork ≤40; each child `setsid()` + double-forks a SIGTERM-ignoring
   grandchild that registers its pid) is capped by
   `processes = Some(8)`, hits the 1.5 s wall (`TimedOut`), the sweep
   reports `Confirmed { kills ≥ 1 }`, and **every** registered pid is dead
   (checked via `/bin/kill -0` from outside). Control: two such escapees
   outlive their unconfined parent (the escape is real; the test kills
   them itself).
10. `linux_dev_shm_and_tmpfs_writes_stay_inside_roots` — `/dev/shm/<pid>`
    and `/run/<pid>` writes are refused confined and nothing is left.
    Control: the same `/dev/shm` write succeeds unconfined (and is
    removed); `/run` has no control twin (root-owned by design).

## Linux verification

**NOT verified on a Linux kernel in this slice.** `tools/rh-dev linux`
(S-Lh) is the real gate; it needs `--ssh <user@host>` for a reachable VM
and no VM target is documented/reachable from this host (`utmctl` absent,
no default host in `docs/slices/S-Lh.md`). Per the fail-closed reading:
the ten new cases stay **off every matrix row** (enforced by the new unit
test), and the conductor should run

```
tools/rh-dev linux --ssh <user@host>
```

to promote them. Cross-checks done on the macOS host:

```
cargo check -p harness-sandbox -p harness-sandbox-linux --all-targets \
  --target aarch64-unknown-linux-gnu --offline   # clean (2 pre-existing
                                                 # warnings, see below)
cargo fmt --all                                  # clean
cargo clippy --locked --workspace --all-targets -- -D warnings   # clean
cargo test --locked -p harness-sandbox           # 92 passed
cargo test --locked -p harness-sandbox-linux     # 29 passed (macOS no-ops)
```

(The `aarch64` target is used because the `x86_64-unknown-linux-gnu`
std installed in the rustup toolchain is not resolvable through the
homebrew-shadowed PATH; `~/.cargo/bin` first in PATH works.)

## Out-of-scope fix carried

`crates/harness-sandbox-linux/tests/probe_live.rs` (untouched since
S-Le) was missing `use harness_sandbox::Backend as _;`, so it failed to
compile on **every** Linux target (E0599, `probe` not found) — this
blocked the Linux-target cross-check of the crates this slice touches.
Fixed as a one-line cfg'd import (commit `a94fafa`). Pre-existing
warnings left alone as documented by S-Lf: `spec.rs`
`PortsWitness::new` dead-code on Linux targets, one unused `child` in
`supervisor_live.rs`.

## Design notes / questions for the conductor

- Test 1 asserts `refused` for the outside/`..`/symlink arms regardless
  of errno (openat2 may fail with EACCES, EXDEV or EINVAL depending on
  arm and kernel); the positive arms assert `OPENED` exactly. On the VM,
  check the stderr-free exit shapes; if an arm unexpectedly succeeds,
  that is a real finding, not a flaky test.
- Test 5's control demands a permissive (non-nosuid) workspace mount;
  if the VM mounts the temp dir nosuid, the test fails loudly by design
  (it cannot witness the case then) — move `Tree::new`'s base if so.
- Test 9 asserts wall + sweep within 10 s and all registered pids dead;
  RLIMIT_NPROC counts all of the user's processes, so the fork count
  assertion is `n < 40` (never an exact number).
