# S-Lf — `tests/conformance_linux.rs`: the macOS suite mirrored through the real spawn seam

## What landed
- `crates/harness-sandbox/tests/conformance_linux.rs` (new): one-for-one with
  `conformance_macos.rs` — same `Case` ids (FT-1..FT-18 as applicable, D31,
  nested-sandbox, hard-link), every check from OUTSIDE, unconfined controls,
  serial. 19 cases: the 16 named in the slice card plus the witness-mint test
  (asserts the row `linux-landlock-seccomp-nons-v1`, `H2_EXIT_CASES` coverage,
  `RlimitAddressSpace`/`RlimitNprocPerUser`, `require().is_ok()`), the
  benign env/output sanity run, and `output_is_capped_without_blocking`
  (exercises the new output-cap mapping of the seam).
- The spawn seam itself (the card's "real spawn seam" reading; the old
  `Linux::spawn` stub said "S-Lf wires the Linux spawn path"):
  - `crates/harness-sandbox/src/linux.rs`: `Child` (wraps
    `supervisor::Running` + the spec's output cap), `finish`/`capped`
    (RawExit → `ConfinedExit`: wall-clock → `TimedOut`, helper's 94..102 →
    `ExecFailed`, else the wait status; sweep report → `Confirmed{kills}` /
    `Unconfirmed(detail)`), `private_dir` (lexical anchor only, removed
    after validation), `start` (validate → `supervisor::Program` →
    `supervisor::spawn` with `current_exe()` as the helper). Network tiers
    are refused by validation (`proxy: false`, `ports_conformed: false`):
    the row's seccomp denies `socket()` outright, so no network grant is
    enforceable. `spawn_live` keeps the trait's default refusal.
  - `crates/harness-sandbox/src/lib.rs`: `ConfinedChild` gains the
    `#[cfg(target_os = "linux")] inner: linux::Child` arm (all five methods).
- `crates/harness-sandbox/Cargo.toml`: `[[test]] conformance_linux`
  `harness = false` (its `main()` is also the supervisor helper: argv
  `__confine` dispatch, like the live binaries of harness-sandbox-linux; a
  libtest harness would swallow those args as filters). It prints
  libtest-shaped tallies itself (`running N tests` / `test NAME ... ok` /
  `test result: ok. …`), honours one positional substring filter, and
  exits 1 on failure, so `rh-dev linux`'s `test result:` parsing works with
  `cargo test -p harness-sandbox --test conformance_linux --
  --nocapture --test-threads=1` unchanged.
- Self dev-dependency `harness-sandbox = { path = ".", features =
  ["linux-probe-row"] }` so the witness hand-out (the uncommitted row) is
  visible to `cargo test -p harness-sandbox` with no `--features` flag —
  the same sealed-seam pattern as harness-journal's `fault-injection`.
  `required-features` was rejected: the suite would be silently skipped
  (no tally) wherever the feature is off, which rh-dev would read as FAIL.
  **H-F note:** this adds one `Cargo.lock` edge (harness-sandbox → itself,
  dev). Not a new workspace crate; regenerated offline, not hand-merged.

## Linux flavours (differences from macOS, all deliberate)
- FT-1/D31/FT-11: seccomp denies `socket()` itself, so the canaries print
  `refused` at socket creation; the TEST-NET arm still shows
  `refused Operation not permitted` (seccomp EACCES).
- FT-5: no watchdog on this row — per-user `RLIMIT_NPROC` makes forks fail
  (EAGAIN); the script prints its forked count and the test asserts
  `count < 40` plus completion, not `ProcessLimit`.
- FT-6: `RLIMIT_AS` hard-bounds the bomb; no host-pressure skip (the VM is
  dedicated; if the control cannot allocate 320 MiB the suite must fail
  loudly).
- FT-12: the macOS FT-27 FIFO arm is absent — this row's file check is
  path-based (Landlock), and a FIFO inside the granted workspace opens.
- nested-sandbox: `unshare -Ur` refused by seccomp (Landlock additionally
  has no un-restrict); the control is informative only (AppArmor may deny
  user namespaces to unconfined users on Ubuntu 24.04).
- FT-17/FT-18: absent, macOS-only escape surfaces (per L-Q3 recorded on the
  row, not silently dropped).
- FT-16: only the setsid arm is here (the named case); the plain
  double-fork arm and the macOS stub-kill gap (`ft16_stub_killed_first…`)
  are Seatbelt-sweep specifics with no Linux counterpart in this slice.
- FT-2 (real cargo build), the proxy section (FT-13p/15p/19/20), the
  macOS-only `cpu_limit`/`exec_outside_the_allowed_paths_fails` (no exec
  allowlist beyond Landlock exec rights) and the sandbox-exec stub nesting
  tests are not mirrored; they need the proxy/ports tier or macOS
  mechanics the namespace-less row does not have. Candidates for the
  later ports slice on Linux.

## Cross-check status (honest)
- Darwin gates green: `cargo fmt --all`, `cargo clippy --locked --workspace
  --all-targets -- -D warnings`, `cargo test --locked -p harness-sandbox`
  (91 unit + 38 macOS conformance + 10 ports + 10 bg + doc-tests, all ok;
  `conformance_linux` builds and runs as a no-op there).
- The Linux-gated code cannot be fully clippy-checked on this host
  (homebrew toolchain shadowing + no linux `clippy-driver`/gcc in
  `~/.cargo/bin`), but it IS compile-checked:
  `cargo check -p harness-sandbox -p harness-sandbox-linux --all-targets
  --target x86_64-unknown-linux-gnu --offline` passes clean.
- Pre-existing find from that cross-check (fixed here, one line):
  `linux.rs::the_digest_names_the_real_sweep_deadline` (S-Le, cfg'd
  `target_os = "linux"`) used `Duration` unimported — it had never been
  compiled on a Linux target. Also pre-existing and NOT fixed here (not
  this slice's scope): on a Linux target, `spec.rs::PortsWitness::new`
  warns dead_code (macOS-only caller); if a Linux `clippy -D warnings`
  gate is ever run in the VM it will trip on it first.
- The green VM run (`rh-dev linux`) is the actual gate; this host cannot
  execute the suite.
