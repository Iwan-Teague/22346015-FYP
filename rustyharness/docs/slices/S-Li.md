# S-Li — Conductor Linux gate step: `rh-dev linux` after the macOS gates, never silently green

Implements design note `docs/slices/S-L-linux-sandbox.md` §5.2–§5.3 (slice card
S-L-i): the conductor's optional Linux step, run after the macOS member gates
pass, for slices that touch `harness-sandbox-linux` or `conformance_linux`.
Thin launcher only; every decision stays in `rh-dev linux` (slice S-Lh).

## What landed

- **`scripts/ci/linux-gate.sh` — the launcher, in the repo so the contract is
  versioned.** The design note's "verify/conductor integration — a launcher
  line" points at `devkit/swarm/verify.sh`, which lives OUTSIDE this repo (the
  conductor is the manager's throwaway orchestration; nothing under `devkit/`
  is committed here). This slice therefore commits the launcher itself under
  `scripts/ci/` (alongside `gates.sh`, the other conductor-called entrypoint)
  and records the exact conductor line below; the one-line edit to
  `devkit/swarm/verify.sh` itself is left to whoever runs the conductor.
- **What the launcher does** (and nothing more): `cd` to the repo root, find
  the `rh-dev` binary (`$RH_DEV_BIN` if set and executable — no silent
  fallback — else `tools/rh-dev/target/release/rh-dev`, then the debug build),
  require `$RH_LINUX_SSH`, and exec
  `rh-dev linux --vm "${RH_LINUX_VM:-rh-linux}" --ssh "$RH_LINUX_SSH" --timeout "${RH_LINUX_TIMEOUT:-1800}" "$@"`
  (`"$@"` passes through `--boot`, `--only`, `--keep-logs`, `--ssh-wait`, …).
  It parses no output and decides nothing: rh-dev owns all logic, exactly as
  the card requires.
- **Exit-code contract (rh-dev's codes, propagated unchanged):**
  `0` pass (the slice is Linux-verified); `1` tests failed; `2` usage;
  `3` SKIPPED (VM unreachable **or** VM lock busy — NOT a pass);
  `4` could not run. A missing binary or a missing `RH_LINUX_SSH` is the
  launcher's own loud exit 4. The only output the launcher adds is the §5.2
  banner on a skip:
  `LINUX STEP SKIPPED: VM UNREACHABLE — NOT VERIFIED ON LINUX`, plus the
  report line `linux: skipped (rh-dev's reason above; unreachable or vm
  busy)…`. A skip is never exit 0, never a pass, and no matrix row may be
  committed from a skipped run.
- **Deviation from the design's literal banner (fail-closed, named):** §5.2
  words the banner for the unreachable case only, but rh-dev's exit 3 covers
  both skip reasons (unreachable, `vm busy`, §5.3). Distinguishing them in the
  launcher would mean parsing rh-dev's output — logic the card forbids — so
  the banner keeps the design's exact string and the following line says
  which reason rh-dev reported. The conductor's worker report should quote
  rh-dev's own line (`SKIPPED — the Linux conformance did NOT run` /
  `SKIPPED (vm busy)`), which is precise.

## The conductor line (for `devkit/swarm/verify.sh`, outside this repo)

After the macOS member gates pass, for a slice that touches
`harness-sandbox-linux` or `conformance_linux`:

```sh
RH_LINUX_SSH=<user@host> RH_LINUX_TIMEOUT=1800 \
    sh scripts/ci/linux-gate.sh --keep-logs "<conductor-log-dir>" --ssh-wait 60
case $? in
  0) linux="linux: ok (Linux-verified)" ;;
  3) linux="linux: skipped (see rh-dev's reason: unreachable or vm busy) — NOT Linux-verified, row NOT committed" ;;
  *) fail "Linux gate failed (rh-dev exit $?): the merge is gated like any other gate" ;;
esac
```

Exit 0 gates the merge like any other gate; 1/2/4 fail it; 3 marks the slice
not Linux-verified (merge policy on a skip is the conductor's per §5.2 — the
invariant this slice guarantees is that a skip can never read as green).

## Manual/recorded tests

The conductor is throwaway orchestration; the behaviour assertions live in
rh-dev's own suite, per the card. All launcher runs below were recorded
against the real launcher in this worktree against the real launcher in this worktree (`rh-dev` built with
`cargo build --release --locked` inside `tools/rh-dev/`):

1. No `rh-dev` binary → banner `LINUX STEP COULD NOT RUN: no rh-dev binary …
   not a pass`, exit **4**.
2. `RH_DEV_BIN=/nonexistent/rh-dev` → banner naming the path, exit **4**
   (no silent fallback).
3. Binary present, no `RH_LINUX_SSH` → banner `set RH_LINUX_SSH=<user@host> …
   not a pass`, exit **4**.
4. `RH_LINUX_SSH=ci@vm.invalid` (unreachable), `--ssh-wait 2 --keep-logs …` →
   rh-dev prints `linux: Linux VM rh-linux (ci@vm.invalid) unreachable after
   2s.` and `linux: SKIPPED — the Linux conformance did NOT run; this is not
   a pass.`; the launcher prints the §5.2 banner and the `linux: skipped …`
   report line; exit **3**; the transcript is kept at
   `<dir>/rh-linux-<unix-secs>.log`.
5. `/tmp/rh-linux-vm.lock` held by hand (busy), same target → rh-dev prints
   `linux: /tmp/rh-linux-vm.lock is held … SKIPPED (vm busy), not a pass`;
   launcher banner, exit **3**; the foreign lock is left in place (the
   launcher never removes it).
6. `sh -n scripts/ci/linux-gate.sh` — syntax clean. (shellcheck is not a repo
   gate; not run.)

`rh-dev linux`'s own behaviour (banner text, non-green-on-skip) is asserted by
S-Lh's tests, re-run green for this slice: 11 passed, 0 failed
(incl. `rh_dev_linux_unreachable_vm_is_loud_nonzero`,
`rh_dev_linux_busy_lock_skips_without_running_anything`,
`rh_dev_linux_keeps_logs_on_a_skip`).

## Known limits / follow-ups

- `devkit/swarm/verify.sh` itself is outside this repo; until the conductor
  adopts the line above, `rh-dev linux` runs only by hand (which is also the
  §5.3 pattern: the lock serialises hand-runs and conductor runs alike).
- The launcher does not build `rh-dev` on demand (fail-closed: a gate step
  that compiles its own judge could surprise); the error names the build
  command. If the conductor wants auto-build, that is a manager decision.
- No auto-test of the launcher in the repo gates: the repo's gates drive
  cargo only, the card routes behaviour assertions to S-Lh's suite, and a
  shell self-test would add shell logic the card forbids. The manual runs
  above are the record; re-run them after any launcher edit.
- A real pass (exit 0) was NOT observed: no Linux VM was reachable from this
  worktree (and S-Lf has not landed `conformance_linux` yet, so a reachable
  VM would still fail loudly at the first suite — S-Lh's known limit, by
  design). The pass path is rh-dev's verdict logic, covered by its tests and
  later slices' VM runs.
