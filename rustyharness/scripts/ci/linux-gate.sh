#!/bin/sh
# S-Li: the conductor's optional Linux gate step (design note
# docs/slices/S-L-linux-sandbox.md §5.2–§5.3). A THIN launcher: every
# decision is `rh-dev linux`'s (tools/rh-dev); this script only finds the
# binary, passes the conductor contract's arguments, and turns rh-dev's
# exit codes into the loud, never-silently-green posture the design asks
# for. The conductor runs it AFTER the macOS member gates
# (scripts/ci/gates.sh) have passed, for slices that touch
# harness-sandbox-linux or conformance_linux.
#
# Environment (no default is guessed):
#   RH_LINUX_SSH     the guest ssh target, `user@host-or-ip` (required)
#   RH_LINUX_VM      the UTM VM name (default rh-linux)
#   RH_LINUX_TIMEOUT the whole-run wall-clock budget in seconds (default 1800)
#   RH_DEV_BIN       explicit path to the rh-dev binary (else the release,
#                    then the debug build under tools/rh-dev/target is used)
# Extra arguments are passed through to `rh-dev linux` (e.g. `--boot`,
# `--only <test>`, `--keep-logs <dir>`; a `--ssh-wait` bound is wise in a
# conductor, which should skip fast rather than stall).
#
# Exit codes are `rh-dev linux`'s, propagated unchanged
# (tools/rh-dev/src/linux.rs `code`): 0 pass (the slice is Linux-verified);
# 1 tests failed; 2 usage; 3 SKIPPED (VM unreachable or VM lock busy — NOT
# a pass, the slice is NOT Linux-verified and no matrix row may be
# committed from a skipped run); 4 could not run. A missing rh-dev binary
# or a missing ssh target is this script's own exit 4: the step could not
# run, which is never a silent green.
set -eu

cd "$(dirname "$0")/../.."

banner() {
    printf '%s\n' '======================================================================'
    printf '%s\n' "$1"
    printf '%s\n' '======================================================================'
}

# The binary: $RH_DEV_BIN wins when set (and must exist — no silent
# fallback), otherwise the release then the debug build.
RH_DEV="${RH_DEV_BIN:-}"
if [ -n "$RH_DEV" ] && [ ! -x "$RH_DEV" ]; then
    banner "LINUX STEP COULD NOT RUN: RH_DEV_BIN=$RH_DEV is not executable — NOT VERIFIED ON LINUX, not a pass"
    exit 4
fi
if [ -z "$RH_DEV" ]; then
    for candidate in tools/rh-dev/target/release/rh-dev tools/rh-dev/target/debug/rh-dev; do
        if [ -x "$candidate" ]; then
            RH_DEV="$candidate"
            break
        fi
    done
fi
if [ -z "$RH_DEV" ]; then
    banner 'LINUX STEP COULD NOT RUN: no rh-dev binary (build it: (cd tools/rh-dev && cargo build --release --locked)) — NOT VERIFIED ON LINUX, not a pass'
    exit 4
fi

# The ssh target must come from the conductor's environment.
if [ -z "${RH_LINUX_SSH:-}" ]; then
    banner 'LINUX STEP COULD NOT RUN: set RH_LINUX_SSH=<user@host> — NOT VERIFIED ON LINUX, not a pass'
    exit 4
fi

printf '%s\n' "=== Linux gate (S-Li): $RH_DEV linux --vm ${RH_LINUX_VM:-rh-linux} --ssh $RH_LINUX_SSH ==="

code=0
"$RH_DEV" linux --vm "${RH_LINUX_VM:-rh-linux}" --ssh "$RH_LINUX_SSH" \
    --timeout "${RH_LINUX_TIMEOUT:-1800}" "$@" || code=$?

if [ "$code" -eq 3 ]; then
    # §5.2: the loud banner a skip must print. Exit 3 covers both skip
    # reasons (unreachable, busy lock); rh-dev's own line above names
    # which one it was, for the worker report's `linux: skipped …`.
    banner 'LINUX STEP SKIPPED: VM UNREACHABLE — NOT VERIFIED ON LINUX'
    printf '%s\n' 'linux: skipped (rh-dev'"'"'s reason above; unreachable or vm busy): the slice is NOT Linux-verified; NO matrix row may be committed from a skipped run.'
fi

exit "$code"
