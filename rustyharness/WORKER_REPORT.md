# WORKER_REPORT — P-23 fix-up round 2

## What failed and the root cause

Stage `gates` failed to compile `harness-cli`:

```
error[E0061]: this function takes 7 arguments but 6 arguments were supplied
   --> crates/harness-cli/src/cmd_compare.rs:545:21
```

Root cause: my P-23 slice added the `accept_edits: bool` parameter to
`crate::bundle::write_run_bundle` (crates/harness-cli/src/bundle.rs:335). The
call sites in `cmd_run.rs` and `cmd_chat.rs` were updated; the call site in
`cmd_compare.rs` was missed. This was a plain missed-call-site compile error,
not a test or environment problem.

## Fix

`crates/harness-cli/src/cmd_compare.rs` (`run_arm`, the one call site): pass
`false` as the 7th argument, with a comment explaining why. Rationale:
`compare` takes no `--accept-edits` flag (its option allow-lists are
`ALLOWED`/`VALUELESS` at cmd_compare.rs:58-61, and its arm option maps never
carry `accept-edits`), so `crate::inputs::inputs` builds every arm's digests
with `accept_edits == false` (inputs.rs:246). The bundle self-check must
digest the policy the same way the run did, so `false` is the only value
consistent with the arm's recorded `inp.digests`.

I deliberately did NOT add an `--accept-edits` option to `compare`: that is
new user-facing behaviour (new flag in the allow-lists, args docs, tests,
journaling) and is out of scope for a fix-up whose job is to restore the
build. Flagging below as a design question.

## Files touched

- crates/harness-cli/src/cmd_compare.rs (one call site + comment, +6 lines)

No tests weakened, deleted or ignored. No dependencies added. No changes to
scripts/ci/*.

## Commit

- `24d41d5` "P-23: compare writes its run bundle with the accept-edits arg write_run_bundle gained"
  (on branch w/P-23; tree clean)

## Verification

- `sh scripts/ci/gates.sh` (whole thing, network used by the cargo-deny
  stage as the manager instructed): exit 0, printed
  `All 5 rustyharness gates passed.`
  Gates: 1/5 cargo fmt --check, 2/5 purity checks, 3/5 cargo deny,
  4/5 cargo clippy -D warnings (incl. gate-outcome without the json
  feature), 5/5 cargo test --workspace (incl. gate-outcome standalone and
  compile-fail doctests).
- Full-workspace test totals across the gates log:
  `1253 passed; 0 failed; 13 ignored` (95 `test result: ok.` lines, all ok).
- Per-crate summary lines are in the gates log at
  /var/folders/l7/ynr6pppn4vxf6b5smv497d4m0000gn/T/opencode/gates-p23.log;
  representative final lines:

```
test result: ok. 85 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.36s
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.25s
All 5 rustyharness gates passed.
```

## Not finished / doubts

- None functionally. First `gates.sh` attempt was killed by my tooling's
  20-minute timeout mid-run (cold build); the re-run with a longer timeout
  passed from scratch — no flakiness, no Seatbelt `LiveProbeFailed` seen.
- The 13 ignored tests are pre-existing (marked in the log before this
  round's changes); I did not touch them.

## Design questions for the manager

1. Should `compare` accept `--accept-edits` at all? Arms are supposed to be
   "exactly as `run` would have built them", and `run` has the flag. If yes,
   that is a small follow-up slice: add it to compare's allow-lists, thread
   it into the arm option maps (inputs.rs then applies the overlay), pass it
   to `write_run_bundle`, and test that a compare run's bundle replays. I
   chose the fail-closed reading (no new flag) for this fix-up.
2. `write_run_bundle` now has two adjacent `bool` parameters (`overlay`,
   `accept_edits`). If a third overlay lands, consider a small
   `OverlaySettings` struct to keep the seven positional bools from
   re-biting the next call site.
