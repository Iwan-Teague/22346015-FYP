//! `rh-dev`: rustyharness's dev-only tooling binary (memory
//! "rust-only-tooling": no logic in shell scripts; every external program —
//! `utmctl`, `ssh`, `rsync` — is invoked as an argv array through
//! `std::process::Command`, never through a shell).
//!
//! This crate is deliberately OUTSIDE the repo's root workspace (see the
//! note in `Cargo.toml`): the shipped harness is held by
//! `scripts/ci/purity.sh` to two pinned spawn modules and refuses any
//! workspace crate it does not read, while a dev tool's job is to drive
//! external programs. Keeping the crate standalone keeps every root gate
//! and the root `Cargo.lock` exactly as they were; its own gates are
//! `cargo fmt`, `cargo clippy --all-targets -- -D warnings` and
//! `cargo test --locked`, run inside `tools/rh-dev/`.
//!
//! Verbs (one module each, dispatched in `main.rs`):
//!
//! - [`linux`] — `rh-dev linux` (slice S-Lh): sync the workspace to the
//!   Linux VM over `rsync`, run the Linux conformance suite and the
//!   sandbox's unit tests over `ssh` under a wall-clock timeout, parse
//!   cargo's `test result:` lines and exit 0 only if every selected test
//!   passed. One VM, so the whole run holds `/tmp/rh-linux-vm.lock`; an
//!   unreachable VM or a busy lock is a LOUD non-zero skip that is never a
//!   pass (design note `docs/slices/S-L-linux-sandbox.md` §5).
//!
//! Shared helpers the verbs reuse: [`proc`] (bounded argv runs, the
//! process-group kill) and [`parse`] (cargo output parsing).

#![forbid(unsafe_code)]
// The panic-set lints ratchet production code; unit tests may assert loosely.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]
// The tool drives ssh/rsync/utmctl over unix process semantics
// (`CommandExt::process_group`, the `/bin/kill` group kill).
#[cfg(not(unix))]
compile_error!("rh-dev drives unix processes (ssh, rsync, utmctl); unix only.");

pub mod linux;
pub mod parse;
pub mod proc;
