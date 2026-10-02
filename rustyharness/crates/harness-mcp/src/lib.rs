//! rustyharness MCP stdio client (design note `docs/slices/P-37-mcp-client.md`).
//!
//! This slice (P-37c) is the pure wire codec only ([`wire`]): bounded
//! newline framing, strict duplicate-key-refusing parsing, message
//! classification and the deterministic request encoders. The client state
//! machine, the provider and the confined connector are later slices of
//! P-37; the fake server they are tested against is the fixture crate.
//!
//! The scanned file (`scripts/ci/purity.sh` §2) is pure in the gate's
//! sense: bytes are fed in and values come out, no facility of the I/O,
//! process, environment, console or clock kind is named, and no global
//! state is kept — the same shape as `harness-model-core`'s `SseReader`,
//! for the same reason: audit recomputes MCP request bytes from this
//! code, so it must stay a pure function of bytes and arguments.

#![forbid(unsafe_code)]
// The panic-set lints ratchet production code; unit tests may assert loosely.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

pub mod wire;
