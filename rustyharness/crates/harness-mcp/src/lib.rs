//! rustyharness MCP stdio client (design note `docs/slices/P-37-mcp-client.md`).
//!
//! This slice (P-37f) adds the pure response renderer ([`render`]) to the
//! pure wire codec of P-37c ([`wire`]): one raw response line plus the
//! result cap in, an observation's status, text, cut mark and digest out —
//! the function audit re-runs from the journaled `mcp_response` line (§12).
//! The client state machine, the provider and the confined connector are
//! later slices of P-37; the fake server they are tested against is the
//! fixture crate.
//!
//! The scanned files (`scripts/ci/purity.sh` §2) are pure in the gate's
//! sense: bytes are fed in and values come out, no facility of the I/O,
//! process, environment, console or clock kind is named, and no global
//! state is kept — the same shape as `harness-model-core`'s `SseReader`,
//! for the same reason: audit recomputes MCP request bytes and re-renders
//! MCP responses from this code, so both must stay pure functions of bytes
//! and arguments.

#![forbid(unsafe_code)]
// The panic-set lints ratchet production code; unit tests may assert loosely.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

pub mod render;
pub mod wire;
