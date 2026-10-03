//! rustyharness MCP stdio client (design note `docs/slices/P-37-mcp-client.md`).
//!
//! This slice (P-37e) adds the client state machine ([`client`]) to the
//! pure wire codec of P-37c ([`wire`]) and the pure response renderer of
//! P-37f ([`render`]): the lifecycle (§3.3), id discipline (§3.2), noise
//! caps and `-32601` refusals (§3.5), the bounds of §4, and the
//! kill-on-any-fault rule, over two seams the caller supplies — a
//! [`client::Clock`] for the deadlines and a [`client::Transport`] for
//! the server's pipes. The provider, the connector seam and the confined
//! connector are later slices of P-37; the fake server the client is
//! tested against is the fixture crate, whose package hosts this slice's
//! hostile-server suite (the purity gate scans every file of THIS
//! package, so its pipes and clocks are named only from outside it).
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

pub mod client;
pub mod render;
pub mod wire;
