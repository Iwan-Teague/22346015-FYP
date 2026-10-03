//! rustyharness MCP stdio client (design note `docs/slices/P-37-mcp-client.md`).
//!
//! This slice (P-37h) adds the provider ([`provider`]) and the connector
//! seam ([`connect`]) to the client state machine of P-37e ([`client`]),
//! the pure wire codec of P-37c ([`wire`]) and the pure response renderer
//! of P-37f ([`render`]): the admitted-call -> one `tools/call` exchange
//! path of §7-§9, the pre-call relist and its quarantine rule (§7.2), and
//! the wire facts the loop journals (`McpRecord`). A provider is generic
//! over [`connect::McpConnector`], the one seam that touches the
//! platform: the confined stdio connector is P-37l. The connector the
//! tests drive is the fixture crate's, which also hosts this slice's
//! provider suite (the purity gate scans every file of THIS package, so
//! its pipes and clocks are named only from outside it).
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
pub mod connect;
pub mod provider;
pub mod render;
#[cfg(feature = "testing")]
pub mod testing;
pub mod wire;
