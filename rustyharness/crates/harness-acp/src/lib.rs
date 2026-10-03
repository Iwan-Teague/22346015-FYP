//! The rustyharness ACP server (P-35): the Agent Client Protocol v1
//! (pinned in `docs/slices/P-35-acp-spec-notes.md`) over stdio —
//! newline-delimited JSON-RPC, no listener, no socket.
//!
//! [`serve`] is the whole server: it reads the client's side on one
//! thread, writes the protocol from the caller's thread, and bridges
//! the four baseline methods onto one `harness_run::run_session` per
//! ACP session:
//!
//! - `initialize` — the handshake; version 1, no capabilities
//!   advertised (fail closed).
//! - `session/new` — validates `cwd` (absolute, a directory; it IS the
//!   session's workspace) and refuses MCP servers; at most one ACP
//!   session at a time.
//! - `session/prompt` — one user turn; the response (`stopReason`) is
//!   written at the turn boundary after the turn. Journal records the
//!   client can see stream out as `session/update` notifications
//!   while the turn runs.
//! - `session/cancel` — a notification; fail-closed semantics (see the
//!   module docs of the bridge): it never interrupts a journaled turn,
//!   it answers the pending prompt `cancelled`.
//! - `session/request_permission` — the client is the approver
//!   (`ApproverKind::Embedded`); a cancelled outcome, an error, or
//!   silence is a deny.
//!
//! Every method we do not speak is `-32601`; anything before
//! `initialize` is a server error; untrusted text is resolved out of
//! the journal's blobs and sanitized before it reaches the wire.

#![forbid(unsafe_code)]
// The panic-set lints ratchet production code; integration tests may
// assert loosely.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

mod bridge;
mod server;
mod wire;

pub use server::{serve, ServeOutput, ServeParams};
