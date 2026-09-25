//! The model layer (design `docs/01-design-v0.1.md` §3, §2.2 steps 3-4,
//! §2.9, §5.5; H1 row of §9).
//!
//! - [`ModelBackend`]: one call, one [`Completion`] or a typed
//!   [`ModelError`]. Implementations: [`client::OpenAiCompatible`]
//!   (loopback HTTP), [`replay::ReplayBackend`] (§2.9), and
//!   [`scripted::ScriptedBackend`] (tests).
//! - [`Message`] carries its trust mark across the loop boundary
//!   (scaffold review F4): only harness templates and the task are trusted;
//!   model replies and observations are [`Untrusted`]. [`wire::render_request`]
//!   is the one place they are read for the wire.
//! - [`protocol`]: both action protocols, parsed strictly; only the model's
//!   own reply is ever parsed (INV-29), free text outside the action stays
//!   untrusted reasoning, and a format error is charged to the meter.
//! - [`profile`]: per-model profiles (§3.4) and the `profile check` scoring.
//!
//! **Pure and I/O parts.** The pure half (`endpoint`, `wire`, `protocol`,
//! `profile`, `context` and the data types) is the separate pure crate
//! `harness-model-core`, re-exported here (H1e-1 review NF-A); `http` and
//! `client` own the sockets; `replay` and `smoke` are generic over a
//! backend.
//!
//! **Blocking, not tokio (for now).** Design §3.2 sketches the client over
//! tokio because rmcp (H4) needs a runtime. For loopback-only H1 a blocking
//! client over `std::net` needs no dependency at all, and the trait is
//! synchronous like `ToolProvider` (H1c). H1e decided: both stay synchronous
//! for H1, and the question returns with rmcp (H4).

#![forbid(unsafe_code)]
// The panic-set lints ratchet production code; unit tests may assert loosely.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

use std::time::Instant;

pub mod client;
pub(crate) mod http;
pub mod replay;
pub mod scripted;
pub mod smoke;

// The pure half lives in `harness-model-core` (H1e-1 review NF-A); it is
// re-exported here so the model layer keeps one public face.
pub use harness_model_core::*;

/// A model backend (§3.1). Synchronous for now (see the crate docs).
pub trait ModelBackend {
    /// What the journal header records.
    fn identity(&self) -> ModelIdentity;

    /// One call under `deadline`.
    fn complete(&self, req: &ModelRequest, deadline: Instant) -> Result<Completion, ModelError>;
}
