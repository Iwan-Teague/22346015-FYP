//! `bench-submit` — the offline half of the submission / privacy pipeline (docs/11, docs/12,
//! roadmap P6). No network. It turns a local journal and hardware profile into an upload
//! bundle that is redacted, schema-validated, canonically serialised and content-hashed; gates
//! that on explicit consent; and re-checks a bundle (`verify-bundle`).
//!
//! What is deliberately *not* here, and why, is recorded in
//! [OPEN-QUESTIONS Q32](../../../docs/OPEN-QUESTIONS.md): signing (needs an ed25519 crate and a
//! key policy, and an embedded key is T0-only anyway), encrypted replay artifacts (needs a server
//! key), the challenge/batch protocol and seed secrecy (BLOCKED by REVIEW-5 R5-S2 / Q22 / Q23),
//! and raw calibration numbers (REVIEW-5 R5-S6: either a fingerprint or a control, not both).

pub mod bundle;
pub mod canon;
pub mod cli;
pub mod consent;
pub mod error;
pub mod redact;
pub mod verify;

pub use bundle::{build, BuildInputs, BuildOptions, Built, Bundle};
pub use error::SubmitError;
