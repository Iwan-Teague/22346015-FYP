//! rustyharness execution confinement, and the host probes the run needs.
//!
//! The one rule settled before any backend exists: **no containment, no
//! execution.** When this platform cannot establish the
//! full confinement a policy asks for, [`require`] refuses — there is no
//! "run it anyway and record that it was unsandboxed" path. rustybenchmark
//! has exactly that fail-open path today (suite AQ-194); this crate must not
//! repeat it.
//!
//! Backends (macOS seatbelt, Linux landlock + seccomp + namespaces, Windows
//! Job Objects + AppContainer) are designed in the suite's cross-platform
//! sandbox work (lane d27) and the rustyharness design (§6); none is built
//! yet (H2), so [`available`] reports `Unavailable` on every platform and
//! [`require`] refuses everywhere.
//!
//! Also here, because they measure the host: the filesystem-locality probe
//! ([`locality`], §2.8) and the environment probe ([`environment`], §7.1).
//! On macOS they run the harness's only unconfined children in H1: the three
//! fixed read-only queries of the private `capture` module (§4.5, INV-23).

#![forbid(unsafe_code)]
// The panic-set lints ratchet production code; unit tests may assert loosely.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

// The bounded spawn the macOS probes use (tested wherever /bin/sh exists).
#[cfg(any(target_os = "macos", all(test, unix)))]
mod capture;
pub mod environment;
pub mod locality;

/// What confinement this platform can establish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Containment {
    /// A backend that has passed the shared hostile-task conformance suite.
    Available(Backend),
    /// No conforming backend; the reason is recorded, never ignored.
    Unavailable(&'static str),
}

/// A confinement backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// macOS seatbelt profile.
    Seatbelt,
    /// Linux landlock + seccomp + namespaces.
    Landlock,
    /// Windows Job Objects + AppContainer.
    AppContainer,
}

/// Returned when execution is refused because confinement is unavailable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("refusing to execute: no confinement on this platform ({0})")]
pub struct Refused(pub &'static str);

/// The confinement this platform can establish. Pure; safe for reporting.
pub fn available() -> Containment {
    Containment::Unavailable("no backend has passed conformance yet (H2)")
}

/// Obtain a backend or refuse. Every execution an agent or a check can ask
/// for goes through here; there is no API that runs one without a [`Backend`]
/// in hand. (The harness's own three host queries in `capture` are fixed
/// programs with fixed arguments, §4.5; nothing chosen at run time reaches
/// them.)
pub fn require() -> Result<Backend, Refused> {
    match available() {
        Containment::Available(b) => Ok(b),
        Containment::Unavailable(why) => Err(Refused(why)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_backend_refuses_everywhere() {
        assert!(matches!(available(), Containment::Unavailable(_)));
        assert!(require().is_err());
    }
}
