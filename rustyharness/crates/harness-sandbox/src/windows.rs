//! The Windows backend: designed to the same [`Backend`] trait, not built
//! in S-W1. It never mints a witness.
//!
//! The mechanism is the one [`BackendKind::AppContainer`] names: an
//! AppContainer with no network capability, a Job Object for the kill
//! domain, memory and process bounds. Building it needs Win32 calls, and
//! Win32 calls need `unsafe`, which this workspace forbids
//! (`forbid(unsafe_code)`, §6.7): the audited Win32 crate the design gives
//! the volume query (`harness-sandbox-windows`) does not exist yet. Spike
//! S-W1 made the rest of the harness Windows-correct — the pure path rules
//! (`harness-policy::path`), the read/edit/search/outline tools, the
//! `FsQuery::Windows` locality shape and the `doctor` report — and this
//! stub fills the [`Backend`] seam so `platform_probe` and
//! `SystemConfinement::spawn` route to the right backend per OS. A Windows
//! conformance suite (the macOS `tests/conformance_macos.rs` shape) is the
//! bar execution waits for; until then `probe` refuses with the facts and
//! `spawn` refuses without running anything.

use crate::{
    Backend, BackendKind, ConfinedChild, ConfinedSpec, Conformed, SpawnError, Unavailable,
    UnavailableReason,
};

/// Why the backend is not built (the refusal's facts line). A constant:
/// `std` offers no window on AppContainer or Job Objects, and this crate
/// forbids `unsafe`, so there is nothing to measure (compare
/// `linux::host_facts`, which reads `/proc` and `/sys`).
const NOT_BUILT_FACTS: &str = "windows: no AppContainer/JobObject backend yet; the Win32 \
                               calls need the audited FFI crate this workspace does not \
                               ship (spike S-W1: read and edit only)";

/// The Windows backend (facts only until its conformance suite passes).
#[derive(Debug, Clone, Copy, Default)]
pub struct Windows;

impl Backend for Windows {
    fn kind(&self) -> BackendKind {
        BackendKind::AppContainer
    }

    fn probe(&self) -> Result<Conformed, Unavailable> {
        if cfg!(not(target_os = "windows")) {
            return Err(Unavailable {
                backend: None,
                reason: UnavailableReason::NoBackendForOs,
            });
        }
        Err(Unavailable {
            backend: Some(BackendKind::AppContainer),
            reason: UnavailableReason::NotBuilt {
                facts: NOT_BUILT_FACTS.to_owned(),
            },
        })
    }

    fn spawn(&self, _spec: &ConfinedSpec, ev: &Conformed) -> Result<ConfinedChild, SpawnError> {
        if ev.backend() != BackendKind::AppContainer {
            return Err(SpawnError::WrongWitness);
        }
        // Unreachable: no Windows witness can be minted (no matrix row,
        // and probe() always refuses).
        Err(SpawnError::Io("the Windows backend is not built".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // S-W1: a Windows witness is never minted, and off Windows the stub
    // refuses as "no backend for this OS" (so a stray routing change
    // cannot make macOS probe the Windows stub).
    #[test]
    fn the_windows_backend_never_mints() {
        assert!(Windows.probe().is_err());
        #[cfg(not(target_os = "windows"))]
        assert!(matches!(
            Windows.probe().unwrap_err().reason,
            UnavailableReason::NoBackendForOs
        ));
    }

    // The named S-W1 behaviour: on Windows, execution refuses before
    // anything starts, with the same fail-closed message the other
    // non-macOS platforms get today (INV-6), and the stub's own probe
    // refuses with its facts.
    #[cfg(target_os = "windows")]
    #[test]
    fn exec_refuses_without_confinement_on_windows() {
        use crate::Containment;

        let e = crate::require().unwrap_err();
        assert!(
            e.to_string().contains("no confinement on this platform"),
            "{e}"
        );
        assert!(e.0.to_string().contains("no conformance matrix row"), "{e}");
        assert_eq!(e.0.kind(), crate::UnavailableKind::CouldNotRun);
        assert!(matches!(crate::available(), Containment::Unavailable(_)));
        let u = Windows.probe().unwrap_err();
        assert!(
            matches!(u.reason, UnavailableReason::NotBuilt { .. }),
            "{u}"
        );
        assert!(u.to_string().contains("backend not built yet"), "{u}");
    }
}
