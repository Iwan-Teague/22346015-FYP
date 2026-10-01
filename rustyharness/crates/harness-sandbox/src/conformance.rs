//! The hostile-task cases (design §6.6) and the committed pass matrix
//! (§6.1 condition 1).
//!
//! A backend mints [`crate::Conformed`] only if its matrix row exists here
//! AND its live self-probe passes on this host. The witness carries the
//! row's case set; [`crate::require`], the production entry point, demands
//! [`H2_EXIT_CASES`] in full, so a backend whose row is partial can be
//! exercised by its conformance tests but gates no execution.

use crate::{BackendKind, KillDomain, NetworkMechanism};

/// A hostile task of the conformance suite (§6.6), plus the variants the
/// H2 work added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Case {
    /// FT-1: a program opens TCP to an address; connect fails.
    Ft1,
    /// FT-2: a build script opens the same socket.
    Ft2,
    /// FT-3: writes outside the workspace fail; nothing is left behind.
    Ft3,
    /// FT-4: a home-shaped secret canary is unreadable; env canary absent.
    Ft4,
    /// FT-5: a bounded fork bomb is killed by a limit.
    Ft5,
    /// FT-6: a memory bomb is killed by a limit.
    Ft6,
    /// FT-7: a disk fill is stopped by the file-size cap.
    Ft7,
    /// FT-8: a busy loop is killed at the wall clock.
    Ft8,
    /// FT-9: writes to protected paths fail; the file is unchanged.
    Ft9,
    /// FT-10: the harness state and journal are not even readable.
    Ft10,
    /// FT-11: connecting to a unix socket outside the workspace fails.
    Ft11,
    /// FT-12: a symlink out of the workspace is not followed by `exec`.
    Ft12,
    /// FT-13: a direct connect bypassing the proxy fails.
    Ft13,
    /// FT-14: the proxy refuses a hostname resolving to a private address (H4).
    Ft14,
    /// FT-15: no resolver is reachable (DNS exfiltration).
    Ft15,
    /// FT-16: a double-forking, SIGTERM-ignoring child is gone after the kill.
    Ft16,
    /// FT-16 with `setsid()`: the descendant leaves the process group
    /// (OD-5 review M-5).
    Ft16Setsid,
    /// FT-17: LaunchServices (launching outside the sandbox) is unreachable.
    Ft17,
    /// FT-18: keychain / pasteboard services are unreachable.
    Ft18,
    /// D31: with `network = none`, no bind at all, even on loopback.
    NoBind,
    /// A confined process cannot apply another sandbox, so it can neither
    /// loosen its profile nor leave its sandbox instance (the kill domain).
    NestedSandbox,
}

impl Case {
    /// The corpus id.
    pub fn id(self) -> &'static str {
        match self {
            Case::Ft1 => "FT-1",
            Case::Ft2 => "FT-2",
            Case::Ft3 => "FT-3",
            Case::Ft4 => "FT-4",
            Case::Ft5 => "FT-5",
            Case::Ft6 => "FT-6",
            Case::Ft7 => "FT-7",
            Case::Ft8 => "FT-8",
            Case::Ft9 => "FT-9",
            Case::Ft10 => "FT-10",
            Case::Ft11 => "FT-11",
            Case::Ft12 => "FT-12",
            Case::Ft13 => "FT-13",
            Case::Ft14 => "FT-14",
            Case::Ft15 => "FT-15",
            Case::Ft16 => "FT-16",
            Case::Ft16Setsid => "FT-16-setsid",
            Case::Ft17 => "FT-17",
            Case::Ft18 => "FT-18",
            Case::NoBind => "D31-no-bind",
            Case::NestedSandbox => "nested-sandbox",
        }
    }
}

/// What a backend must pass before `require()` hands out a witness: the
/// whole §6.6 suite as H2's exit states it (network = none only, so FT-14,
/// a proxy behaviour, waits for H4), plus the setsid variant, D31, and the
/// nested-sandbox refusal the kill domain relies on.
pub const H2_EXIT_CASES: &[Case] = &[
    Case::Ft1,
    Case::Ft2,
    Case::Ft3,
    Case::Ft4,
    Case::Ft5,
    Case::Ft6,
    Case::Ft7,
    Case::Ft8,
    Case::Ft9,
    Case::Ft10,
    Case::Ft11,
    Case::Ft12,
    Case::Ft13,
    Case::Ft15,
    Case::Ft16,
    Case::Ft16Setsid,
    Case::Ft17,
    Case::Ft18,
    Case::NoBind,
    Case::NestedSandbox,
];

/// One committed row of the pass matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatrixRow {
    /// Row id, carried in the witness and the journal header.
    pub id: &'static str,
    /// The backend.
    pub backend: BackendKind,
    /// The OS family (`std::env::consts::OS`).
    pub os: &'static str,
    /// The cases this backend passed.
    pub cases: &'static [Case],
    /// How the backend blocks the network.
    pub network: NetworkMechanism,
    /// How the backend empties a call's processes.
    pub kill_domain: KillDomain,
    /// Where the pass was observed.
    pub evidence: &'static str,
}

/// The committed matrix. A backend with no row here cannot mint a witness.
pub const MATRIX: &[MatrixRow] = &[MatrixRow {
    id: "seatbelt-macos-h2a",
    backend: BackendKind::Seatbelt,
    os: "macos",
    cases: &[
        Case::Ft1,
        Case::Ft2,
        Case::Ft3,
        Case::Ft4,
        Case::Ft7,
        Case::Ft8,
        Case::Ft9,
        Case::Ft10,
        Case::Ft11,
        Case::Ft12,
        Case::Ft13,
        Case::Ft15,
        Case::Ft16,
        Case::Ft16Setsid,
        Case::Ft17,
        Case::Ft18,
        Case::NoBind,
        Case::NestedSandbox,
    ],
    network: NetworkMechanism::SeatbeltDenyAll,
    kill_domain: KillDomain::GroupAndSandboxSweep,
    evidence: "harness-sandbox tests/conformance_macos.rs, macOS 26.5.1 arm64, 2026-09-28 (local; CI pending)",
}];

/// The row for `backend` on `os`, if one is committed.
pub fn row(backend: BackendKind, os: &str) -> Option<&'static MatrixRow> {
    MATRIX.iter().find(|r| r.backend == backend && r.os == os)
}

/// The cases of `required` that `have` lacks.
pub fn missing(have: &[Case], required: &[Case]) -> Vec<Case> {
    required
        .iter()
        .copied()
        .filter(|c| !have.contains(c))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_macos_row_is_partial_so_require_refuses() {
        let r = row(BackendKind::Seatbelt, "macos").unwrap();
        let m = missing(r.cases, H2_EXIT_CASES);
        // FT-5 and FT-6: no enforceable limit on macOS without privileges.
        assert_eq!(m, vec![Case::Ft5, Case::Ft6]);
        assert!(row(BackendKind::Linux, "linux").is_none());
        assert!(row(BackendKind::AppContainer, "windows").is_none());
    }
}
