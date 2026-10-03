//! The hostile-task cases (design §6.6) and the committed pass matrix
//! (§6.1 condition 1).
//!
//! A backend mints [`crate::Conformed`] only if its matrix row exists here
//! AND its live self-probe passes on this host. The witness carries the
//! row's case set; [`crate::require`], the production entry point, demands
//! [`H2_EXIT_CASES`] in full, so a backend whose row is partial can be
//! exercised by its conformance tests but gates no execution.
//!
//! The web airlock (§5.3) adds the proxy-profile cases; a research session
//! that fetches demands `AIRLOCK_CASES` in its witness's covers (INV-46).
//! They are deliberately not part of [`H2_EXIT_CASES`] or the matrix row:
//! plain execution must not demand proxy-profile behaviour, only the
//! airlock's spawn path does.

use crate::{BackendKind, KillDomain, MemoryGuard, NetworkMechanism, ProcessGuard};

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
    /// A hard link from a file outside the read-write roots into the
    /// workspace is refused, so path-based rules cannot be sidestepped by
    /// aliasing an outside file under a workspace path (review LOW-4).
    HardLink,
    /// P-36a: a bind to `localhost:<granted>` is allowed.
    PortsBindGranted,
    /// P-36a: a bind to an ungranted (but free) port is refused.
    PortsBindUngranted,
    /// P-36a: a wildcard bind (`0.0.0.0:<granted>`) is refused without a
    /// LAN grant, so `localhost:<p>` does not admit the whole interface.
    PortsWildcardNoLan,
    /// P-36a: a wildcard bind is allowed with a LAN grant (`*:<p>`).
    PortsWildcardLan,
    /// P-36a: an outbound connect to a granted port is allowed.
    PortsConnectGranted,
    /// P-36a: an outbound connect to an ungranted loopback port is
    /// refused.
    PortsConnectUngranted,
    /// P-36a: a connect to the model server's port is refused, and the
    /// listener sees no connection (INV-41).
    PortsModelServer,
    /// P-36a: under a port profile, outbound to routable addresses, unix
    /// sockets and the resolver are still refused (FT-1, FT-11, FT-15).
    PortsKeepFt1Ft11Ft15,
    /// P-36a: a UDP bind on a TCP-granted port is refused (the grants name
    /// `tcp` only).
    PortsUdp,
    /// FT-13 under the proxy profile: a direct connect to a routable
    /// address fails while the granted pump port connects (the positive
    /// control; §5.3).
    Ft13P,
    /// FT-15 under the proxy profile: no resolver is reachable, even with
    /// one loopback port granted.
    Ft15P,
    /// FT-19: a connect to any other loopback port fails, including one
    /// with a listener standing in for the model server (§6.5).
    Ft19,
    /// FT-20: no bind and no listen, even under the proxy profile.
    Ft20,
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
            Case::HardLink => "hard-link",
            Case::PortsBindGranted => "ports-bind-granted",
            Case::PortsBindUngranted => "ports-bind-ungranted",
            Case::PortsWildcardNoLan => "ports-wildcard-no-lan",
            Case::PortsWildcardLan => "ports-wildcard-lan",
            Case::PortsConnectGranted => "ports-connect-granted",
            Case::PortsConnectUngranted => "ports-connect-ungranted",
            Case::PortsModelServer => "ports-model-server",
            Case::PortsKeepFt1Ft11Ft15 => "ports-keep-ft1-ft11-ft15",
            Case::PortsUdp => "ports-udp",
            Case::Ft13P => "FT-13-proxy",
            Case::Ft15P => "FT-15-proxy",
            Case::Ft19 => "FT-19",
            Case::Ft20 => "FT-20",
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
    Case::HardLink,
];

/// The loopback-port cases (P-36a, §12 `PORTS_CASES`): what SBPL must be
/// measured to express before any run is granted ports. A backend's row
/// lists them only when every case's test passed on the minting host, so
/// `covers(PORTS_CASES)` is the gate `Network::Loopback` validates
/// against; until then ports are refused everywhere.
pub const PORTS_CASES: &[Case] = &[
    Case::PortsBindGranted,
    Case::PortsBindUngranted,
    Case::PortsWildcardNoLan,
    Case::PortsWildcardLan,
    Case::PortsConnectGranted,
    Case::PortsConnectUngranted,
    Case::PortsModelServer,
    Case::PortsKeepFt1Ft11Ft15,
    Case::PortsUdp,
];

/// What the airlock's fetcher must have witnessed before a research session
/// may fetch (§5.3, INV-46): the whole H2 exit set plus the proxy-profile
/// cases. Spelled out (not computed) because a `const` slice cannot
/// concatenate.
pub const AIRLOCK_CASES: &[Case] = &[
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
    Case::HardLink,
    Case::Ft13P,
    Case::Ft15P,
    Case::Ft19,
    Case::Ft20,
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
    /// How the backend bounds a call's memory (FT-6); names the exact bar.
    pub memory: MemoryGuard,
    /// How the backend bounds a call's process count (FT-5); names the bar.
    pub processes: ProcessGuard,
    /// Where the pass was observed.
    pub evidence: &'static str,
}

/// The committed matrix. A backend with no row here cannot mint a witness.
pub const MATRIX: &[MatrixRow] = &[MatrixRow {
    id: "seatbelt-macos-h2c",
    backend: BackendKind::Seatbelt,
    os: "macos",
    cases: &[
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
        Case::HardLink,
    ],
    network: NetworkMechanism::SeatbeltDenyAll,
    kill_domain: KillDomain::GroupAndSandboxSweep,
    // FT-6 at the strong bar (kernel-enforced per-process address space);
    // FT-5 at a named weaker bar (a member-count watchdog: no per-sandbox
    // process rlimit exists on macOS without privilege). See the H2c report.
    memory: MemoryGuard::RlimitAddressSpace,
    processes: ProcessGuard::MemberCountWatchdog,
    evidence: "harness-sandbox tests/conformance_macos.rs, macOS 26.5.1 (25F80) arm64, 2026-09-28 (local; CI pending)",
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
    fn the_macos_row_now_covers_the_whole_exit_set() {
        let r = row(BackendKind::Seatbelt, "macos").unwrap();
        // H2c added the FT-5 (watchdog) and FT-6 (RLIMIT_AS) guards and the
        // hard-link case, so the row is complete and require() can pass.
        assert!(
            missing(r.cases, H2_EXIT_CASES).is_empty(),
            "still missing: {:?}",
            missing(r.cases, H2_EXIT_CASES)
        );
        assert_eq!(r.memory, MemoryGuard::RlimitAddressSpace);
        assert_eq!(r.processes, ProcessGuard::MemberCountWatchdog);
        assert!(row(BackendKind::Linux, "linux").is_none());
        assert!(row(BackendKind::AppContainer, "windows").is_none());
    }

    #[test]
    fn airlock_cases_are_the_h2_set_plus_the_proxy_cases() {
        // The airlock set is a strict superset of the H2 exit set ...
        assert!(missing(AIRLOCK_CASES, H2_EXIT_CASES).is_empty());
        // ... and exactly the H2 set plus the four proxy-profile cases.
        let extra = missing(H2_EXIT_CASES, AIRLOCK_CASES);
        assert_eq!(
            extra,
            vec![Case::Ft13P, Case::Ft15P, Case::Ft19, Case::Ft20]
        );
        assert_eq!(Case::Ft13P.id(), "FT-13-proxy");
        assert_eq!(Case::Ft15P.id(), "FT-15-proxy");
        assert_eq!(Case::Ft19.id(), "FT-19");
        assert_eq!(Case::Ft20.id(), "FT-20");
        // Plain execution must not demand proxy behaviour: the matrix row
        // still covers only the H2 exit set.
        let r = row(BackendKind::Seatbelt, "macos").unwrap();
        assert!(missing(r.cases, AIRLOCK_CASES).len() == 4);
        assert!(!r.cases.contains(&Case::Ft13P));
    }
}
