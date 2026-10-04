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
    /// P-36d (§7.2): the file-op helper's kernel view — a symlink planted
    /// or swapped inside the workspace is never followed to outside the
    /// profile's roots, measured at the open/rename moment.
    FileOpKernelView,
    /// P-36d (§7.1): the file-op helper cannot fork — the stub never does
    /// and the profile refuses it, so the instance holds one process.
    FileOpNoFork,
    /// P-36d (§7.2): a FIFO swapped into a requested path is refused fast,
    /// not read or written.
    FileOpFifo,
    /// P-36d (§7.1): writes under a protected overlay are refused while
    /// the same write succeeds unconfined.
    FileOpProtected,
    /// P-36d (§7.2): a hard link from outside the workspace cannot be the
    /// target of a replace (nlink refusal), so outside content cannot be
    /// smuggled in or clobbered through one.
    FileOpHardLink,
    /// S-Lg: `openat2` (with or without `RESOLVE_BENEATH`) cannot reach
    /// outside the Landlock read set; `..` and symlinked paths resolve to
    /// the same denial (the handle model decides, not the path text).
    LinuxOpenat2,
    /// S-Lg: `/proc/self/mem` and `/proc/<pid>/mem` are not a write
    /// channel outside the roots; another confined process's mem is
    /// unreachable (`ptrace` is seccomp-denied).
    LinuxProcSelfMem,
    /// S-Lg: only std{in,out,err} cross `exec` into the program child;
    /// the helper's fds are closed (`close_range`) before it.
    LinuxFdInherit,
    /// S-Lg: the built environment carries no `LD_*` loader variable
    /// (INV-10), and a planted one in the harness's own environment does
    /// not reach the child.
    LinuxLdPreload,
    /// S-Lg: a setuid-root binary exec'd by the confined child gains no
    /// privilege (`no_new_privs`); an unconfined control on a permissive
    /// host does gain it.
    LinuxSetuid,
    /// S-Lg: `memfd_create` + `execveat(AT_EMPTY_PATH)` is refused — no
    /// Landlock execute right exists for an anonymous file, and the
    /// `AT_EMPTY_PATH` flag itself is seccomp-denied.
    LinuxMemfdExec,
    /// S-Lg: the abstract unix namespace is unreachable — `socket(AF_UNIX)`
    /// is seccomp-denied, and Landlock (below ABI 6) cannot scope it.
    LinuxAbstractUnix,
    /// S-Lg: `ptrace(PTRACE_ATTACH)` of a sibling confined process is
    /// seccomp-denied, so `/proc/<sibling>/mem` stays unreachable.
    LinuxPtraceSibling,
    /// S-Lg: a fork bomb whose children `setsid()` and double-fork into
    /// other process groups is still bounded, and every descendant is
    /// gone after the stop (the subreaper sweep).
    LinuxForkBombPgroup,
    /// S-Lg: `/dev/shm` and any tmpfs outside the read-write roots are
    /// not writable; a denied write leaves nothing behind.
    LinuxDevShmTmpfs,
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
            Case::FileOpKernelView => "fileop-kernel-view",
            Case::FileOpNoFork => "fileop-no-fork",
            Case::FileOpFifo => "fileop-fifo",
            Case::FileOpProtected => "fileop-protected",
            Case::FileOpHardLink => "fileop-hard-link",
            Case::LinuxOpenat2 => "linux-openat2",
            Case::LinuxProcSelfMem => "linux-proc-self-mem",
            Case::LinuxFdInherit => "linux-fd-inherit",
            Case::LinuxLdPreload => "linux-ld-preload",
            Case::LinuxSetuid => "linux-setuid",
            Case::LinuxMemfdExec => "linux-memfd-exec",
            Case::LinuxAbstractUnix => "linux-abstract-unix",
            Case::LinuxPtraceSibling => "linux-ptrace-sibling",
            Case::LinuxForkBombPgroup => "linux-fork-bomb-pgroup",
            Case::LinuxDevShmTmpfs => "linux-dev-shm-tmpfs",
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

/// The loopback-port subset the namespace tier (S-Lj) can honestly be
/// measured against: every grant is bound to a named TCP port, so the
/// tier's empty netns bounds each grant's reach. The wildcard pair
/// ([`Case::PortsWildcardNoLan`] / [`Case::PortsWildcardLan`]) is absent
/// with a written reason: the tier's seccomp filter cannot inspect a
/// `bind()` sockaddr (it would have to allow all AF_INET binds), and the
/// tier's netns makes a wildcard bind unreachable from other hosts
/// anyway, so neither "refused because expressed" nor "allowed with a LAN
/// grant" is a truthful statement here. LAN grants are refused at this
/// tier in code (`spec.rs`); a future mount-namespace tier that
/// bind-mounts per-port sockets can carry the pair.
pub const PORTS_CASES_NETNS: &[Case] = &[
    Case::PortsBindGranted,
    Case::PortsBindUngranted,
    Case::PortsConnectGranted,
    Case::PortsConnectUngranted,
    Case::PortsModelServer,
    Case::PortsKeepFt1Ft11Ft15,
    Case::PortsUdp,
];

/// The Linux escape-surface cases (S-Lg, §12 discipline): each witnesses
/// an escape a namespace-less Landlock+seccomp row must refuse. None of
/// them joins a matrix row here — they enter [`MATRIX`] (or the probe row)
/// only as their tests pass, one by one, on a real Linux kernel; until
/// then [`missing`] reports them against every row, which is the
/// fail-closed stance the slice card demands.
pub const LINUX_ESCAPE_CASES: &[Case] = &[
    Case::LinuxOpenat2,
    Case::LinuxProcSelfMem,
    Case::LinuxFdInherit,
    Case::LinuxLdPreload,
    Case::LinuxSetuid,
    Case::LinuxMemfdExec,
    Case::LinuxAbstractUnix,
    Case::LinuxPtraceSibling,
    Case::LinuxForkBombPgroup,
    Case::LinuxDevShmTmpfs,
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

/// What the file-op helper conformance adds to the macOS row (P-36d, §12):
/// the kernel-view pair, the fork refusal, the fast FIFO refusal, the
/// protected-overlay refusal and the hard-link refusal. These live in
/// `tests/conformance_fileop_macos.rs` so the existing suite is untouched.
pub const FILEOP_CASES: &[Case] = &[
    Case::FileOpKernelView,
    Case::FileOpNoFork,
    Case::FileOpFifo,
    Case::FileOpProtected,
    Case::FileOpHardLink,
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
        // P-36d: the file-op helper's kernel-view cases (§12), green on
        // this host in tests/conformance_fileop_macos.rs.
        Case::FileOpKernelView,
        Case::FileOpNoFork,
        Case::FileOpFifo,
        Case::FileOpProtected,
        Case::FileOpHardLink,
    ],
    network: NetworkMechanism::SeatbeltDenyAll,
    kill_domain: KillDomain::GroupAndSandboxSweep,
    // FT-6 at the strong bar (kernel-enforced per-process address space);
    // FT-5 at a named weaker bar (a member-count watchdog: no per-sandbox
    // process rlimit exists on macOS without privilege). See the H2c report.
    memory: MemoryGuard::RlimitAddressSpace,
    processes: ProcessGuard::MemberCountWatchdog,
    evidence: "harness-sandbox tests/conformance_macos.rs + tests/conformance_fileop_macos.rs, macOS 26.5.1 (25F80) arm64, H2 cases 2026-09-28, fileop cases 2026-10-03 (local; CI pending)",
}];

/// The row for `backend` on `os`, if one is committed.
pub fn row(backend: BackendKind, os: &str) -> Option<&'static MatrixRow> {
    MATRIX.iter().find(|r| r.backend == backend && r.os == os)
}

/// The Linux default tier's row, NOT yet committed (S-Le): the card lands
/// the probe with this row behind a test/feature gate, and the row joins
/// [`MATRIX`] only once S-Lf has run it green on a real Linux kernel. It
/// is `H2_EXIT_CASES` at the namespace-less default tier's honest bars:
/// Landlock + seccomp for the network, the subreaper sweep for the kill,
/// the address-space rlimit for memory (FT-6), per-user `RLIMIT_NPROC`
/// for processes (FT-5). FT-17 (Seatbelt-specific escape) and FT-18
/// (macOS launch/keychain surface) are macOS cases a Linux row cannot
/// exercise; they are absent with that reason, not silently.
#[cfg(any(test, feature = "linux-probe-row"))]
pub(crate) const LINUX_ROW_UNCOMMITTED: MatrixRow = MatrixRow {
    id: "linux-landlock-seccomp-nons-v1",
    backend: BackendKind::Linux,
    os: "linux",
    cases: H2_EXIT_CASES,
    network: NetworkMechanism::LinuxLandlockSeccomp,
    kill_domain: KillDomain::SubreaperSweep,
    memory: MemoryGuard::RlimitAddressSpace,
    processes: ProcessGuard::RlimitNprocPerUser,
    evidence: "S-Le live probe (uncommitted until S-Lf passes on a real Linux kernel)",
};

/// The namespace tier's row (S-Lj), NOT yet committed: where
/// `HostFacts.userns_usable()` is true, the Linux backend may opt into an
/// unprivileged user+net+pid namespace with the harness-process forwarder.
/// It carries the whole H2 exit set PLUS the netns-port subset
/// ([`PORTS_CASES_NETNS`]) — the only tier whose row lists any ports
/// cases, because only here a port grant is structurally bounded (empty
/// netns) rather than expressed in a filter that cannot read sockaddrs.
/// Guards: Landlock + seccomp (now `linux-net-namespace`) for the
/// network, the PID-namespace init for the kill domain, the same rlimit
/// bars for memory and processes. FT-17/FT-18 stay macOS-only as on the
/// default row; the wildcard port pair is absent for the reason written
/// on [`PORTS_CASES_NETNS`].
#[cfg(any(test, feature = "linux-probe-row"))]
pub(crate) const LINUX_NETNS_ROW_UNCOMMITTED: MatrixRow = MatrixRow {
    id: "linux-netns-pidns-v1",
    backend: BackendKind::Linux,
    os: "linux",
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
        Case::PortsBindGranted,
        Case::PortsBindUngranted,
        Case::PortsConnectGranted,
        Case::PortsConnectUngranted,
        Case::PortsModelServer,
        Case::PortsKeepFt1Ft11Ft15,
        Case::PortsUdp,
    ],
    network: NetworkMechanism::LinuxNetNamespace,
    kill_domain: KillDomain::LinuxPidNamespace,
    memory: MemoryGuard::RlimitAddressSpace,
    processes: ProcessGuard::RlimitNprocPerUser,
    evidence: "S-Lj live probe (uncommitted until the netns tier passes on a real Linux kernel)",
};

/// The uncommitted Linux row, when this build carries it (tests, or the
/// `linux-probe-row` feature). A committed row always wins.
#[cfg(any(test, feature = "linux-probe-row"))]
pub(crate) fn linux_row_uncommitted() -> Option<&'static MatrixRow> {
    match row(BackendKind::Linux, "linux") {
        Some(r) => Some(r),
        None => Some(&LINUX_ROW_UNCOMMITTED),
    }
}

/// The uncommitted namespace-tier row, when this build carries it. The
/// selector is called only after `namespaces::tier_for` said this host is
/// a netns-tier host; a committed row always wins.
#[cfg(any(test, feature = "linux-probe-row"))]
pub(crate) fn linux_netns_row_uncommitted() -> Option<&'static MatrixRow> {
    match row(BackendKind::Linux, "linux") {
        Some(r) if r.network == NetworkMechanism::LinuxNetNamespace => Some(r),
        _ => Some(&LINUX_NETNS_ROW_UNCOMMITTED),
    }
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
    use crate::Conformed;

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

    #[test]
    fn fileop_cases_are_in_the_macos_row() {
        // P-36d (§12): the five file-op cases are committed on the same
        // row, with stable ids for the journal.
        let r = row(BackendKind::Seatbelt, "macos").unwrap();
        assert!(missing(r.cases, FILEOP_CASES).is_empty());
        assert_eq!(FILEOP_CASES.len(), 5);
        assert_eq!(Case::FileOpKernelView.id(), "fileop-kernel-view");
        assert_eq!(Case::FileOpNoFork.id(), "fileop-no-fork");
        assert_eq!(Case::FileOpFifo.id(), "fileop-fifo");
        assert_eq!(Case::FileOpProtected.id(), "fileop-protected");
        assert_eq!(Case::FileOpHardLink.id(), "fileop-hard-link");
        // The ids are distinct from every other case id.
        let mut ids: Vec<&str> = r.cases.iter().map(|c| c.id()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), r.cases.len());
        // The evidence names the fileop suite and its date.
        assert!(r.evidence.contains("tests/conformance_fileop_macos.rs"));
        assert!(r.evidence.contains("2026-10-03"));
    }

    #[test]
    fn the_linux_row_stays_uncommitted_until_slf() {
        // The committed matrix has no Linux row yet: S-Le carries the row
        // only behind the test/feature gate, and require() on Linux must
        // not pass until S-Lf observes the row green on a real kernel.
        assert!(row(BackendKind::Linux, "linux").is_none());
        // The gated row covers the whole exit set at the default tier's
        // honest bars, and is the one linux_row_uncommitted hands out.
        let r = linux_row_uncommitted().unwrap();
        assert_eq!(r.id, "linux-landlock-seccomp-nons-v1");
        assert!(missing(r.cases, H2_EXIT_CASES).is_empty());
        assert_eq!(r.network, NetworkMechanism::LinuxLandlockSeccomp);
        assert_eq!(r.kill_domain, KillDomain::SubreaperSweep);
        assert_eq!(r.memory, MemoryGuard::RlimitAddressSpace);
        assert_eq!(r.processes, ProcessGuard::RlimitNprocPerUser);
        assert_eq!(r.os, "linux");
        assert_eq!(r.backend, BackendKind::Linux);
    }

    #[test]
    fn the_netns_row_covers_the_exit_set_and_the_netns_port_subset() {
        // The gated namespace-tier row carries the whole exit set ...
        let r = linux_netns_row_uncommitted().unwrap();
        assert_eq!(r.id, "linux-netns-pidns-v1");
        assert!(missing(r.cases, H2_EXIT_CASES).is_empty());
        // ... plus exactly the netns-port subset (not the wildcard pair):
        // the row is the exit set + the subset, nothing more.
        assert!(missing(r.cases, PORTS_CASES_NETNS).is_empty());
        assert_eq!(r.cases.len(), H2_EXIT_CASES.len() + PORTS_CASES_NETNS.len());
        // The wildcard pair is absent with the written reason, so the row
        // is NOT a full PORTS_CASES row.
        let short = missing(r.cases, PORTS_CASES);
        assert_eq!(
            short,
            vec![Case::PortsWildcardNoLan, Case::PortsWildcardLan]
        );
        assert_eq!(r.network, NetworkMechanism::LinuxNetNamespace);
        assert_eq!(r.kill_domain, KillDomain::LinuxPidNamespace);
        assert_eq!(r.memory, MemoryGuard::RlimitAddressSpace);
        assert_eq!(r.processes, ProcessGuard::RlimitNprocPerUser);
        assert_eq!(r.os, "linux");
        assert_eq!(r.backend, BackendKind::Linux);
        assert_eq!(Case::PortsBindGranted.id(), "ports-bind-granted");
        assert_eq!(Case::PortsUdp.id(), "ports-udp");
    }

    /// The covers() gate behind "ports are refused on the default tier"
    /// (§1 ports row): a default-tier witness covers none of the port
    /// cases, so `Network::Loopback` is refused with
    /// `SpecError::Unsupported` before any process is spawned. Runs on
    /// every OS: the witness is minted from the static committed row
    /// (pure data), no live probe involved.
    #[test]
    fn default_tier_witness_refuses_loopback_ports() {
        let row = row(BackendKind::Seatbelt, "macos").unwrap();
        let ev = Conformed::mint(row, harness_core::sha256(b"gate-test"));
        assert_eq!(ev.network(), NetworkMechanism::SeatbeltDenyAll);
        let refused = ev
            .covers(PORTS_CASES)
            .expect_err("default tier must refuse ports");
        assert_eq!(refused, PORTS_CASES.to_vec());
        // The namespace-tier witness is the only one that lifts the
        // refusal, and even it keeps the wildcard pair refused.
        let netns = linux_netns_row_uncommitted().unwrap();
        let ev_netns = Conformed::mint(netns, harness_core::sha256(b"gate-test"));
        assert_eq!(ev_netns.network(), NetworkMechanism::LinuxNetNamespace);
        assert!(ev_netns.covers(PORTS_CASES_NETNS).is_ok());
        let still_refused = ev_netns
            .covers(PORTS_CASES)
            .expect_err("wildcard pair stays off the netns row");
        assert_eq!(
            still_refused,
            vec![Case::PortsWildcardNoLan, Case::PortsWildcardLan]
        );
        // The default Linux tier's row refuses every port case too.
        let default_linux = linux_row_uncommitted().unwrap();
        let ev_default = Conformed::mint(default_linux, harness_core::sha256(b"gate-test"));
        assert_eq!(
            ev_default.covers(PORTS_CASES).unwrap_err(),
            PORTS_CASES.to_vec()
        );
    }

    #[test]
    fn the_linux_escape_cases_have_stable_ids_and_are_not_yet_on_any_row() {
        // The corpus ids are stable API (the witness and journal carry
        // them); spell them out so a rename cannot slip through.
        let ids: Vec<&str> = LINUX_ESCAPE_CASES.iter().map(|c| c.id()).collect();
        assert_eq!(
            ids,
            vec![
                "linux-openat2",
                "linux-proc-self-mem",
                "linux-fd-inherit",
                "linux-ld-preload",
                "linux-setuid",
                "linux-memfd-exec",
                "linux-abstract-unix",
                "linux-ptrace-sibling",
                "linux-fork-bomb-pgroup",
                "linux-dev-shm-tmpfs",
            ]
        );
        // §12 discipline: no row carries them yet — not the committed
        // macOS row, not the gated Linux probe row, and none of the
        // named case sets — so `require()` cannot pass on their account
        // until S-Lg's tests pass on a real kernel and a later slice
        // commits them.
        for c in LINUX_ESCAPE_CASES {
            let mac = row(BackendKind::Seatbelt, "macos").unwrap();
            assert!(
                !mac.cases.contains(c),
                "{} must not be on the macOS row",
                c.id()
            );
            if let Some(r) = linux_row_uncommitted() {
                assert!(
                    !r.cases.contains(c),
                    "{} must not be on the Linux probe row yet",
                    c.id()
                );
            }
            assert!(!H2_EXIT_CASES.contains(c));
            assert!(!AIRLOCK_CASES.contains(c));
            assert!(!PORTS_CASES.contains(c));
        }
    }
}
