//! rustyharness execution confinement, and the host probes the run needs.
//!
//! The rule: **no containment, no execution** (INV-6). When this platform
//! cannot establish the confinement a policy asks for, [`require`] refuses;
//! there is no "run it anyway and record that it was unsandboxed" path.
//!
//! **Confinement (design §6, slice H2a).**
//! - [`Backend`] is the fail-closed trait of §6.1: `probe()` is the only
//!   way to obtain a [`Conformed`] witness, and `spawn()` takes one.
//! - A witness needs BOTH a committed matrix row ([`conformance::MATRIX`])
//!   AND a live self-probe that passes on this host. It records the
//!   backend, the row, the case set the row covers, the network mechanism,
//!   the kill domain and a digest of what the probe observed.
//! - [`require`] is the production entry point: it demands the full H2
//!   exit case set ([`conformance::H2_EXIT_CASES`]) and checks the row
//!   BEFORE starting anything. In H2a no row is complete, so it refuses on
//!   every platform, naming what is missing; the conformance tests use a
//!   backend's `probe()` directly.
//! - macOS: [`seatbelt::Seatbelt`], `sandbox-exec` with a generated
//!   deny-default profile ([`profile`]) and a domain stub that sweeps every
//!   process of the sandbox instance when a call ends
//!   (`confine_spawn`). Linux: [`linux::Linux`] reads the host's
//!   confinement facts and refuses (the mechanism is owner decision D29).
//!   Windows: unavailable (spike S-W1).
//!
//! **Host probes**, here because they measure the host: filesystem
//! locality ([`locality`], §2.8) and the environment sample
//! ([`environment`], §7.1). On macOS those run the three fixed read-only
//! queries of the private `capture` module (§4.5, INV-23).

#![forbid(unsafe_code)]
// The panic-set lints ratchet production code; unit tests may assert loosely.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

// The bounded spawn the macOS probes use (tested wherever /bin/sh exists).
#[cfg(any(target_os = "macos", all(test, unix)))]
mod capture;
// The confined spawn (macOS).
#[cfg(target_os = "macos")]
mod confine_spawn;
pub mod conformance;
pub mod environment;
pub mod linux;
pub mod locality;
pub mod profile;
#[cfg(target_os = "macos")]
pub mod seatbelt;
pub mod spec;

use conformance::{Case, MatrixRow};
pub use spec::{
    ChildStatus, ConfinedExit, ConfinedSpec, DomainCleanup, Limits, Network, SpecError,
};

/// A confinement backend family. Mechanism-agnostic on purpose: which
/// primitives a backend uses is recorded in [`NetworkMechanism`] and
/// [`KillDomain`], not in its name (the Linux mechanism is still open, D29).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// macOS `sandbox-exec` (Seatbelt).
    Seatbelt,
    /// Linux (mechanism per host: see [`linux`]).
    Linux,
    /// Windows AppContainer + Job Object.
    AppContainer,
}

/// How a backend keeps a child off the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMechanism {
    /// Seatbelt `(deny network*)` under `(deny default)`: no connect, bind,
    /// listen or unix-socket connect.
    SeatbeltDenyAll,
    /// Linux: an empty network namespace (opt-in tier where userns works).
    LinuxNetNamespace,
    /// Linux: Landlock TCP rules plus a seccomp `socket()` filter.
    LinuxLandlockSeccomp,
    /// Windows: an AppContainer with no network capability.
    AppContainerNoCapability,
}

/// How a backend makes sure nothing a call started outlives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillDomain {
    /// macOS: the stub's in-sandbox sweep (kernel-filtered to the sandbox
    /// instance), with a process-group kill from outside as the fallback.
    GroupAndSandboxSweep,
    /// Linux: a PID namespace.
    LinuxPidNamespace,
    /// Linux: a systemd user scope / cgroup kill.
    LinuxCgroup,
    /// Windows: a Job Object with kill-on-close.
    JobObject,
}

/// How a backend bounds a call's memory (FT-6). The name records the exact
/// bar met, so a witness and the journal say `rlimit-address-space`, not
/// merely "bounded".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryGuard {
    /// macOS: per-process `RLIMIT_AS`, set to the program's own virtual size
    /// plus the spec's budget, inherited across fork and exec (H2c;
    /// kernel-enforced, measured). Bounds each process, not the tree's sum.
    RlimitAddressSpace,
    /// Linux: cgroup v2 `memory.max` (a whole-tree bound).
    LinuxCgroupMax,
    /// Windows: a Job Object memory limit.
    JobObjectMemory,
}

/// How a backend bounds a call's process count (FT-5). The name records the
/// exact bar, e.g. `member-count-watchdog`, not merely "bounded".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessGuard {
    /// macOS: the in-sandbox stub counts its instance's members and sweeps
    /// when they exceed the cap (H2c). A weaker bar than a kernel limit:
    /// `RLIMIT_NPROC` is per user on macOS, so it cannot bound one sandbox;
    /// it bounds *sustained* members, with the per-user ceiling as a backstop.
    MemberCountWatchdog,
    /// Linux: a PID namespace plus cgroup v2 `pids.max` (a hard bound).
    LinuxPidsMax,
    /// Windows: a Job Object active-process limit.
    JobObjectActiveProcess,
}

/// The journal names of the witness's parts (H2d): the header records
/// which backend, row and bars a run's commands ran under, in these words.
macro_rules! journal_names {
    ($ty:ident { $($v:ident => $n:literal),+ $(,)? }) => {
        impl $ty {
            /// Every variant.
            pub const ALL: &'static [$ty] = &[$($ty::$v),+];
            /// The name the journal header records.
            pub fn name(self) -> &'static str {
                match self {
                    $($ty::$v => $n),+
                }
            }
            /// The variant a recorded name names.
            pub fn from_name(s: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|v| v.name() == s)
            }
        }
    };
}

journal_names!(BackendKind {
    Seatbelt => "seatbelt",
    Linux => "linux",
    AppContainer => "app-container",
});
journal_names!(NetworkMechanism {
    SeatbeltDenyAll => "seatbelt-deny-all",
    LinuxNetNamespace => "linux-net-namespace",
    LinuxLandlockSeccomp => "linux-landlock-seccomp",
    AppContainerNoCapability => "app-container-no-capability",
});
journal_names!(KillDomain {
    GroupAndSandboxSweep => "group-and-sandbox-sweep",
    LinuxPidNamespace => "linux-pid-namespace",
    LinuxCgroup => "linux-cgroup",
    JobObject => "job-object",
});
journal_names!(MemoryGuard {
    RlimitAddressSpace => "rlimit-address-space",
    LinuxCgroupMax => "linux-cgroup-max",
    JobObjectMemory => "job-object-memory",
});
journal_names!(ProcessGuard {
    MemberCountWatchdog => "member-count-watchdog",
    LinuxPidsMax => "linux-pids-max",
    JobObjectActiveProcess => "job-object-active-process",
});

/// The evidence that a backend passed conformance on this host (§6.1). Its
/// fields are private and it has no public constructor: only a backend's
/// `probe()` makes one (INV-15).
///
/// ```compile_fail,E0451
/// let c = harness_sandbox::Conformed {
///     backend: harness_sandbox::BackendKind::Seatbelt,
///     matrix_row: "forged",
///     cases: &[],
///     network: harness_sandbox::NetworkMechanism::SeatbeltDenyAll,
///     kill_domain: harness_sandbox::KillDomain::GroupAndSandboxSweep,
///     memory: harness_sandbox::MemoryGuard::RlimitAddressSpace,
///     processes: harness_sandbox::ProcessGuard::MemberCountWatchdog,
///     probe_digest: harness_core::sha256(b""),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conformed {
    backend: BackendKind,
    matrix_row: &'static str,
    cases: &'static [Case],
    network: NetworkMechanism,
    kill_domain: KillDomain,
    memory: MemoryGuard,
    processes: ProcessGuard,
    probe_digest: harness_core::Digest,
}

impl Conformed {
    /// Mint a witness. Crate-private: called only by a backend's `probe()`
    /// after its row was found and its live probe passed.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn mint(row: &'static MatrixRow, probe_digest: harness_core::Digest) -> Self {
        Conformed {
            backend: row.backend,
            matrix_row: row.id,
            cases: row.cases,
            network: row.network,
            kill_domain: row.kill_domain,
            memory: row.memory,
            processes: row.processes,
            probe_digest,
        }
    }
    /// The backend that minted it.
    pub fn backend(&self) -> BackendKind {
        self.backend
    }
    /// The matrix row.
    pub fn matrix_row(&self) -> &'static str {
        self.matrix_row
    }
    /// The cases the row covers.
    pub fn cases(&self) -> &'static [Case] {
        self.cases
    }
    /// The network mechanism.
    pub fn network(&self) -> NetworkMechanism {
        self.network
    }
    /// The kill domain.
    pub fn kill_domain(&self) -> KillDomain {
        self.kill_domain
    }
    /// The memory guard (FT-6): the exact bar met.
    pub fn memory(&self) -> MemoryGuard {
        self.memory
    }
    /// The process guard (FT-5): the exact bar met.
    pub fn processes(&self) -> ProcessGuard {
        self.processes
    }
    /// SHA-256 of the live probe's observations.
    pub fn probe_digest(&self) -> &harness_core::Digest {
        &self.probe_digest
    }
    /// Refuse unless every case in `required` is covered.
    pub fn covers(&self, required: &[Case]) -> Result<(), Vec<Case>> {
        let m = conformance::missing(self.cases, required);
        if m.is_empty() {
            Ok(())
        } else {
            Err(m)
        }
    }
}

/// Why a backend is unavailable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnavailableReason {
    /// No backend exists for this OS.
    NoBackendForOs,
    /// The backend has no committed matrix row.
    MatrixRowMissing,
    /// The row lacks cases the caller requires.
    MatrixRowIncomplete {
        /// The missing cases.
        missing: Vec<Case>,
    },
    /// A primitive the backend needs is absent (e.g. `sandbox-exec`).
    PrimitiveMissing(&'static str),
    /// A live self-probe was not refused (or could not be observed).
    LiveProbeFailed {
        /// The probe.
        probe: &'static str,
        /// What was seen.
        observed: String,
    },
    /// The backend is designed but not built; the host facts are recorded.
    NotBuilt {
        /// What the host offers, as measured.
        facts: String,
    },
    /// An I/O error while probing.
    Io(String),
}

/// How an unavailability maps onto the outcome vocabulary (§6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailableKind {
    /// `Indeterminate { UnsupportedOs }`: no backend for this platform.
    UnsupportedOs,
    /// `Indeterminate { CouldNotRun }`: a backend exists but not here/now.
    CouldNotRun,
}

/// A backend cannot confine on this host.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason}; fix: {}", self.fix())]
pub struct Unavailable {
    /// The backend, if one exists for this OS.
    pub backend: Option<BackendKind>,
    /// Why.
    pub reason: UnavailableReason,
}

impl std::fmt::Display for UnavailableReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnavailableReason::NoBackendForOs => write!(f, "no confinement backend for this OS"),
            UnavailableReason::MatrixRowMissing => {
                write!(f, "no conformance matrix row for this backend")
            }
            UnavailableReason::MatrixRowIncomplete { missing } => {
                let ids: Vec<&str> = missing.iter().map(|c| c.id()).collect();
                write!(
                    f,
                    "the backend has not passed the full hostile-task suite (missing {})",
                    ids.join(", ")
                )
            }
            UnavailableReason::PrimitiveMissing(p) => write!(f, "{p} is missing"),
            UnavailableReason::LiveProbeFailed { probe, observed } => {
                write!(f, "live probe {probe} was not refused ({observed})")
            }
            UnavailableReason::NotBuilt { facts } => {
                write!(f, "backend not built yet (host: {facts})")
            }
            UnavailableReason::Io(e) => write!(f, "probe failed: {e}"),
        }
    }
}

impl Unavailable {
    /// The outcome mapping of §6.1.
    pub fn kind(&self) -> UnavailableKind {
        match self.reason {
            UnavailableReason::NoBackendForOs => UnavailableKind::UnsupportedOs,
            _ => UnavailableKind::CouldNotRun,
        }
    }
    /// A plain-language fix.
    pub fn fix(&self) -> &'static str {
        match self.reason {
            UnavailableReason::NoBackendForOs => {
                "run on macOS or Linux; this OS gets read-only sessions only"
            }
            UnavailableReason::MatrixRowMissing | UnavailableReason::MatrixRowIncomplete { .. } => {
                "none on this host: this harness version does not execute here yet (design §9, H2)"
            }
            UnavailableReason::PrimitiveMissing(_) => {
                "the OS no longer ships a primitive this backend needs; execution stays off (Q8)"
            }
            UnavailableReason::LiveProbeFailed { .. } => {
                "this host weakens the sandbox (a disabled feature or an enclosing sandbox); run where the probe passes"
            }
            UnavailableReason::NotBuilt { .. } => "none yet: the backend is not built (H2)",
            UnavailableReason::Io(_) => "check the temporary directory is writable and retry",
        }
    }
}

/// Why a spawn was refused. Nothing ran.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpawnError {
    /// The spec is refused.
    #[error("spec refused: {0}")]
    Spec(#[from] SpecError),
    /// The witness was minted by another backend.
    #[error("the witness belongs to another backend")]
    WrongWitness,
    /// The OS refused to start the sandbox.
    #[error("could not start the sandbox: {0}")]
    Io(String),
}

/// A running confined call.
pub struct ConfinedChild {
    #[cfg(target_os = "macos")]
    inner: confine_spawn::Running,
    #[cfg(not(target_os = "macos"))]
    inner: std::convert::Infallible,
}

impl std::fmt::Debug for ConfinedChild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConfinedChild")
    }
}

impl ConfinedChild {
    /// Wait for the call to end (exit or wall clock), empty its kill domain
    /// and return what it left.
    pub fn wait(self) -> ConfinedExit {
        #[cfg(target_os = "macos")]
        {
            self.inner.wait()
        }
        #[cfg(not(target_os = "macos"))]
        {
            match self.inner {}
        }
    }
}

/// The fail-closed backend trait (§6.1).
pub trait Backend {
    /// Which backend this is.
    fn kind(&self) -> BackendKind;
    /// Establish that this backend confines on this host: its matrix row
    /// exists and its live self-probe passes. The only mint of [`Conformed`].
    fn probe(&self) -> Result<Conformed, Unavailable>;
    /// Start `spec` confined. Needs this backend's witness.
    fn spawn(&self, spec: &ConfinedSpec, ev: &Conformed) -> Result<ConfinedChild, SpawnError>;
}

/// What confinement this platform can establish (for reporting).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Containment {
    /// A backend passed; here is its witness.
    Available(Conformed),
    /// No conforming backend; the reason is recorded, never ignored.
    Unavailable(Unavailable),
}

/// Returned when execution is refused because confinement is unavailable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("refusing to execute: no confinement on this platform ({0})")]
pub struct Refused(pub Unavailable);

/// The confinement this platform can establish, at the production bar.
pub fn available() -> Containment {
    match require() {
        Ok(c) => Containment::Available(c),
        Err(Refused(u)) => Containment::Unavailable(u),
    }
}

/// Obtain a witness at the production bar or refuse. Every execution an
/// agent or a check can ask for goes through here. The committed matrix
/// row is checked against [`conformance::H2_EXIT_CASES`] first, so a
/// partial row refuses without starting any process; only a complete row
/// leads to the live probe. (The harness's own three host queries in
/// `capture` are fixed programs with fixed arguments, §4.5.)
pub fn require() -> Result<Conformed, Refused> {
    let (kind, os) = match std::env::consts::OS {
        "macos" => (BackendKind::Seatbelt, "macos"),
        "linux" => (BackendKind::Linux, "linux"),
        "windows" => (BackendKind::AppContainer, "windows"),
        _ => {
            return Err(Refused(Unavailable {
                backend: None,
                reason: UnavailableReason::NoBackendForOs,
            }))
        }
    };
    let refuse = |reason| {
        Refused(Unavailable {
            backend: Some(kind),
            reason,
        })
    };
    let Some(row) = conformance::row(kind, os) else {
        return Err(refuse(UnavailableReason::MatrixRowMissing));
    };
    let missing = conformance::missing(row.cases, conformance::H2_EXIT_CASES);
    if !missing.is_empty() {
        return Err(refuse(UnavailableReason::MatrixRowIncomplete { missing }));
    }
    platform_probe().map_err(Refused)
}

#[cfg(target_os = "macos")]
fn platform_probe() -> Result<Conformed, Unavailable> {
    seatbelt::Seatbelt::new().probe()
}

#[cfg(not(target_os = "macos"))]
fn platform_probe() -> Result<Conformed, Unavailable> {
    linux::Linux.probe()
}

/// Where a run gets its confinement (H2d): [`require`] and the platform
/// backend's spawn behind one seam, so a caller can be handed one that
/// refuses (the refusal path's tests; a run that never executes). The seam
/// cannot run anything unconfined: nothing outside this crate can mint a
/// [`Conformed`] or construct a [`ConfinedChild`], so an implementation
/// elsewhere can only refuse or forward to this crate.
pub trait Confinement {
    /// A witness at the production bar, or the refusal ([`require`]).
    fn require(&self) -> Result<Conformed, Refused>;
    /// Start `spec` confined, under the witness `ev`.
    fn spawn(&self, spec: &ConfinedSpec, ev: &Conformed) -> Result<ConfinedChild, SpawnError>;
}

/// The production confinement: [`require`], and the backend of this
/// platform for every spawn.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemConfinement;

impl Confinement for SystemConfinement {
    fn require(&self) -> Result<Conformed, Refused> {
        require()
    }

    fn spawn(&self, spec: &ConfinedSpec, ev: &Conformed) -> Result<ConfinedChild, SpawnError> {
        #[cfg(target_os = "macos")]
        {
            seatbelt::Seatbelt::new().spawn(spec, ev)
        }
        #[cfg(not(target_os = "macos"))]
        {
            linux::Linux.spawn(spec, ev)
        }
    }
}

/// A confinement that refuses: no backend, so nothing can execute. For
/// callers that never grant execution, and for the refusal path's tests.
#[derive(Debug, Clone)]
pub struct NoConfinement(pub Unavailable);

impl Confinement for NoConfinement {
    fn require(&self) -> Result<Conformed, Refused> {
        Err(Refused(self.0.clone()))
    }

    fn spawn(&self, _spec: &ConfinedSpec, _ev: &Conformed) -> Result<ConfinedChild, SpawnError> {
        Err(SpawnError::Io("no confinement is available".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_now_passes_on_macos_naming_its_guards_and_refuses_elsewhere() {
        if cfg!(target_os = "macos") {
            // H2c: the row covers the whole exit set, so require() runs the
            // live probe and mints a witness that names the guards met.
            let c = require().expect("macOS require() should pass after H2c");
            assert_eq!(c.backend(), BackendKind::Seatbelt);
            assert_eq!(c.memory(), MemoryGuard::RlimitAddressSpace);
            assert_eq!(c.processes(), ProcessGuard::MemberCountWatchdog);
            assert!(matches!(available(), Containment::Available(_)));
        } else {
            let e = require().unwrap_err();
            assert!(matches!(available(), Containment::Unavailable(_)));
            assert!(
                e.to_string().contains("no conformance matrix row")
                    || e.to_string().contains("no confinement backend"),
                "{e}"
            );
            assert_eq!(e.0.kind(), UnavailableKind::CouldNotRun);
        }
    }
}
