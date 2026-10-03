//! The Linux confinement primitives, kept apart so `unsafe` has exactly one
//! home (design §6.7; docs/slices/S-L-linux-sandbox.md).
//!
//! INV-6 is **no containment, no execution**: this crate never contains
//! anything and never starts anything. It answers one fail-closed question —
//! given what a Linux host measured, is every confinement primitive the
//! default tier needs PRESENT? An unknown fact is not a present fact, so it
//! counts as missing. `harness_sandbox::linux::Linux::probe()` delegates the
//! refusal decision here on `target_os = "linux"`; on every other target the
//! crate is not even pulled in (the dependency is target-gated).
//!
//! The crate is the workspace's single named `unsafe` exception
//! (`#![allow(unsafe_code)]`, checked first thing by scripts/ci/purity.sh
//! §5), because wiring the Landlock and seccomp primitives of the default
//! tier (Landlock ABI 4 for files and TCP, seccomp denying `socket()`
//! families and namespace creation, and the process-group `kill` for the
//! tree kill) needs FFI. S-La commits the crate with the decision logic
//! only — no FFI site yet, so the purity.sh unsafe-site ratchet stands at
//! **zero** and rises by review, one `// SAFETY:` comment per site, when
//! S-Lb/S-Lc land the primitives behind the reviewed allowlist (landlock,
//! rustix on its libc backend, enumflags2; see deny.toml and the purity.sh
//! registry list).
//!
//! Since S-Lb the crate also builds the Landlock ruleset itself
//! ([`landlock_rules`]): the portable rule planner compiles (and is
//! unit-tested) on every OS; the syscall side — ruleset creation from
//! `PathFd` handles and `apply()` — is Linux-only and refuses, never
//! degrades, when the kernel's Landlock ABI is below what the grants need.

#![allow(unsafe_code)]
// The panic-set lints ratchet production code; unit tests may assert loosely.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

/// What the host MEASURED about the confinement primitives of the default
/// tier (read-only probes of `/proc` and `/sys`; a missing file is recorded
/// as [`Option::None`], never guessed).
///
/// `Some(true)` = present, `Some(false)` = measured absent,
/// [`Option::None`] = unknown (the file was absent or unreadable). The
/// fail-closed rule treats unknown as missing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Primitives {
    /// Landlock is in the active LSM list (`/sys/kernel/security/lsm`).
    pub landlock_lsm: Option<bool>,
    /// A `kill` action is available to seccomp
    /// (`/proc/sys/kernel/seccomp/actions_avail`).
    pub seccomp_kill: Option<bool>,
}

/// The Linux backend's primitive decision (the crate's one job).
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxBackend;

pub mod landlock_rules;

impl LinuxBackend {
    /// The FIRST confinement primitive the default tier is missing, in
    /// check order, or [`Option::None`] when every primitive is present.
    ///
    /// Fail closed per host capability (INV-6): a primitive that is
    /// measured absent, or merely unknown, is missing — the caller refuses
    /// and names it. Order: Landlock first (the file plane), then the
    /// seccomp `kill` (the egress and namespace plane).
    pub fn missing_primitive(primitives: &Primitives) -> Option<&'static str> {
        if primitives.landlock_lsm != Some(true) {
            return Some("landlock");
        }
        if primitives.seccomp_kill != Some(true) {
            return Some("seccomp-kill");
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_missing_primitive_is_named_not_guessed() {
        let both_missing = Primitives {
            landlock_lsm: Some(false),
            seccomp_kill: Some(false),
        };
        assert_eq!(
            LinuxBackend::missing_primitive(&both_missing),
            Some("landlock")
        );
        let only_landlock = Primitives {
            landlock_lsm: Some(true),
            seccomp_kill: Some(false),
        };
        assert_eq!(
            LinuxBackend::missing_primitive(&only_landlock),
            Some("seccomp-kill")
        );
    }

    #[test]
    fn an_unknown_fact_is_missing_fail_closed() {
        let unknown = Primitives::default();
        assert_eq!(LinuxBackend::missing_primitive(&unknown), Some("landlock"));
        let landlock_unknown = Primitives {
            landlock_lsm: None,
            seccomp_kill: Some(true),
        };
        assert_eq!(
            LinuxBackend::missing_primitive(&landlock_unknown),
            Some("landlock")
        );
    }

    #[test]
    fn every_primitive_present_is_none() {
        let full = Primitives {
            landlock_lsm: Some(true),
            seccomp_kill: Some(true),
        };
        assert_eq!(LinuxBackend::missing_primitive(&full), None);
    }

    // The slice's target check: the crate must BUILD and DECIDE on a Linux
    // target (it compiles nowhere else, by the target-gated dependency).
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_crate_builds_on_linux_target() {
        let measured = Primitives {
            landlock_lsm: Some(true),
            seccomp_kill: Some(false),
        };
        assert_eq!(
            LinuxBackend::missing_primitive(&measured),
            Some("seccomp-kill")
        );
    }
}
