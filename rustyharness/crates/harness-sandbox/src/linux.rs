//! The Linux backend: designed to the same [`Backend`] trait, not built in
//! H2a. It never mints a witness.
//!
//! The mechanism is owner decision D29, still open. The design's first
//! attempt (§6.3: user, mount, net and pid namespaces plus Landlock and
//! seccomp) does not work on stock Ubuntu 24.04, where AppArmor refuses
//! unprivileged user namespaces; the likely default is the namespace-less
//! set of rustysuite AQ-208 (Landlock ABI 4 for files and TCP, seccomp
//! denying `socket()` families and namespace creation, a systemd user scope
//! or cgroup for the tree kill), with a network namespace as an opt-in
//! tier. So nothing here assumes namespaces: [`probe`](Backend::probe)
//! MEASURES what the host offers, read-only, and refuses with those facts
//! (fail closed per host capability). Every probe input is a small file
//! under `/proc` or `/sys`, read bounded; a missing file is recorded as
//! absent, never guessed. Whether the measured primitives suffice is the
//! fail-closed decision of `harness-sandbox-linux` (design §6.7, slice
//! S-La), the workspace's one named `unsafe` crate, pulled in only on
//! `target_os = "linux"`; this crate itself stays `#![forbid(unsafe_code)]`.

use crate::{
    Backend, BackendKind, ConfinedChild, ConfinedSpec, Conformed, SpawnError, Unavailable,
    UnavailableReason,
};

/// What a Linux host offers for confinement, as measured.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostFacts {
    /// `landlock` is in `/sys/kernel/security/lsm`.
    pub landlock_lsm: Option<bool>,
    /// `/proc/sys/kernel/apparmor_restrict_unprivileged_userns`.
    pub apparmor_restricts_userns: Option<bool>,
    /// `/proc/sys/kernel/unprivileged_userns_clone` (Debian-family).
    pub userns_clone: Option<bool>,
    /// `/proc/sys/user/max_user_namespaces`.
    pub max_user_namespaces: Option<u64>,
    /// cgroup v2 unified hierarchy (`/sys/fs/cgroup/cgroup.controllers`).
    pub cgroup_v2: Option<bool>,
    /// `kill` is in `/proc/sys/kernel/seccomp/actions_avail`.
    pub seccomp_kill: Option<bool>,
}

impl HostFacts {
    /// Build from the raw file contents (`None` = file absent or unreadable).
    pub fn from_sources(
        lsm: Option<&str>,
        apparmor_userns: Option<&str>,
        userns_clone: Option<&str>,
        max_userns: Option<&str>,
        cgroup_controllers: Option<&str>,
        seccomp_actions: Option<&str>,
    ) -> Self {
        let flag = |s: Option<&str>| {
            s.and_then(|t| match t.trim() {
                "0" => Some(false),
                "1" => Some(true),
                _ => None,
            })
        };
        HostFacts {
            landlock_lsm: lsm.map(|t| t.trim().split(',').any(|m| m == "landlock")),
            apparmor_restricts_userns: flag(apparmor_userns),
            userns_clone: flag(userns_clone),
            max_user_namespaces: max_userns.and_then(|t| t.trim().parse().ok()),
            cgroup_v2: Some(cgroup_controllers.is_some()),
            seccomp_kill: seccomp_actions.map(|t| {
                t.split_whitespace()
                    .any(|a| a == "kill" || a == "kill_process")
            }),
        }
    }

    /// Whether unprivileged user namespaces look usable (the opt-in tier).
    pub fn userns_usable(&self) -> Option<bool> {
        if self.apparmor_restricts_userns == Some(true)
            || self.userns_clone == Some(false)
            || self.max_user_namespaces == Some(0)
        {
            return Some(false);
        }
        self.max_user_namespaces.map(|n| n > 0)
    }

    /// One line for the refusal message and the journal.
    pub fn summary(&self) -> String {
        let s = |v: Option<bool>| match v {
            Some(true) => "yes",
            Some(false) => "no",
            None => "unknown",
        };
        format!(
            "landlock={} userns={} cgroup_v2={} seccomp_kill={}",
            s(self.landlock_lsm),
            s(self.userns_usable()),
            s(self.cgroup_v2),
            s(self.seccomp_kill)
        )
    }
}

/// The Linux backend (facts only in H2a).
#[derive(Debug, Clone, Copy, Default)]
pub struct Linux;

#[cfg(target_os = "linux")]
fn read_small(path: &str) -> Option<String> {
    use std::io::Read;
    let f = std::fs::File::open(path).ok()?;
    let mut s = String::new();
    f.take(64 * 1024).read_to_string(&mut s).ok()?;
    Some(s)
}

/// Measure this host (Linux only; elsewhere every fact is unknown).
pub fn host_facts() -> HostFacts {
    #[cfg(target_os = "linux")]
    {
        HostFacts::from_sources(
            read_small("/sys/kernel/security/lsm").as_deref(),
            read_small("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref(),
            read_small("/proc/sys/kernel/unprivileged_userns_clone").as_deref(),
            read_small("/proc/sys/user/max_user_namespaces").as_deref(),
            read_small("/sys/fs/cgroup/cgroup.controllers").as_deref(),
            read_small("/proc/sys/kernel/seccomp/actions_avail").as_deref(),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        HostFacts::default()
    }
}

/// The refusal a Linux probe returns, given which confinement primitive is
/// missing (the decision itself lives in `harness-sandbox-linux`).
///
/// With a named missing primitive the reason is
/// [`UnavailableReason::PrimitiveMissing`]; with `None` — every primitive
/// present — there is still no committed matrix row (design §3.3), so the
/// honest reason is [`UnavailableReason::MatrixRowMissing`]. Either way the
/// probe refuses: this function never returns [`UnavailableReason::NotBuilt`].
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_refusal(missing_primitive: Option<&'static str>) -> Unavailable {
    let reason = match missing_primitive {
        Some(p) => UnavailableReason::PrimitiveMissing(p),
        None => UnavailableReason::MatrixRowMissing,
    };
    Unavailable {
        backend: Some(BackendKind::Linux),
        reason,
    }
}

impl Backend for Linux {
    fn kind(&self) -> BackendKind {
        BackendKind::Linux
    }

    fn probe(&self) -> Result<Conformed, Unavailable> {
        #[cfg(target_os = "linux")]
        {
            let facts = host_facts();
            let primitives = harness_sandbox_linux::Primitives {
                landlock_lsm: facts.landlock_lsm,
                seccomp_kill: facts.seccomp_kill,
            };
            Err(linux_refusal(
                harness_sandbox_linux::LinuxBackend::missing_primitive(&primitives),
            ))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Unavailable {
                backend: None,
                reason: UnavailableReason::NoBackendForOs,
            })
        }
    }

    fn spawn(&self, _spec: &ConfinedSpec, ev: &Conformed) -> Result<ConfinedChild, SpawnError> {
        if ev.backend() != BackendKind::Linux {
            return Err(SpawnError::WrongWitness);
        }
        // Unreachable: no Linux witness can be minted (no matrix row, and
        // probe() always refuses).
        Err(SpawnError::Io("the Linux backend is not built".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ubuntu_2404_shape_is_userns_blocked() {
        let f = HostFacts::from_sources(
            Some("lockdown,capability,landlock,yama,apparmor"),
            Some("1\n"),
            None,
            Some("63446\n"),
            Some("cpuset cpu io memory pids"),
            Some("kill_process kill_thread trap errno user_notif trace log allow"),
        );
        assert_eq!(f.landlock_lsm, Some(true));
        assert_eq!(f.userns_usable(), Some(false));
        assert_eq!(f.seccomp_kill, Some(true));
        assert_eq!(
            f.summary(),
            "landlock=yes userns=no cgroup_v2=yes seccomp_kill=yes"
        );
    }

    #[test]
    fn missing_sources_are_unknown_not_guessed() {
        let f = HostFacts::from_sources(None, None, None, None, None, None);
        assert_eq!(f.landlock_lsm, None);
        assert_eq!(f.userns_usable(), None);
        assert_eq!(f.cgroup_v2, Some(false));
    }

    #[test]
    fn the_linux_backend_never_mints() {
        assert!(Linux.probe().is_err());
    }

    #[test]
    fn probe_still_refuses_without_primitives() {
        // The delegation shape: a missing primitive is NAMED (never NotBuilt)
        // and the refusal points at the Linux backend.
        let r = linux_refusal(Some("landlock"));
        assert_eq!(r.backend, Some(BackendKind::Linux));
        assert_eq!(r.reason, UnavailableReason::PrimitiveMissing("landlock"));
        let r = linux_refusal(Some("seccomp-kill"));
        assert_eq!(r.backend, Some(BackendKind::Linux));
        assert_eq!(
            r.reason,
            UnavailableReason::PrimitiveMissing("seccomp-kill")
        );
    }

    #[test]
    fn every_primitive_present_still_refuses_without_a_matrix_row() {
        // No Linux matrix row is committed (design §3.3), so even a full
        // primitive set refuses — honestly, as MatrixRowMissing.
        let r = linux_refusal(None);
        assert_eq!(r.backend, Some(BackendKind::Linux));
        assert_eq!(r.reason, UnavailableReason::MatrixRowMissing);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_delegates_to_the_linux_crate() {
        // On a Linux host the probe refuses via the new crate's decision:
        // PrimitiveMissing (some fact unknown or absent) or, on a host with
        // every primitive present, MatrixRowMissing. Never NotBuilt, never Ok.
        let err = Linux.probe().unwrap_err();
        assert_eq!(err.backend, Some(BackendKind::Linux));
        assert!(matches!(
            err.reason,
            UnavailableReason::PrimitiveMissing(_) | UnavailableReason::MatrixRowMissing
        ));
    }
}
