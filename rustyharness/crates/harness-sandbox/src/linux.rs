//! The Linux backend: designed to the same [`Backend`] trait, not built in
//! H2a. Since S-Le it MINTS a witness — but only after its live self-probe
//! passed on this host (INV-15: the only `Conformed` source for Linux).
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
//!
//! When the primitives are present and the (still uncommitted, S-Lf)
//! matrix row covers the exit set, the probe delegates to
//! `harness-sandbox-linux`'s live canaries (S-Le): children through the
//! real supervisor path, every one of which must be REFUSED. Only a clean
//! observation mints. Load-shaped failures (a spawn that failed, a run
//! that never reported) retry on the H2f backoffs; a canary that was not
//! refused is final.

use crate::conformance::MatrixRow;
use crate::{
    Backend, BackendKind, ConfinedChild, ConfinedSpec, Conformed, LinuxWitness, SeccompAction,
    SpawnError, Unavailable, UnavailableReason,
};

// The spawn path exists only where the supervisor does; elsewhere the
// backend refuses with [`UnavailableReason::NoBackendForOs`] and nothing
// here compiles in.
#[cfg(target_os = "linux")]
use crate::ring::{Chunk, Mode, Stream, StreamTotals};
#[cfg(target_os = "linux")]
use crate::spec::{self, Context, Enforceable};
#[cfg(target_os = "linux")]
use crate::spec::{ChildStatus, ConfinedExit, DomainCleanup};

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

/// The probe's retry backoffs, in milliseconds (H2f: two load-shaped
/// retries at most; a third failure is final).
#[cfg_attr(not(all(target_os = "linux", not(test))), allow(dead_code))]
const PROBE_BACKOFFS_MS: &[u64] = &[250, 1000];

/// The live probe's profile version: part of the observation digest, so a
/// canary-set change cannot pass for an old observation.
#[cfg_attr(not(all(target_os = "linux", not(test))), allow(dead_code))]
const PROBE_PROFILE_VERSION: &str = "rh-linux-probe/1";

/// How many attempts a probe pass took.
#[cfg_attr(not(all(target_os = "linux", not(test))), allow(dead_code))]
struct Attempts {
    count: u32,
}

/// Whether a probe failure is one a loaded machine can cause (H2f): a
/// spawn that failed, or a canary run that timed out or never reported.
/// An escape — a canary that was seen NOT refused — is never load-shaped,
/// and a guard that did not hold is never retried away.
#[cfg_attr(not(all(target_os = "linux", not(test))), allow(dead_code))]
fn load_shaped(u: &Unavailable) -> bool {
    let UnavailableReason::LiveProbeFailed { probe, observed } = &u.reason else {
        return false;
    };
    match *probe {
        "spawn" | "mem-spawn" | "proc-spawn" => true,
        "run" | "mem-applied" | "proc-run" => {
            observed.starts_with("TimedOut") || observed.starts_with("Unknown")
        }
        _ => false,
    }
}

/// Run `attempt` on the H2f backoffs: a load-shaped failure waits for the
/// next backoff and tries again; when the backoffs run out the last error
/// is final. Any other failure is final at once.
#[cfg_attr(not(all(target_os = "linux", not(test))), allow(dead_code))]
fn probe_with_retries(
    mut attempt: impl FnMut() -> Result<String, Unavailable>,
    backoffs_ms: &[u64],
    mut pause: impl FnMut(u64),
) -> Result<(String, Attempts), Unavailable> {
    let mut retries = backoffs_ms.iter();
    let mut count = 1u32;
    loop {
        match attempt() {
            Ok(observed) => return Ok((observed, Attempts { count })),
            Err(e) => {
                if !load_shaped(&e) {
                    return Err(e);
                }
                match retries.next() {
                    Some(&ms) => {
                        pause(ms);
                        count += 1;
                    }
                    None => return Err(e),
                }
            }
        }
    }
}

/// The live probe's digest: profile version, the row it observed for, the
/// observations and the attempt count, so a witness cannot stand for
/// another row or a different number of tries.
#[cfg_attr(not(all(target_os = "linux", not(test))), allow(dead_code))]
fn observations_digest(row_id: &str, observed: &[u8], attempts: u32) -> harness_core::Digest {
    let attempts_line = format!("attempts={attempts} sweep-deadline=3s\n");
    harness_core::sha256_parts(&[
        PROBE_PROFILE_VERSION.as_bytes(),
        b"\n",
        row_id.as_bytes(),
        b"\n",
        observed,
        attempts_line.as_bytes(),
    ])
}

/// The probe proper: clean observations and a prepared row mint a witness
/// carrying the backend detail L-D7 journals. Anything else refuses.
#[cfg_attr(not(all(target_os = "linux", not(test))), allow(dead_code))]
fn probe_with(
    facts: &HostFacts,
    abi: u32,
    row: &'static MatrixRow,
    attempt: impl FnMut() -> Result<String, Unavailable>,
    backoffs_ms: &[u64],
    pause: impl FnMut(u64),
) -> Result<Conformed, Unavailable> {
    let (observed, attempts) = probe_with_retries(attempt, backoffs_ms, pause)?;
    let digest = observations_digest(row.id, observed.as_bytes(), attempts.count);
    let witness = LinuxWitness::new(
        abi,
        SeccompAction::Errno,
        harness_core::sha256(facts.summary().as_bytes()),
    );
    Ok(Conformed::mint_linux(row, digest, witness))
}

/// The live attempt: this process's own binary as the supervisor's helper.
#[cfg(all(target_os = "linux", not(test)))]
fn live_attempt() -> impl FnMut() -> Result<String, Unavailable> {
    || {
        let helper = std::env::current_exe().map_err(|e| Unavailable {
            backend: Some(BackendKind::Linux),
            reason: UnavailableReason::Io(e.to_string()),
        })?;
        harness_sandbox_linux::probe::live_probe(helper.as_os_str())
            .map_err(|f| live_refusal(f.probe, f.observed, f.load_shaped))
    }
}

/// Under the unit-test harness the live probe does not run: the test
/// binary does not dispatch the supervisor's `__confine` helper, so a
/// probe here would only burn its backoffs on a helper that never
/// reports. The honest refusal names that; the real live coverage is the
/// `probe_live` binary (an integration test, not the unit harness).
#[cfg(all(target_os = "linux", test))]
fn live_attempt() -> impl FnMut() -> Result<String, Unavailable> {
    || {
        Err(Unavailable {
            backend: Some(BackendKind::Linux),
            reason: UnavailableReason::LiveProbeFailed {
                probe: "probe",
                observed: "unit-test builds do not run the live probe".into(),
            },
        })
    }
}

/// Map a live-probe refusal onto the witness vocabulary. A spawn refusal
/// that is not load-shaped is the supervisor's unsupported-arch answer: a
/// missing primitive, named.
#[cfg_attr(not(all(target_os = "linux", not(test))), allow(dead_code))]
fn live_refusal(probe: &'static str, observed: String, load_shaped: bool) -> Unavailable {
    let reason = match probe {
        "spawn" if !load_shaped => UnavailableReason::PrimitiveMissing("modelled-arch"),
        _ => UnavailableReason::LiveProbeFailed { probe, observed },
    };
    Unavailable {
        backend: Some(BackendKind::Linux),
        reason,
    }
}

/// The uncommitted Linux row when this build carries it (tests, or the
/// `linux-probe-row` feature); `None` otherwise, so a plain release build
/// still refuses with [`UnavailableReason::MatrixRowMissing`].
#[cfg(any(test, feature = "linux-probe-row"))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_row_gated() -> Option<&'static MatrixRow> {
    crate::conformance::linux_row_uncommitted()
}

/// The release-build twin: the gate is off, there is no row to hand out.
#[cfg(not(any(test, feature = "linux-probe-row")))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_row_gated() -> Option<&'static MatrixRow> {
    None
}

/// A live Linux call: the supervisor's handle plus the spec's output cap,
/// mapped onto this crate's vocabulary exactly as the macOS stub's handle
/// is. Constructed only by [`start`], behind a minted witness.
#[cfg(target_os = "linux")]
pub(crate) struct Child {
    inner: harness_sandbox_linux::supervisor::Running,
    output_bytes: u64,
}

#[cfg(target_os = "linux")]
impl Child {
    pub(crate) fn wait(self) -> ConfinedExit {
        finish(self.inner.wait(), self.output_bytes)
    }

    pub(crate) fn try_status(&mut self) -> Option<ConfinedExit> {
        Some(finish(self.inner.try_status()?, self.output_bytes))
    }

    pub(crate) fn read(&self, stream: Stream, since: u64, cap: usize, mode: Mode) -> Chunk {
        use harness_sandbox_linux::supervisor::{RawMode, RawStream};
        let raw = self.inner.read(
            match stream {
                Stream::Out => RawStream::Out,
                Stream::Err => RawStream::Err,
            },
            since,
            cap,
            match mode {
                Mode::Next => RawMode::Next,
                Mode::Tail => RawMode::Tail,
            },
        );
        Chunk {
            from: raw.from,
            to: raw.to,
            dropped: raw.dropped,
            skipped: raw.skipped,
            bytes: raw.bytes,
        }
    }

    pub(crate) fn totals(&self) -> StreamTotals {
        use harness_core::Digest;
        let t = self.inner.totals();
        StreamTotals {
            out_total: t.out_total,
            out_sha: Digest::from_bytes(t.out_sha),
            err_total: t.err_total,
            err_sha: Digest::from_bytes(t.err_sha),
        }
    }

    pub(crate) fn stop(self) -> ConfinedExit {
        finish(self.inner.stop(), self.output_bytes)
    }
}

/// Map the supervisor's raw exit onto the crate's vocabulary: the wall
/// clock first, then the setup-failure window (the helper's 94..102 exit
/// codes), then the wait status; the sweep's report says whether the kill
/// domain is confirmed. `output_bytes` caps what `stdout`/`stderr` hand
/// back (the totals always count every byte).
#[cfg(target_os = "linux")]
fn finish(exit: harness_sandbox_linux::supervisor::RawExit, output_bytes: u64) -> ConfinedExit {
    let (stdout, stdout_truncated) = capped(exit.stdout, output_bytes);
    let (stderr, stderr_truncated) = capped(exit.stderr, output_bytes);
    let status = if exit.timed_out {
        ChildStatus::TimedOut
    } else if !exit.exec_ok {
        ChildStatus::ExecFailed
    } else {
        match exit.outcome {
            harness_sandbox_linux::supervisor::WaitCause::Exited(code) => ChildStatus::Exited(code),
            harness_sandbox_linux::supervisor::WaitCause::Signaled(sig) => {
                ChildStatus::Signaled(sig)
            }
            harness_sandbox_linux::supervisor::WaitCause::Unknown => ChildStatus::Unknown,
        }
    };
    let domain = if exit.confirmed {
        DomainCleanup::Confirmed { kills: exit.kills }
    } else {
        DomainCleanup::Unconfirmed(exit.detail)
    };
    ConfinedExit {
        status,
        stdout,
        stdout_truncated,
        stderr,
        stderr_truncated,
        domain,
        elapsed: exit.elapsed,
    }
}

#[cfg(target_os = "linux")]
fn capped(bytes: Vec<u8>, cap: u64) -> (Vec<u8>, bool) {
    let cap = usize::try_from(cap).unwrap_or(usize::MAX);
    if bytes.len() > cap {
        (bytes.into_iter().take(cap).collect(), true)
    } else {
        (bytes, false)
    }
}

/// The spawn path's twin of the Seatbelt private directory: a unique 0700
/// directory under the temp root. The supervisor needs no stub file on
/// disk (the helper is the re-exec'd binary itself), so this exists only
/// to keep the validator's lexical overlap checks anchored and does not
/// outlive validation.
#[cfg(target_os = "linux")]
fn private_dir(tag: &str) -> std::io::Result<std::path::PathBuf> {
    use std::hash::BuildHasher;
    use std::os::unix::fs::DirBuilderExt;
    let root = std::fs::canonicalize(std::env::temp_dir())?;
    for attempt in 0u32..16 {
        let n = std::collections::hash_map::RandomState::new().hash_one((
            std::process::id(),
            attempt,
            std::time::SystemTime::now(),
        ));
        let dir = root.join(format!("rh-linux-{tag}-{n:016x}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("no unique private directory"))
}

/// Validate and start through the real supervisor: the Linux twin of
/// `Seatbelt::start`. No profile is rendered and no stub is written — the
/// helper is this binary itself, re-exec'd with the `__confine` argument,
/// and the domain is built in the program child. The network tiers
/// (`Loopback`/`Proxy`) are refused by validation here: the namespace-less
/// row's seccomp filter denies `socket()` outright, so no network grant is
/// enforceable (fail closed, not best effort).
#[cfg(target_os = "linux")]
fn start(spec: &ConfinedSpec) -> Result<ConfinedChild, SpawnError> {
    let dir = private_dir("call").map_err(|e| SpawnError::Io(e.to_string()))?;
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let cx = Context {
        home: home.as_deref(),
        private_dir: &dir,
        enforce: Enforceable {
            memory: true,
            processes: true,
        },
        reserved_ports: &[],
        ports_conformed: false,
        proxy: false,
    };
    let approved = match spec::validate(spec, &cx) {
        Ok(a) => a,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e.into());
        }
    };
    let _ = std::fs::remove_dir_all(&dir);
    let v = approved.spec;
    let program = harness_sandbox_linux::supervisor::Program {
        argv: v.argv,
        env: v.env,
        cwd: v.cwd,
        read_only: v.read_only,
        read_write: v.read_write,
        protected: v.protected,
        limits: harness_sandbox_linux::supervisor::Limits {
            cpu: v.limits.cpu,
            file_size: v.limits.file_size,
            memory: v.limits.memory,
            processes: v.limits.processes,
        },
    };
    // The helper is this very binary: whoever runs a confined call (the
    // harness, or the conformance suite) carries the `__confine` entry
    // point with it.
    let helper = std::env::current_exe().map_err(|e| SpawnError::Io(e.to_string()))?;
    let child = harness_sandbox_linux::supervisor::spawn(
        &program,
        helper.as_os_str(),
        // The ring holds at least the retained output window; the output
        // cap bounds what `wait` hands back either way.
        v.limits.output_bytes.max(1),
        v.limits.wall,
    )
    .map_err(|e| SpawnError::Io(e.to_string()))?;
    Ok(ConfinedChild {
        inner: Child {
            inner: child,
            output_bytes: v.limits.output_bytes,
        },
    })
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
            if let Some(p) = harness_sandbox_linux::LinuxBackend::missing_primitive(&primitives) {
                return Err(linux_refusal(Some(p)));
            }
            // The ABI the children's domains are built and enforced at
            // (L-D7): the landlock crate's own hard-requirement gate
            // answers whether the kernel reaches it.
            let Some(abi) = harness_sandbox_linux::landlock_rules::kernel_abi_probe() else {
                return Err(linux_refusal(Some("landlock-abi")));
            };
            // A committed row always wins; the S-Le gate hands out the
            // uncommitted one until S-Lf observes it green on a real
            // kernel.
            let Some(row) =
                crate::conformance::row(BackendKind::Linux, "linux").or_else(linux_row_gated)
            else {
                return Err(linux_refusal(None));
            };
            probe_with(&facts, abi, row, live_attempt(), PROBE_BACKOFFS_MS, |ms| {
                std::thread::sleep(std::time::Duration::from_millis(ms))
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Unavailable {
                backend: None,
                reason: UnavailableReason::NoBackendForOs,
            })
        }
    }

    fn spawn(&self, spec: &ConfinedSpec, ev: &Conformed) -> Result<ConfinedChild, SpawnError> {
        if ev.backend() != BackendKind::Linux {
            return Err(SpawnError::WrongWitness);
        }
        #[cfg(target_os = "linux")]
        {
            start(spec)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = spec;
            Err(SpawnError::Io("the Linux backend is not built".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host where every measured primitive is present.
    fn facts_full() -> HostFacts {
        HostFacts {
            landlock_lsm: Some(true),
            apparmor_restricts_userns: Some(true),
            userns_clone: None,
            max_user_namespaces: Some(63_446),
            cgroup_v2: Some(true),
            seccomp_kill: Some(true),
        }
    }

    /// What a clean live probe observes: every canary refused, the control
    /// run, both guard canaries bounded (the exact text is the probe's).
    fn clean_observation() -> Result<String, Unavailable> {
        Ok(
            "--canaries--\nnet ok\nbind ok\nwrite ok\nread ok\nlink ok\nhome ok\nenv ok\nsysbin ok\nescape ok\n--memory--\napplied\n--processes--\nforked=2\nsurvived\n"
                .into(),
        )
    }

    /// The gated (uncommitted) Linux row, the one the probe hands out.
    fn gated_row() -> &'static MatrixRow {
        crate::conformance::linux_row_uncommitted().unwrap()
    }

    fn no_pause(_ms: u64) {}

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

    // On a non-Linux host there is no Linux backend at all; on Linux the
    // unit harness never runs the live probe (see `live_attempt`), so the
    // probe refuses there too. Either way it never mints HERE.
    #[test]
    fn the_linux_backend_never_mints_under_the_unit_harness() {
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

    #[test]
    fn probe_mints_only_when_every_canary_is_refused() {
        let row = gated_row();
        let clean = clean_observation();
        let w = probe_with(
            &facts_full(),
            3,
            row,
            || clean.clone(),
            PROBE_BACKOFFS_MS,
            no_pause,
        )
        .unwrap();
        assert_eq!(w.backend(), BackendKind::Linux);
        // One canary NOT refused (here: the outside write landed) mints
        // nothing.
        let escaped = || {
            Err(Unavailable {
                backend: Some(BackendKind::Linux),
                reason: UnavailableReason::LiveProbeFailed {
                    probe: "write",
                    observed: "the file outside the roots exists".into(),
                },
            })
        };
        assert!(probe_with(&facts_full(), 3, row, escaped, PROBE_BACKOFFS_MS, no_pause).is_err());
    }

    #[test]
    fn an_escape_is_final_and_mints_nothing() {
        let row = gated_row();
        let mut calls = 0u32;
        let escaped = || {
            calls += 1;
            Err(Unavailable {
                backend: Some(BackendKind::Linux),
                reason: UnavailableReason::LiveProbeFailed {
                    probe: "net",
                    observed: "the listener saw 127.0.0.1:55555".into(),
                },
            })
        };
        let r = probe_with(&facts_full(), 3, row, escaped, PROBE_BACKOFFS_MS, no_pause);
        assert!(r.is_err());
        // An escape is never retried: the first refusal is the last.
        assert_eq!(calls, 1);
    }

    #[test]
    fn a_load_shaped_io_failure_is_retried() {
        let row = gated_row();
        let clean = clean_observation();
        let mut calls = 0u32;
        let flaky = || {
            calls += 1;
            if calls == 1 {
                // A spawn that failed on a loaded machine.
                return Err(Unavailable {
                    backend: Some(BackendKind::Linux),
                    reason: UnavailableReason::LiveProbeFailed {
                        probe: "spawn",
                        observed: "fork failed under load".into(),
                    },
                });
            }
            clean.clone()
        };
        let w = probe_with(&facts_full(), 3, row, flaky, PROBE_BACKOFFS_MS, no_pause).unwrap();
        // The retry is part of the witness: two attempts, not one.
        let clean_digest = observations_digest(row.id, clean_observation().unwrap().as_bytes(), 1);
        assert_ne!(w.probe_digest(), &clean_digest);
    }

    #[test]
    fn a_probe_that_never_reports_refuses_after_the_bounded_retries() {
        let row = gated_row();
        let mut calls = 0u32;
        let never_reports = || {
            calls += 1;
            Err(Unavailable {
                backend: Some(BackendKind::Linux),
                reason: UnavailableReason::LiveProbeFailed {
                    probe: "run",
                    observed: "Unknown detail=the supervisor helper did not report".into(),
                },
            })
        };
        let r = probe_with(
            &facts_full(),
            3,
            row,
            never_reports,
            PROBE_BACKOFFS_MS,
            no_pause,
        );
        assert!(r.is_err());
        // Two load-shaped retries, then the last failure is final.
        assert_eq!(calls, 3);
    }

    #[test]
    fn witness_names_backend_abi_and_guards() {
        let row = gated_row();
        let facts = facts_full();
        let w = probe_with(
            &facts,
            3,
            row,
            clean_observation,
            PROBE_BACKOFFS_MS,
            no_pause,
        )
        .unwrap();
        // The row's bars, by name:
        assert_eq!(w.matrix_row(), "linux-landlock-seccomp-nons-v1");
        assert_eq!(w.network(), crate::NetworkMechanism::LinuxLandlockSeccomp);
        assert_eq!(w.kill_domain(), crate::KillDomain::SubreaperSweep);
        assert_eq!(w.memory(), crate::MemoryGuard::RlimitAddressSpace);
        assert_eq!(w.processes(), crate::ProcessGuard::RlimitNprocPerUser);
        // The L-D7 backend detail: the enforced ABI, the seccomp denial
        // action, and the host facts the decision was made from.
        let lw = w.linux().expect("a Linux witness carries its detail");
        assert_eq!(lw.landlock_abi(), 3);
        assert_eq!(lw.seccomp_action(), SeccompAction::Errno);
        assert_eq!(
            lw.host_facts_digest(),
            &harness_core::sha256(facts.summary().as_bytes())
        );
        // The attempts line is part of the digest, so a retried pass can
        // never stand for a clean one.
        let mut calls = 0u32;
        let retried = probe_with(
            &facts,
            3,
            row,
            || {
                calls += 1;
                if calls == 1 {
                    return Err(Unavailable {
                        backend: Some(BackendKind::Linux),
                        reason: UnavailableReason::LiveProbeFailed {
                            probe: "proc-spawn",
                            observed: "fork failed under load".into(),
                        },
                    });
                }
                clean_observation()
            },
            PROBE_BACKOFFS_MS,
            no_pause,
        )
        .unwrap();
        assert_eq!(calls, 2);
        assert_ne!(w.probe_digest(), retried.probe_digest());
    }

    #[test]
    fn an_arch_without_the_supervisor_is_a_missing_primitive() {
        // A spawn refusal that is NOT load-shaped is the supervisor's
        // unsupported-architecture answer: named, final, never retried.
        let u = live_refusal("spawn", "unsupported architecture".into(), false);
        assert_eq!(
            u.reason,
            UnavailableReason::PrimitiveMissing("modelled-arch")
        );
        assert!(!load_shaped(&u));
    }

    // The digest names the supervisor's fixed sweep deadline; on Linux it
    // must stay in lockstep with the real constant.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_digest_names_the_real_sweep_deadline() {
        assert_eq!(
            harness_sandbox_linux::supervisor::SWEEP_DEADLINE,
            std::time::Duration::from_secs(3)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_delegates_to_the_linux_crate() {
        // Under the unit harness the live probe refuses without running,
        // naming itself; a non-test build would run the real canaries.
        let err = Linux.probe().unwrap_err();
        assert_eq!(err.backend, Some(BackendKind::Linux));
        assert!(matches!(
            err.reason,
            UnavailableReason::PrimitiveMissing(_)
                | UnavailableReason::MatrixRowMissing
                | UnavailableReason::LiveProbeFailed { .. }
        ));
    }
}
