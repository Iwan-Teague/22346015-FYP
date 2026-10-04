//! The live Linux probe's end-to-end test binary (S-Le; a `harness = false`
//! integration test, like `supervisor_live.rs`).
//!
//! Two jobs, dispatched on `argv[1]`:
//!
//! - `__confine`: re-exec'd by the supervisor as the containment helper —
//!   this is HOW the probe runs the real supervisor path with this binary
//!   as its own helper.
//! - anything else: the VM tests. These are the only tests that can prove
//!   the witness names what the kernel really enforced, so they run the
//!   probe for real; on a non-Linux host (or a non-modelled architecture)
//!   they are a no-op, because the harness-sandbox-linux dependency and
//!   the probe only exist there.
//!
//! The `linux-probe-row` feature is on here (dev-dependency): it is the
//! S-Le gate that lets `require()` hand out the still-uncommitted Linux
//! row. The committed matrix gains the row only in S-Lf, after a green
//! run of this binary on a real kernel.

// `probe` is the `Backend` trait method; the import exists only where the
// probe does (S-Lg: this was missing, so the file did not compile on any
// Linux target).
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use harness_sandbox::Backend as _;

fn main() {
    // The helper dispatch and the tests exist only where the supervisor
    // does (Linux, modelled architecture); elsewhere this binary is a
    // no-op, like supervisor_live.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        let mut args = std::env::args();
        let _ = args.next();
        match args.next().as_deref() {
            Some(harness_sandbox_linux::supervisor::HELPER_ARG) => {
                harness_sandbox_linux::supervisor::helper_main()
            }
            _ => run(),
        }
    }
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        run();
    }
}

/// The VM tests, on Linux with a modelled architecture; a no-op elsewhere.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn run() {
    println!("probe_mints_only_when_every_canary_is_refused ...");
    probe_mints_only_when_every_canary_is_refused();
    println!("ok");
    println!("require_passes_on_linux_when_the_probe_passes ...");
    require_passes_on_linux_when_the_probe_passes();
    println!("ok");
    println!("the_tier_follows_the_host_facts ...");
    the_tier_follows_the_host_facts();
    println!("ok");
    println!("the_netns_probe_runs_when_userns_is_usable ...");
    the_netns_probe_runs_when_userns_is_usable();
    println!("ok");
}

/// Which tier this host's facts pick, and the row each tier must name.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn tier_shape() -> (
    bool,
    &'static str,
    harness_sandbox::NetworkMechanism,
    harness_sandbox::KillDomain,
) {
    let facts = harness_sandbox::linux::host_facts();
    match facts.userns_usable() {
        Some(true) => (
            true,
            "linux-netns-pidns-v1",
            harness_sandbox::NetworkMechanism::LinuxNetNamespace,
            harness_sandbox::KillDomain::LinuxPidNamespace,
        ),
        _ => (
            false,
            "linux-landlock-seccomp-nons-v1",
            harness_sandbox::NetworkMechanism::LinuxLandlockSeccomp,
            harness_sandbox::KillDomain::SubreaperSweep,
        ),
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn probe_mints_only_when_every_canary_is_refused() {
    let (netns, row, network, kill) = tier_shape();
    let w = harness_sandbox::Backend::probe(&harness_sandbox::linux::Linux::default())
        .expect("the live probe must mint when every canary is refused");
    assert_eq!(w.backend(), harness_sandbox::BackendKind::Linux);
    // The tier the facts picked is the tier the witness names.
    assert_eq!(w.matrix_row(), row);
    assert_eq!(w.network(), network);
    assert_eq!(w.kill_domain(), kill);
    assert_eq!(netns, w.network() == network, "facts and row must agree");
    let lw = w.linux().expect("a Linux witness carries its detail");
    assert_eq!(lw.landlock_abi(), 3);
    assert_eq!(lw.seccomp_action(), harness_sandbox::SeccompAction::Errno);
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn require_passes_on_linux_when_the_probe_passes() {
    let (_, row, network, kill) = tier_shape();
    let w = harness_sandbox::require()
        .expect("require() must pass on Linux when the live probe passes");
    assert_eq!(w.backend(), harness_sandbox::BackendKind::Linux);
    // The guards the chosen tier really met, by name:
    assert_eq!(w.matrix_row(), row);
    assert_eq!(w.network(), network);
    assert_eq!(w.kill_domain(), kill);
    assert_eq!(w.memory(), harness_sandbox::MemoryGuard::RlimitAddressSpace);
    assert_eq!(
        w.processes(),
        harness_sandbox::ProcessGuard::RlimitNprocPerUser
    );
    assert!(w
        .covers(harness_sandbox::conformance::H2_EXIT_CASES)
        .is_ok());
}

/// The namespace tier, when this host can serve it: its probe runs the
/// same canaries through the empty netns/pidns and its witness names the
/// tier. On a default-tier host this is recorded as skipped, not passed
/// silently (an AppArmor-restricted VM, say, stays on the default tier by
/// design, L-Q8).
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn the_tier_follows_the_host_facts() {
    let (netns, row, network, kill) = tier_shape();
    let w = harness_sandbox::Backend::probe(&harness_sandbox::linux::Linux::default())
        .expect("the probe mints for the tier the facts pick");
    assert_eq!(w.matrix_row(), row);
    assert_eq!(w.network(), network);
    assert_eq!(w.kill_domain(), kill);
    if !netns {
        println!("  (host userns not usable: netns tier skipped, default tier served)");
    }
}

/// The netns probe itself, on a host where the tier is usable: the raw
/// observation must carry every canary as refused.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn the_netns_probe_runs_when_userns_is_usable() {
    let (netns, ..) = tier_shape();
    if !netns {
        println!("  (host userns not usable: live_probe_netns skipped)");
        return;
    }
    let helper = std::env::current_exe().expect("this binary is the helper");
    let obs = harness_sandbox_linux::probe::live_probe_netns(helper.as_os_str())
        .expect("the netns probe must see every canary refused");
    for name in harness_sandbox_linux::probe::PROBES {
        assert!(obs.contains(&format!("{name} ok\n")), "{obs}");
    }
    assert!(obs.contains("--memory--\napplied\n"));
    assert!(obs.contains("forked="));
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn run() {}
