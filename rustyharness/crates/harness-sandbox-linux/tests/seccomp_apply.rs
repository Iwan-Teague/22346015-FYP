//! Applied-filter probe for the seccomp denylist (slice S-Lc).
//!
//! The pure-data tests live in `src/seccomp.rs` and run on any host; this
//! file holds the one behaviour that needs a real Linux process: installing
//! the filter and proving the socket family answers `EACCES` from inside a
//! confined child, with an unconfined control child that must still open
//! one. Integration tests are the INV-23-sanctioned place a test may spawn
//! (`scripts/ci/purity.sh` §2f), and std's `TcpListener` keeps the probe
//! itself free of `unsafe` — a denied `socket(2)` surfaces as `EACCES`
//! through the ordinary `io::Error` path.
//!
//! Linux-only, and only on the arches whose rule tables are modelled (the
//! syscall numbers are verified in `src/seccomp.rs`); skipped elsewhere.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use harness_sandbox_linux::seccomp::{Denylist, NetworkMode, SeccompFilter};
use std::process::Command;

/// Env marker telling a re-exec'd copy of this test binary to run the probe
/// branch instead of the harness.
const PROBE_ENV: &str = "RH_SECCOMP_PROBE_SLICE_S_LC";

/// `EACCES`, the errno the denylist answers the socket family with.
const EACCES: i32 = 13;

/// Open a loopback listener: `socket(2)`, then `bind`/`listen`. Succeeds
/// only when the socket family is reachable.
fn bind_loopback() -> Result<(), std::io::Error> {
    std::net::TcpListener::bind("127.0.0.1:0").map(|_| ())
}

/// The child arm: attempt (or deliberately not attempt) a socket and report
/// by exit code — a filtered child cannot rely on much else.
fn probe_child(mode: &str) -> ! {
    match mode {
        // Control: no filter applied — the socket must succeed.
        "control" => {
            if bind_loopback().is_ok() {
                std::process::exit(0);
            }
            std::process::exit(4);
        }
        // Filtered: install the denylist, then the socket must fail with
        // exactly EACCES (a named step refusing, not a crash).
        "filtered" => {
            let filter = Denylist::new(NetworkMode::None);
            if SeccompFilter::apply(&filter).is_err() {
                std::process::exit(2);
            }
            match bind_loopback() {
                Ok(()) => std::process::exit(3),
                Err(err) => match err.raw_os_error() {
                    Some(EACCES) => std::process::exit(0),
                    _ => std::process::exit(5),
                },
            }
        }
        _ => std::process::exit(6),
    }
}

#[test]
fn applied_filter_blocks_socket_in_a_child() {
    // Child arm: run the probe and exit with its code.
    if let Ok(mode) = std::env::var(PROBE_ENV) {
        probe_child(&mode);
    }
    let exe = std::env::current_exe().expect("current_exe");
    for mode in ["control", "filtered"] {
        let output = Command::new(&exe)
            .args(["--exact", "applied_filter_blocks_socket_in_a_child"])
            .env(PROBE_ENV, mode)
            .output()
            .expect("spawn probe child");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "probe {mode}: exit {:?}, stderr: {stderr}",
            output.status.code()
        );
    }
}
