//! The harness's only spawns in H1 (§4.5, INV-23): a closed set of
//! read-only system queries, [`Query`], each with its program and argv
//! fixed here, run through a bounded capture of their standard output. The
//! macOS probes use them: `/sbin/mount` (locality, §2.8), `/usr/sbin/sysctl`
//! and `/usr/bin/vm_stat` (environment sample, §7.1).
//!
//! `scripts/ci/purity.sh` holds the build to this. The word `Command` may
//! appear in code only in this file and its `#[cfg(test)]` tests (its §2f),
//! the binary is built from nothing that scan does not read or the gate
//! has not reviewed (its section 5), and this file is pinned by its
//! SHA-256, so its programs, argv and bounds change only with the gate. So
//! no caller can choose a program or an argument, however it is spelled,
//! and no dependency can spawn for it (H1f-4 review F-1, confirming review
//! NF-1 and NF-2). Changing this file means updating `capture_sha256`
//! there, by review.
//!
//! The capture bounds what the child can do to the harness (H1f-3 review
//! F-7), assuming it does not fork (none of the three does; a killed
//! child's own children would outlive it, and `wait` after a kill is not
//! time-limited): its environment is cleared and `LC_ALL=C` set (a locale
//! cannot change the number format), stdin is null, stderr is discarded, at
//! most [`CAPTURE_MAX_BYTES`] + 1 bytes of stdout are read, and past the
//! deadline the child is killed. Anything but a clean exit within the
//! bounds is an error, which the probes turn into a refusal or
//! `read_failed`.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Cap on a captured stdout: the locality probe's mount-table cap (a
/// query's output is a few KiB; the cap only bounds a misbehaving child).
pub const CAPTURE_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// How long a system query may take.
pub const CAPTURE_DEADLINE: Duration = Duration::from_secs(5);

/// The system queries the harness may run, and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Query {
    /// `/sbin/mount`: the mount table (locality probe, §2.8).
    Mount,
    /// `/usr/sbin/sysctl -n vm.loadavg hw.memsize hw.logicalcpu`.
    Sysctl,
    /// `/usr/bin/vm_stat`.
    VmStat,
}

impl Query {
    /// The query's fixed program and argv.
    fn command(self) -> Command {
        match self {
            Query::Mount => Command::new("/sbin/mount"),
            Query::Sysctl => {
                let mut c = Command::new("/usr/sbin/sysctl");
                c.args(["-n", "vm.loadavg", "hw.memsize", "hw.logicalcpu"]);
                c
            }
            Query::VmStat => Command::new("/usr/bin/vm_stat"),
        }
    }
}

/// Run `q` and return its stdout, within the bounds above.
// Only the macOS probes call it; unix test builds compile the module too.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn query(q: Query) -> Result<Vec<u8>, String> {
    capture(q.command(), CAPTURE_DEADLINE)
}

/// Run `cmd` and return its stdout, within the bounds above.
fn capture(mut cmd: Command, deadline: Duration) -> Result<Vec<u8>, String> {
    let until = Instant::now() + deadline;
    let mut child = cmd
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot run: {e}"))?;
    let Some(mut out) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("no stdout pipe".into());
    };
    let (tx, rx) = mpsc::channel();
    // Builder, not thread::spawn: a thread that cannot be created is an
    // error here, never a panic (confirming review NF-2).
    let reader = std::thread::Builder::new().spawn(move || {
        let mut buf = Vec::new();
        let r = (&mut out)
            .take(CAPTURE_MAX_BYTES + 1)
            .read_to_end(&mut buf)
            .map(|_| buf);
        let _ = tx.send(r);
    });
    if let Err(e) = reader {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("cannot start the reader: {e}"));
    }
    let read = rx.recv_timeout(until.saturating_duration_since(Instant::now()));
    let buf = match read {
        Ok(Ok(buf)) if buf.len() as u64 <= CAPTURE_MAX_BYTES => buf,
        Ok(Ok(_)) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("output over the cap".into());
        }
        Ok(Err(e)) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("output unreadable: {e}"));
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("no complete output before the deadline".into());
        }
    };
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(buf),
            Ok(Some(status)) => return Err(format!("exited with {status}")),
            Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(5)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("did not exit before the deadline".into());
            }
            Err(e) => return Err(format!("cannot wait: {e}")),
        }
    }
}

#[cfg(test)]
mod tests;
