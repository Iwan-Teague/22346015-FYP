//! Bounded runs of external programs by argv array.
//!
//! The one place in `rh-dev` that touches `std::process`. Every caller
//! passes a complete argv (program first); nothing here looks up a shell,
//! and no caller may build a `sh -c` string (memory "rust-only-tooling").
//! A run is bounded by a deadline in TWO layers: the child is put in its
//! own process group at spawn (`CommandExt::process_group`), and past the
//! deadline the whole group is killed — `/bin/kill -9 -- -<pid>`, the
//! process-group kill the repo's conventions name — with a plain
//! `Child::kill` of the leader as the fallback. Killing the group, not
//! the leader, is what stops a hung `ssh` from wedging the tool; the
//! remote side's own `timeout(1)` (set by the caller in the argv) bounds
//! the guest.

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

/// How often the deadline poll wakes to check the child.
const POLL_EVERY: std::time::Duration = std::time::Duration::from_millis(100);

/// Cap on captured output (stdout + stderr together): cargo's suite output
/// is a few MiB; the cap only bounds a misbehaving child so the tool cannot
/// be made to buffer without end. A child that exceeds it is killed and the
/// run is an error, never a truncated pass.
pub const OUTPUT_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// The process-group kill: the one absolute program path this crate names.
/// (The repo's purity conventions admit `/bin/kill` for exactly this job.)
const KILL: &str = "/bin/kill";

/// What a bounded run observed.
#[derive(Debug)]
pub struct Outcome {
    /// The child's exit status, if it exited before the deadline.
    pub status: Option<ExitStatus>,
    /// True when the deadline passed first and the group was killed.
    pub timed_out: bool,
    /// The child's stdout + stderr, in arrival order per stream.
    pub output: Vec<u8>,
}

impl Outcome {
    /// True iff the child exited 0 within the deadline.
    pub fn success(&self) -> bool {
        self.status.is_some_and(|s| s.success())
    }
}

/// A run whose child was killed because it hit the output cap.
struct OverCap;

/// Run `argv` (program first) with stdin null, capture its output, and
/// bound it by `deadline` (an absolute `Instant`, so a caller can budget a
/// whole phase). Fails only on things that stop a run from being judged at
/// all: the program could not spawn, a pipe broke, a thread panicked, or
/// the output cap was hit. A non-zero exit is NOT an error here — the
/// caller reads [`Outcome::status`].
pub fn run_bounded(argv: &[String], deadline: Instant) -> Result<Outcome, String> {
    let (program, args) = match argv.split_first() {
        Some((program, args)) => (program, args),
        None => return Err("empty argv".to_string()),
    };
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Its own group: the deadline kill below takes the whole tree, so
        // no grandchild of ssh can outlive the kill.
        .process_group(0);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("{program}: cannot spawn: {e}"))?;
    let pid = child.id();

    // Two reader threads drain the pipes into one buffer; without them a
    // full pipe would block the child and the deadline would never be the
    // reason a run ends.
    let out = Arc::new(Mutex::new(Vec::new()));
    let over = Arc::new(Mutex::new(None::<OverCap>));
    let mut readers = Vec::new();
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = kill_group_and_wait(&mut child, pid);
        return Err(format!("{program}: stdout/stderr not captured"));
    };
    readers.push(spawn_reader(stdout, Arc::clone(&out), Arc::clone(&over)));
    readers.push(spawn_reader(stderr, Arc::clone(&out), Arc::clone(&over)));

    let mut judged = poll_child(&mut child, deadline, pid);
    for reader in readers {
        let _ = reader.join();
    }
    judged.output = match Arc::try_unwrap(out) {
        Ok(covered) => covered.into_inner().unwrap_or_else(|e| e.into_inner()),
        Err(_) => return Err(format!("{program}: output buffer still shared")),
    };
    if judged.timed_out {
        return Ok(judged);
    }
    if lock(&over).is_some() {
        return Err(format!(
            "{program}: output exceeded the {} MiB cap",
            OUTPUT_MAX_BYTES / (1024 * 1024)
        ));
    }
    Ok(judged)
}

/// Lock a shared buffer, surviving a poisoned mutex (a reader panic must
/// not lose the bytes already read; the run is still judged on them).
fn lock<T>(cell: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    cell.lock().unwrap_or_else(|e| e.into_inner())
}

/// Spawn the thread that drains one pipe into the shared buffer, stopping
/// (and flagging) at the output cap.
fn spawn_reader<R: Read + Send + 'static>(
    mut pipe: R,
    out: Arc<Mutex<Vec<u8>>>,
    over: Arc<Mutex<Option<OverCap>>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let mut all = lock(&out);
                    if all.len() as u64 + n as u64 > OUTPUT_MAX_BYTES {
                        *lock(&over) = Some(OverCap);
                        break;
                    }
                    let filled = buf.get(..n).unwrap_or(&buf);
                    all.extend_from_slice(filled);
                }
                Err(_) => break,
            }
        }
    })
}

/// Wait for `child` until `deadline`, killing its process group on expiry.
fn poll_child(child: &mut Child, deadline: Instant, pid: u32) -> Outcome {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Outcome {
                    status: Some(status),
                    timed_out: false,
                    output: Vec::new(),
                };
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = kill_group_and_wait(child, pid);
                    return Outcome {
                        status: None,
                        timed_out: true,
                        output: Vec::new(),
                    };
                }
                thread::sleep(POLL_EVERY);
            }
            Err(_) => {
                // A wait error after a spawn is unrecoverable bookkeeping;
                // judge the run as killed, with no status.
                let _ = kill_group_and_wait(child, pid);
                return Outcome {
                    status: None,
                    timed_out: true,
                    output: Vec::new(),
                };
            }
        }
    }
}

/// Kill the child's process group (it was put in its own group at spawn, so
/// the group id is the pid), then reap the leader. Best-effort twice over:
/// `/bin/kill -9 -- -<pid>` first, `Child::kill` as the fallback.
fn kill_group_and_wait(child: &mut Child, pid: u32) -> std::io::Result<ExitStatus> {
    let _ = Command::new(KILL).args(["-9", &format!("-{pid}")]).status();
    child.kill()?;
    child.wait()
}
