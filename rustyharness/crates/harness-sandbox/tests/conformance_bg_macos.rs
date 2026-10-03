//! The background-child conformance suite (P-36b, spec §4.2/§5.3/§12) on
//! the macOS Seatbelt backend, through the real `spawn_live` seam. Each
//! test states the case it witnesses: a live call stays readable while it
//! runs (`read`/`totals`), the deadline closer and `stop` both end it with
//! a swept domain, a killed harness still gets its sweep (the kernel
//! closes the control pipes), an output flood cannot outgrow its ring, and
//! the process-guard watchdog stops a fork bomb without touching a
//! neighbour.
//!
//! `bg_sigkill_harness_entrypoint` is the re-exec body of
//! `ft_bg_parent_sigkill_sweeps_the_domain`: with `RH_BG_HARNESS=sigkill`
//! in the environment it plays the harness (starts a live sleeper with a
//! setsid grandchild, both writing their pids away, then blocks), so the
//! test can SIGKILL it and watch the domain sweep itself. Without the
//! variable it returns at once, so the full suite runs it as a no-op.
#![cfg(target_os = "macos")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use harness_core::sha256;
use harness_sandbox::seatbelt::Seatbelt;
use harness_sandbox::{
    Backend, ChildStatus, ConfinedExit, ConfinedSpec, Conformed, DomainCleanup, Limits, LiveOpts,
    Mode, Network, Stream,
};

const PERL: &str = "/usr/bin/perl";

fn witness() -> &'static Conformed {
    static W: OnceLock<Conformed> = OnceLock::new();
    W.get_or_init(|| {
        Seatbelt::new()
            .probe()
            .expect("the Seatbelt live probe must pass")
    })
}

/// A fresh directory tree with one read-write root (`ws`), canonical.
struct Tree {
    root: PathBuf,
    ws: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Tree {
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let root = base.join(format!(
            "rh-bg-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let ws = root.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        Tree { root, ws }
    }

    fn spec(&self, argv: &[&str]) -> ConfinedSpec {
        self.spec_limits(
            argv,
            Limits {
                wall: Duration::from_secs(20),
                cpu: None,
                file_size: None,
                memory: None,
                processes: None,
                output_bytes: 1 << 20,
            },
        )
    }

    /// The same spec with explicit limits (the fork bomb's process cap, the
    /// exec-run output cap).
    fn spec_limits(&self, argv: &[&str], limits: Limits) -> ConfinedSpec {
        ConfinedSpec {
            argv: argv.iter().map(OsString::from).collect(),
            cwd: self.ws.clone(),
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            read_only: vec![],
            read_write: vec![self.ws.clone()],
            protected: vec![],
            network: Network::None,
            limits,
        }
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A live call with a lifetime far past any test here, so only `stop` (or
/// the SIGKILL harness case) ends it.
const LONG_LIFETIME: Duration = Duration::from_secs(60);
const KIB: u64 = 1024;

fn spawn_live(
    spec: &ConfinedSpec,
    lifetime: Duration,
    ring_bytes: u64,
) -> harness_sandbox::ConfinedChild {
    let live = LiveOpts {
        ring_bytes,
        lifetime,
    };
    Seatbelt::new().spawn_live(spec, witness(), &live).unwrap()
}

/// Whether a process still exists (`/bin/kill -0`, unconfined: test code).
fn alive(pid: u32) -> bool {
    Command::new("/bin/kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Read the single pid a confined program wrote to `path`.
fn pid_in(path: &Path) -> u32 {
    std::fs::read_to_string(path)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

/// Poll until `path` exists and holds its pid (the confined program's sync
/// marker). The program creates the file (`open >`) before it writes the
/// pid, so bare existence races a reader into an empty file: wait for the
/// content, which the program writes in one `close`-time flush.
fn wait_for(path: &Path, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !std::fs::read_to_string(path).is_ok_and(|s| !s.trim().is_empty()) {
        assert!(Instant::now() < deadline, "{what} never happened");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn confirmed(e: &ConfinedExit) {
    assert!(
        matches!(e.domain, DomainCleanup::Confirmed { .. }),
        "domain not confirmed: {:?}; stderr {}",
        e.domain,
        String::from_utf8_lossy(&e.stderr)
    );
}

/// `bg-stop-sweep`: a long-lived background child that outlives the
/// caller's interest is swept by `stop`: the control pipe closes, the stub
/// halts the program and sweeps, and the domain confirms.
#[test]
fn ft_bg_long_lived_child_is_swept_on_stop() {
    let t = Tree::new("stop-sweep");
    let pidfile = t.ws.join("pid");
    let spec = t.spec(&[
        PERL,
        "-e",
        "open(my $m, q{>}, $ARGV[0]) or exit 2; print $m $$; close $m; sleep 30;",
        pidfile.to_str().unwrap(),
    ]);
    let mut child = spawn_live(&spec, LONG_LIFETIME, 64 * KIB);
    wait_for(&pidfile, "the child pid marker");
    let pid = pid_in(&pidfile);
    assert!(alive(pid), "the child must be running before the stop");
    assert!(
        child.try_status().is_none(),
        "a running child has no status"
    );
    let exit = child.stop();
    confirmed(&exit);
    assert_eq!(exit.status, ChildStatus::Unknown, "a stop is not a timeout");
    let deadline = Instant::now() + Duration::from_secs(10);
    while alive(pid) {
        assert!(Instant::now() < deadline, "the child survived its stop");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `bg-stop-sweep` with a descendant that left the process group: a setsid
/// grandchild cannot leave the sandbox instance, so `stop` sweeps it too.
#[test]
fn ft_bg_setsid_descendant_is_swept_on_stop() {
    let t = Tree::new("stop-setsid");
    let pidfile = t.ws.join("pid");
    let grandfile = t.ws.join("grand");
    let script = "use POSIX qw(setsid); \
        open(my $m, q{>}, $ARGV[0]) or exit 2; print $m $$; close $m; \
        my $k = fork(); if (!defined $k) { exit 3 } \
        if ($k == 0) { setsid(); \
            open(my $g, q{>}, $ARGV[1]) or exit 2; print $g $$; close $g; sleep 60; exit 0 } \
        waitpid($k, 0); sleep 30;";
    let spec = t.spec(&[
        PERL,
        "-e",
        script,
        pidfile.to_str().unwrap(),
        grandfile.to_str().unwrap(),
    ]);
    let child = spawn_live(&spec, LONG_LIFETIME, 64 * KIB);
    wait_for(&pidfile, "the child pid marker");
    wait_for(&grandfile, "the grandchild pid marker");
    let pid = pid_in(&pidfile);
    let grand = pid_in(&grandfile);
    let exit = child.stop();
    confirmed(&exit);
    let deadline = Instant::now() + Duration::from_secs(10);
    while alive(pid) || alive(grand) {
        assert!(
            Instant::now() < deadline,
            "a setsid descendant survived the stop"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The re-exec body of `ft_bg_parent_sigkill_sweeps_the_domain` (§5.3):
/// with `RH_BG_HARNESS=sigkill`, play the harness — start a live sleeper
/// with a setsid grandchild (both pids written away) and block on it, so
/// the test can SIGKILL this process mid-call. Without the variable this
/// is a no-op so the suite runs it harmlessly.
#[test]
fn bg_sigkill_harness_entrypoint() {
    let Ok(mode) = std::env::var("RH_BG_HARNESS") else {
        return;
    };
    if mode != "sigkill" {
        return;
    }
    let ws = PathBuf::from(std::env::var("RH_BG_WS").unwrap());
    let pidfile = PathBuf::from(std::env::var("RH_BG_CHILD_PF").unwrap());
    let grandfile = PathBuf::from(std::env::var("RH_BG_GRAND_PF").unwrap());
    let script = "use POSIX qw(setsid); \
        open(my $m, q{>}, $ARGV[0]) or exit 2; print $m $$; close $m; \
        my $k = fork(); if (!defined $k) { exit 3 } \
        if ($k == 0) { setsid(); \
            open(my $g, q{>}, $ARGV[1]) or exit 2; print $g $$; close $g; sleep 120; exit 0 } \
        waitpid($k, 0); sleep 120;";
    let spec = ConfinedSpec {
        argv: vec![
            PERL.into(),
            "-e".into(),
            script.into(),
            pidfile.clone().into_os_string(),
            grandfile.clone().into_os_string(),
        ],
        cwd: ws.clone(),
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        read_only: vec![],
        read_write: vec![ws],
        protected: vec![],
        network: Network::None,
        limits: Limits {
            wall: Duration::from_secs(180),
            cpu: None,
            file_size: None,
            memory: None,
            processes: None,
            output_bytes: 1 << 20,
        },
    };
    let _child = spawn_live(&spec, Duration::from_secs(120), 64 * KIB);
    // Blocked on the call, like a real harness waiting on a live child.
    std::thread::sleep(Duration::from_secs(120));
}

/// `bg-parent-death`: SIGKILL the harness mid-call; the kernel closes the
/// control pipes, the stub stops the program and sweeps the whole domain
/// — including the setsid grandchild — with no harness code running. The
/// test re-execs this binary as the harness (see the entrypoint above).
///
/// The harness is spawned through `sh ... &` so that this process is
/// never its parent and launchd reaps it. The stub's per-pass canary
/// accepts only EPERM or ESRCH, and on macOS `kill(0, zombie)` still
/// succeeds: if the harness died and stayed a zombie past the stub's
/// first sweep pass (one 20 ms select tick after the pipes closed), the
/// canary would report and the domain would get no sweep at all. A
/// reaper on this test's own scheduling (a thread blocked in `wait`)
/// loses that race on a loaded host; launchd reaps at kernel pace, so
/// the stub always sees ESRCH.
#[test]
fn ft_bg_parent_sigkill_sweeps_the_domain() {
    let t = Tree::new("parent-death");
    let pidfile = t.ws.join("pid");
    let grandfile = t.ws.join("grand");
    let harness_pidfile = t.ws.join("harness-pid");
    let exe = std::env::current_exe().unwrap();
    let sh = Command::new("/bin/sh")
        .arg("-c")
        .arg("\"$0\" \"$1\" --exact --nocapture & echo $! >\"$2\"")
        .arg(&exe)
        .arg("bg_sigkill_harness_entrypoint")
        .arg(&harness_pidfile)
        .env("RH_BG_HARNESS", "sigkill")
        .env("RH_BG_WS", &t.ws)
        .env("RH_BG_CHILD_PF", &pidfile)
        .env("RH_BG_GRAND_PF", &grandfile)
        .status()
        .unwrap();
    assert!(sh.success(), "the sh wrapper must have started the harness");
    wait_for(&harness_pidfile, "the harness's own pid marker");
    let harness_pid: u32 = std::fs::read_to_string(&harness_pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let guards = || -> (u32, u32) {
        wait_for(&pidfile, "the harness child's pid marker");
        wait_for(&grandfile, "the setsid grandchild's pid marker");
        (pid_in(&pidfile), pid_in(&grandfile))
    };
    let (pid, grand) = guards();
    // Murder the harness with the call still open. It is not this
    // process's child, so there is nothing to reap (see the comment on
    // the spawn above).
    Command::new("/bin/kill")
        .arg("-KILL")
        .arg(harness_pid.to_string())
        .status()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut timeline: Vec<String> = Vec::new();
    let mut tick = Instant::now();
    while alive(pid) || alive(grand) {
        if tick.elapsed() >= Duration::from_millis(200) {
            tick = Instant::now();
            let stub = Command::new("/bin/ps")
                .args(["-eo", "pid,ppid,command"])
                .output()
                .map(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .filter(|l| l.contains("sandbox-exec"))
                        .count()
                })
                .unwrap_or(usize::MAX);
            timeline.push(format!(
                "+{:.1}s pid={} grand={} sandbox_exec_procs={stub}",
                (Instant::now() - deadline).as_secs_f64() + 15.0,
                alive(pid),
                alive(grand),
            ));
        }
        if Instant::now() >= deadline {
            let ps = Command::new("/bin/ps")
                .args(["-eo", "pid,ppid,pgid,stat,command"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_default();
            let mine: String = ps
                .lines()
                .filter(|l| l.contains("rh-bg-parent-death") || l.contains("sandbox-exec"))
                .collect::<Vec<_>>()
                .join("\n");
            // Clean the survivors so a failed run leaves no orphans.
            for p in [pid, grand] {
                let _ = Command::new("/bin/kill")
                    .arg("-KILL")
                    .arg(p.to_string())
                    .status();
            }
            panic!(
                "the domain outlived its killed harness (pid {pid}, grand {grand}); \
                 timeline:\n{}\nsurvivors:\n{mine}",
                timeline.join("\n")
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `bg-parent-death` with the harness left unreaped: a SIGKILLed harness
/// is a zombie until its parent waits on it, and on macOS `kill(0, zombie)`
/// still succeeds — so the stub must ride the reap window out (re-checking
/// its per-pass success) and sweep anyway, instead of canarying the moment
/// the harness dies and orphaning the domain. The zombie is held for 400ms,
/// well past the stub's first per-pass checks, then reaped.
#[test]
fn ft_bg_sigkilled_unreaped_harness_still_sweeps() {
    let t = Tree::new("parent-death-unreaped");
    let pidfile = t.ws.join("pid");
    let grandfile = t.ws.join("grand");
    let exe = std::env::current_exe().unwrap();
    let mut h = Command::new(exe)
        .args(["bg_sigkill_harness_entrypoint", "--exact", "--nocapture"])
        .env("RH_BG_HARNESS", "sigkill")
        .env("RH_BG_WS", &t.ws)
        .env("RH_BG_CHILD_PF", &pidfile)
        .env("RH_BG_GRAND_PF", &grandfile)
        .spawn()
        .unwrap();
    let harness_pid = h.id();
    let (pid, grand) = {
        wait_for(&pidfile, "the harness child's pid marker");
        wait_for(&grandfile, "the setsid grandchild's pid marker");
        (pid_in(&pidfile), pid_in(&grandfile))
    };
    // Murder the harness with the call still open, then leave the corpse
    // alone: no `wait`, no reaper thread. A pre-fix stub canaries within
    // ~20ms of this kill, while the zombie still answers `kill(0)`.
    Command::new("/bin/kill")
        .arg("-KILL")
        .arg(harness_pid.to_string())
        .status()
        .unwrap();
    std::thread::sleep(Duration::from_millis(400));
    use std::os::unix::process::ExitStatusExt;
    let status = h.wait().unwrap();
    assert_eq!(
        status.signal(),
        Some(9),
        "the harness should have died by our SIGKILL, got {status:?}"
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while alive(pid) || alive(grand) {
        if Instant::now() >= deadline {
            // Clean the survivors so a failed run leaves no orphans.
            for p in [pid, grand] {
                let _ = Command::new("/bin/kill")
                    .arg("-KILL")
                    .arg(p.to_string())
                    .status();
            }
            panic!(
                "the domain outlived its killed and deliberately unreaped harness \
                 (pid {pid}, grand {grand}); the stub must retry through the reap \
                 window instead of canarying on a zombie"
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `bg-lifetime`: the deadline closer closes the control pipe at the
/// lifetime while the caller keeps blocking on the child; the domain is
/// swept and `try_status` starts returning the collected exit.
#[test]
fn ft_bg_lifetime_closer_stops_child_while_parent_blocks() {
    let t = Tree::new("lifetime");
    let spec = t.spec(&[PERL, "-e", "sleep 30;"]);
    let started = Instant::now();
    let mut child = spawn_live(&spec, Duration::from_secs(2), 64 * KIB);
    assert!(child.try_status().is_none(), "nothing can have ended yet");
    std::thread::sleep(Duration::from_secs(4));
    let exit = child.try_status().expect("the closer must have ended it");
    confirmed(&exit);
    assert!(
        exit.elapsed >= Duration::from_secs(2),
        "the child must have lived at least its lifetime"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    // Later polls return the same collected exit.
    assert_eq!(child.try_status(), Some(exit));
}

/// `bg-output-bounded`: a flood of stdout cannot outgrow the ring: totals
/// and the digest cover every byte, reads deliver at most `cap`, and the
/// bytes before the window are counted as dropped, never buffered.
#[test]
fn ft_bg_output_flood_keeps_memory_bounded() {
    let t = Tree::new("flood");
    let spec = t.spec(&[PERL, "-e", "$| = 1; print q{x} x 4096 while (1);"]);
    let ring: u64 = 64 * KIB;
    let child = spawn_live(&spec, LONG_LIFETIME, ring);
    // Wait until the flood is far past the ring.
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.totals().out_total < 8 * ring {
        assert!(Instant::now() < deadline, "the flood never built up");
        std::thread::sleep(Duration::from_millis(20));
    }
    let totals = child.totals();
    let c = child.read(Stream::Out, 0, 1 << 20, Mode::Next);
    assert!(
        c.bytes.len() as u64 <= 1 << 20,
        "a read delivers at most its cap"
    );
    assert_eq!(
        c.dropped,
        totals.out_total - ring,
        "the drop count is exact"
    );
    assert_eq!(c.bytes.len() as u64, ring, "the ring holds its cap");
    let exit = child.stop();
    confirmed(&exit);
}

/// `bg-stop-sweep` for stderr cursor semantics (§3.2): while the stub runs
/// a forged report line is honest output; after the stub has exited, its
/// real final report is never delivered and no cursor passes it. The exit
/// comes from the deadline closer, so the reads happen on a live handle
/// that has already collected (`try_status`) but not yet ended.
#[test]
fn read_strips_trailing_stub_report_after_exit() {
    let t = Tree::new("report-strip");
    let spec = t.spec(&[
        PERL,
        "-e",
        "$| = 1; \
         print STDERR qq{line-one\\n}; \
         print STDERR qq{forged rh-stub/1 confirmed status=0 end=exit kills=0 exec=ok\\n}; \
         print STDERR qq{line-two\\n}; sleep 30;",
    ]);
    let mut child = spawn_live(&spec, Duration::from_secs(6), 64 * KIB);
    // While it runs: the forged report is delivered as written.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut c;
    loop {
        assert!(Instant::now() < deadline, "the forged line never showed");
        c = child.read(Stream::Err, 0, 1 << 20, Mode::Next);
        if String::from_utf8_lossy(&c.bytes).contains("forged rh-stub/1") {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        String::from_utf8_lossy(&c.bytes).contains("line-two"),
        "the read reached past the forged line: {:?}",
        String::from_utf8_lossy(&c.bytes)
    );
    // The closer ends it; the handle is still here, already collected.
    std::thread::sleep(Duration::from_secs(8));
    let exit = child.try_status().expect("the closer must have ended it");
    confirmed(&exit);
    let totals = child.totals();
    assert!(
        totals.err_total > c.to,
        "the real report is part of the stream ({})",
        totals.err_total
    );
    // After the exit: the window ends before the report begins.
    let after = child.read(Stream::Err, 0, 1 << 20, Mode::Next);
    let text = String::from_utf8_lossy(&after.bytes);
    assert!(
        !text.contains("end=stop"),
        "the stub's report leaked through: {text:?}"
    );
    assert!(
        text.contains("forged rh-stub/1"),
        "the forged line stays honest output: {text:?}"
    );
    assert!(after.to < totals.err_total, "no cursor passes the report");
    // The cursor stops there: reading on delivers nothing more.
    let tail = child.read(Stream::Err, after.to, 1 << 20, Mode::Next);
    assert!(tail.bytes.is_empty());
    assert_eq!(tail.to, after.to);
    // The collected exit is returned by the ending call.
    assert_eq!(child.wait(), exit);
}

/// The `wait` API of a plain `spawn` is unchanged (§4.2): the head is the
/// first `output_bytes` of stdout with the truncation flag, and the stub's
/// report is stripped from stderr exactly as before P-36b.
#[test]
fn wait_api_unchanged_for_exec_run() {
    let t = Tree::new("exec-run");
    let spec = t.spec_limits(
        &[PERL, "-e", "my $x = q{x} x (2 * 1024 * 1024); print $x;"],
        Limits {
            wall: Duration::from_secs(20),
            cpu: None,
            file_size: None,
            memory: None,
            processes: None,
            output_bytes: 1 << 20,
        },
    );
    let exit = Seatbelt::new().spawn(&spec, witness()).unwrap().wait();
    confirmed(&exit);
    assert_eq!(exit.status, ChildStatus::Exited(0));
    assert_eq!(exit.stdout.len(), 1 << 20, "the head caps at output_bytes");
    assert!(exit.stdout.iter().all(|&b| b == b'x'));
    assert!(exit.stdout_truncated, "2 MiB through a 1 MiB cap");
    assert!(exit.stderr.is_empty());
    assert!(
        !exit.stderr_truncated,
        "the report is stripped, not truncated"
    );
}

/// The process-guard watchdog (FT-5) stops a fork bomb at its cap and
/// sweeps every forked member, while a second live child in the same test
/// — a plain sleeper — is unaffected.
#[test]
fn ft_bg_fork_bomb_stopped_by_watchdog_other_children_unaffected() {
    let t = Tree::new("fork-bomb");
    let bomb = t.spec_limits(
        &[
            PERL,
            "-e",
            "my $n = 0; \
             while ($n < 100) { my $p = fork(); last if !defined $p; \
                 if ($p == 0) { sleep 30; exit 0 } $n++ } sleep 30;",
        ],
        Limits {
            wall: Duration::from_secs(20),
            cpu: None,
            file_size: None,
            memory: None,
            processes: Some(8),
            output_bytes: 1 << 20,
        },
    );
    let sleeper = t.spec(&[
        PERL,
        "-e",
        "open(my $m, q{>}, $ARGV[0]) or exit 2; print $m $$; close $m; sleep 30;",
        t.ws.join("sleeper-pid").to_str().unwrap(),
    ]);
    let mut child = spawn_live(&bomb, LONG_LIFETIME, 64 * KIB);
    let mut neighbour = spawn_live(&sleeper, LONG_LIFETIME, 64 * KIB);
    wait_for(&t.ws.join("sleeper-pid"), "the neighbour's pid marker");
    // The watchdog fires within a few counts (~240 ms each).
    let deadline = Instant::now() + Duration::from_secs(15);
    let exit = loop {
        if let Some(e) = child.try_status() {
            break e;
        }
        assert!(Instant::now() < deadline, "the watchdog never fired");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(exit.status, ChildStatus::ProcessLimit);
    confirmed(&exit);
    // The neighbour runs on, untouched.
    assert!(
        neighbour.try_status().is_none(),
        "the unrelated child must still be running"
    );
    assert!(alive(pid_in(&t.ws.join("sleeper-pid"))));
    let exit = neighbour.stop();
    confirmed(&exit);
}

/// A ten-minute soak (`--ignored`): a ticking child read through the whole
/// run delivers every byte in order, the running digest matches the bytes
/// delivered, the child never reports early, and the stop confirms.
#[test]
#[ignore]
fn bg_soak_ten_minutes() {
    let t = Tree::new("soak");
    let spec = t.spec(&[
        PERL,
        "-e",
        "$| = 1; while (1) { print qq{tick $$\\n}; sleep 1 }",
    ]);
    let mut child = spawn_live(&spec, Duration::from_secs(1200), 64 * KIB);
    let mut cursor = 0u64;
    let mut delivered: Vec<u8> = Vec::new();
    for i in 0..600 {
        std::thread::sleep(Duration::from_secs(1));
        let c = child.read(Stream::Out, cursor, 64 * 1024, Mode::Next);
        cursor = c.to;
        delivered.extend_from_slice(&c.bytes);
        if i % 30 == 0 {
            assert!(child.try_status().is_none(), "the child must keep running");
        }
    }
    let totals = child.totals();
    assert_eq!(totals.out_total, delivered.len() as u64, "no byte was lost");
    assert_eq!(cursor, totals.out_total, "the cursor reached the end");
    assert_eq!(
        totals.out_sha,
        sha256(&delivered),
        "the running digest covers every byte"
    );
    let exit = child.stop();
    confirmed(&exit);
}
