//! The default tier's live self-probe (slice S-Le, design §3.4).
//!
//! A witness needs more than present primitives: the sandbox must be seen
//! to hold, here, now. This module runs the canary children — through the
//! real supervisor path ([`crate::supervisor`], so Landlock, seccomp and
//! the rlimits are applied in the child exactly as for a run) — and
//! reports what was observed. Every canary must be REFUSED; the one
//! control must run. The minting decision stays in `harness-sandbox`
//! (INV-15): this module returns raw observations only.
//!
//! Canaries (§3.4): a TCP connect to a listener this process holds (FT-1,
//! and the listener must see nothing); a bind (D31); a write outside the
//! read-write roots, leaving no file (FT-3); a read of a planted
//! `.ssh`-shaped canary outside the roots (FT-4) and of a workspace
//! symlink to it (FT-12); an environment that is exactly the spec's; the
//! home directory unreadable; a benign system binary that must run (the
//! control); a setsid double-fork escapee the sweep must reap
//! (FT-16-setsid, and the sweep must report at least one kill); a memory
//! bomb stopped by the address-space rlimit (FT-6); a fork burst stopped
//! by the process rlimit (FT-5).
//!
//! The probe interpreter is `/usr/bin/perl`, the same stand-in the macOS
//! probe uses (perl-base is an Essential package on Debian/Ubuntu, so the
//! interpreter exists wherever the harness targets a Linux host).
//!
//! This module is pure orchestration over std and [`crate::supervisor`]:
//! no FFI here, the crate's reviewed sites stay the ones S-Lc/S-Ld
//! landed (S-Lj added the namespace tier's own wrappers in
//! [`crate::namespaces`]; this module calls no syscall itself).
//!
//! The namespace tier ([`crate::namespaces`], S-Lj) probes through the
//! SAME canaries ([`live_probe_netns`]): the program child runs inside the
//! empty netns/pidns behind `nsprep`, with no ports granted, so every
//! network canary must still be refused — the tier grants nothing until a
//! port is. Two judgement differences, both structural: the sweep's kill
//! count may be 0 (the kernel ends the whole pidns when its init dies, so
//! the setsid escapee is gone before the helper's sweep looks), and a
//! failed `unshare` (the 104..=106 window) is a final refusal, never
//! load-shaped.

use std::net::TcpListener;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::supervisor::{self, Limits, Program, RawExit, SpawnFail, WaitCause};

/// Why the live probe refused: which canary was not refused, and what the
/// child was seen to do. `load_shaped` marks the failures a loaded machine
/// can cause (a spawn that failed, a child that never reported); the
/// caller may retry those, never an escape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeFail {
    /// The canary that failed: `"setup"` (the probe's own files or
    /// listener could not be prepared), `"spawn"`, `"run"` (the canary
    /// child's run), one of [`PROBES`], `"mem-spawn"`, `"mem-applied"`,
    /// `"mem-bound"`, `"mem-sweep"`, `"proc-spawn"`, `"proc-limit"`,
    /// `"proc-run"` or `"proc-sweep"`.
    pub probe: &'static str,
    /// What was observed (stdout, the raw exit or the I/O error).
    pub observed: String,
    /// Whether the failure is load-shaped (H2f): a spawn failure, or a run
    /// that timed out or never reported. An escape is never load-shaped.
    pub load_shaped: bool,
}

/// The canaries the probe script reports, each as `<name> ok`, in the
/// order the script prints them.
pub const PROBES: &[&str] = &[
    "net", "bind", "write", "read", "link", "home", "env", "sysbin", "escape",
];

/// The FT-6 memory canary's address-space budget: enough for perl to
/// start, far less than its 512 MiB allocation attempt, so the attempt
/// must be refused.
pub const MEM_PROBE_BUDGET: u64 = 64 * 1024 * 1024;

/// The FT-5 process canary's rlimit cap; the canary forks a burst above it.
pub const PROC_PROBE_CAP: u32 = 4;

/// How many forks the process canary attempts: a guard that lets the whole
/// burst through is not holding.
pub const PROC_BURST: u32 = 12;

/// Each canary child's wall clock (also its supervisor lifetime).
const PROBE_WALL: Duration = Duration::from_secs(20);

/// Bytes kept per stream of a canary child: the outputs are tiny.
const PROBE_RING: u64 = 1024 * 1024;

/// The environment a canary child gets: exactly the spec's (the `env`
/// canary demands it), nothing inherited.
const PROBE_ENV: &[&[u8]] = &[b"RH_PROBE=1"];

/// The live canary script (arguments: port, outside path to write, canary,
/// workspace symlink to the canary, home directory). It prints `<name> ok`
/// when the canary was refused and `<name> FAIL` when it was not; the
/// spawner checks every line.
const PROBE_SCRIPT: &str = r#"use strict; use warnings; use POSIX ();
my ($port,$w,$can,$link,$home)=@ARGV; $|=1;
sub r { print $_[0], ($_[1] ? ' ok' : ' FAIL'), "\n" }
my $open = sub { my $s; return socket($s,2,1,0) ? $s : undef };
my $sa = sub { pack('Sna4x8', 2, $_[0], pack('C4',127,0,0,1)) };
my $s = $open->(); my $net = 1;
if (defined $s) { $net = !connect($s, $sa->($port)); close $s }
r('net', $net);
my $b = $open->(); my $bind = 1;
if (defined $b) { $bind = !bind($b, $sa->(0)); close $b }
r('bind', $bind);
r('write', !open(my $f, '>', $w));
r('read', !open(my $g, '<', $can));
r('link', !open(my $h, '<', $link));
my $home_ok = 1;
if (defined $home && length $home) { $home_ok = !opendir(my $d, $home) }
r('home', $home_ok);
r('env', join(',', sort keys %ENV) eq 'RH_PROBE');
my $u = ''; if (open(my $l, '-|', '/usr/bin/uname')) { $u = join('', <$l>); close $l }
r('sysbin', $u eq "Linux\n");
my $p = fork();
if (defined $p && $p == 0) {
    if (fork()) { POSIX::_exit(0) }
    setsid();
    close STDOUT; close STDERR;
    $SIG{TERM} = 'IGNORE'; sleep 30; POSIX::_exit(0);
}
waitpid($p, 0);
r('escape', 1);
"#;

/// The FT-6 memory canary: declare the limit applied, then attempt the
/// allocation. A child that survives to print `notbounded` shows the
/// address-space rlimit did not hold.
const MEM_PROBE_SCRIPT: &str = r#"$|=1; print "applied\n"; my @k;
for (1..64) { push @k, 'x' x (8 * 1024 * 1024) }
print "notbounded\n";
"#;

/// The FT-5 process canary: fork a burst above the cap, report how many
/// forks succeeded, then reap. A guard that let `PROC_BURST` through is
/// not holding.
const PROC_PROBE_SCRIPT: &str = r#"$|=1; my $n = 0;
for (1..12) {
    my $p = fork();
    if (!defined $p) { last }
    if ($p == 0) { sleep 3; exit 0 }
    $n++;
}
print "forked=$n\n";
my $w = 0; while ($w < $n) { wait(); $w++ }
print "survived\n";
"#;

impl ProbeFail {
    fn new(probe: &'static str, observed: impl Into<String>) -> Self {
        ProbeFail {
            probe,
            observed: observed.into(),
            load_shaped: false,
        }
    }
}

/// The spawn failures a loaded machine can cause (H2f). A spec the probe
/// itself built wrong is not load-shaped, but it is also not an escape:
/// the probe refuses, and the witness names what was seen.
fn load_shaped_spawn(e: &SpawnFail) -> bool {
    !matches!(e, SpawnFail::UnsupportedArch)
}

/// The run-shaped observation of a raw exit, for the refusal message.
fn run_observed(raw: &RawExit) -> String {
    let stderr = String::from_utf8_lossy(&raw.stderr);
    format!("{:?} detail={} stderr={}", raw.outcome, raw.detail, stderr)
}

/// Wait a canary child out and judge its raw exit. `Ok(())` means the run
/// itself is sound (it reported, was not cut off, and its program came
/// up); what the program then DID is the caller's canary checks.
fn wait_sound(raw: RawExit, what: &'static str) -> Result<RawExit, ProbeFail> {
    if raw.timed_out || matches!(raw.outcome, WaitCause::Unknown) {
        return Err(ProbeFail {
            probe: what,
            observed: run_observed(&raw),
            load_shaped: true,
        });
    }
    if !raw.exec_ok {
        // The child's sandbox setup or the exec itself failed (the
        // 94..=106 window; on the namespace tier this is nsprep's unshare,
        // id-map or lo-up step): a primitive that will not apply refuses
        // the probe, and no retry changes that.
        return Err(ProbeFail::new(what, run_observed(&raw)));
    }
    Ok(raw)
}

/// Spawn a canary child (the probe script with `args` and `limits`). The
/// child's working directory and only writable root is the probe's own
/// workspace, as in a real run. `netns` is `Some` only for the namespace
/// tier's probe: the child then runs as the pidns init behind `nsprep`,
/// with the relay directory prepared (it must exist before the spawn —
/// `nsprep` binds its relay socket there).
fn spawn_child(
    helper: &std::ffi::OsStr,
    script: &str,
    args: &[Vec<u8>],
    limits: Limits,
    root: &Path,
    netns: Option<crate::namespaces::NetnsSpec>,
) -> Result<supervisor::Running, ProbeFail> {
    let mut argv = vec![
        b"/usr/bin/perl".to_vec(),
        b"-e".to_vec(),
        script.as_bytes().to_vec(),
    ];
    argv.extend_from_slice(args);
    let root = root.to_string_lossy().into_owned();
    let prog = Program {
        argv,
        env: PROBE_ENV.iter().map(|e| e.to_vec()).collect(),
        cwd: root.clone(),
        read_only: Vec::new(),
        read_write: vec![root],
        protected: Vec::new(),
        limits,
        netns,
    };
    supervisor::spawn(&prog, helper, PROBE_RING, PROBE_WALL).map_err(|e| ProbeFail {
        probe: "spawn",
        observed: e.to_string(),
        load_shaped: load_shaped_spawn(&e),
    })
}

/// Run the canary script child and check every canary it reports, plus the
/// parent-side observations (the listener saw nothing, no file was left,
/// the sweep reaped the escapee). Returns the child's stdout (the
/// observation text).
fn run_canaries(
    helper: &std::ffi::OsStr,
    listener: &TcpListener,
    ws: &Path,
    written: &Path,
    canary: &Path,
    link: &Path,
    home: &[u8],
    netns: Option<crate::namespaces::NetnsSpec>,
    expect_sweep_kills: bool,
) -> Result<String, ProbeFail> {
    let args = vec![
        listener
            .local_addr()
            .map_err(|e| ProbeFail::new("setup", e.to_string()))?
            .port()
            .to_string()
            .into_bytes(),
        written.as_os_str().as_bytes().to_vec(),
        canary.as_os_str().as_bytes().to_vec(),
        link.as_os_str().as_bytes().to_vec(),
        home.to_vec(),
    ];
    let child = spawn_child(helper, PROBE_SCRIPT, &args, Limits::default(), ws, netns)?;
    let raw = wait_sound(child.wait(), "run")?;
    let out = String::from_utf8_lossy(&raw.stdout).into_owned();
    for name in PROBES {
        let want = format!("{name} ok\n");
        if !out.contains(&want) {
            return Err(ProbeFail::new(name, out));
        }
    }
    // FT-1, parent side: the listener must have seen no connection. Any
    // accept error other than "nothing there" is a broken measurement,
    // not a pass.
    match listener.accept() {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok((_, peer)) => {
            return Err(ProbeFail::new("net", format!("the listener saw {peer:?}")));
        }
        Err(e) => return Err(ProbeFail::new("net", format!("accept failed: {e}"))),
    }
    // FT-3, parent side: nothing may be left behind outside the roots.
    if written.exists() {
        return Err(ProbeFail::new(
            "write",
            "the file outside the roots exists".to_string(),
        ));
    }
    // FT-16-setsid, parent side. The default tier needs a swept escapee
    // (at least one kill). The namespace tier may see zero kills: the
    // kernel SIGKILLs every pidns member when its init dies, so the
    // escapee is gone before the helper's sweep looks — what must hold is
    // only the confirmed-empty verdict.
    if !raw.confirmed || (expect_sweep_kills && raw.kills < 1) {
        return Err(ProbeFail::new(
            "sweep",
            format!(
                "confirmed={} kills={} {}",
                raw.confirmed, raw.kills, raw.detail
            ),
        ));
    }
    Ok(out)
}

/// The FT-6 memory canary: under the budget, the allocation must die.
fn run_memory_canary(helper: &std::ffi::OsStr, ws: &Path) -> Result<String, ProbeFail> {
    let limits = Limits {
        memory: Some(MEM_PROBE_BUDGET),
        ..Limits::default()
    };
    let child = spawn_child(helper, MEM_PROBE_SCRIPT, &[], limits, ws, None).map_err(|mut e| {
        e.probe = "mem-spawn";
        e
    })?;
    let raw = wait_sound(child.wait(), "mem-applied")?;
    let out = String::from_utf8_lossy(&raw.stdout).into_owned();
    if !out.contains("applied\n") {
        return Err(ProbeFail::new("mem-applied", out));
    }
    if out.contains("notbounded") || matches!(raw.outcome, WaitCause::Exited(0)) {
        return Err(ProbeFail::new(
            "mem-bound",
            format!("{:?} {out}", raw.outcome),
        ));
    }
    if !raw.confirmed {
        return Err(ProbeFail::new("mem-sweep", run_observed(&raw)));
    }
    Ok(out)
}

/// The FT-5 process canary: under the cap, the burst must be bounded. The
/// rlimit is per-user, so on a busy host the cap may refuse every fork of
/// the burst at once; what must never happen is that all of
/// [`PROC_BURST`] succeed.
fn run_process_canary(helper: &std::ffi::OsStr, ws: &Path) -> Result<String, ProbeFail> {
    let limits = Limits {
        processes: Some(PROC_PROBE_CAP),
        ..Limits::default()
    };
    let child =
        spawn_child(helper, PROC_PROBE_SCRIPT, &[], limits, ws, None).map_err(|mut e| {
            e.probe = "proc-spawn";
            e
        })?;
    let raw = wait_sound(child.wait(), "proc-run")?;
    let out = String::from_utf8_lossy(&raw.stdout).into_owned();
    let mut forked = None;
    for line in out.lines() {
        if let Some(n) = line.strip_prefix("forked=") {
            if let Ok(n) = n.parse::<u32>() {
                forked = Some(n);
            }
        }
    }
    let n = forked.ok_or_else(|| ProbeFail::new("proc-run", out.clone()))?;
    if n >= PROC_BURST {
        return Err(ProbeFail::new(
            "proc-limit",
            format!("all {PROC_BURST} forks succeeded: {out}"),
        ));
    }
    if !out.contains("survived\n") {
        return Err(ProbeFail::new("proc-run", out));
    }
    if !raw.confirmed {
        return Err(ProbeFail::new("proc-sweep", run_observed(&raw)));
    }
    Ok(out)
}

/// Run the whole live probe against `helper` (this process's own binary,
/// which re-execs itself as the supervisor's `__confine` helper).
///
/// Returns the observation text the witness digests: the canaries'
/// stdout, then the memory and process canaries', each under its own
/// marker. Any refusal — a canary that was not refused, a control that did
/// not run, a sweep that did not confirm — is [`ProbeFail`], and the
/// caller must not mint.
pub fn live_probe(helper: &std::ffi::OsStr) -> Result<String, ProbeFail> {
    live_probe_inner(helper, false)
}

/// The namespace tier's live probe ([`live_probe`], through the empty
/// netns/pidns): the same canaries, with the child running as the pidns
/// init behind `nsprep` and no port granted. The observation text has the
/// same shape; the digest binds the tier's row id, so the two tiers'
/// witnesses can never stand for each other.
pub fn live_probe_netns(helper: &std::ffi::OsStr) -> Result<String, ProbeFail> {
    live_probe_inner(helper, true)
}

/// The shared probe body. `netns` selects the tier: the relay directory is
/// prepared before the spawn (nsprep binds its socket into it), and the
/// sweep-kill expectation drops (see [`run_canaries`]).
fn live_probe_inner(helper: &std::ffi::OsStr, netns: bool) -> Result<String, ProbeFail> {
    // A scratch directory of our own: the canaries need paths outside the
    // child's read-write root that only this probe created.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let dir: PathBuf =
        std::env::temp_dir().join(format!("rh-probe-{}-{}", std::process::id(), nanos));
    let io = |e: std::io::Error| ProbeFail::new("setup", e.to_string());
    let ws = dir.join("ws");
    let outside = dir.join("outside");
    std::fs::create_dir_all(&ws).map_err(io)?;
    std::fs::create_dir_all(outside.join(".ssh")).map_err(io)?;
    let canary = outside.join(".ssh").join("id_canary");
    std::fs::write(&canary, b"rh-probe-canary").map_err(io)?;
    let link = ws.join("link");
    symlink(&canary, &link).map_err(io)?;
    let written = outside.join("written");
    let listener = TcpListener::bind("127.0.0.1:0").map_err(io)?;
    listener.set_nonblocking(true).map_err(io)?;
    // The home canary reads the real home directory (FT-4's `.ssh`-shaped
    // path is planted outside the roots instead); without a `HOME` the
    // canary passes vacuously, as on the macOS probe.
    let home = std::env::var_os("HOME")
        .map(|h| h.as_bytes().to_vec())
        .unwrap_or_default();
    // The tier: on the namespace tier the relay directory must exist
    // before the spawn — `nsprep` binds its relay socket into it — and the
    // spec carries no port at all (the tier grants nothing until a port
    // is; the canaries must all be refused anyway).
    let netns_spec = if netns {
        let relay = dir.join("relay");
        std::fs::create_dir_all(&relay).map_err(io)?;
        Some(crate::namespaces::NetnsSpec {
            relay_dir: relay.to_string_lossy().into_owned(),
            bind: Vec::new(),
            connect: Vec::new(),
        })
    } else {
        None
    };

    let run = run_canaries(
        helper, &listener, &ws, &written, &canary, &link, &home, netns_spec, !netns,
    );
    let mem = run_memory_canary(helper, &ws);
    let procs = run_process_canary(helper, &ws);
    // Best effort: the scratch tree is disposable.
    let _ = std::fs::remove_dir_all(&dir);
    let run = run?;
    let mem = mem?;
    let procs = procs?;
    Ok(format!(
        "--canaries--\n{run}--memory--\n{mem}--processes--\n{procs}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_canary_list_matches_the_scripts_reported_names() {
        for name in PROBES {
            assert!(PROBE_SCRIPT.contains(&format!("r('{name}',")));
        }
        // The scripts report exactly the markers the checks look for.
        assert!(MEM_PROBE_SCRIPT.contains("applied"));
        assert!(MEM_PROBE_SCRIPT.contains("notbounded"));
        assert!(PROC_PROBE_SCRIPT.contains("forked="));
        assert!(PROC_PROBE_SCRIPT.contains("survived"));
    }

    #[test]
    fn the_escapee_ignores_term_and_leaves_the_group() {
        assert!(PROBE_SCRIPT.contains("setsid()"));
        assert!(PROBE_SCRIPT.contains("$SIG{TERM} = 'IGNORE'"));
    }

    #[test]
    fn the_canary_environment_is_exactly_the_specs() {
        assert_eq!(PROBE_ENV, &[b"RH_PROBE=1".as_slice()]);
    }

    #[test]
    fn budgets_name_their_bars() {
        assert_eq!(MEM_PROBE_BUDGET, 64 * 1024 * 1024);
        assert_eq!(PROC_PROBE_CAP, 4);
        assert_eq!(PROC_BURST, 12);
    }
}
