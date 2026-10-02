//! The hostile-task conformance suite (design §6.6) against the macOS
//! Seatbelt backend, through the real spawn seam. Each test states the case
//! it witnesses and checks the behaviour from OUTSIDE the sandbox where it
//! can (files absent, listeners silent, processes gone), not only what the
//! confined program printed. Controls run the same program unconfined to
//! show the hostile action works when nothing stops it, so a pass is not an
//! accident of a broken program.
//!
//! FT-5 (process count) and FT-6 (memory) ARE exercised here as of H2c, but
//! only in strictly self-limiting form on this owner's Mac: the fork "bomb"
//! stops itself at a small count and the memory "bomb" at a small size even
//! if the guard fails, and the memory test skips (reported) under host
//! pressure. FT-6 is bounded by a kernel-enforced per-process RLIMIT_AS
//! (measured on this host); FT-5 by the stub's member-count watchdog.
#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use harness_sandbox::conformance::Case;
use harness_sandbox::seatbelt::{Seatbelt, DOMAIN_STUB};
use harness_sandbox::{
    Backend, BackendKind, ChildStatus, ConfinedExit, ConfinedSpec, Conformed, DomainCleanup,
    Limits, Network, SpawnError, UnavailableReason,
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

/// A fresh directory tree: `ws` (the read-write root) and `outside` (never
/// granted), canonical.
struct Tree {
    root: PathBuf,
    ws: PathBuf,
    outside: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Tree {
        Tree::under(&std::env::temp_dir(), name)
    }

    fn under(base: &Path, name: &str) -> Tree {
        let base = std::fs::canonicalize(base).unwrap();
        let root = base.join(format!(
            "rh-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let ws = root.join("ws");
        let outside = root.join("outside");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        Tree { root, ws, outside }
    }

    fn spec(&self, argv: &[&str]) -> ConfinedSpec {
        ConfinedSpec {
            argv: argv.iter().map(OsString::from).collect(),
            cwd: self.ws.clone(),
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            read_only: vec![],
            read_write: vec![self.ws.clone()],
            protected: vec![],
            network: Network::None,
            limits: Limits::wall(Duration::from_secs(20)),
        }
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn run(spec: &ConfinedSpec) -> ConfinedExit {
    Seatbelt::new().spawn(spec, witness()).unwrap().wait()
}

fn perl(tree: &Tree, script: &str, args: &[&str]) -> ConfinedExit {
    let mut argv = vec![PERL, "-e", script];
    argv.extend_from_slice(args);
    run(&tree.spec(&argv))
}

/// A spec like [`Tree::spec`] but with the proxy network grant on `port`.
fn proxy_spec(t: &Tree, argv: &[&str], port: u16) -> ConfinedSpec {
    let mut s = t.spec(argv);
    s.network = Network::Proxy { port };
    s
}

/// Like [`perl`] but with the proxy network grant on `port` (§5.3).
fn proxy_perl(t: &Tree, port: u16, script: &str, args: &[&str]) -> ConfinedExit {
    let mut argv = vec![PERL, "-e", script];
    argv.extend_from_slice(args);
    run(&proxy_spec(t, &argv, port))
}

/// Run the same perl unconfined (the control).
fn control(script: &str, args: &[&str]) -> std::process::Output {
    Command::new(PERL)
        .arg("-e")
        .arg(script)
        .args(args)
        .output()
        .unwrap()
}

fn out(e: &ConfinedExit) -> String {
    String::from_utf8_lossy(&e.stdout).into_owned()
}

fn confirmed(e: &ConfinedExit) {
    assert!(
        matches!(e.domain, DomainCleanup::Confirmed { .. }),
        "domain not confirmed: {:?}; stderr {}",
        e.domain,
        String::from_utf8_lossy(&e.stderr)
    );
}

fn alive(pid: u32) -> bool {
    Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap()
        .success()
}

#[test]
fn witness_is_minted_by_the_live_probe_and_names_its_row() {
    let w = witness();
    assert_eq!(w.backend(), BackendKind::Seatbelt);
    assert_eq!(w.matrix_row(), "seatbelt-macos-h2c");
    assert!(w
        .covers(&[Case::Ft1, Case::Ft16Setsid, Case::NoBind])
        .is_ok());
    // H2c: the row now covers the whole exit set, and the witness names the
    // exact FT-5 and FT-6 bars, so the production bar passes.
    assert!(w
        .covers(harness_sandbox::conformance::H2_EXIT_CASES)
        .is_ok());
    assert_eq!(w.memory(), harness_sandbox::MemoryGuard::RlimitAddressSpace);
    assert_eq!(
        w.processes(),
        harness_sandbox::ProcessGuard::MemberCountWatchdog
    );
    assert!(harness_sandbox::require().is_ok());
}

#[test]
fn a_benign_program_runs_with_exactly_its_env_and_output() {
    let t = Tree::new("benign");
    let mut s = t.spec(&[
        PERL,
        "-e",
        "print join(',', sort keys %ENV), qq{\\n}; print STDERR qq{e\\n}; exit 3",
    ]);
    s.env.push(("RH_X".into(), "y".into()));
    let e = run(&s);
    assert_eq!(e.status, ChildStatus::Exited(3));
    assert_eq!(out(&e), "PATH,RH_X\n");
    assert_eq!(e.stderr, b"e\n", "the stub's report is removed from stderr");
    confirmed(&e);
}

/// FT-1 / FT-13: no connect, checked at the listener outside.
#[test]
fn ft1_tcp_connect_is_refused_and_nothing_arrives() {
    let t = Tree::new("ft1");
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let port = l.local_addr().unwrap().port().to_string();
    let script = "use Socket; socket(my $s,PF_INET,SOCK_STREAM,0) or die; print connect($s, sockaddr_in($ARGV[0], inet_aton(q{127.0.0.1}))) ? qq{CONNECTED\\n} : qq{refused\\n}";
    let c = control(script, &[&port]);
    assert_eq!(String::from_utf8_lossy(&c.stdout), "CONNECTED\n", "control");
    let _ = l.accept(); // drain the control's connection
    let e = perl(&t, script, &[&port]);
    assert_eq!(out(&e), "refused\n");
    assert!(matches!(l.accept(), Err(ref x) if x.kind() == std::io::ErrorKind::WouldBlock));
    // A routable address too (TEST-NET-1: never answers, so only a refusal is fast).
    let e = perl(&t, "use Socket; socket(my $s,PF_INET,SOCK_STREAM,0) or die; print connect($s, sockaddr_in(80, inet_aton(q{192.0.2.1}))) ? qq{CONNECTED\\n} : qq{refused $!\\n}", &[]);
    assert!(
        out(&e).starts_with("refused Operation not permitted"),
        "{}",
        out(&e)
    );
    confirmed(&e);
}

/// D31: no bind on the shared network stack, loopback included.
#[test]
fn d31_bind_is_refused_even_on_loopback() {
    let t = Tree::new("bind");
    let script = "use Socket; socket(my $s,PF_INET,SOCK_STREAM,0) or die; print bind($s, sockaddr_in(0, inet_aton(q{127.0.0.1}))) ? qq{BOUND\\n} : qq{refused\\n}; socket(my $u,PF_INET,SOCK_DGRAM,0) or die; print bind($u, sockaddr_in(0, inet_aton(q{127.0.0.1}))) ? qq{BOUND\\n} : qq{refused\\n}";
    assert_eq!(
        String::from_utf8_lossy(&control(script, &[]).stdout),
        "BOUND\nBOUND\n"
    );
    assert_eq!(out(&perl(&t, script, &[])), "refused\nrefused\n");
}

/// FT-3: writes outside the workspace (a home-shaped dir and a sibling
/// run's directory) fail and leave nothing.
#[test]
fn ft3_writes_outside_fail_and_leave_nothing() {
    let t = Tree::new("ft3");
    let sibling = t.outside.join("runs").join("other-run").join("workspace");
    std::fs::create_dir_all(&sibling).unwrap();
    let a = t.outside.join("canary");
    let b = sibling.join("canary");
    let script = "for (@ARGV) { print open(my $f, q{>}, $_) ? qq{WROTE\\n} : qq{refused\\n} } print open(my $g, q{>}, q{inside}) ? qq{inside\\n} : qq{NO\\n}";
    let h = PathBuf::from(std::env::var("HOME").unwrap())
        .join(format!(".rh-ft3-canary-{}", std::process::id()));
    let e = perl(
        &t,
        script,
        &[
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            h.to_str().unwrap(),
        ],
    );
    let in_home = h.exists();
    let _ = std::fs::remove_file(&h);
    assert_eq!(out(&e), "refused\nrefused\nrefused\ninside\n");
    assert!(!a.exists() && !b.exists() && !in_home);
    assert!(t.ws.join("inside").exists());
}

/// FT-4: a planted `.ssh`-shaped secret is unreadable, the real home is not
/// even listable, and the harness's environment does not leak.
#[test]
fn ft4_secrets_and_home_are_unreadable_and_env_is_built() {
    let t = Tree::new("ft4");
    std::fs::create_dir_all(t.outside.join(".ssh")).unwrap();
    let key = t.outside.join(".ssh").join("id_ed25519");
    std::fs::write(&key, "rh-canary-secret").unwrap();
    let home = std::env::var("HOME").unwrap();
    let script = "print open(my $f, q{<}, $ARGV[0]) ? qq{READ\\n} : qq{refused\\n}; print opendir(my $d, $ARGV[1]) ? qq{LISTED\\n} : qq{refused\\n}; print open(my $g, q{<}, $ARGV[1].q{/Library/Preferences/.GlobalPreferences.plist}) ? qq{READ\\n} : qq{refused\\n}; print exists $ENV{HOME} || exists $ENV{USER} || exists $ENV{SSH_AUTH_SOCK} ? qq{LEAK\\n} : qq{clean\\n}";
    let c = control(script, &[key.to_str().unwrap(), &home]);
    assert_eq!(
        String::from_utf8_lossy(&c.stdout),
        "READ\nLISTED\nREAD\nLEAK\n",
        "control"
    );
    let e = perl(&t, script, &[key.to_str().unwrap(), &home]);
    assert_eq!(out(&e), "refused\nrefused\nrefused\nclean\n");
}

/// FT-7: a disk fill stops at the file-size cap.
#[test]
fn ft7_disk_fill_stops_at_the_file_size_cap() {
    let t = Tree::new("ft7");
    let mut s = t.spec(&[PERL, "-e", "$SIG{XFSZ}=q{IGNORE}; open(my $f, q{>}, q{fill}) or die; my $b = q{x} x 65536; for (1..64) { syswrite($f, $b) or do { print qq{stopped\\n}; exit 0 } } print qq{FILLED\\n}"]);
    s.limits.file_size = Some(256 * 1024);
    let e = run(&s);
    assert_eq!(out(&e), "stopped\n");
    assert!(std::fs::metadata(t.ws.join("fill")).unwrap().len() <= 256 * 1024);
}

/// FT-8: a busy loop is killed at the wall clock, and the call ends
/// within wall + grace.
#[test]
fn ft8_busy_loop_is_killed_at_the_wall_clock() {
    let t = Tree::new("ft8");
    let mut s = t.spec(&[PERL, "-e", "$SIG{TERM}=q{IGNORE}; 1 while 1"]);
    s.limits.wall = Duration::from_millis(500);
    let start = Instant::now();
    let e = run(&s);
    assert_eq!(e.status, ChildStatus::TimedOut);
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
    confirmed(&e);
}

/// CPU limit: a busy loop dies of SIGXCPU before the wall clock.
#[test]
fn cpu_limit_kills_a_busy_loop() {
    let t = Tree::new("cpu");
    let mut s = t.spec(&[PERL, "-e", "1 while 1"]);
    s.limits.cpu = Some(Duration::from_secs(1));
    s.limits.wall = Duration::from_secs(15);
    let e = run(&s);
    assert_eq!(e.status, ChildStatus::Signaled(24), "SIGXCPU");
}

/// Host memory pressure, so the FT-6 test can skip rather than push a
/// loaded machine (the owner's working Mac). Normal is level 1.
fn under_memory_pressure() -> Option<String> {
    let level = Command::new("/usr/sbin/sysctl")
        .args(["-n", "kern.memorystatus_vm_pressure_level"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    if level != "1" && !level.is_empty() {
        return Some(format!("kern.memorystatus_vm_pressure_level={level}"));
    }
    let swap = Command::new("/usr/sbin/sysctl")
        .args(["-n", "vm.swapusage"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    // "total = ... used = ... free = 921.62M ...": skip if free swap is tiny.
    let free_mib = swap
        .split("free = ")
        .nth(1)
        .and_then(|s| s.split('M').next())
        .and_then(|s| s.trim().parse::<f64>().ok())
        .unwrap_or(f64::INFINITY);
    (free_mib < 256.0).then(|| format!("free swap {free_mib} MiB"))
}

/// FT-6: a memory bomb is bounded by the per-process `RLIMIT_AS` the stub
/// sets (H2c). SELF-LIMITING: the program allocates at most 40 x 8 MiB =
/// 320 MiB even if the guard fails, and the test skips under host pressure.
/// Control: the same program unconfined allocates and reaches FILLED.
#[test]
fn ft6_memory_bomb_is_bounded_by_rlimit_as() {
    if let Some(why) = under_memory_pressure() {
        eprintln!("SKIPPED ft6: host under memory pressure ({why})");
        return;
    }
    let t = Tree::new("ft6");
    // Allocate AND touch in 8 MiB steps, hard-capped at 40 steps (320 MiB).
    let bomb = "$|=1; my @k; for my $i (1..40){ my $s = q{X} x (8*1024*1024); substr($s,0,4096,q{Y}x4096); push @k,$s } print qq{FILLED\\n}";
    let c = control(bomb, &[]);
    assert_eq!(
        String::from_utf8_lossy(&c.stdout),
        "FILLED\n",
        "control should allocate freely"
    );
    let mut s = t.spec(&[PERL, "-e", bomb]);
    s.limits.memory = Some(128 * 1024 * 1024); // budget < the 320 MiB attempt
    let e = run(&s);
    assert!(
        !out(&e).contains("FILLED"),
        "the memory bomb was not bounded: {:?} {}",
        e.status,
        out(&e)
    );
    assert_ne!(e.status, ChildStatus::Exited(0), "bomb should have died");
    confirmed(&e);
}

/// FT-5: a fork bomb is stopped by the stub's member-count watchdog (H2c).
/// SELF-LIMITING: at most 40 extra processes even if the guard fails, and
/// each self-exits after a few seconds. Control: unconfined, the same burst
/// (exiting at once) runs with nothing to stop it.
#[test]
fn ft5_fork_bomb_is_stopped_by_the_watchdog() {
    let t = Tree::new("ft5");
    // arg: seconds each child lives. 0 for the control (fast), a few seconds
    // confined so the burst outlives a watchdog poll (~240 ms).
    let burst = "use POSIX (); $|=1; my $live=$ARGV[0]; my @k; for(1..40){ my $p=fork(); if(defined $p && $p==0){ POSIX::_exit(0) if !$live; sleep $live; POSIX::_exit(0) } push @k,$p if $p } print qq{forked\\n}; if(!$live){ waitpid($_,0) for @k; print qq{DONE\\n} } else { sleep 20 }";
    let c = control(burst, &["0"]);
    assert_eq!(
        String::from_utf8_lossy(&c.stdout),
        "forked\nDONE\n",
        "control should fork freely"
    );
    let mut s = t.spec(&[PERL, "-e", burst, "6"]);
    s.limits.processes = Some(8);
    s.limits.wall = Duration::from_secs(30);
    let start = Instant::now();
    let e = run(&s);
    assert_eq!(
        e.status,
        ChildStatus::ProcessLimit,
        "the watchdog should have stopped the fork bomb: {:?} {}",
        e.status,
        String::from_utf8_lossy(&e.stderr)
    );
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "the watchdog fired far too late: {:?}",
        start.elapsed()
    );
    confirmed(&e);
}

/// FT-6/LOW-4: a hard link from a file OUTSIDE the read-write roots into the
/// workspace is refused, so an outside file's content cannot be aliased under
/// a workspace path (Seatbelt rules are path-based). Control: unconfined the
/// same link succeeds.
#[test]
fn hard_link_from_outside_into_workspace_is_refused() {
    let t = Tree::new("hardlink");
    let marker = t.outside.join("marker");
    std::fs::write(&marker, "rh-hardlink-canary").unwrap();
    // Control: unconfined ln succeeds and the content is readable.
    let ctl = t.ws.join("ctl-link");
    let c = Command::new("/bin/ln")
        .args([marker.to_str().unwrap(), ctl.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(c.success(), "control ln should succeed");
    assert_eq!(std::fs::read_to_string(&ctl).unwrap(), "rh-hardlink-canary");
    std::fs::remove_file(&ctl).unwrap();
    // Confined: link() and reading are both refused; nothing appears.
    let script = "my ($src,$dst)=@ARGV; print link($src,$dst) ? qq{LINKED\\n} : qq{refused\\n}; print open(my $f,q{<},$dst) ? qq{read-link\\n} : qq{no-link\\n}; print open(my $g,q{<},$src) ? qq{read-direct\\n} : qq{no-direct\\n}";
    let dst = t.ws.join("x");
    let e = perl(
        &t,
        script,
        &[marker.to_str().unwrap(), dst.to_str().unwrap()],
    );
    assert_eq!(out(&e), "refused\nno-link\nno-direct\n");
    assert!(!dst.exists(), "the hard link must not exist");
    assert_eq!(
        std::fs::metadata(&marker).unwrap().nlink(),
        1,
        "the outside file must not have gained a link"
    );
    confirmed(&e);
}

/// FT-9: protected paths inside the workspace are read-only; the digest
/// (here: the bytes) is unchanged, and no new file appears under them.
#[test]
fn ft9_protected_paths_are_read_only() {
    let t = Tree::new("ft9");
    let git = t.ws.join(".git");
    std::fs::create_dir_all(&git).unwrap();
    std::fs::write(git.join("config"), "orig").unwrap();
    std::fs::write(t.ws.join("tests.rs"), "orig").unwrap();
    let mut s = t.spec(&[PERL, "-e", "for (@ARGV) { print open(my $f, q{>>}, $_) ? qq{WROTE\\n} : qq{refused\\n} } print unlink(q{tests.rs}) ? qq{DELETED\\n} : qq{kept\\n}; print rename(q{.git}, q{g2}) ? qq{MOVED\\n} : qq{kept\\n}; print open(my $r, q{<}, q{.git/config}) ? qq{readable\\n} : qq{NOREAD\\n}", ".git/config", ".git/new", "tests.rs"]);
    s.protected = vec![git.clone(), t.ws.join("tests.rs")];
    let e = run(&s);
    assert_eq!(out(&e), "refused\nrefused\nrefused\nkept\nkept\nreadable\n");
    assert_eq!(std::fs::read_to_string(git.join("config")).unwrap(), "orig");
    assert_eq!(
        std::fs::read_to_string(t.ws.join("tests.rs")).unwrap(),
        "orig"
    );
    assert!(!git.join("new").exists());
}

/// P-29: `.git` inside the workspace is a read-only overlay for a sandboxed
/// command, the way the exec tools fill `ConfinedSpec.protected`: a shell
/// append into `.git/config` fails and the file is byte-unchanged, while
/// the unconfined control shows the same append works.
#[test]
fn exec_cannot_write_dot_git() {
    let t = Tree::new("p29-git");
    let git = t.ws.join(".git");
    std::fs::create_dir_all(&git).unwrap();
    let config = git.join("config");
    std::fs::write(&config, "orig\n").unwrap();
    let script = "print qq{APPENDED\\n} if open(my $f, q{>>}, $ARGV[0]); print $f qq{tampered\\n}";
    let target = config.to_str().unwrap();
    // The control: unconfined, the shell appends. Rewind the file after.
    let ctl = control(script, &[target]);
    assert!(
        ctl.status.success() && String::from_utf8_lossy(&ctl.stdout).contains("APPENDED"),
        "the control shows the append works unconfined"
    );
    std::fs::write(&config, "orig\n").unwrap();
    let mut s = t.spec(&["/bin/sh", "-c", script, target]);
    s.protected = vec![git.clone()];
    let e = run(&s);
    confirmed(&e);
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        "orig\n",
        ".git/config is byte-unchanged"
    );
}

/// FT-10: a state_root-shaped directory (journal, config) outside the
/// grants is neither readable nor listable nor writable.
#[test]
fn ft10_harness_state_is_not_even_readable() {
    let t = Tree::new("ft10");
    let run_dir = t
        .outside
        .join("state")
        .join("runs")
        .join("r1")
        .join("attempt-1");
    std::fs::create_dir_all(&run_dir).unwrap();
    let journal = run_dir.join("journal.jsonl");
    std::fs::write(&journal, "{}\n").unwrap();
    let script = "print open(my $f, q{<}, $ARGV[0]) ? qq{READ\\n} : qq{refused\\n}; print opendir(my $d, $ARGV[1]) ? qq{LISTED\\n} : qq{refused\\n}; print open(my $g, q{>>}, $ARGV[0]) ? qq{WROTE\\n} : qq{refused\\n}";
    let e = perl(
        &t,
        script,
        &[journal.to_str().unwrap(), run_dir.to_str().unwrap()],
    );
    assert_eq!(out(&e), "refused\nrefused\nrefused\n");
    assert_eq!(std::fs::read_to_string(&journal).unwrap(), "{}\n");
}

/// FT-11: a unix socket listener outside the workspace is unreachable, and
/// so is one inside it (deny network* covers unix connects).
#[test]
fn ft11_unix_socket_connect_fails() {
    // Socket paths are short (SUN_LEN): use /tmp.
    let t = Tree::under(Path::new("/tmp"), "11");
    let outside = t.outside.join("s.sock");
    let inside = t.ws.join("s.sock");
    let lo = std::os::unix::net::UnixListener::bind(&outside).unwrap();
    let li = std::os::unix::net::UnixListener::bind(&inside).unwrap();
    lo.set_nonblocking(true).unwrap();
    li.set_nonblocking(true).unwrap();
    let script = "use Socket; for (@ARGV) { socket(my $s, PF_UNIX, SOCK_STREAM, 0) or die; print connect($s, pack_sockaddr_un($_)) ? qq{CONNECTED\\n} : qq{refused\\n} }";
    let e = perl(
        &t,
        script,
        &[outside.to_str().unwrap(), inside.to_str().unwrap()],
    );
    assert_eq!(out(&e), "refused\nrefused\n");
    assert!(lo.accept().is_err() && li.accept().is_err());
}

/// FT-12: a symlink in the workspace pointing outside is not followed by
/// an exec'd program (the kernel view decides), for reading, writing, or
/// as a directory; and a FIFO in the workspace cannot be opened (FT-27).
#[test]
fn ft12_symlink_escape_is_refused_by_the_kernel() {
    let t = Tree::new("ft12");
    std::fs::write(t.outside.join("secret"), "rh-canary").unwrap();
    std::os::unix::fs::symlink(t.outside.join("secret"), t.ws.join("s")).unwrap();
    std::os::unix::fs::symlink(&t.outside, t.ws.join("d")).unwrap();
    let st = Command::new("/usr/bin/mkfifo")
        .arg(t.ws.join("fifo"))
        .status()
        .unwrap();
    assert!(st.success());
    let script = "print open(my $f, q{<}, q{s}) ? qq{READ\\n} : qq{refused\\n}; print open(my $g, q{>}, q{d/new}) ? qq{WROTE\\n} : qq{refused\\n}; print opendir(my $h, q{d}) ? qq{LISTED\\n} : qq{refused\\n}; print sysopen(my $p, q{fifo}, 0|4) ? qq{FIFO\\n} : qq{refused\\n}";
    let e = perl(&t, script, &[]);
    assert_eq!(out(&e), "refused\nrefused\nrefused\nrefused\n");
    assert!(!t.outside.join("new").exists());
}

/// FT-15: no resolver is reachable. A name that only DNS can answer does
/// not resolve (`localhost` is not asked: it comes from `/etc/hosts`, a
/// file, not a resolver). The control resolves the same kind of name only
/// when the host itself has DNS, so it is informative, not required.
#[test]
fn ft15_no_dns_resolution() {
    let t = Tree::new("ft15");
    let script = "my @a = gethostbyname(q{apple.com}); print @a ? qq{RESOLVED\\n} : qq{none\\n}";
    let c = control(script, &[]);
    eprintln!(
        "ft15 control (host DNS): {}",
        String::from_utf8_lossy(&c.stdout).trim()
    );
    assert_eq!(out(&perl(&t, script, &[])), "none\n");
}

const ESCAPE: &str = "use POSIX (); my ($file, $setsid, $killstub) = @ARGV; my $p = fork(); if ($p == 0) { POSIX::setsid() if $setsid; if (fork()) { POSIX::_exit(0) } $SIG{TERM} = q{IGNORE}; open(my $o, q{>}, $file) or die; print $o $$; close $o; close STDOUT; close STDERR; sleep 60; POSIX::_exit(0) } waitpid($p, 0); for (1..200) { last if -s $file; select(undef, undef, undef, 0.01) } kill(q{KILL}, getppid()) if $killstub; print qq{parent done\\n}";

fn escapee(t: &Tree, setsid: bool, killstub: bool) -> (ConfinedExit, u32) {
    let pidfile = t.ws.join("escapee.pid");
    let e = perl(
        t,
        ESCAPE,
        &[
            pidfile.to_str().unwrap(),
            if setsid { "1" } else { "" },
            if killstub { "1" } else { "" },
        ],
    );
    let pid: u32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    (e, pid)
}

/// FT-16: a double-forked, SIGTERM-ignoring orphan is gone after the call.
#[test]
fn ft16_double_forked_orphan_is_gone() {
    let t = Tree::new("ft16");
    let (e, pid) = escapee(&t, false, false);
    confirmed(&e);
    assert!(!alive(pid), "orphan {pid} survived");
}

/// FT-16 with `setsid()`: the descendant left the process group, and the
/// sandbox sweep still kills it (a process-group kill alone would not:
/// OD-5 review M-5).
#[test]
fn ft16_setsid_escapee_is_swept() {
    let t = Tree::new("ft16s");
    let (e, pid) = escapee(&t, true, false);
    confirmed(&e);
    assert!(matches!(e.domain, DomainCleanup::Confirmed { kills } if kills >= 1));
    assert!(!alive(pid), "setsid escapee {pid} survived");
}

/// The named gap: a member kills the domain stub first, then its setsid'd
/// descendant survives. The harness must say so (Unconfirmed), never
/// report a clean stop. The test cleans up the survivor it caused.
#[test]
fn ft16_stub_killed_first_is_reported_unconfirmed() {
    let t = Tree::new("ft16k");
    let (e, pid) = escapee(&t, true, true);
    let survived = alive(pid);
    if survived {
        let _ = Command::new("/bin/kill")
            .args(["-KILL", &pid.to_string()])
            .status();
    }
    assert!(
        matches!(e.domain, DomainCleanup::Unconfirmed(_)),
        "a killed stub must never read as confirmed: {:?}",
        e.domain
    );
    assert!(
        survived,
        "expected the known gap (survivor) to be observable here"
    );
}

/// FT-17: LaunchServices is unreachable, so nothing can be launched
/// outside the sandbox through it (checked with a read-only query, never
/// with `open`).
#[test]
fn ft17_launchservices_is_unreachable() {
    let t = Tree::new("ft17");
    let c = Command::new("/usr/bin/lsappinfo")
        .args(["info", "-only", "pid", "Finder"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&c.stdout).contains("pid"),
        "control"
    );
    let e = run(&t.spec(&["/usr/bin/lsappinfo", "info", "-only", "pid", "Finder"]));
    // LOW-2: prove the confined binary actually RAN (a real exit, not
    // ExecFailed), so an exec failure with empty output cannot masquerade as
    // "mach blocked". lsappinfo exits 0 but, with no mach-lookup, returns no
    // pid. (Break-it: drop /usr/bin from the exec allow list -> ExecFailed
    // here.)
    assert_eq!(e.status, ChildStatus::Exited(0), "lsappinfo did not run");
    assert!(!out(&e).contains("pid"), "{}", out(&e));
    confirmed(&e);
}

/// FT-18: the keychain service is unreachable.
#[test]
fn ft18_keychain_service_is_unreachable() {
    let t = Tree::new("ft18");
    let c = Command::new("/usr/bin/security")
        .arg("list-keychains")
        .output()
        .unwrap();
    assert!(c.status.success(), "control");
    let e = run(&t.spec(&["/usr/bin/security", "list-keychains"]));
    // LOW-2: prove the binary RAN (a real exit code, not ExecFailed) AND
    // that it failed without listing a keychain, so exec failure cannot pass
    // for a mach denial. security exits non-zero when the service is
    // unreachable. (Break-it: drop /usr/bin from the exec allow list ->
    // ExecFailed here, so the Exited(_) assertion fails.)
    assert!(
        matches!(e.status, ChildStatus::Exited(n) if n != 0),
        "security did not run (or unexpectedly succeeded): {:?}",
        e.status
    );
    assert!(!out(&e).contains("keychain"));
    confirmed(&e);
}

// The proxy-profile cases (§5.3, P-39e): the profile grants exactly one
// loopback port — the harness pump's — where the `port` argument of each
// test is a listener the TEST process holds, standing in for the pump or,
// in FT-19, for the model server.

/// Positive control for the whole proxy section (FT-13p's granted arm):
/// under `Network::Proxy`, the confined fetcher can connect to the granted
/// loopback port and exchange bytes with the harness-side pump.
#[test]
fn granted_port_connects() {
    let t = Tree::new("ft13-granted");
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let port = l.local_addr().unwrap().port();
    let script = "use Socket; socket(my $s,PF_INET,SOCK_STREAM,0) or die; connect($s, sockaddr_in($ARGV[0], inet_aton(q{127.0.0.1}))) or die; send($s, q{ping}, 0) or die; my $b; recv($s, $b, 8, 0); print qq{got:$b\\n}";
    let pump = std::thread::spawn(move || {
        let mut c = None;
        for _ in 1..100 {
            if let Ok((s, _)) = l.accept() {
                c = Some(s);
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let mut c = c.expect("the fetcher's connection never arrived");
        use std::io::{Read, Write};
        let mut buf = [0u8; 4];
        c.read_exact(&mut buf).expect("the ping must arrive");
        assert_eq!(&buf, b"ping");
        c.write_all(b"ok").expect("the pump can answer");
    });
    let e = proxy_perl(&t, port, script, &[&port.to_string()]);
    pump.join().unwrap();
    assert_eq!(out(&e), "got:ok\n", "the pump's answer must come back");
    confirmed(&e);
}

/// FT-13 under the proxy profile (FT-13p): a direct connect to a routable
/// address is refused, while the granted port still connects (the positive
/// control, so the refusal is the profile's doing, not a broken program).
#[test]
fn ft13_proxy_direct_connect_refused() {
    let t = Tree::new("ft13p");
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let port = l.local_addr().unwrap().port().to_string();
    let granted = "use Socket; socket(my $s,PF_INET,SOCK_STREAM,0) or die; print connect($s, sockaddr_in($ARGV[0], inet_aton(q{127.0.0.1}))) ? qq{CONNECTED\\n} : qq{refused\\n}";
    let direct = "use Socket; socket(my $s,PF_INET,SOCK_STREAM,0) or die; print connect($s, sockaddr_in(80, inet_aton(q{192.0.2.1}))) ? qq{CONNECTED\\n} : qq{refused $!\\n}";
    let e = proxy_perl(&t, port.parse().unwrap(), granted, &[&port]);
    assert_eq!(out(&e), "CONNECTED\n", "the granted port must still work");
    let _ = l.accept(); // drain the fetcher's connection
    let e = proxy_perl(&t, port.parse().unwrap(), direct, &[]);
    assert!(
        out(&e).starts_with("refused Operation not permitted"),
        "{}",
        out(&e)
    );
    assert!(matches!(l.accept(), Err(ref x) if x.kind() == std::io::ErrorKind::WouldBlock));
    confirmed(&e);
}

/// FT-15 under the proxy profile (FT-15p): no resolver is reachable, even
/// with one loopback port granted (no DNS exfiltration channel).
#[test]
fn ft15_proxy_no_resolver() {
    let t = Tree::new("ft15p");
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let script = "my @a = gethostbyname(q{apple.com}); print @a ? qq{RESOLVED\\n} : qq{none\\n}";
    let c = control(script, &[]);
    eprintln!(
        "ft15p control (host DNS): {}",
        String::from_utf8_lossy(&c.stdout).trim()
    );
    let e = proxy_perl(&t, port, script, &[]);
    assert_eq!(out(&e), "none\n");
    confirmed(&e);
}

/// FT-19: any loopback port other than the granted one is refused, even
/// with a listener standing in for the model server there (§6.5: the model
/// server must not be reachable from any sandbox).
#[test]
fn ft19_other_loopback_port_refused() {
    let t = Tree::new("ft19");
    let pump = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let model = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    pump.set_nonblocking(true).unwrap();
    model.set_nonblocking(true).unwrap();
    let pump_port = pump.local_addr().unwrap().port();
    let model_port = model.local_addr().unwrap().port().to_string();
    let script = "use Socket; for my $a ([q{granted},$ARGV[0]],[q{model},$ARGV[1]]) { socket(my $s,PF_INET,SOCK_STREAM,0) or die; print $a->[0], connect($s, sockaddr_in($a->[1], inet_aton(q{127.0.0.1}))) ? qq{ CONNECTED\\n} : qq{ refused\\n} }";
    let e = proxy_perl(
        &t,
        pump_port,
        script,
        &[&pump_port.to_string(), &model_port],
    );
    assert_eq!(out(&e), "granted CONNECTED\nmodel refused\n");
    assert!(matches!(model.accept(), Err(ref x) if x.kind() == std::io::ErrorKind::WouldBlock));
    confirmed(&e);
}

/// FT-20: no bind and no listen, even under the proxy profile (the
/// outbound allow is not a listening grant).
#[test]
fn ft20_proxy_no_listen() {
    let t = Tree::new("ft20");
    let script = "use Socket; socket(my $s,PF_INET,SOCK_STREAM,0) or die; print bind($s, sockaddr_in(0, inet_aton(q{127.0.0.1}))) ? qq{BOUND\\n} : qq{refused\\n}; socket(my $u,PF_INET,SOCK_DGRAM,0) or die; print bind($u, sockaddr_in(0, inet_aton(q{127.0.0.1}))) ? qq{BOUND\\n} : qq{refused\\n}";
    let c = control(script, &[]);
    assert_eq!(
        String::from_utf8_lossy(&c.stdout),
        "BOUND\nBOUND\n",
        "control"
    );
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let e = proxy_perl(&t, port, script, &[]);
    assert_eq!(out(&e), "refused\nrefused\n");
    confirmed(&e);
}

/// FT-17 and FT-18 re-run under the proxy profile: no mach-lookup grant
/// comes with the network allow, so LaunchServices and the keychain stay
/// unreachable.
#[test]
fn ft17_ft18_hold_under_proxy_profile() {
    let t = Tree::new("ft17-18p");
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let c = Command::new("/usr/bin/lsappinfo")
        .args(["info", "-only", "pid", "Finder"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&c.stdout).contains("pid"),
        "control"
    );
    let e = run(&proxy_spec(
        &t,
        &["/usr/bin/lsappinfo", "info", "-only", "pid", "Finder"],
        port,
    ));
    assert_eq!(e.status, ChildStatus::Exited(0), "lsappinfo did not run");
    assert!(!out(&e).contains("pid"), "{}", out(&e));
    confirmed(&e);
    let c = Command::new("/usr/bin/security")
        .arg("list-keychains")
        .output()
        .unwrap();
    assert!(c.status.success(), "control");
    let e = run(&proxy_spec(
        &t,
        &["/usr/bin/security", "list-keychains"],
        port,
    ));
    assert!(
        matches!(e.status, ChildStatus::Exited(n) if n != 0),
        "security did not run (or unexpectedly succeeded): {:?}",
        e.status
    );
    assert!(!out(&e).contains("keychain"));
    confirmed(&e);
}

/// INV-6: a witness from another backend is refused, and a spec the
/// backend cannot honour is refused before anything starts. (H2c: memory and
/// process caps ARE enforceable now, so the unenforceable/invalid cases here
/// are an out-of-range limit and a zero proxy port; P-39e: a real proxy
/// port now spawns, and FT-13-proxy above bounds what it allows.)
#[test]
fn inv6_spawn_needs_this_backends_witness_and_an_enforceable_spec() {
    let t = Tree::new("inv6");
    let linux = harness_sandbox::linux::Linux;
    assert!(matches!(
        linux.spawn(&t.spec(&["/bin/echo"]), witness()),
        Err(SpawnError::WrongWitness)
    ));
    // A memory budget the backend cannot frame (over the bound) is refused
    // before start, not accepted and then failed late.
    let mut s = t.spec(&["/bin/echo"]);
    s.limits.memory = Some(u64::MAX);
    assert!(matches!(
        Seatbelt::new().spawn(&s, witness()),
        Err(SpawnError::Spec(_))
    ));
    // A reasonable memory budget, by contrast, is now accepted (FT-6).
    let mut s = t.spec(&["/bin/echo"]);
    s.limits.memory = Some(256 * 1024 * 1024);
    assert!(Seatbelt::new().spawn(&s, witness()).is_ok());
    // A zero proxy port is refused before start (§5.3).
    let mut s = t.spec(&["/bin/echo"]);
    s.network = Network::Proxy { port: 0 };
    assert!(matches!(
        Seatbelt::new().spawn(&s, witness()),
        Err(SpawnError::Spec(_))
    ));
    // A real port is accepted by this Seatbelt-capable backend and spawns;
    // what that profile allows is exactly FT-13-proxy/FT-15-proxy/FT-19/
    // FT-20 above, and the positive control `granted_port_connects`.
    let mut s = t.spec(&["/bin/echo"]);
    s.network = Network::Proxy { port: 8080 };
    assert!(Seatbelt::new().spawn(&s, witness()).is_ok());
}

/// Refusal path: without its primitives the backend mints nothing.
#[test]
fn a_missing_primitive_refuses_the_witness() {
    let u = Seatbelt::new()
        .with_primitive_paths("/nonexistent/sandbox-exec".into(), PERL.into())
        .probe()
        .unwrap_err();
    assert_eq!(
        u.reason,
        UnavailableReason::PrimitiveMissing("/usr/bin/sandbox-exec")
    );
    let u = Seatbelt::new()
        .with_primitive_paths("/usr/bin/sandbox-exec".into(), "/nonexistent/perl".into())
        .probe()
        .unwrap_err();
    assert_eq!(
        u.reason,
        UnavailableReason::PrimitiveMissing("/usr/bin/perl")
    );
}

/// A program the sandbox cannot exec is reported as such.
#[test]
fn exec_outside_the_allowed_paths_fails() {
    let t = Tree::new("exec");
    let prog = t.outside.join("prog");
    std::fs::copy("/bin/echo", &prog).unwrap();
    let e = run(&t.spec(&[prog.to_str().unwrap(), "hi"]));
    assert_eq!(e.status, ChildStatus::ExecFailed);
    confirmed(&e);
}

/// Output is capped, and a flood does not block the call.
#[test]
fn output_is_capped_without_blocking() {
    let t = Tree::new("cap");
    let mut s = t.spec(&[PERL, "-e", "print q{x} x 5000000"]);
    s.limits.output_bytes = 1000;
    let e = run(&s);
    assert_eq!(e.stdout.len(), 1000);
    assert!(e.stdout_truncated);
    assert_eq!(e.status, ChildStatus::Exited(0));
}

/// FT-2: a build script is confined like the program: a real `cargo build`
/// (the rustup 1.85.0 toolchain as a read-only root, the Xcode linker as
/// another) runs inside the sandbox, compiles and links, and its build
/// script's connect to a harness listener is refused. Skips, loudly, where
/// that toolchain is not installed (it is not a CI assumption yet).
#[test]
fn ft2_build_script_network_is_refused_under_real_cargo() {
    let home = PathBuf::from(std::env::var("HOME").unwrap());
    let tc = home.join(".rustup/toolchains/1.85.0-aarch64-apple-darwin");
    let dev = PathBuf::from("/Library/Developer/CommandLineTools");
    if !tc.join("bin/cargo").exists() || !dev.exists() {
        eprintln!("SKIPPED ft2: toolchain or Xcode missing");
        return;
    }
    let t = Tree::new("ft2");
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let port = l.local_addr().unwrap().port();
    let p = t.ws.join("p");
    std::fs::create_dir_all(p.join("src")).unwrap();
    std::fs::write(
        p.join("Cargo.toml"),
        "[package]\nname = \"ft2\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(
        p.join("src/main.rs"),
        "fn main() { println!(\"built\"); }\n",
    )
    .unwrap();
    std::fs::write(
        p.join("build.rs"),
        format!("fn main() {{ let r = match std::net::TcpStream::connect(\"127.0.0.1:{port}\") {{ Ok(_) => \"CONNECTED\".to_string(), Err(e) => format!(\"refused: {{e}}\") }}; std::fs::write(\"ft2-result\", r).unwrap(); }}\n"),
    )
    .unwrap();
    std::fs::create_dir_all(t.ws.join("tmp")).unwrap();
    let cargo = tc.join("bin/cargo");
    let mut s = t.spec(&[cargo.to_str().unwrap(), "run", "--offline", "-q"]);
    s.cwd = p.clone();
    // What cargo and the linker need beyond the base profile (spike S-M1
    // material): the system TLS config libressl reads at start.
    s.read_only = vec![tc.clone(), dev.clone(), "/private/etc/ssl".into()];
    s.env = vec![
        (
            "PATH".into(),
            format!("{}:/usr/bin:/bin", tc.join("bin").display()).into(),
        ),
        ("HOME".into(), t.ws.clone().into()),
        ("CARGO_HOME".into(), t.ws.join("cargo-home").into()),
        ("TMPDIR".into(), t.ws.join("tmp").into()),
        ("DEVELOPER_DIR".into(), dev.clone().into()),
    ];
    s.limits.wall = Duration::from_secs(120);
    let e = run(&s);
    let err = String::from_utf8_lossy(&e.stderr).into_owned();
    assert_eq!(e.status, ChildStatus::Exited(0), "cargo failed: {err}");
    assert_eq!(out(&e), "built\n");
    let r = std::fs::read_to_string(p.join("ft2-result")).unwrap();
    assert!(r.starts_with("refused: Operation not permitted"), "{r}");
    assert!(matches!(l.accept(), Err(ref x) if x.kind() == std::io::ErrorKind::WouldBlock));
    confirmed(&e);
}

/// The stub's frame for `argv` with no environment and no limits.
fn frame(argv: &[&str]) -> String {
    let mut f = format!("rh-stub/1\nlim 0 0 0 0\n{}\n", argv.len());
    for a in argv {
        f.push_str(&format!("{}\n{a}", a.len()));
    }
    f.push_str("0\n");
    f
}

const START_REFUSED: &str = "rh-stub/1 canary status=-2 end=start kills=0 exec=none\n";

/// Review follow-up 1: the stub's start check. The stub is run NESTED
/// inside a correctly confined call, as the child of a shell that is a
/// member of the same sandbox instance, so signal 0 to its parent
/// succeeds: the filter cannot be shown to hold, and the stub must refuse
/// before reading its frame or starting anything. Harmless even if the
/// check were broken: the outer profile keeps the kernel filter in force,
/// so a nested sweep could reach only this sandbox's own members.
#[test]
fn stub_refuses_to_start_when_its_parent_is_not_refused() {
    let t = Tree::new("canary1");
    std::fs::write(t.ws.join("stub.pl"), DOMAIN_STUB).unwrap();
    let marker = t.ws.join("ran");
    std::fs::write(
        t.ws.join("frame"),
        frame(&["/usr/bin/touch", marker.to_str().unwrap()]),
    )
    .unwrap();
    let e = run(&t.spec(&[
        "/bin/sh",
        "-c",
        "/usr/bin/perl stub.pl < frame 2> nested.err; echo $? > nested.rc",
    ]));
    confirmed(&e);
    let err = std::fs::read_to_string(t.ws.join("nested.err")).unwrap();
    assert!(err.ends_with(START_REFUSED), "{err:?}");
    assert_eq!(
        std::fs::read_to_string(t.ws.join("nested.rc")).unwrap(),
        "4\n"
    );
    assert!(!marker.exists(), "the refused stub must start nothing");
}

/// The start check's other arm: a stub whose parent is gone (re-parented
/// to launchd, pid 1) refuses too. Same harmless nesting as above.
#[test]
fn stub_refuses_to_start_when_its_parent_is_gone() {
    let t = Tree::new("canary2");
    std::fs::write(t.ws.join("stub.pl"), DOMAIN_STUB).unwrap();
    let marker = t.ws.join("ran");
    std::fs::write(
        t.ws.join("frame"),
        frame(&["/usr/bin/touch", marker.to_str().unwrap()]),
    )
    .unwrap();
    let e = run(&t.spec(&[
        "/bin/sh",
        "-c",
        "( ( /bin/sleep 0.5; exec /usr/bin/perl stub.pl < frame 2> nested.err ) & ); \
         i=0; while [ ! -s nested.err ] && [ $i -lt 100 ]; do /bin/sleep 0.1; i=$((i+1)); done",
    ]));
    confirmed(&e);
    let err = std::fs::read_to_string(t.ws.join("nested.err")).unwrap();
    assert!(err.ends_with(START_REFUSED), "{err:?}");
    assert!(!marker.exists(), "the refused stub must start nothing");
}

/// Review follow-up 2: a sweep reaches only its own sandbox INSTANCE.
/// Run B (sleeps about 3 s, then writes a marker) is alive while run A,
/// with the byte-identical profile, runs to completion and sweeps (A's
/// setsid'd escapee is killed). B's program must survive A's sweep and
/// finish normally, with B's own domain confirmed. Parallel benchmark
/// tasks depend on this.
#[test]
fn a_sweep_never_reaches_another_sandbox_instance() {
    let t = Tree::new("xsb");
    let b_script = "open(my $s, q{>}, q{b.started}) or die; close $s; sleep 3; \
                    open(my $f, q{>}, q{b.done}) or die; print $f $$; close $f; print qq{b finished\\n}";
    let b = Seatbelt::new()
        .spawn(&t.spec(&[PERL, "-e", b_script]), witness())
        .unwrap();
    let started = Instant::now();
    while !t.ws.join("b.started").exists() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "B never started"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // A: the same Tree, so the same roots and a byte-identical profile.
    let (a, a_pid) = escapee(&t, true, false);
    assert!(matches!(a.domain, DomainCleanup::Confirmed { kills } if kills >= 1));
    assert!(!alive(a_pid), "A's own escapee survived A's sweep");
    assert!(
        !t.ws.join("b.done").exists(),
        "B finished before A's sweep ran; the test proves nothing"
    );
    let eb = b.wait();
    assert_eq!(eb.status, ChildStatus::Exited(0), "B was disturbed");
    assert_eq!(out(&eb), "b finished\n");
    assert!(t.ws.join("b.done").exists());
    confirmed(&eb);
}

/// A confined process cannot apply a new sandbox (measured E12:
/// `sandbox_apply` fails with EPERM). So it can neither loosen its own
/// profile nor leave its sandbox instance, which the sweep relies on.
#[test]
fn a_confined_process_cannot_apply_another_sandbox() {
    let t = Tree::new("nest");
    let c = Command::new("/usr/bin/sandbox-exec")
        .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
        .status()
        .unwrap();
    assert!(c.success(), "control");
    let script = "my $rc = system(q{/usr/bin/sandbox-exec}, q{-p}, q{(version 1)(allow default)}, q{/usr/bin/true}); print $rc == 0 ? qq{APPLIED\\n} : qq{refused\\n}";
    let e = perl(&t, script, &[]);
    assert_eq!(out(&e), "refused\n");
    assert!(String::from_utf8_lossy(&e.stderr).contains("sandbox_apply: Operation not permitted"));
}
