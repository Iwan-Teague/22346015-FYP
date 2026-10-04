//! The hostile-task conformance suite (design §6.6) against the Linux
//! backend, through the real spawn seam — one-for-one with
//! `conformance_macos.rs`, the same case ids (`FT-1..FT-18` as applicable,
//! D31, nested-sandbox, hard-link). Each test states the case it witnesses
//! and checks the behaviour from OUTSIDE the sandbox where it can (files
//! absent, listeners silent, processes gone), not only what the confined
//! program printed. Controls run the same program unconfined to show the
//! hostile action works when nothing stops it, so a pass is not an accident
//! of a broken program.
//!
//! This is the suite `rh-dev linux` runs in the VM; its green run on a real
//! kernel is what lets the Linux matrix row be committed. The Linux
//! flavours of the guards differ from macOS by design (the namespace-less
//! row): FT-6 is the per-process `RLIMIT_AS`, FT-5 per-user `RLIMIT_NPROC`
//! (forks start failing, no watchdog), and FT-17/FT-18 are macOS-only
//! escape surfaces a Linux row cannot exercise (recorded with that reason,
//! not silently).
//!
//! S-Lg adds the Linux escape-surface cases (`linux-*` ids in
//! [`harness_sandbox::conformance`]): openat2, `/proc` mem, fd
//! inheritance, loader variables, setuid under `no_new_privs`,
//! `memfd_create`+`execveat`, the abstract unix namespace, `ptrace`, a
//! setsid-ing fork bomb, and tmpfs outside the roots. Each follows the
//! same discipline: a refused arm confined, an unconfined control doing
//! the same thing successfully (so the pass is not an accident of a
//! broken program), and outside checks (files absent, pids gone). The
//! matrix row does not carry these cases until this suite passes green on
//! a real kernel.
//!
//! The binary is `harness = false` (see Cargo.toml): `main()` dispatches on
//! `argv[1]` — `__confine` is the supervisor helper arm (this very binary
//! is re-exec'd as the helper, so the suite runs the real spawn path), and
//! anything else runs the tests, serially, printing libtest-shaped tallies
//! (`cargo test -- --test-threads=1` passes its arguments straight through;
//! an optional positional argument filters by substring, as libtest does).

fn main() {
    // The helper dispatch and the tests exist only where the supervisor
    // does (Linux, modelled architecture); elsewhere this binary is a
    // no-op, like the live binaries of harness-sandbox-linux.
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
            _ => imp::run_suite(),
        }
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod imp {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use std::ffi::OsString;
    use std::io::Write as _;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    use harness_sandbox::conformance::{Case, H2_EXIT_CASES};
    use harness_sandbox::{
        Backend, BackendKind, ChildStatus, ConfinedExit, ConfinedSpec, Conformed, DomainCleanup,
        Limits, MemoryGuard, Network, ProcessGuard,
    };

    const PERL: &str = "/usr/bin/perl";

    fn witness() -> &'static Conformed {
        static W: OnceLock<Conformed> = OnceLock::new();
        W.get_or_init(|| {
            harness_sandbox::linux::Linux::default()
                .probe()
                .expect("the Linux live probe must pass")
        })
    }

    /// A fresh directory tree: `ws` (the read-write root) and `outside`
    /// (never granted), canonical.
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
        harness_sandbox::linux::Linux::default()
            .spawn(spec, witness())
            .unwrap()
            .wait()
    }

    fn perl(tree: &Tree, script: &str, args: &[&str]) -> ConfinedExit {
        let mut argv = vec![PERL, "-e", script];
        argv.extend_from_slice(args);
        run(&tree.spec(&argv))
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

    /// Wait (briefly) for `path` to appear and return its contents: the
    /// pidfile handshake with a sleeper we just spawned.
    fn wait_for(path: &Path) -> String {
        for _ in 0..500 {
            match std::fs::read_to_string(path) {
                Ok(s) => return s,
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        panic!("{} never appeared", path.display());
    }

    /// A confined sleeper that writes its pid to `t.ws/<name>` and stays
    /// alive until the caller stops it: a sibling under the caller's
    /// control for cross-process checks.
    fn confined_sleeper(t: &Tree, name: &str) -> (harness_sandbox::ConfinedChild, u32) {
        let pidfile = t.ws.join(name);
        let s = t.spec(&[
            PERL,
            "-e",
            "open(my $o, q{>}, $ARGV[0]) or die; print $o $$; close $o; sleep 60",
            pidfile.to_str().unwrap(),
        ]);
        let child = harness_sandbox::linux::Linux
            .spawn(&s, witness())
            .expect("sleeper spawn must succeed");
        let pid: u32 = wait_for(&pidfile).trim().parse().unwrap();
        (child, pid)
    }

    fn witness_is_minted_by_the_live_probe_and_names_its_row() {
        let w = witness();
        assert_eq!(w.backend(), BackendKind::Linux);
        assert_eq!(w.matrix_row(), "linux-landlock-seccomp-nons-v1");
        assert!(w
            .covers(&[Case::Ft1, Case::Ft16Setsid, Case::NoBind])
            .is_ok());
        // The namespace-less row covers the whole exit set, and the witness
        // names the exact FT-5 and FT-6 bars, so the production bar passes.
        assert!(w.covers(H2_EXIT_CASES).is_ok());
        assert_eq!(w.memory(), MemoryGuard::RlimitAddressSpace);
        assert_eq!(w.processes(), ProcessGuard::RlimitNprocPerUser);
        assert!(harness_sandbox::require().is_ok());
    }

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
        assert_eq!(e.stderr, b"e\n", "the helper's report is never in stderr");
        confirmed(&e);
    }

    /// FT-1 / FT-13: no connect, checked at the listener outside. The
    /// seccomp filter denies `socket()` outright, so the refusal is at
    /// socket creation (EACCES) and the program never even dials.
    fn ft1_tcp_connect_refused() {
        let t = Tree::new("ft1");
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let port = l.local_addr().unwrap().port().to_string();
        let script = "use Socket; for my $a ([q{loop},$ARGV[0]]) { unless (socket(my $s,PF_INET,SOCK_STREAM,0)) { print qq{refused\n}; next } print connect($s, sockaddr_in($a->[1], inet_aton(q{127.0.0.1}))) ? qq{CONNECTED\n} : qq{refused\n} }";
        let c = control(script, &[&port]);
        assert_eq!(String::from_utf8_lossy(&c.stdout), "CONNECTED\n", "control");
        let _ = l.accept(); // drain the control's connection
        let e = perl(&t, script, &[&port]);
        assert_eq!(out(&e), "refused\n");
        assert!(matches!(l.accept(), Err(ref x) if x.kind() == std::io::ErrorKind::WouldBlock));
        // A routable address too (TEST-NET-1: never answers, so only a
        // refusal is fast).
        let e = perl(&t, "use Socket; unless (socket(my $s,PF_INET,SOCK_STREAM,0)) { print qq{refused $!\n}; exit 0 } print connect($s, sockaddr_in(80, inet_aton(q{192.0.2.1}))) ? qq{CONNECTED\n} : qq{refused $!\n}", &[]);
        assert!(
            out(&e).starts_with("refused Operation not permitted"),
            "{}",
            out(&e)
        );
        confirmed(&e);
    }

    /// D31: no bind on the shared network stack, loopback included.
    fn d31_bind_refused() {
        let t = Tree::new("bind");
        let script = "use Socket; for my $u (0, 1) { my $ty = $u ? SOCK_DGRAM : SOCK_STREAM; unless (socket(my $s,PF_INET,$ty,0)) { print qq{refused\n}; next } print bind($s, sockaddr_in(0, inet_aton(q{127.0.0.1}))) ? qq{BOUND\n} : qq{refused\n} }";
        assert_eq!(
            String::from_utf8_lossy(&control(script, &[]).stdout),
            "BOUND\nBOUND\n"
        );
        assert_eq!(out(&perl(&t, script, &[])), "refused\nrefused\n");
    }

    /// FT-3: writes outside the workspace (a sibling run's directory and a
    /// home-shaped path) fail and leave nothing.
    fn ft3_writes_outside_fail() {
        let t = Tree::new("ft3");
        let sibling = t.outside.join("runs").join("other-run").join("workspace");
        std::fs::create_dir_all(&sibling).unwrap();
        let a = t.outside.join("canary");
        let b = sibling.join("canary");
        let script = "for (@ARGV) { print open(my $f, q{>}, $_) ? qq{WROTE\n} : qq{refused\n} } print open(my $g, q{>}, q{inside}) ? qq{inside\n} : qq{NO\n}";
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

    /// FT-4: a planted `.ssh`-shaped secret is unreadable, the real home is
    /// not even listable, and the harness's environment does not leak.
    fn ft4_secrets_and_home_unreadable() {
        let t = Tree::new("ft4");
        std::fs::create_dir_all(t.outside.join(".ssh")).unwrap();
        let key = t.outside.join(".ssh").join("id_ed25519");
        std::fs::write(&key, "rh-canary-secret").unwrap();
        let home = std::env::var("HOME").unwrap();
        let script = "print open(my $f, q{<}, $ARGV[0]) ? qq{READ\n} : qq{refused\n}; print opendir(my $d, $ARGV[1]) ? qq{LISTED\n} : qq{refused\n}; print exists $ENV{HOME} || exists $ENV{USER} || exists $ENV{SSH_AUTH_SOCK} ? qq{LEAK\n} : qq{clean\n}";
        let c = control(script, &[key.to_str().unwrap(), &home]);
        assert_eq!(
            String::from_utf8_lossy(&c.stdout),
            "READ\nLISTED\nLEAK\n",
            "control"
        );
        let e = perl(&t, script, &[key.to_str().unwrap(), &home]);
        assert_eq!(out(&e), "refused\nrefused\nclean\n");
    }

    /// FT-7: a disk fill stops at the file-size cap (`RLIMIT_FSIZE`).
    fn ft7_disk_fill_capped() {
        let t = Tree::new("ft7");
        let mut s = t.spec(&[PERL, "-e", "$SIG{XFSZ}=q{IGNORE}; open(my $f, q{>}, q{fill}) or die; my $b = q{x} x 65536; for (1..64) { syswrite($f, $b) or do { print qq{stopped\n}; exit 0 } } print qq{FILLED\n}"]);
        s.limits.file_size = Some(256 * 1024);
        let e = run(&s);
        assert_eq!(out(&e), "stopped\n");
        assert!(std::fs::metadata(t.ws.join("fill")).unwrap().len() <= 256 * 1024);
    }

    /// FT-8: a busy loop is killed at the wall clock, and the call ends
    /// within wall + grace.
    fn ft8_busy_loop_killed() {
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

    /// FT-6: a memory bomb is bounded by the per-process `RLIMIT_AS` the
    /// program child carries. Control: the same program unconfined
    /// allocates and reaches FILLED (the VM is dedicated; if IT cannot
    /// allocate, the suite must say so, not skip).
    fn ft6_memory_bomb_bounded() {
        let t = Tree::new("ft6");
        // Allocate AND touch in 8 MiB steps, hard-capped at 40 steps (320 MiB).
        let bomb = "$|=1; my @k; for my $i (1..40){ my $s = q{X} x (8*1024*1024); substr($s,0,4096,q{Y}x4096); push @k,$s } print qq{FILLED\n}";
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

    /// FT-5: a fork burst is bounded by the per-user `RLIMIT_NPROC` the
    /// program child carries: forks fail with EAGAIN long before 40, where
    /// the unconfined control forks all 40 and reaps them. No watchdog on
    /// this row (the macOS member-count flavour is macOS's), so the count
    /// itself is the evidence.
    fn ft5_fork_bomb_bounded() {
        let t = Tree::new("ft5");
        // arg: seconds each child lives. 0 for the control (fast), a few
        // seconds confined so the burst is observable.
        let burst = "use POSIX (); $|=1; my $live=$ARGV[0]; my @k; for(1..40){ my $p=fork(); if(defined $p && $p==0){ POSIX::_exit(0) if !$live; sleep $live; POSIX::_exit(0) } push @k,$p if $p } print qq{forked }, scalar(@k), qq{\n}; waitpid($_,0) for @k; print qq{DONE\n}";
        let c = control(burst, &["0"]);
        assert_eq!(
            String::from_utf8_lossy(&c.stdout),
            "forked 40\nDONE\n",
            "control should fork freely"
        );
        let mut s = t.spec(&[PERL, "-e", burst, "3"]);
        s.limits.processes = Some(8);
        s.limits.wall = Duration::from_secs(30);
        let start = Instant::now();
        let e = run(&s);
        let o = out(&e);
        let n: u32 = o
            .split_whitespace()
            .nth(1)
            .and_then(|w| w.parse().ok())
            .unwrap_or(u32::MAX);
        assert!(
            n < 40,
            "the fork burst was not bounded (forked {n}): {:?} {o}",
            e.status
        );
        assert!(o.contains("DONE"), "the program never finished: {o}");
        assert!(
            start.elapsed() < Duration::from_secs(25),
            "far too slow for an 8-process cap: {:?}",
            start.elapsed()
        );
        confirmed(&e);
    }

    /// FT-6/LOW-4: a hard link from a file OUTSIDE the read-write roots
    /// into the workspace is refused, so an outside file's content cannot
    /// be aliased under a workspace path (Landlock rules are path-based).
    /// Control: unconfined the same link succeeds.
    fn hard_link_from_outside_refused() {
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
        let script = "my ($src,$dst)=@ARGV; print link($src,$dst) ? qq{LINKED\n} : qq{refused\n}; print open(my $f,q{<},$dst) ? qq{read-link\n} : qq{no-link\n}; print open(my $g,q{<},$src) ? qq{read-direct\n} : qq{no-direct\n}";
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

    /// S-Lg `linux-openat2`: `openat2` with `RESOLVE_BENEATH` (and with no
    /// resolve flags at all) cannot reach outside the Landlock read set;
    /// `..` and a symlinked path resolve to the same denial, because the
    /// handle model decides, not the path text. Control: the same six arms
    /// unconfined (cwd = the workspace) all open.
    fn linux_openat2_resolve_flags_cannot_escape_roots() {
        let t = Tree::new("openat2");
        std::fs::write(t.ws.join("inside"), "ok").unwrap();
        std::fs::write(t.outside.join("secret"), "canary").unwrap();
        std::os::unix::fs::symlink(t.outside.join("secret"), t.ws.join("s")).unwrap();
        // openat2 is 437 on x86_64 and aarch64 alike; AT_FDCWD is -100;
        // `struct open_how` is three u64s (flags, mode, resolve), 24 bytes;
        // RESOLVE_BENEATH is 0x8.
        let script = "while (@ARGV) { my $p = shift @ARGV; my $r = shift @ARGV; my $how = pack(q{Q3}, 0, 0, $r); my $fd = syscall(437, -100, $p, $how, 24); if ($fd < 0) { print qq{refused\\n} } else { syscall(3, $fd); print qq{OPENED\\n} } }";
        let outside = t.outside.join("secret").to_str().unwrap().to_string();
        let args = [
            "inside",
            "8",
            &outside,
            "8",
            "..",
            "8",
            "s",
            "8",
            outside.as_str(),
            "0",
            "inside",
            "0",
        ];
        let c = Command::new(PERL)
            .arg("-e")
            .arg(script)
            .current_dir(&t.ws)
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&c.stdout),
            "OPENED\nOPENED\nOPENED\nOPENED\nOPENED\nOPENED\n",
            "control must open every arm unconfined"
        );
        let e = perl(&t, script, &args);
        assert_eq!(
            out(&e),
            "OPENED\nrefused\nrefused\nrefused\nrefused\nOPENED\n"
        );
        confirmed(&e);
    }

    /// S-Lg `linux-proc-self-mem`: `/proc/self/mem` is not a write channel
    /// and `/proc/<pid>/mem` of another confined process is unreachable —
    /// /proc is not in the read set, and cross-process ptrace access is
    /// seccomp-denied. Control: a parent reading its own forked child's
    /// mem (and its own) opens both unconfined.
    fn linux_proc_self_mem_and_pid_mem_are_not_a_write_channel() {
        let t = Tree::new("procmem");
        let script = "use POSIX (); my $kid = fork(); if ($kid == 0) { sleep 5; POSIX::_exit(0) } select(undef,undef,undef,0.05); my $other = $ARGV[0] eq q{kid} ? $kid : $ARGV[0]; print open(my $f, q{+<}, qq{/proc/$other/mem}) ? qq{pid OPENED\\n} : qq{pid refused\\n}; print open(my $g, q{+<}, q{/proc/self/mem}) ? qq{self OPENED\\n} : qq{self refused\\n}; kill(q{KILL}, $kid); waitpid($kid, 0)";
        let c = control(script, &["kid"]);
        assert_eq!(
            String::from_utf8_lossy(&c.stdout),
            "pid OPENED\nself OPENED\n",
            "control must read its own child's mem"
        );
        let e = perl(&t, script, &["kid"]);
        assert_eq!(out(&e), "pid refused\nself refused\n");
        confirmed(&e);
    }

    /// S-Lg `linux-fd-inherit`: exactly std{in,out,err} cross `exec` into
    /// the program child (the helper closes everything from
    /// `FD_LEAK_FLOOR` up with `close_range`). Checked from OUTSIDE by
    /// listing `/proc/<pid>/fd` while the child sleeps, with a marker file
    /// the test holds open as bait. Control: the same listing method on an
    /// unconfined child that opens the marker shows it (so the method
    /// would see a leak).
    fn linux_no_unexpected_fd_is_inherited_into_the_child() {
        let t = Tree::new("fdinh");
        let marker = t.outside.join("marker");
        let _bait = std::fs::File::create(&marker).unwrap();
        let script = "open(my $f, q{<}, $ARGV[0]) or die; sleep 60";
        let pidfile = t.ws.join("sib.pid");
        let mut s = t.spec(&[PERL, "-e", script, marker.to_str().unwrap()]);
        s.limits.wall = Duration::from_secs(60);
        let child = harness_sandbox::linux::Linux
            .spawn(&s, witness())
            .expect("sleeper spawn must succeed");
        let pid: u32 = wait_for(&pidfile).trim().parse().unwrap();
        let fds = format!("/proc/{pid}/fd");
        let mut names: Vec<String> = std::fs::read_dir(&fds)
            .unwrap()
            .map(|en| en.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["0", "1", "2"], "unexpected fd set in the child");
        for n in &names {
            let target = std::fs::read_link(format!("{fds}/{n}"))
                .unwrap()
                .to_string_lossy()
                .into_owned();
            assert!(
                !target.contains("marker"),
                "fd {n} points at the bait: {target}"
            );
        }
        let e = child.stop();
        confirmed(&e);
        // Control: an unconfined child that opens the marker lists it via
        // the same /proc method — the check above can see a leak.
        let ctl = Command::new(PERL)
            .args([
                "-e",
                "open(my $f, q{<}, $ARGV[0]) or die; opendir(my $d, q{/proc/self/fd}); for (readdir $d) { next unless /^\\d+$/; my $t = readlink(qq{/proc/self/fd/$_}) // q{?}; print qq{$_ -> $t\\n} }",
                marker.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        let co = String::from_utf8_lossy(&ctl.stdout).into_owned();
        assert!(
            co.lines().any(|l| l.contains("->") && l.contains("marker")),
            "control must show the open marker: {co}"
        );
        assert!(co.lines().count() > 3, "control shows its own fds: {co}");
    }

    /// S-Lg `linux-ld-preload`: loader variables are refused in the spec
    /// outright (INV-10), and a loader variable planted in the harness's
    /// own environment does not reach the child (the child env is built,
    /// not inherited). Control: unconfined, the planted variable is
    /// visible in the child's env.
    fn linux_ld_preload_and_loader_env_are_absent() {
        let t = Tree::new("ldpreload");
        let mut bad = t.spec(&[PERL, "-e", "print qq{ran\\n}"]);
        bad.env
            .push(("LD_PRELOAD".into(), "/nonexistent/librh.so".into()));
        let err = harness_sandbox::linux::Linux
            .spawn(&bad, witness())
            .expect_err("an LD_PRELOAD spec must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("loader variable") && msg.contains("LD_PRELOAD"),
            "{msg}"
        );
        // Now plant the variables in the harness's own environment.
        std::env::set_var("LD_PRELOAD", "/nonexistent/librh.so");
        std::env::set_var("LD_LIBRARY_PATH", "/nonexistent");
        let e = perl(&t, "print join(q{,}, sort keys %ENV), qq{\\n}", &[]);
        std::env::remove_var("LD_PRELOAD");
        std::env::remove_var("LD_LIBRARY_PATH");
        let o = out(&e);
        assert!(!o.contains("LD_"), "loader variable reached the child: {o}");
        assert!(o.contains("PATH"), "the child env is intact: {o}");
        let c = Command::new(PERL)
            .args(["-e", "print $ENV{LD_PRELOAD} // q{absent}"])
            .env("LD_PRELOAD", "/nonexistent/librh.so")
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&c.stdout),
            "/nonexistent/librh.so",
            "control must see the variable"
        );
    }

    /// S-Lg `linux-setuid`: the program child runs under
    /// `no_new_privs` (read from `/proc/<pid>/status` from outside), and
    /// exec'ing a setuid-root copy of `/usr/bin/id` grants nothing — no
    /// `euid=` appears. Control: unconfined the same copy grants `euid=0`
    /// (a permissive host; a nosuid mount makes the test say so and fail).
    fn linux_setuid_binary_gains_nothing_under_no_new_privs() {
        use std::os::unix::fs::PermissionsExt;
        let t = Tree::new("setuid");
        // (a) the flag itself, on a live child vs an unconfined sibling.
        let (child, cpid) = confined_sleeper(&t, "c.pid");
        let ctl_pidfile = t.ws.join("ctl.pid");
        let mut ctl = Command::new(PERL)
            .args([
                "-e",
                "open(my $o, q{>}, $ARGV[0]) or die; print $o $$; close $o; sleep 60",
                ctl_pidfile.to_str().unwrap(),
            ])
            .spawn()
            .unwrap();
        let upid: u32 = wait_for(&ctl_pidfile).trim().parse().unwrap();
        let nnp = |pid: u32| -> bool {
            std::fs::read_to_string(format!("/proc/{pid}/status"))
                .unwrap()
                .lines()
                .find_map(|l| l.strip_prefix("NoNewPrivs:"))
                .map(|v| v.trim() == "1")
                .unwrap_or(false)
        };
        assert!(nnp(cpid), "confined child must carry no_new_privs");
        assert!(!nnp(upid), "unconfined sibling must not carry it");
        let e = child.stop();
        confirmed(&e);
        let _ = ctl.kill();
        let _ = ctl.wait();
        // (b) a setuid-root binary exec'd by the confined child.
        let ro = t.root.join("bin");
        std::fs::create_dir_all(&ro).unwrap();
        assert!(Path::new("/usr/bin/id").exists(), "the VM must ship id");
        let idcopy = ro.join("id");
        std::fs::copy("/usr/bin/id", &idcopy).unwrap();
        std::fs::set_permissions(&idcopy, std::fs::Permissions::from_mode(0o4755)).unwrap();
        let argv = idcopy.to_str().unwrap().to_string();
        let mut s = t.spec(&[argv.as_str()]);
        s.read_only = vec![ro.clone()];
        let e = run(&s);
        let o = out(&e);
        assert!(
            matches!(e.status, ChildStatus::Exited(0)),
            "exec must succeed: {:?} {o} {}",
            e.status,
            String::from_utf8_lossy(&e.stderr)
        );
        assert!(o.contains("uid="), "{o}");
        assert!(
            !o.contains("euid="),
            "the setuid bit must not take effect under no_new_privs: {o}"
        );
        let c = Command::new(&idcopy).output().unwrap();
        let co = String::from_utf8_lossy(&c.stdout).into_owned();
        assert!(
            co.contains("euid=0"),
            "host is not permissive (nosuid mount?); control says: {co}"
        );
    }

    /// S-Lg `linux-memfd-exec`: `memfd_create` then
    /// `execveat(AT_EMPTY_PATH)` is refused — the AT_EMPTY_PATH flag is
    /// seccomp-denied, and an anonymous file has no Landlock execute
    /// right. The program builds the memfd, copies /bin/echo in (it can:
    /// memfd_create itself is allowed), then execveat's it; success would
    /// replace the process with echo printing a bare newline. Control:
    /// the same program unconfined prints exactly that newline.
    fn linux_memfd_create_then_execveat_is_refused() {
        let t = Tree::new("memfd");
        let script = "use POSIX (); use Config; my $arm = $Config{archname} =~ /aarch64/ ? 1 : 0; my ($memfd, $execveat) = $arm ? (279, 281) : (319, 322); my $fd = syscall($memfd, q{rh-memfd}, 0); if ($fd < 0) { print qq{memfd refused $!\\n}; POSIX::_exit(0) } open(my $src, q{<}, q{/bin/echo}) or do { print qq{read refused $!\\n}; POSIX::_exit(0) }; binmode $src; my $elf = do { local $/; <$src> }; open(my $mh, q{>&=}, $fd) or do { print qq{dup refused $!\\n}; POSIX::_exit(0) }; binmode $mh; print $mh $elf; close $mh; syscall($execveat, $fd, q{}, 0, 0, 4096); print qq{refused $!\\n}; POSIX::_exit(0)";
        let c = control(script, &[]);
        assert_eq!(
            String::from_utf8_lossy(&c.stdout),
            "\n",
            "control must exec the memfd (bare echo newline)"
        );
        let e = perl(&t, script, &[]);
        assert!(
            out(&e).starts_with("refused"),
            "memfd exec must be refused: {:?}",
            out(&e)
        );
        confirmed(&e);
    }

    /// S-Lg `linux-abstract-unix`: the abstract unix namespace is
    /// unreachable — `socket(AF_UNIX)` is seccomp-denied and Landlock
    /// (below ABI 6) cannot scope abstract addresses. The test holds the
    /// abstract listener (Rust, `from_abstract_name`); the control
    /// connects to it unconfined, the confined program is refused at
    /// socket creation. The control's sockaddr is packed by hand so the
    /// address length matches the abstract name exactly.
    fn linux_abstract_unix_socket_connect_is_refused() {
        let t = Tree::under(Path::new("/tmp"), "abs");
        use std::os::linux::net::SocketAddrExt as _;
        let name = format!("rh-abs-{}", std::process::id());
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let l = std::os::unix::net::UnixListener::bind_addr(&addr).unwrap();
        l.set_nonblocking(true).unwrap();
        let script = "use Socket; my $n = $ARGV[0]; unless (socket(my $s, PF_UNIX, SOCK_STREAM, 0)) { print qq{refused\\n}; exit 0 } my $sun = pack(q{S}, AF_UNIX) . qq{\\0$n}; print connect($s, $sun) ? qq{CONNECTED\\n} : qq{refused\\n}";
        let c = control(script, &[&name]);
        assert_eq!(
            String::from_utf8_lossy(&c.stdout),
            "CONNECTED\n",
            "control must reach the abstract listener"
        );
        let _ = l.accept(); // drain the control's connection
        let e = perl(&t, script, &[&name]);
        assert_eq!(out(&e), "refused\n");
        assert!(
            matches!(l.accept(), Err(ref x) if x.kind() == std::io::ErrorKind::WouldBlock),
            "the confined program must not have connected"
        );
    }

    /// S-Lg `linux-ptrace-sibling`: `ptrace(PTRACE_ATTACH)` of another
    /// process is seccomp-denied, and with it `/proc/<pid>/mem` of the
    /// confined sibling stays unreachable. The program forks a child of
    /// its own (a parent may ptrace a direct child: the control proves
    /// the syscall works on this host) and then tries the confined
    /// sibling passed as an argument.
    fn linux_ptrace_of_a_sibling_is_refused() {
        let t = Tree::new("ptrace");
        let (sib_child, sib_pid) = confined_sleeper(&t, "sib.pid");
        let sib = sib_pid.to_string();
        let script = "use POSIX (); use Config; my $ptrace = $Config{archname} =~ /aarch64/ ? 117 : 101; my $kid = fork(); if ($kid == 0) { sleep 5; POSIX::_exit(0) } select(undef,undef,undef,0.05); my $other = $ARGV[0] eq q{kid} ? $kid : $ARGV[0]; my $a = syscall($ptrace, 16, $kid); print $a == 0 ? qq{attach OPENED\\n} : qq{attach refused\\n}; print open(my $f, q{+<}, qq{/proc/$other/mem}) ? qq{mem OPENED\\n} : qq{mem refused\\n}; if ($a == 0) { syscall($ptrace, 17, $kid) } kill(q{KILL}, $kid); waitpid($kid, 0)";
        let c = control(script, &["kid"]);
        assert_eq!(
            String::from_utf8_lossy(&c.stdout),
            "attach OPENED\nmem OPENED\n",
            "control must ptrace its own child"
        );
        let e = perl(&t, script, &[sib.as_str()]);
        assert_eq!(out(&e), "attach refused\nmem refused\n");
        confirmed(&e);
        assert!(alive(sib_pid), "the confined sibling must survive");
        let e2 = sib_child.stop();
        confirmed(&e2);
    }

    /// S-Lg `linux-fork-bomb-pgroup`: a fork bomb whose children
    /// `setsid()` and double-fork (so they sit in other process groups,
    /// writing their pids to a file) is bounded by the process cap and,
    /// when the wall fires, EVERY descendant is gone — the subreaper
    /// sweep, not a group kill. Control: unconfined, the same
    /// setsid+double-fork children survive their parent (the escape
    /// mechanism is real; the test kills them itself).
    fn linux_fork_bomb_and_setsid_double_fork_are_all_reaped() {
        let t = Tree::new("forkbomb");
        const BOMB: &str = "use POSIX (); my ($pidfile, $max, $csleep, $psleep) = @ARGV; $|=1; my $n = 0; for (1..$max) { my $p = fork(); if (!defined $p) { last } if ($p == 0) { POSIX::setsid(); if (fork()) { POSIX::_exit(0) } $SIG{TERM} = q{IGNORE}; open(my $o, q{>>}, $pidfile) or POSIX::_exit(1); print $o $$, qq{\\n}; close $o; sleep $csleep; POSIX::_exit(0) } $n++ } print qq{forked $n\\n}; sleep $psleep";
        // Control: two escapees outlive their parent.
        let cpidfile = t.ws.join("ctl.pids");
        let c = control(BOMB, &[cpidfile.to_str().unwrap(), "2", "2", "0"]);
        assert_eq!(
            String::from_utf8_lossy(&c.stdout),
            "forked 2\n",
            "control must fork freely"
        );
        let mut escapees: Vec<u32> = Vec::new();
        for _ in 0..100 {
            escapees = cpidfile
                .to_str()
                .map(|p| std::fs::read_to_string(p).unwrap_or_default())
                .unwrap_or_default()
                .lines()
                .filter_map(|l| l.trim().parse().ok())
                .collect();
            if escapees.len() >= 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(escapees.len(), 2, "control escapees must exist");
        for p in &escapees {
            assert!(alive(*p), "control escapee {p} must outlive its parent");
        }
        // Confined: the bomb hits the cap, the wall fires, all reaped.
        let pidfile = t.ws.join("bomb.pids");
        let mut s = t.spec(&[
            PERL,
            "-e",
            BOMB,
            pidfile.to_str().unwrap(),
            "40",
            "60",
            "60",
        ]);
        s.limits.processes = Some(8);
        s.limits.wall = Duration::from_millis(1500);
        let start = Instant::now();
        let e = run(&s);
        assert_eq!(e.status, ChildStatus::TimedOut, "{}", out(&e));
        let n: u32 = out(&e)
            .split_whitespace()
            .nth(1)
            .and_then(|w| w.parse().ok())
            .unwrap_or(u32::MAX);
        assert!(n < 40, "the bomb was not bounded (forked {n})");
        confirmed(&e);
        assert!(
            matches!(e.domain, DomainCleanup::Confirmed { kills } if kills >= 1),
            "the sweep must have killed something"
        );
        let pids: Vec<u32> = std::fs::read_to_string(&pidfile)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect();
        assert!(!pids.is_empty(), "grandchildren must have registered");
        std::thread::sleep(Duration::from_millis(50));
        for p in &pids {
            assert!(!alive(*p), "setsid escapee {p} survived the sweep");
        }
        for p in &escapees {
            let _ = Command::new("/bin/kill")
                .args(["-9", &p.to_string()])
                .status();
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the wall must fire promptly: {:?}",
            start.elapsed()
        );
    }

    /// S-Lg `linux-dev-shm-tmpfs`: `/dev/shm` (the world-writable tmpfs)
    /// and `/run` are not writable from the confined child — they are
    /// outside the read-write roots — and a denied write leaves nothing.
    /// Control: unconfined the same write to /dev/shm succeeds (and is
    /// cleaned up); the /run arm has no unconfined twin (/run is
    /// root-owned by design — its refusal is the Landlock check).
    fn linux_dev_shm_and_tmpfs_writes_stay_inside_roots() {
        let t = Tree::new("devshm");
        let shm = format!("/dev/shm/rh-canary-{}", std::process::id());
        let run = format!("/run/rh-canary-{}", std::process::id());
        let script = "for (@ARGV) { print open(my $f, q{>}, $_) ? qq{WROTE\\n} : qq{refused\\n} }";
        assert!(
            Path::new("/dev/shm").is_dir(),
            "/dev/shm must exist for the case to be non-vacuous"
        );
        let c = control(script, &[&shm]);
        assert_eq!(
            String::from_utf8_lossy(&c.stdout),
            "WROTE\n",
            "control must write /dev/shm"
        );
        assert!(Path::new(&shm).exists());
        let _ = std::fs::remove_file(&shm);
        let e = perl(&t, script, &[shm.as_str(), run.as_str()]);
        assert_eq!(out(&e), "refused\nrefused\n");
        assert!(!Path::new(&shm).exists(), "nothing may be left in /dev/shm");
        assert!(!Path::new(&run).exists(), "nothing may be left in /run");
        confirmed(&e);
    }

    /// FT-9: protected paths inside the workspace are read-only; the bytes
    /// are unchanged, and no new file appears under them.
    fn ft9_protected_paths_read_only() {
        let t = Tree::new("ft9");
        let git = t.ws.join(".git");
        std::fs::create_dir_all(&git).unwrap();
        std::fs::write(git.join("config"), "orig").unwrap();
        std::fs::write(t.ws.join("tests.rs"), "orig").unwrap();
        let mut s = t.spec(&[PERL, "-e", "for (@ARGV) { print open(my $f, q{>>}, $_) ? qq{WROTE\n} : qq{refused\n} } print unlink(q{tests.rs}) ? qq{DELETED\n} : qq{kept\n}; print rename(q{.git}, q{g2}) ? qq{MOVED\n} : qq{kept\n}; print open(my $r, q{<}, q{.git/config}) ? qq{readable\n} : qq{NOREAD\n}", ".git/config", ".git/new", "tests.rs"]);
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

    /// FT-10: a state_root-shaped directory (journal, config) outside the
    /// grants is neither readable nor listable nor writable.
    fn ft10_harness_state_unreadable() {
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
        let script = "print open(my $f, q{<}, $ARGV[0]) ? qq{READ\n} : qq{refused\n}; print opendir(my $d, $ARGV[1]) ? qq{LISTED\n} : qq{refused\n}; print open(my $g, q{>>}, $ARGV[0]) ? qq{WROTE\n} : qq{refused\n}";
        let e = perl(
            &t,
            script,
            &[journal.to_str().unwrap(), run_dir.to_str().unwrap()],
        );
        assert_eq!(out(&e), "refused\nrefused\nrefused\n");
        assert_eq!(std::fs::read_to_string(&journal).unwrap(), "{}\n");
    }

    /// FT-11: a unix socket listener outside the workspace is unreachable,
    /// and so is one inside it. The seccomp filter denies `socket()` at
    /// every family, so the refusal is at socket creation.
    fn ft11_unix_socket_connect_fails() {
        // Socket paths are short (SUN_LEN): use /tmp.
        let t = Tree::under(Path::new("/tmp"), "11");
        let outside = t.outside.join("s.sock");
        let inside = t.ws.join("s.sock");
        let lo = std::os::unix::net::UnixListener::bind(&outside).unwrap();
        let li = std::os::unix::net::UnixListener::bind(&inside).unwrap();
        lo.set_nonblocking(true).unwrap();
        li.set_nonblocking(true).unwrap();
        let script = "use Socket; for (@ARGV) { unless (socket(my $s, PF_UNIX, SOCK_STREAM, 0)) { print qq{refused\n}; next } print connect($s, pack_sockaddr_un($_)) ? qq{CONNECTED\n} : qq{refused\n} }";
        let e = perl(
            &t,
            script,
            &[outside.to_str().unwrap(), inside.to_str().unwrap()],
        );
        assert_eq!(out(&e), "refused\nrefused\n");
        assert!(lo.accept().is_err() && li.accept().is_err());
    }

    /// FT-12: a symlink in the workspace pointing outside is not followed
    /// (the resolved target decides, and Landlock grants nothing there),
    /// for reading, writing, or as a directory. The macOS FT-27 flavour
    /// (a workspace FIFO unopenable under deny-network*) is absent: on
    /// this row the check is path-based, and a FIFO inside the granted
    /// workspace opens.
    fn ft12_symlink_escape_refused() {
        let t = Tree::new("ft12");
        std::fs::write(t.outside.join("secret"), "rh-canary").unwrap();
        std::os::unix::fs::symlink(t.outside.join("secret"), t.ws.join("s")).unwrap();
        std::os::unix::fs::symlink(&t.outside, t.ws.join("d")).unwrap();
        let script = "print open(my $f, q{<}, q{s}) ? qq{READ\n} : qq{refused\n}; print open(my $g, q{>}, q{d/new}) ? qq{WROTE\n} : qq{refused\n}; print opendir(my $h, q{d}) ? qq{LISTED\n} : qq{refused\n}";
        let e = perl(&t, script, &[]);
        assert_eq!(out(&e), "refused\nrefused\nrefused\n");
        assert!(!t.outside.join("new").exists());
    }

    /// FT-15: no resolver is reachable. A name that only DNS can answer
    /// does not resolve (`localhost` is not asked: it comes from
    /// `/etc/hosts`, a file, not a resolver). The control resolves the same
    /// kind of name only when the host itself has DNS, so it is
    /// informative, not required.
    fn ft15_no_dns() {
        let t = Tree::new("ft15");
        let script = "my @a = gethostbyname(q{apple.com}); print @a ? qq{RESOLVED\n} : qq{none\n}";
        let c = control(script, &[]);
        eprintln!(
            "ft15 control (host DNS): {}",
            String::from_utf8_lossy(&c.stdout).trim()
        );
        assert_eq!(out(&perl(&t, script, &[])), "none\n");
    }

    const ESCAPE: &str = "use POSIX (); my ($file, $setsid, $killstub) = @ARGV; my $p = fork(); if ($p == 0) { POSIX::setsid() if $setsid; if (fork()) { POSIX::_exit(0) } $SIG{TERM} = q{IGNORE}; open(my $o, q{>}, $file) or die; print $o $$; close $o; close STDOUT; close STDERR; sleep 60; POSIX::_exit(0) } waitpid($p, 0); for (1..200) { last if -s $file; select(undef, undef, undef, 0.01) } kill(q{KILL}, getppid()) if $killstub; print qq{parent done\n}";

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

    /// FT-16 with `setsid()`: the descendant left the process group, and
    /// the subreaper sweep still kills it (a process-group kill alone
    /// would not).
    fn ft16_setsid_escapee_reaped() {
        let t = Tree::new("ft16s");
        let (e, pid) = escapee(&t, true, false);
        confirmed(&e);
        assert!(matches!(e.domain, DomainCleanup::Confirmed { kills } if kills >= 1));
        assert!(!alive(pid), "setsid escapee {pid} survived");
    }

    /// A confined process cannot create a new namespace (seccomp denies
    /// `unshare` and the `CLONE_NEW*` flags of `clone`), so it can neither
    /// loosen its domain nor escape it — the kernel-side reason a nested
    /// sandbox cannot weaken this row (Landlock, additionally, has no
    /// un-restrict). The control is informative only: a host may refuse
    /// unprivileged user namespaces to its own users too (AppArmor on
    /// Ubuntu 24.04), which looks the same unconfined.
    fn nested_sandbox_cannot_loosen() {
        let t = Tree::new("nest");
        let script = "my $rc = system(q{unshare}, q{-Ur}, q{/bin/true}); print $rc == 0 ? qq{APPLIED\n} : qq{refused\n}";
        let c = control(script, &[]);
        eprintln!(
            "nested control (host userns): {}",
            String::from_utf8_lossy(&c.stdout).trim()
        );
        let e = perl(&t, script, &[]);
        assert_eq!(out(&e), "refused\n");
        confirmed(&e);
    }

    /// Output is capped at the spec's budget, and a flood does not block
    /// the call (the ring keeps the retained window; totals still count
    /// every byte).
    fn output_is_capped_without_blocking() {
        let t = Tree::new("cap");
        let mut s = t.spec(&[PERL, "-e", "print q{x} x 5000000"]);
        s.limits.output_bytes = 1000;
        let e = run(&s);
        assert_eq!(e.stdout.len(), 1000);
        assert!(e.stdout_truncated);
        assert_eq!(e.status, ChildStatus::Exited(0));
    }

    /// The suite, serially, with libtest-shaped output. `--test-threads=1`
    /// and `--nocapture` pass through unused; one optional positional
    /// argument filters by substring.
    pub(crate) fn run_suite() {
        let filter = std::env::args().skip(1).find(|a| !a.starts_with('-'));
        let all: &[(&str, fn())] = &[
            (
                "witness_is_minted_by_the_live_probe_and_names_its_row",
                witness_is_minted_by_the_live_probe_and_names_its_row,
            ),
            (
                "a_benign_program_runs_with_exactly_its_env_and_output",
                a_benign_program_runs_with_exactly_its_env_and_output,
            ),
            ("ft1_tcp_connect_refused", ft1_tcp_connect_refused),
            ("d31_bind_refused", d31_bind_refused),
            ("ft3_writes_outside_fail", ft3_writes_outside_fail),
            (
                "ft4_secrets_and_home_unreadable",
                ft4_secrets_and_home_unreadable,
            ),
            ("ft5_fork_bomb_bounded", ft5_fork_bomb_bounded),
            ("ft6_memory_bomb_bounded", ft6_memory_bomb_bounded),
            ("ft7_disk_fill_capped", ft7_disk_fill_capped),
            ("ft8_busy_loop_killed", ft8_busy_loop_killed),
            (
                "ft9_protected_paths_read_only",
                ft9_protected_paths_read_only,
            ),
            (
                "ft10_harness_state_unreadable",
                ft10_harness_state_unreadable,
            ),
            (
                "ft11_unix_socket_connect_fails",
                ft11_unix_socket_connect_fails,
            ),
            ("ft12_symlink_escape_refused", ft12_symlink_escape_refused),
            ("ft15_no_dns", ft15_no_dns),
            ("ft16_setsid_escapee_reaped", ft16_setsid_escapee_reaped),
            ("nested_sandbox_cannot_loosen", nested_sandbox_cannot_loosen),
            (
                "hard_link_from_outside_refused",
                hard_link_from_outside_refused,
            ),
            (
                "linux_openat2_resolve_flags_cannot_escape_roots",
                linux_openat2_resolve_flags_cannot_escape_roots,
            ),
            (
                "linux_proc_self_mem_and_pid_mem_are_not_a_write_channel",
                linux_proc_self_mem_and_pid_mem_are_not_a_write_channel,
            ),
            (
                "linux_no_unexpected_fd_is_inherited_into_the_child",
                linux_no_unexpected_fd_is_inherited_into_the_child,
            ),
            (
                "linux_ld_preload_and_loader_env_are_absent",
                linux_ld_preload_and_loader_env_are_absent,
            ),
            (
                "linux_setuid_binary_gains_nothing_under_no_new_privs",
                linux_setuid_binary_gains_nothing_under_no_new_privs,
            ),
            (
                "linux_memfd_create_then_execveat_is_refused",
                linux_memfd_create_then_execveat_is_refused,
            ),
            (
                "linux_abstract_unix_socket_connect_is_refused",
                linux_abstract_unix_socket_connect_is_refused,
            ),
            (
                "linux_ptrace_of_a_sibling_is_refused",
                linux_ptrace_of_a_sibling_is_refused,
            ),
            (
                "linux_fork_bomb_and_setsid_double_fork_are_all_reaped",
                linux_fork_bomb_and_setsid_double_fork_are_all_reaped,
            ),
            (
                "linux_dev_shm_and_tmpfs_writes_stay_inside_roots",
                linux_dev_shm_and_tmpfs_writes_stay_inside_roots,
            ),
            (
                "output_is_capped_without_blocking",
                output_is_capped_without_blocking,
            ),
        ];
        let selected: Vec<(&str, fn())> = all
            .iter()
            .copied()
            .filter(|(name, _)| match filter.as_deref() {
                Some(f) => name.contains(f),
                None => true,
            })
            .collect();
        println!("\nrunning {} tests", selected.len());
        let _ = std::io::stdout().flush();
        let start = Instant::now();
        let mut passed = 0usize;
        let mut failed: Vec<&str> = Vec::new();
        for (name, f) in &selected {
            print!("test {name} ... ");
            let _ = std::io::stdout().flush();
            match std::panic::catch_unwind(f) {
                Ok(()) => {
                    println!("ok");
                    passed += 1;
                }
                Err(_) => {
                    println!("FAILED");
                    failed.push(name);
                }
            }
            let _ = std::io::stdout().flush();
        }
        println!(
            "\ntest result: {}. {} passed; {} failed; 0 ignored; 0 measured; {} filtered out; finished in {:.2}s\n",
            if failed.is_empty() { "ok" } else { "FAILED" },
            passed,
            failed.len(),
            all.len() - selected.len(),
            start.elapsed().as_secs_f32()
        );
        if !failed.is_empty() {
            std::process::exit(1);
        }
    }
}
