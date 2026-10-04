//! Live process-tree tests for the supervisor (slice S-Ld).
//!
//! The unit tests in `src/supervisor.rs` cover the pure protocol layer on
//! every OS; this file holds what needs a real Linux process tree: a stop
//! kills the whole group, a `setsid` double-fork escapee is still reaped by
//! the subreaper, a spawner crash sweeps through the control pipe (and a
//! helper crash through the program's `PR_SET_PDEATHSIG`), no supervisor fd
//! crosses the exec, the ring bounds and digests live output, and both the
//! wall clock and `RLIMIT_CPU` stop a busy loop.
//!
//! This target is `harness = false` and must stay that way: the helper is a
//! re-exec of this very binary (`argv = [bin, "__confine", <spawner pid>]`)
//! and a libtest harness would parse that argv as test filters before any
//! dispatch could run. Instead `main` dispatches on argv — helper arm,
//! confined-scenario arm, then a small sequential runner for the tests —
//! and on a non-Linux host the binary builds to an empty `main`, so the
//! crate still builds and tests everywhere.
//!
//! Linux-only, and only on the arches whose syscall tables are modelled
//! (as in `tests/seccomp_apply.rs`); skipped elsewhere.

fn main() {
    let mut args = std::env::args().skip(1);
    let verb = args.next();
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        use harness_sandbox_linux::supervisor;
        match verb.as_deref() {
            // The helper arm: never returns.
            Some(supervisor::HELPER_ARG) => supervisor::helper_main(),
            // A confined scenario arm: this binary is the program.
            Some("scenario") => live::run_scenario(args.next().as_deref().unwrap_or("")),
            // The runner arm: an optional substring filter, as libtest has.
            _ => live::run_all(verb.as_deref()),
        }
    }
    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        let _ = (verb, args);
        // Nothing to run off Linux: an empty main passes the empty harness.
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod live {
    use harness_sandbox_linux::supervisor::{
        self, Limits, Program, RawEnd, RawMode, RawStream, WaitCause,
    };
    use std::io::Write as _;
    use std::os::unix::ffi::OsStringExt as _;
    use std::time::{Duration, Instant};

    extern "C" {
        fn fork() -> i32;
        fn setsid() -> i32;
        fn kill(pid: i32, sig: i32) -> i32;
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    }

    /// `F_GETFD`: the cheap "is this fd open?" probe.
    const F_GETFD: i32 = 1;
    const SIGKILL: i32 = 9;

    // ---- the confined scenarios (this binary as the program) --------------

    /// Dispatch a scenario by name; an unknown one is a scenario failure.
    pub fn run_scenario(name: &str) -> ! {
        match name {
            "echo" => scenario_echo(),
            "busy" => busy(),
            "busy-children" => scenario_busy_children(),
            "setsid" => scenario_setsid(),
            "fd-sweep" => scenario_fd_sweep(),
            _ => std::process::exit(7),
        }
    }

    /// Burn CPU forever without touching memory, files or the network.
    fn busy() -> ! {
        loop {
            std::hint::black_box(1);
        }
    }

    /// 5 MiB of a repeating decimal pattern on stdout, 1 MiB of `z` on
    /// stderr, exit 0: the ring's totals and digest have exact answers.
    fn scenario_echo() -> ! {
        let out = "0123456789".repeat(524_288);
        let mut so = std::io::stdout();
        let _ = so.write_all(out.as_bytes());
        let _ = so.flush();
        let err = "z".repeat(1_048_576);
        let mut se = std::io::stderr();
        let _ = se.write_all(err.as_bytes());
        let _ = se.flush();
        std::process::exit(0);
    }

    /// A leader with three forked children, every one of them busy: a group
    /// kill must reach all four, and the sweep must reap all four.
    fn scenario_busy_children() -> ! {
        for _ in 0..3 {
            let pid = unsafe { fork() };
            if pid < 0 {
                std::process::exit(8);
            }
            if pid == 0 {
                busy();
            }
        }
        busy();
    }

    /// The classic escape: a middle process forks a grandchild that calls
    /// `setsid()` (leaving the group), the middle exits at once, and the
    /// grandchild re-parents to the nearest subreaper — the helper — where
    /// the sweep's orphan scan must find it.
    fn scenario_setsid() -> ! {
        let middle = unsafe { fork() };
        if middle < 0 {
            std::process::exit(8);
        }
        if middle == 0 {
            let grand = unsafe { fork() };
            if grand < 0 {
                std::process::exit(8);
            }
            if grand == 0 {
                if unsafe { setsid() } < 0 {
                    std::process::exit(9);
                }
                busy();
            }
            std::process::exit(0);
        }
        busy();
    }

    /// Report every open fd below 1024, one `fd <n>` per line: the direct
    /// probe that nothing but the three stdio fds crossed the exec.
    fn scenario_fd_sweep() -> ! {
        let mut out = std::io::stdout();
        for fd in 0..1024i32 {
            if unsafe { fcntl(fd, F_GETFD) } != -1 {
                let _ = writeln!(out, "fd {fd}");
            }
        }
        let _ = out.flush();
        std::process::exit(0);
    }

    // ---- the spawner side -------------------------------------------------

    fn exe() -> std::path::PathBuf {
        match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("current_exe failed: {e}");
                std::process::exit(2);
            }
        }
    }

    /// The read-only grants every scenario needs to exec at all: the binary
    /// itself (its own directory) and the loader's libraries.
    fn grants() -> Vec<String> {
        let mut roots = vec!["/usr".to_string(), "/lib".to_string(), "/etc".to_string()];
        if std::path::Path::new("/lib64").exists() {
            roots.push("/lib64".to_string());
        }
        if let Some(dir) = exe().parent() {
            if let Some(s) = dir.to_str() {
                roots.push(s.to_string());
            }
        }
        roots
    }

    fn program(scenario: &str, limits: Limits) -> Program {
        Program {
            argv: vec![
                exe().into_os_string().into_vec(),
                b"scenario".to_vec(),
                scenario.as_bytes().to_vec(),
            ],
            env: Vec::new(),
            cwd: "/tmp".to_string(),
            read_only: grants(),
            read_write: Vec::new(),
            protected: Vec::new(),
            limits,
            netns: None,
        }
    }

    fn spawn_prog(
        scenario: &str,
        ring: u64,
        life: Duration,
        limits: Limits,
    ) -> supervisor::Running {
        match supervisor::spawn(&program(scenario, limits), exe().as_os_str(), ring, life) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("spawn of scenario {scenario} failed: {e}");
                std::process::exit(2);
            }
        }
    }

    /// The cmdline marker of a scenario process (`argv` is
    /// `[exe, "scenario", <name>]`, NUL-separated in /proc).
    fn marker(scenario: &str) -> Vec<u8> {
        let mut m = b"scenario\0".to_vec();
        m.extend_from_slice(scenario.as_bytes());
        m
    }

    /// Pids of live (non-zombie: a zombie's cmdline is empty) processes
    /// whose cmdline contains `marker`.
    fn pids_running_with(marker: &[u8]) -> Vec<u32> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return out;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            let Ok(cmd) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
                continue;
            };
            if cmd.windows(marker.len()).any(|w| w == marker) {
                out.push(pid);
            }
        }
        out
    }

    fn wait_tree_empty(markers: &[Vec<u8>], limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        loop {
            let empty = markers.iter().all(|m| pids_running_with(m).is_empty());
            if empty {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    // ---- the tests --------------------------------------------------------

    fn stop_kills_the_whole_process_group() -> Result<(), String> {
        let child = spawn_prog(
            "busy-children",
            64 * 1024,
            Duration::from_secs(60),
            Limits::default(),
        );
        std::thread::sleep(Duration::from_millis(300));
        let m = marker("busy-children");
        if pids_running_with(&m).len() < 4 {
            return Err("the group did not reach four processes (leader + 3 children)".into());
        }
        let exit = child.stop();
        if !exit.confirmed {
            return Err(format!("stop not confirmed: {}", exit.detail));
        }
        if exit.kills < 3 {
            return Err(format!("only {} kills reported", exit.kills));
        }
        if exit.timed_out {
            return Err("a stop must not read as a timeout".into());
        }
        if !matches!(exit.outcome, WaitCause::Signaled(9)) {
            return Err(format!(
                "leader should have died by SIGKILL, got {:?}",
                exit.outcome
            ));
        }
        if !wait_tree_empty(&[m, b"__confine".to_vec()], Duration::from_secs(5)) {
            return Err("processes survived the stop".into());
        }
        Ok(())
    }

    fn setsid_double_fork_escapee_is_reaped_by_the_subreaper() -> Result<(), String> {
        let child = spawn_prog(
            "setsid",
            64 * 1024,
            Duration::from_secs(60),
            Limits::default(),
        );
        std::thread::sleep(Duration::from_millis(400));
        let m = marker("setsid");
        if pids_running_with(&m).is_empty() {
            return Err("the escapee was not running before the stop".into());
        }
        let exit = child.stop();
        if !exit.confirmed {
            return Err(format!("stop not confirmed: {}", exit.detail));
        }
        if exit.kills < 1 {
            return Err(format!(
                "the escapee was not counted (kills={})",
                exit.kills
            ));
        }
        if !wait_tree_empty(&[m], Duration::from_secs(5)) {
            return Err("the setsid escapee survived the stop".into());
        }
        Ok(())
    }

    fn crash_of_the_parent_sweeps_via_pdeathsig() -> Result<(), String> {
        // (a) The SPAWNER is killed mid-run: its control-pipe write end
        // closes with the process, the helper sees EOF, sweeps, reports to
        // a pipe nobody will read, and exits.
        let shim = unsafe { fork() };
        if shim < 0 {
            return Err("fork of the crash shim failed".into());
        }
        if shim == 0 {
            let child = spawn_prog(
                "busy-children",
                64 * 1024,
                Duration::from_secs(60),
                Limits::default(),
            );
            // Hold the control pipe open until the SIGKILL lands. The sleep
            // keeps the Running alive; `exit` skips its Drop either way.
            std::thread::sleep(Duration::from_secs(60));
            std::process::exit(0);
        }
        std::thread::sleep(Duration::from_millis(300));
        let m = marker("busy-children");
        if pids_running_with(&m).is_empty() {
            return Err("the tree was not up before the crash".into());
        }
        if unsafe { kill(shim as i32, SIGKILL) } != 0 {
            return Err("could not SIGKILL the spawner shim".into());
        }
        if !wait_tree_empty(&[m, b"__confine".to_vec()], Duration::from_secs(6)) {
            return Err("a spawner crash left the tree alive".into());
        }
        // (b) The HELPER is killed: the program's PR_SET_PDEATHSIG must end
        // it within moments, well before any spawner-side escalation grace.
        let child = spawn_prog(
            "busy",
            64 * 1024,
            Duration::from_secs(60),
            Limits::default(),
        );
        std::thread::sleep(Duration::from_millis(300));
        let mb = marker("busy");
        if pids_running_with(&mb).is_empty() {
            return Err("the program was not up before the helper kill".into());
        }
        if unsafe { kill(child.pid() as i32, SIGKILL) } != 0 {
            return Err("could not SIGKILL the helper".into());
        }
        if !wait_tree_empty(&[mb], Duration::from_secs(2)) {
            return Err("the program outlived its helper (PDEATHSIG did not fire)".into());
        }
        let exit = child.wait();
        if exit.confirmed {
            return Err("a killed helper cannot confirm a sweep".into());
        }
        Ok(())
    }

    fn no_stray_fd_crosses_exec() -> Result<(), String> {
        let child = spawn_prog(
            "fd-sweep",
            64 * 1024,
            Duration::from_secs(30),
            Limits::default(),
        );
        let exit = child.wait();
        if exit.outcome != WaitCause::Exited(0) {
            return Err(format!(
                "the fd probe did not exit cleanly: {:?}",
                exit.outcome
            ));
        }
        let text = String::from_utf8(exit.stdout.clone())
            .map_err(|_| "stdout was not UTF-8".to_string())?;
        let want = "fd 0\nfd 1\nfd 2\n";
        if text != want {
            return Err(format!("exec crossed stray fds: {text:?} (want {want:?})"));
        }
        if !exit.exec_ok || !exit.confirmed {
            return Err("a clean run must be exec_ok and confirmed".into());
        }
        Ok(())
    }

    fn ring_output_is_bounded_and_digested() -> Result<(), String> {
        const OUT: usize = 5 * 1024 * 1024;
        const ERR: usize = 1024 * 1024;
        const RING: u64 = 64 * 1024;
        let child = spawn_prog("echo", RING, Duration::from_secs(30), Limits::default());
        // A live read while the program streams: bounded by the cap asked.
        let deadline = Instant::now() + Duration::from_secs(5);
        while child.totals().out_total < OUT as u64 {
            if Instant::now() >= deadline {
                return Err("the echo program never finished writing".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let chunk = child.read(RawStream::Out, 0, 32 * 1024, RawMode::Next);
        if chunk.bytes.len() > 32 * 1024 {
            return Err(format!(
                "a read returned {} bytes, over the cap",
                chunk.bytes.len()
            ));
        }
        if !chunk.bytes.iter().all(u8::is_ascii_digit) {
            return Err("live stdout bytes were not the echo pattern".into());
        }
        // Every byte is counted and digested, ring or no ring.
        let totals = child.totals();
        let exit = child.wait();
        if totals.out_total != OUT as u64 {
            return Err(format!("out_total was {}, want {OUT}", totals.out_total));
        }
        let mut sha = supervisor::Sha256::new();
        sha.update("0123456789".repeat(OUT / 10).as_bytes());
        if totals.out_sha != sha.finish() {
            return Err("the stdout digest did not match the pattern".into());
        }
        if totals.err_total != ERR as u64 {
            return Err(format!("err_total was {}, want {ERR}", totals.err_total));
        }
        let mut sha = supervisor::Sha256::new();
        sha.update("z".repeat(ERR).as_bytes());
        if totals.err_sha != sha.finish() {
            return Err("the stderr digest did not match the pattern".into());
        }
        if exit.outcome != WaitCause::Exited(0) || exit.end != RawEnd::Exit {
            return Err(format!(
                "a clean echo ended as {:?} / {:?}",
                exit.outcome, exit.end
            ));
        }
        if exit.stdout.len() > RING as usize {
            return Err(format!(
                "the retained stdout was {} bytes, over the ring",
                exit.stdout.len()
            ));
        }
        if !exit.stdout_truncated {
            return Err("5 MiB through a 64 KiB ring must read as truncated".into());
        }
        if !exit.confirmed {
            return Err(format!("a clean run must be confirmed: {}", exit.detail));
        }
        Ok(())
    }

    fn wall_clock_and_rlimit_cpu_both_stop_a_busy_loop() -> Result<(), String> {
        // (a) The wall clock: the control pipe closes at the deadline, the
        // helper stops the tree, the spawner reads a timeout.
        let child = spawn_prog("busy", 4 * 1024, Duration::from_secs(1), Limits::default());
        let exit = child.wait();
        if !exit.timed_out {
            return Err("the wall clock did not end the call".into());
        }
        if exit.end != RawEnd::Stop {
            return Err(format!("a timeout must end=stop, got {:?}", exit.end));
        }
        if !exit.confirmed {
            return Err(format!(
                "a wall-clock stop must still confirm: {}",
                exit.detail
            ));
        }
        if !matches!(exit.outcome, WaitCause::Signaled(9)) {
            return Err(format!(
                "the busy loop should have died by SIGKILL, got {:?}",
                exit.outcome
            ));
        }
        // (b) RLIMIT_CPU: SIGXCPU at the soft limit, well inside the wall.
        let limits = Limits {
            cpu: Some(Duration::from_secs(1)),
            ..Limits::default()
        };
        let child = spawn_prog("busy", 4 * 1024, Duration::from_secs(10), limits);
        let exit = child.wait();
        if !matches!(exit.outcome, WaitCause::Signaled(24)) {
            return Err(format!(
                "RLIMIT_CPU should end a busy loop by SIGXCPU, got {:?}",
                exit.outcome
            ));
        }
        if exit.timed_out || exit.end != RawEnd::Exit {
            return Err("an rlimit ending is the program's own exit, not a stop".into());
        }
        if !exit.confirmed {
            return Err(format!(
                "an rlimit stop must still confirm: {}",
                exit.detail
            ));
        }
        Ok(())
    }

    // ---- the runner -------------------------------------------------------

    /// Run the tests in order, optionally filtered by substring; the shape
    /// of libtest's output, so `cargo test` logs read as usual.
    pub fn run_all(filter: Option<&str>) -> ! {
        let tests: &[(&str, fn() -> Result<(), String>)] = &[
            (
                "stop_kills_the_whole_process_group",
                stop_kills_the_whole_process_group,
            ),
            (
                "setsid_double_fork_escapee_is_reaped_by_the_subreaper",
                setsid_double_fork_escapee_is_reaped_by_the_subreaper,
            ),
            (
                "crash_of_the_parent_sweeps_via_pdeathsig",
                crash_of_the_parent_sweeps_via_pdeathsig,
            ),
            ("no_stray_fd_crosses_exec", no_stray_fd_crosses_exec),
            (
                "ring_output_is_bounded_and_digested",
                ring_output_is_bounded_and_digested,
            ),
            (
                "wall_clock_and_rlimit_cpu_both_stop_a_busy_loop",
                wall_clock_and_rlimit_cpu_both_stop_a_busy_loop,
            ),
        ];
        let mut passed = 0usize;
        let mut failed = 0usize;
        for (name, test) in tests {
            if let Some(f) = filter {
                if !name.contains(f) {
                    continue;
                }
            }
            print!("test {name} ... ");
            let _ = std::io::stdout().flush();
            match test() {
                Ok(()) => {
                    println!("ok");
                    passed += 1;
                }
                Err(e) => {
                    println!("FAILED");
                    eprintln!("  {e}");
                    failed += 1;
                }
            }
        }
        println!("test result: {passed} passed; {failed} failed; 0 ignored");
        std::process::exit(i32::from(failed > 0));
    }
}
