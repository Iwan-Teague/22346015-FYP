//! The `linux` verb (slice S-Lh): run the Linux conformance suite in the
//! UTM VM over ssh (design note `docs/slices/S-L-linux-sandbox.md` §5).
//!
//! One VM exists, so the whole run — boot, sync, suite — holds
//! `/tmp/rh-linux-vm.lock` (a directory lock: creating it is acquiring it;
//! the lock is a directory, so acquisition is atomic and a crashed run
//! leaves it behind, which is fail-closed: the next run reports the VM
//! busy rather than racing it, and a person removes the directory).
//!
//! The steps, in order, each loud when it cannot be honest:
//!
//! 1. `--boot` (optional): `utmctl start <vm>`, then poll `ssh … true`
//!    until the guest answers or the `--ssh-wait` bound passes.
//! 2. Without `--boot`, the same poll, shorter by default. A guest that
//!    never answers is a LOUD skip: `SKIPPED` on stderr, exit
//!    [`code::SKIPPED`] — never a silent green (S-Li's conductor and a
//!    worker's hand-run both read this as "not Linux-verified").
//! 3. `rsync` the workspace to `rh-work/` in the guest's home, excluding
//!    `target/` and `.git/`, with `--delete` so a stale guest tree can
//!    never fake a pass. A content digest of the synced tree (FNV-1a, over
//!    the same exclusions) is printed for the report.
//! 4. The suite, over ssh, each command wrapped in the guest's
//!    `timeout(1)` AND bounded locally: the ssh child is spawned in its
//!    own process group and past the deadline the whole group is killed
//!    ([`crate::proc`]), so a hung test cannot wedge the tool. The
//!    commands are the Linux conformance suite (serialised:
//!    `--test-threads=1`, the live probe is flaky under concurrent
//!    sandbox apply) and the sandbox crate's own tests as a control.
//! 5. Parse every `test result:` line ([`crate::parse`]) and exit 0 only
//!    if at least one suite ran and every suite was `ok`. A log with no
//!    result lines is a failure, never a pass.
//!
//! `--keep-logs DIR` copies the full transcript (every command's output)
//! to `DIR/<vm>-<unix-secs>.log` whatever the verdict.
//!
//! Exit codes: [`code::PASS`], [`code::TESTS_FAILED`], [`code::USAGE`],
//! [`code::SKIPPED`] (unreachable VM or busy lock — NOT a pass),
//! [`code::COULD_NOT_RUN`] (boot/rsync/ssh failure or deadline hit).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::parse;
use crate::proc;

/// Exit codes of `rh-dev linux`. Distinct so a conductor (S-Li) can tell
/// "the tests failed" from "the VM was not there" — the one thing that may
/// never happen is a non-zero code being read as a pass, or a skip being
/// read as green.
pub mod code {
    /// Every selected test passed.
    pub const PASS: i32 = 0;
    /// At least one selected test failed, or no result line was parsed.
    pub const TESTS_FAILED: i32 = 1;
    /// Bad arguments.
    pub const USAGE: i32 = 2;
    /// Skipped: the VM was unreachable or the VM lock was held. NOT a pass.
    pub const SKIPPED: i32 = 3;
    /// Could not run: boot, sync or ssh failed, or the deadline was hit.
    pub const COULD_NOT_RUN: i32 = 4;
}

/// The default guest VM name.
const DEFAULT_VM: &str = "rh-linux";
/// The default wall-clock budget for the whole run (design §5.1).
const DEFAULT_TIMEOUT_SECS: u64 = 1800;
/// The default bound on waiting for the guest to answer ssh.
const DEFAULT_SSH_WAIT_SECS: u64 = 300;
/// The default pause between ssh polls.
const DEFAULT_POLL_EVERY: Duration = Duration::from_secs(2);
/// The default guest-side directory the workspace is synced to (under the
/// ssh user's home; the path stays relative so the guest's own home is
/// authoritative).
const DEFAULT_GUEST_DIR: &str = "rh-work";
/// The one VM lock (design §5.3): one VM, serialised.
pub const DEFAULT_LOCK: &str = "/tmp/rh-linux-vm.lock";
/// The verified absolute path of UTM's control tool (design §5).
const DEFAULT_UTMCTL: &str = "/Applications/UTM.app/Contents/MacOS/utmctl";

/// Usage text for the `linux` verb.
pub const USAGE: &str = "\
usage: rh-dev linux --ssh <user@host> [--vm <name>]
                    [--boot] [--timeout <secs>] [--ssh-wait <secs>]
                    [--only <test>] [--keep-logs <dir>] [--repo <dir>]

Sync this workspace to the Linux VM over rsync and run the Linux
conformance suite plus the sandbox's unit tests over ssh, under a
wall-clock timeout. Holds /tmp/rh-linux-vm.lock for the whole run.
Exit: 0 all pass; 1 tests failed; 2 usage; 3 SKIPPED (unreachable VM or
busy lock — NOT a pass); 4 could not run (boot/rsync/ssh/timeout).
";

/// Everything the verb needs; every external program is a field so tests
/// can point it at a stub instead of a VM.
#[derive(Debug, Clone)]
pub struct Options {
    /// The UTM VM name (`utmctl start <vm>` when `--boot`).
    pub vm: String,
    /// The ssh destination (`user@host-or-ip`).
    pub ssh_target: String,
    /// Start the VM with `utmctl` before polling ssh.
    pub boot: bool,
    /// Wall-clock budget for the whole run (boot poll aside).
    pub timeout: Duration,
    /// Bound on waiting for the guest to answer ssh.
    pub ssh_wait: Duration,
    /// Pause between ssh polls.
    pub poll_every: Duration,
    /// A single test-name filter to pass to both cargo commands.
    pub only: Option<String>,
    /// Directory to copy the full transcript into, when set.
    pub keep_logs: Option<PathBuf>,
    /// The workspace root to sync (normally the repo/worktree root).
    pub repo_root: PathBuf,
    /// The guest-side directory under the ssh user's home.
    pub guest_dir: String,
    /// The VM lock directory.
    pub lock_path: PathBuf,
    /// The `utmctl` program.
    pub utmctl: PathBuf,
    /// The `ssh` program (looked up on `PATH` when not absolute).
    pub ssh: PathBuf,
    /// The `rsync` program (looked up on `PATH` when not absolute).
    pub rsync: PathBuf,
}

impl Options {
    /// Options for `--vm <vm> --ssh <target>` with every default applied.
    pub fn new(vm: &str, ssh_target: &str) -> Options {
        Options {
            vm: vm.to_string(),
            ssh_target: ssh_target.to_string(),
            boot: false,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            ssh_wait: Duration::from_secs(DEFAULT_SSH_WAIT_SECS),
            poll_every: DEFAULT_POLL_EVERY,
            only: None,
            keep_logs: None,
            repo_root: PathBuf::from("."),
            guest_dir: DEFAULT_GUEST_DIR.to_string(),
            lock_path: PathBuf::from(DEFAULT_LOCK),
            utmctl: PathBuf::from(DEFAULT_UTMCTL),
            ssh: PathBuf::from("ssh"),
            rsync: PathBuf::from("rsync"),
        }
    }
}

/// Parse the words after the `linux` verb. Errors carry the usage text.
pub fn parse_args(args: &[&str]) -> Result<Options, String> {
    let mut opts = Options::new(DEFAULT_VM, "");
    let mut vm = Option::<String>::None;
    let mut ssh = Option::<String>::None;
    let mut timeout = Option::<u64>::None;
    let mut ssh_wait = Option::<u64>::None;
    let mut only = Option::<String>::None;
    let mut keep_logs = Option::<PathBuf>::None;
    let mut repo = Option::<PathBuf>::None;
    let mut boot = false;
    let mut i = 0;
    while let Some(flag) = args.get(i) {
        let flag = *flag;
        let value = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            args.get(*i)
                .map(|v| (*v).to_string())
                .ok_or_else(|| format!("missing value for {flag}\n\n{USAGE}"))
        };
        match flag {
            "--vm" => vm = Some(value(&mut i)?),
            "--ssh" => ssh = Some(value(&mut i)?),
            "--boot" => boot = true,
            "--timeout" => {
                let raw = value(&mut i)?;
                timeout = Some(
                    raw.parse()
                        .map_err(|_| format!("--timeout wants seconds, got {raw}\n\n{USAGE}"))?,
                )
            }
            "--ssh-wait" => {
                let raw = value(&mut i)?;
                ssh_wait = Some(
                    raw.parse()
                        .map_err(|_| format!("--ssh-wait wants seconds, got {raw}\n\n{USAGE}"))?,
                )
            }
            "--only" => only = Some(value(&mut i)?),
            "--keep-logs" => keep_logs = Some(PathBuf::from(value(&mut i)?)),
            "--repo" => repo = Some(PathBuf::from(value(&mut i)?)),
            _ => return Err(format!("unknown flag {flag}\n\n{USAGE}")),
        }
        i += 1;
    }
    let Some(ssh_target) = ssh else {
        return Err(format!("--ssh <user@host> is required\n\n{USAGE}"));
    };
    let at_least_one_sec = |what: &str, n: u64| {
        if n == 0 {
            Err(format!("{what} must be at least 1 second\n\n{USAGE}"))
        } else {
            Ok(Duration::from_secs(n))
        }
    };
    opts.vm = vm.unwrap_or_else(|| DEFAULT_VM.to_string());
    opts.ssh_target = ssh_target;
    opts.boot = boot;
    if let Some(secs) = timeout {
        opts.timeout = at_least_one_sec("--timeout", secs)?;
    }
    if let Some(secs) = ssh_wait {
        opts.ssh_wait = at_least_one_sec("--ssh-wait", secs)?;
    }
    if let Some(only) = only {
        opts.only = Some(only);
    }
    if let Some(dir) = keep_logs {
        opts.keep_logs = Some(dir);
    }
    if let Some(dir) = repo {
        opts.repo_root = dir;
    }
    Ok(opts)
}

/// The whole-run transcript, kept for `--keep-logs`.
struct Transcript(String);

impl Transcript {
    fn add(&mut self, what: &str, bytes: &[u8]) {
        self.0.push_str("\n===== ");
        self.0.push_str(what);
        self.0.push_str(" =====\n");
        self.0.push_str(&String::from_utf8_lossy(bytes));
    }
}

/// The VM lock: a directory at `lock_path`, held for the whole run.
#[derive(Debug)]
pub struct VmLock {
    path: PathBuf,
}

impl Drop for VmLock {
    fn drop(&mut self) {
        // Best-effort release; if the directory cannot be removed the next
        // run reports the VM busy, which is the safe direction.
        let _ = fs::remove_dir(&self.path);
    }
}

/// Why the lock could not be taken.
#[derive(Debug)]
pub enum LockError {
    /// Another `rh-dev linux` (or a crashed one) holds the lock.
    Busy,
    /// The lock could not even be attempted (permissions, …).
    Io(std::io::Error),
}

/// Acquire the VM lock, or say why not.
pub fn acquire_lock(path: &Path) -> Result<VmLock, LockError> {
    match fs::create_dir(path) {
        Ok(()) => Ok(VmLock {
            path: path.to_path_buf(),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(LockError::Busy),
        Err(e) => Err(LockError::Io(e)),
    }
}

/// One remote cargo command of the suite.
pub struct Suite {
    /// The label the verdict table prints.
    pub label: &'static str,
    /// The cargo package/test selectors, after `cargo test`.
    pub selectors: &'static [&'static str],
    /// The libtest arguments after the separating `--` (empty for a plain
    /// `cargo test`, which needs none).
    pub libtest: &'static [&'static str],
}

/// The suite the design fixes (§5.1): the Linux conformance suite,
/// serialised (`--test-threads=1`, `--nocapture`), then the sandbox
/// crate's own tests as the control. When `harness-sandbox-linux` (S-Lb)
/// exists, its unit tests join here — noted in `docs/slices/S-Lh.md`.
const SUITES: &[Suite] = &[
    Suite {
        label: "conformance_linux",
        selectors: &["-p", "harness-sandbox", "--test", "conformance_linux"],
        libtest: &["--nocapture", "--test-threads=1"],
    },
    Suite {
        label: "harness-sandbox (unit + control)",
        selectors: &["-p", "harness-sandbox"],
        libtest: &[],
    },
];

/// The ssh argv that probes reachability: `true` must exit 0 in the guest.
pub fn poll_argv(opts: &Options) -> Vec<String> {
    vec![
        opts.ssh.to_string_lossy().into_owned(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "ConnectTimeout=5".into(),
        opts.ssh_target.clone(),
        "--".into(),
        "true".into(),
    ]
}

/// The `utmctl start` argv.
pub fn boot_argv(opts: &Options) -> Vec<String> {
    vec![
        opts.utmctl.to_string_lossy().into_owned(),
        "start".into(),
        opts.vm.clone(),
    ]
}

/// The rsync argv: the whole tree, `--delete`d to match the source,
/// excluding the build and git directories at any depth (what a fresh,
/// reproducible guest tree means, design §5.1 step 2).
pub fn rsync_argv(opts: &Options) -> Vec<String> {
    let mut argv = vec![
        opts.rsync.to_string_lossy().into_owned(),
        "-a".into(),
        "--delete".into(),
        "--exclude".into(),
        "target/".into(),
        "--exclude".into(),
        ".git/".into(),
        "-e".into(),
        "ssh".into(),
    ];
    let mut source = opts.repo_root.clone();
    source.push("");
    argv.push(source.to_string_lossy().into_owned());
    argv.push(format!("{}:{}/", opts.ssh_target, opts.guest_dir));
    argv
}

/// The ssh argv for one suite command: `cd <guest-dir> && timeout <secs>
/// cargo test …`, passed as argv items (ssh joins the remote command with
/// spaces and the guest's login shell runs it; nothing here spawns a shell
/// locally, and the only remote shell words are the fixed `cd`, `&&` and
/// the `timeout` wrapper the design prescribes).
pub fn suite_argv(opts: &Options, suite: &Suite, timeout_secs: u64) -> Vec<String> {
    let mut remote: Vec<String> = vec![
        "cd".into(),
        opts.guest_dir.clone(),
        "&&".into(),
        "timeout".into(),
        timeout_secs.to_string(),
        "cargo".into(),
        "test".into(),
    ];
    remote.extend(suite.selectors.iter().map(|s| (*s).to_string()));
    if !suite.libtest.is_empty() || opts.only.is_some() {
        remote.push("--".into());
        if let Some(only) = &opts.only {
            remote.push(only.clone());
        }
        remote.extend(suite.libtest.iter().map(|s| (*s).to_string()));
    }
    let mut argv = vec![
        opts.ssh.to_string_lossy().into_owned(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-tt".into(),
        opts.ssh_target.clone(),
        "--".into(),
    ];
    argv.extend(remote);
    argv
}

/// The directories rsync excludes, which the digest prunes to match.
fn excluded(name: &std::ffi::OsStr) -> bool {
    name == std::ffi::OsStr::new("target") || name == std::ffi::OsStr::new(".git")
}

/// FNV-1a over `bytes` (the one digest this std-only tool can afford; it
/// labels the sync in a report, it is not a security claim).
fn fnv1a(start: u64, bytes: &[u8]) -> u64 {
    bytes.iter().fold(start, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x100_0000_0193)
    })
}

/// Digest the synced tree exactly as rsync will sync it: every file's
/// relative path and content, symlinks by their target, `target/` and
/// `.git/` pruned at any depth. Depth-bounded so a surprise (a self-made
/// loop the walker cannot see, a pathological tree) fails loudly rather
/// than running away.
fn tree_digest(root: &Path) -> Result<u64, String> {
    const MAX_DEPTH: usize = 64;
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut paths = Vec::new();
    let mut links = Vec::new();
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            return Err(format!(
                "tree deeper than {MAX_DEPTH} under {}",
                root.display()
            ));
        }
        let entries =
            fs::read_dir(&dir).map_err(|e| format!("{}: cannot read: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
            let path = entry.path();
            let name = entry.file_name();
            if excluded(name.as_os_str()) {
                continue;
            }
            let kind = entry
                .file_type()
                .map_err(|e| format!("{}: {e}", path.display()))?;
            if kind.is_dir() {
                stack.push((path, depth + 1));
            } else if kind.is_symlink() {
                // A symlink is synced as a link, so it is digested as the
                // link, never followed (what the guest will see decides).
                let target =
                    fs::read_link(&path).map_err(|e| format!("{}: {e}", path.display()))?;
                links.push((path, target));
            } else {
                paths.push(path);
            }
        }
    }
    paths.sort();
    links.sort();
    for path in &paths {
        let rel = path
            .strip_prefix(root)
            .map_err(|_| format!("{}: not under {}", path.display(), root.display()))?;
        hash = fnv1a(hash, rel.to_string_lossy().as_bytes());
        hash = fnv1a(hash, &[0]);
        let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        hash = fnv1a(hash, &bytes);
        hash = fnv1a(hash, &[0]);
    }
    for (path, target) in &links {
        let rel = path
            .strip_prefix(root)
            .map_err(|_| format!("{}: not under {}", path.display(), root.display()))?;
        hash = fnv1a(hash, rel.to_string_lossy().as_bytes());
        hash = fnv1a(hash, &[0]);
        hash = fnv1a(hash, b"link:");
        hash = fnv1a(hash, target.to_string_lossy().as_bytes());
        hash = fnv1a(hash, &[0]);
    }
    Ok(hash)
}

/// Run the verb; the return value is the process exit code.
pub fn run(opts: &Options, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let started = Instant::now();
    let mut transcript = Transcript(String::new());

    // The lock covers boot + sync + suite (one VM, serialised; §5.3).
    let _lock = match acquire_lock(&opts.lock_path) {
        Ok(lock) => lock,
        Err(LockError::Busy) => {
            let _ = writeln!(
                err,
                "linux: {} is held — another rh-dev linux owns the VM.\n\
                 linux: SKIPPED (vm busy), not a pass; remove the lock directory only if no run is live.",
                opts.lock_path.display()
            );
            return code::SKIPPED;
        }
        Err(LockError::Io(e)) => {
            let _ = writeln!(
                err,
                "linux: cannot acquire {}: {e}\nlinux: COULD NOT RUN, not a pass",
                opts.lock_path.display()
            );
            return code::COULD_NOT_RUN;
        }
    };

    if opts.boot {
        let argv = boot_argv(opts);
        match proc::run_bounded(&argv, started + opts.timeout) {
            Ok(shot) => {
                transcript.add(&format!("{} start", opts.vm), &shot.output);
                let _ = writeln!(out, "linux: utmctl start {} requested", opts.vm);
            }
            Err(e) => {
                let _ = writeln!(
                    err,
                    "linux: boot failed: {e}\nlinux: COULD NOT RUN, not a pass"
                );
                keep_logs(opts, &transcript.0, err);
                return code::COULD_NOT_RUN;
            }
        }
    }

    // Poll reachability. Every failed poll is retried until the bound; a
    // guest that never answers ends the run as a loud SKIPPED.
    let reachable_by = Instant::now() + opts.ssh_wait;
    let poll = poll_argv(opts);
    loop {
        let attempt_deadline = reachable_by.min(Instant::now() + Duration::from_secs(15));
        match proc::run_bounded(&poll, attempt_deadline) {
            Ok(shot) if shot.success() => break,
            Ok(shot) => transcript.add("ssh probe (failed)", &shot.output),
            Err(e) => {
                let _ = writeln!(
                    err,
                    "linux: cannot probe the VM with ssh: {e}\nlinux: COULD NOT RUN, not a pass"
                );
                keep_logs(opts, &transcript.0, err);
                return code::COULD_NOT_RUN;
            }
        }
        if Instant::now() >= reachable_by {
            let _ = writeln!(
                err,
                "linux: Linux VM {} ({}) unreachable after {}s.\n\
                 linux: SKIPPED — the Linux conformance did NOT run; this is not a pass.",
                opts.vm,
                opts.ssh_target,
                opts.ssh_wait.as_secs()
            );
            keep_logs(opts, &transcript.0, err);
            return code::SKIPPED;
        }
        std::thread::sleep(opts.poll_every);
    }
    let _ = writeln!(out, "linux: {} ({}) reachable", opts.vm, opts.ssh_target);

    // Sync. The digest labels what was synced (it goes in the report).
    let digest = match tree_digest(&opts.repo_root) {
        Ok(digest) => digest,
        Err(e) => {
            let _ = writeln!(
                err,
                "linux: cannot digest the tree: {e}\nlinux: COULD NOT RUN, not a pass"
            );
            keep_logs(opts, &transcript.0, err);
            return code::COULD_NOT_RUN;
        }
    };
    let argv = rsync_argv(opts);
    match proc::run_bounded(&argv, started + opts.timeout) {
        Ok(shot) if shot.success() => {
            transcript.add("rsync", &shot.output);
            let _ = writeln!(
                out,
                "linux: synced {} -> {}:{}/ (digest {digest:016x})",
                opts.repo_root.display(),
                opts.ssh_target,
                opts.guest_dir
            );
        }
        Ok(shot) => {
            transcript.add("rsync (failed)", &shot.output);
            let _ = writeln!(
                err,
                "linux: rsync failed ({})\nlinux: COULD NOT RUN, not a pass",
                rsync_why(&shot)
            );
            keep_logs(opts, &transcript.0, err);
            return code::COULD_NOT_RUN;
        }
        Err(e) => {
            let _ = writeln!(
                err,
                "linux: rsync failed: {e}\nlinux: COULD NOT RUN, not a pass"
            );
            keep_logs(opts, &transcript.0, err);
            return code::COULD_NOT_RUN;
        }
    }

    // The suite: every command bounded by what is left of the budget.
    let deadline = started + opts.timeout;
    let mut judged: Vec<(&'static str, parse::Summary)> = Vec::new();
    for suite in SUITES {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            let _ = writeln!(
                err,
                "linux: wall-clock budget ({}) exhausted before {}\n\
                 linux: COULD NOT RUN, not a pass",
                opts.timeout.as_secs(),
                suite.label
            );
            keep_logs(opts, &transcript.0, err);
            return code::COULD_NOT_RUN;
        };
        let argv = suite_argv(opts, suite, remaining.as_secs().max(1));
        let _ = writeln!(out, "linux: running {} …", suite.label);
        match proc::run_bounded(&argv, deadline) {
            Ok(shot) if shot.timed_out => {
                transcript.add(&format!("{} (killed at the deadline)", suite.label), &[]);
                let _ = writeln!(
                    err,
                    "linux: {} killed at the wall-clock deadline; the process group is dead.\n\
                     linux: COULD NOT RUN, not a pass",
                    suite.label
                );
                keep_logs(opts, &transcript.0, err);
                return code::COULD_NOT_RUN;
            }
            Ok(shot) => {
                transcript.add(suite.label, &shot.output);
                let text = String::from_utf8_lossy(&shot.output);
                judged.push((suite.label, parse::summarize_output(&text)));
            }
            Err(e) => {
                let _ = writeln!(
                    err,
                    "linux: {} could not run: {e}\nlinux: COULD NOT RUN, not a pass",
                    suite.label
                );
                keep_logs(opts, &transcript.0, err);
                return code::COULD_NOT_RUN;
            }
        }
    }

    // The verdict: exit 0 only if every suite ran and every suite was ok.
    let mut total = parse::Summary {
        suites: 0,
        passed: 0,
        failed: 0,
        ignored: 0,
        all_ok: !judged.is_empty(),
    };
    let _ = writeln!(out, "linux: suite results:");
    for (label, summary) in &judged {
        let _ = writeln!(
            out,
            "  {:38} {} ({} passed, {} failed, {} ignored)",
            label,
            if summary.all_ok { "ok" } else { "FAILED" },
            summary.passed,
            summary.failed,
            summary.ignored
        );
        total.suites += summary.suites;
        total.passed += summary.passed;
        total.failed += summary.failed;
        total.ignored += summary.ignored;
        total.all_ok &= summary.all_ok;
    }
    transcript.add("verdict", format!("{total:?}").as_bytes());
    keep_logs(opts, &transcript.0, err);
    if total.all_ok {
        let _ = writeln!(
            out,
            "linux: PASS {} suites, {} passed, {} failed, {} ignored ({}s)",
            judged.len(),
            total.passed,
            total.failed,
            total.ignored,
            started.elapsed().as_secs()
        );
        return code::PASS;
    }
    if total.suites == 0 {
        let _ = writeln!(
            err,
            "linux: FAIL no `test result:` line in the whole log — the suite did not run to a tally; not a pass"
        );
    } else {
        let _ = writeln!(
            err,
            "linux: FAIL {} suites, {} passed, {} failed, {} ignored ({}s)",
            judged.len(),
            total.passed,
            total.failed,
            total.ignored,
            started.elapsed().as_secs()
        );
    }
    code::TESTS_FAILED
}

/// The human reason a run's exit status was not success, for one line.
fn rsync_why(shot: &proc::Outcome) -> String {
    match shot.status {
        Some(status) => format!("exit {status}"),
        None => "no exit status".to_string(),
    }
}

/// Copy the transcript to `--keep-logs DIR`, when asked, whatever the
/// verdict; a failure to keep logs is reported but never changes the code.
fn keep_logs(opts: &Options, transcript: &str, err: &mut dyn Write) {
    let Some(dir) = &opts.keep_logs else {
        return;
    };
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = dir.join(format!("{}-{secs}.log", opts.vm));
    if let Err(e) = fs::create_dir_all(dir).and_then(|()| fs::write(&path, transcript)) {
        let _ = writeln!(err, "linux: could not keep logs at {}: {e}", path.display());
    } else {
        let _ = writeln!(err, "linux: transcript kept at {}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory the test owns (and a later run of the same test
    /// re-creates from scratch).
    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rh-dev-linux-test-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Fast options pointed at programs that cannot reach a VM; the lock
    /// lives in the scratch dir so tests never touch `/tmp/rh-linux-vm.lock`.
    fn stub_options(tag: &str) -> (Options, PathBuf) {
        let tmp = temp_dir(tag);
        let mut opts = Options::new("rh-linux", "ci@vm.invalid");
        opts.lock_path = tmp.join("lock");
        opts.ssh_wait = Duration::from_millis(400);
        opts.poll_every = Duration::from_millis(25);
        opts.ssh = PathBuf::from("/usr/bin/false");
        (opts, tmp)
    }

    /// No `--ssh` means no run; the error must carry the usage text.
    #[test]
    fn rh_dev_linux_usage_requires_ssh_target() {
        let err = parse_args(&[]).unwrap_err();
        assert!(err.contains("--ssh"), "usage must name --ssh: {err}");
        assert!(err.contains(USAGE));

        let err = parse_args(&["--ssh"]).unwrap_err();
        assert!(err.contains("missing value for --ssh"));

        let err = parse_args(&["--ssh", "u@h", "--nope"]).unwrap_err();
        assert!(err.contains("unknown flag"), "got: {err}");

        let err = parse_args(&["--ssh", "u@h", "--timeout", "0"]).unwrap_err();
        assert!(err.contains("--timeout"), "got: {err}");

        let err = parse_args(&["--ssh", "u@h", "--ssh-wait", "0"]).unwrap_err();
        assert!(err.contains("--ssh-wait"), "got: {err}");

        let opts = parse_args(&["--ssh", "u@h", "--boot", "--only", "t", "--vm", "v"]).unwrap();
        assert!(opts.boot);
        assert_eq!(opts.only.as_deref(), Some("t"));
        assert_eq!(opts.vm, "v");
        assert_eq!(opts.ssh_target, "u@h");
        assert_eq!(opts.lock_path, PathBuf::from(DEFAULT_LOCK));
    }

    /// The lock is the whole-run mutual exclusion: take it, see a second
    /// taker refused, see it gone after the holder drops.
    #[test]
    fn rh_dev_linux_acquires_the_vm_lock() {
        let tmp = temp_dir("lock");
        let path = tmp.join("vm.lock");
        {
            let _guard = acquire_lock(&path).unwrap();
            assert!(path.is_dir(), "the lock is a directory");
            match acquire_lock(&path) {
                Err(LockError::Busy) => {}
                other => panic!("second acquire must be Busy, got {other:?}"),
            }
        }
        assert!(!path.exists(), "dropping the guard releases the lock");
    }

    /// An unreachable VM is a loud non-zero skip that says it is NOT a pass,
    /// and the lock is released on the way out.
    #[test]
    fn rh_dev_linux_unreachable_vm_is_loud_nonzero() {
        let (opts, tmp) = stub_options("unreachable");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&opts, &mut out, &mut err);
        assert_eq!(code, code::SKIPPED, "an unreachable VM is not a pass");
        let err = String::from_utf8(err).unwrap();
        assert!(err.contains("SKIPPED"), "loud: {err}");
        assert!(err.contains("not a pass"), "loud: {err}");
        assert!(
            !opts.lock_path.exists(),
            "the lock must be released on the skip path"
        );
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains("PASS"), "stdout must not claim a pass: {out}");
        let _ = fs::remove_dir_all(&tmp);
    }

    /// Every remote word travels as an argv item; no local shell, no `sh
    /// -c`, for the probe, the boot, the sync and the suite alike.
    #[test]
    fn rh_dev_linux_builds_the_ssh_and_rsync_argv_without_a_shell() {
        let mut opts = Options::new("rh-linux", "ci@vm.invalid");
        opts.repo_root = PathBuf::from("/repo");
        opts.only = Some("my_test".to_string());

        let poll = poll_argv(&opts);
        assert_eq!(
            poll,
            svec(&[
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                "ci@vm.invalid",
                "--",
                "true",
            ])
        );

        let boot = boot_argv(&opts);
        assert_eq!(boot, svec(&[DEFAULT_UTMCTL, "start", "rh-linux"]),);

        let rsync = rsync_argv(&opts);
        assert_eq!(
            rsync,
            svec(&[
                "rsync",
                "-a",
                "--delete",
                "--exclude",
                "target/",
                "--exclude",
                ".git/",
                "-e",
                "ssh",
                "/repo/",
                "ci@vm.invalid:rh-work/",
            ])
        );

        let suite = suite_argv(&opts, &SUITES[0], 60);
        assert_eq!(
            suite,
            svec(&[
                "ssh",
                "-o",
                "BatchMode=yes",
                "-tt",
                "ci@vm.invalid",
                "--",
                "cd",
                "rh-work",
                "&&",
                "timeout",
                "60",
                "cargo",
                "test",
                "-p",
                "harness-sandbox",
                "--test",
                "conformance_linux",
                "--",
                "my_test",
                "--nocapture",
                "--test-threads=1",
            ])
        );

        for argv in [&poll, &boot, &rsync, &suite] {
            for word in argv {
                assert_ne!(word, "sh", "no shell: {argv:?}");
                assert_ne!(word, "bash", "no shell: {argv:?}");
                assert_ne!(word, "-c", "no shell flag: {argv:?}");
            }
        }
    }

    /// A sync that fails is loud and non-zero (COULD NOT RUN), never a
    /// silent pass; a reachable ssh stub is `/usr/bin/true`.
    #[test]
    fn rh_dev_linux_failed_sync_is_loud_nonzero() {
        let (mut opts, tmp) = stub_options("sync");
        opts.ssh = PathBuf::from("/usr/bin/true");
        opts.rsync = PathBuf::from("/usr/bin/false");
        opts.repo_root = tmp.join("repo");
        fs::create_dir_all(&opts.repo_root).unwrap();
        fs::write(opts.repo_root.join("seed.txt"), b"seed").unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&opts, &mut out, &mut err);
        assert_eq!(code, code::COULD_NOT_RUN, "a failed sync is not a pass");
        let err = String::from_utf8(err).unwrap();
        assert!(err.contains("rsync failed"), "loud: {err}");
        assert!(err.contains("not a pass"), "loud: {err}");
        assert!(!opts.lock_path.exists());
        let _ = fs::remove_dir_all(&tmp);
    }

    /// `--keep-logs DIR` gets the transcript even on a skip, and the log
    /// names the VM.
    #[test]
    fn rh_dev_linux_keeps_logs_on_a_skip() {
        let (mut opts, tmp) = stub_options("logs");
        let logs = tmp.join("logs");
        opts.keep_logs = Some(logs.clone());

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&opts, &mut out, &mut err);
        assert_eq!(code, code::SKIPPED);

        let mut entries: Vec<PathBuf> = fs::read_dir(&logs)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(entries.len(), 1, "one transcript: {entries:?}");
        entries.sort();
        let name = entries[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(name.starts_with("rh-linux-"), "named for the VM: {name}");
        let text = fs::read_to_string(&entries[0]).unwrap();
        assert!(
            text.contains("ssh probe"),
            "the transcript, not stdout: {text}"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    /// A busy lock skips before anything runs: no probe, no sync, no suite.
    #[test]
    fn rh_dev_linux_busy_lock_skips_without_running_anything() {
        let (mut opts, tmp) = stub_options("busy");
        fs::create_dir_all(&opts.lock_path).unwrap();
        opts.ssh = PathBuf::from("/usr/bin/false");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&opts, &mut out, &mut err);
        assert_eq!(code, code::SKIPPED);
        let err = String::from_utf8(err).unwrap();
        assert!(err.contains("is held"), "names the holder path: {err}");
        assert!(err.contains("not a pass"));
        let out = String::from_utf8(out).unwrap();
        assert!(out.is_empty(), "nothing ran: {out:?}");
        let _ = fs::remove_dir_all(&tmp);
    }

    fn svec(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_string()).collect()
    }
}
