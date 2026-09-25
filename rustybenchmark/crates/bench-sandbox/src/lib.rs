//! `bench-sandbox` — containment for the one thing that runs untrusted code.
//!
//! The oracle executes model-authored Rust during grading (compile — proc
//! macros run at build time — and the test binaries). Everything the oracle
//! shells out runs through [`run`], so this crate is the single place that
//! containment is applied.
//!
//! **macOS (the only backend):** a seatbelt profile via `sandbox-exec` that
//! denies all network and confines filesystem writes to the grading workspace,
//! the cargo caches, and the temp dirs cargo needs. `sandbox-exec` is
//! deprecated-but-functional and is what Chromium and Claude Code use for the
//! same job.
//!
//! On any other platform [`available`] reports `Unsupported` and [`run`]
//! refuses to execute anything (fail closed) unless the policy carries
//! [`Gate::AllowUnsandboxed`] — the token a caller may only pass after the
//! operator explicitly opted in. This crate never *pretends* to contain.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// Resource limits applied to a contained command. The wall-clock timeout is
/// the load-bearing one — it stops infinite loops, hangs, and fork bombs that
/// never terminate. The rest are backstops.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Wall-clock deadline. On expiry the whole process group is killed.
    pub wall: Duration,
    /// `RLIMIT_CPU` seconds — a far backstop, only for the case where the
    /// wait loop itself fails. Must stay well above the wall clock so it
    /// never pre-empts the primary control.
    pub cpu: Duration,
    /// `RLIMIT_AS` bytes — address-space cap. `None` by default: macOS
    /// enforces `RLIMIT_AS` unreliably, so it is opt-in.
    pub address_space: Option<u64>,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            wall: Duration::from_secs(120),
            cpu: Duration::from_secs(3600),
            address_space: None,
        }
    }
}

/// What containment the current platform can actually apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Containment {
    /// macOS seatbelt: network denied, writes confined to the workspace.
    Seatbelt,
    /// No containment available on this platform. The caller must decide
    /// whether to proceed, and must record that grading was unsandboxed.
    Unsupported,
}

/// The containment this platform can apply. Pure — safe to call for reporting.
pub fn available() -> Containment {
    if cfg!(target_os = "macos") {
        Containment::Seatbelt
    } else {
        Containment::Unsupported
    }
}

/// Whether execution may proceed when the platform provides no containment.
///
/// By default ([`Gate::RequireContained`]) [`run`] refuses to execute any
/// model-authored code on a platform whose containment is
/// [`Containment::Unsupported`] — model code runs at compile time too, so a
/// hostile completion would get the user's network, home directory and
/// secrets. [`Gate::AllowUnsandboxed`] is the explicit opt-in token, and the
/// caller must journal the rows it produced as uncontained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Gate {
    /// Refuse to execute unless the platform actually contains the process
    /// (the default; fail closed).
    #[default]
    RequireContained,
    /// The operator explicitly accepted uncontained execution. The command
    /// still runs uncontained, and the caller must record that in the journal.
    AllowUnsandboxed,
}

/// The one gate every executing path goes through: is `containment` good enough
/// for `gate`? [`run`] applies it before spawning anything; the CLI applies the
/// same function up front so the refusal lands *before* the model is contacted.
/// Kept as one function so the two checks cannot drift.
pub fn check_gate(gate: Gate, containment: Containment) -> io::Result<()> {
    match (gate, containment) {
        (Gate::AllowUnsandboxed, _) => Ok(()),
        (Gate::RequireContained, Containment::Seatbelt) => Ok(()),
        (Gate::RequireContained, Containment::Unsupported) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no sandbox on this platform — refusing to execute model-written code \
             uncontained; re-run with --allow-unsandboxed to accept this explicitly",
        )),
    }
}

/// A containment policy bound to one grading workspace.
pub struct Policy {
    /// The workspace root — the only place the sandboxed command may write
    /// (besides the cargo caches and temp).
    pub workspace: PathBuf,
    /// Cargo's home, allowlisted for writes so `--offline` builds can take the
    /// `.package-cache` lock and reuse the registry.
    pub cargo_home: PathBuf,
    /// Resource limits applied to every command run under this policy.
    pub limits: Limits,
    /// The authorization gate consulted by [`run`] before anything is spawned.
    /// Defaults to [`Gate::RequireContained`] so a policy built without an
    /// explicit decision refuses to run on an Unsupported platform.
    pub gate: Gate,
    /// The harness scratch root this workspace was created under, pinned by
    /// [`Policy::for_workspace_with_scratch`]: it bounds config discovery and
    /// holds the harness-made cargo home. For policies built with
    /// [`Policy::for_workspace`] this is the workspace's parent.
    pub scratch_root: PathBuf,
}

impl Policy {
    /// Build a policy for `workspace` with default limits. Paths are
    /// canonicalised because seatbelt matches on the real path, not symlinks.
    pub fn for_workspace(workspace: &Path) -> io::Result<Policy> {
        let workspace = workspace.canonicalize()?;
        let cargo_home = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")))
            .unwrap_or_else(|| PathBuf::from("/nonexistent"));
        let cargo_home = cargo_home.canonicalize().unwrap_or(cargo_home);
        let scratch_root = workspace
            .parent()
            .map(PathBuf::from)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "workspace has no parent directory; cannot bound config discovery",
                )
            })?
            .canonicalize()
            .unwrap_or_else(|_| workspace.clone());
        Ok(Policy {
            workspace,
            cargo_home,
            limits: Limits::default(),
            gate: Gate::default(),
            scratch_root,
        })
    }

    /// Build a policy for a grading workspace created under the harness's own
    /// scratch root, with a HARNESS-MADE cargo home inside that scratch root
    /// instead of the operator's: cargo reads `config.toml` from the cargo
    /// home, so an ambient `CARGO_HOME` is an operator-config channel straight
    /// into graded code. The task crates are dependency-free and `--offline`,
    /// so an empty per-run home loses nothing. Fails closed unless `workspace`
    /// is strictly inside `scratch_root` (both canonicalised).
    pub fn for_workspace_with_scratch(workspace: &Path, scratch_root: &Path) -> io::Result<Policy> {
        let workspace = workspace.canonicalize()?;
        let scratch_root = scratch_root.canonicalize()?;
        if !workspace.starts_with(&scratch_root) || workspace == scratch_root {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "grading workspace {} is not a directory strictly inside the harness scratch \
                     root {} — refusing to grade",
                    workspace.display(),
                    scratch_root.display()
                ),
            ));
        }
        let cargo_home_root = scratch_root.join(".cargo-home");
        let _ = std::fs::remove_dir_all(&cargo_home_root);
        std::fs::create_dir_all(&cargo_home_root)?;
        let cargo_home = cargo_home_root.canonicalize()?;
        Ok(Policy {
            workspace,
            cargo_home,
            limits: Limits::default(),
            gate: Gate::default(),
            scratch_root,
        })
    }

    /// Set the resource limits (builder style).
    pub fn with_limits(mut self, limits: Limits) -> Policy {
        self.limits = limits;
        self
    }

    /// Set the containment gate (builder style). Only pass
    /// [`Gate::AllowUnsandboxed`] when the operator explicitly opted in.
    pub fn with_gate(mut self, gate: Gate) -> Policy {
        self.gate = gate;
        self
    }
}

/// The result of a contained command.
#[derive(Debug)]
pub struct Outcome {
    pub status: std::process::ExitStatus,
    pub stdout: String,
    pub stderr: String,
    /// The wall-clock deadline fired and the process group was killed.
    pub timed_out: bool,
    /// What containment was actually applied to this run.
    pub containment: Containment,
}

impl Outcome {
    pub fn success(&self) -> bool {
        self.status.success()
    }
}

/// Run `program args…` with the current directory set to the policy's
/// workspace, under the seatbelt profile. `envs` are set on the child (and
/// propagate through `sandbox-exec` to the real program).
///
/// Fail closed: when [`available`] is [`Containment::Unsupported`] the
/// policy's [`Policy::gate`] must be [`Gate::AllowUnsandboxed`] or this
/// returns `PermissionDenied` before any process is spawned.
pub fn run(
    policy: &Policy,
    program: &str,
    args: &[&str],
    envs: &[(&str, &str)],
) -> io::Result<Outcome> {
    check_gate(policy.gate, available())?;
    let profile = seatbelt_profile(policy).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "workspace or cargo-home path contains a double quote; refusing to build a seatbelt profile",
        )
    })?;

    let mut cmd = Command::new("sandbox-exec");
    cmd.arg("-p").arg(&profile).arg(program).args(args);
    cmd.current_dir(&policy.workspace);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    // The only writable temp is inside the workspace (see [`pinned_tmpdir`]);
    // without the pin children would write the system temp and fail.
    cmd.env("TMPDIR", pinned_tmpdir(policy)?);
    finish(cmd, &policy.limits, Containment::Seatbelt)
}

/// The child's only writable temp directory: a scratch inside its own
/// workspace (covered by the workspace write allow), with `TMPDIR` pinned to
/// it. Fails closed: a temp dir that cannot be made refuses the spawn.
fn pinned_tmpdir(policy: &Policy) -> io::Result<PathBuf> {
    let tmp = policy.workspace.join(".tmp");
    std::fs::create_dir_all(&tmp)?;
    Ok(tmp)
}

/// The seatbelt profile (SBPL): permit by default, then subtract what matters —
/// network, and writes outside the confinement set. The rest of the filesystem
/// stays readable because the toolchain needs it. Later rules win in SBPL.
#[cfg(target_os = "macos")]
fn seatbelt_profile(policy: &Policy) -> Option<String> {
    let ws = policy.workspace.to_str()?;
    let ch = policy.cargo_home.to_str()?;
    if ws.contains('"') || ch.contains('"') {
        return None;
    }
    Some(format!(
        "(version 1)\n\
         (allow default)\n\
         (deny network*)\n\
         (deny file-write*)\n\
         (allow file-write* (subpath \"{ws}\"))\n\
         (allow file-write* (subpath \"{ch}\"))\n\
         (allow file-write-data (literal \"/dev/null\") (literal \"/dev/dtracehelper\") (literal \"/dev/urandom\"))"
    ))
}

/// Run `cmd` to completion under `limits`: apply rlimits and a private process
/// group in the child, capture stdio to temp files (so a full pipe cannot
/// deadlock the manual wait), and enforce the wall-clock deadline by killing the
/// whole process group.
fn finish(mut cmd: Command, limits: &Limits, containment: Containment) -> io::Result<Outcome> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        // The child leads its own process group, so the deadline can kill the
        // entire tree (cargo → rustc → the test binary), not just the direct
        // child.
        cmd.process_group(0);

        // rlimits are set post-fork, pre-exec, and inherit to every descendant.
        let cpu = limits.cpu.as_secs();
        let addr = limits.address_space;
        #[allow(unsafe_code)]
        // SAFETY: setrlimit is async-signal-safe; the closure touches no heap
        // and no shared state, which is the contract for pre_exec.
        unsafe {
            cmd.pre_exec(move || {
                let cpu_lim = libc::rlimit {
                    rlim_cur: cpu as libc::rlim_t,
                    rlim_max: cpu as libc::rlim_t,
                };
                libc::setrlimit(libc::RLIMIT_CPU, &cpu_lim);
                if let Some(a) = addr {
                    let as_lim = libc::rlimit {
                        rlim_cur: a as libc::rlim_t,
                        rlim_max: a as libc::rlim_t,
                    };
                    libc::setrlimit(libc::RLIMIT_AS, &as_lim);
                }
                Ok(())
            });
        }

        let out_path = temp_log("out");
        let err_path = temp_log("err");
        cmd.stdout(std::fs::File::create(&out_path)?);
        cmd.stderr(std::fs::File::create(&err_path)?);

        let mut child = cmd.spawn()?;
        let pid = child.id() as i32;
        let deadline = Instant::now() + limits.wall;
        let mut timed_out = false;
        let status = loop {
            if let Some(st) = child.try_wait()? {
                break st;
            }
            if Instant::now() >= deadline {
                timed_out = true;
                // Negative pid = the whole process group.
                #[allow(unsafe_code)]
                // SAFETY: the child was spawned with `process_group(0)` so
                // its pgid equals its pid; `-pid` therefore targets exactly
                // that group and `kill` dereferences no memory.
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
                break child.wait()?;
            }
            std::thread::sleep(Duration::from_millis(25));
        };

        let stdout = std::fs::read_to_string(&out_path).unwrap_or_default();
        let stderr = std::fs::read_to_string(&err_path).unwrap_or_default();
        let _ = std::fs::remove_file(&out_path);
        let _ = std::fs::remove_file(&err_path);
        Ok(Outcome {
            status,
            stdout,
            stderr,
            timed_out,
            containment,
        })
    }

    #[cfg(not(unix))]
    {
        let _ = limits;
        let out = cmd.output()?;
        Ok(Outcome {
            status: out.status,
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            timed_out: false,
            containment,
        })
    }
}

#[cfg(unix)]
fn temp_log(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("rb-sbx-{}-{}-{}.log", std::process::id(), tag, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_matches_platform() {
        let c = available();
        if cfg!(target_os = "macos") {
            assert_eq!(c, Containment::Seatbelt);
        } else {
            assert_eq!(c, Containment::Unsupported);
        }
    }

    #[test]
    fn limits_default_values() {
        let l = Limits::default();
        assert_eq!(l.wall, Duration::from_secs(120));
        // The CPU backstop must stay far above the wall clock so it never
        // pre-empts the primary control (see Limits::cpu docs).
        assert!(l.cpu > l.wall);
        assert_eq!(l.address_space, None);
    }

    #[test]
    fn gate_refuses_unsupported_by_default() {
        let err = check_gate(Gate::default(), Containment::Unsupported).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            err.to_string().contains("--allow-unsandboxed"),
            "refusal must name the opt-in flag, got: {err}"
        );
    }

    #[test]
    fn gate_allows_explicit_opt_in_on_unsupported() {
        check_gate(Gate::AllowUnsandboxed, Containment::Unsupported).unwrap();
    }

    #[test]
    fn gate_allows_contained_execution_by_default() {
        check_gate(Gate::default(), Containment::Seatbelt).unwrap();
    }

    #[test]
    fn policy_defaults_to_require_contained() {
        let p = Policy::for_workspace(&std::env::temp_dir()).unwrap();
        assert_eq!(p.gate, Gate::RequireContained);
        let p = p.with_gate(Gate::AllowUnsandboxed);
        assert_eq!(p.gate, Gate::AllowUnsandboxed);
    }
}
