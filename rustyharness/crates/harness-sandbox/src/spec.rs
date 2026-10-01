//! What a confined child gets (design §6.2), and what it leaves behind.
//!
//! [`ConfinedSpec`] is the backend-neutral request. [`validate`] turns it
//! into a [`Validated`] spec or refuses it with a typed [`SpecError`]; every
//! backend spawns only from a `Validated` spec, so every rule here holds on
//! every OS. Everything not granted is denied: the backend adds nothing but
//! the system paths a process needs to start (named per backend).
//!
//! Rules (each refusal has a test):
//! - `argv` is a vector, never a shell string; `argv[0]` is an absolute
//!   path (the exec allowlist that resolves it is `harness-run`'s, §4.8); no
//!   item holds a NUL.
//! - `env` is built by the harness, never inherited (§5.5): names are
//!   `[A-Za-z_][A-Za-z0-9_]*`, unique, and never a loader variable
//!   (`DYLD_*`, `LD_*`, INV-10's preventive half).
//! - Roots (`read_only`, `read_write`) are existing directories, used by
//!   their canonical path. A root is refused if it is `/`, if it contains
//!   the user's home directory (only subpaths of home may be granted,
//!   §6.2), if its last component is a symlink, if it contains the
//!   backend's private directory, or if a read-only root lies at or under a
//!   read-write root (use `protected` for that). Paths must be UTF-8 with
//!   no `"`, `\` or control character: they are written into generated
//!   policy text (the OD-5 draft's CF-20 concern), so they are refused
//!   rather than escaped.
//! - `protected` paths exist and lie inside a read-write root.
//! - `cwd` exists and lies inside a root.
//! - `network` is `None`; a proxy grant is H4 and refused here.
//! - `limits`: a wall clock is required; CPU, file size, memory
//!   (address-space budget) and process count are optional and bounded to
//!   what the backend's launch protocol accepts (LOW-1). Memory and
//!   process-count limits are refused where the backend cannot enforce them,
//!   never silently dropped.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Largest wall clock a spec may ask for.
pub const MAX_WALL: Duration = Duration::from_secs(24 * 60 * 60);
/// Largest CPU-time limit a spec may ask for (365 days; the macOS stub
/// frames CPU seconds as at most 12 digits, so this stays well inside what
/// the stub accepts, LOW-1).
pub const MAX_CPU: Duration = Duration::from_secs(365 * 24 * 60 * 60);
/// Largest file-size limit a spec may ask for (16 TiB; the stub frames the
/// byte count as at most 15 digits, LOW-1).
pub const MAX_FILE_SIZE: u64 = 1 << 44;
/// Largest memory (address-space) budget a spec may ask for, where a backend
/// enforces one (16 TiB; framed as at most 15 digits by the macOS stub).
pub const MAX_MEMORY: u64 = 1 << 44;
/// Largest process-count cap a spec may ask for, where a backend enforces one
/// (framed as at most 6 digits by the macOS stub's watchdog).
pub const MAX_PROCESSES: u32 = 100_000;
/// Largest per-stream output cap a spec may ask for.
pub const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
/// Largest total size of argv plus env (they travel over a pipe, §6.3).
pub const MAX_ARGV_ENV_BYTES: usize = 1024 * 1024;

/// A request to run one program confined (design §6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfinedSpec {
    /// The program and its arguments; `argv[0]` is an absolute path.
    pub argv: Vec<OsString>,
    /// Working directory; must lie inside a root.
    pub cwd: PathBuf,
    /// The complete environment (built, never inherited).
    pub env: Vec<(OsString, OsString)>,
    /// Readable roots (toolchains, base tree).
    pub read_only: Vec<PathBuf>,
    /// Readable and writable roots (workspace, scratch).
    pub read_write: Vec<PathBuf>,
    /// Read-only overlays inside the read-write roots (§7.6).
    pub protected: Vec<PathBuf>,
    /// Network access.
    pub network: Network,
    /// Resource limits.
    pub limits: Limits,
}

/// Network access for a confined child (§6.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Network {
    /// No network at all: no connect, no bind, no listen, no resolver
    /// (and, D31, no bind on a shared stack even to loopback).
    None,
    /// Egress only through the harness's allowlist proxy (H4; refused).
    Proxy {
        /// The task grant's allowlist id.
        allowlist_id: String,
    },
}

/// Resource limits (§6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Wall clock, enforced by the harness (FT-8).
    pub wall: Duration,
    /// CPU time (whole seconds, rounded up).
    pub cpu: Option<Duration>,
    /// Largest file the child may write, in bytes (FT-7).
    pub file_size: Option<u64>,
    /// Address-space budget in bytes (FT-6): the most memory the confined
    /// program, and each of its descendants, may map beyond its own program
    /// image. On macOS the stub sets `RLIMIT_AS` to the process's own virtual
    /// size plus this budget, so the kernel refuses further `mmap`/`brk`
    /// (H2c: measured enforced on macOS 26.5.1; the H2a report's "not
    /// enforced" was wrong). It bounds each process, not the tree's sum;
    /// combine with `processes` for an aggregate bound. Refused by a backend
    /// that cannot enforce it.
    pub memory: Option<u64>,
    /// Process-count cap (FT-5): the most processes the confined program's
    /// sandbox instance may hold. On macOS the stub's watchdog sweeps the
    /// domain when members exceed this (H2c; `RLIMIT_NPROC` is per user, so it
    /// cannot bound one sandbox). Refused by a backend that cannot enforce it.
    pub processes: Option<u32>,
    /// Bytes kept of each of stdout and stderr; the rest is read and dropped.
    pub output_bytes: u64,
}

impl Limits {
    /// A wall clock with a 1 MiB output cap and no other limit.
    pub fn wall(wall: Duration) -> Self {
        Limits {
            wall,
            cpu: None,
            file_size: None,
            memory: None,
            processes: None,
            output_bytes: 1024 * 1024,
        }
    }
}

/// Why a spec is refused. Every variant is a refusal: nothing runs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpecError {
    /// `argv` is empty.
    #[error("argv is empty")]
    EmptyArgv,
    /// `argv[0]` is not an absolute path.
    #[error("argv[0] is not an absolute path")]
    RelativeProgram,
    /// An argv item or env entry holds a NUL byte.
    #[error("a NUL byte in argv or env")]
    Nul,
    /// argv and env together are too large.
    #[error("argv and env exceed {MAX_ARGV_ENV_BYTES} bytes")]
    TooLarge,
    /// An env name is malformed or repeated.
    #[error("bad or repeated environment name {0:?}")]
    EnvName(String),
    /// An env name is a loader variable.
    #[error("loader variable {0} refused (INV-10)")]
    LoaderVariable(String),
    /// A path cannot be used as a root, cwd or protected path.
    #[error("{what} {path:?} refused: {why}")]
    Path {
        /// Which field.
        what: &'static str,
        /// The path as given.
        path: PathBuf,
        /// Why.
        why: &'static str,
    },
    /// A granted capability this backend or phase cannot provide.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    /// A limit is out of range.
    #[error("limit out of range: {0}")]
    Limit(&'static str),
}

/// Which limits a backend can enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enforceable {
    /// Memory caps are enforced.
    pub memory: bool,
    /// Process-count caps are enforced.
    pub processes: bool,
}

/// A spec that passed [`validate`]: canonical UTF-8 paths, raw argv and
/// `NAME=VALUE` env entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validated {
    /// argv as bytes.
    pub argv: Vec<Vec<u8>>,
    /// env as `NAME=VALUE` bytes.
    pub env: Vec<Vec<u8>>,
    /// Canonical working directory.
    pub cwd: String,
    /// Canonical read-only roots.
    pub read_only: Vec<String>,
    /// Canonical read-write roots.
    pub read_write: Vec<String>,
    /// Canonical protected paths.
    pub protected: Vec<String>,
    /// Limits, checked.
    pub limits: Limits,
}

/// The environment the backend validates against.
#[derive(Debug, Clone)]
pub struct Context<'a> {
    /// The user's home directory, canonical, if known. A root containing it
    /// is refused.
    pub home: Option<&'a Path>,
    /// The backend's private directory (profiles), canonical. A root
    /// containing it is refused.
    pub private_dir: &'a Path,
    /// What the backend can enforce.
    pub enforce: Enforceable,
}

/// Validate `spec` (see the module docs).
pub fn validate(spec: &ConfinedSpec, cx: &Context<'_>) -> Result<Validated, SpecError> {
    let argv = check_argv(&spec.argv)?;
    let env = check_env(&spec.env)?;
    let total: usize = argv.iter().chain(env.iter()).map(|b| b.len() + 16).sum();
    if total > MAX_ARGV_ENV_BYTES {
        return Err(SpecError::TooLarge);
    }
    let read_write = roots("read-write root", &spec.read_write, cx)?;
    let read_only = roots("read-only root", &spec.read_only, cx)?;
    for (given, ro) in spec.read_only.iter().zip(&read_only) {
        if read_write.iter().any(|rw| within(ro, rw)) {
            return Err(path_err(
                "read-only root",
                given,
                "lies at or under a read-write root (use protected)",
            ));
        }
    }
    let mut protected = Vec::new();
    for p in &spec.protected {
        let c = canonical("protected path", p)?;
        if !read_write.iter().any(|rw| within(&c, rw)) {
            return Err(path_err(
                "protected path",
                p,
                "is not inside a read-write root",
            ));
        }
        protected.push(c);
    }
    let cwd = canonical("cwd", &spec.cwd)?;
    if !read_write
        .iter()
        .chain(read_only.iter())
        .any(|r| within(&cwd, r))
    {
        return Err(path_err("cwd", &spec.cwd, "is not inside a root"));
    }
    if spec.network != Network::None {
        return Err(SpecError::Unsupported(
            "network through the egress proxy (H4)",
        ));
    }
    check_limits(&spec.limits, cx.enforce)?;
    Ok(Validated {
        argv,
        env,
        cwd,
        read_only,
        read_write,
        protected,
        limits: spec.limits.clone(),
    })
}

fn bytes_of(s: &std::ffi::OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        s.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        s.to_string_lossy().into_owned().into_bytes()
    }
}

fn check_argv(argv: &[OsString]) -> Result<Vec<Vec<u8>>, SpecError> {
    let Some(first) = argv.first() else {
        return Err(SpecError::EmptyArgv);
    };
    if !Path::new(first).is_absolute() {
        return Err(SpecError::RelativeProgram);
    }
    let out: Vec<Vec<u8>> = argv.iter().map(|a| bytes_of(a)).collect();
    if out.iter().any(|a| a.contains(&0)) {
        return Err(SpecError::Nul);
    }
    Ok(out)
}

fn check_env(env: &[(OsString, OsString)]) -> Result<Vec<Vec<u8>>, SpecError> {
    let mut seen: Vec<&std::ffi::OsStr> = Vec::new();
    let mut out = Vec::new();
    for (k, v) in env {
        let name = k.to_str().unwrap_or("");
        let mut chars = name.chars();
        let ok = match chars.next() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {
                chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
            }
            _ => false,
        };
        if !ok || seen.contains(&k.as_os_str()) {
            return Err(SpecError::EnvName(k.to_string_lossy().into_owned()));
        }
        if name.starts_with("DYLD_") || name.starts_with("LD_") {
            return Err(SpecError::LoaderVariable(name.to_string()));
        }
        seen.push(k);
        let mut e = name.as_bytes().to_vec();
        e.push(b'=');
        e.extend(bytes_of(v));
        if e.contains(&0) {
            return Err(SpecError::Nul);
        }
        out.push(e);
    }
    Ok(out)
}

fn path_err(what: &'static str, path: &Path, why: &'static str) -> SpecError {
    SpecError::Path {
        what,
        path: path.to_path_buf(),
        why,
    }
}

/// `inner` is `outer` or lies under it (canonical strings, component-wise).
pub fn within(inner: &str, outer: &str) -> bool {
    if outer == "/" {
        return true;
    }
    inner == outer
        || (inner.len() > outer.len()
            && inner.starts_with(outer)
            && inner.as_bytes().get(outer.len()) == Some(&b'/'))
}

/// A path string that is safe to write into generated policy text.
pub fn policy_safe(s: &str) -> bool {
    s.starts_with('/') && !s.chars().any(|c| c == '"' || c == '\\' || c.is_control())
}

fn canonical(what: &'static str, p: &Path) -> Result<String, SpecError> {
    if !p.is_absolute() {
        return Err(path_err(what, p, "is not absolute"));
    }
    let c = std::fs::canonicalize(p).map_err(|_| path_err(what, p, "does not exist"))?;
    let Some(s) = c.to_str() else {
        return Err(path_err(what, p, "is not UTF-8"));
    };
    if !policy_safe(s) {
        return Err(path_err(
            what,
            p,
            "holds a quote, backslash or control character",
        ));
    }
    Ok(s.to_string())
}

fn roots(
    what: &'static str,
    given: &[PathBuf],
    cx: &Context<'_>,
) -> Result<Vec<String>, SpecError> {
    let private = cx.private_dir.to_str().unwrap_or("/");
    let home = cx.home.and_then(Path::to_str);
    let mut out = Vec::new();
    for p in given {
        let meta = std::fs::symlink_metadata(p).map_err(|_| path_err(what, p, "does not exist"))?;
        if meta.file_type().is_symlink() {
            return Err(path_err(what, p, "is a symlink"));
        }
        let c = canonical(what, p)?;
        if !std::fs::metadata(&c).map(|m| m.is_dir()).unwrap_or(false) {
            return Err(path_err(what, p, "is not a directory"));
        }
        if c == "/" {
            return Err(path_err(what, p, "is the filesystem root"));
        }
        if let Some(h) = home {
            if within(h, &c) {
                return Err(path_err(what, p, "contains the home directory"));
            }
        }
        if within(private, &c) || within(&c, private) {
            return Err(path_err(
                what,
                p,
                "overlaps the backend's private directory",
            ));
        }
        out.push(c);
    }
    Ok(out)
}

fn check_limits(l: &Limits, enforce: Enforceable) -> Result<(), SpecError> {
    if l.wall.is_zero() || l.wall > MAX_WALL {
        return Err(SpecError::Limit("wall must be in (0, 24h]"));
    }
    if l.output_bytes == 0 || l.output_bytes > MAX_OUTPUT_BYTES {
        return Err(SpecError::Limit("output cap must be in [1, 64 MiB]"));
    }
    // Each optional limit is bounded on BOTH sides: below so it means
    // something, above so a backend's launch protocol can always carry it as
    // a typed refusal here rather than failing to frame later (LOW-1).
    if let Some(c) = l.cpu {
        if c.is_zero() || c > MAX_CPU {
            return Err(SpecError::Limit("cpu must be in (0, 365 days]"));
        }
    }
    if let Some(fs) = l.file_size {
        if fs == 0 || fs > MAX_FILE_SIZE {
            return Err(SpecError::Limit("file size must be in [1, 16 TiB]"));
        }
    }
    if let Some(m) = l.memory {
        if !enforce.memory {
            return Err(SpecError::Unsupported(
                "a memory limit (not enforceable by this backend; FT-6)",
            ));
        }
        if m == 0 || m > MAX_MEMORY {
            return Err(SpecError::Limit("memory budget must be in [1, 16 TiB]"));
        }
    }
    if let Some(n) = l.processes {
        if !enforce.processes {
            return Err(SpecError::Unsupported(
                "a process-count limit (not enforceable by this backend; FT-5)",
            ));
        }
        if n == 0 || n > MAX_PROCESSES {
            return Err(SpecError::Limit("process count must be in [1, 100000]"));
        }
    }
    Ok(())
}

/// How the confined program ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildStatus {
    /// It exited with this code.
    Exited(i32),
    /// It was ended by this signal.
    Signaled(i32),
    /// The wall clock ran out and the harness stopped it (FT-8).
    TimedOut,
    /// The sandbox held more processes than the cap allowed, so the domain
    /// was swept (FT-5). A clean, intended stop, like [`Self::TimedOut`].
    ProcessLimit,
    /// The program could not be started inside the sandbox.
    ExecFailed,
    /// No trustworthy status: the backend's own report is missing.
    Unknown,
}

/// Whether everything the call started is gone (the kill domain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainCleanup {
    /// Every process of the call's domain is confirmed gone.
    Confirmed {
        /// Processes killed by the sweep (the program itself included when
        /// it was still running).
        kills: u32,
    },
    /// The harness cannot confirm the domain is empty: a process may have
    /// survived. Never reported as a clean stop.
    Unconfirmed(String),
}

/// What a confined call left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfinedExit {
    /// How the program ended.
    pub status: ChildStatus,
    /// The first `output_bytes` of stdout.
    pub stdout: Vec<u8>,
    /// Stdout was longer than the cap.
    pub stdout_truncated: bool,
    /// The first `output_bytes` of stderr (the backend's own report removed).
    pub stderr: Vec<u8>,
    /// Stderr was longer than the cap.
    pub stderr_truncated: bool,
    /// The kill domain after the call.
    pub domain: DomainCleanup,
    /// Wall time from spawn to the end of cleanup.
    pub elapsed: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "rh-spec-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn base(ws: &Path) -> ConfinedSpec {
        ConfinedSpec {
            argv: vec!["/bin/echo".into(), "hi".into()],
            cwd: ws.to_path_buf(),
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            read_only: vec![],
            read_write: vec![ws.to_path_buf()],
            protected: vec![],
            network: Network::None,
            limits: Limits::wall(Duration::from_secs(5)),
        }
    }

    const ENF: Enforceable = Enforceable {
        memory: false,
        processes: false,
    };

    #[test]
    fn a_plain_spec_validates_with_canonical_paths() {
        let ws = tmp("ok");
        let private = tmp("private");
        let privc = std::fs::canonicalize(&private).unwrap();
        let cx = Context {
            home: None,
            private_dir: &privc,
            enforce: ENF,
        };
        let v = validate(&base(&ws), &cx).unwrap();
        let c = std::fs::canonicalize(&ws).unwrap();
        assert_eq!(v.read_write, vec![c.to_str().unwrap().to_string()]);
        assert_eq!(v.cwd, c.to_str().unwrap());
        assert_eq!(v.env, vec![b"PATH=/usr/bin:/bin".to_vec()]);
    }

    #[test]
    fn each_rule_refuses() {
        let ws = tmp("refuse");
        let wsc = std::fs::canonicalize(&ws).unwrap();
        let private = tmp("private2");
        let privc = std::fs::canonicalize(&private).unwrap();
        let home = wsc.join("sub");
        std::fs::create_dir_all(&home).unwrap();
        let cx = Context {
            home: Some(&home),
            private_dir: &privc,
            enforce: ENF,
        };
        let cx_nohome = Context {
            home: None,
            private_dir: &privc,
            enforce: ENF,
        };
        let check = |f: &dyn Fn(&mut ConfinedSpec), cx: &Context<'_>, want: &str| {
            let mut s = base(&ws);
            f(&mut s);
            let e = validate(&s, cx).unwrap_err();
            assert!(e.to_string().contains(want), "{e} (wanted {want})");
        };
        check(&|s| s.argv.clear(), &cx_nohome, "argv is empty");
        check(&|s| s.argv[0] = "echo".into(), &cx_nohome, "absolute");
        check(&|s| s.argv.push("a\0b".into()), &cx_nohome, "NUL");
        check(
            &|s| s.env.push(("DYLD_INSERT_LIBRARIES".into(), "x".into())),
            &cx_nohome,
            "loader variable",
        );
        check(
            &|s| s.env.push(("LD_PRELOAD".into(), "x".into())),
            &cx_nohome,
            "loader",
        );
        check(
            &|s| s.env.push(("PATH".into(), "x".into())),
            &cx_nohome,
            "repeated",
        );
        check(
            &|s| s.env.push(("A=B".into(), "x".into())),
            &cx_nohome,
            "environment name",
        );
        check(
            &|s| s.read_write = vec!["/".into()],
            &cx_nohome,
            "filesystem root",
        );
        check(
            &|s| s.read_only.push(ws.clone()),
            &cx_nohome,
            "use protected",
        );
        check(
            &|s| s.read_write.push(privc.clone()),
            &cx_nohome,
            "private directory",
        );
        check(&|_| {}, &cx, "contains the home directory");
        check(&|s| s.cwd = "/usr".into(), &cx_nohome, "not inside a root");
        check(
            &|s| s.protected.push("/usr".into()),
            &cx_nohome,
            "not inside a read-write root",
        );
        check(
            &|s| s.read_write.push(ws.join("missing")),
            &cx_nohome,
            "does not exist",
        );
        check(
            &|s| {
                s.network = Network::Proxy {
                    allowlist_id: "a".into(),
                }
            },
            &cx_nohome,
            "proxy",
        );
        check(&|s| s.limits.memory = Some(1 << 30), &cx_nohome, "FT-6");
        check(&|s| s.limits.processes = Some(10), &cx_nohome, "FT-5");
        check(&|s| s.limits.wall = Duration::ZERO, &cx_nohome, "wall");
        check(&|s| s.limits.output_bytes = 0, &cx_nohome, "output cap");
        let q = ws.join("a\"b");
        std::fs::create_dir_all(&q).unwrap();
        check(&|s| s.read_write.push(q.clone()), &cx_nohome, "quote");
        #[cfg(unix)]
        {
            let link = ws.join("link");
            std::os::unix::fs::symlink(&private, &link).unwrap();
            check(&|s| s.read_only.push(link.clone()), &cx_nohome, "symlink");
        }
    }

    #[test]
    fn limits_are_bounded_on_both_sides() {
        let ws = tmp("limits");
        let privc = std::fs::canonicalize(tmp("limits-priv")).unwrap();
        let enforcing = Context {
            home: None,
            private_dir: &privc,
            enforce: Enforceable {
                memory: true,
                processes: true,
            },
        };
        let check = |f: &dyn Fn(&mut ConfinedSpec), cx: &Context<'_>, want: &str| {
            let mut s = base(&ws);
            f(&mut s);
            let e = validate(&s, cx).unwrap_err();
            assert!(e.to_string().contains(want), "{e} (wanted {want})");
        };
        // Above the upper bound: a typed SpecError, not a spec the backend
        // accepts and then cannot launch (LOW-1).
        check(
            &|s| s.limits.cpu = Some(MAX_CPU + Duration::from_secs(1)),
            &enforcing,
            "cpu must be in",
        );
        check(
            &|s| s.limits.file_size = Some(MAX_FILE_SIZE + 1),
            &enforcing,
            "file size must be in",
        );
        check(
            &|s| s.limits.memory = Some(MAX_MEMORY + 1),
            &enforcing,
            "memory budget must be in",
        );
        check(
            &|s| s.limits.processes = Some(MAX_PROCESSES + 1),
            &enforcing,
            "process count must be in",
        );
        check(&|s| s.limits.memory = Some(0), &enforcing, "memory budget");
        check(
            &|s| s.limits.processes = Some(0),
            &enforcing,
            "process count",
        );
        // At the bound, with an enforcing backend, they validate.
        let mut s = base(&ws);
        s.limits.cpu = Some(MAX_CPU);
        s.limits.file_size = Some(MAX_FILE_SIZE);
        s.limits.memory = Some(MAX_MEMORY);
        s.limits.processes = Some(MAX_PROCESSES);
        assert!(validate(&s, &enforcing).is_ok());
    }

    #[test]
    fn within_is_component_wise() {
        assert!(within("/a/b", "/a"));
        assert!(within("/a", "/a"));
        assert!(!within("/ab", "/a"));
        assert!(within("/x", "/"));
        assert!(!policy_safe("rel"));
        assert!(!policy_safe("/a\nb"));
        assert!(policy_safe("/a b/c"));
    }
}
