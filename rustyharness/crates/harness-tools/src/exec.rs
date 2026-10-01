//! The built-in command runner, `harness.exec.run` (design §4.8, H2d).
//!
//! [`ExecTools`] is a [`ToolProvider`], so it runs only a
//! `Journaled<Authorized<Call>>`: policy planned the session with a
//! conformed sandbox witness (INV-6), resolved `argv[0]` by name against the
//! task's exec allowlist (INV-13), checked `cwd` against the workspace path
//! rule, and asked or was told by a user allow rule, and the intent is
//! durable (INV-33), before anything starts.
//!
//! **Pinned programs.** The task's allowlist ([`ExecSpec`]) maps a program
//! NAME, which is all the model may write in `argv[0]`, to one absolute,
//! canonical path. [`Pinned::check`] refuses anything else and records the
//! SHA-256 of each program's content at the start of the run, so the
//! journal header says exactly which binaries the names resolved to. The
//! model never chooses a path, and nothing is looked up on a `PATH`.
//!
//! **Confined, always.** Every command goes through
//! [`harness_sandbox::Confinement::spawn`] with the run's witness: there is
//! no other way to start one here (INV-6; the purity gate keeps process
//! spawning out of this crate). A command gets: the workspace and the run's
//! scratch directory as its only writable roots; the task's read-only roots
//! (toolchains); no network; a built environment ([`BUILT_ENV`] plus the
//! variables the task declares, never the harness's own, §5.5); stdin null;
//! and limits: the call's deadline as its wall clock, CPU time, a
//! per-process address-space budget (`RLIMIT_AS`, FT-6), the process-count
//! watchdog (FT-5), a file-size cap and a per-stream output cap. Build
//! output and cargo's home live in the scratch directory
//! (`CARGO_TARGET_DIR`, `CARGO_HOME`), outside the workspace, so they are
//! not in its tree digest.
//!
//! **After the command.** The sandbox reports whether every process the
//! command started is gone (its kill domain). Only when that is confirmed
//! is the workspace walked again, so the run can journal its new tree
//! digest; when it is not, nothing more is read here and the run stops
//! (design row H2d: the interim for the file tools' race, option (b); the
//! confined file-op helper of §4.8 is the design-conformant follow-up).
//!
//! **What the model sees** is a bounded excerpt: the exit status, then each
//! stream's size and at most its first [`SHOW_HEAD_LINES`] and last
//! [`SHOW_TAIL_LINES`] lines, each cut at [`SHOW_LINE_BYTES`] (compiler
//! errors come first, test summaries last), and, when the middle is left out,
//! the first [`SHOW_MID_LINES`] lines of it that look like a failure, with
//! their line numbers (H2f). The excerpt's digest is over
//! the excerpt, and `truncated` says whether anything was left out.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use harness_core::{sha256, Digest, Sha256Stream, Source, Untrusted};
use harness_journal::Journaled;
use harness_manifest::ProviderName;
use harness_policy::{workspace_path, Authorized, Call, EXEC_ID, EXEC_MAX_ARGS};
use harness_sandbox::spec::{MAX_CPU, MAX_FILE_SIZE, MAX_MEMORY, MAX_OUTPUT_BYTES, MAX_PROCESSES};
use harness_sandbox::{
    ChildStatus, ConfinedExit, ConfinedSpec, Confinement, Conformed, DomainCleanup, Limits,
    Network, SpawnError,
};
use serde_json::{json, Value};

use crate::builtin::{
    canonical_root, code, err, refused, resolve, workspace_tree, Out, ResolveErr, RootRefused,
};
use crate::provider::{
    ExecCleanup, ExecEnd, ExecRecord, InvokeCtx, RefusalKind, ToolError, ToolProvider, ToolResult,
    ToolStatus,
};

/// Shells (§4.8): never in any default allowlist. A task that allowlists
/// one, by name or by the program's file name, stamps `shell_enabled: true`
/// in the journal header.
pub const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "mksh",
    "csh",
    "tcsh",
    "fish",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
];

/// The variables the harness builds for every command (§5.5); a task may
/// not set them. `PATH` is the allowlisted programs' directories then
/// `/usr/bin:/bin`; `HOME`, `TMPDIR`, `CARGO_HOME` and `CARGO_TARGET_DIR`
/// are directories of the run's scratch.
pub const BUILT_ENV: &[&str] = &["PATH", "HOME", "TMPDIR", "CARGO_HOME", "CARGO_TARGET_DIR"];

/// Lines shown from the start of a stream.
pub const SHOW_HEAD_LINES: usize = 8;
/// Lines shown from the end of a stream.
pub const SHOW_TAIL_LINES: usize = 24;
/// Lines of a stream's middle that look like a failure, shown with their line
/// numbers when the middle is left out (H2f: a `cargo test` result cut in
/// its middle hid the one panic that mattered).
pub const SHOW_MID_LINES: usize = 6;
/// What makes a line of a stream's omitted middle look like a failure: the
/// compiler's and the test harness's own words.
/// Longest such line shown, in bytes: with the head and the tail, two streams
/// of them still fit the context's 16 KiB for one observation.
const SHOW_MID_LINE_BYTES: usize = 120;
const FAILURE_MARKERS: &[&str] = &[
    "panicked at",
    "FAILED",
    "error[E",
    "error:",
    "assertion",
    "thread '",
];
/// Longest line shown, in bytes (cut on a character boundary).
pub const SHOW_LINE_BYTES: usize = 200;
/// Longest value of a task-declared environment variable.
pub const ENV_VALUE_MAX_BYTES: usize = 4096;
/// Most programs on one allowlist.
pub const MAX_PROGRAMS: usize = 32;

/// The command runner's setup from the task spec (§4.8, H2d): the exec
/// allowlist, and what a command needs besides the workspace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecSpec {
    /// The exec allowlist, in the task's order.
    pub programs: Vec<ExecProgram>,
    /// Read-only roots the programs need (a toolchain, the linker's SDK,
    /// the system TLS configuration), absolute and canonical.
    pub read_only: Vec<PathBuf>,
    /// Toolchain variables the task declares (§5.5), beyond [`BUILT_ENV`].
    pub env: Vec<(String, String)>,
    /// Limits per command.
    pub limits: ExecLimits,
}

/// One allowlisted program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecProgram {
    /// What `argv[0]` must say: a plain name, never a path.
    pub name: String,
    /// The one file it runs: absolute and canonical (no symlink).
    pub path: PathBuf,
}

/// Limits per command (§6.2); the wall clock is the call's deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecLimits {
    /// Address-space budget per process, in bytes (FT-6). A build
    /// toolchain wants at least 1 GiB (H2c measured `syn` needing 768 MiB).
    pub memory: u64,
    /// Most processes the command's sandbox may hold (FT-5).
    pub processes: u32,
    /// CPU time per process.
    pub cpu: Duration,
    /// Largest file a process may write, in bytes (FT-7).
    pub file_size: u64,
    /// Bytes kept of each of stdout and stderr.
    pub output_bytes: u64,
}

impl Default for ExecLimits {
    /// 2 GiB per process, 128 processes, 600 s of CPU per process, 1 GiB
    /// files, 1 MiB kept per stream.
    fn default() -> Self {
        Self {
            memory: 2 << 30,
            processes: 128,
            cpu: Duration::from_secs(600),
            file_size: 1 << 30,
            output_bytes: 1 << 20,
        }
    }
}

/// Why an exec setup is refused. Nothing has run.
#[derive(Debug, thiserror::Error)]
pub enum ExecSetupError {
    /// No program on the allowlist, or too many.
    #[error("the exec allowlist must name between 1 and {MAX_PROGRAMS} programs")]
    Count,
    /// A name that is not a plain program name.
    #[error("exec program name {0:?} is not a plain name (letters, digits, '.', '_', '+', '-'; no path)")]
    BadName(String),
    /// A name given twice.
    #[error("exec program {0:?} appears twice")]
    Duplicate(String),
    /// A program path that cannot be pinned.
    #[error("exec program {name:?}: {why}")]
    Program {
        /// The program's name.
        name: String,
        /// Why.
        why: &'static str,
    },
    /// A read-only root that cannot be used.
    #[error("exec read-only root {path:?}: {why}")]
    Root {
        /// The root as given.
        path: PathBuf,
        /// Why.
        why: &'static str,
    },
    /// A task-declared variable that cannot be set.
    #[error("exec environment variable {name:?}: {why}")]
    Env {
        /// Its name.
        name: String,
        /// Why.
        why: &'static str,
    },
    /// A limit out of range.
    #[error("exec limits: {0}")]
    Limits(&'static str),
    /// The scratch directory could not be prepared or overlaps the workspace.
    #[error("the exec scratch directory: {0}")]
    Scratch(String),
    /// The workspace root is not usable.
    #[error("workspace refused: {0}")]
    Workspace(#[from] RootRefused),
}

/// A checked exec setup: every program pinned by its canonical path and by
/// the SHA-256 of its content when the run started.
#[derive(Debug, Clone)]
pub struct Pinned {
    spec: ExecSpec,
    programs: BTreeMap<String, PathBuf>,
    spec_digest: Digest,
    programs_digest: Digest,
}

fn plain_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

fn env_name(s: &str) -> bool {
    let mut b = s.bytes();
    b.next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

/// `inner` is `outer` or lies under it, component-wise.
fn within(inner: &Path, outer: &Path) -> bool {
    inner.starts_with(outer)
}

/// SHA-256 of a file's content, streamed.
fn file_sha256(p: &Path) -> io::Result<Digest> {
    let mut f = fs::File::open(p)?;
    let mut h = Sha256Stream::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(buf.get(..n).unwrap_or_default());
    }
    Ok(h.finish())
}

impl Pinned {
    /// Check `spec` and pin its programs (see [`ExecSetupError`] for every
    /// refusal): names are plain and unique; paths are absolute, canonical,
    /// regular, executable files inside a read-only root or a system
    /// directory the sandbox executes from; roots are absolute, canonical
    /// directories; variables are well-formed, not built by the harness and
    /// not loader variables; limits are in the sandbox's ranges.
    pub fn check(spec: &ExecSpec) -> Result<Pinned, ExecSetupError> {
        if spec.programs.is_empty() || spec.programs.len() > MAX_PROGRAMS {
            return Err(ExecSetupError::Count);
        }
        let mut roots = Vec::new();
        for r in &spec.read_only {
            let bad = |why| ExecSetupError::Root {
                path: r.clone(),
                why,
            };
            if !r.is_absolute() {
                return Err(bad("is not absolute"));
            }
            let m = fs::symlink_metadata(r).map_err(|_| bad("does not exist"))?;
            if m.file_type().is_symlink() || !m.is_dir() {
                return Err(bad("is not a directory (or is a symlink)"));
            }
            if fs::canonicalize(r).ok().as_deref() != Some(r.as_path()) {
                return Err(bad("is not canonical: give its real path"));
            }
            if r.to_str().is_none() {
                return Err(bad("is not UTF-8"));
            }
            roots.push(r.clone());
        }
        let system: Vec<&Path> = harness_sandbox::profile::SYSTEM_EXEC
            .iter()
            .map(Path::new)
            .collect();
        let mut programs = BTreeMap::new();
        let mut content = Sha256Stream::new();
        content.update(b"rh-exec-programs/1\n");
        for p in &spec.programs {
            if !plain_name(&p.name) {
                return Err(ExecSetupError::BadName(p.name.clone()));
            }
            if programs.contains_key(&p.name) {
                return Err(ExecSetupError::Duplicate(p.name.clone()));
            }
            let bad = |why| ExecSetupError::Program {
                name: p.name.clone(),
                why,
            };
            if !p.path.is_absolute() {
                return Err(bad("the path is not absolute"));
            }
            let Some(text) = p.path.to_str() else {
                return Err(bad("the path is not UTF-8"));
            };
            let m = fs::symlink_metadata(&p.path).map_err(|_| bad("no file at the path"))?;
            if m.file_type().is_symlink() || !m.is_file() {
                return Err(bad("the path is not a regular file (or is a symlink)"));
            }
            if fs::canonicalize(&p.path).ok().as_deref() != Some(p.path.as_path()) {
                return Err(bad("the path is not canonical: give the real path"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if m.permissions().mode() & 0o111 == 0 {
                    return Err(bad("the file is not executable"));
                }
            }
            if !roots.iter().any(|r| within(&p.path, r))
                && !system.iter().any(|s| within(&p.path, s))
            {
                return Err(bad(
                    "the program lies outside every read-only root and system directory the sandbox executes from",
                ));
            }
            let digest = file_sha256(&p.path).map_err(|_| bad("the file cannot be read"))?;
            for part in [p.name.as_bytes(), b"\0", text.as_bytes(), b"\0"] {
                content.update(part);
            }
            content.update(digest.to_string().as_bytes());
            content.update(b"\n");
            programs.insert(p.name.clone(), p.path.clone());
        }
        let mut seen = BTreeSet::new();
        for (k, v) in &spec.env {
            let bad = |why| ExecSetupError::Env {
                name: k.clone(),
                why,
            };
            if !env_name(k) {
                return Err(bad("is not a variable name"));
            }
            if BUILT_ENV.contains(&k.as_str()) {
                return Err(bad("is built by the harness"));
            }
            if k.starts_with("DYLD_") || k.starts_with("LD_") {
                return Err(bad("is a loader variable (INV-10)"));
            }
            if !seen.insert(k.as_str()) {
                return Err(bad("appears twice"));
            }
            if v.contains('\0') || v.len() > ENV_VALUE_MAX_BYTES {
                return Err(bad("its value holds a NUL byte or is too long"));
            }
        }
        let l = &spec.limits;
        if l.memory == 0 || l.memory > MAX_MEMORY {
            return Err(ExecSetupError::Limits("memory must be in [1, 16 TiB]"));
        }
        if l.processes == 0 || l.processes > MAX_PROCESSES {
            return Err(ExecSetupError::Limits("processes must be in [1, 100000]"));
        }
        if l.cpu.is_zero() || l.cpu > MAX_CPU {
            return Err(ExecSetupError::Limits("cpu must be in (0, 365 days]"));
        }
        if l.file_size == 0 || l.file_size > MAX_FILE_SIZE {
            return Err(ExecSetupError::Limits("file size must be in [1, 16 TiB]"));
        }
        if l.output_bytes == 0 || l.output_bytes > MAX_OUTPUT_BYTES {
            return Err(ExecSetupError::Limits("output must be in [1, 64 MiB]"));
        }
        Ok(Pinned {
            spec: spec.clone(),
            programs,
            spec_digest: spec.digest(),
            programs_digest: content.finish(),
        })
    }

    /// The digest of the spec as given ([`ExecSpec::digest`]).
    pub fn spec_digest(&self) -> Digest {
        self.spec_digest
    }

    /// SHA-256 over every program's name, path and content digest, as
    /// measured when this setup was checked.
    pub fn programs_digest(&self) -> Digest {
        self.programs_digest
    }

    /// The spec.
    pub fn spec(&self) -> &ExecSpec {
        &self.spec
    }
}

impl ExecSpec {
    /// SHA-256 over everything the spec says, in one canonical encoding
    /// (the journal header's `exec` input: an audit or a resume must be
    /// given the same setup).
    pub fn digest(&self) -> Digest {
        let v = json!({
            "format": "rh-exec/1",
            "programs": self.programs.iter().map(|p| json!([p.name, p.path.to_string_lossy()])).collect::<Vec<_>>(),
            "read_only": self.read_only.iter().map(|r| r.to_string_lossy()).collect::<Vec<_>>(),
            "env": self.env.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
            "limits": {
                "memory": self.limits.memory,
                "processes": self.limits.processes,
                "cpu_ms": u64::try_from(self.limits.cpu.as_millis()).unwrap_or(u64::MAX),
                "file_size": self.limits.file_size,
                "output_bytes": self.limits.output_bytes,
            },
        });
        sha256(v.to_string().as_bytes())
    }

    /// Whether a shell is on the allowlist, by name or by the program's
    /// file name (§4.8: it stamps `shell_enabled: true`).
    pub fn shell_enabled(&self) -> bool {
        self.programs.iter().any(|p| {
            SHELLS.contains(&p.name.as_str())
                || p.path
                    .file_name()
                    .and_then(|f| f.to_str())
                    .is_some_and(|f| SHELLS.contains(&f))
        })
    }

    /// The program names, which policy resolves `argv[0]` against.
    pub fn names(&self) -> Vec<String> {
        self.programs.iter().map(|p| p.name.clone()).collect()
    }
}

/// The run's scratch directory and its parts (design §2.8 `scratch/`).
#[derive(Debug, Clone)]
struct Scratch {
    dir: PathBuf,
    home: PathBuf,
    tmp: PathBuf,
    cargo_home: PathBuf,
    target: PathBuf,
}

impl Scratch {
    /// Create (0700) and canonicalise the scratch directory and its parts.
    fn prepare(dir: &Path, workspace: &Path) -> Result<Self, ExecSetupError> {
        let io = |e: io::Error| ExecSetupError::Scratch(e.to_string());
        make_dir(dir).map_err(io)?;
        let dir = fs::canonicalize(dir).map_err(io)?;
        if within(&dir, workspace) || within(workspace, &dir) {
            return Err(ExecSetupError::Scratch(
                "it overlaps the workspace (build output must stay out of the tree digest)".into(),
            ));
        }
        let part = |name: &str| -> Result<PathBuf, ExecSetupError> {
            let p = dir.join(name);
            make_dir(&p).map_err(io)?;
            Ok(p)
        };
        Ok(Self {
            home: part("home")?,
            tmp: part("tmp")?,
            cargo_home: part("cargo-home")?,
            target: part("target")?,
            dir,
        })
    }
}

fn make_dir(p: &Path) -> io::Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(p)?;
    let m = fs::symlink_metadata(p)?;
    if m.file_type().is_symlink() || !m.is_dir() {
        return Err(io::Error::other("not a real directory"));
    }
    Ok(())
}

/// The built-in command runner (see the module docs).
pub struct ExecTools<'a> {
    ns: ProviderName,
    root: PathBuf,
    pinned: Pinned,
    scratch: Scratch,
    confinement: &'a dyn Confinement,
    witness: Conformed,
    walk_timeout: Duration,
}

impl std::fmt::Debug for ExecTools<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecTools")
            .field("root", &self.root)
            .field("scratch", &self.scratch.dir)
            .finish_non_exhaustive()
    }
}

impl<'a> ExecTools<'a> {
    /// The command runner over the workspace at `root`, with the checked
    /// setup `pinned`, the scratch directory `scratch` (created 0700 if
    /// missing; it must not overlap the workspace), the confinement and
    /// its witness, and the time the post-command workspace walk may take.
    pub fn new(
        root: &Path,
        pinned: Pinned,
        scratch: &Path,
        confinement: &'a dyn Confinement,
        witness: Conformed,
        walk_timeout: Duration,
    ) -> Result<Self, ExecSetupError> {
        let ns = ProviderName::new(harness_manifest::BUILTIN_NAMESPACE)
            .map_err(|_| ExecSetupError::Scratch("builtin namespace".into()))?;
        let root = canonical_root(root)?;
        let scratch = Scratch::prepare(scratch, &root)?;
        Ok(Self {
            ns,
            root,
            pinned,
            scratch,
            confinement,
            witness,
            walk_timeout,
        })
    }

    /// The canonical workspace root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The canonical scratch directory.
    pub fn scratch(&self) -> &Path {
        &self.scratch.dir
    }

    /// The environment every command gets (§5.5): built, never inherited.
    fn env(&self) -> Vec<(OsString, OsString)> {
        let mut path: Vec<String> = Vec::new();
        for p in self.pinned.programs.values() {
            if let Some(d) = p.parent().and_then(Path::to_str) {
                if !path.iter().any(|x| x == d) {
                    path.push(d.to_owned());
                }
            }
        }
        for sys in ["/usr/bin", "/bin"] {
            if !path.iter().any(|x| x == sys) {
                path.push(sys.to_owned());
            }
        }
        let mut env: Vec<(OsString, OsString)> = vec![
            ("PATH".into(), path.join(":").into()),
            ("HOME".into(), self.scratch.home.clone().into()),
            ("TMPDIR".into(), self.scratch.tmp.clone().into()),
            ("CARGO_HOME".into(), self.scratch.cargo_home.clone().into()),
            (
                "CARGO_TARGET_DIR".into(),
                self.scratch.target.clone().into(),
            ),
        ];
        for (k, v) in &self.pinned.spec.env {
            env.push((k.into(), v.into()));
        }
        env
    }

    /// The working directory: the workspace root, or a directory inside it
    /// resolved component by component with no symlink (INV-30's
    /// in-process half; the sandbox canonicalises it again and refuses one
    /// outside its roots).
    fn cwd(&self, cwd: Option<&str>) -> Result<PathBuf, Out> {
        let Some(s) = cwd else {
            return Ok(self.root.clone());
        };
        let p = workspace_path(s).map_err(|e| err(code::PATH_REFUSED, &e.to_string()))?;
        match resolve(&self.root, &p) {
            Ok((path, Some(m))) if m.is_dir() => Ok(path),
            Ok((_, Some(_))) => Err(err(code::NOT_A_DIR, "cwd is not a directory")),
            Ok((_, None)) | Err(ResolveErr::NotFound) => {
                Err(err(code::NOT_FOUND, "cwd: no such directory"))
            }
            Err(ResolveErr::Symlink) => Err(err(
                code::SYMLINK,
                "a component of cwd is a symlink; symlinks are never followed",
            )),
            Err(ResolveErr::Io(_)) => Err(err(code::IO, "cwd could not be examined")),
        }
    }
}

/// The call's argv and cwd (the schema already checked their types).
fn args(a: &Value) -> Result<(Vec<String>, Option<&str>), Out> {
    let items = a
        .get("argv")
        .and_then(Value::as_array)
        .ok_or_else(|| err(code::BAD_ARGS, "argv must be a list of strings"))?;
    if items.is_empty() || items.len() > EXEC_MAX_ARGS {
        return Err(err(
            code::BAD_ARGS,
            "argv must name a program and hold at most 256 items",
        ));
    }
    let mut argv = Vec::with_capacity(items.len());
    for v in items {
        match v.as_str() {
            Some(s) if !s.contains('\0') => argv.push(s.to_owned()),
            _ => {
                return Err(err(
                    code::BAD_ARGS,
                    "argv must be a list of strings without NUL",
                ))
            }
        }
    }
    let cwd = match a.get("cwd") {
        None => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => return Err(err(code::BAD_ARGS, "cwd must be a string")),
    };
    Ok((argv, cwd))
}

/// Cut `line` to at most [`SHOW_LINE_BYTES`] on a character boundary.
fn cut_line(line: &str) -> (&str, bool) {
    if line.len() <= SHOW_LINE_BYTES {
        return (line, false);
    }
    let mut end = SHOW_LINE_BYTES;
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    (line.get(..end).unwrap_or(""), true)
}

/// Append one stream's excerpt to `out`; returns whether anything of it
/// was left out.
fn excerpt(name: &str, bytes: &[u8], dropped: bool, out: &mut String) -> bool {
    if bytes.is_empty() {
        out.push_str(&format!("{name}: (empty)\n"));
        return false;
    }
    let text = String::from_utf8_lossy(bytes);
    let lines: Vec<&str> = text.lines().collect();
    let n = lines.len();
    let shown_all = n <= SHOW_HEAD_LINES + SHOW_TAIL_LINES;
    out.push_str(&format!(
        "{name}: {} bytes, {n} line{}{}{}\n",
        bytes.len(),
        if n == 1 { "" } else { "s" },
        if dropped {
            "; it wrote more, which was not kept"
        } else {
            ""
        },
        if shown_all {
            String::new()
        } else {
            format!("; showing the first {SHOW_HEAD_LINES} and the last {SHOW_TAIL_LINES}, and up to {SHOW_MID_LINES} failure-looking lines from the middle")
        },
    ));
    let mut cut = dropped || !shown_all;
    let mut push = |l: &str| {
        let (s, c) = cut_line(l);
        cut |= c;
        out.push_str(s);
        if c {
            out.push_str(" [line cut]");
        }
        out.push('\n');
    };
    if shown_all {
        lines.iter().for_each(|l| push(l));
    } else {
        lines.iter().take(SHOW_HEAD_LINES).for_each(|l| push(l));
        let skipped = n - SHOW_HEAD_LINES - SHOW_TAIL_LINES;
        // The omitted middle may hold the one line that matters: keep the
        // first few that look like a failure, with where they are.
        let mid: Vec<(usize, &str)> = lines
            .iter()
            .enumerate()
            .skip(SHOW_HEAD_LINES)
            .take(skipped)
            .filter(|(_, l)| FAILURE_MARKERS.iter().any(|m| l.contains(m)))
            .map(|(i, l)| (i + 1, *l))
            .take(SHOW_MID_LINES)
            .collect();
        if mid.is_empty() {
            push(&format!("[... {skipped} lines not shown ...]"));
        } else {
            push(&format!(
                "[... {skipped} lines not shown; the first {} that look like failures, with their line numbers ...]",
                mid.len()
            ));
            for (no, l) in &mid {
                let mut end = l.len().min(SHOW_MID_LINE_BYTES);
                while !l.is_char_boundary(end) {
                    end -= 1;
                }
                push(&format!("{no}: {}", l.get(..end).unwrap_or("")));
            }
            push("[... the rest of the middle is not shown ...]");
        }
        lines.iter().skip(n - SHOW_TAIL_LINES).for_each(|l| push(l));
    }
    cut
}

/// How the command ended, for the journal and the model.
fn end_of(s: &ChildStatus) -> ExecEnd {
    match s {
        ChildStatus::Exited(c) => ExecEnd::Exited(*c),
        ChildStatus::Signaled(n) => ExecEnd::Signaled(*n),
        ChildStatus::TimedOut => ExecEnd::TimedOut,
        ChildStatus::ProcessLimit => ExecEnd::ProcessLimit,
        ChildStatus::ExecFailed => ExecEnd::ExecFailed,
        ChildStatus::Unknown => ExecEnd::Unknown,
    }
}

/// The status a command's end maps to (§4.5): any exit code is a completed
/// call (the code is the command's answer, not the tool's failure).
pub fn status_of(end: &ExecEnd) -> ToolStatus {
    match end {
        ExecEnd::Exited(_) => ToolStatus::Ok,
        ExecEnd::Signaled(n) => ToolStatus::Crashed { signal: Some(*n) },
        ExecEnd::TimedOut => ToolStatus::Timeout,
        ExecEnd::ProcessLimit => ToolStatus::Error {
            code: code::EXEC_PROCESS_LIMIT,
        },
        ExecEnd::ExecFailed => ToolStatus::Error {
            code: code::EXEC_FAILED,
        },
        ExecEnd::Unknown => ToolStatus::Crashed { signal: None },
    }
}

/// The excerpt the model sees (see the module docs).
fn render(exit: &ConfinedExit, limits: &ExecLimits, wall: Duration) -> (String, bool) {
    let mut out = match exit.status {
        ChildStatus::Exited(c) => format!("exit status {c}\n"),
        ChildStatus::Signaled(n) => format!(
            "ended by signal {n}{}\n",
            match n {
                24 => " (its CPU-time limit)",
                25 => " (its file-size limit)",
                _ => "",
            }
        ),
        ChildStatus::TimedOut => format!(
            "stopped: the command ran past its time limit ({} s) and was killed\n",
            wall.as_secs().max(1)
        ),
        ChildStatus::ProcessLimit => format!(
            "stopped: the command started more than {} processes and was killed\n",
            limits.processes
        ),
        ChildStatus::ExecFailed => {
            "error: the program could not be started in the sandbox\n".into()
        }
        ChildStatus::Unknown => {
            "error: the sandbox reported no status the harness can trust\n".into()
        }
    };
    let mut cut = excerpt("stdout", &exit.stdout, exit.stdout_truncated, &mut out);
    cut |= excerpt("stderr", &exit.stderr, exit.stderr_truncated, &mut out);
    if matches!(exit.domain, DomainCleanup::Unconfirmed(_)) {
        out.push_str(
            "warning: the harness could not confirm that every process the command started has \
             ended, so the run stops here\n",
        );
    }
    (out, cut)
}

fn spawn_err(e: &SpawnError) -> Out {
    match e {
        SpawnError::Spec(_) => err(
            code::EXEC_SPAWN,
            "the sandbox refused the command's setup, so nothing ran (check the task's exec section)",
        ),
        SpawnError::WrongWitness | SpawnError::Io(_) => {
            err(code::EXEC_SPAWN, "the sandbox could not start, so nothing ran")
        }
    }
}

fn result_of(cap: &str, out: Out) -> ToolResult {
    ToolResult {
        status: out.status,
        digest: sha256(out.text.as_bytes()),
        output: Untrusted::new(out.text.into_bytes(), Source::Tool(cap.to_owned())),
        truncated: false,
        read: None,
        edit: None,
        exec: None,
    }
}

impl ToolProvider for ExecTools<'_> {
    fn namespace(&self) -> &ProviderName {
        &self.ns
    }

    fn serves(&self, capability: &str) -> bool {
        capability == EXEC_ID
    }

    fn invoke(
        &mut self,
        call: Journaled<Authorized<Call>>,
        ctx: &InvokeCtx<'_>,
    ) -> Result<ToolResult, ToolError> {
        let c = call.call().call();
        let cap = c.capability.as_str();
        if cap != EXEC_ID {
            return Ok(refused(cap, RefusalKind::UnknownCapability));
        }
        let now = Instant::now();
        if now >= ctx.deadline {
            return Ok(refused(cap, RefusalKind::DeadlinePassed));
        }
        let (argv, cwd) = match args(&c.args) {
            Ok(a) => a,
            Err(out) => return Ok(result_of(cap, out)),
        };
        // Policy resolved argv[0] already (INV-13); a name that is not on
        // the allowlist never reaches the sandbox (defence in depth).
        let Some(program) = argv.first().and_then(|n| self.pinned.programs.get(n)) else {
            return Ok(result_of(
                cap,
                err(
                    code::EXEC_NOT_ALLOWED,
                    "argv[0] is not a program this task allows",
                ),
            ));
        };
        let dir = match self.cwd(cwd) {
            Ok(d) => d,
            Err(out) => return Ok(result_of(cap, out)),
        };
        let wall = ctx.deadline.saturating_duration_since(now);
        let l = self.pinned.spec.limits;
        let spec = ConfinedSpec {
            argv: std::iter::once(program.clone().into_os_string())
                .chain(argv.iter().skip(1).map(OsString::from))
                .collect(),
            cwd: dir,
            env: self.env(),
            read_only: self.pinned.spec.read_only.clone(),
            read_write: vec![self.root.clone(), self.scratch.dir.clone()],
            protected: Vec::new(),
            network: Network::None,
            limits: Limits {
                wall,
                cpu: Some(l.cpu),
                file_size: Some(l.file_size),
                memory: Some(l.memory),
                processes: Some(l.processes),
                output_bytes: l.output_bytes,
            },
        };
        let child = match self.confinement.spawn(&spec, &self.witness) {
            Ok(ch) => ch,
            Err(e) => return Ok(result_of(cap, spawn_err(&e))),
        };
        let exit = child.wait();
        // Only when every process the command started is confirmed gone is
        // the workspace read again (option (b), design row H2d); otherwise
        // nothing more is read here, and the run stops.
        let (cleanup, workspace) = match exit.domain {
            DomainCleanup::Confirmed { kills } => (
                ExecCleanup::Confirmed { kills },
                workspace_tree(&self.root, Instant::now() + self.walk_timeout).ok(),
            ),
            DomainCleanup::Unconfirmed(_) => (ExecCleanup::Unconfirmed, None),
        };
        let (text, cut) = render(&exit, &l, wall);
        let end = end_of(&exit.status);
        Ok(ToolResult {
            status: status_of(&end),
            digest: sha256(text.as_bytes()),
            output: Untrusted::new(text.into_bytes(), Source::Tool(cap.to_owned())),
            truncated: cut,
            read: None,
            edit: None,
            exec: Some(ExecRecord {
                end,
                cleanup,
                stdout_bytes: exit.stdout.len() as u64,
                stderr_bytes: exit.stderr.len() as u64,
                stdout_cut: exit.stdout_truncated,
                stderr_cut: exit.stderr_truncated,
                elapsed_ms: u64::try_from(exit.elapsed.as_millis()).unwrap_or(u64::MAX),
                workspace,
            }),
        })
    }
}

#[cfg(test)]
mod tests;
