//! The macOS backend: Seatbelt through `/usr/bin/sandbox-exec` (design
//! §6.3), with the profile of [`crate::profile`] and the domain stub of the
//! private `confine_spawn` module.
//!
//! **Live self-probe** (§6.1 condition 2). [`Seatbelt::probe`] runs one
//! fixed perl script through the same spawn path as every call, in a fresh
//! private directory, and checks from outside wherever it can:
//! - a TCP connect to a listener the harness holds on 127.0.0.1 must fail,
//!   and the listener must have seen no connection (FT-1);
//! - binding 127.0.0.1:0 must fail (D31);
//! - writing a file outside the roots must fail, and the file must be
//!   absent afterwards (FT-3);
//! - reading a planted `.ssh`-shaped canary outside the roots, following a
//!   workspace symlink to it, and listing the real home directory must all
//!   fail (FT-4, FT-12). The canary is planted in the harness's private
//!   directory, not in the user's home: a probe must not write there
//!   (deviation from §6.1's wording, named in the H2a report);
//! - the environment must be exactly the spec's (FT-4's env canary: the
//!   harness's own environment must not leak);
//! - LaunchServices must be unreachable (`lsappinfo` sees no Finder) and
//!   the keychain service too (`security list-keychains` fails) (FT-17,
//!   FT-18);
//! - a `setsid()`'d grandchild must be swept: the domain is `Confirmed`
//!   with at least one kill (FT-16).
//!
//! Each observation feeds the probe digest recorded in the witness.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::conformance;
use crate::spec::{self, ConfinedSpec, Context, Enforceable, Limits, Network};
use crate::{
    confine_spawn, Backend, BackendKind, ChildStatus, ConfinedChild, Conformed, DomainCleanup,
    SpawnError, Unavailable, UnavailableReason,
};

/// The Seatbelt launcher.
pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// The domain stub's text (see `confine_spawn`), exposed for the
/// conformance tests that run it nested inside a sandbox to exercise its
/// start check. It grants nothing: it only starts a program its caller
/// could start anyway, and run anywhere its signal filter cannot be shown
/// to hold (unconfined included) it refuses before starting anything.
#[doc(hidden)]
pub const DOMAIN_STUB: &str = confine_spawn::STUB;

/// What this backend can enforce: neither memory nor process-count caps
/// (macOS does not enforce `RLIMIT_AS`, and `RLIMIT_NPROC` is per user).
pub const ENFORCE: Enforceable = Enforceable {
    memory: false,
    processes: false,
};

/// The macOS Seatbelt backend.
#[derive(Debug, Clone)]
pub struct Seatbelt {
    private_root: PathBuf,
    home: Option<PathBuf>,
    primitives: [PathBuf; 2],
}

impl Default for Seatbelt {
    fn default() -> Self {
        Self::new()
    }
}

impl Seatbelt {
    /// Private files (profiles) under the system temporary directory
    /// (per-user on macOS); `$HOME` as the home directory to protect.
    pub fn new() -> Self {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .and_then(|h| std::fs::canonicalize(h).ok());
        Seatbelt {
            private_root: std::env::temp_dir(),
            home,
            primitives: [SANDBOX_EXEC.into(), crate::profile::STUB_INTERPRETER.into()],
        }
    }

    /// Put the private per-call directories under `root` instead.
    pub fn with_private_root(mut self, root: PathBuf) -> Self {
        self.private_root = root;
        self
    }

    /// Check other paths for the two primitives. This can only make
    /// [`probe`](Backend::probe) refuse (a test of the missing-primitive
    /// path): spawns always use the fixed absolute programs.
    pub fn with_primitive_paths(mut self, sandbox_exec: PathBuf, perl: PathBuf) -> Self {
        self.primitives = [sandbox_exec, perl];
        self
    }

    fn private_dir(&self, tag: &str) -> std::io::Result<PathBuf> {
        use std::hash::BuildHasher;
        use std::os::unix::fs::DirBuilderExt;
        let root = std::fs::canonicalize(&self.private_root)?;
        for attempt in 0u32..16 {
            let n = std::collections::hash_map::RandomState::new().hash_one((
                std::process::id(),
                attempt,
                std::time::SystemTime::now(),
            ));
            let dir = root.join(format!("rh-seatbelt-{tag}-{n:016x}"));
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => return Ok(dir),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::other("no unique private directory"))
    }

    /// Validate, render, write the profile and start. The one spawn path of
    /// this backend: `spawn` and the live probe both come here.
    fn start(&self, spec: &ConfinedSpec) -> Result<ConfinedChild, SpawnError> {
        let dir = self
            .private_dir("call")
            .map_err(|e| SpawnError::Io(e.to_string()))?;
        let cx = Context {
            home: self.home.as_deref(),
            private_dir: &dir,
            enforce: ENFORCE,
        };
        let v = match spec::validate(spec, &cx) {
            Ok(v) => v,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(e.into());
            }
        };
        let profile = dir.join("profile.sb");
        if let Err(e) = std::fs::write(&profile, crate::profile::render(&v)) {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(SpawnError::Io(e.to_string()));
        }
        match confine_spawn::spawn(&profile, &v, Some(dir.clone())) {
            Ok(inner) => Ok(ConfinedChild { inner }),
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                Err(SpawnError::Io(e.to_string()))
            }
        }
    }

    fn live_probe(&self) -> Result<Vec<u8>, Unavailable> {
        let io = |e: std::io::Error| Unavailable {
            backend: Some(BackendKind::Seatbelt),
            reason: UnavailableReason::Io(e.to_string()),
        };
        let fail = |probe: &'static str, observed: String| Unavailable {
            backend: Some(BackendKind::Seatbelt),
            reason: UnavailableReason::LiveProbeFailed { probe, observed },
        };
        let dir = self.private_dir("probe").map_err(io)?;
        let result = (|| {
            let ws = dir.join("ws");
            let outside = dir.join("outside");
            std::fs::create_dir_all(&ws).map_err(io)?;
            std::fs::create_dir_all(outside.join(".ssh")).map_err(io)?;
            let canary = outside.join(".ssh").join("id_canary");
            std::fs::write(&canary, b"rh-probe-canary").map_err(io)?;
            let link = ws.join("link");
            std::os::unix::fs::symlink(&canary, &link).map_err(io)?;
            let written = outside.join("written");
            let listener = TcpListener::bind("127.0.0.1:0").map_err(io)?;
            listener.set_nonblocking(true).map_err(io)?;
            let port = listener.local_addr().map_err(io)?.port();
            let home = self
                .home
                .clone()
                .unwrap_or_else(|| PathBuf::from("/var/root"));
            let spec = ConfinedSpec {
                argv: vec![
                    crate::profile::STUB_INTERPRETER.into(),
                    "-e".into(),
                    PROBE_SCRIPT.into(),
                    port.to_string().into(),
                    written.clone().into(),
                    canary.clone().into(),
                    link.clone().into(),
                    home.into(),
                ],
                cwd: ws.clone(),
                env: vec![("RH_PROBE".into(), "1".into())],
                read_only: vec![],
                read_write: vec![ws.clone()],
                protected: vec![],
                network: Network::None,
                limits: Limits::wall(Duration::from_secs(20)),
            };
            let exit = self
                .start(&spec)
                .map_err(|e| fail("spawn", e.to_string()))?
                .wait();
            if exit.status != ChildStatus::Exited(0) {
                return Err(fail(
                    "run",
                    format!(
                        "{:?}: {}",
                        exit.status,
                        String::from_utf8_lossy(&exit.stderr)
                    ),
                ));
            }
            let out = String::from_utf8_lossy(&exit.stdout).into_owned();
            for name in PROBES {
                let want = format!("{name} ok\n");
                if !out.contains(&want) {
                    return Err(fail(name, out.clone()));
                }
            }
            match listener.accept() {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                other => return Err(fail("net", format!("the listener saw {other:?}"))),
            }
            if written.exists() {
                return Err(fail("write", "the file exists outside the roots".into()));
            }
            match exit.domain {
                DomainCleanup::Confirmed { kills } if kills >= 1 => {}
                d => return Err(fail("sweep", format!("{d:?}"))),
            }
            Ok(out.into_bytes())
        })();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }
}

/// The probes the script reports, each as `<name> ok`.
const PROBES: &[&str] = &[
    "net",
    "bind",
    "write",
    "read",
    "link",
    "home",
    "env",
    "launchservices",
    "keychain",
    "escape",
];

/// The live probe script (arguments: port, outside path to write, canary,
/// symlink to the canary, home directory).
const PROBE_SCRIPT: &str = r#"use strict; use Socket; use POSIX ();
my ($port,$w,$can,$link,$home)=@ARGV; $|=1;
sub r { print $_[0], ($_[1] ? ' ok' : ' FAIL'), "\n" }
socket(my $s,PF_INET,SOCK_STREAM,0) or die; r('net', !connect($s, sockaddr_in($port, inet_aton('127.0.0.1'))));
socket(my $b,PF_INET,SOCK_STREAM,0) or die; r('bind', !bind($b, sockaddr_in(0, inet_aton('127.0.0.1'))));
r('write', !open(my $f,'>',$w));
r('read', !open(my $g,'<',$can));
r('link', !open(my $h,'<',$link));
r('home', !opendir(my $d,$home));
r('env', join(',', sort keys %ENV) eq 'RH_PROBE');
my $o=''; if (open(my $l,'-|','/usr/bin/lsappinfo','info','-only','pid','Finder')) { $o=join('',<$l>); close $l }
r('launchservices', $o !~ /pid/);
my $k=''; my $krc=0; if (open(my $l,'-|','/usr/bin/security','list-keychains')) { $k=join('',<$l>); close $l; $krc=$? } else { $krc=-1 }
r('keychain', $krc != 0 && $k !~ /keychain/);
my $p=fork(); if (defined $p && $p==0) { POSIX::setsid(); if (fork()) { POSIX::_exit(0) } $SIG{TERM}='IGNORE'; close STDOUT; close STDERR; sleep 30; POSIX::_exit(0) }
waitpid($p,0); r('escape', 1);
"#;

impl Backend for Seatbelt {
    fn kind(&self) -> BackendKind {
        BackendKind::Seatbelt
    }

    fn probe(&self) -> Result<Conformed, Unavailable> {
        let Some(row) = conformance::row(BackendKind::Seatbelt, "macos") else {
            return Err(Unavailable {
                backend: Some(BackendKind::Seatbelt),
                reason: UnavailableReason::MatrixRowMissing,
            });
        };
        for (p, name) in self.primitives.iter().zip([SANDBOX_EXEC, "/usr/bin/perl"]) {
            if !Path::new(p).is_file() {
                return Err(Unavailable {
                    backend: Some(BackendKind::Seatbelt),
                    reason: UnavailableReason::PrimitiveMissing(name),
                });
            }
        }
        let observed = self.live_probe()?;
        let digest = harness_core::sha256_parts(&[
            crate::profile::PROFILE_VERSION.as_bytes(),
            b"\n",
            row.id.as_bytes(),
            b"\n",
            &observed,
        ]);
        Ok(Conformed::mint(row, digest))
    }

    fn spawn(&self, spec: &ConfinedSpec, ev: &Conformed) -> Result<ConfinedChild, SpawnError> {
        if ev.backend() != BackendKind::Seatbelt {
            return Err(SpawnError::WrongWitness);
        }
        self.start(spec)
    }
}
