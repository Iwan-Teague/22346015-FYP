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
//! - a `/usr/bin` binary that needs no mach (`uname`) must run and print
//!   `Darwin`, so the two checks below cannot pass merely because a binary
//!   failed to exec (review LOW-2);
//! - LaunchServices must be unreachable (`lsappinfo` sees no Finder) and
//!   the keychain service too (`security list-keychains` fails) (FT-17,
//!   FT-18);
//! - a memory bomb is bounded by `RLIMIT_AS` and a fork bomb by the
//!   member-count watchdog (FT-6, FT-5), each verified live before minting;
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

/// What this backend can enforce (H2c). Memory: per-process `RLIMIT_AS`
/// (measured enforced on this host). Processes: the stub's member-count
/// watchdog (`RLIMIT_NPROC` is per user, so it cannot bound one sandbox; the
/// watchdog is a weaker, named bar). Both are verified live by [`Seatbelt::probe`]
/// before a witness is minted.
pub const ENFORCE: Enforceable = Enforceable {
    memory: true,
    processes: true,
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
        let text = match crate::profile::render(&v) {
            Ok(t) => t,
            Err(e) => {
                // A validated spec never yields an unsafe path; treat a guard
                // trip as a spec refusal rather than starting anything.
                let _ = std::fs::remove_dir_all(&dir);
                return Err(SpawnError::Io(e.to_string()));
            }
        };
        if let Err(e) = std::fs::write(&profile, text) {
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

            // FT-6: RLIMIT_AS is applied AND enforced on this host. The stub
            // sets AS to the program's own virtual size plus this small
            // budget; the program confirms the limit is finite, then a
            // self-capped 512 MiB attempt must be refused (the process dies
            // before printing NOTBOUNDED). If a future macOS stops enforcing
            // it, this fails and no witness is minted.
            let mut mem = ConfinedSpec {
                argv: vec![
                    crate::profile::STUB_INTERPRETER.into(),
                    "-e".into(),
                    MEM_PROBE.into(),
                ],
                cwd: ws.clone(),
                env: vec![("RH_PROBE".into(), "1".into())],
                read_only: vec![],
                read_write: vec![ws.clone()],
                protected: vec![],
                network: Network::None,
                limits: Limits::wall(Duration::from_secs(20)),
            };
            mem.limits.memory = Some(MEM_PROBE_BUDGET);
            let em = self
                .start(&mem)
                .map_err(|e| fail("mem-spawn", e.to_string()))?
                .wait();
            let mo = String::from_utf8_lossy(&em.stdout).into_owned();
            if !mo.contains("applied") {
                return Err(fail("mem-applied", format!("{:?}: {mo}", em.status)));
            }
            if mo.contains("NOTBOUNDED") || em.status == ChildStatus::Exited(0) {
                return Err(fail("mem-bound", format!("{:?}: {mo}", em.status)));
            }

            // FT-5: the member-count watchdog stops a run whose sandbox holds
            // more processes than the cap. The program forks a self-capped
            // burst above the cap; the stub must report the process limit and
            // sweep. Bounded and swept even if the watchdog did not fire.
            let mut proc = mem.clone();
            proc.argv = vec![
                crate::profile::STUB_INTERPRETER.into(),
                "-e".into(),
                PROC_PROBE.into(),
            ];
            proc.limits.memory = None;
            proc.limits.processes = Some(PROC_PROBE_CAP);
            let ep = self
                .start(&proc)
                .map_err(|e| fail("proc-spawn", e.to_string()))?
                .wait();
            if ep.status != ChildStatus::ProcessLimit {
                return Err(fail(
                    "proc-limit",
                    format!("{:?}: {}", ep.status, String::from_utf8_lossy(&ep.stdout)),
                ));
            }
            match ep.domain {
                DomainCleanup::Confirmed { .. } => {}
                d => return Err(fail("proc-sweep", format!("{d:?}"))),
            }

            let mut observed = out.into_bytes();
            observed.extend_from_slice(mo.as_bytes());
            observed.extend_from_slice(format!("{:?}", ep.status).as_bytes());
            Ok(observed)
        })();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }
}

/// The FT-6 probe's address-space budget: enough for perl to start, far less
/// than its self-capped 512 MiB attempt, so the attempt must be refused.
const MEM_PROBE_BUDGET: u64 = 64 * 1024 * 1024;
/// The FT-5 probe's process cap; the probe forks a burst above it.
const PROC_PROBE_CAP: u32 = 4;

/// FT-6 live probe: confirm `RLIMIT_AS` is finite (applied) then that a large
/// allocation is refused (enforced). Self-capped at 512 MiB.
const MEM_PROBE: &str = r#"$|=1; my $g=pack('QQ',0,0); syscall(194,5,$g); my ($cur)=unpack('Q',$g);
if($cur<=0 || $cur>=0x7fffffffffffffff){print qq{unbounded\n}; exit 0}
print qq{applied\n}; my @k; for(1..64){ push @k, ('X' x (8*1024*1024)) } print qq{NOTBOUNDED\n};
"#;

/// FT-5 live probe: fork a self-capped burst above the cap; the watchdog must
/// stop the run. The watchdog fires within ~0.5 s (it counts about every
/// 240 ms), so a 3 s bound is ample and keeps this probe cheap; each child
/// self-exits as a safety net if the watchdog somehow does not fire.
const PROC_PROBE: &str = r#"use POSIX (); $|=1; my @k;
for(1..12){ my $p=fork(); if(defined $p && $p==0){ sleep 3; POSIX::_exit(0) } push @k,$p if $p }
print qq{forked\n}; sleep 3; print qq{SURVIVED\n};
"#;

/// The probes the script reports, each as `<name> ok`.
const PROBES: &[&str] = &[
    "net",
    "bind",
    "write",
    "read",
    "link",
    "home",
    "env",
    "sysbin",
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
my $u=''; if (open(my $l,'-|','/usr/bin/uname')) { $u=join('',<$l>); close $l }
r('sysbin', $u =~ /Darwin/);
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
