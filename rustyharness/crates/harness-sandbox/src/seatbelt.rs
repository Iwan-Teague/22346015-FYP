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
//! Each observation feeds the probe digest recorded in the witness — with
//! the attempt count and the sweep deadline of the last attempt (P-41), so
//! an audit can tell a retried probe from a clean first-attempt one.
//!
//! **Retries under load** (H2f, narrowed by P-41). A failed attempt is
//! retried only while the failure is shaped like load, never more than
//! `PROBE_BACKOFFS_MS.len()` times in all: a spawn that did not start, a
//! probe run that timed out, a sweep that ran out of its deadline (retried
//! once, at a tripled deadline), a probe killed by a signal before it
//! reported (re-run once). Every escape — a guard observed not to hold —
//! is final at once, and so is a second failure of the same kind.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::conformance;
use crate::spec::{self, ConfinedSpec, Context, Enforceable, Limits, Network};
use crate::{
    confine_spawn, Backend, BackendKind, ChildStatus, ConfinedChild, Conformed, DomainCleanup,
    LiveOpts, SpawnError, Unavailable, UnavailableReason,
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
    /// Ports no profile may allow (the model port at least, §4.3): they
    /// are refused as grants at validation and denied last at render
    /// (INV-41). Empty until a caller says otherwise; the run layer passes
    /// the endpoint's port (P-36g).
    reserved_ports: Vec<u16>,
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
            reserved_ports: Vec::new(),
        }
    }

    /// Put the private per-call directories under `root` instead.
    pub fn with_private_root(mut self, root: PathBuf) -> Self {
        self.private_root = root;
        self
    }

    /// Refuse every grant of these ports and deny them last in every
    /// profile (§4.3): the model port at least (INV-41).
    pub fn with_reserved_ports(mut self, ports: Vec<u16>) -> Self {
        self.reserved_ports = ports;
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
    /// this backend: `spawn`, the live probe and the port probe all come
    /// here. The stub sweeps for at most `sweep` when the call ends (P-41).
    /// `ports_conformed` says whether `Network::Loopback` may validate at
    /// all: every production spawn derives it from its witness's coverage
    /// of `PORTS_CASES`; the port probe passes `true` because it IS the
    /// measurement that justifies the coverage. `live` makes the call
    /// readable while it runs and bounds its lifetime (§4.2).
    fn start(
        &self,
        spec: &ConfinedSpec,
        sweep: Duration,
        ports_conformed: bool,
        live: Option<&LiveOpts>,
    ) -> Result<ConfinedChild, SpawnError> {
        let dir = self
            .private_dir("call")
            .map_err(|e| SpawnError::Io(e.to_string()))?;
        let cx = Context {
            home: self.home.as_deref(),
            private_dir: &dir,
            enforce: ENFORCE,
            reserved_ports: &self.reserved_ports,
            ports_conformed,
            // The Seatbelt profile can express the loopback-only proxy
            // allow (§5.3; spelling measured on this host).
            proxy: true,
        };
        let approved = match spec::validate(spec, &cx) {
            Ok(a) => a,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(e.into());
            }
        };
        let profile = dir.join("profile.sb");
        // The port of a proxy grant validate just accepted (§5.3); with no
        // grant, None renders the deny-all form byte-identically.
        let proxy_port = match spec.network {
            Network::Proxy { port } => Some(port),
            Network::None | Network::Loopback { .. } => None,
        };
        let text = match crate::profile::render(
            &approved.spec,
            &approved.ports,
            &self.reserved_ports,
            proxy_port,
        ) {
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
        let started = match live {
            Some(live) => {
                confine_spawn::spawn_live(&profile, &approved.spec, sweep, Some(dir.clone()), live)
            }
            None => confine_spawn::spawn(&profile, &approved.spec, sweep, Some(dir.clone())),
        };
        match started {
            Ok(inner) => Ok(ConfinedChild { inner }),
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                Err(SpawnError::Io(e.to_string()))
            }
        }
    }

    fn live_probe(&self, sweep: Duration) -> Result<Vec<u8>, Unavailable> {
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
                .start(&spec, sweep, false, None)
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
                .start(&mem, sweep, false, None)
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
                .start(&proc, sweep, false, None)
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

    /// The live port probe (§4.4): one confined perl script through the
    /// same spawn path, under a real `Loopback` profile rendered from the
    /// granted `bind` ports, that must observe — each as `<name> ok`:
    /// - `bind-granted`: binding and listening on one granted port works;
    /// - `bind-ungranted`: binding a free but ungranted port fails with
    ///   `EPERM`, so only the profile can have refused it;
    /// - `bind-wildcard`: binding `0.0.0.0:<granted>` fails without a LAN
    ///   grant, so `localhost:<p>` does not admit the whole interface;
    /// - `connect-reserved`: connecting to a harness-held listener standing
    ///   in for the model port fails, and the listener sees no connection
    ///   (checked from outside, INV-41);
    /// - `connect-routable`: connecting to a routable address still fails.
    ///
    /// Run at planning when the task grants ports; a failure refuses the
    /// run (its task asked for ports). Single attempt: a loaded host
    /// refuses and planning can be re-run; no observation is ever retried
    /// past a refusal. The existing H2 probe is not touched.
    pub fn probe_ports(
        &self,
        ev: &Conformed,
        bind: &[u16],
        reserved: &[u16],
    ) -> Result<PortsWitness, Unavailable> {
        let fail = |probe: &'static str, observed: String| Unavailable {
            backend: Some(BackendKind::Seatbelt),
            reason: UnavailableReason::LiveProbeFailed { probe, observed },
        };
        if ev.backend() != self.kind() {
            return Err(fail(
                "ports-witness",
                "the witness belongs to another backend".into(),
            ));
        }
        // The script measures on the first granted port; the rest are in
        // the profile and the digest all the same.
        let granted = match bind.first() {
            Some(&p) => p,
            None => {
                return Err(fail(
                    "ports-grant",
                    "the port probe needs at least one granted port".into(),
                ))
            }
        };
        let io = |e: std::io::Error| Unavailable {
            backend: Some(BackendKind::Seatbelt),
            reason: UnavailableReason::Io(e.to_string()),
        };
        let dir = self.private_dir("ports").map_err(io)?;
        let result = (|| {
            let ws = dir.join("ws");
            std::fs::create_dir_all(&ws).map_err(io)?;
            // A free port that is NOT granted: bound, recorded, released at
            // once, so only the profile can refuse the child's bind there.
            let ungranted = {
                let l = TcpListener::bind("127.0.0.1:0").map_err(io)?;
                l.local_addr().map_err(io)?.port()
            };
            // The stand-in model port: this listener stays bound for the
            // whole probe, so "the listener saw nothing" is checkable from
            // outside, and the profile renders its final deny for it.
            let model_listener = TcpListener::bind("127.0.0.1:0").map_err(io)?;
            model_listener.set_nonblocking(true).map_err(io)?;
            let model = model_listener.local_addr().map_err(io)?.port();
            let mut probe_sb = self.clone();
            probe_sb.reserved_ports = {
                let mut r = reserved.to_vec();
                if !r.contains(&model) {
                    r.push(model);
                }
                r
            };
            let spec = ConfinedSpec {
                argv: vec![
                    crate::profile::STUB_INTERPRETER.into(),
                    "-e".into(),
                    PORT_PROBE.into(),
                    granted.to_string().into(),
                    ungranted.to_string().into(),
                    model.to_string().into(),
                ],
                cwd: ws.clone(),
                env: vec![("RH_PROBE".into(), "1".into())],
                read_only: vec![],
                read_write: vec![ws],
                protected: vec![],
                network: Network::Loopback {
                    bind: bind.to_vec(),
                    connect: vec![],
                    lan: vec![],
                },
                limits: Limits::wall(Duration::from_secs(20)),
            };
            let exit = probe_sb
                .start(&spec, confine_spawn::SWEEP_DEADLINE, true, None)
                .map_err(|e| fail("ports-spawn", e.to_string()))?
                .wait();
            if exit.status != ChildStatus::Exited(0) {
                return Err(fail(
                    "ports-run",
                    format!(
                        "{:?}: {}",
                        exit.status,
                        String::from_utf8_lossy(&exit.stderr)
                    ),
                ));
            }
            let observed = check_port_observations(&String::from_utf8_lossy(&exit.stdout))?;
            match model_listener.accept() {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                other => {
                    return Err(fail(
                        "connect-reserved",
                        format!("the model-port listener saw {other:?}"),
                    ));
                }
            }
            match exit.domain {
                DomainCleanup::Confirmed { .. } => {}
                d => return Err(fail("ports-sweep", format!("{d:?}"))),
            }
            Ok(observed)
        })();
        let _ = std::fs::remove_dir_all(&dir);
        result.map(|observed| PortsWitness::new(ports_digest(bind, reserved, &observed)))
    }
}

/// The pauses, in milliseconds, before each retry of the live probe (H2f):
/// at most this many retries in all, so at most `len + 1` attempts.
const PROBE_BACKOFFS_MS: &[u64] = &[250, 1000];

/// Whether a failed live probe failed the way a loaded machine makes it
/// fail, rather than by finding a confinement guard not to hold (H2f).
///
/// Only failures of the probe's own running land here: a spawn that did
/// not start (`spawn`, `mem-spawn`, `proc-spawn`) and a probe run itself
/// timing out or ending without a status (`run`). The sweep deadline's own
/// timeout is [`sweep_timed_out`] (retried once, at a tripled deadline,
/// P-41) and a signal death before a report is [`signal_before_report`]
/// (re-run once, P-41). Every result that says a guard did not hold is
/// final at once: a named probe not refused, the network, the write
/// outside the roots, the memory bound, the process limit, `Confirmed`
/// with no kill. A retry therefore never turns a breach into a pass: the
/// attempt that passes ran and checked every guard itself, in its own
/// fresh private directory.
fn load_shaped(u: &Unavailable) -> bool {
    match &u.reason {
        UnavailableReason::LiveProbeFailed { probe, observed } => match *probe {
            "spawn" | "mem-spawn" | "proc-spawn" => true,
            "run" => observed.starts_with("TimedOut") || observed.starts_with("Unknown"),
            _ => false,
        },
        _ => false,
    }
}

/// Whether the failed attempt is a sweep that ran out of its deadline
/// (`Unconfirmed` from the stub's `unconverged`), the one load failure the
/// schedule answers with a tripled deadline (P-41). Any other
/// `Unconfirmed` — a mid-run canary, a stub that died with no report — is
/// a negative observation, and so is `Confirmed` with no kill: neither is
/// this, and neither is retried.
fn sweep_timed_out(u: &Unavailable) -> bool {
    matches!(
        &u.reason,
        UnavailableReason::LiveProbeFailed { probe, observed }
            if (*probe == "sweep" || *probe == "proc-sweep")
                && observed.contains("would not die within the sweep deadline")
    )
}

/// Whether the failed attempt's probe was killed by a signal before it
/// could report (`Signaled(n)` where a verdict was expected): re-run once;
/// a second failure of this kind is final (P-41).
fn signal_before_report(u: &Unavailable) -> bool {
    matches!(
        &u.reason,
        UnavailableReason::LiveProbeFailed { probe, observed }
            if matches!(*probe, "run" | "mem-applied" | "proc-limit")
                && observed.starts_with("Signaled(")
    )
}

/// How many attempts a passing probe took, and the sweep deadline its last
/// attempt used. Both go into the witness's probe digest, so an audit can
/// tell a retried probe from a clean first-attempt one (P-41).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Attempts {
    count: u32,
    sweep: Duration,
}

/// Run `attempt` (the whole live probe, at the sweep deadline it is given)
/// and retry it while it fails in a load-shaped way (H2f), at most
/// `backoffs_ms.len()` times in all, pausing before each retry. The
/// schedule (P-41):
///
/// - a sweep that ran out of its deadline is retried once, at a TRIPLED
///   deadline (the stub is asked for 9 s instead of 3 s);
/// - a probe killed by a signal before it reported is re-run once; a
///   second failure of the same kind is final;
/// - every other load-shaped failure uses up the remaining budget;
/// - an escape — any result that says a guard did not hold — is final at
///   once, whatever came before it.
///
/// The last failure is returned as it is: a probe that really fails still
/// refuses, with its own error.
fn probe_with_retries<T>(
    mut attempt: impl FnMut(Duration) -> Result<T, Unavailable>,
    backoffs_ms: &[u64],
    mut pause: impl FnMut(u64),
) -> Result<(T, Attempts), Unavailable> {
    let mut retries = backoffs_ms.iter();
    let mut sweep = confine_spawn::SWEEP_DEADLINE;
    let mut count = 0u32;
    let mut sweep_retried = false;
    let mut signal_retried = false;
    loop {
        count += 1;
        match attempt(sweep) {
            Ok(t) => return Ok((t, Attempts { count, sweep })),
            Err(e) => {
                let retriable = if sweep_timed_out(&e) {
                    if sweep_retried {
                        false
                    } else {
                        sweep_retried = true;
                        sweep *= 3;
                        true
                    }
                } else if signal_before_report(&e) {
                    if signal_retried {
                        false
                    } else {
                        signal_retried = true;
                        true
                    }
                } else {
                    load_shaped(&e)
                };
                let next = if retriable { retries.next() } else { None };
                match next {
                    Some(&ms) => pause(ms),
                    None => return Err(e),
                }
            }
        }
    }
}

/// SHA-256 over the profile version, the matrix row, what the probe
/// observed, and its attempt count and sweep deadline (P-41): the witness's
/// digest records a retried probe, so an audit replay can tell it from a
/// clean first-attempt probe.
fn observations_digest(row_id: &str, observed: &[u8], attempts: Attempts) -> harness_core::Digest {
    let attempts_line = format!(
        "attempts={} sweep-deadline={}s\n",
        attempts.count,
        attempts.sweep.as_secs()
    );
    harness_core::sha256_parts(&[
        crate::profile::PROFILE_VERSION.as_bytes(),
        b"\n",
        row_id.as_bytes(),
        b"\n",
        observed,
        attempts_line.as_bytes(),
    ])
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

// The witness type lives with the spec (P-36g): the `Confinement` trait's
// `probe_ports` is cross-platform, so the type must be too.
use crate::spec::PortsWitness;

/// The probes the port script reports, each as `<name> ok` (ok: the
/// observation matched what a conforming host must show).
const PORT_PROBES: &[&str] = &[
    "bind-granted",
    "bind-ungranted",
    "bind-wildcard",
    "connect-reserved",
    "connect-routable",
];

/// Verify the port probe's observations: every name must read `<name> ok`,
/// in the fixed order the script prints them. A missing or negative
/// observation is a host that does not express the port rules, and is the
/// final answer (§4.4).
fn check_port_observations(out: &str) -> Result<Vec<u8>, Unavailable> {
    let mut observed = String::new();
    for name in PORT_PROBES {
        let want = format!("{name} ok\n");
        if !out.contains(&want) {
            return Err(Unavailable {
                backend: Some(BackendKind::Seatbelt),
                reason: UnavailableReason::LiveProbeFailed {
                    probe: name,
                    observed: out.to_string(),
                },
            });
        }
        observed.push_str(&want);
    }
    Ok(observed.into_bytes())
}

/// The port probe's digest: profile version, the granted and reserved
/// ports probed, and the observations, so a witness for one grant cannot
/// stand for another.
fn ports_digest(bind: &[u16], reserved: &[u16], observed: &[u8]) -> harness_core::Digest {
    let ports_line = format!("bind={bind:?} reserved={reserved:?}\n");
    harness_core::sha256_parts(&[
        crate::profile::PROFILE_VERSION.as_bytes(),
        b"\n",
        ports_line.as_bytes(),
        observed,
    ])
}

/// The live port probe script (arguments: one granted port, an ungranted
/// free port, the model-port stand-in). `EPERM` (1) is required for the
/// bind refusals: a refusal for any other reason (say `EADDRINUSE`) means
/// the measurement is bad, and reports FAIL.
const PORT_PROBE: &str = r#"use strict; use Socket;
my ($granted,$ungranted,$model)=@ARGV; $|=1;
sub r { print $_[0], ($_[1] ? ' ok' : ' FAIL'), "\n" }
socket(my $g,PF_INET,SOCK_STREAM,0) or die;
my $b = bind($g, sockaddr_in($granted, inet_aton('127.0.0.1')));
r('bind-granted', $b && listen($g,1));
close($g);
socket(my $u,PF_INET,SOCK_STREAM,0) or die;
my $bu = bind($u, sockaddr_in($ungranted, inet_aton('127.0.0.1')));
r('bind-ungranted', !$bu && ($!+0)==1);
close($u);
socket(my $w,PF_INET,SOCK_STREAM,0) or die;
my $bw = bind($w, sockaddr_in($granted, INADDR_ANY));
r('bind-wildcard', !$bw && ($!+0)==1);
close($w);
socket(my $m,PF_INET,SOCK_STREAM,0) or die;
r('connect-reserved', !connect($m, sockaddr_in($model, inet_aton('127.0.0.1'))));
close($m);
socket(my $o,PF_INET,SOCK_STREAM,0) or die;
r('connect-routable', !connect($o, sockaddr_in(80, inet_aton('192.0.2.1'))));
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
        let (observed, attempts) = probe_with_retries(
            |sweep| self.live_probe(sweep),
            PROBE_BACKOFFS_MS,
            |ms| std::thread::sleep(Duration::from_millis(ms)),
        )?;
        let digest = observations_digest(row.id, &observed, attempts);
        Ok(Conformed::mint(row, digest))
    }

    fn spawn(&self, spec: &ConfinedSpec, ev: &Conformed) -> Result<ConfinedChild, SpawnError> {
        if ev.backend() != BackendKind::Seatbelt {
            return Err(SpawnError::WrongWitness);
        }
        // Defence in depth (§4.3): `validate` refuses `Network::Loopback`
        // unless its context says the port cases are covered; a spawn may
        // only claim that from its own witness, never from configuration.
        let ports_conformed = ev.covers(conformance::PORTS_CASES).is_ok();
        self.start(spec, confine_spawn::SWEEP_DEADLINE, ports_conformed, None)
    }

    fn spawn_live(
        &self,
        spec: &ConfinedSpec,
        ev: &Conformed,
        live: &LiveOpts,
    ) -> Result<ConfinedChild, SpawnError> {
        if ev.backend() != BackendKind::Seatbelt {
            return Err(SpawnError::WrongWitness);
        }
        let ports_conformed = ev.covers(conformance::PORTS_CASES).is_ok();
        self.start(
            spec,
            confine_spawn::SWEEP_DEADLINE,
            ports_conformed,
            Some(live),
        )
    }
}

#[cfg(test)]
mod retry_tests {
    use super::*;

    fn failed(probe: &'static str, observed: &str) -> Unavailable {
        Unavailable {
            backend: Some(BackendKind::Seatbelt),
            reason: UnavailableReason::LiveProbeFailed {
                probe,
                observed: observed.into(),
            },
        }
    }

    /// The `sweep` observation of a stub that ran out of its 3 s deadline.
    const SWEEP_TIMEOUT: &str =
        "Unconfirmed(\"processes of the domain would not die within the sweep deadline (3 s)\")";
    /// The same, at the tripled deadline a retry asks for.
    const SWEEP_TIMEOUT_9S: &str =
        "Unconfirmed(\"processes of the domain would not die within the sweep deadline (9 s)\")";
    /// The `sweep` observation of a stub whose signal filter failed
    /// mid-run: a negative security observation, never a timeout.
    const SWEEP_CANARY: &str =
        "Unconfirmed(\"the domain stub stopped sweeping: its signal filter check failed \
         mid-run (canary)\")";
    /// The `sweep` observation of a stub that died with no report: a
    /// negative security observation, never a timeout.
    const SWEEP_NO_REPORT: &str =
        "Unconfirmed(\"no report from the domain stub (stub status Some(9))\")";
    /// The observation of a probe killed by a signal before it reported.
    const SIGNALLED: &str = "Signaled(5): ";

    #[test]
    fn probe_retries_unconfirmed_timeout_once() {
        // A sweep that ran out of its 3 s deadline is retried exactly once
        // (P-41), asking the stub for a tripled deadline; the passing
        // attempt's count and deadline are what the witness will record.
        let mut sweeps = Vec::new();
        let mut pauses = Vec::new();
        let r = probe_with_retries(
            |sweep| {
                sweeps.push(sweep);
                if sweeps.len() == 1 {
                    Err(failed("sweep", SWEEP_TIMEOUT))
                } else {
                    Ok(())
                }
            },
            PROBE_BACKOFFS_MS,
            |ms| pauses.push(ms),
        );
        let ((), attempts) = r.unwrap();
        assert_eq!(
            sweeps,
            vec![Duration::from_secs(3), Duration::from_secs(9)],
            "one retry, at 3x the deadline"
        );
        assert_eq!(
            attempts,
            Attempts {
                count: 2,
                sweep: Duration::from_secs(9)
            }
        );
        assert_eq!(pauses, vec![250], "one pause, from the usual budget");
    }

    #[test]
    fn probe_retry_never_masks_an_escape() {
        // A negative security observation is the answer at once, whatever
        // came before it (P-41): here, the result of a fixture run where
        // the sandbox did not hold — the escapee survived the sweep, the
        // filter failed mid-run, the stub died, the network let a
        // connection through, the write landed, the memory bound did not.
        for (probe, observed) in [
            ("sweep", "Confirmed { kills: 0 }"),
            ("proc-sweep", "Confirmed { kills: 0 }"),
            ("sweep", SWEEP_CANARY),
            ("proc-sweep", SWEEP_NO_REPORT),
            ("net", "the listener saw Ok(..)"),
            ("write", "the file exists outside the roots"),
            ("mem-bound", "Exited(0): NOTBOUNDED"),
        ] {
            let mut calls = 0;
            let r: Result<((), Attempts), _> = probe_with_retries(
                |_| {
                    calls += 1;
                    Err(failed(probe, observed))
                },
                PROBE_BACKOFFS_MS,
                |_| {},
            );
            assert_eq!(calls, 1, "{probe} ({observed}): never retried");
            assert_eq!(r, Err(failed(probe, observed)));
        }
        // A timeout earns its one 3x retry — but an escape that retry
        // finds is still the final answer.
        let mut calls = 0;
        let r: Result<((), Attempts), _> = probe_with_retries(
            |_| {
                calls += 1;
                Err(if calls == 1 {
                    failed("sweep", SWEEP_TIMEOUT)
                } else {
                    failed("sweep", "Confirmed { kills: 0 }")
                })
            },
            PROBE_BACKOFFS_MS,
            |_| {},
        );
        assert_eq!(calls, 2);
        assert_eq!(r, Err(failed("sweep", "Confirmed { kills: 0 }")));
    }

    #[test]
    fn probe_second_failure_is_final() {
        // A probe killed by a signal before it reports is re-run once, at
        // the same deadline; the second identical death stands (P-41).
        let mut calls = 0;
        let mut sweeps = Vec::new();
        let r: Result<((), Attempts), _> = probe_with_retries(
            |sweep| {
                calls += 1;
                sweeps.push(sweep);
                Err(failed("mem-applied", SIGNALLED))
            },
            PROBE_BACKOFFS_MS,
            |_| {},
        );
        assert_eq!(calls, 2, "one re-run, no more");
        assert_eq!(
            sweeps,
            vec![Duration::from_secs(3); 2],
            "the deadline does not move for a signal death"
        );
        assert_eq!(r, Err(failed("mem-applied", SIGNALLED)));
    }

    #[test]
    fn a_load_shaped_failure_is_retried_until_it_passes() {
        // H2f, unchanged where P-41 is silent: a spawn that did not start
        // is retried on the usual short, growing pauses, and the deadline
        // does not move for it.
        let mut calls = 0;
        let mut pauses = Vec::new();
        let r = probe_with_retries(
            |sweep| {
                calls += 1;
                assert_eq!(sweep, Duration::from_secs(3));
                if calls < 3 {
                    Err(failed("spawn", "SpawnError"))
                } else {
                    Ok(())
                }
            },
            PROBE_BACKOFFS_MS,
            |ms| pauses.push(ms),
        );
        let ((), attempts) = r.unwrap();
        assert_eq!(
            attempts,
            Attempts {
                count: 3,
                sweep: Duration::from_secs(3)
            }
        );
        assert_eq!(pauses, vec![250, 1000], "short, growing pauses, in order");
    }

    #[test]
    fn a_probe_that_really_fails_still_refuses_after_the_bounded_retries() {
        let mut calls = 0;
        let r: Result<((), Attempts), _> = probe_with_retries(
            |_| {
                calls += 1;
                Err(failed("spawn", "SpawnError"))
            },
            PROBE_BACKOFFS_MS,
            |_| {},
        );
        assert_eq!(calls, 3, "one attempt and two retries, no more");
        assert_eq!(
            r,
            Err(failed("spawn", "SpawnError")),
            "the failure, unchanged"
        );
    }

    #[test]
    fn a_guard_that_did_not_hold_is_final_at_the_first_attempt() {
        for (probe, observed) in [
            ("net", "the listener saw Ok(..)"),
            ("write", "the file exists outside the roots"),
            ("read", "read fail"),
            ("mem-bound", "Exited(0): NOTBOUNDED"),
            ("mem-applied", "TimedOut: "),
            ("proc-limit", "TimedOut: forked"),
            ("run", "Exited(1): boom"),
            ("sweep", "Confirmed { kills: 0 }"),
            ("proc-sweep", "Confirmed { kills: 0 }"),
        ] {
            let mut calls = 0;
            let mut paused = false;
            let r: Result<((), Attempts), _> = probe_with_retries(
                |_| {
                    calls += 1;
                    Err(failed(probe, observed))
                },
                PROBE_BACKOFFS_MS,
                |_| paused = true,
            );
            assert_eq!(calls, 1, "{probe}: never retried");
            assert!(!paused, "{probe}");
            assert_eq!(r, Err(failed(probe, observed)));
        }
        // An I/O or missing-primitive refusal is not a load symptom either.
        let io = Unavailable {
            backend: Some(BackendKind::Seatbelt),
            reason: UnavailableReason::Io("no space".into()),
        };
        let mut calls = 0;
        let _ = probe_with_retries::<()>(
            |_| {
                calls += 1;
                Err(io.clone())
            },
            PROBE_BACKOFFS_MS,
            |_| {},
        );
        assert_eq!(calls, 1);
    }

    #[test]
    fn a_breach_after_a_load_failure_is_not_forgiven() {
        // The first attempt fails by load, the second finds a guard not
        // holding: that is the answer, not a third try.
        let mut calls = 0;
        let r: Result<((), Attempts), _> = probe_with_retries(
            |_| {
                calls += 1;
                Err(if calls == 1 {
                    failed("spawn", "SpawnError")
                } else {
                    failed("write", "the file exists outside the roots")
                })
            },
            PROBE_BACKOFFS_MS,
            |_| {},
        );
        assert_eq!(calls, 2);
        assert_eq!(r, Err(failed("write", "the file exists outside the roots")));
    }

    #[test]
    fn the_sweep_timeout_s_observation_is_recognised_at_either_deadline() {
        // The message names the deadline it ran out of, so the detector
        // must not depend on which one.
        assert!(sweep_timed_out(&failed("sweep", SWEEP_TIMEOUT)));
        assert!(sweep_timed_out(&failed("sweep", SWEEP_TIMEOUT_9S)));
        assert!(sweep_timed_out(&failed("proc-sweep", SWEEP_TIMEOUT_9S)));
        assert!(!sweep_timed_out(&failed("sweep", SWEEP_CANARY)));
        assert!(!sweep_timed_out(&failed("sweep", SWEEP_NO_REPORT)));
        assert!(!sweep_timed_out(&failed("sweep", "Confirmed { kills: 0 }")));
        assert!(!sweep_timed_out(&failed("run", SWEEP_TIMEOUT)));
        assert!(signal_before_report(&failed("mem-applied", SIGNALLED)));
        assert!(signal_before_report(&failed("run", SIGNALLED)));
        assert!(signal_before_report(&failed("proc-limit", SIGNALLED)));
        assert!(!signal_before_report(&failed("mem-applied", "TimedOut: ")));
        assert!(!signal_before_report(&failed("mem-applied", "Exited(1): ")));
        assert!(!signal_before_report(&failed("spawn", SIGNALLED)));
    }

    #[test]
    fn witness_records_attempts_and_deadline() {
        // The witness's probe digest commits to the attempt count and the
        // sweep deadline of the last attempt (P-41): a retried probe's
        // witness differs from a clean one, the same record recomputes the
        // same digest, and either field alone changes it.
        let row = conformance::row(BackendKind::Seatbelt, "macos").expect("the row is committed");
        let seen = b"net ok\nmem-applied ok\n";
        let clean = observations_digest(
            row.id,
            seen,
            Attempts {
                count: 1,
                sweep: Duration::from_secs(3),
            },
        );
        let retried = observations_digest(
            row.id,
            seen,
            Attempts {
                count: 2,
                sweep: Duration::from_secs(9),
            },
        );
        assert_ne!(
            clean, retried,
            "a retried probe's witness is distinguishable"
        );
        let witness = Conformed::mint(row, clean);
        let retried_witness = Conformed::mint(row, retried);
        assert_ne!(witness.probe_digest(), retried_witness.probe_digest());
        assert_eq!(
            observations_digest(
                row.id,
                seen,
                Attempts {
                    count: 2,
                    sweep: Duration::from_secs(9)
                }
            ),
            retried,
            "the same record recomputes the same digest"
        );
        for changed in [
            Attempts {
                count: 1,
                sweep: Duration::from_secs(9),
            },
            Attempts {
                count: 2,
                sweep: Duration::from_secs(3),
            },
            Attempts {
                count: 3,
                sweep: Duration::from_secs(9),
            },
        ] {
            assert_ne!(
                observations_digest(row.id, seen, changed),
                clean,
                "{changed:?} must not hash as the clean first attempt"
            );
        }
        // The observations themselves are still part of the commitment.
        assert_ne!(
            observations_digest(
                row.id,
                b"net ok\n",
                Attempts {
                    count: 1,
                    sweep: Duration::from_secs(3)
                }
            ),
            clean
        );
    }
}

#[cfg(test)]
mod port_probe_tests {
    use super::*;

    #[test]
    fn probe_ports_refuses_when_an_ungranted_bind_succeeds() {
        // The injected observation (§4.4): a host whose sandbox let the
        // ungranted bind through reports `bind-ungranted FAIL`; the
        // checker must refuse, naming that probe, so no PortsWitness is
        // minted from a host that does not express the port rules.
        let mut good = String::new();
        for name in PORT_PROBES {
            good.push_str(name);
            good.push_str(" ok\n");
        }
        assert!(check_port_observations(&good).is_ok());
        let hostile = good.replace("bind-ungranted ok", "bind-ungranted FAIL");
        let e = check_port_observations(&hostile).unwrap_err();
        assert!(
            matches!(
                &e.reason,
                UnavailableReason::LiveProbeFailed { probe, .. } if *probe == "bind-ungranted"
            ),
            "{e}"
        );
        // A wildcard bind let through is refused the same way.
        let hostile = good.replace("bind-wildcard ok", "bind-wildcard FAIL");
        assert!(check_port_observations(&hostile).is_err());
        // A truncated report (a probe that never ran) refuses too.
        assert!(check_port_observations("bind-granted ok\n").is_err());
        assert!(check_port_observations("").is_err());
    }

    #[test]
    fn ports_witness_digest_covers_the_ports_and_the_observations() {
        let o: &[u8] = b"bind-granted ok\n";
        let a = ports_digest(&[5173], &[11434], o);
        // The same record recomputes the same digest; any other grant,
        // reservation, or observation hashes differently.
        assert_eq!(a, ports_digest(&[5173], &[11434], o));
        assert_ne!(a, ports_digest(&[5174], &[11434], o));
        assert_ne!(a, ports_digest(&[5173], &[], o));
        assert_ne!(a, ports_digest(&[5173], &[11434], b"bind-granted FAIL\n"));
        let w = PortsWitness::new(a);
        assert_eq!(w.digest(), &a);
    }
}
