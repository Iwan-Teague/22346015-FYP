//! The namespace tier (S-Lj): an unprivileged user/network/PID namespace
//! pair plus the harness-side port forwarder that makes
//! `Network::Loopback` grants possible (§1's ports row; P-36 §8 point 3).
//!
//! The tier is strictly opt-in and strictly narrower than the default:
//!
//! ```text
//!   spawner (the harness)
//!     ├─ Forwarder (THIS process; host half of the relay)
//!     │    TcpListeners on 127.0.0.1:<bind ports>
//!     │    UnixListener on <relay>/connect.sock
//!     └─ helper (as in supervisor.rs)
//!          └─ nsprep (own group; unshare NEWUSER|NEWNET|NEWPID|NEWIPC,
//!             uid/gid map, lo up)
//!               ├─ UnixListener on <relay>/bind.sock
//!               ├─ inside TcpListeners for the <connect ports>
//!               └─ program (the namespace's PID-1: Landlock + seccomp +
//!                  rlimits, then execve; KillDomain::LinuxPidNamespace)
//! ```
//!
//! Data paths (one unix connection per flow, header `p <port>\n`, then raw
//! bytes both ways):
//!
//! - a **bind** grant (`host 127.0.0.1:P` must reach the program): the
//!   Forwarder accepts on its `TcpListener(P)`, dials `<relay>/bind.sock`,
//!   sends `p P`; nsprep checks `P` against its bind list, dials inside
//!   `127.0.0.1:P`, and pumps. The netns is empty, so nothing else is
//!   reachable.
//! - a **connect** grant (the program may reach `127.0.0.1:C`): nsprep
//!   listens on `C` inside the netns, accepts the program's connection,
//!   dials `<relay>/connect.sock`, sends `p C`; the Forwarder checks `C`
//!   against its connect list — the model port cannot be forwarded by
//!   construction — dials host `127.0.0.1:C`, and pumps.
//!
//! Layering mirrors [`crate::supervisor`]: [`Tier`], [`NetnsSpec`], the
//! header codec, the allowlist check and the whole [`Forwarder`] are pure
//! std and unit-tested on every OS; `nsprep_main` and the raw syscall
//! wrappers (`unshare`, the ioctl pair for `lo`, the id-map inputs) exist
//! only on Linux, through the same one-`unsafe`-site raw `syscall(2)` FFI
//! shape the crate committed to in S-Lc (the shared supervisor wrappers
//! are reused where the call is the same).
//!
//! Fail-closed tier selection ([`tier_for`], L-Q8): a host whose userns is
//! measured unusable or unknown stays on the default tier (ports refused
//! there); the namespace tier is chosen only when `userns_usable()` is
//! `Some(true)`. A failed namespace setup is an exec-failure exit code
//! (104/105/106), never a degraded run.
//!
//! Deliberate deviations from the slice card's sketch, both noted in
//! docs/slices/S-Lj.md: no bind-mount of the relay socket (this tier does
//! not unshare the mount namespace, so the same filesystem view reaches
//! both halves, and the program cannot use unix sockets anyway — seccomp
//! denies `socket(AF_UNIX)`), and the nsprep relay serves one flow at a
//! time (conformance scale; a stalled flow delays exit reporting by at
//! most that flow's lifetime, bounded by the wall clock upstream).

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// The relay directory's bind-side socket (listened by nsprep).
pub const BIND_RELAY: &str = "bind.sock";
/// The relay directory's connect-side socket (listened by the Forwarder).
pub const CONNECT_RELAY: &str = "connect.sock";

/// The relay header's largest sensible line (`p 65535\n` is 8 bytes).
const HEADER_MAX: usize = 32;
/// The accept loops' wake-up tick.
const TICK: Duration = Duration::from_millis(50);
/// A relay peer gets this long to produce its header before it is dropped.
const HEADER_TIMEOUT: Duration = Duration::from_secs(2);

/// Which containment tier a Linux host runs (S-Lj).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Landlock + seccomp + process-group sweep; ports refused.
    Default,
    /// The default domain inside an unprivileged userns/netns/pidns, with
    /// the relay forwarder enabling loopback-port grants.
    Netns,
}

/// Pick the tier from `HostFacts::userns_usable()` (L-Q8): unknown or
/// measured-unusable falls back to the default tier — an AppArmor-restricted
/// userns host must refuse PORTS, never refuse the backend outright.
#[must_use]
pub fn tier_for(userns_usable: Option<bool>) -> Tier {
    match userns_usable {
        Some(true) => Tier::Netns,
        Some(false) | None => Tier::Default,
    }
}

/// The namespace half of a [`crate::supervisor::Program`]: the relay
/// directory (shared with the harness's [`Forwarder`]) and the two port
/// grant lists. `None` on the field means the default (no-namespace) tier.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetnsSpec {
    /// The relay directory holding [`BIND_RELAY`] and [`CONNECT_RELAY`].
    pub relay_dir: String,
    /// Ports the host may reach inside (`Network::Loopback.bind`).
    pub bind: Vec<u16>,
    /// Ports inside may reach on the host (`Network::Loopback.connect`).
    pub connect: Vec<u16>,
}

impl NetnsSpec {
    /// Whether any port grant is in play (drives the seccomp shape: with
    /// none, the ladder is the identical deny-all of the default tier).
    #[must_use]
    pub fn has_ports(&self) -> bool {
        !self.bind.is_empty() || !self.connect.is_empty()
    }

    /// The full path of the bind-side relay socket.
    #[must_use]
    pub fn bind_path(&self) -> PathBuf {
        relay_path(&self.relay_dir, BIND_RELAY)
    }

    /// The full path of the connect-side relay socket.
    #[must_use]
    pub fn connect_path(&self) -> PathBuf {
        relay_path(&self.relay_dir, CONNECT_RELAY)
    }
}

/// Join a relay directory and socket name.
#[must_use]
pub fn relay_path(dir: &str, name: &str) -> PathBuf {
    Path::new(dir).join(name)
}

/// The relay header line for `port` (`p <port>\n`).
#[must_use]
pub fn port_line(port: u16) -> String {
    format!("p {port}\n")
}

/// Parse a `p <port>\n` header. Anything else is a refusal.
#[must_use]
pub fn parse_port_line(line: &[u8]) -> Option<u16> {
    let body = line.strip_suffix(b"\n").unwrap_or(line);
    let rest = body.strip_prefix(b"p ")?;
    if rest.is_empty() || rest.len() > 5 || !rest.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(rest).ok()?.parse().ok()
}

/// Read one header line byte-by-byte (never past the newline) and parse it.
fn read_port_line<R: Read>(r: &mut R) -> Option<u16> {
    let mut one = [0u8; 1];
    let mut acc: Vec<u8> = Vec::new();
    loop {
        let n = r.read(&mut one).ok()?;
        if n == 0 {
            return None;
        }
        let b = one.first().copied()?;
        if b == b'\n' {
            return parse_port_line(&acc);
        }
        acc.push(b);
        if acc.len() > HEADER_MAX {
            return None;
        }
    }
}

/// Whether a grant list covers `port` (the allowlist gate both relay
/// halves apply before dialing anything).
#[must_use]
pub fn grant_allows(grants: &[u16], port: u16) -> bool {
    grants.contains(&port)
}

// ---- the host half of the relay (the harness process) ----------------------

/// One direction pair's shared shape: clone the handle, and stop the
/// socket when a copy finishes so the opposite direction cannot hang.
trait Relayed: Read + Write + Send + Sync + 'static {
    /// A duplicate handle of this socket.
    fn twin(&self) -> std::io::Result<Self>
    where
        Self: Sized;
    /// End the socket (best effort; unix streams end by dropping).
    fn shut(&self);
}

impl Relayed for TcpStream {
    fn twin(&self) -> std::io::Result<Self> {
        Self::try_clone(self)
    }
    fn shut(&self) {
        let _ = self.shutdown(std::net::Shutdown::Both);
    }
}

impl Relayed for UnixStream {
    fn twin(&self) -> std::io::Result<Self> {
        Self::try_clone(self)
    }
    fn shut(&self) {
        // A unix stream has no shutdown(2): the peer learns of the end by
        // this process dropping its handles (each pump thread's clones die
        // with the thread).
    }
}

/// Pump two relay endpoints until both directions end. Two threads, each
/// `io::copy`-ing one way; whichever finishes first stops its output side.
fn cross_pump<X: Relayed, Y: Relayed>(x: X, y: Y) {
    let (Ok(mut xr), Ok(mut yw)) = (x.twin(), y.twin()) else {
        return;
    };
    let (Ok(mut yr), Ok(mut xw)) = (y.twin(), x.twin()) else {
        return;
    };
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut xr, &mut yw);
        yw.shut();
    });
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut yr, &mut xw);
        xw.shut();
    });
}

/// The host half of the relay, run inside the harness process.
///
/// It owns the forward-facing listeners: one `TcpListener` on
/// `127.0.0.1:<p>` per bind grant, and the unix listener on
/// `<relay>/connect.sock`. Host clients are only ever relayed toward the
/// nsprep half; nsprep's connections to `connect.sock` are only ever
/// dialed onto the host when the header's port is in the connect grant
/// list — the model port cannot be forwarded by construction.
pub struct Forwarder {
    stop: Arc<AtomicBool>,
    connect: Vec<u16>,
    connect_sock: PathBuf,
}

impl Forwarder {
    /// Bind the forward-facing listeners and start the accept loops.
    /// A bind port that is already taken fails the start (the caller
    /// validated reservation upstream; a race loses fail-closed).
    pub fn start(relay_dir: &str, bind: &[u16], connect: &[u16]) -> std::io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let bind_sock = relay_path(relay_dir, BIND_RELAY);
        for &port in bind {
            let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
            let listener = TcpListener::bind(addr)?;
            let _ = listener.set_nonblocking(true);
            let stop_loop = Arc::clone(&stop);
            let sock = bind_sock.clone();
            std::thread::spawn(move || {
                while !stop_loop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((client, _)) => {
                            // BSD accept() inherits O_NONBLOCK from the
                            // listener; the relay pumps want blocking fds.
                            let _ = client.set_nonblocking(false);
                            let stop_conn = Arc::clone(&stop_loop);
                            let sock = sock.clone();
                            std::thread::spawn(move || {
                                if stop_conn.load(Ordering::Acquire) {
                                    return;
                                }
                                let _ = serve_bind_client(client, port, &sock);
                            });
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(TICK);
                        }
                        Err(_) => break,
                    }
                }
            });
        }
        let connect_sock = relay_path(relay_dir, CONNECT_RELAY);
        let _ = std::fs::remove_file(&connect_sock);
        let unix_listener = UnixListener::bind(&connect_sock)?;
        let _ = unix_listener.set_nonblocking(true);
        let connect_list: Vec<u16> = connect.to_vec();
        let stop_loop = Arc::clone(&stop);
        let grants_loop = connect_list.clone();
        std::thread::spawn(move || {
            while !stop_loop.load(Ordering::Acquire) {
                match unix_listener.accept() {
                    Ok((relay, _)) => {
                        let _ = relay.set_nonblocking(false);
                        let stop_conn = Arc::clone(&stop_loop);
                        let grants = grants_loop.clone();
                        std::thread::spawn(move || {
                            if stop_conn.load(Ordering::Acquire) {
                                return;
                            }
                            let _ = serve_connect_relay(relay, &grants);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(TICK);
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            stop,
            connect: connect_list,
            connect_sock,
        })
    }

    /// The forward-facing connect grants (the dial allowlist).
    #[must_use]
    pub fn connect_grants(&self) -> &[u16] {
        &self.connect
    }

    /// Signal every accept loop to stop (the `Drop` does this too).
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = std::fs::remove_file(&self.connect_sock);
    }
}

/// A host client on bind port `port`: hand it to nsprep's `bind.sock`,
/// naming the inside port, then pump. Any failure drops the client
/// (fail closed: never a half-open relay).
fn serve_bind_client(client: TcpStream, port: u16, bind_sock: &Path) -> std::io::Result<()> {
    let relay = UnixStream::connect(bind_sock)?;
    let mut relay = relay;
    relay.write_all(port_line(port).as_bytes())?;
    cross_pump(relay, client);
    Ok(())
}

/// nsprep's connection on `connect.sock`: read its header, dial the host
/// only when the port is granted, then pump. A refused or malformed
/// header drops the unix connection without dialing anything.
fn serve_connect_relay(relay: UnixStream, grants: &[u16]) -> std::io::Result<()> {
    let mut relay = relay;
    let _ = relay.set_read_timeout(Some(HEADER_TIMEOUT));
    let Some(port) = read_port_line(&mut relay) else {
        return Ok(());
    };
    if !grant_allows(grants, port) {
        return Ok(());
    }
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let Ok(host) = TcpStream::connect(addr) else {
        return Ok(());
    };
    cross_pump(relay, host);
    Ok(())
}

// ---- the Linux process layer (nsprep) --------------------------------------

/// The namespace-tier exec-failure codes, beyond the supervisor's window:
/// 104: the `unshare` refused (a host without unprivileged userns must
/// never reach the tier — the caller gates on `tier_for` first).
pub const NSPREP_UNSHARE_FAIL: i32 = 104;
/// 105: the id maps or the `lo` bring-up failed.
pub const NSPREP_DOMAIN_FAIL: i32 = 105;
/// 106: any other nsprep setup step failed (relay socket, inside
/// listeners, the program fork, the program's pidfd).
pub const NSPREP_SETUP_FAIL: i32 = 106;

/// The nsprep body: never returns. Runs only on Linux. On entry this is a
/// single-threaded fork of the helper holding the supervisor's fds; it
/// leaves as the parent of the namespace's PID 1 with the relay served.
///
/// Exit code: the program's own ending (`Exited(c)` → `c`, `Signaled(s)`
/// → `128+s`), or a 104..=106 setup failure. Either way the kernel has
/// already torn the namespaces down with the last member.
#[cfg(target_os = "linux")]
pub fn nsprep_main(prog: &crate::supervisor::Program) -> ! {
    use crate::supervisor::sys as ssys;
    use std::os::fd::AsRawFd;

    let Some(spec) = prog.netns.as_ref() else {
        ssys::raw_exit(NSPREP_SETUP_FAIL);
    };
    // Die with the helper; own group so one group kill (or the helper's
    // sweep) reaches nsprep and everything below it.
    if ssys::prctl_pdeathsig().is_err() || ssys::setpgid_self().is_err() {
        ssys::raw_exit(NSPREP_SETUP_FAIL);
    }
    // The bind-side relay socket exists before the program starts.
    let bind_sock = spec.bind_path();
    let _ = std::fs::remove_file(&bind_sock);
    let Ok(bind_listener) = UnixListener::bind(&bind_sock) else {
        ssys::raw_exit(NSPREP_SETUP_FAIL);
    };
    let _ = bind_listener.set_nonblocking(true);

    // The real uid/gid, read before the unshare hides them.
    let (uid, gid) = (sys::getuid(), sys::getgid());
    if sys::unshare_user_net_pid_ipc().is_err() {
        ssys::raw_exit(NSPREP_UNSHARE_FAIL);
    }
    if write_id_maps(uid, gid).is_err() || bring_lo_up().is_err() {
        ssys::raw_exit(NSPREP_DOMAIN_FAIL);
    }
    // Inside listeners for the connect grants, in the new netns.
    let mut connect_listeners: Vec<(TcpListener, u16)> = Vec::new();
    for &port in &spec.connect {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        match TcpListener::bind(addr) {
            Ok(l) => {
                let _ = l.set_nonblocking(true);
                connect_listeners.push((l, port));
            }
            Err(_) => ssys::raw_exit(NSPREP_SETUP_FAIL),
        }
    }

    // The program becomes the namespace's PID 1. It stays in this process
    // group (no second setpgid): one group kill covers the whole tree on
    // the host's pid terms, and the pidns init death is the backstop.
    let child = match ssys::fork_prog() {
        Ok(0) => crate::supervisor::child_exec(prog),
        Ok(pid) => pid,
        Err(()) => ssys::raw_exit(NSPREP_SETUP_FAIL),
    };
    // The program holds the stream ends now; nsprep's copies must not keep
    // the spawner's pipes alive (and the status pipe is the helper's).
    ssys::close(crate::supervisor::FD_OUT_W);
    ssys::close(crate::supervisor::FD_ERR_W);
    ssys::close(crate::supervisor::FD_STATUS_W);

    let child_pid = u32::try_from(child).unwrap_or(u32::MAX);
    let Ok(pidfd) = ssys::pidfd_open(child_pid) else {
        ssys::raw_exit(NSPREP_SETUP_FAIL);
    };

    // Serve until the program ends: accept on bind.sock (host → inside)
    // and on each connect listener (inside → host), then map the exit.
    loop {
        let mut fds = vec![ssys::PollFd {
            fd: bind_listener.as_raw_fd(),
            events: ssys::POLL_IN,
            revents: 0,
        }];
        for (l, _) in &connect_listeners {
            fds.push(ssys::PollFd {
                fd: l.as_raw_fd(),
                events: ssys::POLL_IN,
                revents: 0,
            });
        }
        fds.push(ssys::PollFd {
            fd: pidfd,
            events: ssys::POLL_IN,
            revents: 0,
        });
        let hit = ssys::ppoll(&mut fds, crate::supervisor::LIVE_TICK);
        if hit < 0 {
            continue;
        }
        let ready = |i: usize| -> bool {
            fds.get(i)
                .is_some_and(|f| f.revents & (ssys::POLL_IN | ssys::POLL_HUP) != 0)
        };
        if ready(fds.len() - 1) {
            // The namespace's PID 1 is gone; the kernel emptied the rest.
            let status = ssys::wait_block(child_pid).map(i64::from).unwrap_or(-1);
            let _ = std::fs::remove_file(&bind_sock);
            match crate::supervisor::decode_wait(status) {
                crate::supervisor::WaitCause::Exited(c) => ssys::raw_exit(c),
                crate::supervisor::WaitCause::Signaled(s) => ssys::raw_exit(128 + s),
                crate::supervisor::WaitCause::Unknown => ssys::raw_exit(1),
            }
        }
        if ready(0) {
            if let Ok((relay, _)) = bind_listener.accept() {
                let _ = relay.set_nonblocking(false);
                serve_inside_bind(relay, &spec.bind);
            }
        }
        for (i, (l, _)) in connect_listeners.iter().enumerate() {
            if ready(i + 1) {
                if let Ok((client, _)) = l.accept() {
                    let _ = client.set_nonblocking(false);
                    serve_inside_connect(client, &spec.connect_path());
                }
            }
        }
    }
}

/// The inside half of a bind flow: a Forwarder connection on `bind.sock`
/// naming an inside port. Dial `127.0.0.1:<port>` only when the bind list
/// covers it, then pump. Everything here runs in nsprep (inside the
/// namespaces, outside the program's Landlock/seccomp domain by design:
/// it is the harness's relay, not the program).
#[cfg(target_os = "linux")]
fn serve_inside_bind(relay: UnixStream, bind: &[u16]) {
    let mut relay = relay;
    let _ = relay.set_read_timeout(Some(HEADER_TIMEOUT));
    let Some(port) = read_port_line(&mut relay) else {
        return;
    };
    if !grant_allows(bind, port) {
        return;
    }
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let Ok(inside) = TcpStream::connect(addr) else {
        return;
    };
    cross_pump(relay, inside);
}

/// The inside half of a connect flow: the program connected to an inside
/// listener; hand the flow to the Forwarder's `connect.sock`, naming the
/// inside port, then pump. The Forwarder re-checks the port against its
/// own grant list before dialing the host.
#[cfg(target_os = "linux")]
fn serve_inside_connect(client: TcpStream, connect_sock: &Path) {
    let port = match client.local_addr() {
        Ok(SocketAddr::V4(v4)) => v4.port(),
        _ => return,
    };
    let Ok(mut relay) = UnixStream::connect(connect_sock) else {
        return;
    };
    if relay.write_all(port_line(port).as_bytes()).is_err() {
        return;
    }
    cross_pump(relay, client);
}

/// `/proc/self/setgroups` = deny, then the single-uid maps for the new
/// userns. Pure std: procfs writes, no syscalls.
#[cfg(target_os = "linux")]
fn write_id_maps(uid: u32, gid: u32) -> Result<(), ()> {
    std::fs::write("/proc/self/setgroups", b"deny").map_err(|_| ())?;
    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1\n")).map_err(|_| ())?;
    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1\n")).map_err(|_| ())
}

/// Bring `lo` up inside the new netns: an AF_INET datagram socket and the
/// two interface-flags ioctls. The process holds every capability in the
/// new userns, so the ioctls are allowed.
#[cfg(target_os = "linux")]
fn bring_lo_up() -> Result<(), ()> {
    use crate::supervisor::sys::close;
    const IFF_UP: i16 = 0x1;
    const IFF_RUNNING: i16 = 0x2;
    let mut req = sys::IfReq {
        name: [0u8; 16],
        flags: 0,
        pad: [0u8; 24],
    };
    let name = b"lo";
    if let Some(slot) = req.name.get_mut(..name.len()) {
        slot.copy_from_slice(name);
    }
    let fd = sys::socket_inet_dgram()?;
    if sys::ioctl_ifflags(fd, sys::SIOCGIFFLAGS, &mut req).is_err() {
        close(fd);
        return Err(());
    }
    req.flags |= IFF_UP | IFF_RUNNING;
    let set = sys::ioctl_ifflags(fd, sys::SIOCSIFFLAGS, &mut req);
    close(fd);
    set
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod sys {
    //! The namespace tier's own syscall wrappers — only the calls the
    //! supervisor does not already wrap. They funnel through the
    //! supervisor's one raw variadic `syscall(2)` call, so the crate keeps
    //! exactly one `unsafe` site: every pointer argument addresses
    //! caller-owned memory for the call's duration, every failure surfacing
    //! as `Err`.

    use crate::supervisor::sys::sc;

    #[cfg(target_arch = "x86_64")]
    const SYS_IOCTL: i64 = 16;
    #[cfg(target_arch = "aarch64")]
    const SYS_IOCTL: i64 = 29;
    #[cfg(target_arch = "x86_64")]
    const SYS_UNSHARE: i64 = 272;
    #[cfg(target_arch = "aarch64")]
    const SYS_UNSHARE: i64 = 97;
    #[cfg(target_arch = "x86_64")]
    const SYS_GETUID: i64 = 102;
    #[cfg(target_arch = "aarch64")]
    const SYS_GETUID: i64 = 174;
    #[cfg(target_arch = "x86_64")]
    const SYS_GETGID: i64 = 104;
    #[cfg(target_arch = "aarch64")]
    const SYS_GETGID: i64 = 176;
    #[cfg(target_arch = "x86_64")]
    const SYS_SOCKET: i64 = 41;
    #[cfg(target_arch = "aarch64")]
    const SYS_SOCKET: i64 = 198;

    /// `CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWIPC`.
    pub(super) const NS_FLAGS: u64 = 0x1000_0000 | 0x4000_0000 | 0x2000_0000 | 0x0800_0000;
    /// `SIOCGIFFLAGS`.
    pub(super) const SIOCGIFFLAGS: u64 = 0x8913;
    /// `SIOCSIFFLAGS`.
    pub(super) const SIOCSIFFLAGS: u64 = 0x8914;
    /// `AF_INET`, `SOCK_DGRAM` (the ioctl carrier socket).
    const AF_INET: u64 = 2;
    const SOCK_DGRAM: u64 = 2;

    fn ok(rc: i64) -> Result<(), ()> {
        if rc == -1 {
            Err(())
        } else {
            Ok(())
        }
    }

    /// `unshare(CLONE_NEWUSER|NEWNET|NEWPID|NEWIPC)` in one call (the
    /// unprivileged form requires the user namespace in the same set).
    pub(super) fn unshare_user_net_pid_ipc() -> Result<(), ()> {
        // SAFETY: one immediate flags value; no pointers.
        ok(sc(SYS_UNSHARE, NS_FLAGS, 0, 0, 0, 0))
    }

    /// `getuid()` (the real uid, before the unshare).
    pub(super) fn getuid() -> u32 {
        // SAFETY: no arguments.
        sc(SYS_GETUID, 0, 0, 0, 0, 0) as u32
    }

    /// `getgid()` (the real gid, before the unshare).
    pub(super) fn getgid() -> u32 {
        // SAFETY: no arguments.
        sc(SYS_GETGID, 0, 0, 0, 0, 0) as u32
    }

    /// The `ifreq` the ioctls carry (the kernel's layout: a 16-byte name,
    /// then the 24-byte union whose first member is the flags short).
    #[repr(C)]
    pub(super) struct IfReq {
        /// The interface name, NUL-padded.
        pub name: [u8; 16],
        /// `ifr_flags`.
        pub flags: i16,
        /// The rest of the union (unused here).
        pub pad: [u8; 24],
    }

    /// `socket(AF_INET, SOCK_DGRAM, 0)`: the carrier for the ioctls.
    pub(super) fn socket_inet_dgram() -> Result<i32, ()> {
        // SAFETY: immediate values; the return value is an fd.
        let rc = sc(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0, 0, 0);
        if rc == -1 {
            Err(())
        } else {
            Ok(rc as i32)
        }
    }

    /// `ioctl(fd, req, &ifreq)` for the interface-flags pair.
    pub(super) fn ioctl_ifflags(fd: i32, req: u64, ifr: &mut IfReq) -> Result<(), ()> {
        // SAFETY: the kernel reads the fd and request and writes the flags
        // field of the caller-owned ifreq for the call's duration.
        ok(sc(
            SYS_IOCTL,
            fd as u64,
            req,
            std::ptr::from_mut(ifr) as u64,
            0,
            0,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- the tier decision ----

    #[test]
    fn tier_falls_back_to_default_unless_userns_is_usable() {
        // L-Q8: unknown or measured-unusable stays on the default tier
        // (ports refused there), never an outright backend refusal.
        assert_eq!(tier_for(None), Tier::Default);
        assert_eq!(tier_for(Some(false)), Tier::Default);
        assert_eq!(tier_for(Some(true)), Tier::Netns);
    }

    // ---- the header codec ----

    #[test]
    fn port_line_round_trips_strictly() {
        for port in [0u16, 1, 1024, 65_535] {
            assert_eq!(parse_port_line(port_line(port).as_bytes()), Some(port));
        }
        assert_eq!(parse_port_line(b"p 8080"), Some(8080), "newline optional");
        assert_eq!(parse_port_line(b"p "), None);
        assert_eq!(parse_port_line(b"p x\n"), None);
        assert_eq!(parse_port_line(b"p 123456\n"), None);
        assert_eq!(parse_port_line(b"p -1\n"), None);
        assert_eq!(parse_port_line(b"q 1\n"), None);
        assert_eq!(parse_port_line(b""), None);
        assert_eq!(parse_port_line(b"p 8080 tail\n"), None);
    }

    #[test]
    fn read_port_line_never_reads_past_the_newline() {
        let mut wire = b"p 42\nREST OF THE FLOW".to_vec();
        let mut cursor = std::io::Cursor::new(&mut wire);
        assert_eq!(read_port_line(&mut cursor), Some(42));
        // The cursor sits exactly past the newline; the flow bytes remain.
        let at = cursor.position() as usize;
        assert_eq!(wire.get(at..), Some(&b"REST OF THE FLOW"[..]));
        let mut empty = std::io::Cursor::new(Vec::new());
        assert_eq!(read_port_line(&mut empty), None);
        let mut long = std::io::Cursor::new(vec![b'x'; HEADER_MAX + 1]);
        assert_eq!(read_port_line(&mut long), None);
    }

    #[test]
    fn grant_allows_is_the_exact_allowlist() {
        let grants = [8080u16, 8443];
        assert!(grant_allows(&grants, 8080));
        assert!(!grant_allows(&grants, 9090));
        assert!(!grant_allows(&[], 8080));
    }

    // ---- the spec shape ----

    #[test]
    fn netns_spec_reports_whether_any_port_is_granted() {
        let none = NetnsSpec::default();
        assert!(!none.has_ports());
        let bind_only = NetnsSpec {
            relay_dir: "/tmp/r".into(),
            bind: vec![8080],
            connect: Vec::new(),
        };
        assert!(bind_only.has_ports());
        let connect_only = NetnsSpec {
            relay_dir: "/tmp/r".into(),
            connect: vec![9090],
            ..NetnsSpec::default()
        };
        assert!(connect_only.has_ports());
        assert_eq!(bind_only.bind_path(), Path::new("/tmp/r").join(BIND_RELAY));
        assert_eq!(
            connect_only.connect_path(),
            Path::new("/tmp/r").join(CONNECT_RELAY)
        );
    }

    // ---- the Forwarder (a fake nsprep plays the other half) ----

    /// A free 127.0.0.1 port.
    fn free_port() -> u16 {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        l.local_addr().expect("addr").port()
    }

    /// Wait until a path exists (the other half creates sockets async).
    fn wait_for(path: &Path) {
        for _ in 0..200 {
            if path.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(path.exists(), "path {path:?} never appeared");
    }

    /// The fake nsprep's bind half: echo every header, then a fixed reply.
    fn fake_nsprep_bind(bind_sock: &Path, reply: &'static [u8]) {
        let listener = UnixListener::bind(bind_sock).expect("bind sock");
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let mut conn = conn;
                let _ = conn.set_read_timeout(Some(HEADER_TIMEOUT));
                let Some(port) = read_port_line(&mut conn) else {
                    continue;
                };
                let _ = conn.write_all(port_line(port).as_bytes());
                let _ = conn.write_all(reply);
            }
        });
    }

    #[test]
    fn forwarder_relays_a_bind_port_to_the_relay_socket() {
        let dir = std::env::temp_dir().join(format!("rh-ns-fwd-bind-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let bind_sock = dir.join(BIND_RELAY);
        let _ = std::fs::remove_file(&bind_sock);
        let port = free_port();
        fake_nsprep_bind(&bind_sock, b"pong");
        let fwd = Forwarder::start(dir.to_string_lossy().as_ref(), &[port], &[])
            .expect("forwarder starts");
        wait_for(&bind_sock);
        // The host client sees the fake nsprep's reply through the relay.
        let mut client = loop {
            match TcpStream::connect((Ipv4Addr::LOCALHOST, port)) {
                Ok(c) => break c,
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        };
        let _ = client.set_read_timeout(Some(HEADER_TIMEOUT));
        let mut got = Vec::new();
        let _ = client.read_to_end(&mut got);
        let text = String::from_utf8_lossy(&got).to_string();
        assert!(
            text.contains("pong"),
            "expected the relayed reply, got {text:?}"
        );
        drop(client);
        drop(fwd);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn forwarder_dials_only_granted_connect_ports() {
        let dir = std::env::temp_dir().join(format!("rh-ns-fwd-con-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let connect_sock = dir.join(CONNECT_RELAY);
        let _ = std::fs::remove_file(&connect_sock);
        let granted = free_port();
        let host = TcpListener::bind((Ipv4Addr::LOCALHOST, granted)).expect("host listener");
        let _ = host.set_nonblocking(true);
        let fwd = Forwarder::start(dir.to_string_lossy().as_ref(), &[], &[granted])
            .expect("forwarder starts");
        wait_for(&connect_sock);

        // A granted header reaches the host listener, both ways.
        let mut relay = UnixStream::connect(&connect_sock).expect("dial");
        let _ = relay.set_read_timeout(Some(HEADER_TIMEOUT));
        relay.write_all(port_line(granted).as_bytes()).expect("hdr");
        relay.write_all(b"ping").expect("ping");
        let (mut accepted, _) = loop {
            match host.accept() {
                Ok(pair) => break pair,
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        };
        let _ = accepted.set_read_timeout(Some(HEADER_TIMEOUT));
        let mut ping = [0u8; 4];
        accepted.read_exact(&mut ping).expect("host reads ping");
        assert_eq!(&ping, b"ping");
        accepted.write_all(b"ack").expect("host acks");
        let mut ack = [0u8; 3];
        relay.read_exact(&mut ack).expect("relay reads ack");
        assert_eq!(&ack, b"ack");

        // A header naming an UNGRANTED port never dials the host: the unix
        // side is dropped (EOF) and nothing listens on the ungranted port.
        let ungranted = free_port();
        let mut relay = UnixStream::connect(&connect_sock).expect("dial");
        let _ = relay.set_read_timeout(Some(HEADER_TIMEOUT));
        relay
            .write_all(port_line(ungranted).as_bytes())
            .expect("hdr");
        let mut eof = Vec::new();
        let _ = relay.read_to_end(&mut eof);
        assert!(eof.is_empty(), "a refused relay is closed, not served");
        drop(fwd);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
