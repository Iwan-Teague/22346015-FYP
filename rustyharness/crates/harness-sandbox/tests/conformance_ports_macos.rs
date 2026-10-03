//! The loopback-port conformance suite (P-36a, design note §12
//! `PORTS_CASES`) against the macOS Seatbelt backend, through the real
//! spawn seam. Each test states the case it witnesses and checks the
//! behaviour from OUTSIDE the sandbox where it can (listeners silent,
//! bytes arriving), and runs an unconfined control showing the same action
//! works when nothing stops it.
//!
//! These tests ARE the measurement the design note asks for first: whether
//! SBPL's `localhost:<p>` form really admits only a loopback bind (never a
//! wildcard one), whether granted outbound connects work, and whether
//! everything else stays denied under a port profile. `PORTS_CASES` is
//! listed in the matrix row only because every case here passed on the
//! minting host; if one ever fails, ports must be refused again.
//!
//! The measurement was taken (P-36a): SBPL's `localhost:<p>` admits the
//! wildcard bind too, so the loopback-only rule is not expressible and the
//! cases stay OUT of this host's row — see `docs/slices/P-36a.md`. Until a
//! host's row lists them, every port grant is refused by design (fail
//! closed), and each test pins exactly that refusal instead of measuring;
//! the measurement bodies run only where the row covers the cases.
#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::ffi::OsString;
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use harness_sandbox::seatbelt::Seatbelt;
use harness_sandbox::{
    Backend, ConfinedExit, ConfinedSpec, Conformed, DomainCleanup, Limits, Network, SpawnError,
    SpecError,
};

const PERL: &str = "/usr/bin/perl";

fn witness() -> &'static Conformed {
    static W: OnceLock<Conformed> = OnceLock::new();
    W.get_or_init(|| {
        Seatbelt::new()
            .probe()
            .expect("the Seatbelt live probe must pass")
    })
}

/// A fresh directory tree: `ws` (the read-write root) and `outside` (never
/// granted), canonical.
struct Tree {
    root: PathBuf,
    ws: PathBuf,
    outside: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Tree {
        Self::in_base(std::fs::canonicalize(std::env::temp_dir()).unwrap(), name)
    }

    /// The same tree under a short base: a unix-socket path must fit
    /// `sockaddr_un::sun_path` (104 bytes on macOS), which the default
    /// temporary directory alone can exceed.
    fn new_short(name: &str) -> Tree {
        Self::in_base(std::fs::canonicalize(PathBuf::from("/tmp")).unwrap(), name)
    }

    fn in_base(base: PathBuf, name: &str) -> Tree {
        let root = base.join(format!(
            "rh-ports-{name}-{}-{}",
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

    /// The same spec with a loopback-port grant (P-36a).
    fn spec_ports(
        &self,
        argv: &[&str],
        bind: &[u16],
        connect: &[u16],
        lan: &[u16],
    ) -> ConfinedSpec {
        let mut s = self.spec(argv);
        s.network = Network::Loopback {
            bind: bind.to_vec(),
            connect: connect.to_vec(),
            lan: lan.to_vec(),
        };
        s
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Whether the minting witness's row lists the port cases: only then do
/// port grants validate and the measurement bodies below run.
fn ports_conformed() -> bool {
    witness()
        .covers(harness_sandbox::conformance::PORTS_CASES)
        .is_ok()
}

/// The designed refusal of any port grant while the row lacks the port
/// cases (P-36a, fail closed): nothing runs, nothing binds.
fn refused_unconformed(spec: &ConfinedSpec) {
    let e = Seatbelt::new().spawn(spec, witness()).unwrap_err();
    assert_eq!(
        e,
        SpawnError::Spec(SpecError::Unsupported(
            "loopback ports (not conformed on this host)"
        )),
        "ports must be refused until the row covers PORTS_CASES"
    );
}

fn run(spec: &ConfinedSpec) -> ConfinedExit {
    Seatbelt::new().spawn(spec, witness()).unwrap().wait()
}

/// Run through a backend that reserves `reserved` ports (the model-port
/// stand-in of the model-server case).
fn run_reserved(spec: &ConfinedSpec, reserved: &[u16]) -> ConfinedExit {
    Seatbelt::new()
        .with_reserved_ports(reserved.to_vec())
        .spawn(spec, witness())
        .unwrap()
        .wait()
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

/// A free TCP port: bound once and released, so a later bind fails only if
/// something (here: the profile) refuses it, not because it is taken.
fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// A held harness listener, non-blocking for the post-hoc "saw nothing"
/// checks.
fn held_listener() -> (TcpListener, u16) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let port = l.local_addr().unwrap().port();
    (l, port)
}

/// Poll until `path` exists (the confined program's sync marker).
fn wait_for(path: &Path, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(Instant::now() < deadline, "{what} never happened");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Whether a queued connection can be accepted (the listener "saw" one).
fn saw_connection(l: &TcpListener) -> bool {
    for _ in 0..40 {
        if l.accept().is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

/// Drain whatever a control left queued on `l`.
fn drain(l: &TcpListener) {
    while l.accept().is_ok() {}
}

/// `ports-bind-granted`: a bind to `localhost:<granted>` is allowed, the
/// listener is reachable from OUTSIDE the sandbox (the point of the
/// grant: the user's browser), and the accepted connection carries bytes.
#[test]
fn ft_ports_bind_granted_loopback_port_is_allowed() {
    let t = Tree::new("bind-granted");
    let p = free_port();
    // Bind, listen, mark, accept one connection, echo one line of it.
    let script = "use Socket; socket(my $s,PF_INET,SOCK_STREAM,0) or die; \
        my $b = bind($s, sockaddr_in($ARGV[0], inet_aton(q{127.0.0.1}))); \
        print $b ? qq{BOUND\n} : qq{refused $!\n}; $b or exit 1; \
        listen($s,1) or die; open(my $m,q{>},$ARGV[1]) or die; close $m; \
        accept(my $c,$s) or die; my $d; sysread($c,$d,64) or die; print qq{got-$d}";
    // The control runs the same bind and listen unconfined, then exits: it
    // must not also accept, or it would block forever, with no client ever
    // to serve it.
    let ctl = "use Socket; socket(my $s,PF_INET,SOCK_STREAM,0) or die; \
        my $b = bind($s, sockaddr_in($ARGV[0], inet_aton(q{127.0.0.1}))); \
        print $b ? qq{BOUND\n} : qq{refused $!\n}; $b or exit 1; \
        listen($s,1) or die";
    let cp = free_port();
    let c = control(ctl, &[&cp.to_string()]);
    assert!(
        c.status.success() && String::from_utf8_lossy(&c.stdout).contains("BOUND"),
        "control should bind freely: {:?} {}",
        c.status,
        String::from_utf8_lossy(&c.stdout)
    );
    let marker = t.ws.join("bound");
    let spec = t.spec_ports(
        &[PERL, "-e", script, &p.to_string(), marker.to_str().unwrap()],
        &[p],
        &[],
        &[],
    );
    if !ports_conformed() {
        refused_unconformed(&spec);
        return;
    }
    let child = Seatbelt::new().spawn(&spec, witness()).unwrap();
    wait_for(&marker, "the confined bind");
    let mut conn = std::net::TcpStream::connect(("127.0.0.1", p)).unwrap();
    conn.write_all(b"ping\n").unwrap();
    drop(conn);
    let e = child.wait();
    assert_eq!(
        out(&e),
        "BOUND\ngot-ping\n",
        "{}",
        String::from_utf8_lossy(&e.stderr)
    );
    confirmed(&e);
}

/// `ports-bind-ungranted`: a bind to a free but ungranted port fails with
/// `EPERM`, so the refusal is the profile's, not a busy port's.
#[test]
fn ft_ports_bind_ungranted_port_is_refused() {
    let t = Tree::new("bind-ungranted");
    let q = free_port();
    let script = "use Socket; socket(my $s,PF_INET,SOCK_STREAM,0) or die; print bind($s, sockaddr_in($ARGV[0], inet_aton(q{127.0.0.1}))) ? qq{BOUND\\n} : qq{refused $!\\n}";
    let c = control(script, &[&q.to_string()]);
    assert!(
        String::from_utf8_lossy(&c.stdout).contains("BOUND"),
        "control should bind freely"
    );
    // No grant at all: every bind is refused.
    let spec = t.spec_ports(&[PERL, "-e", script, &q.to_string()], &[], &[], &[]);
    if !ports_conformed() {
        refused_unconformed(&spec);
        return;
    }
    let e = run(&spec);
    assert_eq!(out(&e), "refused Operation not permitted\n", "{}", out(&e));
    confirmed(&e);
}

/// `ports-wildcard-no-lan`: binding `0.0.0.0:<granted>` is refused without
/// a LAN grant — the key measurement that `localhost:<p>` expresses a
/// loopback-only rule and does not admit the whole interface.
#[test]
fn ft_ports_bind_wildcard_address_is_refused_without_lan() {
    let t = Tree::new("wildcard-no-lan");
    let p = free_port();
    let script = "use Socket; socket(my $s,PF_INET,SOCK_STREAM,0) or die; print bind($s, sockaddr_in($ARGV[0], INADDR_ANY)) ? qq{BOUND\\n} : qq{refused $!\\n}";
    let c = control(script, &[&p.to_string()]);
    assert!(
        String::from_utf8_lossy(&c.stdout).contains("BOUND"),
        "control should bind the wildcard address"
    );
    let spec = t.spec_ports(&[PERL, "-e", script, &p.to_string()], &[p], &[], &[]);
    if !ports_conformed() {
        refused_unconformed(&spec);
        return;
    }
    let e = run(&spec);
    assert_eq!(out(&e), "refused Operation not permitted\n", "{}", out(&e));
    confirmed(&e);
}

/// `ports-wildcard-lan`: with the LAN grant (`lan ⊆ bind`) the wildcard
/// bind on the same port is allowed, and the listener answers on loopback.
#[test]
fn ft_ports_bind_wildcard_address_is_allowed_with_lan_grant() {
    let t = Tree::new("wildcard-lan");
    let p = free_port();
    let script = "use Socket; socket(my $s,PF_INET,SOCK_STREAM,0) or die; \
        my $b = bind($s, sockaddr_in($ARGV[0], INADDR_ANY)); \
        print $b ? qq{BOUND\\n} : qq{refused $!\\n}; $b or exit 1; \
        listen($s,1) or die; open(my $m,q{>},q{bound}) or die; close $m; \
        accept(my $c,$s) or die; print qq{accepted\\n}";
    let marker = t.ws.join("bound");
    let spec = t.spec_ports(&[PERL, "-e", script, &p.to_string()], &[p], &[], &[p]);
    if !ports_conformed() {
        refused_unconformed(&spec);
        return;
    }
    let child = Seatbelt::new().spawn(&spec, witness()).unwrap();
    wait_for(&marker, "the confined wildcard bind");
    assert!(std::net::TcpStream::connect(("127.0.0.1", p)).is_ok());
    let e = child.wait();
    assert_eq!(
        out(&e),
        "BOUND\naccepted\n",
        "{}",
        String::from_utf8_lossy(&e.stderr)
    );
    confirmed(&e);
}

/// `ports-connect-granted`: an outbound connect to a granted port is
/// allowed and arrives at the harness's listener.
#[test]
fn ft_ports_connect_to_granted_port_is_allowed() {
    let t = Tree::new("connect-granted");
    let (l, q) = held_listener();
    let script = "use Socket; socket(my $s,PF_INET,SOCK_STREAM,0) or die; print connect($s, sockaddr_in($ARGV[0], inet_aton(q{127.0.0.1}))) ? qq{CONNECTED\\n} : qq{refused $!\\n}; select(undef,undef,undef,1)";
    let c = control(script, &[&q.to_string()]);
    assert!(
        String::from_utf8_lossy(&c.stdout).contains("CONNECTED"),
        "control should connect"
    );
    drain(&l);
    let spec = t.spec_ports(&[PERL, "-e", script, &q.to_string()], &[], &[q], &[]);
    if !ports_conformed() {
        refused_unconformed(&spec);
        return;
    }
    let e = run(&spec);
    assert_eq!(
        out(&e),
        "CONNECTED\n",
        "{}",
        String::from_utf8_lossy(&e.stderr)
    );
    confirmed(&e);
    assert!(saw_connection(&l), "the granted connect must arrive");
}

/// `ports-connect-ungranted`: an outbound connect to a loopback port the
/// run did not grant is refused, and the listener sees nothing.
#[test]
fn ft_ports_connect_to_ungranted_loopback_port_is_refused() {
    let t = Tree::new("connect-ungranted");
    let (l, q) = held_listener();
    let script = "use Socket; socket(my $s,PF_INET,SOCK_STREAM,0) or die; print connect($s, sockaddr_in($ARGV[0], inet_aton(q{127.0.0.1}))) ? qq{CONNECTED\\n} : qq{refused $!\\n}";
    let c = control(script, &[&q.to_string()]);
    assert!(
        String::from_utf8_lossy(&c.stdout).contains("CONNECTED"),
        "control should connect"
    );
    drain(&l);
    let spec = t.spec_ports(&[PERL, "-e", script, &q.to_string()], &[], &[], &[]);
    if !ports_conformed() {
        refused_unconformed(&spec);
        return;
    }
    let e = run(&spec);
    assert_eq!(out(&e), "refused Operation not permitted\n", "{}", out(&e));
    confirmed(&e);
    assert!(
        !saw_connection(&l),
        "an ungranted connect must never arrive"
    );
}

/// `ports-model-server` (INV-41): a connect to the model server's port —
/// reserved in the backend and denied last in the profile — is refused,
/// and the listener sees no connection. The reserved port is also never
/// grantable (validate refuses it), so this measures the profile's final
/// deny end to end.
#[test]
fn ft_ports_connect_to_model_server_port_is_refused() {
    let t = Tree::new("model-server");
    let (l, m) = held_listener();
    let script = "use Socket; socket(my $s,PF_INET,SOCK_STREAM,0) or die; print connect($s, sockaddr_in($ARGV[0], inet_aton(q{127.0.0.1}))) ? qq{CONNECTED\\n} : qq{refused $!\\n}";
    let c = control(script, &[&m.to_string()]);
    assert!(
        String::from_utf8_lossy(&c.stdout).contains("CONNECTED"),
        "control should connect"
    );
    drain(&l);
    let spec = t.spec_ports(&[PERL, "-e", script, &m.to_string()], &[], &[], &[]);
    if !ports_conformed() {
        refused_unconformed(&spec);
        return;
    }
    let e = run_reserved(&spec, &[m]);
    assert_eq!(out(&e), "refused Operation not permitted\n", "{}", out(&e));
    confirmed(&e);
    assert!(!saw_connection(&l), "the model server saw a connection");
}

/// `ports-keep-ft1-ft11-ft15`: under a port profile, outbound to routable
/// addresses, unix sockets (outside AND inside the workspace) and the
/// resolver stay refused (FT-1, FT-11, FT-15 unchanged).
#[test]
fn ft_ports_outbound_routable_unix_and_dns_still_refused() {
    let t = Tree::new_short("keep-fts");
    let p = free_port();
    let lo = std::os::unix::net::UnixListener::bind(t.outside.join("s.sock")).unwrap();
    let li = std::os::unix::net::UnixListener::bind(t.ws.join("s.sock")).unwrap();
    lo.set_nonblocking(true).unwrap();
    li.set_nonblocking(true).unwrap();
    // Control: the unix connect works unconfined.
    let ctl = "use Socket; socket(my $s,PF_UNIX,SOCK_STREAM,0) or die; print connect($s, pack_sockaddr_un($ARGV[0])) ? qq{CONNECTED\\n} : qq{refused\\n}";
    assert_eq!(
        String::from_utf8_lossy(
            &control(ctl, &[t.outside.join("s.sock").to_str().unwrap()]).stdout
        ),
        "CONNECTED\n"
    );
    let script = "use Socket; \
        socket(my $r,PF_INET,SOCK_STREAM,0) or die; print connect($r, sockaddr_in(80, inet_aton(q{192.0.2.1}))) ? qq{ROUTED\\n} : qq{routed $!\\n}; \
        socket(my $u,PF_UNIX,SOCK_STREAM,0) or die; print connect($u, pack_sockaddr_un($ARGV[0])) ? qq{UNIX\\n} : qq{unix\\n}; \
        socket(my $v,PF_UNIX,SOCK_STREAM,0) or die; print connect($v, pack_sockaddr_un($ARGV[1])) ? qq{UNIX\\n} : qq{unix\\n}; \
        my @a = gethostbyname(q{apple.com}); print @a ? qq{RESOLVED\\n} : qq{dns\\n}";
    let spec = t.spec_ports(
        &[
            PERL,
            "-e",
            script,
            t.outside.join("s.sock").to_str().unwrap(),
            t.ws.join("s.sock").to_str().unwrap(),
        ],
        &[p],
        &[p],
        &[],
    );
    if !ports_conformed() {
        refused_unconformed(&spec);
        return;
    }
    let e = run(&spec);
    assert_eq!(
        out(&e),
        "routed Operation not permitted\nunix\nunix\ndns\n",
        "{}",
        String::from_utf8_lossy(&e.stderr)
    );
    confirmed(&e);
    assert!(
        lo.accept().is_err() && li.accept().is_err(),
        "a unix connect arrived"
    );
}

/// `ports-udp`: a UDP bind on a TCP-granted port is refused — the grants
/// name `tcp` only.
#[test]
fn ft_ports_udp_bind_refused() {
    let t = Tree::new("udp");
    let p = free_port();
    let script = "use Socket; socket(my $u,PF_INET,SOCK_DGRAM,0) or die; print bind($u, sockaddr_in($ARGV[0], inet_aton(q{127.0.0.1}))) ? qq{BOUND\\n} : qq{refused $!\\n}";
    let c = control(script, &[&p.to_string()]);
    assert!(
        String::from_utf8_lossy(&c.stdout).contains("BOUND"),
        "control should bind UDP"
    );
    // The same port, granted for TCP, must not carry a UDP listener.
    let spec = t.spec_ports(&[PERL, "-e", script, &p.to_string()], &[p], &[], &[]);
    if !ports_conformed() {
        refused_unconformed(&spec);
        return;
    }
    let e = run(&spec);
    assert_eq!(out(&e), "refused Operation not permitted\n", "{}", out(&e));
    confirmed(&e);
}

/// The measurement the design note names beside the cases: whether the
/// `localhost:<p>` form covers IPv6 loopback (`::1`) too, and whether
/// `/private/etc/hosts` is readable (so `localhost` resolves) inside a
/// port profile. The outcome is recorded in `docs/slices/P-36a.md`; this
/// test pins what this host showed, loudly, so a macOS change is noticed.
/// On a host whose row lacks the port cases it pins the designed refusal
/// instead.
#[test]
fn measured_localhost_ipv6_and_hosts_file_under_port_profile() {
    let t = Tree::new("measure-v6");
    let p = free_port();
    let v6 = "use Socket; socket(my $s,PF_INET6,SOCK_STREAM,0) or die; print bind($s, sockaddr_in6($ARGV[0], inet_pton(AF_INET6,q{::1}))) ? qq{BOUND6\\n} : qq{bind6 $!\\n}";
    let spec = t.spec_ports(&[PERL, "-e", v6, &p.to_string()], &[p], &[], &[]);
    if !ports_conformed() {
        refused_unconformed(&spec);
        return;
    }
    let e = run(&spec);
    let ipv6 = out(&e).trim().to_string();
    let hosts = "my $sz = -s q{/private/etc/hosts}; print qq{hosts-}, ($sz // q{no}), qq{\\n}; my @h = gethostbyname(q{localhost}); print (@h ? qq{resolved\\n} : qq{unresolved\\n})";
    let e = run(&t.spec_ports(&[PERL, "-e", hosts, &p.to_string()], &[p], &[], &[]));
    eprintln!(
        "P-36a measurement (this host): ::1 bind under the localhost profile = {ipv6:?}; {}",
        out(&e).trim().replace('\n', "; ")
    );
    assert!(
        out(&e).starts_with("hosts-"),
        "the hosts-file probe must report"
    );
    confirmed(&e);
}
