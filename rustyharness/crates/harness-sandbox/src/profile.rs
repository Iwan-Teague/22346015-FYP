//! The macOS Seatbelt (SBPL) profile for one confined call (design §6.3).
//!
//! Pure text generation from a [`Validated`] spec, so it is built and
//! tested on every OS. The shape is `(deny default)` with explicit allows;
//! later rules override earlier ones (measured, E6), so the protected
//! overlays, the FIFO rule and the network deny come last.
//!
//! What a confined process gets besides its roots, and why:
//! - `process-fork`; `process-exec` of the stub interpreter, the system
//!   binary directories and the roots (toolchains, build outputs). The
//!   power of system tools such as `open` or `security` lies in mach
//!   services, and **no** `mach-lookup` is allowed (FT-17, FT-18).
//! - `signal` only to processes of the same sandbox instance: the domain
//!   stub's sweep relies on the kernel refusing every other target.
//! - `process-info*` on itself; `sysctl-read`.
//! - Reads of `/` itself (bash aborts without it, E2), the system trees
//!   `/usr`, `/System`, `/bin`, `/private/var/select` (the `/bin/sh`
//!   variant link), and the character devices null, zero, random,
//!   urandom. Metadata (not contents) of each root's ancestors, so path
//!   resolution works; nothing else of `$HOME` or `/private/tmp` or
//!   `/private/var/folders` is visible.
//! - Writes to the read-write roots and `/dev/null`.
//! - Then: `deny file-write*` on protected paths (FT-9); `deny file-read*
//!   file-write*` on FIFOs anywhere (the OD-5 draft's FT-27: a FIFO in a
//!   granted root is otherwise a channel); `deny network*`: no connect, no
//!   bind, no listen, no unix-socket connect (FT-1, FT-11, FT-15, D31).
//! - Port grants (P-36a, §4.3) come AFTER that deny, because later rules
//!   win (measured, E6): `network-bind`/`network-inbound` per granted
//!   port (`localhost:<p>`, or `*:<p>` for the LAN members) and
//!   `network-outbound` per connect port.
//! - With a [`Network::Proxy`][crate::spec::Network::Proxy] grant, one
//!   allow after the grants: `network-outbound` to `localhost:<port>` and
//!   nothing else — the harness's loopback pump port (§5.3; spelling
//!   measured on this host, SBPL refuses a numeric host in
//!   `(remote ip ...)`). The fetcher dials `127.0.0.1:<port>` (§5.2);
//!   every other loopback port, IPv6 loopback, the resolver and bind stay
//!   denied (FT-13-proxy, FT-15-proxy, FT-19, FT-20).
//! - Last of all, one final `deny network*` per reserved port (the model
//!   port at least, INV-41), so even a renderer bug that let a reserved
//!   port into a grant is overridden. With `Network::None` (and no
//!   reserved ports) none of this renders: the profile is byte-identical
//!   to the pre-ports one (golden test).

use crate::spec::{policy_safe, Ports, Validated};

/// A path that should have been `policy_safe` reached profile rendering. It
/// cannot happen after [`crate::spec::validate`] (which refuses such paths),
/// so this is a fail-closed guard, not an expected error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("profile render refused an unsafe path: {0:?}")]
pub struct UnsafePath(pub String);

/// The interpreter of the domain stub (see `confine_spawn`).
pub const STUB_INTERPRETER: &str = "/usr/bin/perl";

/// System directories whose binaries may be executed.
pub const SYSTEM_EXEC: &[&str] = &["/bin", "/usr/bin", "/usr/sbin", "/usr/libexec"];

/// System trees that may be read.
pub const SYSTEM_READ: &[&str] = &["/usr", "/System", "/bin", "/private/var/select"];

/// Devices that may be read.
pub const DEVICES_READ: &[&str] = &["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"];

/// Version tag of the generated profile (part of the probe digest).
pub const PROFILE_VERSION: &str = "rh-seatbelt/1";

fn q(s: &str) -> Result<String, UnsafePath> {
    // Every path reaching here passed `policy_safe` (validate refuses the
    // rest). This re-check is a real guard in every build, not a
    // `debug_assert!` the release build skips (LOW-5): a path that is not
    // safe to quote is refused rather than written into policy text.
    if !policy_safe(s) {
        return Err(UnsafePath(s.to_string()));
    }
    Ok(format!("\"{s}\""))
}

fn ancestors(root: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = root;
    while let Some(i) = cur.rfind('/') {
        cur = &cur[..i];
        if cur.is_empty() {
            break;
        }
        out.push(cur.to_string());
    }
    out
}

/// The profile text for the validated spec `v` with its approved port
/// grants `ports`, the reserved ports `reserved` no rule may allow, and
/// the proxy overlay for `proxy_port` (the granted pump port of a
/// [`Network::Proxy`][crate::spec::Network::Proxy] spec; `None` adds
/// nothing). The caller passes the port and grants only of a spec
/// [`crate::spec::validate`] accepted. `Err` only if a path is not safe
/// to quote, which validate already refuses, so in practice this is
/// infallible; returning a `Result` keeps the guard real in release builds
/// (LOW-5) instead of a skipped `debug_assert!`.
pub fn render(
    v: &Validated,
    ports: &Ports,
    reserved: &[u16],
    proxy_port: Option<u16>,
) -> Result<String, UnsafePath> {
    let mut p = String::new();
    p.push_str(&format!(
        "(version 1)\n; {PROFILE_VERSION}\n(deny default)\n"
    ));
    p.push_str("(allow process-fork)\n");
    p.push_str(&format!(
        "(allow process-exec (literal {})",
        q(STUB_INTERPRETER)?
    ));
    for d in SYSTEM_EXEC {
        p.push_str(&format!(" (subpath {})", q(d)?));
    }
    for r in v.read_only.iter().chain(v.read_write.iter()) {
        p.push_str(&format!(" (subpath {})", q(r)?));
    }
    p.push_str(")\n");
    p.push_str("(allow signal (target same-sandbox))\n");
    p.push_str("(allow process-info* (target self))\n");
    p.push_str("(allow sysctl-read)\n");
    p.push_str("(allow file-read* (literal \"/\")");
    for d in SYSTEM_READ {
        p.push_str(&format!(" (subpath {})", q(d)?));
    }
    for d in DEVICES_READ {
        p.push_str(&format!(" (literal {})", q(d)?));
    }
    for r in v.read_only.iter().chain(v.read_write.iter()) {
        p.push_str(&format!(" (subpath {})", q(r)?));
    }
    p.push_str(")\n");
    let mut anc: Vec<String> = v
        .read_only
        .iter()
        .chain(v.read_write.iter())
        .flat_map(|r| ancestors(r))
        .collect();
    anc.sort();
    anc.dedup();
    if !anc.is_empty() {
        p.push_str("(allow file-read-metadata");
        for a in &anc {
            p.push_str(&format!(" (literal {})", q(a)?));
        }
        p.push_str(")\n");
    }
    p.push_str("(allow file-write-data (literal \"/dev/null\"))\n");
    if !v.read_write.is_empty() {
        p.push_str("(allow file-write*");
        for r in &v.read_write {
            p.push_str(&format!(" (subpath {})", q(r)?));
        }
        p.push_str(")\n");
    }
    for pr in &v.protected {
        p.push_str(&format!("(deny file-write* (subpath {}))\n", q(pr)?));
    }
    p.push_str("(deny file-read* file-write* (vnode-type FIFO))\n");
    p.push_str("(deny network*)\n");
    // The port grants (§4.3): AFTER the deny, because later rules win
    // (measured, E6). Ports are plain decimal numbers, so nothing here can
    // carry an unsafe path. The loopback-only form (`localhost:<p>`) is
    // what the port probe measures first (P-36a): whether it covers ::1
    // and refuses a wildcard bind is recorded on the host that mints the
    // port cases, and a wildcard bind is allowed only for the lan members.
    for port in &ports.bind {
        if ports.lan.contains(port) {
            continue;
        }
        p.push_str(&format!(
            "(allow network-bind network-inbound (local tcp \"localhost:{port}\"))\n"
        ));
    }
    for port in &ports.lan {
        p.push_str(&format!(
            "(allow network-bind network-inbound (local tcp \"*:{port}\"))\n"
        ));
    }
    for port in &ports.connect {
        p.push_str(&format!(
            "(allow network-outbound (remote tcp \"localhost:{port}\"))\n"
        ));
    }
    // The proxy overlay (§5.3): the granted pump port, spelled `localhost`
    // (SBPL refuses a numeric host in `(remote ip ...)`, measured on this
    // host). Only loopback outbound opens; bind stays denied.
    if let Some(port) = proxy_port {
        p.push_str(&format!(
            "(allow network-outbound (remote ip \"localhost:{port}\"))\n"
        ));
    }
    // The reserved-port backstop (§4.3): LAST, so a renderer bug that let
    // a reserved port into a grant is overridden by a later deny (INV-41).
    for m in reserved {
        p.push_str(&format!(
            "(deny network* (remote tcp \"localhost:{m}\") (local tcp \"*:{m}\"))\n"
        ));
    }
    Ok(p)
}

/// The profile text for the file-op helper instance (P-36d, §7.1): one
/// fork-less perl serving `rh-fileop/1` requests against the workspace.
/// Differences from [`render`], each load-bearing:
///
/// - **No `process-fork`.** The helper forks nothing, so a fork is
///   impossible twice over (the stub never calls it, the kernel refuses
///   it); the instance holds exactly one process by construction.
/// - **`process-exec` of the stub interpreter ONLY.** The helper never
///   launches another program, so no system or root subpath is executable.
/// - **No `signal` allow.** The start canary needs `signal 0` to the
///   parent to fail with `EPERM`, and the helper never signals anything.
/// - Reads are as broad as a confined call's (the kernel view is a write
///   view); writes land only on the read-write roots (none at all for a
///   read-only session) and `/dev/null`.
/// - Protected overlays, FIFOs and the network are denied last, as in
///   [`render`]. No port grant ever renders here: the helper asks for
///   `Network::None`.
pub fn render_fileop(v: &Validated) -> Result<String, UnsafePath> {
    let mut p = String::new();
    p.push_str(&format!(
        "(version 1)\n; {PROFILE_VERSION}\n(deny default)\n"
    ));
    p.push_str(&format!(
        "(allow process-exec (literal {}))\n",
        q(STUB_INTERPRETER)?
    ));
    p.push_str("(allow process-info* (target self))\n");
    p.push_str("(allow sysctl-read)\n");
    p.push_str("(allow file-read* (literal \"/\")");
    for d in SYSTEM_READ {
        p.push_str(&format!(" (subpath {})", q(d)?));
    }
    for d in DEVICES_READ {
        p.push_str(&format!(" (literal {})", q(d)?));
    }
    for r in v.read_only.iter().chain(v.read_write.iter()) {
        p.push_str(&format!(" (subpath {})", q(r)?));
    }
    p.push_str(")\n");
    let mut anc: Vec<String> = v
        .read_only
        .iter()
        .chain(v.read_write.iter())
        .flat_map(|r| ancestors(r))
        .collect();
    anc.sort();
    anc.dedup();
    if !anc.is_empty() {
        p.push_str("(allow file-read-metadata");
        for a in &anc {
            p.push_str(&format!(" (literal {})", q(a)?));
        }
        p.push_str(")\n");
    }
    p.push_str("(allow file-write-data (literal \"/dev/null\"))\n");
    if !v.read_write.is_empty() {
        p.push_str("(allow file-write*");
        for r in &v.read_write {
            p.push_str(&format!(" (subpath {})", q(r)?));
        }
        p.push_str(")\n");
    }
    for pr in &v.protected {
        p.push_str(&format!("(deny file-write* (subpath {}))\n", q(pr)?));
    }
    p.push_str("(deny file-read* file-write* (vnode-type FIFO))\n");
    p.push_str("(deny network*)\n");
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::Limits;
    use std::time::Duration;

    fn v() -> Validated {
        Validated {
            argv: vec![b"/bin/echo".to_vec()],
            env: vec![],
            cwd: "/w/ws".into(),
            read_only: vec!["/opt/tool".into()],
            read_write: vec!["/w/ws".into()],
            protected: vec!["/w/ws/.git".into()],
            limits: Limits::wall(Duration::from_secs(1)),
        }
    }

    fn render_none(f: &Validated) -> String {
        render(f, &Ports::default(), &[], None).unwrap()
    }

    #[test]
    fn network_none_profile_unchanged_byte_for_byte() {
        // Golden: with no port grant and no reserved port, the profile is
        // byte-identical to the pre-ports renderer, so every exec profile
        // and the live probe digest are unchanged (§4.3).
        let want = "(version 1)\n\
                    ; rh-seatbelt/1\n\
                    (deny default)\n\
                    (allow process-fork)\n\
                    (allow process-exec (literal \"/usr/bin/perl\") (subpath \"/bin\") (subpath \"/usr/bin\") (subpath \"/usr/sbin\") (subpath \"/usr/libexec\") (subpath \"/opt/tool\") (subpath \"/w/ws\"))\n\
                    (allow signal (target same-sandbox))\n\
                    (allow process-info* (target self))\n\
                    (allow sysctl-read)\n\
                    (allow file-read* (literal \"/\") (subpath \"/usr\") (subpath \"/System\") (subpath \"/bin\") (subpath \"/private/var/select\") (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/random\") (literal \"/dev/urandom\") (subpath \"/opt/tool\") (subpath \"/w/ws\"))\n\
                    (allow file-read-metadata (literal \"/opt\") (literal \"/w\"))\n\
                    (allow file-write-data (literal \"/dev/null\"))\n\
                    (allow file-write* (subpath \"/w/ws\"))\n\
                    (deny file-write* (subpath \"/w/ws/.git\"))\n\
                    (deny file-read* file-write* (vnode-type FIFO))\n\
                    (deny network*)\n";
        assert_eq!(render_none(&v()), want);
    }

    #[test]
    fn deny_default_with_overrides_last() {
        let p = render_none(&v());
        assert!(p.contains("(deny default)"));
        assert!(!p.contains("(allow default)"));
        assert!(!p.contains("mach-lookup"));
        assert!(!p.contains("network-bind") && !p.contains("(allow network"));
        let w = p.find("(allow file-write* (subpath \"/w/ws\"))").unwrap();
        let pr = p
            .find("(deny file-write* (subpath \"/w/ws/.git\"))")
            .unwrap();
        let fifo = p.find("(vnode-type FIFO)").unwrap();
        let net = p.find("(deny network*)").unwrap();
        assert!(w < pr && pr < fifo && fifo < net);
        assert!(p.ends_with("(deny network*)\n"));
        assert!(p.contains("(allow signal (target same-sandbox))"));
    }

    #[test]
    fn read_only_roots_are_not_writable_and_ancestors_are_metadata_only() {
        let p = render_none(&v());
        assert!(!p.contains("(allow file-write* (subpath \"/opt/tool\")"));
        assert!(p.contains("(allow file-read-metadata (literal \"/opt\") (literal \"/w\"))"));
        assert_eq!(
            ancestors("/a/b/c"),
            vec!["/a/b".to_string(), "/a".to_string()]
        );
    }

    #[test]
    fn an_unsafe_path_is_refused_in_every_build_not_only_debug() {
        // `Validated` should never carry such a path (validate refuses it),
        // but if one reached render it must be an error, not silently quoted
        // into policy text nor a release-build no-op (LOW-5).
        assert_eq!(q("/a b/c").unwrap(), "\"/a b/c\"");
        assert!(matches!(q("/a\"b"), Err(UnsafePath(_))));
        let mut bad = v();
        bad.read_write.push("/w/ws/a\"b".to_string());
        assert!(matches!(
            render(&bad, &Ports::default(), &[], None),
            Err(UnsafePath(_))
        ));
    }

    #[test]
    fn render_puts_port_allows_after_network_deny_and_reserved_deny_last() {
        // 5173 is loopback-only, 8000 is the LAN member (a `*` rule, and no
        // `localhost` allow of its own), 5173 is also a connect target, and
        // 11434 stands in for the model port: its deny is the last rule of
        // the whole profile (§4.3, INV-41).
        let ports = Ports {
            bind: vec![5173, 8000],
            connect: vec![5173],
            lan: vec![8000],
        };
        let p = render(&v(), &ports, &[11434], None).unwrap();
        let net = p.find("(deny network*)\n").unwrap();
        let bind5173 = p
            .find("(allow network-bind network-inbound (local tcp \"localhost:5173\"))\n")
            .unwrap();
        let bind8000 = p
            .find("(allow network-bind network-inbound (local tcp \"*:8000\"))\n")
            .unwrap();
        let out5173 = p
            .find("(allow network-outbound (remote tcp \"localhost:5173\"))\n")
            .unwrap();
        let deny11434 = p
            .find("(deny network* (remote tcp \"localhost:11434\") (local tcp \"*:11434\"))\n")
            .unwrap();
        assert!(net < bind5173 && bind5173 < bind8000 && bind8000 < out5173 && out5173 < deny11434);
        assert!(
            p.ends_with(
                "(deny network* (remote tcp \"localhost:11434\") (local tcp \"*:11434\"))\n"
            ),
            "the reserved deny is the profile's last rule"
        );
        // The lan member never gets a loopback allow of its own, and the
        // reserved port is never allowed in any list.
        assert!(!p.contains("(local tcp \"localhost:8000\")"));
        assert!(!p.contains(":11434\"))\n(allow"));
        // Multiple reserved ports each get their final deny.
        let p = render(&v(), &ports, &[11434, 9999], None).unwrap();
        assert!(
            p.contains("(deny network* (remote tcp \"localhost:9999\") (local tcp \"*:9999\"))\n")
        );
        assert!(
            p.find("(deny network* (remote tcp \"localhost:9999\")")
                .unwrap()
                > p.find("(deny network* (remote tcp \"localhost:11434\")")
                    .unwrap(),
            "reserved denies follow the grants"
        );
    }

    #[test]
    fn proxy_profile_allows_only_the_granted_loopback_port() {
        // Golden suffix: the deny stays, and exactly one allow follows it —
        // the pump's port, spelled `localhost` (SBPL refuses a numeric host
        // in `(remote ip ...)`, measured on this host; §5.3).
        let p = render(&v(), &Ports::default(), &[], Some(8080)).unwrap();
        assert!(
            p.ends_with(
                "(deny network*)\n\
                 (allow network-outbound (remote ip \"localhost:8080\"))\n"
            ),
            "{p}"
        );
        assert_eq!(p.matches("(allow network").count(), 1);
        assert!(!p.contains("(allow network-bind"));
        // Without a grant the profile renders byte-identically to the
        // deny-all form (the P-36 convention).
        let p = render_none(&v());
        assert!(p.ends_with("(deny network*)\n"));
        assert!(!p.contains("(allow network"));
    }

    #[test]
    fn proxy_profile_keeps_deny_network_before_the_allow() {
        let p = render(&v(), &Ports::default(), &[], Some(8123)).unwrap();
        let deny = p.find("(deny network*)").unwrap();
        let allow = p
            .find("(allow network-outbound (remote ip \"localhost:8123\"))")
            .unwrap();
        assert!(deny < allow);
    }

    // --- render_fileop (P-36d, §7.1) -------------------------------------

    #[test]
    fn fileop_profile_is_deny_default_with_one_exec_and_no_fork() {
        let p = render_fileop(&v()).unwrap();
        assert!(p.starts_with("(version 1)\n; rh-seatbelt/1\n(deny default)\n"));
        // Fork-less twice over: the stub never calls it and the kernel
        // refuses it, so the instance is exactly one process.
        assert!(!p.contains("process-fork"));
        // The helper never signals: the start canary needs the refusal.
        assert!(!p.contains("(allow signal"));
        let exec = p
            .find("(allow process-exec")
            .map(|at| p[at..].lines().next().unwrap().to_string());
        assert_eq!(
            exec.as_deref(),
            Some("(allow process-exec (literal \"/usr/bin/perl\"))"),
            "only the stub interpreter is executable: no system or root subpath"
        );
        assert!(p.contains("(allow process-info* (target self))\n"));
        assert!(p.contains("(allow sysctl-read)\n"));
        assert!(p.contains("(allow file-read* (literal \"/\")"));
        assert!(p.contains("(allow file-write* (subpath \"/w/ws\"))\n"));
        assert!(p.contains("(allow file-write-data (literal \"/dev/null\"))\n"));
        assert!(p.contains("(allow file-read-metadata (literal \"/opt\") (literal \"/w\"))\n"));
    }

    #[test]
    fn fileop_profile_puts_the_write_denies_after_the_write_allow() {
        let p = render_fileop(&v()).unwrap();
        let w = p.find("(allow file-write* (subpath \"/w/ws\"))").unwrap();
        let pr = p
            .find("(deny file-write* (subpath \"/w/ws/.git\"))")
            .unwrap();
        let fifo = p.find("(vnode-type FIFO)").unwrap();
        let net = p.find("(deny network*)").unwrap();
        assert!(w < pr && pr < fifo && fifo < net);
        assert!(p.ends_with("(deny network*)\n"));
        assert!(!p.contains("network-bind"));
        assert!(!p.contains("network-outbound"));
        assert!(!p.contains("mach-lookup"));
    }

    #[test]
    fn fileop_readonly_profile_grants_no_write_root_at_all() {
        let mut ro = v();
        ro.read_write.clear();
        ro.read_only.push("/w/ws".into());
        ro.protected.clear();
        let p = render_fileop(&ro).unwrap();
        assert!(!p.contains("(allow file-write*"));
        assert!(p.contains("(allow file-read* (literal \"/\") (subpath \"/usr\")"));
        assert!(p.contains("(subpath \"/w/ws\"))"));
        // Read roots still get their ancestors as metadata-only.
        assert!(p.contains("(literal \"/w\"))"));
    }

    #[test]
    fn fileop_profile_refuses_an_unsafe_path_like_the_exec_one() {
        let mut bad = v();
        bad.read_write.push("/w/ws/a\"b".to_string());
        assert!(matches!(render_fileop(&bad), Err(UnsafePath(_))));
    }
}
