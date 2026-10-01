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

use crate::spec::{policy_safe, Validated};

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

fn q(s: &str) -> String {
    // Every path reaching here passed `policy_safe` (validate refuses the
    // rest); the assertion keeps a future caller honest.
    debug_assert!(policy_safe(s));
    format!("\"{s}\"")
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

/// The profile text for `v`.
pub fn render(v: &Validated) -> String {
    let mut p = String::new();
    p.push_str(&format!(
        "(version 1)\n; {PROFILE_VERSION}\n(deny default)\n"
    ));
    p.push_str("(allow process-fork)\n");
    p.push_str(&format!(
        "(allow process-exec (literal {})",
        q(STUB_INTERPRETER)
    ));
    for d in SYSTEM_EXEC {
        p.push_str(&format!(" (subpath {})", q(d)));
    }
    for r in v.read_only.iter().chain(v.read_write.iter()) {
        p.push_str(&format!(" (subpath {})", q(r)));
    }
    p.push_str(")\n");
    p.push_str("(allow signal (target same-sandbox))\n");
    p.push_str("(allow process-info* (target self))\n");
    p.push_str("(allow sysctl-read)\n");
    p.push_str("(allow file-read* (literal \"/\")");
    for d in SYSTEM_READ {
        p.push_str(&format!(" (subpath {})", q(d)));
    }
    for d in DEVICES_READ {
        p.push_str(&format!(" (literal {})", q(d)));
    }
    for r in v.read_only.iter().chain(v.read_write.iter()) {
        p.push_str(&format!(" (subpath {})", q(r)));
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
            p.push_str(&format!(" (literal {})", q(a)));
        }
        p.push_str(")\n");
    }
    p.push_str("(allow file-write-data (literal \"/dev/null\"))\n");
    if !v.read_write.is_empty() {
        p.push_str("(allow file-write*");
        for r in &v.read_write {
            p.push_str(&format!(" (subpath {})", q(r)));
        }
        p.push_str(")\n");
    }
    for pr in &v.protected {
        p.push_str(&format!("(deny file-write* (subpath {}))\n", q(pr)));
    }
    p.push_str("(deny file-read* file-write* (vnode-type FIFO))\n");
    p.push_str("(deny network*)\n");
    p
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

    #[test]
    fn deny_default_with_overrides_last() {
        let p = render(&v());
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
        let p = render(&v());
        assert!(!p.contains("(allow file-write* (subpath \"/opt/tool\")"));
        assert!(p.contains("(allow file-read-metadata (literal \"/opt\") (literal \"/w\"))"));
        assert_eq!(
            ancestors("/a/b/c"),
            vec!["/a/b".to_string(), "/a".to_string()]
        );
    }
}
