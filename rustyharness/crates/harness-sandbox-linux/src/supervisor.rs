//! The process-tree supervisor of the default Linux tier (slice S-Ld,
//! docs/slices/S-L-linux-sandbox.md §1 "Process-tree containment & reliable
//! kill", FT-5/8/16/16-setsid).
//!
//! One process tree, emptied on every ending:
//!
//! ```text
//!   spawner (the harness)          keeps: control write end, out/err/status
//!     └─ helper (re-exec'd binary, read ends at fixed fds 3-6)
//!        argv: <bin> __confine <spawner pid>
//!        PR_SET_CHILD_SUBREAPER — orphaned descendants re-parent here
//!          └─ program (own process group; landlock + seccomp + rlimits +
//!             PR_SET_PDEATHSIG applied before execve)
//!               └─ whatever it forks (same group; a setsid escapee is
//!                  re-parented to the helper)
//! ```
//!
//! The helper is the sweep owner. It reads a framed [`Program`] from the
//! control pipe, forks the program into its own process group with the
//! Landlock/seccomp/rlimit domain of S-Lb/S-Lc applied before `execve`,
//! then watches two fds: the program's `pidfd` (exit) and the control pipe
//! (EOF — the kernel closes the spawner's fds on ANY death, SIGKILL
//! included). Either ending triggers the same sweep: `kill(-pgid, SIGKILL)`,
//! a `/proc` scan for processes re-parented to the helper (the subreaper
//! sees setsid escapees), SIGKILL for each, and `wait4(-1)` until a full
//! pass reaps nothing or the sweep deadline passes. A final report line on
//! the status pipe carries the raw wait status and the kill count; the
//! helper exits 0 only when the sweep confirmed an empty tree.
//!
//! Two deliberate deviations from the slice card, both fail-closed
//! simplifications (docs/slices/S-Ld.md):
//!
//! 1. `PR_SET_PDEATHSIG` is set on the PROGRAM (parent = helper), not on
//!    the helper. A self-PDEATHSIG `SIGKILL` races the control-pipe EOF and
//!    would kill the helper before it can sweep, leaking grandchildren. The
//!    control pipe is the crash detector (reliable: the kernel closes the
//!    fds of a dead process); the program's PDEATHSIG is the kernel-side
//!    backstop that ends the program even if the helper is SIGKILLed.
//! 2. The report travels on its own status pipe, not as trailing stderr
//!    bytes: stderr stays the program's output, unmixed with harness
//!    framing.
//!
//! Layering (the dependency direction forbids using harness-sandbox here):
//! the pure protocol layer — frame, report, wait-status decoding, SHA-256
//! and the bounded stream ring mirroring `harness-sandbox/src/ring.rs` —
//! compiles and is unit-tested on every OS; the process layer —
//! [`spawn`], [`helper_main`] and the `sys` wrappers — exists only on
//! Linux, on the arches whose syscall numbers are modelled (the same two
//! as `seccomp`). Every syscall goes through the raw `syscall(2)` FFI this
//! crate committed to in S-Lc; there is still no libc dependency.

// The pure protocol layer below needs only `Duration`; the process layer
// (cfg-gated) owns the rest.
use std::time::Duration;

use crate::namespaces::NetnsSpec;

#[cfg(target_os = "linux")]
use std::ffi::OsStr;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "linux")]
use std::time::Instant;

/// How long the helper may take to empty the tree once the call ended
/// (the macOS stub's sweep deadline, same value).
pub const SWEEP_DEADLINE: Duration = Duration::from_secs(3);
/// Extra wait for the last pipe bytes after the helper exited.
pub const READ_GRACE: Duration = Duration::from_secs(2);
/// The watch loop's tick (and the ppoll timeout).
pub const LIVE_TICK: Duration = Duration::from_millis(50);
/// Ring bound ceiling: the spec's `MAX_OUTPUT_BYTES`.
pub const MAX_RING_BYTES: u64 = 64 << 20;
/// Wall-clock ceiling: the spec's `MAX_WALL`.
pub const MAX_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
/// The framed spec cap: the spec's argv/env budget plus paths and slack.
const MAX_FRAME_BYTES: usize = 4 << 20;
/// Verbatim trailing bytes kept beside the ring (as in `ring.rs`).
// Only the Linux process layer pushes bytes through the ring; the ring
// stays compiled and unit-tested on every OS (see the module docs).
#[cfg_attr(not(any(test, target_os = "linux")), expect(dead_code))]
const TAIL_BYTES: usize = 4096;

/// The control pipe's read end, as the helper execs with it.
pub const FD_CONTROL_R: i32 = 3;
/// The program's stdout, as the helper execs with it (dup'd to 1 in the
/// forked program).
pub const FD_OUT_W: i32 = 4;
/// The program's stderr (dup'd to 2 in the program).
pub const FD_ERR_W: i32 = 5;
/// The status pipe to the spawner: the hello line, then the final report.
pub const FD_STATUS_W: i32 = 6;
/// Everything at and above this number is closed before an exec.
pub const FD_LEAK_FLOOR: i32 = 7;

/// The helper's argv marker (`<bin> __confine <spawner pid>`).
pub const HELPER_ARG: &str = "__confine";

// ---- the pure protocol layer (any OS) --------------------------------------

/// The confined program, as the spawner frames it for the helper.
///
/// Plain fields by design (the S-Lb constraint): `harness-sandbox` owns the
/// validated spec and this crate cannot depend on it, so the spawner
/// converts, and the helper re-checks only shape (NUL-free, bounded) — the
/// spec validator stays the one gate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Program {
    /// The program and its arguments; `argv[0]` is the executable path.
    pub argv: Vec<Vec<u8>>,
    /// The exact environment, each entry `NAME=VALUE`.
    pub env: Vec<Vec<u8>>,
    /// The working directory (canonical, absolute).
    pub cwd: String,
    /// Read-only filesystem roots (Landlock).
    pub read_only: Vec<String>,
    /// Read-write filesystem roots (Landlock).
    pub read_write: Vec<String>,
    /// Protected roots (Landlock, read-only).
    pub protected: Vec<String>,
    /// The rlimits the program runs under.
    pub limits: Limits,
    /// The namespace tier (S-Lj): when `Some`, the helper forks an nsprep
    /// that unshares userns/netns/pidns/ipc and execs the program as the
    /// namespace's PID 1, with the relay at the given directory. `None` is
    /// the default (no-namespace) tier.
    pub netns: Option<NetnsSpec>,
}

/// The rlimits of a [`Program`]. The wall clock is not here: it is the
/// spawner's control-pipe deadline, enforced outside the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Limits {
    /// CPU time (`RLIMIT_CPU`; `SIGXCPU` at the soft limit).
    pub cpu: Option<Duration>,
    /// Largest file the program may write (`RLIMIT_FSIZE`; `SIGXFSZ`).
    pub file_size: Option<u64>,
    /// Address-space budget (`RLIMIT_AS`).
    pub memory: Option<u64>,
    /// Process count (`RLIMIT_NPROC`) — best effort: it is per-user, so the
    /// sweep stays the real containment.
    pub processes: Option<u32>,
}

/// How the program ended, decoded from a raw `wait4` status integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitCause {
    /// It exited with this code.
    Exited(i32),
    /// It was ended by this signal.
    Signaled(i32),
    /// No trustworthy status (nobody could wait for the program).
    Unknown,
}

/// Decode a raw `wait4` status (or `-1` when none was ever collected).
#[must_use]
pub fn decode_wait(raw: i64) -> WaitCause {
    if raw < 0 {
        return WaitCause::Unknown;
    }
    let raw = raw & 0xff_ff;
    let sig = raw & 0x7f;
    if sig == 0 {
        WaitCause::Exited(((raw >> 8) & 0xff) as i32)
    } else {
        WaitCause::Signaled(sig as i32)
    }
}

/// Whether a program exit code names a failed setup rather than a program
/// result (fail closed: a setup failure is never mistaken for a run).
#[must_use]
pub fn is_exec_failure(code: i32) -> bool {
    (EXEC_FAIL_FLOOR..=EXEC_FAIL_CEIL).contains(&code)
}

/// The report's wire shape (the status pipe's final line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// `confirmed` (tree empty) or `unconverged`.
    pub result: String,
    /// The raw wait status, or `-1` when none was collected.
    pub status: i64,
    /// `exit` (the program ended first) or `stop` (the control pipe did).
    pub end: String,
    /// Processes the sweep killed.
    pub kills: u32,
    /// `ok`, or `failed` when the program's setup failed before `execve`.
    pub exec: String,
}

/// Find the report as the final line of `tail`; returns it and the offset
/// of its leading newline within `tail`.
#[must_use]
pub fn parse_report(tail: &[u8]) -> Option<(Report, usize)> {
    let body = tail.strip_suffix(b"\n")?;
    let marker = b"\nrh-sup/1 ";
    let at = body.windows(marker.len()).rposition(|w| w == marker)?;
    let line = std::str::from_utf8(body.get(at + 1..)?).ok()?;
    // The report is the final line: nothing may follow it.
    if line.contains('\n') {
        return None;
    }
    let mut f = line.split(' ');
    if f.next()? != "rh-sup/1" {
        return None;
    }
    let result = f.next()?.to_string();
    let status = f.next()?.strip_prefix("status=")?.parse().ok()?;
    let end = f.next()?.strip_prefix("end=")?.to_string();
    let kills = f.next()?.strip_prefix("kills=")?.parse().ok()?;
    let exec = f.next()?.strip_prefix("exec=")?.to_string();
    if f.next().is_some() {
        return None;
    }
    Some((
        Report {
            result,
            status,
            end,
            kills,
            exec,
        },
        at,
    ))
}

/// The helper's hello line: the program's pid (its process-group leader),
/// sent before any wait begins.
#[must_use]
pub fn parse_hello(tail: &[u8]) -> Option<u32> {
    let rest = tail.strip_prefix(b"pid ")?;
    let end = rest.iter().position(|b| *b == b'\n')?;
    let digits = rest.get(..end)?;
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}

/// Serialize `prog` for the control pipe (the helper's first read). `None`
/// when the program cannot be framed soundly (an interior NUL, more
/// argv/env entries than the wire's count field carries, or a frame past
/// `MAX_FRAME_BYTES` — the helper's reader drops those, so the spawner
/// refuses to emit one).
#[must_use]
pub fn frame(prog: &Program) -> Option<Vec<u8>> {
    let nul = |b: &[u8]| b.contains(&0);
    if prog.argv.iter().any(|a| nul(a))
        || prog.env.iter().any(|e| nul(e))
        || nul(prog.cwd.as_bytes())
        || prog
            .read_only
            .iter()
            .chain(&prog.read_write)
            .chain(&prog.protected)
            .any(|p| nul(p.as_bytes()))
        || prog
            .netns
            .as_ref()
            .is_some_and(|ns| nul(ns.relay_dir.as_bytes()))
        || prog.argv.len() > u16::MAX as usize
        || prog.env.len() > u16::MAX as usize
    {
        return None;
    }
    let opt = |v: Option<u64>| match v {
        Some(n) => n.to_string(),
        None => "-".to_string(),
    };
    let ms = |d: Option<Duration>| match d {
        // Zero means "no limit" on the wire; the spec validator refuses
        // zero-duration limits upstream, so no information is lost.
        Some(d) => d.as_millis().min(u64::MAX as u128) as u64,
        None => 0,
    };
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"rh-sup/1\n");
    out.extend_from_slice(
        format!(
            "lim {} {} {} {}\n",
            ms(prog.limits.cpu),
            opt(prog.limits.file_size),
            opt(prog.limits.memory),
            opt(prog.limits.processes.map(u64::from)),
        )
        .as_bytes(),
    );
    let put_bytes = |out: &mut Vec<u8>, b: &[u8]| {
        out.extend_from_slice(format!("{}\n", b.len()).as_bytes());
        out.extend_from_slice(b);
    };
    out.extend_from_slice(b"cwd ");
    put_bytes(&mut out, prog.cwd.as_bytes());
    let put_list = |out: &mut Vec<u8>, tag: &str, list: &[Vec<u8>]| {
        out.extend_from_slice(tag.as_bytes());
        out.extend_from_slice(format!(" {}\n", list.len()).as_bytes());
        for item in list {
            put_bytes(out, item);
        }
    };
    put_list(&mut out, "argv", &prog.argv);
    put_list(&mut out, "env", &prog.env);
    let strs = |list: &[String]| -> Vec<Vec<u8>> {
        list.iter()
            .map(String::as_bytes)
            .map(<[u8]>::to_vec)
            .collect()
    };
    put_list(&mut out, "ro", &strs(&prog.read_only));
    put_list(&mut out, "rw", &strs(&prog.read_write));
    put_list(&mut out, "px", &strs(&prog.protected));
    // The namespace tier (S-Lj): `net -` or a `net ns` section with the
    // relay directory and the two port grant lists.
    match &prog.netns {
        None => out.extend_from_slice(b"net -\n"),
        Some(ns) => {
            out.extend_from_slice(b"net ns\n");
            put_bytes(&mut out, ns.relay_dir.as_bytes());
            out.extend_from_slice(format!("bind {}\n", ns.bind.len()).as_bytes());
            for port in &ns.bind {
                out.extend_from_slice(format!("{port}\n").as_bytes());
            }
            out.extend_from_slice(format!("con {}\n", ns.connect.len()).as_bytes());
            for port in &ns.connect {
                out.extend_from_slice(format!("{port}\n").as_bytes());
            }
        }
    }
    if out.len() > MAX_FRAME_BYTES {
        return None;
    }
    Some(out)
}

/// A parsed [`frame`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedFrame {
    /// The framed program.
    pub program: Program,
}

/// Parse what [`frame`] wrote. Any shape deviation is a refusal.
#[must_use]
pub fn parse_frame(bytes: &[u8]) -> Option<ParsedFrame> {
    let mut r = Reader { b: bytes, at: 0 };
    if r.line()? != "rh-sup/1" {
        return None;
    }
    let lim = r.line()?;
    let mut f = lim.split(' ');
    if f.next()? != "lim" {
        return None;
    }
    let cpu_ms = f.next()?.parse::<u64>().ok()?;
    let fs = f.next()?;
    let mem = f.next()?;
    let procs = f.next()?;
    if f.next().is_some() {
        return None;
    }
    let limits = Limits {
        cpu: (cpu_ms > 0).then(|| Duration::from_millis(cpu_ms)),
        file_size: opt_u64(fs)?,
        memory: opt_u64(mem)?,
        processes: opt_u64(procs)?.and_then(|n| u32::try_from(n).ok()),
    };
    if !r.eat_tag("cwd ")? {
        return None;
    }
    let cwd = String::from_utf8(r.bytes()?.to_vec()).ok()?;
    let argv = r.list("argv")?;
    let env = r.list("env")?;
    let read_only = strings(r.list("ro")?)?;
    let read_write = strings(r.list("rw")?)?;
    let protected = strings(r.list("px")?)?;
    let netns = if r.eat_tag("net -\n")? {
        None
    } else if r.eat_tag("net ns\n")? {
        let relay_dir = String::from_utf8(r.bytes()?.to_vec()).ok()?;
        let bind = r.port_list("bind")?;
        let connect = r.port_list("con")?;
        Some(NetnsSpec {
            relay_dir,
            bind,
            connect,
        })
    } else {
        return None;
    };
    if r.at != bytes.len() {
        return None;
    }
    Some(ParsedFrame {
        program: Program {
            argv,
            env,
            cwd,
            read_only,
            read_write,
            protected,
            limits,
            netns,
        },
    })
}

fn opt_u64(s: &str) -> Option<Option<u64>> {
    match s {
        "-" => Some(None),
        n => n.parse::<u64>().ok().map(Some),
    }
}

fn strings(list: Vec<Vec<u8>>) -> Option<Vec<String>> {
    list.into_iter()
        .map(|b| String::from_utf8(b).ok())
        .collect()
}

/// The frame reader: line- and length-prefixed reads over a byte slice.
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn line(&mut self) -> Option<&str> {
        let rest = self.b.get(self.at..)?;
        let end = rest.iter().position(|c| *c == b'\n')? + self.at;
        let line = std::str::from_utf8(self.b.get(self.at..end)?).ok()?;
        self.at = end + 1;
        Some(line)
    }

    fn eat_tag(&mut self, tag: &str) -> Option<bool> {
        let t = tag.as_bytes();
        let hit = self.b.get(self.at..self.at + t.len())? == t;
        if hit {
            self.at += t.len();
        }
        Some(hit)
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.line()?.parse::<usize>().ok()?;
        let end = self.at.checked_add(n)?;
        let out = self.b.get(self.at..end)?;
        self.at = end;
        Some(out)
    }

    fn list(&mut self, tag: &str) -> Option<Vec<Vec<u8>>> {
        if !self.eat_tag(tag)? {
            return None;
        }
        // The count sits on the tag's line after exactly one space
        // (`frame` writes `tag N\n`); anything else is a refusal.
        let n = self
            .line()?
            .strip_prefix(' ')
            .and_then(|n| n.parse::<usize>().ok())?;
        let mut out = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            out.push(self.bytes()?.to_vec());
        }
        Some(out)
    }

    /// A port grant list (`tag N\n` then N decimal lines). A count beyond
    /// the spec's port budget plus slack refuses (no unbounded reads).
    fn port_list(&mut self, tag: &str) -> Option<Vec<u16>> {
        let line = self.line()?;
        let rest = line.strip_prefix(tag)?;
        let n = rest.strip_prefix(' ')?.parse::<usize>().ok()?;
        if n > 1024 {
            return None;
        }
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.line()?.parse().ok()?);
        }
        Some(out)
    }
}

// ---- SHA-256 (pure; this crate has no sha2 dependency) ---------------------

/// Minimal streaming SHA-256 (FIPS 180-4). The workspace's one SHA-256
/// implementation lives in `harness-core` (RustCrypto `sha2`), which this
/// crate cannot depend on; the digest over a stream must match it byte for
/// byte, which the test vectors below pin.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    fill: usize,
    len: u64,
}

impl Sha256 {
    /// A fresh hash.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            buf: [0u8; 64],
            fill: 0,
            len: 0,
        }
    }

    /// Feed more bytes.
    pub fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        if self.fill > 0 {
            let want = 64 - self.fill;
            let take = want.min(data.len());
            if let (Some(dst), Some(src)) = (
                self.buf.get_mut(self.fill..self.fill + take),
                data.get(..take),
            ) {
                dst.copy_from_slice(src);
            }
            self.fill += take;
            data = data.get(take..).unwrap_or(&[]);
            if self.fill == 64 {
                let block = self.buf;
                self.compress(&block);
                self.fill = 0;
            }
        }
        while data.len() >= 64 {
            let (block, rest) = data.split_at(64);
            let mut b = [0u8; 64];
            if let Some(slot) = b.get_mut(..64) {
                slot.copy_from_slice(block);
            }
            self.compress(&b);
            data = rest;
        }
        // Here `fill` is 0 unless `data` was exhausted into the partial
        // block above, so append (never restart) at the fill mark.
        if let (Some(dst), Some(src)) = (
            self.buf.get_mut(self.fill..self.fill + data.len()),
            data.get(..data.len()),
        ) {
            dst.copy_from_slice(src);
        }
        self.fill += data.len();
    }

    /// The digest of everything fed.
    #[must_use]
    pub fn finish(mut self) -> [u8; 32] {
        let bits = self.len.wrapping_mul(8);
        let mut pad = [0u8; 72];
        if let Some(first) = pad.first_mut() {
            *first = 0x80;
        }
        // Pad to 56 mod 64, then the 8 length bytes: the padding bytes are
        // not message data, so they are fed straight through `update` (the
        // addition wraps the `55 - fill` distance into range).
        let pad_len = (55 + 64 - self.fill) % 64 + 1;
        if let Some(chunk) = pad.get(..pad_len) {
            self.update(chunk);
        }
        let mut block = [0u8; 64];
        let head = self.fill;
        if let (Some(dst), Some(src)) = (block.get_mut(..head), self.buf.get(..head)) {
            dst.copy_from_slice(src);
        }
        if let Some(slot) = block.get_mut(56..64) {
            slot.copy_from_slice(&bits.to_be_bytes());
        }
        self.compress(&block);
        let mut out = [0u8; 32];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a_2f98,
            0x7137_4491,
            0xb5c0_fbcf,
            0xe9b5_dba5,
            0x3956_c25b,
            0x59f1_11f1,
            0x923f_82a4,
            0xab1c_5ed5,
            0xd807_aa98,
            0x1283_5b01,
            0x2431_85be,
            0x550c_7dc3,
            0x72be_5d74,
            0x80de_b1fe,
            0x9bdc_06a7,
            0xc19b_f174,
            0xe49b_69c1,
            0xefbe_4786,
            0x0fc1_9dc6,
            0x240c_a1cc,
            0x2de9_2c6f,
            0x4a74_84aa,
            0x5cb0_a9dc,
            0x76f9_88da,
            0x983e_5152,
            0xa831_c66d,
            0xb003_27c8,
            0xbf59_7fc7,
            0xc6e0_0bf3,
            0xd5a7_9147,
            0x06ca_6351,
            0x1429_2967,
            0x27b7_0a85,
            0x2e1b_2138,
            0x4d2c_6dfc,
            0x5338_0d13,
            0x650a_7354,
            0x766a_0abb,
            0x81c2_c92e,
            0x9272_2c85,
            0xa2bf_e8a1,
            0xa81a_664b,
            0xc24b_8b70,
            0xc76c_51a3,
            0xd192_e819,
            0xd699_0624,
            0xf40e_3585,
            0x106a_a070,
            0x19a4_c116,
            0x1e37_6c08,
            0x2748_774c,
            0x34b0_bcb5,
            0x391c_0cb3,
            0x4ed8_aa4a,
            0x5b9c_ca4f,
            0x682e_6ff3,
            0x748f_82ee,
            0x78a5_636f,
            0x84c8_7814,
            0x8cc7_0208,
            0x90be_fffa,
            0xa450_6ceb,
            0xbef9_a3f7,
            0xc671_78f2,
        ];
        let mut w = [0u32; 64];
        for (word, chunk) in w.iter_mut().zip(block.chunks_exact(4)) {
            let mut be = [0u8; 4];
            for (slot, byte) in be.iter_mut().zip(chunk.iter()) {
                *slot = *byte;
            }
            *word = u32::from_be_bytes(be);
        }
        for i in 16..64 {
            let get = |j: usize| w.get(j).copied().unwrap_or(0);
            let (m15, m2, m7, m16) = (get(i - 15), get(i - 2), get(i - 7), get(i - 16));
            let s0 = m15.rotate_right(7) ^ m15.rotate_right(18) ^ (m15 >> 3);
            let s1 = m2.rotate_right(17) ^ m2.rotate_right(19) ^ (m2 >> 10);
            if let Some(slot) = w.get_mut(i) {
                *slot = m16.wrapping_add(s0).wrapping_add(m7).wrapping_add(s1);
            }
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g0, mut h] = self.state;
        for (k, wi) in K.iter().zip(w.iter()) {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g0);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(*k)
                .wrapping_add(*wi);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g0;
            g0 = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        let add = [a, b, c, d, e, f, g0, h];
        for (slot, v) in self.state.iter_mut().zip(add) {
            *slot = slot.wrapping_add(v);
        }
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

// ---- the bounded stream ring (mirror of harness-sandbox/src/ring.rs) -------

/// How a read moves the cursor (as in `ring.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawMode {
    /// Continue from `since`.
    Next,
    /// Jump to the tail of what the ring holds.
    Tail,
}

/// One delivered read (as in `ring.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawChunk {
    /// Absolute offset of the first byte.
    pub from: u64,
    /// Cursor for the next read.
    pub to: u64,
    /// Bytes already lost to the ring bound between `since` and `from`.
    pub dropped: u64,
    /// Bytes jumped over in [`RawMode::Tail`].
    pub skipped: u64,
    /// The payload.
    pub bytes: Vec<u8>,
}

/// Per-stream totals (as in `ring.rs`), with the digest as raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawTotals {
    /// Every byte ever written to stdout.
    pub out_total: u64,
    /// SHA-256 over them.
    pub out_sha: [u8; 32],
    /// Every byte ever written to stderr.
    pub err_total: u64,
    /// SHA-256 over them.
    pub err_sha: [u8; 32],
}

/// Which stream a read names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawStream {
    /// The program's stdout.
    Out,
    /// The program's stderr.
    Err,
}

/// Move a slice end back onto a UTF-8 char boundary (as in `ring.rs`).
#[cfg_attr(not(any(test, target_os = "linux")), expect(dead_code))]
fn align_to_char_boundary(bytes: &mut Vec<u8>, from: u64) -> u64 {
    let mut keep = bytes.len();
    // The window may end inside a character: find where the last character
    // starts (at most three continuation bytes back) and, when the lead
    // byte's width outruns what the window holds, hold the tail back.
    if keep > 0 {
        let mut start = keep - 1;
        while keep - start < 4 && start > 0 {
            match bytes.get(start) {
                Some(b) if b & 0b1100_0000 == 0b1000_0000 => start -= 1,
                _ => break,
            }
        }
        let width = match bytes.get(start).copied().unwrap_or(0) {
            0xC2..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF4 => 4,
            _ => 1,
        };
        if width > 1 && keep - start < width {
            keep = start;
        }
    }
    if keep < bytes.len() {
        bytes.truncate(keep);
    }
    from + keep as u64
}

/// The window arithmetic of `ring.rs::window`, identical in behaviour:
/// `(from, to, dropped, skipped)`.
#[cfg_attr(not(any(test, target_os = "linux")), expect(dead_code))]
fn window(
    total: u64,
    ring_bytes: u64,
    since: u64,
    cap: u64,
    mode: RawMode,
) -> (u64, u64, u64, u64) {
    let since = since.min(total);
    let ring_start = total.saturating_sub(ring_bytes.min(total));
    let from0 = since.max(ring_start);
    let dropped = from0.saturating_sub(since);
    let (from, to, skipped) = match mode {
        RawMode::Next => (from0, total.min(from0.saturating_add(cap)), 0),
        RawMode::Tail => {
            let to = total;
            let from = from0.max(to.saturating_sub(cap));
            (from, to, from.saturating_sub(from0))
        }
    };
    (from, to, dropped, skipped)
}

/// A bounded circular byte ring with a running SHA-256 and a verbatim tail:
/// the shape of `ring.rs::Ring`, local to this crate because the dependency
/// direction forbids reaching harness-sandbox from here.
#[cfg_attr(not(any(test, target_os = "linux")), expect(dead_code))]
struct StreamRing {
    cap: usize,
    buf: Vec<u8>,
    head: usize,
    len: usize,
    total: u64,
    sha: Sha256,
    tail: Vec<u8>,
}

#[cfg_attr(not(any(test, target_os = "linux")), expect(dead_code))]
impl StreamRing {
    fn new(cap: u64) -> Self {
        let cap = cap.max(1) as usize;
        Self {
            cap,
            buf: vec![0u8; cap],
            head: 0,
            len: 0,
            total: 0,
            sha: Sha256::new(),
            tail: Vec::new(),
        }
    }

    fn push(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        self.total = self.total.saturating_add(data.len() as u64);
        self.sha.update(data);
        let excess = self.tail.len() + data.len();
        if excess > TAIL_BYTES {
            let cut = (excess - TAIL_BYTES).min(self.tail.len());
            self.tail.drain(..cut);
        }
        self.tail.extend_from_slice(data);

        // More data than the whole ring: only the last `cap` bytes survive.
        let data = if data.len() >= self.cap {
            self.head = 0;
            self.len = 0;
            data.get(data.len() - self.cap..).unwrap_or(&[])
        } else {
            data
        };
        let pos = (self.head + self.len) % self.cap;
        let free = self.cap - self.len;
        let fill = data.len().min(free);
        if fill > 0 {
            ring_put(&mut self.buf, pos, data.get(..fill).unwrap_or(&[]));
            self.len += fill;
        }
        let rest = data.get(fill..).unwrap_or(&[]);
        if !rest.is_empty() {
            ring_put(&mut self.buf, self.head, rest);
            self.head = (self.head + rest.len()) % self.cap;
        }
    }

    fn ring_start(&self) -> u64 {
        self.total.saturating_sub(self.len as u64)
    }

    fn total(&self) -> u64 {
        self.total
    }

    /// Absolute-offset slice `[from, to)`, clamped to what the ring holds.
    fn range(&self, from: u64, to: u64) -> Vec<u8> {
        let start = self.ring_start();
        let lo = from.max(start).min(self.total);
        let hi = to.max(lo).min(self.total);
        let mut out = Vec::with_capacity((hi - lo) as usize);
        let mut pos = (self.head + (lo - start) as usize) % self.cap;
        let mut left = (hi - lo) as usize;
        while left > 0 {
            let run = (self.cap - pos).min(left);
            match self.buf.get(pos..pos + run) {
                Some(part) => out.extend_from_slice(part),
                None => break,
            }
            pos = 0;
            left -= run;
        }
        out
    }

    /// Plan and deliver one read (§3.2): window arithmetic, a byte slice,
    /// and a UTF-8 aligned cursor.
    fn chunk(&self, since: u64, cap: usize, mode: RawMode) -> RawChunk {
        let (from, to, dropped, skipped) =
            window(self.total, self.cap as u64, since, cap as u64, mode);
        let mut bytes = self.range(from, to);
        let to = align_to_char_boundary(&mut bytes, from);
        RawChunk {
            from,
            to,
            dropped,
            skipped,
            bytes,
        }
    }
}

/// Copies `data` into `buf` starting at `start`, wrapping (as in `ring.rs`).
#[cfg_attr(not(any(test, target_os = "linux")), expect(dead_code))]
fn ring_put(buf: &mut [u8], start: usize, data: &[u8]) {
    let first = data.len().min(buf.len() - start);
    if let (Some(dst), Some(src)) = (buf.get_mut(start..start + first), data.get(..first)) {
        dst.copy_from_slice(src);
    }
    if first < data.len() {
        if let (Some(dst), Some(src)) = (buf.get_mut(..data.len() - first), data.get(first..)) {
            dst.copy_from_slice(src);
        }
    }
}

// ---- the Linux process layer ------------------------------------------------

/// The exit-code window that names a failed program setup (94 setpgid
/// missing … 102 `execve` refused; 103 the helper's own re-exec; 104..=106
/// the namespace tier's nsprep setup, S-Lj); a setup failure is never
/// mistaken for a program result.
const EXEC_FAIL_FLOOR: i32 = 94;
const EXEC_FAIL_CEIL: i32 = 106;

/// Why a spawn was refused or failed. Nothing unconfined ever ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnFail {
    /// The live options are out of range (the spec validator's bounds).
    Opts(String),
    /// A pipe or fd setup step failed before any fork.
    Pipe,
    /// The fork itself failed.
    Fork,
    /// The program shape cannot be framed (an interior NUL, say).
    Spec,
    /// This host architecture is not modelled; nothing is attempted.
    UnsupportedArch,
}

impl std::fmt::Display for SpawnFail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpawnFail::Opts(m) => write!(f, "live options refused: {m}"),
            SpawnFail::Pipe => write!(f, "the supervisor pipes could not be made"),
            SpawnFail::Fork => write!(f, "the supervisor fork failed"),
            SpawnFail::Spec => write!(f, "the program cannot be framed for the supervisor"),
            SpawnFail::UnsupportedArch => {
                write!(
                    f,
                    "this host architecture is not modelled by the supervisor"
                )
            }
        }
    }
}

impl std::error::Error for SpawnFail {}

/// A live confined call (the Linux counterpart of the macOS `Running`):
/// stream rings, the control pipe, and the sweep bookkeeping.
#[cfg(target_os = "linux")]
pub struct Running {
    /// The helper's pid (its own process group, set in its pre-exec).
    helper_pid: u32,
    /// The control pipe's write end; closing it is the stop signal.
    control: Arc<ControlWrite>,
    /// The program's streams.
    out: Arc<Mutex<StreamRing>>,
    err: Arc<Mutex<StreamRing>>,
    /// What the status-pipe reader learned.
    status: Arc<StatusRx>,
    /// Spawn time, for `elapsed`.
    started: Instant,
    /// When the wall clock closes the control pipe.
    deadline: Instant,
    /// Collected once; later waits return the same exit.
    finished: Option<RawExit>,
}

/// The control pipe's write end, closed exactly once (deadline thread,
/// `stop`, or `Drop`).
#[cfg(target_os = "linux")]
struct ControlWrite {
    fd: Mutex<Option<i32>>,
}

#[cfg(target_os = "linux")]
impl ControlWrite {
    fn close(&self) {
        let fd = self.fd.lock().ok().and_then(|mut g| g.take());
        if let Some(fd) = fd {
            sys::close(fd);
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for ControlWrite {
    fn drop(&mut self) {
        self.close();
    }
}

/// What the status-pipe reader learned.
#[cfg(target_os = "linux")]
struct StatusRx {
    /// The program's pid, from the hello line (before the report).
    child: Mutex<Option<u32>>,
    /// Set once the pipe hit EOF and the tail was parsed.
    done: AtomicBool,
    /// The parsed report, if the pipe carried one.
    report: Mutex<Option<Report>>,
}

#[cfg(target_os = "linux")]
impl StatusRx {
    fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    fn take_report(&self) -> Option<Report> {
        if !self.is_done() {
            return None;
        }
        self.report.lock().ok().and_then(|mut g| g.take())
    }

    fn pgid(&self) -> Option<u32> {
        self.child.lock().ok().and_then(|g| *g)
    }
}

/// What a [`Running`] left behind (the raw shape; `harness-sandbox` maps it
/// onto its exit vocabulary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawExit {
    /// How the program ended.
    pub outcome: WaitCause,
    /// False when the program's setup failed before `execve`.
    pub exec_ok: bool,
    /// Which ending came first.
    pub end: RawEnd,
    /// Processes the sweep killed.
    pub kills: u32,
    /// The helper confirmed an empty tree.
    pub confirmed: bool,
    /// The wall clock ran out before the program ended.
    pub timed_out: bool,
    /// What went wrong when this is not a clean stop.
    pub detail: String,
    /// Wall time from spawn to the end of cleanup.
    pub elapsed: Duration,
    /// The oldest retained bytes of stdout (at most the ring bound).
    pub stdout: Vec<u8>,
    /// Stdout was longer than the ring.
    pub stdout_truncated: bool,
    /// The oldest retained bytes of stderr.
    pub stderr: Vec<u8>,
    /// Stderr was longer than the ring.
    pub stderr_truncated: bool,
}

/// Which ending came first (the report's `end=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawEnd {
    /// The program ended before the control pipe closed.
    Exit,
    /// The control pipe closed first (wall clock or stop).
    Stop,
}

/// Start `prog` confined, supervised by `helper` (a binary that dispatches
/// [`HELPER_ARG`] to [`helper_main`]).
///
/// `ring_bytes` bounds each stream ring (1..=`MAX_RING_BYTES`); `lifetime`
/// is the wall clock (in (0, `MAX_LIFETIME`]): at the deadline the control
/// pipe closes and the helper stops the tree. Both bounds are re-checked
/// here — the spawner's validator is not reachable from this crate.
///
/// Only on Linux, on a modelled architecture; everywhere else this is not
/// even compiled (and [`SpawnFail::UnsupportedArch`] would refuse).
#[cfg(target_os = "linux")]
pub fn spawn(
    prog: &Program,
    helper: &OsStr,
    ring_bytes: u64,
    lifetime: Duration,
) -> Result<Running, SpawnFail> {
    if !modelled_arch() {
        return Err(SpawnFail::UnsupportedArch);
    }
    if ring_bytes == 0 || ring_bytes > MAX_RING_BYTES {
        return Err(SpawnFail::Opts("ring_bytes must be in [1, 64 MiB]".into()));
    }
    if lifetime.is_zero() || lifetime > MAX_LIFETIME {
        return Err(SpawnFail::Opts("lifetime must be in (0, 24 h]".into()));
    }
    let frame = frame(prog).ok_or(SpawnFail::Spec)?;
    let helper_path = helper.as_bytes().to_vec();
    if helper_path.contains(&0) || helper_path.is_empty() {
        return Err(SpawnFail::Spec);
    }
    let parent_pid = std::process::id();

    let mut control = [0; 2];
    let mut out = [0; 2];
    let mut err = [0; 2];
    let mut status = [0; 2];
    for p in [&mut control, &mut out, &mut err, &mut status] {
        sys::pipe2(p).map_err(|_| SpawnFail::Pipe)?;
    }

    let child_raw = sys::fork_prog().map_err(|_| {
        for p in [&control, &out, &err, &status] {
            for fd in p {
                sys::close(*fd);
            }
        }
        SpawnFail::Fork
    })?;
    if child_raw == 0 {
        // The helper arm: the four pipes at their fixed numbers, its own
        // process group (the spawner's fallback kill target), a clean fd
        // table, and a re-exec of this binary as the helper. Never returns.
        pre_exec_helper(
            &helper_path,
            parent_pid,
            [control[0], out[1], err[1], status[1]],
        );
    }
    // Parent: close the child's copies, keep the ends it reads and writes.
    for fd in [control[0], out[1], err[1], status[1]] {
        sys::close(fd);
    }
    // pids are positive in practice; a negative one is not a pid we spawn.
    let child = u32::try_from(child_raw).map_err(|_| SpawnFail::Fork)?;
    if sys::write_all(control[1], &frame).is_err() {
        // The helper is gone or unreadable; kill it and refuse.
        sys::kill_pid(child);
        sys::close(control[1]);
        for fd in [out[0], err[0], status[0]] {
            sys::close(fd);
        }
        return Err(SpawnFail::Pipe);
    }

    let started = Instant::now();
    let running = Running {
        helper_pid: child,
        control: Arc::new(ControlWrite {
            fd: Mutex::new(Some(control[1])),
        }),
        out: Arc::new(Mutex::new(StreamRing::new(ring_bytes))),
        err: Arc::new(Mutex::new(StreamRing::new(ring_bytes))),
        status: Arc::new(StatusRx {
            child: Mutex::new(None),
            done: AtomicBool::new(false),
            report: Mutex::new(None),
        }),
        started,
        deadline: started + lifetime,
        finished: None,
    };
    running.start_readers(out[0], err[0], status[0]);
    running.start_deadline_closer();
    Ok(running)
}

#[cfg(target_os = "linux")]
impl Running {
    /// The helper's pid (its own process group's leader). A spawner that
    /// needs to escalate beyond this module's grace — or a test that wants
    /// to prove a crash sweeps — addresses the helper here.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.helper_pid
    }

    /// Drain the two stream read ends into the rings and parse the status
    /// pipe (hello line, then report, then EOF).
    fn start_readers(&self, out_r: i32, err_r: i32, status_r: i32) {
        for (fd, ring) in [(out_r, &self.out), (err_r, &self.err)] {
            let ring = Arc::clone(ring);
            std::thread::spawn(move || {
                let mut buf = [0u8; 64 * 1024];
                loop {
                    match sys::read_fd(fd, &mut buf) {
                        0 => break,
                        n if n > 0 => {
                            let chunk = buf.get(..n as usize).unwrap_or(&[]);
                            if let Ok(mut g) = ring.lock() {
                                g.push(chunk);
                            }
                        }
                        -4 => continue, // EINTR
                        _ => break,
                    }
                }
                sys::close(fd);
            });
        }
        let status = Arc::clone(&self.status);
        std::thread::spawn(move || {
            let mut acc: Vec<u8> = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match sys::read_fd(status_r, &mut buf) {
                    0 => break,
                    n if n > 0 => {
                        let chunk = buf.get(..n as usize).unwrap_or(&[]);
                        acc.extend_from_slice(chunk);
                    }
                    -4 => continue,
                    _ => break,
                }
                if acc.len() > 64 * 1024 {
                    break; // a runaway helper: refuse to buffer it all
                }
            }
            sys::close(status_r);
            if let Ok(mut g) = status.child.lock() {
                *g = parse_hello(&acc);
            }
            if let Some((report, _)) = parse_report(&acc) {
                if let Ok(mut g) = status.report.lock() {
                    *g = Some(report);
                }
            }
            status.done.store(true, Ordering::Release);
        });
    }

    /// Close the control pipe when the wall clock runs out; the helper then
    /// stops the program and sweeps — the same path an operator's stop
    /// takes.
    fn start_deadline_closer(&self) {
        let control = Arc::clone(&self.control);
        let deadline = self.deadline;
        std::thread::spawn(move || {
            let now = Instant::now();
            if deadline > now {
                std::thread::sleep(deadline - now);
            }
            control.close();
        });
    }

    /// The program's process group, once the hello line arrived.
    fn pgid(&self) -> Option<u32> {
        self.status.pgid()
    }

    /// Kill the helper's group and the program's group. Best effort by
    /// construction: used only when the report is missing.
    fn escalate(&self) {
        sys::kill_group(self.helper_pid);
        if let Some(pgid) = self.pgid() {
            sys::kill_group(pgid);
        }
    }

    /// Poll the status reader until its final report or `until`.
    fn await_report(&self, until: Instant) -> Option<Report> {
        while Instant::now() < until {
            if self.status.is_done() {
                return self.status.take_report();
            }
            std::thread::sleep(LIVE_TICK);
        }
        self.status.take_report()
    }

    /// Collect the streams and build the raw exit.
    fn collect(&self, timed_out: bool, report: Option<Report>) -> RawExit {
        let snapshot = |ring: &Mutex<StreamRing>| match ring.lock() {
            Ok(g) => (g.total(), g.range(0, g.total()), g.sha.clone().finish()),
            Err(_) => (0u64, Vec::new(), [0u8; 32]),
        };
        let (out_total, stdout, _) = snapshot(&self.out);
        let (err_total, stderr, _) = snapshot(&self.err);
        let elapsed = self.started.elapsed();
        let out_truncated = out_total > stdout.len() as u64;
        let err_truncated = err_total > stderr.len() as u64;
        match report {
            Some(r) => {
                let outcome = decode_wait(r.status);
                let exec_ok = !matches!(outcome, WaitCause::Exited(c) if is_exec_failure(c));
                let confirmed = r.result == "confirmed";
                RawExit {
                    outcome,
                    exec_ok,
                    end: if r.end == "stop" {
                        RawEnd::Stop
                    } else {
                        RawEnd::Exit
                    },
                    kills: r.kills,
                    confirmed,
                    timed_out,
                    detail: if confirmed {
                        String::new()
                    } else {
                        "the sweep could not confirm an empty tree".into()
                    },
                    elapsed,
                    stdout,
                    stdout_truncated: out_truncated,
                    stderr,
                    stderr_truncated: err_truncated,
                }
            }
            None => RawExit {
                outcome: WaitCause::Unknown,
                exec_ok: false,
                end: RawEnd::Stop,
                kills: 0,
                confirmed: false,
                timed_out,
                detail: "the supervisor helper did not report; the tree was killed".into(),
                elapsed,
                stdout,
                stdout_truncated: out_truncated,
                stderr,
                stderr_truncated: err_truncated,
            },
        }
    }

    /// The shared tail of [`Self::wait`] and [`Self::stop`]: give the
    /// helper its sweep grace, escalate if it will not report, collect.
    fn finish(&mut self, stopped: bool) -> RawExit {
        if let Some(done) = self.finished.take() {
            return done;
        }
        let timed_out = !stopped && Instant::now() >= self.deadline;
        let grace_end = Instant::now() + SWEEP_DEADLINE + READ_GRACE;
        let report = self.await_report(grace_end);
        if report.is_none() {
            self.escalate();
        }
        let exit = self.collect(timed_out, report);
        self.finished = Some(exit.clone());
        exit
    }

    /// Wait for the call to end (program exit or wall clock), let the
    /// helper sweep, and collect what it left.
    pub fn wait(mut self) -> RawExit {
        self.finish(false)
    }

    /// Poll the call without blocking (§4.2): `None` while it runs, `Some`
    /// once the helper has reported and been collected.
    pub fn try_status(&mut self) -> Option<RawExit> {
        if self.finished.is_some() {
            return self.finished.take();
        }
        if !self.status.is_done() {
            return None;
        }
        let report = self.status.take_report();
        let exit = self.collect(false, report);
        self.finished = Some(exit.clone());
        Some(exit)
    }

    /// Read a bounded window of a live stream (§3.2), exactly as the macOS
    /// running child exposes it.
    #[must_use]
    pub fn read(&self, stream: RawStream, since: u64, cap: usize, mode: RawMode) -> RawChunk {
        let ring = match stream {
            RawStream::Out => &self.out,
            RawStream::Err => &self.err,
        };
        match ring.lock() {
            Ok(g) => g.chunk(since, cap, mode),
            Err(_) => RawChunk {
                from: since,
                to: since,
                dropped: 0,
                skipped: 0,
                bytes: Vec::new(),
            },
        }
    }

    /// Total bytes and the running SHA-256 of each stream (§4.2), covering
    /// every byte ever written whether a ring still holds it or not.
    #[must_use]
    pub fn totals(&self) -> RawTotals {
        let snapshot = |ring: &Mutex<StreamRing>| match ring.lock() {
            Ok(g) => (g.total(), g.sha.clone().finish()),
            Err(_) => (0u64, [0u8; 32]),
        };
        let (out_total, out_sha) = snapshot(&self.out);
        let (err_total, err_sha) = snapshot(&self.err);
        RawTotals {
            out_total,
            out_sha,
            err_total,
            err_sha,
        }
    }

    /// Stop a live call (§4.2): close the control pipe, give the helper its
    /// sweep grace, and collect. A helper that will not finish in the grace
    /// is killed with its group and reported unconfirmed.
    pub fn stop(mut self) -> RawExit {
        self.control.close();
        self.finish(true)
    }
}

#[cfg(target_os = "linux")]
impl Drop for Running {
    fn drop(&mut self) {
        self.control.close();
        if self.finished.is_some() {
            return;
        }
        // Best effort, bounded: a caller that drops a running child gets the
        // same treatment as a stop, without waiting past the sweep.
        let until = Instant::now() + SWEEP_DEADLINE;
        let report = self.await_report(until);
        if report.is_none() {
            self.escalate();
        }
        let _ = self.collect(true, report);
    }
}

/// The helper's entry: never returns. A binary dispatches
/// `argv[1] == HELPER_ARG` here (its own `main`, before anything else).
///
/// On entry, stdin (fd 3) is the control pipe — the framed [`Program`],
/// then EOF when the spawner is gone — fd 4/5 are the program's stdout and
/// stderr, fd 6 the status pipe, and nothing else is open above 2.
#[cfg(target_os = "linux")]
pub fn helper_main() -> ! {
    if !modelled_arch() {
        sys::raw_exit(90);
    }
    // The spawner's pid arrives in argv[2]; if the spawner died between the
    // fork and here, getppid differs and this helper must not start a tree.
    let Some(parent) = std::env::args_os()
        .nth(2)
        .and_then(|p| p.into_string().ok())
        .and_then(|p| p.parse::<u32>().ok())
    else {
        sys::raw_exit(90);
    };
    if sys::getppid() != parent {
        sys::raw_exit(91);
    }
    // The sweep owner becomes the orphans' parent: a setsid escapee whose
    // intermediate process died re-parents here, where the sweep finds it.
    if sys::prctl_subreaper().is_err() {
        sys::raw_exit(92);
    }
    let mut acc: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    let frame = loop {
        match sys::read_fd(FD_CONTROL_R, &mut buf) {
            0 => sys::raw_exit(91),
            n if n > 0 => {
                let chunk = buf.get(..n as usize).unwrap_or(&[]);
                acc.extend_from_slice(chunk);
                if let Some(f) = parse_frame(&acc) {
                    break f.program;
                }
                if acc.len() > MAX_FRAME_BYTES {
                    sys::raw_exit(93);
                }
            }
            -4 => continue,
            _ => sys::raw_exit(93),
        }
    };
    sys::close(FD_CONTROL_R);

    let child = match sys::fork_prog() {
        Ok(0) => {
            // Namespace tier (S-Lj): the fork's child is the nsprep — it
            // unshares the namespaces and execs the program as the
            // namespace's PID 1 (its exit code maps the program's ending).
            // Everything the helper does below (pidfd, hello, watch,
            // sweep) is unchanged: the pidfd now covers nsprep, whose exit
            // is the kernel tearing the namespace down.
            if frame.netns.is_some() {
                crate::namespaces::nsprep_main(&frame);
            }
            child_exec(&frame);
        }
        Ok(pid) => u32::try_from(pid).unwrap_or(u32::MAX),
        Err(()) => sys::raw_exit(93),
    };
    // The helper keeps no copy of the program's stream ends: the pipe EOFs
    // the spawner sees are exactly the program family's ends.
    sys::close(FD_OUT_W);
    sys::close(FD_ERR_W);
    let pidfd = match sys::pidfd_open(child) {
        Ok(fd) => fd,
        Err(()) => {
            sys::kill_group(child);
            sys::raw_exit(93);
        }
    };
    // The hello line: the spawner learns the group leader before any wait.
    let _ = sys::write_all(FD_STATUS_W, format!("pid {child}\n").as_bytes());

    let end = watch(pidfd);
    sys::close(pidfd);
    let end_name = match end {
        Ending::Exited => "exit",
        Ending::Stopped => "stop",
    };
    // The program's raw wait status: blocking after a pidfd exit; after a
    // stop, whatever the sweep leaves (it SIGKILLs the program too).
    let mut status = match end {
        Ending::Exited => sys::wait_block(child).map(i64::from).unwrap_or(-1),
        Ending::Stopped => {
            let pid = i32::try_from(child).unwrap_or(-1);
            sys::wait_no_hang(pid).map(i64::from).unwrap_or(-1)
        }
    };
    let (kills, confirmed) = sweep(child);
    if status < 0 {
        // The sweep ended the program: collect its real status now.
        status = sys::wait_block(child).map(i64::from).unwrap_or(-1);
    }
    report_and_exit(FD_STATUS_W, status, end_name, kills, confirmed);
}

/// What ended the watch.
#[cfg(target_os = "linux")]
enum Ending {
    /// The program's pidfd signalled exit.
    Exited,
    /// The control pipe closed (spawner gone, or an operator's stop).
    Stopped,
}

/// Watch the program's pidfd and the control pipe until one ends the call.
#[cfg(target_os = "linux")]
fn watch(pidfd: i32) -> Ending {
    loop {
        let mut fds = [
            sys::PollFd {
                fd: pidfd,
                events: sys::POLL_IN,
                revents: 0,
            },
            sys::PollFd {
                fd: FD_CONTROL_R,
                events: sys::POLL_IN,
                revents: 0,
            },
        ];
        let hit = sys::ppoll(&mut fds, LIVE_TICK);
        let read_control = |fds: &mut [sys::PollFd]| -> bool {
            // POLL_IN on a pipe nobody writes to is a hangup: a read
            // returns 0. A stray data byte is drained and ignored.
            let Some(cf) = fds.get_mut(1) else {
                return true;
            };
            let hup = cf.revents & sys::POLL_HUP != 0;
            hup || sys::read_fd(FD_CONTROL_R, &mut [0u8; 1]) == 0
        };
        if hit < 0 {
            // EINTR or worse: re-check both ends without blocking.
            if sys::wait_no_hang(-1).is_some() {
                return Ending::Exited;
            }
            if read_control(&mut fds) {
                return Ending::Stopped;
            }
            continue;
        }
        let pidfd_hit = fds
            .first()
            .is_some_and(|f| f.revents & (sys::POLL_IN | sys::POLL_HUP) != 0);
        if pidfd_hit {
            return Ending::Exited;
        }
        let control_hit = fds
            .get(1)
            .is_some_and(|f| f.revents & (sys::POLL_IN | sys::POLL_HUP) != 0);
        if control_hit && read_control(&mut fds) {
            return Ending::Stopped;
        }
    }
}

/// Empty the tree: SIGKILL the program's group, SIGKILL anything the
/// subreaper inherited (setsid escapees show up with ppid == this pid),
/// and reap until a full pass collects nothing or the deadline passes.
/// Returns the kill count and whether an empty tree was confirmed.
#[cfg(target_os = "linux")]
fn sweep(leader: u32) -> (u32, bool) {
    sys::kill_group(leader);
    let deadline = Instant::now() + SWEEP_DEADLINE;
    let mut kills = 0u32;
    let me = std::process::id();
    while Instant::now() < deadline {
        for pid in orphaned_children(me) {
            sys::kill_pid(pid);
            kills += 1;
        }
        if sys::wait_no_hang(-1).is_some() {
            kills += 1;
            continue;
        }
        if orphaned_children(me).is_empty() {
            return (kills, true);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    (kills, false)
}

/// Pids whose parent is `me`: the descendants the subreaper inherited when
/// an intermediate process died — the setsid escapees.
#[cfg(target_os = "linux")]
fn orphaned_children(me: u32) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if pid != me && ppid_of(pid) == Some(me) {
            out.push(pid);
        }
    }
    out
}

/// A process's parent pid from `/proc/<pid>/stat` (field 4, after the comm
/// field, which may contain spaces and parens).
#[cfg(target_os = "linux")]
fn ppid_of(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.rfind(')')?;
    let rest = stat.get(close + 2..)?;
    rest.split(' ').nth(1)?.parse().ok()
}

/// The program's final report on the status pipe, then the helper's verdict
/// exit: 0 only for a confirmed empty tree.
#[cfg(target_os = "linux")]
fn report_and_exit(fd: i32, status: i64, end: &str, kills: u32, confirmed: bool) -> ! {
    let outcome = decode_wait(status);
    let exec_ok = !matches!(outcome, WaitCause::Exited(c) if is_exec_failure(c));
    let line = format!(
        "\nrh-sup/1 {} status={} end={} kills={} exec={}\n",
        if confirmed {
            "confirmed"
        } else {
            "unconverged"
        },
        status,
        end,
        kills,
        if exec_ok { "ok" } else { "failed" },
    );
    let _ = sys::write_all(fd, line.as_bytes());
    sys::close(fd);
    sys::raw_exit(if confirmed { 0 } else { 3 });
}

/// The forked program's setup: die-with-parent, own process group (unless
/// the namespace tier keeps it in nsprep's group), the streams, the
/// working directory, then the confinement domain (no_new_privs via
/// Landlock, Landlock, seccomp, rlimits), a clean fd table, and `execve`.
/// Every failure exits with a code in the exec-failure window; nothing
/// half-configured execs. Never returns.
#[cfg(target_os = "linux")]
pub(crate) fn child_exec(prog: &Program) -> ! {
    // Die with the parent (the helper, or nsprep on the namespace tier):
    // any ancestor death ends the program even if a sweep was cut short.
    if sys::prctl_pdeathsig().is_err() {
        sys::raw_exit(94);
    }
    // Own process group: the kill domain is the whole tree at once. On the
    // namespace tier nsprep already leads the group, and the program stays
    // in it — one group kill covers nsprep, the program and its forks on
    // the host's pid terms (the pidns init death is the backstop).
    if prog.netns.is_none() && sys::setpgid_self().is_err() {
        sys::raw_exit(95);
    }
    if sys::dup2(FD_OUT_W, 1).is_err() || sys::dup2(FD_ERR_W, 2).is_err() {
        sys::raw_exit(96);
    }
    if sys::dup2_devnull_stdin().is_err() {
        sys::raw_exit(97);
    }
    // The supervisor's own pipe ends do not cross the exec either: with the
    // streams re-pointed, fds 3..=6 are pure harness state, and a program
    // must not inherit them (FT-8). Idempotent: fd 3 was already closed
    // before the fork.
    for fd in [FD_CONTROL_R, FD_OUT_W, FD_ERR_W, FD_STATUS_W] {
        sys::close(fd);
    }
    if sys::chdir(&prog.cwd).is_err() {
        sys::raw_exit(98);
    }
    // The confinement domain, before exec: Landlock (which sets
    // no_new_privs for the restrict_self) is the file plane, seccomp last
    // (S-Lc's ordering).
    let domain =
        match crate::landlock_rules::build(&prog.read_only, &prog.read_write, &prog.protected) {
            Ok(d) => d,
            Err(_) => sys::raw_exit(99),
        };
    if domain.apply().is_err() {
        sys::raw_exit(99);
    }
    // The seccomp shape: the default tier's deny-all, or the namespace
    // tier's ladder (with an empty netns, `ports: false` compiles the same
    // deny-all; a port grant adds only AF_INET/6 stream sockets — still no
    // unix sockets, dgram, raw, or socketpair).
    let mode = match prog.netns.as_ref() {
        Some(ns) => crate::seccomp::NetworkMode::Netns {
            ports: ns.has_ports(),
        },
        None => crate::seccomp::NetworkMode::None,
    };
    let filter = crate::LinuxBackend::seccomp_denylist(mode);
    if crate::seccomp::SeccompFilter::apply(&filter).is_err() {
        sys::raw_exit(100);
    }
    if sys::set_rlimits(&prog.limits).is_err() {
        sys::raw_exit(101);
    }
    // No harness fd crosses the exec: the four supervisor fds and anything
    // else at or above the floor are closed here, in the program itself.
    if sys::close_range(FD_LEAK_FLOOR).is_err() {
        sys::raw_exit(101);
    }
    let _ = sys::execve(&prog.argv, &prog.env);
    sys::raw_exit(102);
}

/// The spawner-side pre-exec: become the helper — re-exec this binary with
/// the helper argv — with the four pipes at their fixed numbers, its own
/// process group, and a fd table that holds nothing else. Never returns.
#[cfg(target_os = "linux")]
fn pre_exec_helper(helper: &[u8], parent_pid: u32, fds: [i32; 4]) -> ! {
    let [control_r, out_w, err_w, status_w] = fds;
    let _ = sys::dup2(control_r, FD_CONTROL_R);
    let _ = sys::dup2(out_w, FD_OUT_W);
    let _ = sys::dup2(err_w, FD_ERR_W);
    let _ = sys::dup2(status_w, FD_STATUS_W);
    // The helper's own group: the spawner's fallback kill target when no
    // hello line ever arrived.
    let _ = sys::setpgid_self();
    let _ = sys::close_range(FD_LEAK_FLOOR);
    let argv = vec![
        helper.to_vec(),
        HELPER_ARG.as_bytes().to_vec(),
        parent_pid.to_string().into_bytes(),
    ];
    let _ = sys::execve(&argv, &[]);
    sys::raw_exit(103);
}

/// Whether this host's process layer exists at all: Linux on a modelled
/// architecture (the syscall numbers are per-arch consts in `sys`).
#[cfg(target_os = "linux")]
fn modelled_arch() -> bool {
    cfg!(any(target_arch = "x86_64", target_arch = "aarch64"))
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) mod sys {
    //! Thin `syscall(2)` wrappers. Every `unsafe` block is one raw syscall
    //! whose pointer arguments address memory this module or its caller
    //! owns for the call's duration; every failure surfaces as `Err`/`-1`,
    //! and a caller that cannot complete a step refuses — never continues.
    //! The namespace tier's nsprep (`crate::namespaces`) reuses these
    //! wrappers for the calls it shares.

    use super::Limits;

    // Syscall numbers per arch (gnu/b64 tables; x86_64 numbers verified in
    // S-Lc, aarch64 asm-generic likewise).
    #[cfg(target_arch = "x86_64")]
    const SYS_READ: i64 = 0;
    #[cfg(target_arch = "x86_64")]
    const SYS_WRITE: i64 = 1;
    #[cfg(target_arch = "x86_64")]
    const SYS_OPENAT: i64 = 257;
    #[cfg(target_arch = "x86_64")]
    const SYS_CLOSE: i64 = 3;
    #[cfg(target_arch = "x86_64")]
    const SYS_PPOLL: i64 = 271;
    #[cfg(target_arch = "x86_64")]
    const SYS_WAIT4: i64 = 61;
    #[cfg(target_arch = "x86_64")]
    const SYS_KILL: i64 = 62;
    #[cfg(target_arch = "x86_64")]
    const SYS_FORK: i64 = 57;
    #[cfg(target_arch = "x86_64")]
    const SYS_EXECVE: i64 = 59;
    #[cfg(target_arch = "x86_64")]
    const SYS_EXIT: i64 = 60;
    #[cfg(target_arch = "x86_64")]
    const SYS_PIPE2: i64 = 293;
    #[cfg(target_arch = "x86_64")]
    const SYS_DUP3: i64 = 292;
    #[cfg(target_arch = "x86_64")]
    const SYS_SETPGID: i64 = 109;
    #[cfg(target_arch = "x86_64")]
    const SYS_GETPPID: i64 = 110;
    #[cfg(target_arch = "x86_64")]
    const SYS_CHDIR: i64 = 80;
    #[cfg(target_arch = "x86_64")]
    const SYS_PRLIMIT64: i64 = 302;
    #[cfg(target_arch = "x86_64")]
    const SYS_PIDFD_OPEN: i64 = 434;
    #[cfg(target_arch = "x86_64")]
    const SYS_CLOSE_RANGE: i64 = 436;
    #[cfg(target_arch = "aarch64")]
    const SYS_READ: i64 = 63;
    #[cfg(target_arch = "aarch64")]
    const SYS_WRITE: i64 = 64;
    #[cfg(target_arch = "aarch64")]
    const SYS_OPENAT: i64 = 56;
    #[cfg(target_arch = "aarch64")]
    const SYS_CLOSE: i64 = 57;
    #[cfg(target_arch = "aarch64")]
    const SYS_PPOLL: i64 = 270;
    #[cfg(target_arch = "aarch64")]
    const SYS_WAIT4: i64 = 260;
    #[cfg(target_arch = "aarch64")]
    const SYS_KILL: i64 = 129;
    // aarch64 has no `fork`; `clone(SIGCHLD, …)` is the same thing.
    #[cfg(target_arch = "aarch64")]
    const SYS_CLONE: i64 = 220;
    #[cfg(target_arch = "aarch64")]
    const SYS_EXECVE: i64 = 221;
    #[cfg(target_arch = "aarch64")]
    const SYS_EXIT: i64 = 93;
    #[cfg(target_arch = "aarch64")]
    const SYS_PIPE2: i64 = 59;
    #[cfg(target_arch = "aarch64")]
    const SYS_DUP3: i64 = 24;
    #[cfg(target_arch = "aarch64")]
    const SYS_SETPGID: i64 = 234;
    #[cfg(target_arch = "aarch64")]
    const SYS_GETPPID: i64 = 173;
    #[cfg(target_arch = "aarch64")]
    const SYS_CHDIR: i64 = 49;
    #[cfg(target_arch = "aarch64")]
    const SYS_PRLIMIT64: i64 = 261;
    #[cfg(target_arch = "aarch64")]
    const SYS_PIDFD_OPEN: i64 = 434;
    #[cfg(target_arch = "aarch64")]
    const SYS_CLOSE_RANGE: i64 = 436;
    #[cfg(target_arch = "x86_64")]
    const SYS_PRCTL: i64 = 157;
    #[cfg(target_arch = "aarch64")]
    const SYS_PRCTL: i64 = 167;

    /// `PR_SET_PDEATHSIG`.
    const PR_SET_PDEATHSIG: i64 = 1;
    /// `PR_SET_CHILD_SUBREAPER`.
    const PR_SET_CHILD_SUBREAPER: i64 = 36;
    /// `O_CLOEXEC`.
    const O_CLOEXEC: u64 = 0o2_000_000;
    /// `AT_FDCWD`.
    const AT_FDCWD: u64 = (-100i64) as u64;
    /// `RLIM_INFINITY`.
    const RLIM_INF: u64 = u64::MAX;
    // rlimit resources (the same numbers on both arches).
    const RLIMIT_CPU: i64 = 0;
    const RLIMIT_FSIZE: i64 = 1;
    const RLIMIT_NPROC: i64 = 6;
    const RLIMIT_AS: i64 = 9;
    /// `POLLIN`.
    pub(crate) const POLL_IN: i16 = 0x001;
    /// `POLLHUP`.
    pub(crate) const POLL_HUP: i16 = 0x010;
    /// `WNOHANG`.
    const WNOHANG: u64 = 1;
    /// `SIGKILL`.
    const SIGKILL: u64 = 9;
    /// `SIGCHLD` (the clone exit signal on aarch64).
    #[cfg(target_arch = "aarch64")]
    const SIGCHLD: u64 = 17;
    /// `EINTR`.
    const EINTR: i64 = -4;

    extern "C" {
        fn syscall(num: i64, ...) -> i64;
    }

    /// The one variadic raw call every wrapper funnels through. Also the
    /// funnel for the namespace tier's own wrappers (`crate::namespaces`),
    /// so the crate keeps exactly one `unsafe` site.
    pub(crate) fn sc(num: i64, a: u64, b: u64, c: u64, d: u64, e: u64) -> i64 {
        // SAFETY: the module's ONE raw variadic call. Every argument is a
        // value the kernel reads only (or a pointer, as each wrapper's own
        // SAFETY note describes); the return value is the kernel's.
        unsafe { syscall(num, a, b, c, d, e) }
    }

    fn ok(rc: i64) -> Result<(), ()> {
        if rc == -1 {
            Err(())
        } else {
            Ok(())
        }
    }

    /// `pipe2(fds, O_CLOEXEC)`: both ends close on any exec, so an end the
    /// pre-exec hands onward is dup'd to its fixed number first (dup
    /// clears the flag on the new number only — what the handoff wants).
    pub(super) fn pipe2(fds: &mut [i32; 2]) -> Result<(), ()> {
        // SAFETY: the kernel writes exactly two ints into the caller-owned
        // array for the call's duration.
        let rc = sc(
            SYS_PIPE2,
            std::ptr::from_mut(fds) as u64,
            O_CLOEXEC,
            0,
            0,
            0,
        );
        ok(rc)
    }

    /// `close(fd)`.
    pub(crate) fn close(fd: i32) {
        // SAFETY: a plain fd close of an fd this process owns.
        let _ = sc(SYS_CLOSE, fd as u64, 0, 0, 0, 0);
    }

    /// `close_range(first, ~0, 0)`: everything at or above `first` is gone,
    /// so no spawner fd can cross an exec.
    pub(super) fn close_range(first: i32) -> Result<(), ()> {
        // SAFETY: immediate range values; the kernel closes the calling
        // process's own descriptors.
        ok(sc(SYS_CLOSE_RANGE, first as u64, u32::MAX as u64, 0, 0, 0))
    }

    /// `dup3(old, new, 0)`.
    pub(super) fn dup2(old: i32, new: i32) -> Result<(), ()> {
        // SAFETY: two fd numbers, no pointers.
        ok(sc(SYS_DUP3, old as u64, new as u64, 0, 0, 0))
    }

    /// `prctl(PR_SET_PDEATHSIG, SIGKILL)` — on the program, whose parent is
    /// the helper.
    pub(crate) fn prctl_pdeathsig() -> Result<(), ()> {
        // SAFETY: immediate option values only.
        ok(sc(SYS_PRCTL, PR_SET_PDEATHSIG as u64, SIGKILL, 0, 0, 0))
    }

    /// `prctl(PR_SET_CHILD_SUBREAPER, 1)` — on the helper: orphaned
    /// descendants are re-parented here, so the sweep can find (and reap)
    /// setsid escapees.
    pub(super) fn prctl_subreaper() -> Result<(), ()> {
        // SAFETY: immediate option values only.
        ok(sc(SYS_PRCTL, PR_SET_CHILD_SUBREAPER as u64, 1, 0, 0, 0))
    }

    /// `setpgid(0, 0)`: the caller becomes its own group leader.
    pub(crate) fn setpgid_self() -> Result<(), ()> {
        // SAFETY: immediate values only.
        ok(sc(SYS_SETPGID, 0, 0, 0, 0, 0))
    }

    /// `fork()` (x86_64) or `clone(SIGCHLD, …)` (aarch64): the supervisor's
    /// forks happen only in the fresh single-threaded helper (or the
    /// spawner's pre-exec child, before any thread exists).
    pub(crate) fn fork_prog() -> Result<i32, ()> {
        // SAFETY: no pointer arguments; the return value distinguishes the
        // child (0) from the parent (the child's pid).
        #[cfg(target_arch = "x86_64")]
        let rc = sc(SYS_FORK, 0, 0, 0, 0, 0);
        #[cfg(target_arch = "aarch64")]
        let rc = sc(SYS_CLONE, SIGCHLD, 0, 0, 0, 0);
        if rc == -1 {
            Err(())
        } else {
            Ok(rc as i32)
        }
    }

    /// `execve(path, argv, envp)` over byte vectors (the spec's shape; the
    /// framer refused interior NULs). Returns only on failure.
    pub(super) fn execve(argv: &[Vec<u8>], env: &[Vec<u8>]) -> Result<(), ()> {
        let Some(path) = argv.first() else {
            return Err(());
        };
        let mut ptrs: Vec<*const u8> = Vec::with_capacity(argv.len() + 1);
        for a in argv {
            ptrs.push(a.as_ptr());
        }
        ptrs.push(std::ptr::null());
        let mut envs: Vec<*const u8> = Vec::with_capacity(env.len() + 1);
        for e in env {
            envs.push(e.as_ptr());
        }
        envs.push(std::ptr::null());
        // SAFETY: the pointer arrays are null-terminated lists pointing at
        // the caller-owned NUL-free byte vectors, valid for the call's
        // duration; execve returns only when it refused.
        let rc = sc(
            SYS_EXECVE,
            path.as_ptr() as u64,
            ptrs.as_ptr() as u64,
            envs.as_ptr() as u64,
            0,
            0,
        );
        ok(rc)
    }

    /// `pidfd_open(pid)`: a stable handle whose pollability replaces
    /// SIGCHLD plumbing.
    pub(crate) fn pidfd_open(pid: u32) -> Result<i32, ()> {
        // SAFETY: immediate values; the return value is an fd.
        let rc = sc(SYS_PIDFD_OPEN, pid as u64, 0, 0, 0, 0);
        if rc == -1 {
            Err(())
        } else {
            Ok(rc as i32)
        }
    }

    /// One `pollfd` (the kernel's layout on both arches).
    #[repr(C)]
    pub(crate) struct PollFd {
        /// The fd to watch.
        pub fd: i32,
        /// The events requested.
        pub events: i16,
        /// The events seen.
        pub revents: i16,
    }

    /// `ppoll(fds, nfds, timeout)` with a relative timeout.
    pub(crate) fn ppoll(fds: &mut [PollFd], timeout: std::time::Duration) -> i64 {
        #[repr(C)]
        struct Timespec {
            sec: i64,
            nsec: i64,
        }
        let ts = Timespec {
            sec: timeout.as_secs() as i64,
            nsec: i64::from(timeout.subsec_nanos()),
        };
        // SAFETY: the kernel reads the caller-owned pollfd array and
        // timespec and writes the revents fields in place.
        sc(
            SYS_PPOLL,
            fds.as_mut_ptr() as u64,
            fds.len() as u64,
            std::ptr::from_ref(&ts) as u64,
            0,
            0,
        )
    }

    /// `wait4(pid, &status, WNOHANG, NULL)`: `Some(raw)` when a child was
    /// reaped, `None` when none was ready (or the call failed — both mean
    /// "nothing more to collect here").
    pub(super) fn wait_no_hang(pid: i32) -> Option<i32> {
        let mut st: i32 = 0;
        // SAFETY: the kernel writes one int into the caller-owned slot.
        let rc = sc(
            SYS_WAIT4,
            pid as u64,
            std::ptr::from_mut(&mut st) as u64,
            WNOHANG,
            0,
            0,
        );
        if rc > 0 {
            Some(st)
        } else {
            None
        }
    }

    /// `wait4(pid, &status, 0, NULL)`, blocking: the raw wait status.
    pub(crate) fn wait_block(pid: u32) -> Option<i32> {
        let mut st: i32 = 0;
        // SAFETY: the kernel writes one int into the caller-owned slot.
        let rc = sc(
            SYS_WAIT4,
            pid as u64,
            std::ptr::from_mut(&mut st) as u64,
            0,
            0,
            0,
        );
        if rc > 0 {
            Some(st)
        } else {
            None
        }
    }

    /// `kill(-pgid, SIGKILL)`: the whole group at once.
    pub(super) fn kill_group(pgid: u32) {
        // SAFETY: immediate values; a negative pid names a process group.
        let _ = sc(
            SYS_KILL,
            (pgid as i64).wrapping_neg() as u64,
            SIGKILL,
            0,
            0,
            0,
        );
    }

    /// `kill(pid, SIGKILL)` for an escapee the group kill cannot reach.
    pub(super) fn kill_pid(pid: u32) {
        // SAFETY: immediate values only.
        let _ = sc(SYS_KILL, pid as u64, SIGKILL, 0, 0, 0);
    }

    /// `chdir(path)`.
    pub(super) fn chdir(path: &str) -> Result<(), ()> {
        if path.contains('\0') {
            return Err(());
        }
        // SAFETY: the kernel reads the caller-owned NUL-free path bytes.
        ok(sc(SYS_CHDIR, path.as_ptr() as u64, 0, 0, 0, 0))
    }

    /// `openat(AT_FDCWD, "/dev/null", O_RDONLY)` then `dup2(fd, 0)`: the
    /// program's stdin, before Landlock closes the file plane.
    pub(super) fn dup2_devnull_stdin() -> Result<(), ()> {
        const DEVNULL: &[u8] = b"/dev/null\0";
        // SAFETY: the kernel reads the static NUL-terminated path; the
        // returned fd is closed again below on every path.
        let fd = sc(SYS_OPENAT, AT_FDCWD, DEVNULL.as_ptr() as u64, 0, 0, 0);
        if fd == -1 {
            return Err(());
        }
        let r = dup2(fd as i32, 0);
        close(fd as i32);
        r
    }

    /// `prlimit64(0, res, &new, NULL)` for each `Some` limit.
    pub(super) fn set_rlimits(limits: &Limits) -> Result<(), ()> {
        #[repr(C)]
        struct RLimit {
            cur: u64,
            max: u64,
        }
        let set = |res: i64, cur: u64| -> Result<(), ()> {
            let rl = RLimit { cur, max: RLIM_INF };
            // SAFETY: the kernel reads the caller-owned rlimit struct.
            ok(sc(
                SYS_PRLIMIT64,
                0,
                res as u64,
                std::ptr::from_ref(&rl) as u64,
                0,
                0,
            ))
        };
        if let Some(cpu) = limits.cpu {
            set(RLIMIT_CPU, cpu.as_secs().max(1))?;
        }
        if let Some(fs) = limits.file_size {
            set(RLIMIT_FSIZE, fs)?;
        }
        if let Some(n) = limits.processes {
            set(RLIMIT_NPROC, u64::from(n))?;
        }
        if let Some(mem) = limits.memory {
            set(RLIMIT_AS, mem)?;
        }
        Ok(())
    }

    /// `read(fd, buf)`: the byte count, `0` at EOF, negative `-errno` on
    /// error (callers match [`EINTR`]).
    pub(super) fn read_fd(fd: i32, buf: &mut [u8]) -> i64 {
        if buf.is_empty() {
            return 0;
        }
        // SAFETY: the kernel writes at most buf.len() bytes into the
        // caller-owned buffer.
        sc(
            SYS_READ,
            fd as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            0,
            0,
        )
    }

    /// `write(fd, bytes)` until done or a non-EINTR error.
    pub(super) fn write_all(fd: i32, bytes: &[u8]) -> Result<(), ()> {
        let mut at = 0usize;
        while at < bytes.len() {
            let rest = bytes.get(at..).unwrap_or(&[]);
            if rest.is_empty() {
                return Ok(());
            }
            // SAFETY: the kernel reads the caller-owned slice.
            let n = sc(
                SYS_WRITE,
                fd as u64,
                rest.as_ptr() as u64,
                rest.len() as u64,
                0,
                0,
            );
            if n == EINTR {
                continue;
            }
            if n <= 0 {
                return Err(());
            }
            at += n as usize;
        }
        Ok(())
    }

    /// `getppid()`.
    pub(super) fn getppid() -> u32 {
        // SAFETY: no arguments.
        sc(SYS_GETPPID, 0, 0, 0, 0, 0) as u32
    }

    /// `_exit(code)`: the helper and the pre-exec arms never unwind, and a
    /// half-configured process must not run destructors.
    pub(crate) fn raw_exit(code: i32) -> ! {
        // SAFETY: an immediate value; this never returns, so the loop
        // below is unreachable by construction and keeps the fn `!`-typed
        // without a panic (the panic set is denied here).
        let _ = sc(SYS_EXIT, code as u64, 0, 0, 0, 0);
        loop {
            std::hint::spin_loop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- the frame round-trip ----

    fn sample() -> Program {
        Program {
            argv: vec![b"/bin/sh".to_vec(), b"-c".to_vec(), b"echo hi".to_vec()],
            env: vec![b"PATH=/usr/bin".to_vec(), b"RH_X=1".to_vec()],
            cwd: "/tmp".into(),
            read_only: vec!["/usr".into()],
            read_write: vec!["/tmp/w".into()],
            protected: vec!["/tmp/prot".into()],
            limits: Limits {
                cpu: Some(Duration::from_millis(1500)),
                file_size: Some(1 << 20),
                memory: Some(1 << 30),
                processes: Some(64),
            },
            netns: None,
        }
    }

    #[test]
    fn frame_round_trips_through_parse() {
        let p = sample();
        let bytes = frame(&p).expect("frames");
        let parsed = parse_frame(&bytes).expect("parses");
        assert_eq!(parsed.program, p);
    }

    #[test]
    fn frame_without_limits_round_trips() {
        let mut p = sample();
        p.limits = Limits::default();
        let bytes = frame(&p).expect("frames");
        assert_eq!(parse_frame(&bytes).expect("parses").program, p);
    }

    #[test]
    fn frame_round_trips_a_netns_spec() {
        let mut p = sample();
        p.netns = Some(NetnsSpec {
            relay_dir: "/tmp/rh-relay-xyz".into(),
            bind: vec![8080, 8443],
            connect: vec![9090],
        });
        let bytes = frame(&p).expect("frames");
        assert_eq!(parse_frame(&bytes).expect("parses").program, p);
        // The wire names the tier and carries the grants in order.
        let text = String::from_utf8_lossy(&bytes).to_string();
        assert!(text.contains("net ns\n"), "the ns marker is on the wire");
        assert!(text.contains("bind 2\n8080\n8443\n"));
        assert!(text.contains("con 1\n9090\n"));
        // An empty grant list still marks the tier (`ports: false` shape).
        let mut empty = sample();
        empty.netns = Some(NetnsSpec::default());
        assert_eq!(
            parse_frame(&frame(&empty).expect("frames"))
                .expect("parses")
                .program,
            empty
        );
        // The no-namespace marker round-trips as None (covered by the
        // sample's round-trip above), and a truncated ns section refuses.
        let bytes = frame(&p).expect("frames");
        let cut = bytes.len() - 1;
        assert!(parse_frame(&bytes[..cut]).is_none());
        // A relay directory with an interior NUL refuses to frame.
        let mut nul = sample();
        nul.netns = Some(NetnsSpec {
            relay_dir: "/tmp/r\0elay".into(),
            bind: Vec::new(),
            connect: Vec::new(),
        });
        assert_eq!(frame(&nul), None);
    }

    #[test]
    fn a_nul_anywhere_refuses_the_frame() {
        let mut p = sample();
        p.argv[2] = b"echo\0hi".to_vec();
        assert_eq!(frame(&p), None);
        let mut p = sample();
        p.env[0] = b"NAME=\0".to_vec();
        assert_eq!(frame(&p), None);
        let mut p = sample();
        p.cwd = "/tm\0p".into();
        assert_eq!(frame(&p), None);
        let mut p = sample();
        p.read_write.push("/a\0b".into());
        assert_eq!(frame(&p), None);
    }

    #[test]
    fn an_oversized_frame_refuses_at_the_cap() {
        // The helper's reader drops anything past MAX_FRAME_BYTES (exit 93),
        // so the spawner refuses to frame one. Exactly at the cap still
        // frames and round-trips.
        let mut base = sample();
        base.argv.push(Vec::new());
        let base_len = frame(&base).expect("frames").len();
        // The count line of the padded entry grows with its payload ("0\n"
        // in the base vs `d` digits), so solve L + (d - 1) = fit.
        let fit = MAX_FRAME_BYTES - base_len;
        let mut l = fit;
        for _ in 0..4 {
            l = fit + 1 - l.to_string().len();
        }
        let mut p = sample();
        p.argv.push(vec![b'a'; l]);
        let bytes = frame(&p).expect("a frame at exactly the cap frames");
        assert_eq!(bytes.len(), MAX_FRAME_BYTES);
        assert_eq!(parse_frame(&bytes).expect("parses").program, p);
        let mut p = sample();
        p.argv.push(vec![b'a'; l + 1]);
        assert_eq!(frame(&p), None, "one byte over the cap must refuse");
    }

    #[test]
    fn a_truncated_or_adulterated_frame_refuses() {
        let bytes = frame(&sample()).expect("frames");
        for cut in [0, 1, 8, bytes.len() / 2, bytes.len() - 1] {
            assert!(
                parse_frame(&bytes[..cut]).is_none(),
                "a cut at {cut} must not parse"
            );
        }
        let mut tampered = bytes.clone();
        let at = tampered.iter().position(|b| *b == b'w').expect("tag");
        tampered[at] = b'X';
        assert!(parse_frame(&tampered).is_none(), "a bad tag must not parse");
        assert!(parse_frame(b"").is_none());
        assert!(parse_frame(b"rh-sup/1\nlim - - - -\n").is_none());
        assert!(parse_frame(b"other/9\nlim - - - -\n").is_none());
    }

    // ---- the report and hello lines ----

    #[test]
    fn report_parses_from_the_tail() {
        let mut stream = b"pid 4242\n".to_vec();
        let line = b"\nrh-sup/1 confirmed status=0 end=exit kills=2 exec=ok\n";
        stream.extend_from_slice(line);
        let (r, at) = parse_report(&stream).expect("parses");
        assert_eq!(r.result, "confirmed");
        assert_eq!(r.status, 0);
        assert_eq!(r.end, "exit");
        assert_eq!(r.kills, 2);
        assert_eq!(r.exec, "ok");
        assert_eq!(at, 9, "the offset names the leading newline");
        // Noise before the report does not confuse it.
        let mut noisy = b"pid 1\nmid text\n".to_vec();
        noisy.extend_from_slice(line);
        assert!(parse_report(&noisy).is_some());
        // Anything after the final line refuses.
        let mut trailing = stream.clone();
        trailing.extend_from_slice(b"more\n");
        assert!(parse_report(&trailing).is_none());
        // A malformed field refuses.
        let bad = b"\nrh-sup/1 confirmed status=zero end=exit kills=2 exec=ok\n";
        assert!(parse_report(bad).is_none());
        assert!(parse_report(b"").is_none());
        assert!(parse_report(b"pid 1\n").is_none());
    }

    #[test]
    fn hello_parses_only_a_clean_pid_line() {
        assert_eq!(parse_hello(b"pid 4242\n"), Some(4242));
        assert_eq!(parse_hello(b"pid 0\n"), Some(0));
        assert_eq!(parse_hello(b"pid \n"), None);
        assert_eq!(parse_hello(b"pid 4x\n"), None);
        assert_eq!(parse_hello(b"pid -1\n"), None);
        assert_eq!(parse_hello(b""), None);
        assert_eq!(parse_hello(b"pid 4242"), None);
    }

    // ---- wait-status decoding ----

    #[test]
    fn wait_status_decodes_exit_signal_and_unknown() {
        assert_eq!(decode_wait(0), WaitCause::Exited(0));
        assert_eq!(decode_wait(0x0700), WaitCause::Exited(7));
        assert_eq!(decode_wait(0x0f00), WaitCause::Exited(15));
        assert_eq!(decode_wait(9), WaitCause::Signaled(9));
        assert_eq!(decode_wait(24), WaitCause::Signaled(24));
        assert_eq!(decode_wait(0x7f), WaitCause::Signaled(0x7f));
        assert_eq!(decode_wait(-1), WaitCause::Unknown);
    }

    #[test]
    fn exec_failure_codes_are_the_setup_window() {
        // 94..=102 the program's setup steps, 103 the helper's re-exec,
        // 104..=106 the namespace tier's nsprep (S-Lj).
        for code in 94..=106 {
            assert!(is_exec_failure(code), "{code} is a setup failure");
        }
        assert!(!is_exec_failure(93));
        assert!(!is_exec_failure(107));
        assert!(!is_exec_failure(0));
    }

    // ---- SHA-256 against the FIPS vectors ----

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn sha256_matches_the_fips_vectors() {
        let h = Sha256::new();
        assert_eq!(
            hex(&h.finish()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let mut h = Sha256::new();
        h.update(b"abc");
        assert_eq!(
            hex(&h.finish()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // The two-block vector.
        let mut h = Sha256::new();
        h.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            hex(&h.finish()),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // A million 'a', fed in odd-sized pieces (the streaming path).
        let mut h = Sha256::new();
        let piece = [b'a'; 997];
        for _ in 0..(1_000_000 / 997) {
            h.update(&piece);
        }
        h.update(&[b'a'; 1_000_000 % 997]);
        assert_eq!(
            hex(&h.finish()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn sha256_matches_the_one_shot_over_split_updates() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let mut whole = Sha256::new();
        whole.update(&data);
        let one_shot = whole.finish();
        for split in [1, 2, 63, 64, 65, 128, 4096] {
            let mut h = Sha256::new();
            for chunk in data.chunks(split) {
                h.update(chunk);
            }
            assert_eq!(
                h.finish(),
                one_shot,
                "split at {split} must not change the digest"
            );
        }
    }

    // ---- the stream ring (the mirror of ring.rs) ----

    #[test]
    fn ring_cursor_arithmetic_next_and_tail() {
        // `since` older than the ring: everything before ring_start drops.
        let (from, to, dropped, skipped) = window(1000, 100, 0, 50, RawMode::Next);
        assert_eq!((from, to, dropped, skipped), (900, 950, 900, 0));
        // Tail mode ends at total and skips forward within the window.
        let (from, to, dropped, skipped) = window(1000, 100, 0, 50, RawMode::Tail);
        assert_eq!((from, to, dropped, skipped), (950, 1000, 900, 50));
        // A cursor near the end reads the short remainder.
        let (from, to, dropped, skipped) = window(1000, 100, 990, 50, RawMode::Next);
        assert_eq!((from, to, dropped, skipped), (990, 1000, 0, 0));
        // A cursor past the end is clamped to an empty window.
        let (from, to, dropped, skipped) = window(10, 100, 99, 5, RawMode::Next);
        assert_eq!((from, to, dropped, skipped), (10, 10, 0, 0));
        // A zero cap delivers nothing but keeps the cursor.
        let (from, to, dropped, skipped) = window(10, 100, 3, 0, RawMode::Next);
        assert_eq!((from, to, dropped, skipped), (3, 3, 0, 0));
        // An empty stream yields an empty window at zero.
        let (from, to, dropped, skipped) = window(0, 100, 0, 50, RawMode::Tail);
        assert_eq!((from, to, dropped, skipped), (0, 0, 0, 0));

        // The same arithmetic through a live ring: 25 bytes in a 10-byte ring.
        let mut ring = StreamRing::new(10);
        ring.push(b"0123456789");
        ring.push(b"abcdefghijklnop");
        assert_eq!(ring.total(), 25);
        let c = ring.chunk(0, 5, RawMode::Next);
        assert_eq!(c.from, 15, "bytes 0..15 were overwritten");
        assert_eq!(c.dropped, 15);
        assert_eq!(c.to, 20);
        assert_eq!(c.bytes, b"fghij");
        let c = ring.chunk(20, 100, RawMode::Next);
        assert_eq!((c.from, c.to), (20, 25));
        assert_eq!(c.bytes, b"klnop");
        let c = ring.chunk(0, 5, RawMode::Tail);
        assert_eq!((c.from, c.to, c.skipped, c.dropped), (20, 25, 5, 15));
        assert_eq!(c.bytes, b"klnop");
        // A full drain in next mode reaches exactly the end.
        let c = ring.chunk(15, 100, RawMode::Next);
        assert_eq!((c.from, c.to), (15, 25));
        // ...and the delivered cursor is where the next read resumes.
        let c = ring.chunk(c.to, 100, RawMode::Next);
        assert!(c.bytes.is_empty());
        assert_eq!(c.from, 25);
    }

    #[test]
    fn ring_drop_counts_overwritten_bytes() {
        let mut ring = StreamRing::new(8);
        ring.push(b"0123456789");
        assert_eq!(ring.total(), 10, "the count never forgets");
        assert_eq!(ring.range(0, 100), b"23456789", "oldest bytes drop first");
        let c = ring.chunk(0, 100, RawMode::Next);
        assert_eq!(c.dropped, 2, "two bytes fell out of the ring");
        ring.push(b"abc");
        assert_eq!(ring.total(), 13);
        assert_eq!(ring.range(0, 100), b"56789abc");
        assert_eq!(ring.range(11, 13), b"bc", "absolute offsets stay stable");
        ring.push(b"XY");
        // One push larger than the ring keeps only the ring's worth.
        let big = vec![b'.'; 20];
        ring.push(&big);
        assert_eq!(ring.total(), 35);
        assert_eq!(
            ring.range(0, 100),
            &big[12..],
            "the last cap bytes survive a flood"
        );
        // The tail keeps just the last TAIL_BYTES verbatim.
        let mut all = b"0123456789abcXY".to_vec();
        all.extend_from_slice(&big);
        let want = TAIL_BYTES.min(35);
        assert_eq!(ring.tail.len(), want);
        assert_eq!(&ring.tail[..], &all[all.len() - want..]);
    }

    #[test]
    fn ring_digest_covers_dropped_bytes() {
        let data: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
        let mut ring = StreamRing::new(64);
        for chunk in data.chunks(777) {
            ring.push(chunk);
        }
        let mut whole = Sha256::new();
        whole.update(&data);
        assert_eq!(ring.sha.clone().finish(), whole.finish());
        assert_eq!(ring.total(), 10_000);
        assert_eq!(ring.range(0, 10_000).len(), 64, "the ring stays bounded");
    }

    #[test]
    fn ring_chunks_align_to_utf8_boundaries() {
        let text = "héllo".as_bytes().to_vec(); // é is two bytes at 1..3
        let mut ring = StreamRing::new(1024);
        ring.push(&text);
        let c = ring.chunk(0, 2, RawMode::Next);
        assert_eq!(c.to, 1, "the cursor stops before splitting é");
        assert_eq!(c.bytes, b"h");
        let c = ring.chunk(0, 1024, RawMode::Next);
        assert_eq!(c.to, text.len() as u64);
        assert_eq!(c.bytes, text);
    }
}
