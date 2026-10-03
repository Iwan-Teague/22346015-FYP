//! The seccomp-BPF denylist of the default sandbox tier (slice S-Lc).
//!
//! Landlock confines the filesystem; it says nothing about sockets, namespaces
//! or the debug surface. This module closes the remaining §1 gaps ("what
//! Landlock cannot do") with one seccomp filter, applied **last** before
//! `execve` (after `no_new_privs` and Landlock): network, namespace/privilege,
//! debug, kernel-image, keyring and io_uring syscalls are refused, while the
//! syscall surface a worker needs stays allowed.
//!
//! The policy is pure Rust data: an audit-arch-guarded `nr → RET_ERRNO`
//! ladder assembled from two per-arch rule tables (x86_64 and aarch64). The
//! builder runs (and is unit-tested) on any host; only
//! [`SeccompFilter::apply`] touches the kernel, and it exists only on Linux.
//!
//! Denial style is fail-closed but not lethal: refused calls return
//! `−EACCES` (network) or `−EPERM` (escape surface) instead of killing the
//! process, so a straying worker fails its syscall, not the run. An unknown
//! audit architecture is refused with `−ENOSYS`: the guard denies before it
//! ever allows, so a future ABI the tables do not model cannot pass.

use super::LinuxBackend;

/// A compiled classic-BPF program: the wire form `seccomp(2)` consumes.
pub type BpfProgram = Vec<SockFilter>;

/// One classic-BPF instruction, laid out exactly like the kernel's
/// `struct sock_filter` (`#[repr(C)]`: the program is handed to the kernel as
/// a pointer, so field order and padding must match the ABI).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockFilter {
    /// Opcode (`BPF_*` class | size | mode).
    pub code: u16,
    /// Jump offset (in instructions, from the *next* one) when true.
    pub jt: u8,
    /// Jump offset when false.
    pub jf: u8,
    /// Immediate operand.
    pub k: u32,
}

// ---- classic-BPF instruction encoding (linux/filter.h) ----

/// `BPF_LD | BPF_W | BPF_ABS`: 32-bit absolute load from `seccomp_data`.
const BPF_LD_ABS_W: u16 = 0x20;
/// `BPF_ALU | BPF_AND | BPF_K`: AND an immediate into the accumulator.
const BPF_ALU_AND_K: u16 = 0x54;
/// `BPF_JMP | BPF_JA`: unconditional relative jump.
const BPF_JMP_JA: u16 = 0x05;
/// `BPF_JMP | BPF_JEQ | BPF_K`: conditional jump on the accumulator.
const BPF_JMP_JEQ_K: u16 = 0x15;
/// `BPF_RET | BPF_K`: return the immediate as the filter verdict.
const BPF_RET_K: u16 = 0x06;

// ---- struct seccomp_data field offsets ----

/// Offset of `nr` (the syscall number).
const OFF_NR: u32 = 0;
/// Offset of `arch` (the `AUDIT_ARCH_*` value of the calling ABI).
const OFF_ARCH: u32 = 4;
/// Offset of `args[0]`; each `u64` argument occupies 8 bytes.
const OFF_ARGS: u32 = 16;

// ---- audit architectures this filter models ----

/// `AUDIT_ARCH_X86_64` — the only 64-bit ABI on x86_64; the x32 ABI
/// (`0x4000_003e`) fails this guard and is denied like any unknown arch.
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
/// `AUDIT_ARCH_AARCH64`.
const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

// ---- verdict encoding (linux/seccomp.h) ----

/// `SECCOMP_RET_ALLOW`: let the syscall through.
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
/// `SECCOMP_RET_ERRNO`: return `errno` (low 16 bits) to the caller.
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

// ---- errnos used as verdicts ----

/// `EACCES`: denied because the sandbox grants no network at this tier.
const EACCES: u32 = 13;
/// `EPERM`: denied because the operation would escape the sandbox.
const EPERM: u32 = 1;
/// `ENOSYS`: denied because the calling ABI is not modelled (fail closed).
const ENOSYS: u32 = 38;

// ---- arg-filter masks (linux/sched.h, linux/fcntl.h) ----

/// Every `CLONE_NEW*` namespace flag (newns, newcgroup, newuts, newipc,
/// newuser, newpid, newnet); all live in the low 32 bits of `clone`'s
/// `args[0]`.
const CLONE_NEW_MASK: u32 = 0x7e02_0000;
/// `AT_EMPTY_PATH` on `execveat`'s `args[4]`: belt-and-braces against the
/// fd-relative exec that bypasses path-based Landlock rules (§1).
const AT_EMPTY_PATH: u32 = 0x1000;
/// `clone3` takes its argument struct behind a pointer — seccomp-blind — so
/// it is denied outright rather than arg-filtered; same number on every
/// modelled arch (asm-generic).
const CLONE3_NR: u32 = 435;

/// The network grant the filter is built for — a mirror of the spec's
/// `Network` enum (harness-sandbox depends on this crate, not the other way
/// around), narrowed to what a seccomp filter can actually express.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkMode {
    /// `Network::None`: no socket of any family may be opened.
    None,
    /// A port grant (`Network::Proxy`/`Network::Loopback`). seccomp cannot
    /// inspect a `sockaddr` (it sits behind a pointer), so this tier cannot
    /// express those grants and the supervisor refuses them upstream; should
    /// one ever reach this filter anyway it compiles the *identical*
    /// deny-all ladder — a grant can never widen this filter.
    Granted,
}

/// One denylist row: syscall `nr` is answered `SECCOMP_RET_ERRNO` with
/// `errno` on the architecture the row is filed under.
struct Rule {
    nr: u32,
    errno: u32,
}

/// Per-architecture rule table: the arch guard plus the two deny groups.
struct ArchRules {
    audit_arch: u32,
    /// The whole socket family: denied `EACCES` at every network mode.
    socket_family: &'static [Rule],
    /// Namespace, privilege, debug, kernel-image, keyring and io_uring
    /// surface (§1): denied `EPERM`.
    escape_surface: &'static [Rule],
    /// `clone`: allowed, but arg-filtered on `CLONE_NEW*`.
    clone_nr: u32,
    /// `execveat`: allowed, but arg-filtered on `AT_EMPTY_PATH`.
    execveat_nr: u32,
}

const fn denied(nr: u32, errno: u32) -> Rule {
    Rule { nr, errno }
}

/// x86_64 numbers (libc's gnu/b64/x86_64 table; verified in slice S-Lc).
const X86_64: ArchRules = ArchRules {
    audit_arch: AUDIT_ARCH_X86_64,
    socket_family: &[
        denied(41, EACCES),  // socket
        denied(42, EACCES),  // connect
        denied(43, EACCES),  // accept
        denied(44, EACCES),  // sendto
        denied(45, EACCES),  // recvfrom
        denied(46, EACCES),  // sendmsg
        denied(47, EACCES),  // recvmsg
        denied(48, EACCES),  // shutdown
        denied(49, EACCES),  // bind
        denied(50, EACCES),  // listen
        denied(51, EACCES),  // getsockname
        denied(52, EACCES),  // getpeername
        denied(53, EACCES),  // socketpair
        denied(54, EACCES),  // setsockopt
        denied(55, EACCES),  // getsockopt
        denied(288, EACCES), // accept4
        denied(299, EACCES), // recvmmsg
        denied(307, EACCES), // sendmmsg
    ],
    escape_surface: &[
        // Namespace / privilege.
        denied(272, EPERM),       // unshare
        denied(308, EPERM),       // setns
        denied(165, EPERM),       // mount
        denied(166, EPERM),       // umount2
        denied(155, EPERM),       // pivot_root
        denied(161, EPERM),       // chroot
        denied(105, EPERM),       // setuid
        denied(106, EPERM),       // setgid
        denied(113, EPERM),       // setreuid
        denied(114, EPERM),       // setregid
        denied(116, EPERM),       // setgroups
        denied(117, EPERM),       // setresuid
        denied(119, EPERM),       // setresgid
        denied(122, EPERM),       // setfsuid
        denied(123, EPERM),       // setfsgid
        denied(CLONE3_NR, EPERM), // struct behind a pointer, seccomp-blind — denied outright
        // Debug surface.
        denied(101, EPERM), // ptrace
        denied(310, EPERM), // process_vm_readv
        denied(311, EPERM), // process_vm_writev
        denied(298, EPERM), // perf_event_open
        denied(321, EPERM), // bpf
        denied(312, EPERM), // kcmp
        // Kernel image / module / reboot.
        denied(246, EPERM), // kexec_load
        denied(320, EPERM), // kexec_file_load
        denied(175, EPERM), // init_module
        denied(313, EPERM), // finit_module
        denied(176, EPERM), // delete_module
        denied(169, EPERM), // reboot
        // Keyring.
        denied(248, EPERM), // add_key
        denied(249, EPERM), // request_key
        denied(250, EPERM), // keyctl
        // io_uring (submits I/O that bypasses fd permission checks).
        denied(425, EPERM), // io_uring_setup
        denied(426, EPERM), // io_uring_enter
        denied(427, EPERM), // io_uring_register
        // Misc escape surface.
        denied(323, EPERM), // userfaultfd
        denied(300, EPERM), // fanotify_init
        denied(304, EPERM), // open_by_handle_at
    ],
    clone_nr: 56,
    execveat_nr: 322,
};

/// aarch64 numbers (asm-generic gnu/b64/aarch64 table; verified in S-Lc).
const AARCH64: ArchRules = ArchRules {
    audit_arch: AUDIT_ARCH_AARCH64,
    socket_family: &[
        denied(198, EACCES), // socket
        denied(199, EACCES), // socketpair
        denied(200, EACCES), // bind
        denied(201, EACCES), // listen
        denied(202, EACCES), // accept
        denied(203, EACCES), // connect
        denied(204, EACCES), // getsockname
        denied(205, EACCES), // getpeername
        denied(206, EACCES), // sendto
        denied(207, EACCES), // recvfrom
        denied(208, EACCES), // setsockopt
        denied(209, EACCES), // getsockopt
        denied(210, EACCES), // shutdown
        denied(211, EACCES), // sendmsg
        denied(212, EACCES), // recvmsg
        denied(242, EACCES), // accept4
        denied(243, EACCES), // recvmmsg
        denied(269, EACCES), // sendmmsg
    ],
    escape_surface: &[
        // Namespace / privilege.
        denied(97, EPERM),        // unshare
        denied(268, EPERM),       // setns
        denied(40, EPERM),        // mount
        denied(39, EPERM),        // umount2
        denied(41, EPERM),        // pivot_root
        denied(51, EPERM),        // chroot
        denied(146, EPERM),       // setuid
        denied(144, EPERM),       // setgid
        denied(145, EPERM),       // setreuid
        denied(143, EPERM),       // setregid
        denied(159, EPERM),       // setgroups
        denied(147, EPERM),       // setresuid
        denied(149, EPERM),       // setresgid
        denied(151, EPERM),       // setfsuid
        denied(152, EPERM),       // setfsgid
        denied(CLONE3_NR, EPERM), // denied outright (see the x86_64 table)
        // Debug surface.
        denied(117, EPERM), // ptrace
        denied(270, EPERM), // process_vm_readv
        denied(271, EPERM), // process_vm_writev
        denied(241, EPERM), // perf_event_open
        denied(280, EPERM), // bpf
        denied(272, EPERM), // kcmp
        // Kernel image / module / reboot.
        denied(104, EPERM), // kexec_load
        denied(294, EPERM), // kexec_file_load
        denied(105, EPERM), // init_module
        denied(273, EPERM), // finit_module
        denied(106, EPERM), // delete_module
        denied(142, EPERM), // reboot
        // Keyring.
        denied(217, EPERM), // add_key
        denied(218, EPERM), // request_key
        denied(219, EPERM), // keyctl
        // io_uring.
        denied(425, EPERM), // io_uring_setup
        denied(426, EPERM), // io_uring_enter
        denied(427, EPERM), // io_uring_register
        // Misc escape surface.
        denied(282, EPERM), // userfaultfd
        denied(262, EPERM), // fanotify_init
        denied(265, EPERM), // open_by_handle_at
    ],
    clone_nr: 220,
    execveat_nr: 281,
};

/// The modelled architectures, in dispatch order.
const ARCHES: &[&ArchRules] = &[&X86_64, &AARCH64];

const fn sock_filter(code: u16, jt: u8, jf: u8, k: u32) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// Absolute 32-bit load of `seccomp_data` at `off` into the accumulator.
const fn load_abs(off: u32) -> SockFilter {
    sock_filter(BPF_LD_ABS_W, 0, 0, off)
}

/// `acc &= k`.
const fn alu_and(k: u32) -> SockFilter {
    sock_filter(BPF_ALU_AND_K, 0, 0, k)
}

/// `if acc == k { jump jt } else { jump jf }` (offsets from the next insn).
const fn jeq(k: u32, jt: u8, jf: u8) -> SockFilter {
    sock_filter(BPF_JMP_JEQ_K, jt, jf, k)
}

/// Unconditional jump `k` instructions ahead.
const fn jmp_a(k: u32) -> SockFilter {
    sock_filter(BPF_JMP_JA, 0, 0, k)
}

/// Verdict: return `SECCOMP_RET_ERRNO | errno`.
const fn ret_errno(errno: u32) -> SockFilter {
    sock_filter(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | errno)
}

/// Verdict: allow.
const fn ret_allow() -> SockFilter {
    sock_filter(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW)
}

/// Ladder instructions before the rule table: one `ld` plus, per arg
/// filter, a `jeq` on the syscall number and the 4-instruction flag check.
const fn ladder_fixed() -> usize {
    1 + 2 * 5 // ld nr; clone filter (5) + execveat filter (5)
}

/// Compiled ladder length for `rules`.
const fn ladder_len(rules: &ArchRules) -> usize {
    ladder_fixed() + 2 * rules.socket_family.len() + 2 * rules.escape_surface.len() + 1
    // trailing ja → allow
}

// Classic-BPF jumps are forward-only u8 offsets relative to the next
// instruction, so the JEQ chain must reach the last ladder and its
// fall-through target within one byte each. The largest such distance is
// `sum of all ladder lengths` (from the first JEQ to the unknown-arch deny);
// the const assert turns any future table growth that could overflow it into
// a compile error, which is why no runtime guard is needed on the casts in
// [`assemble`].
const _: () = assert!(
    ladder_len(&X86_64) + ladder_len(&AARCH64) < 256,
    "arch JEQ chain would exceed u8 jump range; split the ladder"
);

/// Ladder body for one architecture: load `nr`, deny each listed rule, then
/// the two arg filters (`clone`'s namespace flags, `execveat`'s
/// `AT_EMPTY_PATH`). The caller appends the jump-to-allow.
fn ladder(rules: &ArchRules) -> Vec<SockFilter> {
    let rules_len = rules.socket_family.len() + rules.escape_surface.len();
    let mut out = Vec::with_capacity(ladder_fixed() + 2 * rules_len);
    out.push(load_abs(OFF_NR));
    for rule in rules
        .socket_family
        .iter()
        .chain(rules.escape_surface.iter())
    {
        out.push(jeq(rule.nr, 0, 1));
        out.push(ret_errno(rule.errno));
    }
    // clone(flags, …): flags are args[0]; deny exactly the CLONE_NEW* mask.
    // The nr check gates the flag inspection, so any other syscall falls
    // through (a plain clone keeps its flags untouched and is allowed).
    out.extend([
        jeq(rules.clone_nr, 0, 4),
        load_abs(OFF_ARGS),
        alu_and(CLONE_NEW_MASK),
        jeq(0, 1, 0),
        ret_errno(EPERM),
    ]);
    // execveat(…, flags): flags are args[4]; deny AT_EMPTY_PATH, gated on nr
    // the same way.
    out.extend([
        jeq(rules.execveat_nr, 0, 4),
        load_abs(OFF_ARGS + 4 * 8),
        alu_and(AT_EMPTY_PATH),
        jeq(0, 1, 0),
        ret_errno(EPERM),
    ]);
    out
}

/// Assemble the arch-guarded ladder:
///
/// ```text
///   ld [arch]
///   jeq x86_64 → ladder_x86   (else fall through)
///   jeq aarch64 → ladder_arm  (else → deny_unknown_arch)
///   ladder_x86 … ja → allow
///   ladder_arm … ja → allow
///   deny_unknown_arch: ret ENOSYS
///   allow: ret SECCOMP_RET_ALLOW
/// ```
///
/// The guard runs before any allow exists, so an unmodelled ABI (including
/// x32) gets `−ENOSYS` for *everything* — fail closed.
fn assemble(arches: &[&ArchRules]) -> BpfProgram {
    let ladders: Vec<Vec<SockFilter>> = arches.iter().map(|rules| ladder(rules)).collect();
    let header_len = 1 + arches.len(); // ld + one jeq per arch
    let mut starts = Vec::with_capacity(arches.len());
    let mut end = header_len;
    for ladder_body in &ladders {
        starts.push(end);
        // +1: the trailing ja → allow appended to each ladder below.
        end += ladder_body.len() + 1;
    }
    let deny_unknown = end;
    let allow = end + 1;

    let total: usize = arches.iter().map(|rules| ladder_len(rules)).sum();
    let mut program = BpfProgram::with_capacity(header_len + total + 2);
    program.push(load_abs(OFF_ARCH));
    for ((i, rules), start) in arches.iter().enumerate().zip(starts.iter()) {
        // Jump offsets are relative to the instruction after the jump, at
        // position `here`; the const assert above bounds every distance.
        let here = 1 + i + 1;
        let jt = (*start - here) as u8;
        let jf = if i + 1 < arches.len() {
            0 // false arm falls through to the next arch check
        } else {
            (deny_unknown - here) as u8
        };
        program.push(jeq(rules.audit_arch, jt, jf));
    }
    // Append each ladder at its jump target; the running program length
    // tracks where the next ladder starts.
    let mut next_start = header_len;
    for mut ladder_body in ladders {
        // The ja sits after the ladder body; its offset counts from the
        // instruction after itself.
        let after_ja = next_start + ladder_body.len() + 1;
        ladder_body.push(jmp_a((allow - after_ja) as u32));
        program.append(&mut ladder_body);
        next_start = program.len();
    }
    program.push(ret_errno(ENOSYS));
    program.push(ret_allow());
    program
}

/// The default tier's seccomp policy (§3.1): the §1 denylist.
#[derive(Clone, Copy, Debug)]
pub struct Denylist {
    network: NetworkMode,
}

impl Denylist {
    /// Build the policy for `network`. See [`NetworkMode`] for why a port
    /// grant compiles the same ladder as no network at all.
    #[must_use]
    pub fn new(network: NetworkMode) -> Self {
        Self { network }
    }
}

impl SeccompFilter for Denylist {
    fn bpf_program(&self) -> BpfProgram {
        match self.network {
            // One shape per tier: `None` denies the whole socket family, and
            // a grant (which this tier cannot express) gets the same ladder
            // rather than a wider one.
            NetworkMode::None | NetworkMode::Granted => assemble(ARCHES),
        }
    }
}

/// The seam between policy (pure data, testable on any host) and application
/// (the kernel call, Linux-only). Internal to this crate's design: the
/// hand-assembled [`Denylist`] is the committed implementation; a reviewed
/// external assembler could land behind this trait without touching callers.
pub trait SeccompFilter {
    /// The filter as pure data — no kernel involvement, testable anywhere.
    fn bpf_program(&self) -> BpfProgram;

    /// Install the filter on the current thread: `prctl(PR_SET_NO_NEW_PRIVS)`
    /// first (so an unprivileged caller may install), then one
    /// `seccomp(SECCOMP_SET_MODE_FILTER)`. Any failure is returned, never
    /// ignored — a caller that cannot filter must refuse to spawn.
    #[cfg(target_os = "linux")]
    fn apply(&self) -> Result<(), ApplyError> {
        sys::apply(&self.bpf_program())
    }
}

/// Why an apply failed, named by the step that refused (fail closed: the
/// caller must treat every variant as "do not exec unfiltered").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyError {
    /// `prctl(PR_SET_NO_NEW_PRIVS)` failed — install would be refused anyway.
    NoNewPrivs,
    /// `seccomp(SECCOMP_SET_MODE_FILTER)` failed (or the program shape was
    /// refused before the call).
    Install,
    /// This host architecture is not modelled; no filter is attempted at all.
    UnsupportedArch,
}

#[cfg(target_os = "linux")]
mod sys {
    use super::{ApplyError, SockFilter};
    use core::ffi::c_long;

    /// `seccomp(2)` operation: install a filter.
    const SECCOMP_SET_MODE_FILTER: c_long = 1;
    /// `prctl(2)` option: never gain privileges via exec (filter prerequisite).
    const PR_SET_NO_NEW_PRIVS: c_long = 38;
    /// Kernel instruction cap (`BPF_MAXINSNS`); refused before the call.
    const BPF_MAXINSNS: usize = 4096;

    // syscall(2) numbers per host architecture (gnu/b64 tables; S-Lc).
    #[cfg(target_arch = "x86_64")]
    const SYS_PRCTL: c_long = 157;
    #[cfg(target_arch = "x86_64")]
    const SYS_SECCOMP: c_long = 317;
    #[cfg(target_arch = "aarch64")]
    const SYS_PRCTL: c_long = 167;
    #[cfg(target_arch = "aarch64")]
    const SYS_SECCOMP: c_long = 277;

    /// `struct sock_fprog`, as the kernel reads it.
    #[repr(C)]
    struct SockFProg {
        len: u16,
        filter: *const SockFilter,
    }

    extern "C" {
        fn syscall(num: c_long, ...) -> c_long;
    }

    /// The crate's single production `unsafe` site: the one filter apply.
    pub(super) fn apply(program: &[SockFilter]) -> Result<(), ApplyError> {
        if program.is_empty() || program.len() > BPF_MAXINSNS {
            return Err(ApplyError::Install);
        }
        let fprog = SockFProg {
            len: u16::try_from(program.len()).map_err(|_| ApplyError::Install)?,
            filter: program.as_ptr(),
        };
        // SAFETY: the ONE FFI apply of the default tier (slice S-Lc). Two raw
        // `syscall(2)` calls with immediate arguments: `prctl
        // (PR_SET_NO_NEW_PRIVS)` so an unprivileged caller may install, then
        // `seccomp(SECCOMP_SET_MODE_FILTER)` handed a pointer to a
        // `#[repr(C)]` program the kernel only reads. Neither call writes
        // through any pointer we own; every failure path returns an error so
        // a caller can refuse to exec unfiltered. Only reached on host
        // architectures with verified syscall numbers (see the SYS_* cfgs).
        let rc = unsafe {
            if syscall(SYS_PRCTL, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(ApplyError::NoNewPrivs);
            }
            syscall(
                SYS_SECCOMP,
                SECCOMP_SET_MODE_FILTER,
                0, // flags: the child installs before exec, single-threaded
                core::ptr::from_ref(&fprog) as usize as c_long,
            )
        };
        if rc != 0 {
            Err(ApplyError::Install)
        } else {
            Ok(())
        }
    }
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
mod sys {
    use super::{ApplyError, SockFilter};

    /// Unmodelled host architecture: refuse before touching the kernel.
    pub(super) fn apply(_program: &[SockFilter]) -> Result<(), ApplyError> {
        Err(ApplyError::UnsupportedArch)
    }
}

impl LinuxBackend {
    /// The default tier's seccomp policy: the §1 denylist (slice S-Lc).
    #[must_use]
    pub fn seccomp_denylist(network: NetworkMode) -> Denylist {
        Denylist::new(network)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sentinel the evaluator returns for "malformed program / fell off the
    /// end": no real verdict equals it, so any assert fails loudly.
    const MALFORMED: u32 = u32::MAX;

    /// A tiny classic-BPF interpreter over `struct seccomp_data` — just the
    /// opcodes [`assemble`] emits (`ld abs`, `and`, `ja`, `jeq`, `ret k`),
    /// with little-endian 32-bit word loads. Enough to execute the ladder
    /// exactly as the kernel would.
    fn eval(program: &[SockFilter], nr: u32, arch: u32, args: [u64; 6]) -> u32 {
        let word = |off: u32| -> u32 {
            match off {
                0 => nr,
                4 => arch,
                o if (OFF_ARGS..OFF_ARGS + 48).contains(&o) && o % 4 == 0 => {
                    let slot = (o - OFF_ARGS) / 8;
                    let value = args[slot as usize];
                    if (o - OFF_ARGS) % 8 == 0 {
                        value as u32
                    } else {
                        (value >> 32) as u32
                    }
                }
                _ => 0, // instruction-pointer words are never compared
            }
        };
        let mut acc: u32 = 0;
        let mut pc: usize = 0;
        // Any well-formed program terminates within its own length of steps.
        for _ in 0..(program.len() * 2 + 8) {
            if pc >= program.len() {
                return MALFORMED;
            }
            let insn = program[pc];
            pc += 1;
            match insn.code {
                BPF_LD_ABS_W => acc = word(insn.k),
                BPF_ALU_AND_K => acc &= insn.k,
                BPF_JMP_JA => pc += insn.k as usize,
                BPF_JMP_JEQ_K => {
                    pc += if acc == insn.k {
                        insn.jt as usize
                    } else {
                        insn.jf as usize
                    };
                }
                BPF_RET_K => return insn.k,
                _ => return MALFORMED,
            }
        }
        MALFORMED
    }

    fn program(network: NetworkMode) -> BpfProgram {
        Denylist::new(network).bpf_program()
    }

    /// The clone arg-set of a plain worker fork: `SIGCHLD | CLONE_VM |
    /// CLONE_FS` — none of which is a namespace flag.
    const CLONE_PLAIN: u64 = 0x11 | 0x0000_0100 | 0x0000_0200;

    /// Every `CLONE_NEW*` flag, individually.
    const CLONE_NEW_FLAGS: [u64; 7] = [
        0x0002_0000, // CLONE_NEWNS
        0x0200_0000, // CLONE_NEWCGROUP
        0x0400_0000, // CLONE_NEWUTS
        0x0800_0000, // CLONE_NEWIPC
        0x1000_0000, // CLONE_NEWUSER
        0x2000_0000, // CLONE_NEWPID
        0x4000_0000, // CLONE_NEWNET
    ];

    /// `AT_EMPTY_PATH` (execveat's flags arg), the arg-filtered escape.
    const EXECVEAT_EMPTY_PATH: u64 = AT_EMPTY_PATH as u64;

    fn benign_allowlist(audit_arch: u32) -> &'static [(u32, &'static str)] {
        if audit_arch == AUDIT_ARCH_X86_64 {
            &[
                (0, "read"),
                (1, "write"),
                (3, "close"),
                (9, "mmap"),
                (14, "rt_sigprocmask"),
                (56, "clone"),
                (57, "fork"),
                (59, "execve"),
                (61, "wait4"),
                (202, "futex"),
                (231, "exit_group"),
                (257, "openat"),
                (293, "pipe2"),
                (318, "getrandom"),
            ]
        } else {
            &[
                (24, "dup3"),
                (56, "openat"),
                (57, "close"),
                (59, "pipe2"),
                (63, "read"),
                (94, "exit_group"),
                (98, "futex"),
                (115, "clock_nanosleep"),
                (220, "clone"),
                (221, "execve"),
                (222, "mmap"),
                (260, "wait4"),
                (278, "getrandom"),
                (279, "memfd_create"),
            ]
        }
    }

    #[test]
    fn filter_data_denies_the_documented_syscalls() {
        for rules in ARCHES {
            let prog = program(NetworkMode::None);
            let arch = rules.audit_arch;
            for rule in rules
                .socket_family
                .iter()
                .chain(rules.escape_surface.iter())
            {
                assert_eq!(
                    eval(&prog, rule.nr, arch, [0; 6]),
                    SECCOMP_RET_ERRNO | rule.errno,
                    "arch {arch:#x}: nr {} must be denied",
                    rule.nr
                );
            }
            // Control: the worker surface stays allowed.
            for (nr, name) in benign_allowlist(arch) {
                assert_eq!(
                    eval(&prog, *nr, arch, [CLONE_PLAIN, 0, 0, 0, 0, 0]),
                    SECCOMP_RET_ALLOW,
                    "arch {arch:#x}: {name} must stay allowed"
                );
            }
        }
    }

    #[test]
    fn filter_data_is_deterministic() {
        let a = program(NetworkMode::None);
        let b = program(NetworkMode::None);
        assert_eq!(a, b, "the same policy must compile byte-identically");
        // A grant cannot widen this tier's filter: identical program.
        assert_eq!(a, program(NetworkMode::Granted));
        // And the program stays within the kernel's instruction cap.
        assert!(a.len() <= 4096);
    }

    #[test]
    fn network_syscalls_denied_at_network_none() {
        for rules in ARCHES {
            let prog = program(NetworkMode::None);
            for rule in rules.socket_family {
                assert_eq!(
                    eval(&prog, rule.nr, rules.audit_arch, [0; 6]),
                    SECCOMP_RET_ERRNO | EACCES,
                    "arch {:#x}: nr {} must answer EACCES",
                    rules.audit_arch,
                    rule.nr
                );
            }
        }
    }

    #[test]
    fn clone3_denied_and_clone_newns_flag_filtered() {
        for rules in ARCHES {
            let prog = program(NetworkMode::None);
            let arch = rules.audit_arch;
            // clone3 takes its struct behind a pointer — seccomp-blind, so it
            // is denied outright rather than arg-filtered.
            assert_eq!(
                eval(&prog, CLONE3_NR, arch, [0; 6]),
                SECCOMP_RET_ERRNO | EPERM,
                "arch {arch:#x}: clone3 must be denied outright"
            );
            // clone: each CLONE_NEW* flag denied…
            for flag in CLONE_NEW_FLAGS {
                assert_eq!(
                    eval(&prog, rules.clone_nr, arch, [flag, 0, 0, 0, 0, 0]),
                    SECCOMP_RET_ERRNO | EPERM,
                    "arch {arch:#x}: clone with flag {flag:#x} must be denied"
                );
            }
            // …the whole mask at once denied…
            let all = CLONE_NEW_FLAGS.iter().fold(0u64, |acc, f| acc | f);
            assert_eq!(
                eval(&prog, rules.clone_nr, arch, [all, 0, 0, 0, 0, 0]),
                SECCOMP_RET_ERRNO | EPERM
            );
            // …a plain worker fork allowed…
            assert_eq!(
                eval(&prog, rules.clone_nr, arch, [CLONE_PLAIN, 0, 0, 0, 0, 0]),
                SECCOMP_RET_ALLOW
            );
            // …and execveat(AT_EMPTY_PATH) denied while plain execveat is not.
            assert_eq!(
                eval(
                    &prog,
                    rules.execveat_nr,
                    arch,
                    [0, 0, 0, 0, EXECVEAT_EMPTY_PATH, 0]
                ),
                SECCOMP_RET_ERRNO | EPERM
            );
            assert_eq!(
                eval(&prog, rules.execveat_nr, arch, [0; 6]),
                SECCOMP_RET_ALLOW
            );
        }
    }

    #[test]
    fn every_jump_lands_inside_the_program() {
        for network in [NetworkMode::None, NetworkMode::Granted] {
            let prog = program(network);
            for (i, insn) in prog.iter().enumerate() {
                match insn.code {
                    BPF_JMP_JA => assert!(
                        i + 1 + (insn.k as usize) < prog.len(),
                        "ja at {i} lands outside the program"
                    ),
                    BPF_JMP_JEQ_K => {
                        assert!(
                            i + 1 + (insn.jt as usize) < prog.len(),
                            "jeq jt at {i} lands outside the program"
                        );
                        assert!(
                            i + 1 + (insn.jf as usize) < prog.len(),
                            "jeq jf at {i} lands outside the program"
                        );
                    }
                    BPF_RET_K => {}
                    BPF_LD_ABS_W | BPF_ALU_AND_K => {}
                    other => assert_eq!(
                        other, 0,
                        "unexpected opcode {other:#x} at {i} (0 never occurs)"
                    ),
                }
            }
            assert_eq!(*prog.last().expect("non-empty"), ret_allow());
        }
    }

    #[test]
    fn an_unknown_audit_arch_is_refused_fail_closed() {
        let prog = program(NetworkMode::None);
        // A made-up arch…
        assert_eq!(
            eval(&prog, 59 /* execve */, 0xdead_beef, [0; 6]),
            SECCOMP_RET_ERRNO | ENOSYS
        );
        // …and the real x32 ABI, whose low bit differs from x86_64's.
        assert_eq!(
            eval(&prog, 59, 0x4000_003e, [0; 6]),
            SECCOMP_RET_ERRNO | ENOSYS
        );
    }
}
