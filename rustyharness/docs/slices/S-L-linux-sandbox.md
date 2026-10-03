# S-L: the Linux confinement backend (Landlock + seccomp), design note + slice cards

Status: DESIGN NOTE + implementable slice cards. No product code lands here. The mechanism is owner
decision **D29** (Q-17), still open; this note proposes the fail-closed default and the slices that
build it. Resolves the `linux.rs` "facts only, never mints" state (`crates/harness-sandbox/src/linux.rs`)
into a backend that passes the same hostile-task suite the macOS Seatbelt backend passes, or refuses.

Read first: `README.md`, `docs/ROADMAP-parity.md` §3 gap 26 / §3.3 S-L / §4.1, `docs/01-design-v0.1.md`
§6 (INV-6, §6.1–§6.7), `docs/slices/P-36-background-processes.md` §8 (the backend-neutral contract),
`crates/harness-sandbox/src/{lib.rs,linux.rs,confine_spawn.rs,profile.rs,conformance.rs,spec.rs,seatbelt.rs}`,
`deny.toml`, `scripts/ci/purity.sh`.

Every API name below already exists in the crate unless marked NEW. The guiding invariant is INV-6: **no
containment, no execution.** There is no "run unconfined and record it" tier. Everything a confined child
gets is granted explicitly; everything else is denied.

---

## 0. Decisions at a glance (each with its fail-closed default)

| # | Decision | Default taken here (fail closed) |
|---|---|---|
| L-D1 | Mechanism | Namespace-less **Landlock (ABI 1–4+) + seccomp-bpf + no_new_privs + rlimits + process-group/subreaper kill**, as rustysuite AQ-208. Unprivileged user/net/pid/mount namespaces are an **opt-in stronger tier**, used only where the host offers them; never required. |
| L-D2 | `unsafe` | Confined to a new `harness-sandbox-linux` crate (design §6.7 pattern), `allow(unsafe_code)` with `// SAFETY:` per site and a CI ratchet. `harness-sandbox` stays `#![forbid(unsafe_code)]`. |
| L-D3 | Dependencies | `landlock` (0.4.x), `seccompiler` (0.5.x) or a hand-assembled BPF filter, `rustix` (process/thread/fs, libc backend), `libc`. Minimum justified in §2. |
| L-D4 | Landlock gaps (no netns) | Closed by **seccomp** denying the socket families Landlock cannot (`socket()` for everything but `AF_UNIX`/`AF_INET`-loopback as granted), or documented as a limit with the host fact recorded. |
| L-D5 | Degrade | If the kernel lacks the needed Landlock ABI, or seccomp `SECCOMP_RET_KILL_PROCESS` is unavailable, or no_new_privs cannot be set: **refuse** (`Unavailable`), never run weaker. |
| L-D6 | Verification | Runtime tests run in a real Linux VM (aarch64 under UTM/QEMU, over ssh), driven by a NEW `rh-dev linux` subcommand. macOS-only `cargo check --target` is not a pass; the matrix row is committed only when the suite is green on a real kernel. |
| L-D7 | Journal | A `backend` object records `kind=linux`, the Landlock ABI applied, the seccomp action and rule-set id, the kill domain and the host-facts digest, all replay-verifiable. |

---

## 1. Threat-model parity: each macOS guarantee → the Linux mechanism that gives it

The macOS backend's guarantees are the behaviours its conformance suite (`tests/conformance_macos.rs`,
through `require()` + the live probe) witnesses. The Linux backend must witness the same `Case` ids
(`crates/harness-sandbox/src/conformance.rs`). Column 3 is the Linux mechanism; column 4 is the gap, if
any, and how it is closed.

| Guarantee (macOS) | Case ids | Linux mechanism | Gap / closure |
|---|---|---|---|
| **No network** — no connect, bind, listen, unix-socket connect, DNS | FT-1, FT-2, FT-11, FT-13, FT-15, D31-no-bind | **seccomp denies `socket(2)`** for every domain except what a grant allows. Default (`Network::None`): `socket` → `EACCES`/`SECCOMP_RET_ERRNO` for `AF_INET`,`AF_INET6`,`AF_UNIX`,`AF_PACKET`,`AF_NETLINK`,… so nothing can open any socket at all. Also deny `connect`,`bind`,`listen`,`accept*`,`sendto`,`recvfrom`,`socketpair`. | Landlock ABI < 4 has **no** network rules; ABI 4 adds only `bind`/`connect` **TCP** (`AccessNet::BindTcp`/`ConnectTcp`), and even at ABI 4 it is subject to erratum 1 (non-TCP stream sockets mis-restricted). UDP, unix-socket **paths**, and raw/packet sockets are **not** expressible in Landlock before ABI 6 / not at all. **Closed by seccomp**, which is domain-aware at the `socket()` boundary and needs no netns. The empty-netns opt-in tier (L-D1) closes it a second way where available. |
| **Filesystem read allowlist** — only system trees, devices, and granted roots readable; home/state/secret canary unreadable | FT-4, FT-10 | **Landlock** ruleset: `AccessFs::{ReadFile,ReadDir}` granted on exactly the system-read trees (`/usr`,`/lib`,`/bin`,`/etc` as needed by the toolchain), the device reads (`/dev/null`,`/dev/zero`,`/dev/random`,`/dev/urandom`), and the spec's `read_only`+`read_write` roots. Everything else, including `$HOME`, `state_root`, the trust base, has **no** rule → denied by Landlock's deny-by-default on handled accesses. | Landlock is path-handle based (`PathFd`), so it is immune to `..`/symlink games that defeat string matching (§4). Ancestors need no read rule (unlike SBPL metadata allows). No gap. |
| **Filesystem write allowlist** — writes only under read-write roots and `/dev/null`; writes outside leave nothing | FT-3, FT-7 | **Landlock** `AccessFs::{WriteFile,Truncate (ABI 3),MakeReg,MakeDir,RemoveFile,RemoveDir,…}` on the `read_write` roots only. `read_only` roots get read rights but **not** write rights. | FT-7 (file-size cap) is **`RLIMIT_FSIZE`** via `rustix::process::setrlimit`, not Landlock. No gap. |
| **Protected paths read-only** — `.git`, tests, lockfiles under a writable workspace are not writable | FT-9, hard-link | The `protected` dirs (from `harness-tools::protected`, P-29) are added to the ruleset with **read rights only**, after/inside the read-write root. Landlock evaluates the most specific path rule, so a read-only rule on `<ws>/.git` beats the writable rule on `<ws>`. | macOS does this with SBPL rule ordering; Landlock does it with path specificity — same result. Hard-link from outside: Landlock `AccessFs::Refer` (ABI 2) governs linking/renaming across directories; denying `Refer` outside the rw roots blocks aliasing an outside file in. No gap. |
| **No setuid / privilege escalation via exec** | (FT-4 secrets, LD_PRELOAD §4) | **`no_new_privs`** (`PR_SET_NO_NEW_PRIVS`, set by the `landlock` crate by default and independently by us before seccomp). A setuid binary exec'd under no_new_privs does not gain privilege; seccomp and Landlock survive exec. | Plus a built `env` (no `LD_PRELOAD`/`LD_*`; already enforced by `spec::validate`, INV-10). No gap. |
| **Process-tree containment & reliable kill ("every command process is gone")** | FT-5, FT-8, FT-16, FT-16-setsid | **Default tier:** the harness is the subreaper (`PR_SET_CHILD_SUBREAPER` via `rustix::process::set_child_subreaper`); the launched program runs in its **own process group** (`setpgid`), and the launcher re-execs as `rustyharness __confine` holding a **pidfd** (`pidfd_open`) of the child and a control pipe. Stop = kill the process group (`kill(-pgid, SIGKILL)` via `rustix::process::kill_process_group`) and reap; crash = the control-pipe EOF + `PR_SET_PDEATHSIG` on the helper means the kernel signals the helper, which sweeps. A `setsid()` escapee leaves the group, so the subreaper still reaps it and the sweep re-scans descendants from the subreaper's child list. **Opt-in tier:** an unprivileged **PID namespace** makes the helper the namespace `init`; killing it kills the whole namespace atomically — no setsid escape possible, no R-1 orphan gap (P-36 §8 point 2). | macOS relies on a Seatbelt `signal (target same-sandbox)` kernel filter + pid-range sweep; it has a named residual (a member can kill the stub first → `Unconfirmed` → group kill). Linux's subreaper+pgid is strictly better at the default tier (the subreaper cannot be killed by a confined child it is not in the group of), and the PID-namespace tier removes the residual entirely. This is the one place Linux is *stronger* than macOS. |
| **Memory bound** | FT-6 | Default: **`RLIMIT_AS`** per process via `setrlimit` (the macOS bar, `MemoryGuard::LinuxCgroupMax` is the opt-in whole-tree bar). Opt-in: cgroup v2 `memory.max` on a delegated subtree → `MemoryGuard::LinuxCgroupMax`. | `RLIMIT_AS` bounds each process; with the process cap it bounds the tree, exactly as macOS argues. cgroup is the strictly-better whole-tree bound where a delegated subtree exists. |
| **Process-count bound** | FT-5 | Default: **`RLIMIT_NPROC`** — and on Linux this *is* per-process-tree-usable via the per-user count, but the honest per-sandbox bound at the default tier is still a member-count watchdog over the subreaper's descendants (`ProcessGuard::LinuxPidsMax` only when cgroup is used). Opt-in: cgroup v2 **`pids.max`** → a hard kernel bound (`ProcessGuard::LinuxPidsMax`). | `RLIMIT_NPROC` is per-UID like macOS, so same caveat; cgroup `pids.max` is the strong bar. The existing `ProcessGuard`/`MemoryGuard` enum variants (`LinuxPidsMax`, `LinuxCgroupMax`) already exist in `lib.rs` for this. |
| **Wall-clock kill** | FT-8 | Harness-side deadline (same as macOS: `confine_spawn`'s deadline closer), plus `RLIMIT_CPU` for CPU time. | No gap. |
| **LaunchServices / keychain unreachable** | FT-17, FT-18 | macOS-specific (mach services). On Linux the analogues are the **kernel keyring** (`keyctl`,`add_key`,`request_key`) and D-Bus/credential sockets: seccomp denies the keyring syscalls; the credential sockets are unreachable because `socket(AF_UNIX)` is denied and the paths are not in the Landlock read set. Design §6.6 FT-18 already says "Linux: keyring syscalls refused". | Cases FT-17/FT-18 stay in the matrix as the same ids; their Linux realisation is keyring+socket denial. No gap. |
| **Nested sandbox cannot be loosened / escaped** | nested-sandbox | A confined process cannot widen its own Landlock domain (Landlock domains only ever **narrow**: a child `restrict_self` adds restrictions, never removes), cannot clear no_new_privs, and cannot install a weaker seccomp (seccomp filters only stack). So it can neither loosen its profile nor leave its kill domain. | Direct Linux analogue of the Seatbelt "profile fixed for life" property. No gap. |
| **Ports (P-36a), loopback bind/connect grants** | PORTS_* | Opt-in **PID+net namespace tier** with a harness forwarder (P-36 §8 point 3): host `127.0.0.1:<p>` ⇄ bind-mounted unix socket ⇄ `127.0.0.1:<p>` inside the netns. At the **namespace-less default tier**, loopback-port grants require a seccomp policy that allows `socket(AF_INET, SOCK_STREAM)` + `bind`/`connect` only to `127.0.0.1:<granted>` — but seccomp **cannot inspect the sockaddr** (it is behind a pointer; seccomp sees only scalar args). So **ports are refused at the default tier** and available only at the netns tier. | This is the one guarantee the namespace-less tier **cannot** give (seccomp's pointer-argument blindness). Documented as a limit: `PORTS_CASES` are listed on the Linux row **only** for the netns tier; `Network::Loopback` validation refuses on a default-tier witness (the existing `ev.covers(PORTS_CASES)` gate already enforces this). |

### What Landlock cannot do (be explicit)

- **ABI < 4: no network control at all.** Any network guarantee on such kernels is seccomp's alone.
- **ABI 4: TCP `bind`/`connect` only.** No UDP, no unix-socket **path** rules, no raw/packet sockets.
  Erratum 1 (ABI 4) mis-restricts non-TCP stream sockets (SMC/MPTCP/SCTP) under the TCP rights.
- **ABI < 6: no unix-socket scoping, no signal scoping (IPC).** `Scope::AbstractUnixSocket` and
  `Scope::Signal` appear only at ABI 6 (`landlock::Scope`, `scope.rs`). So **abstract unix sockets**
  and **cross-domain signals** are not Landlock-controllable before ABI 6.
- **No syscall filtering.** Landlock is filesystem + (ABI4+) TCP + (ABI6+) scopes only; `ptrace`,
  `io_uring`, `mount`, `unshare`, `kexec`, `bpf`, `perf_event_open`, `memfd_create`, the keyring, and
  `socket()` family selection are **seccomp's** job.

Every one of those gaps is closed by seccomp or the netns tier, or (ports at default tier) documented
as a refusal, never a silent allow.

### The seccomp denylist (namespace-less default tier)

A denylist of dangerous syscalls layered under `SECCOMP_RET_ERRNO`/`SECCOMP_RET_KILL_PROCESS`, applied
**after** no_new_privs and the Landlock ruleset, **last** before exec (like the macOS stub's order):

- **Network:** `socket`, `socketpair`, `connect`, `bind`, `listen`, `accept`, `accept4`, `sendto`,
  `recvfrom`, `sendmsg`, `recvmsg`, `getsockopt`, `setsockopt` — all → `EACCES` at `Network::None`.
- **Namespace / privilege:** `unshare`, `setns`, `clone`/`clone3` with `CLONE_NEW*` flags (arg-filtered on
  the flags scalar — this *is* seccomp-visible), `mount`, `umount2`, `pivot_root`, `chroot`,
  `setuid`/`setgid` family where disallowed.
- **Debug / introspection:** `ptrace`, `process_vm_readv`, `process_vm_writev`, `perf_event_open`,
  `bpf`, `kcmp`.
- **Kernel / module:** `kexec_load`, `kexec_file_load`, `init_module`, `finit_module`, `delete_module`,
  `reboot`.
- **Keyring (FT-18):** `add_key`, `request_key`, `keyctl`.
- **io_uring (a well-known seccomp bypass surface):** `io_uring_setup`, `io_uring_enter`,
  `io_uring_register` — denied, because an io_uring ring can perform file/network ops that never pass
  through the filtered syscalls.
- **Misc escape surface:** `userfaultfd`, `fanotify_init`, `open_by_handle_at` (bypasses path-based
  Landlock via file handles), `memfd_create` + exec is handled by Landlock exec rights on the resulting
  fd path (an anonymous memfd has no path in the read set, so `execveat` of it is denied by Landlock's
  `AccessFs::Execute` absence; seccomp need not special-case it, but we deny `execveat(AT_EMPTY_PATH)`
  belt-and-braces).

`clone3`'s struct argument is behind a pointer (seccomp-blind), so the `CLONE_NEW*` arg-filter works on
`clone` but **not** `clone3`; `clone3` is therefore denied outright (programs fall back to `clone`),
which is the fail-closed choice.

---

## 2. Dependency decision (justified against deny.toml and purity.sh)

The purity gate (`scripts/ci/purity.sh` §5) requires **every lib/bin root** to open with
`#![forbid(unsafe_code)]` and allowlists exactly the reviewed crates.io crates; `deny.toml` allows only
`Apache-2.0`, `MIT`, `Unicode-3.0`, `PolyForm-Noncommercial-1.0.0`. Any new crate must clear both. All
candidate sources are already vendored in `~/.cargo/registry` (verified).

**Recommendation — minimum set, in a new `harness-sandbox-linux` crate only:**

| Crate | Ver | Licence | Why it earns its place | Alternative considered |
|---|---|---|---|---|
| `landlock` | 0.4.7 | MIT OR Apache-2.0 | Safe, typed wrapper over the Landlock uAPI; handles ABI compatibility (`ABI::V1..V9`, `CompatLevel`), sets `no_new_privs` by default, uses `PathFd` (O_PATH handles, immune to TOCTOU). Re-implementing it by hand is ~300 lines of `unsafe` syscall plumbing for no safety gain. Pulls `enumflags2` (MIT/Apache), `libc`, `thiserror` (already allowed). No build script. | Hand-rolled Landlock via raw `landlock_create_ruleset`/`add_rule`/`restrict_self` syscalls: more `unsafe`, more to get wrong on ABI degrade. Rejected. |
| `rustix` | 1.1.x | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | **Safe** wrappers for every process/thread primitive we need, verified present: `set_child_subreaper`, `set_parent_process_death_signal` (PDEATHSIG), `set_no_new_privs`, `setrlimit`, `pidfd_open`, `pidfd_send_signal`, `kill_process`, `kill_process_group`, `waitpid`/`waitid`, `unshare` (opt-in tier). Features `process,thread,fs,pipe,std` with the **libc backend** (`rustix_use_libc`) to avoid its inline-asm linux-raw path (keeps the "no assembly" purity posture). Has a `build.rs` (cfg probing only) — see purity note below. | `nix`: heavier, less granular features, also present (0.29). `rustix` is the leaner, more auditable choice. |
| `seccompiler` | 0.5.0 | Apache-2.0 OR BSD-3-Clause | Firecracker's seccomp-BPF assembler: builds a `BpfProgram` (`Vec<sock_filter>`) from a rule table and applies it with `apply_filter` (one `prctl(PR_SET_NO_NEW_PRIVS)` + one `seccomp(2)` with TSYNC). Pure Rust, no build script, default features (no serde). | **Hand-assembled BPF** (see below). |
| `libc` | 0.2 | MIT OR Apache-2.0 | Already on the purity allowlist (used by `cpufeatures`/sha2). Provides syscall numbers and `sock_filter` constants. | — |
| `enumflags2` | 0.7.12 | MIT OR Apache-2.0 | Transitive (landlock). No build script. | — |

**BSD-3-Clause** is not in today's `deny.toml` `allow` list; `seccompiler` is `Apache-2.0 OR
BSD-3-Clause`, so cargo-deny picks `Apache-2.0` and **no licence change is needed**. (If a future
seccompiler drops the Apache option, the hand-assembled path below removes the dependency entirely.)

**The hand-assembled-filter option (fallback, and arguably the primary choice).** A seccomp filter is a
classic-BPF program over `struct seccomp_data` (arch, nr, 6 scalar args). The denylist in §1 is ~40
syscalls plus one `clone` flag check — about **~100 lines of safe Rust data** building a `Vec<sock_filter>`
(a `jump-if-nr-equals → RET_ERRNO` ladder with an arch guard), applied by **one** `seccomp(SECCOMP_SET_MODE_FILTER,
SECCOMP_FILTER_FLAG_TSYNC, &prog)` syscall. That single syscall is the only `unsafe` needed for seccomp.
**Recommendation:** start with `seccompiler` (audited, used by Firecracker/QEMU-microvm) to get the
suite green fast; keep the hand-assembled module behind the same internal trait so the dependency can be
dropped after review if the owner prefers zero seccomp deps (owner question L-Q4). Either way the BPF
**data** is pure Rust; only the apply is `unsafe`.

**purity.sh / deny.toml changes required (enumerated so a slice can make them, under review):**

1. §5 root scan: `harness-sandbox-linux/src/lib.rs` must be allowed to open with
   `#![allow(unsafe_code)]` instead of `#![forbid(...)]`. Add it as the single named exception
   (mirroring the planned `harness-sandbox-windows` exception, design §6.7), with an `unsafe`-site
   **ratchet count** that may only fall without review.
2. §5 registry allowlist: add `landlock`, `rustix`, `seccompiler`, `enumflags2`, `linux-raw-sys`
   (if the raw backend is ever enabled — default is libc backend, so ideally not), `bitflags`,
   `errno`/`libc_errno` (rustix transitive). Each with a one-line reason: "Linux confinement
   primitives; `unsafe` confined to harness-sandbox-linux; no network/process API reaches the agent."
3. §5 build-script ban: `rustix` ships a `build.rs`. The gate currently forbids build scripts. Options:
   (a) enable `rustix`'s `RUSTFLAGS`-cfg-free mode / pin `--cfg rustix_use_libc` so the script only
   probes cfgs (it emits no code and links nothing), and **narrow** the ban to "no build script that
   generates code or adds linker args," verified by reading rustix's `build.rs` (it only `println!`s
   `cargo::rustc-check-cfg`/`cfg`); or (b) prefer `nix` (no build script) if the gate reviewer wants the
   ban kept absolute. **This is owner question L-Q2.** Fail-closed default: keep the absolute build-script
   ban and use the hand-assembled seccomp + a thinner primitive crate (`nix` or raw `libc`) if `rustix`'s
   build.rs cannot be admitted.
4. `deny.toml`: `multiple-versions = "warn"` already; `bitflags` 1.x/2.x may both appear — acceptable as a
   warn. No licence list change (all picks resolve to MIT/Apache).

No change to `harness-sandbox`'s own `Cargo.toml` dependency shape except an optional
`[target.'cfg(target_os="linux")'.dependencies] harness-sandbox-linux = { path = ... }`, so the macOS and
other-OS builds pull **none** of it.

---

## 3. Module layout, API, error taxonomy, the probe, and the journal

### 3.1 Crates and modules

```
crates/harness-sandbox/                 # unchanged: #![forbid(unsafe_code)], the Backend trait, Conformed,
  src/linux.rs                          #   HostFacts stays; its Backend::probe() now DELEGATES to the
                                        #   linux crate when target_os=linux and facts permit, else refuses.
crates/harness-sandbox-linux/           # NEW. #![allow(unsafe_code)] (ratcheted). target_os=linux only.
  src/lib.rs                            #   pub struct LinuxBackend; impl the private spawn.
  src/landlock_rules.rs                 #   Validated spec -> landlock Ruleset (ABI-aware, best-effort DISABLED:
                                        #     we HARD-require the ABI we need; degrade = refuse, L-D5).
  src/seccomp.rs                        #   the denylist -> BpfProgram (data) + one apply syscall.
  src/supervisor.rs                     #   subreaper, pidfd, pgid, control pipe, PDEATHSIG, sweep, reap.
  src/namespaces.rs                     #   OPT-IN tier: userns/netns/pidns/mountns + forwarder hook.
  src/probe.rs                          #   the live self-probe child (canary write/connect/read).
```

The pure window/ring code (`ring.rs`) and the fileop codec (`fileop/proto.rs`) are already
backend-neutral in `harness-sandbox` (P-36b moved them there for exactly this reason), so the Linux
live child reuses them unchanged.

### 3.2 The trait the backend satisfies (so `harness-run` is unchanged)

Nothing in `harness-run` changes. `harness-sandbox::linux::Linux` keeps implementing the existing
`Backend` trait (`lib.rs`): `kind() -> BackendKind::Linux`, `probe() -> Result<Conformed, Unavailable>`,
`spawn(spec, &Conformed)`, `spawn_live(spec, &Conformed, &LiveOpts)`. `SystemConfinement` already routes
`cfg(not(any(macos,windows)))` to `linux::Linux` for `require`/`spawn`/`spawn_live`. The only change is
that `Linux::probe()` stops unconditionally returning `NotBuilt` and instead:

1. measures `HostFacts` (already implemented, read-only `/proc`,`/sys`);
2. decides the tier (namespace-less default vs netns opt-in) from the facts;
3. if the required primitives are absent → `Unavailable` with the typed reason (never a weaker run);
4. otherwise delegates to `harness_sandbox_linux::LinuxBackend::probe_live(tier)`, which runs the live
   self-probe (§3.4) and, on success, mints `Conformed` via `Conformed::mint(row, digest)` — the same
   crate-private mint the macOS backend uses (INV-15 preserved: only a `probe()` mints).

`Conformed`'s fields (`backend`, `matrix_row`, `cases`, `network`, `kill_domain`, `memory`, `processes`,
`probe_digest`) already carry Linux variants (`NetworkMechanism::{LinuxNetNamespace,LinuxLandlockSeccomp}`,
`KillDomain::{LinuxPidNamespace,LinuxCgroup}`, `MemoryGuard::LinuxCgroupMax`, `ProcessGuard::LinuxPidsMax`).
The matrix row (§3.5) chooses which.

### 3.3 Error taxonomy

Reuse `UnavailableReason` unchanged; map Linux failures onto it:

- `MatrixRowMissing` — no committed Linux row for this tier yet (the state until the suite is green).
- `MatrixRowIncomplete { missing }` — row exists but lacks cases a caller requires (e.g. a default-tier
  row asked for `PORTS_CASES`).
- `PrimitiveMissing(&'static str)` — `"landlock-abi"`, `"seccomp-kill"`, `"no_new_privs"`, `"pidfd"`.
- `LiveProbeFailed { probe, observed }` — a canary that was **not** refused (an escape). Final at once,
  never retried (matches `seatbelt.rs` H2f: load-shaped failures retry, escapes do not).
- `NotBuilt { facts }` — only on non-linux targets / before the crate exists.
- `Io(String)` — probe plumbing failure (retryable, load-shaped).

`SpawnError` (`Spec`, `WrongWitness`, `Io`) is unchanged.

### 3.4 `exec refuses off macOS` → `exec works on Linux when the probe passes`

The whole gate is `require()` (`lib.rs`) → `linux::Linux.probe()`. Today `probe()` returns `NotBuilt`, so
`require()` refuses on Linux (`RunRefused::Confinement`, CLI exit 3). After S-L:

- `probe()` returns `Conformed` **iff** (a) a committed matrix row covers `H2_EXIT_CASES` for this tier
  **and** (b) the live self-probe actually **applied the sandbox in a child and the child's canaries were
  refused**. The probe child (`probe.rs`) is spawned through the **same** spawn path as a real call
  (`supervisor.rs`), applies Landlock+seccomp+rlimits, then attempts: a TCP connect to a harness-held
  loopback listener (must fail, listener sees nothing — FT-1); a `bind` (must fail — D31); a write outside
  the roots (must fail, file absent after — FT-3); a read of a planted `.ssh`-shaped canary outside the
  roots and following a workspace symlink to it (must fail — FT-4/FT-12); the built env is exactly the
  spec's (FT-4 env); a benign `/usr/bin` program (`uname`, prints `Linux`) must run (control, so a refusal
  is not just a broken exec); a fork bomb bounded by the process guard and a memory bomb by the memory
  guard (FT-5/FT-6); a `setsid()` grandchild is swept (FT-16-setsid). **Fail closed:** any canary not
  refused → `LiveProbeFailed`, no witness, exec refuses.
- Degrade is refusal, not weakening (L-D5): a kernel without the needed Landlock ABI, or without
  `SECCOMP_RET_KILL_PROCESS` in `/proc/sys/kernel/seccomp/actions_avail`, or where
  `apparmor_restrict_unprivileged_userns=1` blocks the opt-in netns tier, yields `Unavailable` naming the
  missing primitive — the namespace-less default tier still runs if *its* primitives are present.

### 3.5 Journal (replay-verifiable)

Add a `backend` object to the run header (alongside the existing witness fields), emitted by whichever
layer records the witness today. Fields (all from `Conformed`, so already in the witness, so replay can
recompute and compare — INV-40 style):

```json
"backend": {
  "kind": "linux",
  "matrix_row": "linux-landlock-seccomp-nons-v1",
  "network": "linux-landlock-seccomp",         // or "linux-net-namespace"
  "kill_domain": "linux-cgroup",               // or "linux-pid-namespace"
  "memory": "linux-cgroup-max",                // or rlimit-address-space
  "processes": "linux-pids-max",
  "landlock_abi": 4,                            // the ABI actually applied
  "seccomp_action": "kill-process",            // or "errno"
  "host_facts_digest": "<sha256 of HostFacts.summary()>",
  "probe_digest": "<sha256 of the live probe observations>"
}
```

`name()`/`from_name()` on `BackendKind`/`NetworkMechanism`/`KillDomain`/`MemoryGuard`/`ProcessGuard`
already give the exact strings (`lib.rs` `journal_names!`). Replay re-feeds `host_facts_digest` and
`probe_digest` as measurements (not recomputed — they are host observations), and recomputes the
`name()` strings from the witness variants; a mismatch is a divergence. This mirrors how the macOS
witness is already journalled.

---

## 4. Linux conformance suite spec (`tests/conformance_linux.rs`)

`#![cfg(target_os = "linux")]`, mirroring `tests/conformance_macos.rs` one-for-one, **through the real
spawn seam** (`LinuxBackend` via `probe()`→`spawn()`), checking from **outside** the sandbox (file absent,
listener silent, pid gone) with an unconfined **control** for every case. Reuse every existing `Case` id.

**Parity cases (same ids as macOS):** FT-1, FT-2 (network in a `cargo` build script under real cargo),
FT-3, FT-4, FT-5, FT-6, FT-7, FT-8, FT-9, FT-10, FT-11, FT-12, FT-15, FT-16, FT-16-setsid, FT-17 (Linux:
no analogue of LaunchServices — map to "no new session/process outside the kill domain can be launched";
or mark FT-17 macOS-only on the Linux row with a written reason, **L-Q3**), FT-18 (keyring syscalls
refused), D31-no-bind, nested-sandbox, hard-link.

**Linux-specific escape cases (NEW `Case` variants, added to the Linux row only — see the JSON in §6):**

| New `Case` | Test name | What it proves |
|---|---|---|
| `LinuxOpenat2` | `linux_openat2_resolve_flags_cannot_escape_roots` | `openat2(2)` with `RESOLVE_BENEATH`/no-flags cannot reach outside the Landlock read set; `..` and symlink-in-path are denied by Landlock's handle model. |
| `LinuxProcSelfMem` | `linux_proc_self_mem_and_pid_mem_are_not_a_write_channel` | `/proc/self/mem` and `/proc/<pid>/mem` are not writable outside roots; `/proc/<other>/mem` of a non-descendant is unreachable (ptrace denied by seccomp). |
| `LinuxFdInherit` | `linux_no_unexpected_fd_is_inherited_into_the_child` | only the control pipe + std{in,out,err} cross exec; `close_range(3, ~0)` is applied before exec so no harness fd leaks. |
| `LinuxLdPreload` | `linux_ld_preload_and_loader_env_are_absent` | the built env carries no `LD_PRELOAD`/`LD_*` (INV-10, already enforced by `spec::validate`); a planted `LD_PRELOAD` in the harness env does not reach the child. |
| `LinuxSetuid` | `linux_setuid_binary_gains_nothing_under_no_new_privs` | exec of a setuid helper (control: it would gain euid 0 unconfined on a permissive host) gains no privilege under `no_new_privs`. |
| `LinuxMemfdExec` | `linux_memfd_create_then_execveat_is_refused` | `memfd_create`+`execveat(AT_EMPTY_PATH)` is refused (no Landlock exec right on an anonymous fd; `execveat(AT_EMPTY_PATH)` seccomp-denied). |
| `LinuxAbstractUnix` | `linux_abstract_unix_socket_connect_is_refused` | `socket(AF_UNIX)` is seccomp-denied, so abstract-namespace unix sockets (which Landlock < ABI6 cannot scope) are unreachable. |
| `LinuxPtraceSibling` | `linux_ptrace_of_a_sibling_is_refused` | `ptrace(PTRACE_ATTACH)` of another confined sibling is seccomp-denied (no cross-process memory read). |
| `LinuxForkBombPgroup` | `linux_fork_bomb_and_setsid_double_fork_are_all_reaped` | a fork bomb is bounded and, with `setsid`+double-fork escape attempts, **every** descendant is gone after stop (subreaper sweep / PID-ns kill). |
| `LinuxDevShmTmpfs` | `linux_dev_shm_and_tmpfs_writes_stay_inside_roots` | `/dev/shm` and any tmpfs not in the rw roots are not writable; a write there leaves nothing and is Landlock-denied. |

Each Linux-specific case is added to the committed Linux matrix row **only** in the slice whose test
passes on a real kernel (same discipline as P-36 §12). Until then the row omits it and any caller
requiring it refuses.

---

## 5. Testing without eyeballing: a real Linux VM, driven by Rust

**Fail-closed VM, not `cargo check`.** macOS cross-`cargo check --target aarch64-unknown-linux-gnu`
catches compile errors but proves **nothing** about kernel enforcement. The matrix row is committed only
from a run on a real kernel. There is already a VM on this Mac: UTM `rh-linux.utm` (aarch64, Shared
networking, VirtFS directory share) — verified present at
`~/Library/Containers/com.utmapp.UTM/Data/Documents/rh-linux.utm`.

### 5.1 The dev tool (Rust, no shell logic — memory "rust-only-tooling")

Add a subcommand to the existing Rust dev binary `tools/rh-dev` (it already shells out only via
`std::process::Command` argv arrays, ports of the old zsh scripts — the right home for this):

```
rh-dev linux --vm rh-linux --ssh <user@host-or-ip> [--boot] [--timeout 1800] [--only <test>] [--keep-logs DIR]
```

What it does (all in Rust, `std::process::Command` with argv arrays; **no** logic in shell):

1. **Ensure the guest is up.** `--boot`: start the VM via `utmctl start rh-linux`
   (`/Applications/UTM.app/Contents/MacOS/utmctl`, verified present), then poll ssh (TCP connect +
   `ssh ... true`) until reachable or `--timeout`. If unreachable and not `--boot`: **exit non-zero with a
   loud message** ("Linux VM rh-linux unreachable; Linux conformance SKIPPED — this is not a pass"), never
   silent-green.
2. **Sync the workspace to the guest.** `rsync` over ssh (argv array) of the repo worktree to
   `~/rh-work` on the guest, excluding `target/` and `.git/` (fresh, reproducible; a dirty guest tree is a
   test hazard). A content digest of what was synced goes in the report.
3. **Run the suite with a timeout.** Over ssh:
   `cargo test -p harness-sandbox --test conformance_linux -- --nocapture --test-threads=1`
   (serialised: the live probe is flaky under concurrent sandbox apply, same lesson as the Seatbelt probe
   in `verify.sh`), plus `cargo test -p harness-sandbox-linux` for the unit tests, plus the normal
   `cargo test -p harness-sandbox` (the pure parts) as a control. Wall-clock timeout kills the ssh child's
   process group on the guest (`ssh -tt` + a `timeout(1)` wrapper invoked as argv, or a pidfd-style kill
   of the ssh child) so a hung test cannot wedge the tool.
4. **Return pass/fail + logs.** Parse cargo's `test result:` lines (rh-dev already parses tool output in
   `suite.rs`/`checks.rs`); print a one-line verdict and the per-test pass/fail table; copy full logs to
   `--keep-logs`. Exit 0 only if every selected test passed.

A thin `tools/rh-dev/.../linux.rs` module; a sibling `tools/rh-vm` crate is an acceptable alternative if
`rh-dev` should stay slim (L-Q5). Either way it is Rust; the only external programs are `utmctl`, `ssh`,
`rsync`, invoked by argv.

### 5.2 Conductor gate (optional Linux step, never silently green)

The swarm conductor's member gates (`devkit/swarm/verify.sh` → `scripts/ci/gates.sh`) stay macOS-only by
default. Add an **optional** Linux step the conductor runs **after** the macOS gates pass, for slices
that touch `harness-sandbox-linux` or `conformance_linux`:

- The conductor calls `rh-dev linux --vm rh-linux --ssh … --timeout 1800`.
- **VM reachable:** its exit code gates the merge exactly like the macOS gates.
- **VM unreachable:** the step prints a **loud** banner (`LINUX STEP SKIPPED: VM UNREACHABLE — NOT
  VERIFIED ON LINUX`) and records `linux: skipped (unreachable)` in the worker report, and the slice is
  marked **not** Linux-verified (its matrix row is *not* committed from a skipped run). It never counts as
  green. This mirrors design §9 H2's "UNVERIFIED on real Linux until someone runs the suite" posture.

### 5.3 GLM workers running Linux tests safely (serialised, one VM, a lock)

One VM, so Linux runs must serialise across workers exactly as the Seatbelt test step does. Reuse the
`verify.sh` pattern: a filesystem lock (`mkdir /tmp/rh-linux-vm.lock` / `flock`) that a worker must hold
for the whole `rh-dev linux` invocation; `rh-dev linux` acquires it itself (so a hand-run and a conductor
run cannot collide). The guest tree is re-synced per run (step 2), so one worker's tree never leaks into
another's. A worker that cannot get the lock within a bound reports `linux: skipped (vm busy)` — again not
green. Workers never boot/poweroff the VM concurrently (the lock covers `--boot`).

---

## 6. Slice cards (S-L-a … S-L-k) and the `deps_extra.json` object

Format matches `docs/ROADMAP-parity.md` §4.3 (Why | Crates | Tests | Deps | Parallel | Risk | ARCH).
The cards themselves are appended to `docs/ROADMAP-parity.md` under a new heading **"Track S-L (Linux)"**
in the `**S-L-a …**` bold-card shape `mkbrief.py` matches (`^\*\*S-L-a ` … up to the next `^\*\*`/heading).
Eleven slices, each GLM-flash-sized (one crate area, named tests).

Order / chain: **S-L-a → S-L-b → S-L-c → S-L-d → S-L-e** is the serial build-up (crate skeleton →
Landlock → seccomp → supervisor/kill → probe+mint). **S-L-f** (conformance parity suite) and **S-L-g**
(Linux-specific escape cases) follow e. **S-L-h** (rh-dev linux tool) and **S-L-i** (conductor Linux
step) are parallel infra, needed before f/g can be *verified* but not before they are *written*. **S-L-j**
(opt-in namespace tier + ports) and **S-L-k** (cgroup v2 memory/pids + fileop helper) are the stronger-tier
extensions, last.

```json
{
 "S-La": { "deps": ["ARCH:S-L"], "prio": 10 },
 "S-Lb": { "deps": ["S-La"], "prio": 11 },
 "S-Lc": { "deps": ["S-La"], "prio": 11 },
 "S-Ld": { "deps": ["S-Lb", "S-Lc"], "prio": 12 },
 "S-Le": { "deps": ["S-Ld"], "prio": 13 },
 "S-Lf": { "deps": ["S-Le", "S-Lh"], "prio": 14 },
 "S-Lg": { "deps": ["S-Lf"], "prio": 15 },
 "S-Lh": { "deps": [], "prio": 9 },
 "S-Li": { "deps": ["S-Lh"], "prio": 10 },
 "S-Lj": { "deps": ["S-Lf"], "prio": 16 },
 "S-Lk": { "deps": ["S-Lf"], "prio": 16 }
}
```

(`ARCH:S-L` marks this design note as the required predecessor, matching the `deps_extra.json`
`ARCH:P-47` convention.)

---

## 7. Owner questions (each with its fail-closed default)

| # | Question | Fail-closed default (holds until Iwan decides) |
|---|---|---|
| L-Q1 | `unsafe` location: a new `harness-sandbox-linux` crate (design §6.7 pattern) vs raising the workspace `unsafe_code` lint for `harness-sandbox` itself. | **Separate crate**, `allow(unsafe_code)` ratcheted, only `harness-sandbox` may depend on it. `harness-sandbox` stays `#![forbid(unsafe_code)]`. |
| L-Q2 | May `rustix` (and its cfg-probing `build.rs`) be admitted past purity.sh's absolute build-script ban, or must we use `nix`/raw `libc` to keep the ban absolute? | **Keep the ban absolute**; use the hand-assembled seccomp + `nix`/raw `libc` (no build script) unless the reviewer admits rustix's build.rs after reading it. |
| L-Q3 | FT-17 (LaunchServices) has no Linux analogue. Map it to "no process escapes the kill domain", or mark it macOS-only on the Linux row with a written reason? | **Mark macOS-only** on the Linux row, reason recorded; do not fake an equivalent. |
| L-Q4 | seccomp: depend on `seccompiler`, or ship the ~100-line hand-assembled BPF filter with zero seccomp deps? | **Hand-assembled** behind a trait for the committed version (fewest deps, memory "rust-only"/minimal-supply-chain); `seccompiler` allowed temporarily during bring-up only. |
| L-Q5 | Dev tool home: a subcommand on `tools/rh-dev`, or a new `tools/rh-vm` crate? | **Subcommand on `rh-dev`** (one dev binary; it already owns suite-running). |
| L-Q6 | Default tier only (namespace-less), or build the opt-in namespace tier (S-L-j) for ports + stronger kill in the first cut? | **Default tier first**; ports **refused** on Linux until the netns tier lands (seccomp cannot inspect sockaddr). Namespace tier is a later slice. |
| L-Q7 | Which kernels count as "supported" for the committed row (min Landlock ABI)? | **ABI ≥ 1 required for files; ABI ≥ 4 required before any TCP-port grant.** Below ABI 1 → refuse. Target: Ubuntu 24.04 LTS (ABI 4), Debian 12, Fedora. |
| L-Q8 | On a host where unprivileged userns is AppArmor-restricted (Ubuntu 24.04 default), is the namespace-less tier acceptable as the *only* tier, or should such hosts refuse entirely? | **Namespace-less tier is acceptable and is the default**; such hosts run with Landlock+seccomp, ports refused. Refuse only if even the default-tier primitives are missing. |

---

## Appendix: how this satisfies INV-6 / INV-15

- INV-15 (`Conformed` unminttable without `probe()`): preserved. `harness-sandbox-linux` calls the
  **crate-private** `Conformed::mint` only from `Linux::probe()` (the delegation keeps the mint inside
  `harness-sandbox`; the linux crate returns raw observations + the chosen row, and `linux.rs` mints).
  The `compile_fail,E0451` doctest in `lib.rs` still proves no external construction.
- INV-6 (no containment, no execution): `require()` is the only exec gate; on Linux it returns a witness
  only when a committed row + a live probe that **applied the sandbox and saw the canaries refused** both
  hold. Degrade is refusal (L-D5). No unconfined fallback exists: `SystemConfinement::spawn` for
  `cfg(not(macos/windows))` forwards to `linux::Linux`, which cannot spawn without a Linux witness.
