# S-Lc — seccomp-BPF denylist: network off by default, escape syscalls refused

Landed in `crates/harness-sandbox-linux/src/seccomp.rs` (+ `tests/seccomp_apply.rs`,
`lib.rs` module decl, purity.sh ratchet). Design: `docs/slices/S-L-linux-sandbox.md`
§1/§3.1, L-Q4 answer (hand-assembled BPF, no seccompiler dep, no new crates).

## Shape

- `BpfProgram = Vec<SockFilter>`; `SockFilter` is `#[repr(C)]` (the kernel reads
  the program through a pointer, so layout is ABI).
- Pure-data builder (`assemble`) compiles an arch-guarded ladder:
  `ld [arch]` → `jeq AUDIT_ARCH_X86_64 → ladder_x86` → `jeq AUDIT_ARCH_AARCH64 →
  ladder_arm` → `ret ENOSYS` (unknown arch, incl. x32) → per-ladder `ret ALLOW`
  at the end. The guard denies *before* any allow exists: an unmodelled ABI
  gets `−ENOSYS` for everything (fail closed).
- Rule tables are private per-arch consts, numbers taken from libc 0.2.189's
  `gnu/b64/{x86_64,aarch64}` tables and cross-checked (x86_64 `pivot_root` = 155,
  not the 218 seen in some i386 lists; aarch64 has `accept` = 202, no fork/vfork).
- Verdict style: `EACCES` for the whole socket family, `EPERM` for the escape
  surface (namespace/priv, debug, kernel-image, keyring, io_uring, userfaultfd,
  fanotify, open_by_handle_at, `clone3` outright). `clone` and `execveat` are
  arg-filtered: `CLONE_NEW*` mask `0x7e020000` on args[0], `AT_EMPTY_PATH` on
  args[4]; the flag inspection is gated on an nr `jeq`, so every other syscall
  falls through untouched.
- `NetworkMode { None, Granted }` mirrors spec's `Network` (the dep points the
  other way, so the crate cannot name `harness_sandbox::spec::Network`). Both
  variants compile the *identical* ladder: this tier cannot express port grants
  (seccomp cannot inspect a sockaddr) and the supervisor refuses them upstream;
  a grant reaching the filter can never widen it. Test-pinned.
- `SeccompFilter` trait = the L-Q4 seam: `bpf_program()` (pure, testable
  anywhere) + `apply()` (linux-only). `Denylist` is the committed impl; a
  reviewed external assembler could land behind the trait.
- `apply()` = the crate's single production `unsafe` site: `prctl
  (PR_SET_NO_NEW_PRIVS)` then one `seccomp(SECCOMP_SET_MODE_FILTER)`, flags=0
  (the child installs before exec, single-threaded). Errors are named steps
  (`NoNewPrivs` / `Install` / `UnsupportedArch`), no errno reads; on a non-x86_64
  /non-aarch64 linux host `apply` returns `UnsupportedArch` without any FFI.
- `LinuxBackend::seccomp_denylist(network)` is the constructor S-Ld's spawn path
  should call.

## Tests (all required names present)

- `filter_data_denies_the_documented_syscalls` — every table row denied with its
  errno; benign worker surface (read/write/openat/execve/clone-plain/mmap/futex/
  getrandom/exit_group/memfd_create/…) asserted ALLOWED as the control arm.
- `filter_data_is_deterministic` — byte-identical rebuilds; Granted == None
  program; within the 4096-instruction kernel cap.
- `network_syscalls_denied_at_network_none` — whole socket family → EACCES, both
  arches.
- `clone3_denied_and_clone_newns_flag_filtered` — clone3 outright EPERM; each of
  the seven `CLONE_NEW*` flags and the combined mask EPERM; plain
  `SIGCHLD|CLONE_VM|CLONE_FS` clone allowed; `execveat(AT_EMPTY_PATH)` EPERM
  while plain execveat is allowed.
- `applied_filter_blocks_socket_in_a_child` (integration,
  `tests/seccomp_apply.rs`) — parent re-execs the test binary as control and
  filtered children; filtered child installs the denylist and must get EACCES
  from a loopback `TcpListener::bind`; control child must bind successfully.
  Linux-only, arch-gated.

Extras: `every_jump_lands_inside_the_program` (classic-BPF jumps are forward-only
u8 offsets — the const assert `ladder_len(X86_64)+ladder_len(AARCH64) < 256`
makes future table growth that could overflow it a compile error, which is why
the casts in `assemble` carry no runtime guard) and
`an_unknown_audit_arch_is_refused_fail_closed` (incl. the real x32 audit arch).
The test-only classic-BPF evaluator runs every assertion through the same
opcodes the kernel would execute.

## Notes for reviewers / later slices

- purity.sh §5b `linux_unsafe_ratchet` 0 → **1** (the one filter apply; the
  probe test needs no unsafe — std observes the denied socket through
  `io::Error`). purity-selftest stays green (it only asserts refusal on a
  planted site).
- The applied test lives in `tests/` because purity §2f (INV-23) refuses the
  words `Command`/`CommandExt`/`raw_arg` anywhere under `crates/*/src/` except
  the pinned spawn modules; the gate itself documents that integration tests
  may spawn freely. No gate semantics were changed — only the ratchet number.
- Cross-checked on this (macOS) host by `cargo check --all-targets` for both
  `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`; the applied test
  exercises for real only on a Linux runner.
- Not loop-visible: nothing here renders into context or produces journal
  events (the sandbox backend is not wired into the loop yet), so no journal
  record, `replay.rs::audit` recomputation or `rh-context` bump. S-Ld (spawn
  wiring) is where the "filter refused → run refused" outcome becomes visible.
- S-Ld should map `spec::Network` → `NetworkMode` as: `None` → `None`,
  `Proxy`/`Loopback` → refuse (do not pass `Granted`; the variant exists so the
  filter can *prove* a grant cannot widen it, not to bless grants through).
- If a future slice adds deny rules, remember: (a) table rows come in JEQ+RET
  pairs and count toward the u8-jump const assert; (b) x86_64 and aarch64 rows
  must both change; (c) `filter_data_denies_the_documented_syscalls` picks the
  errno up from the row, so the test extends itself.
