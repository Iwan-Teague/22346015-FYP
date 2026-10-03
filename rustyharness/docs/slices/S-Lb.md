# S-Lb — Landlock ruleset building (crates/harness-sandbox-linux)

Status: done (see WORKER_REPORT.md in the worktree root for the run log).

## What landed

`src/landlock_rules.rs` maps the three validated root lists of a spec
(`read_only`, `read_write`, `protected` — the fields of
`harness_sandbox::spec::Validated`) onto a Landlock ruleset, in two layers:

* Portable layer (compiles and is unit-tested on every OS): `plan()` returns
  `Vec<PathRule>` (`path` + portable `Rights` bit set). No syscalls, no
  `landlock` types. Grants:
  * system read trees `/usr`, `/lib`, `/bin`, `/etc` → read + execute
  * device nodes `/dev/null`, `/dev/zero`, `/dev/random`, `/dev/urandom` → read only
  * spec `read_only` roots → read + execute
  * spec `read_write` roots → read + execute + write set
    (`WriteFile, Truncate, MakeReg, MakeDir, MakeSym, MakeSock, MakeFifo,
    MakeBlock, MakeChar, RemoveFile, RemoveDir, Refer`)
  * spec `protected` paths → read only (the kernel applies the most specific
    rule, so protection wins inside a writable root)
* Linux-only layer (`cfg(target_os = "linux")`): `build()` opens every rule
  root as a `PathFd` (O_PATH) handle and adds a `PathBeneath` rule per entry;
  `Domain::apply()` runs `restrict_self()` (with the crate-default
  `no_new_privs = true`) and returns the kernel's `RestrictionStatus` for the
  journal (L-D7 wiring).

## ABI gate (L-D5, degrade = refuse)

* Required level: **ABI v3** (`REQUIRED_ABI_LEVEL = 3`). Rationale: the write
  grant contains `Refer` (v2) and `Truncate` (v3), so anything below v3
  cannot express the spec faithfully.
* The ruleset *handles* `AccessFs::from_all(ABI::V3)` under
  `CompatLevel::HardRequirement` — deny-by-default; no best-effort anywhere.
* `build()` calls `abi_gate(kernel_abi_probe())` first: the probe hard-requires
  the v3 right set through the landlock crate itself, so a kernel below v3
  (or without Landlock) yields `RulesError::PrimitiveMissing("landlock-abi")`.
  The landlock builder's own HardRequirement is the backstop.
  `abi_gate(Option<u32>)` is the pure decision table so the refusal is
  unit-tested on every OS.

## Why the dependency is target-gated

landlock 0.4.7 references Linux-only libc items (`prctl`, `O_PATH`) and does
not compile on macOS (verified: `cargo check` fails in the crate itself). The
dep lives under `[target.'cfg(target_os = "linux")'.dependencies]`; the pure
layer deliberately uses no landlock types. Consequence: the Linux-only half
cannot be compile-checked on this macOS host (no cross std installed,
offline). It was reviewed by hand; the CI Linux run must be its first compile.

## Tests (names required by the slice card)

* `rules_grant_exactly_the_spec_roots`
* `protected_dir_is_read_only_inside_a_writable_root`
* `missing_required_abi_refuses_not_degrades`
* `ro_root_gets_no_write_right`
* `refer_denied_outside_rw_roots` (hard-link: `Refer` is only granted on rw
  roots, so hard-linking a secret into a writable root is denied by default)

All run on any OS; `missing_required_abi_refuses_not_degrades` has an extra
`cfg(linux)` live block that builds (never applies) a domain and checks
build/probe agreement.

## Open questions / deviations

* `lib.rs` prose (S-La) says "Landlock ABI 4 for files and TCP". This slice
  requires **v3** because the FS grants need exactly that; the TCP scope is
  not implemented here. If S-Lc adds a `Scope::Bits` TCP net port, the
  required level must be revisited (v4) or the seccomp socket denial must
  cover egress instead (design leans on the latter).
* `/sbin` and `/lib64` (dynamic loader on non-merged-usr distros) are not in
  the system read trees; design §1 lists only `/usr`, `/lib`, `/bin`, `/etc`
  "as needed by the toolchain". If the conformance slice (S-Lf) shows the
  loader unreadable on some distro, add them there — note `/lib64` is a
  symlink into `/usr` on merged-usr systems and is already covered by the
  `/usr` grant.
* `plan()` deliberately takes the three root lists (not `&Validated`) because
  harness-sandbox-linux cannot depend on harness-sandbox (dependency cycle:
  the latter target-gates on the former). The wiring slice passes the fields.
