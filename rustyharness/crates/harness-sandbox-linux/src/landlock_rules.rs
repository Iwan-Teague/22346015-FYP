//! Building a Landlock ruleset from a validated sandbox spec
//! (design §6.7; docs/slices/S-L-linux-sandbox.md, slice S-Lb).
//!
//! Two layers, split by target. The portable, syscall-free layer (this
//! file's non-`cfg` items): [`plan`] maps the three validated root lists
//! (`read_only`, `read_write`, `protected`) onto [`PathRule`]s carrying
//! portable [`Rights`]. It compiles and unit-tests on every OS, because it
//! never touches the kernel or the `landlock` crate (which is Linux-only).
//!
//! The Linux-only layer ([`build`], [`Domain`]) turns a plan into a real
//! `landlock::RulesetCreated` behind a set of `PathFd` (O_PATH) handles,
//! with the compatibility level set to [`CompatLevel::HardRequirement`].
//! L-D5 (degrade = refuse): a kernel missing the Landlock ABI the grants
//! need is a refusal named [`RulesError::PrimitiveMissing`]`("landlock-abi")`
//! — never a weaker domain, never a best-effort subset.
//!
//! Deny-by-default: the ruleset *handles* every `AccessFs` right the
//! required ABI knows, so any path without a rule (and any right not in a
//! rule) is denied. Where a spec root and a more specific protected path
//! overlap, the kernel applies the most specific rule, which is what makes
//! `protected` read-only inside a writable root.

// ---- portable layer ------------------------------------------------------

/// The lowest Landlock ABI level that can express every right this module
/// grants: `Refer` (hard-link/rename across directories) arrived in ABI v2
/// and `Truncate` in ABI v3, and both are in the write grant of a
/// `read_write` root, so ABI v3 is required ([`abi_gate`] refuses anything
/// below). On Linux this corresponds to `landlock::ABI::V3`; the number is
/// kept target-independent so the gate is testable everywhere.
pub const REQUIRED_ABI_LEVEL: u32 = 3;

/// System read trees granted to every job (design §1: "the system-read
/// trees as needed by the toolchain"). Read + execute, never write.
pub const SYSTEM_READ_TREES: [&str; 4] = ["/usr", "/lib", "/bin", "/etc"];

/// Device nodes granted read access to every job (design §1). Read only:
/// devices never get execute or write rights.
pub const SYSTEM_DEVICES: [&str; 4] = ["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"];

/// A portable bit set of Landlock file-system rights.
///
/// Kept as plain bits (not `landlock::BitFlags<AccessFs>`) so the pure
/// planning layer has no dependency on the Linux-only `landlock` crate.
/// The mapping to `AccessFs` happens once, in the Linux-only `to_bitflags`,
/// on Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rights(u32);

impl Rights {
    /// Execute a file (`execve`).
    pub const EXECUTE: Self = Self(1 << 0);
    /// Open a file for reading.
    pub const READ_FILE: Self = Self(1 << 1);
    /// Open a directory or list its contents.
    pub const READ_DIR: Self = Self(1 << 2);
    /// Open a file for writing.
    pub const WRITE_FILE: Self = Self(1 << 3);
    /// Truncate a file (`truncate`, `ftruncate`, `O_TRUNC`).
    pub const TRUNCATE: Self = Self(1 << 4);
    /// Unlink or rename a file out of the hierarchy.
    pub const REMOVE_FILE: Self = Self(1 << 5);
    /// Remove or rename an empty directory.
    pub const REMOVE_DIR: Self = Self(1 << 6);
    /// Create (or link/rename in) a regular file.
    pub const MAKE_REG: Self = Self(1 << 7);
    /// Create (or rename in) a directory.
    pub const MAKE_DIR: Self = Self(1 << 8);
    /// Create (or rename in) a symbolic link.
    pub const MAKE_SYM: Self = Self(1 << 9);
    /// Create (or rename in) a UNIX domain socket.
    pub const MAKE_SOCK: Self = Self(1 << 10);
    /// Create (or rename in) a named pipe.
    pub const MAKE_FIFO: Self = Self(1 << 11);
    /// Create (or rename in) a block device node.
    pub const MAKE_BLOCK: Self = Self(1 << 12);
    /// Create (or rename in) a character device node.
    pub const MAKE_CHAR: Self = Self(1 << 13);
    /// Link or rename a file from or to a different directory (the
    /// hard-link / cross-directory `rename` right, ABI v2).
    pub const REFER: Self = Self(1 << 14);

    /// Every bit of `other` is set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// At least one bit is shared between `self` and `other`.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

impl std::ops::BitOr for Rights {
    type Output = Self;
    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Read a tree: open files and directories for reading.
pub const READ_SET: Rights = Rights(Rights::READ_FILE.0 | Rights::READ_DIR.0);

/// A read-only root: read plus execute (running toolchain binaries).
pub const RO_ROOT_SET: Rights = Rights(READ_SET.0 | Rights::EXECUTE.0);

/// The write grant of a `read_write` root: everything needed to build
/// (create/truncate/write files and dirs, remove them, hard-link and
/// rename across directories). No `IoctlDev` — device IO is not a build
/// need.
pub const WRITE_SET: Rights = Rights(
    Rights::WRITE_FILE.0
        | Rights::TRUNCATE.0
        | Rights::REMOVE_FILE.0
        | Rights::REMOVE_DIR.0
        | Rights::MAKE_REG.0
        | Rights::MAKE_DIR.0
        | Rights::MAKE_SYM.0
        | Rights::MAKE_SOCK.0
        | Rights::MAKE_FIFO.0
        | Rights::MAKE_BLOCK.0
        | Rights::MAKE_CHAR.0
        | Rights::REFER.0,
);

/// A writable root: read + execute + [`WRITE_SET`].
pub const RW_ROOT_SET: Rights = Rights(RO_ROOT_SET.0 | WRITE_SET.0);

/// One path rule of a plan: a canonical path and the rights granted on the
/// file hierarchy beneath it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathRule {
    /// The root of the hierarchy (canonical, from the validated spec or
    /// from [`SYSTEM_READ_TREES`]/[`SYSTEM_DEVICES`]).
    pub path: String,
    /// The rights granted beneath [`PathRule::path`].
    pub rights: Rights,
}

/// Plans the rules for a validated spec: system read trees, device nodes,
/// then the spec's `read_only`, `read_write` and `protected` roots.
///
/// Pure: no filesystem access, no syscalls, safe on every OS. Rules may
/// overlap (`protected` lies inside a `read_write` root by the spec's
/// validation); the kernel resolves overlaps by path specificity, so the
/// order of the returned rules carries no meaning.
#[must_use]
pub fn plan(read_only: &[String], read_write: &[String], protected: &[String]) -> Vec<PathRule> {
    let mut rules = Vec::new();
    for tree in SYSTEM_READ_TREES {
        rules.push(PathRule {
            path: tree.to_string(),
            rights: RO_ROOT_SET,
        });
    }
    for device in SYSTEM_DEVICES {
        rules.push(PathRule {
            path: device.to_string(),
            rights: READ_SET,
        });
    }
    for path in read_only {
        rules.push(PathRule {
            path: path.clone(),
            rights: RO_ROOT_SET,
        });
    }
    for path in read_write {
        rules.push(PathRule {
            path: path.clone(),
            rights: RW_ROOT_SET,
        });
    }
    for path in protected {
        rules.push(PathRule {
            path: path.clone(),
            rights: READ_SET,
        });
    }
    rules
}

/// The ABI gate (L-D5): a kernel whose Landlock ABI is below
/// [`REQUIRED_ABI_LEVEL`] — or whose Landlock support is unknown — is a
/// refusal naming the primitive, never a weaker domain.
///
/// `kernel_abi` is the numeric ABI level the kernel reported
/// ([`Option::None`] = Landlock absent or unusable). The Linux-only
/// [`build`] enforces the same decision live (via
/// `CompatLevel::HardRequirement`, plus this gate called first); this pure
/// function is the decision table, testable on every OS.
pub fn abi_gate(kernel_abi: Option<u32>) -> Result<(), RulesError> {
    match kernel_abi {
        Some(level) if level >= REQUIRED_ABI_LEVEL => Ok(()),
        _ => Err(RulesError::PrimitiveMissing("landlock-abi")),
    }
}

/// Errors from building or applying a ruleset. Every variant is
/// fail-closed: the caller must not spawn the job when any of these occur.
#[derive(Debug)]
pub enum RulesError {
    /// Landlock, or the ABI level the grants need, is unavailable. The
    /// value names the primitive (`"landlock-abi"`); it matches the error
    /// taxonomy shared with `harness-sandbox`'s refusal types.
    PrimitiveMissing(&'static str),
    /// A spec root or system path could not be opened for a rule handle.
    /// The spec validator should have caught vanished roots; fail closed.
    Path {
        /// The path that could not be opened.
        path: String,
        /// The open(2) error.
        source: std::io::Error,
    },
    /// The kernel refused the ruleset, a rule, or its enforcement.
    Enforce(std::io::Error),
}

impl std::fmt::Display for RulesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrimitiveMissing(name) => {
                write!(f, "primitive missing: {name} (refusing, not degrading)")
            }
            Self::Path { path, .. } => write!(f, "cannot open sandbox root {path}"),
            Self::Enforce(_) => write!(f, "kernel refused the landlock ruleset"),
        }
    }
}

impl std::error::Error for RulesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PrimitiveMissing(_) => None,
            Self::Path { source, .. } | Self::Enforce(source) => Some(source),
        }
    }
}

// ---- Linux-only layer ----------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    //! The syscall side: real `PathFd` handles, real ruleset creation,
    //! real enforcement. Compiled (and reachable) on Linux only.

    use super::{plan, RulesError, REQUIRED_ABI_LEVEL};
    use landlock::{
        Access as _, AccessFs, AddRuleError, AddRulesError, CompatLevel, Compatible,
        CreateRulesetError, PathBeneath, PathFd, PathFdError, RestrictSelfError, Ruleset,
        RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetError, ABI,
    };

    /// The `BitFlags<AccessFs>` form of a [`Rights`](super::Rights) set.
    fn to_bitflags(rights: super::Rights) -> landlock::BitFlags<AccessFs> {
        use super::Rights;
        const MAP: [(Rights, AccessFs); 15] = [
            (Rights::EXECUTE, AccessFs::Execute),
            (Rights::READ_FILE, AccessFs::ReadFile),
            (Rights::READ_DIR, AccessFs::ReadDir),
            (Rights::WRITE_FILE, AccessFs::WriteFile),
            (Rights::TRUNCATE, AccessFs::Truncate),
            (Rights::REMOVE_FILE, AccessFs::RemoveFile),
            (Rights::REMOVE_DIR, AccessFs::RemoveDir),
            (Rights::MAKE_REG, AccessFs::MakeReg),
            (Rights::MAKE_DIR, AccessFs::MakeDir),
            (Rights::MAKE_SYM, AccessFs::MakeSym),
            (Rights::MAKE_SOCK, AccessFs::MakeSock),
            (Rights::MAKE_FIFO, AccessFs::MakeFifo),
            (Rights::MAKE_BLOCK, AccessFs::MakeBlock),
            (Rights::MAKE_CHAR, AccessFs::MakeChar),
            (Rights::REFER, AccessFs::Refer),
        ];
        MAP.iter()
            .fold(landlock::BitFlags::EMPTY, |acc, (bit, fs)| {
                if rights.contains(*bit) {
                    acc | *fs
                } else {
                    acc
                }
            })
    }

    /// Probes the running kernel through the landlock crate's own gate: a
    /// ruleset that hard-requires every right of
    /// [`AccessFs::from_all`](`landlock::Access::from_all`) at
    /// [`ABI::V3`] is accepted only when the kernel's ABI is at least the
    /// required one. `handle_access` can only fail with a compatibility
    /// error here, so [`Option::None`] means exactly "below the required
    /// ABI (or no Landlock)" — the [`abi_gate`](super::abi_gate) refusal.
    pub fn kernel_abi_probe() -> Option<u32> {
        Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(ABI::V3))
            .is_ok()
            .then_some(REQUIRED_ABI_LEVEL)
    }

    /// Maps landlock errors onto the fail-closed taxonomy: compatibility
    /// refusals are `PrimitiveMissing("landlock-abi")` (L-D5: refuse,
    /// never degrade), plain syscall failures are `Enforce`. Unknown
    /// future variants refuse too.
    fn classify(err: RulesetError) -> RulesError {
        match err {
            RulesetError::HandleAccesses(_) => RulesError::PrimitiveMissing("landlock-abi"),
            RulesetError::CreateRuleset(CreateRulesetError::MissingHandledAccess) => {
                RulesError::PrimitiveMissing("landlock-abi")
            }
            RulesetError::CreateRuleset(CreateRulesetError::CreateRulesetCall {
                source, ..
            }) => RulesError::Enforce(source),
            RulesetError::AddRules(AddRulesError::Fs(AddRuleError::Compat(_))) => {
                RulesError::PrimitiveMissing("landlock-abi")
            }
            RulesetError::AddRules(AddRulesError::Fs(AddRuleError::AddRuleCall {
                source, ..
            })) => RulesError::Enforce(source),
            RulesetError::RestrictSelf(RestrictSelfError::RestrictSelfCall { source, .. }) => {
                RulesError::Enforce(source)
            }
            other => RulesError::Enforce(std::io::Error::other(other.to_string())),
        }
    }

    /// A built-but-not-yet-applied Landlock domain.
    ///
    /// Held by the supervisor's spawn path; [`Domain::apply`] must be
    /// called in the forked child before `exec` (the S-Ld wiring), where
    /// it also sets `no_new_privs`.
    pub struct Domain {
        inner: RulesetCreated,
    }

    impl Domain {
        /// Enforces the domain on the calling thread (`landlock_restrict_self(2)`
        /// + `prctl(PR_SET_NO_NEW_PRIVS)`).
        ///
        /// Returns the kernel's status so the caller can journal the
        /// enforced ABI (L-D7). Under [`CompatLevel::HardRequirement`]
        /// there is no partial outcome: either the full domain is
        /// enforced or this is an error.
        pub fn apply(self) -> Result<landlock::RestrictionStatus, RulesError> {
            self.inner.restrict_self().map_err(classify)
        }
    }

    /// Builds the domain for a validated spec (the Linux half of
    /// [`plan`](super::plan)).
    ///
    /// Fails closed: the ABI gate runs first
    /// ([`abi_gate`](super::abi_gate) over
    /// [`kernel_abi_probe`]), the landlock builder itself runs under
    /// [`CompatLevel::HardRequirement`] as a backstop, and every rule
    /// root is opened as a `PathFd` handle — a vanished root is an error,
    /// not a skipped rule.
    pub fn build(
        read_only: &[String],
        read_write: &[String],
        protected: &[String],
    ) -> Result<Domain, RulesError> {
        super::abi_gate(kernel_abi_probe())?;
        let ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(ABI::V3))
            .map_err(classify)?;
        let mut created = ruleset.create().map_err(classify)?;
        for rule in plan(read_only, read_write, protected) {
            let fd = match PathFd::new(&rule.path) {
                Ok(fd) => fd,
                Err(PathFdError::OpenCall { source, .. }) => {
                    return Err(RulesError::Path {
                        path: rule.path.clone(),
                        source,
                    });
                }
                Err(other) => {
                    return Err(RulesError::Enforce(std::io::Error::other(
                        other.to_string(),
                    )));
                }
            };
            created
                .add_rule(PathBeneath::new(fd, to_bitflags(rule.rights)))
                .map_err(classify)?;
        }
        Ok(Domain { inner: created })
    }
}

#[cfg(target_os = "linux")]
pub use linux::{build, Domain};

// ---- tests ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Paths below are plain strings: `plan` is pure and never stats
    // anything, so synthetic canonical paths are enough to pin the
    // mapping. The existence checks belong to the spec validator
    // (harness-sandbox), and `PathFd` re-checks at build time (fail
    // closed).

    #[test]
    fn rules_grant_exactly_the_spec_roots() {
        let read_only = vec!["/ws/ro".to_string()];
        let read_write = vec!["/ws".to_string()];
        let rules = plan(&read_only, &read_write, &[]);
        // System trees + devices + exactly the two spec roots.
        assert_eq!(
            rules.len(),
            SYSTEM_READ_TREES.len() + SYSTEM_DEVICES.len() + 2
        );
        for rule in &rules {
            if SYSTEM_READ_TREES.contains(&rule.path.as_str()) {
                assert_eq!(rule.rights, RO_ROOT_SET, "{}", rule.path);
            } else if SYSTEM_DEVICES.contains(&rule.path.as_str()) {
                assert_eq!(rule.rights, READ_SET, "{}", rule.path);
            }
        }
        let ro = rules
            .iter()
            .find(|r| r.path == "/ws/ro")
            .expect("read_only root planned");
        assert_eq!(ro.rights, RO_ROOT_SET);
        let rw = rules
            .iter()
            .find(|r| r.path == "/ws")
            .expect("read_write root planned");
        assert_eq!(rw.rights, RW_ROOT_SET);
        // The cwd lies inside a root (validated spec) and gets NO rule of
        // its own: grants attach to roots, not to working directories.
        assert!(rules.iter().all(|r| r.path != "/ws/src"));
    }

    #[test]
    fn protected_dir_is_read_only_inside_a_writable_root() {
        let read_write = vec!["/ws".to_string()];
        let protected = vec!["/ws/.git".to_string()];
        let rules = plan(&[], &read_write, &protected);
        let ws = rules
            .iter()
            .find(|r| r.path == "/ws")
            .expect("rw root planned");
        assert!(ws.rights.contains(Rights::WRITE_FILE));
        assert!(ws.rights.contains(READ_SET));
        let git = rules
            .iter()
            .find(|r| r.path == "/ws/.git")
            .expect("protected path planned");
        // Path specificity beats the wider rw rule: the protected subtree
        // is exactly read-only, nothing more.
        assert_eq!(git.rights, READ_SET);
        assert!(!git.rights.intersects(WRITE_SET));
        assert!(!git.rights.contains(Rights::EXECUTE));
    }

    #[test]
    fn missing_required_abi_refuses_not_degrades() {
        // The decision table: absent (None), unknown-level, and every
        // level below the required one refuse; the required level and any
        // newer one pass.
        for kernel in [None, Some(0), Some(1), Some(2)] {
            assert!(
                matches!(
                    abi_gate(kernel),
                    Err(RulesError::PrimitiveMissing("landlock-abi"))
                ),
                "{kernel:?} must refuse, not degrade"
            );
        }
        for kernel in [Some(3), Some(4), Some(5), Some(9)] {
            assert!(abi_gate(kernel).is_ok(), "{kernel:?} must pass the gate");
        }

        // Live check (Linux only, real kernel): build() either succeeds on
        // a kernel at/above the required ABI or refuses with the named
        // primitive below it — matching the probe, never a weaker domain.
        // This only BUILDS the ruleset; apply() is not called here (the
        // conformance slice exercises real enforcement).
        #[cfg(target_os = "linux")]
        {
            use super::linux::kernel_abi_probe;
            let probe = kernel_abi_probe();
            let root = vec!["/tmp".to_string()];
            match build(&root, &[], &[]) {
                Ok(_) => assert!(probe.is_some(), "built a domain below the required ABI"),
                Err(err) => {
                    assert!(
                        matches!(err, RulesError::PrimitiveMissing("landlock-abi")),
                        "unexpected build error: {err}"
                    );
                    assert!(probe.is_none(), "refused although the probe passed");
                }
            }
        }
    }

    #[test]
    fn ro_root_gets_no_write_right() {
        let read_only = vec!["/ws/ro".to_string()];
        let rules = plan(&read_only, &[], &[]);
        let ro = rules
            .iter()
            .find(|r| r.path == "/ws/ro")
            .expect("ro root planned");
        assert_eq!(ro.rights, RO_ROOT_SET);
        assert!(!ro.rights.intersects(WRITE_SET));
        // Spot-check the write-shaped rights individually: a bug that
        // granted only e.g. Truncate must not slip through a set check.
        assert!(!ro.rights.contains(Rights::WRITE_FILE));
        assert!(!ro.rights.contains(Rights::TRUNCATE));
        assert!(!ro.rights.contains(Rights::MAKE_REG));
        assert!(!ro.rights.contains(Rights::REMOVE_FILE));
        assert!(!ro.rights.contains(Rights::REFER));
    }

    #[test]
    fn refer_denied_outside_rw_roots() {
        // Refer is the ABI v2 right behind hard-link(2) and cross-directory
        // rename(2). Deny-by-default means: it is denied everywhere it is
        // not granted, so hard-linking a secret (e.g. the private dir) into
        // a writable root fails with EACCES unless the source hierarchy
        // carries Refer. Only rw roots carry it.
        let rules = plan(
            &["/ws/ro".to_string()],
            &["/ws".to_string()],
            &["/ws/.git".to_string()],
        );
        for rule in &rules {
            let should_refer = rule.path == "/ws";
            assert_eq!(
                rule.rights.contains(Rights::REFER),
                should_refer,
                "{}",
                rule.path
            );
        }
        // And the write grant does carry it (else the deny would be
        // meaningless: nothing anywhere could ever link).
        assert!(WRITE_SET.contains(Rights::REFER));
    }
}
