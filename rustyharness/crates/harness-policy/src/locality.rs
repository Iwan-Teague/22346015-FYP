//! Filesystem-locality check: interface, decision and conservative default
//! (design §2.8, INV-35). The measuring probes of spike S-F1 live in
//! `harness_sandbox::locality`.
//!
//! `state_root` is used only on a filesystem POSITIVELY identified as local,
//! because the journal's single-writer lock and fsync durability (§7.1) do
//! not hold reliably on network filesystems. The check is an allowlist: an
//! unrecognised filesystem, a failed query or no query at all is a refusal.
//!
//! Split, so the decision stays pure and replayable:
//! - [`LocalityProbe`] measures (the mount table on Linux and macOS since
//!   S-F1; the volume APIs on Windows once S-W1 lands). Implementations do
//!   I/O and belong in `harness-sandbox` (Windows calls in
//!   `harness-sandbox-windows`). This crate ships only [`NoProbe`], which
//!   measures nothing.
//! - [`classify`] decides over the measured facts, here, with the §2.8
//!   allowlist rows.
//!
//! **The conservative default:** an OS without a confirmed probe (Windows
//! until S-W1) answers [`FsQuery::Unmeasured`], and [`check`] refuses.
//! There is no override flag (§2.8).
//!
//! No `Path` type here (review F-2): `Path` carries I/O methods (`exists`,
//! `canonicalize`, `read_dir`, ...) that never name the `fs` module. The
//! probe receives the path as an opaque string and does all I/O on its own
//! side of the trait; the purity gate refuses the standard `path` module in
//! this crate. (The gate scans comments too, hence the spelling.)

/// Local Linux filesystems by `statfs.f_type` magic (§2.8 "Admitted").
/// Values from `linux/magic.h` (ZFS from OpenZFS `ZFS_SUPER_MAGIC`); S-F1
/// must re-confirm each on a real mount.
pub const LINUX_LOCAL_MAGIC: &[(u64, &str)] = &[
    (0xEF53, "ext2/3/4"),
    (0x5846_5342, "xfs"),
    (0x9123_683E, "btrfs"),
    (0x0102_1994, "tmpfs"),
    (0x2FC1_2FC1, "zfs"),
    (0xF2F5_2010, "f2fs"),
];

/// overlayfs: admitted only when its upper layer is itself admitted.
pub const LINUX_OVERLAYFS_MAGIC: u64 = 0x794C_7630;

/// Local Linux filesystems by their kernel type NAME, as the mount table
/// (`/proc/self/mountinfo`) reports them: the same six rows as
/// [`LINUX_LOCAL_MAGIC`] (S-F1 measures names; see the design's H1e-2c
/// row). Everything else is refused, explicitly including `nfs`, `nfs4`,
/// `cifs`, `smb3`, `9p`, `ceph`, `fuse`, `fuseblk` and every `fuse.*`.
pub const LINUX_LOCAL_TYPES: &[&str] = &[
    "ext2", "ext3", "ext4", "xfs", "btrfs", "tmpfs", "zfs", "f2fs",
];

/// The overlayfs type name.
pub const LINUX_OVERLAY_TYPE: &str = "overlay";

/// macOS `f_fstypename` values admitted when `MNT_LOCAL` is also set.
pub const MACOS_LOCAL_TYPES: &[&str] = &["apfs", "hfs"];

/// Windows file-system names admitted on a `DRIVE_FIXED` volume.
pub const WINDOWS_LOCAL_FS: &[&str] = &["NTFS", "ReFS"];

/// Windows `GetDriveTypeW` result classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinDrive {
    /// `DRIVE_FIXED`.
    Fixed,
    /// `DRIVE_REMOTE`.
    Remote,
    /// `DRIVE_REMOVABLE`.
    Removable,
    /// `DRIVE_UNKNOWN` / `DRIVE_NO_ROOT_DIR`.
    Unknown,
    /// Anything else (`DRIVE_CDROM`, `DRIVE_RAMDISK`, ...).
    Other,
}

/// What a probe measured about the filesystem holding a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsQuery {
    /// Linux `statfs(2)`.
    Linux {
        /// `f_type`.
        f_type: u64,
        /// For overlayfs: the `f_type` of the `upperdir` (from
        /// `/proc/self/mountinfo`), if it could be read.
        overlay_upper: Option<u64>,
    },
    /// Linux, measured through the mount table: the kernel's type name of
    /// the mount the path is on (matched by device number).
    LinuxNamed {
        /// The mount's filesystem type name (e.g. `ext4`, `nfs4`, `fuse.sshfs`).
        fs_type: String,
        /// For overlayfs: the type name of the mount holding `upperdir`,
        /// if it could be determined.
        overlay_upper: Option<String>,
    },
    /// macOS: the `MNT_LOCAL` flag and the type name of the volume (as
    /// `statfs(2)` or the mount list reports them).
    MacOs {
        /// `f_flags & MNT_LOCAL != 0`.
        mnt_local: bool,
        /// `f_fstypename`.
        fs_type_name: String,
    },
    /// Windows volume query.
    Windows {
        /// The path had UNC shape (refused before any call).
        unc_shape: bool,
        /// `GetDriveTypeW`.
        drive: WinDrive,
        /// `GetVolumeInformationW` file-system name.
        fs_name: String,
    },
    /// The query ran and failed.
    QueryFailed {
        /// What failed (for the message).
        detail: String,
    },
    /// No probe exists for this OS in this build (the S-F1 default).
    Unmeasured,
}

/// A filesystem positively identified as local.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalFs {
    /// Human-readable type, for the journal header.
    pub fs_type: String,
}

/// Refusal: `state_root` is not on a filesystem identified as local. The run
/// does not start (`Indeterminate { CouldNotRun }`, exit 5, §2.8).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("state_root is not on a filesystem identified as local (detected: {detected}); point state_root at a local disk")]
pub struct LocalityRefused {
    /// What was detected, named for the user.
    pub detected: String,
}

/// Measures the filesystem under a path. Implemented in the I/O crates.
pub trait LocalityProbe {
    /// Measure; never panic, never guess: report `QueryFailed` instead.
    /// `path` is the canonicalised `state_root` (or attempt directory) as
    /// the caller spelled it; this crate never interprets it.
    fn query(&self, path: &str) -> FsQuery;
}

/// The refusing probe: measures nothing, so every check refuses. The binary
/// uses the real per-OS probe (`harness-sandbox`, spike S-F1); this one is
/// for callers and tests that must never admit a `state_root`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoProbe;

impl LocalityProbe for NoProbe {
    fn query(&self, _path: &str) -> FsQuery {
        FsQuery::Unmeasured
    }
}

fn refuse(detected: impl Into<String>) -> LocalityRefused {
    LocalityRefused {
        detected: detected.into(),
    }
}

fn linux_local(f_type: u64) -> Option<&'static str> {
    LINUX_LOCAL_MAGIC
        .iter()
        .find(|(m, _)| *m == f_type)
        .map(|(_, n)| *n)
}

/// Decide over measured facts with the §2.8 allowlist.
pub fn classify(q: &FsQuery) -> Result<LocalFs, LocalityRefused> {
    match q {
        FsQuery::Linux {
            f_type,
            overlay_upper,
        } => {
            if let Some(name) = linux_local(*f_type) {
                return Ok(LocalFs {
                    fs_type: name.to_owned(),
                });
            }
            if *f_type == LINUX_OVERLAYFS_MAGIC {
                return match overlay_upper.and_then(linux_local) {
                    Some(upper) => Ok(LocalFs {
                        fs_type: format!("overlayfs over {upper}"),
                    }),
                    None => Err(refuse(format!(
                        "overlayfs whose upper layer is not admitted ({overlay_upper:x?})"
                    ))),
                };
            }
            Err(refuse(format!("Linux f_type {f_type:#x}")))
        }
        FsQuery::LinuxNamed {
            fs_type,
            overlay_upper,
        } => {
            if LINUX_LOCAL_TYPES.contains(&fs_type.as_str()) {
                return Ok(LocalFs {
                    fs_type: fs_type.clone(),
                });
            }
            if fs_type == LINUX_OVERLAY_TYPE {
                return match overlay_upper {
                    Some(u) if LINUX_LOCAL_TYPES.contains(&u.as_str()) => Ok(LocalFs {
                        fs_type: format!("overlayfs over {u}"),
                    }),
                    _ => Err(refuse(format!(
                        "overlayfs whose upper layer is not admitted ({overlay_upper:?})"
                    ))),
                };
            }
            Err(refuse(format!("Linux {fs_type:?}")))
        }
        FsQuery::MacOs {
            mnt_local,
            fs_type_name,
        } => {
            if *mnt_local && MACOS_LOCAL_TYPES.contains(&fs_type_name.as_str()) {
                Ok(LocalFs {
                    fs_type: fs_type_name.clone(),
                })
            } else {
                Err(refuse(format!(
                    "macOS {fs_type_name:?} (MNT_LOCAL {})",
                    if *mnt_local { "set" } else { "not set" }
                )))
            }
        }
        FsQuery::Windows {
            unc_shape,
            drive,
            fs_name,
        } => {
            if *unc_shape {
                return Err(refuse("a UNC path"));
            }
            if *drive == WinDrive::Fixed && WINDOWS_LOCAL_FS.contains(&fs_name.as_str()) {
                Ok(LocalFs {
                    fs_type: fs_name.clone(),
                })
            } else {
                Err(refuse(format!("Windows {drive:?} drive with {fs_name:?}")))
            }
        }
        FsQuery::QueryFailed { detail } => Err(refuse(format!("query failed: {detail}"))),
        FsQuery::Unmeasured => Err(refuse(
            "no filesystem probe for this OS in this build (Windows: the volume query awaits spike S-W1)",
        )),
    }
}

/// UNC shape on Windows, refused by shape before any call (§2.8):
/// `\\server\share`, `//server/share`, `\\?\UNC\…`, and device paths
/// `\\.\…`. A verbatim DISK path `\\?\C:\…` (what canonicalisation
/// returns on Windows) is not UNC and goes on to the volume query.
pub fn is_unc_shape(path: &str) -> bool {
    // `\\?\` (Win32 verbatim), `//?/`, and the NT `\??\` prefix, which
    // Win32 passes through as an NT path (H1b confirming review NF-3).
    let verbatim = path
        .strip_prefix("\\\\?\\")
        .or_else(|| path.strip_prefix("//?/"))
        .or_else(|| path.strip_prefix("\\??\\"));
    if let Some(rest) = verbatim {
        let b = rest.as_bytes();
        let disk = b.len() >= 2
            && b.first().is_some_and(u8::is_ascii_alphabetic)
            && b.get(1) == Some(&b':');
        return !disk;
    }
    // Any two leading separators, in any mix: Win32 normalises `/` to `\`
    // outside verbatim paths, so `\/server` and `/\server` are UNC too
    // (review F-9).
    let sep = |b: Option<&u8>| matches!(b, Some(b'/') | Some(b'\\'));
    let b = path.as_bytes();
    sep(b.first()) && sep(b.get(1))
}

/// Run the check: measure with `probe`, decide with [`classify`]. Callers
/// run it on the canonicalised `state_root` at startup and on each new
/// `attempt-<n>` directory (§2.8), before any journal header is written.
pub fn check(probe: &dyn LocalityProbe, path: &str) -> Result<LocalFs, LocalityRefused> {
    classify(&probe.query(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux(f_type: u64) -> FsQuery {
        FsQuery::Linux {
            f_type,
            overlay_upper: None,
        }
    }

    #[test]
    fn inv_35_default_build_refuses_every_state_root() {
        // The conservative default: no probe, no admission.
        assert!(check(&NoProbe, "/var/lib/state").is_err());
        assert!(check(&NoProbe, "C:\\state").is_err());
    }

    #[test]
    fn inv_35_network_and_unknown_filesystems_refused() {
        for magic in [
            0x6969,      // NFS
            0x517B,      // SMB
            0xFF53_4D42, // CIFS
            0xFE53_4D42, // SMB2
            0x6573_5546, // FUSE (sshfs and friends)
            0x0102_1997, // 9p
            0x00C3_6400, // Ceph
            0,
            u64::MAX,
        ] {
            assert!(classify(&linux(magic)).is_err(), "{magic:#x}");
        }
        for (local, name) in [
            (false, "apfs"),
            (false, "smbfs"),
            (true, "smbfs"),
            (true, "nfs"),
            (true, "APFS"),
        ] {
            let q = FsQuery::MacOs {
                mnt_local: local,
                fs_type_name: name.into(),
            };
            assert!(classify(&q).is_err(), "{local} {name}");
        }
        for (unc, drive, fs) in [
            (true, WinDrive::Fixed, "NTFS"),
            (false, WinDrive::Remote, "NTFS"),
            (false, WinDrive::Removable, "NTFS"),
            (false, WinDrive::Unknown, "NTFS"),
            (false, WinDrive::Fixed, "FAT32"),
            (false, WinDrive::Fixed, "ntfs"),
        ] {
            let q = FsQuery::Windows {
                unc_shape: unc,
                drive,
                fs_name: fs.into(),
            };
            assert!(classify(&q).is_err(), "{unc} {drive:?} {fs}");
        }
        assert!(classify(&FsQuery::QueryFailed {
            detail: "EIO".into()
        })
        .is_err());
    }

    #[test]
    fn inv_35_overlay_admitted_only_over_an_admitted_upper() {
        let over = |upper| FsQuery::Linux {
            f_type: LINUX_OVERLAYFS_MAGIC,
            overlay_upper: upper,
        };
        assert!(classify(&over(Some(0xEF53))).is_ok());
        assert!(classify(&over(Some(0x6969))).is_err());
        assert!(classify(&over(Some(LINUX_OVERLAYFS_MAGIC))).is_err());
        assert!(classify(&over(None)).is_err());
    }

    #[test]
    fn admitted_rows_classify_as_local() {
        for (magic, _) in LINUX_LOCAL_MAGIC {
            assert!(classify(&linux(*magic)).is_ok());
        }
        for name in MACOS_LOCAL_TYPES {
            let q = FsQuery::MacOs {
                mnt_local: true,
                fs_type_name: (*name).into(),
            };
            assert!(classify(&q).is_ok());
        }
        for fs in WINDOWS_LOCAL_FS {
            let q = FsQuery::Windows {
                unc_shape: false,
                drive: WinDrive::Fixed,
                fs_name: (*fs).into(),
            };
            assert!(classify(&q).is_ok());
        }
    }

    #[test]
    fn inv_35_linux_type_names_admit_only_the_local_rows() {
        let named = |t: &str, up: Option<&str>| FsQuery::LinuxNamed {
            fs_type: t.into(),
            overlay_upper: up.map(Into::into),
        };
        for ok in LINUX_LOCAL_TYPES {
            assert!(classify(&named(ok, None)).is_ok(), "{ok}");
        }
        for bad in [
            "nfs",
            "nfs4",
            "cifs",
            "smb3",
            "9p",
            "ceph",
            "fuse",
            "fuseblk",
            "fuse.sshfs",
            "fuse.rclone",
            "proc",
            "sysfs",
            "devtmpfs",
            "autofs",
            "vfat",
            "",
            "EXT4",
        ] {
            let e = classify(&named(bad, None)).unwrap_err();
            assert!(e.detected.contains(&format!("{bad:?}")), "{bad}: {e}");
        }
        assert!(classify(&named("overlay", Some("ext4"))).is_ok());
        assert!(classify(&named("overlay", Some("nfs4"))).is_err());
        assert!(classify(&named("overlay", None)).is_err());
    }

    #[test]
    fn unc_shapes_are_recognised() {
        for unc in [
            "\\\\server\\share",
            "//server/share",
            "\\\\?\\UNC\\server\\share",
        ] {
            assert!(is_unc_shape(unc), "{unc}");
        }
        assert!(is_unc_shape("\\\\.\\PhysicalDrive0"));
        // H1b confirming review NF-3: the NT `\??\` prefix is verbatim too.
        assert!(is_unc_shape("\\??\\UNC\\server\\share\\x"));
        assert!(!is_unc_shape("\\??\\C:\\state"));
        // Review F-9: Win32 normalises `/` to `\` outside verbatim paths.
        assert!(is_unc_shape("\\/server/share"));
        assert!(is_unc_shape("/\\server\\share"));
        for not in ["C:\\x", "/x", "x", "\\\\?\\C:\\state"] {
            assert!(!is_unc_shape(not), "{not}");
        }
    }
}
