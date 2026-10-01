//! The filesystem-locality probe (design §2.8, INV-35, spike S-F1).
//!
//! [`SystemProbe`] MEASURES which filesystem holds a path; the pure
//! `harness_policy::locality::classify` DECIDES over the measurement with
//! the §2.8 allowlist. The probe never decides "local" itself: every
//! failure (the path cannot be examined, the mount table cannot be read or
//! parsed, no entry matches, entries disagree) is reported as
//! `FsQuery::QueryFailed`, which `classify` refuses.
//!
//! **How each OS is measured (no `unsafe`, no new crate).** `statfs(2)`
//! needs FFI, which this crate forbids (§6.7), so the probe reads the
//! kernel's mount table and matches the path to its mount by DEVICE NUMBER
//! (the path's `st_dev`), never by path prefix, so symlinks, bind mounts
//! and macOS firmlinks cannot mislead it:
//!
//! - **Linux:** `/proc/self/mountinfo` carries each mount's `major:minor`
//!   and its filesystem type name (`ext4`, `nfs4`, `fuse.sshfs`, ...). The
//!   path's device selects the entry; for `overlay`, the `upperdir` option's
//!   device selects the upper layer's type. Admitted: the §2.8 local types.
//! - **macOS:** `/sbin/mount` lists every mount with its type and the
//!   `local` flag (`MNT_LOCAL`). Only entries that are `apfs` or `hfs` AND
//!   `local` are stat'ed (never a network mount, which could hang); the path
//!   is local only if its device equals one of theirs. Anything else is
//!   refused, naming the mount the path appears to be on.
//! - **Windows:** a UNC-shaped path is refused by shape. The volume APIs
//!   (`GetDriveTypeW`, `GetVolumeInformationW`) need FFI, which lives in the
//!   audited `harness-sandbox-windows` crate that does not exist yet (spike
//!   S-W1), so every other path is `Unmeasured`: refused. Compile-checked
//!   for the Windows targets; not run.
//! - **Any other OS:** `Unmeasured`, refused.
//!
//! **Named residuals.** The mount table is read after the path is
//! examined, so a mount placed over the path in between is not seen (the
//! check runs again on each new attempt directory, §2.8). A Linux btrfs
//! subvolume that is not itself a mount point has an anonymous device
//! number that matches no entry, so it is refused (availability, not
//! safety). A local filesystem on network block storage (iSCSI) looks
//! local (§11).

use std::path::Path;

use harness_policy::locality::{FsQuery, LocalityProbe};

/// Largest mount table read.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const MOUNT_TABLE_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// The real per-OS probe (see the module docs).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemProbe;

impl LocalityProbe for SystemProbe {
    fn query(&self, path: &str) -> FsQuery {
        query(Path::new(path))
    }
}

fn failed(detail: impl Into<String>) -> FsQuery {
    FsQuery::QueryFailed {
        detail: detail.into(),
    }
}

#[cfg(target_os = "linux")]
fn query(path: &Path) -> FsQuery {
    linux::query(path)
}

#[cfg(target_os = "macos")]
fn query(path: &Path) -> FsQuery {
    macos::query(path)
}

#[cfg(windows)]
fn query(path: &Path) -> FsQuery {
    match path.to_str() {
        Some(p) if harness_policy::locality::is_unc_shape(p) => FsQuery::Windows {
            unc_shape: true,
            drive: harness_policy::locality::WinDrive::Unknown,
            fs_name: String::new(),
        },
        _ => FsQuery::Unmeasured,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn query(_path: &Path) -> FsQuery {
    FsQuery::Unmeasured
}

#[cfg(target_os = "linux")]
fn read_bounded(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut s = String::new();
    std::fs::File::open(path)?
        .take(MOUNT_TABLE_MAX_BYTES + 1)
        .read_to_string(&mut s)?;
    if s.len() as u64 > MOUNT_TABLE_MAX_BYTES {
        return Err(std::io::Error::other("the mount table is too large"));
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// Linux: /proc/self/mountinfo.
// ---------------------------------------------------------------------------

/// One `/proc/self/mountinfo` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMount {
    /// `(major, minor)` of the mounted filesystem.
    pub dev: (u64, u64),
    /// The mount point (octal escapes decoded).
    pub mount_point: String,
    /// The filesystem type name.
    pub fs_type: String,
    /// The per-superblock options.
    pub super_options: String,
}

/// Decode mountinfo's octal escapes (`\040` for a space, ...).
fn unescape_octal(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'\\' {
            let digits = b.get(i + 1..i + 4)?;
            if !digits.iter().all(|d| (b'0'..=b'7').contains(d)) {
                return None;
            }
            let v = digits.iter().fold(0u32, |a, d| a * 8 + u32::from(d - b'0'));
            out.push(u8::try_from(v).ok()?);
            i += 4;
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Parse `/proc/self/mountinfo` (proc(5)). Any malformed line refuses the
/// whole table: a table the probe cannot read is not evidence.
pub fn parse_mountinfo(text: &str) -> Result<Vec<LinuxMount>, &'static str> {
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let (pre, post) = line
            .split_once(" - ")
            .ok_or("a line has no ' - ' separator")?;
        let f: Vec<&str> = pre.split(' ').collect();
        let (Some(devs), Some(mp)) = (f.get(2), f.get(4)) else {
            return Err("a line has too few fields");
        };
        let (maj, min) = devs
            .split_once(':')
            .ok_or("a device field is not major:minor")?;
        let dev = (
            maj.parse().map_err(|_| "a major number is not a number")?,
            min.parse().map_err(|_| "a minor number is not a number")?,
        );
        let g: Vec<&str> = post.split(' ').collect();
        let (Some(fs_type), Some(opts)) = (g.first(), g.get(2)) else {
            return Err("a line has too few fields after the separator");
        };
        out.push(LinuxMount {
            dev,
            mount_point: unescape_octal(mp).ok_or("a mount point has a bad escape")?,
            fs_type: unescape_octal(fs_type).ok_or("a type has a bad escape")?,
            super_options: (*opts).to_owned(),
        });
    }
    if out.is_empty() {
        return Err("the mount table is empty");
    }
    Ok(out)
}

/// glibc's `dev_t` layout: the major and minor numbers of a device.
pub fn linux_dev_split(dev: u64) -> (u64, u64) {
    let major = ((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0x0000_0fff);
    let minor = ((dev >> 12) & 0xffff_ff00) | (dev & 0x0000_00ff);
    (major, minor)
}

/// The type of the one filesystem mounted with device `dev`. Several
/// entries (bind mounts) must agree.
pub fn linux_type_of(mounts: &[LinuxMount], dev: (u64, u64)) -> Result<&LinuxMount, String> {
    let hits: Vec<&LinuxMount> = mounts.iter().filter(|m| m.dev == dev).collect();
    let first = hits
        .first()
        .ok_or_else(|| format!("no mount entry has the path's device {}:{}", dev.0, dev.1))?;
    if hits.iter().any(|m| m.fs_type != first.fs_type) {
        return Err(format!(
            "the mount entries for device {}:{} disagree on the type",
            dev.0, dev.1
        ));
    }
    Ok(first)
}

/// The measurement for a path whose device is `dev`, given the mount
/// table; `upper_dev` resolves an overlay's `upperdir` to a device.
pub fn linux_measure(
    mounts: &[LinuxMount],
    dev: (u64, u64),
    upper_dev: &dyn Fn(&str) -> Option<(u64, u64)>,
) -> FsQuery {
    let m = match linux_type_of(mounts, dev) {
        Ok(m) => m,
        Err(e) => return failed(e),
    };
    let overlay_upper = if m.fs_type == harness_policy::locality::LINUX_OVERLAY_TYPE {
        m.super_options
            .split(',')
            .find_map(|o| o.strip_prefix("upperdir="))
            .and_then(upper_dev)
            .and_then(|d| linux_type_of(mounts, d).ok())
            .map(|u| u.fs_type.clone())
    } else {
        None
    };
    FsQuery::LinuxNamed {
        fs_type: m.fs_type.clone(),
        overlay_upper,
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    use harness_policy::locality::FsQuery;

    use super::{failed, linux_dev_split, linux_measure, parse_mountinfo, read_bounded};

    pub(super) fn query(path: &Path) -> FsQuery {
        let dev = match std::fs::metadata(path) {
            Ok(m) => linux_dev_split(m.dev()),
            Err(e) => return failed(format!("the path cannot be examined: {e}")),
        };
        let table = match read_bounded(Path::new("/proc/self/mountinfo")) {
            Ok(t) => t,
            Err(e) => return failed(format!("/proc/self/mountinfo cannot be read: {e}")),
        };
        let mounts = match parse_mountinfo(&table) {
            Ok(m) => m,
            Err(e) => return failed(format!("/proc/self/mountinfo: {e}")),
        };
        linux_measure(&mounts, dev, &|u| {
            std::fs::metadata(u).ok().map(|m| linux_dev_split(m.dev()))
        })
    }
}

// ---------------------------------------------------------------------------
// macOS: /sbin/mount.
// ---------------------------------------------------------------------------

/// One line of macOS `mount` output:
/// `<device> on <mount point> (<type>, <flag>, ...)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacMount {
    /// The mount point.
    pub mount_point: String,
    /// The filesystem type name.
    pub fs_type: String,
    /// Whether the `local` flag (`MNT_LOCAL`) is listed.
    pub local: bool,
}

/// Parse macOS `mount` output. Any malformed line refuses the whole list.
pub fn parse_mac_mount(text: &str) -> Result<Vec<MacMount>, &'static str> {
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let (_, rest) = line.split_once(" on ").ok_or("a line has no ' on '")?;
        let open = rest.rfind(" (").ok_or("a line has no flag list")?;
        let mount_point = rest.get(..open).ok_or("a line is malformed")?;
        let flags = rest
            .get(open + 2..)
            .and_then(|f| f.strip_suffix(')'))
            .ok_or("a flag list is not closed")?;
        let mut parts = flags.split(", ");
        let fs_type = parts
            .next()
            .filter(|t| !t.is_empty())
            .ok_or("a line has no type")?;
        let local = parts.any(|f| f == "local");
        out.push(MacMount {
            mount_point: mount_point.to_owned(),
            fs_type: fs_type.to_owned(),
            local,
        });
    }
    if out.is_empty() {
        return Err("the mount list is empty");
    }
    Ok(out)
}

/// The measurement for a path with device `dev`: local only when the
/// device equals that of an `apfs`/`hfs` mount flagged `local`
/// (`dev_of` is asked ONLY about those mount points). Otherwise refused,
/// naming the mount the path lexically appears to be on.
pub fn mac_measure(
    mounts: &[MacMount],
    path: &str,
    dev: u64,
    dev_of: &dyn Fn(&str) -> Option<u64>,
) -> FsQuery {
    let candidate = mounts.iter().find(|m| {
        m.local
            && harness_policy::locality::MACOS_LOCAL_TYPES.contains(&m.fs_type.as_str())
            && dev_of(&m.mount_point) == Some(dev)
    });
    if let Some(m) = candidate {
        return FsQuery::MacOs {
            mnt_local: true,
            fs_type_name: m.fs_type.clone(),
        };
    }
    // For the message only (never admitted): the lexically longest mount
    // point containing the path.
    let appears = mounts
        .iter()
        .filter(|m| {
            path == m.mount_point
                || m.mount_point == "/"
                || path.starts_with(&format!("{}/", m.mount_point))
        })
        .max_by_key(|m| m.mount_point.len());
    failed(match appears {
        Some(m) => format!(
            "the path is not on a local APFS or HFS+ volume (it appears to be on {} {}, {})",
            m.fs_type,
            m.mount_point,
            if m.local { "local" } else { "not local" }
        ),
        None => "the path is not on a local APFS or HFS+ volume".to_owned(),
    })
}

#[cfg(target_os = "macos")]
mod macos {
    use harness_policy::locality::FsQuery;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    use crate::capture::{self, Query};

    use super::{failed, mac_measure, parse_mac_mount, MOUNT_TABLE_MAX_BYTES};

    pub(super) fn query(path: &Path) -> FsQuery {
        let dev = match std::fs::metadata(path) {
            Ok(m) => m.dev(),
            Err(e) => return failed(format!("the path cannot be examined: {e}")),
        };
        // Bounded, with a deadline and a cleared environment (H1f-3 review
        // F-7; see crate::capture).
        let out = match capture::query(Query::Mount) {
            Ok(o) => o,
            Err(e) => return failed(format!("/sbin/mount: {e}")),
        };
        if out.len() as u64 > MOUNT_TABLE_MAX_BYTES {
            return failed("the mount list is too large");
        }
        let Ok(text) = String::from_utf8(out) else {
            return failed("the mount list is not UTF-8");
        };
        let mounts = match parse_mac_mount(&text) {
            Ok(m) => m,
            Err(e) => return failed(format!("/sbin/mount: {e}")),
        };
        mac_measure(&mounts, &path.to_string_lossy(), dev, &|mp| {
            std::fs::metadata(mp).ok().map(|m| m.dev())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harness_policy::locality::classify;

    const MOUNTINFO: &str = "\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
23 22 0:21 / /proc rw,nosuid shared:2 - proc proc rw
24 22 0:5 / /dev rw,nosuid shared:3 - devtmpfs udev rw,size=4000k
30 22 0:40 / /mnt/nfs rw,relatime shared:9 - nfs4 server:/export rw,vers=4.2
31 22 0:41 / /mnt/smb\\040share rw shared:10 - cifs //server/share rw,vers=3.1.1
32 22 0:42 / /mnt/sshfs rw,nosuid,nodev shared:11 - fuse.sshfs user@host: rw,user_id=1000
33 22 0:43 / /var/lib/docker/overlay2/x/merged rw shared:12 - overlay overlay rw,lowerdir=/l,upperdir=/var/lib/docker/overlay2/x/diff,workdir=/w
34 22 8:1 /home /bind rw shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
";

    fn linux(dev: (u64, u64)) -> FsQuery {
        let m = parse_mountinfo(MOUNTINFO).unwrap();
        // The overlay's upperdir lives on the root ext4 filesystem.
        linux_measure(&m, dev, &|u| u.starts_with("/var/").then_some((8, 1)))
    }

    #[test]
    fn mountinfo_parses_escapes_and_types() {
        let m = parse_mountinfo(MOUNTINFO).unwrap();
        assert_eq!(m.len(), 8);
        assert_eq!(m[4].mount_point, "/mnt/smb share");
        assert_eq!(m[4].fs_type, "cifs");
        assert_eq!(m[1].dev, (0, 21));
        for bad in [
            "",
            "1 2 3",
            "1 1 x:y / / rw - ext4 a b",
            "1 1 8:1 / /a\\9 rw - ext4 a b",
        ] {
            assert!(parse_mountinfo(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn inv_35_linux_admits_local_types_and_refuses_the_rest() {
        assert!(
            classify(&linux((8, 1))).is_ok(),
            "ext4 (and its bind mount)"
        );
        for (dev, what) in [
            ((0, 40), "nfs4"),
            ((0, 41), "cifs"),
            ((0, 42), "fuse.sshfs"),
            ((0, 5), "devtmpfs"),
            ((0, 21), "proc"),
        ] {
            let e = classify(&linux(dev)).unwrap_err();
            assert!(e.detected.contains(what), "{what}: {e}");
        }
        // No entry for the device: refused, never assumed local.
        assert!(classify(&linux((9, 9))).is_err());
        // overlay over a local upper layer is admitted.
        assert_eq!(
            classify(&linux((0, 43))).unwrap().fs_type,
            "overlayfs over ext4"
        );
    }

    #[test]
    fn linux_entries_that_disagree_are_refused() {
        let t = "1 0 8:1 / / rw - ext4 a rw\n2 1 8:1 / /x rw - nfs4 b rw\n";
        let m = parse_mountinfo(t).unwrap();
        assert!(classify(&linux_measure(&m, (8, 1), &|_| None)).is_err());
    }

    #[test]
    fn linux_dev_numbers_split_like_glibc() {
        // makedev(8, 1) and makedev(259, 65537)
        assert_eq!(linux_dev_split(0x801), (8, 1));
        let (maj, min) = (259u64, 65537u64);
        let dev =
            ((maj & 0xfff) << 8) | ((maj & !0xfff) << 32) | (min & 0xff) | ((min & !0xff) << 12);
        assert_eq!(linux_dev_split(dev), (259, 65537));
    }

    const MAC: &str = "\
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
devfs on /dev (devfs, local, nobrowse)
/dev/disk3s5 on /System/Volumes/Data (apfs, local, journaled, nobrowse, protect, root data)
map auto_home on /System/Volumes/Data/home (autofs, automounted, nobrowse)
//user@server/share on /Volumes/share (smbfs, nodev, nosuid, mounted by user)
server:/export on /Volumes/nfs (nfs, nodev, nosuid, mounted by user)
/dev/disk6s2 on /Volumes/Shared Support (hfs, local, nodev, nosuid, read-only, nobrowse)
/dev/disk7s1 on /Volumes/Stick (msdos, local, nodev, nosuid, noowners)
/dev/disk9s1 on /Volumes/NetImage (apfs, nodev, nosuid, mounted by user)
";

    fn mac(path: &str, dev: u64) -> (FsQuery, Vec<String>) {
        let m = parse_mac_mount(MAC).unwrap();
        let asked = std::cell::RefCell::new(Vec::new());
        let q = mac_measure(&m, path, dev, &|mp| {
            asked.borrow_mut().push(mp.to_owned());
            Some(match mp {
                "/" => 1,
                "/System/Volumes/Data" => 5,
                "/Volumes/Shared Support" => 6,
                "/Volumes/NetImage" => 9,
                _ => 99,
            })
        });
        (q, asked.into_inner())
    }

    #[test]
    fn mac_mount_output_parses_names_with_spaces() {
        let m = parse_mac_mount(MAC).unwrap();
        assert_eq!(m[6].mount_point, "/Volumes/Shared Support");
        assert_eq!((m[6].fs_type.as_str(), m[6].local), ("hfs", true));
        assert_eq!((m[4].fs_type.as_str(), m[4].local), ("smbfs", false));
        assert!(parse_mac_mount("").is_err());
        assert!(parse_mac_mount("x on / apfs").is_err());
    }

    #[test]
    fn inv_35_mac_admits_only_a_local_apfs_or_hfs_device() {
        // Lexically under the sealed system volume "/", but on the Data
        // volume's device (a firmlink): the DEVICE decides.
        let (q, asked) = mac("/opt/state", 5);
        assert_eq!(classify(&q).unwrap().fs_type, "apfs", "the Data volume");
        // Only local apfs/hfs mount points are ever examined: never a
        // network mount, which could hang.
        assert!(asked.iter().all(
            |a| ["/", "/System/Volumes/Data", "/Volumes/Shared Support"].contains(&a.as_str())
        ));
        for (path, dev, what) in [
            ("/Volumes/share/state", 40, "smbfs"),
            ("/Volumes/nfs/state", 41, "nfs"),
            ("/Volumes/Stick/state", 42, "msdos"),
            // apfs, but not flagged local (e.g. a disk image on a share).
            ("/Volumes/NetImage/state", 9, "apfs"),
            ("/dev", 43, "devfs"),
            // Lexically under the local Data volume, but on another device
            // (e.g. something mounted below it that the list names
            // differently): refused, never admitted by path prefix.
            ("/System/Volumes/Data/elsewhere/state", 77, "apfs"),
        ] {
            let e = classify(&mac(path, dev).0).unwrap_err();
            assert!(e.detected.contains(what), "{what}: {e}");
        }
    }

    #[test]
    fn inv_35_this_host_admits_a_local_directory_and_refuses_dev() {
        let here = std::env::temp_dir();
        let q = SystemProbe.query(&here.to_string_lossy());
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            let local = classify(&q);
            assert!(local.is_ok(), "{q:?}");
        } else {
            assert!(classify(&q).is_err());
        }
        assert!(
            classify(&SystemProbe.query("/dev")).is_err(),
            "devfs/devtmpfs"
        );
        assert!(classify(&SystemProbe.query("/no/such/path/at/all")).is_err());
    }
}
