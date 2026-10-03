//! [`FileOps`] as today's code: plain calls into `std::fs`, unconfined.
//! This is the whole of the filesystem behaviour the built-in file tools
//! had before P-36e, gathered here verbatim (same limits, same errors,
//! same temp-file names).

use super::{FileOps, Kind, Listed, Meta, Next, Step};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// How big one read chunk is, and how many times a temp-file name is
/// retried before giving up.
const CHUNK_BYTES: usize = 64 * 1024;
const TEMP_TRIES: u32 = 16;

static TEMP_N: AtomicU64 = AtomicU64::new(0);

/// The in-process implementation: every call is the plain `std::fs` call
/// the tools made before the seam existed.
#[derive(Debug, Clone, Copy, Default)]
pub struct InProcess;

impl FileOps for InProcess {
    fn clone_box(&self) -> Box<dyn FileOps> {
        Box::new(*self)
    }

    fn lstat(&mut self, path: &Path) -> io::Result<Meta> {
        fs::symlink_metadata(path).map(|m| meta_of(&m))
    }

    fn canonicalize(&mut self, path: &Path) -> io::Result<PathBuf> {
        fs::canonicalize(path)
    }

    fn list(&mut self, dir: &Path, visit: &mut dyn FnMut(Step) -> Next) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    if visit(Step::Unreadable) == Next::Stop {
                        break;
                    }
                    continue;
                }
            };
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let step = match fs::symlink_metadata(&path) {
                Ok(m) => Step::Entry(Listed {
                    path,
                    name,
                    meta: meta_of(&m),
                }),
                Err(_) => Step::Unreadable,
            };
            if visit(step) == Next::Stop {
                break;
            }
        }
        Ok(())
    }

    fn read(&mut self, path: &Path, max: u64, deadline: Option<Instant>) -> io::Result<Vec<u8>> {
        let mut f = File::open(path)?.take(max);
        let mut bytes = Vec::new();
        let mut buf = vec![0u8; CHUNK_BYTES];
        loop {
            if let Some(deadline) = deadline {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the facts walk passed its deadline",
                    ));
                }
            }
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(buf.get(..n).unwrap_or(&buf));
        }
        Ok(bytes)
    }

    fn create_dir(&mut self, path: &Path) -> io::Result<()> {
        fs::create_dir(path)
    }

    fn remove_dir(&mut self, path: &Path) -> io::Result<()> {
        fs::remove_dir(path)
    }

    fn remove_file(&mut self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }

    fn write_atomic(&mut self, path: &Path, bytes: &[u8], mode: Option<u32>) -> io::Result<()> {
        let dir = path.parent().unwrap_or(Path::new("."));
        let (tmp, mut f) = create_temp(dir)?;
        let done = (|| -> io::Result<()> {
            f.write_all(bytes)?;
            if let Some(mode) = mode {
                f.set_permissions(permissions_of(mode))?;
            }
            f.sync_all()?;
            drop(f);
            fs::rename(&tmp, path)
        })();
        if done.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        done
    }
}

/// The `lstat` facts of one metadata value: the length, the kind and, on
/// platforms with permission bits, those bits.
fn meta_of(m: &fs::Metadata) -> Meta {
    let kind = if m.file_type().is_symlink() {
        Kind::Symlink
    } else if m.is_dir() {
        Kind::Dir
    } else if m.is_file() {
        Kind::File
    } else {
        Kind::Other
    };
    Meta {
        len: m.len(),
        kind,
        #[cfg(unix)]
        mode: Some(std::os::unix::fs::PermissionsExt::mode(&m.permissions())),
        #[cfg(not(unix))]
        mode: None,
    }
}

/// Permission bits back into a `Permissions` value for the rewrite.
#[cfg(unix)]
fn permissions_of(mode: u32) -> fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    fs::Permissions::from_mode(mode)
}

#[cfg(not(unix))]
fn permissions_of(_mode: u32) -> fs::Permissions {
    fs::Permissions::default()
}

/// A fresh temp file in `dir`, named like the edits always named theirs
/// (`.rh-edit-{pid}-{n}.tmp`), never following an existing name.
fn create_temp(dir: &Path) -> io::Result<(PathBuf, File)> {
    let pid = std::process::id();
    for _ in 0..TEMP_TRIES {
        let n = TEMP_N.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!(".rh-edit-{pid}-{n}.tmp"));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => return Ok((path, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "every temp-file name tried already exists",
    ))
}
