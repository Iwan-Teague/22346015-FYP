//! The one seam every built-in file tool touches the filesystem through
//! (P-36e §7.4): [`FileOps`], with [`InProcess`] as today's in-process
//! implementation. Results are byte-identical to the direct calls it
//! replaced; P-36f adds a confined implementation behind the same trait.

mod in_process;

pub use in_process::InProcess;

use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// What a directory entry looked like when it was listed: its full path,
/// its (lossily decoded) file name and its `lstat` facts.
#[derive(Debug, Clone)]
pub struct Listed {
    /// The entry's full path (the directory joined with the name).
    pub path: PathBuf,
    /// The entry's file name, lossily decoded from the OS bytes.
    pub name: String,
    /// The entry's `lstat` facts (never the link target's).
    pub meta: Meta,
}

/// One step of a directory listing: an entry with its facts, or an entry
/// that could not be `lstat`'d (counted by callers, never fatal).
#[derive(Debug)]
pub enum Step {
    /// A listed entry.
    Entry(Listed),
    /// The directory entry could not be read.
    Unreadable,
}

/// Whether a listing goes on (`Continue`) or stops early (`Stop`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// Keep listing.
    Continue,
    /// Stop after this entry.
    Stop,
}

/// What kind a path's final component is, per `lstat` (a symlink is a
/// symlink, never its target).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symlink.
    Symlink,
    /// Anything else (a socket, a device, ...).
    Other,
}

impl Kind {
    /// The final component is a regular file.
    pub fn is_file(self) -> bool {
        self == Kind::File
    }

    /// The final component is a directory.
    pub fn is_dir(self) -> bool {
        self == Kind::Dir
    }

    /// The final component is a symlink.
    pub fn is_symlink(self) -> bool {
        self == Kind::Symlink
    }
}

/// The facts a file tool needs about one path: its length, its kind and,
/// where the platform exposes them, its permission bits (so a rewrite can
/// put them back).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    /// The file's length in bytes (a symlink's own length, never the
    /// target's).
    pub len: u64,
    /// The path's kind.
    pub kind: Kind,
    /// The permission bits, when the platform exposes them.
    pub mode: Option<u32>,
}

/// Every filesystem access of the built-in read, search, glob, list,
/// outline, edit and workspace-tree tools goes through here, so P-36f can
/// confine the same tools by swapping the implementation.
///
/// Error values are the OS's own; callers map them to model-facing text.
/// A `deadline` of `None` means the call is too short to bother checking.
pub trait FileOps: std::fmt::Debug {
    /// A boxed clone of this implementation, so a `Box<dyn FileOps>` can be
    /// cloned along with the engine that holds it (the `Clone` on
    /// `EditEngine` and `EditTools` rides on this).
    fn clone_box(&self) -> Box<dyn FileOps>;

    /// `lstat`: the facts of `path` itself, a symlink never followed.
    fn lstat(&mut self, path: &Path) -> io::Result<Meta>;

    /// The canonical (symlink-free, absolute) form of `path`.
    fn canonicalize(&mut self, path: &Path) -> io::Result<PathBuf>;

    /// List `dir`, calling `visit` once per directory entry with its
    /// `lstat` facts (a `Step::Unreadable` for an entry that cannot be
    /// `lstat`'d). Returns the `read_dir` error, if the directory itself
    /// could not be read; `Next::Stop` ends the listing early.
    fn list(&mut self, dir: &Path, visit: &mut dyn FnMut(Step) -> Next) -> io::Result<()>;

    /// Read at most `max` bytes of `path`, honouring `deadline` between
    /// chunks (a passed deadline is an `io::Error` of kind `TimedOut`).
    fn read(&mut self, path: &Path, max: u64, deadline: Option<Instant>) -> io::Result<Vec<u8>>;

    /// Create the directory `path` (its parent must exist).
    fn create_dir(&mut self, path: &Path) -> io::Result<()>;

    /// Remove the empty directory `path`.
    fn remove_dir(&mut self, path: &Path) -> io::Result<()>;

    /// Remove the file `path`.
    fn remove_file(&mut self, path: &Path) -> io::Result<()>;

    /// Write `bytes` to `path` atomically: a temp file in the target's
    /// directory, synced, renamed over the target, its permission bits
    /// restored from `mode` when the platform has them.
    fn write_atomic(&mut self, path: &Path, bytes: &[u8], mode: Option<u32>) -> io::Result<()>;

    /// A health check for future confined implementations; the in-process
    /// one has nothing to say.
    fn ping(&mut self) {}
}

impl Clone for Box<dyn FileOps> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}
