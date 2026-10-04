//! The confined file-op helper as the tools' [`FileOps`] implementation
//! (P-36f, design §7.4): every filesystem access of the built-in file
//! tools becomes a `rh-fileop/1` request to the stub process the sandbox
//! confines (§7), so a run that may execute commands reads and writes the
//! workspace only through the kernel-enforced view (INV-42).
//!
//! The mapping, op by op: `lstat`, `read` and `list` are the helper's own
//! ops; a write is `lstat` then, for a new path, `create` (exclusive), for
//! an existing one `replace` with the digest of the bytes the helper last
//! served for that path (fetched by a `read` when they were not cached) —
//! the helper re-checks the digest at the rename, so a write that would
//! clobber a foreign change fails (`changed`) instead of landing (§7.4's
//! stale check, kept because `write_atomic` has no `expect_sha`). A
//! `create_dir` makes the directory by creating and removing a marker file
//! with one new directory allowed (the protocol has no mkdir); `remove_dir`
//! and `remove_file` map to `rmdir`/`unlink`, the latter with the same
//! digest check.
//!
//! What the helper cannot express, this side refuses (fail closed): the
//! workspace root has no workspace-relative path (tools reach it through
//! [`Confined::tree`], which lists the root via the `tree` op plus one
//! `lstat` per depth-one entry), a file whose digest cannot be fetched
//! (over the per-read bound) is not rewritten or removed, and a symlink is
//! never followed or unlinked. An entry the stub cannot `lstat` is skipped
//! by the helper's walks where the in-process walk would refuse — a
//! named residual, recorded in the slice notes.
//!
//! **Losses (§7.5).** A request that times out or loses the helper is an
//! ordinary error of the call (`TimedOut` / other); the helper restarts at
//! the next file call, and the error result is journaled like any tool
//! result (no new journal kind). After three losses in one attempt the
//! run's stop flag is set: the driver stops the run with
//! `StopCause::SandboxLost` instead of continuing on a broken helper.
//!
//! The digest cache is per instance and only ever holds digests of whole
//! files this implementation read or wrote itself; the helper's
//! rename-time check is the authority, so a stale cache entry can only
//! cause a refused write, never a lost update.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use harness_core::{sha256, Digest};
use harness_policy::{workspace_path, WorkspacePath};
use harness_sandbox::fileop::{ErrorCode, FileOpError, FileOpHelper, Reply, Request};

use super::{FileOps, Kind, Listed, Meta, Next, Step};
use crate::builtin::{TreeEntry, WorkspaceTree};

/// A call with no deadline of its own gets this long. The run's own
/// per-call timeout is normally shorter and arrives as the `deadline`
/// argument; this is the backstop for calls that pass `None`.
const DEFAULT_REQUEST_DEADLINE: Duration = Duration::from_secs(30);

/// Most entries one `list` or `tree` request may return: the stub's own
/// cap (a `tree` over a bigger workspace is refused by the helper, where
/// the in-process walk would cap at [`crate::builtin::FACTS_MAX_ENTRIES`]).
const HELPER_MAX_ENTRIES: u32 = 100_000;

/// Most bytes one read may ask for: the protocol's per-read bound minus
/// the one byte the stub reads past it to detect an oversized file.
const DIGEST_READ_MAX: u32 = 8_388_607;

/// The marker file one `create_dir` makes (and removes) to create the
/// directory itself.
const MKDIR_MARKER: &str = ".rh-mkdir";

/// The confined helper as [`FileOps`]: one instance per run attempt,
/// shared by the read, edit and patch tools through their clones.
pub struct Confined {
    root: PathBuf,
    deadline: Duration,
    inner: Arc<Mutex<Inner>>,
    /// Set after the third loss of the attempt; the driver stops the run.
    stop: Arc<AtomicBool>,
}

impl Confined {
    /// How long the view check at startup may take.
    pub const PING_DEADLINE: Duration = Duration::from_secs(10);
}

struct Inner {
    helper: FileOpHelper,
    /// Workspace-relative path → SHA-256 hex of the whole file, for the
    /// last bytes this implementation served or wrote.
    cache: HashMap<String, String>,
    losses: u32,
}

impl std::fmt::Debug for Confined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Confined")
    }
}

impl Confined {
    /// A [`FileOps`] implementation over a started helper. `root` is the
    /// canonical workspace root the helper was given as its `cwd`;
    /// `deadline` bounds one request; `stop` is the run's file-helper stop
    /// flag, set here after the third loss of the attempt.
    pub fn new(
        root: PathBuf,
        helper: FileOpHelper,
        deadline: Duration,
        stop: Arc<AtomicBool>,
    ) -> Self {
        Self {
            root,
            deadline,
            inner: Arc::new(Mutex::new(Inner {
                helper,
                cache: HashMap::new(),
                losses: 0,
            })),
            stop,
        }
    }

    /// The stub's pid while it runs (tests, diagnostics).
    pub fn stub_pid(&self) -> Option<u32> {
        self.lock().ok().and_then(|i| i.helper.pid())
    }

    fn lock(&self) -> io::Result<MutexGuard<'_, Inner>> {
        self.inner
            .lock()
            .map_err(|_| io::Error::other("the file helper's state was poisoned"))
    }

    /// `path` as a workspace-relative [`WorkspacePath`]. Anything the
    /// lexical rule refuses (outside the root, non-UTF-8, the root itself)
    /// is refused here, before any request exists.
    fn rel(&self, path: &Path) -> io::Result<WorkspacePath> {
        let rest = path.strip_prefix(&self.root).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the path is outside the workspace",
            )
        })?;
        if rest.as_os_str().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the workspace root itself has no workspace-relative path",
            ));
        }
        let s = rest
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "the path is not UTF-8"))?;
        workspace_path(s).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
    }

    /// One request with loss accounting: a timeout or a lost helper is an
    /// ordinary error of the call, counted; the third loss of the attempt
    /// sets the run's stop flag (§7.5). The helper restarts at the next
    /// request by itself.
    fn ask(&self, inner: &mut Inner, req: &Request, deadline: Duration) -> io::Result<Reply> {
        match inner.helper.request(req, deadline) {
            Ok(reply) => Ok(reply),
            Err(FileOpError::Timeout) => {
                self.note_loss(inner);
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the file helper passed its deadline",
                ))
            }
            Err(FileOpError::Lost(why)) => {
                self.note_loss(inner);
                Err(io::Error::other(format!("the file helper was lost: {why}")))
            }
            Err(e) => Err(io::Error::other(format!("the file helper refused: {e}"))),
        }
    }

    fn note_loss(&self, inner: &mut Inner) {
        inner.losses += 1;
        if inner.losses >= 3 {
            self.stop.store(true, Ordering::SeqCst);
        }
    }

    fn refused(code: ErrorCode) -> io::Error {
        let (kind, msg) = match code {
            ErrorCode::NoEnt => (io::ErrorKind::NotFound, "no such file or directory"),
            ErrorCode::Symlink => (
                io::ErrorKind::Other,
                "a path component is a symlink; symlinks are never followed",
            ),
            ErrorCode::NotDir => (io::ErrorKind::Other, "not a directory"),
            ErrorCode::IsDir => (io::ErrorKind::Other, "is a directory"),
            ErrorCode::Exists => (io::ErrorKind::AlreadyExists, "the file already exists"),
            ErrorCode::TooBig => (io::ErrorKind::InvalidData, "the file is too large"),
            ErrorCode::Changed => (
                io::ErrorKind::InvalidData,
                "the file changed under the helper",
            ),
            ErrorCode::Denied => (
                io::ErrorKind::PermissionDenied,
                "the sandbox denied the operation",
            ),
            ErrorCode::NLink => (
                io::ErrorKind::InvalidData,
                "the file has more than one link",
            ),
            ErrorCode::Io => (
                io::ErrorKind::Other,
                "the helper's file system refused the operation",
            ),
            ErrorCode::BadReq => (
                io::ErrorKind::InvalidInput,
                "the helper refused the request",
            ),
        };
        io::Error::new(kind, msg)
    }

    /// A reply that must be `Ok`, with its items.
    fn items(reply: Reply) -> io::Result<Vec<Vec<u8>>> {
        match reply {
            Reply::Ok { items } => Ok(items),
            Reply::Err { code } => Err(Self::refused(code)),
        }
    }

    fn malformed(what: &str) -> io::Error {
        io::Error::other(format!("the helper's {what} reply was malformed"))
    }

    /// The whole workspace through the helper's `tree` op (one round trip;
    /// the helper digests file contents itself, §7.4). The entries and
    /// their order match the in-process walk's, so the digest matches too.
    /// A workspace with an entry over the helper's read cap is refused
    /// here where the in-process walk would size it only (fail closed).
    pub fn tree(&mut self, timeout: Duration) -> io::Result<WorkspaceTree> {
        let mut inner = self.lock()?;
        let ms = u32::try_from(timeout.as_millis().min(u128::from(u32::MAX))).unwrap_or(1);
        let reply = self.ask(
            &mut inner,
            &Request::Tree {
                max_entries: HELPER_MAX_ENTRIES,
                timeout_ms: ms.max(1),
            },
            timeout,
        )?;
        let items = Self::items(reply)?;
        let mut entries: Vec<TreeEntry> = Vec::new();
        let mut files = 0u64;
        for group in items.chunks(4) {
            let rel = group.first().ok_or_else(|| Self::malformed("tree"))?;
            let kind = group.get(1).ok_or_else(|| Self::malformed("tree"))?;
            let sha = group.get(3).ok_or_else(|| Self::malformed("tree"))?;
            let (kind, content) = match text(kind).as_str() {
                "dir" => (b'd', String::new()),
                "file" => {
                    files += 1;
                    (b'f', text(sha))
                }
                "link" => (b'l', String::new()),
                _ => (b'o', String::new()),
            };
            entries.push(TreeEntry {
                rel: text(rel),
                kind,
                content,
            });
        }
        entries.sort_by(|a, b| walk_order(&a.rel, &b.rel));
        Ok(WorkspaceTree::from_entries(entries, files, 0))
    }

    /// The root cannot be addressed by a `list` request (the protocol has
    /// no path for it), so a walk that starts at the root gets the
    /// depth-one entries from the `tree` op, each confirmed by its own
    /// `lstat` (the list shows lengths).
    fn list_root(&mut self, visit: &mut dyn FnMut(Step) -> Next) -> io::Result<()> {
        let timeout = self.deadline;
        let tree = self.tree(timeout)?;
        for entry in &tree.entries {
            if entry.rel.contains('/') {
                continue;
            }
            let path = self.root.join(&entry.rel);
            let meta = self.lstat(&path)?;
            if visit(Step::Entry(Listed {
                path,
                name: entry.rel.clone(),
                meta,
            })) == Next::Stop
            {
                return Ok(());
            }
        }
        Ok(())
    }

    /// The digest the helper would expect for `wp`'s current bytes: the
    /// cached one when the whole file was served or written through here,
    /// else a fetch-and-hash. A file too big for one read cannot be
    /// checked, so it cannot be rewritten or removed through the helper.
    fn digest_of(&self, inner: &mut Inner, wp: &WorkspacePath) -> io::Result<Digest> {
        if let Some(hex) = inner.cache.get(wp.as_str()) {
            return hex_digest(hex);
        }
        let reply = self.ask(
            inner,
            &Request::Read {
                path: wp.clone(),
                max: DIGEST_READ_MAX,
            },
            self.deadline,
        )?;
        let items = Self::items(reply)?;
        let bytes = items
            .into_iter()
            .next()
            .ok_or_else(|| Self::malformed("read"))?;
        let digest = sha256(&bytes);
        inner
            .cache
            .insert(wp.as_str().to_owned(), digest.to_string());
        Ok(digest)
    }
}

/// Compare two relative paths the way the walk orders them: component by
/// component (builtin.rs's `walk_order`, mirrored here so the helper's
/// entries land in the same order and hash to the same digest).
fn walk_order(a: &str, b: &str) -> std::cmp::Ordering {
    a.split('/').cmp(b.split('/'))
}

fn num(item: &[u8]) -> io::Result<u64> {
    text(item)
        .parse::<u64>()
        .map_err(|_| io::Error::other("the helper's reply was malformed"))
}

fn text(item: &[u8]) -> String {
    String::from_utf8_lossy(item).into_owned()
}

fn kind_of(s: &str) -> Kind {
    match s {
        "dir" => Kind::Dir,
        "file" => Kind::File,
        "link" => Kind::Symlink,
        _ => Kind::Other,
    }
}

fn meta_of(items: &[Vec<u8>]) -> io::Result<Meta> {
    let kind = items
        .first()
        .map(|k| kind_of(&text(k)))
        .ok_or_else(|| Confined::malformed("lstat"))?;
    let len = items
        .get(1)
        .map(|l| num(l))
        .transpose()?
        .ok_or_else(|| Confined::malformed("lstat"))?;
    // The stub prints the mode in octal (`sprintf "%o"`).
    let mode = items
        .get(2)
        .map(|m| u32::from_str_radix(&text(m), 8).map_err(|_| Confined::malformed("lstat")))
        .transpose()?;
    Ok(Meta { len, kind, mode })
}

fn hex_digest(s: &str) -> io::Result<Digest> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return Err(io::Error::other("the helper's digest was malformed"));
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = bytes
            .get(i * 2)
            .and_then(|h| (*h as char).to_digit(16))
            .ok_or_else(|| io::Error::other("the helper's digest was malformed"))?;
        let lo = bytes
            .get(i * 2 + 1)
            .and_then(|l| (*l as char).to_digit(16))
            .ok_or_else(|| io::Error::other("the helper's digest was malformed"))?;
        *slot = ((hi << 4) | lo) as u8;
    }
    Ok(Digest::from_bytes(out))
}

impl FileOps for Confined {
    fn clone_box(&self) -> Box<dyn FileOps> {
        Box::new(Confined {
            root: self.root.clone(),
            deadline: self.deadline,
            inner: Arc::clone(&self.inner),
            stop: Arc::clone(&self.stop),
        })
    }

    fn lstat(&mut self, path: &Path) -> io::Result<Meta> {
        if path == self.root {
            // The root is a real directory (checked before the helper was
            // started); the stub has no path for it, and no caller needs
            // its facts beyond the kind.
            return Ok(Meta {
                len: 0,
                kind: Kind::Dir,
                mode: Some(0o755),
            });
        }
        let wp = self.rel(path)?;
        let mut inner = self.lock()?;
        let reply = self.ask(&mut inner, &Request::Lstat { path: wp }, self.deadline);
        match reply? {
            Reply::Err {
                code: ErrorCode::Symlink,
            } => Ok(Meta {
                len: 0,
                kind: Kind::Symlink,
                mode: None,
            }),
            other => meta_of(&Self::items(other)?),
        }
    }

    fn canonicalize(&mut self, path: &Path) -> io::Result<PathBuf> {
        // The helper's view has no links to resolve (the stub refuses to
        // follow or traverse one), so the canonical form is textual.
        if path == self.root {
            return Ok(self.root.clone());
        }
        let wp = self.rel(path)?;
        Ok(self.root.join(wp.as_str()))
    }

    fn list(&mut self, dir: &Path, visit: &mut dyn FnMut(Step) -> Next) -> io::Result<()> {
        if dir == self.root {
            return self.list_root(visit);
        }
        let wp = self.rel(dir)?;
        let mut inner = self.lock()?;
        let reply = self.ask(
            &mut inner,
            &Request::List {
                path: wp,
                max_entries: HELPER_MAX_ENTRIES,
                depth: 1,
            },
            self.deadline,
        )?;
        let items = Self::items(reply)?;
        for group in items.chunks(3) {
            let name = group.first().ok_or_else(|| Self::malformed("list"))?;
            let kind = group.get(1).ok_or_else(|| Self::malformed("list"))?;
            let len = group.get(2).ok_or_else(|| Self::malformed("list"))?;
            let name = text(name);
            let meta = Meta {
                len: num(len)?,
                kind: kind_of(&text(kind)),
                mode: None,
            };
            if visit(Step::Entry(Listed {
                path: dir.join(&name),
                name,
                meta,
            })) == Next::Stop
            {
                return Ok(());
            }
        }
        Ok(())
    }

    fn read(&mut self, path: &Path, max: u64, deadline: Option<Instant>) -> io::Result<Vec<u8>> {
        let wp = self.rel(path)?;
        let cap = max.min(u64::from(DIGEST_READ_MAX));
        let mut inner = self.lock()?;
        let ttl = deadline
            .and_then(|t| t.checked_duration_since(Instant::now()))
            .unwrap_or(DEFAULT_REQUEST_DEADLINE.min(self.deadline));
        let reply = self.ask(
            &mut inner,
            &Request::Read {
                path: wp.clone(),
                max: u32::try_from(cap).unwrap_or(DIGEST_READ_MAX),
            },
            ttl.max(Duration::from_millis(1)),
        )?;
        let items = Self::items(reply)?;
        let mut bytes = items
            .into_iter()
            .next()
            .ok_or_else(|| Self::malformed("read"))?;
        if bytes.len() as u64 > max {
            bytes.truncate(usize::try_from(max).unwrap_or(usize::MAX));
        } else {
            // The whole file came back: cache its digest for the next
            // write's or unlink's stale check.
            inner
                .cache
                .insert(wp.as_str().to_owned(), sha256(&bytes).to_string());
        }
        Ok(bytes)
    }

    fn create_dir(&mut self, path: &Path) -> io::Result<()> {
        let wp = self.rel(path)?;
        let mut inner = self.lock()?;
        match self.ask(
            &mut inner,
            &Request::Lstat { path: wp.clone() },
            self.deadline,
        ) {
            Ok(Reply::Ok { .. }) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "the directory already exists",
                ));
            }
            Ok(Reply::Err {
                code: ErrorCode::NoEnt,
            }) => {}
            Ok(Reply::Err { code }) => return Err(Self::refused(code)),
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            Err(_) => {}
        }
        // No mkdir op: create a marker file allowing exactly one new
        // directory — the target itself — then remove the marker. What is
        // left behind is the empty directory (0755, the stub's mkdir mode).
        let marker = workspace_path(&format!("{}/{}", wp.as_str(), MKDIR_MARKER))
            .map_err(|_| io::Error::other("the marker path was refused"))?;
        let reply = self.ask(
            &mut inner,
            &Request::Create {
                path: marker.clone(),
                bytes: Vec::new(),
                mode: 0o644,
                max_new_dirs: 1,
            },
            self.deadline,
        )?;
        Self::items(reply)?;
        let reply = self.ask(
            &mut inner,
            &Request::Unlink {
                path: marker,
                expect_sha: sha256(b""),
            },
            self.deadline,
        )?;
        Self::items(reply)?;
        Ok(())
    }

    fn remove_dir(&mut self, path: &Path) -> io::Result<()> {
        let wp = self.rel(path)?;
        let mut inner = self.lock()?;
        let reply = self.ask(&mut inner, &Request::Rmdir { path: wp }, self.deadline)?;
        Self::items(reply)?;
        Ok(())
    }

    fn remove_file(&mut self, path: &Path) -> io::Result<()> {
        let wp = self.rel(path)?;
        let mut inner = self.lock()?;
        let expect_sha = self.digest_of(&mut inner, &wp)?;
        let reply = self.ask(
            &mut inner,
            &Request::Unlink {
                path: wp.clone(),
                expect_sha,
            },
            self.deadline,
        )?;
        Self::items(reply)?;
        inner.cache.remove(wp.as_str());
        Ok(())
    }

    fn write_atomic(&mut self, path: &Path, bytes: &[u8], mode: Option<u32>) -> io::Result<()> {
        let wp = self.rel(path)?;
        let mut inner = self.lock()?;
        let exists = match self.ask(
            &mut inner,
            &Request::Lstat { path: wp.clone() },
            self.deadline,
        ) {
            Ok(Reply::Ok { items }) => Some(
                items
                    .first()
                    .map(|k| kind_of(&text(k)))
                    .ok_or_else(|| Self::malformed("lstat"))?,
            ),
            Ok(Reply::Err {
                code: ErrorCode::NoEnt,
            }) => None,
            Ok(Reply::Err { code }) => return Err(Self::refused(code)),
            Err(e) => return Err(e),
        };
        match exists {
            None => {
                let reply = self.ask(
                    &mut inner,
                    &Request::Create {
                        path: wp.clone(),
                        bytes: bytes.to_vec(),
                        mode: mode.unwrap_or(0),
                        max_new_dirs: 0,
                    },
                    self.deadline,
                )?;
                Self::items(reply)?;
                inner
                    .cache
                    .insert(wp.as_str().to_owned(), sha256(bytes).to_string());
                Ok(())
            }
            Some(Kind::Symlink) => Err(Self::refused(ErrorCode::Symlink)),
            Some(kind) if kind.is_dir() => Err(Self::refused(ErrorCode::IsDir)),
            Some(_) => {
                // The stub preserves the old mode at the rename, which is
                // what the callers pass back anyway; a `mode` for a new
                // file goes through `Create` above.
                let expect_sha = self.digest_of(&mut inner, &wp)?;
                let reply = self.ask(
                    &mut inner,
                    &Request::Replace {
                        path: wp.clone(),
                        bytes: bytes.to_vec(),
                        expect_sha,
                    },
                    self.deadline,
                )?;
                let items = Self::items(reply)?;
                let sha = items
                    .first()
                    .map(|s| text(s))
                    .ok_or_else(|| Self::malformed("replace"))?;
                inner.cache.insert(wp.as_str().to_owned(), sha);
                Ok(())
            }
        }
    }

    fn ping(&mut self) {
        // A health check has no channel to report through: a view check
        // that answers (the kernel's denial) is health; anything else — a
        // broken helper, a lost conversation — fails the next real call
        // (and is counted there).
        let mut inner = match self.lock() {
            Ok(inner) => inner,
            Err(_) => return,
        };
        let req = Request::Ping {
            outside_probe_path: "/etc/hosts".to_string(),
        };
        let _ = self.ask(&mut inner, &req, Self::PING_DEADLINE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_digest_round_trips_the_stub_form() {
        let d = sha256(b"note");
        let parsed = hex_digest(&d.to_string()).unwrap();
        assert_eq!(parsed, d);
    }

    #[test]
    fn hex_digest_refuses_a_short_or_non_hex_form() {
        assert!(hex_digest("ab").is_err());
        assert!(hex_digest(&"g".repeat(64)).is_err());
    }

    #[test]
    fn lstat_items_become_meta_with_octal_mode() {
        let m = meta_of(&[
            b"file".to_vec(),
            b"12".to_vec(),
            b"644".to_vec(),
            b"1".to_vec(),
        ])
        .unwrap();
        assert_eq!(m.kind, Kind::File);
        assert_eq!(m.len, 12);
        assert_eq!(m.mode, Some(0o644));
    }

    #[test]
    fn walk_order_matches_the_components_rule() {
        assert_eq!(walk_order("a/b", "a-c"), std::cmp::Ordering::Less);
        assert_eq!(walk_order("a", "a/b"), std::cmp::Ordering::Less);
    }
}
