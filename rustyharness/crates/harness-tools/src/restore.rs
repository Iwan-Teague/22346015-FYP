//! The restore primitive (P-22): put a stored file image's bytes back,
//! under digests verified both ways.
//!
//! [`restore_file`] is the one primitive every later restore route (the
//! P-26 restore-to-step and a user's `/undo` among them) must go through.
//! It takes the image to restore (its bytes and their SHA-256, which is
//! the blob name the pre-image store keeps them under) and the digest the
//! file must hold right now (the after-image's, so a restore can never
//! clobber a change the harness has not seen). Every digest is checked
//! before anything is written, and the write is applied exactly as the
//! edit engine applies: atomically, then re-read and verified.
//!
//! The caller owns what [`restore_file`] does not check: whether the path
//! is protected (an editable file is never protected, so a pre-image of
//! one can only be restored onto a path that was editable) and the
//! journaling of the restore itself (P-26 owns the `Restored` record).
//!
//! Undo needs the two moves [`restore_file`] cannot express, so P-26 adds
//! them as siblings under the same rules (P-26): [`recreate_file`] puts a
//! pre-image back where the file is now GONE (the inverse of a delete),
//! and [`uncreate_file`] takes a file away again after checking it still
//! holds the digest the edit produced (the inverse of a create). Both
//! verify every digest before anything moves, and both walk the same
//! never-through-a-link path as every other access.

use std::io;
use std::path::Path;

use harness_core::{sha256, Digest};
use harness_policy::workspace_path;

use crate::builtin::{resolve, ResolveErr};
use crate::edit::{atomic_write, read_capped, EditError, EDIT_MAX_BYTES};
use crate::provider::Image;

/// Why a restore was refused. Nothing here can mean the file was touched:
/// the write is the last step, and only its post-write verification can
/// fail after bytes moved.
#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    /// The path fails the lexical workspace rule (§4.8).
    #[error("the path is refused: {0}")]
    PathRefused(harness_policy::PathRefused),
    /// Nothing exists at the path (or an intermediate component).
    #[error("no such file or directory")]
    NotFound,
    /// A component of the path is a symlink (never followed).
    #[error("a path component is a symlink; symlinks are never followed")]
    Symlink,
    /// Not a regular file.
    #[error("not a regular file")]
    NotAFile,
    /// Something already exists at the path, so a recreate would clobber
    /// it: the inverse of a delete only applies where the delete's effect
    /// still stands. The path is untouched.
    #[error("a file already exists at the path")]
    Exists,
    /// The image's bytes do not hash to their own digest: the blob is not
    /// the evidence it claims to be, so nothing is restored.
    #[error("the stored image does not hash to its digest: found {found}, expected {expected}")]
    BlobMismatch {
        /// The digest the image claims.
        expected: Digest,
        /// The digest its bytes have.
        found: Digest,
    },
    /// The file does not hold the expected digest right now: it changed
    /// since the image was taken, and a restore would clobber that change.
    /// The file is untouched.
    #[error(
        "the file changed since the image was taken: it hashes to {found}, expected {expected}"
    )]
    ChangedSince {
        /// The digest the file should hold (the after-image's).
        expected: Digest,
        /// The digest the file has.
        found: Digest,
    },
    /// The write was applied but the re-read did not find the image's
    /// digest: like the edit engine's `Unverified`, the only case where
    /// the workspace may have changed.
    #[error("the restored file does not hash to its image: found {found}, expected {expected}")]
    Verify {
        /// The digest the restored file should have.
        expected: Digest,
        /// The digest found on re-read.
        found: Digest,
    },
    /// Larger than the read cap: not a file this harness reads whole, so
    /// not one it restores. Checked before anything is written.
    #[error("{len} bytes is over the {cap}-byte cap")]
    TooLarge {
        /// The offending size.
        len: u64,
        /// The cap.
        cap: u64,
    },
    /// Any other file-system error.
    #[error("the file system refused the operation: {0}")]
    Io(#[from] io::Error),
}

impl From<ResolveErr> for RestoreError {
    fn from(e: ResolveErr) -> Self {
        match e {
            ResolveErr::NotFound => RestoreError::NotFound,
            ResolveErr::Symlink => RestoreError::Symlink,
            ResolveErr::Io(e) => RestoreError::Io(e),
        }
    }
}

/// The bounded whole-file read of a file [`resolve`] already showed to be
/// a regular file, in [`RestoreError`] terms: the cap and I/O errors keep
/// their meaning, and anything else means the file changed as it was read
/// (the path walked is re-checked by [`resolve`], so a symlink or a
/// missing file surfaces there first).
fn read_whole(path: &Path, len: u64) -> Result<Vec<u8>, RestoreError> {
    read_capped(path, len, EDIT_MAX_BYTES).map_err(|e| match e {
        EditError::TooLarge { len, cap } => RestoreError::TooLarge { len, cap },
        EditError::Io(e) => RestoreError::Io(e),
        other => RestoreError::Io(io::Error::other(format!(
            "the file changed as it was read: {other}"
        ))),
    })
}

/// Restore `image`'s bytes to the workspace file `rel`, fail closed:
///
/// 1. the image is verified first — its bytes must hash to their own
///    digest — before anything on disk is looked at;
/// 2. the file at `rel` (a real file reached through the same
///    component-by-component, never-through-a-link walk every file
///    access takes) must hash to `expect_current` — the after-image's
///    digest — or the restore is refused with the file untouched;
/// 3. the bytes are applied with the edit engine's atomic write, the
///    file's permissions carried over;
/// 4. the re-read must hash to the image's own digest, or the restore
///    reports [`RestoreError::Verify`] (the workspace may have changed;
///    the caller treats it so, H2b).
pub fn restore_file(
    root: &Path,
    rel: &str,
    image: &Image,
    expect_current: Digest,
) -> Result<(), RestoreError> {
    let wp = workspace_path(rel).map_err(RestoreError::PathRefused)?;
    let found = sha256(&image.bytes);
    if found != image.sha256 {
        return Err(RestoreError::BlobMismatch {
            expected: image.sha256,
            found,
        });
    }
    let (path, meta) = resolve(root, &wp)?;
    let Some(meta) = meta else {
        return Err(RestoreError::NotFound);
    };
    if !meta.is_file() {
        return Err(RestoreError::NotAFile);
    }
    let current = read_whole(&path, meta.len())?;
    let found = sha256(&current);
    if found != expect_current {
        return Err(RestoreError::ChangedSince {
            expected: expect_current,
            found,
        });
    }
    let perms = meta.permissions();
    atomic_write(&path, &image.bytes, Some(perms))?;
    // The re-read takes the same walk and cap as every access: a target
    // that became a symlink or grew past the cap after the rename fails
    // the restore instead of being followed.
    let (path, meta) = resolve(root, &wp)?;
    let Some(meta) = meta else {
        return Err(RestoreError::NotFound);
    };
    if !meta.is_file() {
        return Err(RestoreError::NotAFile);
    }
    let after = read_whole(&path, meta.len())?;
    let found = sha256(&after);
    if found != image.sha256 {
        return Err(RestoreError::Verify {
            expected: image.sha256,
            found,
        });
    }
    Ok(())
}

/// Recreate the workspace file `rel` from `image` (the pre-image a delete
/// kept), where the file must be ABSENT right now — the inverse of the
/// delete, fail closed (P-26):
///
/// 1. the image is verified first, before anything on disk is looked at
///    (as [`restore_file`]);
/// 2. the path must resolve to "only the final component missing": a
///    missing intermediate directory, a symlink anywhere, or anything
///    already at the path refuses the recreate ([`RestoreError::Exists`]
///    when something is there — undo never clobbers);
/// 3. the bytes are applied with the edit engine's atomic write (no
///    permissions to carry: the file they belonged to is gone), then
///    re-read and verified against the image's digest.
///
/// The caller owns the journaling and the tree-digest bookkeeping.
pub fn recreate_file(root: &Path, rel: &str, image: &Image) -> Result<(), RestoreError> {
    let wp = workspace_path(rel).map_err(RestoreError::PathRefused)?;
    let found = sha256(&image.bytes);
    if found != image.sha256 {
        return Err(RestoreError::BlobMismatch {
            expected: image.sha256,
            found,
        });
    }
    let (path, meta) = resolve(root, &wp)?;
    if meta.is_some() {
        return Err(RestoreError::Exists);
    }
    atomic_write(&path, &image.bytes, None)?;
    let (path, meta) = resolve(root, &wp)?;
    let Some(meta) = meta else {
        return Err(RestoreError::NotFound);
    };
    if !meta.is_file() {
        return Err(RestoreError::NotAFile);
    }
    let after = read_whole(&path, meta.len())?;
    let found = sha256(&after);
    if found != image.sha256 {
        return Err(RestoreError::Verify {
            expected: image.sha256,
            found,
        });
    }
    Ok(())
}

/// Take the workspace file `rel` away again (the inverse of a create),
/// fail closed (P-26): the file must exist as a regular file reached
/// through the never-through-a-link walk, must still hash to `after`
/// (the digest the create produced), and is then removed and verified
/// gone. Any other content refuses the un-create with the file untouched.
pub fn uncreate_file(root: &Path, rel: &str, after: Digest) -> Result<(), RestoreError> {
    let wp = workspace_path(rel).map_err(RestoreError::PathRefused)?;
    let (path, meta) = resolve(root, &wp)?;
    let Some(meta) = meta else {
        return Err(RestoreError::NotFound);
    };
    if !meta.is_file() {
        return Err(RestoreError::NotAFile);
    }
    let bytes = read_whole(&path, meta.len())?;
    let found = sha256(&bytes);
    if found != after {
        return Err(RestoreError::ChangedSince {
            expected: after,
            found,
        });
    }
    std::fs::remove_file(&path)?;
    // Verified gone: the path must now resolve to "only the final
    // component missing". Anything still there is a change the harness
    // did not make.
    if resolve(root, &wp)?.1.is_some() {
        return Err(RestoreError::Io(io::Error::other(
            "the file still exists after the removal",
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let ws = std::env::temp_dir().join(format!("restore-{name}"));
        let _ = std::fs::remove_dir_all(&ws);
        std::fs::create_dir_all(&ws).expect("ws");
        ws
    }

    fn image(bytes: &[u8]) -> Image {
        Image {
            sha256: sha256(bytes),
            bytes: bytes.to_vec(),
        }
    }

    // The whole path: a file holds the after digest, the stored pre-image
    // hashes to its own, and the restore puts the prior bytes back,
    // verified by the re-read.
    #[test]
    fn restore_file_verifies_digest() {
        let ws = scratch("verify-digest");
        std::fs::write(ws.join("notes.txt"), b"version one\n").expect("seed");
        let pre = image(b"version zero\n");
        restore_file(&ws, "notes.txt", &pre, sha256(b"version one\n")).expect("restore");
        assert_eq!(
            std::fs::read(ws.join("notes.txt")).expect("read back"),
            b"version zero\n".to_vec()
        );
        // And the way back, now that the file holds the other image's
        // digest again.
        restore_file(
            &ws,
            "notes.txt",
            &image(b"version one\n"),
            sha256(b"version zero\n"),
        )
        .expect("restore back");
        assert_eq!(
            std::fs::read(ws.join("notes.txt")).expect("read back"),
            b"version one\n".to_vec()
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    // The file changed since the image was taken: the restore is refused
    // with the file untouched — a restore never clobbers a change the
    // harness has not seen.
    #[test]
    fn restore_refuses_if_file_changed_since_after_digest() {
        let ws = scratch("changed-since");
        std::fs::write(ws.join("notes.txt"), b"changed since\n").expect("seed");
        let err = restore_file(&ws, "notes.txt", &image(b"prior\n"), sha256(b"after\n"))
            .expect_err("refused");
        assert!(matches!(
            err,
            RestoreError::ChangedSince { expected, found }
                if expected == sha256(b"after\n") && found == sha256(b"changed since\n")
        ));
        assert_eq!(
            std::fs::read(ws.join("notes.txt")).expect("read back"),
            b"changed since\n".to_vec()
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    // The blob is verified before anything is looked at: bytes that do
    // not hash to their own digest are refused with the file untouched,
    // even one that still holds the expected after digest.
    #[test]
    fn restore_refuses_a_blob_that_does_not_hash() {
        let ws = scratch("blob-mismatch");
        std::fs::write(ws.join("notes.txt"), b"current\n").expect("seed");
        let forged = Image {
            sha256: sha256(b"not these bytes"),
            bytes: b"these bytes\n".to_vec(),
        };
        let err =
            restore_file(&ws, "notes.txt", &forged, sha256(b"current\n")).expect_err("refused");
        assert!(matches!(err, RestoreError::BlobMismatch { .. }));
        assert_eq!(
            std::fs::read(ws.join("notes.txt")).expect("read back"),
            b"current\n".to_vec()
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    // The inverse of a delete: the file is gone, the pre-image is
    // recreated at the path and verified by the re-read.
    #[test]
    fn recreate_file_puts_deleted_bytes_back() {
        let ws = scratch("recreate");
        std::fs::create_dir_all(ws.join("dir")).expect("dir");
        recreate_file(&ws, "dir/notes.txt", &image(b"version zero\n")).expect("recreate");
        assert_eq!(
            std::fs::read(ws.join("dir/notes.txt")).expect("read back"),
            b"version zero\n".to_vec()
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    // A recreate never clobbers: something already at the path (or a
    // missing intermediate directory, or a symlink) refuses it.
    #[test]
    fn recreate_file_refuses_when_something_exists() {
        let ws = scratch("recreate-exists");
        std::fs::write(ws.join("notes.txt"), b"someone else\n").expect("seed");
        let err = recreate_file(&ws, "notes.txt", &image(b"prior\n")).expect_err("refused");
        assert!(matches!(err, RestoreError::Exists));
        assert_eq!(
            std::fs::read(ws.join("notes.txt")).expect("read back"),
            b"someone else\n".to_vec()
        );
        // A missing intermediate directory is a plain NotFound.
        let err = recreate_file(&ws, "gone/notes.txt", &image(b"prior\n")).expect_err("refused");
        assert!(matches!(err, RestoreError::NotFound));
        let _ = std::fs::remove_dir_all(&ws);
    }

    // The inverse of a create: a file that still holds the digest the
    // create produced is removed and verified gone.
    #[test]
    fn uncreate_file_removes_the_created_file() {
        let ws = scratch("uncreate");
        std::fs::write(ws.join("notes.txt"), b"fresh\n").expect("seed");
        uncreate_file(&ws, "notes.txt", sha256(b"fresh\n")).expect("uncreate");
        assert!(!ws.join("notes.txt").exists());
        let _ = std::fs::remove_dir_all(&ws);
    }

    // An un-create never removes content the harness has not seen: a
    // file holding any other digest refuses, untouched.
    #[test]
    fn uncreate_file_refuses_when_file_changed() {
        let ws = scratch("uncreate-changed");
        std::fs::write(ws.join("notes.txt"), b"changed\n").expect("seed");
        let err = uncreate_file(&ws, "notes.txt", sha256(b"fresh\n")).expect_err("refused");
        assert!(matches!(
            err,
            RestoreError::ChangedSince { expected, .. } if expected == sha256(b"fresh\n")
        ));
        assert_eq!(
            std::fs::read(ws.join("notes.txt")).expect("read back"),
            b"changed\n".to_vec()
        );
        let _ = std::fs::remove_dir_all(&ws);
    }
}
