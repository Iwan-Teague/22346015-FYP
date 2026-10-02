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
}
