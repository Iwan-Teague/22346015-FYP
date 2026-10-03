//! The scratch-copy helper (P-48): walk a workspace, digest every regular
//! file, and copy it byte-for-byte into a fresh directory. Shared by the
//! CLI's `--workspace-mode scratch` (P-52) and the `compare` verb, which
//! makes one fresh copy per arm from the same source. A copy never follows
//! a symlink (a symlink is skipped, never copied), never enters `target/`
//! or `node_modules/`, and enters `.git` only on request.

use std::path::Path;

use gate_outcome::Digest;
use harness_core::sha256;

/// The directories a copy never enters.
const SKIPPED_DIRS: [&str; 2] = ["target", "node_modules"];

/// The directory entered only when the caller asks for it.
const GIT_DIR: &str = ".git";

/// The scratch copy's file-count cap (P-52). The walk itself is cap-free;
/// the caps are the caller's policy, so a refusal can name the workspace
/// before anything is copied. Generous on purpose: the point is a stopped
/// run, not a silent truncation.
pub const SCRATCH_MAX_FILES: usize = 20_000;

/// The scratch copy's byte cap (P-52); see [`SCRATCH_MAX_FILES`].
pub const SCRATCH_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// One regular file a walk found (and, in [`copy_workspace`], copied).
#[derive(Debug, Clone)]
pub struct CopiedFile {
    /// The path under the root, with forward slashes.
    pub rel: String,
    /// The SHA-256 of the file's bytes.
    pub digest: Digest,
    /// The file's size, in bytes.
    pub bytes: u64,
}

/// Walk `root`, collecting every regular file's relative path (forward
/// slashes), content digest and size, sorted by path (so a manifest and
/// its `WorkspaceModeRecord` digest list are reproducible). The walk is
/// read-only; the caps are the caller's policy.
pub fn copy_walk(root: &Path, with_git: bool) -> Result<Vec<CopiedFile>, String> {
    let mut files = Vec::new();
    walk(root, root, with_git, &mut files)?;
    files.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(files)
}

/// Copy every regular file [`copy_walk`] finds in `source` into `dest`,
/// byte-for-byte, creating directories as needed, and return the same
/// list the walk produced. The caps ([`SCRATCH_MAX_FILES`],
/// [`SCRATCH_MAX_BYTES`]) are checked after the walk and before the
/// first byte is copied: a workspace over either is refused whole, never
/// copied short. `dest` should be a name nothing else uses (the callers
/// pick a fresh stamp): a copy is never merged into an existing tree.
pub fn copy_workspace(
    source: &Path,
    dest: &Path,
    with_git: bool,
) -> Result<Vec<CopiedFile>, String> {
    let files = copy_walk(source, with_git)?;
    if files.len() > SCRATCH_MAX_FILES {
        return Err(format!(
            "the workspace has {} files; the cap is {SCRATCH_MAX_FILES}",
            files.len()
        ));
    }
    let total: u64 = files.iter().map(|f| f.bytes).sum();
    if total > SCRATCH_MAX_BYTES {
        return Err(format!(
            "the workspace is {total} bytes; the cap is {SCRATCH_MAX_BYTES} bytes"
        ));
    }
    std::fs::create_dir_all(dest).map_err(|e| format!("cannot create {}: {e}", dest.display()))?;
    for f in &files {
        let from = source.join(&f.rel);
        let to = dest.join(&f.rel);
        let parent = to
            .parent()
            .ok_or_else(|| format!("{} has no parent directory", to.display()))?;
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        let bytes =
            std::fs::read(&from).map_err(|e| format!("cannot read {}: {e}", from.display()))?;
        std::fs::write(&to, &bytes).map_err(|e| format!("cannot write {}: {e}", to.display()))?;
    }
    Ok(files)
}

fn walk(base: &Path, dir: &Path, with_git: bool, out: &mut Vec<CopiedFile>) -> Result<(), String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in rd {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let ft = entry
            .file_type()
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            if name == GIT_DIR && !with_git {
                continue;
            }
            if SKIPPED_DIRS.contains(&name.as_str()) {
                continue;
            }
            walk(base, &path, with_git, out)?;
            continue;
        }
        let bytes =
            std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let rel = path
            .strip_prefix(base)
            .map_err(|_| format!("{} is not under {}", path.display(), base.display()))?
            .to_string_lossy()
            .replace('\\', "/");
        out.push(CopiedFile {
            rel,
            digest: sha256(&bytes),
            bytes: bytes.len() as u64,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{copy_walk, copy_workspace};

    /// A small tree: two files, one nested; a symlink, `target/` and
    /// `.git/` beside them.
    fn tree(root: &std::path::Path) {
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::create_dir_all(root.join("target")).unwrap();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join("a.txt"), b"alpha\n").unwrap();
        std::fs::write(root.join("sub/b.txt"), b"beta\n").unwrap();
        std::fs::write(root.join("target/c.txt"), b"built\n").unwrap();
        std::fs::write(root.join(".git/config"), b"[core]\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("a.txt", root.join("link.txt")).unwrap();
    }

    /// The walk skips symlinks, `target/` and `.git/` by default, and
    /// sorts by path; with `with_git` it takes `.git/` too.
    #[test]
    fn walk_skips_symlinks_and_build_dirs() {
        let base = std::env::temp_dir().join(format!("rh-scratch-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        tree(&base);
        let files = copy_walk(&base, false).unwrap();
        let rels: Vec<&str> = files.iter().map(|f| f.rel.as_str()).collect();
        assert_eq!(rels, ["a.txt", "sub/b.txt"]);
        let files = copy_walk(&base, true).unwrap();
        let rels: Vec<&str> = files.iter().map(|f| f.rel.as_str()).collect();
        assert_eq!(rels, [".git/config", "a.txt", "sub/b.txt"]);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The copy is byte-for-byte, leaves the source alone, and returns
    /// the walk's list; the skipped entries are not there.
    #[test]
    fn copy_is_byte_for_byte_and_skips_the_same_entries() {
        let base = std::env::temp_dir().join(format!("rh-scratch-copy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        tree(&base);
        let dest = base
            .parent()
            .unwrap()
            .join(format!("copy-{}", std::process::id()));
        let files = copy_workspace(&base, &dest, false).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(
            std::fs::read(dest.join("sub/b.txt")).unwrap(),
            b"beta\n".to_vec()
        );
        assert!(!dest.join("link.txt").exists());
        assert!(!dest.join("target").exists());
        // The source is untouched.
        assert_eq!(
            std::fs::read(base.join("a.txt")).unwrap(),
            b"alpha\n".to_vec()
        );
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&dest);
    }
}
