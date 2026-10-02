//! Protected paths (P-29, ROADMAP §4.3): globs the edit tools refuse, so
//! a real repository's metadata (`.git` and friends) is read-only for the
//! model by default — a reward-hack and safety floor on a repo the run
//! could otherwise rewrite out from under the harness.
//!
//! Two fail-closed sources, merged:
//!
//! - the build's [`DEFAULT_DENY`] globs (`.git/**`, `.rustyharness/**`),
//!   always on;
//! - the task's own declared list (the task file's `protected` entry),
//!   for files a task knows it must never touch.
//!
//! The globs are matched against the workspace-relative path the edit
//! call names (the lexical [`WorkspacePath`], no `..`, no absolute path,
//! no symlinks followed by construction — the engine's confinement walk
//! guarantees the file really is under the root). A match refuses the
//! edit before anything is read, created or written; the message names
//! the pattern and tells the model to leave the file alone.
//!
//! Reads stay allowed: `fs.read`, `fs.search`, `fs.list` and `fs.glob`
//! are not gated here ([`read_of_dot_git_allowed`] in `builtin.rs`
//! holds), and the sandboxed exec layer receives the deny globs as
//! read-only overlays in `ConfinedSpec.protected` (the macOS conformance
//! case `exec_cannot_write_dot_git`).
//!
//! [`WorkspacePath`]: harness_policy::WorkspacePath
//! [`read_of_dot_git_allowed`]: crate::builtin

use std::path::{Path, PathBuf};

use harness_core::glob::{Glob, GlobError};

/// The build's always-on deny globs (P-29): repository metadata and the
/// harness's own scratch tree inside the workspace.
pub const DEFAULT_DENY: &[&str] = &[".git/**", ".rustyharness/**"];

/// The ask-tier globs (P-29): CI configuration and lockfiles. The driver
/// adds a default ask rule for these over every edit capability, so a
/// policy that allows edits outright still asks a human before one of
/// these changes. Enforced by the policy, not by the edit engine.
pub const DEFAULT_ASK: &[&str] = &[".github/**", "Cargo.lock"];

/// Why a protected-path list was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtectedError {
    /// A glob in the list does not compile; the message is static text
    /// for the kind of problem (like the tools' [`BAD_PATTERN`](crate::builtin::code) class).
    #[error("protected glob refused: {0}")]
    Glob(&'static str),
}

impl From<GlobError> for ProtectedError {
    fn from(e: GlobError) -> Self {
        Self::Glob(e.message())
    }
}

/// The merged deny list of one run: the build defaults plus the task's
/// declared globs. Empty only if the defaults were compiled away — never
/// in practice, so the floor is always at least [`DEFAULT_DENY`].
#[derive(Debug, Clone)]
pub struct Protected {
    entries: Vec<(String, Glob)>,
}

impl Protected {
    /// The merged list: the task's globs after the build defaults. Any
    /// uncompilable glob refuses the run (fail closed).
    pub fn new(task_declared: &[String]) -> Result<Self, ProtectedError> {
        let mut entries = Vec::with_capacity(DEFAULT_DENY.len() + task_declared.len());
        for pattern in DEFAULT_DENY
            .iter()
            .copied()
            .chain(task_declared.iter().map(String::as_str))
        {
            entries.push((pattern.to_owned(), Glob::new(pattern)?));
        }
        Ok(Self { entries })
    }

    /// A list with nothing in it (unit tests, tool construction before
    /// the driver installs the real one). `EditEngine::new` starts here;
    /// the driver always replaces it with [`Protected::new`].
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// The patterns, defaults first, in order.
    pub fn patterns(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(p, _)| p.as_str())
    }

    /// Whether any entry is installed.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The first pattern matching the workspace-relative path, if any.
    pub fn matched(&self, path: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(_, g)| g.matches(path))
            .map(|(p, _)| p.as_str())
    }
}

/// The sandbox overlay for the exec tools (P-29): the deny globs' base
/// directories under `root`, for `ConfinedSpec.protected`. A glob's base
/// is its text before a trailing `/**` (a bare `**` has no base and is
/// skipped); a base whose directory does not exist in this workspace is
/// skipped — the sandbox spec requires protected paths to exist, and a
/// missing one must never refuse a run that never touches it. The result
/// is canonicalised absolute paths, deduplicated and sorted, as the
/// sandbox spec expects.
pub fn overlay_dirs(root: &Path, sources: &[String]) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    for source in sources {
        let base = source.strip_suffix("/**").unwrap_or(source);
        if base.is_empty() || base == "**" {
            continue;
        }
        // A source without `/**` protects only the named path; still
        // overlay that path (and whatever is under it — over-protecting
        // the overlay is the safe direction).
        let dir = root.join(base);
        let Ok(meta) = std::fs::symlink_metadata(&dir) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            // The sandbox refuses symlink components; skip rather than
            // canonicalise into whatever it points at.
            continue;
        }
        if let Ok(canon) = dir.canonicalize() {
            if !dirs.contains(&canon) {
                dirs.push(canon);
            }
        }
    }
    dirs.sort();
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_compile_and_match_dot_git() {
        let p = Protected::new(&[]).expect("defaults compile");
        assert_eq!(p.patterns().collect::<Vec<_>>(), DEFAULT_DENY.to_vec());
        assert_eq!(p.matched(".git/config"), Some(".git/**"));
        assert_eq!(p.matched(".git/objects/ab/cd"), Some(".git/**"));
        assert_eq!(
            p.matched(".rustyharness/scratch/x"),
            Some(".rustyharness/**")
        );
        assert_eq!(p.matched("src/lib.rs"), None);
        // A sibling directory is not protected.
        assert_eq!(p.matched("agit/config"), None);
        assert_eq!(p.matched("gitignore"), None);
    }

    #[test]
    fn task_list_extends_the_defaults() {
        let p = Protected::new(&["secrets/**".to_owned()]).expect("compiles");
        assert_eq!(p.matched("secrets/key.txt"), Some("secrets/**"));
        assert_eq!(p.matched(".git/config"), Some(".git/**"));
        assert_eq!(p.patterns().count(), DEFAULT_DENY.len() + 1);
    }

    #[test]
    fn a_bad_task_glob_refuses() {
        let err = Protected::new(&["..".to_owned()]).expect_err("refused");
        assert!(matches!(err, ProtectedError::Glob(_)));
    }

    #[test]
    fn empty_protects_nothing() {
        let p = Protected::empty();
        assert!(p.is_empty());
        assert_eq!(p.matched(".git/config"), None);
    }

    #[test]
    fn overlay_dirs_strip_the_globs_base() {
        let ws = std::env::temp_dir().join(format!("rh-protected-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ws);
        std::fs::create_dir_all(ws.join(".git")).expect("git dir");
        std::fs::create_dir_all(ws.join("secrets")).expect("secrets dir");
        let dirs = overlay_dirs(
            &ws,
            &[
                ".git/**".to_owned(),
                "secrets/**".to_owned(),
                "missing/**".to_owned(),
            ],
        );
        assert_eq!(dirs.len(), 2, "missing base skipped: {dirs:?}");
        assert!(dirs[0].ends_with(".git"), "{dirs:?}");
        assert!(dirs[1].ends_with("secrets"), "{dirs:?}");
        assert!(dirs.iter().all(|d| d.is_absolute()));
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn overlay_dirs_skip_bare_globs_and_missing() {
        let ws = std::env::temp_dir().join(format!("rh-protected2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ws);
        std::fs::create_dir_all(&ws).expect("ws");
        let dirs = overlay_dirs(
            &ws,
            &["**".to_owned(), "*.lock".to_owned(), "gone".to_owned()],
        );
        assert!(dirs.is_empty(), "{dirs:?}");
        let _ = std::fs::remove_dir_all(&ws);
    }
}
