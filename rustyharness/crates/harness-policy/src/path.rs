//! What a built-in read may touch (design §4.8, §6.2, §6.4; INV-30 lexical
//! half).
//!
//! A read reaches only the workspace. The trust base, `state_root`, the
//! home directory and other runs' directories are never inside the
//! workspace (§2.8, §6.4), so a path that provably stays inside the
//! workspace cannot name them. This module is the LEXICAL rule: a path
//! argument must be a normalised, relative, portable path with no way to
//! climb out or alias. It is necessary, not sufficient: a symlink inside the
//! workspace could still point out. In H1 that half is materialisation's
//! job (§4.8: the harness materialises the workspace refusing outward
//! symlinks, and a read-only session cannot create new ones); in H2 the
//! confined file-op helper makes the kernel enforce the view (FT-12).

use std::fmt;

/// Longest path argument accepted, in bytes.
pub const PATH_MAX_BYTES: usize = 4096;

/// A path argument that stays inside the workspace, lexically. `""` is the
/// workspace root (written `.` by callers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePath(String);

impl WorkspacePath {
    /// The normalised relative path (`""` for the root). Components are
    /// joined with `/`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The path's components.
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').filter(|c| !c.is_empty())
    }
}

/// Why a path argument was refused. Every variant is a refusal: nothing is
/// normalised away silently, because a path the model wrote one way and the
/// tool read another is how aliasing bugs start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathRefused {
    /// The empty string (use `.` for the root).
    Empty,
    /// Longer than [`PATH_MAX_BYTES`].
    TooLong,
    /// Starts at a root: `/…`.
    Absolute,
    /// Contains `\` (a separator on Windows, so meaning differs per OS; also
    /// UNC `\\server\share`).
    Backslash,
    /// Contains `:` (a drive letter `C:`, an NTFS stream `file:stream`).
    Colon,
    /// A `..` component.
    Parent,
    /// A `.` component other than the whole path `.`.
    CurrentDir,
    /// An empty component (`a//b`, a trailing `/`).
    EmptyComponent,
    /// A control character (NUL included).
    Control,
    /// A component ending in `.` or space (Windows strips those, so `a.`
    /// would alias `a`).
    TrailingDotOrSpace,
    /// A component whose stem is a Windows reserved device name (`CON`,
    /// `NUL.txt`, `a/aux.c`, `CONIN$`, `COM¹`, ...). Refused on every OS.
    DeviceName,
}

impl fmt::Display for PathRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Empty => "path is empty (use \".\" for the workspace root)",
            Self::TooLong => "path is too long",
            Self::Absolute => "path is absolute; use a path relative to the workspace",
            Self::Backslash => "path contains a backslash; use '/'",
            Self::Colon => "path contains ':'",
            Self::Parent => "path contains a '..' component",
            Self::CurrentDir => "path contains a '.' component",
            Self::EmptyComponent => "path contains an empty component",
            Self::Control => "path contains a control character",
            Self::TrailingDotOrSpace => "a path component ends in '.' or a space",
            Self::DeviceName => "a path component is a Windows device name (CON, NUL, COM1, ...)",
        };
        f.write_str(s)
    }
}

/// Check a path argument against the lexical workspace rule.
pub fn workspace_path(s: &str) -> Result<WorkspacePath, PathRefused> {
    if s.is_empty() {
        return Err(PathRefused::Empty);
    }
    if s.len() > PATH_MAX_BYTES {
        return Err(PathRefused::TooLong);
    }
    if s.chars().any(char::is_control) {
        return Err(PathRefused::Control);
    }
    if s == "." {
        return Ok(WorkspacePath(String::new()));
    }
    if s.contains('\\') {
        return Err(PathRefused::Backslash);
    }
    if s.starts_with('/') {
        return Err(PathRefused::Absolute);
    }
    if s.contains(':') {
        return Err(PathRefused::Colon);
    }
    for c in s.split('/') {
        match c {
            "" => return Err(PathRefused::EmptyComponent),
            "." => return Err(PathRefused::CurrentDir),
            ".." => return Err(PathRefused::Parent),
            _ if c.ends_with('.') || c.ends_with(' ') => {
                return Err(PathRefused::TrailingDotOrSpace)
            }
            _ if is_device_name(c) => return Err(PathRefused::DeviceName),
            _ => {}
        }
    }
    Ok(WorkspacePath(s.to_owned()))
}

/// Windows reserved device names (lowercase). Win32 maps a component to a
/// device when its stem (the text before the first `.`, trailing spaces
/// dropped) is one of these, case-insensitively, with any extension and in
/// any directory. `COM¹`-`COM³` and `LPT¹`-`LPT³` (superscript digits) are
/// devices too.
const DEVICE_NAMES: &[&str] = &[
    "con",
    "prn",
    "aux",
    "nul",
    "conin$",
    "conout$",
    "com0",
    "com1",
    "com2",
    "com3",
    "com4",
    "com5",
    "com6",
    "com7",
    "com8",
    "com9",
    "com\u{b9}",
    "com\u{b2}",
    "com\u{b3}",
    "lpt0",
    "lpt1",
    "lpt2",
    "lpt3",
    "lpt4",
    "lpt5",
    "lpt6",
    "lpt7",
    "lpt8",
    "lpt9",
    "lpt\u{b9}",
    "lpt\u{b2}",
    "lpt\u{b3}",
];

/// Whether a path component names a Windows device (review F-1). Checked
/// on every OS, like `:` and `\`, so a path means the same thing on every
/// host.
fn is_device_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    let stem = stem.trim_end_matches(' ').to_ascii_lowercase();
    DEVICE_NAMES.contains(&stem.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inv_30_lexical_escapes_are_refused() {
        for (bad, why) in [
            ("", PathRefused::Empty),
            ("/etc/passwd", PathRefused::Absolute),
            ("//server/share", PathRefused::Absolute),
            ("..", PathRefused::Parent),
            ("../x", PathRefused::Parent),
            ("a/../../x", PathRefused::Parent),
            ("a/..", PathRefused::Parent),
            ("C:/Windows", PathRefused::Colon),
            ("C:x", PathRefused::Colon),
            ("file.txt:stream", PathRefused::Colon),
            ("..\\x", PathRefused::Backslash),
            ("\\\\server\\share", PathRefused::Backslash),
            ("a\\b", PathRefused::Backslash),
            ("a//b", PathRefused::EmptyComponent),
            ("a/", PathRefused::EmptyComponent),
            ("./a", PathRefused::CurrentDir),
            ("a/./b", PathRefused::CurrentDir),
            ("a\0b", PathRefused::Control),
            ("a\nb", PathRefused::Control),
            ("a./b", PathRefused::TrailingDotOrSpace),
            ("a /b", PathRefused::TrailingDotOrSpace),
        ] {
            assert_eq!(workspace_path(bad), Err(why), "{bad:?}");
        }
        assert_eq!(workspace_path(&"a".repeat(4097)), Err(PathRefused::TooLong));
    }

    // Review F-1: Win32 opens these as devices (with any extension, in any
    // directory), so `CONIN$` would read the harness's console input.
    #[test]
    fn inv_30_windows_device_names_are_refused_on_every_os() {
        for bad in [
            "CON",
            "nul",
            "NUL.txt",
            "COM1",
            "LPT1.log",
            "a/aux.c",
            "CONIN$",
            "conout$",
            "Conin$.x",
            "prn",
            "Aux",
            "COM0",
            "com9.tar.gz",
            "LPT0",
            "lpt9",
            "COM\u{b9}",
            "com\u{b2}.txt",
            "LPT\u{b3}",
            "src/deep/NUL.rs",
            "CON .txt",
            "nul  .x",
        ] {
            assert_eq!(workspace_path(bad), Err(PathRefused::DeviceName), "{bad:?}");
        }
        // Near misses are ordinary names.
        for ok in [
            "console",
            "CONFIG",
            "com10",
            "lpt",
            "nulls.txt",
            "aux_x",
            "a.con",
            "COM\u{2074}",
            "conin",
            "x/CONOUT",
        ] {
            assert!(workspace_path(ok).is_ok(), "{ok:?}");
        }
    }

    #[test]
    fn ordinary_relative_paths_are_accepted() {
        assert_eq!(workspace_path(".").unwrap().as_str(), "");
        for ok in [
            "src/lib.rs",
            ".gitignore",
            "a/b/c.d",
            "~x",
            "dir with space/f",
            "..a",
            "a..b",
        ] {
            assert_eq!(workspace_path(ok).unwrap().as_str(), ok, "{ok}");
        }
        let p = workspace_path("a/b/c").unwrap();
        assert_eq!(p.components().collect::<Vec<_>>(), ["a", "b", "c"]);
    }
}
