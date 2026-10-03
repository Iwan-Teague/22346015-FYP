//! The P-36e seam, enforced: no file-tool module touches the filesystem
//! directly any more — every access goes through [`FileOps`], and the only
//! `std::fs` in the crate's file-tool half is the `InProcess`
//! implementation (and, out of scope for this slice, the command runner
//! and the sandbox overlay helper, which are not file tools).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::{Path, PathBuf};

/// The file-tool modules the slice routed through the seam.
const TOOL_MODULES: [&str; 6] = [
    "builtin.rs",
    "edit.rs",
    "patch.rs",
    "restore.rs",
    "search.rs",
    "outline.rs",
];

/// What only `file_ops/in_process.rs` may hold.
const FS_TOKENS: [&str; 6] = [
    "std::fs",
    "fs::",
    "File::",
    "OpenOptions",
    "read_to_end",
    "set_permissions",
];

fn src(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(name)
}

/// The module's production text: everything before its `#[cfg(test)]`
/// section (the scratch setup may use the filesystem like any test).
fn production(path: &Path) -> String {
    let all = fs::read_to_string(path).unwrap();
    all.split("#[cfg(test)]").next().unwrap_or(&all).to_owned()
}

#[test]
fn tool_modules_touch_fs_only_through_file_ops() {
    for module in TOOL_MODULES {
        let text = production(&src(module));
        for token in FS_TOKENS {
            assert!(
                !text.contains(token),
                "{module} must not touch the filesystem directly: it holds {token:?}; every access goes through FileOps"
            );
        }
    }
    // The seam's own types never reach the filesystem either.
    let seam = production(&src("file_ops/mod.rs"));
    for token in FS_TOKENS {
        assert!(!seam.contains(token), "file_ops/mod.rs holds {token:?}");
    }
    // The implementation is where the filesystem calls live.
    let imp = production(&src("file_ops/in_process.rs"));
    assert!(
        imp.contains("std::fs"),
        "InProcess is the std::fs implementation"
    );
    // The modules that hold the seam themselves name it; search and
    // outline go through it via `builtin`'s `Walk` and `read_bounded`.
    for module in ["builtin.rs", "edit.rs", "patch.rs", "restore.rs"] {
        let text = production(&src(module));
        assert!(
            text.contains("FileOps"),
            "{module} goes through the FileOps seam"
        );
    }
}
