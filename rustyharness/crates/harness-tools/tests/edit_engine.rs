//! Integration tests for the in-process edit engine (§4.9, D9): the
//! pure library half of H2 — stale-read anchoring, exact-unique
//! replace, whole-file write, atomic apply, CRLF preservation,
//! confinement and bounds. These drive the library API directly; the
//! engine is not wired into the tool seam yet, so there is no
//! policy/journal rig here.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::{Path, PathBuf};

use harness_core::sha256;
use harness_policy::PathRefused;
use harness_tools::edit::{
    EditEngine, EditError, ReadLog, ReplaceReq, StaleRead, WriteReq, EDIT_MAX_BYTES,
    WRITE_OVERWRITE_MAX_LINES,
};

fn ws(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("edit-engine-{name}"));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn engine(name: &str) -> (PathBuf, EditEngine) {
    let d = ws(name);
    let e = EditEngine::new(&d).unwrap();
    (d, e)
}

fn file(p: &Path, content: impl AsRef<[u8]>) {
    fs::write(p, content).unwrap();
}

/// A read log holding one fresh read of `rel`.
fn read_of(root: &Path, rel: &str) -> ReadLog {
    let mut log = ReadLog::default();
    log.record(rel, sha256(&fs::read(root.join(rel)).unwrap()));
    log
}

#[test]
fn a_unique_match_applies_with_before_and_after_hashes() {
    let (d, e) = engine("unique");
    file(&d.join("a.txt"), "alpha\nbeta\ngamma\n");
    let original = fs::read(d.join("a.txt")).unwrap();
    let mut reads = read_of(&d, "a.txt");
    let applied = e.replace(&rep("a.txt", "beta", "delta"), &reads).unwrap();
    assert_eq!(fs::read(d.join("a.txt")).unwrap(), b"alpha\ndelta\ngamma\n");
    assert_eq!(applied.before, Some(sha256(&original)));
    assert_eq!(applied.after, sha256(b"alpha\ndelta\ngamma\n"));
    assert_ne!(applied.before, Some(applied.after));
    // A second identical replace now fails: the anchor is stale.
    match e.replace(&rep("a.txt", "beta", "delta"), &reads) {
        Err(EditError::Stale(StaleRead::Changed)) => {}
        other => panic!("wrong result: {other:?}"),
    }
    // Re-read, and the old text is gone: zero matches.
    reads = read_of(&d, "a.txt");
    match e.replace(&rep("a.txt", "beta", "x"), &reads) {
        Err(EditError::ZeroMatches { .. }) => {}
        other => panic!("wrong result: {other:?}"),
    }
}

/// The request shorthand: unique-match replace.
fn rep(path: &str, old: &str, new: &str) -> ReplaceReq {
    ReplaceReq {
        path: path.to_owned(),
        old: old.to_owned(),
        new: new.to_owned(),
        count: 1,
    }
}

#[test]
fn no_match_names_nearest_lines_and_hints_at_crlf() {
    let (d, e) = engine("nomatch");
    file(&d.join("c.txt"), "one\r\ntwo\r\nthree\r\n");
    let reads = read_of(&d, "c.txt");
    // LF `old` never byte-matches a CRLF file…
    match e.replace(&rep("c.txt", "two\nthree", "X"), &reads) {
        Err(EditError::ZeroMatches { nearest, crlf_hint }) => {
            assert_eq!(nearest, vec![2]);
            assert!(crlf_hint);
        }
        other => panic!("wrong result: {other:?}"),
    }
    // …but the same span with CRLF does.
    e.replace(&rep("c.txt", "two\r\nthree", "X"), &reads)
        .unwrap();
    assert_eq!(fs::read(d.join("c.txt")).unwrap(), b"one\r\nX\r\n");
    // Something nowhere close: no nearest lines, no hint, no change.
    let (d, e) = engine("nomatch-far");
    file(&d.join("f.txt"), "a\nb\nc\n");
    let reads = read_of(&d, "f.txt");
    match e.replace(&rep("f.txt", "zzz", "X"), &reads) {
        Err(EditError::ZeroMatches { nearest, crlf_hint }) => {
            assert!(nearest.is_empty());
            assert!(!crlf_hint);
        }
        other => panic!("wrong result: {other:?}"),
    }
    assert_eq!(fs::read(d.join("f.txt")).unwrap(), b"a\nb\nc\n");
}

#[test]
fn multiple_matches_name_every_line_and_change_nothing() {
    let (d, e) = engine("multi");
    file(&d.join("m.txt"), "keep\ndup\nkeep\ndup\nkeep\n");
    let original = fs::read(d.join("m.txt")).unwrap();
    let reads = read_of(&d, "m.txt");
    match e.replace(&rep("m.txt", "dup", "X"), &reads) {
        Err(EditError::MatchCount {
            expected,
            found,
            lines,
        }) => {
            assert_eq!((expected, found), (1, 2));
            assert_eq!(lines, vec![2, 4]);
        }
        other => panic!("wrong result: {other:?}"),
    }
    assert_eq!(fs::read(d.join("m.txt")).unwrap(), original);
    // With count = 2 both are replaced in one atomic apply.
    e.replace(
        &ReplaceReq {
            path: "m.txt".into(),
            old: "dup".into(),
            new: "X".into(),
            count: 2,
        },
        &reads,
    )
    .unwrap();
    assert_eq!(
        fs::read(d.join("m.txt")).unwrap(),
        b"keep\nX\nkeep\nX\nkeep\n"
    );
    // Expected 3, found 2: still refused, with the lines named.
    let (d, e) = engine("count");
    file(&d.join("c.txt"), "dup\ndup\n");
    let reads = read_of(&d, "c.txt");
    match e.replace(
        &ReplaceReq {
            path: "c.txt".into(),
            old: "dup".into(),
            new: "X".into(),
            count: 3,
        },
        &reads,
    ) {
        Err(EditError::MatchCount {
            expected: 3,
            found: 2,
            lines,
        }) => assert_eq!(lines, vec![1, 2]),
        other => panic!("wrong result: {other:?}"),
    }
}

#[test]
fn bad_arguments_are_refused_before_the_file_is_touched() {
    let (d, e) = engine("badargs");
    file(&d.join("a.txt"), "abc\n");
    let reads = read_of(&d, "a.txt");
    // `old` == `new` is a no-op, refused as such.
    match e.replace(&rep("a.txt", "abc", "abc"), &reads) {
        Err(EditError::NoOp) => {}
        other => panic!("wrong result: {other:?}"),
    }
    // Empty `old`…
    match e.replace(&rep("a.txt", "", "x"), &reads) {
        Err(EditError::EmptyOld) => {}
        other => panic!("wrong result: {other:?}"),
    }
    // …and count = 0 are argument errors.
    match e.replace(
        &ReplaceReq {
            path: "a.txt".into(),
            old: "abc".into(),
            new: "x".into(),
            count: 0,
        },
        &reads,
    ) {
        Err(EditError::BadCount) => {}
        other => panic!("wrong result: {other:?}"),
    }
    assert_eq!(fs::read(d.join("a.txt")).unwrap(), b"abc\n");
}

#[test]
fn edits_require_a_fresh_read() {
    let (d, e) = engine("stale");
    file(&d.join("a.txt"), "one\ntwo\n");
    // Never read: refused outright, replace and overwrite both.
    let empty = ReadLog::default();
    match e.replace(&rep("a.txt", "one", "1"), &empty) {
        Err(EditError::Stale(StaleRead::NeverRead)) => {}
        other => panic!("wrong result: {other:?}"),
    }
    match e.write(&wr("a.txt", "x\n"), &empty) {
        Err(EditError::Stale(StaleRead::NeverRead)) => {}
        other => panic!("wrong result: {other:?}"),
    }
    // Read, then the file changes behind the log's back: Changed.
    let reads = read_of(&d, "a.txt");
    file(&d.join("a.txt"), "one\nTWO\n");
    match e.replace(&rep("a.txt", "one", "1"), &reads) {
        Err(EditError::Stale(StaleRead::Changed)) => {}
        other => panic!("wrong result: {other:?}"),
    }
    match e.write(&wr("a.txt", "x\n"), &reads) {
        Err(EditError::Stale(StaleRead::Changed)) => {}
        other => panic!("wrong result: {other:?}"),
    }
    // A fresh read unblocks it.
    let reads = read_of(&d, "a.txt");
    e.replace(&rep("a.txt", "TWO", "2"), &reads).unwrap();
    assert_eq!(fs::read(d.join("a.txt")).unwrap(), b"one\n2\n");
}

/// The request shorthand: whole-file write.
fn wr(path: &str, content: &str) -> WriteReq {
    WriteReq {
        path: path.to_owned(),
        content: content.to_owned(),
    }
}

#[test]
fn crlf_files_stay_crlf() {
    let (d, e) = engine("crlf");
    file(&d.join("c.txt"), "a\r\nb\r\nc\r\n");
    let reads = read_of(&d, "c.txt");
    // LF `new` takes the file's line endings.
    e.replace(&rep("c.txt", "b", "x\ny"), &reads).unwrap();
    assert_eq!(fs::read(d.join("c.txt")).unwrap(), b"a\r\nx\r\ny\r\nc\r\n");
    // So does an LF write body.
    let reads = read_of(&d, "c.txt");
    e.write(&wr("c.txt", "p\nq\n"), &reads).unwrap();
    assert_eq!(fs::read(d.join("c.txt")).unwrap(), b"p\r\nq\r\n");
    // An LF-only file keeps LF, whatever `new` carries.
    file(&d.join("l.txt"), "a\nb\n");
    let reads = read_of(&d, "l.txt");
    e.replace(&rep("l.txt", "a", "x\r\ny"), &reads).unwrap();
    assert_eq!(fs::read(d.join("l.txt")).unwrap(), b"x\r\ny\nb\n");
}

#[test]
fn a_write_body_equal_after_conversion_is_a_noop() {
    let (d, e) = engine("noop");
    file(&d.join("c.txt"), "a\r\nb\r\n");
    let reads = read_of(&d, "c.txt");
    match e.write(&wr("c.txt", "a\r\nb\r\n"), &reads) {
        Err(EditError::NoOp) => {}
        other => panic!("wrong result: {other:?}"),
    }
    // Even spelled with bare LFs: converted, it equals the file.
    match e.write(&wr("c.txt", "a\nb\n"), &reads) {
        Err(EditError::NoOp) => {}
        other => panic!("wrong result: {other:?}"),
    }
    // A replace whose `new` converts back onto `old` is the silent
    // no-op class of R1 §2: a failure, never a success.
    match e.replace(&rep("c.txt", "a\r\n", "a\n"), &reads) {
        Err(EditError::NoChange { .. }) => {}
        other => panic!("wrong result: {other:?}"),
    }
    assert_eq!(fs::read(d.join("c.txt")).unwrap(), b"a\r\nb\r\n");
}

#[test]
fn write_creates_only_where_nothing_exists() {
    let (d, e) = engine("create");
    let empty = ReadLog::default();
    let applied = e.write(&wr("new.txt", "fresh\n"), &empty).unwrap();
    assert_eq!(fs::read(d.join("new.txt")).unwrap(), b"fresh\n");
    assert_eq!(applied.before, None);
    assert_eq!(applied.after, sha256(b"fresh\n"));
    // The §4.8 schema is one capability with no mode flag, so an
    // existing target is the overwrite regime: it needs a fresh read.
    match e.write(&wr("new.txt", "other\n"), &empty) {
        Err(EditError::Stale(StaleRead::NeverRead)) => {}
        other => panic!("wrong result: {other:?}"),
    }
    assert_eq!(fs::read(d.join("new.txt")).unwrap(), b"fresh\n");
    // A create under a missing parent is refused.
    match e.write(&wr("nodir/x.txt", "x\n"), &empty) {
        Err(EditError::NotFound) => {}
        other => panic!("wrong result: {other:?}"),
    }
}

#[test]
fn overwrites_are_capped_at_400_lines() {
    let (d, e) = engine("lines");
    file(
        &d.join("big.txt"),
        "l\n".repeat(WRITE_OVERWRITE_MAX_LINES + 1),
    );
    let reads = read_of(&d, "big.txt");
    match e.write(&wr("big.txt", "x\n"), &reads) {
        Err(EditError::TooManyLines {
            lines,
            cap: WRITE_OVERWRITE_MAX_LINES,
        }) => assert_eq!(lines, WRITE_OVERWRITE_MAX_LINES + 1),
        other => panic!("wrong result: {other:?}"),
    }
    // At the cap the overwrite applies.
    file(&d.join("ok.txt"), "l\n".repeat(WRITE_OVERWRITE_MAX_LINES));
    let reads = read_of(&d, "ok.txt");
    e.write(&wr("ok.txt", "done\n"), &reads).unwrap();
    assert_eq!(fs::read(d.join("ok.txt")).unwrap(), b"done\n");
}

#[test]
fn oversize_and_non_utf8_files_are_refused() {
    let (d, e) = engine("bounds");
    // Over the byte cap by one: refused without a read.
    file(
        &d.join("big.bin"),
        "x".repeat(usize::try_from(EDIT_MAX_BYTES).unwrap() + 1),
    );
    let reads = read_of(&d, "big.bin");
    match e.replace(&rep("big.bin", "x", "y"), &reads) {
        Err(EditError::TooLarge {
            len,
            cap: EDIT_MAX_BYTES,
        }) => assert_eq!(len, EDIT_MAX_BYTES + 1),
        other => panic!("wrong result: {other:?}"),
    }
    // A write body over the cap is refused too.
    let empty = ReadLog::default();
    let huge = "x".repeat(usize::try_from(EDIT_MAX_BYTES).unwrap() + 1);
    match e.write(&wr("huge.txt", &huge), &empty) {
        Err(EditError::TooLarge { .. }) => {}
        other => panic!("wrong result: {other:?}"),
    }
    // Non-UTF-8 files are refused even with a matching hash on record
    // (the engine takes the log on faith; fs.read would not fill it).
    file(&d.join("bin.dat"), b"text\xFF\xFE");
    let reads = read_of(&d, "bin.dat");
    match e.replace(&rep("bin.dat", "text", "x"), &reads) {
        Err(EditError::NotUtf8) => {}
        other => panic!("wrong result: {other:?}"),
    }
    match e.write(&wr("bin.dat", "x\n"), &reads) {
        Err(EditError::NotUtf8) => {}
        other => panic!("wrong result: {other:?}"),
    }
    assert_eq!(fs::read(d.join("bin.dat")).unwrap(), b"text\xFF\xFE");
}

#[test]
fn paths_outside_the_workspace_are_refused_lexically() {
    let (d, e) = engine("outside");
    file(&d.join("a.txt"), "abc\n");
    let reads = read_of(&d, "a.txt");
    for path in ["/etc/passwd", "../escape", "a/../../escape", "C:\\x"] {
        match e.replace(&rep(path, "a", "b"), &reads) {
            Err(EditError::PathRefused(_)) => {}
            other => panic!("path {path:?}: wrong result: {other:?}"),
        }
        match e.write(&wr(path, "x"), &reads) {
            Err(EditError::PathRefused(_)) => {}
            other => panic!("path {path:?}: wrong result: {other:?}"),
        }
    }
    // The refusals name the rule that fired.
    assert_eq!(
        harness_policy::workspace_path("/etc/passwd")
            .unwrap_err()
            .to_string(),
        PathRefused::Absolute.to_string()
    );
    // A path under a regular file is not a place to edit.
    match e.replace(&rep("a.txt/x", "a", "b"), &reads) {
        Err(EditError::Io(_)) => {}
        other => panic!("wrong result: {other:?}"),
    }
    // The workspace root itself is not a file.
    match e.replace(&rep(".", "a", "b"), &reads) {
        Err(EditError::NotAFile) => {}
        other => panic!("wrong result: {other:?}"),
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn symlinks_are_refused_at_any_component() {
        let outside = ws("unix-outside");
        file(&outside.join("secret.txt"), "secret\n");
        let (d, e) = engine("symlink");
        fs::create_dir(d.join("src")).unwrap();
        std::os::unix::fs::symlink(&outside, d.join("linkdir")).unwrap();
        std::os::unix::fs::symlink(outside.join("secret.txt"), d.join("src/linkfile")).unwrap();
        let empty = ReadLog::default();
        // Final component…
        match e.replace(&rep("src/linkfile", "secret", "x"), &empty) {
            Err(EditError::Symlink) => {}
            other => panic!("wrong result: {other:?}"),
        }
        match e.write(&wr("src/linkfile", "x\n"), &empty) {
            Err(EditError::Symlink) => {}
            other => panic!("wrong result: {other:?}"),
        }
        // …and a mid-path directory link: neither follows it out.
        match e.replace(&rep("linkdir/secret.txt", "secret", "x"), &empty) {
            Err(EditError::Symlink) => {}
            other => panic!("wrong result: {other:?}"),
        }
        match e.write(&wr("linkdir/secret.txt", "x\n"), &empty) {
            Err(EditError::Symlink) => {}
            other => panic!("wrong result: {other:?}"),
        }
        assert_eq!(
            fs::read(outside.join("secret.txt")).unwrap(),
            b"secret\n",
            "the target must be untouched"
        );
        // A symlinked workspace root is refused at construction.
        let linked = ws("symlink-root");
        std::os::unix::fs::symlink(&linked, d.join("rootlink")).unwrap();
        match EditEngine::new(&d.join("rootlink")) {
            Err(harness_tools::builtin::RootRefused::Symlink) => {}
            other => panic!("wrong result: {other:?}"),
        }
    }

    /// Once H2 runs model code, anything in the workspace may have been
    /// planted — including a symlink at the engine's temp-file name, which
    /// is predictable (`.rh-edit-<pid>-<n>.tmp`). The engine runs outside
    /// the sandbox, so following such a link would write outside the
    /// workspace as the harness user. A planted name must never be
    /// followed: the edit may fail, but the outside file stays untouched
    /// and the target stays a regular file.
    #[test]
    fn a_planted_temp_name_symlink_is_never_followed() {
        let outside = ws("unix-temp-victim");
        file(&outside.join("victim.txt"), "victim\n");
        let (d, e) = engine("temp-symlink");
        file(&d.join("a.txt"), "old\n");
        // The counter is shared by every test in this binary, so plant a
        // wide range of names.
        let pid = std::process::id();
        for n in 0..2048 {
            std::os::unix::fs::symlink(
                outside.join("victim.txt"),
                d.join(format!(".rh-edit-{pid}-{n}.tmp")),
            )
            .unwrap();
        }
        let reads = read_of(&d, "a.txt");
        let replaced = e.replace(&rep("a.txt", "old", "new"), &reads);
        let created = e.write(&wr("fresh.txt", "made\n"), &ReadLog::default());
        assert_eq!(
            fs::read(outside.join("victim.txt")).unwrap(),
            b"victim\n",
            "an edit followed a planted temp-name symlink out of the workspace \
             (replace: {replaced:?}, write: {created:?})"
        );
        for name in ["a.txt", "fresh.txt"] {
            if let Ok(m) = fs::symlink_metadata(d.join(name)) {
                assert!(
                    !m.file_type().is_symlink(),
                    "{name} became a symlink (replace: {replaced:?}, write: {created:?})"
                );
            }
        }
    }

    #[test]
    fn edits_preserve_permissions_and_fail_atomically() {
        let (d, e) = engine("atomic");
        file(&d.join("a.txt"), "keep\nme\n");
        fs::set_permissions(d.join("a.txt"), fs::Permissions::from_mode(0o600)).unwrap();
        let reads = read_of(&d, "a.txt");
        // A happy edit keeps the file's mode through the temp+rename.
        e.replace(&rep("a.txt", "me", "us"), &reads).unwrap();
        let mode = fs::metadata(d.join("a.txt")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        // A read-only directory makes the temp write fail: Io, the
        // original intact, no temp left behind.
        let reads = read_of(&d, "a.txt");
        fs::set_permissions(&d, fs::Permissions::from_mode(0o555)).unwrap();
        let failed = e.replace(&rep("a.txt", "keep", "drop"), &reads);
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        match failed {
            Err(EditError::Io(_)) => {}
            other => panic!("wrong result: {other:?}"),
        }
        assert_eq!(fs::read(d.join("a.txt")).unwrap(), b"keep\nus\n");
        for entry in fs::read_dir(&d).unwrap() {
            let name = entry.unwrap().file_name();
            assert!(
                !name.to_string_lossy().starts_with(".rh-edit-"),
                "temp left behind: {name:?}"
            );
        }
    }
}
