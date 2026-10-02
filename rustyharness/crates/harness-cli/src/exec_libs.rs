//! Resolve a pinned program's dynamic-library dependencies (P-51): the
//! read-only roots the sandbox must add so the program's own `dyld` (or
//! `ld.so`) finds its shared libraries.
//!
//! Why: a homebrew `cargo` links `libgit2` from another Cellar directory,
//! which the `rust` preset's toolchain root (P-11) does not cover. The
//! first pre-submit `cargo test` then died inside the sandbox with a dyld
//! error: the harness failed closed (`submitted_checks_failed`) and a
//! correct agent looked wrong. This module runs in the trust base, when
//! `--allow-exec` resolves a program: it reads the program's load
//! commands (`harness_core::objfile`), expands every install name the way
//! the loader would, and returns the directories its libraries live in,
//! to become read-only roots shown to the user and recorded in the
//! header's exec section (through the spec's digest, as part of
//! `read_only`).
//!
//! Fail-closed, and bounded, because a parser's output about
//! untrusted-ish binaries is driving what the sandbox will allow.
//! Dependencies under the system prefixes (`/usr/lib`, `/System`, `/lib`,
//! …) need no root and are not followed; anything outside the allowed
//! prefixes (the home directory, `/opt/homebrew`, `/usr/local`,
//! `/Library/Developer`, and the roots the preset or the user already
//! named) is listed and refused — the user adds it, by giving the task an
//! explicit exec section with those read-only roots. One level of
//! transitive dependencies is followed (a program's libraries, and their
//! libraries), with the depth and the number of distinct libraries
//! bounded; a file that is not an object file at all (a shell script
//! shim) has no dependencies; a file that claims to be one but does not
//! parse is a refusal, never a panic. No `otool`, no `ldd`, no
//! subprocess: the file reads are this module's own and the parsing is
//! pure.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use harness_core::objfile::{self, Format};

/// How deep dependencies are followed: the program (level 0), its
/// libraries (1) and their libraries (2) — one level of transitive
/// dependencies, per the slice. Anything further is not resolved here; a
/// missing deeper library surfaces as the program's own dyld error.
pub(crate) const MAX_DEPTH: usize = 2;

/// Most distinct non-system libraries one program may have before the
/// resolution is refused as out of bounds. A real toolchain stays under
/// a few dozen; the cap keeps a pathological binary from a long walk.
pub(crate) const MAX_DEPS: usize = 256;

/// Largest object file read, in bytes (512 MiB): every real program and
/// library is far under; a bigger file is refused, not read.
const MAX_OBJECT_BYTES: u64 = 512 << 20;

/// Prefixes that are readable and executable in the sandbox already (the
/// system's own directories): a dependency there needs no root, is never
/// refused and is not followed further — the system libraries' own
/// dependencies are system business. Component-wise matching, so
/// `/usr/lib` does not cover `/usr/libexec`.
const SYSTEM_PREFIXES: &[&str] = &["/usr/lib", "/System", "/lib", "/lib64", "/usr/lib64"];

/// Prefixes outside the system whose directories may become read-only
/// roots: the two package-manager prefixes and Apple's developer trees.
/// The home directory joins them through [`Allowed`]. Anything else is
/// refused and named.
const ALLOWED_PREFIXES: &[&str] = &["/opt/homebrew", "/usr/local", "/Library/Developer"];

/// What one program's dependency resolution found.
#[derive(Debug)]
pub(crate) struct LibRoots {
    /// New read-only roots: the canonical directories of every resolved
    /// non-system library, each not already inside a root the caller
    /// named. The caller adds them to the exec spec's `read_only`.
    pub(crate) roots: Vec<PathBuf>,
    /// The resolved library files, in resolve order, for the
    /// "will allow" line shown before the run starts.
    pub(crate) libs: Vec<PathBuf>,
}

/// The caller's environment for one resolution: the roots already named
/// (a preset's toolchain root, the task's own) and the home directory,
/// canonical, when it is known.
pub(crate) struct Allowed<'a> {
    pub(crate) roots: &'a [PathBuf],
    pub(crate) home: Option<&'a Path>,
}

impl Allowed<'_> {
    /// Whether `p` is the system's own (needs no root, no following).
    fn system(&self, p: &Path) -> bool {
        SYSTEM_PREFIXES.iter().any(|s| p.starts_with(s))
    }

    /// Whether `p` may become a read-only root: it lies under an allowed
    /// prefix, a root the caller named, or the home directory.
    fn allowed(&self, p: &Path) -> bool {
        self.roots.iter().any(|r| p.starts_with(r))
            || ALLOWED_PREFIXES.iter().any(|s| p.starts_with(s))
            || self.home.is_some_and(|h| p.starts_with(h))
    }

    /// Whether `dir` is already covered by a named root (then adding it
    /// would only widen the spec without widening the sandbox).
    fn covered(&self, dir: &Path) -> bool {
        self.roots.iter().any(|r| dir.starts_with(r))
    }
}

/// This process's home directory, canonicalised (roots must be given in
/// their real form); `None` when `HOME` is unset or unreadable, in which
/// case nothing under a home directory is allowed without a named root.
pub(crate) fn home_dir() -> Option<PathBuf> {
    let h = std::env::var_os("HOME")?;
    let p = PathBuf::from(h);
    if !p.is_absolute() {
        return None;
    }
    Some(std::fs::canonicalize(&p).unwrap_or(p))
}

/// Read `path`'s bytes, bounded ([`MAX_OBJECT_BYTES`]). The reading stays
/// in the CLI (the object-file module is pure).
fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let size = std::fs::symlink_metadata(path)
        .map_err(|e| format!("{} cannot be examined: {e}", path.display()))?
        .len();
    if size > MAX_OBJECT_BYTES {
        return Err(format!(
            "{} is {size} bytes, past the {} MiB cap for object files",
            path.display(),
            MAX_OBJECT_BYTES >> 20
        ));
    }
    std::fs::read(path).map_err(|e| format!("{} cannot be read: {e}", path.display()))
}

/// The first of `candidates` that exists, in its real (canonical) form.
fn real_of(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates
        .iter()
        .filter(|c| std::fs::symlink_metadata(c).is_ok())
        .find_map(|c| std::fs::canonicalize(c).ok())
}

/// The paths the loader would search for one dependency of `obj` (loaded
/// by `loader`), in search order: a Mach-O install name is expanded from
/// the loading file's directory and rpaths (and the run program's
/// directory, for `@executable_path`); an ELF soname is searched in the
/// loading object's runpath (`$ORIGIN` is its own directory), then the
/// system library directories.
fn candidates(name: &str, loader: &Path, obj: &objfile::ObjFile, program: &Path) -> Vec<PathBuf> {
    // `objfile::candidates` is pure and so speaks strings, not
    // `std::path` types; the lossy conversion only names directories the
    // loader itself would walk, and canonicalisation happens on `real_of`.
    let loader_dir = loader.parent().unwrap_or(Path::new("/")).to_string_lossy();
    let exec_dir = program.parent().unwrap_or(Path::new("/")).to_string_lossy();
    match obj.format {
        Format::MachO => objfile::candidates(name, &loader_dir, &obj.rpaths, &exec_dir)
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        Format::Elf => {
            let mut c: Vec<PathBuf> = Vec::new();
            for r in &obj.rpaths {
                let r = r.strip_prefix("$ORIGIN").unwrap_or(r);
                if !r.starts_with('/') {
                    continue;
                }
                c.push(PathBuf::from(r).join(name));
            }
            for s in SYSTEM_PREFIXES {
                c.push(Path::new(s).join(name));
            }
            c
        }
    }
}

/// Resolve `program`'s dynamic-library dependencies (see the module
/// docs). `Err` is a refusal naming every library that cannot be allowed:
/// nothing has run, and the flags' caller turns it into unreadable input
/// (exit 4) like any other bad resolution.
pub(crate) fn resolve(program: &Path, allowed: &Allowed<'_>) -> Result<LibRoots, String> {
    let bytes = read_bounded(program)?;
    // A file that is no object file (a script shim) has no dependencies:
    // its interpreter runs, and that is the system's.
    if !objfile::is_object(&bytes) {
        return Ok(LibRoots {
            roots: Vec::new(),
            libs: Vec::new(),
        });
    }
    let mut out = LibRoots {
        roots: Vec::new(),
        libs: Vec::new(),
    };
    let mut refused: Vec<String> = Vec::new();
    // (file to parse, its depth), oldest first; `visited` bounds the walk
    // to distinct files.
    let mut queue: Vec<(PathBuf, usize)> = vec![(program.to_path_buf(), 0)];
    let mut visited: BTreeSet<PathBuf> = BTreeSet::new();
    visited.insert(program.to_path_buf());
    let mut qi = 0;
    while let Some((file, depth)) = queue.get(qi) {
        qi += 1;
        let (file, depth) = (file.clone(), *depth);
        if visited.len() > MAX_DEPS {
            return Err(format!(
                "{}: more than {MAX_DEPS} distinct libraries; resolve them by hand in the \
                 task's exec section",
                program.display()
            ));
        }
        let bytes = read_bounded(&file)?;
        let obj = match objfile::parse(&bytes) {
            Ok(o) => o,
            // Not an object file at all: no dependencies to follow (its
            // interpreter runs instead).
            Err(objfile::ObjError::UnknownFormat) => continue,
            // Claims to be one but does not parse: dyld would fail on it
            // too, so refuse now, by name.
            Err(e) => {
                refused.push(format!("{}: {e}", file.display()));
                continue;
            }
        };
        for name in &obj.libs {
            let tried = candidates(name, &file, &obj, program);
            let real = real_of(&tried);
            // Nothing on disk is not yet a refusal: the system's own
            // libraries may exist only in the dyld shared cache (modern
            // macOS keeps no on-disk copy), so a miss on a system path is
            // how the system's libraries look. A miss anywhere else is
            // refused, by name.
            let Some(real) = real else {
                if tried.first().is_some_and(|p| allowed.system(p)) {
                    continue;
                }
                refused.push(format!(
                    "{name} was not found (tried {})",
                    tried
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
                continue;
            };
            // A system library needs no root and is not followed.
            if allowed.system(&real) {
                continue;
            }
            if !allowed.allowed(&real) || !real.is_file() {
                refused.push(format!(
                    "{name} resolves to {}, outside every allowed prefix (home, \
                     /opt/homebrew, /usr/local, /Library/Developer, the named roots)",
                    real.display()
                ));
                continue;
            }
            let dir = real.parent().unwrap_or(Path::new("/")).to_path_buf();
            if !allowed.covered(&dir) && !out.roots.iter().any(|r| dir.starts_with(r)) {
                out.roots.push(dir);
            }
            out.libs.push(real.clone());
            // One level of transitive dependencies: the program (0), its
            // libraries (1), their libraries (2).
            if depth < MAX_DEPTH && visited.insert(real.clone()) {
                queue.push((real, depth + 1));
            }
        }
    }
    if !refused.is_empty() {
        return Err(format!(
            "its dynamic libraries need directories the sandbox does not read: {}; fix: give \
             the task an exec section with those directories as read_only roots, or use a \
             program built under an allowed prefix",
            refused.join("; ")
        ));
    }
    Ok(out)
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;

    /// A throwaway directory, removed by the caller.
    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rh-p51-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A little-endian 64-bit Mach-O with the given rpaths and install
    /// names (the same fixture form the object-file module's tests use).
    fn macho_bytes(rpaths: &[&str], libs: &[&str]) -> Vec<u8> {
        const MH_MAGIC_64: u32 = 0xfeedfacf;
        const LC_LOAD_DYLIB: u32 = 0x0c;
        const LC_RPATH: u32 = 0x8000_001c;
        let mut v = Vec::new();
        v.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        v.extend_from_slice(&0x0100_000cu32.to_le_bytes()); // CPU_TYPE_ARM64
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&6u32.to_le_bytes()); // MH_DYLIB
        v.extend_from_slice(&((rpaths.len() + libs.len()) as u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        let mut cmds: Vec<u8> = Vec::new();
        for r in rpaths {
            let len = 12 + r.len() + 1;
            let size = len.div_ceil(4) * 4;
            cmds.extend_from_slice(&LC_RPATH.to_le_bytes());
            cmds.extend_from_slice(&(size as u32).to_le_bytes());
            cmds.extend_from_slice(&12u32.to_le_bytes());
            cmds.extend_from_slice(r.as_bytes());
            cmds.push(0);
            cmds.resize(cmds.len() + (size - len), 0);
        }
        for l in libs {
            let len = 24 + l.len() + 1;
            let size = len.div_ceil(4) * 4;
            cmds.extend_from_slice(&LC_LOAD_DYLIB.to_le_bytes());
            cmds.extend_from_slice(&(size as u32).to_le_bytes());
            cmds.extend_from_slice(&24u32.to_le_bytes());
            cmds.extend_from_slice(&1u32.to_le_bytes());
            cmds.extend_from_slice(&0u32.to_le_bytes());
            cmds.extend_from_slice(&0u32.to_le_bytes());
            cmds.extend_from_slice(l.as_bytes());
            cmds.push(0);
            cmds.resize(cmds.len() + (size - len), 0);
        }
        v[20..24].copy_from_slice(&(cmds.len() as u32).to_le_bytes());
        v.extend_from_slice(&cmds);
        v
    }

    /// A Mach-O file at `dir/<name>` with the given references,
    /// canonicalised.
    fn macho(dir: &Path, name: &str, rpaths: &[&str], libs: &[&str]) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, macho_bytes(rpaths, libs)).unwrap();
        std::fs::canonicalize(&p).unwrap()
    }

    /// The allowed-prefix table the tests use: the temp directory stands
    /// in for the home directory (a test must never write into the real
    /// prefixes), with no named roots.
    fn allowed_home(home: &Path) -> Allowed<'_> {
        Allowed {
            roots: &[],
            home: Some(home),
        }
    }

    #[test]
    fn transitive_depth_is_bounded() {
        let d = tmp("depth");
        let d = std::fs::canonicalize(&d).unwrap();
        // a -> b -> c -> d, each library in its own directory; the program
        // and one level of transitive dependencies are parsed (a, b, c).
        // Every name a parsed object carries is still resolved (c names
        // d, so d's directory is a root too), but d itself is never
        // parsed: it names a missing library, and an unbounded walk would
        // parse d and refuse.
        let a = macho(
            &d.join("bin"),
            "a",
            &[],
            &["@loader_path/../lib_b/libb.dylib"],
        );
        let b = macho(
            &d.join("lib_b"),
            "libb.dylib",
            &[],
            &["@loader_path/../lib_c/libc.dylib"],
        );
        let c = macho(
            &d.join("lib_c"),
            "libc.dylib",
            &[],
            &["@loader_path/../lib_d/libd.dylib"],
        );
        let d4 = macho(
            &d.join("lib_d"),
            "libd.dylib",
            &[],
            &["@loader_path/../lib_e/libe.dylib"],
        );
        let r = resolve(&a, &allowed_home(&d)).unwrap();
        let dirs: Vec<&Path> = r.roots.iter().map(|p| p.as_path()).collect();
        for want in [
            b.parent().unwrap(),
            c.parent().unwrap(),
            d4.parent().unwrap(),
        ] {
            assert!(dirs.contains(&want), "{dirs:?}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn deps_outside_allowed_prefixes_listed_and_refused() {
        let d = tmp("refuse");
        let d = std::fs::canonicalize(&d).unwrap();
        // The library exists, but in a directory under no allowed prefix
        // (no home given): named in the refusal, with the fix.
        let a = macho(
            &d.join("bin"),
            "a",
            &[],
            &["@loader_path/../evil/libevil.dylib"],
        );
        macho(&d.join("evil"), "libevil.dylib", &[], &[]);
        let e = resolve(
            &a,
            &Allowed {
                roots: &[],
                home: None,
            },
        )
        .unwrap_err();
        assert!(e.contains("libevil.dylib"), "{e}");
        assert!(e.contains("outside every allowed prefix"), "{e}");
        assert!(e.contains("exec section"), "{e}");
        // A missing dependency is refused by name too, with what was tried.
        let a = macho(&d.join("bin2"), "a2", &[], &["@rpath/libgone.dylib"]);
        let e = resolve(&a, &allowed_home(&d)).unwrap_err();
        assert!(
            e.contains("libgone.dylib") && e.contains("was not found"),
            "{e}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn system_libraries_need_no_root_and_scripts_have_no_deps() {
        let d = tmp("allowed");
        let d = std::fs::canonicalize(&d).unwrap();
        // A system library needs no root (the prefix check is on the path
        // alone, so it holds whether or not the file is there); a library
        // under the (stand-in home) prefix becomes one; a script shim has
        // no dependencies at all.
        let libdir = d.join("opt").join("lib");
        // Only a system library: no root, no refusal.
        let a = macho(&d.join("bin"), "a", &[], &["/usr/lib/libSystem.B.dylib"]);
        // The rpath points at the stand-in prefix.
        let with_rpath = macho(
            &d.join("bin"),
            "b",
            &[&format!("{}/../opt/lib", d.join("bin").display())],
            &["@rpath/libgit2.1.9.dylib"],
        );
        macho(&libdir, "libgit2.1.9.dylib", &[], &[]);
        let r = resolve(&a, &allowed_home(&d)).unwrap();
        assert!(r.roots.is_empty(), "{:?}", r.roots);
        let r = resolve(&with_rpath, &allowed_home(&d)).unwrap();
        assert_eq!(r.roots, vec![libdir.clone()]);
        // A program that is a script resolves to no roots at all.
        let script = d.join("bin").join("shim");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        let script = std::fs::canonicalize(&script).unwrap();
        let r = resolve(&script, &allowed_home(&d)).unwrap();
        assert!(r.roots.is_empty() && r.libs.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn malformed_object_file_is_refused_not_panicked() {
        let d = tmp("malformed");
        let d = std::fs::canonicalize(&d).unwrap();
        // The magic of a Mach-O, then garbage: a refusal, not a panic.
        let p = d.join("broken");
        std::fs::write(&p, [0xcf, 0xfa, 0xed, 0xfe, 0xff, 0xff, 0xff, 0xff]).unwrap();
        let p = std::fs::canonicalize(&p).unwrap();
        let e = resolve(&p, &allowed_home(&d)).unwrap_err();
        assert!(e.contains("shorter than an object-file header"), "{e}");
        // A dependency that claims to be an object file but is broken is
        // refused the same way.
        let a = macho(&d.join("bin"), "a", &[], &["@loader_path/libbroken.dylib"]);
        std::fs::write(d.join("libbroken.dylib"), [0xcf, 0xfa, 0xed, 0xfe, 9]).unwrap();
        let e = resolve(&a, &allowed_home(&d)).unwrap_err();
        assert!(e.contains("libbroken.dylib"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The machine's own cargo: not a fixture. Its resolved roots stay
    /// under the allowed prefixes, which is the property every run
    /// depends on. Skipped, with the reason, where cargo is not a Mach-O.
    #[cfg(target_os = "macos")]
    #[test]
    fn machine_cargo_roots_stay_under_allowed_prefixes() {
        let Some(path) = std::env::var_os("PATH") else {
            eprintln!("skip: PATH is not set");
            return;
        };
        let Ok(cargo) = crate::exec_presets::look_up("cargo", &path) else {
            eprintln!("skip: no cargo on PATH");
            return;
        };
        let bytes = std::fs::read(&cargo).unwrap();
        let macho = harness_core::objfile::parse(&bytes)
            .ok()
            .is_some_and(|o| o.format == harness_core::objfile::Format::MachO);
        if !macho {
            eprintln!("skip: cargo is not a Mach-O on this machine");
            return;
        }
        let home = home_dir();
        let allowed = Allowed {
            roots: &[],
            home: home.as_deref(),
        };
        let r = resolve(&cargo, &allowed).unwrap();
        for dir in &r.roots {
            assert!(dir.is_absolute() && dir.is_dir(), "{dir:?}");
            assert!(
                ALLOWED_PREFIXES.iter().any(|s| dir.starts_with(s))
                    || home.as_ref().is_some_and(|h| dir.starts_with(h)),
                "{dir:?} is outside every allowed prefix"
            );
        }
    }
}
