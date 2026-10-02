//! Exec presets, PATH pinning and `--shell` (P-11): build a task's `exec`
//! section from program **names** instead of hand-written absolute paths.
//!
//! `--allow-exec cargo,git` (or `exec_programs` in the user config) resolves
//! each name against **this process's own PATH at startup** — the trust
//! base, before anything runs — canonicalises what it finds to one absolute,
//! real path and pins it exactly as a task file's `exec.programs` would.
//! `--preset rust|node|python|go` adds the read-only roots the toolchain
//! needs (found via the resolved binary's parents), its variables and its
//! limits. `--shell` adds `sh` to the allowlist; the journal header then
//! stamps `shell_enabled: true` (§4.8: shells are never in any default
//! allowlist, adding one is explicit). Everything found is printed to the
//! user before the run starts (`will allow: cargo -> /path`).
//!
//! P-51: each resolved program's dynamic-library dependencies are
//! resolved too (`exec_libs`, from the program's own load commands), and
//! their directories join the read-only roots — shown in the same line
//! (`… ; libs: …`), part of the spec the header records. A dependency
//! outside every allowed prefix refuses the resolution, so a run cannot
//! start half-allowed.
//!
//! Fail-closed: a PATH entry that is not absolute is refused (a relative
//! entry would resolve against a moving working directory), the found file
//! must canonicalise to an existing regular file, a preset must name a
//! known table and its anchor program must be on `--allow-exec`, and none
//! of these flags may be combined with a task file that has its own `exec`
//! section — that file already pins its programs. `replay` and `resume`
//! take the same flags, so an audit re-resolves the same section and
//! compares it with the recorded header.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use harness_run::{plain_name, ExecLimits, ExecProgram, ExecSpec, MAX_PROGRAMS};

use crate::config;
use crate::exec_libs;
use crate::report::{exit, refused, Outcome};
use crate::Cx;

/// The capability every exec flag needs in the task's grants.
const EXEC_GRANT: &str = "harness.exec.run";

/// One preset: the anchor program whose resolved path gives the toolchain's
/// read-only root, the variables the toolchain wants, and the per-command
/// limits. Data, not code: a new toolchain is a new row.
struct Preset {
    /// The `--allow-exec` name the roots are derived from.
    anchor: &'static str,
    /// Variables set for every command (§5.5; `CARGO_TARGET_DIR` and the
    /// other scratch variables are built by the harness already).
    env: &'static [(&'static str, &'static str)],
    /// Limits per command (the §6.2 defaults fit every preset today).
    limits: ExecLimits,
}

/// The presets, by name.
fn preset(name: &str) -> Option<Preset> {
    let limits = ExecLimits::default();
    let (anchor, env): (&'static str, &'static [(&'static str, &'static str)]) = match name {
        "rust" => ("cargo", &[("CARGO_NET_OFFLINE", "true")]),
        "node" => ("node", &[]),
        "python" => ("python3", &[]),
        "go" => ("go", &[]),
        _ => return None,
    };
    Some(Preset {
        anchor,
        env,
        limits,
    })
}

/// What the exec flags ask for, after the flag/config forms are read.
pub(crate) struct ExecRequest {
    /// The `--allow-exec` names, in the order given.
    programs: Vec<String>,
    /// The `--preset` name, if given.
    preset: Option<String>,
    /// Whether `--shell` was given.
    shell: bool,
}

impl ExecRequest {
    /// Whether nothing at all was asked for.
    fn empty(&self) -> bool {
        self.programs.is_empty() && self.preset.is_none() && !self.shell
    }
}

/// The exec flags of this invocation: `--allow-exec` (flag or the config's
/// `exec_programs`, comma-separated names), `--preset` and `--shell`.
/// `None` when none was given, so a task without an exec section behaves
/// exactly as before.
pub(crate) fn request(
    o: &BTreeMap<&str, &str>,
    cfg: &Option<config::UserConfig>,
) -> Option<ExecRequest> {
    let programs = match config::value(o, cfg, "allow-exec") {
        None => Vec::new(),
        Some(s) => s.split(',').map(str::trim).map(str::to_owned).collect(),
    };
    let r = ExecRequest {
        programs,
        preset: o.get("preset").map(|s| (*s).to_owned()),
        shell: o.contains_key("shell"),
    };
    if r.empty() {
        None
    } else {
        Some(r)
    }
}

/// What one resolution produced: the exec section (every program pinned,
/// the read-only roots the preset names plus the P-51 library roots) and,
/// per program, the library directories the dependency resolution added,
/// for the line shown to the user before the run starts.
#[derive(Debug)]
pub(crate) struct Resolved {
    /// The exec section, in the task file's own form.
    pub(crate) spec: ExecSpec,
    /// Per program (in `spec.programs`' order): the directories of the
    /// program's dynamic libraries that were added to `read_only`.
    pub(crate) libs: Vec<(String, Vec<PathBuf>)>,
}

/// The exec section these flags describe, resolved now (see the module
/// text). Every refusal names the flag and the why.
pub(crate) fn resolve(req: &ExecRequest, path_var: &OsStr) -> Result<Resolved, String> {
    let mut names: Vec<String> = Vec::new();
    for n in &req.programs {
        if n.is_empty() {
            return Err("--allow-exec: empty program name".into());
        }
        if !plain_name(n) {
            return Err(format!("--allow-exec: {n:?} is not a plain program name"));
        }
        if names.iter().any(|x| x == n) {
            return Err(format!("--allow-exec: {n} appears twice"));
        }
        names.push(n.clone());
    }
    // §4.8: a shell on the allowlist is always explicit, and `--shell` is
    // the explicit way. `shell_enabled` in the header follows from the
    // name alone (harness-tools), so nothing more is needed here.
    if req.shell && !names.iter().any(|n| n == "sh") {
        names.push("sh".to_owned());
    }
    if names.is_empty() {
        return Err(
            "--allow-exec: name at least one program (comma-separated), or use --shell".into(),
        );
    }
    if names.len() > MAX_PROGRAMS {
        return Err(format!("--allow-exec: more than {MAX_PROGRAMS} programs"));
    }
    let programs = names
        .iter()
        .map(|n| {
            look_up(n, path_var).map(|path| ExecProgram {
                name: n.clone(),
                path,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (mut read_only, env, limits) = match &req.preset {
        None => (Vec::new(), Vec::new(), ExecLimits::default()),
        Some(pn) => {
            let p = preset(pn).ok_or_else(|| {
                format!("--preset: unknown preset {pn:?} (known: rust, node, python, go)")
            })?;
            let anchor = programs
                .iter()
                .find(|pr| pr.name == p.anchor)
                .ok_or_else(|| {
                    format!(
                        "--preset {}: it needs {} on the --allow-exec list",
                        pn, p.anchor
                    )
                })?;
            (
                vec![toolchain_root(&anchor.path)?],
                p.env
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
                p.limits,
            )
        }
    };
    // P-51: every program's dynamic libraries become read-only roots too,
    // in the trust base, before anything runs. The preset's roots are
    // passed in as already-allowed prefixes, so a library inside the
    // toolchain adds no new root. A dependency outside every allowed
    // prefix is a refusal: the user adds it, by naming the directory in a
    // task file's own exec section.
    let home = exec_libs::home_dir();
    let mut libs = Vec::new();
    for p in &programs {
        let allowed = exec_libs::Allowed {
            roots: &read_only,
            home: home.as_deref(),
        };
        let lr = exec_libs::resolve(&p.path, &allowed)
            .map_err(|e| format!("--allow-exec: {}: {e}", p.name))?;
        for r in &lr.roots {
            if !read_only.contains(r) {
                read_only.push(r.clone());
            }
        }
        libs.push((p.name.clone(), lr.roots));
    }
    Ok(Resolved {
        spec: ExecSpec {
            programs,
            read_only,
            env,
            limits,
        },
        libs,
    })
}

/// The exec section the flags describe, for callers outside the crate
/// (the integration tests recompute the header's exec input, P-51): the
/// names as `--allow-exec` would take them, the preset, `--shell`, and
/// the PATH to resolve against.
pub fn resolve_names(
    programs: &[&str],
    preset: Option<&str>,
    shell: bool,
    path_var: &OsStr,
) -> Result<ExecSpec, String> {
    resolve(
        &ExecRequest {
            programs: programs.iter().map(|s| (*s).to_owned()).collect(),
            preset: preset.map(str::to_owned),
            shell,
        },
        path_var,
    )
    .map(|r| r.spec)
}

/// The exec section this invocation's flags describe, or `None` when it
/// gave none. Fail-closed on every disagreement between the flags and the
/// task: an exec section the task file already pins, a grant that is
/// missing, a name that is not on PATH — all unreadable input (exit 4),
/// like a malformed exec section, and nothing runs or journals.
/// On success every program is printed, before the run starts.
pub(crate) fn section(
    cx: &Cx<'_>,
    o: &BTreeMap<&str, &str>,
    cfg: &Option<config::UserConfig>,
    grants: &[String],
) -> Result<Option<ExecSpec>, Outcome> {
    let Some(req) = request(o, cfg) else {
        return Ok(None);
    };
    let bad = |e: String| -> Outcome {
        note!(cx, "{e}");
        refused(exit::UNREADABLE_INPUT, e)
    };
    if !grants.iter().any(|g| g == EXEC_GRANT) {
        return Err(bad(format!(
            "--allow-exec needs the task to grant {EXEC_GRANT}; this task does not"
        )));
    }
    let Some(path) = std::env::var_os("PATH") else {
        return Err(bad(
            "--allow-exec: PATH is not set; give the task an exec section with absolute paths \
             instead"
                .into(),
        ));
    };
    let spec = resolve(&req, &path).map_err(bad)?;
    for (p, (_, libs)) in spec.spec.programs.iter().zip(&spec.libs) {
        if libs.is_empty() {
            note!(cx, "will allow: {} -> {}", p.name, p.path.display());
        } else {
            note!(
                cx,
                "will allow: {} -> {}; libs: {}",
                p.name,
                p.path.display(),
                libs.iter()
                    .map(|d| d.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    if let Some(pn) = &req.preset {
        let roots = spec
            .spec
            .read_only
            .iter()
            .map(|r| r.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let env = spec
            .spec
            .env
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ");
        note!(cx, "preset {pn}: read-only: {roots}; env: {env}");
    }
    if req.shell {
        note!(
            cx,
            "--shell: sh is on the allowlist; the header stamps shell_enabled"
        );
    }
    Ok(Some(spec.spec))
}

/// First match of `name` on `path_var`, pinned to its real path: the entry
/// must canonicalise to an existing regular file. A relative PATH entry is
/// refused when the search reaches it (a relative entry would resolve
/// against a working directory this run does not control); a broken or
/// escaping symlink is refused with it.
///
/// Windows (S-W1): a directory entry for a program is usually `name.exe`,
/// so each directory is searched for the name as given first, then the
/// `.exe` form (PATHEXT's first entry; the other script extensions are
/// deliberately not searched — a `.bat` is not a program this harness
/// pins). Off Windows only the name as given is tried.
pub(crate) fn look_up(name: &str, path_var: &OsStr) -> Result<PathBuf, String> {
    for dir in std::env::split_paths(path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        if !dir.is_absolute() {
            return Err(format!(
                "--allow-exec: the PATH entry {dir:?} is relative; programs are resolved from \
                 absolute directories only"
            ));
        }
        for candidate in candidate_names(&dir, name) {
            let Ok(_) = std::fs::symlink_metadata(&candidate) else {
                continue;
            };
            let real = std::fs::canonicalize(&candidate).map_err(|e| {
                format!("--allow-exec: {name}: {candidate:?} does not resolve to a file: {e}")
            })?;
            if real.to_str().is_none() {
                return Err(format!(
                    "--allow-exec: {name}: the resolved path is not UTF-8"
                ));
            }
            if !std::fs::metadata(&real)
                .map(|m| m.is_file())
                .unwrap_or(false)
            {
                return Err(format!(
                    "--allow-exec: {name}: {real:?} is not a regular file"
                ));
            }
            return Ok(real);
        }
    }
    Err(format!("--allow-exec: no {name} on PATH"))
}

/// The spellings of `name` tried in one PATH directory: the name exactly
/// as given (a pinned path must mean what was written), plus on Windows
/// the `.exe` form, which is how `cargo` sits on disk there.
fn candidate_names(dir: &Path, name: &str) -> Vec<PathBuf> {
    let mut v = vec![dir.join(name)];
    if cfg!(windows) {
        v.push(dir.join(format!("{name}.exe")));
    }
    v
}

/// The read-only root a preset derives from its anchor's resolved path: the
/// binary's directory, or the toolchain root above it when the binary sits
/// in a `bin` directory (`…/toolchains/1.88/bin/cargo` pins `…/toolchains/1.88`).
/// The filesystem root is never a read-only root.
pub(crate) fn toolchain_root(bin: &Path) -> Result<PathBuf, String> {
    let dir = bin
        .parent()
        .ok_or_else(|| format!("--preset: {} has no parent directory", bin.display()))?;
    let root = match dir.file_name() {
        Some(f) if f == "bin" => dir.parent().unwrap_or(dir),
        _ => dir,
    };
    if root.parent().is_none() {
        return Err(
            "--preset: the toolchain root would be the filesystem root; give the task an exec \
             section with explicit read-only roots instead"
                .into(),
        );
    }
    Ok(root.to_path_buf())
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    /// A throwaway directory with a `bin/` in it, removed by the caller.
    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rh-p11-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("bin")).unwrap();
        d
    }

    /// An executable script at `dir/bin/<name>`, canonicalised (the temp
    /// directory itself may sit behind a symlink, the pin must not).
    fn script(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join("bin").join(name);
        std::fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::canonicalize(&p).unwrap()
    }

    fn req(programs: &[&str], preset: Option<&str>, shell: bool) -> ExecRequest {
        ExecRequest {
            programs: programs.iter().map(|s| (*s).to_owned()).collect(),
            preset: preset.map(str::to_owned),
            shell,
        }
    }

    fn path_var(dirs: &[PathBuf]) -> OsString {
        std::env::join_paths(dirs.iter().map(|d| d.join("bin"))).unwrap()
    }

    /// The temp directory as the filesystem really names it (macOS puts
    /// temp dirs behind `/var`'s symlink).
    fn canon(p: &Path) -> PathBuf {
        std::fs::canonicalize(p).unwrap()
    }

    #[test]
    fn allow_exec_resolves_to_absolute_path() {
        let d = tmp("resolve");
        let first = script(&d, "mytool");
        let other = tmp("resolve-other");
        let elsewhere = script(&other, "mytool");
        // First directory on the PATH wins; the path is the real one.
        let spec = resolve(
            &req(&["mytool"], None, false),
            &path_var(&[d.clone(), other.clone()]),
        )
        .unwrap()
        .spec;
        assert_eq!(
            spec.programs,
            vec![ExecProgram {
                name: "mytool".into(),
                path: first,
            }]
        );
        assert!(spec.read_only.is_empty() && spec.env.is_empty());
        assert_eq!(spec.limits, ExecLimits::default());
        assert_ne!(spec.programs[0].path, elsewhere);
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&other);
    }

    #[test]
    fn allow_exec_refuses_relative_or_symlink_escape() {
        let d = tmp("refuse");
        script(&d, "mytool");
        let path = path_var(std::slice::from_ref(&d));
        // A name is a name, never a path.
        assert!(resolve(&req(&["bin/mytool"], None, false), &path)
            .unwrap_err()
            .contains("not a plain program name"));
        // A relative PATH entry is refused when the search reaches it.
        let relative: OsString = "bin".into();
        assert!(resolve(&req(&["mytool"], None, false), &relative)
            .unwrap_err()
            .contains("is relative"));
        // A broken symlink does not canonicalise to a file.
        std::os::unix::fs::symlink(d.join("gone"), d.join("bin").join("ghost")).unwrap();
        assert!(resolve(&req(&["ghost"], None, false), &path)
            .unwrap_err()
            .contains("does not resolve to a file"));
        // An entry that is a directory is not a program.
        std::fs::create_dir(d.join("bin").join("dirmaker")).unwrap();
        assert!(resolve(&req(&["dirmaker"], None, false), &path)
            .unwrap_err()
            .contains("is not a regular file"));
        // Nothing by that name anywhere on the PATH.
        assert!(resolve(&req(&["absent-tool"], None, false), &path)
            .unwrap_err()
            .contains("no absent-tool on PATH"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn preset_rust_sets_read_only_roots() {
        let d = tmp("preset");
        let toolchain = d.join("toolchains").join("1.88-aarch64-apple-darwin");
        std::fs::create_dir_all(toolchain.join("bin")).unwrap();
        let cargo = script(&toolchain, "cargo");
        let spec = resolve(
            &req(&["cargo"], Some("rust"), false),
            &path_var(std::slice::from_ref(&toolchain)),
        )
        .unwrap()
        .spec;
        assert_eq!(spec.programs[0].path, cargo);
        // The toolchain root above the binary's `bin` directory, as the
        // filesystem really names it.
        assert_eq!(spec.read_only, vec![canon(&toolchain)]);
        assert_eq!(spec.env, vec![("CARGO_NET_OFFLINE".into(), "true".into())]);
        assert_eq!(spec.limits, ExecLimits::default());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn unknown_preset_refused() {
        let d = tmp("unknown-preset");
        script(&d, "cargo");
        let path = path_var(std::slice::from_ref(&d));
        let e = resolve(&req(&["cargo"], Some("zig"), false), &path).unwrap_err();
        assert!(e.contains("unknown preset") && e.contains("zig"), "{e}");
        // A known preset whose anchor is not allowlisted is refused too.
        script(&d, "node");
        let e = resolve(&req(&["node"], Some("rust"), false), &path).unwrap_err();
        assert!(e.contains("needs cargo"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn resolved_exec_matches_task_file_form() {
        let d = tmp("task-form");
        let toolchain = d.join("toolchains").join("1.88-aarch64-apple-darwin");
        std::fs::create_dir_all(toolchain.join("bin")).unwrap();
        let cargo = script(&toolchain, "cargo");
        // Exactly the `ExecSpec` a task file with this exec section builds:
        //
        // {"exec": {"programs": [{"name": "cargo", "path": "<cargo>"}],
        //           "read_only": ["<toolchain>"],
        //           "env": {"CARGO_NET_OFFLINE": "true"}}}
        //
        // so the resolved section feeds the run, the header and (P-14) the
        // sessions store in the task file's own form.
        let want = ExecSpec {
            programs: vec![ExecProgram {
                name: "cargo".into(),
                path: cargo.clone(),
            }],
            read_only: vec![canon(&toolchain)],
            env: vec![("CARGO_NET_OFFLINE".into(), "true".into())],
            limits: ExecLimits::default(),
        };
        let got = resolve(
            &req(&["cargo"], Some("rust"), false),
            &path_var(std::slice::from_ref(&toolchain)),
        )
        .unwrap()
        .spec;
        assert_eq!(got, want);
        // `--shell` appends `sh`, by name, resolved on the same PATH (the
        // system one here; only the name and absoluteness are asserted).
        let with_shell = resolve(
            &req(&["cargo"], Some("rust"), true),
            &std::env::join_paths([
                toolchain.join("bin"),
                PathBuf::from("/bin"),
                PathBuf::from("/usr/bin"),
            ])
            .unwrap(),
        )
        .unwrap()
        .spec;
        assert_eq!(with_shell.programs.len(), 2);
        assert_eq!(with_shell.programs[1].name, "sh");
        assert!(with_shell.programs[1].path.is_absolute());
        assert!(with_shell.shell_enabled());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// P-51, on this machine's own cargo: the `rust` preset's roots now
    /// include the directories of cargo's dynamic libraries, every one of
    /// them under an allowed prefix. Skipped, with the reason, where this
    /// machine has no cargo on its PATH, cargo is not a Mach-O, or it
    /// links only system libraries (nothing for the preset to add).
    #[cfg(target_os = "macos")]
    #[test]
    fn preset_rust_includes_cargo_dylib_roots() {
        let Some(path) = std::env::var_os("PATH") else {
            eprintln!("skip: PATH is not set");
            return;
        };
        let cargo = match look_up("cargo", &path) {
            Ok(c) => c,
            Err(_) => {
                eprintln!("skip: no cargo on PATH");
                return;
            }
        };
        let bytes = std::fs::read(&cargo).unwrap();
        if !harness_core::objfile::is_object(&bytes) {
            eprintln!("skip: cargo is not a Mach-O on this machine");
            return;
        }
        let resolved = resolve(&req(&["cargo"], Some("rust"), false), &path).unwrap();
        let spec = resolved.spec;
        // The preset's own root is first (the toolchain above the binary).
        let (toolchain, lib_roots) = spec.read_only.split_first().unwrap();
        assert_eq!(toolchain, &toolchain_root(&cargo).unwrap());
        if lib_roots.is_empty() {
            eprintln!("skip: cargo links only system libraries here");
            return;
        }
        let home = std::env::var_os("HOME").map(PathBuf::from);
        for r in lib_roots {
            assert!(r.is_dir(), "{r:?} is not a directory");
            assert!(
                r.starts_with("/opt/homebrew")
                    || r.starts_with("/usr/local")
                    || r.starts_with("/Library/Developer")
                    || home.as_ref().is_some_and(|h| r.starts_with(h))
                    || r.starts_with(toolchain),
                "{r:?} is outside every allowed prefix"
            );
        }
        // The same directories are in the line shown to the user.
        let dirs = resolved.libs.iter().flat_map(|(_, ls)| ls.iter()).count();
        assert_eq!(dirs, lib_roots.len());
    }

    #[test]
    fn look_up_tries_the_name_as_spelled() {
        // Off Windows there is no implicit suffix: `mytool.sh` on disk is
        // found only by asking for `mytool.sh` (S-W1 pins this so the
        // Windows `.exe` search stays the one platform exception).
        let d = tmp("as-spelled");
        script(&d, "mytool.sh");
        let path = path_var(std::slice::from_ref(&d));
        assert!(look_up("mytool", &path)
            .unwrap_err()
            .contains("no mytool on PATH"));
        let found = look_up("mytool.sh", &path).unwrap();
        assert_eq!(found, script(&d, "mytool.sh"));
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
#[cfg(windows)]
mod windows_tests {
    use super::*;
    use std::ffi::OsString;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rh-p11-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("bin")).unwrap();
        d
    }

    fn path_var(dirs: &[PathBuf]) -> OsString {
        std::env::join_paths(dirs.iter().map(|d| d.join("bin"))).unwrap()
    }

    // S-W1: `cargo` resolves to `cargo.exe` on Windows, by the bare name,
    // so the preset anchors are findable there; the name as spelled is
    // still tried first.
    #[test]
    fn look_up_finds_the_exe_form() {
        let d = tmp("exe");
        let exe = d.join("bin").join("mytool.exe");
        std::fs::write(&exe, b"").unwrap();
        let path = path_var(std::slice::from_ref(&d));
        let found = look_up("mytool", &path).unwrap();
        assert_eq!(found, std::fs::canonicalize(&exe).unwrap());
        // The bare spelling wins when both forms sit in the directory.
        let bare = d.join("bin").join("mytool");
        std::fs::write(&bare, b"").unwrap();
        assert_eq!(
            look_up("mytool", &path).unwrap(),
            std::fs::canonicalize(&bare).unwrap()
        );
        // Nothing by that name (in either form) is still "not on PATH".
        assert!(look_up("absent-tool", &path)
            .unwrap_err()
            .contains("no absent-tool on PATH"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
