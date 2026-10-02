//! The `doctor` verb (P-43): a self-diagnosis for the first run, one line
//! per check with PASS/WARN/FAIL and a one-sentence fix. Not a gate child:
//! the last stdout line is a check line, not a `GateReport`. The checks:
//! the platform's sandbox witness, the state root (exists, local,
//! owner-only), the user config (P-07), the model endpoint and its
//! `/v1/models` listing, a model profile and its stamp, the toolchain
//! programs the exec presets need (P-11), and whether stdin is a terminal.
//!
//! Fail-closed in display only, and quiet otherwise: nothing is written
//! except the default state root every P-07 verb would create too, and no
//! network call is made except to the given endpoint (the client refuses
//! anything off loopback before connecting, INV-24). Every detail line is
//! sanitised (P-04): a hostile path, endpoint or model id cannot paint the
//! terminal. Exit 0 when no check FAILed, 1 when one did, 2 on a usage
//! error. A WARN is a working-but-limited host (no sandbox on Linux, no
//! terminal, an unstamped profile), never a bad installation.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use harness_core::display::{sanitize_for_terminal, DisplayMode};
use harness_model::client::{ClientConfig, OpenAiCompatible};
use harness_model::profile::Profile;

use crate::args::{options, USAGE};
use crate::config;
use crate::exec_presets::look_up;
use crate::report::exit;
use crate::Cx;

/// How long the endpoint check waits for `/v1/models`: a diagnosis should
/// not hang on a half-started server.
const ENDPOINT_TIMEOUT: Duration = Duration::from_secs(5);

/// The exec presets and the program each resolves first (P-11): what
/// `--preset <name>` needs on this host's PATH.
const PRESETS: &[(&str, &str)] = &[
    ("rust", "cargo"),
    ("node", "node"),
    ("python", "python3"),
    ("go", "go"),
];

/// One check's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    /// As expected.
    Pass,
    /// Works, with a limit the person should know about.
    Warn,
    /// Broken; the line says how to fix it.
    Fail,
}

impl Status {
    fn tag(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        }
    }
}

/// Print one check line and say whether it FAILed. The detail may name
/// paths, endpoints or server-supplied model ids, none of which are
/// trusted bytes, so it is sanitised before it is printed.
fn check_line(cx: &Cx<'_>, status: Status, name: &str, detail: &str) -> bool {
    let detail = sanitize_for_terminal(detail, DisplayMode::Line);
    say!(cx, "{} {}: {}", status.tag(), name, detail);
    status == Status::Fail
}

/// Run every check, one line each, and exit 0 only when none FAILed.
pub(crate) fn doctor(cx: &Cx<'_>, rest: &[&str]) -> u8 {
    let o = match options(rest, &["endpoint", "state-root"], &[]) {
        Ok(o) => o,
        Err(e) => {
            note!(cx, "{e}\n{USAGE}");
            return exit::USAGE;
        }
    };
    // The config is an input to the checks below and a check itself: a
    // file that is there but unusable is reported, and everything it
    // would have configured is diagnosed as unset.
    let (cfg, config_error): (Option<config::UserConfig>, Option<String>) = match config::load() {
        Ok(c) => (c, None),
        Err(e) => (None, Some(e)),
    };
    let mut failed = false;
    failed |= sandbox(cx);
    failed |= state_root(cx, &o, &cfg);
    failed |= match config_error {
        Some(e) => check_line(
            cx,
            Status::Fail,
            "config",
            &format!("{e}; fix: correct or remove the config file"),
        ),
        None => match &cfg {
            Some(_) => check_line(cx, Status::Pass, "config", "config.json read (strict)"),
            None => check_line(
                cx,
                Status::Pass,
                "config",
                "no config file (flags and defaults)",
            ),
        },
    };
    failed |= endpoint(cx, config::value(&o, &cfg, "endpoint"));
    failed |= profile(cx, &cfg);
    failed |= presets(cx);
    failed |= terminal(cx);
    note!(
        cx,
        "doctor: {}",
        if failed {
            "at least one FAIL above; fix it and run doctor again"
        } else {
            "no FAIL"
        }
    );
    if failed {
        exit::FAILED
    } else {
        exit::PASSED
    }
}

/// The platform check: a sandbox witness (macOS Seatbelt conformance), or
/// the refusal and its fix. A refusal is a WARN, not a FAIL: read-only
/// sessions work everywhere the locality check does; only
/// `harness.exec.run` needs the witness (README, H2d).
fn sandbox(cx: &Cx<'_>) -> bool {
    match cx.confinement.require() {
        Ok(w) => check_line(
            cx,
            Status::Pass,
            "sandbox",
            &format!(
                "conforms: {:?} row {} (probe digest {})",
                w.backend(),
                w.matrix_row(),
                w.probe_digest()
            ),
        ),
        Err(refused) => check_line(
            cx,
            Status::Warn,
            "sandbox",
            &format!(
                "refuses: {}; commands (harness.exec.run) stay off, read and edit work",
                refused.0
            ),
        ),
    }
}

/// The state-root check: the flag, else the config, else the default
/// (created owner-only when missing, exactly as the run verbs do, P-07).
/// An explicit state root is never created, so a missing one is reported:
/// FAIL with the command that fixes it.
fn state_root(
    cx: &Cx<'_>,
    o: &std::collections::BTreeMap<&str, &str>,
    cfg: &Option<config::UserConfig>,
) -> bool {
    let root = match config::state_root(o, cfg) {
        Ok(Some(r)) => Some(r.into_owned()),
        Ok(None) => None,
        Err(e) => {
            return check_line(
                cx,
                Status::Fail,
                "state-root",
                &format!("{e}; fix: pass --state-root <dir>"),
            );
        }
    };
    match root {
        Some(root) => check_state_root(cx, &root),
        None => check_line(
            cx,
            Status::Fail,
            "state-root",
            "no state root given and this platform has no default; fix: pass --state-root <dir>",
        ),
    }
}

/// One state root: exists (else FAIL, with the `mkdir -p` that fixes it),
/// on a local filesystem (else FAIL: the run verbs refuse it too), and
/// owner-only (else WARN with the `chmod` that fixes it).
fn check_state_root(cx: &Cx<'_>, root: &str) -> bool {
    let path = std::path::Path::new(root);
    if !path.is_dir() {
        return check_line(
            cx,
            Status::Fail,
            "state-root",
            &format!("{root} does not exist (or is not a directory); fix: mkdir -p {root}"),
        );
    }
    match harness_policy::locality::check(cx.probe, root) {
        Err(e) => check_line(
            cx,
            Status::Fail,
            "state-root",
            &format!(
                "{root} is not on a local filesystem ({e}); fix: use a directory on a local disk"
            ),
        ),
        Ok(_) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(path)
                    .map(|m| m.permissions().mode() & 0o777)
                    .unwrap_or(0);
                if mode != 0o700 {
                    return check_line(
                        cx,
                        Status::Warn,
                        "state-root",
                        &format!("{root} is local but mode {mode:o} is wider than 0700; fix: chmod 700 {root}"),
                    );
                }
            }
            check_line(
                cx,
                Status::Pass,
                "state-root",
                &format!("{root} exists, local, owner-only"),
            )
        }
    }
}

/// The endpoint check: reachable, and what it lists. Nothing given, or a
/// server that is simply not up yet, is a WARN (start it and run doctor
/// again); an endpoint the client refuses off loopback is a FAIL, because
/// no run can ever use it, and building the client makes no connection.
fn endpoint(cx: &Cx<'_>, endpoint: Option<&str>) -> bool {
    let Some(url) = endpoint else {
        return check_line(
            cx,
            Status::Warn,
            "endpoint",
            "no endpoint given; fix: pass --endpoint http://127.0.0.1:PORT/v1 (the model server's)",
        );
    };
    let probe = match OpenAiCompatible::new(
        url,
        Profile::conservative_default("unspecified"),
        None,
        ClientConfig::default(),
    ) {
        Ok(c) => c,
        Err(e) => {
            return check_line(
                cx,
                Status::Fail,
                "endpoint",
                &format!("{url} refused: {e}; fix: use a loopback endpoint (127.0.0.1, [::1] or localhost)"),
            );
        }
    };
    match probe.list_models(Instant::now() + ENDPOINT_TIMEOUT) {
        Ok(models) => check_line(
            cx,
            Status::Pass,
            "endpoint",
            &format!(
                "{url} reachable, lists {} model(s): {}",
                models.len(),
                models.join(", ")
            ),
        ),
        Err(e) => check_line(
            cx,
            Status::Warn,
            "endpoint",
            &format!("{url} unreachable: {e}; fix: start the model server on that address"),
        ),
    }
}

/// The profile check: the config's profile, else `profile init`'s default
/// location in the config dir. Missing or unreadable is a FAIL (no run
/// starts without one); parseable but unstamped is a WARN (`profile
/// check` stamps it); a valid stamp is a PASS.
fn profile(cx: &Cx<'_>, cfg: &Option<config::UserConfig>) -> bool {
    let path = match cfg.as_ref().and_then(|c| c.profile.clone()) {
        Some(p) => PathBuf::from(p),
        None => match config::config_dir() {
            Ok(Some(dir)) => dir.join("profiles").join("default.json"),
            Ok(None) => {
                return check_line(
                    cx,
                    Status::Fail,
                    "profile",
                    "no profile and no config directory on this platform; fix: \
                     rustyharness profile init --endpoint <url> --out <profile.json>",
                );
            }
            Err(e) => return check_line(cx, Status::Fail, "profile", &e),
        },
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return check_line(
                cx,
                Status::Fail,
                "profile",
                &format!(
                    "no profile at {}; fix: rustyharness profile init --endpoint <url>",
                    path.display()
                ),
            );
        }
        Err(e) => {
            return check_line(
                cx,
                Status::Fail,
                "profile",
                &format!("cannot read {}: {e}", path.display()),
            );
        }
    };
    match Profile::parse(&bytes) {
        Err(e) => check_line(
            cx,
            Status::Fail,
            "profile",
            &format!(
                "{} is not a valid profile: {e}; fix: rustyharness profile init --endpoint <url>",
                path.display()
            ),
        ),
        Ok(p) if p.validated() => check_line(
            cx,
            Status::Pass,
            "profile",
            &format!(
                "{} valid, stamp valid (model {})",
                path.display(),
                p.model()
            ),
        ),
        Ok(_) => check_line(
            cx,
            Status::Warn,
            "profile",
            &format!(
                "{} parses but has no valid stamp; fix: rustyharness profile check \
                 --profile {} --endpoint <url>",
                path.display(),
                path.display()
            ),
        ),
    }
}

/// The preset programs (P-11): each preset's anchor program must be on
/// this process's PATH for `--preset` to pin it. Missing programs limit
/// one preset, not the harness: a WARN with the names.
fn presets(cx: &Cx<'_>) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return check_line(
            cx,
            Status::Warn,
            "presets",
            "PATH is not set, so no preset can resolve its programs; fix: run with PATH set, \
             or give tasks an exec section with absolute paths",
        );
    };
    let missing: Vec<String> = PRESETS
        .iter()
        .filter(|(_, anchor)| look_up(anchor, &path).is_err())
        .map(|(preset, anchor)| format!("{preset} ({anchor})"))
        .collect();
    if missing.is_empty() {
        check_line(
            cx,
            Status::Pass,
            "presets",
            "every preset's program is on PATH (cargo, node, python3, go)",
        )
    } else {
        check_line(
            cx,
            Status::Warn,
            "presets",
            &format!(
                "not on PATH: {}; fix: install them, or give tasks an exec section with \
                 absolute paths (--preset for them refuses)",
                missing.join(", ")
            ),
        )
    }
}

/// The terminal check: asks (edits, commands) are answered by the person
/// at the terminal only when there is one; without it every ask is a deny
/// (§5.2, §5.3) unless the policy allows the tool.
fn terminal(cx: &Cx<'_>) -> bool {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        check_line(
            cx,
            Status::Pass,
            "terminal",
            "stdin is a terminal; asks can be answered",
        )
    } else {
        check_line(
            cx,
            Status::Warn,
            "terminal",
            "stdin is not a terminal, so every ask is a deny; fix: run from a terminal, or \
             list the tools in the policy's allow",
        )
    }
}
