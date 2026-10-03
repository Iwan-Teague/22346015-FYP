//! The `schedule` verb (P-49): a timed, unattended run installed at the
//! user's own launcher level — a launchd plist on macOS, a systemd user
//! service + timer elsewhere on unix. `add` validates a task, profile and
//! policy exactly as `run` would, stores them byte-for-byte under
//! `<state-root>/schedules/<name>/` (0600), and — only after a `y` on the
//! same input source the chat REPL reads lines from — writes the launcher
//! files (0600). Until that answer nothing is written, and the launcher is
//! never loaded into launchd or systemd by this binary: the exact load
//! commands are printed instead.
//!
//! The installed command is `schedule run-now --name <name>`, a gate child
//! under the [`GATE`] id: it re-reads the stored files, re-checks every
//! digest it recorded, and only then runs — always unattended (§5.3: the
//! run a timer starts has nobody to ask, so every ask is a deny, even at a
//! terminal). `list` shows what is installed (the next daily run as a UTC
//! estimate: the OS fires it at local HH:MM and this binary has no
//! timezone database), and `remove` deletes one schedule's files and
//! nothing else.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use gate_outcome::GateId;
use serde::{Deserialize, Serialize};

use crate::args::{options, USAGE};
use crate::cmd_profile::write_private;
use crate::config;
use crate::inputs::{self, INPUT_MAX_BYTES};
use crate::report::{emit, exit, refused};
use crate::{Cx, InputSource};

/// The schedule manifest's name inside `schedules/<name>/`.
const SCHEDULE_FILE: &str = "schedule.json";
const TASK_FILE: &str = "task.json";
const PROFILE_FILE: &str = "profile.json";
const POLICY_FILE: &str = "policy.json";
/// The schedule format tag, refused if it is anything else.
const FORMAT: &str = "rh-schedule/1";
/// The gate id every `run-now` report names.
const GATE: &str = "rustyharness.schedule";
/// The widest `--every`: a week of hours.
const EVERY_MAX_HOURS: u32 = 168;

/// When a schedule fires. Stored in `schedule.json`; `daily` is the local
/// time the OS fires at, spelled `HH:MM`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum Cadence {
    Daily { hh: u32, mm: u32 },
    EveryHours { hours: u32 },
}

impl Cadence {
    /// The display spelling (`list` shows): `daily@23:45`, `every6h`.
    fn text(&self) -> String {
        match self {
            Cadence::Daily { hh, mm } => format!("daily@{hh:02}:{mm:02}"),
            Cadence::EveryHours { hours } => format!("every{hours}h"),
        }
    }
}

/// `schedule.json` as it is stored (strict JSON on read, bounded). The
/// three digests are the run inputs' digests (the header's, the bundle
/// self-check's); `policy` is `"policy.json"` or `"default"`, as the run
/// bundle spells it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduleDoc {
    format: String,
    name: String,
    cadence: Cadence,
    workspace: String,
    endpoint: String,
    state_root: String,
    task_sha256: String,
    profile_sha256: String,
    policy_sha256: String,
    policy: String,
    no_default_denies: bool,
    created: String,
}

pub(crate) fn schedule(cx: &Cx<'_>, rest: &[&str]) -> u8 {
    match rest {
        ["add", rest @ ..] => add(cx, rest),
        ["list", rest @ ..] => list(cx, rest),
        ["remove", rest @ ..] => remove(cx, rest),
        ["run-now", rest @ ..] => run_now(cx, rest),
        _ => {
            note!(cx, "{USAGE}");
            exit::USAGE
        }
    }
}

// ---- shared pieces -----------------------------------------------------------------

/// Where launcher files are installed: `$RUSTYHARNESS_SCHEDULE_HOME` if
/// set (absolute, or the value is refused; the macOS `LaunchAgents` resp.
/// the Linux `systemd/user` layout is added under it), else the user's own
/// launcher directory (`~/Library/LaunchAgents`, or
/// `$XDG_CONFIG_HOME/systemd/user` or `~/.config/systemd/user`).
/// `Ok(None)` is "this platform has none" (Windows: schedules refuse);
/// `Err` is a fail-closed refusal.
fn launcher_dir() -> Result<Option<PathBuf>, String> {
    const OVERRIDE: &str = "RUSTYHARNESS_SCHEDULE_HOME";
    if let Ok(v) = std::env::var(OVERRIDE) {
        if !Path::new(&v).is_absolute() {
            return Err(format!("{OVERRIDE} must be an absolute path, not {v:?}"));
        }
        return Ok(Some(if cfg!(target_os = "macos") {
            PathBuf::from(v).join("LaunchAgents")
        } else {
            PathBuf::from(v).join("systemd/user")
        }));
    }
    if cfg!(target_os = "macos") {
        return match std::env::var_os("HOME") {
            Some(h) if !h.is_empty() => Ok(Some(PathBuf::from(h).join("Library/LaunchAgents"))),
            // No HOME: no launcher location, not an error.
            _ => Ok(None),
        };
    }
    if !cfg!(unix) {
        // Windows (and anything else): no schedules until its spike lands.
        return Ok(None);
    }
    let base = match std::env::var("XDG_CONFIG_HOME") {
        Ok(x) if !x.is_empty() => {
            if !Path::new(&x).is_absolute() {
                return Err(format!(
                    "XDG_CONFIG_HOME must be an absolute path, not {x:?}"
                ));
            }
            PathBuf::from(x)
        }
        _ => match std::env::var_os("HOME") {
            Some(h) if !h.is_empty() => PathBuf::from(h).join(".config"),
            _ => return Ok(None),
        },
    };
    Ok(Some(base.join("systemd/user")))
}

/// The launcher files one schedule installs, in its launcher directory.
/// macOS names launch agents by reverse-dns label; systemd unit file names
/// take the plain form.
fn launcher_paths(dir: &Path, name: &str) -> Vec<PathBuf> {
    if cfg!(target_os = "macos") {
        vec![dir.join(format!("com.rustyharness.schedule.{name}.plist"))]
    } else {
        vec![
            dir.join(format!("rustyharness-{name}.service")),
            dir.join(format!("rustyharness-{name}.timer")),
        ]
    }
}

/// A schedule name: 1..=64 ASCII alphanumerics, `-` and `_`, starting
/// with an alphanumeric — stricter than a run's `plain_name`, because the
/// name is part of a launchd label and a systemd unit file name, where a
/// dot or a `+` would invite confusion with other units.
fn valid_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    match name.chars().next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn parse_daily(s: &str) -> Result<(u32, u32), String> {
    let bad = || "--daily must be HH:MM, from 00:00 to 23:59".to_owned();
    let (h, m) = s.split_once(':').ok_or_else(bad)?;
    if h.len() != 2 || m.len() != 2 {
        return Err(bad());
    }
    let hh: u32 = h.parse().map_err(|_| bad())?;
    let mm: u32 = m.parse().map_err(|_| bad())?;
    if hh > 23 || mm > 59 {
        return Err(bad());
    }
    Ok((hh, mm))
}

fn parse_every(s: &str) -> Result<u32, String> {
    let bad =
        || format!("--every must be a whole number of hours from 1 to {EVERY_MAX_HOURS} (e.g. 6h)");
    let n = s
        .strip_suffix('h')
        .ok_or_else(bad)?
        .parse::<u32>()
        .map_err(|_| bad())?;
    if n == 0 || n > EVERY_MAX_HOURS {
        return Err(bad());
    }
    Ok(n)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The next UTC occurrence of `HH:MM` at or after `now_ms` — an estimate
/// only: the OS fires the schedule at local HH:MM, and this binary has no
/// timezone database to consult (the slice notes carry the argument). The
/// day boundary is UTC midnight, the same civil arithmetic the journal's
/// `rfc3339_utc` uses.
fn next_daily_utc(now_ms: u64, hh: u32, mm: u32) -> u64 {
    let day = now_ms - (now_ms % 86_400_000);
    let at = day + (u64::from(hh) * 3600 + u64::from(mm) * 60) * 1000;
    if at > now_ms {
        at
    } else {
        at + 86_400_000
    }
}

/// XML text escaping for the plist's strings (`&`, `<`, `>`; attributes
/// are not used, so quotes need no escaping).
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// One `ExecStart=` argument: quoted, with the characters systemd reads
/// inside double quotes escaped (`\`, `"`, and `$`, which would start a
/// variable expansion).
fn systemd_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '$' => out.push_str("$$"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Any control character anywhere in a launcher argument is refused
/// fail-closed: none of the renderers can carry one safely.
fn no_control(what: &str, s: &str) -> Result<(), String> {
    if s.chars().any(char::is_control) {
        return Err(format!("{what} has a control character"));
    }
    Ok(())
}

/// A relative path made absolute against the current directory (no
/// canonicalize: the launcher should spell what the user spelled, only
/// anchored). A cwd that cannot be determined is fail-closed.
fn absolutize(what: &str, p: &str) -> Result<String, String> {
    if Path::new(p).is_absolute() {
        return Ok(p.to_owned());
    }
    let cwd = std::env::current_dir().map_err(|e| {
        format!("cannot determine the current directory to make {what} absolute: {e}")
    })?;
    Ok(cwd.join(p).to_string_lossy().into_owned())
}

/// Read `schedule.json` strictly: bounded, strict JSON, the expected
/// shape, the expected format, and a name that matches its directory.
fn load_doc(dir: &Path) -> Result<ScheduleDoc, String> {
    let path = dir.join(SCHEDULE_FILE);
    let bytes = std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if bytes.len() > INPUT_MAX_BYTES as usize {
        return Err(format!("{} is larger than 1 MiB", path.display()));
    }
    let bad = |e: String| format!("{}: {e}", path.display());
    let v = harness_core::strict_json::parse(&bytes)
        .map_err(|e| bad(format!("not strict JSON: {e}")))?;
    let doc: ScheduleDoc =
        serde_json::from_value(v).map_err(|e| bad(format!("unexpected shape: {e}")))?;
    if doc.format != FORMAT {
        return Err(bad(format!("format is {:?}, not {FORMAT:?}", doc.format)));
    }
    if !valid_name(&doc.name) {
        return Err(bad(format!("name {:?} is not a schedule name", doc.name)));
    }
    match dir.file_name().and_then(std::ffi::OsStr::to_str) {
        Some(f) if f == doc.name => {}
        _ => {
            return Err(bad(format!(
                "name {:?} does not match its directory",
                doc.name
            )))
        }
    }
    Ok(doc)
}

/// The one-line answer `add` and `remove` ask for: `y` or `yes` confirms,
/// anything else (or no line: end of input) declines — the same rule the
/// terminal approver applies, read from the same input source `chat` uses.
fn confirmed(cx: &Cx<'_>) -> bool {
    let line: Option<String> = match &cx.input {
        InputSource::Given(lines) => lines.first().map(|l| l.trim().to_ascii_lowercase()),
        InputSource::Stdin => {
            use std::io::{BufRead, Read};
            let mut raw = String::new();
            let read = std::io::stdin()
                .lock()
                .take(1025)
                .read_line(&mut raw)
                .is_ok();
            if read && !raw.is_empty() {
                Some(raw.trim().to_ascii_lowercase())
            } else {
                None
            }
        }
    };
    matches!(line.as_deref(), Some("y") | Some("yes"))
}

// ---- add ---------------------------------------------------------------------------

fn add(cx: &Cx<'_>, rest: &[&str]) -> u8 {
    let o = match options(
        rest,
        &[
            "name",
            "task",
            "daily",
            "every",
            "profile",
            "policy",
            "endpoint",
            "workspace",
            "state-root",
        ],
        &["no-default-denies"],
    ) {
        Ok(o) => o,
        Err(e) => {
            note!(cx, "{e}\n{USAGE}");
            return exit::USAGE;
        }
    };
    // A timed run executes only what the task file's exec section pins
    // (§2.10): the PATH-resolved presets are a person-at-the-terminal
    // convenience and are refused here, before anything else is read.
    for k in ["allow-exec", "preset", "shell"] {
        if o.contains_key(k) {
            note!(
                cx,
                "schedule add refuses --{k}: a timed run executes only what the task \
                 file's own exec section pins\n{USAGE}"
            );
            return exit::USAGE;
        }
    }
    let cfg = match config::load() {
        Ok(c) => c,
        Err(e) => {
            note!(cx, "{e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    let Some(name) = o.get("name").copied() else {
        note!(cx, "--name is required\n{USAGE}");
        return exit::USAGE;
    };
    if !valid_name(name) {
        note!(
            cx,
            "--name must be 1..=64 ASCII letters, digits, '-' or '_', starting with \
             a letter or digit"
        );
        return exit::USAGE;
    }
    let cadence = match (o.get("daily"), o.get("every")) {
        (Some(_), Some(_)) | (None, None) => {
            note!(
                cx,
                "schedule add needs exactly one of --daily <HH:MM> or --every <Nh>\n{USAGE}"
            );
            return exit::USAGE;
        }
        (Some(d), None) => match parse_daily(d) {
            Ok((hh, mm)) => Cadence::Daily { hh, mm },
            Err(e) => {
                note!(cx, "{e}\n{USAGE}");
                return exit::USAGE;
            }
        },
        (None, Some(e)) => match parse_every(e) {
            Ok(hours) => Cadence::EveryHours { hours },
            Err(e) => {
                note!(cx, "{e}\n{USAGE}");
                return exit::USAGE;
            }
        },
    };
    let Some(task_path) = config::value(&o, &cfg, "task") else {
        note!(cx, "--task is required\n{USAGE}");
        return exit::USAGE;
    };
    // The explicit budget, before any other validation: the §2.4 defaults
    // exist for a person's run, and a timer's run has nobody to stop it.
    let task_bytes = match inputs::read_input(task_path) {
        Ok(b) => b,
        Err(e) => {
            note!(cx, "{e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    match inputs::task_budget(&task_bytes) {
        Ok(Some(_)) => {}
        // A task that cannot be parsed at all is refused below, by name.
        Ok(None) => {
            note!(
                cx,
                "the task must set an explicit budget (a \"budget\" section with steps \
                 or wall_secs): a timed run has nobody watching\n{USAGE}"
            );
            return exit::UNREADABLE_INPUT;
        }
        Err(_) => {}
    }
    // The full validation `run` does, before anything is offered.
    let inp = match inputs::inputs(cx, &o, &cfg) {
        Ok(i) => i,
        Err(out) => return out.exit_override.unwrap_or(exit::INDETERMINATE),
    };
    let Some(endpoint) = config::value(&o, &cfg, "endpoint") else {
        note!(cx, "--endpoint is required\n{USAGE}");
        return exit::USAGE;
    };
    let workspace = match config::value(&o, &cfg, "workspace") {
        Some(w) => w.to_owned(),
        None => match std::env::current_dir() {
            Ok(d) => d.to_string_lossy().into_owned(),
            Err(e) => {
                note!(
                    cx,
                    "cannot determine the current directory for --workspace: {e}"
                );
                return exit::INDETERMINATE;
            }
        },
    };
    let state_root = match config::state_root(&o, &cfg) {
        Ok(Some(s)) => s.into_owned(),
        Ok(None) => {
            note!(
                cx,
                "--state-root is required here (no default state root on this platform)\n{USAGE}"
            );
            return exit::USAGE;
        }
        Err(e) => {
            note!(cx, "{e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    // The schedule is run from the launcher's own working directory, not
    // this one: a relative path here would mean a different place there,
    // so both are anchored now and stored absolute (no canonicalize: the
    // user's spelling, only anchored).
    let workspace = match absolutize("--workspace", &workspace) {
        Ok(w) => w,
        Err(e) => {
            note!(cx, "{e}");
            return exit::INDETERMINATE;
        }
    };
    let state_root = match absolutize("--state-root", &state_root) {
        Ok(s) => s,
        Err(e) => {
            note!(cx, "{e}");
            return exit::INDETERMINATE;
        }
    };
    let (launch_dir, have_launcher) = match launcher_dir() {
        Ok(Some(d)) => (d, true),
        Ok(None) => (PathBuf::new(), false),
        Err(e) => {
            note!(cx, "{e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    if !have_launcher {
        note!(
            cx,
            "this platform has no schedule launcher location; schedule add refuses"
        );
        return exit::INDETERMINATE;
    }
    let bundle = Path::new(&state_root).join("schedules").join(name);
    if bundle.symlink_metadata().is_ok() {
        note!(
            cx,
            "a schedule named {name} already exists at {}",
            bundle.display()
        );
        return exit::UNREADABLE_INPUT;
    }
    // The bytes to store, byte-exact, digest-checked against the values
    // the validation just used (a file that changed while being read is
    // refused, never stored half of one thing and half of another).
    let profile_path = config::value(&o, &cfg, "profile").unwrap_or("");
    let policy_path = config::value(&o, &cfg, "policy");
    let profile_bytes = match inputs::read_input(profile_path) {
        Ok(b) => b,
        Err(e) => {
            note!(cx, "{e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    let policy_bytes = match policy_path {
        Some(p) => match inputs::read_input(p) {
            Ok(b) => Some(b),
            Err(e) => {
                note!(cx, "{e}");
                return exit::UNREADABLE_INPUT;
            }
        },
        None => None,
    };
    let no_default_denies = o.contains_key("no-default-denies");
    let overlay = !no_default_denies;
    let got = (
        inputs::task_text(&task_bytes).map(|t| harness_core::sha256(t.as_bytes())),
        inputs::profile_digest(&profile_bytes),
        match &policy_bytes {
            // A schedule is unattended (P-47): no accept-edits overlay
            // (P-23) and no session grants can ever be set for one.
            Some(b) => inputs::policy_digest(b, overlay, false),
            None => inputs::default_policy(!overlay, false).map(|p| p.digest()),
        },
    );
    let check = |what: &str,
                 got: &Result<harness_core::Digest, String>,
                 want: harness_core::Digest|
     -> u8 {
        match got.as_ref().map_err(|e| e.clone()) {
            Err(e) => {
                note!(cx, "{e}");
                exit::UNREADABLE_INPUT
            }
            Ok(d) if *d != want => {
                note!(cx, "{what} changed while it was being read; nothing stored");
                exit::UNREADABLE_INPUT
            }
            Ok(_) => exit::PASSED,
        }
    };
    for (what, got, want) in [
        ("the task", &got.0, inp.digests.task),
        ("the profile", &got.1, inp.digests.profile),
        ("the policy", &got.2, inp.digests.policy),
    ] {
        let code = check(what, got, want);
        if code != exit::PASSED {
            return code;
        }
    }
    let policy_kind = match policy_path {
        Some(_) => POLICY_FILE.to_owned(),
        None => "default".to_owned(),
    };
    // The launcher's whole command: `run-now` re-checks the stored digests
    // on every fire, so the launcher itself carries no input bytes, no
    // paths into the bundle, and no endpoint — only the schedule's name.
    let exe = match std::env::current_exe() {
        Ok(e) => e.to_string_lossy().into_owned(),
        Err(e) => {
            note!(
                cx,
                "cannot determine this binary's path for the launcher: {e}"
            );
            return exit::INDETERMINATE;
        }
    };
    for (what, s) in [
        ("the binary path", exe.as_str()),
        ("--endpoint", endpoint),
        ("--workspace", workspace.as_str()),
        ("--state-root", state_root.as_str()),
    ] {
        if let Err(e) = no_control(what, s) {
            note!(cx, "{e}");
            return exit::UNREADABLE_INPUT;
        }
    }
    for p in [task_path, profile_path] {
        if let Err(e) = no_control("an input path", p) {
            note!(cx, "{e}");
            return exit::UNREADABLE_INPUT;
        }
    }
    let doc = ScheduleDoc {
        format: FORMAT.to_owned(),
        name: name.to_owned(),
        cadence: cadence.clone(),
        workspace: workspace.clone(),
        endpoint: endpoint.to_owned(),
        state_root: state_root.clone(),
        task_sha256: inp.digests.task.to_string(),
        profile_sha256: inp.digests.profile.to_string(),
        policy_sha256: inp.digests.policy.to_string(),
        policy: policy_kind,
        no_default_denies: o.contains_key("no-default-denies"),
        created: harness_journal::rfc3339_utc(now_ms()),
    };
    let doc_bytes = match serde_json::to_vec_pretty(&doc) {
        Ok(b) => b,
        Err(e) => {
            note!(cx, "cannot render {SCHEDULE_FILE}: {e}");
            return exit::INDETERMINATE;
        }
    };
    let files: Vec<(PathBuf, String)> = launcher_files(&launch_dir, name, &doc, &bundle);
    // Nothing is written until the answer: the exact files, printed where
    // they would go (§7.7: machine lines on stdout, the ask on stderr).
    for (p, content) in &files {
        say!(cx, "would install {}:", p.display());
        say!(cx, "{content}");
    }
    say!(
        cx,
        "would store the inputs in {}:",
        bundle.join(SCHEDULE_FILE).display()
    );
    say!(cx, "{}", String::from_utf8_lossy(&doc_bytes));
    note!(
        cx,
        "install this schedule? nothing is written until you answer y"
    );
    if !confirmed(cx) {
        note!(cx, "not installed");
        return exit::PASSED;
    }
    if let Err(e) = config::create_private_dir(&bundle) {
        note!(cx, "{e}");
        return exit::INDETERMINATE;
    }
    for (p, bytes) in [
        (bundle.join(TASK_FILE), &task_bytes),
        (bundle.join(PROFILE_FILE), &profile_bytes),
        (bundle.join(SCHEDULE_FILE), &doc_bytes),
    ] {
        if let Err(e) = write_private(&p, bytes) {
            note!(cx, "{e}");
            return exit::INDETERMINATE;
        }
    }
    if let Some(b) = &policy_bytes {
        if let Err(e) = write_private(&bundle.join(POLICY_FILE), b) {
            note!(cx, "{e}");
            return exit::INDETERMINATE;
        }
    }
    for (p, content) in &files {
        if let Some(parent) = p.parent() {
            if let Err(e) = config::create_private_dir(parent) {
                note!(cx, "{e}");
                return exit::INDETERMINATE;
            }
        }
        if let Err(e) = write_private(p, content.as_bytes()) {
            note!(cx, "{e}");
            return exit::INDETERMINATE;
        }
    }
    if cfg!(target_os = "macos") {
        let p = files
            .first()
            .map(|f| f.0.display().to_string())
            .unwrap_or_default();
        note!(
            cx,
            "installed. Nothing is loaded for you; to load it now:\n  launchctl load {p}"
        );
    } else {
        note!(
            cx,
            "installed. Nothing is loaded for you; to enable it now:\n  systemctl --user daemon-reload\n  systemctl --user enable --now rustyharness-{name}.timer"
        );
    }
    exit::PASSED
}

// ---- the launchers -----------------------------------------------------------------

/// The launcher files one schedule installs, with their rendered content:
/// the plist on macOS, the service + timer pair elsewhere on unix, in
/// [`launcher_paths`]' order.
fn launcher_files(
    dir: &Path,
    name: &str,
    doc: &ScheduleDoc,
    bundle: &Path,
) -> Vec<(PathBuf, String)> {
    let paths = launcher_paths(dir, name);
    if cfg!(target_os = "macos") {
        paths
            .into_iter()
            .map(|p| (p, render_plist(name, doc, bundle)))
            .collect()
    } else {
        let mut it = paths.into_iter();
        let service = it.next().map(|p| (p, render_service(name)));
        let timer = it.next().map(|p| (p, render_timer(name, doc)));
        [service, timer].into_iter().flatten().collect()
    }
}

/// The launchd plist: the run-now command, the schedule, and the log paths
/// inside the schedule's own (0700) directory.
fn render_plist(name: &str, doc: &ScheduleDoc, bundle: &Path) -> String {
    let label = format!("com.rustyharness.schedule.{name}");
    let argv = [
        std::env::current_exe()
            .map(|e| e.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "rustyharness".to_owned()),
        "schedule".to_owned(),
        "run-now".to_owned(),
        "--name".to_owned(),
        name.to_owned(),
    ];
    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    s.push_str("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ");
    s.push_str("\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
    s.push_str("<plist version=\"1.0\">\n");
    s.push_str("<dict>\n");
    s.push_str("  <key>Label</key>\n");
    s.push_str(&format!("  <string>{}</string>\n", xml_escape(&label)));
    s.push_str("  <key>ProgramArguments</key>\n");
    s.push_str("  <array>\n");
    for a in &argv {
        s.push_str(&format!("    <string>{}</string>\n", xml_escape(a)));
    }
    s.push_str("  </array>\n");
    s.push_str("  <key>StandardOutPath</key>\n");
    s.push_str(&format!(
        "  <string>{}</string>\n",
        xml_escape(&bundle.join("launchd.out.log").to_string_lossy())
    ));
    s.push_str("  <key>StandardErrorPath</key>\n");
    s.push_str(&format!(
        "  <string>{}</string>\n",
        xml_escape(&bundle.join("launchd.err.log").to_string_lossy())
    ));
    match &doc.cadence {
        Cadence::Daily { hh, mm } => {
            s.push_str("  <key>StartCalendarInterval</key>\n");
            s.push_str("  <dict>\n");
            s.push_str(&format!(
                "    <key>Hour</key>\n    <integer>{hh}</integer>\n"
            ));
            s.push_str(&format!(
                "    <key>Minute</key>\n    <integer>{mm}</integer>\n"
            ));
            s.push_str("  </dict>\n");
        }
        Cadence::EveryHours { hours } => {
            s.push_str("  <key>StartInterval</key>\n");
            s.push_str(&format!("  <integer>{}</integer>\n", hours * 3600));
        }
    }
    s.push_str("</dict>\n");
    s.push_str("</plist>\n");
    s
}

/// The systemd service: one `run-now` per fire.
fn render_service(name: &str) -> String {
    let argv = [
        std::env::current_exe()
            .map(|e| e.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "rustyharness".to_owned()),
        "schedule".to_owned(),
        "run-now".to_owned(),
        "--name".to_owned(),
        name.to_owned(),
    ];
    let exec = argv
        .iter()
        .map(|a| systemd_quote(a))
        .collect::<Vec<_>>()
        .join(" ");
    let mut s = String::new();
    s.push_str(&format!(
        "[Unit]\nDescription=rustyharness schedule {name} (unattended run)\n\n"
    ));
    s.push_str("[Service]\nType=oneshot\n");
    s.push_str(&format!("ExecStart={exec}\n"));
    s
}

/// The systemd timer paired with the service.
fn render_timer(name: &str, doc: &ScheduleDoc) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "[Unit]\nDescription=rustyharness schedule {name} (unattended run)\n\n"
    ));
    s.push_str("[Timer]\n");
    match &doc.cadence {
        Cadence::Daily { hh, mm } => {
            s.push_str(&format!("OnCalendar=*-*-* {hh:02}:{mm:02}:00\n"));
        }
        Cadence::EveryHours { hours } => {
            s.push_str(&format!("OnBootSec={hours}h\n"));
            s.push_str(&format!("OnUnitActiveSec={hours}h\n"));
        }
    }
    // The schedule is a steady heartbeat, not something to catch up on
    // after the machine was off (a run that starts unattended after days
    // away is a surprise, never a convenience).
    s.push_str("Persistent=false\n\n[Install]\nWantedBy=timers.target\n");
    s
}

// ---- list --------------------------------------------------------------------------

fn list(cx: &Cx<'_>, rest: &[&str]) -> u8 {
    let o = match options(rest, &["state-root"], &[]) {
        Ok(o) => o,
        Err(e) => {
            note!(cx, "{e}\n{USAGE}");
            return exit::USAGE;
        }
    };
    let cfg = match config::load() {
        Ok(c) => c,
        Err(e) => {
            note!(cx, "{e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    let state_root = match config::state_root(&o, &cfg) {
        Ok(Some(s)) => s.into_owned(),
        Ok(None) => {
            note!(
                cx,
                "--state-root is required here (no default state root on this platform)\n{USAGE}"
            );
            return exit::USAGE;
        }
        Err(e) => {
            note!(cx, "{e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    let schedules = Path::new(&state_root).join("schedules");
    let entries = match std::fs::read_dir(&schedules) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return exit::PASSED,
        Err(e) => {
            note!(cx, "cannot read {}: {e}", schedules.display());
            return exit::INDETERMINATE;
        }
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    names.sort();
    let now = now_ms();
    for name in &names {
        let dir = schedules.join(name);
        match load_doc(&dir) {
            Ok(doc) => {
                let installed = match launcher_dir() {
                    Ok(Some(d)) => launcher_paths(&d, name)
                        .iter()
                        .all(|p| p.symlink_metadata().is_ok()),
                    _ => false,
                };
                let next = match &doc.cadence {
                    Cadence::Daily { hh, mm } => {
                        harness_journal::rfc3339_utc(next_daily_utc(now, *hh, *mm))
                    }
                    // A steady interval has no "next" this binary can
                    // name: the OS counts from its own boot/last fire.
                    Cadence::EveryHours { .. } => "-".to_owned(),
                };
                say!(
                    cx,
                    "name={} cadence={} installed={} next={} workspace={} endpoint={}",
                    doc.name,
                    doc.cadence.text(),
                    if installed { "yes" } else { "no" },
                    next,
                    doc.workspace,
                    doc.endpoint
                );
            }
            Err(e) => say!(cx, "{} UNREADABLE ({e})", dir.display()),
        }
    }
    exit::PASSED
}

// ---- remove ------------------------------------------------------------------------

fn remove(cx: &Cx<'_>, rest: &[&str]) -> u8 {
    let o = match options(rest, &["name", "state-root"], &[]) {
        Ok(o) => o,
        Err(e) => {
            note!(cx, "{e}\n{USAGE}");
            return exit::USAGE;
        }
    };
    let cfg = match config::load() {
        Ok(c) => c,
        Err(e) => {
            note!(cx, "{e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    let Some(name) = o.get("name").copied() else {
        note!(cx, "--name is required\n{USAGE}");
        return exit::USAGE;
    };
    // The name is a path component here: anything but the strict spelling
    // is refused before it can name something else.
    if !valid_name(name) {
        note!(
            cx,
            "--name must be 1..=64 ASCII letters, digits, '-' or '_', starting with \
             a letter or digit"
        );
        return exit::USAGE;
    }
    let state_root = match config::state_root(&o, &cfg) {
        Ok(Some(s)) => s.into_owned(),
        Ok(None) => {
            note!(
                cx,
                "--state-root is required here (no default state root on this platform)\n{USAGE}"
            );
            return exit::USAGE;
        }
        Err(e) => {
            note!(cx, "{e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    let bundle = Path::new(&state_root).join("schedules").join(name);
    let launchers: Vec<PathBuf> = match launcher_dir() {
        Ok(Some(d)) => launcher_paths(&d, name),
        Ok(None) => Vec::new(),
        Err(e) => {
            note!(cx, "{e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    let present = |p: &Path| p.symlink_metadata().is_ok();
    let bundle_there = present(&bundle);
    let launchers_there: Vec<&PathBuf> = launchers.iter().filter(|p| present(p)).collect();
    if !bundle_there && launchers_there.is_empty() {
        note!(cx, "no schedule named {name}");
        return exit::UNREADABLE_INPUT;
    }
    say!(cx, "will remove schedule {name}:");
    if bundle_there {
        say!(cx, "  {}", bundle.display());
    }
    for p in &launchers_there {
        say!(cx, "  {}", p.display());
    }
    note!(
        cx,
        "remove this schedule? nothing is removed until you answer y"
    );
    if !confirmed(cx) {
        note!(cx, "not removed");
        return exit::PASSED;
    }
    for p in launchers_there {
        let m = match std::fs::symlink_metadata(p) {
            Ok(m) => m,
            Err(e) => {
                note!(cx, "cannot inspect {}: {e}", p.display());
                return exit::FAILED;
            }
        };
        if m.is_symlink() || !m.is_file() {
            note!(cx, "{} is not a plain file; nothing removed", p.display());
            return exit::FAILED;
        }
        if let Err(e) = std::fs::remove_file(p) {
            note!(cx, "cannot remove {}: {e}", p.display());
            return exit::FAILED;
        }
    }
    if bundle_there {
        let m = match std::fs::symlink_metadata(&bundle) {
            Ok(m) => m,
            Err(e) => {
                note!(cx, "cannot inspect {}: {e}", bundle.display());
                return exit::FAILED;
            }
        };
        if m.is_symlink() || !m.is_dir() {
            note!(
                cx,
                "{} is not a plain directory; nothing removed",
                bundle.display()
            );
            return exit::FAILED;
        }
        if let Err(e) = std::fs::remove_dir_all(&bundle) {
            note!(cx, "cannot remove {}: {e}", bundle.display());
            return exit::FAILED;
        }
    }
    note!(cx, "removed schedule {name}");
    exit::PASSED
}

// ---- run-now -----------------------------------------------------------------------

/// The gate child a launcher runs: re-check the stored schedule against
/// its digests, then run exactly as a timer would — unattended, every ask
/// a deny — and end with the `rustyharness.schedule` report.
fn run_now(cx: &Cx<'_>, rest: &[&str]) -> u8 {
    let gate = match GateId::new(GATE) {
        Ok(g) => g,
        // The constant is a valid gate id; this is fail-closed only.
        Err(_) => return exit::INDETERMINATE,
    };
    let short = |code: u8, msg: String| -> u8 {
        note!(cx, "{msg}");
        emit(cx, &gate, refused(code, msg))
    };
    let o = match options(rest, &["name", "state-root"], &[]) {
        Ok(o) => o,
        Err(e) => return short(exit::USAGE, format!("{e}\n{USAGE}")),
    };
    let cfg = match config::load() {
        Ok(c) => c,
        Err(e) => return short(exit::UNREADABLE_INPUT, e),
    };
    let Some(name) = o.get("name").copied() else {
        return short(exit::USAGE, "--name is required".to_owned());
    };
    if !valid_name(name) {
        return short(exit::USAGE, format!("{name:?} is not a schedule name"));
    }
    let state_root = match config::state_root(&o, &cfg) {
        Ok(Some(s)) => s.into_owned(),
        Ok(None) => {
            return short(
                exit::USAGE,
                "--state-root is required here (no default state root on this platform)".to_owned(),
            )
        }
        Err(e) => return short(exit::UNREADABLE_INPUT, e),
    };
    let bundle = Path::new(&state_root).join("schedules").join(name);
    if !bundle.is_dir() {
        return short(exit::UNREADABLE_INPUT, format!("no schedule named {name}"));
    }
    let doc = match load_doc(&bundle) {
        Ok(d) => d,
        Err(e) => return short(exit::UNREADABLE_INPUT, e),
    };
    // The self-check, before anything runs: the stored files must digest
    // to the values the schedule recorded (which are the values the
    // validation digested when `add` stored them).
    let overlay = !doc.no_default_denies;
    let task_bytes = match inputs::read_input(&bundle.join(TASK_FILE).to_string_lossy()) {
        Ok(b) => b,
        Err(e) => return short(exit::UNREADABLE_INPUT, e),
    };
    let profile_bytes = match inputs::read_input(&bundle.join(PROFILE_FILE).to_string_lossy()) {
        Ok(b) => b,
        Err(e) => return short(exit::UNREADABLE_INPUT, e),
    };
    let policy_bytes = match doc.policy.as_str() {
        POLICY_FILE => match inputs::read_input(&bundle.join(POLICY_FILE).to_string_lossy()) {
            Ok(b) => Some(b),
            Err(e) => return short(exit::UNREADABLE_INPUT, e),
        },
        "default" => None,
        other => {
            return short(
                exit::UNREADABLE_INPUT,
                format!("{SCHEDULE_FILE}: policy is {other:?}, not {POLICY_FILE:?} or \"default\""),
            )
        }
    };
    let parse = |what: &str, hex: &str| -> Result<harness_core::Digest, String> {
        hex.parse()
            .map_err(|_| format!("{SCHEDULE_FILE}: {what}_sha256 is not a sha256 in hex"))
    };
    let recorded = (
        parse("task", &doc.task_sha256),
        parse("profile", &doc.profile_sha256),
        parse("policy", &doc.policy_sha256),
    );
    let actual = (
        inputs::task_text(&task_bytes).map(|t| harness_core::sha256(t.as_bytes())),
        inputs::profile_digest(&profile_bytes),
        match &policy_bytes {
            // Stored the way the schedule recorded it (no overlays beyond
            // the deny default; see the `schedule` write above).
            Some(b) => inputs::policy_digest(b, overlay, false),
            None => inputs::default_policy(!overlay, false).map(|p| p.digest()),
        },
    );
    let (rt, rp, rl) = match recorded {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        _ => {
            return short(
                exit::UNREADABLE_INPUT,
                format!("{SCHEDULE_FILE} records a digest that is not a sha256 in hex"),
            )
        }
    };
    let (at_, ap, al) = match actual {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        (a, b, c) => {
            let e = a
                .err()
                .or(b.err())
                .or(c.err())
                .unwrap_or_else(|| "unreadable input".to_owned());
            return short(exit::UNREADABLE_INPUT, e);
        }
    };
    if (rt, rp, rl) != (at_, ap, al) {
        let why = "the stored inputs no longer digest to what the schedule recorded";
        return short(exit::UNREADABLE_INPUT, why.to_owned());
    }
    // The budget, again: `add` required it, so its absence now means the
    // stored task was replaced with one that digests differently — which
    // the check above refuses first; this is the belt to those braces.
    if inputs::task_budget(&task_bytes).ok().flatten().is_none() {
        return short(
            exit::UNREADABLE_INPUT,
            "the stored task sets no explicit budget".to_owned(),
        );
    }
    // Everything `run` would have been given, rebuilt from the schedule
    // and fed through the ordinary run pipeline, unattended.
    let task_path = bundle.join(TASK_FILE).to_string_lossy().into_owned();
    let profile_path = bundle.join(PROFILE_FILE).to_string_lossy().into_owned();
    let mut owned: BTreeMap<&str, String> = BTreeMap::new();
    owned.insert("task", task_path);
    owned.insert("profile", profile_path);
    if policy_bytes.is_some() {
        owned.insert(
            "policy",
            bundle.join(POLICY_FILE).to_string_lossy().into_owned(),
        );
    }
    owned.insert("workspace", doc.workspace.clone());
    owned.insert("state-root", doc.state_root.clone());
    owned.insert("endpoint", doc.endpoint.clone());
    if doc.no_default_denies {
        owned.insert("no-default-denies", "true".to_owned());
    }
    let view: BTreeMap<&str, &str> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let outcome = crate::cmd_run::run_or_resume_unattended(cx, &view, &cfg);
    emit(cx, &gate, outcome)
}

// ---- the pure pieces, tested in place ----------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daily_and_every_parse_their_spellings_and_refuse_others() {
        assert_eq!(parse_daily("23:45"), Ok((23, 45)));
        assert_eq!(parse_daily("00:00"), Ok((0, 0)));
        for bad in ["24:00", "12:60", "9:30", "0930", "12:30:00", "", "ab:cd"] {
            assert!(parse_daily(bad).is_err(), "{bad}");
        }
        assert_eq!(parse_every("6h"), Ok(6));
        assert_eq!(parse_every("168h"), Ok(168));
        for bad in ["0h", "169h", "6", "h", "-1h", ""] {
            assert!(parse_every(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn names_are_stricter_than_plain_names() {
        assert!(valid_name("nightly"));
        assert!(valid_name("a"));
        assert!(valid_name("N-9_x"));
        for bad in [
            "",
            ".hidden",
            "with.dot",
            "with+plus",
            "with space",
            "with/slash",
            &"a".repeat(65),
        ] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn the_next_daily_slot_is_the_utc_arithmetic_says() {
        // 2026-10-02T10:30:00Z is 3,552,600,000 ms past midnight UTC that
        // day (10 h 30 m) plus the day's own 86400000*20323 ms.
        let day = 20_323 * 86_400_000;
        let now = day + 10 * 3_600_000 + 30 * 60_000;
        // Later the same day: today at 23:45.
        assert_eq!(
            next_daily_utc(now, 23, 45),
            day + 23 * 3_600_000 + 45 * 60_000
        );
        // Earlier the same day: tomorrow at 07:15.
        assert_eq!(
            next_daily_utc(now, 7, 15),
            day + 86_400_000 + 7 * 3_600_000 + 15 * 60_000
        );
        // Exactly now is past: the next day's slot.
        assert_eq!(next_daily_utc(now, 10, 30), now + 86_400_000);
    }

    #[test]
    fn xml_and_systemd_quoting_escape_what_must_be_escaped() {
        assert_eq!(xml_escape("a&b<c>d"), "a&amp;b&lt;c&gt;d");
        assert_eq!(xml_escape("plain"), "plain");
        assert_eq!(systemd_quote("a b"), "\"a b\"");
        assert_eq!(systemd_quote("q\"x\\y$z"), "\"q\\\"x\\\\y$$z\"");
    }

    #[test]
    fn the_renderers_name_their_schedule_and_slot() {
        let doc = |cadence| ScheduleDoc {
            format: FORMAT.to_owned(),
            name: "nightly".to_owned(),
            cadence,
            workspace: "/tmp/w".to_owned(),
            endpoint: "http://127.0.0.1:1/v1".to_owned(),
            state_root: "/tmp/s".to_owned(),
            task_sha256: "0".repeat(64),
            profile_sha256: "0".repeat(64),
            policy_sha256: "0".repeat(64),
            policy: "default".to_owned(),
            no_default_denies: false,
            created: "2026-10-02T00:00:00.000Z".to_owned(),
        };
        let plist = render_plist(
            "nightly",
            &doc(Cadence::Daily { hh: 23, mm: 45 }),
            Path::new("/s/nightly"),
        );
        assert!(plist.contains("<key>Label</key>"), "{plist}");
        assert!(
            plist.contains("com.rustyharness.schedule.nightly"),
            "{plist}"
        );
        assert!(
            plist.contains("<key>StartCalendarInterval</key>"),
            "{plist}"
        );
        assert!(plist.contains("<integer>23</integer>"), "{plist}");
        assert!(plist.contains("<integer>45</integer>"), "{plist}");
        assert!(plist.contains("run-now"), "{plist}");
        assert!(plist.contains("/s/nightly/launchd.out.log"), "{plist}");
        assert!(plist.ends_with("</plist>\n"));
        let every = doc(Cadence::EveryHours { hours: 6 });
        let plist = render_plist("nightly", &every, Path::new("/s/nightly"));
        assert!(plist.contains("<key>StartInterval</key>"), "{plist}");
        assert!(plist.contains("<integer>21600</integer>"), "{plist}");
        let svc = render_service("nightly");
        assert!(svc.contains("[Service]"), "{svc}");
        assert!(svc.contains("Type=oneshot"), "{svc}");
        assert!(svc.contains("run-now"), "{svc}");
        let timer = render_timer("nightly", &every);
        assert!(timer.contains("OnBootSec=6h"), "{timer}");
        assert!(timer.contains("OnUnitActiveSec=6h"), "{timer}");
        assert!(timer.contains("Persistent=false"), "{timer}");
        let timer = render_timer("nightly", &doc(Cadence::Daily { hh: 7, mm: 5 }));
        assert!(timer.contains("OnCalendar=*-*-* 07:05:00"), "{timer}");
    }

    #[test]
    fn the_doc_round_trips_through_strict_json() {
        let doc = ScheduleDoc {
            format: FORMAT.to_owned(),
            name: "n".to_owned(),
            cadence: Cadence::EveryHours { hours: 3 },
            workspace: "/w".to_owned(),
            endpoint: "http://127.0.0.1:1/v1".to_owned(),
            state_root: "/s".to_owned(),
            task_sha256: "0".repeat(64),
            profile_sha256: "0".repeat(64),
            policy_sha256: "0".repeat(64),
            policy: POLICY_FILE.to_owned(),
            no_default_denies: true,
            created: "2026-10-02T00:00:00.000Z".to_owned(),
        };
        let bytes = serde_json::to_vec_pretty(&doc).unwrap();
        let v = harness_core::strict_json::parse(&bytes).unwrap();
        let back: ScheduleDoc = serde_json::from_value(v).unwrap();
        assert_eq!(back.cadence, Cadence::EveryHours { hours: 3 });
        assert!(back.no_default_denies);
        assert_eq!(back.policy, "policy.json");
    }
}
