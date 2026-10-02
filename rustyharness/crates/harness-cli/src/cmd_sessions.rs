//! The `sessions` verb (P-14, OD-5(d)): list the runs in a state root, or
//! show one, by scanning `runs/` with the verifying reader. Read-only, and
//! fail-closed in display too: a run whose journal does not verify is
//! listed as `UNREADABLE`, never skipped. Not a gate child: the last
//! stdout line is data, not a `GateReport`.

use harness_core::display::{sanitize_for_terminal_bounded, DisplayMode};
use harness_core::RunId;
use harness_journal::reader::Verified;
use harness_journal::{scan_runs, ScannedRun};

use crate::args::{options, USAGE};
use crate::bundle;
use crate::config;
use crate::report::exit;
use crate::Cx;

/// The task preview's length bound, then sanitised (never raw terminal
/// bytes from a task file).
const TASK_PREVIEW_BYTES: usize = 60;

enum Mode {
    List,
    Show,
}

pub(crate) fn sessions(cx: &Cx<'_>, rest: &[&str]) -> u8 {
    let (mode, rest) = match rest {
        ["show", rest @ ..] => (Mode::Show, rest),
        _ => (Mode::List, rest),
    };
    let o = match options(rest, &["state-root", "run"], &[]) {
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
    let scanned = match scan_runs(std::path::Path::new(&state_root)) {
        Ok(s) => s,
        Err(e) => {
            note!(cx, "cannot scan {}: {e}", state_root);
            return match e.kind() {
                std::io::ErrorKind::NotFound => exit::UNREADABLE_INPUT,
                _ => exit::INDETERMINATE,
            };
        }
    };
    let show = match mode {
        Mode::Show => match o.get("run") {
            Some(id) => match RunId::parse(id) {
                Some(r) => Some(r),
                None => {
                    note!(cx, "--run is not a run id");
                    return exit::USAGE;
                }
            },
            None => {
                note!(cx, "sessions show needs --run <run-id>\n{USAGE}");
                return exit::USAGE;
            }
        },
        Mode::List => match o.get("run") {
            Some(id) => match RunId::parse(id) {
                Some(r) => Some(r),
                None => {
                    note!(cx, "--run is not a run id");
                    return exit::USAGE;
                }
            },
            None => None,
        },
    };
    let mut rows: Vec<SessionRow> = scanned.iter().map(row_of).collect();
    // Newest first; the unreadable (no start time known) go last.
    rows.sort_by(|a, b| {
        b.start
            .as_deref()
            .unwrap_or("")
            .cmp(a.start.as_deref().unwrap_or(""))
            .then_with(|| a.run.as_str().cmp(b.run.as_str()))
    });
    match show {
        Some(run) => match rows.iter().find(|r| r.run == run) {
            Some(r) => {
                detail(cx, &state_root, r);
                say!(cx, "{}", line_of(&state_root, r));
                exit::PASSED
            }
            None => {
                note!(cx, "no run {run} in {}", state_root);
                exit::UNREADABLE_INPUT
            }
        },
        None => {
            note!(cx, "{} run(s) in {}", rows.len(), state_root);
            for r in &rows {
                say!(cx, "{}", line_of(&state_root, r));
            }
            exit::PASSED
        }
    }
}

/// What a scan found about one run, ready to display.
pub(crate) struct SessionRow {
    pub(crate) run: RunId,
    /// The `RunStarted` wall clock (the run's start time).
    pub(crate) start: Option<String>,
    pub(crate) steps: Option<u64>,
    /// The stop cause and outcome of a committed run.
    pub(crate) stop: Option<(String, String)>,
    pub(crate) head: Option<String>,
    /// Why the journal could not be read, when it could not.
    pub(crate) unreadable: Option<String>,
}

pub(crate) fn row_of(s: &ScannedRun) -> SessionRow {
    let run = s.run.clone();
    match &s.journal {
        Err(e) => SessionRow {
            run,
            start: None,
            steps: None,
            stop: None,
            head: None,
            unreadable: Some(e.to_string()),
        },
        Ok(v) => SessionRow {
            run,
            start: v.records.first().map(|r| r.t_wall.clone()),
            steps: v.records.iter().map(|r| r.step).max(),
            stop: committed_of(v),
            head: Some(v.head.to_string()),
            unreadable: None,
        },
    }
}

/// A committed run's `(stop cause, outcome)` from its `RunStopped` body.
fn committed_of(v: &Verified) -> Option<(String, String)> {
    let last = v.records.last()?;
    if last.kind != harness_journal::EventKind::RunStopped || v.torn_tail.is_some() {
        return None;
    }
    let text = |k: &str| {
        last.body
            .get(k)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-")
            .to_owned()
    };
    Some((text("cause"), text("outcome")))
}

/// One line per run, task last and quoted.
fn line_of(state_root: &str, r: &SessionRow) -> String {
    if let Some(why) = &r.unreadable {
        return format!("{} UNREADABLE ({why})", r.run);
    }
    let inputs =
        harness_journal::layout::run_dir(std::path::Path::new(state_root), &r.run).join("inputs");
    let workspace = bundle::recorded_workspace(&inputs).unwrap_or_else(|| "-".to_owned());
    let task = match bundle::recorded_task_text(&inputs) {
        Some(t) => sanitize_for_terminal_bounded(&t, DisplayMode::Line, TASK_PREVIEW_BYTES),
        None => "-".to_owned(),
    };
    let (stop, outcome) = match &r.stop {
        Some((c, o)) => (c.clone(), o.clone()),
        None => ("-".to_owned(), "-".to_owned()),
    };
    format!(
        "{} {} steps={} stop={} outcome={} head={} workspace={} task=\"{task}\"",
        r.run,
        r.start.as_deref().unwrap_or("-"),
        r.steps.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
        stop,
        outcome,
        r.head.as_deref().unwrap_or("-"),
        workspace,
    )
}

/// `sessions show`'s extra words, on stderr.
fn detail(cx: &Cx<'_>, state_root: &str, r: &SessionRow) {
    let run_dir = harness_journal::layout::run_dir(std::path::Path::new(state_root), &r.run);
    let attempts = std::fs::read_dir(&run_dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    harness_journal::layout::parse_attempt_name(e.file_name().to_str()?)
                })
                .count()
        })
        .unwrap_or(0);
    match &r.unreadable {
        Some(why) => note!(cx, "run {}: journal unreadable: {why}", r.run),
        None => match &r.stop {
            Some(_) => note!(cx, "run {}: committed, {attempts} attempt(s)", r.run),
            None => note!(
                cx,
                "run {}: not committed (the latest attempt has not stopped), {attempts} attempt(s)",
                r.run
            ),
        },
    }
}
