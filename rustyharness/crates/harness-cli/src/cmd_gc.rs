//! The `gc` verb (P-14): remove a finished run's bulk — its `workspace/`,
//! `grading/` and `scratch/` — and nothing else. The journal, the blobs,
//! the snapshots and `inputs/` are never touched, and a run whose latest
//! attempt has not committed (it may still be active: the single-writer
//! journal has no lock to check) or does not verify is refused, never
//! cleaned. Not a gate child.

use std::path::Path;

use harness_core::RunId;
use harness_journal::{layout, scan_runs, ScannedRun};

use crate::args::{options, USAGE};
use crate::cmd_sessions::row_of;
use crate::config;
use crate::report::exit;
use crate::Cx;

/// The only directories `gc` may remove, inside `runs/<id>/`.
const REMOVABLE: [&str; 3] = ["workspace", "grading", "scratch"];

pub(crate) fn gc(cx: &Cx<'_>, rest: &[&str]) -> u8 {
    enum Selector {
        One(RunId),
        Older(u64),
    }
    let o = match options(rest, &["state-root", "run", "older-than"], &[]) {
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
    let selector = match (o.get("run"), o.get("older-than")) {
        (Some(_), Some(_)) | (None, None) => {
            note!(
                cx,
                "gc needs exactly one of --run <run-id> or --older-than <N>d\n{USAGE}"
            );
            return exit::USAGE;
        }
        (Some(id), None) => match RunId::parse(id) {
            Some(r) => Selector::One(r),
            None => {
                note!(cx, "--run is not a run id");
                return exit::USAGE;
            }
        },
        (None, Some(d)) => match older_than(d) {
            Ok(days) => Selector::Older(days),
            Err(e) => {
                note!(cx, "{e}\n{USAGE}");
                return exit::USAGE;
            }
        },
    };
    let scanned = match scan_runs(Path::new(&state_root)) {
        Ok(s) => s,
        Err(e) => {
            note!(cx, "cannot scan {}: {e}", state_root);
            return match e.kind() {
                std::io::ErrorKind::NotFound => exit::UNREADABLE_INPUT,
                _ => exit::INDETERMINATE,
            };
        }
    };
    if let Selector::One(run) = &selector {
        if !scanned.iter().any(|s| &s.run == run) {
            note!(cx, "no run {run} in {}", state_root);
            return exit::UNREADABLE_INPUT;
        }
    }
    let cutoff = match &selector {
        Selector::One(_) => None,
        Selector::Older(days) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            Some(harness_journal::rfc3339_utc(
                now.saturating_sub(days * 24 * 60 * 60 * 1000),
            ))
        }
    };
    let mut removed = 0usize;
    let mut kept = 0usize;
    for s in &scanned {
        match (&selector, cutoff.as_deref(), start_of(s).as_deref()) {
            (Selector::One(run), _, _) if &s.run != run => continue,
            (Selector::Older(_), Some(cutoff), Some(start)) if start >= cutoff => continue,
            (Selector::Older(_), Some(_), None) => continue,
            _ => {}
        }
        match sweep(&state_root, s) {
            Ok(true) => removed += 1,
            Ok(false) => {}
            Err(why) => {
                note!(cx, "gc left run {} in place: {why}", s.run);
                kept += 1;
                if matches!(selector, Selector::One(_)) {
                    return exit::FAILED;
                }
            }
        }
    }
    match selector {
        Selector::One(run) => {
            if removed == 1 {
                note!(cx, "gc: removed the bulk of run {run}");
            } else {
                note!(cx, "gc: nothing to remove for run {run} (already clean)");
            }
            exit::PASSED
        }
        Selector::Older(_) => {
            note!(
                cx,
                "gc: cleaned {removed} run(s), {kept} left in place, {} scanned",
                scanned.len()
            );
            exit::PASSED
        }
    }
}

/// `--older-than <N>d`: a positive whole number of days.
fn older_than(d: &str) -> Result<u64, String> {
    let n = d
        .strip_suffix('d')
        .and_then(|n| n.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .ok_or_else(|| "--older-than is not a positive number of days (e.g. 30d)".to_owned())?;
    // The cutoff arithmetic must not overflow either.
    n.checked_mul(24 * 60 * 60 * 1000)
        .ok_or_else(|| "--older-than is too large".to_owned())?;
    Ok(n)
}

/// A scanned run's start time, if its journal says one.
fn start_of(s: &ScannedRun) -> Option<String> {
    row_of(s).start
}

/// Remove only the bulk of one run. `Ok(true)` when something was removed,
/// `Ok(false)` when there was nothing to remove (idempotent), `Err(why)`
/// when the run is refused: not committed (possibly active), unreadable,
/// or a removable name that is not a plain directory.
fn sweep(state_root: &str, s: &ScannedRun) -> Result<bool, String> {
    let row = row_of(s);
    if let Some(why) = &row.unreadable {
        return Err(format!("journal unreadable: {why}"));
    }
    if row.stop.is_none() {
        return Err("the latest attempt has not committed; the run may still be active".to_owned());
    }
    let run_dir = layout::run_dir(Path::new(state_root), &s.run);
    let mut any = false;
    for name in REMOVABLE {
        let path = run_dir.join(name);
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("cannot inspect {}: {e}", path.display())),
            Ok(m) => {
                if m.file_type().is_symlink() || !m.is_dir() {
                    return Err(format!(
                        "{} is not a plain directory; nothing removed",
                        path.display()
                    ));
                }
                std::fs::remove_dir_all(&path)
                    .map_err(|e| format!("cannot remove {}: {e}", path.display()))?;
                any = true;
            }
        }
    }
    Ok(any)
}
