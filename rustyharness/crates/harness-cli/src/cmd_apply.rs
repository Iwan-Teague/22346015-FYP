//! The `apply` verb (P-52): copy a scratch session's edits back onto the
//! original workspace, only ever after showing the diff and reading a
//! typed `apply`, and only onto originals that still digest to what the
//! copy was made from. A changed original is a conflict, reported and
//! skipped, never overwritten.
//!
//! Everything the verb decides on is bound to the run's journal: the
//! latest attempt's header records the copy manifest's digest and the
//! per-file digests (P-52), and `runs/<id>/workspace-manifest.json` must
//! digest to exactly that. A session that has not committed is refused —
//! apply works on ended runs; inside a live chat, `/apply` does it in
//! process.
//!
//! Exits: 0 applied, created, or a dry run; 1 nothing applied (the typed
//! confirmation was not `apply`, or every change was a conflict); 2 usage;
//! 4 unreadable (the run, its journal, its manifest or its mode); 5 the
//! apply report could not be written (the apply itself already happened).

use std::path::{Path, PathBuf};

use harness_core::{sha256, RunId};
use harness_journal::layout;

use crate::args::{options, USAGE};
use crate::report::exit;
use crate::workspace_mode::{
    apply_planned, plan_apply, record_from_header, summary, ManifestDoc, ManifestFile,
    MANIFEST_FORMAT,
};
use crate::Cx;

/// The apply report's format tag.
const REPORT_FORMAT: &str = "rh-apply/1";

pub(crate) fn apply(cx: &Cx<'_>, rest: &[&str]) -> u8 {
    match try_apply(cx, rest) {
        Ok(code) => code,
        Err((code, why)) => {
            note!(cx, "{why}");
            if code == exit::USAGE {
                note!(cx, "{USAGE}");
            }
            code
        }
    }
}

fn try_apply(cx: &Cx<'_>, rest: &[&str]) -> Result<u8, (u8, String)> {
    let o =
        options(rest, &["session", "state-root"], &["dry-run"]).map_err(|e| (exit::USAGE, e))?;
    let dry_run = o.contains_key("dry-run");
    let session = match o.get("session") {
        Some(s) => {
            RunId::parse(s).ok_or((exit::USAGE, format!("--session is not a run id: {s}")))?
        }
        None => return Err((exit::USAGE, "--session is required".into())),
    };
    let state_root = match crate::config::state_root(&o, &None) {
        Ok(Some(s)) => s.into_owned(),
        Ok(None) => return Err((exit::USAGE, "--state-root is required here".into())),
        Err(e) => return Err((exit::UNREADABLE_INPUT, e)),
    };
    let state = Path::new(&state_root);
    let run_dir = layout::run_dir(state, &session);
    if !run_dir.is_dir() {
        return Err((
            exit::UNREADABLE_INPUT,
            format!("no run {} in {state_root}", session),
        ));
    }
    let n = layout::latest_attempt(&run_dir)
        .map_err(|e| (exit::UNREADABLE_INPUT, format!("cannot list attempts: {e}")))?
        .ok_or((
            exit::UNREADABLE_INPUT,
            "no attempt in the run directory".to_owned(),
        ))?;
    let v =
        harness_journal::JournalReader::open(&layout::attempt_dir(&run_dir, n)).map_err(|e| {
            (
                exit::UNREADABLE_INPUT,
                format!("cannot read the attempt journal: {e}"),
            )
        })?;
    let committed = v
        .records
        .last()
        .is_some_and(|r| r.kind == harness_journal::EventKind::RunStopped)
        && v.torn_tail.is_none();
    if !committed {
        return Err((
            exit::UNREADABLE_INPUT,
            format!("run {session} has not committed its latest attempt; use /apply in its chat"),
        ));
    }
    let header = v.records.first().ok_or((
        exit::UNREADABLE_INPUT,
        "the journal has no header".to_owned(),
    ))?;
    let (manifest_digest, header_files) = header
        .body
        .get("workspace_mode")
        .and_then(record_from_header)
        .ok_or((
            exit::UNREADABLE_INPUT,
            format!("run {session} is not a scratch run (no workspace-mode record in its header)"),
        ))?;
    // The manifest the run published, bound to the header by digest.
    let manifest_path = run_dir.join("workspace-manifest.json");
    let bytes = std::fs::read(&manifest_path).map_err(|e| {
        (
            exit::UNREADABLE_INPUT,
            format!(
                "cannot read {}: {e} (apply needs the manifest the run published)",
                manifest_path.display()
            ),
        )
    })?;
    if sha256(&bytes) != manifest_digest {
        return Err((
            exit::UNREADABLE_INPUT,
            "the run's workspace manifest does not digest to the journal header's record".into(),
        ));
    }
    let bad = |e: String| (exit::UNREADABLE_INPUT, format!("workspace manifest: {e}"));
    let value = harness_core::strict_json::parse(&bytes)
        .map_err(|e| bad(format!("not strict JSON: {e}")))?;
    let doc: ManifestDoc = serde_json::from_value(value).map_err(|e| bad(e.to_string()))?;
    if doc.format != MANIFEST_FORMAT {
        return Err(bad(format!("format is {:?}", doc.format)));
    }
    if doc.files.len() != header_files.len() {
        return Err(bad(
            "the manifest's file list does not match the header's record".to_owned(),
        ));
    }
    for (f, d) in doc.files.iter().zip(&header_files) {
        let parsed: harness_core::Digest = f
            .sha256
            .parse()
            .map_err(|_| bad(format!("{}: sha256 is not a digest", f.path)))?;
        if &parsed != d {
            return Err(bad(format!(
                "{} digests to {}, not the header's {d}",
                f.path, f.sha256
            )));
        }
    }
    if !Path::new(&doc.copy).is_dir() {
        return Err((
            exit::UNREADABLE_INPUT,
            format!(
                "the scratch copy {} is gone; its edits cannot be applied",
                doc.copy
            ),
        ));
    }
    let source = PathBuf::from(&doc.source);
    let copy = PathBuf::from(&doc.copy);
    let mut result = plan_apply(&source, &copy, &doc.files);
    say!(cx, "{}", render_plan(&session, &result));
    if dry_run {
        note!(cx, "--dry-run: nothing written, no report");
        return Ok(exit::PASSED);
    }
    if !result.any_change() && result.conflicts.is_empty() && result.skipped_deletions.is_empty() {
        note!(
            cx,
            "nothing to apply: the original already matches the copy"
        );
        return Ok(exit::PASSED);
    }
    // The typed confirmation: exactly `apply`.
    note!(
        cx,
        "type `apply` to write these changes to {}, anything else declines",
        source.display()
    );
    if read_confirm(cx).as_deref() != Some(crate::workspace_mode::CONFIRM_WORD) {
        note!(cx, "nothing applied (the confirmation was not `apply`)");
        return Ok(1);
    }
    apply_planned(&source, &copy, &mut result)
        .map_err(|e| (exit::INDETERMINATE, format!("the apply failed: {e}")))?;
    note!(cx, "{}", summary(&result));
    write_report(cx, state, &session, &source, &copy, &result)?;
    if result.any_change() {
        Ok(exit::PASSED)
    } else {
        // Every change was a conflict or a skipped deletion.
        Ok(1)
    }
}

/// The plan as stdout text: the header line, the diff, then the lists.
fn render_plan(session: &RunId, r: &crate::workspace_mode::ApplyResult) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = write!(s, "apply plan for run {session}:");
    if !r.conflicts.is_empty() {
        let _ = write!(s, " {} conflict(s),", r.conflicts.len());
    }
    let _ = writeln!(
        s,
        " {} file(s) to write, {} to create",
        r.applied.len(),
        r.created.len()
    );
    s.push_str(&r.plan);
    for c in &r.conflicts {
        let _ = writeln!(s, "! conflict (left untouched): {c}");
    }
    for d in &r.skipped_deletions {
        let _ = writeln!(s, "! deleted in the scratch copy, original kept: {d}");
    }
    s
}

/// One line from the verb's input source: stdin at a terminal, the
/// injected lines in tests. Only the first line is ever read.
fn read_confirm(cx: &Cx<'_>) -> Option<String> {
    match &cx.input {
        crate::InputSource::Stdin => {
            let mut line = String::new();
            use std::io::BufRead;
            match std::io::stdin().lock().read_line(&mut line) {
                Ok(0) => None,
                Ok(_) => Some(line),
                Err(_) => None,
            }
        }
        crate::InputSource::Given(lines) => lines.first().cloned(),
    }
}

/// The apply report: `runs/<id>/apply/apply-<utc>.json` (0600). The apply
/// has already happened, so a failure here is exit 5 and a note, never a
/// half-report passed off as a full one.
fn write_report(
    cx: &Cx<'_>,
    state: &Path,
    session: &RunId,
    source: &Path,
    copy: &Path,
    r: &crate::workspace_mode::ApplyResult,
) -> Result<(), (u8, String)> {
    let file = |list: &[ManifestFile]| -> Vec<serde_json::Value> {
        list.iter()
            .map(|f| {
                serde_json::json!({
                    "path": f.path,
                    "sha256": f.sha256,
                    "bytes": f.bytes,
                })
            })
            .collect()
    };
    let doc = serde_json::json!({
        "format": REPORT_FORMAT,
        "run": session.to_string(),
        "source": source.display().to_string(),
        "copy": copy.display().to_string(),
        "applied": file(&r.applied),
        "created": file(&r.created),
        "conflicts": r.conflicts,
        "skipped_deletions": r.skipped_deletions,
    });
    let dir = layout::run_dir(state, session).join("apply");
    let name = format!("apply-{}.json", crate::workspace_mode::stamp());
    let path = dir.join(name);
    let bytes = serde_json::to_vec_pretty(&doc).map_err(|e| {
        (
            exit::INDETERMINATE,
            format!("cannot render the report: {e}"),
        )
    })?;
    if let Err(e) = (|| -> std::io::Result<()> {
        std::fs::create_dir_all(&dir)?;
        std::fs::write(&path, bytes)?;
        Ok(())
    })() {
        return Err((
            exit::INDETERMINATE,
            format!("cannot write {}: {e}", path.display()),
        ));
    }
    note!(cx, "apply report: {}", path.display());
    Ok(())
}
