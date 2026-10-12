//! The `notes` verb (P-39l, design §6): list, show, verify and rebuild
//! the quarantined research notes under `<state-root>/research/notes/`.
//! `list` and `show` and `verify` are read-only; `rebuild` writes only
//! the notes a verified journal says were saved and the disk does not
//! hold (a note is immutable — an existing id is never rewritten). Every
//! untrusted string is sanitised on the way out. Not a gate child: the
//! last stdout line is data, not a `GateReport`.

use std::str::FromStr;

use harness_core::display::{sanitize_for_terminal, sanitize_for_terminal_bounded, DisplayMode};
use harness_core::{Digest, RunId};
use harness_journal::layout;
use harness_journal::reader::DirBlobSource;
use harness_run::research;

use crate::args::{options, USAGE};
use crate::config;
use crate::report::exit;
use crate::Cx;

/// The show rendering's bound, then sanitised (never raw file bytes).
const SHOW_BYTES: usize = 8192;

enum Mode {
    List,
    Show(String),
    Verify(String),
    Rebuild,
}

pub(crate) fn notes(cx: &Cx<'_>, rest: &[&str]) -> u8 {
    let (mode, rest) = match rest {
        ["list", rest @ ..] => (Mode::List, rest),
        ["show", id, rest @ ..] => (Mode::Show((*id).to_owned()), rest),
        ["verify", id, rest @ ..] => (Mode::Verify((*id).to_owned()), rest),
        ["rebuild", rest @ ..] => (Mode::Rebuild, rest),
        _ => {
            note!(cx, "notes needs list | show | verify | rebuild\n{USAGE}");
            return exit::USAGE;
        }
    };
    let o = match options(rest, &["state-root", "run", "anchor"], &[]) {
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
    // `--run` filters the list and names the rebuild's run: a run id, or
    // nothing.
    let run_filter = match o.get("run") {
        Some(id) => match RunId::parse(id) {
            Some(r) => Some(r),
            None => {
                note!(cx, "--run is not a run id");
                return exit::USAGE;
            }
        },
        None => None,
    };
    let root = std::path::Path::new(&state_root);
    match mode {
        Mode::List => list(cx, root, run_filter.as_ref()),
        Mode::Show(id) => show(cx, root, &id),
        Mode::Verify(id) => verify(cx, root, &id, o.get("anchor").copied()),
        Mode::Rebuild => match run_filter {
            Some(run) => rebuild(cx, root, &run),
            None => {
                note!(cx, "notes rebuild needs --run <run-id>\n{USAGE}");
                exit::USAGE
            }
        },
    }
}

/// `notes list`: what the notes directory holds, then what the runs'
/// journals say should be there and is not. A journal that does not
/// verify claims nothing (fail closed, like `sessions`).
fn list(cx: &Cx<'_>, state_root: &std::path::Path, run: Option<&RunId>) -> u8 {
    let mut rows = match research::scan_note_dirs(state_root) {
        Ok(r) => r,
        Err(e) => {
            note!(cx, "cannot read the notes directory: {e}");
            return exit::INDETERMINATE;
        }
    };
    if let Some(run) = run {
        let run = run.to_string();
        rows.retain(|r| r.run.as_deref() == Some(run.as_str()));
    }
    let missing = match research::missing_notes(state_root) {
        Ok(m) => m,
        Err(e) => {
            note!(cx, "cannot scan the runs: {e}");
            return exit::INDETERMINATE;
        }
    };
    note!(
        cx,
        "{} note(s) under {}",
        rows.len(),
        layout::research_notes_dir(state_root).display()
    );
    for r in &rows {
        let state = if r.intact { "ok" } else { "TAMPERED" };
        say!(
            cx,
            "{}  run {} turn {} sources {} [{}]",
            r.id,
            r.run.as_deref().unwrap_or("-"),
            r.turn.map_or("-".to_owned(), |t| t.to_string()),
            r.sources.map_or("-".to_owned(), |s| s.to_string()),
            state,
        );
    }
    let mut shown_missing = 0;
    for m in &missing {
        if let Some(run) = run {
            if m.run != run.to_string() {
                continue;
            }
        }
        say!(
            cx,
            "{}  MISSING (saved by run {} attempt {}, turn {})",
            m.id,
            m.run,
            m.attempt,
            m.turn,
        );
        shown_missing += 1;
    }
    if shown_missing > 0 {
        note!(
            cx,
            "{shown_missing} note(s) missing; `notes rebuild --run <run-id>` recreates them"
        );
    }
    exit::PASSED
}

/// `notes show <note-id>`: the sanitised `note.md` rendering (the file is
/// sanitised at write time too; a tampered file is shown inert, never
/// raw).
fn show(cx: &Cx<'_>, state_root: &std::path::Path, id: &str) -> u8 {
    if let Err(e) = check_id(id) {
        note!(cx, "{e}\n{USAGE}");
        return exit::USAGE;
    }
    let path = layout::research_notes_dir(state_root)
        .join(id)
        .join("note.md");
    let md = match std::fs::read_to_string(&path) {
        Ok(m) => m,
        Err(e) => {
            note!(cx, "cannot read {}: {e}", path.display());
            return exit::UNREADABLE_INPUT;
        }
    };
    say!(
        cx,
        "{}",
        sanitize_for_terminal_bounded(&md, DisplayMode::Block, SHOW_BYTES)
    );
    exit::PASSED
}

/// `notes verify <note-id> [--anchor <sha256>]`: the note hashes to its
/// id, the run's journal chain verifies (and anchors), a `NoteSaved`
/// record names the id, and the bytes are the journal's deterministic
/// rebuild. Exit 0 verified, 1 not (with the failing part named).
fn verify(cx: &Cx<'_>, state_root: &std::path::Path, id: &str, anchor: Option<&str>) -> u8 {
    if let Err(e) = check_id(id) {
        note!(cx, "{e}\n{USAGE}");
        return exit::USAGE;
    }
    let anchor = match anchor {
        Some(a) => match Digest::from_str(a) {
            Ok(d) => Some(d),
            Err(e) => {
                note!(cx, "--anchor: {e}");
                return exit::USAGE;
            }
        },
        None => None,
    };
    let dir = layout::research_notes_dir(state_root).join(id);
    let json = match std::fs::read(dir.join("note.json")) {
        Ok(j) => j,
        Err(e) => {
            note!(cx, "cannot read {}: {e}", dir.join("note.json").display());
            return exit::UNREADABLE_INPUT;
        }
    };
    // Which run and attempt saved it: from the document, so a verifier
    // needs only the note and the state root.
    let doc = match serde_json::from_slice::<serde_json::Value>(&json) {
        Ok(d) => d,
        Err(e) => {
            note!(cx, "note.json does not parse: {e}");
            return exit::FAILED;
        }
    };
    let (run, attempt) = match (
        doc.get("run").and_then(serde_json::Value::as_str),
        doc.get("attempt").and_then(serde_json::Value::as_u64),
    ) {
        (Some(r), Some(a)) => (r.to_owned(), a),
        _ => {
            note!(cx, "note.json does not name its run and attempt");
            return exit::FAILED;
        }
    };
    let run_id = match RunId::parse(&run) {
        Some(r) => r,
        None => {
            note!(
                cx,
                "note.json names a run id that is not a run id: {}",
                sanitize_for_terminal(&run, DisplayMode::Line)
            );
            return exit::FAILED;
        }
    };
    let attempt_dir = layout::attempt_dir(
        &layout::run_dir(state_root, &run_id),
        u32::try_from(attempt).unwrap_or(u32::MAX),
    );
    let journal_bytes = match std::fs::read(attempt_dir.join(layout::JOURNAL_FILE)) {
        Ok(b) => b,
        Err(e) => {
            note!(
                cx,
                "cannot read the run's journal {}: {e}",
                attempt_dir.join(layout::JOURNAL_FILE).display()
            );
            return exit::UNREADABLE_INPUT;
        }
    };
    let blobs = DirBlobSource::new(attempt_dir.join(layout::BLOBS_DIR));
    match research::verify_note(&json, id, &journal_bytes, &blobs, anchor.as_ref()) {
        Ok(()) => {
            say!(cx, "verified {id} (run {run} attempt {attempt})");
            exit::PASSED
        }
        Err(why) => {
            note!(cx, "NOT VERIFIED {id}: {why}");
            exit::FAILED
        }
    }
}

/// `notes rebuild --run <run-id>`: recreate the run's missing notes from
/// its journals, newest attempt first. Present ids are never rewritten.
fn rebuild(cx: &Cx<'_>, state_root: &std::path::Path, run: &RunId) -> u8 {
    match research::rebuild_run(state_root, run) {
        Ok((rebuilt, present)) => {
            say!(
                cx,
                "rebuilt {} note(s), {} already present (run {})",
                rebuilt.len(),
                present.len(),
                run
            );
            for id in &rebuilt {
                say!(cx, "rebuilt {id}");
            }
            exit::PASSED
        }
        Err(why) => {
            note!(cx, "cannot rebuild run {run}: {why}");
            exit::UNREADABLE_INPUT
        }
    }
}

/// A note id is a note id: 64 lowercase hex characters, so the directory
/// join can never be talked out of the notes directory (NF-3).
fn check_id(id: &str) -> Result<(), String> {
    let ok = id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if ok {
        Ok(())
    } else {
        Err("note-id must be 64 hex characters".to_owned())
    }
}
