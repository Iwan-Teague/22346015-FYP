//! The `events` verb (slice P-15): one attempt's journal as newline-delimited
//! JSON on stdout (not a gate child: plain exit codes, human lines on
//! stderr).
//!
//! The first stdout line is a schema marker, `{"schema":"rh-events/1"}`;
//! then one line per journal record, byte-for-byte the journal's own
//! canonical line (the reader only accepts canonical bytes, so the
//! projection re-encodes them exactly — a consumer can re-verify the hash
//! chain straight off this stream). Untrusted payloads appear in their
//! journal payload home: small ones (<= 4 KiB) inline and escaped (the
//! journal's own sanitisation: control, zero-width and bidi characters
//! neutralised), larger ones as a `blobs/<sha256>` reference with the
//! digest; this verb adds nothing and hides nothing.
//!
//! `--follow` keeps polling the journal (a whole-file re-read and
//! re-verify per poll, the same verifier) until the run commits
//! (`RunStopped` durable), so a torn final line is never shown: a record
//! appears only once it verifies. Any break — an edited journal, a
//! shrunken one — ends the tail with exit 4 (fail-closed), like every
//! unreadable journal.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use harness_core::RunId;
use harness_journal::layout;
use harness_journal::{JournalReader, JournalTail};

use crate::args::{options_with_flags, USAGE};
use crate::report::exit;
use crate::Cx;

/// The stream's schema marker, the first stdout line of every events
/// stream (`events`, and `run --output stream-json`).
pub(crate) const SCHEMA_LINE: &str = r#"{"schema":"rh-events/1"}"#;

/// How long `--follow` waits between polls.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// `events`: project an attempt's journal to stdout. Exit 0 records shown,
/// 2 usage, 4 the run or its journal cannot be read.
pub(crate) fn events(cx: &Cx<'_>, rest: &[&str]) -> u8 {
    // The user's config (P-07) applies here too: it may carry the state
    // root. Unreadable config is unreadable input, as for a gate child.
    let cfg = match crate::config::load() {
        Ok(c) => c,
        Err(e) => {
            note!(cx, "{e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    let parsed = match options_with_flags(rest, &["run", "state-root", "format"], &["follow"]) {
        Ok(p) => p,
        Err(e) => {
            note!(cx, "{e}\n{USAGE}");
            return exit::USAGE;
        }
    };
    let o: &BTreeMap<&str, &str> = &parsed.opts;
    let Some(run_text) = o.get("run").copied() else {
        note!(cx, "--run is required\n{USAGE}");
        return exit::USAGE;
    };
    let Some(run) = RunId::parse(run_text) else {
        note!(cx, "--run is not a run id\n{USAGE}");
        return exit::USAGE;
    };
    if let Some(f) = o.get("format") {
        if *f != "ndjson" {
            note!(cx, "--format must be ndjson (the only format)\n{USAGE}");
            return exit::USAGE;
        }
    }
    let state_root = match crate::config::state_root(o, &cfg) {
        Ok(Some(s)) => s,
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
    let run_dir = layout::run_dir(Path::new(state_root.as_ref()), &run);
    let attempt_dir = match layout::latest_attempt(&run_dir) {
        Ok(Some(n)) => layout::attempt_dir(&run_dir, n),
        Ok(None) => {
            note!(cx, "no run {run} under {}", state_root.as_ref());
            return exit::UNREADABLE_INPUT;
        }
        Err(e) => {
            note!(cx, "cannot read {}: {e}", run_dir.display());
            return exit::UNREADABLE_INPUT;
        }
    };
    if !parsed.flags.contains("follow") {
        return once(cx, &attempt_dir, &run);
    }
    follow(cx, &attempt_dir, &run)
}

/// The whole journal, once.
fn once(cx: &Cx<'_>, attempt_dir: &Path, run: &RunId) -> u8 {
    let v = match JournalReader::open_expecting(attempt_dir, run) {
        Ok(v) => v,
        Err(e) => {
            note!(cx, "cannot read the run's journal: {e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    say!(cx, "{SCHEMA_LINE}");
    print_records(cx, &v, 0);
    exit::PASSED
}

/// Tail the journal until the run commits.
fn follow(cx: &Cx<'_>, attempt_dir: &Path, run: &RunId) -> u8 {
    let mut tail = match JournalTail::open(attempt_dir) {
        Ok(t) => t,
        Err(e) => {
            note!(cx, "cannot read the run's journal: {e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    say!(cx, "{SCHEMA_LINE}");
    loop {
        match tail.poll() {
            Ok(p) => {
                // The journal must still be this run's (a copied journal
                // verifies in the wrong directory; the run id is the
                // defence, as for the one-shot reader).
                if p.verified.run != run.as_str() {
                    note!(cx, "the journal belongs to another run");
                    return exit::UNREADABLE_INPUT;
                }
                let from = p
                    .new_records
                    .first()
                    .map_or(p.verified.records.len(), |r| r.seq as usize);
                print_records(cx, &p.verified, from);
                if p.is_complete() {
                    return exit::PASSED;
                }
            }
            Err(e) => {
                note!(cx, "the journal ended unreadable: {e}");
                return exit::UNREADABLE_INPUT;
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// The journal's own canonical record lines, from `from` on (the reader
/// only accepts canonical bytes, so the re-encoding is byte-exact).
fn print_records(cx: &Cx<'_>, v: &harness_journal::Verified, from: usize) {
    for i in from..v.records.len() {
        if let Some(line) = v.line_bytes(i) {
            say!(cx, "{}", String::from_utf8_lossy(&line));
        }
    }
}
