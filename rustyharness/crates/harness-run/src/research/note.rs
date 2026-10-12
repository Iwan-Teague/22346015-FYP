//! Quarantined research notes (P-39l, design §6, INV-49): the durable,
//! content-addressed artefact a research session saves when a turn ends
//! `answered` or `submitted`.
//!
//! A note is the pair `note.json` (the content-addressed document) and
//! `note.md` (a sanitised human rendering), stored at
//! `<state_root>/research/notes/<id>/` — under the state root, never
//! inside a run directory, so a note survives the run that wrote it and a
//! later run finds it by id alone (INV-49). The id is the SHA-256 of the
//! exact `note.json` bytes, so a note names its own content: any edit
//! breaks the address and [`verify_note`] says so.
//!
//! Everything untrusted in a note — the user's question, the model's
//! answer — is quarantined: stored escaped (the journal's reversible
//! `\u{HEX}` spelling, like an `UntrustedBlob` home), labelled
//! third-party web content, and sanitised again on every display path
//! ([`render_md`]). The note is built as a pure function of the journal:
//! the question from the turn's `UserTurn` record, the answer from that
//! turn's last `ModelReplied` record — so an audit replay rebuilds the
//! identical bytes and the id is recomputed, never trusted
//! ([`rebuild_from_journal`]). (Design §6's `chain_head_at_save` is
//! deliberately left out: a chain head is a hash of timestamped records,
//! so a replay journal — its own clock, its own hashes — can never
//! recompute one, and embedding it in the content-addressed document
//! would make every note unreproducible by the audit the card requires.)
//!
//! The journal leads, the files follow: a turn journals its `NoteSaved`
//! record FIRST and writes the files afterwards; a file failure fails the
//! session closed (the journal says a note exists that the disk may not
//! hold), never silently.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

use gate_outcome::Digest;
use harness_core::sha256;
use harness_journal::canon::escape;
use harness_journal::{BlobSource, Event, EventKind, Trusted};
use harness_model::replay::payload_bytes;
use serde_json::{json, Map, Value};

// ---------------------------------------------------------------------------
// The live loop's note state (P-39l §6).
// ---------------------------------------------------------------------------

/// Where a research session's notes go when the loop journals a
/// `NoteSaved`: to the state root's notes directory (a live run), or
/// nowhere (an audit replay, which must not write files — it only
/// recomputes the record).
pub(crate) enum NoteSink {
    /// Write the note files under this directory (`research/notes`).
    Live { dir: std::path::PathBuf },
    /// Recompute only; never touch the disk.
    Compute,
}

/// The research loop's note facts for the current turn: who and where the
/// session is, the turn's question and answer, and the web sources the
/// answer drew from. Carried by the loop (one field on
/// `crate::driver::LoopInit`, `None` for every coding mode) so the
/// turn-end hook can build the note from journal-shaped facts alone.
pub(crate) struct NotesCtx {
    /// The run id, as the note names it.
    pub(crate) run: String,
    /// The journal attempt the note is saved in.
    pub(crate) attempt: u64,
    /// Where files go (`Live`) or recompute-only (`Compute`).
    pub(crate) sink: NoteSink,
    /// This turn's question (set at `UserTurn`).
    pub(crate) question: Option<String>,
    /// This turn's answer (set where the turn ends `answered` or
    /// `submitted`).
    pub(crate) answer: Option<String>,
    /// The web sources the answer drew from (P-39j+; empty until the web
    /// tools are wired into research sessions).
    pub(crate) sources: Vec<SourceRec>,
    /// The turn's last model reply with content (any step, set as each
    /// reply is journaled): what `/save-note` saves when the turn did not
    /// end `answered` or `submitted`.
    pub(crate) last_reply: Option<String>,
    /// The last turn that ended WITHOUT saving a note but left a question
    /// and a reply: what `/save-note` can still save (`None` once saved,
    /// or when the next turn opens).
    pub(crate) unsaved: Option<UnsavedTurn>,
}

/// A finished turn whose note was not saved at its end (`/save-note`'s
/// subject).
#[derive(Clone)]
pub(crate) struct UnsavedTurn {
    /// The turn's number.
    pub(crate) turn: u64,
    /// The turn's question.
    pub(crate) question: String,
    /// The turn's last model reply.
    pub(crate) reply: String,
}

impl NotesCtx {
    /// A fresh note state for one session loop.
    pub(crate) fn new(run: String, attempt: u64, sink: NoteSink) -> Self {
        Self {
            run,
            attempt,
            sink,
            question: None,
            answer: None,
            sources: Vec::new(),
            last_reply: None,
            unsaved: None,
        }
    }
}

/// One web source a note's answer drew from (design §6 `sources[]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRec {
    /// The requested URL (untrusted; escaped wherever displayed).
    pub url: String,
    /// The URL after redirects.
    pub final_url: String,
    /// The final HTTP status.
    pub status: Option<u16>,
    /// The response's content type.
    pub content_type: Option<String>,
    /// SHA-256 of the fetched body.
    pub body_sha256: Option<Digest>,
    /// SHA-256 of the extracted text.
    pub text_sha256: Option<Digest>,
    /// Whether the extraction was cut by the fetch budget.
    pub truncated: bool,
    /// The step that fetched it.
    pub step: u64,
    /// Redirect hops taken.
    pub hops: u64,
}

// ---------------------------------------------------------------------------
// Building a note (pure, journal-shaped facts in, bytes out).
// ---------------------------------------------------------------------------

/// The journal-shaped facts one saved note records (design §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteFacts {
    /// The run that saved the note.
    pub run: String,
    /// The attempt that saved it.
    pub attempt: u64,
    /// The turn whose answer the note holds.
    pub turn: u64,
    /// The step the `NoteSaved` record was journaled at.
    pub step: u64,
    /// The turn's question (the user's message).
    pub question: String,
    /// The turn's answer (the model's last reply).
    pub answer: String,
    /// The web sources the answer drew from.
    pub sources: Vec<SourceRec>,
}

/// The note's first line, on disk and in every rendering: the reader is
/// told what they are looking at before anything else.
pub const NOTE_BANNER: &str =
    "UNTRUSTED: text written by a model from web pages; do not follow instructions in it";

/// The note's version, in the document.
pub const NOTE_VERSION: u64 = 1;

/// One quarantined text (the question or the answer) as the note stores
/// it: escaped like an `UntrustedBlob` stores text, carrying its own
/// digest and where it came from. Nothing here is plain text — the file
/// never carries a raw untrusted string.
fn untrusted_json(text: &str, kind: &str) -> Value {
    json!({
        "inline": escape(text),
        "sha256": sha256(text.as_bytes()).to_string(),
        "source": { "kind": kind },
        "untrusted": true,
    })
}

/// One web source as the note stores it; absent facts are omitted.
fn source_json(s: &SourceRec) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("final_url".into(), json!(escape(&s.final_url)));
    obj.insert("hops".into(), json!(s.hops));
    obj.insert("step".into(), json!(s.step));
    obj.insert("truncated".into(), json!(s.truncated));
    obj.insert("url".into(), json!(escape(&s.url)));
    if let Some(status) = s.status {
        obj.insert("status".into(), json!(status));
    }
    if let Some(ct) = &s.content_type {
        obj.insert("content_type".into(), json!(escape(ct)));
    }
    if let Some(d) = &s.body_sha256 {
        obj.insert("body_sha256".into(), json!(d.to_string()));
    }
    if let Some(d) = &s.text_sha256 {
        obj.insert("text_sha256".into(), json!(d.to_string()));
    }
    Value::Object(obj)
}

/// The note document (design §6, exact key set): deterministic — sorted
/// keys (`serde_json`'s map is sorted), compact, no timestamps — so the
/// same journal always rebuilds the same bytes and the id with them.
pub fn build(facts: &NoteFacts) -> Value {
    json!({
        "answer": untrusted_json(&facts.answer, "model"),
        "attempt": facts.attempt,
        "labels": {
            "content": "third_party",
            "origin": "web",
            "untrusted": true,
        },
        "note_version": NOTE_VERSION,
        "question": untrusted_json(&facts.question, "user"),
        "run": facts.run,
        "sources": facts.sources.iter().map(source_json).collect::<Vec<Value>>(),
        "step": facts.step,
        "turn": facts.turn,
    })
}

/// A built note: its content address and the exact bytes that hash to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltNote {
    /// SHA-256 of [`BuiltNote::json`].
    pub id: String,
    /// The exact `note.json` bytes (compact, sorted keys).
    pub json: Vec<u8>,
}

/// Build the note document and its content address from journal-shaped
/// facts. Pure: this is what the loop saves with and what a rebuild and
/// a verifier both recompute.
pub fn build_note(facts: &NoteFacts) -> BuiltNote {
    // Serialising a `serde_json::Value` cannot fail (no maps with
    // non-string keys, no floats), so the id is infallible too.
    let json = match serde_json::to_vec(&build(facts)) {
        Ok(bytes) => bytes,
        Err(e) => unreachable!("a note document always serialises: {e}"),
    };
    let id = sha256(&json).to_string();
    BuiltNote { id, json }
}

/// The `NoteSaved` record a saved note is journalled as (the canonical
/// body keys §1.1 fixes: `bytes`, `note`, `sources`, `turn`). The journal
/// leads: this is appended before any file is written.
pub(crate) fn note_saved_event(note: &BuiltNote, sources: u64, turn: u64) -> Event {
    Event::new(EventKind::NoteSaved)
        .field("bytes", Trusted::U64(note.json.len() as u64))
        .field("note", Trusted::Digest(sha256(&note.json)))
        .field("sources", Trusted::U64(sources))
        .field("turn", Trusted::U64(turn))
}

// ---------------------------------------------------------------------------
// The human rendering (note.md).
// ---------------------------------------------------------------------------

/// Render the note for a human: the banner, the question, the sources and
/// the answer — every untrusted string through the one terminal escaper
/// (§7.1), so the file is inert to render.
pub fn render_md(facts: &NoteFacts) -> String {
    use harness_core::display::{sanitize_for_terminal, DisplayMode};
    let mut md = String::new();
    md.push_str(NOTE_BANNER);
    md.push_str("\n\n## Question\n\n");
    md.push_str(&sanitize_for_terminal(&facts.question, DisplayMode::Block));
    md.push_str("\n\n## Sources\n\n");
    if facts.sources.is_empty() {
        md.push_str("(none recorded)\n");
    }
    for s in &facts.sources {
        md.push_str(&format!(
            "- {}\n",
            sanitize_for_terminal(&s.url, DisplayMode::Line)
        ));
        if let Some(d) = &s.body_sha256 {
            md.push_str(&format!("  body sha256: {d}\n"));
        }
        if let Some(d) = &s.text_sha256 {
            md.push_str(&format!("  text sha256: {d}\n"));
        }
    }
    md.push_str("\n## Answer\n\n");
    md.push_str(&sanitize_for_terminal(&facts.answer, DisplayMode::Block));
    md.push('\n');
    md
}

// ---------------------------------------------------------------------------
// Storage: 0700 dirs, 0600 files, atomic rename, immutable by id.
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn set_perms(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_perms(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Write one note file atomically: bytes to `<name>.tmp`, fsync, 0600,
/// rename over the final name (which therefore never exists half-written
/// or world-readable).
fn write_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    set_perms(&tmp, 0o600)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Store a note under `dir/<id>/` (`note.json` + `note.md`): the note
/// directory is 0700, the files 0600, both fsynced. A note is immutable:
/// an existing id directory is left exactly as it is (its content address
/// means the bytes would be identical) and `Ok(false)` comes back — the
/// caller decides whether that is a rebuild (expected) or a clash.
pub fn write_note(dir: &Path, note: &BuiltNote, md: &str) -> std::io::Result<bool> {
    let note_dir = dir.join(&note.id);
    if note_dir.is_dir() {
        return Ok(false);
    }
    fs::create_dir_all(dir)?;
    set_perms(dir, 0o700)?;
    fs::create_dir(&note_dir)?;
    set_perms(&note_dir, 0o700)?;
    write_file(&note_dir.join("note.json"), &note.json)?;
    write_file(&note_dir.join("note.md"), md.as_bytes())?;
    fsync_dir(&note_dir)?;
    fsync_dir(dir)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Rebuilding from the journal (the note is a pure function of the run).
// ---------------------------------------------------------------------------

/// A note rebuilt from a journal: the facts it was built from, the bytes
/// and id, and the human rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuiltNote {
    /// The facts the note was built from.
    pub facts: NoteFacts,
    /// The built note (id + bytes).
    pub note: BuiltNote,
    /// The sanitised `note.md` rendering.
    pub md: String,
}

fn body_u64(body: &Map<String, Value>, key: &str) -> Result<u64, String> {
    body.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("`{key}` is not a number"))
}

fn body_str<'a>(body: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    body.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("`{key}` is not a string"))
}

/// Rebuild every saved note from a verified journal: walk the records,
/// take each turn's question from its `UserTurn`, its answer from the
/// turn's last `ModelReplied`, and build a note for every turn that ended
/// `answered` or `submitted`. Pure — no disk is touched — so an audit
/// replay recomputes the identical `NoteSaved` bodies and a `notes
/// rebuild` can recreate lost files byte for byte.
pub fn rebuild_from_journal(
    v: &harness_journal::Verified,
    blobs: &dyn BlobSource,
) -> Result<Vec<RebuiltNote>, String> {
    let mut notes = Vec::new();
    let mut question: Option<String> = None;
    let mut answer: Option<Value> = None;
    // A turn that ended without a note, still saveable by `/save-note`
    // (the loop's `NotesCtx::unsaved`, mirrored): its facts, with the
    // reply as the journal's payload home.
    let mut unsaved: Option<(u64, String, Value)> = None;
    let decode = |home: &Value, seq: u64, what: &str| -> Result<String, String> {
        let bytes =
            payload_bytes(home, blobs, seq).map_err(|e| format!("{what} (seq {seq}): {e}"))?;
        String::from_utf8(bytes).map_err(|_| format!("{what} (seq {seq}) is not UTF-8"))
    };
    for rec in &v.records {
        match rec.kind {
            EventKind::UserTurn => {
                let home = rec.body.get("text").ok_or("UserTurn without text")?;
                question = Some(decode(home, rec.seq, "UserTurn text")?);
                answer = None;
                unsaved = None;
            }
            EventKind::ModelReplied => {
                // A failed call carries no content: it leaves the last
                // reply as it was (the loop sets it only on a completion).
                if let Some(c) = rec.body.get("content") {
                    answer = Some(c.clone());
                }
            }
            EventKind::TurnEnded => {
                let reason = body_str(&rec.body, "reason")?;
                let turn = body_u64(&rec.body, "turn")?;
                if matches!(reason, "answered" | "submitted") {
                    let q = question
                        .clone()
                        .ok_or_else(|| format!("turn {turn} ended {reason} with no UserTurn"))?;
                    let home = answer
                        .as_ref()
                        .ok_or_else(|| format!("turn {turn} ended {reason} with no model reply"))?;
                    let a = decode(home, rec.seq, &format!("turn {turn} answer"))?;
                    let facts = NoteFacts {
                        run: v.run.clone(),
                        attempt: v.attempt,
                        turn,
                        step: rec.step,
                        question: q,
                        answer: a,
                        sources: Vec::new(),
                    };
                    let note = build_note(&facts);
                    let md = render_md(&facts);
                    notes.push(RebuiltNote { facts, note, md });
                    unsaved = None;
                } else {
                    // Saveable later only with a question and a reply that
                    // is not blank (the loop's own condition).
                    unsaved = match (&question, &answer) {
                        (Some(q), Some(a)) => {
                            let text = decode(a, rec.seq, &format!("turn {turn} reply"))?;
                            (!text.trim().is_empty()).then(|| (turn, q.clone(), a.clone()))
                        }
                        _ => None,
                    };
                }
                question = None;
                answer = None;
            }
            // A `NoteSaved` between turns is `/save-note`'s: it saves the
            // last unsaved turn (the in-turn one is rebuilt at its
            // `TurnEnded` above and finds nothing pending here).
            EventKind::NoteSaved => {
                if let Some((turn, q, a)) = unsaved.take() {
                    let facts = NoteFacts {
                        run: v.run.clone(),
                        attempt: v.attempt,
                        turn,
                        step: rec.step,
                        question: q,
                        answer: decode(&a, rec.seq, &format!("turn {turn} reply"))?,
                        sources: Vec::new(),
                    };
                    let note = build_note(&facts);
                    let md = render_md(&facts);
                    notes.push(RebuiltNote { facts, note, md });
                }
            }
            _ => {}
        }
    }
    Ok(notes)
}

// ---------------------------------------------------------------------------
// Verification.
// ---------------------------------------------------------------------------

/// Verify a note file against the run's journal (design §6): the file
/// hashes to its id, the journal chain verifies (and anchors, when asked),
/// a `NoteSaved` record names this id with matching counts, and the bytes
/// are exactly what the journal deterministically rebuilds. A mismatch
/// names the failing part.
pub fn verify_note(
    json: &[u8],
    note_id: &str,
    journal_bytes: &[u8],
    blobs: &dyn BlobSource,
    anchor: Option<&Digest>,
) -> Result<(), String> {
    // 1. The content address: the file must hash to the id it is stored
    // under. Any edit breaks this first.
    let actual = sha256(json).to_string();
    if actual != note_id {
        return Err(format!(
            "content address: note.json hashes to {actual}, not {note_id}"
        ));
    }

    // 2. The shape: strict JSON, the exact document the design fixes.
    let note = harness_core::strict_json::parse(json)
        .map_err(|e| format!("note.json is not strict JSON: {e}"))?;
    let obj = note.as_object().ok_or("note.json is not a JSON object")?;
    if body_u64(obj, "note_version")? != NOTE_VERSION {
        return Err(format!("note_version is not {NOTE_VERSION}"));
    }

    // 3. The journal: chain verified first — nothing said about a broken
    // chain is evidence.
    let v = harness_journal::verify(journal_bytes, blobs)
        .map_err(|e| format!("the run's journal does not verify: {e}"))?;
    if let Some(a) = anchor {
        v.check_anchor(a).map_err(|e| format!("anchor: {e}"))?;
    }

    // 4. The `NoteSaved` record: this journal must have saved this note,
    // with the byte, source and turn counts the document claims.
    let note_saved = v
        .records
        .iter()
        .find(|r| {
            matches!(r.kind, EventKind::NoteSaved)
                && r.body.get("note").and_then(Value::as_str) == Some(note_id)
        })
        .ok_or_else(|| "no NoteSaved record for this note id in the run's journal".to_owned())?;
    let bytes_claimed = body_u64(&note_saved.body, "bytes")?;
    if bytes_claimed != json.len() as u64 {
        return Err(format!(
            "NoteSaved says {bytes_claimed} bytes, the file holds {}",
            json.len()
        ));
    }
    let sources_claimed = body_u64(&note_saved.body, "sources")?;
    let sources_in_doc = obj
        .get("sources")
        .and_then(Value::as_array)
        .ok_or("note.json `sources` is not an array")?
        .len() as u64;
    if sources_claimed != sources_in_doc {
        return Err(format!(
            "NoteSaved says {sources_claimed} sources, the document holds {sources_in_doc}"
        ));
    }
    let turn_claimed = body_u64(&note_saved.body, "turn")?;
    let turn_in_doc = body_u64(obj, "turn")?;
    if turn_claimed != turn_in_doc {
        return Err(format!(
            "NoteSaved says turn {turn_claimed}, the document says turn {turn_in_doc}"
        ));
    }
    let run_in_doc = body_str(obj, "run")?;
    if run_in_doc != v.run {
        return Err(format!(
            "the document names run {run_in_doc}, the journal is run {}",
            v.run
        ));
    }
    let attempt_in_doc = body_u64(obj, "attempt")?;
    if attempt_in_doc != v.attempt {
        return Err(format!(
            "the document names attempt {attempt_in_doc}, the journal is attempt {}",
            v.attempt
        ));
    }

    // 5. The rebuild: the journal deterministically produces this note's
    // bytes; name the part that drifted when it does not.
    let rebuilt = rebuild_from_journal(&v, blobs)?;
    let r = rebuilt
        .iter()
        .find(|n| n.note.id == note_id)
        .ok_or("the journal's turns do not rebuild this note")?;
    let rn: Value = match serde_json::from_slice(&r.note.json) {
        Ok(v) => v,
        Err(e) => return Err(format!("the rebuild does not parse: {e}")),
    };
    if note.get("answer") != rn.get("answer") {
        return Err(
            "answer: the document's answer is not the turn's journaled model reply".to_owned(),
        );
    }
    if note.get("question") != rn.get("question") {
        return Err(
            "question: the document's question is not the turn's journaled input".to_owned(),
        );
    }
    if note.get("sources") != rn.get("sources") {
        return Err("sources: the document's sources do not match the journal".to_owned());
    }
    if json != r.note.json {
        return Err("bytes: the document differs from the deterministic rebuild".to_owned());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Listing: what is on disk, what the journals say should be.
// ---------------------------------------------------------------------------

/// One note directory found under `research/notes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteRow {
    /// The content address (the directory name).
    pub id: String,
    /// The run that saved it (from the document).
    pub run: Option<String>,
    /// The turn whose answer it holds (from the document).
    pub turn: Option<u64>,
    /// How many web sources it names (from the document).
    pub sources: Option<u64>,
    /// Whether the file still hashes to its id.
    pub intact: bool,
}

/// Scan the state root's notes directory (`research/notes/<id>/{note.json,
/// note.md}`), sorted by id. A directory whose document is missing or not
/// strict JSON still lists, with what could be read and `intact: false` —
/// listing never hides a damaged note (fail visible).
pub fn scan_note_dirs(state_root: &Path) -> std::io::Result<Vec<NoteRow>> {
    let dir = harness_journal::layout::research_notes_dir(state_root);
    let mut rows = Vec::new();
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        // No notes directory: no notes, not an error.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(rows),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = entry?;
        let id = entry.file_name().to_string_lossy().into_owned();
        let json_path = entry.path().join("note.json");
        let bytes = match fs::read(&json_path) {
            Ok(b) => b,
            // A note directory without its document is damaged, not absent.
            Err(_) => {
                rows.push(NoteRow {
                    id,
                    run: None,
                    turn: None,
                    sources: None,
                    intact: false,
                });
                continue;
            }
        };
        let intact = sha256(&bytes).to_string() == id;
        let doc = serde_json::from_slice::<Value>(&bytes).ok();
        rows.push(NoteRow {
            run: doc
                .as_ref()
                .and_then(|d| d.get("run"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            turn: doc
                .as_ref()
                .and_then(|d| d.get("turn"))
                .and_then(Value::as_u64),
            sources: doc
                .as_ref()
                .and_then(|d| d.get("sources"))
                .and_then(|s| s.as_array().map(|a| a.len() as u64)),
            id,
            intact,
        });
    }
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(rows)
}

/// A note a journal saved but the disk does not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingNote {
    /// The run whose journal saved it.
    pub run: String,
    /// The attempt that saved it.
    pub attempt: u64,
    /// The note's content address.
    pub id: String,
    /// The turn whose answer it holds.
    pub turn: u64,
}

/// Cross the state root's runs against its notes directory: every
/// `NoteSaved` id whose note directory is absent, with the run and
/// attempt that can rebuild it. Journals that do not verify are skipped
/// (nothing can be claimed from them); the notes directory is the
/// authority on what is present.
pub fn missing_notes(state_root: &Path) -> std::io::Result<Vec<MissingNote>> {
    let mut missing = Vec::new();
    for scanned in harness_journal::scan::scan_runs(state_root)? {
        let Ok(v) = scanned.journal else { continue };
        for rec in &v.records {
            if !matches!(rec.kind, EventKind::NoteSaved) {
                continue;
            }
            let Some(id) = rec.body.get("note").and_then(Value::as_str) else {
                continue;
            };
            let present = harness_journal::layout::research_notes_dir(state_root)
                .join(id)
                .is_dir();
            if !present {
                missing.push(MissingNote {
                    run: v.run.clone(),
                    attempt: v.attempt,
                    id: id.to_owned(),
                    turn: rec.body.get("turn").and_then(Value::as_u64).unwrap_or(0),
                });
            }
        }
    }
    missing.sort_by(|a, b| (&a.run, &a.id).cmp(&(&b.run, &b.id)));
    Ok(missing)
}

/// Rebuild every missing note for one run from its latest verifiable
/// attempt's journal, writing only the notes that are absent (a note is
/// immutable; a present id is left as it is). Returns
/// `(rebuilt, already_present)` ids.
pub fn rebuild_run(
    state_root: &Path,
    run: &harness_core::RunId,
) -> Result<(Vec<String>, Vec<String>), String> {
    let run_dir = harness_journal::layout::run_dir(state_root, run);
    let mut names: Vec<u32> = std::fs::read_dir(&run_dir)
        .map_err(|e| format!("cannot read {}: {e}", run_dir.display()))?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            harness_journal::layout::parse_attempt_name(&e.file_name().to_string_lossy())
        })
        .collect();
    names.sort_unstable();
    names.reverse();
    let notes_dir = harness_journal::layout::research_notes_dir(state_root);
    let mut rebuilt = Vec::new();
    let mut present = Vec::new();
    for attempt in names {
        let attempt_dir = harness_journal::layout::attempt_dir(&run_dir, attempt);
        let Ok(bytes) = std::fs::read(attempt_dir.join(harness_journal::layout::JOURNAL_FILE))
        else {
            continue;
        };
        let blobs = harness_journal::reader::DirBlobSource::new(
            attempt_dir.join(harness_journal::layout::BLOBS_DIR),
        );
        let Ok(v) = harness_journal::verify(&bytes, &blobs) else {
            continue;
        };
        for n in rebuild_from_journal(&v, &blobs)? {
            if write_note(&notes_dir, &n.note, &n.md).map_err(|e| e.to_string())? {
                rebuilt.push(n.note.id);
            } else {
                present.push(n.note.id);
            }
        }
    }
    Ok((rebuilt, present))
}
