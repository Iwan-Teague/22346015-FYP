//! The verifying reader (design §7.1, INV-11). A separate type from the
//! writer: it can only read.
//!
//! [`verify`] is pure (bytes in, verdict out); [`JournalReader::open`] only
//! reads the files and calls it. It refuses the whole journal at the FIRST
//! broken record and names it. A torn final line (no trailing newline: a
//! crash mid-append) is not a break: it is reported, and the verified prefix
//! is what a resume starts from (§2.10).

use std::fs;
use std::path::{Path, PathBuf};

use harness_core::{sha256, sha256_parts, Digest};
use serde_json::{Map, Value};

use crate::canon::{unescape, EventKind, GENESIS, INLINE_MAX};
use crate::event::UNTRUSTED_KEY;
use crate::layout;
use crate::writer::is_blob_name;

/// Read access to a blob store.
pub trait BlobSource {
    /// The bytes stored under `name`, if present.
    fn get(&self, name: &str) -> Option<Vec<u8>>;
}

/// A `blobs/` directory as a [`BlobSource`]. Only 64-hex names are looked
/// up, so a record cannot steer the reader to another path.
#[derive(Debug)]
pub struct DirBlobSource {
    dir: PathBuf,
}

impl DirBlobSource {
    /// Blobs under `dir`.
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
}

impl BlobSource for DirBlobSource {
    fn get(&self, name: &str) -> Option<Vec<u8>> {
        if !is_blob_name(name) {
            return None;
        }
        fs::read(self.dir.join(name)).ok()
    }
}

/// One verified record.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// Sequence number.
    pub seq: u64,
    /// Loop step.
    pub step: u64,
    /// Kind.
    pub kind: EventKind,
    /// Monotonic milliseconds.
    pub t_mono_ms: u64,
    /// Wall clock (as written).
    pub t_wall: String,
    /// Body (untrusted payloads still escaped and marked).
    pub body: Map<String, Value>,
    /// This record's hash.
    pub hash: Digest,
}

/// A journal whose every complete line verified.
#[derive(Debug, Clone)]
pub struct Verified {
    /// The records, in order.
    pub records: Vec<Record>,
    /// Byte offset of a torn final line, if the file does not end in `\n`.
    pub torn_tail: Option<usize>,
    /// Hash of the last verified record.
    pub head: Digest,
    /// The run id every record carries (from the header).
    pub run: String,
    /// The attempt number every record carries (from the header).
    pub attempt: u64,
}

impl Verified {
    /// Whether the journal ends with `RunStopped` (the run committed). A
    /// journal truncated by whole lines verifies but is not complete.
    pub fn is_complete(&self) -> bool {
        self.torn_tail.is_none()
            && self
                .records
                .last()
                .is_some_and(|r| r.kind == EventKind::RunStopped)
    }

    /// Compare against a chain head recorded elsewhere (the run report, the
    /// suite's evidence records). The only defence against wholesale
    /// replacement or truncation by whole lines (§7.1 "Anchoring").
    pub fn check_anchor(&self, expected: &Digest) -> Result<(), Broken> {
        if &self.head == expected {
            Ok(())
        } else {
            Err(Broken {
                record: self.records.len(),
                why: BreakKind::AnchorMismatch,
            })
        }
    }
}

/// The first broken record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("journal broken at record {record}: {why:?}")]
pub struct Broken {
    /// 0-based line index of the first broken record.
    pub record: usize,
    /// What is wrong with it.
    pub why: BreakKind,
}

/// Why a record is broken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakKind {
    /// The file is empty.
    Empty,
    /// The header line itself is torn (the run never durably started).
    TornHeader,
    /// Not UTF-8.
    NotUtf8,
    /// Not a JSON object with exactly the record fields.
    NotARecord,
    /// Not the canonical encoding of what it parses to (duplicate keys,
    /// reordered keys, whitespace, re-escaping).
    NotCanonical,
    /// `seq` is not this line's index (a deleted or reordered line).
    BadSeq {
        /// Expected.
        expected: u64,
        /// Found.
        found: u64,
    },
    /// `prev` is not the previous record's hash.
    BadPrev,
    /// `hash` does not match the record's content.
    BadHash,
    /// A kind outside the closed set.
    UnknownKind,
    /// Line 0 is not `RunStarted`, or `RunStarted` appears later.
    HeaderMisplaced,
    /// `run` or `attempt` differs from the header's.
    WrongRun,
    /// `t_mono_ms` went backwards.
    TimeBackwards,
    /// A record after `RunStopped`.
    AfterRunStopped,
    /// An untrusted payload object is malformed.
    UntrustedMalformed,
    /// An untrusted payload's bytes do not hash to its `sha256`/`len`.
    UntrustedMismatch,
    /// A referenced blob is missing from the blob store.
    MissingBlob,
    /// The head differs from the externally recorded anchor.
    AnchorMismatch,
    /// The journal's attempt or run differs from the directory it was read
    /// from or the run the caller expected (a copied journal, review F-5).
    WrongAttempt,
}

fn broken(record: usize, why: BreakKind) -> Broken {
    Broken { record, why }
}

const RECORD_KEYS: [&str; 10] = [
    "attempt",
    "body",
    "hash",
    "kind",
    "prev",
    "run",
    "seq",
    "step",
    "t_mono_ms",
    "t_wall",
];

/// Verify a journal's bytes. Pure.
pub fn verify(bytes: &[u8], blobs: &dyn BlobSource) -> Result<Verified, Broken> {
    if bytes.is_empty() {
        return Err(broken(0, BreakKind::Empty));
    }
    let (complete, torn_tail) = match bytes.iter().rposition(|b| *b == b'\n') {
        Some(last) if last + 1 == bytes.len() => (bytes, None),
        Some(last) => (bytes.get(..=last).unwrap_or(bytes), Some(last + 1)),
        None => return Err(broken(0, BreakKind::TornHeader)),
    };
    let body_bytes = complete.strip_suffix(b"\n").unwrap_or(complete);
    let mut records = Vec::new();
    let mut prev = GENESIS;
    let mut run: Option<(String, u64)> = None;
    let mut last_mono = 0u64;
    for (i, line) in body_bytes.split(|b| *b == b'\n').enumerate() {
        let rec = verify_line(i, line, &prev, &mut run, last_mono, blobs)?;
        if let Some(last) = records.last() {
            let last: &Record = last;
            if last.kind == EventKind::RunStopped {
                return Err(broken(i, BreakKind::AfterRunStopped));
            }
        }
        prev = rec.hash;
        last_mono = rec.t_mono_ms;
        records.push(rec);
    }
    let (run, attempt) = run.ok_or(broken(0, BreakKind::Empty))?;
    Ok(Verified {
        records,
        torn_tail,
        head: prev,
        run,
        attempt,
    })
}

fn verify_line(
    i: usize,
    line: &[u8],
    prev: &Digest,
    run: &mut Option<(String, u64)>,
    last_mono: u64,
    blobs: &dyn BlobSource,
) -> Result<Record, Broken> {
    let b = |why| broken(i, why);
    let text = std::str::from_utf8(line).map_err(|_| b(BreakKind::NotUtf8))?;
    let value: Value = serde_json::from_str(text).map_err(|_| b(BreakKind::NotARecord))?;
    // Byte-exact canonical form. (Bound first on purpose: clippy's
    // `cmp_owned` suggestion `value != text` would compare the JSON value
    // against a JSON *string*, which is a different, wrong check.)
    let reencoded = value.to_string();
    if reencoded.as_bytes() != line {
        return Err(b(BreakKind::NotCanonical));
    }
    let Value::Object(mut obj) = value else {
        return Err(b(BreakKind::NotARecord));
    };
    if obj.len() != RECORD_KEYS.len() || !RECORD_KEYS.iter().all(|k| obj.contains_key(*k)) {
        return Err(b(BreakKind::NotARecord));
    }
    let u64_of = |o: &Map<String, Value>, k: &str| o.get(k).and_then(Value::as_u64);
    let str_of =
        |o: &Map<String, Value>, k: &str| o.get(k).and_then(Value::as_str).map(str::to_owned);
    let bad = || b(BreakKind::NotARecord);

    let seq = u64_of(&obj, "seq").ok_or_else(bad)?;
    let expected = u64::try_from(i).unwrap_or(u64::MAX);
    if seq != expected {
        return Err(b(BreakKind::BadSeq {
            expected,
            found: seq,
        }));
    }
    let stated_prev: Digest = str_of(&obj, "prev")
        .and_then(|s| s.parse().ok())
        .ok_or_else(bad)?;
    if &stated_prev != prev {
        return Err(b(BreakKind::BadPrev));
    }
    let stated_hash: Digest = obj
        .remove("hash")
        .and_then(|h| h.as_str().and_then(|s| s.parse().ok()))
        .ok_or_else(bad)?;
    let canonical = Value::Object(obj.clone()).to_string();
    if sha256_parts(&[prev.as_bytes(), canonical.as_bytes()]) != stated_hash {
        return Err(b(BreakKind::BadHash));
    }

    let kind = str_of(&obj, "kind")
        .as_deref()
        .and_then(EventKind::parse)
        .ok_or_else(|| b(BreakKind::UnknownKind))?;
    if (i == 0) != (kind == EventKind::RunStarted) {
        return Err(b(BreakKind::HeaderMisplaced));
    }
    let this_run = (
        str_of(&obj, "run").ok_or_else(bad)?,
        u64_of(&obj, "attempt").ok_or_else(bad)?,
    );
    match run {
        None => *run = Some(this_run),
        Some(r) if *r == this_run => {}
        Some(_) => return Err(b(BreakKind::WrongRun)),
    }
    let t_mono_ms = u64_of(&obj, "t_mono_ms").ok_or_else(bad)?;
    if t_mono_ms < last_mono {
        return Err(b(BreakKind::TimeBackwards));
    }
    let step = u64_of(&obj, "step").ok_or_else(bad)?;
    let t_wall = str_of(&obj, "t_wall").ok_or_else(bad)?;
    let Some(Value::Object(body)) = obj.remove("body") else {
        return Err(bad());
    };
    check_untrusted(&Value::Object(body.clone()), blobs).map_err(b)?;
    Ok(Record {
        seq,
        step,
        kind,
        t_mono_ms,
        t_wall,
        body,
        hash: stated_hash,
    })
}

/// Walk a body; every object marked `"untrusted"` must be a well-formed
/// payload home whose bytes (inline, unescaped, or from the blob store)
/// hash to its `sha256` and have its `len`.
fn check_untrusted(v: &Value, blobs: &dyn BlobSource) -> Result<(), BreakKind> {
    match v {
        Value::Array(a) => a.iter().try_for_each(|e| check_untrusted(e, blobs)),
        Value::Object(o) if o.contains_key(UNTRUSTED_KEY) => check_blob(o, blobs),
        Value::Object(o) => o.values().try_for_each(|e| check_untrusted(e, blobs)),
        _ => Ok(()),
    }
}

fn check_blob(o: &Map<String, Value>, blobs: &dyn BlobSource) -> Result<(), BreakKind> {
    use BreakKind::{MissingBlob, UntrustedMalformed as M, UntrustedMismatch};
    if o.get(UNTRUSTED_KEY) != Some(&Value::Bool(true)) {
        return Err(M);
    }
    let has_inline = o.contains_key("inline");
    let has_blob = o.contains_key("blob");
    if has_inline == has_blob || o.len() != 5 {
        return Err(M);
    }
    check_source(o.get("source").ok_or(M)?)?;
    let sha: Digest = o
        .get("sha256")
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or(M)?;
    let len = o.get("len").and_then(Value::as_u64).ok_or(M)?;
    let bytes = if has_inline {
        let s = o.get("inline").and_then(Value::as_str).ok_or(M)?;
        let raw = unescape(s).ok_or(M)?;
        if raw.len() > INLINE_MAX {
            return Err(M);
        }
        raw.into_bytes()
    } else {
        let name = o.get("blob").and_then(Value::as_str).ok_or(M)?;
        if name != sha.to_string() {
            return Err(M);
        }
        blobs.get(name).ok_or(MissingBlob)?
    };
    if sha256(&bytes) != sha || u64::try_from(bytes.len()).ok() != Some(len) {
        return Err(UntrustedMismatch);
    }
    Ok(())
}

fn check_source(v: &Value) -> Result<(), BreakKind> {
    let m = BreakKind::UntrustedMalformed;
    let o = v.as_object().ok_or(m.clone())?;
    let text = |k: &str| {
        o.get(k)
            .and_then(Value::as_str)
            .and_then(unescape)
            .ok_or(m.clone())
    };
    match o.get("kind").and_then(Value::as_str) {
        Some("model") if o.len() == 1 => Ok(()),
        Some("tool") if o.len() == 2 => text("id").map(drop),
        Some("workspace") if o.len() == 2 => text("path").map(drop),
        _ => Err(m),
    }
}

/// Why a journal could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// The file could not be read.
    #[error("cannot read journal: {0}")]
    Io(String),
    /// A path under the attempt is a symlink or not the expected kind.
    #[error("journal path is not a real file or directory: {0}")]
    NotReal(&'static str),
    /// The directory is not named `attempt-<n>`.
    #[error("not an attempt directory (attempt-<n>)")]
    NotAnAttemptDir,
    /// A record is broken.
    #[error(transparent)]
    Broken(#[from] Broken),
}

/// Opens and verifies an attempt's journal. Read-only by construction.
#[derive(Debug)]
pub struct JournalReader;

fn require_real(path: &Path, want_dir: bool, what: &'static str) -> Result<(), ReadError> {
    let m = fs::symlink_metadata(path).map_err(|e| ReadError::Io(e.to_string()))?;
    if m.file_type().is_symlink() || m.is_dir() != want_dir {
        return Err(ReadError::NotReal(what));
    }
    Ok(())
}

impl JournalReader {
    /// Read `attempt_dir/journal.jsonl` and verify it against
    /// `attempt_dir/blobs/`. The journal is bound to its directory (review
    /// F-5): `attempt_dir` must be named `attempt-<n>` and the journal's
    /// records must all say attempt `n`, so a journal copied into another
    /// attempt directory is refused. Neither the attempt directory, the
    /// journal file nor `blobs/` may be a symlink (review F-4).
    pub fn open(attempt_dir: &Path) -> Result<Verified, ReadError> {
        let n = attempt_dir
            .file_name()
            .and_then(|s| s.to_str())
            .and_then(layout::parse_attempt_name)
            .ok_or(ReadError::NotAnAttemptDir)?;
        require_real(attempt_dir, true, "attempt dir")?;
        let journal = attempt_dir.join(layout::JOURNAL_FILE);
        require_real(&journal, false, "journal.jsonl")?;
        let blobs_dir = attempt_dir.join(layout::BLOBS_DIR);
        require_real(&blobs_dir, true, "blobs dir")?;
        let bytes = fs::read(&journal).map_err(|e| ReadError::Io(e.to_string()))?;
        let v = verify(&bytes, &DirBlobSource::new(blobs_dir))?;
        if v.attempt != u64::from(n) {
            return Err(broken(0, BreakKind::WrongAttempt).into());
        }
        Ok(v)
    }

    /// [`JournalReader::open`], and the journal must belong to `run`.
    pub fn open_expecting(
        attempt_dir: &Path,
        run: &harness_core::RunId,
    ) -> Result<Verified, ReadError> {
        let v = Self::open(attempt_dir)?;
        if v.run != run.as_str() {
            return Err(broken(0, BreakKind::WrongAttempt).into());
        }
        Ok(v)
    }
}
