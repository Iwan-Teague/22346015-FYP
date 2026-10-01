//! The journal writer (design §7.1, §2.2 steps 7-10, INV-33).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use gate_outcome::{GateOutcome, IndeterminateKind};
use harness_core::{sha256, CallDigest, Digest, RunId, StopCause, Untrusted};
use serde_json::{Map, Value};

use crate::canon::{escape, rfc3339_utc, EventKind, Ident, RecordFields, GENESIS, INLINE_MAX};
use crate::conditions::{Condition, StandingConditions};
use crate::event::{BlobRef, Event, Trusted, UntrustedBlob};
use crate::layout;

/// Sealing (review F-3): `JournalFile` and `BlobSink` decide whether a
/// `Journaled` value means "durable", so only this crate may implement them.
/// `Sealed` is public but lives in a private module, so other crates cannot
/// name it and therefore cannot implement the seams.
mod sealed {
    pub trait Sealed {}
}
pub(crate) use sealed::Sealed;

/// The file seam (§7.1 "Testing"): the writer needs exactly these two
/// operations. **Sealed:** the implementations are [`FsFile`] and, only with
/// the `fault-injection` cargo feature (enabled by dev-dependencies), the
/// fault-injecting file in `crate::testing`. No other crate can supply a
/// `sync_data` that does nothing and still obtain `Journaled` values.
///
/// ```compile_fail,E0277
/// struct Noop;
/// impl harness_journal::JournalFile for Noop {
///     fn write_all(&mut self, _: &[u8]) -> std::io::Result<()> { Ok(()) }
///     fn sync_data(&mut self) -> std::io::Result<()> { Ok(()) }
/// }
/// ```
pub trait JournalFile: Sealed {
    /// Write the whole buffer or fail.
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()>;
    /// Make everything written so far durable.
    fn sync_data(&mut self) -> io::Result<()>;
}

/// Where large or non-UTF-8 untrusted payloads go (`blobs/<sha256>`).
/// Sealed like [`JournalFile`]: a blob store that claims durability it
/// does not have would let records cite missing evidence.
///
/// ```compile_fail,E0277
/// struct Noop;
/// impl harness_journal::BlobSink for Noop {
///     fn put(&mut self, _: &str, _: &[u8]) -> std::io::Result<()> { Ok(()) }
/// }
/// ```
pub trait BlobSink: Sealed {
    /// Store `bytes` under `name` (their SHA-256, hex) durably, or fail.
    fn put(&mut self, name: &str, bytes: &[u8]) -> io::Result<()>;
}

/// Time, passed in so records are reproducible under test.
pub trait Clock {
    /// Monotonic milliseconds since some fixed origin.
    fn mono_ms(&self) -> u64;
    /// Wall-clock Unix milliseconds.
    fn unix_ms(&self) -> u64;
}

/// `std::fs::File` as a [`JournalFile`].
#[derive(Debug)]
pub struct FsFile(File);

impl Sealed for FsFile {}

impl JournalFile for FsFile {
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        Write::write_all(&mut self.0, buf)
    }
    fn sync_data(&mut self) -> io::Result<()> {
        self.0.sync_data()
    }
}

/// A `blobs/` directory as a [`BlobSink`]: write to a temporary file,
/// `sync_data`, rename into place, then sync the directory (Unix). An
/// existing blob is accepted only if its content hashes to its name.
#[derive(Debug)]
pub struct DirBlobs {
    dir: PathBuf,
}

impl DirBlobs {
    /// Blobs under `dir` (created by the caller).
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
}

pub(crate) fn is_blob_name(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Sealed for DirBlobs {}

impl BlobSink for DirBlobs {
    fn put(&mut self, name: &str, bytes: &[u8]) -> io::Result<()> {
        if !is_blob_name(name) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad blob name"));
        }
        let target = self.dir.join(name);
        if target.exists() {
            let mut have = Vec::new();
            File::open(&target)?.read_to_end(&mut have)?;
            return if sha256(&have).to_string() == name {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "existing blob does not match its name",
                ))
            };
        }
        let tmp = self.dir.join(format!("{name}.tmp"));
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_data()?;
        drop(f);
        fs::rename(&tmp, &target)?;
        sync_dir(&self.dir)
    }
}

/// Make a directory's entries durable (review F-1): `fsync` on a file does
/// not, by POSIX, persist the directory entry that names it.
///
/// **Windows:** std cannot open a directory handle for `FlushFileBuffers`,
/// so this is a no-op there. The harness relies on NTFS journalling its
/// metadata (a created entry survives a crash once the file's own data is
/// flushed); that assumption is UNVERIFIED until the Windows CI and spike
/// S-W1 exercise it, and is recorded in the design doc (§7.1).
#[cfg(unix)]
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
pub(crate) fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// The directory-sync seam, crate-private so tests can fail it.
pub(crate) trait DirSync {
    fn sync(&self, dir: &Path) -> io::Result<()>;
}

/// The real directory sync.
pub(crate) struct RealDirSync;

impl DirSync for RealDirSync {
    fn sync(&self, dir: &Path) -> io::Result<()> {
        sync_dir(dir)
    }
}

/// `path` exists and is a real directory, not a symlink (review F-4).
fn real_dir(path: &Path) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if m.file_type().is_symlink() || !m.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a real directory (a symlink or not a directory)",
        ));
    }
    Ok(())
}

/// The system clocks.
#[derive(Debug)]
pub struct SystemClock {
    start: Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

/// The same clock serves the Meter's wall budget (F-10.9).
impl harness_core::MonoClock for SystemClock {
    fn now(&self) -> std::time::Duration {
        self.start.elapsed()
    }
}

impl Clock for SystemClock {
    fn mono_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
    fn unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
}

/// The journal header (line 0, kind `RunStarted`). `harness_version` is
/// required; the other §7.1 header fields (config, policy and manifest
/// digests, `ModelIdentity`, sandbox, OS, `shell_enabled`, protected-path
/// digests, plan digest, environment sample) are added by the run driver
/// with [`Header::field`].
#[derive(Debug)]
pub struct Header {
    fields: Vec<(&'static str, Trusted)>,
    claims: Vec<(&'static str, Untrusted<String>)>,
}

impl Header {
    /// A header for this harness version.
    pub fn new(harness_version: Ident) -> Self {
        Self {
            fields: vec![("harness_version", Trusted::Id(harness_version))],
            claims: Vec::new(),
        }
    }

    /// Add a field that is a CLAIM from outside the harness (design §3.5:
    /// what a model server says it serves). It is written as an untrusted
    /// payload (escaped inline, or a blob stored before the header), never
    /// as trusted text.
    #[must_use]
    pub fn claimed(mut self, key: &'static str, value: Untrusted<String>) -> Self {
        self.claims.push((key, value));
        self
    }

    /// Add a header field.
    #[must_use]
    pub fn field(mut self, key: &'static str, value: Trusted) -> Self {
        self.fields.push((key, value));
        self
    }
}

/// A call whose intent record is durable (design §2.2 step 7, §4.5).
///
/// The only constructor is [`JournalWriter::append_intent`], which returns
/// one only after the intent line was written AND fsynced. The fields are
/// private and the type implements no `Clone`, `Default` or serde, so a
/// `Journaled` value cannot be forged, copied or parsed back from bytes.
///
/// ```compile_fail,E0451
/// let forged = harness_journal::Journaled { call: (), intent_seq: 1, intent_hash: harness_core::sha256(b"") };
/// ```
///
/// With a concrete `Clone` payload and fully qualified `Clone::clone`, so
/// the doctest fails ONLY because `Journaled` is not `Clone` (E0277; review
/// F-2: a generic `C` and method syntax made it fail for another reason).
///
/// ```compile_fail,E0277
/// use harness_journal::Journaled;
/// fn dup(j: &Journaled<()>) -> Journaled<()> { <Journaled<()> as Clone>::clone(j) }
/// ```
#[derive(Debug)]
#[must_use = "a Journaled call exists to be executed; dropping it leaves an intent with no result"]
pub struct Journaled<C> {
    call: C,
    intent_seq: u64,
    intent_hash: Digest,
}

impl<C> Journaled<C> {
    /// The call.
    pub fn call(&self) -> &C {
        &self.call
    }
    /// Sequence number of the durable intent record.
    pub fn intent_seq(&self) -> u64 {
        self.intent_seq
    }
    /// Hash of the durable intent record.
    pub fn intent_hash(&self) -> Digest {
        self.intent_hash
    }
}

/// Why an operation on the journal failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JournalError {
    /// The writer is poisoned: an append, fsync or blob write failed, now or
    /// earlier. The run must stop with `StopCause::JournalUnavailable`.
    #[error("journal unavailable: {op} failed: {error}")]
    Unavailable {
        /// The operation that first failed.
        op: &'static str,
        /// Its error.
        error: String,
    },
    /// The event itself was refused (a harness bug, e.g. a duplicate body
    /// key or a kind that only the writer may append). Nothing was written;
    /// the writer is NOT poisoned.
    #[error("journal event refused: {0}")]
    InvalidEvent(&'static str),
}

impl JournalError {
    /// The loop's stop cause for this error (§2.5).
    pub fn stop_cause(&self) -> StopCause {
        match self {
            JournalError::Unavailable { op, error } => StopCause::JournalUnavailable {
                op: (*op).to_owned(),
                error: error.clone(),
            },
            JournalError::InvalidEvent(why) => StopCause::JournalUnavailable {
                op: "append".to_owned(),
                error: (*why).to_owned(),
            },
        }
    }

    /// The run outcome for a journal failure after the header is durable:
    /// `Indeterminate { UnreadableEvidence }` (§2.5, INV-33).
    pub fn outcome(&self) -> GateOutcome {
        GateOutcome::Indeterminate {
            why: IndeterminateKind::UnreadableEvidence,
        }
    }
}

/// The header could not be made durable: the run refuses to start (§2.5).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("journal header not durable ({op}): {error}; the run does not start")]
pub struct StartError {
    /// What failed.
    pub op: &'static str,
    /// Its error.
    pub error: String,
}

impl StartError {
    /// `Indeterminate { CouldNotRun }`: nothing has executed.
    pub fn outcome(&self) -> GateOutcome {
        GateOutcome::Indeterminate {
            why: IndeterminateKind::CouldNotRun,
        }
    }
}

/// What [`JournalWriter::commit`] releases.
#[derive(Debug)]
pub struct Released {
    /// The run's outcome: the one handed in if `RunStopped` is durable,
    /// otherwise `Indeterminate { UnreadableEvidence }`.
    pub outcome: GateOutcome,
    /// The final chain head (the `RunStopped` record's hash), for the run
    /// report and for anchoring; `None` if `RunStopped` is not durable.
    pub chain_head: Option<Digest>,
    /// The journal failure, when the outcome was downgraded.
    pub error: Option<JournalError>,
}

/// Append-only, hash-chained, per-attempt journal writer.
///
/// There is no seek, truncate, remove or rewrite in its API, and no way to
/// open an existing journal for writing: [`JournalWriter::create`] uses
/// `create_new`, so a resume writes a NEW file in a new attempt directory.
///
/// Any write, fsync or blob failure POISONS the writer: every later call
/// returns [`JournalError::Unavailable`] without touching the file, no
/// [`Journaled`] value is minted, a failed fsync is never retried, and
/// [`JournalWriter::commit`] releases `Indeterminate { UnreadableEvidence }`.
pub struct JournalWriter<F, B, K> {
    file: F,
    blobs: B,
    clock: K,
    run: RunId,
    attempt: u32,
    seq: u64,
    head: Digest,
    last_mono: u64,
    poison: Option<JournalError>,
    conditions: StandingConditions,
}

impl<F, B, K> std::fmt::Debug for JournalWriter<F, B, K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JournalWriter")
            .field("run", &self.run)
            .field("attempt", &self.attempt)
            .field("seq", &self.seq)
            .field("poisoned", &self.poison.is_some())
            .finish_non_exhaustive()
    }
}

impl JournalWriter<FsFile, DirBlobs, SystemClock> {
    /// Create `journal.jsonl` and `blobs/` in a fresh attempt directory and
    /// write the durable header. Fails if a journal already exists there:
    /// journals are never reopened for writing (resume opens a new attempt,
    /// §2.10).
    ///
    /// Order: `attempt_dir` must be a real directory (not a symlink); the
    /// journal is created with `create_new` (the single-writer point, see
    /// the crate docs); `blobs/` is created with `create_dir`, never reusing
    /// an existing entry or symlink; the attempt directory is then fsynced
    /// so both new entries are durable; only then is the header written and
    /// fsynced. Any failure is a [`StartError`]: no writer, the run does not
    /// start.
    pub fn create(
        attempt_dir: &Path,
        run: RunId,
        attempt: u32,
        header: Header,
    ) -> Result<Self, StartError> {
        Self::create_with(attempt_dir, run, attempt, header, &RealDirSync)
    }

    pub(crate) fn create_with(
        attempt_dir: &Path,
        run: RunId,
        attempt: u32,
        header: Header,
        ds: &dyn DirSync,
    ) -> Result<Self, StartError> {
        let io_err = |op, e: io::Error| StartError {
            op,
            error: e.to_string(),
        };
        real_dir(attempt_dir).map_err(|e| io_err("attempt dir", e))?;
        let file = OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(attempt_dir.join(layout::JOURNAL_FILE))
            .map_err(|e| io_err("create journal (create_new)", e))?;
        let blobs = attempt_dir.join(layout::BLOBS_DIR);
        fs::create_dir(&blobs).map_err(|e| io_err("create blobs dir", e))?;
        real_dir(&blobs).map_err(|e| io_err("create blobs dir", e))?;
        ds.sync(attempt_dir)
            .map_err(|e| io_err("fsync attempt dir", e))?;
        Self::start(
            FsFile(file),
            DirBlobs::new(blobs),
            SystemClock::default(),
            run,
            attempt,
            header,
        )
    }

    /// Open the NEXT attempt under `run_dir` (`attempt-<max+1>`), fsync
    /// `run_dir` so the new attempt's entry is durable, and start its
    /// journal. The way a resume gets a writer: it never touches an earlier
    /// attempt's journal, poisoned or not. `run_dir` itself must already
    /// exist as a real directory whose own entry the caller made durable
    /// (creating `runs/<run-id>` under `state_root` is the run driver's,
    /// H1e).
    pub fn create_next_attempt(
        run_dir: &Path,
        run: RunId,
        header: Header,
    ) -> Result<(Self, u32), StartError> {
        Self::create_next_attempt_with(run_dir, run, header, &RealDirSync, &|_| Ok(()))
    }

    /// [`JournalWriter::create_next_attempt`], running `check` on the new
    /// attempt directory after it exists and before anything is written in
    /// it (design §2.8: the filesystem-locality check runs "again on each
    /// new attempt-<n> directory", so a mount placed under the run is
    /// caught). A failed check is a [`StartError`]: no header, no writer.
    pub fn create_next_attempt_checked(
        run_dir: &Path,
        run: RunId,
        header: Header,
        check: &dyn Fn(&Path) -> Result<(), String>,
    ) -> Result<(Self, u32), StartError> {
        Self::create_next_attempt_with(run_dir, run, header, &RealDirSync, check)
    }

    /// Open the next `replay-<k>` directory under `run_dir` for an audit
    /// replay (§2.9) and start its journal, whose records carry `attempt`
    /// (the attempt being replayed) so they compare field for field with
    /// the recorded ones. A real, durable journal like any attempt's: the
    /// replay is evidence too.
    pub fn create_replay(
        run_dir: &Path,
        run: RunId,
        attempt: u32,
        header: Header,
    ) -> Result<(Self, PathBuf), StartError> {
        let io_err = |op, e: io::Error| StartError {
            op,
            error: e.to_string(),
        };
        real_dir(run_dir).map_err(|e| io_err("run dir", e))?;
        let (_, dir) =
            layout::create_next_replay(run_dir).map_err(|e| io_err("create replay dir", e))?;
        RealDirSync
            .sync(run_dir)
            .map_err(|e| io_err("fsync run dir", e))?;
        Ok((
            Self::create_with(&dir, run, attempt, header, &RealDirSync)?,
            dir,
        ))
    }

    pub(crate) fn create_next_attempt_with(
        run_dir: &Path,
        run: RunId,
        header: Header,
        ds: &dyn DirSync,
        check: &dyn Fn(&Path) -> Result<(), String>,
    ) -> Result<(Self, u32), StartError> {
        let io_err = |op, e: io::Error| StartError {
            op,
            error: e.to_string(),
        };
        real_dir(run_dir).map_err(|e| io_err("run dir", e))?;
        let (n, dir) =
            layout::create_next_attempt(run_dir).map_err(|e| io_err("create attempt dir", e))?;
        ds.sync(run_dir).map_err(|e| io_err("fsync run dir", e))?;
        check(&dir).map_err(|error| StartError {
            op: "attempt dir check",
            error,
        })?;
        Ok((Self::create_with(&dir, run, n, header, ds)?, n))
    }
}

impl<F: JournalFile, B: BlobSink, K: Clock> JournalWriter<F, B, K> {
    /// Start a journal on `file`: write the header and fsync it. If either
    /// fails there is no writer, and the run must not start (§2.5:
    /// `Indeterminate { CouldNotRun }`, see [`StartError::outcome`]).
    pub fn start(
        file: F,
        blobs: B,
        clock: K,
        run: RunId,
        attempt: u32,
        header: Header,
    ) -> Result<Self, StartError> {
        let mut w = Self {
            file,
            blobs,
            clock,
            run,
            attempt,
            seq: 0,
            head: GENESIS,
            last_mono: 0,
            poison: None,
            conditions: StandingConditions::default(),
        };
        let mut ev = Event::new(EventKind::RunStarted);
        for (k, v) in header.fields {
            ev = ev.field(k, v);
        }
        for (k, v) in &header.claims {
            let blob = w.untrusted(v).map_err(|e| StartError {
                op: "header claim",
                error: e.to_string(),
            })?;
            ev = ev.field(k, Trusted::Untrusted(blob));
        }
        let body = ev.body().map_err(|e| StartError {
            op: "header",
            error: e.to_owned(),
        })?;
        match w.write_record(0, EventKind::RunStarted, body, true) {
            Ok(_) => Ok(w),
            Err(JournalError::Unavailable { op, error }) => Err(StartError { op, error }),
            Err(JournalError::InvalidEvent(e)) => Err(StartError {
                op: "header",
                error: e.to_owned(),
            }),
        }
    }

    /// Whether the writer is poisoned.
    pub fn is_poisoned(&self) -> bool {
        self.poison.is_some()
    }

    /// The hash of the last record written.
    pub fn chain_head(&self) -> Digest {
        self.head
    }

    /// The next sequence number.
    pub fn next_seq(&self) -> u64 {
        self.seq
    }

    fn check_poison(&self) -> Result<(), JournalError> {
        match &self.poison {
            Some(p) => Err(p.clone()),
            None => Ok(()),
        }
    }

    fn poison(&mut self, op: &'static str, e: &io::Error) -> JournalError {
        let err = JournalError::Unavailable {
            op,
            error: e.to_string(),
        };
        self.poison = Some(err.clone());
        err
    }

    fn write_record(
        &mut self,
        step: u64,
        kind: EventKind,
        body: Map<String, Value>,
        fsync: bool,
    ) -> Result<(u64, Digest), JournalError> {
        self.check_poison()?;
        // Monotonic even if the clock source misbehaves.
        let mono = self.clock.mono_ms().max(self.last_mono);
        let fields = RecordFields {
            seq: self.seq,
            prev: self.head,
            t_mono_ms: mono,
            t_wall: rfc3339_utc(self.clock.unix_ms()),
            run: self.run.clone(),
            attempt: self.attempt,
            step,
            kind,
            body,
        };
        let (mut line, hash) = fields.encode();
        line.push(b'\n');
        if let Err(e) = self.file.write_all(&line) {
            return Err(self.poison("append", &e));
        }
        let seq = self.seq;
        self.seq += 1;
        self.head = hash;
        self.last_mono = mono;
        if fsync || kind.needs_fsync() {
            if let Err(e) = self.file.sync_data() {
                // Never retried on this file (§7.1): the writer is poisoned.
                return Err(self.poison("fsync", &e));
            }
        }
        Ok((seq, hash))
    }

    /// Append one event. `RunStarted`, `ToolStarted` and `RunStopped` are
    /// refused here: they are written only by [`JournalWriter::start`],
    /// [`JournalWriter::append_intent`] and [`JournalWriter::commit`].
    /// Kinds in [`EventKind::needs_fsync`] are fsynced before this returns.
    pub fn append(&mut self, step: u64, event: Event) -> Result<u64, JournalError> {
        self.check_poison()?;
        match event.kind() {
            EventKind::RunStarted | EventKind::ToolStarted | EventKind::RunStopped => {
                return Err(JournalError::InvalidEvent(
                    "RunStarted, ToolStarted and RunStopped have dedicated writer calls",
                ))
            }
            _ => {}
        }
        let body = event.body().map_err(JournalError::InvalidEvent)?;
        self.write_record(step, event.kind(), body, false)
            .map(|(seq, _)| seq)
    }

    /// Write-ahead (§2.2 step 7): append the `ToolStarted` intent carrying
    /// `call.call_digest()` (computed here from the call itself), fsync, and only when both succeeded hand back the call
    /// as [`Journaled`]. On any failure no `Journaled` exists and the writer
    /// is poisoned, so the call cannot be executed.
    pub fn append_intent<C: CallDigest>(
        &mut self,
        step: u64,
        event: Event,
        call: C,
    ) -> Result<Journaled<C>, JournalError> {
        // The digest comes from the call itself (H1c review F-7), never from
        // the caller, so the intent describes exactly what may run.
        let call_digest = call.call_digest();
        self.check_poison()?;
        if event.kind() != EventKind::ToolStarted {
            return Err(JournalError::InvalidEvent(
                "an intent is a ToolStarted event",
            ));
        }
        if event.has_key("call") {
            return Err(JournalError::InvalidEvent(
                "the intent's \"call\" digest is set by the writer",
            ));
        }
        let body = event
            .field("call", Trusted::Digest(call_digest))
            .body()
            .map_err(JournalError::InvalidEvent)?;
        let (intent_seq, intent_hash) =
            self.write_record(step, EventKind::ToolStarted, body, true)?;
        Ok(Journaled {
            call,
            intent_seq,
            intent_hash,
        })
    }

    /// Put an untrusted payload into its typed home. Payloads that are
    /// UTF-8 and at most 4 KiB are carried inline, escaped; anything else is
    /// written to the blob store first (a blob failure poisons the writer).
    pub fn untrusted<T: AsRef<[u8]>>(
        &mut self,
        payload: &Untrusted<T>,
    ) -> Result<UntrustedBlob, JournalError> {
        self.check_poison()?;
        let bytes = payload.inspect("journal: untrusted payload home").as_ref();
        let digest = sha256(bytes);
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let inline = match std::str::from_utf8(bytes) {
            Ok(s) if bytes.len() <= INLINE_MAX => Some(escape(s)),
            _ => None,
        };
        let blob = if inline.is_none() {
            let name = digest.to_string();
            if let Err(e) = self.blobs.put(&name, bytes) {
                return Err(self.poison("blob", &e));
            }
            Some(BlobRef(digest))
        } else {
            None
        };
        Ok(UntrustedBlob {
            source: payload.source().clone(),
            sha256: digest,
            len,
            inline,
            blob,
        })
    }

    /// Observe a standing condition (§2.6): a record is appended only when
    /// it begins or ends. Returns the record's seq when one was written.
    pub fn observe_condition(
        &mut self,
        step: u64,
        condition: &Condition,
        active: bool,
    ) -> Result<Option<u64>, JournalError> {
        self.check_poison()?;
        match self.conditions.observe(condition, active) {
            Some(ev) => self.append(step, ev).map(Some),
            None => Ok(None),
        }
    }

    /// The commit point (§7.1). Appends `RunStopped` carrying `cause` and
    /// `outcome`, fsyncs it, and only then releases `outcome`. If the writer
    /// is already poisoned, or this append or fsync fails, the released
    /// outcome is `Indeterminate { UnreadableEvidence }`, whatever was
    /// handed in (a `Passed` included). Consumes the writer: nothing can be
    /// appended after `RunStopped`.
    pub fn commit(
        mut self,
        step: u64,
        cause: &StopCause,
        outcome: GateOutcome,
        deliverable: Option<Digest>,
    ) -> Released {
        let downgraded = |error| Released {
            outcome: GateOutcome::Indeterminate {
                why: IndeterminateKind::UnreadableEvidence,
            },
            chain_head: None,
            error: Some(error),
        };
        if let Err(e) = self.check_poison() {
            return downgraded(e);
        }
        let mut ev = Event::new(EventKind::RunStopped)
            .field("cause", Trusted::Text(stop_cause_name(cause)))
            .field("outcome", Trusted::Text(outcome_name(&outcome)));
        if let StopCause::Budget(dim) = cause {
            ev = ev.field("dimension", Trusted::Text(budget_dim_name(*dim)));
        }
        if let Some(d) = deliverable {
            ev = ev.field("deliverable", Trusted::Digest(d));
        }
        let body = match ev.body() {
            Ok(b) => b,
            Err(e) => return downgraded(JournalError::InvalidEvent(e)),
        };
        match self.write_record(step, EventKind::RunStopped, body, true) {
            Ok((_, head)) => Released {
                outcome,
                chain_head: Some(head),
                error: None,
            },
            Err(e) => downgraded(e),
        }
    }
}

fn budget_dim_name(d: harness_core::BudgetDim) -> &'static str {
    use harness_core::BudgetDim as B;
    match d {
        B::Steps => "steps",
        B::Tokens => "tokens",
        B::Wall => "wall",
        B::Cost => "cost",
        B::FormatErrors => "format_errors",
        B::RepairRounds => "repair_rounds",
    }
}

/// Wire name of a stop cause (details that are runtime text, such as a
/// journal error message, are not journaled: a journal that just failed
/// cannot hold them anyway, §7.1 "Where the failure is reported").
pub fn stop_cause_name(c: &StopCause) -> &'static str {
    use harness_core::LoopKind as L;
    match c {
        StopCause::Submitted => "submitted",
        StopCause::Budget(_) => "budget",
        StopCause::FormatErrors => "format_errors",
        StopCause::Loop(L::Repeat) => "loop:repeat",
        StopCause::Loop(L::EditChurn) => "loop:edit_churn",
        StopCause::Loop(L::NoProgress) => "loop:no_progress",
        StopCause::Loop(L::Denied) => "loop:denied",
        StopCause::ContextExhausted => "context_exhausted",
        StopCause::PolicyAbort => "policy_abort",
        StopCause::ModelUnavailable => "model_unavailable",
        StopCause::Cancelled => "cancelled",
        StopCause::SandboxLost => "sandbox_lost",
        StopCause::JournalUnavailable { .. } => "journal_unavailable",
    }
}

/// Wire name of a gate outcome.
pub fn outcome_name(o: &GateOutcome) -> &'static str {
    match o {
        GateOutcome::Passed(_) => "passed",
        GateOutcome::Failed => "failed",
        GateOutcome::Indeterminate { why } => match why {
            IndeterminateKind::NothingChecked => "indeterminate:nothing_checked",
            IndeterminateKind::UnreadableEvidence => "indeterminate:unreadable_evidence",
            IndeterminateKind::CouldNotRun => "indeterminate:could_not_run",
            IndeterminateKind::UnsupportedOs => "indeterminate:unsupported_os",
            IndeterminateKind::StaleBinary => "indeterminate:stale_binary",
        },
    }
}
