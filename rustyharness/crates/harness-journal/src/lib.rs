//! Run journal v1: per-attempt, hash-chained, append-only JSONL evidence
//! (design `docs/01-design-v0.1.md` §7.1-§7.2, §2.2 steps 7-10, §2.5,
//! §2.6, §2.10, D14, F-01, INV-11, INV-33). Replaces the scaffold
//! `Sink`/`Event` (scaffold review F11).
//!
//! - [`JournalWriter`] owns one attempt's `journal.jsonl`. Its only
//!   operations append: [`JournalWriter::append`],
//!   [`JournalWriter::append_intent`] (write-ahead: append + fsync, THEN
//!   mint [`Journaled`]), [`JournalWriter::untrusted`] (the typed payload
//!   home, with the blob store), [`JournalWriter::observe_condition`]
//!   (standing conditions, once per state change) and
//!   [`JournalWriter::commit`] (the §7.1 commit point).
//! - Any write, fsync or blob failure poisons the writer: every later call
//!   fails without touching the file, no `Journaled` is minted, and the
//!   released outcome is `Indeterminate { UnreadableEvidence }`.
//! - The header must be durable before anything else, or there is no
//!   writer ([`StartError`], outcome `Indeterminate { CouldNotRun }`).
//!   "Durable" includes the directory entries: the run directory is fsynced
//!   after `attempt-<n>` is created, and the attempt directory after
//!   `journal.jsonl` and `blobs/` are (Windows: see `writer::sync_dir`).
//! - The `JournalFile`/`BlobSink` seams are sealed; fault-injecting
//!   implementations exist only behind the dev-only `fault-injection`
//!   feature (module `testing`).
//! - [`JournalReader`] / [`verify`] is a separate, read-only verifier that
//!   names the first broken record.
//!
//! **Pure parts.** [`canon`] (canonical encoding, the hash chain, escaping),
//! [`conditions`] and [`reader::verify`] do no I/O; only `JournalWriter`'s
//! `Fs*` seams, `DirBlobs`, `DirBlobSource`, [`layout`] and
//! `JournalReader::open` touch the filesystem.
//!
//! **Single writer, without an advisory lock (for now).** `std::fs::File::lock`
//! is stable only from Rust 1.89, and this workspace builds on 1.88
//! (`rust-version = 1.85`). Instead of a locking crate (FFI into `flock` /
//! `LockFileEx`), exclusivity comes from how a journal is created: `create_new`
//! (O_EXCL) on a fresh attempt directory, and no API anywhere reopens an
//! existing journal for writing (resume opens `attempt-<n+1>`). Two harness
//! processes therefore cannot both hold a writer for one journal. What this
//! does not stop, an advisory lock would not stop either: a non-harness
//! process writing the file (the chain detects that, INV-11). When the MSRV
//! reaches 1.89, `File::try_lock` can be added as defence in depth.

#![forbid(unsafe_code)]
// The panic-set lints ratchet production code; unit tests may assert loosely.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

pub mod canon;
pub mod conditions;
pub mod event;
pub mod layout;
pub mod reader;
#[cfg(any(test, feature = "fault-injection"))]
pub mod testing;

// The fault-injecting seams are for tests only (H1c confirming review NF-1):
// no optimised build may contain them, whatever feature forwarding enabled
// the feature. (`cargo test --release` would need debug assertions on.)
#[cfg(all(feature = "fault-injection", not(debug_assertions)))]
compile_error!(
    "harness-journal's `fault-injection` feature is test-only and refused in optimised builds"
);
pub mod writer;

pub use canon::{EventKind, Ident};
pub use conditions::{Condition, ConditionKind};
pub use event::{Event, Trusted, UntrustedBlob};
pub use reader::{verify, BlobSource, BreakKind, Broken, JournalReader, Record, Verified};
pub use writer::{
    BlobSink, Clock, Header, JournalError, JournalFile, JournalWriter, Journaled, Released,
    StartError,
};

#[cfg(test)]
mod tests;
