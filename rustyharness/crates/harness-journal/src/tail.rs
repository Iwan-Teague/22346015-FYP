//! The tailing reader for a live journal (`events --follow`, slice P-15).
//!
//! A [`JournalTail`] re-reads and re-verifies the whole `journal.jsonl` on
//! every [`JournalTail::poll`] — the same `verify` the one-shot reader
//! uses, so a record is only ever emitted once it verifies, and a torn
//! final line (a crash mid-append, or a writer still mid-line) is never
//! emitted: it becomes part of the verified prefix only once the newline
//! arrives. Fail-closed, like the reader: any break, a shrunken file (an
//! edit or a replace), or a journal that does not belong to the attempt
//! directory ends the tail with an error. The full re-read keeps the
//! reader simple and honest; journals are small (§7.1), so this is the
//! right trade for v0.1.

use std::fs;
use std::path::{Path, PathBuf};

use crate::layout;
use crate::reader::{broken, require_real, verify, DirBlobSource, ReadError, Record, Verified};

/// One [`JournalTail::poll`]: the records not seen before, and the latest
/// verification of the whole file (which says whether the run committed).
#[derive(Debug)]
pub struct Poll {
    /// Records with a seq no earlier poll reported, in order.
    pub new_records: Vec<Record>,
    /// The verification this poll is based on.
    pub verified: Verified,
}

impl Poll {
    /// Whether the journal ends with a durable `RunStopped` (the run is
    /// committed; no further records can arrive).
    pub fn is_complete(&self) -> bool {
        self.verified.is_complete()
    }
}

/// A live attempt journal being tailed. Opened with the same checks as
/// [`crate::JournalReader::open`] (an `attempt-<n>` directory, no
/// symlinks), then polled.
#[derive(Debug)]
pub struct JournalTail {
    attempt_dir: PathBuf,
    attempt: u32,
    next_seq: u64,
    last_len: usize,
}

impl JournalTail {
    /// Bind a tail to `attempt_dir`, which must be named `attempt-<n>` and
    /// hold a real (non-symlink) `journal.jsonl` and `blobs/`.
    pub fn open(attempt_dir: &Path) -> Result<Self, ReadError> {
        let n = attempt_dir
            .file_name()
            .and_then(|s| s.to_str())
            .and_then(layout::parse_attempt_name)
            .ok_or(ReadError::NotAnAttemptDir)?;
        require_real(attempt_dir, true, "attempt dir")?;
        require_real(
            &attempt_dir.join(layout::JOURNAL_FILE),
            false,
            "journal.jsonl",
        )?;
        require_real(&attempt_dir.join(layout::BLOBS_DIR), true, "blobs dir")?;
        Ok(Self {
            attempt_dir: attempt_dir.to_path_buf(),
            attempt: n,
            next_seq: 0,
            last_len: 0,
        })
    }

    /// Re-read and re-verify the journal; return the records no earlier
    /// poll reported. The file never having shrunk is checked before the
    /// verification, so a replaced (shorter) journal is refused even when
    /// it would verify on its own.
    pub fn poll(&mut self) -> Result<Poll, ReadError> {
        let journal = self.attempt_dir.join(layout::JOURNAL_FILE);
        let meta = fs::symlink_metadata(&journal).map_err(|e| ReadError::Io(e.to_string()))?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(ReadError::NotReal("journal.jsonl"));
        }
        let bytes = fs::read(&journal).map_err(|e| ReadError::Io(e.to_string()))?;
        if bytes.len() < self.last_len {
            return Err(ReadError::Io(format!(
                "journal.jsonl shrank from {} to {} bytes",
                self.last_len,
                bytes.len()
            )));
        }
        let v = verify(
            &bytes,
            &DirBlobSource::new(self.attempt_dir.join(layout::BLOBS_DIR)),
        )?;
        if v.attempt != u64::from(self.attempt) {
            return Err(broken(0, crate::reader::BreakKind::WrongAttempt).into());
        }
        let from = self.next_seq as usize;
        let Some(rest) = v.records.get(from..) else {
            return Err(ReadError::Io(format!(
                "journal now has fewer records ({}) than already reported ({})",
                v.records.len(),
                from
            )));
        };
        let poll = Poll {
            new_records: rest.to_vec(),
            verified: v,
        };
        self.next_seq = poll.verified.records.len() as u64;
        self.last_len = bytes.len();
        Ok(poll)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harness_core::RunId;
    use serde_json::{Map, Value};

    use crate::canon::{EventKind, RecordFields, GENESIS};

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!(
                "harness-journal-tail-test-{tag}-{}-{n}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn chain(kinds: &[EventKind]) -> Vec<u8> {
        let run = RunId::new(1, [0; 10]);
        let mut out = Vec::new();
        let mut prev = GENESIS;
        for (i, kind) in kinds.iter().enumerate() {
            let fields = RecordFields {
                seq: i as u64,
                prev,
                t_mono_ms: 10 * (i as u64 + 1),
                t_wall: "2026-01-01T00:00:00.000Z".into(),
                run: run.clone(),
                attempt: 1,
                step: 0,
                kind: *kind,
                body: Map::<String, Value>::new(),
            };
            let (line, hash) = fields.encode();
            out.extend_from_slice(&line);
            out.push(b'\n');
            prev = hash;
        }
        out
    }

    fn attempt(t: &TempDir) -> std::path::PathBuf {
        let dir =
            t.0.join("runs")
                .join(RunId::new(1, [0; 10]).as_str())
                .join("attempt-1");
        std::fs::create_dir_all(dir.join("blobs")).unwrap();
        dir
    }

    fn write(attempt: &Path, bytes: &[u8]) {
        std::fs::write(attempt.join(layout::JOURNAL_FILE), bytes).unwrap();
    }

    #[test]
    fn tail_poll_emits_only_new_records_and_sees_completion() {
        let t = TempDir::new("follow");
        let dir = attempt(&t);
        write(&dir, &chain(&[EventKind::RunStarted]));
        let mut tail = JournalTail::open(&dir).unwrap();
        let p = tail.poll().unwrap();
        assert_eq!(p.new_records.len(), 1);
        assert!(!p.is_complete());
        // Polling again without growth reports nothing new.
        assert!(tail.poll().unwrap().new_records.is_empty());
        write(
            &dir,
            &chain(&[EventKind::RunStarted, EventKind::ContextBuilt]),
        );
        let p = tail.poll().unwrap();
        assert_eq!(p.new_records.len(), 1);
        assert_eq!(p.new_records[0].kind, EventKind::ContextBuilt);
        write(
            &dir,
            &chain(&[
                EventKind::RunStarted,
                EventKind::ContextBuilt,
                EventKind::RunStopped,
            ]),
        );
        let p = tail.poll().unwrap();
        assert_eq!(p.new_records.len(), 1);
        assert!(p.is_complete());
    }

    #[test]
    fn tail_poll_never_emits_a_torn_final_line() {
        let t = TempDir::new("torn");
        let dir = attempt(&t);
        let two = chain(&[EventKind::RunStarted, EventKind::ContextBuilt]);
        // Cut just after line 0, leaving line 1 torn (no newline yet).
        let split = two.iter().position(|b| *b == b'\n').unwrap() + 1;
        write(&dir, &two[..split]);
        let mut tail = JournalTail::open(&dir).unwrap();
        let p = tail.poll().unwrap();
        assert_eq!(p.new_records.len(), 1, "only the complete line");
        // The torn half-line arrives in full (plus more records): now it is
        // emitted, exactly once.
        write(
            &dir,
            &chain(&[
                EventKind::RunStarted,
                EventKind::ContextBuilt,
                EventKind::RunStopped,
            ]),
        );
        let p = tail.poll().unwrap();
        assert_eq!(p.new_records.len(), 2);
        assert_eq!(p.new_records[0].kind, EventKind::ContextBuilt);
        assert_eq!(p.new_records[1].kind, EventKind::RunStopped);
        assert!(p.is_complete());
    }

    #[test]
    fn tail_poll_refuses_a_broken_or_shrunk_journal() {
        let t = TempDir::new("broken");
        let dir = attempt(&t);
        let good = chain(&[EventKind::RunStarted, EventKind::ContextBuilt]);
        write(&dir, &good);
        let mut tail = JournalTail::open(&dir).unwrap();
        assert!(tail.poll().is_ok());
        // Same length, edited bytes: a break, named by the verifier.
        let mut evil = good.clone();
        let at = evil.iter().position(|b| *b == b'R').unwrap();
        evil[at] = b'X';
        write(&dir, &evil);
        assert!(matches!(tail.poll(), Err(ReadError::Broken(_))));
        // Whole-file truncation (shrink) is refused before verification.
        write(&dir, &good[..good.len() / 2]);
        let res = tail.poll();
        assert!(
            matches!(&res, Err(ReadError::Io(m)) if m.contains("shrank")),
            "expected a shrink refusal, got {res:?}"
        );
    }

    #[test]
    fn tail_open_refuses_an_unbound_directory() {
        let t = TempDir::new("unbind");
        let dir = attempt(&t);
        write(&dir, &chain(&[EventKind::RunStarted]));
        // Another attempt number's directory is not this journal's home.
        let wrong = dir.parent().unwrap().join("attempt-2");
        let _ = std::fs::create_dir_all(wrong.join("blobs"));
        assert!(JournalTail::open(&wrong).is_err());
        // Not an attempt directory at all.
        assert!(JournalTail::open(dir.parent().unwrap()).is_err());
    }

    #[test]
    fn line_bytes_round_trips_to_the_journals_own_line() {
        let t = TempDir::new("lines");
        let dir = attempt(&t);
        let bytes = chain(&[EventKind::RunStarted, EventKind::RunStopped]);
        write(&dir, &bytes);
        let v = crate::JournalReader::open(&dir).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        for (i, line) in text.lines().enumerate() {
            assert_eq!(v.line_bytes(i).unwrap(), line.as_bytes(), "record {i}");
        }
        assert!(v.line_bytes(2).is_none());
    }
}
