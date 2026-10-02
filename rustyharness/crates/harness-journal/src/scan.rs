//! Read-only scan of a state root's runs (design §2.8), for `sessions` and
//! `gc`: every directory under `state_root/runs/` whose name is a
//! [`RunId`], with its latest attempt's journal read through the verifying
//! reader ([`JournalReader::open`]). Nothing is written, locked or
//! repaired: a run whose journal is broken (or absent) is *reported*, not
//! skipped — a session picker must show a broken run to be able to refuse
//! it (fail-closed).

use std::fs;
use std::io;
use std::path::Path;

use harness_core::RunId;

use crate::layout;
use crate::reader::{JournalReader, ReadError, Verified};

/// One scanned run directory.
#[derive(Debug)]
pub struct ScannedRun {
    /// The run id (the directory name, already validated).
    pub run: RunId,
    /// The latest attempt's verified journal, or why it could not be read.
    pub journal: Result<Verified, ScanError>,
}

/// Why a run's journal could not be read during a scan.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// The run directory holds no `attempt-<n>` at all.
    #[error("no attempt directory in run {0}")]
    NoAttempt(String),
    /// Reading or verifying the journal failed.
    #[error(transparent)]
    Read(#[from] ReadError),
}

/// Scan `state_root/runs/`. Directories that are not run ids (and symlinks,
/// files) are ignored; every run id directory appears exactly once, with its
/// latest attempt's journal verified.
///
/// `runs/` absent but `state_root` present is an empty scan (nothing has run
/// yet); a missing state root, a symlinked or fake `runs/` is an error.
pub fn scan_runs(state_root: &Path) -> io::Result<Vec<ScannedRun>> {
    let runs = state_root.join("runs");
    let meta = match fs::symlink_metadata(&runs) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if !fs::symlink_metadata(state_root)
                .map(|m| m.is_dir())
                .unwrap_or(false)
            {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("state root {} does not exist", state_root.display()),
                ));
            }
            return Ok(Vec::new());
        }
        Err(e) => return Err(e),
    };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runs/ is not a real directory",
        ));
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&runs)? {
        let entry = entry?;
        // `DirEntry::file_type` does not follow symlinks.
        let ft = entry.file_type()?;
        if ft.is_symlink() || !ft.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(run) = RunId::parse(name) else {
            continue;
        };
        out.push(scan_run(&runs.join(name), run));
    }
    Ok(out)
}

fn scan_run(run_dir: &Path, run: RunId) -> ScannedRun {
    let journal = match layout::latest_attempt(run_dir) {
        Ok(Some(n)) => {
            JournalReader::open(&layout::attempt_dir(run_dir, n)).map_err(ScanError::from)
        }
        Ok(None) => Err(ScanError::NoAttempt(run.as_str().to_owned())),
        Err(e) => Err(ScanError::Read(ReadError::Io(e.to_string()))),
    };
    ScannedRun { run, journal }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::{Header, JournalWriter};
    use crate::Ident;

    fn temp_root(name: &str) -> io::Result<std::path::PathBuf> {
        let base = std::env::temp_dir().join(format!("rh-scan-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base)?;
        Ok(base)
    }

    fn rid(n: u64) -> RunId {
        RunId::new(n, [0; 10])
    }

    fn make_run(state_root: &Path, run: RunId) -> io::Result<()> {
        let run_dir = state_root.join("runs").join(run.as_str());
        let attempt = run_dir.join("attempt-1");
        fs::create_dir_all(&attempt)?;
        JournalWriter::create(&attempt, run, 1, Header::new(Ident::new("0.0.1").unwrap()))
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(())
    }

    #[test]
    fn missing_state_root_is_an_error() {
        let root = temp_root("missing").unwrap();
        let _ = fs::remove_dir_all(&root);
        let err = scan_runs(&root).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn state_root_without_runs_is_empty() {
        let root = temp_root("noruns").unwrap();
        let scanned = scan_runs(&root).unwrap();
        assert!(scanned.is_empty());
    }

    #[test]
    fn non_run_entries_are_ignored() {
        let root = temp_root("noise").unwrap();
        fs::create_dir_all(root.join("runs").join("not-a-run")).unwrap();
        fs::create_dir_all(root.join("runs").join("scratch")).unwrap();
        fs::write(root.join("runs").join("notes.txt"), b"x").unwrap();
        assert!(scan_runs(&root).unwrap().is_empty());
    }

    #[test]
    fn run_without_attempt_is_reported() {
        let root = temp_root("noattempt").unwrap();
        let run = rid(7);
        fs::create_dir_all(root.join("runs").join(run.as_str())).unwrap();
        let scanned = scan_runs(&root).unwrap();
        assert_eq!(scanned.len(), 1);
        assert!(matches!(
            &scanned[0].journal,
            Err(ScanError::NoAttempt(id)) if *id == run.as_str()
        ));
    }

    #[test]
    fn journals_are_verified_not_skipped() {
        let root = temp_root("verify").unwrap();
        make_run(&root, rid(1)).unwrap();
        // A second run whose journal is tampered with after the header.
        make_run(&root, rid(2)).unwrap();
        let journal = root
            .join("runs")
            .join(rid(2).as_str())
            .join("attempt-1")
            .join("journal.jsonl");
        let mut bytes = fs::read(&journal).unwrap();
        bytes.extend(b"not json\n");
        fs::write(&journal, &bytes).unwrap();

        let mut scanned = scan_runs(&root).unwrap();
        scanned.sort_by(|a, b| a.run.as_str().cmp(b.run.as_str()));
        assert_eq!(scanned.len(), 2);
        assert!(scanned[0].journal.is_ok());
        assert!(scanned[1].journal.is_err());
    }
}
