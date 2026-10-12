//! Journal I/O for `run-suite` and the read-side commands (docs/09): crash-safe appends, in-place
//! repair that preserves what it removes, tolerant loading, and the run lock.
//!
//! The decisions about *which lines are units* live in `bench_core::journal` (pure, tested
//! there). This module is the part that touches the filesystem:
//!
//! * [`append_line`] writes a unit as **one** `write` ending in `\n`, starts on a fresh line even
//!   if a crash left a fragment behind (so a torn fragment can never swallow the next completed
//!   unit), and `fsync`s before returning, so a line the harness has moved past is on disk.
//! * [`repair_in_place`] rewrites the journal only when something needed repairing, atomically
//!   (temp file, fsync, rename), and appends every removed line verbatim to `<journal>.quarantine`
//!   first: nothing is ever deleted without a copy.
//! * [`load_records`] / [`clean_text`] let read-only commands (`stats`, `report`, `status`,
//!   `compare`, `detect`) tolerate a torn tail or a duplicate without modifying the file, which
//!   matters because another process may be mid-append.
//! * [`Lock`] stops two `run-suite` processes interleaving into one journal, and recovers from the
//!   lock a SIGKILLed process leaves behind.

use bench_core::journal::{scan, Scan};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Make a directory entry durable: `fsync` the directory itself. A file's own `fsync` does not cover
/// the entry that names it, so after creating or renaming a file the parent must be synced too (a
/// crash can otherwise lose the whole file, or leave the old name behind). Best effort off unix.
pub fn sync_dir(path: &Path) -> std::io::Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Append one journal line. See the module docs.
pub fn append_line(out: &Path, line: &str) -> std::io::Result<()> {
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let existed = out.exists();
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(out)?;
    if !existed {
        sync_dir(out)?; // the new journal's own directory entry
    }
    let mut buf = String::with_capacity(line.len() + 2);
    if ends_without_newline(&mut f)? {
        // A previous process died mid-append. Start on a fresh line so the fragment stays its own
        // (corrupt) line instead of fusing with this unit.
        buf.push('\n');
    }
    buf.push_str(line);
    buf.push('\n');
    f.write_all(buf.as_bytes())?;
    f.sync_data()
}

/// True if the file is non-empty and its last byte is not `\n`.
fn ends_without_newline(f: &mut std::fs::File) -> std::io::Result<bool> {
    use std::io::{Read, Seek, SeekFrom};
    let len = f.metadata()?.len();
    if len == 0 {
        return Ok(false);
    }
    f.seek(SeekFrom::Start(len - 1))?;
    let mut last = [0u8; 1];
    f.read_exact(&mut last)?;
    f.seek(SeekFrom::End(0))?;
    Ok(last[0] != b'\n')
}

/// The recovered text of the journal: valid units only, duplicates dropped, no torn tail. An
/// absent journal is the empty string. Does not modify the file.
pub fn clean_text(out: &Path) -> std::io::Result<String> {
    Ok(scan_file(out)?.map(|s| s.clean).unwrap_or_default())
}

/// Scan the journal file without modifying it; `None` if it does not exist.
pub fn scan_file(out: &Path) -> std::io::Result<Option<Scan>> {
    match std::fs::read(out) {
        Ok(bytes) => Ok(Some(scan(&String::from_utf8_lossy(&bytes)))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn sibling(out: &Path, suffix: &str) -> PathBuf {
    let mut name = out
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(suffix);
    out.with_file_name(name)
}

pub fn quarantine_path(out: &Path) -> PathBuf {
    sibling(out, ".quarantine")
}

/// Repair the journal in place if it needs it. Returns the scan (its `repairs` say what was done;
/// empty means the file was not touched). Quarantined lines are appended verbatim to
/// `<journal>.quarantine` *before* the journal is replaced.
pub fn repair_in_place(out: &Path) -> std::io::Result<Scan> {
    let Some(s) = scan_file(out)? else {
        return Ok(Scan::default());
    };
    if s.is_clean() {
        return Ok(s);
    }
    if !s.quarantined.is_empty() {
        let mut q = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(quarantine_path(out))?;
        for (r, raw) in s.repairs.iter().zip(&s.quarantined) {
            writeln!(q, "# repaired {:?} (journal line {})", r.kind, r.line)?;
            writeln!(q, "{raw}")?;
        }
        q.sync_all()?;
    }
    let tmp = sibling(out, ".repair.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(s.clean.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, out)?;
    sync_dir(out)?; // the rename itself must survive a crash
    Ok(s)
}

/// Parse the recovered journal into stats records, reporting repairs on stderr. Read-only.
pub fn load_records(out: &Path) -> std::io::Result<Vec<bench_stats::Record>> {
    let Some(s) = scan_file(out)? else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "journal not found",
        ));
    };
    for line in s.summary() {
        eprintln!("journal {}: {line}", out.display());
    }
    bench_stats::parse_journal(&s.clean)
}

// ---------------------------------------------------------------------------
// The run lock
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum LockError {
    /// Another live process holds the lock.
    Held {
        pid: u32,
        path: PathBuf,
    },
    Io(std::io::Error),
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::Held { pid, path } => write!(
                f,
                "another run-suite (pid {pid}) holds {}; two runs would interleave into one journal. \
                 If that process is gone and its pid was reused, delete the lock file",
                path.display()
            ),
            LockError::Io(e) => write!(f, "lock: {e}"),
        }
    }
}

impl std::error::Error for LockError {}

impl From<std::io::Error> for LockError {
    fn from(e: std::io::Error) -> Self {
        LockError::Io(e)
    }
}

/// Holds `<journal>.lock` (containing this process id) until dropped.
#[derive(Debug)]
pub struct Lock {
    path: PathBuf,
    pid: u32,
}

impl Drop for Lock {
    fn drop(&mut self) {
        // Remove it only if it is still ours.
        if std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok())
            == Some(self.pid)
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Whether a process with this id exists. `kill -0` sends nothing; it only asks.
fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(true)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true // cannot verify: refuse rather than risk two writers
    }
}

pub fn lock_path(out: &Path) -> PathBuf {
    sibling(out, ".lock")
}

/// Take the run lock. Returns the lock and, if it replaced a stale one, a note saying so.
pub fn acquire(out: &Path) -> Result<(Lock, Option<String>), LockError> {
    acquire_as(out, std::process::id())
}

/// As [`acquire`] with an explicit pid (tests).
pub fn acquire_as(out: &Path, pid: u32) -> Result<(Lock, Option<String>), LockError> {
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let path = lock_path(out);
    let mut note = None;
    for _ in 0..3 {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                writeln!(f, "{pid}")?;
                f.sync_all()?;
                sync_dir(&path)?;
                return Ok((Lock { path, pid }, note));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                match text.trim().parse::<u32>() {
                    Ok(holder) if holder != pid && pid_alive(holder) => {
                        return Err(LockError::Held { pid: holder, path });
                    }
                    Ok(holder) => {
                        // Dead holder (or a leftover of this very pid): a SIGKILLed run.
                        note = Some(format!(
                            "removed stale lock left by pid {holder} (process no longer exists)"
                        ));
                    }
                    Err(_) => {
                        // Unparseable or empty: a lock being written right now, or garbage.
                        // Fresh = held; old = stale.
                        let age = std::fs::metadata(&path)
                            .and_then(|m| m.modified())
                            .ok()
                            .and_then(|t| t.elapsed().ok())
                            .unwrap_or_default();
                        if age < std::time::Duration::from_secs(10) {
                            return Err(LockError::Held { pid: 0, path });
                        }
                        note = Some("removed stale lock with unreadable contents".to_string());
                    }
                }
                let _ = std::fs::remove_file(&path);
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(LockError::Io(std::io::Error::other(
        "could not take the run lock after removing a stale one (another process won the race)",
    )))
}

// ---------------------------------------------------------------------------
// Heterogeneity gates and taint (docs/09 "Resume validity gates")
// ---------------------------------------------------------------------------

/// What a journal line recorded about where and by what it was produced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Identity {
    pub model_name: Option<String>,
    pub hw_class: Option<String>,
    pub harness: Option<String>,
}

/// The distinct identities recorded for `epoch` in recovered journal text, by field.
pub fn recorded_identity(clean: &str, epoch: &str) -> Vec<Identity> {
    let mut out: Vec<Identity> = Vec::new();
    for line in clean.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if v.get("epoch").and_then(|e| e.as_str()).unwrap_or("local") != epoch {
            continue;
        }
        let id = Identity {
            model_name: v["model"]["name"].as_str().map(str::to_string),
            hw_class: v["hw_class"].as_str().map(str::to_string),
            harness: v["harness"].as_str().map(str::to_string),
        };
        if !out.contains(&id) {
            out.push(id);
        }
    }
    out
}

/// Fields on which `current` differs from anything already recorded. A field the journal never
/// recorded (older lines) cannot mismatch.
pub fn mismatches(recorded: &[Identity], current: &Identity) -> Vec<String> {
    let mut m = Vec::new();
    let differs = |get: fn(&Identity) -> &Option<String>| {
        let cur = get(current);
        cur.is_some()
            && recorded
                .iter()
                .filter_map(|r| get(r).as_ref())
                .any(|r| Some(r) != cur.as_ref())
    };
    if differs(|i| &i.model_name) {
        m.push(format!(
            "model name: journal has {:?}, this run is {:?}",
            distinct(recorded, |i| &i.model_name),
            current.model_name.as_deref().unwrap_or("")
        ));
    }
    if differs(|i| &i.hw_class) {
        m.push(format!(
            "hardware class: journal has {:?}, this machine is {:?}",
            distinct(recorded, |i| &i.hw_class),
            current.hw_class.as_deref().unwrap_or("")
        ));
    }
    if differs(|i| &i.harness) {
        m.push(format!(
            "harness version: journal has {:?}, this binary is {:?}",
            distinct(recorded, |i| &i.harness),
            current.harness.as_deref().unwrap_or("")
        ));
    }
    m
}

fn distinct(rec: &[Identity], get: fn(&Identity) -> &Option<String>) -> Vec<String> {
    let mut v: Vec<String> = rec.iter().filter_map(|r| get(r).clone()).collect();
    v.sort();
    v.dedup();
    v
}

pub fn taint_path(out: &Path) -> PathBuf {
    sibling(out, ".tainted")
}

/// Record that a run was continued across a mismatch. Append-only and never removed: docs/09
/// "There is no way to un-taint a run".
pub fn add_taint(out: &Path, reasons: &[String]) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(taint_path(out))?;
    for r in reasons {
        writeln!(f, "{r}")?;
    }
    f.sync_all()
}

pub fn taint_reasons(out: &Path) -> Vec<String> {
    std::fs::read_to_string(taint_path(out))
        .map(|t| t.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rb-journal-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn unit(id: &str) -> String {
        format!(r#"{{"schema":1,"unit_id":"{id}","task_id":"f/0","oracle":{{"score":1.0}}}}"#)
    }

    #[test]
    fn sync_dir_syncs_the_parent_and_reports_a_missing_one() {
        let d = dir("syncdir");
        let f = d.join("x.jsonl");
        std::fs::write(&f, "x").unwrap();
        sync_dir(&f).unwrap();
        assert!(sync_dir(&d.join("no-such-dir/y")).is_err());
        sync_dir(Path::new("relative-file-name")).unwrap(); // parent is the cwd
    }

    #[test]
    fn append_creates_parents_and_writes_one_line_per_call() {
        let d = dir("append");
        let j = d.join("a/b/j.jsonl");
        append_line(&j, &unit("a")).unwrap();
        append_line(&j, &unit("b")).unwrap();
        let t = std::fs::read_to_string(&j).unwrap();
        assert_eq!(t.lines().count(), 2);
        assert!(t.ends_with('\n'));
        assert!(scan_file(&j).unwrap().unwrap().is_clean());
    }

    #[test]
    fn append_after_a_torn_tail_does_not_fuse_with_the_fragment() {
        let d = dir("fuse");
        let j = d.join("j.jsonl");
        append_line(&j, &unit("a")).unwrap();
        // simulate SIGKILL mid-append: a fragment with no newline
        let mut f = std::fs::OpenOptions::new().append(true).open(&j).unwrap();
        f.write_all(&unit("lost").as_bytes()[..30]).unwrap();
        drop(f);
        append_line(&j, &unit("b")).unwrap();
        let s = scan_file(&j).unwrap().unwrap();
        assert_eq!(
            s.units,
            2,
            "the next completed unit is not swallowed: {:?}",
            s.summary()
        );
        assert!(s.clean.contains("\"b\"") && !s.clean.contains("lost"));
        // and it is a corrupt line in its own right, not a glued one
        assert_eq!(s.repairs.len(), 1);
        assert_eq!(
            s.repairs[0].kind,
            bench_core::journal::RepairKind::CorruptLine
        );
    }

    #[test]
    fn repair_in_place_preserves_what_it_removes_and_is_idempotent() {
        let d = dir("repair");
        let j = d.join("j.jsonl");
        let text = format!(
            "{}\ngarbage line\n{}\n{}\n{}",
            unit("a"),
            unit("b"),
            unit("a"),
            &unit("c")[..25]
        );
        std::fs::write(&j, &text).unwrap();
        let s = repair_in_place(&j).unwrap();
        assert_eq!(s.units, 2);
        assert_eq!(s.repairs.len(), 3, "{:?}", s.summary());
        let now = std::fs::read_to_string(&j).unwrap();
        assert_eq!(now.lines().count(), 2);
        assert!(scan(&now).is_clean());
        let q = std::fs::read_to_string(quarantine_path(&j)).unwrap();
        assert!(q.contains("garbage line"), "{q}");
        assert!(
            q.contains(&unit("c")[..25]),
            "the torn tail is kept, not lost: {q}"
        );
        assert!(q.contains("Duplicate"), "{q}");
        // second repair: nothing to do, file and quarantine untouched
        let before_q = q.clone();
        let s2 = repair_in_place(&j).unwrap();
        assert!(s2.is_clean());
        assert_eq!(
            std::fs::read_to_string(quarantine_path(&j)).unwrap(),
            before_q
        );
        assert!(
            !sibling(&j, ".repair.tmp").exists(),
            "temp file renamed away"
        );
    }

    #[test]
    fn repair_of_a_clean_or_missing_journal_touches_nothing() {
        let d = dir("noop");
        let j = d.join("j.jsonl");
        assert!(repair_in_place(&j).unwrap().is_clean());
        assert!(!j.exists());
        std::fs::write(&j, format!("{}\n", unit("a"))).unwrap();
        let mtime = std::fs::metadata(&j).unwrap().modified().unwrap();
        assert!(repair_in_place(&j).unwrap().is_clean());
        assert_eq!(std::fs::metadata(&j).unwrap().modified().unwrap(), mtime);
        assert!(!quarantine_path(&j).exists());
    }

    #[test]
    fn read_side_loading_tolerates_damage_without_modifying_the_file() {
        let d = dir("load");
        let j = d.join("j.jsonl");
        let text = format!(
            "{}\n{}\n{}",
            r#"{"task_id":"f/0","category":"c","oracle":{"apply_ok":true,"compile_ok":true,"error_codes":[],"warn_count":0,"behavior":{},"constraint":{"violations":[]},"score":1.0,"failure_class":"none","flags":[]},"unit_id":"a"}"#,
            r#"{"task_id":"f/1","category":"c","oracle":{"apply_ok":true,"compile_ok":true,"error_codes":[],"warn_count":0,"behavior":{},"constraint":{"violations":[]},"score":1.0,"failure_class":"none","flags":[]},"unit_id":"a"}"#,
            "{\"task_id\":\"f/2\",\"cat"
        );
        std::fs::write(&j, &text).unwrap();
        let recs = load_records(&j).unwrap();
        assert_eq!(
            recs.len(),
            1,
            "duplicate unit_id counted once, torn tail ignored"
        );
        assert_eq!(std::fs::read_to_string(&j).unwrap(), text, "read-only");
        assert_eq!(
            load_records(&d.join("nope.jsonl")).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }

    // ---- lock ----

    #[test]
    fn a_live_holder_blocks_a_second_run_and_drop_releases() {
        let d = dir("lock-live");
        let j = d.join("j.jsonl");
        let (l1, note) = acquire_as(&j, std::process::id()).unwrap();
        assert!(note.is_none());
        // a different pid asking while the first (this process) is alive
        let e = acquire_as(&j, 999_999_999).unwrap_err();
        assert!(
            matches!(e, LockError::Held { pid, .. } if pid == std::process::id()),
            "{e}"
        );
        assert!(e.to_string().contains("interleave"));
        drop(l1);
        assert!(!lock_path(&j).exists(), "released on drop");
        assert!(acquire_as(&j, 999_999_999).is_ok());
    }

    #[test]
    fn a_stale_lock_from_a_dead_process_is_taken_over_and_reported() {
        let d = dir("lock-stale");
        let j = d.join("j.jsonl");
        // a pid that cannot exist (above any pid_max)
        std::fs::write(lock_path(&j), "2147483000\n").unwrap();
        let (l, note) = acquire(&j).unwrap();
        let note = note.expect("the takeover is reported");
        assert!(
            note.contains("stale lock") && note.contains("2147483000"),
            "{note}"
        );
        assert_eq!(
            std::fs::read_to_string(lock_path(&j)).unwrap().trim(),
            std::process::id().to_string()
        );
        drop(l);
    }

    #[test]
    fn an_unreadable_lock_is_held_while_fresh_and_stale_once_old() {
        let d = dir("lock-garbage");
        let j = d.join("j.jsonl");
        std::fs::write(lock_path(&j), "").unwrap(); // being written right now
        assert!(matches!(acquire(&j), Err(LockError::Held { pid: 0, .. })));
        // age it
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
        std::fs::File::options()
            .write(true)
            .open(lock_path(&j))
            .unwrap()
            .set_modified(old)
            .unwrap();
        let (_l, note) = acquire(&j).unwrap();
        assert!(note.unwrap().contains("unreadable"));
    }

    #[test]
    fn dropping_a_lock_never_removes_someone_elses() {
        let d = dir("lock-theirs");
        let j = d.join("j.jsonl");
        let (l, _) = acquire_as(&j, 4242).unwrap();
        std::fs::write(lock_path(&j), "777\n").unwrap(); // someone replaced it
        drop(l);
        assert!(lock_path(&j).exists());
    }

    // ---- gates ----

    fn line(epoch: &str, model: &str, hw: &str, harness: Option<&str>) -> String {
        let h = harness
            .map(|h| format!(r#","harness":"{h}""#))
            .unwrap_or_default();
        format!(
            r#"{{"unit_id":"{model}{hw}","epoch":"{epoch}","hw_class":"{hw}","model":{{"name":"{model}"}},"oracle":{{}}{h}}}"#
        )
    }

    #[test]
    fn identity_is_read_per_epoch_and_mismatches_name_the_field() {
        let clean = format!(
            "{}\n{}\n",
            line("e1", "qwen", "unified-32", Some("0.0.1")),
            line("other", "llama", "vram-24", None)
        );
        let rec = recorded_identity(&clean, "e1");
        assert_eq!(rec.len(), 1);
        let same = Identity {
            model_name: Some("qwen".into()),
            hw_class: Some("unified-32".into()),
            harness: Some("0.0.1".into()),
        };
        assert!(mismatches(&rec, &same).is_empty());
        let other = Identity {
            model_name: Some("llama".into()),
            hw_class: Some("vram-24".into()),
            harness: Some("0.0.2".into()),
        };
        let m = mismatches(&rec, &other);
        assert_eq!(m.len(), 3, "{m:?}");
        assert!(
            m[0].starts_with("model name")
                && m[1].starts_with("hardware class")
                && m[2].starts_with("harness version")
        );
        // lines that predate a field cannot mismatch on it; a new epoch has no history
        assert!(mismatches(
            &recorded_identity(&clean, "other"),
            &Identity {
                harness: Some("9".into()),
                ..Default::default()
            }
        )
        .is_empty());
        assert!(mismatches(&recorded_identity(&clean, "fresh"), &other).is_empty());
    }

    #[test]
    fn taint_is_append_only_and_readable() {
        let d = dir("taint");
        let j = d.join("j.jsonl");
        assert!(taint_reasons(&j).is_empty());
        add_taint(&j, &["a".into()]).unwrap();
        add_taint(&j, &["b".into(), "c".into()]).unwrap();
        assert_eq!(taint_reasons(&j), vec!["a", "b", "c"]);
    }
}

// ---------------------------------------------------------------------------
// `rustybench journal`
// ---------------------------------------------------------------------------

/// `rustybench journal --journal J [--repair]`: say what recovery would do to a journal, and with
/// `--repair` do it (quarantining, never deleting). Takes the run lock for `--repair`.
#[derive(clap::Args, Debug)]
pub struct JournalArgs {
    #[arg(long, default_value = "runs/journal.jsonl")]
    pub journal: PathBuf,
    /// Rewrite the journal in place (the removed lines are kept in `<journal>.quarantine`).
    #[arg(long)]
    pub repair: bool,
}

pub fn journal_cmd(a: &JournalArgs) -> Result<(), Box<dyn std::error::Error>> {
    let _lock = if a.repair {
        Some(acquire(&a.journal)?)
    } else {
        None
    };
    let s = if a.repair {
        repair_in_place(&a.journal)?
    } else {
        match scan_file(&a.journal)? {
            Some(s) => s,
            None => {
                println!("no journal at {} yet", a.journal.display());
                return Ok(());
            }
        }
    };
    println!("{}: {} completed unit(s)", a.journal.display(), s.units);
    if s.is_clean() {
        println!("  clean: nothing to repair");
    }
    for l in s.summary() {
        println!(
            "  {}: {l}",
            if a.repair { "repaired" } else { "would repair" }
        );
    }
    if !s.is_clean() && !a.repair {
        println!(
            "  re-run with --repair to apply (removed lines are kept in {})",
            quarantine_path(&a.journal).display()
        );
    }
    for r in taint_reasons(&a.journal) {
        println!("  TAINTED: {r}");
    }
    Ok(())
}
