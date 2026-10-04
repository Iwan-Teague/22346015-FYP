//! The confined helper as the tools' [`FileOps`] (P-36f), against the real
//! stub under its own Seatbelt profile (macOS only, like the helper's
//! conformance suite): the helper's `tree` op digests to the in-process
//! walk's digest, the op-by-op mapping lands what it says (a write through
//! the helper is a create or a digest-checked replace, `create_dir` makes
//! the directory, removals are digest-checked), a foreign change between a
//! read and a rewrite is refused instead of clobbered, three lost calls
//! set the run's stop flag, and a call past its deadline ends in
//! `TimedOut` inside the wall.

#![cfg(target_os = "macos")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use harness_sandbox::fileop::FileOpHelper;
use harness_sandbox::seatbelt::Seatbelt;
use harness_sandbox::{Backend, ConfinedSpec, Conformed, Limits, Network};
use harness_tools::builtin::workspace_tree;
use harness_tools::file_ops::{Confined, FileOps};

const WALL: Duration = Duration::from_secs(60);
const SWEEP: Duration = Duration::from_secs(3);
/// The tests' own request deadline: far under the wall, so a hanging call
/// ends inside it.
const DEADLINE: Duration = Duration::from_millis(400);

fn witness() -> &'static Conformed {
    static W: OnceLock<Conformed> = OnceLock::new();
    W.get_or_init(|| Seatbelt::new().probe().expect("the live probe must pass"))
}

/// A fresh workspace: a few files, a nested directory, a symlink, nothing
/// the stub or the walk would refuse.
struct Ws(PathBuf);

impl Ws {
    fn new(name: &str) -> Ws {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        let ws = base.join(format!(
            "rh-confined-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(ws.join("sub")).unwrap();
        fs::write(ws.join("a.txt"), b"alpha\n").unwrap();
        fs::write(ws.join("sub").join("b.txt"), b"beta gamma\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("a.txt", ws.join("link.txt")).unwrap();
        Ws(ws)
    }

    fn rw_spec(&self) -> ConfinedSpec {
        ConfinedSpec {
            argv: vec!["/usr/bin/perl".into()],
            cwd: self.0.clone(),
            env: vec![],
            read_only: vec![],
            read_write: vec![self.0.clone()],
            protected: vec![],
            network: Network::None,
            limits: Limits::wall(WALL),
        }
    }

    fn confined(&self, stop: Arc<AtomicBool>) -> Confined {
        let helper = FileOpHelper::start(
            &self.rw_spec(),
            witness(),
            None,
            &std::env::temp_dir(),
            SWEEP,
        )
        .expect("the helper must start");
        Confined::new(self.0.clone(), helper, DEADLINE, stop)
    }
}

fn stop_flag() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

fn stop_pid(pid: u32) {
    Command::new("/bin/kill")
        .args(["-STOP", &pid.to_string()])
        .status()
        .expect("kill must run");
}

// INV-42's planning half, and the slice's own equality: the digest a
// fresh in-process walk measures equals the digest the helper's `tree` op
// returns, over the same tree.
#[test]
fn helper_tree_digest_equals_in_process_digest() {
    let ws = Ws::new("tree");
    let confined = ws.confined(stop_flag());
    let mut confined = confined;
    let via_helper = confined
        .tree(Duration::from_secs(30))
        .expect("the helper's tree op must serve the walk");
    let in_process = workspace_tree(&ws.0, Instant::now() + Duration::from_secs(30))
        .expect("the in-process walk must serve the same tree");
    assert_eq!(via_helper.digest(), in_process.digest());
}

// The op-by-op mapping: create, replace, read, list, lstat, create_dir,
// remove_file, remove_dir land, and the facts read back through the same
// helper agree with what the in-process implementation reports.
#[test]
fn confined_ops_match_in_process_ops() {
    let ws = Ws::new("ops");
    let flag = stop_flag();
    let mut ops: Box<dyn FileOps> = Box::new(ws.confined(Arc::clone(&flag)));

    // Create (the exclusive-create half of write_atomic), with the mode
    // the caller passes.
    let new = ws.0.join("new.txt");
    ops.write_atomic(&new, b"fresh\n", Some(0o600)).unwrap();
    assert_eq!(fs::read(&new).unwrap(), b"fresh\n");
    assert_eq!(ops.lstat(&new).unwrap().mode, Some(0o600));

    // Replace (the digest-checked half): the bytes the helper last served
    // are the ones replaced, and the stub keeps the old mode at the rename
    // (the callers pass it back anyway).
    ops.write_atomic(&new, b"second\n", None).unwrap();
    assert_eq!(fs::read(&new).unwrap(), b"second\n");

    // Read: what the helper serves is what is on disk.
    let bytes = ops.read(&new, 1024, None).unwrap();
    assert_eq!(bytes, b"second\n");

    let meta = ops.lstat(&new).unwrap();
    assert!(meta.kind.is_file());
    assert_eq!(meta.len, 7);
    assert_eq!(meta.mode, Some(0o600));

    // list: both names under the root, as entries with facts.
    let mut names: Vec<String> = Vec::new();
    ops.list(&ws.0, &mut |step| {
        if let harness_tools::file_ops::Step::Entry(e) = step {
            names.push(e.name);
        }
        harness_tools::file_ops::Next::Continue
    })
    .unwrap();
    names.sort();
    assert!(names.contains(&"a.txt".to_owned()), "{names:?}");
    assert!(names.contains(&"sub".to_owned()), "{names:?}");
    assert!(names.contains(&"link.txt".to_owned()), "{names:?}");

    // create_dir: the marker trick leaves the directory behind.
    let dir = ws.0.join("made");
    ops.create_dir(&dir).unwrap();
    assert!(dir.is_dir());
    assert!(ops.create_dir(&dir).is_err(), "an existing dir is refused");

    // remove_file and remove_dir.
    ops.remove_file(&new).unwrap();
    assert!(!new.exists());
    ops.remove_dir(&dir).unwrap();
    assert!(!dir.exists());

    assert!(!flag.load(Ordering::SeqCst));
}

// §7.4's stale check through the helper: a rewrite whose digest is the
// one the helper last served refuses after a foreign change, and the
// file keeps the foreign bytes (never clobbered).
#[test]
fn replace_through_helper_refuses_a_foreign_change() {
    let ws = Ws::new("stale");
    let mut ops: Box<dyn FileOps> = Box::new(ws.confined(stop_flag()));
    let f = ws.0.join("a.txt");
    // The helper serves the bytes once (digest cached).
    let served = ops.read(&f, 1024, None).unwrap();
    assert_eq!(served, b"alpha\n");
    // A foreign hand changes the file behind the helper's back.
    fs::write(&f, b"pirate\n").unwrap();
    // The stale rewrite is refused; the pirate bytes survive.
    let e = ops
        .write_atomic(&f, b"ours\n", None)
        .expect_err("a stale replace must be refused");
    assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");
    assert_eq!(fs::read(&f).unwrap(), b"pirate\n");
    // Reading fresh re-arms the digest: the honest rewrite lands.
    let fresh = ops.read(&f, 1024, None).unwrap();
    assert_eq!(fresh, b"pirate\n");
    ops.write_atomic(&f, b"ours\n", None).unwrap();
    assert_eq!(fs::read(&f).unwrap(), b"ours\n");
}

// §7.5: three lost calls in one attempt set the stop flag (the driver
// turns that into SandboxLost); a lost call is an ordinary error until
// then, and the helper restarts at the next call by itself.
#[test]
fn helper_lost_three_times_stops_sandbox_lost() {
    let ws = Ws::new("lost");
    let flag = stop_flag();
    let confined = ws.confined(Arc::clone(&flag));
    let mut ops = confined.clone_box();
    let f = ws.0.join("a.txt");

    // One live call first: the stub is up.
    ops.lstat(&f).unwrap();
    let mut losses = 0;
    for _ in 0..12 {
        if flag.load(Ordering::SeqCst) {
            break;
        }
        // Freeze the running stub, if one is running: its next request
        // runs past the deadline (a loss), and the request after that
        // restarts a fresh stub.
        if let Some(pid) = confined.stub_pid() {
            stop_pid(pid);
        }
        if ops.lstat(&f).is_err() {
            losses += 1;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        flag.load(Ordering::SeqCst),
        "the third loss must set the flag"
    );
    assert!(losses >= 3, "{losses}");
}

// A call that hangs runs past its deadline and ends in `TimedOut` well
// inside the wall (the run's own tool timeout is the deadline here).
#[test]
fn hanging_file_op_ends_in_tool_timeout_within_wall() {
    let ws = Ws::new("hang");
    let confined = ws.confined(stop_flag());
    let mut ops = confined.clone_box();
    let f = ws.0.join("a.txt");
    ops.lstat(&f).unwrap();
    let pid = confined.stub_pid().expect("the stub must be up");
    stop_pid(pid);
    let started = Instant::now();
    let e = ops
        .read(&f, 1024, Some(Instant::now() + Duration::from_millis(200)))
        .expect_err("a hanging read must time out");
    assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e}");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "inside the wall"
    );
}

// The digest cache serves the replace path across clones: a clone shares
// the helper and the cache, so an edit engine's clone rewrites what the
// read tools read.
#[test]
fn clones_share_the_helper_and_its_cache() {
    let ws = Ws::new("clone");
    let confined = ws.confined(stop_flag());
    let mut a: Box<dyn FileOps> = confined.clone_box();
    let mut b: Box<dyn FileOps> = confined.clone_box();
    let f = ws.0.join("a.txt");
    let read = a.read(&f, 1024, None).unwrap();
    assert_eq!(read, b"alpha\n");
    // b has never read the file; the shared cache still holds the digest.
    b.write_atomic(&f, b"shared\n", None).unwrap();
    assert_eq!(fs::read(&f).unwrap(), b"shared\n");
    let meta = b.lstat(&f).unwrap();
    assert_eq!(meta.len, 7);
}
