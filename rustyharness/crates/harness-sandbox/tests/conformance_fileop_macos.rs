//! The file-op helper conformance suite (P-36d, spec §7/§12) on the macOS
//! Seatbelt backend, through the real [`FileOpHelper`] seam. Each test
//! states the case it witnesses: reads and writes land inside the
//! workspace only (the happy path), a planted symlink is never followed to
//! outside, a symlink swapped in mid-request can never make the kernel
//! view reach outside (2000 racing requests against a confined swapper),
//! a FIFO is refused fast, protected overlays refuse writes, the helper
//! cannot fork (one process, no fork/exec anywhere), a hard link from
//! outside is refused, the `expect_sha` guards hold, moves never
//! overwrite, a read-only profile refuses every write, a request past its
//! deadline stops the helper and the next request restarts it, and the
//! stub refuses to start unconfined.
//!
//! Every refusal case runs an unconfined control showing the hostile
//! action works when nothing stops it.
#![cfg(target_os = "macos")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use harness_core::{sha256, Digest};
use harness_policy::workspace_path;
use harness_sandbox::fileop::{ErrorCode, FileOpError, FileOpHelper, Reply, Request};
use harness_sandbox::seatbelt::Seatbelt;
use harness_sandbox::{Backend, ConfinedSpec, Conformed, DomainCleanup, Limits, LiveOpts, Network};

const PERL: &str = "/usr/bin/perl";
const HOSTS: &str = "/etc/hosts";
const SWEEP: Duration = Duration::from_secs(3);
const DEADLINE: Duration = Duration::from_secs(10);
const KIB: u64 = 1024;

fn witness() -> &'static Conformed {
    static W: OnceLock<Conformed> = OnceLock::new();
    W.get_or_init(|| {
        Seatbelt::new()
            .probe()
            .expect("the Seatbelt live probe must pass")
    })
}

/// A fresh directory tree with one read-write root (`ws`), canonical.
struct Tree {
    root: PathBuf,
    ws: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Tree {
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let root = base.join(format!(
            "rh-fileop-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let ws = root.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        Tree { root, ws }
    }

    fn spec(&self) -> ConfinedSpec {
        self.spec_roots(vec![self.ws.clone()], vec![], None)
    }

    /// The same shape with explicit roots: `rw` roots may be empty (the
    /// read-only profile) and `protected` is a write-denied overlay.
    fn spec_roots(
        &self,
        rw: Vec<PathBuf>,
        ro: Vec<PathBuf>,
        protected: Option<&Path>,
    ) -> ConfinedSpec {
        ConfinedSpec {
            // What actually runs behind the profile: the stub interpreter
            // and nothing else (§7.1); `launch` never reads this argv, it
            // names the one executable the profile admits.
            argv: vec![OsString::from(PERL)],
            cwd: self.ws.clone(),
            env: vec![],
            read_only: ro,
            read_write: rw,
            protected: protected.map(|p| vec![p.to_path_buf()]).unwrap_or_default(),
            network: Network::None,
            limits: Limits::wall(Duration::from_secs(60)),
        }
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn helper(t: &Tree) -> FileOpHelper {
    FileOpHelper::start(&t.spec(), witness(), None, &std::env::temp_dir(), SWEEP)
        .expect("the fileop helper must start")
}

fn wp(s: &str) -> harness_policy::WorkspacePath {
    workspace_path(s).expect("the test paths are workspace-relative and clean")
}

fn digest_of(bytes: &[u8]) -> Digest {
    sha256(bytes)
}

fn digest_hex(bytes: &[u8]) -> String {
    digest_of(bytes).to_string()
}

/// Unwrap an `Ok` reply into its items (tests only).
fn items(reply: Reply) -> Vec<Vec<u8>> {
    match reply {
        Reply::Ok { items } => items,
        Reply::Err { code } => panic!("unexpected refusal: {code:?}"),
    }
}

/// Unwrap an `Err` reply into its code (tests only).
fn code(reply: Reply) -> ErrorCode {
    match reply {
        Reply::Err { code } => code,
        Reply::Ok { .. } => panic!("unexpected success"),
    }
}

fn first(reply: Vec<Vec<u8>>) -> Vec<u8> {
    reply.into_iter().next().expect("at least one item")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("reply text is utf-8")
}

/// Run an unconfined perl one-liner (the control side of a case) and
/// return whether it succeeded.
fn control_perl(script: &str, args: &[&Path]) -> bool {
    Command::new(PERL)
        .arg("-e")
        .arg(script)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Whether a process still exists (`/bin/kill -0`, unconfined: test code).
fn alive(pid: u32) -> bool {
    Command::new("/bin/kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

const VICTIM: &[u8] = b"normal-victim-bytes\n";

/// `fileop-kernel-view` (§12): a symlink planted inside the workspace is
/// never followed to outside — neither by the helper's own walk nor by the
/// kernel view. The unconfined control reads straight through the same
/// link, so the link is real and the refusal is the confinement's.
#[test]
fn fileop_symlink_to_outside_is_refused_by_the_kernel() {
    let t = Tree::new("symlink");
    let inside = t.ws.join("inside");
    std::fs::write(&inside, b"inside bytes\n").unwrap();
    let link = t.ws.join("link");
    std::os::unix::fs::symlink(HOSTS, &link).unwrap();

    // Control: unconfined, reading through the link works.
    assert!(
        control_perl(
            "open(my $f, q{<}, $ARGV[0]) or exit 3; my $l=<$f>; exit(length($l)>0?0:4);",
            &[&link]
        ),
        "the control must read through the symlink"
    );

    let mut h = helper(&t);
    h.ping(HOSTS, DEADLINE).expect("the view check must hold");

    // Read through the link: refused, not followed.
    let r = h
        .request(
            &Request::Read {
                path: wp("link"),
                max: 4096,
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(code(r), ErrorCode::Symlink);
    // Every op that names the link is refused the same way.
    let r = h
        .request(&Request::Lstat { path: wp("link") }, DEADLINE)
        .unwrap();
    assert_eq!(code(r), ErrorCode::Symlink);
    let r = h
        .request(
            &Request::Create {
                path: wp("link/child"),
                bytes: vec![1],
                mode: 0o644,
                max_new_dirs: 0,
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(code(r), ErrorCode::Symlink);
    let r = h
        .request(
            &Request::Replace {
                path: wp("link"),
                bytes: vec![2],
                expect_sha: digest_of(b"anything"),
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(code(r), ErrorCode::Symlink);
    // A symlinked DIRECTORY component is refused too.
    let dirlink = t.ws.join("dirlink");
    std::os::unix::fs::symlink("/etc", &dirlink).unwrap();
    let r = h
        .request(
            &Request::Read {
                path: wp("dirlink/hosts"),
                max: 4096,
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(code(r), ErrorCode::Symlink);
}

/// `fileop-kernel-view` (§12, the race half): a symlink swapped over the
/// requested path mid-request can never make the helper reach outside.
/// A confined swapper atomically alternates the victim between the regular
/// file and a symlink to `/etc/hosts` while the helper serves 2000 reads;
/// every reply must be the regular bytes or a refusal, `/etc/hosts` must
/// come back byte-identical at the end, and the swapper's domain must
/// confirm.
#[test]
fn fileop_symlink_swap_race_never_reaches_outside() {
    let t = Tree::new("swap-race");
    let victim = t.ws.join("victim");
    std::fs::write(&victim, VICTIM).unwrap();
    let hosts_before = digest_hex(&std::fs::read(HOSTS).unwrap());

    let script = "my $v = shift; my $i = 0; \
        open(my $m, q{>}, qq{$v.go}) or exit 5; print $m q{go}; close $m; \
        while (1) { $i++; \
            if ($i % 2) { \
                symlink(q{/etc/hosts}, qq{$v.swp}) or exit 3; \
                rename(qq{$v.swp}, $v) or exit 3; \
            } else { \
                open(my $t, q{>}, qq{$v.new}) or exit 3; \
                print $t qq{normal-victim-bytes\\n}; close $t; \
                rename(qq{$v.new}, $v) or exit 3; \
            } \
        }";
    let spec = t.spec();
    let child = Seatbelt::new()
        .spawn_live(
            &ConfinedSpec {
                argv: vec![
                    OsString::from(PERL),
                    OsString::from("-e"),
                    OsString::from(script),
                    OsString::from("victim"),
                ],
                ..spec
            },
            witness(),
            &LiveOpts {
                ring_bytes: 64 * KIB,
                lifetime: Duration::from_secs(120),
            },
        )
        .unwrap();
    let go = t.ws.join("victim.go");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !go.exists() {
        assert!(Instant::now() < deadline, "the swapper never started");
        std::thread::sleep(Duration::from_millis(10));
    }

    let mut h = helper(&t);
    for _ in 0..2000 {
        let reply = h
            .request(
                &Request::Read {
                    path: wp("victim"),
                    max: 8192,
                },
                DEADLINE,
            )
            .expect("the racing read must always be answered");
        match reply {
            Reply::Ok { items } => {
                let got = first(items);
                assert_eq!(got, VICTIM, "the kernel view leaked outside bytes");
            }
            Reply::Err { code } => assert!(
                matches!(code, ErrorCode::Symlink | ErrorCode::NoEnt),
                "unexpected refusal during the race: {code:?}"
            ),
        }
    }

    let exit = child.stop();
    assert!(
        matches!(exit.domain, DomainCleanup::Confirmed { .. }),
        "the swapper's domain must confirm: {:?}",
        exit.domain
    );
    let hosts_after = digest_hex(&std::fs::read(HOSTS).unwrap());
    assert_eq!(hosts_before, hosts_after, "/etc/hosts must be untouched");
}

/// `fileop-fifo` (§12): a FIFO in the requested path is refused fast —
/// never opened, never blocked on. The control writes the same FIFO
/// unconfined, so the node is real and usable when nothing stops it.
#[test]
fn fileop_fifo_is_refused_fast() {
    let t = Tree::new("fifo");
    let pipe = t.ws.join("pipe");
    assert!(
        control_perl("use POSIX; exit(mkfifo($ARGV[0], 0600) ? 0 : 3);", &[&pipe]),
        "the control must create the FIFO"
    );
    // Control: unconfined, the FIFO can be opened and written.
    assert!(
        control_perl(
            "use Fcntl; sysopen(my $f, $ARGV[0], O_RDWR|O_NONBLOCK) or exit 3; print $f q{x} or exit 4; close $f;",
            &[&pipe]
        ),
        "the control must write the FIFO"
    );

    let mut h = helper(&t);
    let started = Instant::now();
    let r = h
        .request(
            &Request::Read {
                path: wp("pipe"),
                max: 4096,
            },
            DEADLINE,
        )
        .unwrap();
    // Both shapes are a refusal and a fast one: the profile denies FIFOs
    // (the stub's own type guard answers `denied` when it sees the node
    // first), and measured on this host the kernel view hides the node
    // entirely, so the walk answers `noent` — never a block, never bytes.
    assert!(
        matches!(code(r), ErrorCode::Denied | ErrorCode::NoEnt),
        "a FIFO read must be refused"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the FIFO refusal must be fast, not a block"
    );
    // A replace onto the FIFO is refused the same way (never opened).
    let r = h
        .request(
            &Request::Replace {
                path: wp("pipe"),
                bytes: vec![1],
                expect_sha: digest_of(b""),
            },
            DEADLINE,
        )
        .unwrap();
    assert!(
        matches!(code(r), ErrorCode::Denied | ErrorCode::NoEnt),
        "a FIFO replace must be refused"
    );
}

/// `fileop-protected` (§12): writes under a protected overlay are refused
/// while reads still work, and the same writes succeed unconfined.
#[test]
fn fileop_protected_path_write_refused() {
    let t = Tree::new("protected");
    let prot = t.ws.join("prot");
    std::fs::create_dir(&prot).unwrap();
    let existing = prot.join("exists");
    // Control: unconfined, writing under the protected root works.
    std::fs::write(&existing, b"controlled\n").unwrap();

    let mut h = FileOpHelper::start(
        &t.spec_roots(vec![t.ws.clone()], vec![], Some(&prot)),
        witness(),
        None,
        &std::env::temp_dir(),
        SWEEP,
    )
    .unwrap();
    h.ping(HOSTS, DEADLINE).expect("the view check must hold");

    let r = h
        .request(
            &Request::Create {
                path: wp("prot/new"),
                bytes: b"no".to_vec(),
                mode: 0o644,
                max_new_dirs: 0,
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(code(r), ErrorCode::Denied);
    let r = h
        .request(
            &Request::Replace {
                path: wp("prot/exists"),
                bytes: b"no".to_vec(),
                expect_sha: digest_of(b"controlled\n"),
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(code(r), ErrorCode::Denied);
    let r = h
        .request(
            &Request::Unlink {
                path: wp("prot/exists"),
                expect_sha: digest_of(b"controlled\n"),
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(code(r), ErrorCode::Denied);
    // Reads under the overlay still work (the view is a write view).
    let r = h
        .request(
            &Request::Read {
                path: wp("prot/exists"),
                max: 4096,
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(first(items(r)), b"controlled\n");
    assert_eq!(std::fs::read(&existing).unwrap(), b"controlled\n");
}

/// `fileop-no-fork` (§12): the helper holds exactly one process across
/// requests, and neither the stub text nor the profile knows a way to
/// grow: no fork/system/exec in the stub, no `process-fork` in the
/// profile, the interpreter the only executable.
#[test]
fn fileop_helper_cannot_fork() {
    let t = Tree::new("no-fork");
    let mut h = helper(&t);
    h.request(
        &Request::Create {
            path: wp("f"),
            bytes: b"one".to_vec(),
            mode: 0o644,
            max_new_dirs: 0,
        },
        DEADLINE,
    )
    .unwrap();
    let pid1 = h.pid().expect("the helper runs");
    h.request(
        &Request::Read {
            path: wp("f"),
            max: 64,
        },
        DEADLINE,
    )
    .unwrap();
    h.request(&Request::Lstat { path: wp("f") }, DEADLINE)
        .unwrap();
    let pid2 = h.pid().expect("the helper still runs");
    assert_eq!(
        pid1, pid2,
        "one request, one process: the pid never changes"
    );

    // Static half: the stub never forks, systems or execs; the profile
    // refuses forks and names exactly one executable. (`exec=` only ever
    // appears inside the stub's final report field, so the call-shaped
    // forms are what is refused here.)
    let stub = harness_sandbox::seatbelt::FILEOP_STUB;
    assert!(!stub.contains("fork"), "the stub must not fork");
    assert!(!stub.contains("system"), "the stub must not system");
    assert!(!stub.contains("exec("), "the stub must not exec");
    assert!(!stub.contains("exec "), "the stub must not exec");
    let v = harness_sandbox::spec::Validated {
        argv: vec![b"/usr/bin/perl".to_vec()],
        env: vec![],
        cwd: t.ws.to_str().unwrap().to_string(),
        read_only: vec![],
        read_write: vec![t.ws.to_str().unwrap().to_string()],
        protected: vec![],
        limits: harness_sandbox::Limits::wall(Duration::from_secs(1)),
    };
    let profile = harness_sandbox::profile::render_fileop(&v).unwrap();
    assert!(!profile.contains("process-fork"));
    assert_eq!(profile.matches("(allow process-exec").count(), 1);
    assert!(profile.contains("(allow process-exec (literal \"/usr/bin/perl\"))"));
}

/// `fileop-hard-link` (§12): a hard link from outside the workspace cannot
/// become the target of a replace or unlink (nlink refusal), so outside
/// content can neither be smuggled in nor clobbered through one. The
/// control hard-links the same file in unconfined.
#[test]
fn fileop_hard_link_from_outside_refused() {
    let t = Tree::new("hard-link");
    let outside = t.root.join("outside.txt");
    std::fs::write(&outside, b"outside bytes\n").unwrap();
    let linked = t.ws.join("linked");
    // Control: unconfined, hard-linking across the root boundary works.
    std::fs::hard_link(&outside, &linked).unwrap();

    let mut h = helper(&t);
    let expect = digest_of(b"outside bytes\n");
    let r = h
        .request(
            &Request::Replace {
                path: wp("linked"),
                bytes: b"smuggled".to_vec(),
                expect_sha: expect,
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(code(r), ErrorCode::NLink);
    let r = h
        .request(
            &Request::Unlink {
                path: wp("linked"),
                expect_sha: expect,
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(code(r), ErrorCode::NLink);
    // The outside file is untouched.
    assert_eq!(std::fs::read(&outside).unwrap(), b"outside bytes\n");
}

/// Happy path (§7.3): create, read, replace, lstat, list, tree, move and
/// unlink all land inside the workspace, with the digests and replies the
/// protocol promises.
#[test]
fn fileop_helper_reads_and_writes_inside_workspace() {
    let t = Tree::new("roundtrip");
    let mut h = helper(&t);
    h.ping(HOSTS, DEADLINE).expect("the view check must hold");

    let v1 = b"hello v1\n";
    let r = h
        .request(
            &Request::Create {
                path: wp("notes/a.txt"),
                bytes: v1.to_vec(),
                mode: 0o644,
                max_new_dirs: 1,
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(text(&first(items(r))), "1", "one directory was made");

    let r = h
        .request(
            &Request::Read {
                path: wp("notes/a.txt"),
                max: 1024,
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(first(items(r)), v1);

    let v2 = b"hello v2\n";
    let r = h
        .request(
            &Request::Replace {
                path: wp("notes/a.txt"),
                bytes: v2.to_vec(),
                expect_sha: digest_of(v1),
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(text(&first(items(r))), digest_hex(v2));

    let r = h
        .request(
            &Request::Lstat {
                path: wp("notes/a.txt"),
            },
            DEADLINE,
        )
        .unwrap();
    let it = items(r);
    assert_eq!(text(&it[0]), "file");
    assert_eq!(text(&it[1]), (v2.len() as u64).to_string());
    assert_eq!(text(&it[3]), "1");

    let r = h
        .request(
            &Request::List {
                path: wp("notes"),
                max_entries: 10,
                depth: 1,
            },
            DEADLINE,
        )
        .unwrap();
    let it = items(r);
    assert_eq!(it.len(), 3);
    assert_eq!(text(&it[0]), "a.txt");
    assert_eq!(text(&it[1]), "file");

    let r = h
        .request(
            &Request::Tree {
                max_entries: 10,
                timeout_ms: 1000,
            },
            DEADLINE,
        )
        .unwrap();
    let it = items(r);
    // Two entries, four items each: the `notes` directory and the file
    // under it (paths, types, sizes, and a digest for files only).
    assert_eq!(it.len(), 8);
    assert_eq!(text(&it[0]), "notes");
    assert_eq!(text(&it[1]), "dir");
    assert_eq!(text(&it[3]), "");
    assert_eq!(text(&it[4]), "notes/a.txt");
    assert_eq!(text(&it[5]), "file");
    assert_eq!(text(&it[7]), digest_hex(v2));

    // Move never loses the bytes and cleans up the source.
    let r = h
        .request(
            &Request::Move {
                from: wp("notes/a.txt"),
                to: wp("notes/b.txt"),
                expect_sha: digest_of(v2),
                max_new_dirs: 0,
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(text(&first(items(r))), "0");
    let r = h
        .request(
            &Request::Lstat {
                path: wp("notes/a.txt"),
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(code(r), ErrorCode::NoEnt);
    let r = h
        .request(
            &Request::Read {
                path: wp("notes/b.txt"),
                max: 1024,
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(first(items(r)), v2);

    let r = h
        .request(
            &Request::Unlink {
                path: wp("notes/b.txt"),
                expect_sha: digest_of(v2),
            },
            DEADLINE,
        )
        .unwrap();
    assert!(items(r).is_empty());
    let r = h
        .request(&Request::Rmdir { path: wp("notes") }, DEADLINE)
        .unwrap();
    assert!(items(r).is_empty());
    let r = h
        .request(&Request::Lstat { path: wp("notes") }, DEADLINE)
        .unwrap();
    assert_eq!(code(r), ErrorCode::NoEnt);
}

/// The `expect_sha` guard (§7.3): a replace or unlink whose expected
/// digest names different bytes is refused `changed` and touches nothing.
#[test]
fn fileop_replace_refuses_changed_expect_sha() {
    let t = Tree::new("expect-sha");
    let mut h = helper(&t);
    let v1 = b"version one\n";
    h.request(
        &Request::Create {
            path: wp("f"),
            bytes: v1.to_vec(),
            mode: 0o644,
            max_new_dirs: 0,
        },
        DEADLINE,
    )
    .unwrap();

    let wrong = digest_of(b"version none\n");
    let r = h
        .request(
            &Request::Replace {
                path: wp("f"),
                bytes: b"version two\n".to_vec(),
                expect_sha: wrong,
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(code(r), ErrorCode::Changed);
    let r = h
        .request(
            &Request::Unlink {
                path: wp("f"),
                expect_sha: wrong,
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(code(r), ErrorCode::Changed);
    let r = h
        .request(
            &Request::Read {
                path: wp("f"),
                max: 1024,
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(
        first(items(r)),
        v1,
        "a refused replace must not touch the file"
    );

    // The right digest lets the replace through, and the reply names the
    // after-digest; the stale digest is refused from then on.
    let v2 = b"version two\n";
    let r = h
        .request(
            &Request::Replace {
                path: wp("f"),
                bytes: v2.to_vec(),
                expect_sha: digest_of(v1),
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(text(&first(items(r))), digest_hex(v2));
    let r = h
        .request(
            &Request::Replace {
                path: wp("f"),
                bytes: b"version three\n".to_vec(),
                expect_sha: digest_of(v1),
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(code(r), ErrorCode::Changed);
}

/// Moves never overwrite (§7.3): a move whose destination exists is
/// refused `exists` and both files stay; only a fresh destination moves.
#[test]
fn fileop_move_never_overwrites() {
    let t = Tree::new("move");
    let mut h = helper(&t);
    let src: &[u8] = b"source\n";
    let dst: &[u8] = b"destination\n";
    for (name, bytes) in [("a", src), ("b", dst)] {
        h.request(
            &Request::Create {
                path: wp(name),
                bytes: bytes.to_vec(),
                mode: 0o644,
                max_new_dirs: 0,
            },
            DEADLINE,
        )
        .unwrap();
    }
    let r = h
        .request(
            &Request::Move {
                from: wp("a"),
                to: wp("b"),
                expect_sha: digest_of(src),
                max_new_dirs: 0,
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(code(r), ErrorCode::Exists, "a move must never overwrite");
    let r = h
        .request(
            &Request::Read {
                path: wp("a"),
                max: 64,
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(first(items(r)), src);
    let r = h
        .request(
            &Request::Read {
                path: wp("b"),
                max: 64,
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(first(items(r)), dst);

    let r = h
        .request(
            &Request::Move {
                from: wp("a"),
                to: wp("c"),
                expect_sha: digest_of(src),
                max_new_dirs: 0,
            },
            DEADLINE,
        )
        .unwrap();
    assert!(matches!(r, Reply::Ok { .. }));
    let r = h
        .request(&Request::Lstat { path: wp("a") }, DEADLINE)
        .unwrap();
    assert_eq!(code(r), ErrorCode::NoEnt);
}

/// A read-only profile (§7.1: a session with no edit tool) refuses every
/// write op while reads keep working; the same writes succeed unconfined.
#[test]
fn fileop_readonly_profile_refuses_every_write() {
    let t = Tree::new("readonly");
    let pre = t.ws.join("pre");
    // Control: unconfined, the writes land.
    std::fs::write(&pre, b"pre\n").unwrap();

    let mut h = FileOpHelper::start(
        &t.spec_roots(vec![], vec![t.ws.clone()], None),
        witness(),
        None,
        &std::env::temp_dir(),
        SWEEP,
    )
    .unwrap();
    h.ping(HOSTS, DEADLINE).expect("the view check must hold");

    let expect = digest_of(b"pre\n");
    for (what, r) in [
        (
            "create",
            h.request(
                &Request::Create {
                    path: wp("x"),
                    bytes: b"no".to_vec(),
                    mode: 0o644,
                    max_new_dirs: 0,
                },
                DEADLINE,
            )
            .unwrap(),
        ),
        (
            "replace",
            h.request(
                &Request::Replace {
                    path: wp("pre"),
                    bytes: b"no".to_vec(),
                    expect_sha: expect,
                },
                DEADLINE,
            )
            .unwrap(),
        ),
        (
            "unlink",
            h.request(
                &Request::Unlink {
                    path: wp("pre"),
                    expect_sha: expect,
                },
                DEADLINE,
            )
            .unwrap(),
        ),
        (
            "move",
            h.request(
                &Request::Move {
                    from: wp("pre"),
                    to: wp("pre2"),
                    expect_sha: expect,
                    max_new_dirs: 0,
                },
                DEADLINE,
            )
            .unwrap(),
        ),
    ] {
        assert_eq!(code(r), ErrorCode::Denied, "{what} must be refused");
    }
    // Reads still work.
    let r = h
        .request(
            &Request::Read {
                path: wp("pre"),
                max: 64,
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(first(items(r)), b"pre\n");
    assert_eq!(std::fs::read(&pre).unwrap(), b"pre\n");
}

/// §7.5: a request past its deadline stops the helper (its process dies),
/// and the next request restarts it transparently; the restart is
/// counted.
#[test]
fn fileop_request_timeout_kills_and_restarts_helper() {
    let t = Tree::new("timeout");
    let mut h = helper(&t);
    h.request(
        &Request::Create {
            path: wp("f"),
            bytes: b"held\n".to_vec(),
            mode: 0o644,
            max_new_dirs: 0,
        },
        DEADLINE,
    )
    .unwrap();
    let old = h.pid().expect("the helper runs");

    // Freeze the stub so no reply can come.
    assert!(
        Command::new("/bin/kill")
            .arg("-STOP")
            .arg(old.to_string())
            .status()
            .unwrap()
            .success(),
        "the test must be able to stop the stub"
    );
    let started = Instant::now();
    let r = h.request(
        &Request::Read {
            path: wp("f"),
            max: 64,
        },
        Duration::from_millis(500),
    );
    match r {
        Err(FileOpError::Timeout) => {}
        other => panic!("expected a timeout, got {other:?}"),
    }
    assert!(started.elapsed() >= Duration::from_millis(450));
    // The stopped stub is gone (the stop swept its group).
    let gone = Instant::now() + Duration::from_secs(10);
    while alive(old) {
        assert!(Instant::now() < gone, "the timed-out stub must die");
        std::thread::sleep(Duration::from_millis(20));
    }

    // The next request restarts a fresh stub and answers again.
    let r = h
        .request(
            &Request::Read {
                path: wp("f"),
                max: 64,
            },
            DEADLINE,
        )
        .unwrap();
    assert_eq!(first(items(r)), b"held\n");
    let new = h.pid().expect("the restarted helper runs");
    assert_ne!(new, old);
    assert_eq!(h.restarts(), 1);
}

/// The stub refuses to start unconfined (§7.1): its start canary needs
/// `signal 0` to the parent to FAIL (proof a sandbox is around it), so
/// with no sandbox the check succeeds in signalling and the stub exits 4
/// before reading anything.
#[test]
fn fileop_stub_refuses_to_start_unconfined() {
    let out = Command::new(PERL)
        .arg("-e")
        .arg(harness_sandbox::seatbelt::FILEOP_STUB)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(4),
        "the canary must refuse an unsandboxed start; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Nothing was served: no bytes of protocol traffic.
    assert!(out.stdout.is_empty());
}
