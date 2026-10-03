//! The command runner through the real seam and the real sandbox (H2d,
//! macOS): policy authorises the call (a user allow rule, the program on
//! the allowlist), the journal makes the intent durable, then `ExecTools`
//! starts it through `Confinement::spawn` with the run's witness. Every
//! program here is `/usr/bin/perl` with a short, self-limiting script.

#![cfg(target_os = "macos")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::Cell;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use harness_core::RunId;
use harness_journal::testing::{FaultFile, FaultPlan, MemBlobs};
use harness_journal::{Clock, Event, EventKind, Header, Ident, JournalWriter};
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, SemVer, ValidationContext};
use harness_policy::{Call, Session, SessionKind, SessionSpec, UserPolicy, WorkspaceDecl, EXEC_ID};
use harness_sandbox::{
    ConfinedChild, ConfinedSpec, Confinement, Conformed, Refused, SpawnError, SystemConfinement,
};
use harness_tools::builtin::{code, workspace_tree};
use harness_tools::{
    ExecCleanup, ExecEnd, ExecProgram, ExecSpec, ExecTools, InvokeCtx, Pinned, ReadLog,
    ToolProvider, ToolResult, ToolStatus,
};
use serde_json::{json, Value};

struct Tick(Cell<u64>);
impl Clock for Tick {
    fn mono_ms(&self) -> u64 {
        self.0.set(self.0.get() + 1);
        self.0.get()
    }
    fn unix_ms(&self) -> u64 {
        0
    }
}

/// The production confinement, counting spawns.
struct Counting(AtomicUsize);
impl Confinement for Counting {
    fn require(&self) -> Result<Conformed, Refused> {
        SystemConfinement.require()
    }
    fn spawn(&self, spec: &ConfinedSpec, ev: &Conformed) -> Result<ConfinedChild, SpawnError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        SystemConfinement.spawn(spec, ev)
    }
}

fn witness() -> Conformed {
    static W: OnceLock<Conformed> = OnceLock::new();
    W.get_or_init(|| {
        SystemConfinement
            .require()
            .expect("require() passes on macOS")
    })
    .clone()
}

/// `root/ws` (the workspace), `root/scratch` and `root/outside`, canonical.
fn dirs(name: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "rh-exec-tools-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    for d in ["ws", "scratch", "outside"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    let root = fs::canonicalize(root).unwrap();
    (
        root.join("ws"),
        root.join("scratch"),
        root.join("outside"),
        root,
    )
}

struct Rig {
    w: JournalWriter<FaultFile, MemBlobs, Tick>,
    s: Session,
    t: ExecTools<'static>,
    reads: ReadLog,
    step: u64,
    root: PathBuf,
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn spec(env: &[(&str, &str)]) -> ExecSpec {
    ExecSpec {
        programs: vec![ExecProgram {
            name: "perl".into(),
            path: "/usr/bin/perl".into(),
        }],
        env: env
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
        ..ExecSpec::default()
    }
}

impl Rig {
    fn new(name: &str, exec: &ExecSpec, count: &'static Counting) -> Self {
        let ctx = ValidationContext::new(
            SemVer {
                major: 0,
                minor: 0,
                patch: 1,
            },
            &[],
        )
        .unwrap();
        let reg = Registry::admit(vec![(builtin::manifest(&ctx).unwrap(), Tier::Builtin)]).unwrap();
        // The session's allowlist also names `sh`, which the runner's
        // pinned set does not: the runner refuses it on its own.
        let s = Session::plan(
            &SessionSpec {
                grants: vec![EXEC_ID.into()],
                workspace: Some(WorkspaceDecl::default()),
                approver_present: false,
                personal_data_granted: false,
                conformed: true,
                exec_programs: vec!["perl".into(), "sh".into()],
                read_window: None,
                kind: SessionKind::Coding,
            },
            &reg,
            &UserPolicy::new(&[], &[], &[EXEC_ID]).unwrap(),
        )
        .unwrap();
        let w = JournalWriter::start(
            FaultFile::new(FaultPlan::default()),
            MemBlobs::default(),
            Tick(Cell::new(0)),
            RunId::new(1, [0; 10]),
            1,
            Header::new(Ident::of("0.0.1").unwrap()),
        )
        .unwrap();
        let (ws, scratch, _, root) = dirs(name);
        let t = ExecTools::new(
            &ws,
            Pinned::check(exec).unwrap(),
            &scratch,
            count,
            witness(),
            Duration::from_secs(30),
        )
        .unwrap();
        Self {
            w,
            s,
            t,
            reads: ReadLog::default(),
            step: 0,
            root,
        }
    }

    fn ws(&self) -> PathBuf {
        self.root.join("ws")
    }

    fn call_at(&mut self, args: Value, deadline: Instant) -> ToolResult {
        self.step += 1;
        let a = self
            .s
            .authorize(Call {
                capability: EXEC_ID.into(),
                args,
            })
            .expect("policy allows it");
        let j = self
            .w
            .append_intent(self.step, Event::new(EventKind::ToolStarted), a)
            .unwrap();
        self.t
            .invoke(
                j,
                &InvokeCtx {
                    step: self.step,
                    deadline,
                    reads: &self.reads,
                },
            )
            .unwrap()
    }

    fn perl(&mut self, script: &str, extra: &[&str]) -> ToolResult {
        let mut argv = vec!["perl", "-e", script];
        argv.extend_from_slice(extra);
        self.call_at(
            json!({ "argv": argv }),
            Instant::now() + Duration::from_secs(30),
        )
    }
}

fn text(r: &ToolResult) -> String {
    String::from_utf8(r.output.inspect("test").clone()).unwrap()
}

fn alive(pid: u32) -> bool {
    // Signal 0 through /bin/kill: exit 0 when the process exists.
    std::process::Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
fn a_command_runs_confined_and_reports_status_output_and_the_new_tree() {
    static C: Counting = Counting(AtomicUsize::new(0));
    let mut r = Rig::new("basic", &spec(&[]), &C);
    let before = workspace_tree(&r.ws(), Instant::now() + Duration::from_secs(10)).unwrap();
    let res = r.perl(
        "print qq{hello\\n}; print STDERR qq{warn\\n}; open(my $f, q{>}, q{out.txt}) or die; print $f qq{x}; close $f; exit 3",
        &[],
    );
    let t = text(&res);
    assert_eq!(res.status, ToolStatus::Ok, "{t}");
    assert!(t.starts_with("exit status 3\n"), "{t}");
    assert!(t.contains("stdout: 6 bytes, 1 line\nhello\n"), "{t}");
    assert!(t.contains("stderr: 5 bytes, 1 line\nwarn\n"), "{t}");
    assert!(!res.truncated);
    assert_eq!(res.digest, harness_core::sha256(t.as_bytes()));
    let e = res.exec.as_ref().unwrap();
    assert_eq!(e.end, ExecEnd::Exited(3));
    assert!(matches!(e.cleanup, ExecCleanup::Confirmed { .. }));
    assert_eq!((e.stdout_bytes, e.stderr_bytes), (6, 5));
    let after = e.workspace.as_ref().expect("measured after the command");
    assert_ne!(after.digest(), before.digest());
    assert_eq!(after.facts().files, before.facts().files + 1);
    assert_eq!(fs::read(r.ws().join("out.txt")).unwrap(), b"x");
}

#[test]
fn the_environment_is_built_never_inherited() {
    static C: Counting = Counting(AtomicUsize::new(0));
    let mut r = Rig::new("env", &spec(&[("RH_TASK_VAR", "1")]), &C);
    let res = r.perl(
        "print join(q{,}, sort keys %ENV), qq{\\n}; print qq{$ENV{$_}\\n} for qw(HOME TMPDIR CARGO_HOME CARGO_TARGET_DIR PATH)",
        &[],
    );
    let t = text(&res);
    assert!(
        t.contains("\nCARGO_HOME,CARGO_TARGET_DIR,HOME,PATH,RH_TASK_VAR,TMPDIR\n"),
        "{t}"
    );
    // One line per variable; the excerpt cuts a line past 200 bytes.
    let s = fs::canonicalize(r.root.join("scratch")).unwrap();
    let s = s.to_str().unwrap();
    for want in [
        format!("{s}/home"),
        format!("{s}/tmp"),
        format!("{s}/cargo-home"),
        format!("{s}/target"),
        "/usr/bin:/bin".to_owned(),
    ] {
        assert!(
            t.lines()
                .any(|l| l == want || want.starts_with(l.trim_end_matches(" [line cut]"))),
            "{want}: {t}"
        );
    }
}

#[test]
fn the_working_directory_stays_in_the_workspace_and_follows_no_symlink() {
    static C: Counting = Counting(AtomicUsize::new(0));
    let mut r = Rig::new("cwd", &spec(&[]), &C);
    let ws = r.ws();
    fs::create_dir_all(ws.join("sub")).unwrap();
    fs::write(ws.join("file.txt"), "x").unwrap();
    std::os::unix::fs::symlink(ws.join("sub"), ws.join("link")).unwrap();
    let pwd = |r: &mut Rig, cwd: &str| {
        r.call_at(
            json!({"argv": ["perl", "-e", "use Cwd; print getcwd(), qq{\\n}"], "cwd": cwd}),
            Instant::now() + Duration::from_secs(30),
        )
    };
    let ok = pwd(&mut r, "sub");
    assert!(
        text(&ok).contains(&format!("{}/sub\n", ws.display())),
        "{}",
        text(&ok)
    );
    for (cwd, want) in [
        ("link", code::SYMLINK),
        ("nope", code::NOT_FOUND),
        ("file.txt", code::NOT_A_DIR),
    ] {
        let spawned = C.0.load(Ordering::SeqCst);
        let res = pwd(&mut r, cwd);
        assert_eq!(res.status, ToolStatus::Error { code: want }, "{cwd}");
        assert!(res.exec.is_none(), "{cwd}: nothing started");
        assert_eq!(C.0.load(Ordering::SeqCst), spawned, "{cwd}: no spawn");
    }
}

#[test]
fn a_command_past_its_deadline_is_killed_and_reported() {
    static C: Counting = Counting(AtomicUsize::new(0));
    let mut r = Rig::new("timeout", &spec(&[]), &C);
    let started = Instant::now();
    let res = r.call_at(
        json!({"argv": ["perl", "-e", "sleep 20"]}),
        Instant::now() + Duration::from_millis(1500),
    );
    assert_eq!(res.status, ToolStatus::Timeout, "{}", text(&res));
    let e = res.exec.as_ref().unwrap();
    assert_eq!(e.end, ExecEnd::TimedOut);
    assert_eq!(e.end.guard(), Some("wall"));
    assert!(matches!(e.cleanup, ExecCleanup::Confirmed { .. }));
    assert!(started.elapsed() < Duration::from_secs(12));
    assert!(text(&res).starts_with("stopped: the command ran past its time limit"));
}

/// The tools-level half of the file race's interim (option (b), design row
/// H2d): a background process a command leaves behind is swept when the
/// call returns (the domain is confirmed empty), so it can never touch the
/// workspace afterwards.
#[test]
fn a_background_process_is_swept_before_the_call_returns() {
    static C: Counting = Counting(AtomicUsize::new(0));
    let mut r = Rig::new("orphan", &spec(&[]), &C);
    let script = "use POSIX (); my $p = fork(); if ($p == 0) { POSIX::setsid(); if (fork()) { POSIX::_exit(0) } open(my $o, q{>}, q{pid}) or die; print $o $$; close $o; close STDOUT; close STDERR; sleep 2; open(my $l, q{>}, q{late.txt}); print $l q{late}; close $l; POSIX::_exit(0) } waitpid($p, 0); for (1..200) { last if -s q{pid}; select(undef, undef, undef, 0.01) } print qq{parent done\\n}";
    let res = r.perl(script, &[]);
    let e = res.exec.as_ref().unwrap();
    assert!(
        matches!(e.cleanup, ExecCleanup::Confirmed { kills } if kills >= 1),
        "{:?}: {}",
        e.cleanup,
        text(&res)
    );
    let pid: u32 = fs::read_to_string(r.ws().join("pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(!alive(pid), "the background process {pid} survived");
    std::thread::sleep(Duration::from_millis(2500));
    assert!(!r.ws().join("late.txt").exists());
}

#[test]
fn only_pinned_programs_reach_the_sandbox() {
    static C: Counting = Counting(AtomicUsize::new(0));
    let mut r = Rig::new("pinned", &spec(&[]), &C);
    // `sh` is on the session's list (policy allows it) but not pinned.
    let res = r.call_at(
        json!({"argv": ["sh", "-c", "echo hi"]}),
        Instant::now() + Duration::from_secs(30),
    );
    assert_eq!(
        res.status,
        ToolStatus::Error {
            code: code::EXEC_NOT_ALLOWED
        }
    );
    assert!(res.exec.is_none());
    assert_eq!(C.0.load(Ordering::SeqCst), 0, "nothing reached the sandbox");
}

#[test]
fn build_output_goes_to_scratch_outside_the_tree_and_outside_writes_fail() {
    static C: Counting = Counting(AtomicUsize::new(0));
    let mut r = Rig::new("scratch", &spec(&[]), &C);
    let before = workspace_tree(&r.ws(), Instant::now() + Duration::from_secs(10)).unwrap();
    let outside = r.root.join("outside").join("escape.txt");
    let res = r.perl(
        "open(my $f, q{>}, qq{$ENV{CARGO_TARGET_DIR}/built}) or die qq{target: $!}; print $f q{b}; close $f; if (open(my $g, q{>}, $ARGV[0])) { print qq{WROTE OUTSIDE\\n} } else { print qq{outside refused\\n} }",
        &[outside.to_str().unwrap()],
    );
    let t = text(&res);
    assert!(t.starts_with("exit status 0\n"), "{t}");
    assert!(t.contains("outside refused"), "{t}");
    assert!(!outside.exists());
    assert!(r.root.join("scratch/target/built").exists());
    let e = res.exec.as_ref().unwrap();
    assert_eq!(
        e.workspace.as_ref().unwrap().digest(),
        before.digest(),
        "scratch is not in the tree digest"
    );
}

/// Build output must stay out of the tree digest: a scratch directory
/// inside the workspace, or one that contains it, is refused.
#[test]
fn the_scratch_directory_may_not_overlap_the_workspace() {
    static C: Counting = Counting(AtomicUsize::new(0));
    let (ws, _, _, root) = dirs("overlap");
    for scratch in [ws.join("scratch"), root.clone()] {
        let e = ExecTools::new(
            &ws,
            Pinned::check(&spec(&[])).unwrap(),
            &scratch,
            &C,
            witness(),
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(
            matches!(e, harness_tools::ExecSetupError::Scratch(_)),
            "{scratch:?}: {e}"
        );
    }
    let _ = fs::remove_dir_all(&root);
}
