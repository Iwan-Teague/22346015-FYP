//! H2d: `harness.exec.run` in the loop. Whole runs through the public
//! `run`, `resume` and `audit` with the real journal, the real tools and a
//! scripted model; on macOS the commands run in the real sandbox (every
//! program here is `/usr/bin/perl` with a short, self-limiting script, or
//! `/bin/sh` where a test allowlists a shell on purpose).
//!
//! What is shown: an exec grant is refused before anything is written
//! without a conformed sandbox (INV-6); argv is resolved by name and
//! `sh -c` is refused without a shell on the allowlist (INV-13); a command
//! asks by default; a command's result is journaled with its end, its
//! cleanup and the tree digest measured after it, and audits clean; the
//! interim for the file tools' race (option (b)): a background process a
//! command leaves is swept before the next file operation, and a cleanup
//! the harness cannot confirm stops the run before any; resume and audit
//! never run a completed command again; a command past its timeout is
//! killed and its host sampled.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::{Path, PathBuf};

use gate_outcome::{GateOutcome, IndeterminateKind};
use harness_core::environment::{EnvSample, Unmeasured};
use harness_journal::{layout, EventKind, JournalReader, Record};
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, SemVer, ValidationContext};
use harness_model::profile::Profile;
use harness_model::scripted::{text_reply, ScriptedBackend};
use harness_model::{Completion, ModelError, TaskText};
use harness_policy::locality::{FsQuery, LocalityProbe};
use harness_policy::UserPolicy;
use harness_run::{run, ExecProgram, ExecSpec, Run, RunConfig, RunRefused, RunReport, TaskSpec};
use harness_sandbox::{NoConfinement, Unavailable, UnavailableReason};
use serde_json::{json, Value};

const FIXED_ENV: EnvSample = EnvSample::unmeasured(Unmeasured::NoSafeApi);

struct Local;
impl LocalityProbe for Local {
    fn query(&self, _path: &str) -> FsQuery {
        FsQuery::MacOs {
            mnt_local: true,
            fs_type_name: "apfs".into(),
        }
    }
}

const EXEC: &str = "harness.exec.run";

fn scratch(name: &str) -> (PathBuf, PathBuf) {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("exec-{name}"));
    let _ = fs::remove_dir_all(&base);
    let (state, ws) = (base.join("state"), base.join("ws"));
    fs::create_dir_all(&state).unwrap();
    fs::create_dir_all(&ws).unwrap();
    (state, ws)
}

fn registry() -> Registry {
    let ctx = ValidationContext::new(
        SemVer {
            major: 0,
            minor: 0,
            patch: 1,
        },
        &[],
    )
    .unwrap();
    Registry::admit(vec![(builtin::manifest(&ctx).unwrap(), Tier::Builtin)]).unwrap()
}

fn action(tool: &str, args: &Value) -> Result<Completion, ModelError> {
    Ok(text_reply(&format!(
        "<action>{{\"tool\":\"{tool}\",\"args\":{args}}}</action>"
    )))
}
fn submit() -> Result<Completion, ModelError> {
    action("harness.task.submit", &json!({ "note": "done" }))
}
fn exec(argv: &[&str]) -> Result<Completion, ModelError> {
    action(EXEC, &json!({ "argv": argv }))
}

fn perl_spec() -> ExecSpec {
    ExecSpec {
        programs: vec![ExecProgram {
            name: "perl".into(),
            path: "/usr/bin/perl".into(),
        }],
        ..ExecSpec::default()
    }
}

fn spec_with(grants: &[&str], exec: Option<ExecSpec>) -> TaskSpec {
    TaskSpec {
        task: TaskText::new("Make the tests pass.".into()),
        grants: grants.iter().map(|g| (*g).to_owned()).collect(),
        workspace_public: false,
        ports: Vec::new(),
        lan_ports: Vec::new(),
        exec,
        presubmit: None,
        protected: Vec::new(),
        kind: harness_run::SessionKind::Coding,
    }
}

fn spec() -> TaskSpec {
    spec_with(
        &[
            "harness.fs.read",
            "harness.edit.replace",
            "harness.edit.write",
            EXEC,
        ],
        Some(perl_spec()),
    )
}

/// The unattended policy: edits and commands allowed.
fn allow_all() -> UserPolicy {
    UserPolicy::new(
        &[],
        &[],
        &["harness.edit.replace", "harness.edit.write", EXEC],
    )
    .unwrap()
}

fn records(r: &RunReport, attempt: u32) -> Vec<Record> {
    JournalReader::open(&layout::attempt_dir(&r.run_dir, attempt))
        .unwrap()
        .records
}

fn of(recs: &[Record], kind: EventKind) -> Vec<&Record> {
    recs.iter().filter(|r| r.kind == kind).collect()
}

/// A program that pins on every OS (it is never run here): a file in a
/// fresh directory, both named by their canonical paths, the directory a
/// read-only root. (`/usr/bin/perl` does not exist on Windows, whose
/// refusal path this must reach too.)
fn portable_spec(base: &Path) -> ExecSpec {
    let tools = base.join("tools");
    fs::create_dir_all(&tools).unwrap();
    let tool = tools.join("tool");
    fs::write(&tool, b"#!/bin/sh\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let tools = fs::canonicalize(&tools).unwrap();
    ExecSpec {
        programs: vec![ExecProgram {
            name: "tool".into(),
            path: tools.join("tool"),
        }],
        read_only: vec![tools],
        ..ExecSpec::default()
    }
}

fn unavailable() -> Unavailable {
    Unavailable {
        backend: None,
        reason: UnavailableReason::NoBackendForOs,
    }
}

// INV-6: without a conformed sandbox an exec grant never starts a run: no
// run directory, no journal, nothing executed. Every OS.
#[test]
fn inv_6_an_exec_grant_is_refused_before_anything_is_written() {
    let (state, ws) = scratch("inv6");
    let profile = Profile::conservative_default("m");
    let backend = ScriptedBackend::new(profile.clone(), vec![]);
    let refuse = NoConfinement(unavailable());
    let attempt = |spec: &TaskSpec, c: Option<&dyn harness_sandbox::Confinement>| {
        run(Run {
            state_root: &state,
            workspace: &ws,
            spec,
            registry: &registry(),
            policy: &allow_all(),
            profile: &profile,
            backend: &backend,
            probe: &Local,
            env: &FIXED_ENV,
            config: &RunConfig::defaults(1_000_000),
            approver: None,
            confinement: c,
        })
        .unwrap_err()
    };
    let x = portable_spec(ws.parent().unwrap());
    let with_exec = spec_with(&["harness.fs.read", EXEC], Some(x.clone()));
    let e = attempt(&with_exec, Some(&refuse));
    assert!(matches!(e, RunRefused::Confinement(_)), "{e:?}");
    assert_eq!(
        e.outcome(),
        GateOutcome::Indeterminate {
            why: IndeterminateKind::UnsupportedOs
        }
    );
    let e = attempt(&with_exec, None);
    assert!(matches!(e, RunRefused::ExecGrant(_)), "{e:?}");
    let e = attempt(&spec_with(&[EXEC], None), Some(&refuse));
    assert!(e.to_string().contains("no exec section"), "{e}");
    let e = attempt(
        &spec_with(&["harness.fs.read"], Some(x.clone())),
        Some(&refuse),
    );
    assert!(e.to_string().contains("does not grant"), "{e}");
    let mut bad = x;
    bad.programs[0].path = "tools/tool".into();
    let e = attempt(&spec_with(&[EXEC], Some(bad)), Some(&refuse));
    assert!(matches!(e, RunRefused::Exec(_)), "{e:?}");
    assert!(!state.join("runs").exists(), "nothing was written");
}

#[cfg(target_os = "macos")]
mod live {
    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use harness_core::StopCause;
    use harness_model::{ModelBackend, ModelIdentity, ModelRequest};
    use harness_run::{audit, Audit, Resume};
    use harness_sandbox::{
        ConfinedChild, ConfinedSpec, Confinement, Conformed, Refused, SpawnError, SystemConfinement,
    };
    use harness_tools::builtin::workspace_facts;

    /// The production confinement, counting spawns.
    pub(super) struct Counting(pub(super) AtomicUsize);
    impl Confinement for Counting {
        /// The production witness, obtained once per test binary: every
        /// `require()` runs the live probe (FT-5's fork burst and sweep
        /// among its checks), and ten of them at once under host load were
        /// seen to fail the sweep check (a fail-closed refusal; see the H2d
        /// report). One live probe proves the same for every test here.
        fn require(&self) -> Result<Conformed, Refused> {
            static W: std::sync::OnceLock<Result<Conformed, Refused>> = std::sync::OnceLock::new();
            W.get_or_init(|| SystemConfinement.require()).clone()
        }
        fn spawn(&self, s: &ConfinedSpec, ev: &Conformed) -> Result<ConfinedChild, SpawnError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            SystemConfinement.spawn(s, ev)
        }
    }

    fn go_cfg(
        state: &Path,
        ws: &Path,
        spec: &TaskSpec,
        policy: &UserPolicy,
        backend: &dyn ModelBackend,
        config: &RunConfig,
        c: &'static Counting,
    ) -> RunReport {
        run(Run {
            state_root: state,
            workspace: ws,
            spec,
            registry: &registry(),
            policy,
            profile: &Profile::conservative_default("m"),
            backend,
            probe: &Local,
            env: &FIXED_ENV,
            config,
            approver: None,
            confinement: Some(c),
        })
        .unwrap()
    }

    fn go(
        state: &Path,
        ws: &Path,
        replies: Vec<Result<Completion, ModelError>>,
        c: &'static Counting,
    ) -> RunReport {
        let b = ScriptedBackend::new(Profile::conservative_default("m"), replies);
        go_cfg(
            state,
            ws,
            &spec(),
            &allow_all(),
            &b,
            &RunConfig::defaults(1_000_000),
            c,
        )
    }

    fn audited(
        state: &Path,
        r: &RunReport,
        spec: &TaskSpec,
        attempt: u32,
    ) -> harness_run::AuditReport {
        audit(Audit {
            state_root: state,
            run: &r.run,
            attempt: Some(attempt),
            anchor: r.chain_head,
            spec,
            registry: &registry(),
            policy: &allow_all(),
            profile: &Profile::conservative_default("m"),
            limits: &RunConfig::defaults(1_000_000).limits,
        })
        .unwrap()
    }

    fn tree_of(ws: &Path) -> harness_core::Digest {
        workspace_facts(ws, Instant::now() + Duration::from_secs(60))
            .unwrap()
            .tree
    }

    fn exec_results(recs: &[Record]) -> Vec<&Record> {
        recs.iter()
            .filter(|r| r.kind == EventKind::ToolFinished && r.body.contains_key("exec"))
            .collect()
    }

    fn alive(pid: u32) -> bool {
        std::process::Command::new("/bin/kill")
            .args(["-0", &pid.to_string()])
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    // The whole path: a command that writes a file and prints, then submit.
    // The header names the sandbox and its bars and binds the allowlist;
    // the result carries the command's end, its confirmed cleanup and the
    // tree digest a fresh walk measures; the anchored audit re-feeds it
    // without running anything and recomputes every record.
    #[test]
    fn h2d_a_command_runs_in_the_loop_is_journaled_and_audits_clean() {
        static C: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("e2e");
        let r = go(
            &state,
            &ws,
            vec![
                exec(&[
                    "perl",
                    "-e",
                    "open(my $f, q{>}, q{made.txt}) or die; print $f qq{made\\n}; close $f; print qq{hello from perl\\n}",
                ]),
                submit(),
            ],
            &C,
        );
        assert_eq!(r.cause, StopCause::Submitted);
        assert_eq!(C.0.load(Ordering::SeqCst), 1);
        assert_eq!(fs::read_to_string(ws.join("made.txt")).unwrap(), "made\n");
        let recs = records(&r, 1);
        let h = &recs[0].body;
        assert_eq!(h["sandbox"]["backend"], "seatbelt");
        assert_eq!(h["sandbox"]["matrix_row"], "seatbelt-macos-h2c");
        assert_eq!(h["sandbox"]["memory"], "rlimit-address-space");
        assert_eq!(h["sandbox"]["processes"], "member-count-watchdog");
        assert_eq!(h["shell_enabled"], false);
        assert_eq!(h["exec"]["spec"], perl_spec().digest().to_string());
        assert_eq!(h["exec"]["programs"], 1);
        assert_eq!(h["exec_timeout_ms"], 120_000);
        let x = exec_results(&recs);
        assert_eq!(x.len(), 1);
        let b = &x[0].body;
        assert_eq!(b["status"], "ok");
        assert_eq!(b["exec"]["end"], "exited");
        assert_eq!(b["exec"]["code"], 0);
        assert_eq!(b["exec"]["cleanup"], "confirmed");
        assert_eq!(b["workspace_tree"], tree_of(&ws).to_string());
        // The decision: a user allow rule (an unattended run).
        let d = of(&recs, EventKind::PolicyDecided);
        assert_eq!(d[0].body["decision"], "allow");
        let a = audited(&state, &r, &spec(), 1);
        assert_eq!(a.divergence, None, "{a:?}");
        assert!(a.stop_recomputed);
        assert_eq!(C.0.load(Ordering::SeqCst), 1, "the audit ran nothing");
    }

    // INV-13: `sh -c` is a program name the allowlist does not hold, so
    // policy denies it by name and nothing reaches the sandbox; the header
    // says no shell is enabled. With `sh` allowlisted on purpose, the header
    // stamps `shell_enabled: true` and it runs like any program, confined.
    #[test]
    fn inv_13_sh_c_is_refused_unless_a_shell_is_allowlisted() {
        static C: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("inv13");
        let r = go(
            &state,
            &ws,
            vec![exec(&["sh", "-c", "echo hi > x.txt"]), submit()],
            &C,
        );
        assert_eq!(r.cause, StopCause::Submitted);
        assert_eq!(C.0.load(Ordering::SeqCst), 0);
        assert!(!ws.join("x.txt").exists());
        let recs = records(&r, 1);
        assert_eq!(recs[0].body["shell_enabled"], false);
        let d = of(&recs, EventKind::PolicyDecided);
        assert_eq!(d[0].body["decision"], "deny");
        assert_eq!(d[0].body["rule"], "deny.exec-not-allowlisted");
        assert_eq!(d[0].body["reason"], "exec_not_allowlisted");
        assert_eq!(
            of(&recs, EventKind::ToolStarted).len(),
            1,
            "only the submit started"
        );

        static D: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("inv13-shell");
        let mut with_sh = perl_spec();
        with_sh.programs.push(ExecProgram {
            name: "sh".into(),
            path: "/bin/sh".into(),
        });
        let s = spec_with(&[EXEC], Some(with_sh));
        let b = ScriptedBackend::new(
            Profile::conservative_default("m"),
            vec![exec(&["sh", "-c", "echo hi > x.txt"]), submit()],
        );
        let r = go_cfg(
            &state,
            &ws,
            &s,
            &allow_all(),
            &b,
            &RunConfig::defaults(1_000_000),
            &D,
        );
        assert_eq!(r.cause, StopCause::Submitted);
        assert_eq!(D.0.load(Ordering::SeqCst), 1);
        assert_eq!(fs::read_to_string(ws.join("x.txt")).unwrap(), "hi\n");
        assert_eq!(records(&r, 1)[0].body["shell_enabled"], true);
    }

    // Execute-class asks by default: with no allow rule and no approver the
    // ask is a deny, and nothing reaches the sandbox.
    #[test]
    fn h2d_a_command_asks_by_default_and_without_an_approver_is_denied() {
        static C: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("ask");
        let b = ScriptedBackend::new(
            Profile::conservative_default("m"),
            vec![exec(&["perl", "-e", "print 1"]), submit()],
        );
        let r = go_cfg(
            &state,
            &ws,
            &spec(),
            &UserPolicy::default(),
            &b,
            &RunConfig::defaults(1_000_000),
            &C,
        );
        assert_eq!(r.cause, StopCause::Submitted);
        assert_eq!(C.0.load(Ordering::SeqCst), 0);
        let recs = records(&r, 1);
        let d = of(&recs, EventKind::PolicyDecided);
        assert_eq!(d[0].body["decision"], "deny");
        assert_eq!(d[0].body["rule"], "deny.no-approver");
    }

    /// A scripted model that waits before answering one request (the
    /// background process's window).
    struct Slow {
        inner: ScriptedBackend,
        n: Cell<u64>,
        at: u64,
        wait: Duration,
    }
    impl ModelBackend for Slow {
        fn identity(&self) -> ModelIdentity {
            self.inner.identity()
        }
        fn complete(
            &self,
            req: &ModelRequest,
            deadline: Instant,
        ) -> Result<Completion, ModelError> {
            self.n.set(self.n.get() + 1);
            if self.n.get() == self.at {
                std::thread::sleep(self.wait);
            }
            self.inner.complete(req, deadline)
        }
    }

    /// A command whose setsid'd grandchild outlives it by `sleep` seconds,
    /// then replaces `target.txt` with a symlink to `$ARGV[0]`. The
    /// grandchild writes its pid to `swapper.pid` first. With `killstub`,
    /// the command also kills its domain stub (the named R-1 gap), so the
    /// harness cannot confirm the domain is empty.
    fn swapper(outside: &Path, killstub: bool) -> Result<Completion, ModelError> {
        let script = format!(
            "use POSIX (); my $p = fork(); if ($p == 0) {{ POSIX::setsid(); if (fork()) {{ POSIX::_exit(0) }} open(my $o, q{{>}}, q{{swapper.pid}}) or die; print $o $$; close $o; close STDOUT; close STDERR; sleep 2; unlink q{{target.txt}}; symlink($ARGV[0], q{{target.txt}}); POSIX::_exit(0) }} waitpid($p, 0); for (1..200) {{ last if -s q{{swapper.pid}}; select(undef, undef, undef, 0.01) }} {}print qq{{started\\n}}",
            if killstub {
                "kill(q{KILL}, getppid()); "
            } else {
                ""
            }
        );
        exec(&["perl", "-e", &script, outside.to_str().unwrap()])
    }

    fn read(p: &str) -> Result<Completion, ModelError> {
        action("harness.fs.read", &json!({ "path": p }))
    }

    fn replace(p: &str, old: &str, new: &str) -> Result<Completion, ModelError> {
        action(
            "harness.edit.replace",
            &json!({ "path": p, "old": old, "new": new }),
        )
    }

    // Option (b), the named interim for the file tools' race (design row
    // H2d): a command starts a background process that, after the call
    // returns, would swap the file the next edit targets for a symlink to
    // a file outside the workspace. The domain sweep kills it before the
    // result is journaled (cleanup confirmed, at least one kill), so when
    // the edit runs, seconds after the swap was due, the file is the real
    // one: the edit applies to it and the outside file is untouched.
    #[test]
    fn h2d_option_b_a_background_swap_after_the_call_cannot_touch_the_next_edit() {
        static C: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("race-confirmed");
        let outside = ws.parent().unwrap().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let secret = outside.join("secret.txt");
        fs::write(&secret, "secret\n").unwrap();
        fs::write(ws.join("target.txt"), "before\n").unwrap();
        let b = Slow {
            inner: ScriptedBackend::new(
                Profile::conservative_default("m"),
                vec![
                    read("target.txt"),
                    swapper(&secret, false),
                    replace("target.txt", "before", "after"),
                    submit(),
                ],
            ),
            n: Cell::new(0),
            at: 3,
            wait: Duration::from_millis(3500),
        };
        let r = go_cfg(
            &state,
            &ws,
            &spec(),
            &allow_all(),
            &b,
            &RunConfig::defaults(1_000_000),
            &C,
        );
        assert_eq!(r.cause, StopCause::Submitted);
        let recs = records(&r, 1);
        let x = exec_results(&recs);
        assert_eq!(x[0].body["exec"]["cleanup"], "confirmed");
        assert!(x[0].body["exec"]["kills"].as_u64().unwrap() >= 1);
        let pid: u32 = fs::read_to_string(ws.join("swapper.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(!alive(pid), "the background process {pid} survived");
        let m = fs::symlink_metadata(ws.join("target.txt")).unwrap();
        assert!(m.file_type().is_file(), "target.txt is still a real file");
        assert_eq!(
            fs::read_to_string(ws.join("target.txt")).unwrap(),
            "after\n"
        );
        assert_eq!(fs::read_to_string(&secret).unwrap(), "secret\n");
        assert_eq!(of(&recs, EventKind::EditApplied).len(), 1);
    }

    // Option (b)'s other half: a command that kills its domain stub first
    // (the named R-1 gap) leaves a survivor the harness cannot account
    // for. The cleanup is journaled as unconfirmed and the run stops right
    // there (`SandboxLost`): no further step, no in-process file operation,
    // the edit never attempted. The test then kills the survivor it caused,
    // by its pid. The stop is recomputed by the audit.
    #[test]
    fn h2d_option_b_an_unconfirmed_cleanup_stops_the_run_before_any_file_op() {
        static C: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("race-unconfirmed");
        let outside = ws.parent().unwrap().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let secret = outside.join("secret.txt");
        fs::write(&secret, "secret\n").unwrap();
        fs::write(ws.join("target.txt"), "before\n").unwrap();
        let r = go(
            &state,
            &ws,
            vec![
                read("target.txt"),
                swapper(&secret, true),
                replace("target.txt", "before", "after"),
                submit(),
            ],
            &C,
        );
        // The control: unswept, the survivor does swap the file (so the
        // swept case above is not passing by accident), after the run has
        // already stopped. It exits by itself; a leftover is killed by pid.
        let deadline = Instant::now() + Duration::from_secs(6);
        let mut swapped = false;
        while Instant::now() < deadline {
            if fs::symlink_metadata(ws.join("target.txt")).is_ok_and(|m| m.file_type().is_symlink())
            {
                swapped = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let pid: Option<u32> = fs::read_to_string(ws.join("swapper.pid"))
            .ok()
            .and_then(|s| s.trim().parse().ok());
        if let Some(pid) = pid.filter(|p| alive(*p)) {
            let _ = std::process::Command::new("/bin/kill")
                .args(["-KILL", &pid.to_string()])
                .status();
        }
        assert!(swapped, "the unswept survivor swapped the file (control)");
        assert_eq!(r.cause, StopCause::SandboxLost);
        let recs = records(&r, 1);
        let x = exec_results(&recs);
        assert_eq!(x[0].body["exec"]["cleanup"], "unconfirmed");
        assert!(!x[0].body.contains_key("workspace_tree"), "nothing walked");
        assert!(of(&recs, EventKind::EditApplied).is_empty());
        assert_eq!(
            of(&recs, EventKind::ModelRequested).len(),
            2,
            "no step after the command"
        );
        assert_eq!(recs.last().unwrap().kind, EventKind::RunStopped);
        assert_eq!(recs.last().unwrap().body["cause"], "sandbox_lost");
        assert_eq!(fs::read_to_string(&secret).unwrap(), "secret\n");
        let a = audited(&state, &r, &spec(), 1);
        assert_eq!(a.divergence, None, "{a:?}");
        assert!(a.stop_recomputed);
    }

    /// Cut attempt 1's journal after the records of steps < `keep_below`
    /// (a kill between steps).
    fn crash_after(r: &RunReport, keep_below: u64) {
        let path = layout::attempt_dir(&r.run_dir, 1).join(layout::JOURNAL_FILE);
        let text = fs::read_to_string(&path).unwrap();
        let mut out = String::new();
        for line in text.lines() {
            let v: Value = serde_json::from_str(line).unwrap();
            if v["step"].as_u64().unwrap() < keep_below && v["kind"] != "RunStopped" {
                out.push_str(line);
                out.push('\n');
            }
        }
        fs::write(path, out).unwrap();
    }

    const APPEND: &str =
        "open(my $f, q{>>}, q{count.txt}) or die; print $f qq{ran\\n}; close $f; print qq{appended\\n}";

    // A kill after a command, then a resume: the command's step is complete
    // (its result is durable), so the catch-up re-feeds its result and
    // never runs it again (no spawn; the file it appends to still has one
    // line); the live part starts at the next step; the resumed attempt
    // audits clean, again without running anything.
    #[test]
    fn h2d_resume_and_audit_never_run_a_completed_command_again() {
        static C: Counting = Counting(AtomicUsize::new(0));
        static R: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("resume");
        let r = go(
            &state,
            &ws,
            vec![exec(&["perl", "-e", APPEND]), submit()],
            &C,
        );
        assert_eq!(C.0.load(Ordering::SeqCst), 1);
        assert_eq!(fs::read_to_string(ws.join("count.txt")).unwrap(), "ran\n");
        crash_after(&r, 2);
        let b = ScriptedBackend::new(Profile::conservative_default("m"), vec![submit()]);
        let res = harness_run::resume(Resume {
            state_root: &state,
            run: &r.run,
            workspace: Some(&ws),
            spec: &spec(),
            registry: &registry(),
            policy: &allow_all(),
            profile: &Profile::conservative_default("m"),
            backend: &b,
            probe: &Local,
            env: &FIXED_ENV,
            config: &RunConfig::defaults(1_000_000),
            approver: None,
            confinement: Some(&R),
        })
        .unwrap();
        assert_eq!(res.cause, StopCause::Submitted);
        assert_eq!(res.steps, 2, "step 1 re-fed, step 2 live");
        assert_eq!(
            R.0.load(Ordering::SeqCst),
            0,
            "the command did not run again"
        );
        assert_eq!(fs::read_to_string(ws.join("count.txt")).unwrap(), "ran\n");
        let old = records(&r, 1);
        let new = records(&res, 2);
        let bodies = |v: &[Record]| -> Vec<Value> {
            exec_results(v)
                .iter()
                .map(|x| {
                    let mut b = x.body.clone();
                    b.remove("intent_seq");
                    Value::Object(b)
                })
                .collect()
        };
        assert_eq!(bodies(&new), bodies(&old), "re-fed, record for record");
        let a = audited(&state, &res, &spec(), 2);
        assert_eq!(a.divergence, None, "{a:?}");
        assert!(a.stop_recomputed);
        assert_eq!(R.0.load(Ordering::SeqCst), 0);
    }

    // A command past its timeout (1 s here) is killed at the deadline: the
    // result is a timeout, the wall is named as the limit, the cleanup is
    // confirmed, and the host is sampled (§7.1). The run goes on.
    #[test]
    fn h2d_a_command_past_its_timeout_is_killed_and_the_host_sampled() {
        static C: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("timeout");
        let b = ScriptedBackend::new(
            Profile::conservative_default("m"),
            vec![exec(&["perl", "-e", "sleep 20"]), submit()],
        );
        let mut cfg = RunConfig::defaults(1_000_000);
        cfg.exec_call_timeout = Duration::from_secs(1);
        let started = Instant::now();
        let r = go_cfg(&state, &ws, &spec(), &allow_all(), &b, &cfg, &C);
        assert!(started.elapsed() < Duration::from_secs(15));
        assert_eq!(r.cause, StopCause::Submitted);
        let recs = records(&r, 1);
        let x = exec_results(&recs);
        let b = &x[0].body;
        assert_eq!(b["status"], "timeout");
        assert_eq!(b["exec"]["end"], "timed_out");
        assert_eq!(b["exec"]["guard"], "wall");
        assert_eq!(b["exec"]["cleanup"], "confirmed");
        assert!(b.contains_key("environment"));
        assert_eq!(recs[0].body["exec_timeout_ms"], 1000);
    }

    // ---- forged command records --------------------------------------------------------

    /// Rewrite attempt 1's journal with `edit` changing bodies, and
    /// re-chain it: a forger who recomputes every hash.
    fn forge(r: &RunReport, edit: impl Fn(&mut Value)) {
        use harness_journal::canon::{RecordFields, GENESIS};
        let path = layout::attempt_dir(&r.run_dir, 1).join(layout::JOURNAL_FILE);
        let text = fs::read_to_string(&path).unwrap();
        let mut prev = GENESIS;
        let mut out = Vec::new();
        for (seq, line) in text.lines().enumerate() {
            let mut v: Value = serde_json::from_str(line).unwrap();
            edit(&mut v);
            let f = RecordFields {
                seq: seq as u64,
                prev,
                t_mono_ms: v["t_mono_ms"].as_u64().unwrap(),
                t_wall: v["t_wall"].as_str().unwrap().to_owned(),
                run: harness_core::RunId::parse(v["run"].as_str().unwrap()).unwrap(),
                attempt: u32::try_from(v["attempt"].as_u64().unwrap()).unwrap(),
                step: v["step"].as_u64().unwrap(),
                kind: EventKind::parse(v["kind"].as_str().unwrap()).unwrap(),
                body: v["body"].as_object().unwrap().clone(),
            };
            let (bytes, hash) = f.encode();
            out.extend(bytes);
            out.push(b'\n');
            prev = hash;
        }
        fs::write(path, out).unwrap();
    }

    fn unanchored(state: &Path, r: &RunReport) -> harness_run::AuditReport {
        audit(Audit {
            state_root: state,
            run: &r.run,
            attempt: Some(1),
            anchor: None,
            spec: &spec(),
            registry: &registry(),
            policy: &allow_all(),
            profile: &Profile::conservative_default("m"),
            limits: &RunConfig::defaults(1_000_000).limits,
        })
        .unwrap()
    }

    // A command's record is re-fed by an audit, so its shape is checked:
    // an extra key, a guard the end does not imply, or a command record on
    // a read's result is a record the loop never writes, and the audit says
    // so. A consistent forgery of its values (an exit code) is re-fed like
    // any tool result: only the anchor catches it (the named residual of
    // the H1e-2b row).
    #[test]
    fn h2d_a_forged_command_record_is_unreadable_or_needs_the_anchor() {
        static C: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("forge-exec");
        fs::write(ws.join("a.txt"), "a\n").unwrap();
        let r = go(
            &state,
            &ws,
            vec![
                read("a.txt"),
                exec(&["perl", "-e", "print qq{ok\\n}"]),
                submit(),
            ],
            &C,
        );
        assert_eq!(r.cause, StopCause::Submitted);
        let path = layout::attempt_dir(&r.run_dir, 1).join(layout::JOURNAL_FILE);
        let pristine = fs::read(&path).unwrap();
        let is_exec_result =
            |v: &Value| v["kind"] == "ToolFinished" && v["body"].get("exec").is_some();
        let is_read_result =
            |v: &Value| v["kind"] == "ToolFinished" && v["body"].get("read_sha256").is_some();
        type Forgery = Box<dyn Fn(&mut Value)>;
        let cases: Vec<(&str, Forgery)> = vec![
            (
                "an extra key",
                Box::new(move |v: &mut Value| {
                    if is_exec_result(v) {
                        v["body"]["exec"]["extra"] = json!(1);
                    }
                }),
            ),
            (
                "a guard the end does not imply",
                Box::new(move |v: &mut Value| {
                    if is_exec_result(v) {
                        v["body"]["exec"]["guard"] = json!("wall");
                    }
                }),
            ),
            (
                "a command record on a read's result",
                Box::new(move |v: &mut Value| {
                    if is_read_result(v) {
                        v["body"]["exec"] = json!({
                            "end": "exited", "code": 0, "cleanup": "confirmed", "kills": 0,
                            "stdout_bytes": 0, "stderr_bytes": 0, "stdout_cut": false,
                            "stderr_cut": false, "elapsed_ms": 1
                        });
                    }
                }),
            ),
        ];
        for (what, edit) in cases {
            fs::write(&path, &pristine).unwrap();
            forge(&r, edit);
            let a = unanchored(&state, &r);
            assert_eq!(
                a.divergence.map(|d| d.why),
                Some("a record is not the shape the loop writes"),
                "{what}"
            );
        }
        fs::write(&path, &pristine).unwrap();
        forge(&r, |v| {
            if v["kind"] == "ToolFinished" && v["body"].get("exec").is_some() {
                v["body"]["exec"]["code"] = json!(1);
            }
        });
        assert_eq!(
            unanchored(&state, &r).divergence,
            None,
            "re-fed, like tool output"
        );
        let anchored = audited(&state, &r, &spec(), 1);
        assert!(anchored.divergence.is_some(), "the anchor catches it");
        assert_eq!(C.0.load(Ordering::SeqCst), 1, "no audit ran anything");
    }

    // The programs a run pins are the ones its resume runs: a program whose
    // content changed between the attempts refuses the resume before
    // anything is written (the header's content digest, measured again).
    #[test]
    fn h2d_a_resume_refuses_when_a_pinned_program_changed() {
        static C: Counting = Counting(AtomicUsize::new(0));
        static R: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("pinned-changed");
        let tools = fs::canonicalize(ws.parent().unwrap())
            .unwrap()
            .join("tools");
        fs::create_dir_all(&tools).unwrap();
        let hello = tools.join("hello");
        fs::write(&hello, "#!/bin/sh\necho hello\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&hello, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let x = ExecSpec {
            programs: vec![ExecProgram {
                name: "hello".into(),
                path: hello.clone(),
            }],
            read_only: vec![tools.clone()],
            ..ExecSpec::default()
        };
        let s = spec_with(&["harness.fs.read", EXEC], Some(x));
        let b = ScriptedBackend::new(
            Profile::conservative_default("m"),
            vec![exec(&["hello"]), submit()],
        );
        let r = go_cfg(
            &state,
            &ws,
            &s,
            &allow_all(),
            &b,
            &RunConfig::defaults(1_000_000),
            &C,
        );
        assert_eq!(r.cause, StopCause::Submitted);
        let recs = records(&r, 1);
        assert_eq!(exec_results(&recs)[0].body["exec"]["code"], 0);
        crash_after(&r, 2);
        fs::write(&hello, "#!/bin/sh\necho changed\n").unwrap();
        let b = ScriptedBackend::new(Profile::conservative_default("m"), vec![submit()]);
        let e = harness_run::resume(Resume {
            state_root: &state,
            run: &r.run,
            workspace: Some(&ws),
            spec: &s,
            registry: &registry(),
            policy: &allow_all(),
            profile: &Profile::conservative_default("m"),
            backend: &b,
            probe: &Local,
            env: &FIXED_ENV,
            config: &RunConfig::defaults(1_000_000),
            approver: None,
            confinement: Some(&R),
        })
        .unwrap_err();
        assert!(e.to_string().contains("programs differ"), "{e}");
        assert!(!layout::attempt_dir(&r.run_dir, 2).exists());
        assert_eq!(R.0.load(Ordering::SeqCst), 0);
    }
    /// An approver that answers every ask the same way, and counts them.
    struct Answers(harness_run::ApprovalAnswer, Cell<u32>);
    impl harness_run::Approver for Answers {
        fn kind(&self) -> harness_run::ApproverKind {
            harness_run::ApproverKind::Embedded
        }
        fn ask(
            &self,
            req: &harness_policy::approval::ApprovalRequest,
            _deadline: Instant,
        ) -> harness_run::ApprovalAnswer {
            self.1.set(self.1.get() + 1);
            // The person sees the argv they are approving.
            assert!(req.to_string().contains("appended"), "{req}");
            self.0
        }
    }

    // INV-5 for commands: with no allow rule, a command runs only after an
    // approver said yes to that exact call (once), and a no runs nothing.
    #[test]
    fn inv_5_a_command_runs_only_after_a_yes_and_a_no_runs_nothing() {
        for (yes, answer) in [
            (true, harness_run::ApprovalAnswer::Yes),
            (false, harness_run::ApprovalAnswer::No),
        ] {
            static YES: Counting = Counting(AtomicUsize::new(0));
            static NO: Counting = Counting(AtomicUsize::new(0));
            let c: &'static Counting = if yes { &YES } else { &NO };
            let (state, ws) = scratch(&format!("approve-{yes}"));
            let b = ScriptedBackend::new(
                Profile::conservative_default("m"),
                vec![exec(&["perl", "-e", APPEND]), submit()],
            );
            let approver = Answers(answer, Cell::new(0));
            let r = run(Run {
                state_root: &state,
                workspace: &ws,
                spec: &spec(),
                registry: &registry(),
                policy: &UserPolicy::default(),
                profile: &Profile::conservative_default("m"),
                backend: &b,
                probe: &Local,
                env: &FIXED_ENV,
                config: &RunConfig::defaults(1_000_000),
                approver: Some(&approver),
                confinement: Some(c),
            })
            .unwrap();
            assert_eq!(r.cause, StopCause::Submitted);
            assert_eq!(approver.1.get(), 1, "asked once");
            let recs = records(&r, 1);
            assert_eq!(
                of(&recs, EventKind::PolicyDecided)[0].body["rule"],
                "ask.exec.default"
            );
            if yes {
                assert_eq!(c.0.load(Ordering::SeqCst), 1);
                assert_eq!(of(&recs, EventKind::ApprovalGranted).len(), 1);
                assert_eq!(fs::read_to_string(ws.join("count.txt")).unwrap(), "ran\n");
            } else {
                assert_eq!(c.0.load(Ordering::SeqCst), 0);
                assert_eq!(of(&recs, EventKind::ApprovalDenied).len(), 1);
                assert!(!ws.join("count.txt").exists());
            }
        }
    }
}
