//! P-27: post-edit verified checks. Whole runs through the public `run`,
//! `resume` and `audit` with the real journal and a scripted model. The
//! refusals run on every OS; on macOS the checks run in the real sandbox
//! (each program is `/usr/bin/perl` with a short, self-limiting script).
//!
//! What is shown: a task's post-edit checks are refused before anything is
//! written unless the task grants the command runner, names programs on its
//! allowlist and the policy does not deny them; after an edit the checks
//! whose pattern matches an edited file run like command calls, a failed
//! check rolls the edit back from its pre-image (journaled as `Restored`)
//! by default or, with `keep_on_failure`, keeps the edit and shows the
//! model the check's output delimited; a check past its deadline is killed
//! and still rolls the edit back; everything is journaled, audits clean,
//! and a resume re-feeds a completed check instead of running it again.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::{Path, PathBuf};

use harness_core::environment::{EnvSample, Unmeasured};
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, SemVer, ValidationContext};
use harness_model::profile::Profile;
use harness_model::scripted::ScriptedBackend;
use harness_model::TaskText;
use harness_policy::locality::{FsQuery, LocalityProbe};
use harness_policy::UserPolicy;
use harness_run::{
    run, ExecProgram, ExecSpec, PostEditCheck, PostEditRefused, PostEditResult, PostEditSpec, Run,
    RunConfig, RunRefused, TaskSpec,
};
use harness_sandbox::{NoConfinement, Unavailable, UnavailableReason};

const FIXED_ENV: EnvSample = EnvSample::unmeasured(Unmeasured::NoSafeApi);
const EXEC: &str = "harness.exec.run";

struct Local;
impl LocalityProbe for Local {
    fn query(&self, _path: &str) -> FsQuery {
        FsQuery::MacOs {
            mnt_local: true,
            fs_type_name: "apfs".into(),
        }
    }
}

fn scratch(name: &str) -> (PathBuf, PathBuf) {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("postedit-{name}"));
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

/// A program that pins on every OS (it is never run here): a file in a
/// fresh directory, both named by their canonical paths, the directory a
/// read-only root.
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

fn pe(pattern: &str, argv: &[&str], keep: bool) -> PostEditCheck {
    PostEditCheck {
        pattern: pattern.to_owned(),
        argv: argv.iter().map(|s| (*s).to_owned()).collect(),
        keep_on_failure: keep,
    }
}

fn spec_of(checks: Vec<PostEditCheck>) -> PostEditSpec {
    PostEditSpec::new(checks).unwrap()
}

fn task(grants: &[&str], exec: Option<ExecSpec>, post_edit: Option<PostEditSpec>) -> TaskSpec {
    TaskSpec {
        task: TaskText::new("Make the tests pass.".into()),
        grants: grants.iter().map(|g| (*g).to_owned()).collect(),
        workspace_public: false,
        ports: Vec::new(),
        lan_ports: Vec::new(),
        exec,
        presubmit: None,
        post_edit,
        protected: Vec::new(),
        kind: harness_policy::SessionKind::Coding,
    }
}

fn allow_exec() -> UserPolicy {
    UserPolicy::new(&[], &[], &[EXEC]).unwrap()
}

// A task's post-edit checks are refused before anything is written (no run
// directory, no journal), with the reason named: a pattern the glob rules
// refuse, an argv out of bounds, no command runner, a command that is not
// on the allowlist. Every OS. The shape refusals are the task-file checks
// (`PostEditSpec::new`); the grant refusals are the run's.
#[test]
fn post_edit_needs_exec_grant() {
    // The task-file checks first: one to four checks, each with a
    // well-formed pattern and a bounded argv.
    assert_eq!(
        PostEditSpec::new(vec![]).unwrap_err(),
        PostEditRefused::Checks
    );
    assert_eq!(
        PostEditSpec::new(vec![pe("a.txt", &["tool"], false); 5]).unwrap_err(),
        PostEditRefused::Checks
    );
    assert!(matches!(
        PostEditSpec::new(vec![pe("", &["tool"], false)]).unwrap_err(),
        PostEditRefused::Match(1, _)
    ));
    assert!(matches!(
        PostEditSpec::new(vec![pe("/abs/txt", &["tool"], false)]).unwrap_err(),
        PostEditRefused::Match(1, _)
    ));
    assert!(matches!(
        PostEditSpec::new(vec![pe("a//b", &["tool"], false)]).unwrap_err(),
        PostEditRefused::Match(1, _)
    ));
    assert_eq!(
        PostEditSpec::new(vec![pe("a.txt", &[], false)]).unwrap_err(),
        PostEditRefused::Argv(1)
    );
    let long = vec![pe("a.txt", &["x"; 33], false)];
    assert_eq!(
        PostEditSpec::new(long).unwrap_err(),
        PostEditRefused::Argv(1)
    );
    let big = "x".repeat(1025);
    assert_eq!(
        PostEditSpec::new(vec![pe("a.txt", &[&big], false)]).unwrap_err(),
        PostEditRefused::Argv(1)
    );

    let (state, ws) = scratch("grant");
    let profile = Profile::conservative_default("m");
    let backend = ScriptedBackend::new(profile.clone(), vec![]);
    let refuse = NoConfinement(Unavailable {
        backend: None,
        reason: UnavailableReason::NoBackendForOs,
    });
    let attempt = |spec: &TaskSpec, policy: &UserPolicy| {
        run(Run {
            state_root: &state,
            workspace: &ws,
            spec,
            registry: &registry(),
            policy,
            profile: &profile,
            backend: &backend,
            probe: &Local,
            env: &FIXED_ENV,
            config: &RunConfig::defaults(1_000_000),
            approver: None,
            confinement: Some(&refuse),
        })
        .unwrap_err()
    };
    let x = portable_spec(ws.parent().unwrap());
    let ok = spec_of(vec![pe("fixed.txt", &["tool", "check"], false)]);
    let refused = |e: RunRefused| match e {
        RunRefused::PostEdit(p) => p,
        other => panic!("expected a post_edit refusal, got {other:?}"),
    };

    // No command runner: the checks are commands in the sandbox.
    let e = attempt(
        &task(&["harness.fs.read"], None, Some(ok.clone())),
        &allow_exec(),
    );
    assert_eq!(refused(e), PostEditRefused::NoExec);
    // A grant of the runner without its section is refused before them.
    let e = attempt(&task(&[EXEC], None, Some(ok.clone())), &allow_exec());
    assert!(matches!(e, RunRefused::ExecGrant(_)), "{e:?}");

    // Not on the allowlist.
    let with = |p: PostEditSpec| task(&[EXEC], Some(x.clone()), Some(p));
    let e = attempt(
        &with(spec_of(vec![pe("fixed.txt", &["sh", "-c", "true"], false)])),
        &allow_exec(),
    );
    assert_eq!(refused(e), PostEditRefused::Program(1));

    // Everything checks out: the run goes on to the sandbox, which this
    // seam refuses (INV-6), and still nothing was written.
    let e = attempt(&with(ok), &allow_exec());
    assert!(matches!(e, RunRefused::Confinement(_)), "{e:?}");
    assert!(!state.join("runs").exists(), "nothing was written");
}

// The policy would deny a check, so the run does not start: with no allow
// rule and nobody to ask, or with a user deny rule. Every OS.
#[test]
fn post_edit_policy_denied_refuses_task_file() {
    let (state, ws) = scratch("denied");
    let profile = Profile::conservative_default("m");
    let backend = ScriptedBackend::new(profile.clone(), vec![]);
    let refuse = NoConfinement(Unavailable {
        backend: None,
        reason: UnavailableReason::NoBackendForOs,
    });
    let attempt = |spec: &TaskSpec, policy: &UserPolicy| {
        run(Run {
            state_root: &state,
            workspace: &ws,
            spec,
            registry: &registry(),
            policy,
            profile: &profile,
            backend: &backend,
            probe: &Local,
            env: &FIXED_ENV,
            config: &RunConfig::defaults(1_000_000),
            approver: None,
            confinement: Some(&refuse),
        })
        .unwrap_err()
    };
    let x = portable_spec(ws.parent().unwrap());
    let one = spec_of(vec![pe("fixed.txt", &["tool", "check"], false)]);
    let refused = |e: RunRefused| match e {
        RunRefused::PostEdit(p) => p,
        other => panic!("expected a post_edit refusal, got {other:?}"),
    };

    let with = |p: PostEditSpec| task(&[EXEC], Some(x.clone()), Some(p));
    let e = attempt(&with(one.clone()), &UserPolicy::default());
    assert_eq!(refused(e), PostEditRefused::Denied(1));
    let deny = UserPolicy::new(&[EXEC], &[], &[]).unwrap();
    let e = attempt(&with(one), &deny);
    assert_eq!(refused(e), PostEditRefused::Denied(1));
    assert!(!state.join("runs").exists(), "nothing was written");
}

#[cfg(target_os = "macos")]
mod live {
    use super::*;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use harness_core::StopCause;
    use harness_journal::{layout, EventKind, JournalReader, Record};
    use harness_model::wire::render_request;
    use harness_model::{Completion, ModelBackend, ModelError, ModelRequest};
    use harness_run::{audit, resume, Audit, AuditReport, Resume, RunReport};
    use harness_sandbox::{
        ConfinedChild, ConfinedSpec, Confinement, Conformed, Refused, SpawnError, SystemConfinement,
    };
    use harness_tools::builtin::workspace_facts;
    use serde_json::{json, Value};

    /// The production confinement, counting spawns; one live-probed witness
    /// per test binary (a probe per test, ten at once under host load, was
    /// seen to be refused fail-closed: see the H2d report).
    pub(super) struct Counting(pub(super) AtomicUsize);
    impl Confinement for Counting {
        fn require(&self) -> Result<Conformed, Refused> {
            static W: std::sync::OnceLock<Result<Conformed, Refused>> = std::sync::OnceLock::new();
            W.get_or_init(|| SystemConfinement.require()).clone()
        }
        fn spawn(&self, s: &ConfinedSpec, ev: &Conformed) -> Result<ConfinedChild, SpawnError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            SystemConfinement.spawn(s, ev)
        }
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

    fn action(tool: &str, args: &Value) -> Result<Completion, ModelError> {
        Ok(harness_model::scripted::text_reply(&format!(
            "<action>{{\"tool\":\"{tool}\",\"args\":{args}}}</action>"
        )))
    }

    fn submit(note: &str) -> Result<Completion, ModelError> {
        action("harness.task.submit", &json!({ "note": note }))
    }

    fn write_file(path: &str, content: &str) -> Result<Completion, ModelError> {
        action(
            "harness.edit.write",
            &json!({ "path": path, "content": content }),
        )
    }

    fn perl(script: &str) -> Vec<String> {
        vec!["perl".into(), "-e".into(), script.into()]
    }

    fn pe(pattern: &str, script: &str, keep: bool) -> PostEditCheck {
        PostEditCheck {
            pattern: pattern.to_owned(),
            argv: perl(script),
            keep_on_failure: keep,
        }
    }

    /// A check that always fails, with output the model is shown.
    const ALWAYS_FAILS: &str = "print qq{nope: broken\\n}; exit 3";

    fn spec_of(checks: Vec<PostEditCheck>) -> TaskSpec {
        super::task(
            &["harness.fs.read", "harness.edit.write", EXEC],
            Some(perl_spec()),
            Some(PostEditSpec::new(checks).unwrap()),
        )
    }

    fn allow_all() -> UserPolicy {
        UserPolicy::new(&[], &[], &["harness.edit.write", EXEC]).unwrap()
    }

    /// A backend that keeps every request it is sent, rendered as the wire
    /// body.
    struct Recording {
        inner: ScriptedBackend,
        profile: Profile,
        requests: RefCell<Vec<Value>>,
    }
    impl ModelBackend for Recording {
        fn identity(&self) -> harness_model::ModelIdentity {
            self.inner.identity()
        }
        fn complete(
            &self,
            req: &ModelRequest,
            deadline: Instant,
        ) -> Result<Completion, ModelError> {
            self.requests
                .borrow_mut()
                .push(render_request(req, &self.profile).unwrap());
            self.inner.complete(req, deadline)
        }
    }

    fn go_with_backend(
        state: &Path,
        ws: &Path,
        spec: &TaskSpec,
        b: &Recording,
        cfg: &RunConfig,
        c: &'static Counting,
    ) -> RunReport {
        run(Run {
            state_root: state,
            workspace: ws,
            spec,
            registry: &registry(),
            policy: &allow_all(),
            profile: &Profile::conservative_default("m"),
            backend: b,
            probe: &Local,
            env: &FIXED_ENV,
            config: cfg,
            approver: None,
            confinement: Some(c),
        })
        .unwrap()
    }

    fn go(
        state: &Path,
        ws: &Path,
        spec: &TaskSpec,
        replies: Vec<Result<Completion, ModelError>>,
        cfg: &RunConfig,
        c: &'static Counting,
    ) -> RunReport {
        let b = ScriptedBackend::new(Profile::conservative_default("m"), replies);
        run(Run {
            state_root: state,
            workspace: ws,
            spec,
            registry: &registry(),
            policy: &allow_all(),
            profile: &Profile::conservative_default("m"),
            backend: &b,
            probe: &Local,
            env: &FIXED_ENV,
            config: cfg,
            approver: None,
            confinement: Some(c),
        })
        .unwrap()
    }

    fn cfg() -> RunConfig {
        RunConfig::defaults(1_000_000)
    }

    fn records(r: &RunReport, attempt: u32) -> Vec<Record> {
        JournalReader::open(&layout::attempt_dir(&r.run_dir, attempt))
            .unwrap()
            .records
    }

    fn of(recs: &[Record], kind: EventKind) -> Vec<&Record> {
        recs.iter().filter(|r| r.kind == kind).collect()
    }

    fn exec_results(recs: &[Record]) -> Vec<&Record> {
        recs.iter()
            .filter(|r| r.kind == EventKind::ToolFinished && r.body.contains_key("exec"))
            .collect()
    }

    fn audited(state: &Path, r: &RunReport, spec: &TaskSpec, attempt: u32) -> AuditReport {
        audit(Audit {
            state_root: state,
            run: &r.run,
            attempt: Some(attempt),
            anchor: r.chain_head,
            spec,
            registry: &registry(),
            policy: &allow_all(),
            profile: &Profile::conservative_default("m"),
            limits: &cfg().limits,
            children: harness_run::ChildAudit::Skip,
        })
        .unwrap()
    }

    fn tree_of(ws: &Path) -> harness_core::Digest {
        workspace_facts(ws, Instant::now() + Duration::from_secs(60))
            .unwrap()
            .tree
    }

    /// Cut attempt 1's journal after the record with this seq (a kill
    /// there), dropping `RunStopped`.
    fn cut_after(r: &RunReport, seq: u64) {
        let path = layout::attempt_dir(&r.run_dir, 1).join(layout::JOURNAL_FILE);
        let text = fs::read_to_string(&path).unwrap();
        let mut out = String::new();
        for line in text.lines() {
            let v: Value = serde_json::from_str(line).unwrap();
            if v["seq"].as_u64().unwrap() <= seq {
                out.push_str(line);
                out.push('\n');
            }
        }
        fs::write(path, out).unwrap();
    }

    fn resumed(
        state: &Path,
        ws: &Path,
        r: &RunReport,
        spec: &TaskSpec,
        replies: Vec<Result<Completion, ModelError>>,
        c: &'static Counting,
    ) -> Result<RunReport, RunRefused> {
        let b = ScriptedBackend::new(Profile::conservative_default("m"), replies);
        resume(Resume {
            state_root: state,
            run: &r.run,
            workspace: Some(ws),
            spec,
            registry: &registry(),
            policy: &allow_all(),
            profile: &Profile::conservative_default("m"),
            backend: &b,
            probe: &Local,
            env: &FIXED_ENV,
            config: &cfg(),
            approver: None,
            confinement: Some(c),
        })
    }

    fn lines(ws: &Path, file: &str) -> String {
        fs::read_to_string(ws.join(file)).unwrap_or_default()
    }

    // A failing check rolls the edit back from its pre-image: the file is
    // gone again, the workspace tree is the header's, the rollback is
    // journaled (`Restored` back to the edit's own step) and the model is
    // shown the check's output as an observation. The anchored audit
    // recomputes every record and runs nothing.
    #[test]
    fn post_edit_failure_rolls_back_edit() {
        static C: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("rollback");
        let spec = spec_of(vec![pe("fixed.txt", ALWAYS_FAILS, false)]);
        let r = go(
            &state,
            &ws,
            &spec,
            vec![write_file("fixed.txt", "ok\n"), submit("done")],
            &cfg(),
            &C,
        );
        assert_eq!(r.cause, StopCause::Submitted);
        assert_eq!(r.steps, 2);
        assert_eq!(C.0.load(Ordering::SeqCst), 1, "the check ran once");
        assert!(!ws.join("fixed.txt").exists(), "the edit was rolled back");
        let report = r.post_edit.expect("a task with checks reports them");
        assert_eq!(
            (
                report.submissions,
                report.failed,
                report.rolled_back,
                report.last
            ),
            (1, 1, 1, Some(PostEditResult::Failed))
        );
        let recs = records(&r, 1);
        let head = &recs[0];
        assert_eq!(head.body["post_edit"]["checks"], 1);
        // The edit was journaled, then undone in the same step.
        assert_eq!(of(&recs, EventKind::EditApplied).len(), 1);
        let restored = of(&recs, EventKind::Restored);
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].step, 1);
        assert_eq!(restored[0].body["to_step"], 1);
        assert_eq!(
            restored[0].body["tree_digest"],
            head.body["workspace_tree"].clone(),
            "back to the run's opening tree"
        );
        assert_eq!(restored[0].body["tree_digest"], tree_of(&ws).to_string());
        let rounds = of(&recs, EventKind::PresubmitChecked);
        assert_eq!(rounds.len(), 1);
        assert_eq!(rounds[0].body["result"], "failed");
        assert_eq!(rounds[0].body["accepted"], false);
        assert_eq!(rounds[0].body["turned_back"], 1);
        let a = audited(&state, &r, &spec, 1);
        assert_eq!(a.divergence, None, "{a:?}");
        assert!(a.stop_recomputed);
        assert_eq!(C.0.load(Ordering::SeqCst), 1, "the audit ran nothing");
    }

    // A passing check leaves the edit in place: no `Restored`, the file
    // keeps its content, the round is journaled as accepted, and the
    // anchored audit recomputes everything without running anything.
    #[test]
    fn post_edit_pass_keeps_edit() {
        static C: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("pass");
        let spec = spec_of(vec![pe("fixed.txt", "print qq{ok\\n}; exit 0", false)]);
        let r = go(
            &state,
            &ws,
            &spec,
            vec![write_file("fixed.txt", "ok\n"), submit("done")],
            &cfg(),
            &C,
        );
        assert_eq!(r.cause, StopCause::Submitted);
        assert_eq!(C.0.load(Ordering::SeqCst), 1);
        assert_eq!(lines(&ws, "fixed.txt"), "ok\n", "the edit was kept");
        let report = r.post_edit.expect("a task with checks reports them");
        assert_eq!(
            (
                report.submissions,
                report.failed,
                report.rolled_back,
                report.last
            ),
            (1, 0, 0, Some(PostEditResult::Passed))
        );
        let recs = records(&r, 1);
        assert_eq!(of(&recs, EventKind::Restored).len(), 0);
        let rounds = of(&recs, EventKind::PresubmitChecked);
        assert_eq!(rounds.len(), 1);
        assert_eq!(rounds[0].body["result"], "passed");
        assert_eq!(rounds[0].body["accepted"], true);
        assert_eq!(rounds[0].body["turned_back"], 0);
        let a = audited(&state, &r, &spec, 1);
        assert_eq!(a.divergence, None, "{a:?}");
        assert!(a.stop_recomputed);
    }

    // With `keep_on_failure` a failed check keeps the edit and the model is
    // shown the check's output delimited (the next request carries the
    // delimited diagnostics; the plain edit result came first).
    #[test]
    fn post_edit_diagnostics_shown_to_model_delimited() {
        static C: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("diagnostics");
        let spec = spec_of(vec![pe(
            "fixed.txt",
            "print qq{nope: broken\\n}; exit 7",
            true,
        )]);
        let b = Recording {
            inner: ScriptedBackend::new(
                Profile::conservative_default("m"),
                vec![write_file("fixed.txt", "ok\n"), submit("done")],
            ),
            profile: Profile::conservative_default("m"),
            requests: RefCell::new(Vec::new()),
        };
        let r = go_with_backend(&state, &ws, &spec, &b, &cfg(), &C);
        assert_eq!(r.cause, StopCause::Submitted);
        assert_eq!(lines(&ws, "fixed.txt"), "ok\n", "the edit was kept");
        let report = r.post_edit.unwrap();
        assert_eq!(
            (report.submissions, report.failed, report.rolled_back),
            (1, 1, 0)
        );
        let reqs = b.requests.borrow();
        assert_eq!(reqs.len(), 2, "one request per step");
        let second: Vec<String> = reqs[1]["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| {
                format!(
                    "{}: {}",
                    m["role"].as_str().unwrap_or("?"),
                    m["content"].as_str().unwrap_or("")
                )
            })
            .collect();
        let text = second.join("\n");
        assert!(
            text.contains("a post-edit check failed (check 1 of 1); its output:"),
            "{text}"
        );
        assert!(text.contains("nope: broken"), "{text}");
        assert!(
            matches!(
                (
                    text.find("created fixed.txt"),
                    text.find("a post-edit check failed (check 1 of 1); its output:")
                ),
                (Some(edit), Some(check)) if edit < check
            ),
            "the edit's own result comes first: {text}"
        );
        let recs = records(&r, 1);
        assert_eq!(of(&recs, EventKind::Restored).len(), 0);
        let a = audited(&state, &r, &spec, 1);
        assert_eq!(a.divergence, None, "{a:?}");
    }

    // A check past its time limit is killed at the deadline and is a failed
    // check: the edit is still rolled back, the host is sampled (§7.1), and
    // the audit recomputes the whole step.
    #[test]
    fn post_edit_timeout_rolls_back() {
        static C: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("timeout");
        let spec = spec_of(vec![pe("fixed.txt", "sleep 20", false)]);
        let mut c = cfg();
        c.exec_call_timeout = Duration::from_secs(1);
        let started = Instant::now();
        let r = go(
            &state,
            &ws,
            &spec,
            vec![write_file("fixed.txt", "ok\n"), submit("done")],
            &c,
            &C,
        );
        assert!(started.elapsed() < Duration::from_secs(20));
        assert_eq!(r.cause, StopCause::Submitted);
        assert!(!ws.join("fixed.txt").exists(), "the edit was rolled back");
        let report = r.post_edit.unwrap();
        assert_eq!((report.failed, report.rolled_back), (1, 1));
        let recs = records(&r, 1);
        let x = exec_results(&recs);
        assert_eq!(x[0].body["status"], "timeout");
        assert_eq!(x[0].body["exec"]["guard"], "wall");
        assert!(x[0].body.contains_key("environment"));
        assert_eq!(of(&recs, EventKind::Restored).len(), 1);
        let a = audit(Audit {
            state_root: &state,
            run: &r.run,
            attempt: Some(1),
            anchor: r.chain_head,
            spec: &spec,
            registry: &registry(),
            policy: &allow_all(),
            profile: &Profile::conservative_default("m"),
            limits: &c.limits,
            children: harness_run::ChildAudit::Skip,
        })
        .unwrap();
        assert_eq!(a.divergence, None, "{a:?}");
    }

    // A kill in the middle of the checks, then a resume. The first check's
    // result is durable, so the catch-up re-feeds it and never runs it again;
    // the second was cut before it started, so it runs live in the resumed
    // attempt (one spawn). The edit itself is re-fed record for record. The
    // resumed attempt audits clean.
    #[test]
    fn post_edit_replay_and_resume() {
        static C: Counting = Counting(AtomicUsize::new(0));
        static R: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("resume");
        let spec = spec_of(vec![
            pe("fixed.txt", "print qq{one\\n}; exit 0", false),
            pe("fixed.txt", "print qq{two\\n}; exit 0", false),
        ]);
        let r = go(
            &state,
            &ws,
            &spec,
            vec![write_file("fixed.txt", "ok\n"), submit("done")],
            &cfg(),
            &C,
        );
        assert_eq!(r.cause, StopCause::Submitted);
        assert_eq!(C.0.load(Ordering::SeqCst), 2);
        let old = records(&r, 1);
        let first = exec_results(&old)[0].seq;
        cut_after(&r, first);
        let res = resumed(&state, &ws, &r, &spec, vec![submit("done")], &R).unwrap();
        assert_eq!(res.cause, StopCause::Submitted);
        assert_eq!(res.steps, 2);
        assert_eq!(
            R.0.load(Ordering::SeqCst),
            1,
            "only the check that had not completed ran"
        );
        let new = records(&res, 2);
        assert_eq!(exec_results(&new).len(), 2);
        let body = |r: &Record| {
            let mut b = r.body.clone();
            b.remove("intent_seq");
            Value::Object(b)
        };
        assert_eq!(
            body(exec_results(&new)[0]),
            body(exec_results(&old)[0]),
            "re-fed record for record"
        );
        let rounds = of(&new, EventKind::PresubmitChecked);
        assert_eq!(rounds.len(), 1);
        assert_eq!(rounds[0].body["result"], "passed");
        let a = audit(Audit {
            state_root: &state,
            run: &res.run,
            attempt: Some(2),
            anchor: res.chain_head,
            spec: &spec,
            registry: &registry(),
            policy: &allow_all(),
            profile: &Profile::conservative_default("m"),
            limits: &cfg().limits,
            children: harness_run::ChildAudit::Skip,
        })
        .unwrap();
        assert_eq!(a.divergence, None, "{a:?}");
        assert!(a.stop_recomputed);
        assert_eq!(R.0.load(Ordering::SeqCst), 1, "the audit ran nothing");
    }

    // The checks are a header input: an audit or a resume given other
    // checks (or none) is refused by name, and a run without checks has no
    // such key.
    #[test]
    fn post_edit_header_input_must_match() {
        static C: Counting = Counting(AtomicUsize::new(0));
        static R: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("header");
        let spec = spec_of(vec![pe("fixed.txt", "exit 0", false)]);
        let r = go(
            &state,
            &ws,
            &spec,
            vec![write_file("fixed.txt", "ok\n"), submit("done")],
            &cfg(),
            &C,
        );
        let head = &records(&r, 1)[0];
        assert_eq!(
            head.body["post_edit"]["spec"],
            spec.post_edit.as_ref().unwrap().digest().to_string()
        );
        let why = |spec: &TaskSpec| {
            audit(Audit {
                state_root: &state,
                run: &r.run,
                attempt: Some(1),
                anchor: None,
                spec,
                registry: &registry(),
                policy: &allow_all(),
                profile: &Profile::conservative_default("m"),
                limits: &cfg().limits,
                children: harness_run::ChildAudit::Skip,
            })
            .unwrap()
            .divergence
            .map(|d| d.why)
        };
        let want = Some("the post-edit checks given differ from the recorded header");
        // The same checks audit clean.
        let same = spec_of(vec![pe("fixed.txt", "exit 0", false)]);
        assert_eq!(why(&same), None);
        let mut kept = spec_of(vec![pe("fixed.txt", "exit 0", true)]);
        assert_eq!(why(&kept), want);
        kept.post_edit = Some(PostEditSpec::new(vec![pe("other.txt", "exit 0", false)]).unwrap());
        assert_eq!(why(&kept), want);
        let mut none = kept.clone();
        none.post_edit = None;
        assert_eq!(why(&none), want);
        // A resume is refused the same way, before anything is written.
        cut_after(&r, records(&r, 1)[0].seq + 5);
        let e = resumed(&state, &ws, &r, &none, vec![], &R).unwrap_err();
        assert!(
            e.to_string().contains("the post-edit checks given differ"),
            "{e}"
        );
        assert_eq!(R.0.load(Ordering::SeqCst), 0);
        // And a run without checks writes no such key.
        static D: Counting = Counting(AtomicUsize::new(0));
        let (state2, ws2) = scratch("header-none");
        let plain = super::task(&["harness.fs.read", EXEC], Some(perl_spec()), None);
        let r2 = go(&state2, &ws2, &plain, vec![submit("done")], &cfg(), &D);
        assert!(!records(&r2, 1)[0].body.contains_key("post_edit"));
        assert!(r2.post_edit.is_none());
        assert_eq!(D.0.load(Ordering::SeqCst), 0, "no check without a spec");
    }
}
