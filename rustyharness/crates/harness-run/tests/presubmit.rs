//! H3a: pre-submit checks. Whole runs through the public `run`, `resume` and
//! `audit` with the real journal and a scripted model. The refusals run on
//! every OS; on macOS the checks run in the real sandbox (each program is
//! `/usr/bin/perl` with a short, self-limiting script).
//!
//! What is shown: a task's checks are refused before anything is written
//! unless the task grants the command runner, names programs on its
//! allowlist and the policy does not deny them; on submit the checks run in
//! order, the first failure turns the submission back with its output as an
//! observation and a static notice, the model repairs and submits again; the
//! bound on turned-back submissions is spent and the next submission is
//! accepted with a distinct stop cause; everything is journaled, audits
//! clean, and a resume never repeats a completed check.

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
    run, ExecProgram, ExecSpec, PresubmitRefused, PresubmitSpec, Run, RunConfig, RunRefused,
    TaskSpec,
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
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("presubmit-{name}"));
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

fn checks(commands: &[&[&str]], max_rounds: u32) -> PresubmitSpec {
    PresubmitSpec {
        commands: commands
            .iter()
            .map(|c| c.iter().map(|s| (*s).to_owned()).collect())
            .collect(),
        max_rounds,
    }
}

fn task(grants: &[&str], exec: Option<ExecSpec>, presubmit: Option<PresubmitSpec>) -> TaskSpec {
    TaskSpec {
        task: TaskText::new("Make the tests pass.".into()),
        grants: grants.iter().map(|g| (*g).to_owned()).collect(),
        workspace_public: false,
        ports: Vec::new(),
        lan_ports: Vec::new(),
        exec,
        presubmit,
        post_edit: None,
        protected: Vec::new(),
        kind: harness_run::SessionKind::Coding,
    }
}

fn allow_exec() -> UserPolicy {
    UserPolicy::new(&[], &[], &[EXEC]).unwrap()
}

// A task's checks are refused before anything is written (no run
// directory, no journal), with the reason named: no command runner, a
// command that is not on the allowlist or out of bounds, a policy that would
// deny it. Every OS.
#[test]
fn h3a_checks_are_refused_before_anything_is_written() {
    let (state, ws) = scratch("refused");
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
    let ok = checks(&[&["tool", "build"], &["tool", "test"]], 2);
    let refused = |e: RunRefused| match e {
        RunRefused::Presubmit(p) => p,
        other => panic!("expected a presubmit refusal, got {other:?}"),
    };

    // No command runner: the checks are commands in the sandbox.
    let e = attempt(
        &task(&["harness.fs.read"], None, Some(ok.clone())),
        &allow_exec(),
    );
    assert_eq!(refused(e), PresubmitRefused::NoExec);
    // A grant of the runner without its section is refused before them.
    let e = attempt(&task(&[EXEC], None, Some(ok.clone())), &allow_exec());
    assert!(matches!(e, RunRefused::ExecGrant(_)), "{e:?}");

    // Out of bounds, or not on the allowlist.
    let with = |p: PresubmitSpec| task(&[EXEC], Some(x.clone()), Some(p));
    let e = attempt(&with(checks(&[], 2)), &allow_exec());
    assert_eq!(refused(e), PresubmitRefused::Commands);
    let e = attempt(&with(checks(&[&["tool"]], 0)), &allow_exec());
    assert_eq!(refused(e), PresubmitRefused::Rounds);
    let e = attempt(
        &with(checks(&[&["tool", "a"], &["sh", "-c", "true"]], 2)),
        &allow_exec(),
    );
    assert_eq!(refused(e), PresubmitRefused::Program(2));

    // Policy: with no allow rule and nobody to ask, the command would be
    // denied, so the run does not start; a user deny rule does the same.
    let e = attempt(&with(ok.clone()), &UserPolicy::default());
    assert_eq!(refused(e), PresubmitRefused::Denied(1));
    let deny = UserPolicy::new(&[EXEC], &[], &[]).unwrap();
    let e = attempt(&with(ok.clone()), &deny);
    assert_eq!(refused(e), PresubmitRefused::Denied(1));

    // Everything checks out: the run goes on to the sandbox, which this
    // seam refuses (INV-6), and still nothing was written.
    let e = attempt(&with(ok), &allow_exec());
    assert!(matches!(e, RunRefused::Confinement(_)), "{e:?}");
    assert!(!state.join("runs").exists(), "nothing was written");
}

#[cfg(target_os = "macos")]
mod live {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use harness_core::StopCause;
    use harness_journal::{layout, EventKind, JournalReader, Record};
    use harness_model::{Completion, ModelError};
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

    /// A check that passes only once `fixed.txt` exists.
    const NEEDS_FIXED: &str = "print qq{looking for fixed.txt\\n}; exit(-e q{fixed.txt} ? 0 : 3)";
    /// A command that appends a line to the file it is given, and passes.
    fn appends(file: &str) -> Vec<String> {
        perl(&format!(
            "open(my $f, q{{>>}}, q{{{file}}}) or die; print $f qq{{ran\\n}}; close $f; print qq{{appended {file}\\n}}"
        ))
    }

    fn spec_of(commands: Vec<Vec<String>>, max_rounds: u32) -> TaskSpec {
        task(
            &["harness.fs.read", "harness.edit.write", EXEC],
            Some(perl_spec()),
            Some(PresubmitSpec {
                commands,
                max_rounds,
            }),
        )
    }

    fn allow_all() -> UserPolicy {
        UserPolicy::new(&[], &[], &["harness.edit.write", EXEC]).unwrap()
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
        })
        .unwrap()
    }

    fn tree_of(ws: &Path) -> harness_core::Digest {
        workspace_facts(ws, Instant::now() + Duration::from_secs(60))
            .unwrap()
            .tree
    }

    // The whole path through the real sandbox: the first submission's check
    // fails (fixed.txt is missing), so it is turned back and nothing is
    // accepted; the model writes the file and submits again, the check passes
    // and the second submission is accepted. Journaled: the check's decision,
    // intent and result each time (its end, its confirmed cleanup, the tree a
    // fresh walk measures), the two rounds, the submit's own error result and
    // ok result. The anchored audit recomputes every record and runs nothing.
    #[test]
    fn h3a_a_failing_check_is_repaired_and_the_second_submission_is_accepted() {
        static C: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("e2e");
        let spec = spec_of(vec![perl(NEEDS_FIXED)], 2);
        let r = go(
            &state,
            &ws,
            &spec,
            vec![
                submit("first"),
                write_file("fixed.txt", "ok\n"),
                submit("second"),
            ],
            &cfg(),
            &C,
        );
        assert_eq!(r.cause, StopCause::Submitted);
        assert_eq!(r.steps, 3);
        assert_eq!(C.0.load(Ordering::SeqCst), 2, "the check ran twice");
        let report = r.presubmit.expect("a task with checks reports them");
        assert_eq!(
            (report.submissions, report.turned_back, report.last),
            (2, 1, Some(harness_run::PresubmitResult::Passed))
        );
        let recs = records(&r, 1);
        assert_eq!(recs[0].body["presubmit"]["commands"], 1);
        assert_eq!(recs[0].body["presubmit"]["max_rounds"], 2);
        let x = exec_results(&recs);
        assert_eq!(x.len(), 2);
        assert_eq!(x[0].body["exec"]["code"], 3);
        assert_eq!(x[0].body["exec"]["cleanup"], "confirmed");
        assert_eq!(x[1].body["exec"]["code"], 0);
        assert_eq!(x[1].body["workspace_tree"], tree_of(&ws).to_string());
        let rounds = of(&recs, EventKind::PresubmitChecked);
        assert_eq!(rounds.len(), 2);
        assert_eq!(rounds[0].body["result"], "failed");
        assert_eq!(rounds[0].body["accepted"], false);
        assert_eq!(rounds[1].body["result"], "passed");
        assert_eq!(rounds[1].body["accepted"], true);
        let decided = of(&recs, EventKind::PolicyDecided);
        let rules: Vec<&Value> = decided.iter().map(|d| &d.body["decision"]).collect();
        assert!(rules.iter().all(|d| *d == "allow"), "{rules:?}");
        assert_eq!(recs.last().unwrap().body["cause"], "submitted");
        let a = audited(&state, &r, &spec, 1);
        assert_eq!(a.divergence, None, "{a:?}");
        assert!(a.stop_recomputed);
        assert_eq!(C.0.load(Ordering::SeqCst), 2, "the audit ran nothing");
    }

    // The bound is spent: a check that always fails turns two submissions
    // back, and the third is accepted with its own stop cause. The audit
    // recomputes that stop.
    #[test]
    fn h3a_a_spent_bound_is_a_distinct_stop_and_audits_clean() {
        static C: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("exhausted");
        let spec = spec_of(vec![perl("print qq{nope\\n}; exit 1")], 2);
        let r = go(
            &state,
            &ws,
            &spec,
            vec![submit("a"), submit("b"), submit("c")],
            &cfg(),
            &C,
        );
        assert_eq!(r.cause, StopCause::SubmittedChecksFailed);
        assert_eq!(r.steps, 3);
        assert_eq!(C.0.load(Ordering::SeqCst), 3);
        let recs = records(&r, 1);
        assert_eq!(
            recs.last().unwrap().body["cause"],
            "submitted_checks_failed"
        );
        assert_eq!(
            recs.last().unwrap().body["outcome"],
            "indeterminate:nothing_checked"
        );
        let a = audited(&state, &r, &spec, 1);
        assert_eq!(a.divergence, None, "{a:?}");
        assert!(a.stop_recomputed);
        assert_eq!(C.0.load(Ordering::SeqCst), 3);
    }

    // A check past its time limit is killed at the deadline and is a failed
    // check: the model is shown the timeout, the host is sampled (§7.1).
    #[test]
    fn h3a_a_check_past_its_time_limit_is_killed_and_turns_the_submission_back() {
        static C: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("timeout");
        let spec = spec_of(vec![perl("sleep 20")], 1);
        let mut c = cfg();
        c.exec_call_timeout = Duration::from_secs(1);
        let started = Instant::now();
        let r = go(&state, &ws, &spec, vec![submit("a"), submit("b")], &c, &C);
        assert!(started.elapsed() < Duration::from_secs(20));
        assert_eq!(r.cause, StopCause::SubmittedChecksFailed);
        let recs = records(&r, 1);
        let x = exec_results(&recs);
        assert_eq!(x[0].body["status"], "timeout");
        assert_eq!(x[0].body["exec"]["guard"], "wall");
        assert!(x[0].body.contains_key("environment"));
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
        })
        .unwrap();
        assert_eq!(a.divergence, None, "{a:?}");
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

    // A kill in the middle of the checks, then a resume. The first check's
    // result is durable, so the catch-up re-feeds it and never runs it again
    // (its file still has one line); the second was cut before it started, so
    // it runs live in the resumed attempt (one spawn). The submission is then
    // accepted in the resumed attempt, and that attempt audits clean.
    #[test]
    fn h3a_resume_in_the_middle_of_the_checks_never_repeats_a_completed_check() {
        static C: Counting = Counting(AtomicUsize::new(0));
        static R: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("resume-mid");
        let spec = spec_of(vec![appends("a.txt"), appends("b.txt")], 2);
        let r = go(&state, &ws, &spec, vec![submit("done")], &cfg(), &C);
        assert_eq!(r.cause, StopCause::Submitted);
        assert_eq!(C.0.load(Ordering::SeqCst), 2);
        assert_eq!(
            (lines(&ws, "a.txt"), lines(&ws, "b.txt")),
            ("ran\n".into(), "ran\n".into())
        );
        // Kill after the first check's result; the second never started.
        let old = records(&r, 1);
        let first = exec_results(&old)[0].seq;
        cut_after(&r, first);
        fs::remove_file(ws.join("b.txt")).unwrap();
        let res = resumed(&state, &ws, &r, &spec, vec![], &R).unwrap();
        assert_eq!(res.cause, StopCause::Submitted);
        assert_eq!(res.steps, 1);
        assert_eq!(
            R.0.load(Ordering::SeqCst),
            1,
            "only the check that had not completed ran"
        );
        assert_eq!(
            lines(&ws, "a.txt"),
            "ran\n",
            "the completed check did not run again"
        );
        assert_eq!(lines(&ws, "b.txt"), "ran\n");
        let new = records(&res, 2);
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
        assert_eq!(exec_results(&new).len(), 2);
        assert_eq!(
            of(&new, EventKind::PresubmitChecked)[0].body["result"],
            "passed"
        );
        let a = audited(&state, &res, &spec, 2);
        assert_eq!(a.divergence, None, "{a:?}");
        assert!(a.stop_recomputed);
        assert_eq!(R.0.load(Ordering::SeqCst), 1, "the audit ran nothing");
    }

    // The intent of the second check is durable (written ahead) but its result
    // is not: the check may or may not have run, so it is decided again and run
    // in the resumed attempt (the first is still re-fed, not run again).
    #[test]
    fn h3a_resume_with_a_checks_intent_but_no_result_runs_that_check_again() {
        static C: Counting = Counting(AtomicUsize::new(0));
        static R: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("resume-intent");
        let spec = spec_of(vec![appends("a.txt"), appends("b.txt")], 2);
        let r = go(&state, &ws, &spec, vec![submit("done")], &cfg(), &C);
        let old = records(&r, 1);
        let second_result = exec_results(&old)[1];
        // The record before the second check's result is its intent.
        cut_after(&r, second_result.seq - 1);
        assert_eq!(
            records(&r, 1).last().unwrap().kind,
            EventKind::ToolStarted,
            "cut right after the intent"
        );
        fs::remove_file(ws.join("b.txt")).unwrap();
        let res = resumed(&state, &ws, &r, &spec, vec![], &R).unwrap();
        assert_eq!(res.cause, StopCause::Submitted);
        assert_eq!(R.0.load(Ordering::SeqCst), 1, "only the second check ran");
        assert_eq!(lines(&ws, "a.txt"), "ran\n");
        assert_eq!(lines(&ws, "b.txt"), "ran\n");
        let a = audited(&state, &res, &spec, 2);
        assert_eq!(a.divergence, None, "{a:?}");
    }

    // A kill after every check's result but before the round is recorded: the
    // resume re-feeds them all (no spawn at all), recomputes the round and
    // accepts the submission.
    #[test]
    fn h3a_resume_after_every_check_completed_runs_nothing() {
        static C: Counting = Counting(AtomicUsize::new(0));
        static R: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("resume-all");
        let spec = spec_of(vec![appends("a.txt"), appends("b.txt")], 2);
        let r = go(&state, &ws, &spec, vec![submit("done")], &cfg(), &C);
        let old = records(&r, 1);
        cut_after(&r, exec_results(&old)[1].seq);
        let res = resumed(&state, &ws, &r, &spec, vec![], &R).unwrap();
        assert_eq!(res.cause, StopCause::Submitted);
        assert_eq!(R.0.load(Ordering::SeqCst), 0, "nothing ran again");
        assert_eq!(lines(&ws, "a.txt"), "ran\n");
        assert_eq!(lines(&ws, "b.txt"), "ran\n");
        let a = audited(&state, &res, &spec, 2);
        assert_eq!(a.divergence, None, "{a:?}");
    }

    // A kill after a turned-back submission and its repair: the resume
    // re-feeds the failed round (the check does not run again for it), takes
    // the model's recorded repair, and runs only the new submission's check.
    #[test]
    fn h3a_resume_after_a_turned_back_submission_carries_its_round_count() {
        static C: Counting = Counting(AtomicUsize::new(0));
        static R: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("resume-round");
        let spec = spec_of(vec![perl("print qq{nope\\n}; exit 1")], 1);
        let r = go(
            &state,
            &ws,
            &spec,
            vec![submit("a"), write_file("x.txt", "x\n"), submit("b")],
            &cfg(),
            &C,
        );
        assert_eq!(r.cause, StopCause::SubmittedChecksFailed);
        assert_eq!(C.0.load(Ordering::SeqCst), 2);
        // Kill after the edit (step 2): the second submission never happened.
        let old = records(&r, 1);
        let last_of_step_2 = old
            .iter()
            .filter(|x| x.step == 2)
            .map(|x| x.seq)
            .max()
            .unwrap();
        cut_after(&r, last_of_step_2);
        let res = resumed(&state, &ws, &r, &spec, vec![submit("b")], &R).unwrap();
        // One turn-back was carried over, so the second failing submission is
        // accepted: the same stop as the uninterrupted run.
        assert_eq!(res.cause, StopCause::SubmittedChecksFailed);
        assert_eq!(
            R.0.load(Ordering::SeqCst),
            1,
            "only the new submission's check ran"
        );
        let report = res.presubmit.unwrap();
        assert_eq!((report.submissions, report.turned_back), (2, 1));
        let a = audited(&state, &res, &spec, 2);
        assert_eq!(a.divergence, None, "{a:?}");
    }

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

    fn unanchored(state: &Path, r: &RunReport, spec: &TaskSpec) -> AuditReport {
        audit(Audit {
            state_root: state,
            run: &r.run,
            attempt: Some(1),
            anchor: None,
            spec,
            registry: &registry(),
            policy: &allow_all(),
            profile: &Profile::conservative_default("m"),
            limits: &cfg().limits,
        })
        .unwrap()
    }

    // A check's record is re-fed by an audit, and what the loop derives from
    // it is recomputed. So a forged record of a check is caught even by an
    // unanchored audit, where the forgery changes what the loop decides: a
    // failed check recorded as passed makes the replay accept the submission
    // where the journal goes on; a round record rewritten (accepted, or its
    // count) differs from the recomputed one; a record of a shape the loop
    // never writes is refused as such. Every forgery here re-chains every
    // hash.
    #[test]
    fn h3a_forged_check_results_diverge_from_the_recomputation() {
        static C: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("forge");
        let spec = spec_of(vec![perl(NEEDS_FIXED)], 2);
        let r = go(
            &state,
            &ws,
            &spec,
            vec![
                submit("first"),
                write_file("fixed.txt", "ok\n"),
                submit("second"),
            ],
            &cfg(),
            &C,
        );
        assert_eq!(r.cause, StopCause::Submitted);
        let path = layout::attempt_dir(&r.run_dir, 1).join(layout::JOURNAL_FILE);
        let pristine = fs::read(&path).unwrap();
        assert_eq!(unanchored(&state, &r, &spec).divergence, None);
        let first_exec =
            |v: &Value| v["kind"] == "ToolFinished" && v["body"]["exec"]["code"] == json!(3);
        type Forgery = Box<dyn Fn(&mut Value)>;
        let cases: Vec<(&str, Forgery)> = vec![
            (
                "a failed check recorded as passed",
                Box::new(move |v: &mut Value| {
                    if first_exec(v) {
                        v["body"]["exec"]["code"] = json!(0);
                    }
                }),
            ),
            (
                "a round recorded as accepted",
                Box::new(move |v: &mut Value| {
                    if v["kind"] == "PresubmitChecked" && v["body"]["accepted"] == json!(false) {
                        v["body"]["accepted"] = json!(true);
                    }
                }),
            ),
            (
                "a round's count changed",
                Box::new(move |v: &mut Value| {
                    if v["kind"] == "PresubmitChecked" && v["body"]["round"] == json!(2) {
                        v["body"]["turned_back"] = json!(0);
                    }
                }),
            ),
            (
                "a round with a key the loop never writes",
                Box::new(move |v: &mut Value| {
                    if v["kind"] == "PresubmitChecked" && v["body"]["round"] == json!(1) {
                        v["body"]["extra"] = json!(1);
                    }
                }),
            ),
            (
                "an extra key in a check's command record",
                Box::new(move |v: &mut Value| {
                    if first_exec(v) {
                        v["body"]["exec"]["extra"] = json!(1);
                    }
                }),
            ),
        ];
        for (what, edit) in cases {
            fs::write(&path, &pristine).unwrap();
            forge(&r, edit);
            let a = unanchored(&state, &r, &spec);
            assert!(a.divergence.is_some(), "{what}: {a:?}");
        }
        assert_eq!(C.0.load(Ordering::SeqCst), 2, "no audit ran anything");
    }

    // The checks are a header input: an audit or a resume given other checks
    // (or none) is refused by name, and a run without checks has no such key.
    #[test]
    fn h3a_the_checks_are_a_header_input() {
        static C: Counting = Counting(AtomicUsize::new(0));
        static R: Counting = Counting(AtomicUsize::new(0));
        let (state, ws) = scratch("header");
        let spec = spec_of(vec![appends("a.txt")], 2);
        let r = go(&state, &ws, &spec, vec![submit("done")], &cfg(), &C);
        let head = &records(&r, 1)[0];
        assert_eq!(
            head.body["presubmit"]["spec"],
            spec.presubmit.as_ref().unwrap().digest().to_string()
        );
        let why = |spec: &TaskSpec| unanchored(&state, &r, spec).divergence.map(|d| d.why);
        let want = Some("the pre-submit checks given differ from the recorded header");
        let mut more_rounds = spec_of(vec![appends("a.txt")], 3);
        assert_eq!(why(&more_rounds), want);
        more_rounds.presubmit = Some(PresubmitSpec {
            commands: vec![appends("b.txt")],
            max_rounds: 2,
        });
        assert_eq!(why(&more_rounds), want);
        let mut none = spec_of(vec![appends("a.txt")], 2);
        none.presubmit = None;
        assert_eq!(why(&none), want);
        // A resume is refused the same way, before anything is written.
        cut_after(&r, records(&r, 1)[0].seq + 5);
        let e = resumed(&state, &ws, &r, &none, vec![], &R).unwrap_err();
        assert!(
            e.to_string().contains("the pre-submit checks given differ"),
            "{e}"
        );
        assert_eq!(R.0.load(Ordering::SeqCst), 0);
        // And a run without checks writes no such key.
        static D: Counting = Counting(AtomicUsize::new(0));
        let (state2, ws2) = scratch("header-none");
        let plain = task(&["harness.fs.read", EXEC], Some(perl_spec()), None);
        let r2 = go(&state2, &ws2, &plain, vec![submit("done")], &cfg(), &D);
        assert!(!records(&r2, 1)[0].body.contains_key("presubmit"));
        assert!(r2.presubmit.is_none());
        assert_eq!(D.0.load(Ordering::SeqCst), 0, "no check without a spec");
    }
}
