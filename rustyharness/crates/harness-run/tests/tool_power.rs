//! H2e in the loop: the checklist, the budget notices, the read window,
//! several edits in one file, and the glob and the regex search, through
//! the public `run`, `audit` and `resume` with the real journal, the real
//! tools and a scripted model. Each is journaled, audits clean (the
//! checklist and the step notices recomputed, the wall notices re-fed), and
//! a forged record is caught.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use harness_core::environment::{EnvSample, Unmeasured};
use harness_core::{BudgetDim, StopCause};
use harness_journal::{layout, EventKind, JournalReader, Record};
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, SemVer, ValidationContext};
use harness_model::profile::Profile;
use harness_model::scripted::{text_reply, ScriptedBackend};
use harness_model::{Completion, ModelBackend, ModelError, ModelIdentity, ModelRequest, TaskText};
use harness_policy::locality::{FsQuery, LocalityProbe};
use harness_policy::UserPolicy;
use harness_run::{audit, resume, run, Audit, Resume, Run, RunConfig, RunReport, TaskSpec};
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

const LIB: &str = "/// The first retry waits this long.\npub const RETRY_BASE_MS: u64 = 250;\n\npub fn backoff(n: u32) -> u64 {\n    RETRY_BASE_MS << n\n}\n";

fn scratch(name: &str) -> (PathBuf, PathBuf) {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("tool-power-{name}"));
    let _ = fs::remove_dir_all(&base);
    let (state, ws) = (base.join("state"), base.join("ws"));
    fs::create_dir_all(&state).unwrap();
    fs::create_dir_all(ws.join("src/net")).unwrap();
    fs::create_dir_all(ws.join("docs")).unwrap();
    fs::write(ws.join("src/lib.rs"), LIB).unwrap();
    fs::write(
        ws.join("src/net/mod.rs"),
        "pub const MAX_FETCH_RETRIES: u32 = 4;\n",
    )
    .unwrap();
    for i in 0..10 {
        fs::write(ws.join(format!("docs/f{i}.md")), format!("note {i}\n")).unwrap();
    }
    let long: String = (1..=50).map(|i| format!("line {i}\n")).collect();
    fs::write(ws.join("docs/long.txt"), long).unwrap();
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
fn read(p: &str) -> Result<Completion, ModelError> {
    action("harness.fs.read", &json!({ "path": p }))
}
fn todo(args: Value) -> Result<Completion, ModelError> {
    action("harness.task.todo", &args)
}
fn submit() -> Result<Completion, ModelError> {
    action("harness.task.submit", &json!({ "note": "done" }))
}

fn spec(grants: &[&str]) -> TaskSpec {
    TaskSpec {
        task: TaskText::new("Tune the retry base.".into()),
        grants: grants.iter().map(|g| (*g).to_owned()).collect(),
        workspace_public: false,
        ports: Vec::new(),
        lan_ports: Vec::new(),
        exec: None,
        presubmit: None,
        post_edit: None,
        protected: Vec::new(),
        kind: harness_run::SessionKind::Coding,
    }
}

/// A scripted model that keeps what each request showed it, optionally
/// slow (to spend wall time).
struct Capture {
    inner: ScriptedBackend,
    profile: Profile,
    delay: Duration,
    bodies: RefCell<Vec<String>>,
}

impl ModelBackend for Capture {
    fn identity(&self) -> ModelIdentity {
        self.inner.identity()
    }
    fn complete(&self, req: &ModelRequest, deadline: Instant) -> Result<Completion, ModelError> {
        if let Ok(v) = harness_model::wire::render_request(req, &self.profile) {
            self.bodies.borrow_mut().push(v.to_string());
        }
        std::thread::sleep(self.delay);
        self.inner.complete(req, deadline)
    }
}

fn capture(profile: &Profile, replies: Vec<Result<Completion, ModelError>>) -> Capture {
    Capture {
        inner: ScriptedBackend::new(profile.clone(), replies),
        profile: profile.clone(),
        delay: Duration::ZERO,
        bodies: RefCell::new(Vec::new()),
    }
}

/// Everything a run, its audit and its resume must agree on.
struct Setup {
    grants: Vec<&'static str>,
    policy: UserPolicy,
    profile: Profile,
    config: RunConfig,
}

impl Setup {
    fn new(grants: &[&'static str]) -> Self {
        Self {
            grants: grants.to_vec(),
            policy: UserPolicy::default(),
            profile: Profile::conservative_default("m"),
            config: RunConfig::defaults(1_000_000),
        }
    }

    fn go(&self, state: &Path, ws: &Path, backend: &dyn ModelBackend) -> RunReport {
        run(Run {
            state_root: state,
            workspace: ws,
            spec: &spec(&self.grants),
            registry: &registry(),
            policy: &self.policy,
            profile: &self.profile,
            backend,
            probe: &Local,
            env: &FIXED_ENV,
            config: &self.config,
            approver: None,
            confinement: None,
        })
        .unwrap()
    }

    fn audit(&self, state: &Path, r: &RunReport, attempt: u32) -> harness_run::AuditReport {
        audit(Audit {
            state_root: state,
            run: &r.run,
            attempt: Some(attempt),
            anchor: None,
            spec: &spec(&self.grants),
            registry: &registry(),
            policy: &self.policy,
            profile: &self.profile,
            limits: &self.config.limits,
        })
        .unwrap()
    }

    fn resume(
        &self,
        state: &Path,
        ws: &Path,
        r: &RunReport,
        replies: Vec<Result<Completion, ModelError>>,
    ) -> RunReport {
        let backend = ScriptedBackend::new(self.profile.clone(), replies);
        resume(Resume {
            state_root: state,
            run: &r.run,
            workspace: Some(ws),
            spec: &spec(&self.grants),
            registry: &registry(),
            policy: &self.policy,
            profile: &self.profile,
            backend: &backend,
            probe: &Local,
            env: &FIXED_ENV,
            config: &self.config,
            approver: None,
            confinement: None,
        })
        .unwrap()
    }
}

fn records(r: &RunReport, attempt: u32) -> Vec<Record> {
    JournalReader::open(&layout::attempt_dir(&r.run_dir, attempt))
        .unwrap()
        .records
}

fn of(recs: &[Record], kind: EventKind) -> Vec<&Record> {
    recs.iter().filter(|r| r.kind == kind).collect()
}

/// The results of the calls to `tool`, in order: (status, inline output).
fn results(recs: &[Record], tool: &str) -> Vec<(String, String)> {
    let intents: Vec<u64> = recs
        .iter()
        .filter(|r| r.kind == EventKind::ToolStarted && r.body["capability"] == tool)
        .map(|r| r.seq)
        .collect();
    recs.iter()
        .filter(|r| {
            r.kind == EventKind::ToolFinished
                && intents.contains(&r.body["intent_seq"].as_u64().unwrap())
        })
        .map(|r| {
            (
                r.body["status"].as_str().unwrap().to_owned(),
                harness_journal::canon::unescape(r.body["output"]["inline"].as_str().unwrap_or(""))
                    .unwrap(),
            )
        })
        .collect()
}

/// Rewrite attempt 1's journal, `edit` changing records, and re-chain it:
/// a forger who recomputes every hash. Only the replay (or an anchor) can
/// catch this.
fn forge(r: &RunReport, keep: impl Fn(&Value) -> bool, edit: impl Fn(&mut Value)) {
    use harness_journal::canon::{RecordFields, GENESIS};
    let path = layout::attempt_dir(&r.run_dir, 1).join(layout::JOURNAL_FILE);
    let text = fs::read_to_string(&path).unwrap();
    let mut prev = GENESIS;
    let mut seq = 0u64;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut v: Value = serde_json::from_str(line).unwrap();
        if !keep(&v) {
            continue;
        }
        edit(&mut v);
        let f = RecordFields {
            seq,
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
        seq += 1;
    }
    fs::write(path, out).unwrap();
}

/// Cut attempt `attempt`'s journal after the records of steps < `keep_below`
/// (a kill between steps: whole lines survive, `RunStopped` is gone).
fn crash_after(r: &RunReport, attempt: u32, keep_below: u64) {
    let path = layout::attempt_dir(&r.run_dir, attempt).join(layout::JOURNAL_FILE);
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

const TWO_ITEMS: &str = "checklist updated: 2 item(s): 0 done, 1 in progress, 1 pending\n1. [in progress] read the backoff code\n2. [pending] change the base\n";

fn two_items() -> Value {
    json!({"items": [
        {"text": "read the backoff code", "status": "in_progress"},
        {"text": "change the base", "status": "pending"}
    ]})
}

// The checklist: each call's result is the list after it, journaled like
// any tool's result and shown as an observation; a call without items
// shows it; a refused call changes nothing. The audit recomputes every
// result (never re-fed), so a forged one diverges.
#[test]
fn h2e_the_checklist_is_kept_shown_and_recomputed_by_the_audit() {
    let (state, ws) = scratch("todo");
    let s = Setup::new(&["harness.fs.read", "harness.task.todo"]);
    let many: Vec<Value> = (0..21)
        .map(|i| json!({"text": format!("step {i}"), "status": "pending"}))
        .collect();
    let backend = capture(
        &s.profile,
        vec![
            todo(two_items()),
            read("src/lib.rs"),
            todo(json!({})),
            todo(json!({ "items": many })),
            submit(),
        ],
    );
    let r = s.go(&state, &ws, &backend);
    assert_eq!(r.cause, StopCause::Submitted);
    let recs = records(&r, 1);
    let got = results(&recs, "harness.task.todo");
    assert_eq!(got[0], ("ok".into(), TWO_ITEMS.into()));
    assert_eq!(got[1], ("ok".into(), TWO_ITEMS.replacen(" updated", "", 1)));
    assert_eq!(got[2].0, "error");
    assert!(got[2].1.contains("at most 20 items"), "{}", got[2].1);
    // Allowed by its own rule; never a provider failure.
    let rules: Vec<&str> = of(&recs, EventKind::PolicyDecided)
        .iter()
        .map(|p| p.body["rule"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(rules.iter().filter(|r| **r == "allow.task-todo").count(), 3);
    // The model saw the list as the tool's result.
    assert!(backend.bodies.borrow()[1].contains("1. [in progress] read the backoff code"));
    assert_eq!(s.audit(&state, &r, 1).divergence, None);
    // A forged checklist result is recomputed differently.
    forge(
        &r,
        |_| true,
        |v| {
            if v["kind"] == "ToolFinished" {
                if let Some(o) = v["body"]["output"]["inline"].as_str() {
                    if o.starts_with("checklist updated: 2") {
                        let forged = o.replace("change the base", "remove the test");
                        let raw = harness_journal::canon::unescape(&forged).unwrap();
                        v["body"]["output"]["sha256"] =
                            Value::from(harness_core::sha256(raw.as_bytes()).to_string());
                        v["body"]["output"]["inline"] = Value::from(forged);
                    }
                }
            }
        },
    );
    let a = s.audit(&state, &r, 1);
    let d = a.divergence.expect("the forged result is caught");
    assert_eq!(
        d.why, "the replay recomputed a different body for this record",
        "{d:?}"
    );
}

// The step notices: after the first step at or past 50%, 80% and 90% of the
// step budget, and when one step is left; journaled (`BudgetNotice`) and
// shown after that step's turn in every later request, with the
// checklist's open items counted; recomputed by the audit.
#[test]
fn h2e_step_notices_come_at_the_thresholds_and_audit_clean() {
    let (state, ws) = scratch("step-notices");
    let mut s = Setup::new(&["harness.fs.read", "harness.task.todo"]);
    s.config.limits.steps = 10;
    let mut replies = vec![todo(two_items())];
    replies.extend((0..8).map(|i| read(&format!("docs/f{i}.md"))));
    replies.push(submit());
    let backend = capture(&s.profile, replies);
    let r = s.go(&state, &ws, &backend);
    assert_eq!((r.cause.clone(), r.steps), (StopCause::Submitted, 10));
    let recs = records(&r, 1);
    let notices: Vec<(u64, String, u64)> = of(&recs, EventKind::BudgetNotice)
        .iter()
        .map(|n| {
            (
                n.step,
                n.body["key"].as_str().unwrap().to_owned(),
                n.body["used"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        notices,
        [
            (5, "steps".into(), 5),
            (8, "steps".into(), 8),
            (9, "last_step".into(), 9)
        ]
    );
    let bodies = backend.bodies.borrow();
    let first = "Budget: 5 of 10 steps used, 5 left. If you already have what the task asks for, call harness.task.submit now. Your checklist has 2 open item(s).";
    let seen: Vec<bool> = bodies.iter().map(|b| b.contains(first)).collect();
    assert_eq!(
        seen,
        [false, false, false, false, false, true, true, true, true, true]
    );
    assert!(bodies[9].contains("your next reply is your last step"));
    let a = s.audit(&state, &r, 1);
    assert_eq!(a.divergence, None, "{a:?}");
    assert!(a.stop_recomputed);
    // A notice the loop would not write (moved to another step) diverges.
    forge(
        &r,
        |_| true,
        |v| {
            if v["kind"] == "BudgetNotice" && v["step"] == 5 {
                v["step"] = Value::from(4);
            }
        },
    );
    assert!(s.audit(&state, &r, 1).divergence.is_some());
}

// The wall notice: measured from the meter when the run is live (a slow
// model spends the time), journaled with the time it saw, shown after that
// step's turn; the audit cannot recompute the clock, so it re-feeds the
// recorded notice, and refuses one the loop would not write.
#[test]
fn h2e_a_wall_notice_is_measured_live_and_re_fed_by_the_audit() {
    let (state, ws) = scratch("wall-notice");
    let mut s = Setup::new(&["harness.fs.read"]);
    s.config.limits.wall = Duration::from_secs(8);
    let mut backend = capture(
        &s.profile,
        vec![
            read("docs/f0.md"),
            read("docs/f1.md"),
            read("docs/f2.md"),
            submit(),
        ],
    );
    backend.delay = Duration::from_millis(1500);
    let r = s.go(&state, &ws, &backend);
    assert_eq!(r.cause, StopCause::Submitted, "{:?}", r.cause);
    let recs = records(&r, 1);
    let walls: Vec<&Record> = of(&recs, EventKind::BudgetNotice)
        .into_iter()
        .filter(|n| n.body["key"] == "wall")
        .collect();
    assert!(!walls.is_empty(), "the model took over half the budget");
    let w = walls[0];
    let percent = w.body["percent"].as_u64().unwrap();
    assert!([50, 80, 90].contains(&percent), "{percent}");
    assert_eq!(w.body["limit_ms"], 8000);
    assert!(w.body["used_ms"].as_u64().unwrap() * 100 >= percent * 8000);
    let shown = format!("Budget: {percent}% of the time budget is used");
    let bodies = backend.bodies.borrow();
    let at = usize::try_from(w.step).unwrap();
    assert!(!bodies[at - 1].contains(&shown));
    assert!(bodies[at].contains(&shown), "{}", bodies[at]);
    let a = s.audit(&state, &r, 1);
    assert_eq!(a.divergence, None, "{a:?}");
    // A wall notice the loop would not write: a threshold the recorded time
    // did not reach.
    forge(
        &r,
        |_| true,
        |v| {
            if v["kind"] == "BudgetNotice" && v["body"]["key"] == "wall" {
                v["body"]["percent"] = Value::from(90);
                v["body"]["used_ms"] = Value::from(100);
            }
        },
    );
    assert!(s.audit(&state, &r, 1).divergence.is_some());
}

// A resume re-drives the catch-up: the checklist is rebuilt from the
// recorded calls (a live call without items shows it), and the step
// notices are recomputed; the resumed attempt audits clean.
#[test]
fn h2e_a_resume_rebuilds_the_checklist_and_its_notices() {
    let (state, ws) = scratch("resume-todo");
    let mut s = Setup::new(&["harness.fs.read", "harness.task.todo"]);
    s.config.limits.steps = 6;
    let backend = capture(
        &s.profile,
        vec![
            todo(two_items()),
            read("docs/f0.md"),
            read("docs/f1.md"),
            read("docs/f2.md"),
            submit(),
        ],
    );
    let r = s.go(&state, &ws, &backend);
    assert_eq!(r.cause, StopCause::Submitted);
    crash_after(&r, 1, 5);
    let res = s.resume(&state, &ws, &r, vec![todo(json!({})), submit()]);
    assert_eq!((res.cause.clone(), res.steps), (StopCause::Submitted, 6));
    let recs = records(&res, 2);
    let got = results(&recs, "harness.task.todo");
    assert_eq!(got.len(), 2);
    assert_eq!(got[1], ("ok".into(), TWO_ITEMS.replacen(" updated", "", 1)));
    let notices: Vec<(u64, String)> = of(&recs, EventKind::BudgetNotice)
        .iter()
        .map(|n| (n.step, n.body["key"].as_str().unwrap().to_owned()))
        .collect();
    assert_eq!(notices, [(3, "steps".into()), (5, "last_step".into())]);
    let a = s.audit(&state, &res, 2);
    assert_eq!(a.divergence, None, "{a:?}");
}

// The read window is the profile's: the read tool is offered with it, a
// read returns at most that many lines, and a read asking for more is
// denied with the window's bounds; the audit plans the same window.
#[test]
fn h2e_the_read_window_comes_from_the_profile() {
    let (state, ws) = scratch("window");
    let mut s = Setup::new(&["harness.fs.read"]);
    s.profile = Profile::parse(
        br#"{"profile_version":1,"id":"narrow","model":"m","context_window":8192,
        "fill_ratio":0.6,"protocol":"text","tool_choice_required_ok":false,"grammar":"none",
        "max_active_tools":5,"edit_format":"replace","recent_turns":4,"max_read_lines":20,
        "sampling":{"temperature":0.2,"top_p":0.95,"max_tokens":1024}}"#,
    )
    .unwrap();
    let backend = capture(
        &s.profile,
        vec![
            read("docs/long.txt"),
            action(
                "harness.fs.read",
                &json!({"path": "docs/long.txt", "start": 21, "lines": 30}),
            ),
            submit(),
        ],
    );
    let r = s.go(&state, &ws, &backend);
    assert_eq!(r.cause, StopCause::Submitted);
    let recs = records(&r, 1);
    let got = results(&recs, "harness.fs.read");
    assert_eq!(got.len(), 1, "the second read was denied");
    assert!(
        got[0].1.starts_with("docs/long.txt: lines 1-20 of 50;"),
        "{}",
        got[0].1
    );
    let bodies = backend.bodies.borrow();
    assert!(bodies[0].contains("Read a window of lines (at most 20)"));
    assert!(
        bodies[0].contains(r#"\"lines\":{\"maximum\":20,\"minimum\":1,\"type\":\"integer\"}"#),
        "{}",
        bodies[0]
    );
    assert!(bodies[2].contains("the argument lines must be an integer from 1 to 20"));
    assert_eq!(s.audit(&state, &r, 1).divergence, None);
}

// Several edits in one file are one verified edit and one `EditApplied`;
// the audit re-feeds it and a resume never applies it again.
#[test]
fn h2e_several_edits_in_one_file_are_one_edit_record_never_repeated() {
    let (state, ws) = scratch("multi");
    let mut s = Setup::new(&["harness.fs.read", "harness.edit.multi"]);
    s.policy = UserPolicy::new(&[], &[], &["harness.edit.multi"]).unwrap();
    let edits = json!({"path": "src/lib.rs", "edits": [
        {"old": "/// The first retry waits this long.", "new": "/// The first retry waits this long, in milliseconds."},
        {"old": "RETRY_BASE_MS: u64 = 250", "new": "BASE_DELAY_MS: u64 = 375"},
        {"old": "    RETRY_BASE_MS << n", "new": "    BASE_DELAY_MS << n"}
    ]});
    let backend = capture(
        &s.profile,
        vec![
            read("src/lib.rs"),
            action("harness.edit.multi", &edits),
            read("src/lib.rs"),
            submit(),
        ],
    );
    let r = s.go(&state, &ws, &backend);
    assert_eq!(r.cause, StopCause::Submitted);
    let want = "/// The first retry waits this long, in milliseconds.\npub const BASE_DELAY_MS: u64 = 375;\n\npub fn backoff(n: u32) -> u64 {\n    BASE_DELAY_MS << n\n}\n";
    assert_eq!(fs::read_to_string(ws.join("src/lib.rs")).unwrap(), want);
    let recs = records(&r, 1);
    assert_eq!(of(&recs, EventKind::EditApplied).len(), 1);
    assert_eq!(s.audit(&state, &r, 1).divergence, None);
    // Kill after the edit's step; the resume re-feeds it.
    crash_after(&r, 1, 3);
    let res = s.resume(&state, &ws, &r, vec![submit()]);
    assert_eq!((res.cause.clone(), res.steps), (StopCause::Submitted, 3));
    assert_eq!(fs::read_to_string(ws.join("src/lib.rs")).unwrap(), want);
    assert_eq!(s.audit(&state, &res, 2).divergence, None);
}

// The glob and the regex search in the loop: journaled, a repeated glob on
// an unchanged workspace noticed like any read, audited clean.
#[test]
fn h2e_glob_and_regex_search_run_in_the_loop_and_audit_clean() {
    let (state, ws) = scratch("search");
    let s = Setup::new(&["harness.fs.read", "harness.fs.search", "harness.fs.glob"]);
    let glob = || action("harness.fs.glob", &json!({"pattern": "**/*.rs"}));
    let backend = capture(
        &s.profile,
        vec![
            glob(),
            action(
                "harness.fs.search",
                &json!({"pattern": "MAX_\\w+_RETRIES: u32 = \\d+", "regex": true, "include": "*.rs"}),
            ),
            glob(),
            submit(),
        ],
    );
    let r = s.go(&state, &ws, &backend);
    assert_eq!(r.cause, StopCause::Submitted);
    let recs = records(&r, 1);
    let globs = results(&recs, "harness.fs.glob");
    assert_eq!(
        globs[0],
        (
            "ok".into(),
            format!(
                "2 file(s) match under .\nsrc/lib.rs ({} bytes)\nsrc/net/mod.rs (38 bytes)\n",
                LIB.len()
            )
        )
    );
    let found = results(&recs, "harness.fs.search");
    assert!(
        found[0].1.starts_with("1 hit(s) in 1 file(s) for a regex match\nsrc/net/mod.rs (1 hit(s))\n  1: pub const MAX_FETCH_RETRIES: u32 = 4;\n"),
        "{}",
        found[0].1
    );
    assert!(backend.bodies.borrow()[3].contains("this call repeats an earlier one exactly"));
    assert_eq!(s.audit(&state, &r, 1).divergence, None);
}

// P-24: the outline runs in the loop: journaled, audited clean, and a
// repeated outline on an unchanged workspace is noticed like any read.
#[test]
fn p24_outline_runs_in_the_loop_and_audits_clean() {
    let (state, ws) = scratch("outline");
    let s = Setup::new(&["harness.fs.outline"]);
    let outlines = || action("harness.fs.outline", &json!({}));
    let backend = capture(&s.profile, vec![outlines(), outlines(), submit()]);
    let r = s.go(&state, &ws, &backend);
    assert_eq!(r.cause, StopCause::Submitted);
    let recs = records(&r, 1);
    let got = results(&recs, "harness.fs.outline");
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].0, "ok");
    let out = &got[0].1;
    assert!(
        out.starts_with("1 symbol(s) in 1 file(s) under .; sha256 "),
        "{out}"
    );
    assert!(
        out.contains("src/lib.rs\n  4: pub fn backoff(n: u32) -> u64 {\n"),
        "{out}"
    );
    // The two calls over the same workspace agree byte for byte.
    assert_eq!(got[0].1, got[1].1);
    // The repeated call was noticed like any repeated read.
    assert!(backend.bodies.borrow()[2].contains("this call repeats an earlier one exactly"));
    assert_eq!(s.audit(&state, &r, 1).divergence, None);
}

// A run that stops on its step budget still has had every notice: the last
// one said the next reply was the last.
#[test]
fn h2e_a_run_that_runs_out_of_steps_was_told_before_its_last() {
    let (state, ws) = scratch("out-of-steps");
    let mut s = Setup::new(&["harness.fs.read"]);
    s.config.limits.steps = 4;
    let backend = capture(
        &s.profile,
        (0..6).map(|i| read(&format!("docs/f{i}.md"))).collect(),
    );
    let r = s.go(&state, &ws, &backend);
    assert_eq!(r.cause, StopCause::Budget(BudgetDim::Steps));
    let bodies = backend.bodies.borrow();
    assert_eq!(bodies.len(), 4);
    assert!(bodies[2].contains("Budget: 2 of 4 steps used, 2 left."));
    assert!(bodies[3].contains("Budget: 3 of 4 steps used; your next reply is your last step."));
    assert_eq!(s.audit(&state, &r, 1).divergence, None);
}

// A path the lexical rule refuses is denied in words that say how to name
// the root (a judge-reviewed run sent "" for it and was not told): the root
// is "."; an optional path may be left out. The rule itself is unchanged.
#[test]
fn h2e_an_empty_or_absolute_path_is_denied_with_how_to_name_the_root() {
    let (state, ws) = scratch("empty-path");
    let s = Setup::new(&["harness.fs.search", "harness.fs.glob"]);
    let backend = capture(
        &s.profile,
        vec![
            action("harness.fs.glob", &json!({"pattern": "*.md", "path": ""})),
            action(
                "harness.fs.search",
                &json!({"pattern": "x", "path": "/etc"}),
            ),
            submit(),
        ],
    );
    let r = s.go(&state, &ws, &backend);
    assert_eq!(r.cause, StopCause::Submitted);
    let bodies = backend.bodies.borrow();
    assert!(
        bodies[1].contains(r#"the path is empty. The workspace root is \".\"; where path is optional, leaving it out means the root."#),
        "{}",
        bodies[1]
    );
    assert!(
        bodies[2].contains("the path is absolute. Paths are relative to the workspace root"),
        "{}",
        bodies[2]
    );
    assert_eq!(s.audit(&state, &r, 1).divergence, None);
}

// A resume's catch-up re-feeds a recorded wall notice (the clock cannot be
// replayed): the catch-up renders every recorded request byte for byte, so
// the resumed run is not unreadable, and the resumed journal repeats the
// notice as recorded; a live step after the catch-up measures the meter,
// which carries the time the first attempt spent.
#[test]
fn h2e_a_resume_re_feeds_a_recorded_wall_notice() {
    let (state, ws) = scratch("resume-wall");
    let mut s = Setup::new(&["harness.fs.read"]);
    s.config.limits.wall = Duration::from_secs(8);
    let mut backend = capture(
        &s.profile,
        vec![
            read("docs/f0.md"),
            read("docs/f1.md"),
            read("docs/f2.md"),
            submit(),
        ],
    );
    backend.delay = Duration::from_millis(1500);
    let r = s.go(&state, &ws, &backend);
    assert_eq!(r.cause, StopCause::Submitted, "{:?}", r.cause);
    let walls = |recs: &[Record]| -> Vec<(u64, Value, Value)> {
        of(recs, EventKind::BudgetNotice)
            .into_iter()
            .filter(|n| n.body["key"] == "wall")
            .map(|n| (n.step, n.body["percent"].clone(), n.body["used_ms"].clone()))
            .collect()
    };
    let before = walls(&records(&r, 1));
    assert!(
        !before.is_empty(),
        "the slow model spent over half the budget"
    );
    // Kill after the last read's step; the catch-up re-drives steps 1-3.
    crash_after(&r, 1, 4);
    let res = s.resume(&state, &ws, &r, vec![submit()]);
    assert_eq!((res.cause.clone(), res.steps), (StopCause::Submitted, 4));
    assert_ne!(
        res.outcome,
        gate_outcome::GateOutcome::Indeterminate {
            why: gate_outcome::IndeterminateKind::UnreadableEvidence
        },
        "every recorded request rendered byte for byte"
    );
    assert_eq!(walls(&records(&res, 2)), before, "re-fed as recorded");
    assert_eq!(s.audit(&state, &res, 2).divergence, None);
}

// H2f: a new file's missing directories are made by the write, the result
// names them, it is one edit record, the tree digest the loop keeps equals
// the one a fresh walk measures (the resume's catch-up measures it), and the
// audit and a resume agree.
#[test]
fn h2f_a_write_creates_its_missing_directories_and_audits_clean() {
    let (state, ws) = scratch("write-dirs");
    let mut s = Setup::new(&["harness.fs.read", "harness.edit.write"]);
    s.policy = UserPolicy::new(&[], &[], &["harness.edit.write"]).unwrap();
    let backend = capture(
        &s.profile,
        vec![
            action(
                "harness.edit.write",
                &json!({"path": "docs/notes/design.md", "content": "# Design\n"}),
            ),
            read("docs/notes/design.md"),
            submit(),
        ],
    );
    let r = s.go(&state, &ws, &backend);
    assert_eq!(r.cause, StopCause::Submitted);
    assert_eq!(
        fs::read_to_string(ws.join("docs/notes/design.md")).unwrap(),
        "# Design\n"
    );
    let recs = records(&r, 1);
    assert_eq!(of(&recs, EventKind::EditApplied).len(), 1);
    assert_eq!(s.audit(&state, &r, 1).divergence, None);
    // Kill after the write's step; the resume measures the tree afresh and
    // must find the digest the live run recorded.
    crash_after(&r, 1, 2);
    let res = s.resume(&state, &ws, &r, vec![submit()]);
    assert_eq!((res.cause.clone(), res.steps), (StopCause::Submitted, 2));
    assert_eq!(s.audit(&state, &res, 2).divergence, None);
}
