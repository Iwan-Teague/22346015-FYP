//! H2b: edits in the loop. Whole runs through the public `run` and `audit`
//! with the real journal, the real read and edit tools and a scripted
//! model: an edit is decided by policy, anchored on the run's reads,
//! journaled (`EditApplied` before its `ToolFinished`), keeps the tree
//! digest current, and is re-fed, never re-applied, by an audit.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use gate_outcome::{GateOutcome, IndeterminateKind};
use harness_core::environment::{EnvSample, Unmeasured};
use harness_core::{sha256, LoopKind, StopCause};
use harness_journal::{layout, EventKind, JournalReader, Record};
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, SemVer, ValidationContext};
use harness_model::profile::Profile;
use harness_model::scripted::{text_reply, ScriptedBackend};
use harness_model::{Completion, ModelBackend, ModelError, ModelIdentity, ModelRequest, TaskText};
use harness_policy::locality::{FsQuery, LocalityProbe};
use harness_policy::UserPolicy;
use harness_run::{audit, run, Audit, Run, RunConfig, RunReport, TaskSpec};
use harness_tools::builtin::workspace_facts;
use serde_json::Value;

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

const LIB: &str = "pub const RETRY_BASE_MS: u64 = 250;\npub fn backoff(n: u32) -> u64 {\n    RETRY_BASE_MS << n\n}\n";

fn scratch(name: &str) -> (PathBuf, PathBuf) {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("edits-{name}"));
    let _ = fs::remove_dir_all(&base);
    let (state, ws) = (base.join("state"), base.join("ws"));
    fs::create_dir_all(&state).unwrap();
    fs::create_dir_all(ws.join("src")).unwrap();
    fs::write(ws.join("src/lib.rs"), LIB).unwrap();
    fs::write(ws.join("README.md"), "# fixture\n").unwrap();
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
    action("harness.fs.read", &serde_json::json!({ "path": p }))
}
fn replace(p: &str, old: &str, new: &str) -> Result<Completion, ModelError> {
    action(
        "harness.edit.replace",
        &serde_json::json!({ "path": p, "old": old, "new": new }),
    )
}
fn write(p: &str, content: &str) -> Result<Completion, ModelError> {
    action(
        "harness.edit.write",
        &serde_json::json!({ "path": p, "content": content }),
    )
}
fn submit() -> Result<Completion, ModelError> {
    action(
        "harness.task.submit",
        &serde_json::json!({ "note": "done" }),
    )
}

const TASK: &str = "Set the retry base to 375 ms.";
const GRANTS: [&str; 3] = [
    "harness.fs.read",
    "harness.edit.replace",
    "harness.edit.write",
];

fn spec() -> TaskSpec {
    TaskSpec {
        task: TaskText::new(TASK.into()),
        grants: GRANTS.iter().map(|g| (*g).to_owned()).collect(),
        workspace_public: false,
        exec: None,
        presubmit: None,
    }
}

/// The policy an unattended run edits under: the edit tools allowed.
fn allow_edits() -> UserPolicy {
    UserPolicy::new(&[], &[], &["harness.edit.replace", "harness.edit.write"]).unwrap()
}

fn go_with(state: &Path, ws: &Path, policy: &UserPolicy, backend: &dyn ModelBackend) -> RunReport {
    run(Run {
        state_root: state,
        workspace: ws,
        spec: &spec(),
        registry: &registry(),
        policy,
        profile: &Profile::conservative_default("m"),
        backend,
        probe: &Local,
        env: &FIXED_ENV,
        config: &RunConfig::defaults(1_000_000),
        approver: None,
        confinement: None,
    })
    .unwrap()
}

fn go(
    state: &Path,
    ws: &Path,
    policy: &UserPolicy,
    replies: Vec<Result<Completion, ModelError>>,
) -> RunReport {
    let backend = ScriptedBackend::new(Profile::conservative_default("m"), replies);
    go_with(state, ws, policy, &backend)
}

fn records(r: &RunReport) -> Vec<Record> {
    JournalReader::open(&layout::attempt_dir(&r.run_dir, 1))
        .unwrap()
        .records
}

fn of(recs: &[Record], kind: EventKind) -> Vec<&Record> {
    recs.iter().filter(|r| r.kind == kind).collect()
}

fn audited(state: &Path, r: &RunReport, policy: &UserPolicy) -> harness_run::AuditReport {
    audit(Audit {
        state_root: state,
        run: &r.run,
        attempt: None,
        anchor: r.chain_head,
        spec: &spec(),
        registry: &registry(),
        policy,
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

const NOTHING_CHECKED: GateOutcome = GateOutcome::Indeterminate {
    why: IndeterminateKind::NothingChecked,
};

// The whole path: read, a unique replace, the same read again (a new key:
// the tree changed, so no repeat notice), submit. The file holds the edit;
// `EditApplied` carries the before and after digests and the tree digest a
// fresh walk measures, right before its `ToolFinished`; the anchored audit
// recomputes every record and the stop.
#[test]
fn h2b_a_run_reads_edits_rereads_and_submits_and_audits_clean() {
    let (state, ws) = scratch("e2e");
    let tree0 = tree_of(&ws);
    let r = go(
        &state,
        &ws,
        &allow_edits(),
        vec![
            read("src/lib.rs"),
            replace("src/lib.rs", "= 250;", "= 375;"),
            read("src/lib.rs"),
            submit(),
        ],
    );
    assert_eq!(r.cause, StopCause::Submitted);
    assert_eq!(r.outcome, NOTHING_CHECKED);
    let edited = LIB.replace("= 250;", "= 375;");
    assert_eq!(fs::read_to_string(ws.join("src/lib.rs")).unwrap(), edited);
    let recs = records(&r);
    assert_eq!(
        recs[0].body["workspace_tree"],
        Value::from(tree0.to_string())
    );
    let applied = of(&recs, EventKind::EditApplied);
    assert_eq!(applied.len(), 1);
    let e = &applied[0].body;
    assert_eq!(e["before"], Value::from(sha256(LIB.as_bytes()).to_string()));
    assert_eq!(
        e["after"],
        Value::from(sha256(edited.as_bytes()).to_string())
    );
    assert_eq!(e["workspace_tree"], Value::from(tree_of(&ws).to_string()));
    assert_eq!(e["path"]["untrusted"], Value::Bool(true));
    // EditApplied is immediately before its ToolFinished, same intent.
    let at = recs
        .iter()
        .position(|x| x.kind == EventKind::EditApplied)
        .unwrap();
    assert_eq!(recs[at + 1].kind, EventKind::ToolFinished);
    assert_eq!(recs[at + 1].body["intent_seq"], e["intent_seq"]);
    assert_eq!(recs[at + 1].body["status"], "ok");
    // The policy rule: the user allow, not a default.
    let decided: Vec<&Value> = of(&recs, EventKind::PolicyDecided)
        .iter()
        .map(|x| &x.body["rule"])
        .collect();
    assert_eq!(decided[1]["list"], "allow");
    assert!(of(&recs, EventKind::LoopDetected).is_empty());
    let a = audited(&state, &r, &allow_edits());
    assert_eq!(a.divergence, None, "{a:?}");
    assert!(a.stop_recomputed && a.anchored);
    assert_eq!(a.outcome, NOTHING_CHECKED);
}

// Replay re-feeds an edit's result and never applies it again: with the
// workspace put back as it was, the audit still matches every record, and
// the file stays as the test left it.
#[test]
fn h2b_an_audit_re_feeds_edits_and_never_re_applies_them() {
    let (state, ws) = scratch("replay-no-reapply");
    let r = go(
        &state,
        &ws,
        &allow_edits(),
        vec![
            read("src/lib.rs"),
            replace("src/lib.rs", "= 250;", "= 375;"),
            write("src/new.rs", "pub fn added() {}\n"),
            submit(),
        ],
    );
    assert_eq!(r.cause, StopCause::Submitted);
    fs::write(ws.join("src/lib.rs"), LIB).unwrap();
    fs::remove_file(ws.join("src/new.rs")).unwrap();
    let a = audited(&state, &r, &allow_edits());
    assert_eq!(a.divergence, None, "{a:?}");
    assert!(a.stop_recomputed);
    assert_eq!(fs::read_to_string(ws.join("src/lib.rs")).unwrap(), LIB);
    assert!(!ws.join("src/new.rs").exists(), "the audit created a file");
}

// §5.2 in this build: with no allow rule and no approver, an edit is
// denied (deny.no-approver) and never runs; the model is told why.
#[test]
fn h2b_without_an_allow_rule_or_an_approver_an_edit_is_denied() {
    let (state, ws) = scratch("no-approver");
    let r = go(
        &state,
        &ws,
        &UserPolicy::default(),
        vec![
            read("src/lib.rs"),
            replace("src/lib.rs", "= 250;", "= 375;"),
            submit(),
        ],
    );
    assert_eq!(r.cause, StopCause::Submitted);
    assert_eq!(fs::read_to_string(ws.join("src/lib.rs")).unwrap(), LIB);
    let recs = records(&r);
    let denied = &of(&recs, EventKind::PolicyDecided)[1].body;
    assert_eq!(denied["decision"], "deny");
    assert_eq!(denied["rule"], "deny.no-approver");
    assert_eq!(denied["reason"], "no_approver");
    assert!(of(&recs, EventKind::EditApplied).is_empty());
    let started: Vec<&str> = of(&recs, EventKind::ToolStarted)
        .iter()
        .map(|x| x.body["capability"].as_str().unwrap())
        .collect();
    assert_eq!(started, ["harness.fs.read", "harness.task.submit"]);
    let a = audited(&state, &r, &UserPolicy::default());
    assert_eq!(a.divergence, None, "{a:?}");
}

/// A scripted model that runs `hook` just before answering request `at`
/// (1-based): a stand-in for something else changing the workspace
/// between two steps.
struct Hooked<'a> {
    inner: ScriptedBackend,
    calls: Cell<usize>,
    at: usize,
    hook: Box<dyn Fn() + 'a>,
}

impl ModelBackend for Hooked<'_> {
    fn identity(&self) -> ModelIdentity {
        self.inner.identity()
    }
    fn complete(&self, req: &ModelRequest, deadline: Instant) -> Result<Completion, ModelError> {
        self.calls.set(self.calls.get() + 1);
        if self.calls.get() == self.at {
            (self.hook)();
        }
        self.inner.complete(req, deadline)
    }
}

// §2.3 stale reads through the loop: an edit to a file never read is
// refused, and so is one to a file that changed after it was read; after
// a re-read the same edit applies.
#[test]
fn h2b_a_stale_or_missing_read_refuses_the_edit_until_a_re_read() {
    let (state, ws) = scratch("stale");
    let lib = ws.join("src/lib.rs");
    let changed = LIB.replace("<< n", "<< (n + 1)");
    let backend = Hooked {
        inner: ScriptedBackend::new(
            Profile::conservative_default("m"),
            vec![
                replace("src/lib.rs", "= 250;", "= 375;"), // never read
                read("src/lib.rs"),
                replace("src/lib.rs", "= 250;", "= 375;"), // changed since
                read("src/lib.rs"),
                replace("src/lib.rs", "= 250;", "= 375;"), // fresh: applies
                submit(),
            ],
        ),
        calls: Cell::new(0),
        at: 3,
        hook: Box::new(|| fs::write(&lib, &changed).unwrap()),
    };
    let r = go_with(&state, &ws, &allow_edits(), &backend);
    assert_eq!(r.cause, StopCause::Submitted);
    let recs = records(&r);
    let finished: Vec<(String, Option<u64>)> = of(&recs, EventKind::ToolFinished)
        .iter()
        .map(|x| {
            (
                x.body["status"].as_str().unwrap().to_owned(),
                x.body.get("code").and_then(Value::as_u64),
            )
        })
        .collect();
    let stale = harness_tools::builtin::code::STALE_READ;
    assert_eq!(
        finished,
        [
            ("error".to_owned(), Some(u64::from(stale))),
            ("ok".to_owned(), None),
            ("error".to_owned(), Some(u64::from(stale))),
            ("ok".to_owned(), None),
            ("ok".to_owned(), None),
            ("ok".to_owned(), None),
        ]
    );
    assert_eq!(
        fs::read_to_string(&lib).unwrap(),
        changed.replace("= 250;", "= 375;")
    );
    assert_eq!(of(&recs, EventKind::EditApplied).len(), 1);
}

// A create has no `before`; the harness's own write is the file's latest
// read, so the model may rewrite what it created without reading it back.
#[test]
fn h2b_a_create_has_no_before_and_may_be_rewritten_without_a_re_read() {
    let (state, ws) = scratch("create");
    let r = go(
        &state,
        &ws,
        &allow_edits(),
        vec![
            write("src/new.rs", "pub fn one() {}\n"),
            write("src/new.rs", "pub fn two() {}\n"),
            submit(),
        ],
    );
    assert_eq!(r.cause, StopCause::Submitted);
    assert_eq!(
        fs::read_to_string(ws.join("src/new.rs")).unwrap(),
        "pub fn two() {}\n"
    );
    let recs = records(&r);
    let applied = of(&recs, EventKind::EditApplied);
    assert_eq!(applied.len(), 2);
    assert!(applied[0].body.get("before").is_none(), "a create");
    assert_eq!(
        applied[1].body["before"],
        Value::from(sha256(b"pub fn one() {}\n").to_string())
    );
    assert_eq!(
        applied[1].body["workspace_tree"],
        Value::from(tree_of(&ws).to_string())
    );
    let a = audited(&state, &r, &allow_edits());
    assert_eq!(a.divergence, None, "{a:?}");
}

// §2.6 with the H2 condition: the same read after each edit is a new key,
// so read/edit/read/edit/read never gets a repeat notice. Control: three
// identical reads with no edit in between do.
#[test]
fn h2b_re_reading_after_an_edit_is_not_a_repeat() {
    let (state, ws) = scratch("repeat");
    let r = go(
        &state,
        &ws,
        &allow_edits(),
        vec![
            read("src/lib.rs"),
            replace("src/lib.rs", "= 250;", "= 300;"),
            read("src/lib.rs"),
            replace("src/lib.rs", "= 300;", "= 375;"),
            read("src/lib.rs"),
            submit(),
        ],
    );
    assert_eq!(r.cause, StopCause::Submitted);
    assert!(of(&records(&r), EventKind::LoopDetected).is_empty());

    let (state, ws) = scratch("repeat-control");
    let r = go(
        &state,
        &ws,
        &allow_edits(),
        vec![
            read("src/lib.rs"),
            read("src/lib.rs"),
            read("src/lib.rs"),
            submit(),
        ],
    );
    let recs = records(&r);
    let loops = of(&recs, EventKind::LoopDetected);
    assert_eq!(loops.len(), 1);
    assert_eq!(loops[0].body["kind"], "repeat");
}

// §2.6 edit churn: the ninth successful edit to one file stops the run
// with Loop(EditChurn), after its result is durable; the audit recomputes
// the stop. (Each edit differs: a ping-pong between two edits is caught
// earlier, as a repeat, since each is proposed again on the same tree.)
#[test]
fn h2b_edit_churn_stops_the_run_after_eight_edits_to_one_file() {
    let (state, ws) = scratch("churn");
    let mut replies = vec![read("src/lib.rs")];
    for i in 0..9 {
        replies.push(replace(
            "src/lib.rs",
            &format!("= {};", 250 + i),
            &format!("= {};", 251 + i),
        ));
    }
    replies.push(submit());
    let r = go(&state, &ws, &allow_edits(), replies);
    assert_eq!(r.cause, StopCause::Loop(LoopKind::EditChurn));
    let recs = records(&r);
    assert_eq!(of(&recs, EventKind::EditApplied).len(), 9);
    let last = recs.iter().rev().nth(1).unwrap();
    assert_eq!(last.kind, EventKind::LoopDetected);
    assert_eq!(last.body["kind"], "edit_churn");
    let a = audited(&state, &r, &allow_edits());
    assert_eq!(a.divergence, None, "{a:?}");
    assert!(a.stop_recomputed);
}

// A ping-pong between two edits is a repeat: each edit is proposed again
// on the same tree digest, so the tree-keyed repeat detector still sees it.
#[test]
fn h2b_a_ping_pong_between_two_edits_is_a_repeat() {
    let (state, ws) = scratch("ping-pong");
    let mut replies = vec![read("src/lib.rs")];
    for i in 0..9 {
        let (a, b) = if i % 2 == 0 {
            ("250", "251")
        } else {
            ("251", "250")
        };
        replies.push(replace(
            "src/lib.rs",
            &format!("= {a};"),
            &format!("= {b};"),
        ));
    }
    replies.push(submit());
    let r = go(&state, &ws, &allow_edits(), replies);
    assert_eq!(r.cause, StopCause::Loop(LoopKind::Repeat));
}

// The lexical workspace rule holds for edits before any allow rule: an
// allowed edit that leaves the workspace is denied and nothing is written.
#[test]
fn h2b_an_edit_that_leaves_the_workspace_is_denied_even_when_allowed() {
    let (state, ws) = scratch("outside");
    let outside = ws.parent().unwrap().join("victim.txt");
    fs::write(&outside, "victim\n").unwrap();
    let r = go(
        &state,
        &ws,
        &allow_edits(),
        vec![
            write("../victim.txt", "pwned\n"),
            replace("/etc/hosts", "localhost", "pwned"),
            submit(),
        ],
    );
    assert_eq!(r.cause, StopCause::Submitted);
    assert_eq!(fs::read_to_string(&outside).unwrap(), "victim\n");
    let recs = records(&r);
    let rules: Vec<&str> = of(&recs, EventKind::PolicyDecided)
        .iter()
        .map(|x| x.body["rule"].as_str().unwrap_or("user"))
        .collect();
    assert_eq!(
        rules[..2],
        ["deny.path-outside-workspace", "deny.path-outside-workspace"]
    );
    assert!(of(&recs, EventKind::EditApplied).is_empty());
}

// ---- resume after a kill (§2.10, the H1e-2b row's H2 condition) ----------------------

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

/// Cut attempt 1's journal inside `step`, before its first `kind` record
/// (a kill mid-step).
fn crash_in(r: &RunReport, step: u64, kind: &str) {
    let path = layout::attempt_dir(&r.run_dir, 1).join(layout::JOURNAL_FILE);
    let text = fs::read_to_string(&path).unwrap();
    let mut out = String::new();
    for line in text.lines() {
        let v: Value = serde_json::from_str(line).unwrap();
        let s = v["step"].as_u64().unwrap();
        if s > step || (s == step && v["kind"] == kind) || v["kind"] == "RunStopped" {
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    fs::write(path, out).unwrap();
}

fn resume_edits(
    state: &Path,
    ws: &Path,
    run: &harness_core::RunId,
    replies: Vec<Result<Completion, ModelError>>,
) -> Result<RunReport, harness_run::RunRefused> {
    let backend = ScriptedBackend::new(Profile::conservative_default("m"), replies);
    harness_run::resume(harness_run::Resume {
        state_root: state,
        run,
        workspace: ws,
        spec: &spec(),
        registry: &registry(),
        policy: &allow_edits(),
        profile: &Profile::conservative_default("m"),
        backend: &backend,
        probe: &Local,
        env: &FIXED_ENV,
        config: &RunConfig::defaults(1_000_000),
        approver: None,
        confinement: None,
    })
}

/// An edit that still matches after it is applied, so applying it twice
/// shows: `= 250;` stays in the file.
fn tag() -> Result<Completion, ModelError> {
    replace("src/lib.rs", "= 250;", "= 250; // tagged")
}

fn tags(ws: &Path) -> usize {
    fs::read_to_string(ws.join("src/lib.rs"))
        .unwrap()
        .matches("// tagged")
        .count()
}

// Kill after an edit, then resume: the edit's step is complete (its result
// is durable), so the catch-up re-feeds it and never applies it again; the
// live part starts at the next step; the resumed attempt audits clean.
#[test]
fn h2b_a_kill_after_an_edit_then_a_resume_never_applies_it_again() {
    let (state, ws) = scratch("kill-after-edit");
    let r = go(
        &state,
        &ws,
        &allow_edits(),
        vec![read("src/lib.rs"), tag(), read("src/lib.rs"), submit()],
    );
    assert_eq!(tags(&ws), 1);
    crash_after(&r, 1, 3);
    // One live reply: the step after the edit. Were step 2 run again, it
    // would take this submit, or apply the edit a second time.
    let res = resume_edits(&state, &ws, &r.run, vec![submit()]).unwrap();
    assert_eq!(res.cause, StopCause::Submitted);
    assert_eq!(res.steps, 3, "steps 1-2 re-fed, step 3 live");
    assert_eq!(tags(&ws), 1, "the edit was not applied again");
    let old = records(&r);
    let new = JournalReader::open(&layout::attempt_dir(&res.run_dir, 2))
        .unwrap()
        .records;
    let applied = |v: &[Record]| -> Vec<Value> {
        of(v, EventKind::EditApplied)
            .iter()
            .map(|x| Value::Object(x.body.clone()))
            .collect()
    };
    assert_eq!(applied(&new), applied(&old), "re-fed, record for record");
    // The resumed header carries the run's start facts (block 4 is the
    // run's), not the edited workspace's.
    assert_eq!(new[0].body["workspace_tree"], old[0].body["workspace_tree"]);
    let a = audit(Audit {
        state_root: &state,
        run: &r.run,
        attempt: Some(2),
        anchor: res.chain_head,
        spec: &spec(),
        registry: &registry(),
        policy: &allow_edits(),
        profile: &Profile::conservative_default("m"),
        limits: &RunConfig::defaults(1_000_000).limits,
    })
    .unwrap();
    assert_eq!(a.divergence, None, "{a:?}");
    assert!(a.stop_recomputed);
}

// Kill inside the edit's step, after the edit but before its result was
// durable: the workspace no longer matches the journal's last durable
// state, and there is no snapshot to restore, so the resume is refused and
// writes nothing. The cut attempt still audits: its trailing EditApplied
// is re-fed as the edit it records.
#[test]
fn h2b_a_kill_between_an_edit_and_its_result_refuses_the_resume() {
    for cut_before in ["ToolFinished", "EditApplied"] {
        let (state, ws) = scratch(&format!("kill-mid-edit-{cut_before}"));
        let r = go(
            &state,
            &ws,
            &allow_edits(),
            vec![read("src/lib.rs"), tag(), submit()],
        );
        crash_in(&r, 2, cut_before);
        let e = resume_edits(&state, &ws, &r.run, vec![tag(), submit()]).unwrap_err();
        assert!(
            matches!(e, harness_run::RunRefused::NotResumable(w) if w.contains("workspace differs")),
            "{cut_before}: {e:?}"
        );
        assert!(!layout::attempt_dir(&r.run_dir, 2).exists(), "{cut_before}");
        assert_eq!(tags(&ws), 1, "{cut_before}");
        // (No anchor: the cut journal's head is not the committed one.)
        let a = audit(Audit {
            state_root: &state,
            run: &r.run,
            attempt: None,
            anchor: None,
            spec: &spec(),
            registry: &registry(),
            policy: &allow_edits(),
            profile: &Profile::conservative_default("m"),
            limits: &RunConfig::defaults(1_000_000).limits,
        })
        .unwrap();
        assert_eq!(a.divergence, None, "{cut_before}: {a:?}");
        assert_eq!(
            a.outcome,
            GateOutcome::Indeterminate {
                why: IndeterminateKind::CouldNotRun
            },
            "{cut_before}: never committed"
        );
    }
}

// The same cut when the edit never reached the file (the kill came before
// the rename): the workspace matches the journal, so the cut step is
// decided again live, and its edit applies exactly once.
#[test]
fn h2b_a_trailing_edit_intent_that_never_applied_is_decided_again_live() {
    let (state, ws) = scratch("intent-only");
    let r = go(
        &state,
        &ws,
        &allow_edits(),
        vec![read("src/lib.rs"), tag(), submit()],
    );
    crash_in(&r, 2, "EditApplied");
    fs::write(ws.join("src/lib.rs"), LIB).unwrap(); // the rename never happened
    let res = resume_edits(&state, &ws, &r.run, vec![tag(), submit()]).unwrap();
    assert_eq!(res.cause, StopCause::Submitted);
    assert_eq!(res.steps, 3, "step 1 re-fed, steps 2 and 3 live");
    assert_eq!(tags(&ws), 1);
}

// Kill, resume, edit, kill, resume: the second resume expects the tree the
// resumed attempt's own last edit recorded.
#[test]
fn h2b_chained_resumes_follow_each_attempts_last_edit() {
    let (state, ws) = scratch("chained");
    let r = go(
        &state,
        &ws,
        &allow_edits(),
        vec![read("src/lib.rs"), tag(), submit()],
    );
    crash_after(&r, 1, 3);
    let second = resume_edits(
        &state,
        &ws,
        &r.run,
        vec![
            replace("src/lib.rs", "// tagged", "// tagged again"),
            submit(),
        ],
    )
    .unwrap();
    assert_eq!(second.attempt, 2);
    assert_eq!(second.steps, 4);
    crash_after(&second, 2, 4); // attempt 2's step 3 edit is complete
    let third = resume_edits(&state, &ws, &r.run, vec![submit()]).unwrap();
    assert_eq!(third.attempt, 3);
    assert_eq!(third.cause, StopCause::Submitted);
    assert_eq!(third.steps, 4, "steps 1-3 re-fed, step 4 live");
    let text = fs::read_to_string(ws.join("src/lib.rs")).unwrap();
    assert_eq!(text.matches("// tagged again").count(), 1, "{text}");
}

// ---- the dev-suite judge's findings (b) and (c) ---------------------------------------

/// A scripted model that keeps what each request showed it.
struct Capture {
    inner: ScriptedBackend,
    bodies: std::cell::RefCell<Vec<String>>,
}

impl ModelBackend for Capture {
    fn identity(&self) -> ModelIdentity {
        self.inner.identity()
    }
    fn complete(&self, req: &ModelRequest, deadline: Instant) -> Result<Completion, ModelError> {
        if let Ok(v) = harness_model::wire::render_request(req, &Profile::conservative_default("m"))
        {
            self.bodies.borrow_mut().push(v.to_string());
        }
        self.inner.complete(req, deadline)
    }
}

fn capture(replies: Vec<Result<Completion, ModelError>>) -> Capture {
    Capture {
        inner: ScriptedBackend::new(Profile::conservative_default("m"), replies),
        bodies: std::cell::RefCell::new(Vec::new()),
    }
}

const REPEATED: &str =
    "Notice: this call repeats an earlier one exactly, on an unchanged workspace";

// (b): an exact repeat of a read on an unchanged workspace, with the same
// output, is said so after its result; after an edit the same read is a
// new call and gets no notice. The loop detector's rules are unchanged.
#[test]
fn judge_b_an_exact_repeat_of_a_read_is_noticed_until_the_workspace_changes() {
    let (state, ws) = scratch("judge-b");
    let backend = capture(vec![
        read("src/lib.rs"),
        read("README.md"),
        read("src/lib.rs"), // an exact repeat, the tree unchanged: noticed
        replace("src/lib.rs", "= 250;", "= 375;"),
        read("src/lib.rs"), // the tree changed: a new call
        submit(),
    ]);
    let r = go_with(&state, &ws, &allow_edits(), &backend);
    assert_eq!(r.cause, StopCause::Submitted);
    let bodies = backend.bodies.borrow();
    let noticed: Vec<bool> = bodies.iter().map(|b| b.contains(REPEATED)).collect();
    // Request k shows the results of steps 1..k-1.
    assert_eq!(noticed, [false, false, false, true, true, true]);
    assert_eq!(
        bodies[5].matches(REPEATED).count(),
        1,
        "only step 3's read was a repeat"
    );
    assert!(of(&records(&r), EventKind::LoopDetected).is_empty());
    assert_eq!(audited(&state, &r, &allow_edits()).divergence, None);
}

// (c): a read with `lines` over its schema's maximum is denied, and the
// denial names the argument and its bounds as the schema gives them.
#[test]
fn judge_c_an_out_of_range_argument_is_denied_with_its_bounds() {
    let (state, ws) = scratch("judge-c");
    let backend = capture(vec![
        action(
            "harness.fs.read",
            &serde_json::json!({"path": "src/lib.rs", "lines": 101}),
        ),
        submit(),
    ]);
    let r = go_with(&state, &ws, &allow_edits(), &backend);
    assert_eq!(r.cause, StopCause::Submitted);
    let recs = records(&r);
    assert_eq!(
        of(&recs, EventKind::PolicyDecided)[0].body["rule"],
        "deny.args-schema"
    );
    assert!(
        backend.bodies.borrow()[1].contains("the argument lines must be an integer from 1 to 100"),
        "{}",
        backend.bodies.borrow()[1]
    );
    assert_eq!(audited(&state, &r, &allow_edits()).divergence, None);
}

// ---- forged edit records --------------------------------------------------------------

/// Rewrite attempt 1's journal with `keep` deciding which records stay and
/// `edit` changing bodies, and re-chain it: a forger who recomputes every
/// hash. Only the replay (or an anchor) can catch this.
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

fn audit_unanchored(state: &Path, r: &RunReport) -> harness_run::AuditReport {
    audit(Audit {
        state_root: state,
        run: &r.run,
        attempt: Some(1),
        anchor: None,
        spec: &spec(),
        registry: &registry(),
        policy: &allow_edits(),
        profile: &Profile::conservative_default("m"),
        limits: &RunConfig::defaults(1_000_000).limits,
    })
    .unwrap()
}

// An ok edit's result always follows its EditApplied: a journal with the
// EditApplied cut out (the intent seqs repointed, re-chained), or with one
// added to a read's result, is a shape the loop never writes, and the
// audit says so instead of re-feeding it.
#[test]
fn a_journal_missing_or_adding_an_edit_record_is_unreadable() {
    let (state, ws) = scratch("forge-edit-record");
    let r = go(
        &state,
        &ws,
        &allow_edits(),
        vec![
            read("src/lib.rs"),
            replace("src/lib.rs", "= 250;", "= 375;"),
            submit(),
        ],
    );
    let pristine = fs::read(layout::attempt_dir(&r.run_dir, 1).join(layout::JOURNAL_FILE)).unwrap();
    let applied_seq = of(&records(&r), EventKind::EditApplied)[0].seq;
    // Cut it out; every later intent_seq shifts down by one.
    forge(
        &r,
        |v| v["seq"].as_u64() != Some(applied_seq),
        |v| {
            if let Some(n) = v["body"]["intent_seq"].as_u64() {
                if n > applied_seq {
                    v["body"]["intent_seq"] = Value::from(n - 1);
                }
            }
        },
    );
    let a = audit_unanchored(&state, &r);
    assert_eq!(
        a.divergence.map(|d| d.why),
        Some("a record is not the shape the loop writes"),
        "a missing EditApplied"
    );
    // Relabel it as belonging to the read's intent instead.
    fs::write(
        layout::attempt_dir(&r.run_dir, 1).join(layout::JOURNAL_FILE),
        &pristine,
    )
    .unwrap();
    let read_intent = of(&records(&r), EventKind::ToolStarted)[0].seq;
    forge(
        &r,
        |_| true,
        |v| {
            if v["seq"].as_u64() == Some(applied_seq) {
                v["body"]["intent_seq"] = Value::from(read_intent);
            }
        },
    );
    let a = audit_unanchored(&state, &r);
    assert_eq!(
        a.divergence.map(|d| d.why),
        Some("a record is not the shape the loop writes"),
        "an EditApplied on a read"
    );
}
