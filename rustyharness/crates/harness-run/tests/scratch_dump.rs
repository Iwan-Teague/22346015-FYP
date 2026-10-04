//! Scratch debug (delete before commit).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use harness_core::environment::{EnvSample, Unmeasured};
use harness_journal::layout;
use harness_journal::JournalReader;
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, SemVer, ValidationContext};
use harness_model::profile::Profile;
use harness_model::scripted::{text_reply, ScriptedBackend};
use harness_model::{Completion, ModelError, TaskText};
use harness_policy::UserPolicy;
use harness_run::child_task_text;
use harness_run::{
    audit, run, Audit, ChildAudit, Run, RunConfig, RunReport, SessionKind, TaskSpec,
};
use serde_json::Value;

const FIXED_ENV: EnvSample = EnvSample::unmeasured(Unmeasured::NoSafeApi);

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

fn spec() -> TaskSpec {
    let s = TaskSpec {
        task: TaskText::new("the parent task".into()),
        grants: vec!["harness.fs.read".to_owned()],
        workspace_public: false,
        ports: Vec::new(),
        lan_ports: Vec::new(),
        exec: None,
        presubmit: None,
        post_edit: None,
        protected: Vec::new(),
        kind: SessionKind::Coding,
    };
    delegating(s)
}

fn delegating(mut s: TaskSpec) -> TaskSpec {
    let mut g = s.grants.clone();
    g.push("harness.task.delegate".to_owned());
    g.sort();
    s.grants = g;
    s
}

fn act(tool: &str, args: &str) -> Result<Completion, ModelError> {
    Ok(text_reply(&format!(
        "thinking <action>{{\"tool\":\"{tool}\",\"args\":{args}}}</action>"
    )))
}

fn note(note: &str) -> Result<Completion, ModelError> {
    act(
        "harness.task.submit",
        &serde_json::json!({ "note": note }).to_string(),
    )
}

#[test]
fn scratch_child_audit() {
    let root = std::env::temp_dir().join(format!("scratch-p38h-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("ws")).unwrap();
    std::fs::create_dir_all(root.join("state")).unwrap();
    std::fs::write(root.join("ws/a.txt"), "hello\n").unwrap();
    let profile = Profile::conservative_default("m");
    let backend = ScriptedBackend::new(
        profile.clone(),
        vec![
            act("harness.task.delegate", r#"{"task":"what is in a.txt?"}"#),
            act("harness.fs.read", r#"{"path":"a.txt"}"#),
            note("it says hello"),
            note("the parent is done"),
        ],
    );
    let reg = registry();
    let sp = spec();
    let policy = UserPolicy::default();
    let config = RunConfig::defaults(1_000_000);
    let report = run(Run {
        state_root: &root.join("state"),
        workspace: &root.join("ws"),
        spec: &sp,
        registry: &reg,
        policy: &policy,
        profile: &profile,
        backend: &backend,
        probe: &harness_testkit::Local,
        env: &FIXED_ENV,
        config: &config,
        approver: None,
        confinement: None,
    })
    .unwrap();
    let RunReport { run_dir, .. } = &report;
    let v = JournalReader::open(&layout::attempt_dir(run_dir, report.attempt)).unwrap();
    let cr = v
        .records
        .iter()
        .find(|r| r.kind == harness_journal::EventKind::ChildRun)
        .unwrap();
    println!("ChildRun body={}", serde_json::to_string(&cr.body).unwrap());
    let child_id = cr.body["child"].as_str().unwrap();
    let brief = cr.body["brief"].as_str().unwrap();
    println!("child={child_id} brief_digest={brief}");
    // Child header.
    let child_dir = root.join("state").join("runs").join(child_id);
    let cv = JournalReader::open(&child_dir.join("attempt-1")).unwrap();
    let head = &cv.records[0];
    println!(
        "child header={}",
        serde_json::to_string(&head.body).unwrap()
    );
    // Replica of the child audit (audit.rs:1083): spec from the header.
    let grants: Vec<String> = head.body["grants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g.as_str().unwrap().to_owned())
        .collect();
    let inline = head.body["child_brief"]["inline"].as_str().unwrap();
    let nonce = head.body["child"]["brief_nonce"].as_str().unwrap();
    let n = harness_core::Nonce::new(nonce).unwrap();
    let child_spec = TaskSpec {
        task: child_task_text(inline, &n),
        grants,
        workspace_public: false,
        ports: Vec::new(),
        lan_ports: Vec::new(),
        exec: None,
        presubmit: None,
        post_edit: None,
        protected: Vec::new(),
        kind: SessionKind::Coding,
    };
    let child_limits = harness_core::MeterLimits {
        steps: 15,
        tokens: 200_000,
        wall: std::time::Duration::from_millis(600_000),
        cost_micros: 0,
        format_errors: 3,
        repair_rounds: 0,
    };
    let a = audit(Audit {
        state_root: &root.join("state"),
        run: &harness_core::RunId::parse(child_id).unwrap(),
        attempt: Some(1),
        anchor: None,
        spec: &child_spec,
        registry: &reg,
        policy: &policy,
        profile: &profile,
        limits: &child_limits,
        children: ChildAudit::Skip,
    });
    match a {
        Ok(r) => println!(
            "CHILD AUDIT ok divergence={:?} matched={} outcome={:?}",
            r.divergence, r.matched, r.outcome
        ),
        Err(e) => println!("CHILD AUDIT REFUSED: {e:?}"),
    }
    let parent_audit = audit(Audit {
        state_root: &root.join("state"),
        run: &report.run,
        attempt: Some(1),
        anchor: None,
        spec: &sp,
        registry: &reg,
        policy: &policy,
        profile: &profile,
        limits: &config.limits,
        children: ChildAudit::Verify,
    });
    match parent_audit {
        Ok(r) => {
            println!(
                "PARENT AUDIT ok divergence={:?} matched={} outcome={:?}",
                r.divergence, r.matched, r.outcome
            );
            for c in &r.children {
                println!(
                    "  child {} anchored={} divergence={:?} outcome={:?}",
                    c.run, c.anchored, c.divergence, c.outcome
                );
            }
        }
        Err(e) => println!("PARENT AUDIT REFUSED: {e:?}"),
    }
    let _ = (brief, head.body.get("workspace_files"));
    let _v: Value = serde_json::json!(null);
}
