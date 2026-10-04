//! P-31: a hosted profile's run — the planning refusals (no price table,
//! no personal-sensitivity grants), the `Cost` budget, and the hosted
//! declaration recorded in the header and recomputed by the audit.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use harness_core::environment::{EnvSample, Unmeasured};
use harness_core::{BudgetDim, StopCause};
use harness_journal::{EventKind, JournalReader, Record};
use harness_manifest::admission::Registry;
use harness_model::profile::Profile;
use harness_model::scripted::ScriptedBackend;
use harness_model::{Completion, ServerUsage};
use harness_policy::UserPolicy;
use harness_run::{audit, run, Audit, Run, RunConfig, RunRefused, RunReport, TaskSpec};
use harness_testkit::{act, submit, Fixture, Local};

/// A fixed environment sample (the real probe is harness-sandbox's; these
/// tests only need the header and records to carry one).
const FIXED_ENV: EnvSample = EnvSample::unmeasured(Unmeasured::NoSafeApi);

/// A hosted profile (P-31): `upstream: "hosted"`, plus a price table (3
/// micro-USD per input kilo-token, 15 per output) unless `priced` is false.
fn hosted_profile(priced: bool) -> Profile {
    let mut o: serde_json::Map<String, serde_json::Value> = serde_json::from_str(
        r#"{"profile_version":1,"id":"hosted-m","model":"m","context_window":8192,
            "fill_ratio":0.6,"protocol":"text","tool_choice_required_ok":false,
            "grammar":"none","max_active_tools":5,"edit_format":"replace","recent_turns":4,
            "sampling":{"temperature":0.2,"top_p":0.95,"max_tokens":1024},
            "upstream":"hosted"}"#,
    )
    .unwrap();
    if priced {
        o.insert(
            "price_table".into(),
            serde_json::json!({"in_micro_per_ktok": 3000, "out_micro_per_ktok": 15000}),
        );
    }
    Profile::parse(serde_json::Value::Object(o).to_string().as_bytes()).unwrap()
}

/// The built-in registry admitted alone; the records of a run's first
/// attempt.
fn records(r: &RunReport) -> Vec<Record> {
    JournalReader::open(&r.run_dir.join("attempt-1"))
        .unwrap()
        .records
}

/// `run` with a given profile and a cost limit (0 = no budget in use, the
/// defaults).
fn drive(
    fx: &Fixture,
    spec: &TaskSpec,
    registry: &Registry,
    profile: &Profile,
    replies: Vec<Completion>,
    cost_micros: u64,
) -> Result<RunReport, RunRefused> {
    let backend = ScriptedBackend::new(profile.clone(), replies.into_iter().map(Ok).collect());
    let mut cfg = RunConfig::defaults(1_000_000);
    cfg.limits.cost_micros = cost_micros;
    run(Run {
        state_root: fx.state_root(),
        workspace: fx.workspace(),
        spec,
        registry,
        policy: &UserPolicy::default(),
        profile,
        backend: &backend,
        probe: &Local,
        env: &FIXED_ENV,
        config: &cfg,
        approver: None,
        confinement: None,
    })
}

// §2.4: a hosted run without a price table refuses to start.
#[test]
fn hosted_profile_without_price_table_refuses() {
    let fx = Fixture::new("p31-no-table").unwrap();
    fx.write("a.txt", "hello").unwrap();
    let reg = harness_testkit::registry().unwrap();
    let spec = harness_testkit::read_spec("What is in a.txt?");
    let err = drive(&fx, &spec, &reg, &hosted_profile(false), Vec::new(), 0).unwrap_err();
    assert!(
        matches!(err, RunRefused::Hosted(m) if m.contains("price table")),
        "{err}"
    );
    // Control: the priced hosted profile starts (it runs below).
}

// §2.4: cost is derived from usage × the profile's price table and latches
// `Budget(Cost)` like any renewable dimension; the exchange that crossed
// the limit runs nothing.
#[test]
fn cost_budget_stops_run() {
    let fx = Fixture::new("p31-cost-stop").unwrap();
    fx.write("a.txt", "hello").unwrap();
    let reg = harness_testkit::registry().unwrap();
    let spec = harness_testkit::read_spec("What is in a.txt?");
    // 1000 in × 3 + 100 out × 15 = 4_500 micros, past the 4_000 limit.
    let mut first = act("harness.fs.read", "{\"path\":\"a.txt\"}");
    first.usage = Some(ServerUsage {
        input: 1000,
        output: 100,
    });
    let r = drive(
        &fx,
        &spec,
        &reg,
        &hosted_profile(true),
        vec![first, submit()],
        4_000,
    )
    .unwrap();
    assert_eq!(r.cause, StopCause::Budget(BudgetDim::Cost));
    assert!(
        !records(&r).iter().any(|x| x.kind == EventKind::ToolStarted),
        "the exchange that crossed the limit runs nothing"
    );
}

// Q-3: the hosted declaration is a header input — recorded, and recomputed
// by the audit (an audit given the same profile is clean; one given a
// local profile diverges at the header).
#[test]
fn hosted_declared_header_recorded_and_audited() {
    let fx = Fixture::new("p31-audited").unwrap();
    fx.write("a.txt", "hello").unwrap();
    let reg = harness_testkit::registry().unwrap();
    let spec = harness_testkit::read_spec("What is in a.txt?");
    let profile = hosted_profile(true);
    let backend = ScriptedBackend::new(
        profile.clone(),
        vec![
            Ok(act("harness.fs.read", "{\"path\":\"a.txt\"}")),
            Ok(submit()),
        ],
    );
    // A cost budget well above what this run spends (a real one is the
    // user's call; the default, 0, is "no budget in use" for a local model
    // and an immediate stop for a priced hosted one). The audit gets the
    // same limits: they are a header input (review F-1).
    let mut cfg = RunConfig::defaults(1_000_000);
    cfg.limits.cost_micros = 1_000_000_000;
    let r = run(Run {
        state_root: fx.state_root(),
        workspace: fx.workspace(),
        spec: &spec,
        registry: &reg,
        policy: &UserPolicy::default(),
        profile: &profile,
        backend: &backend,
        probe: &Local,
        env: &FIXED_ENV,
        config: &cfg,
        approver: None,
        confinement: None,
    })
    .unwrap();
    assert_eq!(r.cause, StopCause::Submitted);
    assert_eq!(
        records(&r)[0]
            .body
            .get("endpoint_class")
            .and_then(|v| v.as_str()),
        Some("loopback-proxy-hosted")
    );
    let a = audit(Audit {
        state_root: fx.state_root(),
        run: &r.run,
        attempt: None,
        anchor: r.chain_head,
        spec: &spec,
        registry: &reg,
        policy: &UserPolicy::default(),
        profile: &profile,
        limits: &cfg.limits,
    })
    .unwrap();
    assert!(a.divergence.is_none(), "{:?}", a.divergence);
    assert!(a.stop_recomputed);
    assert!(a.anchored);
    // The same journal, audited with the local profile whose digest the
    // header does not carry, diverges rather than replays.
    let local = Profile::conservative_default("m");
    let a = audit(Audit {
        profile: &local,
        ..Audit {
            state_root: fx.state_root(),
            run: &r.run,
            attempt: None,
            anchor: r.chain_head,
            spec: &spec,
            registry: &reg,
            policy: &UserPolicy::default(),
            profile: &profile,
            limits: &cfg.limits,
        }
    })
    .unwrap();
    assert!(
        a.divergence.is_some(),
        "a different profile is a divergence"
    );
}
