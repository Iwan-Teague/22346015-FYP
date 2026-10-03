//! The MCP provider through the real seam (P-37h, macOS): the sandbox
//! witness is the real one, policy authorises the call, the journal makes
//! the intent durable, then `McpProvider` relists, compares against the
//! connect-time baseline and only then calls. The server is this crate's
//! fixture on the in-memory connector, so every wire assertion reads the
//! frames the client actually sent.
//!
//! Quarantine semantics (§7.2): the provider refuses with `Quarantined`;
//! the session-level quarantine and the `McpDrift` journal record are the
//! driver's job (P-37i).

#![cfg(target_os = "macos")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use harness_core::{sha256, RunId, Source};
use harness_journal::testing::{FaultFile, FaultPlan, MemBlobs};
use harness_journal::{Clock, Event, EventKind, Header, Ident, JournalWriter};
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::pins::{description_digest, schema_digest};
use harness_manifest::{Manifest, ProviderName, SemVer, Sha256Pin, ValidationContext};
use harness_mcp::provider::{McpConfig, McpProvider};
use harness_mcp::render::MCP_RESULT_DEFAULT;
use harness_mcp::wire;
use harness_mcp_fixture::connector::InMemoryConnector;
use harness_mcp_fixture::tools::ok_tools;
use harness_mcp_fixture::PROTOCOL_VERSION;
use harness_policy::{Call, Session, SessionKind, SessionSpec, UserPolicy, WorkspaceDecl};
use harness_sandbox::{Confinement, Conformed, SystemConfinement};
use harness_tools::{InvokeCtx, McpRecord, ReadLog, ToolProvider, ToolResult, ToolStatus};
use serde_json::{json, Map, Value};

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

type W = JournalWriter<FaultFile, MemBlobs, Tick>;

/// Any 64-hex pin: the tier pins the manifest bytes, not a known value.
const MANIFEST_PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn witness() -> Conformed {
    static W: OnceLock<Conformed> = OnceLock::new();
    W.get_or_init(|| {
        SystemConfinement
            .require()
            .expect("require() passes on macOS")
    })
    .clone()
}

/// The fixture manifest rebuilt from the very tools the fixture serves, so
/// the pins match what the baseline list will present.
fn manifest_json() -> Value {
    let caps: Vec<Value> = ok_tools()
        .iter()
        .map(|t| {
            json!({
                "id": format!("fixture.{}", t.name),
                "mcp_name": t.name,
                "summary": t.description,
                "effect": "read",
                "sensitivity": "public",
                "blast_radius": "own",
                "egress": "none",
                "content": "own",
                "confirmation": "none",
                "input_schema": t.input_schema,
                "schema_sha256": schema_digest(&t.input_schema).to_string(),
                "description_sha256": description_digest(t.description).to_string(),
            })
        })
        .collect();
    json!({
        "schema_version": 1,
        "provider": "fixture",
        "provider_version": "1.2.3",
        "min_harness": "0.0.1",
        "transport": {"kind": "mcp-stdio", "argv": ["/opt/fixture/bin/server"], "env_allow": ["FIXTURE_HOME"]},
        "mcp_protocols": [PROTOCOL_VERSION],
        "capabilities": caps,
    })
}

fn std_cfg() -> McpConfig {
    McpConfig {
        protocol: PROTOCOL_VERSION.into(),
        client_version: "0.0.1".into(),
        init: Duration::from_secs(5),
        page: Duration::from_secs(2),
        list: Duration::from_secs(5),
        call: Duration::from_secs(5),
        result_cap: MCP_RESULT_DEFAULT,
    }
}

/// Short budgets for the hang mode: the test must not wait out the
/// production budgets to prove a timeout.
fn hang_cfg() -> McpConfig {
    McpConfig {
        init: Duration::from_secs(2),
        page: Duration::from_millis(500),
        list: Duration::from_secs(1),
        call: Duration::from_millis(300),
        ..std_cfg()
    }
}

struct Rig {
    w: W,
    #[allow(dead_code)] // keeps the session's policy state alive
    s: Session,
    probe: InMemoryConnector,
    p: McpProvider<InMemoryConnector>,
    step: u64,
}

impl Rig {
    /// A connected provider over `mode`, admitted for `admitted`
    /// (capability id -> server tool name).
    fn new(mode: &str, cfg: McpConfig, admitted: &[(&str, &str)]) -> Rig {
        let ctx = ValidationContext::new(
            SemVer {
                major: 0,
                minor: 0,
                patch: 1,
            },
            &[],
        )
        .unwrap();
        let m = Manifest::parse(manifest_json().to_string().as_bytes(), &ctx)
            .expect("the fixture manifest parses");
        let reg = Registry::admit(vec![(
            m,
            Tier::Pinned {
                manifest_sha256: Sha256Pin::parse_hex(MANIFEST_PIN).unwrap(),
            },
        )])
        .expect("the pinned manifest admits");
        let s = Session::plan(
            &SessionSpec {
                // The session grants BOTH fixture capabilities: the
                // provider's admission map is the narrower gate under test.
                grants: vec!["fixture.echo".into(), "fixture.add".into()],
                workspace: Some(WorkspaceDecl::default()),
                approver_present: false,
                personal_data_granted: false,
                conformed: true,
                exec_programs: Vec::new(),
                lan_ports: Vec::new(),
                read_window: None,
                kind: SessionKind::Coding,
                mode: harness_policy::SessionMode::Build,
            },
            &reg,
            &UserPolicy::new(&[], &[], &["fixture.*"]).unwrap(),
        )
        .expect("the fixture grants plan");
        let w = JournalWriter::start(
            FaultFile::new(FaultPlan::default()),
            MemBlobs::default(),
            Tick(Cell::new(0)),
            RunId::new(1, [0; 10]),
            1,
            Header::new(Ident::of("0.0.1").unwrap()),
        )
        .unwrap();
        let connector = InMemoryConnector::new(mode);
        let probe = connector.clone();
        let map: std::collections::BTreeMap<String, String> = admitted
            .iter()
            .map(|(id, name)| ((*id).to_owned(), (*name).to_owned()))
            .collect();
        let mut p = McpProvider::new(connector, cfg, ProviderName::new("fixture").unwrap(), map);
        p.connect(&witness()).expect("the fixture connects");
        Rig {
            w,
            s,
            probe,
            p,
            step: 0,
        }
    }

    /// Policy -> journal -> provider, the production order.
    fn call(&mut self, cap: &str, args: Value) -> ToolResult {
        self.step += 1;
        let a = self
            .s
            .authorize(Call {
                capability: cap.into(),
                args,
            })
            .expect("policy allows it");
        let j = self
            .w
            .append_intent(self.step, Event::new(EventKind::ToolStarted), a)
            .unwrap();
        self.p
            .invoke(
                j,
                &InvokeCtx {
                    step: self.step,
                    deadline: Instant::now() + Duration::from_secs(30),
                    reads: &ReadLog::default(),
                    egress: None,
                },
            )
            .expect("the provider answers with a result, not an error")
    }

    /// The kill flag and the client-sent frames of the dialed pipe.
    fn handles(&self) -> (Arc<AtomicBool>, Arc<Mutex<Vec<String>>>) {
        let h = self.probe.handles().expect("the provider dialed once");
        (h.killed, h.sent)
    }

    /// How many `tools/call` frames the client actually sent.
    fn sent_calls(&self) -> usize {
        let (_, sent) = self.handles();
        let guard = sent.lock().unwrap();
        guard
            .iter()
            .filter(|l| l.contains("\"method\":\"tools/call\""))
            .count()
    }
}

fn text(r: &ToolResult) -> String {
    String::from_utf8(r.output.inspect("test").clone()).unwrap()
}

/// The whole-entry baseline the fixture presents, as the client saw it at
/// connect (echo first, then add).
fn expected_list_sha256() -> String {
    let entries: Vec<Value> = ok_tools()
        .iter()
        .map(|t| {
            json!({"name": t.name, "description": t.description,
                   "inputSchema": t.input_schema})
        })
        .collect();
    sha256(Value::Array(entries).to_string().as_bytes()).to_string()
}

#[test]
fn provider_relist_drift_quarantines_before_call() {
    let mut r = Rig::new(
        "rug-pull-after:1",
        std_cfg(),
        &[("fixture.echo", "echo"), ("fixture.add", "add")],
    );
    // Call 1: the relist still matches the baseline, so the call proceeds.
    let first = r.call("fixture.echo", json!({"text": "hi"}));
    assert_eq!(first.status, ToolStatus::Ok);
    assert_eq!(text(&first), "hi");
    assert!(r.p.take_drift().is_none(), "no drift before the rug pull");
    // Call 2: the relist sees the changed echo entry; the provider
    // quarantines and refuses BEFORE sending tools/call.
    let second = r.call("fixture.echo", json!({"text": "again"}));
    assert_eq!(
        second.status,
        ToolStatus::Refused {
            reason: harness_tools::RefusalKind::Quarantined
        }
    );
    assert!(second.mcp.is_none(), "a refusal carries no MCP record");
    let drift = r.p.take_drift().expect("the rug pull is journaled drift");
    assert_eq!(drift.changed, vec!["echo".to_owned()]);
    assert!(drift.removed.is_empty());
    assert_eq!(drift.unlisted, 0);
    assert_eq!(r.sent_calls(), 1, "only the first call reached the wire");
    // The quarantine sticks.
    let third = r.call("fixture.echo", json!({"text": "more"}));
    assert_eq!(
        third.status,
        ToolStatus::Refused {
            reason: harness_tools::RefusalKind::Quarantined
        }
    );
    assert_eq!(r.sent_calls(), 1);
}

#[test]
fn provider_new_unlisted_tool_does_not_quarantine() {
    let mut r = Rig::new(
        "new-tool-after:1",
        std_cfg(),
        &[("fixture.echo", "echo"), ("fixture.add", "add")],
    );
    let first = r.call("fixture.echo", json!({"text": "hi"}));
    assert_eq!(first.status, ToolStatus::Ok);
    // Call 2: the listing now carries `extra`. The digest changed, the
    // admitted set did not: the new tool is counted and dropped, the call
    // proceeds.
    let second = r.call("fixture.echo", json!({"text": "yo"}));
    assert_eq!(second.status, ToolStatus::Ok);
    assert_eq!(text(&second), "yo");
    let drift = r.p.take_drift().expect("the new tool is journaled drift");
    assert!(drift.changed.is_empty());
    assert!(drift.removed.is_empty());
    assert_eq!(drift.unlisted, 1);
    assert!(
        r.p.quarantined().is_empty(),
        "a new tool never quarantines the admitted set"
    );
    assert_eq!(r.sent_calls(), 2, "both calls went out");
}

#[test]
fn provider_vanished_tool_quarantines() {
    let mut r = Rig::new(
        "vanish-after:1",
        std_cfg(),
        &[("fixture.echo", "echo"), ("fixture.add", "add")],
    );
    let first = r.call("fixture.echo", json!({"text": "hi"}));
    assert_eq!(first.status, ToolStatus::Ok);
    // Call 2: echo is gone from the listing; the provider refuses before
    // calling it.
    let second = r.call("fixture.echo", json!({"text": "again"}));
    assert_eq!(
        second.status,
        ToolStatus::Refused {
            reason: harness_tools::RefusalKind::Quarantined
        }
    );
    let drift = r.p.take_drift().expect("the vanish is journaled drift");
    assert_eq!(drift.removed, vec!["echo".to_owned()]);
    assert!(drift.changed.is_empty());
    assert_eq!(r.sent_calls(), 1, "the vanished tool is never called");
}

#[test]
fn provider_timeout_marks_provider_dead() {
    // `hang-after-connect`: connect's list is answered, every later list
    // hangs, so the FIRST call's pre-call relist hits the deadline.
    let mut r = Rig::new(
        "hang-after-connect",
        hang_cfg(),
        &[("fixture.echo", "echo"), ("fixture.add", "add")],
    );
    let (killed, _) = r.handles();
    let only = r.call("fixture.echo", json!({"text": "hi"}));
    assert_eq!(only.status, ToolStatus::Timeout);
    assert!(only.mcp.is_some(), "the record survives, sans response");
    assert!(
        !only.mcp.as_ref().unwrap().response_frame.is_some(),
        "a timed-out call has no response frame"
    );
    assert!(r.p.is_dead(), "a timeout marks the provider dead");
    assert!(killed.load(Ordering::SeqCst), "the transport was killed");
    assert_eq!(
        r.sent_calls(),
        0,
        "the relist died before any tools/call was sent"
    );
    // Every later call replays the fault (§4).
    let again = r.call("fixture.echo", json!({"text": "more"}));
    assert_eq!(
        again.status,
        ToolStatus::Refused {
            reason: harness_tools::RefusalKind::Quarantined
        }
    );
    assert_eq!(r.sent_calls(), 0);
}

#[test]
fn provider_result_is_untrusted_tool_source() {
    let mut r = Rig::new(
        "ok",
        std_cfg(),
        &[("fixture.echo", "echo"), ("fixture.add", "add")],
    );
    let out = r.call("fixture.echo", json!({"text": "hi"}));
    assert_eq!(out.status, ToolStatus::Ok);
    assert_eq!(text(&out), "hi");
    // The observation is attributed to the CAPABILITY, not the provider.
    assert_eq!(out.output.source(), &Source::Tool("fixture.echo".into()));
    assert_eq!(out.digest, sha256(b"hi"));
    assert!(!out.truncated);
    let rec: &McpRecord = out.mcp.as_ref().expect("an MCP call carries its record");
    // initialize=1, the connect-time baseline list=2, the pre-call
    // relist=3, this call=4.
    assert_eq!(rec.request_id, 4);
    let mut args = Map::new();
    args.insert("text".into(), json!("hi"));
    assert_eq!(
        rec.request_sha256.to_string(),
        sha256(wire::encode_call(4, "echo", &args).as_slice()).to_string()
    );
    assert_eq!(
        rec.list_sha256.to_string(),
        expected_list_sha256(),
        "the record pins the listing the call was cleared against"
    );
    assert_eq!(rec.noise, 0, "the ok mode stays quiet");
    let frame = rec
        .response_frame
        .as_ref()
        .expect("a completed call keeps the raw response");
    let raw = frame.inspect("test");
    assert!(raw.starts_with(b"{\""), "a raw JSON-RPC line, not prose");
    assert!(
        String::from_utf8_lossy(raw).contains("\"jsonrpc\":\"2.0\""),
        "the frame is the raw server line, not a re-rendering"
    );
}

#[test]
fn provider_never_sends_mcp_name_it_was_not_admitted_for() {
    // The registry and session still know fixture.add; the PROVIDER was
    // admitted for echo only.
    let mut r = Rig::new("ok", std_cfg(), &[("fixture.echo", "echo")]);
    let out = r.call("fixture.add", json!({"a": 1, "b": 2}));
    assert_eq!(
        out.status,
        ToolStatus::Refused {
            reason: harness_tools::RefusalKind::UnknownCapability
        }
    );
    assert!(out.mcp.is_none(), "no wire traffic, no record");
    assert_eq!(
        r.sent_calls(),
        0,
        "the un-admitted capability produced zero tools/call traffic"
    );
}
