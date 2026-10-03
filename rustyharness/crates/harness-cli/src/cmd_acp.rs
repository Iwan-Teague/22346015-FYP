//! The `acp` verb (P-35): the Agent Client Protocol v1 server over
//! stdio (see `harness-acp`, pinned in docs/slices/P-35-acp-spec-notes.md).
//! It reads its inputs exactly as `chat` does (task, policy, profile,
//! locality), but the protocol OWNS stdout: every line the client sees
//! is JSON-RPC, the session's workspace is each `session/new`'s own
//! `cwd`, and the gate report is written to STDERR at the end — a
//! deliberate deviation from the gate-child contract (the last stdout
//! line would corrupt an ACP client's stream), recorded as a design
//! question in docs/slices/P-35.md.

use std::time::{Duration, Instant};

use gate_outcome::{Coverage, Finding, FindingCode, GateId, GateReport, IndeterminateKind, Scope};
use harness_model::client::{ClientConfig, OpenAiCompatible};
use harness_run::session::SessionConfig;
use harness_run::RunRefused;

use crate::repl::BackendSource;
use crate::report::{exit, info, refused, Outcome};
use crate::Cx;

/// The default gate id, as in `chat`.
const DEFAULT_GATE: &str = "rustyharness.run";

/// The `acp` verb's options (as `chat`'s, minus everything that names
/// or reshapes a workspace: the ACP client brings its own per session).
const ALLOWED: &[&str] = &[
    "task",
    "state-root",
    "profile",
    "endpoint",
    "policy",
    "gate",
    "allow-exec",
    "preset",
    "shell",
    "no-default-denies",
    "allow-session-grants",
    "accept-edits",
];

/// The `acp` verb's valueless flags.
const FLAGS: &[&str] = &["shell", "no-default-denies"];

/// The token budget every CLI session is given (`chat`; the task's
/// `budget` section is not applied to sessions here either).
const TOKEN_BUDGET: u64 = 1_000_000;

/// This process's stdin, buffered, as the ACP server's owned `Send`
/// reader (`StdinLock` borrows; `BufReader<Stdin>` moves).
type StdinSource = std::io::BufReader<std::io::Stdin>;

pub(crate) fn acp(cx: &Cx<'_>, rest: &[&str]) -> u8 {
    let parsed = crate::args::options_with_flags(rest, ALLOWED, FLAGS);
    let gate_text = parsed
        .as_ref()
        .ok()
        .and_then(|p| p.opts.get("gate").copied())
        .unwrap_or(DEFAULT_GATE);
    let gate = match GateId::new(gate_text) {
        Ok(g) => g,
        Err(_) => return exit::USAGE,
    };
    let cfg = match crate::config::load() {
        Ok(c) => c,
        Err(e) => {
            note!(cx, "{e}");
            return emit_err(cx, &gate, refused(exit::UNREADABLE_INPUT, e));
        }
    };
    match parsed {
        Err(e) => {
            note!(cx, "{e}\n{}", crate::args::USAGE);
            emit_err(cx, &gate, refused(exit::USAGE, "usage error".into()))
        }
        Ok(o) => {
            let mut owned: std::collections::BTreeMap<&str, String> =
                o.opts.into_iter().map(|(k, v)| (k, v.to_owned())).collect();
            if let Err(x) = crate::bundle::fill(cx, &mut owned, &cfg) {
                return emit_err(cx, &gate, x);
            }
            let filled: std::collections::BTreeMap<&str, &str> =
                owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
            emit_err(cx, &gate, try_acp(cx, &filled, &cfg))
        }
    }
}

fn try_acp(
    cx: &Cx<'_>,
    o: &std::collections::BTreeMap<&str, &str>,
    cfg: &Option<crate::config::UserConfig>,
) -> Outcome {
    let inp = match crate::inputs::inputs(cx, o, cfg) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let state_root = match crate::config::state_root(o, cfg) {
        Ok(Some(s)) => s,
        Ok(None) => {
            note!(
                cx,
                "--state-root is required here (no default state root on this platform)\n{}",
                crate::args::USAGE
            );
            return refused(exit::USAGE, "--state-root missing".into());
        }
        Err(e) => {
            note!(cx, "{e}");
            return refused(exit::UNREADABLE_INPUT, e);
        }
    };
    // The state root's locality first (§2.8), as `chat` does. Each ACP
    // session's workspace is checked by the run itself (its own `cwd`).
    let root = match std::fs::canonicalize(state_root.as_ref()) {
        Ok(r) => r,
        Err(e) => {
            let why = format!("cannot read the state root: {e}");
            note!(cx, "{why}");
            return refused(exit::INDETERMINATE, why);
        }
    };
    if let Err(e) = harness_policy::locality::check(cx.probe, &root.to_string_lossy()) {
        let why = format!("the state root is not usable here: {e}");
        note!(cx, "{why}");
        return refused(exit::INDETERMINATE, why);
    }
    // The backend: the shipped binary builds the OpenAI-compatible
    // client from --endpoint (and checks the server); an embedder hands
    // one over and no endpoint is needed.
    let endpoint = crate::config::value(o, cfg, "endpoint");
    let client;
    let backend: &dyn harness_model::ModelBackend = match cx.backend {
        BackendSource::Given(b) => b,
        BackendSource::BuiltIn => {
            let Some(url) = endpoint else {
                note!(cx, "--endpoint is required\n{}", crate::args::USAGE);
                return refused(exit::USAGE, "--endpoint missing".into());
            };
            client = match OpenAiCompatible::new(
                url,
                inp.profile.clone(),
                None,
                ClientConfig::default(),
            ) {
                Ok(c) => c,
                Err(e) => {
                    note!(cx, "endpoint refused: {e}");
                    return refused(exit::UNREADABLE_INPUT, format!("endpoint refused: {e}"));
                }
            };
            if let Err(e) = client.startup_check(Instant::now() + Duration::from_secs(30)) {
                note!(cx, "model server check failed: {e}");
                return refused(
                    exit::INDETERMINATE,
                    format!("model server check failed: {e}"),
                );
            }
            &client
        }
    };
    banner(
        cx,
        &inp,
        std::path::Path::new(state_root.as_ref()),
        endpoint,
    );
    // Who answers an ask: the ACP client does (the server's approver
    // bridge). A library-given approver or a terminal prompt is never
    // wired here — stdout is the protocol.
    // The session budgets are the P-05 defaults, as `chat`; the only
    // per-run setting carried over is the session-grants flag (P-23).
    let mut session_config = SessionConfig::defaults(TOKEN_BUDGET);
    session_config.run.allow_session_grants = inp.config.allow_session_grants;
    let mut notes_into = |s: &str| note!(cx, "{s}");
    let out = harness_acp::serve(
        harness_acp::ServeParams {
            state_root: std::path::Path::new(state_root.as_ref()),
            spec: &inp.spec,
            registry: &inp.registry,
            policy: &inp.policy,
            profile: &inp.profile,
            backend,
            probe: cx.probe,
            env: &harness_sandbox::environment::SystemEnv,
            confinement: Some(cx.confinement),
            config: session_config,
            allow_session_grants: inp.config.allow_session_grants,
            notes: &mut notes_into,
        },
        StdinSource::new(std::io::stdin()),
        std::io::stdout().lock(),
    );
    if let Some(e) = &out.start_refused {
        let mut o = from_refusal(cx, e);
        // The refusal is reported, the session(s) that did run (if
        // any) are still found below.
        if out.sessions.is_empty() {
            return o;
        }
        o.findings.extend(session_findings(&out));
        return o;
    }
    if out.sessions.is_empty() {
        note!(cx, "no ACP session ran");
        return refused(exit::INDETERMINATE, "no ACP session ran".into());
    }
    let (where_, report) = match out.sessions.last() {
        Some((sid, r)) => (format!("acp session {sid}"), r),
        None => return refused(exit::INDETERMINATE, "no ACP session ran".into()),
    };
    for (sid, r) in &out.sessions {
        note!(
            cx,
            "acp session {sid} attempt {}: {} turn(s), {} step(s), stopped ({})",
            r.run.attempt,
            r.turns,
            r.run.steps,
            harness_journal::writer::stop_cause_name(&r.run.cause)
        );
    }
    if let Some(e) = &report.run.journal_error {
        note!(cx, "journal failure: {e}");
    }
    let mut findings = session_findings(&out);
    if let Ok(f) = Finding::new(
        gate_outcome::Severity::Info,
        FindingCode("harness.acp.sessions".to_owned()),
        &where_,
        "the ACP sessions this stream served",
        format!("{} session(s)", out.sessions.len()),
    ) {
        findings.push(f);
    }
    Outcome {
        outcome: report.run.outcome.clone(),
        findings,
        chain_head: report.run.chain_head.map(|d| d.to_string()),
        exit_override: None,
    }
}

fn session_findings(out: &harness_acp::ServeOutput) -> Vec<Finding> {
    out.sessions
        .iter()
        .filter_map(|(sid, r)| {
            info(
                "harness.acp.session",
                &format!("acp session {sid}"),
                "a verification plan (H1 tasks have none)",
                format!(
                    "{} turn(s), {} step(s), stopped: {}; no checks planned",
                    r.turns,
                    r.run.steps,
                    harness_journal::writer::stop_cause_name(&r.run.cause)
                ),
            )
        })
        .collect()
}

fn banner(
    cx: &Cx<'_>,
    inp: &crate::inputs::Inputs,
    state_root: &std::path::Path,
    endpoint: Option<&str>,
) {
    note!(
        cx,
        "rustyharness acp (Agent Client Protocol v1 over stdio; the exit is Indeterminate until H3)"
    );
    note!(cx, "state root {}", state_root.display());
    note!(
        cx,
        "model {} ({})",
        inp.profile.id(),
        endpoint.unwrap_or("(a backend given to the library)")
    );
    if inp.spec.exec.is_some() {
        match harness_sandbox::available() {
            harness_sandbox::Containment::Available(b) => {
                note!(cx, "confinement: {}", b.matrix_row());
            }
            harness_sandbox::Containment::Unavailable(u) => note!(
                cx,
                "confinement unavailable ({}); commands will be refused",
                u.reason
            ),
        }
    } else {
        note!(cx, "no confinement: read/edit only");
    }
    note!(cx, "tools: {}", inp.spec.grants.join(", "));
    note!(cx, "policy digest: {}", inp.policy.digest());
}

fn from_refusal(cx: &Cx<'_>, e: &RunRefused) -> Outcome {
    note!(cx, "the session did not start: {e}");
    let code = match e {
        RunRefused::Confinement(_) => exit::CONFINEMENT_REFUSED,
        RunRefused::Presubmit(_) => exit::UNREADABLE_INPUT,
        _ => exit::INDETERMINATE,
    };
    let mut out = refused(code, format!("the session did not start: {e}"));
    out.outcome = e.outcome();
    out
}

/// [`crate::report::emit`] for a verb whose stdout is a protocol
/// stream: the same report line and exit code, but on STDERR, and no
/// `GATE_OK_FILE` marker (an H1 session is never `Passed`). The
/// deviation from the gate-child contract is recorded in
/// docs/slices/P-35.md as a design question.
fn emit_err(cx: &Cx<'_>, gate: &GateId, o: Outcome) -> u8 {
    let code = match (&o.exit_override, &o.outcome) {
        (Some(c), _) => *c,
        (None, gate_outcome::GateOutcome::Passed(_)) => exit::PASSED,
        (None, gate_outcome::GateOutcome::Failed) => exit::FAILED,
        (None, gate_outcome::GateOutcome::Indeterminate { .. }) => exit::INDETERMINATE,
    };
    let report = GateReport::new(
        gate.clone(),
        o.outcome,
        o.findings,
        Coverage::Full,
        Scope::empty(),
    )
    .or_else(|_| {
        GateReport::new(
            gate.clone(),
            gate_outcome::GateOutcome::Indeterminate {
                why: IndeterminateKind::CouldNotRun,
            },
            Vec::new(),
            Coverage::Full,
            Scope::empty(),
        )
    });
    let Ok(report) = report else {
        return exit::INDETERMINATE;
    };
    let Ok(line) = serde_json::to_string(&report) else {
        return exit::INDETERMINATE;
    };
    if let Some(h) = &o.chain_head {
        note!(cx, "chain_head {h}");
    }
    note!(cx, "{line}");
    code
}
