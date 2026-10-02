//! The journal header every mode builds or recomputes: the inputs, the
//! command-runner fields (H2d), the keys a replay compares, and [`header`]
//! itself.

use gate_outcome::Digest;
use harness_core::environment::EnvSample;
use harness_core::{sha256, MeterLimits, Source, Untrusted};
use harness_journal::{Header, Ident, StartError, Trusted};
use harness_manifest::admission::{Registry, Resolved};
use harness_manifest::builtin;
use harness_model::context::{CONTEXT_FORMAT, SESSION_CONTEXT_FORMAT};
use harness_model::profile::{Profile, Protocol};
use harness_policy::{UserPolicy, SUBMIT_ID};
use harness_sandbox::Conformed;
use harness_tools::builtin::WorkspaceFacts;
use harness_tools::protected::{DEFAULT_ASK, DEFAULT_DENY};
use harness_tools::Pinned;
use serde_json::Value;

use super::{RunConfig, TaskSpec};
use crate::sample;

/// The `protected` header field (P-29): what the task declared (a digest,
/// the globs are run input), plus this build's deny and ask defaults
/// (compile-time constants, listed). An audit recomputes all three, so a
/// journal from a build with different defaults is refused by name.
pub(crate) fn protected_task_digest(globs: &[String]) -> Digest {
    let mut s = String::from("[");
    for (i, g) in globs.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&Value::from(g.as_str()).to_string());
    }
    s.push(']');
    sha256(s.as_bytes())
}

/// A compile-time glob list as a trusted list (P-29).
fn trusted_globs(globs: &[&'static str]) -> Trusted {
    Trusted::List(globs.iter().map(|g| Trusted::Text(g)).collect())
}

/// Everything the journal header is built from.
pub(crate) struct HeaderInputs<'a> {
    pub(crate) spec: &'a TaskSpec,
    pub(crate) registry: &'a Registry,
    pub(crate) policy: &'a UserPolicy,
    pub(crate) profile: &'a Profile,
    pub(crate) identity: &'a harness_model::ModelIdentity,
    pub(crate) facts: WorkspaceFacts,
    pub(crate) limits: &'a MeterLimits,
    /// A resumed attempt: the attempt it continues, that journal's chain
    /// head, the wall time carried into this attempt (every earlier
    /// attempt's, in milliseconds), and the later attempts passed over as
    /// holding no evidence (H1 phase-exit review F-5).
    pub(crate) resumed_from: Option<(u32, Digest, u64, Vec<u32>)>,
    /// The environment sample (§7.1): measured for a live attempt, the
    /// recorded one for an audit replay.
    pub(crate) environment: EnvSample,
    /// Whether `environment` was copied from a recording (an audit replay's
    /// header) rather than measured here (H1f-3 review F-9).
    pub(crate) environment_recorded: bool,
    /// Whether an approver answers asks in this run (§5.2, H2b).
    pub(crate) approver_present: bool,
    /// The session's turn limits (P-05 §1.4); `None` for a batch run, whose
    /// header carries neither `mode` nor `turn_limits`.
    pub(crate) session: Option<crate::session::TurnLimits>,
    /// The command runner's header fields, with an exec grant (H2d).
    pub(crate) exec: Option<ExecHeader>,
}

/// The sandbox a run's commands ran under, as its witness names it (H2d):
/// the backend, the matrix row, and the exact bars met.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SandboxRecord {
    backend: &'static str,
    matrix_row: &'static str,
    network: &'static str,
    kill_domain: &'static str,
    memory: &'static str,
    processes: &'static str,
    probe: Digest,
}

impl SandboxRecord {
    /// The record of a witness.
    pub(crate) fn of(w: &Conformed) -> Self {
        Self {
            backend: w.backend().name(),
            matrix_row: w.matrix_row(),
            network: w.network().name(),
            kill_domain: w.kill_domain().name(),
            memory: w.memory().name(),
            processes: w.processes().name(),
            probe: *w.probe_digest(),
        }
    }

    /// A recorded header's `sandbox` object, when it is one this build
    /// writes for a witness (an audit re-states it; H2d).
    pub(crate) fn parse(v: &Value) -> Option<Self> {
        use harness_sandbox::{
            BackendKind, KillDomain, MemoryGuard, NetworkMechanism, ProcessGuard,
        };
        let o = v.as_object()?;
        if o.len() != 7 {
            return None;
        }
        let s = |k: &str| o.get(k).and_then(Value::as_str);
        let row = s("matrix_row")?;
        Some(Self {
            backend: BackendKind::from_name(s("backend")?)?.name(),
            matrix_row: harness_sandbox::conformance::MATRIX
                .iter()
                .map(|r| r.id)
                .find(|id| *id == row)?,
            network: NetworkMechanism::from_name(s("network")?)?.name(),
            kill_domain: KillDomain::from_name(s("kill_domain")?)?.name(),
            memory: MemoryGuard::from_name(s("memory")?)?.name(),
            processes: ProcessGuard::from_name(s("processes")?)?.name(),
            probe: s("probe")?.parse().ok()?,
        })
    }

    fn trusted(&self) -> Trusted {
        Trusted::Obj(vec![
            ("backend", Trusted::Text(self.backend)),
            ("matrix_row", Trusted::Text(self.matrix_row)),
            ("network", Trusted::Text(self.network)),
            ("kill_domain", Trusted::Text(self.kill_domain)),
            ("memory", Trusted::Text(self.memory)),
            ("processes", Trusted::Text(self.processes)),
            ("probe", Trusted::Digest(self.probe)),
        ])
    }
}

/// What the header records about the command runner (H2d).
#[derive(Debug, Clone)]
pub(crate) struct ExecHeader {
    /// The sandbox the commands run under.
    pub(crate) sandbox: SandboxRecord,
    /// A shell is on the allowlist (§4.8).
    pub(crate) shell_enabled: bool,
    /// The spec's digest ([`ExecSpec::digest`]): a header input.
    pub(crate) spec: Digest,
    /// How many programs the allowlist names.
    pub(crate) programs: u64,
    /// The pinned programs' content digest, measured at the start.
    pub(crate) programs_sha256: Digest,
    /// Each command's wall clock (`RunConfig::exec_call_timeout`).
    pub(crate) timeout_ms: u64,
}

impl ExecHeader {
    /// The header of a live attempt: the pinned setup and the witness.
    pub(crate) fn live(p: &Pinned, w: &Conformed, config: &RunConfig) -> Self {
        Self {
            sandbox: SandboxRecord::of(w),
            shell_enabled: p.spec().shell_enabled(),
            spec: p.spec_digest(),
            programs: p.spec().programs.len() as u64,
            programs_sha256: p.programs_digest(),
            timeout_ms: u64::try_from(config.exec_call_timeout.as_millis()).unwrap_or(u64::MAX),
        }
    }
}

/// The header keys an audit replay or a resume recomputes from its own
/// inputs and requires to be equal to the recorded ones. `limits` is one
/// (H1 phase-exit review F-1): the replay recomputes every budget stop
/// from the limits, so limits taken from the journal would let a
/// re-chained edit choose the stop the audit then "recomputes".
/// `builtin_manifest` (H1f-3) and `context_format` (H1h) belong to the
/// harness build: a journal another build wrote is refused by name, never
/// replayed into a mismatch. `shell_enabled` and `exec` (H2d) are the
/// task's exec allowlist: absent without an exec grant, so a journal
/// without one reads as before. `mode` and `turn_limits` (P-05 §1.4) are
/// the session's: absent in a batch run's header, so such a journal reads
/// as before.
pub(crate) const HEADER_INPUT_KEYS: [&str; 16] = [
    "task",
    "grants",
    "workspace_public",
    "protocol",
    "profile",
    "policy",
    "checks",
    "builtin_manifest",
    "shell_enabled",
    "protected",
    "context_format",
    "limits",
    "exec",
    "presubmit",
    "mode",
    "turn_limits",
];

/// The header's `limits` object, field by field: the one encoding the
/// header writes and an audit or a resume compares.
pub(crate) fn limits_fields(l: &MeterLimits) -> [(&'static str, u64); 6] {
    [
        ("steps", u64::from(l.steps)),
        ("tokens", l.tokens),
        (
            "wall_ms",
            u64::try_from(l.wall.as_millis()).unwrap_or(u64::MAX),
        ),
        ("cost_micros", l.cost_micros),
        ("format_errors", u64::from(l.format_errors)),
        ("repair_rounds", u64::from(l.repair_rounds)),
    ]
}

/// The SHA-256 of the compiled-in manifest (§7.1 header "manifest
/// SHA-256s": in H1 the built-in provider is the only one admission
/// accepts). rustc reads CRLF sources as LF, so it is the same digest on
/// every OS.
pub(crate) fn builtin_manifest_sha256() -> Digest {
    sha256(builtin::builtin_manifest_json().as_bytes())
}

pub(crate) fn header(h: &HeaderInputs<'_>) -> Result<Header, super::RunRefused> {
    let version = Ident::of(env!("CARGO_PKG_VERSION")).ok_or(StartError {
        op: "header",
        error: "the harness version is not an identifier".into(),
    })?;
    let spec = h.spec;
    let grants = spec
        .grants
        .iter()
        // The sentinel once, whether or not the spec granted it (review N-c).
        .chain(
            (!spec.grants.iter().any(|g| g == SUBMIT_ID))
                .then(|| SUBMIT_ID.to_owned())
                .as_ref(),
        )
        .filter_map(|g| match h.registry.resolve(g) {
            Resolved::One { capability, .. } => Ident::from_capability(capability),
            _ => None,
        })
        .map(Trusted::Id)
        .collect();
    let mut hd = Header::new(version)
        .field(
            "endpoint",
            Trusted::Text(match h.identity.endpoint {
                harness_model::EndpointClass::Loopback => "loopback",
                harness_model::EndpointClass::Replay => "replay",
                harness_model::EndpointClass::Scripted => "scripted",
            }),
        )
        .field(
            "protocol",
            Trusted::Text(match h.profile.protocol() {
                Protocol::Text => "text",
                Protocol::Native => "native",
            }),
        )
        .field(
            "task",
            Trusted::Digest(sha256(spec.task.as_str().as_bytes())),
        )
        .field("profile", Trusted::Digest(h.profile.content_sha256()))
        .field(
            "profile_validated",
            Trusted::Bool(h.identity.profile_validated),
        )
        .field("policy", Trusted::Digest(h.policy.digest()))
        // Whether asks can be answered (H2b): it decides every ask, so an
        // audit plans with the recorded value and a resume must match it.
        .field("approver_present", Trusted::Bool(h.approver_present))
        .field("grants", Trusted::List(grants))
        .field("workspace_public", Trusted::Bool(spec.workspace_public))
        .field("workspace_tree", Trusted::Digest(h.facts.tree))
        .field("workspace_files", Trusted::U64(h.facts.files))
        .field("workspace_oversize", Trusted::U64(h.facts.oversize))
        .field(
            "limits",
            Trusted::Obj(
                limits_fields(h.limits)
                    .into_iter()
                    .map(|(k, v)| (k, Trusted::U64(v)))
                    .collect(),
            ),
        )
        .field("checks", Trusted::U64(0))
        .field(
            "builtin_manifest",
            Trusted::Digest(builtin_manifest_sha256()),
        )
        // A shell on the exec allowlist (§4.8, H2d); none without one.
        .field(
            "shell_enabled",
            Trusted::Bool(h.exec.as_ref().is_some_and(|e| e.shell_enabled)),
        )
        // The protected paths (P-29): what the task declared (a digest of
        // the globs, they are run input) and this build's deny/ask
        // defaults; an audit recomputes all three.
        .field(
            "protected",
            Trusted::Obj(vec![
                (
                    "task",
                    Trusted::Digest(protected_task_digest(&spec.protected)),
                ),
                ("deny_default", trusted_globs(DEFAULT_DENY)),
                ("ask_default", trusted_globs(DEFAULT_ASK)),
            ]),
        )
        // What this build's contexts and requests are (H1h): a replay
        // recomputes them, so it needs the same format. A session run's
        // contexts differ (the users' share, P-05 §2.3), so it has its own.
        .field(
            "context_format",
            Trusted::Text(match h.session {
                Some(_) => SESSION_CONTEXT_FORMAT,
                None => CONTEXT_FORMAT,
            }),
        )
        // The sandbox commands run under (H2d): the witness's backend, row
        // and bars; `none` for a run without an exec grant (no witness was
        // asked for).
        .field(
            "sandbox",
            match &h.exec {
                Some(e) => e.sandbox.trusted(),
                None => Trusted::Obj(vec![("backend", Trusted::Text("none"))]),
            },
        )
        .field("os", Trusted::Text(std::env::consts::OS))
        .field("arch", Trusted::Text(std::env::consts::ARCH))
        .field("environment", sample::to_trusted(&h.environment))
        .field(
            "environment_source",
            Trusted::Text(if h.environment_recorded {
                "recorded"
            } else {
                "measured"
            }),
        );
    if let Some(e) = &h.exec {
        hd = hd
            .field(
                "exec",
                Trusted::Obj(vec![
                    ("spec", Trusted::Digest(e.spec)),
                    ("programs", Trusted::U64(e.programs)),
                ]),
            )
            .field("exec_programs_sha256", Trusted::Digest(e.programs_sha256))
            .field("exec_timeout_ms", Trusted::U64(e.timeout_ms));
    }
    // The task's pre-submit checks (H3a): a header input, compared by audit
    // and resume; no key without checks, so older journals read as before.
    if let Some(p) = &spec.presubmit {
        hd = hd.field(
            "presubmit",
            Trusted::Obj(vec![
                ("spec", Trusted::Digest(p.digest())),
                ("commands", Trusted::U64(p.commands.len() as u64)),
                ("max_rounds", Trusted::U64(u64::from(p.max_rounds))),
            ]),
        );
    }
    // P-05 §1.4: the session's mode and turn limits, header inputs an
    // audit or a resume compares; no key in a batch run's header.
    if let Some(t) = &h.session {
        hd = hd.field("mode", Trusted::Text("session")).field(
            "turn_limits",
            Trusted::Obj(vec![
                ("steps", Trusted::U64(u64::from(t.steps))),
                ("format_errors", Trusted::U64(u64::from(t.format_errors))),
            ]),
        );
    }
    if let Some((attempt, head, carried_ms, skipped)) = &h.resumed_from {
        let mut from = vec![
            ("attempt", Trusted::U64(u64::from(*attempt))),
            ("chain_head", Trusted::Digest(*head)),
            // H1e-2b confirming review NF-1: the wall time of EVERY
            // earlier attempt, so a chain of resumes is charged in full.
            ("wall_carried_ms", Trusted::U64(*carried_ms)),
        ];
        // Named, not silently passed over (H1 phase-exit review F-5).
        if !skipped.is_empty() {
            from.push((
                "skipped_attempts",
                Trusted::List(
                    skipped
                        .iter()
                        .map(|n| Trusted::U64(u64::from(*n)))
                        .collect(),
                ),
            ));
        }
        hd = hd.field("resumed_from", Trusted::Obj(from));
    }
    // §3.5: what the server claims, as untrusted payloads, labelled.
    let c = &h.identity.claimed;
    for (key, v) in [
        ("claimed_model_id", &c.model_id),
        ("claimed_server", &c.server),
        ("claimed_template_sha256", &c.template_sha256),
    ] {
        if let Some(v) = v {
            hd = hd.claimed(key, Untrusted::new(v.clone(), Source::Model));
        }
    }
    Ok(hd)
}
