//! The journal header every mode builds or recomputes: the inputs, the
//! command-runner fields (H2d), the keys a replay compares, and [`header`]
//! itself.

use gate_outcome::Digest;
use harness_core::environment::EnvSample;
use harness_core::{sha256, MeterLimits, Nonce, RunId, Source, Untrusted};
use harness_journal::{Header, Ident, StartError, Trusted};
use harness_manifest::admission::{Registry, Resolved};
use harness_manifest::builtin;
use harness_model::context::{CONTEXT_FORMAT, RESEARCH_CONTEXT_FORMAT, SESSION_CONTEXT_FORMAT};
use harness_model::profile::{Profile, Protocol};
use harness_policy::{SessionKind, UserPolicy, WebConfirmation, SUBMIT_ID};
use harness_sandbox::{Conformed, PortsWitness};
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
    /// The task's port grant, with the probed witness (P-36g §6.1); `None`
    /// without ports, so older journals read as before.
    pub(crate) ports: Option<PortsHeader>,
    /// The project instructions the user trusted at the session's start
    /// (P-30); `None` loads none, so older journals read as before.
    pub(crate) instructions: Option<&'a crate::session::Instructions>,
    /// The workspace-mode record (P-52); `None` in-place (no field).
    pub(crate) workspace_mode: Option<&'a WorkspaceModeRecord>,
    /// The child link (P-38): present only in a child run's header, whose
    /// `mode` is `child`. A batch or session header carries neither this
    /// nor `child`.
    pub(crate) parent: Option<ParentLink>,
    /// The child record (P-38): the brief's nonce, the pinned template,
    /// the brief's digest and the carved wall budget; present only in a
    /// child run's header.
    pub(crate) child: Option<ChildHeader>,
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

/// The workspace-mode record (P-52): what the CLI, as trust base, did to
/// the workspace before the run. The journal records the copy manifest's
/// digest and each file's content digest, never a host path (`Trusted`
/// text is compile-time only): the paths travel in the manifest the CLI
/// writes beside the copy, which this digest binds. Recorded only for a
/// scratch copy; an in-place run's header has no such field, like a
/// journal from before P-52. Not a header input an audit compares: it
/// records host files the replay cannot re-measure — an audit and a
/// resume re-state the recorded value verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceModeRecord {
    /// The mode, `scratch` (the only one this build writes).
    pub mode: &'static str,
    /// The SHA-256 of the copy manifest's exact bytes.
    pub manifest: Digest,
    /// Each file's content digest, in the manifest's order (by path).
    pub files: Vec<Digest>,
}

impl WorkspaceModeRecord {
    /// The record of a scratch copy (P-52).
    pub fn scratch(manifest: Digest, files: Vec<Digest>) -> Self {
        Self {
            mode: "scratch",
            manifest,
            files,
        }
    }

    pub(crate) fn trusted(&self) -> Trusted {
        Trusted::Obj(vec![
            ("mode", Trusted::Text(self.mode)),
            ("manifest", Trusted::Digest(self.manifest)),
            (
                "files",
                Trusted::List(self.files.iter().map(|d| Trusted::Digest(*d)).collect()),
            ),
        ])
    }

    /// A recorded header's `workspace_mode` object, when it is one this
    /// build writes (an audit re-states it; like [`SandboxRecord::parse`]).
    pub(crate) fn parse(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        if o.len() != 3 || o.get("mode")?.as_str()? != "scratch" {
            return None;
        }
        let manifest = o.get("manifest")?.as_str()?.parse().ok()?;
        let files = o
            .get("files")?
            .as_array()?
            .iter()
            .map(|f| f.as_str()?.parse().ok())
            .collect::<Option<Vec<Digest>>>()?;
        Some(Self {
            mode: "scratch",
            manifest,
            files,
        })
    }
}

/// A child run's parent link (P-38): which run delegated, at which attempt
/// and step, and the digest of the delegating call's intent record. Header
/// inputs an audit or a resume compares; only a child header carries one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParentLink {
    /// The delegating run.
    pub(crate) run: RunId,
    /// The delegating attempt.
    pub(crate) attempt: u32,
    /// The delegating loop step.
    pub(crate) step: u64,
    /// The delegating `ToolStarted` record's intent digest
    /// ([`harness_journal::Journaled::intent_hash`]).
    pub(crate) intent_hash: Digest,
}

impl ParentLink {
    fn trusted(&self) -> Result<Trusted, StartError> {
        Ok(Trusted::Obj(vec![
            (
                "run",
                Trusted::Id(Ident::from_trusted(&self.run).ok_or(StartError {
                    op: "header",
                    error: "the parent run id is not an identifier".into(),
                })?),
            ),
            ("attempt", Trusted::U64(u64::from(self.attempt))),
            ("step", Trusted::U64(self.step)),
            ("intent_hash", Trusted::Digest(self.intent_hash)),
        ]))
    }
}

/// What the header records about a child run itself (P-38): the brief's
/// delimiter nonce, the pinned template it was rendered into, the brief's
/// content digest, and the wall budget it was carved. The brief text
/// itself travels beside the header as the untrusted `child_brief` claim
/// (sourced from `harness.task.delegate`), like the `claimed_*` fields:
/// a header field is trusted, so model text cannot be one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChildHeader {
    /// The SHA-256 of the compiled-in brief template, placeholders included.
    pub(crate) template: Digest,
    /// The SHA-256 of the brief's exact bytes (invisible characters
    /// stripped, as [`crate::delegate::child_task_text`] embeds it).
    pub(crate) brief: Digest,
    /// The delimiter nonce drawn for the brief.
    pub(crate) brief_nonce: Nonce,
    /// The wall budget carved for this child, in milliseconds.
    pub(crate) limits_wall_ms: u64,
}

impl ChildHeader {
    fn trusted(&self) -> Result<Trusted, StartError> {
        Ok(Trusted::Obj(vec![
            ("template", Trusted::Digest(self.template)),
            ("brief", Trusted::Digest(self.brief)),
            (
                "brief_nonce",
                Trusted::Id(Ident::from_trusted(&self.brief_nonce).ok_or(StartError {
                    op: "header",
                    error: "the brief nonce is not an identifier".into(),
                })?),
            ),
            ("limits_wall_ms", Trusted::U64(self.limits_wall_ms)),
        ]))
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

/// The header's `ports` object (P-36g §6.1): the granted ports, their LAN
/// subset, the model's reserved ports, and the probe's digest. A header
/// input an audit and a resume compare; absent without a port grant, so
/// older journals read as before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PortsHeader {
    /// Every granted port, in the task's order.
    pub(crate) loopback: Vec<u16>,
    /// The LAN subset, in the task's order.
    pub(crate) lan: Vec<u16>,
    /// The model's own ports, in the caller's order.
    pub(crate) reserved: Vec<u16>,
    /// The ports witness's digest ([`harness_sandbox::PortsWitness`]).
    pub(crate) probe: Digest,
}

impl PortsHeader {
    /// The header of a run that holds ports: `None` without a port grant,
    /// and the witness is there exactly then (planning probes when, and
    /// only when, the task holds ports).
    pub(crate) fn of(
        spec: &TaskSpec,
        config: &RunConfig,
        witness: Option<&PortsWitness>,
    ) -> Option<Self> {
        if spec.ports.is_empty() {
            return None;
        }
        // Planning probed exactly when the task holds ports, so the
        // witness is there; without one this is `None` and the header
        // carries no `ports` key, which an audit or a resume refuses.
        let probe = *witness?.digest();
        Some(Self {
            loopback: spec.ports.clone(),
            lan: spec.lan_ports.clone(),
            reserved: config.reserved_ports.clone(),
            probe,
        })
    }

    fn trusted(&self) -> Trusted {
        Trusted::Obj(vec![
            (
                "loopback",
                Trusted::List(
                    self.loopback
                        .iter()
                        .map(|p| Trusted::U64(u64::from(*p)))
                        .collect(),
                ),
            ),
            (
                "lan",
                Trusted::List(
                    self.lan
                        .iter()
                        .map(|p| Trusted::U64(u64::from(*p)))
                        .collect(),
                ),
            ),
            (
                "reserved",
                Trusted::List(
                    self.reserved
                        .iter()
                        .map(|p| Trusted::U64(u64::from(*p)))
                        .collect(),
                ),
            ),
            ("probe", Trusted::Digest(self.probe)),
        ])
    }

    /// A recorded header's `ports` object, when it is one this build
    /// writes (an audit re-states it; like [`SandboxRecord::parse`]).
    pub(crate) fn parse(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        if o.len() != 4 {
            return None;
        }
        let list = |k: &str| -> Option<Vec<u16>> {
            o.get(k)?
                .as_array()?
                .iter()
                .map(|x| u16::try_from(x.as_u64()?).ok())
                .collect()
        };
        Some(Self {
            loopback: list("loopback")?,
            lan: list("lan")?,
            reserved: list("reserved")?,
            probe: o.get("probe")?.as_str()?.parse().ok()?,
        })
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
/// without one reads as before. `ports` (P-36g §6.1) is the task's port
/// grant and its probe: absent without a port grant, so a journal without
/// one reads as before. `mode` and `turn_limits` (P-05 §1.4) are
/// the session's: absent in a batch run's header, so such a journal reads
/// as before. `session_kind` and `web` (P-39i) are a research session's:
/// absent for a coding session, so coding journals read exactly as before.
/// `post_edit` (P-27) is the task's post-edit checks: absent without one,
/// so a journal without one reads as before. `parent` and `child` (P-38)
/// are a child run's: a batch or session journal has neither, and an audit
/// or a resume recomputes a batch or session header, so a child journal is
/// refused at `mode` (its expected `mode` input is absent, the recorded
/// one says `child`). `instructions` (P-30) is the trusted project
/// instructions' digest: absent when none were loaded, so journals
/// without any read as before. `endpoint_class` (P-31) is a
/// hosted profile's declaration (Q-3): absent for a local model, so every
/// journal written before P-31 reads as before.
pub(crate) const HEADER_INPUT_KEYS: [&str; 25] = [
    "task",
    "grants",
    "workspace_public",
    "protocol",
    "profile",
    "policy",
    "checks",
    "builtin_manifest",
    "tool_docs",
    "shell_enabled",
    "protected",
    "context_format",
    "limits",
    "exec",
    "ports",
    "presubmit",
    "post_edit",
    "mode",
    "turn_limits",
    "session_kind",
    "web",
    "parent",
    "child",
    "instructions",
    "endpoint_class",
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

/// The SHA-256 of the compiled-in terse tool-doc table (P-53): recorded in
/// the header when a run's profile asks for terse docs, so a journal from
/// a build whose table differs is refused by name, exactly like the
/// `builtin_manifest` digest.
pub(crate) fn terse_table_sha256() -> Digest {
    sha256(builtin::terse_table_text().as_bytes())
}

/// The `web` header input of a research session (P-39i, INV-42): the
/// SHA-256 of the grant's canonical JSON — the allowlist exactly as the
/// task gave it, the search flag, the confirmation. A digest, because the
/// allowlist is run input: a journal names the authority it started with,
/// and an audit or a resume recomputes the same digest or refuses.
pub(crate) fn web_grant_digest(g: &harness_policy::WebGrant) -> Digest {
    let v = serde_json::json!({
        "allowlist": g.allowlist,
        "confirmed": match g.confirmed {
            Some(WebConfirmation::Tty) => "tty",
            Some(WebConfirmation::Flag) => "flag",
            None => "none",
        },
        "search": g.search,
    });
    sha256(v.to_string().as_bytes())
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
        // contexts differ (the users' share, P-05 §2.3), so it has its own;
        // a research session's differ again (P-39i, rh-research/2).
        .field(
            "context_format",
            Trusted::Text(match &spec.kind {
                SessionKind::Research(_) => RESEARCH_CONTEXT_FORMAT,
                SessionKind::Coding => match h.session {
                    Some(_) => SESSION_CONTEXT_FORMAT,
                    None => CONTEXT_FORMAT,
                },
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
    // P-53: which terse table this build renders the tool declarations
    // with, when the profile asks for terse docs; no key for a full-docs
    // profile, so every older journal reads as before.
    if h.profile.tool_docs() == harness_model::profile::ToolDocs::Terse {
        hd = hd.field("tool_docs", Trusted::Digest(terse_table_sha256()));
    }
    // P-31, Q-3: the hosted declaration, so a journal says in its header
    // that its context went to a hosted provider. No key for a local
    // model, so every journal written before P-31 reads as before.
    if h.profile.hosted() {
        hd = hd.field("endpoint_class", Trusted::Text("loopback-proxy-hosted"));
    }
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
    // The task's port grant (P-36g §6.1): the ports, their LAN subset, the
    // model's reserved ports and the probe's digest; no key without a port
    // grant, so older journals read as before.
    if let Some(p) = &h.ports {
        hd = hd.field("ports", p.trusted());
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
    // The task's post-edit checks (P-27): the same, by the same rules.
    if let Some(p) = &spec.post_edit {
        hd = hd.field(
            "post_edit",
            Trusted::Obj(vec![
                ("spec", Trusted::Digest(p.digest())),
                ("checks", Trusted::U64(p.checks.len() as u64)),
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
    } else if let (Some(p), Some(c)) = (&h.parent, &h.child) {
        // P-38: a child run's header. Both links must be present (a child
        // is constructed with both); the keys are header inputs, so an
        // audit or a resume of the journal as a batch or session run is
        // refused at `mode` before them.
        hd = hd
            .field("mode", Trusted::Text("child"))
            .field("parent", p.trusted()?)
            .field("child", c.trusted()?);
    } else if h.parent.is_some() || h.child.is_some() {
        // Half a child header is an internal caller's bug; refuse rather
        // than write a journal that names one link and not the other.
        return Err(super::RunRefused::Delegate(
            "a child run's header takes both the parent link and the child record",
        ));
    }
    // P-39i: a research session's kind and web grant, header inputs an
    // audit or a resume compares (INV-42: the session's own authority,
    // journaled before any use). No key for a coding session, so coding
    // journals read exactly as before.
    if let SessionKind::Research(g) = &spec.kind {
        hd = hd
            .field("session_kind", Trusted::Text("research"))
            .field("web", Trusted::Digest(web_grant_digest(g)));
    }
    // P-30: the trusted project instructions' digest, a header input an
    // audit or a resume compares (what entered the context must be what
    // the user approved). No key when none were loaded, so older journals
    // read as before.
    if let Some(n) = &h.instructions {
        hd = hd.field("instructions", Trusted::Digest(n.digest));
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
    // The workspace mode (P-52): present only for a scratch copy, so
    // older journals and in-place runs read as before. Not a header
    // input: an audit or a resume re-states the recorded value.
    if let Some(m) = &h.workspace_mode {
        hd = hd.field("workspace_mode", m.trusted());
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
