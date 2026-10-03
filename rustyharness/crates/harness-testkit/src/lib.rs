//! Dev-only test kit for the rustyharness workspace's own tests (slice
//! P-03). Not published, not part of the harness: everything here is
//! scaffolding around the public APIs, kept in one place so the crates'
//! integration tests stop duplicating it (a fixture, the locality probe,
//! the built-in registry, a scripted model, an audit assertion and an
//! in-process CLI driver).
//!
//! Nothing here may weaken what a test can assert: [`run_scripted`] runs
//! the real `harness_run::run` against the real journal on a real disk,
//! [`assert_audit_clean`] runs the real audit replay, and [`cli`] drives
//! the real `harness_cli` verbs in process. The kit adds convenience only.
//!
//! [`mutator`] (P-54) adds the deterministic fuzz-style generator the
//! parsers' robustness tests share.

#![forbid(unsafe_code)]
// The panic-set lints ratchet production code, and this crate is a
// dependency of other crates' tests: it stays inside the ratchet and
// returns `Result`s instead of panicking. (Its own integration tests
// re-allow the set in their files, as every crate's do.)
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

pub mod mutator;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use harness_core::environment::{EnvSample, Unmeasured};
use harness_journal::{layout, EventKind, JournalReader};
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, SemVer, ValidationContext};
use harness_model::profile::Profile;
use harness_model::scripted::{text_reply, ScriptedBackend};
use harness_model::{Completion, TaskText};
use harness_policy::locality::{FsQuery, LocalityProbe};
use harness_policy::UserPolicy;
use harness_run::{
    audit, audit_session, run, ApprovalAnswer, Approver, ApproverKind, Audit, Run, RunConfig,
    RunRefused, RunReport, SessionConfig, SessionReport, TaskSpec,
};

/// The token budget every scripted run is given. An audit must be given
/// the same limits the run was (review F-1), so [`assert_audit_clean`]
/// derives them from this too.
const TOKEN_BUDGET: u64 = 1_000_000;

/// A fixed environment sample (the real probe is harness-sandbox's; a
/// scripted run only needs the header and records to carry one).
const FIXED_ENV: EnvSample = EnvSample::unmeasured(Unmeasured::NoSafeApi);

/// A probe that reports a local APFS volume (the decision is pure, so this
/// is admitted on any host).
pub struct Local;

impl LocalityProbe for Local {
    fn query(&self, _path: &str) -> FsQuery {
        FsQuery::MacOs {
            mnt_local: true,
            fs_type_name: "apfs".into(),
        }
    }
}

/// The built-in manifest, admitted alone (the only provider a scripted run
/// can ever call).
pub fn registry() -> io::Result<Registry> {
    let ctx = ValidationContext::new(
        SemVer {
            major: 0,
            minor: 0,
            patch: 1,
        },
        &[],
    )
    .map_err(|e| io::Error::other(format!("validation context: {e}")))?;
    let m =
        builtin::manifest(&ctx).map_err(|e| io::Error::other(format!("built-in manifest: {e}")))?;
    Registry::admit(vec![(m, Tier::Builtin)])
        .map_err(|e| io::Error::other(format!("admission: {e}")))
}

// ---------------------------------------------------------------------------
// Scripted model replies.
// ---------------------------------------------------------------------------

/// A free-text reply.
pub fn say(content: &str) -> Completion {
    text_reply(content)
}

/// An action reply in the text protocol: `<action>{"tool":…,"args":…}</action>`.
pub fn act(tool: &str, args: &str) -> Completion {
    say(&format!(
        "<action>{{\"tool\":\"{tool}\",\"args\":{args}}}</action>"
    ))
}

/// The built-in submit action (§2.5), the usual last reply of a scripted
/// run.
pub fn submit() -> Completion {
    act("harness.task.submit", "{\"note\":\"done\"}")
}

/// A read-only task spec: the three built-in read grants and a private
/// workspace.
pub fn read_spec(task: &str) -> TaskSpec {
    TaskSpec {
        task: TaskText::new(task.into()),
        grants: vec![
            "harness.fs.read".into(),
            "harness.fs.search".into(),
            "harness.fs.list".into(),
        ],
        workspace_public: false,
        exec: None,
        presubmit: None,
        protected: Vec::new(),
        kind: harness_run::SessionKind::Coding,
    }
}

// ---------------------------------------------------------------------------
// The fixture.
// ---------------------------------------------------------------------------

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

/// A temporary state root and workspace on disk, removed when dropped.
///
/// The pair is unique per fixture (process id, a counter and the label),
/// so tests can hold several at once and never share a directory, and a
/// crashed test run leaves nothing a later run would pick up: `new`
/// removes a stale directory of the same name before creating it.
pub struct Fixture {
    base: PathBuf,
    state_root: PathBuf,
    workspace: PathBuf,
    /// The task spec runs (and audits) are given. Override it freely
    /// before [`run_scripted`]; the audit compares against the fixture's
    /// spec, so change it before running, not after.
    pub spec: TaskSpec,
}

impl Fixture {
    /// A fixture whose base directory is named with `label` (every
    /// character outside ASCII alphanumerics and `-` becomes `-`).
    pub fn new(label: &str) -> io::Result<Self> {
        Self::with_spec(label, read_spec("What does a.txt say?"))
    }

    /// [`Fixture::new`] with a different starting task spec.
    pub fn with_spec(label: &str, spec: TaskSpec) -> io::Result<Self> {
        let n = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let safe: String = label
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        let base = std::env::temp_dir().join(format!(
            "rustyharness-testkit-{}-{}-{safe}",
            std::process::id(),
            n
        ));
        // A leftover from a crashed earlier process must not leak in.
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("state"))?;
        std::fs::create_dir_all(base.join("ws"))?;
        Ok(Self {
            state_root: base.join("state"),
            workspace: base.join("ws"),
            base,
            spec,
        })
    }

    /// The fixture's base directory (everything lives under it).
    pub fn base(&self) -> &Path {
        &self.base
    }

    /// The state root a run is given.
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    /// The workspace a run is given.
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// Write a file into the workspace (parent directories included),
    /// returning its full path.
    pub fn write(&self, rel: &str, contents: &str) -> io::Result<PathBuf> {
        let p = self.workspace.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&p, contents)?;
        Ok(p)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

// ---------------------------------------------------------------------------
// Scripted runs, audits, journals.
// ---------------------------------------------------------------------------

/// Why a scripted run never started.
#[derive(Debug, thiserror::Error)]
pub enum ScriptedRunRefused {
    /// The built-in registry could not be admitted (a harness bug, never a
    /// test's input).
    #[error("registry: {0}")]
    Registry(#[from] io::Error),
    /// `run` refused before anything ran.
    #[error(transparent)]
    Run(#[from] RunRefused),
}

/// Run a task to a stop against a scripted model: the real `run`, the real
/// journal, the real tools, the built-in registry, the default user policy
/// and profile, [`Local`]'s locality answer and [`FIXED_ENV`]. The replies
/// are handed to the backend in order.
pub fn run_scripted(
    fx: &Fixture,
    replies: Vec<Completion>,
) -> Result<RunReport, ScriptedRunRefused> {
    run_scripted_policy(fx, &UserPolicy::default(), replies)
}

/// [`run_scripted`] under a caller-chosen user policy (P-08): the real
/// `run` reads its matchers, and the journal carries the policy's digest,
/// which [`assert_audit_clean_policy`] must be given back.
pub fn run_scripted_policy(
    fx: &Fixture,
    policy: &UserPolicy,
    replies: Vec<Completion>,
) -> Result<RunReport, ScriptedRunRefused> {
    let registry = registry()?;
    let profile = Profile::conservative_default("m");
    let backend = ScriptedBackend::new(profile.clone(), replies.into_iter().map(Ok).collect());
    let report = run(Run {
        state_root: fx.state_root(),
        workspace: fx.workspace(),
        spec: &fx.spec,
        registry: &registry,
        policy,
        profile: &profile,
        backend: &backend,
        probe: &Local,
        env: &FIXED_ENV,
        config: &RunConfig::defaults(TOKEN_BUDGET),
        approver: None,
        confinement: None,
    })?;
    Ok(report)
}

/// Audit the run a scripted (or hand-built) run left behind, and require
/// it clean: no divergence, the recorded stop recomputed, and — when the
/// run reported a chain head — that head anchored. The audit is given the
/// fixture's spec, the default policy and profile, and the same limits
/// [`run_scripted`] gave the run (review F-1), with the report's chain
/// head as the anchor.
pub fn assert_audit_clean(fx: &Fixture, report: &RunReport) -> Result<(), String> {
    assert_audit_clean_policy(fx, &UserPolicy::default(), report)
}

/// [`assert_audit_clean`] under a caller-chosen user policy (P-08): the
/// replay recomputes every matched decision with the SAME policy the run
/// had — a different policy (a different digest) is refused before any
/// decision is compared (§2.9, §7.1 header).
pub fn assert_audit_clean_policy(
    fx: &Fixture,
    policy: &UserPolicy,
    report: &RunReport,
) -> Result<(), String> {
    let registry = registry().map_err(|e| format!("registry: {e}"))?;
    let a = audit(Audit {
        state_root: fx.state_root(),
        run: &report.run,
        attempt: None,
        anchor: report.chain_head,
        spec: &fx.spec,
        registry: &registry,
        policy,
        profile: &Profile::conservative_default("m"),
        limits: &RunConfig::defaults(TOKEN_BUDGET).limits,
    })
    .map_err(|e| format!("audit refused: {e}"))?;
    if let Some(d) = &a.divergence {
        return Err(format!(
            "the replay diverged at seq {} (step {}): {}",
            d.seq, d.step, d.why
        ));
    }
    if !a.stop_recomputed {
        return Err(
            "the recorded stop was not recomputed (a wall stop or an uncommitted attempt)".into(),
        );
    }
    if report.chain_head.is_some() && !a.anchored {
        return Err("the run's chain head did not anchor the journal".into());
    }
    Ok(())
}

/// [`assert_audit_clean`] for a session run (P-20): the same three
/// requirements — no divergence, the recorded stop recomputed, and the
/// chain head anchored — checked by the session audit
/// (`audit_session`), which replays the session's turns against its own
/// header (`mode: session`, the `/6` context format, the run's limits
/// with the meter's `format_errors` replaced by "never", and the
/// configured turn limits). The audit is given the fixture's spec, the
/// default policy and profile, the defaults' session config, and the
/// report's chain head as the anchor.
pub fn assert_session_audit_clean(fx: &Fixture, report: &SessionReport) -> Result<(), String> {
    assert_session_audit_clean_with(
        fx,
        &UserPolicy::default(),
        &Profile::conservative_default("m"),
        report,
        &SessionConfig::defaults(TOKEN_BUDGET),
        None,
    )
}

/// [`assert_session_audit_clean`] with explicit everything: a
/// caller-chosen policy and profile (the run's own, whose digests the
/// header carries), the session config the run (or its resume) was
/// given — its limits and turn limits are the header's — and the
/// attempt to audit (`None` for the recorded one, `Some(2)` for a
/// resumed attempt).
pub fn assert_session_audit_clean_with(
    fx: &Fixture,
    policy: &UserPolicy,
    profile: &Profile,
    report: &SessionReport,
    config: &SessionConfig,
    attempt: Option<u32>,
) -> Result<(), String> {
    let mut limits = config.run.limits.clone();
    limits.format_errors = u32::MAX;
    let reg = registry().map_err(|e| format!("registry: {e}"))?;
    let a = audit_session(
        Audit {
            state_root: fx.state_root(),
            run: &report.run.run,
            attempt,
            anchor: report.run.chain_head,
            spec: &fx.spec,
            registry: &reg,
            policy,
            profile,
            limits: &limits,
        },
        &config.turn,
    )
    .map_err(|e| format!("session audit refused: {e}"))?;
    if let Some(d) = &a.divergence {
        return Err(format!(
            "the replay diverged at seq {} (step {}): {}",
            d.seq, d.step, d.why
        ));
    }
    if !a.stop_recomputed {
        return Err(
            "the recorded stop was not recomputed (a wall stop or an uncommitted attempt)".into(),
        );
    }
    if report.run.chain_head.is_some() && !a.anchored {
        return Err("the run's chain head did not anchor the journal".into());
    }
    Ok(())
}

/// The event kinds of the run's reported attempt, in journal order.
pub fn journal_kinds(report: &RunReport) -> io::Result<Vec<EventKind>> {
    let dir = layout::attempt_dir(&report.run_dir, report.attempt);
    let v = JournalReader::open(&dir)
        .map_err(|e| io::Error::other(format!("journal at {}: {e}", dir.display())))?;
    Ok(v.records.iter().map(|r| r.kind).collect())
}

// ---------------------------------------------------------------------------
// The in-process CLI driver.
// ---------------------------------------------------------------------------

/// An approver fed pre-typed lines, one per ask (the in-process twin of
/// the terminal prompt's rules: `y`/`yes` approves, any other line
/// declines, and no line left is no answer).
struct LineApprover {
    lines: RefCell<VecDeque<String>>,
}

impl Approver for LineApprover {
    fn kind(&self) -> ApproverKind {
        ApproverKind::Embedded
    }

    fn ask(
        &self,
        _req: &harness_policy::approval::ApprovalRequest,
        _deadline: Instant,
    ) -> ApprovalAnswer {
        match self.lines.borrow_mut().pop_front() {
            Some(line) => {
                let a = line.trim().to_ascii_lowercase();
                if a == "y" || a == "yes" {
                    ApprovalAnswer::Yes
                } else {
                    ApprovalAnswer::No
                }
            }
            None => ApprovalAnswer::NoAnswer,
        }
    }
}

/// Run one CLI invocation in process, capturing everything: the exit code,
/// standard output and standard error as strings. The locality probe is
/// [`Local`], the approver is fed `stdin_lines` in order (see
/// [`LineApprover`]), the `GATE_OK_FILE` marker is `gate-ok` under the
/// fixture's base directory, and confinement is the production
/// `SystemConfinement`. Nothing here touches a network or a real terminal.
pub fn cli(fx: &Fixture, args: &[&str], stdin_lines: &[&str]) -> (u8, String, String) {
    let approver = LineApprover {
        lines: RefCell::new(stdin_lines.iter().map(|s| (*s).to_owned()).collect()),
    };
    let no_input: Vec<String> = Vec::new();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = {
        let cx = harness_cli::Cx {
            probe: &Local,
            gate_ok_file: Some(fx.base.join("gate-ok")),
            out: RefCell::new(&mut out),
            err: RefCell::new(&mut err),
            approver: harness_cli::ApproverSource::Given(&approver),
            confinement: &harness_sandbox::SystemConfinement,
            input: harness_cli::InputSource::Given(&no_input),
            backend: harness_cli::BackendSource::BuiltIn,
        };
        harness_cli::main_with(&cx, args)
    };
    (
        code,
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
    )
}

/// Run one `chat` invocation in process (P-18): the model replies are
/// handed to a scripted backend, the REPL reads `input_lines` in order
/// (end of input when they run out), and an ask is answered from
/// `approver_lines` (`y`/`yes` approves, anything else declines, no line
/// left is no answer — nobody is at a terminal here). Everything else is
/// as [`cli`].
pub fn chat_cli(
    fx: &Fixture,
    args: &[&str],
    input_lines: &[&str],
    replies: Vec<Completion>,
    approver_lines: &[&str],
) -> (u8, String, String) {
    let approver = LineApprover {
        lines: RefCell::new(approver_lines.iter().map(|s| (*s).to_owned()).collect()),
    };
    let input: Vec<String> = input_lines.iter().map(|s| (*s).to_owned()).collect();
    let backend = ScriptedBackend::new(
        Profile::conservative_default("m"),
        replies.into_iter().map(Ok).collect(),
    );
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = {
        let cx = harness_cli::Cx {
            probe: &Local,
            gate_ok_file: Some(fx.base.join("gate-ok")),
            out: RefCell::new(&mut out),
            err: RefCell::new(&mut err),
            approver: harness_cli::ApproverSource::Given(&approver),
            confinement: &harness_sandbox::SystemConfinement,
            input: harness_cli::InputSource::Given(&input),
            backend: harness_cli::BackendSource::Given(&backend),
        };
        harness_cli::main_with(&cx, args)
    };
    (
        code,
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
    )
}

/// [`chat_cli`] with nobody to answer an ask (the piped-stdin case): every
/// ask is a deny (§5.2), whatever lines are left.
pub fn chat_cli_unattended(
    fx: &Fixture,
    args: &[&str],
    input_lines: &[&str],
    replies: Vec<Completion>,
) -> (u8, String, String) {
    let input: Vec<String> = input_lines.iter().map(|s| (*s).to_owned()).collect();
    let backend = ScriptedBackend::new(
        Profile::conservative_default("m"),
        replies.into_iter().map(Ok).collect(),
    );
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = {
        let cx = harness_cli::Cx {
            probe: &Local,
            gate_ok_file: Some(fx.base.join("gate-ok")),
            out: RefCell::new(&mut out),
            err: RefCell::new(&mut err),
            approver: harness_cli::ApproverSource::None,
            confinement: &harness_sandbox::SystemConfinement,
            input: harness_cli::InputSource::Given(&input),
            backend: harness_cli::BackendSource::Given(&backend),
        };
        harness_cli::main_with(&cx, args)
    };
    (
        code,
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
    )
}
