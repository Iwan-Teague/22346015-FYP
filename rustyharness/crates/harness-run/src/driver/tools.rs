//! The loop's tool side: recorded results re-fed instead of calls (an
//! audit replay, a resume's catch-up), the command runner's journal fields
//! and their exact parse-back, and the command-runner wiring of a run.

use std::path::Path;

use gate_outcome::Digest;
use harness_core::environment::EnvSample;
use harness_core::{Source, StopCause, Untrusted};
use harness_journal::Trusted;
use harness_manifest::admission::{Registry, Resolved};
use harness_manifest::Capability;
use harness_policy::EXEC_ID;
use harness_sandbox::Confinement;
use harness_tools::protected::overlay_dirs;
use harness_tools::{ExecCleanup, ExecEnd, ExecRecord, ExecTools, ToolStatus};
use serde_json::Value;

use super::plan::Prepared;
use super::step::Loop;
use super::{RunConfig, RunRefused};

/// The run's scratch directory, under `runs/<run-id>/` (design §2.8; per
/// run rather than per attempt, H2d).
pub(crate) const SCRATCH_DIR: &str = "scratch";

/// The command runner of a run with an exec grant (H2d): over the
/// workspace, with `runs/<run-id>/scratch` as its scratch directory (per
/// run, so a resumed attempt reuses the build cache; outside the workspace,
/// so build output is not in the tree digest), under the witness `prepare`
/// obtained.
pub(crate) fn exec_tools<'p>(
    pre: &Prepared,
    run_dir: &Path,
    confinement: Option<&'p dyn Confinement>,
    config: &RunConfig,
) -> Result<Option<ExecTools<'p>>, RunRefused> {
    let (Some((pinned, witness)), Some(c)) = (&pre.exec, confinement) else {
        return Ok(None);
    };
    let sources: Vec<String> = pre.protected.patterns().map(str::to_owned).collect();
    Ok(Some(
        ExecTools::new(
            pre.read_tools.root(),
            pinned.clone(),
            &run_dir.join(SCRATCH_DIR),
            c,
            witness.clone(),
            config.facts_timeout,
        )?
        .with_protected_dirs(overlay_dirs(pre.read_tools.root(), &sources)),
    ))
}

/// Whether `tool` is a built-in workspace edit (H2b).
pub(crate) fn is_edit(tool: &str) -> bool {
    harness_policy::EDIT_IDS.contains(&tool)
}

/// Whether `tool` is the built-in command runner (H2d).
pub(crate) fn is_exec(tool: &str) -> bool {
    tool == EXEC_ID
}

/// Whether `tool` is a built-in read tool (`harness.fs.*`).
pub(crate) fn is_read(tool: &str) -> bool {
    matches!(
        tool,
        "harness.fs.read"
            | "harness.fs.search"
            | "harness.fs.list"
            | "harness.fs.glob"
            | "harness.fs.outline"
    )
}

/// A recorded `ToolFinished`, re-fed in place of the call it records.
#[derive(Debug, Clone)]
pub(crate) struct RecordedResult {
    /// The capability the recorded intent named.
    pub(crate) capability: String,
    /// `None` for a recorded provider failure.
    pub(crate) status: Option<ToolStatus>,
    pub(crate) output: Vec<u8>,
    pub(crate) truncated: bool,
    pub(crate) digest: Digest,
    pub(crate) read_sha256: Option<Digest>,
    /// The sample recorded with a `timeout`, `crashed` or `provider_error`
    /// result (§7.1).
    pub(crate) environment: Option<EnvSample>,
    /// The `EditApplied` recorded before an ok edit's result (H2b).
    pub(crate) edit: Option<RecordedEdit>,
    /// What a recorded command did, and the tree digest measured after it
    /// (`None`: not measured), from its `ToolFinished` (H2d).
    pub(crate) exec: Option<(ExecRecord, Option<Digest>)>,
}

impl RecordedResult {
    /// The recorded result as a tool result for this call. A recorded
    /// result for another capability is a provider failure here, so the
    /// replayed journal differs from the recorded one at this step.
    pub(crate) fn into_result(
        self,
        tool: &str,
        path: Option<&str>,
    ) -> Result<harness_tools::ToolResult, harness_tools::ToolError> {
        let unfit =
            || harness_tools::ToolError("the recorded result does not fit this call".into());
        if self.capability != tool {
            return Err(unfit());
        }
        let status = self.status.ok_or_else(unfit)?;
        let read = match (self.read_sha256, path) {
            (Some(sha256), Some(p)) => Some(harness_tools::ReadRecord {
                path: harness_policy::workspace_path(p).map_err(|_| unfit())?,
                sha256,
            }),
            (None, _) => None,
            (Some(_), None) => return Err(unfit()),
        };
        let edit = match (self.edit, path) {
            (Some(e), Some(p)) if is_edit(tool) => Some(harness_tools::EditRecord {
                path: harness_policy::workspace_path(p).map_err(|_| unfit())?,
                before: e.before,
                after: e.after,
            }),
            (None, _) => None,
            _ => return Err(unfit()),
        };
        let exec = match self.exec {
            Some((x, _)) if is_exec(tool) => Some(x),
            None => None,
            Some(_) => return Err(unfit()),
        };
        Ok(harness_tools::ToolResult {
            status,
            output: Untrusted::new(self.output, Source::Tool(self.capability)),
            truncated: self.truncated,
            digest: self.digest,
            read,
            edit,
            exec,
        })
    }
}

/// What an `EditApplied` record says an edit did (the path is the call's).
#[derive(Debug, Clone, Copy)]
pub(crate) struct RecordedEdit {
    pub(crate) before: Option<Digest>,
    pub(crate) after: Digest,
    /// The workspace tree digest after the edit.
    pub(crate) tree: Digest,
}

/// A command's journal record (H2d): how it ended (the exit code or the
/// signal, and the limit that ended it where the harness can tell), whether
/// its kill domain is confirmed empty (and how many it killed), what it
/// wrote (bytes kept, whether a stream was cut at the cap), and its wall
/// time. [`parse_exec`] reads exactly this shape back.
pub(crate) fn exec_fields(x: &ExecRecord) -> Trusted {
    let mut f = vec![("end", Trusted::Text(end_name(x.end)))];
    match x.end {
        ExecEnd::Exited(c) => f.push(("code", Trusted::I64(i64::from(c)))),
        ExecEnd::Signaled(n) => f.push(("signal", Trusted::I64(i64::from(n)))),
        _ => {}
    }
    if let Some(g) = x.end.guard() {
        f.push(("guard", Trusted::Text(g)));
    }
    match x.cleanup {
        ExecCleanup::Confirmed { kills } => {
            f.push(("cleanup", Trusted::Text("confirmed")));
            f.push(("kills", Trusted::U64(u64::from(kills))));
        }
        ExecCleanup::Unconfirmed => f.push(("cleanup", Trusted::Text("unconfirmed"))),
    }
    f.extend([
        ("stdout_bytes", Trusted::U64(x.stdout_bytes)),
        ("stderr_bytes", Trusted::U64(x.stderr_bytes)),
        ("stdout_cut", Trusted::Bool(x.stdout_cut)),
        ("stderr_cut", Trusted::Bool(x.stderr_cut)),
        ("elapsed_ms", Trusted::U64(x.elapsed_ms)),
    ]);
    Trusted::Obj(f)
}

fn end_name(e: ExecEnd) -> &'static str {
    match e {
        ExecEnd::Exited(_) => "exited",
        ExecEnd::Signaled(_) => "signaled",
        ExecEnd::TimedOut => "timed_out",
        ExecEnd::ProcessLimit => "process_limit",
        ExecEnd::ExecFailed => "exec_failed",
        ExecEnd::Unknown => "unknown",
    }
}

/// Read back a command record exactly as [`exec_fields`] writes it, or
/// nothing: every key present exactly when the writer writes it, the guard
/// the one the end implies. Re-fed with no workspace listing.
pub(crate) fn parse_exec(v: &Value) -> Option<ExecRecord> {
    let o = v.as_object()?;
    let i32_at = |k: &str| o.get(k)?.as_i64().and_then(|n| i32::try_from(n).ok());
    let end = match o.get("end")?.as_str()? {
        "exited" => ExecEnd::Exited(i32_at("code")?),
        "signaled" => ExecEnd::Signaled(i32_at("signal")?),
        "timed_out" => ExecEnd::TimedOut,
        "process_limit" => ExecEnd::ProcessLimit,
        "exec_failed" => ExecEnd::ExecFailed,
        "unknown" => ExecEnd::Unknown,
        _ => return None,
    };
    let cleanup = match o.get("cleanup")?.as_str()? {
        "confirmed" => ExecCleanup::Confirmed {
            kills: u32::try_from(o.get("kills")?.as_u64()?).ok()?,
        },
        "unconfirmed" => ExecCleanup::Unconfirmed,
        _ => return None,
    };
    let x = ExecRecord {
        end,
        cleanup,
        stdout_bytes: o.get("stdout_bytes")?.as_u64()?,
        stderr_bytes: o.get("stderr_bytes")?.as_u64()?,
        stdout_cut: o.get("stdout_cut")?.as_bool()?,
        stderr_cut: o.get("stderr_cut")?.as_bool()?,
        elapsed_ms: o.get("elapsed_ms")?.as_u64()?,
        workspace: None,
    };
    // The exact shape: what the writer would write for this record.
    let Trusted::Obj(fields) = exec_fields(&x) else {
        return None;
    };
    let keys: Vec<&str> = fields.iter().map(|(k, _)| *k).collect();
    if o.len() != keys.len() || !keys.iter().all(|k| o.contains_key(*k)) {
        return None;
    }
    if o.get("guard").and_then(Value::as_str) != x.end.guard() {
        return None;
    }
    Some(x)
}

pub(crate) fn status_name(s: ToolStatus) -> &'static str {
    match s {
        ToolStatus::Ok => "ok",
        ToolStatus::Error { .. } => "error",
        ToolStatus::Timeout => "timeout",
        ToolStatus::Crashed { .. } => "crashed",
        ToolStatus::Refused { .. } => "refused",
    }
}

impl<'a> Loop<'a> {
    /// The admitted capability behind an active tool id.
    pub(crate) fn capability(&self, id: &str) -> Result<&'a Capability, StopCause> {
        let registry: &'a Registry = self.registry;
        match registry.resolve(id) {
            Resolved::One { capability, .. } => Ok(capability),
            // The parser only returns active tool ids, all resolved at
            // planning; anything else is a harness bug, refused.
            _ => Err(StopCause::PolicyAbort),
        }
    }
}
