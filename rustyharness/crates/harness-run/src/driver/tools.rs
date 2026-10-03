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
use harness_tools::{ExecCleanup, ExecEnd, ExecRecord, ExecTools, Image, ToolStatus};
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
    let (Some((pinned, witness)), Some(c), Some(read)) =
        (&pre.exec, confinement, pre.read_tools.as_ref())
    else {
        // A research session (P-39i) has neither an exec grant nor read
        // tools; a coding run has both whenever the grant is set.
        return Ok(None);
    };
    let sources: Vec<String> = pre.protected.patterns().map(str::to_owned).collect();
    Ok(Some(
        ExecTools::new(
            read.root(),
            pinned.clone(),
            &run_dir.join(SCRATCH_DIR),
            c,
            witness.clone(),
            config.facts_timeout,
        )?
        .with_protected_dirs(overlay_dirs(read.root(), &sources)),
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
    /// The `EditApplied` records before an ok edit's result (H2b), in the
    /// order they were journaled: one per touched file since P-25 (a
    /// patch touches several, a move two).
    pub(crate) edits: Vec<RecordedEdit>,
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
        let mut edits = Vec::new();
        match self.edits.is_empty() {
            true => {}
            false if is_edit(tool) => {
                for e in &self.edits {
                    edits.push(harness_tools::EditRecord {
                        path: harness_policy::workspace_path(&e.path).map_err(|_| unfit())?,
                        before: e.before,
                        after: e.after,
                        before_image: e.before_image.clone(),
                        after_image: e.after_image.clone(),
                    });
                }
            }
            false => return Err(unfit()),
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
            edits,
            exec,
            // Replay recompute of an `McpRecord` from the journal's
            // `ToolFinished` mcp fields arrives with the MCP driver slice
            // (P-37i); no journal written so far carries them.
            mcp: None,
            web: None,
        })
    }
}

/// What an `EditApplied` record says one file's edit did (its own `path`,
/// not the call's), with the images its record cites, read back from the
/// blob store (P-22; `after`/`after_image` are `None` for a delete, where
/// the record carries no after-image at all).
#[derive(Debug, Clone)]
pub(crate) struct RecordedEdit {
    /// The file the record is about (P-25; before that, the call's path).
    pub(crate) path: String,
    pub(crate) before: Option<Digest>,
    /// The file's digest after the edit (`None`: the file was deleted).
    pub(crate) after: Option<Digest>,
    /// The workspace tree digest after the edit.
    pub(crate) tree: Digest,
    /// The file's bytes before the edit, from the record's `before_blob`
    /// (`None` for a create, which keeps no pre-image).
    pub(crate) before_image: Option<Image>,
    /// The file's bytes after the edit, from the record's `after_blob`
    /// (`None` for a delete).
    pub(crate) after_image: Option<Image>,
}

/// A command's journal record (H2d): how it ended (the exit code or the
/// signal, and the limit that ended it where the harness can tell), whether
/// its kill domain is confirmed empty (and how many it killed), what it
/// wrote (bytes kept, whether a stream was cut at the cap), and its wall
/// time. `connect` lists the loopback ports of the run's live background
/// processes the command may reach (P-36 §6.2), recorded only when
/// non-empty, so journals from builds before background processes encode
/// byte for byte the same. [`parse_exec`] reads exactly this shape back.
pub(crate) fn exec_fields(x: &ExecRecord, connect: &[u16]) -> Trusted {
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
    if !connect.is_empty() {
        f.push(("connect", ports_list(connect)));
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
/// nothing: every key present exactly when the writer writes it (a
/// non-empty `connect` included, `connect: []` never), the guard the one
/// the end implies. Re-fed with no workspace listing.
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
    let connect: Vec<u16> = match o.get("connect") {
        Some(c) => c
            .as_array()?
            .iter()
            .map(|p| p.as_u64().and_then(|n| u16::try_from(n).ok()))
            .collect::<Option<Vec<_>>>()?,
        None => Vec::new(),
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
    let Trusted::Obj(fields) = exec_fields(&x, &connect) else {
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

// ---- Background processes (P-36 §10.2) -------------------------------------

/// A granted loopback port's reach (P-36 §3.1): this turn, or the session
/// (`--bg-persist`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
pub(crate) enum BgScope {
    Turn,
    Session,
}

/// A `harness.exec.read` mode (P-36 §3.2): continue where the last read
/// stopped, or show the recent tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
pub(crate) enum BgReadMode {
    Next,
    Tail,
}

/// A background process's journaled state (P-36 §11.2): running after a
/// successful start; the others only after a stop record says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
pub(crate) enum BgState {
    Running,
    Exited,
    Stopped,
    Lost,
}

/// What a start waited for (P-36 §3.1 step 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
pub(crate) enum BgReadyKind {
    Port,
    Text,
}

/// How a start's spawn ended, when it did not start (P-36 §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
pub(crate) enum BgStartState {
    Running,
    ExecFailed,
}

/// A `ready` wait's result (P-36 §10.2): met or not (not met is not an
/// error), and how long the harness waited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
pub(crate) struct BgReady {
    pub(crate) kind: BgReadyKind,
    pub(crate) met: bool,
    pub(crate) waited_ms: u64,
}

/// One stream's delivered window (P-36 §10.2 `W`): what the reader asked
/// for (`since`), what the ring could still give (`from`, after `dropped`
/// bytes it already lost) and what the tail cut (`skipped`), the cursor
/// the bytes were shown to (`to`), the stream's whole size (`total`), and
/// the SHA-256 of exactly the delivered bytes (`sha`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
pub(crate) struct BgWindow {
    pub(crate) since: u64,
    pub(crate) from: u64,
    pub(crate) to: u64,
    pub(crate) dropped: u64,
    pub(crate) skipped: u64,
    pub(crate) total: u64,
    pub(crate) sha: Digest,
}

/// One id of a `read` without an id: the listing the model sees (P-36
/// §3.2), with the bytes not yet delivered per stream.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
pub(crate) struct BgListItem {
    pub(crate) id: u32,
    pub(crate) state: BgState,
    pub(crate) ports: Vec<u16>,
    pub(crate) pending_out: u64,
    pub(crate) pending_err: u64,
}

/// The `bg` object of a successful or refused `harness.exec.start` (P-36
/// §10.2): the minted id, whether it is running or the spawn failed, the
/// ports it holds (loopback and of those the LAN-visible ones), its scope
/// and lifetime, and the `ready` wait when one was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
pub(crate) struct BgStart {
    pub(crate) id: u32,
    pub(crate) state: BgStartState,
    pub(crate) ports: Vec<u16>,
    pub(crate) lan: Vec<u16>,
    pub(crate) scope: BgScope,
    pub(crate) lifetime_s: u32,
    pub(crate) ready: Option<BgReady>,
}

/// The `bg` object of a `harness.exec.read` of one id (P-36 §10.2): both
/// streams' windows, and, when the id has ended, how (`end`, `cleanup`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
pub(crate) struct BgRead {
    pub(crate) id: u32,
    pub(crate) mode: BgReadMode,
    pub(crate) state: BgState,
    pub(crate) out: BgWindow,
    pub(crate) err: BgWindow,
    pub(crate) ended: Option<(ExecEnd, ExecCleanup)>,
}

/// The `bg` object of a `harness.exec.stop` (P-36 §10.2): how it ended,
/// whether its kill domain is confirmed swept, both streams' final
/// windows, and the totals and whole-stream digests the journal commits
/// to without storing the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
pub(crate) struct BgStop {
    pub(crate) id: u32,
    pub(crate) end: ExecEnd,
    pub(crate) cleanup: ExecCleanup,
    pub(crate) out: BgWindow,
    pub(crate) err: BgWindow,
    pub(crate) out_total: u64,
    pub(crate) err_total: u64,
    pub(crate) out_sha: Digest,
    pub(crate) err_sha: Digest,
}

/// A background tool's journal record: the `bg` object of its
/// `ToolFinished`, exactly one shape per op. [`parse_bg`] reads it back.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
pub(crate) enum BgRecord {
    Start(BgStart),
    Read(BgRead),
    List(Vec<BgListItem>),
    Stop(BgStop),
}

fn ports_list(ports: &[u16]) -> Trusted {
    Trusted::List(ports.iter().map(|p| Trusted::U64(u64::from(*p))).collect())
}

/// The exec record's `end` object (P-36 §10.1: "as exec_fields' end").
#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
fn bg_end_obj(e: ExecEnd) -> Trusted {
    let mut f = vec![("end", Trusted::Text(end_name(e)))];
    match e {
        ExecEnd::Exited(c) => f.push(("code", Trusted::I64(i64::from(c)))),
        ExecEnd::Signaled(n) => f.push(("signal", Trusted::I64(i64::from(n)))),
        _ => {}
    }
    if let Some(g) = e.guard() {
        f.push(("guard", Trusted::Text(g)));
    }
    Trusted::Obj(f)
}

/// A sweep decision (P-36 §10.1): the confirmed kill count as an object,
/// `unconfirmed` as plain text.
#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
fn bg_cleanup_obj(c: ExecCleanup) -> Trusted {
    match c {
        ExecCleanup::Confirmed { kills } => {
            Trusted::Obj(vec![("confirmed", Trusted::U64(u64::from(kills)))])
        }
        ExecCleanup::Unconfirmed => Trusted::Text("unconfirmed"),
    }
}

#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
fn bg_window_obj(w: &BgWindow) -> Trusted {
    Trusted::Obj(vec![
        ("since", Trusted::U64(w.since)),
        ("from", Trusted::U64(w.from)),
        ("to", Trusted::U64(w.to)),
        ("dropped", Trusted::U64(w.dropped)),
        ("skipped", Trusted::U64(w.skipped)),
        ("total", Trusted::U64(w.total)),
        ("sha", Trusted::Digest(w.sha)),
    ])
}

#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
fn bg_scope_name(s: BgScope) -> &'static str {
    match s {
        BgScope::Turn => "turn",
        BgScope::Session => "session",
    }
}

#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
fn bg_mode_name(m: BgReadMode) -> &'static str {
    match m {
        BgReadMode::Next => "next",
        BgReadMode::Tail => "tail",
    }
}

#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
fn bg_state_name(s: BgState) -> &'static str {
    match s {
        BgState::Running => "running",
        BgState::Exited => "exited",
        BgState::Stopped => "stopped",
        BgState::Lost => "lost",
    }
}

#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
fn bg_ready_kind_name(k: BgReadyKind) -> &'static str {
    match k {
        BgReadyKind::Port => "port",
        BgReadyKind::Text => "text",
    }
}

#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
fn bg_start_state_name(s: BgStartState) -> &'static str {
    match s {
        BgStartState::Running => "running",
        BgStartState::ExecFailed => "exec_failed",
    }
}

/// A background tool's journal record (P-36 §10.2), beside
/// [`exec_fields`]: the `bg` object of its `ToolFinished`, every key
/// present exactly when the writer writes it.
#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
pub(crate) fn bg_fields(b: &BgRecord) -> Trusted {
    match b {
        BgRecord::Start(s) => {
            let mut f = vec![
                ("op", Trusted::Text("start")),
                ("id", Trusted::U64(u64::from(s.id))),
                ("state", Trusted::Text(bg_start_state_name(s.state))),
                ("ports", ports_list(&s.ports)),
                ("lan", ports_list(&s.lan)),
                ("scope", Trusted::Text(bg_scope_name(s.scope))),
                ("lifetime_s", Trusted::U64(u64::from(s.lifetime_s))),
            ];
            if let Some(r) = s.ready {
                f.push((
                    "ready",
                    Trusted::Obj(vec![
                        ("kind", Trusted::Text(bg_ready_kind_name(r.kind))),
                        ("met", Trusted::Bool(r.met)),
                        ("waited_ms", Trusted::U64(r.waited_ms)),
                    ]),
                ));
            }
            Trusted::Obj(f)
        }
        BgRecord::Read(r) => {
            let mut f = vec![
                ("op", Trusted::Text("read")),
                ("id", Trusted::U64(u64::from(r.id))),
                ("mode", Trusted::Text(bg_mode_name(r.mode))),
                ("state", Trusted::Text(bg_state_name(r.state))),
                ("out", bg_window_obj(&r.out)),
                ("err", bg_window_obj(&r.err)),
            ];
            if let Some((end, cleanup)) = r.ended {
                f.push(("end", bg_end_obj(end)));
                f.push(("cleanup", bg_cleanup_obj(cleanup)));
            }
            Trusted::Obj(f)
        }
        BgRecord::List(items) => Trusted::Obj(vec![
            ("op", Trusted::Text("list")),
            (
                "items",
                Trusted::List(
                    items
                        .iter()
                        .map(|i| {
                            Trusted::Obj(vec![
                                ("id", Trusted::U64(u64::from(i.id))),
                                ("state", Trusted::Text(bg_state_name(i.state))),
                                ("ports", ports_list(&i.ports)),
                                ("pending_out", Trusted::U64(i.pending_out)),
                                ("pending_err", Trusted::U64(i.pending_err)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]),
        BgRecord::Stop(s) => Trusted::Obj(vec![
            ("op", Trusted::Text("stop")),
            ("id", Trusted::U64(u64::from(s.id))),
            ("end", bg_end_obj(s.end)),
            ("cleanup", bg_cleanup_obj(s.cleanup)),
            ("out", bg_window_obj(&s.out)),
            ("err", bg_window_obj(&s.err)),
            ("out_total", Trusted::U64(s.out_total)),
            ("err_total", Trusted::U64(s.err_total)),
            ("out_sha", Trusted::Digest(s.out_sha)),
            ("err_sha", Trusted::Digest(s.err_sha)),
        ]),
    }
}

/// Read back a background record exactly as [`bg_fields`] writes it, or
/// nothing: every key present exactly when the writer writes it (an
/// ended read carries `end` and `cleanup` together or not at all, the
/// end's guard the one the end implies, every nested object exactly its
/// canonical keys).
#[cfg_attr(not(test), allow(dead_code))] // the tools arrive with P-36i; tests until then
pub(crate) fn parse_bg(v: &Value) -> Option<BgRecord> {
    let o = v.as_object()?;
    let u64_at = |o: &serde_json::Map<String, Value>, k: &str| o.get(k).and_then(Value::as_u64);
    let u32_at = |o: &serde_json::Map<String, Value>, k: &str| {
        o.get(k)?.as_u64().and_then(|n| u32::try_from(n).ok())
    };
    let ports_at = |o: &serde_json::Map<String, Value>, k: &str| -> Option<Vec<u16>> {
        o.get(k)?
            .as_array()?
            .iter()
            .map(|p| p.as_u64().and_then(|n| u16::try_from(n).ok()))
            .collect()
    };
    let window_at = |w: &Value| -> Option<BgWindow> {
        let w = w.as_object()?;
        if w.len() != 7 {
            return None;
        }
        Some(BgWindow {
            since: u64_at(w, "since")?,
            from: u64_at(w, "from")?,
            to: u64_at(w, "to")?,
            dropped: u64_at(w, "dropped")?,
            skipped: u64_at(w, "skipped")?,
            total: u64_at(w, "total")?,
            sha: w.get("sha")?.as_str()?.parse().ok()?,
        })
    };
    let end_at = |e: &Value| -> Option<ExecEnd> {
        let e = e.as_object()?;
        let i32_at = |k: &str| e.get(k)?.as_i64().and_then(|n| i32::try_from(n).ok());
        let end = match e.get("end")?.as_str()? {
            "exited" => ExecEnd::Exited(i32_at("code")?),
            "signaled" => ExecEnd::Signaled(i32_at("signal")?),
            "timed_out" => ExecEnd::TimedOut,
            "process_limit" => ExecEnd::ProcessLimit,
            "exec_failed" => ExecEnd::ExecFailed,
            "unknown" => ExecEnd::Unknown,
            _ => return None,
        };
        // The exact shape: what the writer would write for this end.
        let Trusted::Obj(fields) = bg_end_obj(end) else {
            return None;
        };
        let keys: Vec<&str> = fields.iter().map(|(k, _)| *k).collect();
        if e.len() != keys.len() || !keys.iter().all(|k| e.contains_key(*k)) {
            return None;
        }
        if e.get("guard").and_then(Value::as_str) != end.guard() {
            return None;
        }
        Some(end)
    };
    let cleanup_at = |c: &Value| -> Option<ExecCleanup> {
        match c.as_str() {
            Some("unconfirmed") => Some(ExecCleanup::Unconfirmed),
            _ => {
                let c = c.as_object()?;
                if c.len() != 1 {
                    return None;
                }
                Some(ExecCleanup::Confirmed {
                    kills: u32_at(c, "confirmed")?,
                })
            }
        }
    };
    let state_at = |s: &str| match s {
        "running" => Some(BgState::Running),
        "exited" => Some(BgState::Exited),
        "stopped" => Some(BgState::Stopped),
        "lost" => Some(BgState::Lost),
        _ => None,
    };
    let list_item = |i: &Value| -> Option<BgListItem> {
        let i = i.as_object()?;
        if i.len() != 5 {
            return None;
        }
        Some(BgListItem {
            id: u32_at(i, "id")?,
            state: state_at(i.get("state")?.as_str()?)?,
            ports: ports_at(i, "ports")?,
            pending_out: u64_at(i, "pending_out")?,
            pending_err: u64_at(i, "pending_err")?,
        })
    };
    let record = match o.get("op")?.as_str()? {
        "start" => {
            let ready = match o.get("ready") {
                Some(r) => {
                    let r = r.as_object()?;
                    if r.len() != 3 {
                        return None;
                    }
                    Some(BgReady {
                        kind: match r.get("kind")?.as_str()? {
                            "port" => BgReadyKind::Port,
                            "text" => BgReadyKind::Text,
                            _ => return None,
                        },
                        met: r.get("met")?.as_bool()?,
                        waited_ms: u64_at(r, "waited_ms")?,
                    })
                }
                None => None,
            };
            let scope = match o.get("scope")?.as_str()? {
                "turn" => BgScope::Turn,
                "session" => BgScope::Session,
                _ => return None,
            };
            BgRecord::Start(BgStart {
                id: u32_at(o, "id")?,
                state: match o.get("state")?.as_str()? {
                    "running" => BgStartState::Running,
                    "exec_failed" => BgStartState::ExecFailed,
                    _ => return None,
                },
                ports: ports_at(o, "ports")?,
                lan: ports_at(o, "lan")?,
                scope,
                lifetime_s: u32_at(o, "lifetime_s")?,
                ready,
            })
        }
        "read" => {
            let ended = match (o.get("end"), o.get("cleanup")) {
                (Some(e), Some(c)) => Some((end_at(e)?, cleanup_at(c)?)),
                (None, None) => None,
                _ => return None,
            };
            BgRecord::Read(BgRead {
                id: u32_at(o, "id")?,
                mode: match o.get("mode")?.as_str()? {
                    "next" => BgReadMode::Next,
                    "tail" => BgReadMode::Tail,
                    _ => return None,
                },
                state: state_at(o.get("state")?.as_str()?)?,
                out: window_at(o.get("out")?)?,
                err: window_at(o.get("err")?)?,
                ended,
            })
        }
        "list" => BgRecord::List(
            o.get("items")?
                .as_array()?
                .iter()
                .map(list_item)
                .collect::<Option<Vec<_>>>()?,
        ),
        "stop" => BgRecord::Stop(BgStop {
            id: u32_at(o, "id")?,
            end: end_at(o.get("end")?)?,
            cleanup: cleanup_at(o.get("cleanup")?)?,
            out: window_at(o.get("out")?)?,
            err: window_at(o.get("err")?)?,
            out_total: u64_at(o, "out_total")?,
            err_total: u64_at(o, "err_total")?,
            out_sha: o.get("out_sha")?.as_str()?.parse().ok()?,
            err_sha: o.get("err_sha")?.as_str()?.parse().ok()?,
        }),
        _ => return None,
    };
    // The exact shape: what the writer would write for this record.
    let Trusted::Obj(fields) = bg_fields(&record) else {
        return None;
    };
    let keys: Vec<&str> = fields.iter().map(|(k, _)| *k).collect();
    if o.len() != keys.len() || !keys.iter().all(|k| o.contains_key(*k)) {
        return None;
    }
    Some(record)
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
