//! The built-in background-process tools (design P-36 §3, §6.2):
//! `harness.exec.start`, `harness.exec.read` and `harness.exec.stop`.
//!
//! [`BgTools`] is a [`ToolProvider`], so it runs only a
//! `Journaled<Authorized<Call>>`: policy planned the session with a
//! conformed sandbox witness, resolved the program against the exec
//! allowlist (INV-13) and checked `cwd` against the workspace path rule,
//! before anything starts.
//!
//! **Live, confined, bounded.** A start goes through
//! [`harness_sandbox::Confinement::spawn_live`] with the same pinned
//! program, scratch and limits a command gets, a per-stream ring of
//! [`BG_RING_BYTES`] bytes, and the asked lifetime as its wall clock
//! (bounded by [`BG_LIFETIME_MAX`] and by the run's wall clock remaining).
//! There are at most [`BG_MAX_LIVE`] live processes and [`BG_MAX_STARTS`]
//! starts per run; ids are sequential and never reused, and a start that
//! fails to spawn journals its id with state `exec_failed`.
//!
//! **Refusal order** (§3): program and `cwd` first, then the limits, then
//! the ports (each in the task's grant, not held by a live id, free on the
//! host — the host check binds and releases, so a busy port is a measured
//! refusal), then the scope (`session` needs the run's `bg.persist`
//! header), then the witness (it must cover [`BG_CASES`], plus
//! [`PORTS_CASES`] when ports are asked), and only then the spawn. A
//! refusal before the spawn consumes no id and journals no `bg` record.
//!
//! **Confinement invariant (INV-42, P-36f).** These tools need the
//! confined file-op helper: a run whose file tools run in process has no
//! kernel-enforced view for a live child, so every bg call is refused
//! ([`code::BG_FILE_OPS`]) before anything is examined. The driver wires
//! the flag when it starts the helper.
//!
//! **Reading.** `harness.exec.read` without an id lists every id with its
//! state, program, ports and undelivered bytes; with an id it delivers a
//! window of one or both streams through the pure cursor arithmetic of
//! [`window`] (re-exported from the sandbox's ring), at most
//! [`BG_READ_MAX`] bytes per call (three quarters to stdout, the rest —
//! including any unused share — to stderr), in `next` or `tail` mode, with
//! an optional bounded wait. The delivered cursor becomes the window's
//! `to`, moved back where it would split a UTF-8 character.
//!
//! **Stopping.** `harness.exec.stop` closes the live child's control pipe
//! and reports the recorded end, whether the sweep is confirmed, and the
//! output not yet delivered (tail mode, capped). Stopping an id that
//! already ended is a deterministic refusal repeating that end.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use harness_core::Digest;
use harness_journal::Journaled;
use harness_manifest::ProviderName;
use harness_policy::{Authorized, Call, EXEC_READ_ID, EXEC_START_ID, EXEC_STOP_ID};
use harness_sandbox::conformance::{BG_CASES, PORTS_CASES};
use harness_sandbox::spec::{PORTS_PER_START, PORT_MIN};
use harness_sandbox::{
    ChildStatus, Chunk, ConfinedChild, ConfinedExit, ConfinedSpec, Confinement, Conformed,
    DomainCleanup, Limits, LiveOpts, Mode, Network, SpawnError, Stream, StreamTotals,
};
use serde_json::Value;

use crate::builtin::{arg_u64, canonical_root, code, err, finish, refused, Out, RootRefused};
use crate::exec::{env_for, parse_argv, resolve_cwd, ExecLimits, Pinned, Scratch};
use crate::file_ops::InProcess;
use crate::provider::{
    ExecCleanup, ExecEnd, InvokeCtx, RefusalKind, ToolError, ToolProvider, ToolResult, ToolStatus,
};

// ---- Constants (§3; the journal header's `bg` object documents them) ------

/// Most background processes live at once (§3).
pub const BG_MAX_LIVE: usize = 4;
/// Most starts one run may make, live or failed to spawn (§3).
pub const BG_MAX_STARTS: u32 = 16;
/// A start's default lifetime, in seconds (§3).
pub const BG_LIFETIME_DEFAULT: u32 = 1800;
/// The longest lifetime a start may ask, in seconds (§3).
pub const BG_LIFETIME_MAX: u32 = 4 * 60 * 60;
/// Bytes kept per stream while a process runs (§3); the count and digest
/// never forget.
pub const BG_RING_BYTES: u64 = 1024 * 1024;
/// Most bytes one read delivers (§3.2).
pub const BG_READ_MAX: usize = 16 * 1024;
/// The longest `ready` wait a start may ask, in seconds (§3).
pub const BG_READY_MAX: u32 = 60;
/// The longest `wait_secs` a read may ask, in seconds (§3.2).
pub const BG_READ_WAIT_MAX: u32 = 30;
/// Most ports the task may grant one run (§3.1; the sandbox's
/// `PORTS_PER_START` bounds one start's binds).
pub const PORTS_PER_TASK: usize = 8;

/// The cursor arithmetic one read is stated in (§3.2): pure, from the
/// sandbox's ring.
pub use harness_sandbox::ring::window;

// ---- Journal record types (§10.2; `bg_fields` in the run writes them) -----

/// A granted loopback port's reach (P-36 §3.1): this turn, or the session
/// (`--bg-persist`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgScope {
    /// Stops at the end of the turn that started it.
    Turn,
    /// Stops at the end of the run (`bg.persist`).
    Session,
}

/// A `harness.exec.read` mode (P-36 §3.2): continue where the last read
/// stopped, or show the recent tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgReadMode {
    /// Continue after `since`.
    Next,
    /// The recent tail; the jump counts as `skipped`.
    Tail,
}

/// A background process's journaled state (P-36 §11.2): running after a
/// successful start; the others only after a stop record says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgState {
    /// Started and not yet observed to end.
    Running,
    /// Observed to have exited (a stop record or a read's poll said so).
    Exited,
    /// Stopped by `harness.exec.stop`.
    Stopped,
    /// Lost: the sandbox could not account for it.
    Lost,
}

/// What a start waited for (P-36 §3.1 step 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgReadyKind {
    /// A TCP connect to the port.
    Port,
    /// The text in either stream.
    Text,
}

/// How a start's spawn ended, when it did not start (P-36 §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgStartState {
    /// Spawned and running.
    Running,
    /// The sandbox refused or failed the spawn; the id is consumed.
    ExecFailed,
}

/// A `ready` wait's result (P-36 §10.2): met or not (not met is not an
/// error), and how long the harness waited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BgReady {
    /// What the start waited for.
    pub kind: BgReadyKind,
    /// Whether the wait saw it before its seconds ran out.
    pub met: bool,
    /// How long the harness waited.
    pub waited_ms: u64,
}

/// One stream's delivered window (P-36 §10.2 `W`): what the reader asked
/// for (`since`), what the ring could still give (`from`, after `dropped`
/// bytes it already lost) and what the tail cut (`skipped`), the cursor
/// the bytes were shown to (`to`), the stream's whole size (`total`), and
/// the SHA-256 of exactly the delivered bytes (`sha`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BgWindow {
    /// What the reader asked for.
    pub since: u64,
    /// First absolute offset delivered.
    pub from: u64,
    /// One past the last offset delivered; the next cursor.
    pub to: u64,
    /// Bytes before `from` the ring had already dropped.
    pub dropped: u64,
    /// Bytes between `from` and `to` a tail read jumped.
    pub skipped: u64,
    /// The stream's whole size.
    pub total: u64,
    /// SHA-256 of exactly the delivered bytes.
    pub sha: Digest,
}

/// One id of a `read` without an id: the listing the model sees (P-36
/// §3.2), with the bytes not yet delivered per stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgListItem {
    /// The process id.
    pub id: u32,
    /// Its journaled state.
    pub state: BgState,
    /// The loopback ports it holds.
    pub ports: Vec<u16>,
    /// Stdout bytes written but not yet delivered.
    pub pending_out: u64,
    /// Stderr bytes written but not yet delivered.
    pub pending_err: u64,
}

/// The `bg` object of a successful or refused `harness.exec.start` (P-36
/// §10.2): the minted id, whether it is running or the spawn failed, the
/// ports it holds (loopback and of those the LAN-visible ones), its scope
/// and lifetime, and the `ready` wait when one was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgStart {
    /// The minted id (consumed by the attempt, success or not).
    pub id: u32,
    /// Whether it spawned or the spawn failed.
    pub state: BgStartState,
    /// The loopback ports it holds.
    pub ports: Vec<u16>,
    /// Of those, the LAN-visible ones.
    pub lan: Vec<u16>,
    /// Its scope.
    pub scope: BgScope,
    /// Its lifetime, in seconds as asked (after the run's wall clamp).
    pub lifetime_s: u32,
    /// The `ready` wait, when one was asked.
    pub ready: Option<BgReady>,
}

/// The `bg` object of a `harness.exec.read` of one id (P-36 §10.2): both
/// streams' windows, and, when the id has ended, how (`end`, `cleanup`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgRead {
    /// The process read.
    pub id: u32,
    /// The mode the call asked.
    pub mode: BgReadMode,
    /// The process's state as this read left it.
    pub state: BgState,
    /// The stdout window.
    pub out: BgWindow,
    /// The stderr window.
    pub err: BgWindow,
    /// How the process ended, when this read knows (`end`, `cleanup`).
    pub ended: Option<(ExecEnd, ExecCleanup)>,
}

/// The `bg` object of a `harness.exec.stop` (P-36 §10.2): how it ended,
/// whether its kill domain is confirmed swept, both streams' final
/// windows, and the totals and whole-stream digests the journal commits
/// to without storing the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgStop {
    /// The process stopped.
    pub id: u32,
    /// How it ended.
    pub end: ExecEnd,
    /// Whether its kill domain is confirmed swept.
    pub cleanup: ExecCleanup,
    /// The stdout window of the stop's report.
    pub out: BgWindow,
    /// The stderr window of the stop's report.
    pub err: BgWindow,
    /// Whole stdout bytes ever written.
    pub out_total: u64,
    /// Whole stderr bytes ever written.
    pub err_total: u64,
    /// SHA-256 over every stdout byte ever written.
    pub out_sha: Digest,
    /// SHA-256 over every stderr byte ever written.
    pub err_sha: Digest,
}

/// A background tool's journal record: the `bg` object of its
/// `ToolFinished`, exactly one shape per op. The run's `parse_bg` reads it
/// back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgRecord {
    /// A start's record: the minted id and whether it runs.
    Start(BgStart),
    /// A read of one id: both windows.
    Read(BgRead),
    /// A read without an id: every id's listing.
    List(Vec<BgListItem>),
    /// A stop: the end, the sweep and the final windows.
    Stop(BgStop),
}

// ---- The provider ----------------------------------------------------------

/// The harness's bind probe address (§3): a start's port is measured free
/// by binding loopback and releasing.
fn probe_addr(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
}

/// Bind `port` on loopback and release it: `Ok` when the host let the
/// harness have it (the measurement a start journals), `Err` why not.
fn host_binds(port: u16) -> Result<(), std::io::Error> {
    TcpListener::bind(probe_addr(port)).map(|_| ())
}

/// Try a TCP connect to a start's `ready` port (connect, then close).
fn port_ready(port: u16) -> bool {
    TcpStream::connect_timeout(
        &SocketAddr::from(probe_addr(port)),
        Duration::from_millis(250),
    )
    .is_ok()
}

/// One live or ended background process the manager accounts for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BgEntry {
    pub(crate) id: u32,
    /// The allowlisted program's name (`argv[0]`).
    pub(crate) program: String,
    pub(crate) ports: Vec<u16>,
    pub(crate) lan: Vec<u16>,
    pub(crate) scope: BgScope,
    pub(crate) lifetime_s: u32,
    pub(crate) start_step: u64,
    pub(crate) state: BgState,
    pub(crate) end: Option<(ExecEnd, ExecCleanup)>,
    /// The delivered cursor of each stream.
    pub(crate) out_cursor: u64,
    pub(crate) err_cursor: u64,
}

/// The manager's pure bookkeeping: every start this run made (in id
/// order), the live children, and how many starts were made. The refusal
/// arithmetic (limits, held ports, sequential ids) runs on this alone, so
/// it is testable without any process.
#[derive(Default)]
pub(crate) struct BgBook {
    pub(crate) entries: Vec<BgEntry>,
    pub(crate) children: BTreeMap<u32, ConfinedChild>,
    /// Starts so far, each with an id: live, ended, and failed to spawn.
    pub(crate) started: u32,
}

impl BgBook {
    /// Processes currently live (§3: `running` after a successful start;
    /// `exited`/`stopped` only after a stop record).
    pub(crate) fn live(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.state == BgState::Running)
            .count()
    }

    /// Whether one more start fits the run's limits (§3): under
    /// [`BG_MAX_LIVE`] live and under [`BG_MAX_STARTS`] starts.
    pub(crate) fn start_fits(&self) -> Result<(), Out> {
        if self.live() >= BG_MAX_LIVE {
            return Err(err(
                code::BG_LIVE_LIMIT,
                "the run already holds 4 live background processes; stop one first",
            ));
        }
        if self.started >= BG_MAX_STARTS {
            return Err(err(
                code::BG_START_LIMIT,
                "the run already made 16 background starts (the per-run cap)",
            ));
        }
        Ok(())
    }

    /// The next id: sequential over every journaled start, never reused.
    pub(crate) fn next_id(&self) -> u32 {
        self.started + 1
    }

    /// The ports the live ids hold (§6.2): a start may not take one, and
    /// an exec call's `connect` is exactly this set.
    pub(crate) fn held_ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self
            .entries
            .iter()
            .filter(|e| e.state == BgState::Running)
            .flat_map(|e| e.ports.iter().copied())
            .collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    pub(crate) fn entry(&self, id: u32) -> Option<&BgEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub(crate) fn entry_mut(&mut self, id: u32) -> Option<&mut BgEntry> {
        self.entries.iter_mut().find(|e| e.id == id)
    }
}

/// The built-in background-process tools of one run (see the module docs).
pub struct BgTools<'a> {
    ns: ProviderName,
    root: PathBuf,
    scratch: Scratch,
    pinned: Pinned,
    limits: ExecLimits,
    confinement: &'a dyn Confinement,
    witness: Conformed,
    protected_dirs: Vec<PathBuf>,
    /// The run's `bg.persist` header: `scope: "session"` starts exist only
    /// when it is set (§3).
    persist: bool,
    /// Whether the run's file tools go through the confined helper
    /// (P-36f, INV-42): these tools refuse whole when not.
    confined_files: bool,
    /// The task's loopback-port grants (§3.1), and, of those, the
    /// LAN-visible ones.
    port_grants: Vec<u16>,
    lan_grants: Vec<u16>,
    /// The run's wall clock remaining, as the driver last measured it: a
    /// lifetime never runs past it (§3). `None` before the driver wires it.
    wall_remaining: Option<Duration>,
    book: BgBook,
}

impl std::fmt::Debug for BgTools<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgTools")
            .field("root", &self.root)
            .field("scratch", &self.scratch.dir())
            .field("started", &self.book.started)
            .finish_non_exhaustive()
    }
}

/// Why the bg setup was refused at construction.
#[derive(Debug, thiserror::Error)]
pub enum BgSetupError {
    /// The workspace or scratch root is not usable.
    #[error("workspace refused: {0}")]
    Root(#[from] RootRefused),
    /// The scratch directory could not be prepared or overlaps the
    /// workspace.
    #[error("the background scratch directory: {0}")]
    Scratch(String),
}

impl<'a> BgTools<'a> {
    /// The background tools over the workspace at `root`, with the same
    /// checked exec setup `pinned` the command runner holds (the allowlist,
    /// limits and environment are the task's), the scratch directory (the
    /// run's, shared with `harness.exec.run`), the confinement and its
    /// witness.
    pub fn new(
        root: &Path,
        pinned: Pinned,
        scratch: &Path,
        confinement: &'a dyn Confinement,
        witness: Conformed,
    ) -> Result<Self, BgSetupError> {
        let ns = ProviderName::new(harness_manifest::BUILTIN_NAMESPACE)
            .map_err(|_| BgSetupError::Scratch("builtin namespace".into()))?;
        let root = canonical_root(&mut InProcess, root)?;
        let scratch =
            Scratch::prepare(scratch, &root).map_err(|e| BgSetupError::Scratch(e.to_string()))?;
        Ok(Self {
            ns,
            root,
            scratch,
            limits: pinned.spec().limits,
            pinned,
            confinement,
            witness,
            protected_dirs: Vec::new(),
            persist: false,
            confined_files: false,
            port_grants: Vec::new(),
            lan_grants: Vec::new(),
            wall_remaining: None,
            book: BgBook::default(),
        })
    }

    /// The protected-path overlay directories, as the command runner gets
    /// them (P-29).
    #[must_use]
    pub fn with_protected_dirs(mut self, dirs: Vec<PathBuf>) -> Self {
        self.protected_dirs = dirs;
        self
    }

    /// Whether the run's header set `bg.persist` (§3): `scope: "session"`
    /// starts exist only then. Off by default.
    #[must_use]
    pub fn with_persist(mut self, persist: bool) -> Self {
        self.persist = persist;
        self
    }

    /// Whether the run's file tools go through the confined helper
    /// (P-36f): these tools refuse whole when not. Off by default.
    #[must_use]
    pub fn with_confined_files(mut self, confined: bool) -> Self {
        self.confined_files = confined;
        self
    }

    /// The task's port grants (§3.1): the loopback ports any start may
    /// bind, and, of those, the LAN-visible ones. Empty by default (no
    /// ports were granted).
    #[must_use]
    pub fn with_port_grants(mut self, ports: Vec<u16>, lan: Vec<u16>) -> Self {
        self.port_grants = ports;
        self.lan_grants = lan;
        self
    }

    /// The run's wall clock remaining, as the driver measures it per step
    /// (§3: a lifetime never runs past the run). Unset by default, which
    /// leaves a lifetime at what it asked.
    #[must_use]
    pub fn with_wall_remaining(mut self, remaining: Option<Duration>) -> Self {
        self.wall_remaining = remaining;
        self
    }

    /// The ports the live ids hold right now (§6.2): the loop's
    /// `connect` set for the next exec call. The driver calls this at
    /// each step boundary (P-36j).
    pub fn held_ports(&self) -> Vec<u16> {
        self.book.held_ports()
    }

    /// Collect every live id the sandbox already has an exit for, without
    /// blocking (§5.2): the driver calls this at the start of every step
    /// and before every `harness.exec.start` decision, so the journal
    /// says a process ended before anything acts on the assumption it
    /// runs. A collected id keeps its child, so its undelivered output
    /// stays readable; it stops holding ports.
    pub fn poll(&mut self) -> Vec<BgExit> {
        let mut exits = Vec::new();
        let ids: Vec<u32> = self
            .book
            .entries
            .iter()
            .filter(|e| e.state == BgState::Running)
            .map(|e| e.id)
            .collect();
        for id in ids {
            let Some(child) = self.book.children.get_mut(&id) else {
                continue;
            };
            let Some(exit) = child.try_status() else {
                continue;
            };
            let totals = child.totals();
            if let Some(e) = self.book.entry_mut(id) {
                e.state = BgState::Exited;
                e.end = Some((end_of(&exit.status), cleanup_of(&exit.domain)));
            }
            exits.push(BgExit {
                id,
                end: end_of(&exit.status),
                cleanup: cleanup_of(&exit.domain),
                out_total: totals.out_total,
                err_total: totals.err_total,
                out_sha: totals.out_sha,
                err_sha: totals.err_sha,
            });
        }
        exits
    }

    /// Stop live ids, without the tool call (§5.1): the turn-scoped ones
    /// when the turn ends (`turn_only`), every one at the run's, the
    /// session's or the sandbox's end. Each child's control pipe closes
    /// and the sandbox sweeps its kill domain; the id ends `stopped` with
    /// the recorded end. An unconfirmed sweep travels back in the exit, so
    /// the driver stops the rest and the run with it.
    pub fn stop_live(&mut self, turn_only: bool) -> Vec<BgExit> {
        let mut exits = Vec::new();
        let ids: Vec<u32> = self
            .book
            .entries
            .iter()
            .filter(|e| e.state == BgState::Running && (!turn_only || e.scope == BgScope::Turn))
            .map(|e| e.id)
            .collect();
        for id in ids {
            let Some(child) = self.book.children.remove(&id) else {
                continue;
            };
            // The totals before the stop consumes the child: the streams'
            // whole size and digests are what the journal commits to.
            let totals = child.totals();
            let exit = child.stop();
            let end = end_of(&exit.status);
            let cleanup = cleanup_of(&exit.domain);
            if let Some(e) = self.book.entry_mut(id) {
                e.state = BgState::Stopped;
                e.end = Some((end, cleanup));
            }
            exits.push(BgExit {
                id,
                end,
                cleanup,
                out_total: totals.out_total,
                err_total: totals.err_total,
                out_sha: totals.out_sha,
                err_sha: totals.err_sha,
            });
        }
        exits
    }
}

/// One background process the driver observed to end, or stopped, outside
/// the tool calls (P-36 §5.1/§5.2): the id, how it ended, whether its kill
/// domain is confirmed swept, and the streams' totals and whole-stream
/// digests — exactly what a `BgStopped` record carries beside `reason`,
/// which the driver chooses (§10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgExit {
    /// The process id.
    pub id: u32,
    /// How it ended (the journal's `end` object, as exec_fields' end).
    pub end: ExecEnd,
    /// Whether the sweep is confirmed.
    pub cleanup: ExecCleanup,
    /// The stdout stream's whole size.
    pub out_total: u64,
    /// The stderr stream's whole size.
    pub err_total: u64,
    /// SHA-256 of the whole stdout stream.
    pub out_sha: Digest,
    /// SHA-256 of the whole stderr stream.
    pub err_sha: Digest,
}

/// The check results of one start's refusal order (§3), before any spawn.
/// Pure over the manager's state, so every refusal is testable without a
/// process.
#[derive(Debug)]
struct StartPlan {
    id: u32,
    program: PathBuf,
    name: String,
    cwd: PathBuf,
    ports: Vec<u16>,
    lan: Vec<u16>,
    scope: BgScope,
    lifetime_s: u32,
}

impl StartPlan {
    /// Walk the refusal order (§3) over parsed args and the manager's
    /// state. `parse` produced the argv/cwd pair; everything past it runs
    /// here. The port stage needs the grants and the persist flag from the
    /// tool, so they come in as a tuple.
    #[allow(clippy::too_many_arguments)]
    fn plan(
        book: &BgBook,
        pinned: &Pinned,
        root: &Path,
        persist: bool,
        port_grants: &[u16],
        lan_grants: &[u16],
        wall_remaining: Option<Duration>,
        argv: &[String],
        cwd_arg: Option<&str>,
        ports_arg: Option<Vec<u16>>,
        scope_arg: Option<BgScope>,
        lifetime_arg: Option<u32>,
    ) -> Result<StartPlan, Out> {
        // (1) The program, by name, on the allowlist (INV-13's in-process
        // half; policy refused first — defence in depth), and cwd by the
        // workspace rule.
        let Some(name) = argv.first() else {
            return Err(err(code::BAD_ARGS, "argv must name a program"));
        };
        let Some(program) = pinned.programs().get(name) else {
            return Err(err(
                code::EXEC_NOT_ALLOWED,
                "argv[0] is not a program this task allows",
            ));
        };
        let cwd = resolve_cwd(root, cwd_arg)?;
        // (3) The limits: live ids, then starts this run.
        book.start_fits()?;
        // (4) The ports: each in the task's grant, none held by a live id,
        // no duplicates, at most PORTS_PER_START (the sandbox checks the
        // rest; defence in depth here).
        let mut ports = Vec::new();
        if let Some(given) = ports_arg {
            if given.len() > PORTS_PER_START {
                return Err(err(code::BAD_ARGS, "a start may bind at most 4 ports"));
            }
            let mut seen = BTreeSet::new();
            for p in given {
                if p < PORT_MIN {
                    return Err(err(
                        code::BG_PORT_UNGRANTED,
                        "ports start at 1024 (PORT_MIN)",
                    ));
                }
                if !port_grants.contains(&p) {
                    return Err(err(
                        code::BG_PORT_UNGRANTED,
                        "the port is not in the task's grant",
                    ));
                }
                if !seen.insert(p) {
                    return Err(err(code::BAD_ARGS, "the same port appears twice"));
                }
                if book.held_ports().contains(&p) {
                    return Err(err(
                        code::BG_PORT_HELD,
                        "the port is held by another live background process",
                    ));
                }
                ports.push(p);
            }
        }
        let lan: Vec<u16> = ports
            .iter()
            .copied()
            .filter(|p| lan_grants.contains(p))
            .collect();
        // (5) The scope: a session-scoped process exists only under
        // `bg.persist` (§3).
        let scope = scope_arg.unwrap_or(BgScope::Turn);
        if scope == BgScope::Session && !persist {
            return Err(err(
                code::BG_SCOPE_REFUSED,
                "scope \"session\" needs the run's bg.persist header",
            ));
        }
        // The lifetime: 1..=BG_LIFETIME_MAX seconds, never past the run's
        // wall clock remaining (§3).
        let mut lifetime_s = lifetime_arg.unwrap_or(BG_LIFETIME_DEFAULT);
        if let Some(left) = wall_remaining {
            let cap = u32::try_from(left.as_secs()).unwrap_or(u32::MAX);
            lifetime_s = lifetime_s.min(cap.max(1));
        }
        Ok(StartPlan {
            id: book.next_id(),
            program: program.clone(),
            name: name.clone(),
            cwd,
            ports,
            lan,
            scope,
            lifetime_s,
        })
    }
}

/// The `ready` arguments: exactly one of a port or a text needle (§3).
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReadyArg {
    Port(u16),
    Text(String),
}

/// Parse the start's `ready` object (§3): at most one of `port` or
/// `text`, the text at most 256 bytes.
fn parse_ready(args: &Value) -> Result<Option<ReadyArg>, Out> {
    let Some(r) = args.get("ready") else {
        return Ok(None);
    };
    let o = r
        .as_object()
        .ok_or_else(|| err(code::BAD_ARGS, "ready must be an object"))?;
    let port = o.get("port");
    let text = o.get("text");
    match (port, text) {
        (Some(p), None) => Ok(Some(ReadyArg::Port(
            p.as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .filter(|n| *n >= PORT_MIN)
                .ok_or_else(|| err(code::BG_BAD_READY, "ready.port must be a granted port"))?,
        ))),
        (None, Some(t)) => {
            let s = t
                .as_str()
                .ok_or_else(|| err(code::BG_BAD_READY, "ready.text must be a string"))?;
            if s.is_empty() || s.len() > 256 {
                return Err(err(code::BG_BAD_READY, "ready.text must be 1..=256 bytes"));
            }
            Ok(Some(ReadyArg::Text(s.to_owned())))
        }
        (Some(_), Some(_)) => Err(err(
            code::BG_BAD_READY,
            "ready takes a port or a text needle, not both",
        )),
        (None, None) => Err(err(
            code::BG_BAD_READY,
            "ready takes a port or a text needle",
        )),
    }
}

/// Parse the start's port list (§3): at most 4, each at least PORT_MIN.
fn parse_ports(args: &Value) -> Result<Option<Vec<u16>>, Out> {
    let Some(v) = args.get("ports") else {
        return Ok(None);
    };
    let items = v
        .as_array()
        .ok_or_else(|| err(code::BAD_ARGS, "ports must be a list of port numbers"))?;
    let mut ports = Vec::with_capacity(items.len());
    for p in items {
        let p = p
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| err(code::BAD_ARGS, "ports must be a list of port numbers"))?;
        ports.push(p);
    }
    Ok(Some(ports))
}

/// Parse the start's scope (§3).
fn parse_scope(args: &Value) -> Result<Option<BgScope>, Out> {
    match args.get("scope") {
        None => Ok(None),
        Some(Value::String(s)) => match s.as_str() {
            "turn" => Ok(Some(BgScope::Turn)),
            "session" => Ok(Some(BgScope::Session)),
            _ => Err(err(code::BAD_ARGS, "scope must be \"turn\" or \"session\"")),
        },
        Some(_) => Err(err(code::BAD_ARGS, "scope must be \"turn\" or \"session\"")),
    }
}

/// How a read's wait ended.
enum Waited {
    /// New bytes arrived (or none were asked): deliver.
    Bytes,
    /// The process ended while waiting: its end is recorded.
    Ended(ExecEnd, ExecCleanup),
    /// The wait ran out with nothing new.
    Quiet,
}

/// The bounded wait (§3.2): poll for new bytes past `since` on either
/// stream, and for the process's end, until `until`. New bytes win; the
/// end wins over quiet.
fn wait_bytes_or_end(
    tools: &mut BgTools<'_>,
    id: u32,
    since_out: u64,
    since_err: u64,
    until: Instant,
) -> Waited {
    loop {
        if let Some(child) = tools.book.children.get(&id) {
            let out = child.read(Stream::Out, since_out, 1, Mode::Next);
            let errb = child.read(Stream::Err, since_err, 1, Mode::Next);
            if out.to > since_out || errb.to > since_err {
                return Waited::Bytes;
            }
        }
        if let Some(child) = tools.book.children.get_mut(&id) {
            if let Some(exit) = child.try_status() {
                return Waited::Ended(end_of(&exit.status), cleanup_of(&exit.domain));
            }
        }
        if Instant::now() >= until {
            return Waited::Quiet;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

impl<'a> BgTools<'a> {
    /// `harness.exec.start` (§3): the refusal order, then the spawn, then
    /// the `ready` wait, then the result with the first output.
    fn start(&mut self, args: &Value, ctx: &InvokeCtx<'_>) -> Out {
        match self.try_start(args, ctx) {
            Ok(o) | Err(o) => o,
        }
    }

    fn try_start(&mut self, args: &Value, ctx: &InvokeCtx<'_>) -> Result<Out, Out> {
        // (1) The program and cwd.
        let (argv, cwd_arg) = parse_argv(args)?;
        let ports_arg = parse_ports(args)?;
        let scope_arg = parse_scope(args)?;
        let lifetime_arg = match args.get("lifetime_secs") {
            None => None,
            Some(v) => Some(
                v.as_u64()
                    .filter(|n| (1..=u64::from(BG_LIFETIME_MAX)).contains(n))
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| err(code::BAD_ARGS, "lifetime_secs must be 1..=14400"))?,
            ),
        };
        let ready = parse_ready(args)?;
        let ready_secs = arg_u64(args, "ready_secs", 10, 1, u64::from(BG_READY_MAX))? as u32;
        let plan = StartPlan::plan(
            &self.book,
            &self.pinned,
            &self.root,
            self.persist,
            &self.port_grants,
            &self.lan_grants,
            self.wall_remaining,
            &argv,
            cwd_arg,
            ports_arg,
            scope_arg,
            lifetime_arg,
        )?;
        // (6) The witness must cover the background cases — and the port
        // cases when ports are asked (§3).
        if self.witness.covers(BG_CASES).is_err() {
            return Err(err(
                code::BG_WITNESS_REFUSED,
                "this host's sandbox witness does not cover the background-process cases",
            ));
        }
        if !plan.ports.is_empty() && self.witness.covers(PORTS_CASES).is_err() {
            return Err(err(
                code::BG_WITNESS_REFUSED,
                "this host's sandbox witness does not cover the loopback-port cases",
            ));
        }
        // (7) The host check: bind and release each port (§3, a measured
        // refusal).
        for p in &plan.ports {
            if let Err(e) = host_binds(*p) {
                return Err(err(
                    code::BG_PORT_BUSY,
                    &format!("the harness could not bind port {p}: {e}"),
                ));
            }
        }
        // (8) The spawn, live, under the run's witness.
        let lifetime = Duration::from_secs(u64::from(plan.lifetime_s));
        let network = if plan.ports.is_empty() {
            Network::None
        } else {
            Network::Loopback {
                bind: plan.ports.clone(),
                connect: Vec::new(),
                lan: plan.lan.clone(),
            }
        };
        let spec = ConfinedSpec {
            argv: std::iter::once(plan.program.clone().into_os_string())
                .chain(argv.iter().skip(1).map(OsString::from))
                .collect(),
            cwd: plan.cwd.clone(),
            env: env_for(
                &self.scratch,
                self.pinned.programs(),
                &self.pinned.spec().env,
            ),
            read_only: self.pinned.spec().read_only.clone(),
            read_write: vec![self.root.clone(), self.scratch.dir().to_path_buf()],
            protected: self.protected_dirs.clone(),
            network,
            limits: Limits {
                wall: lifetime,
                cpu: Some(self.limits.cpu),
                file_size: Some(self.limits.file_size),
                memory: Some(self.limits.memory),
                processes: Some(self.limits.processes),
                output_bytes: self.limits.output_bytes,
            },
        };
        // The id is consumed by the attempt: a spawn that fails journals
        // its id with state `exec_failed` (§10.2).
        let id = plan.id;
        self.book.started += 1;
        let child = match self.confinement.spawn_live(
            &spec,
            &self.witness,
            &LiveOpts {
                ring_bytes: BG_RING_BYTES,
                lifetime,
                lease: None,
            },
        ) {
            Ok(ch) => ch,
            Err(e) => {
                let rec = BgRecord::Start(BgStart {
                    id,
                    state: BgStartState::ExecFailed,
                    ports: plan.ports,
                    lan: plan.lan,
                    scope: plan.scope,
                    lifetime_s: plan.lifetime_s,
                    ready: None,
                });
                let mut out = spawn_err(&e, id);
                out.bg = Some(Box::new(rec));
                return Ok(out);
            }
        };
        self.book.entries.push(BgEntry {
            id,
            program: plan.name.clone(),
            ports: plan.ports.clone(),
            lan: plan.lan.clone(),
            scope: plan.scope,
            lifetime_s: plan.lifetime_s,
            start_step: ctx.step,
            state: BgState::Running,
            end: None,
            out_cursor: 0,
            err_cursor: 0,
        });
        self.book.children.insert(id, child);
        // (9) The `ready` wait (§3): a connect to the port, or the needle
        // in either stream. Not met is not an error.
        let ready_out = match &ready {
            None => None,
            Some(ReadyArg::Port(p)) => {
                let until = ready_deadline(ready_secs, ctx.deadline);
                let (met, waited_ms) = wait_port(*p, until);
                Some(BgReady {
                    kind: BgReadyKind::Port,
                    met,
                    waited_ms,
                })
            }
            Some(ReadyArg::Text(needle)) => {
                let until = ready_deadline(ready_secs, ctx.deadline);
                let child = self.book.children.get(&id);
                let (met, waited_ms) = match child {
                    Some(c) => wait_text(c, needle, until),
                    None => (false, 0),
                };
                Some(BgReady {
                    kind: BgReadyKind::Text,
                    met,
                    waited_ms,
                })
            }
        };
        // The first output (§3.2): the recent tail, capped, without
        // moving the delivered cursors.
        let peek = self.peek(id);
        let ports_shown = plan
            .ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let rec = BgRecord::Start(BgStart {
            id,
            state: BgStartState::Running,
            ports: plan.ports,
            lan: plan.lan,
            scope: plan.scope,
            lifetime_s: plan.lifetime_s,
            ready: ready_out,
        });
        let mut text = if ports_shown.is_empty() {
            format!(
                "started background process {id} (program {}, stops at the end of this {} or after {} s)\n",
                plan.name,
                scope_word(plan.scope),
                plan.lifetime_s
            )
        } else {
            format!(
                "started background process {id} (program {}, ports {ports_shown} loopback, stops at the end of this {} or after {} s)\n",
                plan.name,
                scope_word(plan.scope),
                plan.lifetime_s
            )
        };
        if let Some(r) = ready_out {
            text.push_str(&format!(
                "ready {}: {} (waited {} ms)\n",
                match r.kind {
                    BgReadyKind::Port => "port",
                    BgReadyKind::Text => "text",
                },
                if r.met { "met" } else { "not met" },
                r.waited_ms
            ));
        }
        text.push_str(&peek);
        Ok(Out {
            status: ToolStatus::Ok,
            text,
            read: None,
            bg: Some(Box::new(rec)),
        })
    }

    /// The recent output of both streams (§3.2 tail, capped), for a
    /// start's result. The delivered cursors stay where they were.
    fn peek(&self, id: u32) -> String {
        let (Some(_entry), Some(child)) = (self.book.entry(id), self.book.children.get(&id)) else {
            return String::new();
        };
        let totals = child.totals();
        let w = render_windows(
            child,
            totals,
            0,
            0,
            Mode::Tail,
            (BG_READ_MAX / 4 * 3, BG_READ_MAX),
        );
        sections(&w)
    }

    /// `harness.exec.read` (§3.2): the list, or one id's windows.
    fn read(&mut self, args: &Value, ctx: &InvokeCtx<'_>) -> Out {
        match self.try_read(args, ctx) {
            Ok(o) | Err(o) => o,
        }
    }

    fn try_read(&mut self, args: &Value, ctx: &InvokeCtx<'_>) -> Result<Out, Out> {
        let mode = match args.get("mode") {
            None => BgReadMode::Tail,
            Some(Value::String(s)) => match s.as_str() {
                "next" => BgReadMode::Next,
                "tail" => BgReadMode::Tail,
                _ => return Err(err(code::BAD_ARGS, "mode must be \"next\" or \"tail\"")),
            },
            Some(_) => return Err(err(code::BAD_ARGS, "mode must be \"next\" or \"tail\"")),
        };
        let max_bytes =
            arg_u64(args, "max_bytes", BG_READ_MAX as u64, 1, BG_READ_MAX as u64)? as usize;
        let wait_secs = arg_u64(args, "wait_secs", 0, 0, u64::from(BG_READ_WAIT_MAX))? as u32;
        match args.get("id") {
            None | Some(Value::Null) => self.list(),
            Some(v) => {
                let id = v
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| err(code::BAD_ARGS, "id must be a process id"))?;
                self.read_one(id, mode, args, max_bytes, wait_secs, ctx)
            }
        }
    }

    /// Every id, with its state and undelivered bytes (§3.2).
    fn list(&self) -> Result<Out, Out> {
        let mut items = Vec::new();
        let mut text = String::from("background processes:\n");
        for e in &self.book.entries {
            let (pending_out, pending_err) = self.pending(e.id);
            items.push(BgListItem {
                id: e.id,
                state: e.state,
                ports: e.ports.clone(),
                pending_out,
                pending_err,
            });
            let ports = if e.ports.is_empty() {
                String::new()
            } else {
                format!(
                    ", ports {}",
                    e.ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            text.push_str(&format!(
                "{} {} ({}{}, {}, started at step {}, pending {} out / {} err)\n",
                e.id,
                e.program,
                state_word(e.state),
                ports,
                scope_word(e.scope),
                e.start_step,
                pending_out,
                pending_err
            ));
        }
        if items.is_empty() {
            text = "no background processes this run\n".into();
        }
        Ok(Out {
            status: ToolStatus::Ok,
            text,
            read: None,
            bg: Some(Box::new(BgRecord::List(items))),
        })
    }

    /// Bytes written but not yet delivered (§10.2).
    fn pending(&self, id: u32) -> (u64, u64) {
        let Some(e) = self.book.entry(id) else {
            return (0, 0);
        };
        let Some(c) = self.book.children.get(&id) else {
            return (0, 0);
        };
        let t = c.totals();
        (
            t.out_total.saturating_sub(e.out_cursor),
            t.err_total.saturating_sub(e.err_cursor),
        )
    }

    fn read_one(
        &mut self,
        id: u32,
        mode: BgReadMode,
        args: &Value,
        max_bytes: usize,
        wait_secs: u32,
        ctx: &InvokeCtx<'_>,
    ) -> Result<Out, Out> {
        let Some(entry) = self.book.entry(id) else {
            return Err(err(
                code::BG_UNKNOWN_ID,
                "no background process with that id this run",
            ));
        };
        if matches!(entry.state, BgState::Stopped | BgState::Lost) {
            let ended = entry
                .end
                .unwrap_or((ExecEnd::Unknown, ExecCleanup::Confirmed { kills: 0 }));
            return Err(ended_out(id, ended));
        }
        let since_out = arg_u64(args, "since_out", entry.out_cursor, 0, u64::MAX)?;
        let since_err = arg_u64(args, "since_err", entry.err_cursor, 0, u64::MAX)?;
        let (mut state, mut ended) = (entry.state, entry.end);
        // The bounded wait (§3.2): until new bytes, the process's end, or
        // the wait runs out. Charged as tool time, under the call's
        // deadline.
        if wait_secs > 0 {
            let until = ready_deadline(wait_secs, ctx.deadline);
            match wait_bytes_or_end(self, id, since_out, since_err, until) {
                Waited::Ended(end, cleanup) => {
                    ended = Some((end, cleanup));
                    state = BgState::Exited;
                    if let Some(e) = self.book.entry_mut(id) {
                        e.state = BgState::Exited;
                        e.end = Some((end, cleanup));
                    }
                }
                // The bytes came; give the stub a moment to hand the
                // harness its exit report, so the read says so when the
                // process ended right behind its output.
                _ => {
                    let settle = Instant::now() + Duration::from_millis(200);
                    while Instant::now() < settle {
                        match self.try_collect(id) {
                            Some(exit) => {
                                let end = end_of(&exit.status);
                                let cleanup = cleanup_of(&exit.domain);
                                ended = Some((end, cleanup));
                                state = BgState::Exited;
                                if let Some(e) = self.book.entry_mut(id) {
                                    e.state = BgState::Exited;
                                    e.end = Some((end, cleanup));
                                }
                                break;
                            }
                            None => std::thread::sleep(Duration::from_millis(20)),
                        }
                    }
                }
            }
        } else if let Some(exit) = self.try_collect(id) {
            let end = end_of(&exit.status);
            let cleanup = cleanup_of(&exit.domain);
            state = BgState::Exited;
            ended = Some((end, cleanup));
            if let Some(e) = self.book.entry_mut(id) {
                e.state = BgState::Exited;
                e.end = Some((end, cleanup));
            }
        }
        let Some(child) = self.book.children.get(&id) else {
            return Err(err(
                code::BG_UNKNOWN_ID,
                "no background process with that id this run",
            ));
        };
        let totals = child.totals();
        // Three quarters to stdout; the rest — including any unused
        // share — to stderr (§3.2).
        let w = render_windows(
            child,
            totals,
            since_out,
            since_err,
            match mode {
                BgReadMode::Next => Mode::Next,
                BgReadMode::Tail => Mode::Tail,
            },
            (max_bytes / 4 * 3, max_bytes),
        );
        // The delivered cursor becomes the window's `to` (§3.2).
        if let Some(e) = self.book.entry_mut(id) {
            e.out_cursor = w.out.to;
            e.err_cursor = w.err.to;
        }
        let rec = BgRecord::Read(BgRead {
            id,
            mode,
            state,
            out: w.out,
            err: w.err,
            ended,
        });
        let mut text = format!("background process {id} ({})\n", state_word(state));
        text.push_str(&sections(&w));
        Ok(Out {
            status: ToolStatus::Ok,
            text,
            read: None,
            bg: Some(Box::new(rec)),
        })
    }

    /// Collect an exited child without blocking: `Some` when the sandbox
    /// has its exit now.
    fn try_collect(&mut self, id: u32) -> Option<ConfinedExit> {
        let child = self.book.children.get_mut(&id)?;
        child.try_status()
    }

    /// `harness.exec.stop` (§3): sweep, report, refuse what already ended.
    fn stop(&mut self, args: &Value) -> Out {
        match self.try_stop(args) {
            Ok(o) | Err(o) => o,
        }
    }

    fn try_stop(&mut self, args: &Value) -> Result<Out, Out> {
        let id = match args.get("id") {
            Some(v) => v
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| err(code::BAD_ARGS, "id must be a process id"))?,
            None => return Err(err(code::BAD_ARGS, "stop needs the id to stop")),
        };
        let Some(entry) = self.book.entry(id) else {
            return Err(err(
                code::BG_UNKNOWN_ID,
                "no background process with that id this run",
            ));
        };
        if matches!(
            entry.state,
            BgState::Stopped | BgState::Lost | BgState::Exited
        ) {
            let ended = entry
                .end
                .unwrap_or((ExecEnd::Unknown, ExecCleanup::Unconfirmed));
            return Err(ended_out(id, ended));
        }
        let cursors = (entry.out_cursor, entry.err_cursor);
        // The not-yet-delivered output first (the child is consumed by the
        // stop): tail mode from the delivered cursors, capped (§3).
        let (w, totals) = {
            let child = self.book.children.get(&id);
            let Some(child) = child else {
                return Err(err(
                    code::BG_UNKNOWN_ID,
                    "no background process with that id this run",
                ));
            };
            let t = child.totals();
            let w = render_windows(
                child,
                t.clone(),
                cursors.0,
                cursors.1,
                Mode::Tail,
                (BG_READ_MAX / 4 * 3, BG_READ_MAX),
            );
            (w, t)
        };
        let Some(child) = self.book.children.remove(&id) else {
            return Err(err(
                code::BG_UNKNOWN_ID,
                "no background process with that id this run",
            ));
        };
        let exit = child.stop();
        let end = end_of(&exit.status);
        let cleanup = cleanup_of(&exit.domain);
        if let Some(e) = self.book.entry_mut(id) {
            e.state = BgState::Stopped;
            e.end = Some((end, cleanup));
        }
        let rec = BgRecord::Stop(BgStop {
            id,
            end,
            cleanup,
            out: w.out,
            err: w.err,
            out_total: totals.out_total,
            err_total: totals.err_total,
            out_sha: totals.out_sha,
            err_sha: totals.err_sha,
        });
        let mut text = format!("background process {id} stopped ({})\n", end_word(end));
        match cleanup {
            ExecCleanup::Confirmed { kills } => {
                text.push_str(&format!("cleanup: confirmed ({kills} killed)\n"));
            }
            ExecCleanup::Unconfirmed => text.push_str(
                "cleanup: unconfirmed — a process may have survived; the run stops here\n",
            ),
        }
        text.push_str(&sections(&w));
        Ok(Out {
            status: ToolStatus::Ok,
            text,
            read: None,
            bg: Some(Box::new(rec)),
        })
    }
}

// ---- Shared seams ----------------------------------------------------------

/// The `ready` deadline: the asked seconds, never past the call's.
fn ready_deadline(secs: u32, call_deadline: Instant) -> Instant {
    let at = Instant::now() + Duration::from_secs(u64::from(secs));
    at.min(call_deadline)
}

/// Wait for a TCP listener on loopback `port` (§3, ready): connect, then
/// close. Returns whether it was met and how long the harness waited.
fn wait_port(port: u16, until: Instant) -> (bool, u64) {
    let started = Instant::now();
    loop {
        if port_ready(port) {
            return (true, ms_since(started));
        }
        if Instant::now() >= until {
            return (false, ms_since(started));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Wait for `needle` in either stream of a live child (§3, ready). The
/// bytes stay in the streams: the wait peeks, it does not deliver.
fn wait_text(child: &ConfinedChild, needle: &str, until: Instant) -> (bool, u64) {
    let started = Instant::now();
    let needle = needle.as_bytes();
    loop {
        let out = child.read(Stream::Out, 0, 4096, Mode::Tail);
        let errb = child.read(Stream::Err, 0, 4096, Mode::Tail);
        if contains(&out.bytes, needle) || contains(&errb.bytes, needle) {
            return (true, ms_since(started));
        }
        if Instant::now() >= until {
            return (false, ms_since(started));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `haystack.windows(needle)` over the peeked bytes.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn ms_since(at: Instant) -> u64 {
    u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// A spawn that failed: the id is spent, the program never ran (§10.2).
fn spawn_err(e: &SpawnError, id: u32) -> Out {
    let why = match e {
        SpawnError::Spec(_) => "the sandbox refused the process's setup",
        SpawnError::WrongWitness | SpawnError::Io(_) => "the sandbox could not start it",
    };
    Out {
        status: ToolStatus::Error {
            code: code::EXEC_SPAWN,
        },
        text: format!("error: background process {id}: {why}, so nothing is running"),
        read: None,
        bg: None,
    }
}

/// `ChildStatus` as the journal's end (§10.1, exec_fields' end).
fn end_of(s: &ChildStatus) -> ExecEnd {
    match s {
        ChildStatus::Exited(c) => ExecEnd::Exited(*c),
        ChildStatus::Signaled(n) => ExecEnd::Signaled(*n),
        ChildStatus::TimedOut => ExecEnd::TimedOut,
        ChildStatus::ProcessLimit => ExecEnd::ProcessLimit,
        ChildStatus::ExecFailed => ExecEnd::ExecFailed,
        ChildStatus::Unknown => ExecEnd::Unknown,
    }
}

/// The sandbox's domain report as the journal's cleanup.
fn cleanup_of(d: &DomainCleanup) -> ExecCleanup {
    match d {
        DomainCleanup::Confirmed { kills } => ExecCleanup::Confirmed { kills: *kills },
        DomainCleanup::Unconfirmed(_) => ExecCleanup::Unconfirmed,
    }
}

/// The deterministic refusal repeating a recorded end (§3).
fn ended_out(id: u32, ended: (ExecEnd, ExecCleanup)) -> Out {
    let (end, cleanup) = ended;
    let mut text = format!(
        "error: background process {id} already ended ({})\n",
        end_word(end)
    );
    match cleanup {
        ExecCleanup::Confirmed { kills } => {
            text.push_str(&format!("cleanup was confirmed ({kills} killed)\n"))
        }
        ExecCleanup::Unconfirmed => text.push_str("cleanup was not confirmed\n"),
    }
    Out {
        status: ToolStatus::Error {
            code: code::BG_ALREADY_ENDED,
        },
        text,
        read: None,
        bg: None,
    }
}

fn end_word(e: ExecEnd) -> &'static str {
    match e {
        ExecEnd::Exited(_) => "exited",
        ExecEnd::Signaled(_) => "signaled",
        ExecEnd::TimedOut => "timed out at its lifetime",
        ExecEnd::ProcessLimit => "swept at the process cap",
        ExecEnd::ExecFailed => "never started (the sandbox refused it)",
        ExecEnd::Unknown => "ended without a status the harness can trust",
    }
}

fn state_word(s: BgState) -> &'static str {
    match s {
        BgState::Running => "running",
        BgState::Exited => "exited",
        BgState::Stopped => "stopped",
        BgState::Lost => "lost",
    }
}

fn scope_word(s: BgScope) -> &'static str {
    match s {
        BgScope::Turn => "turn",
        BgScope::Session => "run",
    }
}

/// Both streams' delivered windows and bytes, computed and delivered by
/// the sandbox's live ring (§3.2): the window arithmetic first, then the
/// bytes, with the stderr cap given what stdout delivered (unused share
/// flows).
struct Windows {
    out: BgWindow,
    err: BgWindow,
    out_bytes: Vec<u8>,
    err_bytes: Vec<u8>,
}

fn render_windows(
    child: &ConfinedChild,
    totals: StreamTotals,
    since_out: u64,
    since_err: u64,
    mode: Mode,
    caps: (usize, usize),
) -> Windows {
    let out = child.read(Stream::Out, since_out, caps.0, mode);
    let err_left = caps.1.saturating_sub(out.bytes.len()).max(1);
    let errb = child.read(Stream::Err, since_err, err_left, mode);
    let w = |since: u64, c: &Chunk, total: u64, sha: Digest| BgWindow {
        since,
        from: c.from,
        to: c.to,
        dropped: c.dropped,
        skipped: c.skipped,
        total,
        sha,
    };
    Windows {
        out: w(since_out, &out, totals.out_total, totals.out_sha),
        err: w(since_err, &errb, totals.err_total, totals.err_sha),
        out_bytes: out.bytes,
        err_bytes: errb.bytes,
    }
}

/// The read result's body: two labelled sections, each with its
/// drop/skip markers when non-zero, then the bytes, lossy UTF-8 (§3.2).
fn sections(w: &Windows) -> String {
    let mut text = String::new();
    let one = |name: &str, win: &BgWindow, bytes: &[u8], text: &mut String| {
        text.push_str(&format!(
            "{name} (bytes {}..{} of {}):\n",
            win.from, win.to, win.total
        ));
        if win.dropped > 0 {
            text.push_str(&format!("[{} bytes dropped]\n", win.dropped));
        }
        if win.skipped > 0 {
            text.push_str(&format!("[{} bytes skipped]\n", win.skipped));
        }
        if bytes.is_empty() {
            text.push_str("(empty)\n");
        } else {
            text.push_str(&String::from_utf8_lossy(bytes));
            if !bytes.ends_with(b"\n") {
                text.push('\n');
            }
        }
    };
    one("stdout", &w.out, &w.out_bytes, &mut text);
    one("stderr", &w.err, &w.err_bytes, &mut text);
    text
}

impl ToolProvider for BgTools<'_> {
    fn namespace(&self) -> &ProviderName {
        &self.ns
    }

    fn serves(&self, capability: &str) -> bool {
        matches!(capability, EXEC_START_ID | EXEC_READ_ID | EXEC_STOP_ID)
    }

    fn invoke(
        &mut self,
        call: Journaled<Authorized<Call>>,
        ctx: &InvokeCtx<'_>,
    ) -> Result<ToolResult, ToolError> {
        let c = call.call().call();
        let cap = c.capability.as_str();
        if !matches!(cap, EXEC_START_ID | EXEC_READ_ID | EXEC_STOP_ID) {
            return Ok(refused(cap, RefusalKind::UnknownCapability));
        }
        if Instant::now() >= ctx.deadline {
            return Ok(refused(cap, RefusalKind::DeadlinePassed));
        }
        // INV-42 (P-36f): without the confined file helper there is no
        // kernel-enforced view for a live child; nothing here starts.
        if !self.confined_files {
            let out = err(
                code::BG_FILE_OPS,
                "background processes need this run's confined file helper, which is not active",
            );
            return Ok(finish(cap, out));
        }
        let out = match cap {
            EXEC_START_ID => self.start(&c.args, ctx),
            EXEC_READ_ID => self.read(&c.args, ctx),
            _ => self.stop(&c.args),
        };
        Ok(finish(cap, out))
    }
}

#[cfg(test)]
mod tests;
