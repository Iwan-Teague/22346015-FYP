//! The background-process tools through the real seam and the real
//! sandbox (P-36 §3, macOS): policy authorises each call, the journal
//! makes the intent durable, then `BgTools` starts, reads and stops live
//! confined children. Every program is `/usr/bin/perl` with a short,
//! self-limiting script, like the command runner's tests. The pure
//! refusal arithmetic (limits, held ports) is tested without any process.

#![cfg(target_os = "macos")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::bg::{BgBook, BgEntry};
use crate::bg::{BgReadMode, BgRecord, BgScope, BgStartState, BgState, BG_MAX_LIVE, BG_MAX_STARTS};
use crate::builtin::code;
use crate::exec::{ExecProgram, ExecSpec, Pinned};
use crate::{BgTools, InvokeCtx, ReadLog, ToolProvider, ToolResult, ToolStatus};
use harness_core::RunId;
use harness_journal::testing::{FaultFile, FaultPlan, MemBlobs};
use harness_journal::{Clock, Event, EventKind, Header, Ident, JournalWriter};
use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{builtin, SemVer, ValidationContext};
use harness_policy::{
    Call, Session, SessionKind, SessionSpec, UserPolicy, WorkspaceDecl, EXEC_READ_ID,
    EXEC_START_ID, EXEC_STOP_ID,
};
use harness_sandbox::{Confinement, SystemConfinement};
use serde_json::{json, Value};

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

fn witness() -> harness_sandbox::Conformed {
    static W: std::sync::OnceLock<harness_sandbox::Conformed> = std::sync::OnceLock::new();
    W.get_or_init(|| {
        SystemConfinement
            .require()
            .expect("require() passes on macOS")
    })
    .clone()
}

/// `root/ws` (the workspace) and `root/scratch`, canonical.
fn dirs(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "rh-bg-tools-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    for d in ["ws", "scratch"] {
        fs::create_dir_all(root.join(d)).unwrap();
    }
    let root = fs::canonicalize(root).unwrap();
    (root.join("ws"), root.join("scratch"), root)
}

fn spec() -> ExecSpec {
    ExecSpec {
        programs: vec![ExecProgram {
            name: "perl".into(),
            path: "/usr/bin/perl".into(),
        }],
        ..ExecSpec::default()
    }
}

struct Rig {
    w: JournalWriter<FaultFile, MemBlobs, Tick>,
    s: Session,
    t: BgTools<'static>,
    reads: ReadLog,
    step: u64,
    root: PathBuf,
}

impl Drop for Rig {
    fn drop(&mut self) {
        // Whatever the test left running is swept: stop every live id
        // through the tool itself so the sandbox domains empty.
        let ids: Vec<u32> = self.t.book.entries.iter().map(|e| e.id).collect();
        for id in ids {
            if self.t.book.entry(id).map(|e| e.state) == Some(BgState::Running) {
                let _ = self.call(EXEC_STOP_ID, json!({ "id": id }), Instant::now() + secs(10));
            }
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

impl Rig {
    fn new(name: &str) -> Self {
        let ctx = ValidationContext::new(
            SemVer {
                major: 0,
                minor: 0,
                patch: 1,
            },
            &[],
        )
        .unwrap();
        let reg = Registry::admit(vec![(builtin::manifest(&ctx).unwrap(), Tier::Builtin)]).unwrap();
        let s = Session::plan(
            &SessionSpec {
                grants: vec![
                    EXEC_START_ID.into(),
                    EXEC_READ_ID.into(),
                    EXEC_STOP_ID.into(),
                ],
                workspace: Some(WorkspaceDecl::default()),
                approver_present: false,
                personal_data_granted: false,
                conformed: true,
                // The session also allowlists `sh`, which the pinned set
                // does not: the provider refuses it on its own (defence
                // in depth), the way the command runner's tests do.
                exec_programs: vec!["perl".into(), "sh".into()],
                lan_ports: Vec::new(),
                read_window: None,
                kind: SessionKind::Coding,
                mode: harness_policy::SessionMode::Build,
            },
            &reg,
            &UserPolicy::new(&[], &[], &[EXEC_START_ID, EXEC_READ_ID, EXEC_STOP_ID]).unwrap(),
        )
        .unwrap();
        let w = JournalWriter::start(
            FaultFile::new(FaultPlan::default()),
            MemBlobs::default(),
            Tick(Cell::new(0)),
            RunId::new(1, [0; 10]),
            1,
            Header::new(Ident::of("0.0.1").unwrap()),
        )
        .unwrap();
        let (ws, scratch, root) = dirs(name);
        let t = BgTools::new(
            &ws,
            Pinned::check(&spec()).unwrap(),
            &scratch,
            &SystemConfinement,
            witness(),
        )
        .unwrap()
        .with_confined_files(true);
        Self {
            w,
            s,
            t,
            reads: ReadLog::default(),
            step: 0,
            root,
        }
    }

    fn call(&mut self, cap: &str, args: Value, deadline: Instant) -> ToolResult {
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
        self.t
            .invoke(
                j,
                &InvokeCtx {
                    step: self.step,
                    deadline,
                    reads: &self.reads,
                    egress: None,
                    bg_ports: &[],
                },
            )
            .unwrap()
    }

    fn start(&mut self, args: Value) -> ToolResult {
        self.call(EXEC_START_ID, args, Instant::now() + secs(30))
    }

    fn read(&mut self, args: Value) -> ToolResult {
        self.call(EXEC_READ_ID, args, Instant::now() + secs(30))
    }

    fn stop(&mut self, args: Value) -> ToolResult {
        self.call(EXEC_STOP_ID, args, Instant::now() + secs(30))
    }

    /// A long-lived sleeper: writes its pid, prints `text`, then sleeps.
    fn start_sleeper(&mut self, text: &str, sleep_s: u32) -> ToolResult {
        self.start(json!({
            "argv": ["perl", "-e",
                &format!("$| = 1; print qq{{{text}\\n}}; sleep {sleep_s};"),
                ],
            "lifetime_secs": 60,
        }))
    }
}

fn text(r: &ToolResult) -> String {
    String::from_utf8(r.output.inspect("test").clone()).unwrap()
}

fn bg(r: &ToolResult) -> &BgRecord {
    r.bg.as_ref().expect("a bg record")
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Wait until the child has written its first bytes (the stub flushes on
/// its own schedule).
fn wait_pending(r: &Rig, id: u32, min: u64, what: &str) {
    let deadline = Instant::now() + secs(10);
    loop {
        let (out, _) = r.t.pending(id);
        if out >= min {
            break;
        }
        assert!(Instant::now() < deadline, "{what} never landed");
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ---- Pure refusal arithmetic -----------------------------------------------

fn entry(id: u32, ports: &[u16], state: BgState) -> BgEntry {
    BgEntry {
        id,
        program: "perl".into(),
        ports: ports.to_vec(),
        lan: Vec::new(),
        scope: BgScope::Turn,
        lifetime_s: 1800,
        start_step: 1,
        state,
        end: None,
        out_cursor: 0,
        err_cursor: 0,
    }
}

#[test]
fn bg_start_refuses_over_max_live_and_max_starts() {
    // BG_MAX_LIVE live entries: the next start is refused on the live cap.
    let mut book = BgBook::default();
    for i in 1..=BG_MAX_LIVE as u32 {
        book.entries.push(entry(i, &[], BgState::Running));
        book.started = i;
    }
    assert_eq!(book.live(), BG_MAX_LIVE);
    let e = book.start_fits().unwrap_err();
    assert_eq!(
        e.status,
        ToolStatus::Error {
            code: code::BG_LIVE_LIMIT
        }
    );
    // An ended id frees a live slot but not a start slot...
    book.entries[0].state = BgState::Stopped;
    assert!(book.start_fits().is_ok());
    // ...until BG_MAX_STARTS starts were made.
    book.started = BG_MAX_STARTS;
    let e = book.start_fits().unwrap_err();
    assert_eq!(
        e.status,
        ToolStatus::Error {
            code: code::BG_START_LIMIT
        }
    );
    // Ids are sequential and never reused, however many ended.
    assert_eq!(book.next_id(), BG_MAX_STARTS + 1);
}

#[test]
fn bg_start_refuses_ungranted_or_held_port() {
    // Ungranted: no grants at all, so any port is refused.
    let mut book = BgBook::default();
    book.entries.push(entry(1, &[6000], BgState::Running));
    let argv = json!({ "argv": ["perl"] });
    let plan = crate::exec::parse_argv(&argv).unwrap();
    let pinned = Pinned::check(&spec()).unwrap();
    let ws = dirs("ports-refusal").0;
    let e = crate::bg::StartPlan::plan(
        &book,
        &pinned,
        &ws,
        false,
        &[],
        &[],
        None,
        &plan.0,
        plan.1,
        Some(vec![7000]),
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(
        e.status,
        ToolStatus::Error {
            code: code::BG_PORT_UNGRANTED
        }
    );
    // Held: the port a live id already holds is refused.
    let grants = [6000u16, 7000];
    let e = crate::bg::StartPlan::plan(
        &book,
        &pinned,
        &ws,
        false,
        &grants,
        &[],
        None,
        &["perl".to_string()],
        None,
        Some(vec![6000]),
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(
        e.status,
        ToolStatus::Error {
            code: code::BG_PORT_HELD
        }
    );
    // The same port when the holder ended is fine, and the held set is
    // exactly the live ids'.
    assert_eq!(book.held_ports(), vec![6000]);
    book.entries[0].state = BgState::Exited;
    assert!(book.held_ports().is_empty());
    let ok = crate::bg::StartPlan::plan(
        &book,
        &pinned,
        &ws,
        false,
        &grants,
        &[],
        None,
        &["perl".to_string()],
        None,
        Some(vec![6000]),
        None,
        None,
    )
    .unwrap();
    assert_eq!(ok.ports, vec![6000]);
    // Scope "session" without the run's persist header is refused.
    let e = crate::bg::StartPlan::plan(
        &book,
        &pinned,
        &ws,
        false,
        &grants,
        &[],
        None,
        &["perl".to_string()],
        None,
        None,
        Some(BgScope::Session),
        None,
    )
    .unwrap_err();
    assert_eq!(
        e.status,
        ToolStatus::Error {
            code: code::BG_SCOPE_REFUSED
        }
    );
}

// ---- Live through the real sandbox ------------------------------------------

#[test]
fn bg_start_returns_sequential_ids() {
    let mut r = Rig::new("sequential-ids");
    let a = r.start_sleeper("one", 30);
    let t = text(&a);
    assert_eq!(a.status, ToolStatus::Ok, "{t}");
    assert!(
        t.starts_with("started background process 1 (program perl,"),
        "{t}"
    );
    assert!(
        t.contains("stops at the end of this turn or after 60 s"),
        "{t}"
    );
    let b = r.start_sleeper("two", 30);
    assert!(
        text(&b).starts_with("started background process 2 (program perl,"),
        "{}",
        text(&b)
    );
    match bg(&a) {
        BgRecord::Start(s) => {
            assert_eq!(s.id, 1);
            assert_eq!(s.state, BgStartState::Running);
            assert_eq!(s.scope, BgScope::Turn);
            assert!(s.ports.is_empty());
        }
        other => panic!("a start record, got {other:?}"),
    }
}

#[test]
fn bg_start_refuses_program_not_on_allowlist() {
    let mut r = Rig::new("not-allowed");
    let res = r.start(json!({ "argv": ["sh", "-c", "sleep 1"] }));
    let t = text(&res);
    assert_eq!(
        res.status,
        ToolStatus::Error {
            code: code::EXEC_NOT_ALLOWED
        },
        "{t}"
    );
    assert!(
        res.bg.is_none(),
        "a refusal before the spawn journals no bg record"
    );
    // Nothing is live and no id was consumed.
    assert!(r.t.book.entries.is_empty());
    assert_eq!(r.t.book.started, 0);
}

#[test]
fn bg_start_refuses_when_port_busy_on_host() {
    // The host check is the measured refusal: the harness binds and
    // releases. A held port fails; the same port free passes.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let busy = l.local_addr().unwrap().port();
    assert!(crate::bg::host_binds(busy).is_err());
    drop(l);
    assert!(crate::bg::host_binds(busy).is_ok());
    let free = free_port();
    assert!(crate::bg::host_binds(free).is_ok());
}

#[test]
fn bg_read_next_and_tail_modes_cursor_arithmetic() {
    let mut r = Rig::new("cursor-modes");
    let start = r.start_sleeper("abcdefghijklmnopqrst", 30);
    assert_eq!(start.status, ToolStatus::Ok, "{}", text(&start));
    wait_pending(&r, 1, 21, "the sleeper's line");
    // Next mode: deliver from the cursor, at most the cap (the stub may
    // deliver fewer than asked; the cursor is exactly what came).
    let a = r.read(json!({ "id": 1, "mode": "next", "max_bytes": 8 }));
    let t = text(&a);
    assert_eq!(a.status, ToolStatus::Ok, "{t}");
    assert!(t.contains("abcdef"), "{t}");
    let cursor1 = match bg(&a) {
        BgRecord::Read(x) => {
            assert_eq!(x.mode, BgReadMode::Next);
            assert_eq!(x.out.since, 0);
            assert_eq!(x.out.from, 0);
            assert!(x.out.to >= 1 && x.out.to <= 8, "{}", x.out.to);
            x.out.to
        }
        other => panic!("a read record, got {other:?}"),
    };
    // The delivered cursor advanced to the window's `to`; the next read
    // starts there.
    assert_eq!(r.t.book.entry(1).unwrap().out_cursor, cursor1);
    // Tail mode ends at the total and counts its jump as skipped. The
    // cap splits 3/4 to stdout, so a tail of max_bytes 4 keeps 3.
    let b = r.read(json!({ "id": 1, "mode": "tail", "max_bytes": 4 }));
    let t = text(&b);
    assert_eq!(b.status, ToolStatus::Ok, "{t}");
    assert!(t.contains("st\n"), "{t}");
    match bg(&b) {
        BgRecord::Read(x) => {
            assert_eq!(x.mode, BgReadMode::Tail);
            assert_eq!(x.out.since, cursor1, "the cursor is the default since");
            assert_eq!(x.out.to, 21, "a tail ends at the stream's total");
            assert_eq!(x.out.from, 18, "at most the cap's worth, from the end");
            assert_eq!(x.out.skipped, 18 - cursor1, "the jump is counted");
            assert_eq!(x.out.dropped, 0);
        }
        other => panic!("a read record, got {other:?}"),
    }
}

#[test]
fn bg_read_reports_dropped_after_ring_overrun() {
    let mut r = Rig::new("ring-overrun");
    // Flood past the 1 MiB ring: the oldest bytes are dropped, the count
    // and digest are exact.
    let start = r.start(json!({
        "argv": ["perl", "-e", "print qq{x} x 2097152; $| = 1; sleep 30;"],
        "lifetime_secs": 60,
    }));
    assert_eq!(start.status, ToolStatus::Ok, "{}", text(&start));
    // Wait until the flood landed.
    let deadline = Instant::now() + secs(10);
    let total = loop {
        let (pending_out, _) = r.t.pending(1);
        if pending_out >= 2_097_152 {
            break pending_out;
        }
        assert!(Instant::now() < deadline, "the flood never landed");
        std::thread::sleep(Duration::from_millis(20));
    };
    let a = r.read(json!({ "id": 1, "mode": "next", "max_bytes": 64 }));
    let t = text(&a);
    assert_eq!(a.status, ToolStatus::Ok, "{t}");
    assert!(t.contains("bytes dropped"), "{t}");
    match bg(&a) {
        BgRecord::Read(x) => {
            assert_eq!(x.out.total, total);
            assert!(x.out.dropped > 0, "{}", t);
            assert_eq!(x.out.from, total - crate::bg::BG_RING_BYTES);
        }
        other => panic!("a read record, got {other:?}"),
    }
}

#[test]
fn bg_read_wait_returns_on_new_output_or_exit() {
    let mut r = Rig::new("wait");
    // Prints after a second, then ends on its own.
    let start = r.start(json!({
        "argv": ["perl", "-e", "sleep 1; print qq{late\\n}; exit 0"],
        "lifetime_secs": 30,
    }));
    assert_eq!(start.status, ToolStatus::Ok, "{}", text(&start));
    let began = Instant::now();
    let a = r.read(json!({ "id": 1, "mode": "next", "max_bytes": 64, "wait_secs": 20 }));
    let t = text(&a);
    assert_eq!(a.status, ToolStatus::Ok, "{t}");
    assert!(t.contains("late"), "{t}");
    assert!(
        began.elapsed() >= Duration::from_millis(500),
        "the wait waited"
    );
    // The read that finds the process gone records its end.
    match bg(&a) {
        BgRecord::Read(x) => {
            assert_eq!(x.state, BgState::Exited);
            assert!(x.ended.is_some(), "{t}");
        }
        other => panic!("a read record, got {other:?}"),
    }
}

#[test]
fn bg_read_without_id_lists_all() {
    let mut r = Rig::new("list");
    let a = r.read(json!({}));
    let t = text(&a);
    assert_eq!(a.status, ToolStatus::Ok, "{t}");
    assert!(t.contains("no background processes"), "{t}");
    match bg(&a) {
        BgRecord::List(items) => assert!(items.is_empty()),
        other => panic!("a list record, got {other:?}"),
    }
    r.start_sleeper("first", 30)
        .status
        .eq(&ToolStatus::Ok)
        .then_some(())
        .unwrap();
    r.start_sleeper("second", 30)
        .status
        .eq(&ToolStatus::Ok)
        .then_some(())
        .unwrap();
    wait_pending(&r, 1, 6, "the first sleeper's line");
    wait_pending(&r, 2, 6, "the second sleeper's line");
    let b = r.read(json!({}));
    let t = text(&b);
    assert!(
        t.contains("1 perl (running") && t.contains("2 perl (running"),
        "{t}"
    );
    match bg(&b) {
        BgRecord::List(items) => {
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].state, BgState::Running);
            assert_eq!((items[0].pending_out, items[0].pending_err), (6, 0));
        }
        other => panic!("a list record, got {other:?}"),
    }
}

#[test]
fn bg_stop_sweeps_and_returns_final_output() {
    let mut r = Rig::new("stop");
    let start = r.start_sleeper("payload", 60);
    assert_eq!(start.status, ToolStatus::Ok, "{}", text(&start));
    wait_pending(&r, 1, 8, "the payload line");
    let stop = r.stop(json!({ "id": 1 }));
    let t = text(&stop);
    assert_eq!(stop.status, ToolStatus::Ok, "{t}");
    assert!(t.contains("background process 1 stopped"), "{t}");
    assert!(t.contains("cleanup: confirmed"), "{t}");
    assert!(t.contains("payload"), "{t}");
    match bg(&stop) {
        BgRecord::Stop(s) => {
            assert_eq!(s.id, 1);
            assert!(matches!(s.end, crate::ExecEnd::Unknown), "{:?}", s.end);
            assert!(matches!(s.cleanup, crate::ExecCleanup::Confirmed { .. }));
            assert_eq!(s.out_total, 8, "payload\\n is 8 bytes");
            assert_eq!(s.out.total, 8);
        }
        other => panic!("a stop record, got {other:?}"),
    }
    // The entry says stopped, with the end recorded.
    let e = r.t.book.entry(1).unwrap();
    assert_eq!(e.state, BgState::Stopped);
    assert!(e.end.is_some());
}

#[test]
fn bg_read_of_unknown_or_stopped_id_refused() {
    let mut r = Rig::new("unknown-or-stopped");
    // Never started.
    let a = r.read(json!({ "id": 99 }));
    assert_eq!(
        a.status,
        ToolStatus::Error {
            code: code::BG_UNKNOWN_ID
        },
        "{}",
        text(&a)
    );
    let s = r.stop(json!({ "id": 99 }));
    assert_eq!(
        s.status,
        ToolStatus::Error {
            code: code::BG_UNKNOWN_ID
        },
        "{}",
        text(&s)
    );
    // Stopped: the refusal repeats the recorded end.
    r.start_sleeper("gone", 30);
    let stop = r.stop(json!({ "id": 1 }));
    assert_eq!(stop.status, ToolStatus::Ok, "{}", text(&stop));
    let again = r.stop(json!({ "id": 1 }));
    let t = text(&again);
    assert_eq!(
        again.status,
        ToolStatus::Error {
            code: code::BG_ALREADY_ENDED
        },
        "{t}"
    );
    assert!(t.contains("already ended"), "{t}");
    let read_again = r.read(json!({ "id": 1 }));
    assert_eq!(
        read_again.status,
        ToolStatus::Error {
            code: code::BG_ALREADY_ENDED
        },
        "{}",
        text(&read_again)
    );
}

#[test]
fn bg_ready_port_waits_for_listener() {
    // A listener already up: the wait meets it fast.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let mut r = Rig::new("ready-port");
    let start = r.start(json!({
        "argv": ["perl", "-e", "sleep 30;"],
        "lifetime_secs": 60,
        "ready": { "port": port }, "ready_secs": 5,
    }));
    let t = text(&start);
    assert_eq!(start.status, ToolStatus::Ok, "{t}");
    assert!(t.contains("ready port: met"), "{t}");
    match bg(&start) {
        BgRecord::Start(s) => {
            let ready = s.ready.expect("a ready wait");
            assert!(ready.met, "{t}");
            assert!(ready.waited_ms < 5_000, "{}", ready.waited_ms);
        }
        other => panic!("a start record, got {other:?}"),
    }
    drop(l);
    // Nothing listens: the wait runs out, not met is not an error.
    let quiet = free_port();
    let began = Instant::now();
    let b = r.start(json!({
        "argv": ["perl", "-e", "sleep 30;"],
        "lifetime_secs": 60,
        "ready": { "port": quiet }, "ready_secs": 1,
    }));
    let t = text(&b);
    assert_eq!(b.status, ToolStatus::Ok, "{t}");
    assert!(t.contains("ready port: not met"), "{t}");
    assert!(began.elapsed() >= Duration::from_millis(900), "{t}");
}

#[test]
fn bg_requires_confined_file_ops() {
    // INV-42 (P-36f): without the confined helper, nothing here starts,
    // reads or stops.
    let mut r = Rig::new("needs-confined");
    r.t.confined_files = false;
    for res in [
        r.start(json!({ "argv": ["perl", "-e", "sleep 1"] })),
        r.read(json!({})),
        r.stop(json!({ "id": 1 })),
    ] {
        let t = text(&res);
        assert_eq!(
            res.status,
            ToolStatus::Error {
                code: code::BG_FILE_OPS
            },
            "{t}"
        );
    }
    assert!(r.t.book.entries.is_empty());
}

// The `BTreeMap` import pins the manager's child-map type; the book's
// children cannot be built outside the sandbox, so the live tests above
// drive them through the provider only.
const _: Option<BTreeMap<u32, harness_sandbox::ConfinedChild>> = None;

/// Poll until the driver seam sees the id's exit, or fail.
fn wait_exit(r: &mut Rig, id: u32, what: &str) -> crate::bg::BgExit {
    let deadline = Instant::now() + secs(10);
    loop {
        let found = r.t.poll().into_iter().find(|x| x.id == id);
        if let Some(x) = found {
            return x;
        }
        assert!(Instant::now() < deadline, "{what} never ended");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn bg_poll_collects_an_exited_id_and_releases_its_ports() {
    let mut r = Rig::new("poll-exit");
    let start = r.start(json!({
        "argv": ["perl", "-e", "$| = 1; print qq{bye\\n}; exit 3"],
        "lifetime_secs": 30,
    }));
    assert_eq!(start.status, ToolStatus::Ok, "{}", text(&start));
    wait_pending(&r, 1, 4, "the bye line");
    // Nothing to collect while it runs.
    assert!(r.t.poll().is_empty());
    let x = wait_exit(&mut r, 1, "the instant exit");
    assert_eq!(x.end, crate::ExecEnd::Exited(3));
    assert!(matches!(x.cleanup, crate::ExecCleanup::Confirmed { .. }));
    assert_eq!(x.out_total, 4, "bye\\n is 4 bytes");
    // The entry says exited, the ports are free, a second poll is quiet.
    let e = r.t.book.entry(1).unwrap();
    assert_eq!(e.state, BgState::Exited);
    assert!(e.end.is_some());
    assert!(r.t.held_ports().is_empty());
    assert!(r.t.poll().is_empty());
    // The undelivered output stays readable, and a stop of the exited id
    // is the deterministic already-ended refusal.
    let read = r.read(json!({ "id": 1, "mode": "next" }));
    let t = text(&read);
    assert_eq!(read.status, ToolStatus::Ok, "{t}");
    assert!(t.contains("bye"), "{t}");
    let stop = r.stop(json!({ "id": 1 }));
    assert_eq!(
        stop.status,
        ToolStatus::Error {
            code: code::BG_ALREADY_ENDED
        },
        "{}",
        text(&stop)
    );
}

#[test]
fn bg_stop_live_stops_turn_scoped_only_and_marks_stopped() {
    let mut r = Rig::new("stop-live-scope");
    // The session scope exists only under the run's persist header; the
    // rig's tool is built without it, so the test turns it on directly.
    r.t.persist = true;
    let a = r.start(json!({
        "argv": ["perl", "-e", "sleep 30;"],
        "lifetime_secs": 60,
    }));
    assert_eq!(a.status, ToolStatus::Ok, "{}", text(&a));
    let b = r.start(json!({
        "argv": ["perl", "-e", "sleep 30;"],
        "lifetime_secs": 60,
        "scope": "session",
    }));
    assert_eq!(b.status, ToolStatus::Ok, "{}", text(&b));
    // The turn's end stops the turn-scoped id only.
    let stopped = r.t.stop_live(true);
    assert_eq!(stopped.len(), 1);
    assert_eq!(stopped[0].id, 1);
    assert!(matches!(
        stopped[0].cleanup,
        crate::ExecCleanup::Confirmed { .. }
    ));
    assert_eq!(r.t.book.entry(1).unwrap().state, BgState::Stopped);
    assert_eq!(r.t.book.entry(2).unwrap().state, BgState::Running);
    assert_eq!(r.t.book.live(), 1);
    // The session's end stops the rest.
    let rest = r.t.stop_live(false);
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].id, 2);
    assert_eq!(r.t.book.live(), 0);
    assert!(r.t.stop_live(false).is_empty());
}
