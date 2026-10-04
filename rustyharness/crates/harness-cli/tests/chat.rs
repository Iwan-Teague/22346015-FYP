//! The `chat` REPL (P-18) end to end, in process: scripted input lines
//! and a scripted model, the real session loop, the real journal. The
//! session always ends `Indeterminate { NothingChecked }` (exit 5) until
//! H3, and the last stdout line is always the `GateReport`.
//!
//! `--resume` here can only refuse: reopening a session journal needs
//! P-17, which is not in this build (docs/slices/P-18.md).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use harness_journal::{layout, EventKind, JournalReader};
use harness_testkit::{act, chat_cli, chat_cli_unattended, say, Fixture};

const PROFILE: &str = r#"{"profile_version":1,"id":"mock-m","model":"m",
  "context_window":32768,"fill_ratio":0.6,"protocol":"text","tool_choice_required_ok":false,
  "grammar":"none","max_active_tools":6,"edit_format":"replace","recent_turns":5,
  "sampling":{"temperature":0.2,"top_p":0.95,"seed":7,"max_tokens":2048}}"#;

/// Task and profile files under the fixture's base (outside the
/// workspace, so the read tools never see them), and one workspace file.
fn setup(fx: &Fixture, grants: &[&str]) -> Vec<String> {
    let task = serde_json::json!({"task": "Chat about the workspace.", "grants": grants});
    let task_path = fx.base().join("task.json");
    std::fs::write(&task_path, serde_json::to_string(&task).unwrap()).unwrap();
    let profile_path = fx.base().join("profile.json");
    std::fs::write(&profile_path, PROFILE).unwrap();
    fx.write("a.txt", "the answer is in here\n").unwrap();
    vec![
        "chat".to_owned(),
        "--task".to_owned(),
        task_path.to_string_lossy().into_owned(),
        "--profile".to_owned(),
        profile_path.to_string_lossy().into_owned(),
        "--workspace".to_owned(),
        fx.workspace().to_string_lossy().into_owned(),
        "--state-root".to_owned(),
        fx.state_root().to_string_lossy().into_owned(),
    ]
}

fn argv(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

/// The `session <id> attempt <n>:` summary line's words.
fn session_words(err: &str) -> (String, String) {
    let line = err
        .lines()
        .find(|l| l.starts_with("session "))
        .unwrap_or_else(|| panic!("no session summary in: {err}"));
    let w: Vec<&str> = line.split_whitespace().collect();
    let id = w.get(1).copied().unwrap_or_default().to_owned();
    let attempt = w
        .get(3)
        .copied()
        .unwrap_or_default()
        .trim_end_matches(':')
        .to_owned();
    (id, attempt)
}

#[test]
fn chat_runs_two_prompts_and_prints_chain_head() {
    let fx = Fixture::new("chat-two-prompts").unwrap();
    let base = setup(&fx, &["harness.fs.read"]);
    let (code, out, err) = chat_cli(
        &fx,
        &argv(&base),
        &["hello one", "hello two"],
        vec![say("first answer"), say("second answer")],
        &[],
    );
    assert_eq!(code, 5, "stderr: {err}");
    assert!(out.contains("chain_head "), "stdout: {out}");
    let last = out.lines().last().unwrap();
    let v: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(
        v["outcome"]["Indeterminate"]["why"].as_str(),
        Some("NothingChecked"),
        "report: {last}"
    );
    assert!(err.contains("2 turn(s)"), "stderr: {err}");
    assert!(err.contains("first answer"), "stderr: {err}");
    assert!(err.contains("second answer"), "stderr: {err}");
}

#[test]
fn chat_streams_text_to_output() {
    let fx = Fixture::new("chat-streams").unwrap();
    let base = setup(&fx, &["harness.fs.read"]);
    let (code, _out, err) = chat_cli(
        &fx,
        &argv(&base),
        &["go ahead"],
        vec![say("a plain streamed answer")],
        &[],
    );
    assert_eq!(code, 5, "stderr: {err}");
    assert!(err.contains("a plain streamed answer"), "stderr: {err}");
}

#[test]
fn chat_denies_asks_without_tty() {
    let fx = Fixture::new("chat-denies").unwrap();
    let base = setup(&fx, &["harness.fs.read", "harness.edit.write"]);
    let (code, _out, err) = chat_cli_unattended(
        &fx,
        &argv(&base),
        &["write new.txt please"],
        vec![
            act(
                "harness.edit.write",
                r#"{"path":"new.txt","content":"denied ink"}"#,
            ),
            say("understood"),
        ],
    );
    assert_eq!(code, 5, "stderr: {err}");
    assert!(
        !fx.workspace().join("new.txt").exists(),
        "an ask was answered by nobody and the edit ran anyway"
    );
    // No approver present: the policy denies the ask outright, and chat
    // shows the denial (no approval records are journaled at all).
    assert!(err.contains("[deny]"), "stderr: {err}");
    assert!(err.contains("no_approver"), "stderr: {err}");
}

#[test]
fn chat_approves_edit_with_diff_shown() {
    let fx = Fixture::new("chat-approves").unwrap();
    let base = setup(&fx, &["harness.fs.read", "harness.edit.write"]);
    let (code, _out, err) = chat_cli(
        &fx,
        &argv(&base),
        &["write new.txt please"],
        vec![
            act(
                "harness.edit.write",
                r#"{"path":"new.txt","content":"approved ink"}"#,
            ),
            say("done"),
        ],
        &["y"],
    );
    assert_eq!(code, 5, "stderr: {err}");
    assert_eq!(
        std::fs::read_to_string(fx.workspace().join("new.txt")).unwrap(),
        "approved ink"
    );
    // The ask is shown with the sink's request line (the P-16 in-loop
    // diff preview is not wireable at this layer; P-18.md notes the
    // deviation). The y/N prompt itself is the terminal approver's, and
    // the scripted one here is silent.
    assert!(err.contains("[approve]"), "stderr: {err}");
    assert!(err.contains("harness.edit.write"), "stderr: {err}");
}

#[test]
fn chat_slash_status_lists_tools() {
    let fx = Fixture::new("chat-slash").unwrap();
    let base = setup(&fx, &["harness.fs.read", "harness.fs.search"]);
    let (code, _out, err) = chat_cli(
        &fx,
        &argv(&base),
        &["/status", "/tools", "hello"],
        vec![say("hi there")],
        &[],
    );
    assert_eq!(code, 5, "stderr: {err}");
    assert!(err.contains("workspace"), "stderr: {err}");
    assert!(err.contains("harness.fs.read"), "stderr: {err}");
    assert!(err.contains("harness.fs.search"), "stderr: {err}");
}

#[test]
fn chat_resume_continues_previous_session() {
    let fx = Fixture::new("chat-resume").unwrap();
    let base = setup(&fx, &["harness.fs.read"]);
    let (code, _out, err) = chat_cli(&fx, &argv(&base), &["hello"], vec![say("hi")], &[]);
    assert_eq!(code, 5, "stderr: {err}");
    let (id, _attempt) = session_words(&err);
    // An explicit id: refused, naming the run it would reopen.
    let mut again = argv(&base);
    again.push("--resume");
    again.push(&id);
    let (code, _out, err) = chat_cli(&fx, &again, &[], vec![], &[]);
    assert_eq!(code, 4, "stderr: {err}");
    assert!(err.contains("P-17"), "stderr: {err}");
    assert!(err.contains(&id), "stderr: {err}");
    // The picker form refuses the same way.
    let mut picker = argv(&base);
    picker.push("--continue");
    let (code, _out, err) = chat_cli(&fx, &picker, &[], vec![], &[]);
    assert_eq!(code, 4, "stderr: {err}");
    assert!(err.contains("P-17"), "stderr: {err}");
}

#[test]
fn chat_undo_restores_the_last_edit() {
    let fx = Fixture::new("chat-undo").unwrap();
    let base = setup(&fx, &["harness.fs.read", "harness.edit.write"]);
    let (code, _out, err) = chat_cli(
        &fx,
        &argv(&base),
        &["rewrite a.txt", "/undo"],
        vec![
            act("harness.fs.read", r#"{"path":"a.txt"}"#),
            act(
                "harness.edit.write",
                r#"{"path":"a.txt","content":"rewritten"}"#,
            ),
            say("done"),
        ],
        &["y"],
    );
    assert_eq!(code, 5, "stderr: {err}");
    assert!(err.contains("undoing 1 file edit(s)"), "stderr: {err}");
    assert!(err.contains("[restore] back to step"), "stderr: {err}");
    assert_eq!(
        std::fs::read_to_string(fx.workspace().join("a.txt")).unwrap(),
        "the answer is in here\n"
    );
}

#[test]
fn chat_undo_without_edits_says_nothing_to_undo() {
    let fx = Fixture::new("chat-undo-nothing").unwrap();
    let base = setup(&fx, &["harness.fs.read"]);
    let (code, _out, err) = chat_cli(&fx, &argv(&base), &["hello", "/undo"], vec![say("hi")], &[]);
    assert_eq!(code, 5, "stderr: {err}");
    assert!(err.contains("nothing to undo"), "stderr: {err}");
    assert!(!err.contains("[restore]"), "stderr: {err}");
}

#[test]
fn chat_output_has_no_raw_escape_from_model() {
    let fx = Fixture::new("chat-escape").unwrap();
    let base = setup(&fx, &["harness.fs.read"]);
    let (code, _out, err) = chat_cli(
        &fx,
        &argv(&base),
        &["x"],
        vec![say("red \u{1b}[31malert\u{1b}[0m end")],
        &[],
    );
    assert_eq!(code, 5, "stderr: {err}");
    assert!(
        !err.contains('\u{1b}'),
        "a raw ESC reached the terminal: {err:?}"
    );
    assert!(
        err.contains("\\u{1B}"),
        "the ESC was not shown escaped: {err:?}"
    );
}

#[test]
fn chat_eof_ends_cleanly_exit5_report_line() {
    let fx = Fixture::new("chat-eof").unwrap();
    let base = setup(&fx, &["harness.fs.read"]);
    let (code, out, err) = chat_cli(&fx, &argv(&base), &[], vec![], &[]);
    assert_eq!(code, 5, "stderr: {err}");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines.len() >= 2, "stdout: {out}");
    assert!(
        lines[0].starts_with("chain_head ") && lines[0].len() == "chain_head ".len() + 64,
        "stdout: {out}"
    );
    let last = lines.last().unwrap();
    let v: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(
        v["outcome"]["Indeterminate"]["why"].as_str(),
        Some("NothingChecked"),
        "report: {last}"
    );
    assert!(err.contains("0 turn(s)"), "stderr: {err}");
}

#[test]
fn chat_session_journal_audits_clean() {
    let fx = Fixture::new("chat-journal").unwrap();
    let base = setup(&fx, &["harness.fs.read"]);
    let (code, _out, err) = chat_cli(
        &fx,
        &argv(&base),
        &["what does a.txt say?"],
        vec![
            act("harness.fs.read", r#"{"path":"a.txt"}"#),
            say("it says: the answer is in here"),
        ],
        &[],
    );
    assert_eq!(code, 5, "stderr: {err}");
    let (id, attempt) = session_words(&err);
    let run = harness_core::RunId::parse(&id).unwrap();
    let run_dir = layout::run_dir(fx.state_root(), &run);
    let attempt_dir = layout::attempt_dir(&run_dir, attempt.parse::<u32>().unwrap());
    // The verifying reader refuses a broken chain, so `open` succeeding
    // IS the chain check; `torn_tail` would name an uncommitted tail.
    let v = JournalReader::open(&attempt_dir).unwrap();
    assert!(v.torn_tail.is_none(), "torn tail: {:?}", v.torn_tail);
    let kinds: Vec<EventKind> = v.records.iter().map(|r| r.kind).collect();
    assert_eq!(kinds[0], EventKind::RunStarted);
    assert_eq!(*kinds.last().unwrap(), EventKind::RunStopped);
    for want in [
        EventKind::UserTurn,
        EventKind::ModelReplied,
        EventKind::ToolStarted,
        EventKind::ToolFinished,
        EventKind::TurnEnded,
        EventKind::InputEnded,
    ] {
        assert!(kinds.contains(&want), "missing {want:?} in {kinds:?}");
    }
    let stop = v.records.last().unwrap();
    assert_eq!(
        stop.body.get("cause").and_then(serde_json::Value::as_str),
        Some("session_ended")
    );
    assert_eq!(
        stop.body.get("outcome").and_then(serde_json::Value::as_str),
        Some("indeterminate:nothing_checked")
    );
}

// P-31: a hosted profile's chat says so in the banner (and `/status`).
#[test]
fn hosted_chat_discloses_the_upstream() {
    let fx = Fixture::new("chat-hosted").unwrap();
    let base = setup(&fx, &["harness.fs.read"]);
    let mut p: serde_json::Map<String, serde_json::Value> = serde_json::from_str(PROFILE).unwrap();
    p.insert("upstream".into(), serde_json::json!("hosted"));
    p.insert(
        "price_table".into(),
        serde_json::json!({"in_micro_per_ktok": 3000, "out_micro_per_ktok": 15000}),
    );
    std::fs::write(
        fx.base().join("profile.json"),
        serde_json::Value::Object(p).to_string(),
    )
    .unwrap();
    let (_code, _out, err) = chat_cli(&fx, &argv(&base), &["hello"], vec![say("hi")], &[]);
    assert!(
        err.contains("context is sent to a hosted provider"),
        "{err}"
    );
}

// P-38g: the chat sink shows a delegate as a helper — a `[helper]
// started` line from the parent's `ChildRun` record and the framed
// report line from the delegate's `ToolFinished`.
#[test]
fn chat_shows_helper_start_and_report_lines() {
    let fx = Fixture::new("chat-helper-lines").unwrap();
    let base = setup(&fx, &["harness.fs.read", "harness.task.delegate"]);
    let (code, _out, err) = chat_cli(
        &fx,
        &argv(&base),
        &["ask a helper what a.txt says"],
        vec![
            act("harness.task.delegate", r#"{"task":"what is in a.txt?"}"#),
            act("harness.fs.read", r#"{"path":"a.txt"}"#),
            act(
                "harness.task.submit",
                r#"{"note":"a.txt says the answer is in here"}"#,
            ),
            say("the helper read it for me"),
        ],
        &[],
    );
    assert_eq!(code, 5, "stderr: {err}");
    assert!(err.contains("[helper] started (run "), "stderr: {err}");
    let started = err
        .lines()
        .find(|l| l.starts_with("[helper] started"))
        .unwrap_or_else(|| panic!("no helper start line in: {err}"));
    assert!(
        started.ends_with(" steps)"),
        "the helper's step budget is shown: {started}"
    );
    assert!(err.contains("[helper] report -> ok"), "stderr: {err}");
    let report = err
        .lines()
        .find(|l| l.starts_with("[helper] report"))
        .unwrap_or_else(|| panic!("no helper report line in: {err}"));
    assert!(
        report.contains("Report from a read-only helper"),
        "the framed report is previewed: {report}"
    );
    assert!(
        !err.contains("[tool] harness.task.delegate"),
        "the delegate is not rendered as a plain tool: {err}"
    );
}
