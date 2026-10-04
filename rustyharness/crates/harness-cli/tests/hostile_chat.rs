//! Hostile delegation at the terminal (P-38h): a helper's report is
//! attacker-controlled text, and the `chat` REPL prints tool lines to a
//! real stderr. Whatever ANSI paint, bidi overrides or control bytes the
//! helper hides in its note, nothing raw reaches the terminal: every
//! display line goes through `harness_core::display`'s sanitizer
//! (`render.rs`), and the report preview never reaches the note at all.
//!
//! In-process twin of `tests/chat.rs`, with one scripted delegation.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use harness_testkit::{act, chat_cli, say, Fixture};

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

#[test]
fn hostile_delegate_report_cannot_paint_terminal() {
    let fx = Fixture::new("hostile-chat-paint").unwrap();
    let base = setup(&fx, &["harness.fs.read", "harness.task.delegate"]);
    // The paint the helper hides in its note: ANSI color, a right-to-left
    // override with its pop, and DEL bytes.
    let raw = "\u{1b}[31mRED\u{1b}[0m \u{202e}reversed\u{202c} \u{7f}END\u{7f}";
    let note = serde_json::json!({ "note": raw }).to_string();
    let (code, out, err) = chat_cli(
        &fx,
        &argv(&base),
        &["go"],
        vec![
            act(
                "harness.task.delegate",
                r#"{"task":"read a.txt and report what it says"}"#,
            ),
            act("harness.task.submit", &note),
            say("thanks"),
        ],
        &[],
    );
    assert_eq!(code, 5, "stderr: {err}");
    // The delegation really ran and its framed report reached the tool
    // line (the test is not passing vacuously; P-38g phrases the line as
    // the helper's report).
    assert!(err.contains("[helper] report -> ok"), "stderr: {err}");
    assert!(
        err.contains("Report from a read-only helper"),
        "stderr: {err}"
    );
    // And nothing hostile is paintable: no raw escape, DEL or bidi byte
    // on either stream.
    for text in [&out, &err] {
        assert!(
            !text.bytes().any(|b| b == 0x1b),
            "a raw ESC byte reached the terminal: {text:?}"
        );
        assert!(
            !text.bytes().any(|b| b == 0x7f),
            "a raw DEL byte reached the terminal: {text:?}"
        );
        assert!(
            !text.contains('\u{202e}'),
            "a raw bidi mark reached the terminal: {text:?}"
        );
    }
    assert!(!err.contains("RED"), "stderr: {err}");
    assert!(!err.contains("reversed"), "stderr: {err}");
    // The session still ends the normal way: the GateReport is the last
    // stdout line.
    let last = out.lines().last().unwrap();
    let v: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(
        v["outcome"]["Indeterminate"]["why"].as_str(),
        Some("NothingChecked"),
        "report: {last}"
    );
}
