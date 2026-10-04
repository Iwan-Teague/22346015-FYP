//! Golden transcripts of `chat` (P-34, part b): eight flows, end to end
//! in process, the real session loop and journal. The transcripts freeze
//! the sanitised, timing-stripped output: model text, tool lines, asks,
//! denials, restores, budget notices, the resume refusal, and the
//! stdout report line. Nondeterminism is normalised away — the fixture
//! base path, run ids and nonces (32 hex), digests (64 hex) and the
//! tool-line milliseconds — and everything else must stay byte-exact.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use harness_core::{Source, Untrusted};
use harness_model::{Completion, FinishReason, ServerUsage};
use harness_testkit::{act, chat_cli, chat_cli_unattended, say, Fixture};

const PROFILE: &str = r#"{"profile_version":1,"id":"mock-m","model":"m",
  "context_window":32768,"fill_ratio":0.6,"protocol":"text","tool_choice_required_ok":false,
  "grammar":"none","max_active_tools":6,"edit_format":"replace","recent_turns":5,
  "sampling":{"temperature":0.2,"top_p":0.95,"seed":7,"max_tokens":2048}}"#;

fn setup(fx: &Fixture, grants: &[&str]) -> Vec<String> {
    let task = serde_json::json!({"task": "Golden chat probe.", "grants": grants});
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

fn is_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

/// Replace every maximal hex run of at least `n` characters with `tag`.
fn replace_hex(s: &str, n: usize, tag: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        let run_start = is_hex(b[i]) && (i == 0 || !is_hex(b[i - 1]));
        if run_start {
            let mut j = i;
            while j < b.len() && is_hex(b[j]) {
                j += 1;
            }
            if j - i >= n {
                out.push_str(tag);
                i = j;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// Tool lines carry live milliseconds: `123 ms)` becomes `N ms)`.
fn strip_ms(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i..].starts_with(b" ms)") {
            let mut start = out.len();
            while start > 0 && out[start - 1].is_ascii_digit() {
                start -= 1;
            }
            out.truncate(start);
            out.extend_from_slice(b"N ms)");
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

fn normalise(base: &std::path::Path, s: &str) -> String {
    let s = s.replace(base.to_string_lossy().as_ref(), "<base>");
    let s = replace_hex(&s, 64, "<hex64>");
    let s = replace_hex(&s, 32, "<hex32>");
    strip_ms(&s)
}

/// Compare against the frozen transcript; on a mismatch, print both.
fn check(name: &str, golden: &str, base: &std::path::Path, out: &str, err: &str) {
    let actual = format!(
        "-- stdout --\n{}\n-- stderr --\n{}\n",
        normalise(base, out),
        normalise(base, err)
    );
    if actual != golden {
        panic!(
            "golden {name} drifted.\n===== expected =====\n{golden}===== actual =====\n{actual}===== end ====="
        );
    }
}

// ---------------------------------------------------------------------------
// The eight flows.
// ---------------------------------------------------------------------------

#[test]
fn golden_chat_read_only_qa() {
    let fx = Fixture::new("golden-read-only").unwrap();
    let base = setup(&fx, &["harness.fs.read"]);
    let (code, out, err) = chat_cli(
        &fx,
        &argv(&base),
        &["What does a.txt say?"],
        vec![
            act("harness.fs.read", r#"{"path":"a.txt"}"#),
            say("it says: the answer is in here"),
        ],
        &[],
    );
    assert_eq!(code, 5, "stderr: {err}");
    check("read_only_qa", GOLDEN_READ_ONLY_QA, fx.base(), &out, &err);
}

#[test]
fn golden_chat_edit_with_approval() {
    let fx = Fixture::new("golden-edit-approve").unwrap();
    let base = setup(&fx, &["harness.fs.read", "harness.edit.write"]);
    let (code, out, err) = chat_cli(
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
    check(
        "edit_with_approval",
        GOLDEN_EDIT_WITH_APPROVAL,
        fx.base(),
        &out,
        &err,
    );
}

#[test]
fn golden_chat_deny() {
    let fx = Fixture::new("golden-deny").unwrap();
    let base = setup(&fx, &["harness.fs.read", "harness.edit.write"]);
    let (code, out, err) = chat_cli(
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
        &["n"],
    );
    assert_eq!(code, 5, "stderr: {err}");
    assert!(!fx.workspace().join("new.txt").exists());
    check("deny", GOLDEN_DENY, fx.base(), &out, &err);
}

#[test]
fn golden_chat_undo() {
    let fx = Fixture::new("golden-undo").unwrap();
    let base = setup(&fx, &["harness.fs.read", "harness.edit.write"]);
    let (code, out, err) = chat_cli(
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
    assert_eq!(
        std::fs::read_to_string(fx.workspace().join("a.txt")).unwrap(),
        "the answer is in here\n"
    );
    check("undo", GOLDEN_UNDO, fx.base(), &out, &err);
}

#[test]
fn golden_chat_plan_build() {
    let fx = Fixture::new("golden-plan-build").unwrap();
    let base = setup(&fx, &["harness.fs.read", "harness.edit.write"]);
    let (code, out, err) = chat_cli(
        &fx,
        &argv(&base),
        &["/plan", "draft it", "/build", "go ahead"],
        vec![
            act(
                "harness.plan.submit",
                r#"{"summary":"Rewrite a.txt.","files":["a.txt"],"steps":["rewrite a.txt"]}"#,
            ),
            act("harness.fs.read", r#"{"path":"a.txt"}"#),
            act(
                "harness.edit.write",
                r#"{"path":"a.txt","content":"planned ink"}"#,
            ),
            say("built"),
        ],
        &[],
    );
    assert_eq!(code, 5, "stderr: {err}");
    check("plan_build", GOLDEN_PLAN_BUILD, fx.base(), &out, &err);
    assert_eq!(
        std::fs::read_to_string(fx.workspace().join("a.txt")).unwrap(),
        "planned ink"
    );
}

#[test]
fn golden_chat_resume() {
    let fx = Fixture::new("golden-resume").unwrap();
    let base = setup(&fx, &["harness.fs.read"]);
    let (code, out, err) = chat_cli(&fx, &argv(&base), &["hello"], vec![say("hi")], &[]);
    assert_eq!(code, 5, "stderr: {err}");
    // Reopening needs P-17 (not in this build): the refusal, frozen.
    let id = err
        .lines()
        .find(|l| l.starts_with("session "))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_owned();
    let mut again = argv(&base);
    again.push("--resume");
    again.push(&id);
    let (code2, out2, err2) = chat_cli(&fx, &again, &[], vec![], &[]);
    assert_eq!(code2, 4, "stderr: {err2}");
    check(
        "resume",
        &GOLDEN_RESUME_TEMPLATE.replace("<run>", &id),
        fx.base(),
        &out,
        &err,
    );
    check(
        "resume_refusal",
        &GOLDEN_RESUME_REFUSAL.replace("<run>", &id),
        fx.base(),
        &out2,
        &err2,
    );
}

#[test]
fn golden_chat_hostile_output() {
    let fx = Fixture::new("golden-hostile").unwrap();
    let base = setup(&fx, &["harness.fs.read"]);
    let (code, out, err) = chat_cli(
        &fx,
        &argv(&base),
        &["go on"],
        vec![
            say("red \u{1b}[31malert\u{1b}[0m \u{202e}evil\u{1b}[0m end"),
            say("clean"),
        ],
        &[],
    );
    assert_eq!(code, 5, "stderr: {err}");
    assert!(!err.contains('\u{1b}'), "a raw ESC reached the terminal");
    check(
        "hostile_output",
        GOLDEN_HOSTILE_OUTPUT,
        fx.base(),
        &out,
        &err,
    );
}

#[test]
fn golden_chat_budget_stop() {
    let fx = Fixture::new("golden-budget").unwrap();
    let base = setup(&fx, &["harness.fs.read"]);
    let costly = |content: &str| Completion {
        content: Untrusted::new(content.to_owned(), Source::Model),
        tool_calls: Vec::new(),
        finish: FinishReason::Stop,
        usage: Some(ServerUsage {
            input: 700_000,
            output: 700_000,
        }),
        request_bytes: 0,
        reply_bytes: content.len() as u64,
        retried: Vec::new(),
        server_stats: None,
    };
    let (code, out, err) = chat_cli_unattended(
        &fx,
        &argv(&base),
        &["burn the budget", "still there?"],
        vec![costly("spending tokens"), costly("more tokens")],
    );
    assert_eq!(code, 5, "stderr: {err}");
    check("budget_stop", GOLDEN_BUDGET_STOP, fx.base(), &out, &err);
}

// ---------------------------------------------------------------------------
// The frozen transcripts.
// ---------------------------------------------------------------------------

const GOLDEN_READ_ONLY_QA: &str = concat!(
    "-- stdout --\n",
    "chain_head <hex64>\n",
    r#"{"gate":"rustyharness.run","outcome":{"Indeterminate":{"why":"NothingChecked"}},"findings":[{"severity":"Info","code":"harness.chat","location":"session <hex32> attempt 1","expected":"a verification plan (H1 tasks have none)","observed":"stopped: session_ended; no checks planned"},{"severity":"Info","code":"harness.chat.turns","location":"session <hex32> attempt 1","expected":"the turns the session journaled","observed":"1 turn(s)"}],"coverage":"Full","scope":{"examined":[],"excluded":[],"pin":null}}"#,
    "\n\n-- stderr --\n",
    "rustyharness chat (the exit is Indeterminate until H3: nothing here has checked the result)\n",
    "workspace <base>/ws\n",
    "state root <base>/state\n",
    "model mock-m ((a backend given to the library))\n",
    "no confinement: read/edit only\n",
    "tools: harness.fs.read\n",
    "policy digest: <hex64>\n",
    "[tool] harness.fs.read -> ok (N ms) = a.txt: lines 1-1 of 1; sha256 <hex64>\\u{A}1\tthe [17 bytes cut]\n",
    "it says: the answer is in here\n",
    "[turn] answered (2 step(s))\n",
    "session <hex32> attempt 1: 1 turn(s), 2 step(s), stopped (session_ended)\n",
    "outcome: indeterminate (NothingChecked): nothing has verified the result\n\n",
);

const GOLDEN_EDIT_WITH_APPROVAL: &str = concat!(
    "-- stdout --\n",
    "chain_head <hex64>\n",
    r#"{"gate":"rustyharness.run","outcome":{"Indeterminate":{"why":"NothingChecked"}},"findings":[{"severity":"Info","code":"harness.chat","location":"session <hex32> attempt 1","expected":"a verification plan (H1 tasks have none)","observed":"stopped: session_ended; no checks planned"},{"severity":"Info","code":"harness.chat.turns","location":"session <hex32> attempt 1","expected":"the turns the session journaled","observed":"1 turn(s)"}],"coverage":"Full","scope":{"examined":[],"excluded":[],"pin":null}}"#,
    "\n\n-- stderr --\n",
    "rustyharness chat (the exit is Indeterminate until H3: nothing here has checked the result)\n",
    "workspace <base>/ws\n",
    "state root <base>/state\n",
    "model mock-m ((a backend given to the library))\n",
    "no confinement: read/edit only\n",
    "tools: harness.fs.read, harness.edit.write\n",
    "policy digest: <hex64>\n",
    "[approve] harness.edit.write (user_confirm) needs approval\n",
    "[approve] granted\n",
    "[edit] new.txt applied\n",
    "[tool] harness.edit.write -> ok (N ms) = created new.txt: 1 line; sha256 <hex64>\n",
    "done\n",
    "[turn] answered (2 step(s))\n",
    "session <hex32> attempt 1: 1 turn(s), 2 step(s), stopped (session_ended)\n",
    "outcome: indeterminate (NothingChecked): nothing has verified the result\n\n",
);

const GOLDEN_DENY: &str = concat!(
    "-- stdout --\n",
    "chain_head <hex64>\n",
    r#"{"gate":"rustyharness.run","outcome":{"Indeterminate":{"why":"NothingChecked"}},"findings":[{"severity":"Info","code":"harness.chat","location":"session <hex32> attempt 1","expected":"a verification plan (H1 tasks have none)","observed":"stopped: session_ended; no checks planned"},{"severity":"Info","code":"harness.chat.turns","location":"session <hex32> attempt 1","expected":"the turns the session journaled","observed":"1 turn(s)"}],"coverage":"Full","scope":{"examined":[],"excluded":[],"pin":null}}"#,
    "\n\n-- stderr --\n",
    "rustyharness chat (the exit is Indeterminate until H3: nothing here has checked the result)\n",
    "workspace <base>/ws\n",
    "state root <base>/state\n",
    "model mock-m ((a backend given to the library))\n",
    "no confinement: read/edit only\n",
    "tools: harness.fs.read, harness.edit.write\n",
    "policy digest: <hex64>\n",
    "[approve] harness.edit.write (user_confirm) needs approval\n",
    "[approve] denied\n",
    "understood\n",
    "[turn] answered (2 step(s))\n",
    "session <hex32> attempt 1: 1 turn(s), 2 step(s), stopped (session_ended)\n",
    "outcome: indeterminate (NothingChecked): nothing has verified the result\n\n",
);
const GOLDEN_UNDO: &str = concat!(
    "-- stdout --\n",
    "chain_head <hex64>\n",
    r#"{"gate":"rustyharness.run","outcome":{"Indeterminate":{"why":"NothingChecked"}},"findings":[{"severity":"Info","code":"harness.chat","location":"session <hex32> attempt 1","expected":"a verification plan (H1 tasks have none)","observed":"stopped: session_ended; no checks planned"},{"severity":"Info","code":"harness.chat.turns","location":"session <hex32> attempt 1","expected":"the turns the session journaled","observed":"1 turn(s)"}],"coverage":"Full","scope":{"examined":[],"excluded":[],"pin":null}}"#,
    "\n\n-- stderr --\n",
    "rustyharness chat (the exit is Indeterminate until H3: nothing here has checked the result)\n",
    "workspace <base>/ws\n",
    "state root <base>/state\n",
    "model mock-m ((a backend given to the library))\n",
    "no confinement: read/edit only\n",
    "tools: harness.fs.read, harness.edit.write\n",
    "policy digest: <hex64>\n",
    "[tool] harness.fs.read -> ok (N ms) = a.txt: lines 1-1 of 1; sha256 <hex64>\\u{A}1\tthe [17 bytes cut]\n",
    "[approve] harness.edit.write (user_confirm) needs approval\n",
    "[approve] granted\n",
    "[edit] a.txt applied\n",
    "[tool] harness.edit.write -> ok (N ms) = rewrote a.txt: 1 line; sha256 <hex64> (was afa90[60 bytes cut]\n",
    "done\n",
    "[turn] answered (3 step(s))\n",
    "undoing 1 file edit(s) back to step 0\n",
    "[restore] back to step 0: 1 file edit(s) undone\n",
    "session <hex32> attempt 1: 1 turn(s), 3 step(s), stopped (session_ended)\n",
    "outcome: indeterminate (NothingChecked): nothing has verified the result\n\n",
);

const GOLDEN_PLAN_BUILD: &str = concat!(
    "-- stdout --\n",
    "chain_head <hex64>\n",
    r#"{"gate":"rustyharness.run","outcome":{"Indeterminate":{"why":"NothingChecked"}},"findings":[{"severity":"Info","code":"harness.chat","location":"session <hex32> attempt 1","expected":"a verification plan (H1 tasks have none)","observed":"stopped: session_ended; no checks planned"},{"severity":"Info","code":"harness.chat.turns","location":"session <hex32> attempt 1","expected":"the turns the session journaled","observed":"2 turn(s)"}],"coverage":"Full","scope":{"examined":[],"excluded":[],"pin":null}}"#,
    "\n\n-- stderr --\n",
    "rustyharness chat (the exit is Indeterminate until H3: nothing here has checked the result)\n",
    "workspace <base>/ws\n",
    "state root <base>/state\n",
    "model mock-m ((a backend given to the library))\n",
    "no confinement: read/edit only\n",
    "tools: harness.fs.read, harness.edit.write\n",
    "policy digest: <hex64>\n",
    "[tool] harness.plan.submit -> ok (N ms) = Plan recorded. It is shown to the user for approval with /build.\n",
    "[turn] plan_submitted (1 step(s))\n",
    "[tool] harness.fs.read -> ok (N ms) = a.txt: lines 1-1 of 1; sha256 <hex64>\\u{A}1\tthe [17 bytes cut]\n",
    "[edit] a.txt applied\n",
    "[tool] harness.edit.write -> ok (N ms) = rewrote a.txt: 1 line; sha256 <hex64> (was afa90[60 bytes cut]\n",
    "built\n",
    "[turn] answered (3 step(s))\n",
    "session <hex32> attempt 1: 2 turn(s), 4 step(s), stopped (session_ended)\n",
    "outcome: indeterminate (NothingChecked): nothing has verified the result\n\n",
);

const GOLDEN_RESUME_TEMPLATE: &str = concat!(
    "-- stdout --\n",
    "chain_head <hex64>\n",
    r#"{"gate":"rustyharness.run","outcome":{"Indeterminate":{"why":"NothingChecked"}},"findings":[{"severity":"Info","code":"harness.chat","location":"session <hex32> attempt 1","expected":"a verification plan (H1 tasks have none)","observed":"stopped: session_ended; no checks planned"},{"severity":"Info","code":"harness.chat.turns","location":"session <hex32> attempt 1","expected":"the turns the session journaled","observed":"1 turn(s)"}],"coverage":"Full","scope":{"examined":[],"excluded":[],"pin":null}}"#,
    "\n\n-- stderr --\n",
    "rustyharness chat (the exit is Indeterminate until H3: nothing here has checked the result)\n",
    "workspace <base>/ws\n",
    "state root <base>/state\n",
    "model mock-m ((a backend given to the library))\n",
    "no confinement: read/edit only\n",
    "tools: harness.fs.read\n",
    "policy digest: <hex64>\n",
    "hi\n",
    "[turn] answered (1 step(s))\n",
    "session <hex32> attempt 1: 1 turn(s), 1 step(s), stopped (session_ended)\n",
    "outcome: indeterminate (NothingChecked): nothing has verified the result\n\n",
);

const GOLDEN_HOSTILE_OUTPUT: &str = concat!(
    "-- stdout --\n",
    "chain_head <hex64>\n",
    r#"{"gate":"rustyharness.run","outcome":{"Indeterminate":{"why":"NothingChecked"}},"findings":[{"severity":"Info","code":"harness.chat","location":"session <hex32> attempt 1","expected":"a verification plan (H1 tasks have none)","observed":"stopped: session_ended; no checks planned"},{"severity":"Info","code":"harness.chat.turns","location":"session <hex32> attempt 1","expected":"the turns the session journaled","observed":"1 turn(s)"}],"coverage":"Full","scope":{"examined":[],"excluded":[],"pin":null}}"#,
    "\n\n-- stderr --\n",
    "rustyharness chat (the exit is Indeterminate until H3: nothing here has checked the result)\n",
    "workspace <base>/ws\n",
    "state root <base>/state\n",
    "model mock-m ((a backend given to the library))\n",
    "no confinement: read/edit only\n",
    "tools: harness.fs.read\n",
    "policy digest: <hex64>\n",
    "red \\u{1B}[31malert\\u{1B}[0m \\u{202E}evil\\u{1B}[0m end\n",
    "[turn] answered (1 step(s))\n",
    "session <hex32> attempt 1: 1 turn(s), 1 step(s), stopped (session_ended)\n",
    "outcome: indeterminate (NothingChecked): nothing has verified the result\n\n",
);

const GOLDEN_BUDGET_STOP: &str = concat!(
    "-- stdout --\n",
    "chain_head <hex64>\n",
    r#"{"gate":"rustyharness.run","outcome":{"Indeterminate":{"why":"NothingChecked"}},"findings":[{"severity":"Info","code":"harness.chat","location":"session <hex32> attempt 1","expected":"a verification plan (H1 tasks have none)","observed":"stopped: budget; no checks planned"},{"severity":"Info","code":"harness.chat.turns","location":"session <hex32> attempt 1","expected":"the turns the session journaled","observed":"1 turn(s)"}],"coverage":"Full","scope":{"examined":[],"excluded":[],"pin":null}}"#,
    "\n\n-- stderr --\n",
    "rustyharness chat (the exit is Indeterminate until H3: nothing here has checked the result)\n",
    "workspace <base>/ws\n",
    "state root <base>/state\n",
    "model mock-m ((a backend given to the library))\n",
    "no confinement: read/edit only\n",
    "tools: harness.fs.read\n",
    "policy digest: <hex64>\n",
    "session <hex32> attempt 1: 1 turn(s), 1 step(s), stopped (budget)\n",
    "outcome: indeterminate (NothingChecked): nothing has verified the result\n\n",
);

// The refusal names the run id, which the normaliser has already turned
// into `<hex32>` in both the frozen text and the actual output.
const GOLDEN_RESUME_REFUSAL: &str = concat!(
    "-- stdout --\n",
    r#"{"gate":"rustyharness.run","outcome":{"Indeterminate":{"why":"CouldNotRun"}},"findings":[{"severity":"Info","code":"harness.refused","location":"rustyharness","expected":"a run that starts","observed":"session reopen needs P-17 (not in this build); would resume <hex32>"}],"coverage":"Full","scope":{"examined":[],"excluded":[],"pin":null}}"#,
    "\n\n-- stderr --\n",
    "session reopen needs P-17 (not in this build); would resume <hex32>\n\n",
);
