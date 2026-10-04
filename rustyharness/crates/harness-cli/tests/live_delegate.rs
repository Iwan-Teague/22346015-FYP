//! Live smoke tests for delegation (P-38i): a fixture workspace whose
//! question is answered once with the `harness.task.delegate` grant (the
//! model hands the searching to a read-only helper; the helper's journal is
//! recorded in the parent's as `ChildRun` records and audited with the
//! parent) and once without it (no helper runs). The steps and tokens of
//! both variants are written out as a TSV so the slice note can quote them.
//!
//! Like `exit_h1`, these need a real model server, so they are `#[ignore]`d
//! in the gates and run on purpose:
//!
//! ```text
//! RUSTYHARNESS_EXIT_ENDPOINT=http://127.0.0.1:8080/v1 \
//! RUSTYHARNESS_EXIT_MODEL=<the model id the server lists> \
//!   cargo test -p harness-cli --test live_delegate -- --ignored --test-threads=1
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_rustyharness");

/// The fact the model has to find, buried under a decoy codename.
const CODENAME: &str = "GREEN-FALCON-91";

/// An older codename the workspace also mentions, so the search is real.
const DECOY: &str = "OLD-SPARROW-07";

const INLINE_GRANTS: &[&str] = &["harness.fs.read", "harness.fs.list", "harness.fs.search"];

const DELEGATE_GRANTS: &[&str] = &[
    "harness.fs.read",
    "harness.fs.list",
    "harness.fs.search",
    "harness.task.delegate",
];

fn task_text() -> String {
    "Several files in this workspace mention project codenames; exactly one of them \
     is the CURRENT codename. Find it, then submit the codename (and nothing else) \
     as the note of harness.task.submit. If a helper tool is granted, hand the \
     searching to the helper and use its report."
        .to_owned()
}

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| {
        panic!("{k} is not set: this test needs a local model server (see the module docs)")
    })
}

struct Fx {
    state: PathBuf,
    ws: PathBuf,
    task: PathBuf,
    profile: PathBuf,
}

fn fixture(name: &str, grants: &[&str]) -> Fx {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("live-delegate-{name}"));
    let _ = std::fs::remove_dir_all(&base);
    let (state, ws) = (base.join("state"), base.join("ws"));
    std::fs::create_dir_all(&state).unwrap();
    std::fs::create_dir_all(ws.join("docs")).unwrap();
    std::fs::create_dir_all(ws.join("src")).unwrap();
    std::fs::write(
        ws.join("README.md"),
        "# A small project\n\nSee docs/ for the project notes.\n",
    )
    .unwrap();
    std::fs::write(
        ws.join("src/main.rs"),
        "fn main() {\n    println!(\"hello\");\n}\n",
    )
    .unwrap();
    std::fs::write(
        ws.join("docs/archive.txt"),
        format!("Archive\n\nThe codename used to be {DECOY}; it was retired.\n"),
    )
    .unwrap();
    std::fs::write(
        ws.join("docs/meeting.txt"),
        "Meeting notes\n\nSomeone asked again which codename is current; see notes.txt.\n",
    )
    .unwrap();
    std::fs::write(
        ws.join("docs/notes.txt"),
        format!("Project notes\n\nThe CURRENT codename is {CODENAME}.\nIt ships in autumn.\n"),
    )
    .unwrap();
    let task = base.join("task.json");
    std::fs::write(
        &task,
        serde_json::json!({
            "task": task_text(),
            "grants": grants
        })
        .to_string(),
    )
    .unwrap();
    let profile = base.join("profile.json");
    std::fs::write(
        &profile,
        serde_json::json!({
            "profile_version": 1,
            "id": format!("live-delegate-{name}"),
            "model": env("RUSTYHARNESS_EXIT_MODEL"),
            "context_window": 32768,
            "fill_ratio": 0.6,
            "protocol": "text",
            "tool_choice_required_ok": false,
            "grammar": "none",
            "max_active_tools": 6,
            "edit_format": "replace",
            "recent_turns": 5,
            "sampling": {"temperature": 0.2, "top_p": 0.95, "seed": 7, "max_tokens": 8192}
        })
        .to_string(),
    )
    .unwrap();
    Fx {
        state,
        ws,
        task,
        profile,
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
        .env_remove("GATE_OK_FILE")
        .output()
        .unwrap()
}

fn last_line(o: &Output) -> serde_json::Value {
    let out = String::from_utf8(o.stdout.clone()).unwrap();
    serde_json::from_str(out.lines().last().unwrap()).unwrap()
}

/// The run id from the summary line, which starts with `run ` — helper
/// lines (`[helper] started (run ...)`) also name run ids, so a plain
/// substring search would find the wrong one.
fn run_id_of(stderr: &str) -> String {
    let line = stderr
        .lines()
        .find(|l| l.starts_with("run "))
        .unwrap_or_else(|| panic!("no `run ...` summary line in:\n{stderr}"));
    line[4..36].to_owned()
}

fn chain_head_of(stdout: &str) -> String {
    stdout
        .lines()
        .find(|l| l.starts_with("chain_head "))
        .unwrap_or_else(|| panic!("no chain_head line in:\n{stdout}"))["chain_head ".len()..]
        .to_owned()
}

fn journal_of(state: &Path, run_id: &str) -> harness_journal::Verified {
    let attempt = state.join("runs").join(run_id).join("attempt-1");
    harness_journal::JournalReader::open(&attempt).unwrap()
}

fn submit_note(v: &harness_journal::Verified) -> String {
    v.records
        .iter()
        .find(|r| r.kind == harness_journal::EventKind::SubmitRequested)
        .map(|r| r.body["note"]["inline"].as_str().unwrap_or("").to_owned())
        .unwrap_or_default()
}

/// The parent's own spend, counted the way the minibench counts: one step
/// per `ModelReplied`, tokens summed over every reply's usage.
fn parent_tallies(v: &harness_journal::Verified) -> (u64, u64) {
    let mut steps = 0;
    let mut tokens = 0;
    for r in &v.records {
        if r.kind == harness_journal::EventKind::ModelReplied {
            steps += 1;
            if let Some(usage) = r.body.get("usage") {
                tokens += usage["input"].as_u64().unwrap_or(0);
                tokens += usage["output"].as_u64().unwrap_or(0);
            }
        }
    }
    (steps, tokens)
}

/// The helpers' spend, read from the parent's `ChildRun` records.
fn child_tallies(v: &harness_journal::Verified) -> (u64, u64, u64) {
    let mut runs = 0;
    let mut steps = 0;
    let mut tokens = 0;
    for r in &v.records {
        if r.kind == harness_journal::EventKind::ChildRun {
            runs += 1;
            steps += r.body["spent"]["steps"].as_u64().unwrap_or(0);
            tokens += r.body["spent"]["tokens_in"].as_u64().unwrap_or(0);
            tokens += r.body["spent"]["tokens_out"].as_u64().unwrap_or(0);
        }
    }
    (runs, steps, tokens)
}

/// One full variant: run the task, return (run id, chain head, journal).
fn run_variant(grants: &[&str]) -> (Fx, String, String, harness_journal::Verified) {
    let name = if grants.contains(&"harness.task.delegate") {
        "delegate"
    } else {
        "inline"
    };
    let endpoint = env("RUSTYHARNESS_EXIT_ENDPOINT");
    let fx = fixture(name, grants);
    let (task, ws, state, profile) = (
        fx.task.to_str().unwrap(),
        fx.ws.to_str().unwrap(),
        fx.state.to_str().unwrap(),
        fx.profile.to_str().unwrap(),
    );
    let o = run(&[
        "run",
        "--task",
        task,
        "--workspace",
        ws,
        "--state-root",
        state,
        "--profile",
        profile,
        "--endpoint",
        &endpoint,
    ]);
    let stderr = String::from_utf8_lossy(&o.stderr).into_owned();
    eprintln!("--- {name} run stderr ---\n{stderr}");
    assert_eq!(o.status.code(), Some(5), "{stderr}");
    let report = last_line(&o);
    assert_eq!(report["outcome"]["Indeterminate"]["why"], "NothingChecked");
    assert_eq!(
        report["findings"][0]["observed"], "stopped: submitted; no checks planned",
        "the task must end with a submit: {report}"
    );
    assert!(stderr.contains("stopped (submitted)"), "{stderr}");
    let run_id = run_id_of(&stderr);
    let chain_head = chain_head_of(&String::from_utf8(o.stdout.clone()).unwrap());
    let v = journal_of(&fx.state, &run_id);
    assert!(
        submit_note(&v).contains(CODENAME),
        "the current codename was not submitted: {:?}",
        submit_note(&v)
    );
    (fx, run_id, chain_head, v)
}

#[test]
#[ignore = "needs a local model server: set RUSTYHARNESS_EXIT_ENDPOINT and RUSTYHARNESS_EXIT_MODEL"]
fn live_delegate_answers_fixture_question_and_audits() {
    let (fx, run_id, chain_head, v) = run_variant(DELEGATE_GRANTS);

    // The helper really ran, and its spend is recorded in the parent.
    let (runs, child_steps, _child_tokens) = child_tallies(&v);
    assert!(runs >= 1, "no ChildRun record in the parent journal");
    assert!(child_steps >= 1, "the helper ran no steps");
    for r in &v.records {
        if r.kind == harness_journal::EventKind::ChildRun {
            let limit = r.body["limits"]["steps"].as_u64().unwrap_or(0);
            assert!(
                (1..=15).contains(&limit),
                "the helper's step carve must be within the 15-step cap: {limit}"
            );
            assert!(
                r.body["spent"]["steps"].as_u64().unwrap_or(0) >= 1,
                "the helper's spend is recorded"
            );
        }
    }

    // Replay, anchored: the parent's records match and every helper is
    // audited with the run.
    let profile = fx.profile.to_str().unwrap();
    let state = fx.state.to_str().unwrap();
    let task = fx.task.to_str().unwrap();
    let r = run(&[
        "replay",
        "--run",
        &run_id,
        "--task",
        task,
        "--state-root",
        state,
        "--profile",
        profile,
        "--anchor",
        &chain_head,
    ]);
    let rs = String::from_utf8_lossy(&r.stderr).into_owned();
    eprintln!("--- delegate replay stderr ---\n{rs}");
    assert_eq!(r.status.code(), Some(5));
    assert_eq!(
        last_line(&r)["outcome"]["Indeterminate"]["why"],
        "NothingChecked"
    );
    assert!(
        rs.contains("child run ") && rs.contains("anchored, no divergence"),
        "each helper is audited and vouched for: {rs}"
    );
    assert!(
        rs.contains("The anchor matched the journal's chain head."),
        "{rs}"
    );
}

#[test]
#[ignore = "needs a local model server: set RUSTYHARNESS_EXIT_ENDPOINT and RUSTYHARNESS_EXIT_MODEL"]
fn live_delegate_vs_inline_usage_recorded() {
    // Without the grant: no helper can run.
    let (fx_inline, run_inline, head_inline, v_inline) = run_variant(INLINE_GRANTS);
    let (p_steps, p_tokens) = parent_tallies(&v_inline);
    let (c_runs, _c_steps, _c_tokens) = child_tallies(&v_inline);
    assert_eq!(c_runs, 0, "no delegate grant, yet helpers ran");

    // With the grant: the helper runs, the parent stays within its carve.
    let (fx_del, run_del, head_del, v_del) = run_variant(DELEGATE_GRANTS);
    let (d_steps, d_tokens) = parent_tallies(&v_del);
    let (dc_runs, dc_steps, dc_tokens) = child_tallies(&v_del);
    assert!(dc_runs >= 1, "the delegate grant did not produce helpers");
    assert!(dc_steps >= 1, "the helper ran no steps");

    // Both variants replay anchored, helpers audited with the parent.
    for (fx, run_id, head, label) in [
        (&fx_inline, &run_inline, &head_inline, "inline"),
        (&fx_del, &run_del, &head_del, "delegate"),
    ] {
        let r = run(&[
            "replay",
            "--run",
            run_id,
            "--task",
            fx.task.to_str().unwrap(),
            "--state-root",
            fx.state.to_str().unwrap(),
            "--profile",
            fx.profile.to_str().unwrap(),
            "--anchor",
            head,
        ]);
        let rs = String::from_utf8_lossy(&r.stderr).into_owned();
        eprintln!("--- {label} replay stderr ---\n{rs}");
        assert_eq!(r.status.code(), Some(5), "{rs}");
        assert!(
            rs.contains("The anchor matched the journal's chain head."),
            "{rs}"
        );
    }

    // The measured numbers, for the slice note to quote.
    let header = "variant\tdelegate_granted\thelper_runs\tdelegated\tsubmitted\tparent_steps\tparent_tokens\thelper_steps\thelper_tokens";
    let rows = [
        format!("inline\tno\t0\tno\tyes\t{p_steps}\t{p_tokens}\t0\t0"),
        format!(
            "delegate\tyes\t{dc_runs}\tyes\tyes\t{d_steps}\t{d_tokens}\t{dc_steps}\t{dc_tokens}"
        ),
    ];
    let tsv = format!("{header}\n{}\n{}\n", rows[0], rows[1]);
    eprintln!("--- live-delegate usage TSV ---\n{tsv}");
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("live-delegate-usage.tsv");
    std::fs::write(&out, &tsv).unwrap();
}

#[test]
fn readme_mentions_delegate_grant_limits() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../README.md");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    // Match over reflowed lines: compare on whitespace-normalized text.
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    for pin in [
        "`harness.task.delegate`",
        "never by default",
        "read-only helper",
        "no edits, no commands, no helper of its own",
        "at most 15 steps",
        "at most 5 helpers",
        "at most 200 000 tokens",
        "10 minutes",
        "untrusted",
        "audits the helpers with the run",
    ] {
        assert!(
            text.contains(pin),
            "{} must mention {pin:?} in its Try-it section",
            path.display()
        );
    }
}
