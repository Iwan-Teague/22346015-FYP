//! AQ-194 r59 F-1/F-2: `detect` and `status` must never present an
//! all-uncontained journal as if it were a sandboxed one. These run the real
//! binary so the refusals, the `!!` banner and the per-line `(UNCONTAINED)`
//! label are asserted on actual CLI output.
//!
//! On the pre-fix code both tests fail: `detect` exited 0 with unlabelled
//! verdicts, and `status` printed no containment line at all.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

const OK_ORACLE: &str = r#"{"apply_ok":true,"compile_ok":true,"error_codes":[],"warn_count":0,"behavior":{"unit":null,"property":null,"differential":null,"score":1.0},"constraint":{"alloc_ok":null,"clippy_clean":null,"fmt_ok":null,"unsafe_blocks":null,"unsafe_ok":null,"paths_ok":null,"violations":[],"score":null},"score":1.0,"failure_class":"none","flags":[]}"#;

/// One paired family (index-0 core + index-0 probe in epoch `e1`), every row
/// carrying the given `sandbox` value.
fn paired_journal(name: &str, sandbox: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rustybench-cli-it-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("j.jsonl");
    let mut f = std::fs::File::create(&p).unwrap();
    for kind in ["core", "probe"] {
        writeln!(
            f,
            "{{\"task_id\":\"fam/0\",\"category\":\"c\",\"kind\":\"{kind}\",\
             \"index\":0,\"epoch\":\"e1\",\"sandbox\":\"{sandbox}\",\
             \"oracle\":{OK_ORACLE}}}"
        )
        .unwrap();
    }
    p
}

fn rustybench() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rustybench"))
}

#[test]
fn detect_refuses_uncontained_and_labels_when_opted_in() {
    let j = paired_journal("detect", "unsupported");

    let out = rustybench()
        .args(["detect", "--journal"])
        .arg(&j)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "all-uncontained detect must refuse without --allow-uncontained"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--allow-uncontained"),
        "refusal must name the opt-in flag, got: {err}"
    );

    let out = rustybench()
        .args(["detect", "--journal"])
        .arg(&j)
        .arg("--allow-uncontained")
        .output()
        .unwrap();
    assert!(out.status.success(), "opt-in detect must run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("!! UNCONTAINED"),
        "opt-in detect must print the banner, got: {stdout}"
    );
    assert!(
        stdout.contains("(no significant core advantage) (UNCONTAINED)"),
        "every verdict line must carry the UNCONTAINED suffix, got: {stdout}"
    );
    let _ = std::fs::remove_dir_all(j.parent().unwrap());
}

#[test]
fn status_labels_uncontained_journal_and_is_quiet_for_contained() {
    let j = paired_journal("status", "unsupported");

    let out = rustybench()
        .args(["status", "--journal"])
        .arg(&j)
        .output()
        .unwrap();
    assert!(out.status.success(), "status is a read-only readout");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("!! UNCONTAINED"),
        "status must label an uncontained journal, got: {stdout}"
    );
    let _ = std::fs::remove_dir_all(j.parent().unwrap());

    let j = paired_journal("status-contained", "seatbelt");
    let out = rustybench()
        .args(["status", "--journal"])
        .arg(&j)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("!!") && !stdout.contains("UNCONTAINED"),
        "contained status carries no label, got: {stdout}"
    );
    let _ = std::fs::remove_dir_all(j.parent().unwrap());
}
