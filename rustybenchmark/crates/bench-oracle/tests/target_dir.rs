//! `grade` must build inside the grading workspace whatever `CARGO_TARGET_DIR` the harness's own
//! environment carries. A global `CARGO_TARGET_DIR` is common (it is how most Rust developers keep
//! `target/` off their project trees); inherited by every graded workspace it makes unrelated units
//! share artifacts, and puts the build outside the only directory the sandbox lets it write to.
//! This file is one test so it owns its process (and therefore its environment).

use bench_core::{Instance, OracleWeights};
use bench_oracle::{grade, GradeSpec};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn instance() -> Instance {
    let mut files = BTreeMap::new();
    files.insert(
        PathBuf::from("Cargo.toml"),
        "[package]\nname = \"tdfix\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[workspace]\n"
            .to_string(),
    );
    Instance {
        prompt: String::new(),
        files,
        hidden: BTreeMap::new(),
        canary: String::new(),
    }
}

#[test]
fn grade_builds_in_the_workspace_even_when_cargo_target_dir_is_set() {
    let base = std::env::temp_dir().join(format!("rb-target-dir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let foreign = base.join("shared-target");
    let ws = base.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    std::env::set_var("CARGO_TARGET_DIR", &foreign);

    let spec = GradeSpec {
        answer_path: Path::new("src/lib.rs"),
        weights: &OracleWeights::default(),
        behavior_test: None,
        differential_test: None,
        alloc_test: None,
        limits: bench_sandbox::Limits::default(),
        max_unsafe: None,
        forbidden_paths: Vec::new(),
        check_clippy: false,
        clippy_allow: Vec::new(),
        check_miri: false,
    };
    let v = grade(
        &instance(),
        "```rust\npub fn answer() -> i32 { 42 }\n```",
        &spec,
        &ws,
    )
    .unwrap();
    assert!(v.apply_ok && v.compile_ok, "{v:?}");
    assert!(
        ws.join("target").join("debug").exists(),
        "the build must land in the grading workspace"
    );
    assert!(
        !foreign.exists(),
        "an inherited CARGO_TARGET_DIR must not receive graded builds"
    );
    let _ = std::fs::remove_dir_all(&base);
}
