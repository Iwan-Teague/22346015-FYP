//! `--help` (P-58): every verb path the dispatch answers prints usage
//! text and exits 0; anything else keeps the ordinary usage error.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_rustyharness");

/// The verb paths `main_with` answers, exactly as [`is_verb_path`] names
/// them (the test holds the line from the other side: a verb dropped
/// from the dispatch still passes here, but a new verb without `--help`
/// wiring fails the unit test beside the dispatch).
#[test]
fn help_for_each_verb_exits_zero() {
    let paths: &[&[&str]] = &[
        &["--help"],
        &["version"],
        &["sandbox"],
        &["doctor"],
        &["run"],
        &["resume"],
        &["replay"],
        &["events"],
        &["review"],
        &["apply"],
        &["sessions"],
        &["gc"],
        &["chat"],
        &["acp"],
        &["compare"],
        &["manifest"],
        &["manifest", "check"],
        &["profile"],
        &["profile", "check"],
        &["profile", "init"],
        &["schedule"],
        &["schedule", "add"],
        &["schedule", "list"],
        &["schedule", "remove"],
        &["schedule", "run-now"],
        &["compare", "reveal"],
    ];
    for path in paths {
        let mut cmd = Command::new(BIN);
        if *path != ["--help"] {
            cmd.args(*path).arg("--help");
        } else {
            cmd.arg("--help");
        }
        let out = cmd.output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "`{} --help` did not exit 0 (stderr: {})",
            path.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(
            text.contains("rustyharness"),
            "`{} --help` printed no usage text",
            path.join(" ")
        );
        if path.len() == 1 && path[0] != "--help" {
            assert!(
                text.contains(&format!("rustyharness {}", path[0])),
                "`{} --help` does not name the verb",
                path.join(" ")
            );
        }
    }
}

/// `--help` after anything that is not a verb path keeps the ordinary
/// usage error (fail closed): an unknown verb, and a real verb with
/// options after it, exit 2.
#[test]
fn help_anywhere_else_stays_a_usage_error() {
    // Hermetic config: the gate child reads the user's config file
    // before it reports a parse error.
    let config_home = std::env::temp_dir().join(format!("rh-help-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&config_home);
    for args in [
        vec!["bogus", "--help"],
        vec!["run", "--task", "x", "--help"],
    ] {
        let out = Command::new(BIN)
            .args(&args)
            .env("RUSTYHARNESS_CONFIG_HOME", &config_home)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "`{}` should be a usage error",
            args.join(" ")
        );
    }
}
