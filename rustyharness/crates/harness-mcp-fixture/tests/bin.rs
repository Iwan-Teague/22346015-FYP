//! The `rh-mcp-fixture` BINARY over real pipes (P-37 design note §14):
//! Cargo exposes `CARGO_BIN_EXE_rh-mcp-fixture` only to this crate's own
//! integration tests, so the newline framing the MCP stdio transport
//! needs is proven here, against the built binary, not just the lib.
//! These are plain std spawns of a test binary (purity §2f allows tests
//! to spawn; the confined end-to-end runs that go through
//! `SystemConfinement` land with P-37l).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_rh-mcp-fixture");

#[test]
fn fixture_bin_speaks_newline_json() {
    let mut child = Command::new(BIN)
        .args(["--mode", "ok"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("fixture binary spawns");
    let mut stdin = child.stdin.take().expect("stdin piped");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout piped"));

    // initialize: one line in, exactly one newline-terminated JSON object
    // line out, no \r anywhere (a transport may refuse it, §3.1).
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-06-18","capabilities":{{}},"clientInfo":{{"name":"t","version":"0"}}}}}}"#
    )
    .expect("initialize writes");
    stdin.flush().expect("initialize flushes");
    let mut line = String::new();
    stdout
        .read_line(&mut line)
        .expect("initialize answer reads");
    assert!(line.ends_with('\n'), "the answer is one newline frame");
    assert!(!line.contains('\r'), "no carriage return on the wire");
    let init: serde_json::Value =
        serde_json::from_str(line.trim_end()).expect("the answer line is one JSON object");
    assert_eq!(init.get("id"), Some(&serde_json::json!(1)));
    assert_eq!(
        init["result"]
            .get("protocolVersion")
            .and_then(serde_json::Value::as_str),
        Some("2025-06-18")
    );

    // tools/list: the second line is again exactly one JSON object.
    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list"}}"#)
        .expect("tools/list writes");
    stdin.flush().expect("tools/list flushes");
    let mut line = String::new();
    stdout.read_line(&mut line).expect("list answer reads");
    let list: serde_json::Value =
        serde_json::from_str(line.trim_end()).expect("the list line is one JSON object");
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|t| {
            t.get("name")
                .and_then(serde_json::Value::as_str)
                .expect("name")
        })
        .collect();
    assert_eq!(names, vec!["echo", "add"]);

    // Clean end: closing stdin ends the server with status 0.
    drop(stdin);
    let status = child.wait().expect("fixture waits");
    assert!(status.success(), "the fixture exits 0 at end of input");
    // Nothing is left buffered: stdout is at EOF.
    let mut rest = Vec::new();
    stdout.read_to_end(&mut rest).expect("stdout drains");
    assert!(rest.is_empty(), "no extra bytes after the frames");
}

#[test]
fn fixture_bin_refuses_unknown_mode_and_missing_mode() {
    for args in [
        vec!["--mode", "nope"],
        vec![],
        vec!["--mode"],
        vec!["--what"],
    ] {
        let out = Command::new(BIN)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("fixture binary runs");
        assert_eq!(out.status.code(), Some(2), "args {args:?} refuse with 2");
        assert!(
            !out.stdout.is_empty() || !out.stderr.is_empty(),
            "args {args:?} print a usage line"
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("usage:") || err.contains("unknown"),
            "args {args:?} explain the refusal: {err}"
        );
    }
}
