//! The `confinement-probe` tool: a fake tool that deliberately tries the
//! things a confined MCP server must never manage (P-37 design note §14)
//! and reports each attempt as one text line, so an end-to-end test can
//! assert every line says the attempt was refused.
//!
//! The probe is deliberately permissive about its input (it is hostile
//! server code, not harness code): it honours extra targets from the
//! call's arguments and adds fixed attempts of its own. Everything is
//! bounded: at most 8 extra targets per kind and 200 bytes per path.

use std::io::Write as _;
use std::net::TcpStream;
use std::path::Path;

use serde_json::Value;

/// How many extra targets of each kind the arguments may name.
const MAX_EXTRAS: usize = 8;

/// How many bytes of one target to echo back in a report line.
const MAX_TARGET_CHARS: usize = 200;

/// Runs every attempt and returns the report text (one line per attempt,
/// `\n`-joined, no trailing newline). Fixed attempts first, then the
/// argument-named extras:
///
/// 1. write `$HOME/rh-fixture-canary-write` (a write into HOME);
/// 2. read `$HOME/rh-fixture-canary` (a canary a test plants in HOME);
/// 3. write `./rh-fixture-workspace-canary` (cwd; confined, cwd is the
///    server's scratch dir, never the workspace);
/// 4. connect `1.1.1.1:443` (an internet route);
/// 5. the arguments' `write`, `read` and `connect` arrays, in that order.
pub fn report(args: &Value) -> String {
    let mut lines: Vec<String> = Vec::new();

    match std::env::var("HOME") {
        Err(_) => lines.push("home (no HOME set): skipped".to_owned()),
        Ok(home) => {
            let write_path = Path::new(&home).join("rh-fixture-canary-write");
            lines.push(write_line("home-write", &write_path));
            let read_path = Path::new(&home).join("rh-fixture-canary");
            lines.push(read_line("home-read", &read_path));
        }
    }
    lines.push(write_line(
        "cwd-write",
        Path::new("./rh-fixture-workspace-canary"),
    ));
    lines.push(connect_line("1.1.1.1:443"));

    for path in string_args(args, "write") {
        lines.push(write_line("arg-write", Path::new(&path)));
    }
    for path in string_args(args, "read") {
        lines.push(read_line("arg-read", Path::new(&path)));
    }
    for addr in string_args(args, "connect") {
        lines.push(connect_line(&addr));
    }
    lines.join("\n")
}

/// The call arguments' `name` array, capped and sanitised: non-strings
/// and over-long strings are skipped, extras past the cap are dropped.
fn string_args(args: &Value, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(list) = args.get(name).and_then(Value::as_array) else {
        return out;
    };
    for item in list {
        if out.len() >= MAX_EXTRAS {
            break;
        }
        if let Some(s) = item.as_str() {
            if s.len() <= MAX_TARGET_CHARS {
                out.push(s.to_owned());
            }
        }
    }
    out
}

/// Tries to create/overwrite `path`; reports `ok` or the io error's kind.
fn write_line(kind: &str, path: &Path) -> String {
    match std::fs::write(path, b"rh-mcp-fixture probe") {
        Ok(()) => format!("{kind} {} ok", display(path)),
        Err(e) => format!("{kind} {} refused ({})", display(path), e.kind()),
    }
}

/// Tries to read `path`; reports `ok`, `refused` (io error) or `missing`.
fn read_line(kind: &str, path: &Path) -> String {
    match std::fs::read(path) {
        Ok(bytes) => format!("{kind} {} ok ({} bytes)", display(path), bytes.len()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            format!("{kind} {} missing", display(path))
        }
        Err(e) => format!("{kind} {} refused ({})", display(path), e.kind()),
    }
}

/// Tries one TCP connect; reports `ok` or the io error's kind.
fn connect_line(addr: &str) -> String {
    match addr.parse::<std::net::SocketAddr>() {
        Ok(target) => match TcpStream::connect(target) {
            Ok(mut stream) => {
                // Leave immediately; a successful connect is all the
                // report needs. A failed shutdown is still `ok`.
                let _ = stream.flush();
                format!("connect {addr} ok")
            }
            Err(e) => format!("connect {addr} refused ({})", e.kind()),
        },
        Err(_) => format!("connect {addr} refused (unparseable)"),
    }
}

/// The path as text, cut at [`MAX_TARGET_CHARS`] characters.
fn display(path: &Path) -> String {
    let shown: String = path.display().to_string();
    if shown.chars().count() <= MAX_TARGET_CHARS {
        shown
    } else {
        shown.chars().take(MAX_TARGET_CHARS).collect()
    }
}
