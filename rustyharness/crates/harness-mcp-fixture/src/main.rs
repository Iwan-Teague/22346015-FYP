//! The `rh-mcp-fixture` binary: [`harness_mcp_fixture::serve`] over real
//! stdin and stdout, with the mode named by `--mode <m>` (P-37 design
//! note §14). Stderr stays the fixture's own (the `stderr-spam` mode
//! writes there on purpose). End-to-end tests spawn this binary with
//! `CARGO_BIN_EXE_rh-mcp-fixture`.

#![forbid(unsafe_code)]

use std::io::Write as _;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut mode: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => match args.next() {
                Some(m) => mode = Some(m),
                None => return usage(),
            },
            other => {
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "rh-mcp-fixture: unknown argument {other:?}"
                );
                return usage();
            }
        }
    }
    let Some(mode) = mode else {
        return usage();
    };
    // An unknown mode name is a usage error (exit 2), not a serving error.
    if harness_mcp_fixture::Mode::parse(&mode).is_err() {
        let _ = writeln!(
            std::io::stderr().lock(),
            "rh-mcp-fixture: unknown mode {mode:?}"
        );
        return usage();
    }
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    match harness_mcp_fixture::serve(&mode, stdin.lock(), stdout.lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(std::io::stderr().lock(), "rh-mcp-fixture: {e}");
            ExitCode::from(1)
        }
    }
}

/// The usage refusal: exit 2, one stderr line, no serving.
fn usage() -> ExitCode {
    let _ = writeln!(
        std::io::stderr().lock(),
        "usage: rh-mcp-fixture --mode <mode>"
    );
    ExitCode::from(2)
}
