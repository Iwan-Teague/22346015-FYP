//! The `rh-dev` binary: argv dispatch to the verb modules. No logic here —
//! each verb owns its own options, output and exit codes (`linux` in
//! [`rh_dev::linux`]); this file only routes the first word and turns a
//! usage error into exit 2 with the verb's usage text on stderr.

#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

use rh_dev::linux;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr().lock();
    let code = match args.split_first() {
        Some((&"linux", rest)) => match linux::parse_args(rest) {
            Ok(opts) => linux::run(&opts, &mut out, &mut err),
            Err(usage) => {
                let _ = write!(err, "{usage}");
                linux::code::USAGE
            }
        },
        _ => {
            let _ = write!(
                err,
                "usage: rh-dev <verb> …

verbs:
  linux    run the Linux conformance suite in the UTM VM over ssh

{}",
                linux::USAGE
            );
            linux::code::USAGE
        }
    };
    ExitCode::from(code as u8)
}
