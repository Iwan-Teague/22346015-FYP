//! The verb dispatch: [`main_with`] is one match with one line per verb,
//! and the gate-child plumbing that turns `rest` into options, an
//! [`Outcome`](crate::report::Outcome) and an exit code.

use std::collections::BTreeMap;

use gate_outcome::GateId;

use crate::args::{options, USAGE};
use crate::cmd_doctor::doctor;
use crate::cmd_events::events;
use crate::cmd_gc::gc;
use crate::cmd_manifest::manifest_check;
use crate::cmd_profile::{profile_check, profile_init};
use crate::cmd_replay::replay;
use crate::cmd_run::run_or_resume;
use crate::cmd_sessions::sessions;
use crate::report::{emit, exit, refused};
use crate::Cx;

/// The gate id the report names when `--gate` is not given.
const DEFAULT_GATE: &str = "rustyharness.run";

/// The options that are flags, not `--key value` pairs (P-11; P-12 added
/// `no-default-denies`).
pub(crate) const VALUELESS: &[&str] = &["shell", "no-default-denies"];

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verb {
    Run,
    Resume,
    Replay,
}

/// Run the command line `args` (without the program name). Returns the
/// process exit code.
pub fn main_with(cx: &Cx<'_>, args: &[&str]) -> u8 {
    match args {
        ["version"] => {
            say!(cx, "rustyharness {}", env!("CARGO_PKG_VERSION"));
            0
        }
        ["sandbox"] => match harness_sandbox::require() {
            Ok(b) => {
                say!(cx, "confinement available: {b:?}");
                0
            }
            Err(e) => {
                note!(cx, "{e}");
                3
            }
        },
        ["doctor", rest @ ..] => doctor(cx, rest),
        ["manifest", "check", path] => manifest_check(cx, path),
        ["run", rest @ ..] => gate_child(cx, rest, Verb::Run),
        ["resume", rest @ ..] => gate_child(cx, rest, Verb::Resume),
        ["replay", rest @ ..] => gate_child(cx, rest, Verb::Replay),
        ["events", rest @ ..] => events(cx, rest),
        ["profile", "check", rest @ ..] => profile_check(cx, rest),
        ["profile", "init", rest @ ..] => profile_init(cx, rest),
        ["sessions", rest @ ..] => sessions(cx, rest),
        ["gc", rest @ ..] => gc(cx, rest),
        ["schedule", rest @ ..] => crate::cmd_schedule::schedule(cx, rest),
        ["chat", rest @ ..] => crate::cmd_chat::chat(cx, rest),
        _ => {
            note!(cx, "{USAGE}");
            exit::USAGE
        }
    }
}

fn gate_child(cx: &Cx<'_>, rest: &[&str], verb: Verb) -> u8 {
    let allowed: &[&str] = match verb {
        Verb::Run => &[
            "task",
            "workspace",
            "state-root",
            "profile",
            "endpoint",
            "policy",
            "gate",
            "output",
            "allow-exec",
            "preset",
            "shell",
            "no-default-denies",
        ],
        Verb::Resume => &[
            "run",
            "task",
            "workspace",
            "state-root",
            "profile",
            "endpoint",
            "policy",
            "gate",
            "output",
            "allow-exec",
            "preset",
            "shell",
            "no-default-denies",
        ],
        Verb::Replay => &[
            "run",
            "task",
            "state-root",
            "profile",
            "attempt",
            "anchor",
            "policy",
            "gate",
            "allow-exec",
            "preset",
            "shell",
            "no-default-denies",
        ],
    };
    let parsed = options(rest, allowed, VALUELESS);
    let gate_text = parsed
        .as_ref()
        .ok()
        .and_then(|o| o.get("gate").copied())
        .unwrap_or(DEFAULT_GATE);
    // An invalid --gate is a usage error like any other, reported under
    // the default id (H1e-2b review F-3): the report line is never missing.
    let (gate, bad_gate) = match GateId::new(gate_text) {
        Ok(g) => (g, false),
        Err(_) => match GateId::new(DEFAULT_GATE) {
            Ok(g) => (g, true),
            Err(_) => return exit::USAGE,
        },
    };
    if bad_gate {
        note!(cx, "--gate is not a valid gate id\n{USAGE}");
        return emit(
            cx,
            &gate,
            refused(exit::USAGE, "--gate is not a valid gate id".into()),
        );
    }
    // The user's config file, once per command (P-07): flags override it.
    // A file that is there but unusable is unreadable input (exit 4), and
    // the report line is never missing.
    let cfg = match crate::config::load() {
        Ok(c) => c,
        Err(e) => {
            note!(cx, "{e}");
            return emit(cx, &gate, refused(exit::UNREADABLE_INPUT, e));
        }
    };
    let result = match parsed {
        Err(e) => {
            note!(cx, "{e}\n{USAGE}");
            refused(exit::USAGE, "usage error".into())
        }
        Ok(o) => {
            // The run bundle (P-14): before a `run`-family verb reads its
            // inputs, fill the flags it left unset from
            // `runs/<id>/inputs/`. Flags and config still win, and what
            // they choose must digest to the bundle's recorded values.
            let mut owned: BTreeMap<&str, String> =
                o.into_iter().map(|(k, v)| (k, v.to_owned())).collect();
            if let Err(x) = crate::bundle::fill(cx, &mut owned, &cfg) {
                return emit(cx, &gate, x);
            }
            let filled: BTreeMap<&str, &str> =
                owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
            match verb {
                Verb::Run | Verb::Resume => run_or_resume(cx, &filled, verb, &cfg),
                Verb::Replay => replay(cx, &filled, &cfg),
            }
        }
    };
    emit(cx, &gate, result)
}
