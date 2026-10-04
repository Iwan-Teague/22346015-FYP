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
use crate::cmd_review::review;
use crate::cmd_run::run_or_resume;
use crate::cmd_sessions::sessions;
use crate::report::{emit, exit, refused};
use crate::Cx;

/// The gate id the report names when `--gate` is not given.
const DEFAULT_GATE: &str = "rustyharness.run";

/// The verbs `main_with` dispatches, as their first command-line tokens
/// (H-A: one line per verb). `manifest`, `profile`, `schedule` and
/// `compare` take a subverb. Keep in step with the match below and with
/// USAGE (`args`): `every_dispatch_verb_has_usage_text` holds the line.
const VERBS: &[&str] = &[
    "version", "sandbox", "doctor", "manifest", "run", "resume", "replay", "events", "review",
    "apply", "profile", "sessions", "gc", "schedule", "chat", "acp", "compare",
];

/// The options that are flags, not `--key value` pairs (P-11; P-12 added
/// `no-default-denies`; P-23 added the session-grant flags).
pub(crate) const VALUELESS: &[&str] = &[
    "shell",
    "no-default-denies",
    "allow-session-grants",
    "accept-edits",
];

/// The gate children's options, verb by verb (the `--key value` pairs),
/// and [`RUN_FLAGS`]/[`RESUME_FLAGS`], their valueless flags. The
/// usage-completeness tests read these against USAGE, so a new option
/// with no usage line fails a test, not a user.
const RUN_ALLOWED: &[&str] = &[
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
    "allow-session-grants",
    "accept-edits",
    "workspace-mode",
    "allow-port",
    "allow-lan-port",
];
const RESUME_ALLOWED: &[&str] = &[
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
    "allow-session-grants",
    "accept-edits",
    "allow-port",
    "allow-lan-port",
];
const REPLAY_ALLOWED: &[&str] = &[
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
    "accept-edits",
    "allow-port",
    "allow-lan-port",
];

/// `scratch-with-git` (P-52) goes with `--workspace-mode scratch`, which
/// only a run may take; replay has no workspace to copy. `bg-persist`
/// (P-36g) is a run's or a resume's choice about its own processes. The
/// session-grant flags are [`VALUELESS`].
const RUN_FLAGS: &[&str] = &[
    "shell",
    "no-default-denies",
    "allow-session-grants",
    "accept-edits",
    "scratch-with-git",
    "bg-persist",
];
const RESUME_FLAGS: &[&str] = &[
    "shell",
    "no-default-denies",
    "allow-session-grants",
    "accept-edits",
    "bg-persist",
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verb {
    Run,
    Resume,
    Replay,
}

/// Run the command line `args` (without the program name). Returns the
/// process exit code.
pub fn main_with(cx: &Cx<'_>, args: &[&str]) -> u8 {
    // `--help` is answered before anything is read (P-58): bare, after a
    // verb, or after a verb and its subverb. Anything else with `--help`
    // first falls through to the ordinary usage error.
    match args {
        ["--help"] | ["-h"] => {
            say!(cx, "{USAGE}");
            return 0;
        }
        [v @ .., "--help"] if v.len() <= 2 && is_verb_path(v) => {
            say!(
                cx,
                "{}",
                crate::args::help_for(v).unwrap_or_else(|| USAGE.to_owned())
            );
            return 0;
        }
        _ => {}
    }
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
        ["review", rest @ ..] => review(cx, rest),
        ["apply", rest @ ..] => crate::cmd_apply::apply(cx, rest),
        ["profile", "check", rest @ ..] => profile_check(cx, rest),
        ["profile", "init", rest @ ..] => profile_init(cx, rest),
        ["sessions", rest @ ..] => sessions(cx, rest),
        ["gc", rest @ ..] => gc(cx, rest),
        ["schedule", rest @ ..] => crate::cmd_schedule::schedule(cx, rest),
        ["chat", rest @ ..] => crate::cmd_chat::chat(cx, rest),
        ["acp", rest @ ..] => crate::cmd_acp::acp(cx, rest),
        ["compare", rest @ ..] => crate::cmd_compare::compare(cx, rest),
        _ => {
            note!(cx, "{USAGE}");
            exit::USAGE
        }
    }
}

/// A verb path `--help` answers (P-58): a verb from [`VERBS`], or one of
/// its subverbs. Anything else keeps the ordinary dispatch — an unknown
/// verb asked for `--help` stays a usage error (fail closed).
fn is_verb_path(path: &[&str]) -> bool {
    match path {
        ["manifest", "check"] | ["profile", "check"] | ["profile", "init"] => true,
        ["schedule", "add" | "list" | "remove" | "run-now"] => true,
        ["compare", "reveal"] => true,
        [v] => VERBS.contains(v),
        _ => false,
    }
}

fn gate_child(cx: &Cx<'_>, rest: &[&str], verb: Verb) -> u8 {
    let allowed: &[&str] = match verb {
        Verb::Run => RUN_ALLOWED,
        Verb::Resume => RESUME_ALLOWED,
        Verb::Replay => REPLAY_ALLOWED,
    };
    let valueless: &[&str] = match verb {
        Verb::Run => RUN_FLAGS,
        Verb::Resume => RESUME_FLAGS,
        Verb::Replay => VALUELESS,
    };
    let parsed = options(rest, allowed, valueless);
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

#[cfg(test)]
mod tests {
    use super::{is_verb_path, RESUME_FLAGS, RUN_ALLOWED, RUN_FLAGS, VERBS};
    use crate::args::{help_for, options, USAGE};

    /// P-58: every verb the dispatch answers names itself in USAGE, so a
    /// new verb without a usage line fails here, not at a terminal.
    #[test]
    fn every_dispatch_verb_has_usage_text() {
        for verb in VERBS {
            let needle = format!("rustyharness {verb}");
            assert!(
                USAGE.lines().any(|l| l.trim_start().starts_with(&needle)),
                "USAGE has no synopsis line for {verb}"
            );
        }
    }

    /// P-58: every option `run` and `chat` accept appears in USAGE, and
    /// so do the chat-only resume/fork spellings.
    #[test]
    fn usage_mentions_every_flag_of_chat_and_run() {
        for flag in RUN_ALLOWED
            .iter()
            .chain(RUN_FLAGS)
            .chain(crate::cmd_chat::ALLOWED)
            .chain(crate::cmd_chat::FLAGS)
        {
            assert!(USAGE.contains(&format!("--{flag}")), "USAGE omits --{flag}");
        }
        for special in ["--resume", "--continue", "--fork"] {
            assert!(USAGE.contains(special), "USAGE omits {special}");
        }
    }

    /// The session-grant flags are valueless on every gate child (P-23
    /// documented them flag-first; P-58 aligned run and resume with the
    /// text, replay already took them flagless).
    #[test]
    fn session_grant_flags_take_no_value() {
        for flags in [RUN_FLAGS, RESUME_FLAGS] {
            for flag in ["allow-session-grants", "accept-edits"] {
                assert!(flags.contains(&flag), "flag list omits {flag}");
            }
        }
        assert!(options(
            &["--allow-session-grants", "--accept-edits"],
            RUN_ALLOWED,
            RUN_FLAGS,
        )
        .is_ok());
    }

    /// P-58: the README's quickstart commands all name verbs this
    /// dispatch answers. The README is read at run time from the repo
    /// root (a compile-time `include_str!` is refused by the purity
    /// gate's INV-23 scan, even in test code), and an unreadable README
    /// fails the test rather than passing it.
    #[test]
    fn readme_quickstart_commands_exist_as_verbs() {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let path = std::path::Path::new(manifest).join("../../README.md");
        let readme = std::fs::read_to_string(&path);
        assert!(
            readme.is_ok(),
            "cannot read {}: {:?}",
            path.display(),
            readme.as_ref().err()
        );
        let readme = readme.unwrap_or_default();
        let mut commands = 0;
        let mut in_block = false;
        for line in readme.lines() {
            if line.trim_start().starts_with("```") {
                in_block = !in_block;
                continue;
            }
            if !in_block {
                continue;
            }
            let trimmed = line.trim_start();
            let cmd = trimmed
                .strip_prefix("rustyharness ")
                .or_else(|| trimmed.strip_prefix("cargo run -p harness-cli -- "));
            let Some(cmd) = cmd else { continue };
            let path: Vec<&str> = cmd
                .split_whitespace()
                .take(2)
                .take_while(|t| !t.starts_with('-') && !t.starts_with('<') && !t.starts_with('#'))
                .collect();
            assert!(
                !path.is_empty(),
                "README quickstart has a bare command: {line}"
            );
            assert!(
                is_verb_path(&path),
                "README quickstart names no verb: {line}"
            );
            commands += 1;
        }
        assert!(
            commands >= 3,
            "README quickstart commands not found: {commands}"
        );
    }

    /// P-58: `--help` renders for every verb path the dispatch answers,
    /// and for nothing else.
    #[test]
    fn help_renders_for_every_verb_path() {
        for verb in VERBS {
            assert!(help_for(&[verb]).is_some(), "no help for {verb}");
        }
        for path in [
            ["manifest", "check"],
            ["profile", "check"],
            ["profile", "init"],
            ["schedule", "add"],
            ["schedule", "list"],
            ["schedule", "remove"],
            ["schedule", "run-now"],
            ["compare", "reveal"],
        ] {
            assert!(help_for(&path).is_some(), "no help for {}", path.join(" "));
        }
        assert!(help_for(&["bogus"]).is_none());
    }
}
