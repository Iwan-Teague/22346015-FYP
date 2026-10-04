//! The command line's options: the usage text and the `--key value`
//! parser every verb shares.

use std::collections::{BTreeMap, BTreeSet};

pub(crate) const USAGE: &str = "usage:
  rustyharness version
  rustyharness sandbox             report confinement (refuses to run anything without it)
  rustyharness doctor [--endpoint <url>] [--state-root <dir>]
                                   one PASS/WARN/FAIL line per check (sandbox, state root,
                                   config, endpoint, profile, presets, terminal) and a fix;
                                   exit 0 when no FAIL
  rustyharness manifest check <file.json>   exit 0 valid (valid is not admitted), 1 refused, 4 unreadable
  rustyharness run    --task <task.json> --workspace <dir> --state-root <dir>
                       --profile <profile.json> --endpoint <http://127.0.0.1:PORT/v1>
                       [--policy <policy.json>] [--gate <gate-id>] [--output stream-json]
                       [--allow-exec <name[,name]>] [--preset <rust|node|python|go>] [--shell]
                       [--no-default-denies] [--workspace-mode in-place|scratch]
                       [--scratch-with-git] [--allow-session-grants] [--accept-edits]
                       [--allow-port <p[,p]>] [--allow-lan-port <p[,p]>] [--bg-persist]
   rustyharness resume --run <run-id> + the run options except
                       --workspace-mode and --scratch-with-git
  rustyharness replay --run <run-id> --task <task.json> --state-root <dir>
                       --profile <profile.json> [--attempt <n>] [--anchor <sha256>]
                       [--policy <policy.json>] [--gate <gate-id>]
                       [--allow-exec <name[,name]>] [--preset <rust|node|python|go>] [--shell]
                       [--no-default-denies] [--accept-edits]
                       [--allow-port <p[,p]>] [--allow-lan-port <p[,p]>]
   rustyharness events --run <run-id> [--state-root <dir>] [--format ndjson] [--follow]
  rustyharness review --run <run-id> --workspace <dir> [--state-root <dir>]
  rustyharness apply  --session <run-id> [--state-root <dir>] [--dry-run]
                       copy a scratch session's edits back onto the original
                       workspace after showing the diff; a typed `apply`
                       confirms, conflicts are reported and skipped
  rustyharness profile check --profile <profile.json> --endpoint <url>
  rustyharness profile init  --endpoint <url> [--out <profile.json>]
  rustyharness sessions [--state-root <dir>] [--run <run-id>]
  rustyharness gc --run <run-id> | --older-than <N>d   [--state-root <dir>]
  rustyharness chat   --task <task.json> --profile <profile.json> [--endpoint <url>]
                        [--workspace <dir>] [--state-root <dir>] [--policy <policy.json>]
                        [--gate <gate-id>] [--allow-exec <name[,name]>] [--preset <rust|node|python|go>]
                        [--shell] [--no-default-denies] [--workspace-mode in-place|scratch]
                        [--scratch-with-git] [--allow-session-grants] [--accept-edits]
                        [--resume [<run-id>] | --continue | --fork RUN@STEP]
  rustyharness acp    --task <task.json> --profile <profile.json> [--endpoint <url>]
                        --state-root <dir> [--policy <policy.json>] [--gate <gate-id>]
                        [--allow-exec <name[,name]>] [--preset <rust|node|python|go>]
                        [--shell] [--no-default-denies] [--allow-session-grants]
                        [--accept-edits]
                        Agent Client Protocol v1 over stdio (P-35): JSON-RPC on stdin/stdout;
                        each session/new brings its own workspace (cwd); notes and the gate
                        report go to stderr.
  rustyharness schedule add --name <name> --task <task.json>
                        (--daily <HH:MM> | --every <Nh>)
                        [--profile <profile.json>] [--policy <policy.json>] [--endpoint <url>]
                        [--workspace <dir>] [--state-root <dir>] [--no-default-denies]
  rustyharness schedule list      [--state-root <dir>]
  rustyharness schedule remove    --name <name> [--state-root <dir>]
  rustyharness schedule run-now   --name <name> [--state-root <dir>]
  rustyharness compare --task <task.json> --workspace <dir> --state-root <dir>
                       (--profile <profile.json> --endpoint <url>){2..4}
                       [--policy <policy.json>] [--gate <gate-id>] [--no-default-denies]
  rustyharness compare reveal --report <report.json> [--winner <A|B|C|D>]

compare (P-48): runs the same task on 2-4 profiles one after another,
  each from a fresh scratch copy under <state-root>/compare/<stamp>/; the
  report lists facts only (steps, tokens, wall, format errors, tool
  counts, final diff, pre-submit result, chain head) with arms labelled in
  a recorded random order — no score, no winner from the harness (OD-3).
  The label→model map sits in mapping.json (0600) and is printed only by
  `compare reveal` after --winner records the pick in report.json; every
  arm replays with `replay --run`.

defaults (P-07): --workspace is the current directory; --state-root, the
  profile, the policy and the endpoint come from <config dir>/config.json
  (strict JSON; a flag always overrides it) when the flag is not given;
  without any of them the state root is the per-user data directory's
  rustyharness/ (created 0700). The config is read only from the user's
  config directory, never from the workspace. Every run copies its resolved
  task, profile and policy into runs/<id>/inputs/ (0600), so `replay --run`
  and `resume --run` need no other flags; flags still override and must
  digest to what the run recorded. gc removes only a finished run's
  workspace/, grading/ and scratch/ — never its journal, blobs or inputs.

schedules (P-49): `schedule add` stores the validated task, profile and
  policy byte-for-byte in <state-root>/schedules/<name>/ (0600) and, only
  after a `y` on the same input chat reads lines from, writes the launchd
  plist (macOS) or systemd user service+timer (Linux), 0600; until then
  nothing is written. The task must carry an explicit budget (steps or
  wall_secs) and --allow-exec/--preset/--shell are refused: a timed run
  executes only what the task file pins, and every ask is denied. The
  launcher runs `schedule run-now --name <name>`, which re-checks every
  digest before it runs; `schedule list` shows the next daily run as a
  UTC estimate (the OS fires it at local HH:MM). Nothing is loaded into
  launchd or systemd for you.

sensitive paths (P-12): without --no-default-denies the CLI overlays a
  default deny list on the policy (.env, .env.*, *.pem, *.key, id_rsa*,
  .aws/**, .ssh/**, .git/config, .npmrc, .netrc) for read, search, glob,
  list and the edits; search, glob and list say how many paths they
  skipped, and the effective policy is what the run header digests.
  --no-default-denies turns the overlay off; replay and resume must be
  given the same flag the run was given.

exec by name (P-11): for a task that grants harness.exec.run but has no
  exec section, --allow-exec resolves each name against this process's own
  PATH, pins the absolute path it finds, and prints it (exec_programs in
  the config does the same); --preset adds the toolchain's read-only roots
  and variables (rust needs cargo on --allow-exec); --shell adds sh (the
  header stamps shell_enabled). A task file with its own exec section
  takes none of them. replay and resume must be given the same flags the
  run was given, so the audit re-resolves the same allowlist.

ports (P-36g): a task file's exec section may hold ports (loopback ports
  harness.exec.start may bind) and lan_ports (the subset reachable from
  the LAN); --allow-port and --allow-lan-port give the same lists when the
  task file has none. At most 8 ports, each 1024 or above, no duplicates
  in a list, lan_ports inside ports. The model endpoint's own port (from
  --endpoint or the config when it is a 127.0.0.1/localhost URL) is
  refused as a grant and recorded as reserved instead. Starting a process
  that binds a LAN port is a protected action: it asks every time and a
  session grant never covers it.";

/// The help text `rustyharness <verb path> --help` prints (P-58): the
/// USAGE synopsis entries whose command path extends `path` (`schedule
/// --help` shows every schedule subverb), plus a pointer to the whole
/// usage for the shared notes. `None` when USAGE names no such path: the
/// caller's ordinary dispatch answers instead, so an unknown verb keeps
/// its usage error (fail closed).
pub(crate) fn help_for(path: &[&str]) -> Option<String> {
    // One entry per `rustyharness ...` synopsis line: its command path
    // (the leading plain words, so `manifest check` and `schedule
    // run-now` are two tokens) and its lines (continuations belong to
    // the entry above them, until the blank line before the notes).
    let mut entries: Vec<(Vec<&str>, String)> = Vec::new();
    let mut open = true;
    for line in USAGE.lines() {
        if line.trim().is_empty() {
            open = false;
        }
        match line.trim_start().strip_prefix("rustyharness ") {
            Some(rest) => {
                let cmd: Vec<&str> = rest
                    .split_whitespace()
                    .take(2)
                    .take_while(|t| {
                        !t.starts_with('-')
                            && t.chars()
                                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                    })
                    .collect();
                entries.push((cmd, line.to_owned()));
            }
            None => {
                if let Some((_, text)) = entries.last_mut() {
                    if open {
                        text.push('\n');
                        text.push_str(line);
                    }
                }
            }
        }
    }
    let matched: Vec<&str> = entries
        .iter()
        .filter(|(cmd, _)| {
            cmd.len() >= path.len() && path.iter().enumerate().all(|(i, p)| cmd.get(i) == Some(p))
        })
        .map(|(_, text)| text.as_str())
        .collect();
    if matched.is_empty() {
        return None;
    }
    let mut out = matched.join("\n");
    out.push_str(
        "\n\nrun `rustyharness --help` for every verb and the shared notes\n\
         (defaults, sensitive paths, exec by name, ports, schedules).\n",
    );
    Some(out)
}

/// Parse `--key value` pairs; a repeated or unknown key is a usage error.
/// A key in `valueless` is a flag: it takes no value (`--shell`), and a
/// value-shaped token after it is refused as an unknown option.
pub(crate) fn options<'a>(
    rest: &[&'a str],
    allowed: &[&str],
    valueless: &[&str],
) -> Result<BTreeMap<&'a str, &'a str>, String> {
    options_with_flags(rest, allowed, valueless).map(|p| p.opts)
}

/// What [`options_with_flags`] read: `--key value` pairs and valueless
/// `--flag` marks. A flag is in `opts` too, as `"true"` (the flat map the
/// run verbs read); `flags` names the flags alone.
pub(crate) struct Parsed<'a> {
    pub(crate) opts: BTreeMap<&'a str, &'a str>,
    pub(crate) flags: BTreeSet<&'a str>,
}

/// Like [`options`], but `flags` are accepted without a value. A key given
/// both with and without a value, twice either way, or unknown, is a usage
/// error.
pub(crate) fn options_with_flags<'a>(
    rest: &[&'a str],
    allowed: &[&str],
    flags: &[&str],
) -> Result<Parsed<'a>, String> {
    let mut opts = BTreeMap::new();
    let mut flags_seen = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut it = rest.iter();
    while let Some(k) = it.next() {
        let key = k
            .strip_prefix("--")
            .filter(|k| allowed.contains(k) || flags.contains(k))
            .ok_or_else(|| format!("unknown option {k}"))?;
        if !seen.insert(key) {
            return Err(format!("--{key} given twice"));
        }
        if flags.contains(&key) {
            flags_seen.insert(key);
            // The flat `options` contract (P-11): a flag reads back as
            // `"true"` in the map (`--shell` there).
            opts.insert(key, "true");
            continue;
        }
        let v = it.next().ok_or_else(|| format!("--{key} needs a value"))?;
        opts.insert(key, *v);
    }
    Ok(Parsed {
        opts,
        flags: flags_seen,
    })
}

#[cfg(test)]
mod tests {
    use super::USAGE;

    /// Golden: the usage text is part of the contract with the person at
    /// the terminal, so an accidental edit shows here first.
    #[test]
    fn usage_text_unchanged() {
        assert_eq!(
            USAGE,
            "usage:
  rustyharness version
  rustyharness sandbox             report confinement (refuses to run anything without it)
  rustyharness doctor [--endpoint <url>] [--state-root <dir>]
                                   one PASS/WARN/FAIL line per check (sandbox, state root,
                                   config, endpoint, profile, presets, terminal) and a fix;
                                   exit 0 when no FAIL
  rustyharness manifest check <file.json>   exit 0 valid (valid is not admitted), 1 refused, 4 unreadable
  rustyharness run    --task <task.json> --workspace <dir> --state-root <dir>
                       --profile <profile.json> --endpoint <http://127.0.0.1:PORT/v1>
                       [--policy <policy.json>] [--gate <gate-id>] [--output stream-json]
                       [--allow-exec <name[,name]>] [--preset <rust|node|python|go>] [--shell]
                       [--no-default-denies] [--workspace-mode in-place|scratch]
                       [--scratch-with-git] [--allow-session-grants] [--accept-edits]
                       [--allow-port <p[,p]>] [--allow-lan-port <p[,p]>] [--bg-persist]
   rustyharness resume --run <run-id> + the run options except
                       --workspace-mode and --scratch-with-git
  rustyharness replay --run <run-id> --task <task.json> --state-root <dir>
                       --profile <profile.json> [--attempt <n>] [--anchor <sha256>]
                       [--policy <policy.json>] [--gate <gate-id>]
                       [--allow-exec <name[,name]>] [--preset <rust|node|python|go>] [--shell]
                       [--no-default-denies] [--accept-edits]
                       [--allow-port <p[,p]>] [--allow-lan-port <p[,p]>]
   rustyharness events --run <run-id> [--state-root <dir>] [--format ndjson] [--follow]
  rustyharness review --run <run-id> --workspace <dir> [--state-root <dir>]
  rustyharness apply  --session <run-id> [--state-root <dir>] [--dry-run]
                       copy a scratch session's edits back onto the original
                       workspace after showing the diff; a typed `apply`
                       confirms, conflicts are reported and skipped
  rustyharness profile check --profile <profile.json> --endpoint <url>
  rustyharness profile init  --endpoint <url> [--out <profile.json>]
  rustyharness sessions [--state-root <dir>] [--run <run-id>]
  rustyharness gc --run <run-id> | --older-than <N>d   [--state-root <dir>]
  rustyharness chat   --task <task.json> --profile <profile.json> [--endpoint <url>]
                        [--workspace <dir>] [--state-root <dir>] [--policy <policy.json>]
                        [--gate <gate-id>] [--allow-exec <name[,name]>] [--preset <rust|node|python|go>]
                        [--shell] [--no-default-denies] [--workspace-mode in-place|scratch]
                        [--scratch-with-git] [--allow-session-grants] [--accept-edits]
                        [--resume [<run-id>] | --continue | --fork RUN@STEP]
  rustyharness acp    --task <task.json> --profile <profile.json> [--endpoint <url>]
                        --state-root <dir> [--policy <policy.json>] [--gate <gate-id>]
                        [--allow-exec <name[,name]>] [--preset <rust|node|python|go>]
                        [--shell] [--no-default-denies] [--allow-session-grants]
                        [--accept-edits]
                        Agent Client Protocol v1 over stdio (P-35): JSON-RPC on stdin/stdout;
                        each session/new brings its own workspace (cwd); notes and the gate
                        report go to stderr.
  rustyharness schedule add --name <name> --task <task.json>
                        (--daily <HH:MM> | --every <Nh>)
                        [--profile <profile.json>] [--policy <policy.json>] [--endpoint <url>]
                        [--workspace <dir>] [--state-root <dir>] [--no-default-denies]
  rustyharness schedule list      [--state-root <dir>]
  rustyharness schedule remove    --name <name> [--state-root <dir>]
  rustyharness schedule run-now   --name <name> [--state-root <dir>]
  rustyharness compare --task <task.json> --workspace <dir> --state-root <dir>
                       (--profile <profile.json> --endpoint <url>){2..4}
                       [--policy <policy.json>] [--gate <gate-id>] [--no-default-denies]
  rustyharness compare reveal --report <report.json> [--winner <A|B|C|D>]

compare (P-48): runs the same task on 2-4 profiles one after another,
  each from a fresh scratch copy under <state-root>/compare/<stamp>/; the
  report lists facts only (steps, tokens, wall, format errors, tool
  counts, final diff, pre-submit result, chain head) with arms labelled in
  a recorded random order — no score, no winner from the harness (OD-3).
  The label→model map sits in mapping.json (0600) and is printed only by
  `compare reveal` after --winner records the pick in report.json; every
  arm replays with `replay --run`.

defaults (P-07): --workspace is the current directory; --state-root, the
  profile, the policy and the endpoint come from <config dir>/config.json
  (strict JSON; a flag always overrides it) when the flag is not given;
  without any of them the state root is the per-user data directory's
  rustyharness/ (created 0700). The config is read only from the user's
  config directory, never from the workspace. Every run copies its resolved
  task, profile and policy into runs/<id>/inputs/ (0600), so `replay --run`
  and `resume --run` need no other flags; flags still override and must
  digest to what the run recorded. gc removes only a finished run's
  workspace/, grading/ and scratch/ — never its journal, blobs or inputs.

schedules (P-49): `schedule add` stores the validated task, profile and
  policy byte-for-byte in <state-root>/schedules/<name>/ (0600) and, only
  after a `y` on the same input chat reads lines from, writes the launchd
  plist (macOS) or systemd user service+timer (Linux), 0600; until then
  nothing is written. The task must carry an explicit budget (steps or
  wall_secs) and --allow-exec/--preset/--shell are refused: a timed run
  executes only what the task file pins, and every ask is denied. The
  launcher runs `schedule run-now --name <name>`, which re-checks every
  digest before it runs; `schedule list` shows the next daily run as a
  UTC estimate (the OS fires it at local HH:MM). Nothing is loaded into
  launchd or systemd for you.

sensitive paths (P-12): without --no-default-denies the CLI overlays a
  default deny list on the policy (.env, .env.*, *.pem, *.key, id_rsa*,
  .aws/**, .ssh/**, .git/config, .npmrc, .netrc) for read, search, glob,
  list and the edits; search, glob and list say how many paths they
  skipped, and the effective policy is what the run header digests.
  --no-default-denies turns the overlay off; replay and resume must be
  given the same flag the run was given.

exec by name (P-11): for a task that grants harness.exec.run but has no
  exec section, --allow-exec resolves each name against this process's own
  PATH, pins the absolute path it finds, and prints it (exec_programs in
  the config does the same); --preset adds the toolchain's read-only roots
  and variables (rust needs cargo on --allow-exec); --shell adds sh (the
  header stamps shell_enabled). A task file with its own exec section
  takes none of them. replay and resume must be given the same flags the
  run was given, so the audit re-resolves the same allowlist.

ports (P-36g): a task file's exec section may hold ports (loopback ports
  harness.exec.start may bind) and lan_ports (the subset reachable from
  the LAN); --allow-port and --allow-lan-port give the same lists when the
  task file has none. At most 8 ports, each 1024 or above, no duplicates
  in a list, lan_ports inside ports. The model endpoint's own port (from
  --endpoint or the config when it is a 127.0.0.1/localhost URL) is
  refused as a grant and recorded as reserved instead. Starting a process
  that binds a LAN port is a protected action: it asks every time and a
  session grant never covers it."
        );
    }
}
