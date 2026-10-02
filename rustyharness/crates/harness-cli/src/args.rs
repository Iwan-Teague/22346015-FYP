//! The command line's options: the usage text and the `--key value`
//! parser every verb shares.

use std::collections::{BTreeMap, BTreeSet};

pub(crate) const USAGE: &str = "usage:
  rustyharness version
  rustyharness sandbox             report confinement (refuses to run anything without it)
  rustyharness manifest check <file.json>   exit 0 valid (valid is not admitted), 1 refused, 4 unreadable
  rustyharness run    --task <task.json> --workspace <dir> --state-root <dir>
                       --profile <profile.json> --endpoint <http://127.0.0.1:PORT/v1>
                       [--policy <policy.json>] [--gate <gate-id>] [--output stream-json]
                       [--allow-exec <name[,name]>] [--preset <rust|node|python|go>] [--shell]
                       [--no-default-denies]
  rustyharness resume --run <run-id> + the run options
  rustyharness replay --run <run-id> --task <task.json> --state-root <dir>
                       --profile <profile.json> [--attempt <n>] [--anchor <sha256>]
                       [--policy <policy.json>] [--gate <gate-id>]
                       [--allow-exec <name[,name]>] [--preset <rust|node|python|go>] [--shell]
                       [--no-default-denies]
  rustyharness events --run <run-id> [--state-root <dir>] [--format ndjson] [--follow]
  rustyharness profile check --profile <profile.json> --endpoint <url>
  rustyharness profile init  --endpoint <url> [--out <profile.json>]
  rustyharness sessions [--state-root <dir>] [--run <run-id>]
  rustyharness gc --run <run-id> | --older-than <N>d   [--state-root <dir>]

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
  run was given, so the audit re-resolves the same allowlist.";

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
  rustyharness manifest check <file.json>   exit 0 valid (valid is not admitted), 1 refused, 4 unreadable
  rustyharness run    --task <task.json> --workspace <dir> --state-root <dir>
                       --profile <profile.json> --endpoint <http://127.0.0.1:PORT/v1>
                       [--policy <policy.json>] [--gate <gate-id>] [--output stream-json]
                       [--allow-exec <name[,name]>] [--preset <rust|node|python|go>] [--shell]
                       [--no-default-denies]
  rustyharness resume --run <run-id> + the run options
  rustyharness replay --run <run-id> --task <task.json> --state-root <dir>
                       --profile <profile.json> [--attempt <n>] [--anchor <sha256>]
                       [--policy <policy.json>] [--gate <gate-id>]
                       [--allow-exec <name[,name]>] [--preset <rust|node|python|go>] [--shell]
                       [--no-default-denies]
  rustyharness events --run <run-id> [--state-root <dir>] [--format ndjson] [--follow]
  rustyharness profile check --profile <profile.json> --endpoint <url>
  rustyharness profile init  --endpoint <url> [--out <profile.json>]
  rustyharness sessions [--state-root <dir>] [--run <run-id>]
  rustyharness gc --run <run-id> | --older-than <N>d   [--state-root <dir>]

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
  run was given, so the audit re-resolves the same allowlist."
        );
    }
}
