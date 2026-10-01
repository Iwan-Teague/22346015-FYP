//! The command line's options: the usage text and the `--key value`
//! parser every verb shares.

use std::collections::BTreeMap;

pub(crate) const USAGE: &str = "usage:
  rustyharness version
  rustyharness sandbox             report confinement (refuses to run anything without it)
  rustyharness manifest check <file.json>   exit 0 valid (valid is not admitted), 1 refused, 4 unreadable
  rustyharness run    --task <task.json> --workspace <dir> --state-root <dir>
                      --profile <profile.json> --endpoint <http://127.0.0.1:PORT/v1>
                      [--policy <policy.json>] [--gate <gate-id>]
  rustyharness resume --run <run-id> + the run options
  rustyharness replay --run <run-id> --task <task.json> --state-root <dir>
                      --profile <profile.json> [--attempt <n>] [--anchor <sha256>]
                      [--policy <policy.json>] [--gate <gate-id>]
  rustyharness profile check --profile <profile.json> --endpoint <url>";

/// Parse `--key value` pairs; a repeated or unknown key is a usage error.
pub(crate) fn options<'a>(
    rest: &[&'a str],
    allowed: &[&str],
) -> Result<BTreeMap<&'a str, &'a str>, String> {
    let mut out = BTreeMap::new();
    let mut it = rest.iter();
    while let Some(k) = it.next() {
        let key = k
            .strip_prefix("--")
            .filter(|k| allowed.contains(k))
            .ok_or_else(|| format!("unknown option {k}"))?;
        let v = it.next().ok_or_else(|| format!("--{key} needs a value"))?;
        if out.insert(key, *v).is_some() {
            return Err(format!("--{key} given twice"));
        }
    }
    Ok(out)
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
                      [--policy <policy.json>] [--gate <gate-id>]
  rustyharness resume --run <run-id> + the run options
  rustyharness replay --run <run-id> --task <task.json> --state-root <dir>
                      --profile <profile.json> [--attempt <n>] [--anchor <sha256>]
                      [--policy <policy.json>] [--gate <gate-id>]
  rustyharness profile check --profile <profile.json> --endpoint <url>"
        );
    }
}
