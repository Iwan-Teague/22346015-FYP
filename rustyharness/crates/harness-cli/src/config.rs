//! The user's config file (`<config dir>/config.json`) and the default
//! locations (P-07): the config dir and the default `state_root`. The file
//! is optional, read only from the user's config directory — never from
//! the workspace — strict JSON (unknown or duplicate keys refused), and
//! every command-line flag overrides it.
//!
//! - The config dir is `$RUSTYHARNESS_CONFIG_HOME` if set (absolute, or the
//!   value is refused), else `~/Library/Application Support/rustyharness`
//!   on macOS, else `$XDG_CONFIG_HOME/rustyharness` or
//!   `~/.config/rustyharness`. On Windows (and anywhere without `HOME`)
//!   there is no config: not an error, just defaults and flags.
//! - The default `state_root` is the same layout under the data home
//!   (`$RUSTYHARNESS_STATE_HOME`, else the same per-OS home), created with
//!   owner-only permissions (0700) when missing. A `--state-root` or a
//!   configured one is never created: it must exist, as before.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// The config file's name, inside [`config_dir`].
const CONFIG_FILE: &str = "config.json";

/// Who answers an ask (§5.3) when the config says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ApproverSetting {
    /// The person at the terminal, when there is one (the default).
    #[default]
    Terminal,
    /// Nobody: every ask is a deny, even at a terminal.
    None,
}

/// One user's defaults, as read from `config.json` (all keys optional).
#[derive(Debug, Clone, Default)]
pub(crate) struct UserConfig {
    pub(crate) endpoint: Option<String>,
    pub(crate) profile: Option<String>,
    pub(crate) policy: Option<String>,
    pub(crate) state_root: Option<String>,
    pub(crate) approver: ApproverSetting,
    /// The exec allowlist by name (P-11), the `--allow-exec` names
    /// comma-joined, exactly as the flag takes them. Absent when the list
    /// is empty, so an empty list means no allowlist.
    pub(crate) exec_programs: Option<String>,
}

impl UserConfig {
    /// Strict parse (deny unknown fields, duplicate keys refused by the
    /// strict parser), then fail-closed validation by name: absolute
    /// paths, a non-empty endpoint, a known approver.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, String> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            #[serde(default)]
            endpoint: Option<String>,
            #[serde(default)]
            profile: Option<String>,
            #[serde(default)]
            policy: Option<String>,
            #[serde(default)]
            state_root: Option<String>,
            #[serde(default)]
            approver: Option<String>,
            #[serde(default)]
            exec_programs: Option<Vec<String>>,
        }
        let v = harness_core::strict_json::parse(bytes)
            .map_err(|e| format!("{CONFIG_FILE} is not strict JSON: {e}"))?;
        let r: Raw = serde_json::from_value(v)
            .map_err(|e| format!("{CONFIG_FILE} does not have the expected shape: {e}"))?;
        let abs = |what: &str, p: &Option<String>| match p {
            None => Ok(None),
            Some(s) if std::path::Path::new(s).is_absolute() => Ok(Some(s.clone())),
            Some(s) => Err(format!(
                "{CONFIG_FILE}: {what} must be an absolute path, not {s:?}"
            )),
        };
        let approver = match r.approver.as_deref() {
            None | Some("terminal") => ApproverSetting::Terminal,
            Some("none") => ApproverSetting::None,
            Some(other) => {
                return Err(format!(
                    "{CONFIG_FILE}: approver must be \"terminal\" or \"none\", not {other:?}"
                ))
            }
        };
        // exec_programs (P-11): every entry a plain program name, no
        // duplicates — the names --allow-exec would resolve.
        let exec_programs = match r.exec_programs {
            None => None,
            Some(list) => {
                let mut names: Vec<String> = Vec::new();
                for n in &list {
                    let n = n.trim();
                    if !harness_run::plain_name(n) {
                        return Err(format!(
                            "{CONFIG_FILE}: exec_programs: {n:?} is not a plain program name"
                        ));
                    }
                    if names.iter().any(|x| x == n) {
                        return Err(format!("{CONFIG_FILE}: exec_programs: {n} appears twice"));
                    }
                    names.push(n.to_owned());
                }
                if names.is_empty() {
                    None
                } else {
                    Some(names.join(","))
                }
            }
        };
        Ok(Self {
            endpoint: match &r.endpoint {
                None => Ok(None),
                Some(s) if !s.is_empty() => Ok(Some(s.clone())),
                Some(_) => Err(format!("{CONFIG_FILE}: endpoint must not be empty")),
            }?,
            profile: abs("profile", &r.profile)?,
            policy: abs("policy", &r.policy)?,
            state_root: abs("state_root", &r.state_root)?,
            approver,
            exec_programs,
        })
    }
}

/// The flag's value, else the config's: a command-line flag always
/// overrides the config file. Neither input is mutated.
pub(crate) fn value<'a>(
    o: &'a BTreeMap<&str, &str>,
    cfg: &'a Option<UserConfig>,
    flag: &str,
) -> Option<&'a str> {
    if let Some(v) = o.get(flag) {
        return Some(*v);
    }
    let c = cfg.as_ref()?;
    match flag {
        "endpoint" => c.endpoint.as_deref(),
        "profile" => c.profile.as_deref(),
        "policy" => c.policy.as_deref(),
        // The flag is spelled `--state-root`, the config key `state_root`.
        "state-root" => c.state_root.as_deref(),
        // The flag is `--allow-exec`, the config key `exec_programs`
        // (P-11), stored in the flag's comma-joined form.
        "allow-exec" => c.exec_programs.as_deref(),
        _ => None,
    }
}

/// The user's config directory, if this platform has one (see the module
/// text). `Ok(None)` is "no config here", not an error; `Err` is a
/// fail-closed refusal (an override variable set to a relative path).
pub(crate) fn config_dir() -> Result<Option<PathBuf>, String> {
    home_dir("RUSTYHARNESS_CONFIG_HOME", "XDG_CONFIG_HOME", ".config")
        .map(|h| h.map(|h| h.join("rustyharness")))
}

/// The per-user application-data home (see the module text): the parent of
/// both the config dir and the default state root.
fn home_dir(
    override_var: &str,
    xdg_var: &str,
    xdg_default: &str,
) -> Result<Option<PathBuf>, String> {
    if let Ok(v) = std::env::var(override_var) {
        if std::path::Path::new(&v).is_absolute() {
            return Ok(Some(PathBuf::from(v)));
        }
        return Err(format!(
            "{override_var} must be an absolute path, not {v:?}"
        ));
    }
    if cfg!(target_os = "macos") {
        return match std::env::var_os("HOME") {
            Some(h) if !h.is_empty() => {
                Ok(Some(PathBuf::from(h).join("Library/Application Support")))
            }
            // No HOME: no defaults, not an error.
            _ => Ok(None),
        };
    }
    if !cfg!(unix) {
        // Windows (and anything else): no config until its spike lands.
        return Ok(None);
    }
    if let Ok(x) = std::env::var(xdg_var) {
        // An empty XDG variable counts as unset, per the XDG spec.
        if !x.is_empty() {
            if std::path::Path::new(&x).is_absolute() {
                return Ok(Some(PathBuf::from(x)));
            }
            return Err(format!("{xdg_var} must be an absolute path, not {x:?}"));
        }
    }
    match std::env::var_os("HOME") {
        Some(h) if !h.is_empty() => Ok(Some(PathBuf::from(h).join(xdg_default))),
        _ => Ok(None),
    }
}

/// The default `state_root` for this user: `<data home>/rustyharness`,
/// created owner-only (0700) when missing. `Ok(None)` is "this platform
/// has no default" (a `--state-root` is then required); `Err` is
/// fail-closed (the directory cannot be created or is not a directory).
pub(crate) fn default_state_root() -> Result<Option<PathBuf>, String> {
    let Some(home) = home_dir("RUSTYHARNESS_STATE_HOME", "XDG_DATA_HOME", ".local/share")? else {
        return Ok(None);
    };
    let root = home.join("rustyharness");
    create_private_dir(&root)?;
    Ok(Some(root))
}

/// A directory that only its owner may read (0700 on unix), created when
/// missing; an existing directory is left as it is.
pub(crate) fn create_private_dir(path: &std::path::Path) -> Result<(), String> {
    if let Err(e) = std::fs::create_dir_all(path) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(format!("cannot create {}: {e}", path.display()));
        }
    }
    if !path.is_dir() {
        return Err(format!("{} is not a directory", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// The state root a gate child uses: the flag, else the config, else the
/// default (`<data home>/rustyharness`, created owner-only when missing).
/// `Ok(None)` is "nothing given and no default here" (the caller makes it
/// a usage error); `Err` is a fail-closed refusal.
pub(crate) fn state_root<'a>(
    o: &'a BTreeMap<&str, &str>,
    cfg: &'a Option<UserConfig>,
) -> Result<Option<std::borrow::Cow<'a, str>>, String> {
    if let Some(v) = value(o, cfg, "state-root") {
        return Ok(Some(std::borrow::Cow::Borrowed(v)));
    }
    match default_state_root()? {
        None => Ok(None),
        Some(p) => Ok(Some(std::borrow::Cow::Owned(
            p.to_string_lossy().into_owned(),
        ))),
    }
}

/// Read the user's config, if there is one: `Ok(None)` when there is no
/// config dir or no file in it, `Err` when a file there is unusable or a
/// location override is refused.
pub(crate) fn load() -> Result<Option<UserConfig>, String> {
    let Some(dir) = config_dir()? else {
        return Ok(None);
    };
    let path = dir.join(CONFIG_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    if bytes.len() > 1024 * 1024 {
        return Err(format!("{} is larger than 1 MiB", path.display()));
    }
    UserConfig::parse(&bytes).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_keys_and_the_expected_shape_are_refused() {
        let ok = br#"{"endpoint":"http://127.0.0.1:1/v1"}"#;
        assert!(UserConfig::parse(ok).is_ok());
        for bad in [
            r#"{"Endpoint":"x"}"#,
            r#"{"endpoint":"x","extra":1}"#,
            r#"{"approver":"sudo"}"#,
            r#"{"profile":"relative/path.json"}"#,
            r#"{"policy":"p.json"}"#,
            r#"{"state_root":"state"}"#,
            r#"{"endpoint":""}"#,
        ] {
            assert!(UserConfig::parse(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn duplicate_keys_are_refused_and_absolute_paths_pass() {
        let dup = br#"{"endpoint":"a","endpoint":"b"}"#;
        assert!(UserConfig::parse(dup).is_err());
        let c = UserConfig::parse(
            br#"{"profile":"/abs/p.json","policy":"/abs/q.json","state_root":"/abs/s","approver":"none"}"#,
        )
        .unwrap();
        assert_eq!(c.approver, ApproverSetting::None);
        assert_eq!(c.profile.as_deref(), Some("/abs/p.json"));
    }

    /// exec_programs (P-11): plain, unique names, kept in the flag's
    /// comma-joined form; anything else refused.
    #[test]
    fn exec_programs_are_plain_unique_names_in_flag_form() {
        let c = UserConfig::parse(br#"{"exec_programs":["cargo","git","rg"]}"#).unwrap();
        assert_eq!(c.exec_programs.as_deref(), Some("cargo,git,rg"));
        // An empty list is no allowlist at all, not an empty one.
        let c = UserConfig::parse(br#"{"exec_programs":[]}"#).unwrap();
        assert!(c.exec_programs.is_none());
        for bad in [
            r#"{"exec_programs":["bin/cargo"]}"#,
            r#"{"exec_programs":["cargo","cargo"]}"#,
            r#"{"exec_programs":[""]}"#,
        ] {
            assert!(UserConfig::parse(bad.as_bytes()).is_err(), "{bad}");
        }
    }
}
