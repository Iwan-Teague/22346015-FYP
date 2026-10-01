//! The `profile` verbs: `profile check` (the smoke eval against a live
//! model server, and the stamp to add to the profile) and `profile init`
//! (write a conservative profile for a model the server lists; P-07).
//! Neither is a gate child.

use std::io::{BufRead, Write as _};
use std::time::{Duration, Instant};

use harness_model::client::{ClientConfig, OpenAiCompatible};
use harness_model::profile::{CheckResult, EditFormat, Profile, Protocol};

use crate::args::{options, USAGE};
use crate::config;
use crate::inputs::read_input;
use crate::report::exit;
use crate::Cx;

pub(crate) fn profile_check(cx: &Cx<'_>, rest: &[&str]) -> u8 {
    let o = match options(rest, &["profile", "endpoint"], &[]) {
        Ok(o) => o,
        Err(e) => {
            note!(cx, "{e}\n{USAGE}");
            return exit::USAGE;
        }
    };
    let (Some(path), Some(endpoint)) = (o.get("profile"), o.get("endpoint")) else {
        note!(cx, "--profile and --endpoint are required\n{USAGE}");
        return exit::USAGE;
    };
    let profile = match read_input(path).and_then(|b| Profile::parse(&b).map_err(|e| e.to_string()))
    {
        Ok(p) => p,
        Err(e) => {
            note!(cx, "{e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    let client =
        match OpenAiCompatible::new(endpoint, profile.clone(), None, ClientConfig::default()) {
            Ok(c) => c,
            Err(e) => {
                note!(cx, "endpoint refused: {e}");
                return exit::UNREADABLE_INPUT;
            }
        };
    if let Err(e) = client.startup_check(Instant::now() + Duration::from_secs(30)) {
        note!(cx, "model server check failed: {e}");
        return exit::INDETERMINATE;
    }
    let (r, verdict) = harness_model::smoke::run(&client, &profile, Duration::from_secs(120));
    note!(cx,
        "profile check: {} case(s), {} valid tool call(s), {} format error(s), {} failed call(s); edit format unchecked",
        r.cases, r.valid_tool_calls, r.format_errors, r.call_failures
    );
    match verdict {
        CheckResult::Stamp(s) => {
            say!(
                cx,
                "{}",
                serde_json::json!({"validated": {
                    "report_sha256": s.report_sha256,
                    "stamp_sha256": s.stamp_sha256,
                }})
            );
            note!(cx, "add the \"validated\" object above to the profile");
            exit::PASSED
        }
        CheckResult::NoStamp(why) => {
            note!(cx, "no stamp: {why}");
            exit::FAILED
        }
    }
}

/// The profile document rendered from a parsed profile's getters (P-07):
/// the shape `Profile::parse` accepts, with every optional field left out
/// while it is off. A render that would not parse back is refused before
/// anything is written.
pub(crate) fn render_profile(p: &Profile) -> serde_json::Value {
    let s = p.sampling();
    let mut sampling = serde_json::json!({
        "temperature": s.temperature,
        "top_p": s.top_p,
        "max_tokens": s.max_tokens,
    });
    if let (Some(seed), Some(o)) = (s.seed, sampling.as_object_mut()) {
        o.insert("seed".into(), seed.into());
    }
    let mut v = serde_json::json!({
        "profile_version": 1,
        "id": p.id(),
        "model": p.model(),
        "context_window": p.context_window(),
        "fill_ratio": p.fill_ratio(),
        "protocol": match p.protocol() { Protocol::Native => "native", Protocol::Text => "text" },
        "tool_choice_required_ok": p.tool_choice_required_ok(),
        "grammar": "none",
        "max_active_tools": p.max_active_tools(),
        "edit_format": match p.edit_format() { EditFormat::Replace => "replace", EditFormat::Whole => "whole" },
        "recent_turns": p.recent_turns(),
        "sampling": sampling,
    });
    let o = match v.as_object_mut() {
        Some(o) => o,
        None => return v,
    };
    if let Some(n) = p.kv_quant_note() {
        o.insert("kv_quant_note".into(), n.into());
    }
    if p.parallel_tool_calls_false_ok() {
        o.insert("parallel_tool_calls_false_ok".into(), true.into());
    }
    if p.stream_include_usage_ok() {
        o.insert("stream_include_usage_ok".into(), true.into());
    }
    v
}

/// One stdin line, trimmed; `Err` when stdin cannot be read.
fn read_choice_line() -> Result<String, String> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("cannot read the choice: {e}"))?;
    Ok(line.trim().to_owned())
}

/// The chosen model: the line as an exact id, or a 1-based number into the
/// list. Anything else is refused (fail closed: no guessing).
pub(crate) fn resolve_choice(line: &str, models: &[String]) -> Option<String> {
    let line = line.trim();
    if let Some(m) = models.iter().find(|m| m.as_str() == line) {
        return Some(m.clone());
    }
    let n: usize = line.parse().ok()?;
    if n == 0 {
        return None;
    }
    models.get(n - 1).cloned()
}

/// The model-name rule a profile must satisfy (§3.4): non-empty, at most
/// 256 bytes, visible ASCII. Mirrors the parser's own check, so a server
/// id that could never parse is refused before anything is written.
fn usable_model_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Write `bytes` so only the owner can read them (0600 on unix).
fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let mut f =
        std::fs::File::create(path).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot secure {}: {e}", path.display()))?;
    }
    Ok(())
}

pub(crate) fn profile_init(cx: &Cx<'_>, rest: &[&str]) -> u8 {
    let o = match options(rest, &["endpoint", "out"], &[]) {
        Ok(o) => o,
        Err(e) => {
            note!(cx, "{e}\n{USAGE}");
            return exit::USAGE;
        }
    };
    let Some(endpoint) = o.get("endpoint") else {
        note!(cx, "--endpoint is required\n{USAGE}");
        return exit::USAGE;
    };
    // A probe client: only its endpoint and `GET /models` matter here.
    let probe = match OpenAiCompatible::new(
        endpoint,
        Profile::conservative_default("unspecified"),
        None,
        ClientConfig::default(),
    ) {
        Ok(c) => c,
        Err(e) => {
            note!(cx, "endpoint refused: {e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    let models = match probe.list_models(Instant::now() + Duration::from_secs(30)) {
        Ok(m) => m,
        Err(e) => {
            note!(cx, "cannot list the server's models: {e}");
            return exit::INDETERMINATE;
        }
    };
    if models.is_empty() {
        note!(cx, "the server lists no models; nothing to init");
        return exit::FAILED;
    }
    use std::io::IsTerminal;
    let chosen = if std::io::stdin().is_terminal() {
        note!(cx, "models the server lists:");
        for (i, m) in models.iter().enumerate() {
            note!(cx, "  {}. {m}", i + 1);
        }
        note!(cx, "pick one (number or exact id):");
        match read_choice_line() {
            Ok(line) => resolve_choice(&line, &models),
            Err(e) => {
                note!(cx, "{e}");
                return exit::FAILED;
            }
        }
    } else if models.len() == 1 {
        models.first().cloned()
    } else {
        note!(
            cx,
            "the server lists {} models; run `profile init` from a terminal to choose one",
            models.len()
        );
        None
    };
    let Some(model) = chosen else {
        note!(cx, "no model chosen; nothing written");
        return exit::FAILED;
    };
    if !usable_model_name(&model) {
        note!(
            cx,
            "the server's model id {model:?} is not a usable model name"
        );
        return exit::FAILED;
    }
    let profile = Profile::conservative_default(&model);
    let doc = render_profile(&profile);
    // Fail closed on a render drift: the file must parse back to the same
    // content, or nothing is written.
    let bytes = serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string());
    let bytes = match bytes {
        Ok(b) => b,
        Err(e) => {
            note!(cx, "cannot render the profile: {e}");
            return exit::INDETERMINATE;
        }
    };
    match Profile::parse(&bytes) {
        Ok(back) if back.content_sha256() == profile.content_sha256() => {}
        _ => {
            note!(
                cx,
                "the rendered profile does not match the intended one; nothing written"
            );
            return exit::INDETERMINATE;
        }
    }
    // Where to write: --out, else <config dir>/profiles/default.json.
    let out: std::path::PathBuf = match o.get("out") {
        Some(p) => std::path::PathBuf::from(p),
        None => match config::config_dir() {
            Ok(Some(dir)) => {
                let dir = dir.join("profiles");
                if let Err(e) = config::create_private_dir(&dir) {
                    note!(cx, "{e}");
                    return exit::UNREADABLE_INPUT;
                }
                dir.join("default.json")
            }
            Ok(None) => {
                note!(
                    cx,
                    "no config directory on this platform; pass --out\n{USAGE}"
                );
                return exit::USAGE;
            }
            Err(e) => {
                note!(cx, "{e}");
                return exit::UNREADABLE_INPUT;
            }
        },
    };
    if let Err(e) = write_private(&out, &bytes) {
        note!(cx, "{e}");
        return exit::INDETERMINATE;
    }
    note!(cx, "wrote {} (conservative, unstamped)", out.display());
    // The smoke eval on the new profile, as `profile check` does it.
    let client =
        match OpenAiCompatible::new(endpoint, profile.clone(), None, ClientConfig::default()) {
            Ok(c) => c,
            Err(e) => {
                note!(cx, "endpoint refused: {e}");
                return exit::UNREADABLE_INPUT;
            }
        };
    if let Err(e) = client.startup_check(Instant::now() + Duration::from_secs(30)) {
        note!(cx, "model server check failed: {e}");
        return exit::INDETERMINATE;
    }
    let (r, verdict) = harness_model::smoke::run(&client, &profile, Duration::from_secs(120));
    note!(cx,
        "profile init: {} case(s), {} valid tool call(s), {} format error(s), {} failed call(s); edit format unchecked",
        r.cases, r.valid_tool_calls, r.format_errors, r.call_failures
    );
    match verdict {
        CheckResult::Stamp(s) => {
            // Stamp the file: insert "validated", re-parse, and rewrite
            // only if the stamp validates the content it was made for.
            let mut doc: serde_json::Value = match serde_json::from_slice(&bytes) {
                Ok(d) => d,
                Err(e) => {
                    note!(cx, "cannot re-read the written profile: {e}");
                    return exit::INDETERMINATE;
                }
            };
            match doc.as_object_mut() {
                Some(o) => {
                    o.insert(
                        "validated".into(),
                        serde_json::json!({
                            "report_sha256": s.report_sha256,
                            "stamp_sha256": s.stamp_sha256,
                        }),
                    );
                }
                None => {
                    note!(cx, "cannot re-read the written profile");
                    return exit::INDETERMINATE;
                }
            }
            let stamped = match serde_json::to_vec_pretty(&doc) {
                Ok(b) => b,
                Err(e) => {
                    note!(cx, "cannot render the stamped profile: {e}");
                    return exit::INDETERMINATE;
                }
            };
            match Profile::parse(&stamped) {
                Ok(p) if p.validated() => {}
                _ => {
                    note!(
                        cx,
                        "the stamp does not validate the written profile; it stays unstamped"
                    );
                    return exit::INDETERMINATE;
                }
            }
            if let Err(e) = write_private(&out, &stamped) {
                note!(cx, "{e}");
                return exit::INDETERMINATE;
            }
            note!(cx, "stamped {}", out.display());
            say!(
                cx,
                "{}",
                serde_json::json!({"validated": {
                    "report_sha256": s.report_sha256,
                    "stamp_sha256": s.stamp_sha256,
                }})
            );
            exit::PASSED
        }
        CheckResult::NoStamp(why) => {
            note!(cx, "no stamp: {why}; the profile stays unstamped");
            exit::FAILED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_choice;

    #[test]
    fn a_choice_is_an_exact_id_or_a_one_based_number() {
        let m = vec!["a".to_owned(), "b".to_owned()];
        assert_eq!(resolve_choice("a", &m).as_deref(), Some("a"));
        assert_eq!(resolve_choice("2", &m).as_deref(), Some("b"));
        assert_eq!(resolve_choice(" 1 ", &m).as_deref(), Some("a"));
        assert_eq!(resolve_choice("c", &m), None);
        assert_eq!(resolve_choice("3", &m), None);
        assert_eq!(resolve_choice("0", &m), None);
        assert_eq!(resolve_choice("-1", &m), None);
        assert_eq!(resolve_choice("", &m), None);
    }
}
