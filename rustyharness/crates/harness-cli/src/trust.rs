//! The trust store (P-30): `<config dir>/trust.json`, the digests the
//! user approved once and the harness remembers. Two lists, strict JSON
//! (unknown or duplicate keys refused), never inside a workspace:
//!
//! - `instructions`: the full-text digests of project notes
//!   (`AGENTS.md`/`CLAUDE.md`) a chat may load again without asking. The
//!   file lives in the workspace; the approval lives here, by digest — a
//!   changed file is a different digest, and asks again.
//! - `commands`: the template digests of workspace slash commands
//!   (`.rustyharness/commands/*.md`) the user approved. Commands in the
//!   user's own config dir need no entry: their directory is already the
//!   user's.

/// The store file's name, inside [`crate::config::config_dir`].
const TRUST_FILE: &str = "trust.json";

/// The approved digests. A digest is 64 lowercase hex characters.
#[derive(Debug, Clone, Default)]
pub(crate) struct Trust {
    pub(crate) instructions: Vec<String>,
    pub(crate) commands: Vec<String>,
}

fn is_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Trust {
    /// Strict parse (deny unknown fields, duplicate keys refused by the
    /// strict parser): each list present, every entry a digest, no
    /// duplicates.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, String> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            #[serde(default)]
            instructions: Vec<String>,
            #[serde(default)]
            commands: Vec<String>,
        }
        let v = harness_core::strict_json::parse(bytes)
            .map_err(|e| format!("{TRUST_FILE} is not strict JSON: {e}"))?;
        let r: Raw = serde_json::from_value(v)
            .map_err(|e| format!("{TRUST_FILE} does not have the expected shape: {e}"))?;
        let list = |what: &str, l: &[String]| -> Result<Vec<String>, String> {
            let mut out = Vec::with_capacity(l.len());
            for d in l {
                if !is_digest(d) {
                    return Err(format!(
                        "{TRUST_FILE}: {what}: {d:?} is not a sha256 digest"
                    ));
                }
                if out.iter().any(|x| x == d) {
                    return Err(format!("{TRUST_FILE}: {what}: {d} appears twice"));
                }
                out.push(d.clone());
            }
            Ok(out)
        };
        Ok(Self {
            instructions: list("instructions", &r.instructions)?,
            commands: list("commands", &r.commands)?,
        })
    }

    /// Read the store: an empty one when there is no config dir or no
    /// file; `Err` when a file there is unusable (fail closed: an
    /// unreadable store approves nothing and refuses the chat).
    pub(crate) fn load() -> Result<Self, String> {
        let Some(dir) = crate::config::config_dir()? else {
            return Ok(Self::default());
        };
        let path = dir.join(TRUST_FILE);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        if bytes.len() > 64 * 1024 {
            return Err(format!("{} is larger than 64 KiB", path.display()));
        }
        Self::parse(&bytes)
    }

    /// Whether this instructions digest was approved before.
    pub(crate) fn has_instruction(&self, digest: &str) -> bool {
        self.instructions.iter().any(|d| d == digest)
    }

    /// Whether this command-template digest was approved before.
    pub(crate) fn has_command(&self, digest: &str) -> bool {
        self.commands.iter().any(|d| d == digest)
    }

    /// Approve an instructions digest from now on.
    pub(crate) fn trust_instruction(&mut self, digest: &str) {
        if !self.has_instruction(digest) {
            self.instructions.push(digest.to_owned());
        }
    }

    /// Approve a command-template digest from now on.
    pub(crate) fn trust_command(&mut self, digest: &str) {
        if !self.has_command(digest) {
            self.commands.push(digest.to_owned());
        }
    }

    /// Write the store back (best effort is not enough: an approval the
    /// store cannot hold is refused, so the chat says so and the next one
    /// asks again — never silently approved forever).
    pub(crate) fn save(&self) -> Result<(), String> {
        let Some(dir) = crate::config::config_dir()? else {
            return Err(format!("no config directory to hold {TRUST_FILE}"));
        };
        crate::config::create_private_dir(&dir)?;
        let v = serde_json::json!({
            "instructions": self.instructions,
            "commands": self.commands,
        });
        let path = dir.join(TRUST_FILE);
        std::fs::write(&path, serde_json::to_vec_pretty(&v).unwrap_or_default())
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_shape_and_digests_only() {
        let ok = br#"{"instructions":["00ff"],"commands":[]}"#;
        assert!(Trust::parse(ok).is_err(), "a digest is 64 hex characters");
        let ok = br#"{"instructions":["0000..."],"commands":[]}"#;
        assert!(Trust::parse(ok).is_err(), "dots are not hex");
        let hex64 = "a".repeat(64);
        let ok = format!(r#"{{"instructions":["{hex64}"],"commands":[]}}"#);
        let t = Trust::parse(ok.as_bytes()).unwrap();
        assert!(t.has_instruction(&hex64));
        assert!(!t.has_command(&hex64));
        for bad in [
            r#"{"extra":1}"#,
            r#"{"instructions":"x"}"#,
            r#"{"instructions":[123]}"#,
        ] {
            assert!(Trust::parse(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn approve_is_unique_per_list() {
        let mut t = Trust::default();
        let hex64 = "b".repeat(64);
        t.trust_instruction(&hex64);
        t.trust_instruction(&hex64);
        assert_eq!(t.instructions.len(), 1, "unique");
        t.trust_command("c".repeat(64).as_str());
        assert!(t.has_command(&"c".repeat(64)));
        assert!(!t.has_instruction(&"c".repeat(64)));
    }
}
