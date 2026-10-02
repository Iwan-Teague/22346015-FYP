//! Rule argument matchers (P-08, design §4.8): the `match` object a user
//! policy rule may carry, narrowing one selector to calls whose canonical
//! arguments satisfy every present condition (design §4.8, R1 §3.1's
//! Codex-style prefix rules).
//!
//! Pure: a matcher reads only the call's `args` value — the same canonical
//! value [`crate::canonical_call_digest`] digests — so audit replay
//! recomputes every matched decision (§2.9). A condition whose argument is
//! absent or of the wrong shape never holds: a matcher does not guess
//! (fail-closed, the [`crate::Selector`] refusal precedent).
//!
//! Conditions (all present ones must hold):
//! - `path_glob`: the string at `path` matches the glob (the pure matcher
//!   of [`harness_core::glob`]); the pattern is compiled once at load, and
//!   a pattern the glob refuses refuses the whole file.
//! - `argv_prefix`: the string list at `argv` starts with these items.
//! - `argv_not_prefix`: the string list at `argv` does NOT start with
//!   these items (the `git push` of the slice card).

use serde_json::Value;

use crate::PolicyConfigError;

/// The compiled `match` object of one user rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matcher {
    path_glob: Option<PathGlob>,
    argv_prefix: Option<Vec<String>>,
    argv_not_prefix: Option<Vec<String>>,
}

/// A compiled `path_glob` plus the source text it came from (the digest
/// names the rule as written, not as compiled).
#[derive(Debug, Clone, PartialEq, Eq)]
struct PathGlob {
    source: String,
    glob: harness_core::glob::Glob,
}

impl Matcher {
    /// Build a matcher whose only condition is `path_glob`: the pattern
    /// the harness itself writes (P-29 protected-path ask rules). A pattern
    /// the glob compiler refuses is refused here too — the same rule as
    /// [`Matcher::parse`]'s `path_glob` key.
    pub fn path_glob(pattern: &str) -> Result<Matcher, PolicyConfigError> {
        let glob = harness_core::glob::Glob::new(pattern)
            .map_err(|e| bad_matcher(&format!("path_glob refused: {}", e.message())))?;
        Ok(Matcher {
            path_glob: Some(PathGlob {
                source: pattern.to_owned(),
                glob,
            }),
            argv_prefix: None,
            argv_not_prefix: None,
        })
    }

    /// Parse the value of a rule's `"match"` key (must be an object, and
    /// not empty: a `match` that says nothing is an authoring mistake the
    /// §5.1 order cannot disambiguate). Unknown keys are refused.
    pub(crate) fn parse(v: &Value) -> Result<Option<Matcher>, PolicyConfigError> {
        let Some(map) = v.as_object() else {
            return Err(bad_matcher("match must be an object"));
        };
        let mut path_glob = None;
        let mut argv_prefix = None;
        let mut argv_not_prefix = None;
        for (key, val) in map {
            match key.as_str() {
                "path_glob" => {
                    let src = val
                        .as_str()
                        .ok_or_else(|| bad_matcher("path_glob must be a string glob pattern"))?;
                    let glob = harness_core::glob::Glob::new(src)
                        .map_err(|e| bad_matcher(&format!("path_glob refused: {}", e.message())))?;
                    path_glob = Some(PathGlob {
                        source: src.to_owned(),
                        glob,
                    });
                }
                "argv_prefix" | "argv_not_prefix" => {
                    let Some(items) = val.as_array() else {
                        return Err(bad_matcher(&format!("{key} must be a list of strings")));
                    };
                    if items.is_empty() {
                        return Err(bad_matcher(&format!("{key} must not be empty")));
                    }
                    let mut prefix = Vec::with_capacity(items.len());
                    for item in items {
                        let Some(s) = item.as_str() else {
                            return Err(bad_matcher(&format!("{key} must be a list of strings")));
                        };
                        if s.is_empty() {
                            return Err(bad_matcher(&format!(
                                "{key} holds an empty item, which would match every argv"
                            )));
                        }
                        prefix.push(s.to_owned());
                    }
                    if key == "argv_prefix" {
                        argv_prefix = Some(prefix);
                    } else {
                        argv_not_prefix = Some(prefix);
                    }
                }
                other => return Err(bad_matcher(&format!("unknown match key {other:?}"))),
            }
        }
        if path_glob.is_none() && argv_prefix.is_none() && argv_not_prefix.is_none() {
            return Err(bad_matcher("match names no condition"));
        }
        Ok(Some(Matcher {
            path_glob,
            argv_prefix,
            argv_not_prefix,
        }))
    }

    /// Whether `args` (the canonical argument object of a call) satisfies
    /// every present condition. Total: no panic, no panic-adjacent index.
    pub fn matches(&self, args: &Value) -> bool {
        if let Some(pg) = &self.path_glob {
            // The schema says `path` is a string; anything else (or absent)
            // does not match — the policy never reads past what is there.
            match args.get("path").and_then(Value::as_str) {
                Some(p) if pg.glob.matches(p) => {}
                _ => return false,
            }
        }
        if let Some(prefix) = &self.argv_prefix {
            if !argv_starts_with(args, prefix) {
                return false;
            }
        }
        if let Some(prefix) = &self.argv_not_prefix {
            if argv_starts_with(args, prefix) {
                return false;
            }
        }
        true
    }

    /// The compiled glob when this matcher is exactly one `path_glob`
    /// (no argv conditions): lets tools reuse an already-decided deny rule
    /// as a skip predicate over paths (P-12). A matcher with any argv
    /// condition returns `None` — it is not a pure path predicate.
    pub fn path_only_glob(&self) -> Option<&harness_core::glob::Glob> {
        if self.argv_prefix.is_none() && self.argv_not_prefix.is_none() {
            self.path_glob.as_ref().map(|pg| &pg.glob)
        } else {
            None
        }
    }

    /// The matcher's canonical JSON text (sorted keys): what the policy
    /// digest appends to a rule's line and what makes two rules with the
    /// same selector comparable.
    pub(crate) fn canonical(&self) -> String {
        let mut m = serde_json::Map::new();
        if let Some(pg) = &self.path_glob {
            m.insert("path_glob".into(), Value::from(pg.source.clone()));
        }
        if let Some(p) = &self.argv_prefix {
            m.insert(
                "argv_prefix".into(),
                Value::Array(p.iter().map(|s| Value::from(s.clone())).collect()),
            );
        }
        if let Some(p) = &self.argv_not_prefix {
            m.insert(
                "argv_not_prefix".into(),
                Value::Array(p.iter().map(|s| Value::from(s.clone())).collect()),
            );
        }
        Value::Object(m).to_string()
    }
}

fn bad_matcher(what: &str) -> PolicyConfigError {
    PolicyConfigError::BadMatcher(what.to_owned())
}

/// Whether `argv` (a list of strings, per the exec schema) starts with
/// `prefix`. Absent, short, or any non-string item: no (fail-closed).
fn argv_starts_with(args: &Value, prefix: &[String]) -> bool {
    let Some(items) = args.get("argv").and_then(Value::as_array) else {
        return false;
    };
    if items.len() < prefix.len() {
        return false;
    }
    items
        .iter()
        .zip(prefix)
        .all(|(item, p)| item.as_str() == Some(p.as_str()))
}
