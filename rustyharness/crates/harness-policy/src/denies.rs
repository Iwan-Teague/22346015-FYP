//! The CLI's sensitive-path default deny list (P-12): the globs every
//! command-line run refuses to surface — `.env` files, key material,
//! cloud and credential directories — applied through the P-08 matchers
//! (design §4.8) so `read`, `search`, `glob`, `list` and the workspace
//! edits all refuse the same paths.
//!
//! A library default is deliberately EMPTY (OD-2): an embedder decides
//! which paths are sensitive in its product. The CLI overlays this list
//! on top of whatever `--policy` the user gave (or on the empty policy)
//! unless `--no-default-denies` is passed; the effective policy (defaults
//! included) is what the run header digests, so replay and audit see
//! exactly what decided (§2.9, §7.1).
//!
//! The rules are deny rules with a `path_glob` matcher each, in a fixed
//! capability-major × glob order, so rule indices — and the digest — are
//! stable across builds. A `--policy` that already names one of these
//! rules is refused as ambiguous (the duplicate-rule precedent): the two
//! spellings could drift, and a config that says two things about one
//! rule should be fixed, not silently merged.
//!
//! Pure: the list is data and the overlay is list surgery — no I/O, no
//! clock, so audit recomputes every decision the defaults produced.

use std::collections::BTreeSet;

use harness_manifest::CapId;
use serde_json::json;

use crate::builtin::{EDIT_IDS, GLOB_ID, LIST_ID, OUTLINE_ID, READ_ID, SEARCH_ID};
use crate::matcher::Matcher;
use crate::{PolicyConfigError, Rule, Selector, UserPolicy};

/// The sensitive-path globs the CLI denies by default (P-12): environment
/// files, certificates and private keys, SSH/Cloud-credential directories,
/// and the package-manager and network credential files. Workspace-relative,
/// `/`-separated (the [`harness_core::glob`] spelling); a pattern without
/// `/` matches a name at any depth.
pub const DEFAULT_DENY_GLOBS: [&str; 10] = [
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "id_rsa*",
    ".aws/**",
    ".ssh/**",
    ".git/config",
    ".npmrc",
    ".netrc",
];

/// The capabilities the default list denies these paths on: the five
/// content-surfacing read tools and the six workspace edits (including the
/// P-25 patch script and delete/move file operations, whose `to` path is
/// denied through policy's move-target shadow). Write-class tools that do
/// not name a workspace path (the submit sentinel, the checklist, exec) are
/// out of scope — a denied edit covers the same paths as a denied read.
const DEFAULT_DENY_CAPABILITIES: [&str; 11] = [
    READ_ID,
    SEARCH_ID,
    GLOB_ID,
    LIST_ID,
    OUTLINE_ID,
    EDIT_IDS[0],
    EDIT_IDS[1],
    EDIT_IDS[2],
    EDIT_IDS[3],
    EDIT_IDS[4],
    EDIT_IDS[5],
];

/// One deny rule per capability × glob, in the stable order.
fn default_rules() -> Result<Vec<Rule>, PolicyConfigError> {
    let mut rules = Vec::new();
    for cap in DEFAULT_DENY_CAPABILITIES {
        let selector = Selector::parse(cap)?;
        for glob in DEFAULT_DENY_GLOBS {
            rules.push(Rule {
                selector: selector.clone(),
                matcher: Some(path_glob_matcher(glob)?),
            });
        }
    }
    Ok(rules)
}

/// The `{"path_glob": g}` matcher, compiled once here so tools can reuse
/// it as a skip predicate ([`UserPolicy::denied_globs`]).
fn path_glob_matcher(glob: &str) -> Result<Matcher, PolicyConfigError> {
    Matcher::parse(&json!({ "path_glob": glob }))?.ok_or_else(|| {
        PolicyConfigError::BadMatcher(format!("path_glob {glob:?} compiled to no matcher"))
    })
}

/// The default-deny policy on its own: 11 capabilities × 10 globs of deny
/// rules with `path_glob` matchers, empty ask and allow. A library embedder
/// that wants this behaviour calls this and passes it as the run's policy
/// (the run itself never applies defaults — OD-2).
pub fn default_denies() -> Result<UserPolicy, PolicyConfigError> {
    Ok(UserPolicy {
        deny: default_rules()?,
        ask: Vec::new(),
        allow: Vec::new(),
    })
}

/// Overlay the default deny rules on `policy`: the CLI's reading of
/// `--policy` (or no `--policy`) unless `--no-default-denies` was passed.
/// The defaults are appended after the user's own rules, so user deny
/// indices stay where they were and the digest names the union. A policy
/// that already names one of the default rules is refused as ambiguous —
/// remove the duplicate or pass `--no-default-denies` and write the list
/// you mean.
pub fn overlay_default_denies(mut policy: UserPolicy) -> Result<UserPolicy, PolicyConfigError> {
    let mut seen: BTreeSet<String> = policy
        .deny
        .iter()
        .chain(policy.ask.iter())
        .chain(policy.allow.iter())
        .map(Rule::key)
        .collect();
    for rule in default_rules()? {
        let key = rule.key();
        if !seen.insert(key.clone()) {
            return Err(PolicyConfigError::Ambiguous(key));
        }
        policy.deny.push(rule);
    }
    Ok(policy)
}

/// Overlay an allow rule per workspace edit capability (P-23's
/// `--accept-edits`): `**` on each of the edit tools, appended after
/// the user's own allow rules. The P-22 pre-image store makes every edit
/// undoable, which is what licenses a blanket allow. Idempotent: a rule
/// already present (the bundle's effective policy already overlaid it) is
/// skipped, not refused — replay and audit re-apply the overlay. Refused
/// outright when the pre-image store is missing: an undoable-only default
/// must not silently become a non-undoable one.
pub fn overlay_accept_edits(
    mut policy: UserPolicy,
    pre_image_store: bool,
) -> Result<UserPolicy, PolicyConfigError> {
    if !pre_image_store {
        return Err(PolicyConfigError::BadRule(
            "the edit pre-image store is missing, so --accept-edits is refused".to_owned(),
        ));
    }
    let mut seen: BTreeSet<String> = policy
        .deny
        .iter()
        .chain(policy.ask.iter())
        .chain(policy.allow.iter())
        .map(Rule::key)
        .collect();
    for cap in EDIT_IDS {
        let rule = Rule {
            selector: Selector::parse(cap)?,
            matcher: Some(path_glob_matcher("**")?),
        };
        let key = rule.key();
        if seen.insert(key) {
            policy.allow.push(rule);
        }
    }
    Ok(policy)
}

impl UserPolicy {
    /// The compiled globs of the deny rules that cover the content-surfacing
    /// read tools (`read`, `search`, `glob`, `list`, `outline`) and are
    /// exactly one `path_glob` matcher: the skip predicate the tools walk
    /// with (P-12). Deny rules on other capabilities (an exec rule, an
    /// edit-only rule) stay call-level — they cannot be evaluated per path.
    /// Infallible: the globs were compiled at policy load.
    pub fn denied_globs(&self) -> Vec<harness_core::glob::Glob> {
        const SURFACING: [&str; 5] = [READ_ID, SEARCH_ID, GLOB_ID, LIST_ID, OUTLINE_ID];
        let ids: Vec<CapId> = SURFACING
            .iter()
            .filter_map(|s| CapId::new(s).ok())
            .collect();
        self.deny
            .iter()
            .filter(|r| ids.iter().any(|id| r.selector.matches(id)))
            .filter_map(|r| {
                r.matcher
                    .as_ref()
                    .and_then(Matcher::path_only_glob)
                    .cloned()
            })
            .collect()
    }
}
