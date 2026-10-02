//! rustyharness policy for read classes, the built-in workspace edits and
//! the confined command runner (design `docs/01-design-v0.1.md` §4.2, §5.1, §5.2, §5.3, §5.4; this
//! slice of §9 H1/H2).
//!
//! Pure: no I/O, no clock, no global state. Everything a decision reads is
//! in its arguments, so audit replay can recompute it (§2.9).
//!
//! - [`effective_class`]: the max-rule of §4.2 (declared ∨ derived floors ∨
//!   user policy).
//! - [`Session::plan`]: session-level refusals before anything runs:
//!   unknown or duplicate grants, `restricted` (INV-27), the trifecta
//!   (INV-9, pure half), and every class this slice does not decide. The
//!   write-class capabilities it does decide are the built-in submit
//!   sentinel [`SUBMIT_ID`] (§2.5), allowed by the named rule
//!   `allow.task-submit` after every deny rule and schema check, the
//!   built-in checklist [`TODO_ID`] (H2e), allowed the same way by its
//!   rule [`TODO_RULE`], and the
//!   built-in workspace edits [`EDIT_IDS`] (H2b): allowed only by a user
//!   allow rule, otherwise an ask (rule [`EDIT_DEFAULT_RULE`]), a deny with
//!   no approver present. §5.2's default allow for them assumes a sandbox
//!   and snapshots that make an edit undoable; this build edits the
//!   workspace in place with neither, so it asks. The one execute-class
//!   capability is the built-in command runner [`EXEC_ID`] (H2d): planned
//!   only with a workspace and a conformed sandbox witness (INV-6), its
//!   `argv[0]` must name a program on the task's exec allowlist and its
//!   `cwd` stay in the workspace (INV-13), and it asks by default (rule
//!   [`EXEC_DEFAULT_RULE`]) unless a user allow rule allows it.
//! - [`Session::plan_child`] (P-38): the parent's planning plus the
//!   child-scope refusal — only the built-in fs tools and the submit
//!   sentinel plan into a helper run, and a delegate's label must cover
//!   what its child scope could read — so a delegate call can never start
//!   a run that reads past the session's own trifecta label.
//! - [`Session::decide`]: the §5.1 order — deny rules (first match wins,
//!   cannot be overridden), then ask rules, then allow rules, then DENY by
//!   default. Every decision carries the id of the rule that produced it.
//! - [`Session::authorize`]: a mint of [`Authorized`]; only `Allow`
//!   mints. An `Ask` alone never mints: with no approver present an `Ask`
//!   is a `Deny` (§5.2), and with one it stays an `Ask` until the approver
//!   says yes and a valid, bound, unconsumed approval token is redeemed
//!   (§5.3, INV-5).
//! - [`approval`]: the §5.3 approval tokens. An
//!   [`ApprovalAuthority`] mints HMAC-bound, 15-minute, single-use (or
//!   run-scoped-identical) tokens under a per-run key that exists only in
//!   harness memory; a token that is forged, expired, rebound, cross-run
//!   or replayed is refused (INV-16).
//! - [`Session::authorize_approved`]: the ONLY other mint of
//!   [`Authorized`]: an `Ask` decision plus a redeemed token that binds
//!   exactly this call. Nothing else turns an `Ask` into a call.
//! - [`path`]: what a built-in read may touch (the workspace, lexically).
//! - [`locality`]: the `state_root` filesystem-locality check's interface
//!   and its refusing default (the per-OS probes live in `harness-sandbox`).
//!
//! Fail-closed throughout: an unknown capability, a class this slice does
//! not decide, or an ambiguous lookup is refused, never allowed.
//!
//! [`PolicyDecision`] is not a verdict (§1.4): it says what may happen to one
//! call, never whether a run passed. The one outcome type stays
//! `gate_outcome::GateOutcome` (INV-28).

#![forbid(unsafe_code)]
// The panic-set lints ratchet production code; unit tests may assert loosely.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use harness_manifest::admission::{Registry, Resolved};
use harness_manifest::{
    ArgsError, BlastRadius, CapId, Capability, Confirmation, Content, Effect, Egress, InputSchema,
    ProviderName, Sensitivity, BUILTIN_NAMESPACE,
};
use serde_json::Value;

pub mod approval;
pub mod builtin;
pub mod denies;
pub mod locality;
pub mod matcher;
pub mod path;
pub mod web;

pub use builtin::{
    CHILD_ELIGIBLE, DELEGATE_ID, EDIT_DEFAULT_RULE, EDIT_IDS, EXEC_DEFAULT_RULE, EXEC_ID, GLOB_ID,
    LIST_ID, OUTLINE_ID, READ_ID, SEARCH_ID, SUBMIT_ID, TODO_ID, TODO_RULE,
};
pub use denies::{default_denies, overlay_default_denies, DEFAULT_DENY_GLOBS};
pub use matcher::Matcher;
pub use path::{workspace_path, PathRefused, WorkspacePath};

// ---------------------------------------------------------------------------
// Effective class (§4.2).
// ---------------------------------------------------------------------------

/// A capability's dimensions plus its EFFECTIVE confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveClass {
    /// Declared effect.
    pub effect: Effect,
    /// Declared sensitivity.
    pub sensitivity: Sensitivity,
    /// Declared blast radius.
    pub blast_radius: BlastRadius,
    /// Declared egress.
    pub egress: Egress,
    /// Declared content provenance.
    pub content: Content,
    /// max(declared, derived floors, user policy).
    pub confirmation: Confirmation,
    /// `execute` needs a `Conformed` sandbox token (derived floor, §4.2).
    pub requires_conformed: bool,
}

/// The derived confirmation floor of §4.2: `irreversible` or `shared` →
/// `protected_action`; `egress = internet` or `sensitivity ≥ personal` →
/// `user_confirm`.
pub fn derived_floor(c: &Capability) -> Confirmation {
    if c.effect() == Effect::Irreversible || c.blast_radius() == BlastRadius::Shared {
        Confirmation::ProtectedAction
    } else if c.egress() == Egress::Internet || c.sensitivity() >= Sensitivity::Personal {
        Confirmation::UserConfirm
    } else {
        Confirmation::None
    }
}

/// The max-rule: a manifest can only make things MORE restrictive, and user
/// policy can only raise the floor.
pub fn effective_class(c: &Capability, user_floor: Confirmation) -> EffectiveClass {
    EffectiveClass {
        effect: c.effect(),
        sensitivity: c.sensitivity(),
        blast_radius: c.blast_radius(),
        egress: c.egress(),
        content: c.content(),
        confirmation: c.confirmation().max(derived_floor(c)).max(user_floor),
        requires_conformed: c.effect() >= Effect::Execute,
    }
}

// ---------------------------------------------------------------------------
// User policy.
// ---------------------------------------------------------------------------

/// What a user rule matches: one capability id, or a whole provider
/// (`provider.*`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Selector {
    /// Exactly this id.
    Capability(CapId),
    /// Every capability of this provider.
    Provider(ProviderName),
}

impl Selector {
    /// Parse `provider.*` or a capability id. Anything else is refused.
    pub fn parse(s: &str) -> Result<Self, PolicyConfigError> {
        let bad = || PolicyConfigError::BadSelector(s.chars().take(80).collect());
        if let Some(p) = s.strip_suffix(".*") {
            return ProviderName::new(p)
                .map(Selector::Provider)
                .map_err(|_| bad());
        }
        CapId::new(s).map(Selector::Capability).map_err(|_| bad())
    }

    /// Whether this selector matches `id`.
    pub fn matches(&self, id: &CapId) -> bool {
        match self {
            Selector::Capability(c) => c == id,
            Selector::Provider(p) => id.provider() == p.as_str(),
        }
    }
}

/// Which user rule list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleList {
    /// `deny`.
    Deny,
    /// `ask`.
    Ask,
    /// `allow`.
    Allow,
}

/// One user rule: a [`Selector`] plus, since P-08, an optional argument
/// [`Matcher`] (design §4.8). Without a matcher the rule is the v1 form and
/// matches every call its selector covers; with one, only calls whose
/// canonical arguments satisfy every condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// What capability (or provider) the rule names.
    pub selector: Selector,
    /// The `match` conditions, if any.
    pub matcher: Option<Matcher>,
}

impl Rule {
    /// The rule's canonical key: selector line plus matcher JSON, the same
    /// spelling [`UserPolicy::digest`] writes, so two rules are the same
    /// rule exactly when their keys are.
    fn key(&self) -> String {
        let mut k = selector_str(&self.selector);
        if let Some(m) = &self.matcher {
            k.push('\t');
            k.push_str(&m.canonical());
        }
        k
    }
}

/// A user policy from the harness config (trust base, §6.4). Three ordered
/// lists; within the §5.1 order a user deny cannot be overridden, a user ask
/// raises the effective confirmation to `user_confirm` (max-rule), and a
/// user allow can never lower a floor (it is consulted after every ask rule).
/// Since P-08 a rule may carry a [`Matcher`]: a deny matcher denies only the
/// calls it matches, an ask matcher asks only about them (and does not raise
/// the session-wide floor), an allow matcher allows only them — but the
/// order itself never moves (§5.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserPolicy {
    deny: Vec<Rule>,
    ask: Vec<Rule>,
    allow: Vec<Rule>,
}

/// A user policy that cannot be applied unambiguously.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyConfigError {
    /// Not `provider.*` and not a capability id.
    #[error("policy selector {0:?} is neither a capability id nor provider.*")]
    BadSelector(String),
    /// The same rule (selector AND matcher) appears twice (in one list or
    /// across lists). The §5.1 order would pick deny, but a config that says
    /// two things about one rule is refused so its author finds out. Two
    /// rules with the same selector and DIFFERENT matchers are fine: they
    /// say different things about different calls (`allow cargo test` but
    /// `ask git push`, P-08).
    #[error("policy rule {0:?} appears more than once")]
    Ambiguous(String),
    /// A policy file (v2, [`UserPolicy::from_json`]) whose shape is wrong:
    /// not an object, a missing or mis-typed list, an unknown key, a rule
    /// object without a `capability`, and the like.
    #[error("policy file is invalid: {0}")]
    BadRule(String),
    /// A `match` object the matcher refuses: unknown key, an empty or
    /// mis-typed condition, or a glob that is not a glob.
    #[error("policy matcher is invalid: {0}")]
    BadMatcher(String),
    /// A rule's `examples` failed at load: the rule does not behave as its
    /// author documented, or an example itself is malformed (§4.8: examples
    /// are checked as unit tests when the config loads).
    #[error("policy example failed: {0}")]
    BadExample(String),
}

/// A rule's selector as a digest line (the v1 spelling, unchanged).
fn selector_str(sel: &Selector) -> String {
    match sel {
        Selector::Capability(c) => c.as_str().to_owned(),
        Selector::Provider(p) => format!("{}.*", p.as_str()),
    }
}

impl UserPolicy {
    /// Build from selector strings; refuses malformed or repeated selectors.
    /// Every rule has no matcher (the v1 form); [`UserPolicy::from_json`]
    /// builds the v2 form with matchers.
    pub fn new(deny: &[&str], ask: &[&str], allow: &[&str]) -> Result<Self, PolicyConfigError> {
        let mut seen = BTreeSet::new();
        let mut parse = |list: &[&str]| -> Result<Vec<Rule>, PolicyConfigError> {
            list.iter()
                .map(|s| {
                    let rule = Rule {
                        selector: Selector::parse(s)?,
                        matcher: None,
                    };
                    if !seen.insert(rule.key()) {
                        return Err(PolicyConfigError::Ambiguous((*s).to_owned()));
                    }
                    Ok(rule)
                })
                .collect()
        };
        Ok(Self {
            deny: parse(deny)?,
            ask: parse(ask)?,
            allow: parse(allow)?,
        })
    }

    /// Build from a policy file's parsed JSON (v2, P-08): `{"deny": …,
    /// "ask": …, "allow": …}`, each list a list of rules (a list may be
    /// absent, which is empty — the v1 files rely on that). A rule is a v1
    /// selector string or an object `{"capability": …, "match": {…},
    /// "examples": […]}` (`match` and `examples` optional). The v1 shape
    /// parses identically and digests identically (superset, not a new
    /// format). Unknown keys, malformed rules and failing `examples` are
    /// refused: the file never loads half-understood (§4.8, fail-closed).
    pub fn from_json(v: &Value) -> Result<Self, PolicyConfigError> {
        let bad = |what: &str| PolicyConfigError::BadRule(what.to_owned());
        let obj = v
            .as_object()
            .ok_or_else(|| bad("policy file is not a JSON object"))?;
        for key in obj.keys() {
            if !matches!(key.as_str(), "deny" | "ask" | "allow") {
                return Err(bad(&format!("unknown policy key {key:?}")));
            }
        }
        let mut seen = BTreeSet::new();
        let mut list = |name: &str| -> Result<Vec<Rule>, PolicyConfigError> {
            // An absent list is empty (the v1 files rely on this); a list
            // that is present must be a list of rules.
            let Some(items) = obj.get(name) else {
                return Ok(Vec::new());
            };
            let Some(items) = items.as_array() else {
                return Err(bad(&format!("{name} must be a list of rules")));
            };
            items
                .iter()
                .map(|entry| {
                    let rule = rule_from_json(entry, name)?;
                    if !seen.insert(rule.key()) {
                        return Err(PolicyConfigError::Ambiguous(rule.key()));
                    }
                    Ok(rule)
                })
                .collect()
        };
        Ok(Self {
            deny: list("deny")?,
            ask: list("ask")?,
            allow: list("allow")?,
        })
    }

    /// SHA-256 of the policy's canonical form (each list in order, one
    /// rule per line, `deny`/`ask`/`allow` sections): journaled in the
    /// header so an audit replay under a different policy is refused
    /// before any decision is compared (§2.9, §7.1 header). A rule with a
    /// matcher appends its canonical matcher JSON after a TAB; a policy of
    /// v1 rules digests byte-for-byte as before (P-08 keeps old journals
    /// verifiable).
    pub fn digest(&self) -> harness_core::Digest {
        let mut s = String::new();
        for (name, list) in [
            ("deny", &self.deny),
            ("ask", &self.ask),
            ("allow", &self.allow),
        ] {
            s.push_str(name);
            s.push('\n');
            for rule in list {
                s.push_str(&rule.key());
                s.push('\n');
            }
        }
        harness_core::sha256(s.as_bytes())
    }

    /// Append one rule to the `ask` list (the P-29 protected-path floor:
    /// the harness raises its own asks on top of whatever the user wrote).
    /// A rule whose key (selector AND matcher) is already present in any
    /// list is refused as [`PolicyConfigError::Ambiguous`]: a floor that
    /// also allowed the same call would say two things about one rule.
    pub fn push_ask(&mut self, rule: Rule) -> Result<(), PolicyConfigError> {
        for list in [&self.deny, &self.ask, &self.allow] {
            if list.iter().any(|r| r.key() == rule.key()) {
                return Err(PolicyConfigError::Ambiguous(rule.key()));
            }
        }
        self.ask.push(rule);
        Ok(())
    }

    /// The indices (in list order) of the rules of `list` whose selector
    /// covers `id`, each with its matcher: the candidates a decision walks
    /// in §5.1 order, matcher-tested per call.
    fn candidates(list: &[Rule], id: &CapId) -> Vec<UserCandidate> {
        list.iter()
            .enumerate()
            .filter(|(_, r)| r.selector.matches(id))
            .map(|(index, r)| UserCandidate {
                index,
                matcher: r.matcher.clone(),
            })
            .collect()
    }
}

/// One user rule as a JSON object: `capability` required, `match` and
/// `examples` optional, nothing else.
fn rule_from_json(entry: &Value, list: &str) -> Result<Rule, PolicyConfigError> {
    let bad = |what: String| PolicyConfigError::BadRule(format!("{list} rule: {what}"));
    // v1: a bare selector string. v2: an object.
    if let Some(s) = entry.as_str() {
        return Ok(Rule {
            selector: Selector::parse(s)?,
            matcher: None,
        });
    }
    let entry = entry
        .as_object()
        .ok_or_else(|| bad("a rule must be a selector string or an object".to_owned()))?;
    let mut selector = None;
    let mut matcher = None;
    let mut examples: Option<&Vec<Value>> = None;
    for (key, val) in entry {
        match key.as_str() {
            "capability" => {
                let Some(s) = val.as_str() else {
                    return Err(bad("capability must be a string".to_owned()));
                };
                selector = Some(Selector::parse(s)?);
            }
            "match" => matcher = Matcher::parse(val)?,
            "examples" => {
                let Some(items) = val.as_array() else {
                    return Err(bad("examples must be a list".to_owned()));
                };
                examples = Some(items);
            }
            other => return Err(bad(format!("unknown key {other:?}"))),
        }
    }
    let selector = selector.ok_or_else(|| bad("a rule needs a capability".to_owned()))?;
    let rule = Rule { selector, matcher };
    if let Some(items) = examples {
        check_examples(&rule, items)?;
    }
    Ok(rule)
}

/// A rule's `examples` (§4.8): `{"capability": …, "args": {…},
/// "expect": "match"|"not_match"}`. Each is checked against the rule NOW,
/// at load: a rule that does not do what its author documented refuses the
/// whole file (Codex-style `match`/`not_match` unit tests, R1 §3.1).
fn check_examples(rule: &Rule, items: &[Value]) -> Result<(), PolicyConfigError> {
    for (i, item) in items.iter().enumerate() {
        let bad = |what: String| PolicyConfigError::BadExample(format!("example {i}: {what}"));
        let Some(obj) = item.as_object() else {
            return Err(bad("an example must be an object".to_owned()));
        };
        let mut capability = None;
        let mut args: Option<&Value> = None;
        let mut expect = None;
        for (key, val) in obj {
            match key.as_str() {
                "capability" => {
                    let Some(s) = val.as_str() else {
                        return Err(bad("capability must be a string".to_owned()));
                    };
                    capability =
                        Some(CapId::new(s).map_err(|_| {
                            bad(format!("capability {s:?} is not a capability id"))
                        })?);
                }
                "args" => {
                    if !val.is_object() {
                        return Err(bad("args must be an object".to_owned()));
                    }
                    args = Some(val);
                }
                "expect" => {
                    let Some(s) = val.as_str() else {
                        return Err(bad("expect must be a string".to_owned()));
                    };
                    expect = Some(match s {
                        "match" => true,
                        "not_match" => false,
                        other => {
                            return Err(bad(format!(
                                "expect is {other:?}, want \"match\" or \"not_match\""
                            )))
                        }
                    });
                }
                other => return Err(bad(format!("unknown key {other:?}"))),
            }
        }
        let Some(args) = args else {
            return Err(bad("an example needs args".to_owned()));
        };
        let Some(expect) = expect else {
            return Err(bad(
                "an example needs expect: \"match\" or \"not_match\"".to_owned()
            ));
        };
        // Under a provider selector an example must say which capability it
        // is about; under a capability selector it may omit it. Either way
        // the capability must be one the rule's selector covers.
        let cap = match (&rule.selector, capability) {
            (_, Some(c)) => c,
            (Selector::Capability(c), None) => c.clone(),
            (Selector::Provider(_), None) => {
                return Err(bad(
                    "under a provider.* selector an example needs an explicit capability"
                        .to_owned(),
                ))
            }
        };
        if !rule.selector.matches(&cap) {
            return Err(bad(format!(
                "capability {} is not covered by the rule's selector",
                cap.as_str()
            )));
        }
        let matched = rule.matcher.as_ref().is_none_or(|m| m.matches(args));
        if matched != expect {
            let want = if expect { "match" } else { "not_match" };
            return Err(bad(format!(
                "args {args} was expected to {want} and did not"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Decisions.
// ---------------------------------------------------------------------------

/// The rule that produced a decision (§5.1: every decision carries one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleId {
    /// A built-in rule, by stable name (e.g. `deny.not-granted`).
    Builtin(&'static str),
    /// Entry `index` of a user rule list.
    User {
        /// Which list.
        list: RuleList,
        /// Index in that list.
        index: usize,
    },
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleId::Builtin(n) => f.write_str(n),
            RuleId::User { list, index } => write!(f, "user.{list:?}[{index}]"),
        }
    }
}

/// Why a call was denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// Not in the session's active set (unknown or never granted).
    NotGranted,
    /// Quarantined (pin drift, H4).
    Quarantined,
    /// A class this slice does not decide (write, execute, irreversible).
    ClassOutOfScope(Effect),
    /// `restricted` sensitivity (INV-27).
    Restricted,
    /// Egress needs the allowlist proxy (H4).
    EgressUnavailable,
    /// Execute class without `Conformed`.
    NoConformed,
    /// `personal` data the session was not granted.
    PersonalNotGranted,
    /// A user deny rule.
    UserDenied,
    /// Arguments outside the capability's input schema.
    Args(ArgsError),
    /// A built-in file tool's path argument leaves the workspace.
    Path(PathRefused),
    /// A command-runner call refused before it runs (H2d, INV-13).
    Exec(ExecRefused),
    /// An ask with nobody to answer it (§5.2: every Ask becomes Deny).
    NoApprover,
    /// No allow rule matched (the §5.1 default).
    NoRuleMatched,
}

/// Why a `harness.exec.run` call is refused before anything runs (§4.8,
/// INV-13). The program is resolved by NAME against the task's exec
/// allowlist; the model never chooses a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecRefused {
    /// `argv` is empty: there is no program.
    EmptyArgv,
    /// `argv[0]` is not a program name on the task's exec allowlist (a
    /// path, a shell that was not allowlisted, anything else).
    NotAllowlisted,
    /// More than [`EXEC_MAX_ARGS`] items.
    TooManyArgs,
    /// An item holds a NUL byte, which no OS argv can carry.
    Nul,
}

/// The most `argv` items one `harness.exec.run` call may pass (the 64 KiB
/// action cap binds on their total size first).
pub const EXEC_MAX_ARGS: usize = 256;

/// What may happen to one call (§5.1). Not a verdict (§1.4, INV-28).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Allowed.
    Allow {
        /// Producing rule.
        rule: RuleId,
    },
    /// Needs an approval at this tier.
    Ask {
        /// Approval tier.
        tier: Confirmation,
        /// Producing rule.
        rule: RuleId,
    },
    /// Refused.
    Deny {
        /// Why.
        reason: DenyReason,
        /// Producing rule.
        rule: RuleId,
    },
}

impl PolicyDecision {
    /// The producing rule.
    pub fn rule(&self) -> RuleId {
        match self {
            PolicyDecision::Allow { rule }
            | PolicyDecision::Ask { rule, .. }
            | PolicyDecision::Deny { rule, .. } => *rule,
        }
    }
}

/// A proposed tool call, after parsing (§2.2 step 4). `args` is model
/// output: this crate only validates it, never trusts it.
#[derive(Debug, Clone, PartialEq)]
pub struct Call {
    /// Capability id as the model wrote it.
    pub capability: String,
    /// Arguments object.
    pub args: Value,
}

/// A call that policy allowed. Fields are private and the only
/// constructors are [`Session::authorize`] and, for a call policy asked
/// about, [`Session::authorize_approved`] with a redeemed approval token
/// (§5.3), so a provider that accepts only `Authorized<Call>` cannot be
/// driven by an unchecked call (§4.5).
///
/// ```compile_fail,E0451
/// let forged = harness_policy::Authorized {
///     call: harness_policy::Call { capability: "harness.fs.read".into(), args: serde_json::json!({}) },
///     rule: harness_policy::RuleId::Builtin("allow.default.read"),
/// };
/// ```
#[derive(Debug)]
pub struct Authorized<C> {
    call: C,
    rule: RuleId,
}

/// The canonical form of a call, digested for the journal's write-ahead
/// intent: the compact JSON of `{"args": …, "capability": …}` with sorted
/// keys (serde_json's map is ordered). The journal calls this on the very
/// `Authorized<Call>` it then returns as `Journaled`, so the intent names
/// exactly the call that may run (H1c review F-7). The same digest binds
/// approval tokens to the call they approve (§5.3).
impl harness_core::CallDigest for Authorized<Call> {
    fn call_digest(&self) -> harness_core::Digest {
        canonical_call_digest(&self.call)
    }
}

/// SHA-256 of a call's canonical form (the sorted-key compact JSON of
/// `{"args": …, "capability": …}`): the one digest shared by the journal's
/// call intent ([`harness_core::CallDigest`]) and approval-token binding
/// (§5.3), so a token can never bind a call under a different spelling.
pub(crate) fn canonical_call_digest(call: &Call) -> harness_core::Digest {
    let mut m = serde_json::Map::new();
    m.insert("args".into(), call.args.clone());
    m.insert("capability".into(), Value::from(call.capability.clone()));
    harness_core::sha256(Value::Object(m).to_string().as_bytes())
}

impl<C> Authorized<C> {
    /// The authorised call.
    pub fn call(&self) -> &C {
        &self.call
    }

    /// The allow rule that authorised it (journaled with the intent).
    pub fn rule(&self) -> RuleId {
        self.rule
    }
}

// ---------------------------------------------------------------------------
// Session planning (§2.1 "plan session", §5.4).
// ---------------------------------------------------------------------------

/// The task's workspace declaration. Workspaces are private and their
/// content third-party by default (§5.4); only privacy can be declared away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorkspaceDecl {
    /// The task spec declared the workspace `public`.
    pub declared_public: bool,
}

/// What the task spec asks of policy.
#[derive(Debug, Clone, Default)]
pub struct SessionSpec {
    /// Granted capability ids.
    pub grants: Vec<String>,
    /// The workspace, if the task grants one. Built-in file tools exist only
    /// with a workspace (§4.8).
    pub workspace: Option<WorkspaceDecl>,
    /// An approver (CLI prompt or embedding UI) is present.
    pub approver_present: bool,
    /// The session was granted personal data (§5.2).
    pub personal_data_granted: bool,
    /// The run holds a `Conformed` sandbox witness (§6.1): the caller
    /// obtained one from `harness_sandbox::require()` before planning. An
    /// execute-class capability is planned and decided only with one
    /// (INV-6). The policy crate cannot name the witness's type (the edge
    /// runs sandbox → policy), so the caller states it.
    pub conformed: bool,
    /// The program names on the task's exec allowlist (§4.8, H2d): a
    /// command runs only when its `argv[0]` is one of them (INV-13).
    pub exec_programs: Vec<String>,
    /// The run's read window, in lines (H2e: the profile's): a read's
    /// `lines` above it is denied like any argument outside the schema the
    /// model was shown. `None`: the manifest's maximum alone.
    pub read_window: Option<u64>,
}

/// Why a session was refused at planning. Nothing has run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionRefused {
    /// A grant names no admitted capability.
    #[error("grant {0:?} names no admitted capability")]
    UnknownCapability(String),
    /// A grant appears twice.
    #[error("grant {0:?} appears twice")]
    DuplicateGrant(String),
    /// A grant resolves to more than one capability.
    #[error("grant {0:?} is ambiguous")]
    Ambiguous(String),
    /// A `restricted` capability (INV-27: refused in the standalone default).
    #[error("capability {0} is restricted; no v0.1 session may hold it")]
    Restricted(String),
    /// Private ∧ untrusted ∧ egress (INV-9).
    #[error(
        "lethal trifecta: private via {private}, untrusted via {untrusted}, egress via {egress}"
    )]
    Trifecta {
        /// A capability (or `workspace`) giving P.
        private: String,
        /// A capability (or `workspace`) giving U.
        untrusted: String,
        /// A capability giving E.
        egress: String,
    },
    /// A built-in file tool granted without a workspace.
    #[error("capability {0} needs a workspace and the task grants none")]
    NoWorkspace(String),
    /// An execute-class capability granted with no `Conformed` sandbox
    /// witness (INV-6: no unconfined fallback).
    #[error("capability {0} needs a conformed sandbox and this host has none; refused")]
    NoConfinement(String),
    /// A class or feature this build's policy does not decide.
    #[error("capability {capability}: {what} is not decided by this build's policy; refused")]
    OutOfScope {
        /// Capability.
        capability: String,
        /// What.
        what: &'static str,
    },
    /// A granted delegate whose child scope could read above the delegate's
    /// own sensitivity (P-38, D12): the session's trifecta label would not
    /// cover what a helper run reads (§9).
    #[error(
        "capability {0}: a helper run could read above the delegate's own sensitivity; refused"
    )]
    DelegateScope(String),
    /// A grant a child run may not hold (P-38, D11): only the built-in fs
    /// tools and the submit sentinel plan into a child.
    #[error("capability {0} may not be granted to a helper run; refused")]
    ChildScope(String),
}

/// Compute the trifecta labels over an active set plus the workspace
/// (§5.4). `Err` names one source per label.
pub fn trifecta(
    active: &[(&CapId, EffectiveClass)],
    workspace: Option<WorkspaceDecl>,
) -> Result<(), SessionRefused> {
    let ws_private = workspace.is_some_and(|w| !w.declared_public);
    let ws_untrusted = workspace.is_some();
    let find = |pred: &dyn Fn(&EffectiveClass) -> bool| {
        active
            .iter()
            .find(|(_, c)| pred(c))
            .map(|(id, _)| id.to_string())
    };
    let p = find(&|c| c.sensitivity >= Sensitivity::Personal)
        .or_else(|| ws_private.then(|| "workspace".to_owned()));
    let u = find(&|c| c.content == Content::ThirdParty)
        .or_else(|| ws_untrusted.then(|| "workspace".to_owned()));
    let e = find(&|c| c.egress != Egress::None);
    match (p, u, e) {
        (Some(private), Some(untrusted), Some(egress)) => Err(SessionRefused::Trifecta {
            private,
            untrusted,
            egress,
        }),
        _ => Ok(()),
    }
}

/// One user-rule candidate for a capability: the rule's index in its list
/// plus its matcher, if it carries one (P-08). Plan time resolves
/// selectors; decide time matcher-tests the candidates against the call's
/// canonical args, first match winning (§5.1).
#[derive(Debug, Clone)]
struct UserCandidate {
    index: usize,
    matcher: Option<Matcher>,
}

/// First candidate whose matcher (or lack of one) matches `args`: the
/// §5.1 "first match wins" within a list. Matcher conditions on absent or
/// mis-shaped arguments never hold, so an unmatched candidate falls
/// through to the next one and finally to the built-in rules.
fn first_matching(cands: &[UserCandidate], args: &Value) -> Option<usize> {
    cands
        .iter()
        .find(|c| c.matcher.as_ref().is_none_or(|m| m.matches(args)))
        .map(|c| c.index)
}

#[derive(Debug, Clone)]
struct Active {
    class: EffectiveClass,
    schema: InputSchema,
    user_deny: Vec<UserCandidate>,
    user_ask: Vec<UserCandidate>,
    user_allow: Vec<UserCandidate>,
    /// A built-in file tool: its `path` argument must stay in the workspace.
    fs_tool: bool,
    /// The built-in submit sentinel (§2.5).
    submit: bool,
    /// The built-in checklist (`harness.task.todo`, H2e): allowed by its
    /// named rule after every deny rule and the schema.
    todo: bool,
    /// The built-in delegate (`harness.task.delegate`, P-38): a read-class
    /// call that starts one read-only helper run, granted only explicitly;
    /// its label must cover the child scope (checked at planning).
    delegate: bool,
    /// A built-in workspace edit (`harness.edit.*`, §4.8, H2b): its `path`
    /// must stay in the workspace, and it is allowed only by a user allow
    /// rule or an approval (see [`Session::decide`]).
    edit: bool,
    /// The built-in command runner (`harness.exec.run`, §4.8, H2d): its
    /// `cwd` must stay in the workspace, its `argv[0]` must be on the exec
    /// allowlist, and it is allowed only by a user allow rule or an
    /// approval, and only with a conformed sandbox.
    exec: bool,
}

/// A planned session: the active set with each capability's effective
/// class. Constructible only through [`Session::plan`].
#[derive(Debug, Clone)]
pub struct Session {
    active: BTreeMap<CapId, Active>,
    quarantined: BTreeSet<CapId>,
    approver_present: bool,
    personal_granted: bool,
    conformed: bool,
    exec_programs: BTreeSet<String>,
    read_window: Option<u64>,
}

impl Session {
    /// The program names on the task's exec allowlist (H2f), in name order:
    /// task configuration, so a denial may list them.
    pub fn exec_programs(&self) -> impl Iterator<Item = &str> {
        self.exec_programs.iter().map(String::as_str)
    }
}

/// A grant's resolution (private mirror of `Resolved` without provenance).
enum Lookup<'a> {
    One(&'a Capability),
    NotFound,
    Ambiguous,
}

impl Session {
    /// Plan a session: every grant must resolve to exactly one admitted
    /// capability, and the set must pass the session-level refusals, in this
    /// order: resolution → `restricted` → trifecta → workspace → classes this
    /// slice does not decide.
    pub fn plan(
        spec: &SessionSpec,
        registry: &Registry,
        policy: &UserPolicy,
    ) -> Result<Self, SessionRefused> {
        Self::plan_with(spec, policy, &|g| match registry.resolve(g) {
            Resolved::One { capability, .. } => Lookup::One(capability),
            Resolved::NotFound => Lookup::NotFound,
            Resolved::Ambiguous => Lookup::Ambiguous,
        })
    }

    /// The planning logic over any lookup. Private: production planning goes
    /// through an admitted [`Registry`] only; unit tests use this to plan
    /// over parsed manifests the H1 admission gate would refuse, so the
    /// decision order is exercised on every dimension now.
    fn plan_with<'a>(
        spec: &SessionSpec,
        policy: &UserPolicy,
        lookup: &dyn Fn(&str) -> Lookup<'a>,
    ) -> Result<Self, SessionRefused> {
        let mut seen = BTreeSet::new();
        let mut resolved: Vec<&Capability> = Vec::with_capacity(spec.grants.len());
        for g in &spec.grants {
            if !seen.insert(g.as_str()) {
                return Err(SessionRefused::DuplicateGrant(g.clone()));
            }
            match lookup(g) {
                Lookup::One(capability) => resolved.push(capability),
                Lookup::NotFound => return Err(SessionRefused::UnknownCapability(g.clone())),
                Lookup::Ambiguous => return Err(SessionRefused::Ambiguous(g.clone())),
            }
        }

        let mut classes = Vec::with_capacity(resolved.len());
        for c in &resolved {
            let user_ask = UserPolicy::candidates(&policy.ask, c.id());
            // Only an UNCONDITIONAL ask rule (no matcher) raises the
            // capability's confirmation floor: a matcher ask asks about the
            // calls it matches, at decide time, not about the capability
            // (P-08: `ask git push` must not make `cargo test` ask).
            let floor = if user_ask.iter().any(|c| c.matcher.is_none()) {
                Confirmation::UserConfirm
            } else {
                Confirmation::None
            };
            classes.push((c.id(), effective_class(c, floor), user_ask));
        }

        // INV-27 before anything else can be said about the set.
        if let Some((id, _, _)) = classes
            .iter()
            .find(|(_, cl, _)| cl.sensitivity == Sensitivity::Restricted)
        {
            return Err(SessionRefused::Restricted(id.to_string()));
        }

        let labels: Vec<(&CapId, EffectiveClass)> =
            classes.iter().map(|(id, cl, _)| (*id, *cl)).collect();
        trifecta(&labels, spec.workspace)?;

        for (c, (id, cl, _)) in resolved.iter().zip(&classes) {
            let out = |what| SessionRefused::OutOfScope {
                capability: id.to_string(),
                what,
            };
            let reg = builtin::registration(id.as_str());
            if reg.is_some_and(|t| t.kind.needs_workspace()) && spec.workspace.is_none() {
                return Err(SessionRefused::NoWorkspace(id.to_string()));
            }
            if cl.effect != Effect::Read && !reg.is_some_and(|t| (t.labels)(c)) {
                return Err(out("a non-read effect class"));
            }
            // INV-6: no execution without a conformed sandbox, refused at
            // planning, before anything starts (§4.5).
            if cl.requires_conformed && !spec.conformed {
                return Err(SessionRefused::NoConfinement(id.to_string()));
            }
            if cl.egress != Egress::None {
                return Err(out("egress (the allowlist proxy is H4)"));
            }
        }

        let mut active = BTreeMap::new();
        for (c, (_, class, user_ask)) in resolved.iter().zip(&classes) {
            active.insert(
                c.id().clone(),
                Active {
                    class: *class,
                    schema: c.input_schema().clone(),
                    user_deny: UserPolicy::candidates(&policy.deny, c.id()),
                    user_ask: user_ask.clone(),
                    user_allow: UserPolicy::candidates(&policy.allow, c.id()),
                    fs_tool: c.id().provider() == BUILTIN_NAMESPACE
                        && c.id().as_str().starts_with(builtin::FS_PREFIX),
                    submit: builtin::is_submit_sentinel(c),
                    todo: builtin::is_builtin_todo(c),
                    delegate: builtin::is_builtin_delegate(c),
                    edit: builtin::is_builtin_edit(c),
                    exec: builtin::is_builtin_exec(c),
                },
            );
        }

        // D12 (P-38 §9): a delegate's static label must cover what its
        // helper can read. The child scope (§2.2) is the parent's grants
        // under the eligible read ids, so a grant there that could read
        // above the delegate's own sensitivity would let a child read past
        // the label the trifecta saw, without any journaled raise. Planning
        // refuses it at session start. In this build every eligible tool is
        // operational, so this never fires on a real manifest; `plan_with`
        // over a fixture exercises it.
        if let Some((delegated, d)) = active.iter().find(|(_, a)| a.delegate) {
            for (g, (_, (_, child, _))) in spec.grants.iter().zip(resolved.iter().zip(&classes)) {
                if builtin::CHILD_ELIGIBLE.contains(&g.as_str())
                    && child.sensitivity > d.class.sensitivity
                {
                    return Err(SessionRefused::DelegateScope(delegated.to_string()));
                }
            }
        }

        Ok(Self {
            active,
            quarantined: BTreeSet::new(),
            approver_present: spec.approver_present,
            personal_granted: spec.personal_data_granted,
            conformed: spec.conformed,
            exec_programs: spec.exec_programs.iter().cloned().collect(),
            read_window: spec.read_window,
        })
    }

    /// Plan a helper run's session (P-38 §11): the parent's planning plus
    /// one refusal — a grant whose registration is not a built-in fs tool
    /// or the submit sentinel is refused as [`SessionRefused::ChildScope`]
    /// — so a child holds only the read-only explorer set. A provider
    /// capability has no registration and is refused like the rest: the
    /// depth limit is not a table the child could grow into.
    pub fn plan_child(
        spec: &SessionSpec,
        registry: &Registry,
        policy: &UserPolicy,
    ) -> Result<Self, SessionRefused> {
        let child = Self::plan(spec, registry, policy)?;
        for g in &spec.grants {
            if !matches!(
                builtin::registration(g).map(|t| t.kind),
                Some(builtin::ToolKind::Fs) | Some(builtin::ToolKind::Submit)
            ) {
                return Err(SessionRefused::ChildScope(g.clone()));
            }
        }
        Ok(child)
    }

    /// Quarantine a capability for the rest of the session (H4 wires this to
    /// pin drift; removal can only shrink the trifecta labels).
    pub fn quarantine(&mut self, id: &CapId) {
        self.quarantined.insert(id.clone());
    }

    /// The effective class of an active capability.
    pub fn class(&self, id: &str) -> Option<EffectiveClass> {
        self.active
            .iter()
            .find(|(k, _)| k.as_str() == id)
            .map(|(_, a)| a.class)
    }

    /// Decide one call (§5.1). Pure and total.
    pub fn decide(&self, call: &Call) -> PolicyDecision {
        let deny = |reason, name| PolicyDecision::Deny {
            reason,
            rule: RuleId::Builtin(name),
        };

        // ---- 1. Deny rules: first match wins, nothing later overrides. ----
        let Some((id, a)) = self
            .active
            .iter()
            .find(|(k, _)| k.as_str() == call.capability)
        else {
            return deny(DenyReason::NotGranted, "deny.not-granted");
        };
        if self.quarantined.contains(id) {
            return deny(DenyReason::Quarantined, "deny.quarantined");
        }
        let cl = a.class;
        if cl.effect != Effect::Read && !a.submit && !a.todo && !a.edit && !a.exec {
            return deny(
                DenyReason::ClassOutOfScope(cl.effect),
                "deny.class-out-of-scope",
            );
        }
        if cl.sensitivity == Sensitivity::Restricted {
            return deny(DenyReason::Restricted, "deny.restricted");
        }
        if cl.egress != Egress::None {
            return deny(DenyReason::EgressUnavailable, "deny.egress-unavailable");
        }
        // INV-6: execute-class only with a conformed sandbox witness.
        if cl.requires_conformed && !self.conformed {
            return deny(DenyReason::NoConformed, "deny.no-conformed");
        }
        if cl.sensitivity == Sensitivity::Personal && !self.personal_granted {
            return deny(DenyReason::PersonalNotGranted, "deny.personal-not-granted");
        }
        if let Some(index) = first_matching(&a.user_deny, &call.args) {
            return PolicyDecision::Deny {
                reason: DenyReason::UserDenied,
                rule: RuleId::User {
                    list: RuleList::Deny,
                    index,
                },
            };
        }
        if let Err(e) = a.schema.validate_args(&call.args) {
            return deny(DenyReason::Args(e), "deny.args-schema");
        }
        // The run's read window (H2e): the manifest's maximum for `lines` is
        // the widest any profile may set; the window is the maximum the
        // model is shown, and the one policy holds a read to.
        if a.fs_tool && call.capability == builtin::READ_ID {
            let lines = call.args.get("lines").and_then(Value::as_u64);
            if let (Some(max), Some(n)) = (self.read_window, lines) {
                if n > max {
                    return deny(
                        DenyReason::Args(ArgsError {
                            at: "/lines".into(),
                            detail: format!("above the read window of {max} lines"),
                        }),
                        "deny.args-schema",
                    );
                }
            }
        }
        if a.fs_tool || a.edit {
            if let Some(p) = call.args.get("path") {
                // The schema says string; anything else was refused above.
                let checked = p.as_str().map_or(Err(PathRefused::Empty), workspace_path);
                if let Err(e) = checked {
                    return deny(DenyReason::Path(e), "deny.path-outside-workspace");
                }
            }
        }
        if a.exec {
            if let Some(p) = call.args.get("cwd") {
                let checked = p.as_str().map_or(Err(PathRefused::Empty), workspace_path);
                if let Err(e) = checked {
                    return deny(DenyReason::Path(e), "deny.path-outside-workspace");
                }
            }
            if let Err(e) = self.exec_argv(&call.args) {
                let name = match e {
                    ExecRefused::NotAllowlisted | ExecRefused::EmptyArgv => {
                        "deny.exec-not-allowlisted"
                    }
                    ExecRefused::TooManyArgs | ExecRefused::Nul => "deny.exec-argv",
                };
                return deny(DenyReason::Exec(e), name);
            }
        }

        // ---- 2. Ask rules. ----
        // An unconditional ask rule raised the floor at plan time; a
        // matcher ask rule (P-08) asks only about the calls it matches.
        // The user rule is credited only when the tier it produced is
        // exactly `user_confirm` — its own tier or a matcher ask's tier —
        // never above it: there the floor asks, not the user.
        let ask_hit = first_matching(&a.user_ask, &call.args);
        if cl.confirmation >= Confirmation::UserConfirm || ask_hit.is_some() {
            let rule = match ask_hit {
                Some(index) if cl.confirmation <= Confirmation::UserConfirm => RuleId::User {
                    list: RuleList::Ask,
                    index,
                },
                _ => RuleId::Builtin("ask.confirmation-floor"),
            };
            let tier = cl.confirmation.max(Confirmation::UserConfirm);
            if !self.approver_present {
                return deny(DenyReason::NoApprover, "deny.no-approver");
            }
            return PolicyDecision::Ask { tier, rule };
        }

        // ---- 3. Allow rules. ----
        if let Some(index) = first_matching(&a.user_allow, &call.args) {
            return PolicyDecision::Allow {
                rule: RuleId::User {
                    list: RuleList::Allow,
                    index,
                },
            };
        }
        if cl.effect == Effect::Read && cl.sensitivity <= Sensitivity::Operational {
            return PolicyDecision::Allow {
                rule: RuleId::Builtin("allow.default.read"),
            };
        }
        if a.submit {
            return PolicyDecision::Allow {
                rule: RuleId::Builtin("allow.task-submit"),
            };
        }
        // The checklist (H2e) changes only the run's own list, which the
        // model sees in the result; nothing in the workspace or outside it.
        if a.todo {
            return PolicyDecision::Allow {
                rule: RuleId::Builtin(TODO_RULE),
            };
        }
        // Built-in workspace edits (H2b). §5.2 allows them by default
        // because "the sandbox plus snapshots make them undoable"; this
        // build has neither (it edits the task's workspace in place), so
        // they take the provider-declared write row instead: ask unless a
        // user allow rule (checked above) allows them, and with no approver
        // the ask is a deny (§5.2). The decision is an Ask at
        // `user_confirm` although the declared confirmation is `none`: the
        // tier comes from this rule, not from the class.
        if a.edit {
            if !self.approver_present {
                return deny(DenyReason::NoApprover, "deny.no-approver");
            }
            return PolicyDecision::Ask {
                tier: Confirmation::UserConfirm,
                rule: RuleId::Builtin(EDIT_DEFAULT_RULE),
            };
        }
        // The command runner (H2d): execute-class asks by default. The
        // sandbox is the control and the allowlist names the programs, but
        // a build script is arbitrary code whatever the argv says (§4.8), so
        // running one is the user's call unless a user allow rule (checked
        // above) says so. No approver: the ask is a deny (§5.2).
        if a.exec {
            if !self.approver_present {
                return deny(DenyReason::NoApprover, "deny.no-approver");
            }
            return PolicyDecision::Ask {
                tier: Confirmation::UserConfirm,
                rule: RuleId::Builtin(EXEC_DEFAULT_RULE),
            };
        }

        // ---- 4. Default: deny. ----
        deny(DenyReason::NoRuleMatched, "deny.default")
    }

    /// The `argv` rule of the command runner (INV-13): a non-empty list of
    /// at most [`EXEC_MAX_ARGS`] strings without NUL whose first item is a
    /// program NAME on the task's exec allowlist. The schema has already
    /// made `argv` a list of strings.
    fn exec_argv(&self, args: &Value) -> Result<(), ExecRefused> {
        let items = args
            .get("argv")
            .and_then(Value::as_array)
            .ok_or(ExecRefused::EmptyArgv)?;
        let first = items
            .first()
            .and_then(Value::as_str)
            .ok_or(ExecRefused::EmptyArgv)?;
        if items.len() > EXEC_MAX_ARGS {
            return Err(ExecRefused::TooManyArgs);
        }
        if items
            .iter()
            .any(|v| v.as_str().is_none_or(|s| s.contains('\0')))
        {
            return Err(ExecRefused::Nul);
        }
        if !self.exec_programs.contains(first) {
            return Err(ExecRefused::NotAllowlisted);
        }
        Ok(())
    }

    /// Whether the session holds a conformed sandbox witness (§6.1).
    pub fn conformed(&self) -> bool {
        self.conformed
    }

    /// Mint an [`Authorized`] call, only when [`Session::decide`] allows it.
    /// Any other decision is returned as the error, unchanged.
    pub fn authorize(&self, call: Call) -> Result<Authorized<Call>, PolicyDecision> {
        match self.decide(&call) {
            PolicyDecision::Allow { rule } => Ok(Authorized { call, rule }),
            other => Err(other),
        }
    }

    /// Mint an [`Authorized`] call from an `Ask` plus a REDEEMED approval
    /// token (§5.3): the only path besides [`Session::authorize`], and
    /// nothing else turns an `Ask` into a call. The decision must be
    /// `Ask`, and the [`approval::Redeemed`] proof must bind exactly this
    /// call — same capability, same canonical argument digest
    /// ([`canonical_call_digest`]), same tier as asked. The proof is
    /// consumed by value, so a single-use approval cannot be spent twice.
    ///
    /// Anything else fails closed: an `Ask` whose token does not bind this
    /// call stays an `Ask` (never a mint), and `Allow`/`Deny` decisions
    /// pass through untouched — an approval can never authorize a call
    /// policy did not ask about.
    pub fn authorize_approved(
        &self,
        call: Call,
        redeemed: approval::Redeemed,
    ) -> Result<Authorized<Call>, PolicyDecision> {
        match self.decide(&call) {
            PolicyDecision::Ask { tier, rule } => {
                if redeemed.tier() == tier
                    && redeemed.capability().as_str() == call.capability
                    && redeemed.args_sha256() == canonical_call_digest(&call)
                {
                    Ok(Authorized { call, rule })
                } else {
                    Err(PolicyDecision::Ask { tier, rule })
                }
            }
            other => Err(other),
        }
    }
}

#[cfg(test)]
mod tests;
