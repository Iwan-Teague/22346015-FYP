//! rustyharness policy, READ CLASSES ONLY (design `docs/01-design-v0.1.md`
//! §4.2, §5.1, §5.2, §5.4; this slice of §9 H1).
//!
//! Pure: no I/O, no clock, no global state. Everything a decision reads is
//! in its arguments, so audit replay can recompute it (§2.9).
//!
//! - [`effective_class`]: the max-rule of §4.2 (declared ∨ derived floors ∨
//!   user policy).
//! - [`Session::plan`]: session-level refusals before anything runs:
//!   unknown or duplicate grants, `restricted` (INV-27), the trifecta
//!   (INV-9, pure half), and every class this slice does not decide. The
//!   one write-class capability it does decide is the built-in submit
//!   sentinel [`SUBMIT_ID`] (§2.5), allowed by the named rule
//!   `allow.task-submit` after every deny rule and schema check.
//! - [`Session::decide`]: the §5.1 order — deny rules (first match wins,
//!   cannot be overridden), then ask rules, then allow rules, then DENY by
//!   default. Every decision carries the id of the rule that produced it.
//! - [`Session::authorize`]: the only mint of [`Authorized`]; only `Allow`
//!   mints. An `Ask` cannot be turned into an `Authorized` in this build
//!   (approval tokens are H2), and with no approver present an `Ask` is a
//!   `Deny` (§5.2).
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

pub mod locality;
pub mod path;

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

/// User policy from the harness config (trust base, §6.4). Three ordered
/// lists; within the §5.1 order a user deny cannot be overridden, a user ask
/// raises the effective confirmation to `user_confirm` (max-rule), and a
/// user allow can never lower a floor (it is consulted after every ask rule).
#[derive(Debug, Clone, Default)]
pub struct UserPolicy {
    deny: Vec<Selector>,
    ask: Vec<Selector>,
    allow: Vec<Selector>,
}

/// A user policy that cannot be applied unambiguously.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyConfigError {
    /// Not `provider.*` and not a capability id.
    #[error("policy selector {0:?} is neither a capability id nor provider.*")]
    BadSelector(String),
    /// The same selector appears twice (in one list or across lists). The
    /// §5.1 order would pick deny, but a config that says two things about
    /// one selector is refused so its author finds out.
    #[error("policy selector {0:?} appears more than once")]
    Ambiguous(String),
}

impl UserPolicy {
    /// Build from selector strings; refuses malformed or repeated selectors.
    pub fn new(deny: &[&str], ask: &[&str], allow: &[&str]) -> Result<Self, PolicyConfigError> {
        let mut seen = BTreeSet::new();
        let mut parse = |list: &[&str]| -> Result<Vec<Selector>, PolicyConfigError> {
            list.iter()
                .map(|s| {
                    let sel = Selector::parse(s)?;
                    if !seen.insert(sel.clone()) {
                        return Err(PolicyConfigError::Ambiguous((*s).to_owned()));
                    }
                    Ok(sel)
                })
                .collect()
        };
        Ok(Self {
            deny: parse(deny)?,
            ask: parse(ask)?,
            allow: parse(allow)?,
        })
    }

    /// SHA-256 of the policy's canonical form (each list in order, one
    /// selector per line, `deny`/`ask`/`allow` sections): journaled in the
    /// header so an audit replay under a different policy is refused
    /// before any decision is compared (§2.9, §7.1 header).
    pub fn digest(&self) -> harness_core::Digest {
        let mut s = String::new();
        for (name, list) in [
            ("deny", &self.deny),
            ("ask", &self.ask),
            ("allow", &self.allow),
        ] {
            s.push_str(name);
            s.push('\n');
            for sel in list {
                match sel {
                    Selector::Capability(c) => s.push_str(c.as_str()),
                    Selector::Provider(p) => {
                        s.push_str(p.as_str());
                        s.push_str(".*");
                    }
                }
                s.push('\n');
            }
        }
        harness_core::sha256(s.as_bytes())
    }

    fn first_match(list: &[Selector], id: &CapId) -> Option<usize> {
        list.iter().position(|s| s.matches(id))
    }
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
    /// An ask with nobody to answer it (§5.2: every Ask becomes Deny).
    NoApprover,
    /// No allow rule matched (the §5.1 default).
    NoRuleMatched,
}

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

/// A call that policy allowed. Fields are private and the only constructor
/// is [`Session::authorize`], so a provider that accepts only
/// `Authorized<Call>` cannot be driven by an unchecked call (§4.5).
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
/// exactly the call that may run (H1c review F-7).
impl harness_core::CallDigest for Authorized<Call> {
    fn call_digest(&self) -> harness_core::Digest {
        let mut m = serde_json::Map::new();
        m.insert("args".into(), self.call.args.clone());
        m.insert(
            "capability".into(),
            Value::from(self.call.capability.clone()),
        );
        harness_core::sha256(Value::Object(m).to_string().as_bytes())
    }
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
    /// A class or feature this build's policy does not decide.
    #[error("capability {capability}: {what} is not decided by this build's policy; refused")]
    OutOfScope {
        /// Capability.
        capability: String,
        /// What.
        what: &'static str,
    },
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

#[derive(Debug, Clone)]
struct Active {
    class: EffectiveClass,
    schema: InputSchema,
    user_deny: Option<usize>,
    user_ask: Option<usize>,
    user_allow: Option<usize>,
    /// A built-in file tool: its `path` argument must stay in the workspace.
    fs_tool: bool,
    /// The built-in submit sentinel (§2.5), the one write-class capability
    /// this slice decides.
    submit: bool,
}

/// A planned session: the active set with each capability's effective
/// class. Constructible only through [`Session::plan`].
#[derive(Debug, Clone)]
pub struct Session {
    active: BTreeMap<CapId, Active>,
    quarantined: BTreeSet<CapId>,
    approver_present: bool,
    personal_granted: bool,
}

const FS_PREFIX: &str = "harness.fs.";

/// The submit sentinel's id (§2.5, §4.8). Only the compiled-in `harness`
/// manifest can declare it (the namespace is reserved, §4.3).
pub const SUBMIT_ID: &str = "harness.task.submit";

/// Whether `c` is the built-in submit sentinel with exactly the labels §4.8
/// gives it (write / public / own / none, content own, no confirmation). A
/// manifest that labelled it anything else would not be the sentinel, and
/// its write class is then out of scope like any other.
fn is_submit_sentinel(c: &Capability) -> bool {
    c.id().as_str() == SUBMIT_ID
        && c.id().provider() == BUILTIN_NAMESPACE
        && c.effect() == Effect::Write
        && c.sensitivity() == Sensitivity::Public
        && c.blast_radius() == BlastRadius::Own
        && c.egress() == Egress::None
        && c.content() == Content::Own
        && c.confirmation() == Confirmation::None
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
            let user_ask = UserPolicy::first_match(&policy.ask, c.id());
            let floor = if user_ask.is_some() {
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
            if id.as_str().starts_with(FS_PREFIX) && spec.workspace.is_none() {
                return Err(SessionRefused::NoWorkspace(id.to_string()));
            }
            if cl.effect != Effect::Read && !is_submit_sentinel(c) {
                return Err(out("a non-read effect class"));
            }
            if cl.egress != Egress::None {
                return Err(out("egress (the allowlist proxy is H4)"));
            }
        }

        let mut active = BTreeMap::new();
        for (c, (_, class, user_ask)) in resolved.iter().zip(classes) {
            active.insert(
                c.id().clone(),
                Active {
                    class,
                    schema: c.input_schema().clone(),
                    user_deny: UserPolicy::first_match(&policy.deny, c.id()),
                    user_ask,
                    user_allow: UserPolicy::first_match(&policy.allow, c.id()),
                    fs_tool: c.id().provider() == BUILTIN_NAMESPACE
                        && c.id().as_str().starts_with(FS_PREFIX),
                    submit: is_submit_sentinel(c),
                },
            );
        }
        Ok(Self {
            active,
            quarantined: BTreeSet::new(),
            approver_present: spec.approver_present,
            personal_granted: spec.personal_data_granted,
        })
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
        if cl.effect != Effect::Read && !a.submit {
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
        if cl.requires_conformed {
            return deny(DenyReason::NoConformed, "deny.no-conformed");
        }
        if cl.sensitivity == Sensitivity::Personal && !self.personal_granted {
            return deny(DenyReason::PersonalNotGranted, "deny.personal-not-granted");
        }
        if let Some(index) = a.user_deny {
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
        if a.fs_tool {
            if let Some(p) = call.args.get("path") {
                // The schema says string; anything else was refused above.
                let checked = p.as_str().map_or(Err(PathRefused::Empty), workspace_path);
                if let Err(e) = checked {
                    return deny(DenyReason::Path(e), "deny.path-outside-workspace");
                }
            }
        }

        // ---- 2. Ask rules. ----
        if cl.confirmation >= Confirmation::UserConfirm {
            let rule = match a.user_ask {
                Some(index) if cl.confirmation == Confirmation::UserConfirm => RuleId::User {
                    list: RuleList::Ask,
                    index,
                },
                _ => RuleId::Builtin("ask.confirmation-floor"),
            };
            if !self.approver_present {
                return deny(DenyReason::NoApprover, "deny.no-approver");
            }
            return PolicyDecision::Ask {
                tier: cl.confirmation,
                rule,
            };
        }

        // ---- 3. Allow rules. ----
        if let Some(index) = a.user_allow {
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

        // ---- 4. Default: deny. ----
        deny(DenyReason::NoRuleMatched, "deny.default")
    }

    /// Mint an [`Authorized`] call, only when [`Session::decide`] allows it.
    /// Any other decision is returned as the error, unchanged.
    pub fn authorize(&self, call: Call) -> Result<Authorized<Call>, PolicyDecision> {
        match self.decide(&call) {
            PolicyDecision::Allow { rule } => Ok(Authorized { call, rule }),
            other => Err(other),
        }
    }
}

#[cfg(test)]
mod tests;
