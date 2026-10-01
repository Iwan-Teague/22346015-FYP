//! Trust tiers and admission as data (design §4.4), with the H1 phase gate.
//!
//! A [`Registry`] is the set of providers a session may draw capabilities
//! from. It is built in one step, [`Registry::admit`], over every
//! `(manifest, tier)` pair, and the checks run in this order:
//!
//! 1. **Shadowing (INV-8):** two entries with the same namespace are
//!    refused, whatever their tiers.
//! 2. **Tier coherence:** `builtin` tier ⇔ a compiled-in manifest.
//! 3. **Tier data rules (§4.4 table):** a `pinned` manifest may not declare
//!    `sensitivity > operational` or `blast_radius > host`, and may not be an
//!    in-process adapter (§4.5: in-process is `builtin` or `signed` only).
//! 4. **H1 phase gate:** what this build cannot honour is REFUSED, not
//!    accepted on trust. Signature verification and manifest-hash pinning
//!    need the ed25519 and SHA-256 crates and the admission CLI (H4);
//!    mcp-stdio and in-process transports need `harness-mcp` / `Conformed`
//!    (H2/H4); secret handles need the §5.5 secrets boundary (H2). So in H1
//!    only the `builtin` tier with a secret-free `builtin` transport admits.
//!
//! The data rules (1-3) run before the phase gate so they are exercised now
//! and cannot silently rot while the gate hides them.

use std::collections::BTreeMap;

use crate::{
    BlastRadius, Capability, Manifest, Origin, ProviderName, Sensitivity, Sha256Pin, Transport,
};

/// How a provider was admitted (§4.4). Data only: the admission CLI that
/// records `Signed`/`Pinned` entries in the user config is H4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tier {
    /// Ships in the binary (`harness.*`).
    Builtin,
    /// Manifest signed (ed25519 over the exact bytes) by a trusted key.
    Signed {
        /// Which of the user's `trusted_keys` signed it.
        key_id: String,
    },
    /// Unsigned; the user approved this exact manifest SHA-256.
    Pinned {
        /// The approved manifest digest.
        manifest_sha256: Sha256Pin,
    },
}

impl Tier {
    /// Short name for messages.
    pub fn name(&self) -> &'static str {
        match self {
            Tier::Builtin => "builtin",
            Tier::Signed { .. } => "signed",
            Tier::Pinned { .. } => "pinned",
        }
    }
}

/// Why admission was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    /// Two providers claim one namespace (INV-8, the shadowing defence).
    #[error("provider namespace {0} is admitted twice")]
    Shadowed(String),
    /// Tier and origin disagree.
    #[error("provider {provider}: tier {tier} does not match the manifest's origin")]
    TierMismatch {
        /// Provider.
        provider: String,
        /// Tier claimed.
        tier: &'static str,
    },
    /// A `pinned` manifest declares more than its tier may.
    #[error(
        "provider {provider}: a pinned manifest may not declare {what}{}",
        capability_clause(.capability)
    )]
    TierExceeded {
        /// Provider.
        provider: String,
        /// Offending capability.
        capability: String,
        /// What it declared.
        what: &'static str,
    },
    /// Something this build cannot honour yet; refused rather than trusted.
    #[error(
        "provider {provider}: {what} is not available in this build (arrives in {phase}); refused"
    )]
    NotInThisPhase {
        /// Provider.
        provider: String,
        /// What was asked for.
        what: &'static str,
        /// The design phase that adds it.
        phase: &'static str,
    },
}

/// ` (capability <id>)`, or nothing when the refusal is about the whole
/// manifest (its transport).
fn capability_clause(capability: &str) -> String {
    if capability.is_empty() {
        String::new()
    } else {
        format!(" (capability {capability})")
    }
}

/// Resolution of a capability id against a registry.
#[derive(Debug)]
pub enum Resolved<'a> {
    /// Exactly one capability has this id.
    One {
        /// The capability.
        capability: &'a Capability,
        /// Its provider's manifest.
        manifest: &'a Manifest,
        /// Its provider's tier.
        tier: &'a Tier,
    },
    /// No admitted capability has this id.
    NotFound,
    /// More than one does. Unreachable while namespaces are unique and ids
    /// are unique per manifest; kept so a future bug refuses instead of
    /// picking one.
    Ambiguous,
}

/// The admitted providers.
#[derive(Debug, Clone)]
pub struct Registry {
    providers: BTreeMap<ProviderName, (Manifest, Tier)>,
}

impl Registry {
    /// Admit every entry or none (checks in the module-level order).
    pub fn admit(entries: Vec<(Manifest, Tier)>) -> Result<Self, AdmissionError> {
        // 1. Shadowing, over the whole set first.
        let mut seen = std::collections::BTreeSet::new();
        for (m, _) in &entries {
            if !seen.insert(m.provider().clone()) {
                return Err(AdmissionError::Shadowed(m.provider().to_string()));
            }
        }
        for (m, tier) in &entries {
            let provider = m.provider().to_string();
            // 2. Coherence.
            let coherent = matches!(
                (tier, m.origin()),
                (Tier::Builtin, Origin::Compiled)
                    | (Tier::Signed { .. }, Origin::External)
                    | (Tier::Pinned { .. }, Origin::External)
            );
            if !coherent {
                return Err(AdmissionError::TierMismatch {
                    provider,
                    tier: tier.name(),
                });
            }
            // 3. Tier data rules.
            if let Tier::Pinned { .. } = tier {
                if let Transport::InProcess { .. } = m.transport() {
                    return Err(AdmissionError::TierExceeded {
                        provider,
                        capability: String::new(),
                        what: "an in-process transport",
                    });
                }
                for c in m.capabilities() {
                    let what = if c.sensitivity > Sensitivity::Operational {
                        Some("sensitivity above operational")
                    } else if c.blast_radius > BlastRadius::Host {
                        Some("blast_radius shared")
                    } else {
                        None
                    };
                    if let Some(what) = what {
                        return Err(AdmissionError::TierExceeded {
                            provider,
                            capability: c.id.to_string(),
                            what,
                        });
                    }
                }
            }
            // 4. H1 phase gate.
            let gate = |what, phase| AdmissionError::NotInThisPhase {
                provider: provider.clone(),
                what,
                phase,
            };
            match tier {
                Tier::Builtin => {}
                Tier::Signed { .. } => return Err(gate("signature verification", "H4")),
                Tier::Pinned { .. } => return Err(gate("manifest-hash pinning", "H4")),
            }
            match m.transport() {
                Transport::Builtin => {}
                Transport::McpStdio { .. } => return Err(gate("the mcp-stdio transport", "H4")),
                Transport::InProcess { .. } => return Err(gate("the in-process transport", "H4")),
            }
            if m.capabilities().iter().any(|c| !c.secrets.is_empty()) {
                return Err(gate("secret handles", "H2"));
            }
        }
        Ok(Self {
            providers: entries
                .into_iter()
                .map(|(m, t)| (m.provider().clone(), (m, t)))
                .collect(),
        })
    }

    /// Resolve a capability id. Counts every match; anything but exactly one
    /// is not a resolution.
    pub fn resolve(&self, id: &str) -> Resolved<'_> {
        let mut found = None;
        let mut count = 0usize;
        for (m, t) in self.providers.values() {
            for c in m.capabilities() {
                if c.id.as_str() == id {
                    count += 1;
                    found = Some((c, m, t));
                }
            }
        }
        match (count, found) {
            (1, Some((capability, manifest, tier))) => Resolved::One {
                capability,
                manifest,
                tier,
            },
            (0, _) => Resolved::NotFound,
            _ => Resolved::Ambiguous,
        }
    }

    /// Admitted provider namespaces.
    pub fn providers(&self) -> impl Iterator<Item = &ProviderName> {
        self.providers.keys()
    }
}
