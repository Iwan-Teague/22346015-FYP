//! The consent gate (docs/11 "Consent").
//!
//! docs/11 specifies three separate consents. Only the first can be honoured offline:
//!
//! 1. **Public scores + licence** — implemented here.
//! 2. **Encrypted replay artifacts** — needs a server public key and an encryption primitive
//!    (neither exists); [`Consent::ReplayArtifacts`] is accepted by the parser only so it can be
//!    refused with an explanation. REVIEW-5 `consent-two-is-mandatory` also notes it is a
//!    precondition for any ranked row, so the "three separate consents" are not separable —
//!    unresolved, see OPEN-QUESTIONS Q32.
//! 3. **Audit contact** — needs an identifier channel (Q23); refused likewise.
//!
//! The consent text below is a **draft**: the licence wording is a legal decision that belongs to
//! the project owner, not to this crate.

use crate::error::SubmitError;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Bump on any change to [`TERMS_TEXT`]; stored consent for another version is void.
pub const TERMS_VERSION: &str = "2026-10-05-draft";

/// docs/11: the licence must be named in full on the consent screen, not linked, and a test
/// asserts it. The exact phrase the test (and `verify-bundle`) looks for:
pub const LICENCE_NAME: &str = "Creative Commons Attribution 4.0 International (CC BY 4.0)";

pub const TERMS_TEXT: &str = "\
RUSTYBENCH CONSENT 1 OF 3 -- PUBLISH REDACTED SCORES  (terms 2026-10-05-draft, DRAFT WORDING)

If you export this bundle and later submit it, you agree that:

  1. The redacted scores, error codes, timings, token counts and bucketed hardware class in the
     bundle (exactly the JSON that `rustybench export --dry-run` prints) may be published on the
     public leaderboard and in the public results dump.

  2. You grant the project a perpetual, worldwide, non-exclusive licence to publish these
     redacted results and to license them onward under the licence named in full here:

         Creative Commons Attribution 4.0 International (CC BY 4.0)


  3. Nothing else leaves your machine in this bundle: no model output, no source code, no
     file paths, hostnames, usernames, IP or MAC addresses, serial numbers or environment
     variables, and no exact GPU/CPU/OS identity (only a coarse hardware class). Per-unit seeds
     and batch nonces are withheld until the epoch closes.

You can withdraw consent at any time. A deletion request cannot recall copies already
published under CC BY 4.0 or copied by others.

Consents 2 (encrypted replay artifacts) and 3 (audit contact) are NOT available in this build.
";

/// `blake3:<hex>` of the exact consent text; recorded in every bundle so the grant a row was
/// collected under is a fact (DATA-LICENSE.md).
pub fn terms_hash() -> String {
    format!("blake3:{}", blake3::hash(TERMS_TEXT.as_bytes()).to_hex())
}

/// Consent kinds the CLI can name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consent {
    PublicScores,
    ReplayArtifacts,
    AuditContact,
}

impl Consent {
    pub fn parse(s: &str) -> Result<Consent, SubmitError> {
        match s {
            "public-scores" => Ok(Consent::PublicScores),
            "replay-artifacts" => Ok(Consent::ReplayArtifacts),
            "audit-contact" => Ok(Consent::AuditContact),
            _ => Err(SubmitError::Consent(format!(
                "unknown consent `{s}` (known: public-scores)"
            ))),
        }
    }
}

/// The stored consent record. Local only; never part of a bundle (the bundle carries only the
/// booleans, `terms_version` and `terms_hash`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentRecord {
    pub schema: u32,
    pub terms_version: String,
    pub terms_hash: String,
    pub public_scores: bool,
    /// Unix seconds when recorded. Local bookkeeping only.
    pub recorded_unix: u64,
}

impl ConsentRecord {
    pub fn grant_now() -> ConsentRecord {
        ConsentRecord {
            schema: 1,
            terms_version: TERMS_VERSION.to_string(),
            terms_hash: terms_hash(),
            public_scores: true,
            recorded_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        }
    }

    pub fn revoked_now() -> ConsentRecord {
        ConsentRecord {
            public_scores: false,
            ..ConsentRecord::grant_now()
        }
    }

    /// Valid only for the terms text this build ships.
    fn is_current(&self) -> bool {
        self.terms_version == TERMS_VERSION && self.terms_hash == terms_hash()
    }
}

pub fn load(path: &Path) -> Result<Option<ConsentRecord>, SubmitError> {
    match std::fs::read_to_string(path) {
        Ok(t) => serde_json::from_str(&t)
            .map(Some)
            .map_err(|e| SubmitError::Input(format!("consent file {}: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn save(path: &Path, rec: &ConsentRecord) -> Result<(), SubmitError> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    let text = serde_json::to_string_pretty(rec).map_err(|e| SubmitError::Io(e.to_string()))?;
    std::fs::write(path, text + "\n")?;
    Ok(())
}

/// Where permission to export came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Basis {
    /// `--consent public-scores` on this invocation.
    Flag,
    /// A stored record for the current terms.
    Stored,
}

/// The pure gate. `opt_out_env` is the value of `RUSTBENCH_SUBMIT` (if set).
///
/// `--no-submit` and `RUSTBENCH_SUBMIT=0` always win, whatever else is granted (docs/11).
pub fn decide(
    no_submit: bool,
    opt_out_env: Option<&str>,
    flags: &[Consent],
    stored: Option<&ConsentRecord>,
) -> Result<Basis, SubmitError> {
    if no_submit {
        return Err(SubmitError::Consent(
            "--no-submit given: nothing is exported".into(),
        ));
    }
    if let Some(v) = opt_out_env {
        if matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ) {
            return Err(SubmitError::Consent(
                "RUSTBENCH_SUBMIT=0 is set: nothing is exported".into(),
            ));
        }
    }
    for f in flags {
        match f {
            Consent::PublicScores => {}
            Consent::ReplayArtifacts => {
                return Err(SubmitError::Consent(
                    "consent `replay-artifacts` is not available in this build (needs a server \
                     public key and encryption; see OPEN-QUESTIONS Q32)"
                        .into(),
                ))
            }
            Consent::AuditContact => {
                return Err(SubmitError::Consent(
                    "consent `audit-contact` is not available in this build (needs an identity \
                     channel; see OPEN-QUESTIONS Q23)"
                        .into(),
                ))
            }
        }
    }
    if flags.contains(&Consent::PublicScores) {
        return Ok(Basis::Flag);
    }
    match stored {
        Some(r) if r.public_scores && r.is_current() => Ok(Basis::Stored),
        Some(r) if r.public_scores => Err(SubmitError::Consent(format!(
            "stored consent is for terms `{}`, this build ships `{TERMS_VERSION}`; run \
             `rustybench consent show`, then re-consent",
            r.terms_version
        ))),
        Some(_) => Err(SubmitError::Consent(
            "consent was revoked: re-run `rustybench consent grant` or pass --consent public-scores"
                .into(),
        )),
        None => Err(SubmitError::Consent(
            "no consent recorded. Review `rustybench export --dry-run`, read `rustybench consent \
             show`, then pass --consent public-scores or run `rustybench consent grant`"
                .into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_text_names_the_licence_in_full() {
        // docs/11: "The licence is named in full on the consent screen -- not linked -- and a
        // harness test asserts the consent text contains that name."
        assert!(TERMS_TEXT.contains(LICENCE_NAME));
        assert!(TERMS_TEXT.contains("perpetual, worldwide, non-exclusive licence"));
        assert!(
            !TERMS_TEXT.contains("http"),
            "licence must be named, not linked"
        );
    }

    #[test]
    fn refuses_without_consent() {
        let e = decide(false, None, &[], None).unwrap_err();
        assert!(e.to_string().contains("no consent recorded"));
    }

    #[test]
    fn flag_grants_and_stored_grants() {
        assert_eq!(
            decide(false, None, &[Consent::PublicScores], None).unwrap(),
            Basis::Flag
        );
        let rec = ConsentRecord::grant_now();
        assert_eq!(decide(false, None, &[], Some(&rec)).unwrap(), Basis::Stored);
    }

    #[test]
    fn opt_out_always_wins() {
        let rec = ConsentRecord::grant_now();
        assert!(decide(true, None, &[Consent::PublicScores], Some(&rec)).is_err());
        for v in ["0", "false", "OFF", " no "] {
            assert!(
                decide(false, Some(v), &[Consent::PublicScores], Some(&rec)).is_err(),
                "{v}"
            );
        }
        assert!(decide(false, Some("1"), &[Consent::PublicScores], None).is_ok());
    }

    #[test]
    fn stale_or_revoked_stored_consent_is_void() {
        let mut rec = ConsentRecord::grant_now();
        rec.terms_version = "1999-01-01".into();
        assert!(decide(false, None, &[], Some(&rec))
            .unwrap_err()
            .to_string()
            .contains("re-consent"));
        let mut rec = ConsentRecord::grant_now();
        rec.terms_hash = "blake3:00".into();
        assert!(decide(false, None, &[], Some(&rec)).is_err());
        assert!(decide(false, None, &[], Some(&ConsentRecord::revoked_now())).is_err());
    }

    #[test]
    fn unavailable_consents_are_refused_not_ignored() {
        assert!(decide(false, None, &[Consent::ReplayArtifacts], None).is_err());
        assert!(decide(
            false,
            None,
            &[Consent::PublicScores, Consent::AuditContact],
            None
        )
        .is_err());
        assert!(Consent::parse("nonsense").is_err());
    }

    #[test]
    fn consent_file_round_trip() {
        let dir = std::env::temp_dir().join(format!("rb-consent-{}", std::process::id()));
        let p = dir.join("c.json");
        assert!(load(&p).unwrap().is_none());
        let rec = ConsentRecord::grant_now();
        save(&p, &rec).unwrap();
        assert_eq!(load(&p).unwrap().unwrap(), rec);
        let _ = std::fs::remove_dir_all(dir);
    }
}
