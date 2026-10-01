//! The `manifest check` verb: a provider manifest through the admission
//! parser, with each capability's class and what this build's admission
//! would do (not a gate child).

use harness_manifest::admission::{Registry, Tier};
use harness_manifest::{ManifestError, SemVer, ValidationContext};

use crate::report::exit;
use crate::Cx;

/// `manifest check`: validate a provider's manifest with the parser
/// admission uses (`harness_manifest::Manifest::parse`: schema v1, strict
/// JSON, reserved namespaces, §4.3 content rules), show each capability's
/// §4.2 class and the floors its transport and the pinned tier add, and say
/// what this build's admission would do if the user pinned these exact
/// bytes. Exit codes: see the crate docs.
///
/// Named residuals (H1f-2 review F-7): the reserved set is the core
/// constant only (H1 has no harness config, so no `extra_reserved`); only
/// the pinned tier is tried (a manifest refused as pinned may be admissible
/// as signed, from H4); user policy can raise a class further at run time.
pub(crate) fn manifest_check(cx: &Cx<'_>, path: &str) -> u8 {
    use std::io::Read;
    let mut bytes = Vec::new();
    let read = std::fs::File::open(path).and_then(|f| {
        // One byte past the cap is enough to know it is too large.
        f.take(harness_manifest::MANIFEST_MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
    });
    if let Err(e) = read {
        note!(cx, "cannot read {path}: {e}");
        return exit::UNREADABLE_INPUT;
    }
    if bytes.len() > harness_manifest::MANIFEST_MAX_BYTES {
        note!(
            cx,
            "cannot read {path}: larger than the manifest cap of {} bytes",
            harness_manifest::MANIFEST_MAX_BYTES
        );
        return exit::UNREADABLE_INPUT;
    }
    let ctx = match SemVer::parse(env!("CARGO_PKG_VERSION"))
        .ok_or_else(|| "the harness version is not SemVer".to_owned())
        .and_then(|v| ValidationContext::new(v, &[]).map_err(|e| e.to_string()))
    {
        Ok(c) => c,
        Err(e) => {
            note!(cx, "cannot check manifests: {e}");
            return exit::INDETERMINATE;
        }
    };
    let m = match harness_manifest::Manifest::parse(&bytes, &ctx) {
        Ok(m) => m,
        // Not a JSON document at all: unreadable input (§7.7).
        Err(e @ (ManifestError::Json(_) | ManifestError::TooLarge { .. })) => {
            note!(cx, "cannot read {path}: {e}");
            return exit::UNREADABLE_INPUT;
        }
        // A JSON document that is not a valid manifest. Every message here
        // shows manifest-chosen text escaped or Debug-quoted (§7.1).
        Err(e) => {
            note!(cx, "REFUSED {path}: {e}");
            return exit::FAILED;
        }
    };
    let digest = harness_core::sha256(&bytes);
    say!(
        cx,
        "OK {path}: provider {} {} (schema v{}, transport {}), {} capabilit{}",
        m.provider(),
        m.provider_version(),
        m.schema_version(),
        m.transport().kind(),
        m.capabilities().len(),
        if m.capabilities().len() == 1 {
            "y"
        } else {
            "ies"
        }
    );
    say!(cx, "  manifest sha256 {digest}");
    say!(
        cx,
        "  capability classes (§4.2: declared confirmation raised by the derived floors, before user policy and tier floors):"
    );
    for c in m.capabilities() {
        let e = harness_policy::effective_class(c, harness_manifest::Confirmation::None);
        say!(
            cx,
            "  {}: effect {}, sensitivity {}, blast {}, egress {}, content {}; confirmation {} (declared {}){}",
            c.id(),
            e.effect.as_str(),
            e.sensitivity.as_str(),
            e.blast_radius.as_str(),
            e.egress.as_str(),
            e.content.as_str(),
            e.confirmation.as_str(),
            c.confirmation().as_str(),
            if e.requires_conformed {
                "; needs a conformed sandbox"
            } else {
                ""
            }
        );
    }
    if let harness_manifest::Transport::McpStdio { .. } = m.transport() {
        say!(
            cx,
            "  transport mcp-stdio: the server is started only inside a conformed sandbox, never unconfined (§4.5)"
        );
    }
    // What admission would say if the user pinned exactly these bytes: the
    // same code a run uses. In H1 it always refuses (pinning is H4).
    let admission = harness_manifest::Sha256Pin::parse_hex(&digest.to_string())
        .ok_or_else(|| "the manifest digest is not a pin".to_owned())
        .and_then(|pin| {
            Registry::admit(vec![(
                m,
                Tier::Pinned {
                    manifest_sha256: pin,
                },
            )])
            .map_err(|e| e.to_string())
        });
    match admission {
        Ok(_) => say!(
            cx,
            "  if pinned as sha256 {digest}, this build would admit it"
        ),
        Err(e) => say!(
            cx,
            "  if pinned as sha256 {digest}, this build would refuse it: {e}"
        ),
    }
    say!(
        cx,
        "  a pinned provider is always sandboxed, confirms at least user_confirm and never shares a session with personal or restricted capabilities (§4.4)"
    );
    exit::PASSED
}
