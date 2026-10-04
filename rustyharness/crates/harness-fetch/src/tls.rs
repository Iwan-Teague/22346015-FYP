//! The TLS arm of the confined fetcher (design note `P-39-web-airlock`
//! §5.2/§5.4, slice P-39n; the `net` feature).
//!
//! One hop, one TLS session, rustls with the ring provider — the ONLY code
//! in the workspace that links a TLS stack (INV-52 keeps it out of
//! harness-cli in every feature combination). The posture is fail-closed
//! and narrow:
//!
//! - SNI is the request's host; the certificate must verify for that exact
//!   name (wrong-host and expired certificates are refused, never warned
//!   about);
//! - the roots are [`webpki_roots`] (Mozilla's set as compiled data) via
//!   [`fetch_over_tls`] — the system trust store is NEVER read (§5.2);
//! - ALPN offers `http/1.1` and nothing else; the rustls defaults give
//!   TLS 1.2 and TLS 1.3;
//! - no client certificate; no session resumption carried across hops (a
//!   fresh config per hop);
//! - every failure — handshake, name, expiry, trust, negotiation — is the
//!   one opaque `tls_failed` kind, never a server-controlled reason string.
//!
//! The ring provider is installed per config with
//! `builder_with_provider`, never via the process-wide
//! `CryptoProvider::install_default()`: a process default would leak into
//! every other rustls user linked into the same binary (today only the
//! fetcher and its test probe, but the constraint is the design's, not
//! today's call graph's).
//!
//! [`fetch_over_tls_with_roots`] is the test seam: the fixture tests
//! present the committed test CA, and the confined positive control
//! (`rustyharness-fetch-probe`) carries it across the sandbox boundary.
//! Production callers have exactly one entry, [`fetch_over_tls`].

use std::io::{Read, Write};
use std::sync::Arc;

use harness_core::fetch_frame::{Frame, TlsInfo};
use harness_core::sha256;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, Stream};

use crate::{http_over, Request, KIND_TLS_FAILED};

/// Run one HTTPS fetch over an already-open `tunnel` against the web's
/// public roots. Same contract as [`crate::fetch_over`]: never `Err`, every
/// failure becomes an error frame (here always the `tls_failed` kind).
pub fn fetch_over_tls<S: Read + Write>(mut tunnel: S, req: &Request) -> crate::Frame {
    match https_over_web_roots(&mut tunnel, req) {
        Ok(frame) => frame,
        Err(kind) => crate::Frame::error(&kind),
    }
}

/// The same fetch against explicit roots. The test seam (see the module
/// docs): production code calls [`fetch_over_tls`] only.
pub fn fetch_over_tls_with_roots<S: Read + Write>(
    mut tunnel: S,
    req: &Request,
    roots: &RootCertStore,
) -> crate::Frame {
    match https_over(&mut tunnel, req, roots) {
        Ok(frame) => frame,
        Err(kind) => crate::Frame::error(&kind),
    }
}

/// The production arm of [`crate::run`]'s `https` dispatch: the web's
/// public roots, nothing else.
pub(crate) fn https_over_web_roots<S: Read + Write>(
    tunnel: &mut S,
    req: &Request,
) -> Result<Frame, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    https_over(tunnel, req, &roots)
}

/// Handshake over `tunnel`, then run the bounded HTTP exchange through the
/// decoded stream. The tunnel's own read/write timeouts (set by the
/// process, §5.1) bound every blocking step of the handshake.
pub(crate) fn https_over<S: Read + Write>(
    tunnel: &mut S,
    req: &Request,
    roots: &RootCertStore,
) -> Result<Frame, String> {
    let server_name =
        ServerName::try_from(req.host.clone()).map_err(|_| KIND_TLS_FAILED.to_string())?;
    let config = client_config(roots)?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|_| KIND_TLS_FAILED.to_string())?;
    complete_handshake(&mut conn, tunnel)?;
    let info = session_info(&conn);
    let mut stream = Stream::new(&mut conn, tunnel);
    http_over(&mut stream, req, Some(info))
}

/// Drive the handshake to completion: every `complete_io` step makes
/// progress or the failure is the one `tls_failed` kind.
fn complete_handshake<S: Read + Write>(
    conn: &mut ClientConnection,
    tunnel: &mut S,
) -> Result<(), String> {
    while conn.is_handshaking() {
        conn.complete_io(tunnel)
            .map_err(|_| KIND_TLS_FAILED.to_string())?;
    }
    Ok(())
}

/// The client config for ONE hop: ring provider named explicitly (never a
/// process-wide default), webpki roots, ALPN `http/1.1` only.
fn client_config(roots: &RootCertStore) -> Result<ClientConfig, String> {
    let builder =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .map_err(|_| KIND_TLS_FAILED.to_string())?;
    let mut config = builder
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// The frame's `tls` block, read off the established session: protocol
/// version, the negotiated suite's IANA name, and the SHA-256 of the leaf
/// certificate's DER (harness-core's `sha256`).
fn session_info(conn: &rustls::ClientConnection) -> TlsInfo {
    let version = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_2) => "tls1.2".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_3) => "tls1.3".to_string(),
        _ => "unknown".to_string(),
    };
    let suite = conn
        .negotiated_cipher_suite()
        .and_then(|suite| suite.suite().as_str())
        .unwrap_or("unknown")
        .to_string();
    let cert_sha256 = conn
        .peer_certificates()
        .and_then(|chain| chain.first())
        .map(|leaf| sha256(leaf.as_ref()).to_string())
        .unwrap_or_else(|| "none".to_string());
    TlsInfo {
        version,
        suite,
        cert_sha256,
    }
}
