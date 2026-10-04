#![forbid(unsafe_code)]
//! The test-only TLS probe (slice P-39n): the fetcher's own dial-and-fetch
//! path, packaged as a second binary so the macOS positive control can run
//! it confined (`tests/tls.rs::tls_handshake_inside_proxy_sandbox`). argv
//! is `[probe, request.json, ca.pem]`; the request file names the loopback
//! port to dial and the hop's `https` shape, the PEM file is the committed
//! TEST CA — the production fetcher binary never takes a root argument and
//! never trusts anything but the web roots. Same reporting contract as
//! `rustyharness-fetch`: one `rh-fetch/1` frame on stdout, exit 0 unless
//! the frame write itself fails.

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::process::ExitCode;
use std::time::Duration;

use harness_fetch::{encode_frame, fetch_over_tls_with_roots, read_request, Frame};
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;

/// How long the dial may take (the fetcher binary's own figure).
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

fn main() -> ExitCode {
    let mut args = std::env::args();
    let _ = args.next();
    let (Some(req_path), Some(ca_path)) = (args.next(), args.next()) else {
        return emit(Frame::error("bad_request"));
    };
    let Ok(bytes) = std::fs::read(&req_path) else {
        return emit(Frame::error("bad_request"));
    };
    let Ok(ca) = std::fs::read(&ca_path) else {
        return emit(Frame::error("bad_request"));
    };
    let Ok(request) = read_request(&bytes) else {
        return emit(Frame::error("bad_request"));
    };
    let Ok(roots) = test_roots(&ca) else {
        return emit(Frame::error("tls_failed"));
    };
    let peer = SocketAddr::from(([127, 0, 0, 1], request.proxy_port));
    let Ok(stream) = TcpStream::connect_timeout(&peer, DIAL_TIMEOUT) else {
        return emit(Frame::error("connect_failed"));
    };
    let socket_timeout = Duration::from_millis(request.timeout_ms);
    let _ = stream.set_read_timeout(Some(socket_timeout));
    let _ = stream.set_write_timeout(Some(socket_timeout));
    emit(fetch_over_tls_with_roots(stream, &request, &roots))
}

/// The test CA, as a root store. PEM parsing is `rustls-pki-types`' built-in
/// `PemObject` (dev-only dependency); any parse or store failure is the
/// probe's own brokenness, reported as `tls_failed`.
fn test_roots(ca: &[u8]) -> Result<RootCertStore, ()> {
    use rustls::pki_types::pem::PemObject;
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(ca) {
        let cert = cert.map_err(|_| ())?;
        roots.add(cert).map_err(|_| ())?;
    }
    if roots.is_empty() {
        return Err(());
    }
    Ok(roots)
}

/// Write one frame to stdout. Success means exit 0 even for an error frame;
/// only a failed write is a non-zero exit (as in `rustyharness-fetch`).
fn emit(frame: Frame) -> ExitCode {
    let encoded = encode_frame(&frame);
    match std::io::stdout().lock().write_all(&encoded) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
