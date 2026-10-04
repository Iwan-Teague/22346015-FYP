//! The `net` TLS arm's tests (slice P-39n): the fixture handshake against
//! the committed test CA, the refusals (wrong host, expired leaf), the SNI
//! pin, and the macOS positive control (`tls_handshake_inside_proxy_sandbox`)
//! that runs the whole fetch confined under the proxy profile.
//!
//! Everything here is loopback and test-root only: the production fetcher
//! path never sees these PEM files (see `src/tls.rs`).

#![cfg(feature = "net")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use harness_core::fetch_frame::parse_frame;
use harness_fetch::{fetch_over_tls_with_roots, Mode, Request, Scheme, KIND_TLS_FAILED};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::{RootCertStore, ServerConfig, ServerConnection, Stream};

/// A committed PEM fixture from `tests/fixtures/`.
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn pem_certs(name: &str) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(&std::fs::read(fixture(name)).unwrap())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn pem_key(name: &str) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_slice(&std::fs::read(fixture(name)).unwrap()).unwrap()
}

/// The trust anchor for every test hop: the committed test CA alone.
fn ca_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    for cert in pem_certs("ca.pem") {
        roots.add(cert).unwrap();
    }
    roots
}

/// One HTTPS fetch of the fixture server. The frame must be a clean 200
/// with `hello` and leaf-digesting TLS info.
fn fetch(server_port: u16, host: &str) -> harness_fetch::Frame {
    let req = Request {
        v: 1,
        proxy_port: server_port,
        token: "tok".to_string(),
        scheme: Scheme::Https,
        host: host.to_string(),
        port: server_port,
        target: "/".to_string(),
        accept: "text/plain".to_string(),
        max_body: 1024,
        max_header_bytes: 1024,
        timeout_ms: 5000,
        user_agent: "ua".to_string(),
        mode: Mode::Direct,
    };
    let stream = TcpStream::connect(("127.0.0.1", server_port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    fetch_over_tls_with_roots(stream, &req, &ca_roots())
}

/// The fixture server: one TLS connection, one request read, one canned
/// 200. Records the client's SNI for [`sni_is_the_allowlisted_host`].
struct FixtureServer {
    port: u16,
    sni: Arc<Mutex<Option<String>>>,
    handle: std::thread::JoinHandle<()>,
}

fn start_server(leaf: &str, key: &str) -> FixtureServer {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let certs = pem_certs(leaf);
    let key = pem_key(key);
    let sni: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let sni_out = Arc::clone(&sni);
    let handle = std::thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        sock.set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut sock = sock;
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        let mut conn = ServerConnection::new(Arc::new(config)).unwrap();
        let mut buf = [0u8; 1024];
        {
            let mut io = Stream::new(&mut conn, &mut sock);
            if io.read(&mut buf).is_err() {
                return;
            }
        }
        *sni_out.lock().unwrap() = conn.server_name().map(str::to_string);
        let mut io = Stream::new(&mut conn, &mut sock);
        io.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello",
        )
        .unwrap();
        let _ = io.flush();
    });
    FixtureServer { port, sni, handle }
}

fn kind_of(frame: &harness_fetch::Frame) -> Option<&str> {
    frame.header.error.as_deref()
}

#[test]
fn tls_handshake_against_fixture_with_test_root() {
    let server = start_server("leaf-localhost.pem", "leaf-localhost.key");
    let frame = fetch(server.port, "localhost");
    assert_eq!(kind_of(&frame), None, "frame error: {frame:?}");
    assert_eq!(frame.header.status, Some(200));
    assert_eq!(frame.header.content_type.as_deref(), Some("text/plain"));
    assert_eq!(frame.body, b"hello");
    let tls = frame.header.tls.as_ref().expect("tls info on a 200 frame");
    assert!(
        tls.version == "tls1.2" || tls.version == "tls1.3",
        "unexpected version {tls:?}"
    );
    assert!(!tls.suite.is_empty(), "cipher suite must be named");
    let leaf = pem_certs("leaf-localhost.pem").remove(0);
    assert_eq!(
        tls.cert_sha256,
        harness_core::sha256(leaf.as_ref()).to_string()
    );
    server.handle.join().unwrap();
}

#[test]
fn wrong_host_cert_refused() {
    let server = start_server("leaf-localhost.pem", "leaf-localhost.key");
    let frame = fetch(server.port, "example.net");
    assert_eq!(kind_of(&frame), Some(KIND_TLS_FAILED));
    assert!(frame.body.is_empty(), "refused hop leaked body bytes");
    assert!(frame.header.tls.is_none());
    assert_ne!(frame.header.status, Some(200));
    server.handle.join().unwrap();
}

#[test]
fn expired_cert_refused() {
    let server = start_server("leaf-expired.pem", "leaf-expired.key");
    let frame = fetch(server.port, "localhost");
    assert_eq!(kind_of(&frame), Some(KIND_TLS_FAILED));
    assert!(frame.body.is_empty(), "refused hop leaked body bytes");
    server.handle.join().unwrap();
}

#[test]
fn sni_is_the_allowlisted_host() {
    let server = start_server("leaf-localhost.pem", "leaf-localhost.key");
    let frame = fetch(server.port, "localhost");
    assert_eq!(kind_of(&frame), None, "frame error: {frame:?}");
    let seen = server.sni.lock().unwrap().clone();
    assert_eq!(seen.as_deref(), Some("localhost"));
    server.handle.join().unwrap();
}

/// The request file shape the confined probe consumes (same schema
/// `read_request` enforces; see the unit tests in src/lib.rs).
fn probe_request_json(port: u16) -> String {
    format!(
        concat!(
            "{{\"v\":1,\"proxy_port\":{port},\"token\":\"tok\",\"scheme\":\"https\",",
            "\"host\":\"localhost\",\"port\":{port},\"target\":\"/\",",
            "\"accept\":\"text/plain\",\"max_body\":1024,\"max_header_bytes\":1024,",
            "\"timeout_ms\":10000,\"user_agent\":\"ua\",\"mode\":\"direct\"}}"
        ),
        port = port
    )
}

#[cfg(target_os = "macos")]
mod sandbox_airlock {
    use super::*;
    use harness_sandbox::seatbelt::Seatbelt;
    use harness_sandbox::{Backend, Conformed};
    use harness_sandbox::{
        ChildStatus, ConfinedSpec, Confinement, Limits, Network, SystemConfinement,
    };
    use std::path::{Path, PathBuf};

    fn witness() -> Conformed {
        Seatbelt::new()
            .probe()
            .expect("the Seatbelt live probe must pass")
    }

    fn temp_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rh-fetch-tls-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn tls_handshake_inside_proxy_sandbox() {
        let server = start_server("leaf-localhost.pem", "leaf-localhost.key");
        let work = temp_root("sandbox");
        std::fs::write(work.join("request.json"), probe_request_json(server.port)).unwrap();
        std::fs::copy(fixture("ca.pem"), work.join("ca.pem")).unwrap();

        let probe = PathBuf::from(env!("CARGO_BIN_EXE_rustyharness-fetch-probe"));
        let spec = ConfinedSpec {
            argv: vec![
                probe.as_os_str().to_owned(),
                "request.json".into(),
                "ca.pem".into(),
            ],
            cwd: work.clone(),
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            read_only: vec![probe.parent().map(Path::to_path_buf).unwrap()],
            read_write: vec![work.clone()],
            protected: vec![],
            network: Network::Proxy { port: server.port },
            limits: Limits::wall(Duration::from_secs(20)),
        };

        let exit = SystemConfinement.spawn(&spec, &witness()).unwrap().wait();
        let _ = std::fs::remove_dir_all(&work);
        assert_eq!(
            exit.status,
            ChildStatus::Exited(0),
            "stderr: {}",
            String::from_utf8_lossy(&exit.stderr)
        );
        let frame = parse_frame(&exit.stdout, 1 << 20).unwrap();
        assert_eq!(kind_of(&frame), None, "frame error: {frame:?}");
        assert_eq!(frame.header.status, Some(200));
        assert_eq!(frame.body, b"hello");
        let tls = frame.header.tls.as_ref().expect("tls info in the sandbox");
        assert!(!tls.cert_sha256.is_empty());
        server.handle.join().unwrap();
    }
}
