#![forbid(unsafe_code)]
//! The confined web fetcher binary (design note `P-39-web-airlock` §5.2,
//! slice P-39d).
//!
//! argv[1] names a request file (a PATH, never an inline payload, INV-23).
//! The process dials the loopback pump port from the request, runs exactly
//! one bounded fetch via [`harness_fetch::fetch_over`], writes one
//! `rh-fetch/1` frame to stdout and exits 0 — on success AND on failure:
//! every failure is already a typed error frame. Only two conditions leave
//! the frame unwritten and exit non-zero (both are the harness's
//! `ended: fetcher_failed`): stdout itself failing, or a crash before we
//! get here (the sandbox's own wall/memory caps).

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::process::ExitCode;
use std::time::Duration;

use harness_fetch::{encode_frame, fetch_over, read_request, Frame};

/// How long the dial to the loopback pump may take.
const PUMP_DIAL_TIMEOUT: Duration = Duration::from_secs(5);

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        return emit(Frame::error("bad_request"));
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return emit(Frame::error("bad_request"));
    };
    let Ok(request) = read_request(&bytes) else {
        return emit(Frame::error("bad_request"));
    };
    let pump = SocketAddr::from(([127, 0, 0, 1], request.proxy_port));
    let Ok(stream) = TcpStream::connect_timeout(&pump, PUMP_DIAL_TIMEOUT) else {
        return emit(Frame::error("connect_failed"));
    };
    let socket_timeout = Duration::from_millis(request.timeout_ms);
    let _ = stream.set_read_timeout(Some(socket_timeout));
    let _ = stream.set_write_timeout(Some(socket_timeout));
    emit(fetch_over(stream, &request))
}

/// Write one frame to stdout. Success means exit 0 even for an error frame;
/// only a failed write is a non-zero exit.
fn emit(frame: Frame) -> ExitCode {
    let encoded = encode_frame(&frame);
    match std::io::stdout().lock().write_all(&encoded) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
