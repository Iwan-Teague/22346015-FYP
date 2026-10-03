//! The in-memory connector (P-37h): [`InMemoryConnector`] implements
//! `harness_mcp::connect::McpConnector` by serving this crate's fixture on
//! a worker thread joined by channels, the same plumbing the hostile suites
//! use. This module lives in the FIXTURE package on purpose: the purity
//! gate scans every file of `harness-mcp` (`scripts/ci/purity.sh` §2), so
//! the provider crate may not name threads, channels or a wall clock even
//! for tests; a test double may.
//!
//! `dial` ignores the sandbox witness: the fixture is no process, so there
//! is nothing to confine. The confined connector that spawns the real
//! server is P-37l.

use std::io::{BufRead, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use harness_mcp::client::{Clock, Transport, TransportFault};
use harness_mcp::connect::{ConnectorError, McpConnector};

use crate::serve;

/// One served connection's client side (P-37h): the pipes, the log of the
/// frames the client sent (the wire-discipline assertions read it), the
/// kill flag, and the served worker (dropping the pipe detaches it; the
/// `hang` mode never notices end of input and sleeps until the process
/// ends, which is fine).
pub struct TestPipe {
    to_server: Option<SyncSender<Vec<u8>>>,
    from_server: Receiver<Vec<u8>>,
    sent: Arc<Mutex<Vec<String>>>,
    killed: Arc<AtomicBool>,
    _server: JoinHandle<()>,
}

/// The fixture's output sink: every write becomes one pipe chunk, the
/// same granularity a flushed line has on a real pipe.
struct ChanWriter {
    tx: SyncSender<Vec<u8>>,
}

impl Write for ChanWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.tx
            .send(buf.to_vec())
            .map(|_| buf.len())
            .map_err(|_| std::io::Error::other("fixture output closed"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The fixture's input source: pipe chunks as they arrive, end of input
/// when every sender is gone (the client killed or dropped the pipe).
struct ChanReader {
    rx: Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl Read for ChanReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let filled = self.fill_buf()?;
        let n = filled.len().min(out.len());
        let (Some(dst), Some(src)) = (out.get_mut(..n), filled.get(..n)) else {
            return Err(std::io::Error::other(
                "fixture buffer shrank under the reader",
            ));
        };
        dst.copy_from_slice(src);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for ChanReader {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.pos >= self.buf.len() {
            if let Ok(chunk) = self.rx.recv() {
                self.buf = chunk;
                self.pos = 0;
            }
        }
        // `consume` is only ever fed fill_buf's own length, so `pos` never
        // passes `len`: the fallthrough is fail-closed, not reachable.
        Ok(self.buf.get(self.pos..).unwrap_or(&[]))
    }

    fn consume(&mut self, amt: usize) {
        self.pos += amt;
    }
}

impl TestPipe {
    /// Serves `mode` of the fixture on the far side of the pipes.
    pub fn fixture(mode: &str) -> TestPipe {
        let mode = mode.to_owned();
        let (to_server, server_in) = sync_channel(64);
        let (server_out, from_server) = sync_channel(256);
        let input: Box<dyn BufRead + Send> = Box::new(ChanReader {
            rx: server_in,
            buf: Vec::new(),
            pos: 0,
        });
        let output: Box<dyn Write + Send> = Box::new(ChanWriter { tx: server_out });
        let _server = thread::spawn(move || {
            let _ = serve(&mode, input, output);
        });
        TestPipe {
            to_server: Some(to_server),
            from_server,
            sent: Arc::new(Mutex::new(Vec::new())),
            killed: Arc::new(AtomicBool::new(false)),
            _server,
        }
    }

    /// Clones of the observation handles a test asserts on after the pipe
    /// has been moved into the provider.
    pub fn handles(&self) -> (Arc<AtomicBool>, Arc<Mutex<Vec<String>>>) {
        (self.killed.clone(), self.sent.clone())
    }
}

impl Transport for TestPipe {
    type Deadline = Instant;

    fn send(&mut self, frame: &[u8]) -> Result<(), TransportFault> {
        let tx = match self.to_server.as_ref() {
            Some(tx) => tx,
            None => return Err(TransportFault::Closed),
        };
        self.sent
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(String::from_utf8_lossy(frame).into_owned());
        let mut line = frame.to_vec();
        line.push(b'\n');
        tx.send(line).map_err(|_| TransportFault::Closed)
    }

    fn recv(&mut self, deadline: Instant) -> Result<Option<Vec<u8>>, TransportFault> {
        let Some(budget) = deadline.checked_duration_since(Instant::now()) else {
            return Err(TransportFault::Deadline);
        };
        match self.from_server.recv_timeout(budget) {
            Ok(chunk) => Ok(Some(chunk)),
            Err(RecvTimeoutError::Timeout) => Err(TransportFault::Deadline),
            Err(RecvTimeoutError::Disconnected) => Ok(None),
        }
    }

    fn kill(&mut self) {
        self.killed.store(true, Ordering::SeqCst);
        // End of input ends the served session (the `hang` mode excepted;
        // it never reads again).
        self.to_server = None;
    }
}

/// The connector's clock: the real wall clock, read in the one place the
/// client's [`Clock`] seam allows.
#[derive(Debug, Clone, Copy, Default)]
pub struct WallClock;

impl Clock for WallClock {
    type Time = Instant;

    fn after(&self, budget: Duration) -> Instant {
        Instant::now() + budget
    }
}

/// The observation handles of one dialed pipe: the kill flag and the log
/// of frames the client sent, for the wire-discipline assertions.
#[derive(Debug, Clone)]
pub struct PipeHandles {
    /// Set when the client killed the transport.
    pub killed: Arc<AtomicBool>,
    /// Every frame the client sent, lossy-UTF8, in order.
    pub sent: Arc<Mutex<Vec<String>>>,
}

/// The connector the provider tests drive (P-37h): every dial serves the
/// fixture's `mode` on a fresh worker thread. The sandbox witness is
/// accepted and ignored (see the module doc).
#[derive(Debug, Clone)]
pub struct InMemoryConnector {
    mode: String,
    last: Arc<Mutex<Option<PipeHandles>>>,
}

impl InMemoryConnector {
    /// A connector whose servers run `mode` (one fixture server per dial).
    pub fn new(mode: &str) -> InMemoryConnector {
        InMemoryConnector {
            mode: mode.to_owned(),
            last: Arc::new(Mutex::new(None)),
        }
    }

    /// The handles of the most recent dial ( [`McpConnector::dial`] runs
    /// inside the provider, so a test reads them here instead).
    pub fn handles(&self) -> Option<PipeHandles> {
        self.last
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl McpConnector for InMemoryConnector {
    type Time = Instant;
    type Clock = WallClock;
    type Transport = TestPipe;

    fn clock(&self) -> Self::Clock {
        WallClock
    }

    fn dial(
        &mut self,
        _conformed: &harness_sandbox::Conformed,
    ) -> Result<TestPipe, ConnectorError> {
        // The fixture is in-process; there is nothing to confine, so the
        // witness is only evidence the caller cleared the policy gate.
        let pipe = TestPipe::fixture(&self.mode);
        let (killed, sent) = pipe.handles();
        *self
            .last
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(PipeHandles { killed, sent });
        Ok(pipe)
    }
}
