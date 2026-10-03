//! The connector seam (design note §6, P-37h): the one place a provider
//! touches the platform. A connector dials the server — spawning it over
//! stdio pipes for the confined connector of P-37l — and yields the
//! transport and clock the pure client of P-37e runs on.
//!
//! The trait takes [`harness_sandbox::Conformed`] by reference: an MCP
//! server is a foreign process, so a provider may not dial one without a
//! conformed sandbox (§2.2 step 7; the policy already refuses MCP
//! capabilities without confinement). The in-memory connector used by this
//! slice's tests ignores the witness — its "server" is a thread inside the
//! test process — and lives in the fixture package, because the purity gate
//! scans every file of THIS package and a dialing connector names threads
//! and pipes (see the crate doc).

use crate::client;

/// Why a connector could not start the server (§6). One variant on
/// purpose: whatever went wrong is the connector's to describe, and the
/// provider fails closed on it either way.
#[derive(Debug, thiserror::Error)]
#[error("the connector could not start the server: {0}")]
pub struct ConnectorError(pub String);

/// Dials the server for one provider (§6). The associated types feed
/// [`crate::Client`] directly, so a connector invents no new protocol —
/// it only decides how bytes move and how deadlines are anchored.
pub trait McpConnector {
    /// The deadline kind the transport's `recv` takes.
    type Time: Copy + Ord;
    /// The clock anchoring the client's budgets.
    type Clock: client::Clock<Time = Self::Time>;
    /// The byte pipe to the server (and back).
    type Transport: client::Transport<Deadline = Self::Time>;

    /// The clock handed to the client.
    fn clock(&self) -> Self::Clock;

    /// Starts the server and returns its pipe. Called once per
    /// [`crate::provider::McpProvider::connect`]; a connector that cannot
    /// start its server returns [`ConnectorError`] and the provider stays
    /// unconnected (fail closed).
    ///
    /// The budget parameters are informational (how long the caller is
    /// prepared to wait for the handshake): the client enforces its own
    /// budgets; a connector that must bound the dial itself bounds them
    /// with [`Duration`].
    fn dial(
        &mut self,
        conformed: &harness_sandbox::Conformed,
    ) -> Result<Self::Transport, ConnectorError>;
}
