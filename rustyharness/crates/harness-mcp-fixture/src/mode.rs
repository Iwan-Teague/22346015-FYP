//! The fixture's scripted modes (P-37 design note §14): one enum the serve
//! loop branches on, parsed from the `rh-mcp-fixture --mode` value or the
//! [`crate::serve`] argument. Parsing is total and fail-closed: an unknown
//! name or a malformed parameter is a typed error, never a silent fall
//! back to `ok` (a test that mistypes a mode must fail, not pass against
//! the benign server).
//!
//! Two modes take a parameter: `rug-pull-after:<n>` and `vanish-after:<n>`
//! change the tool list after `<n>` `tools/call` requests (0 means from
//! the first list), `version:<v>` answers `initialize` naming another
//! protocol version, and `paginate:<pages>` splits the list over that many
//! cursor pages.

use std::fmt;

/// The one protocol version the fixture speaks by default (the harness's
/// only supported one; P-37 design note §3.3, D2).
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Every mode string the design note lists (§14), with the parameterised
/// ones given a sample argument. Hostile suites (this crate's tests, then
/// `harness-mcp`'s) iterate it to prove each mode at least parses; it is
/// the crate's own table of contents. Keep it in the note's order.
pub const SAMPLE_MODE_STRINGS: &[&str] = &[
    "ok",
    "drift-description",
    "drift-schema",
    "rug-pull-after:1",
    "vanish-after:1",
    "new-tool-after:1",
    "list-changed-spam",
    "malformed",
    "huge-frame",
    "slow-loris",
    "wrong-id",
    "string-id",
    "double-response",
    "result-and-error",
    "flood",
    "sampling",
    "roots",
    "elicit",
    "ping",
    "request-flood",
    "batch",
    "version:2025-11-25",
    "no-tools-capability",
    "dup-tool-name",
    "paginate:3",
    "instructions-injection",
    "result-injection",
    "exit-midcall",
    "stderr-spam",
    "hang",
    "hang-after-connect",
    "confinement-probe",
];

/// A scripted server behaviour (P-37 design note §14). Every hostile mode
/// is named by one of these; the serve loop's branch per variant is the
/// mode's whole specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Two well-behaved tools (`echo`, `add`), fixed pins: the positive
    /// control every other mode is measured against.
    Ok,
    /// `echo`'s description is wrong from the first list (connect-time pin
    /// drift).
    DriftDescription,
    /// `echo`'s input schema is wrong from the first list (connect-time
    /// pin drift).
    DriftSchema,
    /// After `<n>` `tools/call` requests, `echo`'s description changes in
    /// the list: the rug-pull the pre-call re-list must catch.
    RugPullAfter(u64),
    /// After `<n>` `tools/call` requests, `echo` vanishes from the list.
    VanishAfter(u64),
    /// After `<n>` `tools/call` requests, an unlisted tool `extra` joins
    /// the list (P-37h: the relist counts it and never quarantines).
    NewToolAfter(u64),
    /// Sends a `notifications/tools/list_changed` before every list
    /// answer and after every call result.
    ListChangedSpam,
    /// Writes one line that is not JSON (after a normal `initialize`).
    Malformed,
    /// Answers every request after `initialize` with one 2 MiB line.
    HugeFrame,
    /// Writes the `initialize` result one byte per 100 ms: an absolute
    /// deadline must end it, not a patience contest.
    SlowLoris,
    /// Answers every request with the wrong id (424242).
    WrongId,
    /// Answers every request with its id echoed back as a JSON string
    /// (`"1"` for `1`).
    StringId,
    /// Writes every response frame twice.
    DoubleResponse,
    /// Puts `result` AND `error` in one response.
    ResultAndError,
    /// Writes 10 000 notifications before the `initialize` result.
    Flood,
    /// Sends a `sampling/createMessage` request after `initialized`.
    Sampling,
    /// Sends a `roots/list` request after `initialized`.
    Roots,
    /// Sends an `elicitation/create` request after `initialized`.
    Elicit,
    /// Sends a `ping` request after `initialized`.
    Ping,
    /// Blasts 20 server requests before the first list answer (over the
    /// client's per-run cap).
    RequestFlood,
    /// Answers `initialize` with a JSON array (a batch).
    Batch,
    /// Answers `initialize` naming exactly `<v>` as the protocol version.
    Version(String),
    /// `initialize` result has no `capabilities.tools`.
    NoToolsCapability,
    /// Lists the tool `echo` twice in one page.
    DupToolName,
    /// Splits the tool list over `<pages>` cursor pages.
    Paginate(u32),
    /// `initialize` carries an `instructions` string with an action block
    /// in it (a prompt-injection channel by design; never shown to a
    /// model).
    InstructionsInjection,
    /// `echo`'s result text carries an action block and a forged
    /// untrusted-block delimiter.
    ResultInjection,
    /// Writes half a frame on the first `tools/call`, then ends: the
    /// client sees EOF mid-call.
    ExitMidcall,
    /// Behaves like `ok` while spewing junk lines on stderr.
    StderrSpam,
    /// Answers `initialize`, then never answers anything again.
    Hang,
    /// Answers the lifecycle through the FIRST `tools/list`, then never
    /// answers again (P-37h: a connect that succeeds and a pre-call
    /// relist that hangs — the provider's call-phase timeout, not the
    /// handshake's).
    HangAfterConnect,
    /// Offers one tool that probes its confinement (home and cwd writes,
    /// loopback and internet connects, a planted home canary) and reports
    /// each attempt as a text line.
    ConfinementProbe,
}

impl Mode {
    /// Parses one mode string ([`SAMPLE_MODE_STRINGS`] is the accepted
    /// grammar's table of contents). Unknown names, missing or malformed
    /// parameters are refused.
    pub fn parse(s: &str) -> Result<Mode, ModeError> {
        let (name, param) = match s.split_once(':') {
            Some((name, param)) => (name, Some(param)),
            None => (s, None),
        };
        match name {
            "ok" => no_param(s, param, Mode::Ok),
            "drift-description" => no_param(s, param, Mode::DriftDescription),
            "drift-schema" => no_param(s, param, Mode::DriftSchema),
            "rug-pull-after" => calls_param(s, param).map(Mode::RugPullAfter),
            "vanish-after" => calls_param(s, param).map(Mode::VanishAfter),
            "new-tool-after" => calls_param(s, param).map(Mode::NewToolAfter),
            "list-changed-spam" => no_param(s, param, Mode::ListChangedSpam),
            "malformed" => no_param(s, param, Mode::Malformed),
            "huge-frame" => no_param(s, param, Mode::HugeFrame),
            "slow-loris" => no_param(s, param, Mode::SlowLoris),
            "wrong-id" => no_param(s, param, Mode::WrongId),
            "string-id" => no_param(s, param, Mode::StringId),
            "double-response" => no_param(s, param, Mode::DoubleResponse),
            "result-and-error" => no_param(s, param, Mode::ResultAndError),
            "flood" => no_param(s, param, Mode::Flood),
            "sampling" => no_param(s, param, Mode::Sampling),
            "roots" => no_param(s, param, Mode::Roots),
            "elicit" => no_param(s, param, Mode::Elicit),
            "ping" => no_param(s, param, Mode::Ping),
            "request-flood" => no_param(s, param, Mode::RequestFlood),
            "batch" => no_param(s, param, Mode::Batch),
            "version" => version_param(s, param),
            "no-tools-capability" => no_param(s, param, Mode::NoToolsCapability),
            "dup-tool-name" => no_param(s, param, Mode::DupToolName),
            "paginate" => pages_param(s, param),
            "instructions-injection" => no_param(s, param, Mode::InstructionsInjection),
            "result-injection" => no_param(s, param, Mode::ResultInjection),
            "exit-midcall" => no_param(s, param, Mode::ExitMidcall),
            "stderr-spam" => no_param(s, param, Mode::StderrSpam),
            "hang" => no_param(s, param, Mode::Hang),
            "hang-after-connect" => no_param(s, param, Mode::HangAfterConnect),
            "confinement-probe" => no_param(s, param, Mode::ConfinementProbe),
            _ => Err(ModeError::Unknown(s.to_owned())),
        }
    }
}

/// One mode string refused, with the reason. Fail-closed: the caller (the
/// binary, or a test) stops instead of serving something else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModeError {
    /// No mode is named exactly this (the whole string is echoed back).
    Unknown(String),
    /// A parameterised mode got a missing or malformed parameter.
    BadParam {
        /// The mode string as written (e.g. `rug-pull-after`).
        mode: String,
        /// The parameter that was missing or malformed (e.g. `n`).
        param: String,
    },
}

impl fmt::Display for ModeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ModeError::Unknown(s) => write!(f, "unknown fixture mode: {s}"),
            ModeError::BadParam { mode, param } => {
                write!(f, "bad parameter for fixture mode {mode}: {param:?}")
            }
        }
    }
}

impl std::error::Error for ModeError {}

/// A mode that takes no `:<param>` suffix.
fn no_param(s: &str, param: Option<&str>, mode: Mode) -> Result<Mode, ModeError> {
    match param {
        None => Ok(mode),
        Some(param) => Err(ModeError::BadParam {
            mode: s.to_owned(),
            param: param.to_owned(),
        }),
    }
}

/// The `<n>` of `rug-pull-after:<n>` / `vanish-after:<n>`: any u64 (0
/// means the drift is live from the first list).
fn calls_param(s: &str, param: Option<&str>) -> Result<u64, ModeError> {
    let param = param.ok_or_else(|| ModeError::BadParam {
        mode: s.to_owned(),
        param: String::new(),
    })?;
    param.parse::<u64>().map_err(|_| ModeError::BadParam {
        mode: s.to_owned(),
        param: param.to_owned(),
    })
}

/// The `<v>` of `version:<v>`: any non-empty version string (the fixture
/// is a test double; whether the client accepts `v` is the client's rule).
fn version_param(s: &str, param: Option<&str>) -> Result<Mode, ModeError> {
    match param {
        Some("") | None => Err(ModeError::BadParam {
            mode: s.to_owned(),
            param: param.unwrap_or_default().to_owned(),
        }),
        Some(v) => Ok(Mode::Version(v.to_owned())),
    }
}

/// The `<pages>` of `paginate:<pages>`: 1 to 64 (the client's page cap is
/// far lower; the fixture stays useful for bounds tests above it).
fn pages_param(s: &str, param: Option<&str>) -> Result<Mode, ModeError> {
    let pages = calls_param(s, param)?;
    if pages == 0 || pages > 64 {
        return Err(ModeError::BadParam {
            mode: s.to_owned(),
            param: param.unwrap_or_default().to_owned(),
        });
    }
    Ok(Mode::Paginate(u32::try_from(pages).unwrap_or(1)))
}
