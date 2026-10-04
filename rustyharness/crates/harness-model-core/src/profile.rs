//! Per-model profiles (design §3.4). Pure.
//!
//! A profile is a data file (JSON, strict: duplicate keys and unknown fields
//! refused). Content checks: every number in range, names in their
//! grammar, no field that this build cannot honour:
//! - `grammar` other than `none` is refused (constrained decoding through
//!   the OpenAI-compatible API is spike S-P1; safety never depends on it);
//! - `price` is refused: prices for hosted endpoints are declared with
//!   P-31's `price_table` next to `upstream: "hosted"` instead (N-7: "a
//!   hosted run without a price table refuses to start" is enforced where
//!   runs are planned, not here — a hosted profile without a price table
//!   parses, and every run of it is refused);
//! - `tool_choice_required_ok: true` with the text protocol is refused as
//!   meaningless, and so is `parallel_tool_calls_false_ok: true`;
//! - `parallel_tool_calls: true` (P-53) is refused with the text protocol
//!   as meaningless (the text protocol is exactly one action by
//!   definition) and with `parallel_tool_calls_false_ok` as
//!   contradictory (that flag already asks the server for one call).
//!
//! **Optional fields within version 1.** `parallel_tool_calls_false_ok`
//! (design row H1h), `stream_include_usage_ok` (row H1i) and
//! `max_read_lines` (row H2e: the read window, 10 to 2000 lines, bounded by
//! the context budget) and `read_timeout_secs` (row H2f: the model read
//! timeout, 5 to 600 s) are optional and off by default, like
//! `kv_quant_note`: every profile written before them still parses, and
//! still has the same content digest (each joins the digest only when it is
//! on), so its `profile check` stamp stays valid. An
//! older harness refuses a profile that sets one (unknown fields are
//! refused), so no build silently ignores it. The same is true of P-53's
//! `tool_docs` (`full` by default; `terse` joins the digest) and
//! `parallel_tool_calls` (`false` by default; `true` joins the digest), and
//! of P-31's hosted declaration (`upstream` and `price_table` are absent
//! for a local model, which keeps the digest of every profile written
//! before P-31; both join the digest when the profile says
//! `upstream: "hosted"`).
//!
//! An unknown model gets [`Profile::conservative_default`]. A profile runs
//! whether or not `profile check` stamped it; `profile_validated` is
//! recorded in every journal header (§3.4).

use serde::Deserialize;

use harness_core::{sha256, strict_json, Digest};

/// Action protocol (§3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// OpenAI `tools` / `tool_calls`.
    Native,
    /// One `<action>{…}</action>` block in the reply text.
    Text,
}

/// Constrained decoding (§3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Grammar {
    /// None.
    None,
    /// llama.cpp lazy GBNF.
    GbnfLazy,
    /// JSON-Schema-constrained.
    JsonSchema,
}

/// Edit format (§4.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EditFormat {
    /// Exact search/replace.
    Replace,
    /// Whole-file write.
    Whole,
    /// Multi-file `*** Begin Patch` scripts (P-25).
    Patch,
}

/// How tool declarations describe the tools (P-53).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolDocs {
    /// The manifest summary (the default).
    #[default]
    Full,
    /// The terse fixed table (`harness_manifest::builtin::terse_summary`):
    /// one sentence per tool plus its argument names, for small local
    /// models that read shorter declarations better.
    Terse,
}

/// Where a model's inference runs (P-31). Only the hosted case is
/// representable: the endpoint is the user's loopback proxy in front of a
/// hosted provider (docs/hosted-proxy.md), so the context leaves the
/// machine and the hosted disclosure rules apply (Q-2, Q-3). Any other
/// value is an unknown variant and refused as a shape error, fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Upstream {
    /// The endpoint proxies a hosted provider.
    Hosted,
}

/// A price table (P-31, §2.4): the hosted provider's price in micro-USD
/// per kilo-token. It feeds the meter's `Cost` budget; a hosted run whose
/// profile has none refuses to start (enforced where runs are planned).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriceTable {
    /// Input price, micro-USD per kilo-token.
    pub in_micro_per_ktok: u64,
    /// Output price, micro-USD per kilo-token.
    pub out_micro_per_ktok: u64,
}

/// Sampling defaults.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sampling {
    /// 0.0..=2.0.
    pub temperature: f64,
    /// (0.0, 1.0].
    pub top_p: f64,
    /// Optional fixed seed.
    #[serde(default)]
    pub seed: Option<u64>,
    /// Completion cap, 1..context_window.
    pub max_tokens: u64,
}

/// The `profile check` stamp, bound to the profile's content (H1d review
/// F-5): `stamp_sha256 = sha256(content digest hex ":" report digest hex)`,
/// where the content digest covers every profile field except the stamp
/// itself. [`Profile::validated`] recomputes it, so a stamp copied into
/// another profile, a made-up stamp, or a profile edited after
/// `profile check` is simply unvalidated.
///
/// **What it is and is not (H1e-1 review NF-E).** It is a STALENESS check:
/// it proves the stamp was computed for exactly this content. It is NOT
/// authentication: the digest is unkeyed and public, so whoever can edit
/// the profile file can also compute a matching stamp. `profile_validated`
/// therefore means "stamp consistent with content", never "the harness saw
/// this profile pass". Authenticity (the smoke report stored under
/// `state_root` and re-verified) arrives with the `profile check` CLI verb.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stamp {
    /// SHA-256 (hex) of the smoke-eval report.
    pub report_sha256: String,
    /// SHA-256 (hex) binding the report to this profile's content.
    pub stamp_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileWire {
    profile_version: u32,
    id: String,
    model: String,
    context_window: u64,
    fill_ratio: f64,
    protocol: Protocol,
    tool_choice_required_ok: bool,
    #[serde(default)]
    parallel_tool_calls_false_ok: bool,
    #[serde(default)]
    parallel_tool_calls: bool,
    #[serde(default)]
    stream_include_usage_ok: bool,
    #[serde(default)]
    tool_docs: ToolDocs,
    #[serde(default)]
    max_read_lines: Option<u64>,
    #[serde(default)]
    read_timeout_secs: Option<u64>,
    grammar: Grammar,
    max_active_tools: u32,
    edit_format: EditFormat,
    recent_turns: u32,
    sampling: Sampling,
    #[serde(default)]
    kv_quant_note: Option<String>,
    #[serde(default)]
    upstream: Option<Upstream>,
    #[serde(default)]
    price_table: Option<PriceTable>,
    #[serde(default)]
    price: Option<serde_json::Value>,
    #[serde(default)]
    validated: Option<Stamp>,
}

/// A validated profile. Private fields; built by [`Profile::parse`] or
/// [`Profile::conservative_default`].
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    id: String,
    model: String,
    context_window: u64,
    fill_ratio: f64,
    protocol: Protocol,
    tool_choice_required_ok: bool,
    parallel_tool_calls_false_ok: bool,
    parallel_tool_calls: bool,
    stream_include_usage_ok: bool,
    tool_docs: ToolDocs,
    max_read_lines: Option<u64>,
    read_timeout_secs: Option<u64>,
    max_active_tools: u32,
    edit_format: EditFormat,
    recent_turns: u32,
    sampling: Sampling,
    kv_quant_note: Option<String>,
    upstream: Option<Upstream>,
    price_table: Option<PriceTable>,
    validated: Option<Stamp>,
    sha256: Option<Digest>,
}

/// The shortest model read timeout a profile may set, in seconds (H2f).
pub const READ_TIMEOUT_MIN_SECS: u64 = 5;
/// The longest, in seconds (H2f): the run drives a model call to at most its
/// own call deadline (300 s by default), whatever this says.
pub const READ_TIMEOUT_MAX_SECS: u64 = 600;
/// The read window a profile sets when it does not say (§4.8): 100 lines.
pub const READ_WINDOW_DEFAULT_LINES: u64 = 100;
/// The narrowest window a profile may set, in lines (H2e).
pub const READ_WINDOW_MIN_LINES: u64 = 10;
/// The widest window a profile may set, in lines (H2e): the built-in
/// manifest's hard maximum for `harness.fs.read`'s `lines`.
pub const READ_WINDOW_MAX_LINES: u64 = 2000;
/// Bytes a window allows per line of it (H2e). A window of N lines holds at
/// most `max(16 KiB, N × 64)` bytes, and never more than 64 KiB, the tool
/// result cap: a read of longer lines stops at a line boundary before the
/// bytes run out and says where to continue.
pub const READ_WINDOW_BYTES_PER_LINE: u64 = 64;
/// The fewest bytes a window allows (the default window's).
pub const READ_WINDOW_MIN_BYTES: u64 = 16 * 1024;
/// The most bytes a window allows (the tool result cap).
pub const READ_WINDOW_MAX_BYTES: u64 = 64 * 1024;

/// A run's read window (H2e): the most lines one `harness.fs.read` returns,
/// and the most bytes of its result. It also sets the context's
/// per-observation cap, so a read is never cut in the context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadWindow {
    /// Most lines per read.
    pub lines: u64,
    /// Most bytes of a read's result.
    pub bytes: u64,
}

impl ReadWindow {
    /// The window of `lines` lines (clamped to the allowed range).
    pub fn of_lines(lines: u64) -> Self {
        let lines = lines.clamp(READ_WINDOW_MIN_LINES, READ_WINDOW_MAX_LINES);
        let bytes = lines
            .saturating_mul(READ_WINDOW_BYTES_PER_LINE)
            .clamp(READ_WINDOW_MIN_BYTES, READ_WINDOW_MAX_BYTES);
        Self { lines, bytes }
    }
}

/// Why a profile was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// Not strict JSON, or an unknown/missing field.
    #[error("profile is not a valid profile document: {0}")]
    Shape(String),
    /// A field out of range or outside its grammar.
    #[error("profile field {0} is out of range or malformed")]
    Field(&'static str),
    /// `max_read_lines` asks for a window the context budget cannot hold
    /// (H2e): a window's lines at 64 bytes each must fit in half the
    /// budget.
    #[error("profile field max_read_lines: {lines} lines need about {needs} tokens, more than half of the context budget of {budget} tokens")]
    ReadWindow {
        /// The lines asked for.
        lines: u64,
        /// Their estimate, in tokens.
        needs: u64,
        /// The context budget (`context_window × fill_ratio`), in tokens.
        budget: u64,
    },
    /// A field this build cannot honour.
    #[error("profile field {field}: {why}")]
    NotInThisBuild {
        /// Field.
        field: &'static str,
        /// Why.
        why: &'static str,
    },
}

/// Profile schema versions understood.
pub const PROFILE_VERSIONS: &[u32] = &[1];

fn is_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn is_model_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| b.is_ascii_graphic())
}

impl Profile {
    /// Parse and validate a profile file's bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProfileError> {
        let v = strict_json::parse(bytes).map_err(|e| ProfileError::Shape(e.to_string()))?;
        // An explicit null is not "absent" (H2e: the read window is a
        // number when it is there at all).
        if v.get("max_read_lines")
            .is_some_and(serde_json::Value::is_null)
        {
            return Err(ProfileError::Shape(
                "max_read_lines is null; leave it out for the default window".into(),
            ));
        }
        if v.get("read_timeout_secs")
            .is_some_and(serde_json::Value::is_null)
        {
            return Err(ProfileError::Shape(
                "read_timeout_secs is null; leave it out for the default timeout".into(),
            ));
        }
        if v.get("upstream").is_some_and(serde_json::Value::is_null) {
            return Err(ProfileError::Shape(
                "upstream is null; leave it out for a local model".into(),
            ));
        }
        if v.get("price_table").is_some_and(serde_json::Value::is_null) {
            return Err(ProfileError::Shape(
                "price_table is null; leave it out (or declare `upstream` with it)".into(),
            ));
        }
        let w: ProfileWire =
            serde_json::from_value(v).map_err(|e| ProfileError::Shape(e.to_string()))?;
        let f = ProfileError::Field;
        if !PROFILE_VERSIONS.contains(&w.profile_version) {
            return Err(f("profile_version"));
        }
        if !is_id(&w.id) {
            return Err(f("id"));
        }
        if !is_model_name(&w.model) {
            return Err(f("model"));
        }
        if !(512..=4_194_304).contains(&w.context_window) {
            return Err(f("context_window"));
        }
        if !(w.fill_ratio > 0.0 && w.fill_ratio <= 1.0) {
            return Err(f("fill_ratio"));
        }
        if !(5..=8).contains(&w.max_active_tools) {
            return Err(f("max_active_tools"));
        }
        if !(1..=32).contains(&w.recent_turns) {
            return Err(f("recent_turns"));
        }
        let s = w.sampling;
        if !(0.0..=2.0).contains(&s.temperature) {
            return Err(f("sampling.temperature"));
        }
        if !(s.top_p > 0.0 && s.top_p <= 1.0) {
            return Err(f("sampling.top_p"));
        }
        if s.max_tokens == 0 || s.max_tokens >= w.context_window {
            return Err(f("sampling.max_tokens"));
        }
        if let Some(n) = &w.kv_quant_note {
            if n.is_empty() || n.len() > 256 || n.chars().any(char::is_control) {
                return Err(f("kv_quant_note"));
            }
        }
        if let Some(st) = &w.validated {
            if st.report_sha256.parse::<Digest>().is_err() {
                return Err(f("validated.report_sha256"));
            }
            if st.stamp_sha256.parse::<Digest>().is_err() {
                return Err(f("validated.stamp_sha256"));
            }
        }
        if w.grammar != Grammar::None {
            return Err(ProfileError::NotInThisBuild {
                field: "grammar",
                why: "constrained decoding is not sent by this build (spike S-P1)",
            });
        }
        if w.price.is_some() {
            return Err(ProfileError::NotInThisBuild {
                field: "price",
                why: "prices apply to hosted endpoints, which this build does not have",
            });
        }
        // P-31, fail closed: a price table prices a hosted provider, so it
        // only means something next to `upstream: "hosted"` (and a hosted
        // run without one is refused at planning, per §2.4 — parsing stays
        // permissive so the profile file can be checked on its own).
        if w.price_table.is_some() && w.upstream != Some(Upstream::Hosted) {
            return Err(ProfileError::NotInThisBuild {
                field: "price_table",
                why: "a price table needs `upstream: \"hosted\"`",
            });
        }
        if w.tool_choice_required_ok && w.protocol == Protocol::Text {
            return Err(f("tool_choice_required_ok"));
        }
        if w.parallel_tool_calls_false_ok && w.protocol == Protocol::Text {
            return Err(f("parallel_tool_calls_false_ok"));
        }
        // P-53: parallel calls are a native-protocol shape (the text
        // protocol is exactly one action by definition), and they make no
        // sense next to a flag that asks the server for one call per reply.
        if w.parallel_tool_calls {
            if w.protocol == Protocol::Text {
                return Err(f("parallel_tool_calls"));
            }
            if w.parallel_tool_calls_false_ok {
                return Err(f("parallel_tool_calls"));
            }
        }
        if let Some(t) = w.read_timeout_secs {
            if !(READ_TIMEOUT_MIN_SECS..=READ_TIMEOUT_MAX_SECS).contains(&t) {
                return Err(f("read_timeout_secs"));
            }
        }
        if let Some(lines) = w.max_read_lines {
            if !(READ_WINDOW_MIN_LINES..=READ_WINDOW_MAX_LINES).contains(&lines) {
                return Err(f("max_read_lines"));
            }
            // Bounded by the context budget (H2e): the window's lines, at 64
            // bytes each and 3 bytes to a token (the estimate of §2.3), must
            // fit in half of it, beside the rules, the task and the turns.
            // context_window ≤ 4 Mi and 0 < fill_ratio ≤ 1 (checked above).
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let budget = (w.context_window as f64 * w.fill_ratio).floor() as u64;
            let needs = lines.saturating_mul(READ_WINDOW_BYTES_PER_LINE).div_ceil(3);
            if needs.saturating_mul(2) > budget {
                return Err(ProfileError::ReadWindow {
                    lines,
                    needs,
                    budget,
                });
            }
        }
        Ok(Self {
            id: w.id,
            model: w.model,
            context_window: w.context_window,
            fill_ratio: w.fill_ratio,
            protocol: w.protocol,
            tool_choice_required_ok: w.tool_choice_required_ok,
            parallel_tool_calls_false_ok: w.parallel_tool_calls_false_ok,
            parallel_tool_calls: w.parallel_tool_calls,
            stream_include_usage_ok: w.stream_include_usage_ok,
            tool_docs: w.tool_docs,
            max_read_lines: w.max_read_lines,
            read_timeout_secs: w.read_timeout_secs,
            max_active_tools: w.max_active_tools,
            edit_format: w.edit_format,
            recent_turns: w.recent_turns,
            sampling: s,
            kv_quant_note: w.kv_quant_note,
            upstream: w.upstream,
            price_table: w.price_table,
            validated: w.validated,
            sha256: Some(sha256(bytes)),
        })
    }

    /// The conservative default for a model without a profile (§3.4): text
    /// protocol, 5 tools, replace edits, K = 4. Unvalidated.
    pub fn conservative_default(model: &str) -> Self {
        Self {
            id: "default".into(),
            model: model.to_owned(),
            context_window: 8192,
            fill_ratio: 0.6,
            protocol: Protocol::Text,
            tool_choice_required_ok: false,
            parallel_tool_calls_false_ok: false,
            parallel_tool_calls: false,
            stream_include_usage_ok: false,
            tool_docs: ToolDocs::Full,
            max_read_lines: None,
            read_timeout_secs: None,
            max_active_tools: 5,
            edit_format: EditFormat::Replace,
            recent_turns: 4,
            sampling: Sampling {
                temperature: 0.2,
                top_p: 0.95,
                seed: None,
                max_tokens: 1024,
            },
            kv_quant_note: None,
            upstream: None,
            price_table: None,
            validated: None,
            sha256: None,
        }
    }

    /// Profile id.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// The server's model name.
    pub fn model(&self) -> &str {
        &self.model
    }
    /// Context window in tokens.
    pub fn context_window(&self) -> u64 {
        self.context_window
    }
    /// Context fill ratio (§2.3).
    pub fn fill_ratio(&self) -> f64 {
        self.fill_ratio
    }
    /// Action protocol.
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
    /// Whether `tool_choice: "required"` may be sent.
    pub fn tool_choice_required_ok(&self) -> bool {
        self.tool_choice_required_ok
    }
    /// Whether `parallel_tool_calls: false` is sent with the tools (native
    /// protocol; design row H1h). A server that honours it makes at most
    /// one call per reply; one that accepts and ignores it (Z.ai's
    /// glm-5.3-flash, measured 2026-09-28) leaves the harness's
    /// one-action rule to its format error and repair message.
    pub fn parallel_tool_calls_false_ok(&self) -> bool {
        self.parallel_tool_calls_false_ok
    }
    /// Whether the model may make several tool calls in one assistant turn
    /// (P-53). Off by default: a second call is a format error with the
    /// usual repair message. On (native protocol only), the first call of a
    /// multi-call reply runs and the rest are dropped with a notice. The
    /// text protocol is exactly-one-action by definition, and
    /// [`Profile::parallel_tool_calls_false_ok`] already asks the server
    /// for one call, so either combination is refused at parse time.
    pub fn parallel_tool_calls(&self) -> bool {
        self.parallel_tool_calls
    }
    /// How tool declarations describe the tools (P-53): the manifest
    /// summary, or the terse fixed table. Full by default, so every profile
    /// written before P-53 renders exactly as it did.
    pub fn tool_docs(&self) -> ToolDocs {
        self.tool_docs
    }
    /// Whether the request asks for usage in the stream,
    /// `stream_options: {"include_usage": true}` (design row H1i). llama.cpp
    /// (build 10470 measured) sends a streamed reply's token usage only
    /// when asked; its final chunk carries `timings` either way. Off by
    /// default: a server that refuses unknown parameters would refuse every
    /// request. Z.ai accepts it (measured 2026-09-28) and sends usage anyway.
    pub fn stream_include_usage_ok(&self) -> bool {
        self.stream_include_usage_ok
    }
    /// The read window (H2e): the profile's `max_read_lines`, or 100 lines
    /// when it does not set one, with the bytes that allows.
    pub fn read_window(&self) -> ReadWindow {
        ReadWindow::of_lines(self.max_read_lines.unwrap_or(READ_WINDOW_DEFAULT_LINES))
    }
    /// The model read timeout (H2f): the longest the harness waits for any
    /// single read from the model server, when the profile sets one.
    /// `None` keeps the client's default (60 s).
    pub fn read_timeout(&self) -> Option<std::time::Duration> {
        self.read_timeout_secs.map(std::time::Duration::from_secs)
    }
    /// Cap on the active tool set.
    pub fn max_active_tools(&self) -> u32 {
        self.max_active_tools
    }
    /// Edit format.
    pub fn edit_format(&self) -> EditFormat {
        self.edit_format
    }
    /// Recent turns kept verbatim (K).
    pub fn recent_turns(&self) -> u32 {
        self.recent_turns
    }
    /// Sampling defaults.
    pub fn sampling(&self) -> Sampling {
        self.sampling
    }
    /// The KV-quantization note.
    pub fn kv_quant_note(&self) -> Option<&str> {
        self.kv_quant_note.as_deref()
    }
    /// Whether the profile declares a hosted upstream (P-31): the endpoint
    /// is the user's loopback proxy in front of a hosted provider, so the
    /// context leaves the machine. Hosted runs get the disclosure banner,
    /// refuse grants at personal sensitivity or above (Q-2), need a price
    /// table (§2.4), and record `endpoint_class: loopback-proxy-hosted` in
    /// the journal header (Q-3).
    pub fn hosted(&self) -> bool {
        self.upstream == Some(Upstream::Hosted)
    }
    /// The price table as per-token pricing (P-31) for the meter's `Cost`
    /// budget. Per kilo-token prices divide by 1000 with integer division:
    /// a price that is not a whole number of micro-USD per token floors
    /// (the budget is a ceiling, never a discount, and the audit recomputes
    /// the same way). `None` unless the profile is hosted and sets a table.
    pub fn pricing(&self) -> Option<harness_core::Pricing> {
        let t = self.price_table?;
        Some(harness_core::Pricing {
            input_micros_per_token: t.in_micro_per_ktok / 1000,
            output_micros_per_token: t.out_micro_per_ktok / 1000,
        })
    }
    /// Whether `profile check` stamped this profile. Recorded as
    /// `profile_validated` in every journal header (§3.4).
    pub fn validated(&self) -> bool {
        self.validated.as_ref().is_some_and(|st| {
            st.report_sha256
                .parse::<Digest>()
                .is_ok_and(|r| self.stamp_for(&r) == *st)
        })
    }

    /// The stamp digest, when the stamp is valid for this content (what the
    /// journal header records next to `profile_validated`).
    pub fn stamp_sha256(&self) -> Option<&str> {
        self.validated
            .as_ref()
            .filter(|_| self.validated())
            .map(|s| s.stamp_sha256.as_str())
    }

    /// The canonical content of this profile: every field except the stamp,
    /// as sorted-key JSON. Derived from the validated fields, so two files
    /// that differ only in whitespace or key order have the same content.
    pub fn content_sha256(&self) -> Digest {
        let s = self.sampling;
        let mut v = serde_json::json!({
            "profile_version": 1,
            "id": self.id,
            "model": self.model,
            "context_window": self.context_window,
            "fill_ratio": self.fill_ratio,
            "protocol": match self.protocol { Protocol::Native => "native", Protocol::Text => "text" },
            "tool_choice_required_ok": self.tool_choice_required_ok,
            "grammar": "none",
            "max_active_tools": self.max_active_tools,
            "edit_format": match self.edit_format { EditFormat::Replace => "replace", EditFormat::Whole => "whole", EditFormat::Patch => "patch" },
            "recent_turns": self.recent_turns,
            "sampling": {"temperature": s.temperature, "top_p": s.top_p, "max_tokens": s.max_tokens},
        });
        if let (Some(seed), Some(sampling)) = (
            s.seed,
            v.get_mut("sampling").and_then(|x| x.as_object_mut()),
        ) {
            sampling.insert("seed".into(), serde_json::Value::from(seed));
        }
        if let (Some(n), Some(o)) = (&self.kv_quant_note, v.as_object_mut()) {
            o.insert("kv_quant_note".into(), serde_json::Value::from(n.clone()));
        }
        // Only when on (H1h), so every profile without it keeps its digest
        // and its stamp.
        if let (true, Some(o)) = (self.parallel_tool_calls_false_ok, v.as_object_mut()) {
            o.insert(
                "parallel_tool_calls_false_ok".into(),
                serde_json::Value::Bool(true),
            );
        }
        // The same for H1i's flag.
        if let (true, Some(o)) = (self.stream_include_usage_ok, v.as_object_mut()) {
            o.insert(
                "stream_include_usage_ok".into(),
                serde_json::Value::Bool(true),
            );
        }
        // And for H2e's read window: only when set, so every profile
        // without it keeps its digest and its stamp.
        if let (Some(n), Some(o)) = (self.max_read_lines, v.as_object_mut()) {
            o.insert("max_read_lines".into(), serde_json::Value::from(n));
        }
        // And for H2f's read timeout: only when set.
        if let (Some(n), Some(o)) = (self.read_timeout_secs, v.as_object_mut()) {
            o.insert("read_timeout_secs".into(), serde_json::Value::from(n));
        }
        // And for P-53's tool docs: only when terse, so every profile
        // written before P-53 keeps its digest and its stamp.
        if let (ToolDocs::Terse, Some(o)) = (self.tool_docs, v.as_object_mut()) {
            o.insert("tool_docs".into(), serde_json::Value::from("terse"));
        }
        // And for P-53's parallel calls: only when opted in.
        if let (true, Some(o)) = (self.parallel_tool_calls, v.as_object_mut()) {
            o.insert("parallel_tool_calls".into(), serde_json::Value::Bool(true));
        }
        // And for P-31's hosted declaration: only when hosted, so every
        // local profile (each profile written before P-31) keeps its
        // digest and its stamp. A hosted profile without a price table is
        // representable here (every run of it refuses) and digests as
        // `upstream` alone.
        if self.hosted() {
            if let Some(o) = v.as_object_mut() {
                o.insert("upstream".into(), serde_json::Value::from("hosted"));
                if let Some(t) = self.price_table {
                    o.insert(
                        "price_table".into(),
                        serde_json::json!({
                            "in_micro_per_ktok": t.in_micro_per_ktok,
                            "out_micro_per_ktok": t.out_micro_per_ktok,
                        }),
                    );
                }
            }
        }
        sha256(v.to_string().as_bytes())
    }

    /// The stamp `profile check` writes for a passing report on THIS content.
    /// Crate-private (H1e-1 review NF-E): outside code gets a stamp only
    /// through [`score`] over smoke results.
    pub(crate) fn stamp_for(&self, report: &Digest) -> Stamp {
        let bound = format!("{}:{}", self.content_sha256(), report);
        Stamp {
            report_sha256: report.to_string(),
            stamp_sha256: sha256(bound.as_bytes()).to_string(),
        }
    }
    /// SHA-256 of the profile file, when loaded from one.
    pub fn sha256(&self) -> Option<Digest> {
        self.sha256
    }

    /// The profile with `tool_docs` set (P-53): what `profile init` writes
    /// for a local small model without hand-editing. Unstamped content: the
    /// file digest is dropped, and any stamp a profile carried would no
    /// longer match the content (`validated` recomputes over the content),
    /// which is honest for a profile that was just changed.
    #[must_use]
    pub fn with_tool_docs(mut self, docs: ToolDocs) -> Self {
        self.tool_docs = docs;
        self.sha256 = None;
        self
    }
}

/// What the `profile check` smoke eval observed (§3.4). Edit-format
/// compliance needs the edit tools (H2) and is recorded as unchecked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmokeResults {
    /// Cases run.
    pub cases: u32,
    /// Replies that parsed to exactly the expected tool call.
    pub valid_tool_calls: u32,
    /// Replies that were format errors.
    pub format_errors: u32,
    /// Model calls that failed outright (transport or typed model error).
    pub call_failures: u32,
}

/// The verdict of `profile check`: stamp the profile, or not. Not a gate
/// outcome (it describes a profile, not a run).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResult {
    /// Passed; stamp the profile with this digest.
    Stamp(Stamp),
    /// Did not pass; the reason.
    NoStamp(&'static str),
}

/// Minimum smoke cases for a stamp.
pub const SMOKE_MIN_CASES: u32 = 5;

/// Score smoke results (pure). A stamp needs at least [`SMOKE_MIN_CASES`]
/// cases, no failed call, at least 80% exactly valid tool calls, and a
/// format-error rate of at most 20%. The stamp is the SHA-256 of a
/// canonical report line naming the profile, the counts and the unchecked
/// edit-format part.
pub fn score(profile: &Profile, r: &SmokeResults) -> CheckResult {
    if r.cases < SMOKE_MIN_CASES {
        return CheckResult::NoStamp("too few cases");
    }
    if r.call_failures > 0 {
        return CheckResult::NoStamp("a model call failed");
    }
    if u64::from(r.valid_tool_calls) * 5 < u64::from(r.cases) * 4 {
        return CheckResult::NoStamp("fewer than 80% valid tool calls");
    }
    if u64::from(r.format_errors) * 5 > u64::from(r.cases) {
        return CheckResult::NoStamp("format-error rate above 20%");
    }
    let report = format!(
        "profile-check/1 id={} model={} protocol={:?} cases={} valid={} format_errors={} edit_format=unchecked",
        profile.id, profile.model, profile.protocol, r.cases, r.valid_tool_calls, r.format_errors
    );
    CheckResult::Stamp(profile.stamp_for(&sha256(report.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"{"profile_version":1,"id":"qwen-7b-q4","model":"qwen2.5-coder:7b",
      "context_window":32768,"fill_ratio":0.6,"protocol":"text","tool_choice_required_ok":false,
      "grammar":"none","max_active_tools":6,"edit_format":"replace","recent_turns":5,
      "sampling":{"temperature":0.2,"top_p":0.95,"seed":7,"max_tokens":2048}}"#;

    fn with(k: &str, v: &str) -> String {
        let mut o: serde_json::Map<String, serde_json::Value> = serde_json::from_str(GOOD).unwrap();
        o.insert(k.into(), serde_json::from_str(v).unwrap());
        serde_json::Value::Object(o).to_string()
    }

    #[test]
    fn good_profile_parses_unvalidated() {
        let p = Profile::parse(GOOD.as_bytes()).unwrap();
        assert_eq!(p.protocol(), Protocol::Text);
        assert!(!p.validated());
        assert_eq!(p.sha256(), Some(sha256(GOOD.as_bytes())));
    }

    #[test]
    fn conservative_default_matches_the_design() {
        let p = Profile::conservative_default("anything");
        assert_eq!(p.protocol(), Protocol::Text);
        assert_eq!(p.max_active_tools(), 5);
        assert_eq!(p.edit_format(), EditFormat::Replace);
        assert_eq!(p.recent_turns(), 4);
        assert!(!p.validated());
    }

    // P-25: `"edit_format":"patch"` parses (the enum grows; the default and
    // every existing profile stay exactly as they were).
    #[test]
    fn profile_edit_format_patch_parses() {
        let p = Profile::parse(with("edit_format", "\"patch\"").as_bytes()).unwrap();
        assert_eq!(p.edit_format(), EditFormat::Patch);
        assert_eq!(
            Profile::conservative_default("m").edit_format(),
            EditFormat::Replace
        );
    }

    // P-25: the new enum arm changes nothing for profiles written before it —
    // the replace and whole digests are the pre-P-25 values (captured at the
    // H1h/parallel_tool_calls pins above), so existing stamps stay valid.
    #[test]
    fn old_profile_digest_unchanged() {
        const REPLACE_CONTENT: &str =
            "b8bf6a5e7b6c3f107548dc8cb096d84b2900f8e0846e474845521be5f8fcfb6f";
        const WHOLE_CONTENT: &str =
            "8b851b54c20fa753fcc10026dcad988f1cb83eca160e2c4ad6c1e1b5c7350630";
        let p = Profile::parse(GOOD.as_bytes()).unwrap();
        assert_eq!(p.content_sha256().to_string(), REPLACE_CONTENT);
        let mut o: serde_json::Map<String, serde_json::Value> = serde_json::from_str(GOOD).unwrap();
        o.insert("edit_format".into(), serde_json::json!("whole"));
        let w = Profile::parse(serde_json::Value::Object(o).to_string().as_bytes()).unwrap();
        assert_eq!(w.edit_format(), EditFormat::Whole);
        assert_eq!(w.content_sha256().to_string(), WHOLE_CONTENT);
    }

    // P-31: a local profile — every profile written before P-31 — keeps its
    // digest and its stamp. `upstream` and `price_table` are content only
    // when the profile is hosted.
    #[test]
    fn local_profile_digest_unchanged() {
        const GOOD_CONTENT: &str =
            "b8bf6a5e7b6c3f107548dc8cb096d84b2900f8e0846e474845521be5f8fcfb6f";
        const DEFAULT_CONTENT: &str =
            "d6b9b8ef0476910c516913f9edd2adfb5c8d91798e629f2403906c69141ba6cb";
        let p = Profile::parse(GOOD.as_bytes()).unwrap();
        assert!(!p.hosted());
        assert_eq!(p.pricing(), None);
        assert_eq!(p.content_sha256().to_string(), GOOD_CONTENT);
        let d = Profile::conservative_default("m");
        assert!(!d.hosted());
        assert_eq!(d.pricing(), None);
        assert_eq!(d.content_sha256().to_string(), DEFAULT_CONTENT);
    }

    // P-31: a hosted profile parses with the price table, converts it to
    // per-token pricing for the meter's Cost budget, and is content (its
    // digest differs from the local one). Hosted without a table parses
    // too — every run of it refuses, at planning (§2.4).
    #[test]
    fn hosted_profile_declares_upstream_and_price_table() {
        let hosted = with("upstream", r#""hosted""#);
        let p = Profile::parse(hosted.as_bytes()).unwrap();
        assert!(p.hosted());
        assert_eq!(p.pricing(), None);
        let local = Profile::parse(GOOD.as_bytes()).unwrap();
        assert_ne!(p.content_sha256(), local.content_sha256());

        let mut o: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&hosted).unwrap();
        o.insert(
            "price_table".into(),
            serde_json::json!({"in_micro_per_ktok": 3000, "out_micro_per_ktok": 15000}),
        );
        let priced = Profile::parse(serde_json::Value::Object(o).to_string().as_bytes()).unwrap();
        assert!(priced.hosted());
        assert_eq!(
            priced.pricing(),
            Some(harness_core::Pricing {
                input_micros_per_token: 3,
                output_micros_per_token: 15,
            })
        );
        assert_ne!(priced.content_sha256(), p.content_sha256());
    }

    // P-31, fail closed: the declaration only means one thing.
    #[test]
    fn hosted_declarations_fail_closed() {
        // A price table prices a hosted provider; without the declaration
        // it is refused.
        let table = r#"{"in_micro_per_ktok":1,"out_micro_per_ktok":1}"#;
        assert!(matches!(
            Profile::parse(with("price_table", table).as_bytes()),
            Err(ProfileError::NotInThisBuild {
                field: "price_table",
                ..
            })
        ));
        // Explicit nulls are not absence.
        for k in ["upstream", "price_table"] {
            assert!(
                matches!(
                    Profile::parse(with(k, "null").as_bytes()),
                    Err(ProfileError::Shape(_))
                ),
                "{k}"
            );
        }
        // Only `hosted` is an upstream; anything else is a shape error
        // (an unknown variant), never silently local.
        for v in ["\"regional\"", "\"\"", "1"] {
            assert!(
                matches!(
                    Profile::parse(with("upstream", v).as_bytes()),
                    Err(ProfileError::Shape(_))
                ),
                "{v}"
            );
        }
        // The table itself is strict.
        for t in [
            r#"{"in_micro_per_ktok":1}"#,
            r#"{"in_micro_per_ktok":1,"out_micro_per_ktok":1,"surprise":0}"#,
        ] {
            let mut o: serde_json::Map<String, serde_json::Value> =
                serde_json::from_str(&with("upstream", r#""hosted""#)).unwrap();
            o.insert("price_table".into(), serde_json::from_str(t).unwrap());
            assert!(
                matches!(
                    Profile::parse(serde_json::Value::Object(o).to_string().as_bytes()),
                    Err(ProfileError::Shape(_))
                ),
                "{t}"
            );
        }
    }

    #[test]
    fn bad_profiles_are_refused() {
        let dup = GOOD.replacen("\"id\":\"qwen-7b-q4\"", "\"id\":\"a\",\"id\":\"b\"", 1);
        assert!(matches!(
            Profile::parse(dup.as_bytes()),
            Err(ProfileError::Shape(_))
        ));
        for (k, v) in [("surprise", "1"), ("protocol", "\"xml\"")] {
            assert!(
                matches!(
                    Profile::parse(with(k, v).as_bytes()),
                    Err(ProfileError::Shape(_))
                ),
                "{k}"
            );
        }
        for (k, v) in [
            ("profile_version", "2"),
            ("id", "\"a b\""),
            ("model", "\"\""),
            ("context_window", "100"),
            ("fill_ratio", "0"),
            ("fill_ratio", "1.5"),
            ("max_active_tools", "9"),
            ("max_active_tools", "4"),
            ("recent_turns", "0"),
            (
                "sampling",
                r#"{"temperature":3,"top_p":0.9,"max_tokens":10}"#,
            ),
            (
                "sampling",
                r#"{"temperature":0.2,"top_p":0,"max_tokens":10}"#,
            ),
            (
                "sampling",
                r#"{"temperature":0.2,"top_p":0.9,"max_tokens":40000}"#,
            ),
            ("kv_quant_note", "\"a\\nb\""),
            (
                "validated",
                r#"{"report_sha256":"nope","stamp_sha256":"nope"}"#,
            ),
        ] {
            assert!(
                matches!(
                    Profile::parse(with(k, v).as_bytes()),
                    Err(ProfileError::Field(_))
                ),
                "{k}={v}"
            );
        }
        let native_tc = with("tool_choice_required_ok", "true");
        assert_eq!(
            Profile::parse(native_tc.as_bytes()),
            Err(ProfileError::Field("tool_choice_required_ok"))
        );
        let text_ptc = with("parallel_tool_calls_false_ok", "true");
        assert_eq!(
            Profile::parse(text_ptc.as_bytes()),
            Err(ProfileError::Field("parallel_tool_calls_false_ok"))
        );
        // P-53: parallel calls are a native-protocol shape, and they
        // contradict the flag that asks the server for one call per reply.
        let text_pc = with("parallel_tool_calls", "true");
        assert_eq!(
            Profile::parse(text_pc.as_bytes()),
            Err(ProfileError::Field("parallel_tool_calls"))
        );
        let both = {
            let mut o: serde_json::Map<String, serde_json::Value> =
                serde_json::from_str(&with("protocol", "\"native\"")).unwrap();
            o.insert("parallel_tool_calls".into(), true.into());
            o.insert("parallel_tool_calls_false_ok".into(), true.into());
            serde_json::Value::Object(o).to_string()
        };
        assert_eq!(
            Profile::parse(both.as_bytes()),
            Err(ProfileError::Field("parallel_tool_calls"))
        );
        for v in ["null", "\"yes\"", "1"] {
            assert!(
                matches!(
                    Profile::parse(with("parallel_tool_calls", v).as_bytes()),
                    Err(ProfileError::Shape(_))
                ),
                "{v}"
            );
        }
        for v in ["null", "\"yes\"", "1"] {
            assert!(
                matches!(
                    Profile::parse(with("parallel_tool_calls_false_ok", v).as_bytes()),
                    Err(ProfileError::Shape(_))
                ),
                "{v}"
            );
        }
        for (k, v) in [("grammar", "\"gbnf_lazy\""), ("price", r#"{"input":1}"#)] {
            assert!(
                matches!(
                    Profile::parse(with(k, v).as_bytes()),
                    Err(ProfileError::NotInThisBuild { .. })
                ),
                "{k}"
            );
        }
    }

    fn stamp_json(st: &Stamp) -> String {
        format!(
            r#"{{"report_sha256":"{}","stamp_sha256":"{}"}}"#,
            st.report_sha256, st.stamp_sha256
        )
    }

    // H1d review F-5: the stamp is bound to the profile's content.
    #[test]
    fn a_stamp_validates_only_the_content_it_was_made_for() {
        let p = Profile::parse(GOOD.as_bytes()).unwrap();
        let st = p.stamp_for(&sha256(b"report"));
        let stamped = Profile::parse(with("validated", &stamp_json(&st)).as_bytes()).unwrap();
        assert!(stamped.validated());
        assert_eq!(stamped.stamp_sha256(), Some(st.stamp_sha256.as_str()));
        assert_eq!(
            stamped.content_sha256(),
            p.content_sha256(),
            "the stamp is not content"
        );

        // Edited after profile check: a different model, protocol or sampling.
        let mut o: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&with("validated", &stamp_json(&st))).unwrap();
        o.insert("model".into(), serde_json::json!("another-model"));
        let edited = Profile::parse(serde_json::Value::Object(o).to_string().as_bytes()).unwrap();
        assert!(!edited.validated(), "an edited profile is unvalidated");
        assert_eq!(edited.stamp_sha256(), None);

        // A made-up stamp (any 64 hex digits) validates nothing.
        let fake = r#"{"report_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","stamp_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}"#;
        assert!(!Profile::parse(with("validated", fake).as_bytes())
            .unwrap()
            .validated());
        // Neither does a stamp copied from another profile.
        let other = Profile::conservative_default("m").stamp_for(&sha256(b"report"));
        assert!(
            !Profile::parse(with("validated", &stamp_json(&other)).as_bytes())
                .unwrap()
                .validated()
        );
    }

    // H1h: the optional flag. Off by default; a profile without it (every
    // profile written before it) keeps the content digest it had at the
    // H1g exit build (`05e91dc`), so its stamp stays valid; on, it is part
    // of the content.
    #[test]
    fn parallel_tool_calls_false_ok_is_optional_and_off_by_default() {
        const GOOD_CONTENT: &str =
            "b8bf6a5e7b6c3f107548dc8cb096d84b2900f8e0846e474845521be5f8fcfb6f";
        const DEFAULT_CONTENT: &str =
            "d6b9b8ef0476910c516913f9edd2adfb5c8d91798e629f2403906c69141ba6cb";
        let p = Profile::parse(GOOD.as_bytes()).unwrap();
        assert!(!p.parallel_tool_calls_false_ok());
        assert_eq!(p.content_sha256().to_string(), GOOD_CONTENT);
        let d = Profile::conservative_default("m");
        assert!(!d.parallel_tool_calls_false_ok());
        assert_eq!(d.content_sha256().to_string(), DEFAULT_CONTENT);

        let native = with("protocol", "\"native\"");
        let off = Profile::parse(native.as_bytes()).unwrap();
        let explicit_off = {
            let mut o: serde_json::Map<String, serde_json::Value> =
                serde_json::from_str(&native).unwrap();
            o.insert("parallel_tool_calls_false_ok".into(), false.into());
            Profile::parse(serde_json::Value::Object(o).to_string().as_bytes()).unwrap()
        };
        let on = {
            let mut o: serde_json::Map<String, serde_json::Value> =
                serde_json::from_str(&native).unwrap();
            o.insert("parallel_tool_calls_false_ok".into(), true.into());
            Profile::parse(serde_json::Value::Object(o).to_string().as_bytes()).unwrap()
        };
        assert!(on.parallel_tool_calls_false_ok());
        assert_eq!(off.content_sha256(), explicit_off.content_sha256());
        assert_ne!(off.content_sha256(), on.content_sha256());
        // A stamp made without the flag does not validate the profile with it.
        let st = off.stamp_for(&sha256(b"report"));
        let mut o: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&native).unwrap();
        o.insert("parallel_tool_calls_false_ok".into(), true.into());
        o.insert(
            "validated".into(),
            serde_json::from_str(&stamp_json(&st)).unwrap(),
        );
        let stamped = Profile::parse(serde_json::Value::Object(o).to_string().as_bytes()).unwrap();
        assert!(!stamped.validated());
    }

    // H1i: `stream_include_usage_ok`, optional and off by default like the
    // H1h flag: every existing profile keeps the digest pinned above (the
    // same constants), explicit `false` equals absent, `true` is content;
    // either protocol may set it.
    #[test]
    fn stream_include_usage_ok_is_optional_and_off_by_default() {
        let p = Profile::parse(GOOD.as_bytes()).unwrap();
        assert!(!p.stream_include_usage_ok());
        assert!(!Profile::conservative_default("m").stream_include_usage_ok());
        assert_eq!(
            p.content_sha256().to_string(),
            "b8bf6a5e7b6c3f107548dc8cb096d84b2900f8e0846e474845521be5f8fcfb6f"
        );
        let off = Profile::parse(with("stream_include_usage_ok", "false").as_bytes()).unwrap();
        assert_eq!(off.content_sha256(), p.content_sha256());
        for protocol in ["\"text\"", "\"native\""] {
            let mut o: serde_json::Map<String, serde_json::Value> =
                serde_json::from_str(&with("protocol", protocol)).unwrap();
            o.insert("stream_include_usage_ok".into(), true.into());
            let on = Profile::parse(serde_json::Value::Object(o).to_string().as_bytes()).unwrap();
            assert!(on.stream_include_usage_ok());
            assert_ne!(
                on.content_sha256(),
                Profile::parse(with("protocol", protocol).as_bytes())
                    .unwrap()
                    .content_sha256()
            );
        }
        for v in ["null", "\"yes\"", "1"] {
            assert!(
                matches!(
                    Profile::parse(with("stream_include_usage_ok", v).as_bytes()),
                    Err(ProfileError::Shape(_))
                ),
                "{v}"
            );
        }
    }

    // H2f: the model read timeout. Optional, off by default (a profile
    // without it keeps the digest pinned in the read-window test and its
    // stamp); set, it is content. 5 to 600 seconds.
    #[test]
    fn read_timeout_secs_is_optional_bounded_and_content_when_set() {
        let p = Profile::parse(GOOD.as_bytes()).unwrap();
        assert_eq!(p.read_timeout(), None);
        assert_eq!(Profile::conservative_default("m").read_timeout(), None);
        let t = Profile::parse(with("read_timeout_secs", "240").as_bytes()).unwrap();
        assert_eq!(t.read_timeout(), Some(std::time::Duration::from_secs(240)));
        assert_ne!(t.content_sha256(), p.content_sha256());
        assert_eq!(
            Profile::parse(with("read_timeout_secs", "5").as_bytes())
                .unwrap()
                .read_timeout(),
            Some(std::time::Duration::from_secs(5))
        );
        assert!(Profile::parse(with("read_timeout_secs", "600").as_bytes()).is_ok());
        for v in ["4", "601", "0"] {
            assert!(
                matches!(
                    Profile::parse(with("read_timeout_secs", v).as_bytes()),
                    Err(ProfileError::Field("read_timeout_secs"))
                ),
                "{v}"
            );
        }
        for v in ["null", "\"60\"", "-1", "1.5"] {
            assert!(
                matches!(
                    Profile::parse(with("read_timeout_secs", v).as_bytes()),
                    Err(ProfileError::Shape(_))
                ),
                "{v}"
            );
        }
    }

    // H2e: the read window. Optional, off by default, and a profile without
    // it keeps the digest pinned above (and its stamp); set, it is content.
    // Its range is 10 to 2000 lines, and its lines at 64 bytes each must fit
    // in half the context budget.
    #[test]
    fn max_read_lines_is_optional_and_bounded_by_the_context_budget() {
        let p = Profile::parse(GOOD.as_bytes()).unwrap();
        assert_eq!(
            p.read_window(),
            ReadWindow {
                lines: 100,
                bytes: 16 * 1024
            }
        );
        assert_eq!(
            p.content_sha256().to_string(),
            "b8bf6a5e7b6c3f107548dc8cb096d84b2900f8e0846e474845521be5f8fcfb6f"
        );
        assert_eq!(
            Profile::conservative_default("m").read_window(),
            ReadWindow::of_lines(100)
        );
        // GOOD: 32768 × 0.6 = 19660 tokens; half is 9830, so at most
        // 9830 × 3 / 64 = 460 lines.
        let w = Profile::parse(with("max_read_lines", "400").as_bytes()).unwrap();
        assert_eq!(
            w.read_window(),
            ReadWindow {
                lines: 400,
                bytes: 400 * 64
            }
        );
        assert_ne!(w.content_sha256(), p.content_sha256());
        let explicit = Profile::parse(with("max_read_lines", "100").as_bytes()).unwrap();
        assert_ne!(
            explicit.content_sha256(),
            p.content_sha256(),
            "set is content, even to the default"
        );
        assert_eq!(explicit.read_window(), p.read_window());
        assert!(Profile::parse(with("max_read_lines", "460").as_bytes()).is_ok());
        assert!(matches!(
            Profile::parse(with("max_read_lines", "461").as_bytes()),
            Err(ProfileError::ReadWindow {
                lines: 461,
                budget: 19660,
                ..
            })
        ));
        for v in ["9", "2001", "0"] {
            assert!(
                matches!(
                    Profile::parse(with("max_read_lines", v).as_bytes()),
                    Err(ProfileError::Field("max_read_lines"))
                ),
                "{v}"
            );
        }
        for v in ["null", "\"400\"", "-1", "1.5"] {
            assert!(
                matches!(
                    Profile::parse(with("max_read_lines", v).as_bytes()),
                    Err(ProfileError::Shape(_))
                ),
                "{v}"
            );
        }
        // A big window on a big context: the bytes stop at the result cap.
        let mut o: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&with("context_window", "131072")).unwrap();
        o.insert("max_read_lines".into(), 2000.into());
        let big = Profile::parse(serde_json::Value::Object(o).to_string().as_bytes());
        // 131072 × 0.6 = 78643 tokens; 2000 lines need 42667, over half.
        assert!(matches!(big, Err(ProfileError::ReadWindow { .. })));
        let mut o: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&with("context_window", "131072")).unwrap();
        o.insert("max_read_lines".into(), 1800.into());
        let big = Profile::parse(serde_json::Value::Object(o).to_string().as_bytes()).unwrap();
        assert_eq!(
            big.read_window(),
            ReadWindow {
                lines: 1800,
                bytes: 64 * 1024
            }
        );
        assert_eq!(ReadWindow::of_lines(5).lines, READ_WINDOW_MIN_LINES);
        assert_eq!(ReadWindow::of_lines(9999).lines, READ_WINDOW_MAX_LINES);
    }

    // P-53: the tool docs. Full by default, so every profile written
    // before P-53 keeps the digest pinned above (and its stamp); terse is
    // content, round-trips through parse, agrees with the builder `profile
    // init` uses, and a stamp made for full content does not validate a
    // terse profile.
    #[test]
    fn profile_stamp_changes_with_tool_docs() {
        const GOOD_CONTENT: &str =
            "b8bf6a5e7b6c3f107548dc8cb096d84b2900f8e0846e474845521be5f8fcfb6f";
        let p = Profile::parse(GOOD.as_bytes()).unwrap();
        assert_eq!(p.tool_docs(), ToolDocs::Full);
        assert_eq!(p.content_sha256().to_string(), GOOD_CONTENT);
        assert_eq!(
            Profile::conservative_default("m").tool_docs(),
            ToolDocs::Full
        );

        // Terse is content; an explicit "full" is the absent default.
        let terse_json = with("tool_docs", "\"terse\"");
        let terse = Profile::parse(terse_json.as_bytes()).unwrap();
        assert_eq!(terse.tool_docs(), ToolDocs::Terse);
        assert_ne!(terse.content_sha256(), p.content_sha256());
        assert_eq!(
            Profile::parse(with("tool_docs", "\"full\"").as_bytes())
                .unwrap()
                .content_sha256(),
            p.content_sha256()
        );
        // The builder `profile init` uses agrees with the parsed file, and
        // setting Full changes nothing.
        assert_eq!(
            p.clone().with_tool_docs(ToolDocs::Terse).content_sha256(),
            terse.content_sha256()
        );
        assert_eq!(
            p.clone().with_tool_docs(ToolDocs::Full).content_sha256(),
            p.content_sha256()
        );
        // A stamp made without terse does not validate the terse profile.
        let st = p.stamp_for(&sha256(b"report"));
        let mut o: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&terse_json).unwrap();
        o.insert(
            "validated".into(),
            serde_json::from_str(&stamp_json(&st)).unwrap(),
        );
        let stamped = Profile::parse(serde_json::Value::Object(o).to_string().as_bytes()).unwrap();
        assert!(!stamped.validated());
        assert_eq!(stamped.stamp_sha256(), None);
        for v in ["null", "\"short\"", "1"] {
            assert!(
                matches!(
                    Profile::parse(with("tool_docs", v).as_bytes()),
                    Err(ProfileError::Shape(_))
                ),
                "{v}"
            );
        }
    }

    #[test]
    fn smoke_scoring_is_strict() {
        let p = Profile::conservative_default("m");
        let r = |cases, valid, fe, fail| SmokeResults {
            cases,
            valid_tool_calls: valid,
            format_errors: fe,
            call_failures: fail,
        };
        assert!(matches!(score(&p, &r(5, 5, 0, 0)), CheckResult::Stamp(_)));
        assert!(matches!(score(&p, &r(5, 4, 1, 0)), CheckResult::Stamp(_)));
        assert!(matches!(score(&p, &r(4, 4, 0, 0)), CheckResult::NoStamp(_)));
        assert!(matches!(score(&p, &r(5, 3, 2, 0)), CheckResult::NoStamp(_)));
        assert!(matches!(score(&p, &r(5, 5, 0, 1)), CheckResult::NoStamp(_)));
        // Deterministic stamp.
        assert_eq!(score(&p, &r(5, 5, 0, 0)), score(&p, &r(5, 5, 0, 0)));
    }
}
