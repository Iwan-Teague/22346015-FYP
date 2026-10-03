//! The usage/cost footer (slice P-15): counts computed from a verified
//! attempt journal — steps, model calls, token totals and wall time, and
//! per-tool call counts. Nothing here is a bill: the token counts are what
//! the server reported per reply (`ModelReplied.usage`), and the cached
//! total is the server's own further claim (`claimed_stats`, an untrusted
//! payload), shown only when some reply claimed one.

use std::collections::BTreeMap;

use harness_journal::canon::{unescape, EventKind};
use harness_journal::Verified;
use serde_json::{Map, Value};

pub(crate) struct Usage {
    steps: u64,
    model_calls: u64,
    tokens_in: u64,
    tokens_out: u64,
    /// Sum of the servers' cached-token claims, when any reply made one.
    tokens_cached: Option<u64>,
    wall_ms: u64,
    /// Tool calls started, by capability id.
    tools: BTreeMap<String, u64>,
}

impl Usage {
    /// Compute the footer from a verified journal. Display only: no
    /// decision reads these numbers, so an unparseable `claimed_stats`
    /// merely drops out of the cached claim (fail-open for display,
    /// fail-closed elsewhere).
    pub(crate) fn from_journal(v: &Verified) -> Self {
        let mut u = Self {
            steps: 0,
            model_calls: 0,
            tokens_in: 0,
            tokens_out: 0,
            tokens_cached: None,
            wall_ms: 0,
            tools: BTreeMap::new(),
        };
        for r in &v.records {
            u.steps = u.steps.max(r.step);
            match r.kind {
                EventKind::ModelRequested => u.model_calls += 1,
                EventKind::ModelReplied => {
                    if let Some(n) = u64_at(&r.body, &["usage", "input"]) {
                        u.tokens_in += n;
                    }
                    if let Some(n) = u64_at(&r.body, &["usage", "output"]) {
                        u.tokens_out += n;
                    }
                    if let Some(c) = claimed_cached(r) {
                        *u.tokens_cached.get_or_insert(0) += c;
                    }
                }
                EventKind::ToolStarted => {
                    if let Some(cap) = r.body.get("capability").and_then(Value::as_str) {
                        *u.tools.entry(cap.to_owned()).or_insert(0) += 1;
                    }
                }
                _ => {}
            }
        }
        if let (Some(first), Some(last)) = (v.records.first(), v.records.last()) {
            u.wall_ms = last.t_mono_ms.saturating_sub(first.t_mono_ms);
        }
        u
    }

    /// The counts, for a report that lists an arm's facts (P-48 `compare`):
    /// the same numbers the footer words say, without the words. (`steps`
    /// is not here: the run report's own count is the fact.)
    pub(crate) fn tokens_in(&self) -> u64 {
        self.tokens_in
    }

    pub(crate) fn tokens_out(&self) -> u64 {
        self.tokens_out
    }

    pub(crate) fn wall_ms(&self) -> u64 {
        self.wall_ms
    }

    pub(crate) fn tools(&self) -> &BTreeMap<String, u64> {
        &self.tools
    }

    /// The footer as one compact JSON object, e.g.
    /// `{"model_calls":2,"steps":3,"tokens":{"cached":64,"in":200,"out":20},"tools":{"harness.fs.read":1},"wall_ms":150}`.
    /// (`cached` appears only when some reply claimed cached tokens; keys
    /// sorted, as every JSON object this harness writes.)
    pub(crate) fn to_json(&self) -> Value {
        let mut tokens = Map::new();
        tokens.insert("in".into(), Value::from(self.tokens_in));
        tokens.insert("out".into(), Value::from(self.tokens_out));
        if let Some(c) = self.tokens_cached {
            tokens.insert("cached".into(), Value::from(c));
        }
        let mut m = Map::new();
        m.insert("model_calls".into(), Value::from(self.model_calls));
        m.insert("steps".into(), Value::from(self.steps));
        m.insert("tokens".into(), Value::Object(tokens));
        m.insert(
            "tools".into(),
            Value::Object(
                self.tools
                    .iter()
                    .map(|(k, n)| (k.clone(), Value::from(*n)))
                    .collect(),
            ),
        );
        m.insert("wall_ms".into(), Value::from(self.wall_ms));
        Value::Object(m)
    }

    /// The footer in words, for the person at the terminal.
    pub(crate) fn in_words(&self) -> String {
        let cached = match self.tokens_cached {
            Some(c) => format!(" (cached {c}, server-claimed)"),
            None => String::new(),
        };
        let tools = if self.tools.is_empty() {
            "none".to_owned()
        } else {
            self.tools
                .iter()
                .map(|(k, n)| format!("{k} {n}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        format!(
            "usage: {} step(s), {} model call(s), tokens in {} out {}{cached}, wall {} ms, tool call(s): {tools}",
            self.steps, self.model_calls, self.tokens_in, self.tokens_out, self.wall_ms
        )
    }
}

/// Walk `path` into `body`; the number at the end, if there is one.
fn u64_at(body: &Map<String, Value>, path: &[&str]) -> Option<u64> {
    let mut cur = body.get(*path.first()?)?;
    for k in path.get(1..).unwrap_or_default() {
        cur = cur.get(*k)?;
    }
    cur.as_u64()
}

/// The cached-token claim in one `ModelReplied`'s `claimed_stats` payload
/// home: the untrusted inline text (claimed_stats is small, always inline;
/// a blob-carried one adds nothing) parsed strictly, read for OpenAI's
/// `usage.prompt_tokens_details.cached_tokens` or llama.cpp's
/// `timings.cache_n`. `None` when there is no claim or it does not parse:
/// it is the server's claim about its own account, not a harness
/// measurement.
fn claimed_cached(r: &harness_journal::Record) -> Option<u64> {
    let home = r.body.get("claimed_stats")?;
    if home.get("untrusted") != Some(&Value::Bool(true)) {
        return None;
    }
    let text = unescape(home.get("inline").and_then(Value::as_str)?)?;
    let v: Value = serde_json::from_str(&text).ok()?;
    v.pointer("/prompt_tokens_details/cached_tokens")
        .and_then(Value::as_u64)
        .or_else(|| v.pointer("/timings/cache_n").and_then(Value::as_u64))
}
