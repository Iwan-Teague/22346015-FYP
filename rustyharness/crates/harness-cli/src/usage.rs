//! The usage/cost footer (slice P-15): counts computed from a verified
//! attempt journal — steps, model calls, token totals and wall time, and
//! per-tool call counts. Nothing here is a bill: the token counts are what
//! the server reported per reply (`ModelReplied.usage`), and the cached
//! total is the server's own further claim (`claimed_stats`, an untrusted
//! payload), shown only when some reply claimed one. Helper runs a parent
//! delegated (P-38g) show as their own `helpers` sums, read from each
//! `ChildRun`'s `spent` (the meter's per-child measurement, which may be
//! partly server-estimated — flagged, never hidden).

use std::collections::BTreeMap;

use harness_journal::canon::{unescape, EventKind};
use harness_journal::Verified;
use serde_json::{Map, Value};

/// What the run's helpers spent, summed over the parent's `ChildRun`
/// records (P-38g). Shown beside the parent's totals, not folded into
/// them: the parent's token numbers stay "what the server reported per
/// reply", and the helpers' numbers carry their own estimated flag.
#[derive(Default)]
struct Helpers {
    runs: u64,
    steps: u64,
    tokens_in: u64,
    tokens_out: u64,
    wall_ms: u64,
    /// Any child's meter had to estimate a server that reported nothing.
    estimated: bool,
}

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
    /// What the reported tokens cost at the profile's price table (P-31),
    /// in micro-USD. `None` without pricing (a local model costs nothing,
    /// §2.4) and only from the tokens the servers reported: replies
    /// without a usage report are estimated by the meter for the budget
    /// but contribute nothing here (the footer claims no estimate).
    cost_micros: Option<u64>,
    /// The delegated helpers' own spend (P-38g).
    helpers: Helpers,
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
            cost_micros: None,
            helpers: Helpers::default(),
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
                EventKind::ChildRun => {
                    u.helpers.runs += 1;
                    if let Some(n) = u64_at(&r.body, &["spent", "steps"]) {
                        u.helpers.steps += n;
                    }
                    if let Some(n) = u64_at(&r.body, &["spent", "tokens_in"]) {
                        u.helpers.tokens_in += n;
                    }
                    if let Some(n) = u64_at(&r.body, &["spent", "tokens_out"]) {
                        u.helpers.tokens_out += n;
                    }
                    if let Some(n) = u64_at(&r.body, &["spent", "wall_ms"]) {
                        u.helpers.wall_ms += n;
                    }
                    if r.body
                        .get("spent")
                        .and_then(|s| s.get("estimated"))
                        .and_then(Value::as_bool)
                        == Some(true)
                    {
                        u.helpers.estimated = true;
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

    /// Price the reported tokens at the profile's price table (P-31):
    /// micro-USD per token, saturating, the same derivation the meter's
    /// `Cost` budget charges with. No pricing, no cost in the footer.
    pub(crate) fn priced(mut self, pricing: Option<harness_core::Pricing>) -> Self {
        if let Some(p) = pricing {
            self.cost_micros = Some(
                self.tokens_in
                    .saturating_mul(p.input_micros_per_token)
                    .saturating_add(self.tokens_out.saturating_mul(p.output_micros_per_token)),
            );
        }
        self
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
        if self.helpers.runs > 0 {
            let mut tokens = Map::new();
            tokens.insert("in".into(), Value::from(self.helpers.tokens_in));
            tokens.insert("out".into(), Value::from(self.helpers.tokens_out));
            let mut h = Map::new();
            h.insert("runs".into(), Value::from(self.helpers.runs));
            h.insert("steps".into(), Value::from(self.helpers.steps));
            h.insert("tokens".into(), Value::Object(tokens));
            h.insert("wall_ms".into(), Value::from(self.helpers.wall_ms));
            if self.helpers.estimated {
                h.insert("estimated".into(), Value::Bool(true));
            }
            m.insert("helpers".into(), Value::Object(h));
        }
        m.insert("model_calls".into(), Value::from(self.model_calls));
        m.insert("steps".into(), Value::from(self.steps));
        m.insert("tokens".into(), Value::Object(tokens));
        if let Some(c) = self.cost_micros {
            m.insert("cost_micros".into(), Value::from(c));
        }
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
        // P-31: the price is the profile's own table (a hosted profile's
        // `price_table`, micro-USD per kilo-token), so six decimals are
        // enough to show every whole micro-USD ($0.000001).
        let cost = match self.cost_micros {
            Some(c) => format!(", cost ${:.6}", c as f64 / 1_000_000.0),
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
        let helpers = if self.helpers.runs == 0 {
            String::new()
        } else {
            let estimated = if self.helpers.estimated {
                " (partly server-estimated)"
            } else {
                ""
            };
            format!(
                ", helpers: {} helper run(s), {} step(s), tokens in {} out {}, wall {} ms{estimated}",
                self.helpers.runs,
                self.helpers.steps,
                self.helpers.tokens_in,
                self.helpers.tokens_out,
                self.helpers.wall_ms
            )
        };
        format!(
            "usage: {} step(s), {} model call(s), tokens in {} out {}{cached}{cost}, wall {} ms, tool call(s): {tools}{helpers}",
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

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use harness_core::sha256;
    use harness_journal::Record;

    fn record(seq: u64, step: u64, kind: EventKind, body: Value) -> Record {
        Record {
            seq,
            step,
            kind,
            t_mono_ms: seq * 10,
            t_wall: "2026-01-01T00:00:00Z".to_owned(),
            body: body.as_object().cloned().unwrap_or_default(),
            hash: sha256(format!("record-{seq}").as_bytes()),
        }
    }

    // P-38g: the footer reads each helper's `ChildRun.spent` and shows
    // the sums as their own `helpers` block (words and JSON), with the
    // meter's estimated flag surfaced; the parent's own totals stay
    // theirs, and a run with no helpers shows no `helpers` key at all.
    #[test]
    fn usage_footer_includes_child_spend() {
        let journal = |records: Vec<Record>| Verified {
            records,
            torn_tail: None,
            head: sha256(b"head"),
            run: "0123456789abcdef0123456789abcdef".to_owned(),
            attempt: 1,
        };
        let parent_reply = |seq: u64, step: u64| {
            record(
                seq,
                step,
                EventKind::ModelReplied,
                serde_json::json!({"usage": {"input": 100, "output": 10}}),
            )
        };
        let child = record(
            2,
            2,
            EventKind::ChildRun,
            serde_json::json!({
                "child": "aa55aa55aa55aa55aa55aa55aa55aa55",
                "stop": "goal",
                "spent": {
                    "steps": 2,
                    "tokens_in": 110,
                    "tokens_out": 11,
                    "estimated": true,
                    "wall_ms": 50,
                },
                "wall_used_ms": 50,
            }),
        );

        let without = Usage::from_journal(&journal(vec![
            record(1, 1, EventKind::RunStarted, serde_json::json!({})),
            parent_reply(2, 1),
            record(3, 2, EventKind::RunStopped, serde_json::json!({})),
        ]));
        assert!(without.to_json().get("helpers").is_none());
        assert!(!without.in_words().contains("helpers"));

        let with = Usage::from_journal(&journal(vec![
            record(1, 1, EventKind::RunStarted, serde_json::json!({})),
            parent_reply(2, 1),
            child,
            record(
                4,
                3,
                EventKind::ModelReplied,
                serde_json::json!({
                    "usage": {"input": 90, "output": 9}
                }),
            ),
            record(5, 3, EventKind::RunStopped, serde_json::json!({})),
        ]));
        assert_eq!(with.tokens_in(), 190, "the parent's own totals stay");
        assert_eq!(
            with.to_json()["helpers"],
            serde_json::json!({
                "runs": 1,
                "steps": 2,
                "tokens": {"in": 110, "out": 11},
                "wall_ms": 50,
                "estimated": true,
            })
        );
        assert_eq!(
            with.to_json()["steps"],
            serde_json::json!(3),
            "steps stays the parent's count"
        );
        assert!(
            with.in_words().contains(
                ", helpers: 1 helper run(s), 2 step(s), tokens in 110 out 11, wall 50 ms (partly server-estimated)"
            ),
            "words: {}",
            with.in_words()
        );
    }
}
