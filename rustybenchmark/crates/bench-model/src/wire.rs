//! Parsing of what OpenAI-compatible servers actually send, tolerant of the quirks measured in
//! docs/15 §2/§10: `content: null`, a missing or partial `usage`, `reasoning_content` (llama.cpp,
//! DeepSeek-style) or `reasoning` (newer vLLM, Ollama), llama.cpp's non-standard `timings` block,
//! `prompt_tokens_details.cached_tokens`, an empty `choices` array on the trailing usage chunk of
//! a stream, and `{"error": ...}` bodies delivered with a 200 status or mid-stream.
//!
//! Everything here is pure (`&str` in, values out) so it is tested without a socket. The values
//! are taken from `serde_json::Value` by hand rather than derived structs on purpose: a derived
//! struct turns any one unexpected `null` into a hard failure of the whole unit.

use crate::ModelError;
use serde_json::Value;

/// llama.cpp's `timings` block. Present on its standard endpoint (also on the final stream chunk),
/// absent on vLLM / Ollama / LM Studio. Spoofable like every field the endpoint reports (docs/15).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ServerTimings {
    /// Prompt tokens actually evaluated (excludes `cache_n`).
    pub prompt_n: u32,
    pub prompt_ms: f64,
    pub predicted_n: u32,
    pub predicted_ms: f64,
    pub cache_n: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub cached_tokens: Option<u32>,
}

/// One response (or the final state of a stream) in endpoint-neutral form.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Parsed {
    pub text: String,
    pub reasoning: Option<String>,
    pub finish_reason: Option<String>,
    /// `None` = the endpoint reported no usage at all (do not treat zero as a measurement).
    pub usage: Option<Usage>,
    pub timings: Option<ServerTimings>,
}

fn u32_of(v: &Value) -> Option<u32> {
    v.as_u64().and_then(|n| u32::try_from(n).ok())
}

fn finite_nonneg(v: &Value) -> Option<f64> {
    v.as_f64().filter(|x| x.is_finite() && *x >= 0.0)
}

/// `content` may be a string, `null`, or (rarely) an array of `{type:"text", text}` parts.
fn text_of(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|p| p.get("text").and_then(Value::as_str))
            .collect(),
        _ => String::new(),
    }
}

fn reasoning_of(obj: &Value) -> Option<String> {
    for key in ["reasoning_content", "reasoning"] {
        if let Some(s) = obj.get(key).and_then(Value::as_str) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

pub fn parse_usage(v: &Value) -> Option<Usage> {
    let u = v.get("usage").filter(|u| u.is_object())?;
    let prompt = u.get("prompt_tokens").and_then(u32_of);
    let completion = u.get("completion_tokens").and_then(u32_of);
    if prompt.is_none() && completion.is_none() {
        return None;
    }
    let cached = u
        .get("prompt_tokens_details")
        .and_then(|d| d.get("cached_tokens"))
        .and_then(u32_of);
    Some(Usage {
        prompt_tokens: prompt.unwrap_or(0),
        completion_tokens: completion.unwrap_or(0),
        cached_tokens: cached,
    })
}

pub fn parse_timings(v: &Value) -> Option<ServerTimings> {
    let t = v.get("timings").filter(|t| t.is_object())?;
    let predicted_ms = finite_nonneg(t.get("predicted_ms")?)?;
    let prompt_ms = finite_nonneg(t.get("prompt_ms")?)?;
    Some(ServerTimings {
        prompt_n: t.get("prompt_n").and_then(u32_of)?,
        prompt_ms,
        predicted_n: t.get("predicted_n").and_then(u32_of)?,
        predicted_ms,
        cache_n: t.get("cache_n").and_then(u32_of).unwrap_or(0),
    })
}

/// A body that is an error object. Servers send these with 4xx/5xx, but also with 200 (LM Studio
/// model-load failures) and as a stream event.
pub fn api_error(v: &Value) -> Option<ModelError> {
    let e = v.get("error")?;
    let msg = match e {
        Value::String(s) => s.clone(),
        Value::Object(_) => e
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("error object without message")
            .to_string(),
        _ => return None,
    };
    if let Some(ctx) = context_exceeded(v) {
        return Some(ctx);
    }
    Some(ModelError::Api {
        message: clip(&msg, 500),
    })
}

/// llama.cpp fails *loudly* on an over-long prompt: `{"error":{"type":"exceed_context_size_error",
/// "n_prompt_tokens":5583,"n_ctx":4096,...}}` (docs/05, measured). Ollama truncates silently and
/// never produces this; the context probe (docs/05) is what catches that.
pub fn context_exceeded(v: &Value) -> Option<ModelError> {
    let e = v.get("error")?;
    let ty = e.get("type").and_then(Value::as_str).unwrap_or("");
    let code = e.get("code").and_then(Value::as_str).unwrap_or("");
    let msg = e.get("message").and_then(Value::as_str).unwrap_or("");
    if ty == "exceed_context_size_error"
        || code == "context_length_exceeded"
        || msg.contains("maximum context length")
    {
        return Some(ModelError::ContextExceeded {
            n_prompt_tokens: e.get("n_prompt_tokens").and_then(Value::as_u64),
            n_ctx: e.get("n_ctx").and_then(Value::as_u64),
        });
    }
    None
}

pub fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push_str("...");
        t
    }
}

/// Parse a complete (non-streaming) response body.
pub fn parse_response(body: &str) -> Result<Parsed, ModelError> {
    let v: Value = serde_json::from_str(body).map_err(|e| {
        ModelError::Malformed(format!("response is not JSON ({})", e.classify_name()))
    })?;
    if let Some(e) = api_error(&v) {
        return Err(e);
    }
    let first = v
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .ok_or(ModelError::NoChoices)?;
    let msg = first.get("message");
    Ok(Parsed {
        text: text_of(msg.and_then(|m| m.get("content"))),
        reasoning: msg.and_then(reasoning_of),
        finish_reason: first
            .get("finish_reason")
            .and_then(Value::as_str)
            .map(str::to_string),
        usage: parse_usage(&v),
        timings: parse_timings(&v),
    })
}

trait ClassifyName {
    fn classify_name(&self) -> &'static str;
}
impl ClassifyName for serde_json::Error {
    fn classify_name(&self) -> &'static str {
        use serde_json::error::Category::*;
        match self.classify() {
            Io => "io",
            Syntax => "syntax",
            Data => "data",
            Eof => "unexpected end",
        }
    }
}

/// Incremental state of a streamed response. Feed it one SSE `data` payload at a time together
/// with a monotonic millisecond clock reading; it records *when* the first and last tokens
/// arrived, which is the only prefill/decode split the OpenAI surface permits on most backends.
#[derive(Clone, Debug, Default)]
pub struct StreamAccumulator {
    pub text: String,
    pub reasoning: String,
    pub finish_reason: Option<String>,
    pub usage: Option<Usage>,
    pub timings: Option<ServerTimings>,
    /// Client clock (ms since request start) at the first non-empty content or reasoning delta.
    pub first_token_ms: Option<f64>,
    pub last_token_ms: Option<f64>,
    /// Non-empty deltas received. One delta is *usually* one token on llama.cpp but nothing
    /// guarantees it, so this is only ever a fallback token count, and is labelled as one.
    pub delta_chunks: u32,
    pub done: bool,
}

impl StreamAccumulator {
    /// Returns `Ok(true)` when the stream is finished (`[DONE]`).
    pub fn feed(&mut self, data: &str, now_ms: f64) -> Result<bool, ModelError> {
        let data = data.trim();
        if data == "[DONE]" {
            self.done = true;
            return Ok(true);
        }
        if data.is_empty() {
            return Ok(false);
        }
        let v: Value = serde_json::from_str(data).map_err(|e| {
            ModelError::Malformed(format!("stream event is not JSON ({})", e.classify_name()))
        })?;
        if let Some(e) = api_error(&v) {
            return Err(e);
        }
        // A trailing usage chunk has `choices: []` (vLLM, OpenAI with include_usage): normal.
        if let Some(c) = v
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|c| c.first())
        {
            let delta = c.get("delta");
            let content = text_of(delta.and_then(|d| d.get("content")));
            let reasoning = delta.and_then(reasoning_of).unwrap_or_default();
            if !content.is_empty() || !reasoning.is_empty() {
                if self.first_token_ms.is_none() {
                    self.first_token_ms = Some(now_ms);
                }
                self.last_token_ms = Some(now_ms);
                self.delta_chunks += 1;
                self.text.push_str(&content);
                self.reasoning.push_str(&reasoning);
            }
            if let Some(f) = c.get("finish_reason").and_then(Value::as_str) {
                self.finish_reason = Some(f.to_string());
            }
        }
        if let Some(u) = parse_usage(&v) {
            self.usage = Some(u);
        }
        if let Some(t) = parse_timings(&v) {
            self.timings = Some(t);
        }
        Ok(false)
    }

    pub fn into_parsed(self) -> Parsed {
        Parsed {
            text: self.text,
            reasoning: (!self.reasoning.is_empty()).then_some(self.reasoning),
            finish_reason: self.finish_reason,
            usage: self.usage,
            timings: self.timings,
        }
    }
}

/// Incremental SSE line reader state: collects `data:` lines until a blank line ends the event.
#[derive(Default)]
pub struct SseEvents {
    data: Vec<String>,
}

impl SseEvents {
    /// Feed one line (without its newline). Returns a complete event payload at a blank line.
    pub fn line(&mut self, line: &str) -> Option<String> {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            if self.data.is_empty() {
                return None;
            }
            let ev = self.data.join("\n");
            self.data.clear();
            return Some(ev);
        }
        if line.starts_with(':') {
            return None; // comment / keep-alive
        }
        if let Some(rest) = line.strip_prefix("data:") {
            self.data
                .push(rest.strip_prefix(' ').unwrap_or(rest).to_string());
        }
        // `event:`, `id:`, `retry:` are irrelevant to chat completions.
        None
    }

    /// At end of input, a final event not terminated by a blank line (some servers omit it).
    pub fn flush(&mut self) -> Option<String> {
        if self.data.is_empty() {
            None
        } else {
            let ev = self.data.join("\n");
            self.data.clear();
            Some(ev)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_null_with_reasoning_content_is_a_normal_reasoning_reply() {
        let p = parse_response(
            r#"{"choices":[{"message":{"role":"assistant","content":null,"reasoning_content":"hmm"},"finish_reason":"length"}],
                "usage":{"prompt_tokens":5,"completion_tokens":100}}"#,
        )
        .unwrap();
        assert_eq!(p.text, "");
        assert_eq!(p.reasoning.as_deref(), Some("hmm"));
        assert_eq!(p.finish_reason.as_deref(), Some("length"));
    }

    #[test]
    fn vllm_style_reasoning_key_and_part_array_content() {
        let p = parse_response(
            r#"{"choices":[{"message":{"content":[{"type":"text","text":"a"},{"type":"text","text":"b"}],"reasoning":"why"},"finish_reason":"stop"}]}"#,
        )
        .unwrap();
        assert_eq!(p.text, "ab");
        assert_eq!(p.reasoning.as_deref(), Some("why"));
        assert!(p.usage.is_none(), "no usage object = unreported, not zero");
    }

    #[test]
    fn usage_cached_tokens_and_partial_usage() {
        let p = parse_response(
            r#"{"choices":[{"message":{"content":"x"}}],
                "usage":{"prompt_tokens":10,"prompt_tokens_details":{"cached_tokens":4}}}"#,
        )
        .unwrap();
        let u = p.usage.unwrap();
        assert_eq!(
            (u.prompt_tokens, u.completion_tokens, u.cached_tokens),
            (10, 0, Some(4))
        );
        // `usage: {}` and `usage: null` are both "not reported".
        for body in [
            r#"{"choices":[{"message":{"content":"x"}}],"usage":{}}"#,
            r#"{"choices":[{"message":{"content":"x"}}],"usage":null}"#,
        ] {
            assert!(parse_response(body).unwrap().usage.is_none());
        }
    }

    #[test]
    fn llama_cpp_timings_parse_and_garbage_is_ignored() {
        let p = parse_response(
            r#"{"choices":[{"message":{"content":"x"}}],
                "timings":{"cache_n":3,"prompt_n":40,"prompt_ms":80.0,"predicted_n":20,"predicted_ms":400.0}}"#,
        )
        .unwrap();
        let t = p.timings.unwrap();
        assert_eq!((t.cache_n, t.prompt_n, t.predicted_n), (3, 40, 20));
        for bad in [
            r#""timings":{"prompt_n":1,"prompt_ms":-1.0,"predicted_n":1,"predicted_ms":1.0}"#,
            r#""timings":{"prompt_n":1}"#,
            r#""timings":"fast""#,
        ] {
            let body = format!(r#"{{"choices":[{{"message":{{"content":"x"}}}}],{bad}}}"#);
            assert!(parse_response(&body).unwrap().timings.is_none(), "{bad}");
        }
    }

    #[test]
    fn empty_choices_and_error_bodies() {
        assert!(matches!(
            parse_response(r#"{"choices":[]}"#),
            Err(ModelError::NoChoices)
        ));
        assert!(matches!(
            parse_response(r#"{}"#),
            Err(ModelError::NoChoices)
        ));
        assert!(matches!(
            parse_response(r#"{"error":{"message":"model not loaded"}}"#),
            Err(ModelError::Api { .. })
        ));
        assert!(matches!(
            parse_response(r#"{"error":"boom"}"#),
            Err(ModelError::Api { .. })
        ));
        assert!(matches!(
            parse_response("<html>"),
            Err(ModelError::Malformed(_))
        ));
    }

    #[test]
    fn llama_cpp_context_error_is_typed() {
        let e = parse_response(
            r#"{"error":{"code":400,"message":"the request exceeds the available context size","type":"exceed_context_size_error","n_prompt_tokens":5583,"n_ctx":4096}}"#,
        )
        .unwrap_err();
        assert!(matches!(
            e,
            ModelError::ContextExceeded {
                n_prompt_tokens: Some(5583),
                n_ctx: Some(4096)
            }
        ));
        let e = parse_response(r#"{"error":{"code":"context_length_exceeded","message":"x"}}"#)
            .unwrap_err();
        assert!(matches!(e, ModelError::ContextExceeded { .. }));
    }

    #[test]
    fn error_text_is_clipped() {
        let long = "x".repeat(5000);
        let e = parse_response(&format!(r#"{{"error":{{"message":"{long}"}}}}"#)).unwrap_err();
        assert!(e.to_string().len() < 700);
    }

    #[test]
    fn sse_framing_handles_comments_crlf_multiline_and_missing_final_blank() {
        let mut s = SseEvents::default();
        assert_eq!(s.line(": keep-alive"), None);
        assert_eq!(s.line("data: {\"a\":1}\r"), None);
        assert_eq!(s.line("\r").as_deref(), Some("{\"a\":1}"));
        assert_eq!(s.line("event: message"), None);
        assert_eq!(s.line("data:{\"b\":"), None);
        assert_eq!(s.line("data: 2}"), None);
        assert_eq!(s.line("").as_deref(), Some("{\"b\":\n2}"));
        assert_eq!(s.line("data: [DONE]"), None);
        assert_eq!(s.flush().as_deref(), Some("[DONE]"));
        assert_eq!(s.flush(), None);
    }

    #[test]
    fn accumulator_records_first_and_last_token_and_ignores_usage_only_chunks() {
        let mut a = StreamAccumulator::default();
        // role chunk: empty content must NOT count as the first token
        assert!(!a
            .feed(
                r#"{"choices":[{"delta":{"role":"assistant","content":""}}]}"#,
                5.0
            )
            .unwrap());
        assert!(a.first_token_ms.is_none());
        a.feed(
            r#"{"choices":[{"delta":{"reasoning_content":"th"}}]}"#,
            30.0,
        )
        .unwrap();
        a.feed(r#"{"choices":[{"delta":{"content":"ab"}}]}"#, 40.0)
            .unwrap();
        a.feed(
            r#"{"choices":[{"delta":{"content":"c"},"finish_reason":"stop"}]}"#,
            50.0,
        )
        .unwrap();
        a.feed(
            r#"{"choices":[],"usage":{"prompt_tokens":9,"completion_tokens":3}}"#,
            51.0,
        )
        .unwrap();
        assert!(a.feed("[DONE]", 52.0).unwrap());
        assert_eq!(
            (a.first_token_ms, a.last_token_ms, a.delta_chunks),
            (Some(30.0), Some(50.0), 3)
        );
        let p = a.into_parsed();
        assert_eq!(p.text, "abc");
        assert_eq!(p.reasoning.as_deref(), Some("th"));
        assert_eq!(p.finish_reason.as_deref(), Some("stop"));
        assert_eq!(p.usage.unwrap().completion_tokens, 3);
    }

    #[test]
    fn accumulator_surfaces_mid_stream_errors_and_garbage() {
        let mut a = StreamAccumulator::default();
        assert!(matches!(
            a.feed(r#"{"error":{"message":"oom"}}"#, 1.0),
            Err(ModelError::Api { .. })
        ));
        assert!(matches!(
            a.feed("not json", 1.0),
            Err(ModelError::Malformed(_))
        ));
        assert!(!a.feed("", 1.0).unwrap());
    }
}
