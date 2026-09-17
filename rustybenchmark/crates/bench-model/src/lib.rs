//! `bench-model` — a client for OpenAI-compatible chat endpoints.
//!
//! The harness speaks only HTTP, which keeps the serving backend swappable
//! (llama.cpp, Ollama, vLLM, LM Studio). This is the *only* place the harness
//! talks to the model, and per docs/08-run-protocol.md it runs in the harness
//! process, NOT inside the grading sandbox — generation executes nothing, so
//! sandboxing it would protect against nothing and break the one thing it does.
//!
//! P0 scope: a blocking `/v1/chat/completions` call that records the completion
//! text, token counts, and wall time. The full pinned sampler chain
//! (docs/15-profiles-and-divisions.md §2.2) and the prefill/decode split arrive
//! with the profile work; here we send an explicit `temperature` and `n`,
//! because omitting them yields the server's own defaults, not neutrality.

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("http transport: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("model server returned {status}: {body}")]
    Status { status: u16, body: String },
    #[error("response had no choices")]
    NoChoices,
}

/// What the harness pins in the request body. Only the fields the P0 spine
/// needs; the remaining samplers (top_k, min_p, penalties, …) join this struct
/// with the profile work.
#[derive(Clone, Debug)]
pub struct SamplingConfig {
    pub temperature: f32,
    pub top_p: f32,
    pub max_tokens: u32,
    pub seed: Option<u64>,
}

impl Default for SamplingConfig {
    fn default() -> Self {
        // Greedy primary run (docs/07-statistics.md sampling protocol).
        SamplingConfig {
            temperature: 0.0,
            top_p: 1.0,
            max_tokens: 4096,
            seed: Some(42),
        }
    }
}

/// One model turn: the text it returned, what it cost, and how long it took.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Completion {
    pub text: String,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub finish_reason: String,
    /// Total wall time of the request. The prefill/decode split is not
    /// available over the OpenAI surface on three of four backends
    /// (docs/REVIEW-5.md R5-S6), so the spine records only the total.
    pub elapsed_ms: u64,
}

pub struct ModelClient {
    base_url: String,
    model: String,
    http: reqwest::blocking::Client,
}

impl ModelClient {
    /// `base_url` is the server origin, e.g. `http://localhost:8080`. The
    /// `/v1/chat/completions` path is appended.
    pub fn new(base_url: impl Into<String>, model: impl Into<String>) -> Self {
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(900))
            .build()
            .expect("reqwest client builds with default config");
        ModelClient {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            model: model.into(),
            http,
        }
    }

    pub fn complete(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        sampling: &SamplingConfig,
    ) -> Result<Completion, ModelError> {
        // Endpoint pinned to /v1/chat/completions: /v1/completions applies no
        // chat template at all (docs/15 §2.2). The `tools` key is deliberately
        // absent — offering tools flips models to empty-content tool calls.
        let body = ChatRequest {
            model: &self.model,
            messages: vec![
                Message {
                    role: "system",
                    content: system_prompt,
                },
                Message {
                    role: "user",
                    content: user_prompt,
                },
            ],
            temperature: sampling.temperature,
            top_p: sampling.top_p,
            max_tokens: sampling.max_tokens,
            n: 1,
            seed: sampling.seed,
            stream: false,
        };

        let url = format!("{}/v1/chat/completions", self.base_url);
        let start = Instant::now();
        let resp = self.http.post(&url).json(&body).send()?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(ModelError::Status {
                status: status.as_u16(),
                body,
            });
        }
        let parsed: ChatResponse = resp.json()?;
        let elapsed_ms = start.elapsed().as_millis() as u64;

        let choice = parsed
            .choices
            .into_iter()
            .next()
            .ok_or(ModelError::NoChoices)?;
        Ok(Completion {
            text: choice.message.content,
            prompt_tokens: parsed.usage.prompt_tokens,
            completion_tokens: parsed.usage.completion_tokens,
            finish_reason: choice.finish_reason.unwrap_or_else(|| "unknown".into()),
            elapsed_ms,
        })
    }
}

// --- wire types ---

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<Message<'a>>,
    temperature: f32,
    top_p: f32,
    max_tokens: u32,
    n: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<u64>,
    stream: bool,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
    #[serde(default)]
    usage: Usage,
}

#[derive(Deserialize)]
struct Choice {
    message: RespMessage,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct RespMessage {
    #[serde(default)]
    content: String,
}

#[derive(Deserialize, Default)]
struct Usage {
    #[serde(default)]
    prompt_tokens: u32,
    #[serde(default)]
    completion_tokens: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- SamplingConfig ---

    #[test]
    fn default_sampling_is_greedy_with_pinned_seed() {
        let s = SamplingConfig::default();
        assert_eq!(s.temperature, 0.0);
        assert_eq!(s.top_p, 1.0);
        assert_eq!(s.max_tokens, 4096);
        assert_eq!(s.seed, Some(42));
    }

    // --- client construction ---

    #[test]
    fn base_url_trailing_slashes_are_trimmed() {
        for raw in [
            "http://localhost:8080",
            "http://localhost:8080/",
            "http://localhost:8080///",
        ] {
            let c = ModelClient::new(raw, "m");
            assert_eq!(c.base_url, "http://localhost:8080", "input {raw}");
        }
    }

    #[test]
    fn model_name_is_preserved_verbatim() {
        let c = ModelClient::new("http://localhost:8080/", "qwen2.5-coder-7b-instruct");
        assert_eq!(c.model, "qwen2.5-coder-7b-instruct");
    }

    // --- request wire format ---

    #[test]
    fn request_serialises_the_full_pinned_body() {
        let body = ChatRequest {
            model: "test-model",
            messages: vec![
                Message {
                    role: "system",
                    content: "sys",
                },
                Message {
                    role: "user",
                    content: "usr",
                },
            ],
            temperature: 0.0,
            top_p: 1.0,
            max_tokens: 4096,
            n: 1,
            seed: Some(42),
            stream: false,
        };
        let v: serde_json::Value = serde_json::to_value(&body).unwrap();
        assert_eq!(v["model"], "test-model");
        assert_eq!(v["messages"][0]["role"], "system");
        assert_eq!(v["messages"][0]["content"], "sys");
        assert_eq!(v["messages"][1]["role"], "user");
        assert_eq!(v["temperature"], 0.0);
        assert_eq!(v["top_p"], 1.0);
        assert_eq!(v["max_tokens"], 4096);
        assert_eq!(v["n"], 1);
        assert_eq!(v["seed"], 42);
        assert_eq!(v["stream"], false);
    }

    #[test]
    fn request_omits_seed_when_none_so_server_default_applies_only_if_asked() {
        let body = ChatRequest {
            model: "m",
            messages: vec![],
            temperature: 0.0,
            top_p: 1.0,
            max_tokens: 1,
            n: 1,
            seed: None,
            stream: false,
        };
        let v: serde_json::Value = serde_json::to_value(&body).unwrap();
        assert!(v.get("seed").is_none(), "seed must be absent when None");
    }

    // --- response parsing ---

    fn response_json(extra: &str) -> String {
        format!(
            r#"{{"id":"x","object":"chat.completion","choices":[{{"index":0,
                "message":{{"role":"assistant","content":"fn main() {{}}"}},"finish_reason":"stop"}}],
                "usage":{{"prompt_tokens":11,"completion_tokens":7}}{extra}}}"#
        )
    }

    #[test]
    fn response_parses_text_tokens_and_finish_reason() {
        let r: ChatResponse =
            serde_json::from_str(&response_json("")).expect("full payload parses");
        assert_eq!(r.choices.len(), 1);
        assert_eq!(r.choices[0].message.content, "fn main() {}");
        assert_eq!(r.choices[0].finish_reason.as_deref(), Some("stop"));
        assert_eq!(r.usage.prompt_tokens, 11);
        assert_eq!(r.usage.completion_tokens, 7);
    }

    #[test]
    fn missing_usage_defaults_to_zero_not_an_error() {
        // Some backends omit usage entirely; the wire type must tolerate it.
        let r: ChatResponse = serde_json::from_str(
            r#"{"choices":[{"message":{"content":"hi"},"finish_reason":"length"}]}"#,
        )
        .expect("usage-less payload parses");
        assert_eq!(r.usage.prompt_tokens, 0);
        assert_eq!(r.usage.completion_tokens, 0);
        assert_eq!(r.choices[0].finish_reason.as_deref(), Some("length"));
    }

    #[test]
    fn missing_content_and_finish_reason_default_cleanly() {
        let r: ChatResponse =
            serde_json::from_str(r#"{"choices":[{"message":{"role":"assistant"}}],"usage":{}}"#)
                .expect("sparse payload parses");
        assert_eq!(r.choices[0].message.content, "");
        assert!(r.choices[0].finish_reason.is_none());
    }

    #[test]
    fn empty_choices_is_a_valid_parse_that_complete_rejects_as_no_choices() {
        // The struct parses (serde is happy with an empty array); the
        // NoChoices error comes from complete()'s take-first logic.
        let r: ChatResponse = serde_json::from_str(
            r#"{"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#,
        )
        .expect("empty choices parse");
        assert!(
            r.choices.is_empty(),
            "complete()'s take-first then hits ModelError::NoChoices"
        );
    }

    // --- Completion round-trip ---

    #[test]
    fn completion_round_trips_through_jsonl_friendly_json() {
        let c = Completion {
            text: "hello".into(),
            prompt_tokens: 10,
            completion_tokens: 3,
            finish_reason: "stop".into(),
            elapsed_ms: 1234,
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: Completion = serde_json::from_str(&json).unwrap();
        assert_eq!(back.text, "hello");
        assert_eq!(back.prompt_tokens, 10);
        assert_eq!(back.completion_tokens, 3);
        assert_eq!(back.finish_reason, "stop");
        assert_eq!(back.elapsed_ms, 1234);
    }
}
