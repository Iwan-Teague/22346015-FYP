//! The client against the in-repo mock server. Everything here is verified against a mock written
//! from documented endpoint behaviour (docs/15), **not** against a real llama.cpp / vLLM /
//! Ollama / LM Studio; BUILD-LOG records which claims are mock-only.

use crate::mock::{Behavior, MockServer, ModelSpec, SseEnd};
use crate::*;
use serde_json::json;

fn fast_retry(attempts: u32) -> RetryPolicy {
    RetryPolicy {
        max_attempts: attempts,
        backoff_base: Duration::from_millis(10),
        backoff_cap: Duration::from_millis(40),
        retry_after_cap: Duration::from_millis(50),
    }
}

fn client(url: &str, stream: bool, attempts: u32) -> ModelClient {
    ModelClient::with_config(
        url,
        "mock-model",
        ClientConfig {
            stream,
            retry: fast_retry(attempts),
            request_timeout: Duration::from_secs(20),
            ..Default::default()
        },
    )
}

fn ask(c: &ModelClient, max_tokens: u32) -> Result<Completion, ModelError> {
    let s = SamplingConfig {
        max_tokens,
        ..Default::default()
    };
    c.chat(&ChatSpec {
        system: Some("be brief"),
        user: "count to ten please",
        sampling: &s,
        ignore_eos: false,
    })
}

fn sse(data: &str) -> (u64, String) {
    (0, format!("data: {data}\n\n"))
}

// ---- happy paths and what each one honestly measures ---------------------------------------

#[test]
fn non_streaming_llama_cpp_reports_server_timings() {
    let srv = MockServer::start(vec![Behavior::Model(ModelSpec::default())]);
    let c = ask(&client(&srv.url(), false, 1), 20).unwrap();
    assert_eq!(c.completion_tokens, 20);
    assert_eq!(c.finish_reason, "length"); // 20 < eos_after(200) and max_tokens hit
    assert_eq!(c.timing.source, TimingSource::ServerTimings);
    // The mock's own decode rate comes straight back out of its `timings`.
    let d = c.timing.decode_tok_per_s.unwrap();
    assert!((d - 2000.0).abs() < 1.0, "{d}");
    assert!(
        c.timing.ttft_ms.is_none(),
        "non-streaming has no client TTFT"
    );
    assert_eq!(c.attempts, 1);
    assert_eq!(c.retry_wait_ms, 0);
    // The request pinned what docs/15 says to pin.
    let r = &srv.requests()[0];
    assert_eq!(r["stream"], false);
    assert_eq!(r["cache_prompt"], false);
    assert_eq!(r["n"], 1);
    assert!(r.get("tools").is_none());
}

#[test]
fn non_streaming_without_timings_has_wall_clock_only_and_no_decode_rate() {
    // vLLM / Ollama / LM Studio: usage but no `timings`.
    let spec = ModelSpec {
        emit_timings: false,
        ..Default::default()
    };
    let srv = MockServer::start(vec![Behavior::Model(spec)]);
    let c = ask(&client(&srv.url(), false, 1), 30).unwrap();
    assert_eq!(c.timing.source, TimingSource::ClientWall);
    assert!(c.timing.decode_tok_per_s.is_none());
    assert!(c.timing.prefill_ms.is_none());
    assert!(c.timing.end_to_end_tok_per_s.unwrap() > 0.0);
    assert!(c.usage_reported);
}

#[test]
fn streaming_without_server_timings_measures_decode_from_arrivals() {
    let spec = ModelSpec {
        emit_timings: false,
        prefill_tok_per_s: 2_000.0, // ~10 ms prefill for the ~17-token prompt
        decode_tok_per_s: 1_000.0,
        ..Default::default()
    };
    let srv = MockServer::start(vec![Behavior::Model(spec)]);
    let c = ask(&client(&srv.url(), true, 1), 60).unwrap();
    assert_eq!(c.timing.source, TimingSource::ClientStream);
    assert_eq!(c.completion_tokens, 60);
    assert_eq!(c.timing.token_count_source, TokenCountSource::Usage);
    let ttft = c.timing.ttft_ms.unwrap();
    assert!(
        ttft > 0.0 && ttft < f64::from(c.timing.total_ms as u32),
        "ttft {ttft}"
    );
    // Wide tolerance: this machine is shared and sleeps are coarse. The point is the estimator,
    // which must be near the true 1000 tok/s and far above the end-to-end figure's inclusion of
    // prefill only if prefill were large (it is not here).
    let d = c.timing.decode_tok_per_s.unwrap();
    assert!((500.0..1600.0).contains(&d), "decode {d}");
    assert!(c.timing.prefill_tok_per_s.is_some());
    assert!(srv.requests()[0]["stream_options"]["include_usage"] == true);
}

#[test]
fn streaming_with_llama_cpp_timings_prefers_them() {
    let srv = MockServer::start(vec![Behavior::Model(ModelSpec::default())]);
    let c = ask(&client(&srv.url(), true, 1), 25).unwrap();
    assert_eq!(c.timing.source, TimingSource::ServerTimings);
    assert!((c.timing.decode_tok_per_s.unwrap() - 2000.0).abs() < 1.0);
    assert!(
        c.timing.ttft_ms.is_some(),
        "client TTFT is still recorded when streaming"
    );
}

#[test]
fn a_server_that_ignores_stream_true_is_handled() {
    let srv = MockServer::start(vec![Behavior::ok("fn main() {}")]);
    let c = ask(&client(&srv.url(), true, 1), 10).unwrap();
    assert_eq!(c.text, "fn main() {}");
    assert_eq!(c.timing.source, TimingSource::ClientWall);
    assert!(c.timing.ttft_ms.is_none());
}

#[test]
fn reasoning_content_is_kept_apart_from_content_streaming_or_not() {
    for stream in [false, true] {
        let spec = ModelSpec {
            reasoning_tokens: 6,
            ..Default::default()
        };
        let srv = MockServer::start(vec![Behavior::Model(spec)]);
        let c = ask(&client(&srv.url(), stream, 1), 10).unwrap();
        let r = c.reasoning_content.as_deref().expect("reasoning captured");
        assert!(r.starts_with("r0 "), "{r}");
        assert!(
            !c.text.contains("r0"),
            "reasoning leaked into content (stream={stream})"
        );
        assert!(c.text.starts_with("w6 "), "{}", c.text);
        assert_eq!(
            c.completion_tokens, 10,
            "reasoning tokens count in completion_tokens"
        );
    }
}

#[test]
fn length_truncation_with_only_reasoning_is_visible_not_silent() {
    // Ornith-style: max_tokens consumed entirely by reasoning, 0 chars of content (docs/15).
    let spec = ModelSpec {
        reasoning_tokens: 100,
        ..Default::default()
    };
    let srv = MockServer::start(vec![Behavior::Model(spec)]);
    let c = ask(&client(&srv.url(), false, 1), 20).unwrap();
    assert!(c.truncated());
    assert_eq!(c.text, "");
    assert!(c.reasoning_content.is_some());
}

#[test]
fn natural_stop_reports_stop_and_ignore_eos_is_sent_when_asked() {
    let spec = ModelSpec {
        eos_after: 5,
        ..Default::default()
    };
    let srv = MockServer::start(vec![Behavior::Model(spec)]);
    let c = ask(&client(&srv.url(), false, 1), 50).unwrap();
    assert_eq!((c.finish_reason.as_str(), c.completion_tokens), ("stop", 5));

    let s = SamplingConfig {
        max_tokens: 50,
        ..Default::default()
    };
    let c2 = client(&srv.url(), false, 1)
        .chat(&ChatSpec {
            system: None,
            user: "u",
            sampling: &s,
            ignore_eos: true,
        })
        .unwrap();
    assert_eq!(c2.completion_tokens, 50);
    assert_eq!(srv.requests()[1]["ignore_eos"], true);
}

#[test]
fn a_server_that_ignores_ignore_eos_is_detectable_from_the_token_count() {
    let spec = ModelSpec {
        eos_after: 5,
        honors_ignore_eos: false,
        ..Default::default()
    };
    let srv = MockServer::start(vec![Behavior::Model(spec)]);
    let s = SamplingConfig {
        max_tokens: 50,
        ..Default::default()
    };
    let c = client(&srv.url(), false, 1)
        .chat(&ChatSpec {
            system: None,
            user: "u",
            sampling: &s,
            ignore_eos: true,
        })
        .unwrap();
    assert_eq!(
        c.completion_tokens, 5,
        "the caller sees 5, not the 50 it asked for"
    );
}

#[test]
fn content_null_and_missing_usage_do_not_fail_the_unit() {
    let body = json!({"choices":[{"message":{"role":"assistant","content":null},"finish_reason":"tool_calls"}]});
    let srv = MockServer::start(vec![Behavior::json(200, body.to_string())]);
    let c = ask(&client(&srv.url(), false, 1), 10).unwrap();
    assert_eq!(c.text, "");
    assert_eq!(c.finish_reason, "tool_calls");
    assert!(!c.usage_reported);
    assert_eq!((c.prompt_tokens, c.completion_tokens), (0, 0));
}

// ---- retries -------------------------------------------------------------------------------

#[test]
fn retries_429_and_503_with_capped_retry_after_then_succeeds() {
    let srv = MockServer::start(vec![
        Behavior::json_with(
            429,
            &[("Retry-After", "3600")],
            r#"{"error":{"message":"slow down"}}"#,
        ),
        Behavior::json(503, r#"{"error":{"message":"loading model"}}"#),
        Behavior::ok("done"),
    ]);
    let c = ask(&client(&srv.url(), false, 4), 10).unwrap();
    assert_eq!(c.text, "done");
    assert_eq!(c.attempts, 3);
    // attempt 1: Retry-After 3600s capped to 50ms; attempt 2: backoff 10ms*2 = 20ms.
    assert_eq!(c.retry_wait_ms, 70);
    assert_eq!(srv.request_count(), 3);
}

#[test]
fn gives_up_after_the_attempt_cap_and_reports_the_last_error() {
    let srv = MockServer::start(vec![Behavior::json(500, r#"{"error":"boom"}"#)]);
    let e = ask(&client(&srv.url(), false, 3), 10).unwrap_err();
    match e {
        ModelError::GaveUp { attempts, last } => {
            assert_eq!(attempts, 3);
            assert!(matches!(*last, ModelError::Status { status: 500, .. }));
        }
        other => panic!("{other}"),
    }
    assert_eq!(srv.request_count(), 3, "never more than max_attempts");
}

#[test]
fn client_errors_are_not_retried() {
    for (status, body) in [
        (400, r#"{"error":"bad"}"#),
        (401, "{}"),
        (404, "{}"),
        (422, "{}"),
    ] {
        let srv = MockServer::start(vec![Behavior::json(status, body)]);
        let e = ask(&client(&srv.url(), false, 5), 10).unwrap_err();
        assert!(
            matches!(e, ModelError::Status { status: s, .. } if s == status),
            "{status}: {e}"
        );
        assert_eq!(
            srv.request_count(),
            1,
            "status {status} must not be retried"
        );
    }
}

#[test]
fn llama_cpp_context_overflow_is_typed_and_not_retried() {
    let spec = ModelSpec {
        ctx: Some(12),
        ..Default::default()
    };
    let srv = MockServer::start(vec![Behavior::Model(spec)]);
    let e = ask(&client(&srv.url(), false, 5), 10).unwrap_err();
    assert!(
        matches!(
            e,
            ModelError::ContextExceeded {
                n_prompt_tokens: Some(14),
                n_ctx: Some(12)
            }
        ),
        "{e}"
    );
    assert_eq!(srv.request_count(), 1);
}

#[test]
fn a_dropped_connection_is_retried() {
    let srv = MockServer::start(vec![Behavior::Drop, Behavior::ok("back")]);
    let c = ask(&client(&srv.url(), false, 3), 10).unwrap();
    assert_eq!((c.text.as_str(), c.attempts), ("back", 2));
}

#[test]
fn a_truncated_json_body_is_retried() {
    let body = json!({"choices":[{"message":{"content":"x".repeat(200)},"finish_reason":"stop"}]})
        .to_string();
    let srv = MockServer::start(vec![
        Behavior::TruncatedJson { body },
        Behavior::ok("whole"),
    ]);
    let c = ask(&client(&srv.url(), false, 3), 10).unwrap();
    assert_eq!((c.text.as_str(), c.attempts), ("whole", 2));
}

#[test]
fn connection_refused_is_retried_then_reported() {
    let url = {
        let srv = MockServer::start(vec![Behavior::ok("x")]);
        srv.url()
    }; // server dropped: nothing is listening
    let e = ask(&client(&url, false, 2), 10).unwrap_err();
    match e {
        ModelError::GaveUp { attempts: 2, last } => {
            assert!(matches!(*last, ModelError::Transport(_)))
        }
        other => panic!("{other}"),
    }
}

#[test]
fn a_request_deadline_timeout_is_not_retried() {
    let srv = MockServer::start(vec![Behavior::Delayed {
        ms: 1500,
        then: Box::new(Behavior::ok("late")),
    }]);
    let c = ModelClient::with_config(
        srv.url(),
        "m",
        ClientConfig {
            request_timeout: Duration::from_millis(150),
            retry: fast_retry(4),
            ..Default::default()
        },
    );
    let e = ask(&c, 10).unwrap_err();
    assert!(
        matches!(&e, ModelError::Transport(t) if t.is_timeout()),
        "{e}"
    );
    assert_eq!(
        srv.request_count(),
        1,
        "re-sending would just wait the full deadline again"
    );
}

// ---- streams that go wrong -----------------------------------------------------------------

fn partial_stream(end: SseEnd) -> Behavior {
    Behavior::Sse {
        events: vec![
            sse(r#"{"choices":[{"delta":{"role":"assistant","content":""}}]}"#),
            sse(r#"{"choices":[{"delta":{"content":"fn "}}]}"#),
            sse(r#"{"choices":[{"delta":{"content":"main"}}]}"#),
        ],
        end,
    }
}

fn sse_ok(content: &str) -> Behavior {
    Behavior::Sse {
        events: vec![
            sse(&json!({"choices":[{"delta":{"content":content}}]}).to_string()),
            sse(r#"{"choices":[{"delta":{},"finish_reason":"stop"}]}"#),
            sse(r#"{"choices":[],"usage":{"prompt_tokens":9,"completion_tokens":4}}"#),
            (0, "data: [DONE]\n\n".to_string()),
        ],
        end: SseEnd::Done,
    }
}

#[test]
fn connection_reset_mid_stream_keeps_the_partial_and_retries() {
    let srv = MockServer::start(vec![partial_stream(SseEnd::Reset), sse_ok("fn main() {}")]);
    let c = ask(&client(&srv.url(), true, 3), 10).unwrap();
    assert_eq!(c.text, "fn main() {}");
    assert_eq!(c.attempts, 2);
}

#[test]
fn persistent_mid_stream_resets_surface_the_partial_text() {
    let srv = MockServer::start(vec![partial_stream(SseEnd::Reset)]);
    let e = ask(&client(&srv.url(), true, 2), 10).unwrap_err();
    match e {
        ModelError::GaveUp { attempts: 2, last } => match *last {
            ModelError::StreamInterrupted { partial, .. } => {
                assert_eq!(partial.text, "fn main");
                assert!(partial.timing.ttft_ms.is_some());
            }
            other => panic!("{other}"),
        },
        other => panic!("{other}"),
    }
}

#[test]
fn stream_ending_cleanly_without_finish_reason_is_truncation_not_success() {
    let srv = MockServer::start(vec![partial_stream(SseEnd::Done)]);
    let e = ask(&client(&srv.url(), true, 1), 10).unwrap_err();
    assert!(matches!(e, ModelError::StreamInterrupted { .. }), "{e}");
}

#[test]
fn stream_ending_with_finish_reason_but_no_done_is_accepted() {
    let srv = MockServer::start(vec![Behavior::Sse {
        events: vec![
            sse(r#"{"choices":[{"delta":{"content":"ok"}}]}"#),
            sse(r#"{"choices":[{"delta":{},"finish_reason":"stop"}]}"#),
        ],
        end: SseEnd::Done,
    }]);
    let c = ask(&client(&srv.url(), true, 1), 10).unwrap();
    assert_eq!((c.text.as_str(), c.finish_reason.as_str()), ("ok", "stop"));
    assert!(!c.usage_reported);
    assert_eq!(c.timing.token_count_source, TokenCountSource::StreamChunks);
}

#[test]
fn a_stalled_stream_hits_the_stall_timeout_and_is_retried() {
    let srv = MockServer::start(vec![partial_stream(SseEnd::Hang(1500)), sse_ok("fine")]);
    let c = ModelClient::with_config(
        srv.url(),
        "m",
        ClientConfig {
            stream: true,
            stall_timeout: Some(Duration::from_millis(200)),
            retry: fast_retry(3),
            ..Default::default()
        },
    );
    let out = ask(&c, 10).unwrap();
    assert_eq!((out.text.as_str(), out.attempts), ("fine", 2));
}

#[test]
fn an_error_event_inside_a_stream_is_an_api_error_not_a_retry() {
    let srv = MockServer::start(vec![Behavior::Sse {
        events: vec![sse(r#"{"error":{"message":"model unloaded"}}"#)],
        end: SseEnd::Done,
    }]);
    let e = ask(&client(&srv.url(), true, 4), 10).unwrap_err();
    assert!(matches!(e, ModelError::Api { .. }), "{e}");
    assert_eq!(srv.request_count(), 1);
}

#[test]
fn error_object_with_a_200_status_is_an_api_error() {
    let srv = MockServer::start(vec![Behavior::json(
        200,
        r#"{"error":{"message":"no model loaded"}}"#,
    )]);
    let e = ask(&client(&srv.url(), false, 4), 10).unwrap_err();
    assert!(matches!(e, ModelError::Api { .. }), "{e}");
    assert_eq!(srv.request_count(), 1);
}

#[test]
fn empty_choices_is_no_choices_and_not_retried() {
    let srv = MockServer::start(vec![Behavior::json(
        200,
        r#"{"choices":[],"usage":{"prompt_tokens":1}}"#,
    )]);
    let e = ask(&client(&srv.url(), false, 4), 10).unwrap_err();
    assert!(matches!(e, ModelError::NoChoices), "{e}");
    assert_eq!(srv.request_count(), 1);
}

#[test]
fn non_json_200_is_malformed_and_not_retried() {
    let srv = MockServer::start(vec![Behavior::json(200, "<html>proxy login</html>")]);
    let e = ask(&client(&srv.url(), false, 4), 10).unwrap_err();
    assert!(matches!(e, ModelError::Malformed(_)), "{e}");
    assert_eq!(srv.request_count(), 1);
}

#[test]
fn error_bodies_are_clipped_in_the_message() {
    let srv = MockServer::start(vec![Behavior::json(404, "x".repeat(10_000))]);
    let e = ask(&client(&srv.url(), false, 1), 10).unwrap_err();
    assert!(e.to_string().len() < 2200, "{}", e.to_string().len());
}
