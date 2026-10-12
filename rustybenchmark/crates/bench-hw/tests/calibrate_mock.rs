//! Calibration driven through `bench-model` against the in-repo mock endpoint. These prove the
//! *protocol and estimators*; they say nothing about any real backend's wire behaviour (BUILD-LOG
//! records which claims are mock-only).

use bench_hw::calibrate::*;
use bench_model::mock::{Behavior, MockServer, ModelSpec};
use bench_model::{ClientConfig, ModelClient, RetryPolicy};
use std::time::Duration;

fn quick(reps: u32) -> CalibConfig {
    CalibConfig {
        tier: Tier::Full,
        warmup: Duration::ZERO,
        reps,
        pp_tokens: 512,
        tg_tokens: 128,
        sustained: None,
        sustained_prompt_tokens: 2000,
        sustained_gen_tokens: 100,
    }
}

fn client(url: &str) -> ModelClient {
    ModelClient::with_config(
        url,
        "mock",
        ClientConfig {
            stream: true,
            retry: RetryPolicy {
                max_attempts: 2,
                backoff_base: Duration::from_millis(5),
                backoff_cap: Duration::from_millis(10),
                retry_after_cap: Duration::from_millis(10),
            },
            request_timeout: Duration::from_secs(30),
            ..Default::default()
        },
    )
}

fn go(spec: ModelSpec, cfg: &CalibConfig) -> Result<(Calibration, MockServer), CalibError> {
    let srv = MockServer::start(vec![Behavior::Model(spec)]);
    let c = run(&client(&srv.url()), cfg, &mut |_| {})?;
    Ok((c, srv))
}

#[test]
fn server_timings_recover_the_true_rates_and_the_actual_prompt_size() {
    let (c, _srv) = go(ModelSpec::default(), &quick(5)).unwrap();
    assert_eq!(c.timing_source, "server_timings");
    let (pp, tg) = (c.pp512.unwrap(), c.tg128.unwrap());
    assert!((pp.median - 50_000.0).abs() < 50.0, "pp {pp:?}");
    assert!((tg.median - 2_000.0).abs() < 2.0, "tg {tg:?}");
    assert_eq!((pp.reps, tg.reps), (5, 5));
    let n = c.pp_tokens_actual.unwrap();
    assert!(
        (497..=527).contains(&n),
        "prompt sized from the endpoint's own count: {n}"
    );
    assert_eq!(c.tg_tokens_actual, Some(128), "ignore_eos honoured");
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
    assert!(c.sustained.is_none());
    assert!(c
        .not_measured
        .iter()
        .any(|m| m.contains("abbreviated") || m.contains("sustained")));
    assert!(c.peak_accel_mem_mb.is_none() && c.peak_host_rss_mb.is_none());
    assert!(c
        .not_measured
        .iter()
        .any(|m| m.contains("peak_accel_mem_mb")));
}

#[test]
fn the_prompt_is_resized_until_the_reported_size_is_near_the_target() {
    // A chat template that adds 150 tokens: the first probe lands well over 512.
    let spec = ModelSpec {
        template_overhead: 150,
        ..Default::default()
    };
    let (c, srv) = go(spec, &quick(3)).unwrap();
    let n = c.pp_tokens_actual.unwrap();
    assert!((497..=527).contains(&n), "{n}");
    assert!(
        srv.request_count() > 1 + 3 + 3,
        "more than one sizing probe was needed"
    );
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
}

#[test]
fn every_rep_uses_a_distinct_prompt_prefix_and_the_pinned_request_shape() {
    let (_c, srv) = go(ModelSpec::default(), &quick(4)).unwrap();
    let reqs = srv.requests();
    let firsts: Vec<String> = reqs
        .iter()
        .map(|r| {
            r["messages"][0]["content"]
                .as_str()
                .unwrap()
                .split(':')
                .next()
                .unwrap()
                .to_string()
        })
        .collect();
    let mut uniq = firsts.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(
        uniq.len(),
        firsts.len(),
        "a repeated prefix would let a prefix cache fake pp: {firsts:?}"
    );
    for r in &reqs {
        assert_eq!(r["stream"], true);
        assert_eq!(r["cache_prompt"], false);
        assert_eq!(
            r["messages"].as_array().unwrap().len(),
            1,
            "no system prompt in calibration"
        );
        assert!(r.get("tools").is_none());
    }
    assert!(
        reqs.iter()
            .any(|r| r["ignore_eos"] == true && r["max_tokens"] == 128),
        "tg asks for 128 tokens"
    );
    assert!(reqs.iter().any(|r| r["max_tokens"] == 1), "pp asks for one");
}

#[test]
fn without_server_timings_it_falls_back_to_the_stream_and_says_so() {
    let spec = ModelSpec {
        emit_timings: false,
        prefill_tok_per_s: 20_000.0,
        decode_tok_per_s: 1_000.0,
        ..Default::default()
    };
    let (c, _s) = go(spec, &quick(5)).unwrap();
    assert_eq!(c.timing_source, "client_stream");
    assert!(
        c.warnings.iter().any(|w| w.contains("time-to-first-token")),
        "{:?}",
        c.warnings
    );
    let tg = c.tg128.unwrap().median;
    assert!((500.0..1_600.0).contains(&tg), "tg {tg}");
    // pp from TTFT includes one decode step plus the network, so it can only under-read.
    let pp = c.pp512.unwrap().median;
    assert!(pp < 20_000.0 * 1.05 && pp > 20_000.0 * 0.3, "pp {pp}");
}

#[test]
fn an_endpoint_without_usage_cannot_size_pp_but_still_yields_tg() {
    let spec = ModelSpec {
        emit_usage: false,
        emit_timings: false,
        ..Default::default()
    };
    let (c, _s) = go(spec, &quick(4)).unwrap();
    assert!(c.pp512.is_none());
    assert!(
        c.warnings.iter().any(|w| w.contains("prompt token count")),
        "{:?}",
        c.warnings
    );
    assert!(c.not_measured.iter().any(|m| m.starts_with("pp:")));
    let tg = c
        .tg128
        .expect("tg needs only arrival gaps and the chunk count");
    assert!(tg.median > 300.0);
}

#[test]
fn a_server_that_ignores_ignore_eos_is_flagged_with_the_achieved_length() {
    let spec = ModelSpec {
        eos_after: 20,
        honors_ignore_eos: false,
        ..Default::default()
    };
    let (c, _s) = go(spec, &quick(3)).unwrap();
    assert_eq!(c.tg_tokens_actual, Some(20));
    assert!(
        c.warnings.iter().any(|w| w.contains("ignore_eos")),
        "{:?}",
        c.warnings
    );
}

#[test]
fn prefix_cache_hits_are_discarded_not_averaged_in() {
    let spec = ModelSpec {
        report_cached: 400,
        ..Default::default()
    };
    let (c, _s) = go(spec, &quick(3)).unwrap();
    assert!(c.pp512.is_none(), "every pp rep reported cached tokens");
    assert!(
        c.warnings
            .iter()
            .filter(|w| w.contains("cached prompt tokens"))
            .count()
            >= 3
    );
    assert!(c.tg128.is_some());
}

#[test]
fn warm_up_load_is_sent_and_discarded() {
    let cfg = CalibConfig {
        warmup: Duration::from_millis(150),
        ..quick(2)
    };
    let (c, srv) = go(ModelSpec::default(), &cfg).unwrap();
    // 1 sizing probe + 2 pp + 2 tg = 5 without warm-up; 150 ms of 64 ms tg requests adds >= 2.
    assert!(srv.request_count() >= 7, "{}", srv.request_count());
    assert_eq!(
        (c.pp512.unwrap().reps, c.tg128.unwrap().reps),
        (2, 2),
        "warm-up results never count"
    );
    assert_eq!(c.warmup_s, 0.15);
}

#[test]
fn sustained_phase_sees_no_delta_on_a_steady_machine() {
    let cfg = CalibConfig {
        sustained: Some(Duration::from_millis(600)),
        sustained_gen_tokens: 100,
        ..quick(3)
    };
    let (c, _s) = go(ModelSpec::default(), &cfg).unwrap();
    let s = c.sustained.clone().expect("sustained ran");
    assert!(s.requests >= 5, "{}", s.requests);
    // server timings are exact, so a steady mock has exactly zero drift
    assert!(s.delta_pct.abs() < 0.5, "{}", s.delta_pct);
    assert!((s.minute_1_tps - 2000.0).abs() < 2.0);
    assert!(!c.throughput_unstable());
    assert!(s.throttle_events.is_none() && s.clock_start_mhz.is_none());
}

#[test]
fn sustained_phase_detects_a_throttling_machine() {
    // Decode halves once the server has been up for 1 s; the sustained phase starts well before
    // that and ends well after it.
    let spec = ModelSpec {
        throttle: Some((1_000, 0.5)),
        ..Default::default()
    };
    let cfg = CalibConfig {
        sustained: Some(Duration::from_millis(1_800)),
        sustained_gen_tokens: 100,
        ..quick(3)
    };
    let (c, _s) = go(spec, &cfg).unwrap();
    let s = c.sustained.clone().unwrap();
    assert!(
        (-60.0..-35.0).contains(&s.delta_pct),
        "delta {} (early {}, late {})",
        s.delta_pct,
        s.minute_1_tps,
        s.minute_10_tps
    );
    assert!(
        c.throughput_unstable(),
        "a >15% cold/warm delta marks throughput unstable"
    );
}

#[test]
fn a_small_context_skips_sustained_with_a_warning_but_keeps_pp_and_tg() {
    let spec = ModelSpec {
        ctx: Some(700),
        ..Default::default()
    };
    let cfg = CalibConfig {
        sustained: Some(Duration::from_millis(300)),
        ..quick(2)
    };
    let (c, _s) = go(spec, &cfg).unwrap();
    assert!(c.sustained.is_none());
    assert!(
        c.warnings.iter().any(|w| w.contains("context window")),
        "{:?}",
        c.warnings
    );
    assert!(c.pp512.is_some() && c.tg128.is_some());
}

#[test]
fn a_context_too_small_even_for_pp_is_an_error_not_a_guess() {
    let spec = ModelSpec {
        ctx: Some(100),
        ..Default::default()
    };
    let e = go(spec, &quick(2)).map(|_| ()).unwrap_err();
    assert!(e.to_string().contains("context"), "{e}");
}

#[test]
fn a_non_streaming_client_is_refused() {
    let srv = MockServer::start(vec![Behavior::Model(ModelSpec::default())]);
    let c = ModelClient::new(srv.url(), "m");
    let e = run(&c, &quick(1), &mut |_| {}).unwrap_err();
    assert!(matches!(e, CalibError::NotStreaming));
    assert_eq!(srv.request_count(), 0, "refused before sending anything");
}

#[test]
fn an_unreachable_or_failing_endpoint_is_an_error() {
    let srv = MockServer::start(vec![Behavior::json(500, r#"{"error":"down"}"#)]);
    let e = run(&client(&srv.url()), &quick(2), &mut |_| {}).unwrap_err();
    assert!(matches!(e, CalibError::Model(_)), "{e}");
}

#[test]
fn escalation_is_driven_by_real_measurements() {
    let full = go(ModelSpec::default(), &quick(5)).unwrap().0;
    let same = go(
        ModelSpec::default(),
        &CalibConfig {
            tier: Tier::Abbreviated,
            ..quick(5)
        },
    )
    .unwrap()
    .0;
    assert!(
        !needs_escalation(&full, &same),
        "an unchanged machine does not escalate"
    );
    let slower = go(
        ModelSpec {
            decode_tok_per_s: 1_500.0,
            ..Default::default()
        },
        &CalibConfig {
            tier: Tier::Abbreviated,
            ..quick(5)
        },
    )
    .unwrap()
    .0;
    assert!(needs_escalation(&full, &slower), "tg 2000 -> 1500 is -25%");
    assert!(tg_unstable_across_segments(&[
        full.clone(),
        same.clone(),
        slower
    ]));
    assert!(!tg_unstable_across_segments(&[full, same]));
}

#[test]
fn progress_lines_name_each_phase() {
    let srv = MockServer::start(vec![Behavior::Model(ModelSpec::default())]);
    let mut lines = Vec::new();
    let cfg = CalibConfig {
        warmup: Duration::from_millis(30),
        sustained: Some(Duration::from_millis(100)),
        sustained_gen_tokens: 50,
        ..quick(1)
    };
    run(&client(&srv.url()), &cfg, &mut |l| {
        lines.push(l.to_string())
    })
    .unwrap();
    let all = lines.join("|");
    for k in ["sizing", "warm-up", "pp:", "tg:", "sustained"] {
        assert!(all.contains(k), "missing {k}: {all}");
    }
}
