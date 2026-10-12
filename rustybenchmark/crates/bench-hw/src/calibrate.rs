//! Phase B of docs/05: inference calibration — `pp512`, `tg128` and the sustained phase —
//! measured through `bench-model` against any OpenAI-compatible endpoint.
//!
//! The protocol follows llama-bench so the numbers are comparable to the wider ecosystem, with the
//! deviations that the OpenAI surface forces. Every one is recorded in the output, not hidden:
//!
//! * **No tokenizer here.** A prompt of "512 tokens" cannot be built blind, so the harness sends a
//!   probe, reads the server's own `usage.prompt_tokens`, and rescales the word count until the
//!   *reported* size is within 3% of the target. The size actually measured is recorded
//!   (`pp_tokens_actual`); it includes the chat template's overhead.
//! * **`pp` is `evaluated prompt tokens / prefill seconds`**, with prefill taken from the server's
//!   `timings` when sent (llama.cpp) and otherwise the client's time-to-first-token with
//!   `max_tokens = 1` (which includes one decode step and the network: a small, documented bias).
//!   The source is in `timing_source`. Each rep uses a distinct prompt prefix so a prefix cache
//!   cannot turn prefill into a cache read, and any rep that reports cached tokens is discarded.
//! * **`tg` is the decode rate from the arrival gaps / server timings, excluding prefill.** A
//!   non-streaming reply has only wall time, which includes prefill, so it yields *no* `tg`
//!   figure rather than a wrong one (`bench-model` returns `None`).
//! * **`ignore_eos` is requested** so 128 tokens are actually generated; a server that ignores it
//!   shows up as a short generation and a warning, and the achieved count is recorded.
//! * **Not measured**, and recorded as null with the reason: peak accelerator memory, peak host
//!   RSS, clocks and thermal events. None is available over HTTP, and Phase A has no probe for
//!   them yet. A made-up number on a leaderboard is worse than a missing one (docs/05).
//!
//! The statistics (percentiles, windows, escalation) are pure functions, tested without a server.

use bench_model::{
    ChatSpec, ClientConfig, Completion, ModelClient, ModelError, SamplingConfig, TimingSource,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

pub const CALIB_SCHEMA: u32 = 1;

/// docs/05: abbreviated calibration is escalated to full if it deviates by more than this from
/// segment 0, and throughput is "unstable" if `tg128` varies by more than this across segments.
pub const TG_DEVIATION_LIMIT: f64 = 0.10;
/// docs/05 pre-run gate: cold/warm delta above this marks throughput metrics unstable.
pub const SUSTAINED_DELTA_LIMIT_PCT: f64 = 15.0;
/// The reported prompt size must be within this fraction of the target.
const FIT_TOLERANCE: f64 = 0.03;
const FIT_MAX_PROBES: u32 = 4;
/// A generation shorter than this fraction of the requested length is flagged.
const SHORT_GENERATION: f64 = 0.9;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Segment 0: warm-up + 10 reps + sustained phase (~15 min).
    Full,
    /// Segments 1..n: warm-up + 5 reps, no sustained phase (~3 min).
    Abbreviated,
}

#[derive(Clone, Debug)]
pub struct CalibConfig {
    pub tier: Tier,
    /// Load applied and discarded before measuring. docs/05: 60 s.
    pub warmup: Duration,
    pub reps: u32,
    pub pp_tokens: u32,
    pub tg_tokens: u32,
    /// `Some(d)`: run the sustained phase for `d` (docs/05: 10 minutes).
    pub sustained: Option<Duration>,
    pub sustained_prompt_tokens: u32,
    pub sustained_gen_tokens: u32,
}

impl CalibConfig {
    /// docs/05 segment 0.
    pub fn full() -> Self {
        CalibConfig {
            tier: Tier::Full,
            warmup: Duration::from_secs(60),
            reps: 10,
            pp_tokens: 512,
            tg_tokens: 128,
            sustained: Some(Duration::from_secs(600)),
            sustained_prompt_tokens: 2000,
            sustained_gen_tokens: 1000,
        }
    }

    /// docs/05 segments 1..n.
    pub fn abbreviated() -> Self {
        CalibConfig {
            tier: Tier::Abbreviated,
            reps: 5,
            sustained: None,
            ..Self::full()
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CalibError {
    #[error("model endpoint: {0}")]
    Model(#[from] ModelError),
    #[error("calibration needs a streaming client (ClientConfig::stream = true)")]
    NotStreaming,
    #[error("{0}")]
    NoData(String),
}

/// `median`, `p5`, `p95` over `reps` valid repetitions (docs/05 "report median + p5 + p95").
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    pub median: f64,
    pub p5: f64,
    pub p95: f64,
    pub reps: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Sustained {
    pub duration_s: f64,
    pub requests: u32,
    /// Decode tok/s early in the phase (docs/05 "minute 1").
    pub minute_1_tps: f64,
    /// Decode tok/s late in the phase ("minute 10").
    pub minute_10_tps: f64,
    pub delta_pct: f64,
    /// Length of the early and late windows (the whole phase / 4, at most 60 s).
    pub window_s: f64,
    /// Not probed: no clock or thermal source exists yet.
    pub clock_start_mhz: Option<u32>,
    pub clock_end_mhz: Option<u32>,
    pub throttle_events: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Drift {
    /// `(median of the second half of reps - median of the first) / first * 100`.
    pub pp_pct: Option<f64>,
    pub tg_pct: Option<f64>,
}

/// The result: docs/12 `segments/<n>/calib.json`, plus the provenance this crate adds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Calibration {
    pub schema: u32,
    pub tier: Tier,
    pub warmup_s: f64,
    /// `server_timings`, `client_stream`, or `mixed` (a warning is then raised).
    pub timing_source: String,
    pub pp_tokens_target: u32,
    /// The prompt size the endpoint itself reported for the measured reps (median).
    pub pp_tokens_actual: Option<u32>,
    pub pp512: Option<Summary>,
    pub tg_tokens_target: u32,
    /// Median tokens actually generated per tg rep.
    pub tg_tokens_actual: Option<u32>,
    pub tg128: Option<Summary>,
    pub sustained: Option<Sustained>,
    pub drift: Drift,
    pub peak_accel_mem_mb: Option<u64>,
    pub peak_host_rss_mb: Option<u64>,
    /// What was not measured, and (briefly) why.
    pub not_measured: Vec<String>,
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Pure statistics
// ---------------------------------------------------------------------------

/// Linear-interpolation percentile (`q` in 0..=1) of an unsorted sample. `None` if empty.
pub fn percentile(xs: &[f64], q: f64) -> Option<f64> {
    let mut v: Vec<f64> = xs.iter().copied().filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.total_cmp(b));
    let pos = q.clamp(0.0, 1.0) * (v.len() - 1) as f64;
    let (lo, hi) = (pos.floor() as usize, pos.ceil() as usize);
    Some(v[lo] + (v[hi] - v[lo]) * (pos - lo as f64))
}

pub fn summarise(xs: &[f64]) -> Option<Summary> {
    Some(Summary {
        median: percentile(xs, 0.5)?,
        p5: percentile(xs, 0.05)?,
        p95: percentile(xs, 0.95)?,
        reps: xs.iter().filter(|x| x.is_finite()).count() as u32,
    })
}

/// First-half vs second-half median drift, in percent. Needs at least 4 samples.
pub fn drift_pct(xs: &[f64]) -> Option<f64> {
    if xs.len() < 4 {
        return None;
    }
    let (a, b) = xs.split_at(xs.len() / 2);
    let (ma, mb) = (percentile(a, 0.5)?, percentile(b, 0.5)?);
    (ma > 0.0).then(|| (mb - ma) / ma * 100.0)
}

/// One sustained-phase request: when it finished (seconds into the phase) and its decode rate.
#[derive(Clone, Copy, Debug)]
pub struct SustainedSample {
    pub end_s: f64,
    pub tps: f64,
}

/// docs/05: "tok/s at minute 1 vs minute 10". The windows are `window` long at the start and the
/// end of the phase; if a window caught no request (requests longer than the window) the first /
/// last sample stands in.
pub fn sustained_summary(
    samples: &[SustainedSample],
    duration_s: f64,
    window_s: f64,
) -> Option<Sustained> {
    if samples.is_empty() {
        return None;
    }
    let med = |xs: Vec<f64>| percentile(&xs, 0.5);
    let early: Vec<f64> = samples
        .iter()
        .filter(|s| s.end_s <= window_s)
        .map(|s| s.tps)
        .collect();
    let late: Vec<f64> = samples
        .iter()
        .filter(|s| s.end_s >= duration_s - window_s)
        .map(|s| s.tps)
        .collect();
    let first = med(early).unwrap_or(samples[0].tps);
    let last = med(late).unwrap_or(samples[samples.len() - 1].tps);
    Some(Sustained {
        duration_s,
        requests: samples.len() as u32,
        minute_1_tps: first,
        minute_10_tps: last,
        delta_pct: if first > 0.0 {
            (last - first) / first * 100.0
        } else {
            0.0
        },
        window_s,
        clock_start_mhz: None,
        clock_end_mhz: None,
        throttle_events: None,
    })
}

impl Calibration {
    /// Throughput metrics must be flagged unstable (docs/05 pre-run gates).
    pub fn throughput_unstable(&self) -> bool {
        self.sustained
            .as_ref()
            .is_some_and(|s| s.delta_pct.abs() > SUSTAINED_DELTA_LIMIT_PCT)
    }
}

fn rel_dev(a: f64, b: f64) -> f64 {
    if a > 0.0 {
        (b - a).abs() / a
    } else {
        f64::INFINITY
    }
}

/// docs/05: escalate an abbreviated calibration to a full one if `tg128` (or `pp512`) deviates by
/// more than 10% from segment 0. A missing figure on either side is an escalation too: a machine
/// that can no longer be measured the same way has changed.
pub fn needs_escalation(segment0: &Calibration, abbreviated: &Calibration) -> bool {
    let dev = |a: &Option<Summary>, b: &Option<Summary>| match (a, b) {
        (Some(a), Some(b)) => rel_dev(a.median, b.median) > TG_DEVIATION_LIMIT,
        (None, None) => false,
        _ => true,
    };
    dev(&segment0.tg128, &abbreviated.tg128) || dev(&segment0.pp512, &abbreviated.pp512)
}

/// docs/05: if calibrated `tg128` varies by more than ±10% across segments, the run's throughput
/// metrics are flagged unstable. Measured as the largest deviation from the mean of the medians.
pub fn tg_unstable_across_segments(segments: &[Calibration]) -> bool {
    let meds: Vec<f64> = segments
        .iter()
        .filter_map(|c| c.tg128.as_ref().map(|s| s.median))
        .collect();
    if meds.len() < 2 {
        return false;
    }
    let mean = meds.iter().sum::<f64>() / meds.len() as f64;
    meds.iter().any(|m| rel_dev(mean, *m) > TG_DEVIATION_LIMIT)
}

// ---------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------

const WORDS: &[&str] = &[
    "the", "of", "and", "to", "in", "is", "that", "for", "it", "as", "was", "with", "be", "by",
    "on", "not",
];

/// `words` filler words behind a unique tag. A distinct tag per request defeats a prefix cache.
pub fn filler_prompt(tag: &str, words: usize) -> String {
    let mut s = String::with_capacity(words * 5 + tag.len() + 2);
    s.push_str(tag);
    s.push(':');
    for i in 0..words {
        s.push(' ');
        s.push_str(WORDS[i % WORDS.len()]);
    }
    s
}

/// The next word count for a prompt whose measured size was `reported` tokens at `words` words.
pub fn rescale_words(words: usize, reported: u32, target: u32) -> usize {
    if reported == 0 {
        return words;
    }
    ((words as f64) * f64::from(target) / f64::from(reported))
        .round()
        .max(1.0) as usize
}

fn within(reported: u32, target: u32) -> bool {
    (f64::from(reported) - f64::from(target)).abs() <= FIT_TOLERANCE * f64::from(target)
}

// ---------------------------------------------------------------------------
// Running it
// ---------------------------------------------------------------------------

/// A streaming client with the default retry policy, as calibration requires.
pub fn client_for(base_url: &str, model: &str) -> ModelClient {
    ModelClient::with_config(
        base_url,
        model,
        ClientConfig {
            stream: true,
            ..Default::default()
        },
    )
}

struct Ctx<'a> {
    client: &'a ModelClient,
    progress: &'a mut dyn FnMut(&str),
    tag_counter: u32,
    sources: Vec<TimingSource>,
    warnings: Vec<String>,
}

impl Ctx<'_> {
    fn tag(&mut self, kind: &str) -> String {
        self.tag_counter += 1;
        format!("cal-{kind}-{}", self.tag_counter)
    }

    fn ask(
        &mut self,
        kind: &str,
        words: usize,
        max_tokens: u32,
        ignore_eos: bool,
    ) -> Result<Completion, CalibError> {
        let tag = self.tag(kind);
        let prompt = filler_prompt(&tag, words);
        let sampling = SamplingConfig {
            max_tokens,
            seed: Some(42),
            ..Default::default()
        };
        Ok(self.client.chat(&ChatSpec {
            system: None,
            user: &prompt,
            sampling: &sampling,
            ignore_eos,
        })?)
    }

    fn note_source(&mut self, c: &Completion) {
        self.sources.push(c.timing.source);
    }
}

/// Find a word count whose *reported* prompt size is within 3% of `target`. Returns
/// `(words, reported)`; if the endpoint reports no prompt size, calibration cannot size prompts.
fn fit_prompt(ctx: &mut Ctx<'_>, target: u32) -> Result<(usize, u32), CalibError> {
    let mut words = target.saturating_sub(10).max(1) as usize;
    let mut last = 0u32;
    for _ in 0..FIT_MAX_PROBES {
        let c = ctx.ask("fit", words, 1, false)?;
        if !c.usage_reported || c.prompt_tokens == 0 {
            return Err(CalibError::NoData(
                "the endpoint reports no prompt token count, so a prompt of a known size cannot be built \
                 and pp cannot be computed (the bench-model usage_reported flag is false)"
                    .into(),
            ));
        }
        last = c.prompt_tokens;
        if within(last, target) {
            return Ok((words, last));
        }
        words = rescale_words(words, last, target);
    }
    ctx.warnings.push(format!(
        "prompt size did not converge to {target} tokens (last probe reported {last}); measuring at that size"
    ));
    Ok((words, last))
}

fn tg_request(ctx: &mut Ctx<'_>, tokens: u32) -> Result<Completion, CalibError> {
    // A short prompt that invites a long answer; EOS is ignored where the server allows it.
    ctx.ask("tg", 8, tokens, true)
}

/// Run calibration against `client` (which must stream). `progress` receives one line per phase.
pub fn run(
    client: &ModelClient,
    cfg: &CalibConfig,
    progress: &mut dyn FnMut(&str),
) -> Result<Calibration, CalibError> {
    if !client.config().stream {
        return Err(CalibError::NotStreaming);
    }
    let mut ctx = Ctx {
        client,
        progress,
        tag_counter: 0,
        sources: Vec::new(),
        warnings: Vec::new(),
    };
    let mut not_measured = vec![
        "peak_accel_mem_mb: not available over the OpenAI-compatible surface; no host probe yet"
            .to_string(),
        "peak_host_rss_mb: not available over the OpenAI-compatible surface; no host probe yet"
            .to_string(),
        "clocks / thermal events: no probe exists (Phase A has none)".to_string(),
    ];

    // 1. size the pp prompt from the endpoint's own token counts
    (ctx.progress)(&format!("sizing a ~{}-token prompt", cfg.pp_tokens));
    let fit = fit_prompt(&mut ctx, cfg.pp_tokens);
    let (pp_words, pp_reported) = match fit {
        Ok(x) => (Some(x.0), Some(x.1)),
        Err(CalibError::NoData(m)) => {
            ctx.warnings.push(m);
            (None, None)
        }
        Err(e) => return Err(e),
    };

    // 2. warm-up: tg-shaped load, discarded
    if !cfg.warmup.is_zero() {
        (ctx.progress)(&format!(
            "warm-up for {} s (discarded)",
            cfg.warmup.as_secs_f64()
        ));
        let t0 = Instant::now();
        while t0.elapsed() < cfg.warmup {
            tg_request(&mut ctx, cfg.tg_tokens)?;
        }
    }

    // 3. pp reps
    let mut pp: Vec<f64> = Vec::new();
    let mut pp_sizes: Vec<f64> = Vec::new();
    if let Some(words) = pp_words {
        (ctx.progress)(&format!("pp: {} reps", cfg.reps));
        for _ in 0..cfg.reps {
            let c = ctx.ask("pp", words, 1, false)?;
            ctx.note_source(&c);
            if c.cached_tokens.unwrap_or(0) > 0 {
                ctx.warnings.push(format!(
                    "a pp rep reported {} cached prompt tokens and was discarded (prefix cache active)",
                    c.cached_tokens.unwrap_or(0)
                ));
                continue;
            }
            match c.timing.prefill_tok_per_s {
                Some(v) => {
                    pp.push(v);
                    pp_sizes.push(f64::from(c.prompt_tokens));
                }
                None => ctx.warnings.push(
                    "a pp rep yielded no prefill rate (no server timings, and no first-token time)"
                        .into(),
                ),
            }
        }
    } else {
        not_measured.push("pp: prompt token count unavailable".to_string());
    }

    // 4. tg reps
    (ctx.progress)(&format!("tg: {} reps", cfg.reps));
    let mut tg: Vec<f64> = Vec::new();
    let mut tg_sizes: Vec<f64> = Vec::new();
    let mut short = 0u32;
    for _ in 0..cfg.reps {
        let c = tg_request(&mut ctx, cfg.tg_tokens)?;
        ctx.note_source(&c);
        match c.timing.decode_tok_per_s {
            Some(v) => {
                if f64::from(c.completion_tokens) < SHORT_GENERATION * f64::from(cfg.tg_tokens) {
                    short += 1;
                }
                tg.push(v);
                tg_sizes.push(f64::from(c.completion_tokens));
            }
            None => ctx.warnings.push(
                "a tg rep yielded no decode rate (needs server timings or a streamed reply with at least 2 tokens)"
                    .into(),
            ),
        }
    }
    if short > 0 {
        ctx.warnings.push(format!(
            "{short} tg rep(s) generated under {:.0}% of {} tokens: the server stopped early or ignores ignore_eos; \
             tg is then measured over a shorter run",
            SHORT_GENERATION * 100.0,
            cfg.tg_tokens
        ));
    }

    // 5. sustained phase
    let mut sustained = None;
    if let (Some(dur), Some(words_512)) = (cfg.sustained, pp_words) {
        (ctx.progress)(&format!("sustained phase for {} s", dur.as_secs_f64()));
        // Words per measured token at the pp size, scaled to the sustained prompt size.
        let wpt = words_512 as f64 / f64::from(pp_reported.unwrap_or(cfg.pp_tokens).max(1));
        let words = (wpt * f64::from(cfg.sustained_prompt_tokens))
            .round()
            .max(1.0) as usize;
        let mut samples = Vec::new();
        let t0 = Instant::now();
        while t0.elapsed() < dur {
            match ctx.ask("sus", words, cfg.sustained_gen_tokens, true) {
                Ok(c) => {
                    ctx.note_source(&c);
                    if let Some(v) = c.timing.decode_tok_per_s {
                        samples.push(SustainedSample {
                            end_s: t0.elapsed().as_secs_f64(),
                            tps: v,
                        });
                    }
                }
                Err(CalibError::Model(ModelError::ContextExceeded { .. })) => {
                    ctx.warnings.push(format!(
                        "sustained phase skipped: the context window is smaller than the {} + {} tokens it needs",
                        cfg.sustained_prompt_tokens, cfg.sustained_gen_tokens
                    ));
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        let dur_s = t0.elapsed().as_secs_f64();
        sustained = sustained_summary(&samples, dur_s, (dur_s / 4.0).min(60.0));
        if sustained.is_none() {
            not_measured.push("sustained: no request produced a decode rate".to_string());
        }
    } else if cfg.sustained.is_some() {
        not_measured.push("sustained: needs the pp prompt size, which was unavailable".to_string());
    } else {
        not_measured.push("sustained: not run (abbreviated tier)".to_string());
    }

    // Provenance: one source or an honest "mixed".
    let mut srcs = ctx.sources.clone();
    srcs.sort_by_key(|s| *s as u8);
    srcs.dedup();
    let timing_source = match srcs.as_slice() {
        [] => "none".to_string(),
        [TimingSource::ServerTimings] => "server_timings".to_string(),
        [TimingSource::ClientStream] => "client_stream".to_string(),
        [TimingSource::ClientWall] => "client_wall".to_string(),
        _ => {
            ctx.warnings.push(
                "timing sources differ between requests; figures are not strictly comparable"
                    .into(),
            );
            "mixed".to_string()
        }
    };
    if timing_source == "client_stream" {
        ctx.warnings.push(
            "no server timings: pp uses client time-to-first-token (includes network and one decode step); \
             tg uses streamed arrival gaps"
                .into(),
        );
    }

    let median_u32 = |xs: &[f64]| percentile(xs, 0.5).map(|m| m.round() as u32);
    let cal = Calibration {
        schema: CALIB_SCHEMA,
        tier: cfg.tier,
        warmup_s: cfg.warmup.as_secs_f64(),
        timing_source,
        pp_tokens_target: cfg.pp_tokens,
        pp_tokens_actual: median_u32(&pp_sizes),
        pp512: summarise(&pp),
        tg_tokens_target: cfg.tg_tokens,
        tg_tokens_actual: median_u32(&tg_sizes),
        tg128: summarise(&tg),
        sustained,
        drift: Drift {
            pp_pct: drift_pct(&pp),
            tg_pct: drift_pct(&tg),
        },
        peak_accel_mem_mb: None,
        peak_host_rss_mb: None,
        not_measured,
        warnings: ctx.warnings,
    };
    if cal.pp512.is_none() && cal.tg128.is_none() {
        return Err(CalibError::NoData(
            "no repetition produced a usable rate; see the warnings: ".to_string()
                + &cal.warnings.join("; "),
        ));
    }
    Ok(cal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cal(tg: Option<f64>, pp: Option<f64>) -> Calibration {
        let s = |m: f64| Summary {
            median: m,
            p5: m,
            p95: m,
            reps: 5,
        };
        Calibration {
            schema: 1,
            tier: Tier::Full,
            warmup_s: 0.0,
            timing_source: "server_timings".into(),
            pp_tokens_target: 512,
            pp_tokens_actual: None,
            pp512: pp.map(s),
            tg_tokens_target: 128,
            tg_tokens_actual: None,
            tg128: tg.map(s),
            sustained: None,
            drift: Drift {
                pp_pct: None,
                tg_pct: None,
            },
            peak_accel_mem_mb: None,
            peak_host_rss_mb: None,
            not_measured: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn percentiles_interpolate_and_ignore_non_finite() {
        let xs = [10.0, 20.0, 30.0, 40.0, f64::NAN];
        assert_eq!(percentile(&xs, 0.5), Some(25.0));
        assert_eq!(percentile(&xs, 0.0), Some(10.0));
        assert_eq!(percentile(&xs, 1.0), Some(40.0));
        assert_eq!(percentile(&[], 0.5), None);
        assert_eq!(percentile(&[7.0], 0.95), Some(7.0));
        // ten reps, as docs/05: p5 sits between the two lowest
        let ten: Vec<f64> = (1..=10).map(f64::from).collect();
        let s = summarise(&ten).unwrap();
        assert_eq!((s.median, s.reps), (5.5, 10));
        assert!((s.p5 - 1.45).abs() < 1e-9 && (s.p95 - 9.55).abs() < 1e-9);
    }

    #[test]
    fn drift_compares_halves() {
        assert_eq!(drift_pct(&[100.0, 100.0, 90.0, 90.0]), Some(-10.0));
        assert_eq!(drift_pct(&[1.0, 2.0, 3.0]), None);
        assert_eq!(
            drift_pct(&[0.0, 0.0, 1.0, 1.0]),
            None,
            "no division by a zero baseline"
        );
    }

    #[test]
    fn sustained_windows_and_fallback() {
        let s = |end_s, tps| SustainedSample { end_s, tps };
        let samples = [s(10.0, 50.0), s(20.0, 48.0), s(80.0, 40.0), s(95.0, 38.0)];
        // 100 s phase, 25 s windows: early {50,48} -> 49, late {38} (95 >= 75; 80 too) -> {40,38} 39
        let r = sustained_summary(&samples, 100.0, 25.0).unwrap();
        assert_eq!(
            (r.minute_1_tps, r.minute_10_tps, r.requests),
            (49.0, 39.0, 4)
        );
        assert!(
            (r.delta_pct - (-20.408163265306122)).abs() < 1e-9,
            "{}",
            r.delta_pct
        );
        // requests longer than the window: first / last stand in
        let long = [s(40.0, 30.0), s(80.0, 24.0)];
        let r = sustained_summary(&long, 100.0, 5.0).unwrap();
        assert_eq!((r.minute_1_tps, r.minute_10_tps), (30.0, 24.0));
        assert!(sustained_summary(&[], 10.0, 1.0).is_none());
        assert!(
            r.clock_start_mhz.is_none() && r.throttle_events.is_none(),
            "unprobed stays null"
        );
    }

    #[test]
    fn escalation_follows_docs_05() {
        let seg0 = cal(Some(40.0), Some(800.0));
        assert!(
            !needs_escalation(&seg0, &cal(Some(43.0), Some(820.0))),
            "7.5% is within 10%"
        );
        assert!(
            needs_escalation(&seg0, &cal(Some(35.0), Some(800.0))),
            "-12.5% escalates"
        );
    }

    #[test]
    fn escalation_boundary_and_missing_figures() {
        let seg0 = cal(Some(100.0), Some(1000.0));
        assert!(
            !needs_escalation(&seg0, &cal(Some(110.0), Some(1000.0))),
            "exactly 10% does not escalate"
        );
        assert!(needs_escalation(&seg0, &cal(Some(110.1), Some(1000.0))));
        assert!(
            needs_escalation(&seg0, &cal(Some(100.0), Some(850.0))),
            "pp deviation escalates too"
        );
        assert!(
            needs_escalation(&seg0, &cal(None, Some(1000.0))),
            "a figure that vanished is a change"
        );
        assert!(!needs_escalation(&cal(None, None), &cal(None, None)));
    }

    #[test]
    fn segment_instability_is_deviation_from_the_mean() {
        let segs = |v: &[f64]| v.iter().map(|m| cal(Some(*m), None)).collect::<Vec<_>>();
        assert!(!tg_unstable_across_segments(&segs(&[40.0, 41.0, 39.5])));
        assert!(tg_unstable_across_segments(&segs(&[40.0, 40.0, 30.0])));
        assert!(
            !tg_unstable_across_segments(&segs(&[40.0])),
            "one segment cannot be unstable"
        );
    }

    #[test]
    fn sustained_delta_over_15_percent_flags_throughput() {
        let mut c = cal(Some(40.0), None);
        assert!(!c.throughput_unstable());
        let s = |d| Sustained {
            duration_s: 600.0,
            requests: 10,
            minute_1_tps: 40.0,
            minute_10_tps: 40.0 * (1.0 + d / 100.0),
            delta_pct: d,
            window_s: 60.0,
            clock_start_mhz: None,
            clock_end_mhz: None,
            throttle_events: None,
        };
        c.sustained = Some(s(-14.9));
        assert!(!c.throughput_unstable());
        c.sustained = Some(s(-15.1));
        assert!(c.throughput_unstable());
    }

    #[test]
    fn prompt_sizing_helpers() {
        assert_eq!(rescale_words(500, 600, 512), 427);
        assert_eq!(rescale_words(10, 0, 512), 10);
        assert!(within(520, 512) && !within(540, 512));
        let a = filler_prompt("cal-pp-1", 20);
        let b = filler_prompt("cal-pp-2", 20);
        assert_ne!(a, b, "distinct tags defeat a prefix cache");
        assert_eq!(a.split_whitespace().count(), 21);
        assert!(!a.contains('\n'));
    }

    #[test]
    fn calibration_serialises_with_nulls_for_what_was_not_measured() {
        let c = cal(Some(40.0), Some(800.0));
        let v = serde_json::to_value(&c).unwrap();
        assert!(v["peak_accel_mem_mb"].is_null() && v["peak_host_rss_mb"].is_null());
        assert_eq!(v["tg128"]["median"], 40.0);
        assert_eq!(v["tier"], "full");
        let back: Calibration = serde_json::from_value(v).unwrap();
        assert_eq!(back, c);
    }
}
