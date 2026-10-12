//! `rustybench calibrate` — docs/05 Phase B (pp512 / tg128 / sustained) against a live endpoint.
//!
//! This sends real load to `--model`. It is never run by tests (they use the in-repo mock); point
//! it at a model you are happy to occupy for the duration (full tier: ~15 minutes).

use bench_hw::calibrate::{client_for, run, CalibConfig, Calibration};
use clap::{Args, ValueEnum};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum TierArg {
    /// Warm-up + 10 reps + sustained phase (docs/05 segment 0).
    Full,
    /// Warm-up + 5 reps, no sustained phase (docs/05 segments 1..n).
    Abbreviated,
}

#[derive(Args, Debug)]
pub struct CalibrateArgs {
    /// OpenAI-compatible base URL, e.g. http://localhost:8080
    #[arg(long)]
    pub model: String,
    #[arg(long, default_value = "local")]
    pub model_name: String,
    #[arg(long, value_enum, default_value = "full")]
    pub tier: TierArg,
    /// Override the warm-up length (seconds; docs/05: 60).
    #[arg(long)]
    pub warmup_secs: Option<u64>,
    /// Override the repetition count (docs/05: 10 full, 5 abbreviated).
    #[arg(long)]
    pub reps: Option<u32>,
    /// Override the sustained phase length in seconds (0 disables; docs/05: 600).
    #[arg(long)]
    pub sustained_secs: Option<u64>,
    /// Write the result as JSON (docs/12 `segments/<n>/calib.json` shape).
    #[arg(long)]
    pub out: Option<PathBuf>,
}

pub fn config_of(a: &CalibrateArgs) -> CalibConfig {
    let mut c = match a.tier {
        TierArg::Full => CalibConfig::full(),
        TierArg::Abbreviated => CalibConfig::abbreviated(),
    };
    if let Some(w) = a.warmup_secs {
        c.warmup = Duration::from_secs(w);
    }
    if let Some(r) = a.reps {
        c.reps = r.max(1);
    }
    if let Some(s) = a.sustained_secs {
        c.sustained = (s > 0).then(|| Duration::from_secs(s));
    }
    c
}

fn line(label: &str, s: &Option<bench_hw::calibrate::Summary>, unit: &str) -> String {
    match s {
        Some(s) => format!(
            "  {label:<6} median {:>10.1}  p5 {:>10.1}  p95 {:>10.1} {unit}  ({} reps)",
            s.median, s.p5, s.p95, s.reps
        ),
        None => format!("  {label:<6} not measured"),
    }
}

pub fn render(c: &Calibration) -> String {
    let mut o = format!(
        "calibration ({:?} tier, timing source: {})\n",
        c.tier, c.timing_source
    );
    o.push_str(&line("pp", &c.pp512, "tok/s"));
    if let Some(n) = c.pp_tokens_actual {
        o.push_str(&format!(
            "   [prompt: {n} tokens reported by the endpoint, target {}]",
            c.pp_tokens_target
        ));
    }
    o.push('\n');
    o.push_str(&line("tg", &c.tg128, "tok/s"));
    if let Some(n) = c.tg_tokens_actual {
        o.push_str(&format!(
            "   [generated {n} tokens, target {}]",
            c.tg_tokens_target
        ));
    }
    o.push('\n');
    if let Some(s) = &c.sustained {
        o.push_str(&format!(
            "  sustained {:.0} s, {} requests: early {:.1} -> late {:.1} tok/s ({:+.1}%){}\n",
            s.duration_s,
            s.requests,
            s.minute_1_tps,
            s.minute_10_tps,
            s.delta_pct,
            if c.throughput_unstable() {
                "  THROUGHPUT UNSTABLE (>15%)"
            } else {
                ""
            }
        ));
    }
    if let (Some(p), Some(t)) = (c.drift.pp_pct, c.drift.tg_pct) {
        o.push_str(&format!("  drift across reps: pp {p:+.1}%, tg {t:+.1}%\n"));
    }
    for w in &c.warnings {
        o.push_str(&format!("  warning: {w}\n"));
    }
    for m in &c.not_measured {
        o.push_str(&format!("  not measured: {m}\n"));
    }
    o
}

pub fn run_cmd(a: &CalibrateArgs) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config_of(a);
    let client = client_for(&a.model, &a.model_name);
    let cal = run(&client, &cfg, &mut |l| eprintln!("calibrate: {l}"))?;
    print!("{}", render(&cal));
    if let Some(p) = &a.out {
        if let Some(d) = p.parent() {
            if !d.as_os_str().is_empty() {
                std::fs::create_dir_all(d)?;
            }
        }
        std::fs::write(p, serde_json::to_string_pretty(&cal)? + "\n")?;
        eprintln!("wrote {}", p.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bench_hw::calibrate::Tier;

    fn args(tier: TierArg) -> CalibrateArgs {
        CalibrateArgs {
            model: "http://x".into(),
            model_name: "m".into(),
            tier,
            warmup_secs: None,
            reps: None,
            sustained_secs: None,
            out: None,
        }
    }

    #[test]
    fn tiers_follow_docs_05_and_overrides_apply() {
        let f = config_of(&args(TierArg::Full));
        assert_eq!(
            (f.reps, f.warmup.as_secs(), f.sustained.map(|d| d.as_secs())),
            (10, 60, Some(600))
        );
        assert_eq!((f.pp_tokens, f.tg_tokens), (512, 128));
        let a = config_of(&args(TierArg::Abbreviated));
        assert_eq!((a.reps, a.warmup.as_secs(), a.sustained), (5, 60, None));
        assert_eq!(a.tier, Tier::Abbreviated);
        let mut o = args(TierArg::Full);
        o.reps = Some(0);
        o.sustained_secs = Some(0);
        o.warmup_secs = Some(1);
        let c = config_of(&o);
        assert_eq!((c.reps, c.sustained, c.warmup.as_secs()), (1, None, 1));
    }
}
