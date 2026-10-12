//! Scheduling controls for `run-suite` (docs/09 "Scheduling controls"): `--max-duration`,
//! `--until`, `--max-units`, `--pause-on-battery`.
//!
//! Every control is **polled at a unit boundary** by the run loop, through the same clean-stop path
//! as the first `SIGINT`: the unit in flight always finishes and is journalled, the segment closes,
//! the lock is released, exit status 0. A control can therefore overshoot its limit by at most one
//! unit; it can never leave a torn line, because nothing here interrupts anything.
//!
//! Probes (elapsed time, wall clock, local time of day, power source) sit behind [`Env`] so the
//! decision logic is tested with a fake and no real waiting. The real [`SystemEnv`] additionally
//! honours `RUSTBENCH_SCHEDULE_FAKE=<json file>`, re-read at every poll, so end-to-end tests can
//! drive the real binary deterministically (fields `elapsed_s`, `now_unix`, `local_hms`,
//! `battery`: `"ac"` | `"battery"` | `"unknown"`; absent fields fall back to the real probe).
//!
//! **Not implemented, deliberately:** `--idle-only` (see OPEN-QUESTIONS Q34: docs/09 defines neither
//! "idle" nor whether a busy machine pauses or ends the segment), `--pause-on-thermal` (no thermal
//! probe exists), `--resume-daily` (marked v2).

use std::time::{Duration, Instant};

#[derive(clap::Args, Debug, Default, Clone)]
pub struct ScheduleArgs {
    /// Stop cleanly after this much execution time in this session (e.g. `4h`, `90m`, `1h30m`,
    /// `3600`). Checked between units, so the last unit may finish after the limit.
    #[arg(long, value_parser = parse_duration)]
    pub max_duration: Option<Duration>,
    /// Stop cleanly at this local wall-clock time, `HH:MM` (the next time it occurs).
    #[arg(long, value_parser = parse_hm)]
    pub until: Option<(u32, u32)>,
    /// Stop cleanly after this many units in this session.
    #[arg(long)]
    pub max_units: Option<usize>,
    /// Checkpoint and exit if the machine is running on battery (also at start).
    #[arg(long)]
    pub pause_on_battery: bool,
}

/// Why a session ended early. The labels follow docs/09's `exit_reason` where it has one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    MaxDuration,
    UntilTime,
    /// Not in docs/09's `exit_reason` enum (Q34).
    MaxUnits,
    Battery,
}

impl StopReason {
    pub fn label(self) -> &'static str {
        match self {
            StopReason::MaxDuration => "max_duration",
            StopReason::UntilTime => "until_time",
            StopReason::MaxUnits => "max_units",
            StopReason::Battery => "battery",
        }
    }
}

/// What the schedule needs to know about the world.
pub trait Env {
    /// Execution time since the session started.
    fn elapsed(&self) -> Duration;
    /// Wall clock, seconds since the Unix epoch.
    fn now_unix(&self) -> u64;
    /// Local time of day `(h, m, s)`, if it can be determined.
    fn local_hms(&self) -> Option<(u32, u32, u32)>;
    /// `Some(true)` on battery, `Some(false)` on AC, `None` if unknown (a desktop, no probe).
    fn on_battery(&self) -> Option<bool>;
}

#[derive(Clone, Debug)]
pub struct Schedule {
    max_duration: Option<Duration>,
    until: Option<(u32, u32)>,
    max_units: Option<usize>,
    pause_on_battery: bool,
    /// Absolute stop time for `--until`, fixed when the session starts.
    until_deadline_unix: Option<u64>,
}

/// Seconds from local time-of-day `now` until the next occurrence of `target` (`HH:MM`). If the
/// time is exactly now, it means tomorrow: a session started at 07:30:00 with `--until 07:30`
/// is a request to run through the night, not to stop at once.
pub fn secs_until(now: (u32, u32, u32), target: (u32, u32)) -> u64 {
    let day = 24 * 3600u64;
    let n = u64::from(now.0) * 3600 + u64::from(now.1) * 60 + u64::from(now.2);
    let t = u64::from(target.0) * 3600 + u64::from(target.1) * 60;
    let d = (t + day - n % day) % day;
    if d == 0 {
        day
    } else {
        d
    }
}

impl Schedule {
    pub fn from_args(a: &ScheduleArgs) -> Schedule {
        Schedule {
            max_duration: a.max_duration,
            until: a.until,
            max_units: a.max_units,
            pause_on_battery: a.pause_on_battery,
            until_deadline_unix: None,
        }
    }

    /// Fix the `--until` deadline now. Errors if the local time cannot be determined: a stop time
    /// that cannot be evaluated must not be silently ignored.
    pub fn start(&mut self, env: &dyn Env) -> Result<(), String> {
        if let Some(target) = self.until {
            let now = env
                .local_hms()
                .ok_or("--until needs the local time of day, which could not be determined")?;
            self.until_deadline_unix = Some(env.now_unix() + secs_until(now, target));
        }
        Ok(())
    }

    /// Should the session stop before starting another unit? `units_done` counts units completed
    /// in this session. Checked in a fixed order so the reported reason is deterministic.
    pub fn check(&self, env: &dyn Env, units_done: usize) -> Option<StopReason> {
        if self.max_units.is_some_and(|n| units_done >= n) {
            return Some(StopReason::MaxUnits);
        }
        if self.max_duration.is_some_and(|d| env.elapsed() >= d) {
            return Some(StopReason::MaxDuration);
        }
        if self
            .until_deadline_unix
            .is_some_and(|t| env.now_unix() >= t)
        {
            return Some(StopReason::UntilTime);
        }
        if self.pause_on_battery && env.on_battery() == Some(true) {
            return Some(StopReason::Battery);
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// `4h`, `90m`, `45s`, `1h30m`, `1h30m15s`, or bare seconds. Zero is allowed (it stops before the
/// first unit); empty, negative or malformed input is an error, never silently "no limit".
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    if let Ok(n) = s.parse::<u64>() {
        return Ok(Duration::from_secs(n));
    }
    let mut total = 0u64;
    let mut num = String::new();
    let mut seen_unit = false;
    for c in s.chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let mult = match c {
            'h' | 'H' => 3600,
            'm' | 'M' => 60,
            's' | 'S' => 1,
            _ => {
                return Err(format!(
                    "`{s}` is not a duration (use e.g. 4h, 90m, 1h30m, 3600)"
                ))
            }
        };
        if num.is_empty() {
            return Err(format!(
                "`{s}` is not a duration (a unit needs a number before it)"
            ));
        }
        let n: u64 = num
            .parse()
            .map_err(|_| format!("`{s}`: number too large"))?;
        total = total
            .checked_add(n.checked_mul(mult).ok_or("duration too large")?)
            .ok_or("duration too large")?;
        num.clear();
        seen_unit = true;
    }
    if !num.is_empty() || !seen_unit {
        return Err(format!(
            "`{s}` is not a duration (trailing digits need a unit)"
        ));
    }
    Ok(Duration::from_secs(total))
}

/// `HH:MM`, 24-hour.
pub fn parse_hm(s: &str) -> Result<(u32, u32), String> {
    let (h, m) = s
        .trim()
        .split_once(':')
        .ok_or_else(|| format!("`{s}` is not a time of day (use HH:MM, 24-hour)"))?;
    let bad = || format!("`{s}` is not a time of day (use HH:MM, 24-hour)");
    let (h, m): (u32, u32) = (h.parse().map_err(|_| bad())?, m.parse().map_err(|_| bad())?);
    if h > 23 || m > 59 {
        return Err(bad());
    }
    Ok((h, m))
}

// ---------------------------------------------------------------------------
// The real world
// ---------------------------------------------------------------------------

pub struct SystemEnv {
    started: Instant,
}

impl SystemEnv {
    pub fn new() -> SystemEnv {
        SystemEnv {
            started: Instant::now(),
        }
    }

    /// The test-hook JSON, re-read each time so a test can change the world mid-run.
    fn fake(&self) -> Option<serde_json::Value> {
        let path = std::env::var_os("RUSTBENCH_SCHEDULE_FAKE")?;
        serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
    }
}

impl Default for SystemEnv {
    fn default() -> Self {
        Self::new()
    }
}

impl Env for SystemEnv {
    fn elapsed(&self) -> Duration {
        self.fake()
            .and_then(|v| v["elapsed_s"].as_f64())
            .map(Duration::from_secs_f64)
            .unwrap_or_else(|| self.started.elapsed())
    }

    fn now_unix(&self) -> u64 {
        self.fake()
            .and_then(|v| v["now_unix"].as_u64())
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs())
            })
    }

    fn local_hms(&self) -> Option<(u32, u32, u32)> {
        let from_text = |t: &str| {
            let mut p = t.trim().split(':').map(|x| x.parse::<u32>().ok());
            Some((p.next()??, p.next()??, p.next().flatten().unwrap_or(0)))
        };
        if let Some(t) = self
            .fake()
            .and_then(|v| v["local_hms"].as_str().map(str::to_string))
        {
            return from_text(&t);
        }
        let out = std::process::Command::new("date")
            .arg("+%H:%M:%S")
            .output()
            .ok()
            .filter(|o| o.status.success())?;
        from_text(&String::from_utf8_lossy(&out.stdout))
    }

    fn on_battery(&self) -> Option<bool> {
        if let Some(b) = self
            .fake()
            .and_then(|v| v["battery"].as_str().map(str::to_string))
        {
            return match b.as_str() {
                "battery" => Some(true),
                "ac" => Some(false),
                _ => None,
            };
        }
        use bench_hw::Probe;
        let out = bench_hw::SystemProbe::default().run("pmset", &["-g", "batt"])?;
        let (src, has_battery) = bench_hw::parse::parse_pmset_batt(&out);
        has_battery.then_some(src == bench_hw::PowerSource::Battery)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct Fake {
        elapsed: Cell<u64>,
        now: Cell<u64>,
        hms: Option<(u32, u32, u32)>,
        battery: Cell<Option<bool>>,
    }
    impl Fake {
        fn new() -> Fake {
            Fake {
                elapsed: Cell::new(0),
                now: Cell::new(1_000_000),
                hms: Some((23, 0, 0)),
                battery: Cell::new(Some(false)),
            }
        }
    }
    impl Env for Fake {
        fn elapsed(&self) -> Duration {
            Duration::from_secs(self.elapsed.get())
        }
        fn now_unix(&self) -> u64 {
            self.now.get()
        }
        fn local_hms(&self) -> Option<(u32, u32, u32)> {
            self.hms
        }
        fn on_battery(&self) -> Option<bool> {
            self.battery.get()
        }
    }

    fn sched(f: impl FnOnce(&mut ScheduleArgs)) -> Schedule {
        let mut a = ScheduleArgs::default();
        f(&mut a);
        Schedule::from_args(&a)
    }

    #[test]
    fn durations_parse_in_every_documented_shape_and_reject_the_rest() {
        let s = |x| parse_duration(x).map(|d| d.as_secs());
        assert_eq!(s("4h"), Ok(14_400));
        assert_eq!(s("90m"), Ok(5_400));
        assert_eq!(s("45s"), Ok(45));
        assert_eq!(s("1h30m"), Ok(5_400));
        assert_eq!(s("1h30m15s"), Ok(5_415));
        assert_eq!(s("3600"), Ok(3_600));
        assert_eq!(s("0"), Ok(0));
        assert_eq!(s(" 2H "), Ok(7_200));
        for bad in [
            "",
            "h",
            "4",
            "x",
            "4x",
            "1h30",
            "-5m",
            "1.5h",
            "m5",
            "99999999999999999999h",
        ] {
            if bad == "4" {
                continue; // bare seconds
            }
            assert!(parse_duration(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn times_of_day_are_24_hour_hh_mm() {
        assert_eq!(parse_hm("07:30"), Ok((7, 30)));
        assert_eq!(parse_hm("0:5"), Ok((0, 5)));
        assert_eq!(parse_hm("23:59"), Ok((23, 59)));
        for bad in ["24:00", "07:60", "0730", "7", "ab:cd", ":", "07:", "-1:00"] {
            assert!(parse_hm(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn until_means_the_next_occurrence_and_exactly_now_means_tomorrow() {
        assert_eq!(
            secs_until((22, 0, 0), (7, 30)),
            9 * 3600 + 30 * 60,
            "overnight"
        );
        assert_eq!(secs_until((6, 0, 0), (7, 30)), 90 * 60, "later today");
        assert_eq!(secs_until((7, 29, 50), (7, 30)), 10);
        assert_eq!(
            secs_until((7, 30, 0), (7, 30)),
            24 * 3600,
            "exactly now is tomorrow, not now"
        );
        assert_eq!(secs_until((7, 30, 1), (7, 30)), 24 * 3600 - 1);
        assert_eq!(secs_until((0, 0, 0), (0, 0)), 24 * 3600);
    }

    #[test]
    fn max_units_counts_this_session_and_zero_stops_before_the_first() {
        let env = Fake::new();
        let s = sched(|a| a.max_units = Some(3));
        assert_eq!([0, 1, 2].map(|n| s.check(&env, n)), [None, None, None]);
        assert_eq!(s.check(&env, 3), Some(StopReason::MaxUnits));
        assert_eq!(s.check(&env, 4), Some(StopReason::MaxUnits));
        assert_eq!(
            sched(|a| a.max_units = Some(0)).check(&env, 0),
            Some(StopReason::MaxUnits)
        );
    }

    #[test]
    fn max_duration_stops_at_or_after_the_limit() {
        let env = Fake::new();
        let s = sched(|a| a.max_duration = Some(Duration::from_secs(100)));
        env.elapsed.set(99);
        assert_eq!(s.check(&env, 5), None);
        env.elapsed.set(100);
        assert_eq!(s.check(&env, 5), Some(StopReason::MaxDuration));
        env.elapsed.set(10_000);
        assert_eq!(
            s.check(&env, 5),
            Some(StopReason::MaxDuration),
            "overshoot by a long unit is still a stop"
        );
    }

    #[test]
    fn until_fixes_an_absolute_deadline_at_start_and_follows_the_wall_clock() {
        let mut s = sched(|a| a.until = Some((23, 0)));
        let mut env = Fake::new();
        env.hms = Some((22, 59, 50));
        s.start(&env).unwrap();
        env.now.set(1_000_009);
        assert_eq!(s.check(&env, 0), None);
        env.now.set(1_000_010);
        assert_eq!(s.check(&env, 0), Some(StopReason::UntilTime));
        // the monotonic elapsed time is irrelevant to --until (a lid closed overnight still stops)
        env.now.set(1_000_009);
        env.elapsed.set(999_999);
        assert_eq!(s.check(&env, 0), None);
    }

    #[test]
    fn until_without_a_readable_clock_is_an_error_not_no_limit() {
        let mut s = sched(|a| a.until = Some((7, 30)));
        let mut env = Fake::new();
        env.hms = None;
        assert!(s.start(&env).unwrap_err().contains("local time"));
        // and a schedule without --until never asks
        assert!(sched(|a| a.max_units = Some(1)).start(&env).is_ok());
    }

    #[test]
    fn battery_stops_only_when_asked_and_only_when_known() {
        let env = Fake::new();
        let on = sched(|a| a.pause_on_battery = true);
        assert_eq!(on.check(&env, 0), None, "on AC");
        env.battery.set(Some(true));
        assert_eq!(
            on.check(&env, 0),
            Some(StopReason::Battery),
            "also before the first unit"
        );
        assert_eq!(
            sched(|_| {}).check(&env, 0),
            None,
            "ignored without the flag"
        );
        env.battery.set(None);
        assert_eq!(
            on.check(&env, 0),
            None,
            "unknown power state (a desktop) never stops a run"
        );
    }

    #[test]
    fn the_reported_reason_is_deterministic_when_several_apply() {
        let env = Fake::new();
        env.elapsed.set(10_000);
        env.battery.set(Some(true));
        let s = sched(|a| {
            a.max_units = Some(1);
            a.max_duration = Some(Duration::from_secs(1));
            a.pause_on_battery = true;
        });
        assert_eq!(s.check(&env, 1), Some(StopReason::MaxUnits));
        assert_eq!(s.check(&env, 0), Some(StopReason::MaxDuration));
        assert_eq!(
            [
                StopReason::MaxDuration,
                StopReason::UntilTime,
                StopReason::MaxUnits,
                StopReason::Battery
            ]
            .map(StopReason::label),
            ["max_duration", "until_time", "max_units", "battery"]
        );
    }
}
