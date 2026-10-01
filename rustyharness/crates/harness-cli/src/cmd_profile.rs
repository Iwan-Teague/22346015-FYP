//! The `profile check` verb: the smoke eval against a live model server,
//! and the stamp to add to the profile (not a gate child).

use std::time::{Duration, Instant};

use harness_model::client::{ClientConfig, OpenAiCompatible};
use harness_model::profile::{CheckResult, Profile};

use crate::args::{options, USAGE};
use crate::inputs::read_input;
use crate::report::exit;
use crate::Cx;

pub(crate) fn profile_check(cx: &Cx<'_>, rest: &[&str]) -> u8 {
    let o = match options(rest, &["profile", "endpoint"]) {
        Ok(o) => o,
        Err(e) => {
            note!(cx, "{e}\n{USAGE}");
            return exit::USAGE;
        }
    };
    let (Some(path), Some(endpoint)) = (o.get("profile"), o.get("endpoint")) else {
        note!(cx, "--profile and --endpoint are required\n{USAGE}");
        return exit::USAGE;
    };
    let profile = match read_input(path).and_then(|b| Profile::parse(&b).map_err(|e| e.to_string()))
    {
        Ok(p) => p,
        Err(e) => {
            note!(cx, "{e}");
            return exit::UNREADABLE_INPUT;
        }
    };
    let client =
        match OpenAiCompatible::new(endpoint, profile.clone(), None, ClientConfig::default()) {
            Ok(c) => c,
            Err(e) => {
                note!(cx, "endpoint refused: {e}");
                return exit::UNREADABLE_INPUT;
            }
        };
    if let Err(e) = client.startup_check(Instant::now() + Duration::from_secs(30)) {
        note!(cx, "model server check failed: {e}");
        return exit::INDETERMINATE;
    }
    let (r, verdict) = harness_model::smoke::run(&client, &profile, Duration::from_secs(120));
    note!(cx,
        "profile check: {} case(s), {} valid tool call(s), {} format error(s), {} failed call(s); edit format unchecked",
        r.cases, r.valid_tool_calls, r.format_errors, r.call_failures
    );
    match verdict {
        CheckResult::Stamp(s) => {
            say!(
                cx,
                "{}",
                serde_json::json!({"validated": {
                    "report_sha256": s.report_sha256,
                    "stamp_sha256": s.stamp_sha256,
                }})
            );
            note!(cx, "add the \"validated\" object above to the profile");
            exit::PASSED
        }
        CheckResult::NoStamp(why) => {
            note!(cx, "no stamp: {why}");
            exit::FAILED
        }
    }
}
