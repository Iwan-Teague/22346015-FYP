//! The `replay` verb: an audit of a recorded run against the task, policy
//! and profile it was given, with what was re-fed and what recomputed said
//! plainly.

use std::collections::BTreeMap;

use gate_outcome::{GateOutcome, IndeterminateKind};
use harness_core::RunId;
use harness_run::Audit;

use crate::args::USAGE;
use crate::inputs::{inputs, required};
use crate::report::{exit, info, refused, Outcome};
use crate::Cx;

/// What an audit replay re-feeds and what it recomputes (H1 phase-exit
/// review, named item 2): the recorded inputs are re-fed, not re-run, so a
/// match never means every record was recomputed.
const REPLAY_SCOPE: &str = "Re-fed from the journal, not re-run: the model replies, the tool results and the environment samples. Recomputed and compared: every context, parse, loop-detector and policy decision";

/// [`REPLAY_SCOPE`] in the report's finding.
const REPLAY_SCOPE_SHORT: &str =
    "replies, tool results and samples re-fed; contexts, parses and decisions recomputed";

pub(crate) fn replay(
    cx: &Cx<'_>,
    o: &BTreeMap<&str, &str>,
    cfg: &Option<crate::config::UserConfig>,
) -> Outcome {
    match try_replay(cx, o, cfg) {
        Ok(x) | Err(x) => x,
    }
}

fn try_replay(
    cx: &Cx<'_>,
    o: &BTreeMap<&str, &str>,
    cfg: &Option<crate::config::UserConfig>,
) -> Result<Outcome, Outcome> {
    let inp = inputs(cx, o, cfg)?;
    let state_root = match crate::config::state_root(o, cfg) {
        Ok(Some(s)) => s,
        Ok(None) => {
            note!(
                cx,
                "--state-root is required here (no default state root on this platform)\n{USAGE}"
            );
            return Err(refused(exit::USAGE, "--state-root missing".into()));
        }
        Err(e) => {
            note!(cx, "{e}");
            return Err(refused(exit::UNREADABLE_INPUT, e));
        }
    };
    let usage = |what: &str| {
        note!(cx, "{what}\n{USAGE}");
        refused(exit::USAGE, what.to_owned())
    };
    let run =
        RunId::parse(required(cx, o, "run")?).ok_or_else(|| usage("--run is not a run id"))?;
    let attempt = match o.get("attempt") {
        None => None,
        Some(a) => Some(
            a.parse::<u32>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| usage("--attempt is not a positive number"))?,
        ),
    };
    let anchor = match o.get("anchor") {
        None => None,
        Some(a) => Some(
            a.parse()
                .map_err(|_| usage("--anchor is not a sha256 in hex"))?,
        ),
    };
    let rep = harness_run::audit(Audit {
        state_root: std::path::Path::new(state_root.as_ref()),
        run: &run,
        attempt,
        anchor,
        spec: &inp.spec,
        registry: &inp.registry,
        policy: &inp.policy,
        profile: &inp.profile,
        limits: &inp.config.limits,
    })
    .map_err(|e| {
        note!(cx, "the replay did not start: {e}");
        refused(
            exit::INDETERMINATE,
            format!("the replay did not start: {e}"),
        )
    })?;
    // Wall-budget records are left out of the comparison (their timing is
    // the clock's) after a shape check; say how many (review F-1).
    let (walls, walls_short) = if rep.wall_skipped == 0 {
        (String::new(), String::new())
    } else {
        (
            format!(
                " Not recomputable, checked for shape only: {} wall-budget record(s).",
                rep.wall_skipped
            ),
            format!(
                "; {} wall-budget record(s) checked for shape only",
                rep.wall_skipped
            ),
        )
    };
    let findings = match &rep.divergence {
        None if rep.stop_recomputed => {
            // H1 phase-exit review, named item 2: what was re-fed and what
            // recomputed, never "every record recomputed".
            note!(
                cx,
                "replay of run {run} attempt {}: {} records matched. {REPLAY_SCOPE}, and the stop.{walls} {}",
                rep.attempt,
                rep.matched,
                if rep.anchored {
                    "The anchor matched the journal's chain head."
                } else {
                    "Without --anchor, a journal rewritten consistently is not detected (the chain is unkeyed)."
                }
            );
            info(
                "harness.replay",
                &format!("run {run} attempt {}", rep.attempt),
                "the recorded journal",
                format!(
                    "{} records matched ({REPLAY_SCOPE_SHORT}){walls_short}{}",
                    rep.matched,
                    if rep.anchored { "; anchor matched" } else { "" }
                ),
            )
        }
        None if matches!(
            rep.outcome,
            GateOutcome::Indeterminate {
                why: IndeterminateKind::CouldNotRun
            }
        ) =>
        {
            note!(
                cx,
                "replay of run {run} attempt {}: the attempt never committed (no RunStopped); its {} records matched",
                rep.attempt,
                rep.matched
            );
            info(
                "harness.replay.incomplete",
                &format!("run {run} attempt {}", rep.attempt),
                "a committed attempt",
                format!("no RunStopped; {} records matched", rep.matched),
            )
        }
        None if rep.anchored => {
            note!(
                    cx,
                    "replay of run {run} attempt {}: {} records matched. {REPLAY_SCOPE}; the stop, a wall-budget stop, is not recomputable.{walls} The anchor matched the journal's chain head, so no record was cut from it.",
                    rep.attempt,
                    rep.matched
                );
            info(
                "harness.replay.anchored",
                &format!("run {run} attempt {}", rep.attempt),
                "the recorded journal",
                format!(
                    "{} records matched ({REPLAY_SCOPE_SHORT}){walls_short}; stop not recomputable; the anchor matched",
                    rep.matched
                ),
            )
        }
        None => {
            // H1e-2b review F-1: never "every record matched" for a
            // stop the replay could not recompute.
            note!(
                    cx,
                    "replay of run {run} attempt {}: {} records matched, but the stop was NOT recomputed: wall stop not recomputable; only --anchor proves no truncation",
                    rep.attempt,
                    rep.matched
                );
            info(
                "harness.replay.stop-unverified",
                &format!("run {run} attempt {}", rep.attempt),
                "a stop the replay recomputes, or a matching --anchor",
                "wall stop not recomputable; only --anchor proves no truncation".to_owned(),
            )
        }
        Some(d) => {
            note!(
                cx,
                "replay of run {run} attempt {}: DIVERGED at record {} (step {}): {}",
                rep.attempt,
                d.seq,
                d.step,
                d.why
            );
            info(
                "harness.replay.divergence",
                &format!(
                    "run {run} attempt {} record {} step {}",
                    rep.attempt, d.seq, d.step
                ),
                "the recorded journal",
                d.why.to_owned(),
            )
        }
    };
    Ok(Outcome {
        outcome: rep.outcome,
        findings: findings.into_iter().collect(),
        chain_head: None,
        exit_override: None,
    })
}
