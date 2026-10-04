//! The header and record-by-record comparison of a recorded attempt with
//! its replay, and where the two first disagree.

use std::borrow::Cow;

use harness_core::MeterLimits;
use harness_journal::{EventKind, Record};
use harness_manifest::admission::{Registry, Resolved};
use harness_model::context::{CONTEXT_FORMAT, RESEARCH_CONTEXT_FORMAT, SESSION_CONTEXT_FORMAT};
use harness_model::profile::{Profile, Protocol, ToolDocs};
use harness_policy::{SessionKind, UserPolicy, SUBMIT_ID};
use harness_tools::protected::{DEFAULT_ASK, DEFAULT_DENY};
use serde_json::{Map, Value};

use crate::driver::{
    builtin_manifest_sha256, limits_fields, protected_task_digest, PortsHeader, TaskSpec,
    HEADER_INPUT_KEYS,
};

/// Where a journal and the replay first disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Divergence {
    /// The recorded record's sequence number (0 = the header).
    pub seq: u64,
    /// Its loop step.
    pub step: u64,
    /// What differs (harness text).
    pub why: &'static str,
}

pub(crate) fn diverge(seq: u64, step: u64, why: &'static str) -> Divergence {
    Divergence { seq, step, why }
}

/// The header values an audit or a resume recomputes from its own inputs
/// (task grants, workspace declaration, protocol, profile, policy, number
/// of checks, budget limits), as the header writes them. `session` is the
/// session's turn limits (P-05 §1.4); `None` recomputes a batch header,
/// which carries neither `mode` nor `turn_limits`. `ports` is the task's
/// port grant (P-36g §6.1); a resume recomputes it with a fresh probe, an
/// audit re-states the recorded one (the probe's observation is a past
/// host's), and `None` recomputes a header without ports. `parent` and
/// `child` are a child run's delegation header inputs (P-38); `None` for
/// both recomputes a header without them, as the header writes it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn expected_inputs(
    spec: &TaskSpec,
    registry: &Registry,
    policy: &UserPolicy,
    profile: &Profile,
    limits: &MeterLimits,
    session: Option<&crate::session::TurnLimits>,
    ports: Option<&PortsHeader>,
    instructions: Option<&crate::session::Instructions>,
    parent: Option<&crate::driver::ParentLink>,
    child: Option<&crate::driver::ChildHeader>,
) -> Map<String, Value> {
    let mut grants: Vec<Value> = Vec::new();
    let mut names: Vec<&str> = spec.grants.iter().map(String::as_str).collect();
    if !names.contains(&SUBMIT_ID) {
        names.push(SUBMIT_ID);
    }
    for g in names {
        if let Resolved::One { capability, .. } = registry.resolve(g) {
            grants.push(Value::from(capability.id().as_str()));
        }
    }
    let mut m = Map::new();
    m.insert(
        "task".into(),
        Value::from(harness_core::sha256(spec.task.as_str().as_bytes()).to_string()),
    );
    m.insert("grants".into(), Value::Array(grants));
    m.insert(
        "workspace_public".into(),
        Value::Bool(spec.workspace_public),
    );
    m.insert(
        "protocol".into(),
        Value::from(match profile.protocol() {
            Protocol::Text => "text",
            Protocol::Native => "native",
        }),
    );
    m.insert(
        "profile".into(),
        Value::from(profile.content_sha256().to_string()),
    );
    m.insert("policy".into(), Value::from(policy.digest().to_string()));
    m.insert("checks".into(), Value::from(0u64));
    m.insert(
        "builtin_manifest".into(),
        Value::from(builtin_manifest_sha256().to_string()),
    );
    // P-53: the terse table's digest, when the profile asks for terse
    // tool docs; no key without it, as the header writes it.
    if profile.tool_docs() == ToolDocs::Terse {
        m.insert(
            "tool_docs".into(),
            Value::from(crate::driver::terse_table_sha256().to_string()),
        );
    }
    // P-31, Q-3: the hosted declaration; no key for a local model, as the
    // header writes it, so every journal written before P-31 compares as
    // before.
    if profile.hosted() {
        m.insert(
            "endpoint_class".into(),
            Value::from("loopback-proxy-hosted"),
        );
    }
    // The exec allowlist (H2d): whether a shell is on it, and the spec's
    // digest; no `exec` key without one, as the header writes it.
    m.insert(
        "shell_enabled".into(),
        Value::Bool(spec.exec.as_ref().is_some_and(|e| e.shell_enabled())),
    );
    // The protected paths (P-29), as the header writes them: the task's
    // declared globs as a digest, and this build's defaults listed.
    m.insert(
        "protected".into(),
        Value::Object({
            let mut o = Map::new();
            o.insert(
                "task".into(),
                Value::from(protected_task_digest(&spec.protected).to_string()),
            );
            o.insert(
                "deny_default".into(),
                Value::Array(DEFAULT_DENY.iter().map(|g| Value::from(*g)).collect()),
            );
            o.insert(
                "ask_default".into(),
                Value::Array(DEFAULT_ASK.iter().map(|g| Value::from(*g)).collect()),
            );
            o
        }),
    );
    if let Some(e) = &spec.exec {
        let mut o = Map::new();
        o.insert("spec".into(), Value::from(e.digest().to_string()));
        o.insert("programs".into(), Value::from(e.programs.len() as u64));
        m.insert("exec".into(), Value::Object(o));
        // P-36f: an execute-class run's file work ran through the confined
        // helper, so the expected header carries the mode and the pinned
        // stub's digest, exactly as the header writes them. No key without
        // an exec grant, so in-process journals compare as before.
        let mut o = Map::new();
        o.insert("mode".into(), Value::from("confined-helper"));
        o.insert(
            "stub".into(),
            Value::from(crate::driver::header::fileop_stub_sha256().to_string()),
        );
        m.insert("file_ops".into(), Value::Object(o));
    }
    // The port grant (P-36g §6.1), as the header writes it: the granted
    // ports, their LAN subset, the model's reserved ports and the probe's
    // digest; no key without a grant.
    if let Some(p) = ports {
        let nums = |v: &[u16]| Value::Array(v.iter().map(|x| Value::from(u64::from(*x))).collect());
        m.insert(
            "ports".into(),
            Value::Object({
                let mut o = Map::new();
                o.insert("loopback".into(), nums(&p.loopback));
                o.insert("lan".into(), nums(&p.lan));
                o.insert("reserved".into(), nums(&p.reserved));
                o.insert("probe".into(), Value::from(p.probe.to_string()));
                o
            }),
        );
    }
    // The pre-submit checks (H3a): no key without them, as the header writes it.
    if let Some(p) = &spec.presubmit {
        m.insert("presubmit".into(), p.header_value());
    }
    // The post-edit checks (P-27): the same.
    if let Some(p) = &spec.post_edit {
        m.insert("post_edit".into(), p.header_value());
    }
    m.insert(
        "context_format".into(),
        Value::from(match &spec.kind {
            // A research session's contexts are the research ones (P-39i),
            // whatever the turn limits say.
            SessionKind::Research(_) => RESEARCH_CONTEXT_FORMAT,
            SessionKind::Coding => match session {
                Some(_) => SESSION_CONTEXT_FORMAT,
                None => CONTEXT_FORMAT,
            },
        }),
    );
    m.insert(
        "limits".into(),
        Value::Object(
            limits_fields(limits)
                .into_iter()
                .map(|(k, v)| (k.to_owned(), Value::from(v)))
                .collect(),
        ),
    );
    // P-05 §1.4: a session's mode and turn limits; no key without them,
    // as the header writes it, so a batch header compares as before.
    if let Some(t) = session {
        m.insert("mode".into(), Value::from("session"));
        m.insert(
            "turn_limits".into(),
            Value::Object(
                [
                    ("steps", u64::from(t.steps)),
                    ("format_errors", u64::from(t.format_errors)),
                ]
                .into_iter()
                .map(|(k, v)| (k.to_owned(), Value::from(v)))
                .collect(),
            ),
        );
    }
    // P-39i: a research session's kind and web grant; no key without them,
    // as the header writes it (the web grant as its canonical digest, the
    // allowlist being run input), so a coding journal compares as before.
    if let SessionKind::Research(g) = &spec.kind {
        m.insert("session_kind".into(), Value::from("research"));
        m.insert(
            "web".into(),
            Value::from(crate::driver::web_grant_digest(g).to_string()),
        );
    }
    // P-30: the trusted project instructions' digest; no key when none
    // were loaded, as the header writes it, so older journals compare as
    // before.
    if let Some(n) = instructions {
        m.insert("instructions".into(), Value::from(n.digest.to_string()));
    }
    // P-38: a child run's delegation inputs, exactly as its header writes
    // them; no key without a delegation, as the header writes it.
    if let Some(p) = parent {
        m.insert(
            "parent".into(),
            Value::Object({
                let mut o = Map::new();
                o.insert("run".into(), Value::from(p.run.to_string()));
                o.insert("attempt".into(), Value::from(u64::from(p.attempt)));
                o.insert("step".into(), Value::from(p.step));
                o.insert("intent_hash".into(), Value::from(p.intent_hash.to_string()));
                o
            }),
        );
    }
    if let Some(c) = child {
        m.insert(
            "child".into(),
            Value::Object({
                let mut o = Map::new();
                o.insert("template".into(), Value::from(c.template.to_string()));
                o.insert("brief".into(), Value::from(c.brief.to_string()));
                // The nonce text, as the header's `Trusted::Id(Ident)`
                // writes it (the header refuses to start unless the nonce
                // fits the identifier grammar, and `Nonce::new` checked the
                // same before it).
                o.insert("brief_nonce".into(), Value::from(c.brief_nonce.as_str()));
                o.insert("limits_wall_ms".into(), Value::from(c.limits_wall_ms));
                o
            }),
        );
        // A child run's header names its mode; a batch parent journal has
        // no `mode` key, so it is only expected here (P-38f).
        m.insert("mode".into(), Value::from("child"));
    }
    m
}

pub(crate) fn check_header(
    recorded: &Record,
    expected: &Map<String, Value>,
) -> Result<(), Divergence> {
    for k in HEADER_INPUT_KEYS {
        if recorded.body.get(k) != expected.get(k) {
            return Err(diverge(0, 0, header_mismatch(k)));
        }
    }
    Ok(())
}

/// What a differing header input means (H1f-3 review F-5): most are the
/// caller's inputs; `builtin_manifest`, `shell_enabled` and
/// `context_format` belong to the harness build, so a journal written by
/// another build (every journal from before H1f-3 included, and, for the
/// context format, every journal from before H1h) cannot be audited or
/// resumed by this one, and says so.
fn header_mismatch(key: &str) -> &'static str {
    match key {
        "task" => "the task given differs from the recorded header",
        "grants" => "the grants given differ from the recorded header",
        "workspace_public" => "the workspace declaration differs from the recorded header",
        "protocol" | "profile" => "the profile given differs from the recorded header",
        "policy" => "the policy given differs from the recorded header",
        "checks" => "the verification plan differs from the recorded header",
        "limits" => "the budget limits given differ from the recorded header",
        "builtin_manifest" => {
            "another harness build wrote this journal (its built-in manifest differs)"
        }
        "shell_enabled" | "exec" => "the exec allowlist given differs from the recorded header",
        "ports" => {
            "the port grants (loopback, lan, reserved or the probe's ports) differ from the \
             recorded header"
        }
        "file_ops" => "another harness build wrote this journal (its file-op mode or stub differs)",
        "presubmit" => "the pre-submit checks given differ from the recorded header",
        "post_edit" => "the post-edit checks given differ from the recorded header",
        "protected" => {
            "the protected-path lists (task-declared or this build's defaults) differ from the \
             recorded header"
        }
        "mode" => "the run's mode (batch, session or child) differs from the recorded header",
        "parent" => "the run's parent link differs from the recorded header",
        "child" => "the child's brief, template or wall limit differs from the recorded header",
        "turn_limits" => "the turn limits given differ from the recorded header",
        "session_kind" => "the session kind differs from the recorded header",
        "web" => "the web grant (allowlist, search, confirmation) differs from the recorded header",
        "instructions" => "the project instructions differ from the recorded header",
        "endpoint_class" => {
            "the profile's endpoint class (local or hosted) differs from the recorded header"
        }
        "context_format" => {
            "another harness build wrote this journal (its context format differs: since H1h the \
             native protocol shows past actions as tool calls, since H1i each observation keeps \
             its own delimiter nonce and the context is append-mostly, and since H2e a turn may \
             carry a budget notice, is first shown with a cap that holds one whole read, and a \
             format error's repair message names its fault, so an older journal's contexts and \
             requests cannot be recomputed; audit it with the build that wrote it)"
        }
        _ => "a header input differs from the recorded header",
    }
}

/// A wall-budget condition record: when the clock crossed 80% of the wall
/// budget is not recomputable, so the comparison leaves these out.
fn is_wall_condition(r: &Record) -> bool {
    r.kind == EventKind::BudgetCharged && r.body.get("key").and_then(Value::as_str) == Some("wall")
}

/// Check the recorded wall-budget condition records before they are left
/// out of the comparison (H1 phase-exit review F-1): each must be exactly
/// what the loop writes (`StandingConditions::observe`). For the wall
/// dimension that is at most one record per attempt, the entry
/// `{condition: enter, key: wall}`: the meter's wall time never decreases
/// within an attempt and its limit is fixed, so the 80% condition turns
/// true at most once and never turns false again, and the loop never
/// writes a wall exit (H1g confirming review NF-1). A second record, an
/// exit, or any other body is a record the loop did not write. Returns
/// how many were left out (0 or 1).
pub(crate) fn check_wall_conditions(recorded: &[Record]) -> Result<usize, Divergence> {
    let mut n = 0;
    for r in recorded.iter().filter(|r| is_wall_condition(r)) {
        let b = &r.body;
        let loop_wrote =
            n == 0 && b.len() == 2 && b.get("condition").and_then(Value::as_str) == Some("enter");
        if !loop_wrote {
            return Err(diverge(
                r.seq,
                r.step,
                "a wall-budget record is not one the loop writes",
            ));
        }
        n += 1;
    }
    Ok(n)
}

/// How a recorded attempt compared with its replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Compared {
    /// Records that matched (header and wall-budget records excluded).
    pub(crate) matched: usize,
    /// Wall-budget condition records left out of the comparison, each
    /// checked to be a record the loop writes.
    pub(crate) wall_skipped: usize,
    /// Whether the recorded stop itself was recomputed: false for a
    /// wall-budget stop (the clock is not replayable) and for an attempt
    /// that never committed.
    pub(crate) stop_recomputed: bool,
}

/// Compare the recorded attempt with its replay, header excluded: the
/// first divergence in record order, whether it is a record the replay
/// recomputed differently or a wall-budget record the loop does not write.
pub(crate) fn compare(recorded: &[Record], replayed: &[Record]) -> Result<Compared, Divergence> {
    match (
        check_wall_conditions(recorded),
        compare_recomputed(recorded, replayed),
    ) {
        (Ok(wall_skipped), Ok(c)) => Ok(Compared { wall_skipped, ..c }),
        (Err(w), Err(d)) => Err(if w.seq < d.seq { w } else { d }),
        (Err(w), Ok(_)) => Err(w),
        (Ok(_), Err(d)) => Err(d),
    }
}

/// The seqs of a journal's wall-budget condition records, in order.
fn wall_seqs(records: &[Record]) -> Vec<u64> {
    records
        .iter()
        .filter(|r| is_wall_condition(r))
        .map(|r| r.seq)
        .collect()
}

/// A body as the comparison sees it. A result's `intent_seq` (the seq of
/// the intent it answers) is counted among the records compared, without
/// the wall-budget records before it: the replay writes none, so each one
/// the recorded journal holds shifts every later seq by one, and a run
/// that crossed 80% of its wall budget before a later tool result would
/// otherwise never match (found fixing H1 phase-exit review F-1). One
/// that points at a wall-budget record points at no intent: it never
/// matches.
fn compared_body<'r>(r: &'r Record, walls: &[u64]) -> Cow<'r, Map<String, Value>> {
    match r.body.get("intent_seq").and_then(Value::as_u64) {
        Some(n) => {
            let counted = match walls.binary_search(&n) {
                Ok(_) => Value::Null,
                Err(before) => Value::from(n.saturating_sub(before as u64)),
            };
            let mut b = r.body.clone();
            b.insert("intent_seq".into(), counted);
            Cow::Owned(b)
        }
        None => Cow::Borrowed(&r.body),
    }
}

/// Compare every recorded record the replay recomputes (all but the header
/// and the wall-budget records) with the replay's.
fn compare_recomputed(recorded: &[Record], replayed: &[Record]) -> Result<Compared, Divergence> {
    let (rec_walls, rep_walls) = (wall_seqs(recorded), wall_seqs(replayed));
    let rec: Vec<&Record> = recorded
        .iter()
        .skip(1)
        .filter(|r| !is_wall_condition(r))
        .collect();
    let rep: Vec<&Record> = replayed
        .iter()
        .skip(1)
        .filter(|r| !is_wall_condition(r))
        .collect();
    let (rec_body, rec_stop) = match rec.split_last() {
        Some((last, body)) if last.kind == EventKind::RunStopped => (body, Some(*last)),
        _ => (rec.as_slice(), None),
    };
    for (i, r) in rec_body.iter().enumerate() {
        let Some(p) = rep.get(i) else {
            return Err(diverge(
                r.seq,
                r.step,
                "the replay stopped before this recorded record",
            ));
        };
        if p.kind != r.kind || p.step != r.step {
            return Err(diverge(
                r.seq,
                r.step,
                "the replay wrote a different record here",
            ));
        }
        if compared_body(p, &rep_walls) != compared_body(r, &rec_walls) {
            return Err(diverge(
                r.seq,
                r.step,
                "the replay recomputed a different body for this record",
            ));
        }
    }
    let Some(stop) = rec_stop else {
        // An attempt that never committed: its recorded prefix matched.
        return Ok(Compared {
            matched: rec_body.len(),
            wall_skipped: 0,
            stop_recomputed: false,
        });
    };
    let s = |r: &Record, k: &str| r.body.get(k).cloned();
    if s(stop, "cause") == Some(Value::from("budget"))
        && s(stop, "dimension") == Some(Value::from("wall"))
    {
        // The wall clock is not replayable. Every recorded record matched,
        // but the stop was NOT recomputed: a journal cut at any step and
        // ended with a forged wall stop (re-chained) looks exactly like
        // this, so the caller must not call it verified without an anchor
        // (H1e-2b review F-1).
        return Ok(Compared {
            matched: rec_body.len(),
            wall_skipped: 0,
            stop_recomputed: false,
        });
    }
    let Some(p) = rep.get(rec_body.len()) else {
        return Err(diverge(stop.seq, stop.step, "the replay did not stop here"));
    };
    if p.kind != EventKind::RunStopped || rep.len() != rec_body.len() + 1 {
        return Err(diverge(
            stop.seq,
            stop.step,
            "the replay went on past the recorded stop",
        ));
    }
    if p.body != stop.body || p.step != stop.step {
        return Err(diverge(
            stop.seq,
            stop.step,
            "the replay stopped for another reason or with another outcome",
        ));
    }
    Ok(Compared {
        matched: rec_body.len() + 1,
        wall_skipped: 0,
        stop_recomputed: true,
    })
}
