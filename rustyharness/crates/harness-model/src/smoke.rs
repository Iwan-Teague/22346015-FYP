//! The `profile check` smoke eval (design §3.4): a fixed set of cases sent
//! through any [`ModelBackend`], each asking for one known tool call.
//! Scoring and the stamp are [`crate::profile::score`] (pure). The CLI verb
//! `rustyharness profile check` that runs this against a live server and
//! writes the stamp into the profile file is H1e.
//!
//! Measured here: tool-call validity and format-error rate. Edit-format
//! compliance needs the edit tools (H2) and is reported as unchecked.

use std::time::{Duration, Instant};

use serde_json::json;

use crate::profile::{score, CheckResult, Profile, SmokeResults};
use crate::protocol::{parse_reply, protocol_system_text};
use crate::{HarnessText, Message, ModelBackend, ModelRequest, RenderNonce, TaskText, ToolSpec};

/// The paths the fixed cases ask for.
pub const SMOKE_PATHS: [&str; 5] = [
    "README.md",
    "src/lib.rs",
    "docs/notes.txt",
    "Cargo.toml",
    "tests/basic.rs",
];

/// The one tool offered in the smoke eval.
pub fn smoke_tool() -> ToolSpec {
    ToolSpec {
        id: "harness.fs.read".into(),
        description: HarnessText::from_static(
            "Read a window of lines from a file inside the workspace",
        ),
        parameters: json!({
            "type": "object", "additionalProperties": false,
            "properties": {"path": {"type": "string", "maxLength": 4096}},
            "required": ["path"]
        }),
    }
}

/// Run the fixed cases and score them.
pub fn run(
    backend: &dyn ModelBackend,
    profile: &Profile,
    per_call: Duration,
) -> (SmokeResults, CheckResult) {
    let tools = vec![smoke_tool()];
    let mut r = SmokeResults {
        cases: 0,
        valid_tool_calls: 0,
        format_errors: 0,
        call_failures: 0,
    };
    for (i, path) in SMOKE_PATHS.iter().enumerate() {
        r.cases += 1;
        let Some(nonce) = RenderNonce::new(&format!("{:016x}", i + 1)) else {
            r.call_failures += 1;
            continue;
        };
        let req = ModelRequest {
            messages: vec![
                Message::System(protocol_system_text(profile.protocol(), &tools)),
                Message::Task(TaskText::new(format!(
                    "Read the file {path} with harness.fs.read. Do nothing else."
                ))),
            ],
            tools: tools.clone(),
            nonce,
        };
        let completion = match backend.complete(&req, Instant::now() + per_call) {
            Ok(c) => c,
            Err(_) => {
                r.call_failures += 1;
                continue;
            }
        };
        match parse_reply(&completion, profile.protocol(), &tools) {
            Ok(p) => {
                let expected = json!({"path": path});
                if p.action.tool == "harness.fs.read"
                    && serde_json::Value::Object(p.action.args) == expected
                {
                    r.valid_tool_calls += 1;
                }
            }
            Err(_) => r.format_errors += 1,
        }
    }
    let verdict = score(profile, &r);
    (r, verdict)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scripted::{text_reply, tool_reply, ScriptedBackend};

    #[test]
    fn a_model_that_follows_the_protocol_gets_a_stamp() {
        let p = Profile::conservative_default("m");
        let replies = SMOKE_PATHS
            .iter()
            .map(|path| {
                Ok(text_reply(&format!(
                    "ok <action>{{\"tool\":\"harness.fs.read\",\"args\":{{\"path\":\"{path}\"}}}}</action>"
                )))
            })
            .collect();
        let (r, v) = run(
            &ScriptedBackend::new(p.clone(), replies),
            &p,
            Duration::from_secs(1),
        );
        assert_eq!(r.valid_tool_calls, 5);
        assert!(matches!(v, CheckResult::Stamp(_)));
    }

    #[test]
    fn a_model_that_breaks_the_protocol_gets_none() {
        let p = Profile::conservative_default("m");
        // Native tool calls in text mode, and free text: format errors.
        let replies = vec![
            Ok(tool_reply("harness_fs_read", "{\"path\":\"README.md\"}")),
            Ok(text_reply("I read it.")),
            Ok(text_reply("<action>{\"tool\":\"harness.fs.read\",\"args\":{\"path\":\"docs/notes.txt\"}}</action>")),
            Ok(text_reply("<action>{\"tool\":\"harness.fs.read\",\"args\":{\"path\":\"WRONG\"}}</action>")),
            Err(crate::ModelError::Empty),
        ];
        let (r, v) = run(
            &ScriptedBackend::new(p.clone(), replies),
            &p,
            Duration::from_secs(1),
        );
        assert_eq!(
            (r.valid_tool_calls, r.format_errors, r.call_failures),
            (1, 2, 1)
        );
        assert!(matches!(v, CheckResult::NoStamp(_)));
    }
}
