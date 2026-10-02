//! The built-in manifest fragment for harness.task.delegate.
//!
//! Byte-exact as cut from the design note (P-38 §1): the concatenation
//! in `builtin::builtin_manifest_json`'s order is pinned by
//! `tests::builtin_manifest_bytes_unchanged`.

pub(crate) const TASK_DELEGATE: &str = r#"    {
      "id": "harness.task.delegate",
      "summary": "Ask a read-only helper to explore the workspace and answer one question. It works in its own context with its own step budget and returns a short report, which is untrusted: check it before you rely on it. task is the question, with what to look for",
      "effect": "read",
      "sensitivity": "operational",
      "blast_radius": "own",
      "egress": "none",
      "content": "third_party",
      "confirmation": "none",
      "input_schema": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "task": { "type": "string", "maxLength": 2000 }
        },
        "required": ["task"]
      }
    },
"#;
