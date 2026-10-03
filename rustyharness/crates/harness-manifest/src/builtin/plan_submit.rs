//! The built-in manifest fragment for harness.plan.submit (P-28).
//!
//! Byte-exact as cut from the former single literal: the concatenation
//! in `builtin::builtin_manifest_json`'s order is pinned by
//! `tests::builtin_manifest_bytes_unchanged`.

pub(crate) const PLAN_SUBMIT: &str = r#"    {
      "id": "harness.plan.submit",
      "summary": "Show a plan for approval before editing: summary, files (the paths the plan will touch) and steps; the user approves it with /build, and only then can those files be edited",
      "effect": "write",
      "sensitivity": "public",
      "blast_radius": "own",
      "egress": "none",
      "content": "own",
      "confirmation": "none",
      "input_schema": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "summary": { "type": "string", "maxLength": 2000 },
          "files": {
            "type": "array",
            "items": { "type": "string", "maxLength": 4096 }
          },
          "steps": {
            "type": "array",
            "items": { "type": "string", "maxLength": 500 }
          }
        },
        "required": ["summary", "files", "steps"]
      }
    },
"#;
