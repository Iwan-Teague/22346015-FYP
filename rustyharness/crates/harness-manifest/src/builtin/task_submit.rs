//! The built-in manifest fragment for harness.task.submit.
//!
//! Byte-exact as cut from the former single literal: the concatenation
//! in `builtin::builtin_manifest_json`'s order is pinned by
//! `tests::builtin_manifest_bytes_unchanged`.

pub(crate) const TASK_SUBMIT: &str = r#"    {
      "id": "harness.task.submit",
      "summary": "Submit the task for verification with a short note",
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
          "note": { "type": "string", "maxLength": 2000 }
        },
        "required": ["note"]
      }
    }
"#;
