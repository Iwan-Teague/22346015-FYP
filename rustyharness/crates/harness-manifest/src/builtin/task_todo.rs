//! The built-in manifest fragment for harness.task.todo.
//!
//! Byte-exact as cut from the former single literal: the concatenation
//! in `builtin::builtin_manifest_json`'s order is pinned by
//! `tests::builtin_manifest_bytes_unchanged`.

pub(crate) const TASK_TODO: &str = r#"    {
      "id": "harness.task.todo",
      "summary": "Keep a short checklist of your steps for this task: items replaces the whole list, each item a text and a status (pending, in_progress or done); without items the list is only shown. The result shows the list",
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
          "items": {
            "type": "array",
            "items": {
              "type": "object",
              "additionalProperties": false,
              "properties": {
                "text": { "type": "string", "maxLength": 200 },
                "status": { "type": "string", "enum": ["pending", "in_progress", "done"] }
              },
              "required": ["text", "status"]
            }
          }
        }
      }
    },
"#;
