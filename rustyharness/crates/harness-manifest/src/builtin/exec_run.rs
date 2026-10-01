//! The built-in manifest fragment for harness.exec.run.
//!
//! Byte-exact as cut from the former single literal: the concatenation
//! in `builtin::builtin_manifest_json`'s order is pinned by
//! `tests::builtin_manifest_bytes_unchanged`.

pub(crate) const EXEC_RUN: &str = r#"    {
      "id": "harness.exec.run",
      "summary": "Run one program the task allows, confined with no network: argv is a list whose first item names the program; cwd is a directory relative to the workspace root (default the root)",
      "effect": "execute",
      "sensitivity": "operational",
      "blast_radius": "own",
      "egress": "none",
      "content": "third_party",
      "confirmation": "none",
      "input_schema": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "argv": { "type": "array", "items": { "type": "string", "maxLength": 4096 } },
          "cwd": { "type": "string", "maxLength": 4096 }
        },
        "required": ["argv"]
      }
    },
"#;
