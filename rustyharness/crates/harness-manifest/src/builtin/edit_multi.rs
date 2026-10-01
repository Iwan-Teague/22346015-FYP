//! The built-in manifest fragment for harness.edit.multi.
//!
//! Byte-exact as cut from the former single literal: the concatenation
//! in `builtin::builtin_manifest_json`'s order is pinned by
//! `tests::builtin_manifest_bytes_unchanged`.

pub(crate) const EDIT_MULTI: &str = r#"    {
      "id": "harness.edit.multi",
      "summary": "Make several exact replacements in one workspace file read in this run with the file-read tool (a search does not count as a read), all or none: edits are applied in order, and each old text must match exactly once in the file as the edits before it left it. Paths are relative to the workspace root",
      "effect": "write",
      "sensitivity": "operational",
      "blast_radius": "own",
      "egress": "none",
      "content": "own",
      "confirmation": "none",
      "input_schema": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "path": { "type": "string", "maxLength": 4096 },
          "edits": {
            "type": "array",
            "items": {
              "type": "object",
              "additionalProperties": false,
              "properties": {
                "old": { "type": "string", "maxLength": 65536 },
                "new": { "type": "string", "maxLength": 65536 }
              },
              "required": ["old", "new"]
            }
          }
        },
        "required": ["path", "edits"]
      }
    },
"#;
