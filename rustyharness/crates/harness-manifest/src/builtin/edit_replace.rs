//! The built-in manifest fragment for harness.edit.replace.
//!
//! Byte-exact as cut from the former single literal: the concatenation
//! in `builtin::builtin_manifest_json`'s order is pinned by
//! `tests::builtin_manifest_bytes_unchanged`.

pub(crate) const EDIT_REPLACE: &str = r#"    {
      "id": "harness.edit.replace",
      "summary": "Replace an exact text in a workspace file read in this run with the file-read tool (a search does not count as a read); it must match exactly count times (default 1). Paths are relative to the workspace root",
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
          "old": { "type": "string", "maxLength": 65536 },
          "new": { "type": "string", "maxLength": 65536 },
          "count": { "type": "integer", "minimum": 1, "maximum": 1000 }
        },
        "required": ["path", "old", "new"]
      }
    },
"#;
