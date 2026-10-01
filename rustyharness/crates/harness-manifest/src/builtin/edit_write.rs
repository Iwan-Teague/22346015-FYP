//! The built-in manifest fragment for harness.edit.write.
//!
//! Byte-exact as cut from the former single literal: the concatenation
//! in `builtin::builtin_manifest_json`'s order is pinned by
//! `tests::builtin_manifest_bytes_unchanged`.

pub(crate) const EDIT_WRITE: &str = r#"    {
      "id": "harness.edit.write",
      "summary": "Create a new workspace file (missing directories on its path are created), or rewrite a whole file of at most 400 lines read in this run with the file-read tool. Paths are relative to the workspace root",
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
          "content": { "type": "string", "maxLength": 65536 }
        },
        "required": ["path", "content"]
      }
    },
"#;
