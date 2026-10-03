//! The built-in manifest fragment for harness.edit.delete (P-25).
//!
//! Byte-exact as cut: the concatenation in `builtin::builtin_manifest_json`'s
//! order is pinned by `tests::builtin_manifest_bytes_unchanged`.

pub(crate) const EDIT_DELETE: &str = r#"    {
      "id": "harness.edit.delete",
      "summary": "Delete one workspace file that was read in this run with the file-read tool (a search does not count as a read); the file's bytes are kept as a pre-image like any edit's. Paths are relative to the workspace root",
      "effect": "write",
      "sensitivity": "operational",
      "blast_radius": "own",
      "egress": "none",
      "content": "own",
      "confirmation": "user_confirm",
      "input_schema": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "path": { "type": "string", "maxLength": 4096 }
        },
        "required": ["path"]
      }
    },
"#;
