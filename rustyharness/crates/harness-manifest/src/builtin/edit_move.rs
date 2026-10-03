//! The built-in manifest fragment for harness.edit.move (P-25).
//!
//! Byte-exact as cut: the concatenation in `builtin::builtin_manifest_json`'s
//! order is pinned by `tests::builtin_manifest_bytes_unchanged`.

pub(crate) const EDIT_MOVE: &str = r#"    {
      "id": "harness.edit.move",
      "summary": "Move one workspace file that was read in this run with the file-read tool (a search does not count as a read) to another path in the workspace, refusing if the target path already exists; the file's bytes are kept as a pre-image like any edit's. Paths are relative to the workspace root",
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
          "path": { "type": "string", "maxLength": 4096 },
          "to": { "type": "string", "maxLength": 4096 }
        },
        "required": ["path", "to"]
      }
    },
"#;
