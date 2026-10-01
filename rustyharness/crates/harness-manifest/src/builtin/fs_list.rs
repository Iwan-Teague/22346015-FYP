//! The built-in manifest fragment for harness.fs.list.
//!
//! Byte-exact as cut from the former single literal: the concatenation
//! in `builtin::builtin_manifest_json`'s order is pinned by
//! `tests::builtin_manifest_bytes_unchanged`.

pub(crate) const FS_LIST: &str = r#"    {
      "id": "harness.fs.list",
      "summary": "List a directory inside the workspace, bounded in depth and count. Paths are relative to the workspace root; \".\" is the root",
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
          "path": { "type": "string", "maxLength": 4096 },
          "depth": { "type": "integer", "minimum": 1, "maximum": 4 }
        },
        "required": ["path"]
      }
    },
"#;
