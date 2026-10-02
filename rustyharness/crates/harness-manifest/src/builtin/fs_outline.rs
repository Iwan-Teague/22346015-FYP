//! The built-in manifest fragment for harness.fs.outline.
//!
//! Byte-exact as cut from the former single literal: the concatenation
//! in `builtin::builtin_manifest_json`'s order is pinned by
//! `tests::builtin_manifest_bytes_unchanged`.

pub(crate) const FS_OUTLINE: &str = r#"    {
      "id": "harness.fs.outline",
      "summary": "Outline a file's or a directory's symbols (functions, types, headings) by deterministic line regexes, bounded and sorted. Paths are relative to the workspace root; \".\" is the root",
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
          "kind": { "type": "string", "maxLength": 16 }
        }
      }
    },
"#;
