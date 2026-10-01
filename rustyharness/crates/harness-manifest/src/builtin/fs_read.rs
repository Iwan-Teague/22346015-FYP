//! The built-in manifest fragment for harness.fs.read.
//!
//! Byte-exact as cut from the former single literal: the concatenation
//! in `builtin::builtin_manifest_json`'s order is pinned by
//! `tests::builtin_manifest_bytes_unchanged`.

pub(crate) const FS_READ: &str = r#"    {
      "id": "harness.fs.read",
      "summary": "Read a window of lines from a file inside the workspace: start is the first line (1-based) and lines how many, at most the run's read window (100 lines unless the model profile sets another). Paths are relative to the workspace root",
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
          "start": { "type": "integer", "minimum": 1 },
          "lines": { "type": "integer", "minimum": 1, "maximum": 2000 }
        },
        "required": ["path"]
      }
    },
"#;
