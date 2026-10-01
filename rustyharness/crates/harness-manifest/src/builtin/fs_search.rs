//! The built-in manifest fragment for harness.fs.search.
//!
//! Byte-exact as cut from the former single literal: the concatenation
//! in `builtin::builtin_manifest_json`'s order is pinned by
//! `tests::builtin_manifest_bytes_unchanged`.

pub(crate) const FS_SEARCH: &str = r#"    {
      "id": "harness.fs.search",
      "summary": "Search the files inside the workspace line by line for a literal text or, with regex true, a regular expression. include and exclude are globs (*.rs, src/**) over paths below path; context adds up to 5 lines around each hit. Paths are relative to the workspace root; \".\" is the root",
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
          "pattern": { "type": "string", "maxLength": 1024 },
          "path": { "type": "string", "maxLength": 4096 },
          "regex": { "type": "boolean" },
          "include": { "type": "string", "maxLength": 256 },
          "exclude": { "type": "string", "maxLength": 256 },
          "context": { "type": "integer", "minimum": 0, "maximum": 5 }
        },
        "required": ["pattern"]
      }
    },
"#;
