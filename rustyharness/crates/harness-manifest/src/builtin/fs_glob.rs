//! The built-in manifest fragment for harness.fs.glob.
//!
//! Byte-exact as cut from the former single literal: the concatenation
//! in `builtin::builtin_manifest_json`'s order is pinned by
//! `tests::builtin_manifest_bytes_unchanged`.

pub(crate) const FS_GLOB: &str = r#"    {
      "id": "harness.fs.glob",
      "summary": "Find files inside the workspace whose paths below path (default the root) match a glob: * and ? within a name, ** across directories, [abc], {a,b}; a pattern without / matches file names at any depth. Paths are relative to the workspace root; \".\" is the root",
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
          "pattern": { "type": "string", "maxLength": 256 },
          "path": { "type": "string", "maxLength": 4096 }
        },
        "required": ["pattern"]
      }
    },
"#;
