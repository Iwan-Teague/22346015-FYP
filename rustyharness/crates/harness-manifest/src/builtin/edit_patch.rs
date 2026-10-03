//! The built-in manifest fragment for harness.edit.patch (P-25).
//!
//! Byte-exact as cut: the concatenation in `builtin::builtin_manifest_json`'s
//! order is pinned by `tests::builtin_manifest_bytes_unchanged`.

pub(crate) const EDIT_PATCH: &str = r#"    {
      "id": "harness.edit.patch",
      "summary": "Apply a `*** Begin Patch` script across several workspace files, all or none: sections `*** Add File:`, `*** Update File:` (hunks of ' ' context, '-' removed, '+' added lines; each hunk's context must match the file exactly once) and `*** Delete File:`. Every file named must have been read in this run with the file-read tool (a search does not count as a read); if any section fails, nothing is written. Paths are relative to the workspace root",
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
          "patch": { "type": "string", "maxLength": 65536 }
        },
        "required": ["patch"]
      }
    },
"#;
