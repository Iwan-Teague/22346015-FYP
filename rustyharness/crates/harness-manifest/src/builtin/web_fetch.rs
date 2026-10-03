//! The built-in manifest fragment for harness.web.fetch (P-39b, §2.3).
//!
//! The research manifest's concatenation order is pinned by
//! `tests::research_manifest_bytes_pinned`; the coding manifest never
//! includes this fragment (pinned by `tests::builtin_manifest_bytes_unchanged`).

pub(crate) const WEB_FETCH: &str = r#"    {
      "id": "harness.web.fetch",
      "summary": "Fetch one URL from the session's allowlist and return its text: url, start (the first line, 1-based), lines how many",
      "effect": "read",
      "sensitivity": "operational",
      "blast_radius": "own",
      "egress": "internet",
      "content": "third_party",
      "confirmation": "none",
      "input_schema": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "url": { "type": "string", "maxLength": 4096 },
          "start": { "type": "integer", "minimum": 1 },
          "lines": { "type": "integer", "minimum": 1, "maximum": 400 }
        },
        "required": ["url"]
      }
    },
"#;
