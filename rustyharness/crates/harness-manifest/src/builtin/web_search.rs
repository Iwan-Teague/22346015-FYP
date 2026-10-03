//! The built-in manifest fragment for harness.web.search (P-39b, §2.3).
//!
//! The research manifest's concatenation order is pinned by
//! `tests::research_manifest_bytes_pinned`; the coding manifest never
//! includes this fragment (pinned by `tests::builtin_manifest_bytes_unchanged`).

pub(crate) const WEB_SEARCH: &str = r#"    {
      "id": "harness.web.search",
      "summary": "Search the web endpoint configured for the session: query, max_results",
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
          "query": { "type": "string", "maxLength": 256 },
          "max_results": { "type": "integer", "minimum": 1, "maximum": 10 }
        },
        "required": ["query"]
      }
    },
"#;
