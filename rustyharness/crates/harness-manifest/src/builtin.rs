//! The built-in manifest for H1's read tools (design §4.8, §9 H1: read tools
//! in-process, no exec).
//!
//! The built-ins are declared by a `harness` manifest and take the same
//! validation and policy path as any provider, with no special case beyond
//! the origin: this text is compiled in, so it alone may use the reserved
//! `harness` namespace and the `builtin` transport.
//!
//! H1 declares the three read tools and the submit sentinel
//! `harness.task.submit` (§2.5, H1e-2). `harness.edit.*`, `harness.exec.run`
//! and `harness.notes.write` are write/execute class and arrive with the
//! slices that implement their policy (H2).
//!
//! Read tools: read / operational / own / none, as §4.8's table says;
//! `content` is `third_party` because file contents in a workspace are other
//! people's text by default (§5.4). That changes no default decision (§5.2
//! allows both read rows) and only makes the trifecta label honest.
//!
//! The sentinel: write / public / own / none (§4.8), `content: own`. It
//! changes nothing but the run's phase; policy allows it by one named rule
//! (`allow.task-submit`), the only write-class capability H1 decides.
//!
//! `harness.fs.search` matches a literal substring, not a regular
//! expression: H1 adds no regex crate (§4.8 deviation, recorded in the
//! design's changes table).

use crate::{parse_with_origin, Manifest, ManifestError, Origin, ValidationContext};

/// The compiled-in manifest text (JSON, manifest v1).
pub const BUILTIN_MANIFEST_JSON: &str = r#"{
  "schema_version": 1,
  "provider": "harness",
  "provider_version": "0.0.1",
  "min_harness": "0.0.1",
  "transport": { "kind": "builtin" },
  "capabilities": [
    {
      "id": "harness.fs.read",
      "summary": "Read a window of lines from a file inside the workspace",
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
          "lines": { "type": "integer", "minimum": 1, "maximum": 100 }
        },
        "required": ["path"]
      }
    },
    {
      "id": "harness.fs.search",
      "summary": "Search files inside the workspace for a literal text",
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
          "path": { "type": "string", "maxLength": 4096 }
        },
        "required": ["pattern"]
      }
    },
    {
      "id": "harness.fs.list",
      "summary": "List a directory inside the workspace, bounded in depth and count",
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
    {
      "id": "harness.task.submit",
      "summary": "Submit the task for verification with a short note",
      "effect": "write",
      "sensitivity": "public",
      "blast_radius": "own",
      "egress": "none",
      "content": "own",
      "confirmation": "none",
      "input_schema": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "note": { "type": "string", "maxLength": 2000 }
        },
        "required": ["note"]
      }
    }
  ]
}"#;

/// The built-in manifest, validated like any other (plus: it is the only
/// manifest allowed the `harness` namespace and the `builtin` transport).
pub fn manifest(ctx: &ValidationContext) -> Result<Manifest, ManifestError> {
    parse_with_origin(BUILTIN_MANIFEST_JSON.as_bytes(), ctx, Origin::Compiled)
}
