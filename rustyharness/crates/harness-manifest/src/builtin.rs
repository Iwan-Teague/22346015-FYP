//! The built-in manifest (design §4.8): the read tools, the edit tools
//! (H2b), the confined command runner (H2d) and the submit sentinel.
//!
//! The built-ins are declared by a `harness` manifest and take the same
//! validation and policy path as any provider, with no special case beyond
//! the origin: this text is compiled in, so it alone may use the reserved
//! `harness` namespace and the `builtin` transport.
//!
//! It declares the three read tools, the two edit tools
//! `harness.edit.replace` and `harness.edit.write` (§4.9, H2b), the
//! command runner `harness.exec.run` (§4.8, H2d) and the submit sentinel
//! `harness.task.submit` (§2.5, H1e-2). `harness.notes.write` arrives with
//! the slice that implements it.
//!
//! Read tools: read / operational / own / none, as §4.8's table says;
//! `content` is `third_party` because file contents in a workspace are other
//! people's text by default (§5.4). That changes no default decision (§5.2
//! allows both read rows) and only makes the trifecta label honest.
//!
//! Edit tools: write / operational / own / none (§4.8), `content: own` (an
//! edit's result is the harness's report of what it changed: a path, line
//! numbers and digests, never file text), confirmation `none` as declared.
//! What policy decides for them is `harness-policy`'s (§5.2): allowed by a
//! user allow rule, otherwise an ask, and with no approver a deny. Their
//! schemas are §4.9's `{path, old, new, count = 1}` and §4.8's
//! `{path, content}`; the string caps sit above the 64 KiB action cap
//! (`harness_model_core::protocol::ACTION_MAX_BYTES`), which binds first.
//!
//! The command runner: execute / operational / own / none (§4.8), `content:
//! third_party` (its output quotes workspace text: compiler messages, test
//! names), confirmation `none` as declared; the derived floor makes it need
//! a conformed sandbox (§4.2), and policy asks by default (H2d). Its schema
//! is `{argv: [string], cwd?: string}`: `argv[0]` names a program on the
//! task's exec allowlist, never a path the model chooses (§4.8, INV-13).
//!
//! The sentinel: write / public / own / none (§4.8), `content: own`. It
//! changes nothing but the run's phase; policy allows it by one named rule
//! (`allow.task-submit`).
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
      "summary": "Read a window of lines (at most 100) from a file inside the workspace. Paths are relative to the workspace root",
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
      "summary": "Search files inside the workspace for a literal text. Paths are relative to the workspace root; \".\" is the root",
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
    {
      "id": "harness.edit.replace",
      "summary": "Replace an exact text in a workspace file read in this run; it must match exactly count times (default 1). Paths are relative to the workspace root",
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
          "path": { "type": "string", "maxLength": 4096 },
          "old": { "type": "string", "maxLength": 65536 },
          "new": { "type": "string", "maxLength": 65536 },
          "count": { "type": "integer", "minimum": 1, "maximum": 1000 }
        },
        "required": ["path", "old", "new"]
      }
    },
    {
      "id": "harness.edit.write",
      "summary": "Create a new workspace file, or rewrite a whole file of at most 400 lines read in this run. Paths are relative to the workspace root",
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
          "path": { "type": "string", "maxLength": 4096 },
          "content": { "type": "string", "maxLength": 65536 }
        },
        "required": ["path", "content"]
      }
    },
    {
      "id": "harness.exec.run",
      "summary": "Run one program the task allows, confined with no network: argv is a list whose first item names the program; cwd is a directory relative to the workspace root (default the root)",
      "effect": "execute",
      "sensitivity": "operational",
      "blast_radius": "own",
      "egress": "none",
      "content": "third_party",
      "confirmation": "none",
      "input_schema": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "argv": { "type": "array", "items": { "type": "string", "maxLength": 4096 } },
          "cwd": { "type": "string", "maxLength": 4096 }
        },
        "required": ["argv"]
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
