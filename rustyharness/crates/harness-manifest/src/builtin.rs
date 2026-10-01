//! The built-in manifest (design §4.8): the read tools, the edit tools
//! (H2b), the confined command runner (H2d) and the submit sentinel.
//!
//! The built-ins are declared by a `harness` manifest and take the same
//! validation and policy path as any provider, with no special case beyond
//! the origin: this text is compiled in, so it alone may use the reserved
//! `harness` namespace and the `builtin` transport.
//!
//! It declares the read tools (`harness.fs.read`, `harness.fs.search`,
//! `harness.fs.list` and, since H2e, `harness.fs.glob`), the two edit tools
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
//! H2e (design rows H2e): `harness.fs.search` matches a literal substring
//! by default, as before, and a regular expression with `regex: true`,
//! with `include` / `exclude` globs and `context` lines; `harness.fs.glob`
//! finds files by a glob pattern (read / operational / own / none, like the
//! other read tools); the `lines` of `harness.fs.read` may go up to 2000,
//! the widest read window a profile may set, while each run's window (100
//! by default) is what the model is shown and what a read returns.
//! `harness.edit.multi {path, edits: [{old, new}]}` makes several exact
//! replacements in one file, all or none, with the edit tools' labels.
//! `harness.task.todo {items?: [{text, status}]}` keeps the model's
//! checklist in the run's state: write / public / own / none, `content:
//! own` (its result echoes the model's own list), like the sentinel; policy
//! allows it by one named rule (`allow.task-todo`). The number of edits and
//! items is bounded by the tools (the schema subset has no `maxItems`).

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
    {
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
    {
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
      "summary": "Replace an exact text in a workspace file read in this run with the file-read tool (a search does not count as a read); it must match exactly count times (default 1). Paths are relative to the workspace root",
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
      "summary": "Create a new workspace file (missing directories on its path are created), or rewrite a whole file of at most 400 lines read in this run with the file-read tool. Paths are relative to the workspace root",
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
      "id": "harness.edit.multi",
      "summary": "Make several exact replacements in one workspace file read in this run with the file-read tool (a search does not count as a read), all or none: edits are applied in order, and each old text must match exactly once in the file as the edits before it left it. Paths are relative to the workspace root",
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
          "edits": {
            "type": "array",
            "items": {
              "type": "object",
              "additionalProperties": false,
              "properties": {
                "old": { "type": "string", "maxLength": 65536 },
                "new": { "type": "string", "maxLength": 65536 }
              },
              "required": ["old", "new"]
            }
          }
        },
        "required": ["path", "edits"]
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
      "id": "harness.task.todo",
      "summary": "Keep a short checklist of your steps for this task: items replaces the whole list, each item a text and a status (pending, in_progress or done); without items the list is only shown. The result shows the list",
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
          "items": {
            "type": "array",
            "items": {
              "type": "object",
              "additionalProperties": false,
              "properties": {
                "text": { "type": "string", "maxLength": 200 },
                "status": { "type": "string", "enum": ["pending", "in_progress", "done"] }
              },
              "required": ["text", "status"]
            }
          }
        }
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
