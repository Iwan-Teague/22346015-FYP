//! The built-in manifest fragment for harness.exec.stop (P-36g).

pub(crate) const EXEC_STOP: &str = r#"    {
      "id": "harness.exec.stop",
      "summary": "Stop one background process this run started: id is the process id a start returned",
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
          "id": { "type": "integer", "minimum": 1 }
        },
        "required": ["id"]
      }
    },
"#;
