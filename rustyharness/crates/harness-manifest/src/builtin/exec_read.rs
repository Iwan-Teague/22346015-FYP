//! The built-in manifest fragment for harness.exec.read (P-36g).

pub(crate) const EXEC_READ: &str = r#"    {
      "id": "harness.exec.read",
      "summary": "Read what a background process printed, without blocking: id is the process id a start returned; mode picks out (default), err or both; since_out and since_err skip bytes already seen; max_bytes caps what comes back; wait_secs bounds how long it waits for new output",
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
          "id": { "type": "integer", "minimum": 1 },
          "mode": { "type": "string", "enum": ["out", "err", "both"] },
          "since_out": { "type": "integer", "minimum": 0 },
          "since_err": { "type": "integer", "minimum": 0 },
          "max_bytes": { "type": "integer", "minimum": 1 },
          "wait_secs": { "type": "integer", "minimum": 0 }
        },
        "required": ["id"]
      }
    },
"#;
