//! The built-in manifest fragment for harness.exec.start (P-36g).

pub(crate) const EXEC_START: &str = r#"    {
      "id": "harness.exec.start",
      "summary": "Start one allowed program in the background and get a process id back: argv is a list whose first item names the program; cwd is a directory relative to the workspace root (default the root); ports optionally binds loopback ports; scope is turn (default, stopped at the turn's end) or session (kept until stopped or the run ends); lifetime_secs caps how long it lives; ready names the port or text that marks it up",
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
          "cwd": { "type": "string", "maxLength": 4096 },
          "ports": { "type": "array", "items": { "type": "integer", "minimum": 1024, "maximum": 65535 } },
          "scope": { "type": "string", "enum": ["turn", "session"] },
          "lifetime_secs": { "type": "integer", "minimum": 1 },
          "ready": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
              "port": { "type": "integer", "minimum": 1024, "maximum": 65535 },
              "text": { "type": "string", "maxLength": 4096 }
            }
          },
          "ready_secs": { "type": "integer", "minimum": 1 }
        },
        "required": ["argv"]
      }
    },
"#;
