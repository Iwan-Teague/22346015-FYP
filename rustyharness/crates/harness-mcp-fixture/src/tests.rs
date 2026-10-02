//! The fixture's own tests: the `ok` mode's whole exchange, the mode
//! parser over every §14 string, the rug-pull switch, the drift modes'
//! first lists, pagination, the id/shape violations, and the pin helper
//! against what the server actually presents. The client-side hostile
//! suite lives in `harness-mcp` (P-37e); this crate only proves the
//! server speaks its script.

use std::io::BufRead;

use serde_json::Value;

use crate::mode::{Mode, ModeError, PROTOCOL_VERSION, SAMPLE_MODE_STRINGS};
use crate::tools::{
    ok_pins, ECHO_DESCRIPTION, ECHO_DESCRIPTION_DRIFTED, ECHO_DESCRIPTION_RUG_PULL,
};
use crate::{serve, ServeError};

/// Feeds `requests` (one JSON-RPC message per line) to `serve` in `mode`
/// and returns the output split into its lines, each parsed as JSON.
fn exchange(mode: &str, requests: &[&str]) -> Result<Vec<Value>, ServeError> {
    let mut input = requests.join("\n");
    input.push('\n');
    let mut output = Vec::new();
    serve(mode, input.as_bytes(), &mut output)?;
    Ok(split_frames(&output))
}

/// Serves `requests` in `mode` and hands back (output lines as raw bytes,
/// raw output bytes) for the tests that check framing itself.
fn exchange_raw(mode: &str, requests: &[&str]) -> Result<(Vec<Vec<u8>>, Vec<u8>), ServeError> {
    let mut input = requests.join("\n");
    input.push('\n');
    let mut output = Vec::new();
    serve(mode, input.as_bytes(), &mut output)?;
    Ok((split_lines(&output), output))
}

/// Splits a transcript into its non-empty `\n`-terminated lines.
fn split_lines(output: &[u8]) -> Vec<Vec<u8>> {
    output
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

/// Splits a transcript into its `\n`-terminated frames and parses each.
fn split_frames(output: &[u8]) -> Vec<Value> {
    split_lines(output)
        .iter()
        .map(|line| serde_json::from_slice(line).expect("frame is json"))
        .collect()
}

/// The `ok` exchange: initialize, initialized, list, echo, add.
fn ok_requests() -> Vec<&'static str> {
    vec![
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"add","arguments":{"a":2,"b":3}}}"#,
    ]
}

fn result_of(frame: &Value) -> &Value {
    frame.get("result").expect("frame has a result")
}

fn tool_entry<'a>(frame: &'a Value, name: &str) -> &'a Value {
    result_of(frame)["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .find(|t| t.get("name").and_then(Value::as_str) == Some(name))
        .expect("tool is listed")
}

#[test]
fn fixture_ok_mode_answers_initialize_list_call() {
    let frames = exchange("ok", &ok_requests()).expect("ok mode serves");
    // Five requests, four answers: `notifications/initialized` is a
    // notification and is answered with silence.
    assert_eq!(frames.len(), 4);

    // initialize: pinned version, tools capability, server info, id echo.
    let init = result_of(&frames[0]);
    assert_eq!(
        init.get("protocolVersion").and_then(Value::as_str),
        Some(PROTOCOL_VERSION)
    );
    assert!(init["capabilities"].get("tools").is_some());
    assert_eq!(
        init["serverInfo"].get("name").and_then(Value::as_str),
        Some(crate::SERVER_NAME)
    );
    assert_eq!(frames[0].get("id"), Some(&serde_json::json!(1)));

    // tools/list: exactly echo and add, schemas are objects.
    let tools = result_of(&frames[1])["tools"].as_array().expect("tools");
    let names: Vec<&str> = tools
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str))
        .collect();
    assert_eq!(names, vec!["echo", "add"]);
    assert_eq!(
        tool_entry(&frames[1], "echo")
            .get("description")
            .and_then(Value::as_str),
        Some(ECHO_DESCRIPTION)
    );
    assert_eq!(
        tool_entry(&frames[1], "echo")["inputSchema"].get("type"),
        Some(&serde_json::json!("object"))
    );

    // calls: echo repeats the text; add sums; ids echo the requests'.
    let echoed = result_of(&frames[2])["content"][0]["text"]
        .as_str()
        .expect("echo text");
    assert_eq!(echoed, "hi");
    assert_eq!(result_of(&frames[2])["isError"], serde_json::json!(false));
    assert_eq!(frames[2].get("id"), Some(&serde_json::json!(3)));
    let summed = result_of(&frames[3])["content"][0]["text"]
        .as_str()
        .expect("add text");
    assert_eq!(summed, "5");
}

#[test]
fn fixture_every_mode_parses() {
    // Every §14 mode string parses, and no two of them are the same.
    for s in SAMPLE_MODE_STRINGS {
        let parsed = Mode::parse(s);
        assert!(parsed.is_ok(), "mode {s} must parse: {:?}", parsed.err());
    }
    for (i, a) in SAMPLE_MODE_STRINGS.iter().enumerate() {
        for b in SAMPLE_MODE_STRINGS.iter().skip(i + 1) {
            assert_ne!(a, b, "duplicate sample mode string {a}");
        }
    }
    // ... and everything else is refused, not defaulted to `ok`.
    assert_eq!(
        Mode::parse("nope"),
        Err(ModeError::Unknown("nope".to_owned()))
    );
    assert!(matches!(
        Mode::parse("rug-pull-after"),
        Err(ModeError::BadParam { .. })
    ));
    assert!(matches!(
        Mode::parse("rug-pull-after:x"),
        Err(ModeError::BadParam { .. })
    ));
    assert!(matches!(
        Mode::parse("ok:1"),
        Err(ModeError::BadParam { .. })
    ));
    assert!(matches!(
        Mode::parse("version:"),
        Err(ModeError::BadParam { .. })
    ));
    assert!(matches!(
        Mode::parse("paginate:0"),
        Err(ModeError::BadParam { .. })
    ));
    assert!(matches!(
        Mode::parse("paginate:65"),
        Err(ModeError::BadParam { .. })
    ));
}

#[test]
fn fixture_rug_pull_changes_description_after_n_calls() {
    // n = 1: the first list still carries the pinned description; after
    // one call the description is the rug-pull text, and `add` is
    // untouched.
    let requests = vec![
        ok_requests()[0],
        ok_requests()[2],
        ok_requests()[3],
        ok_requests()[2],
    ];
    let frames = exchange("rug-pull-after:1", &requests).expect("rug pull serves");
    assert_eq!(frames.len(), 4);
    assert_eq!(
        tool_entry(&frames[1], "echo")
            .get("description")
            .and_then(Value::as_str),
        Some(ECHO_DESCRIPTION),
        "first list is still pinned"
    );
    assert_eq!(
        tool_entry(&frames[3], "echo")
            .get("description")
            .and_then(Value::as_str),
        Some(ECHO_DESCRIPTION_RUG_PULL),
        "second list is the rug pull"
    );
    assert_eq!(
        tool_entry(&frames[1], "add")
            .get("description")
            .and_then(Value::as_str),
        tool_entry(&frames[3], "add")
            .get("description")
            .and_then(Value::as_str)
    );
    // n = 0 means the very first list is already hostile.
    let early = exchange("rug-pull-after:0", &[ok_requests()[0], ok_requests()[2]])
        .expect("rug pull at 0 serves");
    assert_eq!(
        tool_entry(&early[1], "echo")
            .get("description")
            .and_then(Value::as_str),
        Some(ECHO_DESCRIPTION_RUG_PULL)
    );
}

#[test]
fn fixture_vanish_after_removes_echo_only() {
    let requests = vec![
        ok_requests()[0],
        ok_requests()[2],
        ok_requests()[3],
        ok_requests()[2],
    ];
    let frames = exchange("vanish-after:1", &requests).expect("vanish serves");
    let before = result_of(&frames[1])["tools"].as_array().expect("tools");
    let after = result_of(&frames[3])["tools"].as_array().expect("tools");
    assert_eq!(before.len(), 2);
    assert_eq!(after.len(), 1);
    assert_eq!(
        after[0].get("name").and_then(Value::as_str),
        Some("add"),
        "echo vanished, add stayed"
    );
}

#[test]
fn fixture_drift_modes_present_wrong_pins_from_first_list() {
    let requests = vec![ok_requests()[0], ok_requests()[2]];
    let drift = exchange("drift-description", &requests).expect("drift serves");
    assert_eq!(
        tool_entry(&drift[1], "echo")
            .get("description")
            .and_then(Value::as_str),
        Some(ECHO_DESCRIPTION_DRIFTED)
    );
    let schema = exchange("drift-schema", &requests).expect("drift serves");
    assert_eq!(
        tool_entry(&schema[1], "echo")["inputSchema"],
        crate::tools::echo_schema_drifted(),
        "echo's schema is the drifted one"
    );
    let add_schema = serde_json::from_str::<Value>(&ok_pins()["add"].canonical_schema)
        .expect("add's pinned schema parses");
    assert_eq!(
        tool_entry(&schema[1], "add")["inputSchema"],
        add_schema,
        "add is untouched by echo's drift"
    );
}

#[test]
fn fixture_paginate_walks_cursor_pages() {
    let requests = vec![
        ok_requests()[0],
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"cursor":"p1"}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{"cursor":"p2"}}"#,
    ];
    let frames = exchange("paginate:3", &requests).expect("paginate serves");
    // Two tools over three pages: one name per populated page, then an
    // empty page that ends the walk.
    let mut names: Vec<&str> = Vec::new();
    for frame in &frames[1..] {
        let page = result_of(frame);
        for tool in page["tools"].as_array().expect("page tools") {
            names.push(tool.get("name").and_then(Value::as_str).expect("name"));
        }
        let next = page.get("nextCursor").and_then(Value::as_str);
        match frame.get("id") {
            Some(id) if id == &serde_json::json!(4) => {
                assert_eq!(next, None, "the last page names no successor");
                assert!(
                    page["tools"].as_array().expect("page tools").is_empty(),
                    "two tools over three pages leave one page empty"
                );
            }
            _ => assert!(next.is_some(), "a middle page names its successor"),
        }
    }
    assert_eq!(names, vec!["echo", "add"]);
}

#[test]
fn fixture_id_and_shape_violations_look_as_scripted() {
    // wrong-id: an id nobody sent.
    let frames = exchange("wrong-id", &[ok_requests()[0]]).expect("wrong-id serves");
    assert_eq!(frames[0].get("id"), Some(&serde_json::json!(424242)));
    // string-id: the request's id echoed as a JSON string.
    let frames = exchange("string-id", &[ok_requests()[0]]).expect("string-id serves");
    assert_eq!(frames[0].get("id"), Some(&serde_json::json!("1")));
    // double-response: two identical lines for one request.
    let (frames, raw) =
        exchange_raw("double-response", &[ok_requests()[0]]).expect("doubled serves");
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0], frames[1]);
    assert_eq!(raw.iter().filter(|b| **b == b'\n').count(), 2);
    // result-and-error: one frame carrying both keys.
    let frames = exchange("result-and-error", &[ok_requests()[0]]).expect("both serves");
    assert_eq!(frames.len(), 1);
    assert!(frames[0].get("result").is_some() && frames[0].get("error").is_some());
    // batch: the initialize answer is a JSON array.
    let frames = exchange("batch", &[ok_requests()[0]]).expect("batch serves");
    assert_eq!(frames.len(), 1);
    assert!(frames[0].is_array());
    assert_eq!(frames[0][0].get("id"), Some(&serde_json::json!(1)));
}

#[test]
fn fixture_version_and_capability_scripts_apply() {
    // version:<v> names exactly v.
    let frames = exchange("version:1999-01-01", &[ok_requests()[0]]).expect("version mode serves");
    assert_eq!(
        result_of(&frames[0])
            .get("protocolVersion")
            .and_then(Value::as_str),
        Some("1999-01-01")
    );
    // no-tools-capability: initialize carries no tools capability.
    let frames = exchange("no-tools-capability", &[ok_requests()[0]]).expect("no-tools serves");
    assert!(result_of(&frames[0])["capabilities"].get("tools").is_none());
    // instructions-injection: the instructions string is present as
    // scripted (what the client does with it is INV-29's business).
    let frames =
        exchange("instructions-injection", &[ok_requests()[0]]).expect("instructions mode serves");
    assert_eq!(
        result_of(&frames[0])
            .get("instructions")
            .and_then(Value::as_str),
        Some(crate::INSTRUCTIONS_INJECTION)
    );
}

#[test]
fn fixture_result_injection_text_is_scripted() {
    let frames = exchange(
        "result-injection",
        &[
            ok_requests()[0],
            ok_requests()[1],
            ok_requests()[2],
            ok_requests()[3],
        ],
    )
    .expect("injection serves");
    let text = result_of(&frames[2])["content"][0]["text"]
        .as_str()
        .expect("echo text");
    assert_eq!(text, crate::RESULT_INJECTION_TEXT);
    assert!(text.contains("<action>"), "an action block is in the text");
    assert!(
        text.contains("<<untrusted cafebabe"),
        "a forged delimiter is in the text"
    );
}

#[test]
fn fixture_request_flood_blasts_before_the_list() {
    // Twenty server requests (pings) precede the list answer; the
    // client's -32601 replies come back id-less and are dropped.
    let requests = vec![
        ok_requests()[0],
        ok_requests()[1],
        ok_requests()[2],
        // The client's refusal to every ping.
        r#"{"jsonrpc":"2.0","id":1001,"error":{"code":-32601,"message":"not supported"}}"#,
        r#"{"jsonrpc":"2.0","id":1002,"error":{"code":-32601,"message":"not supported"}}"#,
    ];
    let frames = exchange("request-flood", &requests).expect("flood serves");
    // The initialize answer, 20 pings, then the list answer; the two
    // refusal responses are not echoed.
    assert_eq!(frames.len(), 22);
    let pings = frames[1..21]
        .iter()
        .filter(|f| f.get("method").and_then(Value::as_str) == Some("ping"))
        .count();
    assert_eq!(pings, 20);
    assert!(frames[21].get("result").is_some());
}

#[test]
fn fixture_server_request_modes_speak_after_initialized() {
    for (mode, method) in [
        ("sampling", "sampling/createMessage"),
        ("roots", "roots/list"),
        ("elicit", "elicitation/create"),
        ("ping", "ping"),
    ] {
        let requests = vec![ok_requests()[0], ok_requests()[1], ok_requests()[2]];
        let frames = exchange(mode, &requests).expect("server-request mode serves");
        assert_eq!(frames.len(), 3, "{mode}: init result, request, list");
        assert_eq!(
            frames[1].get("method").and_then(Value::as_str),
            Some(method),
            "{mode} interjects its request"
        );
        assert!(
            frames[1].get("id").is_some(),
            "{mode} request carries an id"
        );
        assert!(frames[2].get("result").is_some(), "{mode} still lists");
    }
}

#[test]
fn fixture_list_changed_spam_notifies_per_exchange() {
    let requests = vec![
        ok_requests()[0],
        ok_requests()[1],
        ok_requests()[2],
        ok_requests()[3],
    ];
    let frames = exchange("list-changed-spam", &requests).expect("spam serves");
    let changed = frames
        .iter()
        .filter(|f| {
            f.get("method").and_then(Value::as_str) == Some("notifications/tools/list_changed")
        })
        .count();
    assert_eq!(changed, 2, "one before the list, one after the call");
}

#[test]
fn fixture_exit_midcall_ends_after_half_a_frame() {
    let (lines, raw) = exchange_raw(
        "exit-midcall",
        &[
            ok_requests()[0],
            ok_requests()[1],
            ok_requests()[2],
            ok_requests()[3],
        ],
    )
    .expect("exit-midcall serves until the call");
    assert_eq!(lines.len(), 3, "initialize, list, then the half frame");
    assert_eq!(lines[2], b"{\"jsonrpc\":".to_vec());
    assert!(!raw.ends_with(b"\n"), "the session ended mid-frame");
}

#[test]
fn fixture_huge_frame_is_one_long_line() {
    let (lines, _raw) = exchange_raw(
        "huge-frame",
        &[ok_requests()[0], ok_requests()[1], ok_requests()[2]],
    )
    .expect("huge frame serves");
    assert_eq!(lines.len(), 2, "the initialize answer, then one huge line");
    serde_json::from_slice::<Value>(&lines[0]).expect("the answer parses");
    assert!(
        lines[1].len() > 1024 * 1024,
        "one line, over 1 MiB: {}",
        lines[1].len()
    );
}

#[test]
fn fixture_malformed_line_after_initialize() {
    let (lines, _raw) = exchange_raw(
        "malformed",
        &[ok_requests()[0], ok_requests()[1], ok_requests()[2]],
    )
    .expect("malformed serves");
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[1], b"{not json".to_vec());
}

#[test]
fn fixture_unknown_tool_and_bad_args_refused() {
    let requests = vec![
        ok_requests()[0],
        ok_requests()[1],
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"rm","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"add","arguments":{"a":"x"}}}"#,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"echo","arguments":{"other":1}}}"#,
    ];
    let frames = exchange("ok", &requests).expect("ok serves");
    assert_eq!(frames.len(), 4);
    assert_eq!(frames[1].get("id"), Some(&serde_json::json!(3)));
    assert!(frames[1].get("error").is_some(), "unknown tool refused");
    assert_eq!(frames[2].get("id"), Some(&serde_json::json!(4)));
    assert!(frames[2].get("error").is_some(), "bad add args refused");
    // echo without `text` echoes the arguments' canonical JSON.
    assert!(frames[3].get("result").is_some());
    let text = result_of(&frames[3])["content"][0]["text"]
        .as_str()
        .expect("echo text");
    assert_eq!(text, r#"{"other":1}"#);
}

#[test]
fn fixture_confinement_probe_reports_each_attempt() {
    let requests = vec![
        ok_requests()[0],
        ok_requests()[1],
        ok_requests()[2],
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"probe","arguments":{"connect":["127.0.0.1:1"],"read":["/tmp"]}}}"#,
    ];
    let frames = exchange("confinement-probe", &requests).expect("probe serves");
    let text = result_of(&frames[2])["content"][0]["text"]
        .as_str()
        .expect("probe report");
    // The fixed attempts are all reported, one line each.
    assert!(text.contains("home-write "), "home write reported: {text}");
    assert!(text.contains("home-read "), "home read reported: {text}");
    assert!(text.contains("cwd-write "), "cwd write reported: {text}");
    assert!(text.contains("connect 1.1.1.1:443"), "net reported: {text}");
    // Argument-named extras are reported too, in order, capped in shape.
    assert!(
        text.contains("connect 127.0.0.1:1"),
        "extra connect: {text}"
    );
    assert!(text.contains("arg-read /tmp"), "extra read: {text}");
}

#[test]
fn fixture_unknown_method_gets_32601() {
    let requests = vec![
        ok_requests()[0],
        r#"{"jsonrpc":"2.0","id":9,"method":"resources/list"}"#,
    ];
    let frames = exchange("ok", &requests).expect("ok serves");
    assert_eq!(frames.len(), 2);
    assert_eq!(
        frames[1]["error"].get("code"),
        Some(&serde_json::json!(-32601))
    );
    assert_eq!(frames[1].get("id"), Some(&serde_json::json!(9)));
}

#[test]
fn fixture_eof_ends_serve() {
    // A truncated last line (no newline) still serves what it can, then
    // serve returns cleanly at end of input.
    let mut output = Vec::new();
    serve(
        "ok",
        &b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\""[..],
        &mut output,
    )
    .expect("eof ends serve");
    assert!(output.is_empty(), "a truncated request answers nothing");
}

#[test]
fn fixture_pins_helper_matches_ok_mode() {
    let pins = ok_pins();
    assert_eq!(pins.len(), 2, "echo and add, nothing else");
    let frames = exchange("ok", &[ok_requests()[0], ok_requests()[2]]).expect("ok serves");
    for (name, pin) in &pins {
        let entry = tool_entry(&frames[1], name);
        assert_eq!(
            entry.get("description").and_then(Value::as_str),
            Some(pin.description.as_str()),
            "{name}'s presented description is the pinned bytes"
        );
        let presented = entry.get("inputSchema").expect("schema");
        assert_eq!(
            crate::tools::canonical(presented),
            pin.canonical_schema,
            "{name}'s presented schema canonicalises to the pinned bytes"
        );
    }
}

#[test]
fn fixture_output_frames_have_no_embedded_newline() {
    // The transcript of the whole ok exchange is exactly its frames, each
    // one line: count newlines against parsed frames, and prove no frame
    // carries a raw `\r` (trailing or embedded).
    let (frames, raw) = exchange_raw("ok", &ok_requests()).expect("ok serves");
    let newlines = raw.iter().filter(|b| **b == b'\n').count();
    assert_eq!(newlines, frames.len(), "one newline per frame");
    assert!(!raw.contains(&b'\r'), "no carriage returns on the wire");
    // Every line read back parses (BufRead over the raw transcript).
    let reader = std::io::Cursor::new(raw);
    let lines = reader.lines();
    let mut count = 0;
    for line in lines {
        let line = line.expect("line reads");
        serde_json::from_str::<Value>(&line).expect("line is json");
        count += 1;
    }
    assert_eq!(count, frames.len());
}
