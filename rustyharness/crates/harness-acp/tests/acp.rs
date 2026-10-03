//! The P-35 acceptance tests (docs/slices/P-35.md): the ACP v1 server
//! over injected pipes — no sockets anywhere, the model scripted, the
//! journal audited for real.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

use std::io::{BufRead, Read, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use harness_core::environment::{EnvProbe, EnvSample, Unmeasured};
use harness_model::profile::Profile;
use harness_model::scripted::ScriptedBackend;
use harness_model::{Completion, TaskText};
use harness_policy::{SessionKind, UserPolicy};
use harness_run::session::SessionConfig;
use harness_run::TaskSpec;
use harness_testkit::{read_spec, registry, Fixture, Local};
use serde_json::{json, Value};

/// How long any single wait may take before the test fails loudly.
const WAIT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// The pipes: client → server and server → client, no sockets.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct PipeInner {
    buf: Vec<u8>,
    eof: bool,
}

/// One direction of the test pipe: a shared buffer with a condvar.
#[derive(Clone, Default)]
struct Pipe(Arc<(Mutex<PipeInner>, Condvar)>);

impl Pipe {
    /// Append bytes (the writer's side).
    fn push(&self, bytes: &[u8]) {
        let (lock, cv) = &*self.0;
        let mut g = lock.lock().unwrap();
        g.buf.extend_from_slice(bytes);
        cv.notify_all();
    }

    /// Close the pipe: readers see end-of-stream.
    fn close(&self) {
        let (lock, cv) = &*self.0;
        let mut g = lock.lock().unwrap();
        g.eof = true;
        cv.notify_all();
    }

    /// Pop one `\n`-terminated line, waiting at most `WAIT` for it.
    fn pop_line(&self) -> String {
        let (lock, cv) = &*self.0;
        let mut g = lock.lock().unwrap();
        loop {
            if let Some(i) = g.buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = g.buf.drain(..=i).collect();
                return String::from_utf8_lossy(&line[..line.len() - 1]).into_owned();
            }
            if g.eof {
                panic!("the server's stream closed before a line arrived");
            }
            let (g2, timeout) = cv.wait_timeout(g, WAIT).unwrap();
            g = g2;
            if timeout.timed_out() {
                panic!("timed out waiting for a protocol line");
            }
        }
    }
}

/// The client's writer (the server reads this).
struct TestWriter(Pipe);

impl Write for TestWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.push(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The server's reader half: blocks until bytes arrive, then serves
/// them from a local staging buffer (`BufRead::fill_buf` returns a
/// borrowed slice, so the wait happens before the borrow).
struct TestReader {
    pipe: Pipe,
    staging: Vec<u8>,
    pos: usize,
}

impl TestReader {
    /// Block until the pipe has bytes or is closed. `false` = over.
    fn wait_for_data(&mut self) -> bool {
        let (lock, cv) = &*self.pipe.0;
        let mut g = lock.lock().unwrap();
        loop {
            if self.pos < self.staging.len() || !g.buf.is_empty() {
                return true;
            }
            if g.eof {
                return false;
            }
            let (g2, timeout) = cv.wait_timeout(g, WAIT).unwrap();
            g = g2;
            if timeout.timed_out() {
                return false;
            }
        }
    }

    fn refill(&mut self) {
        if self.pos >= self.staging.len() {
            // TAKE the pipe's bytes (never swap: the consumed staging
            // must not go back into the pipe).
            let taken = std::mem::take(&mut self.pipe.0 .0.lock().unwrap().buf);
            self.staging = taken;
            self.pos = 0;
        }
    }
}

impl Read for TestReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        // Delegated to fill_buf/consume so no bytes are ever taken
        // from the pipe past what the caller accepts.
        let available = self.fill_buf()?;
        let n = available.len().min(out.len());
        out[..n].copy_from_slice(&available[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for TestReader {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if !self.wait_for_data() {
            return Ok(&[]);
        }
        self.refill();
        Ok(&self.staging[self.pos..])
    }

    fn consume(&mut self, amt: usize) {
        self.pos = (self.pos + amt).min(self.staging.len());
    }
}

/// The test's ACP client: writes requests, reads the protocol lines.
#[derive(Clone)]
struct Client {
    up: Pipe,
    down: Pipe,
}

impl Client {
    fn new() -> (Self, Pipe, Pipe) {
        let up = Pipe::default();
        let down = Pipe::default();
        let c = Self {
            up: up.clone(),
            down: down.clone(),
        };
        (c, up, down)
    }

    fn send(&self, v: &Value) {
        self.up.push(format!("{v}\n").as_bytes());
    }

    fn send_raw(&self, line: &str) {
        self.up.push(format!("{line}\n").as_bytes());
    }

    fn recv(&self) -> Value {
        let line = self.down.pop_line();
        serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("the server sent non-JSON ({e}): {line}"))
    }

    /// The next line whose `method` is `want` (other lines are kept in
    /// `seen`).
    fn recv_method(&self, want: &str, seen: &mut Vec<Value>) -> Value {
        loop {
            let v = self.recv();
            if v.get("method").and_then(Value::as_str) == Some(want) {
                return v;
            }
            seen.push(v);
        }
    }

    fn close(&self) {
        self.up.close();
    }
}

// ---------------------------------------------------------------------------
// The scripted server under test.
// ---------------------------------------------------------------------------

struct FixedEnv;

impl EnvProbe for FixedEnv {
    fn sample(&self) -> EnvSample {
        EnvSample::unmeasured(Unmeasured::NoSafeApi)
    }
}

/// A read-only fixture: a.txt in the workspace, the read spec.
fn read_fixture(label: &str) -> Fixture {
    let fx = Fixture::with_spec(label, read_spec("What does a.txt say?")).unwrap();
    fx.write("a.txt", "the answer is in here\n").unwrap();
    fx
}

/// An edit fixture: a.txt, and the edit grant (the default policy asks).
fn edit_fixture(label: &str) -> Fixture {
    let spec = TaskSpec {
        task: TaskText::new("Change 'answer' to 'reply' in a.txt.".into()),
        grants: vec!["harness.fs.read".into(), "harness.edit.replace".into()],
        workspace_public: false,
        ports: Vec::new(),
        lan_ports: Vec::new(),
        exec: None,
        presubmit: None,
        post_edit: None,
        protected: Vec::new(),
        kind: SessionKind::Coding,
    };
    let fx = Fixture::with_spec(label, spec).unwrap();
    fx.write("a.txt", "the answer is in here\n").unwrap();
    fx
}

fn backend(replies: Vec<Completion>) -> ScriptedBackend {
    ScriptedBackend::new(
        Profile::conservative_default("m"),
        replies.into_iter().map(Ok).collect(),
    )
}

/// The scripted `harness.edit.replace` chain: read, replace, submit.
fn edit_replies() -> Vec<Completion> {
    vec![
        harness_testkit::act("harness.fs.read", r#"{"path":"a.txt"}"#),
        harness_testkit::act(
            "harness.edit.replace",
            r#"{"path":"a.txt","old":"answer","new":"reply"}"#,
        ),
        harness_testkit::submit(),
    ]
}

/// Spawn `serve` in a thread with the pipes as its stdio. The fixture
/// moves in and comes back with the reports (the audit runs on the
/// test's thread).
fn serve_thread(
    fx: Fixture,
    up: Pipe,
    down: Pipe,
    replies: Vec<Completion>,
) -> std::thread::JoinHandle<(Fixture, harness_acp::ServeOutput)> {
    std::thread::spawn(move || {
        let policy = UserPolicy::default();
        let profile = Profile::conservative_default("m");
        let reg = registry().unwrap();
        let backend = backend(replies);
        let config = SessionConfig::defaults(1_000_000);
        let params = harness_acp::ServeParams {
            state_root: fx.state_root(),
            spec: &fx.spec,
            registry: &reg,
            policy: &policy,
            profile: &profile,
            backend: &backend,
            probe: &Local,
            env: &FixedEnv,
            confinement: None,
            config,
            allow_session_grants: false,
            notes: &mut |_s: &str| {},
        };
        let reader = TestReader {
            pipe: up,
            staging: Vec::new(),
            pos: 0,
        };
        let out = harness_acp::serve(params, reader, TestWriter(down));
        (fx, out)
    })
}

fn initialize(client: &Client) -> Value {
    client.send(&json!({
        "jsonrpc":"2.0","id":0,"method":"initialize",
        "params":{"protocolVersion":1,"clientCapabilities":{},"clientInfo":{"name":"test"}}
    }));
    client.recv()
}

fn new_session(client: &Client, id: i32, ws: &std::path::Path) -> String {
    client.send(&json!({
        "jsonrpc":"2.0","id":id,"method":"session/new",
        "params":{"cwd": ws.to_string_lossy(), "mcpServers":[]}
    }));
    let v = client.recv();
    v["result"]["sessionId"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn prompt(client: &Client, id: i32, sid: &str, text: &str) {
    client.send(&json!({
        "jsonrpc":"2.0","id":id,"method":"session/prompt",
        "params":{"sessionId":sid,"prompt":[{"type":"text","text":text}]}
    }));
}

/// Read protocol lines until the prompt response (`id`) arrives;
/// returns its stopReason.
fn await_response(client: &Client, id: i64, max_lines: usize) -> Value {
    for _ in 0..max_lines {
        let v = client.recv();
        if v["id"].as_i64() == Some(id) {
            return v["result"]["stopReason"].clone();
        }
    }
    panic!("the prompt {id} was never answered");
}

// ---------------------------------------------------------------------------
// The tests.
// ---------------------------------------------------------------------------

#[test]
fn acp_initialize_handshake() {
    let fx = read_fixture("acp-handshake");
    let ws = fx.workspace().to_path_buf();
    let (client, up, down) = Client::new();
    let handle = serve_thread(fx, up, down, vec![]);
    // Before `initialize`, every request is a server error.
    client.send(&json!({
        "jsonrpc":"2.0","id":9,"method":"session/new",
        "params":{"cwd": ws.to_string_lossy(),"mcpServers":[]}
    }));
    let early = client.recv();
    assert_eq!(early["id"], 9);
    assert_eq!(early["error"]["code"], -32002, "{early}");
    let v = initialize(&client);
    assert_eq!(v["result"]["protocolVersion"], 1, "{v}");
    assert_eq!(v["result"]["agentInfo"]["name"], "rustyharness", "{v}");
    assert_eq!(
        v["result"]["agentCapabilities"]["loadSession"],
        json!(false),
        "{v}"
    );
    assert_eq!(v["result"]["authMethods"], json!([]), "{v}");
    // A second `initialize` is refused.
    client.send(&json!({
        "jsonrpc":"2.0","id":10,"method":"initialize","params":{"protocolVersion":1}
    }));
    let again = client.recv();
    assert_eq!(again["error"]["code"], -32601, "{again}");
    client.close();
    let (_, out) = handle.join().unwrap();
    assert!(out.sessions.is_empty(), "{}", out.sessions.len());
}

#[test]
fn acp_prompt_streams_updates() {
    let fx = read_fixture("acp-stream");
    let ws = fx.workspace().to_path_buf();
    let (client, up, down) = Client::new();
    let handle = serve_thread(
        fx,
        up,
        down,
        vec![harness_testkit::say("The answer is forty-two.")],
    );
    initialize(&client);
    let sid = new_session(&client, 1, &ws);
    assert!(!sid.is_empty());
    prompt(&client, 2, &sid, "What does a.txt say?");
    // The reply streams as an update BEFORE the prompt's response.
    let mut seen: Vec<Value> = Vec::new();
    let chunk = client.recv_method("session/update", &mut seen);
    assert_eq!(
        chunk["params"]["update"]["sessionUpdate"], "agent_message_chunk",
        "{chunk}"
    );
    assert!(
        chunk["params"]["update"]["content"]["text"]
            .as_str()
            .unwrap_or_default()
            .contains("forty-two"),
        "{chunk}"
    );
    assert_eq!(await_response(&client, 2, 8), json!("end_turn"));
    client.close();
    let (fx, out) = handle.join().unwrap();
    assert_eq!(out.sessions.len(), 1, "{}", out.sessions.len());
    let (_, report) = &out.sessions[0];
    harness_testkit::assert_session_audit_clean(&fx, report).unwrap();
}

#[test]
fn acp_permission_request_roundtrip_yes_no() {
    // YES: the edit is approved and runs.
    let fx = edit_fixture("acp-perm-yes");
    let ws = fx.workspace().to_path_buf();
    let (client, up, down) = Client::new();
    let handle = serve_thread(fx, up, down, edit_replies());
    initialize(&client);
    let sid = new_session(&client, 1, &ws);
    prompt(&client, 2, &sid, "Change 'answer' to 'reply' in a.txt.");
    let mut seen: Vec<Value> = Vec::new();
    let perm = client.recv_method("session/request_permission", &mut seen);
    let perm_id = perm["id"].as_str().expect("string request id").to_owned();
    let options = perm["params"]["options"].as_array().expect("options");
    assert!(
        options.iter().any(|o| o["optionId"] == "allow-once"),
        "{perm}"
    );
    assert!(
        options.iter().any(|o| o["optionId"] == "reject-once"),
        "{perm}"
    );
    // No session-grant options without the flag.
    assert!(
        !options.iter().any(|o| o["optionId"] == "allow-always"),
        "{perm}"
    );
    assert_eq!(perm["params"]["sessionId"], sid, "{perm}");
    client.send(&json!({
        "jsonrpc":"2.0","id":perm_id,
        "result":{"outcome":{"outcome":"selected","optionId":"allow-once"}}
    }));
    // The answered ask's tool call completes; the prompt is answered.
    let mut completed = false;
    for _ in 0..48 {
        let v = client.recv();
        let u = &v["params"]["update"];
        if v["method"] == json!("session/update")
            && u["sessionUpdate"] == json!("tool_call_update")
            && u["toolCallId"]
                .as_str()
                .is_some_and(|t| t.starts_with("ask-"))
        {
            assert_eq!(u["status"], json!("completed"), "{v}");
            completed = true;
        }
        if v["id"].as_i64() == Some(2) {
            assert_eq!(v["result"]["stopReason"], json!("end_turn"), "{v}");
            break;
        }
    }
    assert!(completed, "the ask's tool call never completed");
    client.close();
    let (fx, out) = handle.join().unwrap();
    assert_eq!(
        std::fs::read_to_string(ws.join("a.txt")).unwrap(),
        "the reply is in here\n"
    );
    harness_testkit::assert_session_audit_clean(&fx, &out.sessions[0].1).unwrap();

    // NO: the same ask, rejected — the edit never runs.
    let fx = edit_fixture("acp-perm-no");
    let ws = fx.workspace().to_path_buf();
    let (client, up, down) = Client::new();
    let handle = serve_thread(fx, up, down, edit_replies());
    initialize(&client);
    let sid = new_session(&client, 1, &ws);
    prompt(&client, 2, &sid, "Change 'answer' to 'reply' in a.txt.");
    let mut seen: Vec<Value> = Vec::new();
    let perm = client.recv_method("session/request_permission", &mut seen);
    let perm_id = perm["id"].as_str().expect("string request id").to_owned();
    client.send(&json!({
        "jsonrpc":"2.0","id":perm_id,
        "result":{"outcome":{"outcome":"selected","optionId":"reject-once"}}
    }));
    let mut failed = false;
    for _ in 0..48 {
        let v = client.recv();
        let u = &v["params"]["update"];
        if v["method"] == json!("session/update")
            && u["sessionUpdate"] == json!("tool_call_update")
            && u["toolCallId"]
                .as_str()
                .is_some_and(|t| t.starts_with("ask-"))
        {
            assert_eq!(u["status"], json!("failed"), "{v}");
            failed = true;
        }
        if v["id"].as_i64() == Some(2) {
            assert_eq!(v["result"]["stopReason"], json!("end_turn"), "{v}");
            break;
        }
    }
    assert!(failed, "the ask's tool call never failed");
    client.close();
    let (fx, out) = handle.join().unwrap();
    assert_eq!(
        std::fs::read_to_string(ws.join("a.txt")).unwrap(),
        "the answer is in here\n"
    );
    harness_testkit::assert_session_audit_clean(&fx, &out.sessions[0].1).unwrap();
}

#[test]
fn acp_cancel_ends_turn() {
    let fx = edit_fixture("acp-cancel");
    let ws = fx.workspace().to_path_buf();
    let (client, up, down) = Client::new();
    let handle = serve_thread(fx, up, down, edit_replies());
    initialize(&client);
    let sid = new_session(&client, 1, &ws);
    prompt(&client, 2, &sid, "Change 'answer' to 'reply' in a.txt.");
    let mut seen: Vec<Value> = Vec::new();
    let perm = client.recv_method("session/request_permission", &mut seen);
    let perm_id = perm["id"].as_str().expect("string request id").to_owned();
    // The client cancels the turn, then answers the pending permission
    // cancelled (the spec's own sequence): the ask is a deny, the turn
    // runs to its natural end, and the prompt's response is
    // `cancelled`.
    client.send(&json!({
        "jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":sid}
    }));
    client.send(&json!({
        "jsonrpc":"2.0","id":perm_id,"result":{"outcome":"cancelled"}
    }));
    assert_eq!(await_response(&client, 2, 48), json!("cancelled"));
    client.close();
    let (fx, out) = handle.join().unwrap();
    // The workspace is untouched: the cancelled ask denied the edit.
    assert_eq!(
        std::fs::read_to_string(ws.join("a.txt")).unwrap(),
        "the answer is in here\n"
    );
    harness_testkit::assert_session_audit_clean(&fx, &out.sessions[0].1).unwrap();
}

#[test]
fn acp_session_journal_audits_clean() {
    let fx = read_fixture("acp-audit");
    let ws = fx.workspace().to_path_buf();
    let (client, up, down) = Client::new();
    let handle = serve_thread(
        fx,
        up,
        down,
        vec![
            harness_testkit::say("Working on it."),
            harness_testkit::submit(),
        ],
    );
    initialize(&client);
    let sid = new_session(&client, 1, &ws);
    prompt(&client, 2, &sid, "What does a.txt say?");
    assert_eq!(await_response(&client, 2, 32), json!("end_turn"));
    client.close();
    let (fx, out) = handle.join().unwrap();
    assert_eq!(out.sessions.len(), 1);
    let (_, report) = &out.sessions[0];
    harness_testkit::assert_session_audit_clean(&fx, report).unwrap();
}

#[test]
fn acp_rejects_malformed_json_rpc() {
    let fx = read_fixture("acp-malformed");
    let ws = fx.workspace().to_path_buf();
    let (client, up, down) = Client::new();
    let handle = serve_thread(fx, up, down, vec![]);
    // Not JSON at all: -32700 with id null.
    client.send_raw("this is not json");
    let v = client.recv();
    assert_eq!(v["error"]["code"], -32700, "{v}");
    assert!(v["id"].is_null(), "{v}");
    // Wrong protocol version: -32600.
    client.send_raw(r#"{"jsonrpc":"1.0","id":1,"method":"initialize","params":{}}"#);
    let v = client.recv();
    assert_eq!(v["error"]["code"], -32600, "{v}");
    // The handshake itself is fine.
    let v = initialize(&client);
    assert_eq!(v["result"]["protocolVersion"], 1);
    // Unknown method: -32601.
    client.send(&json!({"jsonrpc":"2.0","id":2,"method":"frobnicate","params":{}}));
    let v = client.recv();
    assert_eq!(v["error"]["code"], -32601, "{v}");
    // Bad params: session/new with a relative cwd → -32602.
    client.send(&json!({
        "jsonrpc":"2.0","id":3,"method":"session/new",
        "params":{"cwd":"relative/path","mcpServers":[]}
    }));
    let v = client.recv();
    assert_eq!(v["error"]["code"], -32602, "{v}");
    // An MCP server list is refused (none advertised).
    client.send(&json!({
        "jsonrpc":"2.0","id":4,"method":"session/new",
        "params":{"cwd": ws.to_string_lossy(),
                  "mcpServers":[{"name":"x","command":"y"}]}
    }));
    let v = client.recv();
    assert_eq!(v["error"]["code"], -32602, "{v}");
    // A capability we do not advertise: -32601.
    client.send(&json!({
        "jsonrpc":"2.0","id":5,"method":"session/load",
        "params":{"sessionId":"x","cwd":"/"}
    }));
    let v = client.recv();
    assert_eq!(v["error"]["code"], -32601, "{v}");
    // An unsupported prompt content block: -32602.
    let sid = new_session(&client, 6, &ws);
    client.send(&json!({
        "jsonrpc":"2.0","id":7,"method":"session/prompt",
        "params":{"sessionId":sid,"prompt":[{"type":"image","data":"aGk=","mimeType":"image/png"}]}
    }));
    let v = client.recv();
    assert_eq!(v["error"]["code"], -32602, "{v}");
    client.close();
    let (_, out) = handle.join().unwrap();
    // Nothing above started a run.
    assert!(out.sessions.is_empty(), "{}", out.sessions.len());
}

#[test]
fn acp_never_binds_a_socket() {
    // Code scan (P-35): the server is stdio-only — no listener, no
    // socket type, no bind/listen anywhere in the crate's sources.
    let manifest = env!("CARGO_MANIFEST_DIR");
    let src = std::path::Path::new(manifest).join("src");
    let forbidden = [
        "TcpListener",
        "TcpStream",
        "UdpSocket",
        "UnixListener",
        "UnixDatagram",
        "UnixStream",
        ".bind(",
        ".listen(",
    ];
    let mut scanned = 0;
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().and_then(|x| x.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&p).unwrap();
            for tok in forbidden {
                assert!(
                    !text.contains(tok),
                    "{} must not contain {tok}: the ACP server is stdio-only",
                    p.display()
                );
            }
            scanned += 1;
        }
    }
    assert!(scanned >= 3, "the scan saw only {scanned} files");
}
