//! An in-repo mock OpenAI-compatible HTTP server, std only (no new dependencies).
//!
//! It exists so the client's behaviour against *realistic endpoint failure modes* is tested
//! without loading a model on a shared machine: scripted responses (status codes, `Retry-After`,
//! SSE streams that stall, reset or end early, truncated bodies, dropped connections) and a
//! synthetic [`ModelSpec`] "model" with a configurable prefill rate, decode rate, throttling and
//! reporting quirks, which is what bench-hw's calibration is exercised against.
//!
//! **What it is not:** a model, or evidence about any real backend. Everything verified against
//! it is verified against *this author's reading of* llama.cpp / vLLM / Ollama / LM Studio
//! behaviour (docs/15 §2, §10), and BUILD-LOG says so per item.
//!
//! One request per connection (`Connection: close`), a thread per connection, chunked transfer
//! for SSE so that an abrupt close without the terminating chunk is a genuine mid-stream failure
//! to the client rather than a clean end.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How a scripted SSE stream ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SseEnd {
    /// Terminate the chunked body properly.
    Done,
    /// Close the socket without the terminating chunk: a connection reset mid-stream.
    Reset,
    /// Keep the connection open and silent for this long (a stalled server).
    Hang(u64),
}

/// A synthetic model. Rates are tokens per second; all pacing is deadline-based so sleep jitter
/// does not accumulate.
#[derive(Clone, Debug)]
pub struct ModelSpec {
    pub prefill_tok_per_s: f64,
    pub decode_tok_per_s: f64,
    /// `(after_ms, factor)`: once the *server* has been up for `after_ms`, decode runs at
    /// `decode_tok_per_s * factor` (a laptop throttling under sustained load).
    pub throttle: Option<(u64, f64)>,
    /// Include llama.cpp's `timings` block.
    pub emit_timings: bool,
    /// Include `usage`.
    pub emit_usage: bool,
    /// Leading reasoning tokens, sent as `reasoning_content`.
    pub reasoning_tokens: u32,
    /// Context window; a longer prompt gets llama.cpp's HTTP 400.
    pub ctx: Option<u32>,
    /// The model would stop by itself after this many tokens.
    pub eos_after: u32,
    /// Whether the server honours `ignore_eos`.
    pub honors_ignore_eos: bool,
    /// Tokens the chat template adds around the messages.
    pub template_overhead: u32,
    /// Report this many prompt tokens as served from a cache (`usage.prompt_tokens_details.cached_tokens`
    /// and `timings.cache_n`), as a backend that ignores `cache_prompt: false` would.
    pub report_cached: u32,
}

impl Default for ModelSpec {
    fn default() -> Self {
        ModelSpec {
            prefill_tok_per_s: 50_000.0,
            decode_tok_per_s: 2_000.0,
            throttle: None,
            emit_timings: true,
            emit_usage: true,
            reasoning_tokens: 0,
            ctx: None,
            eos_after: 200,
            honors_ignore_eos: true,
            template_overhead: 8,
            report_cached: 0,
        }
    }
}

/// One scripted reply. The Nth request gets `script[min(N, len-1)]`: the last entry repeats.
#[derive(Clone, Debug)]
pub enum Behavior {
    Json {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    },
    /// Raw SSE text blocks (each normally `data: {...}\n\n`), each preceded by a delay in ms.
    Sse {
        events: Vec<(u64, String)>,
        end: SseEnd,
    },
    /// `Content-Length` claims the whole body; only the first half is sent before closing.
    TruncatedJson {
        body: String,
    },
    /// Accept the connection, read the request, close without answering.
    Drop,
    /// Wait, then behave as `then` (for client request timeouts).
    Delayed {
        ms: u64,
        then: Box<Behavior>,
    },
    Model(ModelSpec),
}

impl Behavior {
    pub fn json(status: u16, body: impl Into<String>) -> Behavior {
        Behavior::Json {
            status,
            headers: vec![],
            body: body.into(),
        }
    }

    pub fn json_with(status: u16, headers: &[(&str, &str)], body: impl Into<String>) -> Behavior {
        Behavior::Json {
            status,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.into(),
        }
    }

    /// A well-formed non-streaming completion.
    pub fn ok(text: &str) -> Behavior {
        Behavior::json(
            200,
            json!({"choices":[{"index":0,"message":{"role":"assistant","content":text},"finish_reason":"stop"}],
                   "usage":{"prompt_tokens":11,"completion_tokens":7}})
            .to_string(),
        )
    }
}

struct Shared {
    script: Vec<Behavior>,
    requests: Mutex<Vec<Value>>,
    count: AtomicUsize,
    stop: AtomicBool,
    started: Instant,
}

pub struct MockServer {
    addr: std::net::SocketAddr,
    shared: Arc<Shared>,
    handle: Option<JoinHandle<()>>,
}

impl MockServer {
    pub fn start(script: Vec<Behavior>) -> MockServer {
        assert!(!script.is_empty(), "a mock needs at least one behaviour");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let shared = Arc::new(Shared {
            script,
            requests: Mutex::new(Vec::new()),
            count: AtomicUsize::new(0),
            stop: AtomicBool::new(false),
            started: Instant::now(),
        });
        let sh = Arc::clone(&shared);
        let handle = std::thread::spawn(move || {
            for conn in listener.incoming() {
                if sh.stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = conn else { continue };
                let sh = Arc::clone(&sh);
                std::thread::spawn(move || {
                    let _ = serve(stream, &sh);
                });
            }
        });
        MockServer {
            addr,
            shared,
            handle: Some(handle),
        }
    }

    /// `http://127.0.0.1:<port>`
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Request bodies received so far (parsed JSON), in arrival order.
    pub fn requests(&self) -> Vec<Value> {
        self.shared
            .requests
            .lock()
            .map(|r| r.clone())
            .unwrap_or_default()
    }

    pub fn request_count(&self) -> usize {
        self.shared.count.load(Ordering::SeqCst)
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr); // wake the accept loop
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn read_request(stream: &TcpStream) -> std::io::Result<Option<(String, Value)>> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
    let mut content_length = 0usize;
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;
    let v = serde_json::from_slice(&body).unwrap_or(Value::Null);
    Ok(Some((path, v)))
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        408 => "Request Timeout",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}

fn write_json(
    s: &mut TcpStream,
    status: u16,
    headers: &[(String, String)],
    body: &str,
) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        status_text(status),
        body.len()
    );
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes())?;
    s.write_all(body.as_bytes())?;
    s.flush()
}

fn sse_head(s: &mut TcpStream) -> std::io::Result<()> {
    s.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
    )?;
    s.flush()
}

fn sse_chunk(s: &mut TcpStream, data: &str) -> std::io::Result<()> {
    s.write_all(format!("{:x}\r\n{}\r\n", data.len(), data).as_bytes())?;
    s.flush()
}

fn serve(mut stream: TcpStream, sh: &Shared) -> std::io::Result<()> {
    let Some((path, req)) = read_request(&stream)? else {
        return Ok(()); // the wake-up connection from Drop
    };
    if path != "/v1/chat/completions" {
        return write_json(
            &mut stream,
            404,
            &[],
            r#"{"error":{"message":"not found"}}"#,
        );
    }
    let idx = sh.count.fetch_add(1, Ordering::SeqCst);
    if let Ok(mut r) = sh.requests.lock() {
        r.push(req.clone());
    }
    let b = &sh.script[idx.min(sh.script.len() - 1)];
    run(&mut stream, b, &req, sh)
}

fn run(s: &mut TcpStream, b: &Behavior, req: &Value, sh: &Shared) -> std::io::Result<()> {
    match b {
        Behavior::Json {
            status,
            headers,
            body,
        } => write_json(s, *status, headers, body),
        Behavior::TruncatedJson { body } => {
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            s.write_all(head.as_bytes())?;
            s.write_all(&body.as_bytes()[..body.len() / 2])?;
            s.flush()?;
            s.shutdown(Shutdown::Both)
        }
        Behavior::Drop => s.shutdown(Shutdown::Both),
        Behavior::Delayed { ms, then } => {
            std::thread::sleep(Duration::from_millis(*ms));
            run(s, then, req, sh)
        }
        Behavior::Sse { events, end } => {
            sse_head(s)?;
            for (delay, text) in events {
                std::thread::sleep(Duration::from_millis(*delay));
                sse_chunk(s, text)?;
            }
            match end {
                SseEnd::Done => {
                    s.write_all(b"0\r\n\r\n")?;
                    s.flush()
                }
                SseEnd::Reset => s.shutdown(Shutdown::Both),
                SseEnd::Hang(ms) => {
                    std::thread::sleep(Duration::from_millis(*ms));
                    s.shutdown(Shutdown::Both)
                }
            }
        }
        Behavior::Model(spec) => model(s, spec, req, sh),
    }
}

fn sleep_until(t: Instant) {
    let now = Instant::now();
    if t > now {
        std::thread::sleep(t - now);
    }
}

fn prompt_tokens(spec: &ModelSpec, req: &Value) -> u32 {
    let words: usize = req["messages"]
        .as_array()
        .map(|m| {
            m.iter()
                .filter_map(|x| x["content"].as_str())
                .map(|c| c.split_whitespace().count())
                .sum()
        })
        .unwrap_or(0);
    spec.template_overhead + words as u32
}

fn chunk_json(delta: Value, finish: Value) -> String {
    format!(
        "data: {}\n\n",
        json!({"id":"mock","object":"chat.completion.chunk","choices":[{"index":0,"delta":delta,"finish_reason":finish}]})
    )
}

fn model(s: &mut TcpStream, spec: &ModelSpec, req: &Value, sh: &Shared) -> std::io::Result<()> {
    let prompt_n = prompt_tokens(spec, req);
    if let Some(ctx) = spec.ctx {
        if prompt_n >= ctx {
            let body = json!({"error":{"code":400,"message":"the request exceeds the available context size","type":"exceed_context_size_error","n_prompt_tokens":prompt_n,"n_ctx":ctx}});
            return write_json(s, 400, &[], &body.to_string());
        }
    }
    let max_tokens = req["max_tokens"].as_u64().unwrap_or(256) as u32;
    let ignore_eos = req["ignore_eos"].as_bool().unwrap_or(false) && spec.honors_ignore_eos;
    let natural = if ignore_eos { u32::MAX } else { spec.eos_after };
    let n_gen = max_tokens.min(natural);
    let finish = if n_gen == max_tokens && natural >= max_tokens {
        "length"
    } else {
        "stop"
    };
    let n_reason = spec.reasoning_tokens.min(n_gen);
    let prefill = Duration::from_secs_f64(f64::from(prompt_n) / spec.prefill_tok_per_s);

    // Schedule each token's emission time up front, applying the throttle as the server's
    // uptime crosses its threshold.
    let t0 = Instant::now();
    let mut at = t0 + prefill;
    let mut times = Vec::with_capacity(n_gen as usize);
    let mut decode_total = Duration::ZERO;
    for _ in 0..n_gen {
        let rate = match spec.throttle {
            Some((after_ms, f))
                if sh.started.elapsed() + (at - t0) >= Duration::from_millis(after_ms) =>
            {
                spec.decode_tok_per_s * f
            }
            _ => spec.decode_tok_per_s,
        };
        let step = Duration::from_secs_f64(1.0 / rate);
        at += step;
        decode_total += step;
        times.push(at);
    }
    let timings = spec.emit_timings.then(|| {
        json!({"cache_n":spec.report_cached,"prompt_n":prompt_n,"prompt_ms":prefill.as_secs_f64()*1000.0,
               "predicted_n":n_gen,"predicted_ms":decode_total.as_secs_f64()*1000.0})
    });
    let usage = spec.emit_usage.then(|| {
        let mut u = json!({"prompt_tokens":prompt_n,"completion_tokens":n_gen});
        if spec.report_cached > 0 {
            u["prompt_tokens_details"] = json!({"cached_tokens":spec.report_cached});
        }
        u
    });

    let word = |i: u32| format!("w{i} ");
    if req["stream"].as_bool().unwrap_or(false) {
        sse_head(s)?;
        sse_chunk(
            s,
            &chunk_json(json!({"role":"assistant","content":""}), Value::Null),
        )?;
        for i in 0..n_gen {
            sleep_until(times[i as usize]);
            let delta = if i < n_reason {
                json!({"reasoning_content": format!("r{i} ")})
            } else {
                json!({"content": word(i)})
            };
            sse_chunk(s, &chunk_json(delta, Value::Null))?;
        }
        // final chunk carries finish_reason (+ llama.cpp timings)
        let mut last: Value = serde_json::from_str(
            chunk_json(json!({}), json!(finish))
                .trim_start_matches("data: ")
                .trim(),
        )
        .unwrap_or(Value::Null);
        if let Some(t) = &timings {
            last["timings"] = t.clone();
        }
        sse_chunk(s, &format!("data: {last}\n\n"))?;
        if let Some(u) = &usage {
            sse_chunk(s, &format!("data: {}\n\n", json!({"choices":[],"usage":u})))?;
        }
        sse_chunk(s, "data: [DONE]\n\n")?;
        s.write_all(b"0\r\n\r\n")?;
        s.flush()
    } else {
        if let Some(last) = times.last() {
            sleep_until(*last);
        } else {
            sleep_until(t0 + prefill);
        }
        let content: String = (n_reason..n_gen).map(word).collect();
        let reasoning: String = (0..n_reason).map(|i| format!("r{i} ")).collect();
        let mut msg = json!({"role":"assistant","content":content});
        if n_reason > 0 {
            msg["reasoning_content"] = json!(reasoning);
        }
        let mut body = json!({"choices":[{"index":0,"message":msg,"finish_reason":finish}]});
        if let Some(u) = usage {
            body["usage"] = u;
        }
        if let Some(t) = timings {
            body["timings"] = t;
        }
        write_json(s, 200, &[], &body.to_string())
    }
}
