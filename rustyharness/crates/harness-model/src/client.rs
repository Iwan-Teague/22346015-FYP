//! The loopback OpenAI-compatible backend (design §3.2).
//!
//! - The endpoint is checked when the client is built (session planning):
//!   loopback only, refused otherwise (INV-24, see [`crate::endpoint`]).
//! - Each call renders the request once, then makes up to
//!   `1 + retry.max_retries` attempts. ONLY 429 and 5xx are retried (§3.2),
//!   with exponential backoff and jitter, never past the call's deadline,
//!   and each failed attempt's status is recorded on the result. Empty,
//!   truncated, malformed or oversized replies, timeouts and connection
//!   failures are returned at once as typed errors: never retried here, and
//!   never an empty success (INV-3). Whether a failed call is repeated is the
//!   loop's repair policy (§2.7), not the client's.
//! - The API key (§5.5) lives only in this process: it is written into the
//!   `Authorization` header and nowhere else. `Debug`, errors and the
//!   journal identity carry its handle name, never its value.
//!
//! The socket-level HTTP client is crate-private (H1d review F-1): the only
//! way to reach a server is [`OpenAiCompatible`], whose constructor checks
//! that the endpoint is loopback (INV-24). A streamed reply is parsed as it
//! arrives (P-06) and may be watched through
//! [`OpenAiCompatible::with_observer`]; the observer is display state only —
//! it is not on the [`ModelBackend`] trait, and the returned `Completion`
//! is the same with or without one, so what the journal records does not
//! change.
//!
//! ```compile_fail,E0603
//! let _ = harness_model::http::exchange;
//! ```

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use harness_core::strict_json;
use serde_json::Value;

use crate::endpoint::{Endpoint, EndpointRefused, LoopbackHost};
pub use crate::http::HttpLimits;
use crate::http::{exchange, HttpError, OnChunk};
use crate::profile::Profile;
use crate::wire::{parse_json_reply, render_request, SseReader, StreamObserver};
use crate::{
    Completion, EndpointClass, ModelBackend, ModelError, ModelIdentity, ModelRequest, Unavailable,
};

/// An API key held in process memory (§5.5).
pub struct ApiKey {
    handle: String,
    secret: String,
}

/// Why an API key was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiKeyError {
    /// The handle is not `[A-Za-z0-9._-]{1,64}`.
    #[error("API key handle is not a valid name")]
    Handle,
    /// The secret is empty, too long, or has characters that could break
    /// out of an HTTP header (space, CR, LF, control, non-ASCII).
    #[error("API key value is not a single visible-ASCII token")]
    Secret,
}

impl ApiKey {
    /// A key known to the journal as `handle`.
    pub fn new(handle: &str, secret: String) -> Result<Self, ApiKeyError> {
        let handle_ok = !handle.is_empty()
            && handle.len() <= 64
            && handle
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !handle_ok {
            return Err(ApiKeyError::Handle);
        }
        if secret.is_empty() || secret.len() > 4096 || !secret.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(ApiKeyError::Secret);
        }
        Ok(Self {
            handle: handle.to_owned(),
            secret,
        })
    }

    /// The handle name (what the journal records).
    pub fn handle(&self) -> &str {
        &self.handle
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKey")
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

/// Retry budget for 429 and 5xx (§3.2: default 3 per turn).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Retries after the first attempt.
    pub max_retries: u32,
    /// First backoff, milliseconds.
    pub base_ms: u64,
    /// Largest backoff, milliseconds.
    pub cap_ms: u64,
    /// Jitter seed. The default is 0, and the CLI passes the default, so in
    /// H1 every client backs off on the same schedule (a caller wanting
    /// clients to spread out passes a seed per client).
    pub jitter_seed: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_ms: 500,
            cap_ms: 8000,
            jitter_seed: 0,
        }
    }
}

fn splitmix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// Backoff before retry `attempt` (0-based): exponential with "equal
/// jitter", i.e. half fixed and half jittered, capped. Pure.
pub fn backoff_ms(p: &RetryPolicy, attempt: u32) -> u64 {
    let exp = p
        .base_ms
        .saturating_mul(1u64.checked_shl(attempt).unwrap_or(u64::MAX))
        .min(p.cap_ms);
    let half = exp / 2;
    half + splitmix(p.jitter_seed ^ u64::from(attempt)) % (half + 1)
}

/// Client configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClientConfig {
    /// HTTP limits and timeouts.
    pub limits: HttpLimits,
    /// Retry budget.
    pub retry: RetryPolicy,
}

/// The loopback OpenAI-compatible backend.
pub struct OpenAiCompatible {
    endpoint: Endpoint,
    addr: SocketAddr,
    profile: Profile,
    key: Option<ApiKey>,
    config: ClientConfig,
    claims: std::cell::RefCell<crate::ServerClaims>,
    /// The streaming observer, if any (P-06). Caller state, never printed:
    /// it sees the reply's deltas as they arrive and nothing else, and the
    /// `Completion` is built without it, so the loop, the journal and
    /// replay are unaffected. `Send`: a backend may move between threads
    /// (the callbacks run on whichever thread calls `complete`).
    observer: Option<Box<dyn StreamObserver + Send>>,
}

impl fmt::Debug for OpenAiCompatible {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenAiCompatible")
            .field("endpoint", &self.endpoint)
            .field("addr", &self.addr)
            .field("profile", &self.profile)
            .field("key", &self.key)
            .field("config", &self.config)
            .field("claims", &self.claims)
            .field("observer", &self.observer.is_some())
            .finish()
    }
}

fn map_http(e: HttpError) -> ModelError {
    match e {
        HttpError::Connect(k) | HttpError::Io(k) => {
            ModelError::Unavailable(Unavailable::Connect(k))
        }
        HttpError::ConnectTimeout => ModelError::Unavailable(Unavailable::ConnectTimeout),
        HttpError::ReadTimeout => ModelError::Unavailable(Unavailable::ReadTimeout),
        HttpError::Deadline => ModelError::Unavailable(Unavailable::Deadline),
        HttpError::TooLarge(what) => ModelError::Unusable(format!("{what} too large")),
        HttpError::Malformed(what) => {
            ModelError::Unusable(format!("malformed HTTP response: {what}"))
        }
    }
}

/// One attempt's result: a completion, a retryable status (with the
/// server's `Retry-After`, if any), or a final error.
enum Attempt {
    Done(Result<Completion, ModelError>),
    Retryable(u16, Option<u64>),
}

impl OpenAiCompatible {
    /// Build a client. The endpoint is refused here unless it is loopback
    /// HTTP (§3.2, INV-24).
    pub fn new(
        url: &str,
        profile: Profile,
        key: Option<ApiKey>,
        mut config: ClientConfig,
    ) -> Result<Self, EndpointRefused> {
        let endpoint = Endpoint::parse(url)?;
        // H2f: a profile that sets a read timeout decides how long one read
        // from this model may take; without one, the config's stands.
        if let Some(t) = profile.read_timeout() {
            config.limits.read_timeout = t;
        }
        let ip = match endpoint.host {
            LoopbackHost::V4 => std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            LoopbackHost::V6 => std::net::IpAddr::V6(Ipv6Addr::LOCALHOST),
        };
        Ok(Self {
            addr: SocketAddr::new(ip, endpoint.port),
            endpoint,
            profile,
            key,
            config,
            claims: std::cell::RefCell::new(crate::ServerClaims::default()),
            observer: None,
        })
    }

    /// The HTTP limits this client uses: the config's, with the profile's
    /// read timeout (H2f) when it sets one.
    pub fn limits(&self) -> HttpLimits {
        self.config.limits
    }

    /// Set a streaming observer (P-06): it is told the reply's content,
    /// reasoning and tool-call name deltas as the server sends them, before
    /// the call returns. Deliberately NOT on the [`ModelBackend`] trait: the
    /// loop and replay never see it, and the returned `Completion` — the
    /// thing the journal records — is byte-identical with or without one.
    #[must_use]
    pub fn with_observer(mut self, observer: Box<dyn StreamObserver + Send>) -> Self {
        self.observer = Some(observer);
        self
    }

    fn headers(&self) -> Vec<(&str, String)> {
        let mut h = Vec::new();
        if let Some(k) = &self.key {
            h.push(("Authorization", format!("Bearer {}", k.secret)));
        }
        h
    }

    fn send(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        deadline: Instant,
        on_chunk: Option<&mut crate::http::OnChunk<'_>>,
    ) -> Result<crate::http::HttpResponse, HttpError> {
        let owned = self.headers();
        let headers: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
        exchange(
            self.addr,
            method,
            &self.endpoint.host_header,
            &self.endpoint.path(path),
            &headers,
            body,
            &self.config.limits,
            deadline,
            on_chunk,
        )
    }

    fn attempt(&self, body: &[u8], deadline: Instant, retried: &[u16]) -> Attempt {
        let req_bytes = u64::try_from(body.len()).unwrap_or(u64::MAX);
        // P-06: a streamed reply is parsed as it arrives, feeding the
        // observer, if one is set, while the bytes are still collected; the
        // completion is built from what arrived exactly as the one-shot
        // parse builds it. A parse error aborts the read at once and is
        // carried in `error`, since the exchange itself can only report an
        // `HttpError`.
        let mut reader = SseReader::new(match self.observer.as_deref() {
            // The stored observer is `+ Send`; the reader wants the trait.
            Some(o) => Some(o as &dyn StreamObserver),
            None => None,
        });
        let error: std::cell::RefCell<Option<ModelError>> = std::cell::RefCell::new(None);
        let mut sink = |bytes: &[u8]| -> Result<(), HttpError> {
            match reader.feed(bytes) {
                Ok(()) => Ok(()),
                Err(e) => {
                    *error.borrow_mut() = Some(e);
                    Err(HttpError::Malformed("stream"))
                }
            }
        };
        let resp = match self.send(
            "POST",
            "/chat/completions",
            body,
            deadline,
            Some(&mut sink as &mut OnChunk),
        ) {
            Ok(r) => r,
            Err(e) => {
                return Attempt::Done(Err(match error.into_inner() {
                    Some(e) => e,
                    None => map_http(e),
                }));
            }
        };
        match resp.status {
            200 => Attempt::Done(match resp.content_type.as_deref() {
                Some("text/event-stream") => reader.finish(req_bytes, retried.to_vec()),
                Some("application/json") => {
                    parse_json_reply(&resp.body, req_bytes, retried.to_vec())
                }
                _ => Err(ModelError::Unusable("unexpected content type".into())),
            }),
            429 => Attempt::Retryable(429, resp.retry_after_secs),
            s @ 500..=599 => Attempt::Retryable(s, resp.retry_after_secs),
            s => Attempt::Done(Err(ModelError::Unusable(format!("HTTP status {s}")))),
        }
    }

    /// The models the server lists (`GET /models`, P-07): `profile init`
    /// offers them before a profile exists. Fails closed with a typed
    /// error; unlike [`startup_check`](Self::startup_check) it needs no
    /// profile, so it never sets server claims.
    pub fn list_models(&self, deadline: Instant) -> Result<Vec<String>, ModelError> {
        let resp = self
            .send("GET", "/models", &[], deadline, None)
            .map_err(map_http)?;
        if resp.status != 200 {
            return Err(ModelError::Unusable(format!(
                "GET /models returned {}",
                resp.status
            )));
        }
        let v = strict_json::parse(&resp.body)
            .map_err(|_| ModelError::Unusable("GET /models: malformed JSON".into()))?;
        Ok(v.get("data")
            .and_then(Value::as_array)
            .map(|d| {
                d.iter()
                    .filter_map(|m| m.get("id").and_then(Value::as_str))
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Startup check (§3.2): `GET /models` must answer and list the
    /// profile's model. Fails closed with a typed error.
    pub fn startup_check(&self, deadline: Instant) -> Result<(), ModelError> {
        let resp = self
            .send("GET", "/models", &[], deadline, None)
            .map_err(map_http)?;
        if resp.status != 200 {
            return Err(ModelError::Unusable(format!(
                "GET /models returned {}",
                resp.status
            )));
        }
        let v = strict_json::parse(&resp.body)
            .map_err(|_| ModelError::Unusable("GET /models: malformed JSON".into()))?;
        let listed = v.get("data").and_then(Value::as_array).and_then(|d| {
            d.iter()
                .filter_map(|m| m.get("id").and_then(Value::as_str))
                .find(|id| *id == self.profile.model())
        });
        if let Some(id) = listed {
            // §3.5: what the server claims, kept for the journal header.
            *self.claims.borrow_mut() = crate::ServerClaims {
                model_id: Some(id.to_owned()),
                server: resp.server.clone(),
                template_sha256: None,
            };
            Ok(())
        } else {
            Err(ModelError::Unusable(
                "the server does not list the profile's model".into(),
            ))
        }
    }
}

impl ModelBackend for OpenAiCompatible {
    fn identity(&self) -> ModelIdentity {
        ModelIdentity {
            endpoint: EndpointClass::Loopback,
            profile_id: self.profile.id().to_owned(),
            profile_sha256: self.profile.sha256().map(|d| d.to_string()),
            profile_validated: self.profile.validated(),
            profile_stamp_sha256: self.profile.stamp_sha256().map(str::to_owned),
            api_key_handle: self.key.as_ref().map(|k| k.handle.clone()),
            claimed: self.claims.borrow().clone(),
        }
    }

    fn complete(&self, req: &ModelRequest, deadline: Instant) -> Result<Completion, ModelError> {
        let rendered =
            render_request(req, &self.profile).map_err(|e| ModelError::Unusable(e.to_string()))?;
        let body = rendered.to_string().into_bytes();
        let mut retried: Vec<u16> = Vec::new();
        let mut attempt: u32 = 0;
        loop {
            let (status, retry_after) = match self.attempt(&body, deadline, &retried) {
                Attempt::Done(r) => return r,
                Attempt::Retryable(s, ra) => (s, ra),
            };
            retried.push(status);
            let give_up = |s: u16, statuses: Vec<u16>| {
                if s == 429 {
                    ModelError::RateLimited { statuses }
                } else {
                    ModelError::Unavailable(Unavailable::Status { code: s, statuses })
                }
            };
            if attempt >= self.config.retry.max_retries {
                return Err(give_up(status, retried));
            }
            // Retry-After (H1e-2b) is honoured as a floor on the backoff,
            // still bounded by the retry count above and the deadline below:
            // a server asking for longer than the call has left ends it.
            let wait = Duration::from_millis(backoff_ms(&self.config.retry, attempt))
                .max(Duration::from_secs(retry_after.unwrap_or(0)));
            match deadline.checked_duration_since(Instant::now()) {
                Some(left) if left > wait => std::thread::sleep(wait),
                _ => return Err(give_up(status, retried)),
            }
            attempt += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_is_capped_and_jittered_within_bounds() {
        let p = RetryPolicy {
            max_retries: 3,
            base_ms: 100,
            cap_ms: 1000,
            jitter_seed: 42,
        };
        for a in 0..10 {
            let exp = (100u64 << a.min(20)).min(1000);
            let b = backoff_ms(&p, a);
            assert!(
                b >= exp / 2 && b <= exp,
                "attempt {a}: {b} not in [{}, {exp}]",
                exp / 2
            );
        }
        assert_eq!(
            backoff_ms(&p, 64),
            backoff_ms(&p, 64),
            "no overflow panic, deterministic"
        );
    }

    #[test]
    fn api_keys_are_single_header_tokens_and_never_debug_printed() {
        assert!(ApiKey::new("local-llama", "sk-abc.DEF_123".into()).is_ok());
        for bad in ["", "a b", "a\r\nX-Evil: 1", "é", &"a".repeat(4097)] {
            assert_eq!(
                ApiKey::new("h", bad.to_owned()).unwrap_err(),
                ApiKeyError::Secret,
                "{bad:?}"
            );
        }
        for bad in ["", "a b", "a/b", &"a".repeat(65)] {
            assert_eq!(
                ApiKey::new(bad, "x".into()).unwrap_err(),
                ApiKeyError::Handle
            );
        }
        let k = ApiKey::new("local-llama", "sk-SECRETVALUE".into()).unwrap();
        assert!(!format!("{k:?}").contains("SECRETVALUE"));
        assert_eq!(k.handle(), "local-llama");
    }

    #[test]
    fn inv_24_the_client_refuses_non_loopback_at_construction() {
        let p = Profile::conservative_default("m");
        for url in [
            "http://lan-host.example/v1",
            "https://127.0.0.1/v1",
            "http://127.0.0.2/v1",
        ] {
            assert!(
                OpenAiCompatible::new(url, p.clone(), None, ClientConfig::default()).is_err(),
                "{url}"
            );
        }
    }
}
