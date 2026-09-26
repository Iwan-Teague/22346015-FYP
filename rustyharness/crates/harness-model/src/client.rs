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
//! that the endpoint is loopback (INV-24).
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
use crate::http::{exchange, HttpError};
use crate::profile::Profile;
use crate::wire::{parse_json_reply, parse_sse_reply, render_request};
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
    /// Jitter seed (the run driver passes a random one).
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
#[derive(Debug)]
pub struct OpenAiCompatible {
    endpoint: Endpoint,
    addr: SocketAddr,
    profile: Profile,
    key: Option<ApiKey>,
    config: ClientConfig,
    claims: std::cell::RefCell<crate::ServerClaims>,
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
        config: ClientConfig,
    ) -> Result<Self, EndpointRefused> {
        let endpoint = Endpoint::parse(url)?;
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
        })
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
        )
    }

    fn attempt(&self, body: &[u8], deadline: Instant, retried: &[u16]) -> Attempt {
        let resp = match self.send("POST", "/chat/completions", body, deadline) {
            Ok(r) => r,
            Err(e) => return Attempt::Done(Err(map_http(e))),
        };
        let req_bytes = u64::try_from(body.len()).unwrap_or(u64::MAX);
        match resp.status {
            200 => Attempt::Done(match resp.content_type.as_deref() {
                Some("text/event-stream") => {
                    parse_sse_reply(&resp.body, req_bytes, retried.to_vec())
                }
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

    /// Startup check (§3.2): `GET /models` must answer and list the
    /// profile's model. Fails closed with a typed error.
    pub fn startup_check(&self, deadline: Instant) -> Result<(), ModelError> {
        let resp = self
            .send("GET", "/models", &[], deadline)
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
