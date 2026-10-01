//! Endpoint rules (design §3.2, INV-24). Pure.
//!
//! The default build connects only to loopback. Accepted, exactly:
//! `http://127.0.0.1[:port]/…`, `http://[::1][:port]/…` and
//! `http://localhost[:port]/…` (`localhost` is mapped to 127.0.0.1 without
//! a DNS lookup, so a hosts-file entry cannot redirect it). Everything else
//! is refused before any connection: other hosts (plain HTTP would carry
//! prompts across the LAN in cleartext), `https` (TLS and hosted endpoints
//! need the `hosted` feature, which this build does not have), user info,
//! queries, fragments, and anything malformed.

/// A loopback host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopbackHost {
    /// 127.0.0.1 (also what `localhost` means here).
    V4,
    /// ::1.
    V6,
}

/// A validated loopback endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Host.
    pub host: LoopbackHost,
    /// Port.
    pub port: u16,
    /// Base path, e.g. `/v1` (no trailing slash; may be empty).
    pub base_path: String,
    /// The `Host:` header value.
    pub host_header: String,
}

/// Why an endpoint was refused (at session planning, before any traffic).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointRefused {
    /// Not `http://…` or `https://…`.
    #[error("endpoint must be an http:// URL")]
    Scheme,
    /// `https://`: TLS and hosted endpoints need the `hosted` feature.
    #[error("https endpoints need the `hosted` build feature, which this build does not have")]
    NeedsHosted,
    /// A host other than 127.0.0.1, ::1 or localhost.
    #[error("the default build connects only to loopback (127.0.0.1, ::1, localhost)")]
    NotLoopback,
    /// Malformed (user info, bad port, query, fragment, control characters).
    #[error("malformed endpoint URL: {0}")]
    Malformed(&'static str),
}

impl Endpoint {
    /// Parse and check an endpoint base URL such as
    /// `http://127.0.0.1:8080/v1`.
    pub fn parse(url: &str) -> Result<Self, EndpointRefused> {
        if url.len() > 2048 || url.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(EndpointRefused::Malformed(
                "control or whitespace characters",
            ));
        }
        let rest = if let Some(r) = url.strip_prefix("http://") {
            r
        } else if url.starts_with("https://") {
            return Err(EndpointRefused::NeedsHosted);
        } else {
            return Err(EndpointRefused::Scheme);
        };
        if rest.contains(['?', '#']) {
            return Err(EndpointRefused::Malformed("query or fragment"));
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => (rest.get(..i).unwrap_or(""), rest.get(i..).unwrap_or("")),
            None => (rest, ""),
        };
        if authority.contains('@') {
            return Err(EndpointRefused::Malformed("user info"));
        }
        let (host, port) = split_host_port(authority)?;
        let host = match host {
            "127.0.0.1" | "localhost" => LoopbackHost::V4,
            "[::1]" => LoopbackHost::V6,
            _ => return Err(EndpointRefused::NotLoopback),
        };
        // No percent-encoding in the base path: `%2e%2e` and `%0d%0a` would
        // reach the request line raw (H1d review F-7).
        if path.contains('%') {
            return Err(EndpointRefused::Malformed("percent-encoding in the path"));
        }
        let base_path = path.trim_end_matches('/').to_owned();
        if base_path.split('/').any(|seg| seg == ".." || seg == ".") {
            return Err(EndpointRefused::Malformed("dot segments in the path"));
        }
        let host_header = match (host, port) {
            (LoopbackHost::V4, p) => format!("127.0.0.1:{p}"),
            (LoopbackHost::V6, p) => format!("[::1]:{p}"),
        };
        Ok(Self {
            host,
            port,
            base_path,
            host_header,
        })
    }

    /// The path for `suffix`, e.g. `/v1` + `/chat/completions`.
    pub fn path(&self, suffix: &str) -> String {
        format!("{}{suffix}", self.base_path)
    }
}

fn split_host_port(authority: &str) -> Result<(&str, u16), EndpointRefused> {
    let bad = EndpointRefused::Malformed("bad host or port");
    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']').ok_or(bad.clone())?;
        let host = authority.get(..=end).ok_or(bad.clone())?;
        match authority.get(end + 1..).unwrap_or("") {
            "" => (host, None),
            p => (host, Some(p.strip_prefix(':').ok_or(bad.clone())?)),
        }
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let port = match port {
        None => 80,
        Some(p) => {
            // Canonical decimal only: no leading zero (`:080`), so a port
            // has exactly one spelling (H1d review F-7).
            if p.is_empty()
                || p.len() > 5
                || !p.bytes().all(|b| b.is_ascii_digit())
                || (p.len() > 1 && p.starts_with('0'))
            {
                return Err(bad);
            }
            match p.parse::<u16>() {
                Ok(0) | Err(_) => return Err(bad),
                Ok(n) => n,
            }
        }
    };
    if host.is_empty() {
        return Err(bad);
    }
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inv_24_only_loopback_http_is_accepted() {
        for ok in [
            "http://127.0.0.1:8080/v1",
            "http://localhost:11434/v1/",
            "http://[::1]:8080/v1",
            "http://127.0.0.1/v1",
            "http://127.0.0.1:8080",
        ] {
            assert!(Endpoint::parse(ok).is_ok(), "{ok}");
        }
        let e = Endpoint::parse("http://localhost:11434/v1/").unwrap();
        assert_eq!(e.host, LoopbackHost::V4);
        assert_eq!(e.path("/chat/completions"), "/v1/chat/completions");
        for (bad, why) in [
            ("http://lan-host.example/v1", EndpointRefused::NotLoopback),
            ("http://127.0.0.2:8080/v1", EndpointRefused::NotLoopback),
            (
                "http://localhost.evil.example/v1",
                EndpointRefused::NotLoopback,
            ),
            ("http://0.0.0.0:8080/v1", EndpointRefused::NotLoopback),
            ("http://[::]:8080/v1", EndpointRefused::NotLoopback),
            ("http://LOCALHOST:8080/v1", EndpointRefused::NotLoopback),
            ("https://127.0.0.1:8443/v1", EndpointRefused::NeedsHosted),
            ("https://api.example/v1", EndpointRefused::NeedsHosted),
            ("ftp://127.0.0.1/v1", EndpointRefused::Scheme),
            ("HTTP://127.0.0.1/v1", EndpointRefused::Scheme),
            ("unix:/run/model.sock", EndpointRefused::Scheme),
        ] {
            assert_eq!(Endpoint::parse(bad), Err(why), "{bad}");
        }
        for bad in [
            "http://user@127.0.0.1/v1",
            "http://127.0.0.1@lan-host.example/v1",
            "http://127.0.0.1:0/v1",
            "http://127.0.0.1:99999/v1",
            "http://127.0.0.1:/v1",
            "http://127.0.0.1:80a/v1",
            "http://127.0.0.1/v1?x=1",
            "http://127.0.0.1/v1#f",
            "http://127.0.0.1/v1/../x",
            "http://127.0.0.1/v 1",
            "http://127.0.0.1/v1\r\nHost: x",
            "http://[::1/v1",
            "http://127.0.0.1:080/v1",
            "http://127.0.0.1:08080/v1",
            "http://127.0.0.1/v1/%2e%2e/x",
            "http://127.0.0.1/v1%0d%0aHost:x",
        ] {
            assert!(
                matches!(Endpoint::parse(bad), Err(EndpointRefused::Malformed(_))),
                "{bad}: {:?}",
                Endpoint::parse(bad)
            );
        }
    }
}
