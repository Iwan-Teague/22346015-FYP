//! The web egress rules (design `docs/slices/P-39-web-airlock.md` §4.1, §4.2):
//! URL parsing, the exact-tuple allowlist, IP address classification and
//! redirect-location resolution, all pure. No I/O, no clock, no global state
//! (§2.9): the §5 fetcher is a later slice and may call exactly these, so an
//! audit replay can recompute every refusal from its inputs alone.
//!
//! Fail-closed throughout (§4.1): a URL, allowlist entry, resolver answer or
//! redirect that does not survive every check is refused, never narrowed.

use std::collections::BTreeSet;

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ---------------------------------------------------------------------------
// Limits (§4.1).
// ---------------------------------------------------------------------------

/// The longest URL this crate accepts (§4.1): anything longer is refused
/// before it is parsed.
pub const MAX_URL_BYTES: usize = 4096;

/// The most entries an allowlist may hold (§4.1).
pub const MAX_ALLOWLIST_ENTRIES: usize = 64;

// ---------------------------------------------------------------------------
// URL parsing (§4.1).
// ---------------------------------------------------------------------------

/// Why a URL string was refused (§4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UrlRefused {
    /// Longer than [`MAX_URL_BYTES`] bytes.
    #[error("url is longer than {MAX_URL_BYTES} bytes")]
    TooLong,
    /// Not ASCII: an internationalized name must arrive punycode-encoded.
    #[error("url is not ascii")]
    NotAscii,
    /// A control character or a space anywhere in the URL.
    #[error("url holds a control character or a space")]
    Control,
    /// The scheme is not lowercase `http` or `https` exactly.
    #[error("scheme must be exactly http:// or https://")]
    Scheme,
    /// Userinfo (`user@host`) in the authority.
    #[error("userinfo in the authority is refused")]
    Userinfo,
    /// The host is empty, malformed, or a numeric shorthand a resolver might
    /// re-read as an address.
    #[error("host is malformed")]
    Host,
    /// The port is malformed, has a leading zero, or is zero.
    #[error("port is malformed")]
    Port,
    /// The request target is absent, does not start with `/`, or carries
    /// malformed percent-encoding.
    #[error("request target is malformed")]
    Target,
    /// A redirect location that carries no path to resolve.
    #[error("redirect location is empty")]
    EmptyLocation,
    /// A redirect that would downgrade `https` to `http`.
    #[error("redirect downgrades https to http")]
    Downgrade,
}

/// The only two schemes a web URL may carry (§4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scheme {
    /// Plain text; port 80 by default.
    Http,
    /// TLS; port 443 by default.
    Https,
}

impl Scheme {
    /// The scheme's default port.
    fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }

    /// The scheme as its lowercase spelling.
    fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

/// A parsed web URL (§4.1): everything the fetcher may need and nothing
/// else. The fragment is already gone; the request target keeps the exact
/// path and query bytes the origin will see. Constructed only by
/// [`parse_url`] (and [`resolve_location`], which re-parses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebUrl {
    scheme: Scheme,
    host: String,
    port: u16,
    target: String,
    ip: Option<IpAddr>,
}

impl WebUrl {
    /// The scheme.
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The host: a lowercased DNS name or IP literal, without brackets.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port: explicit, or the scheme's default.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The request target: the verbatim path and query, starting with `/`.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The parsed address, if the host was an IP literal.
    pub fn ip(&self) -> Option<IpAddr> {
        self.ip
    }

    /// The URL's absolute form up to the request target:
    /// `scheme://host:port`, with the host bracketed when it is an IPv6
    /// literal (so the result re-parses).
    fn authority_str(&self) -> String {
        let mut s = String::new();
        s.push_str(self.scheme.as_str());
        s.push_str("://");
        if matches!(self.ip, Some(IpAddr::V6(_))) {
            s.push('[');
            s.push_str(&self.host);
            s.push(']');
        } else {
            s.push_str(&self.host);
        }
        s.push(':');
        s.push_str(&self.port.to_string());
        s
    }
}

/// Parse an absolute `http`/`https` URL (§4.1). Everything that does not
/// survive the check is refused; what survives keeps its request-target
/// bytes verbatim.
pub fn parse_url(raw: &str) -> Result<WebUrl, UrlRefused> {
    if raw.len() > MAX_URL_BYTES {
        return Err(UrlRefused::TooLong);
    }
    if !raw.is_ascii() {
        return Err(UrlRefused::NotAscii);
    }
    if raw.chars().any(|c| c.is_control() || c == ' ') {
        return Err(UrlRefused::Control);
    }
    let (scheme, after_scheme) = match raw.strip_prefix("https://") {
        Some(rest) => (Scheme::Https, rest),
        None => match raw.strip_prefix("http://") {
            Some(rest) => (Scheme::Http, rest),
            None => return Err(UrlRefused::Scheme),
        },
    };
    // The fragment is dropped before anything else sees the URL (§4.1).
    let no_fragment = match after_scheme.split_once('#') {
        Some((before, _)) => before,
        None => after_scheme,
    };
    let (authority, target) = match no_fragment.split_once('/') {
        Some((a, tail)) => (a, Some(format!("/{tail}"))),
        None => (no_fragment, None),
    };
    let target = match target {
        Some(t) => t,
        None => {
            // No path: a pathless query ("host?q") is refused, a bare
            // authority targets "/".
            if authority.contains('?') {
                return Err(UrlRefused::Target);
            }
            "/".to_owned()
        }
    };
    if authority.contains('@') {
        return Err(UrlRefused::Userinfo);
    }
    let (parsed, port) = host_and_port(authority, scheme)?;
    // IP hosts are rebuilt in canonical form; names arrive lowercased.
    let (host, ip) = match parsed {
        ParsedHost::Ip(ip) => (ip.to_string(), Some(ip)),
        ParsedHost::Name(name) => (name, None),
    };
    if !percent_well_formed(&target) {
        return Err(UrlRefused::Target);
    }
    Ok(WebUrl {
        scheme,
        host,
        port,
        target,
        ip,
    })
}

/// Split an authority (no userinfo, already refused) into a parsed host
/// and port, applying the scheme default when the port is absent. The host
/// is checked first: a bad host outranks a bad port.
fn host_and_port(authority: &str, scheme: Scheme) -> Result<(ParsedHost, u16), UrlRefused> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (lit, after) = rest.split_once(']').ok_or(UrlRefused::Host)?;
        let port = match after.strip_prefix(':') {
            Some(p) => parse_port(p)?,
            None => {
                if !after.is_empty() {
                    return Err(UrlRefused::Port);
                }
                scheme.default_port()
            }
        };
        let v6 = lit.parse::<Ipv6Addr>().map_err(|_| UrlRefused::Host)?;
        Ok((ParsedHost::Ip(IpAddr::V6(v6)), port))
    } else {
        let (h, port_str) = match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        let parsed = match parse_host(h)? {
            // A URL host needs at least two labels: no "localhost", no
            // bare TLDs, no numeric shorthand (refused by the grammar).
            ParsedHost::Name(name) if !name.contains('.') => return Err(UrlRefused::Host),
            other => other,
        };
        let port = match port_str {
            Some(p) => parse_port(p)?,
            None => scheme.default_port(),
        };
        Ok((parsed, port))
    }
}

/// A host after syntax checks: an IP literal or a lowercased DNS name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedHost {
    /// A strict dotted-quad IPv4 literal.
    Ip(IpAddr),
    /// A lowercased DNS name (label count NOT checked here: the allowlist
    /// needs single labels visible to refuse them as [`AllowlistRefused::
    /// SingleLabel`]; [`parse_url`] enforces two or more itself).
    Name(String),
}

/// Parse a host string: a strict dotted-quad IPv4 literal, a bracketed
/// IPv6 literal is handled by the caller, otherwise a DNS name whose
/// labels are `1..=63` bytes of `[a-z0-9-]` after one lowercasing, with no
/// leading or trailing `-` per label. Numeric shorthand a resolver might
/// re-read as an address (`0x7f.1`, `2130706433`, `127.0.0.01`, `999.1.1.1`)
/// is refused outright (§4.1).
fn parse_host(raw: &str) -> Result<ParsedHost, UrlRefused> {
    if raw.is_empty() || raw.len() > 253 {
        return Err(UrlRefused::Host);
    }
    // Strict dotted-quad first: only the canonical spelling is an address.
    if let Ok(v4) = raw.parse::<Ipv4Addr>() {
        return Ok(ParsedHost::Ip(IpAddr::V4(v4)));
    }
    // Anything that only looks numeric is refused: a resolver would read it
    // as an address even though the strict parser did not.
    let hex_label = raw
        .split('.')
        .any(|label| label.starts_with("0x") || label.starts_with("0X"));
    let digits_and_dots = raw.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    if hex_label || digits_and_dots {
        return Err(UrlRefused::Host);
    }
    let lowered = raw.to_ascii_lowercase();
    for label in lowered.split('.') {
        if !valid_label(label) {
            return Err(UrlRefused::Host);
        }
    }
    Ok(ParsedHost::Name(lowered))
}

/// One DNS label after lowercasing: `1..=63` bytes of `[a-z0-9-]`, no
/// leading or trailing `-`.
fn valid_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// A port: digits only, at most 5, no leading zeros, not zero, in range.
fn parse_port(p: &str) -> Result<u16, UrlRefused> {
    if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
        return Err(UrlRefused::Port);
    }
    if p.starts_with('0') {
        return Err(UrlRefused::Port);
    }
    p.parse::<u16>().map_err(|_| UrlRefused::Port)
}

/// Whether every `%` in `s` introduces exactly two hex digits (§4.1: the
/// target's percent-encoding must be well-formed; it is never decoded).
fn percent_well_formed(s: &str) -> bool {
    let mut owed = 0usize;
    for b in s.bytes() {
        if owed == 0 {
            if b == b'%' {
                owed = 2;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        } else {
            owed -= 1;
        }
    }
    owed == 0
}

// ---------------------------------------------------------------------------
// Allowlist (§4.1).
// ---------------------------------------------------------------------------

/// Why an allowlist was refused at load (§4.1). Nothing is admitted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AllowlistRefused {
    /// More than [`MAX_ALLOWLIST_ENTRIES`] entries.
    #[error("allowlist holds more than {MAX_ALLOWLIST_ENTRIES} entries")]
    TooMany,
    /// A `*` anywhere in the entry: no wildcards.
    #[error("allowlist entry {0:?} holds a wildcard")]
    Wildcard(String),
    /// A leading or trailing `.` on the host.
    #[error("allowlist entry {0:?} has a leading or trailing dot")]
    Dot(String),
    /// A single-label name, including `localhost`.
    #[error("allowlist entry {0:?} is a single-label name")]
    SingleLabel(String),
    /// The last label is one a private network could answer.
    #[error("allowlist entry {0:?} ends in a forbidden label")]
    ForbiddenSuffix(String),
    /// A non-global IP literal.
    #[error("allowlist entry {0:?} is a non-global IP literal")]
    NonGlobalLiteral(String),
    /// The same (scheme, host, port) tuple twice.
    #[error("allowlist entry {0:?} appears twice")]
    Duplicate(String),
    /// Anything else malformed, including an `https://` prefix (the scheme
    /// is implicit or `http://`, never written `https://`).
    #[error("allowlist entry {0:?} is malformed")]
    BadEntry(String),
}

/// One exact allowlist entry: scheme, host and port, all three. `docs.rs`
/// is `https` on 443 and nothing else; `http://docs.rs` is `http` on 80 and
/// nothing else; `docs.rs:8443` is `https` on 8443.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Entry {
    scheme: Scheme,
    host: String,
    port: u16,
}

/// The egress allowlist (§4.1): a set of exact (scheme, host, port)
/// tuples. No wildcards, no subdomain matching: an entry matches exactly
/// one tuple and nothing else. Constructed only by [`Allowlist::load`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Allowlist {
    entries: BTreeSet<Entry>,
}

impl Allowlist {
    /// Load an allowlist from config strings, refusing anything ambiguous
    /// (§4.1). Entries are `host`, `host:port` (https assumed) or
    /// `http://host[:port]`.
    pub fn load(entries: &[String]) -> Result<Self, AllowlistRefused> {
        if entries.len() > MAX_ALLOWLIST_ENTRIES {
            return Err(AllowlistRefused::TooMany);
        }
        let mut set = BTreeSet::new();
        for raw in entries {
            let entry = parse_entry(raw)?;
            if !set.insert(entry) {
                return Err(AllowlistRefused::Duplicate(raw.clone()));
            }
        }
        Ok(Self { entries: set })
    }

    /// Whether this URL names exactly an allowlisted (scheme, host, port).
    pub fn allows(&self, url: &WebUrl) -> bool {
        self.entries.contains(&Entry {
            scheme: url.scheme,
            host: url.host.clone(),
            port: url.port,
        })
    }

    /// Which part of a refused URL failed the exact match (§2.3): the decide
    /// branch names one rule. Deterministic, and every answer still refuses:
    /// scheme when some entry names the same host and port under the other
    /// scheme, port when some entry names the host at the URL's scheme, and
    /// host when no entry names the host at all.
    pub(crate) fn mismatch(&self, url: &WebUrl) -> UrlMismatch {
        let same_host_port = self
            .entries
            .iter()
            .any(|e| e.host == url.host && e.port == url.port && e.scheme != url.scheme);
        if same_host_port {
            return UrlMismatch::Scheme;
        }
        let same_host_scheme = self
            .entries
            .iter()
            .any(|e| e.host == url.host && e.scheme == url.scheme);
        if same_host_scheme {
            UrlMismatch::Port
        } else {
            UrlMismatch::Host
        }
    }
}

/// Why a refused URL is not exactly on the allowlist (§2.3's three rule
/// names). The security outcome is the same for all three; the rule only
/// says which tuple member differed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UrlMismatch {
    /// The scheme differs from the entry naming the same host and port.
    Scheme,
    /// The port differs from the entry naming the same host and scheme.
    Port,
    /// No entry names the host at all.
    Host,
}

/// The widest a search query may be, in characters (§2.3).
pub(crate) const MAX_QUERY_CHARS: usize = 256;

/// Whether a search query passes §2.3's bounds: 1..=256 characters, and no
/// control, zero-width or bidi code point. The schema bounds `maxLength`
/// only; the lower bound and the invisibility rule are policy's (the same
/// code point set the manifest refuses in summaries).
///
/// Public since P-39h: the provider re-checks the query before egress
/// (defence in depth, the same way it re-checks the URL rule).
pub fn query_clean(q: &str) -> bool {
    q.chars().count() <= MAX_QUERY_CHARS
        && !q.is_empty()
        && !q.chars().any(|c| c.is_control() || is_invisible_or_bidi(c))
}

/// Zero-width and bidi-control code points (§2.3, §4.3): the manifest's
/// summary set.
fn is_invisible_or_bidi(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{17B4}'
            | '\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFFB}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// Parse one allowlist entry (§4.1). Refuses, in order: wildcards, an
/// `https://` prefix, malformed hosts and ports, leading/trailing dots,
/// single labels, forbidden last labels, non-global IP literals.
fn parse_entry(raw: &str) -> Result<Entry, AllowlistRefused> {
    if raw.contains('*') {
        return Err(AllowlistRefused::Wildcard(raw.to_owned()));
    }
    let (scheme, hostport) = if let Some(rest) = raw.strip_prefix("http://") {
        (Scheme::Http, rest)
    } else if raw.starts_with("https://") {
        return Err(AllowlistRefused::BadEntry(raw.to_owned()));
    } else {
        (Scheme::Https, raw)
    };
    let bad = || AllowlistRefused::BadEntry(raw.to_owned());
    if let Some(rest) = hostport.strip_prefix('[') {
        let (lit, after) = rest.split_once(']').ok_or_else(bad)?;
        let port = match after.strip_prefix(':') {
            Some(p) => parse_port(p).map_err(|_| bad())?,
            None => {
                if !after.is_empty() {
                    return Err(bad());
                }
                scheme.default_port()
            }
        };
        let v6 = lit.parse::<Ipv6Addr>().map_err(|_| bad())?;
        check_literal(IpAddr::V6(v6), raw)?;
        Ok(Entry {
            scheme,
            host: lit.to_ascii_lowercase(),
            port,
        })
    } else {
        let (h, port) = match hostport.split_once(':') {
            Some((h, p)) => (h, parse_port(p).map_err(|_| bad())?),
            None => (hostport, scheme.default_port()),
        };
        if h.starts_with('.') || h.ends_with('.') {
            return Err(AllowlistRefused::Dot(raw.to_owned()));
        }
        match parse_host(h).map_err(|_| bad())? {
            ParsedHost::Ip(ip) => {
                check_literal(ip, raw)?;
                Ok(Entry {
                    scheme,
                    host: h.to_ascii_lowercase(),
                    port,
                })
            }
            ParsedHost::Name(name) => {
                let labels: Vec<&str> = name.split('.').collect();
                if labels.len() < 2 {
                    return Err(AllowlistRefused::SingleLabel(raw.to_owned()));
                }
                if let Some(last) = labels.last() {
                    if matches!(*last, "localhost" | "local" | "internal" | "arpa") {
                        return Err(AllowlistRefused::ForbiddenSuffix(raw.to_owned()));
                    }
                }
                Ok(Entry {
                    scheme,
                    host: name,
                    port,
                })
            }
        }
    }
}

/// An IP-literal entry must name a globally routable address (§4.1: the
/// allowlist may never name this host, a link-local metadata service, or
/// anything else a private network could answer).
fn check_literal(ip: IpAddr, raw: &str) -> Result<(), AllowlistRefused> {
    if let AddrClass::NonGlobal(_) = classify(ip) {
        return Err(AllowlistRefused::NonGlobalLiteral(raw.to_owned()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Address classification (§4.2).
// ---------------------------------------------------------------------------

/// The §4.2 class of an IP address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrClass {
    /// Globally routable: the fetcher may connect.
    Global,
    /// Not globally routable, with the reason from the §4.2 table.
    NonGlobal(&'static str),
}

/// Classify an address against the §4.2 table: every special-use range is
/// refused, everything else is global.
pub fn classify(ip: IpAddr) -> AddrClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

/// The §4.2 table for IPv4.
fn classify_v4(ip: Ipv4Addr) -> AddrClass {
    let ng = |why: &'static str| AddrClass::NonGlobal(why);
    match ip.octets() {
        [0, _, _, _] => ng("this-network"),
        [10, _, _, _] => ng("private"),
        [100, 64..=127, _, _] => ng("shared-address-space"),
        [127, _, _, _] => ng("loopback"),
        [169, 254, _, _] => ng("link-local"),
        [172, 16..=31, _, _] => ng("private"),
        [192, 0, 0, _] => ng("ietf-protocol-assignments"),
        [192, 0, 2, _] => ng("documentation"),
        [192, 88, 99, _] => ng("6to4-relay-anycast"),
        [192, 168, _, _] => ng("private"),
        [198, 18..=19, _, _] => ng("benchmarking"),
        [198, 51, 100, _] => ng("documentation"),
        [203, 0, 113, _] => ng("documentation"),
        [224..=239, _, _, _] => ng("multicast"),
        [240..=255, _, _, _] => ng("reserved"),
        _ => AddrClass::Global,
    }
}

/// The two low u16s of an embedded IPv4 literal, as octets.
fn embedded_v4(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8)
}

/// The §4.2 table for IPv6. An IPv4-mapped or NAT64 address is classified
/// by its embedded IPv4; `2002::/16` (6to4) is refused outright, even with
/// a global embedded address, per the table.
fn classify_v6(ip: Ipv6Addr) -> AddrClass {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    let ng = |why: &'static str| AddrClass::NonGlobal(why);
    match ip.segments() {
        [0, 0, 0, 0, 0, 0, 0, 0] => ng("unspecified"),
        [0, 0, 0, 0, 0, 0, 0, 1] => ng("loopback"),
        [0x64, 0xff9b, 0, 0, 0, 0, hi, lo] => classify_v4(embedded_v4(hi, lo)),
        [0x64, 0xff9b, 1, ..] => ng("nat64-local"),
        [0x0100, 0, 0, 0, ..] => ng("discard-only"),
        [0x2001, 0x0000..=0x01ff, ..] => ng("ietf"),
        [0x2001, 0x0db8, ..] => ng("documentation"),
        [0x2002, ..] => ng("6to4"),
        [0xfc00..=0xfdff, ..] => ng("unique-local"),
        [0xfe80..=0xfebf, ..] => ng("link-local"),
        [0xfec0..=0xfeff, ..] => ng("site-local"),
        [0xff00..=0xffff, ..] => ng("multicast"),
        _ => AddrClass::Global,
    }
}

/// Why a resolver answer was refused (§4.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnswerRefused {
    /// The answer holds no address.
    #[error("resolver answer is empty")]
    Empty,
    /// At least one address is not globally routable.
    #[error("resolver answer holds {ip} which is {class}")]
    NonGlobal {
        /// The offending address (the first in resolver order).
        ip: IpAddr,
        /// Its class, from the §4.2 table.
        class: &'static str,
    },
}

/// Check a resolver answer (§4.2): it must be non-empty and every address
/// in it must be globally routable — a mixed answer is refused, never
/// filtered, so a hostile resolver cannot smuggle one private address past
/// a majority of good ones. When the answer survives, the FIRST address is
/// kept: resolver order.
pub fn classify_answer(ips: &[IpAddr]) -> Result<IpAddr, AnswerRefused> {
    let first = ips.first().copied().ok_or(AnswerRefused::Empty)?;
    for ip in ips {
        if let AddrClass::NonGlobal(class) = classify(*ip) {
            return Err(AnswerRefused::NonGlobal { ip: *ip, class });
        }
    }
    Ok(first)
}

// ---------------------------------------------------------------------------
// Redirect resolution (§4.1).
// ---------------------------------------------------------------------------

/// Resolve a redirect `Location` against the base URL (§4.1, RFC 3986 §5
/// subset). The result is parsed by [`parse_url`] all over again, so a
/// redirect can never relax a check the base already passed. An `https`
/// base may not be redirected to `http` ([`UrlRefused::Downgrade`]); an
/// `http` base may be upgraded. The base's query is never carried into a
/// relative resolution; the reference's query, if any, is.
pub fn resolve_location(base: &WebUrl, location: &str) -> Result<WebUrl, UrlRefused> {
    // The fragment splits off before the query: "#f?q" is a bare fragment,
    // which carries no path at all.
    let loc = match location.split_once('#') {
        Some((before, _)) => before,
        None => location,
    };
    if loc.is_empty() || loc.starts_with('?') {
        return Err(UrlRefused::EmptyLocation);
    }
    let url = if loc.starts_with("//") {
        // Scheme-relative: the base's scheme, nothing else carried over.
        // The reference already carries the "//" authority marker.
        parse_url(&format!("{}:{}", base.scheme.as_str(), loc))?
    } else {
        let colon = loc.find(':');
        let slash = loc.find('/');
        match colon {
            // A colon before any slash: an absolute URL, re-parsed whole.
            Some(c) if slash.is_none_or(|s| c < s) => parse_url(loc)?,
            _ => {
                // Absolute-path or relative-path: merge against the base.
                let (ref_path, query) = match loc.split_once('?') {
                    Some((p, q)) => (p, Some(q)),
                    None => (loc, None),
                };
                let base_path = base
                    .target
                    .split_once('?')
                    .map_or(base.target.as_str(), |(p, _)| p);
                let merged = if ref_path.starts_with('/') {
                    ref_path.to_owned()
                } else {
                    let dir = base_path.rsplit_once('/').map_or("", |(d, _)| d);
                    format!("{dir}/{ref_path}")
                };
                let target = remove_dot_segments(&merged);
                let target = match query {
                    Some(q) => format!("{target}?{q}"),
                    None => target,
                };
                parse_url(&format!("{}{}", base.authority_str(), target))?
            }
        }
    };
    if base.scheme == Scheme::Https && url.scheme == Scheme::Http {
        return Err(UrlRefused::Downgrade);
    }
    Ok(url)
}

/// RFC 3986 §5.2.4 over a path that starts with `/`. Excess `..` stops at
/// the root; a trailing `.` or `..` keeps a trailing slash; `%2E` is not a
/// dot (the path is never decoded).
fn remove_dot_segments(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut trailing = false;
    for seg in path.split('/').skip(1) {
        match seg {
            "." => trailing = true,
            ".." => {
                out.pop();
                trailing = true;
            }
            other => {
                out.push(other);
                trailing = false;
            }
        }
    }
    let mut s = String::new();
    for seg in &out {
        s.push('/');
        s.push_str(seg);
    }
    if trailing {
        s.push('/');
    }
    s
}

// ---------------------------------------------------------------------------
// Tests (§14 slice card P-39a).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> WebUrl {
        parse_url(s).expect("test url parses")
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test ip parses")
    }

    fn list(items: &[&str]) -> Allowlist {
        let owned: Vec<String> = items.iter().map(|s| (*s).to_owned()).collect();
        Allowlist::load(&owned).expect("test allowlist loads")
    }

    #[test]
    fn url_parser_refuses_userinfo_controls_and_shorthand_ipv4() {
        let refused: &[(&str, UrlRefused)] = &[
            // Userinfo.
            ("https://user:pass@docs.rs/", UrlRefused::Userinfo),
            ("https://docs.rs@evil.example/", UrlRefused::Userinfo),
            // Controls, spaces, non-ASCII hostilities.
            ("https://docs.rs/\x1b", UrlRefused::Control),
            ("https://do\x7fcs.rs/", UrlRefused::Control),
            ("https://docs.rs/a b", UrlRefused::Control),
            ("https://do\u{202E}cs.rs/", UrlRefused::NotAscii),
            ("https://docs.rs/\u{200B}", UrlRefused::NotAscii),
            ("https://d\u{F6}c.rs/", UrlRefused::NotAscii),
            // Too long.
            (
                &format!("https://docs.rs/{}", "a".repeat(MAX_URL_BYTES)),
                UrlRefused::TooLong,
            ),
            // Scheme: case, other schemes, missing scheme.
            ("HTTPS://docs.rs/", UrlRefused::Scheme),
            ("Http://docs.rs/", UrlRefused::Scheme),
            ("ftp://docs.rs/", UrlRefused::Scheme),
            ("https:/docs.rs/", UrlRefused::Scheme),
            ("docs.rs/index", UrlRefused::Scheme),
            // Ports: zero, leading zeros, overflow, junk, empty.
            ("https://docs.rs:0/", UrlRefused::Port),
            ("https://docs.rs:01/", UrlRefused::Port),
            ("https://docs.rs:00080/", UrlRefused::Port),
            ("https://docs.rs:65536/", UrlRefused::Port),
            ("https://docs.rs:655360/", UrlRefused::Port),
            ("https://docs.rs:8443x/", UrlRefused::Port),
            ("https://docs.rs:-1/", UrlRefused::Port),
            ("https://docs.rs:/", UrlRefused::Port),
            // Hosts: empty, single-label, bad labels, too long.
            ("https:///path", UrlRefused::Host),
            ("https://com/", UrlRefused::Host),
            ("https://localhost/", UrlRefused::Host),
            ("https://-docs.rs/", UrlRefused::Host),
            ("https://docs-.rs/", UrlRefused::Host),
            ("https://docs..rs/", UrlRefused::Host),
            ("https://docs.rs./", UrlRefused::Host),
            ("https://do_cs.rs/", UrlRefused::Host),
            (
                &format!("https://{}.example/", "a".repeat(64)),
                UrlRefused::Host,
            ),
            (
                &format!("https://{}.example/", "a".repeat(300)),
                UrlRefused::Host,
            ),
            // IPv4 shorthand a resolver would re-read as an address.
            ("https://127.0.0.01/", UrlRefused::Host),
            ("https://2130706433/", UrlRefused::Host),
            ("https://0x7f.1/", UrlRefused::Host),
            ("https://999.1.1.1/", UrlRefused::Host),
            ("https://1.2.3/", UrlRefused::Host),
            // Unbracketed or broken IPv6.
            ("https://::1/", UrlRefused::Host),
            ("https://[::1/", UrlRefused::Host),
            ("https://[bad]/", UrlRefused::Host),
            ("https://[1::2::3]/", UrlRefused::Host),
            // Pathless query and percent-encoding.
            ("https://docs.rs?q=1", UrlRefused::Target),
            ("https://docs.rs/%zz", UrlRefused::Target),
            ("https://docs.rs/%2", UrlRefused::Target),
            ("https://docs.rs/%", UrlRefused::Target),
        ];
        for (bad, want) in refused {
            assert_eq!(parse_url(bad), Err(*want), "{bad:?}");
        }
    }

    #[test]
    fn url_fragment_dropped_and_target_verbatim() {
        let u = url("https://docs.rs/a%2Fb/../c//d#frag");
        assert_eq!(u.host(), "docs.rs");
        assert_eq!(u.port(), 443);
        assert_eq!(u.target(), "/a%2Fb/../c//d");
        assert_eq!(u.ip(), None);
        // Defaults and explicit ports.
        assert_eq!(url("https://docs.rs").port(), 443);
        assert_eq!(url("https://docs.rs").target(), "/");
        assert_eq!(url("http://docs.rs").port(), 80);
        assert_eq!(url("https://docs.rs#f").target(), "/");
        let u = url("http://docs.rs:8080/x?q#f");
        assert_eq!(u.port(), 8080);
        assert_eq!(u.target(), "/x?q");
        // IP literals: v4 and v6, explicit port on v6.
        let u = url("https://8.8.8.8/x");
        assert_eq!(u.ip(), Some(ip("8.8.8.8")));
        assert_eq!(u.host(), "8.8.8.8");
        let u = url("https://[2606:4700::1111]:8443/x");
        assert_eq!(u.ip(), Some(ip("2606:4700::1111")));
        assert_eq!(u.host(), "2606:4700::1111");
        assert_eq!(u.port(), 8443);
        // One lowercasing: an uppercase host matches its lowercase form.
        assert_eq!(url("https://DOCS.RS/x").host(), "docs.rs");
    }

    #[test]
    fn allowlist_refuses_star_and_wildcards() {
        let refused: &[(&str, AllowlistRefused)] = &[
            ("*", AllowlistRefused::Wildcard("*".to_owned())),
            (
                "*.docs.rs",
                AllowlistRefused::Wildcard("*.docs.rs".to_owned()),
            ),
            (
                "docs.rs*",
                AllowlistRefused::Wildcard("docs.rs*".to_owned()),
            ),
            (
                "do*rs.example",
                AllowlistRefused::Wildcard("do*rs.example".to_owned()),
            ),
            (
                "http://*.docs.rs",
                AllowlistRefused::Wildcard("http://*.docs.rs".to_owned()),
            ),
            (".docs.rs", AllowlistRefused::Dot(".docs.rs".to_owned())),
            ("docs.rs.", AllowlistRefused::Dot("docs.rs.".to_owned())),
        ];
        for (bad, want) in refused {
            let owned: Vec<String> = vec![(*bad).to_owned()];
            assert_eq!(Allowlist::load(&owned), Err(want.clone()), "{bad:?}");
        }
        // More than the maximum: refused before any entry is parsed.
        let too_many: Vec<String> = (0..=MAX_ALLOWLIST_ENTRIES)
            .map(|i| format!("host{i}.example"))
            .collect();
        assert_eq!(
            Allowlist::load(&too_many),
            Err(AllowlistRefused::TooMany),
            "{} entries",
            too_many.len()
        );
    }

    #[test]
    fn allowlist_refuses_localhost_single_label_and_private_literals() {
        let refused: &[&str] = &[
            // Single labels.
            "localhost",
            "com",
            // Forbidden last labels (incl. .home.arpa).
            "docs.localhost",
            "docs.local",
            "docs.internal",
            "home.arpa",
            "docs.arpa",
            // Non-global literals.
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "[::1]",
            "[fe80::1]",
            "[fc00::1]",
            // Malformed.
            "https://docs.rs",
            "docs.rs:",
            "https://",
        ];
        for bad in refused {
            let owned: Vec<String> = vec![(*bad).to_owned()];
            assert!(Allowlist::load(&owned).is_err(), "{bad:?}");
        }
        // Duplicates: same tuple twice, in either spelling.
        let owned: Vec<String> = vec!["docs.rs".into(), "docs.rs".into()];
        assert_eq!(
            Allowlist::load(&owned),
            Err(AllowlistRefused::Duplicate("docs.rs".to_owned()))
        );
        let owned: Vec<String> = vec!["docs.rs".into(), "docs.rs:443".into()];
        assert!(
            Allowlist::load(&owned).is_err(),
            "same tuple, two spellings"
        );
        // Different tuples are NOT duplicates.
        let owned: Vec<String> = vec!["http://docs.rs".into(), "docs.rs".into()];
        assert!(Allowlist::load(&owned).is_ok(), "http:80 vs https:443");
    }

    #[test]
    fn allowlist_matches_exact_scheme_host_port() {
        let al = list(&[
            "docs.rs",
            "example.com:8443",
            "http://plain.example",
            "http://plain.example:8080",
            "8.8.8.8",
            "[2606:4700::1111]",
        ]);
        let allows = |s: &str| al.allows(&url(s));
        // Exact tuples.
        assert!(allows("https://docs.rs/"));
        assert!(allows("https://DOCS.RS/x?q=1"));
        assert!(allows("https://example.com:8443/"));
        assert!(allows("http://plain.example/"));
        assert!(allows("http://plain.example:8080/"));
        assert!(allows("https://8.8.8.8/"));
        assert!(allows("https://[2606:4700::1111]/"));
        // Subdomains are not covered.
        assert!(!allows("https://www.docs.rs/"));
        assert!(!allows("https://evil.docs.rs:8443/"));
        // Scheme is exact: an https-only entry never allows http.
        assert!(!allows("http://docs.rs/"));
        assert!(!allows("http://example.com:8443/"));
        assert!(!allows("https://plain.example/"));
        assert!(!allows("https://plain.example:8080/"));
        // Port is exact.
        assert!(!allows("https://docs.rs:8443/"));
        assert!(!allows("https://example.com/"));
        assert!(!allows("http://plain.example:8081/"));
        assert!(!allows("http://8.8.8.8/"));
        assert!(!allows("http://[2606:4700::1111]/"));
        assert!(!allows("https://[2606:4700::1111]:4433/"));
        // Nothing else.
        assert!(!allows("https://other.example/"));
    }

    #[test]
    fn classify_refuses_every_private_range() {
        let non_global: &[&str] = &[
            // IPv4 table rows.
            "0.0.0.0",
            "0.255.255.255",
            "10.1.2.3",
            "100.64.0.0",
            "100.100.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
        ];
        for s in non_global {
            assert!(
                matches!(classify(ip(s)), AddrClass::NonGlobal(_)),
                "{s} should be non-global"
            );
        }
        // The exact boundaries of 100.64/10.
        assert!(matches!(classify(ip("100.63.255.255")), AddrClass::Global));
        assert!(matches!(classify(ip("100.128.0.0")), AddrClass::Global));
        // The exact boundaries of 2001::/23.
        assert!(matches!(
            classify(ip("2001:1ff::")),
            AddrClass::NonGlobal(_)
        ));
        assert!(matches!(classify(ip("2001:200::")), AddrClass::Global));
        // More IPv6 rows.
        let v6_non_global: &[&str] = &[
            "::",
            "::1",
            "64:ff9b:1::",
            "100::",
            "2001::",
            "2001:0:1:2:3:4:5:6",
            "2001:db8::1",
            "2002::",
            "2002:808:808::",
            "fc00::",
            "fd00::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
        ];
        for s in v6_non_global {
            assert!(
                matches!(classify(ip(s)), AddrClass::NonGlobal(_)),
                "{s} should be non-global"
            );
        }
        // Globals.
        let global: &[&str] = &[
            "8.8.8.8",
            "93.184.216.34",
            "100.63.255.255",
            "100.128.0.0",
            "172.32.0.1",
            "192.0.1.1",
            "198.20.0.1",
            "203.0.114.1",
            "2606:4700::1111",
            "2001:4860::1",
            "2001:200::",
            "2620:0:ccc::2",
        ];
        for s in global {
            assert_eq!(classify(ip(s)), AddrClass::Global, "{s} should be global");
        }
    }

    #[test]
    fn ipv4_mapped_and_nat64_classified_by_embedded_v4() {
        assert_eq!(
            classify(ip("::ffff:10.0.0.1")),
            classify(ip("10.0.0.1")),
            "mapped private"
        );
        assert_eq!(
            classify(ip("::ffff:8.8.8.8")),
            classify(ip("8.8.8.8")),
            "mapped global"
        );
        assert_eq!(
            classify(ip("::ffff:10.0.0.1")),
            AddrClass::NonGlobal("private")
        );
        assert_eq!(classify(ip("::ffff:8.8.8.8")), AddrClass::Global);
        // NAT64: same rule over the embedded address.
        assert_eq!(
            classify(ip("64:ff9b::10.0.0.1")),
            AddrClass::NonGlobal("private")
        );
        assert_eq!(classify(ip("64:ff9b::8.8.8.8")), AddrClass::Global);
        assert_eq!(
            classify(ip("64:ff9b::127.0.0.1")),
            AddrClass::NonGlobal("loopback")
        );
    }

    #[test]
    fn mixed_answer_refused_and_empty_answer_refused() {
        let mixed: &[&[&str]] = &[
            &["8.8.8.8", "10.0.0.1"],
            &["10.0.0.1", "8.8.8.8"],
            &["8.8.8.8", "::1"],
            &["2606:4700::1111", "8.8.8.8", "192.168.0.1"],
        ];
        for answer in mixed {
            let ips: Vec<IpAddr> = answer.iter().map(|s| ip(s)).collect();
            assert!(
                matches!(classify_answer(&ips), Err(AnswerRefused::NonGlobal { .. })),
                "{answer:?} should be refused"
            );
        }
        // The first offending address is named, in resolver order.
        assert_eq!(
            classify_answer(&[ip("8.8.8.8"), ip("10.0.0.1")]),
            Err(AnswerRefused::NonGlobal {
                ip: ip("10.0.0.1"),
                class: "private"
            })
        );
        assert_eq!(classify_answer(&[]), Err(AnswerRefused::Empty));
        assert_eq!(classify_answer(&[ip("8.8.8.8")]), Ok(ip("8.8.8.8")));
        assert_eq!(
            classify_answer(&[ip("1.1.1.1"), ip("9.9.9.9")]),
            Ok(ip("1.1.1.1")),
            "resolver order: first kept"
        );
    }

    #[test]
    fn redirect_location_resolved_and_rechecked() {
        let base = url("https://docs.rs/a/b?q=1");
        // Absolute path: base query dropped.
        let u = resolve_location(&base, "/c").expect("resolves");
        assert_eq!(u.host(), "docs.rs");
        assert_eq!(u.target(), "/c");
        // Relative path: merged into the base directory.
        assert_eq!(resolve_location(&base, "d/e").unwrap().target(), "/a/d/e");
        // Dot segments, with a query from the reference only.
        let u = resolve_location(&base, "../up?x=2").expect("resolves");
        assert_eq!(u.target(), "/up?x=2");
        // Scheme-relative: base scheme, new host.
        let u = resolve_location(&base, "//other.example/path").expect("resolves");
        assert_eq!(u.scheme(), Scheme::Https);
        assert_eq!(u.host(), "other.example");
        assert_eq!(u.port(), 443);
        assert_eq!(u.target(), "/path");
        // Absolute: re-parsed whole, fragment dropped again.
        let u = resolve_location(&base, "https://abs.example/z?y=1#f").expect("resolves");
        assert_eq!(u.host(), "abs.example");
        assert_eq!(u.target(), "/z?y=1");
        // Percent-encoded dots are NOT dot segments: kept verbatim.
        assert_eq!(
            resolve_location(&base, "/%2e%2e/x").unwrap().target(),
            "/%2e%2e/x"
        );
        // Trailing dot segment keeps the trailing slash.
        assert_eq!(resolve_location(&base, "up/.").unwrap().target(), "/a/up/");
        // Excess ".." stops at the root.
        assert_eq!(
            resolve_location(&base, "../../../../x").unwrap().target(),
            "/x"
        );
        // Refusals: no path to resolve.
        assert_eq!(resolve_location(&base, ""), Err(UrlRefused::EmptyLocation));
        assert_eq!(
            resolve_location(&base, "?q=1"),
            Err(UrlRefused::EmptyLocation)
        );
        assert_eq!(
            resolve_location(&base, "#f"),
            Err(UrlRefused::EmptyLocation)
        );
        assert_eq!(
            resolve_location(&base, "#f?q=1"),
            Err(UrlRefused::EmptyLocation)
        );
        // Re-checks apply: a bad host in a scheme-relative location.
        assert_eq!(
            resolve_location(&base, "//bad_host/x"),
            Err(UrlRefused::Host)
        );
        assert_eq!(
            resolve_location(&base, "//docs.rs?q=1"),
            Err(UrlRefused::Target)
        );
        assert_eq!(
            resolve_location(&base, "http://x.example:0/"),
            Err(UrlRefused::Port)
        );
    }

    #[test]
    fn https_to_http_downgrade_refused() {
        let https = url("https://docs.rs/a");
        // Downgrade refused even though the host is unlisted: the scheme
        // check happens before any allowlist is consulted.
        assert_eq!(
            resolve_location(&https, "http://other.example/x"),
            Err(UrlRefused::Downgrade)
        );
        assert_eq!(
            resolve_location(&https, "//other.example/x"),
            Ok(url("https://other.example/x")),
            "scheme-relative keeps https"
        );
        // An http base may be upgraded.
        let http = url("http://docs.rs/a");
        assert_eq!(
            resolve_location(&http, "https://other.example/x"),
            Ok(url("https://other.example/x"))
        );
        // An http base stays http scheme-relative.
        assert_eq!(
            resolve_location(&http, "//x.example/y"),
            Ok(url("http://x.example/y"))
        );
    }

    #[test]
    fn port_outside_allowlist_refused() {
        let bare = list(&["docs.rs"]);
        assert!(bare.allows(&url("https://docs.rs/")));
        assert!(
            !bare.allows(&url("https://docs.rs:8443/")),
            "explicit other port is a different tuple"
        );
        let pinned = list(&["docs.rs:8443"]);
        assert!(pinned.allows(&url("https://docs.rs:8443/x")));
        assert!(
            !pinned.allows(&url("https://docs.rs/")),
            "bare 443 is a different tuple"
        );
    }
}
