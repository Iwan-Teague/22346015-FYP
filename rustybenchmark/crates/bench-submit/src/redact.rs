//! Redaction: what must never leave the machine (docs/11 "Never uploaded").
//!
//! Two layers, deliberately:
//!
//! 1. **Allow-list structure** (in `bundle.rs`): only named fields are ever copied out of a
//!    journal; every identifier-shaped field must match a strict token grammar or the export is
//!    refused. This is the control that matters — REVIEW-5 `redaction-is-a-denylist` is the
//!    reason redaction is *not* the primary defence.
//! 2. **This module**: the few fields that legitimately carry free text (constraint violation
//!    strings, flags, error-code strings, the user-typed model name) are scrubbed token by token,
//!    and the finished bundle is scanned again ([`Redactor::find_leaks`]) so a bug in layer 1 or in
//!    the scrubber fails the export closed rather than shipping a path.
//!
//! The scrubber over-redacts on purpose: a false positive costs a readable word in a diagnostic
//! string, a false negative costs a username on a public leaderboard.

use std::collections::BTreeMap;

/// What kind of sensitive thing a token looked like. Only the kind is ever reported — never the
/// matched text, which is exactly what must not be logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Path,
    Url,
    Email,
    Ip,
    Mac,
    Host,
    User,
    Env,
    Serial,
    Id,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Path => "path",
            Kind::Url => "url",
            Kind::Email => "email",
            Kind::Ip => "ip",
            Kind::Mac => "mac",
            Kind::Host => "host",
            Kind::User => "user",
            Kind::Env => "env",
            Kind::Serial => "serial",
            Kind::Id => "id",
        }
    }

    fn placeholder(self) -> &'static str {
        match self {
            Kind::Path => "<path>",
            Kind::Url => "<url>",
            Kind::Email => "<email>",
            Kind::Ip => "<ip>",
            Kind::Mac => "<mac>",
            Kind::Host => "<host>",
            Kind::User => "<user>",
            Kind::Env => "<env>",
            Kind::Serial | Kind::Id => "<id>",
        }
    }
}

const PLACEHOLDERS: &[&str] = &[
    "<path>", "<url>", "<email>", "<ip>", "<mac>", "<host>", "<user>", "<env>", "<id>",
];

/// Identity facts about *this* machine, so the scrubber can remove the literal username /
/// hostname even when it appears in a shape no pattern recognises (`jdoe42-finetune.gguf`).
#[derive(Clone, Debug, Default)]
pub struct LocalFacts {
    pub usernames: Vec<String>,
    pub homes: Vec<String>,
    pub hostnames: Vec<String>,
}

impl LocalFacts {
    /// Best-effort discovery from the environment and two tiny OS tools. Never fails; a fact that
    /// cannot be found is simply absent (the pattern layer still applies).
    pub fn detect() -> LocalFacts {
        let mut f = LocalFacts::default();
        for var in ["USER", "LOGNAME", "USERNAME"] {
            if let Ok(v) = std::env::var(var) {
                f.usernames.push(v);
            }
        }
        for var in ["HOME", "USERPROFILE"] {
            if let Ok(v) = std::env::var(var) {
                if let Some(last) = v.rsplit(['/', '\\']).find(|s| !s.is_empty()) {
                    f.usernames.push(last.to_string());
                }
                f.homes.push(v);
            }
        }
        for var in ["HOSTNAME", "COMPUTERNAME"] {
            if let Ok(v) = std::env::var(var) {
                f.hostnames.push(v);
            }
        }
        if let Ok(s) = std::fs::read_to_string("/etc/hostname") {
            f.hostnames.push(s);
        }
        for (cmd, args) in [
            ("hostname", &[][..]),
            ("scutil", &["--get", "ComputerName"][..]),
            ("scutil", &["--get", "LocalHostName"][..]),
        ] {
            if let Ok(out) = std::process::Command::new(cmd).args(args).output() {
                if out.status.success() {
                    f.hostnames
                        .push(String::from_utf8_lossy(&out.stdout).into_owned());
                }
            }
        }
        f.normalise();
        f
    }

    /// Trim, drop empties and 1-character facts (which would shred every string), dedupe.
    pub fn normalise(&mut self) {
        for v in [&mut self.usernames, &mut self.homes, &mut self.hostnames] {
            for s in v.iter_mut() {
                *s = s.trim().to_string();
            }
            v.retain(|s| s.chars().count() >= 2);
            v.sort();
            v.dedup();
        }
        // A home like `/` or `/root` carries no secret worth the collateral damage.
        self.homes.retain(|h| h.len() > 6);
    }
}

/// Result of scrubbing one string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scrubbed {
    pub text: String,
    pub hits: Vec<Kind>,
}

/// Counts of redactions by kind, accumulated across a whole export (for the human report).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RedactionStats(pub BTreeMap<&'static str, usize>);

impl RedactionStats {
    pub fn add(&mut self, hits: &[Kind]) {
        for h in hits {
            *self.0.entry(h.name()).or_insert(0) += 1;
        }
    }
    pub fn total(&self) -> usize {
        self.0.values().sum()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Redactor {
    usernames: Vec<String>,
    homes: Vec<String>,
    hostnames: Vec<String>,
}

impl Redactor {
    pub fn new(facts: &LocalFacts) -> Redactor {
        let mut f = facts.clone();
        f.normalise();
        Redactor {
            usernames: f.usernames,
            homes: f.homes,
            hostnames: f.hostnames,
        }
    }

    /// Scrub free text: remove invisible characters, literal local facts, then every token that
    /// looks like a path, URL, address, host, serial, environment reference or similar.
    pub fn scrub(&self, input: &str) -> Scrubbed {
        let mut hits = Vec::new();
        let cleaned = strip_invisible(input);
        let lit = self.scrub_literals(&cleaned, &mut hits);

        let mut out = String::with_capacity(lit.len());
        let mut redact_next = false;
        for run in split_runs(&lit) {
            match run {
                Run::Space(s) => out.push_str(s),
                Run::Token(t) => {
                    if redact_next {
                        redact_next = false;
                        let (pre, core, suf) = peel(t);
                        if core.is_empty() || PLACEHOLDERS.contains(&core) {
                            out.push_str(t);
                        } else {
                            hits.push(Kind::Id);
                            out.push_str(pre);
                            out.push_str(Kind::Id.placeholder());
                            out.push_str(suf);
                        }
                        continue;
                    }
                    out.push_str(&scrub_token(t, &mut redact_next, &mut hits));
                }
            }
        }
        Scrubbed { text: out, hits }
    }

    /// Detector only: which kinds of sensitive content does `s` still contain? Used on the
    /// finished bundle. Local facts count as a leak of kind `User` / `Host` / `Path`.
    pub fn find_leaks(&self, s: &str) -> Vec<Kind> {
        let cleaned = strip_invisible(s);
        let mut leaks = Vec::new();
        let lower = cleaned.to_ascii_lowercase();
        for h in &self.homes {
            if lower.contains(&h.to_ascii_lowercase()) {
                leaks.push(Kind::Path);
            }
        }
        for u in &self.usernames {
            if u.chars().count() >= 4 {
                if lower.contains(&u.to_ascii_lowercase()) {
                    leaks.push(Kind::User);
                }
            } else if has_word_ci(&cleaned, u) {
                leaks.push(Kind::User);
            }
        }
        for h in &self.hostnames {
            if lower.contains(&h.to_ascii_lowercase()) {
                leaks.push(Kind::Host);
            }
        }
        let mut redact_next = false;
        for run in split_runs(&cleaned) {
            if let Run::Token(t) = run {
                let mut hits = Vec::new();
                let was = redact_next;
                let s = scrub_token(t, &mut redact_next, &mut hits);
                if was {
                    // The previous token was a `serial`/`uuid` keyword: this one is the value.
                    let (_, core, _) = peel(t);
                    if !core.is_empty() && !PLACEHOLDERS.contains(&core) {
                        leaks.push(Kind::Id);
                    }
                    redact_next = false;
                } else if s != t {
                    leaks.extend(hits);
                }
            }
        }
        leaks.sort();
        leaks.dedup();
        leaks
    }

    /// Make a user-typed model name publishable. A name like `/Users/me/models/qwen.gguf` is a
    /// path: keep only the final component, then scrub, then restrict to a safe character set.
    pub fn sanitize_model_name(&self, name: &str, hits_out: &mut Vec<Kind>) -> String {
        let cleaned = strip_invisible(name);
        let t = cleaned.trim();
        let pathy = t.starts_with('/')
            || t.starts_with('~')
            || t.starts_with("./")
            || t.starts_with("../")
            || t.contains('\\')
            || t.matches('/').count() >= 2
            || is_drive(t);
        let base = if pathy {
            hits_out.push(Kind::Path);
            t.rsplit(['/', '\\']).find(|s| !s.is_empty()).unwrap_or("")
        } else {
            t
        };
        // `org/name` (a registry id) has exactly one slash: scrub each half on its own so the
        // slash itself is not mistaken for a path.
        let mut text = String::new();
        for (i, part) in base.split('/').enumerate() {
            let s = self.scrub(part);
            hits_out.extend(s.hits.iter().copied());
            if i > 0 {
                text.push('/');
            }
            text.push_str(&s.text);
        }
        for p in PLACEHOLDERS {
            text = text.replace(p, "redacted");
        }
        let mut out: String = text
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '+' | '-' | '/') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        out.truncate(128);
        let out = out.trim_matches(['/', '.', '_']).to_string();
        if out.is_empty() {
            "unnamed".to_string()
        } else {
            out
        }
    }

    fn scrub_literals(&self, s: &str, hits: &mut Vec<Kind>) -> String {
        let mut text = s.to_string();
        for h in &self.homes {
            text = replace_ci(&text, h, "<path>", Kind::Path, hits);
        }
        for h in &self.hostnames {
            text = replace_ci(&text, h, "<host>", Kind::Host, hits);
        }
        for u in &self.usernames {
            if u.chars().count() >= 4 {
                text = replace_ci(&text, u, "<user>", Kind::User, hits);
            } else {
                text = replace_word_ci(&text, u, "<user>", Kind::User, hits);
            }
        }
        text
    }
}

fn is_drive(t: &str) -> bool {
    let b = t.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'/' || b[2] == b'\\')
}

/// Remove zero-width / bidi / soft-hyphen characters and C0 controls (except `\n`, `\t`) so a
/// literal cannot be split to dodge a match.
fn strip_invisible(s: &str) -> String {
    s.chars()
        .filter(|c| {
            !matches!(*c,
                '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}'
                | '\u{FEFF}' | '\u{00AD}')
                && (!c.is_control() || *c == '\n' || *c == '\t')
        })
        .collect()
}

/// Replace every ASCII-case-insensitive occurrence of `needle`. (ASCII lowering keeps byte
/// offsets valid; non-ASCII case variants of a username are not matched, a documented limit.)
fn replace_ci(hay: &str, needle: &str, repl: &str, kind: Kind, hits: &mut Vec<Kind>) -> String {
    if needle.is_empty() {
        return hay.to_string();
    }
    let lh = hay.to_ascii_lowercase();
    let ln = needle.to_ascii_lowercase();
    let mut out = String::with_capacity(hay.len());
    let mut i = 0;
    while let Some(pos) = lh[i..].find(&ln) {
        out.push_str(&hay[i..i + pos]);
        out.push_str(repl);
        hits.push(kind);
        i += pos + ln.len();
    }
    out.push_str(&hay[i..]);
    out
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

/// Whole-word (alphanumeric-boundary) replace, ASCII-case-insensitive. For short usernames where
/// substring matching would shred ordinary words.
fn replace_word_ci(hay: &str, word: &str, repl: &str, kind: Kind, hits: &mut Vec<Kind>) -> String {
    let lh = hay.to_ascii_lowercase();
    let lw = word.to_ascii_lowercase();
    let mut out = String::with_capacity(hay.len());
    let mut i = 0;
    while let Some(pos) = lh[i..].find(&lw) {
        let start = i + pos;
        let end = start + lw.len();
        let before_ok = hay[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !is_word_char(c));
        let after_ok = hay[end..].chars().next().is_none_or(|c| !is_word_char(c));
        out.push_str(&hay[i..start]);
        if before_ok && after_ok {
            out.push_str(repl);
            hits.push(kind);
        } else {
            out.push_str(&hay[start..end]);
        }
        i = end;
    }
    out.push_str(&hay[i..]);
    out
}

fn has_word_ci(hay: &str, word: &str) -> bool {
    let mut hits = Vec::new();
    replace_word_ci(hay, word, "", Kind::User, &mut hits);
    !hits.is_empty()
}

enum Run<'a> {
    Space(&'a str),
    Token(&'a str),
}

fn split_runs(s: &str) -> Vec<Run<'_>> {
    let mut runs = Vec::new();
    let mut start = 0;
    let mut in_space: Option<bool> = None;
    for (i, c) in s.char_indices() {
        let sp = c.is_whitespace();
        match in_space {
            None => in_space = Some(sp),
            Some(prev) if prev != sp => {
                runs.push(if prev {
                    Run::Space(&s[start..i])
                } else {
                    Run::Token(&s[start..i])
                });
                start = i;
                in_space = Some(sp);
            }
            _ => {}
        }
    }
    if let Some(prev) = in_space {
        runs.push(if prev {
            Run::Space(&s[start..])
        } else {
            Run::Token(&s[start..])
        });
    }
    runs
}

const LEAD: &[char] = &['"', '\'', '(', '[', '{', '<', '`', '*'];
const TRAIL: &[char] = &[
    '"', '\'', ')', ']', '}', '>', ',', ';', '.', '!', '?', '`', '*',
];

/// Split a token into (leading punctuation, core, trailing punctuation).
fn peel(t: &str) -> (&str, &str, &str) {
    if PLACEHOLDERS.contains(&t) {
        return ("", t, "");
    }
    // A token that begins with a placeholder (`<path>/x/lib.rs`, left by the literal pass) keeps its
    // `<`: stripping it would re-wrap the placeholder as `<<path>`.
    let after_lead = if PLACEHOLDERS.iter().any(|p| t.starts_with(p)) {
        t
    } else {
        t.trim_start_matches(LEAD)
    };
    let pre_len = t.len() - after_lead.len();
    let core_end = after_lead.trim_end_matches(TRAIL);
    let suf_start = pre_len + core_end.len();
    (&t[..pre_len], core_end, &t[suf_start..])
}

/// Keys whose *value* is sensitive in `key=value` / `key: value` form.
const SENSITIVE_KEYS: &[&str] = &[
    "user",
    "username",
    "host",
    "hostname",
    "home",
    "cwd",
    "pwd",
    "path",
    "serial",
    "serialnumber",
    "sn",
    "uuid",
    "udid",
    "mac",
    "hwaddr",
    "ether",
    "token",
    "password",
    "passwd",
    "secret",
    "apikey",
    "api_key",
    "key",
    "address",
    "addr",
    "ip",
];
/// Keywords that mark the *next* token as sensitive even without a colon.
const BARE_KEYWORDS: &[&str] = &["serial", "serialnumber", "uuid", "udid", "hwaddr"];

fn scrub_token(t: &str, redact_next: &mut bool, hits: &mut Vec<Kind>) -> String {
    if PLACEHOLDERS.contains(&t) {
        return t.to_string();
    }
    let (pre, core, suf) = peel(t);
    if core.is_empty() {
        return t.to_string();
    }

    // Keyword handling first: `serial:` / `user=` etc.
    let key = core.trim_end_matches([':', '=']);
    let had_sep = key.len() != core.len();
    let lower_key = key.to_ascii_lowercase();
    if had_sep && SENSITIVE_KEYS.contains(&lower_key.as_str()) {
        *redact_next = true;
        return t.to_string();
    }
    if BARE_KEYWORDS.contains(&lower_key.as_str()) {
        *redact_next = true;
        return t.to_string();
    }

    if let Some(k) = classify(core) {
        hits.push(k);
        return format!("{pre}{}{suf}", k.placeholder());
    }

    // `lhs=rhs`: an uppercase env-style key is an environment variable; a sensitive key hides its
    // value; anything else scrubs the value on its own (`--manifest-path=/x`).
    if let Some((lhs, rhs)) = core.split_once('=') {
        if !lhs.is_empty()
            && (is_env_name(lhs)
                || (lhs.len() >= 3
                    && lhs.bytes().any(|c| c.is_ascii_uppercase())
                    && !lhs.contains('-')))
        {
            hits.push(Kind::Env);
            return format!("{pre}<env>{suf}");
        }
        let l = lhs.to_ascii_lowercase();
        if SENSITIVE_KEYS.contains(&l.as_str()) && !rhs.is_empty() {
            if PLACEHOLDERS
                .iter()
                .any(|p| t.ends_with(p) && rhs.len() <= p.len())
            {
                return t.to_string();
            }
            hits.push(Kind::Id);
            return format!("{pre}{lhs}=<id>{suf}");
        }
        let (rp, rc, rs) = peel(rhs);
        if let Some(k) = classify(rc) {
            hits.push(k);
            return format!("{pre}{lhs}={rp}{}{rs}{suf}", k.placeholder());
        }
    }
    embedded(t, hits)
}

/// Sensitive patterns that need no separator to be recognised and so can hide inside a glued
/// token (`a10.0.0.5z`, `ip10.0.0.5:80:12:5`): IPv4, MAC, UUID and long hex runs.
fn embedded(t: &str, hits: &mut Vec<Kind>) -> String {
    let b = t.as_bytes();
    let mut ranges: Vec<(usize, usize, Kind)> = Vec::new();
    // IPv4: maximal [0-9.] runs that are exactly four numeric octets.
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let mut j = i;
            while j < b.len() && (b[j].is_ascii_digit() || b[j] == b'.') {
                j += 1;
            }
            let run = &t[i..j];
            let trimmed = run.trim_end_matches('.');
            if is_ipv4(trimmed) {
                ranges.push((i, i + trimmed.len(), Kind::Ip));
            }
            i = j;
        } else {
            i += 1;
        }
    }
    // IPv6: maximal runs of hex digits, colons and dots.
    let mut i = 0;
    while i < b.len() {
        if hexd_or_colon(b[i]) {
            let mut j = i;
            while j < b.len() && hexd_or_colon(b[j]) {
                j += 1;
            }
            if is_ipv6(&t[i..j]) {
                ranges.push((i, j, Kind::Ip));
            }
            i = j;
        } else {
            i += 1;
        }
    }
    // MAC (17 chars, same separator) and UUID (36 chars) windows; hex runs of 20 or more.
    let hexd = |c: u8| c.is_ascii_hexdigit();
    for i in 0..b.len() {
        if i + 17 <= b.len() {
            let w = &b[i..i + 17];
            for sep in *b":-" {
                if (0..6).all(|g| hexd(w[g * 3]) && hexd(w[g * 3 + 1]))
                    && (0..5).all(|g| w[g * 3 + 2] == sep)
                {
                    ranges.push((i, i + 17, Kind::Mac));
                }
            }
        }
        if i + 36 <= b.len() && t.get(i..i + 36).is_some_and(is_uuid) {
            ranges.push((i, i + 36, Kind::Id));
        }
    }
    let mut i = 0;
    while i < b.len() {
        if hexd(b[i]) {
            let mut j = i;
            while j < b.len() && hexd(b[j]) {
                j += 1;
            }
            if j - i >= 20 {
                ranges.push((i, j, Kind::Id));
            }
            i = j;
        } else {
            i += 1;
        }
    }
    if ranges.is_empty() {
        return t.to_string();
    }
    ranges.sort_by_key(|r| (r.0, std::cmp::Reverse(r.1)));
    let mut out = String::new();
    let mut pos = 0;
    for (s, e, k) in ranges {
        if s < pos {
            continue; // overlaps an earlier replacement
        }
        out.push_str(&t[pos..s]);
        out.push_str(k.placeholder());
        hits.push(k);
        pos = e;
    }
    out.push_str(&t[pos..]);
    out
}

fn hexd_or_colon(c: u8) -> bool {
    c.is_ascii_hexdigit() || c == b':' || c == b'.'
}

fn is_env_name(s: &str) -> bool {
    let mut cs = s.chars();
    match cs.next() {
        Some(c) if c.is_ascii_uppercase() || c == '_' => {}
        _ => return false,
    }
    s.len() >= 2
        && s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Classify a punctuation-peeled token. `None` = nothing sensitive recognised. A trailing
/// `:line` / `:line:col` / `:port` does not hide what precedes it.
fn classify(core: &str) -> Option<Kind> {
    classify_inner(core).or_else(|| {
        let mut s = core;
        while let Some((head, tail)) = s.rsplit_once(':') {
            if tail.is_empty() || !tail.bytes().all(|c| c.is_ascii_digit()) {
                break;
            }
            s = head;
        }
        (s.len() != core.len() && !s.is_empty())
            .then(|| classify_inner(s))
            .flatten()
    })
}

fn classify_inner(core: &str) -> Option<Kind> {
    if core.is_empty() || PLACEHOLDERS.contains(&core) {
        return None;
    }
    let has_alnum = core.chars().any(|c| c.is_alphanumeric());
    if !has_alnum {
        return None;
    }
    if core.contains("://") || core.to_ascii_lowercase().starts_with("www.") {
        return Some(Kind::Url);
    }
    if core.starts_with('$') || core.contains("${") || is_percent_var(core) {
        return Some(Kind::Env);
    }
    if core.contains('/') || core.contains('\\') || (core.starts_with('~') && core.len() > 1) {
        return Some(Kind::Path);
    }
    if let Some((l, r)) = core.split_once('@') {
        if !l.is_empty() && !r.is_empty() {
            return Some(Kind::Email);
        }
    }
    if is_mac(core) {
        return Some(Kind::Mac);
    }
    if is_ipv4(core) || is_ipv6(core) {
        return Some(Kind::Ip);
    }
    if is_uuid(core) || is_long_hex(core) {
        return Some(Kind::Id);
    }
    if is_serial(core) {
        return Some(Kind::Serial);
    }
    if is_hostname(core) {
        return Some(Kind::Host);
    }
    None
}

fn is_percent_var(s: &str) -> bool {
    s.len() > 2 && s.starts_with('%') && s.ends_with('%')
}

fn is_hex(c: char) -> bool {
    c.is_ascii_hexdigit()
}

fn is_mac(s: &str) -> bool {
    for sep in [':', '-'] {
        let parts: Vec<&str> = s.split(sep).collect();
        if parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && p.chars().all(is_hex)) {
            return true;
        }
    }
    // Cisco style aabb.ccdd.eeff
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| p.len() == 4 && p.chars().all(is_hex))
}

fn is_ipv4(s: &str) -> bool {
    // Allow a trailing :port.
    // (`1.2.3.4:80`, and `1.2.3.4:80:12:5` once a line/column is appended.)
    let mut it = s.split(':');
    let host = it.next().unwrap_or("");
    if !it.all(|p| p.chars().all(|c| c.is_ascii_digit())) {
        return false;
    }
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.chars().all(|c| c.is_ascii_digit())
                && p.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

fn is_ipv6(s: &str) -> bool {
    let t: String = s.chars().filter(|c| *c != '[' && *c != ']').collect();
    let t = t.split('%').next().unwrap_or("");
    if t.is_empty() || !t.chars().all(|c| is_hex(c) || c == ':' || c == '.') {
        return false;
    }
    let colons = t.matches(':').count();
    colons >= 2 && (t.contains("::") || colons >= 5)
}

fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    let lens = [8, 4, 4, 4, 12];
    parts.len() == 5
        && parts
            .iter()
            .zip(lens)
            .all(|(p, n)| p.len() == n && p.chars().all(is_hex))
}

fn is_long_hex(s: &str) -> bool {
    let t = s.strip_prefix("0x").unwrap_or(s);
    t.len() >= 20 && t.chars().all(is_hex)
}

/// A macOS / Dell-style serial: 10-14 upper-case alphanumerics with both letters and digits.
fn is_serial(s: &str) -> bool {
    (10..=14).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        && s.chars().any(|c| c.is_ascii_digit())
        && s.chars().any(|c| c.is_ascii_uppercase())
}

const TLDS: &[&str] = &[
    "local",
    "lan",
    "internal",
    "home",
    "corp",
    "localdomain",
    "intranet",
    "private",
    "com",
    "net",
    "org",
    "io",
    "dev",
    "edu",
    "gov",
    "co",
    "uk",
    "ie",
    "de",
    "fr",
    "us",
    "eu",
    "ai",
    "app",
    "cloud",
    "xyz",
    "info",
    "biz",
];

fn is_hostname(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    for frag in [
        "macbook",
        "macmini",
        "mac-mini",
        "mac-studio",
        "macstudio",
        "imac",
    ] {
        if lower.contains(frag) {
            return true;
        }
    }
    if let Some(rest) = lower
        .strip_prefix("desktop-")
        .or_else(|| lower.strip_prefix("laptop-"))
    {
        if rest.len() >= 5 && rest.chars().all(|c| c.is_ascii_alphanumeric()) {
            return true;
        }
    }
    if !s.contains('.') {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels
        .iter()
        .any(|l| l.is_empty() || l.starts_with('-') || l.ends_with('-'))
    {
        return false;
    }
    if !labels
        .iter()
        .all(|l| l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
    {
        return false;
    }
    if !labels
        .iter()
        .any(|l| l.chars().any(|c| c.is_ascii_alphabetic()))
    {
        return false; // a version number such as 1.2.3
    }
    let last = labels.last().unwrap_or(&"").to_ascii_lowercase();
    let last_alpha = last.chars().all(|c| c.is_ascii_alphabetic()) && last.len() >= 2;
    TLDS.contains(&last.as_str()) || (labels.len() >= 3 && last_alpha)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> LocalFacts {
        LocalFacts {
            usernames: vec!["jdoe42".into()],
            homes: vec!["/Users/jdoe42".into()],
            hostnames: vec!["Jdoes-MacBook-Pro".into()],
        }
    }

    fn r() -> Redactor {
        Redactor::new(&facts())
    }

    #[test]
    fn scrubs_the_usual_suspects() {
        let cases = [
            ("error in /Users/jdoe42/proj/src/lib.rs:12:5", "jdoe42"),
            ("see C:\\Users\\bob\\Desktop\\x.rs", "bob"),
            ("connect 192.168.1.77:8080 refused", "192.168.1.77"),
            ("peer fe80::1c2b:3dff:fe4a:9b01 down", "fe80"),
            ("nic aa:bb:cc:dd:ee:ff", "aa:bb"),
            ("nic AA-BB-CC-DD-EE-FF", "AA-BB"),
            ("host Jdoes-MacBook-Pro.local", "MacBook"),
            ("serial: C02XG0FDH7JY ok", "C02XG0FDH7JY"),
            ("serial F5K12345ABC ok", "F5K12345ABC"),
            ("id 550e8400-e29b-41d4-a716-446655440000", "550e8400"),
            ("HOME=/Users/x RUST_LOG=debug", "RUST_LOG"),
            ("cd $HOME/x", "$HOME"),
            ("mail jdoe@example.com now", "example.com"),
            ("fetch https://internal.corp/a", "internal.corp"),
            ("open ~/secrets", "~/secrets"),
        ];
        for (input, needle) in cases {
            let s = r().scrub(input);
            assert!(
                !s.text.to_lowercase().contains(&needle.to_lowercase()),
                "{input:?} -> {:?} still contains {needle:?}",
                s.text
            );
            assert!(!s.hits.is_empty(), "no hit for {input:?}");
            // Idempotent: scrubbing the output changes nothing.
            assert_eq!(r().scrub(&s.text).text, s.text, "not idempotent: {input:?}");
        }
    }

    #[test]
    fn leaves_ordinary_diagnostics_alone() {
        for ok in [
            "alloc: hot path allocated",
            "clippy: needless_range_loop",
            "E0499",
            "timeout:build",
            "unified-32",
            "borrow-lifetimes",
            "0.0.1",
        ] {
            // `clippy:` is not a sensitive key; `timeout:build` has no slash.
            let s = r().scrub(ok);
            assert_eq!(s.text, ok, "over-redacted {ok:?}");
        }
    }

    #[test]
    fn home_prefix_collapses_to_one_placeholder() {
        let s = r().scrub("see /Users/jdoe42/x/src/lib.rs:3:1 now");
        assert_eq!(s.text, "see <path> now");
        assert_eq!(r().scrub(&s.text).text, s.text);
    }

    #[test]
    fn literal_username_inside_other_shapes() {
        let s = r().scrub("jdoe42-finetune-Q4.gguf by JDOE42");
        assert!(!s.text.to_lowercase().contains("jdoe42"));
        assert!(s.hits.contains(&Kind::User));
    }

    #[test]
    fn short_username_is_whole_word_only() {
        let f = LocalFacts {
            usernames: vec!["al".into()],
            ..Default::default()
        };
        let r = Redactor::new(&f);
        assert_eq!(r.scrub("alloc: ok").text, "alloc: ok");
        assert_eq!(r.scrub("user al ran").text, "user <user> ran");
    }

    #[test]
    fn invisible_characters_cannot_split_a_literal() {
        let s = r().scrub("jd\u{200B}oe42 at /Us\u{200D}ers/x");
        assert!(!s.text.to_lowercase().contains("jdoe42"));
        assert!(!s.text.contains("Users"));
    }

    #[test]
    fn model_name_path_keeps_basename_only() {
        let mut h = Vec::new();
        let n =
            r().sanitize_model_name("/Users/jdoe42/models/qwen2.5-coder-7b-Q4_K_M.gguf", &mut h);
        assert_eq!(n, "qwen2.5-coder-7b-Q4_K_M.gguf");
        let n = r().sanitize_model_name("jdoe42-qwen.gguf", &mut h);
        assert_eq!(n, "redacted-qwen.gguf");
        let n = r().sanitize_model_name("Qwen/Qwen3-4B", &mut h);
        assert_eq!(n, "Qwen/Qwen3-4B");
        assert_eq!(r().sanitize_model_name("   ", &mut h), "unnamed");
    }

    #[test]
    fn find_leaks_flags_what_scrub_would_change() {
        assert!(r().find_leaks("fine words only").is_empty());
        assert!(r().find_leaks("see /etc/passwd").contains(&Kind::Path));
        assert!(r().find_leaks("jdoe42").contains(&Kind::User));
        assert!(r().find_leaks("serial X").contains(&Kind::Id));
    }

    #[test]
    fn detect_never_panics_and_drops_tiny_facts() {
        let f = LocalFacts::detect();
        assert!(f.usernames.iter().all(|u| u.chars().count() >= 2));
    }
}
