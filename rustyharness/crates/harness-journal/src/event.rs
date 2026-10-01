//! Event bodies: trusted fields as types, untrusted payloads in their typed
//! home (design §7.1 "Untrusted payload home", §7.2).
//!
//! A body is built only from [`Trusted`] values: numbers, booleans,
//! digests, [`Ident`]s, `&'static str` harness text, and nested lists or
//! objects of those, with `&'static str` keys. There is no constructor that
//! takes a runtime `String` as trusted text. Runtime text from outside the
//! harness (tool output, model replies, file contents, arguments) can reach
//! a record only as an [`UntrustedBlob`], which the writer mints from a
//! `harness_core::Untrusted` value and which serialises with
//! `"untrusted": true`, escaped.

use std::collections::BTreeMap;
use std::fmt;

use harness_core::{Digest, Source};
use serde_json::{Map, Value};

use crate::canon::{escape, EventKind, Ident};

/// A trusted body value.
#[derive(Debug, Clone, PartialEq)]
pub enum Trusted {
    /// Boolean.
    Bool(bool),
    /// Unsigned integer.
    U64(u64),
    /// Signed integer.
    I64(i64),
    /// Harness-authored text (compile-time constant).
    Text(&'static str),
    /// A validated identifier.
    Id(Ident),
    /// A digest (hex on the wire).
    Digest(Digest),
    /// A list.
    List(Vec<Trusted>),
    /// An object with harness-authored keys.
    Obj(Vec<(&'static str, Trusted)>),
    /// An untrusted payload in its typed home.
    Untrusted(UntrustedBlob),
}

/// Key reserved for the untrusted marker; refused as a trusted key.
pub(crate) const UNTRUSTED_KEY: &str = "untrusted";

impl Trusted {
    fn to_value(&self) -> Result<Value, &'static str> {
        Ok(match self {
            Trusted::Bool(b) => Value::Bool(*b),
            Trusted::U64(n) => Value::from(*n),
            Trusted::I64(n) => Value::from(*n),
            Trusted::Text(s) => Value::from(*s),
            Trusted::Id(i) => Value::from(i.as_str()),
            Trusted::Digest(d) => Value::from(d.to_string()),
            Trusted::List(l) => {
                Value::Array(l.iter().map(Trusted::to_value).collect::<Result<_, _>>()?)
            }
            Trusted::Obj(fields) => Value::Object(object(fields)?),
            Trusted::Untrusted(b) => b.to_value(),
        })
    }
}

fn object(fields: &[(&'static str, Trusted)]) -> Result<Map<String, Value>, &'static str> {
    let mut m = Map::new();
    for (k, v) in fields {
        if *k == UNTRUSTED_KEY {
            return Err("the key \"untrusted\" is reserved for untrusted payloads");
        }
        if m.insert((*k).to_owned(), v.to_value()?).is_some() {
            return Err("a body key appears twice");
        }
    }
    Ok(m)
}

/// One event: a kind and a trusted body.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    kind: EventKind,
    fields: Vec<(&'static str, Trusted)>,
}

impl Event {
    /// An event with an empty body.
    pub fn new(kind: EventKind) -> Self {
        Self {
            kind,
            fields: Vec::new(),
        }
    }

    /// Add a body field. Duplicate or reserved keys are refused when the
    /// event is appended (without poisoning the writer: a malformed event
    /// is a harness bug, not an I/O failure).
    #[must_use]
    pub fn field(mut self, key: &'static str, value: Trusted) -> Self {
        self.fields.push((key, value));
        self
    }

    /// The kind.
    pub fn kind(&self) -> EventKind {
        self.kind
    }

    pub(crate) fn body(&self) -> Result<Map<String, Value>, &'static str> {
        object(&self.fields)
    }

    pub(crate) fn has_key(&self, key: &str) -> bool {
        self.fields.iter().any(|(k, _)| *k == key)
    }
}

/// A content-addressed blob name: the payload's SHA-256, lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRef(pub(crate) Digest);

impl BlobRef {
    /// The file name under `blobs/`.
    pub fn name(&self) -> String {
        self.0.to_string()
    }
}

/// An untrusted payload's home in a record (§7.1):
/// `{ source, sha256, len, inline | blob }`, serialised with
/// `"untrusted": true`. Minted only by the writer
/// ([`crate::JournalWriter::untrusted`]), which stores large or non-UTF-8
/// payloads in the blob store BEFORE the record that references them.
///
/// `Debug` shows the digest and length, never the payload (the scaffold's
/// "logs are a sink too").
#[derive(Clone, PartialEq)]
pub struct UntrustedBlob {
    pub(crate) source: Source,
    pub(crate) sha256: Digest,
    pub(crate) len: u64,
    /// Escaped text, when the payload is UTF-8 and at most `INLINE_MAX`.
    pub(crate) inline: Option<String>,
    /// Blob store reference otherwise.
    pub(crate) blob: Option<BlobRef>,
}

impl fmt::Debug for UntrustedBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UntrustedBlob")
            .field("sha256", &self.sha256)
            .field("len", &self.len)
            .field("stored", &self.blob.is_some())
            .finish_non_exhaustive()
    }
}

impl UntrustedBlob {
    /// SHA-256 of the raw payload bytes.
    pub fn sha256(&self) -> Digest {
        self.sha256
    }

    /// Payload length in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert(UNTRUSTED_KEY.into(), Value::Bool(true));
        m.insert("source".into(), source_value(&self.source));
        m.insert("sha256".into(), Value::from(self.sha256.to_string()));
        m.insert("len".into(), Value::from(self.len));
        if let Some(i) = &self.inline {
            m.insert("inline".into(), Value::from(i.clone()));
        }
        if let Some(b) = &self.blob {
            m.insert("blob".into(), Value::from(b.name()));
        }
        Value::Object(m)
    }
}

/// `Source` on the wire. Its strings are runtime text, so they are escaped.
pub(crate) fn source_value(s: &Source) -> Value {
    let mut m = BTreeMap::new();
    match s {
        Source::Model => {
            m.insert("kind", Value::from("model"));
        }
        Source::Tool(id) => {
            m.insert("kind", Value::from("tool"));
            m.insert("id", Value::from(escape(id)));
        }
        Source::Workspace(p) => {
            m.insert("kind", Value::from("workspace"));
            m.insert("path", Value::from(escape(p)));
        }
    }
    Value::Object(m.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}
