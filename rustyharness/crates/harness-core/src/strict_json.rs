//! Duplicate-key-refusing JSON reading (design §4.3, scaffold review F13,
//! INV-22). Shared by the manifest parser and the model-action parsers
//! (moved here from `harness-manifest` in H1d, so both use one reader).
//!
//! serde_json keeps the LAST value of a duplicated key, so
//! `{"schema_version":1, …, "schema_version":0}` would silently read as v0.
//! [`parse`] reads the bytes through a custom visitor that refuses a
//! repeated key in any object at any depth, and only then hands a plain
//! [`serde_json::Value`] to the typed layer.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// A JSON value read with duplicate keys refused.
struct NoDup(Value);

/// Marker prefix of the error the visitor raises, so the caller can type it.
pub const DUPLICATE_KEY: &str = "duplicate JSON key";

impl<'de> Deserialize<'de> for NoDup {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(NoDupVisitor)
    }
}

struct NoDupVisitor;

impl<'de> Visitor<'de> for NoDupVisitor {
    type Value = NoDup;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<NoDup, E> {
        Ok(NoDup(Value::Bool(v)))
    }

    fn visit_i64<E>(self, v: i64) -> Result<NoDup, E> {
        Ok(NoDup(Value::Number(v.into())))
    }

    fn visit_u64<E>(self, v: u64) -> Result<NoDup, E> {
        Ok(NoDup(Value::Number(v.into())))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<NoDup, E> {
        Number::from_f64(v)
            .map(|n| NoDup(Value::Number(n)))
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, v: &str) -> Result<NoDup, E> {
        Ok(NoDup(Value::String(v.to_owned())))
    }

    fn visit_string<E>(self, v: String) -> Result<NoDup, E> {
        Ok(NoDup(Value::String(v)))
    }

    fn visit_unit<E>(self) -> Result<NoDup, E> {
        Ok(NoDup(Value::Null))
    }

    fn visit_none<E>(self) -> Result<NoDup, E> {
        Ok(NoDup(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<NoDup, A::Error> {
        let mut out = Vec::new();
        while let Some(NoDup(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(NoDup(Value::Array(out)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<NoDup, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                // Debug-escaped and bounded: the key is untrusted text.
                let shown: String = key.chars().take(64).collect();
                return Err(de::Error::custom(format!("{DUPLICATE_KEY} {shown:?}")));
            }
            let NoDup(v) = map.next_value()?;
            out.insert(key, v);
        }
        Ok(NoDup(Value::Object(out)))
    }
}

/// Parse `bytes` as exactly one JSON value, refusing duplicate object keys at
/// every depth, invalid UTF-8 and trailing content. serde_json's recursion
/// limit (128) bounds nesting.
pub fn parse(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let NoDup(v) = NoDup::deserialize(&mut de)?;
    de.end()?;
    Ok(v)
}

/// Why [`parse_typed`] refused its input, for a message that names the
/// fault (H2e: a model sent the same action with one extra `}` three
/// times after a repair message that did not say what was wrong).
///
/// Positions are 1-based line and byte column in the input. Nothing of the
/// input itself is kept, so a message built from a `Fault` never quotes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// Nothing, or only whitespace.
    Empty,
    /// One whole JSON value, then more content from this position.
    Trailing {
        /// Line of the first byte after the value.
        line: usize,
        /// Column of that byte.
        column: usize,
    },
    /// The input ends inside a value: an object, array or string left open.
    Truncated,
    /// An object repeats a key.
    DuplicateKey,
    /// Any other refusal (a syntax error, invalid UTF-8, nesting past the
    /// limit), where the reader stopped.
    Syntax {
        /// Line where the reader stopped.
        line: usize,
        /// Column where it stopped.
        column: usize,
    },
}

/// JSON's own whitespace (RFC 8259 §2).
fn json_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// [`parse`], with a refusal typed as a [`Fault`]: it accepts and refuses
/// exactly what [`parse`] does.
pub fn parse_typed(bytes: &[u8]) -> Result<Value, Fault> {
    if bytes.iter().all(|&b| json_space(b)) {
        return Err(Fault::Empty);
    }
    let mut values = serde_json::Deserializer::from_slice(bytes).into_iter::<NoDup>();
    match values.next() {
        None => Err(Fault::Empty),
        Some(Ok(NoDup(v))) => {
            let end = values.byte_offset();
            let rest = bytes.get(end..).unwrap_or_default();
            match rest.iter().position(|&b| !json_space(b)) {
                None => Ok(v),
                Some(k) => {
                    let at = end + k;
                    let before = bytes.get(..at).unwrap_or_default();
                    let line = 1 + before.iter().filter(|&&b| b == b'\n').count();
                    let column = at
                        - before
                            .iter()
                            .rposition(|&b| b == b'\n')
                            .map_or(0, |i| i + 1)
                        + 1;
                    Err(Fault::Trailing { line, column })
                }
            }
        }
        Some(Err(e)) if e.to_string().starts_with(DUPLICATE_KEY) => Err(Fault::DuplicateKey),
        Some(Err(e)) if e.is_eof() => Err(Fault::Truncated),
        Some(Err(e)) => Err(Fault::Syntax {
            line: e.line(),
            column: e.column(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_keys_refused_at_every_depth() {
        for bad in [
            r#"{"a":1,"a":2}"#,
            r#"{"a":{"b":1,"b":1}}"#,
            r#"{"a":[{"x":{"y":true,"y":false}}]}"#,
            r#"[{"k":null,"k":null}]"#,
        ] {
            let err = parse(bad.as_bytes()).expect_err(bad);
            assert!(err.to_string().contains(DUPLICATE_KEY), "{bad}: {err}");
        }
    }

    #[test]
    fn well_formed_json_round_trips() {
        let v = parse(br#"{"a":[1,-2,3.5,"s",null,true],"b":{"c":{}}}"#).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"a":[1,-2,3.5,"s",null,true],"b":{"c":{}}})
        );
    }

    #[test]
    fn trailing_content_and_bad_utf8_refused() {
        assert!(parse(br#"{"a":1} {"a":2}"#).is_err());
        assert!(parse(b"\"\xff\"").is_err());
        assert!(parse(b"").is_err());
    }

    #[test]
    fn h2e_a_refusal_is_typed_and_accepts_exactly_what_parse_accepts() {
        let cases: [(&[u8], Option<Fault>); 16] = [
            (br#"{"a":1}"#, None),
            (b" \n{\"a\":[1,{\"b\":null}]}\r\n\t", None),
            (b"", Some(Fault::Empty)),
            (b" \n\t\r", Some(Fault::Empty)),
            (
                br#"{"tool":"t","args":{"x":1}}}"#,
                Some(Fault::Trailing {
                    line: 1,
                    column: 28,
                }),
            ),
            (
                b"{\"a\":1}\n  } ",
                Some(Fault::Trailing { line: 2, column: 3 }),
            ),
            (
                br#"{"a":1} {"a":2}"#,
                Some(Fault::Trailing { line: 1, column: 9 }),
            ),
            (br#"{"a":{"b":1}"#, Some(Fault::Truncated)),
            (br#"{"a":"b"#, Some(Fault::Truncated)),
            (b"[1,2", Some(Fault::Truncated)),
            (br#"{"a":1,"a":2}"#, Some(Fault::DuplicateKey)),
            (br#"{"a":{"b":1,"b":1}}"#, Some(Fault::DuplicateKey)),
            (br#"{"a":1,}"#, Some(Fault::Syntax { line: 1, column: 8 })),
            (b"{'a':1}", Some(Fault::Syntax { line: 1, column: 2 })),
            (b"\"\xff\"", Some(Fault::Syntax { line: 1, column: 3 })),
            (b"12ab", Some(Fault::Syntax { line: 1, column: 3 })),
        ];
        for (bytes, want) in cases {
            let shown = String::from_utf8_lossy(bytes);
            let got = parse_typed(bytes);
            assert_eq!(got.as_ref().err().copied(), want, "{shown:?}");
            // The typed reader refuses exactly what `parse` refuses, and
            // reads the same value from what it accepts.
            assert_eq!(got.ok(), parse(bytes).ok(), "{shown:?}");
        }
    }
}
