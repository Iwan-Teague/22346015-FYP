//! Canonical serialisation and the content hash.
//!
//! docs/11 and docs/12 specify *canonical CBOR* signed with ed25519. Neither a CBOR crate nor a
//! signing key exists yet (and an embedded key is T0-only anyway, docs/10), so this crate defines
//! **`rb-canon-json-v1`**: JSON with object keys sorted by UTF-8 byte order, no insignificant
//! whitespace, and numbers/strings exactly as `serde_json` renders them (shortest round-trip
//! floats). It is a stand-in with the same property that matters here — one value, one byte
//! string — and it is deliberately *not* RFC 8785 (JCS): float formatting is serde_json's.
//! Switching to CBOR later changes only this module and the `canon` version string.

use serde_json::Value;

/// Names the canonical form, so a verifier can refuse a form it does not implement.
pub const CANON_VERSION: &str = "rb-canon-json-v1";

/// Domain separator mixed into the hash so a bundle hash cannot collide with some other
/// blake3 use (unit ids, suite hashes) over the same bytes.
const HASH_DOMAIN: &[u8] = b"rustybench.upload-bundle.v1\0";

/// Canonical bytes of a JSON value.
pub fn canonical_bytes(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(v, &mut out);
    out
}

fn write_value(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => write_string(s, out),
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(x, out);
            }
            out.push(b']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push(b'{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                write_value(&m[k], out);
            }
            out.push(b'}');
        }
    }
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    // serde_json's string escaping is deterministic and total; reuse it.
    let rendered = serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string());
    out.extend_from_slice(rendered.as_bytes());
}

/// `blake3:<64 hex>` over the domain separator and the canonical bytes of `body`.
pub fn content_hash(body: &Value) -> String {
    let mut h = blake3::Hasher::new();
    h.update(HASH_DOMAIN);
    h.update(&canonical_bytes(body));
    format!("blake3:{}", h.finalize().to_hex())
}

/// True for exactly `blake3:` followed by 64 lower-case hex digits.
pub fn is_blake3_id(s: &str) -> bool {
    s.strip_prefix("blake3:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_sorted_and_compact() {
        let a = json!({"b": 1, "a": [true, null, "x\"y"], "c": {"z": 0.5, "y": -3}});
        assert_eq!(
            String::from_utf8(canonical_bytes(&a)).unwrap(),
            r#"{"a":[true,null,"x\"y"],"b":1,"c":{"y":-3,"z":0.5}}"#
        );
    }

    #[test]
    fn insertion_order_does_not_matter() {
        let a: Value = serde_json::from_str(r#"{"x":1,"y":2}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"y":2,"x":1}"#).unwrap();
        assert_eq!(canonical_bytes(&a), canonical_bytes(&b));
        assert_eq!(content_hash(&a), content_hash(&b));
    }

    #[test]
    fn hash_changes_with_content_and_has_domain() {
        let a = json!({"x": 1});
        let b = json!({"x": 2});
        assert_ne!(content_hash(&a), content_hash(&b));
        let plain = format!("blake3:{}", blake3::hash(&canonical_bytes(&a)).to_hex());
        assert_ne!(content_hash(&a), plain);
        assert!(is_blake3_id(&content_hash(&a)));
    }

    #[test]
    fn blake3_id_shape() {
        assert!(!is_blake3_id("blake3:abc"));
        assert!(!is_blake3_id(&format!("blake3:{}", "A".repeat(64))));
        assert!(is_blake3_id(&format!("blake3:{}", "a".repeat(64))));
    }
}
