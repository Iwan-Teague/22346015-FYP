//! The input-schema subset (design §3.3, §4.1, §4.3) and exact-argument
//! validation against it (§2.2 step 5).
//!
//! Only these keywords exist: `type`, `properties`, `required`, `enum`,
//! `maxLength`, `minimum`, `maximum`, `items`, `additionalProperties`
//! (which must be literally `false` on every object). No `oneOf`, no `$ref`,
//! no recursion, no `description`. Each keyword is legal only on the types
//! it constrains, so a keyword that would be silently ignored is refused.

use serde_json::{Map, Value};

/// Deepest nesting of schema nodes (the top-level object is depth 1).
pub const SCHEMA_DEPTH_MAX: usize = 4;
/// Most properties one object schema may declare.
pub const PROPERTIES_MAX: usize = 32;
/// Most values an `enum` may list.
pub const ENUM_MAX: usize = 64;
/// Longest property name, in bytes.
pub const PROPERTY_NAME_MAX: usize = 64;

/// Why a schema was refused, with a JSON-pointer-like location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaError {
    /// Where in the schema (e.g. `/properties/path`).
    pub at: String,
    /// What is wrong.
    pub detail: String,
}

/// Why arguments were refused by a schema, with a location in the arguments.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("arguments refused at {at}: {detail}")]
pub struct ArgsError {
    /// Where in the arguments (e.g. `/path`).
    pub at: String,
    /// What is wrong.
    pub detail: String,
}

/// A validated input schema. Constructible only through [`InputSchema::new`],
/// so holding one means the subset rules were checked.
#[derive(Debug, Clone, PartialEq)]
pub struct InputSchema(Value);

fn serr(at: &str, detail: impl Into<String>) -> SchemaError {
    SchemaError {
        at: if at.is_empty() { "/".into() } else { at.into() },
        detail: detail.into(),
    }
}

fn aerr(at: &str, detail: impl Into<String>) -> ArgsError {
    ArgsError {
        at: if at.is_empty() { "/".into() } else { at.into() },
        detail: detail.into(),
    }
}

fn is_property_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= PROPERTY_NAME_MAX
        && b.first().is_some_and(u8::is_ascii_lowercase)
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

impl InputSchema {
    /// Check `v` against the subset. The top level must be an object schema.
    pub fn new(v: Value) -> Result<Self, SchemaError> {
        let ty = check_node(&v, "", 1)?;
        if ty != "object" {
            return Err(serr("", "the top-level schema must have type \"object\""));
        }
        Ok(Self(v))
    }

    /// The schema as JSON.
    pub fn as_json(&self) -> &Value {
        &self.0
    }

    /// Validate call arguments exactly: every key declared, every required
    /// key present, exact JSON types, `enum`/`maxLength`/bounds honoured.
    pub fn validate_args(&self, args: &Value) -> Result<(), ArgsError> {
        check_value(&self.0, args, "")
    }
}

fn node_obj<'a>(v: &'a Value, at: &str) -> Result<&'a Map<String, Value>, SchemaError> {
    v.as_object()
        .ok_or_else(|| serr(at, "a schema node must be a JSON object"))
}

/// Check one schema node; returns its `type`.
fn check_node<'a>(v: &'a Value, at: &str, depth: usize) -> Result<&'a str, SchemaError> {
    if depth > SCHEMA_DEPTH_MAX {
        return Err(serr(
            at,
            format!("schema nesting deeper than {SCHEMA_DEPTH_MAX}"),
        ));
    }
    let node = node_obj(v, at)?;
    let ty = node
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| serr(at, "\"type\" must be present and a single string"))?;
    let allowed: &[&str] = match ty {
        "object" => &["type", "properties", "required", "additionalProperties"],
        "array" => &["type", "items"],
        "string" => &["type", "enum", "maxLength"],
        "integer" | "number" => &["type", "enum", "minimum", "maximum"],
        "boolean" => &["type"],
        other => return Err(serr(at, format!("type {other:?} is not in the subset"))),
    };
    if let Some(k) = node.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(serr(
            at,
            format!("keyword {k:?} is not allowed on type {ty:?} (subset, design §3.3)"),
        ));
    }
    match ty {
        "object" => check_object(node, at, depth)?,
        "array" => {
            let items = node
                .get("items")
                .ok_or_else(|| serr(at, "an array schema needs \"items\""))?;
            check_node(items, &format!("{at}/items"), depth + 1)?;
        }
        "string" => {
            if let Some(m) = node.get("maxLength") {
                m.as_u64()
                    .ok_or_else(|| serr(at, "\"maxLength\" must be a non-negative integer"))?;
            }
            check_enum(node, at, ty)?;
        }
        "integer" | "number" => {
            let bound = |k: &str| -> Result<Option<f64>, SchemaError> {
                match node.get(k) {
                    None => Ok(None),
                    Some(b) if ty == "integer" && !(b.is_i64() || b.is_u64()) => {
                        Err(serr(at, format!("{k:?} of an integer must be an integer")))
                    }
                    Some(b) => b
                        .as_f64()
                        .map(Some)
                        .ok_or_else(|| serr(at, format!("{k:?} must be a number"))),
                }
            };
            let (lo, hi) = (bound("minimum")?, bound("maximum")?);
            // Integers compare exactly (review F-4); `number` is f64 by nature.
            let inverted = if ty == "integer" {
                let exact = |k| node.get(k).and_then(as_i128);
                matches!((exact("minimum"), exact("maximum")), (Some(l), Some(h)) if l > h)
            } else {
                matches!((lo, hi), (Some(l), Some(h)) if l > h)
            };
            if inverted {
                return Err(serr(at, "\"minimum\" exceeds \"maximum\""));
            }
            check_enum(node, at, ty)?;
        }
        _ => {}
    }
    Ok(ty)
}

fn check_object(node: &Map<String, Value>, at: &str, depth: usize) -> Result<(), SchemaError> {
    if node.get("additionalProperties") != Some(&Value::Bool(false)) {
        return Err(serr(
            at,
            "an object schema needs \"additionalProperties\": false",
        ));
    }
    let props = node
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| serr(at, "an object schema needs a \"properties\" object"))?;
    if props.len() > PROPERTIES_MAX {
        return Err(serr(at, format!("more than {PROPERTIES_MAX} properties")));
    }
    for (name, sub) in props {
        if !is_property_name(name) {
            return Err(serr(
                at,
                format!("property name {name:?} is not [a-z][a-z0-9_]{{0,63}}"),
            ));
        }
        check_node(sub, &format!("{at}/properties/{name}"), depth + 1)?;
    }
    if let Some(req) = node.get("required") {
        let req = req
            .as_array()
            .ok_or_else(|| serr(at, "\"required\" must be an array"))?;
        let mut seen = std::collections::BTreeSet::new();
        for r in req {
            let r = r
                .as_str()
                .ok_or_else(|| serr(at, "\"required\" entries must be strings"))?;
            if !props.contains_key(r) {
                return Err(serr(
                    at,
                    format!("required {r:?} is not a declared property"),
                ));
            }
            if !seen.insert(r) {
                return Err(serr(at, format!("required {r:?} listed twice")));
            }
        }
    }
    Ok(())
}

fn check_enum(node: &Map<String, Value>, at: &str, ty: &str) -> Result<(), SchemaError> {
    let Some(e) = node.get("enum") else {
        return Ok(());
    };
    let e = e
        .as_array()
        .ok_or_else(|| serr(at, "\"enum\" must be an array"))?;
    if e.is_empty() || e.len() > ENUM_MAX {
        return Err(serr(
            at,
            format!("\"enum\" must list 1..={ENUM_MAX} values"),
        ));
    }
    for (i, v) in e.iter().enumerate() {
        if check_scalar_type(ty, v).is_err() {
            return Err(serr(
                at,
                format!("\"enum\" value {i} does not match type {ty:?}"),
            ));
        }
        if e.iter().take(i).any(|p| p == v) {
            return Err(serr(at, format!("\"enum\" value {i} is a duplicate")));
        }
    }
    Ok(())
}

/// Whether `v` has JSON type `ty` (scalars only; containers checked by caller).
fn check_scalar_type(ty: &str, v: &Value) -> Result<(), String> {
    let ok = match ty {
        "string" => v.is_string(),
        "integer" => v.is_i64() || v.is_u64(),
        "number" => v.is_number(),
        "boolean" => v.is_boolean(),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(format!("expected {ty}"))
    }
}

/// A JSON integer as i128 (every i64 and u64 fits); `None` for non-integers.
fn as_i128(v: &Value) -> Option<i128> {
    v.as_i64()
        .map(i128::from)
        .or_else(|| v.as_u64().map(i128::from))
}

fn check_value(schema: &Value, v: &Value, at: &str) -> Result<(), ArgsError> {
    // The schema was validated at construction; anything unexpected here is
    // refused rather than assumed.
    let node = schema
        .as_object()
        .ok_or_else(|| aerr(at, "schema node unreadable"))?;
    let ty = node
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| aerr(at, "schema node has no type"))?;
    match ty {
        "object" => {
            let obj = v.as_object().ok_or_else(|| aerr(at, "expected object"))?;
            let props = node
                .get("properties")
                .and_then(Value::as_object)
                .ok_or_else(|| aerr(at, "schema object has no properties"))?;
            for (k, sub_v) in obj {
                let sub_s = props
                    .get(k)
                    .ok_or_else(|| aerr(at, format!("unknown argument {k:?}")))?;
                check_value(sub_s, sub_v, &format!("{at}/{k}"))?;
            }
            if let Some(req) = node.get("required").and_then(Value::as_array) {
                for r in req.iter().filter_map(Value::as_str) {
                    if !obj.contains_key(r) {
                        return Err(aerr(at, format!("missing required argument {r:?}")));
                    }
                }
            }
            Ok(())
        }
        "array" => {
            let arr = v.as_array().ok_or_else(|| aerr(at, "expected array"))?;
            let items = node
                .get("items")
                .ok_or_else(|| aerr(at, "schema array has no items"))?;
            for (i, e) in arr.iter().enumerate() {
                check_value(items, e, &format!("{at}/{i}"))?;
            }
            Ok(())
        }
        _ => {
            check_scalar_type(ty, v).map_err(|d| aerr(at, d))?;
            if let Some(e) = node.get("enum").and_then(Value::as_array) {
                if !e.contains(v) {
                    return Err(aerr(at, "value is not one of the enum values"));
                }
            }
            if let (Some(max), Some(s)) =
                (node.get("maxLength").and_then(Value::as_u64), v.as_str())
            {
                if s.chars().count() as u64 > max {
                    return Err(aerr(at, format!("longer than maxLength {max}")));
                }
            }
            if ty == "integer" {
                // Exact: both sides are JSON integers (checked above and at
                // construction), compared as i128 so values past 2^53 do
                // not round together (review F-4).
                let n = as_i128(v).ok_or_else(|| aerr(at, "expected integer"))?;
                if node
                    .get("minimum")
                    .and_then(as_i128)
                    .is_some_and(|lo| n < lo)
                {
                    return Err(aerr(at, "below minimum"));
                }
                if node
                    .get("maximum")
                    .and_then(as_i128)
                    .is_some_and(|hi| n > hi)
                {
                    return Err(aerr(at, "above maximum"));
                }
            } else if let Some(n) = v.as_f64() {
                if node
                    .get("minimum")
                    .and_then(Value::as_f64)
                    .is_some_and(|lo| n < lo)
                {
                    return Err(aerr(at, "below minimum"));
                }
                if node
                    .get("maximum")
                    .and_then(Value::as_f64)
                    .is_some_and(|hi| n > hi)
                {
                    return Err(aerr(at, "above maximum"));
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ok_schema() -> Value {
        json!({"type":"object","additionalProperties":false,
               "properties":{"path":{"type":"string","maxLength":8},
                             "n":{"type":"integer","minimum":1,"maximum":5},
                             "mode":{"type":"string","enum":["a","b"]},
                             "tags":{"type":"array","items":{"type":"string"}}},
               "required":["path"]})
    }

    #[test]
    fn subset_schema_is_accepted() {
        assert!(InputSchema::new(ok_schema()).is_ok());
    }

    #[test]
    fn schemas_outside_the_subset_are_refused() {
        let bad = [
            // missing additionalProperties:false
            json!({"type":"object","properties":{}}),
            // additionalProperties true / schema-valued
            json!({"type":"object","properties":{},"additionalProperties":true}),
            json!({"type":"object","properties":{},"additionalProperties":{}}),
            // keywords outside the subset
            json!({"type":"object","properties":{},"additionalProperties":false,"oneOf":[]}),
            json!({"type":"object","properties":{"a":{"$ref":"#"}},"additionalProperties":false}),
            json!({"type":"object","properties":{"a":{"type":"string","description":"x"}},"additionalProperties":false}),
            json!({"type":"object","properties":{"a":{"type":"string","pattern":"x"}},"additionalProperties":false}),
            // keyword on the wrong type (would be silently ignored)
            json!({"type":"object","properties":{"a":{"type":"string","minimum":1}},"additionalProperties":false}),
            // type arrays / unknown types / no type
            json!({"type":["object","null"],"properties":{},"additionalProperties":false}),
            json!({"type":"object","properties":{"a":{"type":"null"}},"additionalProperties":false}),
            json!({"type":"object","properties":{"a":{}},"additionalProperties":false}),
            // required names an undeclared property / twice
            json!({"type":"object","properties":{},"additionalProperties":false,"required":["x"]}),
            json!({"type":"object","properties":{"x":{"type":"string"}},"additionalProperties":false,"required":["x","x"]}),
            // top level not an object
            json!({"type":"string"}),
            // bad property name
            json!({"type":"object","properties":{"Path":{"type":"string"}},"additionalProperties":false}),
            // min > max; float bound on integer
            json!({"type":"object","properties":{"n":{"type":"integer","minimum":5,"maximum":1}},"additionalProperties":false}),
            json!({"type":"object","properties":{"n":{"type":"integer","minimum":0.5}},"additionalProperties":false}),
            // empty / mistyped / duplicate enum
            json!({"type":"object","properties":{"m":{"type":"string","enum":[]}},"additionalProperties":false}),
            json!({"type":"object","properties":{"m":{"type":"string","enum":[1]}},"additionalProperties":false}),
            json!({"type":"object","properties":{"m":{"type":"string","enum":["a","a"]}},"additionalProperties":false}),
            // array without items
            json!({"type":"object","properties":{"t":{"type":"array"}},"additionalProperties":false}),
            // too deep
            json!({"type":"object","additionalProperties":false,"properties":{"a":{"type":"object","additionalProperties":false,"properties":{"b":{"type":"object","additionalProperties":false,"properties":{"c":{"type":"array","items":{"type":"string"}}}}}}}}),
        ];
        for b in bad {
            assert!(InputSchema::new(b.clone()).is_err(), "must refuse {b}");
        }
    }

    // Review F-4: integer bounds compare exactly, not through f64.
    #[test]
    fn integer_bounds_are_compared_exactly() {
        let s = InputSchema::new(json!({"type":"object","additionalProperties":false,
            "properties":{"n":{"type":"integer","minimum":-9007199254740992_i64,"maximum":9007199254740992_i64},
                          "u":{"type":"integer","maximum":18446744073709551614_u64}}})).unwrap();
        assert!(s.validate_args(&json!({"n": 9007199254740992_i64})).is_ok());
        assert!(s
            .validate_args(&json!({"n": 9007199254740993_i64}))
            .is_err());
        assert!(s
            .validate_args(&json!({"n": -9007199254740992_i64}))
            .is_ok());
        assert!(s
            .validate_args(&json!({"n": -9007199254740993_i64}))
            .is_err());
        assert!(s
            .validate_args(&json!({"u": 18446744073709551614_u64}))
            .is_ok());
        assert!(s
            .validate_args(&json!({"u": 18446744073709551615_u64}))
            .is_err());
    }

    #[test]
    fn args_are_validated_exactly() {
        let s = InputSchema::new(ok_schema()).unwrap();
        assert!(s.validate_args(&json!({"path":"a"})).is_ok());
        assert!(s
            .validate_args(&json!({"path":"a","n":5,"mode":"b","tags":["x"]}))
            .is_ok());
        for bad in [
            json!({}),                      // missing required
            json!({"path":"a","extra":1}),  // unknown argument
            json!({"path":1}),              // wrong type
            json!({"path":"123456789"}),    // maxLength (chars)
            json!({"path":"a","n":0}),      // below minimum
            json!({"path":"a","n":6}),      // above maximum
            json!({"path":"a","n":2.0}),    // float for integer
            json!({"path":"a","mode":"c"}), // not in enum
            json!({"path":"a","tags":[1]}), // item type
            json!("path"),                  // not an object
            json!(null),
        ] {
            assert!(s.validate_args(&bad).is_err(), "must refuse args {bad}");
        }
    }
}
