//! The built-in manifest fragment for the manifest header (provider, versions, the builtin transport).
//!
//! Byte-exact as cut from the former single literal: the concatenation
//! in `builtin::builtin_manifest_json`'s order is pinned by
//! `tests::builtin_manifest_bytes_unchanged`.

pub(crate) const HEAD: &str = r#"{
  "schema_version": 1,
  "provider": "harness",
  "provider_version": "0.0.1",
  "min_harness": "0.0.1",
  "transport": { "kind": "builtin" },
  "capabilities": [
"#;
