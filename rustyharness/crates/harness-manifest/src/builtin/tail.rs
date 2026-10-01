//! The built-in manifest fragment for the capability list and manifest close.
//!
//! Byte-exact as cut from the former single literal: the concatenation
//! in `builtin::builtin_manifest_json`'s order is pinned by
//! `tests::builtin_manifest_bytes_unchanged`.

pub(crate) const TAIL: &str = r#"  ]
}"#;
