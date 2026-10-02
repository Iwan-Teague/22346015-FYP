//! The `rh-fileop/1` file-operation protocol (design §7.3).
//!
//! This module holds the protocol codec only: [`proto`] turns typed
//! requests and replies into bytes and back, with no I/O and no process
//! spawning. The helper that executes the requests arrives in a later
//! slice; both the macOS stub and the Linux backend speak the same frames
//! (design §8.4), so the codec is built unconditionally and is
//! backend-neutral.

pub mod proto;

pub use proto::{
    CodecError, ErrorCode, Reply, Request, MAX_ITEM_LENGTH_DIGITS, MAX_LINE_BYTES,
    MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
};
