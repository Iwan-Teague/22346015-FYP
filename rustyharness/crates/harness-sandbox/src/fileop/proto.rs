//! Byte codec for the `rh-fileop/1` file-operation protocol (design §7.3).
//!
//! A request is an operation name, a decimal item count, and that many
//! *items*; a reply is either `ok <n>` plus `n` items or `err <code>`. An
//! item is `<len>\n<bytes>`, the same frame the domain stub already speaks
//! (`crates/harness-sandbox/src/confine_spawn.rs`): the length is decimal,
//! one to eight digits, `0` allowed for an empty item. Every line is
//! bounded at [`MAX_LINE_BYTES`] bytes and the whole message at
//! [`MAX_REQUEST_BYTES`] (request) or [`MAX_RESPONSE_BYTES`] (reply).
//!
//! The codec is pure: no I/O, no clock, no process. It validates form, not
//! intent — the executing helper re-checks every path and refuses what this
//! module accepted only as well-formed. Decoding is fail-closed and reads
//! ahead of no allocation: every length is checked against the bytes
//! actually present before anything is copied.
//!
//! Numbers (`max`, `max_entries`, `depth`, `mode`, `max_new_dirs`,
//! `timeout_ms`) travel as items holding decimal text; design §7.3 gives
//! `rh-fileop/1` no inline-number syntax, so they ride the uniform item
//! frame. Encoding always emits the canonical shortest form, so equal
//! requests encode to equal bytes.

use std::str::FromStr;

use harness_core::Digest;
use harness_policy::{workspace_path, PathRefused, WorkspacePath};
use thiserror::Error;

/// Largest one request may be, in bytes (design §7.3).
pub const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
/// Largest one reply may be, in bytes (design §7.3: 8 MiB of payload plus
/// 64 bytes of framing).
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024 + 64;
/// Most digits an item length or item count may hold (the stub's
/// `^[0-9]{1,8}$`).
pub const MAX_ITEM_LENGTH_DIGITS: usize = 8;
/// Largest line (operation line, count line, length line) the stub reads,
/// in bytes; decode refuses anything longer.
pub const MAX_LINE_BYTES: usize = 64;

/// A request to perform one file operation inside the workspace (§7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Stat a path without following symlinks; the reply carries type, size,
    /// mode and link count.
    Lstat {
        /// The path to stat, workspace-relative.
        path: WorkspacePath,
    },
    /// Read up to `max` bytes from a file; the reply carries at most
    /// `max + 1` bytes so an over-cap read stays detectable.
    Read {
        /// The file to read, workspace-relative.
        path: WorkspacePath,
        /// Most bytes to return.
        max: u32,
    },
    /// List a directory's entries; the reply carries name, type and size.
    List {
        /// The directory to list, workspace-relative.
        path: WorkspacePath,
        /// Most entries to return.
        max_entries: u32,
        /// How deep to descend into subdirectories.
        depth: u32,
    },
    /// Walk the whole workspace; the reply carries path, type, size and
    /// SHA-256 per entry.
    Tree {
        /// Most entries to return.
        max_entries: u32,
        /// Most time the walk may take, in milliseconds.
        timeout_ms: u32,
    },
    /// Create a file (and at most `max_new_dirs` missing parents); the reply
    /// carries how many directories were made.
    Create {
        /// The file to create, workspace-relative.
        path: WorkspacePath,
        /// The file's contents.
        bytes: Vec<u8>,
        /// The permission bits to apply.
        mode: u32,
        /// Most missing parent directories to create.
        max_new_dirs: u32,
    },
    /// Replace a file's contents only while it still hashes to
    /// `expect_sha`; the reply carries the new digest.
    Replace {
        /// The file to replace, workspace-relative.
        path: WorkspacePath,
        /// The new contents.
        bytes: Vec<u8>,
        /// The digest the file must still have.
        expect_sha: Digest,
    },
    /// Unlink a file only while it still hashes to `expect_sha`.
    Unlink {
        /// The file to unlink, workspace-relative.
        path: WorkspacePath,
        /// The digest the file must still have.
        expect_sha: Digest,
    },
    /// Rename a file (creating at most `max_new_dirs` missing parents of the
    /// destination) only while the source still hashes to `expect_sha`; the
    /// reply carries how many directories were made.
    Move {
        /// The source path, workspace-relative.
        from: WorkspacePath,
        /// The destination path, workspace-relative.
        to: WorkspacePath,
        /// The digest the source must still have.
        expect_sha: Digest,
        /// Most missing parent directories to create at the destination.
        max_new_dirs: u32,
    },
    /// Remove an empty directory.
    Rmdir {
        /// The directory to remove, workspace-relative.
        path: WorkspacePath,
    },
    /// Probe that a path outside the workspace stays refused; the helper
    /// always answers `err denied` (§7.3).
    Ping {
        /// A path deliberately outside the workspace, as raw text: this
        /// argument exists to be refused, so it is not a [`WorkspacePath`].
        outside_probe_path: String,
    },
}

/// How a request ended, in the helper's own words (§7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// A path did not exist.
    NoEnt,
    /// A symlink stood where a plain path was required.
    Symlink,
    /// A path component was not a directory.
    NotDir,
    /// A directory stood where a file was required.
    IsDir,
    /// A file to create already existed.
    Exists,
    /// A size or count bound was exceeded.
    TooBig,
    /// A file changed under an `expect_sha` guard.
    Changed,
    /// The operation was refused (path outside the workspace, probe).
    Denied,
    /// A directory was not empty (or a link-count guard tripped).
    NLink,
    /// An unclassified I/O error.
    Io,
    /// The request itself was malformed or unknown.
    BadReq,
}

impl ErrorCode {
    /// The wire spelling of this code.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::NoEnt => "noent",
            ErrorCode::Symlink => "symlink",
            ErrorCode::NotDir => "notdir",
            ErrorCode::IsDir => "isdir",
            ErrorCode::Exists => "exists",
            ErrorCode::TooBig => "toobig",
            ErrorCode::Changed => "changed",
            ErrorCode::Denied => "denied",
            ErrorCode::NLink => "nlink",
            ErrorCode::Io => "io",
            ErrorCode::BadReq => "badreq",
        }
    }

    /// Parses a wire-spelled code.
    pub fn parse(text: &[u8]) -> Option<ErrorCode> {
        match text {
            b"noent" => Some(ErrorCode::NoEnt),
            b"symlink" => Some(ErrorCode::Symlink),
            b"notdir" => Some(ErrorCode::NotDir),
            b"isdir" => Some(ErrorCode::IsDir),
            b"exists" => Some(ErrorCode::Exists),
            b"toobig" => Some(ErrorCode::TooBig),
            b"changed" => Some(ErrorCode::Changed),
            b"denied" => Some(ErrorCode::Denied),
            b"nlink" => Some(ErrorCode::NLink),
            b"io" => Some(ErrorCode::Io),
            b"badreq" => Some(ErrorCode::BadReq),
            _ => None,
        }
    }
}

/// A reply to one request: success with items, or a refusal code (§7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// The operation succeeded; the items are the operation's results, in
    /// the fixed per-operation order of design §7.3. The wire form carries
    /// no operation name, so the items stay opaque bytes here — the caller
    /// that sent the request knows how to read them.
    Ok {
        /// The result items.
        items: Vec<Vec<u8>>,
    },
    /// The operation was refused.
    Err {
        /// Why it was refused.
        code: ErrorCode,
    },
}

/// Why bytes were refused as a `rh-fileop/1` message.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CodecError {
    /// The request exceeded [`MAX_REQUEST_BYTES`].
    #[error("fileop request is {size} bytes, over the {MAX_REQUEST_BYTES}-byte bound")]
    RequestTooLarge {
        /// The refused size, in bytes.
        size: usize,
    },
    /// The reply exceeded [`MAX_RESPONSE_BYTES`].
    #[error("fileop reply is {size} bytes, over the {MAX_RESPONSE_BYTES}-byte bound")]
    ResponseTooLarge {
        /// The refused size, in bytes.
        size: usize,
    },
    /// An item length did not fit the one-to-eight-digit frame.
    #[error("fileop item length is not representable in {MAX_ITEM_LENGTH_DIGITS} digits")]
    ItemTooLarge,
    /// The item count was not a one-to-eight-digit decimal (or was zero
    /// where items must follow).
    #[error("fileop item count is not a 1-8 digit decimal")]
    BadCount,
    /// An item length was not a one-to-eight-digit decimal.
    #[error("fileop item length is not a 1-8 digit decimal")]
    BadLength,
    /// A numeric argument item was not decimal text.
    #[error("fileop numeric argument is not decimal text")]
    BadNumber,
    /// A digest argument was not 64 hex characters.
    #[error("fileop digest argument is not a 64-hex-character SHA-256")]
    BadDigest,
    /// The operation name was not one of §7.3's.
    #[error("fileop operation name is unknown")]
    UnknownOp,
    /// An error code was not one of §7.3's.
    #[error("fileop error code is unknown")]
    UnknownCode,
    /// The frame ended early, ran long, or carried trailing bytes.
    #[error("fileop frame is truncated or carries trailing bytes")]
    BadFrame,
    /// An item that should be workspace-relative text was refused by the
    /// harness-policy lexical rules.
    #[error("fileop path item was refused: {0}")]
    BadPath(PathRefused),
    /// An item was not valid UTF-8 where text was required.
    #[error("fileop text item is not valid UTF-8")]
    BadUtf8,
    /// A path held an empty, `.` or `..` component. The harness-policy
    /// lexical check should already refuse these; the codec re-checks the
    /// raw item so the frame itself never carries one (defence in depth,
    /// §7.3).
    #[error("fileop path carries an empty, `.` or `..` component")]
    PathComponent,
    /// A ping probe path was empty or held a control character.
    #[error("fileop ping probe path is empty or holds a control character")]
    BadProbePath,
}

impl Request {
    /// The wire name of this operation (§7.3).
    pub fn op_name(&self) -> &'static str {
        match self {
            Request::Lstat { .. } => "lstat",
            Request::Read { .. } => "read",
            Request::List { .. } => "list",
            Request::Tree { .. } => "tree",
            Request::Create { .. } => "create",
            Request::Replace { .. } => "replace",
            Request::Unlink { .. } => "unlink",
            Request::Move { .. } => "move",
            Request::Rmdir { .. } => "rmdir",
            Request::Ping { .. } => "ping",
        }
    }

    /// Encodes this request as one bounded frame.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let items = self.encode_items()?;
        let count = items.len();
        let mut total = self.op_name().len() + 1 + digits_of(count) + 1;
        for item in &items {
            total = total
                .checked_add(digits_of(item.len()) + 1 + item.len())
                .ok_or(CodecError::RequestTooLarge { size: usize::MAX })?;
        }
        if total > MAX_REQUEST_BYTES {
            return Err(CodecError::RequestTooLarge { size: total });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(self.op_name().as_bytes());
        out.push(b'\n');
        out.extend_from_slice(count.to_string().as_bytes());
        out.push(b'\n');
        for item in &items {
            out.extend_from_slice(item.len().to_string().as_bytes());
            out.push(b'\n');
            out.extend_from_slice(item);
        }
        Ok(out)
    }

    /// Decodes one request frame. The whole input must be exactly one
    /// request: no more, no less.
    pub fn decode(input: &[u8]) -> Result<Request, CodecError> {
        if input.len() > MAX_REQUEST_BYTES {
            return Err(CodecError::RequestTooLarge { size: input.len() });
        }
        let (op, pos) = next_line(input, 0).ok_or(CodecError::BadFrame)?;
        let (count_text, mut pos) = next_line(input, pos).ok_or(CodecError::BadFrame)?;
        let count = parse_decimal(count_text).ok_or(CodecError::BadCount)?;
        if count == 0 {
            return Err(CodecError::BadCount);
        }
        let mut items = Vec::new();
        for _ in 0..count {
            let (item, after) = take_item(input, pos)?;
            items.push(item.to_vec());
            pos = after;
        }
        if pos != input.len() {
            return Err(CodecError::BadFrame);
        }
        let mut args = items.iter().map(Vec::as_slice);
        match op {
            b"lstat" => Ok(Request::Lstat {
                path: next_path(&mut args)?,
            }),
            b"read" => {
                let path = next_path(&mut args)?;
                let max = next_u32(&mut args)?;
                Ok(Request::Read { path, max })
            }
            b"list" => {
                let path = next_path(&mut args)?;
                let max_entries = next_u32(&mut args)?;
                let depth = next_u32(&mut args)?;
                Ok(Request::List {
                    path,
                    max_entries,
                    depth,
                })
            }
            b"tree" => {
                let max_entries = next_u32(&mut args)?;
                let timeout_ms = next_u32(&mut args)?;
                Ok(Request::Tree {
                    max_entries,
                    timeout_ms,
                })
            }
            b"create" => {
                let path = next_path(&mut args)?;
                let bytes = next_bytes(&mut args)?.to_vec();
                let mode = next_u32(&mut args)?;
                let max_new_dirs = next_u32(&mut args)?;
                Ok(Request::Create {
                    path,
                    bytes,
                    mode,
                    max_new_dirs,
                })
            }
            b"replace" => {
                let path = next_path(&mut args)?;
                let bytes = next_bytes(&mut args)?.to_vec();
                let expect_sha = next_digest(&mut args)?;
                Ok(Request::Replace {
                    path,
                    bytes,
                    expect_sha,
                })
            }
            b"unlink" => {
                let path = next_path(&mut args)?;
                let expect_sha = next_digest(&mut args)?;
                Ok(Request::Unlink { path, expect_sha })
            }
            b"move" => {
                let from = next_path(&mut args)?;
                let to = next_path(&mut args)?;
                let expect_sha = next_digest(&mut args)?;
                let max_new_dirs = next_u32(&mut args)?;
                Ok(Request::Move {
                    from,
                    to,
                    expect_sha,
                    max_new_dirs,
                })
            }
            b"rmdir" => Ok(Request::Rmdir {
                path: next_path(&mut args)?,
            }),
            b"ping" => Ok(Request::Ping {
                outside_probe_path: next_probe(&mut args)?,
            }),
            _ => Err(CodecError::UnknownOp),
        }
    }

    /// Encodes each field as one item, in §7.3's per-operation order.
    fn encode_items(&self) -> Result<Vec<Vec<u8>>, CodecError> {
        let mut items = Vec::new();
        match self {
            Request::Lstat { path } => push_path(&mut items, path)?,
            Request::Read { path, max } => {
                push_path(&mut items, path)?;
                push_number(&mut items, *max);
            }
            Request::List {
                path,
                max_entries,
                depth,
            } => {
                push_path(&mut items, path)?;
                push_number(&mut items, *max_entries);
                push_number(&mut items, *depth);
            }
            Request::Tree {
                max_entries,
                timeout_ms,
            } => {
                push_number(&mut items, *max_entries);
                push_number(&mut items, *timeout_ms);
            }
            Request::Create {
                path,
                bytes,
                mode,
                max_new_dirs,
            } => {
                push_path(&mut items, path)?;
                items.push(bytes.clone());
                push_number(&mut items, *mode);
                push_number(&mut items, *max_new_dirs);
            }
            Request::Replace {
                path,
                bytes,
                expect_sha,
            } => {
                push_path(&mut items, path)?;
                items.push(bytes.clone());
                push_digest(&mut items, expect_sha);
            }
            Request::Unlink { path, expect_sha } => {
                push_path(&mut items, path)?;
                push_digest(&mut items, expect_sha);
            }
            Request::Move {
                from,
                to,
                expect_sha,
                max_new_dirs,
            } => {
                push_path(&mut items, from)?;
                push_path(&mut items, to)?;
                push_digest(&mut items, expect_sha);
                push_number(&mut items, *max_new_dirs);
            }
            Request::Rmdir { path } => push_path(&mut items, path)?,
            Request::Ping { outside_probe_path } => {
                check_probe(outside_probe_path)?;
                items.push(outside_probe_path.clone().into_bytes());
            }
        }
        Ok(items)
    }
}

impl Reply {
    /// Encodes this reply as one bounded frame.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        match self {
            Reply::Err { code } => {
                let mut out = Vec::with_capacity(4 + code.as_str().len());
                out.extend_from_slice(b"err ");
                out.extend_from_slice(code.as_str().as_bytes());
                out.push(b'\n');
                Ok(out)
            }
            Reply::Ok { items } => {
                let count = items.len();
                let mut total = 3 + digits_of(count) + 1;
                for item in items {
                    total = total
                        .checked_add(digits_of(item.len()) + 1 + item.len())
                        .ok_or(CodecError::ResponseTooLarge { size: usize::MAX })?;
                }
                if total > MAX_RESPONSE_BYTES {
                    return Err(CodecError::ResponseTooLarge { size: total });
                }
                let mut out = Vec::with_capacity(total);
                out.extend_from_slice(b"ok ");
                out.extend_from_slice(count.to_string().as_bytes());
                out.push(b'\n');
                for item in items {
                    out.extend_from_slice(item.len().to_string().as_bytes());
                    out.push(b'\n');
                    out.extend_from_slice(item);
                }
                Ok(out)
            }
        }
    }

    /// Decodes one reply frame. The whole input must be exactly one reply.
    pub fn decode(input: &[u8]) -> Result<Reply, CodecError> {
        if input.len() > MAX_RESPONSE_BYTES {
            return Err(CodecError::ResponseTooLarge { size: input.len() });
        }
        let (head, mut pos) = next_line(input, 0).ok_or(CodecError::BadFrame)?;
        if let Some(count_text) = head.strip_prefix(b"ok ".as_slice()) {
            let count = parse_decimal(count_text).ok_or(CodecError::BadCount)?;
            let mut items = Vec::new();
            for _ in 0..count {
                let (item, after) = take_item(input, pos)?;
                items.push(item.to_vec());
                pos = after;
            }
            if pos != input.len() {
                return Err(CodecError::BadFrame);
            }
            return Ok(Reply::Ok { items });
        }
        if let Some(code_text) = head.strip_prefix(b"err ".as_slice()) {
            if pos != input.len() {
                return Err(CodecError::BadFrame);
            }
            let code = ErrorCode::parse(code_text).ok_or(CodecError::UnknownCode)?;
            return Ok(Reply::Err { code });
        }
        Err(CodecError::BadFrame)
    }
}

/// Reads one line ending in `\n` (the newline is not part of the line) and
/// returns it with the position just past the newline. Lines over
/// [`MAX_LINE_BYTES`] are refused, matching the stub's reader.
fn next_line(input: &[u8], pos: usize) -> Option<(&[u8], usize)> {
    let rest = input.get(pos..)?;
    let end = rest.iter().position(|&b| b == b'\n')?;
    if end > MAX_LINE_BYTES {
        return None;
    }
    Some((rest.get(..end)?, pos + end + 1))
}

/// Reads one framed item at `pos`: a length line, then exactly that many
/// bytes. Bodies are raw, so an item's length line glues straight onto the
/// previous body; lengths are always known, so parsing stays unambiguous.
/// Nothing is copied before the bytes are known to be present.
fn take_item(input: &[u8], pos: usize) -> Result<(&[u8], usize), CodecError> {
    let (length_line, body_start) = next_line(input, pos).ok_or(CodecError::BadFrame)?;
    let length = parse_decimal(length_line).ok_or(CodecError::BadLength)?;
    let body_end = body_start
        .checked_add(length)
        .ok_or(CodecError::ItemTooLarge)?;
    let bytes = input
        .get(body_start..body_end)
        .ok_or(CodecError::BadFrame)?;
    Ok((bytes, body_end))
}

/// Parses strict decimal text: one to eight digits, nothing else. `0` is a
/// valid length; callers decide whether zero is a valid count.
fn parse_decimal(text: &[u8]) -> Option<usize> {
    if text.is_empty() || text.len() > MAX_ITEM_LENGTH_DIGITS {
        return None;
    }
    let mut value: usize = 0;
    for &digit in text {
        if !digit.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add((digit - b'0') as usize)?;
    }
    Some(value)
}

/// Parses a numeric argument item: decimal digits only. The canonical encode
/// form is the shortest one, but any digit string that fits `u32` decodes.
fn parse_u32(text: &[u8]) -> Option<u32> {
    if text.is_empty() || text.len() > 10 {
        return None;
    }
    let mut value: u32 = 0;
    for &digit in text {
        if !digit.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((digit - b'0') as u32)?;
    }
    Some(value)
}

/// Bytes needed to render `value` in decimal.
fn digits_of(value: usize) -> usize {
    let mut digits = 1;
    let mut rest = value;
    while rest >= 10 {
        rest /= 10;
        digits += 1;
    }
    digits
}

/// Re-splits a path on `/` and refuses empty, `.` and `..` components.
fn check_components(path: &str) -> Result<(), CodecError> {
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(CodecError::PathComponent);
        }
    }
    Ok(())
}

/// A ping probe must be non-empty printable text with no NUL: it names a
/// path that must stay outside, so it is deliberately not lexically checked
/// like a workspace path.
fn check_probe(probe: &str) -> Result<(), CodecError> {
    if probe.is_empty() || probe.bytes().any(|b| b == 0 || b.is_ascii_control()) {
        return Err(CodecError::BadProbePath);
    }
    Ok(())
}

/// Appends a workspace path as one item, after the codec's own component
/// re-check.
fn push_path(items: &mut Vec<Vec<u8>>, path: &WorkspacePath) -> Result<(), CodecError> {
    check_components(path.as_str())?;
    items.push(path.as_str().as_bytes().to_vec());
    Ok(())
}

/// Appends a number as one item, in canonical decimal form.
fn push_number(items: &mut Vec<Vec<u8>>, value: u32) {
    items.push(value.to_string().into_bytes());
}

/// Appends a digest as one item, in canonical lowercase hex.
fn push_digest(items: &mut Vec<Vec<u8>>, digest: &Digest) {
    items.push(digest.to_string().into_bytes());
}

fn next_bytes<'a, I>(args: &mut I) -> Result<&'a [u8], CodecError>
where
    I: Iterator<Item = &'a [u8]>,
{
    args.next().ok_or(CodecError::BadFrame)
}

fn next_path<'a, I>(args: &mut I) -> Result<WorkspacePath, CodecError>
where
    I: Iterator<Item = &'a [u8]>,
{
    let text = std::str::from_utf8(next_bytes(args)?).map_err(|_| CodecError::BadUtf8)?;
    check_components(text)?;
    workspace_path(text).map_err(CodecError::BadPath)
}

fn next_u32<'a, I>(args: &mut I) -> Result<u32, CodecError>
where
    I: Iterator<Item = &'a [u8]>,
{
    parse_u32(next_bytes(args)?).ok_or(CodecError::BadNumber)
}

fn next_digest<'a, I>(args: &mut I) -> Result<Digest, CodecError>
where
    I: Iterator<Item = &'a [u8]>,
{
    let text = std::str::from_utf8(next_bytes(args)?).map_err(|_| CodecError::BadUtf8)?;
    Digest::from_str(text).map_err(|_| CodecError::BadDigest)
}

fn next_probe<'a, I>(args: &mut I) -> Result<String, CodecError>
where
    I: Iterator<Item = &'a [u8]>,
{
    let text = std::str::from_utf8(next_bytes(args)?).map_err(|_| CodecError::BadUtf8)?;
    check_probe(text)?;
    Ok(text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> WorkspacePath {
        workspace_path(value).unwrap()
    }

    fn digest(hex: &str) -> Digest {
        Digest::from_str(hex).unwrap()
    }

    fn items(values: &[&[u8]]) -> Vec<Vec<u8>> {
        values.iter().map(|v| v.to_vec()).collect()
    }

    /// Builds a wire frame by hand: `<op>\n<count>\n` then, per spec,
    /// `<length>\n<bytes>` glued back to back — exactly what
    /// [`Request::encode`] emits.
    fn frame(op: &str, count: &str, item_specs: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(op.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(count.as_bytes());
        out.push(b'\n');
        for (length, bytes) in item_specs {
            out.extend_from_slice(length.as_bytes());
            out.push(b'\n');
            out.extend_from_slice(bytes);
        }
        out
    }

    fn every_op() -> Vec<Request> {
        vec![
            Request::Lstat {
                path: path("a.txt"),
            },
            Request::Read {
                path: path("src/main.rs"),
                max: 4096,
            },
            Request::List {
                path: path("src"),
                max_entries: 100,
                depth: 2,
            },
            Request::Tree {
                max_entries: 10_000,
                timeout_ms: 500,
            },
            Request::Create {
                path: path("new/dir/out.bin"),
                bytes: vec![0, 1, 2, 255],
                mode: 0o644,
                max_new_dirs: 2,
            },
            Request::Replace {
                path: path("a.txt"),
                bytes: b"next contents".to_vec(),
                expect_sha: digest(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                ),
            },
            Request::Unlink {
                path: path("tmp/junk"),
                expect_sha: digest(
                    "0000000000000000000000000000000000000000000000000000000000000000",
                ),
            },
            Request::Move {
                from: path("a.txt"),
                to: path("b/c.txt"),
                expect_sha: digest(
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                ),
                max_new_dirs: 1,
            },
            Request::Rmdir { path: path("tmp") },
            Request::Ping {
                outside_probe_path: "../outside/secret".to_owned(),
            },
        ]
    }

    #[test]
    fn fileop_frame_round_trip_every_op() {
        for request in every_op() {
            let bytes = request.encode().unwrap();
            assert!(bytes.len() <= MAX_REQUEST_BYTES);
            assert_eq!(Request::decode(&bytes).unwrap(), request);
        }
    }

    #[test]
    fn fileop_frame_refuses_oversize_item() {
        // A length line of nine digits is unrepresentable, whatever follows.
        let nine_digits = frame("rmdir", "1", &[("999999999", b"")]);
        assert_eq!(Request::decode(&nine_digits), Err(CodecError::BadLength));

        // A length that fits eight digits but outruns the bytes present is
        // refused as a truncated frame, never read short.
        let short_body = frame("read", "2", &[("3", b"src"), ("8", b"409")]);
        assert_eq!(Request::decode(&short_body), Err(CodecError::BadFrame));

        // A request over the 8 MiB bound is refused, not truncated.
        let request = Request::Create {
            path: path("big.bin"),
            bytes: vec![0u8; MAX_REQUEST_BYTES],
            mode: 0o644,
            max_new_dirs: 0,
        };
        assert!(matches!(
            request.encode(),
            Err(CodecError::RequestTooLarge { .. })
        ));

        // A reply over its own bound is refused too.
        let reply = Reply::Ok {
            items: vec![vec![0u8; MAX_RESPONSE_BYTES]],
        };
        assert!(matches!(
            reply.encode(),
            Err(CodecError::ResponseTooLarge { .. })
        ));
    }

    #[test]
    fn fileop_frame_refuses_bad_count_and_non_decimal_length() {
        // Counts that are not 1-8 digit decimals, and the zero count no
        // request may carry.
        for count in ["", "x", "1x", "+1", "0", "123456789"] {
            let bytes = frame("rmdir", count, &[("3", b"tmp")]);
            assert_eq!(
                Request::decode(&bytes),
                Err(CodecError::BadCount),
                "count {count:?}"
            );
        }

        // Item lengths that are not 1-8 digit decimals.
        for length in ["", "x", "1x", "-3", "1e3", " 3"] {
            let bytes = frame("rmdir", "1", &[(length, b"tmp")]);
            assert_eq!(
                Request::decode(&bytes),
                Err(CodecError::BadLength),
                "length {length:?}"
            );
        }

        // A reply count has the same shape, except zero is legal there
        // (rmdir replies `ok 0`).
        let ok_zero = Reply::decode(b"ok 0\n").unwrap();
        assert_eq!(ok_zero, Reply::Ok { items: Vec::new() });
        for count in ["", "x", "1x", "+1", "123456789"] {
            let mut bytes = b"ok ".to_vec();
            bytes.extend_from_slice(count.as_bytes());
            bytes.push(b'\n');
            assert_eq!(Reply::decode(&bytes), Err(CodecError::BadCount));
        }
    }

    #[test]
    fn fileop_response_error_codes_round_trip() {
        let codes = [
            ErrorCode::NoEnt,
            ErrorCode::Symlink,
            ErrorCode::NotDir,
            ErrorCode::IsDir,
            ErrorCode::Exists,
            ErrorCode::TooBig,
            ErrorCode::Changed,
            ErrorCode::Denied,
            ErrorCode::NLink,
            ErrorCode::Io,
            ErrorCode::BadReq,
        ];
        for code in codes {
            let reply = Reply::Err { code };
            let bytes = reply.encode().unwrap();
            assert_eq!(Reply::decode(&bytes).unwrap(), reply);
        }

        // An `ok` reply's items come back byte-identical, including empty
        // and newline-bearing items (bodies are length-framed, not scanned).
        let reply = Reply::Ok {
            items: items(&[b"", b"type\ndir", b"4096"]),
        };
        let bytes = reply.encode().unwrap();
        assert_eq!(Reply::decode(&bytes).unwrap(), reply);

        // Unknown codes and malformed heads are refused.
        assert_eq!(
            Reply::decode(b"err vanished\n"),
            Err(CodecError::UnknownCode)
        );
        assert_eq!(Reply::decode(b"fine 2\n"), Err(CodecError::BadFrame));
        assert_eq!(Reply::decode(b"ok 1\n3\nab"), Err(CodecError::BadFrame));
        assert_eq!(
            Reply::decode(b"ok 1\n3\nabc\ntrailing"),
            Err(CodecError::BadFrame)
        );
    }

    #[test]
    fn fileop_path_must_be_workspace_relative_without_dot_components() {
        for refused in [
            "",
            "/etc/passwd",
            "..",
            "../outside",
            "a/../b",
            "a/./b",
            "./a",
            "a/",
            "//a",
            "a/..",
            "C:\\temp",
            "a\x01b",
        ] {
            let bytes = frame(
                "lstat",
                "1",
                &[(&refused.len().to_string(), refused.as_bytes())],
            );
            let err = Request::decode(&bytes).unwrap_err();
            assert!(
                matches!(err, CodecError::BadPath(_) | CodecError::PathComponent),
                "{refused:?} decoded as Ok: {err}"
            );
        }
    }

    #[test]
    fn fileop_codec_is_deterministic() {
        for request in every_op() {
            let first = request.encode().unwrap();
            let second = request.encode().unwrap();
            assert_eq!(first, second);
            // Re-encoding the decoded request reproduces the same bytes.
            let reencoded = Request::decode(&first).unwrap().encode().unwrap();
            assert_eq!(reencoded, first);
        }
        let reply = Reply::Ok {
            items: items(&[b"dir", b"12", b"420", b"3"]),
        };
        assert_eq!(reply.encode().unwrap(), reply.encode().unwrap());
        assert_eq!(Reply::decode(&reply.encode().unwrap()).unwrap(), reply);
    }
}
