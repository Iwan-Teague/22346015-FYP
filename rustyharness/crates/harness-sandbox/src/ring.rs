//! Stream rings and cursor arithmetic for live confined children (§3.2, §4.2).
//!
//! Backend-neutral by design: the macOS spawner uses it today and the Linux
//! backend reuses the same window arithmetic without touching a process API.

use harness_core::{Digest, Sha256Stream};

/// How many trailing stderr bytes the ring keeps verbatim so the exit report
/// stays parseable even when the ring itself has long since wrapped.
pub const TAIL_BYTES: usize = 4096;

/// Which output stream a read addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stream {
    /// The child's stdout.
    Out,
    /// The child's stderr.
    Err,
}

/// Where a read starts from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Continue after `since`; delivers up to `cap` bytes.
    Next,
    /// Deliver the last `cap` bytes of the stream; jumps forward and counts
    /// the jumped bytes as `skipped`.
    Tail,
}

/// The plan for one read, computed from counts before any bytes move (§3.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Window {
    /// First absolute offset delivered.
    pub from: u64,
    /// One past the last offset delivered; the caller's next cursor.
    pub to: u64,
    /// Bytes between `since` and `from` that the ring already dropped.
    pub dropped: u64,
    /// Bytes between `from` and `to` that a tail read jumped over.
    pub skipped: u64,
}

/// One delivered read: a byte slice plus the cursor bookkeeping around it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Chunk {
    /// First absolute offset of `bytes`.
    pub from: u64,
    /// One past the last delivered offset; pass it as `since` next read.
    pub to: u64,
    /// Bytes the ring had already dropped before `from`.
    pub dropped: u64,
    /// Bytes a tail read jumped over inside the window.
    pub skipped: u64,
    /// The delivered bytes.
    pub bytes: Vec<u8>,
}

/// Per-stream byte totals with the running SHA-256 over everything ever
/// written, retained bytes or not.
#[derive(Clone, Debug)]
pub struct StreamTotals {
    /// Total stdout bytes and the digest over all of them.
    pub out_total: u64,
    /// Running SHA-256 over every stdout byte ever written.
    pub out_sha: Digest,
    /// Total stderr bytes and the digest over all of them.
    pub err_total: u64,
    /// Running SHA-256 over every stderr byte ever written.
    pub err_sha: Digest,
}

/// Plan one read against a stream of `total` bytes kept in a ring of
/// `ring_bytes` capacity (§3.2). Pure arithmetic; no bytes are touched.
///
/// A `since` past the end is clamped to `total` (nothing beyond the end can
/// be delivered), which reads as an empty window with no dropped bytes.
#[must_use]
pub fn window(total: u64, ring_bytes: u64, since: u64, cap: u64, mode: Mode) -> Window {
    let since = since.min(total);
    let ring_start = total.saturating_sub(ring_bytes.min(total));
    let from0 = since.max(ring_start);
    let dropped = from0.saturating_sub(since);
    let (from, to, skipped) = match mode {
        Mode::Next => (from0, total.min(from0.saturating_add(cap)), 0),
        Mode::Tail => {
            let to = total;
            let from = from0.max(to.saturating_sub(cap));
            (from, to, from.saturating_sub(from0))
        }
    };
    Window {
        from,
        to,
        dropped,
        skipped,
    }
}

/// Move a slice end back onto a UTF-8 char boundary (at most 3 bytes) so a
/// text cursor never splits a character. Returns the new end offset.
pub(crate) fn align_to_char_boundary(bytes: &mut Vec<u8>, from: u64) -> u64 {
    let mut keep = bytes.len();
    while bytes.len() - keep < 3 && keep > 0 {
        match bytes.get(keep) {
            // A continuation byte means `keep` sits inside a character.
            Some(b) if b & 0b1100_0000 == 0b1000_0000 => keep -= 1,
            _ => break,
        }
    }
    if keep < bytes.len() {
        bytes.truncate(keep);
    }
    from + keep as u64
}

/// Copies `data` into `buf` starting at `start`, wrapping around the end.
fn put(buf: &mut [u8], start: usize, data: &[u8]) {
    let first = data.len().min(buf.len() - start);
    if let (Some(dst), Some(src)) = (buf.get_mut(start..start + first), data.get(..first)) {
        dst.copy_from_slice(src);
    }
    if first < data.len() {
        if let (Some(dst), Some(src)) = (buf.get_mut(..data.len() - first), data.get(first..)) {
            dst.copy_from_slice(src);
        }
    }
}

/// A bounded circular byte ring with a monotonic byte count, a running
/// SHA-256 over every byte ever pushed, and a small verbatim tail for report
/// parsing. The ring forgets its oldest bytes once `cap` is exceeded; the
/// count and digest never forget.
pub struct Ring {
    cap: usize,
    buf: Vec<u8>,
    head: usize,
    len: usize,
    total: u64,
    sha: Sha256Stream,
    tail: Vec<u8>,
}

impl Ring {
    /// A ring holding the last `cap` bytes (at least one) plus the verbatim
    /// [`TAIL_BYTES`] tail.
    #[must_use]
    pub fn new(cap: u64) -> Self {
        let cap = cap.max(1).min(usize::MAX as u64) as usize;
        Self {
            cap,
            buf: vec![0u8; cap],
            head: 0,
            len: 0,
            total: 0,
            sha: Sha256Stream::default(),
            tail: Vec::new(),
        }
    }

    /// Absolute offset of the oldest byte still retained.
    #[must_use]
    fn ring_start(&self) -> u64 {
        self.total.saturating_sub(self.len as u64)
    }

    /// Absorb bytes: count and digest every one, keep the tail verbatim,
    /// and retain the last `cap` bytes in the circular buffer.
    pub fn push(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        self.total = self.total.saturating_add(data.len() as u64);
        self.sha.update(data);
        let excess = self.tail.len() + data.len();
        if excess > TAIL_BYTES {
            let cut = excess - TAIL_BYTES;
            let cut = cut.min(self.tail.len());
            self.tail.drain(..cut);
        }
        self.tail.extend_from_slice(data);

        // More data than the whole ring: only the last `cap` bytes survive.
        let data = if data.len() >= self.cap {
            self.head = 0;
            self.len = 0;
            data.get(data.len() - self.cap..).unwrap_or(&[])
        } else {
            data
        };
        let pos = (self.head + self.len) % self.cap;
        let free = self.cap - self.len;
        let fill = data.len().min(free);
        if fill > 0 {
            let part = data.get(..fill).unwrap_or(&[]);
            put(&mut self.buf, pos, part);
            self.len += fill;
        }
        let rest = data.get(fill..).unwrap_or(&[]);
        if !rest.is_empty() {
            put(&mut self.buf, self.head, rest);
            self.head = (self.head + rest.len()) % self.cap;
        }
    }

    /// Total bytes ever pushed, retained or not.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total
    }

    /// The verbatim trailing bytes (at most [`TAIL_BYTES`]).
    #[must_use]
    pub fn tail(&self) -> &[u8] {
        &self.tail
    }

    /// SHA-256 over every byte ever pushed.
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.sha.clone().finish()
    }

    /// The oldest retained bytes: everything between `ring_start` and
    /// `total`. For a ring that has never wrapped this is the whole stream.
    #[must_use]
    pub fn head(&self) -> Vec<u8> {
        self.range(self.ring_start(), self.total)
    }

    /// Absolute-offset slice `[from, to)`, clamped to what the ring still
    /// holds. `from > to` yields an empty vector.
    #[must_use]
    pub fn range(&self, from: u64, to: u64) -> Vec<u8> {
        let start = self.ring_start();
        let lo = from.max(start).min(self.total);
        let hi = to.max(lo).min(self.total);
        let mut out = Vec::with_capacity((hi - lo) as usize);
        let mut pos = (self.head + (lo - start) as usize) % self.cap;
        let mut left = (hi - lo) as usize;
        while left > 0 {
            let run = (self.cap - pos).min(left);
            if let Some(part) = self.buf.get(pos..pos + run) {
                out.extend_from_slice(part);
            }
            pos = 0;
            left -= run;
        }
        out
    }

    /// Plan and deliver one read (§3.2): window arithmetic, a byte slice, and
    /// a UTF-8 aligned cursor. `limit` (the stderr report boundary) caps `to`
    /// before delivery so a finished stub's exit report never passes through.
    #[must_use]
    pub fn chunk_until(&self, since: u64, cap: usize, mode: Mode, limit: Option<u64>) -> Chunk {
        let mut w = window(self.total, self.cap as u64, since, cap as u64, mode);
        if let Some(limit) = limit {
            w.to = w.to.min(limit);
        }
        let mut bytes = self.range(w.from, w.to);
        let to = align_to_char_boundary(&mut bytes, w.from);
        Chunk {
            from: w.from,
            to,
            dropped: w.dropped,
            skipped: w.skipped,
            bytes,
        }
    }

    /// [`Ring::chunk_until`] with no report limit.
    #[must_use]
    pub fn chunk(&self, since: u64, cap: usize, mode: Mode) -> Chunk {
        self.chunk_until(since, cap, mode, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_cursor_arithmetic_next_and_tail() {
        // `since` older than the ring: everything before ring_start is dropped.
        let w = window(1000, 100, 0, 50, Mode::Next);
        assert_eq!((w.from, w.to, w.dropped, w.skipped), (900, 950, 900, 0));
        // Tail mode ends at total and skips forward within the window.
        let w = window(1000, 100, 0, 50, Mode::Tail);
        assert_eq!((w.from, w.to, w.dropped, w.skipped), (950, 1000, 900, 50));
        // A cursor near the end reads the short remainder.
        let w = window(1000, 100, 990, 50, Mode::Next);
        assert_eq!((w.from, w.to, w.dropped, w.skipped), (990, 1000, 0, 0));
        // A cursor past the end is clamped to an empty window.
        let w = window(10, 100, 99, 5, Mode::Next);
        assert_eq!((w.from, w.to, w.dropped, w.skipped), (10, 10, 0, 0));
        // A zero cap delivers nothing but keeps the cursor where it was.
        let w = window(10, 100, 3, 0, Mode::Next);
        assert_eq!((w.from, w.to, w.dropped, w.skipped), (3, 3, 0, 0));
        // An empty stream yields an empty window at zero.
        let w = window(0, 100, 0, 50, Mode::Tail);
        assert_eq!((w.from, w.to, w.dropped, w.skipped), (0, 0, 0, 0));

        // The same arithmetic through a live ring: 25 bytes in a 10-byte ring.
        let mut ring = Ring::new(10);
        ring.push(b"0123456789");
        ring.push(b"abcdefghijklnop"); // 15 more bytes: total 25
        assert_eq!(ring.total(), 25);
        let c = ring.chunk(0, 5, Mode::Next);
        assert_eq!(c.from, 15, "bytes 0..15 were overwritten");
        assert_eq!(c.dropped, 15);
        assert_eq!(c.to, 20);
        assert_eq!(c.bytes, b"fghij");
        let c = ring.chunk(20, 100, Mode::Next);
        assert_eq!((c.from, c.to), (20, 25));
        assert_eq!(c.bytes, b"klnop");
        let c = ring.chunk(0, 5, Mode::Tail);
        assert_eq!((c.from, c.to, c.skipped, c.dropped), (20, 25, 5, 15));
        assert_eq!(c.bytes, b"klnop");
        // A full drain in next mode reaches exactly the end.
        let mut c = ring.chunk(15, 100, Mode::Next);
        assert_eq!((c.from, c.to), (15, 25));
        // ...and the delivered cursor is where the next read resumes.
        c = ring.chunk(c.to, 100, Mode::Next);
        assert!(c.bytes.is_empty());
        assert_eq!(c.from, 25);
    }

    #[test]
    fn ring_drop_counts_overwritten_bytes() {
        let mut ring = Ring::new(8);
        ring.push(b"0123456789"); // 10 bytes through an 8-byte ring
        assert_eq!(ring.total(), 10, "the count never forgets");
        assert_eq!(
            ring.head(),
            b"23456789",
            "the oldest bytes are dropped first"
        );
        let c = ring.chunk(0, 100, Mode::Next);
        assert_eq!(c.dropped, 2, "two bytes fell out of the ring");
        ring.push(b"abc");
        assert_eq!(ring.total(), 13);
        assert_eq!(ring.head(), b"56789abc");
        assert_eq!(ring.range(11, 13), b"bc", "absolute offsets stay stable");
        // One push larger than the ring keeps only the ring's worth.
        ring.push(b"XY");
        let big = vec![b'.'; 20];
        ring.push(&big);
        assert_eq!(ring.total(), 35);
        assert_eq!(
            ring.head(),
            &big[12..],
            "the last cap bytes survive a flood"
        );
        // The tail keeps just the last TAIL_BYTES verbatim.
        let mut all = b"0123456789abcXY".to_vec();
        all.extend_from_slice(&big);
        assert_eq!(ring.tail().len(), TAIL_BYTES.min(35));
        assert_eq!(ring.tail(), &all[all.len() - TAIL_BYTES.min(35)..]);
    }

    #[test]
    fn ring_stream_sha_covers_every_byte() {
        // Odd chunk sizes so wrap boundaries land mid-push.
        let mut ring = Ring::new(64);
        let mut all: Vec<u8> = Vec::new();
        let mut n = 0u32;
        while n < 10_000 {
            let len = (n % 13 + 1) as usize;
            let part: Vec<u8> = (n..n + len as u32).map(|i| (i % 251) as u8).collect();
            ring.push(&part);
            all.extend_from_slice(&part);
            n += len as u32;
        }
        assert_eq!(ring.total(), all.len() as u64);
        assert_eq!(ring.digest(), harness_core::sha256(&all));
        assert_eq!(ring.head().len(), 64, "the ring stays bounded");
        assert_eq!(ring.tail().len(), TAIL_BYTES);
        assert_eq!(ring.tail(), &all[all.len() - TAIL_BYTES..]);
        // An empty ring hashes to the digest of nothing at all.
        assert_eq!(Ring::new(4).digest(), harness_core::sha256(&[]));
    }
}
