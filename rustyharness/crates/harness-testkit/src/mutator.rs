//! Deterministic fuzz-style input generation (slice P-54): a seeded
//! xorshift generator and byte-mutation helpers. No `rand` and no other
//! third-party crate: the whole sequence is a pure function of the seed,
//! so a failing case reproduces from the fixed seed the test names and
//! the case index it prints. The helpers never panic and are bounded —
//! `mutate` performs at most `max_ops` operations on a copy of the input,
//! `garbage` produces exactly the length it is given, and [`case_count`]
//! caps what the environment can ask for — so a fuzz loop can only ever
//! terminate.
//!
//! The consumers are the parsers of untrusted bytes: a test feeds each
//! mutated or truncated input to its parser and asserts the parser's own
//! contract — no panic, a typed error or a value, within its documented
//! bounds.

/// The largest count [`case_count`] will return: a fuzz loop is bounded
/// even when the environment asks for the moon.
pub const MAX_CASES: usize = 1_000_000;

/// Bytes parsers trip over: NUL and other C0 controls, ESC, tab, newline,
/// CR, space, quote, apostrophe, slash, `<`/`>`, backslash, braces, DEL,
/// a UTF-8 lead byte and continuation byte, the UTF-8 BOM spelling, and
/// `0xFF` (never valid UTF-8). One random draw from here is worth several
/// uniform bytes.
pub const INTERESTING: &[u8] = &[
    0x00, 0x01, 0x09, 0x0A, 0x0D, 0x1B, 0x20, 0x22, 0x27, 0x2F, 0x3C, 0x3E, 0x5C, 0x7B, 0x7D, 0x7F,
    0x80, 0xC3, 0xEF, 0xBB, 0xBF, 0xFF,
];

/// A seeded xorshift64* generator (Vigna's). Deterministic: the same seed
/// always yields the same stream, on every platform, forever — that is
/// the whole point next to a general RNG.
pub struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    /// A generator for `seed`. A zero seed is remapped to a fixed
    /// non-zero state (xorshift is stuck at zero), so every seed —
    /// including the `0` a half-written test passes — yields a stream.
    pub fn new(seed: u64) -> Self {
        let state = if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        };
        Self { state }
    }

    /// The next 64 bits.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A value in `0..n` (`0` when `n` is `0`, so callers never branch on
    /// the emptiness first). The modulo skew of a 64-bit draw is beyond
    /// any case count a test runs.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            self.next_u64() as usize % n
        }
    }

    /// One byte.
    pub fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }
}

/// One draw from [`INTERESTING`] (or `?` if the table were empty, which
/// it is not — but no indexing means no panic, ever).
fn pick(rng: &mut XorShift64, table: &[u8]) -> u8 {
    table.get(rng.below(table.len())).copied().unwrap_or(b'?')
}

/// Mutate `bytes` with at most `max_ops` operations, drawn from `rng`:
/// a bit flip, a replacement with an [`INTERESTING`] byte, an insertion,
/// a deletion, a truncation, or a duplicated span. The input is copied,
/// never touched. Bounded: the result is at most `bytes.len() + max_ops`
/// bytes, and the call returns after `max_ops` operations whatever they
/// did.
pub fn mutate(bytes: &[u8], rng: &mut XorShift64, max_ops: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    for _ in 0..rng.below(max_ops.saturating_add(1)) {
        if out.is_empty() {
            // Nothing to hit yet: grow, so the loop stays productive.
            out.push(rng.byte());
            continue;
        }
        match rng.below(6) {
            // Flip one bit.
            0 => {
                let i = rng.below(out.len());
                if let Some(old) = out.get(i) {
                    let flipped = *old ^ (1u8 << rng.below(8));
                    if let Some(slot) = out.get_mut(i) {
                        *slot = flipped;
                    }
                }
            }
            // Replace one byte with an interesting one.
            1 => {
                let i = rng.below(out.len());
                if let Some(slot) = out.get_mut(i) {
                    *slot = pick(rng, INTERESTING);
                }
            }
            // Insert an interesting (or random) byte.
            2 => {
                let i = rng.below(out.len() + 1);
                let b = if rng.below(2) == 0 {
                    rng.byte()
                } else {
                    pick(rng, INTERESTING)
                };
                out.insert(i, b);
            }
            // Delete one byte.
            3 => {
                let i = rng.below(out.len());
                if i < out.len() {
                    out.remove(i);
                }
            }
            // Truncate to a prefix.
            4 => {
                let keep = rng.below(out.len());
                out.truncate(keep);
            }
            // Duplicate a short span taken from anywhere.
            _ => {
                let start = rng.below(out.len());
                let span: usize = rng.below(16) + 1;
                let copied: Vec<u8> = out.iter().skip(start).take(span).copied().collect();
                out.extend(copied);
            }
        }
    }
    out
}

/// `len` bytes of garbage: a mix of uniform and [`INTERESTING`] bytes.
/// Exactly `len` long, whatever the generator does.
pub fn garbage(rng: &mut XorShift64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|_| {
            if rng.below(2) == 0 {
                rng.byte()
            } else {
                pick(rng, INTERESTING)
            }
        })
        .collect()
}

/// How many cases a fuzz loop runs: the `RH_FUZZ_CASES` value when it is
/// set and parses as a non-zero count (capped at [`MAX_CASES`]), else
/// `default`. The regular tests pass a modest default (the gates' 2 000
/// per target); the `#[ignore]`d long forms pass a larger one and are
/// driven by setting `RH_FUZZ_CASES` (`cargo test -- --ignored`). A
/// variable that says something else — unparsable, or zero, which would
/// make the loop vacuous — leaves the default standing.
pub fn case_count(default: usize) -> usize {
    match std::env::var("RH_FUZZ_CASES") {
        Ok(raw) => raw
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|n| *n > 0)
            .map(|n| n.clamp(1, MAX_CASES))
            .unwrap_or(default),
        Err(_) => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutator_is_deterministic_for_a_seed() {
        // The byte stream: the same seed, twice, is the same stream; a
        // different seed is a different one.
        let mut a = XorShift64::new(0x5EED_0054);
        let mut b = XorShift64::new(0x5EED_0054);
        let mut c = XorShift64::new(0x5EED_0055);
        let (mut same, mut differs) = (true, false);
        for _ in 0..1_000 {
            let (x, y, z) = (a.next_u64(), b.next_u64(), c.next_u64());
            same &= x == y;
            differs |= x != z;
        }
        assert!(same);
        assert!(differs);
        // A zero seed is a stream too, not a fixed point.
        let mut z0 = XorShift64::new(0);
        let mut z1 = XorShift64::new(0);
        for _ in 0..64 {
            assert_eq!(z0.next_u64(), z1.next_u64());
        }

        // `mutate` and `garbage` are pure functions of (input, seed, ops).
        let input = b"<html><p>hello &amp; goodbye</p></html>".to_vec();
        let mut r1 = XorShift64::new(7);
        let mut r2 = XorShift64::new(7);
        assert_eq!(mutate(&input, &mut r1, 24), mutate(&input, &mut r2, 24));
        let mut g1 = XorShift64::new(9);
        let mut g2 = XorShift64::new(9);
        assert_eq!(garbage(&mut g1, 128), garbage(&mut g2, 128));

        // The seed also names the case: the case-th seed reproduces the
        // case-th mutation exactly.
        let mut again = XorShift64::new(0x5EED_0054 + 12);
        let first = mutate(&input, &mut again, 24);
        let mut replay = XorShift64::new(0x5EED_0054 + 12);
        assert_eq!(mutate(&input, &mut replay, 24), first);
    }

    #[test]
    fn mutator_stays_bounded_and_never_panics_on_degenerate_input() {
        let mut rng = XorShift64::new(3);
        // Empty and one-byte inputs survive every operation.
        assert!(mutate(&[], &mut rng, 64).len() <= 64);
        assert!(mutate(b"x", &mut rng, 64).len() <= 65);
        // The bound: len + at most one byte per operation.
        let big = vec![b'a'; 1_000];
        let out = mutate(&big, &mut rng, 32);
        assert!(out.len() <= big.len() + 32);
        // `garbage` is exactly as long as asked, including zero.
        assert_eq!(garbage(&mut rng, 0).len(), 0);
        assert_eq!(garbage(&mut rng, 500).len(), 500);
        // `below` answers in range, including the degenerate `0`.
        for n in [0usize, 1, 2, 7, 1_000] {
            assert!(rng.below(n) < n.max(1));
        }
    }

    #[test]
    fn case_count_defaults_and_follows_the_environment() {
        // The default stands unless the variable parses as a count.
        std::env::remove_var("RH_FUZZ_CASES");
        assert_eq!(case_count(2_000), 2_000);
        std::env::set_var("RH_FUZZ_CASES", "5");
        assert_eq!(case_count(2_000), 5);
        std::env::set_var("RH_FUZZ_CASES", "  77 ");
        assert_eq!(case_count(2_000), 77);
        std::env::set_var("RH_FUZZ_CASES", "not a number");
        assert_eq!(case_count(2_000), 2_000);
        std::env::set_var("RH_FUZZ_CASES", "0");
        assert_eq!(case_count(2_000), 2_000);
        // A count is capped, so the ignored long forms always terminate.
        std::env::set_var("RH_FUZZ_CASES", "99999999999");
        assert_eq!(case_count(2_000), MAX_CASES);
        std::env::remove_var("RH_FUZZ_CASES");
    }
}
