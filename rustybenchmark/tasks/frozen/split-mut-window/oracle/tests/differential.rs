//! L2 differential sub-oracle: compare the candidate against a hidden reference
//! implementation over many generated inputs. This catches a solution that
//! passes every visible example test and is still wrong — the failure mode the
//! example tests structurally cannot see (docs/03-oracle.md). No external crate:
//! a small seeded LCG keeps grading deterministic and offline.

use split_mut_window::reverse_windows;

/// Known-correct reference. The candidate must match it exactly.
fn reference(v: &mut [i64], w: usize) -> usize {
    if w == 0 {
        return 0;
    }
    let mut n = 0;
    let mut i = 0;
    while i + w <= v.len() {
        v[i..i + w].reverse();
        n += 1;
        i += w;
    }
    n
}

#[test]
fn differential_vs_reference() {
    // Deterministic LCG (Numerical Recipes constants).
    let mut state: u64 = 0x9E3779B97F4A7C15;
    let mut next = || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (state >> 33) as u64
    };

    for _ in 0..3000 {
        let len = (next() % 17) as usize; // 0..=16
        let w = (next() % 6) as usize; // 0..=5, so widths >= 3 ARE exercised
        let mut a: Vec<i64> = (0..len).map(|_| (next() % 100) as i64 - 50).collect();
        let mut b = a.clone();

        let ra = reverse_windows(&mut a, w);
        let rb = reference(&mut b, w);

        assert_eq!(rb, ra, "count mismatch for len={len} w={w}");
        assert_eq!(b, a, "array mismatch for len={len} w={w}");
    }
}
