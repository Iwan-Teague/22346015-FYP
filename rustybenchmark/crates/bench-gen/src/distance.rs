//! Instance-distance measurement — the anti-memorisation check.
//!
//! Two instances of a family should not be cosmetic twins (same structure,
//! renamed): a model that memorised one would then trivially solve the other.
//! For a parametric family the distance is measured on **prompt + skeleton** —
//! what the model actually sees (docs/02, REVIEW-4 R4-S4), not the reference.
//!
//! The metric is normalised token-shingle Jaccard distance: split into
//! alphanumeric tokens, take the set of overlapping `k`-token shingles, and
//! report `1 − |A∩B| / |A∪B|`. 0 = identical structure, 1 = disjoint. Cheap
//! (linear to build, set-sized to compare) and robust — a pure rename shifts
//! only the few shingles that touch the renamed identifier.

use std::collections::HashSet;

/// Tokenise into maximal alphanumeric (plus `_`) runs, lowercased.
fn tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        if c.is_alphanumeric() || c == '_' {
            cur.push(c.to_ascii_lowercase());
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn shingles(s: &str, k: usize) -> HashSet<String> {
    let t = tokens(s);
    if t.len() < k {
        return t.into_iter().collect();
    }
    t.windows(k).map(|w| w.join(" ")).collect()
}

/// Normalised token-shingle Jaccard distance in `[0, 1]`.
pub fn shingle_distance(a: &str, b: &str, k: usize) -> f64 {
    let sa = shingles(a, k);
    let sb = shingles(b, k);
    if sa.is_empty() && sb.is_empty() {
        return 0.0;
    }
    let inter = sa.intersection(&sb).count() as f64;
    let union = sa.union(&sb).count() as f64;
    1.0 - inter / union
}

/// The default shingle size for instance distance.
pub const K: usize = 3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_is_zero() {
        assert_eq!(
            shingle_distance("the quick brown fox", "the quick brown fox", 3),
            0.0
        );
    }

    #[test]
    fn disjoint_is_one() {
        assert_eq!(
            shingle_distance("alpha beta gamma delta", "one two three four", 3),
            1.0
        );
    }

    #[test]
    fn pure_rename_is_small_but_nonzero() {
        // Same structure, one identifier changed, at realistic prompt length: a
        // near-twin. The renamed token touches only a few of the many shingles.
        let shared = "for each consecutive non overlapping window of width w in v reverse the \
                      elements of the window in place any trailing elements that do not fill a \
                      full window are left untouched return the number of full windows processed \
                      operate in place do not allocate a second copy of the data do not use unsafe";
        let a = format!("implement the function reverse_windows {shared}");
        let b = format!("implement the function flip_windows {shared}");
        let d = shingle_distance(&a, &b, 3);
        assert!(d > 0.0 && d < 0.2, "rename distance should be small: {d}");
    }

    #[test]
    fn tokenisation_is_case_insensitive_and_punctuation_splitting() {
        // Case and punctuation differences vanish; only tokens matter.
        assert_eq!(
            shingle_distance("Hello, World! foo_bar", "hello world foo_bar", 1),
            0.0
        );
        // Underscore is a token character: foo_bar != foobar.
        assert!(shingle_distance("foo_bar", "foobar", 1) > 0.0);
    }

    #[test]
    fn empty_inputs_are_defined_not_panicking() {
        assert_eq!(shingle_distance("", "", 3), 0.0);
        assert_eq!(shingle_distance("", "some text", 3), 1.0);
        assert_eq!(shingle_distance("some text", "", 3), 1.0);
    }

    #[test]
    fn k_larger_than_token_count_falls_back_to_single_tokens() {
        // With fewer tokens than k the shingles ARE the tokens, so identical
        // short inputs still measure as identical.
        let a = "one two";
        let b = "one two three";
        let d = shingle_distance(a, b, 5);
        assert!(d > 0.0 && d < 1.0, "partial overlap expected: {d}");
    }

    #[test]
    fn distance_is_symmetric() {
        let a = "reverse every window of width two in place";
        let b = "rotate the whole slice left by one position instead";
        let d1 = shingle_distance(a, b, 3);
        let d2 = shingle_distance(b, a, 3);
        assert!((d1 - d2).abs() < 1e-12);
    }

    #[test]
    fn different_logic_is_large() {
        let a = "reverse the elements of the window in place and count";
        let b = "rotate the elements of the window left by two positions wrapping";
        assert!(shingle_distance(a, b, 3) > 0.5);
    }
}
