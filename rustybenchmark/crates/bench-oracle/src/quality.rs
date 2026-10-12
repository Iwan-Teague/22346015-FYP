//! L4 `size`: how large is a solution relative to the reference (docs/03 §L4, `size.max_ratio_vs_reference`).
//!
//! Measured in **syntactic tokens**, not lines: line counts reward cramming and punish rustfmt,
//! and the model never sees our formatter. Comments and whitespace are not tokens. This is a
//! *measurement only*. docs/03 gives `max_ratio_vs_reference = 3.0` and a weight but no formula
//! from ratio to a `[0,1]` score, and inventing one would be exactly the kind of silent
//! definition REVIEW-6 keeps finding (OPEN-QUESTIONS Q33). Unlike the other L4 parts it is exact
//! and deterministic, so a server could re-derive it.

use proc_macro2::{TokenStream, TokenTree};

fn count(ts: TokenStream) -> usize {
    ts.into_iter()
        .map(|t| match t {
            // The two delimiters plus whatever is inside.
            TokenTree::Group(g) => 2 + count(g.stream()),
            _ => 1,
        })
        .sum()
}

/// Number of tokens in `source`, or `None` if it does not lex.
pub fn token_count(source: &str) -> Option<usize> {
    source.parse::<TokenStream>().ok().map(count)
}

/// `tokens(solution) / tokens(reference)`; `None` if either does not lex or the reference is empty.
pub fn size_ratio(solution: &str, reference: &str) -> Option<f64> {
    let (s, r) = (token_count(solution)?, token_count(reference)?);
    (r > 0).then(|| s as f64 / r as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_and_formatting_do_not_change_the_count() {
        let a = "fn f(a: i32) -> i32 { a + 1 }";
        let b = "// a comment\nfn f(\n    a: i32,\n) -> i32 {\n    /* more */ a\n        + 1\n}\n";
        // the trailing comma in the second is one extra token
        assert_eq!(token_count(b).unwrap(), token_count(a).unwrap() + 1);
        let c = "fn   f ( a : i32 ) ->\n i32 { a+1 }";
        assert_eq!(token_count(c), token_count(a));
    }

    #[test]
    fn groups_count_their_delimiters() {
        assert_eq!(token_count("()"), Some(2));
        assert_eq!(token_count("(a)"), Some(3));
        assert_eq!(token_count("[a, b]"), Some(5));
        assert_eq!(token_count(""), Some(0));
    }

    #[test]
    fn ratio_is_relative_to_the_reference() {
        assert_eq!(size_ratio("a b c d", "a b"), Some(2.0));
        assert_eq!(size_ratio("a", "a b"), Some(0.5));
        assert_eq!(size_ratio("a", ""), None, "an empty reference has no ratio");
        assert_eq!(size_ratio("fn (((", "a"), None);
    }
}
