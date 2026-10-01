//! P-08 fix-up: the wall-clock pin on the glob matcher's linearity. The
//! matcher itself is pure (it lives in `harness-core`, which may not so
//! much as name `Instant`), so the timing assertion lives here, against the
//! unchanged `harness_tools::glob` re-export: a pattern that is exponential
//! for a naive matcher over a long non-matching path finishes at once.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::time::{Duration, Instant};

use harness_tools::glob::Glob;

fn m(p: &str, path: &str) -> bool {
    Glob::new(p).unwrap().matches(path)
}

#[test]
fn hostile_glob_patterns_match_in_bounded_time() {
    let p = format!("{}b", "*a".repeat(40));
    let path = "a".repeat(200);
    let t = Instant::now();
    assert!(!m(&p, &path));
    let q = format!("{}/x", vec!["**"; 20].join("/"));
    assert!(!m(&q, "a/".repeat(90).trim_end_matches('/')));
    assert!(t.elapsed() < Duration::from_secs(2));
}
