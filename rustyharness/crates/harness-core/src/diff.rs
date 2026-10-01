//! A bounded unified diff (P-16): pure text in, text out.
//!
//! [`unified`] renders the classic unified format (hunk headers
//! `@@ -a,b +c,d @@`, ` `-`/`+`/space body lines, the `\ No newline at
//! end of file` marker) with three bounds that keep it a preview, not a
//! dump: `context` lines around each hunk, a line-count cap that ends
//! the output with a `[N lines cut]` marker when cut (the marker is
//! never dropped), and an internal cap on the LCS table that falls back
//! to a plain whole-block replace for enormous inputs — still
//! deterministic, still bounded.
//!
//! Line endings are data here: lines are split on `\n` only and every
//! `\r` stays attached to its line, so CRLF text passes through the
//! diff byte-for-byte and a CRLF/LF difference shows as a change. No
//! I/O, no clock, no maps keyed by OS hashing: the same two inputs give
//! the same output every call.

/// Lines of context shown around each hunk when a caller has no
/// stronger opinion (P-16): 3, the unified-diff convention.
pub const DEFAULT_CONTEXT: usize = 3;

/// Most lines a preview diff shows when a caller has no stronger
/// opinion (P-16): 200. Past that the output ends with a
/// `[N lines cut]` marker.
pub const DEFAULT_MAX_LINES: usize = 200;

/// Most cells the LCS table may hold before the fallback (a plain
/// delete-all/add-all block over the differing middle) takes over. The
/// fallback is worse diffs, never wrong ones, and keeps the table
/// bounded whatever the inputs.
const DP_MAX_CELLS: u128 = 2_000_000;

/// The GNU marker for a file that does not end with a newline.
const NO_NL: &str = "\\ No newline at end of file";

/// One step of the edit script over the differing middle (the common
/// prefix and suffix are stripped first): keep, delete or insert a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    /// A line both sides share.
    Same,
    /// A line only the old side has.
    Del,
    /// A line only the new side has.
    Add,
}

/// Split `s` into lines: on `\n`, with a final newline ending the last
/// line rather than starting an empty one, and every `\r` left attached
/// to its line (so a CRLF line keeps its bytes). The flag says whether
/// `s` ended with a newline; the empty string has no lines and none.
fn lines_of(s: &str) -> (Vec<&str>, bool) {
    if s.is_empty() {
        return (Vec::new(), false);
    }
    let ends_nl = s.ends_with('\n');
    let mut lines: Vec<&str> = s.split('\n').collect();
    if ends_nl {
        lines.pop();
    }
    (lines, ends_nl)
}

/// The header range `start,count`, with the `,1` the format omits.
fn range(start: usize, count: usize) -> String {
    if count == 1 {
        format!("{start}")
    } else {
        format!("{start},{count}")
    }
}

/// The edit script over the middle lines `x` (old) and `y` (new): one
/// [`Op`] per line kept, deleted or inserted, in file order, deletions
/// before additions. A longest-common-subsequence dynamic program,
/// bounded by [`DP_MAX_CELLS`]; past the bound it degrades to deleting
/// all of `x` then adding all of `y`.
fn diff_ops(x: &[&str], y: &[&str]) -> Vec<Op> {
    let m = x.len();
    let n = y.len();
    if m == 0 {
        return vec![Op::Add; n];
    }
    if n == 0 {
        return vec![Op::Del; m];
    }
    if u128::from(m as u64) * u128::from(n as u64) > DP_MAX_CELLS {
        let mut ops = vec![Op::Del; m];
        ops.extend(vec![Op::Add; n]);
        return ops;
    }
    // lcs[i*w + j]: the LCS length of x's first i and y's first j lines.
    let w = n + 1;
    let mut t = vec![0u32; (m + 1) * w];
    for i in 1..=m {
        let xi = x.get(i - 1).copied().unwrap_or("");
        for j in 1..=n {
            let yj = y.get(j - 1).copied().unwrap_or("");
            let v = if xi == yj {
                t.get((i - 1) * w + (j - 1)).copied().unwrap_or(0) + 1
            } else {
                t.get((i - 1) * w + j)
                    .copied()
                    .unwrap_or(0)
                    .max(t.get(i * w + (j - 1)).copied().unwrap_or(0))
            };
            if let Some(slot) = t.get_mut(i * w + j) {
                *slot = v;
            }
        }
    }
    // Walk the table backwards; preferring an insert on a tie makes the
    // forward script list a block's deletions before its additions.
    let mut ops: Vec<Op> = Vec::with_capacity(m + n);
    let mut i = m;
    let mut j = n;
    while i > 0 || j > 0 {
        let same = i > 0 && j > 0 && x.get(i - 1) == y.get(j - 1);
        let add = j > 0
            && !same
            && (i == 0
                || t.get(i * w + (j - 1)).copied().unwrap_or(0)
                    >= t.get((i - 1) * w + j).copied().unwrap_or(0));
        if same {
            ops.push(Op::Same);
            i -= 1;
            j -= 1;
        } else if add {
            ops.push(Op::Add);
            j -= 1;
        } else {
            ops.push(Op::Del);
            i -= 1;
        }
    }
    ops.reverse();
    ops
}

/// Cap the collected diff lines at `max_lines`: everything when it fits,
/// else the first `max_lines - 1` lines and a `[N lines cut]` marker
/// that is never dropped (even at a cap of zero, which shows the marker
/// alone). Identical inputs never reach this with content, and an empty
/// diff is an empty string.
fn bound(lines: &[String], max_lines: usize) -> String {
    let mut out = String::new();
    if lines.len() <= max_lines {
        for l in lines {
            out.push_str(l);
            out.push('\n');
        }
        return out;
    }
    let keep = max_lines.saturating_sub(1);
    for l in lines.iter().take(keep) {
        out.push_str(l);
        out.push('\n');
    }
    out.push_str(&format!("[{} lines cut]\n", lines.len() - keep));
    out
}

/// The unified diff of `old` to `new`: at most `context` lines of
/// unchanged text around each hunk, at most `max_lines` lines of output
/// (a cut ends with a `[N lines cut]` marker). Identical inputs give an
/// empty string. Deterministic: no clock, no hashing, no randomness.
pub fn unified(old: &str, new: &str, context: usize, max_lines: usize) -> String {
    let (a, a_nl) = lines_of(old);
    let (b, b_nl) = lines_of(new);
    if a == b && a_nl == b_nl {
        return String::new();
    }
    // The common prefix and suffix are context only; diff the middles.
    let mut p = 0usize;
    while p < a.len() && p < b.len() && a.get(p) == b.get(p) {
        p += 1;
    }
    let mut sfx = 0usize;
    while sfx < a.len() - p
        && sfx < b.len() - p
        && a.get(a.len() - 1 - sfx) == b.get(b.len() - 1 - sfx)
    {
        sfx += 1;
    }
    let m = a.len() - p - sfx;
    let n = b.len() - p - sfx;
    if m == 0 && n == 0 {
        // Every line is shared; only the final newline differs, which
        // the format can only show by rewriting the last line.
        let last = match a.last() {
            Some(l) => *l,
            None => "",
        };
        let at = range(a.len(), 1);
        let mut lines = vec![format!("@@ -{at} +{at} @@"), format!("-{last}")];
        if !a_nl {
            lines.push(NO_NL.to_owned());
        }
        lines.push(format!("+{last}"));
        if !b_nl {
            lines.push(NO_NL.to_owned());
        }
        return bound(&lines, max_lines);
    }
    // The script over the whole file: the stripped prefix and suffix are
    // Same runs, so hunks can reach back into them for context lines.
    let mut ops: Vec<Op> = vec![Op::Same; p];
    ops.extend(diff_ops(
        &a.iter().skip(p).take(m).copied().collect::<Vec<_>>(),
        &b.iter().skip(p).take(n).copied().collect::<Vec<_>>(),
    ));
    ops.extend(vec![Op::Same; sfx]);
    if ops.iter().all(|op| *op == Op::Same) {
        return String::new();
    }
    // Line numbers: pos[k] is the (old, new) 1-based line op `k` sits on
    // (for a Del, the new line it sits before; for an Add, the old line
    // it sits after). The counters start at zero: the prefix's Same ops
    // walk them up through the prefix themselves.
    let mut pos: Vec<(usize, usize)> = Vec::with_capacity(ops.len());
    let (mut o, mut nw) = (0usize, 0usize);
    for op in ops.iter().copied() {
        match op {
            Op::Same => {
                o += 1;
                nw += 1;
            }
            Op::Del => o += 1,
            Op::Add => nw += 1,
        }
        pos.push((o, nw));
    }
    // A line enters a hunk when it sits within `context` of a change;
    // the included runs are the hunks (two changes at most 2*context
    // apart merge into one hunk, the unified convention).
    let len = ops.len();
    let mut dist: Vec<usize> = vec![usize::MAX; len];
    let mut last: Option<usize> = None;
    for (i, op) in ops.iter().copied().enumerate() {
        if op != Op::Same {
            last = Some(i);
        }
        if let (Some(l), Some(d)) = (last, dist.get_mut(i)) {
            *d = i - l;
        }
    }
    last = None;
    for i in (0..len).rev() {
        if ops.get(i).copied().unwrap_or(Op::Same) != Op::Same {
            last = Some(i);
        }
        if let (Some(l), Some(d)) = (last, dist.get_mut(i)) {
            if l - i < *d {
                *d = l - i;
            }
        }
    }
    let near = |i: usize| dist.get(i).copied().unwrap_or(usize::MAX) <= context;
    let mut lines: Vec<String> = Vec::new();
    let mut k = 0usize;
    while k < len {
        if !near(k) {
            k += 1;
            continue;
        }
        let lo = k;
        while k < len && near(k) {
            k += 1;
        }
        let hi = k - 1;
        let (mut old_start, mut new_start) = (0usize, 0usize);
        let (mut old_count, mut new_count) = (0usize, 0usize);
        for i in lo..=hi {
            let (ol, nl) = pos.get(i).copied().unwrap_or((p, p));
            match ops.get(i).copied().unwrap_or(Op::Same) {
                Op::Same => {
                    if old_start == 0 {
                        old_start = ol;
                    }
                    if new_start == 0 {
                        new_start = nl;
                    }
                    old_count += 1;
                    new_count += 1;
                }
                Op::Del => {
                    if old_start == 0 {
                        old_start = ol;
                    }
                    old_count += 1;
                }
                Op::Add => {
                    if new_start == 0 {
                        new_start = nl;
                    }
                    new_count += 1;
                }
            }
        }
        // A side with no lines in the hunk anchors on the line before
        // the change (0 when the change is at the very start).
        if old_start == 0 {
            old_start = pos.get(lo).copied().unwrap_or((p, p)).0;
        }
        if new_start == 0 {
            new_start = pos.get(lo).copied().unwrap_or((p, p)).1;
        }
        lines.push(format!(
            "@@ -{} +{} @@",
            range(old_start, old_count),
            range(new_start, new_count)
        ));
        for i in lo..=hi {
            let (ol, nl) = pos.get(i).copied().unwrap_or((p, p));
            match ops.get(i).copied().unwrap_or(Op::Same) {
                Op::Same => {
                    lines.push(format!(" {}", a.get(ol - 1).copied().unwrap_or("")));
                    if (ol == a.len() && !a_nl) || (nl == b.len() && !b_nl) {
                        lines.push(NO_NL.to_owned());
                    }
                }
                Op::Del => {
                    lines.push(format!("-{}", a.get(ol - 1).copied().unwrap_or("")));
                    if ol == a.len() && !a_nl {
                        lines.push(NO_NL.to_owned());
                    }
                }
                Op::Add => {
                    lines.push(format!("+{}", b.get(nl - 1).copied().unwrap_or("")));
                    if nl == b.len() && !b_nl {
                        lines.push(NO_NL.to_owned());
                    }
                }
            }
        }
    }
    bound(&lines, max_lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_identical_is_empty() {
        assert_eq!(unified("a\nb\n", "a\nb\n", 3, 200), "");
        assert_eq!(unified("", "", 3, 200), "");
        assert_eq!(unified("same", "same", 3, 200), "");
    }

    #[test]
    fn diff_single_line_change() {
        assert_eq!(
            unified("a\nb\nc\n", "a\nx\nc\n", 3, 200),
            "@@ -1,3 +1,3 @@\n a\n-b\n+x\n c\n"
        );
    }

    #[test]
    fn diff_crlf_preserved_marked() {
        let d = unified("alpha\r\nbeta\r\n", "alpha\r\nBETA\r\n", 3, 200);
        assert!(d.contains(" alpha\r\n"), "{d}");
        assert!(d.contains("-beta\r\n"), "{d}");
        assert!(d.contains("+BETA\r\n"), "{d}");
        // A CRLF-vs-LF difference is a change in every line it touches,
        // \r and all; both files still end with their newline.
        let d = unified("a\r\n", "a\n", 3, 200);
        assert_eq!(d, "@@ -1 +1 @@\n-a\r\n+a\n");
    }

    #[test]
    fn diff_bounded_marks_cut() {
        let old: String = (1..=40).map(|i| format!("l{i}\n")).collect();
        let new: String = (1..=40)
            .map(|i| {
                if i == 30 {
                    "CHANGED\n".to_owned()
                } else {
                    format!("l{i}\n")
                }
            })
            .collect();
        let d = unified(&old, &new, 3, 5);
        let shown: Vec<&str> = d.lines().collect();
        assert_eq!(shown.len(), 5, "{d}");
        assert_eq!(shown.last().copied().unwrap_or(""), "[5 lines cut]");
        assert!(d.starts_with("@@ -27,7 +27,7 @@\n"), "{d}");
        // A cap of zero shows the marker alone; it is never dropped.
        let d = unified(&old, &new, 3, 0);
        assert_eq!(d, "[9 lines cut]\n");
    }

    #[test]
    fn diff_deterministic() {
        let (a, b) = ("x\ny\nz\n", "x\nY\nw\nz\n");
        assert_eq!(unified(a, b, 3, 200), unified(a, b, 3, 200));
        assert_eq!(
            unified(a, b, 3, 200),
            "@@ -1,3 +1,4 @@\n x\n-y\n+Y\n+w\n z\n"
        );
        // Two separate changes two hunks; one change, whatever the
        // middle size, is the same every call.
        let (a, b) = (
            "1\n2\n3\n4\n5\n6\n7\n8\n9\n",
            "1\n2\ntwo\n4\n5\n6\n7\neight\n9\n",
        );
        assert_eq!(unified(a, b, 3, 200), unified(a, b, 3, 200));
        assert_eq!(
            unified(a, b, 1, 200),
            "@@ -2,3 +2,3 @@\n 2\n-3\n+two\n 4\n@@ -7,3 +7,3 @@\n 7\n-8\n+eight\n 9\n"
        );
    }

    #[test]
    fn diff_marks_missing_final_newline() {
        assert_eq!(
            unified("a\nb", "a\nc", 3, 200),
            "@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+c\n\\ No newline at end of file\n"
        );
        assert_eq!(
            unified("a\nb", "a\nb\n", 3, 200),
            "@@ -2 +2 @@\n-b\n\\ No newline at end of file\n+b\n"
        );
        assert_eq!(unified("", "x\n", 3, 200), "@@ -0,0 +1 @@\n+x\n");
        assert_eq!(unified("x\n", "", 3, 200), "@@ -1 +0,0 @@\n-x\n");
    }
}
