//! Terminal-safe display of untrusted text (design §7.1 display paths).
//!
//! The REPL, the event stream and streaming model output print text that
//! crossed a trust boundary: model replies, tool output, file names. A raw
//! control character in such text can redraw the terminal (CSI/OSC), forge
//! a harness-looking line (CR, newline in a one-line field) or reorder and
//! hide what the user reads (bidi overrides, zero-width characters). This
//! module is the ONE escaper every such display path runs text through
//! before printing. Pure: it prints nothing itself — the caller renders
//! the returned string.
//!
//! - [`escape_for_terminal`]: the per-character rule, unbounded.
//! - [`sanitize_for_terminal_bounded`]: escape plus a hard bound on the
//!   output, with a visible `[N bytes cut]` marker when text was left out.
//! - [`sanitize_for_terminal`]: the same at [`DISPLAY_MAX_BYTES`].
//!
//! Two properties the display contract (§7.1) leans on:
//!
//! - **Idempotent.** Sanitizing sanitizer output again returns it
//!   unchanged, so streamed chunks and re-rendered journal text can never
//!   be double-escaped into noise. The escape therefore never doubles a
//!   backslash that already opens an escape sequence it itself produces
//!   (`\\`, `\u{HEX}`); every other lone backslash is doubled, so the
//!   reversible spellings the journal and JSON write (`\n`, `\r`,
//!   `\u001b`, `\\`) still round-trip through display doubled, exactly as
//!   the approval rendering has always shown them.
//! - **Fail visible, never silent.** Nothing is deleted: a control, bidi
//!   or zero-width character becomes its `\u{HEX}` spelling (the journal's
//!   reversible escape, §7.1), so what the model sent stays on screen,
//!   inert. A CSI or OSC sequence is neutralised the same way — its ESC
//!   (or single-byte C1 introducer) is escaped, and the rest of the
//!   sequence survives as ordinary visible text; a truncated sequence at
//!   the end of a chunk is handled by the same rule, with no sequence
//!   state carried across calls.

use std::fmt::Write as _;

/// The default output bound of [`sanitize_for_terminal`], in bytes.
pub const DISPLAY_MAX_BYTES: usize = 8192;

/// Whether the sanitized text must stay a single line.
///
/// `Line` is for prompts, labels, approval requests and status lines: a
/// raw newline would let untrusted text forge the lines beneath it, so
/// `\n` is escaped like any other control. `Block` is for multi-line
/// output (tool results, model replies): `\n` and `\t` are kept, so the
/// shape of the text survives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisplayMode {
    /// Single-line safe: `\n` becomes `\u{A}`; `\t` is kept.
    Line,
    /// Multi-line safe: `\n` and `\t` are kept as themselves.
    Block,
}

/// Untrusted text made safe to print to a terminal (§7.1), with no bound
/// on the output. Every control character (ESC included, so a CSI or OSC
/// sequence is inert), DEL, C1 byte, line or paragraph separator, and
/// zero-width or bidi code point becomes `\u{HEX}`; in [`DisplayMode::Line`]
/// a raw `\n` becomes `\u{A}` as well. `\n` and `\t` are kept in
/// [`DisplayMode::Block`], `\t` in both modes.
pub fn escape_for_terminal(s: &str, mode: DisplayMode) -> String {
    let mut out = String::new();
    push_escaped(s, mode, &mut out, None);
    out
}

/// [`escape_for_terminal`] with a hard bound: the returned string is at
/// most `max` bytes. When input did not fit, the output ends with
/// `[N bytes cut]`, where `N` is how many bytes of the input are not
/// represented. The marker is never dropped, so with a `max` too small to
/// hold it the marker alone is returned (and may itself exceed `max`).
pub fn sanitize_for_terminal_bounded(s: &str, mode: DisplayMode, max: usize) -> String {
    // Whole-fit first: an output within the bound is a fixed point, which
    // is what makes the bounded form idempotent too.
    let escaped = escape_for_terminal(s, mode);
    if escaped.len() <= max {
        return escaped;
    }
    // Reserve room for the worst-case marker, so body + marker never
    // exceeds `max` and a re-run takes the whole-fit branch above.
    let budget = max.saturating_sub(cut_marker_max(s.len()));
    let mut out = String::new();
    let consumed = push_escaped(s, mode, &mut out, Some(budget));
    let cut = s.len() - consumed;
    let _ = write!(out, "[{cut} bytes cut]");
    out
}

/// [`sanitize_for_terminal_bounded`] at [`DISPLAY_MAX_BYTES`].
pub fn sanitize_for_terminal(s: &str, mode: DisplayMode) -> String {
    sanitize_for_terminal_bounded(s, mode, DISPLAY_MAX_BYTES)
}

/// Length of the longest marker this input could produce:
/// `[` + digits + ` bytes cut]` with the cut bounded by the input length.
fn cut_marker_max(input_len: usize) -> usize {
    digits(input_len) + 12
}

fn digits(mut n: usize) -> usize {
    let mut d = 1;
    while n >= 10 {
        d += 1;
        n /= 10;
    }
    d
}

/// Walk `s` once, appending the escaped form to `out`. With a `budget`,
/// stop before the first escape group that would push `out` past it, and
/// return the number of input bytes represented so far; without one,
/// everything is emitted and the input length is returned.
fn push_escaped(s: &str, mode: DisplayMode, out: &mut String, budget: Option<usize>) -> usize {
    fn fits(out_len: usize, group: &str, budget: Option<usize>) -> bool {
        match budget {
            Some(b) => out_len + group.len() <= b,
            None => true,
        }
    }
    let mut it = s.char_indices().peekable();
    while let Some((at, c)) = it.next() {
        let group = match c {
            // A backslash doubles unless it already opens an escape
            // sequence this escaper produces (`\\`, `\u{HEX}`): those pass
            // through untouched, which is what makes the escape
            // idempotent, and what keeps the journal's and JSON's own
            // reversible spellings doubled exactly as before.
            '\\' => {
                let mut ahead = it.clone();
                match ahead.next() {
                    Some((_, '\\')) => {
                        if !fits(out.len(), "\\\\", budget) {
                            return at;
                        }
                        out.push_str("\\\\");
                        it = ahead;
                        continue;
                    }
                    Some((_, 'u')) => match pass_through_braced_hex(&mut ahead) {
                        Some(seq) => {
                            if !fits(out.len(), &seq, budget) {
                                return at;
                            }
                            out.push_str(&seq);
                            it = ahead;
                            continue;
                        }
                        None => String::from("\\\\"),
                    },
                    _ => String::from("\\\\"),
                }
            }
            '\t' => String::from("\t"),
            '\n' => match mode {
                DisplayMode::Block => String::from("\n"),
                DisplayMode::Line => String::from("\\u{A}"),
            },
            // Every other control (C0, DEL, the C1 bytes — so the CSI and
            // OSC introducers 0x9B/0x9D are covered), the line and
            // paragraph separators, and the zero-width and bidi code
            // points (§2.3, §4.3) become the journal's escape spelling.
            _ if is_hidden(c) => {
                let mut g = String::new();
                let _ = write!(g, "\\u{{{:X}}}", u32::from(c));
                g
            }
            _ => String::from(c),
        };
        if !fits(out.len(), &group, budget) {
            return at;
        }
        out.push_str(&group);
    }
    s.len()
}

/// If the iterator stands at `{HEX}` (one or more uppercase hex digits,
/// the spelling this module produces, capped at a `char`'s width), consume
/// it and return the whole `\u{…}` sequence text; otherwise consume
/// nothing and return `None`. The `\u` before the brace was consumed by
/// the caller's lookahead.
fn pass_through_braced_hex(
    ahead: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
) -> Option<String> {
    let mut seq = String::from("\\u");
    match ahead.next() {
        Some((_, '{')) => seq.push('{'),
        _ => return None,
    }
    let mut digits = 0;
    loop {
        match ahead.next() {
            Some((_, '}')) if digits > 0 => {
                seq.push('}');
                return Some(seq);
            }
            Some((_, h @ ('0'..='9' | 'A'..='F'))) if digits < 8 => {
                seq.push(h);
                digits += 1;
            }
            _ => return None,
        }
    }
}

/// Control (C0, DEL, C1), line or paragraph separator, zero-width or bidi
/// code point (§2.3, §4.3). The same character classes the manifest and
/// context builders refuse or strip, kept in step by hand: this crate is
/// below `harness-manifest` and cannot import its list.
fn is_hidden(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{2028}' | '\u{2029}')
        || matches!(c,
            '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}'
            | '\u{180B}'..='\u{180F}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}' | '\u{3164}' | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}'
            | '\u{FFA0}' | '\u{FFF0}'..='\u{FFFB}' | '\u{E0000}'..='\u{E0FFF}')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No control or hidden character may survive except the ones the
    /// mode keeps (`\t`, and `\n` in a block).
    fn assert_terminal_safe(shown: &str, mode: DisplayMode) {
        for c in shown.chars() {
            if c == '\t' || (mode == DisplayMode::Block && c == '\n') {
                continue;
            }
            assert!(!c.is_control(), "raw control {c:?} survived: {shown:?}");
            assert!(!is_hidden(c), "hidden character {c:?} survived: {shown:?}");
        }
    }

    #[test]
    fn display_strips_csi_osc_and_c1() {
        let raw = "a\u{1b}[31mred\u{1b}[0mb\u{1b}]0;evil title\u{7}c\u{9b}1m\u{90}d";
        let shown = sanitize_for_terminal(raw, DisplayMode::Block);
        assert_terminal_safe(&shown, DisplayMode::Block);
        // The introducers are escaped; the rest of each sequence stays
        // visible as inert text (nothing is silently deleted).
        assert!(shown.contains("\\u{1B}[31mred\\u{1B}[0m"), "{shown:?}");
        assert!(shown.contains("\\u{1B}]0;evil title\\u{7}"), "{shown:?}");
        // The single-byte C1 forms of CSI and OSC are covered too.
        assert!(shown.contains("\\u{9B}1m"), "{shown:?}");
        assert!(shown.contains("\\u{90}"), "{shown:?}");
        assert!(
            shown.starts_with("a")
                && shown.contains('b')
                && shown.contains('c')
                && shown.ends_with('d'),
            "{shown:?}"
        );
    }

    #[test]
    fn display_escapes_bidi_and_zero_width() {
        let raw = "file\u{202E}exe.txt\u{200B}end\u{200F}\u{FEFF}\u{00AD}";
        let shown = sanitize_for_terminal(raw, DisplayMode::Line);
        assert_terminal_safe(&shown, DisplayMode::Line);
        assert!(
            shown.contains("file\\u{202E}exe.txt\\u{200B}end"),
            "{shown:?}"
        );
        assert!(
            shown.contains("\\u{200F}") && shown.contains("\\u{FEFF}") && shown.contains("\\u{AD}"),
            "{shown:?}"
        );
        // Plain text around the escapes is untouched.
        assert!(
            shown.starts_with("file") && shown.contains("exe.txt"),
            "{shown:?}"
        );
    }

    #[test]
    fn display_is_idempotent() {
        let corpus: [(&str, &str); 12] = [
            ("plain ascii", "plain ascii"),
            ("csi", "a\u{1b}[31mred\u{1b}[0mb\u{9b}2J"),
            ("osc", "\u{1b}]8;;http://x\u{1b}\\link\u{1b}]0;t\u{7}"),
            (
                "bidi zero width",
                "x\u{202E}rev\u{200B}\u{200F}\u{FEFF}\u{2066}y",
            ),
            ("c0 c1 del", "\u{0}\u{7}\u{8}\u{b}\u{c}\u{1f}\u{7f}\u{9f}ok"),
            ("newlines tabs", "l1\nl2\r\nl3\tend"),
            ("separators", "a\u{2028}b\u{2029}c"),
            ("backslashes", "a\\b\\\\c\\\\\\d\\"),
            (
                "json spellings",
                "\"note\":\"line\\nbreak\\r\\t\\u001b\\\"q\\\\\"",
            ),
            (
                "own spellings",
                "\\u{1B}\\u{202E}\\u{A}\\u{41}\\u{}\\u{1b}\\u{ZZ}\\u{",
            ),
            ("separator in braces", "\\u{"),
            ("marker text", "keep going [12 bytes cut]"),
        ];
        for (name, raw) in corpus {
            for mode in [DisplayMode::Line, DisplayMode::Block] {
                let once = escape_for_terminal(raw, mode);
                assert_eq!(
                    escape_for_terminal(&once, mode),
                    once,
                    "{name}: {raw:?} ({mode:?})"
                );
                let bounded = sanitize_for_terminal_bounded(raw, mode, 64);
                assert_eq!(
                    sanitize_for_terminal_bounded(&bounded, mode, 64),
                    bounded,
                    "{name} bounded: {raw:?} ({mode:?})"
                );
                let default = sanitize_for_terminal(raw, mode);
                assert_eq!(
                    sanitize_for_terminal(&default, mode),
                    default,
                    "{name}: {raw:?}"
                );
            }
        }
    }

    #[test]
    fn display_bound_marks_cut() {
        let raw = "word ".repeat(1000); // 5000 bytes
        let shown = sanitize_for_terminal_bounded(&raw, DisplayMode::Block, 100);
        assert!(shown.len() <= 100, "{} bytes", shown.len());
        let marker_at = shown.rfind('[').expect("no cut marker");
        let marker = &shown[marker_at..];
        assert!(marker.ends_with(" bytes cut]"), "no cut marker: {shown:?}");
        let n: usize = marker[1..marker.len() - " bytes cut]".len()]
            .parse()
            .expect("marker not `[N bytes cut]`");
        // Every byte not shown is accounted for: body + cut == input.
        assert_eq!(shown.len() - marker.len() + n, raw.len());
        // Bounded output is idempotent at the bound.
        assert_eq!(
            sanitize_for_terminal_bounded(&shown, DisplayMode::Block, 100),
            shown
        );
        // Under the bound: no marker.
        let whole = sanitize_for_terminal_bounded("short", DisplayMode::Line, 100);
        assert_eq!(whole, "short");
        // A bound too small for the marker still shows the marker, whole.
        let tiny = sanitize_for_terminal_bounded(&raw, DisplayMode::Block, 4);
        assert_eq!(tiny, format!("[{} bytes cut]", raw.len()));
    }

    #[test]
    fn display_modes_differ_only_on_the_newline() {
        let raw = "l1\nl2\tend";
        let block = escape_for_terminal(raw, DisplayMode::Block);
        assert_eq!(block, "l1\nl2\tend");
        let line = escape_for_terminal(raw, DisplayMode::Line);
        assert_eq!(line, "l1\\u{A}l2\tend");
        assert_terminal_safe(&line, DisplayMode::Line);
        assert_terminal_safe(&block, DisplayMode::Block);
    }

    #[test]
    fn display_keeps_the_reversible_spellings_doubled() {
        // The journal's and JSON's own spellings still double exactly as
        // the approval rendering has always shown them (§7.1).
        assert_eq!(
            escape_for_terminal("\"a\\nb\\r\\u001b\\\\\"", DisplayMode::Line),
            "\"a\\\\nb\\\\r\\\\u001b\\\\\""
        );
        // An already-doubled backslash, or this escaper's own `\u{HEX}`,
        // passes through: that is the idempotency.
        assert_eq!(escape_for_terminal("\\\\n", DisplayMode::Line), "\\\\n");
        assert_eq!(escape_for_terminal("\\u{1B}", DisplayMode::Line), "\\u{1B}");
        // Lowercase hex is not this escaper's spelling: it doubles.
        assert_eq!(
            escape_for_terminal("\\u{1b}", DisplayMode::Line),
            "\\\\u{1b}"
        );
    }
}
