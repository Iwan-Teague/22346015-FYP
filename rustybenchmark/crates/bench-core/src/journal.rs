//! Journal recovery (docs/09 "The journal is the source of truth"): a pure scan of journal text
//! that decides which lines are completed units, and reports everything it had to repair.
//!
//! The journal is append-only JSON lines, one per completed unit. A crash (SIGKILL, power loss,
//! lid close) can leave:
//!
//! * a **torn tail** — the last line cut short, with no newline. docs/09: "detected by JSON parse
//!   failure and discarded; that unit simply re-runs".
//! * a **glued line** — a torn fragment that the next append joined onto, because an append that
//!   does not start on a fresh line concatenates with the fragment. The completed unit in the
//!   second half is real and is *salvaged*, not lost.
//! * **corrupt** lines in the middle (bit rot, a stray editor save), **duplicates** (the same unit
//!   completed twice: two processes, a hand-concatenated journal), and **reordered** lines (harmless:
//!   aggregation is a pure fold, so order carries no meaning and is not touched).
//!
//! Rules, each chosen so that recovery can only *lose a unit that never completed*, never one
//! that did, and never count one twice:
//!
//! 1. Every line that parses as a unit is kept, wherever it is, in file order.
//! 2. Anything else is **quarantined verbatim** (returned in [`Scan::quarantined`] for the caller
//!    to write aside), never silently dropped.
//! 3. A unit seen twice (same `unit_id`) is kept **once, first wins**: the journal is append-only
//!    truth and resume already skips a completed unit. Whether the copies were byte-identical is
//!    reported, because differing copies mean two different grades of one unit and some callers
//!    (export) must refuse that rather than pick.
//! 4. Timestamps are never consulted: no decision depends on the wall clock, so a clock that jumps
//!    backwards cannot reorder, drop or double-count anything.

use serde_json::Value;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepairKind {
    /// The final line had no newline and did not parse: an interrupted append.
    TornTail,
    /// A line that is not a completed unit, in the middle of the file.
    CorruptLine,
    /// A torn fragment with a complete unit glued after it; the unit was recovered.
    SalvagedGlue,
    /// A second copy of a unit already seen; dropped. `identical` = byte-identical to the first.
    Duplicate { identical: bool },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repair {
    pub kind: RepairKind,
    /// 1-based line number in the scanned text.
    pub line: usize,
    pub detail: String,
}

#[derive(Clone, Debug, Default)]
pub struct Scan {
    /// The kept lines, each ending in `\n`, in file order.
    pub clean: String,
    /// Number of completed units kept.
    pub units: usize,
    pub repairs: Vec<Repair>,
    /// Raw text of lines that were not kept, for the caller to preserve.
    pub quarantined: Vec<String>,
}

impl Scan {
    pub fn is_clean(&self) -> bool {
        self.repairs.is_empty()
    }

    /// One human line per repair. Never includes journal content beyond its kind and position.
    pub fn summary(&self) -> Vec<String> {
        self.repairs
            .iter()
            .map(|r| {
                let what = match &r.kind {
                    RepairKind::TornTail => {
                        "torn final line discarded (that unit will re-run)".to_string()
                    }
                    RepairKind::CorruptLine => "corrupt line quarantined".to_string(),
                    RepairKind::SalvagedGlue => {
                        "unit recovered from behind a torn fragment".to_string()
                    }
                    RepairKind::Duplicate { identical: true } => {
                        "duplicate unit dropped (identical copy)".to_string()
                    }
                    RepairKind::Duplicate { identical: false } => {
                        "duplicate unit dropped (DIFFERENT copy: first kept)".to_string()
                    }
                };
                format!("line {}: {what}", r.line)
            })
            .collect()
    }

    /// True if any duplicate differed from the copy that was kept.
    pub fn has_conflicting_duplicates(&self) -> bool {
        self.repairs
            .iter()
            .any(|r| matches!(r.kind, RepairKind::Duplicate { identical: false }))
    }
}

/// A line is a completed unit if it is a JSON object with an `oracle` object (what grading
/// produces). The `unit_id`, when present, is its identity; otherwise the line text is.
fn parse_unit(line: &str) -> Option<Value> {
    let v: Value = serde_json::from_str(line).ok()?;
    (v.is_object() && v.get("oracle").is_some_and(Value::is_object)).then_some(v)
}

fn identity(v: &Value, line: &str) -> String {
    match v.get("unit_id").and_then(Value::as_str) {
        Some(id) => format!("id:{id}"),
        None => format!("line:{line}"),
    }
}

/// The start of a journal object written by this harness. Used only to look for a unit that a
/// torn fragment swallowed.
const OBJECT_START: &str = "{\"schema\":";

/// Scan `text` and decide which lines are completed units. See the module docs for the rules.
pub fn scan(text: &str) -> Scan {
    let mut out = Scan::default();
    let mut seen: HashMap<String, String> = HashMap::new(); // identity -> kept line text
    let ends_with_newline = text.is_empty() || text.ends_with('\n');
    let lines: Vec<&str> = text.split('\n').collect();
    // `split` yields a trailing empty string after a final newline.
    let n_lines = if ends_with_newline {
        lines.len() - 1
    } else {
        lines.len()
    };

    for (i, raw) in lines.iter().take(n_lines).enumerate() {
        let lineno = i + 1;
        let line = raw.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        let is_unterminated_tail = !ends_with_newline && i + 1 == n_lines;

        let (unit, glued) = match parse_unit(line) {
            Some(v) => (Some((v, line.to_string())), false),
            None => {
                // A torn fragment with a whole unit glued behind it: the last object start in
                // the line is where the real unit begins.
                let salvaged = line
                    .rfind(OBJECT_START)
                    .filter(|p| *p > 0)
                    .and_then(|p| parse_unit(&line[p..]).map(|v| (v, line[p..].to_string())));
                match salvaged {
                    Some(s) => (Some(s), true),
                    None => (None, false),
                }
            }
        };

        match unit {
            Some((v, text_of_unit)) => {
                if glued {
                    out.repairs.push(Repair {
                        kind: RepairKind::SalvagedGlue,
                        line: lineno,
                        detail: "torn fragment before a complete unit".into(),
                    });
                    let cut = line.len() - text_of_unit.len();
                    out.quarantined.push(line[..cut].to_string());
                }
                let id = identity(&v, &text_of_unit);
                if let Some(first) = seen.get(&id) {
                    out.repairs.push(Repair {
                        kind: RepairKind::Duplicate {
                            identical: *first == text_of_unit,
                        },
                        line: lineno,
                        detail: "unit already recorded earlier".into(),
                    });
                    out.quarantined.push(text_of_unit);
                } else {
                    seen.insert(id, text_of_unit.clone());
                    out.clean.push_str(&text_of_unit);
                    out.clean.push('\n');
                    out.units += 1;
                }
            }
            None => {
                out.repairs.push(Repair {
                    kind: if is_unterminated_tail {
                        RepairKind::TornTail
                    } else {
                        RepairKind::CorruptLine
                    },
                    line: lineno,
                    detail: format!("{} bytes", line.len()),
                });
                out.quarantined.push(line.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(id: &str, extra: &str) -> String {
        format!(
            r#"{{"schema":1,"unit_id":"{id}","task_id":"fam/0000","oracle":{{"score":1.0}}{extra}}}"#
        )
    }

    fn j(lines: &[String]) -> String {
        lines.iter().map(|l| format!("{l}\n")).collect()
    }

    #[test]
    fn a_clean_journal_is_untouched() {
        let t = j(&[unit("a", ""), unit("b", ""), unit("c", "")]);
        let s = scan(&t);
        assert!(s.is_clean());
        assert_eq!((s.units, s.clean.as_str()), (3, t.as_str()));
        assert!(scan("").is_clean());
        assert_eq!(scan("\n\n").units, 0);
    }

    #[test]
    fn a_torn_tail_is_discarded_and_everything_before_it_survives() {
        let full = unit("c", "");
        for cut in [1, 10, full.len() / 2, full.len() - 1] {
            let t = format!("{}{}", j(&[unit("a", ""), unit("b", "")]), &full[..cut]);
            let s = scan(&t);
            assert_eq!(s.units, 2, "cut at {cut}");
            assert_eq!(s.repairs.len(), 1);
            assert_eq!(s.repairs[0].kind, RepairKind::TornTail);
            assert_eq!(s.repairs[0].line, 3);
            assert_eq!(
                s.quarantined,
                vec![full[..cut].to_string()],
                "kept verbatim, not lost"
            );
            assert_eq!(
                s.clean,
                j(&[unit("a", ""), unit("b", "")]),
                "clean text ends on a newline"
            );
        }
    }

    #[test]
    fn a_torn_fragment_with_a_unit_glued_behind_it_is_salvaged() {
        // What the old append produced: fragment, then the next append directly after it.
        let frag = &unit("lost", "")[..40];
        let t = format!("{}{}{}\n", j(&[unit("a", "")]), frag, unit("b", ""));
        let s = scan(&t);
        assert_eq!(s.units, 2, "the glued unit is real and must not be lost");
        assert!(s.clean.contains("\"unit_id\":\"b\""));
        assert!(!s.clean.contains("lost"));
        assert_eq!(s.repairs[0].kind, RepairKind::SalvagedGlue);
        assert_eq!(s.quarantined, vec![frag.to_string()]);
    }

    #[test]
    fn corrupt_middle_lines_are_quarantined_not_fatal() {
        let t = format!(
            "{}garbage not json\n{}\n{{\"x\":1}}\n{}",
            j(&[unit("a", "")]),
            unit("b", ""),
            j(&[unit("c", "")])
        );
        let s = scan(&t);
        assert_eq!(s.units, 3);
        let kinds: Vec<_> = s.repairs.iter().map(|r| r.kind.clone()).collect();
        assert_eq!(
            kinds,
            vec![RepairKind::CorruptLine, RepairKind::CorruptLine],
            "{:?}",
            s.summary()
        );
        assert_eq!(s.quarantined.len(), 2);
    }

    #[test]
    fn duplicates_keep_the_first_and_say_whether_the_copies_differed() {
        let t = j(&[
            unit("a", ""),
            unit("b", ""),
            unit("a", ""),
            unit("b", r#","note":"regraded""#),
        ]);
        let s = scan(&t);
        assert_eq!(s.units, 2);
        assert_eq!(
            s.repairs.iter().map(|r| r.kind.clone()).collect::<Vec<_>>(),
            vec![
                RepairKind::Duplicate { identical: true },
                RepairKind::Duplicate { identical: false }
            ]
        );
        assert!(s.has_conflicting_duplicates());
        assert!(!s.clean.contains("regraded"), "first copy wins");
        assert!(!scan(&j(&[unit("a", ""), unit("a", "")])).has_conflicting_duplicates());
    }

    #[test]
    fn reordered_lines_are_left_alone_and_lose_nothing() {
        let a = j(&[unit("a", ""), unit("b", ""), unit("c", "")]);
        let b = j(&[unit("c", ""), unit("a", ""), unit("b", "")]);
        let (sa, sb) = (scan(&a), scan(&b));
        assert!(sa.is_clean() && sb.is_clean());
        assert_eq!(sb.clean, b, "file order is preserved, not normalised");
        assert_eq!(sa.units, sb.units);
    }

    #[test]
    fn timestamps_never_influence_the_result() {
        // Clock jumped backwards between segments: completed_at decreases down the file.
        let t = j(&[
            unit("a", r#","completed_at":"2026-10-05T22:00:00Z","segment":0"#),
            unit("b", r#","completed_at":"2026-10-05T21:00:00Z","segment":1"#),
            unit("c", r#","completed_at":"1970-01-01T00:00:00Z","segment":1"#),
        ]);
        let s = scan(&t);
        assert!(s.is_clean());
        assert_eq!((s.units, s.clean.as_str()), (3, t.as_str()));
    }

    #[test]
    fn crlf_and_blank_lines_are_tolerated() {
        let t = format!("{}\r\n\r\n{}\r\n", unit("a", ""), unit("b", ""));
        let s = scan(&t);
        assert_eq!(s.units, 2);
        assert!(s.is_clean());
    }

    #[test]
    fn lines_without_an_oracle_are_not_units() {
        let s = scan("{\"unit_id\":\"a\"}\n[1,2]\n42\n\"str\"\n");
        assert_eq!(s.units, 0);
        assert_eq!(s.repairs.len(), 4);
    }

    #[test]
    fn units_without_a_unit_id_are_deduplicated_by_exact_text() {
        let l = r#"{"task_id":"x","oracle":{"score":0.5}}"#.to_string();
        let s = scan(&j(&[
            l.clone(),
            l.clone(),
            r#"{"task_id":"y","oracle":{"score":0.5}}"#.to_string(),
        ]));
        assert_eq!(s.units, 2);
        assert_eq!(s.repairs.len(), 1);
    }

    #[test]
    fn summary_reports_positions_without_echoing_content() {
        let t = format!("{}SECRET-TORN-BYTES", j(&[unit("a", "")]));
        let s = scan(&t);
        let text = s.summary().join("\n");
        assert!(
            text.contains("line 2") && text.contains("torn final line"),
            "{text}"
        );
        assert!(!text.contains("SECRET"), "{text}");
    }

    #[test]
    fn scanning_is_idempotent() {
        let t = format!(
            "{}torn{}{}\ngarbage\n{}",
            j(&[unit("a", "")]),
            unit("b", ""),
            "",
            j(&[unit("a", ""), unit("c", "")])
        );
        let once = scan(&t);
        let twice = scan(&once.clean);
        assert!(twice.is_clean(), "{:?}", twice.summary());
        assert_eq!(twice.clean, once.clean);
    }
}
